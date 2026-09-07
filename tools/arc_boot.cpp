// arc_boot -- run a lifted program's static constructors, then an entry point.
//
// This is the first thing that executes real game code. The engine's 1,527
// static constructors run before anything else on Android, so they run first
// here too, and they are a good early test in their own right: they allocate,
// take locks, build tables and touch a large part of the shim without needing
// a window, a JNI environment or a server.
//
// Failures are recovered rather than fatal. A boot attempt that dies on the
// first bad constructor tells you one thing per run; one that keeps going
// tells you the shape of what is left.

#include <setjmp.h>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#if defined(_WIN32)
#include <crtdbg.h>
#endif
#include <cstring>
#include <filesystem>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#endif

#include "arm64_context.h"
#include "elf_image.h"
#include "jni_env.h"
#include "lifted.h"
#include "shim.h"
#include "window.h"

namespace {

arc::ElfImage g_image;
std::vector<std::unique_ptr<arc::ElfImage>> g_deps;

// Unresolved imports bind into a guard page, one slot each, so a fault inside
// it names the missing shim exactly. Turning an address back into a symbol is
// the difference between "231 constructors faulted" and "231 constructors
// called one function nobody wrote".
std::vector<std::pair<uint64_t, std::string>> g_unresolved;

// Every image we mapped, so a faulting address can be attributed to one of
// them rather than reported as a bare number.
struct Mapping {
  std::string name;
  uint64_t base;
  uint64_t span;
  const arc::ElfImage* image;
};
std::vector<Mapping> g_mappings;

// The generated program knows which images it covers, by name. Matching on the
// name rather than on load order means the host may map them in any sequence.
void AnnounceImage(const std::string& name, uint64_t base, uint64_t span,
                   const arc::ElfImage* image) {
  g_mappings.push_back({name, base, span, image});
  for (size_t i = 0; i < ARC_IMAGE_COUNT; ++i) {
    const char* known = arc_image_name(i);
    if (known && name == known) {
      arc_set_image(i, base, span);
      return;
    }
  }
}

std::string ExplainAddress(uint64_t addr) {
  for (const auto& u : g_unresolved)
    if (u.first == addr)
      return "unresolved import " + u.second;
  if (arc_jni_owns(addr)) return "past the end of a stand-in JNI handle";
  if (addr < 0x10000) return "near null";
  for (const Mapping& m : g_mappings) {
    if (addr >= m.base && addr < m.base + m.span) {
      char buf[160];
      snprintf(buf, sizeof(buf), "inside %s at +%#llx", m.name.c_str(),
               static_cast<unsigned long long>(addr - m.base));
      return buf;
    }
  }
  // Not in a guest image, so if it is executable it is ours. The dispatcher
  // knows every host function it was told about, and naming the one an address
  // sits inside is usually the whole answer.
  {
    uint64_t delta = 0;
    // Not `near`: MSVC still keeps that as a keyword from its segmented
    // memory days, and using it here is a syntax error with no hint as to why.
    if (const char* host_fn = arc_native_near(addr, &delta)) {
      if (delta < 0x1000) {
        char buf[192];
        snprintf(buf, sizeof(buf), "%#llx into the host's %s",
                 static_cast<unsigned long long>(delta), host_fn);
        return buf;
      }
    }
  }

  // Nothing we allocated deliberately. The operating system still knows what
  // is there, which distinguishes a wild pointer from a real region touched
  // the wrong way -- and that is the difference between hunting a lifter bug
  // and hunting a permissions bug.
#if defined(_WIN32)
  MEMORY_BASIC_INFORMATION mbi;
  if (VirtualQuery(reinterpret_cast<void*>(addr), &mbi, sizeof(mbi))) {
    const char* state = mbi.State == MEM_COMMIT   ? "committed"
                        : mbi.State == MEM_RESERVE ? "reserved, not committed"
                                                   : "unallocated";
    char buf[192];
    snprintf(buf, sizeof(buf),
             "%s, protection %#lx, region of %#llx bytes from %#llx", state,
             static_cast<unsigned long>(mbi.Protect),
             static_cast<unsigned long long>(mbi.RegionSize),
             static_cast<unsigned long long>(
                 reinterpret_cast<uintptr_t>(mbi.AllocationBase)));
    return buf;
  }
#endif
  return "not in any mapped image";
}

// Same answer, in the shape the runtime can take. A dispatch miss is reported
// from inside the library, which knows the branch went somewhere it does not
// recognise but not that the somewhere is an unresolved import.
const char* ExplainForRuntime(uint64_t addr) {
  static thread_local std::string text;
  text = ExplainAddress(addr);
  return text.empty() ? nullptr : text.c_str();
}

// Decode a packed frame back into the image it came from and the offset
// inside it, which is what a disassembler wants.
// A pointer chain, hex-dumped. "d58/358:32" reads the image at +0xd58, follows
// the 64-bit value there, adds 0x358, and prints 32 bytes -- which is how a
// field of an engine singleton is reached from the outside, with no debugger.
void ReportPeek(uint64_t image_base, const std::string& spec) {
  const size_t colon = spec.find(':');
  const size_t len = colon == std::string::npos
                         ? 64
                         : strtoull(spec.c_str() + colon + 1, nullptr, 16);
  std::string chain = spec.substr(0, colon);
  uint64_t at = image_base;
  size_t pos = 0;
  bool first = true;
  while (pos <= chain.size()) {
    const size_t slash = chain.find('/', pos);
    const std::string step = chain.substr(pos, slash - pos);
    if (!first) {
      // Every hop reads a pointer the guest wrote, so a null or a wild value
      // is the answer rather than a reason to crash the host.
      uint64_t next = 0;
      memcpy(&next, reinterpret_cast<const void*>(at), sizeof next);
      if (!next) {
        printf("  peek %s: null at step %zu\n", spec.c_str(), pos);
        return;
      }
      at = next;
    }
    at += strtoull(step.c_str(), nullptr, 16);
    first = false;
    if (slash == std::string::npos) break;
    pos = slash + 1;
  }
  printf("  peek %s = %#llx\n", spec.c_str(),
         static_cast<unsigned long long>(at));
  const auto* p = reinterpret_cast<const unsigned char*>(at);
  for (size_t i = 0; i < len; i += 16) {
    printf("    +%04zx ", i);
    for (size_t j = 0; j < 16 && i + j < len; ++j) printf("%02x ", p[i + j]);
    printf("\n");
  }
}

// The frame as the driver actually rasterised it, which is the only evidence
// that a port renders. Written as binary PPM: no encoder, no dependency, and
// every image tool reads it.
void SaveFrame(const char* path, int w, int h) {
  auto read = reinterpret_cast<void (*)(int, int, int, int, unsigned, unsigned,
                                        void*)>(arc::ShimResolveGL("glReadPixels"));
  if (!read) {
    fprintf(stderr, "no glReadPixels to capture with\n");
    return;
  }
  // With ARC_GL_TINT the guest clears to magenta; clearing to green from here
  // first separates "the guest's GL went nowhere" from "the readback did".
  if (getenv("ARC_GL_TINT")) {
    auto cc = reinterpret_cast<void (*)(float, float, float, float)>(
        arc::ShimResolveGL("glClearColor"));
    auto cl = reinterpret_cast<void (*)(unsigned)>(
        arc::ShimResolveGL("glClear"));
    if (cc && cl) {
      cc(0.0f, 0.6f, 0.2f, 1.0f);
      cl(0x4000 /* GL_COLOR_BUFFER_BIT */);
    }
  }
  std::vector<unsigned char> rgb(static_cast<size_t>(w) * h * 3);
  read(0, 0, w, h, 0x1907 /* GL_RGB */, 0x1401 /* GL_UNSIGNED_BYTE */,
       rgb.data());
  FILE* f = fopen(path, "wb");
  if (!f) {
    fprintf(stderr, "cannot write %s\n", path);
    return;
  }
  fprintf(f, "P6\n%d %d\n255\n", w, h);
  // GL's origin is bottom-left and an image file's is top-left.
  for (int y = h - 1; y >= 0; --y)
    fwrite(rgb.data() + static_cast<size_t>(y) * w * 3, 1,
           static_cast<size_t>(w) * 3, f);
  fclose(f);
  printf("wrote %s (%dx%d)\n", path, w, h);
}

void ReportFrames() {
  const size_t n = arc_frame_count();
  if (!n) return;
  printf("  guest functions entered, most recent first:\n");
  for (size_t i = 0; i < n && i < 16; ++i) {
    const uint64_t packed = arc_frame_at(i);
    const size_t image = static_cast<size_t>(packed >> 56);
    const uint64_t off = packed & 0x00FFFFFFFFFFFFFFull;
    const char* name = arc_image_name(image);
    // A shipped library keeps its .dynsym, so most of these have a name on
    // record -- which is the difference between a trail that has to be
    // disassembled line by line and one that can simply be read.
    std::string sym;
    uint64_t within = 0;
    for (const Mapping& m : g_mappings) {
      if (name && m.image && m.name == name) {
        sym = m.image->SymbolAt(m.base + off, &within);
        break;
      }
    }
    if (sym.empty()) {
      printf("    %-22s +%#llx\n", name ? name : "?",
             static_cast<unsigned long long>(off));
    } else {
      printf("    %-22s +%#llx  %s+%#llx\n", name ? name : "?",
             static_cast<unsigned long long>(off), sym.c_str(),
             static_cast<unsigned long long>(within));
    }
  }
}

// The guest register file at the moment of a fault.
//
// Lifted code keeps its registers in the context rather than in C locals, so
// unlike a host crash this state is simply there to be read. It is the
// difference between "faulted reading 0" and seeing which register held the
// null and what the ones around it were -- an object pointer that survived a
// null check, with a zero where its vtable should be, says something quite
// different from a null argument.
void ReportRegisters(const Arm64Ctx* c) {
  // Only a program lifted with --pc-notes keeps this, and it is the one thing
  // that turns "somewhere in this function" into an instruction.
  if (c->pc) {
    std::string sym;
    uint64_t within = 0;
    for (const Mapping& m : g_mappings) {
      if (m.image && c->pc >= m.base && c->pc < m.base + m.span) {
        sym = m.image->SymbolAt(c->pc, &within);
        printf("  faulted at %s +%#llx%s%s", m.name.c_str(),
               static_cast<unsigned long long>(c->pc - m.base),
               sym.empty() ? "" : "  ", sym.c_str());
        if (!sym.empty())
          printf("+%#llx", static_cast<unsigned long long>(within));
        printf("\n");
        break;
      }
    }
  }
  printf("  guest registers:\n");
  for (int i = 0; i < 31; i += 4) {
    printf("   ");
    for (int j = i; j < i + 4 && j < 31; ++j)
      printf("  x%-2d=%016llx", j, static_cast<unsigned long long>(c->x[j]));
    printf("\n");
  }
  printf("     sp =%016llx\n", static_cast<unsigned long long>(c->sp));
}

void ReportTrail() {
  const size_t n = arc_trace_count();
  if (!n) return;
  printf("  last calls out of the guest, most recent first:\n   ");
  for (size_t i = 0; i < n && i < 12; ++i) {
    const char* what = arc_trace_at(i);
    printf(" %s", what ? what : "?");
  }
  printf("\n");
}

// The guest stack, and where in it the stack pointer starts.
//
// Not at the very top. On a real system a function is entered with a caller's
// frame above it, and code reads into that region -- arguments passed on the
// stack, a saved frame pointer chain. Starting at the top means every such
// read lands past the end of the allocation, which is a fault with no cause
// worth investigating. Leaving headroom above the pointer makes those reads
// land in memory that exists.
constexpr size_t kGuestStack = 64 * 1024 * 1024;
constexpr size_t kStackHeadroom = 16 * 1024 * 1024;

// Kept free of C++ objects: MSVC will not put structured exception handling in
// a frame that also needs unwinding.
int RunWithRecovery(Arm64Ctx* c, uint64_t target) {
  jmp_buf recovery;
  arc_set_recovery(&recovery);
  int rc = 0;
  if (setjmp(recovery) == 0) {
    arc_dispatch(c, target);
  } else {
    rc = 1;  // a guest trap, already described by arc_last_trap()
  }
  arc_set_recovery(nullptr);
  return rc;
}

#if defined(_WIN32)
// Which address the guest touched matters more than the fact that it faulted:
// a null tells you one thing, an address inside the guard page the loader binds
// unresolved imports to tells you exactly which shim is missing.
uint64_t g_fault_address;
const char* g_fault_kind = "";

int FaultFilter(EXCEPTION_POINTERS* ep, unsigned long* code) {
  *code = ep->ExceptionRecord->ExceptionCode;
  g_fault_address = 0;
  g_fault_kind = "";
  if (ep->ExceptionRecord->NumberParameters >= 2) {
    g_fault_address = ep->ExceptionRecord->ExceptionInformation[1];
    switch (ep->ExceptionRecord->ExceptionInformation[0]) {
      case 0: g_fault_kind = "read"; break;
      case 1: g_fault_kind = "write"; break;
      case 8: g_fault_kind = "execute"; break;
      default: break;
    }
  }
  return EXCEPTION_EXECUTE_HANDLER;
}
#else
uint64_t g_fault_address;
const char* g_fault_kind = "";
#endif

int CallGuarded(Arm64Ctx* c, uint64_t target, unsigned long* code) {
#if defined(_WIN32)
  g_fault_address = 0;
  __try {
    return RunWithRecovery(c, target);
  } __except (FaultFilter(GetExceptionInformation(), code)) {
    return 2;  // a fault in lifted code or in something it called
  }
#else
  (void)code;
  return RunWithRecovery(c, target);
#endif
}

// Lifted functions call one another as ordinary C functions, so the guest's
// call depth is the *host* stack's depth. A default thread stack is a megabyte
// or so, which real engine code exhausts quickly -- and a stack overflow is the
// one fault structured exception handling cannot reliably be asked to survive,
// because the guard page it needs is what just went. Giving the thread room is
// cheaper than diagnosing it repeatedly.
struct EntryCall {
  Arm64Ctx* ctx;
  uint64_t target;
  int rc;
  unsigned long code;
  char trap[256];
  arc::Window* window;
};

#if defined(_WIN32)
DWORD WINAPI RunEntry(void* p) {
  EntryCall* e = static_cast<EntryCall*>(p);
  // The context has to be current on the thread that issues the GL calls, and
  // that is this one. Without it the engine's calls have no context to act on,
  // which fails quietly rather than loudly: glGetString(GL_EXTENSIONS) answers
  // null and the engine takes strlen of it.
  if (e->window) {
    std::string err;
    if (!e->window->MakeCurrent(&err))
      printf("  could not make the GL context current: %s\n", err.c_str());
  }
  e->rc = CallGuarded(e->ctx, e->target, &e->code);
  if (e->rc == 1) snprintf(e->trap, sizeof(e->trap), "%s", arc_last_trap());
  if (e->rc != 0) {
    // Both records are per-thread, so they have to be read here rather than
    // after the join.
    ReportTrail();
  }
  // Hand the context back before this thread ends, or the next step cannot
  // take it: a context left current on a thread that no longer exists is not
  // available to claim elsewhere.
  if (e->window) e->window->ReleaseCurrent();
  return 0;
}
#endif

const char* FaultName(unsigned long code) {
#if defined(_WIN32)
  switch (code) {
    case EXCEPTION_ACCESS_VIOLATION: return "access violation";
    case EXCEPTION_INT_DIVIDE_BY_ZERO: return "integer divide by zero";
    case EXCEPTION_STACK_OVERFLOW: return "stack overflow";
    case EXCEPTION_ILLEGAL_INSTRUCTION: return "illegal instruction";
    case EXCEPTION_PRIV_INSTRUCTION: return "privileged instruction";
    default: return "exception";
  }
#else
  (void)code;
  return "signal";
#endif
}

}  // namespace

#if defined(_WIN32)
// Bionic returns an error from a bad argument; the UCRT calls __fastfail, and
// __fastfail is not an exception -- no handler sees it, the process is gone,
// and the log ends mid-line with nothing to say which call did it. A guest is
// exactly the caller that passes arguments the UCRT rejects, so the report has
// to come from here.
void OnInvalidParameter(const wchar_t* expr, const wchar_t* fn,
                        const wchar_t* file, unsigned, uintptr_t) {
  printf("  C library rejected an argument: %ls in %ls\n",
         expr && *expr ? expr : L"(no expression)",
         fn && *fn ? fn : L"(unnamed function)");
  (void)file;
}
#endif

int main(int argc, char** argv) {
  // Unbuffered: this program runs code that can abort the process, and
  // block-buffered output redirected to a file dies with it -- which turns a
  // diagnosable crash into an empty log.
  setvbuf(stdout, nullptr, _IONBF, 0);
  setvbuf(stderr, nullptr, _IONBF, 0);
#if defined(_WIN32)
  _set_invalid_parameter_handler(&OnInvalidParameter);
#endif

  const char* lib = nullptr;
  // An engine's startup is a sequence, not a call. cocos2d-x builds its
  // Application in the first JNI method Android invokes and only then accepts
  // the one that initialises the renderer, so a host that calls the second
  // without the first finds a null singleton. Each --entry adds a step; an
  // --args after one belongs to it.
  std::vector<std::pair<std::string, std::string>> entries;
  long ctor_limit = 0;
  bool want_window = false;
  const char* gl_version = nullptr;
  const char* asset_root = nullptr;
  // Every question about why an engine short-circuited is a question about one
  // field of one object, and the object is on the heap behind a global. A
  // chain says how to get there: an image offset, then a deref per "/".
  std::vector<std::string> peeks;
  bool loop = false;
  long frame_limit = 0;
  const char* shot = nullptr;
  for (int i = 1; i < argc; ++i) {
    if (strncmp(argv[i], "--entry=", 8) == 0)
      entries.emplace_back(argv[i] + 8, std::string());
    else if (strncmp(argv[i], "--args=", 7) == 0) {
      if (entries.empty()) {
        fprintf(stderr, "--args must follow an --entry\n");
        return 2;
      }
      entries.back().second = argv[i] + 7;
    }
    else if (strcmp(argv[i], "--window") == 0)
      want_window = true;
    else if (strncmp(argv[i], "--gl=", 5) == 0)
      gl_version = argv[i] + 5;
    else if (strncmp(argv[i], "--assets=", 9) == 0)
      asset_root = argv[i] + 9;
    else if (strcmp(argv[i], "--loop") == 0)
      loop = true;
    else if (strncmp(argv[i], "--frames=", 9) == 0)
      frame_limit = strtol(argv[i] + 9, nullptr, 10);
    else if (strncmp(argv[i], "--shot=", 7) == 0)
      shot = argv[i] + 7;
    else if (strncmp(argv[i], "--peek=", 7) == 0)
      peeks.emplace_back(argv[i] + 7);
    else if (strncmp(argv[i], "--constructors=", 15) == 0)
      ctor_limit = strtol(argv[i] + 15, nullptr, 10);
    else
      lib = argv[i];
  }
  if (!lib) {
    fprintf(stderr,
            "usage: %s [--window] [--gl=MAJOR.MINOR] [--assets=DIR]"
            " [--constructors=N] [--peek=OFF[/OFF...][:LEN]]"
            " [--loop] [--frames=N] [--shot=FILE.ppm]"
            " [--entry=SYMBOL] [--args=N,N,...]"
            " <library.so>\n",
            argv[0]);
    return 2;
  }

  // Before the engine is loaded, not after. GL imports bind by asking the
  // driver for each name and that needs a current context, so an engine loaded
  // first has its GL slots left unbound -- and an unbound slot is not a missing
  // function, it is a branch into nothing. Same order Android uses, where Java
  // holds a surface before it calls in.
  arc::Window window;
  if (want_window) {
    int gl_major = 0, gl_minor = 0;
    if (gl_version) sscanf(gl_version, "%d.%d", &gl_major, &gl_minor);
    std::string window_err;
    if (!window.Open("androidrecomp", 1280, 720, &window_err, gl_major,
                     gl_minor)) {
      fprintf(stderr, "window failed: %s\n", window_err.c_str());
      return 1;
    }
    printf("window     %dx%d, %s\n", window.width(), window.height(),
           window.Describe().c_str());
  }

  // Resolved against the directory we were started in, and before anything
  // changes that: the assets block below moves us, and a relative library path
  // stops meaning what it meant the moment it does.
  std::error_code lib_ec;
  const std::filesystem::path path = std::filesystem::absolute(lib, lib_ec);
  const std::filesystem::path dir = path.parent_path();
  std::string err;

  // The engine reads its own files through the asset manager, so it needs a
  // directory to read them from. An extracted APK puts the library under
  // lib/<abi>/ and the assets beside that pair, so the default is derived from
  // where the library was found and only has to be given when the layout is
  // not the usual one.
  {
    std::filesystem::path assets =
        asset_root ? std::filesystem::path(asset_root)
                   : dir.parent_path().parent_path() / "assets";
    std::error_code ec;
    if (std::filesystem::is_directory(assets, ec)) {
      // Absolute, and with forward slashes. The guest is Android code: it
      // splits paths on '/' and has no notion of a working directory of ours,
      // so a relative Windows path arrives as one long filename containing no
      // separators at all -- which is not a wrong directory but no directory.
      const std::string root =
          std::filesystem::absolute(assets, ec).generic_string();
      arc::ShimSetAssetRoot(root.c_str());
      // And run from there. The engine opens some of its files by bare name,
      // with no directory at all -- on Android it is launched with its own
      // bundle underfoot and never has to say so. A relative open is not a
      // path we can correct after the fact, because by the time it arrives
      // there is nothing left to say which directory was meant.
      std::filesystem::current_path(assets, ec);
      printf("assets     %s\n", root.c_str());
    } else if (asset_root) {
      fprintf(stderr, "no such assets directory: %s\n",
              assets.string().c_str());
      return 1;
    }
  }

  auto resolve = [](const char* name) -> uint64_t {
    for (const auto& d : g_deps)
      if (uint64_t a = d->Lookup(name)) return a;
    return arc::ShimResolve(name);
  };

  for (const std::string& need : arc::ElfImage::ReadNeeded(path.string())) {
    const std::filesystem::path p = dir / need;
    if (!std::filesystem::exists(p)) continue;
    auto img = std::make_unique<arc::ElfImage>();
    if (img->Load(p.string(), resolve, &err)) {
      arc::ShimRegisterImage(img.get());
      AnnounceImage(need, reinterpret_cast<uint64_t>(img->base()),
                    img->span(), img.get());
      g_deps.push_back(std::move(img));
    }
  }
  if (!g_image.Load(path.string(), resolve, &err)) {
    fprintf(stderr, "load failed: %s\n", err.c_str());
    return 1;
  }
  arc::ShimRegisterImage(&g_image);
  AnnounceImage(path.filename().string(),
                reinterpret_cast<uint64_t>(g_image.base()), g_image.span(),
                &g_image);

  // Every import the shim satisfied is a host address the guest will reach by
  // branching through its GOT. The dispatcher has to be able to tell those
  // from lifted functions.
  auto in_guest_image = [](uint64_t addr) {
    for (const Mapping& m : g_mappings)
      if (addr >= m.base && addr < m.base + m.span) return true;
    return false;
  };

  size_t natives = 0, guest_side = 0;
  auto register_imports = [&](const arc::ElfImage& img) {
    for (const arc::Import& i : img.imports()) {
      if (!i.resolved) {
        g_unresolved.emplace_back(i.bound_to, i.name);
        continue;
      }
      // Satisfied by another guest image rather than by the shim: that address
      // is ARM code. Calling it as a host function would execute the wrong
      // architecture. It belongs to the dispatcher, which will trap until that
      // image is lifted too.
      if (in_guest_image(i.bound_to)) {
        ++guest_side;
        continue;
      }
      arc_register_native(i.bound_to, i.name.c_str());
      ++natives;
    }
  };
  for (const auto& d : g_deps) register_imports(*d);
  register_imports(g_image);

  // The JNI table is reached the same way an import is -- the guest loads a
  // slot out of it and branches -- so its entries have to be known to the
  // bridge as well.
  arc_set_explain(&ExplainForRuntime);
  arc_jni_register();
  arc::ShimRegisterVarargs();
  arc::ShimRegisterGL();

  printf("image      %s at %p\n", path.filename().string().c_str(),
         static_cast<void*>(g_image.base()));
  printf("imports    %zu host functions, %zu satisfied by unlifted guest "
         "images, %zu unresolved\n", natives, guest_side, g_unresolved.size());
  // Named, not just counted. Every one is a branch the guest can take into
  // nothing, so the list is the work queue -- and reading it beforehand is
  // cheaper than meeting them one run at a time.
  if (!g_unresolved.empty()) {
    std::vector<std::string> names;
    for (const auto& u : g_unresolved) names.push_back(u.second);
    std::sort(names.begin(), names.end());
    printf("           still needed:");
    for (size_t i = 0; i < names.size(); ++i)
      printf("%s%s", i && i % 6 == 0 ? "\n                        " : " ",
             names[i].c_str());
    printf("\n");
  }
  printf("\nmapped images\n");
  for (const Mapping& m : g_mappings) {
    bool lifted = false;
    for (size_t i = 0; i < ARC_IMAGE_COUNT; ++i) {
      const char* known = arc_image_name(i);
      if (known && m.name == known) { lifted = true; break; }
    }
    printf("  %-22s %#018llx .. %#018llx  %s\n", m.name.c_str(),
           static_cast<unsigned long long>(m.base),
           static_cast<unsigned long long>(m.base + m.span),
           lifted ? "lifted" : "not lifted");
  }

  std::vector<uint8_t> stack(kGuestStack);
  const uint64_t stack_top =
      (reinterpret_cast<uint64_t>(stack.data()) + kGuestStack -
       kStackHeadroom) & ~15ULL;
  Arm64Ctx ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.image_base = reinterpret_cast<uint64_t>(g_image.base());
  ctx.sp = stack_top;

  // What the Java runtime does once a library is loaded: hand it the VM. A
  // library caches that pointer and reaches every later thread's environment
  // through it, so skipping the call leaves a null behind that surfaces much
  // later, inside whatever first tries to call back into Java.
  //
  // Every image that exports it, not just the engine: a dependency gets its
  // own call when Java loads it by name, and libNimble's cached VM is read by
  // an engine constructor -- so a host that only calls the engine's faults in
  // a constructor, three images deep, on a null nobody can trace back here.
  auto call_on_load = [&](const arc::ElfImage& img, const char* who) {
    const uint64_t on_load = img.Lookup("JNI_OnLoad");
    if (!on_load) return;
    ctx.sp = stack_top;
    memset(ctx.x, 0, sizeof(ctx.x));
    ctx.x[0] = arc_jni_vm();
    arc_frame_clear();
    unsigned long code = 0;
    const int rc = CallGuarded(&ctx, on_load, &code);
    if (rc == 0) {
      printf("\n%s JNI_OnLoad returned JNI version %#llx\n", who,
             static_cast<unsigned long long>(ctx.x[0] & 0xFFFFFFFFu));
    } else if (rc == 1) {
      printf("\n%s JNI_OnLoad: %s\n", who, arc_last_trap());
      ReportFrames();
    } else {
      const std::string what = ExplainAddress(g_fault_address);
      printf("\n%s JNI_OnLoad: %s on %s of %#llx%s%s\n", who, FaultName(code),
             g_fault_kind, static_cast<unsigned long long>(g_fault_address),
             what.empty() ? "" : " -- ", what.c_str());
      ReportFrames();
      ReportRegisters(&ctx);
    }
  };

  // One guest call on a thread of its own, which is where the big stack and
  // the GL context live. Arguments go in ctx.x before the call; the result
  // comes back the same way.
  auto call_guest = [&](uint64_t addr, EntryCall* call) {
    call->ctx = &ctx;
    call->target = addr;
    call->window = want_window ? &window : nullptr;
    // Given up here so the guest's thread can take it: a context is current on
    // one thread at a time, and claiming it elsewhere while this one still
    // holds it fails.
    if (want_window) window.ReleaseCurrent();
    // Per call, not per run. An entry point that returns without faulting
    // still answers a question worth asking -- how much guest code it ran --
    // and a count near zero means it did nothing at all.
    arc_frame_clear();
#if defined(_WIN32)
    // 512 MB reserved. It is address space, not memory: only the pages the
    // guest actually touches are ever committed.
    HANDLE th = CreateThread(nullptr, 512u << 20, RunEntry, call, 0, nullptr);
    if (th) {
      WaitForSingleObject(th, INFINITE);
      CloseHandle(th);
    } else {
      call->rc = CallGuarded(&ctx, addr, &call->code);
    }
#else
    call->rc = CallGuarded(&ctx, addr, &call->code);
#endif
  };

  // Before the engine's constructors, in load order: on Android each library
  // gets this when Java loads it by name, and a dependency is loaded first.
  for (const Mapping& m : g_mappings)
    if (m.image != &g_image) call_on_load(*m.image, m.name.c_str());

  const std::vector<uint64_t>& ctors = g_image.init_array();
  const size_t total = ctor_limit > 0 && static_cast<size_t>(ctor_limit) < ctors.size()
                           ? static_cast<size_t>(ctor_limit)
                           : ctors.size();
  printf("\nrunning %zu of %zu static constructors\n", total, ctors.size());

  size_t ok = 0, trapped = 0, faulted = 0;
  std::vector<std::string> first_failures;
  std::vector<std::pair<uint64_t, size_t>> fault_sites;
  std::vector<std::pair<std::string, size_t>> trap_sites;
  for (size_t i = 0; i < total; ++i) {
    // Each constructor starts from a clean frame; a previous failure must not
    // leave the stack pointer somewhere strange.
    ctx.sp = stack_top;
    arc_frame_clear();
    unsigned long code = 0;
    const int rc = CallGuarded(&ctx, ctors[i], &code);
    if (rc == 0) {
      ++ok;
      continue;
    }
    if (rc == 1) {
      ++trapped;
      const std::string what = arc_last_trap();
      bool seen = false;
      for (auto& t : trap_sites)
        if (t.first == what) { ++t.second; seen = true; break; }
      if (!seen) trap_sites.emplace_back(what, 1);
    } else {
      ++faulted;
      bool seen = false;
      for (auto& f : fault_sites)
        if (f.first == g_fault_address) { ++f.second; seen = true; break; }
      if (!seen) fault_sites.emplace_back(g_fault_address, 1);
    }
    if (first_failures.size() < 12) {
      char buf[320];
      if (rc == 1) {
        snprintf(buf, sizeof(buf), "  ctor %zu at %#llx: %s", i,
                 static_cast<unsigned long long>(ctors[i] - ctx.image_base),
                 arc_last_trap());
      } else {
        const std::string what = ExplainAddress(g_fault_address);
        snprintf(buf, sizeof(buf),
                 "  ctor %zu at %#llx: %s on %s of %#llx%s%s", i,
                 static_cast<unsigned long long>(ctors[i] - ctx.image_base),
                 FaultName(code), g_fault_kind,
                 static_cast<unsigned long long>(g_fault_address),
                 what.empty() ? "" : " -- ", what.c_str());
      }
      first_failures.push_back(buf);
      if (first_failures.size() == 1) {
        printf("%s\n", buf);
        ReportFrames();
        if (rc == 2) ReportRegisters(&ctx);
      }
    }
  }

  printf("  %zu ran, %zu trapped, %zu faulted\n", ok, trapped, faulted);
  if (!trap_sites.empty()) {
    printf("\ndistinct traps (%zu)\n", trap_sites.size());
    std::sort(trap_sites.begin(), trap_sites.end(),
              [](const std::pair<std::string, size_t>& a,
                 const std::pair<std::string, size_t>& b) {
                return a.second > b.second;
              });
    for (size_t i = 0; i < trap_sites.size() && i < 12; ++i) {
      // A trap message carries the address it could not resolve; saying which
      // image that lands in turns "one unlifted target" into a place to look.
      const std::string& msg = trap_sites[i].first;
      std::string where;
      const size_t at = msg.find("0x");
      if (at != std::string::npos)
        where = ExplainAddress(strtoull(msg.c_str() + at, nullptr, 16));
      printf("  %6zu x %s%s%s\n", trap_sites[i].second, msg.c_str(),
             where.empty() ? "" : "\n             -- ", where.c_str());
    }
  }
  if (!fault_sites.empty()) {
    printf("\ndistinct fault addresses (%zu)\n", fault_sites.size());
    std::sort(fault_sites.begin(), fault_sites.end(),
              [](const std::pair<uint64_t, size_t>& a,
                 const std::pair<uint64_t, size_t>& b) {
                return a.second > b.second;
              });
    for (size_t i = 0; i < fault_sites.size() && i < 10; ++i)
      printf("  %6zu x %#018llx  %s\n", fault_sites[i].second,
             static_cast<unsigned long long>(fault_sites[i].first),
             ExplainAddress(fault_sites[i].first).c_str());
  }
  if (!first_failures.empty()) {
    printf("\nfirst failures\n");
    for (const std::string& f : first_failures) printf("%s\n", f.c_str());
  }

  call_on_load(g_image, path.filename().string().c_str());

  for (const auto& step : entries) {
    const char* entry = step.first.c_str();
    const char* entry_args = step.second.empty() ? nullptr
                                                 : step.second.c_str();
    // A raw offset as well as a name. Plenty of the engine is internal
    // and stripped, and an unexported function is often exactly the one
    // worth calling to find out what it gates.
    const uint64_t addr =
        (entry[0] == '0' && (entry[1] == 'x' || entry[1] == 'X'))
            ? ctx.image_base + strtoull(entry + 2, nullptr, 16)
            : g_image.Lookup(entry);
    if (!addr) {
      fprintf(stderr, "\nno symbol named %s\n", entry);
      return 1;
    }
    printf("\ncalling %s at %#llx\n", entry,
           static_cast<unsigned long long>(addr - ctx.image_base));
    ctx.sp = stack_top;
    // A JNI entry point takes the environment first and the object that owns
    // the method second. Neither has anything behind it here, but both have to
    // be non-null: the engine dereferences the environment immediately.
    memset(ctx.x, 0, sizeof(ctx.x));
    ctx.x[0] = arc_jni_env();
    ctx.x[1] = arc_jni_object();  // the object the method was called on
    // The method's own declared arguments follow those two. Passing nothing is
    // not the same as passing nothing meaningful: an entry point given a zero
    // width and height sets up a zero-sized surface and fails somewhere much
    // later, which reads as a porting bug rather than as a missing argument.
    if (entry_args) {
      int slot = 2;
      for (const char* p = entry_args; *p && slot < 8;) {
        // `obj` stands for a Java object the host has no real counterpart for
        // -- a Context, an AssetManager. The engine passes these straight back
        // through JNI rather than reading them, so a stand-in handle is enough,
        // and a plain number here would be a pointer it eventually follows.
        if (strncmp(p, "obj", 3) == 0) {
          ctx.x[slot++] = arc_jni_object();
          p += 3;
          if (*p == ',') ++p;
          continue;
        }
        // `str:TEXT` for a Java String argument. The engine reads these
        // through GetStringUTFChars, so a number in the slot is a pointer it
        // follows into nothing.
        if (strncmp(p, "str:", 4) == 0) {
          const char* comma = strchr(p + 4, ',');
          const std::string text(p + 4, comma ? comma - (p + 4)
                                              : strlen(p + 4));
          ctx.x[slot++] = arc_jni_string(text.c_str());
          p = comma ? comma + 1 : p + strlen(p);
          continue;
        }
        char* end = nullptr;
        const long long v = strtoll(p, &end, 0);
        if (end == p) break;
        ctx.x[slot++] = static_cast<uint64_t>(v);
        p = (*end == ',') ? end + 1 : end;
      }
      printf("  with %d argument(s) after the environment and object\n",
             slot - 2);
    }
    EntryCall call{};
    call_guest(addr, &call);
    const int rc = call.rc;
    const unsigned long code = call.code;
    printf("  JNI:\n");
    arc_jni_report();
    if (rc == 0) {
      printf("  returned, x0 = %#llx after %zu guest calls\n",
             static_cast<unsigned long long>(ctx.x[0]),
             arc_frame_seen());
      if (getenv("ARC_TRACE_FRAMES")) ReportFrames();
      for (const std::string& spec : peeks) ReportPeek(ctx.image_base, spec);
    }
    else if (rc == 1) {
      // A trap says what went wrong but not where. It is the same question a
      // fault raises, and was already answered there.
      printf("  %s\n", call.trap);
      ReportFrames();
      ReportRegisters(&ctx);
    } else {
      const std::string what = ExplainAddress(g_fault_address);
      printf("  %s on %s of %#llx%s%s\n", FaultName(code), g_fault_kind,
             static_cast<unsigned long long>(g_fault_address),
             what.empty() ? "" : " -- ", what.c_str());
      ReportFrames();
      ReportRegisters(&ctx);
    }
  }

  // The part Java does on Android: a thread that renders, presents, and hands
  // touches back in. Everything above this is setup that runs once; a title is
  // only actually running once something calls it again every frame.
  if (loop) {
    const char* kBridge = "Java_com_bight_android_jni_BGCoreJNIBridge_";
    const uint64_t render = g_image.Lookup(
        (std::string(kBridge) + "OGLESRender").c_str());
    const uint64_t resize = g_image.Lookup(
        (std::string(kBridge) + "OGLESResize").c_str());
    const uint64_t pressed = g_image.Lookup(
        (std::string(kBridge) + "pointerPressed").c_str());
    const uint64_t moved = g_image.Lookup(
        (std::string(kBridge) + "pointerMoved").c_str());
    const uint64_t released = g_image.Lookup(
        (std::string(kBridge) + "pointerReleased").c_str());
    if (!render) {
      fprintf(stderr, "no OGLESRender to loop on\n");
      return 1;
    }
    printf("\nrunning. close the window or press escape to stop.\n");
    // Arguments after the environment and the object, in the order the Java
    // declarations give them.
    auto call = [&](uint64_t fn, std::initializer_list<uint64_t> args) {
      if (!fn) return true;
      ctx.sp = stack_top;
      memset(ctx.x, 0, sizeof(ctx.x));
      ctx.x[0] = arc_jni_env();
      ctx.x[1] = arc_jni_object();
      int slot = 2;
      for (uint64_t a : args) ctx.x[slot++] = a;
      EntryCall c{};
      call_guest(fn, &c);
      if (c.rc == 0) return true;
      // A frame that faults will fault again next frame on the same state, so
      // stopping is the only outcome that reports rather than repeats.
      if (c.rc == 1) printf("\n%s\n", c.trap);
      else
        printf("\n%s on %s of %#llx -- %s\n", FaultName(c.code), g_fault_kind,
               static_cast<unsigned long long>(g_fault_address),
               ExplainAddress(g_fault_address).c_str());
      ReportFrames();
      ReportRegisters(&ctx);
      return false;
    };
    bool alive = true;
    long frames = 0;
    while (alive && window.PumpEvents()) {
      if (window.TakeResized())
        alive = call(resize, {static_cast<uint64_t>(window.width()),
                              static_cast<uint64_t>(window.height())});
      arc::Window::Pointer p;
      while (alive && window.NextPointer(&p)) {
        const uint64_t x = static_cast<uint32_t>(p.x);
        const uint64_t y = static_cast<uint32_t>(p.y);
        const uint64_t fx = static_cast<uint32_t>(p.from_x);
        const uint64_t fy = static_cast<uint32_t>(p.from_y);
        if (p.kind == arc::Window::Pointer::Down)
          alive = call(pressed, {x, y, 0});
        else if (p.kind == arc::Window::Pointer::Move)
          alive = call(moved, {x, y, fx, fy, 0});
        else
          alive = call(released, {x, y, 0});
      }
      if (!alive) break;
      alive = call(render, {});
      // The guest thread gives the context up when it returns, so the present
      // -- and a capture, which is a GL call like any other -- has to take it.
      std::string err;
      if (!window.MakeCurrent(&err)) {
        // Silently skipping the present here is how a frame that rendered
        // perfectly still reaches nobody.
        static bool said = false;
        if (!said) {
          said = true;
          printf("  cannot take the GL context to present: %s\n", err.c_str());
        }
      } else {
        ++frames;
        if (shot && frames == (frame_limit ? frame_limit : 1))
          SaveFrame(shot, window.width(), window.height());
        window.Present();
        window.ReleaseCurrent();
      }
      if (frame_limit && frames >= frame_limit) break;
    }
  }
  return 0;
}
