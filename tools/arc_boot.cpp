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

int main(int argc, char** argv) {
  // Unbuffered: this program runs code that can abort the process, and
  // block-buffered output redirected to a file dies with it -- which turns a
  // diagnosable crash into an empty log.
  setvbuf(stdout, nullptr, _IONBF, 0);
  setvbuf(stderr, nullptr, _IONBF, 0);

  const char* lib = nullptr;
  const char* entry = nullptr;
  const char* entry_args = nullptr;
  long ctor_limit = 0;
  bool want_window = false;
  const char* gl_version = nullptr;
  for (int i = 1; i < argc; ++i) {
    if (strncmp(argv[i], "--entry=", 8) == 0)
      entry = argv[i] + 8;
    else if (strncmp(argv[i], "--args=", 7) == 0)
      entry_args = argv[i] + 7;
    else if (strcmp(argv[i], "--window") == 0)
      want_window = true;
    else if (strncmp(argv[i], "--gl=", 5) == 0)
      gl_version = argv[i] + 5;
    else if (strncmp(argv[i], "--constructors=", 15) == 0)
      ctor_limit = strtol(argv[i] + 15, nullptr, 10);
    else
      lib = argv[i];
  }
  if (!lib) {
    fprintf(stderr,
            "usage: %s [--window] [--constructors=N] [--entry=SYMBOL]"
            " [--args=N,N,...] <library.so>\n",
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

  const std::filesystem::path path(lib);
  const std::filesystem::path dir = path.parent_path();
  std::string err;

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

  printf("image      %s at %p\n", path.filename().string().c_str(),
         static_cast<void*>(g_image.base()));
  printf("imports    %zu host functions, %zu satisfied by unlifted guest "
         "images, %zu unresolved\n", natives, guest_side, g_unresolved.size());
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

  if (entry) {
    const uint64_t addr = g_image.Lookup(entry);
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
    call.ctx = &ctx;
    call.target = addr;
    call.window = want_window ? &window : nullptr;
    // Given up here so the guest's thread can take it: a context is current on
    // one thread at a time, and claiming it elsewhere while this one still
    // holds it fails.
    if (want_window) window.ReleaseCurrent();
#if defined(_WIN32)
    // 512 MB reserved. It is address space, not memory: only the pages the
    // guest actually touches are ever committed.
    HANDLE th = CreateThread(nullptr, 512u << 20, RunEntry, &call, 0, nullptr);
    if (th) {
      WaitForSingleObject(th, INFINITE);
      CloseHandle(th);
    } else {
      call.rc = CallGuarded(&ctx, addr, &call.code);
    }
#else
    call.rc = CallGuarded(&ctx, addr, &call.code);
#endif
    const int rc = call.rc;
    const unsigned long code = call.code;
    printf("  JNI:\n");
    arc_jni_report();
    if (rc == 0)
      printf("  returned, x0 = %#llx\n",
             static_cast<unsigned long long>(ctx.x[0]));
    else if (rc == 1) {
      // A trap says what went wrong but not where. It is the same question a
      // fault raises, and was already answered there.
      printf("  %s\n", call.trap);
      ReportFrames();
    } else {
      const std::string what = ExplainAddress(g_fault_address);
      printf("  %s on %s of %#llx%s%s\n", FaultName(code), g_fault_kind,
             static_cast<unsigned long long>(g_fault_address),
             what.empty() ? "" : " -- ", what.c_str());
      ReportFrames();
      ReportRegisters(&ctx);
    }
  }
  return 0;
}
