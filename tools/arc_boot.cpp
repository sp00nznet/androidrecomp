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
#include <atomic>
#include <chrono>
#include <thread>
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
#include <dbghelp.h>
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
// The subset of those the lifted program actually covers, which is the only
// subset whose symbols an import may be bound to.
std::vector<arc::ElfImage*> g_lifted_deps;

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
#if defined(_WIN32)
bool ReadableHere(const void* at, size_t n);
#endif

void ReportPeek(uint64_t image_base, const std::string& spec_in) {
  std::string spec = spec_in;
  const bool deref_each = !spec.empty() && spec.back() == '*';
  if (deref_each) spec.pop_back();
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
  // A trailing "*" says the range is an array of pointers, and prints what
  // each one points at rather than the pointer. That is the shape of a
  // std::vector of polymorphic objects, where the interesting word is each
  // element's vtable -- and picking the one element out of a thousand whose
  // vtable is not what its neighbours' are is otherwise a run per element.
  if (deref_each) {
    for (size_t i = 0; i + 8 <= len; i += 8) {
      uint64_t slot = 0;
      memcpy(&slot, p + i, sizeof slot);
      uint64_t word = 0;
      bool readable = false;
#if defined(_WIN32)
      readable = slot >= 0x10000 && ReadableHere(
                                        reinterpret_cast<const void*>(slot),
                                        sizeof word);
#else
      readable = slot >= 0x10000;
#endif
      if (readable) memcpy(&word, reinterpret_cast<const void*>(slot),
                           sizeof word);
      printf("    [%zu] %#llx -> %#llx\n", i / 8,
             static_cast<unsigned long long>(slot),
             static_cast<unsigned long long>(word));
    }
    return;
  }
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
  // Sixteen is enough to see which call faulted and cheap enough to print
  // on every trap. The ring holds more, and a fault whose cause is a few
  // frames further back wants them: ARC_FRAME_TRAIL raises the cap.
  size_t cap = 16;
  if (const char* e = getenv("ARC_FRAME_TRAIL")) cap = strtoul(e, nullptr, 0);
  for (size_t i = 0; i < n && i < cap; ++i) {
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

// Whether eight bytes at this address can be read without faulting. The walk
// below follows a frame pointer the guest wrote, and faulting while reporting
// a fault loses the report that was the whole point.
bool GuestReadable(uint64_t at) {
#if defined(_WIN32)
  MEMORY_BASIC_INFORMATION mbi;
  if (!VirtualQuery(reinterpret_cast<void*>(at), &mbi, sizeof mbi)) return false;
  if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_GUARD)) return false;
  const DWORD readable = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                         PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                         PAGE_EXECUTE_WRITECOPY;
  if (!(mbi.Protect & readable)) return false;
  return at + 8 <= reinterpret_cast<uint64_t>(mbi.BaseAddress) + mbi.RegionSize;
#else
  return at != 0;
#endif
}

// One guest code address, named the way the trail above names them.
void PrintGuestAddress(const char* lead, uint64_t addr) {
  for (const Mapping& m : g_mappings) {
    if (!m.image || addr < m.base || addr >= m.base + m.span) continue;
    uint64_t within = 0;
    const std::string sym = m.image->SymbolAt(addr, &within);
    printf("    %-4s %-22s +%#llx", lead, m.name.c_str(),
           static_cast<unsigned long long>(addr - m.base));
    if (!sym.empty())
      printf("  %s+%#llx", sym.c_str(),
             static_cast<unsigned long long>(within));
    printf("\n");
    return;
  }
  printf("    %-4s %#018llx\n", lead, static_cast<unsigned long long>(addr));
}

// The guest call stack, walked through the frame pointer.
//
// Lifted code keeps ARM64's frame chain: a non-leaf function opens with
// `stp x29, x30, [sp, #-N]!` and sets x29 to that pair, so x29 points at the
// caller's x29 followed by the return address. Following it gives who called
// whom, which the entry trail above cannot: that records entries in the order
// they happened and says nothing about which had already returned. A fault
// deep in a shared helper is a different bug depending on who reached it.
void ReportGuestStack(const Arm64Ctx* c) {
  printf("  guest call stack, innermost first:\n");
  if (c->x[30]) PrintGuestAddress("in", c->x[30]);
  uint64_t fp = c->x[29];
  for (int depth = 0; depth < 64; ++depth) {
    if (!fp || (fp & 15) || !GuestReadable(fp) || !GuestReadable(fp + 8)) break;
    uint64_t next = 0, ret = 0;
    memcpy(&next, reinterpret_cast<const void*>(fp), sizeof next);
    memcpy(&ret, reinterpret_cast<const void*>(fp + 8), sizeof ret);
    if (!ret) break;
    PrintGuestAddress("from", ret);
    // Stacks grow down, so a caller's frame is always at a higher address.
    // Anything else is a chain that has been overwritten, and following it
    // prints fiction.
    if (next <= fp) break;
    fp = next;
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
#if defined(_WIN32)
bool ReadableHere(const void* at, size_t n) {
  MEMORY_BASIC_INFORMATION info;
  if (!VirtualQuery(at, &info, sizeof info)) return false;
  if (info.State != MEM_COMMIT) return false;
  const DWORD ok = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                   PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                   PAGE_EXECUTE_WRITECOPY;
  if (!(info.Protect & ok) || (info.Protect & PAGE_GUARD)) return false;
  // And it has to be n bytes inside *this* region: the next one up may be
  // unmapped, and a dump is not worth a second fault.
  const auto start = reinterpret_cast<const char*>(info.BaseAddress);
  const auto here = reinterpret_cast<const char*>(at);
  return static_cast<size_t>(here - start) + n <= info.RegionSize;
}
#endif

// What the registers point at, for the ones that point at anything.
//
// A register dump names an address; the bytes there name the object. Engine
// objects carry their own identity -- a std::string with a pack's name, a
// four-byte tag, a vtable pointer that places the class -- and the field that
// actually held the bad value is usually a long way into the object, so this
// prints enough of it to reach one. Where a value here looks like a pointer to
// another object, ARC_DUMP_DEEP follows it one level: a field that is -1 says
// nothing on its own, and the object that owns it says everything.
void DumpBytes(const char* label, uint64_t at, size_t want) {
  char bytes[0x100];
  if (want > sizeof bytes) want = sizeof bytes;
#if defined(_WIN32)
  // Reading it is the whole risk, so ask first rather than fault inside the
  // fault report.
  while (want && !ReadableHere(reinterpret_cast<const void*>(at), want))
    want /= 2;
  if (!want) return;
#endif
  memcpy(bytes, reinterpret_cast<const void*>(at), want);
  for (size_t i = 0; i < want; i += 16) {
    printf("    %-8s +%03zx  ", i ? "" : label, i);
    for (size_t j = 0; j < 16; ++j)
      printf("%s", j < want - i ? "" : "   ");
    for (size_t j = 0; j < 16 && i + j < want; ++j)
      printf("%02x%s", static_cast<unsigned char>(bytes[i + j]),
             (j % 8) == 7 ? " " : "");
    printf(" |");
    for (size_t j = 0; j < 16 && i + j < want; ++j)
      putchar(bytes[i + j] >= 32 && bytes[i + j] < 127 ? bytes[i + j] : '.');
    printf("|\n");
  }
}

void ReportPointedAt(const Arm64Ctx* c) {
  // Deliberately narrow: the callee-saved registers plus the first two
  // arguments are where a `this` lives, and dumping all thirty-one buries it.
  static const int kInteresting[] = {0, 1, 19, 20, 21, 22};
  // How much of each object, and whether to follow the pointers inside it.
  // Default is small because most faults are answered by the first line.
  static const char* deep = getenv("ARC_DUMP_DEEP");
  const size_t span = deep ? strtoull(deep, nullptr, 0) : 32;
  bool any = false;
  for (int which : kInteresting) {
    const uint64_t at = c->x[which];
    if (at < 0x10000) continue;
    if (!any) {
      printf("  what they point at:\n");
      any = true;
    }
    char label[8];
    snprintf(label, sizeof label, "x%d", which);
    DumpBytes(label, at, span ? span : 32);
    // One level down, at an offset the reader names. A field holding -1 says
    // nothing about which object owns it; the object at the pointer beside it
    // usually says everything, and its name is often literally in there.
    static const char* follow = getenv("ARC_DUMP_FOLLOW");
    if (!follow) continue;
    for (const char* p = follow; *p;) {
      const uint64_t off = strtoull(p, nullptr, 16);
      const char* comma = strchr(p, ',');
      p = comma ? comma + 1 : p + strlen(p);
      uint64_t inner = 0;
#if defined(_WIN32)
      if (!ReadableHere(reinterpret_cast<const void*>(at + off), sizeof inner))
        continue;
#endif
      memcpy(&inner, reinterpret_cast<const void*>(at + off), sizeof inner);
      if (inner < 0x10000) continue;
      char deeper[24];
      snprintf(deeper, sizeof deeper, "x%d+%llx", which,
               static_cast<unsigned long long>(off));
      DumpBytes(deeper, inner, span ? span : 32);
    }
  }
}

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
  ReportPointedAt(c);
  ReportGuestStack(c);
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

// A frame that never ends looks exactly like a slow one from outside. On
// Windows it looks like a window that stopped responding, which is all the
// user is ever told: the loop is inside the guest and never comes back to
// pump messages. The guest is blocked somewhere specific, and being blocked
// is the one state where reading its stack from another thread is safe --
// nothing is moving. ARC_STALL_SECONDS, 30 by default, 0 to switch it off.
std::atomic<long> g_frames_done{0};

void StartStallWatch(const Arm64Ctx* c) {
  const char* s = getenv("ARC_STALL_SECONDS");
  const long limit = s ? strtol(s, nullptr, 10) : 30;
  if (limit <= 0) return;
  std::thread([c, limit] {
    long seen = -1, still = 0;
    bool said = false;
    for (;;) {
      std::this_thread::sleep_for(std::chrono::seconds(1));
      const long now = g_frames_done.load();
      if (now != seen) { seen = now; still = 0; said = false; continue; }
      if (++still < limit || said) continue;
      said = true;
      printf("\nno frame completed in %ld seconds -- the guest is blocked\n",
             still);
      ReportFrames();
      ReportTrail();
      ReportRegisters(c);
      fflush(stdout);
    }
  }).detach();
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

// And which code touched it. A guest address alone cannot say whether lifted
// code or a shim read it: both are compiled into this executable. The host
// program counter can, because this build has symbols -- so a fault can answer
// "inside AlGenBuffers" or "inside fn0_13e4410" instead of leaving a register
// dump to be read as tea leaves. That matters because a dumped guest context
// holds the *guest's* registers, which host code neither uses nor updates:
// read as the faulting state, it is a fiction.
uint64_t g_fault_pc;

std::string HostSymbol(uint64_t pc) {
  if (!pc) return std::string();
  static const bool ready =
      SymInitialize(GetCurrentProcess(), nullptr, TRUE) != 0;
  char buf[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = {};
  auto* info = reinterpret_cast<SYMBOL_INFO*>(buf);
  info->SizeOfStruct = sizeof(SYMBOL_INFO);
  info->MaxNameLen = MAX_SYM_NAME;
  DWORD64 delta = 0;
  char out[MAX_PATH + MAX_SYM_NAME];
  // The nearest symbol is reported *after* the module offset, never instead of
  // it. A Release build has no PDB, so SymFromAddr can only see what the image
  // exports -- and an executable exports almost nothing, so it answers with
  // whichever CRT internal happens to be nearest and a delta of any size. That
  // is not a location; the offset into the module is, and arc_boot.map turns
  // it into a name.
  HMODULE mod = nullptr;
  if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                             GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                         reinterpret_cast<LPCSTR>(pc), &mod) &&
      mod) {
    char path[MAX_PATH] = {};
    GetModuleFileNameA(mod, path, sizeof path);
    char nearby[MAX_SYM_NAME + 32] = {};
    if (ready && SymFromAddr(GetCurrentProcess(), pc, &delta, info))
      snprintf(nearby, sizeof nearby, " (nearest export %s+%#llx)", info->Name,
               static_cast<unsigned long long>(delta));
    const char* leaf = strrchr(path, '\\');
    snprintf(out, sizeof out, "%s+%#llx%s", leaf ? leaf + 1 : path,
             static_cast<unsigned long long>(pc -
                                             reinterpret_cast<uint64_t>(mod)),
             nearby);
    return out;
  }
  return std::string();
}

// The host stack at the fault, which is a different question from the guest's.
// A fault inside the C runtime says nothing about who called it, and the guest
// call stack cannot say either -- the call left the guest. RtlVirtualUnwind
// needs no symbols, only the unwind tables every x64 image carries, so this
// works in a Release build with no PDB.
uint64_t g_host_frames[24];
unsigned g_host_frame_count;

void CaptureHostStack(const CONTEXT* at) {
  g_host_frame_count = 0;
  if (!at) return;
  CONTEXT c = *at;
  for (unsigned i = 0; i < 24 && c.Rip; ++i) {
    g_host_frames[g_host_frame_count++] = c.Rip;
    DWORD64 image = 0;
    RUNTIME_FUNCTION* fn = RtlLookupFunctionEntry(c.Rip, &image, nullptr);
    if (!fn) {
      // A leaf with no unwind entry: the return address is at the top of the
      // stack, and one step by hand keeps the walk going.
      uint64_t ret = 0;
      if (!c.Rsp) break;
      memcpy(&ret, reinterpret_cast<void*>(c.Rsp), sizeof ret);
      if (!ret) break;
      c.Rip = ret;
      c.Rsp += 8;
      continue;
    }
    void* handler_data = nullptr;
    DWORD64 establisher = 0;
    RtlVirtualUnwind(UNW_FLAG_NHANDLER, image, c.Rip, fn, &c, &handler_data,
                     &establisher, nullptr);
  }
}

int FaultFilter(EXCEPTION_POINTERS* ep, unsigned long* code) {
  *code = ep->ExceptionRecord->ExceptionCode;
  g_fault_address = 0;
  g_fault_kind = "";
  g_fault_pc = ep->ContextRecord ? ep->ContextRecord->Rip : 0;
  CaptureHostStack(ep->ContextRecord);
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
uint64_t g_fault_pc;
std::string HostSymbol(uint64_t) { return std::string(); }
uint64_t g_host_frames[24];
unsigned g_host_frame_count;
#endif

void ReportHostStack() {
  if (!g_host_frame_count) return;
  printf("  host stack at the fault, innermost first:\n");
  for (unsigned i = 0; i < g_host_frame_count; ++i) {
    const std::string where = HostSymbol(g_host_frames[i]);
    printf("    %s\n", where.empty() ? "(unknown)" : where.c_str());
  }
}

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
  // A step, and when to take it. Android does not make every lifecycle call
  // before the first frame: an engine can queue what it is told and act on it
  // at the top of a frame, so a call issued before the loop and the same call
  // issued between frames are not the same call. at_frame says which -- 0 for
  // the setup that runs before anything is drawn, N to issue it at the top of
  // frame N instead.
  struct EntryStep {
    std::string name;
    std::string args;
    long at_frame = 0;
  };
  std::vector<EntryStep> entries;
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
      entries.push_back({argv[i] + 8, std::string(), 0});
    else if (strncmp(argv[i], "--args=", 7) == 0) {
      if (entries.empty()) {
        fprintf(stderr, "--args must follow an --entry\n");
        return 2;
      }
      entries.back().args = argv[i] + 7;
    }
    else if (strncmp(argv[i], "--entry-at=", 11) == 0) {
      if (entries.empty()) {
        fprintf(stderr, "--entry-at must follow an --entry\n");
        return 2;
      }
      const char* when = argv[i] + 11;
      if (strncmp(when, "frame:", 6) != 0) {
        fprintf(stderr, "--entry-at takes frame:N\n");
        return 2;
      }
      entries.back().at_frame = strtol(when + 6, nullptr, 10);
      if (entries.back().at_frame < 1) {
        fprintf(stderr, "--entry-at=frame:N wants N >= 1\n");
        return 2;
      }
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
            " [--entry=SYMBOL] [--args=N,N,...] [--entry-at=frame:N]"
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

  // Where an imported name is looked for, in order of preference.
  //
  // A dependency the APK ships wins over the shim -- it is the
  // implementation the title was built against. But only if the lifted
  // program covers it: an image that is mapped and *not* lifted is ARM code
  // the dispatcher has nothing to route a branch to, so binding an import
  // there is binding it to a dead end. The miss is reported on whichever
  // thread makes the call, and when that is the render thread it ends the
  // run -- which is how one unlifted audio library stopped a boot eight
  // seconds in, forty-four frames after the window opened.
  //
  // So: lifted dependencies, then the shim, then an unlifted dependency as a
  // last resort, because a branch that traps somewhere nameable is still
  // better than an unresolved import.
  auto resolve = [](const char* name) -> uint64_t {
    // Before anything, the short list of names the host has to win.
    if (uint64_t a = arc::ShimOverride(name)) return a;
    for (const auto& d : g_lifted_deps)
      if (uint64_t a = d->Lookup(name)) return a;
    if (uint64_t a = arc::ShimResolve(name)) return a;
    for (const auto& d : g_deps)
      if (uint64_t a = d->Lookup(name)) return a;
    return 0;
  };

  for (const std::string& need : arc::ElfImage::ReadNeeded(path.string())) {
    const std::filesystem::path p = dir / need;
    if (!std::filesystem::exists(p)) continue;
    auto img = std::make_unique<arc::ElfImage>();
    if (img->Load(p.string(), resolve, &err)) {
      arc::ShimRegisterImage(img.get());
      AnnounceImage(need, reinterpret_cast<uint64_t>(img->base()),
                    img->span(), img.get());
      bool lifted = false;
      for (size_t k = 0; k < ARC_IMAGE_COUNT; ++k) {
        const char* known = arc_image_name(k);
        if (known && need == known) { lifted = true; break; }
      }
      if (lifted) g_lifted_deps.push_back(img.get());
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
  arc_set_image_base(ctx.image_base);
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

  // One step, taken. A lambda rather than a loop body because the same call
  // has to be issuable from two places now: before anything is drawn, and at
  // the top of a frame. False means the symbol is not there, which is a
  // mistake in the command line rather than something the guest did.
  auto run_entry = [&](const EntryStep& step) -> bool {
    const char* entry = step.name.c_str();
    const char* entry_args = step.args.empty() ? nullptr
                                               : step.args.c_str();
    // A raw offset as well as a name. Plenty of the engine is internal
    // and stripped, and an unexported function is often exactly the one
    // worth calling to find out what it gates.
    const uint64_t addr =
        (entry[0] == '0' && (entry[1] == 'x' || entry[1] == 'X'))
            ? ctx.image_base + strtoull(entry + 2, nullptr, 16)
            : g_image.Lookup(entry);
    if (!addr) {
      fprintf(stderr, "\nno symbol named %s\n", entry);
      return false;
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
        // `self:TEXT` names the object the method is called *on*, rather
        // than an argument after it. Most JNI entry points ignore their
        // object, but a bridge whose Java half kept one object per component
        // does not: its native side asks Java which component this is, and
        // the only honest answer is the one the caller had in mind. Written
        // as an argument because that is where a command line can say it; it
        // replaces x1 rather than taking a slot.
        if (strncmp(p, "self:", 5) == 0) {
          const char* comma = strchr(p + 5, ',');
          const std::string text(p + 5, comma ? comma - (p + 5)
                                              : strlen(p + 5));
          ctx.x[1] = arc_jni_string(text.c_str());
          p = comma ? comma + 1 : p + strlen(p);
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
      const std::string where = HostSymbol(g_fault_pc);
      if (!where.empty()) printf("  faulted in %s\n", where.c_str());
      ReportHostStack();
      printf("  %s on %s of %#llx%s%s\n", FaultName(code), g_fault_kind,
             static_cast<unsigned long long>(g_fault_address),
             what.empty() ? "" : " -- ", what.c_str());
      ReportFrames();
      ReportRegisters(&ctx);
    }
    return true;
  };

  for (const EntryStep& step : entries)
    if (step.at_frame == 0 && !run_entry(step)) return 1;

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
        {
          const std::string where = HostSymbol(g_fault_pc);
          if (!where.empty())
            printf("\nfaulted in %s\n", where.c_str());
          ReportHostStack();
        }
        printf("\n%s on %s of %#llx -- %s\n", FaultName(c.code), g_fault_kind,
               static_cast<unsigned long long>(g_fault_address),
               ExplainAddress(g_fault_address).c_str());
      ReportFrames();
      ReportRegisters(&ctx);
      // Everything the engine asked the JNI bridge for and could not be
      // answered, including during the frames -- the report otherwise only
      // prints per entry point, which is the part of a run where nothing
      // interesting happens.
      printf("  JNI:\n");
      arc_jni_report();
      // The frame loop is where a title actually spends its time, and a --peek
      // that only runs between entry points cannot see any of it. On a fault
      // it is exactly the state you want: whatever the engine was holding when
      // it came apart.
      for (const std::string& spec : peeks) ReportPeek(ctx.image_base, spec);
      return false;
    };
    bool alive = true;
    long frames = 0;
    // A step is taken once. The frame counter only advances when the present
    // succeeds, so keying purely off it would repeat a step every time the GL
    // context could not be taken.
    std::vector<char> issued(entries.size(), 0);
    StartStallWatch(&ctx);
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
      // Where a --entry-at=frame:N step belongs: after this frame's events,
      // before anything is drawn for it. Android hands an engine its lifecycle
      // messages and the engine acts on them at the top of a frame, so a call
      // made here is not the same call made before the loop -- which is the
      // whole reason for being able to say which.
      //
      // The observation is PvZ2Native's (OptiJuegos, MIT): its lifecycle
      // driver queues an AndroidAppEvent and drains the queue at the top of
      // every onDrawFrame rather than acting when the call arrives. No code
      // from it is used here; the scheduling idea is theirs.
      for (size_t i = 0; i < entries.size(); ++i)
        if (!issued[i] && entries[i].at_frame == frames + 1) {
          issued[i] = 1;
          if (!run_entry(entries[i])) return 1;
        }
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
        g_frames_done.store(frames);
        // What the guest is doing *now*, on a timer.
        //
        // A title that is running but not progressing is the hardest state to
        // read: no fault, no trap, no stall -- the frames keep coming and the
        // log goes quiet, because whatever it is waiting for it is waiting
        // for silently. The frame ring already knows which guest functions
        // are being entered; printing it every few seconds turns "it sits at
        // the loading screen" into a list of addresses, which is a list of
        // functions. ARC_WATCH_FRAMES=<seconds>.
        {
          static const long every = [] {
            const char* v = getenv("ARC_WATCH_FRAMES");
            return v ? strtol(v, nullptr, 10) : 0;
          }();
          static auto last = std::chrono::steady_clock::now();
          if (every > 0) {
            const auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - last)
                    .count() >= every) {
              last = now;
              printf("\nguest functions being entered, most recent first:\n");
              ReportFrames();
              // Cleared *after* reporting, so each dump is the interval just
              // gone rather than everything since the program started.
              arc_frame_clear();
              fflush(stdout);
            }
          }
        }
        if (shot && frames == (frame_limit ? frame_limit : 1))
          SaveFrame(shot, window.width(), window.height());
        window.Present();
        window.ReleaseCurrent();
      }
      if (frame_limit && frames >= frame_limit) break;
    }
    // Why the loop ended. Three things end it and they mean entirely
    // different problems: the window went away, the guest faulted on a call
    // we made, or the frame limit was reached. Ending silently made a title
    // that quit after eight seconds look exactly like one that was still
    // running and merely quiet -- which sent a whole investigation after the
    // wrong thing.
    printf("\nstopped after %ld frames: %s\n", frames,
           !alive ? "a call into the guest failed"
                  : (frame_limit && frames >= frame_limit)
                        ? "the frame limit was reached"
                        : "the window closed");
    fflush(stdout);
  }
  return 0;
}
