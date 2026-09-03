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
#include "shim.h"

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
};
std::vector<Mapping> g_mappings;

std::string ExplainAddress(uint64_t addr) {
  for (const auto& u : g_unresolved)
    if (u.first == addr)
      return "unresolved import " + u.second;
  for (const Mapping& m : g_mappings) {
    if (addr >= m.base && addr < m.base + m.span) {
      char buf[160];
      snprintf(buf, sizeof(buf), "inside %s at +%#llx", m.name.c_str(),
               static_cast<unsigned long long>(addr - m.base));
      return buf;
    }
  }
  return "not in any mapped image";
}

constexpr size_t kGuestStack = 8 * 1024 * 1024;

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
  const char* lib = nullptr;
  const char* entry = nullptr;
  long ctor_limit = 0;
  for (int i = 1; i < argc; ++i) {
    if (strncmp(argv[i], "--entry=", 8) == 0)
      entry = argv[i] + 8;
    else if (strncmp(argv[i], "--constructors=", 15) == 0)
      ctor_limit = strtol(argv[i] + 15, nullptr, 10);
    else
      lib = argv[i];
  }
  if (!lib) {
    fprintf(stderr,
            "usage: %s [--constructors=N] [--entry=SYMBOL] <library.so>\n",
            argv[0]);
    return 2;
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
      g_mappings.push_back({need, reinterpret_cast<uint64_t>(img->base()),
                            img->span()});
      g_deps.push_back(std::move(img));
    }
  }
  if (!g_image.Load(path.string(), resolve, &err)) {
    fprintf(stderr, "load failed: %s\n", err.c_str());
    return 1;
  }
  arc::ShimRegisterImage(&g_image);
  g_mappings.push_back({path.filename().string(),
                        reinterpret_cast<uint64_t>(g_image.base()),
                        g_image.span()});

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

  printf("image      %s at %p\n", path.filename().string().c_str(),
         static_cast<void*>(g_image.base()));
  printf("imports    %zu host functions, %zu satisfied by unlifted guest "
         "images, %zu unresolved\n", natives, guest_side, g_unresolved.size());
  printf("\nmapped images\n");
  for (const Mapping& m : g_mappings)
    printf("  %-22s %#018llx .. %#018llx\n", m.name.c_str(),
           static_cast<unsigned long long>(m.base),
           static_cast<unsigned long long>(m.base + m.span));

  std::vector<uint8_t> stack(kGuestStack);
  Arm64Ctx ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.image_base = reinterpret_cast<uint64_t>(g_image.base());
  ctx.sp = (reinterpret_cast<uint64_t>(stack.data()) + kGuestStack - 64) & ~15ULL;

  const std::vector<uint64_t>& ctors = g_image.init_array();
  const size_t total = ctor_limit > 0 && static_cast<size_t>(ctor_limit) < ctors.size()
                           ? static_cast<size_t>(ctor_limit)
                           : ctors.size();
  printf("\nrunning %zu of %zu static constructors\n", total, ctors.size());

  size_t ok = 0, trapped = 0, faulted = 0;
  std::vector<std::string> first_failures;
  std::vector<std::pair<uint64_t, size_t>> fault_sites;
  for (size_t i = 0; i < total; ++i) {
    // Each constructor starts from a clean frame; a previous failure must not
    // leave the stack pointer somewhere strange.
    ctx.sp = (reinterpret_cast<uint64_t>(stack.data()) + kGuestStack - 64) & ~15ULL;
    unsigned long code = 0;
    const int rc = CallGuarded(&ctx, ctors[i], &code);
    if (rc == 0) {
      ++ok;
      continue;
    }
    if (rc == 1) {
      ++trapped;
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
    }
  }

  printf("  %zu ran, %zu trapped, %zu faulted\n", ok, trapped, faulted);
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
    ctx.sp = (reinterpret_cast<uint64_t>(stack.data()) + kGuestStack - 64) & ~15ULL;
    unsigned long code = 0;
    const int rc = CallGuarded(&ctx, addr, &code);
    if (rc == 0)
      printf("  returned, x0 = %#llx\n",
             static_cast<unsigned long long>(ctx.x[0]));
    else if (rc == 1)
      printf("  %s\n", arc_last_trap());
    else {
      const std::string what = ExplainAddress(g_fault_address);
      printf("  %s touching %#llx%s%s\n", FaultName(code),
             static_cast<unsigned long long>(g_fault_address),
             what.empty() ? "" : " -- ", what.c_str());
    }
  }
  return 0;
}
