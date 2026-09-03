#include "shim.h"

#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#if defined(_WIN32)
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#if defined(ARC_HAVE_ZLIB)
#include <zlib.h>
#endif

namespace arc {
namespace {

// --- layer 1: Android-only entry points ------------------------------------
// liblog. The engine is chatty; routing this to stderr on the first run is how
// you find out what it is unhappy about.

int AndroidLogVPrint(int prio, const char* tag, const char* fmt, va_list ap) {
  fprintf(stderr, "[%d] %s: ", prio, tag ? tag : "?");
  int n = vfprintf(stderr, fmt, ap);
  fputc('\n', stderr);
  return n;
}

int AndroidLogPrint(int prio, const char* tag, const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  int n = AndroidLogVPrint(prio, tag, fmt, ap);
  va_end(ap);
  return n;
}

int AndroidLogWrite(int prio, const char* tag, const char* text) {
  return fprintf(stderr, "[%d] %s: %s\n", prio, tag ? tag : "?",
                 text ? text : "");
}

// Bionic's FORTIFY_SOURCE variants. Each takes the destination buffer's known
// size as an extra argument and traps on overflow. We are not trying to
// reproduce the diagnostics, only the semantics, so each forwards to the
// unchecked function -- which is exactly what Bionic does when the size is not
// known at compile time.
void* MemcpyChk(void* d, const void* s, size_t n, size_t) { return memcpy(d, s, n); }
void* MemmoveChk(void* d, const void* s, size_t n, size_t) { return memmove(d, s, n); }
char* StrcpyChk(char* d, const char* s, size_t) { return strcpy(d, s); }
char* StrcatChk(char* d, const char* s, size_t) { return strcat(d, s); }
size_t StrlenChk(const char* s, size_t) { return strlen(s); }
char* StrchrChk(const char* s, int c, size_t) {
  return const_cast<char*>(strchr(s, c));
}
int VsnprintfChk(char* d, size_t n, int, size_t, const char* fmt, va_list ap) {
  return vsnprintf(d, n, fmt, ap);
}

[[noreturn]] void Assert2(const char* file, int line, const char* func,
                          const char* msg) {
  fprintf(stderr, "%s:%d: %s: assertion failed: %s\n", file, line,
          func ? func : "?", msg ? msg : "");
  abort();
}

[[noreturn]] void StackChkFail() {
  fprintf(stderr, "stack protector: canary overwritten\n");
  abort();
}

// A data symbol, not a function -- the resolver hands back the address of real
// storage and the engine reads the canary out of it.
uintptr_t g_stack_chk_guard = 0;

int* Errno() { return &errno; }

// The engine registers destructors for its 1,527 static objects here. We never
// unload the image, so there is nothing to run them at, and recording them
// would be bookkeeping with no reader.
int CxaAtexit(void (*)(void*), void*, void*) { return 0; }
void CxaFinalize(void*) {}

struct Entry {
  const char* name;
  void* fn;
};

const Entry kExplicit[] = {
    {"__android_log_print", reinterpret_cast<void*>(&AndroidLogPrint)},
    {"__android_log_vprint", reinterpret_cast<void*>(&AndroidLogVPrint)},
    {"__android_log_write", reinterpret_cast<void*>(&AndroidLogWrite)},
    {"__memcpy_chk", reinterpret_cast<void*>(&MemcpyChk)},
    {"__memmove_chk", reinterpret_cast<void*>(&MemmoveChk)},
    {"__strcpy_chk", reinterpret_cast<void*>(&StrcpyChk)},
    {"__strcat_chk", reinterpret_cast<void*>(&StrcatChk)},
    {"__strlen_chk", reinterpret_cast<void*>(&StrlenChk)},
    {"__strchr_chk", reinterpret_cast<void*>(&StrchrChk)},
    {"__vsnprintf_chk", reinterpret_cast<void*>(&VsnprintfChk)},
    {"__assert2", reinterpret_cast<void*>(&Assert2)},
    {"__stack_chk_fail", reinterpret_cast<void*>(&StackChkFail)},
    {"__stack_chk_guard", reinterpret_cast<void*>(&g_stack_chk_guard)},
    {"__errno", reinterpret_cast<void*>(&Errno)},
    {"__cxa_atexit", reinterpret_cast<void*>(&CxaAtexit)},
    {"__cxa_finalize", reinterpret_cast<void*>(&CxaFinalize)},

#if defined(ARC_HAVE_ZLIB)
    // Statically linked libraries bind by explicit address: they are inside
    // our own executable, so a by-name runtime lookup cannot see them. This is
    // the pattern OpenAL and the GL loader follow too. Bionic's zlib is stock
    // zlib, so every signature matches.
    {"zlibVersion", reinterpret_cast<void*>(&zlibVersion)},
    {"deflate", reinterpret_cast<void*>(&deflate)},
    {"deflateEnd", reinterpret_cast<void*>(&deflateEnd)},
    {"deflateReset", reinterpret_cast<void*>(&deflateReset)},
    {"deflateInit_", reinterpret_cast<void*>(&deflateInit_)},
    {"deflateInit2_", reinterpret_cast<void*>(&deflateInit2_)},
    {"inflate", reinterpret_cast<void*>(&inflate)},
    {"inflateEnd", reinterpret_cast<void*>(&inflateEnd)},
    {"inflateReset", reinterpret_cast<void*>(&inflateReset)},
    {"inflateInit_", reinterpret_cast<void*>(&inflateInit_)},
    {"inflateInit2_", reinterpret_cast<void*>(&inflateInit2_)},
    {"crc32", reinterpret_cast<void*>(&crc32)},
#endif
};

// --- layer 2: same function, different name on this host --------------------
// Every entry here must be ABI-identical, not merely similar. `mkdir` is the
// cautionary case: Bionic takes (path, mode), the Microsoft CRT's `_mkdir`
// takes (path). Aliasing those would compile, link, run, and corrupt the
// stack. Anything whose signature differs is deliberately left unresolved so
// it shows up in the work list and gets a real wrapper.
struct Alias {
  const char* from;
  const char* to;
};

const Alias kAliases[] = {
#if defined(_WIN32)
    {"strdup", "_strdup"},
    {"strcasecmp", "_stricmp"},
    {"strncasecmp", "_strnicmp"},
    {"fileno", "_fileno"},
    {"isatty", "_isatty"},
    {"unlink", "_unlink"},
    {"putenv", "_putenv"},
#endif
};

// --- layer 3: the host C runtime -------------------------------------------

void* HostLookup(const char* name) {
#if defined(_WIN32)
  // The UCRT is where the standard C library actually lives; the
  // api-ms-win-crt-* names are forwarders onto it.
  static HMODULE ucrt = GetModuleHandleA("ucrtbase.dll")
                            ? GetModuleHandleA("ucrtbase.dll")
                            : LoadLibraryA("ucrtbase.dll");
  return ucrt ? reinterpret_cast<void*>(GetProcAddress(ucrt, name)) : nullptr;
#else
  return dlsym(RTLD_DEFAULT, name);
#endif
}

}  // namespace

uint64_t ShimResolve(const char* name) {
  if (uint64_t a = ShimResolvePthread(name)) return a;
  if (uint64_t a = ShimResolvePosix(name)) return a;
  if (uint64_t a = ShimResolveGL(name)) return a;

  for (const Entry& e : kExplicit)
    if (strcmp(e.name, name) == 0) return reinterpret_cast<uint64_t>(e.fn);

  for (const Alias& a : kAliases)
    if (strcmp(a.from, name) == 0)
      return reinterpret_cast<uint64_t>(HostLookup(a.to));

  return reinterpret_cast<uint64_t>(HostLookup(name));
}

size_t ShimExplicitCount() { return sizeof(kExplicit) / sizeof(kExplicit[0]); }

}  // namespace arc
