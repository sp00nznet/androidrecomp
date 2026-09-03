// POSIX, BSD and locale entry points the host CRT does not export by name.
//
// Three kinds of thing live here.
//
// Functions the host has but hides: MSVC defines `printf`, `sprintf`, `wmemcpy`
// and friends inline in its headers rather than exporting them from
// `ucrtbase.dll`, so a by-name lookup misses them even though the code is
// right there. Taking their address binds them.
//
// Functions the host has under different terms: `gmtime_r` and `gmtime_s` swap
// their arguments, `fseeko` is `_fseeki64`. Wrapped, never aliased.
//
// Functions only glibc/Bionic have: `asprintf`, `memrchr`, `strtok_r`.
// Written out.
//
// One rule decides several of these. Where the guest allocated a struct and we
// fill it with the host's version, writing a *smaller* host struct into a
// *larger* guest allocation is safe -- the leading fields line up and the tail
// is untouched. The reverse silently corrupts whatever follows. Bionic's
// `struct tm` carries two fields more than the Microsoft CRT's, so filling it
// from the host is safe. Bionic's `FILE` is the case where the rule bites, and
// `__sF` is deliberately left unresolved rather than guessed at.

#include <cctype>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cwchar>
#include <cmath>
#include <cwctype>
#include <chrono>
#include <thread>

#include "shim.h"

#if defined(_WIN32)
#include <windows.h>
#endif

namespace arc {
namespace {

// --- time ------------------------------------------------------------------
// Bionic's timespec/timeval on LP64: two 64-bit fields each.
struct GuestTimespec {
  int64_t tv_sec;
  int64_t tv_nsec;
};
struct GuestTimeval {
  int64_t tv_sec;
  int64_t tv_usec;
};

int ClockGettime(int /*clock_id*/, GuestTimespec* ts) {
  // ponytail: every clock id answered from the system clock. Split out a
  // steady clock for CLOCK_MONOTONIC if the engine ever measures deltas across
  // a wall-clock adjustment and misbehaves.
  const auto now = std::chrono::system_clock::now().time_since_epoch();
  const auto sec = std::chrono::duration_cast<std::chrono::seconds>(now);
  ts->tv_sec = sec.count();
  ts->tv_nsec =
      std::chrono::duration_cast<std::chrono::nanoseconds>(now - sec).count();
  return 0;
}

int Gettimeofday(GuestTimeval* tv, void*) {
  GuestTimespec ts;
  ClockGettime(0, &ts);
  tv->tv_sec = ts.tv_sec;
  tv->tv_usec = ts.tv_nsec / 1000;
  return 0;
}

int Nanosleep(const GuestTimespec* req, GuestTimespec*) {
  std::this_thread::sleep_for(std::chrono::seconds(req->tv_sec) +
                              std::chrono::nanoseconds(req->tv_nsec));
  return 0;
}
int Usleep(unsigned useconds) {
  std::this_thread::sleep_for(std::chrono::microseconds(useconds));
  return 0;
}
unsigned Sleep_(unsigned seconds) {
  std::this_thread::sleep_for(std::chrono::seconds(seconds));
  return 0;
}

// The _r forms take their arguments the other way round from the Microsoft _s
// forms, so these are wrappers rather than aliases.
struct tm* GmtimeR(const time_t* t, struct tm* out) {
#if defined(_WIN32)
  return gmtime_s(out, t) == 0 ? out : nullptr;
#else
  return gmtime_r(t, out);
#endif
}
struct tm* LocaltimeR(const time_t* t, struct tm* out) {
#if defined(_WIN32)
  return localtime_s(out, t) == 0 ? out : nullptr;
#else
  return localtime_r(t, out);
#endif
}

long g_timezone = 0;  // data symbol

// --- BSD / glibc string helpers --------------------------------------------

void* Memrchr(const void* s, int c, size_t n) {
  const unsigned char* p = static_cast<const unsigned char*>(s);
  for (size_t i = n; i > 0; --i)
    if (p[i - 1] == static_cast<unsigned char>(c))
      return const_cast<unsigned char*>(p + i - 1);
  return nullptr;
}

char* StrtokR(char* str, const char* delim, char** saveptr) {
#if defined(_WIN32)
  return strtok_s(str, delim, saveptr);
#else
  return strtok_r(str, delim, saveptr);
#endif
}

int StrerrorR(int err, char* buf, size_t len) {
#if defined(_WIN32)
  return strerror_s(buf, len, err);
#else
  return strerror_r(err, buf, len);
#endif
}

int Vasprintf(char** out, const char* fmt, va_list ap) {
  va_list copy;
  va_copy(copy, ap);
  int n = vsnprintf(nullptr, 0, fmt, copy);
  va_end(copy);
  if (n < 0) return -1;
  *out = static_cast<char*>(malloc(static_cast<size_t>(n) + 1));
  if (!*out) return -1;
  return vsnprintf(*out, static_cast<size_t>(n) + 1, fmt, ap);
}

int Asprintf(char** out, const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  int n = Vasprintf(out, fmt, ap);
  va_end(ap);
  return n;
}

char* Basename(char* path) {
  if (!path || !*path) return const_cast<char*>(".");
  char* last = path;
  for (char* p = path; *p; ++p)
    if (*p == '/' || *p == '\\') last = p + 1;
  return last;
}

// --- wide character --------------------------------------------------------
// mbsnrtowcs/wcsnrtombs are GNU extensions: like mbsrtowcs but with a limit on
// how many *source* bytes may be read, not just destination units.

size_t Mbsnrtowcs(wchar_t* dst, const char** src, size_t nms, size_t len,
                  mbstate_t* ps) {
  static mbstate_t fallback = {};
  if (!ps) ps = &fallback;
  size_t written = 0;
  const char* s = *src;
  while (nms > 0 && (!dst || written < len)) {
    wchar_t wc;
    size_t n = mbrtowc(&wc, s, nms, ps);
    if (n == static_cast<size_t>(-1) || n == static_cast<size_t>(-2)) return
        static_cast<size_t>(-1);
    if (n == 0) {  // hit the terminator
      if (dst) *src = nullptr;
      if (dst) dst[written] = 0;
      return written;
    }
    if (dst) dst[written] = wc;
    ++written;
    s += n;
    nms -= n;
  }
  if (dst) *src = s;
  return written;
}

size_t Wcsnrtombs(char* dst, const wchar_t** src, size_t nwc, size_t len,
                  mbstate_t* ps) {
  static mbstate_t fallback = {};
  if (!ps) ps = &fallback;
  size_t written = 0;
  const wchar_t* s = *src;
  char buf[MB_LEN_MAX];
  while (nwc > 0) {
    size_t n = wcrtomb(buf, *s, ps);
    if (n == static_cast<size_t>(-1)) return static_cast<size_t>(-1);
    if (dst && written + n > len) break;
    if (dst) memcpy(dst + written, buf, n);
    written += n;
    if (*s == 0) {
      if (dst) *src = nullptr;
      return written - 1;  // the terminator is not counted
    }
    ++s;
    --nwc;
  }
  if (dst) *src = s;
  return written;
}

// `wmemchr` and `swprintf` are overloaded in C++, so their addresses are
// ambiguous. Wrapping picks one and keeps the table uniform.
const wchar_t* Wmemchr(const wchar_t* s, wchar_t c, size_t n) {
  return wmemchr(s, c, n);
}
int Swprintf(wchar_t* buf, size_t n, const wchar_t* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  int r = vswprintf(buf, n, fmt, ap);
  va_end(ap);
  return r;
}


// --- Bionic data symbols ---------------------------------------------------
//
// `__sF` is the array behind stdin/stdout/stderr: the engine computes
// `&__sF[1]` for stdout using *its* sizeof(FILE), baked in when it was
// compiled. Rather than guess that stride -- a wrong guess hands the host CRT
// a wild FILE* -- we reserve a region and treat any pointer inside it as one
// of the standard streams: the base is stdin, anything else is stderr. A
// game's use of these is diagnostic output, so folding stdout into stderr
// costs nothing, and the stride never has to be known at all.
alignas(16) char g_sF[3 * 512];

FILE* Stream(FILE* f) {
  const char* p = reinterpret_cast<const char*>(f);
  if (p < g_sF || p >= g_sF + sizeof(g_sF)) return f;
  return p == g_sF ? stdin : stderr;
}

// Anything that takes a FILE* has to translate first, because the pointer may
// be one of the three above rather than one the host CRT handed out.
int Fprintf(FILE* f, const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  int n = vfprintf(Stream(f), fmt, ap);
  va_end(ap);
  return n;
}
int Vfprintf(FILE* f, const char* fmt, va_list ap) {
  return vfprintf(Stream(f), fmt, ap);
}
size_t Fwrite(const void* p, size_t sz, size_t n, FILE* f) {
  return fwrite(p, sz, n, Stream(f));
}
size_t Fread(void* p, size_t sz, size_t n, FILE* f) {
  return fread(p, sz, n, Stream(f));
}
int Fputs(const char* str, FILE* f) { return fputs(str, Stream(f)); }
int Fputc(int c, FILE* f) { return fputc(c, Stream(f)); }
int Fflush(FILE* f) { return fflush(f ? Stream(f) : nullptr); }
int Fclose(FILE* f) {
  // Closing a standard stream would take the host's own logging with it.
  FILE* h = Stream(f);
  return (h == stdin || h == stderr || h == stdout) ? 0 : fclose(h);
}

// Bionic's `_ctype_` is a 257-entry table indexed as `_ctype_[c + 1]`, with
// index 0 reserved for EOF. The classifications come from the host, so only
// the bit values below are assumed -- and a wrong bit shows up as character
// classification going astray, never as memory corruption.
constexpr unsigned char kCtypeUpper = 0x01, kCtypeLower = 0x02,
                        kCtypeDigit = 0x04, kCtypeSpace = 0x08,
                        kCtypePunct = 0x10, kCtypeControl = 0x20,
                        kCtypeHex = 0x40, kCtypeBlank = 0x80;

const unsigned char* BuildCtype() {
  static unsigned char table[257] = {};
  for (int c = 0; c < 256; ++c) {
    unsigned char f = 0;
    if (isupper(c)) f |= kCtypeUpper;
    if (islower(c)) f |= kCtypeLower;
    if (isdigit(c)) f |= kCtypeDigit;
    if (isspace(c)) f |= kCtypeSpace;
    if (ispunct(c)) f |= kCtypePunct;
    if (iscntrl(c)) f |= kCtypeControl;
    if (isxdigit(c)) f |= kCtypeHex;
    if (c == ' ' || c == '\t') f |= kCtypeBlank;
    table[c + 1] = f;
  }
  return table;
}
const unsigned char* g_ctype = BuildCtype();

// --- odds and ends ---------------------------------------------------------

void Sincosf(float x, float* sin_out, float* cos_out) {
  *sin_out = sinf(x);
  *cos_out = cosf(x);
}

int Getentropy(void* buf, size_t len) {
  auto* out = static_cast<unsigned char*>(buf);
#if defined(_WIN32)
  // RtlGenRandom, reached without dragging in the whole CryptoAPI header set.
  static auto gen = reinterpret_cast<BOOLEAN(WINAPI*)(PVOID, ULONG)>(
      GetProcAddress(LoadLibraryA("advapi32.dll"), "SystemFunction036"));
  if (gen && gen(out, static_cast<ULONG>(len))) return 0;
#endif
  for (size_t i = 0; i < len; ++i) out[i] = static_cast<unsigned char>(rand());
  return 0;
}

// ponytail: thread_local destructors are never run. We never unload an image
// and the process exits wholesale, so there is nothing for them to clean up
// before. Give this a real registry if a title starts leaning on them.
int CxaThreadAtexit(void (*)(void*), void*, void*) { return 0; }

struct Entry {
  const char* name;
  void* fn;
};

// --- locale ----------------------------------------------------------------
// Every `*_l` entry point is the plain function with a locale_t appended. The
// engine runs in the C locale, so each forwards and drops the argument. If a
// real locale ever matters, these are the functions to give bodies to.
#define LOCALE_FWD(name, ret, params, args)                \
  ret name##_l_impl params { return name args; }
// clang-format off
LOCALE_FWD(isdigit,  int, (int c, void*), (c))
LOCALE_FWD(islower,  int, (int c, void*), (c))
LOCALE_FWD(isupper,  int, (int c, void*), (c))
LOCALE_FWD(isxdigit, int, (int c, void*), (c))
LOCALE_FWD(tolower,  int, (int c, void*), (c))
LOCALE_FWD(toupper,  int, (int c, void*), (c))
LOCALE_FWD(iswalpha, int, (wint_t c, void*), (c))
LOCALE_FWD(iswblank, int, (wint_t c, void*), (c))
LOCALE_FWD(iswcntrl, int, (wint_t c, void*), (c))
LOCALE_FWD(iswdigit, int, (wint_t c, void*), (c))
LOCALE_FWD(iswlower, int, (wint_t c, void*), (c))
LOCALE_FWD(iswprint, int, (wint_t c, void*), (c))
LOCALE_FWD(iswpunct, int, (wint_t c, void*), (c))
LOCALE_FWD(iswspace, int, (wint_t c, void*), (c))
LOCALE_FWD(iswupper, int, (wint_t c, void*), (c))
LOCALE_FWD(iswxdigit,int, (wint_t c, void*), (c))
LOCALE_FWD(towlower, wint_t, (wint_t c, void*), (c))
LOCALE_FWD(towupper, wint_t, (wint_t c, void*), (c))
LOCALE_FWD(strcoll,  int, (const char* a, const char* b, void*), (a, b))
LOCALE_FWD(wcscoll,  int, (const wchar_t* a, const wchar_t* b, void*), (a, b))
// clang-format on
#undef LOCALE_FWD

size_t strxfrm_l_impl(char* d, const char* s, size_t n, void*) {
  return strxfrm(d, s, n);
}
size_t wcsxfrm_l_impl(wchar_t* d, const wchar_t* s, size_t n, void*) {
  return wcsxfrm(d, s, n);
}
long long strtoll_l_impl(const char* s, char** end, int base, void*) {
  return strtoll(s, end, base);
}
unsigned long long strtoull_l_impl(const char* s, char** end, int base, void*) {
  return strtoull(s, end, base);
}
long double strtold_l_impl(const char* s, char** end, void*) {
  return strtold(s, end);
}
size_t strftime_l_impl(char* buf, size_t n, const char* fmt, const struct tm* tm,
                       void*) {
  return strftime(buf, n, fmt, tm);
}

// A locale_t here is a token the engine only ever hands back to us.
void* NewLocale(int, const char*, void*) { return reinterpret_cast<void*>(1); }
void FreeLocale(void*) {}
void* UseLocale(void*) { return reinterpret_cast<void*>(1); }
size_t CtypeGetMbCurMax() { return MB_CUR_MAX; }

#define E(sym, fn) {sym, reinterpret_cast<void*>(&fn)}
const Entry kTable[] = {
    // time
    E("clock_gettime", ClockGettime),
    E("gettimeofday", Gettimeofday),
    E("nanosleep", Nanosleep),
    E("usleep", Usleep),
    E("sleep", Sleep_),
    E("gmtime_r", GmtimeR),
    E("localtime_r", LocaltimeR),
    E("timezone", g_timezone),
    E("time", time),
    E("mktime", mktime),
    E("difftime", difftime),
    E("gmtime", gmtime),
    E("localtime", localtime),
    E("ctime", ctime),

    // stdio the host hides behind inline definitions
    E("__sF", g_sF),
    E("_ctype_", g_ctype),
    E("fprintf", Fprintf),
    E("vfprintf", Vfprintf),
    E("fwrite", Fwrite),
    E("fread", Fread),
    E("fputs", Fputs),
    E("fputc", Fputc),
    E("fflush", Fflush),
    E("fclose", Fclose),
    E("sincosf", Sincosf),
    E("getentropy", Getentropy),
    E("__cxa_thread_atexit_impl", CxaThreadAtexit),
    E("printf", printf),
    E("sprintf", sprintf),
    E("snprintf", snprintf),
    E("sscanf", sscanf),
    E("vsnprintf", vsnprintf),
    E("vsscanf", vsscanf),
    E("vfprintf", vfprintf),
    E("asprintf", Asprintf),
    E("vasprintf", Vasprintf),

    // BSD / glibc string helpers
    E("memrchr", Memrchr),
    E("strtok_r", StrtokR),
    E("strerror_r", StrerrorR),
    E("basename", Basename),

    // wide character
    E("wmemchr", Wmemchr),
    E("wmemcmp", wmemcmp),
    E("wmemcpy", wmemcpy),
    E("wmemmove", wmemmove),
    E("wmemset", wmemset),
    E("swprintf", Swprintf),
    E("mbsnrtowcs", Mbsnrtowcs),
    E("wcsnrtombs", Wcsnrtombs),

    // locale
    E("isdigit_l", isdigit_l_impl),
    E("islower_l", islower_l_impl),
    E("isupper_l", isupper_l_impl),
    E("isxdigit_l", isxdigit_l_impl),
    E("tolower_l", tolower_l_impl),
    E("toupper_l", toupper_l_impl),
    E("iswalpha_l", iswalpha_l_impl),
    E("iswblank_l", iswblank_l_impl),
    E("iswcntrl_l", iswcntrl_l_impl),
    E("iswdigit_l", iswdigit_l_impl),
    E("iswlower_l", iswlower_l_impl),
    E("iswprint_l", iswprint_l_impl),
    E("iswpunct_l", iswpunct_l_impl),
    E("iswspace_l", iswspace_l_impl),
    E("iswupper_l", iswupper_l_impl),
    E("iswxdigit_l", iswxdigit_l_impl),
    E("towlower_l", towlower_l_impl),
    E("towupper_l", towupper_l_impl),
    E("strcoll_l", strcoll_l_impl),
    E("wcscoll_l", wcscoll_l_impl),
    E("strxfrm_l", strxfrm_l_impl),
    E("wcsxfrm_l", wcsxfrm_l_impl),
    E("strtoll_l", strtoll_l_impl),
    E("strtoull_l", strtoull_l_impl),
    E("strtold_l", strtold_l_impl),
    E("strftime_l", strftime_l_impl),
    E("newlocale", NewLocale),
    E("freelocale", FreeLocale),
    E("uselocale", UseLocale),
    E("__ctype_get_mb_cur_max", CtypeGetMbCurMax),
};
#undef E

}  // namespace

uint64_t ShimResolvePosix(const char* name) {
  for (const Entry& e : kTable)
    if (strcmp(e.name, name) == 0) return reinterpret_cast<uint64_t>(e.fn);
  return 0;
}

size_t ShimPosixCount() { return sizeof(kTable) / sizeof(kTable[0]); }

}  // namespace arc
