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

#include <algorithm>
#include <cctype>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cwchar>
#include <cmath>
#include <cwctype>
#include <mutex>
#include <numeric>
#include <random>
#include <vector>
#include <chrono>
#include <thread>

#include "arm64_context.h"
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

// Bionic's clock ids. Only the split matters: the realtime ones are a date,
// the rest are a stopwatch.
constexpr int kClockRealtime = 0;
constexpr int kClockRealtimeCoarse = 5;

// One origin, shared. Two monotonic clocks with two origins is not a smaller
// version of the same bug -- it is the same bug: a caller that starts a
// stopwatch on one and reads it on the other measures the distance between
// their origins rather than any elapsed time, every time, from the first
// reading. Here that distance was a minute, so every network timeout in the
// program had already expired when it was set, and every request was
// abandoned and remade as fast as the machine could do it.
std::chrono::steady_clock::duration MonotonicSinceStart() {
  static const auto start = std::chrono::steady_clock::now();
  // Offset by a minute, because a device has been up a while by the time a
  // game starts and some code treats a monotonic reading near zero as "no
  // reading yet". The offset belongs to the clock rather than to one of its
  // two readers, which is the point: whatever it is, both see the same one.
  return std::chrono::steady_clock::now() - start + std::chrono::seconds(60);
}

int ClockGettime(int clock_id, GuestTimespec* ts) {
  // CLOCK_MONOTONIC is seconds since boot, not seconds since 1970, and the
  // difference is not cosmetic. Answered from the wall clock it reads about
  // 1.7e9, and a caller that turns a delta into milliseconds is doing that
  // arithmetic on a number a billion times larger than it expects. An HTTP
  // client is the first thing to notice: every connect it starts is measured
  // against a deadline, and a deadline computed from the wrong magnitude has
  // already passed. The connection opens, is judged to have timed out before
  // it can finish, and is closed and retried forever.
  //
  // The epoch is this process's start, which is what a monotonic clock is
  // allowed to be and keeps the numbers small.
  // ARC_CLOCK_WALL answers every id from the wall clock, which is what this
  // did before. Kept because a caller that mixes time() with a monotonic
  // reading is comparing two epochs, and which epoch is the wrong one is
  // then a question about the caller, not about correctness here.
  static const bool wall = getenv("ARC_CLOCK_WALL") != nullptr;
  if (wall || clock_id == kClockRealtime || clock_id == kClockRealtimeCoarse) {
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    const auto sec = std::chrono::duration_cast<std::chrono::seconds>(now);
    ts->tv_sec = sec.count();
    ts->tv_nsec =
        std::chrono::duration_cast<std::chrono::nanoseconds>(now - sec).count();
    return 0;
  }
  const auto now = MonotonicSinceStart();
  const auto sec = std::chrono::duration_cast<std::chrono::seconds>(now);
  ts->tv_sec = sec.count();
  ts->tv_nsec =
      std::chrono::duration_cast<std::chrono::nanoseconds>(now - sec).count();
  return 0;
}

// A wall clock the host can be asked to lie about.
//
// Seasonal content is a comparison between now and a window, so "does this
// depend on the date at all" is answered by moving the date and looking.
// ARC_FAKE_TIME=<epoch seconds> shifts every wall-clock reading by a constant
// so the run believes it is then; the monotonic clock is left alone, because
// timeouts and frame pacing are not what is being asked about.
int64_t ClockSkew() {
  static const int64_t skew = [] {
    const char* when = getenv("ARC_FAKE_TIME");
    if (!when) return (int64_t)0;
    return (int64_t)strtoll(when, nullptr, 10) - (int64_t)time(nullptr);
  }();
  return skew;
}

time_t TimeNow(time_t* out) {
  const time_t now = time(nullptr) + (time_t)ClockSkew();
  if (out) *out = now;
  return now;
}

int Gettimeofday(GuestTimeval* tv, void*) {
  GuestTimespec ts;
  ClockGettime(kClockRealtime, &ts);
  tv->tv_sec = ts.tv_sec + ClockSkew();
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

// Bionic's `struct tm`, which carries two fields the Microsoft CRT's does not.
//
// The note at the top of this file says filling a larger guest struct from a
// smaller host one is safe because the tail is untouched. For this struct that
// is wrong, and the engine is what proves it: NimbleCppUtility's
// getLocalTimeZone() calls localtime and then strlen on tm_zone at +0x30
// without a null check. Untouched tail means whatever the caller's memory held
// -- and the non-_r forms are worse, because they answer with a pointer to the
// host's own 36-byte static, so +0x30 is past its end entirely. Either way the
// engine reads a wild pointer and dereferences it.
//
// So the two fields are real here, and the layout is written out rather than
// borrowed: `long` is 8 bytes on arm64 and 4 in the Microsoft CRT, which is
// the same class of mismatch one field further along.
struct BionicTm {
  int tm_sec, tm_min, tm_hour, tm_mday, tm_mon, tm_year;
  int tm_wday, tm_yday, tm_isdst;
  int pad;
  int64_t tm_gmtoff;
  const char* tm_zone;
};
static_assert(sizeof(BionicTm) == 56, "Bionic arm64 struct tm is 56 bytes");
static_assert(offsetof(BionicTm, tm_zone) == 0x30, "tm_zone is at +0x30");

// The zone name has to outlive the call, and the guest may ask on any thread.
// Bionic's own answer points into its loaded timezone data and never expires,
// so a per-thread buffer is the closest honest equivalent.
const char* ZoneName(const struct tm* host, bool utc) {
  if (utc) return "UTC";
  static thread_local char name[64];
  // %Z is the one portable way to ask the C library, and it already accounts
  // for whether this timestamp is in daylight saving time.
  if (strftime(name, sizeof name, "%Z", host) == 0) return "UTC";
  return name;
}

int64_t ZoneOffset(const struct tm* host, bool utc) {
  if (utc) return 0;
#if defined(_WIN32)
  // Microsoft reports seconds *west* of UTC, and the daylight bias separately;
  // tm_gmtoff is seconds east, with the bias already folded in.
  long west = 0, bias = 0;
  if (_get_timezone(&west) != 0) west = 0;
  if (_get_dstbias(&bias) != 0) bias = 0;
  return -static_cast<int64_t>(west + (host->tm_isdst > 0 ? bias : 0));
#else
  (void)host;
  return 0;
#endif
}

void ToBionic(const struct tm* host, BionicTm* out, bool utc) {
  out->tm_sec = host->tm_sec;
  out->tm_min = host->tm_min;
  out->tm_hour = host->tm_hour;
  out->tm_mday = host->tm_mday;
  out->tm_mon = host->tm_mon;
  out->tm_year = host->tm_year;
  out->tm_wday = host->tm_wday;
  out->tm_yday = host->tm_yday;
  out->tm_isdst = host->tm_isdst;
  out->pad = 0;
  out->tm_gmtoff = ZoneOffset(host, utc);
  out->tm_zone = ZoneName(host, utc);
}

// Bionic breaks down any time_t it is given. The Microsoft CRT refuses
// anything negative or past 23:59:59 on 31 December 3000 and answers EINVAL,
// and the caller here does not check: the engine converts a double to a
// time_t, calls gmtime, and reads tm_min out of the result. A null there is a
// read of address 8, one frame into gameplay.
//
// So the time is clamped into the range this CRT will accept rather than
// refused. A clamped answer is wrong about the date; a null answer is wrong
// about whether the function works at all, and only one of those is
// survivable. Both are visible under the note below.
constexpr int64_t kEarliest = 0;
constexpr int64_t kLatest = 32535215999LL;  // 3000-12-31T23:59:59Z

// Every distinct date the engine asks about.
//
// A seasonal event is a comparison between now and a window, and if a title
// decides it is midwinter in September the disagreement is visible here
// before it is visible anywhere else. ARC_TRACE_TIME prints each distinct
// timestamp broken down, once.
void NoteDate(time_t when, const struct tm* out, bool utc) {
  static const bool trace = getenv("ARC_TRACE_TIME") != nullptr;
  if (!trace || !out) return;
  static std::mutex lock;
  static std::vector<long long> seen;
  std::lock_guard<std::mutex> held(lock);
  for (long long v : seen)
    if (v == static_cast<long long>(when)) return;
  if (seen.size() > 40) return;
  seen.push_back(static_cast<long long>(when));
  fprintf(stderr, "[time] %s %lld -> %04d-%02d-%02d %02d:%02d:%02d\n",
          utc ? "gmtime  " : "localtime", static_cast<long long>(when),
          out->tm_year + 1900, out->tm_mon + 1, out->tm_mday, out->tm_hour,
          out->tm_min, out->tm_sec);
}

bool HostBreakdown(const time_t* t, struct tm* out, bool utc) {
  if (!t) return false;
  time_t when = *t;
#if defined(_WIN32)
  if (static_cast<int64_t>(when) < kEarliest ||
      static_cast<int64_t>(when) > kLatest) {
    static bool said = false;
    if (!said) {
      said = true;
      fprintf(stderr,
              "[time] %lld is outside the range this C library will break"
              " down; clamping\n",
              static_cast<long long>(when));
    }
    when = static_cast<time_t>(static_cast<int64_t>(when) < kEarliest
                                   ? kEarliest
                                   : kLatest);
  }
  const bool ok = (utc ? gmtime_s(out, &when) : localtime_s(out, &when)) == 0;
  if (ok) NoteDate(when, out, utc);
  return ok;
#else
  return (utc ? gmtime_r(&when, out) : localtime_r(&when, out)) != nullptr;
#endif
}

// The _r forms take their arguments the other way round from the Microsoft _s
// forms, so these are wrappers rather than aliases -- and they write the
// guest's struct in the guest's layout, which is the point.
BionicTm* GmtimeR(const time_t* t, BionicTm* out) {
  struct tm host;
  if (!out || !HostBreakdown(t, &host, true)) return nullptr;
  ToBionic(&host, out, true);
  return out;
}
BionicTm* LocaltimeR(const time_t* t, BionicTm* out) {
  struct tm host;
  if (!out || !HostBreakdown(t, &host, false)) return nullptr;
  ToBionic(&host, out, false);
  return out;
}

// Bionic's non-_r forms return a pointer to storage of their own. Per thread
// rather than one global: the engine breaks timestamps down on its network and
// tracking threads, and a shared buffer would have them overwriting each
// other's answer between the call and the read.
BionicTm* Gmtime(const time_t* t) {
  static thread_local BionicTm slot;
  return GmtimeR(t, &slot);
}
BionicTm* Localtime(const time_t* t) {
  static thread_local BionicTm slot;
  return LocaltimeR(t, &slot);
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
  if (h == stdin || h == stderr || h == stdout) return 0;
  ShimTraceClose(h);
  return fclose(h);
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

// Not bound here. sincosf takes its float in v0, which the fixed-arity thunk
// cannot place, so shim_varargs registers a context-taking version instead --
// same reason as the variadic entries, different cause. Left defined because
// the context version calls the same thing.
void Sincosf(float x, float* sin_out, float* cos_out) {
  *sin_out = sinf(x);
  *cos_out = cosf(x);
}

void Getentropy_impl(void* buf, size_t len);

int Getentropy(void* buf, size_t len) {
  Getentropy_impl(buf, len);
  return 0;
}

// getrandom(2), which Bionic has and the host CRT does not. This is where a
// TLS stack gets its seed: BoringSSL and OpenSSL both reach for it before
// anything else, and unseeded they fail SSL_connect without writing a byte.
// The connection opens, nothing is ever sent, and the caller reports "no
// internet" -- which is a long way from "the random number generator was
// never wired up".
//
// GRND_NONBLOCK and GRND_RANDOM are both honoured by ignoring them: this
// source never blocks and never runs short.
int64_t Getrandom(void* buf, size_t len, unsigned /*flags*/) {
  if (!buf) return -1;
  Getentropy_impl(buf, len);
  return static_cast<int64_t>(len);
}

void Getentropy_impl(void* buf, size_t len) {
  auto* out = static_cast<unsigned char*>(buf);
#if defined(_WIN32)
  // RtlGenRandom, reached without dragging in the whole CryptoAPI header set.
  static auto gen = reinterpret_cast<BOOLEAN(WINAPI*)(PVOID, ULONG)>(
      GetProcAddress(LoadLibraryA("advapi32.dll"), "SystemFunction036"));
  if (gen && gen(out, static_cast<ULONG>(len))) return;
#endif
  for (size_t i = 0; i < len; ++i) out[i] = static_cast<unsigned char>(rand());
}


// ponytail: thread_local destructors are never run. We never unload an image
// and the process exits wholesale, so there is nothing for them to clean up
// before. Give this a real registry if a title starts leaning on them.
int CxaThreadAtexit(void (*)(void*), void*, void*) { return 0; }

// The comparator is guest code, so it is dispatched rather than called -- left
// to the host's qsort, the engine's own comparison function would be invoked
// as a host function pointer and fault on execute. Sorting indices into a copy
// keeps the comparator seeing stable addresses while the array is permuted,
// which a comparator is entitled to assume for the duration of one call.
void Qsort(void* base, uint64_t n, uint64_t size, uint64_t compare) {
  if (!base || !compare || !size || n < 2) return;
  auto* bytes = static_cast<uint8_t*>(base);
  const std::vector<uint8_t> copy(bytes, bytes + n * size);
  std::vector<uint64_t> order(static_cast<size_t>(n));
  std::iota(order.begin(), order.end(), uint64_t{0});
  std::stable_sort(order.begin(), order.end(),
                   [&](uint64_t a, uint64_t b) {
                     const uint64_t args[2] = {
                         reinterpret_cast<uint64_t>(copy.data() + a * size),
                         reinterpret_cast<uint64_t>(copy.data() + b * size)};
                     return static_cast<int32_t>(
                                arc_call_guest(compare, args, 2) & 0xFFFFFFFFu) <
                            0;
                   });
  for (uint64_t i = 0; i < n; ++i)
    memcpy(bytes + i * size, copy.data() + order[i] * size,
           static_cast<size_t>(size));
}

// The float-suffixed math the host defines inline rather than exporting, so a
// by-name lookup misses them even though the code is there.
float Frexpf(float v, int* e) { return frexpf(v, e); }
float Ldexpf(float v, int e) { return ldexpf(v, e); }
float Hypotf(float a, float b) { return hypotf(a, b); }
int Isascii(int c) { return c >= 0 && c < 128; }

// Bionic's memalign. malloc already returns memory aligned for any fundamental
// type, which is what nearly every caller wants -- and the result has to stay
// free()-able, so an aligned allocator whose blocks need their own release
// function is not an option here.
// ponytail: alignments above 16 are answered with 16. Give this a real
// implementation, and a matching free, if a title asks for a cache line.
void* Memalign(size_t /*alignment*/, size_t size) { return malloc(size); }

uint32_t Arc4random() {
  static std::mutex lock;
  static std::random_device source;
  std::lock_guard<std::mutex> held(lock);
  return static_cast<uint32_t>(source());
}

// A FORTIFY variant: the checked forms take the set's size and trap on an
// out-of-range descriptor. The semantics are what matter, not the diagnostic.
void FdClrChk(int fd, void* set, size_t) {
  if (!set || fd < 0) return;
  auto* bits = static_cast<uint64_t*>(set);
  bits[fd / 64] &= ~(uint64_t{1} << (fd % 64));
}

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
    E("time", TimeNow),
    E("mktime", mktime),
    E("difftime", difftime),
    E("gmtime", Gmtime),
    E("localtime", Localtime),
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
    E("getentropy", Getentropy),    E("getrandom", Getrandom),
    E("__cxa_thread_atexit_impl", CxaThreadAtexit),
    E("qsort", Qsort),
    E("frexpf", Frexpf),            E("ldexpf", Ldexpf),
    E("hypotf", Hypotf),            E("isascii", Isascii),
    E("memalign", Memalign),        E("arc4random", Arc4random),
    E("__FD_CLR_chk", FdClrChk),
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

uint64_t ShimMonotonicMillis() {
  return static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          MonotonicSinceStart())
          .count());
}

uint64_t ShimResolvePosix(const char* name) {
  for (const Entry& e : kTable)
    if (strcmp(e.name, name) == 0) return reinterpret_cast<uint64_t>(e.fn);
  return 0;
}

size_t ShimPosixCount() { return sizeof(kTable) / sizeof(kTable[0]); }

}  // namespace arc
