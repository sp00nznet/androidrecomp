// Formatting for functions that take the guest's own va_list.
//
// A va_list is not a pointer on this architecture. It is a 32-byte structure
// holding two separate register save areas -- one for integers, one for
// floating point -- plus a cursor into the stack for anything that did not fit
// in registers:
//
//   void* stack;    void* gr_top;    void* vr_top;    int gr_offs;  int vr_offs;
//
// The host's va_list is a flat pointer that walks one contiguous argument
// area. Handing one to the other compiles, links, runs, and formats nonsense:
// every conversion reads from the wrong place, and the *return value* is wrong
// too, which is worse than the visible garbage. A caller that asks vsnprintf
// how long the result would be, allocates that much and copies it, will copy
// the wrong number of bytes.
//
// So the format string is walked here and each argument fetched according to
// the rules the guest was compiled with. Individual conversions are still
// handed to the host's snprintf -- there is no reason to reimplement float
// formatting -- one specifier at a time.

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <cstring>

#include "arm64_context.h"
#include "shim.h"

namespace arc {
namespace {

struct GuestVaList {
  uint64_t stack;
  uint64_t gr_top;
  uint64_t vr_top;
  int32_t gr_offs;
  int32_t vr_offs;
};

// A general-purpose argument: from the register save area while one remains,
// from the stack afterwards. The offsets are negative while registers are left
// and count up towards zero.
uint64_t NextInt(GuestVaList* ap) {
  uint64_t value;
  if (ap->gr_offs < 0) {
    memcpy(&value, reinterpret_cast<void*>(ap->gr_top + ap->gr_offs), 8);
    ap->gr_offs += 8;
  } else {
    memcpy(&value, reinterpret_cast<void*>(ap->stack), 8);
    ap->stack += 8;
  }
  return value;
}

// Floating-point arguments live in their own save area, in 16-byte slots.
double NextDouble(GuestVaList* ap) {
  double value;
  if (ap->vr_offs < 0) {
    memcpy(&value, reinterpret_cast<void*>(ap->vr_top + ap->vr_offs), 8);
    ap->vr_offs += 16;
  } else {
    memcpy(&value, reinterpret_cast<void*>(ap->stack), 8);
    ap->stack += 8;
  }
  return value;
}

// Appends to a caller's buffer, counting what it would have taken even after
// the buffer is full -- which is what the return value has to report.
struct Sink {
  char* out;
  size_t cap;
  size_t used;

  void Put(const char* text, size_t n) {
    if (out && used < cap) {
      const size_t room = cap - used - 1;
      const size_t take = n < room ? n : room;
      if (take) memcpy(out + used, text, take);
    }
    used += n;
  }
};

bool IsConversion(char c) {
  return strchr("diouxXeEfgGaAcspn%", c) != nullptr;
}

int FormatInto(Sink& sink, const char* fmt, GuestVaList* ap) {
  char spec[64];
  char piece[512];

  for (const char* p = fmt; *p;) {
    if (*p != '%') {
      const char* run = p;
      while (*p && *p != '%') ++p;
      sink.Put(run, static_cast<size_t>(p - run));
      continue;
    }

    const char* start = p++;
    // Flags, width, precision and length, copied through as written. A width
    // or precision given as '*' consumes an argument of its own.
    int stars = 0;
    while (*p && !IsConversion(*p)) {
      if (*p == '*') ++stars;
      ++p;
    }
    if (!*p) break;
    const char conv = *p++;

    if (conv == '%') {
      sink.Put("%", 1);
      continue;
    }

    size_t len = static_cast<size_t>(p - start);
    if (len >= sizeof(spec)) len = sizeof(spec) - 1;
    memcpy(spec, start, len);
    spec[len] = '\0';

    int star_values[2] = {0, 0};
    for (int i = 0; i < stars && i < 2; ++i)
      star_values[i] = static_cast<int>(NextInt(ap));

    int n = 0;
    if (conv == 'f' || conv == 'F' || conv == 'e' || conv == 'E' ||
        conv == 'g' || conv == 'G' || conv == 'a' || conv == 'A') {
      const double v = NextDouble(ap);
      n = stars == 2 ? snprintf(piece, sizeof(piece), spec, star_values[0],
                                star_values[1], v)
          : stars == 1
              ? snprintf(piece, sizeof(piece), spec, star_values[0], v)
              : snprintf(piece, sizeof(piece), spec, v);
    } else if (conv == 's') {
      const char* s = reinterpret_cast<const char*>(NextInt(ap));
      if (!s) s = "(null)";
      n = stars == 2 ? snprintf(piece, sizeof(piece), spec, star_values[0],
                                star_values[1], s)
          : stars == 1
              ? snprintf(piece, sizeof(piece), spec, star_values[0], s)
              : snprintf(piece, sizeof(piece), spec, s);
    } else if (conv == 'n') {
      auto* target = reinterpret_cast<int*>(NextInt(ap));
      if (target) *target = static_cast<int>(sink.used);
      continue;
    } else {
      const uint64_t v = NextInt(ap);
      n = stars == 2 ? snprintf(piece, sizeof(piece), spec, star_values[0],
                                star_values[1], v)
          : stars == 1
              ? snprintf(piece, sizeof(piece), spec, star_values[0], v)
              : snprintf(piece, sizeof(piece), spec, v);
    }

    if (n > 0) {
      size_t produced = static_cast<size_t>(n);
      if (produced >= sizeof(piece)) produced = sizeof(piece) - 1;
      sink.Put(piece, produced);
    }
  }

  if (sink.out && sink.cap) {
    const size_t at = sink.used < sink.cap - 1 ? sink.used : sink.cap - 1;
    sink.out[at] = '\0';
  }
  return static_cast<int>(sink.used);
}

// Optional tracing, because "the formatted length is wrong" and "the length is
// right and something downstream is wrong" look identical from a fault
// address. Set ARC_TRACE_FORMAT to tell them apart.
bool Tracing() {
  static const bool on = getenv("ARC_TRACE_FORMAT") != nullptr;
  return on;
}

void TraceResult(const char* who, const char* fmt, int n, const char* text) {
  if (!Tracing()) return;
  fprintf(stderr, "[format] %s -> %d  fmt=\"%s\"", who, n, fmt ? fmt : "(null)");
  if (text) fprintf(stderr, "  out=\"%.120s\"", text);
  fputc('\n', stderr);
}

// --- the entry points the guest actually imports ---------------------------

int Vsnprintf(char* out, uint64_t cap, const char* fmt, GuestVaList* ap) {
  Sink sink{out, static_cast<size_t>(cap), 0};
  const int n = FormatInto(sink, fmt, ap);
  TraceResult("vsnprintf", fmt, n, out);
  return n;
}

int Vsprintf(char* out, const char* fmt, GuestVaList* ap) {
  Sink sink{out, SIZE_MAX, 0};
  return FormatInto(sink, fmt, ap);
}

int VsnprintfChk(char* out, uint64_t cap, int, uint64_t, const char* fmt,
                 GuestVaList* ap) {
  return Vsnprintf(out, cap, fmt, ap);
}

int Vfprintf(void* stream, const char* fmt, GuestVaList* ap) {
  GuestVaList probe = *ap;
  Sink measure{nullptr, 0, 0};
  const int n = FormatInto(measure, fmt, &probe);
  (void)stream;
  // Streams route to stderr the same way the logging shim does; there is no
  // guest FILE* worth honouring here.
  char* buffer = static_cast<char*>(malloc(static_cast<size_t>(n) + 1));
  if (!buffer) return n;
  Sink sink{buffer, static_cast<size_t>(n) + 1, 0};
  FormatInto(sink, fmt, ap);
  fputs(buffer, stderr);
  free(buffer);
  return n;
}

int Vasprintf(char** out, const char* fmt, GuestVaList* ap) {
  GuestVaList probe = *ap;
  Sink measure{nullptr, 0, 0};
  const int n = FormatInto(measure, fmt, &probe);
  *out = static_cast<char*>(malloc(static_cast<size_t>(n) + 1));
  if (!*out) return -1;
  Sink sink{*out, static_cast<size_t>(n) + 1, 0};
  return FormatInto(sink, fmt, ap);
}

int AndroidLogVprint(int prio, const char* tag, const char* fmt,
                     GuestVaList* ap) {
  GuestVaList probe = *ap;
  Sink measure{nullptr, 0, 0};
  const int n = FormatInto(measure, fmt, &probe);
  char* buffer = static_cast<char*>(malloc(static_cast<size_t>(n) + 1));
  if (!buffer) return n;
  Sink sink{buffer, static_cast<size_t>(n) + 1, 0};
  FormatInto(sink, fmt, ap);
  fprintf(stderr, "[%d] %s: %s\n", prio, tag ? tag : "?", buffer);
  free(buffer);
  return n;
}

// --- variadic calls --------------------------------------------------------
//
// A variadic call and a va_list describe the same thing. The named arguments
// take general registers in order; everything after them continues through the
// remaining general registers, with floating-point arguments taking vector
// registers instead, and the overflow going to the stack. That is exactly what
// a va_list records -- so one can be synthesised from the register state and
// handed to the same formatter.
//
// `named_gp` is how many general registers the named parameters used, which is
// the only thing that differs between these functions.
GuestVaList VaFromContext(Arm64Ctx* c, int named_gp) {
  GuestVaList v;
  v.stack = c->sp;
  v.gr_top = reinterpret_cast<uint64_t>(&c->x[8]);
  v.vr_top = reinterpret_cast<uint64_t>(&c->q[8]);
  v.gr_offs = -static_cast<int32_t>((8 - named_gp) * 8);
  v.vr_offs = -static_cast<int32_t>(8 * 16);
  return v;
}

// Formats into a fresh buffer the caller frees.
char* FormatAlloc(const char* fmt, GuestVaList* ap, int* length) {
  GuestVaList measure = *ap;
  Sink probe{nullptr, 0, 0};
  const int n = FormatInto(probe, fmt, &measure);
  char* buffer = static_cast<char*>(malloc(static_cast<size_t>(n) + 1));
  if (!buffer) {
    *length = 0;
    return nullptr;
  }
  Sink sink{buffer, static_cast<size_t>(n) + 1, 0};
  FormatInto(sink, fmt, ap);
  *length = n;
  return buffer;
}

void PrintfCtx(Arm64Ctx* c) {
  GuestVaList ap = VaFromContext(c, 1);
  int n = 0;
  char* text = FormatAlloc(reinterpret_cast<const char*>(c->x[0]), &ap, &n);
  if (text) {
    fputs(text, stdout);
    free(text);
  }
  c->x[0] = static_cast<uint64_t>(n);
}

void FprintfCtx(Arm64Ctx* c) {
  GuestVaList ap = VaFromContext(c, 2);
  int n = 0;
  char* text = FormatAlloc(reinterpret_cast<const char*>(c->x[1]), &ap, &n);
  if (text) {
    fputs(text, stderr);
    free(text);
  }
  c->x[0] = static_cast<uint64_t>(n);
}

void SprintfCtx(Arm64Ctx* c) {
  GuestVaList ap = VaFromContext(c, 2);
  Sink sink{reinterpret_cast<char*>(c->x[0]), SIZE_MAX, 0};
  c->x[0] = static_cast<uint64_t>(
      FormatInto(sink, reinterpret_cast<const char*>(c->x[1]), &ap));
}

void SnprintfCtx(Arm64Ctx* c) {
  GuestVaList ap = VaFromContext(c, 3);
  char* out = reinterpret_cast<char*>(c->x[0]);
  const char* fmt = reinterpret_cast<const char*>(c->x[2]);
  Sink sink{out, static_cast<size_t>(c->x[1]), 0};
  const int n = FormatInto(sink, fmt, &ap);
  TraceResult("snprintf", fmt, n, out);
  c->x[0] = static_cast<uint64_t>(n);
}

void AsprintfCtx(Arm64Ctx* c) {
  GuestVaList ap = VaFromContext(c, 2);
  int n = 0;
  char* text = FormatAlloc(reinterpret_cast<const char*>(c->x[1]), &ap, &n);
  *reinterpret_cast<char**>(c->x[0]) = text;
  c->x[0] = text ? static_cast<uint64_t>(n) : UINT64_C(0xFFFFFFFFFFFFFFFF);
}

void SyslogCtx(Arm64Ctx* c) {
  GuestVaList ap = VaFromContext(c, 2);
  int n = 0;
  char* text = FormatAlloc(reinterpret_cast<const char*>(c->x[1]), &ap, &n);
  if (text) {
    fprintf(stderr, "%s\n", text);
    free(text);
  }
  c->x[0] = 0;
}

// Not variadic -- these take the context for the other reason it exists. Their
// first argument is a float, which lives in v0, and the thunk carries only the
// integer registers. Bound the ordinary way, the host function receives the two
// output pointers shifted into the wrong parameter slots and writes through
// whatever the guest happened to leave in x2.
//
// That is not hypothetical: it is what three of The Simpsons' static
// constructors were faulting on, writing to address 0x16 because 0x16 is what
// x2 held. The comment on the thunk has always said to generate one of these
// when a title needs it. One did.
void SincosfCtx(Arm64Ctx* c) {
  const float x = c->q[0].f32[0];
  if (c->x[0]) *reinterpret_cast<float*>(c->x[0]) = sinf(x);
  if (c->x[1]) *reinterpret_cast<float*>(c->x[1]) = cosf(x);
}

void SincosCtx(Arm64Ctx* c) {
  const double x = c->q[0].f64[0];
  if (c->x[0]) *reinterpret_cast<double*>(c->x[0]) = sin(x);
  if (c->x[1]) *reinterpret_cast<double*>(c->x[1]) = cos(x);
}

void AndroidLogPrintCtx(Arm64Ctx* c) {
  GuestVaList ap = VaFromContext(c, 3);
  int n = 0;
  char* text = FormatAlloc(reinterpret_cast<const char*>(c->x[2]), &ap, &n);
  fprintf(stderr, "[%d] %s: %s\n", static_cast<int>(c->x[0]),
          c->x[1] ? reinterpret_cast<const char*>(c->x[1]) : "?",
          text ? text : "");
  free(text);
  c->x[0] = static_cast<uint64_t>(n);
}

struct CtxEntry {
  const char* name;
  ArcCtxFn fn;
};

const CtxEntry kCtxTable[] = {
    {"printf", PrintfCtx},
    {"fprintf", FprintfCtx},
    {"sprintf", SprintfCtx},
    {"snprintf", SnprintfCtx},
    {"asprintf", AsprintfCtx},
    {"syslog", SyslogCtx},
    {"__android_log_print", AndroidLogPrintCtx},
    {"sincosf", SincosfCtx},
    {"sincos", SincosCtx},
};

struct Entry {
  const char* name;
  void* fn;
};

#define E(sym, fn) {sym, reinterpret_cast<void*>(&fn)}
const Entry kTable[] = {
    E("vsnprintf", Vsnprintf),
    E("vsprintf", Vsprintf),
    E("__vsnprintf_chk", VsnprintfChk),
    E("vfprintf", Vfprintf),
    E("vasprintf", Vasprintf),
    E("__android_log_vprint", AndroidLogVprint),
};
#undef E

}  // namespace

uint64_t ShimResolveVarargs(const char* name) {
  for (const Entry& e : kTable)
    if (strcmp(e.name, name) == 0) return reinterpret_cast<uint64_t>(e.fn);
  // A variadic function resolves to its own handler's address, which the
  // dispatcher then recognises as wanting the context rather than eight
  // integers.
  for (const CtxEntry& e : kCtxTable)
    if (strcmp(e.name, name) == 0) return reinterpret_cast<uint64_t>(e.fn);
  return 0;
}

void ShimRegisterVarargs() {
  for (const CtxEntry& e : kCtxTable)
    arc_register_ctx_native(reinterpret_cast<uint64_t>(e.fn), e.name, e.fn);
}

}  // namespace arc
