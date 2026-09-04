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
#include <cstring>

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

// --- the entry points the guest actually imports ---------------------------

int Vsnprintf(char* out, uint64_t cap, const char* fmt, GuestVaList* ap) {
  Sink sink{out, static_cast<size_t>(cap), 0};
  return FormatInto(sink, fmt, ap);
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
  Sink measure{nullptr, 0, 0};
  const int n = FormatInto(measure, fmt, ap);
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
  Sink measure{nullptr, 0, 0};
  const int n = FormatInto(measure, fmt, ap);
  *out = static_cast<char*>(malloc(static_cast<size_t>(n) + 1));
  if (!*out) return -1;
  Sink sink{*out, static_cast<size_t>(n) + 1, 0};
  return FormatInto(sink, fmt, ap);
}

int AndroidLogVprint(int prio, const char* tag, const char* fmt,
                     GuestVaList* ap) {
  Sink measure{nullptr, 0, 0};
  const int n = FormatInto(measure, fmt, ap);
  char* buffer = static_cast<char*>(malloc(static_cast<size_t>(n) + 1));
  if (!buffer) return n;
  Sink sink{buffer, static_cast<size_t>(n) + 1, 0};
  FormatInto(sink, fmt, ap);
  fprintf(stderr, "[%d] %s: %s\n", prio, tag ? tag : "?", buffer);
  free(buffer);
  return n;
}

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
  return 0;
}

}  // namespace arc
