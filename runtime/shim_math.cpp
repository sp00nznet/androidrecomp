// The maths imports, which the ordinary native bridge cannot carry.
//
// A dispatch miss calls a host function through one fixed signature: twelve
// 64-bit integers in, one out. That is exactly right for the several hundred
// imports whose arguments are pointers, sizes and flags, and it is wrong for
// every import that takes or returns a float. On AArch64 a float argument
// arrives in s0/d0, not x0, and a float result goes back the same way; the
// integer bridge reads x0 for the first argument, so `modff(x, &whole)` hands
// the host its pointer from the wrong register and the host writes through
// whatever was in x1. That is how this was found: an access violation writing
// to address 3, in the middle of the first frame of actual gameplay.
//
// So these eighteen names -- every float-taking or float-returning import the
// three lifted images have between them -- are bound as context-taking natives
// instead. Each one reads its arguments out of the guest's register file where
// the guest actually put them, and writes its result back the same way.
//
// The list is closed, not a policy: it was derived from the images' own
// undefined symbols. If a fourth image is ever lifted, derive it again.

#include <cmath>
#include <cstdlib>
#include <cstring>

#include "arm64_context.h"
#include "shim.h"

namespace arc {
namespace {

// Reading and writing where the AArch64 procedure call standard says to. The
// integer registers are still x0..x7, which is why the pointer-taking forms
// below mix the two.
float S(const Arm64Ctx* c, unsigned n) { return ARC_S_R(c, n); }
double D(const Arm64Ctx* c, unsigned n) { return ARC_D_R(c, n); }
void RetF(Arm64Ctx* c, float v) { arc_s_w(c, 0, v); }
void RetD(Arm64Ctx* c, double v) { arc_d_w(c, 0, v); }
template <typename T>
T* Ptr(const Arm64Ctx* c, unsigned n) {
  return reinterpret_cast<T*>(static_cast<uintptr_t>(c->x[n]));
}

void Acosf(Arm64Ctx* c) { RetF(c, acosf(S(c, 0))); }
void Atanf(Arm64Ctx* c) { RetF(c, atanf(S(c, 0))); }
void Atan2f(Arm64Ctx* c) { RetF(c, atan2f(S(c, 0), S(c, 1))); }
void Sinf(Arm64Ctx* c) { RetF(c, sinf(S(c, 0))); }
void Tanf(Arm64Ctx* c) { RetF(c, tanf(S(c, 0))); }
void Powf(Arm64Ctx* c) { RetF(c, powf(S(c, 0), S(c, 1))); }
void Fmodf(Arm64Ctx* c) { RetF(c, fmodf(S(c, 0), S(c, 1))); }

void Exp(Arm64Ctx* c) { RetD(c, exp(D(c, 0))); }
void Log(Arm64Ctx* c) { RetD(c, log(D(c, 0))); }
void Log10(Arm64Ctx* c) { RetD(c, log10(D(c, 0))); }
void Pow(Arm64Ctx* c) { RetD(c, pow(D(c, 0), D(c, 1))); }
void Fmod(Arm64Ctx* c) { RetD(c, fmod(D(c, 0), D(c, 1))); }

// The ones that write through a pointer as well as returning a value: the
// value is in d0/s0 and the pointer in x0, which is the mix the integer
// bridge cannot express at all.
void Modf(Arm64Ctx* c) {
  double whole = 0;
  const double frac = modf(D(c, 0), &whole);
  if (double* out = Ptr<double>(c, 0)) *out = whole;
  RetD(c, frac);
}
void Modff(Arm64Ctx* c) {
  float whole = 0;
  const float frac = modff(S(c, 0), &whole);
  if (float* out = Ptr<float>(c, 0)) *out = whole;
  RetF(c, frac);
}
// Bionic's sincosf returns nothing and writes both results.
void Sincosf(Arm64Ctx* c) {
  const float x = S(c, 0);
  if (float* s = Ptr<float>(c, 0)) *s = sinf(x);
  if (float* k = Ptr<float>(c, 1)) *k = cosf(x);
}

// And the string-to-float family, whose arguments are pointers but whose
// result is a float -- so they are wrong in the other direction.
void Atof(Arm64Ctx* c) {
  const char* s = Ptr<const char>(c, 0);
  RetD(c, s ? atof(s) : 0.0);
}
void Strtod(Arm64Ctx* c) {
  const char* s = Ptr<const char>(c, 0);
  RetD(c, s ? strtod(s, Ptr<char*>(c, 1)) : 0.0);
}
void Strtof(Arm64Ctx* c) {
  const char* s = Ptr<const char>(c, 0);
  RetF(c, s ? strtof(s, Ptr<char*>(c, 1)) : 0.0f);
}

struct Entry {
  const char* name;
  ArcCtxFn fn;
};

const Entry kTable[] = {
    {"acosf", &Acosf},     {"atanf", &Atanf},   {"atan2f", &Atan2f},
    {"sinf", &Sinf},       {"tanf", &Tanf},     {"powf", &Powf},
    {"fmodf", &Fmodf},     {"exp", &Exp},       {"log", &Log},
    {"log10", &Log10},     {"pow", &Pow},       {"fmod", &Fmod},
    {"modf", &Modf},       {"modff", &Modff},   {"sincosf", &Sincosf},
    {"atof", &Atof},       {"strtod", &Strtod}, {"strtof", &Strtof},
};

}  // namespace

// Registration happens here rather than at start-up so that a name nobody
// imports costs nothing: the dispatcher matches context natives by address,
// and an address it never sees is an entry it never looks at.
uint64_t ShimResolveMath(const char* name) {
  for (const Entry& e : kTable) {
    if (strcmp(e.name, name) != 0) continue;
    const uint64_t at = reinterpret_cast<uint64_t>(e.fn);
    arc_register_ctx_native(at, e.name, e.fn);
    return at;
  }
  return 0;
}

}  // namespace arc
