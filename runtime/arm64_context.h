// Guest CPU state for lifted ARM64 code, and the operations lifted code emits.
//
// The single most important thing about this design is what is *not* here:
// there is no address translation. A recompiled console needs a virtual memory
// manager because guest pointers name guest physical space. We do not, because
// the guest's pointers are already host pointers -- the loader maps the image
// at a real host address, and the shim hands the engine the host's own malloc.
// So a guest load is a host dereference, and that removes an entire layer that
// usually costs both code and per-access speed.
//
// The one thing that is not position-independent is code addresses baked into
// the instruction stream. `adrp` computes an address from the PC, and the PC in
// the original image is an offset, not where we mapped it. So those are emitted
// relative to `image_base`, which the host fills in after loading.
#pragma once

#include <math.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef union {
  uint64_t u64[2];
  int64_t i64[2];
  uint32_t u32[4];
  int32_t i32[4];
  uint16_t u16[8];
  int16_t i16[8];
  uint8_t u8[16];
  int8_t i8[16];
  double f64[2];
  float f32[4];
} Arm64Vec;

typedef struct Arm64Ctx {
  // x[31] is the zero register. Lifted code never writes it -- reads go
  // through ARC_X_R, which returns 0 for 31, and writes through ARC_X_W, which
  // discards. SP is a separate register on this architecture and is kept apart
  // so the two never alias by accident.
  uint64_t x[32];
  uint64_t sp;
  uint64_t lr_shadow;  // where a lifted `bl` parks its return address

  uint32_t nf, zf, cf, vf;  // NZCV, kept unpacked; nothing reads them as a word

  Arm64Vec q[32];

  // Where the image was mapped. Everything the instruction stream computes
  // from a PC is emitted as image_base + a constant.
  uint64_t image_base;

  // The guest instruction being executed, kept up to date only by a program
  // lifted with `--pc-notes`. A fault otherwise reports the function it landed
  // in and leaves which instruction to inference, which is the difference
  // between reading an answer and arguing towards one. It costs a store per
  // instruction, so it is off unless asked for.
  uint64_t pc;
} Arm64Ctx;

// --- register access -------------------------------------------------------
#define ARC_X_R(c, r) ((r) == 31 ? UINT64_C(0) : (c)->x[(r)])
#define ARC_X_W(c, r, v)               \
  do {                                 \
    if ((r) != 31) (c)->x[(r)] = (v);  \
  } while (0)

#define ARC_W_R(c, r) ((uint32_t)ARC_X_R(c, r))
// A 32-bit write zero-extends into the 64-bit register. Forgetting that is one
// of the classic ways a lift goes subtly wrong, so it lives in the macro.
#define ARC_W_W(c, r, v) ARC_X_W(c, r, (uint64_t)(uint32_t)(v))

// --- flags -----------------------------------------------------------------
// Only the instructions that actually set flags call these, so the common case
// costs nothing.

static inline void arc_flags_logical64(Arm64Ctx* c, uint64_t r) {
  c->nf = (uint32_t)(r >> 63);
  c->zf = (r == 0);
  c->cf = 0;
  c->vf = 0;
}
static inline void arc_flags_logical32(Arm64Ctx* c, uint32_t r) {
  c->nf = r >> 31;
  c->zf = (r == 0);
  c->cf = 0;
  c->vf = 0;
}

static inline uint64_t arc_add64(Arm64Ctx* c, uint64_t a, uint64_t b,
                                 uint64_t carry_in) {
  uint64_t r = a + b + carry_in;
  c->nf = (uint32_t)(r >> 63);
  c->zf = (r == 0);
  // Unsigned overflow: the sum wrapped. Written this way rather than with a
  // 128-bit type so it compiles the same everywhere.
  c->cf = (r < a) || (carry_in && r == a);
  c->vf = (~(a ^ b) & (a ^ r)) >> 63;
  return r;
}
static inline uint32_t arc_add32(Arm64Ctx* c, uint32_t a, uint32_t b,
                                 uint32_t carry_in) {
  uint64_t wide = (uint64_t)a + b + carry_in;
  uint32_t r = (uint32_t)wide;
  c->nf = r >> 31;
  c->zf = (r == 0);
  c->cf = (uint32_t)(wide >> 32);
  c->vf = ((~(a ^ b) & (a ^ r)) >> 31) & 1;
  return r;
}
// Subtraction is addition of the complement with carry in, which is exactly
// how the hardware defines it -- including that borrow appears as carry set.
static inline uint64_t arc_sub64(Arm64Ctx* c, uint64_t a, uint64_t b) {
  return arc_add64(c, a, ~b, 1);
}
static inline uint32_t arc_sub32(Arm64Ctx* c, uint32_t a, uint32_t b) {
  return arc_add32(c, a, ~b, 1);
}

// --- condition codes -------------------------------------------------------
static inline int arc_cond(const Arm64Ctx* c, int cond) {
  switch (cond >> 1) {
    case 0: return c->zf;                            // eq / ne
    case 1: return c->cf;                            // cs / cc
    case 2: return c->nf;                            // mi / pl
    case 3: return c->vf;                            // vs / vc
    case 4: return c->cf && !c->zf;                  // hi / ls
    case 5: return c->nf == c->vf;                   // ge / lt
    case 6: return !c->zf && (c->nf == c->vf);       // gt / le
    default: return 1;                               // al / nv
  }
}
// The low bit of the condition selects the inverted form, except for `al`.
#define ARC_COND(c, k) (((k) & 1) && ((k) != 15) ? !arc_cond(c, k) : arc_cond(c, k))

// --- shifts and extends ----------------------------------------------------
static inline uint64_t arc_ror64(uint64_t v, unsigned n) {
  n &= 63;
  return n ? (v >> n) | (v << (64 - n)) : v;
}
static inline uint32_t arc_ror32(uint32_t v, unsigned n) {
  n &= 31;
  return n ? (v >> n) | (v << (32 - n)) : v;
}

// --- memory ----------------------------------------------------------------
// Guest addresses are host addresses; see the note at the top. memcpy rather
// than a pointer cast because the guest is free to make unaligned accesses that
// a strict-aliasing compiler would otherwise be entitled to miscompile.
static inline uint64_t arc_ld64(uint64_t a) {
  uint64_t v; memcpy(&v, (const void*)(uintptr_t)a, 8); return v;
}
static inline uint32_t arc_ld32(uint64_t a) {
  uint32_t v; memcpy(&v, (const void*)(uintptr_t)a, 4); return v;
}
static inline uint16_t arc_ld16(uint64_t a) {
  uint16_t v; memcpy(&v, (const void*)(uintptr_t)a, 2); return v;
}
static inline uint8_t arc_ld8(uint64_t a) {
  return *(const uint8_t*)(uintptr_t)a;
}
static inline void arc_st64(uint64_t a, uint64_t v) {
  memcpy((void*)(uintptr_t)a, &v, 8);
}
static inline void arc_st32(uint64_t a, uint32_t v) {
  memcpy((void*)(uintptr_t)a, &v, 4);
}
static inline void arc_st16(uint64_t a, uint16_t v) {
  memcpy((void*)(uintptr_t)a, &v, 2);
}
static inline void arc_st8(uint64_t a, uint8_t v) {
  *(uint8_t*)(uintptr_t)a = v;
}

// --- floating point --------------------------------------------------------
// The scalar FP registers are views onto lane 0 of the vector file. Writing any
// of them zeroes the remaining bits of the 128 -- the FP counterpart of a
// 32-bit GPR write zero-extending, and just as easy to forget, so it lives in
// the setters rather than in every emitter.

#define ARC_B_R(c, n) ((c)->q[n].u8[0])
#define ARC_H_R(c, n) ((c)->q[n].u16[0])
#define ARC_S_R(c, n) ((c)->q[n].f32[0])
#define ARC_D_R(c, n) ((c)->q[n].f64[0])
#define ARC_SU_R(c, n) ((c)->q[n].u32[0])
#define ARC_DU_R(c, n) ((c)->q[n].u64[0])

static inline void arc_v_clear(Arm64Ctx* c, unsigned n) {
  c->q[n].u64[0] = 0;
  c->q[n].u64[1] = 0;
}
static inline void arc_s_w(Arm64Ctx* c, unsigned n, float v) {
  arc_v_clear(c, n);
  c->q[n].f32[0] = v;
}
static inline void arc_d_w(Arm64Ctx* c, unsigned n, double v) {
  arc_v_clear(c, n);
  c->q[n].f64[0] = v;
}
static inline void arc_su_w(Arm64Ctx* c, unsigned n, uint32_t v) {
  arc_v_clear(c, n);
  c->q[n].u32[0] = v;
}
static inline void arc_du_w(Arm64Ctx* c, unsigned n, uint64_t v) {
  arc_v_clear(c, n);
  c->q[n].u64[0] = v;
}
static inline void arc_q_w(Arm64Ctx* c, unsigned n, uint64_t lo, uint64_t hi) {
  c->q[n].u64[0] = lo;
  c->q[n].u64[1] = hi;
}

// `fcmp` does not set flags the way an integer compare does, and the fourth
// case is the one that catches people: an unordered result (either operand
// NaN) sets C and V, not Z.
static inline void arc_fcmp(Arm64Ctx* c, double a, double b) {
  if (a != a || b != b) {        /* unordered */
    c->nf = 0; c->zf = 0; c->cf = 1; c->vf = 1;
  } else if (a == b) {
    c->nf = 0; c->zf = 1; c->cf = 1; c->vf = 0;
  } else if (a < b) {
    c->nf = 1; c->zf = 0; c->cf = 0; c->vf = 0;
  } else {
    c->nf = 0; c->zf = 0; c->cf = 1; c->vf = 0;
  }
}

// Minimum and maximum are two operations here, not one, and C only implements
// the other one. ARM's `fmin`/`fmax` *propagate* NaN; its `fminnm`/`fmaxnm` are
// the IEEE forms that ignore it, which is what C's `fmin`/`fmax` do. Using the
// C function for the propagating form quietly returns a number where the
// hardware returns NaN.
//
// The zero case is the other half: min(+0, -0) is -0 and max(+0, -0) is +0, but
// +0 == -0 compares equal, so a plain `a < b ? a : b` picks by argument order.

static inline float arc_quiet32(float v) {
  uint32_t b;
  memcpy(&b, &v, 4);
  b |= 0x00400000u;  // set the quiet bit, preserving the payload
  memcpy(&v, &b, 4);
  return v;
}
static inline double arc_quiet64(double v) {
  uint64_t b;
  memcpy(&b, &v, 8);
  b |= UINT64_C(0x0008000000000000);
  memcpy(&v, &b, 8);
  return v;
}
// The default NaN is positive: sign clear, quiet bit set, payload zero.
static inline float arc_dnan32(void) {
  uint32_t b = 0x7FC00000u;
  float v;
  memcpy(&v, &b, 4);
  return v;
}
static inline double arc_dnan64(void) {
  uint64_t b = UINT64_C(0x7FF8000000000000);
  double v;
  memcpy(&v, &b, 8);
  return v;
}

#define ARC_MINMAX(suffix, type, quiet)                                    \
  static inline type arc_fmin##suffix(type a, type b) {                    \
    if (a != a) return quiet(a);                                           \
    if (b != b) return quiet(b);                                           \
    if (a == b) return signbit(a) ? a : b;                                 \
    return a < b ? a : b;                                                  \
  }                                                                        \
  static inline type arc_fmax##suffix(type a, type b) {                    \
    if (a != a) return quiet(a);                                           \
    if (b != b) return quiet(b);                                           \
    if (a == b) return signbit(a) ? b : a;                                 \
    return a > b ? a : b;                                                  \
  }                                                                        \
  static inline type arc_fminnm##suffix(type a, type b) {                  \
    if (a != a) return b;                                                  \
    if (b != b) return a;                                                  \
    if (a == b) return signbit(a) ? a : b;                                 \
    return a < b ? a : b;                                                  \
  }                                                                        \
  static inline type arc_fmaxnm##suffix(type a, type b) {                  \
    if (a != a) return b;                                                  \
    if (b != b) return a;                                                  \
    if (a == b) return signbit(a) ? b : a;                                 \
    return a > b ? a : b;                                                  \
  }
ARC_MINMAX(32, float, arc_quiet32)
ARC_MINMAX(64, double, arc_quiet64)
#undef ARC_MINMAX

// The four basic operations, with this architecture's answer when one of them
// is invalid -- 0/0, inf-inf, 0*inf. x86 hands back a NaN with the sign bit
// set; the default NaN here has it clear. A propagated input NaN keeps its
// payload and is merely quieted, which is a different rule again, so the two
// cases are separated rather than both answered with a constant.
//
// ponytail: a compare and a predictable branch on every floating-point
// operation, which is the hottest path a game has. Correct first; if a profile
// ever objects, the check can be hoisted into the operations that can actually
// raise invalid.
#define ARC_FP_OPS(suffix, type, quiet, dnan)                              \
  static inline type arc_fop_fix##suffix(type r, type a, type b) {         \
    if (r == r) return r;                                                  \
    if (a != a) return quiet(a);                                           \
    if (b != b) return quiet(b);                                           \
    return dnan();                                                         \
  }                                                                        \
  static inline type arc_fadd##suffix(type a, type b) {                    \
    return arc_fop_fix##suffix(a + b, a, b);                               \
  }                                                                        \
  static inline type arc_fsub##suffix(type a, type b) {                    \
    return arc_fop_fix##suffix(a - b, a, b);                               \
  }                                                                        \
  static inline type arc_fmul##suffix(type a, type b) {                    \
    return arc_fop_fix##suffix(a * b, a, b);                               \
  }                                                                        \
  static inline type arc_fdiv##suffix(type a, type b) {                    \
    return arc_fop_fix##suffix(a / b, a, b);                               \
  }
ARC_FP_OPS(32, float, arc_quiet32, arc_dnan32)
ARC_FP_OPS(64, double, arc_quiet64, arc_dnan64)
#undef ARC_FP_OPS

// The square root of a negative is an invalid operation, and the architecture
// answers it with the *default* NaN -- sign clear. C's sqrt returns a negative
// NaN, which differs in exactly one bit and would never be noticed by reading.
static inline float arc_fsqrt32(float v) {
  if (v != v) return arc_quiet32(v);
  if (v < 0.0f) return arc_dnan32();
  return sqrtf(v);
}
static inline double arc_fsqrt64(double v) {
  if (v != v) return arc_quiet64(v);
  if (v < 0.0) return arc_dnan64();
  return sqrt(v);
}

// Float-to-integer conversion is saturating on this architecture, and NaN
// converts to zero. In C the same cast is undefined behaviour once the value
// does not fit, so it cannot simply be written as a cast -- the compiler is
// entitled to produce anything at all, and at -O2 frequently does.
static inline int64_t arc_f2i64(double v) {
  if (v != v) return 0;
  if (v >= 9223372036854775808.0) return INT64_MAX;
  if (v <= -9223372036854775808.0) return INT64_MIN;
  return (int64_t)v;
}
static inline int32_t arc_f2i32(double v) {
  if (v != v) return 0;
  if (v >= 2147483648.0) return INT32_MAX;
  if (v <= -2147483649.0) return INT32_MIN;
  return (int32_t)v;
}
static inline uint64_t arc_f2u64(double v) {
  if (v != v || v <= 0.0) return 0;
  if (v >= 18446744073709551616.0) return UINT64_MAX;
  return (uint64_t)v;
}
static inline uint32_t arc_f2u32(double v) {
  if (v != v || v <= 0.0) return 0;
  if (v >= 4294967296.0) return UINT32_MAX;
  return (uint32_t)v;
}

// --- exclusives ------------------------------------------------------------
// A load-exclusive / store-exclusive pair is modelled as a reservation
// remembered per thread, and the store as a compare-exchange against the value
// the load saw. That is not what the hardware does -- it reserves an address,
// not a value -- but it fails in the same direction: a store can spuriously
// fail, never spuriously succeed, and every correct guest loop already retries.
typedef struct {
  uint64_t address;
  uint64_t value;
  int valid;
} Arm64Reservation;

uint64_t arc_load_exclusive(Arm64Ctx* c, uint64_t addr, int bytes);
uint32_t arc_store_exclusive(Arm64Ctx* c, uint64_t addr, uint64_t value,
                             int bytes);

// --- variable vector shifts ------------------------------------------------
// One instruction shifts either way: the amount is a signed per-lane value,
// negative meaning right. An out-of-range amount produces zero rather than the
// undefined behaviour C would have.
#define ARC_SHL(bits)                                                     \
  static inline uint##bits##_t arc_ushl##bits(uint##bits##_t v, int8_t s) { \
    if (s >= 0) return s >= bits ? 0 : (uint##bits##_t)(v << s);          \
    s = (int8_t)-s;                                                       \
    return s >= bits ? 0 : (uint##bits##_t)(v >> s);                      \
  }                                                                       \
  static inline uint##bits##_t arc_sshl##bits(uint##bits##_t v, int8_t s) { \
    if (s >= 0) return s >= bits ? 0 : (uint##bits##_t)(v << s);          \
    s = (int8_t)-s;                                                       \
    if (s >= bits) s = bits - 1;                                          \
    return (uint##bits##_t)(((int##bits##_t)v) >> s);                     \
  }
ARC_SHL(8)
ARC_SHL(16)
ARC_SHL(32)
ARC_SHL(64)
#undef ARC_SHL

// --- saturating lane arithmetic --------------------------------------------
// Clamping instead of wrapping is the entire reason these instructions exist:
// pixel and audio code relies on an overflowing sum sticking at full scale
// rather than coming out the other end as a dark pixel or a click. Computed
// one width up, which is why 64-bit lanes are not defined here -- they have no
// wider type to be computed in, and no title has yet used them.
#define ARC_SAT(bits, lo, hi)                                                 \
  static inline int##bits##_t arc_clamp##bits(int64_t r) {                    \
    return (int##bits##_t)(r > (hi) ? (hi) : r < (lo) ? (lo) : r);            \
  }                                                                           \
  static inline int##bits##_t arc_sqadd##bits(int##bits##_t a,                \
                                              int##bits##_t b) {              \
    return arc_clamp##bits((int64_t)a + (int64_t)b);                          \
  }                                                                           \
  static inline int##bits##_t arc_sqsub##bits(int##bits##_t a,                \
                                              int##bits##_t b) {              \
    return arc_clamp##bits((int64_t)a - (int64_t)b);                          \
  }                                                                           \
  static inline uint##bits##_t arc_uqadd##bits(uint##bits##_t a,              \
                                               uint##bits##_t b) {            \
    uint##bits##_t r = (uint##bits##_t)(a + b);                               \
    return r < a ? (uint##bits##_t)~(uint##bits##_t)0 : r;                    \
  }                                                                           \
  static inline uint##bits##_t arc_uqsub##bits(uint##bits##_t a,              \
                                               uint##bits##_t b) {            \
    return a < b ? (uint##bits##_t)0 : (uint##bits##_t)(a - b);               \
  }                                                                           \
  /* Doubling multiply, keeping the high half: (2*a*b) >> bits. Saturates    \
     only where both operands are the most negative value. */                 \
  static inline int##bits##_t arc_sqdmulh##bits(int##bits##_t a,              \
                                                int##bits##_t b) {            \
    return arc_clamp##bits(((int64_t)a * (int64_t)b) >> (bits - 1));          \
  }                                                                           \
  /* The rounding form adds half a unit before discarding the low half. */    \
  static inline int##bits##_t arc_sqrdmulh##bits(int##bits##_t a,             \
                                                 int##bits##_t b) {           \
    int64_t r = (int64_t)a * (int64_t)b * 2 + ((int64_t)1 << (bits - 1));     \
    return arc_clamp##bits(r >> bits);                                        \
  }
ARC_SAT(8, INT8_MIN, INT8_MAX)
ARC_SAT(16, INT16_MIN, INT16_MAX)
ARC_SAT(32, INT32_MIN, INT32_MAX)
#undef ARC_SAT

// A table lookup reads a byte from up to four consecutive registers treated as
// one run of bytes. The register number wraps at 32, and an index past the end
// of the table is not an error: `tbl` answers zero and `tbx` leaves the
// destination byte alone, which is what makes them useful as a permute with a
// built-in mask.
static inline uint8_t arc_tbl(const Arm64Ctx *c, int base, int n, uint8_t i) {
  return i < n * 16 ? c->q[(base + (i >> 4)) & 31].u8[i & 15] : (uint8_t)0;
}

// --- bit manipulation ------------------------------------------------------
// Sign-extending a field means shifting its top bit up to the register's top
// and back down arithmetically. Spelled once here rather than inline in the
// emitters, where the parentheses become unreadable.
static inline uint64_t arc_sext64(uint64_t v, unsigned width) {
  unsigned up = 64 - width;
  return (uint64_t)(((int64_t)(v << up)) >> up);
}
static inline uint32_t arc_sext32(uint32_t v, unsigned width) {
  unsigned up = 32 - width;
  return (uint32_t)(((int32_t)(v << up)) >> up);
}

static inline uint8_t arc_popcount8(uint8_t v) {
  v = (uint8_t)(v - ((v >> 1) & 0x55));
  v = (uint8_t)((v & 0x33) + ((v >> 2) & 0x33));
  return (uint8_t)((v + (v >> 4)) & 0x0F);
}
static inline uint64_t arc_clz64(uint64_t v) {
  uint64_t n = 0;
  if (!v) return 64;
  while (!(v >> 63)) { v <<= 1; ++n; }
  return n;
}
static inline uint32_t arc_clz32(uint32_t v) {
  uint32_t n = 0;
  if (!v) return 32;
  while (!(v >> 31)) { v <<= 1; ++n; }
  return n;
}
static inline uint64_t arc_rbit64(uint64_t v) {
  uint64_t r = 0;
  for (int i = 0; i < 64; ++i) { r = (r << 1) | (v & 1); v >>= 1; }
  return r;
}
static inline uint32_t arc_rbit32(uint32_t v) {
  uint32_t r = 0;
  for (int i = 0; i < 32; ++i) { r = (r << 1) | (v & 1); v >>= 1; }
  return r;
}
static inline uint64_t arc_rev64(uint64_t v) {
  uint64_t r = 0;
  for (int i = 0; i < 8; ++i) { r = (r << 8) | (v & 0xFF); v >>= 8; }
  return r;
}
static inline uint32_t arc_rev32(uint32_t v) {
  return ((v & 0xFFu) << 24) | ((v & 0xFF00u) << 8) |
         ((v >> 8) & 0xFF00u) | ((v >> 24) & 0xFFu);
}
// rev16 reverses bytes within each halfword, rev32 within each word.
static inline uint32_t arc_rev16_32(uint32_t v) {
  return ((v & 0x00FF00FFu) << 8) | ((v >> 8) & 0x00FF00FFu);
}
static inline uint64_t arc_rev16_64(uint64_t v) {
  return ((v & UINT64_C(0x00FF00FF00FF00FF)) << 8) |
         ((v >> 8) & UINT64_C(0x00FF00FF00FF00FF));
}
static inline uint64_t arc_rev32_64(uint64_t v) {
  return ((uint64_t)arc_rev32((uint32_t)v) << 32) |
         arc_rev32((uint32_t)(v >> 32));
}

uint64_t arc_smulh(uint64_t a, uint64_t b);
uint64_t arc_umulh(uint64_t a, uint64_t b);

// TPIDR_EL0 is the thread pointer. Bionic owns it on Android; here the guest
// gets one per host thread, which it may read and write as it likes.
uint64_t arc_tpidr_read(void);
void arc_tpidr_write(uint64_t v);

// FPCR carries the rounding mode and the exception masks. Code that reads it is
// almost always saving it to put back afterwards, so it has to round-trip --
// but the arithmetic underneath is the host's, which rounds to nearest whatever
// this says.
// ponytail: stored, not obeyed. Give it teeth if a title ever depends on a
// directed rounding mode rather than merely preserving one.
// The virtual counter. Compiled code reads it to time itself without a system
// call, so it has to advance -- a clock that never moves makes anything
// measuring an interval either divide by zero or wait forever. Counted in
// nanoseconds, which is what CNTFRQ_EL0 is answered with.
uint64_t arc_cntvct_read(void);

uint64_t arc_fpcr_read(void);
void arc_fpcr_write(uint64_t v);

// setjmp and longjmp, which cannot be the host's own and cannot live in a shim
// either. The host's would save host registers; and a host setjmp called
// inside a shim captures that shim's frame, which is gone the moment it
// returns, so jumping to it later is undefined.
//
// So the lifter emits the setjmp *inline*, in the lifted function that makes
// the call. Lifted functions are ordinary host C functions, so the frame it
// captures is the caller's -- exactly the one that has to still be live when
// the jump happens. This hands out the buffer to capture into, keyed by the
// guest's own; the guest then branches on the result it gets back, which is
// how it already distinguishes arming from returning.
//
// One registry per thread, because a longjmp across threads is undefined
// anywhere.
// Both take the context because a jump has to restore the *guest's* frame as
// well as the host's. A real longjmp puts back x19-x30 and the stack pointer;
// restoring only the host side leaves the guest's callee-saved registers
// holding whatever the callee left in them, and the first thing the returned-to
// function does is check its stack canary against a frame that no longer
// matches. That reads as memory corruption, which is the last place anyone
// would look for a missing register restore.
void* arc_jmpbuf_for(Arm64Ctx* c, uint64_t guest_buffer);
void arc_longjmp(Arm64Ctx* c, uint64_t guest_buffer, int value);

// --- indirect control flow -------------------------------------------------
// Every `blr`/`br` target is looked up in a sorted address -> function table
// built from the recovered function starts. A miss traps loudly: an unlifted
// target reached at runtime is a bug to fix, not something to paper over.
// A guest trap -- `brk`, or an indirect branch that resolves to nothing. Loud
// on purpose: reaching one means the lift is incomplete, not that the game did
// something interesting. A host that has armed a recovery point (see
// arc_set_recovery) gets control back instead of the process dying, which is
// what lets a boot attempt enumerate every failure rather than the first.
void arc_trap(Arm64Ctx* c, const char* what);

// Arms a longjmp target for the next guest call. Pass NULL to disarm.
// The buffer is a jmp_buf; kept as void* so this header needs no <setjmp.h>.
void arc_set_recovery(void* jmp_buffer);
const char* arc_last_trap(void);

// --- calling out of the guest ----------------------------------------------
// An import is reached the same way a virtual method is: the guest loads a GOT
// slot and branches to it. The address in that slot is a *host* function the
// shim supplied, so the dispatch table will never contain it. Registering them
// lets an indirect branch tell the two apart.
void arc_register_native(uint64_t address, const char* name);

// Some imports cannot be reached through the eight-integer thunk at all. A
// variadic function's arguments are spread across the general registers, the
// vector registers and the stack, and which of those a given argument lives in
// depends on its type -- information the thunk does not have and cannot
// recover. Those are registered as taking the context itself, and read their
// own arguments out of it.
typedef void (*ArcCtxFn)(Arm64Ctx*);
void arc_register_ctx_native(uint64_t address, const char* name, ArcCtxFn fn);

// Called by the generated dispatcher when the lifted table has no entry.
void arc_dispatch_miss(Arm64Ctx* c, uint64_t target);

// What an address is, in words, for the host to fill in. The runtime knows an
// indirect branch went somewhere it does not recognise; only the host knows
// that the somewhere is an unresolved import's slot, and which import. Without
// this the trap names a bare address and the answer takes arithmetic against a
// load address that changes every run. Returns NULL when it has nothing to say.
typedef const char* (*ArcExplainFn)(uint64_t address);
void arc_set_explain(ArcExplainFn fn);

// The registered host function nearest below an address, and how far above it
// the address falls. An indirect branch into host code that the dispatcher
// does not recognise is otherwise a bare number: this says which shim it
// landed in the middle of, which is usually the whole answer. NULL if nothing
// is registered below it.
const char* arc_native_near(uint64_t address, uint64_t* delta);

// Call guest code from the host, for the shim entry points that take a
// callback: pthread_once's initialiser, dl_iterate_phdr's visitor, a
// comparator. Those pointers are guest code, and calling one as a host
// function pointer runs ARM instructions on an x86 processor -- which surfaces
// as an access violation on execute, at an address inside the game's own
// image, and so reads as a bad pointer in the guest rather than as the host
// calling it wrongly. Every one of these has to come through here instead.
//
// The callback gets a stack of its own rather than the host's, because lifted
// code addresses its frame through the guest's stack pointer. A fresh one per
// call keeps this safe to re-enter, which matters: an unwinder's callback can
// perfectly well take a lock or throw.
uint64_t arc_call_guest(uint64_t fn, const uint64_t* args, int n);

// --- what the guest was doing -----------------------------------------------
// A fault in lifted code reports an address and nothing else: there is no host
// call stack to walk, because the guest's frames are C frames belonging to
// 70,000 identically-shaped functions. The last few calls it made out to the
// host are the cheapest substitute, and usually enough -- a fault just after
// mmap says something quite different from one just after GetObjectField.
void arc_trace_note(const char* what);

// --- which guest functions ran ----------------------------------------------
// A fault in lifted code names an address in the data it touched, never the
// code that touched it: the host call stack is 70,000 identically-shaped C
// functions and tells you nothing. So each lifted function records that it was
// entered.
//
// A ring of entries rather than a stack of frames, deliberately. Nothing has
// to be popped, so no return path can be missed, and the *path taken* is more
// use than the depth when the question is how execution reached a bad pointer.
// The value is the image index and the offset packed together, which is a
// constant at generation time and so costs one store.
//
// Compiled out unless ARC_FRAMES is defined, because this is one store per
// function call on every path a game has.
#if defined(ARC_FRAMES)
void arc_frame_note(uint64_t packed);
#else
#define arc_frame_note(packed) ((void)0)
#endif
size_t arc_frame_count(void);
uint64_t arc_frame_at(size_t back);  // 0 is the most recent
void arc_frame_clear(void);
size_t arc_trace_count(void);
const char* arc_trace_at(size_t back);  // 0 is the most recent
void arc_trace_clear(void);

typedef void (*Arc64Fn)(Arm64Ctx*);

// Dispatch belongs to the library, and a lifted program plugs into it.
//
// The other way round does not work: the shim itself has to dispatch -- a
// guest thread's entry point is a guest address, not a host function -- so if
// the only definition lived in generated code, the library would reference a
// symbol nothing in it provides and every host without a lifted program would
// fail to link. With no lifted program installed, a branch goes straight to
// the native bridge, which is exactly right for a host that only has imports.
typedef void (*ArcDispatchFn)(Arm64Ctx*, uint64_t);
void arc_set_dispatch(ArcDispatchFn fn);
void arc_dispatch(Arm64Ctx* c, uint64_t target);

#ifdef __cplusplus
}
#endif
