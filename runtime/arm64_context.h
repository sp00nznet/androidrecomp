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

// Called by the generated dispatcher when the lifted table has no entry.
void arc_dispatch_miss(Arm64Ctx* c, uint64_t target);

typedef void (*Arc64Fn)(Arm64Ctx*);
void arc_dispatch(Arm64Ctx* c, uint64_t target);

#ifdef __cplusplus
}
#endif
