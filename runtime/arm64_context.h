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
  uint8_t u8[16];
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

// --- indirect control flow -------------------------------------------------
// Every `blr`/`br` target is looked up in a sorted address -> function table
// built from the recovered function starts. A miss traps loudly: an unlifted
// target reached at runtime is a bug to fix, not something to paper over.
typedef void (*Arc64Fn)(Arm64Ctx*);
void arc_dispatch(Arm64Ctx* c, uint64_t target);

#ifdef __cplusplus
}
#endif
