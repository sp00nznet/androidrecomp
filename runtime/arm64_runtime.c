// Runtime support for lifted code that cannot be expressed inline.
//
// `arc_dispatch` is deliberately not here: it needs the address -> function
// table, which only the generated module knows, so the generated code defines
// it.

#include "arm64_context.h"

#if defined(_MSC_VER)
#include <intrin.h>
#define ARC_THREAD_LOCAL __declspec(thread)
#else
#define ARC_THREAD_LOCAL __thread
#endif

// One reservation per thread, which is what the architecture gives you.
static ARC_THREAD_LOCAL Arm64Reservation t_reservation;

uint64_t arc_load_exclusive(Arm64Ctx* c, uint64_t addr, int bytes) {
  (void)c;
  uint64_t v = 0;
  switch (bytes) {
    case 1: v = arc_ld8(addr); break;
    case 2: v = arc_ld16(addr); break;
    case 4: v = arc_ld32(addr); break;
    default: v = arc_ld64(addr); break;
  }
  t_reservation.address = addr;
  t_reservation.value = v;
  t_reservation.valid = 1;
  return v;
}

static int compare_exchange(uint64_t addr, uint64_t expected, uint64_t desired,
                            int bytes) {
#if defined(_MSC_VER)
  switch (bytes) {
    case 1:
      return _InterlockedCompareExchange8((char*)(uintptr_t)addr,
                                          (char)desired,
                                          (char)expected) == (char)expected;
    case 2:
      return _InterlockedCompareExchange16((short*)(uintptr_t)addr,
                                           (short)desired,
                                           (short)expected) == (short)expected;
    case 4:
      return _InterlockedCompareExchange((long*)(uintptr_t)addr, (long)desired,
                                         (long)expected) == (long)expected;
    default:
      return _InterlockedCompareExchange64((__int64*)(uintptr_t)addr,
                                           (__int64)desired,
                                           (__int64)expected) ==
             (__int64)expected;
  }
#else
  switch (bytes) {
    case 1:
      return __sync_bool_compare_and_swap((uint8_t*)(uintptr_t)addr,
                                          (uint8_t)expected, (uint8_t)desired);
    case 2:
      return __sync_bool_compare_and_swap((uint16_t*)(uintptr_t)addr,
                                          (uint16_t)expected,
                                          (uint16_t)desired);
    case 4:
      return __sync_bool_compare_and_swap((uint32_t*)(uintptr_t)addr,
                                          (uint32_t)expected,
                                          (uint32_t)desired);
    default:
      return __sync_bool_compare_and_swap((uint64_t*)(uintptr_t)addr, expected,
                                          desired);
  }
#endif
}

// Returns 0 on success, 1 on failure -- the same sense as the instruction's
// status register.
uint32_t arc_store_exclusive(Arm64Ctx* c, uint64_t addr, uint64_t value,
                             int bytes) {
  (void)c;
  if (!t_reservation.valid || t_reservation.address != addr) return 1;
  t_reservation.valid = 0;
  return compare_exchange(addr, t_reservation.value, value, bytes) ? 0 : 1;
}

// --- high half of a 128-bit product ----------------------------------------
// No portable C type holds this, so it is the compiler's intrinsic where one
// exists and long multiplication where it does not.
uint64_t arc_umulh(uint64_t a, uint64_t b) {
#if defined(_MSC_VER) && defined(_M_X64)
  return __umulh(a, b);
#elif defined(__SIZEOF_INT128__)
  return (uint64_t)(((unsigned __int128)a * b) >> 64);
#else
  uint64_t alo = a & 0xFFFFFFFFu, ahi = a >> 32;
  uint64_t blo = b & 0xFFFFFFFFu, bhi = b >> 32;
  uint64_t mid = ahi * blo + ((alo * blo) >> 32);
  return ahi * bhi + (mid >> 32) + ((alo * bhi + (mid & 0xFFFFFFFFu)) >> 32);
#endif
}

uint64_t arc_smulh(uint64_t a, uint64_t b) {
#if defined(_MSC_VER) && defined(_M_X64)
  return (uint64_t)__mulh((__int64)a, (__int64)b);
#elif defined(__SIZEOF_INT128__)
  return (uint64_t)((((__int128)(int64_t)a * (int64_t)b)) >> 64);
#else
  // Unsigned high, corrected for each operand's sign.
  uint64_t hi = arc_umulh(a, b);
  if ((int64_t)a < 0) hi -= b;
  if ((int64_t)b < 0) hi -= a;
  return hi;
#endif
}

static ARC_THREAD_LOCAL uint64_t t_tpidr;
uint64_t arc_tpidr_read(void) { return t_tpidr; }
void arc_tpidr_write(uint64_t v) { t_tpidr = v; }

#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static ARC_THREAD_LOCAL jmp_buf* t_recovery;
static ARC_THREAD_LOCAL char t_last_trap[256];

void arc_set_recovery(void* jmp_buffer) {
  t_recovery = (jmp_buf*)jmp_buffer;
}

const char* arc_last_trap(void) { return t_last_trap; }

void arc_trap(Arm64Ctx* c, const char* what) {
  (void)c;
  snprintf(t_last_trap, sizeof(t_last_trap), "%s", what ? what : "?");
  if (t_recovery) longjmp(*t_recovery, 1);
  fprintf(stderr, "guest trap: %s\n", t_last_trap);
  abort();
}

// --- native call bridge ----------------------------------------------------

typedef struct {
  uint64_t address;
  const char* name;
} NativeEntry;

// ponytail: a linear array. It holds a few hundred imports and is searched only
// on a dispatch miss, which is once per call *out* of the guest. Sort it and
// bisect if a profile ever says otherwise.
#define ARC_MAX_NATIVES 2048
static NativeEntry g_natives[ARC_MAX_NATIVES];
static size_t g_native_count;

void arc_register_native(uint64_t address, const char* name) {
  if (!address || g_native_count >= ARC_MAX_NATIVES) return;
  for (size_t i = 0; i < g_native_count; ++i)
    if (g_natives[i].address == address) return;
  g_natives[g_native_count].address = address;
  g_natives[g_native_count].name = name;
  ++g_native_count;
}

// ponytail: eight integer arguments in, one integer result out. That is the
// integer half of the AArch64 calling convention and covers allocation,
// string, file and threading calls -- which is nearly everything a guest asks
// the host for. It does NOT carry floating-point arguments, which live in
// v0-v7 and would need per-signature thunks to place correctly. Generate those
// from the import list when a title actually needs one.
typedef uint64_t (*ArcNative8)(uint64_t, uint64_t, uint64_t, uint64_t,
                               uint64_t, uint64_t, uint64_t, uint64_t);

void arc_dispatch_miss(Arm64Ctx* c, uint64_t target) {
  for (size_t i = 0; i < g_native_count; ++i) {
    if (g_natives[i].address != target) continue;
    ArcNative8 fn = (ArcNative8)(uintptr_t)target;
    uint64_t r = fn(c->x[0], c->x[1], c->x[2], c->x[3],
                    c->x[4], c->x[5], c->x[6], c->x[7]);
    c->x[0] = r;
    return;
  }
  char msg[128];
  snprintf(msg, sizeof(msg),
           "indirect branch to %#llx, neither lifted nor a known import",
           (unsigned long long)target);
  arc_trap(c, msg);
}
