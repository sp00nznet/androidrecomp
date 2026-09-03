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

#include <stdio.h>
#include <stdlib.h>

void arc_trap(Arm64Ctx* c, const char* what) {
  (void)c;
  fprintf(stderr, "guest trap: %s\n", what ? what : "?");
  abort();
}
