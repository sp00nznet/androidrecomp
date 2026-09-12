// The bit-and-byte helpers, against values worked out by hand.
//
// These are the emitters' primitives: one wrong shift or one swapped half is
// not a crash but a different answer, and a different answer to a hash or a
// checksum looks exactly like a correct one. The rev32 case below is the one
// that shipped -- REV32 of a 64-bit register reverses the bytes *within* each
// word and leaves the words where they are, and getting that backwards made
// every SHA-1 digest in the program wrong and every one of them plausible.
#include <assert.h>
#include <stdio.h>

#include "arm64_context.h"

int main(void) {
  assert(arc_rev32(0x01020304u) == 0x04030201u);
  assert(arc_rev64(UINT64_C(0x0102030405060708)) == UINT64_C(0x0807060504030201));
  assert(arc_rev16_32(0x01020304u) == 0x02010403u);
  assert(arc_rev16_64(UINT64_C(0x0102030405060708)) ==
         UINT64_C(0x0201040306050807));
  // Each word byte-reversed in place; the halves do not trade places.
  assert(arc_rev32_64(UINT64_C(0x0102030405060708)) ==
         UINT64_C(0x0403020108070605));
  assert(arc_rbit32(0x80000001u) == 0x80000001u);
  assert(arc_rbit32(0x00000002u) == 0x40000000u);
  assert(arc_ror32(0x00000001u, 1) == 0x80000000u);
  assert(arc_ror32(0x12345678u, 0) == 0x12345678u);
  printf("helpers ok\n");
  return 0;
}
