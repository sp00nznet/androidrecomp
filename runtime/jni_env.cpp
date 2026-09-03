#include "jni_env.h"

#include <cstdio>
#include <utility>

#include "arm64_context.h"

namespace {

constexpr size_t kSlots = 256;

// The table the guest sees, and the pointer that names it. A JNIEnv* is the
// address of `g_table`, not of the table itself -- one more level of
// indirection than feels natural, and the reason a null env faults on a read
// rather than on a call.
uint64_t g_slots[kSlots];
uint64_t g_table = reinterpret_cast<uint64_t>(g_slots);

size_t g_hits[kSlots];
size_t g_total;

extern "C" uint64_t arc_jni_called(size_t index) {
  if (index < kSlots) ++g_hits[index];
  ++g_total;
  return 0;
}

// Every slot has the same shape as the native bridge's thunk, so a call
// arriving through it lands correctly. The index is a template parameter
// purely so each slot gets its own address.
template <size_t N>
uint64_t Slot(uint64_t, uint64_t, uint64_t, uint64_t,
              uint64_t, uint64_t, uint64_t, uint64_t) {
  return arc_jni_called(N);
}

template <size_t... I>
void FillSlots(std::index_sequence<I...>) {
  ((g_slots[I] = reinterpret_cast<uint64_t>(&Slot<I>)), ...);
}

struct Init {
  Init() { FillSlots(std::make_index_sequence<kSlots>{}); }
} g_init;

}  // namespace

extern "C" {

uint64_t arc_jni_env(void) { return reinterpret_cast<uint64_t>(&g_table); }

void arc_jni_register(void) {
  for (size_t i = 0; i < kSlots; ++i) arc_register_native(g_slots[i], "jni");
}

size_t arc_jni_call_count(void) { return g_total; }

void arc_jni_report(void) {
  if (!g_total) {
    printf("  no JNI slots were called\n");
    return;
  }
  printf("  %zu JNI calls across these slots:\n", g_total);
  for (size_t i = 0; i < kSlots; ++i)
    if (g_hits[i])
      printf("    slot %3zu called %zu time(s)\n", i, g_hits[i]);
}

}  // extern "C"
