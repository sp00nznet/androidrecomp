#include "jni_env.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <utility>

#include "arm64_context.h"

namespace {

constexpr size_t kSlots = 256;

// The table the guest sees, and the pointer that names it. A JNIEnv* is the
// address of `g_table`, not of the table itself -- one more level of
// indirection than feels natural, and the reason a null environment faults on
// a read rather than on a call.
uint64_t g_slots[kSlots];
uint64_t g_table = reinterpret_cast<uint64_t>(g_slots);

size_t g_hits[kSlots];
size_t g_total;

// Handles come out of a zeroed arena rather than being a made-up constant, so
// that a caller which dereferences one reads zeroes instead of faulting. That
// buys a surprising amount of progress: most of what a startup path does with
// a handle is pass it back in, and the rest reads a field it can tolerate
// finding empty.
//
// Blocks are generous on purpose. A handle standing in for an object or an
// array gets read at whatever offsets the engine believes that type has, and a
// block big enough to absorb those reads keeps it moving instead of faulting
// just past the end of a tight allocation.
constexpr size_t kArenaSize = 32u << 20;
constexpr size_t kBlock = 64u << 10;
unsigned char* g_arena;
size_t g_arena_used;

uint64_t Allocate() {
  if (!g_arena) {
    g_arena = static_cast<unsigned char*>(calloc(1, kArenaSize));
    if (!g_arena) return 0;
  }
  if (g_arena_used + kBlock > kArenaSize) g_arena_used = 0;  // wrap; nothing frees
  uint64_t p = reinterpret_cast<uint64_t>(g_arena + g_arena_used);
  g_arena_used += kBlock;
  return p;
}

// The standard JNINativeInterface layout. Only the entries worth recognising
// are named; the rest report as a bare index, which is enough to go and look
// one up if a title starts using it.
struct SlotInfo {
  int index;
  const char* name;
  bool returns_handle;
};

constexpr SlotInfo kKnown[] = {
    {4, "GetVersion", false},
    {5, "DefineClass", true},
    {6, "FindClass", true},
    {10, "GetSuperclass", true},
    {13, "Throw", false},
    {14, "ThrowNew", false},
    {15, "ExceptionOccurred", false},   // null means "no exception pending"
    {16, "ExceptionDescribe", false},
    {17, "ExceptionClear", false},
    {21, "NewGlobalRef", true},
    {22, "DeleteGlobalRef", false},
    {23, "DeleteLocalRef", false},
    {24, "IsSameObject", false},
    {25, "NewLocalRef", true},
    {27, "AllocObject", true},
    {28, "NewObject", true},
    {31, "GetObjectClass", true},
    {32, "IsInstanceOf", false},
    {33, "GetMethodID", true},
    {34, "CallObjectMethod", true},
    {61, "CallVoidMethod", false},
    {94, "GetFieldID", true},
    {95, "GetObjectField", true},
    {96, "GetBooleanField", false},
    {100, "GetIntField", false},
    {101, "GetLongField", false},
    {102, "GetFloatField", false},
    {104, "GetStaticMethodID", true},
    {135, "GetStaticFieldID", true},
    {136, "GetStaticObjectField", true},
    {141, "GetStaticIntField", false},
    {154, "NewString", true},
    {158, "NewStringUTF", true},
    {160, "GetStringUTFChars", true},
    {161, "ReleaseStringUTFChars", false},
    {162, "GetArrayLength", false},
    {163, "NewObjectArray", true},
    {164, "GetObjectArrayElement", true},
    {206, "RegisterNatives", false},
    {210, "GetJavaVM", false},
    {217, "NewWeakGlobalRef", true},
    // ExceptionCheck must answer false, or the engine believes a throw is
    // pending after every call and unwinds instead of continuing.
    {219, "ExceptionCheck", false},
    {220, "NewDirectByteBuffer", true},
};

const SlotInfo* Lookup(size_t index) {
  for (const SlotInfo& s : kKnown)
    if (static_cast<size_t>(s.index) == index) return &s;
  return nullptr;
}

extern "C" uint64_t arc_jni_called(size_t index) {
  if (index < kSlots) ++g_hits[index];
  ++g_total;
  const SlotInfo* info = Lookup(index);
  arc_trace_note(info ? info->name : "JNI slot");
  return (info && info->returns_handle) ? Allocate() : 0;
}

// Every slot has the same shape as the native bridge's thunk, so a call
// arriving through it lands correctly. The index is a template parameter purely
// so that each slot gets its own address.
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

int arc_jni_owns(uint64_t address) {
  return g_arena && address >= reinterpret_cast<uint64_t>(g_arena) &&
         address < reinterpret_cast<uint64_t>(g_arena) + kArenaSize;
}

void arc_jni_report(void) {
  if (!g_total) {
    printf("  no JNI slots were called\n");
    return;
  }
  printf("  %zu JNI calls across these slots:\n", g_total);
  for (size_t i = 0; i < kSlots; ++i) {
    if (!g_hits[i]) continue;
    const SlotInfo* info = Lookup(i);
    printf("    %6zu x  slot %3zu  %s\n", g_hits[i], i,
           info ? info->name : "(unnamed)");
  }
}

}  // extern "C"
