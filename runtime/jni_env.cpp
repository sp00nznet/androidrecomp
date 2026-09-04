#include "jni_env.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <utility>

#if defined(_WIN32)
#include <windows.h>
#endif

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

// A string handed back to the guest is not merely a pointer -- something will
// measure it. An arena block is zeroed, so every string read out of Java came
// back empty, and the engine's own string handling then computed a length of
// zero minus one and asked memcpy for eighteen exabytes. Non-empty placeholder
// text costs nothing and keeps that arithmetic in range.
uint64_t Allocate();
const char kPlaceholder[] = "androidrecomp";

uint64_t AllocateString() {
  const uint64_t p = Allocate();
  if (p) memcpy(reinterpret_cast<void*>(p), kPlaceholder, sizeof(kPlaceholder));
  return p;
}

// The arena is placed low in the address space on purpose. A handle is opaque
// to the guest in principle, but code that came from a 32-bit lineage stores
// one in an int somewhere, and a raw 64-bit heap pointer does not survive that.
// A truncated handle then reappears in arithmetic as a large negative number --
// which is exactly the shape of an allocation size seen in the trail.
//
// Keeping handles inside 32 bits makes such a truncation harmless, and costs
// nothing: the guest only ever passes them back.
unsigned char* ReserveLowArena() {
#if defined(_WIN32)
  for (uintptr_t at = 0x10000000; at < 0x60000000; at += 0x1000000) {
    void* p = VirtualAlloc(reinterpret_cast<void*>(at), kArenaSize,
                           MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (p) return static_cast<unsigned char*>(p);
  }
#endif
  return static_cast<unsigned char*>(calloc(1, kArenaSize));
}

uint64_t Allocate() {
  if (!g_arena) {
    g_arena = ReserveLowArena();
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
    // Anything that hands back an object, an array or a buffer has to return
    // something non-null. A zero here is not merely "no answer" -- the caller
    // computes a length or a pointer difference from it, and the result of
    // that arithmetic becomes an allocation size. One zero-returning array slot
    // was enough to produce a calloc for eighteen exabytes.
    {29, "NewObjectV", true},
    {30, "NewObjectA", true},
    {155, "GetStringLength", false},
    {156, "GetStringChars", true},   // measured by the caller; see below
    {157, "ReleaseStringChars", false},
    {159, "GetStringUTFLength", false},
    {165, "SetObjectArrayElement", false},
    {166, "NewBooleanArray", true},
    {167, "NewByteArray", true},
    {168, "NewCharArray", true},
    {169, "NewShortArray", true},
    {170, "NewIntArray", true},
    {171, "NewLongArray", true},
    {172, "NewFloatArray", true},
    {173, "NewDoubleArray", true},
    {174, "GetBooleanArrayElements", true},
    {175, "GetByteArrayElements", true},
    {176, "GetCharArrayElements", true},
    {177, "GetShortArrayElements", true},
    {178, "GetIntArrayElements", true},
    {179, "GetLongArrayElements", true},
    {180, "GetFloatArrayElements", true},
    {181, "GetDoubleArrayElements", true},
    {182, "ReleaseBooleanArrayElements", false},
    {183, "ReleaseByteArrayElements", false},
    {184, "ReleaseCharArrayElements", false},
    {185, "ReleaseShortArrayElements", false},
    {186, "ReleaseIntArrayElements", false},
    {187, "ReleaseLongArrayElements", false},
    {188, "ReleaseFloatArrayElements", false},
    {189, "ReleaseDoubleArrayElements", false},
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
  if (info) {
    if (!info->returns_handle) return 0;
    // Anything the caller will read as text needs to contain some.
    const bool textual = index == 156 || index == 160 || index == 154 ||
                         index == 158;
    return textual ? AllocateString() : Allocate();
  }
  // Not one we recognise. Erring towards a handle is the safer default: one
  // the caller ignores costs a block of arena, whereas a zero it treats as a
  // pointer or a count turns into arithmetic on nothing.
  return Allocate();
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
