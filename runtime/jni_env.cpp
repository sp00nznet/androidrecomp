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

// The environment's table, and eight more stubs behind it for the JavaVM's.
// The two are separate interfaces the guest reaches identically -- a table of
// function pointers, indexed and branched through -- so they share one pool of
// stubs and the VM's indices are simply offset past the environment's.
constexpr size_t kEnvSlots = 256;
constexpr size_t kVmSlots = 8;
constexpr size_t kVmBase = kEnvSlots;
constexpr size_t kSlots = kEnvSlots + kVmSlots;

// The table the guest sees, and the pointer that names it. A JNIEnv* is the
// address of `g_table`, not of the table itself -- one more level of
// indirection than feels natural, and the reason a null environment faults on
// a read rather than on a call.
uint64_t g_slots[kSlots];
uint64_t g_table = reinterpret_cast<uint64_t>(g_slots);

// The invocation interface, which is how the engine reaches the VM rather than
// one environment: three reserved entries, then DestroyJavaVM,
// AttachCurrentThread, DetachCurrentThread, GetEnv and
// AttachCurrentThreadAsDaemon. A JavaVM* is the address of `g_vm_table`, the
// same double indirection as above.
uint64_t g_vm_slots[kVmSlots];
uint64_t g_vm_table = reinterpret_cast<uint64_t>(g_vm_slots);

size_t g_hits[kSlots];
size_t g_total;

// --- the arena -------------------------------------------------------------
// Handles are blocks from a zeroed arena, reserved low in the address space. A
// handle is opaque in principle, but code with a 32-bit lineage stores one in
// an int, and a raw heap pointer does not survive that -- it reappears in
// arithmetic as a large negative number.
constexpr size_t kArenaSize = 32u << 20;
constexpr size_t kBlock = 64u << 10;
unsigned char* g_arena;
size_t g_arena_used;

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
  const uint64_t p = reinterpret_cast<uint64_t>(g_arena + g_arena_used);
  g_arena_used += kBlock;
  return p;
}

// A string handle carries its text, because something will measure it. An
// empty one is not harmless: the engine takes the length, subtracts one, and
// hands the result to memcpy.
uint64_t AllocateText(const char* text) {
  const uint64_t p = Allocate();
  if (p && text) {
    const size_t n = strlen(text);
    memcpy(reinterpret_cast<void*>(p), text, n < kBlock ? n + 1 : kBlock - 1);
  }
  return p;
}

// --- the object the engine is actually asking about ------------------------
//
// A JNI entry point is handed the object its Java declaration named, and reads
// its configuration out of it field by field. Answering every read with zero
// is why initialisation could not proceed: the engine was promised a device
// description, found nothing, and did arithmetic on the nothing.
//
// The field names are read out of the dex -- see tools/dex_contract.py. The
// values are ours to choose; what matters is that they are the right shape and
// that a string is never empty.
struct Field {
  const char* name;
  char kind;  // 's' text, 'i' integer, 'f' float, 'z' boolean
  const char* text;
  int64_t number;
  double real;
};

const Field kFields[] = {
    {"appPath", 's', "/assets", 0, 0},
    {"appBundle", 's', "androidrecomp.host", 0, 0},
    {"appVersion", 's', "1.0", 0, 0},
    {"clientVersion", 's', "1.0", 0, 0},
    {"deviceName", 's', "androidrecomp", 0, 0},
    {"deviceVersion", 's', "1.0", 0, 0},
    {"manufacturerName", 's', "generic", 0, 0},
    {"language", 's', "en", 0, 0},
    {"locale", 's', "en_US", 0, 0},
    {"width", 'i', nullptr, 1280, 0},
    {"height", 'i', nullptr, 720, 0},
    {"orientation", 'i', nullptr, 0, 0},
    {"model", 'i', nullptr, 0, 0},
    {"dpiFromCategory", 'i', nullptr, 320, 0},
    {"miNavBarHeight", 'i', nullptr, 0, 0},
    {"density", 'f', nullptr, 0, 2.0},
    {"densityDPI", 'f', nullptr, 0, 320.0},
    {"mbExternalStorageUnusable", 'z', nullptr, 0, 0},
};
constexpr size_t kFieldCount = sizeof(kFields) / sizeof(kFields[0]);

// Field ids are small and unlike handles, so a mix-up between the two is loud
// rather than plausible.
constexpr uint64_t kFieldIdBase = 0x0F1E1D00;

const Field* FieldFromId(uint64_t id) {
  const uint64_t index = id - kFieldIdBase;
  return index < kFieldCount ? &kFields[index] : nullptr;
}

uint64_t FieldIdFor(const char* name) {
  if (name) {
    for (size_t i = 0; i < kFieldCount; ++i)
      if (strcmp(kFields[i].name, name) == 0) return kFieldIdBase + i;
  }
  // Unknown field: still a usable id, and it reads as zero of its type.
  return kFieldIdBase + kFieldCount;
}

// --- slot behaviour --------------------------------------------------------

struct SlotInfo {
  int index;
  const char* name;
  bool returns_handle;
};

constexpr SlotInfo kKnown[] = {
    {4, "GetVersion", false},           {5, "DefineClass", true},
    {6, "FindClass", true},             {10, "GetSuperclass", true},
    {13, "Throw", false},               {14, "ThrowNew", false},
    {15, "ExceptionOccurred", false},   {16, "ExceptionDescribe", false},
    {17, "ExceptionClear", false},      {21, "NewGlobalRef", true},
    {22, "DeleteGlobalRef", false},     {23, "DeleteLocalRef", false},
    {24, "IsSameObject", false},        {25, "NewLocalRef", true},
    {27, "AllocObject", true},          {28, "NewObject", true},
    {29, "NewObjectV", true},           {30, "NewObjectA", true},
    {31, "GetObjectClass", true},       {32, "IsInstanceOf", false},
    {33, "GetMethodID", true},          {34, "CallObjectMethod", true},
    {61, "CallVoidMethod", false},      {94, "GetFieldID", true},
    {95, "GetObjectField", true},       {96, "GetBooleanField", false},
    {100, "GetIntField", false},        {101, "GetLongField", false},
    {102, "GetFloatField", false},
    // The nine that were missing, and whose absence shifted every index after
    // them nine places low.
    {104, "SetObjectField", false},     {105, "SetBooleanField", false},
    {106, "SetByteField", false},       {107, "SetCharField", false},
    {108, "SetShortField", false},      {109, "SetIntField", false},
    {110, "SetLongField", false},       {111, "SetFloatField", false},
    {112, "SetDoubleField", false},     {113, "GetStaticMethodID", true},
    {144, "GetStaticFieldID", true},    {145, "GetStaticObjectField", true},
    {150, "GetStaticIntField", false},  {163, "NewString", true},
    {164, "GetStringLength", false},    {165, "GetStringChars", true},
    {166, "ReleaseStringChars", false}, {167, "NewStringUTF", true},
    {168, "GetStringUTFLength", false}, {169, "GetStringUTFChars", true},
    {170, "ReleaseStringUTFChars", false},
    {171, "GetArrayLength", false},     {172, "NewObjectArray", true},
    {173, "GetObjectArrayElement", true},
    {174, "SetObjectArrayElement", false},
    {175, "NewBooleanArray", true},     {176, "NewByteArray", true},
    {177, "NewCharArray", true},        {178, "NewShortArray", true},
    {179, "NewIntArray", true},         {180, "NewLongArray", true},
    {181, "NewFloatArray", true},       {182, "NewDoubleArray", true},
    {183, "GetBooleanArrayElements", true},
    {184, "GetByteArrayElements", true},
    {185, "GetCharArrayElements", true},
    {186, "GetShortArrayElements", true},
    {187, "GetIntArrayElements", true},
    {188, "GetLongArrayElements", true},
    {189, "GetFloatArrayElements", true},
    {190, "GetDoubleArrayElements", true},
    {215, "RegisterNatives", false},    {219, "GetJavaVM", false},
    {226, "NewWeakGlobalRef", true},
    // ExceptionCheck must answer false, or the engine believes a throw is
    // pending after every call and unwinds instead of continuing.
    {228, "ExceptionCheck", false},     {229, "NewDirectByteBuffer", true},

    // The invocation interface, offset past the environment's slots.
    {kVmBase + 3, "DestroyJavaVM", false},
    {kVmBase + 4, "AttachCurrentThread", false},
    {kVmBase + 5, "DetachCurrentThread", false},
    {kVmBase + 6, "GetEnv", false},
    {kVmBase + 7, "AttachCurrentThreadAsDaemon", false},
};

const SlotInfo* Lookup(size_t index) {
  for (const SlotInfo& s : kKnown)
    if (static_cast<size_t>(s.index) == index) return &s;
  return nullptr;
}

const char* NameOf(size_t index) {
  const SlotInfo* s = Lookup(index);
  return s ? s->name : "JNI slot";
}

// Every slot takes the context, so it can read its arguments and put a result
// in the right register. A float return lives in v0, which an
// integer-returning thunk has no way to express.
void Handle(size_t index, Arm64Ctx* c) {
  if (index < kSlots) ++g_hits[index];
  ++g_total;

  switch (index) {
    case 94: {  // GetFieldID(env, class, name, signature)
      c->x[0] = FieldIdFor(reinterpret_cast<const char*>(c->x[2]));
      return;
    }
    case 95: {  // GetObjectField(env, object, fieldID)
      const Field* f = FieldFromId(c->x[2]);
      c->x[0] = AllocateText(f && f->kind == 's' ? f->text : "");
      return;
    }
    case 96: {  // GetBooleanField
      const Field* f = FieldFromId(c->x[2]);
      c->x[0] = f && f->kind == 'z' ? static_cast<uint64_t>(f->number) : 0;
      return;
    }
    case 100:    // GetIntField
    case 101: {  // GetLongField
      const Field* f = FieldFromId(c->x[2]);
      c->x[0] = f && f->kind == 'i' ? static_cast<uint64_t>(f->number) : 0;
      return;
    }
    case 102: {  // GetFloatField -- the result belongs in v0, not x0
      const Field* f = FieldFromId(c->x[2]);
      arc_s_w(c, 0, f && f->kind == 'f' ? static_cast<float>(f->real) : 0.0f);
      return;
    }
    case 164:    // GetStringLength
    case 168: {  // GetStringUTFLength
      const char* s = reinterpret_cast<const char*>(c->x[1]);
      c->x[0] = s ? strlen(s) : 0;
      return;
    }
    case 165:    // GetStringChars
    case 169: {  // GetStringUTFChars -- a jstring already holds its own text
      c->x[0] = c->x[1];
      if (c->x[2]) *reinterpret_cast<uint8_t*>(c->x[2]) = 0;  // isCopy = false
      return;
    }
    case 219: {  // GetJavaVM(env, JavaVM** out)
      // Writing the VM out is the whole point of the call. Left unwritten, the
      // caller reads whatever that variable happened to hold and branches
      // through it as though it were a table of functions.
      if (c->x[1])
        *reinterpret_cast<uint64_t*>(c->x[1]) =
            reinterpret_cast<uint64_t>(&g_vm_table);
      c->x[0] = 0;  // JNI_OK
      return;
    }

    // The invocation interface. Attaching a thread and asking for its
    // environment both hand back the one environment there is: nothing in it
    // is per-thread, so every thread can share it.
    case kVmBase + 4:    // AttachCurrentThread(vm, JNIEnv**, void*)
    case kVmBase + 6:    // GetEnv(vm, void**, version)
    case kVmBase + 7: {  // AttachCurrentThreadAsDaemon
      if (c->x[1])
        *reinterpret_cast<uint64_t*>(c->x[1]) =
            reinterpret_cast<uint64_t>(&g_table);
      c->x[0] = 0;
      return;
    }
    case kVmBase + 3:  // DestroyJavaVM
    case kVmBase + 5:  // DetachCurrentThread
      c->x[0] = 0;
      return;

    default:
      break;
  }

  const SlotInfo* info = Lookup(index);
  if (info) {
    c->x[0] = info->returns_handle ? Allocate() : 0;
    return;
  }
  // Not one we recognise. Erring towards a handle is safer: one the caller
  // ignores costs a block of arena, whereas a zero it treats as a pointer or a
  // count becomes arithmetic on nothing.
  c->x[0] = Allocate();
}

template <size_t N>
void Slot(Arm64Ctx* c) {
  Handle(N, c);
}

template <size_t... I>
void FillSlots(std::index_sequence<I...>) {
  ((g_slots[I] = reinterpret_cast<uint64_t>(&Slot<I>)), ...);
}

struct Init {
  Init() {
    FillSlots(std::make_index_sequence<kSlots>{});
    // The VM's table is the tail of the same pool, so the two interfaces are
    // dispatched and named by one mechanism.
    for (size_t i = 0; i < kVmSlots; ++i) g_vm_slots[i] = g_slots[kVmBase + i];
  }
} g_init;

}  // namespace

extern "C" {

uint64_t arc_jni_env(void) { return reinterpret_cast<uint64_t>(&g_table); }

uint64_t arc_jni_vm(void) { return reinterpret_cast<uint64_t>(&g_vm_table); }

void arc_jni_register(void) {
  uint64_t low = g_slots[0], high = g_slots[0];
  for (size_t i = 0; i < kSlots; ++i) {
    arc_register_ctx_native(g_slots[i], NameOf(i),
                            reinterpret_cast<ArcCtxFn>(g_slots[i]));
    if (g_slots[i] < low) low = g_slots[i];
    if (g_slots[i] > high) high = g_slots[i];
  }
  // Printed because a branch through this table that the dispatcher does not
  // recognise is otherwise indistinguishable from one that never came from
  // here at all: with the extent in hand, an address either is a slot or is
  // not, and there is nothing to reason about.
  printf("jni        %zu slots at %p, stubs %#llx..%#llx\n", kSlots,
         static_cast<void*>(&g_table), static_cast<unsigned long long>(low),
         static_cast<unsigned long long>(high));
}

// The object handed to an entry point as its `this`. Nothing reads it
// directly -- every access goes through a field accessor -- so a block of
// arena is enough.
uint64_t arc_jni_object(void) { return Allocate(); }

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
  for (size_t i = 0; i < kSlots; ++i)
    if (g_hits[i])
      printf("    %6zu x  slot %3zu  %s\n", g_hits[i], i, NameOf(i));
}

}  // extern "C"
