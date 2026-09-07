#include "jni_env.h"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <filesystem>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#endif

#include "arm64_context.h"
#include "shim.h"

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

// Counters, not state the guest depends on -- but written from every thread
// the engine starts, so they are atomic rather than merely approximate.
std::atomic<size_t> g_hits[kSlots];
std::atomic<size_t> g_total;

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

// Locked, because the engine reaches this from every thread it starts. Two
// threads racing here do not merely miscount: both leave with the same block,
// and a handle that two owners are writing over is a pointer that reads back
// as something no one stored -- which surfaces far away as a branch to an
// address that was never in any mapped image.
std::mutex g_arena_lock;

uint64_t Allocate() {
  std::lock_guard<std::mutex> held(g_arena_lock);
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
    // Answered from the asset root, not from here -- see DirectoryForName.
    {"writablePath", 's', ".", 0, 0},
    {"appBundle", 's', "androidrecomp.host", 0, 0},
    // Three components, not two. The engine parses these, and with "1.0" its
    // search for the second separator finds nothing -- the span computed from
    // that comes out negative and goes straight into memcpy as -1, which reads
    // until it leaves the heap. The value is ours to choose; the shape is not.
    {"appVersion", 's', "1.0.0", 0, 0},
    {"clientVersion", 's', "1.0.0", 0, 0},
    {"deviceName", 's', "androidrecomp", 0, 0},
    {"deviceVersion", 's', "1.0.0", 0, 0},
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
    // The API level, which read as zero -- not a version any Android
    // ever had, so every check against it took a branch meant for no
    // real device. 21 is the oldest level that can load an arm64
    // library, which keeps the engine on its most self-contained paths
    // rather than ones gated behind newer Java APIs nothing here has.
    {"sdk_int", 'i', nullptr, 21, 0},
    // Zero already meant "no override"; naming it stops it being
    // reported as missing and records that the value is deliberate.
    {"screenOverride", 'i', nullptr, 0, 0},
};
constexpr size_t kFieldCount = sizeof(kFields) / sizeof(kFields[0]);

// Field ids are small and unlike handles, so a mix-up between the two is loud
// rather than plausible.
constexpr uint64_t kFieldIdBase = 0x0F1E1D00;

const Field* FieldFromId(uint64_t id) {
  const uint64_t index = id - kFieldIdBase;
  return index < kFieldCount ? &kFields[index] : nullptr;
}

// Fields the engine asked for that this table has no answer for. Each reads as
// zero of its type -- an empty string, a zero count -- which is a plausible
// value rather than a visible failure, so the engine carries it away and comes
// apart somewhere else entirely. Naming them is the difference between that and
// a line saying which one to add.
std::mutex g_field_lock;
std::deque<std::string> g_unknown_fields;

uint64_t FieldIdFor(const char* name, const char* sig) {
  if (name) {
    for (size_t i = 0; i < kFieldCount; ++i)
      if (strcmp(kFields[i].name, name) == 0) return kFieldIdBase + i;
    // Record the signature with the name. A missing field has to be added back
    // as some particular type, and the caller already said which -- guessing
    // between an int, a boolean and a string is a wrong answer two times in
    // three, and each wrong answer reads as a plausible zero somewhere later.
    const std::string entry = std::string(name) + "  " + (sig ? sig : "?");
    std::lock_guard<std::mutex> held(g_field_lock);
    bool seen = false;
    for (const std::string& s : g_unknown_fields)
      if (s == entry) { seen = true; break; }
    if (!seen) g_unknown_fields.push_back(entry);
  }
  // Unknown field: still a usable id, and it reads as zero of its type.
  return kFieldIdBase + kFieldCount;
}

// --- methods ---------------------------------------------------------------
//
// A method id is opaque, so it may as well be an index into the names the
// engine asked for. That is worth keeping, because a call through an id is
// otherwise answerable only with a blank handle -- and a method that was
// supposed to return a path, answered with an empty string, is how a bundle
// path becomes "/".
//
// A deque and not a vector: names are handed out as pointers and another
// thread may be adding one, which would move a vector's contents.
constexpr uint64_t kMethodIdBase = 0x0E2D1000;
std::mutex g_method_lock;
std::deque<std::string> g_method_names;
std::deque<std::string> g_method_unanswered;

uint64_t MethodIdFor(const char* name) {
  const std::string wanted = name ? name : "?";
  std::lock_guard<std::mutex> held(g_method_lock);
  for (size_t i = 0; i < g_method_names.size(); ++i)
    if (g_method_names[i] == wanted) return kMethodIdBase + i;
  g_method_names.push_back(wanted);
  return kMethodIdBase + g_method_names.size() - 1;
}

const char* MethodName(uint64_t id) {
  const uint64_t index = id - kMethodIdBase;
  std::lock_guard<std::mutex> held(g_method_lock);
  return index < g_method_names.size() ? g_method_names[index].c_str()
                                       : nullptr;
}

void NoteUnanswered(const char* name) {
  if (!name) return;
  std::lock_guard<std::mutex> held(g_method_lock);
  for (const std::string& s : g_method_unanswered)
    if (s == name) return;
  g_method_unanswered.push_back(name);
}

// Every method actually invoked, as opposed to merely looked up. The
// difference matters: a name can be resolved to an id during setup and then
// never called, and reading a value into the answer for a call that never
// happened is a way to spend a long time being wrong.
std::deque<std::string> g_method_called;

void NoteCalled(const char* name) {
  if (!name) return;
  std::lock_guard<std::mutex> held(g_method_lock);
  for (const std::string& s : g_method_called)
    if (s == name) return;
  g_method_called.push_back(name);
}

// What a method returning a string should answer with. The engine builds paths
// out of these, so an empty one is worse than a wrong one: it silently becomes
// the filesystem root.
struct MethodText {
  const char* name;
  const char* text;
};

const MethodText kMethodText[] = {
    {"getCocos2dxPackageName", "androidrecomp.host"},
    {"getPackageName", "androidrecomp.host"},
    // A document, not a name: the engine parses this one as JSON and says so
    // when it cannot ("Failed to construct JsonMap from string ...").
    {"getDeviceInfo", "{}"},
    {"getDeviceModel", "androidrecomp"},
    {"getCurrentLanguage", "en"},
    {"getLanguage", "en"},
    {"getCountry", "US"},
    {"getVersion", "1.0"},
    // A locale variant and an absent preference are legitimately empty, and
    // saying so is different from having no answer.
    {"getVariant", ""},
    {"getStringPreference", ""},
};

// The first argument in a guest va_list that is one of our own handles.
//
// Which position a jstring or a byte[] occupies depends on the Java signature,
// which we do not have -- but a handle we made is recognisable, and no other
// argument will be. So "the first one that is ours" is both the answer and the
// only question we can actually ask.
uint64_t FirstOwnedArg(Arm64Ctx* c) {
  if (!c->x[3]) return 0;
  std::vector<unsigned char> cursor(arc::ShimVaListSize());
  memcpy(cursor.data(), reinterpret_cast<const void*>(c->x[3]), cursor.size());
  for (int i = 0; i < 6; ++i) {
    const uint64_t v = arc::ShimVaNextInt(cursor.data());
    if (v && arc_jni_owns(v)) return v;
  }
  return 0;
}

// What a method returning an integer should answer with. Zero is the default
// and is usually harmless; these are the ones where it is a specific, wrong
// claim about the device.
struct MethodNumber {
  const char* name;
  int64_t value;
};

const MethodNumber kMethodNumbers[] = {
    // Free disk space, in bytes. The engine is about to download content, so
    // it checks for room before it starts loading and quietly refuses below
    // about 40 MB. Zero means "the disk is full": the loading manager goes to
    // a phase that never initialises the font system, every font cache lookup
    // afterwards answers null, and the first one whose caller does not check
    // takes the process down. Four gigabytes free is an ordinary answer.
    {"getFreeDiskSpace", 4LL << 30},
};

int64_t NumberForMethod(uint64_t id, bool* answered) {
  *answered = false;
  const char* name = MethodName(id);
  if (!name) return 0;
  NoteCalled(name);
  for (const MethodNumber& m : kMethodNumbers)
    if (strcmp(m.name, name) == 0) {
      *answered = true;
      return m.value;
    }
  NoteUnanswered(name);
  return 0;
}

// The engine's own log, which on Android goes to Java rather than to
// __android_log. These are the names it writes through; anything else that
// returns void stays quiet.
bool IsLogMethod(const char* name) {
  static const char* const kNames[] = {"Log",      "log",     "LogError",
                                       "logError", "LogInfo", "printLog",
                                       "writeWithTitle", "LogToFile"};
  for (const char* n : kNames)
    if (strcmp(n, name) == 0) return true;
  return false;
}

// What a method returning a boolean should answer with. False is the safe
// default -- "no notification launched us", "no other music is playing" -- and
// it is what an unlisted name gets. These are the ones where false is not
// merely conservative but wrong.
struct MethodFlag {
  const char* name;
  bool value;
};

const MethodFlag kMethodFlags[] = {
    // Handled by ThreadComplete() below rather than here, because "how long
    // did the thread take" is a real variable and answering it instantly is
    // not obviously the honest answer. Listed so the name is not reported as
    // unanswered.
    {"isThreadComplete", true},
    // Java being asked to create a directory. False means it failed, and the
    // caller treats that as a fatal setup error. The filesystem shim creates
    // what the engine actually opens.
    {"mkdir", true},
    // Reachability is a question the engine asks Java, not the network: it
    // never opens a socket to find out. Answered false, it never tries at all
    // -- it goes straight to its error state and offers to retry, which is a
    // correct-looking screen produced without a single connect(). The host has
    // a network; say so, and let the connection succeed or fail on its own.
    {"hasConnectivity", true},
};

// Tri-state on purpose: "not in the table" has to stay distinguishable from
// "in the table, answering false", or every unanswered call would be recorded
// as a deliberate no.
// The loading screen polls a Java worker thread and will not advance until it
// says it is finished. There is no Java here and no work outstanding, so the
// truthful answer is "finished" -- but on a device that thread takes real
// time, and the engine advances its own state machine while it waits. Saying
// yes on the very first poll compresses that to nothing, which is a different
// order of events than the engine was written against.
//
// So it is a knob, defaulting to answering immediately: ARC_THREAD_POLLS is
// how many polls to answer "still running" first. This is the sort of thing a
// real device varies and a host cannot infer.
bool ThreadComplete() {
  static const long wait = [] {
    const char* s = getenv("ARC_THREAD_POLLS");
    return s ? strtol(s, nullptr, 10) : 0;
  }();
  static std::atomic<long> polls{0};
  return polls++ >= wait;
}

bool FlagForMethod(uint64_t id, bool* answered) {
  *answered = false;
  const char* name = MethodName(id);
  if (!name) return false;
  NoteCalled(name);
  if (strcmp(name, "isThreadComplete") == 0) {
    *answered = true;
    return ThreadComplete();
  }
  for (const MethodFlag& m : kMethodFlags)
    if (strcmp(m.name, name) == 0) {
      *answered = true;
      return m.value;
    }
  NoteUnanswered(name);
  return false;
}

// The two the engine turns into directories, which have to be real paths on
// this machine rather than anything invented. They come from the asset root
// the host was given: the bundle is that directory, and what the engine writes
// goes beside it rather than into it.
// The device's locale, which is a real property of a real device and not
// something a host can infer. The engine matches the language string against a
// table of twenty-two it knows and takes the index; a string it does not know
// is index zero, which is also what "English" is, and the two are not
// distinguishable downstream.
//
// So it is a knob. ARC_LANG and ARC_LOCALE override what the JNI bridge
// answers, which is how you find out what a title does with a locale other
// than the one you guessed.
const char* LocaleOverride(const char* name) {
  if (strcmp(name, "language") == 0 || strcmp(name, "getLanguage") == 0 ||
      strcmp(name, "getCurrentLanguage") == 0) {
    static const char* v = getenv("ARC_LANG");
    return v;
  }
  if (strcmp(name, "locale") == 0) {
    static const char* v = getenv("ARC_LOCALE");
    return v;
  }
  return nullptr;
}

const char* DirectoryForName(const char* name) {
  static std::mutex lock;
  static std::string bundle, storage;
  const char* root = arc::ShimAssetRoot();
  if (!root || !*root) return nullptr;
  std::lock_guard<std::mutex> held(lock);
  if (strcmp(name, "getBundleDir") == 0 || strcmp(name, "getAssetsPath") == 0 ||
      strcmp(name, "getCocos2dxWritablePath") == 0 ||
      strcmp(name, "appPath") == 0) {
    bundle = root;
    return bundle.c_str();
  }
  if (strcmp(name, "getStorageDir") == 0 ||
      strcmp(name, "writablePath") == 0) {
    // The same directory, not the one above it. Android hands a title one data
    // directory and it both reads its content out of that and writes beside
    // it: Tapped Out builds "<writablePath>/core/res-core/UberShader.vsh" and
    // "<writablePath>/prefbackup" from the same string. Answering with the
    // parent put every shipped file one directory out of reach, which shows up
    // not as a missing file but as an empty shader that links to nothing and
    // draws a black screen behind a full set of draw calls.
    storage = root;
    return storage.c_str();
  }
  return nullptr;
}

const char* TextForMethod(uint64_t id) {
  const char* name = MethodName(id);
  if (!name) return nullptr;
  NoteCalled(name);
  if (const char* v = LocaleOverride(name)) return v;
  if (const char* dir = DirectoryForName(name)) return dir;
  for (const MethodText& m : kMethodText)
    if (strcmp(m.name, name) == 0) return m.text;
  NoteUnanswered(name);
  return nullptr;
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
    {17, "ExceptionClear", false},      {19, "PushLocalFrame", false},
    {20, "PopLocalFrame", true},        {21, "NewGlobalRef", true},
    {22, "DeleteGlobalRef", false},     {23, "DeleteLocalRef", false},
    {24, "IsSameObject", false},        {25, "NewLocalRef", true},
    {27, "AllocObject", true},          {28, "NewObject", true},
    {29, "NewObjectV", true},           {30, "NewObjectA", true},
    {31, "GetObjectClass", true},       {32, "IsInstanceOf", false},
    {33, "GetMethodID", true},          {34, "CallObjectMethod", true},
    {35, "CallObjectMethodV", true},    {61, "CallVoidMethod", false},
    {94, "GetFieldID", true},
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
    {115, "CallStaticObjectMethodV", true},
    {37, "CallBooleanMethod", false},
    {38, "CallBooleanMethodV", false},
    {39, "CallBooleanMethodA", false},
    {117, "CallStaticBooleanMethod", false},
    {118, "CallStaticBooleanMethodV", false},
    {119, "CallStaticBooleanMethodA", false},
    {130, "CallStaticIntMethodV", false},
    {142, "CallStaticVoidMethodV", false},
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
    {208, "SetByteArrayRegion", false}, {211, "SetIntArrayRegion", false},
    {215, "RegisterNatives", false},    {219, "GetJavaVM", false},
    {222, "GetPrimitiveArrayCritical", true},
    {223, "ReleasePrimitiveArrayCritical", false},
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

  // The three slots that carry a name. A frame that repeats the same
  // lookups is asking for something it never gets, and the only way to
  // know which thing is to read the names it asks by.
  {
    static const bool trace = getenv("ARC_TRACE_JNI") != nullptr;
    if (trace) {
      const char* what = index == 6 ? "FindClass"
                       : index == 33 ? "GetMethodID"
                       : index == 113 ? "GetStaticMethodID"
                       : index == 167 ? "NewStringUTF"
                       : index == 94 ? "GetFieldID" : nullptr;
      if (what) {
        const uint64_t reg = (index == 6 || index == 167) ? c->x[1] : c->x[2];
        fprintf(stderr, "[jni] %s %.72s\n", what,
                reg ? reinterpret_cast<const char*>(reg) : "(null)");
      }
      // A call through an id says nothing on its own. The name behind the
      // id is the whole content of the event: which Java method the engine
      // reached for, and therefore what it believes it is doing.
      if (index >= 34 && index <= 143) {
        if (const char* called = MethodName(c->x[2]))
          fprintf(stderr, "[jni] %s -> %.72s\n", NameOf(index), called);
      }
    }
  }

  switch (index) {
    case 94: {  // GetFieldID(env, class, name, signature)
      c->x[0] = FieldIdFor(reinterpret_cast<const char*>(c->x[2]),
                           reinterpret_cast<const char*>(c->x[3]));
      return;
    }
    case 95: {  // GetObjectField(env, object, fieldID)
      const Field* f = FieldFromId(c->x[2]);
      if (f && f->kind == 's') {
        // A path field has to name a directory that exists on this machine, so
        // it comes from the asset root rather than from the table.
        if (const char* dir = DirectoryForName(f->name)) {
          c->x[0] = AllocateText(dir);
          return;
        }
        if (const char* v = LocaleOverride(f->name)) {
          c->x[0] = AllocateText(v);
          return;
        }
      }
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
    case 165: {  // GetStringChars -- UTF-16, not the UTF-8 the handle holds
      // Handing the handle straight back gives the caller our bytes read as
      // sixteen-bit units, which is right only for a single ASCII character
      // and garbage for anything longer. That is the sort of accident that
      // reads as working: a one-character path survives it intact.
      // ponytail: ASCII widened one byte per unit. Decode properly if a title
      // ever hands us a string that is not.
      const char* s = reinterpret_cast<const char*>(c->x[1]);
      const uint64_t wide = Allocate();
      if (wide && s) {
        auto* out = reinterpret_cast<uint16_t*>(wide);
        size_t i = 0;
        for (; s[i] && (i + 1) * sizeof(uint16_t) < kBlock; ++i)
          out[i] = static_cast<unsigned char>(s[i]);
        out[i] = 0;
      }
      c->x[0] = wide;
      if (c->x[2]) *reinterpret_cast<uint8_t*>(c->x[2]) = 1;  // isCopy = true
      return;
    }
    case 169: {  // GetStringUTFChars -- a jstring already holds its own text
      // An empty answer here is the dangerous one: a caller that takes the
      // length and subtracts one gets -1, hands that to memcpy, and runs off
      // the end of the arena a long way from the call that caused it. Worth
      // being able to see which string was empty and which was not.
      static const bool trace = getenv("ARC_TRACE_JNI") != nullptr;
      if (trace) {
        const char* s = reinterpret_cast<const char*>(c->x[1]);
        fprintf(stderr, "[jni] GetStringUTFChars %#llx %s \"%.48s\"\n",
                static_cast<unsigned long long>(c->x[1]),
                arc_jni_owns(c->x[1]) ? "ours" : "not ours", s ? s : "");
      }
      c->x[0] = c->x[1];
      if (c->x[2]) *reinterpret_cast<uint8_t*>(c->x[2]) = 0;  // isCopy = false
      return;
    }
    case 33:     // GetMethodID(env, class, name, signature)
    case 113: {  // GetStaticMethodID
      c->x[0] = MethodIdFor(reinterpret_cast<const char*>(c->x[2]));
      return;
    }

    // A call returning an object. Where the method's name says that object is
    // a string, answer with one: the engine joins these into paths, and an
    // empty answer is not a harmless unknown -- it becomes the filesystem root
    // and everything looked up beneath it fails.
    case 34:     // CallObjectMethod(env, obj, methodID, ...)
    case 35:     // CallObjectMethodV
    case 36:     // CallObjectMethodA
    case 114:    // CallStaticObjectMethod
    case 115:    // CallStaticObjectMethodV
    case 116: {  // CallStaticObjectMethodA
      // `String.getBytes()` and `toString()` are how a Java string becomes
      // something the engine can read, and both are called *on* the string --
      // so the answer is that object's own text, not an entry in a table. This
      // is why nothing ever called GetStringUTFChars: the conversion goes this
      // way instead, and answering it with a blank handle made every path the
      // engine asked for come back empty.
      const char* name = MethodName(c->x[2]);
      if (name && (strcmp(name, "getBytes") == 0 ||
                   strcmp(name, "toString") == 0)) {
        NoteCalled(name);
        const char* self = reinterpret_cast<const char*>(c->x[1]);
        // Whether the object carries text at all is the question these turn
        // on: a handle we made for a string does, and one we handed back for
        // something we did not understand is a zeroed block that does not.
        static const bool trace = getenv("ARC_TRACE_JNI") != nullptr;
        if (trace)
          fprintf(stderr, "[jni] %s on %#llx %s text=\"%.48s\"\n", name,
                  static_cast<unsigned long long>(c->x[1]),
                  arc_jni_owns(c->x[1]) ? "ours" : "not ours",
                  self ? self : "");
        c->x[0] = AllocateText(self);
        return;
      }
      // A *static* helper that turns something into a String -- the engine
      // fills a byte array and hands it to one of these. The text is in an
      // argument rather than in the object, and passing the handle straight
      // back is what a jstring means here anyway.
      if (name && (strcmp(name, "CreateNewStringUTFSafe") == 0 ||
                   strcmp(name, "createNewStringUTFSafe") == 0 ||
                   strcmp(name, "newStringUTF") == 0)) {
        NoteCalled(name);
        if (const uint64_t arg = FirstOwnedArg(c)) {
          c->x[0] = arg;
          return;
        }
      }
      const char* text = TextForMethod(c->x[2]);
      c->x[0] = text ? AllocateText(text) : Allocate();
      return;
    }

    // A method returning an integer, in every spelling JNI has for it: byte,
    // char, short, int and long, called on an object or on a class, through
    // varargs, a va_list or an array. The width does not change the answer.
    case 40: case 41: case 42:     // CallByteMethod{,V,A}
    case 43: case 44: case 45:     // CallCharMethod
    case 46: case 47: case 48:     // CallShortMethod
    case 49: case 50: case 51:     // CallIntMethod
    case 52: case 53: case 54:     // CallLongMethod
    case 120: case 121: case 122:  // CallStaticByteMethod
    case 123: case 124: case 125:  // CallStaticCharMethod
    case 126: case 127: case 128:  // CallStaticShortMethod
    case 129: case 130: case 131:  // CallStaticIntMethod
    case 132: case 133: case 134: {  // CallStaticLongMethod
      bool answered = false;
      c->x[0] = static_cast<uint64_t>(NumberForMethod(c->x[2], &answered));
      return;
    }

    // A method returning nothing. Almost all of these are genuinely ignorable
    // -- telemetry, analytics, a crash-reporter key -- but one is not: the
    // engine writes its *own* diagnostic log through Java rather than through
    // __android_log, so dropping these silently throws away the running
    // commentary a port most needs. Anything log-shaped is printed.
    case 61:     // CallVoidMethod
    case 62:     // CallVoidMethodV
    case 63:     // CallVoidMethodA
    case 141:    // CallStaticVoidMethod
    case 142:    // CallStaticVoidMethodV
    case 143: {  // CallStaticVoidMethodA
      const char* name = MethodName(c->x[2]);
      if (name) NoteCalled(name);
      // Only the va_list forms carry arguments we can walk; the varargs forms
      // spread theirs across registers we were not handed.
      const bool va = index == 62 || index == 142;
      if (name && va && IsLogMethod(name)) {
        if (const uint64_t msg = FirstOwnedArg(c))
          fprintf(stderr, "[game] %.400s\n",
                  reinterpret_cast<const char*>(msg));
      }
      c->x[0] = 0;
      return;
    }

    // A method returning a boolean, called on an object or on a class. Six
    // slots each because JNI spells every call three ways -- varargs, va_list
    // and array -- and the answer does not depend on which.
    case 37:     // CallBooleanMethod
    case 38:     // CallBooleanMethodV
    case 39:     // CallBooleanMethodA
    case 117:    // CallStaticBooleanMethod
    case 118:    // CallStaticBooleanMethodV
    case 119: {  // CallStaticBooleanMethodA
      bool answered = false;
      c->x[0] = FlagForMethod(c->x[2], &answered) ? 1 : 0;
      return;
    }

    case 171: {  // GetArrayLength
      // Our byte arrays are the same NUL-terminated text a string handle
      // holds, so their length is simply that. An array we did not fill is a
      // zeroed block, which measures zero -- which is the truth about it.
      const char* s = reinterpret_cast<const char*>(c->x[1]);
      c->x[0] = s ? strlen(s) : 0;
      return;
    }
    case 184:    // GetByteArrayElements
    case 222: {  // GetPrimitiveArrayCritical -- the same question, asked in
                 // the form that promises not to hold the collector up
      // The elements *are* the handle: that is where the bytes were put. The
      // default for a slot that returns something is a fresh block, and a
      // fresh block is empty -- so a caller reading an array through this got
      // nothing back and had no way to tell that from an empty array.
      c->x[0] = c->x[1];
      if (c->x[2]) *reinterpret_cast<uint8_t*>(c->x[2]) = 0;  // isCopy = false
      return;
    }
    case 208: {  // SetByteArrayRegion(env, array, start, len, buf)
      // The engine builds a Java string by filling a byte array and handing it
      // to a helper. Dropping this leaves the array empty, the string empty,
      // and the engine's own log a column of blank lines.
      auto* dst = reinterpret_cast<char*>(c->x[1]);
      const auto* src = reinterpret_cast<const char*>(c->x[4]);
      const uint64_t start = c->x[2], len = c->x[3];
      if (dst && src && arc_jni_owns(c->x[1]) && start + len < kBlock) {
        memcpy(dst + start, src, static_cast<size_t>(len));
        // NUL-terminated, because everything downstream reads it as text.
        dst[start + len] = '\0';
      }
      return;
    }

    case 191:    // ReleaseBooleanArrayElements
    case 192:    // ReleaseByteArrayElements
    case 223:    // ReleasePrimitiveArrayCritical
      return;    // nothing was copied, so there is nothing to write back

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

// A jstring, which here is just its own text: every path that reads one --
// GetStringUTFChars, getBytes, toString -- hands the handle straight back.
uint64_t arc_jni_string(const char* text) { return AllocateText(text); }

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
  // Loaded explicitly: an atomic has no business being passed to a variadic
  // function, and MSVC is right to refuse it.
  printf("  %zu JNI calls across these slots:\n", g_total.load());
  for (size_t i = 0; i < kSlots; ++i)
    if (const size_t n = g_hits[i].load())
      printf("    %6zu x  slot %3zu  %s\n", n, i, NameOf(i));

  // The Java methods the engine called expecting an object back, that nothing
  // here had a value for. Each got a blank handle, which reads as an empty
  // string -- so any of these that was meant to be a path is a lookup failing
  // somewhere later for a reason that points nowhere near here.
  {
    std::lock_guard<std::mutex> held(g_field_lock);
    if (!g_unknown_fields.empty()) {
      printf("  object fields asked for that nothing here answers:\n   ");
      for (const std::string& s : g_unknown_fields) printf(" %s", s.c_str());
      printf("\n");
    }
  }
  std::lock_guard<std::mutex> held(g_method_lock);
  if (!g_method_called.empty()) {
    printf("  Java methods invoked:\n   ");
    for (const std::string& s : g_method_called) printf(" %s", s.c_str());
    printf("\n");
  }
  if (!g_method_unanswered.empty()) {
    printf("  ...of which these had no value to return:\n   ");
    for (const std::string& s : g_method_unanswered) printf(" %s", s.c_str());
    printf("\n");
  }
}

}  // extern "C"
