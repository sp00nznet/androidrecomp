// Runtime support for lifted code that cannot be expressed inline.
//
// `arc_dispatch` is deliberately not here: it needs the address -> function
// table, which only the generated module knows, so the generated code defines
// it.

#include "arm64_context.h"

#include <errno.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <time.h>
#endif

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

// The thread pointer. Bionic points TPIDR_EL0 at a per-thread control block,
// and compiled code indexes off it and dereferences without checking -- so
// returning zero is not "no value", it is a null pointer with a small offset
// added, which faults at a low address that looks like a lifter bug.
//
// Nothing here reads meaningful values out of the block; the guest wants it for
// its own thread-local storage. It only has to be real, zeroed, writable memory
// of a plausible size.
#define ARC_TLS_BLOCK 16384
static ARC_THREAD_LOCAL uint64_t t_tpidr;

uint64_t arc_tpidr_read(void) {
  if (!t_tpidr) t_tpidr = (uint64_t)(uintptr_t)calloc(1, ARC_TLS_BLOCK);
  return t_tpidr;
}

void arc_tpidr_write(uint64_t v) { t_tpidr = v; }

uint64_t arc_cntvct_read(void) {
#if defined(_WIN32)
  LARGE_INTEGER now, freq;
  QueryPerformanceCounter(&now);
  QueryPerformanceFrequency(&freq);
  return (uint64_t)((now.QuadPart * 1000000000LL) / freq.QuadPart);
#else
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
#endif
}

static ARC_THREAD_LOCAL uint64_t t_fpcr;
uint64_t arc_fpcr_read(void) { return t_fpcr; }
void arc_fpcr_write(uint64_t v) { t_fpcr = v; }

// The guest's jmp_buf is its own memory and its own size; ours has to live
// somewhere we control, so the two are paired here rather than laid on top of
// one another. Sixteen is generous for nesting -- a decoder arms one and an
// unwinder maybe another -- and reusing the oldest is better than refusing,
// because a refused setjmp is a jump that lands nowhere later.
#define ARC_JMP_SLOTS 16
typedef struct {
  uint64_t guest;
  jmp_buf host;
  /* x19-x30 and the stack pointer: what the architecture says a jump puts
     back, and what the returned-to function's own frame check depends on. */
  uint64_t saved[12];
  uint64_t sp;
  int used;
} ArcJmpSlot;
static ARC_THREAD_LOCAL ArcJmpSlot t_jmps[ARC_JMP_SLOTS];
static ARC_THREAD_LOCAL int t_jmp_next;

static void arc_jmp_save(ArcJmpSlot* slot, const Arm64Ctx* c) {
  int r;
  for (r = 19; r <= 30; ++r) slot->saved[r - 19] = c->x[r];
  slot->sp = c->sp;
}

static void arc_jmp_restore(const ArcJmpSlot* slot, Arm64Ctx* c) {
  int r;
  for (r = 19; r <= 30; ++r) c->x[r] = slot->saved[r - 19];
  c->sp = slot->sp;
}

void* arc_jmpbuf_for(Arm64Ctx* c, uint64_t guest_buffer) {
  int i;
  for (i = 0; i < ARC_JMP_SLOTS; ++i)
    if (t_jmps[i].used && t_jmps[i].guest == guest_buffer) {
      arc_jmp_save(&t_jmps[i], c);
      return &t_jmps[i].host;
    }
  for (i = 0; i < ARC_JMP_SLOTS; ++i)
    if (!t_jmps[i].used) {
      t_jmps[i].used = 1;
      t_jmps[i].guest = guest_buffer;
      arc_jmp_save(&t_jmps[i], c);
      return &t_jmps[i].host;
    }
  i = t_jmp_next;
  t_jmp_next = (t_jmp_next + 1) % ARC_JMP_SLOTS;
  t_jmps[i].guest = guest_buffer;
  arc_jmp_save(&t_jmps[i], c);
  return &t_jmps[i].host;
}

void arc_longjmp(Arm64Ctx* c, uint64_t guest_buffer, int value) {
  int i;
  for (i = 0; i < ARC_JMP_SLOTS; ++i)
    if (t_jmps[i].used && t_jmps[i].guest == guest_buffer) {
      arc_jmp_restore(&t_jmps[i], c);
      longjmp(t_jmps[i].host, value ? value : 1);
    }
  // Nothing armed this on this thread. Saying so beats jumping somewhere
  // plausible: a longjmp to the wrong frame is a crash with no explanation
  // attached to it.
  {
    char msg[96];
    snprintf(msg, sizeof(msg),
             "longjmp(%d) to a buffer no setjmp on this thread armed", value);
    arc_trap(NULL, msg);
  }
}

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

typedef struct {
  uint64_t address;
  const char* name;
  ArcCtxFn fn;
} CtxNative;

// Large enough for a whole JNI table -- 233 environment entries plus the
// invocation interface -- with room for the variadic handlers beside it. It
// was 64, which is smaller than the JNI table alone, so every slot past the
// sixty-fourth was dropped. The guest then branched to a real stub address the
// dispatcher had no record of, and the report said the branch went nowhere
// rather than that the table was full.
#define ARC_MAX_CTX_NATIVES 512
static CtxNative g_ctx_natives[ARC_MAX_CTX_NATIVES];
static size_t g_ctx_native_count;

// Overflowing either table is a configuration mistake, and one that produces a
// symptom pointing anywhere but here. Say so, once, rather than dropping the
// registration in silence.
static void arc_full(const char* which, const char* name) {
  static int said[2];
  const int i = which[0] == 'c' ? 0 : 1;
  if (said[i]) return;
  said[i] = 1;
  fprintf(stderr,
          "arc: the %s table is full; %s and everything after it is "
          "unregistered, and calls to them will look like branches to "
          "nowhere\n",
          which, name ? name : "?");
}

void arc_register_ctx_native(uint64_t address, const char* name, ArcCtxFn fn) {
  if (!address) return;
  if (g_ctx_native_count >= ARC_MAX_CTX_NATIVES) {
    arc_full("context native", name);
    return;
  }
  for (size_t i = 0; i < g_ctx_native_count; ++i)
    if (g_ctx_natives[i].address == address) return;
  g_ctx_natives[g_ctx_native_count].address = address;
  g_ctx_natives[g_ctx_native_count].name = name;
  g_ctx_natives[g_ctx_native_count].fn = fn;
  ++g_ctx_native_count;
}

void arc_register_native(uint64_t address, const char* name) {
  if (!address) return;
  if (g_native_count >= ARC_MAX_NATIVES) {
    arc_full("native", name);
    return;
  }
  for (size_t i = 0; i < g_native_count; ++i)
    if (g_natives[i].address == address) return;
  g_natives[g_native_count].address = address;
  g_natives[g_native_count].name = name;
  ++g_native_count;
}

// Twelve integer arguments in, one integer result out: eight from the
// registers AArch64 passes them in, and four more read from the guest stack,
// where that convention puts the rest.
//
// Eight was not enough, and the way it failed is worth keeping. glTexImage2D
// takes nine -- the ninth being the pixel data -- so the texture was uploaded
// from whatever the driver found in that argument slot. Nothing reported a
// missing argument; the call simply read an address nobody had passed.
//
// Handing a function more arguments than it declares is harmless here: the
// caller sets them up and the callee ignores them. So one thunk serves every
// arity up to twelve rather than needing one per signature.
//
// It still does NOT carry floating-point arguments, which live in v0-v7 and
// would need per-signature thunks to place correctly. Generate those from the
// import list when a title actually needs one.
typedef uint64_t (*ArcNative12)(uint64_t, uint64_t, uint64_t, uint64_t,
                                uint64_t, uint64_t, uint64_t, uint64_t,
                                uint64_t, uint64_t, uint64_t, uint64_t);

#define ARC_TRACE 64
static ARC_THREAD_LOCAL const char* t_trace[ARC_TRACE];
static ARC_THREAD_LOCAL size_t t_trace_next;
static ARC_THREAD_LOCAL size_t t_trace_seen;

void arc_trace_note(const char* what) {
  t_trace[t_trace_next] = what;
  t_trace_next = (t_trace_next + 1) % ARC_TRACE;
  ++t_trace_seen;
}

size_t arc_trace_count(void) {
  return t_trace_seen < ARC_TRACE ? t_trace_seen : ARC_TRACE;
}

const char* arc_trace_at(size_t back) {
  if (back >= arc_trace_count()) return 0;
  size_t i = (t_trace_next + ARC_TRACE - 1 - back) % ARC_TRACE;
  return t_trace[i];
}

void arc_trace_clear(void) {
  t_trace_next = 0;
  t_trace_seen = 0;
}

// Global rather than per-thread. A per-thread ring can only be read from the
// thread that filled it, which forces the reporting to happen inside the guest
// call itself -- exactly where it is least safe to do anything. Interleaving
// between threads costs some precision in the trail; being able to read it
// after the fact is worth more.
#define ARC_FRAME_RING 256
static uint64_t t_frames[ARC_FRAME_RING];
static size_t t_frame_next;
static size_t t_frame_seen;

/* Which thread a trace line came from. Both traces below are written by
   every guest thread at once, and interleaved they answer nothing: the
   question is always what one thread did in order, and a title does its
   networking on a worker while the renderer fills the log. A small number
   rather than the OS id because it has to be readable in a grep. */
static ARC_THREAD_LOCAL unsigned t_trace_id;
static unsigned g_trace_ids;

unsigned arc_trace_thread(void) {
  if (!t_trace_id) t_trace_id = ++g_trace_ids;
  return t_trace_id;
}

/* ARC_TRACE_GUEST prints every guest function entered, which for a title
   that has booted is millions of lines a second -- a firehose that costs far
   more than the thing it is watching, and buries the one call the question is
   about. ARC_TRACE_FN names that call instead: a comma-separated list of
   packed values in hex, and only those are printed. Same trace, with a
   filter, so a question about one function costs one function's worth of
   output. */
static int arc_traced_fn(uint64_t packed) {
  static const char* list;
  static int looked;
  const char* p;
  if (!looked) {
    looked = 1;
    list = getenv("ARC_TRACE_FN");
  }
  if (!list) return 1;
  for (p = list; *p;) {
    char* end;
    unsigned long long v = strtoull(p, &end, 16);
    if (end != p && v == packed) return 1;
    p = (end != p) ? end : p + 1;
    while (*p && *p != ',') ++p;
    while (*p == ',') ++p;
  }
  return 0;
}

#if defined(ARC_FRAMES)
void arc_frame_note(uint64_t packed) {
  /* The ring holds sixteen frames, which says where a fault happened and
     nothing about how a call that returned cleanly spent its time. A whole
     trace answers the other question: which branch a state machine took. */
  static int trace = -1;
  if (trace < 0)
    trace = getenv("ARC_TRACE_GUEST") != NULL || getenv("ARC_TRACE_FN") != NULL;
  /* errno is saved across this: the trace fires on every guest function
     entry, including the one between a call that set errno and the guest
     reading it, and fprintf may set errno itself. Without this a traced
     run is not a run of the same program -- which is the one thing a
     diagnostic must never be. */
  if (trace && arc_traced_fn(packed)) {
    const int saved = errno;
    fprintf(stderr, "[fn] t%u %llx\n", arc_trace_thread(),
            (unsigned long long)packed);
    errno = saved;
  }
  arc_census_note(packed);
  t_frames[t_frame_next] = packed;
  t_frame_next = (t_frame_next + 1) % ARC_FRAME_RING;
  ++t_frame_seen;
}
#endif

/* How often each guest function runs.
 *
 * The ring says which functions ran most recently; it cannot say which ran
 * ten thousand times. That is the question when a layer draws far more
 * sprites than it should: the loop responsible is whichever function runs
 * once per sprite, and nothing else in this kit counts. ARC_FN_CENSUS turns
 * it on; arc_census_report prints the busiest and starts again.
 *
 * ponytail: a fixed open-addressed table with no growth and no eviction --
 * it counts a few thousand distinct functions and stops learning new ones
 * after that, which is enough to find a hot loop. Make it grow if a run ever
 * needs more than the report says it saw. */
#define ARC_CENSUS_SLOTS 8192
static uint64_t g_census_key[ARC_CENSUS_SLOTS];
static uint64_t g_census_hits[ARC_CENSUS_SLOTS];
static int g_census_on = -1;
static uint64_t g_census_lost;

/* Where to start counting from.
 *
 * A frame number is the wrong handle on work that happens once. The town's
 * sprites are built during loading, and a tally that starts when the process
 * does buries twenty thousand one-time calls under a million steady-state
 * ones. ARC_FN_CENSUS_FROM=<image offset> clears the tally the first time
 * that guest function runs, so the next report covers the build and not the
 * history before it. */
static uint64_t g_census_from;
static int g_census_started;
static int g_census_pending;

/* True once the marker has run and the tally has not been reported yet, so
   the caller can report at the first frame boundary after it -- which is the
   work the marker introduces, and nothing after. */
int arc_census_pending(void) { return g_census_pending; }

static void arc_census_clear(void) {
  size_t i;
  for (i = 0; i < ARC_CENSUS_SLOTS; ++i) {
    g_census_key[i] = 0;
    g_census_hits[i] = 0;
  }
  g_census_lost = 0;
}

void arc_census_note(uint64_t packed) {
  size_t i;
  if (g_census_on < 0) {
    const char* from = getenv("ARC_FN_CENSUS_FROM");
    g_census_on = getenv("ARC_FN_CENSUS") != NULL || from != NULL;
    if (from) g_census_from = strtoull(from, NULL, 16);
  }
  if (!g_census_on) return;
  if (g_census_from && !g_census_started && packed == g_census_from) {
    g_census_started = 1;
    g_census_pending = 1;
    arc_census_clear();
    fprintf(stderr, "[fncensus] counting from %#llx\n",
            (unsigned long long)packed);
  }
  i = (size_t)((packed * 0x9E3779B97F4A7C15ull) >> 51) % ARC_CENSUS_SLOTS;
  for (;;) {
    if (g_census_key[i] == packed) { ++g_census_hits[i]; return; }
    if (g_census_key[i] == 0) {
      g_census_key[i] = packed;
      g_census_hits[i] = 1;
      return;
    }
    i = (i + 1) % ARC_CENSUS_SLOTS;
    if (g_census_key[i] == 0 && g_census_key[(i + 1) % ARC_CENSUS_SLOTS] == 0) {
      /* Wrapped far enough to call it full. */
      ++g_census_lost;
      return;
    }
  }
}

void arc_census_report(int top) {
  size_t i, k;
  if (g_census_on <= 0) return;
  g_census_pending = 0;
  fprintf(stderr, "[fncensus] busiest guest functions this frame:\n");
  for (k = 0; k < (size_t)top; ++k) {
    size_t best = ARC_CENSUS_SLOTS;
    uint64_t most = 0;
    for (i = 0; i < ARC_CENSUS_SLOTS; ++i)
      if (g_census_hits[i] > most) { most = g_census_hits[i]; best = i; }
    if (best == ARC_CENSUS_SLOTS) break;
    fprintf(stderr, "[fncensus]   %#llx  %llu\n",
            (unsigned long long)g_census_key[best],
            (unsigned long long)g_census_hits[best]);
    g_census_hits[best] = 0;
  }
  arc_census_clear();
}

size_t arc_frame_count(void) {
  return t_frame_seen < ARC_FRAME_RING ? t_frame_seen : ARC_FRAME_RING;
}

/* The ring saturates, so its count stops telling a busy frame from an idle
   one once it fills. This is how many calls actually happened. */
size_t arc_frame_seen(void) { return t_frame_seen; }

uint64_t arc_frame_at(size_t back) {
  if (back >= arc_frame_count()) return 0;
  return t_frames[(t_frame_next + ARC_FRAME_RING - 1 - back) % ARC_FRAME_RING];
}

void arc_frame_clear(void) {
  t_frame_next = 0;
  t_frame_seen = 0;
}

static ArcDispatchFn g_dispatch;

void arc_set_dispatch(ArcDispatchFn fn) { g_dispatch = fn; }

static ArcExplainFn g_explain;

void arc_set_explain(ArcExplainFn fn) { g_explain = fn; }

/* One guest function, watched: its arguments going in and its result coming
   out, with the memory each pointer argument names.
 *
 * A statically linked library still reaches its own exported functions through
 * the PLT, and a lifted PLT stub is an indirect branch -- so every such call
 * arrives here, with the context in hand. That makes this the one place a
 * specific guest function can be observed without regenerating the program:
 * ARC_WATCH names it by address, and the dump is what a printf inside it would
 * have printed if the source were ours to edit. Answering "is this routine
 * computing the right thing" is otherwise a rebuild of 430 MB of C away.
 */
/* Named by image offset rather than by mapped address: the address moves
   every run, and the offset is what a disassembler and every other trace in
   this kit already speak. */
static uint64_t g_watch_base;

void arc_set_image_base(uint64_t base) { g_watch_base = base; }

static int arc_watched(uint64_t target) {
  static const char* list;
  static int looked;
  const char* p;
  if (!looked) {
    looked = 1;
    list = getenv("ARC_WATCH");
  }
  if (!list || target < g_watch_base) return 0;
  target -= g_watch_base;
  for (p = list; *p;) {
    char* end;
    unsigned long long v = strtoull(p, &end, 16);
    if (end != p && v == target) return 1;
    p = (end != p) ? end : p + 1;
    while (*p && *p != ',') ++p;
    while (*p == ',') ++p;
  }
  return 0;
}

static void arc_watch_bytes(const char* label, uint64_t p, int n) {
  int i;
#if defined(_WIN32)
  MEMORY_BASIC_INFORMATION mbi;
  if (!p || !VirtualQuery((void*)(uintptr_t)p, &mbi, sizeof mbi)) return;
  if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_GUARD)) return;
  if (p + (uint64_t)n >
      (uint64_t)(uintptr_t)mbi.BaseAddress + (uint64_t)mbi.RegionSize)
    return;
#else
  if (!p) return;
#endif
  fprintf(stderr, "  %s %#llx:", label, (unsigned long long)p);
  for (i = 0; i < n; ++i)
    fprintf(stderr, " %02x", ((const unsigned char*)(uintptr_t)p)[i]);
  fprintf(stderr, "  |");
  for (i = 0; i < n; ++i) {
    unsigned char b = ((const unsigned char*)(uintptr_t)p)[i];
    fputc(b >= 0x20 && b < 0x7f ? b : '.', stderr);
  }
  fprintf(stderr, "|\n");
}

/* x8 is dumped on the way out as well as in, from the value it had on entry.
   A C++ function returning anything larger than two words returns it through
   a buffer the caller passes in x8, so for a great deal of real code the
   result is not in x0 at all -- and x8 itself is caller-saved, so reading it
   afterwards reads whatever the callee left there. */
static void arc_watch_report(const char* when, const Arm64Ctx* c,
                             uint64_t target, uint64_t sret) {
  int i;
  fprintf(stderr, "[watch] %s %#llx t%u  ", when, (unsigned long long)target,
          arc_trace_thread());
  for (i = 0; i < 6; ++i)
    fprintf(stderr, "x%d=%llx ", i, (unsigned long long)c->x[i]);
  fprintf(stderr, "x8=%llx\n", (unsigned long long)sret);
  for (i = 0; i < 4; ++i) arc_watch_bytes("arg", c->x[i], 64);
  arc_watch_bytes("x8 ", sret, 32);
}

void arc_dispatch(Arm64Ctx* c, uint64_t target) {
  const int watch = arc_watched(target);
  const uint64_t sret = c->x[8];
  if (watch) arc_watch_report("call", c, target, sret);
  if (g_dispatch)
    g_dispatch(c, target);
  else
    arc_dispatch_miss(c, target);
  if (watch) arc_watch_report("back", c, target, sret);
}

// Big enough for an unwinder or a C++ initialiser, which is what these
// callbacks usually are, and small enough to allocate per call.
#define ARC_CALLBACK_STACK (4u << 20)
#define ARC_CALLBACK_HEADROOM 4096

// One stack per thread, kept and reused, because a comparator is called once
// per comparison and allocating megabytes each time would cost more than the
// sort. The busy flag is what keeps that safe: a callback is entitled to end
// up here again -- an unwinder's visitor can throw, an initialiser can sort --
// and the nested call takes a stack of its own rather than writing over the
// frames of the call it is nested inside.
static ARC_THREAD_LOCAL void* t_callback_stack;
static ARC_THREAD_LOCAL int t_callback_busy;

uint64_t arc_call_guest(uint64_t fn, const uint64_t* args, int n) {
  Arm64Ctx ctx;
  int i, reused = 0;
  void* stack;
  uint64_t result;

  if (!t_callback_busy) {
    if (!t_callback_stack) t_callback_stack = malloc(ARC_CALLBACK_STACK);
    stack = t_callback_stack;
    reused = 1;
  } else {
    stack = malloc(ARC_CALLBACK_STACK);
  }
  if (!stack) return 0;
  if (reused) t_callback_busy = 1;

  memset(&ctx, 0, sizeof(ctx));
  ctx.sp = (((uint64_t)(uintptr_t)stack + ARC_CALLBACK_STACK -
             ARC_CALLBACK_HEADROOM)) & ~(uint64_t)15;
  for (i = 0; i < n && i < 8; ++i) ctx.x[i] = args[i];
  arc_dispatch(&ctx, fn);
  result = ctx.x[0];

  if (reused)
    t_callback_busy = 0;
  else
    free(stack);
  return result;
}

const char* arc_native_near(uint64_t address, uint64_t* delta) {
  const char* best = NULL;
  uint64_t at = 0;
  size_t i;
  for (i = 0; i < g_native_count; ++i)
    if (g_natives[i].address <= address && g_natives[i].address >= at) {
      at = g_natives[i].address;
      best = g_natives[i].name;
    }
  for (i = 0; i < g_ctx_native_count; ++i)
    if (g_ctx_natives[i].address <= address && g_ctx_natives[i].address >= at) {
      at = g_ctx_natives[i].address;
      best = g_ctx_natives[i].name;
    }
  if (best && delta) *delta = address - at;
  return best;
}

void arc_dispatch_miss(Arm64Ctx* c, uint64_t target) {
  // Context-taking natives first: they are a strict superset of what the
  // thunk can express, so a name registered both ways wants this one.
  for (size_t i = 0; i < g_ctx_native_count; ++i) {
    if (g_ctx_natives[i].address != target) continue;
    arc_trace_note(g_ctx_natives[i].name);
    g_ctx_natives[i].fn(c);
    return;
  }
  for (size_t i = 0; i < g_native_count; ++i) {
    if (g_natives[i].address != target) continue;
    arc_trace_note(g_natives[i].name);
    /* Optional argument trace. A name in the trail says the guest called
       memmove; the arguments say whether it asked for a sane length. Set
       ARC_TRACE_CALLS to a substring to see only the calls that matter. */
    {
      static const char* filter;
      static int checked;
      if (!checked) { filter = getenv("ARC_TRACE_CALLS"); checked = 1; }
      /* "*" matches everything: a shell cannot easily pass an empty value.
         Otherwise the filter is a comma-separated list of substrings, because
         a sequence is what answers most questions -- which call a socket got
         between connect and being closed is not visible one name at a time. */
      int matched = 0;
      if (filter && (!*filter || filter[0] == '*')) {
        matched = 1;
      } else if (filter) {
        const char* p = filter;
        while (*p && !matched) {
          const char* comma = strchr(p, ',');
          const size_t n = comma ? (size_t)(comma - p) : strlen(p);
          if (n) {
            char term[64];
            const size_t k = n < sizeof term - 1 ? n : sizeof term - 1;
            memcpy(term, p, k);
            term[k] = 0;
            if (strstr(g_natives[i].name, term)) matched = 1;
          }
          p = comma ? comma + 1 : p + n;
        }
      }
      if (matched)
        {
          const int saved_errno = errno;
          /* A pointer says nothing about which file was wanted. For the
             calls whose first argument is a path by contract, the name
             is the whole point of the trace. */
          static const char* const kPathFirst[] = {
              "fopen", "fopen64", "open", "open64", "stat", "stat64",
              "lstat", "access", "opendir", "unlink", "mkdir",
              /* Not a path, but the same argument: a name, and the whole
                 content of the event. Which host a title resolves is what
                 says where it thinks its server is. */
              "getaddrinfo", "gethostbyname", 0};
          int path_first = 0;
          for (const char* const* q = kPathFirst; *q; ++q)
            if (strcmp(g_natives[i].name, *q) == 0) { path_first = 1; break; }
          if (path_first && c->x[0])
            fprintf(stderr, "[call] t%u %-12s \"%.160s\"\n", arc_trace_thread(),
                    g_natives[i].name, (const char*)(uintptr_t)c->x[0]);
          else
            fprintf(stderr, "[call] t%u %-12s x0=%#llx x1=%#llx x2=%#llx\n",
                    arc_trace_thread(),
                    g_natives[i].name, (unsigned long long)c->x[0],
                    (unsigned long long)c->x[1],
                    (unsigned long long)c->x[2]);
          errno = saved_errno;
        }
    }
    ArcNative12 fn = (ArcNative12)(uintptr_t)target;
    /* Arguments past the eighth sit at the stack pointer, in order. A callee
       taking fewer simply never looks at them. */
    const uint64_t* rest = (const uint64_t*)(uintptr_t)c->sp;
    uint64_t r = fn(c->x[0], c->x[1], c->x[2], c->x[3],
                    c->x[4], c->x[5], c->x[6], c->x[7],
                    rest[0], rest[1], rest[2], rest[3]);
    c->x[0] = r;
    return;
  }
  {
    char msg[256];
    const char* what = g_explain ? g_explain(target) : NULL;
    snprintf(msg, sizeof(msg),
             "indirect branch to %#llx, neither lifted nor a known import%s%s",
             (unsigned long long)target, what ? " -- " : "",
             what ? what : "");
    arc_trap(c, msg);
  }
}

// The fallback for a host with no lifted program is above, in arc_dispatch
// itself: with nothing installed it goes straight to arc_dispatch_miss, which
// resolves the branch against the registered natives or traps loudly. That is
// the right behaviour for triage, loading, or bringing the shim up on an arm64
// machine, and it needs no compile-time flag to select it.
