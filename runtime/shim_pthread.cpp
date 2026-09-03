// POSIX threads, semaphores and thread-local keys for the engine.
//
// The engine allocates `pthread_mutex_t`, `pthread_cond_t` and friends inline
// inside its own structures, sized by Bionic's headers at the time it was
// compiled. We cannot change those sizes, and guessing them wrong is silent
// memory corruption rather than a crash.
//
// So we never depend on them. Every pthread call routes through this file, so
// the guest never inspects the bytes itself -- which means the storage is
// opaque and we only have to *fit inside* it, not match its layout. Each
// object holds a single 32-bit id naming an entry in a registry here. The
// smallest of Bionic's types is `pthread_once_t` at four bytes, so a `uint32_t`
// fits every one of them with room to spare, on every host, with no NDK
// headers required to prove it.
//
// Zero means "not created yet". That is not an accident of ours: Bionic's
// PTHREAD_MUTEX_INITIALIZER is static zeroes, so a statically initialised mutex
// legitimately arrives here having never been through pthread_mutex_init.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <vector>

#include "shim.h"

namespace arc {
namespace {

// ponytail: one lock over every registry. Each mutex_lock briefly serialises
// here, which is a real throughput ceiling for a game. Shard by id, or add a
// lock-free fast path for the already-created case, if profiling says so.
std::mutex g_registry;
uint32_t g_next_id = 1;

template <typename T>
struct Registry {
  // std::map, not unordered_map: references to elements stay valid across
  // inserts, so a holder can keep using its object while another thread
  // creates one.
  std::map<uint32_t, std::unique_ptr<T>> items;

  T* Obtain(uint32_t* slot) {
    std::lock_guard<std::mutex> g(g_registry);
    if (*slot == 0) {
      *slot = g_next_id++;
      items[*slot] = std::make_unique<T>();
    }
    auto it = items.find(*slot);
    return it == items.end() ? nullptr : it->second.get();
  }

  T* Find(uint32_t id) {
    std::lock_guard<std::mutex> g(g_registry);
    auto it = items.find(id);
    return it == items.end() ? nullptr : it->second.get();
  }

  void Release(uint32_t* slot) {
    std::lock_guard<std::mutex> g(g_registry);
    items.erase(*slot);
    *slot = 0;
  }
};

// --- mutexes ---------------------------------------------------------------
// ponytail: every mutex is recursive, whatever type the guest asked for.
// Recursive is strictly more permissive than normal -- code that is correct
// under PTHREAD_MUTEX_NORMAL is still correct here; it just no longer
// self-deadlocks. Split by type only if we ever want to reproduce a deadlock.
Registry<std::recursive_mutex> g_mutexes;
Registry<std::condition_variable_any> g_conds;
Registry<std::shared_mutex> g_rwlocks;

struct Semaphore {
  std::mutex m;
  std::condition_variable cv;
  unsigned count = 0;
};
Registry<Semaphore> g_semaphores;

struct Thread {
  std::thread thread;
  void* result = nullptr;
};
Registry<Thread> g_threads;

struct Attr {
  int detach_state = 0;
  size_t stack_size = 0;
};
Registry<Attr> g_attrs;

// --- thread-local keys -----------------------------------------------------
struct KeyTable {
  std::vector<void*> values;
};
thread_local KeyTable t_keys;
std::atomic<uint32_t> g_next_key{1};

// Which rwlocks this thread holds for writing, so unlock knows which of
// shared_mutex's two unlock calls to make. pthread has one unlock for both.
thread_local std::vector<uint32_t> t_write_held;

// Bionic's timespec on LP64.
struct GuestTimespec {
  int64_t tv_sec;
  int64_t tv_nsec;
};

// The id the guest holds for the calling thread, so pthread_self() and
// pthread_kill() have something to name.
thread_local uint32_t t_self_id = 0;

// --- entry points ----------------------------------------------------------

int MutexInit(uint32_t* m, const void*) {
  *m = 0;
  g_mutexes.Obtain(m);
  return 0;
}
int MutexDestroy(uint32_t* m) {
  g_mutexes.Release(m);
  return 0;
}
int MutexLock(uint32_t* m) {
  if (auto* p = g_mutexes.Obtain(m)) p->lock();
  return 0;
}
int MutexUnlock(uint32_t* m) {
  if (auto* p = g_mutexes.Obtain(m)) p->unlock();
  return 0;
}
int MutexTrylock(uint32_t* m) {
  auto* p = g_mutexes.Obtain(m);
  return (p && p->try_lock()) ? 0 : 16 /* EBUSY */;
}
int MutexattrInit(uint32_t* a) {
  *a = 0;
  return 0;
}
int MutexattrDestroy(uint32_t*) { return 0; }
int MutexattrSettype(uint32_t*, int) { return 0; }  // see the note above

int CondInit(uint32_t* c, const void*) {
  *c = 0;
  g_conds.Obtain(c);
  return 0;
}
int CondDestroy(uint32_t* c) {
  g_conds.Release(c);
  return 0;
}
int CondSignal(uint32_t* c) {
  if (auto* p = g_conds.Obtain(c)) p->notify_one();
  return 0;
}
int CondBroadcast(uint32_t* c) {
  if (auto* p = g_conds.Obtain(c)) p->notify_all();
  return 0;
}
int CondWait(uint32_t* c, uint32_t* m) {
  auto* cv = g_conds.Obtain(c);
  auto* mu = g_mutexes.Obtain(m);
  if (!cv || !mu) return 22 /* EINVAL */;
  std::unique_lock<std::recursive_mutex> lk(*mu, std::adopt_lock);
  cv->wait(lk);
  lk.release();  // the guest still owns the lock on return
  return 0;
}
int CondTimedwait(uint32_t* c, uint32_t* m, const GuestTimespec* abstime) {
  auto* cv = g_conds.Obtain(c);
  auto* mu = g_mutexes.Obtain(m);
  if (!cv || !mu) return 22;
  std::unique_lock<std::recursive_mutex> lk(*mu, std::adopt_lock);
  // pthread's timeout is absolute against CLOCK_REALTIME. system_clock does
  // not tick in nanoseconds on every host, so the deadline is cast to whatever
  // resolution it does use.
  const auto since_epoch = std::chrono::seconds(abstime->tv_sec) +
                           std::chrono::nanoseconds(abstime->tv_nsec);
  const auto deadline = std::chrono::system_clock::time_point(
      std::chrono::duration_cast<std::chrono::system_clock::duration>(
          since_epoch));
  std::cv_status st = cv->wait_until(lk, deadline);
  lk.release();
  return st == std::cv_status::timeout ? 110 /* ETIMEDOUT */ : 0;
}

int RwlockInit(uint32_t* l, const void*) {
  *l = 0;
  g_rwlocks.Obtain(l);
  return 0;
}
int RwlockDestroy(uint32_t* l) {
  g_rwlocks.Release(l);
  return 0;
}
int RwlockRdlock(uint32_t* l) {
  if (auto* p = g_rwlocks.Obtain(l)) p->lock_shared();
  return 0;
}
int RwlockWrlock(uint32_t* l) {
  if (auto* p = g_rwlocks.Obtain(l)) {
    p->lock();
    t_write_held.push_back(*l);
  }
  return 0;
}
int RwlockUnlock(uint32_t* l) {
  auto* p = g_rwlocks.Obtain(l);
  if (!p) return 22;
  auto it = std::find(t_write_held.begin(), t_write_held.end(), *l);
  if (it != t_write_held.end()) {
    t_write_held.erase(it);
    p->unlock();
  } else {
    p->unlock_shared();
  }
  return 0;
}

// pthread_once_t is a bare int, so it holds the state machine directly rather
// than a registry id: 0 = untouched, 1 = running, 2 = done.
int Once(uint32_t* control, void (*fn)(void)) {
  uint32_t expected = 0;
  auto* state = reinterpret_cast<std::atomic<uint32_t>*>(control);
  if (state->compare_exchange_strong(expected, 1)) {
    fn();
    state->store(2);
    return 0;
  }
  while (state->load() != 2) std::this_thread::yield();
  return 0;
}

int KeyCreate(uint32_t* key, void (*)(void*)) {
  *key = g_next_key.fetch_add(1);
  return 0;
}
int KeyDelete(uint32_t) { return 0; }
void* Getspecific(uint32_t key) {
  return key < t_keys.values.size() ? t_keys.values[key] : nullptr;
}
int Setspecific(uint32_t key, void* value) {
  if (key >= t_keys.values.size()) t_keys.values.resize(key + 1, nullptr);
  t_keys.values[key] = value;
  return 0;
}

int Create(uint64_t* out, const void*, void* (*start)(void*), void* arg) {
  uint32_t id = 0;
  Thread* t = g_threads.Obtain(&id);
  if (!t) return 11 /* EAGAIN */;
  t->thread = std::thread([t, id, start, arg] {
    t_self_id = id;
    t->result = start(arg);
  });
  *out = id;
  return 0;
}
int Join(uint64_t id, void** result) {
  Thread* t = g_threads.Find(static_cast<uint32_t>(id));
  if (!t) return 3 /* ESRCH */;
  if (t->thread.joinable()) t->thread.join();
  if (result) *result = t->result;
  return 0;
}
int Detach(uint64_t id) {
  Thread* t = g_threads.Find(static_cast<uint32_t>(id));
  if (t && t->thread.joinable()) t->thread.detach();
  return 0;
}
uint64_t Self() { return t_self_id; }
int Equal(uint64_t a, uint64_t b) { return a == b; }
int Kill(uint64_t, int) { return 0; }
int Setname(uint64_t, const char*) { return 0; }
int Setschedparam(uint64_t, int, const void*) { return 0; }

// pthread_exit unwinds the calling thread. There is no portable way to do that
// from inside a std::thread body, and the engine only reaches it on paths it
// treats as terminal, so this is deliberately a hard stop rather than a
// silently wrong return.
[[noreturn]] void Exit(void*) {
  fprintf(stderr, "pthread_exit called -- not implemented\n");
  abort();
}

int AttrInit(uint32_t* a) {
  *a = 0;
  g_attrs.Obtain(a);
  return 0;
}
int AttrDestroy(uint32_t* a) {
  g_attrs.Release(a);
  return 0;
}
int AttrSetdetachstate(uint32_t* a, int state) {
  if (auto* p = g_attrs.Obtain(a)) p->detach_state = state;
  return 0;
}
int AttrSetstacksize(uint32_t* a, size_t size) {
  if (auto* p = g_attrs.Obtain(a)) p->stack_size = size;
  return 0;
}
int AttrSetschedparam(uint32_t*, const void*) { return 0; }
int AttrSetschedpolicy(uint32_t*, int) { return 0; }

int SemInit(uint32_t* s, int, unsigned value) {
  *s = 0;
  if (auto* p = g_semaphores.Obtain(s)) p->count = value;
  return 0;
}
int SemDestroy(uint32_t* s) {
  g_semaphores.Release(s);
  return 0;
}
int SemPost(uint32_t* s) {
  if (auto* p = g_semaphores.Obtain(s)) {
    std::lock_guard<std::mutex> g(p->m);
    ++p->count;
    p->cv.notify_one();
  }
  return 0;
}
int SemWait(uint32_t* s) {
  if (auto* p = g_semaphores.Obtain(s)) {
    std::unique_lock<std::mutex> lk(p->m);
    p->cv.wait(lk, [p] { return p->count > 0; });
    --p->count;
  }
  return 0;
}
int SemTrywait(uint32_t* s) {
  auto* p = g_semaphores.Obtain(s);
  if (!p) return 22;
  std::lock_guard<std::mutex> g(p->m);
  if (p->count == 0) return 11 /* EAGAIN */;
  --p->count;
  return 0;
}

int SchedYield() {
  std::this_thread::yield();
  return 0;
}
int SchedGetPriorityMin(int) { return 0; }

struct Entry {
  const char* name;
  void* fn;
};

#define E(sym, fn) {sym, reinterpret_cast<void*>(&fn)}
const Entry kTable[] = {
    E("pthread_mutex_init", MutexInit),
    E("pthread_mutex_destroy", MutexDestroy),
    E("pthread_mutex_lock", MutexLock),
    E("pthread_mutex_unlock", MutexUnlock),
    E("pthread_mutex_trylock", MutexTrylock),
    E("pthread_mutexattr_init", MutexattrInit),
    E("pthread_mutexattr_destroy", MutexattrDestroy),
    E("pthread_mutexattr_settype", MutexattrSettype),
    E("pthread_cond_init", CondInit),
    E("pthread_cond_destroy", CondDestroy),
    E("pthread_cond_signal", CondSignal),
    E("pthread_cond_broadcast", CondBroadcast),
    E("pthread_cond_wait", CondWait),
    E("pthread_cond_timedwait", CondTimedwait),
    E("pthread_rwlock_init", RwlockInit),
    E("pthread_rwlock_destroy", RwlockDestroy),
    E("pthread_rwlock_rdlock", RwlockRdlock),
    E("pthread_rwlock_wrlock", RwlockWrlock),
    E("pthread_rwlock_unlock", RwlockUnlock),
    E("pthread_once", Once),
    E("pthread_key_create", KeyCreate),
    E("pthread_key_delete", KeyDelete),
    E("pthread_getspecific", Getspecific),
    E("pthread_setspecific", Setspecific),
    E("pthread_create", Create),
    E("pthread_join", Join),
    E("pthread_detach", Detach),
    E("pthread_self", Self),
    E("pthread_equal", Equal),
    E("pthread_kill", Kill),
    E("pthread_exit", Exit),
    E("pthread_setname_np", Setname),
    E("pthread_setschedparam", Setschedparam),
    E("pthread_attr_init", AttrInit),
    E("pthread_attr_destroy", AttrDestroy),
    E("pthread_attr_setdetachstate", AttrSetdetachstate),
    E("pthread_attr_setstacksize", AttrSetstacksize),
    E("pthread_attr_setschedparam", AttrSetschedparam),
    E("pthread_attr_setschedpolicy", AttrSetschedpolicy),
    E("sem_init", SemInit),
    E("sem_destroy", SemDestroy),
    E("sem_post", SemPost),
    E("sem_wait", SemWait),
    E("sem_trywait", SemTrywait),
    E("sched_yield", SchedYield),
    E("sched_get_priority_min", SchedGetPriorityMin),
};
#undef E

}  // namespace

uint64_t ShimResolvePthread(const char* name) {
  for (const Entry& e : kTable)
    if (strcmp(e.name, name) == 0) return reinterpret_cast<uint64_t>(e.fn);
  return 0;
}

size_t ShimPthreadCount() { return sizeof(kTable) / sizeof(kTable[0]); }

}  // namespace arc
