// A JNIEnv the guest can call through, with nothing behind it.
//
// The engine was written against a JVM: `init` and its neighbours take a
// JNIEnv* and immediately dereference it, because in JNI an environment *is* a
// pointer to a table of function pointers. Passing null is why the first call
// to `init` faulted reading address zero.
//
// There is no JVM here and there will not be one, so every slot is a stub. What
// matters is that the shape is right -- a pointer to a pointer to a table of
// 256 callable addresses -- and that each stub is distinguishable, so a run
// reports *which* slots a title actually reaches. Writing 233 named
// implementations before knowing which half-dozen are needed would be a lot of
// speculative work; the log tells us instead.
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// A JNIEnv* for the guest, in guest terms: an address it can put in x0.
uint64_t arc_jni_env(void);

// Registers every slot with the native bridge, so an indirect branch into the
// table is recognised as a call out to the host rather than a missing function.
void arc_jni_register(void);

// How many slots were called, and a report of which.
size_t arc_jni_call_count(void);
void arc_jni_report(void);

#ifdef __cplusplus
}
#endif
