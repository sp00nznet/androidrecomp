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

// The JavaVM, which is what `JNI_OnLoad` is handed. A library caches it and
// reaches every other thread's environment through it later, so this is the
// one pointer a host must give the guest before anything else asks.
uint64_t arc_jni_vm(void);

// The object an entry point is invoked on. Its fields are answered by the
// accessors rather than read out of it, so this only has to be a valid handle.
uint64_t arc_jni_object(void);

// A jstring holding this text, for an entry point whose Java declaration takes
// a String -- a path, a locale, a launch argument.
uint64_t arc_jni_string(const char* text);

// Registers every slot with the native bridge, so an indirect branch into the
// table is recognised as a call out to the host rather than a missing function.
void arc_jni_register(void);

// How many slots were called, and a report of which.
size_t arc_jni_call_count(void);
void arc_jni_report(void);

// Whether an address is one of the stand-in handles, so a fault on one can be
// reported as such rather than as an unattributable number.
int arc_jni_owns(uint64_t address);

#ifdef __cplusplus
}
#endif
