# The JNI bridge

On Android the Java side owns the window, the GL context and the touch handler,
and calls into the engine through a handful of JNI methods. The engine calls
*back* through a `JNIEnv` for everything it needs from the platform: the device
description, the writable path, the package name, the asset manager.

Replacing the Java shell means answering both directions.

## Discovering a title's host contract

The contract is the set of JNI entry points the Java shell called. It differs per
game, so it is passed in rather than compiled in.

```sh
./build/arc_host libengine.so                    # every Java_* export
python tools/dex_contract.py game.apk --class com.example.Bridge
```

`arc_host` gives you the *names*; the dex gives you the *signatures*, which the
exports alone do not. That distinction matters more than it looks: an entry
point given a zero width and height sets up a zero-sized surface and fails
somewhere much later, which reads as a porting bug rather than as a missing
argument.

**Do not assume the bridge class is the whole contract.** Tapped Out's
`BGCoreJNIBridge` has fourteen methods that look like a complete host contract —
lifecycle, GL surface, resize, render tick, pointer and key input — and they are
not complete. A fifteenth entry point on a *different* class is the game's boot:
it builds the application and installs its first state. Without it the render
tick returned after six guest calls, having found no state to update, and drew
an empty frame forever. Everything that is not obviously a platform service is
worth calling once to see what it does.

Order matters as much as membership. Follow Android's: the GL surface exists
before the game boots, because the game's boot allocates out of the renderer's
heap.

## A JNIEnv with nothing behind it

A JNI entry point takes a `JNIEnv*` and dereferences it immediately, because in
JNI an environment *is* a pointer to a pointer to a table of function pointers.
That is why the first call to an entry point faults reading address zero.

`runtime/jni_env.cpp` supplies the shape without the substance: **256 distinct
stub slots**, each registered as a context native so an indirect branch into the
table is recognised as a call out to the host rather than a branch into nothing.
Every slot records that it was called.

Writing named implementations for all 233 real JNI functions before knowing
which are needed would be a great deal of speculative work. Running it answers
the question instead, and `arc_jni_report()` prints exactly which slots a title
reached and how often.

## Answering by name, and saying what you could not answer

The slots that matter are answered from small tables keyed on the *name* the
engine asked by:

- **Fields** (`GetFieldID` and the typed getters). A table of name → typed value:
  screen width and height, density, locale, SDK level, package name, paths.
- **Methods returning a string** (`CallObjectMethod` and friends). A table of
  name → text. `getBytes` and `toString` are special: they are called *on* a
  string, so the answer is that object's own text rather than a table entry.
- **Paths** are not in either table, because they have to name directories that
  exist on this machine. They come from the asset root the host was given.

Two design rules run through it:

**A zero is a plausible value, not a visible failure.** An unanswered int field
reads as 0, an unanswered string as empty — and the engine carries that away and
comes apart somewhere else entirely. So every unanswered lookup is *recorded
with its signature*, and reported at the end of the run. A missing field has to
be added back as some particular type, and the caller already said which;
guessing between an int, a boolean and a string is a wrong answer two times in
three.

**An empty string is the dangerous one.** A caller that takes the length and
subtracts one gets -1, hands that to `memcpy`, and runs off the end of the arena
a long way from the call that caused it. An empty bundle path becomes the
filesystem root and every lookup beneath it fails.

The worst instance of it was on the way *in* rather than out. `NewStringUTF` is
how the guest's own bytes become a `jstring`, and it is the only place text
ever enters the Java side. Without a case of its own it fell to the default for
a slot that returns a handle — a fresh, empty block — so every string the
engine built for Java arrived blank. Nothing failed: an empty string is a legal
string. It surfaced as a preference lookup being asked for the key `""`, which
is how the title asks where its server lives, and so the title never contacted
a server at all.

**A method that does something must do it, not claim it.** `mkdir` is the
example: answering `true` without creating the directory is worse than
answering `false`, because `false` gets reported. The engine makes its content
directory this way and then writes downloads into it, so a bare `true` left
every one of those opens failing — and a download loop repeating forever with
the server returning 200 each time.

## Handles

A `jobject` is an opaque token the engine holds and hands back. Here it is a
block from a small arena. A `jstring` *is* its own text: every path that reads
one — `GetStringUTFChars`, `getBytes`, `toString` — hands the handle straight
back, so a string handle carries its characters and anything that measures it
gets the right answer.

`arc_jni_owns()` says whether an address is one of these, so a fault on one is
reported as such rather than as an unattributable number.

## The invocation interface

`JNI_OnLoad` is what a library is handed when Java loads it, and it is where a
library caches the `JavaVM` it will reach every later thread's environment
through. **Call it for every mapped image, not just the engine, and call it
before the engine's constructors run.** That is what Android does: a dependency
is loaded by name first and gets its own call.

Skipping it for a dependency leaves a null behind that surfaces much later, in a
constructor, three images deep — Tapped Out lost three static constructors to
exactly that, faulting inside libNimble's `findClass` on a `JavaVM` global its
own `JNI_OnLoad` would have filled in.

`AttachCurrentThread` and `GetEnv` both hand back the one environment there is:
nothing in it is per-thread, so every thread can share it.

## Input

`--loop` in `arc_boot` forwards SDL mouse events to the title's pointer entry
points — press, drag, release — which is the other half of what the Java shell
did. A mouse is a single finger that is only ever down or up, so the pointer id
is always 0, and a move with no button held is not reported at all: Android has
no hover, and feeding one in makes a tap out of every pass over the window.
