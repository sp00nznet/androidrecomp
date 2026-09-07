# Triaging a new title

Point `tools/apk_probe.py` at an APK before committing to a port. It reads the
APK (or an extracted directory), picks a native library, and reports the numbers
that decide whether a static recompile is weeks or years.

```sh
pip install capstone pyelftools
python tools/apk_probe.py game.apk --out triage.md
python tools/apk_probe.py extracted/ --abi arm64-v8a
```

Then `tools/arc_host` turns the remaining unknowns into a work list:

```sh
./build/arc_host path/to/libengine.so          # outstanding imports, by owner
./build/arc_host --contract contract.txt lib.so
```

With no `--contract` it lists every `Java_*` export, which is how a title's host
contract is discovered in the first place. `tools/dex_contract.py` reads the
other half of that contract out of the APK's dex — the *signatures*, which the
exports alone do not give you.

## Method

Point `apk_probe.py` at an APK. The numbers that decide whether a port is weeks
or years:

- **Functions recovered from `.eh_frame`.** Function-boundary recovery is the
  hardest problem in static recompilation, and NDK builds ship complete unwind
  tables — so it is usually free. Low coverage here is the main red flag.
- **Undefined symbol count.** This is the shim surface. A few hundred standard
  POSIX/GL symbols is routine; thousands of exotic ones is not.
- **Indirect branches.** C++ vtable dispatch, resolved against the recovered
  function starts.
- **TLS, exotic relocations, `svc` sites.** Small counts mean a small loader.

Then `arc_host` turns the remaining unknowns into a work list that shrinks.

Three rules earn their keep at the shim boundary:

**If the APK ships it, load it.** Any `DT_NEEDED` entry sitting next to the
engine is loaded as its own image and used to satisfy the engine's imports;
everything else is an Android system library and falls to the shim. This is what
answers `libc++_shared.so`'s NDK-mangled (`_ZNSt6__ndk1...`) symbols, which no
host STL can provide. The exception worth knowing: a shipped `libopenal.so`
resolves plenty but drags in `libOpenSLES` imports, because its audio backend is
Android's — link native openal-soft instead.

**Fit inside the guest's storage; do not match its layout.** An engine allocates
`pthread_mutex_t` inline in its own structures, sized by Bionic's headers when
it was compiled. Guessing those sizes wrong is silent corruption, not a crash.
We never guess: every pthread call routes through the shim, so the bytes are
opaque to the engine, and each object holds nothing but a 32-bit id naming a
registry entry. Bionic's smallest such type is `pthread_once_t` at four bytes,
so a `uint32_t` fits them all, with no NDK headers needed to prove it.

**A smaller host struct written into a larger guest allocation is safe; the
reverse is not.** Bionic's `struct tm` carries two fields more than the
Microsoft CRT's, so filling one from the host leaves the leading fields correct
and the tail untouched. It runs the other way too: Bionic's `struct stat` and
`struct dirent` share no layout with the host's, so those are filled field by
field at Bionic's offsets instead of letting the host write its own shape.

The corollary is that the best answer is often to need neither. `__sF` is the
array behind `stdin`/`stdout`/`stderr`, and the engine indexes it with its own
baked-in `sizeof(FILE)` — a stride we cannot know. So the shim reserves a region
and treats *any* pointer inside it as a standard stream: the base is stdin,
anything else stderr. Diagnostic output does not care, and the stride never has
to be guessed.

The same discipline governs aliases: `mkdir(path, mode)` and the Microsoft CRT's
`_mkdir(path)` are not the same function, and aliasing them would compile, link,
run and corrupt the stack. Nor are Bionic's open flags the host's — `O_CREAT` is
0100 against 0x100 — and `struct addrinfo` orders `ai_addr` and `ai_canonname`
the opposite way from Winsock's. Each of those fails silently, not loudly.
