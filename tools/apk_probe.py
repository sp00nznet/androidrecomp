#!/usr/bin/env python3
"""Feasibility triage for statically recompiling an Android game's native engine.

Reads an APK (or an extracted APK dir), picks a native library, and reports the
things that decide whether a static recompile is weeks or years of work:

  * what the library links against (the shim surface you must write)
  * how many functions .eh_frame recovers (the lifter's work unit count)
  * an instruction histogram, and counts of the constructs a static lifter has
    to special-case: indirect branches, exclusives/atomics, syscalls, SIMD.

Nothing about this is game-specific -- point it at any arm64 Android .so.

    python tools/apk_probe.py game.apk
    python tools/apk_probe.py extracted/ --abi arm64-v8a --out docs/triage.md
"""
from __future__ import annotations

import argparse
import collections
import io
import os
import sys
import zipfile

from elftools.elf.elffile import ELFFile

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
except ImportError:
    sys.exit("need capstone: pip install capstone")

# Mnemonic prefixes that a static ARM64->C lifter cannot emit as straight-line
# C and must handle deliberately. Everything else is a pure register/memory op.
HARD = {
    "indirect-branch": ("br", "blr", "braa", "brab", "blraa", "blrab", "retaa", "retab"),
    "exclusive": ("ldxr", "ldaxr", "stxr", "stlxr", "ldxp", "ldaxp", "stxp", "stlxp"),
    "lse-atomic": ("ldadd", "ldclr", "ldeor", "ldset", "ldsmax", "ldsmin", "ldumax",
                   "ldumin", "swp", "cas"),
    "barrier": ("dmb", "dsb", "isb"),
    "syscall": ("svc", "hvc", "smc", "brk"),
    "sysreg": ("mrs", "msr"),
    "pointer-auth": ("pac", "aut", "xpac"),
}



# --- engine identification --------------------------------------------------
#
# The highest-leverage question in the whole triage, and the cheapest to ask.
#
# A port's hardest problem is usually not the machine code -- it is knowing what
# the host owes the engine: which entry points, in what units, on which thread,
# with what set up before each call. Reverse-engineering that from traces is
# slow and produces guesses. If the engine is one whose source is public, none
# of it has to be guessed: the Java side of every JNI call can simply be read,
# and several of these engines ship a desktop backend, which is a working
# reference implementation of the behaviour the host has to reproduce.
#
# So: look for the engine before doing anything else. It costs a substring
# search and can save the entire contract-discovery phase.
#
# Matching is on symbol prefixes first, because a JNI package name is close to
# proof, then on strings in the binary, which are strong but not conclusive.
ENGINES = [
    ("cocos2d-x",
     ["Java_org_cocos2dx_"],
     [b"cocos2d-x", b"Cocos2dxActivity", b"Cocos2dxRenderer"],
     "source public; ships a desktop backend -- the contract can be read "
     "rather than inferred"),
    ("Unity",
     ["Java_com_unity3d_player_"],
     [b"UnityEngine", b"libunity", b"il2cpp"],
     "source is not public; IL2CPP output is a second lifting problem on top "
     "of this one"),
    ("Unreal Engine",
     ["Java_com_epicgames_"],
     [b"UnrealEngine", b"FEngineLoop", b"UE4"],
     "source available under licence; a desktop target exists"),
    ("Godot",
     ["Java_org_godotengine_"],
     [b"godotengine", b"GodotLib"],
     "source public; desktop is a first-class target"),
    ("libGDX",
     ["Java_com_badlogic_gdx_"],
     [b"libgdx", b"com/badlogic/gdx"],
     "source public; desktop backend is the primary one"),
    ("Defold",
     [],
     [b"dmEngine", b"defold"],
     "source public; desktop targets are first class"),
    ("Solar2D / Corona",
     ["Java_com_ansca_corona_"],
     [b"CoronaLua", b"Corona Labs"],
     "source public since 2020"),
    ("Marmalade",
     [],
     [b"s3eDevice", b"Marmalade"],
     "discontinued; SDK source not public"),
    ("GameMaker",
     [],
     [b"YoYoGames", b"GMRunner"],
     "runner source not public"),
    ("Flutter",
     ["Java_io_flutter_"],
     [b"FlutterEngine", b"flutter_assets"],
     "source public; desktop embedders exist"),
    ("Mono / Xamarin",
     [],
     [b"mono_jit_init", b"Xamarin"],
     "a managed runtime -- the game logic is in assemblies, not this binary"),
    ("SDL",
     [],
     [b"SDL_CreateWindow", b"SDL_GL_SwapWindow"],
     "portable already; the host may need very little"),
]


def identify_engine(blob: bytes, exports: list[str]):
    """(name, evidence, note) for each engine the binary looks like."""
    found = []
    for name, symbols, strings, note in ENGINES:
        evidence = []
        for prefix in symbols:
            hit = next((e for e in exports if e.startswith(prefix)), None)
            if hit:
                evidence.append(f"exports {hit}")
        for needle in strings:
            if needle in blob:
                evidence.append(f'contains "{needle.decode()}"')
        if evidence:
            found.append((name, evidence[:3], note))
    return found


def jni_packages(exports: list[str]) -> list[tuple[str, int]]:
    """JNI entry points grouped by the Java package that declared them.

    Useful even when no engine matches: the package names say who wrote the
    Java side, which is where the host contract came from.
    """
    counts: dict[str, int] = {}
    for name in exports:
        if not name.startswith("Java_"):
            continue
        parts = name[5:].split("_")
        if len(parts) < 2:
            continue
        counts[".".join(parts[:-1])] = counts.get(".".join(parts[:-1]), 0) + 1
    return sorted(counts.items(), key=lambda kv: -kv[1])


def read_lib(path: str, abi: str) -> tuple[str, bytes]:
    """Return (name, bytes) of the largest .so for `abi`, from an APK or a dir."""
    candidates: dict[str, int] = {}
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            for i in z.infolist():
                if i.filename.startswith(f"lib/{abi}/") and i.filename.endswith(".so"):
                    candidates[i.filename] = i.file_size
            if not candidates:
                sys.exit(f"no lib/{abi}/*.so in {path}")
            name = max(candidates, key=candidates.get)
            return name, z.read(name)
    for root, _, files in os.walk(os.path.join(path, "lib", abi)):
        for f in files:
            if f.endswith(".so"):
                p = os.path.join(root, f)
                candidates[p] = os.path.getsize(p)
    if not candidates:
        sys.exit(f"no lib/{abi}/*.so under {path}")
    name = max(candidates, key=candidates.get)
    with open(name, "rb") as fh:
        return name, fh.read()


def functions_from_eh_frame(elf: ELFFile) -> list[tuple[int, int]]:
    """Function (start, size) pairs recovered from .eh_frame FDEs."""
    if not elf.has_dwarf_info():
        return []
    out = []
    for entry in elf.get_dwarf_info().EH_CFI_entries():
        hdr = getattr(entry, "header", None)  # CIE/ZERO terminators have none
        if hdr is None:
            continue
        start = getattr(hdr, "initial_location", None)
        size = getattr(hdr, "address_range", None)
        if start and size:
            out.append((start, size))
    out.sort()
    return out


def probe(name: str, blob: bytes) -> dict:
    elf = ELFFile(io.BytesIO(blob))
    rep: dict = {"lib": name, "bytes": len(blob), "machine": elf["e_machine"]}

    text = elf.get_section_by_name(".text")
    rep["text_addr"] = text["sh_addr"]
    rep["text_size"] = text["sh_size"]

    dyn = elf.get_section_by_name(".dynamic")
    rep["needed"] = [t.needed for t in dyn.iter_tags("DT_NEEDED")] if dyn else []

    imports, exports = [], []
    dynsym = elf.get_section_by_name(".dynsym")
    if dynsym:
        for sym in dynsym.iter_symbols():
            if not sym.name:
                continue
            (imports if sym["st_shndx"] == "SHN_UNDEF" else exports).append(sym.name)
    rep["imports"] = sorted(set(imports))
    rep["exports"] = sorted(set(exports))

    funcs = functions_from_eh_frame(elf)
    rep["func_count"] = len(funcs)
    rep["func_bytes"] = sum(s for _, s in funcs)
    rep["eh_coverage"] = rep["func_bytes"] / rep["text_size"] if rep["text_size"] else 0.0

    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.skipdata = True
    code = text.data()
    hist: collections.Counter[str] = collections.Counter()
    hard: collections.Counter[str] = collections.Counter()
    for insn in md.disasm(code, rep["text_addr"]):
        m = insn.mnemonic
        hist[m] += 1
        for kind, prefixes in HARD.items():
            if m.startswith(prefixes):
                hard[kind] += 1
                break
    rep["engines"] = identify_engine(blob, rep["exports"])
    rep["jni_packages"] = jni_packages(rep["exports"])
    rep["insn_total"] = sum(hist.values())
    rep["insn_distinct"] = len(hist)
    rep["insn_top"] = hist.most_common(25)
    rep["hard"] = dict(hard)
    rep["undisassembled"] = hist.get(".byte", 0)
    return rep


def render(rep: dict) -> str:
    L = [f"# Triage: `{os.path.basename(rep['lib'])}`", ""]
    L += [f"- machine: `{rep['machine']}`",
          f"- file: {rep['bytes'] / 1e6:.1f} MB, `.text`: {rep['text_size'] / 1e6:.1f} MB "
          f"@ `0x{rep['text_addr']:x}`",
          f"- instructions: {rep['insn_total']:,} ({rep['insn_distinct']} distinct mnemonics)",
          f"- functions from `.eh_frame`: **{rep['func_count']:,}** "
          f"covering {rep['eh_coverage']:.1%} of `.text`",
          f"- undisassembled bytes: {rep['undisassembled']:,}", ""]

    if rep["engines"]:
        L += ["## Engine", ""]
        for name, evidence, note in rep["engines"]:
            L += [f"**{name}** -- {note}", "",
                  "".join(f"- {e}\n" for e in evidence)]
        L += ["The host contract for a known engine is read, not inferred: the "
              "Java side of every entry point is source you can open, and a "
              "desktop backend is a reference implementation of what the host "
              "has to reproduce.", ""]
    else:
        L += ["## Engine", "",
              "No engine recognised. The contract will have to be recovered "
              "from the binary and the dex -- see `dex_contract.py`.", ""]

    if rep["jni_packages"]:
        L += ["JNI entry points by declaring package:", ""]
        L += [f"- `{pkg}` -- {n}" for pkg, n in rep["jni_packages"][:8]]
        L += [""]

    L += ["## Shim surface", "", "Linked libraries -- every one of these is a shim you write:", ""]
    L += [f"- `{n}`" for n in rep["needed"]]
    L += ["", f"Undefined symbols to satisfy: **{len(rep['imports'])}**  "]
    L += [f"Exported symbols: **{len(rep['exports'])}**", ""]

    jni = [s for s in rep["exports"] if s.startswith("Java_")]
    if jni:
        L += [f"JNI entry points (the Java glue you must replace): **{len(jni)}**", ""]
        L += ["```"] + jni[:40] + (["..."] if len(jni) > 40 else []) + ["```", ""]

    L += ["## Constructs the lifter must special-case", "",
          "| construct | count |", "|---|---|"]
    for k in HARD:
        L.append(f"| {k} | {rep['hard'].get(k, 0):,} |")
    L += ["", "## Top mnemonics", "", "| mnemonic | count |", "|---|---|"]
    L += [f"| `{m}` | {c:,} |" for m, c in rep["insn_top"]]
    return "\n".join(L) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", help="path to an .apk or an extracted apk directory")
    ap.add_argument("--abi", default="arm64-v8a")
    ap.add_argument("--out", help="write the markdown report here instead of stdout")
    args = ap.parse_args()

    name, blob = read_lib(args.target, args.abi)
    md = render(probe(name, blob))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(md)
        print(f"wrote {args.out}")
    else:
        sys.stdout.write(md)


if __name__ == "__main__":
    main()
