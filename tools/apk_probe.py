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
