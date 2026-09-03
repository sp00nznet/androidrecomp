#!/usr/bin/env python3
"""Build a synthetic aarch64 shared object, load it with arc_host, check the result.

No game may live in this repository, so the loader is tested against a
stand-in: a hand-assembled ELF that exports a JNI-shaped host contract and
exercises all four relocation types a real NDK library uses. Runs anywhere,
needs no APK, no Android NDK and no arm64 hardware.

    python tools/selftest.py [path/to/arc_host]
"""
from __future__ import annotations

import os
import struct
import subprocess
import sys
import tempfile

ENTRY_POINTS = [
    "init", "render", "resize", "pointerPressed", "keyPressed", "destroy",
]
PREFIX = "Java_com_example_testengine_Bridge_"
IMPORT_NAME = "host_func"

R_ABS64, R_GLOB_DAT, R_JUMP_SLOT, R_RELATIVE = 257, 1025, 1026, 1027
SEG0, SEG1, PAGE = 0x0000, 0x1000, 0x1000


class StrTab:
    def __init__(self) -> None:
        self.blob = b"\0"

    def add(self, s: str) -> int:
        off = len(self.blob)
        self.blob += s.encode() + b"\0"
        return off


def build_so() -> bytes:
    strtab = StrTab()
    needed = strtab.add("libtest.so")

    # symbol 0 is the reserved null entry, then the exports, then one import.
    syms = [b"\0" * 24]
    for i, name in enumerate(ENTRY_POINTS):
        off = strtab.add(PREFIX + name)
        # st_name, st_info(GLOBAL FUNC), st_other, st_shndx=1, value, size
        syms.append(struct.pack("<IBBHQQ", off, 0x12, 0, 1, 0x400 + i * 4, 4))
    import_off = strtab.add(IMPORT_NAME)
    import_index = len(syms)
    syms.append(struct.pack("<IBBHQQ", import_off, 0x12, 0, 0, 0, 0))
    symtab = b"".join(syms)
    nsyms = len(syms)

    # The loader reads only nchain (the symbol count) out of DT_HASH.
    hashtab = struct.pack("<II", 1, nsyms) + b"\0" * (4 * (1 + nsyms))

    def rela(offset: int, sym: int, rtype: int, addend: int) -> bytes:
        return struct.pack("<QQq", offset, (sym << 32) | rtype, addend)

    rela_dyn = (rela(SEG1 + 0x00, 0, R_RELATIVE, 0x400) +
                rela(SEG1 + 0x08, import_index, R_GLOB_DAT, 0) +
                rela(SEG1 + 0x10, 1, R_ABS64, 0))
    rela_plt = rela(SEG1 + 0x18, import_index, R_JUMP_SLOT, 0)
    init_array_count = 2

    # --- lay the first segment out; every vaddr equals its file offset -------
    cursor = 0x0100
    def place(blob: bytes) -> int:
        nonlocal cursor
        at = cursor
        cursor += len(blob) + (-len(blob)) % 8
        return at

    at_hash, at_symtab = place(hashtab), place(symtab)
    at_strtab, at_rela_dyn = place(strtab.blob), place(rela_dyn)
    at_rela_plt = place(rela_plt)
    at_dynamic = place(b"\0" * 0x200)

    DT = dict(NEEDED=1, PLTRELSZ=2, HASH=4, STRTAB=5, SYMTAB=6, RELA=7,
              RELASZ=8, RELAENT=9, STRSZ=10, SYMENT=11, PLTREL=20, JMPREL=23,
              INIT_ARRAY=25, INIT_ARRAYSZ=27)
    dynamic = b"".join(struct.pack("<qQ", t, v) for t, v in [
        (DT["NEEDED"], needed),
        (DT["HASH"], at_hash),
        (DT["STRTAB"], at_strtab), (DT["STRSZ"], len(strtab.blob)),
        (DT["SYMTAB"], at_symtab), (DT["SYMENT"], 24),
        (DT["RELA"], at_rela_dyn), (DT["RELASZ"], len(rela_dyn)),
        (DT["RELAENT"], 24),
        (DT["JMPREL"], at_rela_plt), (DT["PLTRELSZ"], len(rela_plt)),
        (DT["PLTREL"], 7),
        (DT["INIT_ARRAY"], SEG1 + 0x20),
        (DT["INIT_ARRAYSZ"], init_array_count * 8),
        (0, 0),
    ])

    phdrs = b"".join(struct.pack("<IIQQQQQQ", *p) for p in [
        (1, 5, SEG0, SEG0, SEG0, PAGE, PAGE, PAGE),   # PT_LOAD  r-x
        (1, 6, SEG1, SEG1, SEG1, PAGE, PAGE, PAGE),   # PT_LOAD  rw-
        (2, 6, at_dynamic, at_dynamic, at_dynamic,    # PT_DYNAMIC
         len(dynamic), len(dynamic), 8),
    ])
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01\x00" + b"\0" * 8,
        3, 183, 1, 0, 64, 0, 0, 64, 56, len(phdrs) // 56, 64, 0, 0)

    image = bytearray(PAGE * 2)
    image[0:len(ehdr)] = ehdr
    image[64:64 + len(phdrs)] = phdrs
    for at, blob in ((at_hash, hashtab), (at_symtab, symtab),
                     (at_strtab, strtab.blob), (at_rela_dyn, rela_dyn),
                     (at_rela_plt, rela_plt), (at_dynamic, dynamic)):
        image[at:at + len(blob)] = blob
    return bytes(image)


def main() -> int:
    host = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "build", "arc_host.exe" if os.name == "nt" else "arc_host")
    if not os.path.exists(host):
        sys.exit(f"arc_host not built at {host} (cmake --build build)")

    work = tempfile.mkdtemp()
    path = os.path.join(work, "libstandin.so")
    with open(path, "wb") as fh:
        fh.write(build_so())
    contract = os.path.join(work, "contract.txt")
    with open(contract, "w") as fh:
        fh.write("\n".join(PREFIX + n for n in ENTRY_POINTS) + "\n")

    proc = subprocess.run([host, f"--contract={contract}", path],
                          capture_output=True, text=True)
    out = proc.stdout

    expected = [
        "segments   2",
        f"symbols    {len(ENTRY_POINTS) + 2}",
        "relocs     4 applied",
        "initarray  2 constructors",
        "imports    1 total, 0 resolved, 1 outstanding",
        f"    {IMPORT_NAME}",
    ]
    failures = [e for e in expected if e not in out]
    for name in ENTRY_POINTS:
        if f"{name:<28} found" not in out:
            failures.append(f"entry point {name} not found")
    if proc.returncode != 0:
        failures.append(f"exit code {proc.returncode}")

    if failures:
        print(out)
        print(proc.stderr, file=sys.stderr)
        for f in failures:
            print(f"FAIL: {f}", file=sys.stderr)
        return 1
    print(f"ok -- loaded {len(ENTRY_POINTS)} entry points, 4 relocations, "
          f"1 unresolved import bound to a trap slot")
    return 0


if __name__ == "__main__":
    sys.exit(main())
