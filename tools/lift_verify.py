#!/usr/bin/env python3
"""Differential-test the lifter against Unicorn, on whatever machine you have.

A lifter is normally validated by running the lifted code on the real hardware
and diffing. Without an arm64 machine that is not available -- so the oracle is
Unicorn, a QEMU-derived arm64 emulator that runs on x86. It is an independent
implementation, which is the property that matters: a bug we invent in the
emitters will not be mirrored in it.

The instructions under test are harvested from a real library rather than
synthesised, so the encodings and operand shapes are the ones that actually
occur. For each sample the same randomised register state is fed to both the
lifted C and Unicorn, and the resulting registers and flags are compared.

    python tools/lift_verify.py libengine.so
    python tools/lift_verify.py libengine.so --per-form 20 --forms ldr,add

Control flow is out of scope here: branches and calls are verified by running
whole functions, not single instructions. This harness covers data processing
and memory, which is where transcription bugs live.
"""
from __future__ import annotations

import argparse
import collections
import ctypes
import os
import random
import subprocess
import sys
import tempfile

from elftools.elf.elffile import ELFFile

try:
    from capstone import arm64 as a64
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, UcError
    from unicorn import arm64_const as uc64
except ImportError as e:
    sys.exit(f"need capstone and unicorn: pip install capstone unicorn ({e})")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lifter import Lifter, Unsupported  # noqa: E402

CODE_BASE = 0x10000000
SCRATCH_SIZE = 0x4000

UC_X = [getattr(uc64, f"UC_ARM64_REG_X{i}") for i in range(29)] + [
    uc64.UC_ARM64_REG_X29, uc64.UC_ARM64_REG_X30]


class Ctx(ctypes.Structure):
    _fields_ = [
        ("x", ctypes.c_uint64 * 32),
        ("sp", ctypes.c_uint64),
        ("lr_shadow", ctypes.c_uint64),
        ("nf", ctypes.c_uint32), ("zf", ctypes.c_uint32),
        ("cf", ctypes.c_uint32), ("vf", ctypes.c_uint32),
        ("q", (ctypes.c_uint64 * 2) * 32),
        ("image_base", ctypes.c_uint64),
    ]


def operand_shape(md, insn) -> str:
    """A form key: mnemonic plus the shape of its operands."""
    parts = []
    for op in insn.operands:
        if op.type == a64.ARM64_OP_REG:
            name = md.reg_name(op.reg) or "?"
            kind = "x" if name.startswith("x") or name in ("sp", "lr", "fp") else \
                   "w" if name.startswith("w") else "v"
            if op.shift.type != a64.ARM64_SFT_INVALID and op.shift.value:
                kind += "<<"
            parts.append(kind)
        elif op.type == a64.ARM64_OP_IMM:
            parts.append("imm")
        elif op.type == a64.ARM64_OP_MEM:
            m = op.mem
            parts.append("[b" + ("+i" if m.index else "") +
                         ("+d" if m.disp else "") + "]")
        else:
            parts.append("?")
    wb = "!" if insn.writeback else ""
    return f"{insn.mnemonic} {','.join(parts)}{wb}"


def harvest(path: str, per_form: int, only: set[str] | None):
    """Sample real instructions from .text, grouped by operand shape."""
    lifter = Lifter()
    md = lifter.md
    with open(path, "rb") as fh:
        elf = ELFFile(fh)
        text = elf.get_section_by_name(".text")
        addr, blob = text["sh_addr"], text.data()

    buckets: dict[str, list] = collections.defaultdict(list)
    skip_groups = {a64.ARM64_GRP_JUMP, a64.ARM64_GRP_CALL, a64.ARM64_GRP_RET,
                   a64.ARM64_GRP_BRANCH_RELATIVE}
    for insn in md.disasm(blob, addr):
        if only and insn.mnemonic not in only:
            continue
        # Control flow and PC-relative addressing are verified elsewhere.
        if any(g in skip_groups for g in insn.groups):
            continue
        if insn.mnemonic in ("adr", "adrp"):
            continue
        form = operand_shape(md, insn)
        if len(buckets[form]) < per_form:
            buckets[form].append(insn)
    return lifter, buckets


def build_dll(lifter: Lifter, cases: list, workdir: str) -> ctypes.CDLL | None:
    """Emit one C function per case and compile them into a shared library."""
    src = ['#include "arm64_context.h"', "",
           "void arc_dispatch(Arm64Ctx* c, uint64_t t) { (void)c; (void)t; }",
           ""]
    exports = []
    for i, (form, insn, lines) in enumerate(cases):
        name = f"t{i}"
        exports.append(name)
        src.append(f"/* {form}: {insn.mnemonic} {insn.op_str} */")
        src.append(f"void {name}(Arm64Ctx* c) {{")
        src.extend("  " + l for l in lines)
        src.append("}")
    src.append("size_t ctx_size(void) { return sizeof(Arm64Ctx); }")

    c_path = os.path.join(workdir, "cases.c")
    with open(c_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(src))

    runtime = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "runtime")
    dll = os.path.join(workdir, "cases.dll" if os.name == "nt" else "cases.so")
    if os.name == "nt":
        defs = os.path.join(workdir, "cases.def")
        with open(defs, "w") as fh:
            fh.write("EXPORTS\n" + "\n".join(exports + ["ctx_size"]) + "\n")
        cmd = ["cl", "/nologo", "/LD", "/O2", "/I", runtime, c_path,
               f"/Fe:{dll}", f"/Fo:{workdir}\\", "/link", f"/DEF:{defs}"]
    else:
        cmd = ["cc", "-shared", "-fPIC", "-O2", "-I", runtime, c_path, "-o", dll]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=workdir)
    if proc.returncode != 0:
        print(proc.stdout[-4000:])
        print(proc.stderr[-4000:], file=sys.stderr)
        return None
    return ctypes.CDLL(dll)


def run_case(lib, index, insn, scratch_addr, rng) -> tuple[bool, str]:
    """Run one instruction through both implementations and compare."""
    regs = [rng.getrandbits(64) for _ in range(31)]
    # Any register the instruction may use as an address has to point at the
    # scratch page in both worlds, and index registers stay small so the
    # effective address cannot leave it.
    mem_ops = [op for op in insn.operands if op.type == a64.ARM64_OP_MEM]
    for op in mem_ops:
        base = op.mem.base
        if base:
            name = insn._cs.reg_name(base)
            if name and name[0] in "xw" and name[1:].isdigit():
                regs[int(name[1:])] = scratch_addr + SCRATCH_SIZE // 2
        if op.mem.index:
            name = insn._cs.reg_name(op.mem.index)
            if name and name[0] in "xw" and name[1:].isdigit():
                regs[int(name[1:])] = rng.randrange(0, 16)
    sp = scratch_addr + SCRATCH_SIZE // 2
    nzcv = rng.getrandbits(4)
    seed_mem = bytes(rng.getrandbits(8) for _ in range(SCRATCH_SIZE))

    # --- oracle
    uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
    uc.mem_map(CODE_BASE, 0x1000)
    uc.mem_map(scratch_addr, SCRATCH_SIZE)
    uc.mem_write(CODE_BASE, bytes(insn.bytes))
    uc.mem_write(scratch_addr, seed_mem)
    for i, r in enumerate(regs):
        uc.reg_write(UC_X[i], r)
    uc.reg_write(uc64.UC_ARM64_REG_SP, sp)
    uc.reg_write(uc64.UC_ARM64_REG_NZCV, nzcv << 28)
    try:
        uc.emu_start(CODE_BASE, CODE_BASE + len(insn.bytes), count=1)
    except UcError as e:
        return True, f"skipped ({e})"
    want = [uc.reg_read(UC_X[i]) for i in range(31)]
    want_sp = uc.reg_read(uc64.UC_ARM64_REG_SP)
    want_nzcv = (uc.reg_read(uc64.UC_ARM64_REG_NZCV) >> 28) & 0xF
    want_mem = bytes(uc.mem_read(scratch_addr, SCRATCH_SIZE))

    # --- lifted
    ctx = Ctx()
    for i, r in enumerate(regs):
        ctx.x[i] = r
    ctx.sp = sp
    ctx.nf = (nzcv >> 3) & 1
    ctx.zf = (nzcv >> 2) & 1
    ctx.cf = (nzcv >> 1) & 1
    ctx.vf = nzcv & 1
    ctypes.memmove(scratch_addr, seed_mem, SCRATCH_SIZE)
    getattr(lib, f"t{index}")(ctypes.byref(ctx))

    for i in range(31):
        if ctx.x[i] != want[i]:
            return False, f"x{i}: lifted {ctx.x[i]:#x} != unicorn {want[i]:#x}"
    if ctx.sp != want_sp:
        return False, f"sp: lifted {ctx.sp:#x} != unicorn {want_sp:#x}"
    got_nzcv = (ctx.nf << 3) | (ctx.zf << 2) | (ctx.cf << 1) | ctx.vf
    if got_nzcv != want_nzcv:
        return False, f"nzcv: lifted {got_nzcv:04b} != unicorn {want_nzcv:04b}"
    got_mem = ctypes.string_at(scratch_addr, SCRATCH_SIZE)
    if got_mem != want_mem:
        for off in range(SCRATCH_SIZE):
            if got_mem[off] != want_mem[off]:
                return False, (f"memory at +{off:#x}: lifted {got_mem[off]:#04x} "
                               f"!= unicorn {want_mem[off]:#04x}")
    return True, "ok"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("library")
    ap.add_argument("--per-form", type=int, default=8)
    ap.add_argument("--forms", help="comma-separated mnemonics to restrict to")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    only = set(args.forms.split(",")) if args.forms else None
    lifter, buckets = harvest(args.library, args.per_form, only)
    print(f"harvested {sum(len(v) for v in buckets.values()):,} samples "
          f"across {len(buckets):,} operand forms")

    # Only forms the lifter claims to handle are worth running.
    cases, unsupported = [], collections.Counter()
    for form, insns in sorted(buckets.items()):
        for insn in insns:
            try:
                lines = lifter.emit(insn, 0, 0, set())
            except Unsupported as e:
                unsupported[form] = str(e)
                break
            cases.append((form, insn, lines))
    print(f"{len(cases):,} testable, {len(unsupported):,} forms not yet emitted")
    if not cases:
        return

    # Held in a live variable on purpose: the address is handed to compiled
    # code and to Unicorn, so letting the buffer be collected leaves both
    # dereferencing freed memory.
    scratch_buf = ctypes.create_string_buffer(SCRATCH_SIZE + 0x1000)
    scratch = ctypes.cast(scratch_buf, ctypes.c_void_p).value
    scratch_addr = (scratch + 0xFFF) & ~0xFFF  # Unicorn maps page-aligned

    # Windows will not delete a DLL that is still loaded, and we hold one
    # for the whole run.
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as work:
        lib = build_dll(lifter, cases, work)
        if lib is None:
            sys.exit("generated C did not compile")
        if lib.ctx_size() != ctypes.sizeof(Ctx):
            sys.exit(f"Arm64Ctx layout mismatch: C says {lib.ctx_size()}, "
                     f"python says {ctypes.sizeof(Ctx)}")

        rng = random.Random(args.seed)
        results: dict[str, list[str]] = collections.defaultdict(list)
        passed = failed = skipped = 0
        for i, (form, insn, _) in enumerate(cases):
            ok, why = run_case(lib, i, insn, scratch_addr, rng)
            if why.startswith("skipped"):
                skipped += 1
            elif ok:
                passed += 1
            else:
                failed += 1
                results[form].append(f"{insn.mnemonic} {insn.op_str}: {why}")

    print(f"\n{passed:,} passed, {failed:,} failed, {skipped:,} skipped "
          f"(faulting access)")
    if results:
        print(f"\nforms that disagree with the oracle ({len(results)})")
        for form, msgs in sorted(results.items()):
            print(f"  {form}  ({len(msgs)})")
            for msg in msgs[:2 if not args.verbose else len(msgs)]:
                print(f"      {msg}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
