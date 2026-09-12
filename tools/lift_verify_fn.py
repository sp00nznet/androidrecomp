#!/usr/bin/env python3
"""Differential-test whole lifted functions against Unicorn.

`lift_verify.py` checks one instruction at a time, which deliberately excludes
control flow. This checks entire functions: the branches, the `goto` web a
lifted function turns into, and the register state that survives across them.

The mechanism that makes it possible is that the lifted program runs against
the *real* image -- its constants, vtables and relocated pointers -- mapped at
a real host address. The oracle is given its own copy at the same numeric
address, so a load of a global reads the same bytes on both sides.

    python tools/lift_verify_fn.py libengine.so --generated generated/
    python tools/lift_verify_fn.py libengine.so --generated generated/ --count 200
"""
from __future__ import annotations

import argparse
import ctypes
import glob
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile

from elftools.elf.elffile import ELFFile

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, UcError
    from unicorn import arm64_const as uc64
except ImportError as e:
    sys.exit(f"need capstone and unicorn: pip install capstone unicorn ({e})")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lifter import functions_from_eh_frame  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STACK_SIZE = 0x10000
ARG_SIZE = 0x40000
SENTINEL = 0x6FFF_0000  # where a returning function lands

UC_X = [getattr(uc64, f"UC_ARM64_REG_X{i}") for i in range(29)] + [
    uc64.UC_ARM64_REG_X29, uc64.UC_ARM64_REG_X30]
UC_Q = [getattr(uc64, f"UC_ARM64_REG_Q{i}") for i in range(32)]

# Instructions that would take the test outside the function under examination.
# A call would run arbitrarily deep and could reach an unlifted stub; a syscall
# has no meaning in either world here.
ESCAPES = ("bl", "blr", "br", "svc", "brk", "hvc", "smc")


class Ctx(ctypes.Structure):
    _fields_ = [
        ("x", ctypes.c_uint64 * 32),
        ("sp", ctypes.c_uint64),
        ("lr_shadow", ctypes.c_uint64),
        ("nf", ctypes.c_uint32), ("zf", ctypes.c_uint32),
        ("cf", ctypes.c_uint32), ("vf", ctypes.c_uint32),
        ("q", (ctypes.c_uint64 * 2) * 32),
        ("image_base", ctypes.c_uint64),
        # Only written by a --pc-notes lift, but it is part of the struct
        # either way, and a layout that disagrees stops the harness dead.
        ("pc", ctypes.c_uint64),
    ]


def build(generated: str, workdir: str):
    """Build the lifted program through CMake and load the result.

    CMake already knows where this project's dependencies are, because it found
    them for the host build. Reproducing that discovery here would be a second
    place to keep in step with the first.
    """
    # Forward slashes: a backslash in a CMake -D argument is an escape, so
    # "G:\\recomp" arrives with a carriage return in it and the glob finds
    # nothing -- silently, because an empty glob is not an error to CMake.
    generated = os.path.abspath(generated).replace("\\", "/")
    print("configuring and building the lifted program ...")
    cfg = ["cmake", "-S", ROOT.replace("\\", "/"), "-B", workdir.replace("\\", "/"),
           "-G", "Ninja", "-DCMAKE_BUILD_TYPE=Release",
           f"-DARC_LIFTED_DIR={generated}"]
    toolchain = os.environ.get("CMAKE_TOOLCHAIN_FILE")
    if toolchain:
        cfg.append(f"-DCMAKE_TOOLCHAIN_FILE={toolchain}")
    elif os.name == "nt" and os.path.exists(r"C:\vcpkg\scripts\buildsystems\vcpkg.cmake"):
        cfg.append(r"-DCMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake")
    for cmd in (cfg, ["cmake", "--build", workdir, "--target", "lifted"]):
        proc = subprocess.run(cmd, capture_output=True, text=True)
        for line in proc.stdout.splitlines():
            if "lifted program" in line or "no generated C" in line:
                print(f"  {line.strip()}")
        if proc.returncode != 0:
            print(proc.stdout[-6000:])
            print(proc.stderr[-4000:], file=sys.stderr)
            sys.exit("the lifted program did not build")

    for root, _, files in os.walk(workdir):
        for f in files:
            if f in ("lifted.dll", "liblifted.so", "liblifted.dylib"):
                path = os.path.join(root, f)
                # Windows resolves a DLL's own dependencies from its directory.
                if os.name == "nt":
                    os.add_dll_directory(root)
                    host_build = os.path.join(ROOT, "build")
                    if os.path.isdir(host_build):
                        os.add_dll_directory(host_build)
                return ctypes.CDLL(path)
    sys.exit("built, but no lifted library was produced")



def alloc_guarded(size: int):
    """A page-aligned region with an inaccessible page after it.

    The code under test writes wherever it believes it should, and a region
    carved out of the interpreter's own heap turns an overrun into heap
    corruption -- which kills the harness outright and reports nothing. A guard
    page turns the same overrun into an access violation the run can catch and
    attribute.
    """
    if os.name == "nt":
        k32 = ctypes.windll.kernel32
        k32.VirtualAlloc.restype = ctypes.c_void_p
        k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                     ctypes.c_ulong, ctypes.c_ulong]
        k32.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                       ctypes.c_ulong,
                                       ctypes.POINTER(ctypes.c_ulong)]
        MEM_COMMIT_RESERVE, PAGE_RW, PAGE_NONE = 0x3000, 0x04, 0x01
        base = k32.VirtualAlloc(None, size + 0x1000, MEM_COMMIT_RESERVE, PAGE_RW)
        if not base:
            sys.exit("could not reserve a scratch region")
        old = ctypes.c_ulong()
        k32.VirtualProtect(ctypes.c_void_p(base + size), 0x1000, PAGE_NONE,
                           ctypes.byref(old))
        return base
    buf = ctypes.create_string_buffer(size + 0x2000)
    keep_alive.append(buf)
    return (ctypes.cast(buf, ctypes.c_void_p).value + 0xFFF) & ~0xFFF


keep_alive = []

def generated_functions(generated: str) -> set:
    """Addresses the generated program actually defines.

    A partial lift is a normal thing to test, and calling a function that was
    never emitted would reach a trapping stub and abort the run rather than
    report anything. So candidates are drawn from what exists.
    """
    header = os.path.join(generated, "lifted.h")
    out = set()
    if not os.path.exists(header):
        return out
    # Names carry an image index now -- fn0_... is the first library given to
    # the lifter, which is the one under test here.
    with open(header, encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("void fn0_"):
                out.add(int(line[9:line.index("(")], 16))
    # The header declares the trapping stubs too -- they have to exist so the
    # program links. Calling one is exactly what it is for, and exactly what a
    # verification run must not do.
    stubs = os.path.join(generated, "stubs.c")
    if os.path.exists(stubs):
        with open(stubs, encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("void fn0_"):
                    out.discard(int(line[9:line.index("(")], 16))
    return out


def pick_functions(path: str, count: int, rng, available: set,
                   window=None, max_size=400):
    """Self-contained functions with real control flow in them.

    A random sweep answers "is the lifter broadly right". It is the wrong
    tool for "is *this* code right", and by the time a title fails in one
    library-shaped corner -- a crypto routine, a decompressor -- that is
    the only question left. `window` restricts the draw to an address
    range, which is how a suspect neighbourhood gets swept exhaustively
    instead of sampled.
    """
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    with open(path, "rb") as fh:
        elf = ELFFile(fh)
        text = elf.get_section_by_name(".text")
        addr, blob = text["sh_addr"], text.data()
        funcs = functions_from_eh_frame(elf)

    candidates = []
    for start, size in funcs:
        if not (16 <= size <= max_size):
            continue
        if window and not (window[0] <= start < window[1]):
            continue
        if available and start not in available:
            continue
        off = start - addr
        if off < 0 or off + size > len(blob):
            continue
        body = blob[off:off + size]
        insns = list(md.disasm(body, start))
        if len(insns) * 4 != size:
            continue  # data in the middle; not a clean function
        if any(i.mnemonic.startswith(ESCAPES) for i in insns):
            continue
        # "Self-contained" has to mean it too. A plain `b` to an address outside
        # the function is a tail call, and following one can land in a function
        # that never lifted -- which traps and takes the whole run with it.
        if any(not (start <= op.imm < start + size)
               for i in insns
               for op in i.operands
               if op.type == 2 and  # ARM64_OP_IMM
               i.mnemonic.startswith(("b", "cb", "tb")) and
               i.mnemonic not in ("bfi", "bfxil", "bic", "bics")):
            continue
        if not any(i.mnemonic.startswith(("b", "cb", "tb")) and
                   i.mnemonic != "bfi" for i in insns):
            continue  # no control flow: the instruction harness covers those
        candidates.append((start, size, body))
    rng.shuffle(candidates)
    return candidates[:count]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("library")
    ap.add_argument("--generated", default="generated")
    ap.add_argument("--count", type=int, default=100)
    ap.add_argument("--build-dir", default="build-lifted",
                    help="kept between runs; rebuilding 430 MB is not free")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--range", dest="window",
                    help="only functions starting in LO:HI (hex offsets)")
    ap.add_argument("--max-size", type=int, default=400,
                    help="largest function body to test, in bytes")
    ap.add_argument("--real-floats", action="store_true",
                    help="seed vector registers with ordinary numbers rather "
                         "than random bits")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    available = generated_functions(args.generated)
    window = None
    if args.window:
        lo, _, hi = args.window.partition(":")
        window = (int(lo, 16), int(hi, 16))
    picks = pick_functions(args.library, args.count, rng, available,
                           window, args.max_size)
    print(f"{len(picks)} self-contained functions with control flow selected")
    if not picks:
        return

    work = os.path.abspath(args.build_dir)
    os.makedirs(work, exist_ok=True)
    if True:
        lib = build(args.generated, work)
        lib.arc_test_load.restype = ctypes.c_uint64
        lib.arc_test_load.argtypes = [ctypes.c_char_p]
        lib.arc_test_span.restype = ctypes.c_uint64
        lib.arc_test_ctx_size.restype = ctypes.c_size_t

        base = lib.arc_test_load(args.library.encode())
        if not base:
            sys.exit("harness could not load the image")
        span = lib.arc_test_span()
        if lib.arc_test_ctx_size() != ctypes.sizeof(Ctx):
            sys.exit("Arm64Ctx layout mismatch between C and python")
        print(f"image mapped at {base:#x}, {span / 1e6:.1f} MB")

        # A pristine copy, restored before every case. Lifted functions write
        # to globals, and each emulator instance is seeded from the image as it
        # currently stands -- so without this, every result depends on which
        # functions ran before it, and changing the lifter silently reshuffles
        # which cases pass. A sweep that is not reproducible cannot be compared
        # against the previous sweep, which is the only thing it is for.
        pristine = ctypes.string_at(base, span)

        # One stack, allocated here, used by the lifted side directly and
        # mapped into the emulator at the same address. Without that a returned
        # pointer into the frame differs on the two sides for no real reason.
        stack_addr = alloc_guarded(STACK_SIZE)
        arg_addr = alloc_guarded(ARG_SIZE)

        # The argument region points at itself. Most functions worth testing
        # walk a pointer -- obj->field->field -- and a region full of random
        # bytes makes the first hop fault, which is why a third of candidates
        # were being skipped rather than compared. Filling it with addresses
        # inside itself means a chase of any depth lands somewhere readable,
        # and the leftover quarter keeps ordinary values in circulation so the
        # comparison still has something to disagree about.
        #
        # Built once: the same bytes are restored before each case, and the
        # randomness that matters between cases is in the registers.
        # Forward-only: a word may point to a *later* word, never an earlier
        # one. Pointers into the region make a chase land somewhere readable,
        # but pointers that can go backwards make cycles, and a function
        # walking a cyclic list never returns -- the emulator stops on its
        # instruction budget while the lifted side runs until the stack is
        # gone. Monotonic targets mean every chase terminates at the end.
        _count = ARG_SIZE // 8
        _words = []
        for _i in range(_count):
            room = _count - _i - 1
            if room > 8 and rng.random() < 0.75:
                _target = rng.randrange(_i + 1, _count)
                _words.append(arg_addr + _target * 8)
            else:
                _words.append(rng.getrandbits(32))
        arg_seed = b"".join(struct.pack("<Q", w) for w in _words)
        stack_seed = bytes(rng.getrandbits(8) for _ in range(STACK_SIZE))

        lib.arc_test_call_guarded.restype = ctypes.c_int
        lib.arc_test_call_guarded.argtypes = [ctypes.c_void_p, ctypes.c_uint64]

        passed = failed = skipped = 0
        failures = []
        for start, size, body in picks:
            # A fresh emulator per function, with the image copied from our own
            # process so both sides see identical memory -- including anything
            # an earlier function wrote.
            ctypes.memmove(base, pristine, span)
            uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
            page = base & ~0xFFF
            uc.mem_map(page, (span + 0x1FFF) & ~0xFFF)
            uc.mem_write(base, pristine)
            uc.mem_map(stack_addr, STACK_SIZE)
            uc.mem_map(arg_addr, ARG_SIZE)
            uc.mem_write(arg_addr, arg_seed)
            ctypes.memmove(arg_addr, arg_seed, ARG_SIZE)
            uc.mem_map(SENTINEL & ~0xFFF, 0x1000)

            regs = [rng.getrandbits(16) for _ in range(31)]
            # x0-x7 carry arguments, and most functions dereference at least
            # one. Point them at distinct, well-separated slots in the scratch
            # region so a load succeeds on both sides instead of faulting.
            for i in range(8):
                regs[i] = arg_addr + (ARG_SIZE // 4) + i * 0x800
            if args.real_floats:
                # Uniform random bits are almost all NaN when read as floats,
                # and ARM and x86 do not agree on *which* NaN comes out of an
                # operation with two NaN inputs -- so a float routine can
                # "disagree" without anything being wrong. Ordinary values
                # separate a genuine lifting bug from that artefact.
                qregs = []
                for _ in range(32):
                    lanes = [struct.pack("<f", rng.uniform(-1e3, 1e3))
                             for _ in range(4)]
                    qregs.append(int.from_bytes(b"".join(lanes), "little"))
            else:
                qregs = [rng.getrandbits(128) for _ in range(32)]
            sp = stack_addr + STACK_SIZE // 2
            nzcv = rng.getrandbits(4)

            for i, r in enumerate(regs):
                uc.reg_write(UC_X[i], r)
            for i, q in enumerate(qregs):
                uc.reg_write(UC_Q[i], q)
            uc.reg_write(uc64.UC_ARM64_REG_X30, SENTINEL)
            uc.reg_write(uc64.UC_ARM64_REG_SP, sp)
            uc.reg_write(uc64.UC_ARM64_REG_NZCV, nzcv << 28)
            uc.mem_write(stack_addr, stack_seed)
            ctypes.memmove(stack_addr, stack_seed, STACK_SIZE)

            try:
                uc.emu_start(base + start, SENTINEL, count=200000)
            except UcError as e:
                skipped += 1
                if args.verbose:
                    print(f"  skip fn_{start:x}: {e}")
                continue
            want = [uc.reg_read(UC_X[i]) for i in range(31)]
            want_q = [uc.reg_read(UC_Q[i]) for i in range(32)]
            want_sp = uc.reg_read(uc64.UC_ARM64_REG_SP)
            want_stack = bytes(uc.mem_read(stack_addr, STACK_SIZE))
            want_args = bytes(uc.mem_read(arg_addr, ARG_SIZE))

            ctx = Ctx()
            for i, r in enumerate(regs):
                ctx.x[i] = r
            for i, q in enumerate(qregs):
                ctx.q[i][0] = q & 0xFFFFFFFFFFFFFFFF
                ctx.q[i][1] = q >> 64
            ctx.x[30] = SENTINEL
            ctx.sp = sp
            ctx.image_base = base
            ctx.nf, ctx.zf = (nzcv >> 3) & 1, (nzcv >> 2) & 1
            ctx.cf, ctx.vf = (nzcv >> 1) & 1, nzcv & 1

            rc = lib.arc_test_call_guarded(ctypes.byref(ctx),
                                          ctypes.c_uint64(start))
            if rc:
                failed += 1
                failures.append((start, "trapped" if rc == 1 else "faulted"))
                continue

            why = None
            for i in range(31):
                if i == 30:
                    continue  # LR is scratch across a call
                if ctx.x[i] != want[i]:
                    why = f"x{i}: lifted {ctx.x[i]:#x} != unicorn {want[i]:#x}"
                    break
            if why is None:
                for i in range(32):
                    got = ctx.q[i][0] | (ctx.q[i][1] << 64)
                    if got != want_q[i]:
                        why = f"q{i}: lifted {got:#x} != unicorn {want_q[i]:#x}"
                        break
            if why is None and \
                    ctypes.string_at(stack_addr, STACK_SIZE) != want_stack:
                why = "stack memory differs"
            if why is None and \
                    ctypes.string_at(arg_addr, ARG_SIZE) != want_args:
                why = "argument memory differs"

            if why:
                failed += 1
                failures.append((start, why))
            else:
                passed += 1

    print(f"\n{passed} passed, {failed} failed, {skipped} skipped")
    if failures:
        print(f"\nfunctions that disagree with the oracle ({len(failures)})")
        for addr, why in failures[:20 if not args.verbose else len(failures)]:
            print(f"  fn_{addr:x}: {why}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
