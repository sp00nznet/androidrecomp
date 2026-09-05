#!/usr/bin/env python3
"""Lift aarch64 machine code to C.

Function boundaries come from `.eh_frame`, which NDK builds ship complete, so
the hardest problem in static recompilation -- knowing where functions start and
end -- is read out of the binary rather than inferred.

Each function becomes one C function over an `Arm64Ctx`. Branches inside a
function are `goto`; calls are direct calls; indirect branches go through a
dispatch table keyed on the recovered function starts.

Run it over a library to see how much of it lifts today:

    python tools/lifter.py libengine.so --report
    python tools/lifter.py libengine.so --out generated/ --limit 500

`--report` is the number that matters while the instruction set is being filled
in: it says what fraction of real instructions the emitters cover, and lists the
forms standing between here and the rest.
"""
from __future__ import annotations

import argparse
import bisect
import collections
import os
import sys

from elftools.elf.elffile import ELFFile

try:
    import capstone
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    from capstone import arm64 as a64
except ImportError:
    sys.exit("need capstone: pip install capstone")

# Condition codes, in the encoding order the ARM manual uses. `arc_cond` in the
# runtime takes the raw value, so this only has to map capstone's names back.
CONDS = ["eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc",
         "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"]
COND_INDEX = {c: i for i, c in enumerate(CONDS)}
COND_INDEX["cs"] = COND_INDEX["hs"]
COND_INDEX["cc"] = COND_INDEX["lo"]


class Unsupported(Exception):
    """Raised by an emitter that does not handle this operand shape."""


def reg_of(md: Cs, reg: int) -> tuple[int, bool, bool]:
    """(index, is_64_bit, is_sp) for a capstone register id."""
    name = md.reg_name(reg)
    if name in ("sp", "wsp"):
        return 31, name == "sp", True
    if name in ("xzr", "wzr"):
        return 31, name == "xzr", False
    if name == "fp":
        return 29, True, False
    if name == "lr":
        return 30, True, False
    if name and name[0] in "xw" and name[1:].isdigit():
        return int(name[1:]), name[0] == "x", False
    raise Unsupported(f"register {name}")


FP_BYTES = {"b": 1, "h": 2, "s": 4, "d": 8, "q": 16}

# Vector arrangements: lanes, the union view to address them through, and the
# element width in bits. A 64-bit arrangement writes only the low half of the
# register and zeroes the top, which the emitters get for free by assembling
# the result in a zeroed temporary.
VAS_INFO = {
    "16B": (16, "u8", 8),   "8B": (8, "u8", 8),
    "8H": (8, "u16", 16),   "4H": (4, "u16", 16),
    "4S": (4, "u32", 32),   "2S": (2, "u32", 32),
    "2D": (2, "u64", 64),   "1D": (1, "u64", 64),
    "1B": (1, "u8", 8),     "1H": (1, "u16", 16),
    "1S": (1, "u32", 32),
}
# Structured load/store: the interleave factor. `ld1` is the odd one out --
# given several registers it fills them consecutively rather than
# de-interleaving, which is the same rule stated with a stride of one.
STRUCT_N = {"ld1": 1, "ld2": 2, "ld3": 3, "ld4": 4,
            "st1": 1, "st2": 2, "st3": 3, "st4": 4}
REPL_N = {"ld1r": 1, "ld2r": 2, "ld3r": 3, "ld4r": 4}

# How far a switch index can reach when it is extended rather than read from a
# table. Only the byte widths are listed on purpose: they bound the reachable
# set to something small enough to enumerate, and a wider extend bounds nothing.
EXTEND_RANGE = {getattr(a64, "ARM64_EXT_SXTB", -1): (-128, 127),
                getattr(a64, "ARM64_EXT_UXTB", -2): (0, 255)}

VAS_NAMES = {getattr(a64, n): n.replace("ARM64_VAS_", "")
             for n in dir(a64) if n.startswith("ARM64_VAS_")}


def vreg_of(md: Cs, reg: int):
    """(index, kind) for an FP/SIMD register, or None if it is not one.

    Scalar kinds are b/h/s/d/q by width; `v` is the vector view, which only the
    arrangement in the instruction gives meaning to.
    """
    name = md.reg_name(reg)
    if not name or not name[1:].isdigit():
        return None
    if name[0] in "bhsdq":
        return int(name[1:]), name[0]
    if name[0] == "v":
        return int(name[1:]), "v"
    return None


class Lifter:
    def __init__(self, image_name: str = "image"):
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        self.md.detail = True
        self.image_name = image_name
        self.unsupported: collections.Counter[str] = collections.Counter()
        self.lifted = 0
        self.total = 0
        # Call and branch targets seen. Some are not recovered function starts:
        # a tail call into a neighbour, or a target in the 1.2% of .text that
        # .eh_frame does not cover. Those need stubs or the link fails.
        self.referenced: set[int] = set()
        # Which image is being lifted. Function names and every PC-relative
        # computation are scoped to it, because two images have overlapping
        # offsets and different bases.
        self.image_index = 0
        # Everything mapped from the current image, for reading jump tables,
        # and the tables found in the function being lifted.
        self.image_sections: list[tuple[int, bytes]] = []
        self.cur_tables: dict[int, list[int]] = {}

    # --- operand helpers ---------------------------------------------------

    def read(self, op) -> str:
        """C expression for a source operand."""
        if op.type == a64.ARM64_OP_REG:
            idx, is64, is_sp = reg_of(self.md, op.reg)
            base = "(c)->sp" if is_sp else (
                f"ARC_X_R(c, {idx})" if is64 else f"ARC_W_R(c, {idx})")
            return self.apply_shift(base, op, is64)
        if op.type == a64.ARM64_OP_IMM:
            # An immediate can carry its own shift -- `add w9, w20, #2, lsl #12`
            # means 8192, not 2. Folding it here is safe because the shift
            # amount is always an encoded constant.
            v = op.imm & 0xFFFFFFFFFFFFFFFF
            if op.shift.type == a64.ARM64_SFT_LSL and op.shift.value:
                v = (v << op.shift.value) & 0xFFFFFFFFFFFFFFFF
            return f"UINT64_C({v})"
        raise Unsupported("operand type")

    def apply_shift(self, expr: str, op, is64: bool) -> str:
        """Wrap a register read in its extend and/or shift.

        The two are not alternatives. An extended-register operand such as
        `add x8, x8, w25, sxtw #3` carries both, and the order matters: the
        source is widened to 64 bits *first*, then shifted. Doing the shift in
        the source width instead drops whatever crosses the 32-bit boundary,
        which is a wrong answer rather than a crash -- exactly the kind of bug
        the oracle exists to catch.
        """
        width = 64 if is64 else 32
        cast = "uint64_t" if is64 else "uint32_t"
        amount = op.shift.value if op.shift.type != a64.ARM64_SFT_INVALID else 0

        ext = getattr(op, "ext", a64.ARM64_EXT_INVALID)
        if ext != a64.ARM64_EXT_INVALID:
            table = {
                a64.ARM64_EXT_UXTB: "(uint64_t)(uint8_t)",
                a64.ARM64_EXT_UXTH: "(uint64_t)(uint16_t)",
                a64.ARM64_EXT_UXTW: "(uint64_t)(uint32_t)",
                a64.ARM64_EXT_UXTX: "(uint64_t)",
                a64.ARM64_EXT_SXTB: "(uint64_t)(int64_t)(int8_t)",
                a64.ARM64_EXT_SXTH: "(uint64_t)(int64_t)(int16_t)",
                a64.ARM64_EXT_SXTW: "(uint64_t)(int64_t)(int32_t)",
                a64.ARM64_EXT_SXTX: "(uint64_t)(int64_t)",
            }
            if ext not in table:
                raise Unsupported("extend type")
            expr = f"({table[ext]}({expr}))"
            return f"((uint64_t)({expr}) << {amount})" if amount else expr

        if amount:
            if op.shift.type == a64.ARM64_SFT_LSL:
                return f"(({cast})({expr}) << {amount})"
            if op.shift.type == a64.ARM64_SFT_LSR:
                return f"(({cast})({expr}) >> {amount})"
            if op.shift.type == a64.ARM64_SFT_ASR:
                signed = "int64_t" if is64 else "int32_t"
                return f"(({cast})(({signed})({expr}) >> {amount}))"
            if op.shift.type == a64.ARM64_SFT_ROR:
                return f"arc_ror{width}({expr}, {amount})"
            raise Unsupported("shift type")
        return expr

    def write(self, op, value: str) -> str:
        idx, is64, is_sp = reg_of(self.md, op.reg)
        if is_sp:
            return f"(c)->sp = (uint64_t)({value});"
        return (f"ARC_X_W(c, {idx}, {value});" if is64
                else f"ARC_W_W(c, {idx}, {value});")

    def dest_is64(self, op) -> bool:
        return reg_of(self.md, op.reg)[1]

    # --- floating point helpers --------------------------------------------

    def fp_of(self, op):
        if op.type != a64.ARM64_OP_REG:
            return None
        return vreg_of(self.md, op.reg)

    def fp_read(self, op) -> str:
        """C expression for a scalar FP source, as its natural C type."""
        info = self.fp_of(op)
        if info is None:
            raise Unsupported("not an FP register")
        idx, kind = info
        if kind == "s":
            return f"ARC_S_R(c, {idx})"
        if kind == "d":
            return f"ARC_D_R(c, {idx})"
        raise Unsupported(f"scalar FP kind {kind}")

    def fp_bits_read(self, op) -> str:
        """The raw bits of an FP register, for moves that do not convert."""
        idx, kind = self.fp_of(op)
        if kind == "s":
            return f"ARC_SU_R(c, {idx})"
        if kind == "d":
            return f"ARC_DU_R(c, {idx})"
        if kind in ("b", "h"):
            return f"ARC_{kind.upper()}_R(c, {idx})"
        raise Unsupported(f"bit read of {kind}")

    def fp_write(self, op, expr: str) -> str:
        idx, kind = self.fp_of(op)
        if kind == "s":
            return f"arc_s_w(c, {idx}, (float)({expr}));"
        if kind == "d":
            return f"arc_d_w(c, {idx}, (double)({expr}));"
        raise Unsupported(f"scalar FP kind {kind}")

    def fp_bits_write(self, op, expr: str) -> str:
        idx, kind = self.fp_of(op)
        if kind == "s":
            return f"arc_su_w(c, {idx}, (uint32_t)({expr}));"
        if kind == "d":
            return f"arc_du_w(c, {idx}, (uint64_t)({expr}));"
        raise Unsupported(f"bit write of {kind}")

    def fp_kind(self, op) -> str:
        info = self.fp_of(op)
        if info is None:
            raise Unsupported("not an FP register")
        return info[1]

    def read_any(self, op) -> str:
        """Source operand that may be a GPR, an immediate or an FP register."""
        if op.type == a64.ARM64_OP_FP:
            return repr(float(op.fp))
        if self.fp_of(op) is not None:
            return self.fp_read(op)
        return self.read(op)

    def mem_address(self, op, insn) -> str:
        """C expression for a memory operand's effective address."""
        m = op.mem
        if m.base == 0:
            raise Unsupported("memory without base")
        bidx, _, b_sp = reg_of(self.md, m.base)
        addr = "(c)->sp" if b_sp else f"ARC_X_R(c, {bidx})"
        if m.index:
            iidx, i64, _ = reg_of(self.md, m.index)
            index = f"ARC_X_R(c, {iidx})" if i64 else f"ARC_W_R(c, {iidx})"
            index = self.apply_shift(index, op, i64)
            addr = f"({addr} + {index})"
        if m.disp:
            addr = f"({addr} + INT64_C({m.disp}))"
        return addr

    # --- vector -------------------------------------------------------------

    def is_vector(self, op) -> bool:
        if op.type != a64.ARM64_OP_REG:
            return False
        return (self.md.reg_name(op.reg) or "").startswith("v")

    def vas_of(self, op):
        """(lanes, view, element bits) for an arrangement, or None."""
        return VAS_INFO.get(VAS_NAMES.get(getattr(op, "vas", 0), ""))

    def lane_of(self, op) -> int:
        return getattr(op, "vector_index", -1)

    def vreg_index(self, op) -> int:
        info = vreg_of(self.md, op.reg)
        if info is None:
            raise Unsupported("not a vector register")
        return info[0]

    def vec_elem(self, op, lane: int, view: str) -> str:
        return f"(c)->q[{self.vreg_index(op)}].{view}[{lane}]"

    def vec_source(self, op, lane: int, view: str) -> str:
        """A source lane, honouring a lane-indexed operand as a broadcast."""
        idx = self.lane_of(op)
        return self.vec_elem(op, idx if idx >= 0 else lane, view)

    def vec_result(self, dest, body):
        """Assemble lanes in a zeroed temporary, then commit.

        The temporary is not decoration. A destination register is frequently
        also a source, so writing lanes in place would feed already-updated
        values into later lanes. Zeroing it also gives the 64-bit arrangements
        their upper-half clear for free.
        """
        return (["{ Arm64Vec _t; _t.u64[0] = 0; _t.u64[1] = 0;"] + body +
                [f"  (c)->q[{self.vreg_index(dest)}] = _t; }}"])

    def vec_result_keep(self, dest, body, clear_top=False):
        """Like vec_result, but starting from what the register already holds.

        Two unrelated kinds of instruction need this. The `2` forms of the
        narrowing instructions write one half of the destination and leave the
        other untouched. The accumulating forms read the destination as an
        operand, so they cannot start from zero either -- but they are still
        ordinary results, and a 64-bit arrangement clears the top half of the
        register the way every other 64-bit result does. Hence `clear_top`:
        the narrowing forms are always 128-bit and must not do it.
        """
        idx = self.vreg_index(dest)
        tail = ["  _t.u64[1] = 0;"] if clear_top else []
        return ([f"{{ Arm64Vec _t = (c)->q[{idx}];"] + body + tail +
                [f"  (c)->q[{idx}] = _t; }}"])

    @staticmethod
    def signed_view(bits: int) -> str:
        return {8: "i8", 16: "i16", 32: "i32", 64: "i64"}[bits]

    def emit_vector_mem(self, insn, ops, m):
        """ldN/stN and the replicating ldNr.

        Four shapes share an emitter because they differ only in which byte of
        the memory stream a lane comes from:

            ld1 {v0, v1}      consecutive whole registers, no interleave
            ldN {v0..vN}      N-way de-interleave: lane e of register r is
                              element e*N + r of the stream
            ldNr {v0}         one element per register, broadcast to its lanes
            ldN {v0.s}[i]     one element per register, into lane i alone

        The write-back is computed here instead of through `writeback`, which
        would silently produce nothing: these encode the post-index increment
        as "however much was transferred" rather than as an immediate, so
        capstone reports the instruction as writing back and leaves no operand
        saying by how much.
        """
        regs = []
        for o in ops:
            if o.type == a64.ARM64_OP_MEM:
                break
            regs.append(o)
        mem = next((o for o in ops if o.type == a64.ARM64_OP_MEM), None)
        if mem is None or not regs:
            raise Unsupported(f"{m} operands")
        info = self.vas_of(regs[0])
        if not info:
            raise Unsupported(f"{m} without arrangement")
        lanes, view, bits = info
        eb = bits // 8
        store = m.startswith("st")
        # The index belongs to the whole register list, and capstone hangs it
        # off the last entry -- the earlier ones report no lane at all. Asking
        # only the first would read -1 and quietly take the whole-register
        # path, which is a different instruction.
        lane = max(self.lane_of(r) for r in regs)
        ld, st = f"arc_ld{bits}", f"arc_st{bits}"

        lines = ["{ const uint64_t _pa = " + self.mem_address(mem, insn) + ";"]
        if lane >= 0:
            # A single-lane transfer leaves the rest of the register alone.
            total = len(regs) * eb
            for r, reg in enumerate(regs):
                slot = self.vec_elem(reg, lane, view)
                lines.append(f"  {st}(_pa + {r * eb}, {slot});" if store
                             else f"  {slot} = {ld}(_pa + {r * eb});")
        elif m in REPL_N:
            total = len(regs) * eb
            for r, reg in enumerate(regs):
                idx = self.vreg_index(reg)
                lines.append(f"  {{ const uint{bits}_t _e = {ld}(_pa + {r * eb});")
                lines.append("    Arm64Vec _t; _t.u64[0] = 0; _t.u64[1] = 0;")
                lines.extend(f"    _t.{view}[{i}] = _e;" for i in range(lanes))
                lines.append(f"    (c)->q[{idx}] = _t; }}")
        else:
            total = len(regs) * lanes * eb
            stride = STRUCT_N[m]
            for r, reg in enumerate(regs):
                # A 64-bit arrangement writes the low half and clears the top,
                # which filling lane by lane would not do on its own.
                if not store and lanes * bits == 64:
                    lines.append(f"  arc_v_clear(c, {self.vreg_index(reg)});")
                for e in range(lanes):
                    off = ((r * lanes + e) if stride == 1
                           else (e * stride + r)) * eb
                    slot = self.vec_elem(reg, e, view)
                    lines.append(f"  {st}(_pa + {off}, {slot});" if store
                                 else f"  {slot} = {ld}(_pa + {off});")

        if insn.writeback:
            bidx, _, b_sp = reg_of(self.md, mem.mem.base)
            trailing = [o for o in ops[len(regs) + 1:]
                        if o.type == a64.ARM64_OP_REG]
            if trailing:
                iidx, _, _ = reg_of(self.md, trailing[0].reg)
                delta = f"ARC_X_R(c, {iidx})"
            else:
                delta = f"UINT64_C({total})"
            lines.append(f"  (c)->sp = (c)->sp + {delta};" if b_sp else
                         f"  ARC_X_W(c, {bidx}, ARC_X_R(c, {bidx}) + {delta});")
        lines.append("}")
        return lines

    def emit_vector(self, insn, ops):
        m = insn.mnemonic

        if m in STRUCT_N or m in REPL_N:
            return self.emit_vector_mem(insn, ops, m)

        # A whole-register move is by far the most common vector instruction in
        # a real engine, and it is only a copy. `orr vD, vN, vN` is the same
        # thing spelled differently, which is how the assembler encodes it.
        if len(ops) >= 2 and self.is_vector(ops[0]) and self.is_vector(ops[1]) \
                and self.lane_of(ops[0]) < 0 and self.lane_of(ops[1]) < 0 \
                and (m == "mov" or
                     (m == "orr" and len(ops) == 3 and ops[1].reg == ops[2].reg)):
            d, n = self.vreg_index(ops[0]), self.vreg_index(ops[1])
            info = self.vas_of(ops[0])
            if info and info[0] * info[2] == 64:
                return [f"arc_q_w(c, {d}, (c)->q[{n}].u64[0], 0);"]
            return [f"(c)->q[{d}] = (c)->q[{n}];"]

        # `fmov vD.4s, #1.0` broadcasts a floating-point immediate.
        if m == "fmov" and self.is_vector(ops[0]) and \
                ops[1].type == a64.ARM64_OP_FP:
            info = self.vas_of(ops[0])
            if info:
                lanes, _, bits = info
                fview = {32: "f32", 64: "f64"}.get(bits)
                if fview:
                    value = repr(float(ops[1].fp))
                    return self.vec_result(ops[0], [
                        f"  _t.{fview}[{i}] = {value};" for i in range(lanes)])
            raise Unsupported("vector fmov")

        # `movi d3, #imm` names a scalar register, so there is no arrangement
        # to replicate across -- the immediate is the whole 64-bit value.
        if m in ("movi", "mvni") and self.fp_of(ops[0]) is not None \
                and self.vas_of(ops[0]) is None \
                and ops[1].type == a64.ARM64_OP_IMM:
            idx, kind = self.fp_of(ops[0])
            value = ops[1].imm & 0xFFFFFFFFFFFFFFFF
            if m == "mvni":
                value = (~value) & 0xFFFFFFFFFFFFFFFF
            if kind == "d":
                return [f"arc_du_w(c, {idx}, UINT64_C({value}));"]
            if kind == "s":
                return [f"arc_su_w(c, {idx}, UINT32_C({value & 0xFFFFFFFF}));"]
            raise Unsupported(f"movi into {kind}")

        if m in ("movi", "mvni") and self.is_vector(ops[0]):
            imm = ops[1]
            if imm.type != a64.ARM64_OP_IMM:
                raise Unsupported("movi operand")
            value = imm.imm
            if imm.shift.type == a64.ARM64_SFT_LSL and imm.shift.value:
                value <<= imm.shift.value
            if value == 0 and m == "movi":
                return [f"arc_v_clear(c, {self.vreg_index(ops[0])});"]
            info = self.vas_of(ops[0])
            if not info:
                raise Unsupported("movi without arrangement")
            lanes, view, bits = info
            mask = (1 << bits) - 1
            if m == "mvni":
                value = ~value
            value &= mask
            return self.vec_result(ops[0], [
                f"  _t.{view}[{i}] = UINT64_C({value});" for i in range(lanes)])

        # Lane to general register. `mov w0, v1.s[2]` is the assembler's
        # preferred spelling of `umov`, so it arrives here under that name.
        if (m in ("umov", "smov")
                or (m == "mov" and len(ops) == 2 and self.is_vector(ops[1])
                    and self.fp_of(ops[0]) is None)) \
                and not self.is_vector(ops[0]):
            src = ops[1]
            info = self.vas_of(src)
            view = info[1] if info else "u32"
            bits = info[2] if info else 32
            expr = self.vec_elem(src, max(self.lane_of(src), 0), view)
            if m == "smov":
                w = 64 if self.dest_is64(ops[0]) else 32
                expr = f"arc_sext{w}({expr}, {bits})"
            return [self.write(ops[0], expr)]

        # Lane to scalar register. Naming a scalar destination is what makes
        # this different from a lane-to-lane move: the write clears the rest
        # of the register rather than leaving the other lanes alone.
        if m in ("mov", "dup") and len(ops) == 2 and not self.is_vector(ops[0]) \
                and self.fp_of(ops[0]) is not None and self.is_vector(ops[1]):
            idx, kind = self.fp_of(ops[0])
            sinfo = self.vas_of(ops[1])
            src_view = sinfo[1] if sinfo else "u64"
            value = self.vec_elem(ops[1], max(self.lane_of(ops[1]), 0), src_view)
            if kind == "q":
                n = self.vreg_index(ops[1])
                return [f"(c)->q[{idx}] = (c)->q[{n}];"]
            fn = "arc_du_w" if kind == "d" else "arc_su_w"
            return [f"{fn}(c, {idx}, {value});"]

        # Into a single lane, from another lane or from a general register.
        if self.is_vector(ops[0]) and self.lane_of(ops[0]) >= 0 and \
                m in ("ins", "mov"):
            d, src = ops[0], ops[1]
            info = self.vas_of(d)
            view = info[1] if info else "u64"
            value = (self.vec_elem(src, max(self.lane_of(src), 0), view)
                     if self.is_vector(src) else self.read(src))
            return [f"{self.vec_elem(d, self.lane_of(d), view)} = ({value});"]

        if m == "dup":
            d, src = ops[0], ops[1]
            info = self.vas_of(d)
            if not info:
                raise Unsupported("dup without arrangement")
            lanes, view, _ = info
            value = (self.vec_source(src, 0, view) if self.is_vector(src)
                     else self.read(src))
            return self.vec_result(d, [f"  _t.{view}[{i}] = ({value});"
                                       for i in range(lanes)])

        # Pairwise reduction to a scalar: `faddp s0, v0.2s` adds the two lanes
        # of its source together. Two operands and a scalar destination is what
        # separates it from the three-operand vector form below.
        if m in ("faddp", "addp") and len(ops) == 2 \
                and not self.is_vector(ops[0]) \
                and self.fp_of(ops[0]) is not None:
            sinfo = self.vas_of(ops[1])
            if not sinfo:
                raise Unsupported(f"{m} source arrangement")
            _, s_view, sbits = sinfo
            idx, kind = self.fp_of(ops[0])
            if m == "faddp":
                fv = {32: "f32", 64: "f64"}.get(sbits)
                if not fv:
                    raise Unsupported(f"{m} on {sbits}-bit lanes")
                return [self.fp_write(
                    ops[0], f"arc_fadd{sbits}({self.vec_elem(ops[1], 0, fv)},"
                            f" {self.vec_elem(ops[1], 1, fv)})")]
            setter = "arc_du_w" if kind == "d" else "arc_su_w"
            return [f"{setter}(c, {idx}, ({self.vec_elem(ops[1], 0, s_view)}"
                    f" + {self.vec_elem(ops[1], 1, s_view)}));"]

        # `fmov d0, x8` moves the bits between a general register and a scalar
        # -- no conversion, and no arrangement to find. It reaches here only
        # because the other operand made it look like a vector instruction.
        if m == "fmov" and len(ops) == 2 and not self.is_vector(ops[0]) \
                and not self.is_vector(ops[1]):
            dst_fp, src_fp = self.fp_of(ops[0]), self.fp_of(ops[1])
            if dst_fp is not None and src_fp is None \
                    and ops[1].type == a64.ARM64_OP_REG:
                idx, kind = dst_fp
                setter = "arc_du_w" if kind == "d" else "arc_su_w"
                return [f"{setter}(c, {idx}, {self.read(ops[1])});"]
            if dst_fp is None and src_fp is not None:
                idx, kind = src_fp
                width = "u64" if kind == "d" else "u32"
                return [self.write(ops[0], f"(c)->q[{idx}].{width}[0]")]
            if dst_fp is not None and ops[1].type == a64.ARM64_OP_FP:
                return [self.fp_write(ops[0], repr(float(ops[1].fp)))]

        # Scalar arithmetic that takes one operand from a lane, as in
        # `fmul s1, s4, v19.s[1]`. The destination is a scalar register and has
        # no arrangement; the lane index on the last operand is the only thing
        # that makes this look like a vector instruction at all.
        if m in ("fmul", "fmulx", "fmla", "fmls") and len(ops) == 3 \
                and not self.is_vector(ops[0]) \
                and self.fp_of(ops[0]) is not None \
                and self.is_vector(ops[2]) and self.lane_of(ops[2]) >= 0:
            kind = self.fp_of(ops[0])[1]
            w = "32" if kind == "s" else "64"
            fview = "f32" if kind == "s" else "f64"
            lane = self.vec_elem(ops[2], self.lane_of(ops[2]), fview)
            n = self.fp_read(ops[1])
            if m in ("fmul", "fmulx"):
                return [self.fp_write(ops[0], f"arc_fmul{w}({n}, {lane})")]
            f = "f" if w == "32" else ""
            sign = "-" if m == "fmls" else ""
            return [self.fp_write(
                ops[0], f"fma{f}({sign}{n}, {lane}, {self.fp_read(ops[0])})")]

        # Horizontal reductions collapse the whole vector into one value, so
        # the destination is a scalar register and carries no arrangement of
        # its own. That is why they have to be answered here, before anything
        # asks the destination for one: the source's arrangement is the only
        # one there is. The `l` forms widen as they go, which is what keeps a
        # sum of sixteen bytes from wrapping at eight bits.
        across = {"addv": "+", "uaddlv": "+", "saddlv": "+",
                  "umaxv": ">", "smaxv": ">", "uminv": "<", "sminv": "<"}
        if m in across and len(ops) == 2 and not self.is_vector(ops[0]) \
                and self.fp_of(ops[0]) is not None:
            sinfo = self.vas_of(ops[1])
            if not sinfo:
                raise Unsupported(f"{m} source arrangement")
            slanes, s_view, sbits = sinfo
            signed = m[0] == "s"
            src_view = self.signed_view(sbits) if signed else s_view
            acc = "int64_t" if signed else "uint64_t"
            idx, kind = self.fp_of(ops[0])
            c = across[m]
            lines = [f"{{ {acc} _r = ({acc})"
                     f"({self.vec_elem(ops[1], 0, src_view)});"]
            for i in range(1, slanes):
                v = f"({acc})({self.vec_elem(ops[1], i, src_view)})"
                if c == "+":
                    lines.append(f"  _r = ({acc})(_r + {v});")
                else:
                    lines.append(f"  {{ {acc} _v = {v};"
                                 f" if (_v {c} _r) _r = _v; }}")
            bits = FP_BYTES.get(kind, 8) * 8
            value = "(uint64_t)_r"
            if bits < 64:
                value = f"((uint64_t)_r & UINT64_C({(1 << bits) - 1}))"
            setter = "arc_du_w" if kind == "d" else "arc_su_w"
            lines.append(f"  {setter}(c, {idx}, {value}); }}")
            return lines

        info = self.vas_of(ops[0]) if self.is_vector(ops[0]) else None
        if not info:
            raise Unsupported(f"vector {m} without arrangement")
        lanes, view, bits = info
        fview = {32: "f32", 64: "f64"}.get(bits)
        sview = {8: "i8", 16: "i16", 32: "i32", 64: "i64"}.get(bits, "i32")
        ones = f"(uint{bits}_t)~(uint{bits}_t)0"

        # Widening shifts: take one half of a narrower source, extend it to the
        # destination's lane width, then shift. The `2` forms take the top half.
        if m in ("ushll", "ushll2", "sshll", "sshll2") and len(ops) == 3:
            sinfo = self.vas_of(ops[1])
            if not sinfo:
                raise Unsupported(f"{m} source arrangement")
            slanes, sview, sbits = sinfo
            signed = m.startswith("s")
            base = slanes - lanes if m.endswith("2") else 0
            src_view = self.signed_view(sbits) if signed else sview
            cast = f"int{bits}_t" if signed else f"uint{bits}_t"
            n = ops[2].imm
            return self.vec_result(ops[0], [
                f"  _t.{view}[{i}] = (uint{bits}_t)(({cast})"
                f"({self.vec_elem(ops[1], base + i, src_view)}) << {n});"
                for i in range(lanes)])

        # Widening add: a full-width operand plus one half of a narrower one.
        if m in ("uaddw", "uaddw2", "saddw", "saddw2", "usubw", "usubw2",
                 "ssubw", "ssubw2") and len(ops) == 3:
            sinfo = self.vas_of(ops[2])
            if not sinfo:
                raise Unsupported(f"{m} source arrangement")
            slanes, sview, sbits = sinfo
            signed = m.startswith("s")
            base = slanes - lanes if m.endswith("2") else 0
            src_view = self.signed_view(sbits) if signed else sview
            cast = f"int{bits}_t" if signed else f"uint{bits}_t"
            op_c = "-" if "sub" in m else "+"
            return self.vec_result(ops[0], [
                f"  _t.{view}[{i}] = {self.vec_source(ops[1], i, view)} {op_c}"
                f" (uint{bits}_t)(({cast})"
                f"({self.vec_elem(ops[2], base + i, src_view)}));"
                for i in range(lanes)])

        # Narrowing: `xtn` fills the low half of the destination, `xtn2` the
        # high half, leaving the other alone.
        if m in ("xtn", "xtn2") and len(ops) == 2:
            sinfo = self.vas_of(ops[1])
            if not sinfo:
                raise Unsupported(f"{m} source arrangement")
            slanes, sview, _ = sinfo
            if m == "xtn":
                return self.vec_result(ops[0], [
                    f"  _t.{view}[{i}] = (uint{bits}_t)"
                    f"({self.vec_elem(ops[1], i, sview)});"
                    for i in range(slanes)])
            return self.vec_result_keep(ops[0], [
                f"  _t.{view}[{lanes - slanes + i}] = (uint{bits}_t)"
                f"({self.vec_elem(ops[1], i, sview)});"
                for i in range(slanes)])

        # Shift by a signed per-lane amount, either direction.
        if m in ("ushl", "sshl") and len(ops) == 3:
            fn = f"arc_{m}{bits}"
            return self.vec_result(ops[0], [
                f"  _t.{view}[{i}] = {fn}({self.vec_source(ops[1], i, view)},"
                f" (int8_t){self.vec_source(ops[2], i, view)});"
                for i in range(lanes)])

        vshift = {"shl": "<<", "ushr": ">>", "sshr": ">>"}
        if m in vshift and len(ops) == 3 and ops[2].type == a64.ARM64_OP_IMM:
            n = ops[2].imm
            # An arithmetic right shift has to read the lane through the signed
            # view; the unsigned one would shift zeroes in.
            src_view = sview if m == "sshr" else view
            return self.vec_result(ops[0], [
                f"  _t.{view}[{i}] = (uint{bits}_t)("
                f"{self.vec_source(ops[1], i, src_view)} {vshift[m]} {n});"
                for i in range(lanes)])

        int_bin = {"add": "+", "sub": "-", "and": "&", "orr": "|",
                   "eor": "^", "mul": "*"}
        flt_bin = {"fadd": "+", "fsub": "-", "fmul": "*", "fdiv": "/"}

        if m in int_bin and len(ops) == 3:
            c = int_bin[m]
            return self.vec_result(ops[0], [
                f"  _t.{view}[{i}] = {self.vec_source(ops[1], i, view)} {c}"
                f" {self.vec_source(ops[2], i, view)};" for i in range(lanes)])
        if m in ("bsl", "bit", "bif") and len(ops) == 3:
            d = self.vec_source(ops[0], 0, view)  # placeholder, per lane below
            body = []
            for i in range(lanes):
                dst = self.vec_elem(ops[0], i, view)
                n = self.vec_source(ops[1], i, view)
                mm = self.vec_source(ops[2], i, view)
                if m == "bsl":
                    # The destination is the mask: bits from the second source
                    # where it is set, from the third where it is clear.
                    expr = f"(({dst} & {n}) | (~{dst} & {mm}))"
                elif m == "bit":
                    expr = f"({dst} ^ (({n} ^ {dst}) & {mm}))"
                else:
                    expr = f"({dst} ^ (({n} ^ {dst}) & ~{mm}))"
                body.append(f"  _t.{view}[{i}] = {expr};")
            return self.vec_result(ops[0], body)

        if m in ("bic", "orn") and len(ops) == 3:
            c = "&" if m == "bic" else "|"
            return self.vec_result(ops[0], [
                f"  _t.{view}[{i}] = {self.vec_source(ops[1], i, view)} {c}"
                f" (~{self.vec_source(ops[2], i, view)});" for i in range(lanes)])
        if m in flt_bin and len(ops) == 3:
            if not fview:
                raise Unsupported(f"{m} on {bits}-bit lanes")
            return self.vec_result(ops[0], [
                f"  _t.{fview}[{i}] = arc_{m}{bits}("
                f"{self.vec_source(ops[1], i, fview)},"
                f" {self.vec_source(ops[2], i, fview)});" for i in range(lanes)])

        vrint = {"frinta": "round", "frintm": "floor", "frintp": "ceil",
                 "frintz": "trunc", "frintn": "nearbyint", "frintx": "rint",
                 "frinti": "rint"}
        if m in vrint and fview:
            f = "f" if bits == 32 else ""
            return self.vec_result(ops[0], [
                f"  _t.{fview}[{i}] = {vrint[m]}{f}("
                f"{self.vec_source(ops[1], i, fview)});" for i in range(lanes)])

        if m in ("fneg", "fabs", "fsqrt") and fview:
            f = "f" if bits == 32 else ""
            w = "32" if bits == 32 else "64"
            body = []
            for i in range(lanes):
                v = self.vec_source(ops[1], i, fview)
                expr = {"fneg": f"-({v})", "fabs": f"fabs{f}({v})",
                        "fsqrt": f"arc_fsqrt{w}({v})"}[m]
                body.append(f"  _t.{fview}[{i}] = {expr};")
            return self.vec_result(ops[0], body)
        if m == "neg":
            return self.vec_result(ops[0], [
                f"  _t.{view}[{i}] = (uint{bits}_t)(0 -"
                f" {self.vec_source(ops[1], i, view)});" for i in range(lanes)])
        if m in ("not", "mvn"):
            return self.vec_result(ops[0], [
                f"  _t.{view}[{i}] = ~{self.vec_source(ops[1], i, view)};"
                for i in range(lanes)])
        if m == "cnt":
            return self.vec_result(ops[0], [
                f"  _t.{view}[{i}] = arc_popcount8("
                f"{self.vec_source(ops[1], i, view)});" for i in range(lanes)])

        if m in ("scvtf", "ucvtf") and fview:
            cast = ("int" if m == "scvtf" else "uint") + str(bits) + "_t"
            ctype = "float" if bits == 32 else "double"
            return self.vec_result(ops[0], [
                f"  _t.{fview}[{i}] = ({ctype})({cast})"
                f"{self.vec_source(ops[1], i, view)};" for i in range(lanes)])
        if m in ("fcvtzs", "fcvtzu") and fview:
            fn = f"arc_f2i{bits}" if m == "fcvtzs" else f"arc_f2u{bits}"
            return self.vec_result(ops[0], [
                f"  _t.{view}[{i}] = {fn}((double)"
                f"{self.vec_source(ops[1], i, fview)});" for i in range(lanes)])

        # A comparison writes all-ones or zero into the lane, not 0 or 1.
        # The `lt`/`le` spellings exist only against zero -- there is no
        # register form, because it is the same instruction with the operands
        # the other way round.
        int_cmp = {"cmeq": "==", "cmgt": ">", "cmge": ">=",
                   "cmhi": ">", "cmhs": ">=", "cmlt": "<", "cmle": "<="}
        flt_cmp = {"fcmeq": "==", "fcmgt": ">", "fcmge": ">=",
                   "fcmlt": "<", "fcmle": "<="}
        if m in int_cmp:
            v = sview if m in ("cmgt", "cmge", "cmlt", "cmle") else view
            body = []
            for i in range(lanes):
                r = (self.vec_source(ops[2], i, v)
                     if len(ops) > 2 and self.is_vector(ops[2]) else "0")
                body.append(f"  _t.{view}[{i}] = ({self.vec_source(ops[1], i, v)}"
                            f" {int_cmp[m]} {r}) ? {ones} : 0;")
            return self.vec_result(ops[0], body)
        if m in flt_cmp and fview:
            body = []
            for i in range(lanes):
                r = (self.vec_source(ops[2], i, fview)
                     if len(ops) > 2 and self.is_vector(ops[2]) else "0.0")
                body.append(f"  _t.{view}[{i}] = ({self.vec_source(ops[1], i, fview)}"
                            f" {flt_cmp[m]} {r}) ? {ones} : 0;")
            return self.vec_result(ops[0], body)

        # Multiply-accumulate. Genuinely fused: a separate multiply and add
        # would round twice, and the difference accumulates.
        if m in ("fmla", "fmls") and fview and len(ops) == 3:
            f = "f" if bits == 32 else ""
            neg = "-" if m == "fmls" else ""
            return self.vec_result_keep(ops[0], [
                f"  _t.{fview}[{i}] = fma{f}({neg}"
                f"{self.vec_source(ops[1], i, fview)},"
                f" {self.vec_source(ops[2], i, fview)}, _t.{fview}[{i}]);"
                for i in range(lanes)], clear_top=lanes * bits == 64)

        if m in ("mla", "mls") and len(ops) == 3:
            c = "+" if m == "mla" else "-"
            return self.vec_result_keep(ops[0], [
                f"  _t.{view}[{i}] = (uint{bits}_t)(_t.{view}[{i}] {c}"
                f" (uint{bits}_t)({self.vec_source(ops[1], i, view)} *"
                f" {self.vec_source(ops[2], i, view)}));"
                for i in range(lanes)], clear_top=lanes * bits == 64)

        # A window of `lanes` bytes taken from the two sources laid end to end.
        if m == "ext" and len(ops) == 4 and ops[3].type == a64.ARM64_OP_IMM:
            n = ops[3].imm
            return self.vec_result(ops[0], [
                f"  _t.u8[{i}] = " + (self.vec_elem(ops[1], n + i, "u8")
                                      if n + i < lanes else
                                      self.vec_elem(ops[2], n + i - lanes, "u8"))
                + ";" for i in range(lanes)])

        # Shift right and accumulate, rather than replace.
        if m in ("usra", "ssra") and len(ops) == 3 \
                and ops[2].type == a64.ARM64_OP_IMM:
            src_view = sview if m == "ssra" else view
            return self.vec_result_keep(ops[0], [
                f"  _t.{view}[{i}] = (uint{bits}_t)(_t.{view}[{i}] +"
                f" (uint{bits}_t)({self.vec_source(ops[1], i, src_view)} >>"
                f" {ops[2].imm}));" for i in range(lanes)],
                clear_top=lanes * bits == 64)

        # Widening multiply and its accumulating forms. All read one half of a
        # narrower source; the `2` spelling reads the top half.
        if m in ("umull", "umull2", "smull", "smull2", "umlal", "umlal2",
                 "smlal", "smlal2", "umlsl", "umlsl2", "smlsl", "smlsl2") \
                and len(ops) == 3:
            sinfo = self.vas_of(ops[1])
            if not sinfo:
                raise Unsupported(f"{m} source arrangement")
            slanes, s_view, sbits = sinfo
            signed = m.startswith("s")
            base = slanes - lanes if m.endswith("2") else 0
            src_view = self.signed_view(sbits) if signed else s_view
            cast = f"int{bits}_t" if signed else f"uint{bits}_t"
            product = [f"(uint{bits}_t)(({cast})"
                       f"({self.vec_elem(ops[1], base + i, src_view)}) *"
                       f" ({cast})({self.vec_source(ops[2], base + i, src_view)}))"
                       for i in range(lanes)]
            if "mul" in m:
                return self.vec_result(ops[0], [
                    f"  _t.{view}[{i}] = {product[i]};" for i in range(lanes)])
            c = "-" if "mlsl" in m else "+"
            return self.vec_result_keep(ops[0], [
                f"  _t.{view}[{i}] = (uint{bits}_t)(_t.{view}[{i}] {c}"
                f" {product[i]});" for i in range(lanes)],
                clear_top=lanes * bits == 64)

        # Widening add: both operands are halves of narrower registers.
        if m in ("uaddl", "uaddl2", "saddl", "saddl2", "usubl", "usubl2",
                 "ssubl", "ssubl2") and len(ops) == 3:
            sinfo = self.vas_of(ops[1])
            if not sinfo:
                raise Unsupported(f"{m} source arrangement")
            slanes, s_view, sbits = sinfo
            signed = m.startswith("s")
            base = slanes - lanes if m.endswith("2") else 0
            src_view = self.signed_view(sbits) if signed else s_view
            cast = f"int{bits}_t" if signed else f"uint{bits}_t"
            c = "-" if "sub" in m else "+"
            return self.vec_result(ops[0], [
                f"  _t.{view}[{i}] = (uint{bits}_t)(({cast})"
                f"({self.vec_elem(ops[1], base + i, src_view)}) {c} ({cast})"
                f"({self.vec_elem(ops[2], base + i, src_view)}));"
                for i in range(lanes)])

        # Narrowing shift: `shrn` fills the low half, `shrn2` the high half.
        if m in ("shrn", "shrn2", "rshrn", "rshrn2") and len(ops) == 3 \
                and ops[2].type == a64.ARM64_OP_IMM:
            sinfo = self.vas_of(ops[1])
            if not sinfo:
                raise Unsupported(f"{m} source arrangement")
            slanes, s_view, sbits = sinfo
            n = ops[2].imm
            # The rounding form adds half a unit of the last bit shifted out.
            rnd = f" + (UINT64_C(1) << {n - 1})" if m.startswith("r") and n else ""
            def narrowed(i):
                return (f"(uint{bits}_t)((uint{sbits}_t)("
                        f"{self.vec_elem(ops[1], i, s_view)}{rnd}) >> {n})")
            if m.endswith("2"):
                return self.vec_result_keep(ops[0], [
                    f"  _t.{view}[{lanes - slanes + i}] = {narrowed(i)};"
                    for i in range(slanes)])
            return self.vec_result(ops[0], [
                f"  _t.{view}[{i}] = {narrowed(i)};" for i in range(slanes)])

        # Absolute difference, and the accumulating form.
        if m in ("uabd", "sabd", "uaba", "saba") and len(ops) == 3:
            v = sview if m[0] == "s" else view
            def absdiff(i):
                a = self.vec_source(ops[1], i, v)
                b = self.vec_source(ops[2], i, v)
                return f"(uint{bits}_t)({a} > {b} ? {a} - {b} : {b} - {a})"
            # `uaba` accumulates, `uabd` replaces -- and they differ only in
            # the last letter, so this has to test the end of the name.
            if m.endswith("a"):
                return self.vec_result_keep(ops[0], [
                    f"  _t.{view}[{i}] = (uint{bits}_t)(_t.{view}[{i}] +"
                    f" {absdiff(i)});" for i in range(lanes)],
                    clear_top=lanes * bits == 64)
            return self.vec_result(ops[0], [
                f"  _t.{view}[{i}] = {absdiff(i)};" for i in range(lanes)])

        # Halving add, rounded or truncated. Computed a lane width up, so the
        # sum cannot wrap before it is halved.
        if m in ("uhadd", "urhadd", "shadd", "srhadd") and len(ops) == 3 \
                and bits < 64:
            signed = m[0] == "s"
            v = sview if signed else view
            wide = (f"int{bits * 2}_t" if signed else f"uint{bits * 2}_t")
            rnd = " + 1" if "rhadd" in m else ""
            return self.vec_result(ops[0], [
                f"  _t.{view}[{i}] = (uint{bits}_t)((({wide})"
                f"{self.vec_source(ops[1], i, v)} + ({wide})"
                f"{self.vec_source(ops[2], i, v)}{rnd}) >> 1);"
                for i in range(lanes)])

        sat = {"sqadd": "arc_sqadd", "sqsub": "arc_sqsub",
               "uqadd": "arc_uqadd", "uqsub": "arc_uqsub",
               "sqdmulh": "arc_sqdmulh", "sqrdmulh": "arc_sqrdmulh"}
        if m in sat and len(ops) == 3:
            if bits >= 64:
                raise Unsupported(f"{m} on 64-bit lanes")
            v = sview if m[0] == "s" else view
            return self.vec_result(ops[0], [
                f"  _t.{view}[{i}] = (uint{bits}_t){sat[m]}{bits}("
                f"{self.vec_source(ops[1], i, v)},"
                f" {self.vec_source(ops[2], i, v)});" for i in range(lanes)])

        # Signed source, unsigned narrower destination: anything negative
        # clamps to zero rather than wrapping to a large positive.
        if m in ("sqshrun", "sqshrun2", "sqxtun", "sqxtun2"):
            sinfo = self.vas_of(ops[1])
            if not sinfo:
                raise Unsupported(f"{m} source arrangement")
            slanes, _, sbits = sinfo
            n = (ops[2].imm if len(ops) > 2
                 and ops[2].type == a64.ARM64_OP_IMM else 0)
            hi = (1 << bits) - 1
            ssv = self.signed_view(sbits)

            def clamped(i):
                v = (f"((int{sbits}_t)({self.vec_elem(ops[1], i, ssv)})"
                     f" >> {n})")
                return (f"(uint{bits}_t)({v} < 0 ? 0 :"
                        f" {v} > {hi} ? {hi} : {v})")
            if m.endswith("2"):
                return self.vec_result_keep(ops[0], [
                    f"  _t.{view}[{lanes - slanes + i}] = {clamped(i)};"
                    for i in range(slanes)])
            return self.vec_result(ops[0], [
                f"  _t.{view}[{i}] = {clamped(i)};" for i in range(slanes)])

        # Permutes. Each names which elements of the two sources interleave:
        # `zip` takes one half of each, `uzp` takes alternate elements of the
        # pair laid end to end, `trn` takes matching even or odd positions.
        if m in ("zip1", "zip2", "uzp1", "uzp2", "trn1", "trn2") \
                and len(ops) == 3:
            half = lanes // 2
            body = []
            for i in range(lanes):
                if m.startswith("zip"):
                    base = half if m == "zip2" else 0
                    src = ops[1] if i % 2 == 0 else ops[2]
                    e = base + i // 2
                elif m.startswith("uzp"):
                    odd = 1 if m == "uzp2" else 0
                    src = ops[1] if i < half else ops[2]
                    e = 2 * (i if i < half else i - half) + odd
                else:
                    odd = 1 if m == "trn2" else 0
                    src = ops[1] if i % 2 == 0 else ops[2]
                    e = (i & ~1) + odd
                body.append(f"  _t.{view}[{i}] = {self.vec_elem(src, e, view)};")
            return self.vec_result(ops[0], body)

        minmax = {"umax": ">", "umin": "<", "smax": ">", "smin": "<"}
        if m in minmax and len(ops) == 3:
            v = sview if m[0] == "s" else view
            body = []
            for i in range(lanes):
                a = self.vec_source(ops[1], i, v)
                b = self.vec_source(ops[2], i, v)
                body.append(f"  _t.{view}[{i}] = (uint{bits}_t)("
                            f"{a} {minmax[m]} {b} ? {a} : {b});")
            return self.vec_result(ops[0], body)

        # Table lookup. The registers between the destination and the index
        # are the table, and they are consecutive by encoding.
        if m in ("tbl", "tbx") and len(ops) >= 3:
            table, index = ops[1:-1], ops[-1]
            first, n = self.vreg_index(table[0]), len(table)
            body = []
            for i in range(lanes):
                e = self.vec_source(index, i, "u8")
                if m == "tbl":
                    body.append(f"  _t.u8[{i}] = arc_tbl(c, {first}, {n}, {e});")
                else:
                    body.append(f"  {{ const uint8_t _i = {e};")
                    body.append(f"    if (_i < {n * 16}) _t.u8[{i}] ="
                                f" arc_tbl(c, {first}, {n}, _i); }}")
            if m == "tbl":
                return self.vec_result(ops[0], body)
            return self.vec_result_keep(ops[0], body,
                                        clear_top=lanes * bits == 64)

        if m == "abs":
            return self.vec_result(ops[0], [
                f"  {{ int{bits}_t _v = {self.vec_source(ops[1], i, sview)};"
                f" _t.{view}[{i}] = (uint{bits}_t)(_v < 0 ? -_v : _v); }}"
                for i in range(lanes)])

        # Reverse the elements inside each container. The number in the name is
        # the container's width, not the element's -- `rev64 v0.8b` reverses
        # eight bytes within each 64-bit half.
        if m in ("rev64", "rev32", "rev16") and len(ops) == 2:
            container = int(m[3:])
            per = container // bits
            if per < 2:
                raise Unsupported(f"{m} on {bits}-bit lanes")
            body = []
            for i in range(lanes):
                group, pos = divmod(i, per)
                src = group * per + (per - 1 - pos)
                body.append(f"  _t.{view}[{i}] ="
                            f" {self.vec_elem(ops[1], src, view)};")
            return self.vec_result(ops[0], body)

        # Shift left long: widen to the destination's lane and shift by the
        # source's element width, which is the only shift this instruction has.
        if m in ("shll", "shll2") and len(ops) == 3:
            sinfo = self.vas_of(ops[1])
            if not sinfo:
                raise Unsupported(f"{m} source arrangement")
            slanes, s_view, sbits = sinfo
            base = slanes - lanes if m.endswith("2") else 0
            return self.vec_result(ops[0], [
                f"  _t.{view}[{i}] = (uint{bits}_t)"
                f"({self.vec_elem(ops[1], base + i, s_view)}) << {sbits};"
                for i in range(lanes)])

        # Widening absolute difference: both operands are halves of narrower
        # registers, and the result cannot overflow the wider lane.
        if m in ("uabdl", "uabdl2", "sabdl", "sabdl2") and len(ops) == 3:
            sinfo = self.vas_of(ops[1])
            if not sinfo:
                raise Unsupported(f"{m} source arrangement")
            slanes, s_view, sbits = sinfo
            signed = m.startswith("s")
            base = slanes - lanes if m.endswith("2") else 0
            src_view = self.signed_view(sbits) if signed else s_view
            cast = f"int{bits}_t" if signed else f"uint{bits}_t"
            body = []
            for i in range(lanes):
                a = f"({cast})({self.vec_elem(ops[1], base + i, src_view)})"
                b = f"({cast})({self.vec_elem(ops[2], base + i, src_view)})"
                body.append(f"  _t.{view}[{i}] = (uint{bits}_t)"
                            f"({a} > {b} ? {a} - {b} : {b} - {a});")
            return self.vec_result(ops[0], body)

        # Signed saturating shift right, narrowing. The destination is signed
        # here, unlike `sqshrun` where it is not.
        if m in ("sqshrn", "sqshrn2") and len(ops) == 3 \
                and ops[2].type == a64.ARM64_OP_IMM:
            sinfo = self.vas_of(ops[1])
            if not sinfo:
                raise Unsupported(f"{m} source arrangement")
            slanes, _, sbits = sinfo
            n = ops[2].imm
            lo, hi = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
            ssv = self.signed_view(sbits)

            def clamp(i):
                v = (f"((int{sbits}_t)({self.vec_elem(ops[1], i, ssv)})"
                     f" >> {n})")
                return (f"(uint{bits}_t)(int{bits}_t)({v} < {lo} ? {lo} :"
                        f" {v} > {hi} ? {hi} : {v})")
            if m.endswith("2"):
                return self.vec_result_keep(ops[0], [
                    f"  _t.{view}[{lanes - slanes + i}] = {clamp(i)};"
                    for i in range(slanes)])
            return self.vec_result(ops[0], [
                f"  _t.{view}[{i}] = {clamp(i)};" for i in range(slanes)])

        # The immediate forms, which take two operands rather than three and
        # read the destination as well as writing it.
        if m in ("bic", "orr") and len(ops) == 2 \
                and ops[1].type == a64.ARM64_OP_IMM:
            value = ops[1].imm
            if ops[1].shift.type == a64.ARM64_SFT_LSL and ops[1].shift.value:
                value <<= ops[1].shift.value
            value &= (1 << bits) - 1
            if m == "bic":
                value = (~value) & ((1 << bits) - 1)
            c = "&" if m == "bic" else "|"
            return self.vec_result_keep(ops[0], [
                f"  _t.{view}[{i}] = (uint{bits}_t)(_t.{view}[{i}] {c}"
                f" UINT64_C({value}));" for i in range(lanes)],
                clear_top=lanes * bits == 64)

        # Floating-point width conversion. `l` widens the low half (or the top
        # half, for the `2` form); `n` narrows into the low half, and `n2`
        # fills the high half without disturbing the low one.
        if m in ("fcvtl", "fcvtl2", "fcvtn", "fcvtn2") and len(ops) == 2:
            sinfo = self.vas_of(ops[1])
            if not sinfo:
                raise Unsupported(f"{m} source arrangement")
            slanes, _, sbits = sinfo
            src_f = {32: "f32", 64: "f64"}.get(sbits)
            if not src_f or not fview:
                raise Unsupported(f"{m} between {sbits} and {bits}")
            ctype = "float" if bits == 32 else "double"
            if m.startswith("fcvtl"):
                base = slanes - lanes if m.endswith("2") else 0
                return self.vec_result(ops[0], [
                    f"  _t.{fview}[{i}] = ({ctype})"
                    f"{self.vec_elem(ops[1], base + i, src_f)};"
                    for i in range(lanes)])
            if m.endswith("2"):
                return self.vec_result_keep(ops[0], [
                    f"  _t.{fview}[{lanes - slanes + i}] = ({ctype})"
                    f"{self.vec_elem(ops[1], i, src_f)};"
                    for i in range(slanes)])
            return self.vec_result(ops[0], [
                f"  _t.{fview}[{i}] = ({ctype})"
                f"{self.vec_elem(ops[1], i, src_f)};" for i in range(slanes)])

        # Pairwise add across two vectors: the destination's first half comes
        # from adjacent pairs of the first source, the second half from the
        # second source.
        if m in ("addp", "faddp") and len(ops) == 3:
            half = lanes // 2
            body = []
            for i in range(lanes):
                src = ops[1] if i < half else ops[2]
                j = (i if i < half else i - half) * 2
                if m == "faddp":
                    if not fview:
                        raise Unsupported(f"{m} on {bits}-bit lanes")
                    body.append(
                        f"  _t.{fview}[{i}] = arc_fadd{bits}("
                        f"{self.vec_elem(src, j, fview)},"
                        f" {self.vec_elem(src, j + 1, fview)});")
                else:
                    body.append(
                        f"  _t.{view}[{i}] = (uint{bits}_t)("
                        f"{self.vec_elem(src, j, view)} +"
                        f" {self.vec_elem(src, j + 1, view)});")
            return self.vec_result(ops[0], body)

        raise Unsupported(f"vector {m}")

    # --- instruction emitters ----------------------------------------------

    def emit(self, insn, func_start: int, func_end: int,
             labels: set[int]) -> list[str]:
        """Lift one instruction, or raise Unsupported.

        Every emitter below assumes the operand shape its mnemonic usually
        has. Vector and scalar forms share mnemonics on this architecture --
        `bic` takes three operands as a scalar and two as a NEON op -- so an
        emitter meeting the wrong shape indexes off the end. That is an
        unsupported form, not a crash, and catching it in one place here keeps
        every emitter free of defensive operand counting.
        """
        try:
            return self._emit(insn, func_start, func_end, labels)
        except Unsupported:
            raise
        except (IndexError, KeyError, AttributeError, ValueError) as e:
            raise Unsupported(f"{insn.mnemonic} operand shape ({type(e).__name__})")

    def _emit(self, insn, func_start: int, func_end: int,
              labels: set[int]) -> list[str]:
        m = insn.mnemonic
        ops = insn.operands
        out: list[str] = []

        # `mov`, `add`, `orr` and `fmul` each name both a scalar and a vector
        # instruction; the operands decide which. Vector forms are split off
        # here, before any scalar emitter gets a chance at them.
        if any(self.is_vector(o) for o in ops):
            return self.emit_vector(insn, ops)

        def arith(op_c: str, set_flags: bool, sub: bool = False):
            d, a, b = ops[0], ops[1], ops[2] if len(ops) > 2 else None
            is64 = self.dest_is64(d)
            w = "64" if is64 else "32"
            rhs = self.read(b) if b is not None else self.read(a)
            lhs = self.read(a) if b is not None else "0"
            if set_flags:
                fn = f"arc_sub{w}" if sub else f"arc_add{w}"
                args = f"c, {lhs}, {rhs}" if sub else f"c, {lhs}, {rhs}, 0"
                return [self.write(d, f"{fn}({args})")]
            return [self.write(d, f"({lhs} {op_c} {rhs})")]

        def compare(sub: bool):
            a, b = ops[0], ops[1]
            is64 = reg_of(self.md, a.reg)[1] if a.type == a64.ARM64_OP_REG else True
            w = "64" if is64 else "32"
            fn = f"arc_sub{w}" if sub else f"arc_add{w}"
            args = (f"c, {self.read(a)}, {self.read(b)}" if sub
                    else f"c, {self.read(a)}, {self.read(b)}, 0")
            return [f"(void){fn}({args});"]

        def logical(op_c: str, set_flags: bool, invert_rhs: bool = False):
            d, a, b = ops[0], ops[1], ops[2]
            is64 = self.dest_is64(d)
            rhs = self.read(b)
            if invert_rhs:
                rhs = f"(~{rhs})"
            expr = f"({self.read(a)} {op_c} {rhs})"
            if set_flags:
                w = "64" if is64 else "32"
                cast = "uint64_t" if is64 else "uint32_t"
                out_ = [f"{{ {cast} _r = ({cast}){expr};",
                        f"  arc_flags_logical{w}(c, _r);",
                        f"  {self.write(d, '_r')} }}"]
                return out_
            return [self.write(d, expr)]

        def branch_target(op) -> int:
            if op.type != a64.ARM64_OP_IMM:
                raise Unsupported("indirect branch as immediate")
            return op.imm

        # -- moves
        if m in ("mov", "movz"):
            return [self.write(ops[0], self.read(ops[1]))]
        if m == "movn":
            d = ops[0]
            width = "uint64_t" if self.dest_is64(d) else "uint32_t"
            return [self.write(d, f"(~({width})({self.read(ops[1])}))")]
        if m == "movk":
            d = ops[0]
            shift = ops[1].shift.value if ops[1].shift.value else 0
            keep = ~(0xFFFF << shift) & 0xFFFFFFFFFFFFFFFF
            idx, is64, _ = reg_of(self.md, d.reg)
            cur = f"ARC_X_R(c, {idx})" if is64 else f"ARC_W_R(c, {idx})"
            val = (ops[1].imm & 0xFFFF) << shift
            return [self.write(d, f"(({cur} & UINT64_C({keep})) | UINT64_C({val}))")]
        if m == "mvn":
            d = ops[0]
            width = "uint64_t" if self.dest_is64(d) else "uint32_t"
            return [self.write(d, f"(~({width})({self.read(ops[1])}))")]
        if m == "neg":
            d = ops[0]
            width = "uint64_t" if self.dest_is64(d) else "uint32_t"
            return [self.write(d, f"(({width})0 - ({width})({self.read(ops[1])}))")]

        # -- arithmetic
        if m == "add":  return arith("+", False)
        if m == "adds": return arith("+", True)
        if m == "sub":  return arith("-", False)
        if m == "subs": return arith("-", True, sub=True)
        if m in ("adc", "adcs", "sbc", "sbcs"):
            d, a, b = ops[0], ops[1], ops[2]
            is64 = self.dest_is64(d)
            w = "64" if is64 else "32"
            cast = "uint64_t" if is64 else "uint32_t"
            rhs = self.read(b)
            if m.startswith("sbc"):
                rhs = f"(({cast})~({cast})({rhs}))"
            if m.endswith("s"):
                return [self.write(
                    d, f"arc_add{w}(c, {self.read(a)}, {rhs}, (c)->cf)")]
            return [self.write(
                d, f"(({cast})({self.read(a)}) + ({cast})({rhs}) + (c)->cf)")]
        if m in ("negs", "ngcs"):
            d, src = ops[0], ops[1]
            is64 = self.dest_is64(d)
            w = "64" if is64 else "32"
            if m == "negs":
                return [self.write(d, f"arc_sub{w}(c, 0, {self.read(src)})")]
            cast = "uint64_t" if is64 else "uint32_t"
            return [self.write(
                d, f"arc_add{w}(c, 0, (({cast})~({cast})({self.read(src)})),"
                   f" (c)->cf)")]
        if m == "cmp":  return compare(sub=True)
        if m == "cmn":  return compare(sub=False)

        # -- logical
        if m == "and":  return logical("&", False)
        if m == "ands": return logical("&", True)
        if m == "bics": return logical("&", True, invert_rhs=True)
        if m == "orr":  return logical("|", False)
        if m == "eor":  return logical("^", False)
        if m == "bic":  return logical("&", False, invert_rhs=True)
        if m == "orn":  return logical("|", False, invert_rhs=True)
        if m == "mneg":
            cast = "uint64_t" if self.dest_is64(ops[0]) else "uint32_t"
            return [self.write(ops[0],
                               f"(({cast})0 - (({cast})({self.read(ops[1])})"
                               f" * ({cast})({self.read(ops[2])})))")]
        if m == "tst":
            a, b = ops[0], ops[1]
            is64 = reg_of(self.md, a.reg)[1]
            w = "64" if is64 else "32"
            cast = "uint64_t" if is64 else "uint32_t"
            return [f"arc_flags_logical{w}(c, ({cast})({self.read(a)} & {self.read(b)}));"]

        # -- shifts
        if m in ("lsl", "lsr", "asr", "ror"):
            d, a, b = ops[0], ops[1], ops[2]
            is64 = self.dest_is64(d)
            cast = "uint64_t" if is64 else "uint32_t"
            signed = "int64_t" if is64 else "int32_t"
            mask = 63 if is64 else 31
            amount = f"(({self.read(b)}) & {mask})"
            if m == "lsl":
                expr = f"(({cast})({self.read(a)}) << {amount})"
            elif m == "lsr":
                expr = f"(({cast})({self.read(a)}) >> {amount})"
            elif m == "asr":
                expr = f"(({cast})(({signed})({self.read(a)}) >> {amount}))"
            else:
                expr = f"arc_ror{'64' if is64 else '32'}({self.read(a)}, {amount})"
            return [self.write(d, expr)]

        # -- multiply and divide
        if m in ("mul", "madd", "msub"):
            d = ops[0]
            cast = "uint64_t" if self.dest_is64(d) else "uint32_t"
            prod = f"(({cast})({self.read(ops[1])}) * ({cast})({self.read(ops[2])}))"
            if m == "mul":
                return [self.write(d, prod)]
            acc = self.read(ops[3])
            sign = "+" if m == "madd" else "-"
            return [self.write(d, f"(({cast})({acc}) {sign} {prod})")]
        if m in ("sdiv", "udiv"):
            d = ops[0]
            is64 = self.dest_is64(d)
            cast = ("int64_t" if is64 else "int32_t") if m == "sdiv" else (
                "uint64_t" if is64 else "uint32_t")
            a, b = self.read(ops[1]), self.read(ops[2])
            # ARM defines division by zero as producing zero, not a trap.
            return [self.write(d, f"(({cast})({b}) == 0 ? 0 : "
                                  f"(({cast})({a}) / ({cast})({b})))")]

        # -- sign and zero extension
        ext_map = {"sxtb": ("int8_t", True), "sxth": ("int16_t", True),
                   "sxtw": ("int32_t", True), "uxtb": ("uint8_t", False),
                   "uxth": ("uint16_t", False)}
        if m in ext_map:
            src_t, signed = ext_map[m]
            d = ops[0]
            outer = ("(int64_t)" if self.dest_is64(d) else "(int32_t)") if signed else ""
            return [self.write(d, f"({outer}({src_t})({self.read(ops[1])}))")]

        # -- conditional select
        if m in ("csel", "csinc", "csinv", "csneg", "cset", "csetm", "cinc"):
            d = ops[0]
            cond = COND_INDEX.get(insn.cc_str if hasattr(insn, "cc_str") else "", None)
            cond = self.cond_of(insn)
            cast = "uint64_t" if self.dest_is64(d) else "uint32_t"
            if m == "cset":
                return [self.write(d, f"(ARC_COND(c, {cond}) ? 1 : 0)")]
            if m == "csetm":
                return [self.write(d, f"(ARC_COND(c, {cond}) ? ({cast})~({cast})0 : 0)")]
            if m == "cinc":
                a = self.read(ops[1])
                return [self.write(d, f"(ARC_COND(c, {cond}) ? ({a}) + 1 : ({a}))")]
            a, b = self.read(ops[1]), self.read(ops[2])
            alt = {"csel": b, "csinc": f"(({b}) + 1)", "csinv": f"(~({cast})({b}))",
                   "csneg": f"(({cast})0 - ({cast})({b}))"}[m]
            return [self.write(d, f"(ARC_COND(c, {cond}) ? ({a}) : {alt})")]

        # -- addressing
        if m == "adr":
            return [self.write(ops[0],
                               f"({self.base_expr()} + UINT64_C({ops[1].imm}))")]
        if m == "adrp":
            return [self.write(ops[0], f"({self.base_expr()} + "
                                       f"UINT64_C({ops[1].imm & ~0xFFF}))")]

        # -- loads and stores
        ld = {"ldr": (None, 8), "ldrb": ("uint8_t", 1), "ldrh": ("uint16_t", 2),
              "ldrsb": ("int8_t", 1), "ldrsh": ("int16_t", 2), "ldrsw": ("int32_t", 4),
              "ldur": (None, 8), "ldurb": ("uint8_t", 1), "ldurh": ("uint16_t", 2)}
        st = {"str": (None, 8), "strb": ("uint8_t", 1), "strh": ("uint16_t", 2),
              "stur": (None, 8), "sturb": ("uint8_t", 1), "sturh": ("uint16_t", 2)}
        if m in ld:
            return self.emit_load(insn, ops, ld[m][0])
        if m in st:
            return self.emit_store(insn, ops, st[m][0])
        if m in ("ldp", "stp"):
            return self.emit_pair(insn, ops, m == "ldp")

        # -- control flow
        if m == "b":
            t = branch_target(ops[0])
            if func_start <= t < func_end:
                return [f"goto L_{t:x};"]
            return [f"{self.fn_name(t)}(c); return;"]
        if m.startswith("b.") and m[2:] in COND_INDEX:
            t = branch_target(ops[0])
            cond = COND_INDEX[m[2:]]
            body = (f"goto L_{t:x};" if func_start <= t < func_end
                    else f"{{ {self.fn_name(t)}(c); return; }}")
            return [f"if (ARC_COND(c, {cond})) {body}"]
        if m in ("cbz", "cbnz"):
            t = branch_target(ops[1])
            test = "==" if m == "cbz" else "!="
            body = (f"goto L_{t:x};" if func_start <= t < func_end
                    else f"{{ {self.fn_name(t)}(c); return; }}")
            return [f"if (({self.read(ops[0])}) {test} 0) {body}"]
        if m in ("tbz", "tbnz"):
            t = branch_target(ops[2])
            test = "==" if m == "tbz" else "!="
            bit = ops[1].imm
            body = (f"goto L_{t:x};" if func_start <= t < func_end
                    else f"{{ {self.fn_name(t)}(c); return; }}")
            return [f"if ((({self.read(ops[0])}) >> {bit} & 1) {test} 0) {body}"]
        if m == "bl":
            t = branch_target(ops[0])
            return [f"ARC_X_W(c, 30, {self.base_expr()} + "
                    f"UINT64_C({insn.address + 4}));",
                    f"{self.fn_name(t)}(c);"]
        if m == "blr":
            return [f"ARC_X_W(c, 30, {self.base_expr()} + "
                    f"UINT64_C({insn.address + 4}));",
                    f"arc_dispatch(c, {self.read(ops[0])});"]
        if m == "br":
            targets = self.cur_tables.get(insn.address)
            if targets:
                # A switch: the branch stays inside this function, so it is a
                # jump and not a call. The dispatcher is still the fallback,
                # because the table's length was inferred rather than read.
                seen, lines = set(), [
                    f"switch ({self.read(ops[0])} - {self.base_expr()}) {{"]
                for t in targets:
                    if t in seen:
                        continue
                    seen.add(t)
                    lines.append(f"  case UINT64_C({t}): goto L_{t:x};")
                lines.append("  default: break;")
                lines.append("}")
                lines.append(f"arc_dispatch(c, {self.read(ops[0])}); return;")
                return lines
            return [f"arc_dispatch(c, {self.read(ops[0])}); return;"]
        if m in ("ret", "retaa", "retab"):
            return ["return;"]
        if m in ("nop", "bti", "hint", "dmb", "dsb", "isb", "prfm", "prfum",
                 "clrex", "sevl", "sev", "wfe", "wfi", "yield"):
            return [f"/* {m}: no architectural effect here */"]

        # Pointer authentication. libc++ is commonly built with -mbranch-
        # protection, so every non-leaf function signs the return address on
        # entry and authenticates it on exit -- two instructions that between
        # them accounted for nearly every function in it failing to lift.
        #
        # They are identity operations for a lifted program. Signing defends a
        # return address held in memory an attacker might corrupt; ours lives
        # in the context, there is no key, and a lifted `ret` returns from a C
        # function rather than branching to x30. Making both no-ops keeps x30
        # consistent from entry to exit, which is what the pair guarantees on
        # hardware.
        if m.startswith(("pac", "aut", "xpac")):
            return [f"/* {m}: pointer authentication is identity when lifted */"]
        if m == "brk":
            return ["arc_trap(c, \"brk\");"]

        # -- floating point
        # Scalar FP maps onto C's own float and double, which is the whole
        # reason to keep the register file as a union: the arithmetic is the
        # host's, and only the corner cases need spelling out.
        if m in ("fadd", "fsub", "fmul", "fdiv"):
            w = "32" if self.fp_kind(ops[0]) == "s" else "64"
            return [self.fp_write(
                ops[0],
                f"arc_{m}{w}({self.fp_read(ops[1])}, {self.fp_read(ops[2])})")]
        # Negated multiply: one instruction, and the negation is of the
        # product rather than of either operand.
        if m == "fnmul":
            w = "32" if self.fp_kind(ops[0]) == "s" else "64"
            return [self.fp_write(
                ops[0], f"(-arc_fmul{w}({self.fp_read(ops[1])},"
                        f" {self.fp_read(ops[2])}))")]
        if m == "fneg":
            return [self.fp_write(ops[0], f"(-({self.fp_read(ops[1])}))")]
        if m == "fabs":
            f = "f" if self.fp_kind(ops[0]) == "s" else ""
            return [self.fp_write(ops[0], f"fabs{f}({self.fp_read(ops[1])})")]
        if m == "fsqrt":
            w = "32" if self.fp_kind(ops[0]) == "s" else "64"
            return [self.fp_write(ops[0],
                                  f"arc_fsqrt{w}({self.fp_read(ops[1])})")]
        rint = {"frinta": "round", "frintm": "floor", "frintp": "ceil",
                "frintz": "trunc", "frintn": "nearbyint", "frintx": "rint",
                "frinti": "rint"}
        if m in rint:
            f = "f" if self.fp_kind(ops[0]) == "s" else ""
            return [self.fp_write(ops[0],
                                  f"{rint[m]}{f}({self.fp_read(ops[1])})")]
        if m in ("fmax", "fmin", "fmaxnm", "fminnm"):
            w = "32" if self.fp_kind(ops[0]) == "s" else "64"
            return [self.fp_write(
                ops[0],
                f"arc_{m}{w}({self.fp_read(ops[1])}, {self.fp_read(ops[2])})")]
        if m in ("fcmp", "fcmpe"):
            b = ("0.0" if ops[1].type == a64.ARM64_OP_FP
                 else self.fp_read(ops[1]))
            return [f"arc_fcmp(c, (double)({self.fp_read(ops[0])}), "
                    f"(double)({b}));"]
        if m == "fcvt":
            return [self.fp_write(ops[0], self.fp_read(ops[1]))]
        if m == "fcsel":
            cond = self.cond_of(insn)
            return [self.fp_write(ops[0],
                                  f"(ARC_COND(c, {cond}) ? {self.fp_read(ops[1])}"
                                  f" : {self.fp_read(ops[2])})")]
        if m in ("fmadd", "fmsub", "fnmadd", "fnmsub"):
            # These are *fused*: one rounding, not two. Writing them as a * b + c
            # rounds twice and disagrees with the hardware in the last bit, which
            # the oracle notices even though a reading of the code would not.
            f = "f" if self.fp_kind(ops[0]) == "s" else ""
            a, b, acc = (self.fp_read(ops[1]), self.fp_read(ops[2]),
                         self.fp_read(ops[3]))
            expr = {
                "fmadd": f"fma{f}({a}, {b}, {acc})",
                "fmsub": f"fma{f}(-({a}), {b}, {acc})",
                "fnmadd": f"(-fma{f}({a}, {b}, {acc}))",
                "fnmsub": f"fma{f}({a}, {b}, -({acc}))",
            }[m]
            return [self.fp_write(ops[0], expr)]

        if m in ("scvtf", "ucvtf"):
            if self.fp_of(ops[1]) is not None:
                # Source is an FP register holding an integer bit pattern.
                sidx, skind = self.fp_of(ops[1])
                bits = 32 if skind == "s" else 64
                cast = ("int" if m == "scvtf" else "uint") + str(bits) + "_t"
                raw = f"ARC_SU_R(c, {sidx})" if skind == "s" else f"ARC_DU_R(c, {sidx})"
                return [self.fp_write(ops[0], f"(({cast})({raw}))")]
            idx, is64, _ = reg_of(self.md, ops[1].reg)
            signed = m == "scvtf"
            cast = (("int64_t" if is64 else "int32_t") if signed
                    else ("uint64_t" if is64 else "uint32_t"))
            val = f"ARC_X_R(c, {idx})" if is64 else f"ARC_W_R(c, {idx})"
            expr = f"(({cast})({val}))"
            if len(ops) > 2:  # fixed-point form: the result is scaled down
                expr = f"({expr} / (double)(UINT64_C(1) << {ops[2].imm}))"
            return [self.fp_write(ops[0], expr)]

        cvt_round = {"fcvtzs": ("", True), "fcvtzu": ("", False),
                     "fcvtas": ("round", True), "fcvtau": ("round", False),
                     "fcvtms": ("floor", True), "fcvtmu": ("floor", False),
                     "fcvtps": ("ceil", True), "fcvtpu": ("ceil", False),
                     "fcvtns": ("nearbyint", True), "fcvtnu": ("nearbyint", False)}
        if m in cvt_round:
            rounder, signed = cvt_round[m]
            if self.fp_of(ops[0]) is not None:
                # Destination is an FP register receiving an integer.
                didx, dkind = self.fp_of(ops[0])
                bits = 32 if dkind == "s" else 64
                expr = self.fp_read(ops[1])
                if rounder:
                    expr = f"{rounder}((double)({expr}))"
                fn = (f"arc_f2i{bits}" if signed else f"arc_f2u{bits}")
                setter = "arc_su_w" if dkind == "s" else "arc_du_w"
                return [f"{setter}(c, {didx}, {fn}((double)({expr})));"]
            idx, is64, _ = reg_of(self.md, ops[0].reg)
            expr = self.fp_read(ops[1])
            if len(ops) > 2:
                expr = f"({expr} * (double)(UINT64_C(1) << {ops[2].imm}))"
            if rounder:
                expr = f"{rounder}((double)({expr}))"
            fn = (("arc_f2i64" if is64 else "arc_f2i32") if signed
                  else ("arc_f2u64" if is64 else "arc_f2u32"))
            return [self.write(ops[0], f"{fn}((double)({expr}))")]

        if m == "fmov":
            d, src = ops[0], ops[1]
            if src.type == a64.ARM64_OP_FP:
                return [self.fp_write(d, repr(float(src.fp)))]
            d_fp, s_fp = self.fp_of(d), self.fp_of(src)
            # fmov moves *bits*, never values -- `fmov x0, d0` hands over the
            # encoding, not the number. Converting here would be silently wrong.
            if d_fp and s_fp:
                return [self.fp_bits_write(d, self.fp_bits_read(src))]
            if d_fp:
                return [self.fp_bits_write(d, self.read(src))]
            if s_fp:
                return [self.write(d, self.fp_bits_read(src))]
            raise Unsupported("fmov shape")

        if m in ("movi", "mvni"):
            info = self.fp_of(ops[0])
            imm = ops[1]
            if not info or imm.type != a64.ARM64_OP_IMM:
                raise Unsupported(f"{m} shape")
            idx, kind = info
            value = imm.imm & 0xFFFFFFFFFFFFFFFF
            if imm.shift.type == a64.ARM64_SFT_LSL and imm.shift.value:
                value = (value << imm.shift.value) & 0xFFFFFFFFFFFFFFFF
            if m == "mvni":
                value = (~value) & 0xFFFFFFFFFFFFFFFF
            if value == 0:
                return [f"arc_v_clear(c, {idx});"]
            if kind == "d":
                return [f"arc_du_w(c, {idx}, UINT64_C({value}));"]
            if kind == "s":
                return [f"arc_su_w(c, {idx}, UINT32_C({value & 0xFFFFFFFF}));"]
            raise Unsupported(f"{m} into {kind}")

        # -- acquire / release
        # Plain accesses plus the ordering the host already gives us: lifted
        # code runs on real threads, so a C11-visible barrier is what these
        # need, not a model of the guest's memory system.
        acq = {"ldar": None, "ldarb": "uint8_t", "ldarh": "uint16_t"}
        rel = {"stlr": None, "stlrb": "uint8_t", "stlrh": "uint16_t"}
        if m in acq:
            return self.emit_load(insn, ops, acq[m])
        if m in rel:
            return self.emit_store(insn, ops, rel[m])

        # -- exclusives
        ldx = {"ldxr": 0, "ldaxr": 0, "ldxrb": 1, "ldaxrb": 1,
               "ldxrh": 2, "ldaxrh": 2}
        stx = {"stxr": 0, "stlxr": 0, "stxrb": 1, "stlxrb": 1,
               "stxrh": 2, "stlxrh": 2}
        if m in ldx:
            d, mem = ops[0], self.find_mem(ops)
            if mem is None:
                raise Unsupported("exclusive addressing")
            size = ldx[m] or (8 if reg_of(self.md, d.reg)[1] else 4)
            addr = self.mem_address(mem, insn)
            return [self.write(d, f"arc_load_exclusive(c, {addr}, {size})")]
        if m in stx:
            status, val, mem = ops[0], ops[1], self.find_mem(ops)
            if mem is None:
                raise Unsupported("exclusive addressing")
            size = stx[m] or (8 if reg_of(self.md, val.reg)[1] else 4)
            addr = self.mem_address(mem, insn)
            return [self.write(
                status,
                f"arc_store_exclusive(c, {addr}, {self.read(val)}, {size})")]

        # -- bitfield
        # Capstone hands these over as (dest, source, lsb, width), which is the
        # assembler's spelling rather than the encoding's.
        if m in ("ubfx", "sbfx", "ubfiz", "sbfiz", "bfi", "bfxil"):
            d, src = ops[0], ops[1]
            lsb, width = ops[2].imm, ops[3].imm
            is64 = self.dest_is64(d)
            cast = "uint64_t" if is64 else "uint32_t"
            signed = "int64_t" if is64 else "int32_t"
            bits = 64 if is64 else 32
            mask = (1 << width) - 1
            val = self.read(src)
            if m in ("ubfx", "sbfx"):
                expr = f"((({cast})({val}) >> {lsb}) & UINT64_C({mask}))"
                if m == "sbfx":
                    expr = f"arc_sext{bits}({expr}, {width})"
                return [self.write(d, expr)]
            if m in ("ubfiz", "sbfiz"):
                field = f"((({cast})({val})) & UINT64_C({mask}))"
                if m == "sbfiz":
                    field = f"arc_sext{bits}({field}, {width})"
                return [self.write(d, f"(({cast})({field}) << {lsb})")]
            didx, _, _ = reg_of(self.md, d.reg)
            cur = f"ARC_X_R(c, {didx})" if is64 else f"ARC_W_R(c, {didx})"
            if m == "bfi":
                keep = ~(mask << lsb) & ((1 << bits) - 1)
                ins = f"(((({cast})({val})) & UINT64_C({mask})) << {lsb})"
                return [self.write(d, f"((({cast})({cur}) & UINT64_C({keep})) | {ins})")]
            # bfxil: take the field from the source, keep the rest of dest
            keep = ~mask & ((1 << bits) - 1)
            ins = f"(((({cast})({val})) >> {lsb}) & UINT64_C({mask}))"
            return [self.write(d, f"((({cast})({cur}) & UINT64_C({keep})) | {ins})")]

        # -- widening and high multiplies
        long_mul = {"smull": ("int64_t", "int32_t", None),
                    "umull": ("uint64_t", "uint32_t", None),
                    "smaddl": ("int64_t", "int32_t", "+"),
                    "umaddl": ("uint64_t", "uint32_t", "+"),
                    "smsubl": ("int64_t", "int32_t", "-"),
                    "umsubl": ("uint64_t", "uint32_t", "-")}
        if m in long_mul:
            wide, narrow, acc_op = long_mul[m]
            a = f"(({wide})({narrow})({self.read(ops[1])}))"
            b = f"(({wide})({narrow})({self.read(ops[2])}))"
            prod = f"({a} * {b})"
            if acc_op:
                prod = f"((({wide})({self.read(ops[3])})) {acc_op} {prod})"
            return [self.write(ops[0], prod)]
        if m in ("smulh", "umulh"):
            fn = "arc_smulh" if m == "smulh" else "arc_umulh"
            return [self.write(ops[0],
                               f"{fn}({self.read(ops[1])}, {self.read(ops[2])})")]

        # -- conditional negate / invert / compare
        if m in ("cneg", "cinv"):
            cond = self.cond_of(insn)
            d = ops[0]
            cast = "uint64_t" if self.dest_is64(d) else "uint32_t"
            v = self.read(ops[1])
            alt = f"(({cast})0 - ({cast})({v}))" if m == "cneg" else f"(~({cast})({v}))"
            return [self.write(d, f"(ARC_COND(c, {cond}) ? {alt} : ({v}))")]
        if m in ("ccmp", "ccmn"):
            # When the condition does not hold, the flags are *assigned* the
            # immediate rather than computed -- that is the whole point of the
            # instruction, and it is easy to read past.
            cond = self.cond_of(insn)
            a, b, nzcv = ops[0], ops[1], ops[2].imm
            is64 = reg_of(self.md, a.reg)[1]
            w = "64" if is64 else "32"
            fn = f"arc_sub{w}" if m == "ccmp" else f"arc_add{w}"
            args = (f"c, {self.read(a)}, {self.read(b)}" if m == "ccmp"
                    else f"c, {self.read(a)}, {self.read(b)}, 0")
            return [f"if (ARC_COND(c, {cond})) {{ (void){fn}({args}); }}",
                    f"else {{ (c)->nf = {(nzcv >> 3) & 1}; (c)->zf = {(nzcv >> 2) & 1};",
                    f"        (c)->cf = {(nzcv >> 1) & 1}; (c)->vf = {nzcv & 1}; }}"]

        # -- bit twiddling
        if m == "extr":
            d = ops[0]
            is64 = self.dest_is64(d)
            cast = "uint64_t" if is64 else "uint32_t"
            bits = 64 if is64 else 32
            lsb = ops[3].imm
            hi, lo = self.read(ops[1]), self.read(ops[2])
            if lsb == 0:
                return [self.write(d, f"(({cast})({lo}))")]
            return [self.write(d, f"((({cast})({lo}) >> {lsb}) | "
                                  f"(({cast})({hi}) << {bits - lsb}))")]
        if m in ("clz", "rbit", "rev", "rev16", "rev32"):
            d = ops[0]
            w = "64" if self.dest_is64(d) else "32"
            fn = {"clz": f"arc_clz{w}", "rbit": f"arc_rbit{w}",
                  "rev": f"arc_rev{w}", "rev16": f"arc_rev16_{w}",
                  "rev32": "arc_rev32_64"}[m]
            return [self.write(d, f"{fn}({self.read(ops[1])})")]

        # -- unscaled signed loads
        unscaled = {"ldursb": "int8_t", "ldursh": "int16_t", "ldursw": "int32_t"}
        if m in unscaled:
            return self.emit_load(insn, ops, unscaled[m])
        if m == "ldpsw":
            a, b, mem = ops[0], ops[1], self.find_mem(ops)
            if mem is None:
                raise Unsupported("ldpsw addressing")
            return (["{ const uint64_t _pa = " + self.mem_address(mem, insn) + ";"] +
                    ["  " + l for l in self.writeback(insn, mem)] +
                    ["  " + self.write(a, "(int64_t)(int32_t)arc_ld32(_pa)"),
                     "  " + self.write(b, "(int64_t)(int32_t)arc_ld32(_pa + 4)")] +
                    ["}"])

        # -- system registers
        # TPIDR_EL0 is the thread pointer. Nothing else is reachable from user
        # code in a way a game depends on, so anything else is left unsupported
        # rather than answered with a plausible lie.
        if m == "mrs":
            if "tpidr_el0" in insn.op_str.lower():
                return [self.write(ops[0], "arc_tpidr_read()")]
            raise Unsupported(f"mrs {insn.op_str.split(',')[-1].strip()}")
        if m == "msr":
            if "tpidr_el0" in insn.op_str.lower():
                return [f"arc_tpidr_write({self.read(ops[1])});"]
            raise Unsupported("msr")

        raise Unsupported(m)

    def cond_of(self, insn) -> int:
        # capstone exposes the condition on the instruction, not the operands.
        cc = insn.cc
        if cc <= 0:
            raise Unsupported("condition")
        return cc - 1  # capstone numbers conditions from 1

    def emit_fp_load(self, insn, d, mem, addr) -> list[str]:
        idx, kind = self.fp_of(d)
        if kind == "q":
            return [f"arc_q_w(c, {idx}, arc_ld64({addr}), arc_ld64({addr} + 8));"]
        setter = {"b": ("arc_su_w", "arc_ld8"), "h": ("arc_su_w", "arc_ld16"),
                  "s": ("arc_su_w", "arc_ld32"), "d": ("arc_du_w", "arc_ld64")}
        if kind not in setter:
            raise Unsupported(f"FP load of {kind}")
        set_fn, ld_fn = setter[kind]
        return [f"{set_fn}(c, {idx}, {ld_fn}({addr}));"]

    def emit_fp_store(self, insn, srcop, mem, addr) -> list[str]:
        idx, kind = self.fp_of(srcop)
        if kind == "q":
            return [f"arc_st64({addr}, (c)->q[{idx}].u64[0]);",
                    f"arc_st64({addr} + 8, (c)->q[{idx}].u64[1]);"]
        st = {"b": ("arc_st8", "u8"), "h": ("arc_st16", "u16"),
              "s": ("arc_st32", "u32"), "d": ("arc_st64", "u64")}
        if kind not in st:
            raise Unsupported(f"FP store of {kind}")
        st_fn, view = st[kind]
        return [f"{st_fn}({addr}, (c)->q[{idx}].{view}[0]);"]

    def find_mem(self, ops):
        """The memory operand, or None for a literal (PC-relative) access.

        Position is not reliable: a post-indexed access puts its increment
        *after* the memory operand, so `ops[-1]` is an immediate there while a
        pre-indexed one ends with the memory operand. Taking the last operand
        and testing its type conflates a post-index with a literal, which
        produces a load from the displacement itself.
        """
        for op in ops:
            if op.type == a64.ARM64_OP_MEM:
                return op
        return None

    def emit_load(self, insn, ops, cast) -> list[str]:
        d = ops[0]
        mem = self.find_mem(ops)
        if mem is None:
            mem = ops[-1]
        if mem.type == a64.ARM64_OP_IMM:
            # A literal load: `ldr x0, <address>`, reading a constant pooled
            # near the code. Capstone resolves the PC-relative offset to an
            # absolute address in the image, so it only needs rebasing.
            addr = f"({self.base_expr()} + UINT64_C({mem.imm}))"
            if self.fp_of(d) is not None:
                return self.emit_fp_load(insn, d, mem, addr)
            is64 = self.dest_is64(d)
            if cast == "int32_t":
                return [self.write(d, f"(int64_t)(int32_t)arc_ld32({addr})")]
            fn = "arc_ld64" if is64 else "arc_ld32"
            return [self.write(d, f"{fn}({addr})")]
        if mem.type != a64.ARM64_OP_MEM:
            raise Unsupported("load addressing")
        addr = self.mem_address(mem, insn)
        if self.fp_of(d) is not None:
            return self.emit_fp_load(insn, d, mem, addr) + self.writeback(insn, mem)
        is64 = self.dest_is64(d)
        if cast is None:
            fn = "arc_ld64" if is64 else "arc_ld32"
            expr = f"{fn}({addr})"
        elif cast.startswith("int"):
            bits = {"int8_t": 8, "int16_t": 16, "int32_t": 32}[cast]
            expr = (f"({'(int64_t)' if is64 else '(int32_t)'}({cast})"
                    f"arc_ld{bits}({addr}))")
        else:
            bits = {"uint8_t": 8, "uint16_t": 16}[cast]
            expr = f"arc_ld{bits}({addr})"
        if insn.writeback:
            # Order matters here too, and differently from how it reads: the
            # address is computed from the base *before* the update, whether
            # the update is written before or after the access in the source.
            return (["{ const uint64_t _a = " + addr + ";"] +
                    ["  " + l for l in self.writeback(insn, mem)] +
                    ["  " + self.write(d, expr.replace(addr, "_a"))] + ["}"])
        return [self.write(d, expr)]

    def emit_store(self, insn, ops, cast) -> list[str]:
        s = ops[0]
        mem = self.find_mem(ops)
        if mem is None:
            raise Unsupported("store addressing")
        addr = self.mem_address(mem, insn)
        if self.fp_of(s) is not None:
            return self.emit_fp_store(insn, s, mem, addr) + self.writeback(insn, mem)
        is64 = reg_of(self.md, s.reg)[1]
        if cast is None:
            fn = "arc_st64" if is64 else "arc_st32"
        else:
            fn = {"uint8_t": "arc_st8", "uint16_t": "arc_st16"}[cast]
        if insn.writeback:
            return (["{ const uint64_t _a = " + addr + ";"] +
                    ["  " + l for l in self.writeback(insn, mem)] +
                    [f"  {fn}(_a, {self.read(s)});"] + ["}"])
        return [f"{fn}({addr}, {self.read(s)});"]

    def emit_pair(self, insn, ops, is_load) -> list[str]:
        a, b = ops[0], ops[1]
        mem = self.find_mem(ops)
        if mem is None:
            raise Unsupported("pair addressing")

        # The address goes into a temporary before anything is written. A load
        # pair whose base is also its first destination -- `ldp x8, x9, [x8]`,
        # which is ordinary code -- otherwise reads its second element through
        # the value the first element just loaded. It is a silent failure: the
        # first half of the pair is still correct.
        lines = ["{ const uint64_t _pa = " + self.mem_address(mem, insn) + ";"]

        if self.fp_of(a) is not None:
            idx, kind = self.fp_of(a)
            step = FP_BYTES.get(kind)
            if step is None:
                raise Unsupported(f"FP pair of {kind}")
            if is_load:
                body = (self.emit_fp_load(insn, a, mem, "_pa") +
                        self.emit_fp_load(insn, b, mem, f"(_pa + {step})"))
            else:
                body = (self.emit_fp_store(insn, a, mem, "_pa") +
                        self.emit_fp_store(insn, b, mem, f"(_pa + {step})"))
        else:
            is64 = reg_of(self.md, a.reg)[1]
            step = 8 if is64 else 4
            ld, st = ("arc_ld64", "arc_st64") if is64 else ("arc_ld32", "arc_st32")
            if is_load:
                body = [self.write(a, f"{ld}(_pa)"),
                        self.write(b, f"{ld}(_pa + {step})")]
            else:
                body = [f"{st}(_pa, {self.read(a)});",
                        f"{st}(_pa + {step}, {self.read(b)});"]

        # Write-back comes after the address is captured and before the access,
        # so it reads the base as it was either way.
        return (lines + ["  " + l for l in self.writeback(insn, mem)] +
                ["  " + l for l in body] + ["}"])

    def writeback(self, insn, mem) -> list[str]:
        """Pre/post-index addressing updates the base register.

        Callers capture the effective address first and only then emit this,
        because the address is a function of the base *before* the update in
        both the pre- and post-indexed forms.
        """
        if not insn.writeback:
            return []
        bidx, _, b_sp = reg_of(self.md, mem.mem.base)
        target = "(c)->sp" if b_sp else None
        # Capstone folds a pre-index displacement into mem.disp and reports
        # post-index as a trailing immediate operand.
        if insn.operands[-1].type == a64.ARM64_OP_IMM:
            delta = insn.operands[-1].imm
        else:
            delta = mem.mem.disp
        if target:
            return [f"(c)->sp = (c)->sp + INT64_C({delta});"]
        return [f"ARC_X_W(c, {bidx}, ARC_X_R(c, {bidx}) + INT64_C({delta}));"]

    def fn_name(self, addr: int) -> str:
        self.referenced.add(addr)
        return f"fn{self.image_index}_{addr:x}"

    def base_expr(self) -> str:
        """The load address of the image this function came from.

        Not a field of the context: a lifted function belongs to exactly one
        image, so which base it means is fixed when the C is generated, and
        baking it in keeps an indirect call from having to carry the answer.
        """
        return f"arc_image_bases[{self.image_index}]"

    # --- function level -----------------------------------------------------

    def read_image(self, addr: int, width: int, signed: bool):
        """One little-endian value from anywhere in the current image."""
        for base, blob in self.image_sections:
            off = addr - base
            if 0 <= off and off + width <= len(blob):
                v = int.from_bytes(blob[off:off + width], "little")
                if signed and v >> (width * 8 - 1):
                    v -= 1 << (width * 8)
                return v
        return None

    def jump_tables(self, insns, start: int, end: int) -> dict[int, list[int]]:
        """Where a switch's indirect branch can actually land.

        A `switch` compiles to a table of offsets and a `br` through it, and
        the targets are *inside* the function doing the branching. Handing that
        to the global dispatcher asks it to find a function beginning halfway
        through this one, which it correctly cannot -- so those branches have
        to become local jumps, and their targets have to be labels.

        Two encodings occur in practice and both are read here: signed 32-bit
        offsets added to the table's own address, and unsigned 16- or 8-bit
        entries scaled by four and added to a separately computed base. What
        they share is the shape `target = base + (entry << shift)`, which is
        all this needs to recognise.

        Nothing in the instruction stream says how long a table is -- the
        bounds check that precedes it does, and reading that would mean
        understanding the comparison. So entries are read until one lands
        outside this function, which is the same limit the bounds check was
        enforcing.
        """
        def num(op):
            return reg_of(self.md, op.reg)[0]

        const: dict[int, int] = {}
        load: dict[int, tuple[int, int, bool]] = {}
        pend: dict[int, tuple[tuple[int, int, bool], int, int]] = {}
        pend_reg: dict[int, tuple[int, int, tuple[int, int]]] = {}
        tables: dict[int, list[int]] = {}
        widths = {"ldrsw": (4, True), "ldrh": (2, False), "ldrb": (1, False),
                  "ldrsh": (2, True), "ldrsb": (1, True)}

        for insn in insns:
            m, ops = insn.mnemonic, insn.operands
            try:
                if m in ("adrp", "adr") and len(ops) == 2 \
                        and ops[1].type == a64.ARM64_OP_IMM:
                    d = num(ops[0])
                    const[d] = ops[1].imm
                    load.pop(d, None)
                    pend.pop(d, None)
                    pend_reg.pop(d, None)
                elif m == "add" and len(ops) == 3 \
                        and ops[2].type == a64.ARM64_OP_IMM \
                        and num(ops[1]) in const:
                    d = num(ops[0])
                    const[d] = const[num(ops[1])] + ops[2].imm
                    load.pop(d, None)
                    pend.pop(d, None)
                    pend_reg.pop(d, None)
                elif m in widths:
                    # Read what the sources hold before invalidating the
                    # destination: these instructions routinely load into a
                    # register that is also the index or the base, and clearing
                    # it first would lose the value being read.
                    d = num(ops[0])
                    mem = next((o for o in ops
                                if o.type == a64.ARM64_OP_MEM), None)
                    table = None
                    if mem is not None and mem.mem.index:
                        base = const.get(reg_of(self.md, mem.mem.base)[0])
                        if base is not None:
                            table = base + mem.mem.disp
                    const.pop(d, None)
                    pend.pop(d, None)
                    pend_reg.pop(d, None)
                    load.pop(d, None)
                    if table is not None:
                        width, signed = widths[m]
                        load[d] = (table, width, signed)
                elif m == "add" and len(ops) == 3 \
                        and ops[2].type == a64.ARM64_OP_REG:
                    d, a, b = num(ops[0]), num(ops[1]), num(ops[2])
                    shift = ops[2].shift.value if ops[2].shift.type else 0
                    # `add x8, x8, x9` is the usual spelling, so the
                    # destination is normally one of the sources. Sample both
                    # before the destination is cleared.
                    load_a, load_b = load.get(a), load.get(b)
                    const_a, const_b = const.get(a), const.get(b)
                    const.pop(d, None)
                    load.pop(d, None)
                    pend.pop(d, None)
                    pend_reg.pop(d, None)
                    # One side is the entry just loaded, the other the base the
                    # offset is relative to; which way round differs by
                    # encoding, so accept either.
                    if load_a is not None and const_b is not None:
                        pend[d] = (load_a, const_b, shift)
                    elif load_b is not None and const_a is not None:
                        pend[d] = (load_b, const_a, shift)
                    else:
                        # No table at all: some switches compute the target
                        # straight from the index, `base + (i << 2)`, with the
                        # base an `adr` to a label in this very function. There
                        # is nothing to read, so the reachable set comes from
                        # how far the index can reach -- which is why only the
                        # byte-wide extends are taken. A wider one would not
                        # bound anything, and guessing there would invent jump
                        # targets rather than find them.
                        ext = EXTEND_RANGE.get(getattr(ops[2], "ext", 0))
                        base = next((v for v in (const_a, const_b)
                                     if v is not None and start <= v < end),
                                    None)
                        if ext and base is not None:
                            pend_reg[d] = (base, shift, ext)
                elif m == "br" and len(ops) == 1:
                    d = num(ops[0])
                    targets: list[int] = []
                    if d in pend:
                        (table, width, signed), base, shift = pend[d]
                        for i in range(4096):
                            v = self.read_image(table + i * width, width, signed)
                            if v is None:
                                break
                            t = (base + (v << shift)) & 0xFFFFFFFFFFFFFFFF
                            if not (start <= t < end) or t % 4:
                                break
                            targets.append(t)
                    elif d in pend_reg:
                        base, shift, (lo, hi) = pend_reg[d]
                        targets = [t for t in
                                   (base + (i << shift) for i in range(lo, hi + 1))
                                   if start <= t < end and not t % 4]
                    if targets:
                        tables[insn.address] = targets
                elif ops and ops[0].type == a64.ARM64_OP_REG:
                    # Anything else writing a register invalidates what was
                    # known about it. Being wrong here fabricates jump targets.
                    d = num(ops[0])
                    const.pop(d, None)
                    load.pop(d, None)
                    pend.pop(d, None)
                    pend_reg.pop(d, None)
            except Unsupported:
                continue
        return tables

    def lift_function(self, addr: int, size: int, code: bytes) -> str | None:
        insns = list(self.md.disasm(code, addr))
        end = addr + size

        # A label is needed wherever a branch inside this function lands.
        labels: set[int] = set()
        for insn in insns:
            for op in insn.operands:
                if (op.type == a64.ARM64_OP_IMM and insn.group(a64.ARM64_GRP_JUMP)
                        and addr <= op.imm < end):
                    labels.add(op.imm)

        # A switch lands inside this function too, through a table rather than
        # an immediate, so those targets are labels as well -- and they have to
        # be found before the labels are collected, not while emitting.
        self.cur_tables = self.jump_tables(insns, addr, end)
        for targets in self.cur_tables.values():
            labels.update(targets)

        body: list[str] = []
        ok = True
        for insn in insns:
            self.total += 1
            if insn.address in labels:
                body.append(f"L_{insn.address:x}:;")
            try:
                lines = self.emit(insn, addr, end, labels)
                self.lifted += 1
            except Unsupported as e:
                self.unsupported[str(e)] += 1
                ok = False
                lines = [f"/* UNSUPPORTED {insn.mnemonic} {insn.op_str} */"]
            body.append(f"  /* {insn.address:x}: {insn.mnemonic} {insn.op_str} */")
            body.extend("  " + l for l in lines)

        if not ok:
            return None
        # The image index and the offset, packed into one constant so that
        # recording an entry is a single store with nothing to look up.
        packed = (self.image_index << 56) | addr
        name = self.fn_name(addr)
        self.referenced.discard(addr)  # defining it is not referencing it
        return (f"void {name}(Arm64Ctx* c) {{\n"
                f"  arc_frame_note(UINT64_C({packed}));\n"
                + "\n".join(body) + "\n}\n")


def code_sections(elf: ELFFile) -> list[tuple[int, bytes]]:
    """Every section holding instructions we may need to lift."""
    out = []
    for name in (".text", ".plt"):
        sec = elf.get_section_by_name(name)
        if sec is not None:
            out.append((sec["sh_addr"], sec.data()))
    return out


def data_sections(elf: ELFFile) -> list[tuple[int, bytes]]:
    """Every allocated section with bytes in the file.

    Wider than `code_sections` because a switch's jump table is data, and the
    compiler puts it wherever it likes -- beside the code it belongs to, or off
    in `.rodata`. Reading one means being able to read anything mapped.
    """
    out = []
    for sec in elf.iter_sections():
        if sec["sh_flags"] & 0x2 and sec["sh_type"] != "SHT_NOBITS":
            out.append((sec["sh_addr"], sec.data()))
    return out


def bytes_at(sections, addr: int, size: int):
    for base, data in sections:
        if base <= addr and addr + size <= base + len(data):
            return data[addr - base:addr - base + size]
    return None


def functions_from_plt(elf: ELFFile) -> list[tuple[int, int]]:
    """The PLT, as 16-byte functions.

    `.eh_frame` describes the functions a compiler emitted, and the PLT is not
    one of them -- the linker synthesises it. But every call to an imported
    function goes through it, so without these a lifted program traps the
    moment it calls out to the host, which is immediately: a C++ static
    constructor registers its destructor through `__cxa_atexit` before it does
    anything else.

    Each entry is the same four instructions -- load the GOT slot, branch to it
    -- so lifting them turns the final `br` into an ordinary indirect branch
    that the dispatcher resolves to the host function the loader bound there.
    """
    plt = elf.get_section_by_name(".plt")
    if plt is None:
        return []
    base, size = plt["sh_addr"], plt["sh_size"]
    return [(base + off, 16) for off in range(0, size - 15, 16)]


def functions_from_eh_frame(elf: ELFFile) -> list[tuple[int, int]]:
    if not elf.has_dwarf_info():
        return []
    out = []
    for entry in elf.get_dwarf_info().EH_CFI_entries():
        hdr = getattr(entry, "header", None)
        if hdr is None:
            continue
        start = getattr(hdr, "initial_location", None)
        size = getattr(hdr, "address_range", None)
        if start and size:
            out.append((start, size))
    out.sort()
    return out


# A function recovered from a call site alone runs until the next thing known
# to start. That is right wherever the compiler laid functions out one after
# another, which is everywhere here -- but a gap that is really data would be
# disassembled as one enormous function, so the span is capped. Nothing in
# either title comes close to it.
RECOVER_MAX = 64 * 1024


def recover_extents(targets, extents, text):
    """(address, size) for call targets no unwind entry describes.

    `.eh_frame` describes what can be unwound through, which is not the same
    as everything that can be called: a leaf that never throws, or hand-written
    assembly, is entitled to no entry at all and is then reachable only from
    its call sites. Those arrive here as references to addresses nothing
    defines, and stubbing them turns a working function into a trap.
    """
    starts = sorted(a for a, _ in extents)
    ends = sorted(extents)
    ordered = sorted(targets)
    out = []
    for t in ordered:
        span = next(((a, e) for a, e in text if a <= t < e), None)
        if span is None:
            continue
        # A target inside a described range is a second entry point into it,
        # not a mistake: one unwind entry can cover several entries, and a
        # local one can be called directly. Emitting it as its own function
        # duplicates the tail it shares, which costs nothing but bytes.
        i = bisect.bisect_right(ends, (t, float("inf"))) - 1
        if i >= 0 and ends[i][0] <= t < ends[i][1]:
            end = ends[i][1]
        else:
            end = span[1]
            j = bisect.bisect_right(starts, t)
            if j < len(starts):
                end = min(end, starts[j])
        k = bisect.bisect_right(ordered, t)
        if k < len(ordered):
            end = min(end, ordered[k])
        if t < end <= t + RECOVER_MAX:
            out.append((t, end - t))
    return out


def uncovered_starts(extents, text):
    """The start of every run of executable bytes no function covers.

    Call-site recovery only finds what something names. An indirect call --
    a virtual dispatch, a jump table -- takes its target out of data, so no
    call site mentions it and `referenced` never sees it. Sweeping the gaps
    between described functions finds those, on the same assumption a
    disassembler makes: executable bytes that nothing claims are code that
    nothing described.
    """
    out = []
    for a, e in text:
        pos = a
        for s, x in sorted(extents):
            if x <= pos or s >= e:
                continue
            if s > pos:
                out.append(pos)
            pos = max(pos, x)
        if pos < e:
            out.append(pos)
    return out


def emit_program(lifter: Lifter, images, out_dir: str, shards: int,
                 limit: int) -> None:
    """Write one lifted program covering every image given.

    A program is not one library. An engine calls into the C++ runtime the APK
    ships beside it, and those calls land in ARM code like any other -- so the
    dispatch table has to span every image, keyed on which one an address falls
    inside. Offsets overlap between images, so function names carry the image
    index too.
    """
    os.makedirs(out_dir, exist_ok=True)
    handles = []
    for i in range(shards):
        fh = open(os.path.join(out_dir, f"lifted_{i:03d}.c"), "w",
                  encoding="utf-8")
        fh.write('#include "lifted.h"\n\n')
        handles.append(fh)

    per_image = []          # (name, defined[], stub_targets[])
    written = 0
    for index, (name, funcs, sections, data) in enumerate(images):
        lifter.image_index = index
        lifter.image_sections = data
        lifter.referenced = set()
        defined, unlifted = [], []
        done = 0
        extents = [(a, a + s) for a, s in funcs]
        text = [(a, a + len(b)) for a, b in sections]
        pending, recovered = list(funcs), 0
        while pending:
            for start_addr, size in pending:
                if limit and done >= limit:
                    break
                body = bytes_at(sections, start_addr, size)
                if body is None:
                    continue
                done += 1
                code = lifter.lift_function(start_addr, size, body)
                defined.append(start_addr)
                if code is None:
                    unlifted.append(start_addr)
                    continue
                handles[written % shards].write(code + "\n")
                written += 1
            if limit and done >= limit:
                break
            # Whatever is still referenced and undefined is a function that no
            # unwind entry described. Lifting those turns up further ones, so
            # this runs until it stops finding any. The first pass also sweeps
            # the gaps, which is the only way to reach a function that exists
            # solely as an address in a vtable.
            targets = lifter.referenced - set(defined)
            if not recovered:
                targets |= set(uncovered_starts(extents, text))
            pending = recover_extents(targets, extents, text)
            extents += [(a, a + s) for a, s in pending]
            recovered += len(pending)
        stubs = sorted(set(unlifted) | (lifter.referenced - set(defined)))
        per_image.append((name, sorted(set(defined) | set(stubs)), stubs,
                          len(defined) - len(unlifted)))
        print(f"  {name}: {len(defined) - len(unlifted):,} lifted "
              f"({recovered:,} recovered from call sites), "
              f"{len(unlifted):,} did not lift, {len(stubs) - len(unlifted):,} "
              f"stubs for targets outside .eh_frame")

    with open(os.path.join(out_dir, "stubs.c"), "w", encoding="utf-8") as fh:
        fh.write('#include "lifted.h"\n\n')
        for index, (_, _, stubs, _) in enumerate(per_image):
            for addr in stubs:
                fh.write(f'void fn{index}_{addr:x}(Arm64Ctx* c) {{ '
                         f'arc_trap(c, "unlifted fn{index}_{addr:x}"); }}\n')

    with open(os.path.join(out_dir, "lifted.h"), "w", encoding="utf-8") as fh:
        fh.write("// Generated by tools/lifter.py -- do not edit.\n"
                 '#pragma once\n#include "arm64_context.h"\n\n'
                 "#ifdef __cplusplus\nextern \"C\" {\n#endif\n\n")
        fh.write("// Where each image was loaded. The host fills these in with\n"
                 "// arc_set_image before calling anything.\n")
        fh.write(f"#define ARC_IMAGE_COUNT {len(per_image)}\n")
        fh.write("extern uint64_t arc_image_bases[ARC_IMAGE_COUNT];\n")
        fh.write("void arc_set_image(size_t index, uint64_t base, uint64_t span);\n")
        fh.write("const char* arc_image_name(size_t index);\n\n")
        for index, (_, all_fns, _, _) in enumerate(per_image):
            for addr in all_fns:
                fh.write(f"void fn{index}_{addr:x}(Arm64Ctx*);\n")
        fh.write("#ifdef __cplusplus\n}\n#endif\n")

    with open(os.path.join(out_dir, "dispatch.c"), "w", encoding="utf-8") as fh:
        fh.write('#include "lifted.h"\n\n'
                 "typedef struct { uint64_t offset; Arc64Fn fn; } ArcEntry;\n"
                 "typedef struct { const ArcEntry* items; size_t count; } ArcTable;\n\n")
        for index, (_, all_fns, _, _) in enumerate(per_image):
            fh.write(f"static const ArcEntry kImage{index}[] = {{\n")
            for addr in all_fns:
                fh.write(f"  {{ UINT64_C({addr}), fn{index}_{addr:x} }},\n")
            fh.write("};\n")
        fh.write("\nstatic const ArcTable kTables[ARC_IMAGE_COUNT] = {\n")
        for index, (_, all_fns, _, _) in enumerate(per_image):
            fh.write(f"  {{ kImage{index}, {len(all_fns)} }},\n")
        fh.write("};\n\n")
        fh.write("static const char* const kNames[ARC_IMAGE_COUNT] = {\n")
        for name, _, _, _ in per_image:
            fh.write(f'  "{name}",\n')
        fh.write("};\n\n")
        fh.write("uint64_t arc_image_bases[ARC_IMAGE_COUNT];\n"
                 "static uint64_t g_spans[ARC_IMAGE_COUNT];\n\n"
                 "static void arc_dispatch_lifted(Arm64Ctx*, uint64_t);\n\n"
                 "void arc_set_image(size_t index, uint64_t base, uint64_t span) {\n"
                 "  // Every host announces its images, so this is where the\n"
                 "  // lifted dispatcher installs itself.\n"
                 "  arc_set_dispatch(arc_dispatch_lifted);\n"
                 "  if (index >= ARC_IMAGE_COUNT) return;\n"
                 "  arc_image_bases[index] = base;\n"
                 "  g_spans[index] = span;\n"
                 "}\n\n"
                 "const char* arc_image_name(size_t index) {\n"
                 "  return index < ARC_IMAGE_COUNT ? kNames[index] : 0;\n"
                 "}\n\n")
        fh.write("""static void arc_dispatch_lifted(Arm64Ctx* c, uint64_t target) {
  for (size_t im = 0; im < ARC_IMAGE_COUNT; ++im) {
    const uint64_t base = arc_image_bases[im];
    if (!base || target < base || target >= base + g_spans[im]) continue;
    const uint64_t off = target - base;
    const ArcEntry* items = kTables[im].items;
    size_t lo = 0, hi = kTables[im].count;
    while (lo < hi) {
      const size_t mid = lo + (hi - lo) / 2;
      if (items[mid].offset < off) lo = mid + 1;
      else hi = mid;
    }
    if (lo < kTables[im].count && items[lo].offset == off) {
      items[lo].fn(c);
      return;
    }
    break;  // inside this image, but not at a function we lifted
  }
  // Not lifted code at all. It may be a host import the guest reached through
  // its GOT, which the runtime knows about and we do not.
  arc_dispatch_miss(c, target);
}
""")

    for fh in handles:
        fh.close()

    total_bytes = sum(os.path.getsize(os.path.join(out_dir, f))
                      for f in os.listdir(out_dir))
    total_fns = sum(len(a) for _, a, _, _ in per_image)
    print(f"\nwrote {out_dir}: {total_fns:,} functions from {len(per_image)} "
          f"images across {shards} units ({total_bytes / 1e6:.0f} MB)")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("library", nargs="+",
                    help="the engine, then any guest libraries it calls into")
    ap.add_argument("--out", help="directory to write generated C into")
    ap.add_argument("--shards", type=int, default=64,
                    help="translation units to split the program across")
    ap.add_argument("--limit", type=int, default=0, help="only lift the first N")
    ap.add_argument("--report", action="store_true",
                    help="print coverage instead of writing code")
    args = ap.parse_args()

    images = []
    for lib in args.library:
        with open(lib, "rb") as fh:
            elf = ELFFile(fh)
            images.append((os.path.basename(lib),
                           sorted(functions_from_eh_frame(elf) +
                                  functions_from_plt(elf)),
                           code_sections(elf),
                           data_sections(elf)))

    lifter = Lifter()

    if args.out:
        emit_program(lifter, images, args.out, args.shards, args.limit)
    else:
        funcs, sections = images[0][1], images[0][2]
        lifter.image_sections = images[0][3]
        done = failed = 0
        for start, size in funcs:
            if args.limit and done + failed >= args.limit:
                break
            body = bytes_at(sections, start, size)
            if body is None:
                continue
            if lifter.lift_function(start, size, body) is None:
                failed += 1
            else:
                done += 1
        total = done + failed
        if total:
            print(f"functions   {total:,} attempted -- {done:,} complete "
                  f"({done / total:.1%})")
    if lifter.total:
        print(f"instructions {lifter.lifted:,} of {lifter.total:,} lifted "
              f"({lifter.lifted / lifter.total:.2%})")
    if lifter.unsupported and (args.report or not args.out):
        print(f"\ntop unsupported forms ({len(lifter.unsupported)} distinct)")
        for name, n in lifter.unsupported.most_common(25):
            print(f"  {n:>9,}  {name}")


if __name__ == "__main__":
    main()
