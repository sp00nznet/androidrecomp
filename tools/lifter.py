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

    def emit_vector(self, insn, ops):
        m = insn.mnemonic

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

        # Lane to general register.
        if m in ("umov", "smov") and not self.is_vector(ops[0]):
            src = ops[1]
            info = self.vas_of(src)
            view = info[1] if info else "u32"
            bits = info[2] if info else 32
            expr = self.vec_elem(src, max(self.lane_of(src), 0), view)
            if m == "smov":
                w = 64 if self.dest_is64(ops[0]) else 32
                expr = f"arc_sext{w}({expr}, {bits})"
            return [self.write(ops[0], expr)]

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

        info = self.vas_of(ops[0]) if self.is_vector(ops[0]) else None
        if not info:
            raise Unsupported(f"vector {m} without arrangement")
        lanes, view, bits = info
        fview = {32: "f32", 64: "f64"}.get(bits)
        sview = {8: "i8", 16: "i16", 32: "i32", 64: "i64"}.get(bits, "i32")
        ones = f"(uint{bits}_t)~(uint{bits}_t)0"

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
        if m in ("bic", "orn") and len(ops) == 3:
            c = "&" if m == "bic" else "|"
            return self.vec_result(ops[0], [
                f"  _t.{view}[{i}] = {self.vec_source(ops[1], i, view)} {c}"
                f" (~{self.vec_source(ops[2], i, view)});" for i in range(lanes)])
        if m in flt_bin and len(ops) == 3:
            if not fview:
                raise Unsupported(f"{m} on {bits}-bit lanes")
            c = flt_bin[m]
            return self.vec_result(ops[0], [
                f"  _t.{fview}[{i}] = {self.vec_source(ops[1], i, fview)} {c}"
                f" {self.vec_source(ops[2], i, fview)};" for i in range(lanes)])

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
        int_cmp = {"cmeq": "==", "cmgt": ">", "cmge": ">=",
                   "cmhi": ">", "cmhs": ">="}
        flt_cmp = {"fcmeq": "==", "fcmgt": ">", "fcmge": ">="}
        if m in int_cmp:
            v = sview if m in ("cmgt", "cmge") else view
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
            return [self.write(ops[0], f"((c)->image_base + UINT64_C({ops[1].imm}))")]
        if m == "adrp":
            return [self.write(ops[0], f"((c)->image_base + UINT64_C({ops[1].imm & ~0xFFF}))")]

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
            return [f"ARC_X_W(c, 30, (c)->image_base + UINT64_C({insn.address + 4}));",
                    f"{self.fn_name(t)}(c);"]
        if m == "blr":
            return [f"ARC_X_W(c, 30, (c)->image_base + UINT64_C({insn.address + 4}));",
                    f"arc_dispatch(c, {self.read(ops[0])});"]
        if m == "br":
            return [f"arc_dispatch(c, {self.read(ops[0])}); return;"]
        if m == "ret":
            return ["return;"]
        if m in ("nop", "bti", "hint", "dmb", "dsb", "isb", "prfm", "prfum"):
            return [f"/* {m}: no architectural effect here */"]
        if m == "brk":
            return ["arc_trap(c, \"brk\");"]

        # -- floating point
        # Scalar FP maps onto C's own float and double, which is the whole
        # reason to keep the register file as a union: the arithmetic is the
        # host's, and only the corner cases need spelling out.
        fp3 = {"fadd": "+", "fsub": "-", "fmul": "*", "fdiv": "/"}
        if m in fp3:
            return [self.fp_write(
                ops[0],
                f"({self.fp_read(ops[1])} {fp3[m]} {self.fp_read(ops[2])})")]
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

        if m == "movi":
            info = self.fp_of(ops[0])
            imm = ops[1]
            if info and imm.type == a64.ARM64_OP_IMM and imm.imm == 0 \
                    and not imm.shift.value:
                return [f"arc_v_clear(c, {info[0]});"]
            raise Unsupported("movi non-zero")

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
            addr = self.mem_address(mem, insn)
            return [self.write(a, f"(int64_t)(int32_t)arc_ld32({addr})"),
                    self.write(b, f"(int64_t)(int32_t)arc_ld32({addr} + 4)")
                    ] + self.writeback(insn, mem)

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
            addr = f"((c)->image_base + UINT64_C({mem.imm}))"
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
        return [self.write(d, expr)] + self.writeback(insn, mem)

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
        return [f"{fn}({addr}, {self.read(s)});"] + self.writeback(insn, mem)

    def emit_pair(self, insn, ops, is_load) -> list[str]:
        a, b = ops[0], ops[1]
        mem = self.find_mem(ops)
        if mem is None:
            raise Unsupported("pair addressing")
        addr = self.mem_address(mem, insn)
        if self.fp_of(a) is not None:
            idx, kind = self.fp_of(a)
            step = FP_BYTES.get(kind)
            if step is None:
                raise Unsupported(f"FP pair of {kind}")
            if is_load:
                body = (self.emit_fp_load(insn, a, mem, addr) +
                        self.emit_fp_load(insn, b, mem, f"({addr} + {step})"))
            else:
                body = (self.emit_fp_store(insn, a, mem, addr) +
                        self.emit_fp_store(insn, b, mem, f"({addr} + {step})"))
            return body + self.writeback(insn, mem)
        is64 = reg_of(self.md, a.reg)[1]
        step = 8 if is64 else 4
        ld, st = ("arc_ld64", "arc_st64") if is64 else ("arc_ld32", "arc_st32")
        if is_load:
            body = [self.write(a, f"{ld}({addr})"),
                    self.write(b, f"{ld}({addr} + {step})")]
        else:
            body = [f"{st}({addr}, {self.read(a)});",
                    f"{st}({addr} + {step}, {self.read(b)});"]
        return body + self.writeback(insn, mem)

    def writeback(self, insn, mem) -> list[str]:
        """Pre/post-index addressing updates the base register."""
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
        return f"fn_{addr:x}"

    # --- function level -----------------------------------------------------

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
        return (f"void {self.fn_name(addr)}(Arm64Ctx* c) {{\n"
                + "\n".join(body) + "\n}\n")


def code_sections(elf: ELFFile) -> list[tuple[int, bytes]]:
    """Every section holding instructions we may need to lift."""
    out = []
    for name in (".text", ".plt"):
        sec = elf.get_section_by_name(name)
        if sec is not None:
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


def emit_program(lifter: Lifter, funcs, sections, out_dir: str,
                 shards: int, limit: int) -> None:
    """Write the whole lifted program as a set of translation units.

    One C file per function would be 62,000 files; one file for everything
    would be several hundred megabytes and defeat any compiler. Sharding keeps
    each unit at a size a compiler is happy with and lets the build run in
    parallel.
    """
    os.makedirs(out_dir, exist_ok=True)
    handles = []
    for i in range(shards):
        fh = open(os.path.join(out_dir, f"lifted_{i:03d}.c"), "w",
                  encoding="utf-8")
        fh.write('#include "lifted.h"\n\n')
        handles.append(fh)

    defined: list[int] = []
    unlifted: list[int] = []
    done = 0
    for start, size in funcs:
        if limit and done >= limit:
            break
        body = bytes_at(sections, start, size)
        if body is None:
            continue
        done += 1
        code = lifter.lift_function(start, size, body)
        defined.append(start)
        if code is None:
            unlifted.append(start)
            continue
        # Round-robin by index: function addresses are 4-byte aligned,
        # so keying the shard on the address itself sends every
        # function to unit zero.
        handles[len(defined) % shards].write(code + "\n")

    # A function that did not lift still needs to exist, or every caller fails
    # to link. It traps instead, so an incomplete lift shows up the moment that
    # path is taken rather than at build time.
    stub_targets = sorted(set(unlifted) |
                          (lifter.referenced - set(defined)))
    with open(os.path.join(out_dir, "stubs.c"), "w", encoding="utf-8") as fh:
        fh.write('#include "lifted.h"\n\n')
        for addr in stub_targets:
            fh.write(f'void fn_{addr:x}(Arm64Ctx* c) {{ '
                     f'arc_trap(c, "unlifted fn_{addr:x}"); }}\n')

    all_fns = sorted(set(defined) | set(stub_targets))
    with open(os.path.join(out_dir, "lifted.h"), "w", encoding="utf-8") as fh:
        fh.write("// Generated by tools/lifter.py -- do not edit.\n"
                 '#pragma once\n#include "arm64_context.h"\n\n'
                 "#ifdef __cplusplus\nextern \"C\" {\n#endif\n\n")
        for addr in all_fns:
            fh.write(f"void fn_{addr:x}(Arm64Ctx*);\n")
        fh.write("\nextern const uint64_t arc_image_size;\n")
        fh.write("#ifdef __cplusplus\n}\n#endif\n")

    # The dispatch table: guest address -> lifted function. Sorted, so an
    # indirect branch is a binary search rather than a hash lookup, and a miss
    # is a trap rather than a wild jump.
    with open(os.path.join(out_dir, "dispatch.c"), "w", encoding="utf-8") as fh:
        fh.write('#include "lifted.h"\n\n'
                 "typedef struct { uint64_t offset; Arc64Fn fn; } ArcEntry;\n\n"
                 "static const ArcEntry kFunctions[] = {\n")
        for addr in all_fns:
            fh.write(f"  {{ UINT64_C({addr}), fn_{addr:x} }},\n")
        fh.write("};\n"
                 "static const size_t kCount = sizeof(kFunctions) / sizeof(kFunctions[0]);\n\n")
        fh.write("""void arc_dispatch(Arm64Ctx* c, uint64_t target) {
  // Targets are host addresses; the table is keyed on image offsets.
  uint64_t off = target - c->image_base;
  size_t lo = 0, hi = kCount;
  while (lo < hi) {
    size_t mid = lo + (hi - lo) / 2;
    if (kFunctions[mid].offset < off) lo = mid + 1;
    else hi = mid;
  }
  if (lo < kCount && kFunctions[lo].offset == off) {
    kFunctions[lo].fn(c);
    return;
  }
  // Not a lifted function. It may still be a host import the guest reached
  // through its GOT, which the runtime knows about and we do not.
  arc_dispatch_miss(c, target);
}
""")

    for fh in handles:
        fh.close()

    total_bytes = sum(os.path.getsize(os.path.join(out_dir, f))
                      for f in os.listdir(out_dir))
    print(f"\nwrote {out_dir}: {len(all_fns):,} functions across {shards} units"
          f" ({total_bytes / 1e6:.0f} MB)")
    print(f"  {len(defined) - len(unlifted):,} lifted, "
          f"{len(unlifted):,} trapping stubs, "
          f"{len(stub_targets) - len(unlifted):,} stubs for targets outside "
          f".eh_frame")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("library")
    ap.add_argument("--out", help="directory to write generated C into")
    ap.add_argument("--shards", type=int, default=64,
                    help="translation units to split the program across")
    ap.add_argument("--limit", type=int, default=0, help="only lift the first N")
    ap.add_argument("--report", action="store_true",
                    help="print coverage instead of writing code")
    args = ap.parse_args()

    with open(args.library, "rb") as fh:
        elf = ELFFile(fh)
        sections = code_sections(elf)
        funcs = sorted(functions_from_eh_frame(elf) + functions_from_plt(elf))

    lifter = Lifter()

    if args.out:
        emit_program(lifter, funcs, sections, args.out, args.shards, args.limit)
    else:
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
