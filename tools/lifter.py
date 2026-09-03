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


class Lifter:
    def __init__(self, image_name: str = "image"):
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        self.md.detail = True
        self.image_name = image_name
        self.unsupported: collections.Counter[str] = collections.Counter()
        self.lifted = 0
        self.total = 0

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
        if m == "cmp":  return compare(sub=True)
        if m == "cmn":  return compare(sub=False)

        # -- logical
        if m == "and":  return logical("&", False)
        if m == "ands": return logical("&", True)
        if m == "orr":  return logical("|", False)
        if m == "eor":  return logical("^", False)
        if m == "bic":  return logical("&", False, invert_rhs=True)
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
        if m == "nop":
            return ["/* nop */"]

        raise Unsupported(m)

    def cond_of(self, insn) -> int:
        # capstone exposes the condition on the instruction, not the operands.
        cc = insn.cc
        if cc <= 0:
            raise Unsupported("condition")
        return cc - 1  # capstone numbers conditions from 1

    def emit_load(self, insn, ops, cast) -> list[str]:
        d, mem = ops[0], ops[-1]
        if mem.type != a64.ARM64_OP_MEM:
            raise Unsupported("load addressing")
        addr = self.mem_address(mem, insn)
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
        s, mem = ops[0], ops[-1]
        if mem.type != a64.ARM64_OP_MEM:
            raise Unsupported("store addressing")
        addr = self.mem_address(mem, insn)
        is64 = reg_of(self.md, s.reg)[1]
        if cast is None:
            fn = "arc_st64" if is64 else "arc_st32"
        else:
            fn = {"uint8_t": "arc_st8", "uint16_t": "arc_st16"}[cast]
        return [f"{fn}({addr}, {self.read(s)});"] + self.writeback(insn, mem)

    def emit_pair(self, insn, ops, is_load) -> list[str]:
        a, b, mem = ops[0], ops[1], ops[2]
        if mem.type != a64.ARM64_OP_MEM:
            raise Unsupported("pair addressing")
        addr = self.mem_address(mem, insn)
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


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("library")
    ap.add_argument("--out", help="directory to write generated C into")
    ap.add_argument("--limit", type=int, default=0, help="only lift the first N")
    ap.add_argument("--report", action="store_true",
                    help="print coverage instead of writing code")
    args = ap.parse_args()

    with open(args.library, "rb") as fh:
        elf = ELFFile(fh)
        text = elf.get_section_by_name(".text")
        text_addr, blob = text["sh_addr"], text.data()
        funcs = functions_from_eh_frame(elf)

    lifter = Lifter()
    done = failed = 0
    chunks: list[str] = []
    for start, size in funcs:
        if args.limit and done + failed >= args.limit:
            break
        off = start - text_addr
        if off < 0 or off + size > len(blob):
            continue
        code = lifter.lift_function(start, size, blob[off:off + size])
        if code is None:
            failed += 1
        else:
            done += 1
            if args.out:
                chunks.append(code)

    total = done + failed
    print(f"functions   {total:,} attempted -- {done:,} complete "
          f"({done / total:.1%})" if total else "no functions")
    print(f"instructions {lifter.lifted:,} of {lifter.total:,} lifted "
          f"({lifter.lifted / lifter.total:.2%})" if lifter.total else "")
    if lifter.unsupported:
        print(f"\ntop unsupported forms ({len(lifter.unsupported)} distinct)")
        for name, n in lifter.unsupported.most_common(25):
            print(f"  {n:>9,}  {name}")

    if args.out and chunks:
        os.makedirs(args.out, exist_ok=True)
        path = os.path.join(args.out, "lifted.c")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write('#include "arm64_context.h"\n\n')
            fh.write("\n".join(chunks))
        print(f"\nwrote {path} ({len(chunks):,} functions)")


if __name__ == "__main__":
    main()
