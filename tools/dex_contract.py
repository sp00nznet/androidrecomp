#!/usr/bin/env python3
"""Recover the signatures of a title's JNI entry points from its dex files.

`arc_host` reports the *names* a library exports, which is enough to know what
the Java shell used to call. It is not enough to call them: a JNI entry point
takes a JNIEnv, the object it was invoked on, and then whatever the Java
declaration says -- paths, handles, dimensions. Passing zeros instead means the
engine reads a configuration it was promised and finds nothing, which is
indistinguishable from a porting bug until you look this up.

The declarations live in the APK's dex. This reads just enough of that format
to answer the question: for a class, every method it declares and the types it
takes.

    python tools/dex_contract.py game.apk --class com.example.Bridge
    python tools/dex_contract.py extracted/classes.dex --grep JNIBridge
"""
from __future__ import annotations

import argparse
import io
import struct
import sys
import zipfile

# Field order after magic(8), checksum(4) and signature(20).
HEADER = ("file_size header_size endian_tag link_size link_off map_off "
          "string_ids_size string_ids_off type_ids_size type_ids_off "
          "proto_ids_size proto_ids_off field_ids_size field_ids_off "
          "method_ids_size method_ids_off class_defs_size class_defs_off "
          "data_size data_off").split()

TYPES = {"V": "void", "Z": "boolean", "B": "byte", "S": "short", "C": "char",
         "I": "int", "J": "long", "F": "float", "D": "double"}


def uleb128(data: bytes, at: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        b = data[at]
        at += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, at
        shift += 7



ACC_NATIVE = 0x100


def mangle(text: str) -> str:
    """JNI's escaping for a name component."""
    out = []
    for ch in text:
        if ch == "_":
            out.append("_1")
        elif ch == ";":
            out.append("_2")
        elif ch == "[":
            out.append("_3")
        elif ch == "/" or ch == ".":
            out.append("_")
        elif ch.isalnum():
            out.append(ch)
        else:
            out.append(f"_0{ord(ch):04x}")
    return "".join(out)


def jni_name(klass: str, method: str, params: list[str] | None) -> str:
    """The exported symbol for a native method.

    The short form is only correct when the name is unique. An overloaded
    native method exports the long form, with the parameter descriptors mangled
    on after a double underscore -- so a contract that assumed the short form
    would name a symbol that is not in the library.
    """
    name = f"Java_{mangle(klass)}_{mangle(method)}"
    if params is None:
        return name
    return name + "__" + "".join(mangle(p) for p in params)


class Dex:
    def __init__(self, blob: bytes):
        if blob[:4] != b"dex\n":
            raise ValueError("not a dex file")
        self.blob = blob
        values = struct.unpack_from("<20I", blob, 32)
        self.h = dict(zip(HEADER, values))

    def string(self, index: int) -> str:
        off = struct.unpack_from("<I", self.blob,
                                 self.h["string_ids_off"] + index * 4)[0]
        _, at = uleb128(self.blob, off)
        end = self.blob.index(b"\0", at)
        # MUTF-8; the surrogate forms only show up in string constants, not in
        # the descriptors this tool reads.
        return self.blob[at:end].decode("utf-8", "replace")

    def type_name(self, index: int) -> str:
        d = self.string(struct.unpack_from(
            "<I", self.blob, self.h["type_ids_off"] + index * 4)[0])
        return self.describe(d)

    @staticmethod
    def describe(d: str) -> str:
        arrays = 0
        while d.startswith("["):
            arrays += 1
            d = d[1:]
        if d in TYPES:
            base = TYPES[d]
        elif d.startswith("L") and d.endswith(";"):
            base = d[1:-1].replace("/", ".")
        else:
            base = d
        return base + "[]" * arrays

    def raw_type(self, index: int) -> str:
        return self.string(struct.unpack_from(
            "<I", self.blob, self.h["type_ids_off"] + index * 4)[0])

    def raw_proto(self, index: int) -> list[str]:
        base = self.h["proto_ids_off"] + index * 12
        _, _, params_off = struct.unpack_from("<3I", self.blob, base)
        if not params_off:
            return []
        count = struct.unpack_from("<I", self.blob, params_off)[0]
        return [self.raw_type(struct.unpack_from(
            "<H", self.blob, params_off + 4 + i * 2)[0]) for i in range(count)]

    def method_at(self, index: int):
        base = self.h["method_ids_off"] + index * 8
        class_idx, proto_idx, name_idx = struct.unpack_from("<HHI", self.blob,
                                                            base)
        return (self.raw_type(class_idx), self.string(name_idx), proto_idx)

    def native_methods(self):
        """(class, method, parameter descriptors) for every native method.

        A contract has to be built from these and not from the method table:
        the method table lists everything the dex mentions, most of which is
        ordinary Java with no exported symbol behind it.
        """
        for i in range(self.h["class_defs_size"]):
            base = self.h["class_defs_off"] + i * 32
            data_off = struct.unpack_from("<I", self.blob, base + 24)[0]
            if not data_off:
                continue
            at = data_off
            counts = []
            for _ in range(4):
                value, at = uleb128(self.blob, at)
                counts.append(value)
            static_fields, instance_fields, direct, virtual = counts
            for _ in range(static_fields + instance_fields):
                _, at = uleb128(self.blob, at)  # field_idx_diff
                _, at = uleb128(self.blob, at)  # access_flags
            for count in (direct, virtual):
                index = 0
                for _ in range(count):
                    diff, at = uleb128(self.blob, at)
                    flags, at = uleb128(self.blob, at)
                    _, at = uleb128(self.blob, at)  # code_off
                    index += diff
                    if flags & ACC_NATIVE:
                        klass, name, proto_idx = self.method_at(index)
                        yield klass, name, self.raw_proto(proto_idx)

    def proto(self, index: int) -> tuple[str, list[str]]:
        base = self.h["proto_ids_off"] + index * 12
        _, ret_idx, params_off = struct.unpack_from("<3I", self.blob, base)
        params = []
        if params_off:
            count = struct.unpack_from("<I", self.blob, params_off)[0]
            for i in range(count):
                t = struct.unpack_from("<H", self.blob, params_off + 4 + i * 2)[0]
                params.append(self.type_name(t))
        return self.type_name(ret_idx), params

    def fields(self):
        for i in range(self.h["field_ids_size"]):
            base = self.h["field_ids_off"] + i * 8
            class_idx, type_idx, name_idx = struct.unpack_from("<HHI", self.blob,
                                                               base)
            yield (self.type_name(class_idx), self.string(name_idx),
                   self.type_name(type_idx))

    def methods(self):
        for i in range(self.h["method_ids_size"]):
            base = self.h["method_ids_off"] + i * 8
            class_idx, proto_idx, name_idx = struct.unpack_from("<HHI", self.blob,
                                                                base)
            yield (self.type_name(class_idx), self.string(name_idx),
                   self.proto(proto_idx))


def dex_blobs(path: str):
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            for name in sorted(z.namelist()):
                if name.endswith(".dex"):
                    yield name, z.read(name)
        return
    with open(path, "rb") as fh:
        yield path, fh.read()



def library_exports(paths: list[str]) -> set[str]:
    """The `Java_*` symbols a package's libraries actually export.

    Takes every library rather than one, because "not in this .so" and "not in
    the package" are different answers and only the second one means anything.
    """
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        sys.exit("cross-checking needs pyelftools")
    found: set[str] = set()
    for path in paths:
        with open(path, "rb") as fh:
            elf = ELFFile(fh)
            table = elf.get_section_by_name(".dynsym")
            if table is None:
                continue
            found |= {sym.name for sym in table.iter_symbols()
                      if sym.name.startswith("Java_")
                      and sym["st_shndx"] != "SHN_UNDEF"}
    return found


def report_disagreement(declared: set[str], exported: set[str]) -> None:
    """Say where the two sources of truth differ, and why they might.

    A dex says what *this* package declares native, with signatures. A library
    says what the engine makes available. They are not the same list and
    neither contains the other, because one binary is usually built once and
    shipped to several storefronts: the exports are the union across those
    builds, while any single package's dex declares only its own.

    So the intersection is what can be called *and* is known to be wanted here,
    and each difference is worth a line rather than a silent choice.
    """
    only_dex = sorted(declared - exported)
    only_lib = sorted(exported - declared)
    if only_dex:
        print(f"\n# {len(only_dex)} declared native here but exported by none "
              "of the libraries checked.")
        print("#   Pass every .so in the package before reading anything into")
        print("#   this: a package declares natives for all of them at once.")
        print("#   If it still comes up empty, the remaining explanation is")
        print("#   that they are bound through RegisterNatives rather than by")
        print("#   name -- a method registered that way needs no export at")
        print("#   all -- or that they are simply unused in this build. Either")
        print("#   way there is no symbol for a host to call, so they cannot")
        print("#   go in a contract.")
        for name in only_dex:
            print(f"#   {name}")
    if only_lib:
        print(f"\n# {len(only_lib)} exported by the library but not declared "
              "native in this package:")
        print("#   most likely another storefront's build -- the library is "
              "shared, the dex is not.")
        for name in only_lib:
            print(f"#   {name}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", help="an .apk or a .dex")
    ap.add_argument("--class", dest="klass", help="exact class name")
    ap.add_argument("--grep", help="substring of the class name")
    ap.add_argument("--fields", action="store_true",
                    help="list the class's fields instead of its methods")
    ap.add_argument("--contract", action="store_true",
                    help="emit a contract file of native entry points")
    ap.add_argument("--library", nargs="+", metavar="SO",
                    help="cross-check against the exports of these libraries; "
                         "pass every .so in the package, not just the engine")
    args = ap.parse_args()

    # A contract is normally wanted whole: every native entry point the package
    # declares, which is the thing a host has to be able to call. Filters are
    # available but not required for it.
    if not args.klass and not args.grep and not args.contract:
        sys.exit("give --class or --grep, or --contract for all of them")

    found = 0
    declared_all: set[str] = set()
    for name, blob in dex_blobs(args.target):
        try:
            dex = Dex(blob)
        except ValueError:
            continue
        seen = set()
        if args.contract:
            # Group by class first, so an overloaded name can be spotted -- it
            # is the difference between the short exported symbol and the long
            # one.
            by_name: dict[tuple[str, str], list[list[str]]] = {}
            for klass, method, params in dex.native_methods():
                pretty = Dex.describe(klass)
                if args.klass and pretty != args.klass:
                    continue
                if args.grep and args.grep not in pretty:
                    continue
                by_name.setdefault((klass, method), []).append(params)
            # Accumulated across every dex, not emitted per dex. A package is
            # routinely multidex, and a name declared in one of them is not
            # missing from the others -- reporting per file would call most of
            # the contract absent five times over.
            for (klass, method), overloads in sorted(by_name.items()):
                inner = klass[1:-1] if klass.startswith("L") else klass
                for params in overloads:
                    declared_all.add(jni_name(inner, method,
                                              params if len(overloads) > 1 else None))
            continue
        if args.fields:
            for klass, field, ftype in dex.fields():
                if args.klass and klass != args.klass:
                    continue
                if args.grep and args.grep not in klass:
                    continue
                if (klass, field) in seen:
                    continue
                seen.add((klass, field))
                print(f"{ftype} {klass}.{field}")
                found += 1
            continue
        for klass, method, (ret, params) in dex.methods():
            if args.klass and klass != args.klass:
                continue
            if args.grep and args.grep not in klass:
                continue
            key = (klass, method, ret, tuple(params))
            if key in seen:
                continue
            seen.add(key)
            if found == 0 or klass not in {k for k, *_ in seen}:
                pass
            print(f"{klass}.{method}({', '.join(params)}) -> {ret}")
            found += 1
    if args.contract:
        exported = library_exports(args.library) if args.library else None
        emit = sorted(declared_all & exported) if exported is not None \
            else sorted(declared_all)
        for name in emit:
            print(name)
        found = len(emit)
        if exported is not None:
            report_disagreement(declared_all, exported)

    if not found:
        print("no matching class found", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
