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


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", help="an .apk or a .dex")
    ap.add_argument("--class", dest="klass", help="exact class name")
    ap.add_argument("--grep", help="substring of the class name")
    ap.add_argument("--fields", action="store_true",
                    help="list the class's fields instead of its methods")
    args = ap.parse_args()

    if not args.klass and not args.grep:
        sys.exit("give --class or --grep")

    found = 0
    for name, blob in dex_blobs(args.target):
        try:
            dex = Dex(blob)
        except ValueError:
            continue
        seen = set()
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
    if not found:
        print("no matching class found", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
