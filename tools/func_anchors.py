#!/usr/bin/env python3
"""
Function-scoped recon using the PE exception directory (.pdata).

Every RUNTIME_FUNCTION gives an exact [start, end) range, so an idiom can be
required to live inside one function instead of "somewhere in 270 MB of .text".

Idioms:

  FNamePool::Resolve(Id)
      Blocks[Id >> 16] + 2 * (Id & 0xFFFF)
      -> function contains  shr r32, 16  AND  a scaled qword load
         mov r64, [r64 + r64*8 + disp32]

  FUObjectArray access
      -> function contains a cmp/mov against [rip+T+0x14] (NumElements)
         AND a qword load from a global (Objects) AND stride 0x18 or *8 chunk index

    python tools/func_anchors.py --exe <path> [--idiom name|objects]
"""

import argparse
import struct
import sys
from collections import defaultdict

import pefile

DEFAULT_EXE = (
    r"D:\FN BUILDS\38.00-CL-47722112\FortniteGame\Binaries\Win64"
    r"\FortniteClient-Win64-Shipping.exe"
)


def load(path):
    pe = pefile.PE(path, fast_load=True)
    secs = {}
    for s in pe.sections:
        name = s.Name.rstrip(b"\0").decode("ascii", "replace")
        secs[name] = {
            "va": s.VirtualAddress,
            "data": pe.__data__[s.PointerToRawData:s.PointerToRawData + s.SizeOfRawData],
            "size": max(s.SizeOfRawData, s.Misc_VirtualSize),
        }
    return pe, secs


def runtime_functions(secs):
    pd = secs.get(".pdata")
    if not pd:
        return []
    buf = pd["data"]
    out = []
    for i in range(0, len(buf) - 12, 12):
        start, end, unwind = struct.unpack_from("<III", buf, i)
        if start == 0 or end <= start:
            continue
        out.append((start, end))
    out.sort()
    return out


def slice_of(text, base, start, end):
    lo = start - base
    hi = end - base
    if lo < 0 or hi > len(text) or hi <= lo:
        return None
    return text[lo:hi]


def find_scaled_loads(buf):
    """mov r64, [r64 + r64*8 + disp32]  ->  [(offset, disp)]"""
    out = []
    for i in range(len(buf) - 8):
        if buf[i] != 0x48 or buf[i + 1] != 0x8B:
            continue
        modrm = buf[i + 2]
        if (modrm & 0xC7) != 0x84:          # mod=10, reg=any, rm=100 (SIB)
            continue
        sib = buf[i + 3]
        if (sib & 0xC0) != 0xC0:            # scale == 8
            continue
        out.append((i, int.from_bytes(buf[i + 4:i + 8], "little", signed=True)))
    return out


SHR16 = (b"\xc1\xe8\x10", b"\xc1\xe9\x10", b"\xc1\xea\x10", b"\xc1\xeb\x10",
         b"\xc1\xef\x10", b"\xc1\xee\x10")
AND_FFFF = (b"\x25\xff\xff\x00\x00", b"\x0f\xb7\xc0", b"\x0f\xb7\xc1",
            b"\x0f\xb7\xc2", b"\x0f\xb7\xc3", b"\x0f\xb7\xc8", b"\x0f\xb7\xca")


def idiom_name(text, base, funcs):
    hits = []
    for start, end in funcs:
        buf = slice_of(text, base, start, end)
        if not buf or len(buf) > 0x8000:
            continue
        if not any(p in buf for p in SHR16):
            continue
        if not any(p in buf for p in AND_FFFF):
            continue
        loads = find_scaled_loads(buf)
        if not loads:
            continue
        for off, disp in loads:
            if 0 <= disp <= 0x8000:
                hits.append((start, end, disp))
                break
    return hits


def idiom_objects(text, base, funcs):
    num = re.compile(rb"[\x8b\x3b\x39][\x05\x0d\x15\x1d\x25\x2d\x35\x3d](.{4})", re.S)
    stride = re.compile(rb"\x48\x6b[\xc0-\xff]\x18|\x48\x8d[\x04-\x3f][\x40-\x7f]\x00\x48\xc1\xe0\x03")

    for start, end in funcs:
        buf = slice_of(text, base, start, end)
        if not buf or len(buf) > 0x8000:
            continue
        if not stride.search(buf):
            continue
        for m in num.finditer(buf):
            insn_end = m.start() + 6
            disp = int.from_bytes(m.group(1), "little", signed=True)
            target = (base + start + insn_end + disp) & 0xFFFFFFFF
            hits.append((start, end, target))
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", default=DEFAULT_EXE)
    ap.add_argument("--idiom", default="all")
    ap.add_argument("--limit", type=int, default=40)
    args = ap.parse_args()

    pe, secs = load(args.exe)
    text = secs[".text"]
    funcs = runtime_functions(secs)

    print("exe %s" % args.exe)
    print("SizeOfImage 0x%X  functions %d" % (pe.OPTIONAL_HEADER.SizeOfImage, len(funcs)))
    print()

    if args.idiom in ("all", "name"):
        names = idiom_name(text["data"], text["va"], funcs)
        print("FNamePool::Resolve candidates (shr16 + andFFFF + scaled load in one function): %d" % len(names))
        by_disp = defaultdict(list)
        for start, end, disp in names:
            by_disp[disp].append((start, end))
        for disp, lst in sorted(by_disp.items(), key=lambda kv: -len(kv[1]))[:args.limit]:
            print("  disp 0x%04X  functions %d   first 0x%X-0x%X (len 0x%X)" % (
                disp, len(lst), lst[0][0], lst[0][1], lst[0][1] - lst[0][0]))
        print()

    if args.idiom in ("all", "objects"):
        objs = idiom_objects(text["data"], text["va"], funcs)
        print("FUObjectArray candidates (stride 0x18 + NumElements-style rip access): %d" % len(objs))
        seen = set()
        shown = 0
        for start, end, target in objs:
            key = (target - 0x14, target)
            if key in seen:
                continue
            seen.add(key)
            print("  func 0x%06X-0x%06X  NumElements-ish target 0x%08X" % (start, end, target))
            shown += 1
            if shown >= args.limit:
                break
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
