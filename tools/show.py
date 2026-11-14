#!/usr/bin/env python3
"""
Disassemble a range of a PE and label rip-relative targets with their section.

    python tools/show.py --exe <path> --rva 0x1A3B0 --len 0x120
    python tools/show.py --exe <path> --func 0x1A3B0          # whole function via .pdata

Used for reading the actual instructions behind a candidate site instead of
pattern-matching bytes and hoping.
"""

import argparse
import struct
import sys

import pefile

try:
    import capstone
except ImportError:
    sys.exit("pip install capstone")

DEFAULT_EXE = (
    r"D:\FN BUILDS\38.00-CL-47722112\FortniteGame\Binaries\Win64"
    r"\FortniteClient-Win64-Shipping.exe"
)


def load(path):
    pe = pefile.PE(path, fast_load=True)
    secs = {}
    for s in pe.sections:
        name = s.Name.rstrip(b"\0").decode("ascii", "replace") or "?"
        secs[name] = {
            "va": s.VirtualAddress,
            "data": pe.__data__[s.PointerToRawData:s.PointerToRawData + s.SizeOfRawData],
            "size": max(s.SizeOfRawData, s.Misc_VirtualSize),
        }
    return pe, secs


def which(secs, rva):
    for name, s in secs.items():
        if s["va"] <= rva < s["va"] + s["size"]:
            return "%s+0x%X" % (name, rva - s["va"])
    return None


def func_range(secs, rva):
    pd = secs.get(".pdata")
    if not pd:
        return None
    buf = pd["data"]
    for i in range(0, len(buf) - 12, 12):
        start, end, _ = struct.unpack_from("<III", buf, i)
        if start <= rva < end:
            return start, end
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", default=DEFAULT_EXE)
    ap.add_argument("--rva", type=lambda s: int(s, 0))
    ap.add_argument("--func", type=lambda s: int(s, 0))
    ap.add_argument("--len", type=lambda s: int(s, 0), default=0x100)
    ap.add_argument("--targets", action="store_true", help="only print rip-relative targets")
    args = ap.parse_args()

    pe, secs = load(args.exe)
    text = secs[".text"]

    start = args.func if args.func is not None else args.rva
    if start is None:
        sys.exit("need --rva or --func")

    if args.func is not None:
        r = func_range(secs, start)
        if r is None:
            sys.exit("no function at 0x%X" % start)
        start, end = r
    else:
        end = start + args.len

    code = text["data"][start - text["va"]:end - text["va"]]

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    md.skipdata = True

    print("func/rva 0x%X .. 0x%X (%d bytes)" % (start, end, len(code)))
    for ins in md.disasm(code, start):
        line = "  0x%08X  %-7s %s" % (ins.address, ins.mnemonic, ins.op_str)

        if ins.id == 0:      # skipdata pseudo-instruction: .operands raises
            print(line)
            continue

        for op in ins.operands:
            if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                tgt = (ins.address + ins.size + op.mem.disp) & 0xFFFFFFFF
                line += "      ; -> 0x%X %s" % (tgt, which(secs, tgt) or "?")
                if args.targets:
                    line = "  0x%08X  -> 0x%X %s" % (ins.address, tgt, which(secs, tgt) or "?")
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
