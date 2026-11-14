#!/usr/bin/env python3
"""
Locates FNamePool clients in a build that keeps the object array chunked.

The pool lookup every UE5 build emits is

    Blocks[Id >> 16] + 2 * (Id & 0xFFFF)

so the instruction window around a `shr r32, 16` contains a movzx of the low
half and a *scale-8* indexed load. Anchor on `shr r32, 16`, then require the
window to carry both halves; print the disassembly of every survivor so the
actual decode (plain, xor, bswap) can be read off the instructions.

    python tools/find_fname.py --exe <path> [--dump N] [--around 0x40]
"""

import argparse
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

# shr r32, 16
SHR16 = [b"\xc1\xe8\x10", b"\xc1\xe9\x10", b"\xc1\xea\x10", b"\xc1\xeb\x10",
         b"\xc1\xef\x10", b"\xc1\xee\x10"]
# movzx e?x, ?x
MOVZX = [b"\x0f\xb7" + bytes([r]) for r in range(0xC0, 0xC8)]
# scaled qword load/add with scale 8 and disp32 == 0:
#   48/4C 8B/03 <modrm 84..BC> <sib C0..FF>
PREFIX = (b"\x48\x8b", b"\x4c\x8b", b"\x48\x03", b"\x4c\x03")


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


def scaled_load_at(buf, i):
    """is there a scale-8 indexed load at i? returns True"""
    if i + 4 > len(buf):
        return False
    if buf[i:i + 2] not in PREFIX:
        return False
    modrm = buf[i + 2]
    if (modrm & 0xC0) != 0x00 or (modrm & 0x07) != 0x04:
        return False
    return (buf[i + 3] & 0xC0) == 0xC0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", default=DEFAULT_EXE)
    ap.add_argument("--dump", type=int, default=0)
    ap.add_argument("--around", type=lambda s: int(s, 0), default=0x40)
    ap.add_argument("--limit", type=int, default=20)
    args = ap.parse_args()

    pe, secs = load(args.exe)
    text = secs[".text"]
    buf = text["data"]
    base = text["va"]

    print("exe %s" % args.exe)
    print("SizeOfImage 0x%X" % pe.OPTIONAL_HEADER.SizeOfImage)

    sites = []
    for pat in SHR16:
        start = 0
        while True:
            i = buf.find(pat, start)
            if i < 0:
                break
            start = i + 1
            lo = max(0, i - args.around)
            hi = min(len(buf), i + args.around)
            win = buf[lo:hi]
            if not any(p in win for p in MOVZX):
                continue
            if not any(scaled_load_at(win, k) for k in range(len(win) - 4)):
                continue
            sites.append(base + i)

    sites = sorted(set(sites))
    print("FNamePool resolve candidates: %d" % len(sites))
    for s in sites[:args.limit]:
        print("  .text+0x%X" % s)

    if args.dump:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True
        for s in sites[:args.dump]:
            lo = max(0, s - base - args.around)
            print("\n--- .text+0x%X ---" % s)
            for ins in md.disasm(buf[lo:lo + args.around * 2], base + lo):
                line = "  0x%08X  %-7s %s" % (ins.address, ins.mnemonic, ins.op_str)
                try:
                    for op in ins.operands:
                        if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                            tgt = (ins.address + ins.size + op.mem.disp) & 0xFFFFFFFF
                            line += "   ; -> 0x%X" % tgt
                except capstone.CsError:
                    pass
                print(line)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
