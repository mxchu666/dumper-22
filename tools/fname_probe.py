#!/usr/bin/env python3
"""
FName probe for an arbitrary Fortnite client.

Answers three questions with evidence instead of a guess:

  A. Is the 42.40-style id decode (`dec eax / xor eax, imm / bswap / inc eax`)
     present?        -> obfuscated ids, same family as 42.40
  B. Is there any bswap inside a name-pool-shaped function?  -> different family
  C. What displacements do the scale-8 indexed qword loads actually use?
     A plain UE5 pool resolves at +0x08 or +0x10 from the pool base; a large
     displacement means the pool is embedded in a wrapper object.

    python tools/fname_probe.py --exe <path> [--dump N]
"""

import argparse
import sys
from collections import Counter

import pefile

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
            return "%s" % name
    return "?"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", default=DEFAULT_EXE)
    ap.add_argument("--dump", type=int, default=0)
    args = ap.parse_args()

    pe, secs = load(args.exe)
    text = secs[".text"]
    buf = text["data"]
    base = text["va"]

    print("exe %s" % args.exe)
    print("SizeOfImage 0x%X" % pe.OPTIONAL_HEADER.SizeOfImage)
    print()

    # ---- A: 42.40 id decode family
    a = []
    for i in range(len(buf) - 10):
        if buf[i] == 0xFF and buf[i + 1] == 0xC8 and buf[i + 2] == 0x35:
            if buf[i + 7:i + 11] == b"\x0f\xc8\xff\xc0":
                a.append((base + i, int.from_bytes(buf[i + 3:i + 7], "little")))
    print("A. dec/xor/bswap/inc id decode : %d sites" % len(a))
    for rva, key in a[:8]:
        print("     .text+0x%X  key 0x%08X" % (rva, key))
    print()

    # ---- B: bswap32 anywhere
    b = [base + i for i in range(len(buf) - 2) if buf[i] == 0x0F and buf[i + 1] == 0xC8]
    print("B. bswap r32 anywhere          : %d sites" % len(b))
    print()

    # ---- C: scale-8 indexed qword load displacement histogram
    hist = Counter()
    sites = []
    for i in range(len(buf) - 8):
        if buf[i] not in (0x48, 0x4C) or buf[i + 1] not in (0x8B, 0x03):
            continue
        modrm = buf[i + 2]
        if (modrm & 0x07) != 0x04:
            continue
        sib = buf[i + 3]
        if (sib & 0xC0) != 0xC0:
            continue
        mod = modrm & 0xC0
        if mod == 0x00:
            disp = 0
            n = 4
        elif mod == 0x40:
            disp = int.from_bytes(buf[i + 4:i + 5], "little", signed=True)
            n = 5
        else:
            disp = int.from_bytes(buf[i + 4:i + 8], "little", signed=True)
            n = 8
        hist[disp] += 1
        if 0 <= disp <= 0x8000:
            sites.append((base + i, disp, n, bytes(buf[i:i + n])))

    print("C. scale-8 indexed qword loads : %d sites" % sum(hist.values()))
    print("   displacement histogram (top 20):")
    for disp, n in hist.most_common(20):
        print("     disp 0x%06X  x%d" % (disp & 0xFFFFFFFFFFFFFFFF if disp >= 0 else disp, n))
    print()

    small = [s for s in sites if s[1] <= 0x20]
    print("   small-disp sites (<= 0x20): %d" % len(small))
    for rva, disp, n, raw in small[:12]:
        print("     .text+0x%X  disp 0x%X  bytes %s" % (rva, disp, raw.hex()))

    if args.dump:
        try:
            import capstone
        except ImportError:
            print("\ncapstone missing")
            return 0
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True
        for rva, disp, n, raw in small[:args.dump]:
            lo = rva - base - 0x30
            print("\n--- .text+0x%X (disp 0x%X) ---" % (rva, disp))
            for ins in md.disasm(buf[lo:lo + 0x70], base + lo):
                line = "  0x%08X  %-7s %s" % (ins.address, ins.mnemonic, ins.op_str)
                try:
                    for op in ins.operands:
                        if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                            tgt = (ins.address + ins.size + op.mem.disp) & 0xFFFFFFFF
                            line += "   ; -> 0x%X %s" % (tgt, which(secs, tgt))
                except capstone.CsError:
                    pass
                print(line)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
