#!/usr/bin/env python3
"""
Plain-UE5 FNamePool::Resolve test.

A non-obfuscated build resolves a name id as:

    Blocks[Id >> 16] + 2 * (Id & 0xFFFF)

which the compiler emits as `movzx eax, ax` followed by

    lea rcx, [rcx + rax*2]        ; 48 8D 0C 41
    lea rdx, [rdx + rax*2]        ; 48 8D 14 42
    ...

An obfuscated build (42.40) adds `bswap` + `xor` + `-1/+1` around the id first.

    python tools/plain_fname.py --exe <path> [--dump N]
"""

import argparse
import sys

import pefile

DEFAULT_EXE = (
    r"D:\FN BUILDS\38.00-CL-47722112\FortniteGame\Binaries\Win64"
    r"\FortniteClient-Win64-Shipping.exe"
)

LEA_SCALED2 = b"\x48\x8d"     # prefix; third byte encodes reg/reg and scale


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


def decode_lea_scaled2(buf, i):
    """return (dst, src, index) if 48 8D <modrm> <sib> is `lea dst,[src+index*2]`"""
    if buf[i] != 0x48 or buf[i + 1] != 0x8D:
        return None
    modrm = buf[i + 2]
    if (modrm & 0xC7) != 0x04:      # mod=00, rm=100 (SIB), no disp
        return None
    sib = buf[i + 3]
    scale = sib >> 6
    if scale != 1:                  # *2
        return None
    dst = (modrm >> 3) & 7
    index = (sib >> 3) & 7
    base = sib & 7
    if index == 4:                  # no index
        return None
    return dst, base, index


REGS = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", default=DEFAULT_EXE)
    ap.add_argument("--dump", type=int, default=0, help="disassemble N hits (needs capstone)")
    args = ap.parse_args()

    pe, secs = load(args.exe)
    text = secs[".text"]
    buf = text["data"]
    base = text["va"]

    print("exe %s" % args.exe)
    print("SizeOfImage 0x%X  .text 0x%X" % (pe.OPTIONAL_HEADER.SizeOfImage, len(buf)))
    print()

    # movzx e?x, ax / cx / dx  == 0F B7 C0/C1/C2
    movzx = []
    for i in range(len(buf) - 4):
        if buf[i] == 0x0F and buf[i + 1] == 0xB7 and 0xC0 <= buf[i + 2] <= 0xC2:
            movzx.append(i)

    # also `and e?x, 0xFFFF` == 81 E0..E2 FF FF 00 00
    andmask = []
    for i in range(len(buf) - 7):
        if buf[i] == 0x81 and buf[i + 1] in (0xE0, 0xE1, 0xE2) and buf[i + 2:i + 6] == b"\xff\xff\x00\x00":
            andmask.append(i)

    print("movzx32,16 sites %d   and-0xFFFF sites %d" % (len(movzx), len(andmask)))

    hits = []
    for i in movzx + andmask:
        for j in range(i + 2, min(i + 0x30, len(buf) - 4)):
            r = decode_lea_scaled2(buf, j)
            if r:
                dst, breg, ireg = r
                hits.append((base + i, base + j, REGS[breg], REGS[ireg]))
                break

    print("movzx/and + lea [base + idx*2] pairs: %d" % len(hits))
    for a, b, breg, ireg in hits[:25]:
        print("  movzx/and .text+0x%X   lea [%s + %s*2] .text+0x%X" % (a, breg, ireg, b))

    if args.dump and hits:
        try:
            import capstone
        except ImportError:
            print("\ncapstone not installed")
            return 0
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        for a, b, _, _ in hits[:args.dump]:
            start = max(0, a - base - 0x30)
            print("\n--- around .text+0x%X ---" % a)
            for ins in md.disasm(buf[start:start + 0xA0], base + start):
                print("  0x%08X  %-7s %s" % (ins.address, ins.mnemonic, ins.op_str))
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
