#!/usr/bin/env python3
"""
Finds FNamePool::Resolve (and therefore GNames + the block-table offset) by
requiring the two-instruction pair that every UE5 build emits:

    lea  rax, [rip + GNames]          ; static pool, or
    mov  rax, [rip + GNames]          ; pointer to a heap pool
    ...
    mov  rcx, [rax + rcx*8 + BLOCKS]  ; Blocks[Id >> 16]

The pair has to sit within a short window, which kills the noise from every
other scaled load in 287 MB of .text.

    python tools/find_pool.py --exe <path>
"""

import argparse
import sys

import pefile

DEFAULT_EXE = (
    r"D:\FN BUILDS\38.00-CL-47722112\FortniteGame\Binaries\Win64"
    r"\FortniteClient-Win64-Shipping.exe"
)

WINDOW = 0x40


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
            return name
    return None


def relocs(secs):
    """list of (insn_rva, target, kind) for the two global-load forms"""
    text = secs[".text"]
    buf = text["data"]
    base = text["va"]
    out = []
    for i in range(len(buf) - 7):
        b0, b1, b2 = buf[i], buf[i + 1], buf[i + 2]
        kind = None
        if b0 == 0x48 and b1 == 0x8D and b2 == 0x05:
            kind = "lea"
        elif b0 == 0x48 and b1 == 0x8B and b2 == 0x05:
            kind = "mov"
        elif b0 == 0x4C and b1 == 0x8D and b2 == 0x05:
            kind = "lea"
        elif b0 == 0x4C and b1 == 0x8B and b2 == 0x05:
            kind = "mov"
        if not kind:
            continue
        disp = int.from_bytes(buf[i + 3:i + 7], "little", signed=True)
        out.append((base + i, (base + i + 7 + disp) & 0xFFFFFFFF, kind))
    return out


def scaled_loads(secs):
    """mov r64, [r64 + r64*8 + disp32] -> (insn_rva, base_reg, index_reg, disp)"""
    text = secs[".text"]
    buf = text["data"]
    base = text["va"]
    regs = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"]
    out = []
    for i in range(len(buf) - 8):
        if buf[i] != 0x48 or buf[i + 1] != 0x8B:
            continue
        modrm = buf[i + 2]
        if (modrm & 0xC7) != 0x84:
            continue
        sib = buf[i + 3]
        if (sib & 0xC0) != 0xC0:
            continue
        breg = regs[sib & 7]
        ireg = regs[(sib >> 3) & 7]
        disp = int.from_bytes(buf[i + 4:i + 8], "little", signed=True)
        out.append((base + i, breg, ireg, disp))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", default=DEFAULT_EXE)
    ap.add_argument("--window", type=lambda s: int(s, 0), default=WINDOW)
    args = ap.parse_args()

    pe, secs = load(args.exe)
    print("exe %s" % args.exe)
    print("SizeOfImage 0x%X" % pe.OPTIONAL_HEADER.SizeOfImage)

    g = relocs(secs)
    s = scaled_loads(secs)
    print("globals %d   scaled loads %d" % (len(g), len(s)))
    print()

    by_reg = {}
    for rva, tgt, kind in g:
        sec = which(secs, tgt)
        if sec in (".data", ".rdata", ".bss"):
            by_reg.setdefault(rva, (tgt, kind))

    results = []
    for insn, breg, ireg, disp in s:
        if not (0 <= disp <= 0x8000):
            continue
        for rva, tgt, kind in g:
            d = insn - rva
            if 0 < d <= args.window:
                results.append((insn, disp, tgt, kind, d, breg))
                break

    print("lea/mov GNames + Blocks[..] pairs within 0x%X:" % args.window)
    seen = set()
    for insn, disp, tgt, kind, d, breg in results:
        key = (tgt, disp)
        mark = ""
        if key in seen:
            mark = " (dup)"
        seen.add(key)
        print("  pool 0x%08X (%s+0x%X, %s)  blocks +0x%04X  site .text+0x%X  delta 0x%X  base=%s%s" % (
            tgt, which(secs, tgt), tgt - secs[which(secs, tgt)]["va"], kind,
            disp, insn, d, breg, mark))
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
