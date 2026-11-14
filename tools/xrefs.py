#!/usr/bin/env python3
"""
Cross-references to a global inside a PE, over every rip-relative instruction.

    python tools/xrefs.py --exe <path> --target 0x16C1C5C0 [--dump N] [--len 0x60]

Prints each site with the instruction form, and with --dump disassembles a
window starting at each site so the calling code can be read directly.
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

# every rip-relative form that can name a global
FORMS = [
    (b"\x48\x8D\x05", 7, "lea r64"),
    (b"\x4C\x8D\x05", 7, "lea r64"),
    (b"\x48\x8B\x05", 7, "mov r64"),
    (b"\x4C\x8B\x05", 7, "mov r64"),
    (b"\x8B\x05", 6, "mov r32"),
    (b"\x89\x05", 6, "mov [g], r32"),
    (b"\x48\x89\x05", 7, "mov [g], r64"),
    (b"\x48\x8D\x0D", 7, "lea r64"),
    (b"\x48\x8D\x15", 7, "lea r64"),
    (b"\x48\x8D\x35", 7, "lea r64"),
    (b"\x48\x8D\x3D", 7, "lea r64"),
    (b"\x48\x8D\x1D", 7, "lea r64"),
    (b"\x8D\x0D", 6, "lea r32"),
    (b"\x8D\x15", 6, "lea r32"),
    (b"\x3B\x05", 6, "cmp r32"),
    (b"\x39\x05", 6, "cmp [g], r32"),
]


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", default=DEFAULT_EXE)
    ap.add_argument("--target", type=lambda s: int(s, 0), required=True)
    ap.add_argument("--dump", type=int, default=0)
    ap.add_argument("--len", type=lambda s: int(s, 0), default=0x50)
    args = ap.parse_args()

    pe, secs = load(args.exe)
    text = secs[".text"]
    buf = text["data"]
    base = text["va"]

    sites = []
    for form, n, kind in FORMS:
        start = 0
        while True:
            i = buf.find(form, start)
            if i < 0:
                break
            start = i + 1
            if i + n > len(buf):
                continue
            disp = int.from_bytes(buf[i + n - 4:i + n], "little", signed=True)
            if ((base + i + n + disp) & 0xFFFFFFFF) == args.target:
                sites.append((base + i, kind))

    sites.sort()
    print("target 0x%X  xrefs %d" % (args.target, len(sites)))
    for rva, kind in sites:
        print("  .text+0x%-8X %s" % (rva, kind))

    if args.dump:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        md.detail = True
        for rva, kind in sites[:args.dump]:
            lo = max(0, rva - base)
            print("\n--- .text+0x%X (%s) ---" % (rva, kind))
            for ins in md.disasm(buf[lo:lo + args.len], rva):
                print("  0x%08X  %-7s %s" % (ins.address, ins.mnemonic, ins.op_str))
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
