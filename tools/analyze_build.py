#!/usr/bin/env python3
"""
Deep static recon of a Fortnite client executable.

    python tools/analyze_build.py                 # 38.00 default
    python tools/analyze_build.py --exe <path>
    python tools/analyze_build.py --section text  # dump section table only

Prints, in order:
  1. PE section table + SizeOfImage
  2. candidates for FUObjectArray (chunked index math, 0x18 item stride)
  3. candidates for FNamePool access (shr 0x10 / and 0xFFFF + block table)
  4. candidate GObjects globals (hot .data references from .text)
  5. the raw bytes + disassembly of every hit window

Nothing is assumed about the obfuscation scheme: the script looks for the
*shape* of the code (index math + pointer split) instead of literal keys.
"""

import argparse
import re
import sys
from collections import Counter

import pefile

DEFAULT_EXE = (
    r"D:\FN BUILDS\38.00-CL-47722112\FortniteGame\Binaries\Win64"
    r"\FortniteClient-Win64-Shipping.exe"
)


def load(path):
    pe = pefile.PE(path, fast_load=True)
    secs = []
    for s in pe.sections:
        name = s.Name.rstrip(b"\0").decode("ascii", "replace")
        secs.append(
            {
                "name": name,
                "va": s.VirtualAddress,
                "raw": s.PointerToRawData,
                "rsize": s.SizeOfRawData,
                "vsize": s.Misc_VirtualSize,
                "data": pe.__data__[s.PointerToRawData:s.PointerToRawData + s.SizeOfRawData],
            }
        )
    return pe, secs


def section_table(pe, secs):
    print("SizeOfImage 0x%X" % pe.OPTIONAL_HEADER.SizeOfImage)
    print("ImageBase   0x%X" % pe.OPTIONAL_HEADER.ImageBase)
    print("%-10s %-12s %-12s %-12s" % ("name", "VA", "rawsize", "vsize"))
    for s in secs:
        print("%-10s 0x%08X   0x%08X   0x%08X" % (s["name"], s["va"], s["rsize"], s["vsize"]))
    print()


def rip(insn_rva, disp):
    return (insn_rva + disp) & 0xFFFFFFFF


def scan(secs):
    text = next(s for s in secs if s["name"] == ".text")
    buf = text["data"]
    base = text["va"]

    hits = {}

    # ---- FUObjectItem stride 0x18 (imul reg, reg, 0x18)
    imul18 = []
    for m in re.finditer(rb"\x48\x6b[\xc0-\xff]\x18", buf):
        imul18.append(base + m.start())
    # lea r,[r+r*2] ; shl 3  == *0x18
    for m in re.finditer(rb"\x48\x8d[\x04-\x3f][\x40-\x7f]\x00?[\x48\xc1\xe0\x03]", buf):
        imul18.append(base + m.start())
    hits["item_stride_0x18"] = imul18

    # ---- block table indexed load  mov r64, [r64 + r64*8 + disp32]
    blocks = []
    for m in re.finditer(rb"\x48\x8b[\x84\x8c\x94\x9c\xb4\xbc\xa4\xac]([\xc0-\xff])(.{4})", buf, re.S):
        disp = int.from_bytes(m.group(2), "little", signed=True)
        blocks.append((base + m.start(), disp))
    hits["indexed_qword_load"] = blocks

    # ---- FName id math: shr eax, 10
    shr10 = [base + m.start() for m in re.finditer(rb"\xc1\xe8\x10", buf)]
    hits["shr_eax_10"] = shr10

    # ---- and eax, 0xFFFF
    andffff = [base + m.start() for m in re.finditer(rb"\x25\xff\xff\x00\x00", buf)]
    hits["and_eax_ffff"] = andffff

    # ---- movzx ..., word  (id & 0xFFFF via movzx)
    movzx16 = [base + m.start() for m in re.finditer(rb"\x0f\xb7[\xc0-\xff]?", buf)]
    hits["movzx16"] = movzx16

    # ---- bswap 32 / bswap 64
    bswap32 = [base + m.start() for m in re.finditer(rb"\x0f\xc8", buf)]
    bswap64 = [base + m.start() for m in re.finditer(rb"\x48\x0f\xc8", buf)]
    hits["bswap32"] = bswap32
    hits["bswap64"] = bswap64

    # ---- lea r64, [rip+disp32]
    leas = []
    for m in re.finditer(rb"\x48\x8d\x05(.{4})", buf, re.S):
        leas.append((base + m.start(), rip(base + m.start() + 7, int.from_bytes(m.group(1), "little", signed=True))))
    hits["lea_rip"] = leas

    # ---- mov r64, [rip+disp32]
    movs = []
    for m in re.finditer(rb"\x48\x8b\x05(.{4})", buf, re.S):
        movs.append((base + m.start(), rip(base + m.start() + 7, int.from_bytes(m.group(1), "little", signed=True))))
    hits["mov_rip"] = movs

    return hits


def report(hits, secs):
    print("=" * 78)
    print("counts")
    for k, v in hits.items():
        print("  %-22s %d" % (k, len(v)))
    print()

    data_ranges = [(s["va"], s["va"] + max(s["rsize"], s["vsize"]), s["name"]) for s in secs]

    def where(rva):
        for lo, hi, name in data_ranges:
            if lo <= rva < hi:
                return name
        return "?"

    print("=" * 78)
    print("indexed qword loads (block-table candidates), disp <= 0x10000")
    for rva, disp in hits["indexed_qword_load"]:
        if 0 <= disp <= 0x10000:
            print("  .text+0x%X  disp 0x%X" % (rva, disp))
    print()

    print("=" * 78)
    print("lea rip targets into .data/.rdata, grouped by target")
    c = Counter()
    for rva, tgt in hits["lea_rip"]:
        if where(tgt) in (".data", ".rdata"):
            c[tgt] += 1
    for tgt, n in c.most_common(25):
        print("  0x%X  %-8s xrefs %d" % (tgt, where(tgt), n))
    print()

    print("=" * 78)
    print("item stride 0x18 sites")
    for rva in hits["item_stride_0x18"][:40]:
        print("  .text+0x%X" % rva)
    print()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", default=DEFAULT_EXE)
    ap.add_argument("--sections", action="store_true")
    args = ap.parse_args()

    pe, secs = load(args.exe)
    if args.sections:
        section_table(pe, secs)
        return 0

    print("exe %s\n" % args.exe)
    section_table(pe, secs)
    hits = scan(secs)
    report(hits, secs)
    return 0


if __name__ == "__main__":
    sys.exit(main())
