#!/usr/bin/env python3
"""
Anchored recon: finds FUObjectArray and FNamePool by *structure*, not by
guessing literal keys.

    python tools/find_anchors.py --exe <path>

Anchors used:

  FUObjectArray is a statically allocated struct. Its members are addressed as
  [rip + GObjects + N] with N in {0x00 Objects, 0x10 Max, 0x14 Num, 0x18 MaxChunks,
  0x1C NumChunks}. So a single RIP target T in .data will show up as several
  distinct RIP targets T+0x00/T+0x10/T+0x14/T+0x18/T+0x1C. We histogram every
  RIP-relative target in .data and look for that sibling pattern.

  FNamePool::Resolve is `Blocks[Id >> 16] + 2 * (Id & 0xFFFF)`, so the block
  table load is a scaled-index qword load with a small displacement:
      mov r64, [r64 + r64*8 + disp32]
  restricted to a function that also does `shr r32, 16` or `and r32, 0xFFFF`.
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
        name = s.Name.rstrip(b"\0").decode("ascii", "replace")
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


def rip32(buf, i):
    """disp32 at i, relative to end of a 7-byte rip-relative instruction starting at i-3"""
    return int.from_bytes(buf[i:i + 4], "little", signed=True)


def anchored_targets(text, base):
    """every `lea r64, [rip+d]` and `mov r64, [rip+d]` -> list of (insn_rva, target)"""
    out = []
    for i in range(len(text) - 7):
        b0 = text[i]
        b1 = text[i + 1]
        b2 = text[i + 2]
        if b0 == 0x48 and b1 == 0x8D and b2 == 0x05:      # lea r64, [rip+d]
            pass
        elif b0 == 0x48 and b1 == 0x8B and b2 == 0x05:    # mov r64, [rip+d]
            pass
        elif b0 == 0x4C and b1 == 0x8D and b2 == 0x05:    # lea r64, [rip+d]
            pass
        elif b0 == 0x8B and b1 == 0x05:                   # mov r32, [rip+d]
            pass
        elif b0 == 0x89 and b1 == 0x05:                   # mov [rip+d], r32
            pass
        elif b0 == 0x3B and b1 in (0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D):
            pass                                          # cmp r32, [rip+d]
        else:
            continue
        n = 6 if b0 == 0x8B and b1 == 0x05 or b0 == 0x89 and b1 == 0x05 else 7
        if b0 == 0x3B:
            n = 6
        d = int.from_bytes(text[i + n - 4:i + n], "little", signed=True)
        out.append((base + i, (base + i + n + d) & 0xFFFFFFFF))
    return out


def find_object_array(secs):
    text = secs[".text"]
    hits = anchored_targets(text["data"], text["va"])

    counts = Counter()
    for _, tgt in hits:
        counts[tgt] += 1

    data_lo = secs[".data"]["va"]
    data_hi = data_lo + secs[".data"]["size"]

    def in_data(a, n=1):
        return all(data_lo <= a + k < data_hi for k in range(n))

    cands = []
    for tgt, n in counts.items():
        if not in_data(tgt):
            continue
        siblings = {
            0x00: counts.get(tgt, 0),
            0x10: counts.get(tgt + 0x10, 0),
            0x14: counts.get(tgt + 0x14, 0),
            0x18: counts.get(tgt + 0x18, 0),
            0x1C: counts.get(tgt + 0x1C, 0),
        }
        score = sum(1 for k, v in siblings.items() if k and v > 0)
        if score >= 3 and siblings[0x14] > 0:
            cands.append((score, siblings[0x14], tgt, siblings))

    cands.sort(key=lambda c: (-c[0], -c[1]))
    return counts, cands, in_data


def find_name_pool(secs):
    text = secs[".text"]["data"]
    base = secs[".text"]["va"]
    out = []

    # mov r64, [r64 + r64*8 + disp32], SIB with scale 3
    for i in range(len(text) - 8):
        if text[i] != 0x48 or text[i + 1] != 0x8B:
            continue
        modrm = text[i + 2]
        # mod != 0 required for disp32-only form
        if (modrm & 0xC0) != 0x80:
            continue
        if (modrm & 0x07) != 0x04:      # SIB follows
            continue
        sib = text[i + 3]
        if (sib & 0xC0) != 0xC0:        # scale *8
            continue
        disp = int.from_bytes(text[i + 4:i + 8], "little", signed=True)
        if not (0 <= disp <= 0x1000):
            continue
        fn = base + i
        win = text[max(0, i - 0x200):i + 0x200]
        has_shift = b"\xc1\xe8\x10" in win or b"\xc1\xe9\x10" in win or b"\xc1\xea\x10" in win
        has_mask = b"\x0f\xb7" in win or b"\x25\xff\xff\x00\x00" in win
        if has_shift or has_mask:
            out.append((fn, disp, has_shift, has_mask))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", default=DEFAULT_EXE)
    args = ap.parse_args()

    pe, secs = load(args.exe)
    print("exe %s" % args.exe)
    print("SizeOfImage 0x%X   .data 0x%X .. 0x%X" % (
        pe.OPTIONAL_HEADER.SizeOfImage,
        secs[".data"]["va"], secs[".data"]["va"] + secs[".data"]["size"]))
    print()

    counts, cands, _ = find_object_array(secs)
    print("FUObjectArray candidates (sibling offsets present in .data):")
    for score, num_hits, tgt, sib in cands[:15]:
        print("  base 0x%08X  score %d  refs %s" % (
            tgt, score, " ".join("+%02X:%d" % (k, v) for k, v in sorted(sib.items()))))
    print()

    pools = find_name_pool(secs)
    print("FName block-table candidates (scaled qword load, disp<=0x1000):")
    for fn, disp, shift, mask in pools[:40]:
        print("  .text+0x%06X  disp 0x%04X  shift=%d  mask=%d" % (fn, disp, shift, mask))
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
