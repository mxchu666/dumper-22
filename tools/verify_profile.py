#!/usr/bin/env python3
"""
Re-derives the Fortnite decryption constants straight out of a client executable
and diffs them against Dumper/Fortnite/FortniteProfile.h.

    python tools/verify_profile.py                        # 42.40 default path
    python tools/verify_profile.py --exe <path>           # any client
    python tools/verify_profile.py --json                 # machine readable

Two obfuscation families exist so far:

  bswap family (42.40-CL-59343437)
      Objects     movabs r8, KEY ; xor r8, [rip+G] ; bswap r8
      NumElements mov edx, KEY  ; xor edx, [rip+G] ; bswap edx
      FName id    dec eax ; xor eax, KEY ; bswap eax ; inc eax

  xor family (38.00-CL-47722112)
      Objects     movabs r8, KEY ; xor r8, [rip+G]
      NumElements mov edx, KEY  ; xor edx, [rip+G]
      FName id    dec eax ; xor eax, KEY ; inc eax

Shared by both: FUObjectItem stride 0x18, keep mask, free tag, and the
Blocks[Id >> 16] pool load.

Exit code 1 when the binary no longer matches the profile table.
"""

import argparse
import json
import re
import sys
from collections import Counter

import pefile

DEFAULT_EXE = (
    r"D:\FN BUILDS\42.40-CL-59343437\FortniteGame\Binaries\Win64"
    r"\FortniteClient-Win64-Shipping.exe"
)

# Values currently in FortniteProfile.h, keyed by SizeOfImage.
EXPECTED = {
    0x1CAD0000: {  # 42.40-CL-59343437
        "name": "Fortnite 42.40-CL-59343437",
        "bByteSwap": True,
        "GObjectsRVA": 0x1B028040,
        "ObjectsKey": 0xAB47766400000000,
        "NumElementsOffset": 0x14,
        "NumElementsKey": 0x0AFED017,
        "ItemKey": 0x6D8533D2,
        "ItemKeepMask": 0x3FFF00000000,
        "ItemFreeTagMask": 0x1020000000000000,
        "ItemEncodedLowOffset": 0x10,
        "FNameKey": 0x6F1D17B8,
        "ToStringRVA": 0x50D90,
        "GNamesRVA": 0x1AF4A680,
        "NamePoolBlocksOffset": 0x2750,
    },
    0x18777000: {  # 38.00-CL-47722112
        "name": "Fortnite 38.00-CL-47722112",
        "bByteSwap": False,
        "GObjectsRVA": 0x16CFAF80,
        "ObjectsKey": 0xFFFFFFFF40F0F3B4,
        "NumElementsOffset": 0x14,
        "NumElementsKey": 0xFF3B3CEB,
        "ItemKey": 0xCC9E16DB,
        "ItemKeepMask": 0x3FFF00000000,
        "ItemFreeTagMask": 0x1020000000000000,
        "ItemEncodedLowOffset": 0x08,
        "FNameKey": 0x6F01622B,
        "ToStringRVA": 0x5E10,
        "GNamesRVA": 0x16C1C5C0,
        "NamePoolBlocksOffset": 0x10,
    },
}

ROWS = [
    "GObjectsRVA", "ObjectsKey", "NumElementsRVA", "NumElementsOffset",
    "NumElementsKey", "ItemKey", "ItemKeepMask", "ItemFreeTagMask",
    "ItemEncodedLowOffset", "FNameKey", "ToStringRVA", "GNamesRVA",
    "NamePoolBlocksOffset",
]


def load(path):
    pe = pefile.PE(path, fast_load=True)
    text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
    start = text.PointerToRawData
    secs = [(s.VirtualAddress, max(s.SizeOfRawData, s.Misc_VirtualSize),
             s.Name.rstrip(b"\0").decode("ascii", "replace") or "?")
            for s in pe.sections]
    return pe, pe.__data__[start:start + text.SizeOfRawData], text.VirtualAddress, secs


def section_of(secs, rva):
    for va, size, name in secs:
        if va <= rva < va + size:
            return name
    return None


def pdata_ranges(pe):
    """Function table out of the exception directory; the exact entry point per site."""
    try:
        d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    except IndexError:
        return []
    if not d.VirtualAddress or not d.Size:
        return []
    try:
        raw = pe.get_data(d.VirtualAddress, d.Size)
    except Exception:
        return []
    out = []
    for i in range(0, len(raw) - 11, 12):
        begin = int.from_bytes(raw[i:i + 4], "little")
        end = int.from_bytes(raw[i + 4:i + 8], "little")
        if begin and end > begin:
            out.append(begin)
    out.sort()
    return out


def enclosing(begins, rva):
    import bisect
    i = bisect.bisect_right(begins, rva) - 1
    if i < 0:
        return None
    b = begins[i]
    return b if rva - b < 0x40000 else None


def u32(buf, off):
    return int.from_bytes(buf[off:off + 4], "little")


def u64(buf, off):
    return int.from_bytes(buf[off:off + 8], "little")


def s32(buf, off):
    return int.from_bytes(buf[off:off + 4], "little", signed=True)


def func_start(text, idx, limit=0x400):
    """MSVC pads between functions; walk back to the first byte after padding."""
    for i in range(idx, max(0, idx - limit), -1):
        if text[i - 1] in (0xCC, 0x90):
            return i
    return None


def derive(path):
    pe, text, text_rva, secs = load(path)
    pdata = pdata_ranges(pe)
    info = {"path": path, "SizeOfImage": pe.OPTIONAL_HEADER.SizeOfImage}

    # ---- bswap family first: the trailing bswap makes the pattern unambiguous
    m = re.search(rb"\x49\xb8(.{8})\x4c\x33\x05(.{4})\x49\x0f\xc8", text, re.S)
    if m:
        info["bByteSwap"] = True
        info["ObjectsKey"] = u64(m.group(1), 0)
        end_of_xor = m.start() + 17          # movabs(10) + xor(7)
        info["GObjectsRVA"] = (text_rva + end_of_xor + s32(m.group(2), 0)) & 0xFFFFFFFF
    else:
        # ---- xor family
        m = re.search(rb"\x49\xb8(.{8})\x4c\x33\x05(.{4})", text, re.S)
        if m:
            info["bByteSwap"] = False
            info["ObjectsKey"] = u64(m.group(1), 0)
            end_of_xor = m.start() + 17
            info["GObjectsRVA"] = (text_rva + end_of_xor + s32(m.group(2), 0)) & 0xFFFFFFFF

    swap = info.get("bByteSwap")

    if swap is True:
        cand = list(re.finditer(rb"\xba(.{4})\x33\x15(.{4})\x0f\xca", text, re.S))
    elif swap is False:
        cand = list(re.finditer(rb"\xba(.{4})\x33\x15(.{4})", text, re.S))
    else:
        cand = []

    # several immediates are XORed against rip-relative globals; the right one is the
    # field that sits exactly 0x14 bytes past the Objects field
    m = None
    for c in cand:
        tgt = (text_rva + c.start() + 11 + s32(c.group(2), 0)) & 0xFFFFFFFF
        if info.get("GObjectsRVA") is not None and tgt == info["GObjectsRVA"] + 0x14:
            m = c
            break
    if m is None and cand:
        m = cand[0]
    if m:
        info["NumElementsKey"] = u32(m.group(1), 0)
        info["NumElementsRVA"] = (text_rva + m.start() + 11 + s32(m.group(2), 0)) & 0xFFFFFFFF
        if "GObjectsRVA" in info:
            info["NumElementsOffset"] = info["NumElementsRVA"] - info["GObjectsRVA"]

    # ---- FUObjectItem::Object, low half, plus the two masks emitted beside it.
    item_site = None
    if swap is True:
        m = re.search(rb"\x41\xb8(.{4})\x44\x33\x42(.{1})\x41\x0f\xc8", text, re.S)
        if m:
            info["ItemKey"] = u32(m.group(1), 0)
            info["ItemEncodedLowOffset"] = m.group(2)[0]
            item_site = m.end()
    elif swap is False:
        # xor family, read straight off the item lookup:
        #   mov  ecx, [rdx + 8]      ; encrypted low dword
        #   mov  edx, KEY
        #   xor  rdx, rcx            ; 48 31 / 48 33
        pairs = Counter()
        positions = {}
        for x in re.finditer(rb"\x8b[\x40-\x7f](.)\xba(.{4})\x48[\x31\x33][\xc0-\xff]", text, re.S):
            disp = x.group(1)[0]
            if disp in (0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38):
                k = (u32(x.group(2), 0), disp)
                pairs[k] += 1
                positions.setdefault(k, x.end())
        if pairs:
            k, _ = pairs.most_common(1)[0]
            info["ItemKey"], info["ItemEncodedLowOffset"] = k
            item_site = positions[k]

    def beside(site, opcode):
        lo = max(0, site - 0x60)
        return re.search(rb"[\x48\x49\x4c][\xb8-\xbf](.{8})" + opcode, text[lo:site + 0x60], re.S)

    if item_site is not None:
        m = beside(item_site, rb"\x48\x21[\xc0-\xff]")      # and rax, mask
        if m:
            info["ItemKeepMask"] = u64(m.group(1), 0)
        m = beside(item_site, rb"\x48\x85[\xc0-\xff]")      # test rax, tag
        if m:
            info["ItemFreeTagMask"] = u64(m.group(1), 0)

    # ---- FName decode sites -> the enclosing function -> GNames + block offset.
    # The pool lookup follows the id decode and is a fixed shape in every build:
    #   shr r32, 0x10
    #   lea rB, [rip + GNames]
    #   mov r, [rB + rI*8 + Blocks]
    # Anchoring on the decode keeps the search inside FName::ToString instead of
    # latching onto the first unrelated pool-shaped load in the image.
    if swap is True:
        site_re = rb"\xff\xc8\x35(.{4})\x0f\xc8\xff\xc0"
    elif swap is False:
        site_re = rb"\xff\xc8\x35(.{4})\xff\xc0"
    else:
        site_re = None

    best = None
    cands = set()
    if site_re:
        for sm in re.finditer(site_re, text, re.S):
            site = sm.start()
            key = u32(sm.group(1), 0)

            fn = enclosing(pdata, text_rva + site)
            start = fn - text_rva if fn is not None else func_start(text, site, 0x800)
            if start is None:
                continue

            has_marker = b"\xc0\x9b\x00\x00" in text[start:site + 0x100]

            found = None
            for s in re.finditer(rb"\xc1[\xe8-\xef]\x10", text[site:site + 0x200], re.S):
                at = site + s.start()
                tail = text[at:at + 0x40]

                lm = re.search(rb"\x48\x8d([\x05\x0d\x15\x1d\x25\x2d\x35\x3d])(.{4})", tail, re.S)
                if lm is None:
                    continue
                lea = at + lm.start()
                reg = (lm.group(1)[0] >> 3) & 7

                # the block load comes in two encodings: +disp8 and +disp32
                for bm, dlen in ((re.search(rb"\x48\x8b([\x44\x4c\x54\x5c\x64\x6c\x74\x7c])([\xc0-\xff])(.)", tail, re.S), 1),
                                 (re.search(rb"\x48\x8b([\x84\x8c\x94\x9c\xa4\xac\xb4\xbc])([\xc0-\xff])(.{4})", tail, re.S), 4)):
                    if bm is None:
                        continue
                    sib = bm.group(2)[0]
                    if (sib & 7) != reg:               # base must be the lea'd GNames
                        continue
                    if (sib & 0xC0) != 0xC0:           # scale 8
                        continue
                    if ((sib >> 3) & 7) == 4:          # needs an index register
                        continue
                    blocks = int.from_bytes(bm.group(3)[:dlen], "little")
                    if not (0x08 <= blocks <= 0x8000):
                        continue
                    target = (text_rva + lea + 7 + s32(text, lea + 3)) & 0xFFFFFFFF
                    if section_of(secs, target) != ".data":
                        continue
                    found = (blocks, target, lea - site)
                    break
                if found:
                    break

            if found is None:
                continue

            # candidate functions differ per build: ToString and the thin append
            # wrapper are separate symbols, both valid for the profile
            cands.add(text_rva + start)

            # prefer the function carrying the outline-number marker, then the pool
            # lookup closest to the decode
            score = (has_marker, -found[2])
            if best is None or score > best[0]:
                best = (score, text_rva + start, found[0], found[1], key)

    if best:
        _, to_string, blocks, gnames, key = best
        info["FNameKey"] = key
        info["ToStringRVA"] = to_string
        info["NamePoolBlocksOffset"] = blocks
        info["GNamesRVA"] = gnames

    info["ToStringCandidates"] = sorted(cands)

    return info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", default=DEFAULT_EXE)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    info = derive(args.exe)

    if args.json:
        print(json.dumps(info, indent=2))
        return 0

    expected = EXPECTED.get(info["SizeOfImage"])
    print(f"exe          {info['path']}")
    print(f"SizeOfImage  0x{info['SizeOfImage']:X}")
    print(f"profile      {expected['name'] if expected else 'UNKNOWN BUILD (add it to the table)'}")
    print(f"family       {'bswap' if info.get('bByteSwap') else 'xor' if info.get('bByteSwap') is False else 'plain'}\n")

    ok = True
    if expected and expected["ToStringRVA"] in info.get("ToStringCandidates", ()):
        info["ToStringRVA"] = expected["ToStringRVA"]

    for key in ROWS:
        value = info.get(key)
        shown = f"0x{value:X}" if isinstance(value, int) else "not present"
        line = f"  {key:24}{shown:>20}"
        if expected and key in expected:
            if key == "ToStringRVA":
                # several symbols share the decode + pool shape; any of them is a valid
                # append entry for the profile
                match = value in info.get("ToStringCandidates", ())
            else:
                match = value == expected[key]
            ok = ok and match
            if not match:
                line += f"   MISMATCH, header has 0x{expected[key]:X}"
            else:
                line += "   ok"
        print(line)

    if expected and expected["ToStringRVA"] not in info.get("ToStringCandidates", ()):
        ok = False
        print(f"\n  the header's ToString 0x{expected['ToStringRVA']:X} is not a decode+pool function any more")

    if expected:
        if "ObjectsKey" not in info:
            ok = False
            print("\n  no obfuscation constants found: the build is plain or the scheme changed")
        elif info.get("NumElementsOffset") != 0x14:
            ok = False
            print("\n  NumElements moved away from +0x14: update FChunkedFixedUObjectArrayLayout too")
        if info.get("bByteSwap") != expected["bByteSwap"]:
            ok = False
            print("\n  byte-swap family changed: flip bByteSwap in the profile")

    print("\nRESULT:", "profile matches" if ok else "PROFILE OUT OF DATE")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
