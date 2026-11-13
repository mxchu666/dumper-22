#!/usr/bin/env python3
"""
Re-derives the constants in Dumper/Fortnite/FortniteProfile.h straight out of a
Fortnite client executable.

    python tools/verify_profile.py                 # 42.40 build on D:
    python tools/verify_profile.py --exe <path>    # any client
    python tools/verify_profile.py --json          # machine readable

Each value is found by locating the instruction that *uses* it, so the output is
the same table the dumper needs: GObjects RVA, Objects key, NumElements RVA and
key, FUObjectItem key/mask/tag, FName key, FName::ToString RVA, FNamePool RVA and
the block-table offset.

Exit code is 1 when the running build no longer matches the profile table, which
is the signal to re-derive the constants and edit the header.
"""

import argparse
import json
import re
import sys

import pefile

DEFAULT_EXE = (
    r"D:\FN BUILDS\42.40-CL-59343437\FortniteGame\Binaries\Win64"
    r"\FortniteClient-Win64-Shipping.exe"
)

# Values currently in FortniteProfile.h, keyed by SizeOfImage.
EXPECTED = {
    0x1CAD0000: {  # 42.40-CL-59343437
        "name": "Fortnite 42.40-CL-59343437",
        "obfuscated": True,
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
        "obfuscated": False,
    },
}


def load(path):
    pe = pefile.PE(path, fast_load=True)
    text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
    start = text.PointerToRawData
    return pe, pe.__data__[start:start + text.SizeOfRawData], text.VirtualAddress


def u32(buf, off):
    return int.from_bytes(buf[off:off + 4], "little")


def u64(buf, off):
    return int.from_bytes(buf[off:off + 8], "little")


def s32(buf, off):
    return int.from_bytes(buf[off:off + 4], "little", signed=True)


def find_function_start(text, idx, limit=0x800):
    """MSVC pads between functions with 0xCC; walk back to the first byte after it."""
    start = max(0, idx - limit)
    for i in range(idx, start, -1):
        if text[i - 1] == 0xCC:
            return i
    return None


def derive(path):
    pe, text, text_rva = load(path)
    info = {"path": path, "SizeOfImage": pe.OPTIONAL_HEADER.SizeOfImage}

    # FUObjectArray::ObjObjects.Objects
    #   movabs r8, KEY ; xor r8, [rip+disp] ; bswap r8
    m = re.search(rb"\x49\xb8(.{8})\x4c\x33\x05(.{4})\x49\x0f\xc8", text, re.S)
    if m:
        info["ObjectsKey"] = u64(m.group(1), 0)
        end_of_xor = m.start() + 17          # 10 bytes movabs + 7 bytes xor
        info["GObjectsRVA"] = (text_rva + end_of_xor + s32(m.group(2), 0)) & 0xFFFFFFFF

    # FUObjectArray::ObjObjects.NumElements
    #   mov edx, KEY ; xor edx, [rip+disp] ; bswap edx
    m = re.search(rb"\xba(.{4})\x33\x15(.{4})\x0f\xca", text, re.S)
    if m:
        info["NumElementsKey"] = u32(m.group(1), 0)
        end_of_xor = m.start() + 11          # 5 bytes mov + 6 bytes xor
        info["NumElementsRVA"] = (text_rva + end_of_xor + s32(m.group(2), 0)) & 0xFFFFFFFF
        if "GObjectsRVA" in info:
            info["NumElementsOffset"] = info["NumElementsRVA"] - info["GObjectsRVA"]

    # FUObjectItem::Object, low half
    #   mov r8d, KEY ; xor r8d, [rdx+disp8] ; bswap r8d
    m = re.search(rb"\x41\xb8(.{4})\x44\x33\x42(.{1})\x41\x0f\xc8", text, re.S)
    if m:
        info["ItemKey"] = u32(m.group(1), 0)
        info["ItemEncodedLowOffset"] = m.group(2)[0]

    # FUObjectItem::Object, high half
    #   movabs rax, KEEP ; and rax, rcx ; or rax, r8 ; shl rax, 3
    m = re.search(rb"\x48\xb8(.{8})\x48\x21\xc8\x4c\x09\xc0\x48\xc1\xe0\x03", text, re.S)
    if m:
        info["ItemKeepMask"] = u64(m.group(1), 0)

    # free-slot tag
    #   movabs rcx, TAG ; test rax, rcx
    m = re.search(rb"\x48\xb9(.{8})\x48\x85\xc8", text, re.S)
    if m:
        info["ItemFreeTagMask"] = u64(m.group(1), 0)

    # FName id decode
    #   dec eax ; xor eax, KEY ; bswap eax ; inc eax
    hits = list(re.finditer(rb"\xff\xc8\x35(.{4})\x0f\xc8\xff\xc0", text, re.S))
    if hits:
        info["FNameKey"] = u32(hits[0].group(1), 0)

    # FNamePool block table, as read by FName::ToString
    #   lea rax, [rip+disp] ; ... ; mov rcx, [rax+rcx*8+BLOCKS]
    # The function has to contain the FName id decode, otherwise it is some other
    # name-pool user and the "ToString" RVA would be wrong.
    decode = re.compile(rb"\xff\xc8\x35.{4}\x0f\xc8\xff\xc0", re.S)
    for m in re.finditer(rb"\x48\x8b\x8c\xc8(.{4})", text, re.S):
        blocks = u32(m.group(1), 0)
        if not (0x1000 <= blocks <= 0x10000):
            continue

        head = max(0, m.start() - 0x80)
        lea = None
        for candidate in re.finditer(rb"\x48\x8d\x05(.{4})", text[head:m.start()], re.S):
            lea = head + candidate.start()

        if lea is None:
            continue

        start = find_function_start(text, lea)
        if start is None or not decode.search(text[start:start + 0x4000]):
            continue

        info["NamePoolBlocksOffset"] = blocks
        info["GNamesRVA"] = (text_rva + lea + 7 + s32(text, lea + 3)) & 0xFFFFFFFF
        info["ToStringRVA"] = text_rva + start
        break

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
    print(f"profile      {expected['name'] if expected else 'UNKNOWN BUILD (update the table)'}\n")

    obfuscated = bool(expected and expected.get("obfuscated"))
    rows = [
        ("GObjectsRVA", 0xFFFFFFFF),
        ("ObjectsKey", 0xFFFFFFFFFFFFFFFF),
        ("NumElementsRVA", 0xFFFFFFFF),
        ("NumElementsOffset", 0xFF),
        ("NumElementsKey", 0xFFFFFFFF),
        ("ItemKey", 0xFFFFFFFF),
        ("ItemKeepMask", 0xFFFFFFFFFFFFFFFF),
        ("ItemFreeTagMask", 0xFFFFFFFFFFFFFFFF),
        ("ItemEncodedLowOffset", 0xFF),
        ("FNameKey", 0xFFFFFFFF),
        ("ToStringRVA", 0xFFFFFFFF),
        ("GNamesRVA", 0xFFFFFFFF),
        ("NamePoolBlocksOffset", 0xFFFF),
    ]

    ok = True
    for key, width in rows:
        value = info.get(key)
        shown = f"0x{value:X}" if isinstance(value, int) else "not present"
        line = f"  {key:24}{shown:>20}"

        if obfuscated and key in expected:
            match = value == expected[key]
            ok = ok and match
            line += f"   {'ok' if match else f'MISMATCH, header has 0x{expected[key]:X}'}"
        print(line)

    if obfuscated:
        if info.get("ObjectsKey") is None:
            ok = False
            print("\n  no obfuscation constants found: the build is plain or the scheme changed")
        elif info.get("NumElementsOffset") != 0x14:
            ok = False
            print("\n  NumElements moved away from +0x14: update FChunkedFixedUObjectArrayLayouts too")
    elif expected is not None:
        found = [k for k in ("ObjectsKey", "ItemKey", "FNameKey") if info.get(k)]
        if found:
            ok = False
            print(f"\n  build was expected plain, but obfuscation is present: {', '.join(found)}")

    print("\nRESULT:", "profile matches" if ok else "PROFILE OUT OF DATE")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
