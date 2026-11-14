# FortniteDumper

Fork of [Encryqed/Dumper-7](https://github.com/Encryqed/Dumper-7) (commit `2c1eae3`, Oct 2026) with
per-build support for the Fortnite client. Same generator, same output layout, plus the
decryption the newer builds need before a single object can be read.

| Build | SizeOfImage | State |
|---|---|---|
| 38.00-CL-47722112 | `0x18777000` | obfuscated object array + FName ids, **no** byte swap |
| 42.40-CL-59343437 | `0x1CAD0000` | obfuscated object array + FName ids, byte swap |

The dumper reads `SizeOfImage` from its own module, picks the profile, and falls back to vanilla
Dumper-7 detection on anything that is not in the table.

## 38.00 decryption scheme

Same instruction family as 42.40 with the byte swap removed. Read out of
`FortniteClient-Win64-Shipping.exe`, every value resolved from the instruction that uses it:

| What | Where | Decode |
|---|---|---|
| `ObjObjects.Objects` | RVA `0x16CFAF80` | `x ^ 0xFFFFFFFF40F0F3B4` |
| `ObjObjects.NumElements` | RVA `0x16CFAF94` | `x ^ 0xFF3B3CEB` |
| `FUObjectItem::Object` | item size `0x18` | `((Raw & 0x3FFF00000000) \| (dword@+0x08 ^ 0xCC9E16DB)) << 3`, free slots tagged `0x1020000000000000` |
| `FName` | 4 bytes, id at `+0x0` | `((id - 1) ^ 0x6F01622B) + 1`, outline number inside the pool entry |
| `FName::ToString` | RVA `0x5E10` | — |
| `FNamePool` | RVA `0x16C1C5C0` | block table at `+0x10`, stride 8 |
| `UObject` | Outer `0x08`, Flags `0x10`, Index `0x14`, Class `0x18`, Name `0x20` | — |

The `UObject` base is **rotated** against stock UE5 in this client: `Outer` sits right after the
vtable and `Name` comes after `Class`. Hardcode all five — the finder cannot classify them
because the raw `FName` ids are encrypted, and its name scan walks every object and faults on the
odd non-`UObject` slot.

Two differences that matter when porting the constants:

- no `bswap` on any decoded word; the XOR is the whole transformation.
- the encrypted low dword of `FUObjectItem::Object` sits at `+0x08` and the serial at `+0x10`
  (42.40 has them the other way round), so `ItemEncodedLowOffset` is `0x08`, not `0x10`.

`NumElements` is also at `+0x14` from `Objects`, so the default
`FChunkedFixedUObjectArrayLayout` is correct.

## 42.40 decryption scheme

Read out of `FortniteClient-Win64-Shipping.exe`, every value resolved from the instruction that
uses it:

| What | Where | Decode |
|---|---|---|
| `ObjObjects.Objects` | RVA `0x1B028040` | `bswap64(x ^ 0xAB47766400000000)` |
| `ObjObjects.NumElements` | RVA `0x1B028054` | `bswap32(x ^ 0x0AFED017)` |
| `FUObjectItem::Object` | item size `0x18` | `((Raw & 0x3FFF00000000) \| bswap32(dword@+0x10 ^ 0x6D8533D2)) << 3`, free slots tagged `0x1020000000000000` |
| `FName` | 4 bytes, id at `+0x0` | `bswap32((id - 1) ^ 0x6F1D17B8) + 1`, outline number inside the pool entry |
| `FName::ToString` | RVA `0x50D90` | — |
| `FNamePool` | RVA `0x1AF4A680` | block table at `+0x2750`, stride 8 |
| `UObject` | Name `0x18`, Flags `0x08`, Index `0x0C`, Class `0x10`, Outer `0x20` | — |

`NumElements` sits at `+0x14` from `Objects`, which is upstream's default
`FChunkedFixedUObjectArrayLayout` — no layout override needed.

## What changed against upstream

- `Dumper/Fortnite/FortniteProfile.{h,cpp}` — build table, detection, profile application.
- `ObjectArray` — int and `FUObjectItem::Object` decryptors, item layout override, and the
  chunk table is now run through `DecryptPtr` on every lookup (upstream only did it for the
  probe, so an encrypted table was indexed while still encrypted).
- `Offsets` — `Name/Flags/Index/Class/Outer` manual overrides and `bUseManualFNameSettings`.
- `OffsetFinder` — skips the FName heuristics when the layout was supplied.
- `UnrealTypes` — validates a decoded FName id against the pool before calling the game's
  `ToString`, which does not bounds-check and faults on a stale name.
- `CppGenerator` — the generated SDK now carries `DecryptItem` next to `DecryptPtr`, so a
  dump taken from 42.40 also resolves object pointers correctly at runtime.
- `CMakeLists.txt` — `cxx_std_23` (upstream uses deducing-this and only builds from the .sln).

## Build

```
cmake -S . -B out/build/msvc -G "Visual Studio 18 2026" -A x64
cmake --build out/build/msvc --config Release
```

Output: `out/build/msvc/bin/Release/Dumper-7.dll`. The VS solution (`Dumper-7.sln`) also works;
the new files are already registered in `Dumper.vcxproj`.

## Run

1. Start the client.
2. Inject `Dumper-7.dll` (F6 unloads).
3. SDK lands in `C:/Dumper-7/<version>-<game>/`.

Expected console output on 42.40:

```
[Fortnite] build: Fortnite 42.40-CL-59343437 (SizeOfImage 0x1CAD0000)
GObjects: 0x...
Off::InSDK::ObjArray::FUObjectItemSize: 24
Manual-Override: FName::ToString --> Offset 0x50D90
```

## Re-verify after a game update

```
python tools/verify_profile.py --exe <client exe>
```

It re-derives every constant from the binary and diffs it against the header, exit code 1 when
the profile is stale. On a new build: run it, paste the values into
`Dumper/Fortnite/FortniteProfile.h`, add the new `SizeOfImage` to the table.

## Status

- `Dumper-7.dll` compiles clean (MSVC 19.51, x64 Release).
- 38.00 constants verified against `FortniteClient-Win64-Shipping.exe`: the object lookup and
  `FUObjectItem::Object` decode at `0x124C1`-`0x1252E` and `0x12681`-`0x126BB`, `FName::ToString`
  at `0x5E10` (id decode, pool init guard, `Blocks[Id >> 16]` load at `+0x10`), and
  `tools/verify_profile.py` re-derives all of them from the binary.
- 42.40 constants verified against `FortniteClient-Win64-Shipping.exe` three ways: raw
  disassembly of the decode sites, `tools/verify_profile.py`, and Hex-Rays in IDA
  (`sub_...1002` for the object array, `sub_...50D90` for `FName::ToString`).
- Not run inside a live client from this machine — the injection and the in-game dump still need
  a run on your side.
