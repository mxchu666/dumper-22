#pragma once

#include <cstdint>

/*
 * Per-build knowledge for the Fortnite client.
 *
 * Everything here was read out of the shipping executables:
 *   38.00-CL-47722112  SizeOfImage 0x18777000  (plain UE layout, auto-finder works)
 *   42.40-CL-59343437  SizeOfImage 0x1CAD0000  (obfuscated FUObjectArray + FName ids)
 *
 * The 42.40 decode sites, all verified against FortniteClient-Win64-Shipping.exe:
 *   FUObjectArray::ObjObjects.Objects  RVA 0x1B028040  bswap64(x ^ 0xAB47766400000000)
 *   FUObjectArray::ObjObjects.NumElements RVA 0x1B028054  bswap32(x ^ 0x0AFED017)
 *   FUObjectItem::Object               split: bits 32..45 of (ptr>>3) in the first qword,
 *                                      the low 32 bits of (ptr>>3) encrypted at +0x10
 *   FName::ToString                    RVA 0x50D90   (4-byte FName, id bswap32((x-1) ^ 0x6F1D17B8)+1,
 *                                      outline number stored in the pool entry, pool at GNames+0x2750)
 */

namespace Fortnite
{
	enum class EBuild : uint8_t
	{
		Unknown,
		v38_00,
		v42_40,
	};

	struct FBuildProfile
	{
		EBuild Build;
		const char* Name;

		/* MODULEINFO.SizeOfImage of the client executable. */
		uint32_t ImageSize;

		/* true when the object array and FName ids are stored obfuscated. */
		bool bObfuscated;

		/* FUObjectArray */
		int32_t  GObjectsRVA;
		int32_t  ElementsPerChunk;
		uint64_t ObjectsKey;
		uint32_t NumElementsKey;
		uint32_t ItemKey;
		uint64_t ItemKeepMask;
		uint64_t ItemFreeTagMask;
		int32_t  ItemEncodedLowOffset;
		uint32_t ItemSize;

		/* FName */
		uint32_t FNameKey;
		int32_t  ToStringRVA;
		int32_t  GNamesRVA;
		int32_t  NamePoolBlocksOffset;

		/* UObject */
		int32_t UObjectName;
		int32_t UObjectFlags;
		int32_t UObjectIndex;
		int32_t UObjectClass;
		int32_t UObjectOuter;
	};

	/* Profile of the running build, or nullptr when this build isn't in the table. */
	const FBuildProfile* GetProfile();

	/* Byte-swaps a 32-bit value; kept separate so the generated SDK uses the same math. */
	inline uint32_t ByteSwap32(uint32_t Value)
	{
		return (Value >> 24)
			| ((Value >> 8) & 0x0000FF00u)
			| ((Value << 8) & 0x00FF0000u)
			| (Value << 24);
	}

	inline uint64_t ByteSwap64(uint64_t Value)
	{
		return (static_cast<uint64_t>(ByteSwap32(static_cast<uint32_t>(Value))) << 32)
			| ByteSwap32(static_cast<uint32_t>(Value >> 32));
	}

	/* Obfuscated FName id -> pool index, exactly as the engine's FName::ToString does it. */
	uint32_t DecodeFNameId(uint32_t RawId);

	/* True when the running build obfuscates FName ids. */
	bool HasObfuscatedFNames();

	/*
	 * Sets up the object array and the FName decoder for the running build.
	 * Replaces the plain ObjectArray::Init() + FName::Init() pair; call it at the
	 * start of Generator::InitEngineCore().
	 */
	void InitEngineCore();
}
