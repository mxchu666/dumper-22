#include "Fortnite/FortniteProfile.h"

#include <Windows.h>
#include <iostream>
#include <format>
#include <string>

#include "Unreal/ObjectArray.h"
#include "Unreal/UnrealTypes.h"
#include "OffsetFinder/Offsets.h"
#include "Platform.h"

namespace
{
	using namespace Fortnite;

	constexpr FBuildProfile BuildProfiles[] =
	{
		{
			.Build = EBuild::v38_00,
			.Name = "Fortnite 38.00-CL-47722112",
			.ImageSize = 0x18777000,
			.bObfuscated = false,
			.GObjectsRVA = -1,			// plain build, the auto-finder resolves everything
			.ElementsPerChunk = 0x10000,
			.ObjectsKey = 0x0,
			.NumElementsKey = 0x0,
			.ItemKey = 0x0,
			.ItemKeepMask = 0x0,
			.ItemFreeTagMask = 0x0,
			.ItemEncodedLowOffset = -1,
			.ItemSize = 0x0,
			.FNameKey = 0x0,
			.ToStringRVA = -1,
			.GNamesRVA = -1,
			.NamePoolBlocksOffset = 0x0,
			.UObjectName = -1,
			.UObjectFlags = -1,
			.UObjectIndex = -1,
			.UObjectClass = -1,
			.UObjectOuter = -1,
		},
		{
			.Build = EBuild::v42_40,
			.Name = "Fortnite 42.40-CL-59343437",
			.ImageSize = 0x1CAD0000,
			.bObfuscated = true,
			.GObjectsRVA = 0x1B028040,
			.ElementsPerChunk = 0x10000,
			.ObjectsKey = 0xAB47766400000000ull,
			.NumElementsKey = 0x0AFED017u,
			.ItemKey = 0x6D8533D2u,
			.ItemKeepMask = 0x3FFF00000000ull,
			.ItemFreeTagMask = 0x1020000000000000ull,
			.ItemEncodedLowOffset = 0x10,
			.ItemSize = 0x18,
			.FNameKey = 0x6F1D17B8u,
			.ToStringRVA = 0x50D90,
			.GNamesRVA = 0x1AF4A680,
			.NamePoolBlocksOffset = 0x2750,
			.UObjectName = 0x18,
			.UObjectFlags = 0x08,
			.UObjectIndex = 0x0C,
			.UObjectClass = 0x10,
			.UObjectOuter = 0x20,
		},
	};

	const FBuildProfile* Active = nullptr;
	bool bResolved = false;

	uint32_t GetImageSize()
	{
		const uintptr_t Base = Platform::GetModuleBase();
		if (!Base)
			return 0u;

		const auto* Dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(Base);
		if (Dos->e_magic != IMAGE_DOS_SIGNATURE)
			return 0u;

		const auto* Nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(Base + Dos->e_lfanew);
		if (Nt->Signature != IMAGE_NT_SIGNATURE)
			return 0u;

		return Nt->OptionalHeader.SizeOfImage;
	}

	/*
	 * The generated SDK has to reproduce both decryptors as well, or an SDK built from a
	 * 42.40 dump would read garbage object pointers at runtime. Written without intrinsics
	 * so the emitted code compiles without extra includes.
	 */
	std::string MakeObjectArrayDecryptorString(const FBuildProfile& P)
	{
		return std::format(
			"[](void* ObjPtr) -> uint8*\n"
			"\t{{\n"
			"\t\tconst uint64 Value = static_cast<uint64>(reinterpret_cast<uintptr_t>(ObjPtr)) ^ 0x{:X}ull;\n"
			"\t\tconst uint32 Hi = static_cast<uint32>(Value >> 32);\n"
			"\t\tconst uint32 Lo = static_cast<uint32>(Value);\n"
			"\t\tconst uint64 Swapped = (static_cast<uint64>((Lo >> 24) | ((Lo >> 8) & 0x0000FF00u) | ((Lo << 8) & 0x00FF0000u) | (Lo << 24)) << 32)\n"
			"\t\t\t| ((Hi >> 24) | ((Hi >> 8) & 0x0000FF00u) | ((Hi << 8) & 0x00FF0000u) | (Hi << 24));\n"
			"\t\treturn reinterpret_cast<uint8*>(Swapped);\n"
			"\t}}", P.ObjectsKey);
	}

	std::string MakeItemDecryptorString(const FBuildProfile& P)
	{
		return std::format(
			"[](void* ItemPtr) -> class UObject*\n"
			"\t{{\n"
			"\t\tconst uint8* Item = static_cast<const uint8*>(ItemPtr);\n"
			"\t\tconst uint64 Raw = *reinterpret_cast<const uint64*>(Item);\n"
			"\t\tif (Raw & 0x{:X}ull)\n"
			"\t\t\treturn nullptr;\n"
			"\t\tconst uint32 Plain = *reinterpret_cast<const uint32*>(Item + 0x{:X}) ^ 0x{:X}u;\n"
			"\t\tconst uint32 Swapped = (Plain >> 24) | ((Plain >> 8) & 0x0000FF00u) | ((Plain << 8) & 0x00FF0000u) | (Plain << 24);\n"
			"\t\treturn reinterpret_cast<class UObject*>(static_cast<uintptr_t>(((Raw & 0x{:X}ull) | Swapped) << 3));\n"
			"\t}}", P.ItemFreeTagMask, P.ItemEncodedLowOffset, P.ItemKey, P.ItemKeepMask);
	}

	void ApplyObfuscatedProfile(const FBuildProfile& Profile)
	{
		static std::string ObjectArrayDecryptor;
		static std::string ItemDecryptor;

		ObjectArrayDecryptor = MakeObjectArrayDecryptorString(Profile);
		ItemDecryptor = MakeItemDecryptorString(Profile);

		ObjectArray::InitDecryption([](void* ObjPtr) -> uint8*
		{
			return reinterpret_cast<uint8*>(ByteSwap64(static_cast<uint64>(reinterpret_cast<uintptr_t>(ObjPtr)) ^ Active->ObjectsKey));
		}, ObjectArrayDecryptor.c_str());

		ObjectArray::InitIntDecryption([](int32 Value) -> int32
		{
			return static_cast<int32>(ByteSwap32(static_cast<uint32>(Value) ^ Active->NumElementsKey));
		});

		ObjectArray::InitObjectPtrDecryption([](uint8* ItemPtr, uint32 ItemOffset) -> void*
		{
			const uint64 Raw = *reinterpret_cast<const uint64*>(ItemPtr + ItemOffset);

			/* Free slots carry this tag; the engine resolves them to nullptr as well. */
			if (Raw & Active->ItemFreeTagMask)
				return nullptr;

			const uint32 EncryptedLow = *reinterpret_cast<const uint32*>(ItemPtr + ItemOffset + Active->ItemEncodedLowOffset);
			const uint64 Decoded = (Raw & Active->ItemKeepMask) | ByteSwap32(EncryptedLow ^ Active->ItemKey);

			return reinterpret_cast<void*>(Decoded << 3);
		});

		ObjectArray::ItemDecryptionLambdaStr = ItemDecryptor;

		ObjectArray::Init(Profile.GObjectsRVA, Profile.ElementsPerChunk);

		/* The object pointer inside each item is obfuscated, so the item size can't be probed. */
		ObjectArray::InitItemLayout(Profile.ItemSize, 0x0);

		FName::Init(Profile.ToStringRVA, FName::EOffsetOverrideType::ToString);

		/* FName ids are obfuscated here, so OffsetFinder's name heuristics can't classify
		 * them: FName is 4 bytes, the outline number lives in the pool entry, the id sits at 0. */
		Off::InSDK::Name::bUseManualFNameSettings = true;
		Settings::Internal::bUseOutlineNumberName = true;
		Settings::Internal::bUseCasePreservingName = false;
		Off::FName::CompIdx = 0x0;
		Off::FName::Number = -0x1;
		Off::InSDK::Name::FNameSize = 0x4;

		Off::InSDK::NameArray::GNames = Profile.GNamesRVA;

		/* Every auto-finder heuristic for these reads plaintext fields or samples fixed
		 * object indices; the values below were read straight out of the binary. */
		Off::UObject::NameOverride = Profile.UObjectName;
		Off::UObject::FlagsOverride = Profile.UObjectFlags;
		Off::UObject::IndexOverride = Profile.UObjectIndex;
		Off::UObject::ClassOverride = Profile.UObjectClass;
		Off::UObject::OuterOverride = Profile.UObjectOuter;
	}
}

namespace Fortnite
{
	const FBuildProfile* GetProfile()
	{
		if (bResolved)
			return Active;

		bResolved = true;

		const uint32_t ImageSize = GetImageSize();

		for (const FBuildProfile& Profile : BuildProfiles)
		{
			if (Profile.ImageSize == ImageSize)
			{
				Active = &Profile;
				break;
			}
		}

		if (Active)
			std::cout << std::format("[Fortnite] build: {} (SizeOfImage 0x{:X})\n", Active->Name, ImageSize);
		else
			std::cout << std::format("[Fortnite] unknown build (SizeOfImage 0x{:X}), falling back to Dumper-7 auto-detection\n", ImageSize);

		return Active;
	}

	uint32_t DecodeFNameId(uint32_t RawId)
	{
		if (!Active || RawId == 0)
			return 0u;

		return ByteSwap32((RawId - 1u) ^ Active->FNameKey) + 1u;
	}

	bool HasObfuscatedFNames()
	{
		return Active && Active->bObfuscated;
	}

	void InitEngineCore()
	{
		const FBuildProfile* Profile = GetProfile();

		if (!Profile || !Profile->bObfuscated)
		{
			ObjectArray::Init();
			CALL_PLATFORM_SPECIFIC_FUNCTION(FName::Init);
			return;
		}

		ApplyObfuscatedProfile(*Profile);
	}
}
