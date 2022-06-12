#pragma once
#include <cstdint>
#include <Windows.h>

namespace mappings
{
	namespace packetStructs
	{
#pragma pack(push,1) // keep struct alignment as-is
		// DO NOT INSTANTIATE - use as base fields only, cast the address to the appropriate parent
		class Packet
		{
		public:
			Packet() = delete;
			UINT32 packetType;
		};

		class SpellPacket : public Packet
		{
		public:
			BYTE packetCnt;
			UINT32 spellId;
			BYTE _pad1[5];
		};
		static_assert(sizeof SpellPacket == 14);

		class MovementPacket : public Packet
		{
		public:
			UINT32 _unk0x4;
			BYTE _unk0x8;
			BYTE _unk0x9;
			BYTE _unk0xA[5];
			UINT32 _unk0xF;
			FLOAT x;
			FLOAT y;
			FLOAT z;
			FLOAT rotation;
			UINT32 _unk0x23;
		};
		static_assert(sizeof MovementPacket == 39);

		struct SelectCreaturePacket
		{
			enum eCreatureType { PLAYER = 0x06, NPC = 0xF1 };

			BYTE _pad1[6];
			UINT16 playerGuid;
			BYTE _pad2[1];
			UINT16 npcId;
			BYTE _pad3[2];
			BYTE fCreatureTypeMaybe; //0x6 player 0xF1 NPC
		};
		static_assert(sizeof SelectCreaturePacket == 14);

		class PacketWrapper
		{
		public:
			char pad_0000[4]; //0x0000
			class Packet* packetPtr; //0x0004
			uint32_t unk0_1; //0x0008
			uint32_t unk256_3; //0x000C
			uint32_t packetLen; //0x0010
			uint32_t unk0_2; //0x0014
			char pad_0018[40]; //0x0018
		}; //Size: 0x0040
		static_assert(sizeof(PacketWrapper) == 0x40);
#pragma pack(pop)
	}
}