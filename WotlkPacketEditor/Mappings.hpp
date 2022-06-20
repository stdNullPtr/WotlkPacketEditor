#pragma once
#include <cstdint>
#include <Windows.h>

namespace mappings
{
	namespace enums
	{
		enum OPCODE
		{
			CMSG_CAST_SPELL = 0x12E,
			CMSG_CANCEL_CAST = 0x12F,

			MSG_MOVE_START_FORWARD = 0x0B5,
			MSG_MOVE_START_BACKWARD = 0x0B6,
			MSG_MOVE_STOP = 0x0B7,
			MSG_MOVE_START_STRAFE_LEFT = 0x0B8,
			MSG_MOVE_START_STRAFE_RIGHT = 0x0B9,
			MSG_MOVE_STOP_STRAFE = 0x0BA,
			MSG_MOVE_JUMP = 0x0BB,
			MSG_MOVE_START_TURN_LEFT = 0x0BC,
			MSG_MOVE_START_TURN_RIGHT = 0x0BD,
			MSG_MOVE_STOP_TURN = 0x0BE,
			MSG_MOVE_START_PITCH_UP = 0x0BF,
			MSG_MOVE_START_PITCH_DOWN = 0x0C0,
			MSG_MOVE_STOP_PITCH = 0x0C1,
			MSG_MOVE_SET_RUN_MODE = 0x0C2,
			MSG_MOVE_SET_WALK_MODE = 0x0C3,
			MSG_MOVE_TOGGLE_LOGGING = 0x0C4,
			MSG_MOVE_TELEPORT = 0x0C5,
			MSG_MOVE_TELEPORT_CHEAT = 0x0C6,
			MSG_MOVE_TELEPORT_ACK = 0x0C7,
			MSG_MOVE_TOGGLE_FALL_LOGGING = 0x0C8,
			MSG_MOVE_FALL_LAND = 0x0C9,
			MSG_MOVE_START_SWIM = 0x0CA,
			MSG_MOVE_STOP_SWIM = 0x0CB,
			MSG_MOVE_SET_RUN_SPEED_CHEAT = 0x0CC,
			MSG_MOVE_SET_RUN_SPEED = 0x0CD,
			MSG_MOVE_SET_RUN_BACK_SPEED_CHEAT = 0x0CE,
			MSG_MOVE_SET_RUN_BACK_SPEED = 0x0CF,
			MSG_MOVE_SET_WALK_SPEED_CHEAT = 0x0D0,
			MSG_MOVE_SET_WALK_SPEED = 0x0D1,
			MSG_MOVE_SET_SWIM_SPEED_CHEAT = 0x0D2,
			MSG_MOVE_SET_SWIM_SPEED = 0x0D3,
			MSG_MOVE_SET_SWIM_BACK_SPEED_CHEAT = 0x0D4,
			MSG_MOVE_SET_SWIM_BACK_SPEED = 0x0D5,
			MSG_MOVE_SET_ALL_SPEED_CHEAT = 0x0D6,
			MSG_MOVE_SET_TURN_RATE_CHEAT = 0x0D7,
			MSG_MOVE_SET_TURN_RATE = 0x0D8,
			MSG_MOVE_TOGGLE_COLLISION_CHEAT = 0x0D9,
			MSG_MOVE_SET_FACING = 0x0DA,
			MSG_MOVE_SET_PITCH = 0x0DB,
			MSG_MOVE_WORLDPORT_ACK = 0x0DC,
			MSG_MOVE_UNROOT	= 0x0ED,
			MSG_MOVE_HEARTBEAT = 0x0EE,
		};
	}
	namespace packetStructs
	{
#pragma pack(push,1) // keep struct alignment as-is
		// DO NOT INSTANTIATE - use as base fields only, cast the address to the appropriate parent
		class Packet
		{
		public:
			Packet() = delete;
			enums::OPCODE packetType;
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