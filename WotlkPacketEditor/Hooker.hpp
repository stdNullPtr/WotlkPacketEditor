#pragma once
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <Windows.h>
#include "ConsoleHelper.hpp"
#include "Settings.hpp"
#include "../Injector/XorStr.hpp"

namespace hook {
	class Hooker
	{
	private:
		const PVOID m_originalFuncAddress;
		const PVOID m_hookFuncAddress;
		const int m_lenStolenBytes;
		std::vector<BYTE> m_oldOpCodes;
		PVOID m_gatewayFuncAddress;

		static bool Detour32(PVOID addressToHook, PVOID hookFunc, int lenStolenBytes);
		static PVOID CreateGateway(PVOID addressToHook, PVOID hookFunc, intptr_t lenStolenBytes);

	public:
		Hooker() = delete;
		~Hooker();

		Hooker(PVOID originalFuncAddress, PVOID hookFuncAddress, int lenStolenBytes);
		const PVOID& getGatewayFuncAddress() const { return m_gatewayFuncAddress; }
	};

	namespace implementations
	{
		namespace hookFunctions
		{
			int __cdecl HkSendPacketWrapper(int* packetWrapperPtr);
			int WINAPI HkSendPacket(SOCKET s, const char* buf, int len, int flags);
		}
		namespace packetStructs
		{
#pragma pack(push,1) // keep struct alignment as-is
			class SpellPacket
			{
			public:
				UINT32 packetType;
				BYTE packetCnt;
				UINT32 spellId;
				BYTE _pad1[5];
			};
			static_assert(sizeof SpellPacket == 14);

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
				class SpellPacket* packetPtr; //0x0004
				uint32_t unk0_1; //0x0008
				uint32_t unk256_3; //0x000C
				uint32_t packetLen; //0x0010
				uint32_t unk0_2; //0x0014
				char pad_0018[40]; //0x0018
			}; //Size: 0x0040
			static_assert(sizeof(PacketWrapper) == 0x40);

#pragma pack(pop)
		}

		extern bool InitHooks();

		namespace g
		{
			extern PVOID g_packetWrapper;
			extern BYTE g_spellPacketCounter;
		}
	}
}