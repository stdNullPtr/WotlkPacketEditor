#pragma once
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>
#include <Windows.h>
#include "ConsoleHelper.hpp"
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
		namespace packetStructs
		{


#pragma pack(push,1) // keep struct alignment as-is
			struct SpellPacket
			{
				BYTE _pad1[6];
				UINT8 packetCnt;
				UINT32 spellId;
				BYTE _pad2[5];
			};
			static_assert(sizeof SpellPacket == 16);

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
#pragma pack(pop)
		}

		extern bool InitHooks();
	}
}