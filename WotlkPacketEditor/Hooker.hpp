#pragma once
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>
#include <Windows.h>
#include "ConsoleHelper.hpp"
#include "Mappings.hpp"
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

		extern bool InitHooks();

		namespace g
		{
			extern PVOID g_spellPacketWrapper;
			extern PVOID g_movementPacketWrapper;
			extern mappings::packetStructs::MovementPacket g_prevPacket;
		}
	}
}
