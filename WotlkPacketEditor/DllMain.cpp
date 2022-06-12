#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <Windows.h>
#include "ConsoleHelper.hpp"
#include "Hooker.hpp"  // NOLINT(clang-diagnostic-pragma-pack)
#include "Mappings.hpp"
#include "Settings.hpp"

void MainLoop(const ConsoleHelper& console)
{
	const bool initHooksResult{ hook::implementations::InitHooks() };

	std::cout << xor ("[INFO] Hooks placed!\n\n");

	while (true)
	{
		if (!initHooksResult)
		{
			break;
		}

		if (GetAsyncKeyState(VK_END) & 1)
		{
			break;
		}

		if (GetAsyncKeyState(VK_F1) & 1)
		{
			Settings::bSendPacketLog = !Settings::bSendPacketLog;
			std::cout << xor ("[INFO] SendPacketLog: ") << Settings::bSendPacketLog << std::endl;
		}
		if (GetAsyncKeyState(VK_F2) & 1)
		{
			Settings::bSendPacketWrapperLog = !Settings::bSendPacketWrapperLog;
			std::cout << xor ("[INFO] SendPacketWrapperLog: ") << Settings::bSendPacketWrapperLog << std::endl;
		}
		if (GetAsyncKeyState(VK_ADD) & 1)
		{
			Settings::bLogAllPackets = !Settings::bLogAllPackets;
			std::cout << xor ("[INFO] bLogAllPackets: ") << Settings::bLogAllPackets << std::endl;
		}
		if (GetAsyncKeyState(VK_F3) & 1)
		{
			using hook::implementations::g::g_spellPacketWrapper;
			using mappings::packetStructs::SpellPacket;
			using mappings::packetStructs::PacketWrapper;
			using hook::implementations::hookFunctions::HkSendPacketWrapper;

			if (!g_spellPacketWrapper)
			{
				std::cerr << xor ("[ERROR] Cast a spell first!\n");
				continue;
			}

			const auto spellPacketWrapper{ static_cast<PacketWrapper*>(g_spellPacketWrapper) };
			constexpr SpellPacket spellPacket{ {0x12E}, 1, 168, {0} };

			spellPacketWrapper->packetPtr = const_cast<SpellPacket*>(&spellPacket);
			spellPacketWrapper->packetLen = sizeof SpellPacket;
			spellPacketWrapper->unk0_1 = 0;
			spellPacketWrapper->unk0_2 = 0;
			// warden?
			spellPacketWrapper->unk256_3 = 0x100;

			HkSendPacketWrapper(static_cast<int*>(g_spellPacketWrapper));

			Sleep(1000);
		}
		if (GetAsyncKeyState(VK_NUMPAD8) & 1)
		{
			using hook::implementations::g::g_movementPacketWrapper;
			using mappings::packetStructs::MovementPacket;
			using mappings::packetStructs::PacketWrapper;
			using hook::implementations::hookFunctions::HkSendPacketWrapper;
			using hook::implementations::g::g_prevPacket;

			if (!g_movementPacketWrapper)
			{
				std::cerr << xor ("[ERROR] walk around first!\n");
				continue;
			}

			const auto movementPacketWrapper{ static_cast<PacketWrapper*>(g_movementPacketWrapper) };
			MovementPacket movementPacket{g_prevPacket};
			movementPacket.packetType = 0xB5; //start walk
			movementPacket.z += 5.0f;

			movementPacketWrapper->packetPtr = &movementPacket;
			movementPacketWrapper->packetLen = sizeof MovementPacket;
			movementPacketWrapper->unk0_1 = 0;
			movementPacketWrapper->unk0_2 = 0;
			// warden?
			movementPacketWrapper->unk256_3 = 0x100;

			HkSendPacketWrapper(static_cast<int*>(g_movementPacketWrapper));
			movementPacket.packetType = 0xB7; // stop walk
			HkSendPacketWrapper(static_cast<int*>(g_movementPacketWrapper));

			Sleep(100);
		}
		if (GetAsyncKeyState(VK_F5) & 1)
		{
			Settings::bInterceptMovement = !Settings::bInterceptMovement;

			std::cout << xor ("[INFO] bInterceptMovement: ") << Settings::bInterceptMovement << std::endl;
		}
		if (GetAsyncKeyState(VK_F6) & 1)
		{
			Settings::bInterceptSpellCast = !Settings::bInterceptSpellCast;

			std::cout << xor ("[INFO] bInterceptSpellCast: ") << Settings::bInterceptSpellCast << std::endl;
		}

		Sleep(10);
	}
}

DWORD CleanupAndExit(const HMODULE hModule, const int exitCode, const ConsoleHelper ch)
{
	ch.DestroyConsole();
	FreeLibraryAndExitThread(hModule, exitCode);
}

DWORD WINAPI MainThread(const HMODULE hModule)
{
	ConsoleHelper ch;

	if (!ch.InitConsole())
	{
		// TODO: print this error in some way, probably inside the InitConsole() function as well, or msgbox?
		return CleanupAndExit(hModule, EXIT_FAILURE, ch);
	}

	ch.ShowConsoleCursor(false);

	MainLoop(ch);

	return CleanupAndExit(hModule, EXIT_SUCCESS, ch);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		// Unnecessary thread calls disabled 
		DisableThreadLibraryCalls(hModule);

		const HANDLE threadHandle{ CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(MainThread), hModule, 0, nullptr) };
		if (threadHandle != NULL)
		{
			CloseHandle(threadHandle);
		}
		else
		{
			// TODO: check with GetLastError
			// GetLastError (how do I print the error? logging system?) and exit????
		}
	}
	else if (ul_reason_for_call == DLL_PROCESS_DETACH)
	{
	}
	return TRUE;
}
