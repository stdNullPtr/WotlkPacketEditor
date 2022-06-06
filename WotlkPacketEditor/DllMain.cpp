#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <Windows.h>
#include "ConsoleHelper.hpp"
#include "Hooker.hpp"  // NOLINT(clang-diagnostic-pragma-pack)
#include "Settings.hpp"

void MainLoop(const ConsoleHelper& console)
{
	const bool initHooksResult{ hook::implementations::InitHooks() };

	std::cout << xor ("[INFO] Hooks placed!") << std::endl;

	while (true)
	{
		if (!initHooksResult)
		{
			break;
		}

		if (GetAsyncKeyState(VK_DELETE) & 1)
		{
			break;
		}

		if (GetAsyncKeyState(VK_F1) & 1)
		{
			Settings::bSendPacketLog = !Settings::bSendPacketLog;
		}
		if (GetAsyncKeyState(VK_F2) & 1)
		{
			Settings::bSendPacketWrapperLog = !Settings::bSendPacketWrapperLog;
		}
		if (GetAsyncKeyState(VK_F3) & 1)
		{
			const auto spellPacketWrapper{ (hook::implementations::packetStructs::PacketWrapper*)0x03B5F0E8 };

			BYTE* spellPacket = (BYTE*)malloc(14);
			const auto spellPacketBuf = "\x2E\x01\x00\x00\x03\xA8\x00\x00\x00\x00\x00\x00\x00\x00";
			memcpy(spellPacket, spellPacketBuf, 14);

			spellPacketWrapper->packetPtr = spellPacket;
			spellPacketWrapper->packetLen = 14;
			spellPacketWrapper->unk0_1 = 0;
			spellPacketWrapper->unk0_2 = 0;
			spellPacketWrapper->unk256_3 = 256;

			hook::implementations::hookFunctions::HkSendPacketWrapper(0x03B5F0E8);
			free(spellPacket);
			Sleep(1000);
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
