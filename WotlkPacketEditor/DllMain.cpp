#include <Windows.h>
#include <iostream>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <vector>
#include "consoleHelper.hpp"
#include "Hooker.hpp"

#pragma pack(1)
struct SpellPacket
{
	BYTE _pad1[6];
	UINT8 packetCnt;
	UINT32 spellId;
	BYTE _pad2[5];
};
static_assert(sizeof SpellPacket == 16);

typedef int(WINAPI* tSend)(SOCKET s, const char* buf, int len, int flags);
tSend sendpacketGate;

// this pointer goes into ECX just like a __thiscall would do it, second one is taken from EDX BUT we dont have anything there because we are emulating a thiscall with a fastcall - brilliant
typedef int(__fastcall* tSendWrapper)(void* self, void* trash, int a2, int a3, int a4, float a5, int a6);
tSendWrapper sendWrapperGate;

int WINAPI HkSendPacket(SOCKET s, const char* buf, int len, int flags)
{
	if (len == 16)
	{
		SpellPacket spellPacket{};
		memcpy(&spellPacket, buf, len);
		//std::cout << (UINT32)spellPacket.packetCnt << std::endl;
		//std::cout << (UINT32)spellPacket.spellId << std::endl;
		//spellPacket.spellId = 59752;
		//memcpy((void*)buf, &spellPacket,  len);
	}

	std::cout << "packet[" << std::setw(3) << std::setfill('0') << len << "]:";
	for (int i = 0; i < len; ++i)
	{
		std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (0xFF & buf[i]) << " " << std::dec;
	}

	std::cout << std::endl;

	return sendpacketGate(s, buf, len, flags);
}

int __fastcall HkSendPacketWrapper(void* self, void* trash, int a2, int a3, int a4, float a5, int a6)
{
	std::cout << "HkSendPacketWrapper["
		<< " self: " << self
		<< " trash: " << trash
		<< " a2: " << a2
		<< " a3: " << a3
		<< " a4: " << a4
		<< " a5: " << a5
		<< " a6: " << a6 << "]\n";

	return sendWrapperGate(self, trash, a2, a3, a4, a5, a6);
}

void PrintWinError()
{
	std::cerr << "[WIN_ERR] " << GetLastError() << std::endl;
}

bool InitHooks()
{
	const auto hModuleWs32{ GetModuleHandle("Ws2_32.dll") };
	if (!hModuleWs32)
	{
		PrintWinError();
		return false;
	}

	const auto originalSendPacketAddress = reinterpret_cast<tSend>(GetProcAddress(hModuleWs32, "send"));
	if (!originalSendPacketAddress)
	{
		PrintWinError();
		return false;
	}
	const auto originalSendPacketWrapperAddress = reinterpret_cast<tSendWrapper>((uintptr_t)GetModuleHandle(NULL) + 0x31EF80u);
	if (!originalSendPacketAddress)
	{
		PrintWinError();
		return false;
	}

	constexpr int originalSendStolenBytesLen{ 5 };
	constexpr int originalSendWrapperStolenBytesLen{ 6 };

	const Hooker sendHooker{ (PVOID)originalSendPacketAddress, (PVOID)HkSendPacket, originalSendStolenBytesLen };
	const Hooker sendWrapperHooker{ (PVOID)originalSendPacketWrapperAddress, (PVOID)HkSendPacketWrapper, originalSendWrapperStolenBytesLen };

	sendpacketGate = (tSend)sendHooker.getGatewayFuncAddress();
	sendWrapperGate = (tSendWrapper)sendWrapperHooker.getGatewayFuncAddress();

	return sendpacketGate && sendWrapperGate;
}

void MainLoop(const ConsoleHelper& console)
{
	const bool hookResult{ InitHooks() };

	std::cout << "[INFO] Hooks placed!" << std::endl;

	while (true)
	{
		if (!hookResult)
		{
			break;
		}

		if (GetAsyncKeyState(VK_DELETE) & 1)
		{
			break;
		}

		if (GetAsyncKeyState(VK_INSERT) & 1)
		{

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
#if _DEBUG
		//MessageBox(NULL, "Detached", "Information", MB_OK);
#endif
	}
	return TRUE;
}
