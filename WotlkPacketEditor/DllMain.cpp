#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <Windows.h>
#include "ConsoleHelper.hpp"
#include "Hooker.hpp"  // NOLINT(clang-diagnostic-pragma-pack)

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
	}
	return TRUE;
	}
