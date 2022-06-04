// ReSharper disable CppClangTidyClangDiagnosticCastQual
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <fstream>
#include <filesystem>
#include "xorStr.hpp"

DWORD GetProcId(const std::string& procName)
{
	DWORD procId{ 0 };
	const HANDLE hSnap{ CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };

	if (hSnap != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 procEntry;
		procEntry.dwSize = sizeof(procEntry);

		if (Process32First(hSnap, &procEntry))
		{
			do
			{
				if (!_stricmp(procEntry.szExeFile, procName.c_str()))
				{
					procId = procEntry.th32ProcessID;
					break;
				}
			} while (Process32Next(hSnap, &procEntry));
		}
	}
	CloseHandle(hSnap);

	return procId;
}

bool FileExists(const std::string& name)
{
	const std::ifstream f(name.c_str());
	return f.good();
}

int APIENTRY WinMain(HINSTANCE hInst, HINSTANCE hInstPrev, PSTR cmdline, int cmdshow)
{
	const std::string dllRelativePath{ xor ("bratko.dll") };

	if (!FileExists(dllRelativePath))
	{
		MessageBox(NULL, std::string(dllRelativePath + std::string(xor (" not found!\n\nPress ok to exit."))).c_str(), "Error", MB_OK);
		return EXIT_FAILURE;
	}

	const std::string dllAbsolutePath{ std::filesystem::absolute(dllRelativePath).string() };

	const std::string procName{ xor ("Wow.exe") };
	const DWORD procId{ GetProcId(procName) };
	if (!procId)
	{
		MessageBox(NULL, std::string(procName + std::string(xor (" not found!\n\nPress ok to exit."))).c_str(), "Error", MB_OK);
		return EXIT_FAILURE;
	}

	const HANDLE hProc{ OpenProcess(PROCESS_ALL_ACCESS, 0, procId) };
	if (!hProc || hProc == INVALID_HANDLE_VALUE)
	{
		MessageBox(NULL, xor ("Failed opening a handle to process!\n\nPress ok to exit."), "Error", MB_OK);
		return EXIT_FAILURE;
	}

	const LPVOID loc{ VirtualAllocEx(hProc, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };
	if (!loc)
	{
		MessageBox(NULL, xor ("VirtualAllocEx failed!\n\nPress ok to exit."), "Error", MB_OK);
		return EXIT_FAILURE;
	}

	WriteProcessMemory(hProc, loc, dllAbsolutePath.c_str(), dllAbsolutePath.length() + 1, 0);

	const HANDLE hThread{ CreateRemoteThread(hProc, 0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryA), loc, 0, 0) };
	if (!hThread)
	{
		MessageBox(NULL, xor ("CreateRemoteThread failed!\n\nPress ok to exit."), "Error", MB_OK);
		return EXIT_FAILURE;
	}

	CloseHandle(hThread);
	CloseHandle(hProc);

	return 0;
}