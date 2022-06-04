#pragma once
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include <Windows.h>

class Hooker
{
private:
	const PVOID m_originalFuncAddress;
	const PVOID m_hookFuncAddress;
	const int m_lenStolenBytes;
	std::vector<BYTE> m_oldOpCodes;
	PVOID m_gatewayFuncAddress;

	static bool Detour32(PVOID addressToHook, PVOID hookFunc, int lenStolenBytes)
	{
		if (lenStolenBytes < 5) return false;

		DWORD curProtection;
		VirtualProtect(addressToHook, lenStolenBytes, PAGE_EXECUTE_READWRITE, &curProtection);

		std::memset(addressToHook, 0x90, lenStolenBytes);

		const uintptr_t relativeAddress = ((UINT_PTR)hookFunc - (UINT_PTR)addressToHook) - 5;

		*(BYTE*)addressToHook = 0xE9;
		*(UINT_PTR*)((UINT_PTR)addressToHook + 1) = relativeAddress;

		VirtualProtect(addressToHook, lenStolenBytes, curProtection, &curProtection);

		return true;
	}
	static PVOID CreateGateway(PVOID addressToHook, PVOID hookFunc, const intptr_t lenStolenBytes)
	{
		// Make sure the length is greater than 5 since a jmp instruction is 5 bytes
		if (lenStolenBytes < 5) return nullptr;

		// Create the gateway (len + 5 for the overwritten bytes + the jmp)
		PVOID gateway = VirtualAlloc(nullptr, lenStolenBytes + 5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!gateway)
		{
			std::cerr << "[WIN_ERR] " << GetLastError() << std::endl;
			return nullptr;
		}

		//Write the stolen bytes into the gateway
		std::memcpy(gateway, addressToHook, lenStolenBytes);

		// Get the gateway to destination addy
		uintptr_t gatewayRelativeAddr = ((UINT_PTR)addressToHook - (UINT_PTR)gateway) - 5;

		// Add the jmp opcode to the end of the gateway
		*(BYTE*)((UINT_PTR)gateway + lenStolenBytes) = 0xE9;

		// Add the address to the jmp
		*(UINT_PTR*)((UINT_PTR)gateway + lenStolenBytes + 1) = gatewayRelativeAddr;

		// Perform the detour
		if (!Detour32(addressToHook, hookFunc, lenStolenBytes))
		{
			std::cerr << "[ERROR] Detour failed!" << std::endl;
			return nullptr;
		}

		return gateway;
	}

public:
	Hooker() = delete;
	Hooker(const PVOID originalFuncAddress, const PVOID hookFuncAddress, const int lenStolenBytes) : m_originalFuncAddress(originalFuncAddress), m_hookFuncAddress(hookFuncAddress), m_lenStolenBytes(lenStolenBytes), m_oldOpCodes(lenStolenBytes), m_gatewayFuncAddress(nullptr)
	{
		static constexpr int jmpInstructionLen{ 5 };

		if (m_lenStolenBytes < jmpInstructionLen)
		{
			const std::string errorMsg{ std::string("[ERROR] lenStolenBytes cannot be less than " + std::to_string(jmpInstructionLen)) };
			std::cerr << errorMsg << std::endl;
			throw std::runtime_error(errorMsg);
		}

		std::cout << "[INFO] Function to hook at: 0x" << m_originalFuncAddress << std::endl
			<< "[INFO] Hook function at: 0x" << m_hookFuncAddress << std::endl
			<< "[INFO] Stolen bytes len: " << m_lenStolenBytes << std::endl;


		std::memcpy(&m_oldOpCodes[0], m_originalFuncAddress, m_lenStolenBytes);

		m_gatewayFuncAddress = CreateGateway(m_originalFuncAddress, m_hookFuncAddress, m_lenStolenBytes);
		if (!m_gatewayFuncAddress)
		{
			const std::string errorMsg{ "[ERROR] Gateway creation failed! " };
			std::cerr << "[WIN_ERR] " << GetLastError() << std::endl;
			std::cerr << errorMsg << std::endl;
			throw std::runtime_error(errorMsg);
		}
	}

	const PVOID& getGatewayFuncAddress() const { return m_gatewayFuncAddress; }

	~Hooker()
	{
		DWORD curProtection;

		VirtualProtect(m_originalFuncAddress, m_lenStolenBytes, PAGE_EXECUTE_READWRITE, &curProtection);
		std::memcpy(m_originalFuncAddress, m_oldOpCodes.data(), m_lenStolenBytes);
		VirtualProtect(m_originalFuncAddress, m_lenStolenBytes, curProtection, &curProtection);

		DiscardVirtualMemory(m_gatewayFuncAddress, m_lenStolenBytes);
	}
};