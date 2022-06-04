#include "Hooker.hpp"

namespace hook
{
	bool Hooker::Detour32(PVOID addressToHook, PVOID hookFunc, int lenStolenBytes)
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

	PVOID Hooker::CreateGateway(PVOID addressToHook, PVOID hookFunc, const intptr_t lenStolenBytes)
	{
		// Make sure the length is greater than 5 since a jmp instruction is 5 bytes
		if (lenStolenBytes < 5) return nullptr;

		// Create the gateway (len + 5 for the overwritten bytes + the jmp)
		PVOID gateway = VirtualAlloc(nullptr, lenStolenBytes + 5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!gateway)
		{
			std::cerr << xor ("[WIN_ERR] ") << GetLastError() << std::endl;
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
			std::cerr << xor ("[ERROR] Detour failed!") << std::endl;
			return nullptr;
		}

		return gateway;
	}

	Hooker::Hooker(const PVOID originalFuncAddress, const PVOID hookFuncAddress, const int lenStolenBytes) : m_originalFuncAddress(originalFuncAddress), m_hookFuncAddress(hookFuncAddress), m_lenStolenBytes(lenStolenBytes), m_oldOpCodes(lenStolenBytes), m_gatewayFuncAddress(nullptr)
	{
		static constexpr int jmpInstructionLen{ 5 };

		if (m_lenStolenBytes < jmpInstructionLen)
		{
			const std::string errorMsg{ std::string(xor ("[ERROR] lenStolenBytes cannot be less than ")) + std::to_string(jmpInstructionLen) };
			std::cerr << errorMsg << std::endl;
			throw std::runtime_error(errorMsg);
		}

		std::cout << xor ("[INFO] Function to hook at: 0x") << m_originalFuncAddress << std::endl
			<< xor ("[INFO] Hook function at: 0x") << m_hookFuncAddress << std::endl
			<< xor ("[INFO] Stolen bytes len: ") << m_lenStolenBytes << std::endl;


		std::memcpy(&m_oldOpCodes[0], m_originalFuncAddress, m_lenStolenBytes);

		m_gatewayFuncAddress = CreateGateway(m_originalFuncAddress, m_hookFuncAddress, m_lenStolenBytes);
		if (!m_gatewayFuncAddress)
		{
			const std::string errorMsg{ xor ("[ERROR] Gateway creation failed! ") };
			std::cerr << xor ("[WIN_ERR] ") << GetLastError() << std::endl;
			std::cerr << errorMsg << std::endl;
			throw std::runtime_error(errorMsg);
		}
	}

	Hooker::~Hooker()
	{
		DWORD curProtection;

		VirtualProtect(m_originalFuncAddress, m_lenStolenBytes, PAGE_EXECUTE_READWRITE, &curProtection);
		std::memcpy(m_originalFuncAddress, m_oldOpCodes.data(), m_lenStolenBytes);
		VirtualProtect(m_originalFuncAddress, m_lenStolenBytes, curProtection, &curProtection);

		DiscardVirtualMemory(m_gatewayFuncAddress, m_lenStolenBytes);
	}

	namespace implementations
	{

		namespace templates
		{
			// "this" pointer goes into ECX just like a __thiscall would do it, second one is taken from EDX BUT we don't have anything there because we are emulating a thiscall with a fastcall - brilliant
			typedef int(__fastcall* tSendWrapper)(void* self, void* trash, int a2);
			typedef int(WINAPI* tSend)(SOCKET s, const char* buf, int len, int flags);
		}

		inline templates::tSend g_sendpacketGate;
		inline templates::tSendWrapper g_sendWrapperGate;

		namespace hookFunctions
		{
			int WINAPI HkSendPacket(SOCKET s, const char* buf, int len, int flags)
			{
				if (len == sizeof packetStructs::SpellPacket)
				{
					packetStructs::SpellPacket packet{};
					memcpy(&packet, buf, len);
					//std::cout << (UINT32)packet.packetCnt << std::endl;
					//std::cout << (UINT32)packet.spellId << std::endl;
					//packet.spellId = 59752;
					//memcpy((void*)buf, &packet,  len);
				}
				if (len == sizeof packetStructs::SelectCreaturePacket)
				{
					packetStructs::SelectCreaturePacket packet{};
					memcpy(&packet, buf, len);
					switch (packet.fCreatureTypeMaybe)
					{
					case packetStructs::SelectCreaturePacket::PLAYER:
					{

						std::cout << "PLAYER GUID (?): [" << packet.playerGuid << "]" << std::endl;
						break;
					}
					case packetStructs::SelectCreaturePacket::NPC:
					{

						std::cout << "NPC ID: [" << packet.npcId << "]" << std::endl;
						break;
					}
					}
				}

				std::cout << "packet[" << std::setw(3) << std::setfill('0') << len << "]:";
				for (int i = 0; i < len; ++i)
				{
					std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (0xFF & buf[i]) << " " << std::dec;
				}

				std::cout << std::endl;

				return g_sendpacketGate(s, buf, len, flags);
			}

			int __fastcall HkSendPacketWrapper(void* self, void* trash, int a2)
			{
				std::cout << "HkSendPacketWrapper["
					<< " self: " << self
					<< " trash?: " << trash
					<< " a2: " << a2
					<< "]\n";

				return g_sendWrapperGate(self, trash, a2);
			}
		}

		inline bool InitHooks()
		{
			const auto hModuleWs32{ GetModuleHandle(xor ("Ws2_32.dll")) };
			if (!hModuleWs32)
			{
				ConsoleHelper::PrintWinError();
				return false;
			}

			const auto originalSendPacketAddress{ reinterpret_cast<templates::tSend>(GetProcAddress(hModuleWs32,xor ("send"))) };
			if (!originalSendPacketAddress)
			{
				ConsoleHelper::PrintWinError();
				return false;
			}
			const auto originalSendPacketWrapperAddress{ reinterpret_cast<templates::tSendWrapper>((uintptr_t)0x632B50) };
			if (!originalSendPacketAddress)
			{
				ConsoleHelper::PrintWinError();
				return false;
			}

			constexpr int originalSendStolenBytesLen{ 5 };
			constexpr int originalSendWrapperStolenBytesLen{ 6 };

			// TODO: hooks being static with no further references is an issue - they should be available globally
			static const Hooker sendHooker{ (PVOID)originalSendPacketAddress, (PVOID)hookFunctions::HkSendPacket, originalSendStolenBytesLen };
			static const Hooker sendWrapperHooker{ (PVOID)originalSendPacketWrapperAddress, (PVOID)hookFunctions::HkSendPacketWrapper, originalSendWrapperStolenBytesLen };

			g_sendpacketGate = (templates::tSend)sendHooker.getGatewayFuncAddress();
			g_sendWrapperGate = (templates::tSendWrapper)sendWrapperHooker.getGatewayFuncAddress();

			return true;
		}
	}
}