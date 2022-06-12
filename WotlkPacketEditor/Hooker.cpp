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

		*static_cast<BYTE*>(addressToHook) = 0xE9;
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
			typedef int(__cdecl* tSendWrapper)(int* packetWrapper);
			typedef int(WINAPI* tSend)(SOCKET s, const char* buf, int len, int flags);
		}

		namespace g
		{
			templates::tSend g_sendPacketGate;
			templates::tSendWrapper g_sendWrapperGate;
			PVOID g_spellPacketWrapper = nullptr;
			PVOID g_movementPacketWrapper = nullptr;
			mappings::packetStructs::MovementPacket g_prevPacket{};
		}

		namespace hookFunctions
		{
			using mappings::packetStructs::MovementPacket;
			using mappings::packetStructs::PacketWrapper;
			using mappings::packetStructs::SpellPacket;
			namespace helpers
			{
				void HandleMovementPacket(MovementPacket* packet)
				{
					g::g_prevPacket = *packet;

					DWORD p1;

					p1 = *(DWORD*)((UINT32)GetModuleHandle(NULL) + 0x8D87A8u);
					p1 = *(DWORD*)(p1 + 0x34);
					p1 = *(DWORD*)(p1 + 0x24);

					float* x = (float*)(p1 + 0x798);
					float* y = x + 1;
					float* z = y + 1;

					*x = packet->x;
					*y = packet->y;
					*z = packet->z;

					if (Settings::bInterceptMovement)
					{
						//packet->rotation = 1.0f;
						packet->z = *z = *z + 1;
					}

					std::stringstream ss;
					ss << xor ("\n[MOVEMENT]packet type: ") << std::hex << std::uppercase << (packet->packetType & 0xFF) << std::dec << std::endl;
					ss << xor ("[MOVEMENT]coords: [")
						<< packet->x << ";"
						<< packet->y << ";"
						<< packet->z << ";"
						<< packet->rotation //rad
						<< "]\n"
						<< xor ("[MOVEMENT]coords: [")
						<< *x << ";"
						<< *y << ";"
						<< *z << ";"
						<< xor ("] - client")
						<< std::endl;

					std::cout << ss.str();
				}

				void HandleSpellPacket(SpellPacket* spellPacket)
				{
					if (Settings::bInterceptSpellCast)
					{
						spellPacket->spellId = 168u;
					}

					std::stringstream ss;
					ss << xor ("\n[SPELL]packet counter: ") << (UINT32)(spellPacket->packetCnt & 0xFF) << std::endl;
					ss << xor ("[SPELL]packet: spellID:") << spellPacket->spellId << " packetType:" << spellPacket->packetType << " packetCount:" << static_cast<UINT32>(spellPacket->packetCnt & 0xFF);
					ss << std::endl;

					std::cout << ss.str();
				}

				void DebugPrint(const PacketWrapper* packetWrapper)
				{
					const auto packetLen{ packetWrapper->packetLen };
					const auto packetStr{ std::string(reinterpret_cast<char*>(packetWrapper->packetPtr), packetLen) };

					std::stringstream ss;
					ss << xor ("PacketWrapper[ ");
					ss << xor ("packetWrapper: 0x") << packetWrapper << std::endl;
					ss << xor ("packetWrapper->packetPtr: 0x") << packetWrapper->packetPtr << std::endl;
					ss << xor ("PacketSize: ") << packetLen << std::endl;
					ss << xor ("buf: ");
					for (size_t i = 0; i < packetLen; ++i)
					{
						ss << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << (static_cast<UINT32>(packetStr[i]) & 0xFF) << std::dec << " ";
					}
					ss << std::endl;

					std::cout << ss.str();
				}

				bool HandlePacket(const PacketWrapper* packetWrapper)
				{
					bool wasPacketHandled{ false };

					switch (packetWrapper->packetPtr->packetType)
					{
					case 0xB5: // W
					case 0xB6: // S
					case 0xB7: // STOP from W or S
					case 0xEE: // continuous walk
					case 0xDA: // rotate with mouse
					case 0xBC: // A
					case 0xBD: // D
					case 0xBE: // STOP from A or D
					case 0xB8: // strafe left
					case 0xB9: // strafe right
					case 0xBA: // stop strafe
					{
						if (!g::g_movementPacketWrapper)
						{
							std::cout << xor ("[MOVEMENT]Datastore pointer stolen!\n");
							g::g_movementPacketWrapper = (PVOID)packetWrapper;
						}
						HandleMovementPacket((MovementPacket*)packetWrapper->packetPtr);
						wasPacketHandled = true;
						break;
					}
					case 0x12E:
					{
						if (!g::g_spellPacketWrapper)
						{
							std::cout << xor ("[SPELL]Datastore pointer stolen!\n");
							g::g_spellPacketWrapper = (PVOID)packetWrapper;
						}
						HandleSpellPacket((SpellPacket*)packetWrapper->packetPtr);
						wasPacketHandled = true;
						break;
					}
					default: break;
					}

					return wasPacketHandled;
				}
			}
			int WINAPI HkSendPacket(SOCKET s, const char* buf, int len, int flags)
			{
				if (!Settings::bSendPacketLog)
					return g::g_sendPacketGate(s, buf, len, flags);

				if (len == sizeof mappings::packetStructs::SpellPacket)
				{
					mappings::packetStructs::SpellPacket packet{};
					memcpy(&packet, buf, len);
					//std::cout << (UINT32)packet.packetCnt << std::endl;
					//std::cout << (UINT32)packet.spellId << std::endl;
					//packet.spellId = 59752;
					//memcpy((void*)buf, &packet,  len);
				}
				if (len == sizeof mappings::packetStructs::SelectCreaturePacket)
				{
					mappings::packetStructs::SelectCreaturePacket packet{};
					memcpy(&packet, buf, len);
					switch (packet.fCreatureTypeMaybe)
					{
					case mappings::packetStructs::SelectCreaturePacket::PLAYER:
					{

						std::cout << "PLAYER GUID (?): [" << packet.playerGuid << "]" << std::endl;
						break;
					}
					case mappings::packetStructs::SelectCreaturePacket::NPC:
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

				return g::g_sendPacketGate(s, buf, len, flags);
			}

			int __cdecl HkSendPacketWrapper(int* packetWrapperPtr)
			{
				const auto packetWrapper{ reinterpret_cast<PacketWrapper*>(packetWrapperPtr) };

				const bool wasPacketHandled{ helpers::HandlePacket(packetWrapper) };

				if (Settings::bSendPacketWrapperLog)
				{
					if (Settings::bLogAllPackets)
					{
						helpers::DebugPrint(packetWrapper);
					}
					else if (wasPacketHandled)
					{
						helpers::DebugPrint(packetWrapper);
					}
				}

				return g::g_sendWrapperGate(packetWrapperPtr);
			}
		}

		bool InitHooks()
		{
			using templates::tSend;
			using templates::tSendWrapper;
			using g::g_sendWrapperGate;
			using g::g_sendPacketGate;
			using hookFunctions::HkSendPacketWrapper;

			const auto hModuleWs32{ GetModuleHandle(xor ("Ws2_32.dll")) };
			if (!hModuleWs32)
			{
				ConsoleHelper::PrintWinError();
				return false;
			}

			const auto originalSendPacketAddress{ reinterpret_cast<tSend>(GetProcAddress(hModuleWs32,xor ("send"))) };
			if (!originalSendPacketAddress)
			{
				ConsoleHelper::PrintWinError();
				return false;
			}
			const auto originalSendPacketWrapperAddress{ reinterpret_cast<tSendWrapper>(static_cast<uintptr_t>(0x6B0B50)) };
			if (!originalSendPacketAddress)
			{
				ConsoleHelper::PrintWinError();
				return false;
			}

			constexpr int originalSendStolenBytesLen{ 5 };
			constexpr int originalSendWrapperStolenBytesLen{ 9 };

			// TODO: hooks being static with no further references is an issue - they should be available globally
			static const Hooker sendHooker{ (PVOID)originalSendPacketAddress, (PVOID)hookFunctions::HkSendPacket, originalSendStolenBytesLen };
			static const Hooker sendWrapperHooker{ (PVOID)originalSendPacketWrapperAddress, (PVOID)HkSendPacketWrapper, originalSendWrapperStolenBytesLen };

			g_sendPacketGate = static_cast<tSend>(sendHooker.getGatewayFuncAddress());
			g_sendWrapperGate = static_cast<tSendWrapper>(sendWrapperHooker.getGatewayFuncAddress());

			return true;
		}
	}
}
