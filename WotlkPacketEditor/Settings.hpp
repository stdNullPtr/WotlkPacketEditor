#pragma once

class Settings
{
public:
	Settings() = delete;

	// use atomic_bools if thread-safety is needed

	inline static bool bSendPacketLog{ false };
	inline static bool bSendPacketWrapperLog{ false };
	inline static bool bLogAllPackets{ false };
};
