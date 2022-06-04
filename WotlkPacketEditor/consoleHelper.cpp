// ReSharper disable CppClangTidyClangDiagnosticCastQual
#include "ConsoleHelper.hpp"

void ConsoleHelper::ClearScreen() const
{
	constexpr COORD homeCoords{ 0, 0 };
	static const std::string fillerString{ std::string(7000, ' ') };

	SetConsoleCursorPosition(m_hStdOut, homeCoords);
	std::cout << fillerString;
	SetConsoleCursorPosition(m_hStdOut, homeCoords);
}

void ConsoleHelper::ShowConsoleCursor(bool showFlag) const
{
	CONSOLE_CURSOR_INFO cursorInfo;

	GetConsoleCursorInfo(m_hStdOut, &cursorInfo);
	cursorInfo.bVisible = showFlag;
	SetConsoleCursorInfo(m_hStdOut, &cursorInfo);
}

bool ConsoleHelper::InitConsole()
{
	FreeConsole();

	if (AllocConsole() == 0)
	{
		return false;
	}

	errno_t err{ 0 };
	err = freopen_s(&m_fInStream, xor("CONIN$"), "r", stdin);
	if (err != 0)
	{
		return false;
	}

	err = freopen_s(&m_fOutStream, xor ("CONOUT$"), "w", stdout);
	if (err != 0)
	{
		return false;
	}

	err = freopen_s(&m_fErrStream, xor ("CONOUT$"), "w", stderr);
	if (err != 0)
	{
		return false;
	}

	if ((m_hStdOut = GetStdHandle(STD_OUTPUT_HANDLE)) == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	return true;
}

void ConsoleHelper::DestroyConsole() const
{
	fclose(m_fInStream);
	fclose(m_fOutStream);
	fclose(m_fErrStream);
	FreeConsole();
}

ConsoleHelper::ConsoleHelper() : m_fInStream(nullptr), m_fOutStream(nullptr), m_fErrStream(nullptr), m_hStdOut(nullptr)
{
}

void ConsoleHelper::PrintWinError()
{
	std::cerr << xor("[WIN_ERR] ") << GetLastError() << std::endl;
}