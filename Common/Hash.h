#pragma once
#include <Windows.h>

namespace Hashing
{

	int StringLengthA(
		_In_ char* String
	);

	int StringLengthW(
		_In_ wchar_t* String
	);

	int StrA(
		_In_	char* String
	);

	int StrW(
		_In_ wchar_t* String
	);
}


constexpr int ctime_StringLengthA(
	_In_ char* String
)
{
	char* String2 = nullptr;
	for (String2 = String; *String2; ++String2);
	return (String2 - String);

}

constexpr int ctime_HashStrA(
	_In_	const char* String
)
{
	int Hash = 0;
	size_t Length = ctime_StringLengthA((char*)String);

	unsigned char	curChar = 0;

	for (int i = 0; i < Length; i++)
	{
		curChar = String[i];
		if (curChar >= 'A' && curChar <= 'Z')
			curChar += 'a' - 'A';

		Hash += curChar;
		Hash += Hash << 10;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}
