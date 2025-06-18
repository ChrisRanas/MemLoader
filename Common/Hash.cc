#include <windows.h>

namespace Hashing
{

	int StringLengthA(
		_In_ char* String
	)
	{
		char* String2;

		for (String2 = String; *String2; ++String2);

		return (String2 - String);
	}

	int StringLengthW(
		_In_ wchar_t* String
	)
	{
		LPCWSTR String2;

		for (String2 = String; *String2; ++String2);

		return (String2 - String);
	}

	int StrA(
		_In_	char* String
	)
	{
		size_t Index = 0;
		int Hash = 0;
		size_t Length = StringLengthA(String);

		unsigned char	curChar = 0;

		while (Index != Length)
		{
			curChar = String[Index++];
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

	int StrW(
		_In_ wchar_t* String
	)
	{
		size_t Index = 0;
		int Hash = 0;
		size_t Length = StringLengthW(String);
		unsigned char	curChar = 0;

		while (Index != Length)
		{
			curChar = String[Index++];
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
}