#include "Native.h"
#include "Hash.h"

#include <iostream>

#define DOWN	32

namespace Win32
{
	PPEB RtlGetPebAddress()
	{
		return reinterpret_cast<PPEB>(__readgsqword(0x60));
	}

	PIMAGE_NT_HEADERS RtlGetImageNtHeaders(
		_In_	void* ModuleAddress
	)
	{
		if (ModuleAddress == nullptr)
		{
			return nullptr;
		}

		PIMAGE_DOS_HEADER	pImageDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(ModuleAddress);
		if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			return nullptr;
		}

		PIMAGE_NT_HEADERS pImageNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<unsigned char*>(ModuleAddress) + pImageDosHeader->e_lfanew);
		if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		{
			return nullptr;
		}
		else
		{
			return pImageNtHeaders;
		}
	}

	void* RtlGetModuleAddress(
		_In_	char* ModuleName
	)
	{
		PPEB pPeb = RtlGetPebAddress();

		UINT_PTR	uiListhead = reinterpret_cast<UINT_PTR>(pPeb->Ldr->InLoadOrderModuleList.Flink);
		PLIST_ENTRY pListEntry = reinterpret_cast<PLIST_ENTRY>(uiListhead);

		if (ModuleName == nullptr)
		{
			return reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(pListEntry)->DllBase;
		}
		else
		{
			do
			{
				if (
					Hashing::StrW(reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(pListEntry)->BaseDllName.Buffer) ==
					Hashing::StrA(ModuleName)
					)
				{
					return reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(pListEntry)->DllBase;
				}
				pListEntry = pListEntry->Flink;

			} while (reinterpret_cast<UINT_PTR>(pListEntry->Flink) != uiListhead);
		}
		return nullptr;
	}

	void* RtlGetModuleAddressWithHash(
		_In_	int	ModuleHash
	)
	{
		PPEB pPeb = RtlGetPebAddress();

		UINT_PTR	uiListhead = reinterpret_cast<UINT_PTR>(pPeb->Ldr->InLoadOrderModuleList.Flink);
		PLIST_ENTRY pListEntry = reinterpret_cast<PLIST_ENTRY>(uiListhead);

		do
		{
			if (ModuleHash == Hashing::StrW(reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(pListEntry)->BaseDllName.Buffer))
			{
				return reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(pListEntry)->DllBase;
			}


			pListEntry = pListEntry->Flink;

		} while (reinterpret_cast<UINT_PTR>(pListEntry->Flink) != uiListhead);

		return nullptr;
		return nullptr;
	}

	void* RtlGetProcedureAddress(
		_In_	void* ModuleAddress,
		_In_	char* ProcedureName
	)
	{
		PIMAGE_NT_HEADERS	pImageNtHeaders = RtlGetImageNtHeaders(ModuleAddress);
		if (!pImageNtHeaders)
		{
			return nullptr;
		}

		PIMAGE_EXPORT_DIRECTORY		pImageExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<unsigned char*>(ModuleAddress) + pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		unsigned long* pdwAddressOfFunctions = reinterpret_cast<unsigned long*>(reinterpret_cast<unsigned char*>(ModuleAddress) + pImageExportDir->AddressOfFunctions);
		unsigned long* pdwAddressOfNames = reinterpret_cast<unsigned long*>(reinterpret_cast<unsigned char*>(ModuleAddress) + pImageExportDir->AddressOfNames);
		unsigned short* pwAddressOfNameOrdinales = reinterpret_cast<unsigned short*>(reinterpret_cast<unsigned char*>(ModuleAddress) + pImageExportDir->AddressOfNameOrdinals);

		for (int i = 0; i < pImageExportDir->NumberOfFunctions; i++)
		{
			LPSTR lpFunctionName = reinterpret_cast<LPSTR>(reinterpret_cast<unsigned char*>(ModuleAddress) + pdwAddressOfNames[i]);
			if (
				Hashing::StrA(ProcedureName) ==
				Hashing::StrA(lpFunctionName)
				)
			{
				return reinterpret_cast<void*>((reinterpret_cast<char*>(ModuleAddress) + pdwAddressOfFunctions[pwAddressOfNameOrdinales[i]]));
			}
		}

		return nullptr;
	}

	void* RtlGetProcedureAddressWithHash(
		_In_	void* ModuleAddress,
		_In_	int		ProcedureHash
	)
	{
		if (!ModuleAddress)
		{
			return nullptr;
		}

		PIMAGE_NT_HEADERS	pImageNtHeaders = RtlGetImageNtHeaders(ModuleAddress);
		if (!pImageNtHeaders)
		{
			return nullptr;
		}

		PIMAGE_EXPORT_DIRECTORY		pImageExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<unsigned char*>(ModuleAddress) + pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
		unsigned long* pdwAddressOfFunctions = reinterpret_cast<unsigned long*>(reinterpret_cast<unsigned char*>(ModuleAddress) + pImageExportDir->AddressOfFunctions);
		unsigned long* pdwAddressOfNames = reinterpret_cast<unsigned long*>(reinterpret_cast<unsigned char*>(ModuleAddress) + pImageExportDir->AddressOfNames);
		unsigned short* pwAddressOfNameOrdinales = reinterpret_cast<unsigned short*>(reinterpret_cast<unsigned char*>(ModuleAddress) + pImageExportDir->AddressOfNameOrdinals);

		for (int i = 0; i < pImageExportDir->NumberOfFunctions; i++)
		{
			if (ProcedureHash == Hashing::StrA(reinterpret_cast<char*>(ModuleAddress) + pdwAddressOfNames[i]))
			{
				return reinterpret_cast<void*>((reinterpret_cast<char*>(ModuleAddress) + pdwAddressOfFunctions[pwAddressOfNameOrdinales[i]]));
			}
		}

		return nullptr;
	}

	bool RtlVerifyPresenceOfHook(
		_In_	void* NtFunctionAddress
	)
	{
		if (!NtFunctionAddress)
		{
			return false;
		}

		if (
			reinterpret_cast<unsigned char*>(NtFunctionAddress)[0] == 0x4C &&
			reinterpret_cast<unsigned char*>(NtFunctionAddress)[1] == 0x8B &&
			reinterpret_cast<unsigned char*>(NtFunctionAddress)[2] == 0xD1 &&
			reinterpret_cast<unsigned char*>(NtFunctionAddress)[3] == 0xB8 &&
			reinterpret_cast<unsigned char*>(NtFunctionAddress)[6] == 0x00 &&
			reinterpret_cast<unsigned char*>(NtFunctionAddress)[7] == 0x00
			)
		{
			return true;
		}
		else
		{
			return false;
		}
	}

	bool RtlGetSyscall(
		_In_	void* NtFunctionAddress,
		_In_	long* pSyscallId,
		_In_	void** pSyscallInstruction
	)
	{
		if (RtlVerifyPresenceOfHook(NtFunctionAddress))
		{
			long high = reinterpret_cast<unsigned char*>(NtFunctionAddress)[5];
			long low = reinterpret_cast<unsigned char*>(NtFunctionAddress)[4];

			*pSyscallId = (high << 8) | low;
			*pSyscallInstruction = reinterpret_cast<void**>((reinterpret_cast<unsigned char*>(NtFunctionAddress) + 0x12));

			return true;

		}
		else
		{
			for (int i = 0; i < 500; i++)
			{
				if (
					reinterpret_cast<unsigned char*>(NtFunctionAddress)[i * DOWN] == 0x4C &&
					reinterpret_cast<unsigned char*>(NtFunctionAddress)[1 + i * DOWN] == 0x8B &&
					reinterpret_cast<unsigned char*>(NtFunctionAddress)[2 + i * DOWN] == 0xD1 &&
					reinterpret_cast<unsigned char*>(NtFunctionAddress)[3 + i * DOWN] == 0xB8 &&
					reinterpret_cast<unsigned char*>(NtFunctionAddress)[6 + i * DOWN] == 0x00 &&
					reinterpret_cast<unsigned char*>(NtFunctionAddress)[7 + i * DOWN] == 0x00
					)
				{
					long high = reinterpret_cast<unsigned char*>(NtFunctionAddress)[5 + i * DOWN];
					long low = reinterpret_cast<unsigned char*>(NtFunctionAddress)[4 + i * DOWN];

					*pSyscallId = (high << 8) | low - 1;
					*pSyscallInstruction = reinterpret_cast<void**>((reinterpret_cast<unsigned char*>(NtFunctionAddress) + 0x12));
					return true;

				}
			}
			return false;
		}
	}

	LARGE_INTEGER ConvertLongToLargeInteger(
		_In_	unsigned long ulNbr
	)
	{
		LARGE_INTEGER li;
		li.QuadPart = -(static_cast<LONGLONG>(ulNbr) * 10000);
		return li;
	}

	bool RtlGetSectionInformationWithHash(
		_In_	void* ModuleAddress,
		_Inout_	void** SectionAddress,
		_Inout_	long* SectionSize,
		_In_	long	SectionHash
	)
	{
		PIMAGE_NT_HEADERS	pImageNtHeaders = RtlGetImageNtHeaders(ModuleAddress);
		if (pImageNtHeaders == nullptr)
		{
			return false;
		}

		PIMAGE_SECTION_HEADER	ppSecHeader = IMAGE_FIRST_SECTION(pImageNtHeaders);

		for (int i = 0; i < pImageNtHeaders->FileHeader.NumberOfSections; i++)
		{
			if (Hashing::StrA((char*)ppSecHeader[i].Name) == SectionHash)
			{
				*SectionSize = ppSecHeader[i].SizeOfRawData;
				*SectionAddress = reinterpret_cast<void*>(reinterpret_cast<char*>(ModuleAddress) + ppSecHeader[i].PointerToRawData);

				return true;
			}
		}

		return false;
	}

	void* RtlAtomicExchange(
		_In_	volatile void* Destination,
		_Inout_	void* Value
	)
	{
		void* OldValue = *(void**)Destination;
		*(void**)Destination = Value;
		return OldValue;
	}



}
