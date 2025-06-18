#ifdef _DEBUG
#include <iostream>
#endif

#include "Native.h"
#include "Common.h"
#include "Hooks.h"

#define D_API( x )  decltype( x ) * x
typedef struct {
	WORD offset : 12;
	WORD type : 4;
} IMAGE_RELOC, * PIMAGE_RELOC;

namespace Reflective
{
	void CopySections(
		_In_	void* pMemPeAddr,
		_In_	PIMAGE_NT_HEADERS	pNtHeader,
		_In_	void* peContent
	)
	{
		auto ppSecHeader = IMAGE_FIRST_SECTION(pNtHeader);

		for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
		{
			auto pDataDst = reinterpret_cast<PVOID>(
				reinterpret_cast<PBYTE>(pMemPeAddr) + ppSecHeader[i].VirtualAddress
				);
			auto pDataSrc = reinterpret_cast<PVOID>(
				reinterpret_cast<PBYTE>(peContent) + ppSecHeader[i].PointerToRawData
				);
			int dwDataSize = ppSecHeader[i].SizeOfRawData;

			RtlCopyMemory(pDataDst, pDataSrc, dwDataSize);
		}
	}


	bool PatchMemoryProtection(
		_In_	void* pMemPeAddr,
		_In_	PIMAGE_NT_HEADERS		pNtHeader,
		_In_	PSYSCALL_ENTRY			NtProtectVirtualMemory
	)
	{
		PIMAGE_SECTION_HEADER pSecHeader = IMAGE_FIRST_SECTION(pNtHeader);
		NTSTATUS status = STATUS_SUCCESS;

		for (DWORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
		{
			void* pSectionAddr = reinterpret_cast<void*>(
				reinterpret_cast<BYTE*>(pMemPeAddr) + pSecHeader[i].VirtualAddress
				);
			size_t	sectionSize = pSecHeader[i].SizeOfRawData;
			DWORD	dwMemProtect = 0;
			DWORD	dwOldProtect = 0;

			if (pSecHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE)
				dwMemProtect = PAGE_WRITECOPY;

			if (pSecHeader[i].Characteristics & IMAGE_SCN_MEM_READ)
				dwMemProtect = PAGE_READONLY;

			if ((pSecHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pSecHeader[i].Characteristics & IMAGE_SCN_MEM_READ))
				dwMemProtect = PAGE_READWRITE;

			if (pSecHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
				dwMemProtect = PAGE_EXECUTE;

			if ((pSecHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pSecHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE))
				dwMemProtect = PAGE_EXECUTE_WRITECOPY;

			if ((pSecHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pSecHeader[i].Characteristics & IMAGE_SCN_MEM_READ))
				dwMemProtect = PAGE_EXECUTE_READ;

			if ((pSecHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pSecHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pSecHeader[i].Characteristics & IMAGE_SCN_MEM_READ))
				dwMemProtect = PAGE_EXECUTE_READWRITE;

			unsigned long OldProtect = 0;
			IndirectSyscall::Prepare(NtProtectVirtualMemory->Jmp, NtProtectVirtualMemory->SyscallId);
			status = IndirectSyscall::Call(NtCurrentProcess, &pSectionAddr, &sectionSize, dwMemProtect, &OldProtect);

			if (NT_ERROR(status))
			{
				return false;
			}


		}
		return true;
	}

	void ApplyBaseRelocations(
		_In_	void* pMemPeAddr,
		_In_	PIMAGE_NT_HEADERS	pNtHeader
	)
	{
		auto pImgBaseReloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
			reinterpret_cast<UINT_PTR>(pMemPeAddr) +
			pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
			);

		ULONG_PTR uPtrDelta = reinterpret_cast<UINT_PTR>(pMemPeAddr) - pNtHeader->OptionalHeader.ImageBase;

		if (pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 0)
		{
			return;
		}

		auto pCurrentReloc = pImgBaseReloc;
		while (pCurrentReloc->SizeOfBlock > 0)
		{
			auto uiRelocBase = reinterpret_cast<UINT_PTR>(pMemPeAddr) + pCurrentReloc->VirtualAddress;
			auto pImgReloc = reinterpret_cast<PIMAGE_RELOC>(
				reinterpret_cast<UINT_PTR>(pCurrentReloc) + sizeof(IMAGE_BASE_RELOCATION)
				);

			auto numRelocations = (pCurrentReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);

			for (size_t i = 0; i < numRelocations; ++i)
			{
				switch (pImgReloc->type)
				{
				case IMAGE_REL_BASED_DIR64:
					*reinterpret_cast<ULONG_PTR*>(uiRelocBase + pImgReloc->offset) += uPtrDelta;
					break;

				case IMAGE_REL_BASED_HIGHLOW:
					*reinterpret_cast<DWORD*>(uiRelocBase + pImgReloc->offset) += static_cast<DWORD>(uPtrDelta);
					break;

				case IMAGE_REL_BASED_HIGH:
					*reinterpret_cast<WORD*>(uiRelocBase + pImgReloc->offset) += HIWORD(uPtrDelta);
					break;

				case IMAGE_REL_BASED_LOW:
					*reinterpret_cast<WORD*>(uiRelocBase + pImgReloc->offset) += LOWORD(uPtrDelta);
					break;

				default:
					break;
				}

				pImgReloc = reinterpret_cast<PIMAGE_RELOC>(
					reinterpret_cast<PBYTE>(pImgReloc) + sizeof(IMAGE_RELOC)
					);
			}

			pCurrentReloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
				reinterpret_cast<UINT_PTR>(pCurrentReloc) + pCurrentReloc->SizeOfBlock
				);
		}
	}

	bool ProcessImportTable(
		_In_	void* pMemPeAddr,
		_In_	PIMAGE_NT_HEADERS	pNtHeader
	)
	{

		auto pImgImportDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
			reinterpret_cast<UINT_PTR>(pMemPeAddr) +
			pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
			);

		while (pImgImportDescriptor->Name != 0)
		{
			auto lpModuleName = reinterpret_cast<char*>(
				reinterpret_cast<UINT_PTR>(pMemPeAddr) + pImgImportDescriptor->Name
				);
#ifndef _DEBUG
			
			HMODULE hModAddr = reinterpret_cast<HMODULE>(Obf::Load(lpModuleName));
#else
			HMODULE hModAddr = LoadLibraryA(lpModuleName);
#endif
			if (!hModAddr)
			{
#ifdef _DEBUG
				printf("[!] Fail to load module : %s\n", lpModuleName);
#endif
				return false;
			}

			auto pOgThunkData = reinterpret_cast<PIMAGE_THUNK_DATA>(
				reinterpret_cast<UINT_PTR>(pMemPeAddr) + pImgImportDescriptor->OriginalFirstThunk
				);
			auto pFirstThunk = reinterpret_cast<PIMAGE_THUNK_DATA>(
				reinterpret_cast<UINT_PTR>(pMemPeAddr) + pImgImportDescriptor->FirstThunk
				);

			while (pOgThunkData->u1.AddressOfData != 0)
			{
				void* pFunctionAddr = nullptr;

				if (IMAGE_SNAP_BY_ORDINAL(pOgThunkData->u1.Ordinal))
				{

					pFunctionAddr = GetProcAddress(hModAddr, MAKEINTRESOURCEA(pOgThunkData->u1.Ordinal));


					if (!pFunctionAddr)
					{
#ifdef _DEBUG
						printf("[!] Fail to solve function from ordinal : %d\n", MAKEINTRESOURCEA(pOgThunkData->u1.Ordinal));
#endif
						return false;
					}

					pFirstThunk->u1.Function = reinterpret_cast<ULONG_PTR>(pFunctionAddr);
				}
				else
				{
					auto pImgImportName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
						reinterpret_cast<UINT_PTR>(pMemPeAddr) + pOgThunkData->u1.AddressOfData
						);

					pFunctionAddr = FunctionHooks(Hashing::StrA(pImgImportName->Name));
					if (!pFunctionAddr)
					{
						pFunctionAddr = GetProcAddress(hModAddr, pImgImportName->Name); 
						if (!pFunctionAddr)
						{
#ifdef _DEBUG
							printf("[!] Fail to solve function from name : %s\n", pImgImportName->Name);
#endif
							return false;
						}
					}
#ifdef _DEBUG
					printf("[*] Function : %s addr : %p\n", pImgImportName->Name, pFunctionAddr);
#endif
					pFirstThunk->u1.Function = reinterpret_cast<ULONG_PTR>(pFunctionAddr);


				}

				pOgThunkData++;
				pFirstThunk++;
			}

			pImgImportDescriptor++;
		}
		return true;

	}

}