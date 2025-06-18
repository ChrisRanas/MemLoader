#pragma once

#include "Native.h"
#include "Common.h"

namespace Reflective
{
	bool ProcessImportTable(
		_In_	void* pMemPeAddr,
		_In_	PIMAGE_NT_HEADERS	pNtHeader
	);

	void ApplyBaseRelocations(
		_In_	void* pMemPeAddr,
		_In_	PIMAGE_NT_HEADERS	pNtHeader
	);

	bool PatchMemoryProtection(
		_In_	void* pMemPeAddr,
		_In_	PIMAGE_NT_HEADERS		pNtHeader,
		_In_	PSYSCALL_ENTRY			NtAllocateVirtualMemory
	);

	void CopySections(
		_In_	void* pMemPeAddr,
		_In_	PIMAGE_NT_HEADERS	pNtHeader,
		_In_	void* peContent
	);
}