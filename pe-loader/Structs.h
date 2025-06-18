#pragma once

#include "Common.h"

typedef NTSTATUS	(__stdcall* xTpAllocWork)			(PTP_WORK*, PTP_WORK_CALLBACK, PVOID, PTP_CALLBACK_ENVIRON);
typedef VOID		(__stdcall* xTpPostWork)			(PTP_WORK);
typedef VOID		(__stdcall* xTpReleaseWork)			(PTP_WORK);
typedef void*		(__stdcall* xLoadLibraryA)			(char*);
typedef void*		(__stdcall* xWaitForSingleObject)	(void*, long);

typedef struct _CALLBAKC_INFO {
	void* FunctionAddress;
	void* Module;
} CALLBACK_INFO, * PCALLBACK_INFO;

typedef struct _WORKER_FUNCTION {
	xTpAllocWork			TpAllocWork;
	xTpPostWork				TpPostWork;
	xTpReleaseWork			TpReleaseWork;
	xLoadLibraryA			LoadLibraryA;
	xWaitForSingleObject	WaitForSingleObject;
} WORKER_FUNCTION, * PWORKER_FUNCTION;

typedef struct _SYSCALL
{
	SYSCALL_ENTRY	NtAllocateVirtualMemory;
	SYSCALL_ENTRY	NtProtectVirtualMemory;
	SYSCALL_ENTRY	NtFreeVirtualMemory;
	SYSCALL_ENTRY	NtCreateThreadEx;
	SYSCALL_ENTRY	NtGetContextThread;
	SYSCALL_ENTRY	NtSetContextThread;
	SYSCALL_ENTRY	NtResumeThread;
	SYSCALL_ENTRY	NtWaitForSingleObject;
} SYSCALL, * PSYSCALL;

