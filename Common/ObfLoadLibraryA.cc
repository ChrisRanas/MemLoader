#ifdef _DEBUG
#include <iostream>
#endif

#include "Native.h"
#include "Hash.h"
#include "Win32.h"

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

#define MAX_CHECK	10
#define DELAY_CHECK	250

namespace Obf {

	__attribute__((naked))
		void CALLBACK WorkCallback(
			_In_	PTP_CALLBACK_INSTANCE	Instance,
			_In_	PVOID					Context,
			_In_	PTP_WORK				Work
		)
	{
		__asm {
			mov rcx, [rdx + 8h]
			mov r10, [rdx]

			jmp r10
		}
	}

	void* GetModuleAddress(
		_In_	char* ModuleName,
		_In_	PWORKER_FUNCTION		WorkerFunc
	)
	{
		void* ModuleAddress = nullptr;

		for (int i = 0; i < MAX_CHECK; i++)
		{
			ModuleAddress = Win32::RtlGetModuleAddress(ModuleName);
			if (ModuleAddress != nullptr)
			{
				return ModuleAddress;
			}
			else
			{
				WorkerFunc->WaitForSingleObject(NtCurrentProcess, DELAY_CHECK);
			}
		}

		return ModuleAddress;
	}

	void* Load(
		_In_	char* ModuleName
	)
	{
		void* pNtdll = Win32::RtlGetModuleAddressWithHash(ctime_HashStrA("ntdll.dll"));
		void* pKernel32 = Win32::RtlGetModuleAddressWithHash(ctime_HashStrA("KERNEL32.DLL"));

		if (!pNtdll || !pKernel32)
		{
			return false;
		}

		WORKER_FUNCTION WorkerFunc = { 0 };

		WorkerFunc.TpAllocWork = reinterpret_cast<xTpAllocWork>(Win32::RtlGetProcedureAddressWithHash(pNtdll, ctime_HashStrA("TpAllocWork")));
		WorkerFunc.TpPostWork = reinterpret_cast<xTpPostWork>(Win32::RtlGetProcedureAddressWithHash(pNtdll, ctime_HashStrA("TpPostWork")));
		WorkerFunc.TpReleaseWork = reinterpret_cast<xTpReleaseWork>(Win32::RtlGetProcedureAddressWithHash(pNtdll, ctime_HashStrA("TpReleaseWork")));

		WorkerFunc.LoadLibraryA = reinterpret_cast<xLoadLibraryA>(Win32::RtlGetProcedureAddressWithHash(pKernel32, ctime_HashStrA("LoadLibraryA")));
		WorkerFunc.WaitForSingleObject = reinterpret_cast<xWaitForSingleObject>(Win32::RtlGetProcedureAddressWithHash(pKernel32, ctime_HashStrA("WaitForSingleObject")));

		if (
			!WorkerFunc.TpAllocWork ||
			!WorkerFunc.TpPostWork ||
			!WorkerFunc.TpReleaseWork ||
			!WorkerFunc.LoadLibraryA ||
			!WorkerFunc.WaitForSingleObject
			)
		{
			return nullptr;
		}

		void* test = &WorkCallback;
#ifdef _DEBUG
		printf("[ObfLoadLibraryA] Module to load : %s\n\tCallback : %p\n", ModuleName, test);
#endif

		void* ModuleAddress = Win32::RtlGetModuleAddress(ModuleName);
		if (ModuleAddress != nullptr)
		{
			return ModuleAddress;
		}


		PTP_WORK WorkReturn = NULL;
		CALLBACK_INFO callbackInfo = { WorkerFunc.LoadLibraryA, ModuleName };

		NTSTATUS status = WorkerFunc.TpAllocWork(&WorkReturn,
			reinterpret_cast<PTP_WORK_CALLBACK>(test),
			&callbackInfo,
			nullptr);

#ifdef _DEBUG
		printf("TpAllocWork status : 0x%llx\nWorker handle : %llx\n", status, WorkReturn);
#endif
		WorkerFunc.TpPostWork(WorkReturn);
		WorkerFunc.TpReleaseWork(WorkReturn);

		ModuleAddress = GetModuleAddress(ModuleName, &WorkerFunc);
		if (ModuleAddress != nullptr)
		{
			return ModuleAddress;
		}
		else
		{
#ifdef _DEBUG
			printf("[!!] Fail to solve module %s with obfuscated LoadLibraryA ! Do a legit call !!\n", ModuleName);
#endif
			return WorkerFunc.LoadLibraryA(ModuleName);
		}
	}
}
