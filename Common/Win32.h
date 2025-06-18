#pragma once

#include "Native.h"     

#define RESOLVE_SYSCALL(hModule, procName) Win32::RtlGetSyscall(Win32::RtlGetProcedureAddressWithHash(hModule, ctime_HashStrA(#procName)), &pSyscall->procName.SyscallId, &pSyscall->procName.Jmp)

namespace Win32
{
    PPEB RtlGetPebAddress();

    PIMAGE_NT_HEADERS RtlGetImageNtHeaders(
        _In_	void* ModuleAddress
    );

    void* RtlGetModuleAddress(
        _In_ char* ModuleName
    );

    void* RtlGetModuleAddressWithHash(
        _In_	int	ModuleHash
    );

    void* RtlGetProcedureAddress(
        _In_	void* ModuleAddress,
        _In_	char* ProcedureName
    );

    void* RtlGetProcedureAddressWithHash(
        _In_	void* ModuleAddress,
        _In_	int		ProcedureHash
    );

    bool RtlVerifyPresenceOfHook(
        _In_ void* NtFunctionAddress
    );

    bool RtlGetSyscall(
        _In_ void* NtFunctionAddress,
        _In_ long* pSyscallId,
        _In_ void** pSyscallInstruction
    );

    LARGE_INTEGER ConvertLongToLargeInteger(
        _In_	unsigned long ulNbr
    );

    bool RtlGetSectionInformationWithHash(
        _In_	void* ModuleAddress,
        _Inout_	void** SectionAddress,
        _Inout_	long* SectionSize,
        _In_	long	SectionHash
    );

    void* RtlAtomicExchange(
        _In_	volatile void* Destination,
        _Inout_	void* Value
    );
}