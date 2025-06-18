#pragma once

#include "Native.h"

#define RESOLVE_SYSCALL(hModule, procName) Win32::RtlGetSyscall(Win32::RtlGetProcedureAddressWithHash(hModule, ctime_HashStrA(#procName)), &pSyscall->procName.SyscallId, &pSyscall->procName.Jmp)


#define NT_CREATE_THREAD_EX_SUSPENDED 1
#define NT_CREATE_THREAD_EX_ALL_ACCESS 0x001FFFFF

typedef struct _SYSCALL_ENTRY
{
    void* Jmp;
    long	SyscallId;
} SYSCALL_ENTRY, * PSYSCALL_ENTRY;

namespace IndirectSyscall {

    void Prepare(
        _In_	void* Gadget,
        _In_	long	Ssn
    );

    long Call(...);

}

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
        _In_ void* ModuleAddress,
        _In_ char* ProcedureName
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

namespace Obf 
{
    void* Load(
        _In_	char* ModuleName
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


typedef struct _USTRING
{
    unsigned long Length;
    unsigned long MaximumLength;
    unsigned char* Buffer;
} USTRING, * PUSTRING;

typedef struct _RC4_CONTEXT
{
    unsigned char state[256];
    unsigned char x, y;
} RC4_CONTEXT;

void SystemFunction032(PUSTRING data, PUSTRING key);

void* RemovePadding(
    _In_    unsigned char* Data,
    _In_    int                 DataSize,
    _In_    int                 RealSize
);

