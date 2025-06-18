#pragma once

#include "Native.h"

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