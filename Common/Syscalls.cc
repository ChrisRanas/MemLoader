#include "Native.h"


namespace IndirectSyscall {
	void* JmpInstruction;
	long	SyscallId;

	void Prepare(
		_In_	void* Gadget,
		_In_	long	Ssn
	)
	{
		JmpInstruction = Gadget;
		SyscallId = Ssn;
	}

	__attribute__((naked))
		long Call(...)
	{
		__asm {
			mov r11, JmpInstruction
			mov eax, SyscallId
			mov r10, rcx
			jmp r11
		}
	}
}
