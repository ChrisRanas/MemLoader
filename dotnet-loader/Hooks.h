#pragma once
#include <Windows.h>

long	VehHandler(
	_In_	PEXCEPTION_POINTERS		ExceptionInfo
);

bool PutHwbp(
	_In_	void* FunctionAddress1,
	_In_	void* FunctionAddress2
);

bool PrepareHook();

bool CleanUp();