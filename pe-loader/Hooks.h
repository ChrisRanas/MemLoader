#pragma once
#pragma once

#include <windows.h>

bool InitArgs(
	_In_	char* Args
);

bool PutHook(
	_In_	void* ModuleAddress,
	_In_	PIMAGE_NT_HEADERS	pImagesNtHeaders
);

void* FunctionHooks(
	_In_	int HashFunctionName
);