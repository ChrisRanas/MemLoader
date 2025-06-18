#pragma once
#include <Windows.h>
#include <iostream>

bool ExecuteAssembly(
	_In_	void* AssemblyContent,
	_In_	long		AssemblySize,
	_In_	std::wstring* AssemblyArgs
);