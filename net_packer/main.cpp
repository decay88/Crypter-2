#include <windows.h>
#include <tchar.h>
#include <metahost.h>
#include <winternl.h>
#pragma comment(lib, "mscoree.lib")

// Import mscorlib.tlb (Microsoft Common Language Runtime Class Library).
#import "mscorlib.tlb" raw_interfaces_only \
	rename("ReportEvent", "InteropServices_ReportEvent")
using namespace mscorlib;

int load_assembly(void *bytes, size_t size)
{

	HRESULT hr;

	ICLRMetaHost *pMeta = NULL;
	ICLRRuntimeInfo *pRun = NULL;
	ICorRuntimeHost *pCor = NULL;

	IUnknownPtr UnkAppDomain = NULL;
	_AppDomainPtr AppDomain = NULL;

	_AssemblyPtr Assembly = NULL;
	_MethodInfoPtr Method = NULL;

	hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_PPV_ARGS(&pMeta));
	if (FAILED(hr))
		goto failed;

	hr = pMeta->GetRuntime(_T("v2.0.50727"), IID_PPV_ARGS(&pRun));
	if (FAILED(hr))
		goto failed;

	BOOL will_load;
	hr = pRun->IsLoadable(&will_load);
	if (FAILED(hr) || !will_load)
		goto failed;

	hr = pRun->GetInterface(CLSID_CorRuntimeHost, IID_PPV_ARGS(&pCor));
	if (FAILED(hr))
		goto failed;

	hr = pCor->Start();
	if (FAILED(hr))
		goto failed;

	hr = pCor->GetDefaultDomain(&UnkAppDomain);
	if (FAILED(hr))
		goto failed;

	hr = UnkAppDomain->QueryInterface(IID_PPV_ARGS(&AppDomain));
	if (FAILED(hr))
		goto failed;

	SAFEARRAYBOUND sab[1];
	sab[0].lLbound = 0;
	sab[0].cElements = size;

	SAFEARRAY *sa = SafeArrayCreate(VT_UI1, 1, sab);
	if (sa == NULL)
		goto failed;

	void *sa_raw;
	hr = SafeArrayAccessData(sa, &sa_raw);
	if (FAILED(hr))
		goto failed;

	memcpy(sa_raw, bytes, size);

	SafeArrayUnaccessData(sa);

	hr = AppDomain->Load_3(sa, &Assembly);
	if (FAILED(hr))
		goto failed;

	hr = Assembly->get_EntryPoint(&Method);
	if (FAILED(hr))
		goto failed;

	SAFEARRAY *mtd_params;
	hr = Method->GetParameters(&mtd_params);
	if (FAILED(hr))
		goto failed;

	SAFEARRAY *p2;
	SAFEARRAY *params;
	if (mtd_params->rgsabound->cElements != 0)
	{
		INT argc;
		WCHAR ** _argv = CommandLineToArgvW(GetCommandLineW(), &argc);

		params = SafeArrayCreateVector(VT_BSTR, 0, argc);
		if (params == NULL)
			goto failed;

		for (int i = 0; i < argc; i++) {
			long lIndex = i;

			hr = SafeArrayPutElement(params, &lIndex, SysAllocString(_argv[i]));
			if (FAILED(hr))
				goto failed;
		}

		p2 = SafeArrayCreateVector(VT_VARIANT, 0, 1);
		LONG l2 = 0;
		VARIANT vp2;

		vp2.vt = VT_ARRAY | VT_BSTR;
		vp2.parray = params;
		hr = SafeArrayPutElement(p2, &l2, &vp2);
		if (FAILED(hr))
			goto failed;
	}
	else {
		SAFEARRAYBOUND sabc[1];
		sabc[0].cElements = 0;
		sabc[0].lLbound = 0;

		p2 = SafeArrayCreate(VT_VARIANT, 1, sabc);
	}

	CoInitialize(NULL);


	PIMAGE_NT_HEADERS nt_hdr = (PIMAGE_NT_HEADERS)(((PIMAGE_DOS_HEADER)bytes)->e_lfanew + (ULONG)bytes);
	PIMAGE_SECTION_HEADER sec_hdr = IMAGE_FIRST_SECTION(nt_hdr);

	void *res_img = VirtualAlloc(0, nt_hdr->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	memcpy(res_img, bytes, nt_hdr->OptionalHeader.SizeOfHeaders);
	for (int i = 0; i < nt_hdr->FileHeader.NumberOfSections; i++)
		memcpy((LPVOID)(sec_hdr[i].VirtualAddress + (ULONG)res_img), (LPVOID)(sec_hdr[i].PointerToRawData + (ULONG)bytes), sec_hdr[i].SizeOfRawData);

	DWORD RelocDirSize = nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	PIMAGE_BASE_RELOCATION pRel = (PIMAGE_BASE_RELOCATION)((ULONG)res_img + nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	while (RelocDirSize)
	{
		DWORD SizeOfBlock = pRel->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION);
		PUSHORT pEntries = PUSHORT(((ULONG)pRel) + sizeof(IMAGE_BASE_RELOCATION));

		for (; SizeOfBlock; pEntries++, SizeOfBlock -= sizeof(USHORT))
		{
			if ((*pEntries >> 12) & IMAGE_REL_BASED_HIGHLOW)
			{
				PDWORD pFixup = PDWORD(((ULONG)res_img) + pRel->VirtualAddress + (*pEntries & (USHORT)0xfff));
				*pFixup += (((ULONG)res_img) - nt_hdr->OptionalHeader.ImageBase);
			}
		}
		RelocDirSize -= pRel->SizeOfBlock;
		pRel = PIMAGE_BASE_RELOCATION((ULONG)pRel + pRel->SizeOfBlock);
	}

	PPEB _peb = (PPEB)__readfsdword(0x30);
	_peb->Reserved3[1] = res_img;
	((PLDR_DATA_TABLE_ENTRY)_peb->Ldr->Reserved2[1])->DllBase = res_img;

	VARIANT v;
	VARIANT v2;
	VariantInit(&v);
	VariantInit(&v2);
	hr = Method->Invoke_3(v2, p2, &v);
	VariantClear(&v);
	VariantClear(&v2);
	if (FAILED(hr))
		goto failed;

failed:
	if (pMeta)
		pMeta->Release();
	if (pRun)
		pRun->Release();
	if (pCor)
	{
		pCor->Stop();
		pCor->Release();
	}
	if (sa)
		SafeArrayDestroy(sa);
	if (params)
		SafeArrayDestroy(params);

	return (hr);
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
{
	HRSRC hRsrc = FindResource(GetModuleHandle(NULL), MAKEINTRESOURCE(0), RT_RCDATA);
	if (hRsrc)
	{
		HGLOBAL hGlob = LoadResource(GetModuleHandle(NULL), hRsrc);
		if (hGlob)
		{
			void *bytes = LockResource(hGlob);
			size_t size = SizeofResource(GetModuleHandle(NULL), hRsrc);
			if (bytes && size)
				load_assembly(bytes, size);
		}
		FreeResource(hGlob);
	}
	ExitProcess(0);
}
