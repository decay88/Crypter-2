#include "utils.h"

unsigned int crc32(unsigned char *message) {
	int i, crc;
	unsigned int byte, c;
	const unsigned int g0 = 0xEDB88320, g1 = g0 >> 1,
		g2 = g0 >> 2, g3 = g0 >> 3, g4 = g0 >> 4, g5 = g0 >> 5,
		g6 = (g0 >> 6) ^ g0, g7 = ((g0 >> 6) ^ g0) >> 1;

	i = 0;
	crc = 0xFFFFFFFF;
	while ((byte = message[i]) != 0) {    // Get next byte.
		crc = crc ^ byte;
		c = ((crc << 31 >> 31) & g7) ^ ((crc << 30 >> 31) & g6) ^
			((crc << 29 >> 31) & g5) ^ ((crc << 28 >> 31) & g4) ^
			((crc << 27 >> 31) & g3) ^ ((crc << 26 >> 31) & g2) ^
			((crc << 25 >> 31) & g1) ^ ((crc << 24 >> 31) & g0);
		crc = ((unsigned)crc >> 8) ^ c;
		i = i + 1;
	}
	return ~crc;
}

LPVOID			get_proc_address(BYTE* pDLL, DWORD dwAPI)
{
	IMAGE_DOS_HEADER* pIDH = (IMAGE_DOS_HEADER*)pDLL;
	IMAGE_NT_HEADERS* pINH = (IMAGE_NT_HEADERS*)((BYTE*)pDLL + pIDH->e_lfanew);
	IMAGE_EXPORT_DIRECTORY* pIED = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)pDLL + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	DWORD* dwNames = (DWORD*)((BYTE*)pDLL + pIED->AddressOfNames);
	DWORD* dwFunctions = (DWORD*)((BYTE*)pDLL + pIED->AddressOfFunctions);
	WORD* wNameOrdinals = (WORD*)((BYTE*)pDLL + pIED->AddressOfNameOrdinals);
	char* pzName;
	DWORD i;

	for (i = 0; i < pIED->NumberOfNames; i++)
	{
		pzName = (char*)((BYTE*)pDLL + dwNames[i]);
		if (crc32(pzName) == dwAPI)
		{
			return ((BYTE*)pDLL + dwFunctions[wNameOrdinals[i]]);
		}
	}

	return 0;
}

LPVOID			get_module_handle(LPWSTR wModule)
{
	PPEB PEB_ptr = (PPEB)__readfsdword(0x30);
	ppeb_ldr_data LDR_ptr = (ppeb_ldr_data)PEB_ptr->Ldr;
	DWORD_PTR Flink_1st = (DWORD_PTR)LDR_ptr->InLoadOrderModuleList.Flink;
	PLDR_MODULE LDR_MOD_ptr = (PLDR_MODULE)LDR_ptr->InLoadOrderModuleList.Flink;

	do
		if (_wstricmp(LDR_MOD_ptr->BaseDllName.Buffer, wModule) == 0)
			return LDR_MOD_ptr->BaseAddress;
	while ((DWORD_PTR)(LDR_MOD_ptr = (PLDR_MODULE)LDR_MOD_ptr->InLoadOrderModuleList.Flink) != Flink_1st);
	return NULL;
}

LPVOID			get_module_path(LPWSTR wModule)
{
	PPEB PEB_ptr = (PPEB)__readfsdword(0x30);
	ppeb_ldr_data LDR_ptr = (ppeb_ldr_data)PEB_ptr->Ldr;
	DWORD_PTR Flink_1st = (DWORD_PTR)LDR_ptr->InLoadOrderModuleList.Flink;
	PLDR_MODULE LDR_MOD_ptr = (PLDR_MODULE)LDR_ptr->InLoadOrderModuleList.Flink;

	do
		if (_wstricmp(LDR_MOD_ptr->BaseDllName.Buffer, wModule) == 0)
			return LDR_MOD_ptr->FullDllName.Buffer;
	while ((DWORD_PTR)(LDR_MOD_ptr = (PLDR_MODULE)LDR_MOD_ptr->InLoadOrderModuleList.Flink) != Flink_1st);
	return NULL;
}

unsigned long	_wstrlen(wchar_t *str)
{
	unsigned long	i;
	for (i = 0; *str; i++, str++);
	return (i);
}

int _wstricmp(wchar_t *s1, wchar_t *s2)
{
	WCHAR w1;
	WCHAR w2;
	unsigned long i;

	if (_wstrlen(s1) != _wstrlen(s2))
		return (1);
	for (i = 0; i < _wstrlen(s1); i++, s1++, s2++)
	{
		w1 = *s1;
		w2 = *s2;
		if (w1 >= 'A' && w1 <= 'Z')
			w1 += 'a' - 'A';
		if (w2 >= 'A' && w2 <= 'Z')
			w2 += 'a' - 'A';
		if (w1 != w2)
			return (1);
	}
	return (0);
}

unsigned long	_strlen(char *str)
{
	unsigned long	i;
	for (i = 0; *str; i++, str++);
	return (i);
}

__declspec (naked) void  __stdcall _memset(void* dst, unsigned char ucByte, DWORD dwSize)
{
	__asm
	{
		mov edx, dword ptr[esp + 4]
		mov eax, dword ptr[esp + 8]
		mov ebx, dword ptr[esp + 12]
		Begin:
		mov byte ptr[edx], AL
			inc edx
			dec ebx
			jnz Begin
			ret 8
	}
}

__declspec(naked)  void* __stdcall _memcpy(void *szBuf, const void *szStr, int nLen)
{
	__asm
	{
		push esi
		push edi
		push ecx
		mov esi, dword ptr[esp + 20]
		mov edi, dword ptr[esp + 16]
		mov ecx, dword ptr[esp + 24]
		rep movsb
		pop ecx
		pop edi
		pop esi
		ret 12
	}
}

BOOL			IsCurrentProcessWow64(APIs a)
{
	BOOL		IsWow64;

	if (a.IsWow64Process)
		return (a.IsWow64Process(INVALID_HANDLE_VALUE, &IsWow64) ? IsWow64 : 0);
	return (0);
}