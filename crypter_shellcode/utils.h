#pragma once
#include <Windows.h>
#include <winternl.h>
#include "main.h"
#include "syscall.h"

typedef struct	_LDR_MODULE {



	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
	PVOID                   BaseAddress;
	PVOID                   EntryPoint;
	ULONG                   SizeOfImage;
	UNICODE_STRING          FullDllName;
	UNICODE_STRING          BaseDllName;
	ULONG                   Flags;
	SHORT                   LoadCount;
	SHORT                   TlsIndex;
	LIST_ENTRY              HashTableEntry;
	ULONG                   TimeDateStamp;

} LDR_MODULE, *PLDR_MODULE;

typedef struct	_peb_ldr_data {

	ULONG                   Length;
	BOOLEAN                 Initialized;
	PVOID                   SsHandle;
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;

} peb_ldr_data, *ppeb_ldr_data;

unsigned long	_strlen(char *str);
int				_wstricmp(wchar_t *s1, wchar_t *s2);
LPVOID			get_module_handle(LPWSTR wModule);
LPVOID			get_module_path(LPWSTR wModule);
LPVOID			get_proc_address(BYTE* pDLL, DWORD dwAPI);
unsigned int	crc32(unsigned char *message);
void  __stdcall _memset(void* dst, unsigned char ucByte, DWORD dwSize);
void* __stdcall _memcpy(void *szBuf, const void *szStr, int nLen);
BOOL			IsCurrentProcessWow64(APIs);