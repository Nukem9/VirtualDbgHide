
EXTERN StartVirtualization:PROC
EXTERN HandleVmExit:PROC

.CODE

_VmxOff PROC
    vmxoff
    mov rsp, rdx
    push rcx
    ret
_VmxOff ENDP

_TSC PROC
;	rdtscp
	rdtsc
	shl		rdx, 32
	or		rax, rdx
	ret
_TSC ENDP

_Rax PROC
	mov		rax, rax
	ret
_Rax ENDP

_Rbx PROC
	mov		rax, rbx
	ret
_Rbx ENDP

_Cs PROC
	mov		rax, cs
	ret
_Cs ENDP

_Ds PROC
	mov		rax, ds
	ret
_Ds ENDP

_Es PROC
	mov		rax, es
	ret
_Es ENDP

_Ss PROC
	mov		rax, ss
	ret
_Ss ENDP

_Fs PROC
	mov		rax, fs
	ret
_Fs ENDP

_Gs PROC
	mov		rax, gs
	ret
_Gs ENDP

_Cr2 PROC
	mov		rax, cr2
	ret
_Cr2 ENDP

_SetCr2 PROC
    mov cr2, rcx
    ret
_SetCr2 ENDP

_Rflags PROC
	pushfq
	pop		rax
	ret
_Rflags ENDP

_Rsp PROC
	mov		rax, rsp
	add		rax, 8
	ret
_Rsp ENDP

_IdtBase PROC
	LOCAL	idtr[10]:BYTE
	
	sidt	idtr
	mov		rax, QWORD PTR idtr[2]
	ret
_IdtBase ENDP

_IdtLimit PROC
	LOCAL	idtr[10]:BYTE
	
	sidt	idtr
	mov		ax, WORD PTR idtr[0]
	ret
_IdtLimit ENDP

_GdtBase PROC
	LOCAL	gdtr[10]:BYTE

	sgdt	gdtr
	mov		rax, QWORD PTR gdtr[2]
	ret
_GdtBase ENDP

_GdtLimit PROC
	LOCAL	gdtr[10]:BYTE

	sgdt	gdtr
	mov		ax, WORD PTR gdtr[0]
	ret
_GdtLimit ENDP

_Ldtr PROC
	sldt	rax
	ret
_Ldtr ENDP

_TrSelector PROC
	str	rax
	ret
_TrSelector ENDP

_VmFailInvalid PROC
    pushfq
    pop rax
    xor rcx, rcx
    bt eax, 0 ; RFLAGS.CF
    adc cl, cl
    mov rax, rcx
    ret
_VmFailInvalid ENDP

_VmFailValid PROC
    pushfq
    pop rax
    xor rcx, rcx
    bt eax, 6 ; RFLAGS.ZF
    adc cl, cl
    mov rax, rcx
    ret
_VmFailValid ENDP    

_StartVirtualization PROC
    ;int 3
	push	rax
	push	rcx
	push	rdx
	push	rbx
	push	rbp
	push	rsi
	push	rdi
	push	r8
	push	r9
	push	r10
	push	r11
	push	r12
	push	r13
	push	r14
	push	r15

	sub	rsp, 28h

	mov	rcx, rsp
	call StartVirtualization
_StartVirtualization ENDP

_GuestEntryPoint PROC

	;call ResumeGuest

	add	rsp, 28h

	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	r11
	pop	r10
	pop	r9
	pop	r8
	pop	rdi
	pop	rsi
	pop	rbp
	pop	rbx
	pop	rdx
	pop	rcx
	pop	rax
	ret

_GuestEntryPoint ENDP 

_StopVirtualization PROC
    push rax
    push rbx
    xor rax, rax
    xor rbx, rbx
    mov eax, 42424242h
    mov ebx, 43434343h
    vmcall
_StopVirtualization ENDP    

_GuestExit PROC
    pop rbx
    pop rax
    ret
_GuestExit ENDP

_ExitHandler PROC

	sub rsp, 100h
	mov [rsp + 0h],  rax
	mov [rsp + 8h],  rcx
	mov [rsp + 10h], rdx
	mov [rsp + 18h], rbx
	mov [rsp + 20h], rbp ; RSP
	mov [rsp + 28h], rbp
	mov [rsp + 30h], rsi
	mov [rsp + 38h], rdi
	mov [rsp + 40h], r8
	mov [rsp + 48h], r9
	mov [rsp + 50h], r10
	mov [rsp + 58h], r11
	mov [rsp + 60h], r12
	mov [rsp + 68h], r13
	mov [rsp + 70h], r14
	mov [rsp + 78h], r15
	movups [rsp + 80h], xmm0
	movups [rsp + 90h], xmm1

	mov rcx, [rsp + 100h] ; PCPU
	mov rdx, rsp		  ; GuestRegs

	sub	rsp, 28h
	call HandleVmExit
	add	rsp, 28h

	mov rax, [rsp + 0h]
	mov rcx, [rsp + 8h]
	mov rdx, [rsp + 10h]
	mov rbx, [rsp + 18h]
	mov rbp, [rsp + 20h] ; RSP
	mov rbp, [rsp + 28h]
	mov rsi, [rsp + 30h]
	mov rdi, [rsp + 38h]
	mov r8,  [rsp + 40h]
	mov r9,  [rsp + 48h]
	mov r10, [rsp + 50h]
	mov r11, [rsp + 58h]
	mov r12, [rsp + 60h]
	mov r13, [rsp + 68h]
	mov r14, [rsp + 70h]
	mov r15, [rsp + 78h]
	movups xmm0, [rsp + 80h]
	movups xmm1, [rsp + 90h]
	add rsp, 100h

	vmresume
	ret

_ExitHandler ENDP

_Invd PROC
    invd
    ret
_Invd ENDP

_InvalidatePage PROC
    invlpg [rcx]
    ret
_InvalidatePage ENDP

END