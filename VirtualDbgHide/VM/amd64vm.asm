
EXTERN StartVirtualization:PROC
EXTERN HandleVmExit:PROC

VMCALL_MAGIC_VALUE = 05644626748696465h

.CODE

_StartVirtualization PROC
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

_StopVirtualization PROC
	mov rcx, VMCALL_MAGIC_VALUE
	mov eax, 0FFFFFFFFh
    vmcall
	int 3
_StopVirtualization ENDP    

_QueryVirtualization PROC
	mov rcx, VMCALL_MAGIC_VALUE
	mov eax, 0h
	vmcall
	ret
_QueryVirtualization ENDP

_GuestEntry PROC
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
_GuestEntry ENDP 

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

END