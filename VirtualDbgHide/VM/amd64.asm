
.CODE

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

__writecr2 PROC
    mov cr2, rcx
    ret
__writecr2 ENDP

__invd PROC
    invd
    ret
__invd ENDP

END