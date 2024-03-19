; Listing generated by Microsoft (R) Optimizing Compiler Version 19.39.33522.0 

include listing.inc

PUBLIC	?create_thread_name@@3PADA			; create_thread_name
PUBLIC	?get_exit_code_thread_name@@3PADA		; get_exit_code_thread_name
PUBLIC	?wait_for_single_object_name@@3PADA		; wait_for_single_object_name
PUBLIC	?message_box_name@@3PADA			; message_box_name
PUBLIC	?kernel32_dll_name@@3PA_WA			; kernel32_dll_name
PUBLIC	?load_lib_name@@3PADA				; load_lib_name
PUBLIC	?get_proc_name@@3PADA				; get_proc_name
PUBLIC	?user32_dll_name@@3PADA				; user32_dll_name
PUBLIC	?msg_content@@3PA_WA				; msg_content
PUBLIC	?msg_title@@3PA_WA				; msg_title
_TEXT	SEGMENT
?user32_dll_name@@3PADA DB 'user32.dll', 00H		; user32_dll_name
	ORG $+5
?message_box_name@@3PADA DB 'MessageBoxW', 00H		; message_box_name
	ORG $+4
?load_lib_name@@3PADA DB 'LoadLibraryA', 00H		; load_lib_name
	ORG $+3
?create_thread_name@@3PADA DB 'CreateThread', 00H	; create_thread_name
	ORG $+3
?get_proc_name@@3PADA DB 'GetProcAddress', 00H		; get_proc_name
	ORG $+1
?get_exit_code_thread_name@@3PADA DB 'GetExitCodeThread', 00H ; get_exit_code_thread_name
	ORG $+6
?wait_for_single_object_name@@3PADA DB 'WaitForSingleObject', 00H ; wait_for_single_object_name
	ORG $+4
?msg_content@@3PA_WA DB 'a', 00H, 't', 00H, 't', 00H, 'e', 00H, 'm', 00H, 'p'
	DB	00H, 't', 00H, ' ', 00H, '1', 00H, '?', 00H, 00H, 00H ; msg_content
	ORG $+2
?kernel32_dll_name@@3PA_WA DB 'k', 00H, 'e', 00H, 'r', 00H, 'n', 00H, 'e', 00H
	DB	'l', 00H, '3', 00H, '2', 00H, '.', 00H, 'd', 00H, 'l', 00H, 'l'
	DB	00H, 00H, 00H				; kernel32_dll_name
	ORG $+6
?msg_title@@3PA_WA DB 'd', 00H, 'e', 00H, 'm', 00H, 'o', 00H, 'n', 00H, 's'
	DB	00H, 't', 00H, 'r', 00H, 'a', 00H, 't', 00H, 'i', 00H, 'o', 00H
	DB	'n', 00H, 00H, 00H				; msg_title
_TEXT	ENDS
PUBLIC	?get_module_by_name@@YAPEAXPEA_W@Z		; get_module_by_name
PUBLIC	?get_func_by_name@@YAPEAXPEAXPEAD@Z		; get_func_by_name
PUBLIC	main

;	COMDAT voltbl
voltbl	SEGMENT
_volmd	DB	014H
voltbl	ENDS

; Function compile flags: /Odtp
_TEXT	SEGMENT

AlignRSP PROC
    push rsi ; Preserve RSI since we're stomping on it
    mov rsi, rsp ; Save the value of RSP so it can be restored
    and rsp, 0FFFFFFFFFFFFFFF0h ; Align RSP to 16 bytes
    sub rsp, 020h ; Allocate homing space for ExecutePayload
    call main ; Call the entry point of the payload
    mov rsp, rsi ; Restore the original value of RSP
    pop rsi ; Restore RSI
    ret ; Return to caller
AlignRSP ENDP

base$ = 48
exitRes$ = 56
exitCode$ = 60
load_lib$ = 64
get_proc$ = 72
create_thread$ = 80
wait_for_single_object$ = 88
get_exit_code_thread$ = 96
$MessageBoxW$ = 104
newThread$ = 112
$LoadLibraryA$ = 120
u32_dll$ = 128
$GetProcAddress$ = 136
$CreateThread$ = 144
$WaitForSingleObject$ = 152
$GetExitCodeThread$ = 160
main	PROC
; File D:\Programming\Projects\pe-file-implementation\payload\payload.cpp
; Line 30
$LN12:
	sub	rsp, 184				; 000000b8H
; Line 31
	lea	rcx, OFFSET FLAT:?kernel32_dll_name@@3PA_WA ; kernel32_dll_name
	call	?get_module_by_name@@YAPEAXPEA_W@Z	; get_module_by_name
	mov	QWORD PTR base$[rsp], rax
; Line 32
	cmp	QWORD PTR base$[rsp], 0
	jne	SHORT $LN2@main
; Line 33
	mov	eax, 1
	jmp	$LN1@main
$LN2@main:
; Line 37
	lea	rdx, OFFSET FLAT:?load_lib_name@@3PADA	; load_lib_name
	mov	rcx, QWORD PTR base$[rsp]
	call	?get_func_by_name@@YAPEAXPEAXPEAD@Z	; get_func_by_name
	mov	QWORD PTR load_lib$[rsp], rax
; Line 38
	cmp	QWORD PTR load_lib$[rsp], 0
	jne	SHORT $LN3@main
; Line 39
	mov	eax, 2
	jmp	$LN1@main
$LN3@main:
; Line 43
	lea	rdx, OFFSET FLAT:?get_proc_name@@3PADA	; get_proc_name
	mov	rcx, QWORD PTR base$[rsp]
	call	?get_func_by_name@@YAPEAXPEAXPEAD@Z	; get_func_by_name
	mov	QWORD PTR get_proc$[rsp], rax
; Line 44
	cmp	QWORD PTR get_proc$[rsp], 0
	jne	SHORT $LN4@main
; Line 45
	mov	eax, 3
	jmp	$LN1@main
$LN4@main:
; Line 49
	lea	rdx, OFFSET FLAT:?create_thread_name@@3PADA ; create_thread_name
	mov	rcx, QWORD PTR base$[rsp]
	call	?get_func_by_name@@YAPEAXPEAXPEAD@Z	; get_func_by_name
	mov	QWORD PTR create_thread$[rsp], rax
; Line 50
	cmp	QWORD PTR create_thread$[rsp], 0
	jne	SHORT $LN5@main
; Line 51
	mov	eax, 4
	jmp	$LN1@main
$LN5@main:
; Line 55
	lea	rdx, OFFSET FLAT:?wait_for_single_object_name@@3PADA ; wait_for_single_object_name
	mov	rcx, QWORD PTR base$[rsp]
	call	?get_func_by_name@@YAPEAXPEAXPEAD@Z	; get_func_by_name
	mov	QWORD PTR wait_for_single_object$[rsp], rax
; Line 56
	cmp	QWORD PTR wait_for_single_object$[rsp], 0
	jne	SHORT $LN6@main
; Line 57
	mov	eax, 5
	jmp	$LN1@main
$LN6@main:
; Line 61
	lea	rdx, OFFSET FLAT:?get_exit_code_thread_name@@3PADA ; get_exit_code_thread_name
	mov	rcx, QWORD PTR base$[rsp]
	call	?get_func_by_name@@YAPEAXPEAXPEAD@Z	; get_func_by_name
	mov	QWORD PTR get_exit_code_thread$[rsp], rax
; Line 62
	cmp	QWORD PTR get_exit_code_thread$[rsp], 0
	jne	SHORT $LN7@main
; Line 63
	mov	eax, 5
	jmp	$LN1@main
$LN7@main:
; Line 67
	mov	rax, QWORD PTR load_lib$[rsp]
	mov	QWORD PTR $LoadLibraryA$[rsp], rax
; Line 68
	mov	rax, QWORD PTR get_proc$[rsp]
	mov	QWORD PTR $GetProcAddress$[rsp], rax
; Line 69
	mov	rax, QWORD PTR create_thread$[rsp]
	mov	QWORD PTR $CreateThread$[rsp], rax
; Line 77
	mov	rax, QWORD PTR wait_for_single_object$[rsp]
	mov	QWORD PTR $WaitForSingleObject$[rsp], rax
; Line 81
	mov	rax, QWORD PTR get_exit_code_thread$[rsp]
	mov	QWORD PTR $GetExitCodeThread$[rsp], rax
; Line 87
	lea	rcx, OFFSET FLAT:?user32_dll_name@@3PADA ; user32_dll_name
	call	QWORD PTR $LoadLibraryA$[rsp]
	mov	QWORD PTR u32_dll$[rsp], rax
; Line 90
	lea	rdx, OFFSET FLAT:?message_box_name@@3PADA ; message_box_name
	mov	rcx, QWORD PTR u32_dll$[rsp]
	call	QWORD PTR $GetProcAddress$[rsp]
	mov	QWORD PTR $MessageBoxW$[rsp], rax
; Line 94
	cmp	QWORD PTR $MessageBoxW$[rsp], 0
	jne	SHORT $LN8@main
	mov	eax, 4
	jmp	SHORT $LN1@main
$LN8@main:
; Line 95
	xor	r9d, r9d
	lea	r8, OFFSET FLAT:?msg_title@@3PA_WA	; msg_title
	lea	rdx, OFFSET FLAT:?msg_content@@3PA_WA	; msg_content
	xor	ecx, ecx
	call	QWORD PTR $MessageBoxW$[rsp]
; Line 97
	mov	QWORD PTR [rsp+40], 0
	mov	DWORD PTR [rsp+32], 0
	xor	r9d, r9d
	mov	r8d, 122832				; 0001dfd0H
	xor	edx, edx
	xor	ecx, ecx
	call	QWORD PTR $CreateThread$[rsp]
	mov	QWORD PTR newThread$[rsp], rax
; Line 99
	mov	edx, -1					; ffffffffH
	mov	rcx, QWORD PTR newThread$[rsp]
	call	QWORD PTR $WaitForSingleObject$[rsp]
; Line 102
	lea	rdx, QWORD PTR exitCode$[rsp]
	mov	rcx, QWORD PTR newThread$[rsp]
	call	QWORD PTR $GetExitCodeThread$[rsp]
	mov	DWORD PTR exitRes$[rsp], eax
; Line 103
	cmp	DWORD PTR exitRes$[rsp], 0
	je	SHORT $LN9@main
; Line 104
	mov	eax, DWORD PTR exitCode$[rsp]
	jmp	SHORT $LN1@main
; Line 105
	jmp	SHORT $LN10@main
$LN9@main:
; Line 106
	mov	eax, 10
$LN10@main:
$LN1@main:
; Line 108
	add	rsp, 184				; 000000b8H
	ret	0
main	ENDP
_TEXT	ENDS
; Function compile flags: /Odtp
;	COMDAT ?get_func_by_name@@YAPEAXPEAXPEAD@Z
_TEXT	SEGMENT
k$1 = 0
i$2 = 8
exp$ = 16
expAddr$ = 24
funcNamesListRVA$ = 28
namesOrdsListRVA$ = 32
funcsListRVA$ = 36
curr_name$3 = 40
idh$ = 48
exportsDir$ = 56
nt_headers$ = 64
namesCount$ = 72
nameIndex$4 = 80
nameRVA$5 = 88
funcRVA$6 = 96
module$ = 128
func_name$ = 136
?get_func_by_name@@YAPEAXPEAXPEAD@Z PROC		; get_func_by_name, COMDAT
; File D:\Programming\Projects\pe-file-implementation\payload\peb-lookup.h
; Line 114
$LN13:
	mov	QWORD PTR [rsp+16], rdx
	mov	QWORD PTR [rsp+8], rcx
	sub	rsp, 120				; 00000078H
; Line 115
	mov	rax, QWORD PTR module$[rsp]
	mov	QWORD PTR idh$[rsp], rax
; Line 116
	mov	rax, QWORD PTR idh$[rsp]
	movzx	eax, WORD PTR [rax]
	cmp	eax, 23117				; 00005a4dH
	je	SHORT $LN8@get_func_b
; Line 117
	xor	eax, eax
	jmp	$LN1@get_func_b
$LN8@get_func_b:
; Line 119
	mov	rax, QWORD PTR idh$[rsp]
	movsxd	rax, DWORD PTR [rax+60]
	mov	rcx, QWORD PTR module$[rsp]
	add	rcx, rax
	mov	rax, rcx
	mov	QWORD PTR nt_headers$[rsp], rax
; Line 120
	mov	eax, 8
	imul	rax, rax, 0
	mov	rcx, QWORD PTR nt_headers$[rsp]
	lea	rax, QWORD PTR [rcx+rax+136]
	mov	QWORD PTR exportsDir$[rsp], rax
; Line 121
	mov	rax, QWORD PTR exportsDir$[rsp]
	cmp	DWORD PTR [rax], 0
	jne	SHORT $LN9@get_func_b
; Line 122
	xor	eax, eax
	jmp	$LN1@get_func_b
$LN9@get_func_b:
; Line 125
	mov	rax, QWORD PTR exportsDir$[rsp]
	mov	eax, DWORD PTR [rax]
	mov	DWORD PTR expAddr$[rsp], eax
; Line 126
	mov	eax, DWORD PTR expAddr$[rsp]
	add	rax, QWORD PTR module$[rsp]
	mov	QWORD PTR exp$[rsp], rax
; Line 127
	mov	rax, QWORD PTR exp$[rsp]
	mov	eax, DWORD PTR [rax+24]
	mov	QWORD PTR namesCount$[rsp], rax
; Line 129
	mov	rax, QWORD PTR exp$[rsp]
	mov	eax, DWORD PTR [rax+28]
	mov	DWORD PTR funcsListRVA$[rsp], eax
; Line 130
	mov	rax, QWORD PTR exp$[rsp]
	mov	eax, DWORD PTR [rax+32]
	mov	DWORD PTR funcNamesListRVA$[rsp], eax
; Line 131
	mov	rax, QWORD PTR exp$[rsp]
	mov	eax, DWORD PTR [rax+36]
	mov	DWORD PTR namesOrdsListRVA$[rsp], eax
; Line 134
	mov	QWORD PTR i$2[rsp], 0
	jmp	SHORT $LN4@get_func_b
$LN2@get_func_b:
	mov	rax, QWORD PTR i$2[rsp]
	inc	rax
	mov	QWORD PTR i$2[rsp], rax
$LN4@get_func_b:
	mov	rax, QWORD PTR namesCount$[rsp]
	cmp	QWORD PTR i$2[rsp], rax
	jae	$LN3@get_func_b
; Line 135
	mov	eax, DWORD PTR funcNamesListRVA$[rsp]
	mov	rcx, QWORD PTR module$[rsp]
	add	rcx, rax
	mov	rax, rcx
	mov	rcx, QWORD PTR i$2[rsp]
	lea	rax, QWORD PTR [rax+rcx*4]
	mov	QWORD PTR nameRVA$5[rsp], rax
; Line 136
	mov	eax, DWORD PTR namesOrdsListRVA$[rsp]
	mov	rcx, QWORD PTR module$[rsp]
	add	rcx, rax
	mov	rax, rcx
	mov	rcx, QWORD PTR i$2[rsp]
	lea	rax, QWORD PTR [rax+rcx*2]
	mov	QWORD PTR nameIndex$4[rsp], rax
; Line 137
	mov	eax, DWORD PTR funcsListRVA$[rsp]
	mov	rcx, QWORD PTR module$[rsp]
	add	rcx, rax
	mov	rax, rcx
	mov	rcx, QWORD PTR nameIndex$4[rsp]
	movzx	ecx, WORD PTR [rcx]
	lea	rax, QWORD PTR [rax+rcx*4]
	mov	QWORD PTR funcRVA$6[rsp], rax
; Line 139
	mov	rax, QWORD PTR nameRVA$5[rsp]
	mov	eax, DWORD PTR [rax]
	mov	rcx, QWORD PTR module$[rsp]
	add	rcx, rax
	mov	rax, rcx
	mov	QWORD PTR curr_name$3[rsp], rax
; Line 140
	mov	QWORD PTR k$1[rsp], 0
; Line 141
	mov	QWORD PTR k$1[rsp], 0
	jmp	SHORT $LN7@get_func_b
$LN5@get_func_b:
	mov	rax, QWORD PTR k$1[rsp]
	inc	rax
	mov	QWORD PTR k$1[rsp], rax
$LN7@get_func_b:
	mov	rax, QWORD PTR k$1[rsp]
	mov	rcx, QWORD PTR func_name$[rsp]
	add	rcx, rax
	mov	rax, rcx
	movsx	eax, BYTE PTR [rax]
	test	eax, eax
	je	SHORT $LN6@get_func_b
	mov	rax, QWORD PTR k$1[rsp]
	mov	rcx, QWORD PTR curr_name$3[rsp]
	add	rcx, rax
	mov	rax, rcx
	movsx	eax, BYTE PTR [rax]
	test	eax, eax
	je	SHORT $LN6@get_func_b
; Line 142
	mov	rax, QWORD PTR k$1[rsp]
	mov	rcx, QWORD PTR func_name$[rsp]
	add	rcx, rax
	mov	rax, rcx
	movsx	eax, BYTE PTR [rax]
	mov	rcx, QWORD PTR k$1[rsp]
	mov	rdx, QWORD PTR curr_name$3[rsp]
	add	rdx, rcx
	mov	rcx, rdx
	movsx	ecx, BYTE PTR [rcx]
	cmp	eax, ecx
	je	SHORT $LN10@get_func_b
	jmp	SHORT $LN6@get_func_b
$LN10@get_func_b:
; Line 143
	jmp	SHORT $LN5@get_func_b
$LN6@get_func_b:
; Line 144
	mov	rax, QWORD PTR k$1[rsp]
	mov	rcx, QWORD PTR func_name$[rsp]
	add	rcx, rax
	mov	rax, rcx
	movsx	eax, BYTE PTR [rax]
	test	eax, eax
	jne	SHORT $LN11@get_func_b
	mov	rax, QWORD PTR k$1[rsp]
	mov	rcx, QWORD PTR curr_name$3[rsp]
	add	rcx, rax
	mov	rax, rcx
	movsx	eax, BYTE PTR [rax]
	test	eax, eax
	jne	SHORT $LN11@get_func_b
; Line 146
	mov	rax, QWORD PTR funcRVA$6[rsp]
	mov	eax, DWORD PTR [rax]
	mov	rcx, QWORD PTR module$[rsp]
	add	rcx, rax
	mov	rax, rcx
	jmp	SHORT $LN1@get_func_b
$LN11@get_func_b:
; Line 148
	jmp	$LN2@get_func_b
$LN3@get_func_b:
; Line 149
	xor	eax, eax
$LN1@get_func_b:
; Line 150
	add	rsp, 120				; 00000078H
	ret	0
?get_func_by_name@@YAPEAXPEAXPEAD@Z ENDP		; get_func_by_name
_TEXT	ENDS
; Function compile flags: /Odtp
;	COMDAT ?get_module_by_name@@YAPEAXPEA_W@Z
_TEXT	SEGMENT
i$1 = 0
tv136 = 8
tv155 = 10
c1$2 = 12
c2$3 = 16
curr_name$4 = 24
curr_module$ = 32
tv132 = 40
tv151 = 44
peb$ = 48
ldr$ = 56
Flink$ = 64
list$ = 72
module_name$ = 128
?get_module_by_name@@YAPEAXPEA_W@Z PROC			; get_module_by_name, COMDAT
; File D:\Programming\Projects\pe-file-implementation\payload\peb-lookup.h
; Line 80
$LN16:
	mov	QWORD PTR [rsp+8], rcx
	push	rsi
	push	rdi
	sub	rsp, 104				; 00000068H
; Line 81
	mov	QWORD PTR peb$[rsp], 0
; Line 83
	mov	rax, QWORD PTR gs:[96]
	mov	QWORD PTR peb$[rsp], rax
; Line 87
	mov	rax, QWORD PTR peb$[rsp]
	mov	rax, QWORD PTR [rax+24]
	mov	QWORD PTR ldr$[rsp], rax
; Line 88
	lea	rax, QWORD PTR list$[rsp]
	mov	rcx, QWORD PTR ldr$[rsp]
	mov	rdi, rax
	lea	rsi, QWORD PTR [rcx+16]
	mov	ecx, 16
	rep movsb
; Line 90
	mov	rax, QWORD PTR list$[rsp]
	mov	QWORD PTR Flink$[rsp], rax
; Line 91
	mov	rax, QWORD PTR Flink$[rsp]
	mov	QWORD PTR curr_module$[rsp], rax
$LN15@get_module:
$LN2@get_module:
; Line 93
	cmp	QWORD PTR curr_module$[rsp], 0
	je	$LN3@get_module
	mov	rax, QWORD PTR curr_module$[rsp]
	cmp	QWORD PTR [rax+48], 0
	je	$LN3@get_module
; Line 94
	mov	rax, QWORD PTR curr_module$[rsp]
	cmp	QWORD PTR [rax+96], 0
	jne	SHORT $LN7@get_module
	jmp	SHORT $LN2@get_module
$LN7@get_module:
; Line 95
	mov	rax, QWORD PTR curr_module$[rsp]
	mov	rax, QWORD PTR [rax+96]
	mov	QWORD PTR curr_name$4[rsp], rax
; Line 97
	mov	QWORD PTR i$1[rsp], 0
; Line 98
	mov	QWORD PTR i$1[rsp], 0
	jmp	SHORT $LN6@get_module
$LN4@get_module:
	mov	rax, QWORD PTR i$1[rsp]
	inc	rax
	mov	QWORD PTR i$1[rsp], rax
$LN6@get_module:
	mov	rax, QWORD PTR module_name$[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	eax, WORD PTR [rax+rcx*2]
	test	eax, eax
	je	$LN5@get_module
	mov	rax, QWORD PTR curr_name$4[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	eax, WORD PTR [rax+rcx*2]
	test	eax, eax
	je	$LN5@get_module
; Line 100
	mov	rax, QWORD PTR module_name$[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	eax, WORD PTR [rax+rcx*2]
	cmp	eax, 90					; 0000005aH
	jg	SHORT $LN11@get_module
	mov	rax, QWORD PTR module_name$[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	eax, WORD PTR [rax+rcx*2]
	cmp	eax, 65					; 00000041H
	jl	SHORT $LN11@get_module
	mov	rax, QWORD PTR module_name$[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	eax, WORD PTR [rax+rcx*2]
	sub	eax, 65					; 00000041H
	add	eax, 97					; 00000061H
	mov	DWORD PTR tv132[rsp], eax
	mov	rax, QWORD PTR module_name$[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	edx, WORD PTR tv132[rsp]
	mov	WORD PTR [rax+rcx*2], dx
	movzx	eax, WORD PTR tv132[rsp]
	mov	WORD PTR tv136[rsp], ax
	jmp	SHORT $LN12@get_module
$LN11@get_module:
	mov	rax, QWORD PTR module_name$[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	eax, WORD PTR [rax+rcx*2]
	mov	WORD PTR tv136[rsp], ax
$LN12@get_module:
	movzx	eax, WORD PTR tv136[rsp]
	mov	WORD PTR c1$2[rsp], ax
; Line 101
	mov	rax, QWORD PTR curr_name$4[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	eax, WORD PTR [rax+rcx*2]
	cmp	eax, 90					; 0000005aH
	jg	SHORT $LN13@get_module
	mov	rax, QWORD PTR curr_name$4[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	eax, WORD PTR [rax+rcx*2]
	cmp	eax, 65					; 00000041H
	jl	SHORT $LN13@get_module
	mov	rax, QWORD PTR curr_name$4[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	eax, WORD PTR [rax+rcx*2]
	sub	eax, 65					; 00000041H
	add	eax, 97					; 00000061H
	mov	DWORD PTR tv151[rsp], eax
	mov	rax, QWORD PTR curr_name$4[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	edx, WORD PTR tv151[rsp]
	mov	WORD PTR [rax+rcx*2], dx
	movzx	eax, WORD PTR tv151[rsp]
	mov	WORD PTR tv155[rsp], ax
	jmp	SHORT $LN14@get_module
$LN13@get_module:
	mov	rax, QWORD PTR curr_name$4[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	eax, WORD PTR [rax+rcx*2]
	mov	WORD PTR tv155[rsp], ax
$LN14@get_module:
	movzx	eax, WORD PTR tv155[rsp]
	mov	WORD PTR c2$3[rsp], ax
; Line 102
	movzx	eax, WORD PTR c1$2[rsp]
	movzx	ecx, WORD PTR c2$3[rsp]
	cmp	eax, ecx
	je	SHORT $LN8@get_module
	jmp	SHORT $LN5@get_module
$LN8@get_module:
; Line 103
	jmp	$LN4@get_module
$LN5@get_module:
; Line 104
	mov	rax, QWORD PTR module_name$[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	eax, WORD PTR [rax+rcx*2]
	test	eax, eax
	jne	SHORT $LN9@get_module
	mov	rax, QWORD PTR curr_name$4[rsp]
	mov	rcx, QWORD PTR i$1[rsp]
	movzx	eax, WORD PTR [rax+rcx*2]
	test	eax, eax
	jne	SHORT $LN9@get_module
; Line 106
	mov	rax, QWORD PTR curr_module$[rsp]
	mov	rax, QWORD PTR [rax+48]
	jmp	SHORT $LN1@get_module
$LN9@get_module:
; Line 109
	mov	rax, QWORD PTR curr_module$[rsp]
	mov	rax, QWORD PTR [rax]
	mov	QWORD PTR curr_module$[rsp], rax
; Line 110
	jmp	$LN15@get_module
$LN3@get_module:
; Line 111
	xor	eax, eax
$LN1@get_module:
; Line 112
	add	rsp, 104				; 00000068H
	pop	rdi
	pop	rsi
	ret	0
?get_module_by_name@@YAPEAXPEA_W@Z ENDP			; get_module_by_name
_TEXT	ENDS
END
