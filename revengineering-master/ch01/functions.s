%macro PROLOGUE 0
        push ebp
        mov ebp, esp
%endmacro

%macro EPILOGUE 0
        leave
        ret
%endmacro

%macro ALLOCATE 1
        sub esp, %1
%endmacro
%macro DEALLOCATE 1
        add esp, %1
%endmacro

        section .text
        global _strlen,_strchr,_memcpy,_memset,_strcmp,_strset

        ;; size_t strlen(const char *s)
_strlen:
        PROLOGUE
        push ecx
        push edi
        xor ecx, ecx
        mov edi, [ebp+8]
        mov al, 0x0 
__start_strlen_loop:
        scasb
        jz __end_strlen_loop
        inc ecx
        jmp __start_strlen_loop
__end_strlen_loop:
        mov eax, ecx
        pop edi
        pop ecx
        EPILOGUE
        
        ;; char *strchr(const char *s, int c)
_strchr:
        PROLOGUE
        push edi
	push ebx
        mov eax, [ebp+12]
        mov edi, [ebp+8]
__start_strchr_loop:
        scasb
        jz __end_strchr_loop
	mov bl,[edi]
	test bl,bl
	jz __ret_null
        jmp __start_strchr_loop
__ret_null:
	mov eax, 0x0
	jmp __end_strchr
__end_strchr_loop:
        lea eax, [edi-0x1]
__end_strchr:	
	pop ebx
        pop edi
        EPILOGUE

        ;; void *memcpy(void *dest, const void *src, size_t n)
_memcpy:
        PROLOGUE
        push edi
        push esi
        push ecx
        mov ecx, [ebp+16]
        mov esi, [ebp+12]
        mov edi, [ebp+8]
__start_memcpy_loop:
        lodsb
        stosb
        loop __start_memcpy_loop
__end_memcpy_loop:
        lea eax, [ebp+8]
        pop ecx
        pop esi
        pop edi
        EPILOGUE

        ;; void *memset(void *s, int c, size_t n)
_memset:
        PROLOGUE
        push ecx
        push edi
        xor ecx, ecx
        mov edi, [ebp+8]
        mov eax, [ebp+12]
        mov ecx, [ebp+16]
__start_memset_loop:
        stosb
        loop __start_memset_loop
__end_memset_loop:
        lea eax, [ebp+8]
        pop edi
        pop ecx
        EPILOGUE
        
        ;; int strcmp(const char *s1, const char *s2)
_strcmp:
        PROLOGUE
        push ebx
        push edx
        push edi
        push esi
        push ecx
        xor ecx, ecx
        mov esi, [ebp+8]
        mov edi, [ebp+12]
        push esi
        call _strlen
        mov ebx, eax
        DEALLOCATE 0x4
        push edi
        call _strlen
        mov edx, eax
        DEALLOCATE 0x4
        cmp ebx, edx
        jg __bigger_than
        jl __lower_than
        mov ecx, ebx
        xor eax, eax
__start_strcmp_loop:
        mov ebx, [esi+ecx]
        mov edx, [edi+ecx]
        cmp bl, dl
        jl __lower_than
        jg __bigger_than
        cmp ecx, 0x0
        je __end
        dec ecx
        jmp __start_strcmp_loop
__bigger_than:
        mov eax, 0x1
        jmp __end
__lower_than:
        mov eax, 0xFFFFFFFF
        jmp __end
__end:  
        pop ecx
        pop esi
        pop edi
        pop edx
        pop ebx
        EPILOGUE

        ;; char *strset(const char *str, char c)
_strset:
        PROLOGUE
        push edi
        push ecx
        xor ecx, ecx
        mov edi, [ebp+8]
        push edi
        call _strlen
        mov ecx, eax
        DEALLOCATE 0x4
        mov eax, [ebp+12]
__start_strset_loop:
        stosb
        loop __start_strset_loop
        pop ecx
        pop edi
        EPILOGUE
        
