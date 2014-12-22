01:    ; BOOL __stdcall DllMain(HINSTANCE hinstDLL, DWORD fdwReason,
       ; LPVOID lpvReserved)
02:                _DllMain@12 proc near
03: 55               push    ebp
04: 8B EC            mov     ebp, esp
05: 81 EC 30 01 00+  sub     esp, 130h
06: 57               push    edi
07: 0F 01 4D F8      sidt    fword ptr [ebp-8]
08: 8B 45 FA         mov     eax, [ebp-6]
09: 3D 00 F4 03 80   cmp     eax, 8003F400h
10: 76 10            jbe     short loc_10001C88 (line 18)
11: 3D 00 74 04 80   cmp     eax, 80047400h
12: 73 09            jnb     short loc_10001C88 (line 18)
13: 33 C0            xor     eax, eax
14: 5F               pop     edi
15: 8B E5            mov     esp, ebp
16: 5D               pop     ebp
17: C2 0C 00         retn    0Ch
18:                loc_10001C88:
19: 33 C0            xor     eax, eax
20: B9 49 00 00 00   mov     ecx, 49h
21: 8D BD D4 FE FF+  lea     edi, [ebp-12Ch]
22: C7 85 D0 FE FF+  mov     dword ptr [ebp-130h], 0
23: 50               push    eax
24: 6A 02            push    2
25: F3 AB            rep stosd
26: E8 2D 2F 00 00   call    CreateToolhelp32Snapshot
27: 8B F8            mov     edi, eax
28: 83 FF FF         cmp     edi, 0FFFFFFFFh
29: 75 09            jnz     short loc_10001CB9 (line 35)
30: 33 C0            xor     eax, eax
31: 5F               pop     edi
32: 8B E5            mov     esp, ebp
33: 5D               pop     ebp
34: C2 0C 00         retn    0Ch
35:                loc_10001CB9:
36: 8D 85 D0 FE FF+  lea     eax, [ebp-130h]
37: 56               push    esi
38: 50               push    eax
39: 57               push    edi
40: C7 85 D0 FE FF+  mov     dword ptr [ebp-130h], 128h
41: E8 FF 2E 00 00   call    Process32First
42: 85 C0            test    eax, eax
43: 74 4F            jz      short loc_10001D24 (line 70)
44: 8B 35 C0 50 00+  mov     esi, ds:_stricmp
45: 8D 8D F4 FE FF+  lea     ecx, [ebp-10Ch]
46: 68 50 7C 00 10   push    10007C50h
47: 51               push    ecx
48: FF D6            call    esi ; _stricmp
49: 83 C4 08         add     esp, 8
50: 85 C0            test    eax, eax
51: 74 26            jz      short loc_10001D16 (line 66)
52:                loc_10001CF0:
53: 8D 95 D0 FE FF+  lea     edx, [ebp-130h]
54: 52               push    edx
55: 57               push    edi
56: E8 CD 2E 00 00   call    Process32Next
57: 85 C0            test    eax, eax
58: 74 23            jz      short loc_10001D24 (line 70)
59: 8D 85 F4 FE FF+  lea     eax, [ebp-10Ch]
60: 68 50 7C 00 10   push    10007C50h
61: 50               push    eax
62: FF D6            call    esi ; _stricmp
63: 83 C4 08         add     esp, 8
64: 85 C0            test    eax, eax
65: 75 DA            jnz     short loc_10001CF0 (line 52)
66:                loc_10001D16:
67: 8B 85 E8 FE FF+  mov     eax, [ebp-118h]
68: 8B 8D D8 FE FF+  mov     ecx, [ebp-128h]
69: EB 06            jmp     short loc_10001D2A (line 73)
70:                loc_10001D24:
71: 8B 45 0C         mov     eax, [ebp+0Ch]
72: 8B 4D 0C         mov     ecx, [ebp+0Ch]
73:                loc_10001D2A:
74: 3B C1            cmp     eax, ecx
75: 5E               pop     esi
76: 75 09            jnz     short loc_10001D38 (line 82)
77: 33 C0            xor     eax, eax
78: 5F               pop     edi
79: 8B E5            mov     esp, ebp
80: 5D               pop     ebp
81: C2 0C 00         retn    0Ch
82:                loc_10001D38:
83: 8B 45 0C         mov     eax, [ebp+0Ch]
84: 48               dec     eax
85: 75 15            jnz     short loc_10001D53 (line 93)
86: 6A 00            push    0
87: 6A 00            push    0
88: 6A 00            push    0
89: 68 D0 32 00 10   push    100032D0h
90: 6A 00            push    0
91: 6A 00            push    0
92: FF 15 20 50 00+  call    ds:CreateThread
93:                loc_10001D53:
94: B8 01 00 00 00   mov     eax, 1
95: 5F               pop     edi
96: 8B E5            mov     esp, ebp
97: 5D               pop     ebp
98: C2 0C 00         retn    0Ch
99:                _DllMain@12 endp
