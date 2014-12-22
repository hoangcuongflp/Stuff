typedef struct _KDPC
{
  UCHAR Type;
  WORD Number;
  UCHAR Importance;
  LIST_ENTRY DpcListEntry;
  PVOID DeferredRoutine;
  PVOID DeferredContext;
  PVOID SystemArgument1;
  PVOID SystemArgument2;
  PVOID Lock
} KDPC, *PKDPC;

/*
  kd> dt nt!_KDPC
   +0x000 Type             : Int2B
   +0x002 Number           : UChar
   +0x003 Importance       : UChar
   +0x004 DpcListEntry     : _LIST_ENTRY
   +0x00c DeferredRoutine  : Ptr32     void
   +0x010 DeferredContext  : Ptr32 Void
   +0x014 SystemArgument1  : Ptr32 Void
   +0x018 SystemArgument2  : Ptr32 Void
   +0x01c Lock             : Ptr32 Uint4B
 */

/*
  ASSEMBLY KeInitializeDpc
  .text:0040E982                 mov     edi, edi
  .text:0040E984                 push    ebp
  .text:0040E985                 mov     ebp, esp
  .text:0040E987                 mov     eax, [ebp+Dpc]
  .text:0040E98A                 mov     ecx, [ebp+DeferredRoutine]
  .text:0040E98D                 and     dword ptr [eax+1Ch], 0
  .text:0040E991                 mov     [eax+0Ch], ecx
  .text:0040E994                 mov     ecx, [ebp+DeferredContext]
  .text:0040E997                 mov     word ptr [eax], 13h
  .text:0040E99C                 mov     byte ptr [eax+2], 0
  .text:0040E9A0                 mov     byte ptr [eax+3], 1
  .text:0040E9A4                 mov     [eax+10h], ecx
  .text:0040E9A7                 pop     ebp
  .text:0040E9A8                 retn    0Ch

*/

/* WinXP SP3 */

VOID KeInitializeDpc(
		     _Out_ PRKDPC Dpc,
		     _In_ PKDEFERRED_ROUTINE DeferredRoutine,
		     _In_opt_ PVOID DeferredContext
		     )
{

  Dpc->Lock = NULL;
  Dpc->DeferredRoutine = DeferredRoutine
   
  Dpc->Type = 0x13;
  Dpc->Number = 0x0;
  Dpc->Importance = 0x1;
  Dpc->DeferredContext = DeferredContext;
  
}


/*
  lkd> dt nt!_KAPC
   +0x000 Type             : Int2B
   +0x002 Size             : Int2B
   +0x004 Spare0           : Uint4B
   +0x008 Thread           : Ptr32 _KTHREAD
   +0x00c ApcListEntry     : _LIST_ENTRY
   +0x014 KernelRoutine    : Ptr32     void
   +0x018 RundownRoutine   : Ptr32     void
   +0x01c NormalRoutine    : Ptr32     void
   +0x020 NormalContext    : Ptr32 Void
   +0x024 SystemArgument1  : Ptr32 Void
   +0x028 SystemArgument2  : Ptr32 Void
   +0x02c ApcStateIndex    : Char
   +0x02d ApcMode          : Char
   +0x02e Inserted         : UChar
*/

typedef struct _KAPC
{
  UCHAR Type;
  UCHAR Size;
  UCHAR SizeByte0;
  PKTHREAD Thread;
  LIST_ENTRY ApcListEntry;
  PVOID KernelRoutine;
  PVOID RoundownRoutine;
  PVOID NormalRoutine;
  PVOID NormalContext;
  PVOID SystemArgument1;
  PVOID SystemArgument2;
  CHAR ApcStateIndex;
  CHAR ApcMode;
  UCHAR Inserted;
} KAPC, *PRKAPC;

/*
  ASSEMBLY KeInitializeApc
  .text:0040E1F7                 mov     edi, edi
  .text:0040E1F9                 push    ebp
  .text:0040E1FA                 mov     ebp, esp
  .text:0040E1FC                 mov     eax, [ebp+arg_0]
  .text:0040E1FF                 mov     edx, [ebp+arg_8]
  .text:0040E202                 cmp     edx, 2
  .text:0040E205                 mov     ecx, [ebp+arg_4]
  .text:0040E208                 mov     word ptr [eax], 12h
  .text:0040E20D                 mov     word ptr [eax+2], 30h
  .text:0040E213                 jz      loc_40DDB4
  .text:0040E219
  .text:0040E219 loc_40E219:
  .text:0040E219                 mov     [eax+8], ecx
  .text:0040E21C                 mov     ecx, [ebp+arg_C]
  .text:0040E21F                 mov     [eax+14h], ecx
  .text:0040E222                 mov     ecx, [ebp+arg_10]
  .text:0040E225                 mov     [eax+2Ch], dl
  .text:0040E228                 mov     [eax+18h], ecx
  .text:0040E22B                 mov     ecx, [ebp+arg_14]
  .text:0040E22E                 xor     edx, edx
  .text:0040E230                 cmp     ecx, edx
  .text:0040E232                 mov     [eax+1Ch], ecx
  .text:0040E235                 jnz     loc_40E3D5
  .text:0040E23B                 mov     [eax+2Dh], dl
  .text:0040E23E                 mov     [eax+20h], edx
  .text:0040E241
  .text:0040E241 loc_40E241:
  .text:0040E241                 mov     [eax+2Eh], dl
  .text:0040E244                 pop     ebp
  .text:0040E245                 retn    20h
 */

/* WinXP SP3 */

VOID
KeInitializeApc (
    __out PRKAPC Apc,
    __in PRKTHREAD Thread,
    __in KAPC_ENVIRONMENT Environment,
    __in PKKERNEL_ROUTINE KernelRoutine,
    __in_opt PKRUNDOWN_ROUTINE RundownRoutine,
    __in_opt PKNORMAL_ROUTINE NormalRoutine,
    __in_opt KPROCESSOR_MODE ApcMode,
    __in_opt PVOID NormalContext
		 ) {
   
  Apc->Size = 0x30;
  Apc->Type = 0x12;
  
  if (Environment == CurrentApcEnvironment) {
    Apc->ApcStateIndex = Thread->ApcStateIndex;
  } else {
    Apc->ApcStateIndex = Environment;
  }

  Apc->Thread = Thread;
  Apc->KernelRoutine = KernelRoutine;
  Apc->RundownRoutine = RundownRoutine;
  Apc->NormalRoutine = NormalRoutine; 
  
  if (NormalRoutine == NULL) {
    Apc->ApcMode = NULL;
    Apc->NormalContext = NULL;
  } else {
    Apc->Inserted = NULL;
  }

}
/* ObjFastDereferenceObject:

  PAGE:00494E6D                 mov     edi, edi
  PAGE:00494E6F                 push    ebp
  PAGE:00494E70                 mov     ebp, esp
  PAGE:00494E72                 sub     esp, 0Ch
  PAGE:00494E75                 push    ebx
  PAGE:00494E76                 push    esi
  PAGE:00494E77                 push    edi
  PAGE:00494E78                 mov     edi, ecx        ; save FastRef into edi
  PAGE:00494E7A                 mov     ebx, edx        ; save Object into ebx
  PAGE:00494E7C                 mov     [ebp+local_var2], edi ; save edi (FastRef pointer) into the 2nd stack var
  PAGE:00494E7F
  PAGE:00494E7F loc_494E7F:                             
  PAGE:00494E7F                 mov     esi, [edi]      ; take the first word of FastRef (Object/Kref) and put it into esi
  PAGE:00494E81                 mov     eax, esi        ; save previously saved Fastref (Object/Kref) word into eax
  PAGE:00494E83                 xor     eax, ebx        ; xor previously saved FastRef (Object/Kref) with Object
  PAGE:00494E85                 cmp     eax, 7          ; compare the xoring with 7
  PAGE:00494E88                 mov     [ebp+local_var3], esi ; save Fastref (Object/Kref) into local_var3
  PAGE:00494E8B                 jnb     short loc_494EA8 ; if kref >= 7 or if Fastref->Object != Object
  PAGE:00494E8B                                         ; jump to loc_494EA8
  PAGE:00494E8D                 lea     eax, [esi+1]    ; Fasteref->Kref++ goes in eax
  PAGE:00494E90                 mov     [ebp+local_var1], eax ; save eax (Fastref->Kref+1) into local_var1
  PAGE:00494E93                 mov     eax, [ebp+local_var3] ; save local_var3 (Fastref->Kref) into eax
  PAGE:00494E96                 mov     ecx, [ebp+local_var2] ; save local_var2 (FastRef PTR) into ecx
  PAGE:00494E99                 mov     edx, [ebp+local_var1] ; save local_var1 (Fastref->Kfref+1 into) edx
  PAGE:00494E9C                 cmpxchg [ecx], edx      ; if Fastref->Kref == eax move edx in [ecx] else move edx in eax
  PAGE:00494E9F                 cmp     eax, esi        ; check if eax was changed by the previous instruction
  PAGE:00494EA1                 jnz     short loc_494E7F ; if the cmpxchg operation does not succedeed jump to loc_49E7F 
  PAGE:00494EA3                                          ; else exit
  PAGE:00494EA3 loc_494EA3:
  PAGE:00494EA3                 pop     edi
  PAGE:00494EA4                 pop     esi
  PAGE:00494EA5                 pop     ebx
  PAGE:00494EA6                 leave
  PAGE:00494EA7                 retn
  PAGE:00494EA8 ; ---------------------------------------------------------------------------
  PAGE:00494EA8
  PAGE:00494EA8 loc_494EA8:
  PAGE:00494EA8                 mov     ecx, ebx
  PAGE:00494EAA                 call    @ObfDereferenceObject@4 ; ObfDereferenceObject(x)
  PAGE:00494EAF                 jmp     short loc_494EA3
  PAGE:00494EAF @ObFastDereferenceObject@8 endp

*/

typedef struct _EX_FAST_REF {
  union {
    PVOID Object;
    ULONG_PTR RefCnt : 3;
    ULONG_PTR Value;
  }
} EX_FAST_REF, *PEX_FAST_REF;

/* WinXP SP3 */

VOID
FASTCALL
ObjFastDereferenceObject(
			 IN PEX_FAST_REF FastRef,
			 IN PVOID Object)
{

  /*
	Thanks to the union and address alignment, this condition will test
	both FastRef->Object != Object and FastRef->RefCnt > 7
  */
  while ((FastRef->Value ^ Object) < 7) {
	  /* ATOMIC returns true if the increment of RefCnt (see lines around cmpxchg above) succedes */
	  if (ATOMIC (FastRef->RefCnt++))
		return;
  }

  /* If fastDereference fails */
  ObjDereferenceObject(object);
  return;
}

/*
  .text:00429C2A ; Attributes: bp-based frame
  .text:00429C2A
  .text:00429C2A                 public KeInitializeQueue
  .text:00429C2A KeInitializeQueue proc near
  .text:00429C2A
  .text:00429C2A
  .text:00429C2A arg_0           = dword ptr  8
  .text:00429C2A arg_4           = dword ptr  0Ch
  .text:00429C2A
  1 .text:00429C2A                 mov     edi, edi
  2 .text:00429C2C                 push    ebp
  3 .text:00429C2D                 mov     ebp, esp
  4 .text:00429C2F                 mov     eax, [ebp+arg_0]
  5 .text:00429C32                 and     dword ptr [eax+4], 0
  6 .text:00429C36                 mov     byte ptr [eax], 4
  7 .text:00429C39                 mov     byte ptr [eax+2], 0Ah
  8 .text:00429C3D                 lea     ecx, [eax+8]
  9 .text:00429C40                 mov     [ecx+4], ecx
  10 .text:00429C43                 mov     [ecx], ecx
  11 .text:00429C45                 lea     ecx, [eax+10h]
  12 .text:00429C48                 mov     [ecx+4], ecx
  13 .text:00429C4B                 mov     [ecx], ecx
  14 .text:00429C4D                 lea     ecx, [eax+20h]
  15 .text:00429C50                 mov     [ecx+4], ecx
  16 .text:00429C53                 mov     [ecx], ecx
  17 .text:00429C55                 mov     ecx, [ebp+arg_4]
  18 .text:00429C58                 and     dword ptr [eax+18h], 0
  19 .text:00429C5C                 test    ecx, ecx
  20 .text:00429C5E                 jz      short loc_429C67
  21 .text:00429C60
  22 .text:00429C60 loc_429C60:
  23 .text:00429C60                 mov     [eax+1Ch], ecx
  24 .text:00429C63                 pop     ebp
  25 .text:00429C64                 retn    8
  26 .text:00429C67 ; --------------------------------------------------------------------------
  27 .text:00429C67                 movsx   ecx, ds:KeNumberProcessors
  28 .text:00429C6E                 jmp     short loc_429C60


lines 3/4 function prologue.
lines 4/5 set to zero the second 4 bytes pointed by arg_0
lines 5/6 set byte pointed from arg_0 to 4
lines 6/7 set bye pointed by arg_0+2 to 16

lines 8/17 Initialize three structure at eax+0x8, eax+0x10, eax+0x20 respectly.
           The two fields in the structures are inizialized at their very same address.

line 18 eax+0x18 are zeroed
line 19/28 set eax+0x1C to args_4 if not null,  to ds:KeNumberProcessor if arg_4 is null

So arg_0 should be a struct like


typedef struct _KQUEUE {
    DISPATCHER_HEADER Header;
    LIST_ENTRY EntryListHead;
    ULONG CurrentCount;
    ULONG MaximumCount;
    LIST_ENTRY ThreadListHead;
} KQUEUE, *PKQUEUE, *RESTRICTED_POINTER PRKQUEUE;

and

typedef struct _LIST_ENTRY {
  struct _LIST_ENTRY  *Flink;
  struct _LIST_ENTRY  *Blink;
} LIST_ENTRY, *PLIST_ENTRY;

*/

/* WinXP SP3 */

VOID KeInitializeQueue(
		       _Out_  PRKQUEUE Queue,
		       _In_   ULONG Count
		       )
{

  Queue->Header.SignalState = 0;
  Queue->Header.Type = 4;
  Queue->Header.WaitListHead->Blink = Queue->Header.WaitListHead;
  Queue->Header.WaitListHead->Flink = Queue->Header.WaitListHead;
  Queue->EntryListHead->Blink = Queue->EntryListHead;
  Queue->EntryListHead->Flink = Queue->EntryListHead;
  Queue->ThreadListHead->Blink = Queue->ThreadListHead;
  Queue->ThreadListHead->Flink = Queue->ThreadListHead;

  if (Count )
    Queue->MaximumCount = Count;
  else
    Queue->MaximumCount = KeNumberProcessors;

  return;

}

typedef struct _KSPIN_LOCK_QUEUE {
    struct _KSPIN_LOCK_QUEUE * volatile Next;
    PKSPIN_LOCK volatile Lock;
} KSPIN_LOCK_QUEUE, *PKSPIN_LOCK_QUEUE;

/* Win7 x86_64 */

PKSPIN_LOCK_QUEUE
KxWaitForLockChainValid (
			 __inout PKSPIN_LOCK_QUEUE LockQueue
			 )
{
  PKSPIN_LOCK_QUEUE AQueue;
  
  do {
    SomeYieldingStuff();
  } while ((AQueue = LockQueue->Next) == NULL); 
}


/* Win7 x86_64 */

VOID
KeReadyThread (
	       __inout PKTHREAD Thread
	       )
{

  if (Thread->Process.StackCount != 7) {
    if(KiInSwapSingleProcess(Thread))
      return;
  }
  KiFastReadyThread(Thread);
  return;
}

/*
  Disassembly of KiInitializeTSS (it should start the TSS segment for the current processor)

  mov     edi, edi
  push    ebp
  mov     ebp, esp
  mov     eax, [ebp+arg_0]
  and     word ptr [eax+64h], 0
  and     word ptr [eax+60h], 0
  mov     word ptr [eax+66h], 20ACh
  mov     word ptr [eax+8], 10h
  pop     ebp
  retn    4
*/


/*
  KTSS Struct

  +0x000 Backlink         : Uint2B
  +0x002 Reserved0        : Uint2B
  +0x004 Esp0             : Uint4B
  +0x008 Ss0              : Uint2B
  +0x00a Reserved1        : Uint2B
  +0x00c NotUsed1         : [4] Uint4B
  +0x01c CR3              : Uint4B
  +0x020 Eip              : Uint4B
  +0x024 EFlags           : Uint4B
  +0x028 Eax              : Uint4B
  +0x02c Ecx              : Uint4B
  +0x030 Edx              : Uint4B
  +0x034 Ebx              : Uint4B
  +0x038 Esp              : Uint4B
  +0x03c Ebp              : Uint4B
  +0x040 Esi              : Uint4B
  +0x044 Edi              : Uint4B
  +0x048 Es               : Uint2B
  +0x04a Reserved2        : Uint2B
  +0x04c Cs               : Uint2B
  +0x04e Reserved3        : Uint2B
  +0x050 Ss               : Uint2B
  +0x052 Reserved4        : Uint2B
  +0x054 Ds               : Uint2B
  +0x056 Reserved5        : Uint2B
  +0x058 Fs               : Uint2B
  +0x05a Reserved6        : Uint2B
  +0x05c Gs               : Uint2B
  +0x05e Reserved7        : Uint2B
  +0x060 LDT              : Uint2B
  +0x062 Reserved8        : Uint2B
  +0x064 Flags            : Uint2B
  +0x066 IoMapBase        : Uint2B
  +0x068 IoMaps           : [1] _KiIoAccessMap
  +0x208c IntDirectionMap  : [32] UChar
  
 */

VOID
KiInitilizeTSS(
	       IN PKTSS Tss
	       )
{
  Tss->Flags = 0x0;
  Tss->LDT = 0x0;
  Tss->IoMapBase = 0x20AC; /* 8364 */
  Tss->Ss0 = 0x10; /* 16 */
}

/*
  RtlValidateUnicodeString disassembly
  
  mov     edi, edi
  push    ebp
  mov     ebp, esp
  cmp     [ebp+arg_0], 0
  jz      short loc_467E21
  mov     eax, 0C000000Dh
  jmp     short loc_467E6D
  
  loc_467E21:                          
  mov     ecx, [ebp+arg_4]
  test    ecx, ecx        
  push    esi
  push    edi
  jz      short loc_467E69
  mov     di, [ecx]
  movzx   eax, di         
  push    2
  cdq                     
  pop     esi
  idiv    esi             
  test    edx, edx        
  jnz     short loc_467E62
  mov     si, [ecx+2]
  push    ebx
  movzx   eax, si         
  push    2
  cdq                     
  pop     ebx
  idiv    ebx             
  pop     ebx
  test    edx, edx        
  jnz     short loc_467E62 
  cmp     di, si          
  ja      short loc_467E62 
  test    di, di          
  jnz     short loc_467E5C 
  test    si, si          
  jz      short loc_467E69 
  
  loc_467E5C:              
  cmp     dword ptr [ecx+4], 0 
  jnz     short loc_467E69 
  
  loc_467E62:              
  
  mov     eax, 0C000000Dh
  jmp     short loc_467E6B ; Jump
    
  loc_467E69:
  xor     eax, eax
  
  loc_467E6B:                             
  pop     esi
  
  loc_467E6D:                             
  pop     ebp
  retn    8               
*/

/*
  +0x000 Length           : Uint2B
  +0x002 MaximumLength    : Uint2B
  +0x004 Buffer           : Ptr32 Uint2B
*/

NTSTATUS RtlUnicodeStringValidate(
				  ULONG Flags,
				  const UNICODE_STRING *String
				  )
{
  if (Flags != 0)
    return 0xC000000D;

  if (String == NULL) {
    return 0;
  } else {
    if ((String->Lenght % 2) != 0)
      return 0xC000000D;
    if ((String->MaximumLenght % 2) != 0)
	return 0xC000000D;
    if (String->Lenght > String->MaximumLenght)
      return 0xC000000D;
    if (String->Lenght == 0)
      return 0;
    if (String->Buffer == NULL)
      return 0xC000000D;
  }
  return 0;
}
