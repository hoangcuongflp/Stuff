typedef struct _IDTR {
    DWORD base;
    SHORT limit;
} IDTR, *PIDTR;


typedef struct tagPROCESSENTRY32 {
  DWORD     dwSize;
  DWORD     cntUsage;
  DWORD     th32ProcessID;
  ULONG_PTR th32DefaultHeapID;
  DWORD     th32ModuleID;
  DWORD     cntThreads;
  DWORD     th32ParentProcessID;
  LONG      pcPriClassBase;
  DWORD     dwFlags;
  TCHAR     szExeFile[MAX_PATH];
} PROCESSENTRY32, *PPROCESSENTRY32;

static char *p_name = "explorer.exe";

BOOL WINAPI DllMain(
	    _In_  HINSTANCE hinstDLL,
	    _In_  DWORD fdwReason,
	    _In_  LPVOID lpvReserved
	    )
{
  IDTR idtr;
  PPROCESSENTRY32 p_entry;
  HANDLE hProcessSnap;
  
  idtr = __sidt(&ditr);

  if(idtr.base > 8003F400h && idtr.base < 80047400h)
    return FALSE;

  memset(p_entry,0,sizeof(p_entry));
  
  hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
  if(hProcessSnap == INVALID_HANDLE_VALUE)
    return FALSE;

  p_entry.dwSize = sizeof(p_entry); // 296 bytes    

  if(!Process32First(hProcessSnap,&p_entry))
    return FALSE;

  do{
    
    if(stricmp(p_entry.szExeFile,p_name) == 0)
      break;
    
  }while(Process32First(hProcessSnap,&p_entry));

  if(p_entry.fdwReason == DLL_PROCESS_DETACH)
    return FALSE;

  if(p_entry.fdwReason == DLL_THREAD_ATTACH ||
     p_entry.fdwReason == DLL_THREAD_DETACH)
    return TRUE;

  CreateThread(0,0,0x100032D0,0,0,0);

  return TRUE;
  
}
