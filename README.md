# Syscall_Injector
Shellcode injector based on direct and indirect syscalls via Maldev Academy's HellHall technique

## Features
 - Support direct or indirect syscalls
 
 - Local and Remote Process Injection
    - Classic injection via: NtAllocateVirtualMemory, NtProtectVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx
	- Mapping injection via: NtCreateSection, NtMapViewOfSection, NtCreateThreadEx
	- Process targeting
	  - Local Process (self injection)
	  - Remote Process targeting via supplied PID, or Process Name
	  
 - Making use of hashed function names to initialize all needed information for syscalls usage.
 
 - RC4 shellcode encryption trough SystemFunction032
    - 64bit XoR-ed encryption key 
    - XoR key obfuscated as an IP address array (currently hardcoded)
	
 - Reading the shellcode from a remote webserver via winhttp lib, or from a local file on disk (mainly for testing).
 
 - Simple evasion techniques implemented
    - ETW patching (EtwpEventWriteFull)
	- Debugger detection trough ProcessDebugPort and ProcessDebugObjectHandle
	- Self delete the resulting binary after run
	- Basic virtual environment/sandbox checks
	   - System resources (less than 2 vCPUs and 2GB Ram)
	   - Check if the file's name is hashed (count the number of digits in it)
	   - Check the number of runnig processes on the system
	- Delayed execution
	- Simple guardrails implementation for execution controll, based on one of the following: 
	    - Username
		- Userdomain
		- ComputerName
		
 - Custom GetAddr function to fetch an API's address without using GetProcAddress
 - Almost no WIN APIs used
 
 
## TODO
 - Do not hardcode the XoR key, maybe concatenate with the payload and parse it.
 - Remove the rest of the Win APIs that are being used.
 - Remove the need for LoadLibraryA
 - Remove the need for CRT library
 - Add additional injection technique, not based on Thread creation (callbacks, thread hijacking, etc.)
 
 
## Usage
The project is created and compiled with Visual Studio 2022, so there are no requirements, just open the solution and compile. :)
 - Decryption key and XoR key can be changed as needed, located in `crypt.c`. Encryption function will be in a separate repo, feel free to use it or create your own.
 - All configurable things can be found in the main header file `main.h`, modify as needed.
 
```C
#define WEB 80
//#define SECURE 443

#define HOST L"127.0.0.1"
#define FILE L"calc-enc.bin"
#define LOCAL_FILE "C:\\Users\\nullb1t3\\Desktop\\calc.bin"



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
#define PROC_NAME L"notepad.exe"
//#define PID 8392


/*------------------------------------------
 Anti-Debug constants
------------------------------------------*/
#define SELF_DELETE		//Delete the file on disk after execution
#define WAIT 2			//minutes
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
``` 
 
## Credits
- @mr.d0x @NUL0x4C and @5pider and the incredible [Maldev academy] (https://maldevacademy.com/)


## Disclaimer
As always this simple tool is created for educational purposes only ! 
 
 
 