#include "_wn64.h"
#include "_rvnt.h"

UINT GetRandom() {
        UINT h = 0, l = 0, r = 0, i = 0;

        __asm__ volatile ("rdtsc" : "=a" (l), "=d" (h));

        for (UINT i = 0; i < (h % 255); i++) {
                r = ((r >> 13) | (r << 21));
                r = r * 0x2499CE2F;
                r = (r + ((l >> (8 * (i % 4))) & 0xFF));
                r = r ^ 0x39C5E493;
        }
        return r;
}

ULONG ROR7_32(CONST UCHAR* Name) {
        ULONG h = 0, i = 0;

        while (Name[i]) {
                h = (h >> 7) | (h << 25);
                h += Name[i++];
        }
        return h;
}

BOOL GetModule(ULONG ModuleHash, VOID** hModule) {
        VOID* pProcessEnvironmentBlock                          = __readgsqword(0x60);
        VOID* pLoaderData                                       = *(VOID**)(((CHAR*)pProcessEnvironmentBlock) + 0x18);
        VOID* pInInitializationOrderModuleList                  = (VOID*)(((CHAR*)pLoaderData) + 0x30);
        VOID* pModuleList                                       = *(VOID**)pInInitializationOrderModuleList;

        while (pInInitializationOrderModuleList != pModuleList) {
                WCHAR   *Buffer                                 = (WCHAR*)*(VOID**)(((CHAR*)pModuleList) + 0x40);
                USHORT  MaximumLength                           = *(USHORT*)(((CHAR*)pModuleList) + 0x3A);
                UCHAR   ModuleNameA[MAX_PATH]                   = { 0 };

                for (ULONG i = 0; i < MaximumLength / 2; i++) {
                        ModuleNameA[i]                          = Buffer[i];
                }
                if (ROR7_32(ModuleNameA) != ModuleHash) {
                        pModuleList                             = *(VOID**)pModuleList;
                        continue;
                }
                *hModule                                        = *(VOID**)(((CHAR*)pModuleList) + 0x10);
                return TRUE;
                
        }
        *hModule                                                = NULL;
        return FALSE;
}

BOOL GetFunction(VOID* hModule, ULONG FunctionHash, VOID** pFunction) {
        VOID* pNtHeaders                                        = (VOID*)(((CHAR*)hModule) + *(ULONG*)(((CHAR*)hModule) + 0x3C));
        VOID* pExportDirectory                                  = (VOID*)(((CHAR*)hModule) + *(ULONG*)(((CHAR*)pNtHeaders) + 0x88));

        ULONG NumberOfNames                                     = *(ULONG*)(((CHAR*)pExportDirectory) + 0x18);
        ULONG* pAddressOfFunctions                              = (ULONG*)(((CHAR*)hModule) + *(ULONG*)(((CHAR*)pExportDirectory) + 0x1C));
        ULONG* pAddressOfNames                                  = (ULONG*)(((CHAR*)hModule) + *(ULONG*)(((CHAR*)pExportDirectory) + 0x20));
        USHORT* pAddressOfNameOrdinals                          = (USHORT*)(((CHAR*)hModule) + *(ULONG*)(((CHAR*)pExportDirectory) + 0x24));

        for (ULONG i = 0; i < NumberOfNames; i++) {
                UCHAR *FunctionName                             = (UCHAR*)hModule + pAddressOfNames[i];

                if (ROR7_32(FunctionName) != FunctionHash)
                        continue;

                *pFunction                                      = (VOID*)(((CHAR*)hModule) + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
                return TRUE;
        }
        *pFunction                                              = NULL;
        return FALSE;
}

BOOL ResolveFunction(ULONG ModuleHash, ULONG FunctionHash, VOID** pFunction) {
        VOID* hModule                                           = NULL;

        if (!GetModule(ModuleHash, &hModule)) {
                *pFunction                                      = NULL;
                return FALSE;
        }
        if (!GetFunction(hModule, FunctionHash, pFunction)) {
                *pFunction                                      = NULL;
                return FALSE;
        }
        return TRUE;
}

LONG VectoredExceptionHandler(EXCEPTION_POINTERS* pBreakPoint) {
        if (pBreakPoint->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) {
                return EXCEPTION_CONTINUE_SEARCH;
        }
        switch (SyscallInformationLookup) {
        case 0:
                if (*(USHORT*)(pBreakPoint->ExceptionRecord->ExceptionAddress - 2) != 0x050F) {
                        pBreakPoint->ContextRecord->EFlags     |= 0x100;
                        break;
                }
                *(VOID**)pBreakPoint->ContextRecord->Rsp        = RealReturnAddress;
                pBreakPoint->ContextRecord->Rip                 = (ULONG_PTR)TRAMPOLINE_EXIT;
                break;
        case 1:
                if (*(USHORT*)pBreakPoint->ExceptionRecord->ExceptionAddress != 0x050F) {
                        pBreakPoint->ContextRecord->EFlags     |= 0x100;
                        break;
                }
                FunctionEntry                                   = (VOID*)pBreakPoint->ContextRecord->Rip;
                SystemServiceNumber                             = (ULONG)pBreakPoint->ContextRecord->Rax;
                pBreakPoint->ContextRecord->Rip                 = (ULONG_PTR)TRAMPOLINE_EXIT;
                break;
        }
        return EXCEPTION_CONTINUE_EXECUTION;
}

VOID* RtlAddVectoredExceptionHandler(ULONG First, VOID* Handler) {
        SET_FUNCTION(
                ROR7_32__NTDLL,
                ROR7_32__RtlAddVectoredExceptionHandler
        );
        return RUN_FUNCTION(
                First,
                Handler
        );
}

VOID* RtlAllocateHeap(VOID* hHeap, ULONG Flags, ULONG_PTR Size) {
        SET_FUNCTION(
                ROR7_32__NTDLL,
                ROR7_32__RtlAllocateHeap
        );
        return RUN_FUNCTION(
                hHeap,
                Flags,
                Size
        );
}

BOOL RtlFreeHeap(VOID* hHeap, ULONG Flags, VOID* pAddress) {
        SET_FUNCTION(
                ROR7_32__NTDLL,
                ROR7_32__RtlFreeHeap
        );
        return (BOOL)RUN_FUNCTION(
                hHeap,
                Flags,
                pAddress
        );
}