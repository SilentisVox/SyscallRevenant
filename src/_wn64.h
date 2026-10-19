#ifndef _W64_H
#define _W64_H

#ifndef BASETYPES
#define BASETYPES
        #define CONST                   const
        #define WINAPI
        #define NTAPI
        #define VOID                    void
        #define PVOID                   void *
        #define HANDLE                  void *
        #define SOCKET                  void *
        #define INT                     int
        #define PINT                    INT *
        #define BOOL                    INT
        #define UINT                    unsigned int
        #define PUINT                   UINT *
        #define CHAR                    char
        #define PCHAR                   CHAR *
        #define UCHAR                   unsigned char
        #define PUCHAR                  UCHAR *
        #define SHORT                   short
        #define PSHORT                  SHORT *
        #define USHORT                  unsigned short
        #define PUSHORT                 USHORT *
        #define WCHAR                   USHORT
        #define PWCHAR                  WCHAR *
        #define LONG                    long
        #define PLONG                   LONG *
        #define ULONG                   unsigned long
        #define PULONG                  ULONG *
        #define ACCESS_MASK             ULONG
        #define LONGLONG                long long
        #define ULONG_PTR               unsigned long long
        #define ULONGLONG               unsigned long long
#endif

#ifndef TRUE
        #define TRUE                    1
        #define FALSE                   0
#endif
#ifndef NULL
        #define NULL                    ((PVOID)0)
#endif
#ifndef ZERO
        #define ZERO                    0
#endif

#define PROCESS_ALL_ACCESS              0x001F0FFF
#define THREAD_ALL_ACCESS               0x001F03FF
#define MEM_COMMIT                      0x00001000

#define PAGE_EXECUTE                    0x10
#define PAGE_EXECUTE_READ               0x20
#define PAGE_EXECUTE_READWRITE          0x40
#define PAGE_EXECUTE_WRITECOPY          0x80
#define PAGE_NOACCESS                   0x01
#define PAGE_READONLY                   0x02
#define PAGE_READWRITE                  0x04
#define PAGE_WRITECOPY                  0x08
#define PAGE_TARGETS_INVALID            0x40000000
#define PAGE_TARGETS_NO_UPDATE          0x40000000

#define NTSTATUS                        LONG
#define NT_SUCCESS(STATUS)              (((NTSTATUS)STATUS) >= 0)
#define NtCurrentProcess()              ((HANDLE)-1)
#define NtCurrentThread()               ((HANDLE)-2)
#define NtCurrentConsole()              ((HANDLE)-3)

#define MAX_PATH                        260
#define HEAP_ZERO_MEMORY                0x00000008

typedef struct _LSA_UNICODE_STRING {
        USHORT          Length;
        USHORT          MaximumLength;
        PUSHORT         Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
        ULONG           Length;
        HANDLE          RootDirectory;
        PUNICODE_STRING ObjectName;
        ULONG           Attributes;
        PVOID           SecurityDescriptor;
        PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_A;

typedef struct _LARGE_INTEGER {
        ULONG_PTR       QuadPart;
} LARGE_INTEGER, * PLARGE_INTEGER;

typedef struct _VM_COUNTERS {
        ULONG_PTR       PeakVirtualSize;
        ULONG_PTR       VirtualSize;
        ULONG           PageFaultCounts;
        ULONG_PTR       PeakWorkingSet;
        ULONG_PTR       WorkingSet;
        ULONG_PTR       QuotaPeakPagedUsage;
        ULONG_PTR       QuotaPagedUsage;
        ULONG_PTR       QuotaPeakNonPagedUsage;
        ULONG_PTR       QuotaNonPagedUsage;
        ULONG_PTR       PagefileUsage;
        ULONG_PTR       PeakPagefileUsage;
} VM_COUNTERS, * PVM_COUNTERS;

typedef struct _IO_COUNTERS {
        ULONG_PTR       ReadOperationCount;
        ULONG_PTR       WriteOperationCount;
        ULONG_PTR       OtherOperationCount;
        ULONG_PTR       ReadTransferCount;
        ULONG_PTR       WriteTransferCount;
        ULONG_PTR       OtherTransferCount;
} IO_COUNTERS, * PIO_COUNTERS;

typedef struct _SYSTEM_PROCESS_INFORMATION {
        ULONG           NextEntryOffset;
        ULONG           NumberOfThreads;
        LARGE_INTEGER   Reserved[3];
        LARGE_INTEGER   CreateTime;
        LARGE_INTEGER   UserTime;
        LARGE_INTEGER   KernelTime;
        UNICODE_STRING  ImageName;
        ULONG           BasePriority;
        HANDLE          UniqueProcessId;
        HANDLE          InheritedFromUniqueProcessId;
        ULONG           HandleCount;
        ULONG           SessionId;
        ULONG           PageDirectoryBase;
        VM_COUNTERS     VirtualMemoryCounters;
        ULONG_PTR       PrivatePageCount;
        IO_COUNTERS     IoCounters;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef struct _CLIENT_ID {
        HANDLE          UniqueProcess;
        HANDLE          UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _FLOATING_SAVE_AREA {
        ULONG           ControlWord;
        ULONG           StatusWord;
        ULONG           TagWord;
        ULONG           ErrorOffset;
        ULONG           ErrorSelector;
        ULONG           DataOffset;
        ULONG           DataSelector;
        UCHAR           RegisterArea[80];
        ULONG           Cr0NpxState;
} FLOATING_SAVE_AREA;

typedef struct _M128A {
        ULONG_PTR       Low;
        ULONG_PTR       High;
} M128A, * PM128A;

typedef struct _XMM_SAVE_AREA32 {
        USHORT          ControlWord;
        USHORT          StatusWord;
        UCHAR           TagWord;
        UCHAR           Reserved1;
        USHORT          ErrorOpcode;
        ULONG           ErrorOffset;
        USHORT          ErrorSelector;
        USHORT          Reserved2;
        ULONG           DataOffset;
        USHORT          DataSelector;
        USHORT          Reserved3;
        ULONG           MxCsr;
        ULONG           MxCsr_Mask;
        M128A           FloatRegisters[8];
        M128A           XmmRegisters[16];
        UCHAR           Reserved4[96];
} XMM_SAVE_AREA32, * PXMM_SAVE_AREA32;

typedef __attribute__((aligned(16))) struct _CONTEXT {
        ULONG_PTR       P1Home;
        ULONG_PTR       P2Home;
        ULONG_PTR       P3Home;
        ULONG_PTR       P4Home;
        ULONG_PTR       P5Home;
        ULONG_PTR       P6Home;
        ULONG           ContextFlags;
        ULONG           MxCsr;
        USHORT          SegCs;
        USHORT          SegDs;
        USHORT          SegEs;
        USHORT          SegFs;
        USHORT          SegGs;
        USHORT          SegSs;
        ULONG           EFlags;
        ULONG_PTR       Dr0;
        ULONG_PTR       Dr1;
        ULONG_PTR       Dr2;
        ULONG_PTR       Dr3;
        ULONG_PTR       Dr6;
        ULONG_PTR       Dr7;
        ULONG_PTR       Rax;
        ULONG_PTR       Rcx;
        ULONG_PTR       Rdx;
        ULONG_PTR       Rbx;
        ULONG_PTR       Rsp;
        ULONG_PTR       Rbp;
        ULONG_PTR       Rsi;
        ULONG_PTR       Rdi;
        ULONG_PTR       R8;
        ULONG_PTR       R9;
        ULONG_PTR       R10;
        ULONG_PTR       R11;
        ULONG_PTR       R12;
        ULONG_PTR       R13;
        ULONG_PTR       R14;
        ULONG_PTR       R15;
        ULONG_PTR       Rip;
        union {
                XMM_SAVE_AREA32 FltSave;
                XMM_SAVE_AREA32 FloatSave;
                struct {
                        M128A Header[2];
                        M128A Legacy[8];
                        M128A Xmm0;
                        M128A Xmm1;
                        M128A Xmm2;
                        M128A Xmm3;
                        M128A Xmm4;
                        M128A Xmm5;
                        M128A Xmm6;
                        M128A Xmm7;
                        M128A Xmm8;
                        M128A Xmm9;
                        M128A Xmm10;
                        M128A Xmm11;
                        M128A Xmm12;
                        M128A Xmm13;
                        M128A Xmm14;
                        M128A Xmm15;
                };
        };
        M128A           VectorRegister[26];
        ULONG_PTR       VectorControl;
        ULONG_PTR       DebugControl;
        ULONG_PTR       LastBranchToRip;
        ULONG_PTR       LastBranchFromRip;
        ULONG_PTR       LastExceptionToRip;
        ULONG_PTR       LastExceptionFromRip;
} CONTEXT, * PCONTEXT;

#define CONTEXT_DEBUG_REGISTERS       (0x100000 | 0x10)
#define EXCEPTION_SINGLE_STEP	      0x80000004
#define EXCEPTION_ILLEGAL_INSTRUCTION 0xC000001D
#define EXCEPTION_CONTINUE_SEARCH     0
#define EXCEPTION_CONTINUE_EXECUTION -1

typedef struct _EXCEPTION_RECORD {
        ULONG           ExceptionCode;
        ULONG           ExceptionFlags;
        struct _EXCEPTION_RECORD *ExceptionRecord;
        ULONG_PTR       ExceptionAddress;
        ULONG           NumberParameters;
        ULONG_PTR       ExceptionInformation[15];
} EXCEPTION_RECORD, * PEXCEPTION_RECORD;

typedef struct _EXCEPTION_POINTERS {
        PEXCEPTION_RECORD       ExceptionRecord;
        PCONTEXT                ContextRecord;
} EXCEPTION_POINTERS, * PEXCEPTION_POINTERS;

UINT GetRandom();

#define __readgsqword(o) ({VOID *v;__asm__ volatile("mov %%gs:%c1, %0":"=r"(v):"i"(o)); v;})
#define NtGetProcessHeap() ({VOID *v; v = *(VOID**)(((CHAR*)__readgsqword(0x60)) + 0x30); v;})

#endif // !_W64_H