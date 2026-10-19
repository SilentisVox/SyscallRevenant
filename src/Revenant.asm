BITS 64

section         .data
global          ENTRY
global          SSN
global          LOOKUP
global          RRTN

ENTRY:          DQ 0
SSN:            DD 0
LOOKUP:         DB 0

FRTN:           DQ 0
RRTN:           DQ 0

section         .text
global          TRAMPOLINE
global          INDIRECT
global          TRAMPOLINE_EXIT

TRAMPOLINE:
        TRAP:
                PUSHFQ
                OR      QWORD   [RSP],  0x100
                POPFQ

        INIT:
                MOV     AL,     BYTE    [LOOKUP]
                CMP     AL,     1
                JNZ     FAKE

        PRESERVE:
                MOV     RAX,    QWORD   [RSP]
                MOV     QWORD   [FRTN], RAX
                JMP     INDIRECT

        FAKE:
                MOV     RAX,    QWORD   [RSP]
                MOV     QWORD   [RRTN], RAX
                MOV     RAX,    QWORD   [FRTN]
                MOV     QWORD   [RSP],  RAX

        INDIRECT:
                MOV     R10,    RCX
                MOV     EAX,    DWORD   [REL SSN]
                JMP     QWORD   [REL ENTRY]

        TRAMPOLINE_EXIT:
                MOV     BYTE    [LOOKUP],       0
                RET
TRAMPOLINE_END: