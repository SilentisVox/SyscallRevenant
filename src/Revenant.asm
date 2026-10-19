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
        INIT:
                MOV     AL,     BYTE    [LOOKUP]
                CMP     AL,     1
                JNZ     FAKE

        PRESERVE:
                MOV     RAX,    QWORD   [RSP]
                MOV     QWORD   [FRTN], RAX
                JMP     TRAP

        FAKE:
                MOV     RAX,    QWORD   [RSP]
                MOV     QWORD   [RRTN], RAX
                MOV     RAX,    QWORD   [FRTN]
                CMP     RAX,    0
                JZ      TRAP
                MOV     QWORD   [RSP],  RAX

        TRAP:
                PUSHFQ
                OR      QWORD   [RSP],  0x100
                POPFQ

        INDIRECT:
                MOV     R10,    RCX
                MOV     EAX,    DWORD   [REL SSN]
                JMP     QWORD   [REL ENTRY]

        TRAMPOLINE_EXIT:
                MOV     QWORD   [FRTN],         0
                MOV     QWORD   [RRTN],         0
                MOV     BYTE    [LOOKUP],       0
                RET
TRAMPOLINE_END: