    .equ SCB_VTOR,        0xE000ED08
    .equ SYS_WRITE0,      4
    .equ SYS_EXIT,        0x18
    .equ ADP_APP_EXIT,    0x20026
    .equ SCB_CFSR,        0xE000ED28
    .equ SCB_HFSR,        0xE000ED2C
    .equ SCB_MMFAR,       0xE000ED34
    .equ SCB_BFAR,        0xE000ED38
    .equ BOOT_ABI_SVC_FORWARD_OFFSET,        0
    .equ BOOT_ABI_MEMMANAGE_FORWARD_OFFSET,  4
    .equ BOOT_ABI_USAGEFAULT_FORWARD_OFFSET, 8
    .equ BOOT_ABI_PERIODIC_TIMER_FORWARD_OFFSET, 12
    /* Oxide SE-owned generic Cortex-M bootable startup.
     *
     * This wrapper is derived from the xiprfs generic bootable startup, but it
     * now lives under core/bootable so board-specific kernels can evolve their
     * vector-table and VTOR policy without coupling that design to xiprfs'
     * default bundled firmware profiles.
     *
     * Failure mapping:
     * - codes 1, 3, 4, 5 are returned by the shared relocation core
     * - code 2 is a legacy reserved slot kept only for message table stability
     * - code 6 is raised here from HardFault_Handler
     * - code 7 is raised here from MemManage_Handler
     * - code 8 is raised here from UsageFault_Handler
     */

    .align 2
    .thumb_func
Reset_Handler:
    cpsid   i
    ldr     r0, =__StackTop
    mov     sp, r0
    mov     r11, sp

    ldr     r0, =__Vectors
    ldr     r1, =SCB_VTOR
    str     r0, [r1]

    ldr     r9, =__fae_ram_start
    bl      .Lfae_rt0_run
    cmp     r0, #0
    bne     .Ldie_common

    mov     sp, r11
    mov     sp, r11
    ldr     r1, =ADP_APP_EXIT
    movs    r0, #SYS_EXIT
    bkpt    0xab

    .thumb_func
SVC_Handler:
    ldr     r0, =__oxide_se_boot_abi_start
    ldr     r0, [r0, #BOOT_ABI_SVC_FORWARD_OFFSET]
    cbz     r0, .Lsvc_unconfigured
    bx      r0

    .thumb_func
.Lsvc_unconfigured:
    movs    r0, #6
    b       .Ldie_common

    .thumb_func
HardFault_Handler:
    mov     r5, lr
    mrs     r6, msp
    mrs     r7, psp
    tst     lr, #4
    ite     eq
    mrseq   r4, msp
    mrsne   r4, psp
    ldr     r1, =__StackTop
    mov     sp, r1
    mov     r0, r4
    mov     r1, r5
    mov     r2, r6
    mov     r3, r7
    bl      .Lhardfault_report
    movs    r0, #6
    b       .Ldie_common

    .thumb_func
MemManage_Handler:
    ldr     r0, =__oxide_se_boot_abi_start
    ldr     r0, [r0, #BOOT_ABI_MEMMANAGE_FORWARD_OFFSET]
    cbz     r0, .Lmemmanage_unconfigured
    bx      r0

    .thumb_func
.Lmemmanage_unconfigured:
    movs    r0, #7
    b       .Ldie_common

    .thumb_func
UsageFault_Handler:
    ldr     r0, =__oxide_se_boot_abi_start
    ldr     r0, [r0, #BOOT_ABI_USAGEFAULT_FORWARD_OFFSET]
    cbz     r0, .Lusagefault_unconfigured
    bx      r0

    .thumb_func
.Lusagefault_unconfigured:
    movs    r0, #8
    b       .Ldie_common

    .thumb_func
PeriodicTimer_Handler:
    ldr     r0, =__oxide_se_boot_abi_start
    ldr     r0, [r0, #BOOT_ABI_PERIODIC_TIMER_FORWARD_OFFSET]
    cbz     r0, .Lperiodic_timer_unconfigured
    bx      r0

    .thumb_func
.Lperiodic_timer_unconfigured:
    bx      lr

.Ldie_common:
    ldr     r1, =__StackTop
    mov     sp, r1
    push    {r0}
    ldr     r1, =board_name
    bl      .Lwrite0
    pop     {r0}
    subs    r0, #1
    lsls    r0, r0, #2
    adr     r1, .Lmsgtab
    ldr     r1, [r1, r0]
    bl      .Lwrite0
.Lhang:
    nop
    b       .Lhang

.Lwrite0:
    movs    r0, #SYS_WRITE0
    bkpt    0xab
    bx      lr

    .thumb_func
.Lhardfault_report:
    push    {r4-r7, lr}
    mov     r4, r0
    mov     r5, r1
    mov     r6, r2
    mov     r7, r3
    adr     r1, .Lhardfault_detail
    bl      .Lwrite0

    adr     r1, .Lexc_return_label
    mov     r2, r5
    bl      .Lwrite_label_value

    adr     r1, .Lmsp_label
    mov     r2, r6
    bl      .Lwrite_label_value

    adr     r1, .Lpsp_label
    mov     r2, r7
    bl      .Lwrite_label_value

    adr     r1, .Lselected_sp_label
    mov     r2, r4
    bl      .Lwrite_label_value

    adr     r1, .Lhfsr_label
    ldr     r0, =SCB_HFSR
    ldr     r2, [r0]
    bl      .Lwrite_label_value

    adr     r1, .Lcfsr_label
    ldr     r0, =SCB_CFSR
    ldr     r2, [r0]
    bl      .Lwrite_label_value

    adr     r1, .Lmmfar_label
    ldr     r0, =SCB_MMFAR
    ldr     r2, [r0]
    bl      .Lwrite_label_value

    adr     r1, .Lbfar_label
    ldr     r0, =SCB_BFAR
    ldr     r2, [r0]
    bl      .Lwrite_label_value

    adr     r1, .Lstacked_pc_label
    ldr     r2, [r4, #24]
    bl      .Lwrite_label_value

    adr     r1, .Lstacked_lr_label
    ldr     r2, [r4, #20]
    bl      .Lwrite_label_value

    pop     {r4-r7, pc}

    .thumb_func
.Lwrite_label_value:
    push    {r2, lr}
    bl      .Lwrite0
    pop     {r0, lr}
    b       .Lwrite_hex32

    .thumb_func
.Lwrite_hex32:
    push    {r4-r7, lr}
    sub     sp, sp, #16
    mov     r4, sp
    mov     r5, r0
    movs    r0, #'0'
    strb    r0, [r4, #0]
    movs    r0, #'x'
    strb    r0, [r4, #1]
    movs    r6, #0
1:
    movs    r0, #7
    subs    r0, r0, r6
    lsls    r0, r0, #2
    lsrs    r1, r5, r0
    movs    r0, #0x0f
    ands    r1, r0
    cmp     r1, #10
    blo     2f
    adds    r1, r1, #('A' - 10)
    b       3f
2:
    adds    r1, r1, #'0'
3:
    adds    r0, r4, #2
    adds    r0, r0, r6
    strb    r1, [r0]
    adds    r6, r6, #1
    cmp     r6, #8
    blo     1b
    movs    r0, #'\n'
    strb    r0, [r4, #10]
    movs    r0, #0
    strb    r0, [r4, #11]
    mov     r1, r4
    bl      .Lwrite0
    add     sp, sp, #16
    pop     {r4-r7, pc}

    .align 2
.Lmsgtab:
    .word .Lerr1, .Lerr2, .Lerr3, .Lerr4, .Lerr5, .Lerr6, .Lerr7, .Lerr8
.Lerr1:
    .asciz "invalid file version"
.Lerr2:
    .asciz "not enough ram"
.Lerr3:
    .asciz "out-of-bounds offset"
.Lerr4:
    .asciz "cannot relocate offsets in .rom"
.Lerr5:
    .asciz "cannot relocate offsets in .got"
.Lerr6:
    .asciz "hard fault"
.Lerr7:
    .asciz "memmanage fault"
.Lerr8:
    .asciz "usage fault"
.Lhardfault_detail:
    .asciz "hard fault detail:\n"
.Lexc_return_label:
    .asciz "  exc_return="
.Lmsp_label:
    .asciz "  msp="
.Lpsp_label:
    .asciz "  psp="
.Lselected_sp_label:
    .asciz "  selected_sp="
.Lhfsr_label:
    .asciz "  hfsr="
.Lcfsr_label:
    .asciz "  cfsr="
.Lmmfar_label:
    .asciz "  mmfar="
.Lbfar_label:
    .asciz "  bfar="
.Lstacked_pc_label:
    .asciz "  stacked_pc="
.Lstacked_lr_label:
    .asciz "  stacked_lr="

    .align 2
    .thumb_func
.Lfae_rt0_run:
    .include "tooling/build-fae/rt0/arm-thumb/rt0-thumb.s"

    .global _end
_end:
