   
    .syntax unified
    .arch armv8-m.main
    .thumb


    .section .vectors, "ax", %progbits
    .align 11
    .global __Vectors
    .type __Vectors, %object
__Vectors:
    .word   __StackTop
    .word   Reset_Handler
    .word   0                            /* NMI_Handler */
    .word   HardFault_Handler
    .word   MemManage_Handler             
    .word   0                            /* BusFault_Handler */
    .word   UsageFault_Handler            /* Includes MSPLIM/PSPLIM overflow */
    .word   0                            /* SecureFault_Handler */
    .word   0
    .word   0
    .word   0
    .word   SVC_Handler
    .word   0                            /* DebugMon_Handler */
    .word   0
    .word   0                            /* PendSV_Handler */
    .word   gpos_core_periodic_timer_interrupt_handler /* SysTick_Handler */
    
    .space (480 * 4)                    /* Interrupt vector table */
    

    .section .picobin_block, "a"
    .word 0xffffded3          // PICOBIN_BLOCK_MARKER_START

    .byte 0x42
    .byte 0x1
    .hword 0b0001000000100001

    .byte 0xff
    .hword 0x0001
    .byte 0

    .word 0                 
    .word 0xab123579          // PICOBIN_BLOCK_MARKER_END

    
    .section .text, "ax", %progbits   
    
board_name:
    .asciz "raspi-pico2: "

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

    .global _start
    .thumb_set _start, __Vectors

    .align 2
    .thumb_func
Reset_Handler:


    ldr     r0, =__Vectors
    ldr     r1, =SCB_VTOR 
    str     r0, [r1]

    bl      copy_critical_kernel_fct
    bl      .Lcopy_data
    bl      .Lzero_bss
    bl      start

    mov     sp, r11
    ldr     r1, =ADP_APP_EXIT
    movs    r0, #SYS_EXIT
    bkpt    0xab

    .thumb_func
copy_critical_kernel_fct:
    ldr     r0, =__critical_kernel_fct_load
    ldr     r1, =__critical_kernel_fct_start
    ldr     r2, =__critical_kernel_fct_end
copy_critical_kernel_fct_loop:
    cmp     r1, r2
    bcs     copy_critical_kernel_fct_done
    ldr     r3, [r0]
    str     r3, [r1]
    adds    r0, #4
    adds    r1, #4
    b       copy_critical_kernel_fct_loop
copy_critical_kernel_fct_done:
    bx      lr

    .thumb_func
SVC_Handler:
    ldr     r0, =__oxide_se_boot_abi_start
    ldr     r0, [r0, #BOOT_ABI_SVC_FORWARD_OFFSET]
    cbz     r0, .Lsvc_unconfigured
    bx      r0

    .thumb_func
.Lsvc_unconfigured:
    movs    r0, #1
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
    movs    r0, #2
    b       .Ldie_common

    .thumb_func
MemManage_Handler:
    ldr     r0, =__oxide_se_boot_abi_start
    ldr     r0, [r0, #BOOT_ABI_MEMMANAGE_FORWARD_OFFSET]
    cbz     r0, .Lmemmanage_unconfigured
    bx      r0

    .thumb_func
.Lmemmanage_unconfigured:
    movs    r0, #3
    b       .Ldie_common

    .thumb_func
UsageFault_Handler:
    ldr     r0, =__oxide_se_boot_abi_start
    ldr     r0, [r0, #BOOT_ABI_USAGEFAULT_FORWARD_OFFSET]
    cbz     r0, .Lusagefault_unconfigured
    bx      r0

    .thumb_func
.Lusagefault_unconfigured:
    movs    r0, #4
    b       .Ldie_common

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
    .word .Lerr1, .Lerr2, .Lerr3, .Lerr4
.Lerr1:
    .asciz "svc before kernel init"
.Lerr2:
    .asciz "hard fault"
.Lerr3:
    .asciz "memmanage fault"
.Lerr4:
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
.Lcopy_data:
    ldr     r0, =__data_load
    ldr     r1, =__data_start
    ldr     r2, =__data_end
.Lcopy_data_loop:
    cmp     r1, r2
    bcs     .Lcopy_data_done
    ldr     r3, [r0], #4
    str     r3, [r1], #4
    b       .Lcopy_data_loop
.Lcopy_data_done:
    bx      lr

    .thumb_func
.Lzero_bss:
    ldr     r0, =__bss_start
    ldr     r1, =__bss_end
    movs    r2, #0
.Lzero_bss_loop:
    cmp     r0, r1
    bcs     .Lzero_bss_done
    str     r2, [r0], #4
    b       .Lzero_bss_loop
.Lzero_bss_done:
    bx      lr
