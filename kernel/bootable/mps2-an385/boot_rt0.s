    .syntax unified
    .arch armv7-m
    .thumb

    /*
     * Oxide SE bootable FAE startup for QEMU mps2-an385.
     */

    .section ._start, "ax", %progbits
    .align 2

    .global __Vectors
    .type __Vectors, %object
__Vectors:
    .global _start
    .thumb_set _start, __Vectors
    .word   __StackTop
    .word   Reset_Handler
    .word   0
    .word   HardFault_Handler
    .word   MemManage_Handler
    .word   0
    .word   UsageFault_Handler
    .word   0
    .word   0
    .word   0
    .word   0
    .word   SVC_Handler
    .word   0
    .word   0
    .word   0
    .word   PeriodicTimer_Handler

board_name:
    .asciz "mps2-an385: "

    .include "kernel/bootable/generic-cortex-m/boot_rt0.s"
