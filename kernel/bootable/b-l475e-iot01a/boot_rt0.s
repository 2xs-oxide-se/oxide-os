    .syntax unified
    .arch armv7e-m
    .thumb

    /*
     * Oxide SE bootable FAE startup for B-L475E-IOT01A.
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
    .asciz "b-l475e-iot01a: "

    .include "kernel/bootable/generic-cortex-m/boot_rt0.s"
