    .syntax unified
    .arch armv7-m
    .thumb

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
    .word   gpos_core_periodic_timer_interrupt_handler

board_name:
    .asciz "mps2-an385: "

    .include "kernel/native/generic-cortex-m/native_rt0.s"
