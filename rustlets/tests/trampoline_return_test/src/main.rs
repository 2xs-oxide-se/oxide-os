#![no_std]
#![no_main]

use core::arch::global_asm;
use core::panic::PanicInfo;

global_asm!(
    r#"
    .syntax unified
    .thumb

    .section .text.start, "ax", %progbits
    .global start
    .type start, %function
    .thumb_func
start:
    movs r0, #0
    bx lr
"#
);

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {}
}
