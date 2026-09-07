//! Exception entry/return shared by ARMv7-M and ARMv8-M Mainline.
//! ARMv6-M keeps its own instruction sequences and HardFault recovery path.
use super::{decode_svc_immediate, ExceptionFrame, RedirectState, TargetAppEntry};
use crate::core::syscall::{SyscallHandler, SyscallNumber};
use core::arch::global_asm;
use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};

const SCB_SHCSR: *mut u32 = 0xE000_ED24 as *mut u32;
const SCB_CFSR: *mut u32 = 0xE000_ED28 as *mut u32;
const SCB_HFSR: *const u32 = 0xE000_ED2C as *const u32;
const SCB_MMFAR: *const u32 = 0xE000_ED34 as *const u32;
const SCB_BFAR: *const u32 = 0xE000_ED38 as *const u32;
const MAX_SYSCALL_COUNT: usize = 256;
const SCB_SHCSR_MEMFAULTENA: u32 = 1 << 16;
const SCB_SHCSR_USGFAULTENA: u32 = 1 << 18;
const SCB_CFSR_MEMFAULT_MASK: u32 = 0xff;
const SCB_CFSR_USAGEFAULT_MASK: u32 = 0xffff_0000;
const SCB_CFSR_IACCVIOL: u32 = 1 << 0;
const SCB_CFSR_DACCVIOL: u32 = 1 << 1;
const SCB_CFSR_MUNSTKERR: u32 = 1 << 3;
const SCB_CFSR_MLSPERR: u32 = 1 << 5;
const SCB_CFSR_MMARVALID: u32 = 1 << 7;
const SCB_CFSR_BFARVALID: u32 = 1 << 15;
const SCB_CFSR_UNDEFINSTR: u32 = 1 << 16;
const SCB_CFSR_STKOF: u32 = 1 << 20;

const KERNEL_STATIC_BASE: usize = crate::core::target::FAE_STATIC_BASE;
const APP_GATE_REGION_SIZE: usize = crate::core::isolation::APP_GATE_REGION_SIZE;
const APP_GATE_AREA_OFFSET: usize = APP_GATE_REGION_SIZE - (APP_ENTRY_GATE_INSTRUCTIONS.len() * 2);
const APP_ENTRY_GATE_INSTRUCTIONS: [u16; 5] = [0xf384, 0x8814, 0xf3bf, 0x8f6f, 0x4728];

#[derive(Clone, Copy)]
struct MemManageFaultState {
    status: u32,
    address: u32,
    hfsr: u32,
    cfsr: u32,
    mmfar: u32,
    bfar: u32,
    stacked_pc: u32,
    stacked_lr: u32,
}

static mut INITIALIZED: bool = false;
static mut SYSCALL_TABLE: [Option<SyscallHandler>; MAX_SYSCALL_COUNT] = [None; MAX_SYSCALL_COUNT];
static mut APP_GATE_REGION_STORAGE: [u8; APP_GATE_REGION_SIZE * 2] = [0; APP_GATE_REGION_SIZE * 2];
static mut PENDING_REDIRECT: Option<RedirectState> = None;
static mut LAST_MEM_MANAGE_STATUS: u32 = 0;
static mut LAST_MEM_MANAGE_ADDRESS: u32 = 0;
static mut LAST_MEM_MANAGE_HFSR: u32 = 0;
static mut LAST_MEM_MANAGE_CFSR: u32 = 0;
static mut LAST_MEM_MANAGE_MMFAR: u32 = 0;
static mut LAST_MEM_MANAGE_BFAR: u32 = 0;
static mut LAST_MEM_MANAGE_STACKED_PC: u32 = 0;
static mut LAST_MEM_MANAGE_STACKED_LR: u32 = 0;

global_asm!(
    r#"
    .syntax unified
    .thumb

    .global gpos_core_svcall_handler_ptr
    .type gpos_core_svcall_handler_ptr, %function
    .thumb_func
gpos_core_svcall_handler_ptr:
    adr     r0, gpos_core_svcall_handler
    orr.w   r0, r0, #1
    bx      lr

    .global gpos_core_resume_isolated_app_ptr
    .type gpos_core_resume_isolated_app_ptr, %function
    .thumb_func
gpos_core_resume_isolated_app_ptr:
    adr     r0, gpos_core_resume_isolated_app
    orr.w   r0, r0, #1
    bx      lr

    .global gpos_core_mem_manage_handler_ptr
    .type gpos_core_mem_manage_handler_ptr, %function
    .thumb_func
gpos_core_mem_manage_handler_ptr:
    adr     r0, gpos_core_mem_manage_handler
    orr.w   r0, r0, #1
    bx      lr

    .global gpos_core_usage_fault_handler_ptr
    .type gpos_core_usage_fault_handler_ptr, %function
    .thumb_func
gpos_core_usage_fault_handler_ptr:
    adr     r0, gpos_core_usage_fault_handler
    orr.w   r0, r0, #1
    bx      lr

    .global gpos_core_periodic_timer_interrupt_handler
    .type gpos_core_periodic_timer_interrupt_handler, %function
    .global gpos_core_periodic_timer_interrupt_handler_ptr
    .type gpos_core_periodic_timer_interrupt_handler_ptr, %function
    .thumb_func
gpos_core_periodic_timer_interrupt_handler_ptr:
    adr     r0, gpos_core_periodic_timer_interrupt_handler
    orr.w   r0, r0, #1
    bx      lr

    .thumb_func
gpos_core_periodic_timer_interrupt_handler:
    push    {{r4-r11, lr}}
    ldr     r9, ={kernel_static_base}
    mov     r10, r9
    bl      gpos_core_isolation_enter_kernel_execution
    mov     r4, r0
    bl      gpos_core_periodic_timer_interrupt_dispatch
    sub     sp, sp, #12
    mov     r0, sp
    bl      gpos_core_svcall_take_redirect
    cmp     r0, #0
    bne     8f
    cmp     r4, #0
    beq     9f
    bl      gpos_core_isolation_resume_rustlet_execution
9:
    add     sp, sp, #12
    pop     {{r4-r11, lr}}
    bx      lr
8:
    ldr     r0, [sp, #0]
    ldr     r1, [sp, #4]
    ldr     r2, [sp, #8]
    add     sp, sp, #12
    pop     {{r4-r11, lr}}
    b       gpos_core_resume_with_redirect

    .global gpos_core_svcall_handler
    .type gpos_core_svcall_handler, %function
    .thumb_func
gpos_core_svcall_handler:
    tst     lr, #4
    ite     eq
    mrseq   r0, msp
    mrsne   r0, psp
    push    {{r4, r6, r7, lr}}
    mov     r4, r0
    mov     r6, r9
    mov     r7, r10
    ldr     r9, ={kernel_static_base}
    mov     r10, r9
    bl      gpos_core_isolation_enter_kernel_execution
    mov     r0, r4
    bl      gpos_core_svcall_dispatch
    str     r0, [r4, #0]
    sub     sp, sp, #12
    mov     r0, sp
    bl      gpos_core_svcall_take_redirect
    cmp     r0, #0
    beq     1f
    ldr     r1, [sp, #0]
    ldr     r2, [sp, #4]
    ldr     r3, [sp, #8]
    mov     r0, r4
    bl      gpos_core_svcall_try_inline_redirect
    cmp     r0, #0
    beq     2f
    mov     r9, r6
    mov     r10, r7
    add     sp, sp, #12
    pop     {{r4, r6, r7, lr}}
    bx      lr
2:
    ldr     r0, [sp, #0]
    ldr     r1, [sp, #4]
    ldr     r2, [sp, #8]
    add     sp, sp, #12
    pop     {{r4, r6, r7, lr}}
    b       gpos_core_resume_with_redirect
1:
    bl      gpos_core_isolation_resume_rustlet_execution
    mov     r9, r6
    mov     r10, r7
    add     sp, sp, #12
    pop     {{r4, r6, r7, lr}}
    bx      lr

    .global gpos_core_run_isolated_app
    .type gpos_core_run_isolated_app, %function
    .thumb_func
gpos_core_run_isolated_app:
    push    {{r4-r11, lr}}
    sub     sp, sp, #4
    mov     r4, r0
    bl      gpos_core_isolation_enter_rustlet_execution
    ldr     r5, [r4, #0]
    ldr     r6, [r4, #4]
    ldr     r0, [r4, #8]
    ldr     r1, [r4, #12]
    ldr     r2, [r4, #16]
    ldr     r3, [r4, #20]
    ldr     r8, [r4, #24]
    ldr     r7, [r4, #28]
    msr     PSP, r8
    mov     r9, r6
    orr.w   r5, r5, #1
    movs    r4, #3
    bx      r7

    .global gpos_core_resume_isolated_app
    .type gpos_core_resume_isolated_app, %function
    .thumb_func
gpos_core_resume_isolated_app:
    mov     r4, r0
    mov     r5, r1
    bl      gpos_core_isolation_resume_cleanup
    mov     r0, r4
    mov     r1, r5
    add     sp, sp, #4
    pop     {{r4-r11, pc}}

    .global gpos_core_mem_manage_handler
    .type gpos_core_mem_manage_handler, %function
    .thumb_func
gpos_core_mem_manage_handler:
    tst     lr, #4
    ite     eq
    mrseq   r4, msp
    mrsne   r4, psp
    mov     r5, lr
    push    {{r4-r11, lr}}
    ldr     r9, ={kernel_static_base}
    mov     r10, r9
    bl      gpos_core_isolation_enter_kernel_execution
    mov     r1, r4
    mov     r2, r5
    bl      gpos_core_mem_manage_dispatch
    sub     sp, sp, #12
    mov     r0, sp
    bl      gpos_core_svcall_take_redirect
    cmp     r0, #0
    beq     2f
    ldr     r0, [sp, #0]
    ldr     r1, [sp, #4]
    ldr     r2, [sp, #8]
    add     sp, sp, #12
    pop     {{r4-r11, lr}}
    b       gpos_core_resume_with_redirect
2:
    add     sp, sp, #12
    pop     {{r4-r11, lr}}
    bl      gpos_core_mem_manage_fatal

    .global gpos_core_usage_fault_handler
    .type gpos_core_usage_fault_handler, %function
    .thumb_func
gpos_core_usage_fault_handler:
    tst     lr, #4
    ite     eq
    mrseq   r4, msp
    mrsne   r4, psp
    mov     r5, lr
    push    {{r4-r11, lr}}
    ldr     r9, ={kernel_static_base}
    mov     r10, r9
    bl      gpos_core_isolation_enter_kernel_execution
    mov     r1, r4
    mov     r2, r5
    bl      gpos_core_usage_fault_dispatch
    sub     sp, sp, #12
    mov     r0, sp
    bl      gpos_core_svcall_take_redirect
    cmp     r0, #0
    beq     3f
    ldr     r0, [sp, #0]
    ldr     r1, [sp, #4]
    ldr     r2, [sp, #8]
    add     sp, sp, #12
    pop     {{r4-r11, lr}}
    b       gpos_core_resume_with_redirect
3:
    add     sp, sp, #12
    pop     {{r4-r11, lr}}
    bl      gpos_core_usage_fault_fatal

    .global gpos_core_resume_with_redirect
    .type gpos_core_resume_with_redirect, %function
    .thumb_func
gpos_core_resume_with_redirect:
    ldr     r9, ={kernel_static_base}
    mov     r10, r9
    movs    r3, #0
    msr     control, r3
    isb
    sub     sp, sp, #32
    str     r0, [sp, #0]
    str     r1, [sp, #4]
    str     r3, [sp, #8]
    str     r3, [sp, #12]
    str     r3, [sp, #16]
    str     r3, [sp, #20]
    str     r2, [sp, #24]
    ldr     r0, =0x01000000
    str     r0, [sp, #28]
    ldr     lr, =0xFFFFFFF9
    bx      lr
"#,
    kernel_static_base = const KERNEL_STATIC_BASE,
);

pub fn syscall_initialize() {
    if initialized() {
        return;
    }

    set_initialized(true);
    unsafe {
        initialize_app_gates();
        initialize_boot_exception_forwarding();
    }
}

pub fn install_syscall_handler(number: SyscallNumber, handler: SyscallHandler) {
    set_syscall_handler(number, handler);
}

pub fn syscall_table_debug_addr() -> usize {
    core::ptr::addr_of!(SYSCALL_TABLE) as usize
}

pub fn syscall_handler_debug_addr(number: SyscallNumber) -> usize {
    syscall_handler(number)
        .map(|handler| handler as usize)
        .unwrap_or(0)
}

pub fn request_syscall_thread_redirect(pc: usize, r0: usize, r1: usize) {
    set_pending_redirect(Some(RedirectState {
        r0: r0 as u32,
        r1: r1 as u32,
        // Exception-return frames carry Thumb state in xPSR.T; stacked PC
        // itself must remain halfword-aligned.
        pc: (pc & !1) as u32,
    }));
}

pub fn run_isolated_app(
    entry_pc: usize,
    app_gp: usize,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    stack_top: usize,
) -> Option<crate::core::isolation::AppReturnRegisters> {
    if entry_pc > u32::MAX as usize
        || app_gp > u32::MAX as usize
        || arg0 > u32::MAX as usize
        || arg1 > u32::MAX as usize
        || arg2 > u32::MAX as usize
        || arg3 > u32::MAX as usize
        || stack_top > u32::MAX as usize
    {
        return None;
    }

    // Invariant: the shared app gate is app-writable and executable only as a
    // tiny trampoline into the selected FAE entry point. Rewrite it before
    // every app entry so one Rustlet cannot corrupt the gate later used by
    // another Rustlet.
    unsafe {
        initialize_app_gates();
    }

    let gate_region = isolated_app_gate_region()?;

    let entry = TargetAppEntry {
        entry_pc: entry_pc as u32,
        app_gp: app_gp as u32,
        arg0: arg0 as u32,
        arg1: arg1 as u32,
        arg2: arg2 as u32,
        arg3: arg3 as u32,
        stack_top: stack_top as u32,
        entry_gate_pc: gate_region.entry_pc as u32,
    };

    let registers = unsafe { gpos_core_run_isolated_app(&entry) };
    Some(crate::core::isolation::AppReturnRegisters {
        r0: registers as u32 as usize,
        r1: (registers >> 32) as u32 as usize,
    })
}

pub fn isolated_app_gate_region() -> Option<crate::core::target::AppGateRegion> {
    let base = unsafe { aligned_app_gate_region() as usize };
    let entry_pc = ((unsafe { aligned_app_entry_gate() } as usize) | 1) as usize;

    Some(crate::core::target::AppGateRegion {
        base,
        size: APP_GATE_REGION_SIZE,
        entry_pc,
    })
}

pub fn last_mem_manage_fault() -> Option<crate::core::isolation::MemoryFaultInfo> {
    let fault = mem_manage_fault_state();
    if fault.status == 0 {
        return None;
    }

    let address = if fault.status & SCB_CFSR_MMARVALID != 0 {
        Some(fault.address as usize)
    } else {
        None
    };

    Some(crate::core::isolation::MemoryFaultInfo {
        status: fault.status,
        address,
        hfsr: fault.hfsr,
        cfsr: fault.cfsr,
        mmfar: if fault.cfsr & SCB_CFSR_MMARVALID != 0 {
            Some(fault.mmfar as usize)
        } else {
            None
        },
        bfar: if fault.cfsr & SCB_CFSR_BFARVALID != 0 {
            Some(fault.bfar as usize)
        } else {
            None
        },
        stacked_pc: if fault.stacked_pc == 0 {
            None
        } else {
            Some(fault.stacked_pc as usize)
        },
        stacked_lr: if fault.stacked_lr == 0 {
            None
        } else {
            Some(fault.stacked_lr as usize)
        },
    })
}

#[unsafe(no_mangle)]
extern "C" fn gpos_core_svcall_dispatch(frame: *const ExceptionFrame) -> u32 {
    let frame = unsafe { &*frame };
    let syscall_number = decode_svc_immediate(frame.pc as usize);
    let handler = syscall_handler(syscall_number);

    let Some(handler) = handler else {
        crate::consoleln!(
            "svc dispatch missing number={} table=0x{:08x} svc1=0x{:08x}",
            syscall_number,
            syscall_table_debug_addr(),
            syscall_handler_debug_addr(rustlet_runtime::syscall_abi::RETURN_TO_KERNEL)
        );
        panic!("unhandled syscall {}", syscall_number);
    };

    unsafe {
        handler(
            frame.r0 as usize,
            frame.r1 as usize,
            frame.r2 as usize,
            frame.r3 as usize,
        ) as u32
    }
}

#[unsafe(no_mangle)]
extern "C" fn gpos_core_mem_manage_dispatch(
    fault_originated_in_rustlet: u32,
    frame: *const ExceptionFrame,
    _exc_return: u32,
) {
    let frame = unsafe { &*frame };
    let status = unsafe { read_volatile(SCB_CFSR) & SCB_CFSR_MEMFAULT_MASK };
    let cfsr = unsafe { read_volatile(SCB_CFSR) };
    let hfsr = unsafe { read_volatile(SCB_HFSR) };
    let address = if status & SCB_CFSR_MMARVALID != 0 {
        unsafe { read_volatile(SCB_MMFAR) }
    } else {
        0
    };
    let mmfar = if cfsr & SCB_CFSR_MMARVALID != 0 {
        unsafe { read_volatile(SCB_MMFAR) }
    } else {
        0
    };
    let bfar = if cfsr & SCB_CFSR_BFARVALID != 0 {
        unsafe { read_volatile(SCB_BFAR) }
    } else {
        0
    };

    set_mem_manage_fault_state(MemManageFaultState {
        status,
        address,
        hfsr,
        cfsr,
        mmfar,
        bfar,
        stacked_pc: frame.pc,
        stacked_lr: frame.lr,
    });
    unsafe { write_volatile(SCB_CFSR, SCB_CFSR_MEMFAULT_MASK) };

    if kernel_stack_guard_contains(address as usize) {
        crate::consoleln!(
            "kernel MemManage: kernel stack overflow suspected hfsr=0x{:08x} cfsr=0x{:08x} mmfar=0x{:08x} pc=0x{:08x} lr=0x{:08x}",
            hfsr,
            cfsr,
            address,
            frame.pc,
            frame.lr
        );
        crate::core::shutdown(1);
    }

    let recoverable_mask = SCB_CFSR_IACCVIOL | SCB_CFSR_DACCVIOL;
    let fatal_mask = SCB_CFSR_MUNSTKERR | SCB_CFSR_MLSPERR;

    if status & fatal_mask != 0 || status & recoverable_mask == 0 {
        gpos_core_mem_manage_fatal();
    }

    if fault_originated_in_rustlet == 0 || !crate::core::isolation::app_call_active() {
        gpos_core_mem_manage_fatal();
    }

    crate::core::isolation::handle_memory_fault();
}

#[unsafe(no_mangle)]
extern "C" fn gpos_core_mem_manage_fatal() -> ! {
    let Some(info) = last_mem_manage_fault() else {
        crate::consoleln!("fatal MemManage");
        crate::core::shutdown(1)
    };

    let mmfar = info.mmfar.unwrap_or(0);
    let bfar = info.bfar.unwrap_or(0);
    let stacked_pc = info.stacked_pc.unwrap_or(0);
    let stacked_lr = info.stacked_lr.unwrap_or(0);
    crate::consoleln!(
        "fatal MemManage: status=0x{:08x} hfsr=0x{:08x} cfsr=0x{:08x} mmfar=0x{:08x} bfar=0x{:08x} pc=0x{:08x} lr=0x{:08x}",
        info.status,
        info.hfsr,
        info.cfsr,
        mmfar,
        bfar,
        stacked_pc,
        stacked_lr
    );

    crate::core::shutdown(1)
}

/// Terminates an isolated Rustlet on an undefined instruction or ARMv8-M
/// process-stack overflow, using the saved kernel return context.
///
/// Stack-limit faults can leave an incomplete exception frame (Armv8-M ARM,
/// B3.21). Never dereference that frame or attempt to resume the failed PSP.
#[unsafe(no_mangle)]
extern "C" fn gpos_core_usage_fault_dispatch(
    fault_originated_in_rustlet: u32,
    frame: *const ExceptionFrame,
    exc_return: u32,
) {
    let cfsr = unsafe { read_volatile(SCB_CFSR) };
    let hfsr = unsafe { read_volatile(SCB_HFSR) };
    let status = cfsr & SCB_CFSR_USAGEFAULT_MASK;
    let (stacked_pc, stacked_lr) = if status & SCB_CFSR_STKOF != 0 {
        // STKOF can suppress exception stacking. Zero means unavailable in
        // MemoryFaultInfo, not a fabricated PC/LR read from application data.
        (0, 0)
    } else {
        let frame = unsafe { &*frame };
        (frame.pc, frame.lr)
    };
    let mmfar = if cfsr & SCB_CFSR_MMARVALID != 0 {
        unsafe { read_volatile(SCB_MMFAR) }
    } else {
        0
    };
    let bfar = if cfsr & SCB_CFSR_BFARVALID != 0 {
        unsafe { read_volatile(SCB_BFAR) }
    } else {
        0
    };

    set_mem_manage_fault_state(MemManageFaultState {
        status,
        address: 0,
        hfsr,
        cfsr,
        mmfar,
        bfar,
        stacked_pc,
        stacked_lr,
    });
    unsafe { write_volatile(SCB_CFSR, SCB_CFSR_USAGEFAULT_MASK) };

    // Invariant: only a pure ARMv8-M STKOF from Thread mode on PSP can use
    // this recovery. MSP/kernel faults and combined fault causes stay fatal.
    // The existing redirect constructs a new frame on MSP; cleanup then
    // clears PSPLIM. Neither the failed instruction nor its PSP is resumed.
    let process_stack_overflow = cfg!(oxide_se_target_has_stack_limits)
        && cfsr == SCB_CFSR_STKOF
        && hfsr == 0
        && exc_return & 0x0c == 0x0c;
    let undefined_instruction = status & SCB_CFSR_UNDEFINSTR != 0 && status & SCB_CFSR_STKOF == 0;
    if !undefined_instruction && !process_stack_overflow {
        gpos_core_usage_fault_fatal();
    }
    if fault_originated_in_rustlet == 0 || !crate::core::isolation::app_call_active() {
        gpos_core_usage_fault_fatal();
    }

    crate::core::isolation::handle_memory_fault();
}

#[unsafe(no_mangle)]
extern "C" fn gpos_core_usage_fault_fatal() -> ! {
    let Some(info) = last_mem_manage_fault() else {
        crate::consoleln!("fatal UsageFault");
        crate::core::shutdown(1)
    };

    crate::consoleln!(
        "fatal UsageFault: status=0x{:08x} hfsr=0x{:08x} cfsr=0x{:08x} mmfar=0x{:08x} bfar=0x{:08x} pc=0x{:08x} lr=0x{:08x}",
        info.status,
        info.hfsr,
        info.cfsr,
        info.mmfar.unwrap_or(0),
        info.bfar.unwrap_or(0),
        info.stacked_pc.unwrap_or(0),
        info.stacked_lr.unwrap_or(0)
    );
    crate::core::shutdown(1)
}

#[unsafe(no_mangle)]
extern "C" fn gpos_core_svcall_take_redirect(out: *mut RedirectState) -> u32 {
    let pending = pending_redirect();
    let Some(redirect) = pending else {
        return 0;
    };

    set_pending_redirect(None);
    unsafe { *out = redirect };

    1
}

#[unsafe(no_mangle)]
extern "C" fn gpos_core_svcall_try_inline_redirect(
    frame: *mut ExceptionFrame,
    r0: u32,
    r1: u32,
    pc: u32,
) -> u32 {
    let frame = unsafe { &mut *frame };
    let syscall_number = decode_svc_immediate(frame.pc as usize);
    if syscall_number != rustlet_runtime::syscall_abi::ENTER_APP {
        return 0;
    }

    frame.r0 = r0;
    frame.r1 = r1;
    frame.pc = pc;
    1
}

unsafe fn initialize_boot_exception_forwarding() {
    let Some(boot_abi) = crate::core::target::boot_abi_region() else {
        return;
    };

    write_volatile(
        boot_abi.svc_forward as *mut u32,
        gpos_core_svcall_handler_ptr() as usize as u32,
    );
    write_volatile(
        boot_abi.memmanage_forward as *mut u32,
        gpos_core_mem_manage_handler_ptr() as usize as u32,
    );
    write_volatile(
        boot_abi.usagefault_forward as *mut u32,
        gpos_core_usage_fault_handler_ptr() as usize as u32,
    );
    write_volatile(
        boot_abi.periodic_timer_forward as *mut u32,
        gpos_core_periodic_timer_interrupt_handler_ptr() as usize as u32,
    );
    write_volatile(
        SCB_SHCSR,
        read_volatile(SCB_SHCSR) | SCB_SHCSR_MEMFAULTENA | SCB_SHCSR_USGFAULTENA,
    );
    core::arch::asm!("dsb", "isb", options(nostack, preserves_flags));
}

unsafe fn aligned_app_entry_gate() -> *mut u16 {
    aligned_app_gate_region().add(APP_GATE_AREA_OFFSET) as *mut u16
}

unsafe fn aligned_app_gate_region() -> *mut u8 {
    let base =
        addr_of_mut!(APP_GATE_REGION_STORAGE) as *mut [u8; APP_GATE_REGION_SIZE * 2] as usize;
    let aligned = (base + (APP_GATE_REGION_SIZE - 1)) & !(APP_GATE_REGION_SIZE - 1);
    aligned as *mut u8
}

unsafe fn initialize_app_gates() {
    let entry_gate = aligned_app_entry_gate();
    for (index, instruction) in APP_ENTRY_GATE_INSTRUCTIONS.iter().enumerate() {
        write_volatile(entry_gate.add(index), *instruction);
    }
}

fn initialized() -> bool {
    unsafe { read_volatile(addr_of!(INITIALIZED)) }
}

fn set_initialized(value: bool) {
    unsafe {
        write_volatile(addr_of_mut!(INITIALIZED), value);
    }
}

fn syscall_handler(number: SyscallNumber) -> Option<SyscallHandler> {
    unsafe {
        let table = addr_of!(SYSCALL_TABLE) as *const Option<SyscallHandler>;
        read_volatile(table.add(number as usize))
    }
}

fn set_syscall_handler(number: SyscallNumber, handler: SyscallHandler) {
    unsafe {
        let table = addr_of_mut!(SYSCALL_TABLE) as *mut Option<SyscallHandler>;
        write_volatile(table.add(number as usize), Some(handler));
    }
}

fn pending_redirect() -> Option<RedirectState> {
    unsafe { read_volatile(addr_of!(PENDING_REDIRECT)) }
}

fn set_pending_redirect(redirect: Option<RedirectState>) {
    unsafe {
        write_volatile(addr_of_mut!(PENDING_REDIRECT), redirect);
    }
}

fn mem_manage_fault_state() -> MemManageFaultState {
    let status = unsafe { read_volatile(addr_of!(LAST_MEM_MANAGE_STATUS)) };
    let address = unsafe { read_volatile(addr_of!(LAST_MEM_MANAGE_ADDRESS)) };
    let hfsr = unsafe { read_volatile(addr_of!(LAST_MEM_MANAGE_HFSR)) };
    let cfsr = unsafe { read_volatile(addr_of!(LAST_MEM_MANAGE_CFSR)) };
    let mmfar = unsafe { read_volatile(addr_of!(LAST_MEM_MANAGE_MMFAR)) };
    let bfar = unsafe { read_volatile(addr_of!(LAST_MEM_MANAGE_BFAR)) };
    let stacked_pc = unsafe { read_volatile(addr_of!(LAST_MEM_MANAGE_STACKED_PC)) };
    let stacked_lr = unsafe { read_volatile(addr_of!(LAST_MEM_MANAGE_STACKED_LR)) };
    MemManageFaultState {
        status,
        address,
        hfsr,
        cfsr,
        mmfar,
        bfar,
        stacked_pc,
        stacked_lr,
    }
}

fn set_mem_manage_fault_state(fault: MemManageFaultState) {
    unsafe {
        write_volatile(addr_of_mut!(LAST_MEM_MANAGE_STATUS), fault.status);
        write_volatile(addr_of_mut!(LAST_MEM_MANAGE_ADDRESS), fault.address);
        write_volatile(addr_of_mut!(LAST_MEM_MANAGE_HFSR), fault.hfsr);
        write_volatile(addr_of_mut!(LAST_MEM_MANAGE_CFSR), fault.cfsr);
        write_volatile(addr_of_mut!(LAST_MEM_MANAGE_MMFAR), fault.mmfar);
        write_volatile(addr_of_mut!(LAST_MEM_MANAGE_BFAR), fault.bfar);
        write_volatile(addr_of_mut!(LAST_MEM_MANAGE_STACKED_PC), fault.stacked_pc);
        write_volatile(addr_of_mut!(LAST_MEM_MANAGE_STACKED_LR), fault.stacked_lr);
    }
}

fn kernel_stack_guard_contains(address: usize) -> bool {
    let Some((base, size)) = crate::core::target::kernel_stack_guard_window() else {
        return false;
    };

    address >= base && address < base + size
}
unsafe extern "C" {
    fn gpos_core_svcall_handler_ptr() -> *const ();
    fn gpos_core_run_isolated_app(entry: *const TargetAppEntry) -> u64;
    fn gpos_core_mem_manage_handler_ptr() -> *const ();
    fn gpos_core_usage_fault_handler_ptr() -> *const ();
    fn gpos_core_periodic_timer_interrupt_handler_ptr() -> *const ();
}
