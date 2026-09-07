//! ARMv6-M profile: Thumb-1 entry/return, PMSAv6 MPU and HardFault recovery.
use super::common_arm_m_profile::{
    decode_svc_immediate, ExceptionFrame, RedirectState, TargetAppEntry,
};
pub use super::common_arm_m_profile::{
    disable_interrupts, enable_interrupts, interrupts_restore, interrupts_save_and_disable,
};
use crate::core::mpu::{MpuAccess, MpuError, MpuPrivilege, MpuRegion, MpuRegionConfig, MpuResult};
use crate::core::syscall::{SyscallHandler, SyscallNumber};
use core::arch::global_asm;
use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};

const MAX_SYSCALL_COUNT: usize = 256;
const MPU_TYPE: *const u32 = 0xE000_ED90 as *const u32;
const MPU_CTRL: *mut u32 = 0xE000_ED94 as *mut u32;
const MPU_RNR: *mut u32 = 0xE000_ED98 as *mut u32;
const MPU_RBAR: *mut u32 = 0xE000_ED9C as *mut u32;
const MPU_RASR: *mut u32 = 0xE000_EDA0 as *mut u32;

const MPU_CTRL_ENABLE: u32 = 1 << 0;
const MPU_CTRL_PRIVDEFENA: u32 = 1 << 2;
const MPU_RASR_ENABLE: u32 = 1 << 0;
const MPU_RASR_SIZE_SHIFT: u32 = 1;
const MPU_RASR_AP_SHIFT: u32 = 24;
const MPU_RASR_XN: u32 = 1 << 28;

const MPU_AP_NO_ACCESS: u32 = 0b000;
const MPU_AP_PRIVILEGED_RW: u32 = 0b001;
const MPU_AP_PRIVILEGED_RW_UNPRIVILEGED_RW: u32 = 0b011;
const MPU_AP_PRIVILEGED_RO: u32 = 0b101;
const MPU_AP_PRIVILEGED_RO_UNPRIVILEGED_RO: u32 = 0b110;

const MPU_MIN_REGION_SIZE: usize = 32;
const MPU_REGION_COUNT_MASK: u32 = 0xff;
const MPU_REGION_COUNT_SHIFT: u32 = 8;
const ARMV6M_SOFT_MEMFAULT_STATUS: u32 = 1 << 8;
const ARMV6M_SOFT_MEMFAULT_FROM_PSP: u32 = 1 << 9;
const KERNEL_STACK_GUARD_REGION: MpuRegion = 7;
const KERNEL_STACK_GUARD_SIZE: usize = MPU_MIN_REGION_SIZE;
const KERNEL_STATIC_BASE: usize = crate::core::target::FAE_STATIC_BASE;
const APP_GATE_REGION_SIZE: usize = crate::core::isolation::APP_GATE_REGION_SIZE;
const APP_GATE_AREA_OFFSET: usize = APP_GATE_REGION_SIZE - (APP_ENTRY_GATE_INSTRUCTIONS.len() * 2);
const APP_ENTRY_GATE_INSTRUCTIONS: [u16; 5] = [0xf384, 0x8814, 0xf3bf, 0x8f6f, 0x4728];

static mut INITIALIZED: bool = false;
static mut SYSCALL_TABLE: [Option<SyscallHandler>; MAX_SYSCALL_COUNT] = [None; MAX_SYSCALL_COUNT];
static mut PENDING_REDIRECT: Option<RedirectState> = None;
static mut APP_GATE_REGION_STORAGE: [u8; APP_GATE_REGION_SIZE * 2] = [0; APP_GATE_REGION_SIZE * 2];
static mut LAST_SOFT_MEMFAULT_STATUS: u32 = 0;
static mut LAST_SOFT_MEMFAULT_ADDRESS: u32 = 0;
static mut LAST_SOFT_MEMFAULT_STACKED_PC: u32 = 0;
static mut LAST_SOFT_MEMFAULT_STACKED_LR: u32 = 0;
static mut KERNEL_STACK_GUARD_TEST_ACTIVE: u32 = 0;

global_asm!(
    r#"
    .syntax unified
    .arch armv6s-m
    .thumb

    .global gpos_core_resume_isolated_app_ptr
    .type gpos_core_resume_isolated_app_ptr, %function
    .thumb_func
gpos_core_resume_isolated_app_ptr:
    ldr     r0, =gpos_core_armv6m_resume_isolated_app
    movs    r1, #1
    orrs    r0, r1
    bx      lr

    .global gpos_core_periodic_timer_interrupt_handler
    .type gpos_core_periodic_timer_interrupt_handler, %function
    .thumb_func
gpos_core_periodic_timer_interrupt_handler:
    push    {{r4-r7, lr}}
    mov     r6, r9
    mov     r7, r10
    ldr     r5, ={kernel_static_base}
    mov     r9, r5
    mov     r10, r5
    bl      gpos_core_isolation_enter_kernel_execution
    mov     r4, r0
    bl      gpos_core_periodic_timer_interrupt_dispatch
    sub     sp, sp, #12
    mov     r0, sp
    bl      gpos_core_armv6m_svcall_take_redirect
    cmp     r0, #0
    bne     8f
    cmp     r4, #0
    beq     9f
    bl      gpos_core_isolation_resume_rustlet_execution
9:
    add     sp, sp, #12
    mov     r9, r6
    mov     r10, r7
    pop     {{r4-r7}}
    pop     {{r3}}
    mov     lr, r3
    bx      lr
8:
    ldr     r0, [sp, #0]
    ldr     r1, [sp, #4]
    ldr     r2, [sp, #8]
    add     sp, sp, #12
    pop     {{r4-r7}}
    pop     {{r3}}
    mov     lr, r3
    b       gpos_core_armv6m_resume_with_redirect

    .global gpos_core_armv6m_svcall_handler
    .type gpos_core_armv6m_svcall_handler, %function
    .thumb_func
gpos_core_armv6m_svcall_handler:
    mov     r0, lr
    movs    r1, #4
    tst     r0, r1
    beq     1f
    mrs     r0, psp
    b       2f
1:
    mrs     r0, msp
2:
    push    {{r4-r7, lr}}
    mov     r4, r0
    mov     r6, r9
    mov     r7, r10
    ldr     r5, ={kernel_static_base}
    mov     r9, r5
    mov     r10, r5
    bl      gpos_core_isolation_enter_kernel_execution
    mov     r0, r4
    bl      gpos_core_armv6m_svcall_dispatch
    str     r0, [r4, #0]
    sub     sp, sp, #12
    mov     r0, sp
    bl      gpos_core_armv6m_svcall_take_redirect
    cmp     r0, #0
    beq     3f
    ldr     r0, [sp, #0]
    ldr     r1, [sp, #4]
    ldr     r2, [sp, #8]
    add     sp, sp, #12
    pop     {{r4-r7}}
    pop     {{r3}}
    mov     lr, r3
    b       gpos_core_armv6m_resume_with_redirect
3:
    add     sp, sp, #12
    bl      gpos_core_isolation_resume_rustlet_execution
    mov     r9, r6
    mov     r10, r7
    pop     {{r4-r7}}
    pop     {{r3}}
    mov     lr, r3
    bx      lr

    .global gpos_core_armv6m_hardfault_handler
    .type gpos_core_armv6m_hardfault_handler, %function
    .thumb_func
gpos_core_armv6m_hardfault_handler:
    mov     r0, lr
    movs    r1, #4
    tst     r0, r1
    beq     1f
    mrs     r2, psp
    movs    r1, #1
    b       2f
1:
    mrs     r2, msp
    movs    r1, #0
2:
    push    {{r4-r7, lr}}
    mov     r4, r1
    mov     r5, r2
    mov     r6, r9
    mov     r7, r10
    ldr     r2, ={kernel_static_base}
    mov     r9, r2
    mov     r10, r2
    bl      gpos_core_isolation_enter_kernel_execution
    mov     r1, r4
    mov     r2, r5
    bl      gpos_core_armv6m_hardfault_dispatch
    sub     sp, sp, #12
    mov     r0, sp
    bl      gpos_core_armv6m_svcall_take_redirect
    cmp     r0, #0
    beq     3f
    ldr     r0, [sp, #0]
    ldr     r1, [sp, #4]
    ldr     r2, [sp, #8]
    add     sp, sp, #12
    pop     {{r4-r7}}
    pop     {{r3}}
    mov     lr, r3
    b       gpos_core_armv6m_resume_with_redirect
3:
    add     sp, sp, #12
    mov     r9, r6
    mov     r10, r7
    pop     {{r4-r7}}
    pop     {{r3}}
    mov     lr, r3
    ldr     r0, =gpos_core_armv6m_hardfault_fatal
    movs    r1, #1
    orrs    r0, r1
    bx      r0

    .global gpos_core_armv6m_run_isolated_app
    .type gpos_core_armv6m_run_isolated_app, %function
    .thumb_func
gpos_core_armv6m_run_isolated_app:
    push    {{r4-r7, lr}}
    mov     r4, r8
    mov     r5, r9
    mov     r6, r10
    mov     r7, r11
    push    {{r4-r7}}
    sub     sp, sp, #4
    mov     r4, r0
    bl      gpos_core_isolation_enter_rustlet_execution
    ldr     r5, [r4, #0]
    ldr     r6, [r4, #4]
    ldr     r0, [r4, #8]
    ldr     r1, [r4, #12]
    ldr     r2, [r4, #16]
    ldr     r3, [r4, #20]
    ldr     r7, [r4, #24]
    msr     PSP, r7
    mov     r9, r6
    mov     r10, r6
    ldr     r7, [r4, #28]
    movs    r4, #3
    bx      r7

    .global gpos_core_armv6m_resume_isolated_app
    .type gpos_core_armv6m_resume_isolated_app, %function
    .thumb_func
gpos_core_armv6m_resume_isolated_app:
    mov     r4, r0
    mov     r5, r1
    bl      gpos_core_isolation_resume_cleanup
    mov     r0, r4
    mov     r1, r5
    add     sp, sp, #4
    pop     {{r4-r7}}
    mov     r8, r4
    mov     r9, r5
    mov     r10, r6
    mov     r11, r7
    pop     {{r4-r7, pc}}

    .global gpos_core_armv6m_resume_with_redirect
    .type gpos_core_armv6m_resume_with_redirect, %function
    .thumb_func
gpos_core_armv6m_resume_with_redirect:
    ldr     r3, ={kernel_static_base}
    mov     r9, r3
    mov     r10, r3
    movs    r3, #0
    msr     CONTROL, r3
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
    ldr     r0, =0xFFFFFFF9
    mov     lr, r0
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

    let registers = unsafe { gpos_core_armv6m_run_isolated_app(&entry) };
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

pub fn kernel_stack_guard_initialize() {
    if mpu_region_count() <= KERNEL_STACK_GUARD_REGION {
        return;
    }

    let guard_base = kernel_stack_guard_base();
    let result = mpu_set_region(
        KERNEL_STACK_GUARD_REGION,
        &MpuRegionConfig {
            base_addr: guard_base,
            size: KERNEL_STACK_GUARD_SIZE,
            access: MpuAccess::NoAccess,
            privilege: MpuPrivilege::PrivilegedOnly,
            executable: false,
        },
    )
    .and_then(|_| mpu_enable());

    if result.is_err() {
        crate::consoleln!(
            "kernel stack guard setup failed: base=0x{:08x} size={}",
            guard_base,
            KERNEL_STACK_GUARD_SIZE
        );
    }
}

/// ARMv6-M has no MSPLIM register.
pub fn kernel_stack_overflow_protection(_stack: crate::core::isolation::AppMemoryWindow) {}

/// ARMv6-M has no PSPLIM register.
pub fn app_stack_overflow_protection(_stack: Option<crate::core::isolation::AppMemoryWindow>) {}

#[inline(never)]
pub fn kernel_stack_guard_test_touch() {
    unsafe {
        write_volatile(addr_of_mut!(KERNEL_STACK_GUARD_TEST_ACTIVE), 1);
        write_volatile(kernel_stack_guard_base() as *mut u8, 0x5a);
        write_volatile(addr_of_mut!(KERNEL_STACK_GUARD_TEST_ACTIVE), 0);
    }
    crate::consoleln!("kernel stack guard test did not fault");
    crate::core::shutdown(1)
}

#[inline(never)]
pub fn kernel_ram_execute_never_test_touch() -> bool {
    if crate::core::target::kernel_ram_execute_never_windows()
        .iter()
        .all(Option::is_none)
    {
        return false;
    }

    #[repr(align(4))]
    struct RamCode([u16; 1]);

    static mut RAM_CODE: RamCode = RamCode([0]);

    // Invariant: this test runs in kernel phase, after MPU initialization, so
    // region 6 must carry the privileged RAM-XN mapping where the target
    // declares one. Executing this RAM-resident `BX LR` must fault.
    let addr = unsafe { addr_of_mut!(RAM_CODE.0) as usize | 1 };
    unsafe {
        write_volatile((addr & !1) as *mut u16, 0x4770);
        mpu_sync();
    }
    let f: extern "C" fn() = unsafe { core::mem::transmute(addr) };
    f();
    true
}

pub fn last_mem_manage_fault() -> Option<crate::core::isolation::MemoryFaultInfo> {
    let status = unsafe { read_volatile(addr_of!(LAST_SOFT_MEMFAULT_STATUS)) };
    if status == 0 {
        return None;
    }

    let address = unsafe { read_volatile(addr_of!(LAST_SOFT_MEMFAULT_ADDRESS)) };
    let stacked_pc = unsafe { read_volatile(addr_of!(LAST_SOFT_MEMFAULT_STACKED_PC)) };
    let stacked_lr = unsafe { read_volatile(addr_of!(LAST_SOFT_MEMFAULT_STACKED_LR)) };
    Some(crate::core::isolation::MemoryFaultInfo {
        status,
        address: if address == 0 {
            None
        } else {
            Some(address as usize)
        },
        hfsr: 0,
        cfsr: 0,
        mmfar: None,
        bfar: None,
        stacked_pc: if stacked_pc == 0 {
            None
        } else {
            Some(stacked_pc as usize)
        },
        stacked_lr: if stacked_lr == 0 {
            None
        } else {
            Some(stacked_lr as usize)
        },
    })
}

pub fn mpu_enable() -> MpuResult<()> {
    if mpu_region_count() == 0 {
        return Err(MpuError::Unsupported);
    }

    program_kernel_nx_regions()?;

    unsafe {
        write_volatile(MPU_CTRL, MPU_CTRL_ENABLE | MPU_CTRL_PRIVDEFENA);
        mpu_sync();
    }
    Ok(())
}

fn program_kernel_nx_regions() -> MpuResult<()> {
    super::common_arm_m_profile::program_kernel_nx_regions(
        &super::kernel_ram_execute_never_windows(),
        mpu_region_count(),
        mpu_set_region,
    )
}

pub fn mpu_disable() -> MpuResult<()> {
    if mpu_region_count() == 0 {
        return Err(MpuError::Unsupported);
    }

    unsafe {
        write_volatile(MPU_CTRL, 0);
        mpu_sync();
    }
    Ok(())
}

pub fn mpu_set_region(region: MpuRegion, config: &MpuRegionConfig) -> MpuResult<()> {
    validate_region(region)?;
    validate_region_config(config)?;

    let region_size_encoding = encode_region_size(config.size)?;
    let access_bits = encode_access_bits(config.access, config.privilege);

    let mut rasr = MPU_RASR_ENABLE | (region_size_encoding << MPU_RASR_SIZE_SHIFT);
    rasr |= access_bits << MPU_RASR_AP_SHIFT;

    if !config.executable {
        rasr |= MPU_RASR_XN;
    }

    // RNR selects the bank subsequently accessed through RBAR/RASR. Keep
    // that selector stable if the periodic interrupt also updates the MPU.
    let primask = interrupts_save_and_disable();
    unsafe {
        write_volatile(MPU_RNR, region as u32);
        write_volatile(MPU_RBAR, config.base_addr as u32);
        write_volatile(MPU_RASR, rasr);
        mpu_sync();
    }
    interrupts_restore(primask);
    Ok(())
}

pub fn mpu_unset_region(region: MpuRegion) -> MpuResult<()> {
    validate_region(region)?;

    let primask = interrupts_save_and_disable();
    unsafe {
        write_volatile(MPU_RNR, region as u32);
        write_volatile(MPU_RBAR, 0);
        write_volatile(MPU_RASR, 0);
        mpu_sync();
    }
    interrupts_restore(primask);
    Ok(())
}

pub fn protect_kernel_nx(enabled: bool) {
    let unset_kernel_nx_regions = || -> MpuResult<()> {
        for window in crate::core::target::kernel_ram_execute_never_windows()
            .iter()
            .flatten()
        {
            if mpu_region_count() > window.region {
                mpu_unset_region(window.region)?;
            }
        }
        Ok(())
    };
    let result = if enabled {
        program_kernel_nx_regions()
    } else {
        unset_kernel_nx_regions()
    };

    if result.is_err() {
        crate::consoleln!("kernel NX update failed: enabled={}", enabled);
    }
}

#[inline(always)]
pub unsafe fn mpu_set_region_executable_unchecked(region: MpuRegion, executable: bool) {
    let primask = interrupts_save_and_disable();
    write_volatile(MPU_RNR, region as u32);
    let mut rasr = read_volatile(MPU_RASR);
    if executable {
        rasr &= !MPU_RASR_XN;
    } else {
        rasr |= MPU_RASR_XN;
    }
    write_volatile(MPU_RASR, rasr);
    mpu_sync();
    interrupts_restore(primask);
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

fn set_soft_memfault(status: u32, address: Option<u32>, frame: Option<&ExceptionFrame>) {
    let stacked_pc = frame.map(|frame| frame.pc).unwrap_or(0);
    let stacked_lr = frame.map(|frame| frame.lr).unwrap_or(0);
    unsafe {
        write_volatile(addr_of_mut!(LAST_SOFT_MEMFAULT_STATUS), status);
        write_volatile(
            addr_of_mut!(LAST_SOFT_MEMFAULT_ADDRESS),
            address.unwrap_or(0),
        );
        write_volatile(addr_of_mut!(LAST_SOFT_MEMFAULT_STACKED_PC), stacked_pc);
        write_volatile(addr_of_mut!(LAST_SOFT_MEMFAULT_STACKED_LR), stacked_lr);
    }
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

#[unsafe(no_mangle)]
extern "C" fn gpos_core_armv6m_svcall_dispatch(frame: *const ExceptionFrame) -> u32 {
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
extern "C" fn gpos_core_armv6m_svcall_take_redirect(out: *mut RedirectState) -> u32 {
    let pending = pending_redirect();
    let Some(redirect) = pending else {
        return 0;
    };

    set_pending_redirect(None);
    unsafe { *out = redirect };

    1
}

#[unsafe(no_mangle)]
extern "C" fn gpos_core_armv6m_hardfault_dispatch(
    entered_kernel_from_rustlet: u32,
    used_psp: u32,
    frame: *const ExceptionFrame,
) {
    let mut status = ARMV6M_SOFT_MEMFAULT_STATUS;
    if used_psp != 0 {
        status |= ARMV6M_SOFT_MEMFAULT_FROM_PSP;
    }
    let frame = unsafe { frame.as_ref() };
    set_soft_memfault(status, None, frame);

    // ARMv6-M has no MemManage exception. A HardFault raised while the
    // isolation phase is Rustlet is the target backend's recoverable MPU-fault
    // path; other HardFaults remain fatal kernel/porting failures.
    if entered_kernel_from_rustlet == 0 || !crate::core::isolation::app_call_active() {
        gpos_core_armv6m_hardfault_fatal();
    }

    crate::core::isolation::handle_memory_fault();
}

#[unsafe(no_mangle)]
extern "C" fn gpos_core_armv6m_hardfault_fatal() -> ! {
    if kernel_stack_guard_test_active() {
        crate::consoleln!("kernel ARMv6-M HardFault: kernel stack overflow suspected");
        crate::core::shutdown(1);
    }

    if let Some(info) = last_mem_manage_fault() {
        let stacked_pc = info.stacked_pc.unwrap_or(0);
        let stacked_lr = info.stacked_lr.unwrap_or(0);
        crate::consoleln!(
            "fatal ARMv6-M HardFault: status=0x{:08x} hfsr=0x{:08x} cfsr=0x{:08x} mmfar=0x{:08x} bfar=0x{:08x} pc=0x{:08x} lr=0x{:08x}",
            info.status,
            info.hfsr,
            info.cfsr,
            info.mmfar.unwrap_or(0),
            info.bfar.unwrap_or(0),
            stacked_pc,
            stacked_lr
        );
    } else {
        crate::consoleln!("fatal ARMv6-M HardFault");
    }
    crate::core::shutdown(1)
}

fn mpu_region_count() -> u8 {
    unsafe { ((read_volatile(MPU_TYPE) >> MPU_REGION_COUNT_SHIFT) & MPU_REGION_COUNT_MASK) as u8 }
}

fn validate_region(region: MpuRegion) -> MpuResult<()> {
    if mpu_region_count() == 0 {
        return Err(MpuError::Unsupported);
    }
    if region >= mpu_region_count() {
        return Err(MpuError::InvalidRegion);
    }
    Ok(())
}

fn validate_region_config(config: &MpuRegionConfig) -> MpuResult<()> {
    if config.base_addr == 0 {
        return Err(MpuError::InvalidAddress);
    }
    if config.size < MPU_MIN_REGION_SIZE || !config.size.is_power_of_two() {
        return Err(MpuError::InvalidSize);
    }
    if config.base_addr % config.size != 0 {
        return Err(MpuError::UnalignedAddress);
    }
    Ok(())
}

fn encode_region_size(size: usize) -> MpuResult<u32> {
    if size < MPU_MIN_REGION_SIZE || !size.is_power_of_two() {
        return Err(MpuError::InvalidSize);
    }
    Ok(size.trailing_zeros() - 1)
}

fn encode_access_bits(access: MpuAccess, privilege: MpuPrivilege) -> u32 {
    match (access, privilege) {
        (MpuAccess::NoAccess, _) => MPU_AP_NO_ACCESS,
        (MpuAccess::ReadOnly, MpuPrivilege::PrivilegedOnly) => MPU_AP_PRIVILEGED_RO,
        (MpuAccess::ReadOnly, MpuPrivilege::Unprivileged) => MPU_AP_PRIVILEGED_RO_UNPRIVILEGED_RO,
        (MpuAccess::ReadWrite, MpuPrivilege::PrivilegedOnly) => MPU_AP_PRIVILEGED_RW,
        (MpuAccess::ReadWrite, MpuPrivilege::Unprivileged) => MPU_AP_PRIVILEGED_RW_UNPRIVILEGED_RW,
    }
}

fn kernel_stack_guard_base() -> usize {
    crate::core::target::kernel_stack_guard_window()
        .map(|(base, _)| base)
        .unwrap_or(0)
}

fn kernel_stack_guard_test_active() -> bool {
    unsafe { read_volatile(addr_of!(KERNEL_STACK_GUARD_TEST_ACTIVE)) != 0 }
}

#[inline(always)]
fn mpu_sync() {
    super::common_arm_m_profile::synchronize();
}

unsafe extern "C" {
    fn gpos_core_armv6m_run_isolated_app(entry: *const TargetAppEntry) -> u64;
}
