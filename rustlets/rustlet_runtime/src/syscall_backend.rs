#[cfg(target_arch = "arm")]
mod arm {
    /// Emit an SVC with arguments in `r0` and `r1`, returning `r0`.
    ///
    /// `r1` is currently clobbered and reserved for future two-word results.
    #[inline(always)]
    pub fn svc_2<const NUMBER: u8>(arg0: usize, arg1: usize) -> usize {
        let result: usize;
        unsafe {
            core::arch::asm!(
                "svc {number}",
                number = const NUMBER,
                inlateout("r0") arg0 => result,
                inlateout("r1") arg1 => _,
                lateout("r2") _,
                lateout("r3") _,
                lateout("r12") _,
                options(nostack)
            );
        }
        result
    }

    /// Emit an SVC with arguments in `r0`, `r1`, and `r2`.
    ///
    /// Any register results are intentionally ignored by this helper.
    #[inline(always)]
    pub fn svc_3<const NUMBER: u8>(arg0: usize, arg1: usize, arg2: usize) {
        unsafe {
            core::arch::asm!(
                "svc {number}",
                number = const NUMBER,
                inlateout("r0") arg0 => _,
                inlateout("r1") arg1 => _,
                inlateout("r2") arg2 => _,
                lateout("r3") _,
                lateout("r12") _,
                options(nostack)
            );
        }
    }
}

#[cfg(not(target_arch = "arm"))]
mod arm {
    /// Host fallback for returning SVC helpers.
    pub fn svc_2<const NUMBER: u8>(_arg0: usize, _arg1: usize) -> usize {
        0
    }

    /// Host fallback for fire-and-forget SVC helpers.
    pub fn svc_3<const NUMBER: u8>(_arg0: usize, _arg1: usize, _arg2: usize) {}
}

pub use arm::{svc_2, svc_3};
