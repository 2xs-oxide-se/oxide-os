#[cfg(any(oxide_se_trace_semihosting, oxide_se_trace_jtag))]
use ::core::fmt::{self, Write};

const SYS_OPEN: u32 = 0x01;
const SYS_CLOSE: u32 = 0x02;
#[cfg_attr(test, allow(dead_code))]
const SYS_WRITEC: u32 = 0x03;
const SYS_READ: u32 = 0x06;
const OPEN_MODE_READ_BINARY: u32 = 1;

#[cfg(any(oxide_se_trace_semihosting, oxide_se_trace_jtag))]
struct DebugConsole;

#[cfg(any(oxide_se_trace_semihosting, oxide_se_trace_jtag))]
impl Write for DebugConsole {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        write_buffer(s.as_bytes());
        Ok(())
    }
}

#[cfg(any(oxide_se_trace_semihosting, oxide_se_trace_jtag))]
pub(crate) fn log(args: fmt::Arguments<'_>) {
    let mut console = DebugConsole;
    let _ = console.write_fmt(args);
}

#[cfg(any(oxide_se_trace_semihosting, oxide_se_trace_jtag))]
pub fn write_buffer(buf: &[u8]) {
    for &byte in buf {
        crate::core::target::debug_write_byte(byte);
    }
}

#[cfg_attr(test, allow(dead_code))]
pub(crate) fn write_byte(byte: u8) {
    unsafe {
        let _ = semihost_call(SYS_WRITEC, &byte as *const u8);
    }
}

pub fn fill_random(buf: &mut [u8]) -> crate::core::crypto::CryptoResult<()> {
    if buf.is_empty() {
        return Ok(());
    }

    let path = [
        b'/', b'd', b'e', b'v', b'/', b'u', b'r', b'a', b'n', b'd', b'o', b'm', 0,
    ];
    let handle = open_read_only(&path)?;
    let result = read_exact(handle, buf);
    let _ = close(handle);
    result
}

fn open_read_only(path: &[u8]) -> crate::core::crypto::CryptoResult<i32> {
    #[repr(C)]
    struct OpenBlock {
        path: *const u8,
        mode: u32,
        len: u32,
    }

    let block = OpenBlock {
        path: path.as_ptr(),
        mode: OPEN_MODE_READ_BINARY,
        len: (path.len() - 1) as u32,
    };

    let handle = unsafe { semihost_call(SYS_OPEN, &block as *const OpenBlock as *const u8) };
    if handle < 0 {
        return Err(crate::core::crypto::CryptoError::EntropyUnavailable);
    }

    Ok(handle)
}

fn read_exact(handle: i32, buf: &mut [u8]) -> crate::core::crypto::CryptoResult<()> {
    #[repr(C)]
    struct ReadBlock {
        handle: i32,
        buf: *mut u8,
        len: u32,
    }

    let block = ReadBlock {
        handle,
        buf: buf.as_mut_ptr(),
        len: buf.len() as u32,
    };

    let remaining = unsafe { semihost_call(SYS_READ, &block as *const ReadBlock as *const u8) };
    if remaining != 0 {
        return Err(crate::core::crypto::CryptoError::EntropyUnavailable);
    }

    Ok(())
}

fn close(handle: i32) -> crate::core::crypto::CryptoResult<()> {
    let result = unsafe { semihost_call(SYS_CLOSE, &handle as *const i32 as *const u8) };
    if result != 0 {
        return Err(crate::core::crypto::CryptoError::EntropyUnavailable);
    }

    Ok(())
}

#[cfg(target_arch = "arm")]
unsafe fn semihost_call(op: u32, arg: *const u8) -> i32 {
    let mut op_and_result = op as i32;
    ::core::arch::asm!(
        "bkpt 0xab",
        inlateout("r0") op_and_result,
        inlateout("r1") arg => _,
        options(nostack, preserves_flags),
    );
    op_and_result
}

#[cfg(not(target_arch = "arm"))]
unsafe fn semihost_call(_op: u32, _arg: *const u8) -> i32 {
    -1
}
