use core::alloc::Layout;
use core::marker::PhantomData;

use rustlet_runtime::{
    ApduStatus, RustletCtx, SEApdu, SelectedAppDescriptor, SelectedAppVtable,
    SelectedSecurityDomainVtable,
};

use crate::apdu_manager;

#[derive(Clone, Copy)]
struct AppInvocation {
    entry_pc: usize,
    arg0: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    kind: oxi_core::core::isolation::AppCallKind,
    fault_return_value: usize,
}

pub struct LoadedFae {
    pub app_gp: usize,
    pub entrypoint: usize,
    pub shared_buffer: SharedRustletCtx,
    pub memory_layout: oxi_core::core::isolation::AppMemoryLayout,
    pub data_window: oxi_core::core::isolation::AppMemoryWindow,
    pub stack_window: oxi_core::core::isolation::AppMemoryWindow,
    pub isolation_plan: oxi_core::core::isolation::IsolationPlan,
    profile_kind: FaeProfileKind,
    heap_window: Option<oxi_core::core::isolation::AppMemoryWindow>,
    ram_allocation: AppAllocation,
}

pub struct HandlerCallResult {
    pub status: ApduStatus,
    pub returned_normally: bool,
}

const FAE_MAGIC_NUMBER_AND_VERSION: u32 = 0xFAEC_0D10;
const FAE_ABI_DESCRIPTOR: u32 = 0xAC1D_A992;
const FAE_APPLICATION_PROFILE: u32 = 0xA99;
const FAE_SECURITY_DOMAIN_PROFILE: u32 = 0x5DC;
const FAE_MEMORY_UNIT: usize = 32;
const FAE_FOOTER_SIZE: usize = 28;
const FAE_FOOTER_MEMORY_REQUIREMENTS_OFFSET: isize = -28;
const FAE_FOOTER_PROFILE_OFFSET: isize = -24;
const FAE_FOOTER_CRC_OFFSET: isize = -20;
const FAE_FOOTER_EXTRA_FIELDS_OFFSET: isize = -16;
const FAE_FOOTER_ABI_OFFSET: isize = -12;
const FAE_FOOTER_ISA_OFFSET: isize = -8;
const FAE_FOOTER_MAGIC_OFFSET: isize = -4;
const FAE_STACK_SIZE: usize = oxi_core::core::isolation::APP_STACK_REGION_SIZE;

#[derive(Clone, Copy, PartialEq, Eq)]
enum FaeProfileKind {
    Application,
    SecurityDomain,
}

#[repr(C)]
struct ParsedFae {
    text_start: usize,
    text_len: usize,
    writable_len: usize,
    profile_kind: FaeProfileKind,
}

pub const APP_RAM_CAPACITY: usize = 8192;

struct AppAllocation {
    ptr: *mut u8,
    size: usize,
    align: usize,
}

struct ReservedAppMemory {
    allocation: AppAllocation,
    ram_size: usize,
    data_start: *mut u8,
    data_size: usize,
    stack_start: *mut u8,
    stack_size: usize,
}

#[derive(Clone, Copy)]
pub struct SharedRustletCtx {
    ptr: *mut RustletCtx,
}

struct AbiInput;
struct AbiReady;
struct ReturnedState;

/// Typestate transaction for one Rustlet use of the shared secondary buffer.
///
/// Marker states are zero-sized and compile away. The transaction is neither
/// `Copy` nor `Clone`, so ABI preparation, execution, and returned-state access
/// must occur in order.
struct SharedRustletCall<State> {
    shared: SharedRustletCtx,
    _state: PhantomData<State>,
}

impl SharedRustletCtx {
    pub(crate) fn new(ptr: *mut RustletCtx) -> Self {
        Self { ptr }
    }

    pub fn as_mut_ptr(self) -> *mut RustletCtx {
        self.ptr
    }

    fn as_ref(self) -> &'static RustletCtx {
        unsafe { &*self.ptr }
    }

    fn as_mut(self) -> &'static mut RustletCtx {
        unsafe { &mut *self.ptr }
    }

    fn reset(self) {
        unsafe {
            oxi_core::core::secure_zero_raw(
                self.ptr.cast::<u8>(),
                core::mem::size_of::<RustletCtx>(),
            )
        };
    }

    /// Clears all command, response, status and serialized-state bytes.
    pub fn clear(self) {
        self.reset();
    }

    fn prepare_start(self) {
        let buffer = self.as_mut();
        buffer.reset_control();
        buffer.set_version(rustlet_runtime::ABI_VERSION);
    }

    fn stage_command(self, header: rustlet_runtime::RustletApduHeader, incoming: &[u8]) -> bool {
        let buffer = self.as_mut();
        buffer.set_version(rustlet_runtime::ABI_VERSION);
        buffer.stage_command(header, incoming)
    }

    fn stage_existing_command(
        self,
        header: rustlet_runtime::RustletApduHeader,
        incoming_len: usize,
    ) -> bool {
        let buffer = self.as_mut();
        buffer.set_version(rustlet_runtime::ABI_VERSION);
        buffer.stage_existing_command(header, incoming_len)
    }

    pub fn stage_encoded_command(
        self,
        mut header: rustlet_runtime::RustletApduHeader,
        encode: impl FnOnce(&mut [u8]) -> Option<usize>,
    ) -> bool {
        let buffer = self.as_mut();
        buffer.set_version(rustlet_runtime::ABI_VERSION);
        let Some(incoming_len) = encode(&mut buffer.data) else {
            return false;
        };
        if incoming_len > rustlet_runtime::APDU_PAYLOAD_LENGTH_MAX {
            return false;
        }
        header.lc = incoming_len as u8;
        header.le = incoming_len as u8;
        buffer.stage_preencoded_command(header, incoming_len)
    }

    /// Transfers the secondary half from kernel scratch ownership to ABI input.
    ///
    /// This is the mandatory transition before a Rustlet handler call. It
    /// removes any plaintext, ciphertext, MAC input, status, or state bytes
    /// left by the previous kernel-side use before publishing registry state.
    pub fn stage_state_from_registry(self, state: &[u8]) -> bool {
        let buffer = self.as_mut();
        buffer.reset_control();
        buffer.set_version(rustlet_runtime::ABI_VERSION);
        buffer.stage_state(state)
    }

    #[inline(always)]
    fn begin_handler_call(self, state: &[u8]) -> Option<SharedRustletCall<AbiInput>> {
        self.stage_state_from_registry(state)
            .then_some(SharedRustletCall {
                shared: self,
                _state: PhantomData,
            })
    }

    pub fn state_bytes(self) -> &'static [u8] {
        self.as_ref().state_bytes()
    }

    /// Scrubs the complete serialized-state capacity after kernel persistence.
    pub fn clear_state(self) {
        self.as_mut().clear_state();
    }

    fn stage_command_from_apdu(self, apdu: &mut impl SEApdu) -> bool {
        let header = apdu.header();
        let incoming_len = apdu.incoming_data().len();
        let incoming_ptr = apdu.incoming_data().as_ptr();
        let shared_data_ptr = self.as_ref().data.as_ptr();
        let header = rustlet_runtime::RustletApduHeader {
            cla: header.cla,
            ins: header.ins,
            p1: header.p1,
            p2: header.p2,
            lc: header.p3,
            le: header.p3,
        };
        if core::ptr::eq(incoming_ptr, shared_data_ptr) {
            return self.stage_existing_command(header, incoming_len);
        }

        let incoming = apdu.incoming_data();
        self.stage_command(header, incoming)
    }

    fn status(self) -> ApduStatus {
        self.as_ref().status()
    }

    fn status_or(self, fallback: ApduStatus) -> ApduStatus {
        let status = self.status();
        if status.sw1 == 0 && status.sw2 == 0 {
            fallback
        } else {
            status
        }
    }

    fn copy_outgoing_to_apdu(self, apdu: &mut impl SEApdu) -> bool {
        let buffer = self.as_ref();
        let outgoing_len = buffer.outgoing_len();
        if outgoing_len == 0 {
            return true;
        }
        if outgoing_len > rustlet_runtime::APDU_PAYLOAD_LENGTH_MAX {
            return false;
        }

        let _ = apdu.set_outgoing();
        apdu.set_outgoing_length(outgoing_len);
        let outgoing = buffer.outgoing_data();
        let target = &mut apdu.buffer_mut()[..outgoing_len];
        if !core::ptr::eq(target.as_ptr(), outgoing.as_ptr()) {
            target.copy_from_slice(outgoing);
        }
        true
    }

    pub fn outgoing_data(self) -> &'static [u8] {
        self.as_ref().outgoing_data()
    }
}

impl SharedRustletCall<AbiInput> {
    #[inline(always)]
    fn stage_apdu(self, apdu: &mut impl SEApdu) -> Option<SharedRustletCall<AbiReady>> {
        self.shared
            .stage_command_from_apdu(apdu)
            .then_some(SharedRustletCall {
                shared: self.shared,
                _state: PhantomData,
            })
    }

    #[inline(always)]
    fn stage_encoded(
        self,
        header: rustlet_runtime::RustletApduHeader,
        encode: impl FnOnce(&mut [u8]) -> Option<usize>,
    ) -> Option<SharedRustletCall<AbiReady>> {
        self.shared
            .stage_encoded_command(header, encode)
            .then_some(SharedRustletCall {
                shared: self.shared,
                _state: PhantomData,
            })
    }

    #[inline(always)]
    fn stage_existing(
        self,
        header: rustlet_runtime::RustletApduHeader,
        incoming_len: usize,
    ) -> Option<SharedRustletCall<AbiReady>> {
        self.shared
            .stage_existing_command(header, incoming_len)
            .then_some(SharedRustletCall {
                shared: self.shared,
                _state: PhantomData,
            })
    }
}

impl SharedRustletCall<AbiReady> {
    #[inline(always)]
    fn invoke_handler(
        self,
        loaded: &LoadedFae,
        handler: usize,
        state: *mut core::ffi::c_void,
    ) -> (
        SharedRustletCall<ReturnedState>,
        oxi_core::core::isolation::IsolationResult<oxi_core::core::isolation::AppReturnRegisters>,
    ) {
        let status_word = invoke_app(
            loaded,
            AppInvocation {
                entry_pc: handler,
                arg0: state as usize,
                arg1: self.shared.as_mut_ptr() as usize,
                arg2: 0,
                arg3: 0,
                kind: oxi_core::core::isolation::AppCallKind::Handler,
                fault_return_value: ApduStatus::internal_error().to_word() as usize,
            },
        );
        (
            SharedRustletCall {
                shared: self.shared,
                _state: PhantomData,
            },
            status_word,
        )
    }
}

impl SharedRustletCall<ReturnedState> {
    #[inline(always)]
    fn copy_outgoing_to_apdu(&self, apdu: &mut impl SEApdu) -> bool {
        self.shared.copy_outgoing_to_apdu(apdu)
    }

    #[inline(always)]
    fn status_or(&self, fallback: ApduStatus) -> ApduStatus {
        self.shared.status_or(fallback)
    }
}

pub fn load(fae: &'static [u8]) -> Option<LoadedFae> {
    let parsed = parse_fae(fae)?;
    let reserved = reserve_app_memory(parsed.writable_len)?;
    let memory_layout = oxi_core::core::isolation::AppMemoryLayout {
        text: oxi_core::core::isolation::AppMemoryWindow {
            start: parsed.text_start,
            len: parsed.text_len,
        },
        ram: oxi_core::core::isolation::AppMemoryWindow {
            start: reserved.allocation.ptr as usize,
            len: reserved.ram_size,
        },
    };
    let isolation_plan = match oxi_core::core::isolation::plan_app_regions(memory_layout) {
        Ok(plan) => plan,
        Err(_) => {
            release_app_memory(reserved);
            return None;
        }
    };
    let gate_region = match oxi_core::core::target::isolated_app_gate_region() {
        Some(region) => region,
        None => {
            release_app_memory(reserved);
            return None;
        }
    };

    Some(LoadedFae {
        app_gp: reserved.data_start as usize,
        entrypoint: (fae.as_ptr() as usize) | 1,
        shared_buffer: SharedRustletCtx::new(gate_region.base as *mut RustletCtx),
        memory_layout,
        data_window: oxi_core::core::isolation::AppMemoryWindow {
            start: reserved.data_start as usize,
            len: reserved.data_size,
        },
        stack_window: oxi_core::core::isolation::AppMemoryWindow {
            start: reserved.stack_start as usize,
            len: reserved.stack_size,
        },
        isolation_plan,
        profile_kind: parsed.profile_kind,
        heap_window: None,
        ram_allocation: reserved.allocation,
    })
}

pub fn configure_heap_window(
    loaded: &mut LoadedFae,
    heap: rustlet_runtime::RustletHeapRegion,
) -> bool {
    let window = oxi_core::core::isolation::AppMemoryWindow {
        start: heap.storage_start as usize,
        len: heap.storage_len,
    };
    if heap.storage_len == 0 || !contains_in_window(loaded.data_window, window.start, window.len) {
        return false;
    }
    loaded.heap_window = Some(window);
    true
}

pub(crate) fn validate_fae_reader(len: usize, read_byte: impl FnMut(usize) -> Option<u8>) -> bool {
    decode_fae_metadata(len, read_byte).is_some()
}

pub fn unload(loaded: LoadedFae) {
    unsafe {
        // The allocation contains the Rustlet stack, writable statics and
        // private heap. It must never return to the buddy allocator with data
        // belonging to the previous security principal.
        oxi_core::core::secure_zero_raw(loaded.ram_allocation.ptr, loaded.ram_allocation.size);
        oxi_core::core::dealloc(loaded.ram_allocation.ptr, loaded.ram_allocation.layout());
    }
}

pub fn call_start(loaded: &LoadedFae) -> Option<&'static SelectedAppDescriptor> {
    loaded.shared_buffer.prepare_start();
    let descriptor = invoke_app(
        loaded,
        AppInvocation {
            entry_pc: loaded.entrypoint,
            arg0: loaded.shared_buffer.as_mut_ptr() as usize,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            kind: oxi_core::core::isolation::AppCallKind::Start,
            fault_return_value: 0,
        },
    );
    let descriptor = descriptor.ok()?;
    if descriptor.r1 != oxi_core::core::isolation::AppReturnCode::Descriptor.word() {
        oxi_core::consoleln!(
            "rustlet start returned non-descriptor code {}",
            descriptor.r1
        );
        return None;
    }
    let descriptor = descriptor.r0 as *const SelectedAppDescriptor;

    if descriptor.is_null() {
        oxi_core::consoleln!("rustlet start returned null descriptor");
        return None;
    }

    let descriptor_addr = descriptor as usize;
    if !contains_in_window(
        loaded.data_window,
        descriptor_addr,
        core::mem::size_of::<SelectedAppDescriptor>(),
    ) {
        oxi_core::consoleln!(
            "rustlet start returned invalid descriptor pointer 0x{:08x}",
            descriptor_addr
        );
        return None;
    }

    let descriptor = unsafe { descriptor.as_ref()? };
    if descriptor.vtable.is_null() {
        oxi_core::consoleln!("rustlet descriptor vtable null");
        return None;
    }

    if !descriptor_is_sane(loaded, descriptor) {
        log_descriptor_debug(loaded, descriptor);
        return None;
    }

    Some(descriptor)
}

pub fn call_handler(
    loaded: &LoadedFae,
    handler: usize,
    state: *mut core::ffi::c_void,
    apdu: &mut apdu_manager::Apdu<'_>,
    serialized_state: &[u8],
) -> HandlerCallResult {
    let Some(call) = loaded.shared_buffer.begin_handler_call(serialized_state) else {
        return HandlerCallResult {
            status: ApduStatus::wrong_length(),
            returned_normally: false,
        };
    };
    let Some(call) = call.stage_apdu(apdu) else {
        return HandlerCallResult {
            status: ApduStatus::wrong_length(),
            returned_normally: false,
        };
    };

    let (returned, status_word) = call.invoke_handler(loaded, handler, state);
    let returned_normally = matches!(
        oxi_core::core::isolation::last_app_return_kind(),
        Some(oxi_core::core::isolation::AppReturnKind::HandlerReturn)
    );
    let fallback = status_word
        .map(status_from_app_return)
        .unwrap_or_else(|_| ApduStatus::internal_error());
    if !returned.copy_outgoing_to_apdu(apdu) {
        return HandlerCallResult {
            status: ApduStatus::internal_error(),
            returned_normally: false,
        };
    }
    HandlerCallResult {
        status: if returned_normally {
            returned.status_or(fallback)
        } else {
            fallback
        },
        returned_normally,
    }
}

pub fn call_handler_with_encoded_command(
    loaded: &LoadedFae,
    handler: usize,
    state: *mut core::ffi::c_void,
    header: rustlet_runtime::RustletApduHeader,
    encode: impl FnOnce(&mut [u8]) -> Option<usize>,
    serialized_state: &[u8],
) -> HandlerCallResult {
    let Some(call) = loaded.shared_buffer.begin_handler_call(serialized_state) else {
        return HandlerCallResult {
            status: ApduStatus::wrong_length(),
            returned_normally: false,
        };
    };
    let Some(call) = call.stage_encoded(header, encode) else {
        return HandlerCallResult {
            status: ApduStatus::wrong_length(),
            returned_normally: false,
        };
    };

    let (returned, status_word) = call.invoke_handler(loaded, handler, state);
    let returned_normally = matches!(
        oxi_core::core::isolation::last_app_return_kind(),
        Some(oxi_core::core::isolation::AppReturnKind::HandlerReturn)
    );
    let fallback = status_word
        .map(status_from_app_return)
        .unwrap_or_else(|_| ApduStatus::internal_error());
    HandlerCallResult {
        status: if returned_normally {
            returned.status_or(fallback)
        } else {
            fallback
        },
        returned_normally,
    }
}

pub fn call_handler_with_existing_command(
    loaded: &LoadedFae,
    handler: usize,
    state: *mut core::ffi::c_void,
    header: rustlet_runtime::RustletApduHeader,
    incoming_len: usize,
    serialized_state: &[u8],
) -> HandlerCallResult {
    let Some(call) = loaded.shared_buffer.begin_handler_call(serialized_state) else {
        return HandlerCallResult {
            status: ApduStatus::wrong_length(),
            returned_normally: false,
        };
    };
    let Some(call) = call.stage_existing(header, incoming_len) else {
        return HandlerCallResult {
            status: ApduStatus::wrong_length(),
            returned_normally: false,
        };
    };

    let (returned, status_word) = call.invoke_handler(loaded, handler, state);
    let returned_normally = matches!(
        oxi_core::core::isolation::last_app_return_kind(),
        Some(oxi_core::core::isolation::AppReturnKind::HandlerReturn)
    );
    let fallback = status_word
        .map(status_from_app_return)
        .unwrap_or_else(|_| ApduStatus::internal_error());
    HandlerCallResult {
        status: if returned_normally {
            returned.status_or(fallback)
        } else {
            fallback
        },
        returned_normally,
    }
}

fn invoke_app(
    loaded: &LoadedFae,
    invocation: AppInvocation,
) -> oxi_core::core::isolation::IsolationResult<oxi_core::core::isolation::AppReturnRegisters> {
    crate::kernel_main_app::before_rustlet(loaded.stack_window);
    let result = oxi_core::core::isolation::enter_app_in_session(
        &oxi_core::core::isolation::AppExecution {
            entry_pc: invocation.entry_pc,
            app_gp: loaded.app_gp,
            arg0: invocation.arg0,
            arg1: invocation.arg1,
            arg2: invocation.arg2,
            arg3: invocation.arg3,
            stack: loaded.stack_window,
            plan: loaded.isolation_plan,
        },
        oxi_core::core::isolation::AppSession {
            kind: invocation.kind,
            plan: loaded.isolation_plan,
            fault_return_value: invocation.fault_return_value,
        },
    );
    crate::kernel_main_app::after_rustlet(loaded.stack_window);
    unsafe {
        // The stack has no state that may survive an isolated entry. Scrub it
        // only after observers (notably the high-watermark monitor) have read
        // it, and before any later Rustlet can reuse the allocation.
        oxi_core::core::secure_zero_raw(
            loaded.stack_window.start as *mut u8,
            loaded.stack_window.len,
        );

        // Ordinary Rustlet instances serialize their complete persistent
        // state and drop their in-memory instance before a normal handler
        // return. Their heap is consequently scratch storage and must not
        // remain readable between APDUs. Rustlet Security Domains are the
        // deliberate exception: their non-serialized secure-channel session
        // state must remain resident until the channel or SD is torn down;
        // their complete allocation is still scrubbed by `unload`.
        if invocation.kind == oxi_core::core::isolation::AppCallKind::Handler
            && loaded.profile_kind == FaeProfileKind::Application
            && matches!(
                oxi_core::core::isolation::last_app_return_kind(),
                Some(oxi_core::core::isolation::AppReturnKind::HandlerReturn)
            )
        {
            if let Some(heap) = loaded.heap_window {
                oxi_core::core::secure_zero_raw(heap.start as *mut u8, heap.len);
            }
        }
    }
    result
}

fn status_from_app_return(registers: oxi_core::core::isolation::AppReturnRegisters) -> ApduStatus {
    ApduStatus::from_word(registers.r0 as u32)
}

fn descriptor_is_sane(loaded: &LoadedFae, descriptor: &SelectedAppDescriptor) -> bool {
    contains_in_window(
        loaded.data_window,
        descriptor as *const SelectedAppDescriptor as usize,
        core::mem::size_of::<SelectedAppDescriptor>(),
    ) && contains_in_window(loaded.data_window, descriptor.state as usize, 1)
        && contains_in_window(
            loaded.data_window,
            descriptor.vtable as usize,
            core::mem::size_of::<SelectedAppVtable>(),
        )
        && ((loaded.profile_kind == FaeProfileKind::Application
            && descriptor.security_domain_vtable.is_null())
            || (loaded.profile_kind == FaeProfileKind::SecurityDomain
                && !descriptor.security_domain_vtable.is_null()))
        && (descriptor.security_domain_vtable.is_null()
            || contains_in_window(
                loaded.data_window,
                descriptor.security_domain_vtable as usize,
                core::mem::size_of::<SelectedSecurityDomainVtable>(),
            ))
        && contains_in_window(
            loaded.data_window,
            descriptor.heap.storage_start as usize,
            descriptor.heap.storage_len,
        )
}

fn log_descriptor_debug(loaded: &LoadedFae, descriptor: &SelectedAppDescriptor) {
    let descriptor_addr = descriptor as *const SelectedAppDescriptor as usize;
    let vtable_addr = descriptor.vtable as usize;
    let security_domain_vtable_addr = descriptor.security_domain_vtable as usize;
    let heap_start = descriptor.heap.storage_start as usize;
    let heap_len = descriptor.heap.storage_len;

    oxi_core::consoleln!(
        "rustlet descriptor rejected: desc=0x{:08x} state=0x{:08x} vtable=0x{:08x} sd_vtable=0x{:08x} heap=0x{:08x}+{}",
        descriptor_addr,
        descriptor.state as usize,
        vtable_addr,
        security_domain_vtable_addr,
        heap_start,
        heap_len
    );
    oxi_core::consoleln!(
        "rustlet windows: text=0x{:08x}+{} data=0x{:08x}+{} stack=0x{:08x}+{}",
        loaded.memory_layout.text.start,
        loaded.memory_layout.text.len,
        loaded.data_window.start,
        loaded.data_window.len,
        loaded.stack_window.start,
        loaded.stack_window.len
    );
}

fn contains_in_window(
    window: oxi_core::core::isolation::AppMemoryWindow,
    addr: usize,
    len: usize,
) -> bool {
    let Some(end) = addr.checked_add(len) else {
        return false;
    };

    addr >= window.start && end <= window.end()
}

fn parse_fae(fae: &[u8]) -> Option<ParsedFae> {
    let base = fae.as_ptr();
    let (writable_len, profile_kind) =
        decode_fae_metadata(fae.len(), |offset| fae.get(offset).copied())?;
    let (text_start, text_len) = aligned_text_window(base as usize, fae.len())?;

    Some(ParsedFae {
        text_start,
        text_len,
        writable_len,
        profile_kind,
    })
}

fn decode_fae_metadata(
    len: usize,
    mut read_byte: impl FnMut(usize) -> Option<u8>,
) -> Option<(usize, FaeProfileKind)> {
    if len < FAE_FOOTER_SIZE {
        return None;
    }
    let magic = read_u32_from(len, FAE_FOOTER_MAGIC_OFFSET, &mut read_byte)?;
    if magic != FAE_MAGIC_NUMBER_AND_VERSION {
        return None;
    }
    let isa = read_u32_from(len, FAE_FOOTER_ISA_OFFSET, &mut read_byte)?;
    if !fae_isa_matches_kernel(isa) {
        return None;
    }
    if read_u32_from(len, FAE_FOOTER_ABI_OFFSET, &mut read_byte)? != FAE_ABI_DESCRIPTOR
        || read_u32_from(len, FAE_FOOTER_EXTRA_FIELDS_OFFSET, &mut read_byte)? != 0
    {
        return None;
    }
    let stored_crc = read_u32_from(len, FAE_FOOTER_CRC_OFFSET, &mut read_byte)?;
    if fae_crc32_reader(len, &mut read_byte)? != stored_crc {
        return None;
    }

    let profile = read_u32_from(len, FAE_FOOTER_PROFILE_OFFSET, &mut read_byte)?;
    let profile_kind = match profile >> 20 {
        FAE_APPLICATION_PROFILE => FaeProfileKind::Application,
        FAE_SECURITY_DOMAIN_PROFILE => FaeProfileKind::SecurityDomain,
        _ => return None,
    };
    let minimum_version = profile & 0x000F_FFFF;
    if minimum_version > 0x0000_1000 || rustlet_runtime::ABI_VERSION < 1 {
        return None;
    }
    let requirements = read_u32_from(len, FAE_FOOTER_MEMORY_REQUIREMENTS_OFFSET, &mut read_byte)?;
    let writable_len = ((requirements >> 16) as usize).checked_mul(FAE_MEMORY_UNIT)?;
    let stack_len = ((requirements & 0xFFFF) as usize).checked_mul(FAE_MEMORY_UNIT)?;
    if stack_len > FAE_STACK_SIZE {
        return None;
    }

    Some((writable_len, profile_kind))
}

fn read_u32_from(
    len: usize,
    offset_from_end: isize,
    read_byte: &mut impl FnMut(usize) -> Option<u8>,
) -> Option<u32> {
    let start = len.checked_add_signed(offset_from_end)?;
    Some(u32::from_le_bytes([
        read_byte(start)?,
        read_byte(start + 1)?,
        read_byte(start + 2)?,
        read_byte(start + 3)?,
    ]))
}

fn fae_isa_matches_kernel(descriptor: u32) -> bool {
    let family = (descriptor >> 24) as u8;
    let subgroup = (descriptor >> 16) as u8;
    let extra_words = descriptor & 0x0F;
    let expected_subgroup = if cfg!(oxide_se_board_raspi_pico) {
        0x03
    } else {
        0x02
    };
    family == 0x01 && subgroup == expected_subgroup && extra_words == 0
}

#[cfg(test)]
fn fae_crc32(fae: &[u8]) -> u32 {
    fae_crc32_reader(fae.len(), &mut |offset| fae.get(offset).copied())
        .expect("slice reader covers its complete FAE")
}

fn fae_crc32_reader(len: usize, read_byte: &mut impl FnMut(usize) -> Option<u8>) -> Option<u32> {
    let crc_start = len.checked_sub(20)?;
    let mut crc = 0xFFFF_FFFFu32;
    for index in 0..len {
        let byte = read_byte(index)?;
        let byte = if (crc_start..crc_start + 4).contains(&index) {
            0
        } else {
            byte
        };
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & (0u32.wrapping_sub(crc & 1)));
        }
    }
    Some(!crc)
}

fn aligned_text_window(start: usize, len: usize) -> Option<(usize, usize)> {
    let end = start.checked_add(len)?;
    let text_start = oxi_core::core::isolation::align_down(
        start,
        oxi_core::core::isolation::APP_TEXT_REGION_SIZE,
    );
    let text_end =
        oxi_core::core::isolation::align_up(end, oxi_core::core::isolation::APP_TEXT_REGION_SIZE);
    Some((text_start, text_end.checked_sub(text_start)?))
}

fn reserve_app_memory(writable_len: usize) -> Option<ReservedAppMemory> {
    let region_policy = oxi_core::core::target::mpu_region_policy();
    if matches!(
        region_policy.model,
        oxi_core::core::target::MpuAlignmentModel::Unsupported
    ) {
        return None;
    }
    let useful_data_size = core::cmp::max(1, writable_len);
    if useful_data_size > APP_RAM_CAPACITY {
        return None;
    }
    let block_size = app_ram_block_size(useful_data_size)?;
    let block_layout = Layout::from_size_align(block_size, block_size).ok()?;
    let block_ptr = oxi_core::core::alloc(block_layout);
    if block_ptr.is_null() {
        return None;
    }
    unsafe {
        // Allocation is not an initialization boundary: a buddy block may
        // still contain another Rustlet's data from an earlier lifetime.
        oxi_core::core::secure_zero_raw(block_ptr, block_size);
    }

    // The allocator returns one MPU-ready buddy block. The downward-growing
    // stack occupies its low end; GP and writable Rustlet memory start exactly
    // at the upper stack boundary.
    let stack_start = block_ptr;
    let data_start = unsafe { block_ptr.add(FAE_STACK_SIZE) };

    Some(ReservedAppMemory {
        allocation: AppAllocation {
            ptr: block_ptr,
            size: block_size,
            align: block_size,
        },
        ram_size: block_size,
        data_start,
        data_size: block_size - FAE_STACK_SIZE,
        stack_start,
        stack_size: FAE_STACK_SIZE,
    })
}

fn release_app_memory(memory: ReservedAppMemory) {
    unsafe {
        oxi_core::core::secure_zero_raw(memory.allocation.ptr, memory.allocation.size);
        oxi_core::core::dealloc(memory.allocation.ptr, memory.allocation.layout());
    }
}

impl AppAllocation {
    fn layout(&self) -> Layout {
        Layout::from_size_align(self.size, self.align)
            .expect("stored app allocation layout must remain valid")
    }
}

fn app_ram_block_size(writable_len: usize) -> Option<usize> {
    FAE_STACK_SIZE
        .checked_add(writable_len)?
        .checked_next_power_of_two()
}

#[cfg(test)]
mod tests {
    use super::{
        aligned_text_window, app_ram_block_size, fae_crc32, parse_fae, FaeProfileKind,
        SharedRustletCtx, FAE_STACK_SIZE,
    };
    use rustlet_runtime::{ApduStatus, RustletApduHeader, RustletCtx, SEApdu};
    use std::vec;
    use std::vec::Vec;

    #[test]
    fn app_ram_block_contains_stack_then_writable_data() {
        let block_size = app_ram_block_size(4096).expect("RAM block size");

        assert_eq!(block_size, 8192);
        assert_eq!(FAE_STACK_SIZE, 2048);
        assert_eq!(block_size - FAE_STACK_SIZE, 6144);
    }

    fn compact_fae(profile: u32, requirements: u32) -> Vec<u8> {
        let mut image = vec![0xAA; 32];
        image.extend_from_slice(&requirements.to_le_bytes());
        image.extend_from_slice(&profile.to_le_bytes());
        image.extend_from_slice(&0u32.to_le_bytes());
        image.extend_from_slice(&0u32.to_le_bytes());
        image.extend_from_slice(&0xAC1D_A992u32.to_le_bytes());
        image.extend_from_slice(&0x0102_0000u32.to_le_bytes());
        image.extend_from_slice(&0xFAEC_0D10u32.to_le_bytes());
        let crc = fae_crc32(&image);
        let crc_offset = image.len() - 20;
        image[crc_offset..crc_offset + 4].copy_from_slice(&crc.to_le_bytes());
        image
    }

    #[test]
    fn compact_fae_accepts_application_profile_and_decodes_memory() {
        let image = compact_fae(0xA990_1000, (11 << 16) | 64);
        let parsed = parse_fae(&image).expect("valid compact Rustlet FAE");

        assert_eq!(parsed.writable_len, 352);
        assert!(parsed.profile_kind == FaeProfileKind::Application);
    }

    #[test]
    fn compact_fae_accepts_security_domain_profile() {
        let image = compact_fae(0x5DC0_1000, (24 << 16) | 64);
        let parsed = parse_fae(&image).expect("valid compact Security Domain FAE");

        assert!(parsed.profile_kind == FaeProfileKind::SecurityDomain);
    }

    #[test]
    fn compact_fae_rejects_crc_legacy_abi_and_excessive_stack() {
        let valid = compact_fae(0xA990_1000, (11 << 16) | 64);

        let mut bad_crc = valid.clone();
        bad_crc[0] ^= 1;
        assert!(parse_fae(&bad_crc).is_none());

        let mut legacy_abi = valid.clone();
        let abi_offset = legacy_abi.len() - 12;
        legacy_abi[abi_offset..abi_offset + 4].copy_from_slice(&0xFACA_DE16u32.to_le_bytes());
        let crc_offset = legacy_abi.len() - 20;
        legacy_abi[crc_offset..crc_offset + 4].fill(0);
        let crc = fae_crc32(&legacy_abi);
        legacy_abi[crc_offset..crc_offset + 4].copy_from_slice(&crc.to_le_bytes());
        assert!(parse_fae(&legacy_abi).is_none());

        let excessive_stack = compact_fae(0xA990_1000, (11 << 16) | 65);
        assert!(parse_fae(&excessive_stack).is_none());
    }

    #[test]
    fn app_ram_block_rounds_the_complete_request_once() {
        assert_eq!(app_ram_block_size(1), Some(4096));
        assert_eq!(app_ram_block_size(2048), Some(4096));
        assert_eq!(app_ram_block_size(2049), Some(8192));
        assert_eq!(app_ram_block_size(8192), Some(16384));
    }

    #[test]
    fn aligned_text_window_keeps_aligned_fae_bounds() {
        assert_eq!(
            aligned_text_window(0x1000_0000, 4096),
            Some((0x1000_0000, 4096))
        );
    }

    #[test]
    fn aligned_text_window_covers_unaligned_persistent_payload() {
        assert_eq!(
            aligned_text_window(0x1000_000c, 4096),
            Some((0x1000_0000, 6144))
        );
    }

    #[test]
    fn shared_context_is_two_256_byte_buffers() {
        let ctx = RustletCtx::new();
        let base = &ctx as *const RustletCtx as usize;
        let data = ctx.data.as_ptr() as usize;

        assert_eq!(core::mem::size_of::<RustletCtx>(), 512);
        assert_eq!(rustlet_runtime::APDU_SHARED_REGION_SIZE, 512);
        assert_eq!(rustlet_runtime::RUSTLET_CONTROL_BUFFER_CAPACITY, 256);
        assert_eq!(rustlet_runtime::APDU_BUFFER_CAPACITY, 256);
        assert_eq!(rustlet_runtime::APDU_PAYLOAD_LENGTH_MAX, 255);
        assert_eq!(rustlet_runtime::STATE_BUFFER_CAPACITY, 244);
        assert_eq!(data - base, 256);
    }

    #[test]
    fn shared_context_keeps_short_apdu_payload_limit() {
        let mut ctx = RustletCtx::new();
        let header = RustletApduHeader {
            cla: 0x80,
            ins: 0xE6,
            p1: 0x0C,
            p2: 0x00,
            lc: 0xFF,
            le: 0,
        };
        let accepted = [0xA5; rustlet_runtime::APDU_PAYLOAD_LENGTH_MAX];
        let rejected = [0xA5; rustlet_runtime::APDU_BUFFER_CAPACITY];

        assert!(ctx.stage_command(header, &accepted));
        assert_eq!(ctx.incoming_data().len(), 255);
        assert!(!ctx.stage_command(header, &rejected));
    }

    #[test]
    fn clearing_shared_page_removes_payload_state_and_status() {
        let mut ctx = RustletCtx::new();
        assert!(ctx.stage_command(
            RustletApduHeader {
                cla: 0x80,
                ins: 0xE6,
                p1: 0x0C,
                p2: 0x00,
                lc: 3,
                le: 0,
            },
            &[0xAA, 0xBB, 0xCC],
        ));
        assert!(ctx.stage_state(&[0x11, 0x22]));
        ctx.set_status(ApduStatus {
            sw1: 0x91,
            sw2: 0x23,
        });

        SharedRustletCtx::new(&mut ctx).clear();

        assert_eq!(ctx.version(), 0);
        assert_eq!(ctx.status().sw1, 0);
        assert_eq!(ctx.status().sw2, 0);
        assert!(ctx.incoming_data().is_empty());
        assert!(ctx.state_bytes().is_empty());
        assert!(ctx.data.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn staging_registry_state_clears_previous_secondary_scratch() {
        let mut ctx = RustletCtx::new();
        unsafe {
            core::ptr::write_bytes(
                (&mut ctx as *mut RustletCtx).cast::<u8>(),
                0xA5,
                rustlet_runtime::RUSTLET_CONTROL_BUFFER_CAPACITY,
            );
        }

        assert!(SharedRustletCtx::new(&mut ctx).stage_state_from_registry(&[0x11, 0x22]));

        assert_eq!(ctx.version(), rustlet_runtime::ABI_VERSION);
        assert_eq!(ctx.state_bytes(), &[0x11, 0x22]);
        assert!(ctx.state_bytes_mut()[2..].iter().all(|byte| *byte == 0));
        assert_eq!(ctx.status().sw1, 0);
        assert_eq!(ctx.status().sw2, 0);
    }
}
