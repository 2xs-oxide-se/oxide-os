use alloc::boxed::Box;
use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::panic::PanicInfo;
use core::ptr;

use crate::security_domain::{
    InstallForInstall, InstallForLoad, RustletSecurityDomain, SecurityDomainAdministrativeState,
    SecurityDomainLifecycle, SecurityDomainPrivileges, SecurityLevel,
};
use crate::{
    ApduStatus, RustletCtx, RustletHeapRegion, SelectedAppDescriptor, SelectedAppVtable,
    SelectedSecurityDomainVtable,
};

#[doc(hidden)]
pub type InstallFn = fn(&mut RustletCtx) -> Result<RuntimeInstance, ApduStatus>;
#[doc(hidden)]
pub type LoadFn = fn(&mut RustletCtx) -> Result<RuntimeInstance, ApduStatus>;

/// Trait implemented by a Rustlet application.
///
/// A Rustlet is responsible for processing APDUs and optionally
/// loading and saving its persistent state.
pub trait Rustlet {
    /// Handle an incoming APDU using the provided runtime context.
    fn process_apdu(&mut self, ctx: &mut RustletCtx) -> ApduStatus;

    /// Load state from the provided byte slice.
    ///
    /// The default implementation accepts an empty state and returns
    /// `wrong_data` for any non-empty input.
    fn load_state(&mut self, state: &[u8]) -> Result<(), ApduStatus> {
        if state.is_empty() {
            Ok(())
        } else {
            Err(ApduStatus::wrong_data())
        }
    }

    /// Save state into the provided output buffer.
    ///
    /// The default implementation does nothing and returns a length of 0.
    fn save_state(&self, _out: &mut [u8]) -> Result<usize, ApduStatus> {
        Ok(0)
    }
}

#[doc(hidden)]
pub trait PostcardState: serde::Serialize + for<'de> serde::Deserialize<'de> + Sized {
    fn load_postcard_state(&mut self, state: &[u8]) -> Result<(), ApduStatus> {
        *self = postcard::from_bytes(state).map_err(|_| ApduStatus::wrong_data())?;
        Ok(())
    }

    fn save_postcard_state(&self, out: &mut [u8]) -> Result<usize, ApduStatus> {
        let encoded = postcard::to_slice(self, out).map_err(|_| ApduStatus::wrong_length())?;
        Ok(encoded.len())
    }
}

impl<T> PostcardState for T where T: serde::Serialize + for<'de> serde::Deserialize<'de> + Sized {}

#[doc(hidden)]
pub struct RustletHeapStorage<const N: usize> {
    bytes: UnsafeCell<[u8; N]>,
}

impl<const N: usize> RustletHeapStorage<N> {
    pub const fn new() -> Self {
        Self {
            bytes: UnsafeCell::new([0; N]),
        }
    }

    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.bytes.get().cast::<u8>()
    }
}

// Rustlet heap storage is a unique runtime backing store for one loaded FAE.
// The kernel enters the Rustlet synchronously, so there is no concurrent heap access.
unsafe impl<const N: usize> Sync for RustletHeapStorage<N> {}

pub struct PersistentRustlet<T> {
    inner: T,
}

impl<T> PersistentRustlet<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

pub struct PersistentSecurityDomain<T> {
    inner: T,
    administrative_state: SecurityDomainAdministrativeState,
}

impl<T> PersistentSecurityDomain<T> {
    const STATE_ENCODING_VERSION: u8 = 1;
    const STATE_HEADER_LEN: usize = 6;

    pub fn new(inner: T) -> Self {
        Self {
            inner,
            administrative_state: SecurityDomainAdministrativeState::empty(),
        }
    }

    pub fn initialize_from_install_apdu(&mut self, ctx: &mut RustletCtx) -> Result<(), ApduStatus> {
        let install_data = ctx.incoming_data();
        if install_data.is_empty() {
            self.administrative_state = SecurityDomainAdministrativeState::empty();
            return Ok(());
        }

        let Some((_, offset)) = read_lv(install_data, 0) else {
            return Err(ApduStatus::wrong_data());
        };
        let Some((_, offset)) = read_lv(install_data, offset) else {
            return Err(ApduStatus::wrong_data());
        };
        let Some((_, offset)) = read_lv(install_data, offset) else {
            return Err(ApduStatus::wrong_data());
        };
        let Some((privilege_bytes, _)) = read_lv(install_data, offset) else {
            return Err(ApduStatus::wrong_data());
        };
        let privileges = SecurityDomainPrivileges::from_install_bytes(privilege_bytes)
            .map_err(|_| ApduStatus::wrong_data())?;
        self.administrative_state = SecurityDomainAdministrativeState::from_parts(
            privileges,
            SecurityDomainLifecycle::Selectable,
        );
        Ok(())
    }
}

impl<T> Rustlet for PersistentRustlet<T>
where
    T: Rustlet + PostcardState,
{
    fn process_apdu(&mut self, ctx: &mut RustletCtx) -> ApduStatus {
        self.inner.process_apdu(ctx)
    }

    fn load_state(&mut self, state: &[u8]) -> Result<(), ApduStatus> {
        if state.is_empty() {
            Ok(())
        } else {
            self.inner.load_postcard_state(state)
        }
    }

    fn save_state(&self, out: &mut [u8]) -> Result<usize, ApduStatus> {
        self.inner.save_postcard_state(out)
    }
}

impl<T> Rustlet for PersistentSecurityDomain<T>
where
    T: Rustlet + PostcardState,
{
    fn process_apdu(&mut self, ctx: &mut RustletCtx) -> ApduStatus {
        self.inner.process_apdu(ctx)
    }

    fn load_state(&mut self, state: &[u8]) -> Result<(), ApduStatus> {
        if state.is_empty() {
            self.administrative_state = SecurityDomainAdministrativeState::empty();
            return Ok(());
        }
        if state.len() < Self::STATE_HEADER_LEN {
            return Err(ApduStatus::wrong_data());
        }
        if state[0] != Self::STATE_ENCODING_VERSION {
            self.administrative_state = SecurityDomainAdministrativeState::empty();
            return self.inner.load_postcard_state(state);
        }
        let privilege_len = state[2] as usize;
        if privilege_len > 3 {
            return Err(ApduStatus::wrong_data());
        }
        let privileges = SecurityDomainPrivileges::from_install_bytes(&state[3..3 + privilege_len])
            .map_err(|_| ApduStatus::wrong_data())?;
        let lifecycle = SecurityDomainLifecycle::from_stored_byte(state[1]);
        self.administrative_state =
            SecurityDomainAdministrativeState::from_parts(privileges, lifecycle);
        let inner_state = &state[Self::STATE_HEADER_LEN..];
        if inner_state.is_empty() {
            Ok(())
        } else {
            self.inner.load_postcard_state(inner_state)
        }
    }

    fn save_state(&self, out: &mut [u8]) -> Result<usize, ApduStatus> {
        if out.len() < Self::STATE_HEADER_LEN {
            return Err(ApduStatus::wrong_length());
        }
        out[0] = Self::STATE_ENCODING_VERSION;
        out[1] = self.administrative_state.lifecycle().as_byte();
        out[2] = self.administrative_state.privileges().encoded_len() as u8;
        let encoded_privileges = self.administrative_state.privileges().encoded_bytes();
        out[3..6].copy_from_slice(&encoded_privileges);
        let inner_len = self
            .inner
            .save_postcard_state(&mut out[Self::STATE_HEADER_LEN..])?;
        Ok(Self::STATE_HEADER_LEN + inner_len)
    }
}

impl<T> RustletSecurityDomain for PersistentRustlet<T>
where
    T: RustletSecurityDomain + PostcardState,
{
    fn privileges(&self) -> crate::SecurityDomainPrivileges {
        self.inner.privileges()
    }

    fn install_for_load(&mut self, command: &InstallForLoad<'_>) -> Result<(), ApduStatus> {
        self.inner.install_for_load(command)
    }

    fn install_for_install(&mut self, command: &InstallForInstall<'_>) -> Result<(), ApduStatus> {
        self.inner.install_for_install(command)
    }

    fn delete_aid(&mut self, aid: &crate::Aid) -> Result<(), ApduStatus> {
        self.inner.delete_aid(aid)
    }

    fn put_key(&mut self, command: &crate::PutKey<'_>) -> Result<(), ApduStatus> {
        self.inner.put_key(command)
    }

    fn get_data(&mut self, tag: crate::GetDataTag, out: &mut [u8]) -> Result<usize, ApduStatus> {
        self.inner.get_data(tag, out)
    }

    fn may_manage_applet(
        &self,
        package_aid: &crate::Aid,
        applet_aid: &crate::Aid,
        instance_aid: &crate::Aid,
    ) -> bool {
        self.inner
            .may_manage_applet(package_aid, applet_aid, instance_aid)
    }

    fn may_make_selectable(&self, instance_aid: &crate::Aid) -> bool {
        self.inner.may_make_selectable(instance_aid)
    }

    fn supports_scp03(&self) -> bool {
        self.inner.supports_scp03()
    }

    fn supports_scp11a(&self) -> bool {
        self.inner.supports_scp11a()
    }

    fn supports_scp11b(&self) -> bool {
        self.inner.supports_scp11b()
    }

    fn supports_scp11c(&self) -> bool {
        self.inner.supports_scp11c()
    }

    fn claims_delegated_secure_channel_command(
        &self,
        header: crate::DelegatedSecureChannelHeader,
    ) -> bool {
        self.inner.claims_delegated_secure_channel_command(header)
    }

    fn handle_delegated_secure_channel_command(
        &mut self,
        ctx: &mut RustletCtx,
        command: &crate::DelegatedSecureChannelCommand<'_>,
        out: &mut [u8],
    ) -> Result<usize, ApduStatus> {
        self.inner
            .handle_delegated_secure_channel_command(ctx, command, out)
    }

    fn scp11_stage_oce_certificate(
        &mut self,
        ctx: &mut RustletCtx,
        certificate: &crate::Scp11OceCertificate<'_>,
    ) -> Result<(), ApduStatus> {
        self.inner.scp11_stage_oce_certificate(ctx, certificate)
    }

    fn scp11a_mutual_authenticate(
        &mut self,
        ctx: &mut RustletCtx,
        command: &crate::Scp11aMutualAuthenticate<'_>,
        out: &mut [u8],
    ) -> Result<usize, ApduStatus> {
        self.inner.scp11a_mutual_authenticate(ctx, command, out)
    }

    fn scp11b_internal_authenticate(
        &mut self,
        ctx: &mut RustletCtx,
        command: &crate::Scp11bInternalAuthenticate<'_>,
        out: &mut [u8],
    ) -> Result<usize, ApduStatus> {
        self.inner.scp11b_internal_authenticate(ctx, command, out)
    }

    fn scp11c_mutual_authenticate(
        &mut self,
        ctx: &mut RustletCtx,
        command: &crate::Scp11cMutualAuthenticate<'_>,
        out: &mut [u8],
    ) -> Result<usize, ApduStatus> {
        self.inner.scp11c_mutual_authenticate(ctx, command, out)
    }

    fn initialize_update(
        &mut self,
        ctx: &mut RustletCtx,
        command: &crate::InitializeUpdate<'_>,
        out: &mut [u8],
    ) -> Result<usize, ApduStatus> {
        self.inner.initialize_update(ctx, command, out)
    }

    fn external_authenticate(
        &mut self,
        ctx: &mut RustletCtx,
        command: &crate::ExternalAuthenticate<'_>,
    ) -> Result<SecurityLevel, ApduStatus> {
        self.inner.external_authenticate(ctx, command)
    }

    fn current_security_level(&self) -> SecurityLevel {
        self.inner.current_security_level()
    }

    fn secure_channel_open(&self) -> bool {
        self.inner.secure_channel_open()
    }

    fn current_mac_len(&self) -> usize {
        self.inner.current_mac_len()
    }

    fn unwrap_command(
        &mut self,
        ctx: &mut RustletCtx,
        command: &crate::WrappedCommand<'_>,
        out: &mut [u8],
    ) -> Result<usize, ApduStatus> {
        self.inner.unwrap_command(ctx, command, out)
    }

    fn wrap_response(
        &mut self,
        ctx: &mut RustletCtx,
        response: &crate::PlainResponse<'_>,
        out: &mut [u8],
    ) -> Result<usize, ApduStatus> {
        self.inner.wrap_response(ctx, response, out)
    }

    fn reset_secure_channel(&mut self) {
        self.inner.reset_secure_channel()
    }
}

impl<T> RustletSecurityDomain for PersistentSecurityDomain<T>
where
    T: RustletSecurityDomain + PostcardState,
{
    fn administrative_state(&self) -> crate::SecurityDomainAdministrativeState {
        self.administrative_state
    }

    fn get_data(&mut self, tag: crate::GetDataTag, out: &mut [u8]) -> Result<usize, ApduStatus> {
        match tag.0 {
            0x9f70 => self.administrative_state.write_lifecycle_data(out),
            _ => self.inner.get_data(tag, out),
        }
    }

    fn supports_scp03(&self) -> bool {
        self.inner.supports_scp03()
    }

    fn supports_scp11a(&self) -> bool {
        self.inner.supports_scp11a()
    }

    fn supports_scp11b(&self) -> bool {
        self.inner.supports_scp11b()
    }

    fn supports_scp11c(&self) -> bool {
        self.inner.supports_scp11c()
    }

    fn claims_delegated_secure_channel_command(
        &self,
        header: crate::DelegatedSecureChannelHeader,
    ) -> bool {
        self.inner.claims_delegated_secure_channel_command(header)
    }

    fn handle_delegated_secure_channel_command(
        &mut self,
        ctx: &mut RustletCtx,
        command: &crate::DelegatedSecureChannelCommand<'_>,
        out: &mut [u8],
    ) -> Result<usize, ApduStatus> {
        self.inner
            .handle_delegated_secure_channel_command(ctx, command, out)
    }

    fn scp11_stage_oce_certificate(
        &mut self,
        ctx: &mut RustletCtx,
        certificate: &crate::Scp11OceCertificate<'_>,
    ) -> Result<(), ApduStatus> {
        self.inner.scp11_stage_oce_certificate(ctx, certificate)
    }

    fn scp11a_mutual_authenticate(
        &mut self,
        ctx: &mut RustletCtx,
        command: &crate::Scp11aMutualAuthenticate<'_>,
        out: &mut [u8],
    ) -> Result<usize, ApduStatus> {
        self.inner.scp11a_mutual_authenticate(ctx, command, out)
    }

    fn scp11b_internal_authenticate(
        &mut self,
        ctx: &mut RustletCtx,
        command: &crate::Scp11bInternalAuthenticate<'_>,
        out: &mut [u8],
    ) -> Result<usize, ApduStatus> {
        self.inner.scp11b_internal_authenticate(ctx, command, out)
    }

    fn scp11c_mutual_authenticate(
        &mut self,
        ctx: &mut RustletCtx,
        command: &crate::Scp11cMutualAuthenticate<'_>,
        out: &mut [u8],
    ) -> Result<usize, ApduStatus> {
        self.inner.scp11c_mutual_authenticate(ctx, command, out)
    }

    fn initialize_update(
        &mut self,
        ctx: &mut RustletCtx,
        command: &crate::InitializeUpdate<'_>,
        out: &mut [u8],
    ) -> Result<usize, ApduStatus> {
        self.inner.initialize_update(ctx, command, out)
    }

    fn external_authenticate(
        &mut self,
        ctx: &mut RustletCtx,
        command: &crate::ExternalAuthenticate<'_>,
    ) -> Result<SecurityLevel, ApduStatus> {
        self.inner.external_authenticate(ctx, command)
    }

    fn current_security_level(&self) -> SecurityLevel {
        self.inner.current_security_level()
    }

    fn secure_channel_open(&self) -> bool {
        self.inner.secure_channel_open()
    }

    fn current_mac_len(&self) -> usize {
        self.inner.current_mac_len()
    }

    fn unwrap_command(
        &mut self,
        ctx: &mut RustletCtx,
        command: &crate::WrappedCommand<'_>,
        out: &mut [u8],
    ) -> Result<usize, ApduStatus> {
        self.inner.unwrap_command(ctx, command, out)
    }

    fn wrap_response(
        &mut self,
        ctx: &mut RustletCtx,
        response: &crate::PlainResponse<'_>,
        out: &mut [u8],
    ) -> Result<usize, ApduStatus> {
        self.inner.wrap_response(ctx, response, out)
    }

    fn reset_secure_channel(&mut self) {
        self.inner.reset_secure_channel()
    }
}

#[doc(hidden)]
pub enum RuntimeInstance {
    App(Box<dyn Rustlet>),
    SecurityDomain(Box<dyn RustletSecurityDomain>),
}

impl RuntimeInstance {
    fn process_apdu(&mut self, ctx: &mut RustletCtx) -> ApduStatus {
        match self {
            RuntimeInstance::App(instance) => instance.process_apdu(ctx),
            RuntimeInstance::SecurityDomain(instance) => instance.process_apdu(ctx),
        }
    }

    fn load_state(&mut self, state: &[u8]) -> Result<(), ApduStatus> {
        match self {
            RuntimeInstance::App(instance) => instance.load_state(state),
            RuntimeInstance::SecurityDomain(instance) => instance.load_state(state),
        }
    }

    fn save_state(&self, out: &mut [u8]) -> Result<usize, ApduStatus> {
        match self {
            RuntimeInstance::App(instance) => instance.save_state(out),
            RuntimeInstance::SecurityDomain(instance) => instance.save_state(out),
        }
    }

    fn as_security_domain_mut(&mut self) -> Option<&mut dyn RustletSecurityDomain> {
        match self {
            RuntimeInstance::App(_) => None,
            RuntimeInstance::SecurityDomain(instance) => Some(instance.as_mut()),
        }
    }

    fn security_domain_administrative_state(
        &self,
    ) -> Option<crate::SecurityDomainAdministrativeState> {
        match self {
            RuntimeInstance::App(_) => None,
            RuntimeInstance::SecurityDomain(instance) => Some(instance.administrative_state()),
        }
    }
}

#[doc(hidden)]
pub trait DeclareAppWithoutInstallRequiresDefault: Sized {
    fn implicit_install(ctx: &mut RustletCtx) -> Result<Self, ApduStatus>;
}

impl<T> DeclareAppWithoutInstallRequiresDefault for T
where
    T: Default,
{
    fn implicit_install(ctx: &mut RustletCtx) -> Result<Self, ApduStatus> {
        ctx.clear_response();
        Ok(Self::default())
    }
}

struct RuntimeState {
    install: Option<InstallFn>,
    load: Option<LoadFn>,
    instance: Option<RuntimeInstance>,
}

impl RuntimeState {
    const fn new() -> Self {
        Self {
            install: None,
            load: None,
            instance: None,
        }
    }
}

struct SyscallAllocator;

unsafe impl GlobalAlloc for SyscallAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        crate::syscall::runtime::allocator::alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        crate::syscall::runtime::allocator::dealloc(ptr, layout);
    }
}

#[global_allocator]
static ALLOCATOR: SyscallAllocator = SyscallAllocator;

#[repr(C)]
struct RuntimeGlobals {
    state: RuntimeState,
    vtable: SelectedAppVtable,
    security_domain_vtable: SelectedSecurityDomainVtable,
    descriptor: SelectedAppDescriptor,
    active_ctx: *mut RustletCtx,
}

impl RuntimeGlobals {
    const fn new() -> Self {
        Self {
            state: RuntimeState::new(),
            vtable: SelectedAppVtable {
                install: install_handler,
                process_apdu: process_apdu_handler,
            },
            security_domain_vtable: SelectedSecurityDomainVtable {
                sddispatch: security_domain_dispatch_handler,
            },
            descriptor: SelectedAppDescriptor {
                state: ptr::null_mut(),
                vtable: ptr::null(),
                security_domain_vtable: ptr::null(),
                heap: RustletHeapRegion {
                    storage_start: ptr::null_mut(),
                    storage_len: 0,
                },
            },
            active_ctx: ptr::null_mut(),
        }
    }

    fn initialize(
        &mut self,
        install: InstallFn,
        load: LoadFn,
        heap: RustletHeapRegion,
        security_domain_vtable: *const SelectedSecurityDomainVtable,
    ) -> *const SelectedAppDescriptor {
        unsafe {
            ptr::write(
                core::ptr::addr_of_mut!(self.state),
                RuntimeState {
                    install: Some(install),
                    load: Some(load),
                    instance: None,
                },
            );
            ptr::write(
                core::ptr::addr_of_mut!(self.descriptor),
                SelectedAppDescriptor {
                    state: core::ptr::addr_of_mut!(self.state).cast::<c_void>(),
                    vtable: core::ptr::addr_of!(self.vtable),
                    security_domain_vtable,
                    heap,
                },
            );
        }
        core::ptr::addr_of!(self.descriptor)
    }

    fn set_active_ctx(&mut self, ctx: *mut RustletCtx) {
        self.active_ctx = ctx;
    }

    fn write_active_status(&mut self, status: ApduStatus) {
        if let Some(ctx) = unsafe { self.active_ctx.as_mut() } {
            ctx.set_status(status);
        }
    }
}

static mut RUNTIME: RuntimeGlobals = RuntimeGlobals::new();

const RUSTLET_HEAP_ALIGNMENT: usize = 8;

fn align_up(value: usize, align: usize) -> usize {
    let mask = align - 1;
    (value + mask) & !mask
}

fn align_down(value: usize, align: usize) -> usize {
    value & !(align - 1)
}

fn align_heap_region(storage_start: *mut u8, storage_len: usize) -> RustletHeapRegion {
    let aligned_start = align_up(storage_start as usize, RUSTLET_HEAP_ALIGNMENT);
    let padding = aligned_start.saturating_sub(storage_start as usize);
    let aligned_len = align_down(storage_len.saturating_sub(padding), RUSTLET_HEAP_ALIGNMENT);

    RustletHeapRegion {
        storage_start: aligned_start as *mut u8,
        storage_len: aligned_len,
    }
}

fn start_with_security_domain_vtable(
    install: InstallFn,
    load: LoadFn,
    security_domain_vtable: *const SelectedSecurityDomainVtable,
    _ctx: *mut RustletCtx,
    heap_storage_start: *mut u8,
    heap_storage_len: usize,
) -> ! {
    let heap = align_heap_region(heap_storage_start, heap_storage_len);

    let descriptor = unsafe {
        (&mut *core::ptr::addr_of_mut!(RUNTIME)).initialize(
            install,
            load,
            heap,
            security_domain_vtable,
        )
    };

    crate::syscall::runtime::descriptor_return::trigger(descriptor)
}

pub fn start(
    install: InstallFn,
    load: LoadFn,
    ctx: *mut RustletCtx,
    heap_storage_start: *mut u8,
    heap_storage_len: usize,
) -> ! {
    start_with_security_domain_vtable(
        install,
        load,
        ptr::null(),
        ctx,
        heap_storage_start,
        heap_storage_len,
    )
}

pub fn start_security_domain(
    install: InstallFn,
    load: LoadFn,
    ctx: *mut RustletCtx,
    heap_storage_start: *mut u8,
    heap_storage_len: usize,
) -> ! {
    let security_domain_vtable =
        unsafe { core::ptr::addr_of!((*core::ptr::addr_of!(RUNTIME)).security_domain_vtable) };
    start_with_security_domain_vtable(
        install,
        load,
        security_domain_vtable,
        ctx,
        heap_storage_start,
        heap_storage_len,
    )
}

unsafe extern "C" fn install_handler(state: *mut c_void, buffer: *mut RustletCtx) -> u32 {
    let state = &mut *state.cast::<RuntimeState>();
    let ctx = &mut *buffer;
    ctx.clear_response();

    if state.instance.is_some() {
        let status = ApduStatus::conditions_not_satisfied();
        ctx.set_status(status);
        return status.to_word();
    }

    let Some(install) = state.install else {
        ctx.set_status(ApduStatus::internal_error());
        return ApduStatus::internal_error().to_word();
    };

    set_active_ctx(ctx as *mut RustletCtx);
    let result = match install(ctx) {
        Ok(instance) => {
            state.instance = Some(instance);
            let save_status = save_current_instance(state, ctx);
            if save_status.sw1 == 0x90 && save_status.sw2 == 0x00 {
                save_status
            } else {
                save_status
            }
        }
        Err(status) => status,
    };
    set_active_ctx(ptr::null_mut());
    ctx.set_status(result);
    crate::syscall::runtime::handler_return::trigger(result)
}

unsafe extern "C" fn process_apdu_handler(state: *mut c_void, buffer: *mut RustletCtx) -> u32 {
    let state = &mut *state.cast::<RuntimeState>();
    let ctx = &mut *buffer;
    ctx.clear_response();

    if let Err(status) = ensure_instance_loaded(state, ctx) {
        ctx.set_status(status);
        crate::syscall::runtime::exit::trigger(status)
    }

    let Some(instance) = state.instance.as_mut() else {
        ctx.set_status(ApduStatus::conditions_not_satisfied());
        crate::syscall::runtime::exit::trigger(ApduStatus::conditions_not_satisfied())
    };

    set_active_ctx(ctx as *mut RustletCtx);
    let status = instance.process_apdu(ctx);
    set_active_ctx(ptr::null_mut());
    let save_status = save_current_instance(state, ctx);
    let status = if save_status.sw1 == 0x90 && save_status.sw2 == 0x00 {
        status
    } else {
        save_status
    };
    ctx.set_status(status);
    crate::syscall::runtime::handler_return::trigger(status)
}

unsafe extern "C" fn security_domain_dispatch_handler(
    state: *mut c_void,
    buffer: *mut RustletCtx,
) -> u32 {
    let state = &mut *state.cast::<RuntimeState>();
    let ctx = &mut *buffer;
    ctx.clear_response();
    if let Err(status) = ensure_instance_loaded(state, ctx) {
        ctx.set_status(status);
        crate::syscall::runtime::exit::trigger(status)
    }

    let Some(instance) = state.instance.as_mut() else {
        let status = ApduStatus::conditions_not_satisfied();
        ctx.set_status(status);
        crate::syscall::runtime::exit::trigger(status)
    };
    if ctx.sddispatch_opcode() == crate::SddispatchOpcode::GET_ADMINISTRATIVE_STATE {
        let Some(administrative_state) = instance.security_domain_administrative_state() else {
            let status = ApduStatus::conditions_not_satisfied();
            ctx.set_status(status);
            crate::syscall::runtime::exit::trigger(status)
        };
        let encoded = administrative_state.privileges().encoded_bytes();
        let len = administrative_state.privileges().encoded_len() as u8;
        let status = ctx.set_sddispatch_bytes_result(&[
            len,
            encoded[0],
            encoded[1],
            encoded[2],
            administrative_state.lifecycle().as_byte(),
        ]);
        crate::syscall::runtime::handler_return::trigger(status)
    }

    let Some(security_domain) = instance.as_security_domain_mut() else {
        let status = ApduStatus::conditions_not_satisfied();
        ctx.set_status(status);
        crate::syscall::runtime::exit::trigger(status)
    };

    let status = match ctx.sddispatch_opcode() {
        crate::SddispatchOpcode::INSTALL_FOR_LOAD => {
            dispatch_install_for_load(security_domain, ctx)
        }
        crate::SddispatchOpcode::INSTALL_FOR_INSTALL => {
            dispatch_install_for_install(security_domain, ctx)
        }
        crate::SddispatchOpcode::DELETE_AID => dispatch_delete_aid(security_domain, ctx),
        crate::SddispatchOpcode::GET_DATA => dispatch_get_data(security_domain, ctx),
        crate::SddispatchOpcode::PUT_KEY => dispatch_put_key(security_domain, ctx),
        crate::SddispatchOpcode::STORE_DATA => dispatch_store_data(security_domain, ctx),
        crate::SddispatchOpcode::SET_STATUS => dispatch_set_status(security_domain, ctx),
        crate::SddispatchOpcode::MAY_MANAGE_APPLET => {
            dispatch_may_manage_applet(security_domain, ctx)
        }
        crate::SddispatchOpcode::MAY_MAKE_SELECTABLE => {
            dispatch_may_make_selectable(security_domain, ctx)
        }
        crate::SddispatchOpcode::SUPPORTS_SCP03 => {
            ctx.set_sddispatch_bool_result(security_domain.supports_scp03())
        }
        crate::SddispatchOpcode::SUPPORTS_SCP11A => {
            ctx.set_sddispatch_bool_result(security_domain.supports_scp11a())
        }
        crate::SddispatchOpcode::SUPPORTS_SCP11B => {
            ctx.set_sddispatch_bool_result(security_domain.supports_scp11b())
        }
        crate::SddispatchOpcode::SUPPORTS_SCP11C => {
            ctx.set_sddispatch_bool_result(security_domain.supports_scp11c())
        }
        crate::SddispatchOpcode::SCP11_STAGE_OCE_CERTIFICATE => {
            dispatch_scp11_stage_oce_certificate(security_domain, ctx)
        }
        crate::SddispatchOpcode::SCP11A_MUTUAL_AUTHENTICATE => {
            dispatch_scp11a_mutual_authenticate(security_domain, ctx)
        }
        crate::SddispatchOpcode::SCP11B_INTERNAL_AUTHENTICATE => {
            dispatch_scp11b_internal_authenticate(security_domain, ctx)
        }
        crate::SddispatchOpcode::SCP11C_MUTUAL_AUTHENTICATE => {
            dispatch_scp11c_mutual_authenticate(security_domain, ctx)
        }
        crate::SddispatchOpcode::INITIALIZE_UPDATE => {
            dispatch_initialize_update(security_domain, ctx)
        }
        crate::SddispatchOpcode::EXTERNAL_AUTHENTICATE => {
            dispatch_external_authenticate(security_domain, ctx)
        }
        crate::SddispatchOpcode::CURRENT_SECURITY_LEVEL => {
            ctx.set_sddispatch_u8_result(security_domain.current_security_level().bits())
        }
        crate::SddispatchOpcode::SECURE_CHANNEL_OPEN => {
            ctx.set_sddispatch_bool_result(security_domain.secure_channel_open())
        }
        crate::SddispatchOpcode::CURRENT_MAC_LEN => {
            ctx.set_sddispatch_u16_result(security_domain.current_mac_len() as u16)
        }
        crate::SddispatchOpcode::UNWRAP_COMMAND => dispatch_unwrap_command(security_domain, ctx),
        crate::SddispatchOpcode::WRAP_RESPONSE => dispatch_wrap_response(security_domain, ctx),
        crate::SddispatchOpcode::CLAIM_DELEGATED_SECURE_CHANNEL => {
            dispatch_claim_delegated_secure_channel(security_domain, ctx)
        }
        crate::SddispatchOpcode::HANDLE_DELEGATED_SECURE_CHANNEL => {
            dispatch_handle_delegated_secure_channel(security_domain, ctx)
        }
        crate::SddispatchOpcode::RESET_SECURE_CHANNEL => {
            security_domain.reset_secure_channel();
            ctx.set_sddispatch_empty_result()
        }
        _ => ctx.reject_sddispatch(ApduStatus::instruction_not_supported()),
    };
    let save_status = save_current_instance(state, ctx);
    let status = if save_status.sw1 == 0x90 && save_status.sw2 == 0x00 {
        status
    } else {
        save_status
    };
    ctx.set_status(status);
    crate::syscall::runtime::handler_return::trigger(status)
}

fn dispatch_claim_delegated_secure_channel(
    security_domain: &mut dyn RustletSecurityDomain,
    ctx: &mut RustletCtx,
) -> ApduStatus {
    let request = ctx.sddispatch_request();
    if request.len() != 5 {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    }
    let header = crate::DelegatedSecureChannelHeader {
        cla: request[0],
        ins: request[1],
        p1: request[2],
        p2: request[3],
        p3: request[4],
    };
    ctx.set_sddispatch_bool_result(security_domain.claims_delegated_secure_channel_command(header))
}

fn dispatch_handle_delegated_secure_channel(
    security_domain: &mut dyn RustletSecurityDomain,
    ctx: &mut RustletCtx,
) -> ApduStatus {
    let staged: Vec<u8> = ctx.sddispatch_request().to_vec();
    if staged.len() < 5 {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    }
    let command = crate::DelegatedSecureChannelCommand {
        header: crate::DelegatedSecureChannelHeader {
            cla: staged[0],
            ins: staged[1],
            p1: staged[2],
            p2: staged[3],
            p3: staged[4],
        },
        data: &staged[5..],
    };
    let mut out = [0u8; crate::APDU_BUFFER_CAPACITY];
    match security_domain.handle_delegated_secure_channel_command(ctx, &command, &mut out) {
        Ok(len) if len <= crate::APDU_PAYLOAD_LENGTH_MAX => {
            ctx.data[..len].copy_from_slice(&out[..len]);
            ctx.publish_sddispatch_staged_bytes(len)
        }
        Ok(_) => ctx.reject_sddispatch(ApduStatus::wrong_length()),
        Err(status) => ctx.reject_sddispatch(status),
    }
}

fn dispatch_install_for_load(
    security_domain: &mut dyn RustletSecurityDomain,
    ctx: &mut RustletCtx,
) -> ApduStatus {
    let request = ctx.sddispatch_request();
    let Some((package_aid, offset)) = read_aid(request, 0) else {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    };
    let Some((load_parameters, offset)) = read_lv(request, offset) else {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    };
    if offset != request.len() {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    }

    let command = InstallForLoad {
        package_aid,
        load_parameters,
    };
    match security_domain.install_for_load(&command) {
        Ok(()) => ctx.set_sddispatch_empty_result(),
        Err(status) => ctx.reject_sddispatch(status),
    }
}

fn dispatch_install_for_install(
    security_domain: &mut dyn RustletSecurityDomain,
    ctx: &mut RustletCtx,
) -> ApduStatus {
    let request = ctx.sddispatch_request();
    let Some((package_aid, offset)) = read_aid(request, 0) else {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    };
    let Some((applet_aid, offset)) = read_aid(request, offset) else {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    };
    let Some((instance_aid, offset)) = read_aid(request, offset) else {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    };
    let Some((privileges, offset)) = read_lv(request, offset) else {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    };
    let Some((install_parameters, offset)) = read_lv(request, offset) else {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    };
    if offset != request.len() {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    }
    let Ok(decoded_privileges) = SecurityDomainPrivileges::from_install_bytes(privileges) else {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    };

    let command = InstallForInstall {
        package_aid,
        applet_aid,
        instance_aid,
        privilege_bytes: privileges,
        privileges: decoded_privileges,
        install_parameters,
    };
    match security_domain.install_for_install(&command) {
        Ok(()) => ctx.set_sddispatch_bool_result(true),
        Err(status) => ctx.reject_sddispatch(status),
    }
}

fn dispatch_may_manage_applet(
    security_domain: &mut dyn RustletSecurityDomain,
    ctx: &mut RustletCtx,
) -> ApduStatus {
    let request = ctx.sddispatch_request();
    let Some((package_aid, offset)) = read_aid(request, 0) else {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    };
    let Some((applet_aid, offset)) = read_aid(request, offset) else {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    };
    let Some((instance_aid, offset)) = read_aid(request, offset) else {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    };
    if offset != request.len() {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    }

    ctx.set_sddispatch_bool_result(security_domain.may_manage_applet(
        &package_aid,
        &applet_aid,
        &instance_aid,
    ))
}

fn dispatch_may_make_selectable(
    security_domain: &mut dyn RustletSecurityDomain,
    ctx: &mut RustletCtx,
) -> ApduStatus {
    let request = ctx.sddispatch_request();
    let Some((instance_aid, offset)) = read_aid(request, 0) else {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    };
    if offset != request.len() {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    }

    ctx.set_sddispatch_bool_result(security_domain.may_make_selectable(&instance_aid))
}

fn dispatch_delete_aid(
    security_domain: &mut dyn RustletSecurityDomain,
    ctx: &mut RustletCtx,
) -> ApduStatus {
    let request = ctx.sddispatch_request();
    let Some((aid, offset)) = read_aid(request, 0) else {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    };
    if offset != request.len() {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    }

    match security_domain.delete_aid(&aid) {
        Ok(()) => ctx.set_sddispatch_empty_result(),
        Err(status) => ctx.reject_sddispatch(status),
    }
}

fn dispatch_get_data(
    security_domain: &mut dyn RustletSecurityDomain,
    ctx: &mut RustletCtx,
) -> ApduStatus {
    let request = ctx.sddispatch_request();
    if request.len() != 2 {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    }

    let tag = crate::GetDataTag(((request[0] as u16) << 8) | request[1] as u16);
    match security_domain.get_data(tag, &mut ctx.data) {
        Ok(len) => {
            if len > crate::APDU_PAYLOAD_LENGTH_MAX {
                ctx.reject_sddispatch(ApduStatus::wrong_length())
            } else {
                ctx.publish_sddispatch_staged_bytes(len)
            }
        }
        Err(status) => ctx.reject_sddispatch(status),
    }
}

fn dispatch_put_key(
    security_domain: &mut dyn RustletSecurityDomain,
    ctx: &mut RustletCtx,
) -> ApduStatus {
    let request = ctx.sddispatch_request();
    if request.len() < 2 {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    }

    let command = crate::PutKey {
        key_version: request[0],
        key_id: request[1],
        key_data: &request[2..],
    };
    match security_domain.put_key(&command) {
        Ok(()) => ctx.set_sddispatch_empty_result(),
        Err(status) => ctx.reject_sddispatch(status),
    }
}

fn dispatch_store_data(
    security_domain: &mut dyn RustletSecurityDomain,
    ctx: &mut RustletCtx,
) -> ApduStatus {
    let request = ctx.sddispatch_request();
    if request.len() < 2 {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    }

    let command = crate::StoreData {
        tag: ((request[0] as u16) << 8) | request[1] as u16,
        data: &request[2..],
    };
    match security_domain.store_data(&command) {
        Ok(()) => ctx.set_sddispatch_empty_result(),
        Err(status) => ctx.reject_sddispatch(status),
    }
}

fn dispatch_set_status(
    security_domain: &mut dyn RustletSecurityDomain,
    ctx: &mut RustletCtx,
) -> ApduStatus {
    let request = ctx.sddispatch_request();
    if request.len() < 3 {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    }
    let Some((target_aid, offset)) = read_aid(request, 2) else {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    };
    if offset != request.len() {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    }

    let command = crate::SetStatus {
        target_kind: request[0],
        target_state: request[1],
        target_aid,
    };
    match security_domain.set_status(&command) {
        Ok(()) => ctx.set_sddispatch_empty_result(),
        Err(status) => ctx.reject_sddispatch(status),
    }
}

fn dispatch_initialize_update(
    security_domain: &mut dyn RustletSecurityDomain,
    ctx: &mut RustletCtx,
) -> ApduStatus {
    let request = ctx.sddispatch_request();
    if request.len() < 2 {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    }

    let staged: Vec<u8> = request.to_vec();
    if staged.len() > crate::APDU_PAYLOAD_LENGTH_MAX {
        return ctx.reject_sddispatch(ApduStatus::wrong_length());
    }
    let command = crate::InitializeUpdate {
        key_version: staged[0],
        key_id: staged[1],
        host_challenge: &staged[2..],
    };
    let mut out = [0u8; crate::APDU_BUFFER_CAPACITY];
    match security_domain.initialize_update(ctx, &command, &mut out) {
        Ok(len) => {
            if len > crate::APDU_PAYLOAD_LENGTH_MAX {
                ctx.reject_sddispatch(ApduStatus::wrong_length())
            } else {
                ctx.data[..len].copy_from_slice(&out[..len]);
                ctx.publish_sddispatch_staged_bytes(len)
            }
        }
        Err(status) => ctx.reject_sddispatch(status),
    }
}

fn dispatch_external_authenticate(
    security_domain: &mut dyn RustletSecurityDomain,
    ctx: &mut RustletCtx,
) -> ApduStatus {
    let request = ctx.sddispatch_request();
    if request.len() < 3 {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    }

    let staged: Vec<u8> = request.to_vec();
    if staged.len() > crate::APDU_PAYLOAD_LENGTH_MAX {
        return ctx.reject_sddispatch(ApduStatus::wrong_length());
    }
    let command = crate::ExternalAuthenticate {
        cla: staged[0],
        security_level: SecurityLevel::from_bits(staged[1]),
        p2: staged[2],
        authentication_data: &staged[3..],
    };
    match security_domain.external_authenticate(ctx, &command) {
        Ok(security_level) => ctx.set_sddispatch_u8_result(security_level.bits()),
        Err(status) => ctx.reject_sddispatch(status),
    }
}

fn dispatch_scp11_stage_oce_certificate(
    security_domain: &mut dyn RustletSecurityDomain,
    ctx: &mut RustletCtx,
) -> ApduStatus {
    let request = ctx.sddispatch_request();
    let staged: Vec<u8> = request.to_vec();
    if staged.len() < 2 {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    }
    let Some((public_key, offset)) = read_lv(&staged, 2) else {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    };
    let Some((subject_id, offset)) = read_lv(&staged, offset) else {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    };
    let Some((discretionary_data, offset)) = read_lv(&staged, offset) else {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    };
    if offset != staged.len() {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    }
    let certificate = crate::Scp11OceCertificate {
        ca_key_version: staged[0],
        ca_key_id: staged[1],
        public_key,
        subject_id,
        discretionary_data,
    };
    match security_domain.scp11_stage_oce_certificate(ctx, &certificate) {
        Ok(()) => ctx.set_sddispatch_empty_result(),
        Err(status) => ctx.reject_sddispatch(status),
    }
}

fn dispatch_scp11a_mutual_authenticate(
    security_domain: &mut dyn RustletSecurityDomain,
    ctx: &mut RustletCtx,
) -> ApduStatus {
    let request = ctx.sddispatch_request();
    if request.len() < 6 || request[2] > 1 {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    }
    let staged: Vec<u8> = request.to_vec();
    let Some((host_id, offset)) = read_lv(&staged, 6) else {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    };
    let Some((host_ephemeral_public, offset)) = read_lv(&staged, offset) else {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    };
    if offset != staged.len() {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    }
    let command = crate::Scp11aMutualAuthenticate {
        ecka_key_version: staged[0],
        ecka_key_id: staged[1],
        include_identifiers: staged[2] != 0,
        key_usage_qualifier: staged[3],
        key_type: staged[4],
        key_length: staged[5],
        host_id,
        host_ephemeral_public,
    };
    let mut out = [0u8; crate::APDU_BUFFER_CAPACITY];
    match security_domain.scp11a_mutual_authenticate(ctx, &command, &mut out) {
        Ok(len) => {
            if len > crate::APDU_PAYLOAD_LENGTH_MAX {
                ctx.reject_sddispatch(ApduStatus::wrong_length())
            } else {
                ctx.data[..len].copy_from_slice(&out[..len]);
                ctx.publish_sddispatch_staged_bytes(len)
            }
        }
        Err(status) => ctx.reject_sddispatch(status),
    }
}

fn dispatch_scp11b_internal_authenticate(
    security_domain: &mut dyn RustletSecurityDomain,
    ctx: &mut RustletCtx,
) -> ApduStatus {
    let request = ctx.sddispatch_request();
    if request.len() < 6 || request[2] > 1 {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    }
    let staged: Vec<u8> = request.to_vec();
    let Some((host_id, offset)) = read_lv(&staged, 6) else {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    };
    let Some((host_ephemeral_public, offset)) = read_lv(&staged, offset) else {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    };
    if offset != staged.len() {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    }
    let command = crate::Scp11bInternalAuthenticate {
        ecka_key_version: staged[0],
        ecka_key_id: staged[1],
        include_identifiers: staged[2] != 0,
        key_usage_qualifier: staged[3],
        key_type: staged[4],
        key_length: staged[5],
        host_id,
        host_ephemeral_public,
    };
    let mut out = [0u8; crate::APDU_BUFFER_CAPACITY];
    match security_domain.scp11b_internal_authenticate(ctx, &command, &mut out) {
        Ok(len) => {
            if len > crate::APDU_PAYLOAD_LENGTH_MAX {
                ctx.reject_sddispatch(ApduStatus::wrong_length())
            } else {
                ctx.data[..len].copy_from_slice(&out[..len]);
                ctx.publish_sddispatch_staged_bytes(len)
            }
        }
        Err(status) => ctx.reject_sddispatch(status),
    }
}

fn dispatch_scp11c_mutual_authenticate(
    security_domain: &mut dyn RustletSecurityDomain,
    ctx: &mut RustletCtx,
) -> ApduStatus {
    let request = ctx.sddispatch_request();
    if request.len() < 6 || request[2] > 1 {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    }
    let staged: Vec<u8> = request.to_vec();
    let Some((host_id, offset)) = read_lv(&staged, 6) else {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    };
    let Some((host_ephemeral_public, offset)) = read_lv(&staged, offset) else {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    };
    if offset != staged.len() {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    }
    let command = crate::Scp11cMutualAuthenticate {
        ecka_key_version: staged[0],
        ecka_key_id: staged[1],
        include_identifiers: staged[2] != 0,
        key_usage_qualifier: staged[3],
        key_type: staged[4],
        key_length: staged[5],
        host_id,
        host_ephemeral_public,
    };
    let mut out = [0u8; crate::APDU_BUFFER_CAPACITY];
    match security_domain.scp11c_mutual_authenticate(ctx, &command, &mut out) {
        Ok(len) => {
            if len > crate::APDU_PAYLOAD_LENGTH_MAX {
                ctx.reject_sddispatch(ApduStatus::wrong_length())
            } else {
                ctx.data[..len].copy_from_slice(&out[..len]);
                ctx.publish_sddispatch_staged_bytes(len)
            }
        }
        Err(status) => ctx.reject_sddispatch(status),
    }
}

fn dispatch_unwrap_command(
    security_domain: &mut dyn RustletSecurityDomain,
    ctx: &mut RustletCtx,
) -> ApduStatus {
    let request = ctx.sddispatch_request();
    if request.len() < 6 {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    }

    let staged: Vec<u8> = request.to_vec();
    if staged.len() > crate::APDU_PAYLOAD_LENGTH_MAX {
        return ctx.reject_sddispatch(ApduStatus::wrong_length());
    }

    let authenticated_len = ((staged[0] as usize) << 8) | staged[1] as usize;
    let data_len = ((staged[2] as usize) << 8) | staged[3] as usize;
    let mac_len = ((staged[4] as usize) << 8) | staged[5] as usize;
    let Some(authenticated_end) = 6usize.checked_add(authenticated_len) else {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    };
    let Some(data_end) = authenticated_end.checked_add(data_len) else {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    };
    let Some(mac_end) = data_end.checked_add(mac_len) else {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    };
    if mac_end != request.len() {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    }

    let command = crate::WrappedCommand {
        authenticated: &staged[6..authenticated_end],
        data: &staged[authenticated_end..data_end],
        mac: &staged[data_end..mac_end],
    };
    if command.authenticated.len() != authenticated_len || command.data.len() != data_len {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    }

    let mut out = [0u8; crate::APDU_BUFFER_CAPACITY];
    match security_domain.unwrap_command(ctx, &command, &mut out) {
        Ok(len) => {
            if len > crate::APDU_PAYLOAD_LENGTH_MAX {
                ctx.reject_sddispatch(ApduStatus::wrong_length())
            } else {
                ctx.data[..len].copy_from_slice(&out[..len]);
                ctx.publish_sddispatch_staged_bytes(len)
            }
        }
        Err(status) => ctx.reject_sddispatch(status),
    }
}

fn dispatch_wrap_response(
    security_domain: &mut dyn RustletSecurityDomain,
    ctx: &mut RustletCtx,
) -> ApduStatus {
    let request = ctx.sddispatch_request();
    if request.len() < 4 {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    }

    let staged: Vec<u8> = request.to_vec();
    if staged.len() > crate::APDU_PAYLOAD_LENGTH_MAX {
        return ctx.reject_sddispatch(ApduStatus::wrong_length());
    }

    let data_len = ((staged[0] as usize) << 8) | staged[1] as usize;
    let sw1 = staged[2];
    let sw2 = staged[3];
    let Some(end) = 4usize.checked_add(data_len) else {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    };
    if end != request.len() {
        return ctx.reject_sddispatch(ApduStatus::wrong_data());
    }

    let response = crate::PlainResponse {
        data: &staged[4..end],
        status: ApduStatus { sw1, sw2 },
    };
    let mut out = [0u8; crate::APDU_BUFFER_CAPACITY];
    match security_domain.wrap_response(ctx, &response, &mut out) {
        Ok(len) => {
            if len > crate::APDU_PAYLOAD_LENGTH_MAX {
                ctx.reject_sddispatch(ApduStatus::wrong_length())
            } else {
                ctx.data[..len].copy_from_slice(&out[..len]);
                ctx.publish_sddispatch_staged_bytes(len)
            }
        }
        Err(status) => ctx.reject_sddispatch(status),
    }
}

fn read_aid(data: &[u8], offset: usize) -> Option<(crate::Aid, usize)> {
    let (value, offset) = read_lv(data, offset)?;
    Some((crate::Aid::new(value), offset))
}

fn read_lv(data: &[u8], offset: usize) -> Option<(&[u8], usize)> {
    let len = *data.get(offset)? as usize;
    let start = offset.checked_add(1)?;
    let end = start.checked_add(len)?;
    if end > data.len() {
        return None;
    }
    Some((&data[start..end], end))
}

fn ensure_instance_loaded(
    state: &mut RuntimeState,
    ctx: &mut RustletCtx,
) -> Result<(), ApduStatus> {
    if state.instance.is_some() {
        return Ok(());
    }

    let Some(load) = state.load else {
        return Err(ApduStatus::internal_error());
    };
    match load(ctx).and_then(|mut instance| {
        instance.load_state(ctx.state_bytes())?;
        Ok(instance)
    }) {
        Ok(instance) => {
            state.instance = Some(instance);
            Ok(())
        }
        Err(status) => Err(status),
    }
}

fn save_current_instance(state: &mut RuntimeState, ctx: &mut RustletCtx) -> ApduStatus {
    let Some(instance) = state.instance.as_mut() else {
        return ApduStatus::conditions_not_satisfied();
    };

    // Ordinary Rustlets have no volatile state across APDUs: the serialized
    // representation is authoritative. Drop their instance while the kernel
    // allocator binding is still active so the kernel may securely scrub the
    // entire Rustlet heap immediately after this handler returns. Security
    // Domains remain resident because their secure-channel session material is
    // intentionally excluded from serialization.
    let drop_after_save = instance.as_security_domain_mut().is_none();

    ctx.clear_state();
    let capacity = ctx.state_bytes_mut().len();
    let len = match instance.save_state(ctx.state_bytes_mut()) {
        Ok(len) if len <= capacity => len,
        Ok(_) => return ApduStatus::wrong_length(),
        Err(status) => return status,
    };

    if !ctx.set_state_len(len) {
        return ApduStatus::wrong_length();
    }

    if drop_after_save {
        state.instance = None;
    }
    ApduStatus::success()
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    write_active_status(ApduStatus::internal_error());
    crate::syscall::runtime::panic::trigger();
}

#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    write_active_status(ApduStatus::internal_error());
    crate::syscall::runtime::panic::trigger();
}

fn write_active_status(status: ApduStatus) {
    unsafe { (&mut *core::ptr::addr_of_mut!(RUNTIME)).write_active_status(status) };
}

fn set_active_ctx(ctx: *mut RustletCtx) {
    unsafe { (&mut *core::ptr::addr_of_mut!(RUNTIME)).set_active_ctx(ctx) };
}
