use core::alloc::Layout;
use core::ffi::c_void;

use rustlet_runtime::{
    Aid, CryptoCipherDoFinalParams, CryptoEcCurve, CryptoEcGenerateKeypairParams,
    CryptoEcdhDoFinalParams, CryptoErrorCode, CryptoHkdfSha256Params, CryptoMacDoFinalParams,
    CryptoMacOperation, CryptoRandomGenerateParams, CryptoX963Sha256Params, RustletCtx, SEApdu,
    SEApduHeader, Scp03LoadKeyParams, SddispatchOpcode, SelectedAppDescriptor, SelectedAppVtable,
    SelectedSecurityDomainVtable, INS_INSTALL, SDDISPATCH_BOOL_TRUE, SDDISPATCH_CLA,
};
use sha2::{Digest, Sha256};

use crate::apdu_manager;
use crate::embedded_apps;
use crate::fae_runtime;
use crate::object_registry::{
    InstanceObjectState, KeyObjectState, KeyObjectType, ObjectRegistry, PackageObjectState,
    RegistryObject, SecurityDomainObjectState, DEFAULT_KERNEL_OBJECT_REGISTRY_CAPACITY,
};
pub use crate::object_registry::{ManagedObjectKind, SecurityDomainObjectBackend};
use crate::object_registry_persistence as registry_persistence;

struct LoadedApp {
    registry: AppRegistryReference,
    loaded_fae: fae_runtime::LoadedFae,
    state: *mut c_void,
    vtable: *const SelectedAppVtable,
    #[allow(dead_code)]
    security_domain_vtable: *const SelectedSecurityDomainVtable,
    allocator: oxi_core::core::HeapAllocatorState,
    allocator_metadata: AllocatorMetadata,
}

struct AllocatorMetadata {
    ptr: *mut u8,
    len: usize,
    layout: Layout,
}

impl AllocatorMetadata {
    fn allocate(len: usize) -> Option<Self> {
        let layout = Layout::from_size_align(len, oxi_core::core::ALLOCATION_GRANULE).ok()?;
        let ptr = oxi_core::core::alloc(layout);
        if ptr.is_null() {
            None
        } else {
            Some(Self { ptr, len, layout })
        }
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr
    }

    const fn len(&self) -> usize {
        self.len
    }
}

static mut SELECTED_APP: Option<LoadedApp> = None;
// Invariant: the active Rustlet Security Domain remains resident here while an
// ordinary Rustlet occupies SELECTED_APP. Its volatile SCP state must never be
// reconstructed from the registry between unwrap, dispatch, and wrap.
static mut SELECTED_SECURITY_DOMAIN: Option<LoadedApp> = None;
static mut ACTIVE_SECURITY_DOMAIN_SLOT: Option<usize> = None;
static mut ACTIVE_APP_CALL: Option<ActiveAppCall> = None;
static mut OBJECT_REGISTRY: ObjectRegistry<DEFAULT_KERNEL_OBJECT_REGISTRY_CAPACITY> =
    ObjectRegistry::new();
static mut PERSISTENCE_PAGE_BUFFER: [u8; PERSISTENCE_PAGE_BUFFER_SIZE] =
    [0xFF; PERSISTENCE_PAGE_BUFFER_SIZE];
static mut PERSISTENCE_PAYLOAD_BUFFER: [u8; PERSISTENCE_PAYLOAD_BUFFER_SIZE] =
    [0; PERSISTENCE_PAYLOAD_BUFFER_SIZE];
static mut PERSISTENCE_REGISTRY_ENTRIES: [registry_persistence::PersistentRegistryEntry;
    DEFAULT_KERNEL_OBJECT_REGISTRY_CAPACITY] =
    [registry_persistence::PersistentRegistryEntry::EMPTY; DEFAULT_KERNEL_OBJECT_REGISTRY_CAPACITY];
static mut PERSISTENCE_NEXT_OBJECT_REFS: [Option<registry_persistence::PersistentRef>;
    DEFAULT_KERNEL_OBJECT_REGISTRY_CAPACITY] = [None; DEFAULT_KERNEL_OBJECT_REGISTRY_CAPACITY];
static mut PERSISTENCE_PROTECTED_RANGES: [registry_persistence::PersistentRange;
    PERSISTENCE_MAX_PROTECTED_RANGES] =
    [registry_persistence::PersistentRange::EMPTY; PERSISTENCE_MAX_PROTECTED_RANGES];
static mut PERSISTENCE_RUNTIME_STATE: PersistenceRuntimeState = PersistenceRuntimeState::EMPTY;
static mut PERSISTENCE_BOOTSTRAP_IN_PROGRESS: bool = false;
static mut DYNAMIC_LOAD_CONTEXT: Option<DynamicLoadContext> = None;

const PERSISTENCE_PAGE_BUFFER_SIZE: usize = 4096;
const PERSISTENCE_PAYLOAD_BUFFER_SIZE: usize = 512;
const PERSISTENCE_MAX_PROTECTED_RANGES: usize = DEFAULT_KERNEL_OBJECT_REGISTRY_CAPACITY * 2 + 2;

#[derive(Clone, Copy)]
struct PersistenceRuntimeState {
    initialized: bool,
    latest_registry: Option<registry_persistence::PersistentRange>,
    mutation_counter: u32,
    append_offset: usize,
    object_refs:
        [Option<registry_persistence::PersistentRef>; DEFAULT_KERNEL_OBJECT_REGISTRY_CAPACITY],
}

impl PersistenceRuntimeState {
    const EMPTY: Self = Self {
        initialized: false,
        latest_registry: None,
        mutation_counter: 0,
        append_offset: 0,
        object_refs: [None; DEFAULT_KERNEL_OBJECT_REGISTRY_CAPACITY],
    };
}

impl AppRegistryReference {
    fn pending_install(package: usize) -> Self {
        Self::PendingInstall { package }
    }

    fn from_instance(instance: usize) -> Option<Self> {
        let registry = unsafe { &*core::ptr::addr_of!(OBJECT_REGISTRY) };
        let instance_object = registry.resolve(instance)?;
        let package_aid = instance_object.package_aid()?;
        let package = registry
            .find_index(
                &instance_object.parent_sd_aid,
                ManagedObjectKind::Package,
                &package_aid,
            )
            .or_else(|| {
                registry.find_index(
                    &top_level_parent_sd_aid(),
                    ManagedObjectKind::Package,
                    &package_aid,
                )
            })?;
        Some(Self::Installed { package, instance })
    }

    fn package_index(self) -> usize {
        match self {
            Self::PendingInstall { package, .. } | Self::Installed { package, .. } => package,
        }
    }

    fn instance_index(self) -> Option<usize> {
        match self {
            Self::PendingInstall { .. } => None,
            Self::Installed { instance, .. } => Some(instance),
        }
    }

    fn package_object(self) -> Option<&'static RegistryObject> {
        unsafe { (&*core::ptr::addr_of!(OBJECT_REGISTRY)).resolve(self.package_index()) }
    }

    fn instance_object(self) -> Option<&'static RegistryObject> {
        unsafe { (&*core::ptr::addr_of!(OBJECT_REGISTRY)).resolve(self.instance_index()?) }
    }

    fn security_domain_aid(self) -> Option<Aid> {
        match self {
            Self::PendingInstall { .. } => None,
            Self::Installed { .. } => Some(self.instance_object()?.parent_sd_aid),
        }
    }

    fn package_aid(self) -> Option<Aid> {
        Some(self.package_object()?.object_aid)
    }

    fn applet_aid(self) -> Option<Aid> {
        self.package_object()?.package_applet_aid()
    }

    fn instance_aid(self) -> Option<Aid> {
        match self {
            Self::PendingInstall { .. } => None,
            Self::Installed { .. } => Some(self.instance_object()?.object_aid),
        }
    }

    fn fae(self) -> Option<&'static [u8]> {
        self.package_object()?.package_binary_code()
    }

    fn identity(self) -> Option<(Aid, Aid, Aid, Aid)> {
        Some((
            self.security_domain_aid()?,
            self.package_aid()?,
            self.applet_aid()?,
            self.instance_aid()?,
        ))
    }

    fn is_valid(self) -> bool {
        self.package_object().is_some()
            && match self {
                Self::PendingInstall { .. } => true,
                Self::Installed { .. } => self.instance_object().is_some(),
            }
    }

    fn references_slot(self, slot: usize) -> bool {
        self.package_index() == slot || self.instance_index() == Some(slot)
    }
}

/// In-progress GP `INSTALL [for load]` / `LOAD` transaction.
///
/// The payload is streamed directly into the registry persistence area. The
/// context therefore tracks only the announced metadata, the reserved flash
/// span and the page currently staged in [`PERSISTENCE_PAGE_BUFFER`].
#[derive(Clone, Copy)]
struct DynamicLoadContext {
    authority_aid: Aid,
    target_sd_aid: Aid,
    package_aid: Aid,
    protected: bool,
    expected_hash: [u8; 32],
    expected_size: usize,
    reserved_offset: usize,
    block_total_len: usize,
    bytes_received: usize,
    next_block_number: u8,
    current_page_index: usize,
    current_page_dirty: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AppRegistryReference {
    /// Temporary identity used only while `INSTALL [for install]` creates the
    /// instance that will become the stable registry reference.
    PendingInstall { package: usize },
    /// Normal selected-object identity. Both slot numbers remain stable until
    /// the corresponding objects are deleted.
    Installed { package: usize, instance: usize },
}

#[derive(Clone, Copy)]
struct ActiveAppCall {
    transport: *mut apdu_manager::TransportApdu,
    shared_buffer: *mut RustletCtx,
    shared_window: oxi_core::core::isolation::AppMemoryWindow,
    text_window: oxi_core::core::isolation::AppMemoryWindow,
    data_window: oxi_core::core::isolation::AppMemoryWindow,
    stack_window: oxi_core::core::isolation::AppMemoryWindow,
}

struct RunningSEApdu<'a> {
    transport: &'a mut apdu_manager::TransportApdu,
    shared_buffer: &'a mut RustletCtx,
}

#[derive(Clone, Copy)]
enum CipherMode {
    Encrypt,
    Decrypt,
}

#[derive(Clone, Copy)]
enum CipherAlgorithm {
    Aes128CbcNoPadding,
    Aes256CbcNoPadding,
    Aes128CbcIso9797M2,
    Aes256CbcIso9797M2,
    Aes128EcbNoPadding,
    Aes256EcbNoPadding,
}

#[derive(Clone, Copy)]
enum RandomAlgorithm {
    SecureRandom,
}

#[derive(Clone, Copy)]
enum MacAlgorithm {
    AesCmac,
}

struct ActiveAppCallGuard;

impl ActiveAppCallGuard {
    fn install(
        apdu: &mut apdu_manager::Apdu<'_>,
        loaded: &fae_runtime::LoadedFae,
        allocator: *mut oxi_core::core::HeapAllocatorState,
    ) -> Self {
        let transport = apdu.transport_ptr();
        let shared_buffer = loaded.shared_buffer;
        let shared_start = shared_buffer.as_mut_ptr() as usize;
        set_active_app_call(Some(ActiveAppCall {
            transport,
            shared_buffer: shared_buffer.as_mut_ptr(),
            shared_window: oxi_core::core::isolation::AppMemoryWindow {
                start: shared_start,
                len: rustlet_runtime::APDU_SHARED_REGION_SIZE,
            },
            text_window: loaded.memory_layout.text,
            data_window: loaded.data_window,
            stack_window: loaded.stack_window,
        }));
        oxi_core::core::syscall::set_current_app_allocator(allocator);

        Self
    }

    fn install_shared_only(
        loaded: &fae_runtime::LoadedFae,
        allocator: *mut oxi_core::core::HeapAllocatorState,
    ) -> Self {
        let shared_buffer = loaded.shared_buffer;
        let shared_start = shared_buffer.as_mut_ptr() as usize;
        set_active_app_call(Some(ActiveAppCall {
            transport: core::ptr::null_mut(),
            shared_buffer: shared_buffer.as_mut_ptr(),
            shared_window: oxi_core::core::isolation::AppMemoryWindow {
                start: shared_start,
                len: rustlet_runtime::APDU_SHARED_REGION_SIZE,
            },
            text_window: loaded.memory_layout.text,
            data_window: loaded.data_window,
            stack_window: loaded.stack_window,
        }));
        oxi_core::core::syscall::set_current_app_allocator(allocator);

        Self
    }
}

impl Drop for ActiveAppCallGuard {
    fn drop(&mut self) {
        oxi_core::core::syscall::clear_current_app_allocator();
        set_active_app_call(None);
    }
}

pub fn initialize() {
    initialize_registry();
    oxi_core::core::isolation::initialize_runtime_hooks();
    oxi_core::core::isolation::install_exit_observer(app_exit_observer);
    oxi_core::core::syscall::install_bindings(&RUSTLET_SERVICE_SYSCALLS);
    ensure_predeployment_initialized();
}

const RUSTLET_SERVICE_SYSCALLS: [oxi_core::core::syscall::SyscallBinding; 11] = [
    oxi_core::core::syscall::SyscallBinding {
        number: rustlet_runtime::syscall_abi::APDU_SET_INCOMING_AND_RECEIVE,
        handler: apdu_set_incoming_and_receive_syscall,
    },
    oxi_core::core::syscall::SyscallBinding {
        number: rustlet_runtime::syscall_abi::APDU_SET_OUTGOING,
        handler: apdu_set_outgoing_syscall,
    },
    oxi_core::core::syscall::SyscallBinding {
        number: rustlet_runtime::syscall_abi::APDU_SET_OUTGOING_LENGTH,
        handler: apdu_set_outgoing_length_syscall,
    },
    oxi_core::core::syscall::SyscallBinding {
        number: rustlet_runtime::syscall_abi::CRYPTO_CIPHER_DO_FINAL,
        handler: crypto_cipher_do_final_syscall,
    },
    oxi_core::core::syscall::SyscallBinding {
        number: rustlet_runtime::syscall_abi::CRYPTO_RANDOM_GENERATE,
        handler: crypto_random_generate_syscall,
    },
    oxi_core::core::syscall::SyscallBinding {
        number: rustlet_runtime::syscall_abi::CRYPTO_MAC_DO_FINAL,
        handler: crypto_mac_do_final_syscall,
    },
    oxi_core::core::syscall::SyscallBinding {
        number: rustlet_runtime::syscall_abi::SECURITY_DOMAIN_LOAD_SCP03_KEY,
        handler: security_domain_load_scp03_key_syscall,
    },
    oxi_core::core::syscall::SyscallBinding {
        number: rustlet_runtime::syscall_abi::CRYPTO_EC_GENERATE_KEYPAIR,
        handler: crypto_ec_generate_keypair_syscall,
    },
    oxi_core::core::syscall::SyscallBinding {
        number: rustlet_runtime::syscall_abi::CRYPTO_ECDH_DO_FINAL,
        handler: crypto_ecdh_do_final_syscall,
    },
    oxi_core::core::syscall::SyscallBinding {
        number: rustlet_runtime::syscall_abi::CRYPTO_HKDF_SHA256,
        handler: crypto_hkdf_sha256_syscall,
    },
    oxi_core::core::syscall::SyscallBinding {
        number: rustlet_runtime::syscall_abi::CRYPTO_X963_SHA256,
        handler: crypto_x963_sha256_syscall,
    },
];

fn ensure_predeployment_initialized() {
    if restore_persistent_registry_if_available() {
        set_active_security_domain_instance_aid(crate::predeployment::root_instance_aid());
        return;
    }

    let root_instance_aid = crate::predeployment::root_instance_aid();
    if find_any_object_by_aid_raw(&root_instance_aid).is_none() {
        set_persistence_bootstrap_in_progress(true);
        bootstrap_root_security_domain();
        bootstrap_predeployed_plan();
        set_persistence_bootstrap_in_progress(false);
        publish_persistent_registry_after_predeployment();
    } else {
        set_active_security_domain_instance_aid(root_instance_aid);
    }
}

/// Restores mutable registry objects from the latest valid persistent BOSS.
///
/// Embedded package objects are always seeded first by [`initialize_registry`],
/// so package entries restored from flash are currently treated as descriptive
/// metadata. Mutable Security Domains, instances and keys are reconstructed
/// from their referenced payload blocks.
fn restore_persistent_registry_if_available() -> bool {
    let Some(area_bytes) = persistent_registry_area_bytes() else {
        return false;
    };
    if !registry_persistence::has_persistence_area_marker(area_bytes) {
        return false;
    }
    let page_size = oxi_core::core::flash::logical_page_size();
    let Ok(scan) = registry_persistence::scan_persistence_area(area_bytes, page_size) else {
        return false;
    };
    let Some(boss) = scan.latest_registry else {
        initialize_persistence_runtime_state(None, 0, scan.append_offset);
        return false;
    };

    let registry = unsafe { &mut *core::ptr::addr_of_mut!(OBJECT_REGISTRY) };
    let mut index = 0usize;
    while index < boss.entry_count as usize {
        let Ok(entry) = boss.entry(index) else {
            return false;
        };
        if !restore_persistent_registry_entry(registry, area_bytes, page_size, entry) {
            return false;
        }
        index += 1;
    }
    if !validate_security_domain_registry_topology(registry) {
        registry.clear();
        embedded_apps::for_each_embedded_registry_seed(|seed| {
            let _ = registry.insert_package_object(
                top_level_parent_sd_aid(),
                seed.package_aid,
                seed.applet_aid,
                seed.fae,
            );
        });
        return false;
    }
    initialize_persistence_runtime_state(
        Some(registry_persistence::PersistentRange::new(
            boss.offset,
            boss.total_len,
        )),
        boss.mutation_counter,
        scan.append_offset,
    );
    cache_persistent_registry_refs(registry, boss);
    true
}

fn validate_security_domain_registry_topology(
    registry: &ObjectRegistry<DEFAULT_KERNEL_OBJECT_REGISTRY_CAPACITY>,
) -> bool {
    let root_aid = root_security_domain_instance_aid();
    let empty_parent = top_level_parent_sd_aid();
    let Some(root) = registry.entries().find(|object| {
        object.object_kind == ManagedObjectKind::SecurityDomain && object.object_aid == root_aid
    }) else {
        return false;
    };
    if root.parent_sd_aid != empty_parent {
        return false;
    }

    for domain in registry
        .entries()
        .filter(|object| object.object_kind == ManagedObjectKind::SecurityDomain)
    {
        if domain.object_aid == root_aid {
            continue;
        }
        if domain.parent_sd_aid == empty_parent {
            return false;
        }
        let Some(parent) = registry.entries().find(|candidate| {
            candidate.object_kind == ManagedObjectKind::SecurityDomain
                && candidate.object_aid == domain.parent_sd_aid
        }) else {
            return false;
        };
        let Some(parent_privileges) = parent.security_domain_privilege_bytes().and_then(|bytes| {
            crate::security_domain::SecurityDomainPrivileges::from_install_bytes(&bytes)
        }) else {
            return false;
        };
        let Some(child_privileges) = domain.security_domain_privilege_bytes().and_then(|bytes| {
            crate::security_domain::SecurityDomainPrivileges::from_install_bytes(&bytes)
        }) else {
            return false;
        };
        if !parent_privileges.contains(child_privileges) {
            return false;
        }

        let mut cursor = parent;
        let mut remaining = DEFAULT_KERNEL_OBJECT_REGISTRY_CAPACITY;
        while cursor.object_aid != root_aid {
            if remaining == 0 || cursor.parent_sd_aid == empty_parent {
                return false;
            }
            let Some(next) = registry.entries().find(|candidate| {
                candidate.object_kind == ManagedObjectKind::SecurityDomain
                    && candidate.object_aid == cursor.parent_sd_aid
            }) else {
                return false;
            };
            cursor = next;
            remaining -= 1;
        }
    }
    true
}

fn initialize_persistence_runtime_state(
    latest_registry: Option<registry_persistence::PersistentRange>,
    mutation_counter: u32,
    append_offset: usize,
) {
    let state = unsafe { &mut *core::ptr::addr_of_mut!(PERSISTENCE_RUNTIME_STATE) };
    *state = PersistenceRuntimeState {
        initialized: true,
        latest_registry,
        mutation_counter,
        append_offset,
        object_refs: [None; DEFAULT_KERNEL_OBJECT_REGISTRY_CAPACITY],
    };
}

fn cache_persistent_registry_refs(
    registry: &ObjectRegistry<DEFAULT_KERNEL_OBJECT_REGISTRY_CAPACITY>,
    boss: registry_persistence::RegistryBlockView<'_>,
) {
    let state = unsafe { &mut *core::ptr::addr_of_mut!(PERSISTENCE_RUNTIME_STATE) };
    let mut index = 0usize;
    while index < boss.entry_count as usize {
        if let Ok(entry) = boss.entry(index) {
            if let Some(slot) = registry.find_index(
                &entry.parent_sd_aid.as_aid(),
                runtime_object_kind(entry.kind_word.kind()),
                &entry.object_aid.as_aid(),
            ) {
                state.object_refs[slot] = Some(entry.data_ref);
            }
        }
        index += 1;
    }
}

const fn runtime_object_kind(
    kind: registry_persistence::PersistentObjectKind,
) -> ManagedObjectKind {
    match kind {
        registry_persistence::PersistentObjectKind::SecurityDomain => {
            ManagedObjectKind::SecurityDomain
        }
        registry_persistence::PersistentObjectKind::Package => ManagedObjectKind::Package,
        registry_persistence::PersistentObjectKind::Instance => ManagedObjectKind::Instance,
        registry_persistence::PersistentObjectKind::Key => ManagedObjectKind::Key,
        registry_persistence::PersistentObjectKind::Data => ManagedObjectKind::Data,
    }
}

fn restore_persistent_registry_entry(
    registry: &mut ObjectRegistry<DEFAULT_KERNEL_OBJECT_REGISTRY_CAPACITY>,
    area_bytes: &'static [u8],
    page_size: usize,
    entry: registry_persistence::PersistentRegistryEntry,
) -> bool {
    let object_aid = entry.object_aid.as_aid();
    let parent_sd_aid = entry.parent_sd_aid.as_aid();
    match entry.kind_word.kind() {
        registry_persistence::PersistentObjectKind::Package => {
            if entry.data_ref.space != registry_persistence::PersistentSpace::RegistryFlash {
                // Invariant: predeployed package code is supplied by the
                // firmware image on every boot and is seeded before restore.
                return true;
            }
            let Some(block) = persistent_payload_block(area_bytes, page_size, entry.data_ref)
            else {
                return false;
            };
            if block.magic != registry_persistence::PACKAGE_BLOCK_MAGIC {
                return false;
            }
            if !registry.insert_package_object(parent_sd_aid, object_aid, object_aid, block.payload)
            {
                return false;
            }
            let Ok(package_state) =
                registry_persistence::decode_package_state(entry.kind_word.state_bits())
            else {
                return false;
            };
            registry.set_package_state(&parent_sd_aid, &object_aid, package_state)
        }
        registry_persistence::PersistentObjectKind::SecurityDomain => {
            let Some(block) = persistent_payload_block(area_bytes, page_size, entry.data_ref)
            else {
                return false;
            };
            let Ok(payload) = registry_persistence::decode_security_domain_payload(block.payload)
            else {
                return false;
            };
            if !registry.upsert_security_domain_object(
                parent_sd_aid,
                object_aid,
                payload.package_aid.as_aid(),
                payload.backend,
                payload.privilege_bytes,
                payload.serialized_state,
            ) {
                return false;
            }
            let Ok(object_state) =
                registry_persistence::decode_security_domain_state(entry.kind_word.state_bits())
            else {
                return false;
            };
            registry.set_security_domain_state(&parent_sd_aid, &object_aid, object_state)
        }
        registry_persistence::PersistentObjectKind::Instance => {
            let Some(block) = persistent_payload_block(area_bytes, page_size, entry.data_ref)
            else {
                return false;
            };
            let Ok(payload) = registry_persistence::decode_instance_payload(block.payload) else {
                return false;
            };
            if !registry.upsert_instance_object(
                parent_sd_aid,
                object_aid,
                payload.package_aid.as_aid(),
                payload.serialized_state,
            ) {
                return false;
            }
            let Ok(instance_state) =
                registry_persistence::decode_instance_state(entry.kind_word.state_bits())
            else {
                return false;
            };
            registry.set_instance_state(&parent_sd_aid, &object_aid, instance_state)
        }
        registry_persistence::PersistentObjectKind::Key => {
            let Some(block) = persistent_payload_block(area_bytes, page_size, entry.data_ref)
            else {
                return false;
            };
            let Ok(payload) = registry_persistence::decode_key_payload(block.payload) else {
                return false;
            };
            if !registry.upsert_key_object(
                parent_sd_aid,
                object_aid,
                payload.key_type,
                payload.key_state,
                payload.key_version,
                payload.key_id,
                payload.key_usage,
                payload.raw_key_bytes,
            ) {
                return false;
            }
            let state_bits = entry.kind_word.state_bits();
            if state_bits == 0 {
                return true;
            }
            if state_bits == 1 {
                return registry.set_key_state(&parent_sd_aid, &object_aid, KeyObjectState::Locked);
            }
            false
        }
        registry_persistence::PersistentObjectKind::Data => {
            let Some(block) = persistent_payload_block(area_bytes, page_size, entry.data_ref)
            else {
                return false;
            };
            let Ok(payload) = registry_persistence::decode_data_payload(block.payload) else {
                return false;
            };
            registry.upsert_data_object(parent_sd_aid, object_aid, payload.bytes)
        }
    }
}

fn persistent_payload_block<'a>(
    area_bytes: &'a [u8],
    page_size: usize,
    data_ref: registry_persistence::PersistentRef,
) -> Option<registry_persistence::ObjectBlockView<'a>> {
    if data_ref.space != registry_persistence::PersistentSpace::RegistryFlash {
        return None;
    }
    registry_persistence::decode_object_block_at(area_bytes, data_ref.offset as usize, page_size)
        .ok()
}

/// Publishes a persistent snapshot after manifest predeployment succeeds.
fn publish_persistent_registry_after_predeployment() {
    if oxi_core::core::flash::persistence_area().page_count == 0 {
        return;
    }
    // Invariant: boot must not depend on semihosting. If persistence cannot be
    // published, the volatile registry remains authoritative for this boot and
    // the next boot will replay predeployment because no valid BOSS exists.
    let _ = publish_persistent_registry_snapshot();
}

fn set_persistence_bootstrap_in_progress(value: bool) {
    unsafe {
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(PERSISTENCE_BOOTSTRAP_IN_PROGRESS),
            value,
        );
    }
}

fn persistence_bootstrap_in_progress() -> bool {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(PERSISTENCE_BOOTSTRAP_IN_PROGRESS)) }
}

fn publish_persistent_registry_after_mutation() {
    if persistence_bootstrap_in_progress() {
        return;
    }
    if oxi_core::core::flash::persistence_area().page_count == 0 {
        return;
    }
    // Invariant: runtime mutations are accepted in RAM first, then committed by
    // publishing a new CRC-protected BOSS snapshot. If this write is interrupted,
    // recovery keeps using the previous valid BOSS.
    let _ = publish_persistent_registry_snapshot();
}

fn publish_persistent_registry_snapshot() -> bool {
    let Some(area_bytes) = persistent_registry_area_bytes() else {
        return false;
    };
    let page_size = oxi_core::core::flash::logical_page_size();
    if page_size == 0 || page_size > PERSISTENCE_PAGE_BUFFER_SIZE {
        return false;
    }

    if !ensure_persistence_area_initialized(area_bytes, page_size) {
        return false;
    }
    if !ensure_persistence_runtime_state(area_bytes, page_size) {
        return false;
    }

    let runtime_state = unsafe { *core::ptr::addr_of!(PERSISTENCE_RUNTIME_STATE) };
    let latest_boss = runtime_state.latest_registry.and_then(|range| {
        registry_persistence::decode_registry_block_at(area_bytes, range.offset, page_size).ok()
    });
    let next_mutation = if latest_boss.is_some() {
        runtime_state.mutation_counter.wrapping_add(1)
    } else {
        0
    };

    let protected = unsafe { &mut *core::ptr::addr_of_mut!(PERSISTENCE_PROTECTED_RANGES) };
    let mut protected_len = 0usize;
    // Invariant: page zero is not data space. It carries the personalization
    // marker and remains protected even if the XIP view still looks erased just
    // after the flash write.
    push_protected_range(
        protected,
        &mut protected_len,
        registry_persistence::PersistentRange::new(0, page_size),
    );
    if let Some(boss) = latest_boss {
        // Invariant: recovery must be able to use the latest committed BOSS
        // until the replacement BOSS is fully written and CRC-valid.
        push_protected_range(
            protected,
            &mut protected_len,
            registry_persistence::PersistentRange::new(boss.offset, boss.total_len),
        );
        protect_latest_registry_payloads(
            area_bytes,
            page_size,
            boss,
            protected,
            &mut protected_len,
        );
    }

    let registry = unsafe { &*core::ptr::addr_of!(OBJECT_REGISTRY) };
    protect_runtime_registry_flash_payloads(
        registry,
        area_bytes,
        page_size,
        protected,
        &mut protected_len,
    );
    let persistent_entries = unsafe { &mut *core::ptr::addr_of_mut!(PERSISTENCE_REGISTRY_ENTRIES) };
    let next_refs = unsafe { &mut *core::ptr::addr_of_mut!(PERSISTENCE_NEXT_OBJECT_REFS) };
    next_refs.fill(None);
    let mut entry_count = 0usize;
    let mut slot = 0usize;
    while slot < DEFAULT_KERNEL_OBJECT_REGISTRY_CAPACITY {
        let Some(object) = registry.resolve(slot) else {
            slot += 1;
            continue;
        };
        let Some(data_ref) = persist_registry_object_payload(
            object,
            runtime_state.object_refs[slot],
            area_bytes,
            page_size,
            protected,
            &mut protected_len,
        ) else {
            return false;
        };
        persistent_entries[entry_count] =
            registry_persistence::PersistentRegistryEntry::from_registry_object(object, data_ref);
        next_refs[slot] = Some(data_ref);
        entry_count += 1;
        slot += 1;
    }

    if latest_boss
        .map(|boss| persistent_registry_entries_equal(boss, &persistent_entries[..entry_count]))
        .unwrap_or(false)
    {
        return true;
    }

    let page = unsafe { &mut *core::ptr::addr_of_mut!(PERSISTENCE_PAGE_BUFFER) };
    let Ok(registry_len) = registry_persistence::encode_registry_block(
        next_mutation,
        &persistent_entries[..entry_count],
        page_size,
        page,
    ) else {
        return false;
    };
    let Some(offset) = reserve_persistent_span(
        area_bytes,
        page_size,
        registry_len,
        &protected[..protected_len],
    ) else {
        return false;
    };
    if !write_persistent_block(offset, &page[..registry_len]) {
        return false;
    }

    // Invariant: the RAM publication root changes only after the replacement
    // BOSS has been written in full. A power loss before this point leaves the
    // previous BOSS and its referenced payloads authoritative.
    let state = unsafe { &mut *core::ptr::addr_of_mut!(PERSISTENCE_RUNTIME_STATE) };
    state.latest_registry = Some(registry_persistence::PersistentRange::new(
        offset,
        registry_len,
    ));
    state.mutation_counter = next_mutation;
    state.object_refs = *next_refs;
    true
}

fn ensure_persistence_runtime_state(area_bytes: &[u8], page_size: usize) -> bool {
    if unsafe { (*core::ptr::addr_of!(PERSISTENCE_RUNTIME_STATE)).initialized } {
        return true;
    }
    let Ok(scan) = registry_persistence::scan_persistence_area(area_bytes, page_size) else {
        return false;
    };
    initialize_persistence_runtime_state(
        scan.latest_registry
            .map(|boss| registry_persistence::PersistentRange::new(boss.offset, boss.total_len)),
        scan.latest_registry
            .map(|boss| boss.mutation_counter)
            .unwrap_or(0),
        scan.append_offset.max(page_size),
    );
    if let Some(boss) = scan.latest_registry {
        let registry = unsafe { &*core::ptr::addr_of!(OBJECT_REGISTRY) };
        cache_persistent_registry_refs(registry, boss);
    }
    true
}

fn persistent_registry_entries_equal(
    boss: registry_persistence::RegistryBlockView<'_>,
    entries: &[registry_persistence::PersistentRegistryEntry],
) -> bool {
    if boss.entry_count as usize != entries.len() {
        return false;
    }
    let mut index = 0usize;
    while index < entries.len() {
        if boss.entry(index).ok() != Some(entries[index]) {
            return false;
        }
        index += 1;
    }
    true
}

fn protect_latest_registry_payloads(
    area_bytes: &[u8],
    page_size: usize,
    boss: registry_persistence::RegistryBlockView<'_>,
    protected: &mut [registry_persistence::PersistentRange],
    protected_len: &mut usize,
) {
    // Current snapshot publication is intentionally conservative: all payload
    // blocks reachable from the last valid BOSS are protected while we write the
    // replacement snapshot. Once registry writes become strictly per-mutation,
    // unchanged entries will stay referenced by the new BOSS too; the only
    // old-only payload to protect will be the one data_ref replaced or removed
    // by the single in-flight mutation.
    let mut index = 0usize;
    while index < boss.entry_count as usize {
        if let Ok(entry) = boss.entry(index) {
            if entry.data_ref.space == registry_persistence::PersistentSpace::RegistryFlash {
                if let Ok(block) = registry_persistence::decode_object_block_at(
                    area_bytes,
                    entry.data_ref.offset as usize,
                    page_size,
                ) {
                    push_protected_range(
                        protected,
                        protected_len,
                        registry_persistence::PersistentRange::new(block.offset, block.total_len),
                    );
                }
            }
        }
        index += 1;
    }
}

fn protect_runtime_registry_flash_payloads(
    registry: &ObjectRegistry<DEFAULT_KERNEL_OBJECT_REGISTRY_CAPACITY>,
    area_bytes: &[u8],
    page_size: usize,
    protected: &mut [registry_persistence::PersistentRange],
    protected_len: &mut usize,
) {
    for object in registry.entries() {
        if object.object_kind != ManagedObjectKind::Package {
            continue;
        }
        let Some(binary_code) = object.package_binary_code() else {
            continue;
        };
        // Invariant: a just-loaded C0DE package may already be referenced by
        // the RAM registry before the replacement BOSS has been published. It
        // must therefore be protected from recycling while we serialize the
        // remaining registry payloads.
        let _ = dynamic_package_persistent_ref(
            binary_code,
            area_bytes,
            page_size,
            protected,
            protected_len,
        );
    }
}

fn persist_registry_object_payload(
    object: &RegistryObject,
    existing_ref: Option<registry_persistence::PersistentRef>,
    area_bytes: &[u8],
    page_size: usize,
    protected: &mut [registry_persistence::PersistentRange],
    protected_len: &mut usize,
) -> Option<registry_persistence::PersistentRef> {
    if object.object_kind == ManagedObjectKind::Package {
        let binary_code = object.package_binary_code()?;
        if let Some(data_ref) = dynamic_package_persistent_ref(
            binary_code,
            area_bytes,
            page_size,
            protected,
            protected_len,
        ) {
            return Some(data_ref);
        }
        let address = binary_code.as_ptr() as usize;
        return Some(registry_persistence::PersistentRef::new(
            registry_persistence::PersistentSpace::FirmwareImage,
            0,
            address as u32,
        ));
    }

    let payload = unsafe { &mut *core::ptr::addr_of_mut!(PERSISTENCE_PAYLOAD_BUFFER) };
    let page = unsafe { &mut *core::ptr::addr_of_mut!(PERSISTENCE_PAGE_BUFFER) };
    let Ok((magic, payload_len)) =
        registry_persistence::encode_registry_object_payload(object, payload)
    else {
        return None;
    };
    if let Some(data_ref) = existing_ref {
        if persistent_payload_matches(
            area_bytes,
            page_size,
            data_ref,
            magic,
            &payload[..payload_len],
        ) {
            return Some(data_ref);
        }
    }
    let Ok(block_len) =
        registry_persistence::encode_object_block(magic, &payload[..payload_len], page_size, page)
    else {
        return None;
    };
    let offset = reserve_persistent_span(
        area_bytes,
        page_size,
        block_len,
        &protected[..*protected_len],
    )?;
    if !write_persistent_block(offset, &page[..block_len]) {
        return None;
    }
    push_protected_range(
        protected,
        protected_len,
        registry_persistence::PersistentRange::new(offset, block_len),
    );
    Some(registry_persistence::PersistentRef::new(
        registry_persistence::PersistentSpace::RegistryFlash,
        0,
        offset as u32,
    ))
}

fn persistent_payload_matches(
    area_bytes: &[u8],
    page_size: usize,
    data_ref: registry_persistence::PersistentRef,
    magic: u32,
    payload: &[u8],
) -> bool {
    if data_ref.space != registry_persistence::PersistentSpace::RegistryFlash {
        return false;
    }
    registry_persistence::decode_object_block_at(area_bytes, data_ref.offset as usize, page_size)
        .map(|block| block.magic == magic && block.payload == payload)
        .unwrap_or(false)
}

fn dynamic_package_persistent_ref(
    binary_code: &[u8],
    area_bytes: &[u8],
    page_size: usize,
    protected: &mut [registry_persistence::PersistentRange],
    protected_len: &mut usize,
) -> Option<registry_persistence::PersistentRef> {
    // Invariant: dynamically loaded packages are registered as a slice over the
    // C0DE payload, not as a slice over the persistent object header. To persist
    // the registry, we recover the owning C0DE block by subtracting the common
    // object header length and validating that the decoded payload is exactly
    // the runtime package slice.
    let area_start = area_bytes.as_ptr() as usize;
    let payload_start = binary_code.as_ptr() as usize;
    let payload_offset = registry_persistence::OBJECT_BLOCK_HEADER_LEN;
    if payload_start < area_start + payload_offset {
        return None;
    }
    let block_offset = payload_start
        .checked_sub(area_start)?
        .checked_sub(payload_offset)?;
    let block =
        registry_persistence::decode_object_block_at(area_bytes, block_offset, page_size).ok()?;
    if block.magic != registry_persistence::PACKAGE_BLOCK_MAGIC {
        return None;
    }
    if block.payload.as_ptr() != binary_code.as_ptr() || block.payload.len() != binary_code.len() {
        return None;
    }
    push_protected_range(
        protected,
        protected_len,
        registry_persistence::PersistentRange::new(block.offset, block.total_len),
    );
    Some(registry_persistence::PersistentRef::new(
        registry_persistence::PersistentSpace::RegistryFlash,
        0,
        block.offset as u32,
    ))
}

fn push_protected_range(
    protected: &mut [registry_persistence::PersistentRange],
    protected_len: &mut usize,
    range: registry_persistence::PersistentRange,
) {
    if *protected_len < protected.len() {
        protected[*protected_len] = range;
        *protected_len += 1;
    }
}

fn write_persistence_area_marker_page() -> bool {
    let page = unsafe { &mut *core::ptr::addr_of_mut!(PERSISTENCE_PAGE_BUFFER) };
    let page_size = oxi_core::core::flash::logical_page_size();
    if page_size == 0 || page_size > page.len() {
        return false;
    }
    page.fill(0xFF);
    if registry_persistence::write_persistence_area_marker(page).is_err() {
        return false;
    }
    oxi_core::core::flash::write_page(
        oxi_core::core::flash::persistence_area().start,
        &page[..page_size],
    )
    .is_ok()
}

fn write_persistent_block(offset: usize, block: &[u8]) -> bool {
    let area = oxi_core::core::flash::persistence_area();
    let page_size = oxi_core::core::flash::logical_page_size();
    if page_size == 0 || !block.len().is_multiple_of(page_size) {
        return false;
    }
    let mut written = 0usize;
    while written < block.len() {
        // Invariant: `write_page` only programs 1 bits to 0 bits. Sector erase,
        // when needed, has already been performed by `reserve_persistent_span`.
        if oxi_core::core::flash::write_page(
            area.start + offset + written,
            &block[written..written + page_size],
        )
        .is_err()
        {
            return false;
        }
        written += page_size;
    }
    true
}

fn ensure_persistence_area_initialized(area_bytes: &[u8], page_size: usize) -> bool {
    if registry_persistence::has_persistence_area_marker(area_bytes) {
        return true;
    }
    let area = oxi_core::core::flash::persistence_area();
    let erase_sector_size = oxi_core::core::flash::erase_sector_size();
    let Some(area_len) = area.page_count.checked_mul(page_size) else {
        return false;
    };
    if erase_sector_size == 0
        || !erase_sector_size.is_multiple_of(page_size)
        || !area.start.is_multiple_of(erase_sector_size)
        || area_len % erase_sector_size != 0
    {
        return false;
    }
    let mut sector_offset = 0usize;
    while sector_offset < area_len {
        if oxi_core::core::flash::erase_sector(area.start + sector_offset).is_err() {
            return false;
        }
        sector_offset += erase_sector_size;
    }
    write_persistence_area_marker_page()
}

fn reserve_persistent_span(
    area_bytes: &[u8],
    page_size: usize,
    required_len: usize,
    protected: &[registry_persistence::PersistentRange],
) -> Option<usize> {
    let erase_sector_size = oxi_core::core::flash::erase_sector_size();
    let append_offset = unsafe { (*core::ptr::addr_of!(PERSISTENCE_RUNTIME_STATE)).append_offset };
    let span = registry_persistence::erased_span_at(
        area_bytes,
        page_size,
        required_len,
        append_offset,
        protected,
    )
    .ok()
    .flatten()
    .or_else(|| {
        registry_persistence::find_reusable_span(
            area_bytes,
            page_size,
            erase_sector_size,
            required_len,
            protected,
        )
        .ok()
        .flatten()
    })?;
    if span.needs_erase() && !erase_reusable_span(span) {
        return None;
    }
    let state = unsafe { &mut *core::ptr::addr_of_mut!(PERSISTENCE_RUNTIME_STATE) };
    state.append_offset = span.offset.saturating_add(span.total_len);
    Some(span.offset)
}

fn erase_reusable_span(span: registry_persistence::ReusableSpan) -> bool {
    let area = oxi_core::core::flash::persistence_area();
    let erase_sector_size = oxi_core::core::flash::erase_sector_size();
    if !span.needs_erase()
        || erase_sector_size == 0
        || !span.erase_len.is_multiple_of(erase_sector_size)
        || !span.erase_offset.is_multiple_of(erase_sector_size)
    {
        return !span.needs_erase();
    }
    let mut offset = 0usize;
    while offset < span.erase_len {
        // Invariant: the allocator only returns erasable sector runs that do
        // not overlap the latest valid BOSS or any object reachable from it.
        if oxi_core::core::flash::erase_sector(area.start + span.erase_offset + offset).is_err() {
            return false;
        }
        offset += erase_sector_size;
    }
    true
}

/// Starts one GP package LOAD transaction after `INSTALL [for load]`.
///
/// The package code is reserved in the mutable persistence area immediately,
/// but it becomes reachable only after the last `LOAD` block validates the
/// announced size and SHA-256 hash, then publishes a new registry snapshot.
pub fn prepare_dynamic_package_load(
    authority_aid: Aid,
    target_sd_aid: Aid,
    package_aid: Aid,
    protected: bool,
    expected_size: usize,
    expected_hash: [u8; 32],
) -> apdu_manager::ApduStatus {
    if expected_size == 0 || expected_size > 64 * 1024 {
        return apdu_manager::ApduStatus::wrong_data();
    }
    // Invariant: a new INSTALL [for load] aborts any unfinished LOAD. Since no
    // BOSS snapshot references unfinished C0DE pages, discarding the volatile
    // context is equivalent to recovering from a reset before final LOAD.
    clear_dynamic_load_context();
    if find_managed_object_kind_by_aid(&target_sd_aid) != Some(ManagedObjectKind::SecurityDomain) {
        return apdu_manager::ApduStatus::referenced_data_not_found();
    }

    let Some(area_bytes) = persistent_registry_area_bytes() else {
        return apdu_manager::ApduStatus::conditions_not_satisfied();
    };
    let page_size = oxi_core::core::flash::logical_page_size();
    if page_size == 0 || page_size > PERSISTENCE_PAGE_BUFFER_SIZE {
        return apdu_manager::ApduStatus::conditions_not_satisfied();
    }
    let Ok(block_total_len) = registry_persistence::object_block_total_len(
        registry_persistence::PACKAGE_BLOCK_MAGIC,
        expected_size,
        page_size,
    ) else {
        return apdu_manager::ApduStatus::wrong_data();
    };

    let protected_ranges = unsafe { &mut *core::ptr::addr_of_mut!(PERSISTENCE_PROTECTED_RANGES) };
    let Some(protected_len) =
        build_current_persistence_protection(area_bytes, page_size, protected_ranges)
    else {
        return apdu_manager::ApduStatus::conditions_not_satisfied();
    };
    let Some(reserved_offset) = reserve_persistent_span(
        area_bytes,
        page_size,
        block_total_len,
        &protected_ranges[..protected_len],
    ) else {
        return apdu_manager::ApduStatus::conditions_not_satisfied();
    };

    let page = unsafe { &mut *core::ptr::addr_of_mut!(PERSISTENCE_PAGE_BUFFER) };
    page.fill(0xFF);
    // The C0DE header is written as soon as the span is reserved, but no BOSS
    // block points to it until final LOAD validates size, hash and CRC.
    write_u32_le_local(&mut page[0..4], registry_persistence::PACKAGE_BLOCK_MAGIC);
    write_u32_le_local(&mut page[4..8], block_total_len as u32);
    write_u32_le_local(&mut page[8..12], expected_size as u32);
    unsafe {
        *core::ptr::addr_of_mut!(DYNAMIC_LOAD_CONTEXT) = Some(DynamicLoadContext {
            authority_aid,
            target_sd_aid,
            package_aid,
            protected,
            expected_hash,
            expected_size,
            reserved_offset,
            block_total_len,
            bytes_received: 0,
            next_block_number: 0,
            current_page_index: 0,
            current_page_dirty: true,
        });
    }
    apdu_manager::ApduStatus::success()
}

/// Appends one GP `LOAD` block to the active package-load transaction.
///
/// Invariants enforced here:
/// - block numbers are consecutive and start at zero;
/// - total received bytes never exceed the size announced by install-for-load;
/// - only the final block may publish the package;
/// - finalization requires exact size and exact SHA-256 hash match.
pub fn append_dynamic_package_load_block(
    authority_aid: Aid,
    protected: bool,
    block_number: u8,
    is_last_block: bool,
    data: &[u8],
) -> apdu_manager::ApduStatus {
    if data.is_empty() {
        clear_dynamic_load_context();
        return apdu_manager::ApduStatus::wrong_data();
    }

    let mut context = match unsafe { *core::ptr::addr_of!(DYNAMIC_LOAD_CONTEXT) } {
        Some(context) => context,
        None => return apdu_manager::ApduStatus::conditions_not_satisfied(),
    };
    // Invariant: LOAD is a continuation of the accepted INSTALL [for load].
    // The stream must remain under the same Security Domain authority and the
    // same clear/protected channel posture until the final block publishes the
    // package. A clear block may not complete a protected SCP03 load and a
    // protected block may not be spliced into a clear development load.
    if context.authority_aid != authority_aid || context.protected != protected {
        clear_dynamic_load_context();
        return apdu_manager::ApduStatus::conditions_not_satisfied();
    }
    if block_number != context.next_block_number {
        clear_dynamic_load_context();
        return apdu_manager::ApduStatus::wrong_data();
    }
    let data = if block_number == 0 {
        let Some((declared_len, payload)) = parse_gp_load_file_data_block_header(data) else {
            clear_dynamic_load_context();
            return apdu_manager::ApduStatus::wrong_data();
        };
        if declared_len != context.expected_size {
            clear_dynamic_load_context();
            return apdu_manager::ApduStatus::wrong_data();
        }
        payload
    } else {
        data
    };
    if context
        .bytes_received
        .checked_add(data.len())
        .map(|received| received > context.expected_size)
        .unwrap_or(true)
    {
        clear_dynamic_load_context();
        return apdu_manager::ApduStatus::wrong_data();
    }

    let page_size = oxi_core::core::flash::logical_page_size();
    if page_size == 0 || page_size > PERSISTENCE_PAGE_BUFFER_SIZE {
        clear_dynamic_load_context();
        return apdu_manager::ApduStatus::conditions_not_satisfied();
    }
    let page = unsafe { &mut *core::ptr::addr_of_mut!(PERSISTENCE_PAGE_BUFFER) };
    if !append_dynamic_load_payload(&mut context, page_size, page, data) {
        clear_dynamic_load_context();
        return apdu_manager::ApduStatus::conditions_not_satisfied();
    }
    context.bytes_received += data.len();
    if !is_last_block && context.next_block_number == u8::MAX {
        clear_dynamic_load_context();
        return apdu_manager::ApduStatus::wrong_data();
    }
    context.next_block_number = context.next_block_number.wrapping_add(1);
    unsafe {
        *core::ptr::addr_of_mut!(DYNAMIC_LOAD_CONTEXT) = Some(context);
    }

    if !is_last_block {
        return apdu_manager::ApduStatus::success();
    }
    finalize_dynamic_package_load(context)
}

fn parse_gp_load_file_data_block_header(data: &[u8]) -> Option<(usize, &[u8])> {
    if data.first().copied()? != 0xC4 {
        return None;
    }
    let first_len = *data.get(1)?;
    match first_len {
        0x00..=0x7F => Some((first_len as usize, data.get(2..)?)),
        0x81 => Some((*data.get(2)? as usize, data.get(3..)?)),
        0x82 => Some((
            u16::from_be_bytes([*data.get(2)?, *data.get(3)?]) as usize,
            data.get(4..)?,
        )),
        _ => None,
    }
}

fn append_dynamic_load_payload(
    context: &mut DynamicLoadContext,
    page_size: usize,
    page: &mut [u8; PERSISTENCE_PAGE_BUFFER_SIZE],
    data: &[u8],
) -> bool {
    let mut written = 0usize;
    while written < data.len() {
        let absolute_payload_offset =
            registry_persistence::OBJECT_BLOCK_HEADER_LEN + context.bytes_received + written;
        // Invariant: LOAD bytes are written after the persistent object header.
        // The FAE image therefore remains contiguous when later exposed as the
        // decoded C0DE payload.
        let page_index = absolute_payload_offset / page_size;
        if page_index != context.current_page_index {
            if context.current_page_dirty && !flush_dynamic_load_page(context, page_size, page) {
                return false;
            }
            // Invariant: LOAD offsets are sequential; moving to another page
            // can only advance, never skip backwards or create a gap.
            if page_index < context.current_page_index {
                return false;
            }
            context.current_page_index = page_index;
            context.current_page_dirty = false;
            page.fill(0xFF);
        }

        let offset_in_page = absolute_payload_offset % page_size;
        let available = page_size - offset_in_page;
        let take = available.min(data.len() - written);
        page[offset_in_page..offset_in_page + take].copy_from_slice(&data[written..written + take]);
        context.current_page_dirty = true;
        written += take;

        if offset_in_page + take == page_size {
            if !flush_dynamic_load_page(context, page_size, page) {
                return false;
            }
            context.current_page_index += 1;
            context.current_page_dirty = false;
            page.fill(0xFF);
        }
    }
    true
}

fn finalize_dynamic_package_load(context: DynamicLoadContext) -> apdu_manager::ApduStatus {
    if context.bytes_received != context.expected_size {
        clear_dynamic_load_context();
        return apdu_manager::ApduStatus::wrong_data();
    }
    let Some(area_bytes) = persistent_registry_area_bytes() else {
        clear_dynamic_load_context();
        return apdu_manager::ApduStatus::conditions_not_satisfied();
    };
    let page_size = oxi_core::core::flash::logical_page_size();
    let page = unsafe { &mut *core::ptr::addr_of_mut!(PERSISTENCE_PAGE_BUFFER) };
    let mut hasher = Sha256::new();
    update_sha256_from_dynamic_load_region(
        &context,
        area_bytes,
        page,
        registry_persistence::OBJECT_BLOCK_HEADER_LEN,
        context.expected_size,
        &mut hasher,
    );
    let digest = hasher.finalize();
    if digest[..] != context.expected_hash {
        clear_dynamic_load_context();
        return apdu_manager::ApduStatus::wrong_data();
    }

    let payload_in_block = registry_persistence::OBJECT_BLOCK_HEADER_LEN;
    let valid_fae = crate::fae_runtime::validate_fae_reader(context.expected_size, |offset| {
        let absolute = payload_in_block.checked_add(offset)?;
        let page_index = absolute / page_size;
        let offset_in_page = absolute % page_size;
        if page_index == context.current_page_index {
            page.get(offset_in_page).copied()
        } else {
            area_bytes
                .get(context.reserved_offset.checked_add(absolute)?)
                .copied()
        }
    });
    if !valid_fae {
        clear_dynamic_load_context();
        return apdu_manager::ApduStatus::wrong_data();
    }

    if !write_dynamic_load_final_crc(context, area_bytes, page_size, page) {
        clear_dynamic_load_context();
        return apdu_manager::ApduStatus::conditions_not_satisfied();
    }
    let Some(area_bytes) = persistent_registry_area_bytes() else {
        clear_dynamic_load_context();
        return apdu_manager::ApduStatus::conditions_not_satisfied();
    };
    let Ok(block) = registry_persistence::decode_object_block_at(
        area_bytes,
        context.reserved_offset,
        page_size,
    ) else {
        clear_dynamic_load_context();
        return apdu_manager::ApduStatus::conditions_not_satisfied();
    };
    if block.magic != registry_persistence::PACKAGE_BLOCK_MAGIC
        || block.payload.len() != context.expected_size
    {
        clear_dynamic_load_context();
        return apdu_manager::ApduStatus::conditions_not_satisfied();
    }

    // The registry stores the executable package as the C0DE payload slice. The
    // persistent header stays kernel metadata and is never part of the FAE image
    // handed to the Rustlet runtime.
    let inserted = unsafe {
        (&mut *core::ptr::addr_of_mut!(OBJECT_REGISTRY)).insert_package_object(
            context.target_sd_aid,
            context.package_aid,
            context.package_aid,
            block.payload,
        )
    };
    clear_dynamic_load_context();
    if !inserted {
        return apdu_manager::ApduStatus::conditions_not_satisfied();
    }
    if publish_persistent_registry_snapshot() {
        apdu_manager::ApduStatus::success()
    } else {
        apdu_manager::ApduStatus::conditions_not_satisfied()
    }
}

fn write_dynamic_load_final_crc(
    mut context: DynamicLoadContext,
    area_bytes: &[u8],
    page_size: usize,
    page: &mut [u8; PERSISTENCE_PAGE_BUFFER_SIZE],
) -> bool {
    let crc_offset = context.block_total_len - registry_persistence::BLOCK_CRC_LEN;
    let crc_page_index = crc_offset / page_size;
    if context.current_page_index < crc_page_index {
        if context.current_page_dirty && !flush_dynamic_load_page(&context, page_size, page) {
            return false;
        }
        let mut page_index = context.current_page_index + usize::from(context.current_page_dirty);
        page.fill(0xFF);
        while page_index < crc_page_index {
            if !write_dynamic_load_page(context.reserved_offset, page_index, page_size, page) {
                return false;
            }
            page_index += 1;
        }
        context.current_page_index = crc_page_index;
        context.current_page_dirty = true;
        page.fill(0xFF);
    } else if context.current_page_index > crc_page_index {
        return false;
    } else if !context.current_page_dirty {
        page.fill(0xFF);
        context.current_page_dirty = true;
    }

    let crc = crc64_dynamic_load_region(&context, area_bytes, page, 0, crc_offset);
    let crc_in_page = crc_offset % page_size;
    page[crc_in_page..crc_in_page + registry_persistence::BLOCK_CRC_LEN]
        .copy_from_slice(&crc.to_le_bytes());
    write_dynamic_load_page(
        context.reserved_offset,
        context.current_page_index,
        page_size,
        page,
    )
}

fn update_sha256_from_dynamic_load_region(
    context: &DynamicLoadContext,
    area_bytes: &[u8],
    current_page: &[u8; PERSISTENCE_PAGE_BUFFER_SIZE],
    start: usize,
    len: usize,
    hasher: &mut Sha256,
) {
    let page_size = oxi_core::core::flash::logical_page_size();
    let mut offset = 0usize;
    while offset < len {
        let absolute = start + offset;
        let page_index = absolute / page_size;
        let offset_in_page = absolute % page_size;
        let take = (page_size - offset_in_page).min(len - offset);
        if page_index == context.current_page_index {
            hasher.update(&current_page[offset_in_page..offset_in_page + take]);
        } else {
            let start = context.reserved_offset + absolute;
            hasher.update(&area_bytes[start..start + take]);
        }
        offset += take;
    }
}

fn crc64_dynamic_load_region(
    context: &DynamicLoadContext,
    area_bytes: &[u8],
    current_page: &[u8; PERSISTENCE_PAGE_BUFFER_SIZE],
    start: usize,
    len: usize,
) -> u64 {
    let page_size = oxi_core::core::flash::logical_page_size();
    let mut crc = 0u64;
    let mut offset = 0usize;
    while offset < len {
        let absolute = start + offset;
        let page_index = absolute / page_size;
        let offset_in_page = absolute % page_size;
        let take = (page_size - offset_in_page).min(len - offset);
        crc = if page_index == context.current_page_index {
            registry_persistence::crc64_ecma_extend(
                crc,
                &current_page[offset_in_page..offset_in_page + take],
            )
        } else {
            let start = context.reserved_offset + absolute;
            registry_persistence::crc64_ecma_extend(crc, &area_bytes[start..start + take])
        };
        offset += take;
    }
    crc
}

fn flush_dynamic_load_page(
    context: &DynamicLoadContext,
    page_size: usize,
    page: &[u8; PERSISTENCE_PAGE_BUFFER_SIZE],
) -> bool {
    write_dynamic_load_page(
        context.reserved_offset,
        context.current_page_index,
        page_size,
        page,
    )
}

fn write_dynamic_load_page(
    reserved_offset: usize,
    page_index: usize,
    page_size: usize,
    page: &[u8; PERSISTENCE_PAGE_BUFFER_SIZE],
) -> bool {
    let area = oxi_core::core::flash::persistence_area();
    let Some(page_offset) = page_index.checked_mul(page_size) else {
        return false;
    };
    let Some(offset) = reserved_offset.checked_add(page_offset) else {
        return false;
    };
    oxi_core::core::flash::write_page(area.start + offset, &page[..page_size]).is_ok()
}

fn build_current_persistence_protection(
    area_bytes: &[u8],
    page_size: usize,
    protected: &mut [registry_persistence::PersistentRange],
) -> Option<usize> {
    if !ensure_persistence_runtime_state(area_bytes, page_size) {
        return None;
    }
    let mut protected_len = 0usize;
    push_protected_range(
        protected,
        &mut protected_len,
        registry_persistence::PersistentRange::new(0, page_size),
    );
    let latest_registry =
        unsafe { (*core::ptr::addr_of!(PERSISTENCE_RUNTIME_STATE)).latest_registry };
    if let Some(range) = latest_registry {
        let Ok(boss) =
            registry_persistence::decode_registry_block_at(area_bytes, range.offset, page_size)
        else {
            return None;
        };
        push_protected_range(
            protected,
            &mut protected_len,
            registry_persistence::PersistentRange::new(boss.offset, boss.total_len),
        );
        protect_latest_registry_payloads(
            area_bytes,
            page_size,
            boss,
            protected,
            &mut protected_len,
        );
    }
    Some(protected_len)
}

fn clear_dynamic_load_context() {
    unsafe {
        *core::ptr::addr_of_mut!(DYNAMIC_LOAD_CONTEXT) = None;
    }
}

/// Returns true while a GP `INSTALL [for load]` / `LOAD` transaction is active.
///
/// The context is intentionally volatile: it is never published in the object
/// registry and therefore disappears naturally on reset before the final LOAD
/// block commits the package object.
pub fn dynamic_package_load_in_progress() -> bool {
    unsafe { (*core::ptr::addr_of!(DYNAMIC_LOAD_CONTEXT)).is_some() }
}

/// Cancels any in-progress dynamic package load.
///
/// Invariant: because unfinished C0DE pages are not referenced by a committed
/// BOSS snapshot, cancellation only drops volatile state. The flash span is
/// later recyclable as an invalid or unreferenced object block.
pub fn cancel_dynamic_package_load() {
    clear_dynamic_load_context();
}

fn write_u32_le_local(out: &mut [u8], value: u32) {
    out.copy_from_slice(&value.to_le_bytes());
}

fn persistent_registry_area_bytes() -> Option<&'static [u8]> {
    let area = oxi_core::core::flash::persistence_area();
    let page_size = oxi_core::core::flash::logical_page_size();
    let len = area.page_count.checked_mul(page_size)?;
    if len == 0 {
        return None;
    }
    Some(unsafe { core::slice::from_raw_parts(area.start as *const u8, len) })
}

fn bootstrap_root_security_domain() {
    let root_package_aid = crate::predeployment::root_package_aid();
    let root_instance_aid = crate::predeployment::root_instance_aid();
    match crate::predeployment::root_backend() {
        crate::predeployment::RootSecurityDomainBackend::RustletSecurityDomainProxy => {
            let status = install_instance_in_parent(
                &top_level_parent_sd_aid(),
                &root_package_aid,
                &root_package_aid,
                &root_instance_aid,
                crate::predeployment::root_privileges(),
                crate::predeployment::root_install_payload(),
                InstallHandlerPayload::Encode {
                    privileges: crate::predeployment::root_privileges(),
                    install_parameters: crate::predeployment::root_install_payload(),
                },
            );
            if status.sw1 != 0x90 || status.sw2 != 0x00 {
                panic!(
                    "root Rustlet Security Domain bootstrap failed: {:02x}{:02x}",
                    status.sw1, status.sw2
                );
            }
            if find_runtime_state_object_by_aid(&top_level_parent_sd_aid(), &root_instance_aid)
                .is_none()
            {
                let save_status = save_selected_instance_state(
                    &top_level_parent_sd_aid(),
                    &root_package_aid,
                    &root_package_aid,
                    &root_instance_aid,
                    Some(crate::predeployment::root_privileges()),
                );
                if save_status.sw1 != 0x90 || save_status.sw2 != 0x00 {
                    panic!(
                        "root Rustlet Security Domain state save failed: {:02x}{:02x}",
                        save_status.sw1, save_status.sw2
                    );
                }
            }
            set_active_security_domain_instance_aid(root_instance_aid);
            activate_root_rustlet_security_domain(root_instance_aid);
        }
        crate::predeployment::RootSecurityDomainBackend::NullSecurityDomain => {
            bootstrap_kernel_side_security_domain_root(
                SecurityDomainObjectBackend::NullSecurityDomain,
                crate::predeployment::root_install_payload(),
            );
        }
        crate::predeployment::RootSecurityDomainBackend::KernelSecurityDomain => {
            bootstrap_kernel_side_security_domain_root(
                SecurityDomainObjectBackend::KernelSecurityDomain,
                crate::predeployment::root_install_payload(),
            );
        }
    }
}

fn activate_root_rustlet_security_domain(root_instance_aid: Aid) {
    let reference = {
        let registry = unsafe { &*core::ptr::addr_of!(OBJECT_REGISTRY) };
        let Some(instance) = registry.find_index(
            &top_level_parent_sd_aid(),
            ManagedObjectKind::SecurityDomain,
            &root_instance_aid,
        ) else {
            panic!("root Rustlet Security Domain instance is not registered");
        };
        let Some(reference) = AppRegistryReference::from_instance(instance) else {
            panic!("root Rustlet Security Domain package is not registered");
        };
        reference
    };
    let status = activate_registry_reference(reference);
    if status.sw1 != 0x90 || status.sw2 != 0x00 {
        panic!(
            "root Rustlet Security Domain activation failed: {:02x}{:02x}",
            status.sw1, status.sw2
        );
    }
    let Some(selected_app) = selected_app_mut() else {
        panic!("root Rustlet Security Domain activation did not select an app");
    };
    let Some(instance) = reference.instance_object() else {
        panic!("root Rustlet Security Domain state is not registered");
    };
    if !selected_app
        .loaded_fae
        .shared_buffer
        .stage_state_from_registry(instance.serialized_state().unwrap_or(&[]))
    {
        panic!("root Rustlet Security Domain state does not fit in the shared buffer");
    }
    promote_selected_app_to_security_domain();
}

fn bootstrap_kernel_side_security_domain_root(
    backend: SecurityDomainObjectBackend,
    install_payload: &[u8],
) {
    let root_package_aid = crate::predeployment::root_package_aid();
    let root_instance_aid = crate::predeployment::root_instance_aid();
    let status = install_kernel_side_security_domain_instance(
        backend,
        top_level_parent_sd_aid(),
        root_package_aid,
        root_instance_aid,
        install_payload,
    );
    if status.sw1 != 0x90 || status.sw2 != 0x00 {
        panic!(
            "kernel Security Domain bootstrap install failed: {:02x}{:02x}",
            status.sw1, status.sw2
        );
    }
    set_active_security_domain_instance_aid(root_instance_aid);
}

fn bootstrap_predeployed_plan() {
    for security_domain in crate::predeployment::predeployed_security_domains() {
        let status = match security_domain.backend {
            crate::predeployment::RootSecurityDomainBackend::NullSecurityDomain => {
                install_kernel_side_security_domain_instance(
                    SecurityDomainObjectBackend::NullSecurityDomain,
                    security_domain.parent_instance_aid,
                    security_domain.package_aid,
                    security_domain.instance_aid,
                    security_domain.install_payload,
                )
            }
            crate::predeployment::RootSecurityDomainBackend::KernelSecurityDomain => {
                install_kernel_side_security_domain_instance(
                    SecurityDomainObjectBackend::KernelSecurityDomain,
                    security_domain.parent_instance_aid,
                    security_domain.package_aid,
                    security_domain.instance_aid,
                    security_domain.install_payload,
                )
            }
            crate::predeployment::RootSecurityDomainBackend::RustletSecurityDomainProxy => {
                install_instance_in_parent(
                    &security_domain.parent_instance_aid,
                    &security_domain.package_aid,
                    &security_domain.package_aid,
                    &security_domain.instance_aid,
                    &security_domain.privileges,
                    security_domain.install_payload,
                    InstallHandlerPayload::Encode {
                        privileges: &security_domain.privileges,
                        install_parameters: security_domain.install_payload,
                    },
                )
            }
        };
        if status.sw1 != 0x90 || status.sw2 != 0x00 {
            panic!(
                "predeployment security domain install failed: {:02x}{:02x}",
                status.sw1, status.sw2
            );
        }
    }

    for key in crate::predeployment::predeployed_keys() {
        let usage = match key.usage {
            crate::predeployment::PredeployedKeyUsage::Enc => {
                crate::security_domain::Scp03KeyUsage::Enc
            }
            crate::predeployment::PredeployedKeyUsage::Mac => {
                crate::security_domain::Scp03KeyUsage::Mac
            }
        };
        let inserted = match key.key_type {
            crate::predeployment::PredeployedKeyType::Scp03Static => upsert_scp03_key_object(
                key.parent_instance_aid,
                key.key_version,
                key.key_id,
                usage,
                key.material,
            ),
        };
        if !inserted {
            panic!("predeployment key insertion failed");
        }
    }

    for instance in crate::predeployment::predeployed_rustlet_instances() {
        let status = install_instance_in_parent(
            &instance.parent_instance_aid,
            &instance.package_aid,
            &instance.applet_aid,
            &instance.instance_aid,
            &[0x00, 0x00, 0x00],
            instance.install_parameters,
            InstallHandlerPayload::Encode {
                privileges: &[0x00, 0x00, 0x00],
                install_parameters: instance.install_parameters,
            },
        );
        if status.sw1 != 0x90 || status.sw2 != 0x00 {
            panic!(
                "predeployment rustlet install failed: {:02x}{:02x}",
                status.sw1, status.sw2
            );
        }
    }
}

pub fn select_aid(aid: &[u8]) -> apdu_manager::ApduStatus {
    let instance_aid = Aid::new(aid);
    let Some(instance) = find_visible_object_by_aid(&instance_aid) else {
        return apdu_manager::ApduStatus::file_not_found();
    };
    if !instance.may_select() {
        return apdu_manager::ApduStatus::conditions_not_satisfied();
    }
    if is_security_domain_kind(instance.object_kind) {
        set_active_security_domain_instance_aid(instance.object_aid);
    }
    let Some(instance_index) = registry_index_for_object(instance) else {
        return apdu_manager::ApduStatus::file_not_found();
    };
    let Some(reference) = AppRegistryReference::from_instance(instance_index) else {
        return if is_security_domain_kind(instance.object_kind) {
            apdu_manager::ApduStatus::success()
        } else {
            apdu_manager::ApduStatus::file_not_found()
        };
    };

    if let Some(selected_app) = selected_app_mut() {
        if selected_app.registry == reference {
            if !selected_app
                .loaded_fae
                .shared_buffer
                .stage_state_from_registry(instance.serialized_state().unwrap_or(&[]))
            {
                return apdu_manager::ApduStatus::wrong_length();
            }
            return apdu_manager::ApduStatus::success();
        }
    }

    let status = activate_registry_reference(reference);
    if status.sw1 != 0x90 || status.sw2 != 0x00 {
        return status;
    }

    let Some(selected_app) = selected_app_mut() else {
        return apdu_manager::ApduStatus::conditions_not_satisfied();
    };
    if !selected_app
        .loaded_fae
        .shared_buffer
        .stage_state_from_registry(instance.serialized_state().unwrap_or(&[]))
    {
        set_selected_app(None);
        return apdu_manager::ApduStatus::wrong_length();
    }

    apdu_manager::ApduStatus::success()
}

#[allow(dead_code)]
pub fn install_instance_in_security_domain(
    parent_sd_aid: &Aid,
    package_aid: &Aid,
    applet_aid: &Aid,
    instance_aid: &Aid,
    privileges: &[u8],
    install_parameters: &[u8],
) -> apdu_manager::ApduStatus {
    install_instance_in_parent(
        parent_sd_aid,
        package_aid,
        applet_aid,
        instance_aid,
        privileges,
        install_parameters,
        InstallHandlerPayload::Encode {
            privileges,
            install_parameters,
        },
    )
}

pub fn install_instance_in_security_domain_from_current_apdu(
    parent_sd_aid: &Aid,
    package_aid: &Aid,
    applet_aid: &Aid,
    instance_aid: &Aid,
    privileges: &[u8],
    install_parameters: &[u8],
    header: rustlet_runtime::RustletApduHeader,
    incoming_len: usize,
) -> apdu_manager::ApduStatus {
    install_instance_in_parent(
        parent_sd_aid,
        package_aid,
        applet_aid,
        instance_aid,
        privileges,
        install_parameters,
        InstallHandlerPayload::CurrentApdu {
            header,
            incoming_len,
        },
    )
}

enum InstallHandlerPayload<'a> {
    Encode {
        privileges: &'a [u8],
        install_parameters: &'a [u8],
    },
    CurrentApdu {
        header: rustlet_runtime::RustletApduHeader,
        incoming_len: usize,
    },
}

fn install_instance_in_parent(
    parent_sd_aid: &Aid,
    package_aid: &Aid,
    applet_aid: &Aid,
    instance_aid: &Aid,
    privileges: &[u8],
    _install_parameters: &[u8],
    install_payload: InstallHandlerPayload<'_>,
) -> apdu_manager::ApduStatus {
    let Some(package_index) =
        pending_registry_reference_for_install(parent_sd_aid, package_aid, applet_aid)
    else {
        return apdu_manager::ApduStatus::file_not_found();
    };
    let reference = AppRegistryReference::pending_install(package_index);

    if selected_app_matches_install_target(parent_sd_aid, package_aid, applet_aid) {
        set_selected_app(None);
    }

    {
        let activation_status = activate_registry_reference(reference);
        if activation_status.sw1 != 0x90 || activation_status.sw2 != 0x00 {
            activation_status
        } else {
            let result = match install_payload {
                InstallHandlerPayload::Encode {
                    privileges,
                    install_parameters,
                } => {
                    // Invariant: synthetic INSTALL payloads are encoded directly
                    // in the shared Rustlet context. Do not stage them through
                    // TransportApdu.
                    dispatch_install_handler_encoded(|out| {
                        encode_install_for_install_data(
                            out,
                            package_aid,
                            applet_aid,
                            instance_aid,
                            privileges,
                            install_parameters,
                        )
                    })
                }
                InstallHandlerPayload::CurrentApdu {
                    header,
                    incoming_len,
                } => {
                    // Invariant: APDU-originated INSTALL already occupies the
                    // shared APDU buffer. Publish it as-is so install parameters
                    // are not recopied or destroyed by start/control
                    // initialization.
                    dispatch_install_handler_current_apdu(header, incoming_len)
                }
            };
            let status = from_abi_status(result.status);
            if status.sw1 != 0x90 || status.sw2 != 0x00 {
                set_selected_app(None);
                status
            } else {
                // Invariant: a successful INSTALL always leaves a registry
                // object behind. Some runtimes complete through their
                // termination gate rather than a normal function return, so the
                // APDU status is the authoritative result.
                let save_status = save_selected_instance_state(
                    parent_sd_aid,
                    package_aid,
                    applet_aid,
                    instance_aid,
                    Some(privileges),
                );
                if save_status.sw1 == 0x90 && save_status.sw2 == 0x00 {
                    set_selected_app(None);
                    status
                } else {
                    set_selected_app(None);
                    save_status
                }
            }
        }
    }
}

fn encode_install_for_install_data(
    out: &mut [u8],
    package_aid: &Aid,
    applet_aid: &Aid,
    instance_aid: &Aid,
    privileges: &[u8],
    install_parameters: &[u8],
) -> Option<usize> {
    let mut offset = 0usize;
    push_install_lv(out, &mut offset, package_aid.as_slice())?;
    push_install_lv(out, &mut offset, applet_aid.as_slice())?;
    push_install_lv(out, &mut offset, instance_aid.as_slice())?;
    push_install_lv(out, &mut offset, privileges)?;
    push_install_lv(out, &mut offset, install_parameters)?;
    // GlobalPlatform INSTALL [for install] always carries the INSTALL Token
    // LV, even when the active Security Domain policy requires no token.
    push_install_lv(out, &mut offset, &[])?;
    Some(offset)
}

fn push_install_lv(out: &mut [u8], offset: &mut usize, bytes: &[u8]) -> Option<()> {
    let len = u8::try_from(bytes.len()).ok()? as usize;
    let next = offset.checked_add(1 + len)?;
    if next > out.len() {
        return None;
    }
    out[*offset] = len as u8;
    let start = *offset + 1;
    out[start..start + len].copy_from_slice(bytes);
    *offset = next;
    Some(())
}

pub fn dispatch(apdu: &mut apdu_manager::Apdu<'_>) -> apdu_manager::ApduStatus {
    let (result, registry_reference, ordinary_rustlet) = {
        let Some(selected_app) = selected_app_mut() else {
            return apdu_manager::ApduStatus::conditions_not_satisfied();
        };
        let registry_reference = selected_app.registry;
        if !registry_reference.is_valid() {
            return apdu_manager::ApduStatus::conditions_not_satisfied();
        }

        let handler = selected_app_vtable(selected_app).process_apdu as usize;

        let allocator = core::ptr::addr_of_mut!(selected_app.allocator);
        let _active_call = ActiveAppCallGuard::install(apdu, &selected_app.loaded_fae, allocator);
        let instance = selected_app.registry.instance_object();
        let serialized_state = instance
            .as_ref()
            .map(|instance| instance.serialized_state().unwrap_or(&[]))
            .unwrap_or(&[]);
        let result = fae_runtime::call_handler(
            &selected_app.loaded_fae,
            handler,
            selected_app.state,
            apdu,
            serialized_state,
        );

        // Invariant: registry slots remain stable while the Rustlet runs.
        // Keep only the compact slot reference live across the user call and
        // resolve its AIDs after return, rather than retaining four AID copies
        // on the kernel stack throughout every Rustlet syscall.
        (
            result,
            registry_reference,
            selected_app.security_domain_vtable.is_null(),
        )
    };

    let status = from_abi_status(result.status);
    if result.returned_normally {
        let save_status = save_selected_instance_state_by_reference(registry_reference);
        if save_status.sw1 == 0x90 && save_status.sw2 == 0x00 {
            status
        } else {
            save_status
        }
    } else {
        // A failed ordinary call cannot reach the runtime's serialize/drop
        // boundary. Remove it immediately so `unload` scrubs its complete RAM
        // allocation instead of leaving a faulted heap resident.
        if ordinary_rustlet {
            set_selected_app(None);
        }
        status
    }
}

#[inline(never)]
fn save_selected_instance_state_by_reference(
    registry_reference: AppRegistryReference,
) -> apdu_manager::ApduStatus {
    let Some((security_domain_aid, package_aid, applet_aid, instance_aid)) =
        registry_reference.identity()
    else {
        return apdu_manager::ApduStatus::conditions_not_satisfied();
    };
    save_selected_instance_state(
        &security_domain_aid,
        &package_aid,
        &applet_aid,
        &instance_aid,
        None,
    )
}

pub fn dispatch_select(apdu: &mut apdu_manager::Apdu<'_>) -> apdu_manager::ApduStatus {
    let status = dispatch(apdu);
    if (status.sw1 == 0x6d && status.sw2 == 0x00) || (status.sw1 == 0x69 && status.sw2 == 0x85) {
        apdu_manager::ApduStatus::success()
    } else {
        status
    }
}

pub fn security_domain_authorize_install(
    package_aid: &Aid,
    applet_aid: &Aid,
    instance_aid: &Aid,
    privileges: &[u8],
    install_parameters: &[u8],
) -> apdu_manager::ApduStatus {
    let status =
        call_selected_security_domain_encoded(SddispatchOpcode::INSTALL_FOR_INSTALL, |out| {
            encode_sddispatch_install_for_install(
                package_aid,
                applet_aid,
                instance_aid,
                privileges,
                install_parameters,
                out,
            )
        });
    if status.sw1 != 0x90 || status.sw2 != 0x00 {
        return status;
    }

    match selected_security_domain_bool_response() {
        Some(true) => apdu_manager::ApduStatus::success(),
        Some(false) => apdu_manager::ApduStatus::conditions_not_satisfied(),
        None => from_abi_status(rustlet_runtime::ApduStatus::internal_error()),
    }
}

pub fn security_domain_authorize_load(package_aid: &Aid) -> apdu_manager::ApduStatus {
    call_selected_security_domain_encoded(SddispatchOpcode::INSTALL_FOR_LOAD, |out| {
        encode_sddispatch_install_for_load(package_aid, out)
    })
}

pub fn security_domain_delete_aid(aid: &Aid) -> apdu_manager::ApduStatus {
    call_selected_security_domain_encoded(SddispatchOpcode::DELETE_AID, |out| {
        encode_sddispatch_one_aid(aid, out)
    })
}

pub fn security_domain_authorize_put_key(
    key_version: u8,
    key_id: u8,
    key_data: &[u8],
) -> apdu_manager::ApduStatus {
    call_selected_security_domain_encoded(SddispatchOpcode::PUT_KEY, |out| {
        encode_sddispatch_put_key(key_version, key_id, key_data, out)
    })
}

pub fn security_domain_authorize_store_data(tag: u16, data: &[u8]) -> apdu_manager::ApduStatus {
    call_selected_security_domain_encoded(SddispatchOpcode::STORE_DATA, |out| {
        encode_sddispatch_store_data(tag, data, out)
    })
}

pub fn security_domain_authorize_set_status(
    target_kind: u8,
    target_state: u8,
    target_aid: &Aid,
) -> apdu_manager::ApduStatus {
    call_selected_security_domain_encoded(SddispatchOpcode::SET_STATUS, |out| {
        if out.len() < 2 {
            return None;
        }
        out[0] = target_kind;
        out[1] = target_state;
        encode_sddispatch_one_aid(target_aid, &mut out[2..]).map(|len| 2 + len)
    })
}

pub fn security_domain_supports_secure_channel_protocol(
    protocol: crate::security_domain::SecureChannelProtocol,
) -> bool {
    let build_mode = crate::core::target::secure_channel_mode();
    match protocol {
        crate::security_domain::SecureChannelProtocol::Scp03 => {
            if !build_mode.supports_scp03() {
                return false;
            }
            let status = call_selected_security_domain(SddispatchOpcode::SUPPORTS_SCP03, &[]);
            if status.sw1 != 0x90 || status.sw2 != 0x00 {
                return false;
            }
            selected_security_domain_bool_response().unwrap_or(false)
        }
        crate::security_domain::SecureChannelProtocol::Scp11(
            crate::core::scp11::Scp11Profile::A,
        ) => {
            if !build_mode.supports_scp11()
                || !crate::core::target::scp11_profiles()
                    .supports(crate::core::scp11::Scp11Profile::A)
            {
                return false;
            }
            let status = call_selected_security_domain(SddispatchOpcode::SUPPORTS_SCP11A, &[]);
            if status.sw1 != 0x90 || status.sw2 != 0x00 {
                return false;
            }
            selected_security_domain_bool_response().unwrap_or(false)
        }
        crate::security_domain::SecureChannelProtocol::Scp11(
            crate::core::scp11::Scp11Profile::B,
        ) => {
            if !build_mode.supports_scp11()
                || !crate::core::target::scp11_profiles()
                    .supports(crate::core::scp11::Scp11Profile::B)
            {
                return false;
            }
            let status = call_selected_security_domain(SddispatchOpcode::SUPPORTS_SCP11B, &[]);
            if status.sw1 != 0x90 || status.sw2 != 0x00 {
                return false;
            }
            selected_security_domain_bool_response().unwrap_or(false)
        }
        crate::security_domain::SecureChannelProtocol::Scp11(
            crate::core::scp11::Scp11Profile::C,
        ) => {
            if !build_mode.supports_scp11()
                || !crate::core::target::scp11_profiles()
                    .supports(crate::core::scp11::Scp11Profile::C)
            {
                return false;
            }
            let status = call_selected_security_domain(SddispatchOpcode::SUPPORTS_SCP11C, &[]);
            if status.sw1 != 0x90 || status.sw2 != 0x00 {
                return false;
            }
            selected_security_domain_bool_response().unwrap_or(false)
        }
    }
}

/// Asks the selected Rustlet Security Domain to claim one otherwise unknown
/// secure-channel establishment header.
pub fn security_domain_claims_delegated_secure_channel_command(
    header: crate::security_domain::DelegatedSecureChannelHeader,
) -> bool {
    let status = call_selected_security_domain(
        SddispatchOpcode::CLAIM_DELEGATED_SECURE_CHANNEL,
        &[header.cla, header.ins, header.p1, header.p2, header.p3],
    );
    status.sw1 == 0x90
        && status.sw2 == 0x00
        && selected_security_domain_bool_response().unwrap_or(false)
}

/// Dispatches one claimed establishment command without kernel protocol
/// decoding and returns the response length already staged in the shared page.
pub fn security_domain_handle_delegated_secure_channel_command(
    command: &crate::security_domain::SecureChannelEstablishmentCommand<'_>,
) -> Result<usize, apdu_manager::ApduStatus> {
    let status = call_selected_security_domain_encoded(
        SddispatchOpcode::HANDLE_DELEGATED_SECURE_CHANNEL,
        |out| encode_sddispatch_delegated_secure_channel(command, out),
    );
    if status.sw1 != 0x90 || status.sw2 != 0x00 {
        return Err(status);
    }
    selected_security_domain_response_len()
}

pub fn security_domain_scp11_stage_oce_certificate(
    ca_key_version: u8,
    ca_key_id: u8,
    public_key: &[u8],
    subject_id: &[u8],
    discretionary_data: &[u8],
) -> Result<(), apdu_manager::ApduStatus> {
    let status = call_selected_security_domain_encoded(
        SddispatchOpcode::SCP11_STAGE_OCE_CERTIFICATE,
        |out| {
            encode_sddispatch_scp11_oce_certificate(
                ca_key_version,
                ca_key_id,
                public_key,
                subject_id,
                discretionary_data,
                out,
            )
        },
    );
    if status.sw1 != 0x90 || status.sw2 != 0x00 {
        return Err(status);
    }
    Ok(())
}

pub fn security_domain_scp11a_mutual_authenticate(
    ecka_key_version: u8,
    ecka_key_id: u8,
    request: &crate::core::scp11::MutualAuthenticateRequest<'_>,
) -> Result<usize, apdu_manager::ApduStatus> {
    let status = call_selected_security_domain_encoded(
        SddispatchOpcode::SCP11A_MUTUAL_AUTHENTICATE,
        |out| {
            encode_sddispatch_scp11a_mutual_authenticate(
                ecka_key_version,
                ecka_key_id,
                request,
                out,
            )
        },
    );
    if status.sw1 != 0x90 || status.sw2 != 0x00 {
        return Err(status);
    }
    selected_security_domain_response_len()
}

pub fn security_domain_scp11b_internal_authenticate(
    ecka_key_version: u8,
    ecka_key_id: u8,
    request: &crate::core::scp11::MutualAuthenticateRequest<'_>,
) -> Result<usize, apdu_manager::ApduStatus> {
    let status = call_selected_security_domain_encoded(
        SddispatchOpcode::SCP11B_INTERNAL_AUTHENTICATE,
        |out| {
            encode_sddispatch_scp11b_internal_authenticate(
                ecka_key_version,
                ecka_key_id,
                request,
                out,
            )
        },
    );
    if status.sw1 != 0x90 || status.sw2 != 0x00 {
        return Err(status);
    }
    selected_security_domain_response_len()
}

pub fn security_domain_scp11c_mutual_authenticate(
    ecka_key_version: u8,
    ecka_key_id: u8,
    request: &crate::core::scp11::MutualAuthenticateRequest<'_>,
) -> Result<usize, apdu_manager::ApduStatus> {
    let status = call_selected_security_domain_encoded(
        SddispatchOpcode::SCP11C_MUTUAL_AUTHENTICATE,
        |out| {
            encode_sddispatch_scp11c_mutual_authenticate(
                ecka_key_version,
                ecka_key_id,
                request,
                out,
            )
        },
    );
    if status.sw1 != 0x90 || status.sw2 != 0x00 {
        return Err(status);
    }
    selected_security_domain_response_len()
}

pub fn security_domain_current_security_level() -> Option<u8> {
    let status = call_selected_security_domain(SddispatchOpcode::CURRENT_SECURITY_LEVEL, &[]);
    if status.sw1 != 0x90 || status.sw2 != 0x00 {
        return None;
    }
    selected_security_domain_u8_response()
}

pub fn security_domain_secure_channel_open() -> bool {
    let status = call_selected_security_domain(SddispatchOpcode::SECURE_CHANNEL_OPEN, &[]);
    if status.sw1 != 0x90 || status.sw2 != 0x00 {
        return false;
    }
    selected_security_domain_bool_response().unwrap_or(false)
}

pub fn security_domain_current_mac_len() -> Option<usize> {
    let status = call_selected_security_domain(SddispatchOpcode::CURRENT_MAC_LEN, &[]);
    if status.sw1 != 0x90 || status.sw2 != 0x00 {
        return None;
    }
    selected_security_domain_u16_response().map(|value| value as usize)
}

pub fn security_domain_initialize_update(
    key_version: u8,
    key_id: u8,
    host_challenge: &[u8],
) -> Result<usize, apdu_manager::ApduStatus> {
    let status =
        call_selected_security_domain_encoded(SddispatchOpcode::INITIALIZE_UPDATE, |out| {
            encode_sddispatch_initialize_update(key_version, key_id, host_challenge, out)
        });
    if status.sw1 != 0x90 || status.sw2 != 0x00 {
        return Err(status);
    }
    selected_security_domain_response_len()
}

pub fn security_domain_external_authenticate(
    cla: u8,
    security_level: u8,
    p2: u8,
    authentication_data: &[u8],
) -> Result<u8, apdu_manager::ApduStatus> {
    let status =
        call_selected_security_domain_encoded(SddispatchOpcode::EXTERNAL_AUTHENTICATE, |out| {
            encode_sddispatch_external_authenticate(
                cla,
                security_level,
                p2,
                authentication_data,
                out,
            )
        });
    if status.sw1 != 0x90 || status.sw2 != 0x00 {
        return Err(status);
    }
    selected_security_domain_u8_response().ok_or(from_abi_status(
        rustlet_runtime::ApduStatus::internal_error(),
    ))
}

pub fn security_domain_unwrap_command(
    authenticated_header: &[u8],
    authenticated_data: &[u8],
    data: &[u8],
    mac: &[u8],
    out: &mut [u8],
) -> Result<usize, apdu_manager::ApduStatus> {
    let status = call_selected_security_domain_encoded(SddispatchOpcode::UNWRAP_COMMAND, |out| {
        encode_sddispatch_unwrap_command(authenticated_header, authenticated_data, data, mac, out)
    });
    if status.sw1 != 0x90 || status.sw2 != 0x00 {
        return Err(status);
    }
    selected_security_domain_bytes_response(out)
}

pub fn security_domain_wrap_response(
    data: &[u8],
    status: (u8, u8),
    wrapped_data_out: &mut [u8],
    wrapped_mac_out: &mut [u8],
) -> Result<(usize, usize), apdu_manager::ApduStatus> {
    let status_word = status;
    let status = call_selected_security_domain_encoded(SddispatchOpcode::WRAP_RESPONSE, |out| {
        encode_sddispatch_wrap_response(data, status_word, out)
    });
    if status.sw1 != 0x90 || status.sw2 != 0x00 {
        return Err(status);
    }

    let Some(selected_security_domain) = selected_security_domain_mut() else {
        return Err(apdu_manager::ApduStatus::conditions_not_satisfied());
    };
    let response = selected_security_domain
        .loaded_fae
        .shared_buffer
        .outgoing_data();
    if response.len() < 4 {
        return Err(apdu_manager::ApduStatus::wrong_data());
    }
    let data_len = ((response[0] as usize) << 8) | response[1] as usize;
    let mac_len = ((response[2] as usize) << 8) | response[3] as usize;
    let Some(data_end) = 4usize.checked_add(data_len) else {
        return Err(apdu_manager::ApduStatus::wrong_data());
    };
    let Some(mac_end) = data_end.checked_add(mac_len) else {
        return Err(apdu_manager::ApduStatus::wrong_data());
    };
    if mac_end != response.len()
        || data_len > wrapped_data_out.len()
        || mac_len > wrapped_mac_out.len()
    {
        return Err(apdu_manager::ApduStatus::wrong_length());
    }
    wrapped_data_out[..data_len].copy_from_slice(&response[4..data_end]);
    wrapped_mac_out[..mac_len].copy_from_slice(&response[data_end..mac_end]);
    Ok((data_len, mac_len))
}

pub fn security_domain_reset_secure_channel() {
    let _ = call_selected_security_domain(SddispatchOpcode::RESET_SECURE_CHANNEL, &[]);
}

pub fn security_domain_may_manage_applet(
    package_aid: &Aid,
    applet_aid: &Aid,
    instance_aid: &Aid,
) -> bool {
    let status =
        call_selected_security_domain_encoded(SddispatchOpcode::MAY_MANAGE_APPLET, |out| {
            encode_sddispatch_three_aids(package_aid, applet_aid, instance_aid, out)
        });
    if status.sw1 != 0x90 || status.sw2 != 0x00 {
        return false;
    }
    selected_security_domain_bool_response().unwrap_or(false)
}

pub fn security_domain_may_make_selectable(instance_aid: &Aid) -> bool {
    let status =
        call_selected_security_domain_encoded(SddispatchOpcode::MAY_MAKE_SELECTABLE, |out| {
            encode_sddispatch_one_aid(instance_aid, out)
        });
    if status.sw1 != 0x90 || status.sw2 != 0x00 {
        return false;
    }
    selected_security_domain_bool_response().unwrap_or(false)
}

pub fn security_domain_get_data(
    tag: u16,
    out: &mut [u8],
) -> Result<usize, apdu_manager::ApduStatus> {
    let payload = [(tag >> 8) as u8, tag as u8];
    let status = call_selected_security_domain(SddispatchOpcode::GET_DATA, &payload);
    if status.sw1 != 0x90 || status.sw2 != 0x00 {
        return Err(status);
    }

    let Some(selected_security_domain) = selected_security_domain_mut() else {
        return Err(apdu_manager::ApduStatus::conditions_not_satisfied());
    };
    let data = selected_security_domain
        .loaded_fae
        .shared_buffer
        .outgoing_data();
    if data.len() > out.len() {
        return Err(apdu_manager::ApduStatus::wrong_length());
    }
    copy_sddispatch_bytes_at(out, 0, data).ok_or_else(apdu_manager::ApduStatus::wrong_length)?;
    Ok(data.len())
}

fn dispatch_install_handler_encoded(
    encode_payload: impl FnOnce(&mut [u8]) -> Option<usize>,
) -> fae_runtime::HandlerCallResult {
    let Some(selected_app) = selected_app_mut() else {
        return fae_runtime::HandlerCallResult {
            status: rustlet_runtime::ApduStatus::conditions_not_satisfied(),
            returned_normally: false,
        };
    };

    let handler = selected_app_vtable(selected_app).install as usize;
    let allocator = core::ptr::addr_of_mut!(selected_app.allocator);
    let _active_call = ActiveAppCallGuard::install_shared_only(&selected_app.loaded_fae, allocator);
    fae_runtime::call_handler_with_encoded_command(
        &selected_app.loaded_fae,
        handler,
        selected_app.state,
        rustlet_runtime::RustletApduHeader {
            cla: 0x80,
            ins: INS_INSTALL,
            p1: 0x0c,
            p2: 0x00,
            lc: 0x00,
            le: 0x00,
        },
        encode_payload,
        &[],
    )
}

fn dispatch_install_handler_current_apdu(
    header: rustlet_runtime::RustletApduHeader,
    incoming_len: usize,
) -> fae_runtime::HandlerCallResult {
    let Some(selected_app) = selected_app_mut() else {
        return fae_runtime::HandlerCallResult {
            status: rustlet_runtime::ApduStatus::conditions_not_satisfied(),
            returned_normally: false,
        };
    };

    let handler = selected_app_vtable(selected_app).install as usize;
    let allocator = core::ptr::addr_of_mut!(selected_app.allocator);
    let _active_call = ActiveAppCallGuard::install_shared_only(&selected_app.loaded_fae, allocator);
    fae_runtime::call_handler_with_existing_command(
        &selected_app.loaded_fae,
        handler,
        selected_app.state,
        header,
        incoming_len,
        &[],
    )
}

fn call_selected_security_domain(opcode: u8, payload: &[u8]) -> apdu_manager::ApduStatus {
    if payload.len() > u8::MAX as usize {
        return apdu_manager::ApduStatus::wrong_length();
    }
    call_selected_security_domain_encoded(opcode, |out| {
        if payload.len() > out.len() {
            return None;
        }
        out[..payload.len()].copy_from_slice(payload);
        Some(payload.len())
    })
}

fn call_selected_security_domain_encoded(
    opcode: u8,
    encode_payload: impl FnOnce(&mut [u8]) -> Option<usize>,
) -> apdu_manager::ApduStatus {
    let (result, security_domain_aid, package_aid, applet_aid, instance_aid) = {
        let Some(selected_security_domain) = selected_security_domain_mut() else {
            return apdu_manager::ApduStatus::conditions_not_satisfied();
        };
        let Some((security_domain_aid, package_aid, applet_aid, instance_aid)) =
            selected_security_domain.registry.identity()
        else {
            return apdu_manager::ApduStatus::conditions_not_satisfied();
        };
        let instance = selected_security_domain.registry.instance_object();
        let serialized_state = instance
            .as_ref()
            .map(|instance| instance.serialized_state().unwrap_or(&[]))
            .unwrap_or(&[]);
        let allocator = core::ptr::addr_of_mut!(selected_security_domain.allocator);
        let _active_call = ActiveAppCallGuard::install_shared_only(
            &selected_security_domain.loaded_fae,
            allocator,
        );
        let Some(vtable) = selected_security_domain_vtable(selected_security_domain) else {
            return apdu_manager::ApduStatus::instruction_not_supported();
        };
        let result = fae_runtime::call_handler_with_encoded_command(
            &selected_security_domain.loaded_fae,
            vtable.sddispatch as usize,
            selected_security_domain.state,
            rustlet_runtime::RustletApduHeader {
                cla: SDDISPATCH_CLA,
                ins: opcode,
                p1: 0x00,
                p2: 0x00,
                lc: 0x00,
                le: 0x00,
            },
            encode_payload,
            serialized_state,
        );

        (
            result,
            security_domain_aid,
            package_aid,
            applet_aid,
            instance_aid,
        )
    };

    let status = from_abi_status(result.status);
    if result.returned_normally {
        let save_status = save_selected_security_domain_state(
            &security_domain_aid,
            &package_aid,
            &applet_aid,
            &instance_aid,
        );
        if save_status.sw1 == 0x90 && save_status.sw2 == 0x00 {
            status
        } else {
            save_status
        }
    } else {
        status
    }
}

fn encode_sddispatch_install_for_load(package_aid: &Aid, out: &mut [u8]) -> Option<usize> {
    let mut offset = 0;
    push_sddispatch_aid(out, &mut offset, package_aid)?;
    push_sddispatch_lv(out, &mut offset, &[])?;
    Some(offset)
}

fn encode_sddispatch_install_for_install(
    package_aid: &Aid,
    applet_aid: &Aid,
    instance_aid: &Aid,
    privileges: &[u8],
    install_parameters: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let mut offset = 0;
    push_sddispatch_aid(out, &mut offset, package_aid)?;
    push_sddispatch_aid(out, &mut offset, applet_aid)?;
    push_sddispatch_aid(out, &mut offset, instance_aid)?;
    push_sddispatch_lv(out, &mut offset, privileges)?;
    push_sddispatch_lv(out, &mut offset, install_parameters)?;
    Some(offset)
}

fn encode_sddispatch_put_key(
    key_version: u8,
    key_id: u8,
    key_data: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let end = 2usize.checked_add(key_data.len())?;
    if end > out.len() {
        return None;
    }
    // Invariant: key_data may already live in `out` when transport uses the
    // shared APDU buffer; move it before writing the dispatch prefix.
    copy_sddispatch_bytes_at(out, 2, key_data)?;
    out[0] = key_version;
    out[1] = key_id;
    Some(end)
}

fn encode_sddispatch_store_data(tag: u16, data: &[u8], out: &mut [u8]) -> Option<usize> {
    let end = 2usize.checked_add(data.len())?;
    if end > out.len() {
        return None;
    }
    // Invariant: STORE DATA payload may alias `out`; move it before writing
    // the tag prefix.
    copy_sddispatch_bytes_at(out, 2, data)?;
    out[0] = (tag >> 8) as u8;
    out[1] = tag as u8;
    Some(end)
}

fn encode_sddispatch_three_aids(
    package_aid: &Aid,
    applet_aid: &Aid,
    instance_aid: &Aid,
    out: &mut [u8],
) -> Option<usize> {
    let mut offset = 0;
    push_sddispatch_aid(out, &mut offset, package_aid)?;
    push_sddispatch_aid(out, &mut offset, applet_aid)?;
    push_sddispatch_aid(out, &mut offset, instance_aid)?;
    Some(offset)
}

fn encode_sddispatch_one_aid(aid: &Aid, out: &mut [u8]) -> Option<usize> {
    let mut offset = 0;
    push_sddispatch_aid(out, &mut offset, aid)?;
    Some(offset)
}

fn encode_sddispatch_initialize_update(
    key_version: u8,
    key_id: u8,
    host_challenge: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let end = 2usize.checked_add(host_challenge.len())?;
    if end > out.len() {
        return None;
    }
    // Invariant: host_challenge may already live in `out`; move it before
    // writing key version/id at the beginning of the dispatch payload.
    copy_sddispatch_bytes_at(out, 2, host_challenge)?;
    out[0] = key_version;
    out[1] = key_id;
    Some(end)
}

fn encode_sddispatch_delegated_secure_channel(
    command: &crate::security_domain::SecureChannelEstablishmentCommand<'_>,
    out: &mut [u8],
) -> Option<usize> {
    let end = 5usize.checked_add(command.data.len())?;
    if end > out.len() {
        return None;
    }
    copy_sddispatch_bytes_at(out, 5, command.data)?;
    out[..5].copy_from_slice(&[command.cla, command.ins, command.p1, command.p2, command.p3]);
    Some(end)
}

fn encode_sddispatch_external_authenticate(
    cla: u8,
    security_level: u8,
    p2: u8,
    authentication_data: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let end = 3usize.checked_add(authentication_data.len())?;
    if end > out.len() {
        return None;
    }
    // Invariant: authentication_data may alias `out`; move it before writing
    // the command-header fields at the beginning of the dispatch payload.
    copy_sddispatch_bytes_at(out, 3, authentication_data)?;
    out[0] = cla;
    out[1] = security_level;
    out[2] = p2;
    Some(end)
}

fn encode_sddispatch_scp11_oce_certificate(
    ca_key_version: u8,
    ca_key_id: u8,
    public_key: &[u8],
    subject_id: &[u8],
    discretionary_data: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let mut offset = 0;
    push_sddispatch_byte(out, &mut offset, ca_key_version)?;
    push_sddispatch_byte(out, &mut offset, ca_key_id)?;
    push_sddispatch_lv(out, &mut offset, public_key)?;
    push_sddispatch_lv(out, &mut offset, subject_id)?;
    push_sddispatch_lv(out, &mut offset, discretionary_data)?;
    Some(offset)
}

fn encode_sddispatch_scp11a_mutual_authenticate(
    ecka_key_version: u8,
    ecka_key_id: u8,
    request: &crate::core::scp11::MutualAuthenticateRequest<'_>,
    out: &mut [u8],
) -> Option<usize> {
    let mut offset = 0;
    push_sddispatch_byte(out, &mut offset, ecka_key_version)?;
    push_sddispatch_byte(out, &mut offset, ecka_key_id)?;
    push_sddispatch_byte(
        out,
        &mut offset,
        u8::from(request.parameters.include_identifiers),
    )?;
    push_sddispatch_byte(out, &mut offset, request.key_usage_qualifier)?;
    push_sddispatch_byte(out, &mut offset, request.key_type)?;
    push_sddispatch_byte(out, &mut offset, request.key_length)?;
    push_sddispatch_lv(out, &mut offset, request.host_id)?;
    push_sddispatch_lv(out, &mut offset, request.host_ephemeral_public)?;
    Some(offset)
}

fn encode_sddispatch_scp11b_internal_authenticate(
    ecka_key_version: u8,
    ecka_key_id: u8,
    request: &crate::core::scp11::MutualAuthenticateRequest<'_>,
    out: &mut [u8],
) -> Option<usize> {
    let mut offset = 0;
    push_sddispatch_byte(out, &mut offset, ecka_key_version)?;
    push_sddispatch_byte(out, &mut offset, ecka_key_id)?;
    push_sddispatch_byte(
        out,
        &mut offset,
        u8::from(request.parameters.include_identifiers),
    )?;
    push_sddispatch_byte(out, &mut offset, request.key_usage_qualifier)?;
    push_sddispatch_byte(out, &mut offset, request.key_type)?;
    push_sddispatch_byte(out, &mut offset, request.key_length)?;
    push_sddispatch_lv(out, &mut offset, request.host_id)?;
    push_sddispatch_lv(out, &mut offset, request.host_ephemeral_public)?;
    Some(offset)
}

fn encode_sddispatch_scp11c_mutual_authenticate(
    ecka_key_version: u8,
    ecka_key_id: u8,
    request: &crate::core::scp11::MutualAuthenticateRequest<'_>,
    out: &mut [u8],
) -> Option<usize> {
    let mut offset = 0;
    push_sddispatch_byte(out, &mut offset, ecka_key_version)?;
    push_sddispatch_byte(out, &mut offset, ecka_key_id)?;
    push_sddispatch_byte(
        out,
        &mut offset,
        u8::from(request.parameters.include_identifiers),
    )?;
    push_sddispatch_byte(out, &mut offset, request.key_usage_qualifier)?;
    push_sddispatch_byte(out, &mut offset, request.key_type)?;
    push_sddispatch_byte(out, &mut offset, request.key_length)?;
    push_sddispatch_lv(out, &mut offset, request.host_id)?;
    push_sddispatch_lv(out, &mut offset, request.host_ephemeral_public)?;
    Some(offset)
}

fn encode_sddispatch_unwrap_command(
    authenticated_header: &[u8],
    authenticated_data: &[u8],
    data: &[u8],
    mac: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let authenticated_len = authenticated_header
        .len()
        .checked_add(authenticated_data.len())?;
    let auth_offset = 6usize;
    let authenticated_data_offset = auth_offset.checked_add(authenticated_header.len())?;
    let data_offset = auth_offset.checked_add(authenticated_len)?;
    let mac_offset = data_offset.checked_add(data.len())?;
    let end = mac_offset.checked_add(mac.len())?;
    if end > out.len()
        || authenticated_len > u16::MAX as usize
        || data.len() > u16::MAX as usize
        || mac.len() > u16::MAX as usize
    {
        return None;
    }
    // Invariant: any segment may alias the shared APDU buffer. Copy later
    // segments first so earlier prefixes/segments cannot overwrite sources.
    copy_sddispatch_bytes_at(out, mac_offset, mac)?;
    copy_sddispatch_bytes_at(out, data_offset, data)?;
    copy_sddispatch_bytes_at(out, authenticated_data_offset, authenticated_data)?;
    copy_sddispatch_bytes_at(out, auth_offset, authenticated_header)?;
    out[0] = (authenticated_len >> 8) as u8;
    out[1] = authenticated_len as u8;
    out[2] = (data.len() >> 8) as u8;
    out[3] = data.len() as u8;
    out[4] = (mac.len() >> 8) as u8;
    out[5] = mac.len() as u8;
    Some(end)
}

fn encode_sddispatch_wrap_response(data: &[u8], status: (u8, u8), out: &mut [u8]) -> Option<usize> {
    let end = 4usize.checked_add(data.len())?;
    if end > out.len() || data.len() > u16::MAX as usize {
        return None;
    }
    // Invariant: response data can already be staged in `out`; move it before
    // writing the response length/status prefix.
    copy_sddispatch_bytes_at(out, 4, data)?;
    out[0] = (data.len() >> 8) as u8;
    out[1] = data.len() as u8;
    out[2] = status.0;
    out[3] = status.1;
    Some(end)
}

fn push_sddispatch_byte(out: &mut [u8], offset: &mut usize, value: u8) -> Option<()> {
    let end = offset.checked_add(1)?;
    if end > out.len() {
        return None;
    }
    out[*offset] = value;
    *offset = end;
    Some(())
}

fn push_sddispatch_aid(out: &mut [u8], offset: &mut usize, aid: &Aid) -> Option<()> {
    push_sddispatch_lv(out, offset, aid.as_slice())
}

fn push_sddispatch_lv(out: &mut [u8], offset: &mut usize, value: &[u8]) -> Option<()> {
    if value.len() > u8::MAX as usize {
        return None;
    }
    let end = offset.checked_add(1)?.checked_add(value.len())?;
    if end > out.len() {
        return None;
    }
    // Invariant: value may alias `out`; move it before writing the length
    // prefix that could overlap the source bytes.
    copy_sddispatch_bytes_at(out, *offset + 1, value)?;
    out[*offset] = value.len() as u8;
    *offset = end;
    Some(())
}

fn copy_sddispatch_bytes_at(out: &mut [u8], dst: usize, value: &[u8]) -> Option<()> {
    let end = dst.checked_add(value.len())?;
    if end > out.len() {
        return None;
    }
    let out_start = out.as_ptr() as usize;
    let out_end = out_start.checked_add(out.len())?;
    let value_start = value.as_ptr() as usize;
    let value_end = value_start.checked_add(value.len())?;
    if value_start >= out_start && value_end <= out_end {
        let src = value_start.checked_sub(out_start)?;
        out.copy_within(src..src + value.len(), dst);
    } else {
        out[dst..end].copy_from_slice(value);
    }
    Some(())
}

fn selected_security_domain_bool_response() -> Option<bool> {
    let selected_security_domain = selected_security_domain_mut()?;
    let data = selected_security_domain
        .loaded_fae
        .shared_buffer
        .outgoing_data();
    if data.len() != 1 {
        return None;
    }
    Some(data[0] == SDDISPATCH_BOOL_TRUE)
}

fn selected_security_domain_u8_response() -> Option<u8> {
    let selected_security_domain = selected_security_domain_mut()?;
    let data = selected_security_domain
        .loaded_fae
        .shared_buffer
        .outgoing_data();
    if data.len() != 1 {
        return None;
    }
    Some(data[0])
}

fn selected_security_domain_u16_response() -> Option<u16> {
    let selected_security_domain = selected_security_domain_mut()?;
    let data = selected_security_domain
        .loaded_fae
        .shared_buffer
        .outgoing_data();
    if data.len() != 2 {
        return None;
    }
    Some(((data[0] as u16) << 8) | data[1] as u16)
}

fn selected_security_domain_bytes_response(
    out: &mut [u8],
) -> Result<usize, apdu_manager::ApduStatus> {
    let Some(selected_security_domain) = selected_security_domain_mut() else {
        return Err(apdu_manager::ApduStatus::conditions_not_satisfied());
    };
    let data = selected_security_domain
        .loaded_fae
        .shared_buffer
        .outgoing_data();
    if data.len() > out.len() {
        return Err(apdu_manager::ApduStatus::wrong_length());
    }
    out[..data.len()].copy_from_slice(data);
    Ok(data.len())
}

/// Returns the length of a response already published in the shared APDU payload.
///
/// Establishment callers deliberately do not copy these bytes: the transport
/// APDU and SDDISPATCH use the same kernel-owned gate page.
fn selected_security_domain_response_len() -> Result<usize, apdu_manager::ApduStatus> {
    let Some(selected_security_domain) = selected_security_domain_mut() else {
        return Err(apdu_manager::ApduStatus::conditions_not_satisfied());
    };
    Ok(selected_security_domain
        .loaded_fae
        .shared_buffer
        .outgoing_data()
        .len())
}

fn install_selected_app(
    registry: AppRegistryReference,
    mut loaded: fae_runtime::LoadedFae,
    descriptor: &SelectedAppDescriptor,
) -> Result<(), u8> {
    if descriptor.heap.storage_start.is_null() {
        fae_runtime::unload(loaded);
        return Err(0x10);
    }
    if descriptor.heap.storage_len == 0 {
        fae_runtime::unload(loaded);
        return Err(0x11);
    }
    if !fae_runtime::configure_heap_window(&mut loaded, descriptor.heap) {
        fae_runtime::unload(loaded);
        return Err(0x14);
    }
    let required_metadata_len =
        oxi_core::core::metadata_size_for_heap_size(descriptor.heap.storage_len);
    let allocator_metadata = match AllocatorMetadata::allocate(required_metadata_len) {
        Some(metadata) => metadata,
        None => {
            fae_runtime::unload(loaded);
            return Err(0x12);
        }
    };

    set_selected_app(Some(LoadedApp {
        registry,
        loaded_fae: loaded,
        state: descriptor.state,
        vtable: descriptor.vtable,
        security_domain_vtable: descriptor.security_domain_vtable,
        allocator: oxi_core::core::HeapAllocatorState::new(),
        allocator_metadata,
    }));

    let Some(selected_app) = selected_app_mut() else {
        return Err(0x13);
    };

    let heap_ready = unsafe {
        oxi_core::core::reset_heap(
            core::ptr::addr_of_mut!(selected_app.allocator),
            descriptor.heap.storage_start,
            descriptor.heap.storage_len,
            selected_app.allocator_metadata.as_mut_ptr(),
            selected_app.allocator_metadata.len(),
        )
    };
    if !heap_ready {
        set_selected_app(None);
        return Err(0x15);
    }

    Ok(())
}

fn initialize_registry() {
    unsafe {
        let registry = &mut *core::ptr::addr_of_mut!(OBJECT_REGISTRY);
        registry.clear();
        let security_domain_aid = top_level_parent_sd_aid();
        embedded_apps::for_each_embedded_registry_seed(|seed| {
            let _ = registry.insert_package_object(
                security_domain_aid,
                seed.package_aid,
                seed.applet_aid,
                seed.fae,
            );
        });
    }
}

pub fn top_level_parent_sd_aid() -> Aid {
    Aid::new(&[])
}

pub fn root_security_domain_instance_aid() -> Aid {
    crate::security_domain::root_security_domain_aid()
}

pub fn active_security_domain_instance_aid() -> Aid {
    let active_slot =
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ACTIVE_SECURITY_DOMAIN_SLOT)) };
    active_slot
        .and_then(|slot| unsafe {
            (&*core::ptr::addr_of!(OBJECT_REGISTRY))
                .resolve(slot)
                .map(|object| object.object_aid)
        })
        .unwrap_or_else(root_security_domain_instance_aid)
}

pub fn ensure_active_security_domain_loaded_for_secure_channel(
) -> Result<Option<usize>, apdu_manager::ApduStatus> {
    let active = active_security_domain_instance_aid();
    let Some(active_object) = find_any_object_by_aid_raw(&active) else {
        return Ok(None);
    };
    let Some(active_slot) = registry_index_for_object(active_object) else {
        return Ok(None);
    };
    if active_object.object_kind != ManagedObjectKind::SecurityDomain
        || active_object.security_domain_backend()
            != Some(SecurityDomainObjectBackend::RustletSecurityDomain)
    {
        return Ok(None);
    }
    let already_loaded = unsafe {
        let slot = core::ptr::addr_of!(SELECTED_SECURITY_DOMAIN);
        (&*slot)
            .as_ref()
            .is_some_and(|app| app.registry.instance_index() == Some(active_slot))
    };
    if already_loaded {
        return Ok(None);
    }

    // The active Rustlet Security Domain normally remains resident while an
    // ordinary Rustlet occupies SELECTED_APP. This recovery path reloads a
    // missing SD without ever treating its volatile SCP state as persistent.
    let mut displaced_app = None;
    if let Some(selected_app) = current_selected_app_mut() {
        let registry = selected_app.registry;
        displaced_app = registry.instance_index();
        let Some((security_domain_aid, package_aid, applet_aid, instance_aid)) =
            registry.identity()
        else {
            return Err(apdu_manager::ApduStatus::conditions_not_satisfied());
        };
        let save_status = save_selected_instance_state(
            &security_domain_aid,
            &package_aid,
            &applet_aid,
            &instance_aid,
            None,
        );
        if save_status.sw1 != 0x90 || save_status.sw2 != 0x00 {
            return Err(save_status);
        }
        set_selected_app(None);
    }

    let Some(reference) = AppRegistryReference::from_instance(active_slot) else {
        return Err(apdu_manager::ApduStatus::conditions_not_satisfied());
    };
    let Some(instance) = reference.instance_object() else {
        return Err(apdu_manager::ApduStatus::conditions_not_satisfied());
    };
    let status = activate_registry_reference(reference);
    if status.sw1 != 0x90 || status.sw2 != 0x00 {
        return Err(status);
    }
    let Some(selected_security_domain) = current_selected_app_mut() else {
        return Err(apdu_manager::ApduStatus::conditions_not_satisfied());
    };
    if !selected_security_domain
        .loaded_fae
        .shared_buffer
        .stage_state_from_registry(instance.serialized_state().unwrap_or(&[]))
    {
        set_selected_app(None);
        return Err(apdu_manager::ApduStatus::wrong_length());
    }
    promote_selected_app_to_security_domain();
    Ok(displaced_app)
}

pub fn restore_selected_app_after_secure_channel(
    displaced_app: Option<usize>,
) -> apdu_manager::ApduStatus {
    let Some(instance_index) = displaced_app else {
        return apdu_manager::ApduStatus::success();
    };
    let Some(reference) = AppRegistryReference::from_instance(instance_index) else {
        return apdu_manager::ApduStatus::file_not_found();
    };
    let Some(instance) = reference.instance_object() else {
        return apdu_manager::ApduStatus::file_not_found();
    };
    if is_security_domain_kind(instance.object_kind) {
        return apdu_manager::ApduStatus::conditions_not_satisfied();
    }
    let status = activate_registry_reference(reference);
    if status.sw1 != 0x90 || status.sw2 != 0x00 {
        return status;
    }
    let Some(selected_app) = selected_app_mut() else {
        return apdu_manager::ApduStatus::conditions_not_satisfied();
    };
    if !selected_app
        .loaded_fae
        .shared_buffer
        .stage_state_from_registry(instance.serialized_state().unwrap_or(&[]))
    {
        set_selected_app(None);
        return apdu_manager::ApduStatus::wrong_length();
    }
    apdu_manager::ApduStatus::success()
}

pub fn set_active_security_domain_instance_aid(aid: Aid) {
    let previous = active_security_domain_instance_aid();
    let slot = unsafe {
        (&*core::ptr::addr_of!(OBJECT_REGISTRY))
            .find_any_index(&aid)
            .filter(|index| {
                (&*core::ptr::addr_of!(OBJECT_REGISTRY))
                    .resolve(*index)
                    .is_some_and(|object| object.object_kind == ManagedObjectKind::SecurityDomain)
            })
    };
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(ACTIVE_SECURITY_DOMAIN_SLOT), slot);
    }
    let next = active_security_domain_instance_aid();
    if previous != next {
        crate::security_domain::on_active_security_domain_instance_switched(previous, next);
    }
}

fn pending_registry_reference_for_install(
    security_domain_aid: &Aid,
    package_aid: &Aid,
    applet_aid: &Aid,
) -> Option<usize> {
    let registry = unsafe { &*core::ptr::addr_of!(OBJECT_REGISTRY) };
    let package_index = registry
        .find_index(security_domain_aid, ManagedObjectKind::Package, package_aid)
        .or_else(|| {
            registry.find_index(
                &top_level_parent_sd_aid(),
                ManagedObjectKind::Package,
                package_aid,
            )
        })?;
    let package = registry.resolve(package_index)?;
    if !package.may_instantiate_package() {
        return None;
    }
    if package.package_applet_aid() != Some(*applet_aid) {
        return None;
    }
    Some(package_index)
}

fn registry_index_for_object(object: &RegistryObject) -> Option<usize> {
    unsafe {
        (&*core::ptr::addr_of!(OBJECT_REGISTRY)).find_index(
            &object.parent_sd_aid,
            object.object_kind,
            &object.object_aid,
        )
    }
}

fn find_security_domain_object_by_aid(
    parent_sd_aid: &Aid,
    aid: &Aid,
) -> Option<&'static RegistryObject> {
    unsafe {
        (&*core::ptr::addr_of!(OBJECT_REGISTRY)).find_security_domain_object(parent_sd_aid, aid)
    }
}

fn find_instance_object_by_aid(parent_sd_aid: &Aid, aid: &Aid) -> Option<&'static RegistryObject> {
    unsafe { (&*core::ptr::addr_of!(OBJECT_REGISTRY)).find_instance_object(parent_sd_aid, aid) }
}

fn find_key_object_by_aid(parent_sd_aid: &Aid, aid: &Aid) -> Option<&'static RegistryObject> {
    unsafe { (&*core::ptr::addr_of!(OBJECT_REGISTRY)).find_key_object(parent_sd_aid, aid) }
}

fn find_any_object_by_aid_raw(aid: &Aid) -> Option<&'static RegistryObject> {
    unsafe { (&*core::ptr::addr_of!(OBJECT_REGISTRY)).find_any_object(aid) }
}

fn find_object_by_kind_and_aid_raw(
    kind: ManagedObjectKind,
    aid: &Aid,
) -> Option<&'static RegistryObject> {
    unsafe {
        (&*core::ptr::addr_of!(OBJECT_REGISTRY))
            .entries()
            .find(|object| object.object_kind == kind && object.object_aid == *aid)
    }
}

fn find_visible_object_by_aid(aid: &Aid) -> Option<&'static RegistryObject> {
    let object = find_any_object_by_aid_raw(aid)?;
    if active_security_domain_may_reach_instance(aid) {
        Some(object)
    } else {
        None
    }
}

fn find_runtime_state_object_by_aid(
    parent_sd_aid: &Aid,
    aid: &Aid,
) -> Option<&'static RegistryObject> {
    find_security_domain_object_by_aid(parent_sd_aid, aid)
        .or_else(|| find_instance_object_by_aid(parent_sd_aid, aid))
}

pub fn security_domain_backend_by_aid(aid: &Aid) -> Option<SecurityDomainObjectBackend> {
    let object = find_visible_object_by_aid(aid)?;
    if object.object_kind != ManagedObjectKind::SecurityDomain {
        return None;
    }
    object.security_domain_backend()
}

pub fn security_domain_may_open_secure_channel(aid: &Aid) -> bool {
    let Some(object) = find_visible_object_by_aid(aid) else {
        return false;
    };
    object.object_kind == ManagedObjectKind::SecurityDomain && object.may_open_secure_channel()
}

pub fn security_domain_privilege_bytes_by_aid(aid: &Aid) -> Option<[u8; 3]> {
    let object = find_visible_object_by_aid(aid)?;
    if object.object_kind != ManagedObjectKind::SecurityDomain {
        return None;
    }
    object.security_domain_privilege_bytes()
}

pub fn find_security_domain_state_by_aid(aid: &Aid) -> Option<&'static [u8]> {
    let object = find_visible_object_by_aid(aid)?;
    if object.object_kind != ManagedObjectKind::SecurityDomain {
        return None;
    }
    object.serialized_state()
}

pub fn find_managed_object_kind_by_aid(aid: &Aid) -> Option<ManagedObjectKind> {
    find_visible_object_by_aid(aid).map(|instance| instance.object_kind)
}

pub fn upsert_security_domain_state_object(
    parent_sd_aid: Aid,
    package_aid: Aid,
    instance_aid: Aid,
    backend: SecurityDomainObjectBackend,
    privilege_bytes: [u8; 3],
    state: &[u8],
) -> bool {
    let inserted = unsafe {
        (&mut *core::ptr::addr_of_mut!(OBJECT_REGISTRY)).upsert_security_domain_object(
            parent_sd_aid,
            instance_aid,
            package_aid,
            backend,
            privilege_bytes,
            state,
        )
    };
    if inserted {
        publish_persistent_registry_after_mutation();
    }
    inserted
}

pub fn install_kernel_side_security_domain_instance(
    backend: SecurityDomainObjectBackend,
    parent_sd_aid: Aid,
    package_aid: Aid,
    instance_aid: Aid,
    install_payload: &[u8],
) -> apdu_manager::ApduStatus {
    let Some(privileges) = install_payload.get(..3) else {
        return apdu_manager::ApduStatus::wrong_length();
    };
    let Some(encoded_state) = crate::security_domain::encode_administrative_state(privileges)
    else {
        return apdu_manager::ApduStatus::wrong_data();
    };
    let privilege_bytes = [
        privileges[0],
        *privileges.get(1).unwrap_or(&0),
        *privileges.get(2).unwrap_or(&0),
    ];
    if parent_sd_aid == top_level_parent_sd_aid() {
        if instance_aid != root_security_domain_instance_aid() {
            return apdu_manager::ApduStatus::conditions_not_satisfied();
        }
    } else {
        let Some(parent) =
            find_object_by_kind_and_aid_raw(ManagedObjectKind::SecurityDomain, &parent_sd_aid)
        else {
            return apdu_manager::ApduStatus::conditions_not_satisfied();
        };
        let Some(parent_privileges) = parent.security_domain_privilege_bytes().and_then(|bytes| {
            crate::security_domain::SecurityDomainPrivileges::from_install_bytes(&bytes)
        }) else {
            return apdu_manager::ApduStatus::conditions_not_satisfied();
        };
        let Some(child_privileges) =
            crate::security_domain::SecurityDomainPrivileges::from_install_bytes(&privilege_bytes)
        else {
            return apdu_manager::ApduStatus::wrong_data();
        };
        if !parent_privileges.contains(child_privileges) {
            return apdu_manager::ApduStatus::conditions_not_satisfied();
        }
    }
    if unsafe {
        (&mut *core::ptr::addr_of_mut!(OBJECT_REGISTRY)).upsert_security_domain_object(
            parent_sd_aid,
            instance_aid,
            package_aid,
            backend,
            privilege_bytes,
            &encoded_state,
        )
    } {
        if matches!(backend, SecurityDomainObjectBackend::KernelSecurityDomain)
            && parent_sd_aid != top_level_parent_sd_aid()
        {
            let cloned = unsafe {
                (&mut *core::ptr::addr_of_mut!(OBJECT_REGISTRY))
                    .clone_scp03_keys(parent_sd_aid, instance_aid)
            };
            if !cloned {
                return apdu_manager::ApduStatus::conditions_not_satisfied();
            }
        }
        publish_persistent_registry_after_mutation();
        apdu_manager::ApduStatus::success()
    } else {
        apdu_manager::ApduStatus::conditions_not_satisfied()
    }
}

/// Derives the synthetic registry AID used to store one SCP03 key object.
///
/// The tuple `(key_version, key_id, usage)` must map to a stable object AID so
/// that `PUT KEY`, `INITIALIZE UPDATE`, and later persistence all resolve the
/// same material through one lookup path.
fn scp03_key_object_instance_aid(key_version: u8, key_id: u8, usage: u8) -> Aid {
    Aid::from_array([0x4B, 0x45, 0x59, key_version, key_id, usage])
}

fn upsert_typed_key_object(
    parent_sd_aid: Aid,
    key_version: u8,
    key_id: u8,
    usage: u8,
    key_type: KeyObjectType,
    key_material: &[u8],
) -> bool {
    let instance_aid = scp03_key_object_instance_aid(key_version, key_id, usage);
    let inserted = unsafe {
        (&mut *core::ptr::addr_of_mut!(OBJECT_REGISTRY)).upsert_key_object(
            parent_sd_aid,
            instance_aid,
            key_type,
            KeyObjectState::Active,
            key_version,
            key_id,
            usage,
            key_material,
        )
    };
    if inserted {
        publish_persistent_registry_after_mutation();
    }
    inserted
}

/// Stores or replaces one SCP03 static key object under the given Security Domain.
///
/// The kernel stores SCP03 material as typed registry objects owned by a
/// specific Security Domain instance. This keeps key visibility aligned with
/// the administrative subtree and lets the secure-channel path reuse the same
/// lookup logic as persistence and `PUT KEY`.
pub fn upsert_scp03_key_object(
    parent_sd_aid: Aid,
    key_version: u8,
    key_id: u8,
    usage: crate::security_domain::Scp03KeyUsage,
    key_material: &[u8],
) -> bool {
    if key_material.len() != crate::security_domain::SCP03_STATIC_KEY_LEN {
        return false;
    }
    upsert_typed_key_object(
        parent_sd_aid,
        key_version,
        key_id,
        usage.as_byte(),
        KeyObjectType::Scp03Static,
        key_material,
    )
}

/// Stores or replaces one SCP11 key owned by a Security Domain.
pub fn upsert_scp11_key_object(
    parent_sd_aid: Aid,
    key_version: u8,
    key_id: u8,
    usage: u8,
    key_material: &[u8],
) -> bool {
    let (key_type, expected_len) = match usage {
        crate::security_domain::SCP11_PUT_KEY_USAGE_SD_ECKA => {
            (KeyObjectType::Scp11SdEckaPrivate, 32)
        }
        crate::security_domain::SCP11_PUT_KEY_USAGE_CA_KLOC => {
            (KeyObjectType::Scp11CaKlocPublic, 65)
        }
        _ => return false,
    };
    if key_material.len() != expected_len {
        return false;
    }
    let valid = match usage {
        crate::security_domain::SCP11_PUT_KEY_USAGE_SD_ECKA => {
            let mut public = [0u8; 65];
            oxi_core::core::crypto::p256_public_from_private(key_material, &mut public).is_ok()
        }
        crate::security_domain::SCP11_PUT_KEY_USAGE_CA_KLOC => {
            let mut scalar_one = [0u8; 32];
            scalar_one[31] = 1;
            let mut shared = [0u8; 32];
            oxi_core::core::crypto::p256_ecdh(&scalar_one, key_material, &mut shared).is_ok()
        }
        _ => false,
    };
    if !valid {
        return false;
    }
    upsert_typed_key_object(
        parent_sd_aid,
        key_version,
        key_id,
        usage,
        key_type,
        key_material,
    )
}

/// Loads one active SCP11 key with the exact owner, selector and type.
pub fn load_scp11_key_material(
    parent_sd_aid: &Aid,
    key_version: u8,
    key_id: u8,
    usage: u8,
    out: &mut [u8],
) -> Option<usize> {
    let expected_type = match usage {
        crate::security_domain::SCP11_PUT_KEY_USAGE_SD_ECKA => KeyObjectType::Scp11SdEckaPrivate,
        crate::security_domain::SCP11_PUT_KEY_USAGE_CA_KLOC => KeyObjectType::Scp11CaKlocPublic,
        _ => return None,
    };
    let instance_aid = scp03_key_object_instance_aid(key_version, key_id, usage);
    let object = find_key_object_by_aid(parent_sd_aid, &instance_aid)?;
    if object.key_state()? != KeyObjectState::Active {
        return None;
    }
    let (key_type, stored_version, stored_id, stored_usage, material) = object.key_data()?;
    if key_type != expected_type
        || stored_version != key_version
        || stored_id != key_id
        || stored_usage != usage
        || out.len() < material.len()
    {
        return None;
    }
    out[..material.len()].copy_from_slice(material);
    Some(material.len())
}

fn gp_data_object_aid(tag: u16) -> Aid {
    Aid::from_array([0x44, 0x41, 0x54, 0x41, (tag >> 8) as u8, tag as u8])
}

/// Stores or replaces one GP data object under the given Security Domain.
///
/// The object AID is kernel-derived from the two-byte GET/STORE DATA tag. This
/// keeps the public APDU vocabulary tag-based while letting the polymorphic
/// registry remain uniformly AID-addressed.
pub fn upsert_registry_data_object(parent_sd_aid: Aid, tag: u16, data: &[u8]) -> bool {
    let object_aid = gp_data_object_aid(tag);
    let inserted = unsafe {
        (&mut *core::ptr::addr_of_mut!(OBJECT_REGISTRY)).upsert_data_object(
            parent_sd_aid,
            object_aid,
            data,
        )
    };
    if inserted {
        publish_persistent_registry_after_mutation();
    }
    inserted
}

/// Loads one GP data object visible under the given Security Domain.
pub fn load_registry_data_object(parent_sd_aid: &Aid, tag: u16, out: &mut [u8]) -> Option<usize> {
    let object_aid = gp_data_object_aid(tag);
    let data = unsafe {
        (&*core::ptr::addr_of!(OBJECT_REGISTRY))
            .find_data_object(parent_sd_aid, &object_aid)?
            .data_bytes()?
    };
    if out.len() < data.len() {
        return None;
    }
    out[..data.len()].copy_from_slice(data);
    Some(data.len())
}

/// Deletes one registry object reachable from the explicit management authority.
///
/// The APDU layer resolves clear and protected management commands to an
/// authority Security Domain. This helper keeps the final mutation bound to
/// that same authority instead of relying on the currently selected
/// application or Security Domain context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeleteManagedObjectResult {
    Deleted,
    NotFound,
    RelatedObjectsExist,
}

pub fn delete_visible_managed_object_under_authority(
    authority_aid: Aid,
    aid: &Aid,
    delete_related: bool,
) -> DeleteManagedObjectResult {
    let Some(object) = find_any_object_by_aid_raw(aid) else {
        return DeleteManagedObjectResult::NotFound;
    };
    if !security_domain_may_reach_object(&authority_aid, object) {
        return DeleteManagedObjectResult::NotFound;
    }
    if object.object_kind == ManagedObjectKind::SecurityDomain
        && object.object_aid == root_security_domain_instance_aid()
    {
        return DeleteManagedObjectResult::RelatedObjectsExist;
    }
    let Some(slot) = registry_index_for_object(object) else {
        return DeleteManagedObjectResult::NotFound;
    };
    let mut deletion_set = [false; DEFAULT_KERNEL_OBJECT_REGISTRY_CAPACITY];
    deletion_set[slot] = true;
    loop {
        let mut changed = false;
        let registry = unsafe { &*core::ptr::addr_of!(OBJECT_REGISTRY) };
        let mut candidate_slot = 0usize;
        while candidate_slot < DEFAULT_KERNEL_OBJECT_REGISTRY_CAPACITY {
            let Some(candidate) = registry.resolve(candidate_slot) else {
                candidate_slot += 1;
                continue;
            };
            let mut owner_slot = 0usize;
            while owner_slot < DEFAULT_KERNEL_OBJECT_REGISTRY_CAPACITY {
                let Some(owner) = registry.resolve(owner_slot) else {
                    owner_slot += 1;
                    continue;
                };
                let related = deletion_set[owner_slot]
                    && ((owner.object_kind == ManagedObjectKind::SecurityDomain
                        && candidate.parent_sd_aid == owner.object_aid)
                        || (owner.object_kind == ManagedObjectKind::Package
                            && candidate.package_aid() == Some(owner.object_aid)));
                if related && !deletion_set[candidate_slot] {
                    deletion_set[candidate_slot] = true;
                    changed = true;
                }
                owner_slot += 1;
            }
            candidate_slot += 1;
        }
        if !changed {
            break;
        }
    }

    if !delete_related && deletion_set.iter().filter(|selected| **selected).count() != 1 {
        return DeleteManagedObjectResult::RelatedObjectsExist;
    }

    // Validate the complete closure before mutating the first slot. Package
    // dependencies must never turn cumulative deletion into a cross-tree
    // operation, even if a corrupt registry contains such a relationship.
    let registry = unsafe { &*core::ptr::addr_of!(OBJECT_REGISTRY) };
    let mut candidate_slot = 0usize;
    while candidate_slot < DEFAULT_KERNEL_OBJECT_REGISTRY_CAPACITY {
        if deletion_set[candidate_slot] {
            let Some(candidate) = registry.resolve(candidate_slot) else {
                return DeleteManagedObjectResult::NotFound;
            };
            if !security_domain_may_reach_object(&authority_aid, candidate) {
                return DeleteManagedObjectResult::RelatedObjectsExist;
            }
            if candidate.object_kind == ManagedObjectKind::SecurityDomain
                && candidate.object_aid == root_security_domain_instance_aid()
            {
                return DeleteManagedObjectResult::RelatedObjectsExist;
            }
        }
        candidate_slot += 1;
    }

    // Delete dependants before their owner. Registry slots remain stable, so
    // reverse slot order is sufficient after the complete closure is known.
    let mut candidate_slot = DEFAULT_KERNEL_OBJECT_REGISTRY_CAPACITY;
    while candidate_slot != 0 {
        candidate_slot -= 1;
        if candidate_slot != slot
            && deletion_set[candidate_slot]
            && !delete_resolved_managed_object(candidate_slot)
        {
            return DeleteManagedObjectResult::NotFound;
        }
    }
    if delete_resolved_managed_object(slot) {
        // Publish the complete closure once. A reset can therefore expose
        // either the pre-delete registry or the complete cumulative delete,
        // never one of the intermediate dependency states.
        publish_persistent_registry_after_mutation();
        DeleteManagedObjectResult::Deleted
    } else {
        DeleteManagedObjectResult::NotFound
    }
}

fn delete_resolved_managed_object(slot: usize) -> bool {
    let Some(object) = (unsafe {
        (&*core::ptr::addr_of!(OBJECT_REGISTRY))
            .resolve(slot)
            .copied()
    }) else {
        return false;
    };
    if object.object_kind == ManagedObjectKind::SecurityDomain
        && object.object_aid == root_security_domain_instance_aid()
    {
        return false;
    }
    let parent_sd_aid = object.parent_sd_aid;
    let object_kind = object.object_kind;
    let object_aid = object.object_aid;
    invalidate_runtime_references_to_registry_slot(slot);

    unsafe {
        (&mut *core::ptr::addr_of_mut!(OBJECT_REGISTRY)).delete_object(
            &parent_sd_aid,
            object_kind,
            &object_aid,
        )
    }
}

fn invalidate_runtime_references_to_registry_slot(slot: usize) {
    let selected_app_uses_slot = unsafe {
        (&*core::ptr::addr_of!(SELECTED_APP))
            .as_ref()
            .is_some_and(|app| app.registry.references_slot(slot))
    };
    if selected_app_uses_slot {
        set_selected_app(None);
    }

    let selected_security_domain_uses_slot = unsafe {
        (&*core::ptr::addr_of!(SELECTED_SECURITY_DOMAIN))
            .as_ref()
            .is_some_and(|app| app.registry.references_slot(slot))
    };
    if selected_security_domain_uses_slot {
        set_selected_security_domain(None);
    }

    let active_slot =
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ACTIVE_SECURITY_DOMAIN_SLOT)) };
    if active_slot == Some(slot) {
        let previous = active_security_domain_instance_aid();
        unsafe {
            core::ptr::write_volatile(core::ptr::addr_of_mut!(ACTIVE_SECURITY_DOMAIN_SLOT), None);
        }
        crate::security_domain::on_active_security_domain_instance_switched(
            previous,
            root_security_domain_instance_aid(),
        );
    }
}

pub fn set_visible_managed_object_status(authority_aid: Aid, p1: u8, p2: u8, aid: &Aid) -> bool {
    let Some(kind) = set_status_target_kind(p1) else {
        return false;
    };
    let Some(object) = find_object_by_kind_and_aid_raw(kind, aid) else {
        return false;
    };
    if !security_domain_may_reach_object(&authority_aid, object) {
        return false;
    }
    if object.object_kind == ManagedObjectKind::SecurityDomain
        && object.object_aid == root_security_domain_instance_aid()
    {
        // The technical root is a bootstrap anchor, not an ordinary
        // GlobalPlatform lifecycle object.
        return false;
    }

    let changed = unsafe {
        let registry = &mut *core::ptr::addr_of_mut!(OBJECT_REGISTRY);
        match kind {
            ManagedObjectKind::Package => {
                let Some(state) = package_state_from_set_status_p2(p2) else {
                    return false;
                };
                registry.set_package_state(&object.parent_sd_aid, &object.object_aid, state)
            }
            ManagedObjectKind::Instance => {
                let Some(state) = instance_state_from_set_status_p2(p2) else {
                    return false;
                };
                registry.set_instance_state(&object.parent_sd_aid, &object.object_aid, state)
            }
            ManagedObjectKind::SecurityDomain => {
                let Some(state) = security_domain_state_from_set_status_p2(p2) else {
                    return false;
                };
                registry.set_security_domain_state(&object.parent_sd_aid, &object.object_aid, state)
            }
            ManagedObjectKind::Key | ManagedObjectKind::Data => false,
        }
    };
    if changed {
        publish_persistent_registry_after_mutation();
    }
    changed
}

fn set_status_target_kind(p1: u8) -> Option<ManagedObjectKind> {
    match p1 {
        crate::security_domain::SET_STATUS_KIND_PACKAGE => Some(ManagedObjectKind::Package),
        crate::security_domain::SET_STATUS_KIND_APPLICATION => Some(ManagedObjectKind::Instance),
        crate::security_domain::SET_STATUS_KIND_SECURITY_DOMAIN => {
            Some(ManagedObjectKind::SecurityDomain)
        }
        _ => None,
    }
}

fn package_state_from_set_status_p2(p2: u8) -> Option<PackageObjectState> {
    match p2 {
        crate::security_domain::SET_STATUS_STATE_UNLOCK => Some(PackageObjectState::Loaded),
        crate::security_domain::SET_STATUS_STATE_LOCK => Some(PackageObjectState::Locked),
        _ => None,
    }
}

fn instance_state_from_set_status_p2(p2: u8) -> Option<InstanceObjectState> {
    match p2 {
        crate::security_domain::SET_STATUS_STATE_UNLOCK => Some(InstanceObjectState::Selectable),
        crate::security_domain::SET_STATUS_STATE_LOCK => Some(InstanceObjectState::Locked),
        _ => None,
    }
}

fn security_domain_state_from_set_status_p2(p2: u8) -> Option<SecurityDomainObjectState> {
    match p2 {
        crate::security_domain::SET_STATUS_STATE_UNLOCK => {
            Some(SecurityDomainObjectState::Selectable)
        }
        crate::security_domain::SET_STATUS_STATE_LOCK => Some(SecurityDomainObjectState::Locked),
        _ => None,
    }
}

/// Loads the ENC and MAC static keys required to derive one SCP03 session.
///
/// Returns `None` unless both companion key objects are present under the same
/// owner Security Domain and carry valid AES-128 raw material.
pub fn load_scp03_static_keys(
    parent_sd_aid: &Aid,
    key_version: u8,
    key_id: u8,
) -> Option<crate::core::scp03::StaticKeys> {
    load_scp03_static_keys_with_ids(parent_sd_aid, key_version, key_id, key_id).or_else(|| {
        let mac_key_id = key_id.checked_add(1)?;
        load_scp03_static_keys_with_ids(parent_sd_aid, key_version, key_id, mac_key_id)
    })
}

/// Resolves the active SCP03 ENC/MAC pair selected by an INITIALIZE UPDATE key
/// version. GP does not carry a key identifier in P2 for this command, so the
/// identifier is an internal property of the matching keyset rather than a
/// host-supplied selector.
pub fn load_scp03_static_keys_for_version(
    parent_sd_aid: &Aid,
    key_version: u8,
) -> Option<(crate::core::scp03::StaticKeys, u8)> {
    let registry = unsafe { &*core::ptr::addr_of!(OBJECT_REGISTRY) };
    for object in registry.entries() {
        if object.parent_sd_aid != *parent_sd_aid
            || object.key_state() != Some(KeyObjectState::Active)
        {
            continue;
        }
        let Some((key_type, version, key_id, usage, _)) = object.key_data() else {
            continue;
        };
        if key_type == KeyObjectType::Scp03Static
            && version == key_version
            && usage == crate::security_domain::SCP03_PUT_KEY_USAGE_ENC
        {
            if let Some(keys) = load_scp03_static_keys(parent_sd_aid, key_version, key_id) {
                return Some((keys, key_id));
            }
        }
    }
    None
}

fn load_scp03_static_keys_with_ids(
    parent_sd_aid: &Aid,
    key_version: u8,
    enc_key_id: u8,
    mac_key_id: u8,
) -> Option<crate::core::scp03::StaticKeys> {
    let enc_aid = scp03_key_object_instance_aid(
        key_version,
        enc_key_id,
        crate::security_domain::SCP03_PUT_KEY_USAGE_ENC,
    );
    let mac_aid = scp03_key_object_instance_aid(
        key_version,
        mac_key_id,
        crate::security_domain::SCP03_PUT_KEY_USAGE_MAC,
    );
    let enc_state = find_key_object_by_aid(parent_sd_aid, &enc_aid)?;
    let mac_state = find_key_object_by_aid(parent_sd_aid, &mac_aid)?;
    let enc = scp03_key_material_from_object(
        enc_state,
        key_version,
        enc_key_id,
        crate::security_domain::Scp03KeyUsage::Enc,
    )?;
    let mac = scp03_key_material_from_object(
        mac_state,
        key_version,
        mac_key_id,
        crate::security_domain::Scp03KeyUsage::Mac,
    )?;
    Some(crate::core::scp03::StaticKeys::aes128(enc, mac))
}

/// Loads one SCP03 key payload for a specific `(owner, version, id, usage)`.
///
/// This helper is used by the Rustlet Security Domain syscall path. Callers
/// must provide the owner instance AID explicitly so kernel policy decides
/// visibility before user-land touches key bytes.
pub fn load_scp03_key_material(
    parent_sd_aid: &Aid,
    key_version: u8,
    key_id: u8,
    usage: crate::security_domain::Scp03KeyUsage,
    out: &mut [u8],
) -> Option<usize> {
    if key_id == 0 {
        let (_, resolved_id) = load_scp03_static_keys_for_version(parent_sd_aid, key_version)?;
        return load_scp03_key_material(parent_sd_aid, key_version, resolved_id, usage, out);
    }
    load_scp03_key_material_with_id(parent_sd_aid, key_version, key_id, usage, out).or_else(|| {
        if usage != crate::security_domain::Scp03KeyUsage::Mac {
            return None;
        }
        let mac_key_id = key_id.checked_add(1)?;
        load_scp03_key_material_with_id(parent_sd_aid, key_version, mac_key_id, usage, out)
    })
}

fn load_scp03_key_material_with_id(
    parent_sd_aid: &Aid,
    key_version: u8,
    key_id: u8,
    usage: crate::security_domain::Scp03KeyUsage,
    out: &mut [u8],
) -> Option<usize> {
    let instance_aid = scp03_key_object_instance_aid(key_version, key_id, usage.as_byte());
    let state = find_key_object_by_aid(parent_sd_aid, &instance_aid)?;
    let material = scp03_key_material_from_object(state, key_version, key_id, usage)?;
    if out.len() < material.len() {
        return None;
    }
    out[..material.len()].copy_from_slice(&material);
    Some(material.len())
}

fn scp03_key_material_from_object(
    object: &RegistryObject,
    key_version: u8,
    key_id: u8,
    usage: crate::security_domain::Scp03KeyUsage,
) -> Option<[u8; crate::security_domain::SCP03_STATIC_KEY_LEN]> {
    if object.key_state()? != KeyObjectState::Active {
        return None;
    }
    let (key_type, stored_version, stored_id, stored_usage, raw_key) = object.key_data()?;
    if key_type != KeyObjectType::Scp03Static
        || stored_version != key_version
        || stored_id != key_id
        || stored_usage != usage.as_byte()
        || raw_key.len() != crate::security_domain::SCP03_STATIC_KEY_LEN
    {
        return None;
    }
    let mut material = [0u8; crate::security_domain::SCP03_STATIC_KEY_LEN];
    material.copy_from_slice(raw_key);
    Some(material)
}

/// Deletes one SCP03 key object from the given Security Domain keyset.
#[allow(dead_code)]
pub fn delete_scp03_key_object(
    parent_sd_aid: Aid,
    key_version: u8,
    key_id: u8,
    usage: crate::security_domain::Scp03KeyUsage,
) -> bool {
    let object_aid = scp03_key_object_instance_aid(key_version, key_id, usage.as_byte());
    let deleted = unsafe {
        (&mut *core::ptr::addr_of_mut!(OBJECT_REGISTRY)).delete_object(
            &parent_sd_aid,
            ManagedObjectKind::Key,
            &object_aid,
        )
    };
    if deleted {
        publish_persistent_registry_after_mutation();
    }
    deleted
}

fn is_security_domain_kind(kind: ManagedObjectKind) -> bool {
    matches!(kind, ManagedObjectKind::SecurityDomain)
}

pub fn active_security_domain_may_reach_instance(instance_aid: &Aid) -> bool {
    let active = active_security_domain_instance_aid();
    let Some(object) = find_any_object_by_aid_raw(instance_aid) else {
        return false;
    };
    security_domain_may_reach_object(&active, object)
}

fn security_domain_may_reach_object(authority_aid: &Aid, object: &'static RegistryObject) -> bool {
    if object.object_aid == *authority_aid {
        return true;
    }
    let mut current = object;
    let mut remaining_hops = DEFAULT_KERNEL_OBJECT_REGISTRY_CAPACITY;
    while remaining_hops != 0 {
        if current.parent_sd_aid == *authority_aid {
            return true;
        }
        if current.parent_sd_aid == top_level_parent_sd_aid() {
            return *authority_aid == root_security_domain_instance_aid();
        }
        let Some(parent) = find_any_object_by_aid_raw(&current.parent_sd_aid) else {
            return false;
        };
        if parent.object_kind != ManagedObjectKind::SecurityDomain {
            return false;
        }
        current = parent;
        remaining_hops -= 1;
    }
    // A valid registry is acyclic and cannot contain a chain longer than its
    // slot capacity. Reaching this point therefore denotes corrupt topology.
    false
}

/// Result of encoding one short-APDU page of `GET STATUS` records.
pub struct GetStatusPage {
    pub len: usize,
    pub next_slot: Option<usize>,
    pub found: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GetStatusEncodeError {
    InvalidRecord,
    OutputTooSmall,
}

/// Encodes one visible page of GP registry records in stable slot order.
///
/// `start_slot` is the continuation cursor returned by a previous page. The
/// registry itself remains the single source of truth; no object or response
/// record is copied into a pagination cache.
pub fn encode_get_status_page(
    authority_aid: &Aid,
    query: crate::gp_status::GetStatusQuery,
    start_slot: usize,
    out: &mut [u8],
) -> Result<GetStatusPage, GetStatusEncodeError> {
    let registry = unsafe { &*core::ptr::addr_of!(OBJECT_REGISTRY) };
    let root_sd_aid = crate::predeployment::root_instance_aid();
    let issuer_sd_aid = crate::predeployment::issuer_instance_aid();
    let mut slot = start_slot;
    let mut offset = 0usize;
    let mut found = false;

    while slot < DEFAULT_KERNEL_OBJECT_REGISTRY_CAPACITY {
        let Some(object) = registry.resolve(slot) else {
            slot += 1;
            continue;
        };
        if !crate::gp_status::matches_category(query, object, &root_sd_aid, issuer_sd_aid.as_ref())
            || !crate::gp_status::matches_aid(query, &object.object_aid)
            || !security_domain_may_reach_object(authority_aid, object)
        {
            slot += 1;
            continue;
        }

        let record_len = crate::gp_status::encoded_record_len(query, object, &root_sd_aid)
            .ok_or(GetStatusEncodeError::InvalidRecord)?;
        if record_len > out.len().saturating_sub(offset) {
            return if offset == 0 {
                Err(GetStatusEncodeError::OutputTooSmall)
            } else {
                Ok(GetStatusPage {
                    len: offset,
                    next_slot: Some(slot),
                    found,
                })
            };
        }
        let encoded =
            crate::gp_status::encode_record(query, object, &root_sd_aid, &mut out[offset..])
                .map_err(|_| GetStatusEncodeError::InvalidRecord)?;
        if encoded != record_len {
            return Err(GetStatusEncodeError::InvalidRecord);
        }
        offset += encoded;
        found = true;
        slot += 1;
    }

    Ok(GetStatusPage {
        len: offset,
        next_slot: None,
        found,
    })
}

fn save_selected_instance_state(
    security_domain_aid: &Aid,
    package_aid: &Aid,
    _applet_aid: &Aid,
    instance_aid: &Aid,
    install_privileges: Option<&[u8]>,
) -> apdu_manager::ApduStatus {
    let Some(selected_app) = selected_app_mut() else {
        return apdu_manager::ApduStatus::conditions_not_satisfied();
    };
    let state = selected_app.loaded_fae.shared_buffer.state_bytes();
    let inserted = unsafe {
        let registry = &mut *core::ptr::addr_of_mut!(OBJECT_REGISTRY);
        if selected_app.security_domain_vtable.is_null() {
            registry.upsert_instance_object(
                *security_domain_aid,
                *instance_aid,
                *package_aid,
                state,
            )
        } else {
            let privilege_bytes = registry
                .find_security_domain_object(security_domain_aid, instance_aid)
                .and_then(|object| object.security_domain_privilege_bytes())
                .or_else(|| {
                    install_privileges.map(|privileges| {
                        [
                            privileges.first().copied().unwrap_or(0),
                            privileges.get(1).copied().unwrap_or(0),
                            privileges.get(2).copied().unwrap_or(0),
                        ]
                    })
                })
                .unwrap_or([0, 0, 0]);
            registry.upsert_security_domain_object(
                *security_domain_aid,
                *instance_aid,
                *package_aid,
                SecurityDomainObjectBackend::RustletSecurityDomain,
                privilege_bytes,
                state,
            )
        }
    };
    if inserted {
        let object_kind = if selected_app.security_domain_vtable.is_null() {
            ManagedObjectKind::Instance
        } else {
            ManagedObjectKind::SecurityDomain
        };
        let registry = unsafe { &*core::ptr::addr_of!(OBJECT_REGISTRY) };
        let Some(instance) = registry.find_index(security_domain_aid, object_kind, instance_aid)
        else {
            selected_app.loaded_fae.shared_buffer.clear_state();
            return apdu_manager::ApduStatus::conditions_not_satisfied();
        };
        selected_app.registry = AppRegistryReference::Installed {
            package: selected_app.registry.package_index(),
            instance,
        };
        publish_persistent_registry_after_mutation();
        selected_app.loaded_fae.shared_buffer.clear_state();
        apdu_manager::ApduStatus::success()
    } else {
        selected_app.loaded_fae.shared_buffer.clear_state();
        apdu_manager::ApduStatus::conditions_not_satisfied()
    }
}

fn save_selected_security_domain_state(
    security_domain_aid: &Aid,
    package_aid: &Aid,
    _applet_aid: &Aid,
    instance_aid: &Aid,
) -> apdu_manager::ApduStatus {
    let Some(selected_security_domain) = selected_security_domain_mut() else {
        return apdu_manager::ApduStatus::conditions_not_satisfied();
    };
    let state = selected_security_domain
        .loaded_fae
        .shared_buffer
        .state_bytes();
    let inserted = unsafe {
        let registry = &mut *core::ptr::addr_of_mut!(OBJECT_REGISTRY);
        let privilege_bytes = registry
            .find_security_domain_object(security_domain_aid, instance_aid)
            .and_then(|object| object.security_domain_privilege_bytes())
            .unwrap_or([0, 0, 0]);
        registry.upsert_security_domain_object(
            *security_domain_aid,
            *instance_aid,
            *package_aid,
            SecurityDomainObjectBackend::RustletSecurityDomain,
            privilege_bytes,
            state,
        )
    };
    if inserted {
        publish_persistent_registry_after_mutation();
        selected_security_domain
            .loaded_fae
            .shared_buffer
            .clear_state();
        apdu_manager::ApduStatus::success()
    } else {
        selected_security_domain
            .loaded_fae
            .shared_buffer
            .clear_state();
        apdu_manager::ApduStatus::conditions_not_satisfied()
    }
}

fn selected_app_mut() -> Option<&'static mut LoadedApp> {
    unsafe {
        let slot = core::ptr::addr_of_mut!(SELECTED_APP);
        match &mut *slot {
            Some(app) => Some(app),
            None => {
                let sd_slot = core::ptr::addr_of_mut!(SELECTED_SECURITY_DOMAIN);
                match &mut *sd_slot {
                    Some(app) => Some(app),
                    None => None,
                }
            }
        }
    }
}

fn current_selected_app_mut() -> Option<&'static mut LoadedApp> {
    unsafe {
        let slot = core::ptr::addr_of_mut!(SELECTED_APP);
        match &mut *slot {
            Some(app) => Some(app),
            None => None,
        }
    }
}

fn selected_security_domain_mut() -> Option<&'static mut LoadedApp> {
    unsafe {
        let selected_app_slot = core::ptr::addr_of_mut!(SELECTED_APP);
        if let Some(app) = &mut *selected_app_slot {
            if !app.security_domain_vtable.is_null() {
                return Some(app);
            }
        }

        let slot = core::ptr::addr_of_mut!(SELECTED_SECURITY_DOMAIN);
        if let Some(app) = &mut *slot {
            return Some(app);
        }
        None
    }
}

fn selected_app_matches_install_target(
    security_domain_aid: &Aid,
    package_aid: &Aid,
    applet_aid: &Aid,
) -> bool {
    let Some(selected_app) = current_selected_app_mut() else {
        return false;
    };

    selected_app.registry.security_domain_aid() == Some(*security_domain_aid)
        && selected_app.registry.package_aid() == Some(*package_aid)
        && selected_app.registry.applet_aid() == Some(*applet_aid)
}

fn selected_app_vtable(selected_app: &LoadedApp) -> &'static SelectedAppVtable {
    unsafe { &*selected_app.vtable }
}

fn selected_security_domain_vtable(
    selected_security_domain: &LoadedApp,
) -> Option<&'static SelectedSecurityDomainVtable> {
    if selected_security_domain.security_domain_vtable.is_null() {
        None
    } else {
        Some(unsafe { &*selected_security_domain.security_domain_vtable })
    }
}

fn activate_registry_reference(reference: AppRegistryReference) -> apdu_manager::ApduStatus {
    if !reference.is_valid() {
        return apdu_manager::ApduStatus::file_not_found();
    }
    if let Some(selected_app) = current_selected_app_mut() {
        if selected_app.registry != reference {
            if !selected_app.security_domain_vtable.is_null() {
                promote_selected_app_to_security_domain();
            } else {
                set_selected_app(None);
            }
        }
    }

    let Some(fae) = reference.fae() else {
        return apdu_manager::ApduStatus::file_not_found();
    };
    let Some(loaded) = fae_runtime::load(fae) else {
        return apdu_manager::ApduStatus::conditions_not_satisfied();
    };
    let Some(descriptor) = fae_runtime::call_start(&loaded) else {
        fae_runtime::unload(loaded);
        return apdu_manager::ApduStatus::conditions_not_satisfied();
    };

    match install_selected_app(reference, loaded, descriptor) {
        Ok(()) => apdu_manager::ApduStatus::success(),
        Err(_) => apdu_manager::ApduStatus::conditions_not_satisfied(),
    }
}

fn drop_loaded_app(app: LoadedApp) {
    unsafe {
        oxi_core::core::dealloc(app.allocator_metadata.ptr, app.allocator_metadata.layout);
    }
    fae_runtime::unload(app.loaded_fae);
}

fn set_selected_app(app: Option<LoadedApp>) {
    unsafe {
        let previous = core::ptr::replace(core::ptr::addr_of_mut!(SELECTED_APP), app);
        if let Some(previous) = previous {
            drop_loaded_app(previous);
        }
    }
}

fn set_selected_security_domain(app: Option<LoadedApp>) {
    unsafe {
        let previous = core::ptr::replace(core::ptr::addr_of_mut!(SELECTED_SECURITY_DOMAIN), app);
        if let Some(previous) = previous {
            drop_loaded_app(previous);
        }
    }
}

pub fn promote_selected_app_to_security_domain() {
    unsafe {
        let selected = core::ptr::replace(core::ptr::addr_of_mut!(SELECTED_APP), None);
        // Invariant: reselecting an already active rustlet Security Domain may
        // dispatch through the persisted SD slot without repopulating
        // `SELECTED_APP`. In that case the promotion is already satisfied and
        // must remain a no-op.
        if selected.is_none() {
            return;
        }
        set_selected_security_domain(selected);
    }
}

fn active_app_call() -> Option<ActiveAppCall> {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ACTIVE_APP_CALL)) }
}

fn set_active_app_call(call: Option<ActiveAppCall>) {
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!(ACTIVE_APP_CALL), call);
    }
}

fn active_call_contains_readable(active_call: ActiveAppCall, addr: usize, len: usize) -> bool {
    contains_range(active_call.text_window, addr, len)
        || contains_range(active_call.shared_window, addr, len)
        || contains_range(active_call.data_window, addr, len)
        || contains_range(active_call.stack_window, addr, len)
}

fn active_call_contains_writable(active_call: ActiveAppCall, addr: usize, len: usize) -> bool {
    contains_range(active_call.shared_window, addr, len)
        || contains_range(active_call.data_window, addr, len)
        || contains_range(active_call.stack_window, addr, len)
}

#[inline(always)]
fn read_runtime_params<T: Copy>(active_call: ActiveAppCall, addr: usize) -> Option<T> {
    if !active_call_contains_readable(active_call, addr, core::mem::size_of::<T>()) {
        return None;
    }
    // Invariant: the range was validated against the active Rustlet/shared
    // memory windows, and syscall parameter structs are #[repr(C)] + Copy.
    Some(unsafe { core::ptr::read(addr as *const T) })
}

#[inline(always)]
fn runtime_read_slice<'a>(
    active_call: ActiveAppCall,
    ptr: *const u8,
    len: usize,
) -> Option<&'a [u8]> {
    if !active_call_contains_readable(active_call, ptr as usize, len) {
        return None;
    }
    // Invariant: the byte range was validated against readable Rustlet/shared
    // memory and the returned borrow is used only during this syscall.
    Some(unsafe { core::slice::from_raw_parts(ptr, len) })
}

#[inline(always)]
fn runtime_write_slice<'a>(
    active_call: ActiveAppCall,
    ptr: *mut u8,
    len: usize,
) -> Option<&'a mut [u8]> {
    if !active_call_contains_writable(active_call, ptr as usize, len) {
        return None;
    }
    // Invariant: the byte range was validated against writable Rustlet/shared
    // memory and the returned borrow is used only during this syscall.
    Some(unsafe { core::slice::from_raw_parts_mut(ptr, len) })
}

fn contains_range(
    window: oxi_core::core::isolation::AppMemoryWindow,
    addr: usize,
    len: usize,
) -> bool {
    if len == 0 {
        return true;
    }
    let Some(end) = addr.checked_add(len) else {
        return false;
    };

    addr >= window.start && end <= window.end()
}

fn crypto_error_word(error: CryptoErrorCode) -> usize {
    rustlet_runtime::syscall_abi::CRYPTO_RESULT_ERROR_FLAG | error.word()
}

fn from_abi_status(status: rustlet_runtime::ApduStatus) -> apdu_manager::ApduStatus {
    apdu_manager::ApduStatus {
        sw1: status.sw1,
        sw2: status.sw2,
    }
}

fn app_exit_observer(event: oxi_core::core::isolation::AppExitEvent) {
    let active_call = active_app_call();
    if let Some(active_call) = active_call {
        complete_abrupt_app_call(active_call);
        clear_abrupt_app_shared_page(active_call);
    }
    let _ = event;
}

fn complete_abrupt_app_call(active_call: ActiveAppCall) {
    let Some(transport) = active_call_transport(active_call) else {
        return;
    };

    transport.abort_remaining_io();
}

fn clear_abrupt_app_shared_page(active_call: ActiveAppCall) {
    fae_runtime::SharedRustletCtx::new(active_call.shared_buffer).clear();
}

fn active_call_transport(
    active_call: ActiveAppCall,
) -> Option<&'static mut apdu_manager::TransportApdu> {
    if active_call.transport.is_null() {
        return None;
    }
    Some(unsafe { &mut *active_call.transport })
}

fn active_call_shared_buffer(active_call: ActiveAppCall) -> &'static mut RustletCtx {
    unsafe { &mut *active_call.shared_buffer }
}

fn running_se_apdu(active_call: ActiveAppCall) -> Option<RunningSEApdu<'static>> {
    Some(RunningSEApdu {
        transport: active_call_transport(active_call)?,
        shared_buffer: active_call_shared_buffer(active_call),
    })
}

impl SEApdu for RunningSEApdu<'_> {
    fn header(&self) -> SEApduHeader {
        SEApduHeader {
            cla: self.transport.cla(),
            ins: self.transport.ins(),
            p1: self.transport.p1(),
            p2: self.transport.p2(),
            p3: self.transport.ln(),
        }
    }

    fn buffer_mut(&mut self) -> &mut [u8] {
        &mut self.shared_buffer.data
    }

    fn incoming_data(&self) -> &[u8] {
        self.shared_buffer.incoming_data()
    }

    fn set_incoming_and_receive(&mut self) -> usize {
        let Some(incoming_len) = self
            .transport
            .receive_incoming_into_for_runtime(&mut self.shared_buffer.data)
        else {
            return 0;
        };
        if !self.shared_buffer.stage_incoming_len(incoming_len) {
            return 0;
        }
        incoming_len
    }

    fn set_outgoing(&mut self) -> usize {
        let requested = self.transport.begin_outgoing_for_runtime();
        self.shared_buffer.set_outgoing();
        requested
    }

    fn set_outgoing_length(&mut self, len: usize) {
        if !self.transport.outgoing_started() {
            let _ = self.transport.begin_outgoing_for_runtime();
        }
        self.transport.set_outgoing_length_for_runtime(len);
        self.shared_buffer.set_outgoing_length(len);
    }
}

unsafe extern "C" fn apdu_set_incoming_and_receive_syscall(
    _arg0: usize,
    _arg1: usize,
    _arg2: usize,
    _arg3: usize,
) -> usize {
    let Some(active_call) = active_app_call() else {
        return 0;
    };

    let Some(mut apdu) = running_se_apdu(active_call) else {
        return 0;
    };
    apdu.set_incoming_and_receive()
}

unsafe extern "C" fn apdu_set_outgoing_syscall(
    _arg0: usize,
    _arg1: usize,
    _arg2: usize,
    _arg3: usize,
) -> usize {
    let Some(active_call) = active_app_call() else {
        return 0;
    };

    let Some(mut apdu) = running_se_apdu(active_call) else {
        return 0;
    };
    let _ = apdu.set_outgoing();
    0
}

unsafe extern "C" fn apdu_set_outgoing_length_syscall(
    arg0: usize,
    _arg1: usize,
    _arg2: usize,
    _arg3: usize,
) -> usize {
    let Some(active_call) = active_app_call() else {
        return 0;
    };

    let Some(mut apdu) = running_se_apdu(active_call) else {
        return 0;
    };
    apdu.set_outgoing_length(arg0);
    0
}

unsafe extern "C" fn crypto_cipher_do_final_syscall(
    arg0: usize,
    _arg1: usize,
    _arg2: usize,
    _arg3: usize,
) -> usize {
    let Some(active_call) = active_app_call() else {
        return crypto_error_word(CryptoErrorCode::PermissionDenied);
    };
    // All pointers must remain inside APDU/shared memory or Rustlet RAM.
    let Some(params) = read_runtime_params::<CryptoCipherDoFinalParams>(active_call, arg0) else {
        return crypto_error_word(CryptoErrorCode::PermissionDenied);
    };
    let Some(mode) = decode_cipher_mode(params.mode) else {
        return crypto_error_word(CryptoErrorCode::Unsupported);
    };
    let Some(algorithm) = decode_cipher_algorithm(params.algorithm) else {
        return crypto_error_word(CryptoErrorCode::Unsupported);
    };
    if params.iv_len != oxi_core::core::crypto::AES_BLOCK_SIZE {
        return crypto_error_word(CryptoErrorCode::InvalidBufferLength);
    }
    if !key_len_matches_algorithm(params.key_len, algorithm) {
        return crypto_error_word(CryptoErrorCode::InvalidKeyLength);
    }
    let Some(key_slice) = runtime_read_slice(active_call, params.key_ptr, params.key_len) else {
        return crypto_error_word(CryptoErrorCode::PermissionDenied);
    };
    let Some(iv_slice) = runtime_read_slice(active_call, params.iv_ptr, params.iv_len) else {
        return crypto_error_word(CryptoErrorCode::PermissionDenied);
    };
    let Some(input) = runtime_read_slice(active_call, params.input_ptr, params.input_len) else {
        return crypto_error_word(CryptoErrorCode::PermissionDenied);
    };
    let Some(output) = runtime_write_slice(active_call, params.output_ptr, params.output_capacity)
    else {
        return crypto_error_word(CryptoErrorCode::PermissionDenied);
    };
    let mut iv = [0u8; oxi_core::core::crypto::AES_BLOCK_SIZE];
    iv.copy_from_slice(iv_slice);
    let key = match oxi_core::core::crypto::AesKey::from_bytes(key_slice) {
        Ok(key) => key,
        Err(error) => {
            return crypto_error_word(map_core_crypto_error(error));
        }
    };

    let result = match (mode, algorithm) {
        (CipherMode::Encrypt, CipherAlgorithm::Aes128CbcNoPadding)
        | (CipherMode::Encrypt, CipherAlgorithm::Aes256CbcNoPadding) => {
            if input.len() % oxi_core::core::crypto::AES_BLOCK_SIZE != 0 {
                return crypto_error_word(CryptoErrorCode::InvalidBufferLength);
            }
            if output.len() < input.len() {
                Err(oxi_core::core::crypto::CryptoError::InvalidOutputLength)
            } else {
                output[..input.len()].copy_from_slice(input);
                oxi_core::core::crypto::aes_cbc_encrypt_in_place(
                    &key,
                    &iv,
                    &mut output[..input.len()],
                )
                .map(|_| input.len())
            }
        }
        (CipherMode::Decrypt, CipherAlgorithm::Aes128CbcNoPadding)
        | (CipherMode::Decrypt, CipherAlgorithm::Aes256CbcNoPadding) => {
            if input.len() % oxi_core::core::crypto::AES_BLOCK_SIZE != 0 {
                return crypto_error_word(CryptoErrorCode::InvalidBufferLength);
            }
            if output.len() < input.len() {
                Err(oxi_core::core::crypto::CryptoError::InvalidOutputLength)
            } else {
                output[..input.len()].copy_from_slice(input);
                oxi_core::core::crypto::aes_cbc_decrypt_in_place(
                    &key,
                    &iv,
                    &mut output[..input.len()],
                )
                .map(|_| input.len())
            }
        }
        (CipherMode::Encrypt, CipherAlgorithm::Aes128CbcIso9797M2)
        | (CipherMode::Encrypt, CipherAlgorithm::Aes256CbcIso9797M2) => {
            oxi_core::core::crypto::aes_cbc_encrypt_iso9797_m2(&key, &iv, input, output)
        }
        (CipherMode::Decrypt, CipherAlgorithm::Aes128CbcIso9797M2)
        | (CipherMode::Decrypt, CipherAlgorithm::Aes256CbcIso9797M2) => {
            if input.len() % oxi_core::core::crypto::AES_BLOCK_SIZE != 0 {
                return crypto_error_word(CryptoErrorCode::InvalidBufferLength);
            }
            oxi_core::core::crypto::aes_cbc_decrypt_iso9797_m2(&key, &iv, input, output)
        }
        (CipherMode::Encrypt, CipherAlgorithm::Aes128EcbNoPadding)
        | (CipherMode::Encrypt, CipherAlgorithm::Aes256EcbNoPadding) => {
            if input.len() % oxi_core::core::crypto::AES_BLOCK_SIZE != 0 {
                return crypto_error_word(CryptoErrorCode::InvalidBufferLength);
            }
            if output.len() < input.len() {
                Err(oxi_core::core::crypto::CryptoError::InvalidOutputLength)
            } else {
                output[..input.len()].copy_from_slice(input);
                oxi_core::core::crypto::aes_ecb_encrypt_in_place(&key, &mut output[..input.len()])
                    .map(|_| input.len())
            }
        }
        (CipherMode::Decrypt, CipherAlgorithm::Aes128EcbNoPadding)
        | (CipherMode::Decrypt, CipherAlgorithm::Aes256EcbNoPadding) => {
            if input.len() % oxi_core::core::crypto::AES_BLOCK_SIZE != 0 {
                return crypto_error_word(CryptoErrorCode::InvalidBufferLength);
            }
            if output.len() < input.len() {
                Err(oxi_core::core::crypto::CryptoError::InvalidOutputLength)
            } else {
                output[..input.len()].copy_from_slice(input);
                oxi_core::core::crypto::aes_ecb_decrypt_in_place(&key, &mut output[..input.len()])
                    .map(|_| input.len())
            }
        }
    };
    match result {
        Ok(len) => len,
        Err(error) => crypto_error_word(map_core_crypto_error(error)),
    }
}

unsafe extern "C" fn crypto_random_generate_syscall(
    arg0: usize,
    _arg1: usize,
    _arg2: usize,
    _arg3: usize,
) -> usize {
    let Some(active_call) = active_app_call() else {
        return crypto_error_word(CryptoErrorCode::PermissionDenied);
    };
    let Some(params) = read_runtime_params::<CryptoRandomGenerateParams>(active_call, arg0) else {
        return crypto_error_word(CryptoErrorCode::PermissionDenied);
    };
    if decode_random_algorithm(params.algorithm).is_none() {
        return crypto_error_word(CryptoErrorCode::Unsupported);
    }
    let Some(output) = runtime_write_slice(active_call, params.output_ptr, params.output_len)
    else {
        return crypto_error_word(CryptoErrorCode::PermissionDenied);
    };

    match oxi_core::core::crypto::fill_random(output) {
        Ok(()) => 0,
        Err(error) => crypto_error_word(map_core_crypto_error(error)),
    }
}

unsafe extern "C" fn crypto_mac_do_final_syscall(
    arg0: usize,
    _arg1: usize,
    _arg2: usize,
    _arg3: usize,
) -> usize {
    let Some(active_call) = active_app_call() else {
        return crypto_error_word(CryptoErrorCode::PermissionDenied);
    };
    let Some(params) = read_runtime_params::<CryptoMacDoFinalParams>(active_call, arg0) else {
        return crypto_error_word(CryptoErrorCode::PermissionDenied);
    };

    // Application MAC is independent from the future SCP03 secure-channel MAC.
    let Some(algorithm) = decode_mac_algorithm(params.algorithm) else {
        return crypto_error_word(CryptoErrorCode::Unsupported);
    };
    let Ok(operation) = decode_mac_operation(params.operation) else {
        return crypto_error_word(CryptoErrorCode::Unsupported);
    };
    if !mac_key_len_matches_algorithm(params.key_len, algorithm) {
        return crypto_error_word(CryptoErrorCode::InvalidKeyLength);
    }
    let Some(key_slice) = runtime_read_slice(active_call, params.key_ptr, params.key_len) else {
        return crypto_error_word(CryptoErrorCode::PermissionDenied);
    };
    let Some(input) = runtime_read_slice(active_call, params.input_ptr, params.input_len) else {
        return crypto_error_word(CryptoErrorCode::PermissionDenied);
    };

    let key = match oxi_core::core::crypto::AesKey::from_bytes(key_slice) {
        Ok(key) => key,
        Err(error) => return crypto_error_word(map_core_crypto_error(error)),
    };

    let mut tag = [0u8; oxi_core::core::crypto::AES_CMAC_SIZE];
    if let Err(error) = match algorithm {
        MacAlgorithm::AesCmac => oxi_core::core::crypto::aes_cmac(&key, input, &mut tag),
    } {
        return crypto_error_word(map_core_crypto_error(error));
    }

    match operation {
        CryptoMacOperation::Compute => {
            if params.output_capacity < tag.len() {
                return crypto_error_word(CryptoErrorCode::PermissionDenied);
            }
            let Some(output) =
                runtime_write_slice(active_call, params.output_ptr, params.output_capacity)
            else {
                return crypto_error_word(CryptoErrorCode::PermissionDenied);
            };
            output[..tag.len()].copy_from_slice(&tag);
            tag.len()
        }
        CryptoMacOperation::Verify => {
            if params.expected_tag_len != tag.len() {
                return crypto_error_word(CryptoErrorCode::InvalidBufferLength);
            }
            let Some(expected) = runtime_read_slice(
                active_call,
                params.expected_tag_ptr,
                params.expected_tag_len,
            ) else {
                return crypto_error_word(CryptoErrorCode::InvalidBufferLength);
            };
            if constant_time_eq(&tag, expected) {
                1
            } else {
                0
            }
        }
    }
}

unsafe extern "C" fn security_domain_load_scp03_key_syscall(
    arg0: usize,
    _arg1: usize,
    _arg2: usize,
    _arg3: usize,
) -> usize {
    let Some(active_call) = active_app_call() else {
        return crypto_error_word(CryptoErrorCode::PermissionDenied);
    };
    let Some(params) = read_runtime_params::<Scp03LoadKeyParams>(active_call, arg0) else {
        return crypto_error_word(CryptoErrorCode::PermissionDenied);
    };
    let Some(selected_security_domain) = selected_security_domain_mut() else {
        return crypto_error_word(CryptoErrorCode::PermissionDenied);
    };
    // Invariant: the selected security-domain rustlet owns the key lookup
    // context for this syscall. The caller already arrived through the kernel
    // SDDISPATCH path, so tying key visibility to the selected SD instance is
    // sufficient and avoids spurious mismatches with the global "active SD"
    // cursor during clear establishment flows.

    let Some(output) = runtime_write_slice(active_call, params.output_ptr, params.output_capacity)
    else {
        return crypto_error_word(CryptoErrorCode::PermissionDenied);
    };
    let Some(usage) = crate::security_domain::Scp03KeyUsage::from_byte(params.usage) else {
        return crypto_error_word(CryptoErrorCode::Unsupported);
    };
    let Some(instance_aid) = selected_security_domain.registry.instance_aid() else {
        return crypto_error_word(CryptoErrorCode::PermissionDenied);
    };
    match load_scp03_key_material(
        &instance_aid,
        params.key_version,
        params.key_id,
        usage,
        output,
    ) {
        Some(len) => len,
        None => crypto_error_word(CryptoErrorCode::NotFound),
    }
}

unsafe extern "C" fn crypto_ec_generate_keypair_syscall(
    arg0: usize,
    _arg1: usize,
    _arg2: usize,
    _arg3: usize,
) -> usize {
    let Some(active_call) = active_app_call() else {
        return crypto_error_word(CryptoErrorCode::PermissionDenied);
    };
    let Some(params) = read_runtime_params::<CryptoEcGenerateKeypairParams>(active_call, arg0)
    else {
        return crypto_error_word(CryptoErrorCode::PermissionDenied);
    };

    let Some(curve) = decode_ec_curve(params.curve) else {
        return crypto_error_word(CryptoErrorCode::Unsupported);
    };
    if params.private_key_capacity != oxi_core::core::crypto::P256_PRIVATE_KEY_SIZE
        || params.public_key_capacity != oxi_core::core::crypto::P256_PUBLIC_KEY_UNCOMPRESSED_SIZE
    {
        return crypto_error_word(CryptoErrorCode::InvalidOutputLength);
    }
    let Some(private_key) = runtime_write_slice(
        active_call,
        params.private_key_ptr,
        params.private_key_capacity,
    ) else {
        return crypto_error_word(CryptoErrorCode::PermissionDenied);
    };
    let Some(public_key) = runtime_write_slice(
        active_call,
        params.public_key_ptr,
        params.public_key_capacity,
    ) else {
        return crypto_error_word(CryptoErrorCode::PermissionDenied);
    };

    let result = match curve {
        oxi_core::core::crypto::EcCurve::P256 => {
            oxi_core::core::crypto::p256_generate_keypair(private_key, public_key)
        }
    };
    match result {
        Ok(()) => 0,
        Err(error) => crypto_error_word(map_core_crypto_error(error)),
    }
}

unsafe extern "C" fn crypto_ecdh_do_final_syscall(
    arg0: usize,
    _arg1: usize,
    _arg2: usize,
    _arg3: usize,
) -> usize {
    let Some(active_call) = active_app_call() else {
        return crypto_error_word(CryptoErrorCode::PermissionDenied);
    };
    let Some(params) = read_runtime_params::<CryptoEcdhDoFinalParams>(active_call, arg0) else {
        return crypto_error_word(CryptoErrorCode::PermissionDenied);
    };

    let Some(curve) = decode_ec_curve(params.curve) else {
        return crypto_error_word(CryptoErrorCode::Unsupported);
    };
    if params.private_key_len != oxi_core::core::crypto::P256_PRIVATE_KEY_SIZE {
        return crypto_error_word(CryptoErrorCode::InvalidKeyLength);
    }
    if params.output_capacity != oxi_core::core::crypto::P256_SHARED_SECRET_SIZE {
        return crypto_error_word(CryptoErrorCode::InvalidOutputLength);
    }
    let Some(private_key) =
        runtime_read_slice(active_call, params.private_key_ptr, params.private_key_len)
    else {
        return crypto_error_word(CryptoErrorCode::PermissionDenied);
    };
    let Some(peer_public_key) = runtime_read_slice(
        active_call,
        params.peer_public_key_ptr,
        params.peer_public_key_len,
    ) else {
        return crypto_error_word(CryptoErrorCode::PermissionDenied);
    };
    let Some(output) = runtime_write_slice(active_call, params.output_ptr, params.output_capacity)
    else {
        return crypto_error_word(CryptoErrorCode::PermissionDenied);
    };

    let result = match curve {
        oxi_core::core::crypto::EcCurve::P256 => {
            oxi_core::core::crypto::p256_ecdh(private_key, peer_public_key, output)
                .map(|_| oxi_core::core::crypto::P256_SHARED_SECRET_SIZE)
        }
    };
    match result {
        Ok(len) => len,
        Err(error) => crypto_error_word(map_core_crypto_error(error)),
    }
}

unsafe extern "C" fn crypto_hkdf_sha256_syscall(
    arg0: usize,
    _arg1: usize,
    _arg2: usize,
    _arg3: usize,
) -> usize {
    let Some(active_call) = active_app_call() else {
        return crypto_error_word(CryptoErrorCode::PermissionDenied);
    };
    let Some(params) = read_runtime_params::<CryptoHkdfSha256Params>(active_call, arg0) else {
        return crypto_error_word(CryptoErrorCode::PermissionDenied);
    };

    if params.output_capacity == 0 {
        return crypto_error_word(CryptoErrorCode::InvalidOutputLength);
    }
    let Some(ikm) = runtime_read_slice(active_call, params.ikm_ptr, params.ikm_len) else {
        return crypto_error_word(CryptoErrorCode::PermissionDenied);
    };
    let Some(salt) = runtime_read_slice(active_call, params.salt_ptr, params.salt_len) else {
        return crypto_error_word(CryptoErrorCode::PermissionDenied);
    };
    let Some(info) = runtime_read_slice(active_call, params.info_ptr, params.info_len) else {
        return crypto_error_word(CryptoErrorCode::PermissionDenied);
    };
    let Some(output) = runtime_write_slice(active_call, params.output_ptr, params.output_capacity)
    else {
        return crypto_error_word(CryptoErrorCode::PermissionDenied);
    };

    match oxi_core::core::crypto::hkdf_sha256(ikm, salt, info, output) {
        Ok(()) => output.len(),
        Err(error) => crypto_error_word(map_core_crypto_error(error)),
    }
}

unsafe extern "C" fn crypto_x963_sha256_syscall(
    arg0: usize,
    _arg1: usize,
    _arg2: usize,
    _arg3: usize,
) -> usize {
    let Some(active_call) = active_app_call() else {
        return crypto_error_word(CryptoErrorCode::PermissionDenied);
    };
    let Some(params) = read_runtime_params::<CryptoX963Sha256Params>(active_call, arg0) else {
        return crypto_error_word(CryptoErrorCode::PermissionDenied);
    };

    if params.output_capacity == 0 {
        return crypto_error_word(CryptoErrorCode::InvalidOutputLength);
    }
    let Some(shared_secret) = runtime_read_slice(
        active_call,
        params.shared_secret_ptr,
        params.shared_secret_len,
    ) else {
        return crypto_error_word(CryptoErrorCode::PermissionDenied);
    };
    let Some(shared_info) =
        runtime_read_slice(active_call, params.shared_info_ptr, params.shared_info_len)
    else {
        return crypto_error_word(CryptoErrorCode::PermissionDenied);
    };
    let Some(output) = runtime_write_slice(active_call, params.output_ptr, params.output_capacity)
    else {
        return crypto_error_word(CryptoErrorCode::PermissionDenied);
    };

    match oxi_core::core::crypto::x963_sha256_kdf(shared_secret, shared_info, output) {
        Ok(()) => output.len(),
        Err(error) => crypto_error_word(map_core_crypto_error(error)),
    }
}

fn decode_cipher_mode(mode: u8) -> Option<CipherMode> {
    match mode {
        1 => Some(CipherMode::Encrypt),
        2 => Some(CipherMode::Decrypt),
        _ => None,
    }
}

fn decode_cipher_algorithm(algorithm: u8) -> Option<CipherAlgorithm> {
    match algorithm {
        1 => Some(CipherAlgorithm::Aes128CbcNoPadding),
        2 => Some(CipherAlgorithm::Aes256CbcNoPadding),
        3 => Some(CipherAlgorithm::Aes128CbcIso9797M2),
        4 => Some(CipherAlgorithm::Aes256CbcIso9797M2),
        5 => Some(CipherAlgorithm::Aes128EcbNoPadding),
        6 => Some(CipherAlgorithm::Aes256EcbNoPadding),
        _ => None,
    }
}

fn key_len_matches_algorithm(len: usize, algorithm: CipherAlgorithm) -> bool {
    match algorithm {
        CipherAlgorithm::Aes128CbcNoPadding | CipherAlgorithm::Aes128CbcIso9797M2 => {
            len == oxi_core::core::crypto::AES128_KEY_SIZE
        }
        CipherAlgorithm::Aes256CbcNoPadding | CipherAlgorithm::Aes256CbcIso9797M2 => {
            len == oxi_core::core::crypto::AES256_KEY_SIZE
        }
        CipherAlgorithm::Aes128EcbNoPadding => len == oxi_core::core::crypto::AES128_KEY_SIZE,
        CipherAlgorithm::Aes256EcbNoPadding => len == oxi_core::core::crypto::AES256_KEY_SIZE,
    }
}

fn decode_random_algorithm(algorithm: u8) -> Option<RandomAlgorithm> {
    match algorithm {
        1 => Some(RandomAlgorithm::SecureRandom),
        _ => None,
    }
}

fn decode_mac_algorithm(algorithm: u8) -> Option<MacAlgorithm> {
    match algorithm {
        1 => Some(MacAlgorithm::AesCmac),
        _ => None,
    }
}

fn decode_mac_operation(operation: u8) -> Result<CryptoMacOperation, ()> {
    match operation {
        value if value == CryptoMacOperation::Compute as u8 => Ok(CryptoMacOperation::Compute),
        value if value == CryptoMacOperation::Verify as u8 => Ok(CryptoMacOperation::Verify),
        _ => Err(()),
    }
}

fn decode_ec_curve(curve: u8) -> Option<oxi_core::core::crypto::EcCurve> {
    match curve {
        value if value == CryptoEcCurve::P256 as u8 => Some(oxi_core::core::crypto::EcCurve::P256),
        _ => None,
    }
}

fn mac_key_len_matches_algorithm(len: usize, algorithm: MacAlgorithm) -> bool {
    match algorithm {
        MacAlgorithm::AesCmac => {
            len == oxi_core::core::crypto::AES128_KEY_SIZE
                || len == oxi_core::core::crypto::AES256_KEY_SIZE
        }
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0u8;
    for index in 0..left.len() {
        diff |= left[index] ^ right[index];
    }
    diff == 0
}

fn map_core_crypto_error(error: oxi_core::core::crypto::CryptoError) -> CryptoErrorCode {
    match error {
        oxi_core::core::crypto::CryptoError::InvalidKeyLength => CryptoErrorCode::InvalidKeyLength,
        oxi_core::core::crypto::CryptoError::InvalidBufferLength => {
            CryptoErrorCode::InvalidBufferLength
        }
        oxi_core::core::crypto::CryptoError::InvalidOutputLength => {
            CryptoErrorCode::InvalidOutputLength
        }
        oxi_core::core::crypto::CryptoError::Unsupported => CryptoErrorCode::Unsupported,
        oxi_core::core::crypto::CryptoError::EntropyUnavailable => CryptoErrorCode::Unsupported,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security_domain::{Scp03KeyUsage, SCP03_STATIC_KEY_LEN};
    use std::sync::{Mutex, MutexGuard};

    const OWNER_A: Aid = Aid::from_array([0xA0, 0x00, 0x00, 0x47, 0x50, 0x4F, 0x53, 0x41]);
    const OWNER_B: Aid = Aid::from_array([0xA0, 0x00, 0x00, 0x47, 0x50, 0x4F, 0x53, 0x42]);
    static REGISTRY_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn reset_registry_test_state() -> MutexGuard<'static, ()> {
        let guard = REGISTRY_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Invariant: host tests must start from an empty object registry so key
        // ownership and lookup are validated without predeployment noise.
        unsafe {
            (&mut *core::ptr::addr_of_mut!(OBJECT_REGISTRY)).clear();
        }
        unsafe {
            core::ptr::write_volatile(core::ptr::addr_of_mut!(ACTIVE_SECURITY_DOMAIN_SLOT), None);
        }
        clear_dynamic_load_context();
        guard
    }

    fn sample_key(fill: u8) -> [u8; SCP03_STATIC_KEY_LEN] {
        [fill; SCP03_STATIC_KEY_LEN]
    }

    #[test]
    fn scp11_keys_round_trip_by_owner_version_id_and_role() {
        let _registry_guard = reset_registry_test_state();
        let mut private = [0u8; 32];
        private[31] = 1;
        let mut public = [0u8; 65];
        oxi_core::core::crypto::p256_public_from_private(&private, &mut public).unwrap();

        assert!(upsert_scp11_key_object(
            OWNER_A,
            2,
            4,
            crate::security_domain::SCP11_PUT_KEY_USAGE_SD_ECKA,
            &private,
        ));
        assert!(upsert_scp11_key_object(
            OWNER_A,
            2,
            5,
            crate::security_domain::SCP11_PUT_KEY_USAGE_CA_KLOC,
            &public,
        ));

        let mut loaded_private = [0u8; 32];
        assert_eq!(
            load_scp11_key_material(
                &OWNER_A,
                2,
                4,
                crate::security_domain::SCP11_PUT_KEY_USAGE_SD_ECKA,
                &mut loaded_private,
            ),
            Some(32)
        );
        assert_eq!(loaded_private, private);
        assert!(load_scp11_key_material(
            &OWNER_B,
            2,
            4,
            crate::security_domain::SCP11_PUT_KEY_USAGE_SD_ECKA,
            &mut loaded_private,
        )
        .is_none());
    }

    #[test]
    fn runtime_registry_references_remain_word_sized() {
        assert!(core::mem::size_of::<AppRegistryReference>() <= 3 * core::mem::size_of::<usize>());
    }

    #[test]
    fn get_status_pages_visible_gp_objects_without_exposing_keys() {
        let _registry_guard = reset_registry_test_state();
        let root_aid = crate::predeployment::root_instance_aid();
        let root_parent = top_level_parent_sd_aid();
        let package_a = Aid::from_array([0xf0, 0x0d, 0x10]);
        let package_b = Aid::from_array([0xf0, 0x0d, 0x11]);
        unsafe {
            let registry = &mut *core::ptr::addr_of_mut!(OBJECT_REGISTRY);
            assert!(registry.upsert_security_domain_object(
                root_parent,
                root_aid,
                root_aid,
                SecurityDomainObjectBackend::NullSecurityDomain,
                [0xff; 3],
                &[],
            ));
            assert!(registry.insert_package_object(root_aid, package_a, package_a, &[0xca],));
            assert!(registry.insert_package_object(root_aid, package_b, package_b, &[0xfe],));
            assert!(registry.upsert_key_object(
                root_aid,
                Aid::from_array([0x4b, 0x45, 0x59]),
                KeyObjectType::Scp03Static,
                KeyObjectState::Active,
                1,
                3,
                1,
                &[0xaa; SCP03_STATIC_KEY_LEN],
            ));
        }

        let query = crate::gp_status::GetStatusQuery {
            category: crate::gp_status::GetStatusCategory::ExecutableLoadFiles,
            next_occurrence: false,
            aid_filter: Aid::from_array([0xf0, 0x0d]),
        };
        let first_record_len = unsafe {
            let registry = &*core::ptr::addr_of!(OBJECT_REGISTRY);
            let object = registry
                .find_package_object(&root_aid, &package_a)
                .expect("package A");
            crate::gp_status::encoded_record_len(query, object, &root_aid).expect("record length")
        };
        let mut first = [0u8; 64];
        let first_page =
            encode_get_status_page(&root_aid, query, 0, &mut first[..first_record_len])
                .expect("first page");
        assert!(first_page.found);
        assert_eq!(first_page.len, first_record_len);
        let next_slot = first_page.next_slot.expect("second page cursor");

        let mut second = [0u8; 64];
        let second_page =
            encode_get_status_page(&root_aid, query, next_slot, &mut second).expect("second page");
        assert!(second_page.found);
        assert!(second_page.next_slot.is_none());

        let first_stream = &first[..first_page.len];
        let second_stream = &second[..second_page.len];
        assert!(first_stream
            .windows(package_a.len as usize)
            .any(|value| value == package_a.as_slice()));
        assert!(second_stream
            .windows(package_b.len as usize)
            .any(|value| value == package_b.as_slice()));
        assert!(!first_stream
            .windows(3)
            .any(|value| value == [0x4b, 0x45, 0x59]));
        assert!(!second_stream
            .windows(3)
            .any(|value| value == [0x4b, 0x45, 0x59]));
    }

    fn seed_dynamic_load_context(authority_aid: Aid, protected: bool) {
        unsafe {
            *core::ptr::addr_of_mut!(DYNAMIC_LOAD_CONTEXT) = Some(DynamicLoadContext {
                authority_aid,
                target_sd_aid: authority_aid,
                package_aid: Aid::from_array([0xF0, 0x0D]),
                protected,
                expected_hash: [0; 32],
                expected_size: 16,
                reserved_offset: 4096,
                block_total_len: 4096,
                bytes_received: 0,
                next_block_number: 0,
                current_page_index: 0,
                current_page_dirty: false,
            });
        }
    }

    #[test]
    fn dynamic_load_cancel_drops_only_volatile_context() {
        let _registry_guard = reset_registry_test_state();
        seed_dynamic_load_context(OWNER_A, true);
        assert!(dynamic_package_load_in_progress());
        cancel_dynamic_package_load();
        assert!(!dynamic_package_load_in_progress());
    }

    #[test]
    fn dynamic_load_rejects_mismatched_authority_before_flash_access() {
        let _registry_guard = reset_registry_test_state();
        seed_dynamic_load_context(OWNER_A, true);

        let status = append_dynamic_package_load_block(OWNER_B, true, 0, false, &[0xAA]);

        assert_eq!(status, apdu_manager::ApduStatus::conditions_not_satisfied());
        assert!(!dynamic_package_load_in_progress());
    }

    #[test]
    fn scp03_key_material_round_trips_for_matching_owner() {
        let _registry_guard = reset_registry_test_state();
        let enc = sample_key(0x11);
        assert!(upsert_scp03_key_object(
            OWNER_A,
            0x01,
            0x03,
            Scp03KeyUsage::Enc,
            &enc,
        ));

        let mut out = [0u8; SCP03_STATIC_KEY_LEN];
        let len = load_scp03_key_material(&OWNER_A, 0x01, 0x03, Scp03KeyUsage::Enc, &mut out)
            .expect("ENC key should be present under matching owner");
        assert_eq!(len, SCP03_STATIC_KEY_LEN);
        assert_eq!(out, enc);
    }

    #[test]
    fn scp03_key_material_is_isolated_per_owner() {
        let _registry_guard = reset_registry_test_state();
        assert!(upsert_scp03_key_object(
            OWNER_A,
            0x01,
            0x03,
            Scp03KeyUsage::Enc,
            &sample_key(0x22),
        ));

        let mut out = [0u8; SCP03_STATIC_KEY_LEN];
        assert!(
            load_scp03_key_material(&OWNER_B, 0x01, 0x03, Scp03KeyUsage::Enc, &mut out).is_none()
        );
    }

    #[test]
    fn scp03_static_keys_require_both_enc_and_mac_under_same_owner() {
        let _registry_guard = reset_registry_test_state();
        assert!(upsert_scp03_key_object(
            OWNER_A,
            0x01,
            0x03,
            Scp03KeyUsage::Enc,
            &sample_key(0x33),
        ));
        assert!(load_scp03_static_keys(&OWNER_A, 0x01, 0x03).is_none());

        assert!(upsert_scp03_key_object(
            OWNER_A,
            0x01,
            0x03,
            Scp03KeyUsage::Mac,
            &sample_key(0x44),
        ));
        assert!(load_scp03_static_keys(&OWNER_A, 0x01, 0x03).is_some());
    }

    #[test]
    fn scp03_static_keys_accept_gp_multi_entry_consecutive_ids() {
        let _registry_guard = reset_registry_test_state();
        assert!(upsert_scp03_key_object(
            OWNER_A,
            0x01,
            0x03,
            Scp03KeyUsage::Enc,
            &sample_key(0x35),
        ));
        assert!(upsert_scp03_key_object(
            OWNER_A,
            0x01,
            0x04,
            Scp03KeyUsage::Mac,
            &sample_key(0x46),
        ));

        // Invariant: GP multi-entry PUT KEY advances the key identifier for
        // each entry. INITIALIZE UPDATE carries only the version, so the card
        // resolves the first valid ENC/MAC pair for that version internally.
        assert!(load_scp03_static_keys(&OWNER_A, 0x01, 0x03).is_some());
        assert_eq!(
            load_scp03_static_keys_for_version(&OWNER_A, 0x01).map(|(_, id)| id),
            Some(0x03)
        );
    }

    #[test]
    fn scp03_static_keys_do_not_cross_security_domain_boundaries() {
        let _registry_guard = reset_registry_test_state();
        assert!(upsert_scp03_key_object(
            OWNER_A,
            0x01,
            0x03,
            Scp03KeyUsage::Enc,
            &sample_key(0x55),
        ));
        assert!(upsert_scp03_key_object(
            OWNER_B,
            0x01,
            0x03,
            Scp03KeyUsage::Mac,
            &sample_key(0x66),
        ));

        // Invariant: SCP03 session derivation is valid only when both halves of
        // the keyset belong to the same owner Security Domain instance.
        assert!(load_scp03_static_keys(&OWNER_A, 0x01, 0x03).is_none());
        assert!(load_scp03_static_keys(&OWNER_B, 0x01, 0x03).is_none());
    }

    #[test]
    fn scp03_key_upsert_replaces_existing_material() {
        let _registry_guard = reset_registry_test_state();
        assert!(upsert_scp03_key_object(
            OWNER_A,
            0x01,
            0x03,
            Scp03KeyUsage::Enc,
            &sample_key(0x77),
        ));
        assert!(upsert_scp03_key_object(
            OWNER_A,
            0x01,
            0x03,
            Scp03KeyUsage::Enc,
            &sample_key(0x88),
        ));

        let mut out = [0u8; SCP03_STATIC_KEY_LEN];
        let len = load_scp03_key_material(&OWNER_A, 0x01, 0x03, Scp03KeyUsage::Enc, &mut out)
            .expect("replaced ENC key should still be readable");
        assert_eq!(len, SCP03_STATIC_KEY_LEN);
        assert_eq!(out, sample_key(0x88));
    }

    #[test]
    fn scp03_key_usage_lookup_is_specific() {
        let _registry_guard = reset_registry_test_state();
        assert!(upsert_scp03_key_object(
            OWNER_A,
            0x01,
            0x03,
            Scp03KeyUsage::Mac,
            &sample_key(0x99),
        ));

        let mut out = [0u8; SCP03_STATIC_KEY_LEN];
        assert!(
            load_scp03_key_material(&OWNER_A, 0x01, 0x03, Scp03KeyUsage::Enc, &mut out).is_none()
        );
        let len = load_scp03_key_material(&OWNER_A, 0x01, 0x03, Scp03KeyUsage::Mac, &mut out)
            .expect("MAC key should be readable only through MAC usage");
        assert_eq!(len, SCP03_STATIC_KEY_LEN);
        assert_eq!(out, sample_key(0x99));
    }

    #[test]
    fn scp03_key_material_rejects_too_small_output_buffer() {
        let _registry_guard = reset_registry_test_state();
        assert!(upsert_scp03_key_object(
            OWNER_A,
            0x01,
            0x03,
            Scp03KeyUsage::Enc,
            &sample_key(0xAA),
        ));

        let mut out = [0u8; SCP03_STATIC_KEY_LEN - 1];
        assert!(
            load_scp03_key_material(&OWNER_A, 0x01, 0x03, Scp03KeyUsage::Enc, &mut out).is_none()
        );
    }

    #[test]
    fn scp03_key_material_ignores_locked_keys() {
        let _registry_guard = reset_registry_test_state();
        let object_aid = scp03_key_object_instance_aid(0x01, 0x03, Scp03KeyUsage::Enc.as_byte());
        assert!(unsafe {
            (&mut *core::ptr::addr_of_mut!(OBJECT_REGISTRY)).upsert_key_object(
                OWNER_A,
                object_aid,
                KeyObjectType::Scp03Static,
                KeyObjectState::Locked,
                0x01,
                0x03,
                Scp03KeyUsage::Enc.as_byte(),
                &sample_key(0xBB),
            )
        });

        let mut out = [0u8; SCP03_STATIC_KEY_LEN];
        assert!(
            load_scp03_key_material(&OWNER_A, 0x01, 0x03, Scp03KeyUsage::Enc, &mut out).is_none()
        );
    }

    #[test]
    fn install_lookup_rejects_locked_package_objects() {
        let _registry_guard = reset_registry_test_state();
        let parent = OWNER_A;
        let package = Aid::from_array([0xF0, 0x0D, 0x01]);
        let applet = Aid::from_array([0xF0, 0x0D, 0x02]);
        assert!(unsafe {
            (&mut *core::ptr::addr_of_mut!(OBJECT_REGISTRY)).insert_package_object(
                parent,
                package,
                applet,
                &[0xCA, 0xFE],
            )
        });
        assert!(unsafe {
            (&mut *core::ptr::addr_of_mut!(OBJECT_REGISTRY)).set_package_state(
                &parent,
                &package,
                crate::object_registry::PackageObjectState::Locked,
            )
        });

        assert!(pending_registry_reference_for_install(&parent, &package, &applet).is_none());
    }

    #[test]
    fn locked_security_domain_cannot_open_secure_channel() {
        let _registry_guard = reset_registry_test_state();
        let root = top_level_parent_sd_aid();
        assert!(unsafe {
            (&mut *core::ptr::addr_of_mut!(OBJECT_REGISTRY)).upsert_security_domain_object(
                root,
                OWNER_A,
                Aid::from_array([0xF0, 0x0D, 0x03]),
                SecurityDomainObjectBackend::KernelSecurityDomain,
                [0xFF, 0xFF, 0xFF],
                &[0x01],
            )
        });
        assert!(security_domain_may_open_secure_channel(&OWNER_A));
        assert!(unsafe {
            (&mut *core::ptr::addr_of_mut!(OBJECT_REGISTRY)).set_security_domain_state(
                &root,
                &OWNER_A,
                crate::object_registry::SecurityDomainObjectState::Locked,
            )
        });

        assert!(!security_domain_may_open_secure_channel(&OWNER_A));
    }

    #[test]
    fn delete_requires_authority_over_target_object() {
        let _registry_guard = reset_registry_test_state();
        let package = Aid::from_array([0xF0, 0x0D, 0x30]);
        assert!(unsafe {
            (&mut *core::ptr::addr_of_mut!(OBJECT_REGISTRY)).insert_package_object(
                OWNER_A,
                package,
                package,
                &[0xCA, 0xFE],
            )
        });

        assert_eq!(
            delete_visible_managed_object_under_authority(OWNER_B, &package, false),
            DeleteManagedObjectResult::NotFound
        );
        unsafe {
            assert!((&*core::ptr::addr_of!(OBJECT_REGISTRY))
                .find_package_object(&OWNER_A, &package)
                .is_some());
        }

        assert_eq!(
            delete_visible_managed_object_under_authority(OWNER_A, &package, false),
            DeleteManagedObjectResult::Deleted
        );
        unsafe {
            assert!((&*core::ptr::addr_of!(OBJECT_REGISTRY))
                .find_package_object(&OWNER_A, &package)
                .is_none());
        }
    }

    #[test]
    fn global_registry_privilege_does_not_escape_the_authority_subtree() {
        let _registry_guard = reset_registry_test_state();
        let root_parent = top_level_parent_sd_aid();
        let package = Aid::from_array([0xF0, 0x0D, 0x3A]);
        assert!(unsafe {
            let registry = &mut *core::ptr::addr_of_mut!(OBJECT_REGISTRY);
            registry.upsert_security_domain_object(
                root_parent,
                OWNER_A,
                OWNER_A,
                SecurityDomainObjectBackend::KernelSecurityDomain,
                [0x80, 0x04, 0x00],
                &[],
            ) && registry.upsert_security_domain_object(
                root_parent,
                OWNER_B,
                OWNER_B,
                SecurityDomainObjectBackend::KernelSecurityDomain,
                [0x80, 0x00, 0x00],
                &[],
            ) && registry.insert_package_object(OWNER_B, package, package, &[0xCA, 0xFE])
        });

        let object = find_any_object_by_aid_raw(&package).expect("sibling package");
        assert!(!security_domain_may_reach_object(&OWNER_A, object));
    }

    #[test]
    fn root_issuer_detached_and_sibling_visibility_follow_the_declared_tree() {
        let _registry_guard = reset_registry_test_state();
        let root_parent = top_level_parent_sd_aid();
        let root = root_security_domain_instance_aid();
        let issuer = Aid::from_array([0xA0, 0x10]);
        let child_a = Aid::from_array([0xA0, 0x11]);
        let grandchild_a = Aid::from_array([0xA0, 0x12]);
        let child_b = Aid::from_array([0xA0, 0x13]);
        let detached = Aid::from_array([0xA0, 0x14]);
        let detached_child = Aid::from_array([0xA0, 0x15]);
        assert!(unsafe {
            let registry = &mut *core::ptr::addr_of_mut!(OBJECT_REGISTRY);
            let mut insert = |parent, aid| {
                registry.upsert_security_domain_object(
                    parent,
                    aid,
                    aid,
                    SecurityDomainObjectBackend::KernelSecurityDomain,
                    [0x80, 0x00, 0x00],
                    &[],
                )
            };
            insert(root_parent, root)
                && insert(root, issuer)
                && insert(issuer, child_a)
                && insert(child_a, grandchild_a)
                && insert(issuer, child_b)
                && insert(root, detached)
                && insert(detached, detached_child)
        });

        let visible = |authority: Aid, target: Aid| {
            let object = find_any_object_by_aid_raw(&target).expect("declared Security Domain");
            security_domain_may_reach_object(&authority, object)
        };
        for target in [
            root,
            issuer,
            child_a,
            grandchild_a,
            child_b,
            detached,
            detached_child,
        ] {
            assert!(visible(root, target));
        }
        assert!(visible(issuer, child_a));
        assert!(visible(issuer, grandchild_a));
        assert!(visible(issuer, child_b));
        assert!(!visible(issuer, root));
        assert!(!visible(issuer, detached));
        assert!(visible(child_a, grandchild_a));
        assert!(!visible(child_a, issuer));
        assert!(!visible(child_a, child_b));
        assert!(!visible(detached, issuer));
        assert!(visible(detached, detached_child));
    }

    #[test]
    fn registry_topology_rejects_privilege_escalation() {
        let _registry_guard = reset_registry_test_state();
        let root_parent = top_level_parent_sd_aid();
        let root = root_security_domain_instance_aid();
        assert!(unsafe {
            let registry = &mut *core::ptr::addr_of_mut!(OBJECT_REGISTRY);
            registry.upsert_security_domain_object(
                root_parent,
                root,
                root,
                SecurityDomainObjectBackend::KernelSecurityDomain,
                [0xA0, 0x00, 0x00],
                &[],
            ) && registry.upsert_security_domain_object(
                root,
                OWNER_A,
                OWNER_A,
                SecurityDomainObjectBackend::KernelSecurityDomain,
                [0x80, 0x00, 0x00],
                &[],
            )
        });
        assert!(validate_security_domain_registry_topology(unsafe {
            &*core::ptr::addr_of!(OBJECT_REGISTRY)
        }));

        assert!(unsafe {
            (&mut *core::ptr::addr_of_mut!(OBJECT_REGISTRY)).upsert_security_domain_object(
                OWNER_A,
                OWNER_B,
                OWNER_B,
                SecurityDomainObjectBackend::KernelSecurityDomain,
                [0xA0, 0x00, 0x00],
                &[],
            )
        });
        assert!(!validate_security_domain_registry_topology(unsafe {
            &*core::ptr::addr_of!(OBJECT_REGISTRY)
        }));
    }

    #[test]
    fn package_delete_requires_cumulative_flag_when_instances_depend_on_it() {
        let _registry_guard = reset_registry_test_state();
        let package = Aid::from_array([0xF0, 0x0D, 0x32]);
        let instance = Aid::from_array([0xF0, 0x0D, 0x33]);
        assert!(unsafe {
            let registry = &mut *core::ptr::addr_of_mut!(OBJECT_REGISTRY);
            registry.insert_package_object(OWNER_A, package, package, &[0xCA, 0xFE])
                && registry.upsert_instance_object(OWNER_A, instance, package, &[])
        });

        assert_eq!(
            delete_visible_managed_object_under_authority(OWNER_A, &package, false),
            DeleteManagedObjectResult::RelatedObjectsExist
        );
        unsafe {
            let registry = &*core::ptr::addr_of!(OBJECT_REGISTRY);
            assert!(registry.find_package_object(&OWNER_A, &package).is_some());
            assert!(registry.find_instance_object(&OWNER_A, &instance).is_some());
        }

        assert_eq!(
            delete_visible_managed_object_under_authority(OWNER_A, &package, true),
            DeleteManagedObjectResult::Deleted
        );
        unsafe {
            let registry = &*core::ptr::addr_of!(OBJECT_REGISTRY);
            assert!(registry.find_package_object(&OWNER_A, &package).is_none());
            assert!(registry.find_instance_object(&OWNER_A, &instance).is_none());
        }
    }

    #[test]
    fn cumulative_delete_rejects_a_dependency_outside_the_authority_subtree() {
        let _registry_guard = reset_registry_test_state();
        let root_parent = top_level_parent_sd_aid();
        let package = Aid::from_array([0xF0, 0x0D, 0x3B]);
        let sibling_instance = Aid::from_array([0xF0, 0x0D, 0x3C]);
        assert!(unsafe {
            let registry = &mut *core::ptr::addr_of_mut!(OBJECT_REGISTRY);
            registry.upsert_security_domain_object(
                root_parent,
                OWNER_A,
                OWNER_A,
                SecurityDomainObjectBackend::KernelSecurityDomain,
                [0x80, 0x00, 0x00],
                &[],
            ) && registry.upsert_security_domain_object(
                root_parent,
                OWNER_B,
                OWNER_B,
                SecurityDomainObjectBackend::KernelSecurityDomain,
                [0x80, 0x00, 0x00],
                &[],
            ) && registry.insert_package_object(OWNER_A, package, package, &[0xCA, 0xFE])
                && registry.upsert_instance_object(OWNER_B, sibling_instance, package, &[])
        });

        assert_eq!(
            delete_visible_managed_object_under_authority(OWNER_A, &package, true),
            DeleteManagedObjectResult::RelatedObjectsExist
        );
        unsafe {
            let registry = &*core::ptr::addr_of!(OBJECT_REGISTRY);
            assert!(registry.find_package_object(&OWNER_A, &package).is_some());
            assert!(registry
                .find_instance_object(&OWNER_B, &sibling_instance)
                .is_some());
        }
    }

    #[test]
    fn security_domain_cumulative_delete_removes_the_complete_subtree() {
        let _registry_guard = reset_registry_test_state();
        let root = top_level_parent_sd_aid();
        let child = Aid::from_array([0xF0, 0x0D, 0x34]);
        let grandchild = Aid::from_array([0xF0, 0x0D, 0x35]);
        let package = Aid::from_array([0xF0, 0x0D, 0x36]);
        assert!(unsafe {
            let registry = &mut *core::ptr::addr_of_mut!(OBJECT_REGISTRY);
            registry.upsert_security_domain_object(
                root,
                child,
                package,
                SecurityDomainObjectBackend::KernelSecurityDomain,
                [0, 0, 0],
                &[],
            ) && registry.upsert_security_domain_object(
                child,
                grandchild,
                package,
                SecurityDomainObjectBackend::KernelSecurityDomain,
                [0, 0, 0],
                &[],
            ) && registry.insert_package_object(grandchild, package, package, &[0xCA, 0xFE])
        });

        assert_eq!(
            delete_visible_managed_object_under_authority(
                root_security_domain_instance_aid(),
                &child,
                false,
            ),
            DeleteManagedObjectResult::RelatedObjectsExist
        );
        assert_eq!(
            delete_visible_managed_object_under_authority(
                root_security_domain_instance_aid(),
                &child,
                true,
            ),
            DeleteManagedObjectResult::Deleted
        );
        unsafe {
            let registry = &*core::ptr::addr_of!(OBJECT_REGISTRY);
            assert!(registry
                .find_security_domain_object(&root, &child)
                .is_none());
            assert!(registry
                .find_security_domain_object(&child, &grandchild)
                .is_none());
            assert!(registry
                .find_package_object(&grandchild, &package)
                .is_none());
        }
    }

    #[test]
    fn deleting_active_security_domain_clears_its_registry_slot_reference() {
        let _registry_guard = reset_registry_test_state();
        let parent = top_level_parent_sd_aid();
        assert!(unsafe {
            (&mut *core::ptr::addr_of_mut!(OBJECT_REGISTRY)).upsert_security_domain_object(
                parent,
                OWNER_A,
                Aid::from_array([0xF0, 0x0D, 0x31]),
                SecurityDomainObjectBackend::KernelSecurityDomain,
                [0, 0, 0],
                &[],
            )
        });
        let slot = unsafe {
            (&*core::ptr::addr_of!(OBJECT_REGISTRY))
                .find_index(&parent, ManagedObjectKind::SecurityDomain, &OWNER_A)
                .expect("Security Domain slot")
        };
        set_active_security_domain_instance_aid(OWNER_A);
        assert_eq!(
            unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ACTIVE_SECURITY_DOMAIN_SLOT)) },
            Some(slot)
        );

        assert_eq!(
            delete_visible_managed_object_under_authority(OWNER_A, &OWNER_A, false),
            DeleteManagedObjectResult::Deleted
        );
        assert_eq!(
            unsafe { core::ptr::read_volatile(core::ptr::addr_of!(ACTIVE_SECURITY_DOMAIN_SLOT)) },
            None
        );
        assert!(unsafe {
            (&*core::ptr::addr_of!(OBJECT_REGISTRY))
                .resolve(slot)
                .is_none()
        });
    }

    #[test]
    fn get_data_registry_fallback_is_parent_qualified() {
        let _registry_guard = reset_registry_test_state();
        let tag = 0xDF42;
        assert!(upsert_registry_data_object(OWNER_A, tag, &[0xA1, 0xA2]));
        assert!(upsert_registry_data_object(
            OWNER_B,
            tag,
            &[0xB1, 0xB2, 0xB3]
        ));

        let mut out = [0u8; 8];
        let len = load_registry_data_object(&OWNER_A, tag, &mut out)
            .expect("OWNER_A data object should be visible under OWNER_A only");
        assert_eq!(len, 2);
        assert_eq!(&out[..len], &[0xA1, 0xA2]);

        let len = load_registry_data_object(&OWNER_B, tag, &mut out)
            .expect("OWNER_B data object should be visible under OWNER_B only");
        assert_eq!(len, 3);
        assert_eq!(&out[..len], &[0xB1, 0xB2, 0xB3]);

        assert!(load_registry_data_object(&top_level_parent_sd_aid(), tag, &mut out).is_none());
    }

    #[test]
    fn set_status_locks_and_unlocks_lifecycle_objects() {
        let _registry_guard = reset_registry_test_state();
        let root = top_level_parent_sd_aid();
        let package = Aid::from_array([0xF0, 0x0D, 0x10]);
        let instance = Aid::from_array([0xF0, 0x0D, 0x11]);
        let domain = Aid::from_array([0xF0, 0x0D, 0x12]);
        assert!(unsafe {
            let registry = &mut *core::ptr::addr_of_mut!(OBJECT_REGISTRY);
            registry.insert_package_object(root, package, package, &[0xCA, 0xFE])
                && registry.upsert_instance_object(root, instance, package, &[0xAA])
                && registry.upsert_security_domain_object(
                    root,
                    domain,
                    package,
                    SecurityDomainObjectBackend::KernelSecurityDomain,
                    [0xFF, 0xFF, 0xFF],
                    &[0x01],
                )
        });

        assert!(set_visible_managed_object_status(
            root_security_domain_instance_aid(),
            crate::security_domain::SET_STATUS_KIND_PACKAGE,
            crate::security_domain::SET_STATUS_STATE_LOCK,
            &package,
        ));
        assert!(set_visible_managed_object_status(
            root_security_domain_instance_aid(),
            crate::security_domain::SET_STATUS_KIND_APPLICATION,
            crate::security_domain::SET_STATUS_STATE_LOCK,
            &instance,
        ));
        assert!(set_visible_managed_object_status(
            root_security_domain_instance_aid(),
            crate::security_domain::SET_STATUS_KIND_SECURITY_DOMAIN,
            crate::security_domain::SET_STATUS_STATE_LOCK,
            &domain,
        ));

        unsafe {
            let registry = &*core::ptr::addr_of!(OBJECT_REGISTRY);
            assert!(!registry
                .find_package_object(&root, &package)
                .expect("package")
                .may_instantiate_package());
            assert!(!registry
                .find_instance_object(&root, &instance)
                .expect("instance")
                .may_select());
            assert!(!registry
                .find_security_domain_object(&root, &domain)
                .expect("domain")
                .may_open_secure_channel());
        }

        assert!(set_visible_managed_object_status(
            root_security_domain_instance_aid(),
            crate::security_domain::SET_STATUS_KIND_PACKAGE,
            crate::security_domain::SET_STATUS_STATE_UNLOCK,
            &package,
        ));
        assert!(set_visible_managed_object_status(
            root_security_domain_instance_aid(),
            crate::security_domain::SET_STATUS_KIND_APPLICATION,
            crate::security_domain::SET_STATUS_STATE_UNLOCK,
            &instance,
        ));
        assert!(set_visible_managed_object_status(
            root_security_domain_instance_aid(),
            crate::security_domain::SET_STATUS_KIND_SECURITY_DOMAIN,
            crate::security_domain::SET_STATUS_STATE_UNLOCK,
            &domain,
        ));

        unsafe {
            let registry = &*core::ptr::addr_of!(OBJECT_REGISTRY);
            assert!(registry
                .find_package_object(&root, &package)
                .expect("package")
                .may_instantiate_package());
            assert!(registry
                .find_instance_object(&root, &instance)
                .expect("instance")
                .may_select());
            assert!(registry
                .find_security_domain_object(&root, &domain)
                .expect("domain")
                .may_open_secure_channel());
        }
    }

    #[test]
    fn set_status_cannot_change_the_technical_root_lifecycle() {
        let _registry_guard = reset_registry_test_state();
        let root_parent = top_level_parent_sd_aid();
        let root = root_security_domain_instance_aid();
        assert!(unsafe {
            (&mut *core::ptr::addr_of_mut!(OBJECT_REGISTRY)).upsert_security_domain_object(
                root_parent,
                root,
                root,
                SecurityDomainObjectBackend::KernelSecurityDomain,
                [0xFF; 3],
                &[],
            )
        });

        assert!(!set_visible_managed_object_status(
            root,
            crate::security_domain::SET_STATUS_KIND_SECURITY_DOMAIN,
            crate::security_domain::SET_STATUS_STATE_LOCK,
            &root,
        ));
        assert!(unsafe {
            (&*core::ptr::addr_of!(OBJECT_REGISTRY))
                .find_security_domain_object(&root_parent, &root)
                .expect("technical root")
                .may_open_secure_channel()
        });
    }

    #[test]
    fn set_status_does_not_target_key_objects() {
        let _registry_guard = reset_registry_test_state();
        let key_aid = scp03_key_object_instance_aid(0x01, 0x03, Scp03KeyUsage::Enc.as_byte());
        assert!(unsafe {
            (&mut *core::ptr::addr_of_mut!(OBJECT_REGISTRY)).upsert_key_object(
                OWNER_A,
                key_aid,
                KeyObjectType::Scp03Static,
                KeyObjectState::Active,
                0x01,
                0x03,
                Scp03KeyUsage::Enc.as_byte(),
                &sample_key(0x42),
            )
        });

        assert!(!set_visible_managed_object_status(
            OWNER_A,
            0x04,
            crate::security_domain::SET_STATUS_STATE_LOCK,
            &key_aid,
        ));
        assert!(!set_visible_managed_object_status(
            OWNER_A,
            crate::security_domain::SET_STATUS_KIND_APPLICATION,
            crate::security_domain::SET_STATUS_STATE_LOCK,
            &key_aid,
        ));
        assert_eq!(
            unsafe {
                (&*core::ptr::addr_of!(OBJECT_REGISTRY))
                    .find_key_object(&OWNER_A, &key_aid)
                    .expect("key")
                    .key_state()
            },
            Some(KeyObjectState::Active)
        );
    }

    #[test]
    fn set_status_requires_authority_over_target_object() {
        let _registry_guard = reset_registry_test_state();
        let root = top_level_parent_sd_aid();
        let package = Aid::from_array([0xF0, 0x0D, 0x20]);
        assert!(unsafe {
            let registry = &mut *core::ptr::addr_of_mut!(OBJECT_REGISTRY);
            registry.upsert_security_domain_object(
                root,
                OWNER_A,
                Aid::from_array([0xF0, 0x0D, 0x21]),
                SecurityDomainObjectBackend::KernelSecurityDomain,
                [0x00, 0x00, 0x00],
                &[0x01],
            ) && registry.upsert_security_domain_object(
                root,
                OWNER_B,
                Aid::from_array([0xF0, 0x0D, 0x22]),
                SecurityDomainObjectBackend::KernelSecurityDomain,
                [0x00, 0x00, 0x00],
                &[0x01],
            ) && registry.insert_package_object(OWNER_A, package, package, &[0xCA, 0xFE])
        });

        assert!(!set_visible_managed_object_status(
            OWNER_B,
            crate::security_domain::SET_STATUS_KIND_PACKAGE,
            crate::security_domain::SET_STATUS_STATE_LOCK,
            &package,
        ));
        assert!(set_visible_managed_object_status(
            OWNER_A,
            crate::security_domain::SET_STATUS_KIND_PACKAGE,
            crate::security_domain::SET_STATUS_STATE_LOCK,
            &package,
        ));
    }

    #[test]
    fn delete_scp03_key_object_removes_one_key_tuple() {
        let _registry_guard = reset_registry_test_state();
        assert!(upsert_scp03_key_object(
            OWNER_A,
            0x01,
            0x03,
            Scp03KeyUsage::Enc,
            &sample_key(0xCC),
        ));
        assert!(upsert_scp03_key_object(
            OWNER_A,
            0x01,
            0x03,
            Scp03KeyUsage::Mac,
            &sample_key(0xDD),
        ));

        assert!(delete_scp03_key_object(
            OWNER_A,
            0x01,
            0x03,
            Scp03KeyUsage::Enc,
        ));
        let mut out = [0u8; SCP03_STATIC_KEY_LEN];
        assert!(
            load_scp03_key_material(&OWNER_A, 0x01, 0x03, Scp03KeyUsage::Enc, &mut out).is_none()
        );
        assert!(
            load_scp03_key_material(&OWNER_A, 0x01, 0x03, Scp03KeyUsage::Mac, &mut out).is_some()
        );
    }
}
