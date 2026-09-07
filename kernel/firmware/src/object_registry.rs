//! Polymorphic kernel object registry.
//!
//! This module stores the administrative objects that make up the kernel-side
//! GlobalPlatform model:
//! - Security Domains
//! - loaded Rustlet packages
//! - installed Rustlet instances
//! - cryptographic key objects
//! - generic management data objects
//!
//! Every entry is attached to one parent Security Domain AID and one object
//! AID, then interpreted according to its [`ManagedObjectKind`]. This gives us
//! one uniform registry while still allowing each object family to expose its
//! own payload:
//! - Security Domains carry their package binding, base privilege bytes and
//!   serialized administrative state.
//! - Packages carry the embedded binary code that can later be instantiated.
//! - Instances carry their package binding and serialized application state.
//! - Keys carry typed raw bytes plus protocol-specific metadata.
//! - Data objects carry Security-Domain-scoped management bytes such as values
//!   stored through `STORE DATA` and returned through `GET DATA`.
//!
//! The registry intentionally models "what exists" rather than "how it was
//! created". Installation, secure-channel policy and APDU routing are handled
//! by higher layers.

use rustlet_runtime::Aid;

/// Capacity budget used by the kernel-wide object registry.
///
/// This must cover the root Security Domain, predeployed packages, dynamically
/// installed instances and administrative key objects during one boot.
pub const DEFAULT_KERNEL_OBJECT_REGISTRY_CAPACITY: usize = 25;

/// Declares which functional family one registry object belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ManagedObjectKind {
    SecurityDomain,
    Package,
    Instance,
    Key,
    Data,
}

/// Distinguishes the backend used by one registered Security Domain.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
// The suffix is intentional: these names are serialized configuration concepts
// and remain unambiguous when displayed without their enum path.
#[allow(clippy::enum_variant_names)]
pub enum SecurityDomainObjectBackend {
    NullSecurityDomain,
    KernelSecurityDomain,
    RustletSecurityDomain,
}

/// Declares the concrete key-object format stored in one registry entry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyObjectType {
    Scp03Static,
    Scp11SdEckaPrivate,
    Scp11CaKlocPublic,
}

/// Lifecycle state for one registry key object.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyObjectState {
    Active,
    Locked,
}

/// Lifecycle state for one loaded package object.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PackageObjectState {
    Loaded,
    Locked,
}

/// Lifecycle state for one ordinary Rustlet instance object.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InstanceObjectState {
    Selectable,
    Locked,
}

/// Lifecycle state for one Security Domain instance object.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SecurityDomainObjectState {
    Selectable,
    Locked,
}

#[derive(Clone, Copy)]
pub enum RegistryObjectPayload {
    SecurityDomain {
        package_aid: Aid,
        backend: SecurityDomainObjectBackend,
        object_state: SecurityDomainObjectState,
        #[allow(dead_code)]
        privilege_bytes: [u8; 3],
        serialized_state: [u8; rustlet_runtime::STATE_BUFFER_CAPACITY],
        serialized_state_len: usize,
    },
    Package {
        package_state: PackageObjectState,
        applet_aid: Aid,
        binary_code: &'static [u8],
    },
    Instance {
        instance_state: InstanceObjectState,
        package_aid: Aid,
        serialized_state: [u8; rustlet_runtime::STATE_BUFFER_CAPACITY],
        serialized_state_len: usize,
    },
    Key {
        key_type: KeyObjectType,
        key_state: KeyObjectState,
        key_version: u8,
        key_id: u8,
        key_usage: u8,
        raw_key_bytes: [u8; rustlet_runtime::STATE_BUFFER_CAPACITY],
        raw_key_len: usize,
    },
    Data {
        bytes: [u8; rustlet_runtime::STATE_BUFFER_CAPACITY],
        len: usize,
    },
}

/// One stored registry object.
///
/// The common header is always meaningful:
/// - `parent_sd_aid`
/// - `object_kind`
/// - `object_aid`
///
/// The remaining fields are interpreted according to `object_kind`.
#[derive(Clone, Copy)]
pub struct RegistryObject {
    pub parent_sd_aid: Aid,
    pub object_kind: ManagedObjectKind,
    pub object_aid: Aid,
    pub payload: RegistryObjectPayload,
}

impl RegistryObject {
    pub fn package_aid(&self) -> Option<Aid> {
        match self.payload {
            RegistryObjectPayload::SecurityDomain { package_aid, .. }
            | RegistryObjectPayload::Instance { package_aid, .. } => Some(package_aid),
            RegistryObjectPayload::Package { .. }
            | RegistryObjectPayload::Key { .. }
            | RegistryObjectPayload::Data { .. } => None,
        }
    }

    pub fn package_applet_aid(&self) -> Option<Aid> {
        match self.payload {
            RegistryObjectPayload::Package { applet_aid, .. } => Some(applet_aid),
            _ => None,
        }
    }

    pub fn package_binary_code(&self) -> Option<&'static [u8]> {
        match self.payload {
            RegistryObjectPayload::Package { binary_code, .. } => Some(binary_code),
            _ => None,
        }
    }

    pub fn package_state(&self) -> Option<PackageObjectState> {
        match self.payload {
            RegistryObjectPayload::Package { package_state, .. } => Some(package_state),
            _ => None,
        }
    }

    /// Returns whether the package can be used by `INSTALL [for install]`.
    pub fn may_instantiate_package(&self) -> bool {
        self.package_state() == Some(PackageObjectState::Loaded)
    }

    pub fn security_domain_state(&self) -> Option<SecurityDomainObjectState> {
        match self.payload {
            RegistryObjectPayload::SecurityDomain { object_state, .. } => Some(object_state),
            _ => None,
        }
    }

    pub fn instance_state(&self) -> Option<InstanceObjectState> {
        match self.payload {
            RegistryObjectPayload::Instance { instance_state, .. } => Some(instance_state),
            _ => None,
        }
    }

    /// Returns whether this object can become the selected application context.
    pub fn may_select(&self) -> bool {
        match self.payload {
            RegistryObjectPayload::SecurityDomain { object_state, .. } => {
                object_state == SecurityDomainObjectState::Selectable
            }
            RegistryObjectPayload::Instance { instance_state, .. } => {
                instance_state == InstanceObjectState::Selectable
            }
            RegistryObjectPayload::Package { .. }
            | RegistryObjectPayload::Key { .. }
            | RegistryObjectPayload::Data { .. } => false,
        }
    }

    /// Returns whether this Security Domain can authorize SCP establishment.
    pub fn may_open_secure_channel(&self) -> bool {
        self.security_domain_state() == Some(SecurityDomainObjectState::Selectable)
    }

    pub fn security_domain_backend(&self) -> Option<SecurityDomainObjectBackend> {
        match self.payload {
            RegistryObjectPayload::SecurityDomain { backend, .. } => Some(backend),
            _ => None,
        }
    }

    pub fn serialized_state(&self) -> Option<&[u8]> {
        match &self.payload {
            RegistryObjectPayload::SecurityDomain {
                serialized_state,
                serialized_state_len,
                ..
            }
            | RegistryObjectPayload::Instance {
                serialized_state,
                serialized_state_len,
                ..
            } => Some(&serialized_state[..*serialized_state_len]),
            _ => None,
        }
    }

    pub fn security_domain_privilege_bytes(&self) -> Option<[u8; 3]> {
        match self.payload {
            RegistryObjectPayload::SecurityDomain {
                privilege_bytes, ..
            } => Some(privilege_bytes),
            _ => None,
        }
    }

    pub fn key_data(&self) -> Option<(KeyObjectType, u8, u8, u8, &[u8])> {
        match &self.payload {
            RegistryObjectPayload::Key {
                key_type,
                key_state: _,
                key_version,
                key_id,
                key_usage,
                raw_key_bytes,
                raw_key_len,
            } => Some((
                *key_type,
                *key_version,
                *key_id,
                *key_usage,
                &raw_key_bytes[..*raw_key_len],
            )),
            _ => None,
        }
    }

    pub fn key_state(&self) -> Option<KeyObjectState> {
        match self.payload {
            RegistryObjectPayload::Key { key_state, .. } => Some(key_state),
            _ => None,
        }
    }

    pub fn data_bytes(&self) -> Option<&[u8]> {
        match &self.payload {
            RegistryObjectPayload::Data { bytes, len } => Some(&bytes[..*len]),
            _ => None,
        }
    }
}

/// Fixed-capacity polymorphic registry used by the kernel.
///
/// The registry is intentionally allocation-free and can therefore be shared by
/// both host-side tests and the embedded firmware runtime.
pub struct ObjectRegistry<const N: usize> {
    // Invariant: runtime registry references are stable slot numbers. Every
    // `Option<usize>` registry references that can outlive a lookup --
    // `ACTIVE_SECURITY_DOMAIN_SLOT`, `AppRegistryReference::instance_index()`,
    // the exceptionally displaced application returned by
    // `ensure_active_security_domain_loaded_for_secure_channel()`, and the slot
    // consumed by `restore_selected_app_after_secure_channel()` --
    // must be cleared or consumed before `delete_object` makes a slot reusable.
    entries: [Option<RegistryObject>; N],
    len: usize,
}

impl<const N: usize> Default for ObjectRegistry<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> ObjectRegistry<N> {
    pub const fn new() -> Self {
        Self {
            entries: [None; N],
            len: 0,
        }
    }

    pub fn clear(&mut self) {
        self.entries = [None; N];
        self.len = 0;
    }

    /// Returns the number of live registry entries.
    #[allow(dead_code)]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns true when the registry does not contain any live entry.
    #[allow(dead_code)]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Iterates over live entries in stable slot order.
    ///
    /// Persistence code uses this read-only view to publish a committed
    /// registry snapshot without exposing the fixed-capacity backing array.
    #[allow(dead_code)]
    pub fn entries(&self) -> RegistryEntries<'_, N> {
        RegistryEntries {
            registry: self,
            index: 0,
        }
    }

    /// Resolves one stable runtime slot number.
    pub fn resolve(&self, index: usize) -> Option<&RegistryObject> {
        self.entries.get(index)?.as_ref()
    }

    /// Finds the stable slot number for one fully qualified registry identity.
    pub fn find_index(
        &self,
        parent_sd_aid: &Aid,
        object_kind: ManagedObjectKind,
        object_aid: &Aid,
    ) -> Option<usize> {
        self.find_slot_by_identity(parent_sd_aid, object_kind, object_aid)
    }

    /// Finds the preferred live object slot for an unqualified AID lookup.
    pub fn find_any_index(&self, object_aid: &Aid) -> Option<usize> {
        let mut best_index: Option<usize> = None;
        let mut index = 0;
        while index < N {
            if let Some(entry) = self.entries[index].as_ref() {
                if entry.object_aid == *object_aid {
                    let replace = match (
                        best_index.and_then(|slot| self.entries[slot].as_ref()),
                        entry.object_kind,
                    ) {
                        (None, _) => true,
                        (
                            Some(best),
                            ManagedObjectKind::Instance | ManagedObjectKind::SecurityDomain,
                        ) if best.object_kind == ManagedObjectKind::Package
                            || best.object_kind == ManagedObjectKind::Key =>
                        {
                            true
                        }
                        (
                            Some(best),
                            ManagedObjectKind::Package
                            | ManagedObjectKind::Instance
                            | ManagedObjectKind::SecurityDomain,
                        ) if best.object_kind == ManagedObjectKind::Data => true,
                        (Some(best), ManagedObjectKind::SecurityDomain)
                            if best.object_kind == ManagedObjectKind::Instance =>
                        {
                            true
                        }
                        _ => false,
                    };
                    if replace {
                        best_index = Some(index);
                    }
                }
            }
            index += 1;
        }
        best_index
    }

    fn find_slot_by_identity(
        &self,
        parent_sd_aid: &Aid,
        object_kind: ManagedObjectKind,
        object_aid: &Aid,
    ) -> Option<usize> {
        let mut index = 0;
        while index < N {
            if let Some(entry) = self.entries[index].as_ref() {
                if entry.parent_sd_aid == *parent_sd_aid
                    && entry.object_kind == object_kind
                    && entry.object_aid == *object_aid
                {
                    return Some(index);
                }
            }
            index += 1;
        }
        None
    }

    fn find_any_slot_by_kind_and_aid(
        &self,
        object_kind: ManagedObjectKind,
        object_aid: &Aid,
    ) -> Option<usize> {
        let mut index = 0;
        while index < N {
            if let Some(entry) = self.entries[index].as_ref() {
                if entry.object_kind == object_kind && entry.object_aid == *object_aid {
                    return Some(index);
                }
            }
            index += 1;
        }
        None
    }

    fn allocate_or_get_slot(
        &mut self,
        parent_sd_aid: Aid,
        object_kind: ManagedObjectKind,
        object_aid: Aid,
        allow_parent_qualified_reuse: bool,
    ) -> Option<usize> {
        if let Some(index) = self.find_slot_by_identity(&parent_sd_aid, object_kind, &object_aid) {
            return Some(index);
        }
        // Invariant: packages, instances and Security Domains are globally
        // addressable by AID. Key and generic data objects are scoped by their
        // parent Security Domain and may reuse the same object AID there.
        if !allow_parent_qualified_reuse
            && self
                .find_any_slot_by_kind_and_aid(object_kind, &object_aid)
                .is_some()
        {
            return None;
        }
        if self.len >= N {
            return None;
        }
        let mut index = 0;
        while index < N && self.entries[index].is_some() {
            index += 1;
        }
        if index == N {
            return None;
        }
        self.entries[index] = Some(RegistryObject {
            parent_sd_aid,
            object_kind,
            object_aid,
            payload: RegistryObjectPayload::Package {
                package_state: PackageObjectState::Loaded,
                applet_aid: Aid::new(&[]),
                binary_code: &[],
            },
        });
        self.len += 1;
        Some(index)
    }

    pub fn insert_package_object(
        &mut self,
        parent_sd_aid: Aid,
        package_aid: Aid,
        applet_aid: Aid,
        binary_code: &'static [u8],
    ) -> bool {
        // Invariant: one package AID resolves to at most one loaded package
        // object in the registry, even if several Security Domains may later
        // install instances from it.
        let Some(index) = self.allocate_or_get_slot(
            parent_sd_aid,
            ManagedObjectKind::Package,
            package_aid,
            false,
        ) else {
            return false;
        };
        let Some(entry) = self.entries[index].as_mut() else {
            return false;
        };
        entry.payload = RegistryObjectPayload::Package {
            package_state: PackageObjectState::Loaded,
            applet_aid,
            binary_code,
        };
        true
    }

    #[allow(dead_code)]
    pub fn find_package_object(
        &self,
        parent_sd_aid: &Aid,
        package_aid: &Aid,
    ) -> Option<&RegistryObject> {
        let index =
            self.find_slot_by_identity(parent_sd_aid, ManagedObjectKind::Package, package_aid)?;
        self.entries[index].as_ref()
    }

    pub fn set_package_state(
        &mut self,
        parent_sd_aid: &Aid,
        package_aid: &Aid,
        package_state: PackageObjectState,
    ) -> bool {
        let Some(index) =
            self.find_slot_by_identity(parent_sd_aid, ManagedObjectKind::Package, package_aid)
        else {
            return false;
        };
        let Some(entry) = self.entries[index].as_mut() else {
            return false;
        };
        if let RegistryObjectPayload::Package {
            package_state: stored_state,
            ..
        } = &mut entry.payload
        {
            *stored_state = package_state;
            true
        } else {
            false
        }
    }

    pub fn upsert_security_domain_object(
        &mut self,
        parent_sd_aid: Aid,
        instance_aid: Aid,
        package_aid: Aid,
        backend: SecurityDomainObjectBackend,
        privilege_bytes: [u8; 3],
        serialized_state: &[u8],
    ) -> bool {
        if serialized_state.len() > rustlet_runtime::STATE_BUFFER_CAPACITY {
            return false;
        }
        if let Some(index) = self.find_slot_by_identity(
            &parent_sd_aid,
            ManagedObjectKind::SecurityDomain,
            &instance_aid,
        ) {
            let Some(entry) = self.entries[index].as_mut() else {
                return false;
            };
            if let RegistryObjectPayload::SecurityDomain {
                package_aid: stored_package_aid,
                backend: stored_backend,
                object_state: _,
                privilege_bytes: stored_privilege_bytes,
                serialized_state: stored_state,
                serialized_state_len,
            } = &mut entry.payload
            {
                *stored_package_aid = package_aid;
                *stored_backend = backend;
                *stored_privilege_bytes = privilege_bytes;
                stored_state[..serialized_state.len()].copy_from_slice(serialized_state);
                *serialized_state_len = serialized_state.len();
                return true;
            }
            return false;
        }
        let Some(index) = self.allocate_or_get_slot(
            parent_sd_aid,
            ManagedObjectKind::SecurityDomain,
            instance_aid,
            false,
        ) else {
            return false;
        };
        let Some(entry) = self.entries[index].as_mut() else {
            return false;
        };
        // Invariant: the first three install bytes are tracked separately as
        // base privileges because the rest of the serialized state may be
        // backend-specific.
        let mut state = [0u8; rustlet_runtime::STATE_BUFFER_CAPACITY];
        state[..serialized_state.len()].copy_from_slice(serialized_state);
        entry.payload = RegistryObjectPayload::SecurityDomain {
            package_aid,
            backend,
            object_state: SecurityDomainObjectState::Selectable,
            privilege_bytes,
            serialized_state: state,
            serialized_state_len: serialized_state.len(),
        };
        true
    }

    pub fn find_security_domain_object(
        &self,
        parent_sd_aid: &Aid,
        instance_aid: &Aid,
    ) -> Option<&RegistryObject> {
        let index = self.find_slot_by_identity(
            parent_sd_aid,
            ManagedObjectKind::SecurityDomain,
            instance_aid,
        )?;
        self.entries[index].as_ref()
    }

    pub fn set_security_domain_state(
        &mut self,
        parent_sd_aid: &Aid,
        instance_aid: &Aid,
        object_state: SecurityDomainObjectState,
    ) -> bool {
        let Some(index) = self.find_slot_by_identity(
            parent_sd_aid,
            ManagedObjectKind::SecurityDomain,
            instance_aid,
        ) else {
            return false;
        };
        let Some(entry) = self.entries[index].as_mut() else {
            return false;
        };
        if let RegistryObjectPayload::SecurityDomain {
            object_state: stored_state,
            ..
        } = &mut entry.payload
        {
            *stored_state = object_state;
            true
        } else {
            false
        }
    }

    pub fn upsert_instance_object(
        &mut self,
        parent_sd_aid: Aid,
        instance_aid: Aid,
        package_aid: Aid,
        serialized_state: &[u8],
    ) -> bool {
        if serialized_state.len() > rustlet_runtime::STATE_BUFFER_CAPACITY {
            return false;
        }
        if let Some(index) =
            self.find_slot_by_identity(&parent_sd_aid, ManagedObjectKind::Instance, &instance_aid)
        {
            let Some(entry) = self.entries[index].as_mut() else {
                return false;
            };
            if let RegistryObjectPayload::Instance {
                package_aid: stored_package_aid,
                instance_state: _,
                serialized_state: stored_state,
                serialized_state_len,
            } = &mut entry.payload
            {
                *stored_package_aid = package_aid;
                stored_state[..serialized_state.len()].copy_from_slice(serialized_state);
                *serialized_state_len = serialized_state.len();
                return true;
            }
            return false;
        }
        let Some(index) = self.allocate_or_get_slot(
            parent_sd_aid,
            ManagedObjectKind::Instance,
            instance_aid,
            false,
        ) else {
            return false;
        };
        let Some(entry) = self.entries[index].as_mut() else {
            return false;
        };
        // Invariant: ordinary Rustlet instances never carry Security Domain
        // privileges in the registry; only their package binding and serialized
        // runtime state are stored here.
        let mut state = [0u8; rustlet_runtime::STATE_BUFFER_CAPACITY];
        state[..serialized_state.len()].copy_from_slice(serialized_state);
        entry.payload = RegistryObjectPayload::Instance {
            instance_state: InstanceObjectState::Selectable,
            package_aid,
            serialized_state: state,
            serialized_state_len: serialized_state.len(),
        };
        true
    }

    pub fn find_instance_object(
        &self,
        parent_sd_aid: &Aid,
        instance_aid: &Aid,
    ) -> Option<&RegistryObject> {
        let index =
            self.find_slot_by_identity(parent_sd_aid, ManagedObjectKind::Instance, instance_aid)?;
        self.entries[index].as_ref()
    }

    pub fn set_instance_state(
        &mut self,
        parent_sd_aid: &Aid,
        instance_aid: &Aid,
        instance_state: InstanceObjectState,
    ) -> bool {
        let Some(index) =
            self.find_slot_by_identity(parent_sd_aid, ManagedObjectKind::Instance, instance_aid)
        else {
            return false;
        };
        let Some(entry) = self.entries[index].as_mut() else {
            return false;
        };
        if let RegistryObjectPayload::Instance {
            instance_state: stored_state,
            ..
        } = &mut entry.payload
        {
            *stored_state = instance_state;
            true
        } else {
            false
        }
    }

    // The explicit parameters mirror the on-flash key object identity and are
    // clearer at the call sites than a second, partially overlapping DTO.
    #[allow(clippy::too_many_arguments)]
    pub fn upsert_key_object(
        &mut self,
        parent_sd_aid: Aid,
        object_aid: Aid,
        key_type: KeyObjectType,
        key_state: KeyObjectState,
        key_version: u8,
        key_id: u8,
        key_usage: u8,
        raw_key_bytes: &[u8],
    ) -> bool {
        if raw_key_bytes.len() > rustlet_runtime::STATE_BUFFER_CAPACITY {
            return false;
        }
        if let Some(index) =
            self.find_slot_by_identity(&parent_sd_aid, ManagedObjectKind::Key, &object_aid)
        {
            let Some(entry) = self.entries[index].as_mut() else {
                return false;
            };
            if let RegistryObjectPayload::Key {
                key_type: stored_key_type,
                key_state: stored_key_state,
                key_version: stored_key_version,
                key_id: stored_key_id,
                key_usage: stored_key_usage,
                raw_key_bytes: stored_key_bytes,
                raw_key_len,
            } = &mut entry.payload
            {
                *stored_key_type = key_type;
                *stored_key_state = key_state;
                *stored_key_version = key_version;
                *stored_key_id = key_id;
                *stored_key_usage = key_usage;
                stored_key_bytes[..raw_key_bytes.len()].copy_from_slice(raw_key_bytes);
                *raw_key_len = raw_key_bytes.len();
                return true;
            }
            return false;
        }
        let Some(index) =
            self.allocate_or_get_slot(parent_sd_aid, ManagedObjectKind::Key, object_aid, true)
        else {
            return false;
        };
        let Some(entry) = self.entries[index].as_mut() else {
            return false;
        };
        // Invariant: key objects are the only parent-qualified resources that
        // may reuse the same object AID under different Security Domains.
        let mut key_bytes = [0u8; rustlet_runtime::STATE_BUFFER_CAPACITY];
        key_bytes[..raw_key_bytes.len()].copy_from_slice(raw_key_bytes);
        entry.payload = RegistryObjectPayload::Key {
            key_type,
            key_state,
            key_version,
            key_id,
            key_usage,
            raw_key_bytes: key_bytes,
            raw_key_len: raw_key_bytes.len(),
        };
        true
    }

    pub fn find_key_object(
        &self,
        parent_sd_aid: &Aid,
        object_aid: &Aid,
    ) -> Option<&RegistryObject> {
        let index =
            self.find_slot_by_identity(parent_sd_aid, ManagedObjectKind::Key, object_aid)?;
        self.entries[index].as_ref()
    }

    pub fn set_key_state(
        &mut self,
        parent_sd_aid: &Aid,
        object_aid: &Aid,
        key_state: KeyObjectState,
    ) -> bool {
        let Some(index) =
            self.find_slot_by_identity(parent_sd_aid, ManagedObjectKind::Key, object_aid)
        else {
            return false;
        };
        let Some(entry) = self.entries[index].as_mut() else {
            return false;
        };
        if let RegistryObjectPayload::Key {
            key_state: stored_state,
            ..
        } = &mut entry.payload
        {
            *stored_state = key_state;
            true
        } else {
            false
        }
    }

    pub fn upsert_data_object(&mut self, parent_sd_aid: Aid, object_aid: Aid, data: &[u8]) -> bool {
        if data.len() > rustlet_runtime::STATE_BUFFER_CAPACITY {
            return false;
        }
        if let Some(index) =
            self.find_slot_by_identity(&parent_sd_aid, ManagedObjectKind::Data, &object_aid)
        {
            let Some(entry) = self.entries[index].as_mut() else {
                return false;
            };
            if let RegistryObjectPayload::Data { bytes, len } = &mut entry.payload {
                bytes[..data.len()].copy_from_slice(data);
                *len = data.len();
                return true;
            }
            return false;
        }
        let Some(index) =
            self.allocate_or_get_slot(parent_sd_aid, ManagedObjectKind::Data, object_aid, true)
        else {
            return false;
        };
        let Some(entry) = self.entries[index].as_mut() else {
            return false;
        };
        // Invariant: data objects are owned by their parent Security Domain.
        // Their object AID is a kernel-derived identifier for a GP data tag,
        // not an installable or selectable application AID.
        let mut bytes = [0u8; rustlet_runtime::STATE_BUFFER_CAPACITY];
        bytes[..data.len()].copy_from_slice(data);
        entry.payload = RegistryObjectPayload::Data {
            bytes,
            len: data.len(),
        };
        true
    }

    pub fn find_data_object(
        &self,
        parent_sd_aid: &Aid,
        object_aid: &Aid,
    ) -> Option<&RegistryObject> {
        let index =
            self.find_slot_by_identity(parent_sd_aid, ManagedObjectKind::Data, object_aid)?;
        self.entries[index].as_ref()
    }

    /// Deletes one object identified by its common registry identity.
    ///
    /// Returns `true` only when a live object existed and was removed. The
    /// vacated slot becomes a tombstone and no other slot moves.
    pub fn delete_object(
        &mut self,
        parent_sd_aid: &Aid,
        object_kind: ManagedObjectKind,
        object_aid: &Aid,
    ) -> bool {
        let Some(index) = self.find_slot_by_identity(parent_sd_aid, object_kind, object_aid) else {
            return false;
        };
        // Invariant: registry slots never move. The caller invalidates every
        // optional runtime reference to this slot before deletion leaves the
        // tombstone available for reuse.
        self.entries[index] = None;
        self.len -= 1;
        true
    }

    pub fn find_any_object(&self, object_aid: &Aid) -> Option<&RegistryObject> {
        self.resolve(self.find_any_index(object_aid)?)
    }

    pub fn clone_scp03_keys(&mut self, source_sd_aid: Aid, target_sd_aid: Aid) -> bool {
        let mut index = 0usize;
        let mut cloned_any = false;
        while index < N {
            let Some(instance) = self.entries[index].as_ref() else {
                index += 1;
                continue;
            };
            // Invariant: only SCP03 static key objects participate in this
            // helper; package, data, instance and Security Domain objects must
            // never be duplicated implicitly.
            if instance.parent_sd_aid == source_sd_aid
                && instance.object_kind == ManagedObjectKind::Key
            {
                let RegistryObjectPayload::Key {
                    key_type,
                    key_state,
                    key_version,
                    key_id,
                    key_usage,
                    raw_key_bytes,
                    raw_key_len,
                } = instance.payload
                else {
                    index += 1;
                    continue;
                };
                if key_type != KeyObjectType::Scp03Static {
                    index += 1;
                    continue;
                }
                let object_aid = instance.object_aid;
                if !self.upsert_key_object(
                    target_sd_aid,
                    object_aid,
                    KeyObjectType::Scp03Static,
                    key_state,
                    key_version,
                    key_id,
                    key_usage,
                    &raw_key_bytes[..raw_key_len],
                ) {
                    return false;
                }
                cloned_any = true;
            }
            index += 1;
        }
        cloned_any
    }
}

/// Iterator over live [`ObjectRegistry`] entries.
///
/// The iterator skips tombstones while preserving stable slot order.
#[allow(dead_code)]
pub struct RegistryEntries<'a, const N: usize> {
    registry: &'a ObjectRegistry<N>,
    index: usize,
}

impl<'a, const N: usize> Iterator for RegistryEntries<'a, N> {
    type Item = &'a RegistryObject;

    fn next(&mut self) -> Option<Self::Item> {
        while self.index < N {
            let index = self.index;
            self.index += 1;
            if let Some(entry) = self.registry.entries[index].as_ref() {
                return Some(entry);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aid(bytes: &[u8]) -> Aid {
        Aid::new(bytes)
    }

    #[test]
    fn package_and_instance_can_share_same_aid() {
        let mut registry: ObjectRegistry<8> = ObjectRegistry::new();
        let shared = aid(&[0x01]);
        assert!(registry.insert_package_object(aid(&[]), shared, shared, &[0xCA, 0xFE]));
        assert!(registry.upsert_instance_object(aid(&[]), shared, shared, &[0xAA]));
        let resolved = registry.find_any_object(&shared).expect("shared object");
        assert_eq!(resolved.object_kind, ManagedObjectKind::Instance);
    }

    #[test]
    fn package_aids_are_globally_unique() {
        let mut registry: ObjectRegistry<8> = ObjectRegistry::new();
        let package = aid(&[0x01]);
        assert!(registry.insert_package_object(aid(&[]), package, package, &[0x01]));
        assert!(!registry.insert_package_object(aid(&[0x02]), package, package, &[0x02]));
    }

    #[test]
    fn keys_are_parent_qualified() {
        let mut registry: ObjectRegistry<8> = ObjectRegistry::new();
        let key = aid(&[0x4B]);
        assert!(registry.upsert_key_object(
            aid(&[0x01]),
            key,
            KeyObjectType::Scp03Static,
            KeyObjectState::Active,
            1,
            3,
            1,
            &[0xAA]
        ));
        assert!(registry.upsert_key_object(
            aid(&[0x02]),
            key,
            KeyObjectType::Scp03Static,
            KeyObjectState::Active,
            1,
            3,
            1,
            &[0xBB]
        ));
        let a = registry
            .find_key_object(&aid(&[0x01]), &key)
            .expect("key a");
        let b = registry
            .find_key_object(&aid(&[0x02]), &key)
            .expect("key b");
        assert_eq!(a.key_state(), Some(KeyObjectState::Active));
        assert_eq!(b.key_state(), Some(KeyObjectState::Active));
        assert_eq!(a.key_data().expect("key a data").4[0], 0xAA);
        assert_eq!(b.key_data().expect("key b data").4[0], 0xBB);
    }

    #[test]
    fn key_upsert_can_rotate_state_and_material() {
        let mut registry: ObjectRegistry<4> = ObjectRegistry::new();
        let key = aid(&[0x4B]);
        assert!(registry.upsert_key_object(
            aid(&[0x01]),
            key,
            KeyObjectType::Scp03Static,
            KeyObjectState::Active,
            1,
            3,
            1,
            &[0xAA]
        ));
        assert!(registry.upsert_key_object(
            aid(&[0x01]),
            key,
            KeyObjectType::Scp03Static,
            KeyObjectState::Locked,
            1,
            3,
            1,
            &[0xBB]
        ));
        let stored = registry
            .find_key_object(&aid(&[0x01]), &key)
            .expect("rotated key");
        assert_eq!(stored.key_state(), Some(KeyObjectState::Locked));
        assert_eq!(stored.key_data().expect("key data").4, &[0xBB]);
    }

    #[test]
    fn default_lifecycle_states_allow_their_normal_operation_families() {
        let mut registry: ObjectRegistry<8> = ObjectRegistry::new();
        let parent = aid(&[0x10]);
        let package = aid(&[0x20]);
        let instance = aid(&[0x30]);
        let domain = aid(&[0x40]);
        let key = aid(&[0x4B]);

        assert!(registry.insert_package_object(parent, package, package, &[0xCA, 0xFE]));
        assert!(registry.upsert_instance_object(parent, instance, package, &[0xAA]));
        assert!(registry.upsert_security_domain_object(
            parent,
            domain,
            package,
            SecurityDomainObjectBackend::KernelSecurityDomain,
            [0xFF, 0xFF, 0xFF],
            &[0x01],
        ));
        assert!(registry.upsert_key_object(
            parent,
            key,
            KeyObjectType::Scp03Static,
            KeyObjectState::Active,
            1,
            3,
            1,
            &[0xBB],
        ));

        assert!(registry
            .find_package_object(&parent, &package)
            .expect("package")
            .may_instantiate_package());
        assert!(registry
            .find_instance_object(&parent, &instance)
            .expect("instance")
            .may_select());
        let domain_object = registry
            .find_security_domain_object(&parent, &domain)
            .expect("security domain");
        assert!(domain_object.may_select());
        assert!(domain_object.may_open_secure_channel());
        assert_eq!(
            registry
                .find_key_object(&parent, &key)
                .expect("key")
                .key_state(),
            Some(KeyObjectState::Active)
        );
    }

    #[test]
    fn locked_lifecycle_states_block_their_normal_operation_families() {
        let mut registry: ObjectRegistry<8> = ObjectRegistry::new();
        let parent = aid(&[0x10]);
        let package = aid(&[0x20]);
        let instance = aid(&[0x30]);
        let domain = aid(&[0x40]);
        let key = aid(&[0x4B]);

        assert!(registry.insert_package_object(parent, package, package, &[0xCA, 0xFE]));
        assert!(registry.upsert_instance_object(parent, instance, package, &[0xAA]));
        assert!(registry.upsert_security_domain_object(
            parent,
            domain,
            package,
            SecurityDomainObjectBackend::KernelSecurityDomain,
            [0xFF, 0xFF, 0xFF],
            &[0x01],
        ));
        assert!(registry.upsert_key_object(
            parent,
            key,
            KeyObjectType::Scp03Static,
            KeyObjectState::Active,
            1,
            3,
            1,
            &[0xBB],
        ));

        assert!(registry.set_package_state(&parent, &package, PackageObjectState::Locked));
        assert!(registry.set_instance_state(&parent, &instance, InstanceObjectState::Locked));
        assert!(registry.set_security_domain_state(
            &parent,
            &domain,
            SecurityDomainObjectState::Locked,
        ));
        assert!(registry.set_key_state(&parent, &key, KeyObjectState::Locked));

        assert!(!registry
            .find_package_object(&parent, &package)
            .expect("package")
            .may_instantiate_package());
        assert!(!registry
            .find_instance_object(&parent, &instance)
            .expect("instance")
            .may_select());
        let domain_object = registry
            .find_security_domain_object(&parent, &domain)
            .expect("security domain");
        assert!(!domain_object.may_select());
        assert!(!domain_object.may_open_secure_channel());
        assert_eq!(
            registry
                .find_key_object(&parent, &key)
                .expect("key")
                .key_state(),
            Some(KeyObjectState::Locked)
        );
    }

    #[test]
    fn clone_scp03_keys_copies_only_key_objects() {
        let mut registry: ObjectRegistry<8> = ObjectRegistry::new();
        let source = aid(&[0x10]);
        let target = aid(&[0x20]);
        let key = aid(&[0x4B, 0x01]);
        assert!(registry.upsert_key_object(
            source,
            key,
            KeyObjectType::Scp03Static,
            KeyObjectState::Active,
            1,
            3,
            1,
            &[0xCC]
        ));
        assert!(registry.upsert_instance_object(source, aid(&[0x33]), aid(&[0x44]), &[0xDD]));
        assert!(registry.clone_scp03_keys(source, target));
        assert!(registry.find_key_object(&target, &key).is_some());
        assert!(registry
            .find_instance_object(&target, &aid(&[0x33]))
            .is_none());
    }

    #[test]
    fn upserting_instance_updates_existing_state() {
        let mut registry: ObjectRegistry<8> = ObjectRegistry::new();
        let parent = aid(&[0x10]);
        let instance = aid(&[0x20]);
        let package = aid(&[0x30]);
        assert!(registry.upsert_instance_object(parent, instance, package, &[0xAA]));
        assert!(registry.upsert_instance_object(parent, instance, package, &[0xBB, 0xCC]));
        let stored = registry
            .find_instance_object(&parent, &instance)
            .expect("updated instance");
        assert_eq!(
            stored.serialized_state().expect("instance state"),
            &[0xBB, 0xCC]
        );
    }

    #[test]
    fn upserting_security_domain_preserves_backend_and_privileges() {
        let mut registry: ObjectRegistry<8> = ObjectRegistry::new();
        let parent = aid(&[0x01]);
        let instance = aid(&[0x02]);
        let package = aid(&[0x03]);
        assert!(registry.upsert_security_domain_object(
            parent,
            instance,
            package,
            SecurityDomainObjectBackend::KernelSecurityDomain,
            [0xFF, 0xEE, 0xDD],
            &[0x10, 0x20, 0x30],
        ));
        let stored = registry
            .find_security_domain_object(&parent, &instance)
            .expect("security domain");
        assert_eq!(
            stored.security_domain_backend(),
            Some(SecurityDomainObjectBackend::KernelSecurityDomain)
        );
        let RegistryObjectPayload::SecurityDomain {
            privilege_bytes, ..
        } = stored.payload
        else {
            panic!("expected security domain payload");
        };
        assert_eq!(privilege_bytes, [0xFF, 0xEE, 0xDD]);
        assert_eq!(
            stored.serialized_state().expect("sd state"),
            &[0x10, 0x20, 0x30]
        );
    }

    #[test]
    fn security_domain_and_instance_can_share_same_aid_with_sd_priority() {
        let mut registry: ObjectRegistry<8> = ObjectRegistry::new();
        let parent = aid(&[0x01]);
        let shared = aid(&[0x02]);
        assert!(registry.upsert_security_domain_object(
            parent,
            shared,
            aid(&[0x03]),
            SecurityDomainObjectBackend::NullSecurityDomain,
            [0, 0, 0],
            &[0xAA],
        ));
        assert!(registry.upsert_instance_object(parent, shared, aid(&[0x04]), &[0xBB]));
        let resolved = registry
            .find_any_object(&shared)
            .expect("resolved shared aid");
        assert_eq!(resolved.object_kind, ManagedObjectKind::SecurityDomain);
    }

    #[test]
    fn find_any_object_prefers_security_domain_over_instance_and_package() {
        let mut registry: ObjectRegistry<8> = ObjectRegistry::new();
        let shared = aid(&[0x42]);
        let parent = aid(&[0x01]);
        assert!(registry.insert_package_object(parent, shared, shared, &[0x01]));
        assert!(registry.upsert_instance_object(parent, shared, aid(&[0x02]), &[0x02]));
        let before_sd = registry.find_any_object(&shared).expect("instance chosen");
        assert_eq!(before_sd.object_kind, ManagedObjectKind::Instance);
        assert!(registry.upsert_security_domain_object(
            parent,
            shared,
            aid(&[0x03]),
            SecurityDomainObjectBackend::RustletSecurityDomain,
            [1, 2, 3],
            &[0x03],
        ));
        let resolved = registry.find_any_object(&shared).expect("sd chosen");
        assert_eq!(resolved.object_kind, ManagedObjectKind::SecurityDomain);
    }

    #[test]
    fn oversized_instance_state_is_rejected() {
        let mut registry: ObjectRegistry<4> = ObjectRegistry::new();
        let too_large = [0xAA; rustlet_runtime::STATE_BUFFER_CAPACITY + 1];
        assert!(!registry.upsert_instance_object(
            aid(&[0x01]),
            aid(&[0x02]),
            aid(&[0x03]),
            &too_large,
        ));
    }

    #[test]
    fn oversized_key_payload_is_rejected() {
        let mut registry: ObjectRegistry<4> = ObjectRegistry::new();
        let too_large = [0x55; rustlet_runtime::STATE_BUFFER_CAPACITY + 1];
        assert!(!registry.upsert_key_object(
            aid(&[0x01]),
            aid(&[0x4B]),
            KeyObjectType::Scp03Static,
            KeyObjectState::Active,
            1,
            3,
            1,
            &too_large,
        ));
    }

    #[test]
    fn data_objects_are_parent_qualified() {
        let mut registry: ObjectRegistry<8> = ObjectRegistry::new();
        let object_aid = aid(&[0x44, 0x41, 0x54, 0x41, 0xDF, 0x01]);
        assert!(registry.upsert_data_object(aid(&[0x01]), object_aid, b"one"));
        assert!(registry.upsert_data_object(aid(&[0x02]), object_aid, b"two"));
        let first = registry
            .find_data_object(&aid(&[0x01]), &object_aid)
            .expect("first data object");
        let second = registry
            .find_data_object(&aid(&[0x02]), &object_aid)
            .expect("second data object");
        assert_eq!(first.data_bytes(), Some(b"one".as_slice()));
        assert_eq!(second.data_bytes(), Some(b"two".as_slice()));
    }

    #[test]
    fn data_objects_do_not_shadow_selectable_objects() {
        let mut registry: ObjectRegistry<8> = ObjectRegistry::new();
        let shared = aid(&[0x44, 0x41, 0x54, 0x41, 0xDF, 0x01]);
        assert!(registry.upsert_data_object(aid(&[0x01]), shared, b"data"));
        assert!(registry.insert_package_object(aid(&[0x01]), shared, shared, &[0xCA, 0xFE]));
        let resolved = registry
            .find_any_object(&shared)
            .expect("selectable object wins");
        assert_eq!(resolved.object_kind, ManagedObjectKind::Package);
    }

    #[test]
    fn delete_object_is_parent_qualified_for_keys() {
        let mut registry: ObjectRegistry<8> = ObjectRegistry::new();
        let key = aid(&[0x4B, 0x45, 0x59, 0x01, 0x01, 0x01]);
        assert!(registry.upsert_key_object(
            aid(&[0x01]),
            key,
            KeyObjectType::Scp03Static,
            KeyObjectState::Active,
            1,
            1,
            1,
            &[0xAA]
        ));
        assert!(registry.upsert_key_object(
            aid(&[0x02]),
            key,
            KeyObjectType::Scp03Static,
            KeyObjectState::Active,
            1,
            1,
            1,
            &[0xBB]
        ));

        assert!(registry.delete_object(&aid(&[0x01]), ManagedObjectKind::Key, &key));
        assert!(registry.find_key_object(&aid(&[0x01]), &key).is_none());
        let remaining = registry
            .find_key_object(&aid(&[0x02]), &key)
            .expect("second parent key remains");
        assert_eq!(remaining.key_data().expect("key data").4, &[0xBB]);
    }

    #[test]
    fn delete_object_preserves_other_slots_and_reuses_tombstone() {
        let mut registry: ObjectRegistry<2> = ObjectRegistry::new();
        assert!(registry.insert_package_object(aid(&[]), aid(&[0x01]), aid(&[0x01]), &[0x01]));
        assert!(registry.insert_package_object(aid(&[]), aid(&[0x02]), aid(&[0x02]), &[0x02]));
        assert_eq!(registry.len(), 2);
        let first = registry
            .find_index(&aid(&[]), ManagedObjectKind::Package, &aid(&[0x01]))
            .expect("first index");
        let second = registry
            .find_index(&aid(&[]), ManagedObjectKind::Package, &aid(&[0x02]))
            .expect("second index");

        assert!(registry.delete_object(&aid(&[]), ManagedObjectKind::Package, &aid(&[0x01])));
        assert_eq!(registry.len(), 1);
        assert!(registry.resolve(first).is_none());
        assert!(registry.resolve(second).map(|object| object.object_aid) == Some(aid(&[0x02])));
        assert!(registry.find_any_object(&aid(&[0x01])).is_none());
        assert!(registry.find_any_object(&aid(&[0x02])).is_some());
        assert!(registry.insert_package_object(aid(&[]), aid(&[0x03]), aid(&[0x03]), &[0x03]));
        assert!(registry.find_any_object(&aid(&[0x03])).is_some());
        let replacement = registry
            .find_index(&aid(&[]), ManagedObjectKind::Package, &aid(&[0x03]))
            .expect("replacement index");
        assert_eq!(replacement, first);
    }

    #[test]
    fn capacity_limit_is_enforced() {
        let mut registry: ObjectRegistry<2> = ObjectRegistry::new();
        assert!(registry.insert_package_object(aid(&[]), aid(&[0x01]), aid(&[0x01]), &[0x01]));
        assert!(registry.insert_package_object(aid(&[]), aid(&[0x02]), aid(&[0x02]), &[0x02]));
        assert!(!registry.insert_package_object(aid(&[]), aid(&[0x03]), aid(&[0x03]), &[0x03]));
    }

    #[test]
    fn clear_resets_registry() {
        let mut registry: ObjectRegistry<4> = ObjectRegistry::new();
        assert!(registry.insert_package_object(aid(&[]), aid(&[0x01]), aid(&[0x01]), &[0x01]));
        registry.clear();
        assert!(registry.find_any_object(&aid(&[0x01])).is_none());
        assert!(registry.insert_package_object(aid(&[]), aid(&[0x02]), aid(&[0x02]), &[0x02]));
    }

    #[test]
    fn entries_iterates_live_objects_in_stable_slot_order() {
        let mut registry: ObjectRegistry<4> = ObjectRegistry::new();
        assert!(registry.is_empty());
        assert!(registry.insert_package_object(aid(&[]), aid(&[0x01]), aid(&[0x01]), &[0x01]));
        assert!(registry.upsert_instance_object(aid(&[]), aid(&[0x02]), aid(&[0x01]), &[0xAA]));
        assert_eq!(registry.len(), 2);
        let mut entries = registry.entries();
        assert_eq!(
            entries.next().map(|entry| entry.object_aid.as_slice()),
            Some(&[0x01][..])
        );
        assert_eq!(
            entries.next().map(|entry| entry.object_aid.as_slice()),
            Some(&[0x02][..])
        );
        assert!(entries.next().is_none());
    }

    #[test]
    fn default_kernel_capacity_covers_rustlet_test_all_footprint() {
        let mut registry: ObjectRegistry<DEFAULT_KERNEL_OBJECT_REGISTRY_CAPACITY> =
            ObjectRegistry::new();
        let root = aid(&[]);

        let package_aids = [
            aid(&[0x10]),
            aid(&[0x11]),
            aid(&[0x12]),
            aid(&[0x13]),
            aid(&[0x14]),
            aid(&[0x15]),
            aid(&[0x16]),
            aid(&[0x17]),
            aid(&[0x18]),
            aid(&[0x19]),
            aid(&[0x1A]),
        ];
        for package_aid in package_aids {
            assert!(registry.insert_package_object(root, package_aid, package_aid, &[0xAA]));
        }

        assert!(registry.upsert_security_domain_object(
            root,
            aid(&[0x01]),
            aid(&[0x01]),
            SecurityDomainObjectBackend::NullSecurityDomain,
            [0xFF, 0xFF, 0xFF],
            &[0x03, 0xFF, 0xFF, 0xFF],
        ));

        let instances = [
            (aid(&[0x10]), aid(&[0x10])),
            (aid(&[0x11]), aid(&[0x11])),
            (aid(&[0x12]), aid(&[0x12])),
            (aid(&[0x13]), aid(&[0x13])),
            (aid(&[0x14]), aid(&[0x14])),
            (aid(&[0x14]), aid(&[0x1B])),
            (aid(&[0x15]), aid(&[0x15])),
            (aid(&[0x15]), aid(&[0x1C])),
            (aid(&[0x16]), aid(&[0x16])),
            (aid(&[0x17]), aid(&[0x17])),
            (aid(&[0x18]), aid(&[0x18])),
            (aid(&[0x19]), aid(&[0x19])),
            (aid(&[0x1A]), aid(&[0x1A])),
        ];
        for (package_aid, instance_aid) in instances {
            assert!(registry.upsert_instance_object(root, instance_aid, package_aid, &[0x42]));
        }
    }
}
