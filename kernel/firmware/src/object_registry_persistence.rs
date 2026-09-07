//! Persistent binary format for the kernel object registry.
//!
//! The in-RAM [`crate::object_registry::ObjectRegistry`] remains the structure
//! used by the firmware while it runs. This module defines the append-only
//! flash format used to rebuild that registry after boot and to publish a new
//! committed registry after each mutation.
//!
//! The persistence model is deliberately simple:
//! - data/package/state objects are written first;
//! - a new registry block is written only after all referenced objects exist;
//! - every block ends with a CRC64, so an interrupted write is ignored;
//! - the valid registry block with the highest mutation counter is authoritative.
//!
//! A runtime mutation must stay a single registry delta followed by one BOSS
//! publication. During that publication, the previous BOSS remains the recovery
//! root. Therefore the payload replaced or deleted by that one delta is not
//! recyclable until the new BOSS has been written and validated by its CRC.
//!
//! All multi-byte integers are encoded little-endian. Blocks always start on a
//! flash logical page boundary, and their advertised total size is page-aligned.

use crate::object_registry::{
    InstanceObjectState, KeyObjectState, KeyObjectType, ManagedObjectKind, PackageObjectState,
    RegistryObject, RegistryObjectPayload, SecurityDomainObjectBackend, SecurityDomainObjectState,
};
use rustlet_runtime::Aid;

/// First-page marker used to decide whether the persistence area was already
/// initialized.
///
/// If the first page does not begin with this value, the firmware must treat
/// the registry as unpersonalized and replay the predeployment manifest.
pub const PERSISTENCE_AREA_MAGIC: u64 = 0x600D_B055_600D_B005;

/// Magic word for registry blocks.
///
/// `B055` reads as "BOSS": the latest valid block with this magic is the boss
/// copy of the registry.
pub const REGISTRY_BLOCK_MAGIC: u32 = 0x600D_B055;

/// Magic word for loaded package-code payload blocks.
pub const PACKAGE_BLOCK_MAGIC: u32 = 0x600D_C0DE;

/// Magic word for generic data/key payload blocks.
pub const DATA_BLOCK_MAGIC: u32 = 0x600D_BA5E;

/// Magic word for serialized Rustlet instance-state payload blocks.
pub const INSTANCE_STATE_BLOCK_MAGIC: u32 = 0x600D_FACE;

const COMMON_HEADER_LEN: usize = 8;
const REGISTRY_HEADER_LEN: usize = 16;
const OBJECT_HEADER_LEN: usize = 12;
const CRC_LEN: usize = 8;
const AID_ENCODED_LEN: usize = 17;
const SECURITY_DOMAIN_PAYLOAD_HEADER_LEN: usize = AID_ENCODED_LEN + 1 + 3 + 4;
const INSTANCE_PAYLOAD_HEADER_LEN: usize = AID_ENCODED_LEN + 4;
const KEY_PAYLOAD_HEADER_LEN: usize = 1 + 1 + 1 + 1 + 1 + 4;

/// Errors returned while encoding or scanning persistent registry blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersistenceFormatError {
    InvalidAidLength,
    InvalidKind,
    InvalidPageSize,
    InvalidBlockSize,
    InvalidBlockMagic,
    BufferTooSmall,
    CrcMismatch,
    Truncated,
}

/// Number of bytes before the payload in a persistent object block.
pub const OBJECT_BLOCK_HEADER_LEN: usize = OBJECT_HEADER_LEN;

/// Number of trailing CRC bytes present in every persistent block.
pub const BLOCK_CRC_LEN: usize = CRC_LEN;

/// Returns the page-aligned size of an object block for one payload length.
pub fn object_block_total_len(
    magic: u32,
    payload_len: usize,
    page_size: usize,
) -> Result<usize, PersistenceFormatError> {
    validate_page_size(page_size)?;
    if !is_object_magic(magic) {
        return Err(PersistenceFormatError::InvalidBlockMagic);
    }
    align_up(OBJECT_HEADER_LEN + payload_len + CRC_LEN, page_size)
}

/// Functional family stored in the upper four bits of a persistent kind word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PersistentObjectKind {
    SecurityDomain = 1,
    Package = 2,
    Instance = 3,
    Key = 4,
    Data = 5,
}

impl PersistentObjectKind {
    fn from_nibble(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::SecurityDomain),
            2 => Some(Self::Package),
            3 => Some(Self::Instance),
            4 => Some(Self::Key),
            5 => Some(Self::Data),
            _ => None,
        }
    }
}

/// Encodes an object kind plus twelve bits of kind-specific state.
///
/// The high nibble is the object family. The low twelve bits are intentionally
/// interpreted by that family only: privileges stay in Security Domain payloads,
/// package state belongs to packages, and key flags belong to key objects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PersistentKindWord(u16);

impl PersistentKindWord {
    /// Builds a kind word from one object family and twelve state bits.
    pub const fn new(kind: PersistentObjectKind, state_bits: u16) -> Self {
        // Invariant: callers may pass a wider integer, but only the lower
        // twelve bits are persisted as kind-specific state.
        Self(((kind as u16) << 12) | (state_bits & 0x0FFF))
    }

    /// Decodes one persisted raw kind word.
    pub fn from_raw(raw: u16) -> Result<Self, PersistenceFormatError> {
        if PersistentObjectKind::from_nibble((raw >> 12) as u8).is_none() {
            return Err(PersistenceFormatError::InvalidKind);
        }
        Ok(Self(raw))
    }

    /// Returns the object family encoded in the high nibble.
    pub fn kind(self) -> PersistentObjectKind {
        // Invariant: constructors reject unknown high-nibble values.
        PersistentObjectKind::from_nibble((self.0 >> 12) as u8).unwrap()
    }

    /// Returns the kind-specific state bits encoded in the low twelve bits.
    pub const fn state_bits(self) -> u16 {
        self.0 & 0x0FFF
    }

    /// Returns the little-endian raw value stored in flash.
    pub const fn raw(self) -> u16 {
        self.0
    }
}

/// Persistent AID representation used in registry entries.
///
/// Byte 0 is the AID length. Bytes 1..=16 carry the AID value padded with zeroes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PersistentAid {
    encoded: [u8; AID_ENCODED_LEN],
}

impl PersistentAid {
    pub const EMPTY: Self = Self {
        encoded: [0u8; AID_ENCODED_LEN],
    };

    /// Encodes one runtime AID for persistence.
    pub fn from_aid(aid: &Aid) -> Self {
        let mut encoded = [0u8; AID_ENCODED_LEN];
        encoded[0] = aid.len;
        encoded[1..1 + aid.len as usize].copy_from_slice(aid.as_slice());
        Self { encoded }
    }

    /// Decodes a persistent AID from its exact 17-byte representation.
    pub fn from_encoded(encoded: [u8; AID_ENCODED_LEN]) -> Result<Self, PersistenceFormatError> {
        if encoded[0] > 16 {
            return Err(PersistenceFormatError::InvalidAidLength);
        }
        Ok(Self { encoded })
    }

    /// Returns the exact 17 bytes stored in a persistent registry entry.
    pub const fn encoded(self) -> [u8; AID_ENCODED_LEN] {
        self.encoded
    }

    /// Converts the persistent AID back to the runtime representation.
    pub fn as_aid(self) -> Aid {
        Aid::new(&self.encoded[1..1 + self.encoded[0] as usize])
    }
}

/// Names the persistent address space referenced by one registry entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PersistentSpace {
    /// Object stored in the mutable append-only registry flash area.
    RegistryFlash = 0,
    /// Object embedded in immutable firmware/predeployment memory.
    FirmwareImage = 1,
    /// Object stored in another configured persistent backend.
    External = 2,
}

impl PersistentSpace {
    fn from_byte(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::RegistryFlash),
            1 => Some(Self::FirmwareImage),
            2 => Some(Self::External),
            _ => None,
        }
    }
}

/// Portable reference to the bytes associated with one registry entry.
///
/// The reference deliberately avoids storing a raw pointer. `offset` is
/// interpreted relative to the selected [`PersistentSpace`]. This lets a
/// registry entry refer either to an append-only flash object or to an object
/// predeployed in the firmware image without baking CPU pointer width into the
/// on-flash registry format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PersistentRef {
    pub space: PersistentSpace,
    pub flags: u8,
    pub offset: u32,
}

impl PersistentRef {
    pub const ENCODED_LEN: usize = 8;
    pub const EMPTY: Self = Self {
        space: PersistentSpace::RegistryFlash,
        flags: 0,
        offset: 0,
    };

    /// Creates a new persistent reference.
    pub const fn new(space: PersistentSpace, flags: u8, offset: u32) -> Self {
        Self {
            space,
            flags,
            offset,
        }
    }

    /// Encodes the reference in the fixed registry-entry representation.
    pub fn encode(self, out: &mut [u8]) -> Result<(), PersistenceFormatError> {
        if out.len() < Self::ENCODED_LEN {
            return Err(PersistenceFormatError::BufferTooSmall);
        }
        out[0] = self.space as u8;
        out[1] = self.flags;
        out[2] = 0;
        out[3] = 0;
        write_u32_le(&mut out[4..8], self.offset);
        Ok(())
    }

    /// Decodes a fixed-size persistent reference.
    pub fn decode(input: &[u8]) -> Result<Self, PersistenceFormatError> {
        if input.len() < Self::ENCODED_LEN {
            return Err(PersistenceFormatError::Truncated);
        }
        let Some(space) = PersistentSpace::from_byte(input[0]) else {
            return Err(PersistenceFormatError::InvalidBlockSize);
        };
        Ok(Self {
            space,
            flags: input[1],
            offset: read_u32_le(&input[4..8]),
        })
    }
}

/// One fixed-size entry in a persistent registry block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PersistentRegistryEntry {
    pub object_aid: PersistentAid,
    pub parent_sd_aid: PersistentAid,
    pub kind_word: PersistentKindWord,
    pub data_ref: PersistentRef,
}

impl PersistentRegistryEntry {
    pub const ENCODED_LEN: usize =
        AID_ENCODED_LEN + AID_ENCODED_LEN + 2 + PersistentRef::ENCODED_LEN;
    pub const EMPTY: Self = Self {
        object_aid: PersistentAid::EMPTY,
        parent_sd_aid: PersistentAid::EMPTY,
        kind_word: PersistentKindWord::new(PersistentObjectKind::Package, 0),
        data_ref: PersistentRef::EMPTY,
    };

    /// Encodes one registry entry.
    pub fn encode(self, out: &mut [u8]) -> Result<(), PersistenceFormatError> {
        if out.len() < Self::ENCODED_LEN {
            return Err(PersistenceFormatError::BufferTooSmall);
        }
        out[..AID_ENCODED_LEN].copy_from_slice(&self.object_aid.encoded());
        out[AID_ENCODED_LEN..AID_ENCODED_LEN * 2].copy_from_slice(&self.parent_sd_aid.encoded());
        write_u16_le(
            &mut out[AID_ENCODED_LEN * 2..AID_ENCODED_LEN * 2 + 2],
            self.kind_word.raw(),
        );
        self.data_ref
            .encode(&mut out[AID_ENCODED_LEN * 2 + 2..Self::ENCODED_LEN])?;
        Ok(())
    }

    /// Creates a persistent entry from one live runtime registry object.
    ///
    /// The `data_ref` is supplied by the persistence writer after it has placed
    /// the object payload in the appropriate persistent space. This preserves
    /// the transaction invariant: payload first, registry pointer second.
    pub fn from_registry_object(object: &RegistryObject, data_ref: PersistentRef) -> Self {
        Self {
            object_aid: PersistentAid::from_aid(&object.object_aid),
            parent_sd_aid: PersistentAid::from_aid(&object.parent_sd_aid),
            kind_word: PersistentKindWord::new(
                persistent_kind_from_runtime(object.object_kind),
                persistent_state_from_runtime(object),
            ),
            data_ref,
        }
    }

    /// Decodes one registry entry from its fixed-size representation.
    pub fn decode(input: &[u8]) -> Result<Self, PersistenceFormatError> {
        if input.len() < Self::ENCODED_LEN {
            return Err(PersistenceFormatError::Truncated);
        }
        let object_aid = read_persistent_aid(&input[..AID_ENCODED_LEN])?;
        let parent_sd_aid = read_persistent_aid(&input[AID_ENCODED_LEN..AID_ENCODED_LEN * 2])?;
        let kind_word = PersistentKindWord::from_raw(read_u16_le(&input[AID_ENCODED_LEN * 2..]))?;
        let data_ref = PersistentRef::decode(&input[AID_ENCODED_LEN * 2 + 2..])?;
        Ok(Self {
            object_aid,
            parent_sd_aid,
            kind_word,
            data_ref,
        })
    }
}

fn persistent_kind_from_runtime(kind: ManagedObjectKind) -> PersistentObjectKind {
    match kind {
        ManagedObjectKind::SecurityDomain => PersistentObjectKind::SecurityDomain,
        ManagedObjectKind::Package => PersistentObjectKind::Package,
        ManagedObjectKind::Instance => PersistentObjectKind::Instance,
        ManagedObjectKind::Key => PersistentObjectKind::Key,
        ManagedObjectKind::Data => PersistentObjectKind::Data,
    }
}

fn persistent_state_from_runtime(object: &RegistryObject) -> u16 {
    match object.payload {
        RegistryObjectPayload::SecurityDomain { object_state, .. } => match object_state {
            SecurityDomainObjectState::Selectable => 0,
            SecurityDomainObjectState::Locked => 1,
        },
        RegistryObjectPayload::Package { package_state, .. } => match package_state {
            PackageObjectState::Loaded => 0,
            PackageObjectState::Locked => 1,
        },
        RegistryObjectPayload::Instance { instance_state, .. } => match instance_state {
            InstanceObjectState::Selectable => 0,
            InstanceObjectState::Locked => 1,
        },
        RegistryObjectPayload::Key { key_state, .. } => match key_state {
            KeyObjectState::Active => 0,
            KeyObjectState::Locked => 1,
        },
        RegistryObjectPayload::Data { .. } => 0,
    }
}

pub fn decode_package_state(value: u16) -> Result<PackageObjectState, PersistenceFormatError> {
    match value {
        0 => Ok(PackageObjectState::Loaded),
        1 => Ok(PackageObjectState::Locked),
        _ => Err(PersistenceFormatError::InvalidKind),
    }
}

pub fn decode_instance_state(value: u16) -> Result<InstanceObjectState, PersistenceFormatError> {
    match value {
        0 => Ok(InstanceObjectState::Selectable),
        1 => Ok(InstanceObjectState::Locked),
        _ => Err(PersistenceFormatError::InvalidKind),
    }
}

pub fn decode_security_domain_state(
    value: u16,
) -> Result<SecurityDomainObjectState, PersistenceFormatError> {
    match value {
        0 => Ok(SecurityDomainObjectState::Selectable),
        1 => Ok(SecurityDomainObjectState::Locked),
        _ => Err(PersistenceFormatError::InvalidKind),
    }
}

/// Lightweight view of one valid registry block discovered in flash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegistryBlockView<'a> {
    pub offset: usize,
    pub total_len: usize,
    pub mutation_counter: u32,
    pub entry_count: u32,
    entries: &'a [u8],
}

impl<'a> RegistryBlockView<'a> {
    /// Decodes the `index`-th registry entry without allocating.
    pub fn entry(&self, index: usize) -> Result<PersistentRegistryEntry, PersistenceFormatError> {
        if index >= self.entry_count as usize {
            return Err(PersistenceFormatError::Truncated);
        }
        let start = index * PersistentRegistryEntry::ENCODED_LEN;
        let end = start + PersistentRegistryEntry::ENCODED_LEN;
        PersistentRegistryEntry::decode(&self.entries[start..end])
    }
}

/// Lightweight view of one valid object payload block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectBlockView<'a> {
    pub offset: usize,
    pub magic: u32,
    pub total_len: usize,
    pub payload: &'a [u8],
}

/// Zero-copy view of one persisted Security Domain payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PersistentSecurityDomainPayload<'a> {
    pub package_aid: PersistentAid,
    pub backend: SecurityDomainObjectBackend,
    pub privilege_bytes: [u8; 3],
    pub serialized_state: &'a [u8],
}

/// Zero-copy view of one persisted Rustlet instance payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PersistentInstancePayload<'a> {
    pub package_aid: PersistentAid,
    pub serialized_state: &'a [u8],
}

/// Zero-copy view of one persisted key payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PersistentKeyPayload<'a> {
    pub key_type: KeyObjectType,
    pub key_state: KeyObjectState,
    pub key_version: u8,
    pub key_id: u8,
    pub key_usage: u8,
    pub raw_key_bytes: &'a [u8],
}

/// Zero-copy view of one persisted generic data payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PersistentDataPayload<'a> {
    pub bytes: &'a [u8],
}

/// Summary produced by a linear scan of the mutable persistence area.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PersistenceAreaScan<'a> {
    /// Latest valid registry block, if one was found.
    pub latest_registry: Option<RegistryBlockView<'a>>,
    /// First page-aligned erased offset discovered during the full-area scan.
    ///
    /// If no erased page is found, this is `area.len()`. The future allocator
    /// may still recycle older unreferenced blocks, but an erased page is the
    /// simplest append candidate.
    pub append_offset: usize,
}

/// Page-aligned range occupied by one persistent block.
///
/// The allocator uses protected ranges to avoid recycling the latest registry
/// and objects still referenced by that registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PersistentRange {
    pub offset: usize,
    pub total_len: usize,
}

impl PersistentRange {
    pub const EMPTY: Self = Self {
        offset: 0,
        total_len: 0,
    };

    /// Creates one range from a page-aligned offset and page-aligned length.
    pub const fn new(offset: usize, total_len: usize) -> Self {
        Self { offset, total_len }
    }

    fn overlaps(self, other: Self) -> bool {
        let self_end = self.offset.saturating_add(self.total_len);
        let other_end = other.offset.saturating_add(other.total_len);
        self.offset < other_end && other.offset < self_end
    }
}

/// Page-aligned allocation returned by the persistent log scanner.
///
/// If `erase_len` is zero, `offset..offset+total_len` is already erased page
/// space. Otherwise the caller must erase `erase_offset..erase_offset+erase_len`
/// sector by sector before programming the first page at `offset`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReusableSpan {
    pub offset: usize,
    pub total_len: usize,
    pub erase_offset: usize,
    pub erase_len: usize,
}

impl ReusableSpan {
    pub const EMPTY: Self = Self {
        offset: 0,
        total_len: 0,
        erase_offset: 0,
        erase_len: 0,
    };

    const fn erased(offset: usize, total_len: usize) -> Self {
        Self {
            offset,
            total_len,
            erase_offset: 0,
            erase_len: 0,
        }
    }

    const fn recycled_sector(offset: usize, total_len: usize, erase_len: usize) -> Self {
        Self {
            offset,
            total_len,
            erase_offset: offset,
            erase_len,
        }
    }

    /// Returns true when the caller must erase sectors before writing.
    pub const fn needs_erase(self) -> bool {
        self.erase_len != 0
    }
}

/// Returns true when the first page carries the persistence-area marker.
pub fn has_persistence_area_marker(area: &[u8]) -> bool {
    area.len() >= 8 && read_u64_le(&area[..8]) == PERSISTENCE_AREA_MAGIC
}

/// Writes the persistence-area marker at the beginning of a page buffer.
pub fn write_persistence_area_marker(page: &mut [u8]) -> Result<(), PersistenceFormatError> {
    if page.len() < 8 {
        return Err(PersistenceFormatError::BufferTooSmall);
    }
    write_u64_le(&mut page[..8], PERSISTENCE_AREA_MAGIC);
    Ok(())
}

/// Encodes a complete registry block into `out`.
///
/// Returns the page-aligned number of bytes that must be written to flash.
pub fn encode_registry_block(
    mutation_counter: u32,
    entries: &[PersistentRegistryEntry],
    page_size: usize,
    out: &mut [u8],
) -> Result<usize, PersistenceFormatError> {
    validate_page_size(page_size)?;
    let payload_len = entries
        .len()
        .checked_mul(PersistentRegistryEntry::ENCODED_LEN)
        .ok_or(PersistenceFormatError::InvalidBlockSize)?;
    let required = align_up(REGISTRY_HEADER_LEN + payload_len + CRC_LEN, page_size)?;
    if out.len() < required {
        return Err(PersistenceFormatError::BufferTooSmall);
    }
    // Invariant: unwritten padding must match erased flash so that a partial
    // page image can be reasoned about exactly like physical flash contents.
    fill_erased(&mut out[..required]);
    write_u32_le(&mut out[0..4], REGISTRY_BLOCK_MAGIC);
    write_u32_le(&mut out[4..8], required as u32);
    write_u32_le(&mut out[8..12], mutation_counter);
    write_u32_le(&mut out[12..16], entries.len() as u32);
    let mut cursor = REGISTRY_HEADER_LEN;
    for entry in entries {
        entry.encode(&mut out[cursor..cursor + PersistentRegistryEntry::ENCODED_LEN])?;
        cursor += PersistentRegistryEntry::ENCODED_LEN;
    }
    write_final_crc(&mut out[..required]);
    Ok(required)
}

/// Encodes a package, data/key or serialized-state payload block into `out`.
///
/// Returns the page-aligned number of bytes that must be written to flash.
pub fn encode_object_block(
    magic: u32,
    payload: &[u8],
    page_size: usize,
    out: &mut [u8],
) -> Result<usize, PersistenceFormatError> {
    validate_page_size(page_size)?;
    if !is_object_magic(magic) {
        return Err(PersistenceFormatError::InvalidBlockMagic);
    }
    let required = align_up(OBJECT_HEADER_LEN + payload.len() + CRC_LEN, page_size)?;
    if out.len() < required {
        return Err(PersistenceFormatError::BufferTooSmall);
    }
    fill_erased(&mut out[..required]);
    write_u32_le(&mut out[0..4], magic);
    write_u32_le(&mut out[4..8], required as u32);
    write_u32_le(&mut out[8..12], payload.len() as u32);
    out[OBJECT_HEADER_LEN..OBJECT_HEADER_LEN + payload.len()].copy_from_slice(payload);
    write_final_crc(&mut out[..required]);
    Ok(required)
}

/// Encodes the kind-specific payload of one runtime registry object.
///
/// The returned magic identifies the persistent block family that must wrap the
/// bytes written into `out`. Registry entries then point to that block through
/// a [`PersistentRef`].
pub fn encode_registry_object_payload(
    object: &RegistryObject,
    out: &mut [u8],
) -> Result<(u32, usize), PersistenceFormatError> {
    match object.payload {
        RegistryObjectPayload::SecurityDomain {
            package_aid,
            backend,
            privilege_bytes,
            ref serialized_state,
            serialized_state_len,
            ..
        } => {
            let required = SECURITY_DOMAIN_PAYLOAD_HEADER_LEN + serialized_state_len;
            if out.len() < required {
                return Err(PersistenceFormatError::BufferTooSmall);
            }
            out[..AID_ENCODED_LEN]
                .copy_from_slice(&PersistentAid::from_aid(&package_aid).encoded());
            out[AID_ENCODED_LEN] = encode_security_domain_backend(backend);
            out[AID_ENCODED_LEN + 1..AID_ENCODED_LEN + 4].copy_from_slice(&privilege_bytes);
            write_u32_le(
                &mut out[AID_ENCODED_LEN + 4..AID_ENCODED_LEN + 8],
                serialized_state_len as u32,
            );
            out[SECURITY_DOMAIN_PAYLOAD_HEADER_LEN..required]
                .copy_from_slice(&serialized_state[..serialized_state_len]);
            Ok((INSTANCE_STATE_BLOCK_MAGIC, required))
        }
        RegistryObjectPayload::Package { binary_code, .. } => {
            if out.len() < binary_code.len() {
                return Err(PersistenceFormatError::BufferTooSmall);
            }
            out[..binary_code.len()].copy_from_slice(binary_code);
            Ok((PACKAGE_BLOCK_MAGIC, binary_code.len()))
        }
        RegistryObjectPayload::Instance {
            package_aid,
            ref serialized_state,
            serialized_state_len,
            ..
        } => {
            let required = INSTANCE_PAYLOAD_HEADER_LEN + serialized_state_len;
            if out.len() < required {
                return Err(PersistenceFormatError::BufferTooSmall);
            }
            out[..AID_ENCODED_LEN]
                .copy_from_slice(&PersistentAid::from_aid(&package_aid).encoded());
            write_u32_le(
                &mut out[AID_ENCODED_LEN..AID_ENCODED_LEN + 4],
                serialized_state_len as u32,
            );
            out[INSTANCE_PAYLOAD_HEADER_LEN..required]
                .copy_from_slice(&serialized_state[..serialized_state_len]);
            Ok((INSTANCE_STATE_BLOCK_MAGIC, required))
        }
        RegistryObjectPayload::Key {
            key_type,
            key_state,
            key_version,
            key_id,
            key_usage,
            ref raw_key_bytes,
            raw_key_len,
        } => {
            let required = KEY_PAYLOAD_HEADER_LEN + raw_key_len;
            if out.len() < required {
                return Err(PersistenceFormatError::BufferTooSmall);
            }
            out[0] = encode_key_type(key_type);
            out[1] = encode_key_state(key_state);
            out[2] = key_version;
            out[3] = key_id;
            out[4] = key_usage;
            write_u32_le(&mut out[5..9], raw_key_len as u32);
            out[KEY_PAYLOAD_HEADER_LEN..required].copy_from_slice(&raw_key_bytes[..raw_key_len]);
            Ok((DATA_BLOCK_MAGIC, required))
        }
        RegistryObjectPayload::Data { ref bytes, len } => {
            if out.len() < len {
                return Err(PersistenceFormatError::BufferTooSmall);
            }
            out[..len].copy_from_slice(&bytes[..len]);
            Ok((DATA_BLOCK_MAGIC, len))
        }
    }
}

/// Decodes bytes previously produced for a Security Domain registry object.
pub fn decode_security_domain_payload(
    input: &[u8],
) -> Result<PersistentSecurityDomainPayload<'_>, PersistenceFormatError> {
    if input.len() < SECURITY_DOMAIN_PAYLOAD_HEADER_LEN {
        return Err(PersistenceFormatError::Truncated);
    }
    let package_aid = read_persistent_aid(&input[..AID_ENCODED_LEN])?;
    let backend = decode_security_domain_backend(input[AID_ENCODED_LEN])?;
    let mut privilege_bytes = [0u8; 3];
    privilege_bytes.copy_from_slice(&input[AID_ENCODED_LEN + 1..AID_ENCODED_LEN + 4]);
    let state_len = read_u32_le(&input[AID_ENCODED_LEN + 4..AID_ENCODED_LEN + 8]) as usize;
    let state_start = SECURITY_DOMAIN_PAYLOAD_HEADER_LEN;
    let state_end = state_start + state_len;
    if state_end > input.len() {
        return Err(PersistenceFormatError::Truncated);
    }
    Ok(PersistentSecurityDomainPayload {
        package_aid,
        backend,
        privilege_bytes,
        serialized_state: &input[state_start..state_end],
    })
}

/// Decodes bytes previously produced for a Rustlet instance registry object.
pub fn decode_instance_payload(
    input: &[u8],
) -> Result<PersistentInstancePayload<'_>, PersistenceFormatError> {
    if input.len() < INSTANCE_PAYLOAD_HEADER_LEN {
        return Err(PersistenceFormatError::Truncated);
    }
    let package_aid = read_persistent_aid(&input[..AID_ENCODED_LEN])?;
    let state_len = read_u32_le(&input[AID_ENCODED_LEN..AID_ENCODED_LEN + 4]) as usize;
    let state_start = INSTANCE_PAYLOAD_HEADER_LEN;
    let state_end = state_start + state_len;
    if state_end > input.len() {
        return Err(PersistenceFormatError::Truncated);
    }
    Ok(PersistentInstancePayload {
        package_aid,
        serialized_state: &input[state_start..state_end],
    })
}

/// Decodes bytes previously produced for a key registry object.
pub fn decode_key_payload(
    input: &[u8],
) -> Result<PersistentKeyPayload<'_>, PersistenceFormatError> {
    if input.len() < KEY_PAYLOAD_HEADER_LEN {
        return Err(PersistenceFormatError::Truncated);
    }
    let key_type = decode_key_type(input[0])?;
    let key_state = decode_key_state(input[1])?;
    let raw_key_len = read_u32_le(&input[5..9]) as usize;
    let raw_key_start = KEY_PAYLOAD_HEADER_LEN;
    let raw_key_end = raw_key_start + raw_key_len;
    if raw_key_end > input.len() {
        return Err(PersistenceFormatError::Truncated);
    }
    Ok(PersistentKeyPayload {
        key_type,
        key_state,
        key_version: input[2],
        key_id: input[3],
        key_usage: input[4],
        raw_key_bytes: &input[raw_key_start..raw_key_end],
    })
}

/// Decodes bytes previously produced for a generic data registry object.
pub fn decode_data_payload(
    input: &[u8],
) -> Result<PersistentDataPayload<'_>, PersistenceFormatError> {
    Ok(PersistentDataPayload { bytes: input })
}

/// Scans one persistence area and returns the latest valid registry block.
pub fn find_latest_registry_block<'a>(
    area: &'a [u8],
    page_size: usize,
) -> Result<Option<RegistryBlockView<'a>>, PersistenceFormatError> {
    Ok(scan_persistence_area(area, page_size)?.latest_registry)
}

/// Scans the mutable persistence area from its first page.
///
/// The scan always walks the complete circular buffer. Erased pages are valid
/// empty pages, not end markers. Corrupted pages are skipped so that recovery
/// can still find an older valid registry elsewhere in the area.
pub fn scan_persistence_area<'a>(
    area: &'a [u8],
    page_size: usize,
) -> Result<PersistenceAreaScan<'a>, PersistenceFormatError> {
    validate_page_size(page_size)?;
    let mut latest = None;
    let mut first_erased = None;
    let mut offset = 0usize;
    while offset + COMMON_HEADER_LEN <= area.len() {
        if is_erased_page_prefix(&area[offset..]) {
            if first_erased.is_none() {
                first_erased = Some(offset);
            }
            // Invariant: an erased page marks free space in the circular log,
            // but later pages may still contain older valid blocks after wrap.
            offset += page_size;
            continue;
        }
        let magic = read_u32_le(&area[offset..offset + 4]);
        if magic == REGISTRY_BLOCK_MAGIC {
            match decode_registry_block_at(area, offset, page_size) {
                Ok(block) => {
                    if latest
                        .map(|current: RegistryBlockView<'a>| {
                            block.mutation_counter > current.mutation_counter
                        })
                        .unwrap_or(true)
                    {
                        latest = Some(block);
                    }
                    offset += block.total_len;
                }
                Err(_) => {
                    // Invariant: a malformed block must not stop recovery.
                    // Power may have failed mid-write, so the scanner advances
                    // one page and keeps looking for another valid BOSS block.
                    offset += page_size;
                }
            }
            continue;
        }
        if is_object_magic(magic) {
            match decode_object_block_at(area, offset, page_size) {
                Ok(block) => offset += block.total_len,
                Err(_) => offset += page_size,
            }
            continue;
        }
        offset += page_size;
    }
    Ok(PersistenceAreaScan {
        latest_registry: latest,
        append_offset: first_erased.unwrap_or(area.len()),
    })
}

/// Finds a page-aligned span that can hold a new persistent block.
///
/// The search accepts two kinds of reusable space:
/// - contiguous erased pages;
/// - complete erase sectors that do not overlap any protected range.
///
/// This keeps the circular flash journal compact while preserving the core
/// transaction invariant: the caller must never pass the latest registry nor
/// the payload blocks referenced by it as recyclable ranges.
pub fn find_reusable_span(
    area: &[u8],
    page_size: usize,
    erase_sector_size: usize,
    required_len: usize,
    protected: &[PersistentRange],
) -> Result<Option<ReusableSpan>, PersistenceFormatError> {
    validate_page_size(page_size)?;
    validate_erase_sector_size(page_size, erase_sector_size)?;
    let required = align_up(required_len, page_size)?;
    let mut offset = 0usize;
    while offset + page_size <= area.len() {
        let erased_candidate = PersistentRange::new(offset, required);
        if erased_span_is_at_least(&area[offset..], page_size, required)
            && !protected
                .iter()
                .any(|range| range.overlaps(erased_candidate))
        {
            return Ok(Some(ReusableSpan::erased(offset, required)));
        }

        let Some((_magic, total_len)) = recognized_block_header(area, offset, page_size) else {
            offset += page_size;
            continue;
        };
        offset += total_len.max(page_size);
    }

    // Invariant: programming happens at page granularity, but non-erased flash
    // can only be reclaimed by erasing full sectors. A sector is recyclable
    // exactly when it does not overlap the latest valid BOSS graph supplied in
    // `protected`; after erase, any unused trailing pages naturally become
    // discoverable as 0xFF erased pages.
    let erase_len = align_up(required, erase_sector_size)?;
    let mut sector_offset = 0usize;
    while sector_offset + erase_len <= area.len() {
        let candidate = PersistentRange::new(sector_offset, erase_len);
        if sector_offset.is_multiple_of(erase_sector_size)
            && !protected.iter().any(|range| range.overlaps(candidate))
        {
            return Ok(Some(ReusableSpan::recycled_sector(
                sector_offset,
                required,
                erase_len,
            )));
        }
        sector_offset += erase_sector_size;
    }
    Ok(None)
}

/// Tries to reserve erased pages at one exact append cursor.
///
/// This is the nominal allocation path after boot: the caller keeps the cursor
/// in RAM and avoids rediscovering the same append position by scanning the
/// complete flash area for every block. Returning `None` asks the caller to run
/// the slower circular-GC search.
pub fn erased_span_at(
    area: &[u8],
    page_size: usize,
    required_len: usize,
    offset: usize,
    protected: &[PersistentRange],
) -> Result<Option<ReusableSpan>, PersistenceFormatError> {
    validate_page_size(page_size)?;
    let required = align_up(required_len, page_size)?;
    let Some(end) = offset.checked_add(required) else {
        return Ok(None);
    };
    if !offset.is_multiple_of(page_size) || end > area.len() {
        return Ok(None);
    }
    let candidate = PersistentRange::new(offset, required);
    if protected.iter().any(|range| range.overlaps(candidate))
        || !erased_span_is_at_least(&area[offset..], page_size, required)
    {
        return Ok(None);
    }
    Ok(Some(ReusableSpan::erased(offset, required)))
}

/// Decodes a registry block at one exact page-aligned offset.
pub fn decode_registry_block_at<'a>(
    area: &'a [u8],
    offset: usize,
    page_size: usize,
) -> Result<RegistryBlockView<'a>, PersistenceFormatError> {
    validate_page_size(page_size)?;
    validate_offset(offset, page_size)?;
    let block = checked_block(area, offset, page_size, REGISTRY_BLOCK_MAGIC)?;
    if block.len() < REGISTRY_HEADER_LEN + CRC_LEN {
        return Err(PersistenceFormatError::InvalidBlockSize);
    }
    verify_final_crc(block)?;
    let mutation_counter = read_u32_le(&block[8..12]);
    let entry_count = read_u32_le(&block[12..16]);
    let entries_len = (entry_count as usize)
        .checked_mul(PersistentRegistryEntry::ENCODED_LEN)
        .ok_or(PersistenceFormatError::InvalidBlockSize)?;
    let entries_end = REGISTRY_HEADER_LEN + entries_len;
    if entries_end + CRC_LEN > block.len() {
        return Err(PersistenceFormatError::InvalidBlockSize);
    }
    Ok(RegistryBlockView {
        offset,
        total_len: block.len(),
        mutation_counter,
        entry_count,
        entries: &block[REGISTRY_HEADER_LEN..entries_end],
    })
}

/// Decodes an object payload block at one exact page-aligned offset.
pub fn decode_object_block_at<'a>(
    area: &'a [u8],
    offset: usize,
    page_size: usize,
) -> Result<ObjectBlockView<'a>, PersistenceFormatError> {
    validate_page_size(page_size)?;
    validate_offset(offset, page_size)?;
    if offset + COMMON_HEADER_LEN > area.len() {
        return Err(PersistenceFormatError::Truncated);
    }
    let magic = read_u32_le(&area[offset..offset + 4]);
    if !is_object_magic(magic) {
        return Err(PersistenceFormatError::InvalidBlockMagic);
    }
    let block = checked_block(area, offset, page_size, magic)?;
    if block.len() < OBJECT_HEADER_LEN + CRC_LEN {
        return Err(PersistenceFormatError::InvalidBlockSize);
    }
    verify_final_crc(block)?;
    let payload_len = read_u32_le(&block[8..12]) as usize;
    if OBJECT_HEADER_LEN + payload_len + CRC_LEN > block.len() {
        return Err(PersistenceFormatError::InvalidBlockSize);
    }
    Ok(ObjectBlockView {
        offset,
        magic,
        total_len: block.len(),
        payload: &block[OBJECT_HEADER_LEN..OBJECT_HEADER_LEN + payload_len],
    })
}

/// Computes the CRC64 used by every persistent block.
///
/// This is CRC-64/ECMA-182 in its straightforward bitwise form. It is slower
/// than a table-based implementation, but keeps the firmware image small and
/// avoids another static table in the kernel.
#[cfg_attr(
    all(not(test), oxide_se_board_raspi_pico),
    unsafe(link_section = ".critical.kernel.fct")
)]
pub fn crc64_ecma(bytes: &[u8]) -> u64 {
    crc64_ecma_extend(0, bytes)
}

/// Extends an in-progress CRC64/ECMA-182 value with additional bytes.
#[cfg_attr(
    all(not(test), oxide_se_board_raspi_pico),
    unsafe(link_section = ".critical.kernel.fct")
)]
pub fn crc64_ecma_extend(mut crc: u64, bytes: &[u8]) -> u64 {
    const POLY: u64 = 0x42F0_E1EB_A9EA_3693;
    for byte in bytes {
        crc ^= (*byte as u64) << 56;
        let mut bit = 0;
        while bit < 8 {
            crc = if (crc & 0x8000_0000_0000_0000) != 0 {
                (crc << 1) ^ POLY
            } else {
                crc << 1
            };
            bit += 1;
        }
    }
    crc
}

fn checked_block(
    area: &[u8],
    offset: usize,
    page_size: usize,
    expected_magic: u32,
) -> Result<&[u8], PersistenceFormatError> {
    if offset + COMMON_HEADER_LEN > area.len() {
        return Err(PersistenceFormatError::Truncated);
    }
    let magic = read_u32_le(&area[offset..offset + 4]);
    if magic != expected_magic {
        return Err(PersistenceFormatError::InvalidBlockMagic);
    }
    let total_len = read_u32_le(&area[offset + 4..offset + 8]) as usize;
    if total_len < COMMON_HEADER_LEN + CRC_LEN || !total_len.is_multiple_of(page_size) {
        return Err(PersistenceFormatError::InvalidBlockSize);
    }
    if offset + total_len > area.len() {
        return Err(PersistenceFormatError::Truncated);
    }
    Ok(&area[offset..offset + total_len])
}

fn recognized_block_header(area: &[u8], offset: usize, page_size: usize) -> Option<(u32, usize)> {
    if offset + COMMON_HEADER_LEN > area.len() {
        return None;
    }
    let magic = read_u32_le(&area[offset..offset + 4]);
    if magic != REGISTRY_BLOCK_MAGIC && !is_object_magic(magic) {
        return None;
    }
    let total_len = read_u32_le(&area[offset + 4..offset + 8]) as usize;
    if total_len < COMMON_HEADER_LEN + CRC_LEN || !total_len.is_multiple_of(page_size) {
        return None;
    }
    if offset + total_len > area.len() {
        return None;
    }
    Some((magic, total_len))
}

fn block_crc_is_valid(area: &[u8], offset: usize, page_size: usize, magic: u32) -> bool {
    if magic == REGISTRY_BLOCK_MAGIC {
        decode_registry_block_at(area, offset, page_size).is_ok()
    } else {
        decode_object_block_at(area, offset, page_size).is_ok()
    }
}

fn verify_final_crc(block: &[u8]) -> Result<(), PersistenceFormatError> {
    if block.len() < CRC_LEN {
        return Err(PersistenceFormatError::Truncated);
    }
    let expected = read_u64_le(&block[block.len() - CRC_LEN..]);
    let actual = crc64_ecma(&block[..block.len() - CRC_LEN]);
    if expected != actual {
        return Err(PersistenceFormatError::CrcMismatch);
    }
    Ok(())
}

#[cfg_attr(
    all(not(test), oxide_se_board_raspi_pico),
    unsafe(link_section = ".critical.kernel.fct")
)]
fn write_final_crc(block: &mut [u8]) {
    let crc_offset = block.len() - CRC_LEN;
    let crc = crc64_ecma(&block[..crc_offset]);
    write_u64_le(&mut block[crc_offset..], crc);
}

fn read_persistent_aid(input: &[u8]) -> Result<PersistentAid, PersistenceFormatError> {
    if input.len() < AID_ENCODED_LEN {
        return Err(PersistenceFormatError::Truncated);
    }
    let mut encoded = [0u8; AID_ENCODED_LEN];
    encoded.copy_from_slice(&input[..AID_ENCODED_LEN]);
    PersistentAid::from_encoded(encoded)
}

fn validate_page_size(page_size: usize) -> Result<(), PersistenceFormatError> {
    if page_size == 0 || !page_size.is_power_of_two() {
        return Err(PersistenceFormatError::InvalidPageSize);
    }
    Ok(())
}

fn validate_erase_sector_size(
    page_size: usize,
    erase_sector_size: usize,
) -> Result<(), PersistenceFormatError> {
    validate_page_size(erase_sector_size)?;
    if erase_sector_size < page_size || !erase_sector_size.is_multiple_of(page_size) {
        return Err(PersistenceFormatError::InvalidPageSize);
    }
    Ok(())
}

fn validate_offset(offset: usize, page_size: usize) -> Result<(), PersistenceFormatError> {
    if !offset.is_multiple_of(page_size) {
        return Err(PersistenceFormatError::InvalidBlockSize);
    }
    Ok(())
}

fn align_up(value: usize, align: usize) -> Result<usize, PersistenceFormatError> {
    validate_page_size(align)?;
    value
        .checked_add(align - 1)
        .map(|v| v & !(align - 1))
        .ok_or(PersistenceFormatError::InvalidBlockSize)
}

fn is_object_magic(magic: u32) -> bool {
    magic == PACKAGE_BLOCK_MAGIC || magic == DATA_BLOCK_MAGIC || magic == INSTANCE_STATE_BLOCK_MAGIC
}

fn is_erased_page_prefix(input: &[u8]) -> bool {
    input.len() < COMMON_HEADER_LEN || input[..COMMON_HEADER_LEN].iter().all(|byte| *byte == 0xFF)
}

fn erased_span_is_at_least(input: &[u8], page_size: usize, required: usize) -> bool {
    let mut total = 0usize;
    while total < required && total + page_size <= input.len() {
        let page = &input[total..total + page_size];
        if !page.iter().all(|byte| *byte == 0xFF) {
            return false;
        }
        total += page_size;
    }
    total >= required
}

fn encode_security_domain_backend(backend: SecurityDomainObjectBackend) -> u8 {
    match backend {
        SecurityDomainObjectBackend::NullSecurityDomain => 0,
        SecurityDomainObjectBackend::KernelSecurityDomain => 1,
        SecurityDomainObjectBackend::RustletSecurityDomain => 2,
    }
}

fn decode_security_domain_backend(
    value: u8,
) -> Result<SecurityDomainObjectBackend, PersistenceFormatError> {
    match value {
        0 => Ok(SecurityDomainObjectBackend::NullSecurityDomain),
        1 => Ok(SecurityDomainObjectBackend::KernelSecurityDomain),
        2 => Ok(SecurityDomainObjectBackend::RustletSecurityDomain),
        _ => Err(PersistenceFormatError::InvalidKind),
    }
}

fn encode_key_type(key_type: KeyObjectType) -> u8 {
    match key_type {
        KeyObjectType::Scp03Static => 0,
        KeyObjectType::Scp11SdEckaPrivate => 1,
        KeyObjectType::Scp11CaKlocPublic => 2,
    }
}

fn encode_key_state(key_state: KeyObjectState) -> u8 {
    match key_state {
        KeyObjectState::Active => 0,
        KeyObjectState::Locked => 1,
    }
}

fn decode_key_type(value: u8) -> Result<KeyObjectType, PersistenceFormatError> {
    match value {
        0 => Ok(KeyObjectType::Scp03Static),
        1 => Ok(KeyObjectType::Scp11SdEckaPrivate),
        2 => Ok(KeyObjectType::Scp11CaKlocPublic),
        _ => Err(PersistenceFormatError::InvalidKind),
    }
}

fn decode_key_state(value: u8) -> Result<KeyObjectState, PersistenceFormatError> {
    match value {
        0 => Ok(KeyObjectState::Active),
        1 => Ok(KeyObjectState::Locked),
        _ => Err(PersistenceFormatError::InvalidKind),
    }
}

fn fill_erased(out: &mut [u8]) {
    for byte in out {
        *byte = 0xFF;
    }
}

fn read_u16_le(input: &[u8]) -> u16 {
    u16::from_le_bytes([input[0], input[1]])
}

fn read_u32_le(input: &[u8]) -> u32 {
    u32::from_le_bytes([input[0], input[1], input[2], input[3]])
}

fn read_u64_le(input: &[u8]) -> u64 {
    u64::from_le_bytes([
        input[0], input[1], input[2], input[3], input[4], input[5], input[6], input[7],
    ])
}

fn write_u16_le(out: &mut [u8], value: u16) {
    out[..2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32_le(out: &mut [u8], value: u32) {
    out[..4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64_le(out: &mut [u8], value: u64) {
    out[..8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object_registry::ObjectRegistry;
    use std::vec;

    const PAGE: usize = 64;
    const SECTOR: usize = PAGE * 4;

    fn aid(bytes: &[u8]) -> Aid {
        Aid::new(bytes)
    }

    fn entry(object: &[u8], parent: &[u8], kind: PersistentObjectKind) -> PersistentRegistryEntry {
        PersistentRegistryEntry {
            object_aid: PersistentAid::from_aid(&aid(object)),
            parent_sd_aid: PersistentAid::from_aid(&aid(parent)),
            kind_word: PersistentKindWord::new(kind, 0x123),
            data_ref: PersistentRef::new(PersistentSpace::RegistryFlash, 0, 0x40),
        }
    }

    #[test]
    fn persistent_aid_is_length_prefixed_and_roundtrips() {
        let runtime = aid(&[0xA0, 0x00, 0x00, 0x01]);
        let persistent = PersistentAid::from_aid(&runtime);
        let encoded = persistent.encoded();
        assert_eq!(encoded[0], 4);
        assert_eq!(&encoded[1..5], runtime.as_slice());
        assert_eq!(persistent.as_aid().as_slice(), runtime.as_slice());
    }

    #[test]
    fn persistent_aid_rejects_invalid_length() {
        let mut encoded = [0u8; AID_ENCODED_LEN];
        encoded[0] = 17;
        assert_eq!(
            PersistentAid::from_encoded(encoded),
            Err(PersistenceFormatError::InvalidAidLength)
        );
    }

    #[test]
    fn kind_word_splits_family_and_state_bits() {
        let kind = PersistentKindWord::new(PersistentObjectKind::SecurityDomain, 0xFABC);
        assert_eq!(kind.kind(), PersistentObjectKind::SecurityDomain);
        assert_eq!(kind.state_bits(), 0x0ABC);
        assert_eq!(
            PersistentKindWord::from_raw(0x0123),
            Err(PersistenceFormatError::InvalidKind)
        );
    }

    #[test]
    fn persistent_ref_roundtrips_without_raw_pointer_semantics() {
        let reference = PersistentRef::new(PersistentSpace::FirmwareImage, 0xA5, 0x0102_0304);
        let mut encoded = [0u8; PersistentRef::ENCODED_LEN];
        reference.encode(&mut encoded).unwrap();
        assert_eq!(PersistentRef::decode(&encoded), Ok(reference));
    }

    #[test]
    fn persistence_area_marker_is_explicit() {
        let mut page = [0xFFu8; PAGE];
        assert!(!has_persistence_area_marker(&page));
        write_persistence_area_marker(&mut page).unwrap();
        assert!(has_persistence_area_marker(&page));
    }

    #[test]
    fn registry_entry_roundtrips() {
        let original = entry(&[0x10], &[0x01], PersistentObjectKind::Instance);
        let mut encoded = [0u8; PersistentRegistryEntry::ENCODED_LEN];
        original.encode(&mut encoded).unwrap();
        assert_eq!(PersistentRegistryEntry::decode(&encoded), Ok(original));
    }

    #[test]
    fn runtime_registry_object_maps_to_persistent_entry_header() {
        let mut registry: ObjectRegistry<2> = ObjectRegistry::new();
        assert!(registry.upsert_instance_object(aid(&[0x01]), aid(&[0x02]), aid(&[0x03]), &[0xAA]));
        let runtime_entry = registry.entries().next().expect("runtime entry");
        let data_ref = PersistentRef::new(PersistentSpace::RegistryFlash, 0, 0x80);
        let persistent = PersistentRegistryEntry::from_registry_object(runtime_entry, data_ref);

        assert_eq!(persistent.object_aid.as_aid().as_slice(), &[0x02]);
        assert_eq!(persistent.parent_sd_aid.as_aid().as_slice(), &[0x01]);
        assert_eq!(persistent.kind_word.kind(), PersistentObjectKind::Instance);
        assert_eq!(persistent.data_ref, data_ref);
    }

    #[test]
    fn runtime_registry_object_maps_lifecycle_state_bits() {
        let mut registry: ObjectRegistry<4> = ObjectRegistry::new();
        let parent = aid(&[0x01]);
        assert!(registry.insert_package_object(parent, aid(&[0x10]), aid(&[0x10]), &[0xCA]));
        assert!(registry.upsert_instance_object(parent, aid(&[0x20]), aid(&[0x10]), &[0xBB]));
        assert!(registry.upsert_security_domain_object(
            parent,
            aid(&[0x30]),
            aid(&[0x10]),
            SecurityDomainObjectBackend::KernelSecurityDomain,
            [0xFF, 0xFF, 0xFF],
            &[0xCC],
        ));
        assert!(registry.upsert_key_object(
            parent,
            aid(&[0x40]),
            KeyObjectType::Scp03Static,
            KeyObjectState::Locked,
            1,
            1,
            1,
            &[0xDD],
        ));
        assert!(registry.set_package_state(&parent, &aid(&[0x10]), PackageObjectState::Locked));
        assert!(registry.set_instance_state(&parent, &aid(&[0x20]), InstanceObjectState::Locked));
        assert!(registry.set_security_domain_state(
            &parent,
            &aid(&[0x30]),
            SecurityDomainObjectState::Locked,
        ));

        let data_ref = PersistentRef::new(PersistentSpace::RegistryFlash, 0, 0x80);
        for runtime_entry in registry.entries() {
            let persistent = PersistentRegistryEntry::from_registry_object(runtime_entry, data_ref);
            // Invariant: state bit 1 is the persisted encoding of the minimal
            // locked state for every lifecycle-bearing object family.
            assert_eq!(persistent.kind_word.state_bits(), 1);
        }
    }

    #[test]
    fn runtime_instance_payload_encodes_package_binding_and_state() {
        let mut registry: ObjectRegistry<2> = ObjectRegistry::new();
        assert!(registry.upsert_instance_object(
            aid(&[0x01]),
            aid(&[0x02]),
            aid(&[0x03]),
            &[0xAA, 0xBB]
        ));
        let runtime_entry = registry.entries().next().expect("runtime entry");
        let mut payload = [0u8; 64];
        let (magic, len) =
            encode_registry_object_payload(runtime_entry, &mut payload).expect("encode payload");
        let decoded = decode_instance_payload(&payload[..len]).expect("decode instance payload");
        assert_eq!(magic, INSTANCE_STATE_BLOCK_MAGIC);
        assert_eq!(decoded.package_aid.as_aid().as_slice(), &[0x03]);
        assert_eq!(decoded.serialized_state, &[0xAA, 0xBB]);
    }

    #[test]
    fn runtime_security_domain_payload_keeps_privileges_kernel_side() {
        let mut registry: ObjectRegistry<2> = ObjectRegistry::new();
        assert!(registry.upsert_security_domain_object(
            aid(&[0x01]),
            aid(&[0x02]),
            aid(&[0x03]),
            SecurityDomainObjectBackend::KernelSecurityDomain,
            [0xA0, 0x12, 0x34],
            &[0xFE]
        ));
        let runtime_entry = registry.entries().next().expect("runtime entry");
        let mut payload = [0u8; 64];
        let (magic, len) =
            encode_registry_object_payload(runtime_entry, &mut payload).expect("encode payload");
        let decoded = decode_security_domain_payload(&payload[..len]).expect("decode sd payload");
        assert_eq!(magic, INSTANCE_STATE_BLOCK_MAGIC);
        assert_eq!(decoded.package_aid.as_aid().as_slice(), &[0x03]);
        assert_eq!(
            decoded.backend,
            SecurityDomainObjectBackend::KernelSecurityDomain
        );
        assert_eq!(decoded.privilege_bytes, [0xA0, 0x12, 0x34]);
        assert_eq!(decoded.serialized_state, &[0xFE]);
    }

    #[test]
    fn runtime_key_payload_encodes_metadata_and_raw_key() {
        let mut registry: ObjectRegistry<2> = ObjectRegistry::new();
        assert!(registry.upsert_key_object(
            aid(&[0x01]),
            aid(&[0x4B]),
            KeyObjectType::Scp03Static,
            KeyObjectState::Active,
            7,
            3,
            1,
            &[0xCA, 0xFE]
        ));
        let runtime_entry = registry.entries().next().expect("runtime entry");
        let mut payload = [0u8; 64];
        let (magic, len) =
            encode_registry_object_payload(runtime_entry, &mut payload).expect("encode payload");
        let decoded = decode_key_payload(&payload[..len]).expect("decode key payload");
        assert_eq!(magic, DATA_BLOCK_MAGIC);
        assert_eq!(decoded.key_type, KeyObjectType::Scp03Static);
        assert_eq!(decoded.key_state, KeyObjectState::Active);
        assert_eq!(decoded.key_version, 7);
        assert_eq!(decoded.key_id, 3);
        assert_eq!(decoded.key_usage, 1);
        assert_eq!(decoded.raw_key_bytes, &[0xCA, 0xFE]);
    }

    #[test]
    fn runtime_data_payload_encodes_raw_bytes() {
        let mut registry: ObjectRegistry<2> = ObjectRegistry::new();
        assert!(registry.upsert_data_object(
            aid(&[0x01]),
            aid(&[0x44, 0x41, 0x54, 0x41, 0xDF, 0x01]),
            b"persistent-data"
        ));
        let runtime_entry = registry.entries().next().expect("runtime entry");
        let mut payload = [0u8; 64];
        let (magic, len) =
            encode_registry_object_payload(runtime_entry, &mut payload).expect("encode payload");
        let decoded = decode_data_payload(&payload[..len]).expect("decode data payload");
        assert_eq!(magic, DATA_BLOCK_MAGIC);
        assert_eq!(decoded.bytes, b"persistent-data");
    }

    #[test]
    fn object_blocks_encode_decode_and_check_crc() {
        let mut buf = vec![0u8; PAGE * 2];
        let len = encode_object_block(INSTANCE_STATE_BLOCK_MAGIC, &[0xDE, 0xAD], PAGE, &mut buf)
            .expect("encode object");
        assert_eq!(len, PAGE);
        let decoded = decode_object_block_at(&buf, 0, PAGE).expect("decode object");
        assert_eq!(decoded.magic, INSTANCE_STATE_BLOCK_MAGIC);
        assert_eq!(decoded.payload, &[0xDE, 0xAD]);

        buf[OBJECT_HEADER_LEN] ^= 0x01;
        assert_eq!(
            decode_object_block_at(&buf, 0, PAGE).map(|_| ()),
            Err(PersistenceFormatError::CrcMismatch)
        );
    }

    #[test]
    fn package_object_block_exposes_fae_payload_after_persistent_header() {
        let fae = [0xF0, 0x9F, 0xA6, 0x80, 0xFA, 0xE0];
        let mut buf = vec![0u8; PAGE * 2];
        let len =
            encode_object_block(PACKAGE_BLOCK_MAGIC, &fae, PAGE, &mut buf).expect("encode package");
        let decoded = decode_object_block_at(&buf, 0, PAGE).expect("decode package");

        assert_eq!(len, PAGE);
        assert_eq!(decoded.magic, PACKAGE_BLOCK_MAGIC);
        assert_eq!(decoded.payload, fae);
        assert_eq!(decoded.payload.as_ptr(), unsafe {
            buf.as_ptr().add(OBJECT_BLOCK_HEADER_LEN)
        });
    }

    #[test]
    fn registry_blocks_encode_decode_and_expose_entries() {
        let entries = [
            entry(&[0x10], &[0x01], PersistentObjectKind::Package),
            entry(&[0x11], &[0x01], PersistentObjectKind::Instance),
        ];
        let mut buf = vec![0u8; PAGE * 4];
        let len = encode_registry_block(7, &entries, PAGE, &mut buf).expect("encode registry");
        assert_eq!(len, PAGE * 2);
        let decoded = decode_registry_block_at(&buf, 0, PAGE).expect("decode registry");
        assert_eq!(decoded.mutation_counter, 7);
        assert_eq!(decoded.entry_count, 2);
        assert_eq!(decoded.entry(0), Ok(entries[0]));
        assert_eq!(decoded.entry(1), Ok(entries[1]));
    }

    #[test]
    fn scanner_returns_highest_valid_mutation_counter() {
        let first_entry = [entry(&[0x10], &[0x01], PersistentObjectKind::Instance)];
        let second_entry = [entry(&[0x20], &[0x01], PersistentObjectKind::Key)];
        let mut area = vec![0xFFu8; PAGE * 6];
        let first_len =
            encode_registry_block(1, &first_entry, PAGE, &mut area[0..PAGE * 2]).unwrap();
        let second_len = encode_registry_block(
            3,
            &second_entry,
            PAGE,
            &mut area[first_len..first_len + PAGE * 2],
        )
        .unwrap();
        assert_eq!(second_len, PAGE * 2);
        let latest = find_latest_registry_block(&area, PAGE)
            .expect("scan")
            .expect("latest registry");
        assert_eq!(latest.offset, first_len);
        assert_eq!(latest.mutation_counter, 3);
        assert_eq!(latest.entry(0), Ok(second_entry[0]));
    }

    #[test]
    fn area_scan_advances_append_offset_past_objects_and_registry() {
        let entries = [entry(&[0x10], &[0x01], PersistentObjectKind::Instance)];
        let mut area = vec![0xFFu8; PAGE * 8];
        let object_len =
            encode_object_block(DATA_BLOCK_MAGIC, &[0xCA, 0xFE], PAGE, &mut area[..PAGE * 2])
                .unwrap();
        let registry_len = encode_registry_block(
            4,
            &entries,
            PAGE,
            &mut area[object_len..object_len + PAGE * 2],
        )
        .unwrap();

        let scan = scan_persistence_area(&area, PAGE).expect("scan");
        assert_eq!(scan.append_offset, object_len + registry_len);
        assert_eq!(
            scan.latest_registry.map(|block| block.mutation_counter),
            Some(4)
        );
    }

    #[test]
    fn reusable_span_can_use_erased_hole_before_later_valid_blocks() {
        let entries = [entry(&[0x10], &[0x01], PersistentObjectKind::Instance)];
        let mut area = vec![0xFFu8; PAGE * 8];
        encode_registry_block(1, &entries, PAGE, &mut area[PAGE * 4..PAGE * 6]).unwrap();

        let span = find_reusable_span(&area, PAGE, SECTOR, PAGE * 2, &[])
            .expect("search")
            .expect("free span");
        assert_eq!(span, ReusableSpan::erased(0, PAGE * 2));
        assert_eq!(
            find_latest_registry_block(&area, PAGE)
                .expect("scan")
                .map(|block| block.offset),
            Some(PAGE * 4)
        );
    }

    #[test]
    fn reusable_span_never_uses_protected_erased_pages() {
        let area = vec![0xFFu8; PAGE * 4];
        let protected = [PersistentRange::new(0, PAGE)];

        let span = find_reusable_span(&area, PAGE, SECTOR, PAGE, &protected)
            .expect("search")
            .expect("second erased page");
        assert_eq!(span, ReusableSpan::erased(PAGE, PAGE));
    }

    #[test]
    fn exact_append_cursor_reserves_erased_pages_without_a_scan() {
        let area = vec![0xFFu8; PAGE * 4];

        let span = erased_span_at(&area, PAGE, PAGE * 2, PAGE, &[])
            .expect("validate cursor")
            .expect("erased pages");

        assert_eq!(span, ReusableSpan::erased(PAGE, PAGE * 2));
    }

    #[test]
    fn exact_append_cursor_rejects_occupied_or_protected_pages() {
        let mut area = vec![0xFFu8; PAGE * 4];
        area[PAGE] = 0;
        assert_eq!(
            erased_span_at(&area, PAGE, PAGE, PAGE, &[]).expect("occupied cursor"),
            None
        );

        area[PAGE] = 0xFF;
        let protected = [PersistentRange::new(PAGE, PAGE)];
        assert_eq!(
            erased_span_at(&area, PAGE, PAGE, PAGE, &protected).expect("protected cursor"),
            None
        );
    }

    #[test]
    fn reusable_span_recycles_complete_unprotected_sector_before_programming() {
        let mut area = vec![0x00u8; PAGE * 8];
        encode_object_block(
            DATA_BLOCK_MAGIC,
            &[0xA5; PAGE * 3],
            PAGE,
            &mut area[..PAGE * 4],
        )
        .unwrap();
        let protected = [PersistentRange::new(PAGE * 4, PAGE)];

        let span = find_reusable_span(&area, PAGE, SECTOR, PAGE * 2, &protected)
            .expect("search")
            .expect("reusable sector");
        assert_eq!(span, ReusableSpan::recycled_sector(0, PAGE * 2, SECTOR));
    }

    #[test]
    fn reusable_span_recycles_crc_invalid_abandoned_load_sector() {
        let mut area = vec![0x00u8; PAGE * 80];
        let block_len = encode_object_block(
            PACKAGE_BLOCK_MAGIC,
            &[0xA5; PAGE * 3],
            PAGE,
            &mut area[..PAGE * 40],
        )
        .unwrap();
        area[block_len - 1] ^= 0x5A;
        assert!(decode_object_block_at(&area, 0, PAGE).is_err());

        let span = find_reusable_span(&area, PAGE, SECTOR, PAGE * 2, &[])
            .expect("search")
            .expect("abandoned C0DE block");
        assert_eq!(span, ReusableSpan::recycled_sector(0, PAGE * 2, SECTOR));
    }

    #[test]
    fn smaller_rewrite_leaves_erased_tail_as_reusable_hole() {
        let entries = [entry(&[0x10], &[0x01], PersistentObjectKind::Instance)];
        let mut area = vec![0xFFu8; PAGE * 8];
        encode_object_block(
            DATA_BLOCK_MAGIC,
            &[0xA5; PAGE * 3],
            PAGE,
            &mut area[..PAGE * 4],
        )
        .unwrap();
        let smaller_len =
            encode_object_block(DATA_BLOCK_MAGIC, &[0x5A], PAGE, &mut area[..PAGE * 2]).unwrap();
        area[smaller_len..PAGE * 4].fill(0xFF);
        encode_registry_block(5, &entries, PAGE, &mut area[PAGE * 4..PAGE * 6]).unwrap();

        let scan = scan_persistence_area(&area, PAGE).expect("scan");
        assert_eq!(
            scan.latest_registry.map(|block| block.offset),
            Some(PAGE * 4)
        );
        assert_eq!(scan.append_offset, smaller_len);
        let protected = [
            PersistentRange::new(0, smaller_len),
            PersistentRange::new(PAGE * 4, PAGE * 2),
        ];
        let span = find_reusable_span(&area, PAGE, SECTOR, PAGE, &protected)
            .expect("search")
            .expect("tail hole");
        assert_eq!(span, ReusableSpan::erased(smaller_len, PAGE));
    }

    #[test]
    fn scanner_ignores_corrupted_latest_and_keeps_previous_registry() {
        let first_entry = [entry(&[0x10], &[0x01], PersistentObjectKind::Instance)];
        let second_entry = [entry(&[0x20], &[0x01], PersistentObjectKind::Key)];
        let mut area = vec![0xFFu8; PAGE * 6];
        let first_len =
            encode_registry_block(1, &first_entry, PAGE, &mut area[0..PAGE * 2]).unwrap();
        encode_registry_block(
            2,
            &second_entry,
            PAGE,
            &mut area[first_len..first_len + PAGE * 2],
        )
        .unwrap();
        area[first_len + REGISTRY_HEADER_LEN] ^= 0x01;

        let latest = find_latest_registry_block(&area, PAGE)
            .expect("scan")
            .expect("previous registry");
        assert_eq!(latest.offset, 0);
        assert_eq!(latest.mutation_counter, 1);
        assert_eq!(latest.entry(0), Ok(first_entry[0]));
    }

    #[test]
    fn scanner_treats_erased_pages_as_free_space_not_as_end_marker() {
        let entries = [entry(
            &[0x33],
            &[0x01],
            PersistentObjectKind::SecurityDomain,
        )];
        let mut area = vec![0xFFu8; PAGE * 4];
        encode_registry_block(9, &entries, PAGE, &mut area[PAGE..PAGE * 3]).unwrap();
        let scan = scan_persistence_area(&area, PAGE).expect("scan");
        assert_eq!(scan.append_offset, 0);
        let latest = scan.latest_registry.expect("registry after erased page");
        assert_eq!(latest.offset, PAGE);
        assert_eq!(latest.mutation_counter, 9);
    }

    #[test]
    fn reusable_span_never_erases_sector_touching_protected_range() {
        let area = vec![0x00u8; SECTOR * 2];
        let protected = [PersistentRange::new(PAGE * 2, PAGE)];

        let span = find_reusable_span(&area, PAGE, SECTOR, PAGE, &protected)
            .expect("search")
            .expect("second sector");
        assert_eq!(span, ReusableSpan::recycled_sector(SECTOR, PAGE, SECTOR));
    }

    #[test]
    fn reusable_span_can_reserve_multiple_recyclable_sectors_for_large_object() {
        let area = vec![0x00u8; SECTOR * 4];
        let protected = [PersistentRange::new(0, SECTOR)];

        let span = find_reusable_span(&area, PAGE, SECTOR, SECTOR + PAGE, &protected)
            .expect("search")
            .expect("two-sector span");
        assert_eq!(
            span,
            ReusableSpan::recycled_sector(SECTOR, SECTOR + PAGE, SECTOR * 2)
        );
    }

    #[test]
    fn scp11_key_types_have_stable_persistent_tags() {
        assert_eq!(encode_key_type(KeyObjectType::Scp11SdEckaPrivate), 1);
        assert_eq!(encode_key_type(KeyObjectType::Scp11CaKlocPublic), 2);
        assert_eq!(decode_key_type(1), Ok(KeyObjectType::Scp11SdEckaPrivate));
        assert_eq!(decode_key_type(2), Ok(KeyObjectType::Scp11CaKlocPublic));
    }
}
