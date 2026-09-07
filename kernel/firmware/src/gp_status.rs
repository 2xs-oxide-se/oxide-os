//! GlobalPlatform `GET STATUS` command parsing and record encoding.
//!
//! The module is allocation-free and independent from transport state. Registry
//! traversal and visibility are owned by `selected_app`; this module only
//! validates one query and encodes one GP `E3` registry record.

use rustlet_runtime::gp::{BerTlvReader, BerTlvWriter, DecodeError, EncodeError};
use rustlet_runtime::Aid;

use crate::object_registry::{
    InstanceObjectState, ManagedObjectKind, PackageObjectState, RegistryObject,
    SecurityDomainObjectState,
};

/// Object family selected by `GET STATUS P1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GetStatusCategory {
    IssuerSecurityDomain,
    ApplicationsAndSecurityDomains,
    ExecutableLoadFiles,
    ExecutableLoadFilesAndModules,
}

/// One validated `GET STATUS` request.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GetStatusQuery {
    pub category: GetStatusCategory,
    pub next_occurrence: bool,
    pub aid_filter: Aid,
}

/// Structural command errors mapped by the APDU handler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GetStatusQueryError {
    IncorrectP1P2,
    WrongData,
}

/// Parses the modern TLV-form `GET STATUS` command.
///
/// Oxide SE deliberately profiles out the deprecated response format where
/// `P2.b2=0`. The mandatory `4F` search criterion may be empty, exact, or a
/// prefix such as a RID. An optional `5C` tag list is accepted and ignored:
/// the implementation always emits the mandatory fields defined by GP.
pub fn parse_query(p1: u8, p2: u8, data: &[u8]) -> Result<GetStatusQuery, GetStatusQueryError> {
    let category = match p1 {
        0x80 => GetStatusCategory::IssuerSecurityDomain,
        0x40 => GetStatusCategory::ApplicationsAndSecurityDomains,
        0x20 => GetStatusCategory::ExecutableLoadFiles,
        0x10 => GetStatusCategory::ExecutableLoadFilesAndModules,
        _ => return Err(GetStatusQueryError::IncorrectP1P2),
    };
    if p2 & !0x03 != 0 || p2 & 0x02 == 0 {
        return Err(GetStatusQueryError::IncorrectP1P2);
    }

    let mut reader = BerTlvReader::new(data);
    let search = reader
        .next_tlv()
        .map_err(map_decode_error)?
        .ok_or(GetStatusQueryError::WrongData)?;
    if search.tag != 0x4f || search.value.len() > 16 {
        return Err(GetStatusQueryError::WrongData);
    }
    let aid_filter = Aid::new(search.value);
    if let Some(tag_list) = reader.next_tlv().map_err(map_decode_error)? {
        if tag_list.tag != 0x5c {
            return Err(GetStatusQueryError::WrongData);
        }
    }
    if reader.next_tlv().map_err(map_decode_error)?.is_some() {
        return Err(GetStatusQueryError::WrongData);
    }

    Ok(GetStatusQuery {
        category,
        next_occurrence: p2 & 0x01 != 0,
        aid_filter,
    })
}

const fn map_decode_error(_error: DecodeError) -> GetStatusQueryError {
    GetStatusQueryError::WrongData
}

/// Returns true when one live registry object belongs to the requested family.
pub fn matches_category(
    query: GetStatusQuery,
    object: &RegistryObject,
    root_sd_aid: &Aid,
    issuer_sd_aid: Option<&Aid>,
) -> bool {
    match query.category {
        GetStatusCategory::IssuerSecurityDomain => {
            object.object_kind == ManagedObjectKind::SecurityDomain
                && issuer_sd_aid.is_some_and(|issuer| object.object_aid == *issuer)
        }
        GetStatusCategory::ApplicationsAndSecurityDomains => {
            matches!(
                object.object_kind,
                ManagedObjectKind::Instance | ManagedObjectKind::SecurityDomain
            ) && object.object_aid != *root_sd_aid
        }
        GetStatusCategory::ExecutableLoadFiles
        | GetStatusCategory::ExecutableLoadFilesAndModules => {
            object.object_kind == ManagedObjectKind::Package
        }
    }
}

/// Returns true when an AID satisfies the command search criterion.
pub fn matches_aid(query: GetStatusQuery, aid: &Aid) -> bool {
    if query.category == GetStatusCategory::IssuerSecurityDomain {
        return true;
    }
    let prefix = query.aid_filter.as_slice();
    aid.as_slice().starts_with(prefix)
}

fn lifecycle_byte(object: &RegistryObject) -> Option<u8> {
    match object.object_kind {
        ManagedObjectKind::SecurityDomain => match object.security_domain_state()? {
            SecurityDomainObjectState::Selectable => Some(0x07),
            SecurityDomainObjectState::Locked => Some(0x80),
        },
        ManagedObjectKind::Package => match object.package_state()? {
            PackageObjectState::Loaded => Some(0x01),
            PackageObjectState::Locked => Some(0x80),
        },
        ManagedObjectKind::Instance => match object.instance_state()? {
            InstanceObjectState::Selectable => Some(0x07),
            InstanceObjectState::Locked => Some(0x80),
        },
        ManagedObjectKind::Key | ManagedObjectKind::Data => None,
    }
}

const fn tlv_len(tag_len: usize, value_len: usize) -> usize {
    tag_len + 1 + value_len
}

/// Returns the exact encoded size of one modern `E3` registry record.
fn projected_parent_aid<'a>(object: &'a RegistryObject, root_sd_aid: &Aid) -> &'a Aid {
    if object.object_kind == ManagedObjectKind::SecurityDomain
        && object.parent_sd_aid == *root_sd_aid
    {
        // Direct children of the oXiDe technical root are roots of distinct
        // GlobalPlatform association hierarchies and are projected as
        // self-associated. The technical containment edge is kernel-private.
        &object.object_aid
    } else {
        &object.parent_sd_aid
    }
}

pub fn encoded_record_len(
    query: GetStatusQuery,
    object: &RegistryObject,
    root_sd_aid: &Aid,
) -> Option<usize> {
    let _ = lifecycle_byte(object)?;
    let mut content_len = tlv_len(1, object.object_aid.as_slice().len()) + tlv_len(2, 1);
    match object.object_kind {
        ManagedObjectKind::SecurityDomain | ManagedObjectKind::Instance => {
            content_len += tlv_len(1, 3);
            if let Some(package_aid) = object.package_aid() {
                content_len += tlv_len(1, package_aid.as_slice().len());
            }
            let parent = projected_parent_aid(object, root_sd_aid);
            if parent.len != 0 {
                content_len += tlv_len(1, parent.as_slice().len());
            }
        }
        ManagedObjectKind::Package => {
            if query.category == GetStatusCategory::ExecutableLoadFilesAndModules {
                if let Some(module_aid) = object.package_applet_aid() {
                    content_len += tlv_len(1, module_aid.as_slice().len());
                }
            }
            if object.parent_sd_aid.len != 0 {
                content_len += tlv_len(1, object.parent_sd_aid.as_slice().len());
            }
        }
        ManagedObjectKind::Key | ManagedObjectKind::Data => return None,
    }
    Some(tlv_len(1, content_len))
}

/// Encodes one modern GP `E3` registry record directly into `out`.
pub fn encode_record(
    query: GetStatusQuery,
    object: &RegistryObject,
    root_sd_aid: &Aid,
    out: &mut [u8],
) -> Result<usize, EncodeError> {
    let lifecycle = lifecycle_byte(object).ok_or(EncodeError::ValueTooLong)?;
    let mut writer = BerTlvWriter::new(out);
    let record = writer.start(&[0xe3])?;
    writer.primitive(&[0x4f], object.object_aid.as_slice())?;
    writer.primitive(&[0x9f, 0x70], &[lifecycle])?;

    match object.object_kind {
        ManagedObjectKind::SecurityDomain | ManagedObjectKind::Instance => {
            let privileges = object.security_domain_privilege_bytes().unwrap_or([0; 3]);
            writer.primitive(&[0xc5], &privileges)?;
            if let Some(package_aid) = object.package_aid() {
                writer.primitive(&[0xc4], package_aid.as_slice())?;
            }
            let parent = projected_parent_aid(object, root_sd_aid);
            if parent.len != 0 {
                writer.primitive(&[0xcc], parent.as_slice())?;
            }
        }
        ManagedObjectKind::Package => {
            if query.category == GetStatusCategory::ExecutableLoadFilesAndModules {
                if let Some(module_aid) = object.package_applet_aid() {
                    writer.primitive(&[0x84], module_aid.as_slice())?;
                }
            }
            if object.parent_sd_aid.len != 0 {
                writer.primitive(&[0xcc], object.parent_sd_aid.as_slice())?;
            }
        }
        ManagedObjectKind::Key | ManagedObjectKind::Data => {
            return Err(EncodeError::ValueTooLong);
        }
    }

    writer.finish(record)?;
    Ok(writer.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object_registry::{
        RegistryObjectPayload, SecurityDomainObjectBackend, SecurityDomainObjectState,
    };

    fn aid(bytes: &[u8]) -> Aid {
        Aid::new(bytes)
    }

    #[test]
    fn query_requires_modern_tlv_format_and_aid_criterion() {
        assert!(matches!(
            parse_query(0x40, 0x00, &[0x4f, 0x00]),
            Err(GetStatusQueryError::IncorrectP1P2)
        ));
        assert!(matches!(
            parse_query(0x40, 0x02, &[]),
            Err(GetStatusQueryError::WrongData)
        ));
        let query = parse_query(0x40, 0x03, &[0x4f, 0x02, 0xa0, 0x00]).unwrap();
        assert!(query.next_occurrence);
        assert!(query.aid_filter == aid(&[0xa0, 0x00]));
    }

    #[test]
    fn security_domain_record_contains_lifecycle_privileges_and_associations() {
        let object = RegistryObject {
            parent_sd_aid: aid(&[0xa0, 0x01]),
            object_kind: ManagedObjectKind::SecurityDomain,
            object_aid: aid(&[0xa0, 0x02]),
            payload: RegistryObjectPayload::SecurityDomain {
                package_aid: aid(&[0xa0, 0x03]),
                backend: SecurityDomainObjectBackend::KernelSecurityDomain,
                object_state: SecurityDomainObjectState::Selectable,
                privilege_bytes: [0x80, 0x04, 0x00],
                serialized_state: [0; rustlet_runtime::STATE_BUFFER_CAPACITY],
                serialized_state_len: 0,
            },
        };
        let root = aid(&[0xa0, 0x00]);
        let query = GetStatusQuery {
            category: GetStatusCategory::ApplicationsAndSecurityDomains,
            next_occurrence: false,
            aid_filter: Aid::empty(),
        };
        let mut out = [0u8; 64];
        let len = encode_record(query, &object, &root, &mut out).unwrap();
        assert_eq!(len, encoded_record_len(query, &object, &root).unwrap());
        assert_eq!(
            &out[..len],
            &[
                0xe3, 0x15, 0x4f, 0x02, 0xa0, 0x02, 0x9f, 0x70, 0x01, 0x07, 0xc5, 0x03, 0x80, 0x04,
                0x00, 0xc4, 0x02, 0xa0, 0x03, 0xcc, 0x02, 0xa0, 0x01,
            ]
        );
    }

    #[test]
    fn issuer_query_names_the_issuer_instead_of_the_technical_root() {
        let root = aid(&[0xa0, 0x01]);
        let issuer = aid(&[0xa0, 0x02]);
        let query = GetStatusQuery {
            category: GetStatusCategory::IssuerSecurityDomain,
            next_occurrence: false,
            aid_filter: Aid::empty(),
        };
        let object = RegistryObject {
            parent_sd_aid: root,
            object_kind: ManagedObjectKind::SecurityDomain,
            object_aid: issuer,
            payload: RegistryObjectPayload::SecurityDomain {
                package_aid: issuer,
                backend: SecurityDomainObjectBackend::KernelSecurityDomain,
                object_state: SecurityDomainObjectState::Selectable,
                privilege_bytes: [0x80, 0x00, 0x00],
                serialized_state: [0; rustlet_runtime::STATE_BUFFER_CAPACITY],
                serialized_state_len: 0,
            },
        };

        assert!(matches_category(query, &object, &root, Some(&issuer)));
        assert!(!matches_category(query, &object, &issuer, Some(&root)));
    }

    #[test]
    fn direct_root_child_is_projected_as_self_associated() {
        let root = aid(&[0xa0, 0x01]);
        let detached = aid(&[0xa0, 0x02]);
        let object = RegistryObject {
            parent_sd_aid: root,
            object_kind: ManagedObjectKind::SecurityDomain,
            object_aid: detached,
            payload: RegistryObjectPayload::SecurityDomain {
                package_aid: detached,
                backend: SecurityDomainObjectBackend::KernelSecurityDomain,
                object_state: SecurityDomainObjectState::Selectable,
                privilege_bytes: [0x80, 0x00, 0x00],
                serialized_state: [0; rustlet_runtime::STATE_BUFFER_CAPACITY],
                serialized_state_len: 0,
            },
        };
        let query = GetStatusQuery {
            category: GetStatusCategory::ApplicationsAndSecurityDomains,
            next_occurrence: false,
            aid_filter: Aid::empty(),
        };
        let mut out = [0u8; 64];
        let len = encode_record(query, &object, &root, &mut out).unwrap();
        assert!(out[..len]
            .windows(4)
            .any(|window| window == [0xcc, 0x02, 0xa0, 0x02]));
        assert!(!out[..len]
            .windows(4)
            .any(|window| window == [0xcc, 0x02, 0xa0, 0x01]));
    }
}
