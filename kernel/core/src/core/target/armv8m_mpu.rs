//! Pure PMSAv8 register encoding, shared by the target backend and host tests.
//! See Arm CMSIS `ARM_MPU_RBAR` / `ARM_MPU_RLAR`:
//! <https://arm-software.github.io/CMSIS_6/latest/Core/group__mpu8__functions.html>.
use crate::core::mpu::{MpuAccess, MpuError, MpuPrivilege, MpuRegionConfig, MpuResult};

pub(super) const ENABLE_WITH_PRIVILEGED_BACKGROUND: u32 = 1 | (1 << 2);
pub(super) const XN: u32 = 1;

/// Encodes a 32-byte-aligned window using MAIR attribute zero (normal memory).
pub(super) fn encode(config: &MpuRegionConfig) -> MpuResult<(u32, u32)> {
    if config.size < 32 || !config.size.is_multiple_of(32) {
        return Err(MpuError::InvalidSize);
    }
    if !config.base_addr.is_multiple_of(32) {
        return Err(MpuError::UnalignedAddress);
    }
    let limit = config
        .base_addr
        .checked_add(config.size - 1)
        .filter(|limit| *limit <= u32::MAX as usize)
        .ok_or(MpuError::InvalidAddress)?;
    let ap = match (config.access, config.privilege) {
        // PMSAv8 cannot deny privileged reads. Never silently grant RW for NoAccess.
        (MpuAccess::NoAccess, _) => return Err(MpuError::Unsupported),
        (MpuAccess::ReadWrite, MpuPrivilege::PrivilegedOnly) => 0,
        (MpuAccess::ReadWrite, MpuPrivilege::Unprivileged) => 1,
        (MpuAccess::ReadOnly, MpuPrivilege::PrivilegedOnly) => 2,
        (MpuAccess::ReadOnly, MpuPrivilege::Unprivileged) => 3,
    };
    // Invariant: addresses are byte addresses, not fields to shift left again.
    Ok((
        (config.base_addr as u32 & !31) | (ap << 1) | u32::from(!config.executable),
        (limit as u32 & !31) | 1,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> MpuRegionConfig {
        MpuRegionConfig {
            base_addr: 0x2000_0020,
            size: 96,
            access: MpuAccess::ReadWrite,
            privilege: MpuPrivilege::PrivilegedOnly,
            executable: false,
        }
    }
    #[test]
    fn relaxed_window_keeps_byte_addresses_and_inclusive_limit() {
        assert_eq!(encode(&config()), Ok((0x2000_0021, 0x2000_0061)));
    }
    #[test]
    fn permissions_and_execute_never_are_independent() {
        for (access, privilege, ap) in [
            (MpuAccess::ReadWrite, MpuPrivilege::PrivilegedOnly, 0),
            (MpuAccess::ReadWrite, MpuPrivilege::Unprivileged, 1),
            (MpuAccess::ReadOnly, MpuPrivilege::PrivilegedOnly, 2),
            (MpuAccess::ReadOnly, MpuPrivilege::Unprivileged, 3),
        ] {
            for executable in [false, true] {
                let c = MpuRegionConfig {
                    access,
                    privilege,
                    executable,
                    ..config()
                };
                assert_eq!(
                    encode(&c).unwrap().0 & 31,
                    (ap << 1) | u32::from(!executable)
                );
            }
        }
    }
    #[test]
    fn no_access_is_not_misencoded_as_privileged_read_write() {
        assert_eq!(
            encode(&MpuRegionConfig {
                access: MpuAccess::NoAccess,
                ..config()
            }),
            Err(MpuError::Unsupported)
        );
    }
    #[test]
    fn rejects_invalid_windows() {
        for size in [0, 1, 31, 33] {
            assert_eq!(
                encode(&MpuRegionConfig { size, ..config() }),
                Err(MpuError::InvalidSize)
            );
        }
        assert_eq!(
            encode(&MpuRegionConfig {
                base_addr: 1,
                ..config()
            }),
            Err(MpuError::UnalignedAddress)
        );
        assert_eq!(
            encode(&MpuRegionConfig {
                base_addr: 0xffff_ffe0,
                size: 64,
                ..config()
            }),
            Err(MpuError::InvalidAddress)
        );
    }
    #[test]
    fn accepts_last_architectural_granule() {
        assert_eq!(
            encode(&MpuRegionConfig {
                base_addr: 0xffff_ffe0,
                size: 32,
                ..config()
            }),
            Ok((0xffff_ffe1, 0xffff_ffe1))
        );
    }
    #[test]
    fn control_enables_background_not_hardfault_mpu() {
        assert_eq!(ENABLE_WITH_PRIVILEGED_BACKGROUND, 5);
        assert_eq!(XN, 1);
    }
}
