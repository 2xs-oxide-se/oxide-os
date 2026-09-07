pub type MpuRegion = u8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MpuAccess {
    NoAccess,
    ReadOnly,
    ReadWrite,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MpuPrivilege {
    PrivilegedOnly,
    Unprivileged,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MpuRegionConfig {
    pub base_addr: usize,
    pub size: usize,
    pub access: MpuAccess,
    pub privilege: MpuPrivilege,
    pub executable: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MpuError {
    Unsupported,
    InvalidRegion,
    InvalidAddress,
    InvalidSize,
    UnalignedAddress,
}

pub type MpuResult<T> = Result<T, MpuError>;

pub fn enable() -> MpuResult<()> {
    crate::core::target::mpu_enable()
}

pub fn disable() -> MpuResult<()> {
    crate::core::target::mpu_disable()
}

pub fn set_region(region: MpuRegion, config: &MpuRegionConfig) -> MpuResult<()> {
    crate::core::target::mpu_set_region(region, config)
}

pub fn unset_region(region: MpuRegion) -> MpuResult<()> {
    crate::core::target::mpu_unset_region(region)
}
