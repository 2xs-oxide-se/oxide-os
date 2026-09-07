use rustlet_runtime::Aid;

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootSecurityDomainBackend {
    NullSecurityDomain,
    KernelSecurityDomain,
    RustletSecurityDomainProxy,
}

include!(concat!(env!("OUT_DIR"), "/predeployment_manifest.inc.rs"));

pub fn root_package_aid() -> Aid {
    ROOT_SECURITY_DOMAIN_PACKAGE_AID
}

pub fn root_instance_aid() -> Aid {
    ROOT_SECURITY_DOMAIN_INSTANCE_AID
}

pub fn root_backend() -> RootSecurityDomainBackend {
    ROOT_SECURITY_DOMAIN_BACKEND
}

pub fn root_privileges() -> &'static [u8; 3] {
    &ROOT_SECURITY_DOMAIN_PRIVILEGES
}

pub fn root_install_payload() -> &'static [u8] {
    ROOT_SECURITY_DOMAIN_INSTALL_PAYLOAD
}

pub fn issuer_instance_aid() -> Option<Aid> {
    ISSUER_SECURITY_DOMAIN_INSTANCE_AID
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PredeployedSecurityDomainRole {
    Issuer,
    Supplementary,
}

#[allow(dead_code)]
pub struct PredeployedSecurityDomain {
    pub role: PredeployedSecurityDomainRole,
    pub parent_instance_aid: Aid,
    pub backend: RootSecurityDomainBackend,
    pub package_aid: Aid,
    pub instance_aid: Aid,
    pub privileges: [u8; 3],
    pub install_payload: &'static [u8],
}

pub struct PredeployedRustletInstance {
    pub parent_instance_aid: Aid,
    pub package_aid: Aid,
    pub applet_aid: Aid,
    pub instance_aid: Aid,
    pub install_parameters: &'static [u8],
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PredeployedKeyType {
    Scp03Static,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PredeployedKeyUsage {
    Enc,
    Mac,
}

pub struct PredeployedKey {
    pub parent_instance_aid: Aid,
    pub key_type: PredeployedKeyType,
    pub key_version: u8,
    pub key_id: u8,
    pub usage: PredeployedKeyUsage,
    pub material: &'static [u8],
}

pub fn predeployed_security_domains() -> &'static [PredeployedSecurityDomain] {
    PREDEPLOYED_SECURITY_DOMAINS
}

pub fn predeployed_rustlet_instances() -> &'static [PredeployedRustletInstance] {
    PREDEPLOYED_RUSTLET_INSTANCES
}

pub fn predeployed_keys() -> &'static [PredeployedKey] {
    PREDEPLOYED_KEYS
}
