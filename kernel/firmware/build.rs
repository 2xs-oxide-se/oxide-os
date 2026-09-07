use serde::Deserialize;
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy)]
struct EmbeddedRustletBuildSpec {
    crate_dir: &'static str,
    bin_name: &'static str,
    env_var: &'static str,
    selected_cfg: &'static str,
    package_aid: [u8; 16],
    package_aid_len: usize,
    applet_aid: [u8; 16],
    applet_aid_len: usize,
}

#[derive(Clone, Deserialize)]
struct PredeploymentManifest {
    root: Option<RootSecurityDomainDecl>,
    #[serde(default)]
    security_domains: Vec<SecurityDomainDecl>,
}

#[derive(Clone, Deserialize)]
struct RootSecurityDomainDecl {
    package: SecurityDomainPackageDecl,
    instance: SecurityDomainInstanceDecl,
    #[serde(default)]
    keys: Vec<KeyDecl>,
    #[serde(default)]
    packages: Vec<RustletPackageDecl>,
}

#[derive(Clone, Deserialize)]
struct SecurityDomainDecl {
    #[serde(default)]
    role: String,
    parent: ParentSecurityDomainDecl,
    package: SecurityDomainPackageDecl,
    instance: SecurityDomainInstanceDecl,
    #[serde(default)]
    keys: Vec<KeyDecl>,
    #[serde(default)]
    packages: Vec<RustletPackageDecl>,
}

#[derive(Clone, Deserialize)]
struct KeyDecl {
    #[serde(rename = "type")]
    key_type: String,
    version: u8,
    id: u8,
    usage: String,
    material: String,
}

#[derive(Clone, Deserialize)]
struct RustletPackageDecl {
    path: String,
    #[serde(default)]
    instances: Vec<RustletInstanceDecl>,
}

#[derive(Clone, Deserialize)]
struct RustletInstanceDecl {
    aid: String,
    #[serde(default)]
    install_bytes: String,
}

#[derive(Clone, Deserialize)]
struct ParentSecurityDomainDecl {
    aid: String,
}

#[derive(Clone, Deserialize)]
struct SecurityDomainPackageDecl {
    #[serde(default)]
    name: String,
    #[serde(default)]
    path: String,
    aid: String,
}

#[derive(Clone, Deserialize)]
struct SecurityDomainInstanceDecl {
    aid: String,
    install_bytes: String,
}

#[derive(Default, Deserialize)]
struct WorkspaceManifestConfig {
    #[serde(default)]
    workspace: WorkspaceConfigSection,
}

#[derive(Default, Deserialize)]
struct WorkspaceConfigSection {
    #[serde(default)]
    metadata: WorkspaceMetadataSection,
}

#[derive(Default, Deserialize)]
struct WorkspaceMetadataSection {
    #[serde(default)]
    oxide_se: WorkspaceOxideSeMetadata,
}

#[derive(Default, Deserialize)]
struct WorkspaceOxideSeMetadata {
    default_config_toml: Option<String>,
}

struct ParsedRootSecurityDomainDecl {
    backend: &'static str,
    package_aid: [u8; 16],
    package_aid_len: usize,
    instance_aid: [u8; 16],
    instance_aid_len: usize,
    install_bytes_prefix: [u8; 3],
    install_payload: Vec<u8>,
}

struct ParsedSecurityDomainDecl {
    role: &'static str,
    parent_instance_aid: [u8; 16],
    parent_instance_aid_len: usize,
    backend: &'static str,
    package_aid: [u8; 16],
    package_aid_len: usize,
    instance_aid: [u8; 16],
    instance_aid_len: usize,
    install_bytes_prefix: [u8; 3],
    install_payload: Vec<u8>,
}

struct ParsedRustletInstanceDecl {
    parent_instance_aid: [u8; 16],
    parent_instance_aid_len: usize,
    package_aid: [u8; 16],
    package_aid_len: usize,
    applet_aid: [u8; 16],
    applet_aid_len: usize,
    instance_aid: [u8; 16],
    instance_aid_len: usize,
    install_bytes: Vec<u8>,
}

struct ParsedKeyDecl {
    parent_instance_aid: [u8; 16],
    parent_instance_aid_len: usize,
    key_type: &'static str,
    key_version: u8,
    key_id: u8,
    key_usage: &'static str,
    material: [u8; 16],
}

macro_rules! package_aid_build_value {
    (aid: $aid:expr) => {
        (pad_aid_bytes(&$aid), $aid.len())
    };
    (aids: { package_applet: $package_applet:expr, instance: $instance:expr }) => {
        (pad_aid_bytes(&$package_applet), $package_applet.len())
    };
    (aids: { package: $package:expr, applet: $applet:expr, instance: $instance:expr }) => {
        (pad_aid_bytes(&$package), $package.len())
    };
}

macro_rules! applet_aid_build_value {
    (aid: $aid:expr) => {
        (pad_aid_bytes(&$aid), $aid.len())
    };
    (aids: { package_applet: $package_applet:expr, instance: $instance:expr }) => {
        (pad_aid_bytes(&$package_applet), $package_applet.len())
    };
    (aids: { package: $package:expr, applet: $applet:expr, instance: $instance:expr }) => {
        (pad_aid_bytes(&$applet), $applet.len())
    };
}

macro_rules! register_embedded_rustlets {
    ($({
        name: $name:ident,
        aid_const: $aid_const:ident,
        getter: $getter:ident,
        selected_cfg: $selected_cfg:ident,
        crate_dir: $crate_dir:expr,
        bin_name: $bin_name:expr,
        env_var: $env_var:expr,
        minimal: $minimal:literal,
        $aid_kind:ident : $aid_spec:tt
        $(,)?
    },)*) => {
        const EMBEDDED_RUSTLET_SPECS: &[EmbeddedRustletBuildSpec] = &[
            $(
                EmbeddedRustletBuildSpec {
                    crate_dir: $crate_dir,
                    bin_name: $bin_name,
                    env_var: $env_var,
                    selected_cfg: stringify!($selected_cfg),
                    package_aid: package_aid_build_value!($aid_kind: $aid_spec).0,
                    package_aid_len: package_aid_build_value!($aid_kind: $aid_spec).1,
                    applet_aid: applet_aid_build_value!($aid_kind: $aid_spec).0,
                    applet_aid_len: applet_aid_build_value!($aid_kind: $aid_spec).1,
                },
            )*
        ];
    };
}

include!("src/embedded_apps_registry.inc.rs");

#[derive(Clone, Copy)]
struct KernelAppModuleBuildSpec {
    name: &'static str,
    rust_module: &'static str,
    hooks: &'static [&'static str],
}

macro_rules! register_kernel_app_modules {
    ($({
        name: $name:literal,
        module: $module:ident,
        path: $path:literal,
        hooks: [$($hook:ident),* $(,)?],
    },)*) => {
        const KERNEL_APP_MODULE_SPECS: &[KernelAppModuleBuildSpec] = &[
            $(
                KernelAppModuleBuildSpec {
                    name: $name,
                    rust_module: stringify!($module),
                    hooks: &[$(stringify!($hook)),*],
                },
            )*
        ];
    };
}

include!("src/kernel_app_modules_registry.inc.rs");

fn main() {
    let kernel_dir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("missing manifest dir"));
    let repo_root = kernel_dir
        .parent()
        .and_then(|dir| dir.parent())
        .expect("firmware crate has no repository root parent");

    let kernel_only = matches!(
        std::env::var("OXIDE_SE_KERNEL_IMAGE_MODE").ok().as_deref(),
        Some("kernel-only")
    );
    let manifest_path = predeployment_manifest_path(&kernel_dir);
    let manifest = materialize_predeployment_manifest(
        read_predeployment_manifest(&manifest_path),
        kernel_only,
    );
    generate_predeployment_manifest(&manifest_path, &manifest);
    let selected_crate_dirs = selected_embedded_crate_dirs(&manifest, repo_root);

    let configured_modules = std::env::var("OXIDE_SE_KERNEL_APP_MODULES").unwrap_or_default();
    let mut seen = BTreeSet::new();
    let kernel_app_modules: Vec<&KernelAppModuleBuildSpec> = configured_modules
        .split(',')
        .filter(|module| !module.is_empty())
        .map(|module| {
            if !seen.insert(module) {
                panic!("duplicate kernel app module {module}");
            }
            KERNEL_APP_MODULE_SPECS
                .iter()
                .find(|spec| spec.name == module)
                .unwrap_or_else(|| {
                    panic!(
                        "unsupported kernel app module {module}; expected one of: {}",
                        KERNEL_APP_MODULE_SPECS
                            .iter()
                            .map(|spec| spec.name)
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                })
        })
        .collect();
    if kernel_only && kernel_app_modules.is_empty() {
        panic!("kernel-only images require at least one configured kernel app module");
    }
    generate_kernel_app_modules(&kernel_dir, &kernel_app_modules);

    let mut kernel_app_module_values = String::new();
    for (index, spec) in KERNEL_APP_MODULE_SPECS.iter().enumerate() {
        if index != 0 {
            kernel_app_module_values.push_str(", ");
        }
        write!(kernel_app_module_values, "\"{}\"", spec.name).unwrap();
    }

    println!("cargo:rerun-if-env-changed=OXIDE_SE_KERNEL_IMAGE_MODE");
    println!("cargo:rerun-if-env-changed=OXIDE_SE_KERNEL_APP_MODULES");
    println!("cargo:rerun-if-changed=src/kernel_app_modules_registry.inc.rs");
    println!("cargo:rerun-if-env-changed=OXIDE_SE_BOARD");
    println!("cargo:rerun-if-env-changed=OXIDE_SE_NATIVE_STARTUP_FINGERPRINT");
    println!("cargo:rustc-check-cfg=cfg(oxide_se_kernel_image_kernel_only)");
    println!(
        "cargo:rustc-check-cfg=cfg(oxide_se_kernel_app_module, values({kernel_app_module_values}))"
    );
    println!("cargo:rustc-check-cfg=cfg(oxide_se_board_mps2_an385)");
    println!("cargo:rustc-check-cfg=cfg(oxide_se_board_olimex_stm32_h405)");
    println!("cargo:rustc-check-cfg=cfg(oxide_se_board_b_l475e_iot01a)");
    println!("cargo:rustc-check-cfg=cfg(oxide_se_board_raspi_pico)");
    println!("cargo:rustc-check-cfg=cfg(oxide_se_board_raspi_pico2)");
    for spec in EMBEDDED_RUSTLET_SPECS {
        println!("cargo:rustc-check-cfg=cfg({})", spec.selected_cfg);
    }

    match std::env::var("OXIDE_SE_BOARD").as_deref() {
        Ok("olimex-stm32-h405") => {
            println!("cargo:rustc-cfg=oxide_se_board_olimex_stm32_h405")
        }
        Ok("b-l475e-iot01a") => println!("cargo:rustc-cfg=oxide_se_board_b_l475e_iot01a"),
        Ok("raspi-pico1") => println!("cargo:rustc-cfg=oxide_se_board_raspi_pico"),
        Ok("raspi-pico2") => println!("cargo:rustc-cfg=oxide_se_board_raspi_pico2"),
        _ => println!("cargo:rustc-cfg=oxide_se_board_mps2_an385"),
    }
    if kernel_only {
        println!("cargo:rustc-cfg=oxide_se_kernel_image_kernel_only");
    }
    for module in &kernel_app_modules {
        println!(
            "cargo:rustc-cfg=oxide_se_kernel_app_module=\"{}\"",
            module.name
        );
    }

    for spec in EMBEDDED_RUSTLET_SPECS {
        if kernel_only {
            continue;
        }
        if !selected_crate_dirs.contains(spec.crate_dir) {
            continue;
        }

        println!("cargo:rustc-cfg={}", spec.selected_cfg);

        let fae_path = repo_root
            .join(spec.crate_dir)
            .join("build")
            .join(format!("{}.fae", spec.bin_name));
        if !fae_path.exists() {
            panic!(
                "missing embedded FAE at {}. Build through `cargo run bootable <board>` first.",
                fae_path.display()
            );
        }

        println!("cargo:rerun-if-changed={}", fae_path.display());
        println!("cargo:rustc-env={}={}", spec.env_var, fae_path.display());
    }
}

fn generate_kernel_app_modules(kernel_dir: &Path, selected: &[&KernelAppModuleBuildSpec]) {
    let mut generated = String::from("compose_kernel_app_modules! {\n");
    generated.push_str("    initializers: [\n");
    for spec in selected {
        writeln!(
            generated,
            "        <{}::Module as KernelAppModule>::initialize,",
            spec.rust_module
        )
        .unwrap();
    }

    generated.push_str("    ],\n    apdu_filters: [\n");
    for spec in selected
        .iter()
        .filter(|spec| spec.hooks.contains(&"apdu_filter"))
    {
        writeln!(generated, "        {}::APDU_FILTER,", spec.rust_module).unwrap();
    }

    generated.push_str("    ],\n    after_apdu_hooks: [\n");
    for spec in selected
        .iter()
        .filter(|spec| spec.hooks.contains(&"after_apdu"))
    {
        writeln!(
            generated,
            "        {}::record_after_apdu,",
            spec.rust_module
        )
        .unwrap();
    }

    generated.push_str("    ],\n    before_rustlet_hooks: [\n");
    for spec in selected
        .iter()
        .filter(|spec| spec.hooks.contains(&"before_rustlet"))
    {
        writeln!(generated, "        {}::before_rustlet,", spec.rust_module).unwrap();
    }

    generated.push_str("    ],\n    after_rustlet_hooks: [\n");
    for spec in selected
        .iter()
        .filter(|spec| spec.hooks.contains(&"after_rustlet"))
    {
        writeln!(generated, "        {}::after_rustlet,", spec.rust_module).unwrap();
    }

    generated.push_str("    ],\n    preserve_clear_apdu_session_hooks: [\n");
    for spec in selected
        .iter()
        .filter(|spec| spec.hooks.contains(&"preserve_clear_apdu_session"))
    {
        writeln!(
            generated,
            "        {}::preserves_clear_apdu_session,",
            spec.rust_module
        )
        .unwrap();
    }
    generated.push_str("    ],\n}\n");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("missing OUT_DIR"));
    let output_path = out_dir.join("kernel_app_modules.inc.rs");
    if std::fs::read_to_string(&output_path).ok().as_deref() == Some(generated.as_str()) {
        return;
    }
    std::fs::write(&output_path, generated).unwrap_or_else(|err| {
        panic!(
            "failed to write generated kernel app modules {} for {}: {err}",
            output_path.display(),
            kernel_dir.display()
        )
    });
}

fn generate_predeployment_manifest(manifest_path: &Path, manifest: &PredeploymentManifest) {
    let parsed = parse_predeployment_manifest(manifest.clone());
    let generated =
        render_predeployment_manifest(manifest_path, &parsed.0, &parsed.1, &parsed.2, &parsed.3);
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("missing OUT_DIR"));
    let output_path = out_dir.join("predeployment_manifest.inc.rs");
    if std::fs::read_to_string(&output_path).ok().as_deref() == Some(generated.as_str()) {
        return;
    }
    std::fs::write(&output_path, generated).unwrap_or_else(|err| {
        panic!(
            "failed to write generated predeployment manifest {}: {err}",
            output_path.display()
        )
    });
}

fn materialize_predeployment_manifest(
    mut manifest: PredeploymentManifest,
    kernel_only: bool,
) -> PredeploymentManifest {
    if kernel_only {
        if manifest.root.is_some() || !manifest.security_domains.is_empty() {
            panic!("kernel-only images must not contain predeployment declarations");
        }
        manifest.root = None;
        manifest.security_domains.clear();
        manifest.root = Some(RootSecurityDomainDecl {
            package: SecurityDomainPackageDecl {
                name: "NullSecurityDomain".to_owned(),
                path: String::new(),
                aid: "A0:00:00:47:50:4F:53:01".to_owned(),
            },
            instance: SecurityDomainInstanceDecl {
                aid: "A0:00:00:47:50:4F:53:01".to_owned(),
                install_bytes: "FF:FF:FF".to_owned(),
            },
            keys: Vec::new(),
            packages: Vec::new(),
        });
        return manifest;
    }

    if manifest.root.is_none() {
        panic!("global-platform images require a [root] configuration");
    }
    manifest
}

fn predeployment_manifest_path(kernel_dir: &Path) -> PathBuf {
    println!("cargo:rerun-if-env-changed=OXIDE_SE_BUILD_CONFIG");
    let repo_root = kernel_dir
        .parent()
        .and_then(|dir| dir.parent())
        .expect("firmware crate has no repository root parent");
    let manifest_path = std::env::var_os("OXIDE_SE_BUILD_CONFIG")
        .map(PathBuf::from)
        .map(|path| {
            if path.is_absolute() {
                path
            } else {
                repo_root.join(path)
            }
        })
        .unwrap_or_else(|| repo_root.join(default_predeployment_config_relpath(repo_root)));
    println!("cargo:rerun-if-changed={}", manifest_path.display());
    manifest_path
}

fn read_predeployment_manifest(manifest_path: &Path) -> PredeploymentManifest {
    let source = std::fs::read_to_string(manifest_path).unwrap_or_else(|err| {
        panic!(
            "failed to read predeployment manifest {}: {err}",
            manifest_path.display()
        )
    });
    toml::from_str(&source).unwrap_or_else(|err| {
        panic!(
            "failed to parse predeployment manifest {}: {err}",
            manifest_path.display()
        )
    })
}

fn selected_embedded_crate_dirs(
    manifest: &PredeploymentManifest,
    repo_root: &Path,
) -> BTreeSet<String> {
    let mut selected = BTreeSet::new();
    let root = manifest
        .root
        .as_ref()
        .expect("predeployment manifest root was materialized");
    if let Some(crate_dir) = rustlet_backend_crate_dir(&root.package, repo_root) {
        selected.insert(crate_dir);
    }
    for package in &root.packages {
        selected.insert(normalize_rustlet_package_path(&package.path, repo_root));
    }
    for security_domain in &manifest.security_domains {
        if let Some(crate_dir) = rustlet_backend_crate_dir(&security_domain.package, repo_root) {
            selected.insert(crate_dir);
        }
        for package in &security_domain.packages {
            selected.insert(normalize_rustlet_package_path(&package.path, repo_root));
        }
    }
    selected
}

fn default_predeployment_config_relpath(repo_root: &Path) -> String {
    let workspace_manifest = repo_root.join("Cargo.toml");
    let source = std::fs::read_to_string(&workspace_manifest).unwrap_or_default();
    toml::from_str::<WorkspaceManifestConfig>(&source)
        .ok()
        .and_then(|manifest| manifest.workspace.metadata.oxide_se.default_config_toml)
        .unwrap_or_else(|| "config.toml".to_owned())
}

fn parse_predeployment_manifest(
    manifest: PredeploymentManifest,
) -> (
    ParsedRootSecurityDomainDecl,
    Vec<ParsedSecurityDomainDecl>,
    Vec<ParsedRustletInstanceDecl>,
    Vec<ParsedKeyDecl>,
) {
    let PredeploymentManifest {
        root,
        security_domains,
    } = manifest;
    let root = root.expect("predeployment manifest root was materialized");
    let RootSecurityDomainDecl {
        package,
        instance,
        keys: root_keys,
        packages: root_packages,
    } = root;
    let root = parse_root_security_domain_decl(RootSecurityDomainDecl {
        package,
        instance,
        keys: Vec::new(),
        packages: Vec::new(),
    });
    let mut parsed_security_domains: Vec<ParsedSecurityDomainDecl> = Vec::new();
    let mut rustlet_instances = Vec::new();
    let mut keys = Vec::new();
    let mut key_identities = BTreeSet::new();

    collect_keys(
        &mut keys,
        &mut key_identities,
        root.instance_aid,
        root.instance_aid_len,
        &root_keys,
        "root.keys",
    );
    collect_rustlet_instances_from_packages(
        &mut rustlet_instances,
        root.instance_aid,
        root.instance_aid_len,
        &root_packages,
    );

    for security_domain in security_domains {
        let SecurityDomainDecl {
            role,
            parent,
            package,
            instance,
            keys: security_domain_keys,
            packages,
        } = security_domain;
        let parsed = parse_security_domain_decl(&SecurityDomainDecl {
            role,
            parent,
            package,
            instance,
            keys: Vec::new(),
            packages: Vec::new(),
        });
        let parent_instance_aid = parsed.instance_aid;
        let parent_instance_aid_len = parsed.instance_aid_len;
        collect_keys(
            &mut keys,
            &mut key_identities,
            parent_instance_aid,
            parent_instance_aid_len,
            &security_domain_keys,
            "security_domains[].keys",
        );
        collect_rustlet_instances_from_packages(
            &mut rustlet_instances,
            parent_instance_aid,
            parent_instance_aid_len,
            &packages,
        );
        parsed_security_domains.push(parsed);
    }

    validate_security_domain_topology(&root, &parsed_security_domains);
    let parsed_security_domains = order_security_domains(&root, parsed_security_domains);

    (root, parsed_security_domains, rustlet_instances, keys)
}

fn parse_root_security_domain_decl(root: RootSecurityDomainDecl) -> ParsedRootSecurityDomainDecl {
    let backend = parse_security_domain_backend(&root.package, "root.package");
    let (package_aid, package_aid_len) = parse_aid_bytes(&root.package.aid, "root.package.aid");
    let (instance_aid, instance_aid_len) = parse_aid_bytes(&root.instance.aid, "root.instance.aid");
    let install_bytes_prefix =
        parse_privilege_bytes(&root.instance.install_bytes, "root.instance.install_bytes");
    let install_payload = compose_security_domain_install_payload(
        &install_bytes_prefix,
        &root.instance.install_bytes,
        "root.instance.install_bytes",
    );
    ParsedRootSecurityDomainDecl {
        backend,
        package_aid,
        package_aid_len,
        instance_aid,
        instance_aid_len,
        install_bytes_prefix,
        install_payload,
    }
}

fn parse_security_domain_decl(security_domain: &SecurityDomainDecl) -> ParsedSecurityDomainDecl {
    let role = match security_domain.role.trim() {
        "" | "supplementary" => "Supplementary",
        "issuer" => "Issuer",
        other => panic!(
            "unsupported security_domains[].role '{other}'; expected issuer or supplementary"
        ),
    };
    let backend =
        parse_security_domain_backend(&security_domain.package, "security_domains[].package");
    let (parent_instance_aid, parent_instance_aid_len) =
        parse_aid_bytes(&security_domain.parent.aid, "security_domains[].parent.aid");
    let (package_aid, package_aid_len) = parse_aid_bytes(
        &security_domain.package.aid,
        "security_domains[].package.aid",
    );
    let (instance_aid, instance_aid_len) = parse_aid_bytes(
        &security_domain.instance.aid,
        "security_domains[].instance.aid",
    );
    let install_bytes_prefix = parse_privilege_bytes(
        &security_domain.instance.install_bytes,
        "security_domains[].instance.install_bytes",
    );
    let install_payload = compose_security_domain_install_payload(
        &install_bytes_prefix,
        &security_domain.instance.install_bytes,
        "security_domains[].instance.install_bytes",
    );
    ParsedSecurityDomainDecl {
        role,
        parent_instance_aid,
        parent_instance_aid_len,
        backend,
        package_aid,
        package_aid_len,
        instance_aid,
        instance_aid_len,
        install_bytes_prefix,
        install_payload,
    }
}

fn aid_value(bytes: &[u8; 16], len: usize) -> &[u8] {
    &bytes[..len]
}

fn validate_security_domain_topology(
    root: &ParsedRootSecurityDomainDecl,
    security_domains: &[ParsedSecurityDomainDecl],
) {
    let root_aid = aid_value(&root.instance_aid, root.instance_aid_len);
    let mut issuer_seen = false;
    let mut known = BTreeSet::new();
    known.insert(root_aid.to_vec());

    for domain in security_domains {
        let aid = aid_value(&domain.instance_aid, domain.instance_aid_len);
        if !known.insert(aid.to_vec()) {
            panic!("duplicate Security Domain instance AID in predeployment manifest");
        }
        if domain.role == "Issuer" {
            if issuer_seen {
                panic!("predeployment manifest declares more than one Issuer Security Domain");
            }
            issuer_seen = true;
            if aid_value(&domain.parent_instance_aid, domain.parent_instance_aid_len) != root_aid {
                panic!("Issuer Security Domain must be a direct child of the technical root");
            }
        }
    }

    // Validate the complete graph independently of declaration order.
    for domain in security_domains {
        let aid = aid_value(&domain.instance_aid, domain.instance_aid_len);
        let parent = aid_value(&domain.parent_instance_aid, domain.parent_instance_aid_len);
        if parent == aid || !known.contains(parent) {
            panic!("Security Domain parent must name a distinct declared Security Domain");
        }
        let parent_privileges = if parent == root_aid {
            root.install_bytes_prefix
        } else {
            security_domains
                .iter()
                .find(|candidate| {
                    aid_value(&candidate.instance_aid, candidate.instance_aid_len) == parent
                })
                .map(|candidate| candidate.install_bytes_prefix)
                .expect("validated Security Domain parent")
        };
        for (&parent_privilege, &child_privilege) in parent_privileges
            .iter()
            .zip(domain.install_bytes_prefix.iter())
        {
            if parent_privilege & child_privilege != child_privilege {
                panic!("predeployed Security Domain privileges exceed its parent's privileges");
            }
        }

        let mut cursor = parent;
        let mut remaining = security_domains.len() + 1;
        while cursor != root_aid {
            if remaining == 0 {
                panic!("cycle in predeployment Security Domain hierarchy");
            }
            let Some(parent_domain) = security_domains.iter().find(|candidate| {
                aid_value(&candidate.instance_aid, candidate.instance_aid_len) == cursor
            }) else {
                panic!("Security Domain hierarchy does not terminate at the technical root");
            };
            cursor = aid_value(
                &parent_domain.parent_instance_aid,
                parent_domain.parent_instance_aid_len,
            );
            remaining -= 1;
        }
    }
}

/// Orders the already validated hierarchy for first-boot materialization.
///
/// The manifest is declarative: a child may be written before its parent.
/// The technical root is materialized separately, the optional Issuer Security
/// Domain is preferred among the root's ready children, and every remaining
/// domain is emitted only after its parent. Declaration order remains the
/// tie-breaker between otherwise independent domains.
fn order_security_domains(
    root: &ParsedRootSecurityDomainDecl,
    mut remaining: Vec<ParsedSecurityDomainDecl>,
) -> Vec<ParsedSecurityDomainDecl> {
    let mut materialized = BTreeSet::new();
    materialized.insert(aid_value(&root.instance_aid, root.instance_aid_len).to_vec());
    let mut ordered = Vec::with_capacity(remaining.len());

    while !remaining.is_empty() {
        let next = remaining
            .iter()
            .position(|domain| {
                domain.role == "Issuer"
                    && materialized.contains(aid_value(
                        &domain.parent_instance_aid,
                        domain.parent_instance_aid_len,
                    ))
            })
            .or_else(|| {
                remaining.iter().position(|domain| {
                    materialized.contains(aid_value(
                        &domain.parent_instance_aid,
                        domain.parent_instance_aid_len,
                    ))
                })
            })
            .expect("validated Security Domain hierarchy must be orderable");
        let domain = remaining.remove(next);
        materialized.insert(aid_value(&domain.instance_aid, domain.instance_aid_len).to_vec());
        ordered.push(domain);
    }

    ordered
}

fn parse_security_domain_backend(
    package: &SecurityDomainPackageDecl,
    field_name: &str,
) -> &'static str {
    match package.name.trim() {
        "NullSecurityDomain" => "NullSecurityDomain",
        "KernelSecurityDomain" => "KernelSecurityDomain",
        "" => match package.path.trim() {
            other if is_rustlet_backend_path(other) => "RustletSecurityDomainProxy",
            other => panic!("unsupported {field_name}.path '{other}'"),
        },
        other => panic!("unsupported {field_name} '{other}'"),
    }
}

fn compose_security_domain_install_payload(
    _privileges: &[u8; 3],
    install_bytes: &str,
    field_name: &str,
) -> Vec<u8> {
    parse_install_data_bytes(install_bytes, field_name)
}

fn parse_aid_bytes(value: &str, field_name: &str) -> ([u8; 16], usize) {
    let compact: String = value.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if compact.len() < 10 || compact.len() > 32 || !compact.len().is_multiple_of(2) {
        panic!("{field_name} must contain between 5 and 16 bytes encoded as hex");
    }
    let byte_len = compact.len() / 2;
    let mut out = [0u8; 16];
    for (index, byte) in out.iter_mut().enumerate().take(byte_len) {
        let start = index * 2;
        *byte = u8::from_str_radix(&compact[start..start + 2], 16)
            .unwrap_or_else(|_| panic!("{field_name} contains invalid hex"));
    }
    (out, byte_len)
}

fn parse_privilege_bytes(value: &str, field_name: &str) -> [u8; 3] {
    let compact: String = value.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if compact.len() != 6 {
        panic!("{field_name} must contain exactly 3 bytes encoded as hex");
    }
    let mut out = [0u8; 3];
    for (index, byte) in out.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&compact[start..start + 2], 16)
            .unwrap_or_else(|_| panic!("{field_name} contains invalid hex"));
    }
    out
}

fn parse_install_data_bytes(value: &str, field_name: &str) -> Vec<u8> {
    if value.trim().is_empty() {
        return Vec::new();
    }
    let compact: String = value.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if !compact.len().is_multiple_of(2) {
        panic!("{field_name} must contain an even number of hex digits");
    }
    let mut out = Vec::with_capacity(compact.len() / 2);
    for index in 0..(compact.len() / 2) {
        let start = index * 2;
        out.push(
            u8::from_str_radix(&compact[start..start + 2], 16)
                .unwrap_or_else(|_| panic!("{field_name} contains invalid hex")),
        );
    }
    out
}

fn is_rustlet_backend_path(value: &str) -> bool {
    value.starts_with("./") || value.starts_with('/')
}

fn rustlet_backend_crate_dir(
    package: &SecurityDomainPackageDecl,
    repo_root: &Path,
) -> Option<String> {
    let trimmed = package.path.trim();
    if !is_rustlet_backend_path(trimmed) {
        return None;
    }
    Some(normalize_rustlet_package_path(trimmed, repo_root))
}

fn normalize_rustlet_package_path(value: &str, repo_root: &Path) -> String {
    let trimmed = value.trim();
    let candidate = if trimmed.starts_with('/') {
        PathBuf::from(trimmed)
    } else {
        repo_root.join(trimmed)
    };
    let relative = candidate.strip_prefix(repo_root).unwrap_or_else(|_| {
        panic!(
            "rustlet security domain path '{}' must resolve inside repository root {}",
            trimmed,
            repo_root.display()
        )
    });
    relative.to_string_lossy().replace('\\', "/")
}

fn render_predeployment_manifest(
    manifest_path: &Path,
    root: &ParsedRootSecurityDomainDecl,
    security_domains: &[ParsedSecurityDomainDecl],
    rustlet_instances: &[ParsedRustletInstanceDecl],
    keys: &[ParsedKeyDecl],
) -> String {
    let mut out = String::new();
    writeln!(out, "// Generated from {}", manifest_path.display()).unwrap();
    writeln!(out, "// Do not edit by hand.").unwrap();
    writeln!(
        out,
        "pub const ROOT_SECURITY_DOMAIN_BACKEND: RootSecurityDomainBackend = RootSecurityDomainBackend::{};",
        root.backend
    )
    .unwrap();
    writeln!(
        out,
        "pub const ROOT_SECURITY_DOMAIN_PACKAGE_AID: Aid = Aid::from_array([{}]);",
        format_byte_list(&root.package_aid, root.package_aid_len)
    )
    .unwrap();
    writeln!(
        out,
        "pub const ROOT_SECURITY_DOMAIN_INSTANCE_AID: Aid = Aid::from_array([{}]);",
        format_byte_list(&root.instance_aid, root.instance_aid_len)
    )
    .unwrap();
    writeln!(
        out,
        "pub const ROOT_SECURITY_DOMAIN_PRIVILEGES: [u8; 3] = [{}];",
        format_byte_list(&root.install_bytes_prefix, root.install_bytes_prefix.len())
    )
    .unwrap();
    writeln!(
        out,
        "pub const ROOT_SECURITY_DOMAIN_INSTALL_PAYLOAD: &[u8] = &[{}];",
        format_byte_list(&root.install_payload, root.install_payload.len())
    )
    .unwrap();
    let issuer = security_domains
        .iter()
        .find(|domain| domain.role == "Issuer");
    match issuer {
        Some(issuer) => writeln!(
            out,
            "pub const ISSUER_SECURITY_DOMAIN_INSTANCE_AID: Option<Aid> = Some(Aid::from_array([{}]));",
            format_byte_list(&issuer.instance_aid, issuer.instance_aid_len)
        )
        .unwrap(),
        None => writeln!(
            out,
            "pub const ISSUER_SECURITY_DOMAIN_INSTANCE_AID: Option<Aid> = None;"
        )
        .unwrap(),
    }
    writeln!(
        out,
        "pub const PREDEPLOYED_SECURITY_DOMAINS: &[PredeployedSecurityDomain] = &["
    )
    .unwrap();
    for security_domain in security_domains {
        writeln!(
            out,
            "    PredeployedSecurityDomain {{ role: PredeployedSecurityDomainRole::{}, parent_instance_aid: Aid::from_array([{}]), backend: RootSecurityDomainBackend::{}, package_aid: Aid::from_array([{}]), instance_aid: Aid::from_array([{}]), privileges: [{}], install_payload: &[{}] }},",
            security_domain.role,
            format_byte_list(
                &security_domain.parent_instance_aid,
                security_domain.parent_instance_aid_len
            ),
            security_domain.backend,
            format_byte_list(&security_domain.package_aid, security_domain.package_aid_len),
            format_byte_list(&security_domain.instance_aid, security_domain.instance_aid_len),
            format_byte_list(
                &security_domain.install_bytes_prefix,
                security_domain.install_bytes_prefix.len()
            ),
            format_byte_list(&security_domain.install_payload, security_domain.install_payload.len()),
        )
        .unwrap();
    }
    writeln!(out, "];").unwrap();
    writeln!(out, "pub const PREDEPLOYED_KEYS: &[PredeployedKey] = &[").unwrap();
    for key in keys {
        writeln!(
            out,
            "    PredeployedKey {{ parent_instance_aid: Aid::from_array([{}]), key_type: PredeployedKeyType::{}, key_version: 0x{:02X}, key_id: 0x{:02X}, usage: PredeployedKeyUsage::{}, material: &[{}] }},",
            format_byte_list(&key.parent_instance_aid, key.parent_instance_aid_len),
            key.key_type,
            key.key_version,
            key.key_id,
            key.key_usage,
            format_byte_list(&key.material, key.material.len()),
        )
        .unwrap();
    }
    writeln!(out, "];").unwrap();
    writeln!(
        out,
        "pub const PREDEPLOYED_RUSTLET_INSTANCES: &[PredeployedRustletInstance] = &["
    )
    .unwrap();
    for instance in rustlet_instances {
        writeln!(
            out,
            "    PredeployedRustletInstance {{ parent_instance_aid: Aid::from_array([{}]), package_aid: Aid::from_array([{}]), applet_aid: Aid::from_array([{}]), instance_aid: Aid::from_array([{}]), install_parameters: &[{}] }},",
            format_byte_list(&instance.parent_instance_aid, instance.parent_instance_aid_len),
            format_byte_list(&instance.package_aid, instance.package_aid_len),
            format_byte_list(&instance.applet_aid, instance.applet_aid_len),
            format_byte_list(&instance.instance_aid, instance.instance_aid_len),
            format_byte_list(&instance.install_bytes, instance.install_bytes.len()),
        )
        .unwrap();
    }
    writeln!(out, "];").unwrap();
    out
}

fn collect_keys(
    output: &mut Vec<ParsedKeyDecl>,
    identities: &mut BTreeSet<(Vec<u8>, u8, u8, u8)>,
    parent_instance_aid: [u8; 16],
    parent_instance_aid_len: usize,
    keys: &[KeyDecl],
    field_name: &str,
) {
    for key in keys {
        let key_type = match key.key_type.trim() {
            "Scp03Static" => "Scp03Static",
            other => panic!("unsupported {field_name}.type '{other}'; expected Scp03Static"),
        };
        let (key_usage, key_usage_byte) = match key.usage.trim() {
            "Enc" => ("Enc", 0x01),
            "Mac" => ("Mac", 0x02),
            other => panic!("unsupported {field_name}.usage '{other}'; expected Enc or Mac"),
        };
        let material = parse_fixed_key_material(&key.material, field_name);
        let identity = (
            parent_instance_aid[..parent_instance_aid_len].to_vec(),
            key.version,
            key.id,
            key_usage_byte,
        );
        if !identities.insert(identity) {
            panic!(
                "duplicate {field_name} entry for version {}, id {}, usage {}",
                key.version, key.id, key_usage
            );
        }
        output.push(ParsedKeyDecl {
            parent_instance_aid,
            parent_instance_aid_len,
            key_type,
            key_version: key.version,
            key_id: key.id,
            key_usage,
            material,
        });
    }
}

fn parse_fixed_key_material(value: &str, field_name: &str) -> [u8; 16] {
    let bytes = parse_install_data_bytes(value, &format!("{field_name}.material"));
    bytes.try_into().unwrap_or_else(|bytes: Vec<u8>| {
        panic!(
            "{field_name}.material must contain exactly 16 bytes for Scp03Static, got {}",
            bytes.len()
        )
    })
}

fn collect_rustlet_instances_from_packages(
    output: &mut Vec<ParsedRustletInstanceDecl>,
    parent_instance_aid: [u8; 16],
    parent_instance_aid_len: usize,
    packages: &[RustletPackageDecl],
) {
    for package in packages {
        let embedded = find_embedded_rustlet_by_crate_dir(&package.path).unwrap_or_else(|| {
            panic!(
                "unknown embedded rustlet path '{}' in predeployment manifest",
                package.path
            )
        });
        for instance in &package.instances {
            let (instance_aid, instance_aid_len) =
                parse_aid_bytes(&instance.aid, "packages[].instances[].aid");
            let install_bytes = parse_install_data_bytes(
                &instance.install_bytes,
                "packages[].instances[].install_bytes",
            );
            output.push(ParsedRustletInstanceDecl {
                parent_instance_aid,
                parent_instance_aid_len,
                package_aid: embedded.package_aid,
                package_aid_len: embedded.package_aid_len,
                applet_aid: embedded.applet_aid,
                applet_aid_len: embedded.applet_aid_len,
                instance_aid,
                instance_aid_len,
                install_bytes,
            });
        }
    }
}

fn format_byte_list(bytes: &[u8], len: usize) -> String {
    let mut out = String::new();
    for (index, byte) in bytes.iter().take(len).enumerate() {
        if index != 0 {
            out.push_str(", ");
        }
        write!(out, "0x{byte:02X}").unwrap();
    }
    out
}

fn find_embedded_rustlet_by_crate_dir(
    crate_dir: &str,
) -> Option<&'static EmbeddedRustletBuildSpec> {
    let normalized = crate_dir
        .strip_prefix("./")
        .unwrap_or(crate_dir)
        .trim_end_matches('/');
    EMBEDDED_RUSTLET_SPECS.iter().find(|spec| {
        spec.crate_dir == normalized || spec.crate_dir.rsplit('/').next() == Some(normalized)
    })
}

const fn pad_aid_bytes(bytes: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut index = 0;
    while index < bytes.len() {
        out[index] = bytes[index];
        index += 1;
    }
    out
}
