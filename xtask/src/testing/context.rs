//! Explicit build inputs shared by a campaign and its individual boots.
use super::*;

/// Cloning a context changes a scenario's inputs, never the process environment.
/// Session state belongs to the target, not to this configuration.
#[derive(Clone, Debug)]
pub(crate) struct BuildContext {
    pub(crate) config: Option<PathBuf>,
    pub(crate) trace: TraceMode,
    pub(crate) check_stack: bool,
    /// Porting scope: run kernel SCP assertions without loading application code.
    pub(crate) without_rustlets: bool,
    pub(crate) fault_test: Option<&'static str>,
    /// Shared only within one invocation; never caches a running target.
    pub(crate) images: std::rc::Rc<std::cell::RefCell<super::target::ImageCache>>,
}

#[derive(Clone, Debug)]
pub(crate) enum TargetOptions {
    Qemu,
    OpenOcd(super::openocd::Options),
}

/// Complete test execution context. Build inputs and target/deployment options
/// deliberately live in separate objects.
#[derive(Clone, Debug)]
pub(crate) struct TestContext {
    pub(crate) build: BuildContext,
    pub(crate) target: TargetOptions,
    pub(crate) update_stack_baseline: bool,
    pub(crate) apdu_observer: Option<std::rc::Rc<std::cell::RefCell<StackObserver>>>,
}

#[cfg(test)]
// The tests exercise the manifest transformation defined later in this module.
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    #[test]
    fn kernel_scp_scope_removes_all_application_predeployment() {
        let root = repo_root().unwrap();
        for profile in ["scp03", "scp03_s16", "scp11a", "scp11b", "scp11c"] {
            let input =
                fs::read_to_string(root.join(format!("configs/config_{profile}_test.toml")))
                    .unwrap();
            let original: toml::Value = toml::from_str(&input).unwrap();
            let reduced: toml::Value =
                toml::from_str(&kernel_scp_manifest(&input).unwrap()).unwrap();
            assert_eq!(reduced["secure_channel"], original["secure_channel"]);
            assert_eq!(reduced["root"]["instance"], original["root"]["instance"]);
            assert_eq!(reduced["root"].get("keys"), original["root"].get("keys"));
            assert!(reduced["root"].get("packages").is_none(), "{profile}");
            assert!(reduced.get("security_domains").is_none());
            let config: PredeploymentManifestConfig =
                toml::from_str(&toml::to_string(&reduced).unwrap()).unwrap();
            assert!(config.root.unwrap().packages.is_empty());
        }
    }

    #[test]
    fn kernel_scp_scope_requires_kernel_authority_and_drops_child_domains() {
        let root = repo_root().unwrap();
        let null = fs::read_to_string(root.join("configs/config_noscp_test.toml")).unwrap();
        assert!(kernel_scp_manifest(&null).is_err());
        let mut input = fs::read_to_string(root.join("configs/config_scp03_test.toml")).unwrap();
        input.push_str("\n[[security_domains]]\n[security_domains.package]\nname = './rustlets/complete_security_domain'\n");
        let reduced: toml::Value = toml::from_str(&kernel_scp_manifest(&input).unwrap()).unwrap();
        assert!(reduced.get("security_domains").is_none());
        assert!(kernel_scp_manifest("[kernel-image]\nmode='kernel-only'").is_err());
    }

    #[test]
    fn profile_and_fault_changes_are_local_to_the_derived_context() {
        let base = BuildContext::default().with_config("configs/config_scp03_test.toml");
        let changed = base
            .with_config("configs/config_scp03_s16_test.toml")
            .with_fault("OXIDE_SE_KERNEL_RAM_NX_TEST");
        assert_eq!(base.trace, TraceMode::None);
        assert_eq!(base.fault_test, None);
        assert_ne!(base.config, changed.config);
        assert!(std::rc::Rc::ptr_eq(&base.images, &changed.images));
    }

    #[test]
    fn build_variables_are_child_local_and_clear_inherited_protocol_settings() {
        let root = repo_root().unwrap();
        let ctx = BuildContext::default().with_config("configs/config_kernel_ping.toml");
        let before = std::env::var_os("OXIDE_SE_BUILD_CONFIG");
        let settings = BuildManifestEnv::resolve(&ctx, &root, "mps2-an385", "qemu").unwrap();
        let mut command = Command::new("cargo");
        command.env("OXIDE_SE_SCP03_PROFILE", "S16");
        settings.apply(&mut command);
        let vars: std::collections::BTreeMap<_, _> = command.get_envs().collect();
        assert_eq!(
            vars.get(std::ffi::OsStr::new("OXIDE_SE_SCP03_PROFILE")),
            Some(&None)
        );
        assert_eq!(
            vars.get(std::ffi::OsStr::new("OXIDE_SE_BOARD")),
            Some(&Some(std::ffi::OsStr::new("mps2-an385")))
        );
        assert_eq!(
            vars.get(std::ffi::OsStr::new("OXIDE_SE_KERNEL_RAM_NX_TEST")),
            Some(&None)
        );
        assert_eq!(std::env::var_os("OXIDE_SE_BUILD_CONFIG"), before);
    }
}

impl Default for BuildContext {
    fn default() -> Self {
        Self {
            config: None,
            trace: TraceMode::None,
            check_stack: false,
            without_rustlets: false,
            fault_test: None,
            images: Default::default(),
        }
    }
}

impl Default for TestContext {
    fn default() -> Self {
        Self {
            build: BuildContext::default(),
            target: TargetOptions::Qemu,
            update_stack_baseline: false,
            apdu_observer: None,
        }
    }
}

impl TestContext {
    pub(crate) fn execution_env(&self) -> &'static str {
        match self.target {
            TargetOptions::Qemu => "qemu",
            TargetOptions::OpenOcd(_) => "hardware",
        }
    }

    pub(crate) fn openocd(&self) -> Option<&super::openocd::Options> {
        match &self.target {
            TargetOptions::Qemu => None,
            TargetOptions::OpenOcd(options) => Some(options),
        }
    }

    pub(crate) fn with_config(&self, config: impl Into<PathBuf>) -> Self {
        Self {
            build: self.build.with_config(config),
            target: self.target.clone(),
            update_stack_baseline: self.update_stack_baseline,
            apdu_observer: self.apdu_observer.clone(),
        }
    }

    pub(crate) fn with_fault(&self, fault: &'static str) -> Self {
        Self {
            build: self.build.with_fault(fault),
            target: self.target.clone(),
            update_stack_baseline: self.update_stack_baseline,
            apdu_observer: self.apdu_observer.clone(),
        }
    }

    pub(crate) fn with_apdu_observer(
        &self,
        observer: std::rc::Rc<std::cell::RefCell<StackObserver>>,
    ) -> Self {
        Self {
            build: self.build.clone(),
            target: self.target.clone(),
            update_stack_baseline: self.update_stack_baseline,
            apdu_observer: Some(observer),
        }
    }
}

impl BuildContext {
    pub(crate) fn with_config(&self, config: impl Into<PathBuf>) -> Self {
        Self {
            config: Some(config.into()),
            ..self.clone()
        }
    }

    pub(crate) fn with_fault(&self, fault: &'static str) -> Self {
        Self {
            trace: TraceMode::Semihosting,
            fault_test: Some(fault),
            ..self.clone()
        }
    }

    pub(crate) fn manifest_path(&self, root: &Path) -> PathBuf {
        let path = self
            .config
            .clone()
            .unwrap_or_else(|| PathBuf::from(default_predeployment_config_relpath(root)));
        if path.is_absolute() {
            path
        } else {
            root.join(path)
        }
    }

    /// Instrument the selected profile, including profiles selected by a suite.
    pub(crate) fn effective_config(&self, root: &Path) -> Result<PathBuf, Box<dyn Error>> {
        let path = self.manifest_path(root);
        if self.without_rustlets {
            let input = fs::read_to_string(&path)?;
            let output = kernel_scp_manifest(&input)?;
            // Content addressing avoids mixing two profiles or concurrent builds.
            use std::hash::{Hash, Hasher};
            let mut hash = std::collections::hash_map::DefaultHasher::new();
            output.hash(&mut hash);
            let directory = root.join("target/xtask/generated-configs");
            fs::create_dir_all(&directory)?;
            let path = directory.join(format!("kernel_scp_{:016x}.toml", hash.finish()));
            if fs::read_to_string(&path).ok().as_deref() != Some(&output) {
                // Publish complete TOML, so a concurrent build never reads a
                // half-written file even when it requests the same profile.
                let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
                fs::write(&temporary, output)?;
                fs::rename(temporary, &path)?;
            }
            return Ok(path);
        }
        if self.check_stack {
            generate_stack_monitor_config(Some(&path))
        } else {
            Ok(path)
        }
    }
}

/// Keep the selected kernel authority, keys and SCP profile, but no Rustlet
/// payload or child SD. In particular SCP11b must not preinstall its test app.
fn kernel_scp_manifest(input: &str) -> Result<String, Box<dyn Error>> {
    let mut manifest: toml::Value = toml::from_str(input)?;
    let table = manifest.as_table_mut().ok_or("expected a manifest table")?;
    let root = table
        .get_mut("root")
        .and_then(toml::Value::as_table_mut)
        .ok_or("--without-rustlets requires a root KernelSecurityDomain")?;
    if root
        .get("package")
        .and_then(|p| p.get("name"))
        .and_then(toml::Value::as_str)
        != Some("KernelSecurityDomain")
    {
        return Err("--without-rustlets requires a root KernelSecurityDomain".into());
    }
    root.remove("packages");
    table.remove("security_domains");
    Ok(toml::to_string_pretty(&manifest)?)
}
