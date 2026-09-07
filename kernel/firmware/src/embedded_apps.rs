use rustlet_runtime::Aid;

#[derive(Clone, Copy)]
pub struct EmbeddedRegistrySeed {
    pub package_aid: Aid,
    pub applet_aid: Aid,
    pub fae: &'static [u8],
}

#[cfg(not(oxide_se_kernel_image_kernel_only))]
#[derive(Clone, Copy)]
struct EmbeddedRustletRuntimeSpec {
    package_aid: Aid,
    applet_aid: Aid,
    fae_getter: fn() -> &'static [u8],
}

#[cfg(not(oxide_se_kernel_image_kernel_only))]
#[allow(unused_macros)]
macro_rules! aid_value {
    (aid: $aid:expr) => {
        Aid::from_array($aid)
    };
    (aids: { package_applet: $package_applet:expr, instance: $instance:expr }) => {
        Aid::from_array($instance)
    };
    (aids: { package: $package:expr, applet: $applet:expr, instance: $instance:expr }) => {
        Aid::from_array($instance)
    };
}

#[cfg(not(oxide_se_kernel_image_kernel_only))]
#[allow(unused_macros)]
macro_rules! package_aid_value {
    (aid: $aid:expr) => {
        Aid::from_array($aid)
    };
    (aids: { package_applet: $package_applet:expr, instance: $instance:expr }) => {
        Aid::from_array($package_applet)
    };
    (aids: { package: $package:expr, applet: $applet:expr, instance: $instance:expr }) => {
        Aid::from_array($package)
    };
}

#[cfg(not(oxide_se_kernel_image_kernel_only))]
#[allow(unused_macros)]
macro_rules! applet_aid_value {
    (aid: $aid:expr) => {
        Aid::from_array($aid)
    };
    (aids: { package_applet: $package_applet:expr, instance: $instance:expr }) => {
        Aid::from_array($package_applet)
    };
    (aids: { package: $package:expr, applet: $applet:expr, instance: $instance:expr }) => {
        Aid::from_array($applet)
    };
}

#[cfg(not(oxide_se_kernel_image_kernel_only))]
#[allow(unused_macros)]
macro_rules! runtime_item {
    (
        $aid_const:ident,
        $getter:ident,
        $env_var:expr,
        $aid_kind:ident : $aid_spec:tt
    ) => {
        #[allow(dead_code)]
pub const $aid_const: Aid = aid_value!($aid_kind: $aid_spec);

        fn $getter() -> &'static [u8] {
            #[repr(C, align(2048))]
            struct AlignedBytes<const N: usize> {
                bytes: [u8; N],
            }

            static BIN: AlignedBytes<{ include_bytes!(env!($env_var)).len() }> = AlignedBytes {
                bytes: *include_bytes!(env!($env_var)),
            };

            &BIN.bytes
        }
    };
}

#[cfg(not(oxide_se_kernel_image_kernel_only))]
macro_rules! runtime_decl {
    (
        name: COMPLETE_SECURITY_DOMAIN,
        aid_const: $aid_const:ident,
        getter: $getter:ident,
        selected_cfg: $selected_cfg:ident,
        env_var: $env_var:expr,
        minimal: true,
        $aid_kind:ident : $aid_spec:tt
    ) => {
        #[cfg($selected_cfg)]
        runtime_item!($aid_const, $getter, $env_var, $aid_kind: $aid_spec);
    };
    (
        name: COMPLETE_SECURITY_DOMAIN,
        aid_const: $aid_const:ident,
        getter: $getter:ident,
        selected_cfg: $selected_cfg:ident,
        env_var: $env_var:expr,
        minimal: false,
        $aid_kind:ident : $aid_spec:tt
    ) => {
        #[cfg($selected_cfg)]
        runtime_item!($aid_const, $getter, $env_var, $aid_kind: $aid_spec);
    };
    (
        name: $name:ident,
        aid_const: $aid_const:ident,
        getter: $getter:ident,
        selected_cfg: $selected_cfg:ident,
        env_var: $env_var:expr,
        minimal: true,
        $aid_kind:ident : $aid_spec:tt
    ) => {
        #[cfg($selected_cfg)]
        runtime_item!($aid_const, $getter, $env_var, $aid_kind: $aid_spec);
    };
    (
        name: $name:ident,
        aid_const: $aid_const:ident,
        getter: $getter:ident,
        selected_cfg: $selected_cfg:ident,
        env_var: $env_var:expr,
        minimal: false,
        $aid_kind:ident : $aid_spec:tt
    ) => {
        #[cfg($selected_cfg)]
        runtime_item!($aid_const, $getter, $env_var, $aid_kind: $aid_spec);
    };
}

#[cfg(not(oxide_se_kernel_image_kernel_only))]
macro_rules! runtime_spec {
    (
        name: COMPLETE_SECURITY_DOMAIN,
        getter: $getter:ident,
        selected_cfg: $selected_cfg:ident,
        minimal: $minimal:tt,
        $aid_kind:ident : $aid_spec:tt
    ) => {
        #[cfg($selected_cfg)]
        EmbeddedRustletRuntimeSpec {
            package_aid: package_aid_value!($aid_kind: $aid_spec),
            applet_aid: applet_aid_value!($aid_kind: $aid_spec),
            fae_getter: $getter,
        }
    };
    (
        name: $name:ident,
        getter: $getter:ident,
        selected_cfg: $selected_cfg:ident,
        minimal: true,
        $aid_kind:ident : $aid_spec:tt
    ) => {
        #[cfg($selected_cfg)]
        EmbeddedRustletRuntimeSpec {
            package_aid: package_aid_value!($aid_kind: $aid_spec),
            applet_aid: applet_aid_value!($aid_kind: $aid_spec),
            fae_getter: $getter,
        }
    };
    (
        name: $name:ident,
        getter: $getter:ident,
        selected_cfg: $selected_cfg:ident,
        minimal: false,
        $aid_kind:ident : $aid_spec:tt
    ) => {
        #[cfg($selected_cfg)]
        EmbeddedRustletRuntimeSpec {
            package_aid: package_aid_value!($aid_kind: $aid_spec),
            applet_aid: applet_aid_value!($aid_kind: $aid_spec),
            fae_getter: $getter,
        }
    };
}

#[cfg(not(oxide_se_kernel_image_kernel_only))]
macro_rules! register_embedded_rustlets {
    ($({
        name: $name:ident,
        aid_const: $aid_const:ident,
        getter: $getter:ident,
        selected_cfg: $selected_cfg:ident,
        crate_dir: $crate_dir:expr,
        bin_name: $bin_name:expr,
        env_var: $env_var:expr,
        minimal: $minimal:tt,
        $aid_kind:ident : $aid_spec:tt
        $(,)?
    },)*) => {
        $(
            runtime_decl!(
                name: $name,
                aid_const: $aid_const,
                getter: $getter,
                selected_cfg: $selected_cfg,
                env_var: $env_var,
                minimal: $minimal,
                $aid_kind: $aid_spec
            );
        )*
        const EMBEDDED_RUSTLET_SPECS: &[EmbeddedRustletRuntimeSpec] = &[
            $(
                runtime_spec!(
                    name: $name,
                    getter: $getter,
                    selected_cfg: $selected_cfg,
                    minimal: $minimal,
                    $aid_kind: $aid_spec
                ),
            )*
        ];
    };
}

#[cfg(not(oxide_se_kernel_image_kernel_only))]
include!("embedded_apps_registry.inc.rs");

#[cfg(oxide_se_kernel_image_kernel_only)]
pub fn for_each_embedded_registry_seed(_f: impl FnMut(EmbeddedRegistrySeed)) {}

#[cfg(not(oxide_se_kernel_image_kernel_only))]
pub fn for_each_embedded_registry_seed(mut f: impl FnMut(EmbeddedRegistrySeed)) {
    for spec in EMBEDDED_RUSTLET_SPECS {
        f(EmbeddedRegistrySeed {
            package_aid: spec.package_aid,
            applet_aid: spec.applet_aid,
            fae: (spec.fae_getter)(),
        });
    }
}
