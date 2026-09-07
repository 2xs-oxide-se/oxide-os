use crate::apdu_layer::ApduCommand;
use crate::apdu_manager::ApduStatus;
use rustlet_runtime::SEApdu;

// A GlobalPlatform image may deliberately select no modules, in which case
// the generated initializer slice has no trait references.
#[allow(dead_code)]
pub(crate) trait KernelAppModule {
    fn initialize();
}

pub(crate) type KernelAppModuleInitializer = fn();
pub(crate) type AfterApduHook = fn();
pub(crate) type PreserveClearApduSessionHook = fn(&ApduCommand) -> bool;
pub(crate) type BeforeRustletHook = fn(crate::core::isolation::AppMemoryWindow);
pub(crate) type AfterRustletHook = fn(crate::core::isolation::AppMemoryWindow);

#[derive(Clone, Copy)]
pub(crate) struct ApduFilter {
    pub matches: fn(&dyn SEApdu) -> bool,
    pub process: fn(&mut dyn SEApdu) -> ApduStatus,
}

macro_rules! register_kernel_app_modules {
    ($({
        name: $name:literal,
        module: $module:ident,
        path: $path:literal,
        hooks: [$($hook:ident),* $(,)?],
    },)*) => {
        $(
            #[cfg(oxide_se_kernel_app_module = $name)]
            #[path = $path]
            mod $module;
        )*
    };
}

include!("kernel_app_modules_registry.inc.rs");

macro_rules! compose_kernel_app_modules {
    (
        initializers: [$($initializer:expr),* $(,)?],
        apdu_filters: [$($apdu_filter:expr),* $(,)?],
        after_apdu_hooks: [$($after_apdu_hook:expr),* $(,)?],
        before_rustlet_hooks: [$($before_rustlet_hook:expr),* $(,)?],
        after_rustlet_hooks: [$($after_rustlet_hook:expr),* $(,)?],
        preserve_clear_apdu_session_hooks: [
            $($preserve_clear_apdu_session_hook:expr),* $(,)?
        ],
    ) => {
        static KERNEL_APP_MODULE_INITIALIZERS: &[KernelAppModuleInitializer] = &[
            $($initializer),*
        ];
        static APDU_FILTERS: &[ApduFilter] = &[$($apdu_filter),*];
        static AFTER_APDU_HOOKS: &[AfterApduHook] = &[$($after_apdu_hook),*];
        static BEFORE_RUSTLET_HOOKS: &[BeforeRustletHook] = &[$($before_rustlet_hook),*];
        static AFTER_RUSTLET_HOOKS: &[AfterRustletHook] = &[$($after_rustlet_hook),*];
        static PRESERVE_CLEAR_APDU_SESSION_HOOKS: &[PreserveClearApduSessionHook] = &[
            $($preserve_clear_apdu_session_hook),*
        ];
    };
}

include!(concat!(env!("OUT_DIR"), "/kernel_app_modules.inc.rs"));

pub(crate) fn initialize() {
    for initialize in KERNEL_APP_MODULE_INITIALIZERS {
        initialize();
    }
}

pub(crate) fn filter_apdu(apdu: &mut dyn SEApdu) -> Option<ApduStatus> {
    for filter in APDU_FILTERS {
        if (filter.matches)(apdu) {
            return Some((filter.process)(apdu));
        }
    }
    None
}

pub(crate) fn after_apdu() {
    for hook in AFTER_APDU_HOOKS {
        hook();
    }
}

pub(crate) fn before_rustlet(stack: crate::core::isolation::AppMemoryWindow) {
    for hook in BEFORE_RUSTLET_HOOKS {
        hook(stack);
    }
}

pub(crate) fn after_rustlet(stack: crate::core::isolation::AppMemoryWindow) {
    for hook in AFTER_RUSTLET_HOOKS {
        hook(stack);
    }
}

pub(crate) fn preserves_clear_apdu_session(command: &ApduCommand) -> bool {
    PRESERVE_CLEAR_APDU_SESSION_HOOKS
        .iter()
        .any(|hook| hook(command))
}
