#![no_std]
#![cfg_attr(feature = "runtime", feature(alloc_error_handler))]

#[cfg(feature = "runtime")]
extern crate alloc;

mod abi;
mod apdu;
mod crypto;
pub mod gp;
pub mod persistence;
#[cfg(feature = "runtime")]
mod security_domain;
pub mod syscall;
pub mod syscall_abi;
mod syscall_backend;

pub use abi::*;
pub use apdu::*;
pub use crypto::*;
pub use persistence::{PersistenceError, StateReader, StateWriter};
#[cfg(feature = "runtime")]
pub use security_domain::*;
pub use serde;
pub use syscall_abi::{
    CryptoCipherDoFinalParams, CryptoEcCurve, CryptoEcGenerateKeypairParams,
    CryptoEcdhDoFinalParams, CryptoErrorCode, CryptoHkdfSha256Params, CryptoMacDoFinalParams,
    CryptoMacOperation, CryptoRandomGenerateParams, CryptoX963Sha256Params, RuntimeReturnKind,
    RuntimeSyscall, Scp03LoadKeyParams, SyscallNumber, SyscallWord,
};

#[cfg(feature = "runtime")]
pub mod rt;

#[cfg(feature = "runtime")]
pub use rt::{PostcardState, Rustlet};

#[cfg(feature = "runtime")]
#[macro_export]
/// Declares a Rustlet entry point and its private heap.
///
/// The generated entry point exposes only the lifecycle handlers consumed by the
/// kernel. Persistent state is loaded and saved inside the Rustlet runtime
/// around `install` and `process_apdu`.
macro_rules! declare_rustlet {
    // --- Public API Overloads ---

    // Default overload: use implicit install with a default heap size (768 bytes).
    ($app_ty:ty) => {
        $crate::declare_rustlet!(@implicit $app_ty, 768usize);
    };

    // Custom heap size overload with implicit install.
    ($app_ty:ty, $heap_size:expr) => {
        $crate::declare_rustlet!(@implicit $app_ty, $heap_size);
    };

    // Fully explicit overload: custom heap size and custom install function.
    ($app_ty:ty, $heap_size:expr, $install_fn:path) => {
        $crate::declare_rustlet!(@explicit $app_ty, $heap_size, $install_fn);
    };

    // --- Internal Implementation Detail: Implicit Installation ---
    (@implicit $app_ty:ty, $heap_size:expr) => {
        #[doc(hidden)]
        /// Internal adapter for apps implementing Default for installation.
        fn __oxide_se_implicit_install(ctx: &mut $crate::RustletCtx) -> core::result::Result<$app_ty, $crate::ApduStatus> {
            <$app_ty as $crate::rt::DeclareAppWithoutInstallRequiresDefault>::implicit_install(
                ctx,
            )
        }

        $crate::declare_rustlet!(@explicit $app_ty, $heap_size, __oxide_se_implicit_install);
    };

    // --- Internal Implementation Detail: The Core Entry Point ---
    (@explicit $app_ty:ty, $heap_size:expr, $install_fn:path) => {
        extern crate alloc;

        #[doc(hidden)]
        static __OXIDE_SE_RUSTLET_HEAP_STORAGE: $crate::rt::RustletHeapStorage<{ $heap_size }> =
            $crate::rt::RustletHeapStorage::new();

        #[doc(hidden)]
        /// Bridges the typed install function with the boxed trait object required by the runtime.
        fn __oxide_se_install_adapter(
            ctx: &mut $crate::RustletCtx,
        ) -> core::result::Result<$crate::rt::RuntimeInstance, $crate::ApduStatus> {
            let instance: $app_ty = $install_fn(ctx)?;
            Ok($crate::rt::RuntimeInstance::App(alloc::boxed::Box::new(
                $crate::rt::PersistentRustlet::new(instance),
            )))
        }

        #[doc(hidden)]
        fn __oxide_se_load_adapter(
            _ctx: &mut $crate::RustletCtx,
        ) -> core::result::Result<$crate::rt::RuntimeInstance, $crate::ApduStatus>
        where
            $app_ty: core::default::Default,
        {
            let instance = <$app_ty as core::default::Default>::default();
            Ok($crate::rt::RuntimeInstance::App(alloc::boxed::Box::new(
                $crate::rt::PersistentRustlet::new(instance),
            )))
        }

        #[unsafe(no_mangle)]
        #[doc(hidden)]
        /// Low-level entry point called by the Kernel.
        /// Initializes the allocator with the local storage and starts the Rustlet runtime.
        pub extern "C" fn start(buffer: *mut $crate::RustletCtx) -> ! {
            unsafe {
                $crate::rt::start(
                    __oxide_se_install_adapter,
                    __oxide_se_load_adapter,
                    buffer,
                    __OXIDE_SE_RUSTLET_HEAP_STORAGE.as_mut_ptr(),
                    $heap_size,
                )
            }
        }
    };
}

#[cfg(feature = "runtime")]
#[macro_export]
/// Alias for `declare_rustlet!` to maintain compatibility with legacy "app" terminology.
macro_rules! declare_app {
    ($($tt:tt)*) => {
        $crate::declare_rustlet!($($tt)*);
    };
}

#[cfg(feature = "runtime")]
#[macro_export]
/// Declares a Rustlet that can also act as a user-land Security Domain.
///
/// The concrete type must implement both [`Rustlet`] and
/// [`RustletSecurityDomain`]. It remains a normal selectable Rustlet through
/// `process_apdu`, while the kernel can also call the generated Security
/// Domain vtable through a proxy.
macro_rules! declare_security_domain {
    // Default overload: use implicit install with a default heap size (768 bytes).
    ($app_ty:ty) => {
        $crate::declare_security_domain!(@implicit $app_ty, 768usize);
    };

    // Custom heap size overload with implicit install.
    ($app_ty:ty, $heap_size:expr) => {
        $crate::declare_security_domain!(@implicit $app_ty, $heap_size);
    };

    // Fully explicit overload: custom heap size and custom install function.
    ($app_ty:ty, $heap_size:expr, $install_fn:path) => {
        $crate::declare_security_domain!(@explicit $app_ty, $heap_size, $install_fn);
    };

    (@implicit $app_ty:ty, $heap_size:expr) => {
        #[doc(hidden)]
        fn __oxide_se_implicit_install(ctx: &mut $crate::RustletCtx) -> core::result::Result<$app_ty, $crate::ApduStatus> {
            <$app_ty as $crate::rt::DeclareAppWithoutInstallRequiresDefault>::implicit_install(
                ctx,
            )
        }

        $crate::declare_security_domain!(@explicit $app_ty, $heap_size, __oxide_se_implicit_install);
    };

    (@explicit $app_ty:ty, $heap_size:expr, $install_fn:path) => {
        extern crate alloc;

        #[doc(hidden)]
        static __OXIDE_SE_RUSTLET_HEAP_STORAGE: $crate::rt::RustletHeapStorage<{ $heap_size }> =
            $crate::rt::RustletHeapStorage::new();

        #[doc(hidden)]
        fn __oxide_se_install_adapter(
            ctx: &mut $crate::RustletCtx,
        ) -> core::result::Result<$crate::rt::RuntimeInstance, $crate::ApduStatus> {
            fn __oxide_se_assert_security_domain<T: $crate::RustletSecurityDomain>() {}
            __oxide_se_assert_security_domain::<$app_ty>();
            let instance: $app_ty = $install_fn(ctx)?;
            let mut instance = $crate::rt::PersistentSecurityDomain::new(instance);
            instance.initialize_from_install_apdu(ctx)?;
            Ok($crate::rt::RuntimeInstance::SecurityDomain(
                alloc::boxed::Box::new(instance),
            ))
        }

        #[doc(hidden)]
        fn __oxide_se_load_adapter(
            _ctx: &mut $crate::RustletCtx,
        ) -> core::result::Result<$crate::rt::RuntimeInstance, $crate::ApduStatus>
        where
            $app_ty: core::default::Default,
        {
            fn __oxide_se_assert_security_domain<T: $crate::RustletSecurityDomain>() {}
            __oxide_se_assert_security_domain::<$app_ty>();
            let instance = <$app_ty as core::default::Default>::default();
            Ok($crate::rt::RuntimeInstance::SecurityDomain(
                alloc::boxed::Box::new($crate::rt::PersistentSecurityDomain::new(instance)),
            ))
        }

        #[unsafe(no_mangle)]
        #[doc(hidden)]
        pub extern "C" fn start(buffer: *mut $crate::RustletCtx) -> ! {
            unsafe {
                $crate::rt::start_security_domain(
                    __oxide_se_install_adapter,
                    __oxide_se_load_adapter,
                    buffer,
                    __OXIDE_SE_RUSTLET_HEAP_STORAGE.as_mut_ptr(),
                    $heap_size,
                )
            }
        }
    };
}
