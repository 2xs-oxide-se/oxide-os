pub mod runtime {
    pub mod descriptor_return {
        pub fn trigger(descriptor: *const crate::SelectedAppDescriptor) -> ! {
            crate::syscall_backend::svc_3::<{ crate::syscall_abi::RETURN_TO_KERNEL }>(
                descriptor as usize,
                0,
                crate::syscall_abi::RuntimeReturnKind::Descriptor.word(),
            );
            loop {
                core::hint::spin_loop();
            }
        }
    }

    pub mod exit {
        pub fn trigger(status: crate::ApduStatus) -> ! {
            crate::syscall_backend::svc_3::<{ crate::syscall_abi::RETURN_TO_KERNEL }>(
                status.sw1 as usize,
                status.sw2 as usize,
                crate::syscall_abi::RuntimeReturnKind::Exit.word(),
            );
            loop {
                core::hint::spin_loop();
            }
        }
    }

    pub mod handler_return {
        pub fn trigger(status: crate::ApduStatus) -> ! {
            crate::syscall_backend::svc_3::<{ crate::syscall_abi::RETURN_TO_KERNEL }>(
                status.sw1 as usize,
                status.sw2 as usize,
                crate::syscall_abi::RuntimeReturnKind::HandlerReturn.word(),
            );
            loop {
                core::hint::spin_loop();
            }
        }
    }

    pub mod panic {
        pub fn trigger() -> ! {
            super::exit::trigger(crate::ApduStatus::internal_error())
        }
    }

    pub mod allocator {
        use core::alloc::Layout;

        pub fn alloc(layout: Layout) -> *mut u8 {
            crate::syscall_backend::svc_2::<{ crate::syscall_abi::ALLOC }>(
                layout.size(),
                layout.align(),
            ) as *mut u8
        }

        /// # Safety
        ///
        /// `ptr` and `layout` must describe a live allocation previously
        /// returned by `alloc` for the current Rustlet heap.
        pub unsafe fn dealloc(ptr: *mut u8, layout: Layout) {
            crate::syscall_backend::svc_3::<{ crate::syscall_abi::DEALLOC }>(
                ptr as usize,
                layout.size(),
                layout.align(),
            )
        }
    }

    pub mod apdu {
        pub mod set_incoming_and_receive {
            pub fn trigger() -> usize {
                crate::syscall_backend::svc_2::<{ crate::syscall_abi::APDU_SET_INCOMING_AND_RECEIVE }>(
                    0, 0,
                )
            }
        }

        pub mod set_outgoing {
            pub fn trigger() {
                let _ = crate::syscall_backend::svc_2::<{ crate::syscall_abi::APDU_SET_OUTGOING }>(
                    0, 0,
                );
            }
        }

        pub mod set_outgoing_length {
            pub fn trigger(len: usize) {
                let _ = crate::syscall_backend::svc_2::<
                    { crate::syscall_abi::APDU_SET_OUTGOING_LENGTH },
                >(len, 0);
            }
        }
    }

    pub mod crypto {
        pub mod cipher_do_final {
            pub fn trigger(params: &crate::syscall_abi::CryptoCipherDoFinalParams) -> usize {
                crate::syscall_backend::svc_2::<{ crate::syscall_abi::CRYPTO_CIPHER_DO_FINAL }>(
                    params as *const _ as usize,
                    0,
                )
            }
        }

        pub mod random_generate {
            pub fn trigger(params: &crate::syscall_abi::CryptoRandomGenerateParams) -> usize {
                crate::syscall_backend::svc_2::<{ crate::syscall_abi::CRYPTO_RANDOM_GENERATE }>(
                    params as *const _ as usize,
                    0,
                )
            }
        }

        pub mod mac_do_final {
            pub fn trigger(params: &crate::syscall_abi::CryptoMacDoFinalParams) -> usize {
                crate::syscall_backend::svc_2::<{ crate::syscall_abi::CRYPTO_MAC_DO_FINAL }>(
                    params as *const _ as usize,
                    0,
                )
            }
        }

        pub mod load_scp03_key {
            pub fn trigger(params: &crate::syscall_abi::Scp03LoadKeyParams) -> usize {
                crate::syscall_backend::svc_2::<
                    { crate::syscall_abi::SECURITY_DOMAIN_LOAD_SCP03_KEY },
                >(params as *const _ as usize, 0)
            }
        }

        pub mod ec_generate_keypair {
            pub fn trigger(params: &crate::syscall_abi::CryptoEcGenerateKeypairParams) -> usize {
                crate::syscall_backend::svc_2::<{ crate::syscall_abi::CRYPTO_EC_GENERATE_KEYPAIR }>(
                    params as *const _ as usize,
                    0,
                )
            }
        }

        pub mod ecdh_do_final {
            pub fn trigger(params: &crate::syscall_abi::CryptoEcdhDoFinalParams) -> usize {
                crate::syscall_backend::svc_2::<{ crate::syscall_abi::CRYPTO_ECDH_DO_FINAL }>(
                    params as *const _ as usize,
                    0,
                )
            }
        }

        pub mod hkdf_sha256 {
            pub fn trigger(params: &crate::syscall_abi::CryptoHkdfSha256Params) -> usize {
                crate::syscall_backend::svc_2::<{ crate::syscall_abi::CRYPTO_HKDF_SHA256 }>(
                    params as *const _ as usize,
                    0,
                )
            }
        }

        pub mod x963_sha256 {
            pub fn trigger(params: &crate::syscall_abi::CryptoX963Sha256Params) -> usize {
                crate::syscall_backend::svc_2::<{ crate::syscall_abi::CRYPTO_X963_SHA256 }>(
                    params as *const _ as usize,
                    0,
                )
            }
        }
    }
}
