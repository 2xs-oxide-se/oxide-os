#![cfg_attr(not(test), no_std)]
#![allow(dead_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod apdu_debug_mod;
mod apdu_layer;
mod apdu_manager;
mod embedded_apps;
mod fae_runtime;
mod gp_status;
mod kernel_main_app;
pub mod object_registry;
pub mod object_registry_persistence;
mod predeployment;
mod secure_channel;
pub mod security_domain;
pub mod selected_app;
mod time_manager;
mod transport_layer;

pub use oxi_core::core;
