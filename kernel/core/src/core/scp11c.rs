//! Compatibility facade for the current SCP11c profile.
//!
//! New code should use [`crate::core::scp11`] for objects that are common to
//! SCP11a/SCP11b/SCP11c. This module keeps the historical SCP11c path stable
//! while the firmware is migrated profile by profile.

pub use super::scp11::*;

pub type SessionKeys = super::scp11::Scp11SessionKeys;
pub type SessionState = super::scp11::Scp11SessionState;
pub type WrappedLengths = super::scp11::Scp11WrappedLengths;
