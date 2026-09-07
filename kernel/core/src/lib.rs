#![no_std]

extern crate alloc;
#[cfg(any(test, feature = "host-test"))]
extern crate std;

pub mod core;
