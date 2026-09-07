#![no_std]
#![no_main]

use alloc::{
    alloc::{alloc, dealloc, Layout},
    boxed::Box,
    vec::Vec,
};
use rustlet_runtime::{declare_app, Apdu, ApduStatus, Rustlet, RustletCtx};

declare_app!(AllocFreeRustlet, 1024usize);

const ALLOCATION_GRANULE: usize = 8;
const ALIGNMENTS: [usize; 7] = [1, 8, 16, 32, 64, 128, 256];

#[derive(Default, rustlet_runtime::serde::Serialize, rustlet_runtime::serde::Deserialize)]
#[serde(crate = "rustlet_runtime::serde")]
struct AllocFreeRustlet;

impl Rustlet for AllocFreeRustlet {
    fn process_apdu(&mut self, ctx: &mut RustletCtx) -> ApduStatus {
        let apdu = Apdu::new(ctx);

        match apdu.ins() {
            0x30 => self.box_vec_smoke(apdu),
            0x32 => self.tiny_allocation(apdu),
            0x34 => self.requested_alignments(apdu),
            _ => apdu.reject(ApduStatus::instruction_not_supported()),
        }
    }
}

impl AllocFreeRustlet {
    fn box_vec_smoke(&mut self, apdu: Apdu<rustlet_runtime::Command>) -> ApduStatus {
        let boxed = Box::new(0x2Au8);
        let mut values = Vec::with_capacity(32);
        for value in 0u8..32 {
            values.push(value);
        }

        let sum = values
            .iter()
            .fold(0u8, |acc, value| acc.wrapping_add(*value));

        apdu.as_sending().send(&[*boxed, values.len() as u8, sum])
    }

    fn tiny_allocation(&mut self, apdu: Apdu<rustlet_runtime::Command>) -> ApduStatus {
        let layout = match Layout::from_size_align(1, 1) {
            Ok(layout) => layout,
            Err(_) => return apdu.reject(ApduStatus::internal_error()),
        };

        let ptr = unsafe { alloc(layout) };
        if ptr.is_null() || !(ptr as usize).is_multiple_of(ALLOCATION_GRANULE) {
            return apdu.reject(ApduStatus::internal_error());
        }
        unsafe { dealloc(ptr, layout) };

        let recycled = unsafe { alloc(layout) };
        if recycled.is_null() || !(recycled as usize).is_multiple_of(ALLOCATION_GRANULE) {
            return apdu.reject(ApduStatus::internal_error());
        }
        unsafe { dealloc(recycled, layout) };

        apdu.as_sending().send(&[ALLOCATION_GRANULE as u8])
    }

    fn requested_alignments(&mut self, apdu: Apdu<rustlet_runtime::Command>) -> ApduStatus {
        for requested_align in ALIGNMENTS {
            let layout = match Layout::from_size_align(1, requested_align) {
                Ok(layout) => layout,
                Err(_) => return apdu.reject(ApduStatus::internal_error()),
            };
            let ptr = unsafe { alloc(layout) };
            let expected_align = requested_align.max(ALLOCATION_GRANULE);
            if ptr.is_null() || !(ptr as usize).is_multiple_of(expected_align) {
                return apdu.reject(ApduStatus::internal_error());
            }
            unsafe { dealloc(ptr, layout) };
        }

        apdu.as_sending().send(&[ALIGNMENTS.len() as u8])
    }
}
