// Adapted from Raspberry Pi pico-sdk 2.2.0, pico_rand/rand.c:
// https://github.com/raspberrypi/pico-sdk/blob/2.2.0/src/rp2_common/pico_rand/rand.c
// Copyright (c) 2022 Raspberry Pi (Trading) Ltd.
// SPDX-License-Identifier: BSD-3-Clause
// xoroshiro128**: David Blackman and Sebastiano Vigna (2018), public domain.
// splitmix64: Sebastiano Vigna (2015), public domain.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
// 3. Neither the name of the copyright holder nor the names of its contributors
//    may be used to endorse or promote products derived from this software
//    without specific prior written permission.
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

//! SDK-style TRNG-only configuration: raw samples -> splitmix64 -> xoroshiro128**.
//! Optional SDK RAM, time, board-ID, boot-random and bus-counter sources are
//! omitted. Rust state is initialized, never read from uninitialized memory.
//!
//! TODO(security): revisit this use of the TRNG before claiming cryptographic
//! security. Like pico_rand, we bypass hardware health checks and the von
//! Neumann conditioner. xoroshiro128** is NOT a cryptographic DRBG, and passing
//! kernel_crypto does not establish entropy quality or resistance to prediction.
//! Invariant: each 64-bit output mixes another 64 raw samples, as in the SDK;
//! these are samples, NOT a claim of 64 independent bits of entropy.
//! Invariant: one owner accesses the peripheral/state; reentry fails, never
//! spins on an interrupted owner. No allocation or 16-byte reseeding schedule.
//! Invariant: a reset timeout or collection timeout invalidates this backend;
//! explicit crypto initialization is required to recover. Successful raw-mode
//! reads do not certify source health: those hardware checks are bypassed.

use crate::core::crypto::{CryptoError, CryptoResult};
use crate::core::target::MmioRegister32;
use ::core::sync::atomic::{AtomicBool, Ordering};

const BASE: usize = 0x400f_0000;
const POLL_LIMIT: usize = 100_000;
static LOCKED: AtomicBool = AtomicBool::new(false);
static mut STATE: RandomState = RandomState::new();

struct Guard;
impl Guard {
    fn acquire() -> CryptoResult<Self> {
        LOCKED
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| Self)
            .map_err(|_| CryptoError::EntropyUnavailable)
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        LOCKED.store(false, Ordering::Release);
    }
}

struct RandomState {
    ready: bool,
    seeded: bool,
    rng: [u64; 2],
    samples: [u32; 6],
    remaining: usize,
}
impl RandomState {
    const fn new() -> Self {
        Self {
            ready: false,
            seeded: false,
            rng: [0; 2],
            samples: [0; 6],
            remaining: 0,
        }
    }

    fn capture(&mut self) -> CryptoResult<u64> {
        if self.remaining == 0 {
            // Reproduce SDK raw mode, including its implementation-specific
            // all-ones DEBUG_CONTROL write (not a portable Arm TRNG recipe).
            reg(0x130).write(0); // SAMPLE_CNT1
            reg(0x138).write(u32::MAX); // SDK bypass configuration
            reg(0x12c).write(1); // RND_SOURCE_ENABLE
            reg(0x108).write(0x0f); // RNG_ICR
                                    // SDK waits on BUSY in bypass mode, not the conditioned EHR_VALID
                                    // interrupt. Bound its polling here; never fall back to stale PRNG.
            let mut valid = false;
            for _ in 0..POLL_LIMIT {
                if reg(0x1b8).read() == 0 {
                    valid = true;
                    break;
                }
                ::core::hint::spin_loop();
            }
            if !valid {
                return Err(CryptoError::EntropyUnavailable);
            }
            for (i, word) in self.samples.iter_mut().enumerate() {
                *word = reg(0x114 + i * 4).read();
            }
            // Reading EHR_DATA5 consumes the result and restarts collection.
            self.remaining = 6;
            reg(0x10c).write(self.rng[0] as u32 & 3);
        }
        self.remaining -= 2;
        Ok(u64::from(self.samples[self.remaining])
            | (u64::from(self.samples[self.remaining + 1]) << 32))
    }

    fn next(&mut self) -> CryptoResult<u64> {
        if !self.ready {
            return Err(CryptoError::EntropyUnavailable);
        }
        if !self.seeded {
            self.rng = [splitmix64(self.capture()?), 0];
            if self.rng == [0; 2] {
                return Err(CryptoError::EntropyUnavailable);
            }
            xoroshiro128ss(&mut self.rng); // SDK initialization churn
            self.seeded = true;
        }
        self.rng[0] ^= splitmix64(self.capture()?);
        // SDK substitutes time for the forbidden zero state. Fail closed here.
        if self.rng == [0; 2] {
            return Err(CryptoError::EntropyUnavailable);
        }
        Ok(xoroshiro128ss(&mut self.rng))
    }
}

fn reg(offset: usize) -> MmioRegister32 {
    MmioRegister32::new(BASE + offset)
}

pub(super) fn initialize() {
    let Ok(_guard) = Guard::acquire() else {
        return;
    };
    let state = unsafe { &mut *::core::ptr::addr_of_mut!(STATE) };
    *state = RandomState::new();
    MmioRegister32::new(0x4002_2000).write(1 << 25); // assert TRNG reset
    MmioRegister32::new(0x4002_3000).write(1 << 25); // release TRNG reset
    for _ in 0..POLL_LIMIT {
        if MmioRegister32::new(0x4002_0008).read() & (1 << 25) != 0 {
            reg(0x130).write(0);
            reg(0x138).write(u32::MAX);
            reg(0x12c).write(1);
            state.ready = true;
            return;
        }
        ::core::hint::spin_loop();
    }
}

pub(super) fn fill(buf: &mut [u8]) -> CryptoResult<()> {
    if buf.is_empty() {
        return Ok(());
    }
    let _guard = Guard::acquire().inspect_err(|_err| {
        buf.fill(0);
    })?;
    let state = unsafe { &mut *::core::ptr::addr_of_mut!(STATE) };
    for chunk in buf.chunks_mut(8) {
        match state.next() {
            Ok(word) => chunk.copy_from_slice(&word.to_le_bytes()[..chunk.len()]),
            Err(err) => {
                // No partially successful output, cached entropy, or stale state.
                buf.fill(0);
                *state = RandomState::new();
                reg(0x12c).write(0);
                return Err(err);
            }
        }
    }
    Ok(())
}

fn splitmix64(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9e3779b97f4a7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

fn xoroshiro128ss(state: &mut [u64; 2]) -> u64 {
    let s0 = state[0];
    let s1 = state[1] ^ s0;
    let result = s0.wrapping_mul(5).rotate_left(7).wrapping_mul(9);
    state[0] = s0.rotate_left(24) ^ s1 ^ (s1 << 16);
    state[1] = s1.rotate_left(37);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sdk_arithmetic_vectors() {
        assert_eq!(splitmix64(0), 0xe220a8397b1dcdaf);
        let mut state = [1, 2];
        assert_eq!(xoroshiro128ss(&mut state), 5760);
        assert_eq!(state, [0x1030003, 0x6000000000]);
    }
    #[test]
    fn cached_samples_follow_sdk_pair_order() {
        let mut state = RandomState::new();
        state.samples = [1, 2, 3, 4, 5, 6];
        state.remaining = 6;
        assert_eq!(state.capture().unwrap(), (6u64 << 32) | 5);
        assert_eq!(state.capture().unwrap(), (4u64 << 32) | 3);
        assert_eq!(state.capture().unwrap(), (2u64 << 32) | 1);
    }
    #[test]
    fn uninitialized_state_refuses_output() {
        assert_eq!(
            RandomState::new().next(),
            Err(CryptoError::EntropyUnavailable)
        );
    }
    #[test]
    fn each_output_consumes_another_pair_of_samples() {
        let mut state = RandomState::new();
        state.ready = true;
        state.seeded = true;
        state.rng = [1, 2];
        state.samples = [1, 2, 3, 4, 5, 6];
        state.remaining = 6;
        let first = state.next().unwrap();
        assert_eq!(state.remaining, 4);
        let second = state.next().unwrap();
        assert_eq!(state.remaining, 2);
        assert_ne!(first, second);
        state.next().unwrap();
        assert_eq!(state.remaining, 0);
    }
}
