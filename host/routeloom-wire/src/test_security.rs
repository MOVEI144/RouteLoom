//! Deterministic test cipher used by the shared wire golden vectors.
//!
//! This is a byte-for-byte port of `TestSecurity` in
//! `tests/cpp/test_security.hpp`. It is NOT a production AEAD: it exists so
//! that the C++ and Rust encoders produce identical bytes for cross-language
//! vectors. Do not use it for real traffic.

use std::collections::HashMap;

use crate::{ErrorCode, Result, SecurityContext, SecurityProvider, WireError, AEAD_TAG_SIZE};

fn mix(mut state: u64, value: u64) -> u64 {
    state ^= value
        .wrapping_add(0x9e37_79b9_7f4a_7c15)
        .wrapping_add(state << 6)
        .wrapping_add(state >> 2);
    state = state.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    state
}

fn seed(context: &SecurityContext, counter: u64) -> u64 {
    let mut state = 0x726f_7574_656c_6f6f_u64;
    state = mix(state, context.scope as u64);
    state = mix(state, context.network);
    state = mix(state, context.sender);
    state = mix(state, context.receiver);
    state = mix(state, u64::from(context.epoch));
    mix(state, counter)
}

fn make_tag(
    context: &SecurityContext,
    counter: u64,
    aad: &[u8],
    ciphertext: &[u8],
) -> [u8; AEAD_TAG_SIZE] {
    let mut left = seed(context, counter);
    let mut right = mix(left, 0x0074_6167); // "tag"
    for byte in aad {
        left = mix(left, u64::from(*byte));
    }
    for byte in ciphertext {
        right = mix(right, u64::from(*byte));
    }
    let mut tag = [0_u8; AEAD_TAG_SIZE];
    for i in 0..8 {
        tag[i] = (left >> (56 - i * 8)) as u8;
        tag[8 + i] = (right >> (56 - i * 8)) as u8;
    }
    tag
}

type CounterKey = (u8, u64, u64, u64, u16);

fn counter_key(context: &SecurityContext) -> CounterKey {
    (
        context.scope as u8,
        context.network,
        context.sender,
        context.receiver,
        context.epoch,
    )
}

/// Deterministic XOR/mix cipher with a 16-byte tag, for tests and vectors only.
#[derive(Default)]
pub struct TestSecurity {
    counters: HashMap<CounterKey, u64>,
}

impl TestSecurity {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SecurityProvider for TestSecurity {
    fn ready(&self) -> bool {
        true
    }

    fn next_counter(&mut self, context: &SecurityContext) -> Result<u64> {
        let counter = self.counters.entry(counter_key(context)).or_insert(0);
        let value = *counter;
        *counter += 1;
        Ok(value)
    }

    fn seal(
        &mut self,
        context: &SecurityContext,
        counter: u64,
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<[u8; AEAD_TAG_SIZE]> {
        if ciphertext.len() < plaintext.len() {
            return Err(WireError::new(ErrorCode::NoCapacity, "test ciphertext"));
        }
        let mut state = seed(context, counter);
        for (i, byte) in plaintext.iter().enumerate() {
            state = mix(state, i as u64 + 1);
            ciphertext[i] = byte ^ (state >> 56) as u8;
        }
        Ok(make_tag(
            context,
            counter,
            aad,
            &ciphertext[..plaintext.len()],
        ))
    }

    fn open(
        &mut self,
        context: &SecurityContext,
        counter: u64,
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; AEAD_TAG_SIZE],
        plaintext: &mut [u8],
    ) -> Result<()> {
        if plaintext.len() < ciphertext.len() {
            return Err(WireError::new(ErrorCode::NoCapacity, "test plaintext"));
        }
        let expected = make_tag(context, counter, aad, ciphertext);
        let mut diff = 0_u8;
        for i in 0..AEAD_TAG_SIZE {
            diff |= expected[i] ^ tag[i];
        }
        if diff != 0 {
            return Err(WireError::new(
                ErrorCode::AuthenticationFailed,
                "test tag mismatch",
            ));
        }
        let mut state = seed(context, counter);
        for (i, byte) in ciphertext.iter().enumerate() {
            state = mix(state, i as u64 + 1);
            plaintext[i] = byte ^ (state >> 56) as u8;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecurityScope;

    #[test]
    fn seal_open_round_trip() {
        let context = SecurityContext {
            scope: SecurityScope::EndToEnd,
            network: 1,
            sender: 1,
            receiver: 3,
            epoch: 1,
        };
        let mut security = TestSecurity::new();
        let plaintext = b"route-loom";
        let mut ciphertext = [0_u8; 10];
        let tag = security
            .seal(&context, 0, b"aad", plaintext, &mut ciphertext)
            .unwrap();
        assert_ne!(&ciphertext, plaintext);
        let mut recovered = [0_u8; 10];
        security
            .open(&context, 0, b"aad", &ciphertext, &tag, &mut recovered)
            .unwrap();
        assert_eq!(&recovered, plaintext);
        let mut bad = [0_u8; 10];
        assert!(security
            .open(&context, 0, b"other", &ciphertext, &tag, &mut bad)
            .is_err());
    }
}
