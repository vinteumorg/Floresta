// SPDX-License-Identifier: MIT

//! # Floresta Common
//! Provides utility functions, macros and modules to be
//! used in other Floresta crates.
#![cfg_attr(docsrs, feature(doc_cfg))]
#![no_std]
use bitcoin::hashes::sha256;
use bitcoin::hashes::Hash;
use bitcoin::ScriptBuf;
use sha2::Digest;

#[cfg(any(feature = "descriptors-std", feature = "descriptors-no-std"))]
pub mod descriptor_internals;
#[cfg(not(feature = "std"))]
mod error;
pub mod macros;

#[cfg(feature = "slip132")]
pub mod slip132;
pub mod spsc;

pub use spsc::Channel;

/// Computes the SHA-256 digest of the byte slice data and returns a [Hash] from `bitcoin_hashes`.
///
/// [Hash]: https://docs.rs/bitcoin_hashes/latest/bitcoin_hashes/sha256/struct.Hash.html
pub fn get_hash_from_u8(data: &[u8]) -> sha256::Hash {
    let hash = sha2::Sha256::new().chain_update(data).finalize();
    sha256::Hash::from_byte_array(hash.into())
}

/// Computes the SHA-256 digest of a script, reverses its bytes, and returns a [Hash] from
/// `bitcoin_hashes`.
///
/// The source to the specification can be found in the Electrum protocol [documentation], and it is
/// used to identify scripts in the Electrum Protocol.
///
/// [documentation]: https://electrum-protocol.readthedocs.io/en/latest/protocol-basics.html#script-hashes
/// [Hash]: https://docs.rs/bitcoin_hashes/latest/bitcoin_hashes/sha256/struct.Hash.html
pub fn get_spk_hash(spk: &ScriptBuf) -> sha256::Hash {
    let data = spk.as_bytes();
    let mut hash = sha2::Sha256::new().chain_update(data).finalize();
    hash.reverse();
    sha256::Hash::from_byte_array(hash.into())
}

/// Reads a VarInt from the given reader and ensures it is less than or equal to `max`.
///
/// Returns an error if the VarInt is larger than `max`.
pub fn read_bounded_len<R: bitcoin::io::Read + ?Sized>(
    reader: &mut R,
    max: usize,
) -> Result<usize, encode::Error> {
    let n64 = VarInt::consensus_decode(reader)?.0;
    if n64 > max as u64 {
        return Err(encode::Error::OversizedVectorAllocation {
            requested: n64 as usize,
            max,
        });
    }
    Ok(n64 as usize)
}

/// Non-standard service flags that aren't in rust-bitcoin yet.
pub mod service_flags {
    /// This peer supports UTREEXO messages
    pub const UTREEXO: u64 = 1 << 24;

    /// This peer supports UTREEXO filter messages
    pub const UTREEXO_FILTER: u64 = 1 << 25;
}

#[derive(Debug, Clone)]
/// A simple fraction struct that allows adding numbers to the numerator and denominator
///
/// If we want compute a rolling-average, we would naively hold all elements in a list and
/// compute the average from it. This is not efficient, as it requires O(n) memory and O(n)
/// time to compute the average. Instead, we can use a fraction to compute the average in O(1)
/// time and O(1) memory, by keeping track of the sum of all elements and the number of elements.
pub struct FractionAvg {
    numerator: u64,
    denominator: u64,
}

impl FractionAvg {
    /// Creates a new fraction with the given numerator and denominator
    pub fn new(numerator: u64, denominator: u64) -> Self {
        Self {
            numerator,
            denominator,
        }
    }

    /// Adds a number to the numerator and increments the denominator
    pub fn add(&mut self, other: u64) {
        self.numerator += other;
        self.denominator += 1;
    }

    /// Returns the average of the fraction
    pub fn value(&self) -> f64 {
        if self.denominator == 0 {
            return 0.0;
        }

        self.numerator as f64 / self.denominator as f64
    }
}

#[cfg(not(feature = "std"))]
pub mod prelude {
    extern crate alloc;
    pub use alloc::borrow::ToOwned;
    pub use alloc::boxed::Box;
    pub use alloc::format;
    pub use alloc::string::String;
    pub use alloc::string::ToString;
    pub use alloc::vec;
    pub use alloc::vec::Vec;
    pub use core::cmp;
    pub use core::convert;
    pub use core::fmt;
    pub use core::fmt::Display;
    pub use core::iter;
    pub use core::mem;
    pub use core::ops;
    pub use core::ops::Deref;
    pub use core::ops::DerefMut;
    pub use core::option;
    pub use core::result;
    pub use core::slice;
    pub use core::str;
    pub use core::str::FromStr;

    pub use bitcoin::io::Error as ioError;
    pub use bitcoin::io::Read;
    pub use bitcoin::io::Write;
    pub use hashbrown::HashMap;
    pub use hashbrown::HashSet;

    pub use crate::error::Error;
}

#[cfg(feature = "std")]
/// Provides implementation for basic `std` types, without assuming we have a `std` library.
///
/// This module is used to avoid having `#[cfg(feature = "no-std")]` sprinkled
/// around all crates that support `no-std`. It imports all types we would use
/// from the `stdlib`, either from the lib itself, or from other sources in case
/// `stdlib` isn't available.
pub mod prelude {
    extern crate alloc;
    extern crate std;
    pub use alloc::format;
    pub use alloc::string::ToString;
    pub use std::borrow::ToOwned;
    pub use std::boxed::Box;
    pub use std::collections::hash_map::Entry;
    pub use std::collections::HashMap;
    pub use std::collections::HashSet;
    pub use std::error::Error;
    pub use std::fmt::Display;
    pub use std::fmt::Formatter;
    pub use std::fmt::{self};
    pub use std::io::Error as ioError;
    pub use std::io::Read;
    pub use std::io::Write;
    pub use std::ops::Deref;
    pub use std::ops::DerefMut;
    pub use std::result::Result;
    pub use std::str::FromStr;
    pub use std::string::String;
    pub use std::sync;
    pub use std::vec;
    pub use std::vec::Vec;
}
