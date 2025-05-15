// SPDX-License-Identifier: MIT

#![no_std]

use bitcoin::hashes::sha256;
use bitcoin::hashes::Hash;
use bitcoin::ScriptBuf;
#[cfg(any(feature = "descriptors-std", feature = "descriptors-no-std"))]
use miniscript::Descriptor;
#[cfg(any(feature = "descriptors-std", feature = "descriptors-no-std"))]
use miniscript::DescriptorPublicKey;
use sha2::Digest;

#[cfg(not(feature = "std"))]
mod error;
pub mod macros;
pub mod spsc;

#[cfg(any(feature = "descriptors-std", feature = "descriptors-no-std"))]
use prelude::*;
pub use spsc::Channel;

pub fn get_hash_from_u8(data: &[u8]) -> sha256::Hash {
    let hash = sha2::Sha256::new().chain_update(data).finalize();
    sha256::Hash::from_slice(hash.as_slice()).expect("Engines shouldn't be Err")
}

pub fn get_spk_hash(spk: &ScriptBuf) -> sha256::Hash {
    let script_hash = spk.as_bytes();
    let mut hash = sha2::Sha256::new().chain_update(script_hash).finalize();
    hash.reverse();
    sha256::Hash::from_slice(hash.as_slice()).expect("Engines shouldn't be Err")
}

/// Non-standard service flags that aren't in rust-bitcoin yet
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

#[cfg(any(feature = "descriptors-std", feature = "descriptors-no-std"))]
pub fn parse_descriptors(
    descriptors: &[String],
) -> Result<Vec<Descriptor<DescriptorPublicKey>>, miniscript::Error> {
    let descriptors = descriptors
        .iter()
        .map(|descriptor| {
            let descriptor = Descriptor::<DescriptorPublicKey>::from_str(descriptor.as_str())?;
            descriptor.sanity_check()?;
            descriptor.into_single_descriptors()
        })
        .collect::<Result<Vec<Vec<_>>, _>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    Ok(descriptors)
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
