#![no_std]
use bitcoin::hashes::sha256;
use bitcoin::hashes::Hash;
use bitcoin::ScriptBuf;
#[cfg(feature = "descriptors")]
use miniscript::Descriptor;
#[cfg(feature = "descriptors")]
use miniscript::DescriptorPublicKey;
use sha2::Digest;
pub mod constants;
pub mod spsc;

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

#[cfg(feature = "descriptors")]
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
#[cfg(feature = "no-std")]
pub mod prelude {
    extern crate alloc;
    pub use alloc::borrow::ToOwned;
    pub use alloc::boxed::Box;
    pub use alloc::string::String;
    pub use alloc::vec;
    pub use alloc::vec::Vec;
    pub use core::cmp;
    pub use core::convert;
    pub use core::core::str::FromStr;
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

    pub use core2::error::Error;
    pub use core2::io::Error as ioError;
    pub use core2::io::Read;
    pub use core2::io::Write;
    pub use hashbrown::HashMap;
    pub use hashbrown::HashSet;
}
#[cfg(not(feature = "no-std"))]
pub mod prelude {
    extern crate alloc;
    extern crate std;
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
    pub use std::vec::Vec;
    pub use std::vec::{self};
}
#[macro_export]
macro_rules! impl_error_from {
    ($thing:ty, $from_thing:ty, $field:ident) => {
        impl From<$from_thing> for $thing {
            fn from(e: $from_thing) -> Self {
                <$thing>::$field(e)
            }
        }
    };
}
