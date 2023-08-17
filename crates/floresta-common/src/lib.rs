#![no_std]
use bitcoin::hashes::{sha256, Hash};
use bitcoin::Script;
use miniscript::{Descriptor, DescriptorPublicKey};
use prelude::*;

use sha2::Digest;
pub mod constants;

pub fn get_hash_from_u8(data: &[u8]) -> sha256::Hash {
    let hash = sha2::Sha256::new().chain_update(data).finalize();
    sha256::Hash::from_slice(hash.as_slice()).expect("Engines shouldn't be Err")
}

pub fn get_spk_hash(spk: &Script) -> sha256::Hash {
    let script_hash = spk.as_bytes();
    let mut hash = sha2::Sha256::new().chain_update(script_hash).finalize();
    hash.reverse();
    sha256::Hash::from_slice(hash.as_slice()).expect("Engines shouldn't be Err")
}
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
    pub use alloc::{borrow::ToOwned, boxed::Box, string::String, vec, vec::Vec};
    pub use core::{
        cmp, convert,
        core::str::FromStr,
        fmt,
        fmt::Display,
        iter, mem, ops,
        ops::{Deref, DerefMut},
        option, result, slice, str,
    };

    pub use core2::{
        error::Error,
        io::{Error as ioError, Read, Write},
    };
    pub use hashbrown::{HashMap, HashSet};
}
#[cfg(not(feature = "no-std"))]
pub mod prelude {
    extern crate std;
    pub use std::borrow::ToOwned;
    pub use std::{
        boxed::Box,
        collections::{hash_map::Entry, HashMap, HashSet},
        error::Error,
        fmt::{self, Display, Formatter},
        io::{Error as ioError, Read, Write},
        ops::{Deref, DerefMut},
        result::Result,
        str::FromStr,
        string::String,
        sync,
        vec::{self, Vec},
    };
}
#[macro_export]
macro_rules! impl_error_from {
    ($thing: ty, $from_thing: ty, $field: ident) => {
        impl From<$from_thing> for $thing {
            fn from(e: $from_thing) -> Self {
                <$thing>::$field(e)
            }
        }
    };
}
