//! Util types and methods related to internal implementation for dealing with Descriptors.

use core::ops::Range;

use bitcoin::{hashes::sha256d::Hash, secp256k1::Secp256k1};
use miniscript::{DefiniteDescriptorKey, Descriptor, DescriptorPublicKey};
use serde::{Deserialize, Serialize};

use crate::prelude::*;
#[derive(Debug)]
pub enum DescriptorError {
    InvalidDescriptor,
    MiniscriptError(miniscript::Error),
}

/// Interpret [`DescriptorRequest`]s, returning its ScriptPubkeys and the highest timestamp that
/// was requested for a rescan after addresses. The timestamp returned may be a 0u32 indicating
/// that rescanning should be skipped.
pub fn handle_descriptors_requests(
    requests: Vec<DescriptorRequest>,
) -> Result<(Vec<Descriptor<DefiniteDescriptorKey>>, u32), DescriptorError> {
    let mut highes_time = 0u32;
    let descs: Vec<_> = requests
        .iter()
        .flat_map(|d| {
            if let DescriptorTimestamp::SpecifiedTime(time) = d.timestamp {
                if highes_time >= time {
                    highes_time = time;
                }
            } else {
                // This is the case one wants to bypass
                // blockchain rescaning.

                // Simple putting zero avoids the time being changed
                // by the above condition since 0 will be allways
                // less than any correct u32 timestamp and will serve
                // to identify a request to skip blockchain rescaning.
                highes_time = 0;
            }
            d.clone()
                .into_descriptor()
                .expect("The descriptors did well")
        })
        .collect();
    Ok((descs, highes_time))
}

/// Takes an array of descriptors as `String`, performs sanity checks on each one
/// and returns list of parsed descriptors.
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

/// A struct who represents the json object "request" mentioned in "importdescriptors"
/// from bitcoin core rpc api. The internals directly derive cores documentation to
/// better understand they expected behavior.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DescriptorRequest {
    /// (string, required) Descriptor to import.
    pub desc: String,
    /// (boolean, optional, default=false) Set this descriptor to be the active descriptor for the corresponding output type/externality
    pub active: bool,
    /// (numeric or array) If a ranged descriptor is used, this specifies the end or the range (in the form [begin,end]) to import
    pub range: DescriptorRange,
    /// (numeric) If a ranged descriptor is set to active, this specifies the next index to generate addresses from
    pub next_index: Option<u32>,
    /// (integer / string, required) Time from which to start rescanning the blockchain for this descriptor, in UNIX epoch time
    /// Use the string "now" to substitute the current synced blockchain time.
    /// "now" can be specified to bypass scanning, for outputs which are known to never have been used, and
    /// 0 can be specified to scan the entire blockchain. Blocks up to 2 hours before the earliest timestamp
    /// of all descriptors being imported will be scanned.
    pub timestamp: DescriptorTimestamp,
    /// (boolean, optional, default=false) Whether matching outputs should be treated as not incoming payments (e.g. change)
    pub internal: bool,
    ///(string, optional, default='') Label to assign to the address, only allowed with internal=false
    pub label: String,
}

impl DescriptorRequest {
    /// Consume the [`DescriptoRequest`] into a derived [`Descriptor<DescriptorPublickKey>`].
    /// The returning is a Vec of it because a Descriptor request may yield more than one
    /// decriptor while being a ranged one.
    pub fn into_descriptor(
        self,
    ) -> Result<Vec<Descriptor<DefiniteDescriptorKey>>, DescriptorError> {
        self.range
            .into_range()
            .map(|index| {
                // Since the wallet is a watch-only, no need to keep secrets.
                let (parsed, _) = Descriptor::parse_descriptor(&Secp256k1::default(), &self.desc)
                    .map_err(|e| DescriptorError::MiniscriptError(e))?;
                parsed
                    .at_derivation_index(index)
                    .map_err(|_| DescriptorError::InvalidDescriptor)
            })
            .collect::<Result<Vec<Descriptor<DefiniteDescriptorKey>>, DescriptorError>>()
    }
}
/// Hold a way to identify a Descriptor.
pub enum DescriptorId {
    /// Identify a Descriptor by a Label.
    Label(String),
    /// Identify a Descriptor by hash.
    Hash(Hash),
    /// Identify a Descriptor by the script itself.
    Miniscript(String),
}

/// Time from which to start rescanning the blockchain for a descriptor request from "importdescriptors"
#[derive(Debug, Deserialize, Serialize, Clone)]
pub enum DescriptorTimestamp {
    SpecifiedTime(u32),
    Now,
}

/// Represents a descriptor range, which can define the end of a range or a entire one.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub enum DescriptorRange {
    End(u32),
    Range([u32; 2]),
}
impl DescriptorRange {
    /// Consumes the [`DescriptorRange`] in favor of a iterable [`Range<u32>`]
    fn into_range(self) -> Range<u32> {
        match self {
            Self::End(e) => 0..e,
            Self::Range([r, e]) => r..e,
        }
    }
}
