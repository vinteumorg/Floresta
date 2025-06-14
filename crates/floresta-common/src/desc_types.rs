//! Util types and methods related to internal implementation for dealing with Descriptors.

use alloc::string::ToString;
use core::convert::Into;
use core::ops::Range;

use bitcoin::hashes::sha256d;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::Secp256k1;
use miniscript::DefiniteDescriptorKey;
use miniscript::Descriptor;
use miniscript::DescriptorPublicKey;
use serde::de::Error;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;

use crate::prelude::*;
#[derive(Debug)]
pub enum DescriptorError {
    InvalidDescriptor,
    MiniscriptError(miniscript::Error),
    StrictDeletion(Vec<DescriptorId>),
    DescriptorNotFound,
}
fn serialize_descriptor<S>(
    descriptor: &Descriptor<DefiniteDescriptorKey>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    // Convert descriptor to string and serialize that
    let descriptor_str = descriptor.to_string();
    serializer.serialize_str(&descriptor_str)
}

fn deserialize_descriptor<'de, D>(
    deserializer: D,
) -> Result<Descriptor<DefiniteDescriptorKey>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Descriptor::<DefiniteDescriptorKey>::from_str(&s)
        .map_err(|e| D::Error::custom(format!("Descriptor parsing failed: {}", e)))
}

/// "deletedecriptor" response structure that holds the request
/// data that regards the descriptors deletion.
#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteDescriptorRes {
    /// The deleted descriptors if the pulled flag is active
    pub pulled: Vec<BlownDescriptor>,
    /// The difference between the given ids and the found
    /// ones.
    ///
    /// If none, not_found will be an empty vec.
    pub not_found: Vec<DescriptorId>,
}

/// The String key we use to address descriptors in KVs
pub const DESCRIPTOR_STRING_KEY: &str = "Descriptors";

/// Interpret [`DescriptorRequest`]s, returning its ScriptPubkeys and the highest timestamp that
/// was requested for a rescan after addresses. The timestamp returned may be a 0u32 indicating
/// that rescanning should be skipped.
pub fn handle_descriptors_requests(
    requests: Vec<DescriptorRequest>,
) -> Result<(Vec<BlownDescriptor>, u32), DescriptorError> {
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
                // blockchain rescanning.

                // Simple putting zero avoids the time being changed
                // by the above condition since 0 will be always
                // less than any correct u32 timestamp and will serve
                // to identify a request to skip blockchain rescanning.
                highes_time = 0;
            }
            d.clone()
                .get_blown_descriptors()
                .expect("The descriptors did well")
        })
        .collect();
    Ok((descs, highes_time))
}

/// Given a [`Vec<BlownDescriptor>`] to search for the matching ones in `to_match`, that is a [`&[DescriptorId]`].
///
/// The return type is the index position of the found descriptors.
///
/// This function is used in the internals that interact with the DBs that hold the descriptors so it should be
/// performative and infallible.
pub fn extract_matching_ones(
    to_search: &[BlownDescriptor],
    to_match: &[DescriptorId],
) -> Vec<usize> {
    // At least it works.
    let mut ret = Vec::new();
    for (usize, desc) in to_search.iter().enumerate() {
        for id in to_match {
            if desc.match_id(id) {
                ret.push(usize);
            }
        }
    }
    ret
}

/// Given a [`Vec<BlownDescriptor>`] to search for the matching ones in `to_match`, that is a [`DescriptorId`].
///
/// The return type is the index position of the found descriptors.
///
/// This function is used in the internals that interact with the DBs that hold the descriptors so it should be
/// performative and infallible.
pub fn extract_matching_one(
    to_search: &[BlownDescriptor],
    to_match: &DescriptorId,
) -> Option<usize> {
    // At least it works.
    for (usize, desc) in to_search.iter().enumerate() {
        if desc.match_id(to_match) {
            return Some(usize);
        }
    }
    None
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
/// Holds an already derived Descriptor and some metadata.
///
/// This is the object intended to live inside the database
/// that keeps track of descriptors.
pub struct BlownDescriptor {
    /// The descriptor itself who's already derived and yields a
    /// specific ScriptPubkey.
    #[serde(
        serialize_with = "serialize_descriptor",
        deserialize_with = "deserialize_descriptor"
    )]
    pub descriptor: Descriptor<DefiniteDescriptorKey>,
    /// A label given for the descriptor
    pub label: String,
    /// It's from the owner of the wallet?
    ///
    /// Whether this script should be treated as a change
    pub internal: bool,
}

impl BlownDescriptor {
    /// If the given id represents this exact descriptor.
    pub fn match_id(&self, id: &DescriptorId) -> bool {
        match id {
            DescriptorId::Label(l) => l == &self.label,
            DescriptorId::Miniscript(m) => {
                // the miniscript should already be a verified
                // Descriptor<DefiniteDescriptorKey>
                let from_id =
                    Descriptor::<DefiniteDescriptorKey>::from_str(&m.to_string()).expect("");
                self.descriptor == from_id
            }
            DescriptorId::Hash(h) => &self.get_hash() == h,
        }
    }
    /// Returns a sha256d of the descriptor, solely used to compare against DescriptorId.
    pub fn get_hash(&self) -> sha256d::Hash {
        sha256d::Hash::hash(&self.descriptor.to_string().as_bytes())
    }

    pub fn get_id(&self, selection: DescriptorIdSelector) -> DescriptorId {
        match selection {
            DescriptorIdSelector::Hash => DescriptorId::Hash(self.get_hash()),
            DescriptorIdSelector::Label => DescriptorId::Label(self.label.clone()),
            DescriptorIdSelector::Miniscript => {
                DescriptorId::Miniscript(self.descriptor.to_string())
            }
        }
    }
}

/// Helper Enum to choose which [`DescriptorId`] the consumer
/// wants to produce.
pub enum DescriptorIdSelector {
    Hash,
    Label,
    Miniscript,
}

// These defaults can be util.
impl Default for BlownDescriptor {
    fn default() -> Self {
        const DEFAULT_P2PK_DESCRIPTOR: &str =
            "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";
        Self {
            descriptor: Descriptor::<DefiniteDescriptorKey>::from_str(DEFAULT_P2PK_DESCRIPTOR)
                .expect("Impossible to fail."),
            label: "A nice Label".to_string(),
            internal: false,
        }
    }
}

/// A struct who represents the json object "request" mentioned in "importdescriptors"
/// from bitcoin core rpc api. The internals directly derive cores documentation to
/// better understand their expected behavior.
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
    /// "now" can be specified to bypass scanning, for outputs which are known to have never been used, and
    /// 0 can be specified to scan the entire blockchain. Blocks up to 2 hours before the earliest timestamp
    /// of all descriptors being imported will be scanned.
    pub timestamp: DescriptorTimestamp,
    /// (boolean, optional, default=false) Whether matching outputs should be treated as not incoming payments (e.g. change)
    pub internal: bool,
    ///(string, optional, default=${descriptor}) Label to assign to the address, only allowed with internal=false
    pub label: String,
}
impl Default for DescriptorRequest {
    fn default() -> Self {
        const DEFAULT_P2PK_DESCRIPTOR: &str =
            "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";
        Self {
            desc: DEFAULT_P2PK_DESCRIPTOR
                .try_into()
                .expect("Impossible to fail."),
            active: true,
            range: DescriptorRange::End(u32::MAX - 1),
            next_index: None,
            timestamp: DescriptorTimestamp::Now,
            internal: true,
            label: DEFAULT_P2PK_DESCRIPTOR.into(),
        }
    }
}
impl FromStr for DescriptorRequest {
    type Err = DescriptorError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            desc: s.into(),
            label: s.into(),
            ..Default::default()
        })
    }
}

impl DescriptorRequest {
    /// Consume the [`DescriptoRequest`] into a [`BlownDescriptor`].
    ///
    /// The return is a Vec of it because a Descriptor request may yield more than one
    /// decriptor while being a ranged one.
    pub fn get_blown_descriptors(&self) -> Result<Vec<BlownDescriptor>, DescriptorError> {
        self.range
            .range()
            .map(|index| {
                // Since the wallet is a watch-only, no need to keep secrets.
                let (parsed, _) = Descriptor::parse_descriptor(&Secp256k1::default(), &self.desc)
                    .map_err(|e| DescriptorError::MiniscriptError(e))?;
                Ok(BlownDescriptor {
                    descriptor: parsed
                        .at_derivation_index(index)
                        .map_err(|_| DescriptorError::InvalidDescriptor)?,
                    label: self.label.clone(),
                    internal: self.internal,
                })
            })
            .collect::<Result<Vec<BlownDescriptor>, DescriptorError>>()
    }
}
/// Hold a way to identify a Descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DescriptorId {
    /// Identify a Descriptor by a Label.
    Label(String),
    /// Identify a Descriptor by hash.
    Hash(sha256d::Hash),
    /// Identify a Descriptor by the script itself.
    Miniscript(String),
}
impl DescriptorId {
    /// Returns the hash that is used as key for a [`BlownDescriptor`] while
    /// it is in the persisted KV database.
    ///
    /// Since the [`DescriptorId`] can be an arbitrary label, and we cant use that
    /// as key to store the [`BlownDescriptor`], this function might return a None.
    ///
    /// When returning a None, the KV database will try to load every persisted [`BlownDescriptor`]
    /// that it has and search for it in a Vec. So, trying to search a persisted [`BlownDescriptor`]
    /// by its label should be avoided.
    pub fn get_hash(&self) -> sha256d::Hash {
        match self {
            DescriptorId::Hash(hash) => *hash,
            DescriptorId::Miniscript(script) => sha256d::Hash::hash(script.as_bytes()),
            DescriptorId::Label(label) => sha256d::Hash::hash(label.as_bytes()),
        }
    }
}
impl FromStr for DescriptorId {
    type Err = DescriptorError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(_) = Descriptor::<DescriptorPublicKey>::from_str(s) {
            Ok(DescriptorId::Miniscript(s.into()))
        } else {
            Err(DescriptorError::InvalidDescriptor)
        }
    }
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
    /// Consumes the [`DescriptorRange`] in favor of an iterable [`Range<u32>`]
    fn range(&self) -> Range<u32> {
        match self {
            Self::End(e) => 0..*e,
            Self::Range([r, e]) => *r..*e,
        }
    }
}
