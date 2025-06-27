//! Util types and methods related to internal implementation for dealing with Descriptors.

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

#[derive(Debug, PartialEq)]
pub enum DescriptorError {
    InvalidDescriptor,

    Miniscript(miniscript::Error),

    StrictDeletion(Vec<DescriptorId>),

    DescriptorNotFound,
}

/// Since, precisely, Rust Bitcoin's ['Descriptor<DefiniteDescriptorKey>'] doesn't directly implement
/// serde we need this helper function so [`ConcreteDescriptor`] implements serde.
///
/// Wrapper around [`Descriptor::<DefiniteDescriptorKey>::to_string`].
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

/// Since, precisely, Rust Bitcoin's ['Descriptor<DefiniteDescriptorKey>'] doesn't directly implement
/// serde we need this helper function so [`ConcreteDescriptor`] implements serde.
///
/// Wrapper around [`Descriptor::<DefiniteDescriptorKey>::from_str`].
fn deserialize_descriptor<'de, D>(
    deserializer: D,
) -> Result<Descriptor<DefiniteDescriptorKey>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Descriptor::<DefiniteDescriptorKey>::from_str(&s)
        .map_err(|e| D::Error::custom(format!("Descriptor parsing failed: {e}")))
}

/// "deletedecriptor" response structure that holds the request
/// data that regards the descriptors deletion.
#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteDescriptorRes {
    /// The deleted descriptors if the pulled flag is active
    pub pulled: Vec<ConcreteDescriptor>,
}

/// The String key we use to address descriptors in KVs
pub const DESCRIPTOR_STRING_KEY: &str = "Descriptors";

/// Interpret [`DescriptorRequest`]s returning the extracted and already derived
/// descriptors. [`RescanRequest`] is reutilized here to yield a rescan
/// that would satisfy the users request.
///
/// Override priority of the rescan request is
/// Precise < Ignore < Full
///
/// The collected errors are returned
pub fn handle_descriptors_requests(
    requests: Vec<DescriptorRequest>,
) -> Result<(Vec<ConcreteDescriptor>, RescanRequest), Vec<DescriptorError>> {
    let mut rescan_request: RescanRequest = RescanRequest::SpecifiedTime(u32::MAX);
    let mut deriving_errors: Vec<DescriptorError> = Vec::new();
    let mut descriptors: Vec<ConcreteDescriptor> = Vec::new();

    for request in requests {
        rescan_request = rescan_request.check_override(&request.timestamp);

        match request.into_concrete_descriptors() {
            Ok(batch) => {
                for desc in batch {
                    descriptors.push(desc);
                }
            }
            Err(e) => deriving_errors.push(e),
        }
    }

    if deriving_errors.is_empty() {
        Ok((descriptors, rescan_request))
    } else {
        Err(deriving_errors)
    }
}

/// Given a [`Vec<ConcreteDescriptor>`] to search for the matching ones in `to_match`, that is a [`&[DescriptorId]`].
///
/// The return type is the index position of the found descriptors.
///
/// This function is used in the internals that interact with the DBs that hold the descriptors so it should be
/// performative and infallible.
pub fn extract_matching_ones(
    to_search: &[ConcreteDescriptor],
    to_match: &[DescriptorId],
) -> Vec<usize> {
    to_match
        .iter()
        .filter_map(|id| extract_matching_one(to_search, id))
        .collect()
}

/// Given a [`Vec<ConcreteDescriptor>`] to search for the matching ones in `to_match`, that is a [`DescriptorId`].
///
/// The return type is the index position of the found descriptors.
///
/// This function is used in the internals that interact with the DBs that hold the descriptors so it should be
/// performative and infallible.
pub fn extract_matching_one(
    to_search: &[ConcreteDescriptor],
    to_match: &DescriptorId,
) -> Option<usize> {
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
pub struct ConcreteDescriptor {
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
impl Default for ConcreteDescriptor {
    fn default() -> Self {
        const DEFAULT_P2PK_DESCRIPTOR: &str =
            "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";
        Self {
            descriptor: Descriptor::<DefiniteDescriptorKey>::from_str(DEFAULT_P2PK_DESCRIPTOR)
                .expect("Impossible to fail."),
            label: "A nice label".to_string(),
            internal: false,
        }
    }
}

impl ConcreteDescriptor {
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
        sha256d::Hash::hash(self.descriptor.to_string().as_bytes())
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
    /// A descriptor that's identified by its double sha256 of it miniscript string.
    ///
    /// Refer to [`ConcreteDescriptor::get_hash`].
    Hash,

    /// A descriptor that's identified by its label
    Label,

    /// A descriptor that's identified by its miniscript string.
    Miniscript,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
/// A struct who represents the json object "request" mentioned in "importdescriptors"
/// from bitcoin core rpc api. The internals directly derive cores documentation to
/// better understand their expected behavior.
pub struct DescriptorRequest {
    /// (string, required) Descriptor to import.
    pub desc: String,

    /// (boolean, optional, default=false) Set this descriptor to be the active descriptor for the corresponding output type/externality
    pub active: bool,

    /// (numeric or array) If a ranged descriptor is used, this specifies the end or the range (in the form [begin,end]) to import
    pub range: DerivationRange,

    /// (numeric) If a ranged descriptor is set to active, this specifies the next index to generate addresses from
    pub next_index: Option<u32>,

    /// (integer / string, required) Time from which to start rescanning the blockchain for this descriptor, in UNIX epoch time
    /// Use the string "now" to substitute the current synced blockchain time.
    /// "now" can be specified to bypass scanning, for outputs which are known to have never been used, and
    /// 0 can be specified to scan the entire blockchain. Blocks up to 2 hours before the earliest timestamp
    /// of all descriptors being imported will be scanned.
    pub timestamp: RescanRequest,

    /// (boolean, optional, default=false) Whether matching outputs should be treated as not incoming payments (e.g. change)
    pub internal: bool,

    ///(string, optional, default=${descriptor}) Label to assign to the address, only allowed with internal=false
    pub label: String,
}

// These defaults can be util.
impl Default for DescriptorRequest {
    fn default() -> Self {
        const DEFAULT_PKH_DESCRIPTOR: &str =
            "pkh([d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/*)";
        Self {
            desc: DEFAULT_PKH_DESCRIPTOR.to_string(),
            active: false,
            range: DerivationRange::default(),
            next_index: None,
            timestamp: RescanRequest::Full,
            label: DEFAULT_PKH_DESCRIPTOR.to_string(),
            internal: false,
        }
    }
}

impl DescriptorRequest {
    /// Consume the [`DescriptorRequest`] into a [`ConcreteDescriptor`].
    ///
    /// The return is a Vec of it because a Descriptor request may yield more than one
    /// descriptor while being a ranged one.
    pub fn into_concrete_descriptors(self) -> Result<Vec<ConcreteDescriptor>, DescriptorError> {
        self.range
            .range()
            .map(|index| {
                // Since the wallet is a watch-only, no need to keep secrets.
                let (parsed, _) = Descriptor::parse_descriptor(&Secp256k1::default(), &self.desc)
                    .map_err(DescriptorError::Miniscript)?;
                Ok(ConcreteDescriptor {
                    descriptor: parsed
                        .at_derivation_index(index)
                        .map_err(|_| DescriptorError::InvalidDescriptor)?,
                    label: self.label.clone(),
                    internal: self.internal,
                })
            })
            .collect::<Result<Vec<ConcreteDescriptor>, DescriptorError>>()
    }
}

/// Hold a way to identify a Descriptor.
#[derive(Debug, Clone, Serialize, Deserialize, Ord, PartialOrd, Eq, PartialEq)]
pub enum DescriptorId {
    /// Identify a Descriptor by a Label.
    Label(String),

    /// Identify a Descriptor by hash.
    Hash(sha256d::Hash),

    /// Identify a Descriptor by the script itself.
    Miniscript(String),
}

impl DescriptorId {
    /// Returns the hash that is used as key for a [`ConcreteDescriptor`] while
    /// it is in the persisted KV database.
    ///
    /// Since the [`DescriptorId`] can be an arbitrary label, and we cant use that
    /// as key to store the [`ConcreteDescriptor`], this function might return a None.
    ///
    /// When returning a None, the KV database will try to load every persisted [`ConcreteDescriptor`]
    /// that it has and search for it in a Vec. So, trying to search a persisted [`ConcreteDescriptor`]
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
        if Descriptor::<DescriptorPublicKey>::from_str(s).is_ok() {
            Ok(DescriptorId::Miniscript(s.into()))
        } else {
            Err(DescriptorError::InvalidDescriptor)
        }
    }
}

/// Time from which to start rescanning the blockchain for a descriptor request from "importdescriptors"
#[derive(Debug, Deserialize, Serialize, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum RescanRequest {
    /// Tells to make a precise rescan into
    SpecifiedTime(u32),

    /// Tells to make a full rescan
    Full,

    /// Tells to ignore rescan.
    Ignore,
}
impl RescanRequest {
    /// Checks if this [`RescanRequest`] should be overridden by another.
    ///
    /// This function is used to extract the best rescan request that should satisfy
    /// batches of descriptor requests considering the user's will.
    ///
    /// Overriding Priority; Full > Ignore > (lesser) SpecifiedTime > SpecifiedTime
    pub fn check_override(&self, other: &Self) -> RescanRequest {
        match (self, other) {
            (RescanRequest::Full, _) => RescanRequest::Full, // Full have the priority, no one can override it.
            (RescanRequest::Ignore, RescanRequest::Full) => RescanRequest::Full, // Ignore can only be overridden by Full.
            (RescanRequest::SpecifiedTime(_), RescanRequest::Full) => RescanRequest::Full, // SpecifiedTime can be overridden by Full.
            (RescanRequest::SpecifiedTime(_), RescanRequest::Ignore) => RescanRequest::Ignore, // SpecifiedTime can be overridden by Ignore.
            (RescanRequest::SpecifiedTime(have), RescanRequest::SpecifiedTime(given)) => {
                RescanRequest::SpecifiedTime(*have.min(given))
            } // SpecifiedTime can be overridden by a lesser Time.
            _ => self.clone(), // All the other cases shouldn't cause an override.
        }
    }
}

/// Represents a descriptor range, which can define the end of a range or an entire one.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub enum DerivationRange {
    /// This range tells to go from zero until this exact index.
    End(u32),

    /// This range tells to from the first index until the second.
    Range([u32; 2]),
}
impl DerivationRange {
    /// Consumes the [`DerivationRange`] in favor of an iterable [`Range<u32>`]
    fn range(&self) -> Range<u32> {
        match self {
            Self::End(e) => 0..*e,
            Self::Range([r, e]) => *r..*e,
        }
    }
}
impl Default for DerivationRange {
    fn default() -> Self {
        DerivationRange::End(1) // 1 ? Should be enough.
    }
}

#[cfg(test)]
mod tests {
    use core::default::Default;

    use super::*;

    #[test]
    fn test_rescan_priority() {
        let test_cases = vec![
            // These cases should cover every case where an override should occur
            // (existing, new, expected_result)
            (
                RescanRequest::Full,
                RescanRequest::Ignore,
                RescanRequest::Full,
            ), // A full rescan request should remain when compared with an ignore one.
            (
                RescanRequest::Ignore,
                RescanRequest::Full,
                RescanRequest::Full,
            ), // An ignore rescan request should be overridden by a full one.
            (
                RescanRequest::SpecifiedTime(100),
                RescanRequest::Full,
                RescanRequest::Full,
            ), // A full rescan request should override a SpecifiedTime one
            (
                RescanRequest::SpecifiedTime(100),
                RescanRequest::Ignore,
                RescanRequest::Ignore,
            ), // An ignore rescan request should override a SpecifiedTime one
            (
                RescanRequest::SpecifiedTime(100),
                RescanRequest::SpecifiedTime(50),
                RescanRequest::SpecifiedTime(50),
            ), // A specific time rescan request should only be overridden by a lesser one.
        ];

        for (existing, new, expected) in test_cases {
            assert_eq!(existing.check_override(&new), expected);
        }
    }

    #[test]
    fn test_error_aggregation() {
        let bad_req = DescriptorRequest {
            desc: "invalid".into(),
            ..Default::default()
        };

        let result = handle_descriptors_requests(vec![Default::default(), bad_req]);

        assert!(result.is_err()); // Okay, it was supposed to fail and it did.

        assert_eq!(result.unwrap_err().len(), 1); // Okay, it was supposed to return only one error.
    }

    #[test]
    fn test_all_requests_processed() {
        let reqs = vec![
            DescriptorRequest {
                timestamp: RescanRequest::SpecifiedTime(100),
                ..Default::default()
            },
            DescriptorRequest {
                timestamp: RescanRequest::SpecifiedTime(50),
                ..Default::default()
            },
        ];

        let (descs, rescan) = handle_descriptors_requests(reqs).unwrap();

        assert_eq!(descs.len(), 2);

        assert_eq!(rescan, RescanRequest::SpecifiedTime(50));

        let reqs = vec![
            DescriptorRequest {
                timestamp: RescanRequest::Full,
                ..Default::default()
            },
            DescriptorRequest {
                timestamp: RescanRequest::SpecifiedTime(50),
                ..Default::default()
            },
        ];

        let (descs, rescan) = handle_descriptors_requests(reqs).unwrap();

        assert_eq!(descs.len(), 2);

        assert_eq!(rescan, RescanRequest::Full);

        let reqs = vec![
            DescriptorRequest {
                timestamp: RescanRequest::Ignore,
                ..Default::default()
            },
            DescriptorRequest {
                timestamp: RescanRequest::SpecifiedTime(50),
                ..Default::default()
            },
        ];

        let (descs, rescan) = handle_descriptors_requests(reqs).unwrap();

        assert_eq!(descs.len(), 2);

        assert_eq!(rescan, RescanRequest::Ignore);
    }

    #[test]
    fn test_descriptor_matching() {
        let blown = ConcreteDescriptor::default();

        // Test different ID types
        let hand_hash_id = DescriptorId::Hash(blown.get_hash());
        let hand_label_id = DescriptorId::Label("A nice label".into()); // A nice label is the default string used for labelling
        let hand_ms_id = DescriptorId::Miniscript(blown.descriptor.to_string());

        // This block and the next 3 asserts are only being added here to
        // test the get_id function.
        let gen_hash_id = blown.get_id(DescriptorIdSelector::Hash);
        let gen_label_id = blown.get_id(DescriptorIdSelector::Label);
        let gen_ms_id = blown.get_id(DescriptorIdSelector::Miniscript);

        assert_eq!(gen_hash_id, hand_hash_id);
        assert_eq!(gen_label_id, hand_label_id);
        assert_eq!(gen_ms_id, hand_ms_id);

        let descs = vec![blown];

        assert_eq!(extract_matching_one(&descs, &hand_hash_id), Some(0));
        assert_eq!(extract_matching_one(&descs, &hand_label_id), Some(0));
        assert_eq!(extract_matching_one(&descs, &hand_ms_id), Some(0));

        // Test non-existent
        assert!(extract_matching_one(&descs, &DescriptorId::Label("missing".into())).is_none());
    }
}
