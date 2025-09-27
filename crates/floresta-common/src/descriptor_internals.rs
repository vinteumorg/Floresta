//! Util types and methods related to internal implementation for dealing with Descriptors.

use core::cmp::max;
use core::ops::Range;

use bitcoin::hashes::sha256d;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::Secp256k1;
use miniscript::descriptor;
use miniscript::DefiniteDescriptorKey;
use miniscript::Descriptor;
use miniscript::DescriptorPublicKey;
use miniscript::MiniscriptKey;
use miniscript::ToPublicKey;
use serde::de;
use serde::de::Error;
use serde::de::MapAccess;
use serde::de::SeqAccess;
use serde::de::Unexpected;
use serde::de::Visitor;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;

use crate::impl_error_from;
use crate::prelude::*;

#[derive(Debug, PartialEq)]
pub enum DescriptorError {
    /// Error while deriving the descriptors.
    DerivationError(ConversionError),

    /// Couldnt parse the descriptor
    InvalidDescriptor,

    /// The descriptors script may be an invalid one.
    Miniscript(miniscript::Error),

    /// Error while deleting these descriptors
    Deletion(Vec<DescriptorId>),

    /// Specified descriptor was not found.
    DescriptorNotFound,
}

impl_error_from!(DescriptorError,   miniscript::Error, Miniscript);
impl_error_from!(DescriptorError,   ConversionError, DerivationError);

use bitcoin::bip32::Xpub;
use bitcoin::Address;
use bitcoin::Network;
use bitcoin::ScriptBuf;
use miniscript::descriptor::ConversionError;
use serde::ser::SerializeMap;
use serde::ser::SerializeSeq;

/// Converts the inserted addresses, descriptors and xpubs
/// into compatible types so we can cache them using
/// the wallet API.
pub fn convert_to_internal(
    xpubs: &[Xpub],
    initial_descriptors: &[String],
    addresses: &[String],
    network: Network,
    addresses_per_descriptor: u32,
) -> Result<(Vec<ConcreteDescriptor>, Vec<ScriptBuf>), DescriptorError> {
    let mut xpub_descriptor_request: Vec<_> = xpubs
        .iter()
        .flat_map(|x| {
            let main_desc = DescriptorRequest {
                desc: format!("wpkh({x}/0/*)"),
                timestamp: RescanRequest::Full,
                label: format!("A Xpub Descriptor; {x}"),
                range: DerivationRange::End(addresses_per_descriptor),
                ..Default::default()
            };
            let change_desc = DescriptorRequest {
                desc: format!("wpkh({x}/1/*)"),
                timestamp: RescanRequest::Full,
                label: format!("A Xpub Change Descriptor; {x}"),
                range: DerivationRange::End(addresses_per_descriptor),
                ..Default::default()
            };

            [main_desc, change_desc]
        })
        .collect();

    let mut descriptors: Vec<DescriptorRequest> = initial_descriptors
        .iter()
        .map(|d| DescriptorRequest {
            desc: d.clone(),
            timestamp: RescanRequest::Full,
            label: format!("Initialized descriptor {d}"),
            range: DerivationRange::End(addresses_per_descriptor),
            ..Default::default()
        })
        .collect();

    xpub_descriptor_request.append(&mut descriptors);

    let mut desc_ret = Vec::<ConcreteDescriptor>::new();
    
    for d in xpub_descriptor_request.into_iter().map(DescriptorRequest::into_concrete_descriptors){
        desc_ret.append(& mut d?);
    } 

    let mut addr_ret = addresses
        .iter()
        .filter_map(|address| match Address::from_str(address) {
            Ok(address) => address.require_network(network).ok(),
            Err(e) => {
                log::error!("Invalid address provided: {address} \nReason: {e:?}");
                None
            }
        })
        .map(|address| address.script_pubkey())
        .collect::<Vec<ScriptBuf>>();

    desc_ret.dedup();
    addr_ret.dedup();

    Ok((desc_ret, addr_ret))
}

/// Since, precisely, Rust Bitcoin's [`Descriptor<DescriptorPublicKey>`] doesn't directly implement
/// serde we need this helper function so [`ConcreteDescriptor`] implements serde.
fn serialize_descriptor<S>(
    descriptor: &Descriptor<DescriptorPublicKey>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    // Convert descriptor to string and serialize that
    let descriptor_str = descriptor.to_string();
    serializer.serialize_str(&descriptor_str)
}

/// Since, precisely, Rust Bitcoin's [`Descriptor<DescriptorPublicKey>`] doesn't directly implement
/// serde we need this helper function so [`ConcreteDescriptor`] implements serde.
///
/// Wrapper around [`Descriptor::<DescriptorPublicKey>::from_str`].
fn deserialize_descriptor<'de, D>(
    deserializer: D,
) -> Result<Descriptor<DescriptorPublicKey>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Descriptor::<DescriptorPublicKey>::from_str(&s)
        .map_err(|e| D::Error::custom(format!("Descriptor parsing failed: {e}")))
}

/// "deletedecriptor" response structure that holds the request data regarding descriptors deletion.
#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteDescriptorRes {
    /// The deleted descriptors if the pulled flag is active
    pub pulled: Vec<ConcreteDescriptor>,
}

/// The String key we use to address descriptors in kv
pub const DESCRIPTOR_STRING_KEY: &str = "Descriptors";

/// Interpret [`DescriptorRequest`]s returning the extracted and already derived
/// descriptors. [`RescanRequest`] is reutilized here to yield a rescan
/// that would satisfy the users request.
///
/// Rescan requests are overridden as necessary, you can read further on [`RescanRequest::check_override`].
///
/// If a single descriptor raise any error the function will discard the descriptors and return all the collected errors.
pub fn handle_descriptors_requests(
    requests: Vec<DescriptorRequest>,
) -> Result<(Vec<ConcreteDescriptor>, RescanRequest), DescriptorError> {
    let mut rescan_request: RescanRequest = RescanRequest::SpecifiedTime(u32::MAX);
    let mut deriving_errors: Vec<DescriptorError> = Vec::new();
    let mut descriptors: Vec<ConcreteDescriptor> = Vec::new();

    for request in requests {
        rescan_request = rescan_request.check_override(&request.timestamp);

        descriptors.append(& mut request.into_concrete_descriptors()?);
    }
    
    return Ok((descriptors, rescan_request));    
}

/// Given a [`Vec<ConcreteDescriptor>`] finds those with [`&[DescriptorId]`] in a list of ids.
///
/// The return type is the index position of the found descriptors.
///
/// This function is used in the internals that interact with the DBs that hold the descriptors so it should be
/// efficient and infallible.
///
/// Wrapper of [`extract_matching_one`] that iterates over `to_match`.
pub fn extract_matching_ones(
    to_search: &[ConcreteDescriptor],
    to_match: &[DescriptorId],
) -> Vec<usize> {
    to_match
        .iter()
        .filter_map(|id| extract_matching_one(to_search, id))
        .collect()
}

/// Given a [`Vec<ConcreteDescriptor>`] finds those with [`DescriptorId`] in a list of ids.
///
/// The return type is the index position of the found descriptors.
///
/// This function is used in the internals that interact with the DBs that hold the descriptors so it should be
/// efficient and infallible.
pub fn extract_matching_one(
    to_search: &[ConcreteDescriptor],
    to_match: &DescriptorId,
) -> Option<usize> {
    to_search.iter().position(|d| d.match_id(to_match))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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
    pub descriptor: Descriptor<DescriptorPublicKey>,

    /// A label given for the descriptor
    pub label: String,

    /// The derivation range that this descriptor should have addresses
    pub range: DerivationRange,

    /// Whether this descriptor should be treated as a change
    pub internal: bool,
}

// Clippy asked.
unsafe impl Sync for ConcreteDescriptor {}
unsafe impl Send for ConcreteDescriptor {}

// Manually implements PartialEq so descriptors that have a different label doesnt differ.
impl PartialEq for ConcreteDescriptor {
    fn eq(&self, other: &Self) -> bool {
        self.descriptor == other.descriptor
    }
}

impl Default for ConcreteDescriptor {
    fn default() -> Self {
        const DEFAULT_P2PK_DESCRIPTOR: &str =
            "pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)";
        Self {
            descriptor: Descriptor::<DescriptorPublicKey>::from_str(DEFAULT_P2PK_DESCRIPTOR)
                .expect("Impossible to fail."),
            label: "A nice label".to_string(),
            internal: false,
            range: DerivationRange::default(),
        }
    }
}

fn how_many_descriptors_itll_yield(target: &[ConcreteDescriptor]) -> usize {
    let mut ret: usize = 0;
    for i in target.iter() {
        ret += i.resolve_counter()
    }
    ret
}

pub fn resolve_descriptors(to_resolve: &[ConcreteDescriptor]) -> Vec<Descriptor<DefiniteDescriptorKey>> {
    to_resolve.iter().map(ConcreteDescriptor::resolve).flatten().collect()
}

pub fn resolve_descriptors_with<C, T>(to_resolve: &[ConcreteDescriptor], into: C) -> Result<Vec<T>, DescriptorError>
    where C: Fn(Descriptor<DefiniteDescriptorKey>) -> Result<T, DescriptorError>, {
    let mut ret = Vec::<T>::with_capacity(how_many_descriptors_itll_yield(to_resolve));
    for d in to_resolve {
        let mut resolved = d.resolve_with(&into)?;
        ret.append(&mut resolved);
    }
    Ok(ret)
}

impl ConcreteDescriptor {
    /// Returns how much descriptors this one will yield.
    pub fn resolve_counter(&self) -> usize {
        if self.descriptor.has_wildcard() {
            return self.range.range().count()
        }
        1usize
    }

    /// Return the descriptors that this `ConcreteDescriptor` holds.
    pub fn resolve(&self) -> Vec<Descriptor<DefiniteDescriptorKey>> {
        let desc_count  = self.resolve_counter();
        let mut ret = Vec::<Descriptor<DefiniteDescriptorKey>>::with_capacity(desc_count);

        for i in self.range.range() {
            ret.push(self.descriptor.at_derivation_index(i).expect("Concrete Descriptors should always be valid"));
        }
        ret
    }

    /// Wrapper around `resolve` but you can pass a function to directly consume from the descriptor.
    /// 
    /// Util while needing to cast into addresses, take a look at pre-made functions.
    /// 
    /// You should prefer using this wrapper because it enforces compatible error handling and `into` is evaluated together with the cast, avoiding unecessary iterations.
    pub fn resolve_with<C, T>(&self, into: C) -> Result<Vec<T>, DescriptorError>
        where C: Fn(Descriptor<DefiniteDescriptorKey>) -> Result<T, DescriptorError>, {
        let desc_count  = self.resolve_counter();

        // we can expect that `into` will yield 1 `T` for each desc, right ?
        let mut ret = Vec::<T>::with_capacity(desc_count);

        for i in self.range.range() {
            let descriptor = self.descriptor.at_derivation_index(i)?;
            let cast = into(descriptor)?;
            ret.push(cast);
        }
        Ok(ret)
    }

    // TODO, the tests use some pretty normal case for casting descriptors.
    // pre define functions or closures to be used into the above C.

    /// wheter the given id represents this exact descriptor.
    pub fn match_id(&self, id: &DescriptorId) -> bool {
        match id {
            DescriptorId::Label(l) => l == &self.label,
            DescriptorId::Miniscript(m) => {
                if let Ok(d) = Descriptor::<DescriptorPublicKey>::from_str(&m.to_string()) {
                    return self.descriptor == d;
                }
                false
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
/// A struct that represents the json object "request" mentioned in "importdescriptors"
/// from bitcoin core rpc api. The internals use core's documentation directly, to better understand their expected behavior.
pub struct DescriptorRequest {
    /// (string, required) Descriptor to import.
    pub desc: String,

    /// (boolean, optional, default=false) Set this descriptor to be the active descriptor for the corresponding output type/externality
    #[serde(default)]
    pub active: bool,

    /// (numeric or array) If a ranged descriptor is used, this specifies the end or the range (in the form "begin,end") to import
    #[serde(default)]
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
    #[serde(default)]
    pub internal: bool,

    /// (string, optional, default="${descriptor}") Label to assign to the address, only allowed with internal=false
    #[serde(default)]
    pub label: String,
}

// These defaults can be useful.
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
    /// descriptor while being a multipath one.
    pub fn into_concrete_descriptors(self) -> Result<Vec<ConcreteDescriptor>, DescriptorError> {
        let secp = Secp256k1::default();

        let descriptor = Descriptor::parse_descriptor(&secp, &self.desc)?.0;

        descriptor.sanity_check()?;

        let mut range = self.range;
        
        if let Some(i) = self.next_index {
            range = range.with_included_index(i);
        }

        let ret = descriptor.into_single_descriptors()?.into_iter().map(
            |d|{
                ConcreteDescriptor { descriptor: d, label: self.label.clone(), range: range.clone(), internal: self.internal.clone() }
            }
        ).collect();
        Ok(ret)
    }
}

/// An unique descriptor identifier
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum DescriptorId {
    /// Identify a Descriptor by a Label.
    Label(String),

    /// Identify a Descriptor by hash.
    Hash(sha256d::Hash),

    /// Identify a Descriptor by the script itself.
    Miniscript(String),
}

impl DescriptorId {
    /// Computes the sha256 of this [`DescriptorId`].
    ///
    /// The Hash and Miniscript Variants are often used to index such a descriptor in the db.
    pub fn get_hash(&self) -> sha256d::Hash {
        match self {
            DescriptorId::Hash(hash) => *hash,
            DescriptorId::Miniscript(script) => sha256d::Hash::hash(script.as_bytes()),
            DescriptorId::Label(label) => sha256d::Hash::hash(label.as_bytes()),
        }
    }
}
impl Serialize for DescriptorId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(1))?;
        match self {
            DescriptorId::Label(s) => map.serialize_entry("label", s)?,
            DescriptorId::Hash(h) => map.serialize_entry("hash", h)?,
            DescriptorId::Miniscript(s) => map.serialize_entry("miniscript", s)?,
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for DescriptorId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DescriptorIdVisitor;

        impl<'de> Visitor<'de> for DescriptorIdVisitor {
            type Value = DescriptorId;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str(
                    "a JSON object with exactly one key: 'label', 'hash', or 'miniscript'",
                )
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let key: String = map
                    .next_key()?
                    .ok_or_else(|| de::Error::custom("expected non-empty map"))?;

                let value = match key.as_str() {
                    "label" => {
                        let s: String = map.next_value()?;
                        DescriptorId::Label(s)
                    }
                    "hash" => {
                        let h: sha256d::Hash = map.next_value()?;
                        DescriptorId::Hash(h)
                    }
                    "miniscript" => {
                        let s: String = map.next_value()?;
                        DescriptorId::Miniscript(s)
                    }
                    _ => {
                        return Err(de::Error::unknown_field(
                            &key,
                            &["label", "hash", "miniscript"],
                        ))
                    }
                };

                // Ensure no extra fields
                if map.next_key::<String>()?.is_some() {
                    return Err(de::Error::custom("expected exactly one key"));
                }

                Ok(value)
            }
        }

        deserializer.deserialize_map(DescriptorIdVisitor)
    }
}

impl FromStr for DescriptorId {
    type Err = DescriptorError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if Descriptor::<DescriptorPublicKey>::from_str(s).is_ok() {
            return Ok(DescriptorId::Miniscript(s.into()));
        }
        Err(DescriptorError::InvalidDescriptor)
    }
}

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
/// Time from which to start rescanning the blockchain for a descriptor request from "importdescriptors"
pub enum RescanRequest {
    /// Tells to make a precise rescan into
    SpecifiedTime(u32),

    /// Tells to make a full rescan
    Full,

    /// Tells to ignore rescan.
    Now,
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
            (RescanRequest::Now, RescanRequest::Full) => RescanRequest::Full, // Ignore can only be overridden by Full.
            (RescanRequest::SpecifiedTime(_), RescanRequest::Full) => RescanRequest::Full, // SpecifiedTime can be overridden by Full.
            (RescanRequest::SpecifiedTime(_), RescanRequest::Now) => RescanRequest::Now, // SpecifiedTime can be overridden by Ignore.
            (RescanRequest::SpecifiedTime(have), RescanRequest::SpecifiedTime(given)) => {
                RescanRequest::SpecifiedTime(*have.min(given))
            } // SpecifiedTime can be overridden by a lesser Time.
            _ => self.clone(), // All the other cases shouldn't cause an override.
        }
    }

    /// Serializer helper to match Core's timestamp's descriptor request api.
    pub fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            RescanRequest::SpecifiedTime(t) => serializer.serialize_u32(*t),
            RescanRequest::Full => serializer.serialize_u32(0),
            RescanRequest::Now => serializer.serialize_str("now"),
        }
    }

    /// Deserializer helper to match Core's timestamp's descriptor request api.
    ///
    /// This function should make any integer, other than 0, into a [RescanRequest::SpecifiedTime]. 0 should
    /// evaluate to a [RescanRequest::Full] and the literal "now" to a [RescanRequest::Now].
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RescanRequestVisitor;

        impl<'de> Visitor<'de> for RescanRequestVisitor {
            type Value = RescanRequest;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("integer or string \"now\"")
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match value {
                    0 => Ok(RescanRequest::Full),
                    _ => {
                        if value <= u32::MAX as u64 {
                            return Ok(RescanRequest::SpecifiedTime(value as u32));
                        }
                        Err(E::invalid_value(Unexpected::Unsigned(value), &self))
                    }
                }
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value == "now" {
                    return Ok(RescanRequest::Now);
                }
                Err(E::invalid_value(Unexpected::Str(value), &self))
            }
        }

        deserializer.deserialize_any(RescanRequestVisitor)
    }
}

// Implement Serialize and Deserialize using our custom methods
impl Serialize for RescanRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        RescanRequest::serialize(self, serializer)
    }
}

impl<'de> Deserialize<'de> for RescanRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        RescanRequest::deserialize(deserializer)
    }
}

/// Represents a descriptor range, which can define the end of a range or an entire one.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DerivationRange {
    /// This range tells to go from zero until this exact index.
    End(u32),

    /// This range tells to from the first index until the second.
    Range(u32, u32),
}
impl DerivationRange {
    /// Consumes the [`DerivationRange`] in favor of an iterable [`Range<u32>`]
    const fn range(&self) -> Range<u32> {
        match self {
            Self::End(e) => 0..*e,
            Self::Range(s, e) => *s..*e,
        }
    }

    /// Extends the inner range with the given index
    fn with_included_index(self, to_include: u32) -> Self {
        match self {
            Self::End(e) =>{
                if to_include > e {
                    Self::End(to_include);
                }
                self
            }
            Self::Range(s, e ) => {
                // here i know that s can only be less than e. Otherwise it would be a Range(1) or the tuple have a invalid positioning.
                if to_include < s {
                    Self::Range(to_include, e)
                } else {
                    Self::Range(s, to_include)
                }
            }
        }
    }
}

impl Serialize for DerivationRange {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            DerivationRange::End(e) => serializer.serialize_u32(*e),
            DerivationRange::Range(s, e ) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element(s)?;
                seq.serialize_element(e)?;
                seq.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for DerivationRange {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DerivationRangeVisitor;

        impl<'de> Visitor<'de> for DerivationRangeVisitor {
            type Value = DerivationRange;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("u32 or [u32; 2]")
            }

            // Handle single integer
            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value <= u32::MAX as u64 {
                    return Ok(DerivationRange::End(value as u32));
                }
                Err(E::invalid_value(Unexpected::Unsigned(value), &self))
            }

            // Handle array
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let first: u32 = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;

                let second: u32 = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;

                // Ensure no extra elements
                if seq.next_element::<de::IgnoredAny>()?.is_some() {
                    return Err(de::Error::invalid_length(3, &"exactly 2 elements"));
                }

                Ok(DerivationRange::Range(first, second))
            }
        }

        // Try both deserialization methods
        deserializer.deserialize_any(DerivationRangeVisitor)
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
    use crate::slip132::FromSlip132;

    #[test]
    fn test_descriptorrange_serde_implementation() {
        // Serialization
        let end = DerivationRange::End(10);
        assert_eq!(serde_json::to_string(&end).unwrap(), "10");

        let range = DerivationRange::Range(5, 15);
        assert_eq!(serde_json::to_string(&range).unwrap(), "[5,15]");

        // Deserialization
        let from_int: DerivationRange = serde_json::from_str("42").unwrap();
        assert_eq!(from_int, DerivationRange::End(42));

        let from_array: DerivationRange = serde_json::from_str("[1,2]").unwrap();
        assert_eq!(from_array, DerivationRange::Range(1, 2));
    }

    #[test]
    fn test_descriptorid_serde_implementation() {
        const HASH_STR: &str = "d96673894f50ac16db8293d3419c44d634c066b83027a3f144168deac4c68252";
        const MINISCRIPT_STR: &str = "wpkh(xpub6CFy3kRXorC3NMTt8qrsY9ucUfxVLXyFQ49JSLm3iEG5gfAmWewYFzjNYFgRiCjoB9WWEuJQiyYGCdZvUTwPEUPL9pPabT8bkbiD9Po47XG/0/0)#yd323ycg";
        const LABEL_STR: &str = "vinteum is awesome";

        let label_id = DescriptorId::Label(LABEL_STR.to_string());
        let json = serde_json::to_string(&label_id).unwrap();
        assert_eq!(json, format!("{{\"label\":\"{LABEL_STR}\"}}"));

        let casted = sha256d::Hash::from_str(HASH_STR).unwrap();
        let hash_id = DescriptorId::Hash(casted);
        let json = serde_json::to_string(&hash_id).unwrap();
        assert_eq!(json, format!("{{\"hash\":\"{HASH_STR}\"}}"));

        let miniscript_id = DescriptorId::Miniscript(MINISCRIPT_STR.to_string());
        let json = serde_json::to_string(&miniscript_id).unwrap();
        assert_eq!(json, format!("{{\"miniscript\":\"{MINISCRIPT_STR}\"}}"));

        let json_data = format!("{{\"hash\":\"{HASH_STR}\"}}");
        if let DescriptorId::Hash(got) = serde_json::from_str(&json_data).unwrap() {
            assert_eq!(got.to_string(), HASH_STR);
        } else {
            panic!("Ser/De for DescriptorId::Hash is broken");
        };

        let json_data = format!("{{\"label\":\"{LABEL_STR}\"}}");
        if let DescriptorId::Label(got) = serde_json::from_str(&json_data).unwrap() {
            assert_eq!(got.to_string(), LABEL_STR);
        } else {
            panic!("Ser/De for DescriptorId::Label is broken");
        };

        let json_data = format!("{{\"miniscript\":\"{MINISCRIPT_STR}\"}}");
        if let DescriptorId::Miniscript(got) = serde_json::from_str(&json_data).unwrap() {
            assert_eq!(got.to_string(), MINISCRIPT_STR);
        } else {
            panic!("Ser/De for DescriptorId::Miniscript is broken");
        };
    }

    #[test]
    fn test_rescan_request_serde_implementation() {
        let json_full = "0";
        let rescan: RescanRequest = serde_json::from_str(json_full).unwrap();
        assert_eq!(rescan, RescanRequest::Full);

        let json_ignore = "\"now\"";
        let rescan: RescanRequest = serde_json::from_str(json_ignore).unwrap();
        assert_eq!(rescan, RescanRequest::Now);

        let json_specified = "1650000000";
        let rescan: RescanRequest = serde_json::from_str(json_specified).unwrap();
        assert_eq!(rescan, RescanRequest::SpecifiedTime(1650000000));
    }

    #[test]
    fn test_rescan_priority() {
        let test_cases = vec![
            // These cases should cover every case where an override should occur
            // (existing, new, expected_result)
            (RescanRequest::Full, RescanRequest::Now, RescanRequest::Full), // A full rescan request should remain when compared with an ignore one.
            (RescanRequest::Now, RescanRequest::Full, RescanRequest::Full), // An ignore rescan request should be overridden by a full one.
            (
                RescanRequest::SpecifiedTime(100),
                RescanRequest::Full,
                RescanRequest::Full,
            ), // A full rescan request should override a SpecifiedTime one
            (
                RescanRequest::SpecifiedTime(100),
                RescanRequest::Now,
                RescanRequest::Now,
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
    fn test_error_returning() {
        //TODO: expand this for every enum case in DescriptorError
        let bad_req = DescriptorRequest {
            desc: "invalid".into(),
            ..Default::default()
        };

        let result = handle_descriptors_requests(vec![Default::default(), bad_req]);

        assert!(result.is_err()); // Okay, it was supposed to fail and it did.
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
                timestamp: RescanRequest::Now,
                ..Default::default()
            },
            DescriptorRequest {
                timestamp: RescanRequest::SpecifiedTime(50),
                ..Default::default()
            },
        ];

        let (descs, rescan) = handle_descriptors_requests(reqs).unwrap();

        assert_eq!(descs.len(), 2);

        assert_eq!(rescan, RescanRequest::Now);
    }

    #[test]
    fn test_descriptor_matching() {
        let d = ConcreteDescriptor::default();

        // Test different ID types
        let hand_hash_id = DescriptorId::Hash(d.get_hash());
        let hand_label_id = DescriptorId::Label("A nice label".into()); // A nice label is the default string used for labelling
        let hand_ms_id = DescriptorId::Miniscript(d.descriptor.to_string());

        // This block and the next 3 asserts are only being added here to
        // test the get_id function.
        let gen_hash_id = d.get_id(DescriptorIdSelector::Hash);
        let gen_label_id = d.get_id(DescriptorIdSelector::Label);
        let gen_ms_id = d.get_id(DescriptorIdSelector::Miniscript);

        assert_eq!(gen_hash_id, hand_hash_id);
        assert_eq!(gen_label_id, hand_label_id);
        assert_eq!(gen_ms_id, hand_ms_id);

        let descs = vec![d];

        assert_eq!(extract_matching_one(&descs, &hand_hash_id), Some(0));
        assert_eq!(extract_matching_one(&descs, &hand_label_id), Some(0));
        assert_eq!(extract_matching_one(&descs, &hand_ms_id), Some(0));

        // Test non-existent
        assert!(extract_matching_one(&descs, &DescriptorId::Label("missing".into())).is_none());
    }

    #[test]
    fn test_initial_wallet_build() {
        let addresses_per_descriptor = 1;
        let network = Network::Bitcoin;

        let zpub = Xpub::from_slip132_str("zpub6qvVf5mN7DH14wr7oZS7xL6cpcFPDmxFEHBk18YpUF1qnroE1yGfW83eafbbi23dzRk7jrVXeJFMyCo3urmQpwkXtVnRmGmaJ3qVvdwx4mB").unwrap();

        // Build wallet from xpub (in this case a zpub from slip132 standard)
        let w1_xpub =
            convert_to_internal(&[zpub], &[], &[], network, addresses_per_descriptor).unwrap().0;

        // Build same wallet from output descriptor
        let w1_descriptor = convert_to_internal(&[], &[
            "wpkh(xpub6CFy3kRXorC3NMTt8qrsY9ucUfxVLXyFQ49JSLm3iEG5gfAmWewYFzjNYFgRiCjoB9WWEuJQiyYGCdZvUTwPEUPL9pPabT8bkbiD9Po47XG/<0;1>/*)".to_owned()
        ], &[], network, addresses_per_descriptor).unwrap().0;

        let w1_xpub_resolved = resolve_descriptors(&w1_xpub);

        let w1_descriptor_resolved = resolve_descriptors(&w1_descriptor);

        // Using both methods the result should be the same
        assert_eq!(w1_xpub_resolved, w1_descriptor_resolved);

        // Both normal receiving descriptor and change descriptor should be present
        assert_eq!(
            resolve_descriptors_with(&w1_descriptor, |d| Ok(d.to_string())).unwrap(),
            vec!["wpkh(xpub6CFy3kRXorC3NMTt8qrsY9ucUfxVLXyFQ49JSLm3iEG5gfAmWewYFzjNYFgRiCjoB9WWEuJQiyYGCdZvUTwPEUPL9pPabT8bkbiD9Po47XG/0/0)#yd323ycg",
                 "wpkh(xpub6CFy3kRXorC3NMTt8qrsY9ucUfxVLXyFQ49JSLm3iEG5gfAmWewYFzjNYFgRiCjoB9WWEuJQiyYGCdZvUTwPEUPL9pPabT8bkbiD9Po47XG/1/0)#4e5tv3gs"]
        );

        // Receiving and change addresses
        let addresses = vec![
            "bc1q24629yendf7q0dxnw362dqccn52vuz9s0z59hr".to_owned(),
            "bc1q88guum89mxwszau37m3y4p24renwlwgtkscl6x".to_owned(),
        ];

        assert_eq!(
                resolve_descriptors_with(&w1_descriptor
                , |d| Ok(d.address(network).unwrap().to_string())).unwrap(),
            addresses
        );

        // We can build from these addresses
        let w1_addresses =
            convert_to_internal(&[], &[], &addresses, network, addresses_per_descriptor).unwrap();

        let casted_w1_addr = resolve_descriptors_with(&w1_descriptor, | d| Ok(d.address(network)?.script_pubkey())).unwrap();

        // And the result will be the same as from xpub/descriptor
        assert_eq!(casted_w1_addr, w1_addresses.1);
    }

    #[test]
    fn descriptor_index_control() {
        let addresses_per_descriptor = 42u32;

        let network = Network::Testnet;

        let wallet = convert_to_internal(&[], &[
        "wpkh(xpub6CFy3kRXorC3NMTt8qrsY9ucUfxVLXyFQ49JSLm3iEG5gfAmWewYFzjNYFgRiCjoB9WWEuJQiyYGCdZvUTwPEUPL9pPabT8bkbiD9Po47XG/<0;1>/*)".to_owned()
        ], &[], network, addresses_per_descriptor).unwrap().0;
        
        let expected_count = how_many_descriptors_itll_yield(&wallet);

        let resolved = resolve_descriptors(&wallet);
        
        // Resolving and counting does match
        assert_eq!(resolved.len(), expected_count);
        
        // Ill try directly from a request expecting to assert wheter next_index related index control is properly working.
        let from_request = DescriptorRequest {
            ..Default::default()
        };


    }
    
    #[test]
    fn test_initial_wallet_build_multisig_testnet() {
        let addresses_per_descriptor = 1;

        let network = Network::Testnet;

        let w1_descriptor = convert_to_internal(&[], &[
            "wsh(sortedmulti(1,[54ff5a12/48h/1h/0h/2h]tpubDDw6pwZA3hYxcSN32q7a5ynsKmWr4BbkBNHydHPKkM4BZwUfiK7tQ26h7USm8kA1E2FvCy7f7Er7QXKF8RNptATywydARtzgrxuPDwyYv4x/<0;1>/*,[bcf969c0/48h/1h/0h/2h]tpubDEFdgZdCPgQBTNtGj4h6AehK79Jm4LH54JrYBJjAtHMLEAth7LuY87awx9ZMiCURFzFWhxToRJK6xp39aqeJWrG5nuW3eBnXeMJcvDeDxfp/<0;1>/*))#fuw35j0q".to_owned()
        ], &[], network, addresses_per_descriptor).unwrap();

        let addresses = vec![
            "tb1q2eeqw57e7pmrh5w3wkrshctx2qk80vf4mu7l7ek3ne4hg3lmcrnqcwejgj".to_owned(),
            "tb1q6dpyc3jyqelgfwksedef0k2244rcg4gf6wvqm463lk907es2m08qnrfky7".to_owned(),
        ];


        let to_script = resolve_descriptors_with(&w1_descriptor
            .0, |d| Ok(d.address(network)?.to_string())).unwrap();
        
        assert_eq!(to_script, addresses);
    }
}
