//! Holds the methods and types to help handling descriptors exactly how floresta needs.
//!
//! Everything in this module works around [`DescriptorUnit`]. Heres a short description about each struct and what you should do with them.
//!
//! [`DescriptorUnit`] holds a [`Descriptor<DescriptorPublicKey>`] which should satisfy all use cases that floresta might need now,
//! it also holds some metadata such as a `DerivationRange` that accepts operations to extend and sum indices.
//!
//! [`DescriptorRequest`] - The input scheme for the `importdescriptors` RPC that helps us to batch produce [`DescriptorUnit`]s, it is pretty extensive in options and should support
//! any kind of usecase for a descriptor. Internally in floresta, its used as a "Descriptor Constructor" through [`DescriptorRequest::into_unit`], which should be the only way to
//! produce [`DescriptorUnit`]s, facilitating error handling making every [`DescriptorUnit`] already statically valid.
//!
//! [`DerivationRange`] - Holds derivation data for a descriptor and counts with index operations.
//!
//! [`DescriptorId`] - Identifies a descriptor by its label, miniscript or hash (double sha256 of the miniscript).
//! Currently, while the watch only uses a kv database, we use [`DescriptorId::Hash`] variant to indexate the [`DescriptorUnit`],
//! that is, you can use both [`DescriptorId::Hash`] and [`DescriptorId::Miniscript`], since the hash variant is just the miniscript
//! double hashed to instantly return the persisted [`DescriptorUnit`]. Otherwise you would have to iterate after a [`DescriptorUnit`] that
//! matches the [`DescriptorId::Label`].
//!
//! [`RescanRequest`] - Tells from where the user needs for floresta to rescan, it counts with [`RescanRequest::check_override`] thats used to return the most abrangent [`RescanRequest`]
//! to satisfy the user [`DescriptorRequest`].

use core::cmp::max;
use core::cmp::min;
use core::fmt;
use std::ops::Range;
use std::str::FromStr;

use bitcoin::hashes::sha256d;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::Secp256k1;
use floresta_common::impl_error_from;
use miniscript::descriptor::ConversionError;
use miniscript::DefiniteDescriptorKey;
use miniscript::Descriptor;
use miniscript::DescriptorPublicKey;
use serde::de;
use serde::de::Error;
use serde::de::MapAccess;
use serde::de::SeqAccess;
use serde::de::Unexpected;
use serde::de::Visitor;
use serde::ser::SerializeMap;
use serde::ser::SerializeSeq;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;

#[derive(Debug, PartialEq)]
pub enum DescriptorError {
    /// Error while deriving the descriptors.
    DerivationError(ConversionError),

    /// Couldnt parse the descriptor
    InvalidDescriptor,

    /// The descriptors script may be an invalid one.
    Miniscript(miniscript::Error),

    /// Specified descriptor was not found.
    DescriptorNotFound,
}

impl_error_from!(DescriptorError, miniscript::Error, Miniscript);
impl_error_from!(DescriptorError, ConversionError, DerivationError);

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

impl DescriptorRequest {
    /// Interpret [`DescriptorRequest`]s returning the extracted and already derived
    /// descriptors.
    ///
    /// The returned [`RescanRequest`] is the more embracing in order to satisfy the users request.
    /// You can read further on [`RescanRequest::check_override`].
    pub fn handle_requests(
        requests: Vec<DescriptorRequest>,
    ) -> Result<(Vec<DescriptorUnit>, RescanRequest), DescriptorError> {
        let mut rescan_request: RescanRequest = RescanRequest::SpecifiedTime(u32::MAX);
        let mut descriptors: Vec<DescriptorUnit> = Vec::new();

        for request in requests {
            rescan_request = rescan_request.check_override(&request.timestamp);

            descriptors.append(&mut request.into_unit()?);
        }

        Ok((descriptors, rescan_request))
    }

    /// Consume the [`DescriptorRequest`] into a [`DescriptorUnit`].
    pub fn into_unit(self) -> Result<Vec<DescriptorUnit>, DescriptorError> {
        let secp = Secp256k1::default();

        let descriptor = Descriptor::parse_descriptor(&secp, &self.desc)?.0;

        descriptor.sanity_check()?;

        let mut range = self.range;

        if let Some(i) = self.next_index {
            range = range.with_included_index(i);
        }

        let ret = descriptor
            .into_single_descriptors()?
            .into_iter()
            .map(|d| DescriptorUnit {
                descriptor: d,
                label: self.label.clone(),
                range: range.clone(),
                internal: self.internal,
            })
            .collect();
        Ok(ret)
    }
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

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Holds a path set descriptor, a label, an internal flag indicating if its a change
/// address and a derivation range that we expect to have addresses.
///
/// This is the object that we persist inside the database.
pub struct DescriptorUnit {
    /// The descriptor itself, with its path already set, that can be derived.
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

impl DescriptorUnit {
    /// Sums the given index to the inner range.
    ///
    /// Wrapper around [`DerivationRange::sum_index`]
    pub fn sum_index(&mut self, idx: u32) {
        self.range = self.range.sum_index(idx);
    }

    /// Sums the given index to the inner range.
    ///
    /// Same as [`DescriptorUnit::sum_index`] but for an array.
    pub fn batch_sum_index(to_sum: &mut Vec<DescriptorUnit>, idx: u32) {
        for d in to_sum {
            d.sum_index(idx);
        }
    }

    /// derive the descriptors off the given array, deriving all its children.
    ///
    /// Similar to [`DescriptorUnit::derive`] but for an array.
    pub fn derive_descriptors(
        to_derive: &[DescriptorUnit],
    ) -> Vec<Descriptor<DefiniteDescriptorKey>> {
        to_derive.iter().flat_map(DescriptorUnit::derive).collect()
    }

    /// Same as [`DescriptorUnit::derive_descriptors`] but accepts an convert function thats applied while the iteration is going.
    ///
    /// Similar to [`DescriptorUnit::derive_with`] but for an array.
    pub fn derive_descriptors_with<C, T>(
        to_derive: &[DescriptorUnit],
        into: C,
    ) -> Result<Vec<T>, DescriptorError>
    where
        C: Fn(Descriptor<DefiniteDescriptorKey>) -> Result<T, DescriptorError>,
    {
        let mut ret = Vec::<T>::with_capacity(Self::batch_yield_count(to_derive));
        for d in to_derive {
            let mut derived = d.derive_with(&into)?;
            ret.append(&mut derived);
        }
        Ok(ret)
    }

    /// Same as [`DescriptorUnit::yielding_count`] but for an array.
    pub fn batch_yield_count(target: &[DescriptorUnit]) -> usize {
        let mut ret: usize = 0;
        for i in target.iter() {
            ret += i.yielding_count()
        }
        ret
    }

    /// Returns how many descriptors this one will generate.
    ///
    /// Good for Vector control, avoiding unnecessary allocation.
    pub fn yielding_count(&self) -> usize {
        if self.descriptor.has_wildcard() {
            return self.range.range().count();
        }
        1usize
    }

    /// Return the descriptors that this [`DescriptorUnit`] holds.
    pub fn derive(&self) -> Vec<Descriptor<DefiniteDescriptorKey>> {
        let desc_count = self.yielding_count();
        let mut ret = Vec::<Descriptor<DefiniteDescriptorKey>>::with_capacity(desc_count);

        for i in self.range.range() {
            ret.push(
                self.descriptor
                    .at_derivation_index(i)
                    .expect("Descriptor units should always be valid"),
            );
        }
        ret
    }

    /// Similar to [`DescriptorUnit::derive`] but you can pass a function to consume the derived
    /// [`Descriptor<DefiniteDescriptorKey>`], converting them to something like an Address.
    ///
    /// You should prefer using this wrapper because it enforces compatible error handling and `into` is applied right after cast to a [`Descriptor<DefiniteDescriptorKey>`], avoiding unnecessary iterations.
    pub fn derive_with<C, T>(&self, into: C) -> Result<Vec<T>, DescriptorError>
    where
        C: Fn(Descriptor<DefiniteDescriptorKey>) -> Result<T, DescriptorError>,
    {
        let desc_count = self.yielding_count();

        // we can expect that `into` will atleast yield 1 `T` for each desc, right ?
        let mut ret = Vec::<T>::with_capacity(desc_count);

        for i in self.range.range() {
            let descriptor = self.descriptor.at_derivation_index(i)?;
            let cast = into(descriptor)?;
            ret.push(cast);
        }

        Ok(ret)
    }

    /// whether the given id represents this exact descriptor.
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

    /// Returns a sha256d of this [`DescriptorUnit`]s miniscript.
    pub fn get_hash(&self) -> sha256d::Hash {
        sha256d::Hash::hash(self.descriptor.to_string().as_bytes())
    }

    /// Returns the [`DescriptorId::Hash`] that refers to this [`DescriptorUnit`].
    pub fn get_hash_id(&self) -> DescriptorId {
        DescriptorId::Hash(self.get_hash())
    }

    /// Returns the [`DescriptorId::Label`] that refers to this [`DescriptorUnit`].
    pub fn get_label_id(&self) -> DescriptorId {
        DescriptorId::Label(self.label.clone())
    }

    /// Returns the [`DescriptorId::Miniscript`] that refers to this [`DescriptorUnit`].
    pub fn get_miniscript(&self) -> DescriptorId {
        DescriptorId::Miniscript(self.descriptor.to_string())
    }
}

/// Since, precisely, Rust Bitcoin's [`Descriptor<DescriptorPublicKey>`] doesn't directly implement
/// serde we need this helper function so [`DescriptorUnit`] implements serde.
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
/// serde we need this helper function so [`DescriptorUnit`] implements serde.
///
/// Wrapper around [`Descriptor::from_str`].
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

// Clippy asked.
unsafe impl Sync for DescriptorUnit {}
unsafe impl Send for DescriptorUnit {}

// Manually implements PartialEq so descriptors that have a different label doesnt differ.
impl PartialEq for DescriptorUnit {
    fn eq(&self, other: &Self) -> bool {
        self.descriptor == other.descriptor
    }
}

impl Default for DescriptorUnit {
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
    /// Given a [`Vec<DescriptorUnit>`] finds those with [`&[DescriptorId]`] in a list of ids.
    ///
    /// The return type is the index position of the found descriptors.
    ///
    /// This function is used in the internals that interact with the DBs that hold the descriptors so it should be
    /// efficient and infallible.
    ///
    /// Wrapper around [`DescriptorId::extract_matching_one`] that iterates over `to_match`.
    pub fn extract_matching_ones(
        to_search: &[DescriptorUnit],
        to_match: &[DescriptorId],
    ) -> Vec<usize> {
        to_match
            .iter()
            .filter_map(|id| Self::extract_matching_one(to_search, id))
            .collect()
    }

    /// Given a [`Vec<DescriptorUnit>`] finds those with [`DescriptorId`] in a list of ids.
    ///
    /// The return type is the index position of the found descriptors.
    ///
    /// This function is used in the internals that interact with the DBs that hold the descriptors so it should be
    /// efficient and infallible.
    pub fn extract_matching_one(
        to_search: &[DescriptorUnit],
        to_match: &DescriptorId,
    ) -> Option<usize> {
        to_search.iter().position(|d| d.match_id(to_match))
    }

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

    /// Constructor. `stop_at` cannot be zero.
    pub fn new_end(stop_at: u32) -> Result<DerivationRange, DerivationRangeCreationError> {
        if stop_at == 0 {
            return Err(DerivationRangeCreationError::Stop);
        }
        Ok(Self::End(stop_at))
    }

    /// Constructor. `start_at` cannot be zero and higher than `stop_at`.
    pub fn new_ranged(
        start_at: u32,
        stop_at: u32,
    ) -> Result<DerivationRange, DerivationRangeCreationError> {
        if start_at == 0 {
            return Err(DerivationRangeCreationError::Start);
        }

        if start_at >= stop_at {
            return Err(DerivationRangeCreationError::Range);
        }

        Ok(Self::Range(start_at, stop_at))
    }

    /// Extends the inner range with the given index.
    pub fn with_included_index(self, to_include: u32) -> Self {
        match self {
            Self::End(e) => Self::End(max(e, to_include)),
            Self::Range(s, e) => Self::Range(min(s, to_include), max(e, to_include)),
        }
    }

    /// Sums the derivation with the given.
    pub fn sum_index(&self, to_sum: u32) -> DerivationRange {
        match self {
            Self::End(e) => DerivationRange::End(to_sum + e),
            Self::Range(s, e) => DerivationRange::Range(*s, to_sum + e),
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
            DerivationRange::Range(s, e) => {
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
                if value > u32::MAX as u64 {
                    return Err(E::invalid_value(Unexpected::Unsigned(value), &self));
                }

                DerivationRange::new_end(value as u32).map_err(de::Error::custom)
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
                DerivationRange::new_ranged(first, second).map_err(de::Error::custom)
            }
        }

        // Try both deserialization methods
        deserializer.deserialize_any(DerivationRangeVisitor)
    }
}

impl Default for DerivationRange {
    fn default() -> Self {
        DerivationRange::End(42) // 1 ? Should be enough.
    }
}

pub enum DerivationRangeCreationError {
    /// The stop value cant be 0.
    Stop,

    /// The start value cant be 0. Use `DerivationRange::End` instead.
    Start,

    /// start_at and stop_at doesnt form a range.
    Range,
}

impl fmt::Display for DerivationRangeCreationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DerivationRangeCreationError::Stop => {
                write!(f, "stop at cannot be 0")
            }
            DerivationRangeCreationError::Start => {
                write!(
                    f,
                    "start at cannot be 0. Use `DerivationRange::End` instead"
                )
            }
            DerivationRangeCreationError::Range => {
                write!(f, "start_at and stop_at do not form a valid range")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn derivation_range_constructors_errors() {
        assert!(matches!(
            DerivationRange::new_end(0),
            Err(DerivationRangeCreationError::Stop)
        ));

        assert!(matches!(
            DerivationRange::new_ranged(0, 10),
            Err(DerivationRangeCreationError::Start)
        ));

        assert!(matches!(
            DerivationRange::new_ranged(5, 5),
            Err(DerivationRangeCreationError::Range)
        ));

        assert!(matches!(
            DerivationRange::new_ranged(10, 5),
            Err(DerivationRangeCreationError::Range)
        ));
    }

    #[test]
    fn derivation_range_with_included_index_behaviour() {
        // End variant
        let r = DerivationRange::End(10).with_included_index(15);
        assert_eq!(r, DerivationRange::End(15));
        let r = DerivationRange::End(10).with_included_index(5);
        assert_eq!(r, DerivationRange::End(10));

        // Range variant
        let r = DerivationRange::Range(5, 10).with_included_index(3);
        assert_eq!(r, DerivationRange::Range(3, 10));
        let r = DerivationRange::Range(5, 10).with_included_index(12);
        assert_eq!(r, DerivationRange::Range(5, 12));
    }

    #[test]
    fn descriptor_unit_eq_behaviour() {
        let unit = DescriptorUnit::default();

        // PartialEq should ignore label/internal/range, compares only descriptor
        let mut other = unit.clone();
        other.label = "mu e tniv".into();
        other.internal = false;
        other.range = DerivationRange::End(42);
        assert_eq!(unit, other);
    }

    #[test]
    fn multipath_next_index_extends_range_and_counts() {
        // Start with End(5) but next_index=7 should extend to 7
        let req = DescriptorRequest {
            desc: DESCTEST_MULTIPATH.to_string(),
            range: DerivationRange::End(5),
            next_index: Some(7),
            ..DescriptorRequest::default()
        };

        let mut units = req.into_unit().unwrap();
        assert_eq!(units.len(), 2);

        // Each path yields 7, total 14
        let count = DescriptorUnit::batch_yield_count(&units);
        assert_eq!(count, 14);

        // derive and count
        let derived = DescriptorUnit::derive_descriptors(&units);
        assert_eq!(derived.len(), 14);

        // Summing index increases the end on both
        DescriptorUnit::batch_sum_index(&mut units, 1);
        let count_after = DescriptorUnit::batch_yield_count(&units);
        assert_eq!(count_after, 16);
    }

    #[test]
    fn descriptor_id_get_hash_matches_unit_hash() {
        let unit = DescriptorUnit::default();
        let ms_id = unit.get_miniscript(); // Miniscript(string)
        let id_hash = ms_id.get_hash();
        let unit_hash = unit.get_hash();
        assert_eq!(id_hash, unit_hash);
    }

    #[test]
    fn rescan_request_deserialize_invalid_inputs() {
        // Stringified number is invalid (only integer or "now")
        assert!(serde_json::from_str::<RescanRequest>("\"123\"").is_err());
        // Random string
        assert!(serde_json::from_str::<RescanRequest>("\"invalid\"").is_err());
        // Negative integer
        assert!(serde_json::from_str::<RescanRequest>("-1").is_err());
        // Non-scalar
        assert!(serde_json::from_str::<RescanRequest>("[]").is_err());
        assert!(serde_json::from_str::<RescanRequest>("{}").is_err());
    }

    #[test]
    fn handle_requests_respects_next_index_with_ranges() {
        // Demonstrate next_index expanding a ranged [start, end)
        let req = DescriptorRequest {
            desc: DESCTEST_MULTIPATH.to_string(),
            // initial range [5, 10), then include index 12 -> [5, 12)
            range: DerivationRange::Range(5, 10),
            next_index: Some(12),
            ..DescriptorRequest::default()
        };
        let units = req.into_unit().expect("into_unit");
        assert_eq!(units.len(), 2);
        assert_eq!(units[0].range, DerivationRange::Range(5, 12));
        assert_eq!(units[1].range, DerivationRange::Range(5, 12));
    }

    #[test]
    fn descriptor_id_serde_hash_roundtrip_and_consistency() {
        // Ensure our JSON ser/de for hash variant round-trips and matches a known value
        let unit = DescriptorUnit::default();
        let hash = unit.get_hash();
        let id = DescriptorId::Hash(hash);
        let json = serde_json::to_string(&id).unwrap();
        let back: DescriptorId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);

        // Also ensure the explicit parse from hex equals what we produced
        let parsed = sha256d::Hash::from_str(&hash.to_string()).unwrap();
        assert_eq!(parsed, hash);
    }
    /// WPKH, multipath 0 and 1, ranged.
    pub const DESCTEST_MULTIPATH: &str = "wpkh(xpub6CFy3kRXorC3NMTt8qrsY9ucUfxVLXyFQ49JSLm3iEG5gfAmWewYFzjNYFgRiCjoB9WWEuJQiyYGCdZvUTwPEUPL9pPabT8bkbiD9Po47XG/<0;1>/*)";

    use core::default::Default;
    use std::str::FromStr;

    use bitcoin::hashes::sha256d;

    use super::*;
    use crate::descriptors::DescriptorId;

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

        let result = DescriptorRequest::handle_requests(vec![Default::default(), bad_req]);

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

        let (descs, rescan) = DescriptorRequest::handle_requests(reqs).unwrap();

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

        let (descs, rescan) = DescriptorRequest::handle_requests(reqs).unwrap();

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

        let (descs, rescan) = DescriptorRequest::handle_requests(reqs).unwrap();

        assert_eq!(descs.len(), 2);

        assert_eq!(rescan, RescanRequest::Now);
    }

    #[test]
    fn test_descriptor_matching() {
        let d = DescriptorUnit::default();

        // Test different ID types
        let hand_hash_id = DescriptorId::Hash(d.get_hash());
        let hand_label_id = DescriptorId::Label("A nice label".into()); // A nice label is the default string used for labelling
        let hand_ms_id = DescriptorId::Miniscript(d.descriptor.to_string());

        // This block and the next 3 asserts are only being added here to
        // test the get_id function.
        let gen_hash_id = d.get_hash_id();
        let gen_label_id = d.get_label_id();
        let gen_ms_id = d.get_miniscript();

        assert_eq!(gen_hash_id, hand_hash_id);
        assert_eq!(gen_label_id, hand_label_id);
        assert_eq!(gen_ms_id, hand_ms_id);

        let descs = vec![d];

        assert_eq!(
            DescriptorId::extract_matching_one(&descs, &hand_hash_id),
            Some(0)
        );
        assert_eq!(
            DescriptorId::extract_matching_one(&descs, &hand_label_id),
            Some(0)
        );
        assert_eq!(
            DescriptorId::extract_matching_one(&descs, &hand_ms_id),
            Some(0)
        );

        // Test non-existent
        assert!(
            DescriptorId::extract_matching_one(&descs, &DescriptorId::Label("missing".into()))
                .is_none()
        );
    }

    #[test]
    fn descriptor_index_control() {
        let addresses_per_descriptor = 42u32;

        let wallet = DescriptorRequest::default().into_unit().unwrap();
        // Same as [`DescriptorUnit::yield_count`] but for an array.
        let expected_count = DescriptorUnit::batch_yield_count(&wallet);

        let derived = DescriptorUnit::derive_descriptors(&wallet);

        // Resolving and counting does match
        assert_eq!(derived.len(), expected_count);

        // Ill try directly from a request expecting to assert whether next_index related index control is properly working.
        let from_request = DescriptorRequest {
            desc: DESCTEST_MULTIPATH.to_owned(),
            next_index: Some(addresses_per_descriptor), // the descriptor at 42.
            range: DerivationRange::End(41u32),
            ..Default::default()
        };

        let mut converted = from_request.into_unit().unwrap();

        assert_eq!(converted.len(), 2); // we have a multipath descriptor

        assert_eq!(
            converted[0].range,
            DerivationRange::End(addresses_per_descriptor)
        );

        let derived_converted = DescriptorUnit::derive_descriptors(&converted);

        assert_eq!(derived_converted.len(), 84usize);
        let guess = DescriptorUnit::batch_yield_count(&converted);

        assert_eq!(guess, 84usize);

        DescriptorUnit::batch_sum_index(&mut converted, 1); // This should add 1 to each index.
        let sum_guess = DescriptorUnit::batch_yield_count(&converted);

        assert_eq!(sum_guess, 86usize)
    }
}
