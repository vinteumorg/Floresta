use std::any::type_name;
use std::error::Error;
use std::fmt::Display;
use std::str::FromStr;

use crate::rpc_types::DescriptorRange;
use crate::rpc_types::DescriptorRequest;
use crate::rpc_types::DescriptorTimestamp;

#[derive(Debug)]
/// Collection of errors to deal with parsing.
pub enum ParseError {
    /// Returned when the user inserts an broken array
    InvalidArray,

    /// Returned when the consumer of tries to cast into
    /// a incompatible type.
    InvalidTarget(String),
}

impl Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::InvalidArray => write!(
                f,
                "Couldnt parse the inserted as an Array, please refer to the docs"
            ),
            ParseError::InvalidTarget(target) => {
                write!(f, "Could parse itens to {target}")
            }
        }
    }
}

impl Error for ParseError {}

/// Tries to parse a json array, you can insert a type to be casted on each item.
///
/// Example: '["4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b", "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"]'
/// Tries to parse a JSON array of hash strings into a vector of the target type.
///
/// The target type must implement Deserialize and can be converted from a hash string.
/// By default, it will parse into Hash256, but you can specify any other compatible type.
///
/// Example:
/// ```
/// # use bitcoin::hashes::sha256;
/// # use floresta_cli::parsers::parse_json_array;
/// let hashes: Vec<sha256::Hash> =
///     parse_json_array(r#"["4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"]"#)
///         .unwrap();
/// ```
pub fn parse_json_array<Target>(s: &str) -> Result<Vec<Target>, ParseError>
where
    Target: FromStr,
{
    let string_vec: Vec<String> = serde_json::from_str(s).map_err(|_| ParseError::InvalidArray)?;

    string_vec
        .into_iter()
        .map(|s| {
            Target::from_str(&s)
                .map_err(|_| ParseError::InvalidTarget(type_name::<Target>().to_string()))
        })
        .collect()
}

/// Implements [`FromStr`] for a type using [`serde_json::from_str`]
/// for a easy and quick implementation of FromStr for any type that
/// derives [`serde_json::Serialize`] and [`serde_json::Deserialize`].
macro_rules! from_str_by_json {
    ($t:ty) => {
        impl std::str::FromStr for $t {
            type Err = ParseError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                serde_json::from_str::<Self>(s)
                    .map_err(|_| ParseError::InvalidTarget(s.to_string()))
            }
        }
    };
}

// These below are the impls that our internal types need
// to be parsed correctly

from_str_by_json!(DescriptorRange);

from_str_by_json!(DescriptorTimestamp);

from_str_by_json!(DescriptorRequest);
