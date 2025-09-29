use std::error::Error;
use std::fmt::Display;

use bitcoin::hashes::serde::Deserialize;

#[derive(Debug)]
/// Collection of errors to deal with parsing.
pub enum ParseError {
    /// Returned when the user inserts a broken array
    Json(serde_json::Error),

    /// Returned when the consumer of tries to cast into
    /// an incompatible type.
    InvalidTarget(String),
}

impl Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Json(e) => write!(f, "{e}, e"),
            ParseError::InvalidTarget(target) => {
                write!(f, "Could parse items to {target}")
            }
        }
    }
}

impl Error for ParseError {}

/// Tries to parse a json array, you can insert a type to be cast on each item.
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
    Target: for<'a> Deserialize<'a>,
{
    serde_json::from_str(s).map_err(ParseError::Json)
}
