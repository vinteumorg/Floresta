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

#[macro_export]
/// Validates a block hash at compile time. Requires `FromStr` and `BlockHash` in scope.
macro_rules! bhash {
    ($s:expr) => {{
        // Catch invalid literals at compile time
        const _: () = match $crate::macros::validate_hash_compile_time($s) {
            Ok(()) => (),
            Err(e) => panic!("{}", e),
        };
        BlockHash::from_str($s).expect("Literal should be valid")
    }};
}

#[macro_export]
/// Validates utreexo node hashes at compile time. Requires `FromStr` and `BitcoinNodeHash` in scope.
///
/// - Accepts one or more comma-separated hash literal expressions.
/// - Allows an optional trailing comma.
macro_rules! acchashes {
    ( $( $s:expr ),+ $(,)? ) => {
        [ $( {
            // Catch invalid literals at compile time
            const _: () = match $crate::macros::validate_hash_compile_time($s) {
                Ok(()) => (),
                Err(e) => panic!("{}", e),
            };
            BitcoinNodeHash::from_str($s).expect("Literal should be valid")
        } ),+ ]
    };
}

#[doc(hidden)]
// This const function is used to validate hash literals at compile time
pub const fn validate_hash_compile_time(s: &str) -> Result<(), &str> {
    let bytes = s.as_bytes();

    // Note: An ASCII character is 1 byte, so the expected byte count is 64
    if bytes.len() != 64 {
        return Err("Hash literal is not exactly 64 hex digits");
    }

    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if !((b >= b'0' && b <= b'9') || (b >= b'a' && b <= b'f') || (b >= b'A' && b <= b'F')) {
            return Err("Hash literal contains an invalid ASCII hex digit");
        }
        i += 1;
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::validate_hash_compile_time as validate_hash;

    #[test]
    fn test_validate_hash_compile_time() {
        // Valid: exactly 64 ASCII hex digits.
        let valid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(validate_hash(valid).is_ok());

        for len in 0..=128 {
            let test_str = "a".repeat(len);
            if len == 64 {
                assert!(validate_hash(&test_str).is_ok());
            } else {
                assert!(validate_hash(&test_str).is_err());
            }
        }

        // Invalid hex character at the end: 'g'.
        let invalid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg";
        assert_eq!(invalid.len(), 64);
        assert!(validate_hash(invalid).is_err());

        // Invalid ascii character in the middle: 'é'
        let invalid_ascii = "0123456789abcdef0123456789abcdéf0123456789abcdef0123456789abcde";
        assert_eq!(invalid_ascii.len(), 64);
        assert!(validate_hash(invalid_ascii).is_err());
    }
}
