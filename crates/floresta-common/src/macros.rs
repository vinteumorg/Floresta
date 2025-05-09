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
/// Panic if the expression is not `Ok(_)`.
///
/// # Examples
///
/// ```rust
/// # use floresta_common::assert_ok;
/// // Successful
/// assert_ok!(Ok::<u32, &str>(2025));
/// ```
///
/// ```rust,should_panic
/// # use floresta_common::assert_ok;
/// // Panics
/// assert_ok!(Err::<u32, &str>("failed"));
/// ```
///
/// ```rust,compile_fail
/// # use floresta_common::assert_ok;
/// // Compile error: `assert_ok!` requires a `Result` value
/// assert_ok!(Some(42));
/// ```
macro_rules! assert_ok {
    ($expr:expr $(,)?) => {
        if let Err(e) = $expr {
            panic!("assertion failed: expected `Ok(_)`, got `Err({:?})`", e);
        }
    };
}

#[macro_export]
/// Panic if the expression is not `Err(_)`.
///
/// # Examples
///
/// ```rust
/// # use floresta_common::assert_err;
/// // Successful
/// assert_err!(Err::<u32, &str>("failed"));
/// ```
///
/// ```rust,should_panic
/// # use floresta_common::assert_err;
/// // Panics
/// assert_err!(Ok::<u32, &str>(2025));
/// ```
///
/// ```rust,compile_fail
/// # use floresta_common::assert_err;
/// // Compile error: `assert_err!` requires a `Result` value
/// assert_err!(Some(42));
/// ```
macro_rules! assert_err {
    ($expr:expr $(,)?) => {
        if let Ok(v) = $expr {
            panic!("assertion failed: expected `Err(_)`, got `Ok({:?})`", v);
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

    // Submodule to test the behavior of the `assert_ok` and `assert_err` macros
    mod test_assert_ok_err {
        fn ok_fn() -> Result<u32, &'static str> {
            Ok(778)
        }

        fn err_fn() -> Result<u32, &'static str> {
            Err("failure")
        }

        #[test]
        fn test_assert_ok_err_pass() {
            assert_ok!(ok_fn());
            assert_err!(err_fn());
        }

        #[test]
        #[should_panic(expected = "assertion failed: expected `Ok(_)`, got `Err(\"failure\")`")]
        fn test_assert_ok_panics_on_err() {
            // Should panic with our message
            assert_ok!(err_fn());
        }

        #[test]
        #[should_panic(expected = "assertion failed: expected `Err(_)`, got `Ok(778)`")]
        fn test_assert_err_panics_on_ok() {
            // Should panic with our message
            assert_err!(ok_fn());
        }
    }

    #[test]
    fn test_validate_hash_compile_time() {
        // Valid: exactly 64 ASCII hex digits.
        let valid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_ok!(validate_hash(valid));

        for len in 0..=128 {
            let test_str = "a".repeat(len);
            if len == 64 {
                assert_ok!(validate_hash(&test_str));
            } else {
                assert_err!(validate_hash(&test_str));
            }
        }

        // Invalid hex character at the end: 'g'.
        let invalid = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg";
        assert_eq!(invalid.len(), 64);
        assert_err!(validate_hash(invalid));

        // Invalid ascii character in the middle: 'é'
        let invalid_ascii = "0123456789abcdef0123456789abcdéf0123456789abcdef0123456789abcde";
        assert_eq!(invalid_ascii.len(), 64);
        assert_err!(validate_hash(invalid_ascii));
    }
}
