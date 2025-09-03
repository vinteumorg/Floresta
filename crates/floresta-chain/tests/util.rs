#![cfg(all(feature = "bitcoinconsensus", feature = "test-utils"))]
#![allow(clippy::manual_is_multiple_of)]

use std::collections::HashSet;

use bitcoinconsensus::VERIFY_CHECKLOCKTIMEVERIFY;
use bitcoinconsensus::VERIFY_CHECKSEQUENCEVERIFY;
use bitcoinconsensus::VERIFY_DERSIG;
use bitcoinconsensus::VERIFY_NULLDUMMY;
use bitcoinconsensus::VERIFY_P2SH;
use bitcoinconsensus::VERIFY_WITNESS;
pub use script_asm::parse_script;
pub use script_asm::ParseScriptError;

/// Number of script‑verify flags (currently bits 0..=20)
pub const VERIFY_FLAGS_COUNT: usize = 21;
const VERIFY_CLEANSTACK: u32 = 1 << 8;

/// Parse a comma-separated list of script-validation flags (as they appear in the Bitcoin Core
/// JSON test vectors) into the corresponding bitmask. All flag values are defined in
/// [this Core file](https://github.com/bitcoin/bitcoin/blob/master/src/script/interpreter.h).
pub fn parse_flags(s: &str) -> u32 {
    s.split(',')
        .map(|f| match f {
            "NONE" => 0,
            "P2SH" => VERIFY_P2SH,
            "DERSIG" => VERIFY_DERSIG,
            "LOW_S" => 1 << 3,
            "NULLDUMMY" => VERIFY_NULLDUMMY,
            "CHECKLOCKTIMEVERIFY" => VERIFY_CHECKLOCKTIMEVERIFY,
            "CHECKSEQUENCEVERIFY" => VERIFY_CHECKSEQUENCEVERIFY,
            "NULLFAIL" => 1 << 14,
            "STRICTENC" => 1 << 1,
            "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" => 1 << 12,
            "WITNESS" => VERIFY_WITNESS,
            "CONST_SCRIPTCODE" => 1 << 16,
            "CLEANSTACK" => VERIFY_CLEANSTACK,
            "SIGPUSHONLY" => 1 << 5,
            "MINIMALDATA" => 1 << 6,
            "MINIMALIF" => 1 << 13,
            "WITNESS_PUBKEYTYPE" => 1 << 15,

            "BADTX" => 0, // For Core's `checkTransaction` failures
            other => panic!("unknown flag '{other}' in test-vector"),
        })
        .fold(0, |acc, bit| acc | bit)
}

/// Formats a flag to its constituent bit shifts.
pub fn fmt_shift_flags(flags: u32) -> String {
    let parts = (0..32)
        .filter(|&i| flags & (1 << i) != 0)
        .map(|i| format!("1 << {i}"))
        .collect::<Vec<_>>();

    if parts.is_empty() {
        "0".into()
    } else {
        parts.join(" | ")
    }
}

/// Mirror of Bitcoin Core's [`FillFlags`](https://github.com/bitcoin/bitcoin/blob/v29.0/src/test/transaction_tests.cpp#L165).
/// Given a (possibly incomplete) set of script‐verify flags, enforces CLEANSTACK → WITNESS → P2SH.
pub fn fill_flags(mut flags: u32) -> u32 {
    // CLEANSTACK -> WITNESS
    if flags & VERIFY_CLEANSTACK != 0 {
        flags |= VERIFY_WITNESS;
    }
    // WITNESS -> P2SH (and hence CLEANSTACK -> P2SH transitively)
    if flags & VERIFY_WITNESS != 0 {
        flags |= VERIFY_P2SH;
    }

    // Exactly the same as Core's Assert(IsValidFlagCombination(flags));
    assert!(
        is_valid_flag_combination(flags),
        "Invalid flag combination: 0x{flags:x}",
    );

    flags
}

/// Mirror of Bitcoin Core's [`TrimFlags`](https://github.com/bitcoin/bitcoin/blob/v29.0/src/test/transaction_tests.cpp#L154).
/// Drops any "orphan" bits so that:
///  - WITNESS only survives if P2SH is set
///  - CLEANSTACK only survives if WITNESS (and thus P2SH) is set
pub fn trim_flags(mut flags: u32) -> u32 {
    // WITNESS requires P2SH
    if flags & VERIFY_P2SH == 0 {
        flags &= !VERIFY_WITNESS;
    }
    // CLEANSTACK requires WITNESS (and transitively P2SH)
    if flags & VERIFY_WITNESS == 0 {
        flags &= !VERIFY_CLEANSTACK;
    }

    assert!(
        is_valid_flag_combination(flags),
        "Trim produced invalid combination: 0x{flags:x}",
    );

    flags
}

/// Mirror of Bitcoin Core's [`ExcludeIndividualFlags`](https://github.com/bitcoin/bitcoin/blob/v29.0/src/test/transaction_tests.cpp#L180):
///
/// Exclude each possible script verify flag from `flags`. Returns a set of these flag combinations
/// that are valid and without duplicates. For example, if flags=1111 and the 4 possible flags are
/// 0001, 0010, 0100, and 1000, this should return the set {0111, 1011, 1101, 1110}.
pub fn exclude_individual_flags(flags: u32) -> HashSet<u32> {
    let mut combos = HashSet::new();

    for exclude_bit in (0..VERIFY_FLAGS_COUNT).map(|i| 1 << i) {
        let f = trim_flags(flags & !exclude_bit);

        if f != flags {
            combos.insert(f);
        }
    }
    combos
}

/// Mirror of Bitcoin Core's [`IsValidFlagCombination`](https://github.com/bitcoin/bitcoin/blob/v29.0/src/test/util/script.cpp#L8)
fn is_valid_flag_combination(flags: u32) -> bool {
    // CLEANSTACK -> (WITNESS && P2SH)
    if (flags & VERIFY_CLEANSTACK != 0)
        && (flags & (VERIFY_WITNESS | VERIFY_P2SH) != (VERIFY_WITNESS | VERIFY_P2SH))
    {
        return false;
    }

    // WITNESS -> P2SH
    if (flags & VERIFY_WITNESS != 0) && (flags & VERIFY_P2SH == 0) {
        return false;
    }

    true
}

mod script_asm {
    use core::fmt;
    use std::collections::HashMap;
    use std::sync::OnceLock;

    use bitcoin::script::Builder;
    use bitcoin::script::PushBytes;
    use bitcoin::Opcode;
    use bitcoin::ScriptBuf;
    use hex::FromHex;

    #[derive(Debug)]
    pub enum ParseScriptError {
        BadDecimal(String),
        DecimalOutOfRange(i64),
        BadOpcode(String),
    }

    impl fmt::Display for ParseScriptError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                ParseScriptError::BadDecimal(tok) => write!(f, "bad decimal literal `{tok}`"),
                ParseScriptError::DecimalOutOfRange(n) => write!(
                    f,
                    "decimal out of range: {n} (allowed: -0xffffffff..=0xffffffff)"
                ),
                ParseScriptError::BadOpcode(tok) => write!(f, "unknown opcode `{tok}`"),
            }
        }
    }

    static CORE_OPCODE_MAP: OnceLock<HashMap<String, Opcode>> = OnceLock::new();

    fn core_opcode_map() -> &'static HashMap<String, Opcode> {
        CORE_OPCODE_MAP.get_or_init(build_core_opcode_map)
    }

    fn build_core_opcode_map() -> HashMap<String, Opcode> {
        let mut m = HashMap::new();
        for b in 0u8..=255 {
            let op = Opcode::from(b);
            let name = match b {
                // rust-bitcoin formats these as OP_CSV/OP_CLTV, use Core long names instead
                0xb2 => "OP_CHECKSEQUENCEVERIFY".into(),
                0xb1 => "OP_CHECKLOCKTIMEVERIFY".into(),
                _ => op.to_string(),
            };

            if name == "OP_UNKNOWN" {
                continue;
            }
            // Mirror Core: if (op < OP_NOP && op != OP_RESERVED) continue;
            let is_reserved = name == "OP_RESERVED";
            if b < 0x61 && !is_reserved {
                continue;
            }

            m.insert(name.clone(), op);
            if let Some(bare) = name.strip_prefix("OP_") {
                m.insert(bare.to_string(), op);
            }
        }
        m
    }

    pub fn parse_opcode(token: &str) -> Result<Opcode, ParseScriptError> {
        core_opcode_map()
            .get(token) // case-sensitive like Core
            .copied()
            .ok_or_else(|| ParseScriptError::BadOpcode(token.to_string()))
    }

    fn is_all_digits(s: &str) -> bool {
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
    }

    /// This helper mirrors the C++ [IsHex](https://github.com/bitcoin/bitcoin/blob/v29.0/src/util/strencodings.cpp#L41) definition:
    /// ```c++
    /// bool IsHex(std::string_view str)
    /// {
    ///     for (char c : str) {
    ///         if (HexDigit(c) < 0) return false;
    ///     }
    ///     return (str.size() > 0) && (str.size()%2 == 0);
    /// }
    /// ```
    fn is_hex(s: &str) -> bool {
        // Accept even-length pure hex
        !s.is_empty() && s.len() % 2 == 0 && s.bytes().all(|b| b.is_ascii_hexdigit())
    }

    /// Parse the decimal integer and validate its range
    fn parse_decimal_i64(s: &str) -> Result<i64, ParseScriptError> {
        let num_i64 = s
            .parse()
            .map_err(|_| ParseScriptError::BadDecimal(s.to_string()))?;

        const LIM: i64 = 0xffff_ffff;
        if !(-LIM..=LIM).contains(&num_i64) {
            return Err(ParseScriptError::DecimalOutOfRange(num_i64));
        }

        Ok(num_i64)
    }

    enum Tok<'a> {
        Decimal(i64),
        Hex(Vec<u8>),
        Quoted(&'a str),
        Opcode(Opcode),
    }

    fn classify(w: &str) -> Result<Tok<'_>, ParseScriptError> {
        if is_all_digits(w) || (w.starts_with('-') && w.len() > 1 && is_all_digits(&w[1..])) {
            // Decimal literal
            Ok(Tok::Decimal(parse_decimal_i64(w)?))
        } else if w.starts_with("0x") && w.len() > 2 && is_hex(&w[2..]) {
            // Raw hex literal
            let hex_bytes = Vec::from_hex(&w[2..]).expect("valid hex");
            Ok(Tok::Hex(hex_bytes))
        } else if w.len() >= 2 && w.starts_with('\'') && w.ends_with('\'') {
            // Single-quoted literal
            let body = &w[1..w.len() - 1];
            Ok(Tok::Quoted(body))
        } else {
            // Opcode name
            Ok(Tok::Opcode(parse_opcode(w)?))
        }
    }

    /// Parse a Core-style ASM string into a ScriptBuf.
    /// Behavior matches the C++ [ParseScript](https://github.com/bitcoin/bitcoin/blob/v29.0/src/core_read.cpp#L63)
    pub fn parse_script(s: &str) -> Result<ScriptBuf, ParseScriptError> {
        let mut out: Vec<u8> = Vec::new();

        // Same separators as Core's `SplitString(s, " \t\n")`
        for w in s.split([' ', '\t', '\n']).filter(|w| !w.is_empty()) {
            match classify(w)? {
                Tok::Decimal(int) => {
                    // Push the integer using minimal encoding (OP_0/OP_1NEGATE/OP_1..OP_16 when possible)
                    let part = Builder::new().push_int(int).into_script();
                    out.extend_from_slice(part.as_bytes());
                }
                Tok::Hex(hex_bytes) => {
                    // Raw hex inserted (NOT pushed)
                    out.extend_from_slice(&hex_bytes);
                }
                Tok::Quoted(body) => {
                    // Single-quoted literal -> push as data
                    let pb: &PushBytes = body.as_bytes().try_into().expect("length < 2^32 bytes");
                    let part = Builder::new().push_slice(pb).into_script();
                    out.extend_from_slice(part.as_bytes());
                }
                Tok::Opcode(op) => {
                    // Opcode by name
                    let part = Builder::new().push_opcode(op).into_script();
                    out.extend_from_slice(part.as_bytes());
                }
            }
        }

        Ok(ScriptBuf::from_bytes(out))
    }
}

mod util_tests {
    use super::*;

    fn hex_script(asm: &str) -> String {
        parse_script(asm).unwrap().to_hex_string()
    }

    fn expect_err(asm: &str) -> ParseScriptError {
        parse_script(asm).expect_err("Expected Err")
    }

    #[test]
    fn parse_script_canonical_vectors() {
        // 1-of-2 bare multisig redeemScript
        let asm = "1 0x41 0x04cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaff7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4 0x41 0x0461cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d76519aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af 2 OP_CHECKMULTISIG";
        assert_eq!(
        hex_script(asm),
        "514104cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaff7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4410461cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d76519aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af52ae",
    );

        // PUSHDATA1 of a long blob, then standard P2PKH
        let asm = "0x4c 0xae 0x606563686f2022553246736447566b58312b5a536e587574356542793066794778625456415675534a6c376a6a334878416945325364667657734f53474f36633338584d7439435c6e543249584967306a486956304f376e775236644546673d3d22203e20743b206f70656e73736c20656e63202d7061737320706173733a5b314a564d7751432d707269766b65792d6865785d202d64202d6165732d3235362d636263202d61202d696e207460 DROP DUP HASH160 0x14 0xbfd7436b6265aa9de506f8a994f881ff08cc2872 EQUALVERIFY CHECKSIG";
        assert_eq!(
        hex_script(asm),
        "4cae606563686f2022553246736447566b58312b5a536e587574356542793066794778625456415675534a6c376a6a334878416945325364667657734f53474f36633338584d7439435c6e543249584967306a486956304f376e775236644546673d3d22203e20743b206f70656e73736c20656e63202d7061737320706173733a5b314a564d7751432d707269766b65792d6865785d202d64202d6165732d3235362d636263202d61202d696e2074607576a914bfd7436b6265aa9de506f8a994f881ff08cc287288ac",
    );

        // P2PKH + CHECKSIGVERIFY, then mixed extra pushes
        let asm = "DUP HASH160 0x14 0x5b6462475454710f3c22f5fdf0b40704c92f25c3 EQUALVERIFY CHECKSIGVERIFY 1 0x4c 0x47 0x3044022067288ea50aa799543a536ff9306f8e1cba05b9c6b10951175b924f96732555ed022026d7b5265f38d21541519e4a1e55044d5b9e17e15cdbaf29ae3792e99e883e7a01";
        assert_eq!(
            hex_script(asm),
            "76a9145b6462475454710f3c22f5fdf0b40704c92f25c388ad514c473044022067288ea50aa799543a536ff9306f8e1cba05b9c6b10951175b924f96732555ed022026d7b5265f38d21541519e4a1e55044d5b9e17e15cdbaf29ae3792e99e883e7a01"
        );

        assert_eq!(
            hex_script("0x050000008001 CHECKSEQUENCEVERIFY"),
            "050000008001b2"
        );
        assert_eq!(hex_script("0x4c 0x01 0xff"), "4c01ff"); // PUSHDATA1, len=1, 0xff
    }

    #[test]
    fn parse_script_numbers_ok() {
        assert_eq!(hex_script("0"), "00");
        assert_eq!(hex_script("-0"), "00"); // "-0" parses as 0 and becomes OP_0
        assert_eq!(hex_script("000"), "00");
        assert_eq!(hex_script("-00"), "00");
        assert_eq!(hex_script("1"), "51"); // OP_1
        assert_eq!(hex_script("16"), "60"); // OP_16

        // The next value after OP_16 becomes a minimal data push
        assert_eq!(hex_script("17"), "0111");
        assert_eq!(parse_script("127").unwrap().to_hex_string(), "017f");
        assert_eq!(parse_script("128").unwrap().to_hex_string(), "028000"); // 128 needs an extra 0x00

        // Negative values (only -1 has an opcode)
        assert_eq!(hex_script("-1"), "4f"); // OP_1NEGATE
        assert_eq!(hex_script("-2"), "0182"); // minimal ScriptNum for -2
        assert_eq!(parse_script("-127").unwrap().to_hex_string(), "01ff");
        assert_eq!(parse_script("-128").unwrap().to_hex_string(), "028080");

        assert_eq!(hex_script("4294967295"), "05ffffffff00"); // upper bound
        assert_eq!(hex_script("-4294967295"), "05ffffffff80"); // lower bound
        assert_eq!(hex_script("32"), "0120"); // push single space via ScriptNum
    }

    #[test]
    fn parse_script_numbers_err() {
        // Range errors
        assert!(matches!(
            expect_err("4294967296"),
            ParseScriptError::DecimalOutOfRange(_)
        ));
        assert!(matches!(
            expect_err("9223372036854775807"),
            ParseScriptError::DecimalOutOfRange(_)
        ));
        assert!(matches!(
            expect_err("-4294967296"),
            ParseScriptError::DecimalOutOfRange(_)
        ));
        assert!(matches!(
            expect_err("-9223372036854775808"),
            ParseScriptError::DecimalOutOfRange(_)
        ));

        // Parse errors, with i64::MAX + 1 and i64::MIN - 1
        assert!(matches!(
            expect_err("9223372036854775808"),
            ParseScriptError::BadDecimal(_)
        ));
        assert!(matches!(
            expect_err("-9223372036854775809"),
            ParseScriptError::BadDecimal(_)
        ));

        // not-a-number leading '+'
        assert!(matches!(expect_err("+1"), ParseScriptError::BadOpcode(_)));
    }

    #[test]
    fn parse_script_hex_and_pushdata() {
        assert_eq!(hex_script("0x00"), "00"); // raw insert
        assert_eq!(hex_script("0xaa 0xbb"), "aabb");
        assert_eq!(hex_script("0x4c 0x00"), "4c00"); // PUSHDATA1 len=0
        assert!(matches!(expect_err("0XAA"), ParseScriptError::BadOpcode(_))); // uppercase 0X not allowed

        // explicit 1-byte push via raw bytes: len=1, data=0x20
        assert_eq!(hex_script("0x01 0x20"), "0120");
        // raw insert of 0x20
        assert_eq!(hex_script("0x20"), "20");
    }

    #[test]
    fn parse_script_hex_err() {
        // Check invalid hex values and odd lengths, which are parsed as opcodes
        for bad in ["0x", "0xg0", "0xfg", "0xabc", "0xabcde", "0xabcdefg"] {
            assert!(matches!(expect_err(bad), ParseScriptError::BadOpcode(_)));
        }
    }

    #[test]
    fn parse_script_quoted_literals() {
        assert_eq!(hex_script("''"), "00"); // empty push
        assert_eq!(hex_script("'ab'"), "026162"); // OP_PUSHBYTES_2 + 'a' 'b'

        // Quotes don't support spaces inside (split happens first)
        assert!(matches!(expect_err("' '"), ParseScriptError::BadOpcode(_))); // split by space
        assert!(matches!(
            expect_err("'a b'"),
            ParseScriptError::BadOpcode(_)
        ));
    }

    #[test]
    fn parse_script_opcode_names_ok() {
        assert_eq!(hex_script("CHECKMULTISIG"), "ae");
        assert_eq!(hex_script("OP_CHECKMULTISIG"), "ae");
        assert_eq!(hex_script("OP_CHECKLOCKTIMEVERIFY"), "b1");
        assert_eq!(hex_script("CHECKLOCKTIMEVERIFY"), "b1");
        assert_eq!(hex_script("OP_CHECKSEQUENCEVERIFY"), "b2");
        assert_eq!(hex_script("OP_RESERVED"), "50"); // allowed by name
        assert_eq!(hex_script("RESERVED"), "50");
        assert_eq!(hex_script("OP_NOP"), "61");
        assert_eq!(hex_script("OP_NOP10"), "b9");
        assert_eq!(hex_script("OP_INVALIDOPCODE"), "ff");
        assert_eq!(hex_script("DUP"), "76");
    }

    #[test]
    fn parse_script_opcode_names_err() {
        for bad in [
            "OP_CLTV",
            "CLTV",
            "OP_CSV",
            "CSV",
            "OP_1",
            "OP_1NEGATE",
            "OP_0",
            "dup",
            "OP_UNKNOWN",
            "OP_HASH161",
        ] {
            assert!(matches!(expect_err(bad), ParseScriptError::BadOpcode(_)));
        }
    }

    #[test]
    fn parse_script_whitespace_and_empty() {
        assert_eq!(hex_script("  \t\n 1 \n 2\tADD  "), "515293"); // 1 -> OP_1, 2 -> OP_2, ADD -> 0x93
        assert_eq!(hex_script(""), "");
    }

    #[test]
    fn test_exclude_bits() {
        let flags = 0b1111;
        let combos = exclude_individual_flags(flags);
        // We should see 0b1110, 0b1101, 0b1011, 0b0111
        let expected: HashSet<u32> = [0b1110, 0b1101, 0b1011, 0b0111].iter().copied().collect();
        assert_eq!(combos, expected);
    }

    #[test]
    fn test_fill_flags() {
        assert_eq!(fill_flags(0), 0);

        // WITNESS alone → should pull in P2SH
        let w = VERIFY_WITNESS;
        assert_eq!(fill_flags(w), VERIFY_WITNESS | VERIFY_P2SH);

        // CLEANSTACK alone → pulls in WITNESS and transitively P2SH
        let c = VERIFY_CLEANSTACK;
        assert_eq!(
            fill_flags(c),
            VERIFY_CLEANSTACK | VERIFY_WITNESS | VERIFY_P2SH
        );

        // A mix of unrelated flags is left untouched
        let mixed = VERIFY_DERSIG | VERIFY_NULLDUMMY;
        assert_eq!(fill_flags(mixed), mixed);
    }

    #[test]
    fn test_trim_flags() {
        // WITNESS without P2SH → should drop WITNESS
        assert_eq!(trim_flags(VERIFY_WITNESS), 0);

        // CLEANSTACK without WITNESS → drop CLEANSTACK
        assert_eq!(trim_flags(VERIFY_CLEANSTACK), 0);

        // CLEANSTACK + P2SH (but no WITNESS) → drop only CLEANSTACK
        let cp = VERIFY_CLEANSTACK | VERIFY_P2SH;
        assert_eq!(trim_flags(cp), VERIFY_P2SH);

        // Full chain CLEANSTACK → WITNESS → P2SH remains intact
        let full = VERIFY_CLEANSTACK | VERIFY_WITNESS | VERIFY_P2SH;
        assert_eq!(trim_flags(full), full);

        // Other flags are preserved
        let extra = VERIFY_CHECKLOCKTIMEVERIFY | VERIFY_CHECKSEQUENCEVERIFY;
        assert_eq!(trim_flags(extra), extra);
    }
}
