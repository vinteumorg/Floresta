// SPDX-License-Identifier: CC0-1.0

// This module was largely copied from https://github.com/rust-bitcoin/murmel/blob/master/src/blockfilter.rs
// on 11. June 2019 which is licensed under Apache, that file specifically
// was written entirely by Tamas Blummer, who is re-licensing its contents here as CC0.

//! BIP158 Compact Block Filters for light clients.
//!
//! This module implements a structure for compact filters on block data, for
//! use in the BIP 157 light client protocol. The filter construction proposed
//! is an alternative to Bloom filters, as used in BIP 37, that minimizes filter
//! size by using Golomb-Rice coding for compression.
//!
//! ## Example
//!
//! ```ignore
//! fn get_script_for_coin(coin: &OutPoint) -> Result<Script, BlockFilterError> {
//!   // get utxo ...
//! }
//!
//! // create a block filter for a block (server side)
//! let filter = BlockFilter::new_script_filter(&block, get_script_for_coin)?;
//!
//! // or create a filter from known raw data
//! let filter = BlockFilter::new(content);
//!
//! // read and evaluate a filter
//!
//! let query: Iterator<Item=Script> = // .. some scripts you care about
//! if filter.match_any(&block_hash, &mut query.map(|s| s.as_bytes())) {
//!   // get this block
//! }
//!  ```

use std::cmp::Ordering;
use std::cmp::{self};
use std::collections::HashSet;
use std::fmt::Display;
use std::fmt::Formatter;
use std::fmt::{self};
use std::io::Cursor;
use std::io::{self};

use bitcoin::consensus::Decodable;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::siphash24;
use bitcoin::hashes::Hash;
use bitcoin::hex::write_err;
use bitcoin::BlockHash;
use bitcoin::OutPoint;
use bitcoin::VarInt;

/// Golomb encoding parameter as in BIP-158, see also https://gist.github.com/sipa/576d5f09c3b86c3b1b75598d799fc845
const P: u8 = 19;
const M: u64 = 784931;

/// Errors for blockfilter
#[derive(Debug)]
pub enum Error {
    /// missing UTXO, can not calculate script filter
    UtxoMissing(OutPoint),
    /// some IO error reading or writing binary serialization of the filter
    Io(io::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
        match *self {
            Error::UtxoMissing(ref coin) => write!(f, "unresolved UTXO {}", coin),
            Error::Io(ref e) => write_err!(f, "IO error"; e),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match self {
            UtxoMissing(_) => None,
            Io(e) => Some(e),
        }
    }
}

impl From<io::Error> for Error {
    fn from(io: io::Error) -> Self {
        Error::Io(io)
    }
}

/// a computed or read block filter
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockFilter {
    /// Golomb encoded filter
    pub content: Vec<u8>,
}

impl BlockFilter {
    /// create a new filter from pre-computed data
    pub fn new(content: &[u8]) -> BlockFilter {
        BlockFilter {
            content: content.to_vec(),
        }
    }

    /// match any query pattern
    pub fn match_any(
        &self,
        block_hash: &BlockHash,
        query: &mut dyn Iterator<Item = &[u8]>,
    ) -> Result<bool, Error> {
        let filter_reader = BlockFilterReader::new(block_hash);
        filter_reader.match_any(&mut Cursor::new(self.content.as_slice()), query)
    }

    /// match all query pattern
    pub fn match_all(
        &self,
        block_hash: &BlockHash,
        query: &mut dyn Iterator<Item = &[u8]>,
    ) -> Result<bool, Error> {
        let filter_reader = BlockFilterReader::new(block_hash);
        filter_reader.match_all(&mut Cursor::new(self.content.as_slice()), query)
    }
}

/// Reads and interpret a block filter
pub struct BlockFilterReader {
    reader: GCSFilterReader,
}

impl BlockFilterReader {
    /// Create a block filter reader
    pub fn new(block_hash: &BlockHash) -> BlockFilterReader {
        let block_hash_as_int = block_hash.to_byte_array();
        let mut k0 = [0; 8];
        let mut k1 = [0; 8];

        k0.clone_from_slice(&block_hash_as_int[0..8]);
        k1.clone_from_slice(&block_hash_as_int[8..16]);

        let k0 = u64::from_le_bytes(k0);
        let k1 = u64::from_le_bytes(k1);
        BlockFilterReader {
            reader: GCSFilterReader::new(k0, k1, M, P),
        }
    }

    /// match any query pattern
    pub fn match_any(
        &self,
        reader: &mut dyn io::Read,
        query: &mut dyn Iterator<Item = &[u8]>,
    ) -> Result<bool, Error> {
        self.reader.match_any(reader, query)
    }

    /// match all query pattern
    pub fn match_all(
        &self,
        reader: &mut dyn io::Read,
        query: &mut dyn Iterator<Item = &[u8]>,
    ) -> Result<bool, Error> {
        self.reader.match_all(reader, query)
    }
}

/// Golomb-Rice encoded filter reader
pub struct GCSFilterReader {
    filter: GCSFilter,
    m: u64,
}

impl GCSFilterReader {
    /// Create a new filter reader with specific seed to siphash
    pub fn new(k0: u64, k1: u64, m: u64, p: u8) -> GCSFilterReader {
        GCSFilterReader {
            filter: GCSFilter::new(k0, k1, p),
            m,
        }
    }

    /// match any query pattern
    pub fn match_any(
        &self,
        reader: &mut dyn io::Read,
        query: &mut dyn Iterator<Item = &[u8]>,
    ) -> Result<bool, Error> {
        let mut decoder = reader;
        let n_elements: VarInt = Decodable::consensus_decode(&mut decoder).unwrap_or(VarInt(0));
        let reader = &mut decoder;
        // map hashes to [0, n_elements << grp]
        let nm = n_elements.0 * self.m;
        let mut mapped = query
            .map(|e| map_to_range(self.filter.hash(e), nm))
            .collect::<Vec<_>>();
        // sort
        mapped.sort_unstable();
        if mapped.is_empty() {
            return Ok(true);
        }
        if n_elements.0 == 0 {
            return Ok(false);
        }

        // find first match in two sorted arrays in one read pass
        let mut reader = BitStreamReader::new(reader);
        let mut data = self.filter.golomb_rice_decode(&mut reader)?;
        let mut remaining = n_elements.0 - 1;
        for p in mapped {
            loop {
                match data.cmp(&p) {
                    Ordering::Equal => return Ok(true),
                    Ordering::Less => {
                        if remaining > 0 {
                            data += self.filter.golomb_rice_decode(&mut reader)?;
                            remaining -= 1;
                        } else {
                            return Ok(false);
                        }
                    }
                    Ordering::Greater => break,
                }
            }
        }
        Ok(false)
    }

    /// match all query pattern
    pub fn match_all(
        &self,
        reader: &mut dyn io::Read,
        query: &mut dyn Iterator<Item = &[u8]>,
    ) -> Result<bool, Error> {
        let mut decoder = reader;
        let n_elements: VarInt = Decodable::consensus_decode(&mut decoder).unwrap_or(VarInt(0));
        let reader = &mut decoder;
        // map hashes to [0, n_elements << grp]
        let nm = n_elements.0 * self.m;
        let mut mapped = query
            .map(|e| map_to_range(self.filter.hash(e), nm))
            .collect::<Vec<_>>();
        // sort
        mapped.sort_unstable();
        mapped.dedup();
        if mapped.is_empty() {
            return Ok(true);
        }
        if n_elements.0 == 0 {
            return Ok(false);
        }

        // figure if all mapped are there in one read pass
        let mut reader = BitStreamReader::new(reader);
        let mut data = self.filter.golomb_rice_decode(&mut reader)?;
        let mut remaining = n_elements.0 - 1;
        for p in mapped {
            loop {
                match data.cmp(&p) {
                    Ordering::Equal => break,
                    Ordering::Less => {
                        if remaining > 0 {
                            data += self.filter.golomb_rice_decode(&mut reader)?;
                            remaining -= 1;
                        } else {
                            return Ok(false);
                        }
                    }
                    Ordering::Greater => return Ok(false),
                }
            }
        }
        Ok(true)
    }
}

// fast reduction of hash to [0, nm) range
fn map_to_range(hash: u64, nm: u64) -> u64 {
    ((hash as u128 * nm as u128) >> 64) as u64
}

/// Colomb-Rice encoded filter writer
pub struct GCSFilterWriter<'a> {
    filter: GCSFilter,
    writer: &'a mut dyn io::Write,
    elements: HashSet<Vec<u8>>,
    m: u64,
}

impl<'a> GCSFilterWriter<'a> {
    /// Create a new GCS writer wrapping a generic writer, with specific seed to siphash
    pub fn new(
        writer: &'a mut dyn io::Write,
        k0: u64,
        k1: u64,
        m: u64,
        p: u8,
    ) -> GCSFilterWriter<'a> {
        GCSFilterWriter {
            filter: GCSFilter::new(k0, k1, p),
            writer,
            elements: HashSet::new(),
            m,
        }
    }

    /// Add some data to the filter
    pub fn add_element(&mut self, element: &[u8]) {
        if !element.is_empty() {
            self.elements.insert(element.to_vec());
        }
    }

    /// write the filter to the wrapped writer
    pub fn finish(&mut self) -> Result<usize, io::Error> {
        let nm = self.elements.len() as u64 * self.m;

        // map hashes to [0, n_elements * M)
        let mut mapped: Vec<_> = self
            .elements
            .iter()
            .map(|e| map_to_range(self.filter.hash(e.as_slice()), nm))
            .collect();
        mapped.sort_unstable();

        // write number of elements as varint
        let mut wrote = VarInt(mapped.len() as u64).consensus_encode(&mut self.writer)?;

        // write out deltas of sorted values into a Golonb-Rice coded bit stream
        let mut writer = BitStreamWriter::new(self.writer);
        let mut last = 0;
        for data in mapped {
            wrote += self.filter.golomb_rice_encode(&mut writer, data - last)?;
            last = data;
        }
        wrote += writer.flush()?;
        Ok(wrote)
    }
}

/// Golomb Coded Set Filter
struct GCSFilter {
    k0: u64, // sip hash key
    k1: u64, // sip hash key
    p: u8,
}

impl GCSFilter {
    /// Create a new filter
    fn new(k0: u64, k1: u64, p: u8) -> GCSFilter {
        GCSFilter { k0, k1, p }
    }

    /// Golomb-Rice encode a number n to a bit stream (Parameter 2^k)
    fn golomb_rice_encode(&self, writer: &mut BitStreamWriter, n: u64) -> Result<usize, io::Error> {
        let mut wrote = 0;
        let mut q = n >> self.p;
        while q > 0 {
            let nbits = cmp::min(q, 64);
            wrote += writer.write(!0u64, nbits as u8)?;
            q -= nbits;
        }
        wrote += writer.write(0, 1)?;
        wrote += writer.write(n, self.p)?;
        Ok(wrote)
    }

    /// Golomb-Rice decode a number from a bit stream (Parameter 2^k)
    fn golomb_rice_decode(&self, reader: &mut BitStreamReader) -> Result<u64, io::Error> {
        let mut q = 0u64;
        while reader.read(1)? == 1 {
            q += 1;
        }
        let r = reader.read(self.p)?;
        Ok((q << self.p) + r)
    }

    /// Hash an arbitrary slice with siphash using parameters of this filter
    fn hash(&self, element: &[u8]) -> u64 {
        siphash24::Hash::hash_to_u64_with_keys(self.k0, self.k1, element)
    }
}

/// Bitwise stream reader
pub struct BitStreamReader<'a> {
    buffer: [u8; 1],
    offset: u8,
    reader: &'a mut dyn io::Read,
}

impl<'a> BitStreamReader<'a> {
    /// Create a new BitStreamReader that reads bitwise from a given reader
    pub fn new(reader: &'a mut dyn io::Read) -> BitStreamReader {
        BitStreamReader {
            buffer: [0u8],
            reader,
            offset: 8,
        }
    }

    /// Read nbit bits
    pub fn read(&mut self, mut nbits: u8) -> Result<u64, io::Error> {
        if nbits > 64 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "can not read more than 64 bits at once",
            ));
        }
        let mut data = 0u64;
        while nbits > 0 {
            if self.offset == 8 {
                self.reader.read_exact(&mut self.buffer)?;
                self.offset = 0;
            }
            let bits = cmp::min(8 - self.offset, nbits);
            data <<= bits;
            data |= ((self.buffer[0] << self.offset) >> (8 - bits)) as u64;
            self.offset += bits;
            nbits -= bits;
        }
        Ok(data)
    }
}

/// Bitwise stream writer
pub struct BitStreamWriter<'a> {
    buffer: [u8; 1],
    offset: u8,
    writer: &'a mut dyn io::Write,
}

impl<'a> BitStreamWriter<'a> {
    /// Create a new BitStreamWriter that writes bitwise to a given writer
    pub fn new(writer: &'a mut dyn io::Write) -> BitStreamWriter {
        BitStreamWriter {
            buffer: [0u8],
            writer,
            offset: 0,
        }
    }

    /// Write nbits bits from data
    pub fn write(&mut self, data: u64, mut nbits: u8) -> Result<usize, io::Error> {
        if nbits > 64 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "can not write more than 64 bits at once",
            ));
        }
        let mut wrote = 0;
        while nbits > 0 {
            let bits = cmp::min(8 - self.offset, nbits);
            self.buffer[0] |= ((data << (64 - nbits)) >> (64 - 8 + self.offset)) as u8;
            self.offset += bits;
            nbits -= bits;
            if self.offset == 8 {
                wrote += self.flush()?;
            }
        }
        Ok(wrote)
    }

    /// flush bits not yet written
    pub fn flush(&mut self) -> Result<usize, io::Error> {
        if self.offset > 0 {
            self.writer.write_all(&self.buffer)?;
            self.buffer[0] = 0u8;
            self.offset = 0;
            Ok(1)
        } else {
            Ok(0)
        }
    }
}
