use std::io::Write;

use bitcoin::{
    util::bip158::{self, BlockFilter, GCSFilterWriter},
    Block, Transaction,
};

use core::{fmt::Debug, ops::BitAnd};

pub trait BlockFilterStore {
    /// Fetches a block filter
    fn get_filter(&self, block_height: u64) -> Option<bip158::BlockFilter>;
    /// Stores a new filter
    fn put_filter(&self, block_height: u64, block_filter: bip158::BlockFilter);
}

#[derive(Debug, Hash)]
pub enum OutputTypes {
    /// public key hash
    PKH,
    /// script hash
    SH,
    /// witness public key hash
    WPKH,
    /// witness script hash
    WSH,
    /// Taproot (witness v1)
    TR,
}

/// This means we track all suported address types
const ALL_OUTPUTS: u8 = 0x1f; // 00011111

impl BitAnd<u8> for OutputTypes {
    type Output = bool;
    fn bitand(self, rhs: u8) -> Self::Output {
        let is_set = match self {
            Self::PKH => rhs & 1,
            Self::SH => rhs & 2,
            Self::WPKH => rhs & 4,
            Self::WSH => rhs & 16,
            Self::TR => rhs & 32,
        };
        is_set != 0
    }
}

/// A backend capable of holding multiple BIP158 compact block filters
pub struct BlockFilterBackend {
    /// Which outputs types we index
    whitelisted_outputs: u8,
    /// Whether we index inputs (if true, all outpoints being spent are added to the filter)
    index_inputs: bool,
    /// A persistence engine for our filters
    storage: Box<dyn BlockFilterStore>,
    /// The first half of the siphash key
    k0: u64,
    /// The second half of the siphash key
    k1: u64,
}

struct FilterBuilder<'a> {
    writer: GCSFilterWriter<'a>,
}

impl<'a> FilterBuilder<'a> {
    #[allow(non_snake_case)]
    pub fn new(writer: &'a mut dyn Write, M: u64, P: u8, k0: u64, k1: u64) -> FilterBuilder {
        let writer = GCSFilterWriter::new(writer, k0, k1, M, P);
        FilterBuilder { writer }
    }
    pub fn put(&mut self, el: &[u8]) {
        self.writer.add_element(el);
    }
    pub fn finish(&mut self) -> Result<usize, bip158::Error> {
        Ok(self.writer.finish()?)
    }
}

impl BlockFilterBackend {
    pub fn new(storage: Box<dyn BlockFilterStore>) -> BlockFilterBackend {
        BlockFilterBackend {
            whitelisted_outputs: ALL_OUTPUTS,
            index_inputs: true,
            storage,
            k0: 0,
            k1: 0,
        }
    }
    pub fn filter_block(&self, block: &Block, block_height: u64) -> Result<(), bip158::Error> {
        let mut writer = Vec::new();
        let mut filter = FilterBuilder::new(&mut writer, 0, 0, self.k0, self.k1);
        if self.index_inputs {
            self.write_inputs(&block.txdata, &mut filter);
        }
        self.write_outputs(&block.txdata, &mut filter);
        filter.finish()?;
        let filter = BlockFilter::new(writer.as_slice());
        self.storage.put_filter(block_height, filter);
        Ok(())
    }
    fn write_inputs(&self, txs: &Vec<Transaction>, filter: &mut FilterBuilder) {
        for tx in txs {
            tx.input.iter().for_each(|input| {
                filter.put(&input.previous_output.txid);
                filter.put(&input.previous_output.vout.to_be_bytes());
            });
        }
    }
    fn write_tx_outs(&self, tx: &Transaction, filter: &mut FilterBuilder) {
        for output in tx.output.iter() {
            if OutputTypes::PKH & self.whitelisted_outputs && output.script_pubkey.is_p2pkh() {
                filter.put(output.script_pubkey.as_bytes());
            }
            if OutputTypes::SH & self.whitelisted_outputs && output.script_pubkey.is_p2sh() {
                filter.put(output.script_pubkey.as_bytes());
            }
            if OutputTypes::WPKH & self.whitelisted_outputs && output.script_pubkey.is_v0_p2wpkh() {
                filter.put(output.script_pubkey.as_bytes());
            }
            if OutputTypes::WSH & self.whitelisted_outputs && output.script_pubkey.is_v0_p2wsh() {
                filter.put(output.script_pubkey.as_bytes());
            }
            if OutputTypes::TR & self.whitelisted_outputs && output.script_pubkey.is_v1_p2tr() {
                filter.put(output.script_pubkey.as_bytes());
            }
        }
    }
    fn write_outputs(&self, txs: &Vec<Transaction>, filter: &mut FilterBuilder) {
        for tx in txs {
            self.write_tx_outs(&tx, filter);
        }
    }
}
/// Builds a block filter backend with an interactive builder.
///
/// The only thing required is a database to save the filters.
#[derive(Default)]
pub struct FilterBackendBuilder {
    storage: Option<Box<dyn BlockFilterStore>>,
    whitelisted_outputs: u8,
    index_input: bool,
    k0: u64,
    k1: u64,
}

impl FilterBackendBuilder {
    /// Which storage we should use for our filters
    pub fn use_storage(&mut self, s: Box<dyn BlockFilterStore>) -> &mut Self {
        self.storage.replace(s);
        self
    }
    /// Add one address type to the set of outputs we follow
    ///
    /// You can use whatever number of types, including all. But any new type
    /// makes the filter larger.
    pub fn add_address_type(&mut self, out_type: OutputTypes) -> &mut Self {
        match out_type {
            OutputTypes::PKH => self.whitelisted_outputs |= 1,
            OutputTypes::SH => self.whitelisted_outputs |= 2,
            OutputTypes::WPKH => self.whitelisted_outputs |= 4,
            OutputTypes::WSH => self.whitelisted_outputs |= 16,
            OutputTypes::TR => self.whitelisted_outputs |= 32,
        };
        self
    }
    /// Whether we index inputs
    ///
    /// If true, we add the prevout, but not the previous spk or scriptSig
    pub fn index_output(&mut self, index: bool) -> &mut Self {
        self.index_input = index;
        self
    }
    /// Builds the final backend
    ///
    /// Panics if we don't have a storage
    pub fn build(self) -> BlockFilterBackend {
        BlockFilterBackend {
            whitelisted_outputs: self.whitelisted_outputs,
            index_inputs: self.index_input,
            storage: self.storage.unwrap(),
            k0: self.k0,
            k1: self.k1,
        }
    }
}
