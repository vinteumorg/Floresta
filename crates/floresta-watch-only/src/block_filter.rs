use std::io::Write;

use bitcoin::{
    hashes::Hash,
    util::bip158::{self, BlockFilter, GCSFilterWriter},
    Block, BlockHash, OutPoint, Transaction, Txid,
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
    /// Whether we index txids. If true, all txids are added to the filter. This is useful for
    /// using floresta as a lightning node backend
    index_txids: bool,
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
            index_txids: true,
            storage,
            k0: 0,
            k1: 0,
        }
    }
    pub fn filter_block(&self, block: &Block, block_height: u64) -> Result<(), bip158::Error> {
        let mut writer = Vec::new();
        let mut filter = FilterBuilder::new(&mut writer, 784931, 19, self.k0, self.k1);
        if self.index_inputs {
            self.write_inputs(&block.txdata, &mut filter);
        }
        if self.index_txids {
            self.write_txids(&block.txdata, &mut filter);
        }

        self.write_outputs(&block.txdata, &mut filter);
        filter.finish()?;

        let filter = BlockFilter::new(writer.as_slice());
        self.storage.put_filter(block_height, filter);

        Ok(())
    }
    pub fn match_any(&self, start: u64, end: u64, query: &[QueryType]) -> Option<Vec<u64>> {
        let mut values = query.into_iter().map(|filter| &*filter.into_slice());
        let key = BlockHash::from_inner([0; 32]);

        let mut blocks = Vec::new();

        for i in start..=end {
            if self
                .storage
                .get_filter(i)?
                .match_any(&key, &mut values)
                .ok()?
            {
                blocks.push(i);
            }
        }

        Some(blocks)
    }
    fn write_txids(&self, txs: &Vec<Transaction>, filter: &mut FilterBuilder) {
        for tx in txs {
            filter.put(tx.txid().as_inner());
        }
    }
    fn write_inputs(&self, txs: &Vec<Transaction>, filter: &mut FilterBuilder) {
        for tx in txs {
            tx.input.iter().for_each(|input| {
                let mut ser_input = [0; 36];
                ser_input[0..32].clone_from_slice(&input.previous_output.txid);
                ser_input[32..].clone_from_slice(&input.previous_output.vout.to_be_bytes());
                filter.put(&ser_input);
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
/// Fields have the same meaning as in the backend itself.
#[derive(Default)]
pub struct FilterBackendBuilder {
    storage: Option<Box<dyn BlockFilterStore>>,
    whitelisted_outputs: u8,
    index_input: bool,
    index_txids: bool,
    k0: u64,
    k1: u64,
}

impl FilterBackendBuilder {
    /// Which storage we should use for our filters
    ///
    /// This is the only required field.
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
    /// Whether we should index txids
    ///
    /// You can use this index to fetch arbitrary outpoints, like a lightning
    /// channel. In general, this should be used in combination with index_input,
    /// or you can't be sure whether the outpoint is spent or not.
    pub fn index_txids(&mut self, index: bool) -> &mut Self {
        self.index_txids = index;
        self
    }
    /// Whether we index inputs
    ///
    /// If true, we add the prevout, but not the previous spk or scriptSig
    pub fn index_input(&mut self, index: bool) -> &mut Self {
        self.index_input = index;
        self
    }
    /// Builds the final backend
    ///
    /// # Panics
    /// Panics if we don't have a storage
    pub fn build(self) -> BlockFilterBackend {
        BlockFilterBackend {
            whitelisted_outputs: self.whitelisted_outputs,
            index_inputs: self.index_input,
            index_txids: self.index_txids,
            storage: self.storage.unwrap(),
            k0: self.k0,
            k1: self.k1,
        }
    }
}

pub struct QueriableOutpoint(pub(crate) [u8; 36]);

impl From<OutPoint> for QueriableOutpoint {
    fn from(value: OutPoint) -> Self {
        let mut ser_input = [0; 36];
        ser_input[0..32].clone_from_slice(value.txid.as_inner());
        ser_input[32..].clone_from_slice(&value.vout.to_be_bytes());
        QueriableOutpoint(ser_input)
    }
}

pub enum QueryType<'a> {
    Input(QueriableOutpoint),
    Script(&'a [u8]),
    Txid(Txid),
}

impl<'a> QueryType<'a> {
    pub(crate) fn into_slice(&self) -> &[u8] {
        match self {
            QueryType::Txid(txid) => txid.as_inner().as_slice(),
            QueryType::Input(outpoint) => &outpoint.0,
            QueryType::Script(script) => script,
        }
    }
}

#[cfg(test)]
use std::cell::RefCell;

#[cfg(test)]
#[derive(Debug, Default)]
pub struct MemoryBlockFilterStorage {
    filters: RefCell<Vec<bip158::BlockFilter>>,
}

#[cfg(test)]
impl BlockFilterStore for MemoryBlockFilterStorage {
    fn get_filter(&self, block_height: u64) -> Option<bip158::BlockFilter> {
        self.filters.borrow().get(block_height as usize).cloned()
    }
    fn put_filter(&self, _block_height: u64, block_filter: bip158::BlockFilter) {
        self.filters.borrow_mut().push(block_filter);
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        consensus::deserialize,
        hashes::{hex::FromHex, Hash},
        util::bip158,
        Block, BlockHash, OutPoint, Txid,
    };

    use crate::block_filter::QueryType;

    use super::{BlockFilterBackend, FilterBuilder, MemoryBlockFilterStorage};
    #[test]
    fn test_filter() {
        let mut writer = Vec::new();
        let value = [10_u8; 42].as_slice();
        let mut filters = FilterBuilder::new(&mut writer, 784931, 19, 0, 0);

        filters.put(value);
        filters.finish().unwrap();

        let filter = bip158::BlockFilter::new(&writer);
        let res = filter
            .match_any(&BlockHash::from_inner([0; 32]), &mut [value].into_iter())
            .unwrap();
        assert_eq!(res, true);

        let value = [11_u8; 42].as_slice();
        let res = filter
            .match_any(&BlockHash::from_inner([0; 32]), &mut [value].into_iter())
            .unwrap();
        assert_eq!(res, false);
    }

    #[test]
    fn test_filter_block() {
        let block = Vec::from_hex("000000204cc1f0cc52950600bc94fc482713c1f10174c85f20290168832552c1b900000039d96a9dbab5998c344c092583552e6ed5e2884c8a52a95b482f59413f39e8d55cf03f654454011e7d45dc0003020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0f030b8d020a2f7369676e65743a332ffeffffff025503062a010000002251207099e4b23427fc40ba4777bbf52cfd0b7444d69a3e21ef281270723f54c0c14b0000000000000000776a24aa21a9edfb6e452f1cccc00da281067a88bed1d9ec6e02361d424dfd46dc46972b6c22284c4fecc7daa249004730440220435eaca92f93497d07825fe4587183272084e257c61cccab15a1dbc37a946699022000c18b0cba4f96ab5f741478da264b361ba95523a486126657b6f9e1045126a20100012000000000000000000000000000000000000000000000000000000000000000000000000002000000000101125b54a68d9a39561dd268e020e3f26dd900ded46a3dfdbae7ea95797022a0a80100000000fdffffff027082030000000000160014fabea557d8541249533fe281aac45c37b2dbf3422dab090000000000220020dfcc1d4c1fef729015420efed6202f7d1fd1a74813f7875fa235413bd36f73d20800483045022100dce01d603f84de4faeacd7bcdf1bc93fdc3cb7a28eff0544d88c1b64fa07f8d602206aefc00419126035222e5138b07b40d77c71feba78c26d4febd51f10f814dff101483045022100bf7c25066c5c4abb2d2733cf04c700b175d5e92d09e5931313adaef05e062758022001cf4bb4437a0a20b6ff9277c29a2b28259c1a6143fd4938920cae7a8a3658350147304402206f3d38a3f4db843a41f22583cfd344b935156fa0e82afe7212f8861fc04d979c0220726324a84cb6906df296416a00032e0c8238df0f4cf8e7204385f2cdd359056301483045022100fb3a30dc1103ba0b865d96bd9097a264c0e18aeffb2a4ee0875c0edea356cb6c022070e47aac3b0ed218a9afbc7f70d42935084a80f47af44941a6712314b3391b50010000fdea016376a914a2c0c43c1cbc4c3d1f5d197000414de73e76456388ac6b76a914bf51072415ece1527ac34d955924be96d07cbde788ac6c936b76a91425fb796fb6194fe09ab2b06344bace2b9320d45c88ac6c936b76a914a6cb8313859649a1b83dc9b77c3afe7671affe0b88ac6c93518803ffff00b2676376a914c209f7a523ffa69a7226c5a5167b2b37ddec58eb88ac6b76a914d61ff559b874d8833b75b7d6939b0df3e68b583d88ac6c936b76a91444b6c96c823cb70c130bd12ee39b5504d6be84cc88ac6c936b76a914f086890b09e618632f45a3511c5983dafb2e714a88ac6c93528854b267542102a31ccbcc7262f1cf9ee85bf04723d28d5cdebdaa98fa0b972fd5210610c6aaba2102a9b90ff89fa8a411c7e8f1af247ba6e32c6d4d4e682d643eb30a02841dae2a962103b8c2b5e5db7603cb0b3a5280941988588af0f71362321442f228fb2b4a38cbd921022da633f9e545cc1029055cafa583b4cd99b7a4bcfb1ea2a388fbefb11e0c8b9054ae736476a91443948748fc4e5a8300ea3eee7feafad9cdd4a3c588ac6b76a91447f5b0296d7b9dd38b64d45b3ef88490847d17ad88ac6c936b76a914f2b7716f6e11b214457c38c501b7a0f7706e06aa88ac6c936b76a91443587cfdb6e2bace0de537152e1ffa8e8d77d91a88ac6c93538852b268686800000000020000000001013b12458f060f8df025c0ab068695384bcc6c846aefed31b0d203122ee09c71100100000000feffffff02ef8b64d04a0600001600147f5eeef1c2a1c5c81ee1545876c8f8fc93d0c1e6a086010000000000160014a9c03ef086c4d0c9fe2d093a4e1f28dff63c0f700247304402205e1935e762a89e99b9185e540ad0a1800d26a9643599d28c4e8619432f04abc802200a3fedf0746f127884b74087561d3190c408afda770bd5aeb3928bb7a4d61832012103b5746579fa0f79ed83dfd6a2142d957156a89690fcb76ed90debdf287b9bc94bb98c0200").unwrap();

        let block: Block = deserialize(&block).unwrap();
        let storage = MemoryBlockFilterStorage::default();
        let backend = BlockFilterBackend::new(Box::new(storage));

        backend.filter_block(&block, 0).unwrap();

        // One txid from this block
        let txid =
            Txid::from_hex("7e0ce903920704a79beb99beb05c6d5a01852907dccc0973f96eb295d1ad0557")
                .unwrap();
        let txid = QueryType::Txid(txid);

        // One output being spent in this block
        let prev_txid =
            Txid::from_hex("a8a022707995eae7bafd3d6ad4de00d96df2e320e068d21d56399a8da6545b12")
                .unwrap();
        let prev_vout: u32 = 1;

        let prevout = QueryType::Input(
            OutPoint {
                txid: prev_txid,
                vout: prev_vout,
            }
            .into(),
        );

        let expected = Some(vec![0]);

        assert_eq!(backend.match_any(0, 0, &[txid]), expected);
        assert_eq!(backend.match_any(0, 0, &[prevout]), expected);
    }
}
