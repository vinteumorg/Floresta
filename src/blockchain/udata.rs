//! UData is the serialized data used for proof propagation in utreexo. It contains all
//! data needed for validating some piece of information, like a transaction and a block.

use bitcoin::{consensus::Decodable, BlockHash, OutPoint, TxOut};
use serde::Deserialize;

/// Leaf data is the data that is hashed when adding to utreexo state. It contains validation
/// data and some commitments to make it harder to attack an utreexo-only node.
#[derive(Debug, Deserialize)]
pub struct LeafData {
    /// A commitment to the block creating this utxo
    pub block_hash: BlockHash,
    /// The utxo's outpoint
    pub prevout: OutPoint,
    /// Header code is a compact commitment to the block height and whether or not this
    /// transaction is coinbase. It's defined as
    ///
    /// ```
    /// header_code: u32 = if transaction.is_coinbase() {
    ///     (block_height << 1 ) | 1
    /// } else {
    ///     block_height << 1
    /// };
    /// ```
    pub header_code: u32,
    /// The actual utxo
    pub utxo: TxOut,
}

impl Decodable for LeafData {
    fn consensus_decode<R: std::io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        Self::consensus_decode_from_finite_reader(reader)
    }
    fn consensus_decode_from_finite_reader<R: std::io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        let block_hash = BlockHash::consensus_decode(reader)?;
        let prevout = OutPoint::consensus_decode(reader)?;
        let header_code = u32::consensus_decode(reader)?;
        let utxo = TxOut::consensus_decode(reader)?;
        Ok(LeafData {
            block_hash,
            prevout,
            header_code,
            utxo,
        })
    }
}
