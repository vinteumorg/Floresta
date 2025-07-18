//! This module defines the structures and methods for handling Utreexo proofs in the context of
//! Bitcoin.
//!
//! Utreexo is a dynamic accumulator, used to represent the UTXO set in a succinct way. This
//! allows for lightweight clients that still performs full-validation. The trade-off is that
//! for every UTXO being spent, you need a proof showing that UTXO being part of the UTXO set.
//!
//! This proof can be downloaded from the network, as long as you have at least one utreexo
//! archive node. You first download the actual block. Then you figure out which inputs do you
//! need -- you may not need all of them, due to some of them being cached by your local client.
//! Then you request them, by sending a [GetUtreexoProof] message.
//!
//! This message asks for one block hash, whether to include leaf data (the data associated with
//! a given UTXO), and two bitmaps: one for the proof hashes, and one for the leaf indices. These
//! bitmaps are used to indicate which inputs you want to include in the proof. You list the
//! inputs the weren't created in the same block, in the same order they appear in block. If you
//! need it, you set the associated bit to `true`, otherwise you set it to `false`.
//!
//! You'll then receive a [UtreexoProof] message, which contains the block hash, the proof hashes,

use bitcoin::consensus::Decodable;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::sha256;
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use bitcoin::VarInt;
use floresta_chain::CompactLeafData;
use floresta_chain::ScriptPubKeyKind;
use rustreexo::accumulator::node_hash::BitcoinNodeHash;

#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// A Bitmap used to request proof elements in Utreexo proofs.
///
/// This bitmap is used to indicate which inputs you want to include in the proof.
/// Each bit in the bitmap corresponds to an input in the block, where `true` means
/// the input should be included in the proof and `false` means it should not.
pub struct Bitmap {
    /// The actual bytes representing the bitmap.
    bytes: Vec<u8>,

    /// How many elements have been pushed into the bitmap.
    n_inputs: usize,
}

impl Bitmap {
    /// Creates a new empty Bitmap.
    ///
    /// You should use the `push_input` method to add inputs to the bitmap.
    pub fn new() -> Self {
        Self {
            bytes: Vec::new(),
            n_inputs: 0,
        }
    }

    /// Adds a new input to the bitmap.
    ///
    /// This method takes a boolean `request` which indicates whether the input
    /// should be requested from our remote peer (`true`) or not (`false`).
    pub fn push_input(&mut self, request: bool) {
        const BITS_IN_A_BYTE: usize = 8;

        let bit_offset = self.n_inputs % BITS_IN_A_BYTE;
        if bit_offset == 0 {
            self.bytes.push(request as u8);
            return;
        }

        let byte_n = self.n_inputs / BITS_IN_A_BYTE;
        let byte = self.bytes.get_mut(byte_n).unwrap();

        *byte |= (request as u8) << bit_offset;
    }
}

impl Encodable for Bitmap {
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        let mut len = 0;
        len += self.bytes.consensus_encode(writer)?;
        Ok(len)
    }
}

/// Represents a Utreexo proof request, for a specific block.
pub struct GetUtreexoProof {
    /// The block hash for which the proof is requested.
    pub block_hash: BlockHash,

    /// Whether to include leaf data in the proof.
    pub include_leavs: bool,

    /// A bitmap indicating which proof hashes to include in the response.
    pub proof_hashes_bitmap: Bitmap,

    /// A bitmap indicating which leaf indices to include in the response.
    pub leaf_index_bitmap: Bitmap,
}

impl Encodable for GetUtreexoProof {
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        let mut len = 0;
        len += self.block_hash.consensus_encode(writer)?;
        len += self.include_leavs.consensus_encode(writer)?;
        len += self.proof_hashes_bitmap.consensus_encode(writer)?;
        len += self.leaf_index_bitmap.consensus_encode(writer)?;

        Ok(len)
    }
}

#[derive(Debug, Clone)]
/// Represents a Utreexo proof for a specific block.
///
/// This message will be sent in response to a [GetUtreexoProof] request.
pub struct UtreexoProof {
    /// The block hash for which the proof is provided.
    pub block_hash: BlockHash,

    /// The proof hashes for the requested inputs.
    pub proof_hashes: Vec<BitcoinNodeHash>,

    /// The targets for the requested inputs.
    pub targets: Vec<u64>,

    /// The leaf data for the requested inputs.
    pub leaf_datas: Vec<CompactLeafData>,
}

impl Decodable for UtreexoProof {
    fn consensus_decode<R: bitcoin::io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        let block_hash = BlockHash::consensus_decode(reader)?;

        // Read the proof hashes
        let n_hashes = VarInt::consensus_decode(reader)?.0 as usize;
        let mut proof_hashes = Vec::with_capacity(n_hashes);
        for _ in 0..n_hashes {
            let hash = sha256::Hash::consensus_decode(reader)?;
            proof_hashes.push(BitcoinNodeHash::from(hash.as_byte_array()));
        }

        // Read the targets
        let n_targets = VarInt::consensus_decode(reader)?.0 as usize;
        let mut targets = Vec::with_capacity(n_targets);
        for _ in 0..n_targets {
            targets.push(u64::consensus_decode(reader)?);
        }

        // Read the leaf data
        let n_leaf_datas = VarInt::consensus_decode(reader)?.0 as usize;
        let mut leaf_datas = Vec::with_capacity(n_leaf_datas);
        for _ in 0..n_leaf_datas {
            let header_code = u32::consensus_decode(reader)?;
            let amount = u64::consensus_decode(reader)?;
            let spk_ty = ScriptPubKeyKind::consensus_decode(reader)?;

            leaf_datas.push(CompactLeafData {
                header_code,
                amount,
                spk_ty,
            });
        }

        Ok(UtreexoProof {
            block_hash,
            proof_hashes,
            targets,
            leaf_datas,
        })
    }
}

#[cfg(test)]
mod utreexo_proof_tests {
    use crate::p2p_wire::block_proof::Bitmap;

    #[test]
    fn test_build_bitmap() {
        let mut bitmap = Bitmap::new();

        bitmap.push_input(false); // 0
        bitmap.push_input(true); // 01
        bitmap.push_input(false); // 010
        bitmap.push_input(false); // 0100
        bitmap.push_input(true); // 0100 1
        bitmap.push_input(true); // 0100 11
        bitmap.push_input(false); // 0100 110
        bitmap.push_input(false); // 0100 1100
        bitmap.push_input(false); // 0100 1100 0
        bitmap.push_input(false); // 0100 1100 00
        bitmap.push_input(true); // 0100 1100 001

        let final_bitmap = vec![0x0100, 0x1100, 0x0010];
        assert_eq!(bitmap.bytes, final_bitmap);
        assert_eq!(bitmap.n_inputs, 12);
    }

    #[test]
    fn test_empty_bitmap_serialization() {
        use bitcoin::consensus::encode::serialize;

        let bitmap = Bitmap::new();
        let serialized = serialize(&bitmap);
        assert_eq!(serialized, vec![0x00]);
    }
}
