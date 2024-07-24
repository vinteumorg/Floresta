//! UData is the serialized data used for proof propagation in utreexo. It contains all
//! data needed for validating some piece of information, like a transaction and a block.

use bitcoin::consensus;
use bitcoin::consensus::encode::Error;
use bitcoin::consensus::Decodable;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::sha256;
use bitcoin::hashes::Hash;
use bitcoin::Block;
use bitcoin::BlockHash;
use bitcoin::OutPoint;
use bitcoin::TxOut;
use bitcoin::VarInt;
use sha2::Digest;
use sha2::Sha512_256;

use crate::prelude::ioError;
use crate::prelude::Read;
use crate::prelude::*;
use crate::pruned_utreexo::consensus::UTREEXO_TAG_V1;

/// Leaf data is the data that is hashed when adding to utreexo state. It contains validation
/// data and some commitments to make it harder to attack an utreexo-only node.
#[derive(Debug, PartialEq)]
pub struct LeafData {
    /// A commitment to the block creating this utxo
    pub block_hash: BlockHash,
    /// The utxo's outpoint
    pub prevout: OutPoint,
    /// Header code is a compact commitment to the block height and whether or not this
    /// transaction is coinbase. It's defined as
    ///
    /// ```ignore
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

impl LeafData {
    pub fn _get_leaf_hashes(&self) -> sha256::Hash {
        let mut ser_utxo = Vec::new();
        let _ = self.utxo.consensus_encode(&mut ser_utxo);
        let leaf_hash = Sha512_256::new()
            .chain_update(UTREEXO_TAG_V1)
            .chain_update(UTREEXO_TAG_V1)
            .chain_update(self.block_hash)
            .chain_update(self.prevout.txid)
            .chain_update(self.prevout.vout.to_le_bytes())
            .chain_update(self.header_code.to_le_bytes())
            .chain_update(ser_utxo)
            .finalize();
        sha256::Hash::from_slice(leaf_hash.as_slice())
            .expect("parent_hash: Engines shouldn't be Err")
    }
}

impl Decodable for LeafData {
    fn consensus_decode<R: Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        Self::consensus_decode_from_finite_reader(reader)
    }
    fn consensus_decode_from_finite_reader<R: Read + ?Sized>(
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

/// Commitment of the leaf data, but in a compact way
///
/// The serialized format is:
/// [<header_code><amount><spk_type>]
///
/// The serialized header code format is:
///   bit 0 - containing transaction is a coinbase
///   bits 1-x - height of the block that contains the spent txout
///
/// It's calculated with:
///   header_code = <<= 1
///   if IsCoinBase {
///       header_code |= 1 // only set the bit 0 if it's a coinbase.
///   }
/// ScriptPubkeyType is the output's scriptPubkey, but serialized in a more efficient way
/// to save bandwidth. If the type is recoverable from the scriptSig, don't download the
/// scriptPubkey.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct CompactLeafData {
    /// Header code tells the height of creating for this UTXO and whether it's a coinbase
    pub header_code: u32,
    /// The amount locked in this UTXO
    pub amount: u64,
    /// The type of the locking script for this UTXO
    pub spk_ty: ScriptPubkeyType,
}

/// A recoverable scriptPubkey type, this avoids copying over data that are already
/// present or can be computed from the transaction itself.
/// An example is a p2pkh, the public key is serialized in the scriptSig, so we can just
/// grab it and hash to obtain the actual scriptPubkey. Since this data is committed in
/// the Utreexo leaf hash, it is still authenticated
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum ScriptPubkeyType {
    /// An non-specified type, in this case the script is just copied over
    Other(Box<[u8]>),
    /// p2pkh
    PubKeyHash,
    /// p2wsh
    WitnessV0PubKeyHash,
    /// p2sh
    ScriptHash,
    /// p2wsh
    WitnessV0ScriptHash,
}

impl Decodable for ScriptPubkeyType {
    fn consensus_decode<R: Read + ?Sized>(reader: &mut R) -> Result<Self, Error> {
        let ty = u8::consensus_decode(reader)?;
        match ty {
            0x00 => Ok(ScriptPubkeyType::Other(Box::consensus_decode(reader)?)),
            0x01 => Ok(ScriptPubkeyType::PubKeyHash),
            0x02 => Ok(ScriptPubkeyType::WitnessV0PubKeyHash),
            0x03 => Ok(ScriptPubkeyType::ScriptHash),
            0x04 => Ok(ScriptPubkeyType::WitnessV0ScriptHash),
            _ => Err(Error::ParseFailed("Invalid script type")),
        }
    }
}

impl Encodable for ScriptPubkeyType {
    fn consensus_encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<usize, ioError> {
        let mut len = 1;

        match self {
            ScriptPubkeyType::Other(script) => {
                00_u8.consensus_encode(writer)?;
                len += script.consensus_encode(writer)?;
            }
            ScriptPubkeyType::PubKeyHash => {
                0x01_u8.consensus_encode(writer)?;
            }
            ScriptPubkeyType::WitnessV0PubKeyHash => {
                0x02_u8.consensus_encode(writer)?;
            }
            ScriptPubkeyType::ScriptHash => {
                0x03_u8.consensus_encode(writer)?;
            }
            ScriptPubkeyType::WitnessV0ScriptHash => {
                0x04_u8.consensus_encode(writer)?;
            }
        }
        Ok(len)
    }
}

/// BatchProof serialization defines how the utreexo accumulator proof will be
/// serialized both for i/o.
///
/// Note that this serialization format differs from the one from
/// github.com/mit-dci/utreexo/accumulator as this serialization method uses
/// varints and the one in that package does not.  They are not compatible and
/// should not be used together.  The serialization method here is more compact
/// and thus is better for wire and disk storage.
///
/// The serialized format is:
/// [<target count><targets><proof count><proofs>]
///
/// All together, the serialization looks like so:
/// Field          Type       Size
/// target count   varint     1-8 bytes
/// targets        []uint64   variable
/// hash count     varint     1-8 bytes
/// hashes         []32 byte  variable
#[derive(PartialEq, Eq, Clone, Debug, Default)]
pub struct BatchProof {
    /// All targets that'll be deleted
    pub targets: Vec<VarInt>,
    /// The inner hashes of a proof
    pub hashes: Vec<BlockHash>,
}

/// UData contains data needed to prove the existence and validity of all inputs
/// for a Bitcoin block.  With this data, a full node may only keep the utreexo
/// roots and still be able to fully validate a block.
#[derive(PartialEq, Eq, Clone, Debug, Default)]
pub struct UData {
    /// All the indexes of new utxos to remember.
    pub remember_idx: Vec<u64>,
    /// AccProof is the utreexo accumulator proof for all the inputs.
    pub proof: BatchProof,
    /// LeafData are the tx validation data for every input.
    pub leaves: Vec<CompactLeafData>,
}

/// A block plus some udata
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct UtreexoBlock {
    /// A actual block
    pub block: Block,
    /// The utreexo specific data
    pub udata: Option<UData>,
}

impl Decodable for UtreexoBlock {
    fn consensus_decode<R: Read + ?Sized>(
        mut reader: &mut R,
    ) -> Result<Self, consensus::encode::Error> {
        let block = Block::consensus_decode(&mut reader)?;

        if let Err(Error::Io(_remember)) = VarInt::consensus_decode(&mut reader) {
            return Ok(block.into());
        };

        let n_positions = VarInt::consensus_decode(&mut reader)?;
        let mut targets = vec![];
        for _ in 0..n_positions.0 {
            let pos = VarInt::consensus_decode(&mut reader)?;
            targets.push(pos);
        }

        let n_hashes = VarInt::consensus_decode(&mut reader)?;
        let mut hashes = vec![];
        for _ in 0..n_hashes.0 {
            let hash = BlockHash::consensus_decode(&mut reader)?;
            hashes.push(hash);
        }

        let n_leaves = VarInt::consensus_decode(&mut reader)?;
        let mut leaves = vec![];
        for _ in 0..n_leaves.0 {
            let header_code = u32::consensus_decode(&mut reader)?;
            let amount = u64::consensus_decode(&mut reader)?;
            let spk_ty = ScriptPubkeyType::consensus_decode(&mut reader)?;

            leaves.push(CompactLeafData {
                header_code,
                amount,
                spk_ty,
            });
        }

        Ok(Self {
            block,
            udata: Some(UData {
                remember_idx: vec![],
                proof: BatchProof { targets, hashes },
                leaves,
            }),
        })
    }
}

impl From<UtreexoBlock> for Block {
    fn from(block: UtreexoBlock) -> Self {
        block.block
    }
}

impl From<Block> for UtreexoBlock {
    fn from(block: Block) -> Self {
        UtreexoBlock { block, udata: None }
    }
}

pub mod proof_util {
    use bitcoin::blockdata::script::Instruction;
    use bitcoin::hashes::sha256;
    use bitcoin::hashes::Hash;
    use bitcoin::Amount;
    use bitcoin::OutPoint;
    use bitcoin::PubkeyHash;
    use bitcoin::ScriptBuf;
    use bitcoin::ScriptHash;
    use bitcoin::TxIn;
    use bitcoin::TxOut;
    use bitcoin::WPubkeyHash;
    use bitcoin::WScriptHash;
    use rustreexo::accumulator::node_hash::NodeHash;
    use rustreexo::accumulator::proof::Proof;

    use super::LeafData;
    use crate::prelude::*;
    use crate::pruned_utreexo::utxo_data::UtxoData;
    use crate::pruned_utreexo::utxo_data::UtxoMap;
    use crate::pruned_utreexo::BlockchainInterface;
    use crate::BlockchainError;
    use crate::CompactLeafData;
    use crate::ScriptPubkeyType;
    use crate::UData;

    #[derive(Debug)]
    pub enum Error {
        EmptyStack,
    }

    pub fn reconstruct_leaf_data(
        leaf: &CompactLeafData,
        input: &TxIn,
        block_hash: bitcoin::BlockHash,
    ) -> Result<LeafData, BlockchainError> {
        let spk = reconstruct_script_pubkey(leaf, input)?;

        Ok(LeafData {
            block_hash,
            header_code: leaf.header_code,
            prevout: input.previous_output,
            utxo: TxOut {
                script_pubkey: spk,
                value: Amount::from_sat(leaf.amount),
            },
        })
    }

    #[allow(clippy::type_complexity)]
    pub fn process_proof<Chain: BlockchainInterface>(
        udata: &UData,
        block: &bitcoin::Block,
        chain: &Chain,
    ) -> Result<(Proof, Vec<sha256::Hash>, UtxoMap), BlockchainError> {
        let targets = udata.proof.targets.iter().map(|target| target.0).collect();
        let hashes = udata
            .proof
            .hashes
            .iter()
            .map(|hash| NodeHash::Some(*hash.as_byte_array()))
            .collect();
        let proof = Proof::new(targets, hashes);
        let mut hashes = Vec::new();
        let mut leaves_iter = udata.leaves.iter().cloned();

        let mut tx_iter = block.txdata.iter();

        let actual_block_height = match chain.get_block_height(&block.block_hash()) {
            Ok(height) => {
                if let Some(height) = height {
                    height
                } else {
                    return Err(BlockchainError::BlockNotFound);
                }
            }
            Err(_) => return Err(BlockchainError::BlockNotFound),
        };

        tx_iter.next(); // skip coinbase

        let mut inputs = HashMap::new();
        for tx in tx_iter {
            let txid = tx.txid();
            for (vout, out) in tx.output.iter().enumerate() {
                inputs.insert(
                    OutPoint {
                        txid,
                        vout: vout as u32,
                    },
                    UtxoData::new(out.clone(), actual_block_height, 0),
                );
            }

            for input in tx.input.iter() {
                if !inputs.contains_key(&input.previous_output) {
                    if let Some(leaf) = leaves_iter.next() {
                        let height = leaf.header_code >> 1;
                        let hash = chain
                            .get_block_hash(height)
                            .map_err(|_| BlockchainError::BlockNotFound)?;
                        let leaf =
                            reconstruct_leaf_data(&leaf, input, hash).expect("Invalid proof");
                        hashes.push(leaf._get_leaf_hashes());
                        inputs.insert(leaf.prevout, UtxoData::new(leaf.utxo, height, 0));
                    }
                }
            }
        }

        Ok((proof, hashes, inputs))
    }

    fn reconstruct_script_pubkey(
        leaf: &CompactLeafData,
        input: &TxIn,
    ) -> Result<ScriptBuf, BlockchainError> {
        match &leaf.spk_ty {
            ScriptPubkeyType::Other(spk) => Ok(ScriptBuf::from(spk.clone().into_vec())),
            ScriptPubkeyType::PubKeyHash => {
                let pkhash = get_pk_hash(input)?;
                Ok(ScriptBuf::new_p2pkh(&pkhash))
            }
            ScriptPubkeyType::WitnessV0PubKeyHash => {
                let pk_hash = get_witness_pk_hash(input)?;
                Ok(ScriptBuf::new_p2wpkh(&pk_hash))
            }
            ScriptPubkeyType::ScriptHash => {
                let script_hash = get_script_hash(input)?;
                Ok(ScriptBuf::new_p2sh(&script_hash))
            }
            ScriptPubkeyType::WitnessV0ScriptHash => {
                let witness_program_hash = get_witness_script_hash(input)?;
                Ok(ScriptBuf::new_p2wsh(&witness_program_hash))
            }
        }
    }
    fn get_pk_hash(input: &TxIn) -> Result<PubkeyHash, BlockchainError> {
        let script_sig = &input.script_sig;
        let inst = script_sig.instructions().last();
        if let Some(Ok(bitcoin::blockdata::script::Instruction::PushBytes(bytes))) = inst {
            return Ok(PubkeyHash::hash(bytes.as_bytes()));
        }
        Err(BlockchainError::EmptyStack)
    }
    fn get_script_hash(input: &TxIn) -> Result<ScriptHash, BlockchainError> {
        let script_sig = &input.script_sig;
        let inst = script_sig.instructions().last();
        if let Some(Ok(Instruction::PushBytes(bytes))) = inst {
            return Ok(ScriptBuf::from_bytes(bytes.as_bytes().to_vec()).script_hash());
        }
        Err(BlockchainError::EmptyStack)
    }
    fn get_witness_pk_hash(input: &TxIn) -> Result<WPubkeyHash, BlockchainError> {
        let witness = &input.witness;
        let pk = witness.last();
        if let Some(pk) = pk {
            return Ok(WPubkeyHash::hash(pk));
        }
        Err(BlockchainError::EmptyStack)
    }
    fn get_witness_script_hash(input: &TxIn) -> Result<WScriptHash, BlockchainError> {
        let witness = &input.witness;
        let script = witness.last();
        if let Some(script) = script {
            return Ok(WScriptHash::hash(script));
        }
        Err(BlockchainError::EmptyStack)
    }
}
#[cfg(test)]
mod test {
    extern crate std;
    use std::str::FromStr;
    use std::vec::Vec;

    use bitcoin::consensus::deserialize;
    use bitcoin::hashes::hex::FromHex;
    use bitcoin::Amount;
    use bitcoin::BlockHash;
    use bitcoin::ScriptBuf;
    use bitcoin::Transaction;

    use super::proof_util::reconstruct_leaf_data;
    use super::CompactLeafData;
    use super::LeafData;
    use super::ScriptPubkeyType;

    macro_rules! test_recover_spk {
        (
            $tx_hex:literal,
            $height:literal,
            $index:literal,
            $amount:literal,
            $block_hash:literal,
            $spk_type:ident,
            $expected_spk:literal
        ) => {
            let hex = Vec::from_hex($tx_hex).unwrap();
            let s: Transaction = deserialize(&hex).unwrap();
            let leaf = CompactLeafData {
                amount: Amount::from_btc($amount).unwrap().to_sat(),
                header_code: $height,
                spk_ty: ScriptPubkeyType::$spk_type,
            };
            let spk = super::proof_util::reconstruct_leaf_data(
                &leaf,
                &s.input[0],
                BlockHash::from_str($block_hash).unwrap(),
            )
            .unwrap();
            assert_eq!(
                spk.utxo.script_pubkey,
                ScriptBuf::from_hex($expected_spk).unwrap()
            )
        };
    }
    #[test]
    fn test_spk_recovery() {
        // p2pkh
        test_recover_spk!(
            "010000000114baa734ec1a75e84726af2da3abcd41fe9d96f3f8b7e99bcefdfc040cffc2ba030000006a47304402202f89e2deb17f0c2c5732d6f7791a2731703cb128dc86ae0bf288e55a3d7ce9d6022051c2242ca0885a4a2054391385eda03132616fb0c2daa61d6823eff7a21b5d0c01210395c223fbf96e49e5b9e06a236ca7ef95b10bf18c074bd91a5942fc40360d0b68fdffffff04b400000000000000536a4c5058325bc5b3f7d4e7acf388d63ab92d14d7f8f8bcdff384bddd4668f283df0bfe1c2f7728ec1e550ca841794fa28e16e154c5b92b5a1d1d98db4e89f15726bf75e352fe000bddf10068000bd72600012bc20000000000000017a914352481ec2fecfde0c5cdc635a383c4ac27b9f71e87c20000000000000017a9144890aae025c84cb72a9730b49ca12595d6f6088d8772aa0900000000001976a914bf2646b8ba8b4a143220528bde9c306dac44a01c88ac00000000",
            0,
            777548,
            0.03956721,
            "000000000000000000066caa76847c109010eb58402d7a5bf05cc201a011071d",
            PubKeyHash,
            "76a914bf2646b8ba8b4a143220528bde9c306dac44a01c88ac"
        );
        // p2sh
        test_recover_spk!(
            "0200000001ff1ba24eb11f1290b293b2c5520e4863ffedcc4a4ed9e4933334639ecbcc946500000000fc00473044022001460e6d06dc44e163ef1f692d275a1e357d086d0361fbe5012dbf18cbf2617202207f9e8fb54e776d7e98a6425da2be15e2ffca2e623b7617234226eafe77c70eaa01473044022076d756a250ad4044e2b4a0049112d87367b2f0ce80253e400f3ba09d620cbbdd022020f67b65f7cb5e109b8ccbc852e30b4e84b0b682136a5e72f679bd581b271ea8014c695221021c04b91bffe90c3e4defd021a4b6da4983b97e13c772bf15009f1661480658832102be11f7f0d9696ef731c13ed8b6e955df43cd4238d694a1698b02fcb3c2d275322102e0ad7274a4e93b3b30793ff7a04a31d2792ed22a563fe5ea0095af844c10c9c453aefdffffff02fd5403000000000017a914351bb17d072fff46336baec11a6a8d13ab6b590e87305837000000000017a9147b8d77369df3d2172b0d56792308d7f2635ca79087f1dd0b00",
            0,
            777548,
            0.03956721,
            "00000000000000000005a784e2b5006b34ff63644408df00bfc1a0b1b9507021",
            ScriptHash,
            "a914ed9371b30de550c0617cd0c4b2c0c0dc5e88c65487"
        );
        //p2wpkh
        test_recover_spk!(
            "01000000000101a742910d02da84259631288eab229ca2bdd39ed7edc8811ca125dc0bcf2b654c0100000000ffffffff02ba150a000000000016001406a9852b7c9f4ff9993b5d2192ac42a5df54828e34c812000000000016001486bdf86c7cbce4841f95b4d8ef101ce8a306e6ad0247304402202936300c12249c8696bb90addcc9482995429d7be0418260178ddc0c630c10ed02206128cac337841b171d15d9aadc2af77d280da7cd85c049149c8134ddb5adc8a10121038adb3497e025c0ff14521a789af4f10d526ec4c95348e708ebdc4d5ac58228e500000000",
            1,
            777716,
            0.01893642,
            "00000000000000000002264d1e3f90280ededd1587c7af932480dac3e2480048",
            WitnessV0PubKeyHash,
            "001406a9852b7c9f4ff9993b5d2192ac42a5df54828e"
        );
        //p2wsh
        test_recover_spk!(
            "01000000000101cacacdfdc79620cac8bc463cdac9864f557fdb73b6ef0dea8e0d74297d2e4c1a0100000000ffffffff0280841e000000000017a914cef5ab6252860ada719556abebe952c79c466f86878af74e0c00000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d04004730440220289b2e0b6aec5a8f43d283edef0757206de77e3f3acdb322ade452a0468764db02201c332ec46a2ed3614fe392c4011063f39e77def57d89991ccbb99b6c7de2491901473044022044eaf71bdb4b3f0b0ba2f1eec82cad412729a1a4d5fc3b2fa251fecb73c56c0502201579c9e13b4d7595f9c6036a612828eac4796902c248131a7f25a117a0c68ca8016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000",
            0,
            487740,
            2.08551770,
            "0000000000000000004fce5d650f72e8f288e8c81b36377c3c7de3d2bc5b3118",
            WitnessV0ScriptHash,
            "0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d"
        );
        test_recover_spk!(
            "020000000001018f97e04dd76eec325c149ad417175f01f71b45523d8df79d2745cfee110eabf20000000000ffffffff015cddc71d000000002200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc3326001015100000000",
            0,
            27366,
            4.99637721,
            "000000069585e4b2517a8862d527558ff18df7d4b8c2795b249c116aba9c6c98",
            WitnessV0ScriptHash,
            "00204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260"
        );
    }
    #[test]
    fn test_reconstruct_leaf_data() {
        let leaf = Vec::from_hex("f99e24b9e96a3c6220449b2bf520d6a9562237e2f4fc6f6b2ba57a71de000000e6f50efb6747f836ca3510df3da120fdb2ae4cf62893cc014e08c25dab70248b01000000cc000400b429653b4f0600001600142b91c8f80b071c5f60e1a512d49a6a544e51165b").unwrap();
        let leaf: LeafData = deserialize(&leaf).unwrap();
        let spending_tx = Vec::from_hex("02000000000101e6f50efb6747f836ca3510df3da120fdb2ae4cf62893cc014e08c25dab70248b0100000000feffffff02dbe6553b4f0600001600148d57f8da7fc15371dc14d35e97850ab564a17b1240420f0000000000220020ed59bf193c5197a5b1dbbbc723ddeca82cdfbb188218b3ede50150e1890fc55202473044022024979ec4bda473b71288b2c15390418d7d300551aa5e463cc6b64acd5c3070b50220444c94242aff2ba1bd966308d60f537524b0755931d545d98e1fc45239ff6b08012103de7c420624c009d6a5761871e78b39ff864887f885ed313e27f778b3772e74916a000200").unwrap();
        let spending_tx: Transaction = deserialize(&spending_tx).unwrap();

        let compact = CompactLeafData {
            amount: Amount::from_btc(69373.68668596).unwrap().to_sat(),
            header_code: 262348,
            spk_ty: ScriptPubkeyType::WitnessV0PubKeyHash,
        };
        let reconstructed = reconstruct_leaf_data(
            &compact,
            &spending_tx.input[0],
            BlockHash::from_str("000000de717aa52b6b6ffcf4e2372256a9d620f52b9b4420623c6ae9b9249ef9")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(leaf, reconstructed);
    }
}
