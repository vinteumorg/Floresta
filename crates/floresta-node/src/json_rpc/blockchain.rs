use bitcoin::block::Header;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::consensus::Encodable;
use bitcoin::constants::genesis_block;
use bitcoin::Address;
use bitcoin::Block;
use bitcoin::BlockHash;
use bitcoin::MerkleBlock;
use bitcoin::OutPoint;
use bitcoin::Script;
use bitcoin::ScriptBuf;
use bitcoin::Txid;
use miniscript::descriptor::checksum;
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use serde_json::Value;
use tracing::debug;

use super::res::GetBlockResVerbose;
use super::res::GetBlockchainInfoRes;
use super::res::GetTxOutProof;
use super::res::JsonRpcError;
use super::server::RpcChain;
use super::server::RpcImpl;
use crate::json_rpc::res::RescanConfidence;

#[derive(Debug, Serialize, Deserialize)]
/// Struct helper for RpcGetTxOut
pub struct ScriptPubkeyDescription {
    /// Disassembly of the output script
    asm: String,

    /// Inferred descriptor for the output
    desc: String,

    /// The raw output script bytes, hex-encoded
    hex: String,

    /// The type, eg pubkeyhash
    #[serde(rename = "type")]
    type_field: String,

    /// The Bitcoin address (only if a well-defined address exists)
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
/// Struct helper for serialize gettxout rpc
pub struct GetTxOut {
    /// The hash of the block at the tip of the chain
    bestblock: BlockHash,

    /// The number of confirmations
    confirmations: u32,

    /// The transaction value in BTC
    value: f64,

    #[serde(rename = "scriptPubKey")]
    /// Script Public Key struct
    script_pubkey: ScriptPubkeyDescription,

    /// Coinbase or not
    coinbase: bool,
}

impl<Blockchain: RpcChain> RpcImpl<Blockchain> {
    async fn get_block_inner(&self, hash: BlockHash) -> Result<Block, JsonRpcError> {
        let is_genesis = self.chain.get_block_hash(0).unwrap().eq(&hash);

        if is_genesis {
            return Ok(genesis_block(self.network));
        }

        self.node
            .get_block(hash)
            .await
            .map_err(|e| JsonRpcError::Node(e.to_string()))
            .and_then(|block| block.ok_or(JsonRpcError::BlockNotFound))
    }

    /// Return the block that contains the given Txid
    pub fn get_block_by_txid(&self, txid: &Txid) -> Result<Block, JsonRpcError> {
        let height = self
            .wallet
            .get_height(txid)
            .ok_or(JsonRpcError::TxNotFound)?;
        let blockhash = self.chain.get_block_hash(height).unwrap();
        self.chain
            .get_block(&blockhash)
            .map_err(|_| JsonRpcError::BlockNotFound)
    }

    pub async fn get_rescan_interval(
        &self,
        use_timestamp: bool,
        start: Option<u32>,
        stop: Option<u32>,
        confidence: Option<RescanConfidence>,
    ) -> Result<(u32, u32), JsonRpcError> {
        let start = start.unwrap_or(0u32);
        let stop = stop.unwrap_or(0u32);

        if use_timestamp {
            let confidence = confidence.unwrap_or(RescanConfidence::Medium);
            // `get_block_height_by_timestamp` already does the time validity checks.

            let start_height = self
                .get_block_height_by_timestamp(start, &confidence)
                .await?;

            let stop_height = self
                .get_block_height_by_timestamp(stop, &RescanConfidence::Exact)
                .await?;

            return Ok((start_height, stop_height));
        }

        let (tip, _) = self
            .chain
            .get_best_block()
            .map_err(|_| JsonRpcError::Chain)?;

        if stop > tip {
            return Err(JsonRpcError::InvalidRescanVal);
        }

        Ok((start, stop))
    }

    /// Retrieves the height of the block that was mined in the given timestamp.
    ///
    /// `timestamp` has an alias, 0 will directly refer to the network's genesis timestamp.
    pub async fn get_block_height_by_timestamp(
        &self,
        timestamp: u32,
        confidence: &RescanConfidence,
    ) -> Result<u32, JsonRpcError> {
        /// Simple helper to avoid code reuse.
        fn get_block_time<BlockChain: RpcChain>(
            provider: &RpcImpl<BlockChain>,
            at: u32,
        ) -> Result<u32, JsonRpcError> {
            let hash = provider.get_block_hash(at)?;
            let block = provider.get_block_header(hash)?;
            Ok(block.time)
        }

        let genesis_timestamp = genesis_block(self.network).header.time;

        if timestamp == 0 || timestamp == genesis_timestamp {
            return Ok(0);
        };

        let (tip_height, _) = self
            .chain
            .get_best_block()
            .map_err(|_| JsonRpcError::BlockNotFound)?;

        let tip_time = get_block_time(self, tip_height)?;

        if timestamp < genesis_timestamp || timestamp > tip_time {
            return Err(JsonRpcError::InvalidTimestamp);
        }

        let adjusted_target = timestamp.saturating_sub(confidence.as_secs());

        let mut high = tip_height;
        let mut low = 0;
        let max_iters = tip_height.ilog2() + 1;
        for _ in 0..max_iters {
            let cut = (high + low) / 2;

            let block_timestamp = get_block_time(self, cut)?;

            if block_timestamp == adjusted_target {
                debug!("found a precise block; returning {cut}");
                return Ok(cut);
            }

            if high - low <= 2 {
                debug!("didn't find a precise block; returning {low}");
                return Ok(low);
            }

            if block_timestamp > adjusted_target {
                high = cut;
            } else {
                low = cut;
            }
        }

        // This is pretty much unreachable.
        Err(JsonRpcError::BlockNotFound)
    }
}

// blockchain rpcs
impl<Blockchain: RpcChain> RpcImpl<Blockchain> {
    // dumputxoutset

    // getbestblockhash
    pub(super) fn get_best_block_hash(&self) -> Result<BlockHash, JsonRpcError> {
        Ok(self.chain.get_best_block().unwrap().1)
    }

    // getblock
    pub(super) async fn get_block(
        &self,
        hash: BlockHash,
    ) -> Result<GetBlockResVerbose, JsonRpcError> {
        let block = self.get_block_inner(hash).await?;
        let tip = self.chain.get_height().map_err(|_| JsonRpcError::Chain)?;
        let height = self
            .chain
            .get_block_height(&hash)
            .map_err(|_| JsonRpcError::Chain)?
            .unwrap();

        let median_time_past = if height > 11 {
            let mut last_block_times: Vec<_> = ((height - 11)..height)
                .map(|h| {
                    self.chain
                        .get_block_header(&self.chain.get_block_hash(h).unwrap())
                        .unwrap()
                        .time
                })
                .collect();
            last_block_times.sort();
            last_block_times[5]
        } else {
            block.header.time
        };

        let witness_block_size = block
            .txdata
            .iter()
            .map(|tx| tx.total_size() - tx.base_size())
            .sum::<usize>();
        let strippedsize = block.total_size() - witness_block_size;

        let block = GetBlockResVerbose {
            bits: serialize_hex(&block.header.bits.to_consensus().to_be()),
            chainwork: serialize_hex(&block.header.work().to_be_bytes()),
            confirmations: (tip - height) + 1,
            difficulty: block.header.difficulty_float(),
            hash: block.header.block_hash().to_string(),
            height,
            merkleroot: block.header.merkle_root.to_string(),
            nonce: block.header.nonce,
            previousblockhash: block.header.prev_blockhash.to_string(),
            size: block.total_size(),
            time: block.header.time,
            tx: block
                .txdata
                .iter()
                .map(|tx| tx.compute_txid().to_string())
                .collect(),
            version: block.header.version.to_consensus(),
            version_hex: serialize_hex(&(block.header.version.to_consensus() as u32).to_be()),
            weight: block.weight().to_wu() as usize,
            mediantime: median_time_past,
            n_tx: block.txdata.len(),
            nextblockhash: self
                .chain
                .get_block_hash(height + 1)
                .ok()
                .map(|h| h.to_string()),
            strippedsize,
            target: serialize_hex(&block.header.target().to_be_bytes()),
        };

        Ok(block)
    }

    pub(super) async fn get_block_serialized(
        &self,
        hash: BlockHash,
    ) -> Result<String, JsonRpcError> {
        let block = self.get_block_inner(hash).await?;
        Ok(serialize_hex(&block))
    }

    // getblockchaininfo
    pub(super) fn get_blockchain_info(&self) -> Result<GetBlockchainInfoRes, JsonRpcError> {
        let (height, hash) = self.chain.get_best_block().unwrap();
        let validated = self.chain.get_validation_index().unwrap();
        let ibd = self.chain.is_in_ibd();
        let latest_header = self.chain.get_block_header(&hash).unwrap();
        let latest_work = latest_header.work();
        let latest_block_time = latest_header.time;
        let leaf_count = self.chain.acc().leaves as u32;
        let root_count = self.chain.acc().roots.len() as u32;
        let root_hashes = self
            .chain
            .acc()
            .roots
            .into_iter()
            .map(|r| r.to_string())
            .collect();

        let validated_blocks = self.chain.get_validation_index().unwrap();

        Ok(GetBlockchainInfoRes {
            best_block: hash.to_string(),
            height,
            ibd,
            validated,
            latest_work: latest_work.to_string(),
            latest_block_time,
            leaf_count,
            root_count,
            root_hashes,
            chain: self.network.to_string(),
            difficulty: latest_header.difficulty_float(),
            progress: validated_blocks as f32 / height as f32,
        })
    }

    // getblockcount
    pub(super) fn get_block_count(&self) -> Result<u32, JsonRpcError> {
        Ok(self.chain.get_height().unwrap())
    }

    // getblockfilter
    // getblockfrompeer (just call getblock)

    // getblockhash
    pub(super) fn get_block_hash(&self, height: u32) -> Result<BlockHash, JsonRpcError> {
        self.chain
            .get_block_hash(height)
            .map_err(|_| JsonRpcError::BlockNotFound)
    }

    // getblockheader
    pub(super) fn get_block_header(&self, hash: BlockHash) -> Result<Header, JsonRpcError> {
        self.chain
            .get_block_header(&hash)
            .map_err(|_| JsonRpcError::BlockNotFound)
    }

    // getblockstats
    // getchainstates
    // getchaintips
    // getchaintxstats
    // getdeploymentinfo
    // getdifficulty
    // getmempoolancestors
    // getmempooldescendants
    // getmempoolentry
    // getmempoolinfo
    // getrawmempool

    /// Check if the script is anchor type
    fn is_anchor_type(script: &Script) -> bool {
        script.as_bytes().starts_with(&[0x51, 0x02, 0x4e, 0x73])
    }

    /// Returns a label about the scriptPubKey type
    /// (pubkey, pubkeyhash, multisig, nulldata, scripthash, witness_v0_keyhash, witness_v0_scripthash, witness_v1_taproot, anchor, nonstandard)
    fn get_script_type_label(script: &Script) -> &'static str {
        if script.is_p2pk() {
            return "pubkey";
        }

        if script.is_p2pkh() {
            return "pubkeyhash";
        }

        if script.is_multisig() {
            return "multisig";
        }

        if script.is_op_return() {
            return "nulldata";
        }

        if script.is_p2sh() {
            return "scripthash";
        }

        if script.is_p2wpkh() {
            return "witness_v0_keyhash";
        }

        if script.is_p2wsh() {
            return "witness_v0_scripthash";
        }

        if script.is_p2tr() {
            return "witness_v1_taproot";
        }

        if Self::is_anchor_type(script) {
            return "anchor";
        }

        "nonstandard"
    }

    fn get_script_type_descriptor(script: &Script, address: &Option<Address>) -> String {
        let get_addr_str = || {
            address
                .as_ref()
                .expect("address should be Some")
                .to_string()
        };

        if script.is_p2pk() {
            let addr = get_addr_str();
            return format!("pk({addr}");
        }

        if let Some(addr) = address {
            return format!("addr({addr})");
        }

        if script.is_op_return() {
            let hex = script.to_hex_string();
            return format!("raw({hex})");
        }

        if Self::is_anchor_type(script) {
            let addr = get_addr_str();
            return format!("addr({addr})");
        }

        let hex = script.to_hex_string();
        format!("raw({hex})")
    }

    /// Parses the serialized opcodes in a [ScriptBuf] as numbers and it's hashes.
    /// This differs from `ScriptBuf::to_asm_string` in that, `rust-bitcoin` will
    /// show the the human representation of the opcode. It does not omit the number representations of
    /// `OP_PUSHDATA_<N>` and `OP_PUSHBYTE<N>`. This method do the opposite: it not show the human
    /// representation and omit the last opcodes, so it can be compliant with bitcoin-core.
    /// For reference see <https://en.bitcoin.it/wiki/Script#Opcodes>
    fn to_core_asm_string(script: &ScriptBuf) -> Result<String, JsonRpcError> {
        let mut asm = vec![];
        let bytes = script.as_bytes();
        let mut i = 0usize;

        // little reused helper to hex string
        let to_hex_string = |r: &[u8]| r.iter().map(|b| format!("{b:02x}")).collect::<String>();

        while i < bytes.len() {
            let byte = bytes[i];
            i += 1;

            match byte {
                // OP_0
                0x00 => asm.push(format!("{}", 0)),
                // OP_PUSHDATA_<N>: The next N bytes is data to be pushed onto the stack
                0x01..=0x4b => {
                    let pushed_bytes = byte as usize;
                    let hex = to_hex_string(&bytes[i..i + pushed_bytes]);
                    asm.push(hex);
                    i += pushed_bytes;
                }
                // OP_PUSHBYTE1: the next byte contains the number of bytes to be pushed onto the stack.
                0x4c => {
                    let pushed_bytes = bytes[i] as usize;
                    i += 1;
                    let hex = to_hex_string(&bytes[i..i + pushed_bytes]);
                    asm.push(hex);
                    i += pushed_bytes;
                }
                // OP_PUSHBYTE2: the next two bytes contain the number of bytes to be pushed onto the stack in little endian order.
                0x4d => {
                    let pushed_bytes = u16::from_le_bytes([bytes[i], bytes[i + 1]]) as usize;
                    i += 2;
                    let hex = to_hex_string(&bytes[i..i + pushed_bytes]);
                    asm.push(hex);
                    i += pushed_bytes;
                }
                // OP_PUSHBYTE4: the next four bytes contain the number of bytes to be pushed onto the stack in little endian order.
                0x4e => {
                    let pushed_bytes =
                        u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]])
                            as usize;
                    i += 4;
                    let hex = to_hex_string(&bytes[i..i + pushed_bytes]);
                    asm.push(hex);
                    i += pushed_bytes;
                }
                // OP_1 to OP_16
                0x51..=0x60 => {
                    // 0x50 is OP_RESERVED
                    let reserved = 0x50;
                    asm.push(format!("{}", byte - reserved));
                }
                // Any other opcode that should  be pushed
                another_one => {
                    asm.push(format!("{another_one:02x}"));
                }
            }
        }

        Ok(asm.join(" "))
    }

    /// gettxout: returns details about an unspent transaction output.
    pub(super) fn get_tx_out(
        &self,
        txid: Txid,
        outpoint: u32,
        _include_mempool: bool,
    ) -> Result<Option<GetTxOut>, JsonRpcError> {
        let res = match (
            self.wallet.get_transaction(&txid),
            self.wallet.get_height(&txid),
            self.wallet.get_utxo(&OutPoint {
                txid,
                vout: outpoint,
            }),
        ) {
            (Some(cached_tx), Some(height), Some(txout)) => {
                let is_coinbase = cached_tx.tx.is_coinbase();
                let Ok((bestblock_height, bestblock_hash)) = self.chain.get_best_block() else {
                    return Err(JsonRpcError::BlockNotFound);
                };

                let script = txout.script_pubkey.as_script();
                let network = self.chain.get_params().network;
                let address = Address::from_script(script, network).ok();

                let desc = Self::get_script_type_descriptor(script, &address);
                let checksum_desc = checksum::desc_checksum(&desc)
                    .map(|checksum| format!("{desc}#{checksum}"))
                    .map_err(|_| JsonRpcError::InvalidDescriptor)?;

                let asm = Self::to_core_asm_string(&txout.script_pubkey)?;
                let script_pubkey = ScriptPubkeyDescription {
                    asm,
                    hex: txout.script_pubkey.to_hex_string(),
                    desc: checksum_desc,
                    address: address.as_ref().map(ToString::to_string),
                    type_field: Self::get_script_type_label(script).to_string(),
                };

                Some(GetTxOut {
                    bestblock: bestblock_hash,
                    confirmations: bestblock_height - height + 1,
                    value: txout.value.to_btc(),
                    script_pubkey,
                    coinbase: is_coinbase,
                })
            }
            _ => None,
        };
        Ok(res)
    }

    /// Computes the necessary information for the RPC `gettxoutproof [txids] blockhash (optional)`
    ///
    /// This function has two paths, when blockhash is inserted and when isn't.
    ///
    /// Specifying the blockhash will make this function go after the block and search
    /// for the transactions inside it, building a merkle proof from the block with its
    /// indexes. Not specifying will redirect it to search for the merkle proof on our
    /// watch-only wallet which may not have the transaction cached.
    ///
    /// Not finding one of the specified transactions will raise [`JsonRpcError::TxNotFound`].
    pub(super) async fn get_txout_proof(
        &self,
        tx_ids: &[Txid],
        blockhash: Option<BlockHash>,
    ) -> Result<GetTxOutProof, JsonRpcError> {
        let block = match blockhash {
            Some(blockhash) => self.get_block_inner(blockhash).await?,
            // Using the first Txid to get the block should be fine since they are expected to all
            // live in the same block, otherwise, theres no way they have a common proof.
            None => self.get_block_by_txid(&tx_ids[0])?,
        };

        // Before building the merkle block we try to remove all txids
        // that aren't present in the block we found, meaning that
        // at least one of the txids doesn't belong to the block which
        // in case needs to make the command fails.
        //
        // this makes the use MerkleBlock::from_block_with_predicate useless.
        let targeted_txids: Vec<Txid> = block
            .txdata
            .iter()
            .filter_map(|tx| {
                let txid = tx.compute_txid();
                if tx_ids.contains(&txid) {
                    Some(txid)
                } else {
                    None
                }
            })
            .collect();

        if targeted_txids.len() != tx_ids.len() {
            return Err(JsonRpcError::TxNotFound);
        };

        let merkle_block = MerkleBlock::from_block_with_predicate(&block, |tx| tx_ids.contains(tx));
        let mut bytes: Vec<u8> = Vec::new();
        merkle_block
            .consensus_encode(&mut bytes)
            .expect("This will raise if a writer error happens");
        Ok(GetTxOutProof(bytes))
    }

    // gettxoutsetinfo
    // gettxspendigprevout
    // importmempool
    // loadtxoutset
    // preciousblock
    // pruneblockchain
    // savemempool
    // scanblocks
    // scantxoutset
    // verifychain
    // verifytxoutproof

    // floresta flavored rpcs. These are not part of the bitcoin rpc spec
    // findtxout
    pub(super) async fn find_tx_out(
        &self,
        txid: Txid,
        vout: u32,
        script: ScriptBuf,
        height: u32,
    ) -> Result<Value, JsonRpcError> {
        if let Some(txout) = self.wallet.get_utxo(&OutPoint { txid, vout }) {
            return Ok(serde_json::to_value(txout).unwrap());
        }

        // if we are on IBD, we don't have any filters to find this txout.
        if self.chain.is_in_ibd() {
            return Err(JsonRpcError::InInitialBlockDownload);
        }

        // can't proceed without block filters
        let Some(cfilters) = self.block_filter_storage.as_ref() else {
            return Err(JsonRpcError::NoBlockFilters);
        };

        self.wallet.cache_address(script.clone());
        let filter_key = script.to_bytes();
        let candidates = cfilters
            .match_any(
                vec![filter_key.as_slice()],
                Some(height),
                None,
                self.chain.clone(),
            )
            .map_err(|e| JsonRpcError::Filters(e.to_string()))?;

        for candidate in candidates {
            let candidate = self.node.get_block(candidate).await;
            let candidate = match candidate {
                Err(e) => {
                    return Err(JsonRpcError::Node(e.to_string()));
                }
                Ok(None) => {
                    return Err(JsonRpcError::Node(format!(
                        "BUG: block {candidate:?} is a match in our filters, but we can't get it?"
                    )));
                }
                Ok(Some(candidate)) => candidate,
            };

            let Ok(Some(height)) = self.chain.get_block_height(&candidate.block_hash()) else {
                return Err(JsonRpcError::BlockNotFound);
            };

            self.wallet.block_process(&candidate, height);
        }

        let val = match self.get_tx_out(txid, vout, false)? {
            Some(gettxout) => json!(gettxout),
            None => json!({}),
        };
        Ok(val)
    }

    // getroots
    pub(super) fn get_roots(&self) -> Result<Vec<String>, JsonRpcError> {
        let hashes = self.chain.get_root_hashes();
        Ok(hashes.iter().map(|h| h.to_string()).collect())
    }

    pub(super) fn list_descriptors(&self) -> Result<Vec<String>, JsonRpcError> {
        let descriptors = self
            .wallet
            .get_descriptors()
            .map_err(|e| JsonRpcError::Wallet(e.to_string()))?;
        Ok(descriptors)
    }
}
