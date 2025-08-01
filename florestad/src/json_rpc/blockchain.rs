use std::ops::AddAssign;

use bitcoin::block::Header;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::consensus::Encodable;
use bitcoin::constants::genesis_block;
use bitcoin::Block;
use bitcoin::BlockHash;
use bitcoin::MerkleBlock;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Txid;
use floresta_common::descriptor_internals::ConcreteDescriptor;
use serde_json::json;
use serde_json::Value;

use super::res::GetBlockResVerbose;
use super::res::GetBlockchainInfoRes;
use super::res::GetTxOutProof;
use super::res::JsonRpcError;
use super::server::RpcChain;
use super::server::RpcImpl;

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

    /// Retrieves the height of the block that was mined in the given(or less) timestamp.
    /// Intended to use for rescan requests that only has timestamp as info.
    ///
    /// This function uses the blockchain principle that a block is mined in around 10 minutes
    /// to fetch a blockheight.
    ///
    /// The main formula to start searching for the block is (timestamp - GENESIS_TIMESTAMP) / 600
    ///
    /// `timestamp` has an alias, 0 will directly refer to 1231006505, the time of the genesis block  
    pub async fn get_block_height_by_timestamp(&self, timestamp: u32) -> Result<u32, JsonRpcError> {
        if timestamp == 0 {
            return Ok(timestamp);
        };

        const TEN_MINUTES: u32 = 600;
        const GENESIS_TIMESTAMP: u32 = 1231006505; // The u32 representation of 03 Jan 2009, 18:15:05. The salvation of human kind.

        if timestamp <= GENESIS_TIMESTAMP {
            return Err(JsonRpcError::InvalidTimestamp);
        }

        let mut height_target = (timestamp - GENESIS_TIMESTAMP) / TEN_MINUTES;

        // Find the first block at or below the target timestamp
        while height_target > 0 {
            let block_hash = match self.chain.get_block_hash(height_target) {
                Ok(hash) => hash,
                Err(_) => {
                    height_target -= 1;
                    continue;
                }
            };

            let block_header = match self.chain.get_block_header(&block_hash) {
                Ok(header) => header,
                Err(_) => {
                    height_target -= 1;
                    continue;
                }
            };

            let diff: i32 = (timestamp - block_header.time) as i32;
            let abs_diff = diff.unsigned_abs();
            if diff.is_negative() {
                // we got a block thats too high
                if abs_diff > TEN_MINUTES {
                    // When theres more than TEN_MINUTES of difference we can use the diff to have
                    // a more precise guess of the block
                    height_target = height_target.saturating_sub(TEN_MINUTES.div_ceil(abs_diff));
                    continue;
                }
            }

            if diff.is_positive() {
                // we got a block thats too high
                if abs_diff > TEN_MINUTES {
                    // When theres more than TEN_MINUTES of difference we can use the diff to have
                    // a more precise guess of the block
                    height_target.add_assign(TEN_MINUTES.div_ceil(abs_diff));
                    continue;
                }
            }
            // at this point the expected diff is less than 10 minutes from the timestamp so we break expecting to find the closes
            // block in a 2 hours spam
            break;
        }

        // This block spam is the amount of blocks we search for around the height we
        // got to find the closest one.
        //
        // the rationale behind 24 is that a block can have a valid timestamp in a 2 hour spam
        // it can be 2 hours in the future and 2 hours in the past and this 4 hour spam should
        // contain around 24 blocks. This is more a stop point in case the given timestamp is
        // not precise and a block doesnt contain the exact timestamp were trying to find.
        const BLOCK_SPAM: u8 = 24;

        let blockhash = self.chain.get_block_hash(height_target).unwrap();

        let mut target_block = self
            .chain
            .get_block_header(&blockhash)
            .map_err(|_| JsonRpcError::BlockNotFound)?;

        let mut perfect_height: Option<u32> =
            (target_block.time == timestamp).then_some(height_target);

        /// Type alias to hold the height and the timestamp, in the accordingly order.
        type Candidate = (u32, u32);

        let mut candidates: Vec<Candidate> = Vec::new();

        for i in 1..(BLOCK_SPAM / 2) {
            if let Some(height) = perfect_height {
                return Ok(height);
            } else {
                let blockhash = self.chain.get_block_hash(height_target - i as u32).unwrap();

                target_block = self
                    .chain
                    .get_block_header(&blockhash)
                    .map_err(|_| JsonRpcError::BlockNotFound)?;

                if target_block.time == timestamp {
                    perfect_height = Some(height_target - i as u32);
                } else {
                    candidates.push((height_target - i as u32, target_block.time));
                }

                let blockhash = self.chain.get_block_hash(height_target + i as u32).unwrap();

                target_block = self
                    .chain
                    .get_block_header(&blockhash)
                    .map_err(|_| JsonRpcError::BlockNotFound)?;

                if target_block.time == timestamp {
                    perfect_height = Some(height_target + i as u32);
                } else {
                    candidates.push((height_target + i as u32, target_block.time));
                }
            }
        }

        let best_height = candidates
            .iter()
            .min_by_key(|(_, time)| time.abs_diff(timestamp))
            .map(|(h, _)| *h)
            .ok_or(JsonRpcError::BlockNotFound)?;

        Ok(best_height)
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

        let block = GetBlockResVerbose {
            bits: serialize_hex(&block.header.bits),
            chainwork: block.header.work().to_string(),
            confirmations: (tip - height) + 1,
            difficulty: block.header.difficulty(self.chain.get_params()),
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
            version_hex: serialize_hex(&block.header.version),
            weight: block.weight().to_wu() as usize,
            mediantime: median_time_past,
            n_tx: block.txdata.len(),
            nextblockhash: self
                .chain
                .get_block_hash(height + 1)
                .ok()
                .map(|h| h.to_string()),
            strippedsize: block.total_size(),
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
            difficulty: latest_header.difficulty(self.chain.get_params()) as u64,
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
    // gettxout
    pub(super) fn get_tx_out(&self, txid: Txid, outpoint: u32) -> Result<Value, JsonRpcError> {
        let utxo = self.wallet.get_utxo(&OutPoint {
            txid,
            vout: outpoint,
        });

        let res = match utxo {
            Some(utxo) => ::serde_json::to_value(utxo),
            None => Ok(json!({})),
        };

        res.map_err(|_e| JsonRpcError::Encode)
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

        self.get_tx_out(txid, vout)
    }

    // getroots
    pub(super) fn get_roots(&self) -> Result<Vec<String>, JsonRpcError> {
        let hashes = self.chain.get_root_hashes();
        Ok(hashes.iter().map(|h| h.to_string()).collect())
    }

    pub(super) fn list_descriptors(&self) -> Result<Vec<ConcreteDescriptor>, JsonRpcError> {
        let descriptors = self
            .wallet
            .get_descriptors()
            .map_err(|e| JsonRpcError::Wallet(e.to_string()))?;
        Ok(descriptors)
    }
}
