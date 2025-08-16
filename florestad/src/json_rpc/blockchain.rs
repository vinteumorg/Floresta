use std::ops::Div;

use bitcoin::block::Header;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::consensus::Encodable;
use bitcoin::constants::genesis_block;
use bitcoin::hex::DisplayHex;
use bitcoin::params::Params;
use bitcoin::Block;
use bitcoin::BlockHash;
use bitcoin::MerkleBlock;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Txid;
use serde_json::json;
use serde_json::Value;

use super::res::GetBlockRes;
use super::res::GetBlockchainInfoRes;
use super::res::GetTxOutProof;
use super::res::JsonRpcError;
use super::server::RpcChain;
use super::server::RpcImpl;
use crate::json_rpc::res::GetBlockResOne;

impl<Blockchain: RpcChain> RpcImpl<Blockchain> {
    /// Ask the block related to the given hash to the network.
    ///
    /// This function will fail if the given hash doesnt point to a known header.
    async fn get_block_inner(&self, hash: BlockHash) -> Result<Block, JsonRpcError> {
        // This avoid being stalled waiting the network to answer for a blockhash that is invalid and we should atleast have its header on our chain.
        let _ = self
            .chain
            .get_block_header(&hash)
            .map_err(|_| JsonRpcError::BlockNotFound);

        // This function is not expensive as requesting the genesis block directly to the network.
        let genesis = genesis_block(self.network);

        if genesis.block_hash() == hash {
            return Ok(genesis);
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

    /// returns the median time past for the block at the given height.
    pub fn get_mtp_for(&self, height: u32) -> Result<u32, JsonRpcError> {
        if height == 0 {
            return Ok(1231006505);
        }
        let tip = self.get_block_count()?;

        if height > tip {
            return Err(JsonRpcError::InvalidHeight);
        }

        let mut arr = Vec::<u32>::with_capacity(11.min(height as usize));

        for i in height.saturating_sub(11)..height {
            let block_hash = self.get_block_hash(i)?;

            let block = self.get_block_header(block_hash)?;
            arr.push(block.time);
        }

        arr.sort();

        Ok(arr[arr.len().div(2)])
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
        verbosity: Option<u8>,
    ) -> Result<GetBlockRes, JsonRpcError> {
        let verbosity = verbosity.unwrap_or(0);

        // early return to avoid processing data from an invalid request.
        if verbosity > 1 {
            return Err(JsonRpcError::InvalidVerbosityLevel);
        }

        let block = self.get_block_inner(hash).await?;

        // early return for the verbosity level 0.
        if verbosity == 0u8 {
            return Ok(GetBlockRes::Zero(serialize_hex(&block)));
        }

        let tip = self.chain.get_height().map_err(|_| JsonRpcError::Chain)?;
        let height = self
            .chain
            .get_block_height(&hash)
            .map_err(|_| JsonRpcError::Chain)?
            .unwrap();

        let previous_block_hash = match height == 0 {
            true => None,
            false => Some(block.header.prev_blockhash.to_string()),
        };

        let median_time_past = self.get_mtp_for(height)?;

        if verbosity == 1 {
            return Ok(GetBlockRes::One(Box::new(GetBlockResOne {
                bits: block
                    .header
                    .bits
                    .to_consensus()
                    .to_be_bytes()
                    .to_lower_hex_string(),
                chainwork: format!("{:0>64}", block.header.work().to_string()),
                confirmations: (tip - height) + 1,
                difficulty: block.header.difficulty(Params::MAINNET),
                hash: block.header.block_hash().to_string(),
                height,
                merkleroot: block.header.merkle_root.to_string(),
                nonce: block.header.nonce,
                previousblockhash: previous_block_hash,
                size: block.total_size(),
                time: block.header.time,
                tx: block
                    .txdata
                    .iter()
                    .map(|tx| tx.compute_txid().to_string())
                    .collect(),
                version: block.header.version.to_consensus(),
                version_hex: block
                    .header
                    .version
                    .to_consensus()
                    .to_be_bytes()
                    .to_lower_hex_string(),
                weight: block.weight().to_wu() as usize,
                target: block.header.target().to_be_bytes().to_lower_hex_string(),
                mediantime: median_time_past,
                n_tx: block.txdata.len(),
                nextblockhash: self
                    .chain
                    .get_block_hash(height + 1)
                    .ok()
                    .map(|h| h.to_string()),
                strippedsize: block.total_size(),
            })));
        }

        // This is mostly unreachable
        Err(JsonRpcError::InvalidRequest)
    }

    // getblockchaininfo
    pub(super) fn get_blockchain_info(&self) -> Result<GetBlockchainInfoRes, JsonRpcError> {
        let (height, hash) = self.chain.get_best_block().unwrap();
        let validated = self.chain.get_validation_index().unwrap();
        let latest_header = self.chain.get_block_header(&hash).unwrap();
        let latest_work = latest_header.work();
        let latest_block_time = latest_header.time;

        let disk_size = self.chain.disk_size().unwrap();

        Ok(GetBlockchainInfoRes {
            chain: self.network.to_string(),
            blocks: height,
            headers: validated,
            bestblockhash: hash.to_string(),
            bits: serialize_hex(&latest_header.bits),
            target: latest_header.target().to_string(),
            difficulty: latest_header.difficulty(self.network),
            time: latest_block_time,
            mediantime: self.get_mtp_for(height)?,
            verificationprogress: (height as f32).div(validated as f32),
            initialblockdownload: self.chain.is_in_ibd(),
            chainwork: latest_work.to_string(),
            size_on_disk: disk_size,
            pruned: true,
            pruneheight: height,
            automatic_prunning: true,
            prune_target_size: disk_size,
            warnings: vec![],
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
                Some(height as usize),
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

    pub(super) fn list_descriptors(&self) -> Result<Vec<String>, JsonRpcError> {
        let descriptors = self
            .wallet
            .get_descriptors()
            .map_err(|e| JsonRpcError::Wallet(e.to_string()))?;
        Ok(descriptors)
    }
}
