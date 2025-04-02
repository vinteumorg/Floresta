use bitcoin::block::Header;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::constants::genesis_block;
use bitcoin::Block;
use bitcoin::BlockHash;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Txid;
use floresta_chain::pruned_utreexo::BlockchainInterface;
use floresta_chain::pruned_utreexo::UpdatableChainstate;
use serde_json::json;
use serde_json::Value;

use super::res::Error as RpcError;
use super::res::Error;
use super::res::GetBlockResVerbose;
use super::res::GetBlockchainInfoRes;
use super::server::RpcImpl;

impl RpcImpl {
    async fn get_block_inner(&self, hash: BlockHash) -> Result<Block, RpcError> {
        let is_genesis = self.chain.get_block_hash(0).unwrap().eq(&hash);

        if is_genesis {
            return Ok(genesis_block(self.network));
        }

        self.node
            .get_block(hash)
            .await
            .map_err(|e| RpcError::Node(e.to_string()))
            .and_then(|block| block.ok_or(RpcError::BlockNotFound))
    }
}

// blockchain rpcs
impl RpcImpl {
    // dumputxoutset

    // getbestblockhash
    pub(super) fn get_best_block_hash(&self) -> Result<BlockHash, RpcError> {
        Ok(self.chain.get_best_block().unwrap().1)
    }

    // getblock
    pub(super) async fn get_block(&self, hash: BlockHash) -> Result<GetBlockResVerbose, RpcError> {
        let block = self.get_block_inner(hash).await?;
        let tip = self.chain.get_height().map_err(|_| RpcError::Chain)?;
        let height = self
            .chain
            .get_block_height(&hash)
            .map_err(|_| RpcError::Chain)?
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

    pub(super) async fn get_block_serialized(&self, hash: BlockHash) -> Result<String, RpcError> {
        let block = self.get_block_inner(hash).await?;
        Ok(serialize_hex(&block))
    }

    // getblockchaininfo
    pub(super) fn get_blockchain_info(&self) -> Result<GetBlockchainInfoRes, RpcError> {
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
    pub(super) fn get_block_count(&self) -> Result<u32, RpcError> {
        Ok(self.chain.get_height().unwrap())
    }

    // getblockfilter
    // getblockfrompeer (just call getblock)

    // getblockhash
    pub(super) fn get_block_hash(&self, height: u32) -> Result<BlockHash, RpcError> {
        self.chain
            .get_block_hash(height)
            .map_err(|_| RpcError::BlockNotFound)
    }

    // getblockheader
    pub(super) fn get_block_header(&self, hash: BlockHash) -> Result<Header, RpcError> {
        self.chain
            .get_block_header(&hash)
            .map_err(|_| RpcError::BlockNotFound)
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
    pub(super) fn get_tx_out(&self, txid: Txid, outpoint: u32) -> Result<Value, RpcError> {
        let utxo = self.wallet.get_utxo(&OutPoint {
            txid,
            vout: outpoint,
        });

        let res = match utxo {
            Some(utxo) => ::serde_json::to_value(utxo),
            None => Ok(json!({})),
        };

        res.map_err(|_e| RpcError::Encode)
    }

    // gettxoutproof
    pub(super) fn get_tx_proof(&self, tx_id: Txid) -> Result<Vec<String>, RpcError> {
        Ok(self
            .wallet
            .get_merkle_proof(&tx_id)
            .ok_or(RpcError::TxNotFound)?
            .0)
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
    ) -> Result<Value, RpcError> {
        if let Some(txout) = self.wallet.get_utxo(&OutPoint { txid, vout }) {
            return Ok(serde_json::to_value(txout).unwrap());
        }

        // if we are on IBD, we don't have any filters to find this txout.
        if self.chain.is_in_ibd() {
            return Err(RpcError::InInitialBlockDownload);
        }

        // can't proceed without block filters
        let Some(cfilters) = self.block_filter_storage.as_ref() else {
            return Err(RpcError::NoBlockFilters);
        };

        self.wallet.cache_address(script.clone());
        let filter_key = script.to_bytes();
        let candidates = cfilters
            .match_any(
                vec![filter_key.as_slice()],
                Some(height as usize),
                self.chain.clone(),
            )
            .map_err(|e| RpcError::Filters(e.to_string()))?;

        for candidate in candidates {
            let candidate = self.node.get_block(candidate).await;
            let candidate = match candidate {
                Err(e) => {
                    return Err(RpcError::Node(e.to_string()));
                }
                Ok(None) => {
                    return Err(RpcError::Node(format!(
                        "BUG: block {candidate:?} is a match in our filters, but we can't get it?"
                    )));
                }
                Ok(Some(candidate)) => candidate,
            };

            let Ok(Some(height)) = self.chain.get_block_height(&candidate.block_hash()) else {
                return Err(RpcError::BlockNotFound);
            };

            self.wallet.block_process(&candidate, height);
        }

        self.get_tx_out(txid, vout)
    }

    // getroots
    pub(super) fn get_roots(&self) -> Result<Vec<String>, RpcError> {
        let hashes = self.chain.get_root_hashes();
        Ok(hashes.iter().map(|h| h.to_string()).collect())
    }

    pub(super) fn list_descriptors(&self) -> Result<Vec<String>, Error> {
        let descriptors = self
            .wallet
            .get_descriptors()
            .map_err(|e| Error::Wallet(e.to_string()))?;
        Ok(descriptors)
    }
}
