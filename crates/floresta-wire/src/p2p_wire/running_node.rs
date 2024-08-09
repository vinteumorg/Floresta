/// After a node catches-up with the network, we can start listening for new blocks, handing any
/// request our user might make and keep our peers alive. This mode requires way less bandwidth and
/// CPU to run, being bound by the number of blocks found in a given period.
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use bitcoin::bip158::BlockFilter;
use bitcoin::p2p::address::AddrV2Message;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::ServiceFlags;
use bitcoin::BlockHash;
use floresta_chain::pruned_utreexo::partial_chain::PartialChainState;
use floresta_chain::pruned_utreexo::BlockchainInterface;
use floresta_chain::pruned_utreexo::UpdatableChainstate;
use floresta_chain::BlockValidationErrors;
use floresta_chain::BlockchainError;
use floresta_chain::UtreexoBlock;
use floresta_common::service_flags;
use floresta_common::service_flags::UTREEXO;
use log::debug;
use log::error;
use log::info;
use log::warn;
use rand::random;
use rustreexo::accumulator::node_hash::BitcoinNodeHash;
use rustreexo::accumulator::pollard::PollardAddition;
use rustreexo::accumulator::stump::Stump;
use tokio::time::timeout;

use super::error::WireError;
use super::peer::PeerMessages;
use crate::address_man::AddressState;
use crate::node::periodic_job;
use crate::node::try_and_log;
use crate::node::ConnectionKind;
use crate::node::InflightRequests;
use crate::node::NodeNotification;
use crate::node::NodeRequest;
use crate::node::UtreexoNode;
use crate::node_context::NodeContext;
use crate::node_context::PeerId;
use crate::node_interface::NodeResponse;
use crate::node_interface::UserRequest;
use crate::p2p_wire::chain_selector::ChainSelector;
use crate::p2p_wire::sync_node::SyncNode;

#[derive(Debug, Clone)]
pub struct RunningNode {
    pub(crate) last_address_rearrange: Instant,
    /// To find peers with a good connectivity, keep track of what peers sent us an inv message
    /// for a block, in the first 5 seconds after we get the first inv message. If we ever decide
    /// to disconnect a peer, we should disconnect the ones that didn't send us an inv message
    /// in a timely manner, but keep the ones that notified us of a new blocks the fastest.
    /// We also keep the moment we received the first inv message
    pub(crate) last_invs: HashMap<BlockHash, (Instant, Vec<PeerId>)>,
    pub(crate) inflight_filters: BTreeMap<u32, BlockFilter>,
}

impl NodeContext for RunningNode {
    const REQUEST_TIMEOUT: u64 = 2 * 60;
    fn get_required_services(&self) -> ServiceFlags {
        ServiceFlags::NETWORK
            | service_flags::UTREEXO.into()
            | ServiceFlags::WITNESS
            | ServiceFlags::COMPACT_FILTERS
    }
}

impl<Chain> UtreexoNode<Chain, RunningNode>
where
    WireError: From<<Chain as BlockchainInterface>::Error>,
    Chain: BlockchainInterface + UpdatableChainstate + Sync + Send + Clone + 'static,
{
    async fn send_addresses(&mut self) -> Result<(), WireError> {
        let addresses = self
            .address_man
            .get_addresses_to_send()
            .into_iter()
            .map(|(addr, time, services, port)| AddrV2Message {
                services,
                addr,
                port,
                time: time as u32,
            })
            .collect();

        self.send_to_random_peer(NodeRequest::SendAddresses(addresses), ServiceFlags::NONE)
            .await?;
        Ok(())
    }

    async fn check_for_timeout(&mut self) -> Result<(), WireError> {
        let timed_out = self
            .common
            .inflight
            .iter()
            .filter(|(_, (_, instant))| {
                instant.elapsed().as_secs() > ChainSelector::REQUEST_TIMEOUT
            })
            .map(|(req, (_, _))| req.clone())
            .collect::<Vec<_>>();

        for request in timed_out {
            let Some((peer, _)) = self.inflight.remove(&request) else {
                warn!(
                    "POSSIBLE BUG: Request {:?} timed out, but it wasn't in the inflight list",
                    request
                );
                continue;
            };

            if !matches!(request, InflightRequests::Connect(_)) {
                // Punishing this peer for taking too long to respond
                self.increase_banscore(peer, 2).await?;
            }

            match request {
                InflightRequests::UtreexoState(_) => {}
                InflightRequests::Blocks(block) => {
                    if !self.has_utreexo_peers() {
                        continue;
                    }
                    let peer = self
                        .send_to_random_peer(
                            NodeRequest::GetBlock((vec![block], true)),
                            service_flags::UTREEXO.into(),
                        )
                        .await?;
                    self.inflight
                        .insert(InflightRequests::Blocks(block), (peer, Instant::now()));
                }
                InflightRequests::Headers => {
                    let peer = self
                        .send_to_random_peer(NodeRequest::GetAddresses, ServiceFlags::NONE)
                        .await?;
                    self.last_headers_request = Instant::now();
                    self.inflight
                        .insert(InflightRequests::Headers, (peer, Instant::now()));
                }
                InflightRequests::UserRequest(req) => {
                    self.user_requests.send_answer(req, None);
                }
                InflightRequests::Connect(peer) => {
                    self.peers.remove(&peer);
                }
                InflightRequests::GetFilters => {
                    if let Some(ref block_filters) = self.block_filters {
                        let last_success = block_filters.get_height()? + 1;
                        self.last_filter = self.chain.get_block_hash(last_success)?;
                        self.download_filters().await?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Every time we restart the node, we'll be a few blocks behind the tip. This function
    /// will start a sync node that will request, download and validate all blocks from the
    /// last validation index to the tip. This function will block until the sync node is
    /// finished.
    ///
    /// On the first startup, if we use either assumeutreexo or pow fraud proofs, this function
    /// will only download the blocks that are after the one that got assumed. So, for PoW fraud
    /// proofs, this means the last 100 blocks, and for assumeutreexo, this means however many
    /// blocks from the hard-coded value in the config file.
    pub async fn catch_up(&self) -> Result<(), WireError> {
        let sync = UtreexoNode::<Chain, SyncNode>::new(
            self.config.clone(),
            self.chain.clone(),
            self.mempool.clone(),
            None,
            self.kill_signal.clone(),
        )?;

        sync.run(|_| {}).await;

        Ok(())
    }

    /// This function is called periodically to check if we have:
    /// - 10 connections
    /// - At least one utreexo peer
    /// - At least one compact filters peer
    ///
    /// If we are missing the speciall peers but have 10 connections, we should disconnect one
    /// random peer and try to connect to a utreexo and a compact filters peer.
    async fn check_connections(&mut self) -> Result<(), WireError> {
        // We're always looking for a peer with the following services
        let base_services: ServiceFlags = ServiceFlags::NETWORK | ServiceFlags::WITNESS;

        // if we have 10 connections, but not a single utreexo or CBF one, disconnect one random
        // peer and create a utreexo and CBS connection
        if !self.has_utreexo_peers() {
            if self.peer_ids.len() == 10 {
                let peer = random::<usize>() % self.peer_ids.len();
                let peer = self
                    .peer_ids
                    .get(peer)
                    .expect("we've modulo before, we should have it");
                self.send_to_peer(*peer, NodeRequest::Shutdown).await?;
            }

            self.create_connection(ConnectionKind::Regular(base_services | UTREEXO.into()))
                .await;
        }

        if self.block_filters.is_none() {
            return Ok(());
        }

        if !self.has_compact_filters_peer() {
            if self.peer_ids.len() == 10 {
                let peer = random::<usize>() % self.peer_ids.len();
                let peer = self
                    .peer_ids
                    .get(peer)
                    .expect("we've modulo before, we should have it");
                self.send_to_peer(*peer, NodeRequest::Shutdown).await?;
            }

            self.create_connection(ConnectionKind::Regular(
                base_services | ServiceFlags::COMPACT_FILTERS,
            ))
            .await;
        }

        if self.peers.len() < 10 {
            self.create_connection(ConnectionKind::Regular(base_services))
                .await;
        }

        Ok(())
    }

    /// If either PoW fraud proofs or assumeutreexo are enabled, we will "skip" IBD for all
    /// historical blocks. This allow us to start the node faster, making it usable in a few
    /// minutes. If you still want to validate all blocks, you can enable the backfill option.
    ///
    /// This function will spawn a background task that will download and validate all blocks
    /// that got assumed. After completion, the task will shutdown and the node will continue
    /// running normally. If we ever assume an invalid chain, the node will [halt and catch fire].
    ///
    /// [halt and catch fire]: https://en.wikipedia.org/wiki/Halt_and_Catch_Fire_(computing)
    pub fn backfill(&self, done_flag: std::sync::mpsc::Sender<()>) -> Result<bool, WireError> {
        // try finding the last state of the sync node
        let state = std::fs::read(self.config.datadir.clone() + "/.sync_node_state");
        // try to recover from the disk state, if it exists. Otherwise, start from genesis
        let (chain, end) = match state {
            Ok(state) => {
                // if this file is empty, this means we've finished backfilling
                if state.is_empty() {
                    return Ok(false);
                }

                let acc = Stump::deserialize(&state[..(state.len() - 8)]).unwrap();
                let tip = u32::from_le_bytes(
                    state[(state.len() - 8)..(state.len() - 4)]
                        .try_into()
                        .unwrap(),
                );

                let end = u32::from_le_bytes(state[(state.len() - 4)..].try_into().unwrap());
                info!(
                    "Recovering backfill node from state tip={}, end={}",
                    tip, end
                );
                (
                    self.chain
                        .get_partial_chain(tip, end, acc)
                        .expect("Failed to get partial chain"),
                    end,
                )
            }
            Err(_) => {
                // if the file doesn't exist or got corrupted, start from genesis
                let end = self
                    .chain
                    .get_validation_index()
                    .expect("can get the validation index");
                (
                    self.chain
                        .get_partial_chain(0, end, Stump::default())
                        .unwrap(),
                    end,
                )
            }
        };

        let backfill = UtreexoNode::<PartialChainState, SyncNode>::new(
            self.config.clone(),
            chain,
            self.mempool.clone(),
            None,
            self.kill_signal.clone(),
        )
        .unwrap();

        let datadir = self.config.datadir.clone();
        let outer_chain = self.chain.clone();

        let fut = UtreexoNode::<PartialChainState, SyncNode>::run(
            backfill,
            move |chain: &PartialChainState| {
                if chain.has_invalid_blocks() {
                    panic!("We assumed a chain with invalid blocks, something went really wrong");
                }

                done_flag.send(()).unwrap();

                // we haven't finished the backfill yet, save the current state for the next run
                if chain.is_in_idb() {
                    let acc = chain.get_acc();
                    let tip = chain.get_height().unwrap();
                    let mut ser_acc = Vec::new();
                    acc.serialize(&mut ser_acc).unwrap();
                    ser_acc.extend_from_slice(&tip.to_le_bytes());
                    ser_acc.extend_from_slice(&end.to_le_bytes());
                    std::fs::write(datadir + "/.sync_node_state", ser_acc)
                        .expect("Failed to write sync node state");
                    return;
                }

                // empty the file if we're done
                std::fs::write(datadir + "/.sync_node_state", Vec::new())
                    .expect("Failed to write sync node state");

                for block in chain.list_valid_blocks() {
                    outer_chain
                        .mark_block_as_valid(block.block_hash())
                        .expect("Failed to mark block as valid");
                }

                info!("Backfilling task shutting down...");
            },
        );

        tokio::task::spawn(fut);
        Ok(true)
    }

    pub async fn run(mut self, stop_signal: futures::channel::oneshot::Sender<()>) {
        try_and_log!(self.init_peers().await);

        // Use this node state to Initial Block download
        let mut ibd = UtreexoNode {
            common: self.common,
            context: ChainSelector::default(),
        };

        try_and_log!(UtreexoNode::<Chain, ChainSelector>::run(&mut ibd).await);

        self = UtreexoNode {
            common: ibd.common,
            context: self.context,
        };

        if *self.kill_signal.read().await {
            self.shutdown().await;
            try_and_log!(stop_signal.send(()));
            return;
        }

        // download blocks from the network before our validation index, probably because we've
        // assumed it somehow.
        let (sender, recv) = std::sync::mpsc::channel();
        let is_backfilling = match self.config.backfill {
            true => {
                info!("Starting backfill task...");
                self.backfill(sender)
                    .expect("Failed to spawn backfill thread")
            }
            false => false,
        };

        // Catch up with the network, donloading blocks from our last validation index onwnwards
        info!("Catching up with the network...");
        try_and_log!(self.catch_up().await);

        if *self.kill_signal.read().await {
            self.shutdown().await;
            stop_signal.send(()).unwrap();
            return;
        }

        self.last_block_request = self.chain.get_validation_index().unwrap_or(0);
        if let Some(ref cfilters) = self.block_filters {
            self.last_filter = self
                .chain
                .get_block_hash(cfilters.get_height().unwrap_or(1))
                .unwrap();
        }

        self.last_block_request = self.chain.get_validation_index().unwrap_or(0);
        if let Some(ref cfilters) = self.block_filters {
            self.last_filter = self
                .chain
                .get_block_hash(cfilters.get_height().unwrap_or(1))
                .unwrap();
        }

        info!("starting running node...");
        loop {
            if *self.kill_signal.read().await {
                break;
            }

            while let Ok(Some(notification)) =
                timeout(Duration::from_millis(100), self.node_rx.recv()).await
            {
                try_and_log!(self.handle_notification(notification).await);
            }

            // Jobs that don't need a connected peer

            // Save our peers db
            periodic_job!(
                self.save_peers(),
                self.last_peer_db_dump,
                PEER_DB_DUMP_INTERVAL,
                RunningNode
            );

            // Rework our address database
            periodic_job!(
                self.address_man.rearrange_buckets(),
                self.context.last_address_rearrange,
                ADDRESS_REARRANGE_INTERVAL,
                RunningNode,
                true
            );

            // Perhaps we need more connections
            periodic_job!(
                self.check_connections().await,
                self.last_connection,
                TRY_NEW_CONNECTION,
                RunningNode
            );

            // Requests using the node handle
            try_and_log!(self.handle_user_request().await);

            // Check if some of our peers have timed out a request
            try_and_log!(self.check_for_timeout().await);

            // Open new feeler connection periodically
            periodic_job!(
                self.open_feeler_connection().await,
                self.last_feeler,
                FEELER_INTERVAL,
                RunningNode
            );

            // Those jobs bellow needs a connected peer to work
            if self.peer_ids.is_empty() {
                continue;
            }

            // Ask our peers for new addresses
            periodic_job!(
                self.ask_for_addresses().await,
                self.last_get_address_request,
                ASK_FOR_PEERS_INTERVAL,
                RunningNode
            );
            // Try broadcast transactions
            periodic_job!(
                self.handle_broadcast().await,
                self.last_broadcast,
                BROADCAST_DELAY,
                RunningNode
            );
            // Send our addresses to our peers
            periodic_job!(
                self.send_addresses().await,
                self.last_send_addresses,
                SEND_ADDRESSES_INTERVAL,
                RunningNode
            );

            // Check whether we are in a stale tip
            periodic_job!(
                self.check_for_stale_tip().await,
                self.last_tip_update,
                ASSUME_STALE,
                RunningNode
            );
            try_and_log!(self.download_filters().await);

            // requests that need a utreexo peer
            if !self.has_utreexo_peers() {
                continue;
            }

            // Check if we haven't missed any block
            if self.inflight.len() < 10 {
                try_and_log!(self.ask_missed_block().await);
            }
        }

        // ignore the error here because if the backfill task already
        // finished, this channel will be closed
        if is_backfilling {
            let _ = recv.recv();
        }

        self.shutdown().await;
        stop_signal.send(()).unwrap();
    }

    async fn download_filters(&mut self) -> Result<(), WireError> {
        if self.inflight.contains_key(&InflightRequests::GetFilters) {
            return Ok(());
        }

        if !self.has_compact_filters_peer() {
            return Ok(());
        }

        let Some(ref filters) = self.block_filters else {
            return Ok(());
        };

        let mut height = filters.get_height()?;
        let best_height = self.chain.get_height()?;

        if height == 0 {
            let user_height = self.config.filter_start_height.unwrap_or(1);

            height = if user_height < 0 {
                best_height.saturating_sub(user_height.unsigned_abs())
            } else {
                user_height as u32
            };

            height = height.saturating_sub(1);
            filters.save_height(height)?;
        }

        if height >= best_height {
            return Ok(());
        }

        info!("Downloading filters from height {}", filters.get_height()?);
        let stop = if height + 500 > best_height {
            best_height
        } else {
            height + 500
        };

        let stop_hash = self.chain.get_block_hash(stop)?;
        self.last_filter = stop_hash;

        let peer = self
            .send_to_random_peer(
                NodeRequest::GetFilter((stop_hash, height + 1)),
                ServiceFlags::COMPACT_FILTERS,
            )
            .await?;

        self.inflight
            .insert(InflightRequests::GetFilters, (peer, Instant::now()));

        Ok(())
    }

    async fn ask_missed_block(&mut self) -> Result<(), WireError> {
        let tip = self.chain.get_height().unwrap();
        let next = self.chain.get_validation_index().unwrap();
        if tip == next {
            return Ok(());
        }

        let mut blocks = Vec::new();
        for i in (next + 1)..=tip {
            let hash = self.chain.get_block_hash(i)?;
            // already requested
            if self.inflight.contains_key(&InflightRequests::Blocks(hash)) {
                continue;
            }

            if blocks.len() >= RunningNode::MAX_INFLIGHT_REQUESTS {
                break;
            }

            // already downloaded
            if self.blocks.contains_key(&hash) {
                continue;
            }

            blocks.push(hash);
        }

        if blocks.is_empty() {
            return Ok(());
        }

        self.request_blocks(blocks).await?;
        Ok(())
    }

    /// If we think our tip is stale, we may disconnect one peer and try to get a new one.
    /// In this process, if the extra peer gives us a new block, we should drop one of our
    /// already connected peers to keep the number of connections stable. This function
    /// decides which peer to drop based on whether they've timely inv-ed us about the last
    /// 6 blocks.
    fn get_peer_score(&self, peer: PeerId) -> u32 {
        let mut score = 0;
        for block in self.context.last_invs.keys() {
            if self.context.last_invs[block].1.contains(&peer) {
                score += 1;
            }
        }

        score
    }

    /// This function checks how many time has passed since our last tip update, if it's
    /// been more than 15 minutes, try to update it.
    async fn check_for_stale_tip(&mut self) -> Result<(), WireError> {
        warn!("Potential stale tip detected, trying extra peers");

        // this catches an edge-case where all our utreexo peers are gone, and the GetData
        // times-out. That yields an error, but doesn't ask the block again. Our last_block_request
        // will be pointing to a block that will never arrive, so we basically deadlock.
        self.last_block_request = self.chain.get_validation_index().unwrap();
        // update this or we'll get this warning every second after 15 minutes without a block,
        // until we get a new block.
        self.last_tip_update = Instant::now();
        self.create_connection(ConnectionKind::Extra).await;

        self.send_to_random_peer(
            NodeRequest::GetHeaders(self.chain.get_block_locator().unwrap()),
            ServiceFlags::NONE,
        )
        .await?;
        Ok(())
    }

    async fn handle_new_block(&mut self, block: BlockHash, peer: u32) -> Result<(), WireError> {
        if self.inflight.contains_key(&InflightRequests::Headers) {
            return Ok(());
        }

        if self.chain.get_block_header(&block).is_ok() {
            return Ok(());
        }

        let locator = self.chain.get_block_locator().unwrap();
        self.send_to_peer(peer, NodeRequest::GetHeaders(locator))
            .await?;

        self.inflight
            .insert(InflightRequests::Headers, (peer, Instant::now()));

        Ok(())
    }

    /// This function is called every time we get a Block message from a peer.
    /// This block may be a rescan block, a user request or a new block that we
    /// need to process.
    async fn handle_block_data(&mut self, block: UtreexoBlock, peer: u32) -> Result<(), WireError> {
        let Some(block) = self.check_is_user_block_and_reply(block).await? else {
            return Ok(());
        };

        // If none of the above, it means that this block is a new block that we need to
        // process.

        // Check if we actually requested this block. If a peer sends a block we didn't
        // request, we should disconnect it.
        if self
            .inflight
            .remove(&InflightRequests::Blocks(block.block.block_hash()))
            .is_none()
        {
            // We didn't request this block, so we should disconnect the peer.
            error!(
                "Peer {peer} sent us block {} which we didn't request",
                block.block.block_hash()
            );
            self.increase_banscore(peer, 5).await?;
            return Ok(());
        }

        let validation_index = self.chain.get_validation_index()?;
        let mut next_block = self.chain.get_block_hash(validation_index + 1)?;

        debug!(
            "Block {} received, waiting for block {}",
            block.block.block_hash(),
            next_block
        );

        self.blocks.insert(block.block.block_hash(), (peer, block));
        while let Some((peer, block)) = self.blocks.remove(&next_block) {
            let start = Instant::now();

            debug!("processing block {}", block.block.block_hash(),);
            let Some(udata) = &block.udata else {
                warn!("peer {peer} sent us a block without udata");
                self.increase_banscore(peer, 5).await?;
                self.send_to_random_peer(
                    NodeRequest::GetBlock((vec![block.block.block_hash()], true)),
                    service_flags::UTREEXO.into(),
                )
                .await?;
                return Ok(());
            };

            let (proof, del_hashes, inputs) =
                floresta_chain::proof_util::process_proof(udata, &block.block.txdata, &self.chain)?;

            if let Err(e) =
                self.chain
                    .connect_block(&block.block, proof.clone(), inputs, del_hashes.clone())
            {
                error!("Invalid block received by peer {} reason: {:?}", peer, e);
                if let BlockchainError::BlockValidation(e) = e {
                    // Because the proof isn't committed to the block, we can't invalidate
                    // it if the proof is invalid. Any other error should cause the block
                    // to be invalidated.
                    match e {
                        BlockValidationErrors::InvalidCoinbase(_)
                        | BlockValidationErrors::UtxoNotFound(_)
                        | BlockValidationErrors::ScriptValidationError(_)
                        | BlockValidationErrors::InvalidOutput
                        | BlockValidationErrors::ScriptError
                        | BlockValidationErrors::BlockTooBig
                        | BlockValidationErrors::NotEnoughPow
                        | BlockValidationErrors::TooManyCoins
                        | BlockValidationErrors::BadMerkleRoot
                        | BlockValidationErrors::BadWitnessCommitment
                        | BlockValidationErrors::NotEnoughMoney
                        | BlockValidationErrors::FirstTxIsNotCoinbase
                        | BlockValidationErrors::BadCoinbaseOutValue
                        | BlockValidationErrors::EmptyBlock
                        | BlockValidationErrors::BlockExtendsAnOrphanChain
                        | BlockValidationErrors::BadBip34
                        | BlockValidationErrors::CoinbaseNotMatured => {
                            self.send_to_peer(peer, NodeRequest::Shutdown).await?;
                            try_and_log!(self.chain.invalidate_block(block.block.block_hash()));
                        }
                        BlockValidationErrors::InvalidProof => {}
                    }
                }

                // Disconnect the peer and ban it.
                if let Some(peer) = self.peers.get(&peer).cloned() {
                    self.address_man.update_set_state(
                        peer.address_id as usize,
                        AddressState::Banned(RunningNode::BAN_TIME),
                    );
                }
                self.send_to_peer(peer, NodeRequest::Shutdown).await?;
                return Err(WireError::PeerMisbehaving);
            }

            if !self.chain.is_in_idb() {
                // Convert to BitcoinNodeHashes, from rustreexo
                let del_hashes: Vec<_> = del_hashes.into_iter().map(Into::into).collect();

                let block_height = self
                    .chain
                    .get_block_height(&block.block.block_hash())?
                    .unwrap();

                let block_hash = block.block.block_hash();

                let adds = floresta_chain::proof_util::get_block_adds(
                    &block.block,
                    block_height,
                    block_hash,
                );

                let adds: Vec<PollardAddition<BitcoinNodeHash>> = adds
                    .into_iter()
                    .map(|add| PollardAddition {
                        remember: true,
                        hash: add,
                    })
                    .collect();

                let mempool_delta = self
                    .mempool
                    .lock()
                    .await
                    .consume_block(&block.block, proof, &adds, &del_hashes, block_height, false)
                    .unwrap_or(Vec::new());

                debug!(
                    "Block {} accepted, confirmed transactions: {:?}",
                    block.block.block_hash(),
                    mempool_delta
                );
            }

            let next = self.chain.get_validation_index()? + 1;

            match self.chain.get_block_hash(next) {
                Ok(_next_block) => next_block = _next_block,
                Err(_) => break,
            }

            debug!("accepted block {}", block.block.block_hash());

            let elapsed = start.elapsed().as_secs();
            self.block_sync_avg.add(elapsed);

            #[cfg(feature = "metrics")]
            {
                use metrics::get_metrics;

                let avg = self.block_sync_avg.value();
                let metrics = get_metrics();
                metrics.avg_block_processing_time.set(avg);
            }
        }

        // Remove confirmed transactions from the mempool.
        self.last_tip_update = Instant::now();

        Ok(())
    }

    pub(crate) async fn handle_notification(
        &mut self,
        notification: NodeNotification,
    ) -> Result<(), WireError> {
        #[cfg(feature = "metrics")]
        self.register_message_time(&notification);

        match notification {
            NodeNotification::FromPeer(peer, message) => match message {
                PeerMessages::NewBlock(block) => {
                    debug!("We got an inv with block {block} requesting it");
                    self.context
                        .last_invs
                        .entry(block)
                        .and_modify(|(when, peers)| {
                            if peers.contains(&peer) {
                                return;
                            }
                            // if it's been less than 5 seconds since we got the first inv message
                            // for this block, we should mark as this peer sent us in a timely manner
                            if when.elapsed() < Duration::from_secs(5) {
                                peers.push(peer);
                            }
                        })
                        .or_insert_with(|| (Instant::now(), Vec::new()));

                    self.handle_new_block(block, peer).await?;
                }

                PeerMessages::Block(block) => {
                    debug!(
                        "Got data for block {} from peer {peer}",
                        block.block.block_hash()
                    );

                    self.handle_block_data(block, peer).await?;
                }

                PeerMessages::Headers(headers) => {
                    debug!(
                        "Got headers from peer {peer} with {} headers",
                        headers.len()
                    );
                    self.inflight.remove(&InflightRequests::Headers);

                    let peer_info = self.peers.get(&peer).cloned().expect("Peer not found");
                    let is_extra = matches!(peer_info.kind, ConnectionKind::Extra);

                    if is_extra {
                        // if this is an extra peer, and the headers message is empty, disconnect it
                        if headers.is_empty() {
                            self.increase_banscore(peer, 5).await?;
                            return Ok(());
                        }

                        // this peer got us a new block, we should disconnect one of our regular peers
                        // and keep this one.
                        let peer_to_disconnect = self
                            .peers
                            .iter()
                            .filter(|(_, info)| matches!(info.kind, ConnectionKind::Regular(_)))
                            .min_by_key(|(k, _)| self.get_peer_score(**k))
                            .map(|(peer, _)| *peer);

                        // disconnect the peer with the lowest score
                        if let Some(peer) = peer_to_disconnect {
                            self.send_to_peer(peer, NodeRequest::Shutdown).await?;
                        }

                        // update the peer info
                        self.peers.entry(peer).and_modify(|info| {
                            info.kind = ConnectionKind::Regular(peer_info.services);
                        });
                    }

                    for header in headers.iter() {
                        self.chain.accept_header(*header)?;
                    }

                    if self.chain.is_in_idb() {
                        let blocks = headers.iter().map(|header| header.block_hash()).collect();
                        self.request_blocks(blocks).await?;
                    }
                }

                PeerMessages::Ready(version) => {
                    debug!(
                        "handshake with peer={peer} succeeded feeler={:?}",
                        version.kind
                    );
                    self.handle_peer_ready(peer, &version).await?;
                }

                PeerMessages::Disconnected(idx) => {
                    self.handle_disconnection(peer, idx).await?;
                }

                PeerMessages::Addr(addresses) => {
                    debug!("Got {} addresses from peer {}", addresses.len(), peer);
                    let addresses: Vec<_> = addresses.into_iter().map(|addr| addr.into()).collect();

                    self.address_man.push_addresses(&addresses);
                }

                PeerMessages::BlockFilter((hash, filter)) => {
                    debug!("Got a block filter for block {hash} from peer {peer}");

                    if let Some(filters) = self.common.block_filters.as_ref() {
                        let mut current_height = filters.get_height()?;
                        let Some(this_height) = self.chain.get_block_height(&hash)? else {
                            warn!("Filter for block {} received, but we don't have it", hash);
                            return Ok(());
                        };

                        if current_height + 1 != this_height {
                            self.context.inflight_filters.insert(this_height, filter);
                            return Ok(());
                        }

                        filters.push_filter(filter, current_height + 1)?;
                        current_height += 1;

                        while let Some(filter) =
                            self.context.inflight_filters.remove(&(current_height))
                        {
                            filters.push_filter(filter, current_height)?;
                            current_height += 1;
                        }

                        filters.save_height(current_height)?;
                        let current_hash = self.chain.get_block_hash(current_height)?;
                        if self.last_filter == current_hash
                            && self.context.inflight_filters.is_empty()
                        {
                            self.inflight.remove(&InflightRequests::GetFilters);
                            self.download_filters().await?;
                        }
                    }
                }

                PeerMessages::NotFound(inv) => match inv {
                    Inventory::Error => {}
                    Inventory::Block(block)
                    | Inventory::WitnessBlock(block)
                    | Inventory::CompactBlock(block) => {
                        self.user_requests
                            .send_answer(UserRequest::Block(block), None);
                    }

                    Inventory::WitnessTransaction(tx) | Inventory::Transaction(tx) => {
                        self.user_requests
                            .send_answer(UserRequest::MempoolTransaction(tx), None);
                    }
                    _ => {}
                },

                PeerMessages::Transaction(tx) => {
                    debug!("saw a mempool transaction with txid={}", tx.compute_txid());
                    self.user_requests.send_answer(
                        UserRequest::MempoolTransaction(tx.compute_txid()),
                        Some(NodeResponse::MempoolTransaction(tx)),
                    );
                }

                PeerMessages::UtreexoState(_) => {
                    warn!(
                        "Utreexo state received from peer {}, but we didn't ask",
                        peer
                    );
                    self.increase_banscore(peer, 5).await?;
                }
            },
        }
        Ok(())
    }
}
