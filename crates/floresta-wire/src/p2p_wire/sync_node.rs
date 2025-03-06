//! A node that downloads and validates the blockchain.

use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::ServiceFlags;
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
use tokio::sync::RwLock;
use tokio::time::timeout;

use super::error::WireError;
use super::node::PeerStatus;
use super::node_interface::UserRequest;
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

/// [`SyncNode`] is a node that downloads and validates the blockchain.
/// This node implements:
///     - `NodeContext`
///     - `UtreexoNode<SyncNode, Chain>`
///
/// see [node_context](crates/floresta-wire/src/p2p_wire/node_context.rs) and [node.rs](crates/floresta-wire/src/p2p_wire/node.rs) for more information.
#[derive(Clone, Debug, Default)]
pub struct SyncNode {
    last_block_requested: u32,
}

impl NodeContext for SyncNode {
    fn get_required_services(&self) -> bitcoin::p2p::ServiceFlags {
        ServiceFlags::WITNESS | service_flags::UTREEXO.into() | ServiceFlags::NETWORK
    }

    const MAX_OUTGOING_PEERS: usize = 5; // don't need many peers, half the default
    const TRY_NEW_CONNECTION: u64 = 10; // ten seconds
    const REQUEST_TIMEOUT: u64 = 10 * 60; // 10 minutes
    const MAX_INFLIGHT_REQUESTS: usize = 100; // double the default
}

/// Node methods for a [`UtreexoNode`] where its Context is a [`SyncNode`].
/// See [node](crates/floresta-wire/src/p2p_wire/node.rs) for more information.
impl<Chain> UtreexoNode<Chain, SyncNode>
where
    WireError: From<<Chain as BlockchainInterface>::Error>,
    Chain: BlockchainInterface + UpdatableChainstate + 'static,
{
    /// Checks if we have the next 10 missing blocks until the tip, and request missing ones for a peer.
    async fn get_blocks_to_download(&mut self) {
        let mut blocks = Vec::with_capacity(10);
        for _ in 0..10 {
            let next_block = self.context.last_block_requested + 1;
            let next_block = self.chain.get_block_hash(next_block);
            match next_block {
                Ok(next_block) => {
                    blocks.push(next_block);
                    self.context.last_block_requested += 1;
                }
                Err(_) => {
                    break;
                }
            }
        }
        try_and_log!(self.request_blocks(blocks).await);
    }

    /// While in sync phase, we don't want any non-utreexo connections. This function checks
    /// if we have any non-utreexo peers and disconnects them.
    async fn check_connections(&mut self) -> Result<(), WireError> {
        let to_remove = self.peers.iter().filter_map(|(_, peer)| {
            if !peer.services.has(UTREEXO.into()) && peer.state == PeerStatus::Ready {
                return Some(peer);
            }

            None
        });

        for peer in to_remove {
            info!("Disconnecting non-utreexo peer {}", peer.address);
            peer.channel.send(NodeRequest::Shutdown)?;
        }

        self.maybe_open_connection(UTREEXO.into()).await
    }

    /// Starts the sync node by updating the last block requested and starting the main loop.
    /// This loop to the following tasks, in order:
    ///     - Receives messages from our peers through the node_tx channel.
    ///     - Handles the message received.
    ///     - Checks if the kill signal is set, if so, breaks the loop.
    ///     - Checks if the chain is in IBD and disables it if it's not (e.g. if the chain is synced).
    ///     - Checks if our tip is obsolete and requests a new one, creating a new connection.
    ///     - Handles timeouts for inflight requests.
    ///     - If were low on inflights, requests new blocks to validate.
    pub async fn run(&mut self, kill_signal: Arc<RwLock<bool>>, done_cb: impl FnOnce(&Chain)) {
        info!("Starting sync node");
        self.context.last_block_requested = self.chain.get_validation_index().unwrap();

        loop {
            while let Ok(Some(msg)) = timeout(Duration::from_secs(1), self.node_rx.recv()).await {
                try_and_log!(self.handle_message(msg).await);
            }

            if *kill_signal.read().await {
                break;
            }

            if self.chain.get_validation_index().unwrap() == self.chain.get_best_block().unwrap().0
            {
                self.chain.toggle_ibd(false);
                break;
            }

            periodic_job!(
                self.check_connections().await,
                self.last_connection,
                TRY_NEW_CONNECTION,
                SyncNode
            );

            // Open new feeler connection periodically
            periodic_job!(
                self.open_feeler_connection().await,
                self.last_feeler,
                FEELER_INTERVAL,
                SyncNode
            );

            let assume_stale = Instant::now()
                .duration_since(self.common.last_tip_update)
                .as_secs()
                > SyncNode::ASSUME_STALE;

            if assume_stale {
                self.context.last_block_requested = self.chain.get_validation_index().unwrap();
                self.create_connection(ConnectionKind::Extra).await;
                self.last_tip_update = Instant::now();
                continue;
            }

            self.handle_timeout().await;

            if !self.has_utreexo_peers() {
                continue;
            }

            if self.chain.get_validation_index().unwrap() + 10 > self.context.last_block_requested {
                if self.inflight.len() > 10 {
                    continue;
                }
                self.get_blocks_to_download().await;
            }
        }

        done_cb(&self.chain);
    }

    /// Isolate inflights that have timed out and increase the banscore of the peer that sent them and re-request it.
    async fn handle_timeout(&mut self) {
        let to_remove = self
            .common
            .inflight
            .iter()
            .filter(|(_, (_, instant))| instant.elapsed().as_secs() > SyncNode::REQUEST_TIMEOUT)
            .map(|(req, (peer, _))| (req.clone(), *peer))
            .collect::<Vec<_>>();

        for (request, peer) in to_remove {
            match request {
                InflightRequests::Blocks(block) => {
                    self.inflight.remove(&InflightRequests::Blocks(block));

                    try_and_log!(self.increase_banscore(peer, 1).await);
                    try_and_log!(self.request_blocks(vec![block]).await);
                }

                InflightRequests::Connect(addr) => {
                    self.inflight.remove(&InflightRequests::Connect(addr));
                    if let Some(peer) = self.peers.remove(&peer) {
                        let _ = peer.channel.send(NodeRequest::Shutdown);
                    }
                }

                _ => {}
            }
            self.inflight.remove(&request);
            try_and_log!(self.increase_banscore(peer, 1).await);

            if let InflightRequests::UserRequest(req) = request {
                self.user_requests.send_answer(req, None);
                continue;
            }

            let InflightRequests::Blocks(block) = request else {
                continue;
            };

            try_and_log!(self.request_blocks(vec![block]).await);
        }
    }

    /// Process a block received from a peer.
    /// This function removes the received block from the inflight requests and inserts in its own blocks map.
    /// It then processes the block and its proof, and connects it to the chain.
    ///
    /// This function bans the peer if the block is invalid and consider the whole chain as invalid.
    async fn handle_block_data(
        &mut self,
        peer: PeerId,
        block: UtreexoBlock,
    ) -> Result<(), WireError> {
        let Some(block) = self.check_is_user_block_and_reply(block).await? else {
            return Ok(());
        };

        self.inflight
            .remove(&InflightRequests::Blocks(block.block.block_hash()));

        self.blocks.insert(block.block.block_hash(), (peer, block));

        let next_block = self.chain.get_validation_index()? + 1;
        let mut next_block = self.chain.get_block_hash(next_block)?;

        while let Some((peer, block)) = self.blocks.remove(&next_block) {
            let start = Instant::now();
            if block.udata.is_none() {
                error!("Block without proof received from peer {}", peer);
                self.send_to_peer(peer, NodeRequest::Shutdown).await?;
                let next_peer = self
                    .send_to_random_peer(
                        NodeRequest::GetBlock((vec![block.block.block_hash()], true)),
                        service_flags::UTREEXO.into(),
                    )
                    .await?;

                self.inflight.insert(
                    InflightRequests::Blocks(next_block),
                    (next_peer, Instant::now()),
                );
                return Err(WireError::PeerMisbehaving);
            }

            debug!("processing block {}", block.block.block_hash(),);
            let (proof, del_hashes, inputs) = floresta_chain::proof_util::process_proof(
                &block.udata.unwrap(),
                &block.block.txdata,
                &self.chain,
            )?;

            if let Err(e) = self
                .chain
                .connect_block(&block.block, proof, inputs, del_hashes)
            {
                error!(
                    "Invalid block {:?} received by peer {} reason: {:?}",
                    block.block.header, peer, e
                );

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
                        AddressState::Banned(SyncNode::BAN_TIME),
                    );
                }

                self.send_to_peer(peer, NodeRequest::Shutdown).await?;
                return Err(WireError::PeerMisbehaving);
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

        if self.inflight.len() < 4 {
            self.get_blocks_to_download().await;
        }

        Ok(())
    }
    /// Process a message from a peer and handle it accordingly between the variants of [`PeerMessages`].
    async fn handle_message(&mut self, msg: NodeNotification) -> Result<(), WireError> {
        #[cfg(feature = "metrics")]
        self.register_message_time(&msg);

        match msg {
            NodeNotification::FromPeer(peer, notification) => match notification {
                PeerMessages::Block(block) => {
                    if let Err(e) = self.handle_block_data(peer, block).await {
                        error!("Error processing block: {:?}", e);
                    }
                }

                PeerMessages::Ready(version) => {
                    try_and_log!(self.handle_peer_ready(peer, &version).await);
                }

                PeerMessages::Disconnected(idx) => {
                    try_and_log!(self.handle_disconnection(peer, idx).await);
                }

                PeerMessages::Addr(addresses) => {
                    debug!("Got {} addresses from peer {}", addresses.len(), peer);
                    let addresses: Vec<_> = addresses.into_iter().map(|addr| addr.into()).collect();

                    self.address_man.push_addresses(&addresses);
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

                _ => {}
            },
        }

        Ok(())
    }
}
