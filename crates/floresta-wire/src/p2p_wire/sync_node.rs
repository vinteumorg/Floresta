//! A node that downloads and validates the blockchain.

use std::time::Duration;
use std::time::Instant;

use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::ServiceFlags;
use floresta_chain::proof_util;
use floresta_chain::ThreadSafeChain;
use floresta_common::service_flags;
use floresta_common::service_flags::UTREEXO;
use log::debug;
use log::info;
use log::warn;
use tokio::time::timeout;

use super::error::WireError;
use super::node::PeerStatus;
use super::node_interface::UserRequest;
use super::peer::PeerMessages;
use crate::node::periodic_job;
use crate::node::try_and_log;
use crate::node::ConnectionKind;
use crate::node::InflightRequests;
use crate::node::NodeNotification;
use crate::node::NodeRequest;
use crate::node::UtreexoNode;
use crate::node_context::NodeContext;
use crate::node_interface::NodeResponse;

/// [`SyncNode`] is a node that downloads and validates the blockchain.
/// This node implements:
///     - `NodeContext`
///     - `UtreexoNode<SyncNode, Chain>`
///
/// see [node_context](crates/floresta-wire/src/p2p_wire/node_context.rs) and [node.rs](crates/floresta-wire/src/p2p_wire/node.rs) for more information.
#[derive(Clone, Debug, Default)]
pub struct SyncNode {}

impl NodeContext for SyncNode {
    fn get_required_services(&self) -> bitcoin::p2p::ServiceFlags {
        ServiceFlags::WITNESS | service_flags::UTREEXO.into() | ServiceFlags::NETWORK
    }

    const MAX_OUTGOING_PEERS: usize = 5; // don't need many peers, half the default
    const TRY_NEW_CONNECTION: u64 = 60; // one minute
    const REQUEST_TIMEOUT: u64 = 10 * 60; // 10 minutes
    const MAX_INFLIGHT_REQUESTS: usize = 100; // double the default
}

/// Node methods for a [`UtreexoNode`] where its Context is a [`SyncNode`].
/// See [node](crates/floresta-wire/src/p2p_wire/node.rs) for more information.
impl<Chain> UtreexoNode<Chain, SyncNode>
where
    Chain: ThreadSafeChain,
    WireError: From<Chain::Error>,
    Chain::Error: From<proof_util::UtreexoLeafError>,
{
    /// Computes the next blocks to request, and sends a GETDATA request
    ///
    /// We send block requests in batches of four, and we can always have two
    /// such batches inflight. Therefore, we can have at most eight inflight
    /// blocks.
    ///
    /// This function sends exactly one GETDATA, therefore ask for four blocks.
    /// It will compute the next blocks we need, given our tip, validation index,
    /// inflight requests and cached blocks. We then select a random peer and send
    /// the request.
    ///
    /// TODO: Be smarter when selecting peers to send, like taking in consideration
    /// already inflight blocks and latency.
    async fn get_blocks_to_download(&mut self) {
        let max_inflight_blocks = SyncNode::BLOCKS_PER_GETDATA * SyncNode::MAX_CONCURRENT_GETDATA;
        let inflight_blocks = self
            .inflight
            .keys()
            .filter(|inflight| matches!(inflight, InflightRequests::Blocks(_)))
            .count();

        // if we do a request, this will be the new inflight blocks count
        let next_inflight_count = inflight_blocks + SyncNode::BLOCKS_PER_GETDATA;

        // if this request would make our inflight queue too long, postpone it
        if next_inflight_count > max_inflight_blocks {
            return;
        }

        let mut blocks = Vec::with_capacity(SyncNode::BLOCKS_PER_GETDATA);
        for _ in 0..SyncNode::BLOCKS_PER_GETDATA {
            let next_block = self.last_block_request + 1;
            let validation_index = self.chain.get_validation_index().unwrap();
            if next_block <= validation_index {
                self.last_block_request = validation_index;
            }

            let next_block = self.chain.get_block_hash(next_block);
            match next_block {
                Ok(next_block) => {
                    blocks.push(next_block);
                    self.last_block_request += 1;
                }

                Err(_) => {
                    // this is likely because we've reached the end of the chain
                    // and we've got a `BlockNotPresent` error.
                    break;
                }
            }
        }

        try_and_log!(self.request_blocks(blocks).await);
    }

    async fn ask_for_missed_blocks(&mut self) -> Result<(), WireError> {
        let next_request = self.chain.get_validation_index()? + 1;
        let last_block_requested = self.last_block_request;

        // we accumulate the hashes of all blocks in [next_request, last_block_requested] here
        // and pass it to request_blocks, which will filter inflight and pending blocks out.
        let mut range_blocks = Vec::new();

        for request_height in next_request..=last_block_requested {
            let block_hash = self.chain.get_block_hash(request_height)?;
            range_blocks.push(block_hash);
        }

        self.request_blocks(range_blocks).await
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
    pub async fn run(mut self, done_cb: impl FnOnce(&Chain)) -> Self {
        info!("Starting sync node");
        self.last_block_request = self.chain.get_validation_index().unwrap();

        loop {
            while let Ok(Some(msg)) = timeout(Duration::from_secs(1), self.node_rx.recv()).await {
                try_and_log!(self.handle_message(msg).await);
            }

            if *self.kill_signal.read().await {
                break;
            }

            let validation_index = self
                .chain
                .get_validation_index()
                .expect("validation index block should present");

            let best_block = self
                .chain
                .get_best_block()
                .expect("best block should present")
                .0;

            if validation_index == best_block {
                info!("IBD is finished, switching to normal operation mode");
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

            try_and_log!(self.check_for_timeout().await);

            let assume_stale = Instant::now()
                .duration_since(self.common.last_tip_update)
                .as_secs()
                > SyncNode::ASSUME_STALE;

            if assume_stale {
                try_and_log!(self.create_connection(ConnectionKind::Extra).await);
                self.last_tip_update = Instant::now();
                continue;
            }

            try_and_log!(self.process_pending_blocks().await);
            if !self.has_utreexo_peers() {
                continue;
            }

            // Ask for missed blocks if they are no longer inflight or pending
            try_and_log!(self.ask_for_missed_blocks().await);

            self.get_blocks_to_download().await;
        }

        done_cb(&self.chain);
        self
    }

    /// Process a message from a peer and handle it accordingly between the variants of [`PeerMessages`].
    async fn handle_message(&mut self, msg: NodeNotification) -> Result<(), WireError> {
        match msg {
            NodeNotification::FromUser(request, responder) => {
                self.perform_user_request(request, responder).await;
            }

            NodeNotification::DnsSeedAddresses(addresses) => {
                self.address_man.push_addresses(&addresses);
            }

            NodeNotification::FromPeer(peer, notification) => {
                #[cfg(feature = "metrics")]
                self.register_message_time(&notification, peer);

                match notification {
                    PeerMessages::Block(block) => {
                        if self.blocks.contains_key(&block.block_hash()) {
                            debug!(
                                "Received block {} from peer {}, but we already have it",
                                block.block_hash(),
                                peer
                            );

                            return Ok(());
                        }

                        self.request_block_proof(block, peer).await?;

                        self.process_pending_blocks().await?;
                        self.get_blocks_to_download().await;
                    }

                    PeerMessages::Ready(version) => {
                        try_and_log!(self.handle_peer_ready(peer, &version).await);
                    }

                    PeerMessages::Disconnected(idx) => {
                        try_and_log!(self.handle_disconnection(peer, idx).await);
                    }

                    PeerMessages::Addr(addresses) => {
                        debug!("Got {} addresses from peer {}", addresses.len(), peer);
                        let addresses: Vec<_> =
                            addresses.into_iter().map(|addr| addr.into()).collect();

                        self.address_man.push_addresses(&addresses);
                    }

                    PeerMessages::NotFound(inv) => match inv {
                        Inventory::Error => {}
                        Inventory::Block(block)
                        | Inventory::WitnessBlock(block)
                        | Inventory::CompactBlock(block) => {
                            if let Some(request) = self
                                .inflight_user_requests
                                .remove(&UserRequest::Block(block))
                            {
                                request
                                    .2
                                    .send(NodeResponse::Block(None))
                                    .map_err(|_| WireError::ResponseSendError)?;
                            }
                        }

                        Inventory::WitnessTransaction(tx) | Inventory::Transaction(tx) => {
                            if let Some(request) = self
                                .inflight_user_requests
                                .remove(&UserRequest::MempoolTransaction(tx))
                            {
                                request
                                    .2
                                    .send(NodeResponse::MempoolTransaction(None))
                                    .map_err(|_| WireError::ResponseSendError)?;
                            }
                        }
                        _ => {}
                    },

                    PeerMessages::Transaction(tx) => {
                        debug!("saw a mempool transaction with txid={}", tx.compute_txid());
                        if let Some(request) = self
                            .inflight_user_requests
                            .remove(&UserRequest::MempoolTransaction(tx.compute_txid()))
                        {
                            request
                                .2
                                .send(NodeResponse::MempoolTransaction(Some(tx)))
                                .map_err(|_| WireError::ResponseSendError)?;
                        }
                    }

                    PeerMessages::UtreexoState(_) => {
                        warn!("Utreexo state received from peer {peer}, but we didn't ask",);
                        self.increase_banscore(peer, 5).await?;
                    }

                    PeerMessages::UtreexoProof(uproof) => {
                        self.attach_proof(uproof, peer).await?;
                        self.process_pending_blocks().await?;
                        self.get_blocks_to_download().await;
                    }

                    _ => {}
                }
            }
        }

        Ok(())
    }
}
