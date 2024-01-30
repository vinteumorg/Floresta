// SPDX-License-Identifier: MIT

//! A module that connects with multiple peers and finds the best chain.
//!
//! # The theory
//!
//! In Bitcoin, the history of transactions processes by the network is defined by a sequence of
//! blocks, chainned by their cryptographic hash. A block commits the hash for the block right
//! before it. Therefore, if we pick any given block, there's exactly one history leading to the
//! very first block, that commits to no one. However, if you go in the other way, starting at the
//! first block and going up, there may not be only one history. Multiple blocks may commit to the
//! same parent. We need a way to pick just one such chain, among all others.
//!
//! To do that, we use the most work rule, sometimes called "Nakamoto Consensus" after Bitcoin's
//! creator, Satoshi Nakamoto. Every block has to solve a probabilistic challenge of finding a
//! combination of data that hashes to a value smaller than a network-agreed value. Because hash
//! functions are pseudorandom, one must make a amount of hashes (on average) before finding a
//! valid one. If we define the amount of hashes needed to find a block as this block's "work",
//! by adding-up the work in each of a chain's blocks, we arrive with the `chainwork`. The Nakamoto
//! consensus consists in taking the chain with most work as the best one.
//!
//! This works because anyone in the network will compute the same amount of work and pick the same
//! one, regardless of where and when. Because work is a intrinsic and deterministic property of a
//! block, everyone comparing the same chain, be on earth, on mars; in 2020 or 2100, they will
//! choose the exact same chain, aways.
//!
//! The most critial part of syncing-up a Bitcoin node is making sure you know about the most-work
//! chain. If someone can eclypse you, they can make you start following a chain that only you and
//! the attacker care about. If you get pay in this chain, you can't pay someone else outside this
//! chain, because they will be following other chains. Luckly, we only need one honest peer, to
//! find the best-work chain and avoid any attacker to fools us into accepting payments in a "fake
//! Bitcoin"
//!
//! # Implementation
//!
//! This module will connect with multiple peers, ask what is the best chain they know about and
//! try to find a consensus among our peers. We'll use the chain we've just discovered to download
//! the blocks and perform full validation of them. To enumerte all chains, we send a `getblocks`
//! request. This message tells our peers to send the hash of the blocks it knows about.
//! Using this information we find the chains our peers seems to be following, and them download
//! and validate headers for this chains. We need to validate those headers, specially their PoW,
//! to avoid peers forcing us to download an verify an invalid proof, opening a resource exaustion
//! DoS oportunity.

use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use async_std::future::timeout;
use async_std::sync::RwLock;
use bitcoin::block::Header;
use bitcoin::p2p::ServiceFlags;
use floresta_chain::pruned_utreexo::BlockchainInterface;
use floresta_chain::pruned_utreexo::UpdatableChainstate;
use floresta_common::periodic_job;
use floresta_common::try_and_log;
use log::info;

use super::error::WireError;
use super::peer::PeerMessages;
use crate::address_man::AddressState;
use crate::node::InflightRequests;
use crate::node::NodeNotification;
use crate::node::NodeRequest;
use crate::node::UtreexoNode;
use crate::node_context::NodeContext;
use crate::node_context::PeerId;

#[derive(Debug, Default, Clone)]
/// A p2p driver that attemps to connect with multiple peers, ask which chain are them following
/// and download and verify the headers, **not** the actual blocks. This is the first part of a
/// loger IBD pipeline.
/// The actual blocks should be downloaded by a SyncPeer.
pub struct ChainSelector {
    state: ChainSelectorState,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum ChainSelectorState {
    #[default]
    /// We are opening connection with some peers
    CreatingConnections,
    /// We are downloading headers to find the most-work one
    DownloadingHeaders,
    /// We've downloaded all headers
    Done,
}

impl NodeContext for ChainSelector {
    const REQUEST_TIMEOUT: u64 = 10; // Ban peers stalling our IBD
    const TRY_NEW_CONNECTION: u64 = 10; // Try creating connections more aggressively
}

impl<Chain> UtreexoNode<ChainSelector, Chain>
where
    WireError: From<<Chain as BlockchainInterface>::Error>,
    Chain: BlockchainInterface + UpdatableChainstate + 'static,
{
    async fn handle_headers(
        &mut self,
        peer: PeerId,
        headers: Vec<Header>,
    ) -> Result<(), WireError> {
        if headers.is_empty() {
            self.1.state = ChainSelectorState::Done;
            return Ok(());
        }

        info!(
            "Downloading headers from peer={peer} at height={} hash={}",
            self.chain.get_best_block()?.0 + 1,
            headers[0].block_hash()
        );

        for header in headers {
            match self.chain.accept_header(header) {
                Err(e) => {
                    log::error!("Error while downloading headers from peer={peer} err={e}");
                    self.send_to_peer(peer, NodeRequest::Shutdown).await?;
                    let peer = self.peers.get(&peer).unwrap();
                    self.0.address_man.update_set_state(
                        peer.address_id as usize,
                        AddressState::Banned(ChainSelector::BAN_TIME),
                    );
                }
                Ok(ff) => {
                    if !ff {
                        todo!("This peer is in a fork, handle this")
                    }
                }
            }
        }
        self.request_headers().await
    }

    async fn request_headers(&mut self) -> Result<(), WireError> {
        let locator = self.chain.get_block_locator().unwrap_or_default();
        let peer = self
            .send_to_random_peer(NodeRequest::GetHeaders(locator), ServiceFlags::NONE)
            .await?;

        self.inflight
            .insert(InflightRequests::Headers, (peer, Instant::now()));
        Ok(())
    }

    async fn check_for_timeout(&mut self) -> Result<(), WireError> {
        let mut failed = vec![];

        for (request, (peer, instant)) in self.inflight.clone() {
            if instant.elapsed().as_secs() > ChainSelector::REQUEST_TIMEOUT {
                self.send_to_peer(peer, NodeRequest::Shutdown).await?;
                failed.push(request)
            }
        }

        for request in failed {
            self.inflight.remove(&request);
        }

        Ok(())
    }

    pub async fn check_tips(&mut self) -> Result<(), WireError> {
        let locator = self.chain.get_block_locator().unwrap_or_default();
        let mut pendding = Vec::with_capacity(self.peer_ids.len());

        for peer in self.peer_ids.iter() {
            self.send_to_peer(*peer, NodeRequest::GetHeaders(locator.clone()))
                .await?;
            pendding.push(peer);
        }
        // TODO: Check if peer has something
        Ok(())
    }

    pub async fn run(&mut self, stop_signal: &Arc<RwLock<bool>>) -> Result<(), WireError> {
        // Open our first connection to a random peer, we'll use this peer to find a
        // candidate chain.
        let (height, _) = self.chain.get_best_block()?;
        let first_run = height == 0;

        self.create_connection(false).await;
        info!("Starting ibd, selecting the best chain");
        loop {
            while let Ok(notification) =
                timeout(Duration::from_millis(10), self.node_rx.recv()).await
            {
                try_and_log!(self.handle_notification(notification).await);
            }

            periodic_job!(
                self.maybe_open_connection().await,
                self.last_connection,
                TRY_NEW_CONNECTION,
                ChainSelector
            );

            if self.1.state == ChainSelectorState::CreatingConnections {
                // If we have enough peers, try to download headers
                if self.peer_ids.len() >= 2 {
                    try_and_log!(self.request_headers().await);
                    self.1.state = ChainSelectorState::DownloadingHeaders;
                }
            }

            // We downloaded all headers in the most-pow chain. We're done!
            if self.1.state == ChainSelectorState::Done {
                // Do a last check with our peers to find potential tips
                self.check_tips().await?;
                let best_block = self.chain.get_best_block()?;

                info!(
                    "best chain selected at block={} depth={}",
                    best_block.1, best_block.0
                );

                if first_run {
                    // To speed things up, we assume that a given height is valid and
                    // start our chain from there.
                    self.chain.mark_chain_as_valid(best_block.0, best_block.1)?;
                    info!(
                        "this is our first run, starting node from block={}",
                        self.chain.get_best_block()?.1
                    );
                }

                break;
            }

            try_and_log!(self.check_for_timeout().await);

            if *stop_signal.read().await {
                break;
            }
        }

        self.chain.toggle_ibd(false);

        Ok(())
    }

    async fn handle_notification(
        &mut self,
        notification: Result<NodeNotification, async_std::channel::RecvError>,
    ) -> Result<(), WireError> {
        match notification? {
            NodeNotification::FromPeer(peer, message) => match message {
                PeerMessages::Headers(headers) => {
                    self.inflight.remove(&InflightRequests::Headers);
                    return self.handle_headers(peer, headers).await;
                }

                PeerMessages::Ready(version) => {
                    self.handle_peer_ready(peer, &version).await?;
                }

                PeerMessages::Disconnected(idx) => {
                    self.handle_disconnection(peer, idx)?;
                }

                PeerMessages::Addr(addresses) => {
                    let addresses: Vec<_> =
                        addresses.iter().cloned().map(|addr| addr.into()).collect();
                    self.address_man.push_addresses(&addresses);
                }

                _ => {}
            },
        }
        Ok(())
    }
}
