//! This module will abstract away some peer routines like pinging, and timeout of messages
//! if a peer takes too long to respond.

use std::time::{Duration, Instant};

use async_std::{channel::Sender, sync::RwLock};

use super::{NodeNotification, NodeRequest};

pub struct PeerManager {
    node_tx: Sender<NodeNotification>,
    inflight: RwLock<Vec<(u32, NodeRequest, Instant)>>,
}

impl PeerManager {
    pub async fn new_request(&self, peer: u32, request: NodeRequest) {
        let mut inflight = self.inflight.write().await;
        inflight.push((peer, request, Instant::now()));
    }
    pub fn new(node_tx: Sender<NodeNotification>) -> PeerManager {
        PeerManager {
            inflight: RwLock::new(Vec::new()),
            node_tx,
        }
    }
    pub fn done(&self, peer: u32, request: NodeRequest) {

    }
    pub async fn check_timeout(&self) {
        let inflight = self.inflight.read().await;
        for (peer, request, instant) in inflight.iter() {
            if instant.elapsed() < Duration::from_secs(1) {
                self.node_tx
                    .send(NodeNotification::FromPeerManager(
                        PeerManagerNotifications::Timeout(*peer),
                    ))
                    .await;
            }
        }
    }
}

pub enum PeerManagerNotifications {
    Timeout(u32),
}
