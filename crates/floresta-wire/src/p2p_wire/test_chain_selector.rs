#[cfg(test)]
mod tests_utils {
    use std::collections::HashMap;
    use std::mem::ManuallyDrop;
    use std::sync::Arc;
    use std::time::Instant;

    use async_std::channel::Receiver;
    use async_std::channel::Sender;
    use async_std::sync::RwLock;
    use async_std::task;
    use bitcoin::blockdata::block::Header;
    use bitcoin::p2p::ServiceFlags;
    use bitcoin::BlockHash;
    use floresta_chain::AssumeValidArg;
    use floresta_chain::ChainState;
    use floresta_chain::KvChainStore;
    use futures::Future;

    use crate::mempool::Mempool;
    use crate::node::LocalPeerView;
    use crate::node::NodeNotification;
    use crate::node::NodeRequest;
    use crate::node::PeerStatus;
    use crate::node::UtreexoNode;
    use crate::p2p_wire::chain_selector::ChainSelector;
    use crate::p2p_wire::error::WireError;
    use crate::p2p_wire::peer::PeerMessages;
    use crate::UtreexoNodeConfig;

    pub struct TestPeer {
        headers: Vec<Header>,
        filters: HashMap<BlockHash, Vec<u8>>,
        node_tx: Sender<NodeNotification>,
        node_rx: Receiver<NodeRequest>,
    }

    impl TestPeer {
        pub fn new(
            node_tx: Sender<NodeNotification>,
            headers: Vec<Header>,
            filters: HashMap<BlockHash, Vec<u8>>,
            node_rx: Receiver<NodeRequest>,
        ) -> Self {
            TestPeer {
                headers,
                filters,
                node_tx,
                node_rx,
            }
        }

        pub async fn run(self) {
            loop {
                let req = self.node_rx.recv().await.unwrap();
                match req {
                    NodeRequest::GetHeaders(hashes) => {
                        let pos = hashes.first().unwrap();
                        let pos = self.headers.iter().position(|h| h.block_hash() == *pos);
                        let headers = match pos {
                            None => vec![],
                            Some(pos) => self.headers[(pos + 1)..].to_vec(),
                        };

                        self.node_tx
                            .send(NodeNotification::FromPeer(
                                0,
                                PeerMessages::Headers(headers),
                            ))
                            .await
                            .unwrap();
                    }
                    NodeRequest::GetUtreexoState((hash, _)) => {
                        let filters = self.filters.get(&hash).unwrap().clone();
                        self.node_tx
                            .send(NodeNotification::FromPeer(
                                0,
                                PeerMessages::UtreexoState(filters),
                            ))
                            .await
                            .unwrap();
                    }
                    _ => {}
                }
            }
        }
    }

    fn create_peer(
        headers: Vec<Header>,
        filters: HashMap<BlockHash, Vec<u8>>,
        node_sender: Sender<NodeNotification>,
        sender: Sender<NodeRequest>,
        node_rcv: Receiver<NodeRequest>,
    ) -> LocalPeerView {
        let peer = TestPeer::new(node_sender, headers, filters, node_rcv);
        task::spawn(peer.run());

        LocalPeerView {
            address: "127.0.0.1".parse().unwrap(),
            services: ServiceFlags::NETWORK,
            user_agent: "/utreexo:0.1.0/".to_string(),
            height: 0,
            state: PeerStatus::Ready,
            channel: sender,
            port: 8333,
            feeler: false,
            banscore: 0,
            address_id: 0,
            _last_message: Instant::now(),
        }
    }

    pub fn setup_test(
        test_name: &str,
        peers: Vec<(Vec<Header>, HashMap<BlockHash, Vec<u8>>)>,
        pow_fraud_proofs: bool,
        network: floresta_chain::Network,
    ) -> (
        impl Future<Output = Result<(), WireError>>,
        Arc<ChainState<KvChainStore>>,
    ) {
        let datadir = format!("./test/{}", test_name);
        let chainstore = KvChainStore::new(datadir.clone()).unwrap();
        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let chain = ChainState::new(chainstore, network, AssumeValidArg::Disabled);
        let chain = Arc::new(chain);

        let config = UtreexoNodeConfig {
            network: network.into(),
            pow_fraud_proofs,
            compact_filters: false,
            fixed_peer: None,
            max_banscore: 100,
            max_outbound: 8,
            max_inflight: 10,
            datadir: datadir.clone(),
            proxy: None,
        };

        let mut node = UtreexoNode::<ChainSelector, ChainState<KvChainStore>>::new(
            config,
            chain.clone(),
            mempool,
        );

        for (i, peer) in peers.into_iter().enumerate() {
            let (sender, receiver) = async_std::channel::bounded(10);
            let peer = create_peer(
                peer.0,
                peer.1,
                node.node_tx.clone(),
                sender.clone(),
                receiver,
            );
            node.peers.insert(i as u32, peer);
            node.utreexo_peers.push(i as u32);
            node.peer_ids.push(i as u32);
        }

        let mut node = ManuallyDrop::new(Box::new(node));

        let kill_signal = Arc::new(RwLock::new(false));
        // FIXME: This doesn't look very safe, but we need to coerce a &mut reference of the node
        //        to live for the static lifetime, or it can't be spawn-ed by async-std::task
        let _node: &'static mut UtreexoNode<ChainSelector, ChainState<KvChainStore>> =
            unsafe { std::mem::transmute(&mut **node) };

        let fut = _node.run(kill_signal);

        (fut, chain)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use bitcoin::blockdata::block::Header;
    use bitcoin::consensus::deserialize;
    use bitcoin::hex::FromHex;
    use floresta_chain::pruned_utreexo::BlockchainInterface;

    use super::tests_utils::setup_test;

    #[async_std::test]
    async fn accept_one_header() {
        let headers = [
            "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a008f4d5fae77031e8ad22203",
            "00000020f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000f575c83235984e7dc4afc1f30944c170462e84437ab6f2d52e16878a79e4678bd1914d5fae77031eccf40700"
        ]
        .iter()
        .map(|x| {
            let header = Vec::from_hex(x).unwrap();
            deserialize(&header).unwrap()
        })
        .collect::<Vec<Header>>();

        let (fut, chain) = setup_test(
            "test_chain_selector",
            vec![(headers.clone(), HashMap::new())],
            false,
            floresta_chain::Network::Signet,
        );

        fut.await.expect("should fininsh fine");

        assert_eq!(chain.is_in_idb(), false);
        assert_eq!(chain.get_best_block().unwrap().0, 1);
        assert_eq!(chain.get_best_block().unwrap().1, headers[1].block_hash());
    }

    // two peers in different tips

    // 10 peers on different tips

    // two-peers pow fraud proofs one lying

    // 10 peers pow fraud proofs, all but one lying (in the chain with less work)

    // two peers, one invalid accumulator

    // 10 peers, only one valid accumulator
}
