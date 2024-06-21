#[cfg(test)]
mod tests_utils {
    use std::collections::HashMap;
    use std::io::Cursor;
    use std::mem::ManuallyDrop;
    use std::sync::Arc;
    use std::time::Duration;
    use std::time::Instant;

    use async_std::channel::Receiver;
    use async_std::channel::Sender;
    use async_std::future;
    use async_std::sync::RwLock;
    use async_std::task;
    use bitcoin::blockdata::block::Header;
    use bitcoin::consensus::Decodable;
    use bitcoin::p2p::ServiceFlags;
    use bitcoin::BlockHash;
    use floresta_chain::pruned_utreexo::BlockchainInterface;
    use floresta_chain::AssumeValidArg;
    use floresta_chain::ChainState;
    use floresta_chain::KvChainStore;

    use crate::mempool::Mempool;
    use crate::node::LocalPeerView;
    use crate::node::NodeNotification;
    use crate::node::NodeRequest;
    use crate::node::PeerStatus;
    use crate::node::UtreexoNode;
    use crate::p2p_wire::chain_selector::ChainSelector;
    use crate::p2p_wire::peer::PeerMessages;
    use crate::UtreexoNodeConfig;

    pub fn get_test_headers() -> Vec<Header> {
        let file = include_bytes!(
            "../../../../floresta-chain/src/pruned_utreexo/testdata/signet_headers.zst"
        );
        let uncompressed: Vec<u8> = zstd::decode_all(std::io::Cursor::new(file)).unwrap();
        let mut cursor = Cursor::new(uncompressed);
        let mut headers: Vec<Header> = Vec::new();
        while let Ok(header) = Header::consensus_decode(&mut cursor) {
            headers.push(header);
        }
        headers
    }

    pub struct TestPeer {
        headers: Vec<Header>,
        filters: HashMap<BlockHash, Vec<u8>>,
        node_tx: Sender<NodeNotification>,
        node_rx: Receiver<NodeRequest>,
        peer_id: u32,
    }

    impl TestPeer {
        pub fn new(
            node_tx: Sender<NodeNotification>,
            headers: Vec<Header>,
            filters: HashMap<BlockHash, Vec<u8>>,
            node_rx: Receiver<NodeRequest>,
            peer_id: u32,
        ) -> Self {
            TestPeer {
                headers,
                filters,
                node_tx,
                node_rx,
                peer_id,
            }
        }

        ///  FOR KEEPING TRACK OF KINDS OF MESSAGE TYPES
        ///
        ///  NODE REQUESTS:
        ///
        /// GetBlock((Vec<BlockHash>, bool))
        /// GetHeaders(Vec<BlockHash>),         *
        /// GetAddresses,
        /// Shutdown,
        /// BroadcastTransaction(Txid),
        /// MempoolTransaction(Txid),
        /// SendAddresses(Vec<AddrV2Message>),
        /// GetUtreexoState((BlockHash, u32)),
        /// GetFilter((BlockHash, u32))

        /// PEER MESSAGES:
        ///
        /// NewBlock(BlockHash),
        /// Block(UtreexoBlock),
        /// Headers(Vec<BlockHeader>),
        /// Addr(Vec<AddrV2Message>),
        /// Ready(Version),
        /// Disconnected(usize),
        /// NotFound(Inventory),
        /// Transaction(Transaction),
        /// UtreexoState(Vec<u8>),
        /// BlockFilter((BlockHash, floresta_compact_filters::BlockFilter))

        /// NODE NOTIFICATIONS:
        ///
        /// FromPeer(u32, PeerMessages)

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
                                self.peer_id,
                                PeerMessages::Headers(headers),
                            ))
                            .await
                            .unwrap();
                    }
                    NodeRequest::GetUtreexoState((hash, _)) => {
                        let filters = self.filters.get(&hash).unwrap().clone();
                        self.node_tx
                            .send(NodeNotification::FromPeer(
                                self.peer_id,
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
        peer_id: u32,
    ) -> LocalPeerView {
        let peer = TestPeer::new(node_sender, headers, filters, node_rcv, peer_id);
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

    pub async fn setup_test(
        test_name: &str,
        peers: Vec<(Vec<Header>, HashMap<BlockHash, Vec<u8>>)>,
        pow_fraud_proofs: bool,
        network: floresta_chain::Network,
    ) {
        let datadir = format!("./data/{}.node_test", rand::random::<u32>());
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
            assume_utreexo: None,
            backfill: false,
        };

        let mut node = UtreexoNode::<ChainSelector, ChainState<KvChainStore>>::new(
            config,
            chain.clone(),
            mempool,
            None,
        );

        for (i, peer) in peers.into_iter().enumerate() {
            let (sender, receiver) = async_std::channel::bounded(10);
            let peer = create_peer(
                peer.0,
                peer.1,
                node.node_tx.clone(),
                sender.clone(),
                receiver,
                i as u32,
            );

            let _peer = peer.clone();

            node.peers.insert(i as u32, peer);
            node.peer_ids.push(i as u32);
            match node.peer_by_service.get_mut(&_peer.services) {
                Some(peer_vec) => peer_vec.push(i as u32),
                None => {
                    node.peer_by_service.insert(_peer.services, vec![i as u32]);
                    ()
                }
            }
        }

        let mut node = ManuallyDrop::new(Box::new(node));

        let kill_signal = Arc::new(RwLock::new(false));
        // FIXME: This doesn't look very safe, but we need to coerce a &mut reference of the node
        //        to live for the static lifetime, or it can't be spawn-ed by async-std::task
        let _node: &'static mut UtreexoNode<ChainSelector, ChainState<KvChainStore>> =
            unsafe { std::mem::transmute(&mut **node) };

        future::timeout(Duration::from_secs(2), _node.run(kill_signal))
            .await
            .unwrap()
            .unwrap();

        let headers = get_test_headers();

        match test_name {
            "test_chain_selector" => {
                assert_eq!(chain.is_in_idb(), false);
                assert_eq!(chain.get_best_block().unwrap().0, 2015);
                assert_eq!(
                    chain.get_best_block().unwrap().1,
                    headers[2015].block_hash()
                );
            }

            "two_peers_different_tips" => {
                assert_eq!(chain.is_in_idb(), false);
                assert_eq!(chain.get_best_block().unwrap().0, 2014);
                assert_eq!(
                    chain.get_best_block().unwrap().1,
                    headers[2014].block_hash()
                );
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::tests_utils::get_test_headers;
    use super::tests_utils::setup_test;

    #[async_std::test]
    async fn accept_one_header() {
        let headers = get_test_headers();

        setup_test(
            "test_chain_selector",
            vec![(headers, HashMap::new())],
            false,
            floresta_chain::Network::Signet,
        )
        .await;
    }

    #[async_std::test]
    async fn two_peers_different_tips() {
        let mut headers = get_test_headers();

        let mut peers = Vec::new();

        for _ in 0..2 {
            headers.pop();
            peers.push((headers.clone(), HashMap::new()))
        }

        setup_test(
            "two_peers_different_tips",
            peers,
            false,
            floresta_chain::Network::Signet,
        )
        .await;
    }

    // two peers in different tips      *

    // 10 peers on different tips

    // two-peers pow fraud proofs one lying

    // 10 peers pow fraud proofs, all but one lying (in the chain with less work)

    // two peers, one invalid accumulator

    // 10 peers, only one valid accumulator
}
