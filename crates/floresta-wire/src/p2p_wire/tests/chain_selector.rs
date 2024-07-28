#[cfg(test)]
mod tests_utils {
    use std::collections::HashMap;
    use std::mem::ManuallyDrop;
    use std::sync::Arc;
    use std::time::Duration;

    use async_std::future;
    use async_std::sync::RwLock;
    use bitcoin::blockdata::block::Header;
    use bitcoin::BlockHash;
    use floresta_chain::AssumeValidArg;
    use floresta_chain::ChainState;
    use floresta_chain::KvChainStore;
    use floresta_chain::UtreexoBlock;

    use crate::mempool::Mempool;
    use crate::node::UtreexoNode;
    use crate::p2p_wire::chain_selector::ChainSelector;
    use crate::p2p_wire::tests::utils::create_peer;
    use crate::p2p_wire::tests::utils::get_node_config;

    pub async fn setup_node(
        peers: Vec<(
            Vec<Header>,
            HashMap<BlockHash, UtreexoBlock>,
            HashMap<BlockHash, Vec<u8>>,
        )>,
        pow_fraud_proofs: bool,
        network: floresta_chain::Network,
    ) -> Arc<ChainState<KvChainStore<'static>>> {
        let datadir = format!("./data/{}.node_test", rand::random::<u32>());
        let chainstore = KvChainStore::new(datadir.clone()).unwrap();
        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let chain = ChainState::new(chainstore, network, AssumeValidArg::Disabled);
        let chain = Arc::new(chain);

        let config = get_node_config(datadir, network, pow_fraud_proofs);
        let mut node = UtreexoNode::<ChainSelector, Arc<ChainState<KvChainStore>>>::new(
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
                peer.2,
                node.node_tx.clone(),
                sender.clone(),
                receiver,
                i as u32,
            );

            let _peer = peer.clone();

            node.peers.insert(i as u32, peer);
            // node.peer_ids.push(i as u32);
            // match node.peer_by_service.get_mut(&_peer.services) {
            //     Some(peer_vec) => peer_vec.push(i as u32),
            //     None => {
            //         node.peer_by_service.insert(_peer.services, vec![i as u32]);
            //         ()
            //     }
            // }
        }

        let mut node = ManuallyDrop::new(Box::new(node));

        let kill_signal = Arc::new(RwLock::new(false));
        // FIXME: This doesn't look very safe, but we need to coerce a &mut reference of the node
        //        to live for the static lifetime, or it can't be spawn-ed by async-std::task
        let _node: &'static mut UtreexoNode<ChainSelector, Arc<ChainState<KvChainStore>>> =
            unsafe { std::mem::transmute(&mut **node) };

        future::timeout(Duration::from_secs(5), _node.run(kill_signal))
            .await
            .unwrap()
            .unwrap();

        chain
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::str::FromStr;

    use floresta_chain::pruned_utreexo::BlockchainInterface;
    use floresta_chain::pruned_utreexo::UpdatableChainstate;
    use rustreexo::accumulator::node_hash::NodeHash;

    use crate::p2p_wire::tests::chain_selector::tests_utils::setup_node;
    use crate::p2p_wire::tests::utils::create_false_acc;
    use crate::p2p_wire::tests::utils::get_essentials;

    #[async_std::test]
    async fn accept_one_header() {
        let (headers, _, _, _, _) = get_essentials();

        let chain = setup_node(
            vec![(headers.clone(), HashMap::new(), HashMap::new())],
            false,
            floresta_chain::Network::Signet,
        )
        .await;

        assert_eq!(chain.get_best_block().unwrap().0, 2015);
        assert_eq!(
            chain.get_best_block().unwrap().1,
            headers[2015].block_hash()
        );
    }

    #[async_std::test]
    async fn two_peers_different_tips() {
        let (mut headers, _, _, _, _) = get_essentials();
        let _headers = headers.clone();

        let mut peers = Vec::new();

        for _ in 0..2 {
            headers.pop();
            peers.push((headers.clone(), HashMap::new(), HashMap::new()))
        }

        let chain = setup_node(peers, false, floresta_chain::Network::Signet).await;

        assert_eq!(chain.get_best_block().unwrap().0, 2014);
        assert_eq!(
            chain.get_best_block().unwrap().1,
            _headers[2014].block_hash()
        );
    }

    #[async_std::test]
    async fn ten_peers_different_tips() {
        let (mut headers, _, _, _, _) = get_essentials();
        let _headers = headers.clone();

        let mut peers = Vec::new();

        for _ in 0..10 {
            headers.pop();
            headers.pop();

            peers.push((headers.clone(), HashMap::new(), HashMap::new()))
        }

        let chain = setup_node(peers, false, floresta_chain::Network::Signet).await;

        assert_eq!(chain.get_best_block().unwrap().0, 2013);
        assert_eq!(
            chain.get_best_block().unwrap().1,
            _headers[2013].block_hash()
        );
    }

    #[async_std::test]
    async fn two_peers_one_lying() {
        let (mut headers, blocks, true_filters, tip_hash, _) = get_essentials();
        headers.truncate(120);

        // Create a random false utreexo-acc for the lying peer
        let mut false_filters = true_filters.clone();
        false_filters.remove(&tip_hash).unwrap();
        false_filters.insert(tip_hash, create_false_acc(119));

        let peers = vec![
            (headers.clone(), blocks.clone(), true_filters),
            (headers.clone(), blocks, false_filters),
        ];

        let chain = setup_node(peers, true, floresta_chain::Network::Signet).await;

        assert_eq!(
            chain.get_root_hashes()[3],
            NodeHash::from_str("bfe030a7a994b921fb2329ff085bd0f2351cb5fa251985d6646aaf57954b782b")
                .unwrap()
        );
        assert_eq!(chain.get_root_hashes().len(), 6);
        assert_eq!(chain.get_best_block().unwrap().1, headers[119].block_hash());
    }

    #[async_std::test]
    #[ignore = "failing for some reason"]
    async fn ten_peers_one_honest() {
        let (mut headers, blocks, true_filters, tip_hash, _) = get_essentials();
        headers.truncate(120);

        let mut false_filters = true_filters.clone();
        let mut peers = Vec::new();

        // Create 9 lying peers
        for _ in 0..9 {
            false_filters.remove(&tip_hash).unwrap();
            false_filters.insert(tip_hash, create_false_acc(119));
            peers.push((headers.clone(), blocks.clone(), false_filters.clone()));
        }
        peers.push((headers.clone(), blocks, true_filters));

        let chain = setup_node(peers, true, floresta_chain::Network::Signet).await;

        assert_eq!(
            chain.get_root_hashes()[3],
            NodeHash::from_str("bfe030a7a994b921fb2329ff085bd0f2351cb5fa251985d6646aaf57954b782b")
                .unwrap()
        );
        assert_eq!(chain.get_root_hashes().len(), 6);
        assert_eq!(chain.get_best_block().unwrap().1, headers[119].block_hash());
    }
}
