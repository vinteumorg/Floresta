#[cfg(test)]
mod tests_utils {
    use bitcoin::block::Header;
    use bitcoin::BlockHash;
    use bitcoin::Network;
    use floresta_chain::pruned_utreexo::UpdatableChainstate;
    use floresta_chain::AssumeValidArg;
    use floresta_chain::FlatChainStore;
    use floresta_chain::FlatChainStoreConfig;
    use floresta_chain::UtreexoBlock;
    use rustreexo::accumulator::node_hash::BitcoinNodeHash;
    use rustreexo::accumulator::pollard::Pollard;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Mutex;
    use tokio::sync::RwLock;
    use tokio::time::timeout;

    use crate::address_man::AddressMan;
    use crate::node::UtreexoNode;
    use crate::p2p_wire::chain_selector::ChainSelector;
    use crate::p2p_wire::mempool::Mempool;
    use crate::p2p_wire::tests::utils::create_peer;
    use crate::p2p_wire::tests::utils::get_node_config;

    pub async fn setup_node(
        peers: Vec<(
            Vec<Header>,
            HashMap<BlockHash, UtreexoBlock>,
            HashMap<BlockHash, Vec<u8>>,
        )>,
        pow_fraud_proofs: bool,
        network: Network,
    ) -> Arc<floresta_chain::pruned_utreexo::chain_state::ChainState<FlatChainStore>> {
        let datadir = format!("./tmp-db/{}.chain_selector", rand::random::<u32>());
        let config = FlatChainStoreConfig::new(datadir.clone());

        let chainstore = FlatChainStore::new(config).unwrap();
        let acc = Pollard::<BitcoinNodeHash>::new();
        let mempool = Arc::new(Mutex::new(Mempool::new(acc, 1000000)));

        let chain = floresta_chain::pruned_utreexo::chain_state::ChainState::new(
            chainstore,
            network,
            AssumeValidArg::Disabled,
        );
        let chain = Arc::new(chain);

        // Add the first header after genesis to the chain state
        let mut headers = crate::p2p_wire::tests::utils::get_test_headers();
        headers.remove(0);
        headers.truncate(1);
        for header in headers {
            chain.accept_header(header).unwrap();
        }

        let config = get_node_config(datadir, network, pow_fraud_proofs);
        let kill_signal = Arc::new(RwLock::new(false));
        let mut node = UtreexoNode::<Arc<_>, ChainSelector>::new(
            config,
            chain.clone(),
            mempool,
            None,
            kill_signal.clone(),
            AddressMan::default(),
        )
        .unwrap();

        for (i, peer) in peers.into_iter().enumerate() {
            let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
            let peer = create_peer(
                peer.0,
                peer.1,
                peer.2,
                node.node_tx.clone(),
                sender.clone(),
                receiver,
                i as u32,
            );
            node.peers.insert(i as u32, peer);
        }

        timeout(Duration::from_secs(30), node.run())
            .await
            .unwrap()
            .unwrap();

        chain
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::BlockHash;
    use bitcoin::Network;
    use floresta_chain::pruned_utreexo::{BlockchainInterface, UpdatableChainstate};
    use rustreexo::accumulator::node_hash::BitcoinNodeHash;

    use crate::p2p_wire::tests::chain_selector::tests_utils::setup_node;
    use crate::p2p_wire::tests::utils::{create_false_acc, get_essentials, get_test_filters};

    // Use at least 100 headers for realistic sync
    const HEADER_COUNT: usize = 100;

    #[tokio::test]
    async fn accept_one_header() {
        let essentials = get_essentials();
        let headers = essentials.headers[..HEADER_COUNT].to_vec();
        let blocks = essentials.blocks.clone();
        let filters = get_test_filters().unwrap();

        let chain = setup_node(
            vec![(headers.clone(), blocks, filters)],
            false,
            Network::Signet,
        )
        .await;

        let best_block = chain.get_best_block().unwrap();
        let expected_height = headers.len() - 1;
        let expected_hash = headers[expected_height].block_hash();

        assert_eq!(best_block.0, expected_height as u32);
        assert_eq!(best_block.1, expected_hash);
    }

    #[tokio::test]
    async fn two_peers_different_tips() {
        let essentials = get_essentials();
        let headers1 = essentials.headers[..HEADER_COUNT].to_vec();
        let mut headers2 = essentials.headers[..HEADER_COUNT].to_vec();
        headers2.pop();

        let peers = vec![
            (
                headers1.clone(),
                essentials.blocks.clone(),
                get_test_filters().unwrap(),
            ),
            (
                headers2,
                essentials.blocks.clone(),
                get_test_filters().unwrap(),
            ),
        ];

        let chain = setup_node(peers, false, Network::Signet).await;
        let best_block = chain.get_best_block().unwrap();
        let expected_height = headers1.len() - 1;
        let expected_hash = headers1[expected_height].block_hash();

        assert_eq!(best_block.0, expected_height as u32);
        assert_eq!(best_block.1, expected_hash);
    }

    #[tokio::test]
    async fn ten_peers_different_tips() {
        let essentials = get_essentials();
        let mut peers = Vec::new();

        for i in 0..10 {
            let mut headers = essentials.headers[..HEADER_COUNT].to_vec();
            for _ in 0..(i * 2) {
                headers.pop();
            }
            peers.push((
                headers,
                essentials.blocks.clone(),
                get_test_filters().unwrap(),
            ));
        }

        let chain = setup_node(peers, false, Network::Signet).await;
        let best_block = chain.get_best_block().unwrap();
        let expected_height = essentials.headers[..HEADER_COUNT].len() - 1;
        let expected_hash = essentials.headers[expected_height].block_hash();

        assert_eq!(best_block.0, expected_height as u32);
        assert_eq!(best_block.1, expected_hash);
    }

    #[tokio::test]
    async fn two_peers_one_lying() {
        let essentials = get_essentials();
        let headers = essentials.headers[..120].to_vec();

        let true_filters = get_test_filters().unwrap();
        let tip_hash =
            BlockHash::from_str("0000035f0e5513b26bba7cead874fdf06241a934e4bc4cf7a0381c60e4cdd2bb")
                .unwrap();

        let mut false_filters = true_filters.clone();
        false_filters.remove(&tip_hash);
        false_filters.insert(tip_hash, create_false_acc(119));

        let peers = vec![
            (headers.clone(), essentials.blocks.clone(), true_filters),
            (headers.clone(), essentials.blocks.clone(), false_filters),
        ];

        let chain = setup_node(peers, true, Network::Signet).await;
        let best_block = chain.get_best_block().unwrap();
        assert_eq!(best_block.1, headers[119].block_hash());

        let root_hashes = chain.get_root_hashes();
        assert_eq!(
            root_hashes[3],
            BitcoinNodeHash::from_str(
                "bfe030a7a994b921fb2329ff085bd0f2351cb5fa251985d6646aaf57954b782b"
            )
            .unwrap()
        );
        assert_eq!(root_hashes.len(), 6);
    }

    #[tokio::test]
    async fn ten_peers_one_honest() {
        let essentials = get_essentials();
        let headers = essentials.headers[..120].to_vec();

        let true_filters = get_test_filters().unwrap();
        let tip_hash =
            BlockHash::from_str("0000035f0e5513b26bba7cead874fdf06241a934e4bc4cf7a0381c60e4cdd2bb")
                .unwrap();

        let mut peers = Vec::new();
        for _ in 0..9 {
            let mut false_filters = true_filters.clone();
            false_filters.remove(&tip_hash);
            false_filters.insert(tip_hash, create_false_acc(119));
            peers.push((headers.clone(), essentials.blocks.clone(), false_filters));
        }
        // Honest peer has the same length as liars
        peers.push((headers.clone(), essentials.blocks.clone(), true_filters));

        let chain = setup_node(peers, true, Network::Signet).await;
        let best_block = chain.get_best_block().unwrap();
        assert_eq!(best_block.1, headers[119].block_hash());

        let root_hashes = chain.get_root_hashes();
        assert_eq!(
            root_hashes[3],
            BitcoinNodeHash::from_str(
                "bfe030a7a994b921fb2329ff085bd0f2351cb5fa251985d6646aaf57954b782b"
            )
            .unwrap()
        );
        assert_eq!(root_hashes.len(), 6);
    }

    #[tokio::test]
    async fn fork_chainwork_test() {
        let essentials = get_essentials();
        let headers1 = essentials.headers[..HEADER_COUNT].to_vec();
        let mut headers2 = essentials.headers[..HEADER_COUNT].to_vec();

        // Fork: headers2 diverges at height 50
        let fork_height = 50;
        let mut fork_header = headers2[fork_height].clone();
        fork_header.nonce += 1; // Change something to make a fork
        headers2[fork_height] = fork_header;

        let peers = vec![
            (
                headers1.clone(),
                essentials.blocks.clone(),
                get_test_filters().unwrap(),
            ),
            (
                headers2,
                essentials.blocks.clone(),
                get_test_filters().unwrap(),
            ),
        ];

        let chain = setup_node(peers, false, Network::Signet).await;
        let best_block = chain.get_best_block().unwrap();
        let expected_height = headers1.len() - 1;
        let expected_hash = headers1[expected_height].block_hash();

        assert_eq!(best_block.0, expected_height as u32);
        assert_eq!(best_block.1, expected_hash);
    }
}
