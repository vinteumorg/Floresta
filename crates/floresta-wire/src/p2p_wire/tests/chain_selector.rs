#[cfg(test)]
mod tests_utils {

    use std::sync::Arc;
    use std::time::Duration;

    use bitcoin::Network;
    use floresta_chain::pruned_utreexo::UpdatableChainstate;
    use floresta_chain::AssumeValidArg;
    use floresta_chain::FlatChainStore;
    use floresta_chain::FlatChainStoreConfig;
    use rustreexo::accumulator::pollard::Pollard;
    use tokio::sync::Mutex;
    use tokio::sync::RwLock;
    use tokio::time::timeout;

    use crate::address_man::AddressMan;
    use crate::node::UtreexoNode;
    use crate::p2p_wire::mempool::Mempool;
    use crate::p2p_wire::sync_node::SyncNode;
    use crate::p2p_wire::tests::utils::create_peer;
    use crate::p2p_wire::tests::utils::get_node_config;
    use crate::p2p_wire::tests::utils::get_test_headers;
    use crate::p2p_wire::tests::utils::BlockDataMap;
    use crate::p2p_wire::tests::utils::BlockHashMap;
    use crate::p2p_wire::tests::utils::HeaderList;
    use floresta_chain::ChainState;
    pub const NUM_BLOCKS: usize = 10;

    type PeerData = (HeaderList, BlockHashMap, BlockDataMap);

    pub async fn setup_node(
        peers: Vec<PeerData>,
        pow_fraud_proofs: bool,
        network: Network,
    ) -> Arc<floresta_chain::pruned_utreexo::chain_state::ChainState<FlatChainStore>> {
        let datadir = format!("./tmp-db/{}.chain_selector", rand::random::<u32>());
        let config = FlatChainStoreConfig::new(datadir.clone());

        let chainstore = FlatChainStore::new(config).unwrap();
        let mempool = Arc::new(Mutex::new(Mempool::new(Pollard::default(), 1000)));
        let chain = ChainState::new(chainstore, network, AssumeValidArg::Disabled);
        let chain = Arc::new(chain);

        let mut headers = get_test_headers();
        headers.remove(0);
        headers.truncate(9);
        for header in headers {
            chain.accept_header(header).unwrap();
        }

        let config = get_node_config(datadir, network, pow_fraud_proofs);
        let kill_signal = Arc::new(RwLock::new(false));
        let mut node = UtreexoNode::<Arc<ChainState<FlatChainStore>>, SyncNode>::new(
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
            let _peer = peer.clone();

            node.peers.insert(i as u32, peer);
        }

        timeout(Duration::from_secs(100), node.run(|_| {}))
            .await
            .unwrap();

        chain
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::Network;
    use floresta_chain::pruned_utreexo::BlockchainInterface;
    use floresta_chain::pruned_utreexo::UpdatableChainstate;
    use rustreexo::accumulator::node_hash::BitcoinNodeHash;

    use crate::p2p_wire::tests::chain_selector::tests_utils::setup_node;
    use crate::p2p_wire::tests::utils::create_false_acc;
    use crate::p2p_wire::tests::utils::get_essentials;
    use crate::p2p_wire::tests::utils::get_test_filters;

    use crate::p2p_wire::tests::chain_selector::tests_utils::NUM_BLOCKS;
    const STARTING_LIE_BLOCK_HEIGHT: usize = 3;

    #[tokio::test]
    async fn two_peers_one_lying() {
        let essentials = get_essentials();
        let headers = essentials.headers[..10].to_vec();
        let blocks = essentials.blocks;
        let true_filters = get_test_filters().unwrap();
        let mut false_filters = true_filters.clone();

        // this weird looking for loop is due to lint
        for (i, _) in headers
            .iter()
            .enumerate()
            .take(NUM_BLOCKS)
            .skip(STARTING_LIE_BLOCK_HEIGHT)
        {
            false_filters.remove(&headers[i].block_hash());
            false_filters.insert(headers[i].block_hash(), create_false_acc(i));
        }

        let peers = vec![
            (headers.clone(), blocks.clone(), true_filters),
            (headers.clone(), blocks.clone(), false_filters),
        ];

        let chain = setup_node(peers, false, Network::Signet).await;
        let best_block = chain.get_best_block().unwrap();
        assert_eq!(best_block.1, headers[9].block_hash());

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
}
