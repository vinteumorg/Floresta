#[cfg(test)]
mod tests_utils {

    use std::sync::Arc;
    use std::time::Duration;

    use bitcoin::Network;
    use floresta_chain::pruned_utreexo::UpdatableChainstate;
    use floresta_chain::AssumeValidArg;
    use floresta_chain::ChainState;
    use floresta_chain::FlatChainStore;
    use floresta_chain::FlatChainStoreConfig;
    use rustreexo::accumulator::pollard::Pollard;
    use tokio::sync::mpsc::unbounded_channel;
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
    pub const NUM_BLOCKS: usize = 120;

    type PeerData = (HeaderList, BlockHashMap, BlockDataMap);

    pub async fn setup_node(
        peers: Vec<PeerData>,
        pow_fraud_proofs: bool,
        network: Network,
    ) -> Arc<ChainState<FlatChainStore>> {
        let datadir = format!("./tmp-db/{}.chain_selector", rand::random::<u32>());
        let config = FlatChainStoreConfig::new(datadir.clone());

        let chainstore = FlatChainStore::new(config).unwrap();
        let mempool = Arc::new(Mutex::new(Mempool::new(Pollard::default(), 1000)));
        let chain = ChainState::new(chainstore, network, AssumeValidArg::Disabled);
        let chain = Arc::new(chain);

        let mut headers = get_test_headers();
        headers.remove(0);
        headers.truncate(NUM_BLOCKS);
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
            let (sender, receiver) = unbounded_channel();
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

        timeout(Duration::from_secs(100), node.run(|_| {}))
            .await
            .unwrap();

        chain
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::BlockHash;
    use bitcoin::Network;
    use floresta_chain::pruned_utreexo::BlockchainInterface;
    use floresta_chain::pruned_utreexo::UpdatableChainstate;
    use floresta_common::acchashes;
    use floresta_common::prelude::HashMap;
    use rustreexo::accumulator::node_hash::BitcoinNodeHash;
    use rustreexo::accumulator::stump::Stump;

    use crate::p2p_wire::tests::chain_selector::tests_utils::setup_node;
    use crate::p2p_wire::tests::chain_selector::tests_utils::NUM_BLOCKS;
    use crate::p2p_wire::tests::utils::create_false_acc;
    use crate::p2p_wire::tests::utils::get_essentials;
    use crate::p2p_wire::tests::utils::get_test_filters;
    const STARTING_LIE_BLOCK_HEIGHT: usize = 30;

    #[tokio::test]
    async fn two_peers_one_lying() {
        let essentials = get_essentials();
        let headers = essentials.headers.to_vec();
        let blocks = essentials.blocks;
        let true_filters = get_test_filters().unwrap();

        let mut false_filters = true_filters.clone();

        let invalid_filters_iter = headers
            .iter()
            .enumerate()
            .take(NUM_BLOCKS)
            .skip(STARTING_LIE_BLOCK_HEIGHT);

        for (i, _) in invalid_filters_iter {
            false_filters.remove(&headers[i].block_hash());
            false_filters.insert(headers[i].block_hash(), create_false_acc(i));
        }

        let peers = vec![
            (headers.clone(), blocks.clone(), true_filters),
            (headers.clone(), blocks.clone(), false_filters),
        ];

        let chain = setup_node(peers, true, Network::Signet).await;
        let best_block = chain.get_best_block().unwrap();
        assert_eq!(best_block.1, headers[NUM_BLOCKS].block_hash());

        let acc_received = chain.acc();

        let acc = Stump {
            leaves: 120,
            roots: acchashes![
                "fbbff1a533f80135a0cb222859297792d5c9d1cec801a2793ac15184905e672c",
                "42554b3aab845bf18397188fc21f1f39cfc742f36bdb1aae70dd60a39c1fd9b9",
                "2782a7bd0f93d57efb8611c90d41a94d520bceded1fc6c0050b4133db24a15d0",
                "d86dbb6f4c3c258e6a83ae0f349cbee695b10b2b677a02f12e5aefac04d368c9"
            ]
            .to_vec(),
        };
        assert_eq!(acc, acc_received);
    }

    #[tokio::test]
    async fn ten_peers_one_honest() {
        let essentials = get_essentials();
        let headers = essentials.headers.to_vec();
        let blocks = essentials.blocks;
        let true_filters = get_test_filters().unwrap();
        let mut false_filters_array: Vec<HashMap<BlockHash, Vec<u8>>> = Vec::new();

        for i in 0..9 {
            let mut false_filters = true_filters.clone();
            for (j, _) in headers.iter().enumerate().take(NUM_BLOCKS).skip(i * 2) {
                false_filters.remove(&headers[j].block_hash());
                false_filters.insert(headers[j].block_hash(), create_false_acc(j));
            }
            false_filters_array.push(false_filters);
        }

        let mut peers = Vec::new();
        for _ in 0..9 {
            let peer = (
                headers.clone(),
                blocks.clone(),
                false_filters_array.pop().unwrap(),
            );
            peers.push(peer);
        }

        peers.push((headers.clone(), blocks.clone(), true_filters.clone()));

        let chain = setup_node(peers, true, Network::Signet).await;
        let best_block = chain.get_best_block().unwrap();
        assert_eq!(best_block.1, headers[NUM_BLOCKS].block_hash());

        let acc_received = chain.acc();

        let acc = Stump {
            leaves: 120,
            roots: acchashes![
                "fbbff1a533f80135a0cb222859297792d5c9d1cec801a2793ac15184905e672c",
                "42554b3aab845bf18397188fc21f1f39cfc742f36bdb1aae70dd60a39c1fd9b9",
                "2782a7bd0f93d57efb8611c90d41a94d520bceded1fc6c0050b4133db24a15d0",
                "d86dbb6f4c3c258e6a83ae0f349cbee695b10b2b677a02f12e5aefac04d368c9"
            ]
            .to_vec(),
        };
        assert_eq!(acc, acc_received);
    }
}
