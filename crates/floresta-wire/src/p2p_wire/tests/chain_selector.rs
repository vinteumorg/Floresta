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

    use crate::p2p_wire::tests::utils::create_false_acc;
    use crate::p2p_wire::tests::utils::get_essentials;
    use crate::p2p_wire::tests::utils::get_test_filters;
    use crate::p2p_wire::tests::utils::setup_node;
    const STARTING_LIE_BLOCK_HEIGHT: usize = 30;

    pub const NUM_BLOCKS: usize = 120;

    #[tokio::test]
    async fn two_peers_one_lying() {
        let datadir = format!("./tmp-db/{}.chain_selector", rand::random::<u32>());
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

        let chain = setup_node(peers, true, Network::Signet, &datadir, NUM_BLOCKS).await;
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
        let datadir = format!("./tmp-db/{}.chain_selector", rand::random::<u32>());
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

        let chain = setup_node(peers, true, Network::Signet, &datadir, NUM_BLOCKS).await;
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
