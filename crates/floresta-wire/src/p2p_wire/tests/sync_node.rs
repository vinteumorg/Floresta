#[cfg(test)]
mod tests_utils {
    use std::sync::Arc;
    use std::time::Duration;

    use floresta_chain::pruned_utreexo::UpdatableChainstate;
    use floresta_chain::AssumeValidArg;
    use floresta_chain::ChainState;
    use floresta_chain::KvChainStore;
    use rustreexo::accumulator::pollard::Pollard;
    use tokio::sync::Mutex;
    use tokio::sync::RwLock;
    use tokio::time::timeout;

    use crate::address_man::AddressMan;
    use crate::mempool::Mempool;
    use crate::node::UtreexoNode;
    use crate::p2p_wire::sync_node::SyncNode;
    use crate::p2p_wire::tests::utils::create_peer;
    use crate::p2p_wire::tests::utils::get_node_config;
    use crate::p2p_wire::tests::utils::get_test_headers;
    use crate::p2p_wire::tests::utils::BlockDataMap;
    use crate::p2p_wire::tests::utils::BlockHashMap;
    use crate::p2p_wire::tests::utils::HeaderList;

    type PeerData = (HeaderList, BlockHashMap, BlockDataMap);

    pub async fn setup_node(
        peers: Vec<PeerData>,
        pow_fraud_proofs: bool,
        network: floresta_chain::Network,
    ) -> Arc<ChainState<KvChainStore<'static>>> {
        let datadir = format!("./tmp-db/{}.sync_node", rand::random::<u32>());
        let chainstore = KvChainStore::new(datadir.clone()).unwrap();
        let mempool = Arc::new(Mutex::new(Mempool::new(Pollard::default(), 1000)));
        let chain = ChainState::new(chainstore, network, AssumeValidArg::Disabled);
        let chain = Arc::new(chain);

        // Adding 9 signet headers in the chain-state prior validation
        let mut headers = get_test_headers();
        headers.remove(0);
        headers.truncate(9);
        for header in headers {
            chain.accept_header(header).unwrap();
        }

        let config = get_node_config(datadir, network, pow_fraud_proofs);

        let kill_signal = Arc::new(RwLock::new(false));
        let mut node = UtreexoNode::<Arc<ChainState<KvChainStore>>, SyncNode>::new(
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
    use std::collections::HashMap;

    use floresta_chain::pruned_utreexo::BlockchainInterface;
    use floresta_chain::UtreexoBlock;

    use crate::p2p_wire::tests::sync_node::tests_utils::setup_node;
    use crate::p2p_wire::tests::utils::get_essentials;

    #[tokio::test]
    async fn test_sync_valid_blocks() {
        let essentials = get_essentials();
        let chain = setup_node(
            vec![(Vec::new(), essentials.blocks.clone(), HashMap::new())],
            false,
            floresta_chain::Network::Signet,
        )
        .await;

        assert_eq!(chain.get_validation_index().unwrap(), 9);
        assert_eq!(
            chain.get_best_block().unwrap().1,
            essentials.headers[9].block_hash()
        );
        assert!(!chain.is_in_idb());
    }

    #[tokio::test]
    async fn test_sync_invalid_block() {
        // 7th BLOCK IS SET AS INVALID. WHILE CONNECTING THE BLOCKS, 7th BLOCK WILL BE INVALIDATED.
        // HENCE THE CHAIN WILL HAVE A HEIGHT OF 6.

        // THIS SIMULATION WILL TEST:
        // 1) SENDING BLOCK WITH A BADMERKLEROOT: 7TH BLOCK WILL BE INVALIDATED.

        let mut essentials = get_essentials();

        essentials
            .blocks
            .insert(essentials.headers[7].block_hash(), essentials.invalid_block);
        let peer = vec![(Vec::new(), essentials.blocks.clone(), HashMap::new())];
        let chain = setup_node(peer, false, floresta_chain::Network::Signet).await;

        assert_eq!(chain.get_validation_index().unwrap(), 6);
        assert_eq!(
            chain.get_best_block().unwrap().1,
            essentials.headers[6].block_hash()
        );
        assert!(!chain.is_in_idb());
    }

    #[tokio::test]
    async fn test_sync_block_without_udata() {
        // THIS SIMUATION WILL TEST 2 THINGS:
        //
        // 1) SENDING IN THE 3RD BLOCK WITHOUT PROOF: THIS WILL BANN THE PEER
        //
        // 2) SENDING BLOCKS OUT OF ORDER: AFTER ALL THE BLOCKS ARE RECEIVED FROM THE DISHONEST
        //    PEER, WE WILL AGAIN REQUEST FOR THE 3RD BLOCK TO A RANDOM PEER. THE SYNC-NODE WILL
        //    HANDLE IT FINE.
        //
        // SO FINALLY THE LAST VALIDATED BLOCK WILL BE 9.

        let mut essentials = get_essentials();
        let v_blocks = essentials.blocks.clone();

        let u_block = essentials
            .blocks
            .get(&essentials.headers[3].block_hash().clone())
            .unwrap();
        let block = UtreexoBlock {
            block: u_block.block.clone(),
            udata: None,
        };
        essentials
            .blocks
            .insert(essentials.headers[3].block_hash(), block);

        let liar = (Vec::new(), essentials.blocks, HashMap::new());
        let honest1 = (Vec::new(), v_blocks.clone(), HashMap::new());
        let honest2 = (Vec::new(), v_blocks, HashMap::new());

        let chain = setup_node(
            vec![liar, honest1, honest2],
            false,
            floresta_chain::Network::Signet,
        )
        .await;

        assert_eq!(chain.get_validation_index().unwrap(), 9);
        assert_eq!(
            chain.get_best_block().unwrap().1,
            essentials.headers[9].block_hash()
        );
        assert!(!chain.is_in_idb());
    }
}
