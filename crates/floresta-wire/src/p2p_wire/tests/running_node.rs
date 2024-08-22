#[cfg(test)]
mod tests_utils {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    use bitcoin::block::Header;
    use bitcoin::BlockHash;
    use floresta_chain::AssumeValidArg;
    use floresta_chain::ChainState;
    use floresta_chain::KvChainStore;
    use floresta_chain::UtreexoBlock;
    use tokio::sync::RwLock;
    use tokio::task;

    use crate::mempool::Mempool;
    use crate::node::UtreexoNode;
    use crate::p2p_wire::tests::utils::create_peer;
    use crate::p2p_wire::tests::utils::get_node_config;
    use crate::running_node::RunningNode;

    pub async fn setup_node(
        peers: Vec<(
            Vec<Header>,
            HashMap<BlockHash, UtreexoBlock>,
            HashMap<BlockHash, Vec<u8>>,
        )>,
        pow_fraud_proofs: bool,
        network: floresta_chain::Network,
    ) -> Arc<ChainState<KvChainStore<'static>>> {
        let datadir = format!("./data/{}.sync_node", rand::random::<u32>());
        let chainstore = KvChainStore::new(datadir.clone()).unwrap();
        let mempool = Arc::new(RwLock::new(Mempool::new()));
        let chain = ChainState::new(chainstore, network, AssumeValidArg::Disabled);
        let chain = Arc::new(chain);

        let config = get_node_config(datadir, network, pow_fraud_proofs);

        let mut node = UtreexoNode::<RunningNode, Arc<ChainState<KvChainStore>>>::new(
            config,
            chain.clone(),
            mempool,
            None,
        );

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
        let node = Box::new(node);

        let kill_signal = Arc::new(RwLock::new(false));
        let (sender, _) = futures::channel::oneshot::channel();
        task::spawn(node.run(kill_signal.clone(), sender));

        tokio::time::sleep(Duration::from_secs(4)).await;

        let mut kill_guard = kill_signal.write().await;
        *kill_guard = true;

        chain
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use floresta_chain::pruned_utreexo::BlockchainInterface;

    use super::tests_utils::setup_node;
    use crate::p2p_wire::tests::utils::get_essentials;

    #[tokio::test]
    async fn send_headers() {
        let (_, mut headers, _, blocks, _, _, _) = get_essentials();

        // GONNA WORK WITH ONLY 5 BLOCKS:
        // CREATE A PEER WITH 5 BLOCK HEADERS AND 5 BLOCKS. POW_FRAUD_PROOFS GONNA BE OFF !!
        // FIRST THE CHAIN SELECTOR WILL COMPLETE RUNNING
        // SECONDLY THE SYNC NODE WILL COMPLETE RUNNING
        // THEN FIGURE OUT FOR THE RUNNING NODE

        // FOR DEMO GONNA WORK WITH ONLY ONE PEER

        headers.truncate(5);

        let chain = setup_node(
            vec![(headers.clone(), blocks.clone(), HashMap::new())],
            false,
            floresta_chain::Network::Regtest,
        )
        .await;

        assert_eq!(chain.get_best_block().unwrap().1, headers[4].block_hash());
    }
}
