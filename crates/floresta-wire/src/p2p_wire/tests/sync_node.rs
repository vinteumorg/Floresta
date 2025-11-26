#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use bitcoin::Network;
    use floresta_chain::pruned_utreexo::BlockchainInterface;

    use crate::p2p_wire::tests::utils::get_essentials;
    use crate::p2p_wire::tests::utils::setup_node;

    const NUM_BLOCKS: usize = 9;

    #[tokio::test]
    async fn test_sync_valid_blocks() {
        let datadir = format!("./tmp-db/{}.sync_node", rand::random::<u32>());

        let essentials = get_essentials();
        let chain = setup_node(
            vec![(Vec::new(), essentials.blocks.clone(), HashMap::new())],
            false,
            Network::Signet,
            &datadir,
            NUM_BLOCKS,
        )
        .await;

        assert_eq!(chain.get_validation_index().unwrap(), 9);
        assert_eq!(
            chain.get_best_block().unwrap().1,
            essentials.headers[9].block_hash()
        );
        assert!(!chain.is_in_ibd());
    }

    #[tokio::test]
    async fn test_sync_invalid_block() {
        // 7th BLOCK IS SET AS INVALID. WHILE CONNECTING THE BLOCKS, 7th BLOCK WILL BE INVALIDATED.
        // HENCE THE CHAIN WILL HAVE A HEIGHT OF 6.

        // THIS SIMULATION WILL TEST:
        // 1) SENDING BLOCK WITH A BADMERKLEROOT: 7TH BLOCK WILL BE INVALIDATED.

        let datadir = format!("./tmp-db/{}.sync_node", rand::random::<u32>());

        let mut essentials = get_essentials();

        essentials
            .blocks
            .insert(essentials.headers[7].block_hash(), essentials.invalid_block);

        let peer = vec![(Vec::new(), essentials.blocks.clone(), HashMap::new())];
        let chain = setup_node(peer, false, Network::Signet, &datadir, NUM_BLOCKS).await;

        assert_eq!(chain.get_validation_index().unwrap(), 6);
        assert_eq!(
            chain.get_best_block().unwrap().1,
            essentials.headers[6].block_hash()
        );
        assert!(!chain.is_in_ibd());
    }
}
