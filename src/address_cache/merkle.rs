use std::str::FromStr;

use bitcoin::{
    hashes::{sha256, sha256d, Hash, HashEngine},
    Block, Transaction, Txid,
};
#[derive(Debug)]
pub struct MerkleProof {
    target: Txid,
    pos: u64,
    hashes: Vec<sha256d::Hash>,
}
impl MerkleProof {
    fn new() -> Self {
        MerkleProof {
            target: Txid::all_zeros(),
            hashes: vec![],
            pos: 0,
        }
    }
    pub fn from_block_hashes(tx_list: Vec<sha256d::Hash>, target: u64) -> Self {
        let target_hash = tx_list[target as usize];
        let (_, proof) = Self::transverse(tx_list, vec![], target);
        Self {
            target: target_hash.into(),
            pos: target,
            hashes: proof,
        }
    }
    pub fn from_block(block: &Block, target: u64) -> Self {
        let tx_list: Vec<_> = block.txdata.iter().map(|tx| tx.txid().as_hash()).collect();
        Self::from_block_hashes(tx_list, target)
    }
    pub fn verify(&self, root: sha256d::Hash) -> Result<bool, String> {
        let mut computed = self.target.as_hash();
        let mut placement = self.pos;
        for hash in self.hashes.iter() {
            if placement & 1 == 0 {
                computed = Self::parent_hash(&computed, &hash);
            } else {
                computed = Self::parent_hash(&hash, &computed);
            }
            placement >>= 1;
        }

        Ok(root == computed)
    }
    /// Returns the position of a node's parent
    ///```!
    /// Row 3: 14
    ///        |--------------\
    /// Row 2: 12              13
    ///        |-------\       |-------\
    /// Row 1: 08      09      10      11
    ///        |---\   |---\   |---\   |---\
    /// Row 0: 00  01  02  03  04  05  06  07
    ///```
    /// In the above tree, if we need parent for 04, this function returns the index of
    /// 10 (2).
    fn get_parent(pos: u64) -> u64 {
        (pos ^ 1) / 2
    }
    fn get_sibling(pos: u64) -> u64 {
        pos ^ 1
    }
    fn parent_hash(left: &[u8], right: &[u8]) -> sha256d::Hash {
        let mut engine = sha256d::Hash::engine();
        engine.input(left);
        engine.input(right);
        sha256d::Hash::from_engine(engine)
    }

    fn transverse(
        nodes: Vec<sha256d::Hash>,
        mut proof: Vec<sha256d::Hash>,
        target: u64,
    ) -> (Vec<sha256d::Hash>, Vec<sha256d::Hash>) {
        if nodes.len() == 1 {
            return (nodes, proof);
        }
        let mut new_nodes = vec![];

        let sibling = Self::get_sibling(target);
        proof.push(nodes[sibling as usize]);

        let node_count = nodes.len();
        let pairs = if node_count % 2 == 0 {
            node_count / 2
        } else {
            (node_count + 1) / 2
        };
        for idx in 0..pairs {
            if (idx * 2 + 1) == node_count {
                new_nodes.push(Self::parent_hash(&nodes[2 * idx], &nodes[2 * idx]));
            } else {
                new_nodes.push(Self::parent_hash(&nodes[2 * idx], &nodes[2 * idx + 1]));
            }
        }
        Self::transverse(new_nodes, proof, Self::get_parent(target))
    }
}
#[test]
fn test_merkle_root() {
    let hashes = vec![
        "9fe0683d05e5a8ce867712f0f744a1e9893365307d433ab3b8f65dfc59d561de",
        "9e2804f04a9d52ad4b67e10cba631934915a7d6d083126b338dda680522bb602",
        "01ad659d8d3f17e96d54e4240614fad5813a58cc1ac67a336839b0bf6c56f2d3",
        "8627dad7e4df3cc60d1349aac61cae36436423429a12f3df9a1e54a5ca8ee008",
        "5f82784d819f440ee1766d9802d113c54626bd613009cbf699213f49adf2fbbd",
    ];
    let root =
        sha256d::Hash::from_str("ff8fa20a8da05e334d59d257c8ba6f76b31856fafe92afdb51151daa2fe0a240")
            .unwrap();
    let hashes: Vec<_> = hashes
        .iter()
        .map(|txid| sha256d::Hash::from_str(txid).unwrap())
        .collect();
    let proof = MerkleProof::from_block_hashes(hashes, 2);
    assert_eq!(Ok(true), proof.verify(root));
}
