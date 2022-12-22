use bitcoin::{
    consensus::{Decodable, Encodable},
    hashes::{sha256d, Hash, HashEngine},
    Block, Txid,
};
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct MerkleProof {
    target: Txid,
    pos: u64,
    hashes: Vec<sha256d::Hash>,
}
impl Default for MerkleProof {
    fn default() -> Self {
        Self::new()
    }
}
impl MerkleProof {
    /// Creates an empty proof
    fn new() -> Self {
        MerkleProof {
            target: Txid::all_zeros(),
            hashes: vec![],
            pos: 0,
        }
    }
    /// Returns the hashes for this proof
    pub fn hashes(&self) -> Vec<sha256d::Hash> {
        self.hashes.clone()
    }
    /// Creates a new proof from a list of hashes and a target. Target is a 64 bits
    /// unsigned integer indicating the index of a transaction we with to prove. Note that
    /// this only proves one tx at the time.
    pub fn from_block_hashes(tx_list: Vec<sha256d::Hash>, target: u64) -> Self {
        let target_hash = tx_list[target as usize];
        let (_, proof) = Self::transverse(tx_list, vec![], target);
        Self {
            target: target_hash.into(),
            pos: target,
            hashes: proof,
        }
    }
    /// Same as [MerkleProof::from_block_hashes] but you give a block instead of a list of
    /// hashes.
    pub fn from_block(block: &Block, target: u64) -> Self {
        let tx_list: Vec<_> = block.txdata.iter().map(|tx| tx.txid().as_hash()).collect();
        Self::from_block_hashes(tx_list, target)
    }
    #[allow(unused)]
    /// Verifies a proof by hashing up all nodes until reach a root, and compare `root` with
    /// computed root.
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
    fn get_parent(pos: u64) -> u64 {
        (pos ^ 1) / 2
    }
    /// Returns a node's sibling. This is useful because we have to copy a node's sibling
    /// to proof, so we can compute it's parent.
    fn get_sibling(pos: u64) -> u64 {
        pos ^ 1
    }
    /// Computes the hash of two node's parent, by taking sha256d(left_child | right_child), where |
    /// means byte-wise concatenation.
    fn parent_hash(left: &[u8], right: &[u8]) -> sha256d::Hash {
        let mut engine = sha256d::Hash::engine();
        engine.input(left);
        engine.input(right);
        sha256d::Hash::from_engine(engine)
    }
    /// Iterates over the tree, collecting required nodes for proof, internally we compute
    /// all intermediate nodes, but don't keep them.
    fn transverse(
        nodes: Vec<sha256d::Hash>,
        mut proof: Vec<sha256d::Hash>,
        target: u64,
    ) -> (Vec<sha256d::Hash>, Vec<sha256d::Hash>) {
        // We reached a root. This is the recursion base
        if nodes.len() == 1 {
            return (nodes, proof);
        }
        // Here we store all nodes for the next row
        let mut new_nodes = vec![];
        // Grab a node's sibling. In a Merkle Tree, our target nodes are given, and its parent
        // can be computed using available data. We must only provide a node's sibling, so verifier
        // can get a parent hash.
        let sibling = Self::get_sibling(target);
        proof.push(nodes[sibling as usize]);

        // If the row has a odd number of nodes, we must repeat the last node to force it
        // even.
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

impl Decodable for MerkleProof {
    fn consensus_decode<R: std::io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        let pos = u64::consensus_decode(reader)?;
        let target = Txid::consensus_decode(reader)?;
        let len = u64::consensus_decode(reader)?;
        let mut hashes = vec![];
        for _ in 0..len {
            let hash = sha256d::Hash::consensus_decode(reader)?;
            hashes.push(hash);
        }
        Ok(Self {
            hashes,
            pos,
            target,
        })
    }
}
impl Encodable for MerkleProof {
    fn consensus_encode<W: std::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<usize, std::io::Error> {
        let mut len = 0;
        len += self.pos.consensus_encode(writer)?;
        len += self.target.consensus_encode(writer)?;

        let hashes_len = self.hashes.len() as u64;
        len += hashes_len.consensus_encode(writer)?;

        for hash in self.hashes.iter() {
            len += hash.consensus_encode(writer)?;
        }
        Ok(len)
    }
}
#[cfg(test)]
mod test {
    use crate::address_cache::merkle::MerkleProof;
    use bitcoin::{consensus::deserialize, hashes::sha256d};
    use std::str::FromStr;
    #[test]
    fn test_merkle_root() {
        let hashes = vec![
            "9fe0683d05e5a8ce867712f0f744a1e9893365307d433ab3b8f65dfc59d561de",
            "9e2804f04a9d52ad4b67e10cba631934915a7d6d083126b338dda680522bb602",
            "01ad659d8d3f17e96d54e4240614fad5813a58cc1ac67a336839b0bf6c56f2d3",
            "8627dad7e4df3cc60d1349aac61cae36436423429a12f3df9a1e54a5ca8ee008",
            "5f82784d819f440ee1766d9802d113c54626bd613009cbf699213f49adf2fbbd",
        ];
        let root = sha256d::Hash::from_str(
            "ff8fa20a8da05e334d59d257c8ba6f76b31856fafe92afdb51151daa2fe0a240",
        )
        .unwrap();
        let hashes: Vec<_> = hashes
            .iter()
            .map(|txid| sha256d::Hash::from_str(txid).unwrap())
            .collect();
        let proof = MerkleProof::from_block_hashes(hashes, 2);
        assert_eq!(Ok(true), proof.verify(root));
    }
    #[test]
    fn test_serialization() {
        use bitcoin::consensus::serialize;
        let hashes = vec![
            "9fe0683d05e5a8ce867712f0f744a1e9893365307d433ab3b8f65dfc59d561de",
            "9e2804f04a9d52ad4b67e10cba631934915a7d6d083126b338dda680522bb602",
            "01ad659d8d3f17e96d54e4240614fad5813a58cc1ac67a336839b0bf6c56f2d3",
            "8627dad7e4df3cc60d1349aac61cae36436423429a12f3df9a1e54a5ca8ee008",
            "5f82784d819f440ee1766d9802d113c54626bd613009cbf699213f49adf2fbbd",
        ];
        let root = sha256d::Hash::from_str(
            "ff8fa20a8da05e334d59d257c8ba6f76b31856fafe92afdb51151daa2fe0a240",
        )
        .unwrap();
        let hashes: Vec<_> = hashes
            .iter()
            .map(|txid| sha256d::Hash::from_str(txid).unwrap())
            .collect();

        let proof = MerkleProof::from_block_hashes(hashes, 2);
        let ser_proof = serialize(&proof);
        let de_proof = deserialize::<MerkleProof>(&ser_proof);

        assert!(de_proof.is_ok());

        let de_proof = de_proof.unwrap();
        assert_eq!(de_proof, proof);
        assert!(de_proof.verify(root).unwrap());
    }
}
