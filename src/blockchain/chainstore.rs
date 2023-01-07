// Written in 2022 by Davidson Souza

//! This is a basic kv database that stores all metadata about our blockchain and utreexo
//! state.
//! Author: Davidson Souza
type Result<T> = std::result::Result<T, kv::Error>;

use std::ops::Deref;

use bitcoin::{
    consensus::{deserialize, serialize, Decodable, Encodable},
    BlockHash, BlockHeader,
};
#[derive(Debug)]
pub enum DiskBlockHeader {
    FullyValid(BlockHeader, u32),
    Orphan(BlockHeader),
    HeadersOnly(BlockHeader, u32),
}
impl DiskBlockHeader {
    pub fn block_hash(&self) -> BlockHash {
        match self {
            DiskBlockHeader::FullyValid(header, _) => header.block_hash(),
            DiskBlockHeader::Orphan(header) => header.block_hash(),
            DiskBlockHeader::HeadersOnly(header, _) => header.block_hash(),
        }
    }
}
impl Deref for DiskBlockHeader {
    type Target = BlockHeader;
    fn deref(&self) -> &Self::Target {
        match self {
            DiskBlockHeader::FullyValid(header, _) => header,
            DiskBlockHeader::Orphan(header) => header,
            DiskBlockHeader::HeadersOnly(header, _) => header,
        }
    }
}
impl Decodable for DiskBlockHeader {
    fn consensus_decode<R: std::io::Read + ?Sized>(
        reader: &mut R,
    ) -> std::result::Result<Self, bitcoin::consensus::encode::Error> {
        let tag = u8::consensus_decode(reader)?;
        let header = BlockHeader::consensus_decode(reader)?;

        match tag {
            0x00 => {
                let height = u32::consensus_decode(reader)?;
                Ok(Self::FullyValid(header, height))
            }
            0x01 => Ok(Self::Orphan(header)),
            0x02 => {
                let height = u32::consensus_decode(reader)?;
                Ok(Self::HeadersOnly(header, height))
            }
            _ => unreachable!(),
        }
    }
}
impl Encodable for DiskBlockHeader {
    fn consensus_encode<W: std::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> std::result::Result<usize, std::io::Error> {
        let len = 80 + 1 + 4; // Header + tag + hight
        match self {
            DiskBlockHeader::FullyValid(header, height) => {
                0x00_u8.consensus_encode(writer)?;
                header.consensus_encode(writer)?;
                height.consensus_encode(writer)?;
            }
            DiskBlockHeader::Orphan(header) => {
                0x01_u8.consensus_encode(writer)?;
                header.consensus_encode(writer)?;
            }
            DiskBlockHeader::HeadersOnly(header, height) => {
                0x02_u8.consensus_encode(writer)?;
                header.consensus_encode(writer)?;
                height.consensus_encode(writer)?;
            }
        };
        Ok(len)
    }
}
use kv::{Config, Integer, Store};

use super::chain_state::BestChain;
pub trait ChainStore {
    /// Saves the current state of our accumulator.
    fn save_roots(&self, roots: Vec<u8>) -> Result<()>;
    /// Loads the state of our accumulator.
    fn load_roots(&self) -> Result<Option<Vec<u8>>>;
    /// Loads the blockchain height
    fn load_height(&self) -> Result<Option<BestChain>>;
    fn save_height(&self, height: &BestChain) -> Result<()>;
    fn get_header(&self, block_hash: &BlockHash) -> Result<Option<DiskBlockHeader>>;
    fn save_header(&self, header: &DiskBlockHeader, height: u32) -> Result<()>;
    fn get_block_hash(&self, height: u32) -> Result<Option<BlockHash>>;
    fn flush(&self) -> Result<()>;
}

pub struct KvChainStore(Store);
impl KvChainStore {
    pub fn new(datadir: String) -> Result<KvChainStore> {
        // Configure the database
        let cfg = Config::new(datadir + "/chain_data").cache_capacity(100_000_000);

        // Open the key/value store
        let store = Store::new(cfg)?;

        Ok(KvChainStore(store))
    }
}
impl ChainStore for KvChainStore {
    fn load_roots(&self) -> Result<Option<Vec<u8>>> {
        let bucket = self.0.bucket::<&str, Vec<u8>>(None)?;
        bucket.get(&"roots")
    }
    fn save_roots(&self, roots: Vec<u8>) -> Result<()> {
        let bucket = self.0.bucket::<&str, Vec<u8>>(None)?;

        bucket.set(&"roots", &roots)?;
        Ok(())
    }

    fn load_height(&self) -> Result<Option<BestChain>> {
        let bucket = self.0.bucket::<&str, Vec<u8>>(None)?;
        let height = bucket.get(&"height")?;

        if let Some(height) = height {
            return Ok(Some(deserialize(&height).unwrap()));
        }
        Ok(None)
    }

    fn save_height(&self, height: &BestChain) -> Result<()> {
        let bucket = self.0.bucket::<&str, Vec<u8>>(None)?;
        let height = serialize(height);
        bucket.set(&"height", &height)?;
        Ok(())
    }
    fn get_header(&self, block_hash: &BlockHash) -> Result<Option<DiskBlockHeader>> {
        let bucket = self.0.bucket::<&[u8], Vec<u8>>(Some("header"))?;
        let block_hash = serialize(&block_hash);

        let header = bucket.get(&&*block_hash)?;
        if let Some(header) = header {
            return Ok(Some(deserialize(&header).unwrap()));
        }
        Ok(None)
    }
    fn flush(&self) -> Result<()> {
        // Flush the header bucket
        let bucket = self.0.bucket::<&[u8], Vec<u8>>(Some("header"))?;
        bucket.flush()?;
        // Flush the block index
        let bucket = self.0.bucket::<&[u8], Vec<u8>>(Some("index"))?;
        bucket.flush()?;
        // Flush the default bucket with meta-info
        let bucket = self.0.bucket::<&[u8], Vec<u8>>(None)?;
        bucket.flush()?;

        Ok(())
    }
    fn save_header(&self, header: &DiskBlockHeader, height: u32) -> Result<()> {
        let ser_header = serialize(header);
        let block_hash = serialize(&header.block_hash());
        let bucket = self.0.bucket::<&[u8], Vec<u8>>(Some("header"))?;
        bucket.set(&&*block_hash, &ser_header)?;

        let bucket = self.0.bucket::<Integer, Vec<u8>>(Some("index"))?;
        bucket.set(&Integer::from(height), &block_hash)?;
        Ok(())
    }

    fn get_block_hash(&self, height: u32) -> Result<Option<BlockHash>> {
        let bucket = self.0.bucket::<Integer, Vec<u8>>(Some("index"))?;
        let block = bucket.get(&Integer::from(height))?;
        if let Some(block) = block {
            return Ok(Some(deserialize(&block).unwrap()));
        }
        Ok(None)
    }
}
