// Written in 2022 by Davidson Souza

//! This is a basic kv database that stores all metadata about our blockchain and utreexo
//! state.
use bitcoin::block::Header as BlockHeader;
use bitcoin::consensus::deserialize;
use bitcoin::consensus::serialize;
use bitcoin::consensus::Decodable;
use bitcoin::consensus::Encodable;
use bitcoin::BlockHash;

use crate::prelude::*;
#[derive(Debug)]
pub enum DiskBlockHeader {
    FullyValid(BlockHeader, u32),
    Orphan(BlockHeader),
    HeadersOnly(BlockHeader, u32),
    InFork(BlockHeader, u32),
    InvalidChain(BlockHeader),
}
impl DiskBlockHeader {
    pub fn block_hash(&self) -> BlockHash {
        self.deref().block_hash()
    }
    pub fn height(&self) -> Option<u32> {
        match self {
            DiskBlockHeader::FullyValid(_, height) => Some(*height),
            DiskBlockHeader::Orphan(_) => None,
            DiskBlockHeader::HeadersOnly(_, height) => Some(*height),
            DiskBlockHeader::InFork(_, height) => Some(*height),
            DiskBlockHeader::InvalidChain(_) => None,
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
            DiskBlockHeader::InFork(header, _) => header,
            DiskBlockHeader::InvalidChain(header) => header,
        }
    }
}
impl Decodable for DiskBlockHeader {
    fn consensus_decode<R: Read + ?Sized>(
        reader: &mut R,
    ) -> core::result::Result<Self, bitcoin::consensus::encode::Error> {
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
            0x03 => {
                let height = u32::consensus_decode(reader)?;

                Ok(Self::InFork(header, height))
            }
            0x04 => Ok(Self::InvalidChain(header)),
            _ => unreachable!(),
        }
    }
}
impl Encodable for DiskBlockHeader {
    fn consensus_encode<W: Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> core::result::Result<usize, ioError> {
        let mut len = 80 + 1; // Header + tag + height
        match self {
            DiskBlockHeader::FullyValid(header, height) => {
                0x00_u8.consensus_encode(writer)?;
                header.consensus_encode(writer)?;
                height.consensus_encode(writer)?;
                len += 4;
            }
            DiskBlockHeader::Orphan(header) => {
                0x01_u8.consensus_encode(writer)?;
                header.consensus_encode(writer)?;
            }
            DiskBlockHeader::HeadersOnly(header, height) => {
                0x02_u8.consensus_encode(writer)?;
                header.consensus_encode(writer)?;
                height.consensus_encode(writer)?;
                len += 4;
            }
            DiskBlockHeader::InFork(header, height) => {
                0x03_u8.consensus_encode(writer)?;
                header.consensus_encode(writer)?;
                height.consensus_encode(writer)?;
                len += 4;
            }
            DiskBlockHeader::InvalidChain(header) => {
                0x04_u8.consensus_encode(writer)?;
                header.consensus_encode(writer)?;
            }
        };
        Ok(len)
    }
}
use kv::Config;
use kv::Integer;
use kv::Store;

use super::chain_state::BestChain;
use super::ChainStore;
pub struct KvChainStore(Store);
impl KvChainStore {
    pub fn new(datadir: String) -> Result<KvChainStore, kv::Error> {
        // Configure the database
        let cfg = Config::new(datadir + "/chain_data").cache_capacity(100_000_000);

        // Open the key/value store
        let store = Store::new(cfg)?;

        Ok(KvChainStore(store))
    }
}
impl ChainStore for KvChainStore {
    type Error = kv::Error;
    fn load_roots(&self) -> Result<Option<Vec<u8>>, Self::Error> {
        let bucket = self.0.bucket::<&str, Vec<u8>>(None)?;
        bucket.get(&"roots")
    }
    fn save_roots(&self, roots: Vec<u8>) -> Result<(), Self::Error> {
        let bucket = self.0.bucket::<&str, Vec<u8>>(None)?;

        bucket.set(&"roots", &roots)?;
        Ok(())
    }

    fn load_height(&self) -> Result<Option<BestChain>, Self::Error> {
        let bucket = self.0.bucket::<&str, Vec<u8>>(None)?;
        let height = bucket.get(&"height")?;
        if let Some(height) = height {
            return Ok(Some(deserialize(&height).unwrap()));
        }
        Ok(None)
    }

    fn save_height(&self, height: &BestChain) -> Result<(), Self::Error> {
        let bucket = self.0.bucket::<&str, Vec<u8>>(None)?;
        let height = serialize(height);

        bucket.set(&"height", &height)?;

        Ok(())
    }
    fn get_header(&self, block_hash: &BlockHash) -> Result<Option<DiskBlockHeader>, Self::Error> {
        let bucket = self.0.bucket::<&[u8], Vec<u8>>(Some("header"))?;
        let block_hash = serialize(&block_hash);

        let header = bucket.get(&&*block_hash)?;
        if let Some(header) = header {
            return Ok(Some(deserialize(&header).unwrap()));
        }

        Ok(None)
    }
    fn flush(&self) -> Result<(), Self::Error> {
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
    fn save_header(&self, header: &DiskBlockHeader) -> Result<(), Self::Error> {
        let ser_header = serialize(header);
        let block_hash = serialize(&header.block_hash());
        let bucket = self.0.bucket::<&[u8], Vec<u8>>(Some("header"))?;
        bucket.set(&&*block_hash, &ser_header)?;
        Ok(())
    }

    fn get_block_hash(&self, height: u32) -> Result<Option<BlockHash>, Self::Error> {
        let bucket = self.0.bucket::<Integer, Vec<u8>>(Some("index"))?;
        let block = bucket.get(&Integer::from(height))?;
        if let Some(block) = block {
            return Ok(Some(deserialize(&block).unwrap()));
        }
        Ok(None)
    }

    fn update_block_index(&self, height: u32, hash: BlockHash) -> Result<(), Self::Error> {
        let bucket = self.0.bucket::<Integer, Vec<u8>>(Some("index"))?;
        let block_hash = serialize(&hash);

        bucket.set(&Integer::from(height), &block_hash)?;
        Ok(())
    }
}
