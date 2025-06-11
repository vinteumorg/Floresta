//! A fast database for the chainstore
//!
//! In its infancy, floresta-chain used `kv` as database, since `kv` is a small and efficient
//! embedded database that doesn't require any runtime dependency. However, floresta-chain uses the
//! database in a very unusual way: it downloads a bunch of small chunks of data that needs to be
//! indexed and retrieved, all at once (~800k for mainnet at the time of writing). If we simply
//! keep everything in memory, and then make one big batch, most embedded databases will see a big
//! spike in heap usage. This would be OK for regular desktops, but floresta aims to run in small,
//! lower-power devices too, so we can't just assume we have two gigs of RAM to spare. We could make
//! these writes more commonly, but then we reach an I/O bottleneck in those lower-power systems,
//! where usually we won't see high-quality SSDs that can make billions of transfers per second.
//!
//! This chainstore was designed to reduce the over-usage of both. We do rely on any extra RAM as
//! kernel buffers, but we also do a decent level of I/O. We get a better performance by using
//! an ad-hock storage that exploits the fact that the data we keep is canonical and monotonically
//! increasing, so we keep all headers in a simple flat file, one after the other. So `pos(h) = h *
//! size_of(DiskBlockHeader)`, with an overhead factor of 1. We also need a way to map block hashes
//! into the given header, we do this by keeping a persistent, open-addressing hash map that map block
//! hashes -> heights. Then from the height we can work out the block header in the headers file.
//!
//! ## Calculations
//!
//! We want to keep the load factor for the hash map as low as possible, while also avoiding
//! re-hashing. So we pick a fairly big initial space to it, say 10 million buckets. Each bucket is
//! 4 bytes long, so we have 40 MiB of map. Each [HashedDiskHeader] is 116 bytes long (80 bytes for
//! header + 4 for height + 32 for hash), so the maximum size for it, assuming 2.5 million headers
//! (good for the next ~30 years), is 330 MiB. The smallest device I know that can run floresta
//! has ~250 MiB of RAM, so we could  fit almost everything in memory. Given that newer blocks are
//! more likely to be accessed, the OS will keep those in RAM.
//!
//! The longest chain we have right now is testnet, with about 3 million blocks. That yields a load
//! factor of 0.3. With that load factor, there's a ~1/3 probability of collision, we are expected
//! to have a worst-case search ~2. So we'll need to fetch two nodes to find the one we want. Since
//! each node is a u32, most of the time we'll pull the second node too (64 bits machines can't
//! pull 32 bits values from memory). But to avoid going into the map every time, we keep a LRU
//! cache of the last n blocks we've touched.
//!
//! # Good to know
//!
//! A load factor of a hashmap is the relation between empty buckets and buckets that are being used.
//! The load factor is used to express the chance of hash collisions which decreases performance.
//!
//! Buckets are the slots of a hashmap.
//!
//! For more detailed information please refer to [Hash Table] (https://en.wikipedia.org/wiki/Hash_table) from wikipedia.
//!
//! # Safety
//!
//! This is completely reckless and bare-bones, so it needs some safety precautions:
//!     (i): we must make sure that the map and flat file are initialized correctly
//!     (ii): we must make sure that the map won't give us any height greater than the size
//!           of the flat file
//!     (iii): we must make sure that the load factor **never** reaches one
//! i and ii will cause a segfault, iii will turn the addition (or search for non-existent values)
//! an infinite loop. If we are about to reach the map's capacity, we should re-hash with a new
//! capacity.

extern crate std;

use core::mem::size_of;
use core::num::NonZeroUsize;
use std::fs::DirBuilder;
use std::fs::OpenOptions;
use std::fs::Permissions;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::PoisonError;

use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use floresta_common::impl_error_from;
use floresta_common::prelude::*;
use lru::LruCache;
use memmap2::MmapMut;
use memmap2::MmapOptions;
use xxhash_rust::xxh3;

use super::ChainStore;
use crate::BestChain;
use crate::DatabaseError;
use crate::DiskBlockHeader;

/// The magic number we use to make sure we're reading the right file
///
/// This is backwards, because when we look at the hex dump of the file, on little-endian systems,
/// it will show in the correct order.
const FLAT_CHAINSTORE_MAGIC: u32 = 0x74_73_6C_66; // "flst" backwards

/// The version of our flat chain store
const FLAT_CHAINSTORE_VERSION: u32 = 0;

/// We use a LRU cache to keep the last n blocks we've touched, so we don't need to do a map search
/// again. This is the type of our cache
type CacheType = LruCache<BlockHash, DiskBlockHeader>;

/// How long an accumulator is.
///
/// Worst case, we have 64 roots, each with 32 bytes, and a 64 bits integer for the number of
/// leaves. So 32 * 64 + 8 = 2048 + 8 = 2056 bytes
const UTREEXO_ACC_SIZE: usize = 32 * 64 + 8;

#[derive(Clone)]
/// Configuration for our flat chain store. See each field for more information
pub struct FlatChainStoreConfig {
    /// The index map size, in buckets
    ///
    /// This index holds our map from block hashes to block heights. We use an open-addressing hash
    /// map to map block hashes to block heights. Ideally, size should be way bigger than the
    /// number of blocks we expect to have in our chain, therefore reducing the load factor to a
    /// negligible value. The default value is having space for 10 million blocks.
    ///
    /// We compute the actual capacity by rounding the requested size up to the next power of two,
    /// so we can use `hash & (capacity - 1)` instead of `hash % capacity`.
    pub block_index_size: Option<usize>,

    /// The size of the headers file map, in headers
    ///
    /// This is the size of the flat file that holds all of our block headers. We keep all headers
    /// in a simple flat file, one after the other. That file then gets mmaped into RAM, so we can
    /// use pointer arithmetic to find specific block, since pos(h) = h * size_of(DiskBlockHeader)
    /// The default value is having space for 10 million blocks.
    ///
    /// We compute the actual capacity by rounding the requested size up to the next power of two.
    pub headers_file_size: Option<usize>,

    /// The size of the cache, in blocks
    ///
    /// We keep a LRU cache of the last n blocks we've touched. This is to avoid going into the
    /// map every time we need to find a block. The default value is 1000 blocks.
    pub cache_size: Option<usize>,

    /// The permission for all the files we create
    ///
    /// This is the permission we give to all the files we create. The default value is 0o660
    pub file_permission: Option<u32>,

    /// The size of the fork headers file map, in headers
    ///
    /// This store keeps headers that are not in our main chain, but may be needed sometime. The
    /// default value is having space for 10,000 blocks.
    ///
    /// We compute the actual capacity by rounding the requested size up to the next power of two.
    pub fork_file_size: Option<usize>,

    /// The path where we store our files
    ///
    /// We'll create a few files (namely, the index map, headers file, forks file, and metadata file).
    /// We need a directory where we can read and write, it needs at least 880 MiB of free space.
    /// And have a file system that supports mmap and sparse files (all the default *unix FS do).
    pub path: String,
}

impl FlatChainStoreConfig {
    /// Creates a new configuration with the default values
    pub fn new(path: String) -> Self {
        FlatChainStoreConfig {
            file_permission: Some(0o666),
            fork_file_size: Some(10_000),
            path,
            headers_file_size: Some(10_000_000),
            block_index_size: Some(10_000_000),
            cache_size: Some(10_000),
        }
    }
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileChecksum(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The current checksum of our database
struct DbCheckSum {
    /// The checksum of the headers file
    headers_checksum: FileChecksum,

    /// The checksum of the index map
    index_checksum: FileChecksum,

    /// The checksum of the fork headers file
    fork_headers_checksum: FileChecksum,
}

/// A bucket in our index map, holding a pointer to the index.
///
/// This enum indicates whether a given bucket is occupied, and if it is, it holds the respective
/// block header as well.
enum IndexBucket {
    /// This bucket is empty
    ///
    /// If this is a search, this means the entry isn't in the map, and this is where it would be
    Empty { ptr: *mut Index },

    /// This bucket is occupied. We can read or overwrite the index value from the pointer.
    Occupied {
        ptr: *mut Index,
        header: DiskBlockHeader,
    },
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
/// A tagged entry (block height) for our index map
///
/// We use the MSB to mean if this is a block in our main chain (`0`), or a fork (`1`).
/// Inside our main chain headers, we store them sequentially, so we can use the block height
/// as the index in the headers file. For forks, we store them in a separate file, in the order
/// they were received. Therefore, for fork blocks, the LSB for this index has nothing to do with
/// the block height, it's just its position in the fork file.
struct Index(u32);

impl Index {
    /// Mask for the MSB
    const FORK_BIT: u32 = 0x8000_0000;

    /// Mask for the 31 lower bits
    const INDEX_MASK: u32 = 0x7FFF_FFFF;

    /// Create a new mainchain entry (MSB is zero)
    fn new(index: u32) -> Result<Self, FlatChainstoreError> {
        if index >= Self::FORK_BIT {
            // Index value is out of bounds for our 31 bit indexes
            return Err(FlatChainstoreError::IndexTooBig);
        }

        Ok(Index(index))
    }

    /// Create a new fork entry (MSB is set)
    fn new_fork(index: u32) -> Result<Self, FlatChainstoreError> {
        if index >= Self::FORK_BIT {
            // Index value is out of bounds for our 31 bit indexes
            return Err(FlatChainstoreError::IndexTooBig);
        }

        Ok(Index(index | Self::FORK_BIT))
    }

    /// Tells if this is a block in our main chain
    fn is_main_chain(&self) -> bool {
        self.0 & Self::FORK_BIT == 0
    }

    /// Takes only the integer height of the block, without the tag
    fn index(&self) -> u32 {
        self.0 & Self::INDEX_MASK
    }

    /// Tells if this is an empty position (i.e., we haven't written anything here yet, or this is
    /// the mainchain genesis index)
    fn is_empty(&self) -> bool {
        self.0 == 0
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
/// To avoid having to sha256 headers every time we retrieve them, we store the hash along with
/// the header, so we just need to compare the hash to know if we have the right header
struct HashedDiskHeader {
    /// The actual header with contextually relevant information
    header: DiskBlockHeader,

    /// The hash of the header
    hash: BlockHash,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
/// Metadata about our chainstate and the blocks we have. We need this to keep track of the
/// network state, our local validation state and accumulator state
struct Metadata {
    /// A magic number to make sure we're reading the right file and it was initialized correctly
    magic: u32,

    /// The version of our flat chain store
    version: u32,

    /// Hash of the last block in the chain we believe has more work on
    best_block: BlockHash,

    /// How many blocks are pilled on this chain
    depth: u32,

    /// We actually validated blocks up to this point
    validation_index: BlockHash,

    /// Blockchains are not fast-forward only, they might have "forks", sometimes it's useful
    /// to keep track of them, in case they become the best one. This keeps track of some
    /// tips we know about, but are not the best one. We don't keep tips that are too deep
    /// or has too little work if compared to our best one
    alternative_tips: [BlockHash; 64], // we hope to never have more than 64 alt-chains

    /// Saves the height occupied by the assume valid block
    assume_valid_index: u32,

    /// How many blocks we have that are not in our main chain
    fork_count: u32,

    /// How many bytes we have in our accumulator
    acc_size: u32,

    /// Our latest accumulator of the Utreexo forest
    acc: [u8; UTREEXO_ACC_SIZE],

    /// The size of the headers file map, in headers
    headers_file_size: usize,

    /// The size of the fork headers file map, in headers
    fork_file_size: usize,

    /// This holds how much of the index is occupied
    block_index_occupancy: usize,

    /// The capacity of the index, in buckets
    index_capacity: usize,

    /// The checksum of our database, as it was in the last time we've flushed our data
    /// We can use this to check if our database is corrupted
    checksum: DbCheckSum,
}

#[derive(Debug)]
/// An error that can happen when we're dealing with our flat chain store
pub enum FlatChainstoreError {
    /// An I/O error happened
    ///
    /// Check the inner error for more information
    Io(std::io::Error),

    /// We couldn't find the block we were looking for
    NotFound,

    /// The index is full, we can't add more blocks to it
    IndexIsFull,

    /// Tried to open a database that is too new for us
    DbTooNew,

    /// Our cache lock is poisoned
    Poisoned,

    /// We encountered an invalid magic value. Possibly a database corruption
    InvalidMagic,

    /// The provided accumulator is too big
    AccumulatorTooBig,

    /// Tried to create an index more than 31 bits long
    IndexTooBig,

    /// Something wrong happened with the metadata file mmap
    InvalidMetadataPointer,

    /// The database is corrupted
    DbCorrupted,
}

/// Need this to use [FlatChainstoreError] as a [DatabaseError] in [ChainStore]
impl DatabaseError for FlatChainstoreError {}

impl_error_from!(FlatChainstoreError, std::io::Error, Io);

impl From<PoisonError<MutexGuard<'_, CacheType>>> for FlatChainstoreError {
    fn from(_: PoisonError<MutexGuard<'_, CacheType>>) -> Self {
        FlatChainstoreError::Poisoned
    }
}

/// The block index is implemented as a separate struct, to keep the code clean
/// and easy to read. It holds the memory map for the index, and the size of the index
/// in buckets. We keep track of how many buckets are occupied in the metadata file,
/// so we can re-hash the map when it gets full.
struct BlockIndex {
    /// The actual memory map for the index
    index_map: MmapMut,

    /// The maximum size of the index, in buckets
    index_size: usize,
}

impl BlockIndex {
    /// Creates a new block index
    ///
    /// This function should only be called by [FlatChainStore::new], and it should never be called
    /// directly. It creates a new block index, given a memory map for the index map and
    /// its maximum size in buckets.
    fn new(index_map: MmapMut, index_size: usize) -> Self {
        Self {
            index_map,
            index_size,
        }
    }

    /// Flushes the index map to disk
    ///
    /// If we have enough changes that we don't want to lose, we should flush the index map to
    /// disk. This will make sure that the index map is persisted, and we can recover it in case
    /// of a crash.
    fn flush(&self) -> Result<(), FlatChainstoreError> {
        self.index_map.flush()?;

        Ok(())
    }

    /// Updates our index to map a block hash to a block height
    ///
    /// After accepting a new block, this should be updated to tell us in what position in the
    /// chain that block is.
    /// This function returns true if the position was empty, and false if it was occupied, meaning
    /// we are updating an existing entry.
    unsafe fn set_index_for_hash(
        &self,
        hash: BlockHash,
        index: Index,
        get_header_by_index: impl Fn(Index) -> Result<HashedDiskHeader, FlatChainstoreError>,
    ) -> Result<bool, FlatChainstoreError> {
        let pos = self.hash_map_find_pos(hash, get_header_by_index)?;

        match pos {
            IndexBucket::Empty { ptr } => {
                ptr.write(index);
                Ok(true)
            }

            // A position may be re-written if we happen to have a reorg.
            // If this is the case, we should update the fork block to make it into the main chain,
            // and mark the old main chain block as a fork.
            IndexBucket::Occupied { ptr, .. } => {
                ptr.write(index);
                Ok(false)
            }
        }
    }

    /// Returns the block index for a given block hash and its fetched header, if present
    unsafe fn get_index_for_hash(
        &self,
        hash: BlockHash,
        get_header_by_index: impl Fn(Index) -> Result<HashedDiskHeader, FlatChainstoreError>,
    ) -> Result<Option<(Index, DiskBlockHeader)>, FlatChainstoreError> {
        match self.hash_map_find_pos(hash, get_header_by_index)? {
            IndexBucket::Empty { .. } => Ok(None),
            IndexBucket::Occupied { ptr, header } => Ok(Some((*ptr, header))),
        }
    }

    /// Returns the position inside the hash map where a given hash should be
    ///
    /// This function will compute the short hash for this header, look up the position inside the
    /// hash map, and if the position is occupied, return. Keep incrementing the count, until we
    /// either find the record or find a vacant position. If we can't find the original thing, we
    /// return where it would be added in the index. So if you're adding a new record, call this
    /// function (it will return a vacant position) and just write the height there.
    unsafe fn hash_map_find_pos(
        &self,
        block_hash: BlockHash,
        get_header_by_index: impl Fn(Index) -> Result<HashedDiskHeader, FlatChainstoreError>,
    ) -> Result<IndexBucket, FlatChainstoreError> {
        let mut hash = Self::index_hash_fn(block_hash) as usize;

        // Retrieve the base pointer to the start of the memory-mapped index
        let base_ptr = self.index_map.as_ptr() as *mut Index;

        // Since the size is a power of two `2^k`, subtracting one gives a 0b111...1 k-bit mask
        let mask = self.index_size - 1;

        for _ in 0..self.index_size {
            // Obtain the bucket's address by adding the masked hash to the base pointer
            // SAFETY: the masked hash is lower than the `index_size`
            let entry_ptr = base_ptr.add(hash & mask);

            // If this is the first time we've accessed this pointer, this candidate index is 0
            let candidate_index = *entry_ptr;

            // If the header at `candidate_index` matches `block_hash`, this is the target bucket
            let file_header = get_header_by_index(candidate_index)?;
            if file_header.hash == block_hash {
                return Ok(IndexBucket::Occupied {
                    ptr: entry_ptr,
                    header: file_header.header,
                });
            }

            // If we find an empty index, this bucket is where the entry would be added
            // Note: The genesis block doesn't reach this point, as its header hash is matched
            if candidate_index.is_empty() {
                return Ok(IndexBucket::Empty { ptr: entry_ptr });
            }

            // If no match and bucket is occupied, continue probing the next bucket
            hash = hash.wrapping_add(1);
        }

        // If we reach here, it means the index is full. We should re-hash the map
        Err(FlatChainstoreError::IndexIsFull)
    }

    /// The (short) hash function we use to compute where in the map a given block height should be
    ///
    /// In our normal operation, we sometime need to retrieve a header based on a block hash,
    /// rather than height. Block hashes are 256 bits long, so we can't really use them to index
    /// here. Truncating the sha256 is one option, this short hash function will give us a better
    /// randomization over the data, and it's super easy to compute anyways.
    ///
    /// This hash function is based on the Jenkins hash function with non-zero seed.
    fn index_hash_fn(block_hash: BlockHash) -> u32 {
        let mut hash: u32 = (1 << 16) - 1;

        for i in block_hash.to_byte_array() {
            hash = hash.wrapping_add(i as u32);
            hash = hash.wrapping_add(hash << 10);
            hash ^= hash >> 6;
        }

        hash = hash.wrapping_add(hash << 3);
        hash ^= hash >> 11;
        hash = hash.wrapping_add(hash << 15);

        hash
    }
}

/// The main struct that holds all the context for our flat chain store
///
/// This struct is kept in memory, and it holds multiple memory maps that may or may not be
/// in RAM right now. All functions in the impl block are inherently unsafe, since we're dealing
/// with raw pointers and memory maps. We need to be very careful with them. All methods should be
/// carefully tested and reviewed. This struct is not thread-safe, and it's not meant to be used
/// in multi-threaded environments without proper synchronization.
///
/// We only ever expect one chainstate to hold a [FlatChainStore] at a time. You can then use that
/// chainstate to interact with the chainstore, even in a multi-threaded environment.
pub struct FlatChainStore {
    /// The memory map for our headers
    headers: MmapMut,

    /// The memory map for our metadata
    metadata: MmapMut,

    /// The memory map for our block index
    block_index: BlockIndex,

    /// The memory map for our fork files
    fork_headers: MmapMut,

    /// A LRU cache for the last n blocks we've touched
    cache: Mutex<LruCache<BlockHash, DiskBlockHeader>>,
}

impl FlatChainStore {
    /// Creates a new storage, given a configuration
    ///
    /// If any of the I/O operations fail, this function should return an error
    fn create_chain_store(config: FlatChainStoreConfig) -> Result<Self, FlatChainstoreError> {
        let file_mode = config.file_permission.unwrap_or(0o600);
        let dir = &config.path;

        DirBuilder::new().recursive(true).create(dir)?;

        let index_size = config
            .block_index_size
            .map(Self::truncate_to_pow2)
            .unwrap_or(Self::truncate_to_pow2(10_000_000));

        let headers_size = config
            .headers_file_size
            .map(Self::truncate_to_pow2)
            .unwrap_or(Self::truncate_to_pow2(10_000_000));

        let fork_size = config
            .fork_file_size
            .map(Self::truncate_to_pow2)
            .unwrap_or(Self::truncate_to_pow2(10_000));

        let index_path = format!("{dir}/blocks_index.bin");
        let headers_path = format!("{dir}/headers.bin");
        let metadata_path = format!("{dir}/metadata.bin");
        let fork_headers_path = format!("{dir}/fork_headers.bin");

        let index_map_file_size = index_size * size_of::<u32>();
        let index_map = unsafe { Self::init_file(&index_path, index_map_file_size, file_mode)? };

        let headers_file_size = headers_size * size_of::<HashedDiskHeader>();
        let headers = unsafe { Self::init_file(&headers_path, headers_file_size, file_mode)? };

        let metadata =
            unsafe { Self::init_file(&metadata_path, size_of::<Metadata>(), file_mode)? };

        let fork_headers_file_size = fork_size * size_of::<HashedDiskHeader>();
        let fork_headers =
            unsafe { Self::init_file(&fork_headers_path, fork_headers_file_size, file_mode)? };

        let _metadata = metadata.as_ptr() as *mut Metadata;
        let _metadata = unsafe { &mut *_metadata };

        // init the metadata file
        _metadata.magic = FLAT_CHAINSTORE_MAGIC;
        _metadata.version = FLAT_CHAINSTORE_VERSION;
        _metadata.headers_file_size = headers_size;
        _metadata.fork_file_size = fork_size;
        _metadata.index_capacity = index_size;
        _metadata.block_index_occupancy = 0;
        _metadata.acc_size = 0;
        _metadata.acc = [0; UTREEXO_ACC_SIZE];
        _metadata.assume_valid_index = 0;
        _metadata.best_block = BlockHash::all_zeros();
        _metadata.depth = 0;
        _metadata.validation_index = BlockHash::all_zeros();
        _metadata.fork_count = 0;
        _metadata
            .alternative_tips
            .copy_from_slice(&[BlockHash::all_zeros(); 64]);

        _metadata.checksum = DbCheckSum {
            headers_checksum: FileChecksum(0),
            index_checksum: FileChecksum(0),
            fork_headers_checksum: FileChecksum(0),
        };

        let cache_size = config.cache_size.and_then(NonZeroUsize::new).unwrap_or(
            NonZeroUsize::new(1000).expect("Infallible: Hard-coded default is always non-zero"),
        );

        Ok(Self {
            headers,
            metadata,
            block_index: BlockIndex::new(index_map, index_size),
            fork_headers,
            cache: LruCache::new(cache_size).into(),
        })
    }

    /// Opens a new storage. If it already exists, just load. If not, create a new one
    pub fn new(config: FlatChainStoreConfig) -> Result<Self, FlatChainstoreError> {
        let dir = &config.path;
        let metadata_path = format!("{dir}/metadata.bin");

        let file_mode = config.file_permission.unwrap_or(0o600);
        let metadata = unsafe { Self::init_file(&metadata_path, size_of::<Metadata>(), file_mode) };

        let Ok(metadata_file) = metadata else {
            // if we can't get the metadata file, assume it doesn't exist and create
            // a new one
            let mut store = Self::create_chain_store(config)?;
            store.flush()?;

            return Ok(store);
        };

        let metadata = metadata_file.as_ptr() as *const Metadata;
        let metadata = unsafe {
            metadata
                .as_ref()
                .ok_or(FlatChainstoreError::InvalidMetadataPointer)?
        };

        // check the magic number and version
        if metadata.version > FLAT_CHAINSTORE_VERSION {
            return Err(FlatChainstoreError::DbTooNew);
        }

        if metadata.magic != FLAT_CHAINSTORE_MAGIC {
            return Err(FlatChainstoreError::InvalidMagic);
        }

        let index_path = format!("{}/blocks_index.bin", config.path);
        let headers_file_path = format!("{}/headers.bin", config.path);
        let fork_file_path = format!("{}/fork_headers.bin", config.path);

        let index_file_size = metadata.index_capacity * size_of::<u32>();
        let headers_file_size = metadata.headers_file_size * size_of::<HashedDiskHeader>();
        let fork_file_size = metadata.fork_file_size * size_of::<HashedDiskHeader>();

        let index_map = unsafe { Self::init_file(&index_path, index_file_size, file_mode)? };
        let headers = unsafe { Self::init_file(&headers_file_path, headers_file_size, file_mode)? };
        let fork_headers = unsafe { Self::init_file(&fork_file_path, fork_file_size, file_mode)? };
        let cache_size = config.cache_size.and_then(NonZeroUsize::new).unwrap_or(
            NonZeroUsize::new(1000).expect("Infallible: Hard-coded default is always non-zero"),
        );

        Ok(Self {
            headers,
            metadata: metadata_file,
            block_index: BlockIndex::new(index_map, metadata.index_capacity),
            fork_headers,
            cache: LruCache::new(cache_size).into(),
        })
    }

    /// Adds a new entry into the index
    ///
    /// This function will add a new entry into the index, given a block hash and a block height.
    /// It returns an error if the index is full. This function will increment the index
    /// occupancy only if we add a new entry.    
    unsafe fn add_index_entry(
        &self,
        hash: BlockHash,
        index: Index,
    ) -> Result<(), FlatChainstoreError> {
        let metadata = self.get_metadata_mut()?;
        let next_occupancy = metadata.block_index_occupancy + 1;

        if next_occupancy >= metadata.index_capacity {
            return Err(FlatChainstoreError::IndexIsFull);
        }

        let new = self
            .block_index
            .set_index_for_hash(hash, index, |index| self.get_block_header_by_index(index))?;

        // If this function gets called after a reorg, we may be adding a new index for a block
        // hash we already have in the index. This will override the old index, but not increase
        // the index size. This makes sure we won't increase the index size if we don't need to.
        if new {
            metadata.block_index_occupancy = next_occupancy;
        }

        Ok(())
    }

    /// Checks the integrity of our database
    ///
    /// This function will check the integrity of our database by comparing the checksum of the
    /// headers file, index map, and fork headers file with the checksum stored in the metadata.
    ///
    /// As checksum, the [xxHash] of the memory-maped region is used. This is a fast hash function that
    /// is very good at detecting errors in memory. It is not cryptographically secure, but it is
    /// enough for random errors in a file.
    ///
    /// [xxHash]: https://github.com/Cyan4973/xxHash
    fn check_integrity(&self) -> Result<(), FlatChainstoreError> {
        let computed_checksum = self.compute_checksum();
        let metadata = unsafe { self.get_metadata()? };

        if metadata.checksum != computed_checksum {
            return Err(FlatChainstoreError::DbCorrupted);
        }

        Ok(())
    }

    /// Computes a checksum for our database
    fn compute_checksum(&self) -> DbCheckSum {
        // a function that computes the xxHash of a memory map
        let checksum_fn = |mmap: &MmapMut| {
            let mmap_as_slice = mmap.iter().as_slice();
            let hash = xxh3::xxh3_64(mmap_as_slice);

            FileChecksum(hash)
        };

        let headers_checksum = checksum_fn(&self.headers);
        let index_checksum = checksum_fn(&self.block_index.index_map);
        let fork_headers_checksum = checksum_fn(&self.fork_headers);

        DbCheckSum {
            headers_checksum,
            index_checksum,
            fork_headers_checksum,
        }
    }

    /// Truncates a number to the nearest power of 2
    fn truncate_to_pow2(mut n: usize) -> usize {
        if n == 0 {
            return 0;
        }

        n -= 1;
        n |= n >> 1;
        n |= n >> 2;
        n |= n >> 4;
        n |= n >> 8;
        n |= n >> 16;
        n += 1;

        n
    }

    /// Initializes a memory-mapped file with the specified byte size and permissions (mode).
    /// If the underlying file does not exist, it will be created.
    unsafe fn init_file(
        path: &str,
        size: usize,
        mode: u32,
    ) -> Result<MmapMut, FlatChainstoreError> {
        let file = OpenOptions::new()
            // Set read and write access
            .read(true)
            .write(true)
            // Create the file if it doesn't exist
            .create(true)
            .truncate(false)
            .open(path)?;

        #[cfg(unix)]
        {
            let perm = Permissions::from_mode(mode);
            file.set_permissions(perm)?;
        }

        file.set_len(size as u64)?;

        // Return the `MmapMut` instance that represents the file
        Ok(MmapOptions::default().len(size).map_mut(&file)?)
    }

    /// Returns a [HashedDiskHeader] given a block height. This height must be less than or equal to
    /// the total headers inside our storage, or we return the `NotFound` error.
    unsafe fn get_header_by_height(
        &self,
        height: u32,
    ) -> Result<HashedDiskHeader, FlatChainstoreError> {
        let header = self.get_disk_header(height, true)?;

        // Uninitialized memory means we haven't written anything there yet
        if header.hash == BlockHash::all_zeros() {
            return Err(FlatChainstoreError::NotFound);
        }

        Ok(*header)
    }

    unsafe fn get_disk_header(
        &self,
        index: u32,
        mainchain: bool,
    ) -> Result<&HashedDiskHeader, FlatChainstoreError> {
        let metadata = self.get_metadata()?;
        let (max_size, base_ptr) = match mainchain {
            true => (metadata.headers_file_size, self.headers.as_ptr()),
            false => (metadata.fork_file_size, self.fork_headers.as_ptr()),
        };

        let index = index as usize;
        if index >= max_size {
            return Err(FlatChainstoreError::IndexIsFull);
        }

        // SAFETY: we've checked index < max_size
        let ptr = (base_ptr as *const HashedDiskHeader).add(index);

        Ok(&*ptr)
    }

    #[allow(clippy::mut_from_ref)]
    unsafe fn get_disk_header_mut(
        &self,
        index: u32,
        mainchain: bool,
    ) -> Result<&mut HashedDiskHeader, FlatChainstoreError> {
        let metadata = self.get_metadata()?;
        let (max_size, base_ptr) = match mainchain {
            true => (metadata.headers_file_size, self.headers.as_ptr()),
            false => (metadata.fork_file_size, self.fork_headers.as_ptr()),
        };

        let index = index as usize;
        if index >= max_size {
            return Err(FlatChainstoreError::IndexIsFull);
        }

        // SAFETY: we've checked index < max_size
        let ptr = (base_ptr as *mut HashedDiskHeader).add(index);

        Ok(&mut *ptr)
    }

    /// Returns a [HashedDiskHeader] or the `NotFound` error if there's no value at the given index.
    unsafe fn get_block_header_by_index(
        &self,
        index: Index,
    ) -> Result<HashedDiskHeader, FlatChainstoreError> {
        match index.is_main_chain() {
            true => self.get_header_by_height(index.index()),
            false => {
                let header = self.get_disk_header(index.index(), false)?;

                // Uninitialized memory means we haven't written anything there yet
                if header.hash == BlockHash::all_zeros() {
                    return Err(FlatChainstoreError::NotFound);
                }

                Ok(*header)
            }
        }
    }

    unsafe fn get_acc_inner(&self) -> Result<Vec<u8>, FlatChainstoreError> {
        let metadata = self.get_metadata()?;
        let size = metadata.acc_size as usize;

        if size == 0 {
            return Err(FlatChainstoreError::NotFound);
        }

        Ok(metadata.acc[0..size].to_vec())
    }

    unsafe fn do_save_height(&self, best_block: BestChain) -> Result<(), FlatChainstoreError> {
        let metadata = self.get_metadata_mut()?;

        metadata.assume_valid_index = best_block.assume_valid_index;
        metadata.best_block = best_block.best_block;
        metadata.depth = best_block.depth;
        metadata.validation_index = best_block.validation_index;

        assert!(best_block.alternative_tips.len() <= 64);

        metadata
            .alternative_tips
            .as_mut_ptr()
            .copy_from_nonoverlapping(
                best_block.alternative_tips.as_ptr(),
                best_block.alternative_tips.len(),
            );

        Ok(())
    }

    unsafe fn get_best_chain(&self) -> Result<BestChain, FlatChainstoreError> {
        let metadata = self.get_metadata()?;

        Ok(BestChain {
            best_block: metadata.best_block,
            depth: metadata.depth,
            validation_index: metadata.validation_index,
            alternative_tips: metadata
                .alternative_tips
                .into_iter()
                .take_while(|tip| *tip != BlockHash::all_zeros())
                .collect(),
            assume_valid_index: metadata.assume_valid_index,
        })
    }

    /// Returns the block header, given a block hash
    ///
    /// If the header doesn't exist in our index, it'll return an error
    unsafe fn get_header_by_hash(
        &self,
        hash: BlockHash,
    ) -> Result<Option<DiskBlockHeader>, FlatChainstoreError> {
        let result = self
            .block_index
            .get_index_for_hash(hash, |height| self.get_block_header_by_index(height))?
            .map(|idx_and_header| idx_and_header.1);

        Ok(result)
    }

    unsafe fn get_metadata(&self) -> Result<&Metadata, FlatChainstoreError> {
        let ptr = self.metadata.as_ptr() as *const Metadata;

        Ok(ptr
            .as_ref()
            .expect("Infallible: we already validated this pointer"))
    }

    #[allow(clippy::mut_from_ref)]
    unsafe fn get_metadata_mut(&self) -> Result<&mut Metadata, FlatChainstoreError> {
        let ptr = self.metadata.as_ptr() as *mut Metadata;

        Ok(ptr
            .as_mut()
            .expect("Infallible: we already validated this pointer"))
    }

    /// Writes a block header in our storage
    ///
    /// This function will allocate size_of(DiskBlockHeader) bytes in our file and write the raw
    /// header there. May return an error if we can't grow the file
    unsafe fn write_header_to_storage(
        &self,
        header: DiskBlockHeader,
    ) -> Result<(), FlatChainstoreError> {
        let height = header
            .try_height()
            .expect("Infallible: this function is only called for best chain blocks");

        let pos = self.get_disk_header_mut(height, true)?;
        *pos = HashedDiskHeader {
            header,
            hash: header.block_hash(),
        };

        Ok(())
    }

    unsafe fn do_save_roots(&self, roots: Vec<u8>) -> Result<(), FlatChainstoreError> {
        let metadata = self.get_metadata_mut()?;
        let size = roots.len();

        if size > UTREEXO_ACC_SIZE {
            return Err(FlatChainstoreError::AccumulatorTooBig);
        }

        metadata.acc_size = size as u32;
        metadata
            .acc
            .iter_mut()
            .zip(roots.iter())
            .for_each(|(x, y)| *x = *y);

        Ok(())
    }

    /// Saves a block that is not in our main chain
    ///
    /// If called for a reorg, we must make sure that the chain is marked as inactive **before**
    /// marking the new chain as active. This happens because we'll write over the old chain inside
    /// the headers file.
    ///
    /// If we mark a chain as Inactive, when we call get_header_by_index it will return the
    /// main chain index. If we override this position in the headers file, we get a different hash.
    /// The algorithm will think that position is occupied with a different header and therefore
    /// keep looking for a vacant position. Therefore, we'll have one stale index that will never
    /// be used.
    ///
    /// When marking a chain active, because we don't overwrite the fork block (we actually call
    /// update_index before saving the actual header), even if we get an Index to the fork block,
    /// it'll return the same hash. Therefore, our find method will return the right entry that
    /// will be overwritten with the new position.
    ///
    /// Here's an example:
    ///
    /// Say we have the following chain:
    ///
    /// ```text
    /// 1 -> 2 -> 3 -> 4 -> 5
    ///      \ -> 3' -> 4'
    /// ```
    ///
    /// If we want to reorg to the fork chain, we must:
    /// 1. Mark the chain [3, 4, 5] as inactive
    /// 2. Mark the chain [3', 4'] as active
    ///
    /// If we do this in the wrong order, when we try to save, e.g. 3. The index will find a
    /// position for 3 in the main chain, and return the position of 3'. Since 3' is different, the
    /// find algorithm will think this position doesn't exist, returning the next vacant position.
    ///
    /// We will write 3 in a new position, and it should work fine. However, we now have a stale 3
    /// that points to the main chain position where it originally was. This will never be used
    /// again, but will occupy a position in the index. Increasing the load factor for no reason.
    unsafe fn save_fork_block(&self, header: DiskBlockHeader) -> Result<(), FlatChainstoreError> {
        let metadata = self.get_metadata_mut()?;
        let fork_blocks = metadata.fork_count;
        let pos = self.get_disk_header_mut(fork_blocks, false)?;
        let block_hash = header.block_hash();

        *pos = HashedDiskHeader {
            header,
            hash: block_hash,
        };

        let index = Index::new_fork(fork_blocks)?;
        self.add_index_entry(block_hash, index)?;

        metadata.fork_count += 1;

        Ok(())
    }

    unsafe fn do_flush(&self) -> Result<(), FlatChainstoreError> {
        self.headers.flush()?;
        self.block_index.flush()?;
        self.fork_headers.flush()?;

        let checksum = self.compute_checksum();
        let metadata = self.get_metadata_mut()?;

        metadata.checksum = checksum;
        self.metadata.flush()?;
        Ok(())
    }

    #[inline(always)]
    #[doc(hidden)]
    fn get_cache_mut(
        &self,
    ) -> Result<MutexGuard<'_, CacheType>, PoisonError<MutexGuard<'_, CacheType>>> {
        self.cache.lock()
    }
}

impl ChainStore for FlatChainStore {
    type Error = FlatChainstoreError;

    fn check_integrity(&self) -> Result<(), Self::Error> {
        self.check_integrity()
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        unsafe { self.do_flush() }
    }

    fn save_roots(&mut self, roots: Vec<u8>) -> Result<(), Self::Error> {
        unsafe { self.do_save_roots(roots) }
    }

    fn load_roots(&self) -> Result<Option<Vec<u8>>, Self::Error> {
        let acc = unsafe { self.get_acc_inner() };
        match acc {
            Ok(acc) => Ok(Some(acc)),
            Err(FlatChainstoreError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn get_header(&self, block_hash: &BlockHash) -> Result<Option<DiskBlockHeader>, Self::Error> {
        let mut cache = self.get_cache_mut()?;

        if let Some(header) = cache.get(block_hash) {
            return Ok(Some(*header));
        }

        let header = unsafe { self.get_header_by_hash(*block_hash)? };
        if let Some(header) = header {
            cache.put(*block_hash, header);
        }

        Ok(header)
    }

    fn load_height(&self) -> Result<Option<crate::BestChain>, Self::Error> {
        unsafe {
            self.get_best_chain()
                .map(|x| if x.depth == 0 { None } else { Some(x) })
        }
    }

    fn save_height(&mut self, height: &crate::BestChain) -> Result<(), Self::Error> {
        unsafe { self.do_save_height(height.clone()) }
    }

    fn save_header(&mut self, header: &DiskBlockHeader) -> Result<(), Self::Error> {
        let cache = self.get_cache_mut();
        cache?.put(header.block_hash(), *header);

        match header {
            DiskBlockHeader::FullyValid(_, _)
            | DiskBlockHeader::HeadersOnly(_, _)
            | DiskBlockHeader::AssumedValid(_, _) => unsafe {
                self.write_header_to_storage(*header)
            },
            DiskBlockHeader::InFork(_, _)
            | DiskBlockHeader::Orphan(_)
            | DiskBlockHeader::InvalidChain(_) => unsafe { self.save_fork_block(*header) },
        }
    }

    fn get_block_hash(&self, height: u32) -> Result<Option<BlockHash>, Self::Error> {
        unsafe {
            match Self::get_header_by_height(self, height) {
                Ok(header) => Ok(Some(header.hash)),
                Err(FlatChainstoreError::NotFound) => Ok(None),
                Err(e) => Err(e),
            }
        }
    }

    fn update_block_index(&mut self, height: u32, hash: BlockHash) -> Result<(), Self::Error> {
        let index = Index::new(height)?;

        unsafe { self.add_index_entry(hash, index) }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::block::Header;
    use bitcoin::consensus::deserialize;
    use bitcoin::consensus::Decodable;
    use bitcoin::constants::genesis_block;
    use bitcoin::hashes::Hash;
    use bitcoin::Block;
    use bitcoin::BlockHash;
    use bitcoin::Network;
    use xxhash_rust::xxh3;

    use super::FlatChainStore;
    use super::FlatChainstoreError;
    use super::Index;
    use crate::pruned_utreexo::ChainStore;
    use crate::pruned_utreexo::UpdatableChainstate;
    use crate::AssumeValidArg;
    use crate::BestChain;
    use crate::ChainState;
    use crate::DiskBlockHeader;

    #[test]
    fn test_truncate_pow2() {
        assert_eq!(FlatChainStore::truncate_to_pow2(1), 1);
        assert_eq!(FlatChainStore::truncate_to_pow2(2), 2);
        assert_eq!(FlatChainStore::truncate_to_pow2(3), 4);
        assert_eq!(FlatChainStore::truncate_to_pow2(4), 4);
        assert_eq!(FlatChainStore::truncate_to_pow2(5), 8);
        assert_eq!(FlatChainStore::truncate_to_pow2(1023), 1024);
        assert_eq!(FlatChainStore::truncate_to_pow2(1024), 1024);
        assert_eq!(FlatChainStore::truncate_to_pow2(1025), 2048);
        assert_eq!(FlatChainStore::truncate_to_pow2(10_000), 16_384);
        assert_eq!(FlatChainStore::truncate_to_pow2(1_000_000), 1_048_576);
        assert_eq!(FlatChainStore::truncate_to_pow2(1_048_576), 1_048_576);
        assert_eq!(FlatChainStore::truncate_to_pow2(1_048_577), 2_097_152);
        assert_eq!(FlatChainStore::truncate_to_pow2(10_000_000), 16_777_216);
        assert_eq!(
            FlatChainStore::truncate_to_pow2(1_000_000_000),
            1_073_741_824
        );
        assert_eq!(
            FlatChainStore::truncate_to_pow2(1_073_741_824),
            1_073_741_824
        );
        assert_eq!(
            FlatChainStore::truncate_to_pow2(1_073_741_825),
            2_147_483_648
        );
    }

    fn get_test_chainstore() -> FlatChainStore {
        let test_id = rand::random::<u64>();
        let config = super::FlatChainStoreConfig {
            block_index_size: Some(32_768),
            headers_file_size: Some(32_768),
            fork_file_size: Some(10_000), // Will be rounded up to 16,384
            cache_size: Some(10),
            file_permission: Some(0o660),
            path: format!("./tmp-db/{test_id}/"),
        };

        FlatChainStore::new(config).unwrap()
    }

    #[test]
    fn test_create_chainstore() {
        let store = get_test_chainstore();

        store.check_integrity().unwrap();
    }

    #[test]
    // Sanity check
    fn test_checksum() {
        assert_eq!(xxh3::xxh3_64("a".as_bytes()), 0xe6c632b61e964e1f);
        assert_eq!(xxh3::xxh3_64("abc1".as_bytes()), 0xec035b7226cacedf);
        assert_eq!(xxh3::xxh3_64("abc 1".as_bytes()), 0x5740573263e9d84d);
        assert_eq!(xxh3::xxh3_64("Floresta".as_bytes()), 0x066d384879d98e84);
        assert_eq!(xxh3::xxh3_64("floresta".as_bytes()), 0x58d9f8aa416ed680);
        assert_eq!(
            xxh3::xxh3_64("floresta-chain".as_bytes()),
            0x066540290fdae363
        );
    }

    #[test]
    fn test_save_and_retrieve_headers() {
        let mut store = get_test_chainstore();
        let blocks = include_str!("../../testdata/blocks.txt");

        for (i, line) in blocks.lines().enumerate() {
            let block = hex::decode(line).unwrap();
            let block: Block = deserialize(&block).unwrap();

            store
                .save_header(&DiskBlockHeader::FullyValid(block.header, i as u32))
                .unwrap();
            // Map hashes to block indices such that we can later fetch headers from hashes
            // (hash -> index -> header)
            store
                .update_block_index(i as u32, block.block_hash())
                .unwrap();
        }

        for i in 0..151 {
            // Gets the hash by fetching the hashed header
            let hash = store.get_block_hash(i).unwrap().unwrap();
            // Gets the header via the LRU cache, or else via hash -> index -> header
            let header = store.get_header(&hash).unwrap().unwrap();
            // Gets the header via hash -> index -> header
            let header_not_cached = unsafe { store.get_header_by_hash(hash).unwrap().unwrap() };
            assert_eq!(header, header_not_cached);
            assert_eq!(
                header.block_hash(),
                hash,
                "Returned header matches the hash"
            );
            assert_eq!(
                i,
                header.try_height().unwrap(),
                "Returned header has the correct height"
            );

            if i == 0 {
                // Must be the regtest genesis header
                let regtest_genesis = genesis_block(Network::Regtest);
                assert_eq!(regtest_genesis.block_hash(), hash);
                assert_eq!(regtest_genesis.header, *header);
            }
        }
        match store.get_block_hash(151).unwrap() {
            None => (),
            Some(hash) => panic!("Should not have found a block at height 151, hash: {hash}"),
        }
        match store.get_header(&BlockHash::all_zeros()).unwrap() {
            None => (),
            Some(header) => {
                panic!("Should not have found a header with hash all_zeros: {header:?}")
            }
        }

        // Test that the inner header-fetching function returns the proper error for mainnet indices
        unsafe {
            match store.get_block_header_by_index(Index(151)) {
                Err(FlatChainstoreError::NotFound) => (),
                Err(e) => panic!("Unexpected err: {e:?}"),
                Ok(val) => panic!("Should not have found a header at height 151: {val:?}"),
            }
            // Last available position
            match store.get_block_header_by_index(Index(32_767)) {
                Err(FlatChainstoreError::NotFound) => (),
                Err(e) => panic!("Unexpected err: {e:?}"),
                Ok(val) => panic!("Should not have found a header at height 32767: {val:?}"),
            }
            // Exceeds header file capacity
            match store.get_block_header_by_index(Index(32_768)) {
                Err(FlatChainstoreError::IndexIsFull) => (),
                Err(e) => panic!("Unexpected err: {e:?}"),
                Ok(val) => {
                    panic!("Should not have found a header exceeding file capacity: {val:?}")
                }
            }
        }

        // Test that the inner header-fetching function returns the proper error for fork indices
        let mut fork_index = Index::new_fork(0).unwrap();
        unsafe {
            match store.get_block_header_by_index(fork_index) {
                Err(FlatChainstoreError::NotFound) => (),
                Err(e) => panic!("Unexpected err: {e:?}"),
                Ok(val) => panic!("Should not have found any fork header: {val:?}"),
            }
            // Last available position
            fork_index.0 += 16_383;
            match store.get_block_header_by_index(fork_index) {
                Err(FlatChainstoreError::NotFound) => (),
                Err(e) => panic!("Unexpected err: {e:?}"),
                Ok(val) => panic!("Should not have found any fork header: {val:?}"),
            }
            // Exceeds fork file capacity
            fork_index.0 += 1;
            match store.get_block_header_by_index(fork_index) {
                Err(FlatChainstoreError::IndexIsFull) => (),
                Err(e) => panic!("Unexpected err: {e:?}"),
                Ok(val) => {
                    panic!("Should not have found a header exceeding file capacity: {val:?}")
                }
            }
        }
    }

    #[test]
    fn test_save_height() {
        let mut store = get_test_chainstore();
        let height = BestChain {
            alternative_tips: Vec::new(),
            assume_valid_index: 0,
            validation_index: genesis_block(Network::Signet).block_hash(),
            depth: 1,
            best_block: genesis_block(Network::Signet).block_hash(),
        };

        store.save_height(&height).unwrap();

        let recovered = store.load_height().unwrap().unwrap();
        assert_eq!(recovered, height);
    }

    #[test]
    fn test_index() {
        let mut store = get_test_chainstore();
        let mut hashes = Vec::new();
        let blocks = include_str!("../../testdata/blocks.txt");

        for (i, line) in blocks.lines().enumerate() {
            let block = hex::decode(line).unwrap();
            let block: Block = deserialize(&block).unwrap();
            hashes.push(block.block_hash());

            store
                .save_header(&DiskBlockHeader::FullyValid(block.header, i as u32))
                .unwrap();

            store
                .update_block_index(i as u32, block.block_hash())
                .unwrap();
        }

        for hash in hashes {
            if hash == genesis_block(Network::Regtest).block_hash() {
                continue;
            }
            let header = store.get_header(&hash).unwrap().unwrap();

            assert_eq!(header.block_hash(), hash);
        }
    }

    #[test]
    fn accept_mainnet_headers() {
        // Accepts the first 10235 mainnet headers
        let file = include_bytes!("../../testdata/headers.zst");
        let uncompressed: Vec<u8> = zstd::decode_all(std::io::Cursor::new(file)).unwrap();
        let store = get_test_chainstore();
        let chain = ChainState::new(store, Network::Bitcoin, AssumeValidArg::Hardcoded);
        let mut buffer = uncompressed.as_slice();

        while let Ok(header) = Header::consensus_decode(&mut buffer) {
            chain.accept_header(header).unwrap();
        }
    }

    #[test]
    fn accept_first_signet_headers() {
        // Accepts the first 2016 signet headers
        let file = include_bytes!("../../testdata/signet_headers.zst");
        let uncompressed: Vec<u8> = zstd::decode_all(std::io::Cursor::new(file)).unwrap();
        let store = get_test_chainstore();
        let chain = ChainState::new(store, Network::Signet, AssumeValidArg::Hardcoded);
        let mut buffer = uncompressed.as_slice();

        while let Ok(header) = Header::consensus_decode(&mut buffer) {
            chain.accept_header(header).unwrap();
        }
    }

    #[test]
    fn test_fork_blocks() {
        let mut store = get_test_chainstore();
        let file = include_str!("../../testdata/blocks.txt");
        let headers = file
            .lines()
            .map(|x| hex::decode(x).unwrap())
            .collect::<Vec<_>>();

        let (blocks, forks) = headers.split_at(headers.len() / 2);
        for (i, block) in blocks.iter().enumerate() {
            let block: Block = deserialize(block).unwrap();

            store
                .save_header(&DiskBlockHeader::FullyValid(block.header, i as u32))
                .unwrap();

            store
                .update_block_index(i as u32, block.block_hash())
                .unwrap();
        }

        let mut hashes = Vec::new();
        for (i, block) in forks.iter().enumerate() {
            let block: Block = deserialize(block).unwrap();

            hashes.push(block.block_hash());

            store
                .save_header(&DiskBlockHeader::InFork(block.header, i as u32))
                .unwrap();
        }

        for hash in hashes {
            let header = store.get_header(&hash).unwrap().unwrap();

            assert_eq!(header.block_hash(), hash);
        }
    }

    #[test]
    fn test_recover_acc() {
        let test_id = rand::random::<u64>();

        let config = super::FlatChainStoreConfig {
            block_index_size: Some(32_768),
            headers_file_size: Some(32_768),
            fork_file_size: Some(10_000),
            cache_size: Some(10),
            file_permission: Some(0o660),
            path: format!("./tmp-db/{test_id}/"),
        };

        let mut store = FlatChainStore::new(config).unwrap();

        let acc = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        store.save_roots(acc.clone()).unwrap();
        store.flush().unwrap();

        let recovered = store.load_roots().unwrap().unwrap();

        assert_eq!(recovered, acc);

        drop(store);

        let config = super::FlatChainStoreConfig {
            block_index_size: Some(32_768),
            headers_file_size: Some(32_768),
            fork_file_size: Some(10_000),
            cache_size: Some(10),
            file_permission: Some(0o660),
            path: format!("./tmp-db/{test_id}/"),
        };

        let store = FlatChainStore::new(config).unwrap();
        let recovered = store.load_roots().unwrap().unwrap();

        assert_eq!(recovered, acc);
    }
}
