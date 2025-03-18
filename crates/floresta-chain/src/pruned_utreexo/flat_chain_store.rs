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
//! 4 bytes long, so we have 40 MiB of map. Each [DiskBlockHeader] is 84 bytes long,
//! so the maximum size for it, assuming 10 million headers, is 84 MiB So 40 + 84 = 134 MiB.
//! The smallest device I know that can run floresta has ~250 MiB of RAM, so we could fit both
//! the index and flat file in RAM all the time. Moreover, we have some newer CPUs that have over a
//! 100MB of L3 cache, we could fit all of this in the L3 cache of some future CPU, and make the
//! process a whole lot faster.
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
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::PoisonError;

use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use floresta_common::impl_error_from;
use lru::LruCache;
use memmap2::MmapMut;
use memmap2::MmapOptions;

use super::ChainStore;
use crate::BestChain;
use crate::DatabaseError;
use crate::DiskBlockHeader;

/// The magic number we use to make sure we're reading the right file
const FLAT_CHAINSTORE_MAGIC: u32 = 0x66_6C_73_74; // "flst"

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
    /// When computing the size in bytes, we will round the number to the nearest power of 2, minus
    /// 1. This lets us do some optimizations like use & instead of %, and use << instead of *.
    pub index_mmap_size: Option<usize>,

    /// The size of the headers file map, in headers
    ///
    /// This is the size of the flat file that holds all of our block headers. We keep all headers
    /// in a simple flat file, one after the other. That file then gets mmaped into RAM, so we can
    /// use pointer arithmetic to find specific block, since pos(h) = h * size_of(DiskBlockHeader)
    /// The default value is having space for 10 million blocks.
    ///
    /// When computing the size in bytes, we will round the number to the nearest power of 2, minus
    /// 1. This lets us do some optimizations like use & instead of %, and use << instead of *.
    pub headers_file_map_size: Option<usize>,

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
    /// default value is having space for 1000 million blocks.
    ///
    /// When computing the size in bytes, we will round the number to the nearest power of 2, minus
    /// 1. This lets us do some optimizations like use & instead of %, and use << instead of *.
    pub fork_file_map_size: Option<usize>,

    /// The path where we store our files
    ///
    /// We'll create a few files (namely, the index map, headers file, forks file, and metadata file).
    /// We need a directory where we can read and write, it needs at least 250 MiB of free space.
    /// And have a file system that supports mmap and sparse files (all the default *unix FS do).
    pub path: String,
}

/// An entry in our index map
///
/// This entry will tell whether a given bucket is occupied or not, and if this is, what is the
/// block height that is stored there.
pub enum Entry {
    /// This bucket is empty
    ///
    /// Is this is a search, this means the entry isn't in the map, and this is where it would be
    Empty(*mut IndexEntry),

    /// This bucket is occupied. We can read the value from here
    Occupied(*mut IndexEntry),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
/// A tagged entry for our index
///
/// We use the MSB to mean if this is a block in our main chain, or a fork.
pub struct IndexEntry(u32);

impl IndexEntry {
    /// Create a new, non-tagged entry
    pub fn new(index: u32) -> Self {
        Self(index)
    }

    /// Tells if this is a block in our main chain
    pub fn is_main_chain(&self) -> bool {
        self.0 & 0x8000_0000 == 0
    }

    /// Takes only the integer height of the block, without the tag
    pub fn index(&self) -> u32 {
        self.0 & 0x7FFF_FFFF
    }

    /// Sets the tag to mean this is a block in our main chain
    pub fn set_main_chain(&mut self) {
        self.0 &= 0x7FFF_FFFF;
    }

    /// Sets the tag to mean this is a block in a fork
    pub fn set_fork(&mut self) {
        self.0 |= 0x8000_0000;
    }

    /// Tells if this is an empty position (i.e., we haven't written anything here yet)
    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }

    /// Tells if this position is occupied
    pub fn is_occupied(&self) -> bool {
        self.0 != 0
    }
}

#[derive(Debug)]
/// To avoid having to sha256 headers every time we retrieve them, we store the hash along with
/// the header, so we just need to compare the hash to know if we have the right header
pub struct DiskBlockHeaderAndHash {
    /// The actual header with contextually relevant information
    header: DiskBlockHeader,

    /// The hash of the header
    hash: BlockHash,
}

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
    headers_file_map_size: usize,

    /// The size of the fork headers file map, in headers
    fork_file_map_size: usize,

    /// The index map size, in buckets
    index_mmap_size: usize,

    /// The capacity of the index, in buckets
    index_capacity: usize,
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
}

/// Need this to use [FlatChainstoreError] as a [DatabaseError] in [ChainStore]
impl DatabaseError for FlatChainstoreError {}

impl_error_from!(FlatChainstoreError, std::io::Error, Io);

impl From<PoisonError<MutexGuard<'_, CacheType>>> for FlatChainstoreError {
    fn from(_: PoisonError<MutexGuard<'_, CacheType>>) -> Self {
        FlatChainstoreError::Poisoned
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
    headers_map: MmapMut,

    /// The memory map for our metadata
    metadata_map: MmapMut,

    /// The memory map for our block index
    block_index: BlockIndex,

    /// The memory map for our fork files
    fork_headers: MmapMut,

    /// A LRU cache for the last n blocks we've touched
    cache: Mutex<LruCache<BlockHash, DiskBlockHeader>>,
}

/// The block index is implemented as a separate struct, to keep the code clean
/// and easy to read. It holds the memory map for the index, and the size of the index
/// in buckets. It also keeps track of how many buckets are occupied, so we can re-hash
/// the map when it gets full.
pub struct BlockIndex {
    /// The actual memory map for the index
    index_map: MmapMut,

    /// The size of the index in buckets
    ///
    /// This is the index capacity (how many blocks we can store in the index), not the actual
    /// number of blocks we have in the index. The size should be greater than the number of blocks
    /// we inserted in the index. If they are equal, we should re-hash the index.
    index_size: usize,

    /// How many buckets are occupied
    occupied: usize,
}

impl BlockIndex {
    /// Creates a new block index
    ///
    /// This function should only be called by [FlatChainStore::new], and it should never be called
    /// directly. It creates a new block index, given a memory map for the index, the size of the
    /// index in buckets, and how many buckets are occupied.
    pub(super) fn new(index_map: MmapMut, index_size: usize, occupied: usize) -> Self {
        Self {
            index_map,
            index_size,
            occupied,
        }
    }

    /// Flushes the index map to disk
    ///
    /// If we have enough changes that we don't want to lose, we should flush the index map to
    /// disk. This will make sure that the index map is persisted, and we can recover it in case
    /// of a crash.
    pub(super) fn flush(&self) -> Result<(), FlatChainstoreError> {
        self.index_map.flush()?;

        Ok(())
    }

    /// Updates our index to map a block hash to a block height
    ///
    /// After accepting a new block, this should be updated to tell us in what position in the
    /// chain that block is.
    unsafe fn set_index_for_hash(
        &self,
        hash: BlockHash,
        index: IndexEntry,
        get_block_header_by_height: impl Fn(
            IndexEntry,
        )
            -> Result<DiskBlockHeaderAndHash, FlatChainstoreError>,
    ) -> Result<(), FlatChainstoreError> {
        if self.occupied == self.index_size {
            return Err(FlatChainstoreError::IndexIsFull);
        }

        let pos = self.hash_map_find_pos(hash, get_block_header_by_height)?;

        match pos {
            // A position may be re-written if we happen to have a fork.
            // If this is the case, we should update the fork block to make it into the main chain,
            // and mark the old main chain block as a fork.
            Entry::Empty(pos) | Entry::Occupied(pos) => pos.write(index),
        }

        Ok(())
    }

    /// Return the block height of a given block hash
    unsafe fn get_index_for_hash(
        &self,
        hash: BlockHash,
        get_block_header_by_height: impl Fn(
            IndexEntry,
        )
            -> Result<DiskBlockHeaderAndHash, FlatChainstoreError>,
    ) -> Result<Option<IndexEntry>, FlatChainstoreError> {
        match self.hash_map_find_pos(hash, get_block_header_by_height)? {
            Entry::Empty(_) => Ok(None),
            Entry::Occupied(index) => Ok(Some(*index)),
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
        get_block_header_by_height: impl Fn(
            IndexEntry,
        )
            -> Result<DiskBlockHeaderAndHash, FlatChainstoreError>,
    ) -> Result<Entry, FlatChainstoreError> {
        // Rads may loop forever if the index is full
        if self.occupied == self.index_size {
            return Err(FlatChainstoreError::IndexIsFull);
        }

        let mut hash = Self::index_hash_fn(block_hash) as usize;

        // Retrieve the base pointer to the start of the memory-mapped index
        let base_ptr = self.index_map.as_ptr();

        loop {
            // Apply a mask to ensure the value is within the valid range of buckets. Then multiply
            // by 4 to get the byte offset, since each bucket maps to 4 bytes (an u32 index/height)
            let byte_offset = (hash & self.index_size) * size_of::<u32>();

            // Obtain the bucket's address by adding the byte offset to the base pointer
            let entry_ptr = base_ptr.wrapping_add(byte_offset) as *mut IndexEntry;

            let index = (*entry_ptr).index();

            let header = get_block_header_by_height(*entry_ptr)?;

            if header.hash == block_hash {
                return Ok(Entry::Occupied(entry_ptr));
            }

            if index == 0 {
                return Ok(Entry::Empty(entry_ptr));
            }

            // If no match and bucket is occupied, continue probing the next bucket
            hash += 1;
        }
    }

    /// The (short) hash function we use to compute where in the map a given block height should be
    ///
    /// In our normal operation, we sometime need to retrieve a header based on a block hash,
    /// rather than height. Block hashes are 256 bits long, so we can't really use them to index
    /// here. Truncating the sha256 is one option, this short hash function will give us a better
    /// randomization over the data, and it's super easy to compute anyways.
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

    unsafe fn unset_index_pos(&self, header: DiskBlockHeader) -> Result<(), FlatChainstoreError> {
        let pos = self.hash_map_find_pos(header.block_hash(), |_| {
            Ok(DiskBlockHeaderAndHash {
                header,
                hash: header.block_hash(),
            })
        })?;

        match pos {
            Entry::Empty(_) => {}
            Entry::Occupied(pos) => pos.write(IndexEntry::new(0)),
        }

        Ok(())
    }
}

/// Since store is just an unpinned, context independent struct. We can send it between threads
/// without problem. We can **not** use it in multiple threads at the same time, though. So no
/// Sync for it.
unsafe impl Send for FlatChainStore {}

impl FlatChainStore {
    /// Creates a new storage, given a configuration
    ///
    /// If any of the I/O operations fail, this function should return an error
    pub fn create_chain_store(config: FlatChainStoreConfig) -> Result<Self, FlatChainstoreError> {
        let file_mode = config.file_permission.unwrap_or(0o600);

        DirBuilder::new().recursive(true).create(&config.path)?;

        let index_size = config
            .index_mmap_size
            .map(|n| Self::truncate_to_pow2(n) - 1)
            .unwrap_or(268435455);

        let headers_size = config
            .headers_file_map_size
            .map(|n| Self::truncate_to_pow2(n) - 1)
            .unwrap_or(268435455);

        let fork_size = config
            .fork_file_map_size
            .map(|n| Self::truncate_to_pow2(n) - 1)
            .unwrap_or(262143);

        let index_file = format!("{}/blocks_index.bin", config.path);

        let headers_file = format!("{}/headers.bin", config.path);

        let metadata_file = format!("{}/metadata.bin", config.path);

        let fork_file = format!("{}/fork_headers.bin", config.path);

        let index_map_file_size = index_size * size_of::<u32>();

        let index_map = unsafe {
            Self::init_file(&PathBuf::from(&index_file), index_map_file_size, file_mode)?
        };

        let headers_map_size = headers_size * size_of::<DiskBlockHeaderAndHash>();

        let headers_map =
            unsafe { Self::init_file(&PathBuf::from(&headers_file), headers_map_size, file_mode)? };

        let metadata_map = unsafe {
            Self::init_file(
                &PathBuf::from(&metadata_file),
                size_of::<Metadata>(),
                file_mode,
            )?
        };

        let fork_headers_size = fork_size * size_of::<DiskBlockHeaderAndHash>();

        let fork_headers =
            unsafe { Self::init_file(&PathBuf::from(&fork_file), fork_headers_size, file_mode)? };

        Ok(Self {
            headers_map,
            metadata_map,
            block_index: BlockIndex::new(index_map, index_size, 0),
            fork_headers,
            cache: LruCache::new(NonZeroUsize::new(config.cache_size.unwrap_or(1024)).unwrap())
                .into(),
        })
    }

    /// Opens a new storage. If it already exists, just load. If not, create a new one
    pub fn new(config: FlatChainStoreConfig) -> Result<Self, FlatChainstoreError> {
        let metadata_file = format!("{}/metadata.bin", config.path);

        let file_mode = config.file_permission.unwrap_or(0o600);

        let metadata_map = match unsafe {
            Self::init_file(
                &PathBuf::from(&metadata_file),
                size_of::<Metadata>(),
                file_mode,
            )
        } {
            Ok(map) => map,
            Err(_) => return Self::create_chain_store(config),
        };

        // check the magic number and version
        let metadata = metadata_map.as_ptr() as *const Metadata;

        let metadata = unsafe { metadata.as_ref().unwrap() };

        if metadata.magic != FLAT_CHAINSTORE_MAGIC {
            if metadata.version > FLAT_CHAINSTORE_VERSION {
                return Err(FlatChainstoreError::DbTooNew);
            }

            return Self::create_chain_store(config);
        }

        let index_file = format!("{}/blocks_index.bin", config.path);

        let headers_file = format!("{}/headers.bin", config.path);

        let fork_file = format!("{}/fork_headers.bin", config.path);

        let index_size = metadata.index_mmap_size * size_of::<u32>();

        let headers_size = metadata.headers_file_map_size * size_of::<DiskBlockHeaderAndHash>();

        let fork_size = metadata.fork_file_map_size * size_of::<DiskBlockHeaderAndHash>();

        let index_map =
            unsafe { Self::init_file(&PathBuf::from(&index_file), index_size, file_mode)? };

        let headers_map =
            unsafe { Self::init_file(&PathBuf::from(&headers_file), headers_size, file_mode)? };

        let fork_headers =
            unsafe { Self::init_file(&PathBuf::from(&fork_file), fork_size, file_mode)? };

        Ok(Self {
            headers_map,
            metadata_map,
            block_index: BlockIndex::new(
                index_map,
                metadata.index_capacity,
                metadata.index_mmap_size,
            ),
            fork_headers,
            cache: LruCache::new(NonZeroUsize::new(config.cache_size.unwrap_or(1000)).unwrap())
                .into(),
        })
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

    unsafe fn init_file(
        path: &PathBuf,
        size: usize,
        mode: u32,
    ) -> Result<MmapMut, FlatChainstoreError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;

        #[cfg(unix)]
        {
            let perm = Permissions::from_mode(mode);

            file.set_permissions(perm)?;
        }

        file.set_len(size as u64)?;

        Ok(MmapOptions::default().len(size).map_mut(&file)?)
    }

    /// Returns a [DiskBlockHeader] given a block height. This height must be less than or equal to
    /// the total headers inside our storage. It is UB to call this function with a height >
    /// total_headers
    unsafe fn get_header_by_height(
        &self,
        height: u32,
    ) -> Result<DiskBlockHeaderAndHash, FlatChainstoreError> {
        let pos = height as usize * size_of::<DiskBlockHeaderAndHash>();

        let header = self.headers_map.as_ptr().wrapping_add(pos) as *mut DiskBlockHeaderAndHash;

        // uninitialized memory means we haven't written anything there yet
        if (*header).hash == BlockHash::all_zeros() {
            return Err(FlatChainstoreError::NotFound);
        }

        Ok(header.read())
    }

    unsafe fn get_block_header_by_index(
        &self,
        index: IndexEntry,
    ) -> Result<DiskBlockHeaderAndHash, FlatChainstoreError> {
        match index.is_main_chain() {
            true => self.get_header_by_height(index.index()),
            false => {
                let pos = index.index() as usize * size_of::<DiskBlockHeaderAndHash>();

                let header =
                    self.fork_headers.as_ptr().wrapping_add(pos) as *mut DiskBlockHeaderAndHash;

                Ok(header.read())
            }
        }
    }

    unsafe fn get_acc_inner(&self) -> Result<Vec<u8>, FlatChainstoreError> {
        let metadata = self.get_metadata()?;

        let size = metadata.acc_size as usize;

        if size == 0 {
            return Err(FlatChainstoreError::NotFound);
        }

        Ok(metadata.acc[0..size].iter().copied().collect())
    }

    unsafe fn do_save_height(&self, best_block: BestChain) -> Result<(), FlatChainstoreError> {
        let ptr = self.metadata_map.as_ptr() as *mut Metadata;

        let metadata = &mut *ptr;

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
        let height = self
            .block_index
            .get_index_for_hash(hash, |height| self.get_block_header_by_index(height))?
            .map(|height| self.get_block_header_by_index(height));

        Ok(height.transpose()?.map(|x| x.header))
    }

    unsafe fn get_metadata(&self) -> Result<&Metadata, FlatChainstoreError> {
        let ptr = self.metadata_map.as_ptr() as *const Metadata;

        Ok(ptr.as_ref().unwrap())
    }

    unsafe fn get_metadata_mut(&self) -> Result<&mut Metadata, FlatChainstoreError> {
        let ptr = self.metadata_map.as_ptr() as *mut Metadata;

        Ok(ptr.as_mut().unwrap())
    }

    /// Writes a block header in our storage
    ///
    /// This function will allocate size_of(DiskBlockHeader) bytes in our file and write the raw
    /// header there. May return an error if we can't grow the file
    unsafe fn write_header_to_storage(
        &self,
        header: DiskBlockHeader,
    ) -> Result<(), FlatChainstoreError> {
        let offset = size_of::<DiskBlockHeaderAndHash>() * header.height().unwrap() as usize;

        let ptr = self.headers_map.as_ptr().wrapping_add(offset) as *mut DiskBlockHeaderAndHash;

        *ptr = DiskBlockHeaderAndHash {
            header,
            hash: header.block_hash(),
        };

        Ok(())
    }

    unsafe fn do_save_roots(&self, roots: Vec<u8>) -> Result<(), FlatChainstoreError> {
        let metadata = self.get_metadata_mut()?;

        let size = roots.len();

        metadata.acc_size = size as u32;

        metadata
            .acc
            .iter_mut()
            .zip(roots.iter())
            .for_each(|(x, y)| *x = *y);

        Ok(())
    }

    unsafe fn save_fork_block(&self, header: DiskBlockHeader) -> Result<(), FlatChainstoreError> {
        let metadata = self.get_metadata_mut()?;

        let fork_blocks = metadata.fork_count;

        let offset = size_of::<DiskBlockHeaderAndHash>() * fork_blocks as usize;

        let ptr = self.fork_headers.as_ptr().wrapping_add(offset) as *mut DiskBlockHeaderAndHash;

        ptr.write(DiskBlockHeaderAndHash {
            header,
            hash: header.block_hash(),
        });

        self.block_index.unset_index_pos(header)?;

        let mut index = IndexEntry::new(fork_blocks);

        index.set_fork();

        self.block_index
            .set_index_for_hash(header.block_hash(), index, |height| {
                self.get_block_header_by_index(height)
            })?;

        metadata.fork_count += 1;

        Ok(())
    }

    unsafe fn do_flush(&self) -> Result<(), FlatChainstoreError> {
        self.headers_map.flush()?;

        self.block_index.flush()?;

        self.metadata_map.flush()?;

        Ok(())
    }

    #[inline(always)]
    #[must_use]
    #[doc(hidden)]
    fn get_cache_mut(&self) -> Result<MutexGuard<CacheType>, PoisonError<MutexGuard<CacheType>>> {
        self.cache.lock()
    }
}

impl ChainStore for FlatChainStore {
    type Error = FlatChainstoreError;

    fn flush(&self) -> Result<(), Self::Error> {
        unsafe { self.do_flush() }
    }

    fn save_roots(&self, roots: Vec<u8>) -> Result<(), Self::Error> {
        unsafe { self.do_save_roots(roots) }
    }

    fn load_roots(&self) -> Result<Option<Vec<u8>>, Self::Error> {
        unsafe { Ok(self.get_acc_inner().ok()) }
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

    fn save_height(&self, height: &crate::BestChain) -> Result<(), Self::Error> {
        unsafe { self.do_save_height(height.clone()) }
    }

    fn save_header(&self, header: &DiskBlockHeader) -> Result<(), Self::Error> {
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
        let header = unsafe { Self::get_header_by_height(self, height)? };

        Ok(Some(header.header.block_hash()))
    }

    fn update_block_index(&self, height: u32, hash: BlockHash) -> Result<(), Self::Error> {
        let index = IndexEntry::new(height);

        unsafe {
            self.block_index
                .set_index_for_hash(hash, index, |height| self.get_block_header_by_index(height))
        }
    }
}

#[cfg(test)]
mod tests {

    use bitcoin::block::Header;
    use bitcoin::consensus::deserialize;
    use bitcoin::consensus::Decodable;
    use bitcoin::constants::genesis_block;
    use bitcoin::Block;

    use super::FlatChainStore;
    use crate::pruned_utreexo::ChainStore;
    use crate::pruned_utreexo::UpdatableChainstate;
    use crate::AssumeValidArg;
    use crate::BestChain;
    use crate::ChainState;
    use crate::DiskBlockHeader;

    #[test]
    fn test_truncate_pow2() {
        assert_eq!(super::FlatChainStore::truncate_to_pow2(1), 1);
        assert_eq!(super::FlatChainStore::truncate_to_pow2(2), 2);
        assert_eq!(super::FlatChainStore::truncate_to_pow2(3), 4);
        assert_eq!(super::FlatChainStore::truncate_to_pow2(4), 4);
        assert_eq!(super::FlatChainStore::truncate_to_pow2(5), 8);
        assert_eq!(super::FlatChainStore::truncate_to_pow2(1023), 1024);
        assert_eq!(super::FlatChainStore::truncate_to_pow2(1024), 1024);
        assert_eq!(super::FlatChainStore::truncate_to_pow2(1025), 2048);
        assert_eq!(
            super::FlatChainStore::truncate_to_pow2(1_000_000),
            1_048_576
        );
        assert_eq!(
            super::FlatChainStore::truncate_to_pow2(1_048_576),
            1_048_576
        );
        assert_eq!(
            super::FlatChainStore::truncate_to_pow2(1_048_577),
            2_097_152
        );
        assert_eq!(
            super::FlatChainStore::truncate_to_pow2(1_000_000_000),
            1_073_741_824
        );
        assert_eq!(
            super::FlatChainStore::truncate_to_pow2(1_073_741_824),
            1_073_741_824
        );
        assert_eq!(
            super::FlatChainStore::truncate_to_pow2(1_073_741_825),
            2_147_483_648
        );
    }

    fn get_test_chainstore() -> FlatChainStore {
        let test_id = rand::random::<u64>();
        let config = super::FlatChainStoreConfig {
            index_mmap_size: Some(32_768),
            headers_file_map_size: Some(32_768),
            fork_file_map_size: Some(10_000),
            cache_size: Some(10),
            file_permission: Some(0o660),
            path: format!("./tmp-db/{test_id}/"),
        };

        FlatChainStore::new(config).unwrap()
    }

    #[test]
    fn test_create_chainstore() {
        let test_id = rand::random::<u64>();
        let config = super::FlatChainStoreConfig {
            index_mmap_size: Some(10_000),
            headers_file_map_size: Some(10_000),
            fork_file_map_size: Some(10_000),
            cache_size: Some(10),
            file_permission: Some(0o660),
            path: format!("./tmp-db/{test_id}/"),
        };

        let _store = FlatChainStore::new(config).unwrap();
    }

    #[test]
    fn test_save_headers() {
        let store = get_test_chainstore();
        let blocks = include_str!("../../testdata/blocks.txt");

        for (i, line) in blocks.lines().enumerate() {
            let block = hex::decode(line).unwrap();
            let block: Block = deserialize(&block).unwrap();

            store
                .save_header(&DiskBlockHeader::FullyValid(block.header, i as u32))
                .unwrap();
        }
    }

    #[test]
    fn test_save_height() {
        let store = get_test_chainstore();

        let height = BestChain {
            alternative_tips: Vec::new(),
            assume_valid_index: 0,
            validation_index: genesis_block(bitcoin::Network::Signet).block_hash(),
            depth: 1,
            best_block: genesis_block(bitcoin::Network::Signet).block_hash(),
        };

        store.save_height(&height).unwrap();

        let recovered = store.load_height().unwrap().unwrap();
        assert_eq!(recovered, height);
    }

    #[test]
    fn test_index() {
        let store = get_test_chainstore();
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
            if hash == genesis_block(bitcoin::Network::Regtest).block_hash() {
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
        let chain = ChainState::new(store, crate::Network::Bitcoin, AssumeValidArg::Hardcoded);
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
        let chain = ChainState::new(store, crate::Network::Signet, AssumeValidArg::Hardcoded);
        let mut buffer = uncompressed.as_slice();

        while let Ok(header) = Header::consensus_decode(&mut buffer) {
            chain.accept_header(header).unwrap();
        }
    }

    #[test]
    fn test_fork_blocks() {
        let store = get_test_chainstore();

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
            index_mmap_size: Some(32_768),
            headers_file_map_size: Some(32_768),
            fork_file_map_size: Some(10_000),
            cache_size: Some(10),
            file_permission: Some(0o660),
            path: format!("./tmp-db/{test_id}/"),
        };

        let store = FlatChainStore::new(config).unwrap();
        let acc = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        store.save_roots(acc.clone()).unwrap();
        store.flush().unwrap();

        let recovered = store.load_roots().unwrap().unwrap();

        assert_eq!(recovered, acc);

        drop(store);

        let config = super::FlatChainStoreConfig {
            index_mmap_size: Some(32_768),
            headers_file_map_size: Some(32_768),
            fork_file_map_size: Some(10_000),
            cache_size: Some(10),
            file_permission: Some(0o660),
            path: format!("./tmp-db/{test_id}/"),
        };

        let store = FlatChainStore::new(config).unwrap();
        let recovered = store.load_roots().unwrap().unwrap();

        assert_eq!(recovered, acc);
    }
}
