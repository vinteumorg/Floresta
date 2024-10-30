// SPDX-License-Identifier: MIT

//! A library for building and querying BIP-158 compact block filters locally
//!
//! This lib implements BIP-158 client-side Galomb-Rice block filters, without
//! relaying on p2p connections to retrieve them. We use this to speedup wallet
//! resyncs and allow arbitrary UTXO retrieving for lightning nodes.
//!
//! This module should receive blocks as we download them, it'll create a filter
//! for it. Therefore, you can't use this to speedup wallet sync **before** IBD,
//! since we wouldn't have the filter for all blocks yet.
use core::fmt::Debug;
use std::fmt::Display;
use std::sync::PoisonError;
use std::sync::RwLockWriteGuard;

use bitcoin::bip158;
use flat_filters_store::FlatFiltersStore;

pub mod flat_filters_store;
pub mod kv_filter_database;
pub mod network_filters;

/// A database that stores our compact filters
pub trait BlockFilterStore: Send + Sync {
    /// Fetches a block filter
    fn get_filter(&self, block_height: u32) -> Option<bip158::BlockFilter>;
    /// Stores a new filter
    fn put_filter(&self, block_height: u32, block_filter: bip158::BlockFilter);
    /// Persists the height of the last filter we have
    fn put_height(&self, height: u32);
    /// Fetches the height of the last filter we have
    fn get_height(&self) -> Option<u32>;
}

pub enum IteratableFilterStoreError {
    /// I/O error
    Io(std::io::Error),
    /// End of the file
    Eof,
    /// Lock error
    Poisoned,
    /// Filter too large, probably a bug
    FilterTooLarge,
}

impl Debug for IteratableFilterStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IteratableFilterStoreError::Io(e) => write!(f, "I/O error: {e}"),
            IteratableFilterStoreError::Eof => write!(f, "End of file"),
            IteratableFilterStoreError::Poisoned => write!(f, "Lock poisoned"),
            IteratableFilterStoreError::FilterTooLarge => write!(f, "Filter too large"),
        }
    }
}

impl From<std::io::Error> for IteratableFilterStoreError {
    fn from(e: std::io::Error) -> Self {
        IteratableFilterStoreError::Io(e)
    }
}

impl Display for IteratableFilterStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(self, f)
    }
}

impl From<PoisonError<RwLockWriteGuard<'_, FlatFiltersStore>>> for IteratableFilterStoreError {
    fn from(_: PoisonError<RwLockWriteGuard<'_, FlatFiltersStore>>) -> Self {
        IteratableFilterStoreError::Poisoned
    }
}

pub trait IteratableFilterStore:
    Send + Sync + IntoIterator<Item = (u32, bip158::BlockFilter)>
{
    type I: Iterator<Item = (u32, bip158::BlockFilter)>;
    /// Fetches the first filter and sets our internal cursor to the first filter,
    /// succeeding calls to [next] will return the next filter until we reach the end
    fn iter(&self, start_height: Option<usize>) -> Result<Self::I, IteratableFilterStoreError>;
    /// Writes a new filter to the store
    fn put_filter(
        &self,
        block_filter: bip158::BlockFilter,
        height: u32,
    ) -> Result<(), IteratableFilterStoreError>;
    /// Persists the height of the last filter we have
    fn set_height(&self, height: u32) -> Result<(), IteratableFilterStoreError>;
    /// Fetches the height of the last filter we have
    fn get_height(&self) -> Result<u32, IteratableFilterStoreError>;
}
