// SPDX-License-Identifier: MIT

//! # Floresta Chain
//! This crate provides the core validation logic for a full node using libfloresta.
//! It is maintained as a separate crate to allow other projects to build on it,
//! independent of the libfloresta P2P network or libfloresta wallet.
//! The main entry point is the [ChainState] struct, that keeps track of the current
//! blockchain state, like headers and utreexo accumulator.
//!
//! All data is stored in a `ChainStore` implementation, which is generic over the
//! underlying database. See the ChainStore trait for more information. For a
//! ready-to-use implementation, see the [KvChainStore] struct.
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]

pub mod pruned_utreexo;
pub(crate) use floresta_common::prelude;
pub use pruned_utreexo::chain_state::*;
pub use pruned_utreexo::chainparams::*;
pub use pruned_utreexo::chainstore::*;
pub use pruned_utreexo::error::*;
#[cfg(feature = "experimental-db")]
pub use pruned_utreexo::flat_chain_store::*;
pub use pruned_utreexo::udata::*;
pub use pruned_utreexo::ChainBackend;
pub use pruned_utreexo::Notification;
pub use pruned_utreexo::ThreadSafeChain;
