//! In this codebase, we avoid sharing the logic for blockchain updates, like p2p messages
//! and timers. The only shared struct is a [BlockchainState], a stateful RwLock protected
//! struct representing our current view of the network. However, [BlockchainState] doesn't
//! update itself, it relies an external "backend" that pulls blocks and transactions, applying
//! to our current view.
//! 
//! This module defines the interface a object need to provide to update the chainstate.