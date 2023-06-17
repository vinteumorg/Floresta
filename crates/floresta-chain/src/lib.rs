#![cfg_attr(any(feature = "no-std", not(test)), no_std)]

pub mod pruned_utreexo;
pub(crate) use floresta_common::prelude;
pub use pruned_utreexo::chain_state::*;
pub use pruned_utreexo::chainparams::*;
pub use pruned_utreexo::chainstore::*;
pub use pruned_utreexo::error::*;
pub use pruned_utreexo::udata::*;
pub use pruned_utreexo::Notification;

#[macro_export]
macro_rules! impl_error_from {
    ($thing: ty, $from_thing: ty, $field: ident) => {
        impl From<$from_thing> for $thing {
            fn from(e: $from_thing) -> Self {
                <$thing>::$field(e)
            }
        }
    };
}
