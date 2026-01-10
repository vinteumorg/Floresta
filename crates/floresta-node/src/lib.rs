// SPDX-License-Identifier: MIT

// cargo docs options
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(html_logo_url = "https://avatars.githubusercontent.com/u/249173822?s=200&v=4")]
#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/getfloresta/floresta-media/master/logo%20png/Icon%20-%20Green%20(main).png"
)]
#![doc(issue_tracker_base_url = "https://github.com/getfloresta/floresta/issues/")]

mod config_file;
mod error;
mod florestad;
#[cfg(feature = "json-rpc")]
mod json_rpc;
mod slip132;
mod wallet_input;
#[cfg(feature = "zmq-server")]
mod zmq;

pub use florestad::AssumeUtreexoValue;
pub use florestad::AssumeValidArg;
pub use florestad::Config;
pub use florestad::Florestad;
