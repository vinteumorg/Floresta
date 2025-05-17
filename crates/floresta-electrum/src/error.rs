use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid params passed in")]
    InvalidParams,

    #[error("Invalid json string {0}")]
    Parsing(#[from] serde_json::Error),

    #[error("Blockchain error")]
    Blockchain(Box<dyn floresta_common::prelude::Error + Send + 'static>),

    #[error("IO error")]
    Io(#[from] std::io::Error),
}
