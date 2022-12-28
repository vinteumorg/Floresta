use serde::Deserialize;

#[derive(Default, Debug, Deserialize)]
pub struct Wallet {
    pub xpubs: Option<Vec<String>>,
    pub descriptors: Option<Vec<String>>,
    pub addresses: Option<Vec<String>>,
}

#[derive(Default, Debug, Deserialize)]
pub struct Rpc {
    pub rpc_user: Option<String>,
    pub rpc_password: Option<String>,
    pub rpc_host: Option<String>,
    pub rpc_port: Option<u32>,
}
#[derive(Default, Debug, Deserialize)]
pub struct Misc {
    pub external_sync: Option<String>,
}
#[derive(Default, Debug, Deserialize)]
pub struct ConfigFile {
    pub rpc: Rpc,
    pub wallet: Wallet,
    pub misc: Misc,
}
