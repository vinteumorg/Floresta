use serde::Deserialize;

#[derive(Default, Debug, Deserialize)]
pub struct Wallet {
    pub xpubs: Option<Vec<String>>,
    pub descriptors: Option<Vec<String>>,
    pub addresses: Option<Vec<String>>,
}

#[derive(Default, Debug, Deserialize)]
#[allow(dead_code)]
pub struct Rpc {
    pub rpc_user: Option<String>,
    pub rpc_password: Option<String>,
    pub rpc_host: Option<String>,
    pub rpc_port: Option<u32>,
}

#[derive(Default, Debug, Deserialize)]
#[allow(dead_code)]
pub struct Misc {
    pub batch_sync: Option<String>,
}

#[derive(Default, Debug, Deserialize)]
#[allow(dead_code)]
pub struct ConfigFile {
    pub rpc: Option<Rpc>,
    pub wallet: Wallet,
    pub misc: Option<Misc>,
}

impl ConfigFile {
    pub fn from_file(filename: &str) -> Result<Self, crate::error::Error> {
        let file = std::fs::read_to_string(filename)?;
        Ok(toml::from_str(&file)?)
    }
}
