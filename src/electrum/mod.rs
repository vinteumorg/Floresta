pub mod electrum_protocol;
pub mod request;
pub mod error;
pub trait ElectrumMethods {
    fn block_headers(&self);
    fn estimate_fee(&self);
    fn relay_fee(&self);
    fn get_balance(&self);
    fn get_history(&self);
    fn get_mempool(&self);
    fn list_unspent(&self);
}
