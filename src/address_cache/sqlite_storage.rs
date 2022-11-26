use super::AddressCacheDatabase;
pub struct KvDatabase;
impl AddressCacheDatabase for KvDatabase {
    fn load<E>(&self) -> Result<Vec<super::CachedAddress>, E> {
        todo!()
    }
    fn save(&self, address: &super::CachedAddress) {
        todo!()
    }
    fn update(&self, address: &super::CachedAddress) {
        todo!()
    }
}
