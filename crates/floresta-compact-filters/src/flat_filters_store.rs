use std::convert::TryFrom;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::PoisonError;

use crate::IteratableFilterStore;
use crate::IteratableFilterStoreError;

struct FlatFiltersStoreInner {
    file: std::fs::File,
    counter: u32,
    offset: u32,
}

impl From<PoisonError<MutexGuard<'_, FlatFiltersStoreInner>>> for IteratableFilterStoreError {
    fn from(_: PoisonError<MutexGuard<'_, FlatFiltersStoreInner>>) -> Self {
        IteratableFilterStoreError::Poisoned
    }
}

pub struct FlatFiltersStore(Mutex<FlatFiltersStoreInner>);

impl FlatFiltersStore {
    pub fn new(path: PathBuf) -> Self {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .unwrap();

        Self(Mutex::new(FlatFiltersStoreInner {
            file,
            counter: 1, // counter is always 1 because the genesis block doesn't have filter
            offset: 4,  // the first four bytes are reserved for the height
        }))
    }
}

impl TryFrom<&PathBuf> for FlatFiltersStore {
    type Error = std::io::Error;

    fn try_from(path: &PathBuf) -> Result<Self, Self::Error> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)?;

        Ok(Self(Mutex::new(FlatFiltersStoreInner {
            file,
            counter: 1, // counter is always 1 because the genesis block doesn't have filter
            offset: 4,  // the first four bytes are reserved for the height
        })))
    }
}

impl IteratableFilterStore for FlatFiltersStore {
    fn set_height(&self, height: u32) -> Result<(), IteratableFilterStoreError> {
        let mut inner = self.0.lock()?;
        inner.file.seek(SeekFrom::Start(0))?;
        inner.file.write_all(&height.to_le_bytes())?;

        Ok(())
    }

    fn get_height(&self) -> Result<u32, IteratableFilterStoreError> {
        let inner = self.0.lock()?;

        let mut buf = [0; 4];
        inner.file.read_exact_at(&mut buf, 0)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn next(&self) -> Result<(u32, crate::bip158::BlockFilter), IteratableFilterStoreError> {
        let local_heigth = self.get_height()?;
        let mut inner = self.0.lock()?;

        if inner.counter > local_heigth {
            return Err(IteratableFilterStoreError::Eof);
        }

        let mut buf = [0; 4];
        let offset = inner.offset as u64;

        inner.file.seek(SeekFrom::Start(offset))?;
        inner.file.read_exact(&mut buf)?;

        let length = u32::from_le_bytes(buf);

        debug_assert!(length < 1_000_000);

        let mut buf = vec![0_u8; length as usize];
        inner.file.read_exact(&mut buf)?;
        let filter = crate::bip158::BlockFilter::new(&buf);

        inner.offset += length + 4;
        inner.counter += 1;

        Ok((inner.counter - 1, filter))
    }

    fn first(&self) -> Result<(u32, crate::bip158::BlockFilter), IteratableFilterStoreError> {
        {
            let mut inner = self.0.lock()?;

            inner.offset = 4;
            inner.counter = 1;
        }

        self.next()
    }

    fn put_filter(
        &self,
        block_filter: crate::bip158::BlockFilter,
    ) -> Result<(), IteratableFilterStoreError> {
        if block_filter.content.len() > 1_000_000 {
            return Err(IteratableFilterStoreError::FilterTooLarge);
        }
        let mut inner = self.0.lock()?;
        let filter = block_filter.content;
        let length = filter.len() as u32;

        inner.file.seek(SeekFrom::End(0))?;
        inner.file.write_all(&length.to_le_bytes())?;
        inner.file.write_all(&filter)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs::remove_file;

    use super::FlatFiltersStore;
    use crate::bip158::BlockFilter;
    use crate::IteratableFilterStore;

    #[test]
    fn test_filter_store() {
        let path = "test_filter_store";
        let store = FlatFiltersStore::new(path.into());

        let res = store.get_height().unwrap_err();
        assert!(matches!(res, crate::IteratableFilterStoreError::Io(_)));
        store.set_height(1).expect("could not set height");
        assert_eq!(store.get_height().unwrap(), 1);

        let filter = BlockFilter::new(&[10, 11, 12, 13]);
        store
            .put_filter(filter.clone())
            .expect("could not put filter");

        assert_eq!((1, filter), store.first().unwrap());
        let res = store.next().unwrap_err();
        assert!(matches!(res, crate::IteratableFilterStoreError::Eof));
        remove_file(path).expect("could not remove file after test");
    }
}
