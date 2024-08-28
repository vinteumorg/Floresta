use std::convert::TryFrom;
use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::PoisonError;

use crate::IteratableFilterStore;
use crate::IteratableFilterStoreError;

pub struct FiltersIterator {
    reader: BufReader<File>,
}

impl Iterator for FiltersIterator {
    type Item = (u32, crate::bip158::BlockFilter);

    fn next(&mut self) -> Option<Self::Item> {
        let mut buf = [0; 4];

        self.reader.read_exact(&mut buf).ok()?;
        let height = u32::from_le_bytes(buf);

        self.reader.read_exact(&mut buf).ok()?;
        let length = u32::from_le_bytes(buf);

        debug_assert!(
            length < 1_000_000,
            "filter for block {} has length {}",
            height,
            length,
        );

        let mut buf = vec![0_u8; length as usize];
        self.reader.read_exact(&mut buf).ok()?;
        let filter = crate::bip158::BlockFilter::new(&buf);

        Some((height, filter))
    }
}

struct FlatFiltersStoreInner {
    file: std::fs::File,
    path: PathBuf,
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
            .open(&path)
            .unwrap();

        Self(Mutex::new(FlatFiltersStoreInner { file, path }))
    }
}

impl TryFrom<&PathBuf> for FlatFiltersStore {
    type Error = std::io::Error;

    fn try_from(path: &PathBuf) -> Result<Self, Self::Error> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;

        Ok(Self(Mutex::new(FlatFiltersStoreInner {
            file,
            path: path.clone(),
        })))
    }
}

impl IntoIterator for FlatFiltersStore {
    type Item = (u32, crate::bip158::BlockFilter);
    type IntoIter = FiltersIterator;

    fn into_iter(self) -> Self::IntoIter {
        let mut inner = self.0.lock().unwrap();
        inner.file.seek(SeekFrom::Start(4)).unwrap();
        let reader = BufReader::new(inner.file.try_clone().unwrap());
        FiltersIterator { reader }
    }
}

impl IteratableFilterStore for FlatFiltersStore {
    type I = FiltersIterator;
    fn set_height(&self, height: u32) -> Result<(), IteratableFilterStoreError> {
        let mut inner = self.0.lock()?;
        inner.file.seek(SeekFrom::Start(0))?;
        inner.file.write_all(&height.to_le_bytes())?;

        Ok(())
    }

    fn get_height(&self) -> Result<u32, IteratableFilterStoreError> {
        let mut inner = self.0.lock()?;

        let mut buf = [0; 4];
        inner.file.seek(SeekFrom::Start(0))?;
        inner.file.read_exact(&mut buf)?;

        Ok(u32::from_le_bytes(buf))
    }

    fn iter(&self) -> Result<Self::I, IteratableFilterStoreError> {
        let inner = self.0.lock()?;
        let new_file = File::open(inner.path.clone())?;
        let mut reader = BufReader::new(new_file);
        reader.seek(SeekFrom::Start(4))?;
        Ok(FiltersIterator { reader })
    }

    fn put_filter(
        &self,
        block_filter: crate::bip158::BlockFilter,
        height: u32,
    ) -> Result<(), IteratableFilterStoreError> {
        let length = block_filter.content.len() as u32;

        if length > 1_000_000 {
            return Err(IteratableFilterStoreError::FilterTooLarge);
        }

        let mut inner = self.0.lock()?;

        inner.file.seek(SeekFrom::End(0))?;
        inner.file.write_all(&height.to_le_bytes())?;
        inner.file.write_all(&length.to_le_bytes())?;
        inner.file.write_all(&block_filter.content)?;

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
            .put_filter(filter.clone(), 1)
            .expect("could not put filter");

        let mut iter = store.iter().expect("could not get iterator");
        assert_eq!((1, filter), iter.next().unwrap());

        assert_eq!(iter.next(), None);
        remove_file(path).expect("could not remove file after test");
    }
}
