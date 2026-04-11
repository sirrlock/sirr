use anyhow::Result;
use redb::Database;
use std::path::Path;

pub struct Store {
    #[allow(dead_code)]
    db: Database,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let db = Database::create(path)?;
        Ok(Self { db })
    }
}
