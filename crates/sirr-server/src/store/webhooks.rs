use anyhow::{Context, Result};
use redb::{ReadableTable, ReadableTableMetadata, TableDefinition};

use crate::webhooks::WebhookRegistration;

pub(crate) const WEBHOOKS: TableDefinition<&str, &[u8]> = TableDefinition::new("webhooks");

impl super::db::Store {
    /// Insert or overwrite a webhook registration.
    pub fn put_webhook(&self, reg: &WebhookRegistration) -> Result<()> {
        let bytes = bincode::serde::encode_to_vec(reg, bincode::config::standard())
            .context("bincode encode webhook")?;

        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(WEBHOOKS)?;
            table.insert(reg.id.as_str(), bytes.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// List all registered webhooks.
    pub fn list_webhooks(&self) -> Result<Vec<WebhookRegistration>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(WEBHOOKS)?;

        let mut regs = Vec::new();
        for item in table.iter()? {
            let (_k, v) = item?;
            let bytes: &[u8] = v.value();
            let (reg, _): (WebhookRegistration, _) =
                bincode::serde::decode_from_slice(bytes, bincode::config::standard())
                    .context("bincode decode webhook")?;
            regs.push(reg);
        }
        Ok(regs)
    }

    /// Delete a webhook by ID. Returns true if it existed.
    pub fn delete_webhook(&self, id: &str) -> Result<bool> {
        let write_txn = self.db.begin_write()?;
        let existed = {
            let mut table = write_txn.open_table(WEBHOOKS)?;
            let existed = table.remove(id)?.is_some();
            existed
        };
        write_txn.commit()?;
        Ok(existed)
    }

    /// Count the number of registered webhooks.
    pub fn count_webhooks(&self) -> Result<usize> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(WEBHOOKS)?;
        Ok(table.len()? as usize)
    }
}
