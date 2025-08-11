use std::path::Path;
use redb::{Database, TableDefinition, Error, TableHandle};

const CRS_TABLE: TableDefinition<&str, Vec<u8>> = TableDefinition::new("crs_table");
const KEY_TABLE: TableDefinition<&str, Vec<u8>> = TableDefinition::new("key_table");
const DB_PATH: &str = "ttbe_database.redb";

fn ensure_table(db: &Database, table: TableDefinition<&str, Vec<u8>>) -> Result<(), Error> {
    let read_txn = db.begin_read()?;
    if read_txn.open_table(table).is_err() {
        let write_txn = db.begin_write()?;
        {
            write_txn
                .open_table(table)?;  // Should be recognized with correct Redb version and imports
            println!("{} table created .", table.name());
        }
        write_txn.commit()?;
    } else {
        println!("{} table already exists.", table.name());
    }

    Ok(())
}
fn onetime() -> Result<(), Error> {
    println!("Setting up ttbe database and tables…");

    if !Path::new(DB_PATH).exists() {
        let db = Database::create(DB_PATH)?;
        ensure_table(&db, CRS_TABLE)?;
        ensure_table(&db, KEY_TABLE)?;
        println!("Database and tables created successfully.");
    }

    Ok(())
}

fn main() {
    if let Err(e) = onetime() {
        panic!("Database setup failed: {}", e);
    }
}