// src/db.rs

use anyhow::{Result, Context};
use rusqlite::{Connection, params};
use std::io::Write;
use std::time::Instant;

use crate::analytic::{BlockRow, TxRow, InputRow, OutputRow};

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
struct AddressRow {
    address_id: u64,
    address: String,
    script_type: String,
    script_hash: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
struct OutAddrRow {
    output_id: u64,
    address_id: u64,
}

pub fn open(path: &str) -> Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;
         PRAGMA cache_size=-64000; PRAGMA temp_store=MEMORY;"
    )?;
    Ok(conn)
}

pub fn create_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch("
        CREATE TABLE IF NOT EXISTS blocks (
            block_height INTEGER PRIMARY KEY, file_id INTEGER,
            block_hash TEXT, date_time TEXT, version INTEGER,
            prev_block_hash TEXT, merkle_root TEXT,
            bits INTEGER, nonce INTEGER, block_size INTEGER, tx_count INTEGER
        );
        CREATE TABLE IF NOT EXISTS transactions (
            transaction_id INTEGER PRIMARY KEY, block_id INTEGER,
            txid TEXT, version INTEGER, lock_time INTEGER,
            is_segwit INTEGER, is_coinbase INTEGER,
            input_count INTEGER, output_count INTEGER,
            tx_size INTEGER, fee INTEGER
        );
        CREATE TABLE IF NOT EXISTS inputs (
            input_id INTEGER PRIMARY KEY, transaction_id INTEGER,
            txid TEXT, input_index INTEGER, prev_txid TEXT,
            prev_vout INTEGER, script_sig TEXT, sequence_number INTEGER
        );
        CREATE TABLE IF NOT EXISTS outputs (
            output_id INTEGER PRIMARY KEY, transaction_id INTEGER,
            txid TEXT, output_index INTEGER, value INTEGER,
            script_pubkey TEXT, script_type TEXT, data TEXT
        );
        CREATE TABLE IF NOT EXISTS addresses (
            address_id INTEGER PRIMARY KEY, address TEXT,
            script_type TEXT, script_hash TEXT
        );
        CREATE TABLE IF NOT EXISTS output_addresses (
            output_id INTEGER, address_id INTEGER,
            PRIMARY KEY (output_id, address_id)
        );
    ")?;
    Ok(())
}

pub fn create_indexes(conn: &Connection) -> Result<()> {
    let start = Instant::now();
    println!("Creating indexes...");
    conn.execute_batch("
        CREATE INDEX IF NOT EXISTS idx_tx_block ON transactions(block_id);
        CREATE INDEX IF NOT EXISTS idx_inp_tx ON inputs(transaction_id);
        CREATE INDEX IF NOT EXISTS idx_inp_prev ON inputs(prev_txid, prev_vout);
        CREATE INDEX IF NOT EXISTS idx_out_tx ON outputs(transaction_id);
        CREATE INDEX IF NOT EXISTS idx_out_txid ON outputs(txid, output_index);
        CREATE INDEX IF NOT EXISTS idx_addr ON addresses(address);
        CREATE INDEX IF NOT EXISTS idx_oa_addr ON output_addresses(address_id);
    ")?;
    println!("  Indexes created in {:.1?}", start.elapsed());
    Ok(())
}

fn progress(label: &str, count: u64) {
    if count % 100_000 == 0 {
        print!("\r  {}: {}K", label, count / 1000);
        let _ = std::io::stdout().flush();
    }
}

fn done(label: &str, count: u64, start: Instant) {
    println!("\r  {}: {} rows ({:.1?})", label, count, start.elapsed());
}

pub fn load_all(conn: &Connection, input_dir: &str) -> Result<()> {
    conn.execute_batch("PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;")?;
    load_blocks(conn, input_dir)?;
    load_transactions(conn, input_dir)?;
    load_inputs(conn, input_dir)?;
    load_outputs(conn, input_dir)?;
    load_addresses(conn, input_dir)?;
    load_output_addresses(conn, input_dir)?;
    create_indexes(conn)?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
    Ok(())
}

fn load_blocks(conn: &Connection, dir: &str) -> Result<()> {
    let start = Instant::now();
    let path = format!("{}/blocks.csv", dir);
    let mut rdr = csv::Reader::from_path(&path).context("Opening blocks.csv")?;
    let tx = conn.unchecked_transaction()?;
    let mut count = 0u64;
    {
        let mut stmt = tx.prepare("INSERT INTO blocks VALUES (?,?,?,?,?,?,?,?,?,?,?)")?;
        for result in rdr.deserialize() {
            let r: BlockRow = result?;
            stmt.execute(params![r.block_height, r.file_id, r.block_hash, r.date_time,
                r.version, r.prev_block_hash, r.merkle_root, r.bits, r.nonce,
                r.block_size, r.tx_count])?;
            count += 1;
            progress("blocks", count);
        }
    }
    tx.commit()?;
    done("blocks", count, start);
    Ok(())
}

fn load_transactions(conn: &Connection, dir: &str) -> Result<()> {
    let start = Instant::now();
    let path = format!("{}/transactions.csv", dir);
    let mut rdr = csv::Reader::from_path(&path).context("Opening transactions.csv")?;
    let tx = conn.unchecked_transaction()?;
    let mut count = 0u64;
    {
        let mut stmt = tx.prepare("INSERT INTO transactions VALUES (?,?,?,?,?,?,?,?,?,?,?)")?;
        for result in rdr.deserialize() {
            let r: TxRow = result?;
            stmt.execute(params![r.transaction_id, r.block_id, r.txid, r.version,
                r.lock_time, r.is_segwit as i32, r.is_coinbase as i32,
                r.input_count, r.output_count, r.tx_size, r.fee])?;
            count += 1;
            progress("transactions", count);
        }
    }
    tx.commit()?;
    done("transactions", count, start);
    Ok(())
}

fn load_inputs(conn: &Connection, dir: &str) -> Result<()> {
    let start = Instant::now();
    let path = format!("{}/inputs.csv", dir);
    let mut rdr = csv::Reader::from_path(&path).context("Opening inputs.csv")?;
    let tx = conn.unchecked_transaction()?;
    let mut count = 0u64;
    {
        let mut stmt = tx.prepare("INSERT INTO inputs VALUES (?,?,?,?,?,?,?,?)")?;
        for result in rdr.deserialize() {
            let r: InputRow = result?;
            stmt.execute(params![r.input_id, r.transaction_id, r.txid, r.input_index,
                r.prev_txid, r.prev_vout, r.script_sig, r.sequence_number])?;
            count += 1;
            progress("inputs", count);
        }
    }
    tx.commit()?;
    done("inputs", count, start);
    Ok(())
}

fn load_outputs(conn: &Connection, dir: &str) -> Result<()> {
    let start = Instant::now();
    let path = format!("{}/outputs.csv", dir);
    let mut rdr = csv::Reader::from_path(&path).context("Opening outputs.csv")?;
    let tx = conn.unchecked_transaction()?;
    let mut count = 0u64;
    {
        let mut stmt = tx.prepare("INSERT INTO outputs VALUES (?,?,?,?,?,?,?,?)")?;
        for result in rdr.deserialize() {
            let r: OutputRow = result?;
            stmt.execute(params![r.output_id, r.transaction_id, r.txid, r.output_index,
                r.value, r.script_pubkey, r.script_type, r.data])?;
            count += 1;
            progress("outputs", count);
        }
    }
    tx.commit()?;
    done("outputs", count, start);
    Ok(())
}

fn load_addresses(conn: &Connection, dir: &str) -> Result<()> {
    let start = Instant::now();
    let path = format!("{}/addresses.csv", dir);
    let mut rdr = csv::Reader::from_path(&path).context("Opening addresses.csv")?;
    let tx = conn.unchecked_transaction()?;
    let mut count = 0u64;
    {
        let mut stmt = tx.prepare("INSERT INTO addresses VALUES (?,?,?,?)")?;
        for result in rdr.deserialize() {
            let r: AddressRow = result?;
            stmt.execute(params![r.address_id, r.address, r.script_type, r.script_hash])?;
            count += 1;
            progress("addresses", count);
        }
    }
    tx.commit()?;
    done("addresses", count, start);
    Ok(())
}

fn load_output_addresses(conn: &Connection, dir: &str) -> Result<()> {
    let start = Instant::now();
    let path = format!("{}/output_addresses.csv", dir);
    let mut rdr = csv::Reader::from_path(&path).context("Opening output_addresses.csv")?;
    let tx = conn.unchecked_transaction()?;
    let mut count = 0u64;
    {
        let mut stmt = tx.prepare("INSERT INTO output_addresses VALUES (?,?)")?;
        for result in rdr.deserialize() {
            let r: OutAddrRow = result?;
            stmt.execute(params![r.output_id, r.address_id])?;
            count += 1;
            progress("output_addresses", count);
        }
    }
    tx.commit()?;
    done("output_addresses", count, start);
    Ok(())
}

pub fn build_lifecycle(conn: &Connection) -> Result<()> {
    let start = Instant::now();
    println!("Building UTXO lifecycle table...");
    conn.execute_batch("DROP TABLE IF EXISTS utxo_lifecycle")?;
    conn.execute_batch("
        CREATE TABLE utxo_lifecycle AS
        SELECT o.output_id, o.value, tc.block_id AS created_height,
            ts.block_id AS spent_height
        FROM outputs o
        JOIN transactions tc ON o.transaction_id = tc.transaction_id
        LEFT JOIN inputs i ON i.prev_txid = o.txid AND i.prev_vout = o.output_index
        LEFT JOIN transactions ts ON i.transaction_id = ts.transaction_id;

        CREATE INDEX idx_lc_created ON utxo_lifecycle(created_height);
    ")?;
    let count: u64 = conn.query_row(
        "SELECT COUNT(*) FROM utxo_lifecycle", [], |r| r.get(0)
    )?;
    println!("  Lifecycle: {} rows ({:.1?})", count, start.elapsed());
    Ok(())
}

pub fn hodl_waves(conn: &Connection, range_size: u64, output_path: &str) -> Result<()> {
    let start = Instant::now();
    println!("Computing HODL waves (range={})...", range_size);

    let max_height: u64 = conn.query_row(
        "SELECT COALESCE(MAX(block_height), 0) FROM blocks", [], |r| r.get(0)
    )?;

    let mut writer = std::io::BufWriter::new(
        std::fs::File::create(output_path).context("Creating HODL output file")?
    );
    writeln!(writer,
        "BLOCK_RANGE,DATE_TIME,LT_1D,D1_W1,W1_M1,M1_M3,M3_M6,M6_Y1,Y1_Y2,Y2_Y3,Y3_Y5,GT_5Y"
    )?;

    let mut band_stmt = conn.prepare("
        SELECT
            CASE
                WHEN (?1 - created_height) < 144 THEN 0
                WHEN (?1 - created_height) < 1008 THEN 1
                WHEN (?1 - created_height) < 4320 THEN 2
                WHEN (?1 - created_height) < 12960 THEN 3
                WHEN (?1 - created_height) < 25920 THEN 4
                WHEN (?1 - created_height) < 52560 THEN 5
                WHEN (?1 - created_height) < 105120 THEN 6
                WHEN (?1 - created_height) < 157680 THEN 7
                WHEN (?1 - created_height) < 262800 THEN 8
                ELSE 9
            END AS band,
            COALESCE(SUM(value), 0) AS total_sats
        FROM utxo_lifecycle
        WHERE created_height <= ?1 AND (spent_height IS NULL OR spent_height > ?1)
        GROUP BY band
    ")?;

    let mut date_stmt = conn.prepare(
        "SELECT date_time FROM blocks WHERE block_height <= ? ORDER BY block_height DESC LIMIT 1"
    )?;

    let total = max_height / range_size + 1;
    let mut snap_count = 0u64;

    for snapshot in (0..=max_height).step_by(range_size as usize) {
        let date: String = date_stmt.query_row(params![snapshot], |r| r.get(0))
            .unwrap_or_default();

        let mut bands = [0u64; 10];
        let rows = band_stmt.query_map(params![snapshot], |row| {
            Ok((row.get::<_, i32>(0)?, row.get::<_, u64>(1)?))
        })?;
        for row in rows {
            let (band, sats) = row?;
            if band >= 0 && band < 10 {
                bands[band as usize] = sats;
            }
        }

        writeln!(writer, "{},{},{},{},{},{},{},{},{},{},{},{}",
            snapshot, date, bands[0], bands[1], bands[2], bands[3], bands[4],
            bands[5], bands[6], bands[7], bands[8], bands[9])?;

        snap_count += 1;
        if snap_count % 10 == 0 {
            print!("\r  HODL waves: {}/{}", snap_count, total);
            let _ = std::io::stdout().flush();
        }
    }

    writer.flush()?;
    println!("\r  HODL waves: {} snapshots ({:.1?})", snap_count, start.elapsed());
    Ok(())
}

pub fn rich_list(conn: &Connection, limit: u32) -> Result<Vec<(String, f64)>> {
    let mut stmt = conn.prepare("
        SELECT a.address, SUM(o.value) AS total_sats
        FROM outputs o
        JOIN output_addresses oa ON o.output_id = oa.output_id
        JOIN addresses a ON oa.address_id = a.address_id
        LEFT JOIN inputs i ON i.prev_txid = o.txid AND i.prev_vout = o.output_index
        WHERE i.input_id IS NULL
        GROUP BY a.address_id
        ORDER BY total_sats DESC
        LIMIT ?
    ")?;
    let rows = stmt.query_map(params![limit], |row| {
        let addr: String = row.get(0)?;
        let sats: u64 = row.get(1)?;
        Ok((addr, sats as f64 / 100_000_000.0))
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

pub fn balance(conn: &Connection, address: &str) -> Result<(u64, u64)> {
    let mut stmt = conn.prepare("
        SELECT COALESCE(SUM(o.value), 0), COUNT(o.output_id)
        FROM outputs o
        JOIN output_addresses oa ON o.output_id = oa.output_id
        JOIN addresses a ON oa.address_id = a.address_id
        LEFT JOIN inputs i ON i.prev_txid = o.txid AND i.prev_vout = o.output_index
        WHERE a.address = ? AND i.input_id IS NULL
    ")?;
    stmt.query_row(params![address], |row| {
        Ok((row.get::<_, u64>(0)?, row.get::<_, u64>(1)?))
    }).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memory_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        create_schema(&conn).unwrap();
        conn
    }

    #[test]
    fn test_schema_creation() {
        let conn = memory_db();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table'", [], |r| r.get(0)
        ).unwrap();
        assert_eq!(count, 6);
    }

    #[test]
    fn test_lifecycle() {
        let conn = memory_db();
        conn.execute_batch("
            INSERT INTO blocks VALUES (0,0,'h0','2009-01-03 18:15:05',1,'','',0,0,285,1);
            INSERT INTO blocks VALUES (100,0,'h1','2009-01-04 18:15:05',1,'','',0,0,285,1);
            INSERT INTO transactions VALUES (1,0,'tx1',1,0,0,1,0,1,100,0);
            INSERT INTO transactions VALUES (2,100,'tx2',1,0,0,0,1,1,100,0);
            INSERT INTO outputs VALUES (1,1,'tx1',0,5000000000,'','P2PKH','');
            INSERT INTO outputs VALUES (2,2,'tx2',0,4999900000,'','P2PKH','');
            INSERT INTO inputs VALUES (1,2,'tx2',0,'tx1',0,'',0);
        ").unwrap();
        create_indexes(&conn).unwrap();
        build_lifecycle(&conn).unwrap();

        let count: u64 = conn.query_row(
            "SELECT COUNT(*) FROM utxo_lifecycle", [], |r| r.get(0)
        ).unwrap();
        assert_eq!(count, 2);

        let spent: Option<u64> = conn.query_row(
            "SELECT spent_height FROM utxo_lifecycle WHERE output_id=1", [], |r| r.get(0)
        ).unwrap();
        assert_eq!(spent, Some(100));

        let spent: Option<u64> = conn.query_row(
            "SELECT spent_height FROM utxo_lifecycle WHERE output_id=2", [], |r| r.get(0)
        ).unwrap();
        assert_eq!(spent, None);
    }

    #[test]
    fn test_balance() {
        let conn = memory_db();
        conn.execute_batch("
            INSERT INTO blocks VALUES (0,0,'h','2009-01-03',1,'','',0,0,0,1);
            INSERT INTO transactions VALUES (1,0,'tx1',1,0,0,1,0,2,100,0);
            INSERT INTO outputs VALUES (1,1,'tx1',0,5000000000,'','P2PKH','');
            INSERT INTO outputs VALUES (2,1,'tx1',1,2500000000,'','P2PKH','');
            INSERT INTO addresses VALUES (1,'1ABC','P2PKH','hash1');
            INSERT INTO output_addresses VALUES (1,1);
            INSERT INTO output_addresses VALUES (2,1);
        ").unwrap();
        create_indexes(&conn).unwrap();

        let (sats, count) = balance(&conn, "1ABC").unwrap();
        assert_eq!(sats, 7500000000);
        assert_eq!(count, 2);
    }

    #[test]
    fn test_balance_with_spend() {
        let conn = memory_db();
        conn.execute_batch("
            INSERT INTO blocks VALUES (0,0,'h','2009-01-03',1,'','',0,0,0,1);
            INSERT INTO transactions VALUES (1,0,'tx1',1,0,0,1,0,2,100,0);
            INSERT INTO transactions VALUES (2,0,'tx2',1,0,0,0,1,1,100,0);
            INSERT INTO outputs VALUES (1,1,'tx1',0,5000000000,'','P2PKH','');
            INSERT INTO outputs VALUES (2,1,'tx1',1,2500000000,'','P2PKH','');
            INSERT INTO inputs VALUES (1,2,'tx2',0,'tx1',0,'',0);
            INSERT INTO addresses VALUES (1,'1ABC','P2PKH','hash1');
            INSERT INTO output_addresses VALUES (1,1);
            INSERT INTO output_addresses VALUES (2,1);
        ").unwrap();
        create_indexes(&conn).unwrap();

        let (sats, count) = balance(&conn, "1ABC").unwrap();
        assert_eq!(sats, 2500000000);
        assert_eq!(count, 1);
    }

    #[test]
    fn test_rich_list() {
        let conn = memory_db();
        conn.execute_batch("
            INSERT INTO blocks VALUES (0,0,'h','2009-01-03',1,'','',0,0,0,1);
            INSERT INTO transactions VALUES (1,0,'tx1',1,0,0,1,0,2,100,0);
            INSERT INTO outputs VALUES (1,1,'tx1',0,5000000000,'','P2PKH','');
            INSERT INTO outputs VALUES (2,1,'tx1',1,2500000000,'','P2PKH','');
            INSERT INTO addresses VALUES (1,'1ABC','P2PKH','h1');
            INSERT INTO addresses VALUES (2,'1DEF','P2PKH','h2');
            INSERT INTO output_addresses VALUES (1,1);
            INSERT INTO output_addresses VALUES (2,2);
        ").unwrap();
        create_indexes(&conn).unwrap();

        let list = rich_list(&conn, 10).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].0, "1ABC");
        assert_eq!(list[0].1, 50.0);
        assert_eq!(list[1].0, "1DEF");
        assert_eq!(list[1].1, 25.0);
    }
}
