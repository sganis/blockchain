// src/analytic/mod.rs

pub mod network;
pub mod mining;
pub mod script;
pub mod opreturn;
pub mod utxoset;

use anyhow::Result;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[allow(dead_code)]
pub struct BlockRow {
    pub block_height: u64,
    pub file_id: u32,
    pub block_hash: String,
    pub date_time: String,
    pub version: u32,
    pub prev_block_hash: String,
    pub merkle_root: String,
    pub bits: u32,
    pub nonce: u32,
    pub block_size: u64,
    pub tx_count: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[allow(dead_code)]
pub struct TxRow {
    pub transaction_id: u64,
    pub block_id: u64,
    pub txid: String,
    pub version: u32,
    pub lock_time: u32,
    pub is_segwit: bool,
    pub is_coinbase: bool,
    pub input_count: u32,
    pub output_count: u32,
    pub tx_size: u64,
    pub fee: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[allow(dead_code)]
pub struct OutputRow {
    pub output_id: u64,
    pub transaction_id: u64,
    pub txid: String,
    pub output_index: u32,
    pub value: u64,
    pub script_pubkey: String,
    pub script_type: String,
    pub data: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[allow(dead_code)]
pub struct InputRow {
    pub input_id: u64,
    pub transaction_id: u64,
    pub txid: String,
    pub input_index: u32,
    pub prev_txid: String,
    pub prev_vout: u32,
    pub script_sig: String,
    pub sequence_number: u32,
}

pub fn block_range(height: u64, range_size: u64) -> u64 {
    (height / range_size) * range_size
}

pub fn ensure_output_dir(path: &str) -> Result<()> {
    std::fs::create_dir_all(path)?;
    Ok(())
}

/// Load block_height -> date_time map from blocks.csv
pub fn load_block_dates(input_dir: &str) -> Result<std::collections::BTreeMap<u64, String>> {
    let path = format!("{}/blocks.csv", input_dir);
    let mut rdr = csv::Reader::from_path(&path)?;
    let mut map = std::collections::BTreeMap::new();
    for result in rdr.deserialize() {
        let row: BlockRow = result?;
        map.insert(row.block_height, row.date_time);
    }
    Ok(map)
}

/// Build range -> first date in that range from a block dates map
pub fn range_dates(
    block_dates: &std::collections::BTreeMap<u64, String>,
    range_size: u64,
) -> std::collections::BTreeMap<u64, String> {
    let mut map = std::collections::BTreeMap::new();
    for (&height, date) in block_dates {
        let range = block_range(height, range_size);
        map.entry(range).or_insert_with(|| date.clone());
    }
    map
}
