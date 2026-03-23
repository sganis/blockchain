// src/analytic/mining.rs

use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::io::Write;

use super::{BlockRow, TxRow, InputRow};

pub fn run(input_dir: &str, output_dir: &str, _range_size: u64) -> Result<()> {
    println!("\n--- Mining Analytics ---");
    run_difficulty(input_dir, output_dir)?;
    run_coinbase(input_dir, output_dir)?;
    Ok(())
}

fn bits_to_difficulty(bits: u32) -> f64 {
    let exp = (bits >> 24) as i32;
    let coeff = (bits & 0x00FFFFFF) as f64;
    if coeff == 0.0 { return 0.0; }
    (0x00FFFF_u32 as f64 / coeff) * 2_f64.powi(8 * (0x1d - exp))
}

fn run_difficulty(input_dir: &str, output_dir: &str) -> Result<()> {
    let path = format!("{}/blocks.csv", input_dir);
    let mut rdr = csv::Reader::from_path(&path)?;

    let mut out = create_writer(&format!("{}/difficulty.csv", output_dir),
        "BLOCK_HEIGHT,DATE_TIME,BITS,DIFFICULTY")?;

    let mut count = 0u64;
    for result in rdr.deserialize() {
        let row: BlockRow = result?;
        let diff = bits_to_difficulty(row.bits);
        writeln!(out, "{},{},{},{:.4}", row.block_height, row.date_time, row.bits, diff)?;
        count += 1;
    }

    println!("  Difficulty: {} blocks → difficulty.csv", count);
    Ok(())
}

fn extract_ascii(hex_str: &str) -> String {
    let bytes = match hex::decode(hex_str) {
        Ok(b) => b,
        Err(_) => return String::new(),
    };

    let mut runs = Vec::new();
    let mut current = String::new();

    for &b in &bytes {
        if b >= 0x20 && b <= 0x7E {
            current.push(b as char);
        } else {
            if current.len() >= 4 {
                runs.push(current.clone());
            }
            current.clear();
        }
    }
    if current.len() >= 4 {
        runs.push(current);
    }

    runs.join(" | ")
}

fn run_coinbase(input_dir: &str, output_dir: &str) -> Result<()> {
    let block_dates = super::load_block_dates(input_dir)?;

    // Pass 1: find coinbase transaction IDs and their block heights
    let tx_path = format!("{}/transactions.csv", input_dir);
    let mut rdr = csv::Reader::from_path(&tx_path)?;

    let mut coinbase_txs: HashSet<u64> = HashSet::new();
    let mut tx_block: HashMap<u64, u64> = HashMap::new();
    let mut tx_txid: HashMap<u64, String> = HashMap::new();

    for result in rdr.deserialize() {
        let row: TxRow = result?;
        if row.is_coinbase {
            coinbase_txs.insert(row.transaction_id);
            tx_block.insert(row.transaction_id, row.block_id);
            tx_txid.insert(row.transaction_id, row.txid);
        }
    }

    // Pass 2: read inputs for those coinbase txs
    let inp_path = format!("{}/inputs.csv", input_dir);
    let mut rdr = csv::Reader::from_path(&inp_path)?;

    let mut out = create_writer(&format!("{}/coinbase.csv", output_dir),
        "BLOCK_HEIGHT,DATE_TIME,TXID,ASCII_MESSAGE")?;

    let mut count = 0u64;
    for result in rdr.deserialize() {
        let row: InputRow = result?;
        if coinbase_txs.contains(&row.transaction_id) {
            let msg = extract_ascii(&row.script_sig);
            if !msg.is_empty() {
                let height = tx_block.get(&row.transaction_id).copied().unwrap_or(0);
                let date = block_dates.get(&height).map(|s| s.as_str()).unwrap_or("");
                let txid = tx_txid.get(&row.transaction_id).map(|s| s.as_str()).unwrap_or("");
                let escaped = if msg.contains(',') || msg.contains('"') {
                    format!("\"{}\"", msg.replace('"', "\"\""))
                } else {
                    msg
                };
                writeln!(out, "{},{},{},{}", height, date, txid, escaped)?;
                count += 1;
            }
        }
    }

    println!("  Coinbase messages: {} → coinbase.csv", count);
    Ok(())
}

fn create_writer(path: &str, header: &str) -> Result<std::io::BufWriter<std::fs::File>> {
    let file = std::fs::File::create(path)?;
    let mut w = std::io::BufWriter::new(file);
    writeln!(w, "{}", header)?;
    Ok(w)
}
