// src/analytic/opreturn.rs

use anyhow::Result;
use std::collections::{BTreeMap, HashMap};
use std::io::Write;

use super::{TxRow, OutputRow, block_range, load_block_dates, range_dates};

pub fn run(input_dir: &str, output_dir: &str, range_size: u64) -> Result<()> {
    println!("\n--- OP_RETURN Analytics ---");

    let block_dates = load_block_dates(input_dir)?;
    let rdates = range_dates(&block_dates, range_size);

    // Pass 1: tx_id -> block_id
    let tx_path = format!("{}/transactions.csv", input_dir);
    let mut rdr = csv::Reader::from_path(&tx_path)?;
    let mut tx_block: HashMap<u64, u64> = HashMap::new();
    for result in rdr.deserialize() {
        let row: TxRow = result?;
        tx_block.insert(row.transaction_id, row.block_id);
    }

    // Pass 2: filter OP_RETURN outputs
    let out_path = format!("{}/outputs.csv", input_dir);
    let mut rdr = csv::Reader::from_path(&out_path)?;

    let mut range_counts: BTreeMap<u64, (u64, u64)> = BTreeMap::new();
    let mut prefix_counts: HashMap<String, u64> = HashMap::new();
    let mut count = 0u64;

    for result in rdr.deserialize() {
        let row: OutputRow = result?;
        if row.script_type != "OP_RETURN" { continue; }

        let height = tx_block.get(&row.transaction_id).copied().unwrap_or(0);
        let range = block_range(height, range_size);
        let data_bytes = row.data.len() / 2;

        let entry = range_counts.entry(range).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += data_bytes as u64;

        if row.data.len() >= 8 {
            let prefix = row.data[..8].to_string();
            *prefix_counts.entry(prefix).or_insert(0) += 1;
        }

        count += 1;
    }

    let empty = String::new();

    let mut cnt_out = create_writer(&format!("{}/opreturncount.csv", output_dir),
        "BLOCK_RANGE,DATE_TIME,OP_RETURN_COUNT,OP_RETURN_TOTAL_BYTES")?;
    for (range, (cnt, bytes)) in &range_counts {
        let date = rdates.get(range).unwrap_or(&empty);
        writeln!(cnt_out, "{},{},{},{}", range, date, cnt, bytes)?;
    }

    let mut sorted: Vec<_> = prefix_counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));

    let mut proto_out = create_writer(&format!("{}/opreturnprotocol.csv", output_dir),
        "PREFIX_HEX,PREFIX_ASCII,COUNT")?;
    for (prefix_hex, cnt) in sorted.iter().take(100) {
        let ascii = hex_to_ascii(prefix_hex);
        writeln!(proto_out, "{},{},{}", prefix_hex, ascii, cnt)?;
    }

    println!("  OP_RETURN outputs: {} -> opreturncount.csv, opreturnprotocol.csv", count);
    Ok(())
}

fn hex_to_ascii(hex: &str) -> String {
    match hex::decode(hex) {
        Ok(bytes) => bytes.iter()
            .map(|&b| if b >= 0x20 && b <= 0x7E { b as char } else { '.' })
            .collect(),
        Err(_) => String::new(),
    }
}

fn create_writer(path: &str, header: &str) -> Result<std::io::BufWriter<std::fs::File>> {
    let file = std::fs::File::create(path)?;
    let mut w = std::io::BufWriter::new(file);
    writeln!(w, "{}", header)?;
    Ok(w)
}
