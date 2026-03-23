// src/analytic/script.rs

use anyhow::Result;
use std::collections::{BTreeMap, HashMap};
use std::io::Write;

use super::{TxRow, OutputRow, block_range, load_block_dates, range_dates};

const DUST_THRESHOLD: u64 = 546;

pub fn run(input_dir: &str, output_dir: &str, range_size: u64) -> Result<()> {
    println!("\n--- Script Analytics ---");

    let block_dates = load_block_dates(input_dir)?;
    let rdates = range_dates(&block_dates, range_size);

    // Pass 1: build tx_id -> block_id map
    let tx_path = format!("{}/transactions.csv", input_dir);
    let mut rdr = csv::Reader::from_path(&tx_path)?;
    let mut tx_block: HashMap<u64, u64> = HashMap::new();
    for result in rdr.deserialize() {
        let row: TxRow = result?;
        tx_block.insert(row.transaction_id, row.block_id);
    }
    println!("  TX->Block map: {} entries", tx_block.len());

    // Pass 2: read outputs, aggregate by block range
    let out_path = format!("{}/outputs.csv", input_dir);
    let mut rdr = csv::Reader::from_path(&out_path)?;

    let mut script_counts: BTreeMap<u64, [u64; 9]> = BTreeMap::new();
    let mut dust_counts: BTreeMap<u64, (u64, u64)> = BTreeMap::new();
    let mut count = 0u64;

    for result in rdr.deserialize() {
        let row: OutputRow = result?;
        let height = tx_block.get(&row.transaction_id).copied().unwrap_or(0);
        let range = block_range(height, range_size);

        let idx = normalize_script_type(&row.script_type);
        let counts = script_counts.entry(range).or_insert([0u64; 9]);
        counts[idx] += 1;

        if row.value < DUST_THRESHOLD {
            let dust = dust_counts.entry(range).or_insert((0, 0));
            dust.0 += 1;
            dust.1 += row.value;
        }

        count += 1;
    }

    let empty = String::new();

    let mut st_out = create_writer(&format!("{}/scripttype.csv", output_dir),
        "BLOCK_RANGE,DATE_TIME,P2PK,P2PKH,P2SH,P2WPKH,P2WSH,P2TR,OP_RETURN,MULTISIG,OTHER")?;
    for (range, c) in &script_counts {
        let date = rdates.get(range).unwrap_or(&empty);
        writeln!(st_out, "{},{},{},{},{},{},{},{},{},{},{}", range, date,
            c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], c[8])?;
    }

    let mut dust_out = create_writer(&format!("{}/dust.csv", output_dir),
        "BLOCK_RANGE,DATE_TIME,DUST_COUNT,DUST_TOTAL_SATS")?;
    for (range, (cnt, total)) in &dust_counts {
        let date = rdates.get(range).unwrap_or(&empty);
        writeln!(dust_out, "{},{},{},{}", range, date, cnt, total)?;
    }

    println!("  Outputs processed: {} -> scripttype.csv, dust.csv", count);
    Ok(())
}

fn normalize_script_type(st: &str) -> usize {
    if st.starts_with("P2PK") && !st.starts_with("P2PKH") { return 0; }
    if st.starts_with("P2PKH") { return 1; }
    if st == "P2SH" { return 2; }
    if st == "P2WPKH" { return 3; }
    if st == "P2WSH" { return 4; }
    if st == "P2TR" { return 5; }
    if st == "OP_RETURN" { return 6; }
    if st.contains("Multisig") { return 7; }
    8
}

fn create_writer(path: &str, header: &str) -> Result<std::io::BufWriter<std::fs::File>> {
    let file = std::fs::File::create(path)?;
    let mut w = std::io::BufWriter::new(file);
    writeln!(w, "{}", header)?;
    Ok(w)
}
