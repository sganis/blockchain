// src/analytic/utxoset.rs

use anyhow::Result;
use std::collections::BTreeMap;
use std::io::Write;

use super::{TxRow, block_range, load_block_dates, range_dates};

pub fn run(input_dir: &str, output_dir: &str, range_size: u64) -> Result<()> {
    println!("\n--- UTXO Analytics ---");

    let block_dates = load_block_dates(input_dir)?;
    let rdates = range_dates(&block_dates, range_size);

    let tx_path = format!("{}/transactions.csv", input_dir);
    let mut rdr = csv::Reader::from_path(&tx_path)?;

    let mut utxo_count: i64 = 0;
    let mut cumulative_sats: u64 = 0;
    let mut utxo_samples: BTreeMap<u64, i64> = BTreeMap::new();
    let mut supply_samples: BTreeMap<u64, u64> = BTreeMap::new();
    let mut count = 0u64;
    let mut current_range: Option<u64> = None;

    let subsidy = |height: u64| -> u64 {
        let halvings = height / 210_000;
        if halvings >= 64 { 0 } else { (50 * 100_000_000) >> halvings }
    };

    for result in rdr.deserialize() {
        let row: TxRow = result?;
        let range = block_range(row.block_id, range_size);

        let created = row.output_count as i64;
        let spent = if row.is_coinbase { 0i64 } else { row.input_count as i64 };
        utxo_count += created - spent;

        if row.is_coinbase {
            cumulative_sats += subsidy(row.block_id);
        }

        if current_range != Some(range) {
            if let Some(prev_range) = current_range {
                utxo_samples.insert(prev_range, utxo_count);
                supply_samples.insert(prev_range, cumulative_sats);
            }
            current_range = Some(range);
        }

        count += 1;
    }

    if let Some(range) = current_range {
        utxo_samples.insert(range, utxo_count);
        supply_samples.insert(range, cumulative_sats);
    }

    let empty = String::new();

    let mut utxo_out = create_writer(&format!("{}/utxosize.csv", output_dir),
        "BLOCK_RANGE,DATE_TIME,UTXO_COUNT")?;
    for (range, cnt) in &utxo_samples {
        let date = rdates.get(range).unwrap_or(&empty);
        writeln!(utxo_out, "{},{},{}", range, date, cnt)?;
    }

    let mut supply_out = create_writer(&format!("{}/supply.csv", output_dir),
        "BLOCK_RANGE,DATE_TIME,CUMULATIVE_SATS,CUMULATIVE_BTC")?;
    for (range, sats) in &supply_samples {
        let date = rdates.get(range).unwrap_or(&empty);
        let btc = *sats as f64 / 100_000_000.0;
        writeln!(supply_out, "{},{},{},{:.8}", range, date, sats, btc)?;
    }

    println!("  Transactions processed: {} -> utxosize.csv, supply.csv", count);
    Ok(())
}

fn create_writer(path: &str, header: &str) -> Result<std::io::BufWriter<std::fs::File>> {
    let file = std::fs::File::create(path)?;
    let mut w = std::io::BufWriter::new(file);
    writeln!(w, "{}", header)?;
    Ok(w)
}
