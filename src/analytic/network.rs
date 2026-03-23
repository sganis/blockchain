// src/analytic/network.rs

use anyhow::Result;
use std::collections::BTreeMap;
use std::io::Write;

use super::{BlockRow, TxRow, block_range, load_block_dates, range_dates};

pub fn run(input_dir: &str, output_dir: &str, range_size: u64) -> Result<()> {
    println!("\n--- Network Analytics ---");
    run_blocks(input_dir, output_dir)?;
    run_transactions(input_dir, output_dir, range_size)?;
    Ok(())
}

fn run_blocks(input_dir: &str, output_dir: &str) -> Result<()> {
    let path = format!("{}/blocks.csv", input_dir);
    let mut rdr = csv::Reader::from_path(&path)?;

    let mut interval_out = create_writer(&format!("{}/interval.csv", output_dir),
        "BLOCK_HEIGHT,DATE_TIME,INTERVAL_SECONDS")?;
    let mut fullness_out = create_writer(&format!("{}/fullness.csv", output_dir),
        "BLOCK_HEIGHT,DATE_TIME,TX_COUNT,BLOCK_SIZE")?;
    let mut velocity_out = create_writer(&format!("{}/velocity.csv", output_dir),
        "BLOCK_HEIGHT,DATE_TIME,TX_COUNT")?;

    let mut prev_time: Option<chrono::NaiveDateTime> = None;
    let mut count = 0u64;

    for result in rdr.deserialize() {
        let row: BlockRow = result?;
        let dt = chrono::NaiveDateTime::parse_from_str(&row.date_time, "%Y-%m-%d %H:%M:%S")
            .unwrap_or_default();

        if let Some(prev) = prev_time {
            let interval = (dt - prev).num_seconds();
            writeln!(interval_out, "{},{},{}", row.block_height, row.date_time, interval)?;
        }
        prev_time = Some(dt);

        writeln!(fullness_out, "{},{},{},{}", row.block_height, row.date_time, row.tx_count, row.block_size)?;
        writeln!(velocity_out, "{},{},{}", row.block_height, row.date_time, row.tx_count)?;
        count += 1;
    }

    println!("  Blocks processed: {} -> interval.csv, fullness.csv, velocity.csv", count);
    Ok(())
}

struct RangeStats {
    total_tx: u64,
    segwit_tx: u64,
}

fn run_transactions(input_dir: &str, output_dir: &str, range_size: u64) -> Result<()> {
    let block_dates = load_block_dates(input_dir)?;
    let rdates = range_dates(&block_dates, range_size);

    let path = format!("{}/transactions.csv", input_dir);
    let mut rdr = csv::Reader::from_path(&path)?;

    let mut ranges: BTreeMap<u64, RangeStats> = BTreeMap::new();
    let mut count = 0u64;

    for result in rdr.deserialize() {
        let row: TxRow = result?;
        let range = block_range(row.block_id, range_size);
        let stats = ranges.entry(range).or_insert_with(|| RangeStats {
            total_tx: 0, segwit_tx: 0,
        });
        stats.total_tx += 1;
        if row.is_segwit { stats.segwit_tx += 1; }
        count += 1;
    }

    let mut segwit_out = create_writer(&format!("{}/segwit.csv", output_dir),
        "BLOCK_RANGE,DATE_TIME,TOTAL_TX,SEGWIT_TX,SEGWIT_RATIO")?;

    let empty = String::new();
    for (range, stats) in &ranges {
        let date = rdates.get(range).unwrap_or(&empty);
        let ratio = if stats.total_tx > 0 {
            stats.segwit_tx as f64 / stats.total_tx as f64
        } else { 0.0 };
        writeln!(segwit_out, "{},{},{},{},{:.6}", range, date, stats.total_tx, stats.segwit_tx, ratio)?;
    }

    println!("  Transactions processed: {} -> segwit.csv, fee.csv", count);
    Ok(())
}

fn create_writer(path: &str, header: &str) -> Result<std::io::BufWriter<std::fs::File>> {
    let file = std::fs::File::create(path)?;
    let mut w = std::io::BufWriter::new(file);
    writeln!(w, "{}", header)?;
    Ok(w)
}
