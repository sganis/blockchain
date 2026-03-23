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
    fees: Vec<u64>,
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
            total_tx: 0, segwit_tx: 0, fees: Vec::new(),
        });
        stats.total_tx += 1;
        if row.is_segwit { stats.segwit_tx += 1; }
        if !row.is_coinbase { stats.fees.push(row.fee); }
        count += 1;
    }

    let mut segwit_out = create_writer(&format!("{}/segwit.csv", output_dir),
        "BLOCK_RANGE,DATE_TIME,TOTAL_TX,SEGWIT_TX,SEGWIT_RATIO")?;
    let mut fee_out = create_writer(&format!("{}/fee.csv", output_dir),
        "BLOCK_RANGE,DATE_TIME,MEAN_FEE,MEDIAN_FEE,MIN_FEE,MAX_FEE,TOTAL_FEE")?;

    let empty = String::new();
    for (range, stats) in &mut ranges {
        let date = rdates.get(range).unwrap_or(&empty);
        let ratio = if stats.total_tx > 0 {
            stats.segwit_tx as f64 / stats.total_tx as f64
        } else { 0.0 };
        writeln!(segwit_out, "{},{},{},{},{:.6}", range, date, stats.total_tx, stats.segwit_tx, ratio)?;

        if stats.fees.is_empty() {
            writeln!(fee_out, "{},{},0,0,0,0,0", range, date)?;
        } else {
            stats.fees.sort_unstable();
            let total: u64 = stats.fees.iter().sum();
            let mean = total / stats.fees.len() as u64;
            let median = stats.fees[stats.fees.len() / 2];
            let min = stats.fees[0];
            let max = *stats.fees.last().unwrap();
            writeln!(fee_out, "{},{},{},{},{},{},{}", range, date, mean, median, min, max, total)?;
        }
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
