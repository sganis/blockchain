// src/main.rs

use anyhow::Result;
use blockchain::parser::BlockParser;
use clap::Parser;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "btcparse", about = "Bitcoin .dat block file parser to CSV")]
struct Cli {
    /// Path to the blocks directory containing blkNNNNN.dat files
    #[arg(long, default_value = default_blocks_dir())]
    blocks_dir: PathBuf,

    /// Path to the CSV output directory
    #[arg(long, default_value = default_output_dir())]
    output_dir: String,

    /// Enable debug output
    #[arg(long, default_value_t = false)]
    debug: bool,

    /// Wipe existing CSVs and start from file 0
    #[arg(long, default_value_t = false)]
    fresh: bool,
}

fn default_blocks_dir() -> &'static str {
    if cfg!(windows) { "F:/btc/blocks" } else { "data/btc/blocks" }
}

fn default_output_dir() -> &'static str {
    if cfg!(windows) { "F:/csv" } else { "data/csv" }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let append = !cli.fresh && Path::new(&format!("{}/state.json", cli.output_dir)).exists();

    let mut parser = BlockParser::new(&cli.output_dir, cli.debug, append)?;

    println!("Bitcoin Block Parser");
    println!("Blocks: {}", cli.blocks_dir.display());
    println!("Output: {}", cli.output_dir);
    if append {
        println!("Resuming from blk{:05}.dat (height {})", parser.last_file + 1, parser.block_height);
    } else {
        println!("Starting fresh");
    }

    parser.run(&cli.blocks_dir, &cli.output_dir)?;
    Ok(())
}
