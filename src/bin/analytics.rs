// src/bin/analytics.rs

use anyhow::Result;
use blockchain::analytic;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "analytics", about = "Bitcoin blockchain CSV analytics")]
struct Cli {
    /// Path to directory containing source CSVs (blocks.csv, transactions.csv, etc.)
    #[arg(long, default_value = "F:/csv")]
    input: String,

    /// Path to directory for output summary CSVs
    #[arg(long, default_value = "F:/csv/analytics")]
    output: String,

    /// Block range size for aggregation
    #[arg(long, default_value_t = 1000)]
    range: u64,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run all analytics
    All,
    /// Block intervals, fullness, segwit adoption, fees, velocity
    Network,
    /// Script type evolution and dust detection
    Script,
    /// UTXO set size and coin supply
    Utxo,
    /// Difficulty analysis and coinbase messages
    Mining,
    /// OP_RETURN usage and protocol analysis
    Opreturn,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    analytic::ensure_output_dir(&cli.output)?;

    println!("Bitcoin Analytics");
    println!("Input:  {}", cli.input);
    println!("Output: {}", cli.output);
    println!("Range:  {}", cli.range);

    match cli.command {
        Command::All => {
            analytic::network::run(&cli.input, &cli.output, cli.range)?;
            analytic::mining::run(&cli.input, &cli.output, cli.range)?;
            analytic::script::run(&cli.input, &cli.output, cli.range)?;
            analytic::opreturn::run(&cli.input, &cli.output, cli.range)?;
            analytic::utxoset::run(&cli.input, &cli.output, cli.range)?;
        }
        Command::Network => analytic::network::run(&cli.input, &cli.output, cli.range)?,
        Command::Script => analytic::script::run(&cli.input, &cli.output, cli.range)?,
        Command::Utxo => analytic::utxoset::run(&cli.input, &cli.output, cli.range)?,
        Command::Mining => analytic::mining::run(&cli.input, &cli.output, cli.range)?,
        Command::Opreturn => analytic::opreturn::run(&cli.input, &cli.output, cli.range)?,
    }

    println!("Done.");
    Ok(())
}
