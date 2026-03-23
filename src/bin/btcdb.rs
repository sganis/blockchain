// src/bin/btcdb.rs

use anyhow::Result;
use blockchain::db;
use clap::{Parser, Subcommand};

fn default_db() -> String {
    if cfg!(windows) { "F:/csv/blockchain.db".into() } else { "data/csv/blockchain.db".into() }
}

fn default_input() -> String {
    if cfg!(windows) { "F:/csv".into() } else { "data/csv".into() }
}

fn default_output() -> String {
    if cfg!(windows) { "F:/csv/analytics/hodl.csv".into() } else { "data/csv/analytics/hodl.csv".into() }
}

#[derive(Parser)]
#[command(name = "btcdb", about = "Bitcoin blockchain SQLite database & analytics")]
struct Cli {
    /// Path to SQLite database file
    #[arg(long, default_value_t = default_db())]
    db: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Load CSV data into SQLite and build UTXO lifecycle
    Load {
        /// Path to directory containing source CSVs
        #[arg(long, default_value_t = default_input())]
        input: String,
    },
    /// Compute HODL waves (UTXO age distribution over time)
    Hodl {
        /// Output CSV path
        #[arg(long, default_value_t = default_output())]
        output: String,
        /// Block range size for snapshots
        #[arg(long, default_value_t = 1000)]
        range: u64,
    },
    /// Show top addresses by balance
    Richlist {
        /// Number of addresses to show
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    /// Query balance of a specific address
    Balance {
        /// Bitcoin address to query
        address: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    println!("Database: {}", cli.db);

    match cli.command {
        Command::Load { input } => {
            println!("Loading from: {}", input);
            let conn = db::open(&cli.db)?;
            db::create_schema(&conn)?;
            db::load_all(&conn, &input)?;
            db::build_lifecycle(&conn)?;
            println!("Done.");
        }
        Command::Hodl { output, range } => {
            let conn = db::open(&cli.db)?;
            db::hodl_waves(&conn, range, &output)?;
            println!("Output: {}", output);
        }
        Command::Richlist { limit } => {
            let conn = db::open(&cli.db)?;
            let list = db::rich_list(&conn, limit)?;
            println!("\n{:<5} {:<62} {:>15}", "#", "Address", "BTC");
            println!("{}", "-".repeat(84));
            for (i, (addr, btc)) in list.iter().enumerate() {
                println!("{:<5} {:<62} {:>15.8}", i + 1, addr, btc);
            }
        }
        Command::Balance { address } => {
            let conn = db::open(&cli.db)?;
            let (sats, utxos) = db::balance(&conn, &address)?;
            let btc = sats as f64 / 100_000_000.0;
            println!("Address: {}", address);
            println!("Balance: {:.8} BTC ({} sats)", btc, sats);
            println!("UTXOs:   {}", utxos);
        }
    }

    Ok(())
}
