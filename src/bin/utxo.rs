// src/bin/utxo.rs

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::path::Path;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[allow(dead_code)]
struct InputCsv {
    input_id: u64,
    transaction_id: u64,
    txid: String,
    input_index: u32,
    prev_txid: String,
    prev_vout: u32,
    script_sig: String,
    sequence_number: u32,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[allow(dead_code)]
struct OutputCsv {
    output_id: u64,
    transaction_id: u64,
    txid: String,
    output_index: u32,
    value: u64,
    script_pubkey: String,
    script_type: String,
}

#[derive(Debug, Hash, PartialEq, Eq)]
struct Outpoint {
    txid: String,
    vout: u32,
}

fn write_utxos_from_csv(input_file: &str, output_file: &str) -> Result<(), Box<dyn Error>> {
    let mut rdr_inputs = csv::Reader::from_path(input_file)?;
    let mut rdr_outputs = csv::Reader::from_path(output_file)?;

    let mut spent: HashSet<Outpoint> = HashSet::new();
    for result in rdr_inputs.deserialize() {
        let row: InputCsv = result?;
        spent.insert(Outpoint {
            txid: row.prev_txid,
            vout: row.prev_vout,
        });
    }

    let mut all_outputs: HashMap<Outpoint, OutputCsv> = HashMap::new();
    for result in rdr_outputs.deserialize() {
        let row: OutputCsv = result?;
        let key = Outpoint {
            txid: row.txid.clone(),
            vout: row.output_index,
        };
        all_outputs.insert(key, row);
    }

    let utxos: HashMap<_, _> = all_outputs
        .into_iter()
        .filter(|(outpoint, _)| !spent.contains(outpoint))
        .collect();

    let out_path = Path::new(output_file).parent().unwrap().join("utxos.csv");
    let mut wtr = csv::Writer::from_path(&out_path)?;
    wtr.write_record(&["OUTPUT_ID", "TXID", "VOUT", "VALUE", "SCRIPT_PUBKEY"])?;

    for (outpoint, output) in &utxos {
        wtr.write_record(&[
            &output.output_id.to_string(),
            &outpoint.txid,
            &output.output_index.to_string(),
            &output.value.to_string(),
            &output.script_pubkey,
        ])?;
    }

    wtr.flush()?;
    println!("UTXO CSV written to same directory as input: {:?}", out_path);

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    let input_file = args.get(1);
    let output_file = args.get(2);

    if input_file.is_none() || output_file.is_none() {
        eprintln!("Usage: utxo <inputs_csv> <outputs_csv>");
        return Ok(());
    }

    let input_file = input_file.unwrap();
    let output_file = output_file.unwrap();

    write_utxos_from_csv(input_file, output_file)?;

    Ok(())
}
