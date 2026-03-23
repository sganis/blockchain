// src/parser.rs

use anyhow::{Result, Context};
use std::time::Instant;
use sha2::{Sha256, Digest};
use chrono::prelude::{TimeZone, Utc};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Cursor, Read, Write};
use std::path::Path;
use memmap2::Mmap;

use crate::model::*;
use crate::csv::CsvWriters;
use crate::hash;
use crate::transaction::get_tx_type;

pub struct BlockParser {
    id_gen: IdGenerator,
    writers: CsvWriters,
    pub tx_types: HashMap<String, usize>,
    pub debug: bool,
    pub address_cache: HashMap<String, u64>,
    pub block_height: u64,
    pub last_file: u32,
    csv_sizes: HashMap<String, u64>,
    append: bool,
}

impl BlockParser {
    pub fn new(output_dir: &str, debug: bool, append: bool) -> Result<Self> {
        let mut parser = Self {
            id_gen: IdGenerator::new(),
            writers: CsvWriters::new(output_dir, append)?,
            tx_types: HashMap::new(),
            debug,
            address_cache: HashMap::new(),
            block_height: 0,
            last_file: 0,
            csv_sizes: HashMap::new(),
            append,
        };

        if append {
            parser.load_state(output_dir)?;
        }

        Ok(parser)
    }

    fn state_path(output_dir: &str) -> String {
        format!("{}/state.json", output_dir)
    }

    fn load_state(&mut self, output_dir: &str) -> Result<()> {
        let path = Self::state_path(output_dir);
        if !Path::new(&path).exists() {
            return Ok(());
        }
        let data = std::fs::read_to_string(&path)?;
        let state: serde_json::Value = serde_json::from_str(&data)?;

        if let Some(h) = state.get("block_height").and_then(|v| v.as_u64()) {
            self.block_height = h;
        }
        if let Some(f) = state.get("last_file").and_then(|v| v.as_u64()) {
            self.last_file = f as u32;
        }
        if let Some(obj) = state.get("id_counters").and_then(|v| v.as_object()) {
            let map: HashMap<String, u64> = obj.iter()
                .filter_map(|(k, v)| v.as_u64().map(|n| (k.clone(), n)))
                .collect();
            self.id_gen.import(&map);
        }
        if let Some(obj) = state.get("address_cache").and_then(|v| v.as_object()) {
            for (addr, id) in obj {
                if let Some(n) = id.as_u64() {
                    self.address_cache.insert(addr.clone(), n);
                }
            }
        }
        if let Some(obj) = state.get("csv_sizes").and_then(|v| v.as_object()) {
            self.csv_sizes = obj.iter()
                .filter_map(|(k, v)| v.as_u64().map(|n| (k.clone(), n)))
                .collect();
            CsvWriters::truncate_main(output_dir, &self.csv_sizes)?;
        }

        println!("Resumed from state: block_height={}, last_file={}, addresses_cached={}",
            self.block_height, self.last_file, self.address_cache.len());
        Ok(())
    }

    pub fn save_state(&self, output_dir: &str) -> Result<()> {
        let state = serde_json::json!({
            "block_height": self.block_height,
            "last_file": self.last_file,
            "id_counters": self.id_gen.export(),
            "address_cache": self.address_cache,
            "csv_sizes": self.csv_sizes,
        });
        let path = Self::state_path(output_dir);
        let tmp_path = format!("{}.tmp", path);
        std::fs::write(&tmp_path, serde_json::to_string_pretty(&state)?)?;
        std::fs::rename(&tmp_path, &path)?;
        Ok(())
    }

    pub fn parse_header<T: Read>(&self, reader: &mut BufReader<T>) -> Result<Header> {
        let mut version = [0u8; 4];
        let mut prev_hash = [0u8; 32];
        let mut merkle_root = [0u8; 32];
        let mut time = [0u8; 4];
        let mut bits = [0u8; 4];
        let mut nonce = [0u8; 4];

        reader.read_exact(&mut version)?;
        reader.read_exact(&mut prev_hash)?;
        reader.read_exact(&mut merkle_root)?;
        reader.read_exact(&mut time)?;
        reader.read_exact(&mut bits)?;
        reader.read_exact(&mut nonce)?;
        Ok(Header { version, prev_hash, merkle_root, time, bits, nonce })
    }

    fn parse_input<T: Read>(&mut self, reader: &mut BufReader<T>, hasher: &mut Sha256) -> Result<Input> {
        let mut txid_bytes = [0u8; 32];
        let mut vout_bytes = [0u8; 4];

        reader.read_exact(&mut txid_bytes)?;
        hasher.update(&txid_bytes);

        let reversed_txid = hex::encode(txid_bytes.iter().rev().cloned().collect::<Vec<u8>>());

        reader.read_exact(&mut vout_bytes)?;
        hasher.update(&vout_bytes);
        let vout = u32::from_le_bytes(vout_bytes);

        let script_len = read_varint(reader)?;
        hasher.update(&script_len.data[..script_len.len as usize]);

        let mut script = vec![0u8; script_len.value as usize];
        reader.read_exact(&mut script)?;
        hasher.update(&script);

        let mut sequence_bytes = [0u8; 4];
        reader.read_exact(&mut sequence_bytes)?;
        hasher.update(&sequence_bytes);
        let sequence = u32::from_le_bytes(sequence_bytes);

        Ok(Input {
            id: self.id_gen.next_id("txi"),
            txid: reversed_txid,
            vout,
            script,
            sequence,
        })
    }

    fn parse_output<T: Read>(&mut self, reader: &mut BufReader<T>, hasher: &mut Sha256) -> Result<Output> {
        let mut amount_bytes = [0u8; 8];
        reader.read_exact(&mut amount_bytes)?;
        hasher.update(&amount_bytes);
        let amount = u64::from_le_bytes(amount_bytes);

        let script_len = read_varint(reader)?;
        hasher.update(&script_len.data[..script_len.len as usize]);

        let mut script = vec![0u8; script_len.value as usize];
        if script_len.value > 0 {
            reader.read_exact(&mut script)?;
            hasher.update(&script);
        }

        Ok(Output {
            id: self.id_gen.next_id("txo"),
            amount,
            script,
        })
    }

    pub fn parse_witnesses<T: Read>(&mut self, reader: &mut BufReader<T>, inputs: &[Input]) -> Result<Vec<Witness>> {
        let mut witnesses = Vec::new();

        for input in inputs {
            let wit_count = read_varint(reader)?;

            for j in 0..wit_count.value {
                let wit_len = read_varint(reader)?.value;
                let mut wit_data = vec![0u8; wit_len as usize];
                reader.read_exact(&mut wit_data)?;

                witnesses.push(Witness {
                    id: self.id_gen.next_id("wit"),
                    txiid: input.id,
                    index: j as usize,
                    data: wit_data,
                });
            }
        }

        Ok(witnesses)
    }

    fn calculate_txid(hasher: Sha256) -> String {
        let hash = hasher.finalize();
        hex::encode(&hash::reverse(&Sha256::digest(&hash)))
    }

    fn parse_transaction<T: Read>(&mut self, reader: &mut BufReader<T>) -> Result<Tx> {
        let mut hasher = Sha256::new();
        let mut version_bytes = [0u8; 4];

        reader.read_exact(&mut version_bytes)?;
        hasher.update(&version_bytes);
        let version = u32::from_le_bytes(version_bytes);

        let mut in_count = read_varint(reader)?;
        let mut has_witness = false;

        if in_count.value == 0 {
            has_witness = true;
            let mut flag = [0u8; 1];
            reader.read_exact(&mut flag)?;
            if flag[0] != 0x01 {
                return Err(anyhow::anyhow!("Invalid SegWit flag"));
            }
            in_count = read_varint(reader)?;
        }

        hasher.update(&in_count.data[..in_count.len as usize]);

        let mut inputs = Vec::with_capacity(in_count.value as usize);
        for _ in 0..in_count.value {
            inputs.push(self.parse_input(reader, &mut hasher)?);
        }

        let out_count = read_varint(reader)?;
        hasher.update(&out_count.data[..out_count.len as usize]);

        let mut outputs = Vec::with_capacity(out_count.value as usize);
        for _ in 0..out_count.value {
            outputs.push(self.parse_output(reader, &mut hasher)?);
        }

        let witnesses = if has_witness {
            Some(self.parse_witnesses(reader, &inputs)?)
        } else {
            None
        };

        let mut lock_time = [0u8; 4];
        reader.read_exact(&mut lock_time)?;
        hasher.update(&lock_time);

        let txid = Self::calculate_txid(hasher);

        Ok(Tx {
            id: self.id_gen.next_id("tx"),
            version,
            inputs,
            outputs,
            witnesses,
            lock_time,
            txid,
        })
    }

    fn write_block_data(&mut self, block: &Block, file_number: u32, block_height: u64) -> Result<()> {
        let timestamp = u32::from_le_bytes(block.header.time) as i64;
        let datetime = Utc.timestamp_opt(timestamp, 0).single().unwrap();
        let date_time_str = datetime.format("%Y-%m-%d %H:%M:%S");

        let mut hasher = Sha256::new();
        hasher.update(&block.header.version);
        hasher.update(&block.header.prev_hash);
        hasher.update(&block.header.merkle_root);
        hasher.update(&block.header.time);
        hasher.update(&block.header.bits);
        hasher.update(&block.header.nonce);
        let header_hash = hasher.finalize();
        let block_hash = hex::encode(&hash::reverse(&Sha256::digest(&header_hash)));

        let block_size = 80 + block.transactions.iter().map(|tx| {
            let base_size = 4 + 4 + 1 +
                tx.inputs.len() * 41 + 1 +
                tx.outputs.iter().map(|out| 8 + 1 + out.script.len()).sum::<usize>();
            let witness_size = if tx.witnesses.is_some() {
                tx.witnesses.as_ref().unwrap().iter().map(|w| w.data.len() + 1).sum::<usize>()
            } else { 0 };
            base_size + witness_size
        }).sum::<usize>();

        writeln!(self.writers.blocks, "{},{},{},{},{},{},{},{},{},{},{}",
            block_height, file_number, block_hash, date_time_str,
            u32::from_le_bytes(block.header.version),
            hex::encode(block.header.prev_hash_reversed()),
            hex::encode(block.header.merkle_root_reversed()),
            u32::from_le_bytes(block.header.bits),
            u32::from_le_bytes(block.header.nonce),
            block_size,
            block.transactions.len()
        )?;

        for (_tx_index, tx) in block.transactions.iter().enumerate() {
            let is_segwit = tx.witnesses.is_some();
            let tx_size = if is_segwit {
                let witness_size: usize = tx.witnesses.as_ref().unwrap().iter()
                    .map(|w| w.data.len() + 1).sum();
                let base_size = 4 + 1 + tx.inputs.len() * 41 + 1 +
                    tx.outputs.iter().map(|out| 8 + 1 + out.script.len()).sum::<usize>() + 4;
                base_size + witness_size + 2
            } else {
                4 + 1 + tx.inputs.len() * 41 + 1 +
                tx.outputs.iter().map(|out| 8 + 1 + out.script.len()).sum::<usize>() + 4
            };

            let is_coinbase = tx.inputs.len() == 1
                && tx.inputs[0].txid == "0000000000000000000000000000000000000000000000000000000000000000"
                && tx.inputs[0].vout == 0xFFFFFFFF;

            writeln!(self.writers.transactions, "{},{},{},{},{},{},{},{},{},{}",
                tx.id, block_height, tx.txid, tx.version,
                u32::from_le_bytes(tx.lock_time),
                is_segwit,
                is_coinbase,
                tx.inputs.len(),
                tx.outputs.len(),
                tx_size
            )?;

            for (input_index, input) in tx.inputs.iter().enumerate() {
                writeln!(self.writers.inputs, "{},{},{},{},{},{},{},{}",
                    input.id, tx.id, tx.txid, input_index, input.txid, input.vout,
                    hex::encode(&input.script), input.sequence)?;
            }

            for (output_index, output) in tx.outputs.iter().enumerate() {
                let mut tx_type = "unknown".to_string();
                let mut op_return_data = String::new();
                if !output.script.is_empty() {
                    if let Ok(info) = get_tx_type(&output.script) {
                        tx_type = info.script_type;
                        if let Some(data) = info.data {
                            op_return_data = data;
                        }
                        if let Some(address) = info.address {
                            let address_id = if let Some(&existing_id) = self.address_cache.get(&address) {
                                existing_id
                            } else {
                                let new_id = self.id_gen.next_id("addr");
                                let script_hash = hex::encode(&Sha256::digest(&output.script));
                                writeln!(self.writers.addresses, "{},{},{},{}",
                                    new_id, address, tx_type, script_hash)?;
                                self.address_cache.insert(address.clone(), new_id);
                                new_id
                            };
                            writeln!(self.writers.output_addresses, "{},{}",
                                output.id, address_id)?;
                        }
                        *self.tx_types.entry(tx_type.to_string()).or_insert(0) += 1;
                    }
                }

                writeln!(self.writers.outputs, "{},{},{},{},{},{},{},{}",
                    output.id, tx.id, tx.txid, output_index, output.amount,
                    hex::encode(&output.script), &tx_type, &op_return_data)?;
            }

            if let Some(witnesses) = &tx.witnesses {
                for witness in witnesses {
                    writeln!(self.writers.witnesses, "{},{},{},{},{},{},{}",
                        witness.id, tx.id, witness.txiid, witness.index,
                        witness.index, hex::encode(&witness.data), witness.data.len())?;
                }
            }
        }

        Ok(())
    }

    pub fn parse_block_file(&mut self, file_path: &Path, file_number: u32) -> Result<u32> {
        let file = File::open(file_path)
            .context(format!("Failed to open file: {}", file_path.display()))?;

        // Use memory-mapped I/O for large files, fall back to buffered reader for small/empty
        let metadata = file.metadata()?;
        if metadata.len() == 0 {
            return Ok(0);
        }

        let mmap = unsafe { Mmap::map(&file) }
            .context("Failed to memory-map file")?;
        let mut reader = BufReader::new(Cursor::new(&mmap[..]));
        let mut block_count = 0;

        loop {
            let mut magic_bytes = [0u8; 4];
            if reader.read_exact(&mut magic_bytes).is_err() {
                break;
            }

            let magic = u32::from_le_bytes(magic_bytes);
            if magic != MAGIC {
                return Err(anyhow::anyhow!("Invalid magic number in file {}", file_number));
            }

            let mut _size_bytes = [0u8; 4];
            reader.read_exact(&mut _size_bytes)?;

            let header = self.parse_header(&mut reader)?;

            let tx_count = read_varint(&mut reader)?;
            let mut transactions = Vec::with_capacity(tx_count.value as usize);

            for _ in 0..tx_count.value {
                transactions.push(self.parse_transaction(&mut reader)?);
            }

            let block = Block { header, transactions };

            if self.debug {
                let timestamp = u32::from_le_bytes(block.header.time) as i64;
                let datetime = Utc.timestamp_opt(timestamp, 0).single().unwrap();
                println!("FILE {} HEIGHT {} {} {}",
                    file_number, self.block_height,
                    datetime.format("%Y-%m-%d"),
                    datetime.format("%H:%M:%S"));
            }

            self.write_block_data(&block, file_number, self.block_height)?;
            self.block_height += 1;
            block_count += 1;
        }

        Ok(block_count)
    }

    pub fn run(&mut self, blocks_dir: &Path, output_dir: &str) -> Result<()> {
        let run_start = Instant::now();
        let mut total_blocks = 0u64;
        let mut files_processed = 0u32;
        let mut file_number = if self.append {
            self.last_file + 1
        } else {
            self.last_file
        };
        let mut consecutive_missing = 0u32;

        loop {
            let file_path = blocks_dir.join(format!("blk{:05}.dat", file_number));

            if !file_path.exists() {
                consecutive_missing += 1;
                if consecutive_missing >= 3 {
                    break;
                }
                file_number += 1;
                continue;
            }
            consecutive_missing = 0;

            let file_start = Instant::now();
            let saved_height = self.block_height;
            let saved_ids = self.id_gen.export();

            match self.parse_block_file(&file_path, file_number) {
                Ok(block_count) => {
                    total_blocks += block_count as u64;
                    self.last_file = file_number;
                    files_processed += 1;

                    self.writers.commit()?;
                    self.csv_sizes = self.writers.main_sizes();
                    self.save_state(output_dir)?;

                    let dur = file_start.elapsed();
                    println!("blk{:05}.dat  {} blocks  {:.2?}  (total height: {})",
                        file_number, block_count, dur, self.block_height);
                }
                Err(e) => {
                    self.block_height = saved_height;
                    self.id_gen.import(&saved_ids);
                    self.writers.discard()?;
                    eprintln!("Error in blk{:05}.dat: {} — skipping", file_number, e);
                }
            }

            file_number += 1;
        }

        let duration = run_start.elapsed();
        println!("\n=== Done ===");
        println!("Files: {}  Blocks: {}  Time: {:.2?}  Height: {}",
            files_processed, total_blocks, duration, self.block_height);

        Ok(())
    }
}

#[cfg(test)]
#[path = "parsertest.rs"]
mod tests;
