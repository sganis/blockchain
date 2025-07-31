mod opcodes;
mod hash;
mod transaction;

use anyhow::{Result, Context};
use std::time::Instant;
use hex;
use sha2::{Sha256, Digest};
use chrono::prelude::{TimeZone, Utc};
use std::{
    fs::File, 
    io::{BufReader, Write, Read, BufWriter},
    collections::HashMap,
    path::{Path, PathBuf},
};
use opcodes::script_to_opcodes;
use transaction::get_tx_type;

const MAGIC: u32 = 0xD9B4BEF9; // Fixed: Use proper hex representation
const BUFFER_SIZE: usize = 8 * 1024 * 1024; // 8MB buffer

#[derive(Debug, Clone)]
struct VarInt {
    value: u64,
    len: u32,
    data: [u8; 9],
}

impl VarInt {
    fn new(value: u64, len: u32, data: [u8; 9]) -> Self {
        Self { value, len, data }
    }
}

fn read_varint<T: Read>(reader: &mut BufReader<T>) -> Result<VarInt> {
    let mut buffer = [0u8; 9];
    
    reader.read_exact(&mut buffer[0..1])
        .context("Failed to read varint first byte")?;
    
    let first_byte = buffer[0];
    
    match first_byte {
        253 => {
            reader.read_exact(&mut buffer[1..3])
                .context("Failed to read varint 2-byte value")?;
            let value = u16::from_le_bytes([buffer[1], buffer[2]]) as u64;
            Ok(VarInt::new(value, 3, buffer))
        },
        254 => {
            reader.read_exact(&mut buffer[1..5])
                .context("Failed to read varint 4-byte value")?;
            let value = u32::from_le_bytes([buffer[1], buffer[2], buffer[3], buffer[4]]) as u64;
            Ok(VarInt::new(value, 5, buffer))
        },
        255 => {
            reader.read_exact(&mut buffer[1..9])
                .context("Failed to read varint 8-byte value")?;
            let value = u64::from_le_bytes([
                buffer[1], buffer[2], buffer[3], buffer[4],
                buffer[5], buffer[6], buffer[7], buffer[8]
            ]);
            Ok(VarInt::new(value, 9, buffer))
        },
        _ => {
            Ok(VarInt::new(first_byte as u64, 1, buffer))
        }
    }
}

#[derive(Debug)]
struct Header {
    version: [u8; 4],
    prev_hash: [u8; 32],
    merkle_root: [u8; 32],
    time: [u8; 4],
    bits: [u8; 4],
    nonce: [u8; 4],
}

#[derive(Debug)]
struct Block {
    header: Header,
    transactions: Vec<Tx>,
}

#[derive(Debug)]
struct Tx {
    id: u64,
    version: u32,
    flag: Option<[u8; 2]>,
    inputs: Vec<Input>,
    outputs: Vec<Output>,
    witnesses: Option<Vec<Witness>>,
    lock_time: [u8; 4],
    txid: String,
}

#[derive(Debug)]
struct Input {
    id: u64,
    txid: String,
    vout: u32,
    script: Vec<u8>,
    sequence: u32,
}

#[derive(Debug)]
struct Output {
    id: u64,
    amount: u64,
    script: Vec<u8>,
}

#[derive(Debug)]
struct Witness {
    id: u64,
    txiid: u64,
    index: usize,
    data: Vec<u8>,
}

pub struct IdGenerator {
    counters: HashMap<&'static str, u64>,
}

impl IdGenerator {
    pub fn new() -> Self {
        Self {
            counters: HashMap::new(),
        }
    }

    pub fn next_id(&mut self, table: &'static str) -> u64 {
        let counter = self.counters.entry(table).or_insert(1);
        let id = *counter;
        *counter += 1;
        id
    }
}

struct CsvWriters {
    blocks: BufWriter<File>,
    transactions: BufWriter<File>,
    inputs: BufWriter<File>,
    outputs: BufWriter<File>,
    witnesses: BufWriter<File>,
    addresses: BufWriter<File>,
    output_addresses: BufWriter<File>,
}

impl CsvWriters {
    fn new(output_dir: &str) -> Result<Self> {
        std::fs::create_dir_all(output_dir)
            .context("Failed to create output directory")?;

        let blocks = Self::create_csv_file(&format!("{}/blocks.csv", output_dir), 
            "BLOCK_ID,FILE_ID,BLOCK_HASH,DATE_TIME,VERSION,PREV_BLOCK_HASH,MERKLE_ROOT,BITS,NONCE,BLOCK_SIZE,TX_COUNT")?;
        
        let transactions = Self::create_csv_file(&format!("{}/transactions.csv", output_dir), 
            "TRANSACTION_ID,BLOCK_ID,TXID,VERSION,LOCK_TIME,IS_SEGWIT,INPUT_COUNT,OUTPUT_COUNT,TX_SIZE")?;
        
        let inputs = Self::create_csv_file(&format!("{}/inputs.csv", output_dir), 
            "INPUT_ID,TRANSACTION_ID,INPUT_INDEX,PREV_TXID,PREV_VOUT,SCRIPT_SIG,SEQUENCE_NUMBER")?;
        
        let outputs = Self::create_csv_file(&format!("{}/outputs.csv", output_dir), 
            "OUTPUT_ID,TRANSACTION_ID,OUTPUT_INDEX,VALUE,SCRIPT_PUBKEY,SCRIPT_TYPE")?;
        
        let witnesses = Self::create_csv_file(&format!("{}/witnesses.csv", output_dir), 
            "WITNESS_ID,TRANSACTION_ID,INPUT_ID,INPUT_INDEX,WITNESS_INDEX,WITNESS_DATA,WITNESS_SIZE")?;

        let addresses = Self::create_csv_file(&format!("{}/addresses.csv", output_dir), 
            "ADDRESS_ID,ADDRESS,SCRIPT_TYPE,SCRIPT_HASH")?;

        let output_addresses = Self::create_csv_file(&format!("{}/output_addresses.csv", output_dir), 
            "OUTPUT_ID,ADDRESS_ID")?;

        Ok(Self {
            blocks,
            transactions,
            inputs,
            outputs,
            witnesses,
            addresses,
            output_addresses,
        })
    }

    fn create_csv_file(path: &str, header: &str) -> Result<BufWriter<File>> {
        let file = File::create(path)
            .context(format!("Unable to create file: {}", path))?;
        let mut writer = BufWriter::new(file);
        writeln!(writer, "{}", header)?;
        Ok(writer)
    }

    fn flush_all(&mut self) -> Result<()> {
        self.blocks.flush().context("Failed to flush blocks file")?;
        self.transactions.flush().context("Failed to flush transactions file")?;
        self.inputs.flush().context("Failed to flush inputs file")?;
        self.outputs.flush().context("Failed to flush outputs file")?;
        self.witnesses.flush().context("Failed to flush witnesses file")?;
        self.addresses.flush().context("Failed to flush addresses file")?;
        self.output_addresses.flush().context("Failed to flush output_addresses file")?;
        Ok(())
    }
}

struct BlockParser {
    id_gen: IdGenerator,
    writers: CsvWriters,
    tx_types: HashMap<String, usize>,
    debug: bool,
    address_cache: HashMap<String, u64>, // Cache for address IDs
}

impl BlockParser {
    fn new(output_dir: &str, debug: bool) -> Result<Self> {
        Ok(Self {
            id_gen: IdGenerator::new(),
            writers: CsvWriters::new(output_dir)?,
            tx_types: HashMap::new(),
            debug,
            address_cache: HashMap::new(),
        })
    }

    fn parse_header<T: Read>(&self, reader: &mut BufReader<T>) -> Result<Header> {
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

    fn parse_witnesses<T: Read>(&mut self, reader: &mut BufReader<T>, inputs: &[Input]) -> Result<Vec<Witness>> {
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

        // Check for SegWit flag
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

        // Parse inputs
        let mut inputs = Vec::with_capacity(in_count.value as usize);
        for _ in 0..in_count.value {
            inputs.push(self.parse_input(reader, &mut hasher)?);
        }

        // Parse outputs
        let out_count = read_varint(reader)?;
        hasher.update(&out_count.data[..out_count.len as usize]);

        let mut outputs = Vec::with_capacity(out_count.value as usize);
        for _ in 0..out_count.value {
            outputs.push(self.parse_output(reader, &mut hasher)?);
        }

        // Parse witnesses if present
        let witnesses = if has_witness {
            Some(self.parse_witnesses(reader, &inputs)?)
        } else {
            None
        };

        // Lock time
        let mut lock_time = [0u8; 4];
        reader.read_exact(&mut lock_time)?;
        hasher.update(&lock_time);

        let txid = Self::calculate_txid(hasher);

        Ok(Tx {
            id: self.id_gen.next_id("tx"),
            version,
            flag: if has_witness { Some([0x00, 0x01]) } else { None },
            inputs,
            outputs,
            witnesses,
            lock_time,
            txid,
        })
    }

    fn write_block_data(&mut self, block: &Block, file_number: u32, block_number: u32) -> Result<()> {
        let timestamp = u32::from_le_bytes(block.header.time) as i64;
        let datetime = Utc.timestamp_opt(timestamp, 0).single().unwrap();
        let date_time_str = datetime.format("%Y-%m-%d %H:%M:%S");

        // Calculate block hash
        let mut hasher = Sha256::new();
        hasher.update(&block.header.version);
        hasher.update(&block.header.prev_hash);
        hasher.update(&block.header.merkle_root);
        hasher.update(&block.header.time);
        hasher.update(&block.header.bits);
        hasher.update(&block.header.nonce);
        let header_hash = hasher.finalize();
        let block_hash = hex::encode(&hash::reverse(&Sha256::digest(&header_hash)));

        // Calculate block size (approximate)
        let block_size = 80 + block.transactions.iter().map(|tx| {
            let base_size = 4 + 4 + 1 + // version + locktime + input_count
                tx.inputs.len() * 41 + // inputs (approximate)
                1 + // output_count
                tx.outputs.iter().map(|out| 8 + 1 + out.script.len()).sum::<usize>(); // outputs
            
            let witness_size = if tx.witnesses.is_some() {
                tx.witnesses.as_ref().unwrap().iter().map(|w| w.data.len() + 1).sum::<usize>()
            } else { 0 };
            
            base_size + witness_size
        }).sum::<usize>();

        // Write block
        // BLOCK_ID,FILE_ID,BLOCK_HASH,DATE_TIME,VERSION,PREV_BLOCK_HASH,MERKLE_ROOT,BITS,NONCE,BLOCK_SIZE,TX_COUNT
        writeln!(self.writers.blocks, "{},{},{},{},{},{},{},{},{},{},{}", 
            block_number, file_number, block_hash, date_time_str,
            u32::from_le_bytes(block.header.version),
            hex::encode(block.header.prev_hash), 
            hex::encode(block.header.merkle_root), 
            u32::from_le_bytes(block.header.bits),
            u32::from_le_bytes(block.header.nonce),
            block_size,
            block.transactions.len()
        )?;

        // Write transactions and related data
        for (tx_index, tx) in block.transactions.iter().enumerate() {
            let is_segwit = tx.witnesses.is_some();
            let tx_size = if is_segwit {
                // SegWit transaction size calculation (approximate)
                let witness_size: usize = tx.witnesses.as_ref().unwrap().iter()
                    .map(|w| w.data.len() + 1).sum();
                let base_size = 4 + 1 + tx.inputs.len() * 41 + 1 + 
                    tx.outputs.iter().map(|out| 8 + 1 + out.script.len()).sum::<usize>() + 4;
                base_size + witness_size + 2 // +2 for segwit flag
            } else {
                4 + 1 + tx.inputs.len() * 41 + 1 + 
                tx.outputs.iter().map(|out| 8 + 1 + out.script.len()).sum::<usize>() + 4
            };

            // TRANSACTION_ID,BLOCK_ID,TXID,VERSION,LOCK_TIME,IS_SEGWIT,INPUT_COUNT,OUTPUT_COUNT,TX_SIZE
            writeln!(self.writers.transactions, "{},{},{},{},{},{},{},{},{}", 
                tx.id, block_number, tx.txid, tx.version, 
                u32::from_le_bytes(tx.lock_time),
                is_segwit,
                tx.inputs.len(),
                tx.outputs.len(),
                tx_size
            )?;

                    
            // INPUT_ID,TRANSACTION_ID,INPUT_INDEX,PREV_TXID,PREV_VOUT,SCRIPT_SIG,SEQUENCE_NUMBER
            // Write inputs
            for (input_index, input) in tx.inputs.iter().enumerate() {
                writeln!(self.writers.inputs, "{},{},{},{},{},{},{}", 
                    input.id, tx.id, input_index, input.txid, input.vout, 
                    hex::encode(&input.script), input.sequence)?;
            }
        
            // Write outputs
            for (output_index, output) in tx.outputs.iter().enumerate() {                
                // Extract and write address if available
                let mut tx_type = "unknown".to_string();
                if !output.script.is_empty() {
                    if let Ok((tx_typ, address_opt)) = get_tx_type(&output.script) {
                        tx_type = tx_typ;
                        if let Some(address) = address_opt {
                            // Get or create address ID
                            let address_id = if let Some(&existing_id) = self.address_cache.get(&address) {
                                existing_id
                            } else {
                                let new_id = self.id_gen.next_id("addr");                                
                                let script_hash = hex::encode(&Sha256::digest(&output.script));

                                // ADDRESS_ID,ADDRESS,SCRIPT_TYPE,SCRIPT_HASH
                                writeln!(self.writers.addresses, "{},{},{},{}", 
                                    new_id, address, tx_type, script_hash)?;
                                self.address_cache.insert(address.clone(), new_id);
                                new_id
                            };

                            //  OUTPUT_ID,ADDRESS_ID
                            // Write output-address mapping
                            writeln!(self.writers.output_addresses, "{},{}", 
                                output.id, address_id)?;
                        }
                        
                        // Track transaction types
                        *self.tx_types.entry(tx_type.to_string()).or_insert(0) += 1;
                    }
                }

                // OUTPUT_ID,TRANSACTION_ID,OUTPUT_INDEX,VALUE,SCRIPT_PUBKEY,SCRIPT_TYPE
                writeln!(self.writers.outputs, "{},{},{},{},{},{}", 
                    output.id, tx.id, output_index, output.amount, 
                    hex::encode(&output.script), &tx_type)?;
            }

                    
        // let witnesses = Self::create_csv_file(&format!("{}/witnesses.csv", output_dir), 
        //     "WITNESS_ID,TRANSACTION_ID,INPUT_ID,INPUT_INDEX,WITNESS_INDEX,WITNESS_DATA,WITNESS_SIZE")?;

            // Write witnesses
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

    fn parse_block_file(&mut self, file_path: &Path, file_number: u32) -> Result<u32> {
        let file = File::open(file_path)
            .context(format!("Failed to open file: {}", file_path.display()))?;
        let mut reader = BufReader::with_capacity(BUFFER_SIZE, file);
        let mut block_count = 0;

        loop {
            let mut magic_bytes = [0u8; 4];
            if reader.read_exact(&mut magic_bytes).is_err() {
                break; // EOF
            }

            let magic = u32::from_le_bytes(magic_bytes);
            if magic != MAGIC {
                return Err(anyhow::anyhow!("Invalid magic number in file {}", file_number));
            }

            // Read block size (we don't use it but need to consume it)
            let mut _size_bytes = [0u8; 4];
            reader.read_exact(&mut _size_bytes)?;

            // Parse block header
            let header = self.parse_header(&mut reader)?;

            // Parse transactions
            let tx_count = read_varint(&mut reader)?;
            let mut transactions = Vec::with_capacity(tx_count.value as usize);

            for _ in 0..tx_count.value {
                transactions.push(self.parse_transaction(&mut reader)?);
            }

            let block = Block { header, transactions };
            
            if self.debug {
                let timestamp = u32::from_le_bytes(block.header.time) as i64;
                let datetime = Utc.timestamp_opt(timestamp, 0).single().unwrap(); // Fixed: Use single()
                println!("FILE {} BLOCK {} {} {}", 
                    file_number, block_count, 
                    datetime.format("%Y-%m-%d"), 
                    datetime.format("%H:%M:%S"));
            }

            self.write_block_data(&block, file_number, block_count)?;
            block_count += 1;

            // if self.debug && block_count >= 30 {
            //     break;
            // }
        }

        Ok(block_count)
    }

    fn run(&mut self, blocks_dir: &Path, file_range: std::ops::Range<u32>) -> Result<()> { // Fixed: Accept &Path
        let start = Instant::now();
        let mut total_blocks = 0;

        for file_number in file_range.clone() {
            let file_start = Instant::now();
            let file_path = blocks_dir.join(format!("blk{:05}.dat", file_number));
            
            if !file_path.exists() {
                if self.debug {
                    println!("File {} does not exist, skipping", file_path.display());
                }
                continue;
            }

            match self.parse_block_file(&file_path, file_number) {
                Ok(block_count) => {
                    total_blocks += block_count;
                    let file_duration = file_start.elapsed();
                    println!("Processed {} blocks from file {} in {:.2?}", 
                        block_count, file_number, file_duration);
                }
                Err(e) => {
                    eprintln!("Error processing file {}: {}", file_number, e);
                    continue;
                }
            }

            // Flush periodically
            if file_number % 10 == 0 {
                self.writers.flush_all()?;
            }
        }

        self.writers.flush_all()?;

        let duration = start.elapsed();
        let files_processed = file_range.end - file_range.start;
        let blocks_per_second = if duration.as_secs() > 0 {
            total_blocks as f64 / duration.as_secs_f64()
        } else {
            0.0
        };

        println!("\n=== Processing Summary ===");
        println!("Files processed: {}", files_processed);
        println!("Total blocks: {}", total_blocks);
        println!("Total time: {:.2?}", duration);
        println!("Average blocks/second: {:.2}", blocks_per_second);
        
        if !self.tx_types.is_empty() {
            println!("\n--- Transaction Type Summary ---");
            for (tx_type, count) in &self.tx_types {
                println!("{:<15} {}", tx_type, count);
            }
        }

        Ok(())
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    
    // Platform detection
    let root = if cfg!(windows) {
        PathBuf::from("F:/btc")
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("data/btc")
    };

    let blocks_path = root.join("blocks"); // Fixed: Use PathBuf::join
    let csv_path = root.parent().unwrap().join("csv"); // Fixed: Navigate properly

    let blocks_dir = args.get(1)
        .map(|s| PathBuf::from(s)) // Fixed: Convert to PathBuf
        .unwrap_or(blocks_path);

    let output_dir = args.get(2)
        .map(|s| s.to_string())
        .unwrap_or_else(|| csv_path.to_string_lossy().to_string()); // Fixed: Convert PathBuf to String

    let start_file: u32 = args.get(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    
    let end_file: u32 = args.get(4)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    
    let debug = true;

    println!("Bitcoin Block Parser");
    println!("Blocks directory: {}", blocks_dir.display()); // Fixed: Use display()
    println!("Output directory: {}", output_dir);
    println!("File range: {} to {}", start_file, end_file);
    println!("Debug mode: {}", debug);

    let mut parser = BlockParser::new(&output_dir, debug)?;
    parser.run(&blocks_dir, start_file..end_file)?; // Fixed: Pass &Path

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::fs;
    use tempfile::TempDir;
    use chrono::{Datelike, Timelike};
    use hex;

    // Genesis block data (block 0) - well-known constants
    const GENESIS_BLOCK_HASH: &str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    const GENESIS_PREV_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const GENESIS_MERKLE_ROOT: &str = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
    const GENESIS_TIMESTAMP: u32 = 1231006505; // 2009-01-03 18:15:05 UTC
    const GENESIS_BITS: u32 = 0x1d00ffff;
    const GENESIS_NONCE: u32 = 2083236893;
    const GENESIS_COINBASE_TXID: &str = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
    const GENESIS_COINBASE_OUTPUT_VALUE: u64 = 5000000000; // 50 BTC in satoshis

    #[test]
    fn test_varint_parsing_single_byte() {
        let data = [42u8];
        let cursor = Cursor::new(&data[..]);
        let mut reader = BufReader::new(cursor);
        let varint = read_varint(&mut reader).unwrap();
        
        assert_eq!(varint.value, 42);
        assert_eq!(varint.len, 1);
        assert_eq!(varint.data[0], 42);
    }

    #[test]
    fn test_varint_parsing_two_bytes() {
        let data = [253u8, 0xfd, 0x00]; // 253 in little endian
        let cursor = Cursor::new(&data[..]);
        let mut reader = BufReader::new(cursor);
        let varint = read_varint(&mut reader).unwrap();
        
        assert_eq!(varint.value, 253);
        assert_eq!(varint.len, 3);
    }

    #[test]
    fn test_varint_parsing_four_bytes() {
        let data = [254u8, 0x01, 0x00, 0x01, 0x00]; // 65537 in little endian
        let cursor = Cursor::new(&data[..]);
        let mut reader = BufReader::new(cursor);
        let varint = read_varint(&mut reader).unwrap();
        
        assert_eq!(varint.value, 65537);
        assert_eq!(varint.len, 5);
    }

    #[test]
    fn test_varint_parsing_eight_bytes() {
        let data = [255u8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]; // 1 in 8 bytes
        let cursor = Cursor::new(&data[..]);
        let mut reader = BufReader::new(cursor);
        let varint = read_varint(&mut reader).unwrap();
        
        assert_eq!(varint.value, 1);
        assert_eq!(varint.len, 9);
    }

    #[test]
    fn test_magic_constant() {
        assert_eq!(MAGIC, 0xD9B4BEF9);
        assert_eq!(MAGIC, 3652501241); // Decimal equivalent
    }

    #[test]
    fn test_id_generator() {
        let mut id_gen = IdGenerator::new();
        
        assert_eq!(id_gen.next_id("test"), 1);
        assert_eq!(id_gen.next_id("test"), 2);
        assert_eq!(id_gen.next_id("test"), 3);
        
        assert_eq!(id_gen.next_id("other"), 1);
        assert_eq!(id_gen.next_id("other"), 2);
        
        assert_eq!(id_gen.next_id("test"), 4);
    }

    #[test]
    fn test_csv_writers_creation() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().to_str().unwrap();
        
        let writers = CsvWriters::new(output_dir);
        assert!(writers.is_ok());
        
        // Check that all CSV files were created
        assert!(temp_dir.path().join("blocks.csv").exists());
        assert!(temp_dir.path().join("transactions.csv").exists());
        assert!(temp_dir.path().join("inputs.csv").exists());
        assert!(temp_dir.path().join("outputs.csv").exists());
        assert!(temp_dir.path().join("witnesses.csv").exists());
        assert!(temp_dir.path().join("addresses.csv").exists());
        assert!(temp_dir.path().join("output_addresses.csv").exists());
    }

    #[test]
    fn test_csv_headers() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().to_str().unwrap();
        
        let mut writers = CsvWriters::new(output_dir).unwrap();
        writers.flush_all().unwrap();
        
        // Check headers
        let blocks_content = fs::read_to_string(temp_dir.path().join("blocks.csv")).unwrap();
        assert!(blocks_content.starts_with("ID,FILE_NUMBER,BLOCK_NUMBER,BLOCK_HASH,DATE_TIME,VERSION,PREV_BLOCK_HASH,MERKLE_ROOT,BITS,NONCE,BLOCK_SIZE,TX_COUNT"));
        
        let transactions_content = fs::read_to_string(temp_dir.path().join("transactions.csv")).unwrap();
        assert!(transactions_content.starts_with("ID,BLOCK_ID,TXID,VERSION,LOCK_TIME,IS_SEGWIT,INPUT_COUNT,OUTPUT_COUNT,TX_SIZE"));
        
        let witnesses_content = fs::read_to_string(temp_dir.path().join("witnesses.csv")).unwrap();
        assert!(witnesses_content.starts_with("ID,TRANSACTION_ID,INPUT_ID,INPUT_INDEX,WITNESS_INDEX,WITNESS_DATA,WITNESS_SIZE"));
    }

    // Create a mock genesis block for testing
    fn create_mock_genesis_block() -> Vec<u8> {
        let mut block_data = Vec::new();
        
        // Magic number
        block_data.extend_from_slice(&MAGIC.to_le_bytes());
        
        // Block size (we'll update this later)
        let size_placeholder = block_data.len();
        block_data.extend_from_slice(&[0u8; 4]);
        
        // Block header (80 bytes)
        block_data.extend_from_slice(&1u32.to_le_bytes()); // version
        block_data.extend_from_slice(&hex::decode(GENESIS_PREV_HASH).unwrap()); // prev_hash (32 bytes of zeros)
        block_data.extend_from_slice(&hex::decode(GENESIS_MERKLE_ROOT).unwrap()); // merkle_root
        block_data.extend_from_slice(&GENESIS_TIMESTAMP.to_le_bytes()); // timestamp
        block_data.extend_from_slice(&GENESIS_BITS.to_le_bytes()); // bits
        block_data.extend_from_slice(&GENESIS_NONCE.to_le_bytes()); // nonce
        
        // Transaction count (1 transaction)
        block_data.push(1u8);
        
        // Genesis transaction
        block_data.extend_from_slice(&1u32.to_le_bytes()); // version
        
        // Input count (1)
        block_data.push(1u8);
        
        // Input
        block_data.extend_from_slice(&[0u8; 32]); // prev_txid (null)
        block_data.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // prev_vout (0xFFFFFFFF for coinbase)
        
        // Script length and script (Genesis coinbase script)
        let coinbase_script = hex::decode("04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73").unwrap();
        block_data.push(coinbase_script.len() as u8);
        block_data.extend_from_slice(&coinbase_script);
        
        block_data.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // sequence
        
        // Output count (1)
        block_data.push(1u8);
        
        // Output
        block_data.extend_from_slice(&GENESIS_COINBASE_OUTPUT_VALUE.to_le_bytes()); // value
        
        // Output script
        let output_script = hex::decode("4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac").unwrap();
        block_data.push(output_script.len() as u8);
        block_data.extend_from_slice(&output_script);
        
        // Lock time
        block_data.extend_from_slice(&0u32.to_le_bytes());
        
        // Update block size
        let total_size = (block_data.len() - 8) as u32; // Exclude magic and size field
        block_data[size_placeholder..size_placeholder + 4].copy_from_slice(&total_size.to_le_bytes());
        
        block_data
    }

    #[test]
    fn test_genesis_block_parsing() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().to_str().unwrap();
        
        let mut parser = BlockParser::new(output_dir, true).unwrap();
        let genesis_data = create_mock_genesis_block();
        
        // Create a temporary file with genesis block data
        let file_path = temp_dir.path().join("blk00000.dat");
        fs::write(&file_path, &genesis_data).unwrap();
        
        let result = parser.parse_block_file(&file_path, 0);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1); // Should parse 1 block
        
        parser.writers.flush_all().unwrap();
        
        // Verify blocks.csv
        let blocks_csv = fs::read_to_string(temp_dir.path().join("blocks.csv")).unwrap();
        let lines: Vec<&str> = blocks_csv.lines().collect();
        assert_eq!(lines.len(), 2); // Header + 1 block
        
        let block_line = lines[1];
        assert!(block_line.contains("2009-01-03 18:15:05")); // Genesis timestamp
        assert!(block_line.contains(&GENESIS_PREV_HASH)); // Previous hash
        assert!(block_line.contains(&GENESIS_MERKLE_ROOT)); // Merkle root
        
        // Verify transactions.csv
        let transactions_csv = fs::read_to_string(temp_dir.path().join("transactions.csv")).unwrap();
        let tx_lines: Vec<&str> = transactions_csv.lines().collect();
        assert_eq!(tx_lines.len(), 2); // Header + 1 transaction
        
        let tx_line = tx_lines[1];
        assert!(tx_line.contains("false")); // Not SegWit
        assert!(tx_line.contains(",1,1,")); // 1 input, 1 output
    }

    #[test]
    fn test_header_parsing() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().to_str().unwrap();
        let parser = BlockParser::new(output_dir, false).unwrap();
        
        // Create header data
        let mut header_data = Vec::new();
        header_data.extend_from_slice(&1u32.to_le_bytes()); // version
        header_data.extend_from_slice(&[0u8; 32]); // prev_hash
        header_data.extend_from_slice(&hex::decode(GENESIS_MERKLE_ROOT).unwrap()); // merkle_root
        header_data.extend_from_slice(&GENESIS_TIMESTAMP.to_le_bytes()); // time
        header_data.extend_from_slice(&GENESIS_BITS.to_le_bytes()); // bits
        header_data.extend_from_slice(&GENESIS_NONCE.to_le_bytes()); // nonce
        
        let cursor = Cursor::new(header_data);
        let mut reader = BufReader::new(cursor);
        
        let header = parser.parse_header(&mut reader).unwrap();
        
        assert_eq!(u32::from_le_bytes(header.version), 1);
        assert_eq!(header.prev_hash, [0u8; 32]);
        assert_eq!(hex::encode(header.merkle_root), GENESIS_MERKLE_ROOT);
        assert_eq!(u32::from_le_bytes(header.time), GENESIS_TIMESTAMP);
        assert_eq!(u32::from_le_bytes(header.bits), GENESIS_BITS);
        assert_eq!(u32::from_le_bytes(header.nonce), GENESIS_NONCE);
    }

    #[test]
    fn test_coinbase_input_parsing() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().to_str().unwrap();
        let mut parser = BlockParser::new(output_dir, false).unwrap();
        
        // Create coinbase input data
        let mut input_data = Vec::new();
        input_data.extend_from_slice(&[0u8; 32]); // prev_txid (null for coinbase)
        input_data.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // prev_vout
        
        let coinbase_script = hex::decode("04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73").unwrap();
        input_data.push(coinbase_script.len() as u8); // script length
        input_data.extend_from_slice(&coinbase_script); // script
        input_data.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // sequence
        
        let cursor = Cursor::new(input_data);
        let mut reader = BufReader::new(cursor);
        let mut hasher = Sha256::new();
        
        let input = parser.parse_input(&mut reader, &mut hasher).unwrap();
        
        assert_eq!(input.txid, "0000000000000000000000000000000000000000000000000000000000000000");
        assert_eq!(input.vout, 0xFFFFFFFF);
        assert_eq!(input.script, coinbase_script);
        assert_eq!(input.sequence, 0xFFFFFFFF);
    }

    #[test]
    fn test_genesis_output_parsing() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().to_str().unwrap();
        let mut parser = BlockParser::new(output_dir, false).unwrap();
        
        // Create genesis output data
        let mut output_data = Vec::new();
        output_data.extend_from_slice(&GENESIS_COINBASE_OUTPUT_VALUE.to_le_bytes()); // value
        
        let output_script = hex::decode("4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac").unwrap();
        output_data.push(output_script.len() as u8); // script length
        output_data.extend_from_slice(&output_script); // script
        
        let cursor = Cursor::new(output_data);
        let mut reader = BufReader::new(cursor);
        let mut hasher = Sha256::new();
        
        let output = parser.parse_output(&mut reader, &mut hasher).unwrap();
        
        assert_eq!(output.amount, GENESIS_COINBASE_OUTPUT_VALUE);
        assert_eq!(output.script, output_script);
    }

    #[test]
    fn test_no_witnesses_in_genesis() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().to_str().unwrap();
        let mut parser = BlockParser::new(output_dir, false).unwrap();
        
        // Genesis block has no witnesses (pre-SegWit)
        let inputs = vec![Input {
            id: 1,
            txid: "test".to_string(),
            vout: 0,
            script: vec![],
            sequence: 0,
        }];
        
        // This should not panic or fail
        let witnesses = parser.parse_witnesses(&mut BufReader::new(Cursor::new(vec![0u8])), &inputs);
        assert!(witnesses.is_ok());
        let witness_data = witnesses.unwrap();
        assert_eq!(witness_data.len(), 0); // No witnesses for the single input
    }

    #[test]
    fn test_block_timestamp_conversion() {
        let timestamp = GENESIS_TIMESTAMP as i64;
        let datetime = Utc.timestamp_opt(timestamp, 0).single().unwrap();
        
        assert_eq!(datetime.year(), 2009);
        assert_eq!(datetime.month(), 1);
        assert_eq!(datetime.day(), 3);
        assert_eq!(datetime.hour(), 18);
        assert_eq!(datetime.minute(), 15);
        assert_eq!(datetime.second(), 5);
    }

    #[test]
    fn test_hex_encoding_decoding() {
        let test_data = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let hex_string = hex::encode(&test_data);
        assert_eq!(hex_string, "0123456789abcdef");
        
        let decoded = hex::decode(&hex_string).unwrap();
        assert_eq!(decoded, test_data);
    }

    #[test]
    fn test_little_endian_conversion() {
        let value = 0x12345678u32;
        let bytes = value.to_le_bytes();
        assert_eq!(bytes, [0x78, 0x56, 0x34, 0x12]);
        
        let recovered = u32::from_le_bytes(bytes);
        assert_eq!(recovered, value);
    }

    #[test]
    fn test_address_cache() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().to_str().unwrap();
        let mut parser = BlockParser::new(output_dir, false).unwrap();
        
        // Test address caching
        parser.address_cache.insert("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(), 1);
        
        assert_eq!(parser.address_cache.get("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"), Some(&1));
        assert_eq!(parser.address_cache.get("nonexistent"), None);
    }

    #[test]
    fn test_transaction_type_tracking() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().to_str().unwrap();
        let mut parser = BlockParser::new(output_dir, false).unwrap();
        
        // Simulate transaction type tracking
        *parser.tx_types.entry("p2pkh".to_string()).or_insert(0) += 1;
        *parser.tx_types.entry("p2sh".to_string()).or_insert(0) += 1;
        *parser.tx_types.entry("p2pkh".to_string()).or_insert(0) += 1;
        
        assert_eq!(parser.tx_types.get("p2pkh"), Some(&2));
        assert_eq!(parser.tx_types.get("p2sh"), Some(&1));
        assert_eq!(parser.tx_types.get("unknown"), None);
    }

    #[test]
    fn test_buffer_size_constant() {
        assert_eq!(BUFFER_SIZE, 8 * 1024 * 1024);
        assert_eq!(BUFFER_SIZE, 8388608);
    }

    #[test]
    fn test_invalid_magic_number() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().to_str().unwrap();
        let mut parser = BlockParser::new(output_dir, false).unwrap();
        
        // Create data with invalid magic number
        let mut invalid_data = Vec::new();
        invalid_data.extend_from_slice(&0x12345678u32.to_le_bytes()); // Wrong magic
        invalid_data.extend_from_slice(&100u32.to_le_bytes()); // Size
        invalid_data.extend_from_slice(&vec![0u8; 100]); // Dummy data
        
        let file_path = temp_dir.path().join("invalid.dat");
        fs::write(&file_path, &invalid_data).unwrap();
        
        let result = parser.parse_block_file(&file_path, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid magic number"));
    }

    #[test]
    fn test_empty_file() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().to_str().unwrap();
        let mut parser = BlockParser::new(output_dir, false).unwrap();
        
        // Create empty file
        let file_path = temp_dir.path().join("empty.dat");
        fs::write(&file_path, &Vec::<u8>::new()).unwrap();
        
        let result = parser.parse_block_file(&file_path, 0);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0); // No blocks parsed
    }

    #[test]
    fn test_nonexistent_file() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().to_str().unwrap();
        let mut parser = BlockParser::new(output_dir, false).unwrap();
        
        let file_path = temp_dir.path().join("nonexistent.dat");
        
        let result = parser.parse_block_file(&file_path, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_debug_mode() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().to_str().unwrap();
        
        let parser_debug = BlockParser::new(output_dir, true).unwrap();
        assert_eq!(parser_debug.debug, true);
        
        let parser_no_debug = BlockParser::new(output_dir, false).unwrap();
        assert_eq!(parser_no_debug.debug, false);
    }

    #[test]
    fn test_file_range_processing() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().to_str().unwrap();
        let blocks_dir = temp_dir.path().join("blocks");
        fs::create_dir_all(&blocks_dir).unwrap();
        
        let mut parser = BlockParser::new(output_dir, false).unwrap();
        
        // Test with non-existent files
        let result = parser.run(&blocks_dir, 0..5);
        assert!(result.is_ok()); // Should succeed even with no files
    }

    #[test]
    fn test_path_operations() {
        let temp_dir = TempDir::new().unwrap();
        let blocks_dir = temp_dir.path().join("blocks");
        
        let file_path = blocks_dir.join("blk00000.dat");
        assert_eq!(file_path.file_name().unwrap(), "blk00000.dat");
        assert_eq!(file_path.parent().unwrap(), blocks_dir);
    }
}