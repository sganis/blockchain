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
    io::{BufReader, Write, Read, BufWriter, Seek, SeekFrom},
    collections::HashMap,
    path::Path,
};
use opcodes::script_to_opcodes;
use transaction::get_tx_type;

const MAGIC: u32 = 3_652_501_241; // FEBEB4D9
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
    script: Vec<u8>, // Store raw bytes instead of hex string
    sequence: u32,
}

#[derive(Debug)]
struct Output {
    id: u64,
    amount: u64,
    script: Vec<u8>, // Store raw bytes instead of hex string
}

#[derive(Debug)]
struct Witness {
    id: u64,
    txiid: u64,
    index: usize,
    data: Vec<u8>, // Store raw bytes instead of hex string
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
}

impl CsvWriters {
    fn new(output_dir: &str) -> Result<Self> {
        std::fs::create_dir_all(output_dir)
            .context("Failed to create output directory")?;

        let blocks = Self::create_csv_file(&format!("{}/blocks.csv", output_dir), 
            "ID,FILE,BLOCK,DATE,TIME,VERSION,PREV_HASH,MERKLE_ROOT,BITS,NONCE")?;
        
        let transactions = Self::create_csv_file(&format!("{}/tx.csv", output_dir), 
            "ID,BLOCK,TXID,VERSION,LOCKTIME")?;
        
        let inputs = Self::create_csv_file(&format!("{}/txi.csv", output_dir), 
            "ID,TXID,VOUT,SCRIPT,SEQUENCE")?;
        
        let outputs = Self::create_csv_file(&format!("{}/txo.csv", output_dir), 
            "ID,TXID,AMOUNT,SCRIPT")?;
        
        let witnesses = Self::create_csv_file(&format!("{}/wit.csv", output_dir), 
            "ID,INDEX,DATA")?;

        Ok(Self {
            blocks,
            transactions,
            inputs,
            outputs,
            witnesses,
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
        Ok(())
    }
}

struct BlockParser {
    id_gen: IdGenerator,
    writers: CsvWriters,
    tx_types: HashMap<String, usize>,
    debug: bool,
}

impl BlockParser {
    fn new(output_dir: &str, debug: bool) -> Result<Self> {
        Ok(Self {
            id_gen: IdGenerator::new(),
            writers: CsvWriters::new(output_dir)?,
            tx_types: HashMap::new(),
            debug,
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
        let datetime = Utc.timestamp_opt(timestamp, 0).unwrap();
        let date_str = datetime.format("%Y-%m-%d");
        let time_str = datetime.format("%H:%M:%S");

        // Write block
        let block_id = self.id_gen.next_id("blk");
        writeln!(self.writers.blocks, "{},{},{},{},{},{},{},{},{},{}", 
            block_id, file_number, block_number, date_str, time_str,
            hex::encode(block.header.version), 
            hex::encode(block.header.prev_hash), 
            hex::encode(block.header.merkle_root), 
            hex::encode(block.header.bits), 
            hex::encode(block.header.nonce)
        )?;

        // Write transactions and related data
        for tx in &block.transactions {
            writeln!(self.writers.transactions, "{},{},{},{},{}", 
                tx.id, block_number, tx.txid, tx.version, hex::encode(tx.lock_time))?;

            // Write inputs
            for input in &tx.inputs {
                writeln!(self.writers.inputs, "{},{},{},{},{}", 
                    input.id, tx.txid, input.vout, hex::encode(&input.script), input.sequence)?;
            }

            // Write outputs
            for output in &tx.outputs {
                writeln!(self.writers.outputs, "{},{},{},{}", 
                    output.id, tx.txid, output.amount, hex::encode(&output.script))?;
            }

            // Write witnesses
            if let Some(witnesses) = &tx.witnesses {
                for witness in witnesses {
                    writeln!(self.writers.witnesses, "{},{},{}", 
                        witness.id, witness.index, hex::encode(&witness.data))?;
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
                let datetime = Utc.timestamp_opt(timestamp, 0).unwrap();
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

    fn run(&mut self, blocks_dir: &str, file_range: std::ops::Range<u32>) -> Result<()> {
        let start = Instant::now();
        let mut total_blocks = 0;

        for file_number in file_range {
            let file_path = Path::new(blocks_dir).join(format!("blk{:05}.dat", file_number));
            
            if !file_path.exists() {
                if self.debug {
                    println!("File {} does not exist, skipping", file_path.display());
                }
                continue;
            }

            match self.parse_block_file(&file_path, file_number) {
                Ok(block_count) => {
                    total_blocks += block_count;
                    println!("Processed {} blocks from file {}", block_count, file_number);
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
        println!("Processed {} total blocks in {:.2?}", total_blocks, duration);
        
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
    
    let root = "data";
    let blocks_path = &format!("{}/blocks", &root);
    let csv_path = &format!("{}/csv", &root);

    let blocks_dir = args.get(1)
        .map(|s| s.as_str())
        .unwrap_or(blocks_path);

    let output_dir = args.get(2)
        .map(|s| s.as_str())
        .unwrap_or(csv_path);

    let start_file: u32 = args.get(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    
    let end_file: u32 = args.get(4)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    
    //let debug = args.contains(&"--debug".to_string());
    let debug = true;
    let start_file = 976;
    let end_file = 977;

    println!("Bitcoin Block Parser");
    println!("Blocks directory: {}", blocks_dir);
    println!("Output directory: {}", output_dir);
    println!("File range: {} to {}", start_file, end_file);
    println!("Debug mode: {}", debug);

    let mut parser = BlockParser::new(output_dir, debug)?;
    parser.run(blocks_dir, start_file..end_file)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_parsing() {
        // Test small values
        let data = [42u8, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut cursor = std::io::Cursor::new(&data[..1]);
        let mut reader = BufReader::new(cursor);
        let varint = read_varint(&mut reader).unwrap();
        assert_eq!(varint.value, 42);
        assert_eq!(varint.len, 1);
    }

    #[test]
    fn test_magic_constant() {
        assert_eq!(MAGIC, 0xD9B4BEF9);
    }
}