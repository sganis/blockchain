// src/parsertest.rs

use super::*;
use std::io::Cursor;
use std::fs;
use tempfile::TempDir;
use chrono::{Datelike, Timelike};

const GENESIS_PREV_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const GENESIS_MERKLE_ROOT: &str = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";
const GENESIS_TIMESTAMP: u32 = 1231006505;
const GENESIS_BITS: u32 = 0x1d00ffff;
const GENESIS_NONCE: u32 = 2083236893;
const GENESIS_COINBASE_OUTPUT_VALUE: u64 = 5000000000;

fn create_mock_genesis_block() -> Vec<u8> {
    let mut block_data = Vec::new();

    block_data.extend_from_slice(&MAGIC.to_le_bytes());

    let size_placeholder = block_data.len();
    block_data.extend_from_slice(&[0u8; 4]);

    block_data.extend_from_slice(&1u32.to_le_bytes());
    block_data.extend_from_slice(&hex::decode(GENESIS_PREV_HASH).unwrap());
    block_data.extend_from_slice(&hex::decode(GENESIS_MERKLE_ROOT).unwrap());
    block_data.extend_from_slice(&GENESIS_TIMESTAMP.to_le_bytes());
    block_data.extend_from_slice(&GENESIS_BITS.to_le_bytes());
    block_data.extend_from_slice(&GENESIS_NONCE.to_le_bytes());

    block_data.push(1u8);

    block_data.extend_from_slice(&1u32.to_le_bytes());

    block_data.push(1u8);

    block_data.extend_from_slice(&[0u8; 32]);
    block_data.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());

    let coinbase_script = hex::decode("04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73").unwrap();
    block_data.push(coinbase_script.len() as u8);
    block_data.extend_from_slice(&coinbase_script);

    block_data.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());

    block_data.push(1u8);

    block_data.extend_from_slice(&GENESIS_COINBASE_OUTPUT_VALUE.to_le_bytes());

    let output_script = hex::decode("4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac").unwrap();
    block_data.push(output_script.len() as u8);
    block_data.extend_from_slice(&output_script);

    block_data.extend_from_slice(&0u32.to_le_bytes());

    let total_size = (block_data.len() - 8) as u32;
    block_data[size_placeholder..size_placeholder + 4].copy_from_slice(&total_size.to_le_bytes());

    block_data
}

#[test]
fn test_genesis_block_parsing() {
    let temp_dir = TempDir::new().unwrap();
    let output_dir = temp_dir.path().to_str().unwrap();

    let mut parser = BlockParser::new(output_dir, true, false).unwrap();
    let genesis_data = create_mock_genesis_block();

    let file_path = temp_dir.path().join("blk00000.dat");
    fs::write(&file_path, &genesis_data).unwrap();

    let result = parser.parse_block_file(&file_path, 0);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 1);

    parser.writers.commit().unwrap();

    let blocks_csv = fs::read_to_string(temp_dir.path().join("blocks.csv")).unwrap();
    let lines: Vec<&str> = blocks_csv.lines().collect();
    assert_eq!(lines.len(), 2);

    let block_line = lines[1];
    assert!(block_line.contains("2009-01-03 18:15:05"));
    assert!(block_line.contains(&GENESIS_PREV_HASH));

    let transactions_csv = fs::read_to_string(temp_dir.path().join("transactions.csv")).unwrap();
    let tx_lines: Vec<&str> = transactions_csv.lines().collect();
    assert_eq!(tx_lines.len(), 2);

    let tx_line = tx_lines[1];
    assert!(tx_line.contains("false,true,")); // is_segwit=false, is_coinbase=true
    assert!(tx_line.contains(",1,1,")); // 1 input, 1 output
}

#[test]
fn test_header_parsing() {
    let temp_dir = TempDir::new().unwrap();
    let output_dir = temp_dir.path().to_str().unwrap();
    let parser = BlockParser::new(output_dir, false, false).unwrap();

    let mut header_data = Vec::new();
    header_data.extend_from_slice(&1u32.to_le_bytes());
    header_data.extend_from_slice(&[0u8; 32]);
    header_data.extend_from_slice(&hex::decode(GENESIS_MERKLE_ROOT).unwrap());
    header_data.extend_from_slice(&GENESIS_TIMESTAMP.to_le_bytes());
    header_data.extend_from_slice(&GENESIS_BITS.to_le_bytes());
    header_data.extend_from_slice(&GENESIS_NONCE.to_le_bytes());

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
    let mut parser = BlockParser::new(output_dir, false, false).unwrap();

    let mut input_data = Vec::new();
    input_data.extend_from_slice(&[0u8; 32]);
    input_data.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());

    let coinbase_script = hex::decode("04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73").unwrap();
    input_data.push(coinbase_script.len() as u8);
    input_data.extend_from_slice(&coinbase_script);
    input_data.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());

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
    let mut parser = BlockParser::new(output_dir, false, false).unwrap();

    let mut output_data = Vec::new();
    output_data.extend_from_slice(&GENESIS_COINBASE_OUTPUT_VALUE.to_le_bytes());

    let output_script = hex::decode("4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac").unwrap();
    output_data.push(output_script.len() as u8);
    output_data.extend_from_slice(&output_script);

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
    let mut parser = BlockParser::new(output_dir, false, false).unwrap();

    let inputs = vec![Input {
        id: 1,
        txid: "test".to_string(),
        vout: 0,
        script: vec![],
        sequence: 0,
    }];

    let witnesses = parser.parse_witnesses(&mut BufReader::new(Cursor::new(vec![0u8])), &inputs);
    assert!(witnesses.is_ok());
    let witness_data = witnesses.unwrap();
    assert_eq!(witness_data.len(), 0);
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
fn test_address_cache() {
    let temp_dir = TempDir::new().unwrap();
    let output_dir = temp_dir.path().to_str().unwrap();
    let mut parser = BlockParser::new(output_dir, false, false).unwrap();

    parser.address_cache.insert("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(), 1);
    assert_eq!(parser.address_cache.get("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"), Some(&1));
    assert_eq!(parser.address_cache.get("nonexistent"), None);
}

#[test]
fn test_transaction_type_tracking() {
    let temp_dir = TempDir::new().unwrap();
    let output_dir = temp_dir.path().to_str().unwrap();
    let mut parser = BlockParser::new(output_dir, false, false).unwrap();

    *parser.tx_types.entry("p2pkh".to_string()).or_insert(0) += 1;
    *parser.tx_types.entry("p2sh".to_string()).or_insert(0) += 1;
    *parser.tx_types.entry("p2pkh".to_string()).or_insert(0) += 1;

    assert_eq!(parser.tx_types.get("p2pkh"), Some(&2));
    assert_eq!(parser.tx_types.get("p2sh"), Some(&1));
    assert_eq!(parser.tx_types.get("unknown"), None);
}

#[test]
fn test_invalid_magic_number() {
    let temp_dir = TempDir::new().unwrap();
    let output_dir = temp_dir.path().to_str().unwrap();
    let mut parser = BlockParser::new(output_dir, false, false).unwrap();

    let mut invalid_data = Vec::new();
    invalid_data.extend_from_slice(&0x12345678u32.to_le_bytes());
    invalid_data.extend_from_slice(&100u32.to_le_bytes());
    invalid_data.extend_from_slice(&vec![0u8; 100]);

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
    let mut parser = BlockParser::new(output_dir, false, false).unwrap();

    let file_path = temp_dir.path().join("empty.dat");
    fs::write(&file_path, &Vec::<u8>::new()).unwrap();

    let result = parser.parse_block_file(&file_path, 0);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 0);
}

#[test]
fn test_nonexistent_file() {
    let temp_dir = TempDir::new().unwrap();
    let output_dir = temp_dir.path().to_str().unwrap();
    let mut parser = BlockParser::new(output_dir, false, false).unwrap();

    let file_path = temp_dir.path().join("nonexistent.dat");
    let result = parser.parse_block_file(&file_path, 0);
    assert!(result.is_err());
}

#[test]
fn test_debug_mode() {
    let temp_dir = TempDir::new().unwrap();
    let output_dir = temp_dir.path().to_str().unwrap();

    let parser_debug = BlockParser::new(output_dir, true, false).unwrap();
    assert_eq!(parser_debug.debug, true);

    let parser_no_debug = BlockParser::new(output_dir, false, false).unwrap();
    assert_eq!(parser_no_debug.debug, false);
}

#[test]
fn test_file_range_processing() {
    let temp_dir = TempDir::new().unwrap();
    let output_dir = temp_dir.path().to_str().unwrap();
    let blocks_dir = temp_dir.path().join("blocks");
    fs::create_dir_all(&blocks_dir).unwrap();

    let mut parser = BlockParser::new(output_dir, false, false).unwrap();
    let result = parser.run(&blocks_dir, output_dir);
    assert!(result.is_ok());
}

#[test]
fn test_path_operations() {
    let temp_dir = TempDir::new().unwrap();
    let blocks_dir = temp_dir.path().join("blocks");

    let file_path = blocks_dir.join("blk00000.dat");
    assert_eq!(file_path.file_name().unwrap(), "blk00000.dat");
    assert_eq!(file_path.parent().unwrap(), blocks_dir);
}
