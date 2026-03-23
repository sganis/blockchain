// src/model.rs

use anyhow::{Result, Context};
use std::collections::HashMap;
use std::io::{BufReader, Read};

pub const MAGIC: u32 = 0xD9B4BEF9;
pub const BUFFER_SIZE: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct VarInt {
    pub value: u64,
    pub len: u32,
    pub data: [u8; 9],
}

impl VarInt {
    pub fn new(value: u64, len: u32, data: [u8; 9]) -> Self {
        Self { value, len, data }
    }
}

pub fn read_varint<T: Read>(reader: &mut BufReader<T>) -> Result<VarInt> {
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
pub struct Header {
    pub version: [u8; 4],
    pub prev_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub time: [u8; 4],
    pub bits: [u8; 4],
    pub nonce: [u8; 4],
}

impl Header {
    pub fn prev_hash_reversed(&self) -> [u8; 32] {
        let mut reversed = self.prev_hash;
        reversed.reverse();
        reversed
    }
    pub fn merkle_root_reversed(&self) -> [u8; 32] {
        let mut reversed = self.merkle_root;
        reversed.reverse();
        reversed
    }
}

#[derive(Debug)]
pub struct Block {
    pub header: Header,
    pub transactions: Vec<Tx>,
}

#[derive(Debug)]
pub struct Tx {
    pub id: u64,
    pub version: u32,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub witnesses: Option<Vec<Witness>>,
    pub lock_time: [u8; 4],
    pub txid: String,
}

#[derive(Debug)]
pub struct Input {
    pub id: u64,
    pub txid: String,
    pub vout: u32,
    pub script: Vec<u8>,
    pub sequence: u32,
}

#[derive(Debug)]
pub struct Output {
    pub id: u64,
    pub amount: u64,
    pub script: Vec<u8>,
}

#[derive(Debug)]
pub struct Witness {
    pub id: u64,
    pub txiid: u64,
    pub index: usize,
    pub data: Vec<u8>,
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

    pub fn export(&self) -> HashMap<String, u64> {
        self.counters.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    pub fn import(&mut self, data: &HashMap<String, u64>) {
        // Map known string keys back to &'static str
        let key_map: &[&'static str] = &["txi", "txo", "wit", "tx", "addr"];
        for key in key_map {
            if let Some(&val) = data.get(*key) {
                self.counters.insert(key, val);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

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
        let data = [253u8, 0xfd, 0x00];
        let cursor = Cursor::new(&data[..]);
        let mut reader = BufReader::new(cursor);
        let varint = read_varint(&mut reader).unwrap();
        assert_eq!(varint.value, 253);
        assert_eq!(varint.len, 3);
    }

    #[test]
    fn test_varint_parsing_four_bytes() {
        let data = [254u8, 0x01, 0x00, 0x01, 0x00];
        let cursor = Cursor::new(&data[..]);
        let mut reader = BufReader::new(cursor);
        let varint = read_varint(&mut reader).unwrap();
        assert_eq!(varint.value, 65537);
        assert_eq!(varint.len, 5);
    }

    #[test]
    fn test_varint_parsing_eight_bytes() {
        let data = [255u8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let cursor = Cursor::new(&data[..]);
        let mut reader = BufReader::new(cursor);
        let varint = read_varint(&mut reader).unwrap();
        assert_eq!(varint.value, 1);
        assert_eq!(varint.len, 9);
    }

    #[test]
    fn test_magic_constant() {
        assert_eq!(MAGIC, 0xD9B4BEF9);
        assert_eq!(MAGIC, 3652501241);
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
    fn test_buffer_size_constant() {
        assert_eq!(BUFFER_SIZE, 8 * 1024 * 1024);
        assert_eq!(BUFFER_SIZE, 8388608);
    }

    #[test]
    fn test_little_endian_conversion() {
        let value = 0x12345678u32;
        let bytes = value.to_le_bytes();
        assert_eq!(bytes, [0x78, 0x56, 0x34, 0x12]);
        let recovered = u32::from_le_bytes(bytes);
        assert_eq!(recovered, value);
    }
}
