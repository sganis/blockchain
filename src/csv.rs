// src/csv.rs

use anyhow::{Result, Context};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Write, BufWriter};

pub struct CsvWriters {
    output_dir: String,
    pub blocks: BufWriter<File>,
    pub transactions: BufWriter<File>,
    pub inputs: BufWriter<File>,
    pub outputs: BufWriter<File>,
    pub witnesses: BufWriter<File>,
    pub addresses: BufWriter<File>,
    pub output_addresses: BufWriter<File>,
}

const HEADERS: [(&str, &str); 7] = [
    ("blocks.csv", "BLOCK_HEIGHT,FILE_ID,BLOCK_HASH,DATE_TIME,VERSION,PREV_BLOCK_HASH,MERKLE_ROOT,BITS,NONCE,BLOCK_SIZE,TX_COUNT"),
    ("transactions.csv", "TRANSACTION_ID,BLOCK_ID,TXID,VERSION,LOCK_TIME,IS_SEGWIT,IS_COINBASE,INPUT_COUNT,OUTPUT_COUNT,TX_SIZE"),
    ("inputs.csv", "INPUT_ID,TRANSACTION_ID,TXID,INPUT_INDEX,PREV_TXID,PREV_VOUT,SCRIPT_SIG,SEQUENCE_NUMBER"),
    ("outputs.csv", "OUTPUT_ID,TRANSACTION_ID,TXID,OUTPUT_INDEX,VALUE,SCRIPT_PUBKEY,SCRIPT_TYPE,DATA"),
    ("witnesses.csv", "WITNESS_ID,TRANSACTION_ID,INPUT_ID,INPUT_INDEX,WITNESS_INDEX,WITNESS_DATA,WITNESS_SIZE"),
    ("addresses.csv", "ADDRESS_ID,ADDRESS,SCRIPT_TYPE,SCRIPT_HASH"),
    ("output_addresses.csv", "OUTPUT_ID,ADDRESS_ID"),
];

impl CsvWriters {
    fn temp_path(output_dir: &str, name: &str) -> String {
        format!("{}/{}.tmp", output_dir, name)
    }

    fn open_temp(output_dir: &str, name: &str) -> Result<BufWriter<File>> {
        let path = Self::temp_path(output_dir, name);
        let file = File::create(&path)
            .context(format!("Failed to create temp file: {}", path))?;
        Ok(BufWriter::new(file))
    }

    pub fn new(output_dir: &str, append: bool) -> Result<Self> {
        std::fs::create_dir_all(output_dir)
            .context("Failed to create output directory")?;

        if !append {
            for (name, header) in &HEADERS {
                let path = format!("{}/{}", output_dir, name);
                let mut file = File::create(&path)
                    .context(format!("Failed to create: {}", path))?;
                writeln!(file, "{}", header)?;
            }
        }

        for (name, _) in &HEADERS {
            let _ = std::fs::remove_file(Self::temp_path(output_dir, name));
        }

        Ok(Self {
            output_dir: output_dir.to_string(),
            blocks: Self::open_temp(output_dir, HEADERS[0].0)?,
            transactions: Self::open_temp(output_dir, HEADERS[1].0)?,
            inputs: Self::open_temp(output_dir, HEADERS[2].0)?,
            outputs: Self::open_temp(output_dir, HEADERS[3].0)?,
            witnesses: Self::open_temp(output_dir, HEADERS[4].0)?,
            addresses: Self::open_temp(output_dir, HEADERS[5].0)?,
            output_addresses: Self::open_temp(output_dir, HEADERS[6].0)?,
        })
    }

    pub fn flush_all(&mut self) -> Result<()> {
        self.blocks.flush().context("flush blocks")?;
        self.transactions.flush().context("flush transactions")?;
        self.inputs.flush().context("flush inputs")?;
        self.outputs.flush().context("flush outputs")?;
        self.witnesses.flush().context("flush witnesses")?;
        self.addresses.flush().context("flush addresses")?;
        self.output_addresses.flush().context("flush output_addresses")?;
        Ok(())
    }

    pub fn commit(&mut self) -> Result<()> {
        self.flush_all()?;

        let mut contents: Vec<Vec<u8>> = Vec::with_capacity(7);
        for (name, _) in &HEADERS {
            let path = Self::temp_path(&self.output_dir, name);
            contents.push(std::fs::read(&path).unwrap_or_default());
        }

        self.blocks = Self::open_temp(&self.output_dir, HEADERS[0].0)?;
        self.transactions = Self::open_temp(&self.output_dir, HEADERS[1].0)?;
        self.inputs = Self::open_temp(&self.output_dir, HEADERS[2].0)?;
        self.outputs = Self::open_temp(&self.output_dir, HEADERS[3].0)?;
        self.witnesses = Self::open_temp(&self.output_dir, HEADERS[4].0)?;
        self.addresses = Self::open_temp(&self.output_dir, HEADERS[5].0)?;
        self.output_addresses = Self::open_temp(&self.output_dir, HEADERS[6].0)?;

        for (i, (name, _)) in HEADERS.iter().enumerate() {
            if contents[i].is_empty() {
                continue;
            }
            let main_path = format!("{}/{}", self.output_dir, name);
            let mut file = OpenOptions::new().append(true).open(&main_path)
                .context(format!("Failed to append to: {}", main_path))?;
            file.write_all(&contents[i])?;
            file.flush()?;
        }

        Ok(())
    }

    pub fn discard(&mut self) -> Result<()> {
        self.flush_all()?;
        self.blocks = Self::open_temp(&self.output_dir, HEADERS[0].0)?;
        self.transactions = Self::open_temp(&self.output_dir, HEADERS[1].0)?;
        self.inputs = Self::open_temp(&self.output_dir, HEADERS[2].0)?;
        self.outputs = Self::open_temp(&self.output_dir, HEADERS[3].0)?;
        self.witnesses = Self::open_temp(&self.output_dir, HEADERS[4].0)?;
        self.addresses = Self::open_temp(&self.output_dir, HEADERS[5].0)?;
        self.output_addresses = Self::open_temp(&self.output_dir, HEADERS[6].0)?;
        Ok(())
    }

    pub fn main_sizes(&self) -> HashMap<String, u64> {
        let mut sizes = HashMap::new();
        for (name, _) in &HEADERS {
            let path = format!("{}/{}", self.output_dir, name);
            if let Ok(meta) = std::fs::metadata(&path) {
                sizes.insert(name.to_string(), meta.len());
            }
        }
        sizes
    }

    pub fn truncate_main(output_dir: &str, sizes: &HashMap<String, u64>) -> Result<()> {
        for (name, _) in &HEADERS {
            if let Some(&size) = sizes.get(*name) {
                let path = format!("{}/{}", output_dir, name);
                let file = OpenOptions::new().write(true).open(&path)
                    .context(format!("Failed to open for truncation: {}", path))?;
                file.set_len(size)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs;

    #[test]
    fn test_csv_writers_creation() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().to_str().unwrap();
        let writers = CsvWriters::new(output_dir, false);
        assert!(writers.is_ok());
        assert!(temp_dir.path().join("blocks.csv").exists());
        assert!(temp_dir.path().join("transactions.csv").exists());
        assert!(temp_dir.path().join("blocks.csv.tmp").exists());
    }

    #[test]
    fn test_csv_headers() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().to_str().unwrap();
        let _writers = CsvWriters::new(output_dir, false).unwrap();

        let content = fs::read_to_string(temp_dir.path().join("blocks.csv")).unwrap();
        assert!(content.starts_with(HEADERS[0].1));

        let content = fs::read_to_string(temp_dir.path().join("transactions.csv")).unwrap();
        assert!(content.starts_with(HEADERS[1].1));

        let content = fs::read_to_string(temp_dir.path().join("witnesses.csv")).unwrap();
        assert!(content.starts_with(HEADERS[4].1));
    }

    #[test]
    fn test_csv_commit() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().to_str().unwrap();
        let mut writers = CsvWriters::new(output_dir, false).unwrap();

        writeln!(writers.blocks, "0,0,hash,2009-01-03,1,prev,merkle,486604799,2083236893,285,1").unwrap();
        writers.commit().unwrap();

        let content = fs::read_to_string(temp_dir.path().join("blocks.csv")).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);

        writeln!(writers.blocks, "1,0,hash2,2009-01-09,1,prev2,merkle2,486604799,123,215,1").unwrap();
        writers.commit().unwrap();

        let content = fs::read_to_string(temp_dir.path().join("blocks.csv")).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("BLOCK_HEIGHT"));
        assert!(lines[1].starts_with("0,"));
        assert!(lines[2].starts_with("1,"));
    }

    #[test]
    fn test_csv_discard() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().to_str().unwrap();
        let mut writers = CsvWriters::new(output_dir, false).unwrap();

        writeln!(writers.blocks, "0,0,hash,2009-01-03,1,prev,merkle,486604799,2083236893,285,1").unwrap();
        writers.discard().unwrap();

        let content = fs::read_to_string(temp_dir.path().join("blocks.csv")).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 1);
    }

    #[test]
    fn test_csv_append_mode() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().to_str().unwrap();

        let mut w1 = CsvWriters::new(output_dir, false).unwrap();
        writeln!(w1.blocks, "0,0,hash,2009-01-03,1,prev,merkle,486604799,2083236893,285,1").unwrap();
        w1.commit().unwrap();

        let mut w2 = CsvWriters::new(output_dir, true).unwrap();
        writeln!(w2.blocks, "1,0,hash2,2009-01-09,1,prev2,merkle2,486604799,123,215,1").unwrap();
        w2.commit().unwrap();

        let content = fs::read_to_string(temp_dir.path().join("blocks.csv")).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("BLOCK_HEIGHT"));
        assert!(lines[1].starts_with("0,"));
        assert!(lines[2].starts_with("1,"));
    }

    #[test]
    fn test_main_sizes_and_truncate() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().to_str().unwrap();
        let mut writers = CsvWriters::new(output_dir, false).unwrap();

        let sizes_before = writers.main_sizes();

        writeln!(writers.blocks, "0,0,hash,2009-01-03,1,prev,merkle,486604799,2083236893,285,1").unwrap();
        writers.commit().unwrap();

        let sizes_after = writers.main_sizes();
        assert!(sizes_after["blocks.csv"] > sizes_before["blocks.csv"]);

        CsvWriters::truncate_main(output_dir, &sizes_before).unwrap();
        let content = fs::read_to_string(temp_dir.path().join("blocks.csv")).unwrap();
        assert_eq!(content.lines().count(), 1);
    }

    #[test]
    fn test_temp_cleanup_on_create() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().to_str().unwrap();

        let mut w1 = CsvWriters::new(output_dir, false).unwrap();
        writeln!(w1.blocks, "leftover data").unwrap();
        w1.flush_all().unwrap();
        drop(w1);

        let temp_path = temp_dir.path().join("blocks.csv.tmp");
        assert!(fs::read_to_string(&temp_path).unwrap().contains("leftover"));

        let _w2 = CsvWriters::new(output_dir, true).unwrap();
        let content = fs::read_to_string(&temp_path).unwrap();
        assert!(content.is_empty());
    }
}
