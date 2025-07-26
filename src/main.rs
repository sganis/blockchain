mod opcodes;
mod hash;
mod transaction;

use anyhow::Result;
use hex;
use sha2::{Sha256, Digest};
use chrono::prelude::{TimeZone, Utc};
use std::{
    fs::File, 
    fs::OpenOptions, 
    io::{BufReader, Write, Read, BufWriter},
    collections::HashMap
};

use opcodes::script_to_opcodes;
use transaction::get_tx_type;

const MAGIC: u32 = 3_652_501_241; // FEBEB4D9

struct VarInt(u64, u32, [u8; 9]);
impl VarInt {
    fn value(&self) -> u64 {
        self.0
    }
    fn len(&self) -> u32 {
        self.1
    }
    fn data(&self) -> [u8; 9] {
        self.2
    }
}
fn read_varint<T: Read>(reader: &mut BufReader<T>) -> Result<VarInt> {
    let mut b1 = vec![0u8; 1];
    let mut b2 = vec![0u8; 2];
    let mut b4 = vec![0u8; 4];
    let mut b8 = vec![0u8; 8];

    reader.read_exact(&mut b1)?;
    let number = u8::from_le_bytes(b1[..].try_into()?) as u64;
    let mut data = [0u8; 9];
    data[0] = b1[0];

    let varint = match number {
        253 => {
            reader.read_exact(&mut b2)?;
            data[1..3].copy_from_slice(&b2[..]);
            VarInt(u16::from_le_bytes(b2[..].try_into()?) as u64, 3, data)
        },
        254 => {
            reader.read_exact(&mut b4)?;
            data[1..5].copy_from_slice(&b4[..]);
            VarInt(u32::from_le_bytes(b4[..4].try_into()?) as u64, 5, data)
        },
        255 => {
            reader.read_exact(&mut b8)?;
            data[1..9].copy_from_slice(&b8[..]);
            VarInt(u64::from_le_bytes(b8[..8].try_into()?), 9, data)
        },
        _ => {
            VarInt(number, 1, data)
        }
    };
    //println!("VarInt: {} {} {:?}", varint.value(), varint.len(), varint.data());
    Ok(varint)
}
struct Header {
    version: [u8; 4],
    prev_hash: [u8; 32],
    merkle_root: [u8; 32],
    time: [u8; 4],
    bits: [u8; 4],
    nonce: [u8; 4],
}
struct Block {
    size: u32,
    header: Header,
    transactions: Vec<Tx>,
}
struct Tx {
    version: u32,
    flag: Option<[u8; 2]>,
    inputs: Vec<Input>,
    outputs: Vec<Output>,
    witnesses: Option<Vec<Witness>>,
    lock_time: [u8; 4],
}
struct Input {
    txid: [u8; 32],
    vout: u32,
    script_len: VarInt,
    script: Vec<u8>,
    sequence: [u8; 4],
}
struct Output {
    value: u64,
    script_len: VarInt,
    script: Vec<u8>,
}
struct Witness {

}




fn main() -> Result<()> {
    let mut b1 = vec![0u8; 1];
    let mut b4 = vec![0u8; 4];
    let mut b8 = vec![0u8; 8];
    let mut b32 = vec![0u8; 32];
    let mut block_number = 0;

    let mut tx_types: HashMap<String, usize> = HashMap::new(); // tx_type -> txid

    // segwit
    //let mut file_number = 976;

    // create files with headers
    let f = File::create("F:/csv/blocks.csv").expect("Unable to create file");
    let mut blk_w = BufWriter::new(f);
    writeln!(blk_w, "FILE,BLOCK,DATE,TIME,VERSION,PREV_HASH,MERKLE_ROOT,BITS,NONCE,TX_COUNT")?;

    let f = File::create("F:/csv/tx.csv").expect("Unable to create file");
    let mut tx_w = BufWriter::new(f);
    writeln!(tx_w, "BLOCK,TXID,INP_COUNT,OUT_COUNT")?;
    
    let f = File::create("F:/csv/txi.csv").expect("Unable to create file");
    let mut txi_w = BufWriter::new(f);
    writeln!(txi_w, "TXID,TIN,VOUT,SCRIPT")?;

    let f = File::create("F:/csv/txo.csv").expect("Unable to create file");
    let mut txo_w = BufWriter::new(f);
    writeln!(txo_w, "TXID,AMOUNT,SCRIPT")?;

    let mut debug = false;

    for file_number in 0..4926 {
        // if file_number != 4 {
        //     continue;
        // }
        let reader = File::open(format!("F:/btc/blocks/blk{:05}.dat", file_number))?;
        //let reader = File::open("data/blk00000.dat")?;
        let mut reader = BufReader::new(reader);

        loop {       
            if reader.read_exact(&mut b4).is_err() {
                println!("eof for file {}", file_number);
                break;
            }

            //println!("\nBLOCK NUMBER: {}", block_number);

            // if block_number == 214 {
            //      debug = true;
            // }

            let magic = u32::from_le_bytes(b4[..4].try_into()?);
            assert!(magic == MAGIC, "Wrong magic number");    
            //let bsize = u32::from_le_bytes(b4[..4].try_into()?);
            
            // block
            // version
            reader.read_exact(&mut b4)?;
            let version = b4[..].try_into()?;
            let version_int = u32::from_le_bytes(b4[..].try_into()?);
            
            // previous block hash
            reader.read_exact(&mut b32)?;
            let prev_hash = b32[..].try_into()?;
            
            // merkle root
            reader.read_exact(&mut b32)?;
            let merkle_root = b32[..].try_into()?;
            
            // time
            reader.read_exact(&mut b4)?;
            let time = b4[..4].try_into()?;
            let timestamp = u32::from_le_bytes(b4[..].try_into()?) as i64;
            let datetime = Utc.timestamp_opt(timestamp, 0).unwrap();
            let date_str = datetime.format("%Y-%m-%d");
            let time_str = datetime.format("%H:%M:%S");            
            
            println!("FILE {} BLOCK {} {} {}", file_number, block_number, date_str, time_str);
            
            // bits
            reader.read_exact(&mut b4)?;
            let bits = b4[..4].try_into()?;

            // nonce
            reader.read_exact(&mut b4)?;
            let nonce = b4[..4].try_into()?;
            
            // header
            let header = Header {version, prev_hash, merkle_root, time, bits, nonce};
            
            let tx_count = read_varint(&mut reader)?;
            if debug {
                println!("Transactions: {}", tx_count.value());
            }
            writeln!(blk_w, "{},{},{},{},{}", 
                file_number, block_number, date_str, time_str,
                // hex::encode(version), 
                // hex::encode(prev_hash), 
                // hex::encode(merkle_root), 
                // hex::encode(bits), 
                // hex::encode(nonce),
                tx_count.value()
            )?;
            
            // tx
            for t in 0..tx_count.value() {
                if debug {
                    println!(" Transaction: {}", (t + 1));
                }

                let mut hasher = Sha256::new();

                // version
                reader.read_exact(&mut b4)?;
                hasher.update(&b4);
                let version = u32::from_le_bytes(b4[..].try_into()?);                
                //println!("version     : {}", hex::encode(&b4));
                //assert_eq!(version, 1);
                
                // optional flag 0001 2 bytes or varint with num of inputs
                let mut in_count = read_varint(&mut reader)?;
                if debug { 
                    println!(" Inputs     : {}", in_count.value());
                }
                
                let mut has_witness = false;

                if in_count.value() == 0 {
                    has_witness = true;    
                    reader.read_exact(&mut b1)?;
                    assert_eq!(hex::encode(&b1), "01");
                    in_count = read_varint(&mut reader)?;
                    if debug {
                        println!("segwit flag, in_counter: {}", in_count.value());
                    }
                    //debug = true;                    
                } 

                hasher.update(&in_count.data()[..in_count.len() as usize]);
                
                // input
                for _ in 0..in_count.value() {
                    // prev tx hash
                    reader.read_exact(&mut b32)?;
                    hasher.update(&b32);                
                    let txid = hex::encode(&b32);
                    if debug {
                        println!("  txid     : {}", txid);
                    }
                    // prev txout index
                    reader.read_exact(&mut b4)?;
                    hasher.update(&b4);
                    let vout = u32::from_le_bytes(b4[..4].try_into()?); 
                    //println!("  vout: {}", hex::encode(&b4));
                    
                    // tx in script len
                    let in_script_len = read_varint(&mut reader)?;
                    hasher.update(&in_script_len.data()[..in_script_len.len() as usize]);
                    //println!("  script_len: {}", in_script_len.value());
                    // scriptsig
                    let mut script_sig = vec![0u8; in_script_len.value() as usize];
                    reader.read_exact(&mut script_sig)?;
                    hasher.update(&script_sig[..script_sig.len() as usize]);
                    if debug { 
                        println!("  script_sig hex: {}", hex::encode(&script_sig));
                    }
                    
                    // let opcode = script_to_opcodes(&script_sig, debug);
                    // if debug { 
                    //     println!("  script_sig: {}", opcode);
                    // }
                    // sequence
                    reader.read_exact(&mut b4)?;
                    hasher.update(&b4);
                    //println!("  sequence nr : {}", hex::encode(&b4));

                    // writeln!(txi_w, "{},{},{}", txid, vout, opcode)?;
            
                }

                // out-counter
                let out_count = read_varint(&mut reader)?;
                hasher.update(&out_count.data()[..out_count.len() as usize]);
                //println!(" Outputs    : {}", out_count.value());

                // output
                for i in 0..out_count.value() {
                    // sat value
                    reader.read_exact(&mut b8)?;
                    hasher.update(&b8);
                    let value = u64::from_le_bytes(b8[..8].try_into()?);
                    // if value != 50 {
                    //     debug = true;
                    // }
                    if debug {
                        println!("  Output {}/{}: {}", i+1, out_count.value(), value);
                    }
                    // tx in script len
                    let script_len = read_varint(&mut reader)?;
                    hasher.update(&script_len.data()[..script_len.len() as usize]);
                    //println!("  script_len: {}", script_len.value());
                    
                    // scriptpk
                    if script_len.value() > 0 {
                        let mut script_pky = vec![0u8; script_len.value() as usize];
                        reader.read_exact(&mut script_pky)?;
                        hasher.update(&script_pky[..script_pky.len() as usize]);
                        // if debug {
                        //     println!("  script_pub hex: {}", hex::encode(&script_pky));
                        // }
                        let tx_type = get_tx_type(&script_pky);                        
                        if debug {
                            println!("     tx type: {}", tx_type);
                        }
                        // let opcode = script_to_opcodes(&script_pky, debug);
                        // if debug {
                        //     println!("  script_pub: {}", opcode);
                        // }                        

                        let script_type = tx_type.to_string();                       

                        if !tx_types.contains_key(&script_type) {
                            tx_types.insert(script_type.clone(), 1);   
                            //println!("\nFILE {} BLOCK {} {} {}", file_number, block_number, date_str, time_str);             
                            println!("first time tx type: {:<10}", tx_type);
                        } else {
                            tx_types.insert(script_type.clone(), tx_types[&script_type] + 1);
                        }

                        if tx_type == "Unknown" {
                            //println!("\nFILE {} BLOCK {} {} {}", file_number, block_number, date_str, time_str);             
                            println!("  Unknown tx type:");
                            println!("       script_pub: {}", &hex::encode(&script_pky));
                            let opcode = script_to_opcodes(&script_pky, debug);
                            println!("       opcode    : {}", opcode);                             
                        } 
                    }
                    //writeln!(txo_w, "{},{},{}", txid, vout, opcode)?;

                }
                // witnesses
                if has_witness {
                    for _ in 0..in_count.value() {
                        let wit_count = read_varint(&mut reader)?;
                        if debug {
                            println!("  witness items : {}", wit_count.value());
                        }
                        for _ in 0..wit_count.value() {
                            let wit_len = read_varint(&mut reader)?.value();                            
                            let mut wit_buf = vec![0u8; wit_len as usize];
                            reader.read_exact(&mut wit_buf)?;
                            if debug {
                                println!("  witness : {}: {}", wit_len, hex::encode(wit_buf));
                            }

                        }
                    }
                }
                // lock time
                reader.read_exact(&mut b4)?;
                //println!("lock_time : {}", hex::encode(&b4));
                hasher.update(&b4);
                let hash = hasher.finalize();
                let txid = hex::encode(&hash::reverse(&Sha256::digest(&hash)));
                // if debug {
                //     println!("first sigwit txid: {}", txid);
                //     assert!("9c1ab453283035800c43eb6461eb46682b81be110a0cb89ee923882a5fd9daa4"==&txid);
                //     debug = false;
                // }
                
                //writeln!(tx_w, "{},{},{},{}",block_number, txid, in_count.value(), out_count.value())?;
            
            }   

            blk_w.flush()?;

            //break;

            block_number +=1;

        }
    }
    
    println!("\n--- Transaction Type Summary ---");
    for (tx_type, count) in &tx_types {
        println!("{:<10} {}", tx_type, count);
    }

    Ok(())
}

