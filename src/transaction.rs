use sha2::{Digest, Sha256};
use ripemd::Ripemd160;
use bs58;
use bech32::{segwit, Hrp};

pub fn get_tx_type(script: &[u8]) -> (String, Option<String>) {
    match script {
        // P2PK (uncompressed)
        [0x41, 0x04, rest @ .., 0xac] if script.len() == 67 => {
            let pubkey = &script[1..66]; // Extract the 65-byte public key
            let addr = pubkey_to_address(pubkey);
            ("P2PK".to_string(), Some(addr))
        }      
        // P2PK (compressed)
        [0x21, 0x02..=0x03, rest @ .., 0xac] if script.len() == 35 => {
            let pubkey = &script[1..34]; // Extract the 33-byte compressed public key
            let addr = pubkey_to_address(pubkey);
            ("P2PK (compressed)".to_string(), Some(addr))
        }
        // P2PKH: OP_DUP OP_HASH160 PUSH_20 [pubkey_hash] OP_EQUALVERIFY OP_CHECKSIG
        [0x76, 0xa9, 0x14, data @ .., 0x88, 0xac] if script.len() == 25 => {
            let addr = base58_address(0x00, data); // 0x00 is the prefix for mainnet P2PKH
            ("P2PKH".to_string(), Some(addr))
        }

        // P2PKH with NOP (non-standard)
        [0x76, 0xa9, 0x14, .., 0x88, 0xac, 0x61] if script.len() == 26 => {
            ("P2PKH_NOP".to_string(), None)
        }
        
        // P2SH: OP_HASH160 PUSH_20 [script_hash] OP_EQUAL
        [0xa9, 0x14, data @ .., 0x87] if script.len() == 23 => {
            let addr = base58_address(0x05, data); // 0x05 is the prefix for mainnet P2SH
            ("P2SH".to_string(), Some(addr))
        }
        
        // P2WPKH: OP_0 PUSH_20 [pubkey_hash]
        [0x00, 0x14, data @ ..] if script.len() == 22 => {
            let addr = bech32_address("bc", 0, data);
            ("P2WPKH".to_string(), Some(addr))
        }
        
        // P2WSH: OP_0 PUSH_32 [script_hash]
        [0x00, 0x20, data @ ..] if script.len() == 34 => {
            let addr = bech32_address("bc", 0, data);
            ("P2WSH".to_string(), Some(addr))
        }

        // P2TR: OP_1 PUSH_32 [xonly_pubkey]
        [0x51, 0x20, data @ ..] if script.len() == 34 => {
            let addr = bech32_address("bc", 1, data);
            ("P2TR".to_string(), Some(addr))
        }
        
        // Possibly malformed witness program (starts with PUSHBYTES_32 but no version byte)
        [0x20, ..] if script.len() == 33 => {
            ("Nonstandard PUSHBYTES_32 (malformed witness)".to_string(), None)
        }
        
        // PUSHDATA1 + ASCII + OP_CHECKSIG
        [0x4c, len, rest @ .., 0xac] if *len as usize + 3 == script.len() => {
            ("Nonstandard P2PK with ASCII".to_string(), None)
        }
        
        // OP_RETURN
        [0x6a, ..] => {
            ("OP_RETURN".to_string(), None)
        }
        
        // Multisig with possible fake pubkeys (Luke-Jr style)
        _ if script.len() >= 1 && (0x51..=0x60).contains(&script[0]) => {
            let m = script[0] - 0x50;
            let mut index = 1;
            let mut pubkey_count = 0;
            let mut ascii_parts = Vec::new();
            let mut pubkey_addresses = Vec::new();

            while index < script.len() {
                let len = script.get(index).copied().unwrap_or(0) as usize;
                if len != 33 && len != 65 {
                    break;
                }
                if index + 1 + len > script.len() {
                    break;
                }

                let pubkey = &script[index + 1..index + 1 + len];
                
                // Check if it's ASCII data (fake pubkey)
                if is_ascii_printable(pubkey) {
                    ascii_parts.push(String::from_utf8_lossy(pubkey).into_owned());
                } else {
                    // It's a real pubkey, generate address
                    let addr = pubkey_to_address(pubkey);
                    pubkey_addresses.push(addr);
                }

                index += 1 + len;
                pubkey_count += 1;
            }

            let n_index = index;
            let n = script.get(n_index).copied().unwrap_or(0);
            let checkmultisig = script.get(n_index + 1).copied().unwrap_or(0);

            if n >= 0x51 && n <= 0x60 && checkmultisig == 0xae {
                let n_val = n - 0x50;
                if pubkey_count == n_val && m <= n_val {
                    // Generate P2SH address for the multisig script
                    let script_hash = script_to_hash160(script);
                    let p2sh_addr = base58_address(0x05, &script_hash);
                    
                    if !ascii_parts.is_empty() {
                        return (format!("{m}-of-{n_val} Multisig with ASCII data"), Some(p2sh_addr));
                    } else {
                        let addr_info = if !pubkey_addresses.is_empty() {
                            format!(" (pubkey addrs: {})", pubkey_addresses.join(", "))
                        } else {
                            String::new()
                        };
                        return (format!("{m}-of-{n_val} Multisig{}", addr_info), Some(p2sh_addr));
                    }
                }
            }

            ("Unknown multisig-like script".to_string(), None)
        }

        _ => {
            if let Some(ascii) = extract_ascii_data(script) {
                // (format!("Nonstandard with ASCII: \"{}\"", ascii.trim()), None)
                (format!("Nonstandard with ASCII data"), None)
            } else {
                ("Unknown".to_string(), None)
            }
        }
    }
}

fn script_to_hash160(script: &[u8]) -> Vec<u8> {
    // Step 1: SHA256 hash of the script
    let mut sha256_hasher = Sha256::new();
    sha256_hasher.update(script);
    let sha256_hash = sha256_hasher.finalize();
    
    // Step 2: RIPEMD160 hash of the SHA256 hash
    let mut ripemd_hasher = Ripemd160::new();
    ripemd_hasher.update(&sha256_hash);
    ripemd_hasher.finalize().to_vec()
}

fn pubkey_to_address(pubkey: &[u8]) -> String {
    // Step 1: SHA256 hash of the public key
    let mut sha256_hasher = Sha256::new();
    sha256_hasher.update(pubkey);
    let sha256_hash = sha256_hasher.finalize();
    
    // Step 2: RIPEMD160 hash of the SHA256 hash
    let mut ripemd_hasher = Ripemd160::new();
    ripemd_hasher.update(&sha256_hash);
    let pubkey_hash = ripemd_hasher.finalize();
    
    // Step 3: Create P2PKH address using the pubkey hash
    base58_address(0x00, &pubkey_hash)
}

fn base58_address(prefix: u8, data: &[u8]) -> String {
    let mut v = vec![prefix];
    v.extend_from_slice(data);
    
    // Create double SHA256 hash for checksum
    let mut hasher = Sha256::new();
    hasher.update(&v);
    let hash1 = hasher.finalize();
    
    let mut hasher2 = Sha256::new();
    hasher2.update(&hash1);
    let hash2 = hasher2.finalize();
    
    let checksum = &hash2[..4];
    v.extend_from_slice(checksum);
    bs58::encode(v).into_string()
}

fn bech32_address(hrp: &str, witver: u8, program: &[u8]) -> String {
    use bech32::Fe32;
    
    let hrp = Hrp::parse(hrp).unwrap_or_else(|_| Hrp::parse("bc").unwrap());
    
    // Convert u8 witness version to Fe32
    let witver_fe32 = Fe32::try_from(witver).unwrap_or_else(|_| Fe32::Q);
    
    segwit::encode(hrp, witver_fe32, program)
        .unwrap_or_else(|_| "<invalid bech32>".to_string())
}

pub fn extract_ascii_data(script: &[u8]) -> Option<String> {
    let mut i = 0;
    let mut ascii_data = Vec::new();

    while i < script.len() {
        let op = script[i];
        i += 1;

        match op {
            0x01..=0x4b => {
                // PUSHDATA: next `op` bytes are data
                let len = op as usize;
                if i + len > script.len() {
                    break;
                }
                let data = &script[i..i + len];

                if is_ascii_printable(data) {
                    ascii_data.extend_from_slice(data);
                    ascii_data.push(b'\n');
                }

                i += len;
            }
            0x4c => {
                // OP_PUSHDATA1
                if i >= script.len() {
                    break;
                }
                let len = script[i] as usize;
                i += 1;
                if i + len > script.len() {
                    break;
                }
                let data = &script[i..i + len];

                if is_ascii_printable(data) {
                    ascii_data.extend_from_slice(data);
                    ascii_data.push(b'\n');
                }

                i += len;
            }
            0xae => {
                // OP_CHECKMULTISIG — might contain fake pubkeys
                // Go backwards and look for 33- or 65-byte pubkeys
                let mut j = i;
                while j < script.len() {
                    let len = script[j] as usize;
                    j += 1;
                    if j + len > script.len() {
                        break;
                    }
                    let data = &script[j..j + len];
                    if (len == 33 || len == 65) && is_ascii_printable(data) {
                        ascii_data.extend_from_slice(data);
                        ascii_data.push(b'\n');
                    }
                    j += len;
                }
                break;
            }
            0x75 => {
                // OP_DROP — likely data before was for embedding
                // We already caught it above
                continue;
            }
            _ => continue,
        }
    }

    if ascii_data.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&ascii_data).to_string())
    }
}

fn is_ascii_printable(data: &[u8]) -> bool {
    data.iter().all(|&b| b >= 0x20 && b <= 0x7e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::decode;

    #[test]
    fn test_p2pkh() {
        let script = decode("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac").unwrap();
        let (script_type, _addr) = get_tx_type(&script);
        assert_eq!(script_type, "P2PKH");
    }

    #[test]
    fn test_p2pkh_with_nop() {
        let script = decode("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac61").unwrap();
        let (script_type, _addr) = get_tx_type(&script);
        assert_eq!(script_type, "P2PKH_NOP");
    }

    #[test]
    fn test_p2sh() {
        let script = decode("a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba87").unwrap();
        let (script_type, _addr) = get_tx_type(&script);
        assert_eq!(script_type, "P2SH");
    }

    #[test]
    fn test_p2pk_uncompressed() {
        let mut hex_data = "41".to_string();
        hex_data.push_str(&"04".repeat(1));
        hex_data.push_str(&"00".repeat(64));
        hex_data.push_str("ac");
        let script = decode(&hex_data).unwrap();
        let (script_type, _addr) = get_tx_type(&script);
        assert_eq!(script_type, "P2PK");
    }

    #[test]
    fn test_p2pk_compressed() {
        let mut hex_data = "21".to_string();
        hex_data.push_str("02");
        hex_data.push_str(&"00".repeat(32));
        hex_data.push_str("ac");
        let script = decode(&hex_data).unwrap();
        let (script_type, _addr) = get_tx_type(&script);
        assert_eq!(script_type, "P2PK (compressed)");
    }

    #[test]
    fn test_p2wpkh() {
        let script = decode("001489abcdefabbaabbaabbaabbaabbaabbaabbaabba").unwrap();
        let (script_type, _addr) = get_tx_type(&script);
        assert_eq!(script_type, "P2WPKH");
    }

    #[test]
    fn test_p2wsh() {
        let mut hex_data = "0020".to_string();
        hex_data.push_str(&"11".repeat(32));
        let script = decode(&hex_data).unwrap();
        let (script_type, _addr) = get_tx_type(&script);
        assert_eq!(script_type, "P2WSH");
    }

    #[test]
    fn test_p2tr() {
        let mut hex_data = "5120".to_string();
        hex_data.push_str(&"22".repeat(32));
        let script = decode(&hex_data).unwrap();
        let (script_type, _addr) = get_tx_type(&script);
        assert_eq!(script_type, "P2TR");
    }

    #[test]
    fn test_op_return() {
        let script = decode("6a0b68656c6c6f776f726c64").unwrap(); // OP_RETURN "helloworld"
        let (script_type, _addr) = get_tx_type(&script);
        assert_eq!(script_type, "OP_RETURN");
    }

    #[test]
    fn test_multisig_1_of_2() {
        let script = decode(concat!(
            "51", // OP_1
            "21", "037953dbf08030f67352134992643d033417eaa6fcfb770c038f364ff40d761588",
            "21", "0047ab0520d32f1f2c07d6b4955a1e89195be09b9dc646305547fb3fdc425abdf8",
            "52", // OP_2
            "ae"  // OP_CHECKMULTISIG
        )).unwrap();
        let (script_type, _addr) = get_tx_type(&script);
        assert_eq!(script_type, "1-of-2 Multisig");
    }

    #[test]
    fn test_multisig_2_of_3() {
        let script = decode(concat!(
            "52", // OP_2
            "21", "020202020202020202020202020202020202020202020202020202020202020202",
            "21", "030303030303030303030303030303030303030303030303030303030303030303",
            "21", "020202020202020202020202020202020202020202020202020202020202020202",
            "53", // OP_3
            "ae"  // OP_CHECKMULTISIG
        )).unwrap();
        let (script_type, _addr) = get_tx_type(&script);
        assert_eq!(script_type, "2-of-3 Multisig");
    }

    #[test]
    fn test_unknown_script() {
        let script = decode("deadbeef").unwrap();
        let (script_type, _addr) = get_tx_type(&script);
        assert_eq!(script_type, "Unknown");
    }
}