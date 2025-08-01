
use bs58;
use bech32::{segwit, Hrp};
use sha2::{Sha256, Digest};
use ripemd::{Ripemd160, Digest as RipemdDigest};
use anyhow::Result;

pub fn get_tx_type(script: &[u8]) -> Result<(String, Option<String>)> {
    if script.is_empty() {
        return Ok(("Empty Script".to_string(), None));
    }

    match script {
        // P2PK (uncompressed): PUSH_65 [uncompressed_pubkey] OP_CHECKSIG
        [0x41, pubkey @ .., 0xac] if script.len() == 67 && is_valid_uncompressed_pubkey(pubkey) => {
            let addr = pubkey_to_address(pubkey)?;
            Ok(("P2PK".to_string(), Some(addr)))
        }
        
        // P2PK (compressed): PUSH_33 [compressed_pubkey] OP_CHECKSIG
        [0x21, pubkey @ .., 0xac] if script.len() == 35 && is_valid_compressed_pubkey(pubkey) => {
            let addr = pubkey_to_address(pubkey)?;
            Ok(("P2PK (compressed)".to_string(), Some(addr)))
        }
        
        // P2PKH: OP_DUP OP_HASH160 PUSH_20 [pubkey_hash] OP_EQUALVERIFY OP_CHECKSIG
        [0x76, 0xa9, 0x14, hash @ .., 0x88, 0xac] if script.len() == 25 && hash.len() == 20 => {
            let addr = base58_address(0x00, hash)?; // Mainnet P2PKH prefix
            Ok(("P2PKH".to_string(), Some(addr)))
        }

        // P2PKH with trailing OP_NOP (non-standard but valid)
        [0x76, 0xa9, 0x14, hash @ .., 0x88, 0xac, 0x61] if script.len() == 26 && hash.len() == 20 => {
            let addr = base58_address(0x00, hash)?;
            Ok(("P2PKH_NOP".to_string(), Some(addr)))
        }
        
        // P2SH: OP_HASH160 PUSH_20 [script_hash] OP_EQUAL
        [0xa9, 0x14, hash @ .., 0x87] if script.len() == 23 && hash.len() == 20 => {
            let addr = base58_address(0x05, hash)?; // Mainnet P2SH prefix
            Ok(("P2SH".to_string(), Some(addr)))
        }
        
        // P2WPKH: OP_0 PUSH_20 [pubkey_hash]
        [0x00, 0x14, hash @ ..] if script.len() == 22 && hash.len() == 20 => {
            let addr = bech32_address("bc", 0, hash)?;
            Ok(("P2WPKH".to_string(), Some(addr)))
        }
        
        // P2WSH: OP_0 PUSH_32 [script_hash]
        [0x00, 0x20, hash @ ..] if script.len() == 34 && hash.len() == 32 => {
            let addr = bech32_address("bc", 0, hash)?;
            Ok(("P2WSH".to_string(), Some(addr)))
        }

        // P2TR (Taproot): OP_1 PUSH_32 [x_only_pubkey]
        [0x51, 0x20, pubkey @ ..] if script.len() == 34 && pubkey.len() == 32 => {
            let addr = bech32_address("bc", 1, pubkey)?;
            Ok(("P2TR".to_string(), Some(addr)))
        }
        
        // OP_RETURN (data storage)
        [0x6a, ..] => {
            Ok(("OP_RETURN".to_string(), None))
        }
        
        // Check for multisig patterns
        _ if is_multisig_pattern(script) => {
            parse_multisig(script)
        }
        
        // Check for witness program with invalid version
        [version, len, data @ ..] if *version <= 0x10 && *len as usize == data.len() && 
                                    (*len == 20 || *len == 32) => {
            if *version == 0 {
                // Should have been caught by P2WPKH/P2WSH above, but handle edge cases
                Ok(("Invalid_witness_v0".to_string(), None))
            } else {
                // Future witness versions
                Ok((format!("Witness_v{}", version), None))
            }
        }
        
        // Malformed witness program (PUSH_32 without version)
        [0x20, ..] if script.len() == 33 => {
            Ok(("Malformed_witness".to_string(), None))
        }
        
        // PUSHDATA with ASCII content
        [0x4c, len, data @ .., 0xac] if (*len as usize + 3 == script.len()) && 
                                        is_ascii_printable(&data[..*len as usize]) => {
            Ok(("P2PK_ASCII".to_string(), None))
        }
        
        // Generic pattern matching for other cases
        _ => {
            // Check if it contains printable ASCII data
            if let Some(_ascii_data) = extract_ascii_data(script) {
                Ok(("Nonstandard_ASCII".to_string(), None))
            } else {
                Ok(("Unknown".to_string(), None))
            }
        }
    }
}

fn is_multisig_pattern(script: &[u8]) -> bool {
    if script.is_empty() {
        return false;
    }
    
    // Check if starts with OP_1 through OP_16 (0x51 - 0x60)
    let first_op = script[0];
    (0x51..=0x60).contains(&first_op) && script.len() >= 3
}

fn parse_multisig(script: &[u8]) -> Result<(String, Option<String>)> {
    if script.len() < 3 {
        return Ok(("Invalid_multisig".to_string(), None));
    }
    
    let m = script[0].saturating_sub(0x50); // OP_1 = 0x51, so OP_1 - 0x50 = 1
    let mut index = 1;
    let mut pubkey_count = 0;
    let mut has_ascii = false;
    let mut valid_pubkeys = Vec::new();

    // Parse public keys
    while index < script.len() - 2 { // Leave space for n and OP_CHECKMULTISIG
        let push_len = script.get(index).copied().unwrap_or(0) as usize;
        
        // Valid pubkey lengths
        if push_len != 33 && push_len != 65 {
            break;
        }
        
        if index + 1 + push_len >= script.len() {
            break;
        }

        let pubkey_data = &script[index + 1..index + 1 + push_len];
        
        // Check if it's ASCII (fake pubkey like Luke-Jr's)
        if is_ascii_printable(pubkey_data) {
            has_ascii = true;
        } else if is_valid_pubkey(pubkey_data) {
            if let Ok(addr) = pubkey_to_address(pubkey_data) {
                valid_pubkeys.push(addr);
            }
        }

        index += 1 + push_len;
        pubkey_count += 1;
    }

    // Check for proper multisig ending
    if index + 1 < script.len() {
        let n_op = script[index];
        let checkmultisig_op = script[index + 1];
        
        if (0x51..=0x60).contains(&n_op) && checkmultisig_op == 0xae {
            let n = n_op - 0x50;
            
            if pubkey_count == n as usize && m <= n && m > 0 {
                // Generate P2SH address for the multisig script
                let script_hash = script_to_hash160(script)?;
                let p2sh_addr = base58_address(0x05, &script_hash)?;
                
                let tx_type = if has_ascii {
                    format!("{}-of-{}_Multisig_ASCII", m, n)
                } else {
                    format!("{}-of-{}_Multisig", m, n)
                };
                
                return Ok((tx_type, Some(p2sh_addr)));
            }
        }
    }

    Ok(("Invalid_multisig".to_string(), None))
}

fn is_valid_pubkey(pubkey: &[u8]) -> bool {
    match pubkey.len() {
        33 => is_valid_compressed_pubkey(pubkey),
        65 => is_valid_uncompressed_pubkey(pubkey),
        _ => false,
    }
}

fn is_valid_compressed_pubkey(pubkey: &[u8]) -> bool {
    pubkey.len() == 33 && (pubkey[0] == 0x02 || pubkey[0] == 0x03)
}

fn is_valid_uncompressed_pubkey(pubkey: &[u8]) -> bool {
    pubkey.len() == 65 && pubkey[0] == 0x04
}

fn is_ascii_printable(data: &[u8]) -> bool {
    !data.is_empty() && data.iter().all(|&b| b >= 32 && b <= 126)
}

fn extract_ascii_data(script: &[u8]) -> Option<String> {
    // Look for ASCII data in the script
    let mut ascii_parts = Vec::new();
    let mut i = 0;
    
    while i < script.len() {
        if i + 1 < script.len() {
            let len = script[i] as usize;
            if len > 0 && len <= 75 && i + 1 + len <= script.len() { // Standard push data
                let data = &script[i + 1..i + 1 + len];
                if is_ascii_printable(data) && data.len() >= 4 { // At least 4 chars
                    ascii_parts.push(String::from_utf8_lossy(data).into_owned());
                }
                i += 1 + len;
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    
    if !ascii_parts.is_empty() {
        Some(ascii_parts.join(" "))
    } else {
        None
    }
}

// Helper functions that need to be implemented
fn pubkey_to_address(pubkey: &[u8]) -> Result<String> {
    // Hash the public key with SHA256 then RIPEMD160
    let sha256_hash = Sha256::digest(pubkey);
    let ripemd160_hash = Ripemd160::digest(&sha256_hash);
    
    // Create P2PKH address
    base58_address(0x00, &ripemd160_hash)
}

fn script_to_hash160(script: &[u8]) -> Result<[u8; 20]> {
    let sha256_hash = Sha256::digest(script);
    let ripemd160_hash = Ripemd160::digest(&sha256_hash);
    
    let mut result = [0u8; 20];
    result.copy_from_slice(&ripemd160_hash);
    Ok(result)
}

fn base58_address(prefix: u8, data: &[u8]) -> Result<String> {
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
    Ok(bs58::encode(v).into_string())
}

fn bech32_address(hrp: &str, witver: u8, program: &[u8]) -> Result<String> {
    use bech32::Fe32;
    
    let hrp = Hrp::parse(hrp).unwrap_or_else(|_| Hrp::parse("bc").unwrap());
    
    // Convert u8 witness version to Fe32
    let witver_fe32 = Fe32::try_from(witver).unwrap_or_else(|_| Fe32::Q);
    
    Ok(segwit::encode(hrp, witver_fe32, program)
        .unwrap_or_else(|_| "<invalid bech32>".to_string()))
}


#[cfg(test)]
mod tests {
    use super::*;
    use hex::decode;

    #[test]
    fn test_p2pkh_detection() {
        // Standard P2PKH script: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        let script = vec![
            0x76, 0xa9, 0x14, // OP_DUP OP_HASH160 PUSH_20
            0x89, 0xab, 0xcd, 0xef, 0x97, 0x65, 0x43, 0x21, 0x00, 0x12, 
            0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, // 20-byte hash
            0x88, 0xac // OP_EQUALVERIFY OP_CHECKSIG
        ];
        
        let result = get_tx_type(&script);
        assert!(result.is_ok());
        let (script_type, address_opt) = result.unwrap();
        assert_eq!(script_type, "P2PKH");
        assert!(address_opt.is_some());
    }

    #[test]
    fn test_p2sh_detection() {
        // Standard P2SH script: OP_HASH160 <20 bytes> OP_EQUAL
        let script = vec![
            0xa9, 0x14, // OP_HASH160 PUSH_20
            0x89, 0xab, 0xcd, 0xef, 0x97, 0x65, 0x43, 0x21, 0x00, 0x12, 
            0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, // 20-byte hash
            0x87 // OP_EQUAL
        ];
        
        let result = get_tx_type(&script);
        assert!(result.is_ok());
        let (script_type, address_opt) = result.unwrap();
        assert_eq!(script_type, "P2SH");
        assert!(address_opt.is_some());
    }

    #[test]
    fn test_op_return() {
        let script = vec![0x6a, 0x04, b'T', b'e', b's', b't']; // OP_RETURN "Test"
        let result = get_tx_type(&script);
        assert!(result.is_ok());
        let (script_type, address_opt) = result.unwrap();
        assert_eq!(script_type, "OP_RETURN");
        assert!(address_opt.is_none());
    }

    #[test]
    fn test_empty_script() {
        let result = get_tx_type(&[]);
        assert!(result.is_ok());
        let (script_type, address_opt) = result.unwrap();
        assert_eq!(script_type, "Empty Script");
        assert!(address_opt.is_none());
    }

    #[test]
    fn test_p2pkh() {
        let script = decode("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac").unwrap();
        let result = get_tx_type(&script);
        assert!(result.is_ok());
        let (script_type, _addr) = result.unwrap();
        assert_eq!(script_type, "P2PKH");
    }

    #[test]
    fn test_p2pkh_with_nop() {
        let script = decode("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac61").unwrap();
        let result = get_tx_type(&script);
        assert!(result.is_ok());
        let (script_type, _addr) = result.unwrap();
        assert_eq!(script_type, "P2PKH_NOP");
    }

    #[test]
    fn test_p2sh() {
        let script = decode("a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba87").unwrap();
        let result = get_tx_type(&script);
        assert!(result.is_ok());
        let (script_type, _addr) = result.unwrap();
        assert_eq!(script_type, "P2SH");
    }

    #[test]
    fn test_p2pk_uncompressed() {
        // P2PK with uncompressed public key (65 bytes: 0x04 + 32 bytes x + 32 bytes y)
        let mut script = Vec::new();
        script.push(0x41); // PUSH 65 bytes
        script.push(0x04); // Uncompressed public key prefix
        script.extend_from_slice(&[0x00; 64]); // 64 bytes of zeros (32 for x, 32 for y)
        script.push(0xac); // OP_CHECKSIG
        
        let result = get_tx_type(&script);
        assert!(result.is_ok());
        let (script_type, _addr) = result.unwrap();
        assert_eq!(script_type, "P2PK");
    }

    #[test]
    fn test_p2pk_compressed() {
        // P2PK with compressed public key (33 bytes: 0x02/0x03 + 32 bytes)
        let mut script = Vec::new();
        script.push(0x21); // PUSH 33 bytes
        script.push(0x02); // Compressed public key prefix
        script.extend_from_slice(&[0x00; 32]); // 32 bytes of zeros
        script.push(0xac); // OP_CHECKSIG
        
        let result = get_tx_type(&script);
        assert!(result.is_ok());
        let (script_type, _addr) = result.unwrap();
        assert_eq!(script_type, "P2PK (compressed)");
    }

    #[test]
    fn test_p2wpkh() {
        let script = decode("001489abcdefabbaabbaabbaabbaabbaabbaabbaabba").unwrap();
        let result = get_tx_type(&script);
        assert!(result.is_ok());
        let (script_type, _addr) = result.unwrap();
        assert_eq!(script_type, "P2WPKH");
    }

    #[test]
    fn test_p2wsh() {
        // P2WSH: OP_0 followed by 32 bytes
        let mut hex_data = "0020".to_string(); // OP_0 PUSH_32
        hex_data.push_str(&"11".repeat(32)); // 32 bytes
        let script = decode(&hex_data).unwrap();
        let result = get_tx_type(&script);
        assert!(result.is_ok());
        let (script_type, _addr) = result.unwrap();
        assert_eq!(script_type, "P2WSH");
    }

    #[test]
    fn test_p2tr() {
        // P2TR (Taproot): OP_1 followed by 32 bytes
        let mut hex_data = "5120".to_string(); // OP_1 PUSH_32
        hex_data.push_str(&"22".repeat(32)); // 32 bytes
        let script = decode(&hex_data).unwrap();
        let result = get_tx_type(&script);
        assert!(result.is_ok());
        let (script_type, _addr) = result.unwrap();
        assert_eq!(script_type, "P2TR");
    }

    #[test]
    fn test_op_return_with_data() {
        let script = decode("6a0b68656c6c6f776f726c64").unwrap(); // OP_RETURN "helloworld"
        let result = get_tx_type(&script);
        assert!(result.is_ok());
        let (script_type, _addr) = result.unwrap();
        assert_eq!(script_type, "OP_RETURN");
        assert!(_addr.is_none()); // OP_RETURN should not have an address
    }

    #[test]
    fn test_multisig_1_of_2() {
        // Create a proper 1-of-2 multisig script
        let mut script = Vec::new();
        script.push(0x51); // OP_1
        
        // First public key (33 bytes compressed)
        script.push(0x21); // PUSH 33 bytes
        script.extend_from_slice(&hex::decode("037953dbf08030f67352134992643d033417eaa6fcfb770c038f364ff40d761580").unwrap());
        
        // Second public key (33 bytes compressed) 
        script.push(0x21); // PUSH 33 bytes
        script.extend_from_slice(&hex::decode("0047ab0520d32f1f2c07d6b4955a1e89195be09b9dc646305547fb3fdc425abdf8").unwrap());
        
        script.push(0x52); // OP_2
        script.push(0xae); // OP_CHECKMULTISIG
        
        let result = get_tx_type(&script);
        assert!(result.is_ok());
        let (script_type, _addr) = result.unwrap();
        assert_eq!(script_type, "1-of-2_Multisig");
    }

    #[test]
    fn test_multisig_2_of_3() {
        // Create a proper 2-of-3 multisig script
        let mut script = Vec::new();
        script.push(0x52); // OP_2
        
        // Three public keys (33 bytes each, compressed)
        for _ in 0..3 {
            script.push(0x21); // PUSH 33 bytes
            script.push(0x02); // Compressed key prefix
            script.extend_from_slice(&[0x01; 32]); // 32 bytes of 0x01
        }
        
        script.push(0x53); // OP_3
        script.push(0xae); // OP_CHECKMULTISIG
        
        let result = get_tx_type(&script);
        assert!(result.is_ok());
        let (script_type, _addr) = result.unwrap();
        assert_eq!(script_type, "2-of-3_Multisig");
    }

    #[test]
    fn test_unknown_script() {
        let script = decode("deadbeef").unwrap();
        let result = get_tx_type(&script);
        assert!(result.is_ok());
        let (script_type, _addr) = result.unwrap();
        assert_eq!(script_type, "Unknown");
        assert!(_addr.is_none()); // Unknown scripts should not have addresses
    }

    #[test]
    fn test_null_data_script() {
        // Test OP_RETURN with no data
        let script = vec![0x6a]; // Just OP_RETURN
        let result = get_tx_type(&script);
        assert!(result.is_ok());
        let (script_type, address_opt) = result.unwrap();
        assert_eq!(script_type, "OP_RETURN");
        assert!(address_opt.is_none());
    }

    #[test]
    fn test_invalid_p2pkh_wrong_length() {
        // P2PKH with wrong hash length (19 bytes instead of 20)
        let script = vec![
            0x76, 0xa9, 0x13, // OP_DUP OP_HASH160 PUSH_19 (wrong length)
            0x89, 0xab, 0xcd, 0xef, 0x97, 0x65, 0x43, 0x21, 0x00, 0x12, 
            0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, // 19 bytes
            0x88, 0xac // OP_EQUALVERIFY OP_CHECKSIG
        ];
        
        let result = get_tx_type(&script);
        assert!(result.is_ok());
        let (script_type, _addr) = result.unwrap();
        assert_eq!(script_type, "Unknown"); // Should be classified as unknown
    }

    #[test]
    fn test_invalid_p2sh_wrong_length() {
        // P2SH with wrong hash length (19 bytes instead of 20)
        let script = vec![
            0xa9, 0x13, // OP_HASH160 PUSH_19 (wrong length)
            0x89, 0xab, 0xcd, 0xef, 0x97, 0x65, 0x43, 0x21, 0x00, 0x12, 
            0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, // 19 bytes
            0x87 // OP_EQUAL
        ];
        
        let result = get_tx_type(&script);
        assert!(result.is_ok());
        let (script_type, _addr) = result.unwrap();
        assert_eq!(script_type, "Unknown"); // Should be classified as unknown
    }

    #[test]
    fn test_very_large_script() {
        // Test with a very large script to ensure no panics
        let script = vec![0x00; 10000]; // 10KB of zeros
        let result = get_tx_type(&script);
        assert!(result.is_ok());
        let (script_type, _addr) = result.unwrap();
        assert_eq!(script_type, "Unknown");
    }

    #[test]
    fn test_single_byte_scripts() {
        // Test various single-byte scripts
        for opcode in [0x00, 0x51, 0x52, 0x53, 0x63, 0x82, 0x87, 0x88, 0xac, 0xae] {
            let script = vec![opcode];
            let result = get_tx_type(&script);
            assert!(result.is_ok());
            // Most single opcodes should be classified as Unknown
        }
    }
}