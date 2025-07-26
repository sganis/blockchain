pub fn get_tx_type(script: &[u8]) -> String {
    "not implemented".to_string()
    // match script {
    //     // P2PKH
    //     [0x76, 0xa9, 0x14, .., 0x88, 0xac] if script.len() == 25 => "P2PKH".to_string(),
    //     // P2PKH with NOP (non-standard)
    //     [0x76, 0xa9, 0x14, .., 0x88, 0xac, 0x61] if script.len() == 26 => "P2PKH_NOP".to_string(),
    //     // P2SH
    //     [0xa9, 0x14, .., 0x87] if script.len() == 23 => "P2SH".to_string(),
    //     // P2PK (uncompressed)
    //     [0x41, 0x04, .., 0xac] if script.len() == 67 => "P2PK".to_string(),
    //     // P2PK (compressed)
    //     [0x21, 0x02..=0x03, .., 0xac] if script.len() == 35 => "P2PK (compressed)".to_string(),
    //     // P2WPKH
    //     [0x00, 0x14, ..] if script.len() == 22 => "P2WPKH".to_string(),
    //     // P2WSH
    //     [0x00, 0x20, ..] if script.len() == 34 => "P2WSH".to_string(),
    //     // P2TR
    //     [0x51, 0x20, ..] if script.len() == 34 => "P2TR".to_string(),
    //     // Possibly malformed witness program (starts with PUSHBYTES_32 but no version byte)
    //     [0x20, ..] if script.len() == 33 => "Nonstandard PUSHBYTES_32 (malformed witness)".to_string(),
    //     // PUSHDATA1 + ASCII + OP_CHECKSIG
    //     [0x4c, len, rest @ .., 0xac] if *len as usize + 3 == script.len() => {
    //         let ascii_data = &script[2..(2 + *len as usize)];
    //         let decoded = std::str::from_utf8(ascii_data).unwrap_or("<non-ascii>");
    //         format!("Nonstandard P2PK with ASCII: \"{}\"", decoded)
    //     }
    //     // OP_RETURN
    //     //[0x6a, ..] => "OP_RETURN".to_string(),
    //     // OP_RETURN
    //     [0x6a, rest @ ..] => {
    //         let ascii = std::str::from_utf8(rest).unwrap_or("<non-ascii>");
    //         format!("OP_RETURN \"{}\"", ascii)
    //     }
    //     // Catch-all for multisig-like scripts
    //     _ if script.len() >= 1 && script[0] >= 0x51 && script[0] <= 0x60 => {
    //         let m = script[0] - 0x50;
    //         let mut index = 1;
    //         let mut pubkey_count = 0;

    //         while index < script.len() {
    //             let len = script.get(index).copied().unwrap_or(0) as usize;
    //             if len != 33 && len != 65 {
    //                 break;
    //             }

    //             if index + 1 + len > script.len() {
    //                 break;
    //             }

    //             index += 1 + len;
    //             pubkey_count += 1;
    //         }

    //         let n_index = index;
    //         let n = script.get(n_index).copied().unwrap_or(0);
    //         let checkmultisig = script.get(n_index + 1).copied().unwrap_or(0);

    //         if n >= 0x51 && n <= 0x60 && checkmultisig == 0xae {
    //             let n_val = n - 0x50;
    //             if pubkey_count == n_val && m <= n_val {
    //                 return format!("{m}-of-{n_val} Multisig");
    //             }
    //         }

    //         "Unknown".to_string()
    //     }

    //     _ => "Unknown".to_string(),
    // }
}

pub fn extract_ascii_from_pushdata1(script: &[u8]) -> Option<String> {
    // Check for: PUSHDATA1 (0x4c), length byte, then data, then OP_CHECKSIG (0xac)
    if script.len() >= 3 && script[0] == 0x4c {
        let len = script[1] as usize;
        if script.len() == 2 + len + 1 && script[2 + len] == 0xac {
            let data = &script[2..2 + len];
            // Try to convert to ASCII string
            return std::str::from_utf8(data).ok().map(|s| s.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::decode;

    #[test]
    fn test_p2pkh() {
        let script = decode("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac").unwrap();
        assert_eq!(get_tx_type(&script), "P2PKH");
    }

    #[test]
    fn test_p2pkh_with_nop() {
        let script = decode("76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac61").unwrap();
        assert_eq!(get_tx_type(&script), "P2PKH_NOP");
    }

    #[test]
    fn test_p2sh() {
        let script = decode("a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba87").unwrap();
        assert_eq!(get_tx_type(&script), "P2SH");
    }

    #[test]
    fn test_p2pk_uncompressed() {
        let script = decode(&format!("41{}ac", "04".repeat(65))).unwrap();
        assert_eq!(get_tx_type(&script), "P2PK");
    }

    #[test]
    fn test_p2pk_compressed() {
        let script = decode(&format!("21{}ac", "02".repeat(33))).unwrap();
        assert_eq!(get_tx_type(&script), "P2PK (compressed)");
    }

    #[test]
    fn test_p2wpkh() {
        let script = decode("001489abcdefabbaabbaabbaabbaabbaabbaabbaabba").unwrap();
        assert_eq!(get_tx_type(&script), "P2WPKH");
    }

    #[test]
    fn test_p2wsh() {
        let script = decode(&format!("0020{}", "11".repeat(32))).unwrap();
        assert_eq!(get_tx_type(&script), "P2WSH");
    }

    #[test]
    fn test_p2tr() {
        let script = decode(&format!("5120{}", "22".repeat(32))).unwrap();
        assert_eq!(get_tx_type(&script), "P2TR");
    }

    #[test]
    fn test_op_return() {
        let script = decode("6a0b68656c6c6f776f726c64").unwrap(); // OP_RETURN "helloworld"
        assert_eq!(get_tx_type(&script), "OP_RETURN");
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
        assert_eq!(get_tx_type(&script), "1-of-2 Multisig");
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
        assert_eq!(get_tx_type(&script), "2-of-3 Multisig");
    }

    #[test]
    fn test_unknown_script() {
        let script = decode("deadbeef").unwrap();
        assert_eq!(get_tx_type(&script), "Unknown");
    }
}
