pub fn script_to_opcodes(script: &[u8], debug: bool) -> String {
    let mut opcodes = Vec::new();
    let mut index = 0;

    while index < script.len() {
        let byte = script[index];
        
        let opcode = match byte {
            0x00 => "0".to_string(),
            0x01..=0x4b => {
                let mut data_len = byte as usize;
                if index + 1 + data_len <= script.len() {
                    let data = &script[(index + 1)..(index + 1 + data_len)];
                    index += data_len;
                    format!("PUSHBYTES_{} {}", byte, hex::encode(&data))
                } else {
                    index += data_len;
                    format!("PUSHBYTES_{} <overflow>", byte)
                }
            },
            0x4c => {
                let data_len = script[index + 1] as usize;
                index += 1;
                let data = &script[(index + 1)..(index + 1 + data_len)];
                index += data_len;
                format!("PUSHDATA1 {} {}", data_len, hex::encode(data))
            }
            0x4d => {
                let data_len = u16::from_le_bytes([
                    script[index + 1], 
                    script[index + 2]
                ]) as usize;
                index += 2;
                let data = &script[(index + 1)..(index + 1 + data_len)];
                index += data_len;
                format!("PUSHDATA2 {} {}", data_len, hex::encode(data))
            }
            0x4e => {
                let data_len = u32::from_le_bytes([
                    script[index + 1],
                    script[index + 2],
                    script[index + 3],
                    script[index + 4],
                ]) as usize;
                index += 4;
                let data = &script[(index + 1)..(index + 1 + data_len)];
                index += data_len;
                format!("PUSHDATA4 {} {}", data_len, hex::encode(data))
            }
            0x4f => "1NEGATE".to_string(),
            0x50 => "RESERVED".to_string(),
            0x51..=0x60 => format!("{}", byte - 0x50),
            0x61 => "NOP".to_string(),
            0x62 => "VER".to_string(),
            0x63 => "IF".to_string(),
            0x64 => "NOTIF".to_string(),
            0x65 => "VERIF".to_string(),
            0x66 => "VERNOTIF".to_string(),
            0x67 => "ELSE".to_string(),
            0x68 => "ENDIF".to_string(),
            0x69 => "VERIFY".to_string(),
            0x6a => "RETURN".to_string(),
            0x6b => "TOALTSTACK".to_string(),
            0x6c => "FROMALTSTACK".to_string(),
            0x6d => "2DROP".to_string(),
            0x6e => "2DUP".to_string(),
            0x6f => "3DUP".to_string(),
            0x70 => "2OVER".to_string(),
            0x71 => "2ROT".to_string(),
            0x72 => "2SWAP".to_string(),
            0x73 => "IFDUP".to_string(),
            0x74 => "DEPTH".to_string(),
            0x75 => "DROP".to_string(),
            0x76 => "DUP".to_string(),
            0x77 => "NIP".to_string(),
            0x78 => "OVER".to_string(),
            0x79 => "PICK".to_string(),
            0x7a => "ROLL".to_string(),
            0x7b => "ROT".to_string(),
            0x7c => "SWAP".to_string(),
            0x7d => "TUCK".to_string(),            
            //0x7e => "CAT".to_string(),
            //0x7f => "SUBSTR".to_string(),
            //0x80 => "LEFT".to_string(),
            //0x81 => "RIGHT".to_string(),
            0x82 => "SIZE".to_string(),
            //0x83 => "INVERT".to_string(),
            //0x84 => "AND".to_string(),
            //0x85 => "OR".to_string(),
            //0x86 => "XOR".to_string(),
            0x87 => "EQUAL".to_string(),
            0x88 => "EQUALVERIFY".to_string(),            
            0x89 => "RESERVED1".to_string(),            
            0x8a => "RESERVED2".to_string(),            
            0x8b => "1ADD".to_string(),            
            0x8c => "1SUB".to_string(),            
            //0x8d => "2MUL".to_string(),            
            //0x8e => "2DIV".to_string(),            
            0x8f => "NEGATE".to_string(),            
            0x90 => "ABS".to_string(),            
            0x91 => "NOT".to_string(),            
            0x92 => "0NOTEQUAL".to_string(),            
            0x93 => "ADD".to_string(),            
            0x94 => "SUB".to_string(),            
            //0x95 => "MUL".to_string(),            
            //0x96 => "DIV".to_string(),            
            //0x97 => "MOD".to_string(),            
            //0x98 => "LSHIFT".to_string(),            
            //0x99 => "RSHIFT".to_string(),            
            0x9a => "BOOLAND".to_string(),            
            0x9b => "BOOLOR".to_string(),            
            0x9c => "NUMEQUAL".to_string(),            
            0x9d => "NUMEQUALVERIFY".to_string(),            
            0x9e => "NUMNOTEQUAL".to_string(),            
            0x9f => "LESSTHAN".to_string(),            
            0xa0 => "GREATERTHAN".to_string(),
            0xa1 => "LESSTHANOREQUAL".to_string(),
            0xa2 => "GREATHERTHANOREQUAL".to_string(),
            0xa3 => "MIN".to_string(),
            0xa4 => "MAX".to_string(),
            0xa5 => "WITHIN".to_string(),
            0xa6 => "RIPEMD160".to_string(),
            0xa7 => "SHA1".to_string(),
            0xa8 => "SHA256".to_string(),
            0xa9 => "HASH160".to_string(),
            0xaa => "HASH256".to_string(),
            0xab => "CODESEPARATOR".to_string(),
            0xac => "CHECKSIG".to_string(),
            0xad => "CHECKSIGVERIFY".to_string(),
            0xae => "CHECKMULTISIG".to_string(),
            0xaf => "CHECKMULTISIGVERIFY".to_string(),
            0xb0 => "NOP1".to_string(),
            0xb1 => "CHECKLOCKTIMEVERIFY".to_string(),
            0xb2 => "CHECKSEQUENCEVERIFY".to_string(),
            0xb3 => "NOP4".to_string(),
            0xb4 => "NOP5".to_string(),
            0xb5 => "NOP6".to_string(),
            0xb6 => "NOP7".to_string(),
            0xb7 => "NOP8".to_string(),
            0xb8 => "NOP9".to_string(),
            0xb9 => "NOP10".to_string(),
            0xba => "CHECKSIGADD".to_string(),
            0xbb..=0xfe => format!("RETURN_{}", byte),
            0xff => "INVALIDOPCODE".to_string(),            
            _ => format!("UNKNOWN({})", byte),
        };
        if debug {
            println!("{}", opcode.to_string());
        }
        opcodes.push(opcode.to_string());        
        index += 1;
    }

    opcodes.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    
    //#[test]
    fn test_script_to_optcodes() {
        let script: [u8; 9] = [0x4c, 0x05, 0x31, 0x32, 0x33, 0x34, 0x35, 0x6a, 0x67];
        let opcodes = script_to_opcodes(&script);
        assert_eq!(opcodes, "PUSHDATA(3132333435) RETURN ELSE".to_string());
        println!("{}",opcodes);
    }

    #[test]
    fn test_genesis_output() {
        let hex_string = "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac";
        let bytes = hex::decode(hex_string).expect("Failed to decode hex string");        
        let opcodes = script_to_opcodes(&bytes);
        // assert_eq!(opcodes, "PUSHDATA(3132333435) RETURN ELSE".to_string());
        println!("{}",opcodes);
    }
    
    //#[test]
    fn test_script_output() {
        let hex_string = "76a914cbc20a7664f2f69e5355aa427045bc15e7c6c77288ac";
        let bytes = hex::decode(hex_string).expect("Failed to decode hex string");        
        let opcodes = script_to_opcodes(&bytes);
        assert_eq!(opcodes, "DUP HASH160 <cbc20a7664f2f69e5355aa427045bc15e7c6c772> EQUALVERIFY CHECKSIG".to_string());
        println!("{}",opcodes);
    }
}

