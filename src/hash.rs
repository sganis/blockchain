use ripemd::{Ripemd160, Digest};
use sha2::{Sha256, Digest as dig};
use bs58;
use hex::FromHex;

pub fn compute_txid(data: &[u8]) -> Vec<u8> {
    let hash1 = Sha256::digest(data);
    let hash2 = Sha256::digest(&hash1);
    hash2.to_vec() 
}

pub fn hash160(data: &[u8]) -> Vec<u8> {
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    let result = hasher.finalize();
    result[..].to_vec()
}

pub fn hash256(data: &[u8]) -> [u8; 32] {
    let first_hash = Sha256::digest(data);
    let result = Sha256::digest(&first_hash);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

pub fn reverse(data: &[u8]) -> [u8; 32] {
    let reversed: Vec<u8> = data.iter().rev().cloned().collect();
    let mut r = [0u8; 32];
    r.copy_from_slice(&reversed);
    r
}

pub fn pkey_to_address(pkey: &[u8]) -> Vec<u8> {
    let hash_ripemd160 = hash160(pkey);
    let hash_sha256 = hash256(&hash_ripemd160);    
    let decoded = bs58::decode(hash_sha256).into_vec().unwrap();
    decoded
}



#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hash() {
        let pkey = b"045da87c7b825c75ca17ade8bb5cdbcd27af4ce97373aa9848c0c84693ca857cf379e14c2ce61ea2aaee9450d0939e21bd26894aa6dcc808656fa9974dc296589e";
        //let h = pkey_to_address(pkey);
        //println!("address: {:?}", h);
    }

    #[test]
    fn test_txid() {
        let txid_expected = "169e1e83e930853391bc6f35f605c6754cfead57cf8387639d3b4096c54f18f4";
        let tx = "0100000001c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704000000004847304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac4622082221a8768d1d0901ffffffff0200ca9a3b00000000434104ae1a62fe09c5f51b13905f07f06b99a2f7159b2225f374cd378d71302fa28414e7aab37397f554a7df5f142c21c1b7303b8a0626f1baded5c72a704f7e6cd84cac00286bee0000000043410411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3ac00000000";
        let bytes: Vec<u8> = Vec::from_hex(tx).unwrap();
        let txid = hash256(&bytes);
        let txid_hex = hex::encode(&txid); 
        assert!(txid_hex == txid_expected);

        let reversed_expected = "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16";
        let reversed = reverse(&txid);
        let reversed_hex: String = hex::encode(&reversed);
        assert!(reversed_hex == reversed_expected);

    }
    
}

