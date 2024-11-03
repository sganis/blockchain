use ripemd::{Ripemd160, Digest};
use sha2::{Sha256, Digest as dig};
use bs58;

pub fn compute_txid(data: &[u8]) -> Vec<u8> {
    let hash1 = Sha256::digest(data);
    let hash2 = Sha256::digest(&hash1);
    hash2.to_vec() 
}

fn hash160(data: &[u8]) -> Vec<u8> {
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    let result = hasher.finalize();
    result[..].to_vec()
}

fn hash256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.update("String data");
    let hash = hasher.finalize();
    hash[..].to_vec()
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
        let h = pkey_to_address(pkey);
        println!("address: {:?}", h);
    }

    
}

