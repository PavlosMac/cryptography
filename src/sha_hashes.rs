
pub mod sha_hashes {
    use hmac::{Hmac, Mac};
    use sha2::{Sha224, Sha256, Digest};
    use sha3::{Sha3_384};

    pub fn _sha_224(input: &str) -> String {
        let mut hasher = Sha224::new();
        hasher.update(input.as_bytes());
        let result = hasher.finalize();
        let h = hex::encode(&result);
        h
    }

    pub fn _sha_384(i: &str) -> String {
        let mut hasher = Sha3_384::new();
        hasher.update(i.as_bytes());
        let result = hasher.finalize();
        let h = hex::encode(&result);
        h
    }   

    pub fn _hmac_sha256(msg: String, key: String) -> String {
        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("it");        
        mac.update(msg.as_bytes());

        let r = mac.finalize();

        let as_bytes: [u8; 32] = r.into_bytes().as_slice().try_into().expect("msg");

        let h = hex::encode(&as_bytes);
        h
    }
}

#[cfg(test)]
mod tests {
    use crate::sha_hashes::sha_hashes::_sha_224;
    use crate::sha_hashes::sha_hashes::_sha_384;
    use crate::sha_hashes::sha_hashes::_hmac_sha256;

    #[test]
    fn test_sha_224() {
        let r = _sha_224("hello");    
        assert_eq!(r, "ea09ae9cc6768c50fcee903ed054556e5bfc8347907f12598aa24193");
    }

    #[test]
    fn test_sha_338() {
        let r = _sha_384("hello");    
        assert_eq!(r, "720aea11019ef06440fbf05d87aa24680a2153df3907b23631e7177ce620fa1330ff07c0fddee54699a4c3ee0ee9d887");
    }

    // HMAC is used for message authenticity, message integrity and sometimes for key derivation.
    // The results MAC code is a message hash mixed with a secret key. It has the cryptographic properties of hashes: irreversible, collision resistant, etc.
    #[test]
    fn test_hmac_sha256() {
        let str = _hmac_sha256(String::from("sample message"), String::from("12345"));

        assert_eq!(str, "ee40ca7bc90df844d2f5b5667b27361a2350fad99352d8a6ce061c69e41e5d32");
    }
}
