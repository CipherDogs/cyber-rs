use bech32;
use bip39::{Language, Mnemonic, Seed};
use hdwallet::{DefaultKeyChain, ExtendedPrivKey, KeyChain};
use ripemd160::Ripemd160;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

const PUBLIC_KEY_LENGTH: usize = 33;

/// An account possessing a private key. `PrivateKeyAccount` is tied to an address and can sign
pub struct PrivateKeyWallet(SecretKey);

impl PrivateKeyWallet {
    pub fn to_secret_key(&self) -> &SecretKey {
        &self.0
    }

    pub fn from_key(sk: SecretKey) -> PrivateKeyWallet {
        PrivateKeyWallet(sk)
    }

    pub fn from_seed(phrase: String, path: Option<String>) -> PrivateKeyWallet {
        let mnemonic = Mnemonic::from_phrase(phrase.as_str(), Language::English)
            .expect("Failed to create mnemonic phrase");
        let seed = Seed::new(&mnemonic, "");
        let seed_bytes = seed.as_bytes();

        let master_key = ExtendedPrivKey::with_seed(seed_bytes).unwrap();
        let key_chain = DefaultKeyChain::new(master_key);

        let chain_path = match path {
            Some(s) => s,
            None => "m/44'/118'/0'/0/0".to_string(),
        };
        let child_key = key_chain
            .derive_private_key(chain_path.as_str().into())
            .unwrap();

        let private_key = child_key.0.private_key;

        PrivateKeyWallet(private_key)
    }
}

/// An account possessing a public key. Using `PublicKeyWallet` you can get the address.
pub struct PublicKeyWallet([u8; PUBLIC_KEY_LENGTH]);

impl PublicKeyWallet {
    pub fn to_bytes(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        &self.0
    }

    pub fn to_string(&self) -> String {
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_slice(&self.0).expect("Invalid bytes in the public key");
        public_key.to_string()
    }

    pub fn from_key(pk: [u8; PUBLIC_KEY_LENGTH]) -> PublicKeyWallet {
        PublicKeyWallet(pk)
    }

    pub fn from_private_key(key: &SecretKey) -> PublicKeyWallet {
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &key);

        PublicKeyWallet(public_key.serialize())
    }

    pub fn to_address(&self) -> String {
        let mut sha256 = Sha256::new();
        sha256.update(self.0.to_vec());
        let s = sha256.finalize();

        let mut ripemd = Ripemd160::new();
        ripemd.update(s);
        let r = ripemd.finalize();

        let five_bit_r =
            bech32::convert_bits(&r, 8, 8, true).expect("Unsuccessful bech32::convert_bits call");

        subtle_encoding::bech32::encode("cyber", five_bit_r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_seed(phrase: String) -> String {
        let sk = PrivateKeyWallet::from_seed(phrase, None);
        let pk = PublicKeyWallet::from_private_key(sk.to_secret_key());
        pk.to_address()
    }

    #[test]
    fn test_private_from_seed() {
        assert_eq!(
            from_seed(String::from(
                "soap weird dutch gap region blossom antique economy legend loan ugly boring"
            )),
            String::from("cyber1gw824ephm676c93ur3zgefctj3frvupc4tmn3v")
        );

        assert_eq!(
            from_seed(String::from(
                "tomorrow few flag walnut dwarf kiwi close stick sniff satoshi chest vacuum"
            )),
            String::from("cyber1q652n3ylk27rxkkxhj8d0ty3txcm2pjnn4q46r")
        );
    }
}
