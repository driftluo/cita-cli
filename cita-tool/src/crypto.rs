mod cita_ed25519;
mod cita_secp256k1;
mod cita_sm2;
mod crypto_trait;

use hex::encode;
use std::fmt;
use std::str::FromStr;

pub use self::cita_ed25519::{ed25519_sign, Ed25519KeyPair, Ed25519Signature};
pub use self::cita_secp256k1::{secp256k1_sign, Secp256k1KeyPair, Secp256k1Signature};
pub use self::cita_sm2::{sm2_sign, Sm2KeyPair, Sm2Signature};
pub use self::crypto_trait::{CreateKey, Error, Hashable};
use crate::LowerHex;
use types::{Address, H256, H512};

/// Secp256k1 Private key
pub type Secp256k1PrivKey = H256;
/// Secp256k1 Public key
pub type Secp256k1PubKey = H512;
/// Sign Message
pub type Message = H256;
/// Sm2 Private key
pub type Sm2Privkey = H256;
/// Sm2 Public key
pub type Sm2Pubkey = H512;

/// Ed25519 Private key
pub type Ed25519PrivKey = H512;
/// Ed25519 Public key
pub type Ed25519PubKey = H256;

/// Generate Address from public key
pub fn pubkey_to_address(pubkey: &PubKey) -> Address {
    match pubkey {
        PubKey::Secp256k1(pubkey) => Address::from(pubkey.crypt_hash(Encryption::Secp256k1)),
        PubKey::Ed25519(pubkey) => Address::from(pubkey.crypt_hash(Encryption::Ed25519)),
        PubKey::Sm2(pubkey) => Address::from(pubkey.crypt_hash(Encryption::Sm2)),
        PubKey::Null => Address::default(),
    }
}

/// Sign data
pub fn sign(privkey: &PrivateKey, message: &Message) -> Signature {
    match privkey {
        PrivateKey::Secp256k1(pk) => Signature::Secp256k1(secp256k1_sign(pk, message).unwrap()),
        PrivateKey::Ed25519(pk) => Signature::Ed25519(ed25519_sign(pk, message).unwrap()),
        PrivateKey::Sm2(pk) => Signature::Sm2(sm2_sign(pk, message).unwrap()),
        PrivateKey::Null => Signature::Null,
    }
}

/// Encryption enum
#[derive(Clone, Copy)]
pub enum Encryption {
    /// Secp256k1
    Secp256k1,
    /// Ed25519
    Ed25519,
    /// Sm2
    Sm2,
}

impl FromStr for Encryption {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "secp256k1" => Ok(Encryption::Secp256k1),
            "ed25519" => Ok(Encryption::Ed25519),
            "sm2" => Ok(Encryption::Sm2),
            _ => Err("Unsupported algorithm".to_string()),
        }
    }
}

impl fmt::Debug for Encryption {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match self {
            Encryption::Secp256k1 => "secp256k1",
            Encryption::Ed25519 => "ed25519",
            Encryption::Sm2 => "sm2",
        };
        write!(f, "{}", msg)
    }
}

impl fmt::Display for Encryption {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match self {
            Encryption::Secp256k1 => "secp256k1",
            Encryption::Ed25519 => "ed25519",
            Encryption::Sm2 => "sm2",
        };
        write!(f, "{}", msg)
    }
}

/// Private key of Secp256k1/Ed25519/Sm2
#[derive(Clone, Copy)]
pub enum PrivateKey {
    /// Secp256k1
    Secp256k1(Secp256k1PrivKey),
    /// Ed25519
    Ed25519(Ed25519PrivKey),
    /// Sm2
    Sm2(Sm2Privkey),
    /// null
    Null,
}

impl PrivateKey {
    /// Create private key
    pub fn from_str(hex: &str, encryption: Encryption) -> Result<Self, String> {
        match encryption {
            Encryption::Secp256k1 => Ok(PrivateKey::Secp256k1(
                Secp256k1PrivKey::from_str(hex).map_err(|err| format!("{}", err))?,
            )),
            Encryption::Ed25519 => Ok(PrivateKey::Ed25519(
                Ed25519PrivKey::from_str(hex).map_err(|err| format!("{}", err))?,
            )),
            Encryption::Sm2 => Ok(PrivateKey::Sm2(
                Sm2Privkey::from_str(hex).map_err(|err| format!("{}", err))?,
            )),
        }
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match *self {
            PrivateKey::Secp256k1(private_key) => encode(private_key.to_vec()),
            PrivateKey::Ed25519(private_key) => encode(private_key.to_vec()),
            PrivateKey::Sm2(private_key) => encode(private_key.to_vec()),
            PrivateKey::Null => "".to_string(),
        };
        write!(f, "{}", msg)
    }
}

impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match *self {
            PrivateKey::Secp256k1(private_key) => encode(private_key.to_vec()),
            PrivateKey::Ed25519(private_key) => encode(private_key.to_vec()),
            PrivateKey::Sm2(private_key) => encode(private_key.to_vec()),
            PrivateKey::Null => "".to_string(),
        };
        write!(f, "{}", msg)
    }
}

/// Pubkey of Secp256k1/Ed25519/Sm2
pub enum PubKey {
    /// sha3
    Secp256k1(Secp256k1PubKey),
    /// blake2b
    Ed25519(Ed25519PubKey),
    /// Sm2
    Sm2(Sm2Pubkey),
    /// null
    Null,
}

impl PubKey {
    /// Create pubkey key
    pub fn from_str(hex: &str, encryption: Encryption) -> Result<Self, String> {
        match encryption {
            Encryption::Secp256k1 => Ok(PubKey::Secp256k1(
                Secp256k1PubKey::from_str(hex).map_err(|err| format!("{}", err))?,
            )),
            Encryption::Ed25519 => Ok(PubKey::Ed25519(
                Ed25519PubKey::from_str(hex).map_err(|err| format!("{}", err))?,
            )),
            Encryption::Sm2 => Ok(PubKey::Sm2(
                Sm2Pubkey::from_str(hex).map_err(|err| format!("{}", err))?,
            )),
        }
    }

    /// Convert to vec
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            PubKey::Secp256k1(pk) | PubKey::Sm2(pk) => pk.to_vec(),
            PubKey::Ed25519(pk) => pk.to_vec(),
            PubKey::Null => Vec::new(),
        }
    }
}

impl fmt::Display for PubKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match *self {
            PubKey::Secp256k1(pubkey) => encode(pubkey.to_vec()),
            PubKey::Ed25519(pubkey) => encode(pubkey.to_vec()),
            PubKey::Sm2(pubkey) => encode(pubkey.to_vec()),
            PubKey::Null => "".to_string(),
        };
        write!(f, "{}", msg)
    }
}

/// key pair of Secp256k1/Ed25519/Sm2
pub enum KeyPair {
    /// Secp256k1
    Secp256k1(Secp256k1KeyPair),
    /// Ed25519
    Ed25519(Ed25519KeyPair),
    /// Sm2
    Sm2(Sm2KeyPair),
    /// null
    Null,
}

impl KeyPair {
    /// Create new key pair
    pub fn new(encryption: Encryption) -> Self {
        match encryption {
            Encryption::Secp256k1 => KeyPair::Secp256k1(Secp256k1KeyPair::gen_keypair()),
            Encryption::Ed25519 => KeyPair::Ed25519(Ed25519KeyPair::gen_keypair()),
            Encryption::Sm2 => KeyPair::Sm2(Sm2KeyPair::gen_keypair()),
        }
    }

    /// New with private key
    pub fn from_privkey(private_key: PrivateKey) -> Self {
        match private_key {
            PrivateKey::Secp256k1(pk) => {
                KeyPair::Secp256k1(Secp256k1KeyPair::from_privkey(pk).unwrap())
            }
            PrivateKey::Ed25519(pk) => KeyPair::Ed25519(Ed25519KeyPair::from_privkey(pk).unwrap()),
            PrivateKey::Sm2(pk) => KeyPair::Sm2(Sm2KeyPair::from_privkey(pk).unwrap()),
            PrivateKey::Null => KeyPair::Null,
        }
    }

    /// Get private key
    pub fn privkey(&self) -> PrivateKey {
        match self {
            KeyPair::Secp256k1(key_pair) => PrivateKey::Secp256k1(*key_pair.privkey()),
            KeyPair::Ed25519(key_pair) => PrivateKey::Ed25519(*key_pair.privkey()),
            KeyPair::Sm2(key_pair) => PrivateKey::Sm2(*key_pair.privkey()),
            KeyPair::Null => PrivateKey::Null,
        }
    }

    /// Get pubkey
    pub fn pubkey(&self) -> PubKey {
        match self {
            KeyPair::Secp256k1(key_pair) => PubKey::Secp256k1(*key_pair.pubkey()),
            KeyPair::Ed25519(key_pair) => PubKey::Ed25519(*key_pair.pubkey()),
            KeyPair::Sm2(key_pair) => PubKey::Sm2(*key_pair.pubkey()),
            KeyPair::Null => PubKey::Null,
        }
    }

    /// Get Address
    pub fn address(&self) -> Address {
        match self {
            KeyPair::Secp256k1(private_key) => private_key.address(),
            KeyPair::Ed25519(private_key) => private_key.address(),
            KeyPair::Sm2(private_key) => private_key.address(),
            KeyPair::Null => Address::default(),
        }
    }
}

impl KeyPair {
    /// New from private key
    pub fn from_str(private_key: &str, encryption: Encryption) -> Result<Self, String> {
        match PrivateKey::from_str(private_key, encryption)? {
            PrivateKey::Secp256k1(private) => Ok(KeyPair::Secp256k1(
                Secp256k1KeyPair::from_privkey(private).map_err(|err| format!("{}", err))?,
            )),
            PrivateKey::Ed25519(private) => Ok(KeyPair::Ed25519(
                Ed25519KeyPair::from_privkey(private).map_err(|err| format!("{}", err))?,
            )),
            PrivateKey::Sm2(private) => Ok(KeyPair::Sm2(
                Sm2KeyPair::from_privkey(private).map_err(|err| format!("{}", err))?,
            )),
            PrivateKey::Null => Ok(KeyPair::Null),
        }
    }
}

/// Signature
pub enum Signature {
    /// Secp256k1
    Secp256k1(Secp256k1Signature),
    /// Ed25519
    Ed25519(Ed25519Signature),
    /// Sm2
    Sm2(Sm2Signature),
    /// null
    Null,
}

impl Signature {
    /// New from slice
    pub fn from(slice: &[u8]) -> Self {
        if slice.len() == 96 {
            Signature::Ed25519(Ed25519Signature::from(slice))
        } else if slice.len() == 65 {
            Signature::Secp256k1(Secp256k1Signature::from(slice))
        } else if slice.len() == 128 {
            Signature::Sm2(Sm2Signature::from(slice))
        } else {
            Signature::Null
        }
    }

    /// Convert to vec
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Signature::Sm2(sig) => sig.to_vec(),
            Signature::Secp256k1(sig) => sig.to_vec(),
            Signature::Ed25519(sig) => sig.to_vec(),
            Signature::Null => Vec::new(),
        }
    }

    /// Recover public key
    pub fn recover(&self, message: &Message) -> Result<PubKey, String> {
        match self {
            Signature::Secp256k1(sig) => Ok(sig
                .recover(message)
                .map(|pubkey| PubKey::from_str(&pubkey.lower_hex(), Encryption::Secp256k1).unwrap())
                .map_err(|_| "Can't recover to public key".to_string())?),
            Signature::Ed25519(sig) => Ok(sig
                .recover(message)
                .map(|pubkey| PubKey::from_str(&pubkey.lower_hex(), Encryption::Ed25519).unwrap())
                .map_err(|_| "Can't recover to public key".to_string())?),
            Signature::Sm2(sig) => Ok(sig
                .recover(message)
                .map(|pubkey| PubKey::from_str(&pubkey.lower_hex(), Encryption::Sm2).unwrap())
                .map_err(|_| "Can't recover to public key".to_string())?),
            Signature::Null => Err("Mismatched encryption algorithm".to_string()),
        }
    }

    /// Verify public key
    pub fn verify_public(&self, pubkey: PubKey, message: &Message) -> Result<bool, String> {
        match (self, pubkey) {
            (Signature::Secp256k1(sig), PubKey::Secp256k1(pubkey)) => sig
                .verify_public(&pubkey, &message)
                .map_err(|e| e.to_string()),
            (Signature::Ed25519(sig), PubKey::Ed25519(pubkey)) => sig
                .verify_public(&pubkey, &message)
                .map_err(|e| e.to_string()),
            (Signature::Sm2(sig), PubKey::Sm2(pubkey)) => sig
                .verify_public(&pubkey, &message)
                .map_err(|e| e.to_string()),
            (_, _) => Ok(false),
        }
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            Signature::Secp256k1(sig) => write!(f, "{}", encode(sig.0[..].to_vec())),
            Signature::Ed25519(sig) => write!(f, "{}", encode(sig.0[..].to_vec())),
            Signature::Sm2(sig) => write!(f, "{}", encode(sig.0[..].to_vec())),
            Signature::Null => write!(f, "null"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::{Encryption, KeyPair};

    #[test]
    fn secp256k1_generate_from_private_key() {
        let key_pair = KeyPair::from_str(
            "8ee6aa885d9598f9c4e010b659aeecfc3f113beb646166414756568ab656f0f9",
            Encryption::Secp256k1,
        )
        .unwrap();

        assert_eq!(
            format!("{}", key_pair.pubkey()).as_str(),
            "e407bef7ef0a0e21395c46cc2e1ed324119783d0f4f47b676d95b23991f9065db1aa7a9099e2193160243a02168feb70c62eb8442e45c4b3542a4b3c8c8ac5bd"
        );

        assert_eq!(
            format!("{:x}", key_pair.address()).as_str(),
            "eea5c3cbb32fec85bc9b9bffa65fc027e4b1c6d5"
        );
    }

    #[test]
    fn sm2_generate_from_private_key() {
        let key_pair = KeyPair::from_str(
            "c3cf5004e9b025427cb07df7592ebbcc64bbf7285bbf50099f072fc0d06a2b20",
            Encryption::Sm2,
        )
        .unwrap();
        assert_eq!(
            format!("{}", key_pair.pubkey()).as_str(),
            "c82d3230f65335a4d07f81d5ab014c1bb606c90b2d098dadbe0bf1d9cf4618654b3a1310627703859ecf493055ea8389fcb78d9c3cf372780927e076278603ed"
        );

        assert_eq!(
            format!("{:x}", key_pair.address()).as_str(),
            "f73076eed94014142153a9556a810826ba9ae857"
        );
    }

    #[test]
    fn ed25519_generate_from_private_key() {
        let key_pair =
            KeyPair::from_str(
                "87c8f34545181d38666aadaeee4924e811263e05f6e2d87d75fac27ab5075915456fdf394a9c4397ec29f1a72c16d601b4ee7f08160c784877cb6941a0e177a1",
                Encryption::Ed25519
            ).unwrap();

        assert_eq!(
            format!("{}", key_pair.pubkey()).as_str(),
            "456fdf394a9c4397ec29f1a72c16d601b4ee7f08160c784877cb6941a0e177a1"
        );

        assert_eq!(
            format!("{:x}", key_pair.address()).as_str(),
            "5ae200f77d5c7df715f6ccb182fc5073dab1cfe9"
        );
    }
}
