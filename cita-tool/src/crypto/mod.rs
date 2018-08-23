#[cfg(feature = "blake2b_hash")]
mod cita_ed25519;
mod cita_secp256k1;
mod crypto_trait;

use hex::encode;
use std::fmt;
use std::str::FromStr;

#[cfg(feature = "blake2b_hash")]
pub use self::cita_ed25519::{blake2b_sign, Blake2bKeyPair, Blake2bSignature};
pub use self::cita_secp256k1::{sha3_sign, Sh3Signature, Sha3KeyPair};
pub use self::crypto_trait::{CreateKey, Error, Hashable};
use types::{traits::LowerHex, Address, H256, H512};

/// Sha3 Private key
pub type Sha3PrivKey = H256;
/// Sha3 Public key
pub type Sha3PubKey = H512;
/// Sign Message
pub type Message = H256;

/// blake2b Private key
#[cfg(feature = "blake2b_hash")]
pub type Blake2bPrivKey = H512;
/// blake2b Public key
#[cfg(feature = "blake2b_hash")]
pub type Blake2bPubKey = H256;

/// Generate Address from public key
pub fn pubkey_to_address(pubkey: &PubKey) -> Address {
    match pubkey {
        PubKey::Sha3(pubkey) => Address::from(pubkey.crypt_hash(false)),
        #[cfg(feature = "blake2b_hash")]
        PubKey::Blake2b(pubkey) => Address::from(pubkey.crypt_hash(true)),
        PubKey::Null => Address::default(),
    }
}

/// Private key of sha3 and blake2b
pub enum PrivateKey {
    /// sha3
    Sha3(Sha3PrivKey),
    /// blake2b
    #[cfg(feature = "blake2b_hash")]
    Blake2b(Blake2bPrivKey),
    /// null
    Null,
}

impl FromStr for PrivateKey {
    type Err = String;

    /// Create private key
    fn from_str(hex: &str) -> Result<Self, Self::Err> {
        if hex.len() > 65 {
            #[cfg(feature = "blake2b_hash")]
            {
                let private_key = PrivateKey::Blake2b(
                    Blake2bPrivKey::from_str(hex).map_err(|err| format!("{}", err))?,
                );
                return Ok(private_key);
            }

            #[cfg(not(feature = "blake2b_hash"))]
            Err(
                "The current version does not support 512-byte private keys, \
                 should build with feature blake2b_hash"
                    .to_string(),
            )
        } else {
            Ok(PrivateKey::Sha3(
                Sha3PrivKey::from_str(hex).map_err(|err| format!("{}", err))?,
            ))
        }
    }
}

impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match *self {
            PrivateKey::Sha3(private_key) => encode(private_key.to_vec()),
            #[cfg(feature = "blake2b_hash")]
            PrivateKey::Blake2b(private_key) => encode(private_key.to_vec()),
            PrivateKey::Null => "".to_string(),
        };
        write!(f, "{}", msg)
    }
}

/// Pubkey of sha3 and blake2b
pub enum PubKey {
    /// sha3
    Sha3(Sha3PubKey),
    /// blake2b
    #[cfg(feature = "blake2b_hash")]
    Blake2b(Blake2bPubKey),
    /// null
    Null,
}

impl FromStr for PubKey {
    type Err = String;

    /// Create pubkey key
    fn from_str(hex: &str) -> Result<Self, Self::Err> {
        if hex.len() < 65 {
            #[cfg(feature = "blake2b_hash")]
            {
                let private_key = PubKey::Blake2b(
                    Blake2bPubKey::from_str(hex).map_err(|err| format!("{}", err))?,
                );
                return Ok(private_key);
            }

            #[cfg(not(feature = "blake2b_hash"))]
            Err(
                "The current version does not support 256-byte public keys, \
                 should build with feature blake2b_hash"
                    .to_string(),
            )
        } else {
            Ok(PubKey::Sha3(
                Sha3PubKey::from_str(hex).map_err(|err| format!("{}", err))?,
            ))
        }
    }
}

impl fmt::Display for PubKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match *self {
            PubKey::Sha3(pubkey) => encode(pubkey.to_vec()),
            #[cfg(feature = "blake2b_hash")]
            PubKey::Blake2b(pubkey) => encode(pubkey.to_vec()),
            PubKey::Null => "".to_string(),
        };
        write!(f, "{}", msg)
    }
}

/// key pair of sha3 and blake2b
pub enum KeyPair {
    /// sha3
    Sha3(Sha3KeyPair),
    /// blake2b
    #[cfg(feature = "blake2b_hash")]
    Blake2b(Blake2bKeyPair),
    /// null
    Null,
}

impl KeyPair {
    /// Create new key pair
    pub fn new(blake2b: bool) -> Self {
        if blake2b {
            #[cfg(feature = "blake2b_hash")]
            let key_pair = KeyPair::Blake2b(Blake2bKeyPair::gen_keypair());

            #[cfg(not(feature = "blake2b_hash"))]
            let key_pair = KeyPair::Null;

            key_pair
        } else {
            KeyPair::Sha3(Sha3KeyPair::gen_keypair())
        }
    }

    /// Get private key
    pub fn privkey(&self) -> PrivateKey {
        match self {
            KeyPair::Sha3(key_pair) => PrivateKey::Sha3(*key_pair.privkey()),
            #[cfg(feature = "blake2b_hash")]
            KeyPair::Blake2b(key_pair) => PrivateKey::Blake2b(*key_pair.privkey()),
            KeyPair::Null => PrivateKey::Null,
        }
    }

    /// Get pubkey
    pub fn pubkey(&self) -> PubKey {
        match self {
            KeyPair::Sha3(key_pair) => PubKey::Sha3(*key_pair.pubkey()),
            #[cfg(feature = "blake2b_hash")]
            KeyPair::Blake2b(key_pair) => PubKey::Blake2b(*key_pair.pubkey()),
            KeyPair::Null => PubKey::Null,
        }
    }

    /// Get Address
    pub fn address(&self) -> Address {
        match self {
            KeyPair::Sha3(private_key) => private_key.address(),
            #[cfg(feature = "blake2b_hash")]
            KeyPair::Blake2b(private_key) => private_key.address(),
            KeyPair::Null => Address::default(),
        }
    }
}

impl FromStr for KeyPair {
    type Err = String;

    /// New from private key
    fn from_str(private_key: &str) -> Result<Self, Self::Err> {
        match PrivateKey::from_str(private_key)? {
            PrivateKey::Sha3(private) => Ok(KeyPair::Sha3(
                Sha3KeyPair::from_privkey(private).map_err(|err| format!("{}", err))?,
            )),
            #[cfg(feature = "blake2b_hash")]
            PrivateKey::Blake2b(private) => Ok(KeyPair::Blake2b(
                Blake2bKeyPair::from_privkey(private).map_err(|err| format!("{}", err))?,
            )),
            PrivateKey::Null => Ok(KeyPair::Null),
        }
    }
}

/// Signature
pub enum Signature {
    /// sha3
    Sha3(Sh3Signature),
    /// blake2b
    #[cfg(feature = "blake2b_hash")]
    Blake2b(Blake2bSignature),
    /// null
    Null,
}

impl Signature {
    /// New from slice
    pub fn from(slice: &[u8]) -> Self {
        if slice.len() == 96 {
            #[cfg(feature = "blake2b_hash")]
            let key_pair = Signature::Blake2b(Blake2bSignature::from(slice));

            #[cfg(not(feature = "blake2b_hash"))]
            let key_pair = Signature::Null;

            key_pair
        } else if slice.len() == 65 {
            Signature::Sha3(Sh3Signature::from(slice))
        } else {
            Signature::Null
        }
    }

    /// Recover public key
    pub fn recover(&self, message: &Message) -> Result<PubKey, String> {
        match self {
            Signature::Sha3(sig) => Ok(sig
                .recover(message)
                .map(|pubkey| PubKey::from_str(&pubkey.lower_hex()).unwrap())
                .map_err(|_| "Can't recover to public key".to_string())?),
            #[cfg(feature = "blake2b_hash")]
            Signature::Blake2b(sig) => Ok(sig
                .recover(message)
                .map(|pubkey| PubKey::from_str(&pubkey.lower_hex()).unwrap())
                .map_err(|_| "Can't recover to public key".to_string())?),
            Signature::Null => Err("Mismatched encryption algorithm".to_string()),
        }
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match self {
            Signature::Sha3(sig) => write!(f, "{}", encode(sig.to_vec())),
            #[cfg(feature = "blake2b_hash")]
            Signature::Blake2b(sig) => write!(f, "{}", encode(sig.0[..].to_vec())),
            Signature::Null => write!(f, "null"),
        }
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;
    use KeyPair;

    #[test]
    fn generate_from_private_key() {
        let key_pair = KeyPair::from_str(
            "8ee6aa885d9598f9c4e010b659aeecfc3f113beb646166414756568ab656f0f9",
        ).unwrap();

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
    #[cfg(feature = "blake2b_hash")]
    fn blake2b_generate_from_private_key() {
        let key_pair =
            KeyPair::from_str("87c8f34545181d38666aadaeee4924e811263e05f6e2d87d75fac27ab5075915456fdf394a9c4397ec29f1a72c16d601b4ee7f08160c784877cb6941a0e177a1").unwrap();

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
