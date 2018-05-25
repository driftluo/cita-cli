mod crypto_trait;
mod cita_secp256k1;
#[cfg(feature = "blake2b_hash")]
mod cita_ed25519;

use std::str::FromStr;
use std::fmt;
use hex::encode;

pub use self::crypto_trait::{CreateKey, Error, Hashable};
pub use self::cita_secp256k1::{Sha3KeyPair, Signature, sha3_sign};
use types::{Address, H256, H512};
#[cfg(feature = "blake2b_hash")]
pub use self::cita_ed25519::{Blake2bKeyPair, Blake2bSignature, blake2b_sign};

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

/// Generate Address from public key, sha3
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

impl PrivateKey {
    /// Create private key
    pub fn from_str(hex: &str) -> Result<Self, String> {
        if hex.len() > 65 {
            #[cfg(feature = "blake2b_hash")]
            let private_key = PrivateKey::Blake2b(Blake2bPrivKey::from_str(hex)
                .map_err(|err| format!("{}", err))?);
            #[cfg(not(feature = "blake2b_hash"))]
            let private_key = PrivateKey::Null;
            Ok(private_key)
        } else {
            Ok(PrivateKey::Sha3(Sha3PrivKey::from_str(hex)
                .map_err(|err| format!("{}", err))?))
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

impl PubKey {
    /// Create pubkey key
    pub fn from_str(hex: &str) -> Result<Self, String> {
        if hex.len() < 65 {
            #[cfg(feature = "blake2b_hash")]
            let private_key =
                PubKey::Blake2b(Blake2bPubKey::from_str(hex).map_err(|err| format!("{}", err))?);
            #[cfg(not(feature = "blake2b_hash"))]
            let private_key = PubKey::Null;
            Ok(private_key)
        } else {
            Ok(PubKey::Sha3(Sha3PubKey::from_str(hex)
                .map_err(|err| format!("{}", err))?))
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

    /// New from private key
    pub fn from_str(private_key: &str) -> Result<Self, String> {
        match PrivateKey::from_str(private_key)? {
            PrivateKey::Sha3(private) => Ok(KeyPair::Sha3(Sha3KeyPair::from_privkey(private)
                .map_err(|err| format!("{}", err))?)),
            #[cfg(feature = "blake2b_hash")]
            PrivateKey::Blake2b(private) => {
                Ok(KeyPair::Blake2b(Blake2bKeyPair::from_privkey(private)
                    .map_err(|err| format!("{}", err))?))
            }
            PrivateKey::Null => Ok(KeyPair::Null),
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
