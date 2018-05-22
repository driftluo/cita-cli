mod crypto_trait;
mod cita_secp256k1;
#[cfg(feature = "blake2b_hash")]
mod cita_ed25519;

use std::str::FromStr;

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
pub fn sha3_pubkey_to_address(pubkey: &Sha3PubKey) -> Address {
    Address::from(pubkey.crypt_hash(false))
}

/// Generate Address from public key, blake2b
#[cfg(feature = "blake2b_hash")]
pub fn blake2b_pubkey_to_address(pubkey: &Blake2bPubKey) -> Address {
    Address::from(pubkey.crypt_hash(true))
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
    /// create private key
    pub fn from_privkey(hex: &str) -> Result<Self, String> {
        if hex.len() > 300 {
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
