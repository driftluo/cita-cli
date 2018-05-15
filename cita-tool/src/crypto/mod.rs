mod crypto_trait;
mod cita_secp256k1;

pub use self::crypto_trait::{CreateKey, Error, Hashable};
pub use self::cita_secp256k1::{sign, KeyPair, Signature};
use types::{Address, H256, H512};

/// Private key
pub type PrivKey = H256;
/// Public key
pub type PubKey = H512;
/// Sign Message
pub type Message = H256;

/// Generate Address from public key
pub fn pubkey_to_address(pubkey: &PubKey) -> Address {
    Address::from(pubkey.crypt_hash())
}
