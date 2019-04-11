use crate::crypto::Encryption;
use blake2b_simd::Params;
use libsm::sm3;
use std::{fmt, marker};
use tiny_keccak;
use types::{Address, H256};

const BLAKE2BKEY: &str = "CryptapeCryptape";

/// Create secret Key
pub trait CreateKey
where
    Self: marker::Sized,
{
    /// Private key
    type PrivKey;
    /// Public key
    type PubKey;
    /// Error
    type Error;

    /// Create a pair from secret key
    fn from_privkey(privkey: Self::PrivKey) -> Result<Self, Self::Error>;
    /// Generate a pair of public and private keys
    fn gen_keypair() -> Self;
    /// Get private key
    fn privkey(&self) -> &Self::PrivKey;
    /// Get public key
    fn pubkey(&self) -> &Self::PubKey;
    /// Get address of the public key
    fn address(&self) -> Address;
}

/// Hashable for some type
pub trait Hashable {
    /// Calculate crypt HASH of this object.
    fn crypt_hash(&self, encryption: Encryption) -> H256 {
        let mut result = [0u8; 32];
        match encryption {
            Encryption::Secp256k1 => self.sha3_crypt_hash_into(&mut result),
            Encryption::Ed25519 => self.blake2b_crypt_hash_into(&mut result),
            Encryption::Sm2 => self.sm3_crypt_hash_into(&mut result),
        }
        H256(result)
    }

    /// Calculate crypt HASH of this object and place result into dest, use sha3
    fn sha3_crypt_hash_into(&self, dest: &mut [u8]);

    /// Calculate crypt HASH of this object and place result into dest, use blake2b
    fn blake2b_crypt_hash_into(&self, dest: &mut [u8]);

    /// Calculate crypt HASH of this object and place result into dest, use sm3
    fn sm3_crypt_hash_into(&self, dest: &mut [u8]);
}

impl<T> Hashable for T
where
    T: AsRef<[u8]>,
{
    fn sha3_crypt_hash_into(&self, dest: &mut [u8]) {
        let input: &[u8] = self.as_ref();
        tiny_keccak::Keccak::keccak256(input, dest);
    }

    fn blake2b_crypt_hash_into(&self, dest: &mut [u8]) {
        let input: &[u8] = self.as_ref();

        dest.copy_from_slice(
            Params::new()
                .hash_length(dest.len())
                .key(BLAKE2BKEY.as_bytes())
                .to_state()
                .update(input)
                .finalize()
                .as_ref(),
        );
    }

    fn sm3_crypt_hash_into(&self, dest: &mut [u8]) {
        let input: &[u8] = self.as_ref();
        dest.copy_from_slice(sm3::hash::Sm3Hash::new(input).get_hash().as_ref());
    }
}

/// Error of create secret key
#[derive(Debug)]
pub enum Error {
    /// Invalid private key
    InvalidPrivKey,
    /// Invalid public key
    InvalidPubKey,
    /// Invalid signature
    InvalidSignature,
    /// Invalid message
    InvalidMessage,
    /// Recover error
    RecoverError,
    /// Io error
    Io(::std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match *self {
            Error::InvalidPrivKey => "Invalid secret".into(),
            Error::InvalidPubKey => "Invalid public".into(),
            Error::InvalidSignature => "Invalid EC signature".into(),
            Error::InvalidMessage => "Invalid AES message".into(),
            Error::RecoverError => "Recover Error".into(),
            Error::Io(ref err) => format!("I/O error: {}", err),
        };
        f.write_fmt(format_args!("Crypto error ({})", msg))
    }
}

impl From<::secp256k1::Error> for Error {
    fn from(e: ::secp256k1::Error) -> Error {
        match e {
            ::secp256k1::Error::InvalidMessage => Error::InvalidMessage,
            ::secp256k1::Error::InvalidPublicKey => Error::InvalidPubKey,
            ::secp256k1::Error::InvalidSecretKey => Error::InvalidPrivKey,
            _ => Error::InvalidSignature,
        }
    }
}

impl From<::std::io::Error> for Error {
    fn from(err: ::std::io::Error) -> Error {
        Error::Io(err)
    }
}
