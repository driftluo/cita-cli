use std::{fmt, marker};
use types::{Address, H256};
use sha3::sha3_256;
#[cfg(feature = "blake2b_hash")]
use blake2b::blake2b;

#[cfg(feature = "blake2b_hash")]
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
    fn crypt_hash(&self, blake2b: bool) -> H256 {
        let mut result = [0u8; 32];
        if blake2b {
            #[cfg(feature = "blake2b_hash")]
            self.blake2b_crypt_hash_into(&mut result);
        } else {
            self.sha3_crypt_hash_into(&mut result);
        }
        H256(result)
    }

    /// Calculate crypt HASH of this object and place result into dest, use sha3
    fn sha3_crypt_hash_into(&self, dest: &mut [u8]);

    /// Calculate crypt HASH of this object and place result into dest, use blake2b
    #[cfg(feature = "blake2b_hash")]
    fn blake2b_crypt_hash_into(&self, dest: &mut [u8]);
}

impl<T> Hashable for T
where
    T: AsRef<[u8]>,
{
    fn sha3_crypt_hash_into(&self, dest: &mut [u8]) {
        let input: &[u8] = self.as_ref();

        unsafe {
            sha3_256(dest.as_mut_ptr(), dest.len(), input.as_ptr(), input.len());
        }
    }

    #[cfg(feature = "blake2b_hash")]
    fn blake2b_crypt_hash_into(&self, dest: &mut [u8]) {
        let input: &[u8] = self.as_ref();

        unsafe {
            blake2b(
                dest.as_mut_ptr(),
                dest.len(),
                input.as_ptr(),
                input.len(),
                BLAKE2BKEY.as_bytes().as_ptr(),
                BLAKE2BKEY.len(),
            );
        }
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
