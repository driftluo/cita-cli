use crate::crypto::{
    pubkey_to_address, CreateKey, Ed25519PrivKey, Ed25519PubKey, Error, Message, PubKey,
};
use ed25519_dalek::{
    Keypair, PublicKey as EdPublicKey, SecretKey as EdSecretKey, Signature as EdSignature,
};
use hex::encode;
use rand::thread_rng;
use sha2::Sha512;
use std::fmt;
use std::ops::{Deref, DerefMut};
use types::Address;

const SIGNATURE_BYTES_LEN: usize = 96;

/// Ed25519 key pair
#[derive(Default)]
pub struct Ed25519KeyPair {
    privkey: Ed25519PrivKey,
    pubkey: Ed25519PubKey,
}

impl fmt::Display for Ed25519KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        writeln!(f, "privkey:  {}", encode(self.privkey.0.to_vec()))?;
        writeln!(f, "pubkey:  {}", encode(self.pubkey.0.to_vec()))?;
        write!(f, "address:  {}", encode(self.address().0.to_vec()))
    }
}

impl CreateKey for Ed25519KeyPair {
    type PrivKey = Ed25519PrivKey;
    type PubKey = Ed25519PubKey;
    type Error = Error;

    fn from_privkey(privkey: Self::PrivKey) -> Result<Self, Self::Error> {
        let pubkey = Ed25519PubKey::from(&privkey.0[32..]);
        Ok(Ed25519KeyPair { privkey, pubkey })
    }

    fn gen_keypair() -> Self {
        let keypair = Keypair::generate::<Sha512, _>(&mut thread_rng());
        let pubkey = keypair.public.to_bytes();
        let mut privkey = [0u8; 64];
        privkey[..32].copy_from_slice(&keypair.secret.to_bytes());
        privkey[32..].copy_from_slice(&pubkey);

        Ed25519KeyPair {
            privkey: Ed25519PrivKey::from(privkey),
            pubkey: Ed25519PubKey::from(pubkey),
        }
    }

    fn privkey(&self) -> &Self::PrivKey {
        &self.privkey
    }

    fn pubkey(&self) -> &Self::PubKey {
        &self.pubkey
    }

    fn address(&self) -> Address {
        pubkey_to_address(&PubKey::Ed25519(self.pubkey))
    }
}

/// Ed25519 signature
pub struct Ed25519Signature(pub [u8; 96]);

impl Ed25519Signature {
    /// sign area 0-64
    pub fn sig(&self) -> &[u8] {
        &self.0[0..64]
    }

    /// pub area 64-96
    pub fn pk(&self) -> &[u8] {
        &self.0[64..96]
    }

    /// Recover public key
    pub fn recover(&self, message: &Message) -> Result<Ed25519PubKey, Error> {
        let sig = self.sig();
        let pubkey = self.pk();
        EdPublicKey::from_bytes(&pubkey)
            .unwrap()
            .verify::<Sha512>(message, &EdSignature::from_bytes(&sig).unwrap())
            .map_err(|_| Error::InvalidSignature)
            .map(|_| Ed25519PubKey::from(pubkey))
    }

    /// Verify public key
    pub fn verify_public(&self, pubkey: &Ed25519PubKey, message: &Message) -> Result<bool, Error> {
        let sig = self.sig();
        let pk = self.pk();
        if pk != pubkey.as_ref() as &[u8] {
            return Err(Error::InvalidPubKey);
        }

        EdPublicKey::from_bytes(&pubkey)
            .unwrap()
            .verify::<Sha512>(message.as_ref(), &EdSignature::from_bytes(&sig).unwrap())
            .map_err(|_| Error::InvalidSignature)
            .map(|_| true)
    }
}

impl PartialEq for Ed25519Signature {
    fn eq(&self, rhs: &Self) -> bool {
        self.0[..] == rhs.0[..]
    }
}

impl Deref for Ed25519Signature {
    type Target = [u8; 96];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Ed25519Signature {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<[u8; 96]> for Ed25519Signature {
    fn from(bytes: [u8; 96]) -> Self {
        Ed25519Signature(bytes)
    }
}

impl<'a> From<&'a [u8]> for Ed25519Signature {
    fn from(slice: &'a [u8]) -> Ed25519Signature {
        assert_eq!(slice.len(), SIGNATURE_BYTES_LEN);
        let mut bytes = [0u8; 96];
        bytes.copy_from_slice(&slice[..]);
        Ed25519Signature(bytes)
    }
}

impl fmt::Display for Ed25519Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", encode(self.0[..].to_vec()))
    }
}

/// Sign data with ed25519
pub fn ed25519_sign(
    privkey: &Ed25519PrivKey,
    message: &Message,
) -> Result<Ed25519Signature, Error> {
    let secret = EdSecretKey::from_bytes(&privkey.0[..32]).unwrap();
    let public = EdPublicKey::from_bytes(&privkey.0[32..]).unwrap();
    let keypair = Keypair { secret, public };
    let sig = keypair.sign::<Sha512>(message);

    let mut ret = [0u8; 96];
    ret[0..64].copy_from_slice(&sig.to_bytes());
    ret[64..96].copy_from_slice(public.as_bytes());
    Ok(Ed25519Signature(ret))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recover() {
        let keypair = Ed25519KeyPair::gen_keypair();
        let msg = Message::default();
        let sig = ed25519_sign(keypair.privkey(), &msg).unwrap();
        assert_eq!(keypair.pubkey(), &sig.recover(&msg).unwrap());
    }
}
