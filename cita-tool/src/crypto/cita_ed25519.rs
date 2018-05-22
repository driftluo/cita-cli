use super::{Blake2bPrivKey, Blake2bPubKey, CreateKey, Error, Message, blake2b_pubkey_to_address};
use types::Address;
use std::fmt;
use hex::encode;
use sodiumoxide::crypto::sign::{gen_keypair, keypair_from_privkey, sign_detached, SecretKey};
use std::ops::{Deref, DerefMut};

/// Blake2b key pair
#[derive(Default)]
pub struct Blake2bKeyPair {
    privkey: Blake2bPrivKey,
    pubkey: Blake2bPubKey,
}

impl fmt::Display for Blake2bKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        writeln!(f, "privkey:  {}", encode(self.privkey.0.to_vec()))?;
        writeln!(f, "pubkey:  {}", encode(self.pubkey.0.to_vec()))?;
        write!(f, "address:  {}", encode(self.address().0.to_vec()))
    }
}

impl CreateKey for Blake2bKeyPair {
    type PrivKey = Blake2bPrivKey;
    type PubKey = Blake2bPubKey;
    type Error = Error;

    fn from_privkey(privkey: Self::PrivKey) -> Result<Self, Self::Error> {
        let keypair = keypair_from_privkey(privkey.as_ref());
        match keypair {
            None => Err(Error::InvalidPrivKey),
            Some((pk, sk)) => Ok(Blake2bKeyPair {
                privkey: Blake2bPrivKey::from(sk.0),
                pubkey: Blake2bPubKey::from(pk.0),
            }),
        }
    }

    fn gen_keypair() -> Self {
        let (pk, sk) = gen_keypair();
        Blake2bKeyPair {
            privkey: Blake2bPrivKey::from(sk.0),
            pubkey: Blake2bPubKey::from(pk.0),
        }
    }

    fn privkey(&self) -> &Self::PrivKey {
        &self.privkey
    }

    fn pubkey(&self) -> &Self::PubKey {
        &self.pubkey
    }

    fn address(&self) -> Address {
        blake2b_pubkey_to_address(&self.pubkey)
    }
}

/// Blake2b signature
pub struct Blake2bSignature(pub [u8; 96]);

impl Blake2bSignature {
    /// sign area 0-64
    pub fn sig(&self) -> &[u8] {
        &self.0[0..64]
    }

    /// pub area 64-96
    pub fn pk(&self) -> &[u8] {
        &self.0[64..96]
    }
}

impl PartialEq for Blake2bSignature {
    fn eq(&self, rhs: &Self) -> bool {
        &self.0[..] == &rhs.0[..]
    }
}

impl Deref for Blake2bSignature {
    type Target = [u8; 96];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Blake2bSignature {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Sign data with blake2b
pub fn blake2b_sign(
    privkey: &Blake2bPrivKey,
    message: &Message,
) -> Result<Blake2bSignature, Error> {
    let keypair = Blake2bKeyPair::from_privkey(*privkey)?;
    let secret_key = SecretKey::from_slice(privkey.as_ref()).unwrap();
    let pubkey = keypair.pubkey();
    let mut ret = [0u8; 96];
    let sig = sign_detached(message.as_ref(), &secret_key);

    ret[0..64].copy_from_slice(&sig.0[..]);
    ret[64..96].copy_from_slice(pubkey.as_ref() as &[u8]);
    Ok(Blake2bSignature(ret))
}
