use crypto::{pubkey_to_address, CreateKey, Error, Message, PubKey, Sha3PrivKey, Sha3PubKey};
use hex::encode;
use rand::thread_rng;
use secp256k1::{
    key::{self, SecretKey},
    Message as SecpMessage, RecoverableSignature, RecoveryId, Secp256k1,
};
use std::ops::{Deref, DerefMut};
use std::{fmt, mem};
use types::{Address, H256};

lazy_static! {
    pub static ref SECP256K1: Secp256k1 = Secp256k1::new();
}

const SIGNATURE_BYTES_LEN: usize = 65;

/// Sha3 key pair
#[derive(Default)]
pub struct Sha3KeyPair {
    privkey: Sha3PrivKey,
    pubkey: Sha3PubKey,
}

impl fmt::Display for Sha3KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        writeln!(f, "privkey:  {}", encode(self.privkey.0.to_vec()))?;
        writeln!(f, "pubkey:  {}", encode(self.pubkey.0.to_vec()))?;
        write!(f, "address:  {}", encode(self.address().0.to_vec()))
    }
}

impl CreateKey for Sha3KeyPair {
    type PrivKey = Sha3PrivKey;
    type PubKey = Sha3PubKey;
    type Error = Error;

    /// Create a pair from secret key
    fn from_privkey(privkey: Self::PrivKey) -> Result<Self, Self::Error> {
        let context = &SECP256K1;
        let s: key::SecretKey = key::SecretKey::from_slice(context, &privkey.0[..])?;
        let pubkey = key::PublicKey::from_secret_key(context, &s)?;
        let serialized = pubkey.serialize_vec(context, false);

        let mut pubkey = Sha3PubKey::default();
        pubkey.0.copy_from_slice(&serialized[1..65]);

        let keypair = Sha3KeyPair {
            privkey: privkey,
            pubkey: pubkey,
        };

        Ok(keypair)
    }

    fn gen_keypair() -> Self {
        let context = &SECP256K1;
        let (s, p) = context.generate_keypair(&mut thread_rng()).unwrap();
        let serialized = p.serialize_vec(context, false);
        let mut privkey = Sha3PrivKey::default();
        privkey.0.copy_from_slice(&s[0..32]);
        let mut pubkey = Sha3PubKey::default();
        pubkey.0.copy_from_slice(&serialized[1..65]);
        Sha3KeyPair {
            privkey: privkey,
            pubkey: pubkey,
        }
    }

    fn privkey(&self) -> &Self::PrivKey {
        &self.privkey
    }

    fn pubkey(&self) -> &Self::PubKey {
        &self.pubkey
    }

    fn address(&self) -> Address {
        pubkey_to_address(&PubKey::Sha3(self.pubkey))
    }
}

/// Signature
pub struct Sh3Signature(pub [u8; 65]);

impl Sh3Signature {
    /// Get a slice into the 'r' portion of the data.
    pub fn r(&self) -> &[u8] {
        &self.0[0..32]
    }

    /// Get a slice into the 's' portion of the data.
    pub fn s(&self) -> &[u8] {
        &self.0[32..64]
    }

    /// Get the recovery byte.
    pub fn v(&self) -> u8 {
        self.0[64]
    }

    /// Create a signature object from the sig.
    pub fn from_rsv(r: &H256, s: &H256, v: u8) -> Sh3Signature {
        let mut sig = [0u8; 65];
        sig[0..32].copy_from_slice(&r.0);
        sig[32..64].copy_from_slice(&s.0);
        sig[64] = v;
        Sh3Signature(sig)
    }

    /// Check if this is a "low" signature.
    pub fn is_low_s(&self) -> bool {
        H256::from_slice(self.s())
            <= "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0".into()
    }

    /// Check if each component of the signature is in range.
    pub fn is_valid(&self) -> bool {
        self.v() <= 1
            && H256::from_slice(self.r())
                < "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141".into()
            && H256::from_slice(self.r()) >= 1.into()
            && H256::from_slice(self.s())
                < "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141".into()
            && H256::from_slice(self.s()) >= 1.into()
    }

    /// Recover public key
    pub fn recover(&self, message: &Message) -> Result<Sha3PubKey, Error> {
        let context = &SECP256K1;
        let rsig = RecoverableSignature::from_compact(
            context,
            &self.0[0..64],
            RecoveryId::from_i32(self.0[64] as i32)?,
        )?;
        let public = context.recover(&SecpMessage::from_slice(&message.0[..])?, &rsig)?;
        let serialized = public.serialize_vec(context, false);

        let mut pubkey = Sha3PubKey::default();
        pubkey.0.copy_from_slice(&serialized[1..65]);
        Ok(pubkey)
    }
}

/// Sign data with Sha3
pub fn sha3_sign(privkey: &Sha3PrivKey, message: &Message) -> Result<Sh3Signature, Error> {
    let context = &SECP256K1;
    // no way to create from raw byte array.
    let sec: &SecretKey = unsafe { mem::transmute(privkey) };
    let s = context.sign_recoverable(&SecpMessage::from_slice(&message.0[..])?, sec)?;
    let (rec_id, data) = s.serialize_compact(context);
    let mut data_arr = [0; 65];

    // no need to check if s is low, it always is
    data_arr[0..64].copy_from_slice(&data[0..64]);
    data_arr[64] = rec_id.to_i32() as u8;
    Ok(Sh3Signature(data_arr))
}

impl Deref for Sh3Signature {
    type Target = [u8; 65];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Sh3Signature {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl PartialEq for Sh3Signature {
    fn eq(&self, rhs: &Self) -> bool {
        self.0[..] == rhs.0[..]
    }
}

impl Eq for Sh3Signature {}

impl fmt::Debug for Sh3Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_struct("Signature")
            .field("r", &encode(self.0[0..32].to_vec()))
            .field("s", &encode(self.0[32..64].to_vec()))
            .field("v", &encode(self.0[64..65].to_vec()))
            .finish()
    }
}

impl fmt::Display for Sh3Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", encode(self.to_vec()))
    }
}

impl Default for Sh3Signature {
    fn default() -> Self {
        Sh3Signature([0; 65])
    }
}

impl<'a> From<&'a [u8]> for Sh3Signature {
    fn from(slice: &'a [u8]) -> Sh3Signature {
        assert_eq!(slice.len(), SIGNATURE_BYTES_LEN);
        let mut bytes = [0u8; 65];
        bytes.copy_from_slice(&slice[..]);
        Sh3Signature(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recover() {
        let keypair = Sha3KeyPair::gen_keypair();
        let msg = Message::default();
        let sig = sha3_sign(keypair.privkey(), &msg).unwrap();
        assert_eq!(keypair.pubkey(), &sig.recover(&msg).unwrap());
    }
}
