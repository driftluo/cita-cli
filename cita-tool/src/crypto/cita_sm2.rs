use hex::encode;
use libsm::sm2::signature::{SigCtx, Signature as RawSignature};
use std::fmt;
use std::ops::{Deref, DerefMut};
use types::Address;

use crate::crypto::{pubkey_to_address, CreateKey, Error, Message, PubKey, Sm2Privkey, Sm2Pubkey};

const SIGNATURE_BYTES_LEN: usize = 128;

/// Sm2 key pair
pub struct Sm2KeyPair {
    privkey: Sm2Privkey,
    pubkey: Sm2Pubkey,
}

impl fmt::Display for Sm2KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        writeln!(f, "privkey:  {}", encode(self.privkey.0.to_vec()))?;
        writeln!(f, "pubkey:  {}", encode(self.pubkey.0.to_vec()))?;
        write!(f, "address:  {}", encode(self.address().0.to_vec()))
    }
}

impl CreateKey for Sm2KeyPair {
    type PrivKey = Sm2Privkey;
    type PubKey = Sm2Pubkey;
    type Error = Error;

    fn from_privkey(privkey: Self::PrivKey) -> Result<Self, Self::Error> {
        let ctx = SigCtx::new();
        ctx.load_seckey(&privkey.0)
            .map_err(|_| Error::RecoverError)
            .map(|sk| {
                let pk = ctx.pk_from_sk(&sk);
                let pubkey = Sm2Pubkey::from(&ctx.serialize_pubkey(&pk, false)[1..]);
                Sm2KeyPair { privkey, pubkey }
            })
    }

    fn gen_keypair() -> Self {
        let ctx = SigCtx::new();
        let (pk, sk) = ctx.new_keypair();
        let pubkey = Sm2Pubkey::from(&ctx.serialize_pubkey(&pk, false)[1..]);
        let privkey = Sm2Privkey::from(&ctx.serialize_seckey(&sk)[..]);
        Sm2KeyPair { privkey, pubkey }
    }

    fn privkey(&self) -> &Self::PrivKey {
        &self.privkey
    }

    fn pubkey(&self) -> &Self::PubKey {
        &self.pubkey
    }

    fn address(&self) -> Address {
        pubkey_to_address(&PubKey::Sm2(self.pubkey))
    }
}

/// Sm2 signature
pub struct Sm2Signature(pub [u8; 128]);

impl Sm2Signature {
    #[inline]
    fn r(&self) -> &[u8] {
        &self.0[0..32]
    }

    #[inline]
    fn s(&self) -> &[u8] {
        &self.0[32..64]
    }

    #[inline]
    fn pk(&self) -> &[u8] {
        &self.0[64..]
    }

    /// Recover public key
    pub fn recover(&self, message: &Message) -> Result<Sm2Pubkey, Error> {
        let ctx = SigCtx::new();
        let sig = RawSignature::new(self.r(), self.s());
        let mut pk_full = [0u8; 65];
        pk_full[0] = 4;
        pk_full[1..].copy_from_slice(self.pk());
        ctx.load_pubkey(&pk_full[..])
            .map_err(|_| Error::RecoverError)
            .and_then(|pk| {
                if ctx.verify(&message, &pk, &sig) {
                    Ok(Sm2Pubkey::from(self.pk()))
                } else {
                    Err(Error::RecoverError)
                }
            })
    }

    /// Verify public key
    pub fn verify_public(&self, pubkey: &Sm2Pubkey, message: &Message) -> Result<bool, Error> {
        let pubkey_from_sig = Sm2Pubkey::from(self.pk());
        if pubkey_from_sig == *pubkey {
            let ctx = SigCtx::new();
            let sig = RawSignature::new(self.r(), self.s());
            let mut pk_full = [0u8; 65];
            pk_full[0] = 4;
            pk_full[1..].copy_from_slice(self.pk());
            ctx.load_pubkey(&pk_full[..])
                .map_err(|_| Error::RecoverError)
                .map(|pk| ctx.verify(&message, &pk, &sig))
        } else {
            Ok(false)
        }
    }
}

/// Sign data with sm2
pub fn sm2_sign(privkey: &Sm2Privkey, message: &Message) -> Result<Sm2Signature, Error> {
    let ctx = SigCtx::new();
    ctx.load_seckey(&privkey.0)
        .map_err(|_| Error::RecoverError)
        .map(|sk| {
            let pk = ctx.pk_from_sk(&sk);
            let signature = ctx.sign(&message, &sk, &pk);
            let mut sig_bytes = [0u8; SIGNATURE_BYTES_LEN];
            let r_bytes = signature.get_r().to_bytes_be();
            let s_bytes = signature.get_s().to_bytes_be();
            sig_bytes[32 - r_bytes.len()..32].copy_from_slice(&r_bytes[..]);
            sig_bytes[64 - s_bytes.len()..64].copy_from_slice(&s_bytes[..]);
            sig_bytes[64..].copy_from_slice(&ctx.serialize_pubkey(&pk, false)[1..]);
            sig_bytes.into()
        })
}

impl fmt::Debug for Sm2Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_struct("Signature")
            .field("r", &encode(&self.r()))
            .field("s", &encode(&self.s()))
            .field("pk", &encode(&self.pk()))
            .finish()
    }
}

impl fmt::Display for Sm2Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", encode(self.0[..].to_vec()))
    }
}

impl Default for Sm2Signature {
    fn default() -> Self {
        Sm2Signature([0; 128])
    }
}

impl From<[u8; 128]> for Sm2Signature {
    fn from(s: [u8; 128]) -> Self {
        Sm2Signature(s)
    }
}

impl<'a> From<&'a [u8]> for Sm2Signature {
    fn from(slice: &'a [u8]) -> Sm2Signature {
        assert_eq!(slice.len(), SIGNATURE_BYTES_LEN);
        let mut bytes = [0u8; SIGNATURE_BYTES_LEN];
        bytes.copy_from_slice(&slice[..]);
        Sm2Signature(bytes)
    }
}

impl fmt::LowerHex for Sm2Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for i in &self.0[..] {
            write!(f, "{:02x}", i)?;
        }
        Ok(())
    }
}

impl Deref for Sm2Signature {
    type Target = [u8; 128];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Sm2Signature {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recover() {
        let keypair = Sm2KeyPair::gen_keypair();
        let msg = Message::default();
        let sig = sm2_sign(keypair.privkey(), &msg).unwrap();
        assert_eq!(keypair.pubkey(), &sig.recover(&msg).unwrap());
    }
}
