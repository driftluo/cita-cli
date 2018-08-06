pub mod blockchain;

pub use self::blockchain::{Crypto, SignedTransaction, Transaction, UnverifiedTransaction};
use client::remove_0x;
use crypto::PubKey;
#[cfg(feature = "blake2b_hash")]
use crypto::{blake2b_sign, Blake2bKeyPair, Blake2bPrivKey};
use crypto::{
    sha3_sign, CreateKey, Hashable, Message as SignMessage, Sha3KeyPair, Sha3PrivKey, Signature,
};
use hex;
use protobuf::Message as MessageTrait;
use protobuf::{parse_from_bytes, ProtobufEnum};
use serde_json::Value;
use types::H256;

use error::ToolError;

impl UnverifiedTransaction {
    /// Parse UnverifiedTransaction from hex string
    pub fn from_str(content: &str) -> Result<Self, ToolError> {
        let bytes = hex::decode(remove_0x(content)).map_err(ToolError::Decode)?;
        parse_from_bytes(&bytes).map_err(ToolError::Proto)
    }

    /// UnverifiedTransaction as JSON Value
    pub fn to_json(&self) -> Value {
        let tx = self.transaction.get_ref();
        json!({
            "transaction": {
                "to": tx.to,
                "nonce": tx.nonce,
                "quota": tx.quota,
                "valid_until_block": tx.valid_until_block,
                "data": format!("0x{}", hex::encode(&tx.data)),
                "value": tx.value,
                "chain_id": tx.chain_id,
                "version": tx.version,
            },
            "signature": format!("0x{}", hex::encode(&self.signature)),
            "crypto": self.crypto.value(),
        })
    }

    /// Get the transaction public key
    pub fn public_key(&self, blake2b: bool) -> Result<PubKey, String> {
        let bytes: Vec<u8> = self.get_transaction().write_to_bytes().unwrap();
        let hash = H256::from(bytes.crypt_hash(blake2b));
        let signature = self.get_signature();
        let sig = Signature::from(signature);

        match self.get_crypto() {
            Crypto::SECP => sig.recover(&hash),
            _ => Err("Mismatched encryption algorithm".to_string()),
        }
    }
}

impl Transaction {
    /// Signs the transaction by PrivKey, Sha3
    pub fn sha3_sign(&self, sk: Sha3PrivKey) -> SignedTransaction {
        let keypair = Sha3KeyPair::from_privkey(sk).unwrap();
        let pubkey = keypair.pubkey();
        let unverified_tx = self.sha3_build_unverified(sk);

        // Build SignedTransaction
        let mut signed_tx = SignedTransaction::new();
        signed_tx.set_signer(pubkey.to_vec());
        let bytes: Vec<u8> = (&unverified_tx).write_to_bytes().unwrap();
        signed_tx.set_tx_hash(bytes.crypt_hash(false).to_vec());
        signed_tx.set_transaction_with_sig(unverified_tx);
        signed_tx
    }

    /// Build UnverifiedTransaction, Sha3
    pub fn sha3_build_unverified(&self, sk: Sha3PrivKey) -> UnverifiedTransaction {
        let mut unverified_tx = UnverifiedTransaction::new();
        let bytes: Vec<u8> = self.write_to_bytes().unwrap();
        let hash = bytes.crypt_hash(false);
        unverified_tx.set_transaction(self.clone());
        let signature = sha3_sign(&sk, &SignMessage::from(hash)).unwrap();
        unverified_tx.set_signature(signature.to_vec());
        unverified_tx.set_crypto(Crypto::SECP);
        unverified_tx
    }

    /// Signs the transaction by PrivKey, blake2b
    #[cfg(feature = "blake2b_hash")]
    pub fn blake2b_sign(self, sk: Blake2bPrivKey) -> SignedTransaction {
        let keypair = Blake2bKeyPair::from_privkey(sk).unwrap();
        let pubkey = keypair.pubkey();
        let unverified_tx = self.blake2b_build_unverified(sk);

        // Build SignedTransaction
        let mut signed_tx = SignedTransaction::new();
        signed_tx.set_signer(pubkey.to_vec());
        let bytes: Vec<u8> = (&unverified_tx).write_to_bytes().unwrap();
        signed_tx.set_tx_hash(bytes.crypt_hash(true).to_vec());
        signed_tx.set_transaction_with_sig(unverified_tx);
        signed_tx
    }

    /// Build UnverifiedTransaction, blake2b
    #[cfg(feature = "blake2b_hash")]
    pub fn blake2b_build_unverified(&self, sk: Blake2bPrivKey) -> UnverifiedTransaction {
        let mut unverified_tx = UnverifiedTransaction::new();
        let bytes: Vec<u8> = self.write_to_bytes().unwrap();
        let hash = bytes.crypt_hash(true);
        unverified_tx.set_transaction(self.clone());
        let signature = blake2b_sign(&sk, &SignMessage::from(hash)).unwrap();
        unverified_tx.set_signature(signature.to_vec());
        unverified_tx.set_crypto(Crypto::SECP);
        unverified_tx
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // Just to show how to parse Transaction from bytes
    #[test]
    fn test_parse_from_bytes() {
        let content = hex::decode("0a580a28666666666666666666666666666666666666666666666666666666666666666666666666666666661220383865613735396361306465343537353930333965323664623866616633346618c0843d2098f7242a02abce12410eb039fe08783d62f30e1bb5542312e519e7f6bb84ba1c3c08101af902463fda5f1c0e4d54d93bab2541d0a4aa5b85e71dfbaf5206131db6d491b4ffd256e78c00").unwrap();
        let tx: UnverifiedTransaction = parse_from_bytes(&content).unwrap();
        assert_eq!("abce", hex::encode(&tx.transaction.get_ref().data));
    }
}
