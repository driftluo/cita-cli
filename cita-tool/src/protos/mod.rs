pub mod transaction;

pub use self::transaction::{Crypto, SignedTransaction, Transaction, UnverifiedTransaction};
#[cfg(feature = "blake2b_hash")]
use super::{blake2b_sign, Blake2bKeyPair, Blake2bPrivKey};
use super::{sha3_sign, CreateKey, Hashable, Message as SignMessage, Sha3KeyPair, Sha3PrivKey};
use protobuf::Message as MessageTrait;

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
