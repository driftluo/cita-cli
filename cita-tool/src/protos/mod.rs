pub mod transaction;

pub use self::transaction::{Crypto, SignedTransaction, Transaction, UnverifiedTransaction};
use super::{sign, CreateKey, Hashable, KeyPair, Message as SignMessage, PrivKey};
use protobuf::Message as MessageTrait;

impl Transaction {
    /// Signs the transaction by PrivKey.
    pub fn sign(&self, sk: PrivKey) -> SignedTransaction {
        let keypair = KeyPair::from_privkey(sk).unwrap();
        let pubkey = keypair.pubkey();
        let unverified_tx = self.build_unverified(sk);

        // Build SignedTransaction
        let mut signed_tx = SignedTransaction::new();
        signed_tx.set_signer(pubkey.to_vec());
        let bytes: Vec<u8> = (&unverified_tx).write_to_bytes().unwrap();
        signed_tx.set_tx_hash(bytes.crypt_hash().to_vec());
        signed_tx.set_transaction_with_sig(unverified_tx);
        signed_tx
    }

    /// Build UnverifiedTransaction
    pub fn build_unverified(&self, sk: PrivKey) -> UnverifiedTransaction {
        let mut unverified_tx = UnverifiedTransaction::new();
        let bytes: Vec<u8> = self.write_to_bytes().unwrap();
        let hash = bytes.crypt_hash();
        unverified_tx.set_transaction(self.clone());
        let signature = sign(&sk, &SignMessage::from(hash)).unwrap();
        unverified_tx.set_signature(signature.to_vec());
        unverified_tx.set_crypto(Crypto::SECP);
        unverified_tx
    }
}
