//! A easy-use CITA command line tool

#![deny(warnings)]
#![deny(missing_docs)]

#[cfg(feature = "blake2b_hash")]
extern crate blake2b;
extern crate cita_types as types;
#[macro_use]
extern crate failure;
extern crate futures;
extern crate hex;
extern crate hyper;
#[macro_use]
extern crate lazy_static;
extern crate protobuf;
extern crate rand;
extern crate secp256k1;
extern crate serde;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate serde_json;
extern crate ethabi;
#[cfg(feature = "blake2b_hash")]
extern crate sodiumoxide;
extern crate tiny_keccak;
extern crate tokio;
extern crate uuid;
#[macro_use]
extern crate tool_derive;

/// Ethabi
mod abi;
/// The Jsonrpc Client
pub mod client;
/// Encryption algorithm library
pub mod crypto;
/// Error of cita tool
pub mod error;
/// Transaction protobuf code
pub mod protos;
/// Request and Response type
pub mod rpctypes;

pub use abi::{decode_input, decode_logs, decode_params, encode_input, encode_params};
pub use client::{parse_url, remove_0x, TransactionOptions};
#[cfg(feature = "blake2b_hash")]
pub use crypto::{blake2b_sign, Blake2bKeyPair, Blake2bPrivKey, Blake2bPubKey, Blake2bSignature};
pub use crypto::{
    pubkey_to_address, sha3_sign, CreateKey, Hashable, KeyPair, Message, PrivateKey, PubKey,
    Sha3KeyPair, Sha3PrivKey, Sha3PubKey, Signature,
};
pub use error::ToolError;
pub use hex::{decode, encode};
pub use protobuf::Message as ProtoMessage;
pub use protos::{Crypto, SignedTransaction, Transaction, UnverifiedTransaction};
pub use rpctypes::{JsonRpcParams, JsonRpcResponse, ParamsValue, ResponseValue};
pub use types::{traits::LowerHex, H256, U256};
