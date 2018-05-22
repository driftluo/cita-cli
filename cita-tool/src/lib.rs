//! A easy-use CITA command line tool

// #![deny(warnings)]
#![deny(missing_docs)]

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
extern crate sha3;
extern crate tokio_core;
extern crate uuid;
#[cfg(feature = "blake2b_hash")]
extern crate blake2b;
#[cfg(feature = "blake2b_hash")]
extern crate sodiumoxide;

/// The Jsonrpc Client
pub mod client;
/// Transaction protobuf code
pub mod protos;
/// Encryption algorithm library
pub mod crypto;
/// Reqeust and Response type
pub mod rpctypes;
/// Error of cita tool
pub mod error;

pub use client::{Client, ClientExt, remove_0x};
pub use protos::{Crypto, SignedTransaction, Transaction, UnverifiedTransaction};
pub use crypto::{sha3_pubkey_to_address, sha3_sign, CreateKey, Hashable, Sha3KeyPair, Message, Sha3PrivKey, Sha3PubKey,
                 Signature, };
pub use rpctypes::{JsonRpcParams, JsonRpcResponse, ParamsValue, ResponseValue};
pub use error::ToolError;
#[cfg(feature = "blake2b_hash")]
pub use crypto::{blake2b_pubkey_to_address};
