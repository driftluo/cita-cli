//! A easy-use CITA command line tool

// #![deny(warnings)]
#![deny(missing_docs)]

extern crate cita_types as types;
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
extern crate serde_json;
extern crate sha3;
extern crate tokio_core;

/// The Jsonrpc Client
pub mod client;
/// Transaction protobuf code
pub mod protos;
/// Encryption algorithm library
pub mod crypto;

pub use client::{Client, JsonRpcParams, JsonRpcResponse, ParamsValue};
pub use protos::{Crypto, SignedTransaction, Transaction, UnverifiedTransaction};
pub use crypto::{pubkey_to_address, sign, CreateKey, Hashable, KeyPair, Message, PrivKey, PubKey,
                 Signature};
