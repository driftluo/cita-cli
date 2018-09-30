//! A easy-use CITA command line tool

#![deny(warnings)]
#![deny(missing_docs)]

#[cfg(feature = "ed25519")]
extern crate blake2b;
extern crate ethereum_types as types;
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
#[cfg(feature = "ed25519")]
extern crate sodiumoxide;
extern crate tiny_keccak;
extern crate tokio;
extern crate uuid;
#[macro_use]
extern crate tool_derive;
extern crate libsm;

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
#[cfg(feature = "ed25519")]
pub use crypto::{ed25519_sign, Ed25519KeyPair, Ed25519PrivKey, Ed25519PubKey, Ed25519Signature};
pub use crypto::{
    pubkey_to_address, secp256k1_sign, sign, sm2_sign, CreateKey, Encryption, Hashable, KeyPair,
    Message, PrivateKey, PubKey, Secp256k1KeyPair, Secp256k1PrivKey, Secp256k1PubKey, Signature,
    Sm2KeyPair, Sm2Privkey, Sm2Pubkey, Sm2Signature,
};
pub use error::ToolError;
pub use hex::{decode, encode};
pub use protobuf::Message as ProtoMessage;
pub use protos::{Crypto, SignedTransaction, Transaction, UnverifiedTransaction};
pub use rpctypes::{JsonRpcParams, JsonRpcResponse, ParamsValue, ResponseValue};
pub use types::{Address, H128, H160, H256, H264, H32, H512, H520, H64};
pub use types::{U256, U512, U64};

/// Format types
pub trait LowerHex {
    /// hex doesn't with 0x
    fn lower_hex(&self) -> String;
    /// completed hex doesn't with 0x
    fn completed_lower_hex(&self) -> String;
    /// hex with 0x
    fn lower_hex_with_0x(&self) -> String;
}

macro_rules! add_funcs {
    ([$( ($name:ident) ),+ ,]) => {
        add_funcs!([ $( ($name) ),+ ]);
    };

    ([$( ($name:ident) ),+]) => {
        $( add_funcs!($name); )+
    };

    ($name:ident) => {
        impl LowerHex for $name {
            #[inline]
            fn lower_hex(&self) -> String {
                format!("{:x}", self)
            }

            #[inline]
            fn completed_lower_hex(&self) -> String {
                let len = stringify!($name)[1..].parse::<usize>().unwrap() / 4;
                format!("{:0>width$}", self.lower_hex(), width=len)
            }

            #[inline]
            fn lower_hex_with_0x(&self) -> String {
                format!("{:#x}", self)
            }
        }
    }
}

add_funcs!([
    (H32),
    (H64),
    (H128),
    (H160),
    (H256),
    (H264),
    (H512),
    (H520),
    (U64),
    (U256),
    (U512),
]);
