//! A easy-use CITA command line tool

#![deny(warnings)]
#![deny(missing_docs)]

#[macro_use]
extern crate serde_derive;

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

pub use crate::abi::{decode_input, decode_logs, decode_params, encode_input, encode_params};
pub use crate::client::{parse_url, remove_0x, TransactionOptions};
pub use crate::crypto::{
    ed25519_sign, Ed25519KeyPair, Ed25519PrivKey, Ed25519PubKey, Ed25519Signature,
};
pub use crate::crypto::{
    pubkey_to_address, secp256k1_sign, sign, sm2_sign, CreateKey, Encryption, Hashable, KeyPair,
    Message, PrivateKey, PubKey, Secp256k1KeyPair, Secp256k1PrivKey, Secp256k1PubKey, Signature,
    Sm2KeyPair, Sm2Privkey, Sm2Pubkey, Sm2Signature,
};
pub use crate::error::ToolError;
pub use crate::protos::{Crypto, SignedTransaction, Transaction, UnverifiedTransaction};
pub use crate::rpctypes::{JsonRpcParams, JsonRpcResponse, ParamsValue, ResponseValue};
pub use hex::{decode, encode};
pub use protobuf::Message as ProtoMessage;
pub use types::{Address, H128, H160, H256, H264, H32, H512, H520, H64};
pub use types::{U256, U512, U64};

/// Format types
pub trait LowerHex {
    /// hex doesn't with 0x
    fn lower_hex(&self) -> String;
    /// completed hex doesn't with 0x
    fn completed_lower_hex(&self) -> String;
    /// completed with 0x
    fn completed_lower_hex_with_0x(&self) -> String;
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

            fn completed_lower_hex_with_0x(&self) -> String {
                let len = stringify!($name)[1..].parse::<usize>().unwrap() / 4;
                format!("0x{:0>width$}", self.lower_hex(), width=len)
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
