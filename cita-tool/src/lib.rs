//! A easy-use CITA command line tool

// #![deny(warnings)]
#![deny(missing_docs)]

extern crate futures;
extern crate hyper;
extern crate protobuf;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate tokio_core;

/// The Jsonrpc Client
pub mod client;
/// Transaction protobuf code
pub mod protos;

pub use client::{Client, JsonRpcParams, JsonRpcResponse, ParamsValue};
