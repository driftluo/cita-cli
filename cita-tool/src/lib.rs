//! A easy-use CITA command line tool

// #![deny(warnings)]
#![deny(missing_docs)]

extern crate futures;
extern crate hyper;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate tokio_core;

/// The Jsonrpc Client
pub mod client;

pub use client::{Client, JsonRpcParams, JsonRpcResponse, ParamsValue};
