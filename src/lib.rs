//! A easy-use CITA command line tool

// #![deny(warnings)]
#![deny(missing_docs)]

extern crate hyper;
extern crate tokio_core;
extern crate futures;
extern crate serde_json;
extern crate serde;
#[macro_use]
extern crate serde_derive;

/// The Jsonrpc Client
pub mod client;


pub use client::{JsonRpcParams, Client, ParamsValue};
