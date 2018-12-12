use failure::Fail;
use hex::FromHexError;
use hyper;
use protobuf::error::ProtobufError;
use serde_json;
use std::num::ParseIntError;

/// Error summary information
#[derive(Debug, Fail)]
pub enum ToolError {
    /// IO error
    #[fail(display = "Std's io error: {}", _0)]
    Stdio(::std::io::Error),
    /// Parsing json data error
    #[fail(display = "Serde_json error: {}", _0)]
    SerdeJson(serde_json::error::Error),
    /// Hyper error
    #[fail(display = "Hyper error: {}", _0)]
    Hyper(hyper::Error),
    /// ABI error
    #[fail(display = "ABI error: {}", _0)]
    Abi(String),
    /// Protobuf error
    #[fail(display = "Protobuf error: {}", _0)]
    Proto(ProtobufError),
    /// Hex decode error
    #[fail(display = "Hex decode error: {}", _0)]
    Decode(FromHexError),
    /// Parse error
    #[fail(display = "Parse int error: {}", _0)]
    Parse(ParseIntError),
    /// Customize error
    #[fail(display = "Customize error: {}", _0)]
    Customize(String),
}
