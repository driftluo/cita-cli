use std::{collections::HashMap, convert::Into, default::Default, fmt};

use serde_json::{self, json};

/// JsonRpc params
#[derive(Serialize, Deserialize, Clone)]
pub struct JsonRpcParams {
    #[serde(flatten)]
    extra: HashMap<String, ParamsValue>,
}

impl JsonRpcParams {
    /// Create a JsonRpc Params
    pub fn new() -> Self {
        Default::default()
    }

    /// Insert params
    pub fn insert<T: Into<String>>(mut self, key: T, value: ParamsValue) -> Self {
        self.extra.insert(key.into(), value);
        self
    }

    /// Remove params
    pub fn remove<T: Into<String>>(&mut self, key: T) -> Option<ParamsValue> {
        self.extra.remove(&key.into())
    }

    /// Get params
    pub fn get<T: Into<String>>(&self, key: T) -> Option<&ParamsValue> {
        self.extra.get(&key.into())
    }
}

impl Default for JsonRpcParams {
    fn default() -> Self {
        let mut extra = HashMap::new();
        extra.insert(
            String::from("jsonrpc"),
            ParamsValue::String("2.0".to_string()),
        );
        JsonRpcParams { extra }
    }
}

impl fmt::Debug for JsonRpcParams {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", serde_json::to_string_pretty(self).unwrap())
    }
}

impl fmt::Display for JsonRpcParams {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", json!(self))
    }
}

/// The params value of jsonrpc params
#[derive(Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ParamsValue {
    /// Single string parameter
    String(String),
    /// Singe int parameter
    Int(u64),
    /// Multiple parameters
    List(Vec<ParamsValue>),
    /// Map of values
    Map(HashMap<String, ParamsValue>),
    /// bool
    Bool(bool),
    /// Null parameters
    Null,
}

impl fmt::Debug for ParamsValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", serde_json::to_string_pretty(self).unwrap())
    }
}

impl fmt::Display for ParamsValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", json!(self))
    }
}

/// The value of response result or error
#[derive(Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ResponseValue {
    /// Map result
    Map(HashMap<String, ParamsValue>),
    /// Singe result
    Singe(ParamsValue),
}

impl fmt::Debug for ResponseValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", serde_json::to_string_pretty(self).unwrap())
    }
}

impl fmt::Display for ResponseValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", json!(self))
    }
}

/// Jsonrpc response
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct JsonRpcResponse {
    jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<ResponseValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ErrorResponse>,
    id: u64,
}

impl JsonRpcResponse {
    /// Get result
    pub fn result(&self) -> Option<ResponseValue> {
        self.result.clone()
    }

    /// Get error
    pub fn error(&self) -> Option<ErrorResponse> {
        self.error.clone()
    }

    /// Determine if the query is normal
    pub fn is_ok(&self) -> bool {
        self.result.is_some()
    }
}

impl fmt::Debug for JsonRpcResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", serde_json::to_string_pretty(self).unwrap())
    }
}

impl fmt::Display for JsonRpcResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", json!(self))
    }
}

/// Error
#[derive(Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    code: i64,
    message: String,
    /// Optional data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<ParamsValue>,
}

impl ErrorResponse {
    /// Get error message
    pub fn message(&self) -> String {
        self.message.clone()
    }

    /// Get error code
    pub fn code(&self) -> i64 {
        self.code
    }
}

impl fmt::Debug for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", serde_json::to_string_pretty(self).unwrap())
    }
}

impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", json!(self))
    }
}
