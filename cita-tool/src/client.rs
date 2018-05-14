use tokio_core::reactor::Core;
use std::{io, str, u64};
use hyper::{self, Body, Client as HyperClient, Method, Request, Uri};
use std::{collections::HashMap, convert::Into, default::Default, str::FromStr};
use serde_json;
use futures::{Future, Stream, future::JoinAll, future::join_all};

const CITA_BLOCK_BUMBER: &str = "cita_blockNumber";

/// Jsonrpc client
#[derive(Debug)]
pub struct Client {
    id: u64,
    url: Vec<String>,
    core: Core,
}

impl Client {
    /// Create a client for CITA
    pub fn new() -> io::Result<Self> {
        let core = Core::new()?;
        Ok(Client {
            id: 0,
            url: Vec::new(),
            core: core,
        })
    }

    /// Add node url
    pub fn add_url<T: Into<String>>(mut self, url: T) -> Self {
        self.url.push(url.into());
        self
    }

    /// Send requests
    pub fn send_request(
        &mut self,
        method: &str,
        params: JsonRpcParams,
    ) -> Result<Vec<JsonRpcResponse>, ()> {
        self.id = self.id.overflowing_add(1).0;

        let params = params.insert("id", ParamsValue::Int(self.id));
        let reqs = self.make_requests_with_all_url(params);

        match method {
            CITA_BLOCK_BUMBER => {
                let responses = self.core.run(reqs).unwrap();
                let responses = responses
                    .into_iter()
                    .map(|response| serde_json::from_slice::<JsonRpcResponse>(&response).unwrap())
                    .collect::<Vec<JsonRpcResponse>>();
                Ok(responses)
            }
            _ => Err(()),
        }
    }

    fn make_requests_with_all_url(
        &self,
        params: JsonRpcParams,
    ) -> JoinAll<Vec<Box<Future<Item = hyper::Chunk, Error = hyper::error::Error>>>> {
        let client = HyperClient::new(&self.core.handle());
        let mut reqs = Vec::new();
        for url in self.url.as_slice() {
            let uri = Uri::from_str(url).unwrap();
            let mut req: Request<Body> = Request::new(Method::Post, uri);
            req.set_body(serde_json::to_string(&params).unwrap());
            let future: Box<Future<Item = hyper::Chunk, Error = hyper::error::Error>> =
                Box::new(client.request(req).and_then(|res| res.body().concat2()));
            reqs.push(future);
        }
        join_all(reqs)
    }

    #[allow(dead_code)]
    fn make_requests_with_params_list<T: Iterator<Item = JsonRpcParams>>(
        &self,
        params: T,
    ) -> JoinAll<Vec<Box<Future<Item = hyper::Chunk, Error = hyper::error::Error>>>> {
        let client = HyperClient::new(&self.core.handle());
        let mut reqs = Vec::new();
        if !self.url.is_empty() {
            for params in params {
                let uri = Uri::from_str(&self.url.as_slice()[0]).unwrap();
                let mut req: Request<Body> = Request::new(Method::Post, uri);
                req.set_body(serde_json::to_string(&params).unwrap());
                let future: Box<
                    Future<Item = hyper::Chunk, Error = hyper::error::Error>,
                > = Box::new(client.request(req).and_then(|res| res.body().concat2()));
                reqs.push(future);
            }
            join_all(reqs)
        } else {
            join_all(reqs)
        }
    }
}

/// JsonRpc params
#[derive(Serialize, Deserialize)]
pub struct JsonRpcParams {
    #[serde(flatten)] extra: HashMap<String, ParamsValue>,
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
        );;
        JsonRpcParams { extra: extra }
    }
}

/// The params value of jsonrpc params
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ParamsValue {
    /// Single string parameter
    String(String),
    /// Singe int parameter
    Int(u64),
    /// Multiple parameters
    List(Vec<String>),
    /// Null parameters
    Null,
}

/// The value of response result or error
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ResponseValue {
    /// Map result
    Map(HashMap<String, ParamsValue>),
    /// Singe result
    Singe(ParamsValue),
}

/// Jsonrpc response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    jsonrpc: String,
    result: Option<ResponseValue>,
    error: Option<ResponseValue>,
    id: u64,
}

impl JsonRpcResponse {
    /// Get result
    pub fn result(&self) -> Option<ResponseValue> {
        self.result.clone()
    }

    /// Get error
    pub fn error(&self) -> Option<ResponseValue> {
        self.error.clone()
    }

    /// Determine if the query is normal
    pub fn is_ok(&self) -> bool {
        self.result.is_some()
    }
}
