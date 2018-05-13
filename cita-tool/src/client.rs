use tokio_core::reactor::Core;
use std::{io, str};
use hyper::{Body, Client as HyperClient, Method, Request, Uri, client::HttpConnector};
use std::{collections::HashMap, convert::Into, default::Default, str::FromStr};
use serde_json;
use futures::{Future, Stream};

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
    pub fn send_requests(&mut self, method: &str, params: JsonRpcParams) {
        self.id += 1;
        let client = HyperClient::new(&self.core.handle());

        let params = params.insert("id", ParamsValue::Int(self.id));
        let reqs = self.make_requests(params);

        for req in reqs {
            self.send_request(method, &client, req);
        }
    }

    /// Send request
    fn send_request(
        &mut self,
        method: &str,
        client: &HyperClient<HttpConnector>,
        req: Request<Body>,
    ) {
        match method {
            CITA_BLOCK_BUMBER => {
                let work = client.request(req).and_then(|res| {
                    res.body().concat2().and_then(move |body| {
                        match serde_json::from_slice::<serde_json::Value>(&body) {
                            Ok(v) => {
                                println!("The current height is {}", v.get("result").unwrap());
                            }
                            Err(e) => {
                                println!("{}", e);
                            }
                        }
                        Ok(())
                    })
                });
                let _ = self.core.run(work);
            }
            _ => {}
        }
    }

    fn make_requests(&self, params: JsonRpcParams) -> Vec<Request<Body>> {
        let mut reqs = Vec::new();
        for url in self.url.as_slice() {
            let uri = Uri::from_str(url).unwrap();
            let mut req: Request<Body> = Request::new(Method::Post, uri);
            req.set_body(serde_json::to_string(&params).unwrap());

            reqs.push(req);
        }
        reqs
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
