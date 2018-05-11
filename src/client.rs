use std::collections::HashMap;
use tokio_core::reactor::Core;
use std::{io, str};
use hyper::{Client as HyperClient, Method, Request, Uri, Body};
use std::str::FromStr;
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
    pub fn send_requests(&mut self, method: &str, mut params: JsonRpcParams) {
        self.id += 1;
        let client = HyperClient::new(&self.core.handle());

        params.insert(String::from("jsonrpc"), ParamsValue::String("2.0".to_string()));
        params.insert(String::from("id"), ParamsValue::Int(self.id));
        let reqs = self.make_req(params);

        if !reqs.is_empty() {
            match method {
                CITA_BLOCK_BUMBER => {
                    for req in reqs {
                        let work = client.request(req).and_then(|res| {
                            res.body().concat2().and_then(move |body| {
                                match serde_json::from_slice::<serde_json::Value>(&body) {
                                    Ok(v) => {
                                        println!("The current height is {}",v.get("result").unwrap());
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
                },
                _ => {}
            }
        }

    }


    fn make_req(&mut self, params: JsonRpcParams) -> Vec<Request<Body>> {
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
pub type JsonRpcParams = HashMap<String, ParamsValue>;

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
