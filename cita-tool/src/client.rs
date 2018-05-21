use std::str::FromStr;
use std::{str, u64};
use std::collections::HashMap;

use tokio_core::reactor::Core;
use hyper::{self, Body, Client as HyperClient, Method, Request, Uri};
use serde_json;
use futures::{Future, Stream, future::JoinAll, future::join_all};
use super::{JsonRpcParams, JsonRpcResponse, ParamsValue, PrivKey, ResponseValue, ToolError,
            Transaction};
use hex::{decode, encode};
use protobuf::Message;
use uuid::Uuid;

const CITA_BLOCK_BUMBER: &str = "cita_blockNumber";
const CITA_GET_META_DATA: &str = "cita_getMetaData";
const CITA_SEND_TRANSACTION: &str = "cita_sendTransaction";
const NET_PEER_COUNT: &str = "net_peerCount";
const CITA_GET_BLOCK_BY_HASH: &str = "cita_getBlockByHash";
const CITA_GET_BLOCK_BY_NUMBER: &str = "cita_getBlockByNumber";
const CITA_GET_TRANSACTION: &str = "cita_getTransaction";
const CITA_GET_TRANSACTION_PROOF: &str = "cita_getTransactionProof";

const ETH_GET_TRANSACTION_RECEIPT: &str = "eth_getTransactionReceipt";
const ETH_GET_LOGS: &str = "eth_getLogs";
const ETH_CALL: &str = "eth_call";
const ETH_GET_TRANSACTION_COUNT: &str = "eth_getTransactionCount";
const ETH_GET_CODE: &str = "eth_getCode";
const ETH_GET_ABI: &str = "eth_getAbi";
const ETH_GET_BALANCE: &str = "eth_getBalance";

const ETH_NEW_FILTER: &str = "eth_newFilter";
const ETH_NEW_BLOCK_FILTER: &str = "eth_newBlockFilter";
const ETH_UNINSTALL_FILTER: &str = "eth_uninstallFilter";
const ETH_GET_FILTER_CHANGES: &str = "eth_getFilterChanges";
const ETH_GET_FILTER_LOGS: &str = "eth_getFilterLogs";

/// Jsonrpc client, Only to one chain
#[derive(Debug)]
pub struct Client {
    id: u64,
    core: Core,
    chain_id: Option<u32>,
    private_key: Option<PrivKey>,
}

impl Client {
    /// Create a client for CITA
    pub fn new() -> Result<Self, ToolError> {
        let core = Core::new().map_err(ToolError::Stdio)?;
        Ok(Client {
            id: 0,
            core: core,
            chain_id: None,
            private_key: None,
        })
    }

    /// Set chain id
    pub fn set_chain_id(mut self, chain_id: u32) -> Self {
        self.chain_id = Some(chain_id);
        self
    }

    /// Set private key
    pub fn set_private_key(mut self, private_key: PrivKey) -> Self {
        self.private_key = Some(private_key);
        self
    }

    /// Get private key
    pub fn private_key(&self) -> Option<&PrivKey> {
        self.private_key.as_ref()
    }

    /// Send requests
    pub fn send_request(
        &mut self,
        urls: Vec<&str>,
        params: JsonRpcParams,
    ) -> Result<Vec<JsonRpcResponse>, ToolError> {
        let reqs = self.make_requests_with_all_url(urls, params);

        self.run(reqs)
    }

    /// Send multiple params to one node
    pub fn send_request_with_multiple_params<T: Iterator<Item = JsonRpcParams>>(
        &mut self,
        url: &str,
        params: T,
    ) -> Result<Vec<JsonRpcResponse>, ToolError> {
        let reqs = self.make_requests_with_params_list(url, params);

        self.run(reqs)
    }

    fn make_requests_with_all_url(
        &mut self,
        urls: Vec<&str>,
        params: JsonRpcParams,
    ) -> JoinAll<Vec<Box<Future<Item = hyper::Chunk, Error = ToolError>>>> {
        self.id = self.id.overflowing_add(1).0;
        let params = params.insert("id", ParamsValue::Int(self.id));
        let client = HyperClient::new(&self.core.handle());
        let mut reqs = Vec::new();
        urls.iter().for_each(|url| {
            let uri = Uri::from_str(url).unwrap();
            let mut req: Request<Body> = Request::new(Method::Post, uri);
            req.set_body(serde_json::to_string(&params).unwrap());
            let future: Box<Future<Item = hyper::Chunk, Error = ToolError>> = Box::new(
                client
                    .request(req)
                    .and_then(|res| res.body().concat2())
                    .map_err(ToolError::Hyper),
            );
            reqs.push(future);
        });
        join_all(reqs)
    }

    fn make_requests_with_params_list<T: Iterator<Item = JsonRpcParams>>(
        &mut self,
        url: &str,
        params: T,
    ) -> JoinAll<Vec<Box<Future<Item = hyper::Chunk, Error = ToolError>>>> {
        let client = HyperClient::new(&self.core.handle());
        let mut reqs = Vec::new();
        params
            .map(|param| {
                self.id = self.id.overflowing_add(1).0;
                param.insert("id", ParamsValue::Int(self.id))
            })
            .for_each(|param| {
                let uri = Uri::from_str(&url).unwrap();
                let mut req: Request<Body> = Request::new(Method::Post, uri);
                req.set_body(serde_json::to_string(&param).unwrap());
                let future: Box<Future<Item = hyper::Chunk, Error = ToolError>> = Box::new(
                    client
                        .request(req)
                        .and_then(|res| res.body().concat2())
                        .map_err(ToolError::Hyper),
                );
                reqs.push(future);
            });

        join_all(reqs)
    }

    /// Constructing a UnverifiedTransaction hex string
    /// If you want to create a contract, set address to ""
    pub fn generate_transaction(
        &mut self,
        code: &str,
        address: &str,
        current_height: u64,
    ) -> String {
        let data = decode(code).unwrap();

        let mut tx = Transaction::new();
        tx.set_data(data);
        // Create a contract if the target address is empty
        tx.set_to(address.to_string());
        tx.set_nonce(encode(Uuid::new_v4().as_bytes()));
        tx.set_valid_until_block(current_height + 88);
        tx.set_quota(1000000);
        tx.set_chain_id(self.chain_id.expect("Please set chain id"));
        encode(
            tx.sign(*self.private_key().unwrap())
                .take_transaction_with_sig()
                .write_to_bytes()
                .unwrap(),
        )
    }

    /// Get chain id
    pub fn get_chain_id(&mut self, url: &str) -> u32 {
        if self.chain_id.is_some() {
            self.chain_id.unwrap()
        } else {
            if let Some(ResponseValue::Map(mut value)) = self.get_metadata(url, "latest").result() {
                match value.remove("chainId").unwrap() {
                    ParamsValue::Int(chain_id) => {
                        self.chain_id = Some(chain_id as u32);
                        return chain_id as u32;
                    }
                    _ => return 0,
                }
            } else {
                0
            }
        }
    }

    /// Start run
    fn run(
        &mut self,
        reqs: JoinAll<Vec<Box<Future<Item = hyper::Chunk, Error = ToolError>>>>,
    ) -> Result<Vec<JsonRpcResponse>, ToolError> {
        let responses = self.core.run(reqs)?;
        Ok(responses
            .into_iter()
            .map(|response| {
                serde_json::from_slice::<JsonRpcResponse>(&response)
                    .map_err(ToolError::SerdeJson)
                    .unwrap()
            })
            .collect::<Vec<JsonRpcResponse>>())
    }
}

/// High level jsonrpc call
///
/// [Documentation](https://cryptape.github.io/cita/zh/usage-guide/rpc/index.html)
///
/// JSONRPC methods:
///   * net_peerCount
///   * cita_blockNumber
///   * cita_sendTransaction
///   * cita_getBlockByHash
///   * cita_getBlockByNumber
///   * eth_getTransactionReceipt
///   * eth_getLogs
///   * eth_call
///   * cita_getTransaction
///   * eth_getTransactionCount
///   * eth_getCode
///   * eth_getAbi
///   * eth_getBalance
///   * eth_newFilter
///   * eth_newBlockFilter
///   * eth_uninstallFilter
///   * eth_getFilterChanges
///   * eth_getFilterLogs
///   * cita_getTransactionProof
///   * cita_getMetaData
pub trait ClientExt {
    /// net_peerCount: Get network peer count
    fn get_net_peer_count(&mut self, url: &str) -> JsonRpcResponse;
    /// cita_blockNumber: Get current height
    fn get_block_number(&mut self, url: &str) -> JsonRpcResponse;
    /// cita_sendTransaction: Send a transaction return transaction hash
    fn send_transaction(
        &mut self,
        url: &str,
        code: &str,
        address: &str,
        current_height: u64,
    ) -> JsonRpcResponse;
    /// cita_getBlockByHash: Get block by hash
    fn get_block_by_hash(
        &mut self,
        url: &str,
        hash: &str,
        transaction_info: bool,
    ) -> JsonRpcResponse;
    /// cita_getBlockByNumber: Get block by number
    fn get_block_by_number(
        &mut self,
        url: &str,
        height: &str,
        transaction_info: bool,
    ) -> JsonRpcResponse;
    /// eth_getTransactionReceipt: Get transaction receipt
    fn get_transaction_receipt(&mut self, url: &str, hash: &str) -> JsonRpcResponse;
    /// eth_getLogs: Get logs
    fn get_logs(&mut self, url: &str, object: ParamsValue) -> JsonRpcResponse;
    /// eth_call: (readonly, will not save state change)
    fn call(
        &mut self,
        url: &str,
        from: Option<&str>,
        to: &str,
        code: Option<&str>,
        quantity: &str,
    ) -> JsonRpcResponse;
    /// cita_getTransaction: Get transaction by hash
    fn get_transaction(&mut self, url: &str, hash: &str) -> JsonRpcResponse;
    /// eth_getTransactionCount: Get transaction count of an account
    fn get_transaction_count(&mut self, url: &str, address: &str, height: &str) -> JsonRpcResponse;
    /// eth_getCode: Get the code of a contract
    fn get_code(&mut self, url: &str, address: &str, height: &str) -> JsonRpcResponse;
    /// eth_getAbi: Get the ABI of a contract
    fn get_abi(&mut self, url: &str, address: &str, height: &str) -> JsonRpcResponse;
    /// eth_getBalance: Get the balance of a contract (TODO: return U256)
    fn get_balance(&mut self, url: &str, address: &str, height: &str) -> JsonRpcResponse;
    /// eth_newFilter:
    fn new_filter(&mut self, url: &str, object: ParamsValue) -> JsonRpcResponse;
    /// eth_newBlockFilter:
    fn new_block_filter(&mut self, url: &str) -> JsonRpcResponse;
    /// eth_uninstallFilter: Uninstall a filter by its id
    fn uninstall_filter(&mut self, url: &str, filter_id: &str) -> JsonRpcResponse;
    /// eth_getFilterChanges: Get filter changes
    fn get_filter_changes(&mut self, url: &str, filter_id: &str) -> JsonRpcResponse;
    /// eth_getFilterLogs: Get filter logs
    fn get_filter_logs(&mut self, url: &str, filter_id: &str) -> JsonRpcResponse;
    /// cita_getTransactionProof: Get proof of a transaction
    fn get_transaction_proof(&mut self, url: &str, hash: &str) -> JsonRpcResponse;
    /// cita_getMetaData: Get metadata
    fn get_metadata(&mut self, url: &str, height: &str) -> JsonRpcResponse;
}

impl ClientExt for Client {
    fn get_net_peer_count(&mut self, url: &str) -> JsonRpcResponse {
        let params = JsonRpcParams::new()
            .insert("method", ParamsValue::String(String::from(NET_PEER_COUNT)));
        self.send_request(vec![url], params).unwrap().pop().unwrap()

        // match result.result().unwrap() {
        //     ResponseValue::Singe(ParamsValue::String(count)) => {
        //         u32::from_str_radix(&remove_0x(count), 16).unwrap()
        //     }
        //     _ => 0,
        // }
    }

    fn get_block_number(&mut self, url: &str) -> JsonRpcResponse {
        let params = JsonRpcParams::new().insert(
            "method",
            ParamsValue::String(String::from(CITA_BLOCK_BUMBER)),
        );
        self.send_request(vec![url], params).unwrap().pop().unwrap()

        // if let ResponseValue::Singe(ParamsValue::String(height)) = result.result().unwrap() {
        //     Some(u64::from_str_radix(&remove_0x(height), 16).unwrap())
        // } else {
        //     None
        // }
    }

    fn send_transaction(
        &mut self,
        url: &str,
        code: &str,
        address: &str,
        current_height: u64,
    ) -> JsonRpcResponse {
        let byte_code = self.generate_transaction(code, address, current_height);
        let params = JsonRpcParams::new()
            .insert(
                "method",
                ParamsValue::String(String::from(CITA_SEND_TRANSACTION)),
            )
            .insert(
                "params",
                ParamsValue::List(vec![ParamsValue::String(byte_code)]),
            );
        self.send_request(vec![url], params).unwrap().pop().unwrap()

        // if let ResponseValue::Singe(ParamsValue::Map(mut value)) = result.result().unwrap() {
        //     match value.remove("hash").unwrap() {
        //         ParamsValue::String(hash) => Ok(hash),
        //         _ => Err(String::from("Something wrong")),
        //     }
        // } else {
        //     let error = format!(
        //         "Error code:{}, message: {}",
        //         result.error().unwrap().code(),
        //         result.error().unwrap().message()
        //     );
        //     Err(error)
        // }
    }

    fn get_block_by_hash(
        &mut self,
        url: &str,
        hash: &str,
        transaction_info: bool,
    ) -> JsonRpcResponse {
        let params = JsonRpcParams::new()
            .insert(
                "method",
                ParamsValue::String(String::from(CITA_GET_BLOCK_BY_HASH)),
            )
            .insert(
                "params",
                ParamsValue::List(vec![
                    ParamsValue::String(String::from(hash)),
                    ParamsValue::Bool(transaction_info),
                ]),
            );
        self.send_request(vec![url], params).unwrap().pop().unwrap()
    }

    fn get_block_by_number(
        &mut self,
        url: &str,
        height: &str,
        transaction_info: bool,
    ) -> JsonRpcResponse {
        let params = JsonRpcParams::new()
            .insert(
                "method",
                ParamsValue::String(String::from(CITA_GET_BLOCK_BY_NUMBER)),
            )
            .insert(
                "params",
                ParamsValue::List(vec![
                    ParamsValue::String(String::from(height)),
                    ParamsValue::Bool(transaction_info),
                ]),
            );
        self.send_request(vec![url], params).unwrap().pop().unwrap()
    }

    fn get_transaction_receipt(&mut self, url: &str, hash: &str) -> JsonRpcResponse {
        let params = JsonRpcParams::new()
            .insert(
                "method",
                ParamsValue::String(String::from(ETH_GET_TRANSACTION_RECEIPT)),
            )
            .insert(
                "params",
                ParamsValue::List(vec![ParamsValue::String(String::from(hash))]),
            );
        self.send_request(vec![url], params).unwrap().pop().unwrap()
    }

    fn get_logs(&mut self, url: &str, object: ParamsValue) -> JsonRpcResponse {
        let params = JsonRpcParams::new()
            .insert("method", ParamsValue::String(String::from(ETH_GET_LOGS)))
            .insert("params", object);
        self.send_request(vec![url], params).unwrap().pop().unwrap()
    }

    fn call(
        &mut self,
        url: &str,
        from: Option<&str>,
        to: &str,
        data: Option<&str>,
        quantity: &str,
    ) -> JsonRpcResponse {
        let mut object = HashMap::new();

        object.insert(String::from("to"), ParamsValue::String(String::from(to)));
        if from.is_some() {
            object.insert(
                String::from("from"),
                ParamsValue::String(String::from(from.unwrap())),
            );
        }
        if data.is_some() {
            object.insert(
                String::from("data"),
                ParamsValue::String(String::from(data.unwrap())),
            );
        }

        let param = ParamsValue::List(vec![
            ParamsValue::String(String::from(quantity)),
            ParamsValue::Map(object),
        ]);
        let params = JsonRpcParams::new()
            .insert("method", ParamsValue::String(String::from(ETH_CALL)))
            .insert("params", param);

        self.send_request(vec![url], params).unwrap().pop().unwrap()
    }

    fn get_transaction(&mut self, url: &str, hash: &str) -> JsonRpcResponse {
        let params = JsonRpcParams::new()
            .insert(
                "method",
                ParamsValue::String(String::from(CITA_GET_TRANSACTION)),
            )
            .insert(
                "params",
                ParamsValue::List(vec![ParamsValue::String(String::from(hash))]),
            );

        self.send_request(vec![url], params).unwrap().pop().unwrap()
    }

    fn get_transaction_count(&mut self, url: &str, address: &str, height: &str) -> JsonRpcResponse {
        let params = JsonRpcParams::new()
            .insert(
                "method",
                ParamsValue::String(String::from(ETH_GET_TRANSACTION_COUNT)),
            )
            .insert(
                "params",
                ParamsValue::List(vec![
                    ParamsValue::String(String::from(address)),
                    ParamsValue::String(String::from(height)),
                ]),
            );

        self.send_request(vec![url], params).unwrap().pop().unwrap()

        // match result.result().unwrap() {
        //     ResponseValue::Singe(ParamsValue::String(count)) => {
        //         u64::from_str_radix(&remove_0x(count), 16).unwrap()
        //     }
        //     _ => 0,
        // }
    }

    fn get_code(&mut self, url: &str, address: &str, height: &str) -> JsonRpcResponse {
        let params = JsonRpcParams::new()
            .insert("method", ParamsValue::String(String::from(ETH_GET_CODE)))
            .insert(
                "params",
                ParamsValue::List(vec![
                    ParamsValue::String(String::from(address)),
                    ParamsValue::String(String::from(height)),
                ]),
            );

        self.send_request(vec![url], params).unwrap().pop().unwrap()

        // match result.result().unwrap() {
        //     ResponseValue::Singe(ParamsValue::String(code)) => code,
        //     _ => Default::default(),
        // }
    }

    fn get_abi(&mut self, url: &str, address: &str, height: &str) -> JsonRpcResponse {
        let params = JsonRpcParams::new()
            .insert("method", ParamsValue::String(String::from(ETH_GET_ABI)))
            .insert(
                "params",
                ParamsValue::List(vec![
                    ParamsValue::String(String::from(address)),
                    ParamsValue::String(String::from(height)),
                ]),
            );

        self.send_request(vec![url], params).unwrap().pop().unwrap()

        // match result.result().unwrap() {
        //     ResponseValue::Singe(ParamsValue::String(abi)) => abi,
        //     _ => Default::default(),
        // }
    }

    fn get_balance(&mut self, url: &str, address: &str, height: &str) -> JsonRpcResponse {
        let params = JsonRpcParams::new()
            .insert("method", ParamsValue::String(String::from(ETH_GET_BALANCE)))
            .insert(
                "params",
                ParamsValue::List(vec![
                    ParamsValue::String(String::from(address)),
                    ParamsValue::String(String::from(height)),
                ]),
            );

        self.send_request(vec![url], params).unwrap().pop().unwrap()

        // match result.result().unwrap() {
        //     ResponseValue::Singe(ParamsValue::String(balance)) => {
        //         u64::from_str_radix(&remove_0x(balance), 16).unwrap()
        //     }
        //     _ => 0,
        // }
    }

    fn new_filter(&mut self, url: &str, object: ParamsValue) -> JsonRpcResponse {
        let params = JsonRpcParams::new()
            .insert("method", ParamsValue::String(String::from(ETH_NEW_FILTER)))
            .insert("params", object);
        self.send_request(vec![url], params).unwrap().pop().unwrap()

        // match result.result().unwrap() {
        //     ResponseValue::Singe(ParamsValue::String(id)) => {
        //         id
        //     }
        //     _ => Default::default(),
        // }
    }

    fn new_block_filter(&mut self, url: &str) -> JsonRpcResponse {
        let params = JsonRpcParams::new().insert(
            "method",
            ParamsValue::String(String::from(ETH_NEW_BLOCK_FILTER)),
        );
        self.send_request(vec![url], params).unwrap().pop().unwrap()

        // match result.result().unwrap() {
        //     ResponseValue::Singe(ParamsValue::String(id)) => {
        //         id
        //     }
        //     _ => Default::default(),
        // }
    }

    fn uninstall_filter(&mut self, url: &str, filter_id: &str) -> JsonRpcResponse {
        let params = JsonRpcParams::new()
            .insert(
                "method",
                ParamsValue::String(String::from(ETH_UNINSTALL_FILTER)),
            )
            .insert(
                "params",
                ParamsValue::List(vec![ParamsValue::String(String::from(filter_id))]),
            );

        self.send_request(vec![url], params).unwrap().pop().unwrap()

        // match result.result().unwrap() {
        //     ResponseValue::Singe(ParamsValue::Bool(value)) => {
        //         value
        //     }
        //     _ => false,
        // }
    }

    fn get_filter_changes(&mut self, url: &str, filter_id: &str) -> JsonRpcResponse {
        let params = JsonRpcParams::new()
            .insert(
                "method",
                ParamsValue::String(String::from(ETH_GET_FILTER_CHANGES)),
            )
            .insert(
                "params",
                ParamsValue::List(vec![ParamsValue::String(String::from(filter_id))]),
            );

        self.send_request(vec![url], params).unwrap().pop().unwrap()
    }

    fn get_filter_logs(&mut self, url: &str, filter_id: &str) -> JsonRpcResponse {
        let params = JsonRpcParams::new()
            .insert(
                "method",
                ParamsValue::String(String::from(ETH_GET_FILTER_LOGS)),
            )
            .insert(
                "params",
                ParamsValue::List(vec![ParamsValue::String(String::from(filter_id))]),
            );
        self.send_request(vec![url], params).unwrap().pop().unwrap()
    }

    fn get_transaction_proof(&mut self, url: &str, hash: &str) -> JsonRpcResponse {
        let params = JsonRpcParams::new()
            .insert(
                "method",
                ParamsValue::String(String::from(CITA_GET_TRANSACTION_PROOF)),
            )
            .insert(
                "params",
                ParamsValue::List(vec![ParamsValue::String(String::from(hash))]),
            );
        self.send_request(vec![url], params).unwrap().pop().unwrap()
    }

    fn get_metadata(&mut self, url: &str, height: &str) -> JsonRpcResponse {
        let params = JsonRpcParams::new()
            .insert(
                "params",
                ParamsValue::List(vec![ParamsValue::String(String::from(height))]),
            )
            .insert(
                "method",
                ParamsValue::String(String::from(CITA_GET_META_DATA)),
            );
        self.send_request(vec![url], params).unwrap().pop().unwrap()
    }
}

/// Remove hexadecimal prefix "0x" or "0X".
/// Example:
/// ```rust
/// extern crate cita_tool;
///
/// use cita_tool::remove_0x;
///
/// let a = "0x0b";
/// let b = remove_0x(a.to_string());
/// let c = "0X0b";
/// let d = remove_0x(c.to_string());
/// assert_eq!("0b".to_string(), b);
/// assert_eq!("0b".to_string(), d);
/// println!("a = {}, b = {}, c = {}, d= {}", a, b, c, d);
/// ```
pub fn remove_0x(hex: String) -> String {
    let tmp = hex.as_bytes();
    if tmp[..2] == b"0x"[..] || tmp[..2] == b"0X"[..] {
        String::from_utf8(tmp[2..].to_vec()).unwrap()
    } else {
        hex.clone()
    }
}
