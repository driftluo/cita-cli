use std::collections::HashMap;
use std::str::FromStr;
use std::{str, u64};

#[cfg(feature = "blake2b_hash")]
use super::Blake2bPrivKey;
use super::{JsonRpcParams, JsonRpcResponse, ParamsValue, PrivateKey, ResponseValue, Sha3PrivKey,
            ToolError, Transaction};
use futures::{future::join_all, future::JoinAll, Future, Stream};
use hex::{decode, encode};
use hyper::{self, Body, Client as HyperClient, Method, Request, Uri};
use protobuf::Message;
use serde_json;
use tokio_core::reactor::Core;
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
    sha3_private_key: Option<Sha3PrivKey>,
    #[cfg(feature = "blake2b_hash")]
    blake2b_private_key: Option<Blake2bPrivKey>,
    debug: bool,
}

impl Client {
    /// Create a client for CITA
    pub fn new() -> Result<Self, ToolError> {
        let core = Core::new().map_err(ToolError::Stdio)?;
        Ok(Client {
            id: 0,
            core: core,
            chain_id: None,
            sha3_private_key: None,
            #[cfg(feature = "blake2b_hash")]
            blake2b_private_key: None,
            debug: false,
        })
    }

    /// Set chain id
    pub fn set_chain_id(&mut self, chain_id: u32) -> &mut Self {
        self.chain_id = Some(chain_id);
        self
    }

    /// Set private key
    pub fn set_private_key(&mut self, private_key: PrivateKey) -> &mut Self {
        match private_key {
            PrivateKey::Sha3(sha3_private_key) => {
                self.sha3_private_key = Some(sha3_private_key);
            }
            #[cfg(feature = "blake2b_hash")]
            PrivateKey::Blake2b(blake2b_private_key) => {
                self.blake2b_private_key = Some(blake2b_private_key)
            }
            PrivateKey::Null => {}
        }
        self
    }

    /// Get private key
    #[cfg(feature = "blake2b_hash")]
    pub fn blake2b_private_key(&self) -> Option<&Blake2bPrivKey> {
        self.blake2b_private_key.as_ref()
    }

    /// Get private key
    pub fn sha3_private_key(&self) -> Option<&Sha3PrivKey> {
        self.sha3_private_key.as_ref()
    }

    /// Get debug
    pub fn debug(&self) -> bool {
        self.debug
    }

    /// Set debug mode
    pub fn set_debug(mut self, mode: bool) -> Self {
        self.debug = mode;
        self
    }

    /// Send requests
    pub fn send_request(
        &mut self,
        urls: Vec<&str>,
        params: JsonRpcParams,
    ) -> Result<Vec<JsonRpcResponse>, ToolError> {
        if self.debug {
            Self::debug_request(&params)
        }
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
        url: &str,
        code: &str,
        address: &str,
        current_height: Option<u64>,
        quota: Option<u64>,
        value: Option<u64>,
    ) -> Result<String, ToolError> {
        let data = decode(code).unwrap();
        let current_height = current_height.unwrap_or(self.get_current_height(url)?.unwrap());

        let mut tx = Transaction::new();
        tx.set_data(data);
        // Create a contract if the target address is empty
        tx.set_to(address.to_string());
        tx.set_nonce(encode(Uuid::new_v4().as_bytes()));
        tx.set_valid_until_block(current_height + 88);
        tx.set_quota(quota.unwrap_or(1_000_000));
        tx.set_value(value.unwrap_or(0));
        tx.set_chain_id(self.get_chain_id(url)?);
        Ok(encode(
            tx.sha3_sign(*self.sha3_private_key().unwrap())
                .take_transaction_with_sig()
                .write_to_bytes()
                .unwrap(),
        ))
    }

    /// Constructing a UnverifiedTransaction hex string
    /// If you want to create a contract, set address to ""
    #[cfg(feature = "blake2b_hash")]
    pub fn generate_transaction_by_blake2b(
        &mut self,
        url: &str,
        code: &str,
        address: &str,
        current_height: Option<u64>,
        quota: Option<u64>,
        value: Option<u64>,
    ) -> Result<String, ToolError> {
        let data = decode(code).unwrap();
        let current_height = current_height.unwrap_or(self.get_current_height(url)?.unwrap());

        let mut tx = Transaction::new();
        tx.set_data(data);
        // Create a contract if the target address is empty
        tx.set_to(address.to_string());
        tx.set_nonce(encode(Uuid::new_v4().as_bytes()));
        tx.set_valid_until_block(current_height + 88);
        tx.set_quota(quota.unwrap_or(1_000_000));
        tx.set_value(value.unwrap_or(0));
        tx.set_chain_id(self.get_chain_id(url)?);
        Ok(encode(
            tx.blake2b_sign(*self.blake2b_private_key().unwrap())
                .take_transaction_with_sig()
                .write_to_bytes()
                .unwrap(),
        ))
    }

    /// Get chain id
    pub fn get_chain_id(&mut self, url: &str) -> Result<u32, ToolError> {
        if self.chain_id.is_some() {
            Ok(self.chain_id.unwrap())
        } else {
            if let Some(ResponseValue::Map(mut value)) = self.get_metadata(url, "latest")?.result()
            {
                match value.remove("chainId").unwrap() {
                    ParamsValue::Int(chain_id) => {
                        self.chain_id = Some(chain_id as u32);
                        return Ok(chain_id as u32);
                    }
                    _ => return Ok(0),
                }
            } else {
                Ok(0)
            }
        }
    }

    /// Get block height
    pub fn get_current_height(&mut self, url: &str) -> Result<Option<u64>, ToolError> {
        let params = JsonRpcParams::new().insert(
            "method",
            ParamsValue::String(String::from(CITA_BLOCK_BUMBER)),
        );
        let response = self.send_request(vec![url], params)?.pop().unwrap();

        if let ResponseValue::Singe(ParamsValue::String(height)) = response.result().unwrap() {
            Ok(Some(u64::from_str_radix(remove_0x(&height), 16).unwrap()))
        } else {
            Ok(None)
        }
    }

    /// Get authorities
    pub fn get_authorities(&mut self, url: &str) -> Result<Vec<String>, ToolError> {
        if let ResponseValue::Singe(ParamsValue::String(authorities)) = self.call(
            url,
            None,
            "0x00000000000000000000000000000000013241a2",
            Some("0x609df32f"),
            "latest",
        )?
            .result()
            .unwrap()
        {
            let raw_authorities = remove_0x(&authorities).as_bytes();
            let mut authorities = Vec::new();
            let mut i = 64 * 2;
            while i < raw_authorities.len() {
                authorities.push(
                    "0x".to_string() + str::from_utf8(&raw_authorities[i..i + 64][24..]).unwrap(),
                );
                i += 64;
            }
            Ok(authorities)
        } else {
            Ok(Vec::new())
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

    fn debug_request(params: &JsonRpcParams) {
        println!("<--{}", params);
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
    /// Rpc response
    type RpcResult;

    /// net_peerCount: Get network peer count
    fn get_net_peer_count(&mut self, url: &str) -> Self::RpcResult;
    /// cita_blockNumber: Get current height
    fn get_block_number(&mut self, url: &str) -> Self::RpcResult;
    /// cita_sendTransaction: Send a transaction return transaction hash
    fn send_transaction(
        &mut self,
        url: &str,
        code: &str,
        address: &str,
        current_height: Option<u64>,
        quota: Option<u64>,
        value: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult;
    /// cita_getBlockByHash: Get block by hash
    fn get_block_by_hash(
        &mut self,
        url: &str,
        hash: &str,
        transaction_info: bool,
    ) -> Self::RpcResult;
    /// cita_getBlockByNumber: Get block by number
    fn get_block_by_number(
        &mut self,
        url: &str,
        height: &str,
        transaction_info: bool,
    ) -> Self::RpcResult;
    /// eth_getTransactionReceipt: Get transaction receipt
    fn get_transaction_receipt(&mut self, url: &str, hash: &str) -> Self::RpcResult;
    /// eth_getLogs: Get logs
    fn get_logs(
        &mut self,
        url: &str,
        topic: Option<Vec<&str>>,
        address: Option<Vec<&str>>,
        from: Option<&str>,
        to: Option<&str>,
    ) -> Self::RpcResult;
    /// eth_call: (readonly, will not save state change)
    fn call(
        &mut self,
        url: &str,
        from: Option<&str>,
        to: &str,
        data: Option<&str>,
        height: &str,
    ) -> Self::RpcResult;
    /// cita_getTransaction: Get transaction by hash
    fn get_transaction(&mut self, url: &str, hash: &str) -> Self::RpcResult;
    /// eth_getTransactionCount: Get transaction count of an account
    fn get_transaction_count(&mut self, url: &str, address: &str, height: &str) -> Self::RpcResult;
    /// eth_getCode: Get the code of a contract
    fn get_code(&mut self, url: &str, address: &str, height: &str) -> Self::RpcResult;
    /// eth_getAbi: Get the ABI of a contract
    fn get_abi(&mut self, url: &str, address: &str, height: &str) -> Self::RpcResult;
    /// eth_getBalance: Get the balance of a contract (TODO: return U256)
    fn get_balance(&mut self, url: &str, address: &str, height: &str) -> Self::RpcResult;
    /// eth_newFilter:
    fn new_filter(
        &mut self,
        url: &str,
        topic: Option<Vec<&str>>,
        address: Option<Vec<&str>>,
        from: Option<&str>,
        to: Option<&str>,
    ) -> Self::RpcResult;
    /// eth_newBlockFilter:
    fn new_block_filter(&mut self, url: &str) -> Self::RpcResult;
    /// eth_uninstallFilter: Uninstall a filter by its id
    fn uninstall_filter(&mut self, url: &str, filter_id: &str) -> Self::RpcResult;
    /// eth_getFilterChanges: Get filter changes
    fn get_filter_changes(&mut self, url: &str, filter_id: &str) -> Self::RpcResult;
    /// eth_getFilterLogs: Get filter logs
    fn get_filter_logs(&mut self, url: &str, filter_id: &str) -> Self::RpcResult;
    /// cita_getTransactionProof: Get proof of a transaction
    fn get_transaction_proof(&mut self, url: &str, hash: &str) -> Self::RpcResult;
    /// cita_getMetaData: Get metadata
    fn get_metadata(&mut self, url: &str, height: &str) -> Self::RpcResult;
}

impl ClientExt for Client {
    type RpcResult = Result<JsonRpcResponse, ToolError>;

    fn get_net_peer_count(&mut self, url: &str) -> Self::RpcResult {
        let params = JsonRpcParams::new()
            .insert("method", ParamsValue::String(String::from(NET_PEER_COUNT)));
        Ok(self.send_request(vec![url], params)?.pop().unwrap())

        // match result.result().unwrap() {
        //     ResponseValue::Singe(ParamsValue::String(count)) => {
        //         u32::from_str_radix(&remove_0x(count), 16).unwrap()
        //     }
        //     _ => 0,
        // }
    }

    fn get_block_number(&mut self, url: &str) -> Self::RpcResult {
        let params = JsonRpcParams::new().insert(
            "method",
            ParamsValue::String(String::from(CITA_BLOCK_BUMBER)),
        );
        Ok(self.send_request(vec![url], params)?.pop().unwrap())

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
        current_height: Option<u64>,
        quota: Option<u64>,
        value: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult {
        let byte_code = if !blake2b {
            self.generate_transaction(url, code, address, current_height, quota, value)?
        } else {
            #[cfg(feature = "blake2b_hash")]
            let code = self.generate_transaction_by_blake2b(
                url,
                code,
                address,
                current_height,
                quota,
                value,
            )?;
            #[cfg(not(feature = "blake2b_hash"))]
            let code = String::from("");
            code
        };
        let params = JsonRpcParams::new()
            .insert(
                "method",
                ParamsValue::String(String::from(CITA_SEND_TRANSACTION)),
            )
            .insert(
                "params",
                ParamsValue::List(vec![ParamsValue::String(byte_code)]),
            );
        Ok(self.send_request(vec![url], params)?.pop().unwrap())

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
    ) -> Self::RpcResult {
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
        Ok(self.send_request(vec![url], params)?.pop().unwrap())
    }

    fn get_block_by_number(
        &mut self,
        url: &str,
        height: &str,
        transaction_info: bool,
    ) -> Self::RpcResult {
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
        Ok(self.send_request(vec![url], params)?.pop().unwrap())
    }

    fn get_transaction_receipt(&mut self, url: &str, hash: &str) -> Self::RpcResult {
        let params = JsonRpcParams::new()
            .insert(
                "method",
                ParamsValue::String(String::from(ETH_GET_TRANSACTION_RECEIPT)),
            )
            .insert(
                "params",
                ParamsValue::List(vec![ParamsValue::String(String::from(hash))]),
            );
        Ok(self.send_request(vec![url], params)?.pop().unwrap())
    }

    fn get_logs(
        &mut self,
        url: &str,
        topic: Option<Vec<&str>>,
        address: Option<Vec<&str>>,
        from: Option<&str>,
        to: Option<&str>,
    ) -> Self::RpcResult {
        let mut object = HashMap::new();
        object.insert(
            String::from("fromBlock"),
            ParamsValue::String(String::from(from.unwrap_or("latest"))),
        );
        object.insert(
            String::from("toBlock"),
            ParamsValue::String(String::from(to.unwrap_or("latest"))),
        );

        if topic.is_some() {
            object.insert(
                String::from("topics"),
                serde_json::from_str::<ParamsValue>(&serde_json::to_string(&topic).unwrap())
                    .unwrap(),
            );
        } else {
            object.insert(String::from("topics"), ParamsValue::List(Vec::new()));
        }

        object.insert(
            String::from("address"),
            serde_json::from_str::<ParamsValue>(&serde_json::to_string(&address).unwrap()).unwrap(),
        );

        let params = JsonRpcParams::new()
            .insert("method", ParamsValue::String(String::from(ETH_GET_LOGS)))
            .insert("params", ParamsValue::List(vec![ParamsValue::Map(object)]));
        Ok(self.send_request(vec![url], params)?.pop().unwrap())
    }

    fn call(
        &mut self,
        url: &str,
        from: Option<&str>,
        to: &str,
        data: Option<&str>,
        height: &str,
    ) -> Self::RpcResult {
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
            ParamsValue::Map(object),
            ParamsValue::String(String::from(height)),
        ]);
        let params = JsonRpcParams::new()
            .insert("method", ParamsValue::String(String::from(ETH_CALL)))
            .insert("params", param);

        Ok(self.send_request(vec![url], params)?.pop().unwrap())
    }

    fn get_transaction(&mut self, url: &str, hash: &str) -> Self::RpcResult {
        let params = JsonRpcParams::new()
            .insert(
                "method",
                ParamsValue::String(String::from(CITA_GET_TRANSACTION)),
            )
            .insert(
                "params",
                ParamsValue::List(vec![ParamsValue::String(String::from(hash))]),
            );

        Ok(self.send_request(vec![url], params)?.pop().unwrap())
    }

    fn get_transaction_count(&mut self, url: &str, address: &str, height: &str) -> Self::RpcResult {
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

        Ok(self.send_request(vec![url], params)?.pop().unwrap())

        // match result.result().unwrap() {
        //     ResponseValue::Singe(ParamsValue::String(count)) => {
        //         u64::from_str_radix(&remove_0x(count), 16).unwrap()
        //     }
        //     _ => 0,
        // }
    }

    fn get_code(&mut self, url: &str, address: &str, height: &str) -> Self::RpcResult {
        let params = JsonRpcParams::new()
            .insert("method", ParamsValue::String(String::from(ETH_GET_CODE)))
            .insert(
                "params",
                ParamsValue::List(vec![
                    ParamsValue::String(String::from(address)),
                    ParamsValue::String(String::from(height)),
                ]),
            );

        Ok(self.send_request(vec![url], params)?.pop().unwrap())

        // match result.result().unwrap() {
        //     ResponseValue::Singe(ParamsValue::String(code)) => code,
        //     _ => Default::default(),
        // }
    }

    fn get_abi(&mut self, url: &str, address: &str, height: &str) -> Self::RpcResult {
        let params = JsonRpcParams::new()
            .insert("method", ParamsValue::String(String::from(ETH_GET_ABI)))
            .insert(
                "params",
                ParamsValue::List(vec![
                    ParamsValue::String(String::from(address)),
                    ParamsValue::String(String::from(height)),
                ]),
            );

        Ok(self.send_request(vec![url], params)?.pop().unwrap())

        // match result.result().unwrap() {
        //     ResponseValue::Singe(ParamsValue::String(abi)) => abi,
        //     _ => Default::default(),
        // }
    }

    fn get_balance(&mut self, url: &str, address: &str, height: &str) -> Self::RpcResult {
        let params = JsonRpcParams::new()
            .insert("method", ParamsValue::String(String::from(ETH_GET_BALANCE)))
            .insert(
                "params",
                ParamsValue::List(vec![
                    ParamsValue::String(String::from(address)),
                    ParamsValue::String(String::from(height)),
                ]),
            );

        Ok(self.send_request(vec![url], params)?.pop().unwrap())

        // match result.result().unwrap() {
        //     ResponseValue::Singe(ParamsValue::String(balance)) => {
        //         u64::from_str_radix(&remove_0x(balance), 16).unwrap()
        //     }
        //     _ => 0,
        // }
    }

    fn new_filter(
        &mut self,
        url: &str,
        topic: Option<Vec<&str>>,
        address: Option<Vec<&str>>,
        from: Option<&str>,
        to: Option<&str>,
    ) -> Self::RpcResult {
        let mut object = HashMap::new();
        object.insert(
            String::from("fromBlock"),
            ParamsValue::String(String::from(from.unwrap_or("latest"))),
        );
        object.insert(
            String::from("toBlock"),
            ParamsValue::String(String::from(to.unwrap_or("latest"))),
        );
        object.insert(
            String::from("topic"),
            serde_json::from_str::<ParamsValue>(&serde_json::to_string(&topic).unwrap()).unwrap(),
        );
        object.insert(
            String::from("address"),
            serde_json::from_str::<ParamsValue>(&serde_json::to_string(&address).unwrap()).unwrap(),
        );

        let params = JsonRpcParams::new()
            .insert("method", ParamsValue::String(String::from(ETH_NEW_FILTER)))
            .insert("params", ParamsValue::List(vec![ParamsValue::Map(object)]));
        Ok(self.send_request(vec![url], params)?.pop().unwrap())

        // match result.result().unwrap() {
        //     ResponseValue::Singe(ParamsValue::String(id)) => {
        //         id
        //     }
        //     _ => Default::default(),
        // }
    }

    fn new_block_filter(&mut self, url: &str) -> Self::RpcResult {
        let params = JsonRpcParams::new().insert(
            "method",
            ParamsValue::String(String::from(ETH_NEW_BLOCK_FILTER)),
        );
        Ok(self.send_request(vec![url], params)?.pop().unwrap())

        // match result.result().unwrap() {
        //     ResponseValue::Singe(ParamsValue::String(id)) => {
        //         id
        //     }
        //     _ => Default::default(),
        // }
    }

    fn uninstall_filter(&mut self, url: &str, filter_id: &str) -> Self::RpcResult {
        let params = JsonRpcParams::new()
            .insert(
                "method",
                ParamsValue::String(String::from(ETH_UNINSTALL_FILTER)),
            )
            .insert(
                "params",
                ParamsValue::List(vec![ParamsValue::String(String::from(filter_id))]),
            );

        Ok(self.send_request(vec![url], params)?.pop().unwrap())

        // match result.result().unwrap() {
        //     ResponseValue::Singe(ParamsValue::Bool(value)) => {
        //         value
        //     }
        //     _ => false,
        // }
    }

    fn get_filter_changes(&mut self, url: &str, filter_id: &str) -> Self::RpcResult {
        let params = JsonRpcParams::new()
            .insert(
                "method",
                ParamsValue::String(String::from(ETH_GET_FILTER_CHANGES)),
            )
            .insert(
                "params",
                ParamsValue::List(vec![ParamsValue::String(String::from(filter_id))]),
            );

        Ok(self.send_request(vec![url], params)?.pop().unwrap())
    }

    fn get_filter_logs(&mut self, url: &str, filter_id: &str) -> Self::RpcResult {
        let params = JsonRpcParams::new()
            .insert(
                "method",
                ParamsValue::String(String::from(ETH_GET_FILTER_LOGS)),
            )
            .insert(
                "params",
                ParamsValue::List(vec![ParamsValue::String(String::from(filter_id))]),
            );
        Ok(self.send_request(vec![url], params)?.pop().unwrap())
    }

    fn get_transaction_proof(&mut self, url: &str, hash: &str) -> Self::RpcResult {
        let params = JsonRpcParams::new()
            .insert(
                "method",
                ParamsValue::String(String::from(CITA_GET_TRANSACTION_PROOF)),
            )
            .insert(
                "params",
                ParamsValue::List(vec![ParamsValue::String(String::from(hash))]),
            );
        Ok(self.send_request(vec![url], params)?.pop().unwrap())
    }

    fn get_metadata(&mut self, url: &str, height: &str) -> Self::RpcResult {
        let params = JsonRpcParams::new()
            .insert(
                "params",
                ParamsValue::List(vec![ParamsValue::String(String::from(height))]),
            )
            .insert(
                "method",
                ParamsValue::String(String::from(CITA_GET_META_DATA)),
            );
        Ok(self.send_request(vec![url], params)?.pop().unwrap())
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
/// let b = remove_0x(a);
/// let c = "0X0b";
/// let d = remove_0x(c);
/// assert_eq!("0b", b);
/// assert_eq!("0b", d);
/// println!("a = {}, b = {}, c = {}, d= {}", a, b, c, d);
/// ```
pub fn remove_0x(hex: &str) -> &str {
    {
        let tmp = hex.as_bytes();
        if tmp[..2] == b"0x"[..] || tmp[..2] == b"0X"[..] {
            return str::from_utf8(&tmp[2..]).unwrap();
        }
    }
    hex
}
