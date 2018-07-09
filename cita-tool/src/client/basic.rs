use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{str, u64};

use failure::Fail;
use futures::{future::join_all, future::JoinAll, Future, Stream};
use hex::{decode, encode};
use hyper::{self, Body, Client as HyperClient, Request, Uri};
use protobuf::{parse_from_bytes, Message};
use serde;
use serde_json;
use tokio::runtime::Runtime;
use uuid::Uuid;

use abi::encode_params;
use client::{remove_0x, TransactionOptions};
#[cfg(feature = "blake2b_hash")]
use crypto::Blake2bPrivKey;
use crypto::{PrivateKey, Sha3PrivKey};
use error::ToolError;
use protos::{Transaction, UnverifiedTransaction};
use rpctypes::{JsonRpcParams, JsonRpcResponse, ParamsValue, ResponseValue};

const BLOCK_NUMBER: &str = "blockNumber";
const GET_META_DATA: &str = "getMetaData";
const SEND_RAW_TRANSACTION: &str = "sendRawTransaction";
const PEER_COUNT: &str = "peerCount";
const GET_BLOCK_BY_HASH: &str = "getBlockByHash";
const GET_BLOCK_BY_NUMBER: &str = "getBlockByNumber";
const GET_TRANSACTION: &str = "getTransaction";
const GET_TRANSACTION_PROOF: &str = "getTransactionProof";

const GET_TRANSACTION_RECEIPT: &str = "getTransactionReceipt";
const GET_LOGS: &str = "getLogs";
const CALL: &str = "call";
const GET_TRANSACTION_COUNT: &str = "getTransactionCount";
const GET_CODE: &str = "getCode";
const GET_ABI: &str = "getAbi";
const GET_BALANCE: &str = "getBalance";

const NEW_FILTER: &str = "newFilter";
const NEW_BLOCK_FILTER: &str = "newBlockFilter";
const UNINSTALL_FILTER: &str = "uninstallFilter";
const GET_FILTER_CHANGES: &str = "getFilterChanges";
const GET_FILTER_LOGS: &str = "getFilterLogs";

/// Store action target address
pub const STORE_ADDRESS: &str = "0xffffffffffffffffffffffffffffffffff010000";
/// StoreAbi action target address
pub const ABI_ADDRESS: &str = "0xffffffffffffffffffffffffffffffffff010001";
/// Amend action target address
pub const AMEND_ADDRESS: &str = "0xffffffffffffffffffffffffffffffffff010002";

/// amend the abi data
pub const AMEND_ABI: &str = "0x01";
/// amend the account code
pub const AMEND_CODE: &str = "0x02";
/// amend the kv of db
pub const AMEND_KV_H256: &str = "0x03";
/// amend get the value of db
pub const AMEND_GET_KV_H256: &str = "0x04";

/// Jsonrpc client, Only to one chain
#[derive(Debug)]
pub struct Client {
    id: AtomicUsize,
    url: Uri,
    run_time: RefCell<Runtime>,
    chain_id: Option<u32>,
    sha3_private_key: Option<Sha3PrivKey>,
    #[cfg(feature = "blake2b_hash")]
    blake2b_private_key: Option<Blake2bPrivKey>,
    debug: bool,
}

impl Client {
    /// Create a client for CITA
    pub fn new() -> Result<Self, ToolError> {
        let run_time = Runtime::new().map_err(ToolError::Stdio)?;
        Ok(Client {
            id: AtomicUsize::new(0),
            url: "http://127.0.0.1:1337".parse().unwrap(),
            run_time: RefCell::new(run_time),
            chain_id: None,
            sha3_private_key: None,
            #[cfg(feature = "blake2b_hash")]
            blake2b_private_key: None,
            debug: false,
        })
    }

    /// Set url
    /// ---
    /// When the url address is invalid, panic
    pub fn set_uri(mut self, url: &str) -> Self {
        self.url = url.parse().unwrap();
        self
    }

    /// Get url
    pub fn uri(&self) -> &Uri {
        &self.url
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
    pub fn send_request<T: Iterator<Item = JsonRpcParams>>(
        &self,
        params: T,
    ) -> Result<Vec<JsonRpcResponse>, ToolError> {
        let params = params.collect::<Vec<JsonRpcParams>>();
        if self.debug {
            Self::debug_request(params.clone().iter())
        }
        let reqs = self.make_requests_with_params_list(params.into_iter());

        self.run(reqs)
    }

    /// Send multiple params to one node
    pub fn send_request_with_multiple_url<T: Iterator<Item = Uri>>(
        &self,
        url: T,
        params: JsonRpcParams,
    ) -> Result<Vec<JsonRpcResponse>, ToolError> {
        if self.debug {
            Self::debug_request(vec![&params].into_iter());
        }
        let reqs = self.make_requests_with_all_url(url, params);

        self.run(reqs)
    }

    #[inline]
    fn make_requests_with_all_url<T: Iterator<Item = Uri>>(
        &self,
        urls: T,
        params: JsonRpcParams,
    ) -> JoinAll<Vec<Box<dyn Future<Item = hyper::Chunk, Error = ToolError> + 'static + Send>>>
    {
        self.id.fetch_add(1, Ordering::Relaxed);
        let params = params.insert(
            "id",
            ParamsValue::Int(self.id.load(Ordering::Relaxed) as u64),
        );
        let client = HyperClient::new();
        let mut reqs = Vec::new();
        urls.for_each(|url| {
            let req: Request<Body> = Request::builder()
                .uri(url)
                .method("POST")
                .body(Body::from(serde_json::to_string(&params).unwrap()))
                .unwrap();
            let future: Box<
                dyn Future<Item = hyper::Chunk, Error = ToolError> + 'static + Send,
            > = Box::new(
                client
                    .request(req)
                    .and_then(|res| res.into_body().concat2())
                    .map_err(ToolError::Hyper),
            );
            reqs.push(future);
        });
        join_all(reqs)
    }

    #[inline]
    fn make_requests_with_params_list<T: Iterator<Item = JsonRpcParams>>(
        &self,
        params: T,
    ) -> JoinAll<Vec<Box<dyn Future<Item = hyper::Chunk, Error = ToolError> + 'static + Send>>>
    {
        let client = HyperClient::new();
        let mut reqs = Vec::new();
        params
            .map(|param| {
                self.id.fetch_add(1, Ordering::Relaxed);
                param.insert(
                    "id",
                    ParamsValue::Int(self.id.load(Ordering::Relaxed) as u64),
                )
            })
            .for_each(|param| {
                let req: Request<Body> = Request::builder()
                    .uri(self.url.clone())
                    .method("POST")
                    .body(Body::from(serde_json::to_string(&param).unwrap()))
                    .unwrap();
                let future: Box<
                    dyn Future<Item = hyper::Chunk, Error = ToolError> + 'static + Send,
                > = Box::new(
                    client
                        .request(req)
                        .and_then(|res| res.into_body().concat2())
                        .map_err(ToolError::Hyper),
                );
                reqs.push(future);
            });

        join_all(reqs)
    }

    /// Constructing a Transaction
    /// If you want to create a contract, set address to "0x"
    pub fn generate_transaction(
        &mut self,
        transaction_option: TransactionOptions,
    ) -> Result<Transaction, ToolError> {
        let data = decode(remove_0x(transaction_option.code())).map_err(ToolError::Decode)?;
        let current_height = transaction_option
            .current_height()
            .unwrap_or(self.get_current_height()?.unwrap());

        let mut tx = Transaction::new();
        tx.set_data(data);
        // Create a contract if the target address is empty
        tx.set_to(remove_0x(transaction_option.address()).to_string());
        tx.set_nonce(encode(Uuid::new_v4().as_bytes()));
        tx.set_valid_until_block(current_height + 88);
        tx.set_quota(transaction_option.quota().unwrap_or(1_000_000));
        tx.set_value(
            decode(remove_0x(transaction_option.value().unwrap_or("0x")))
                .map_err(ToolError::Decode)?,
        );
        tx.set_chain_id(self.get_chain_id()?);
        Ok(tx)
    }

    /// Constructing a UnverifiedTransaction hex string
    #[inline]
    pub fn generate_sign_transaction(
        &self,
        tx: Transaction,
        blake2b: bool,
    ) -> Result<String, ToolError> {
        if blake2b {
            #[cfg(feature = "blake2b_hash")]
            {
                return Ok(format!(
                    "0x{}",
                    encode(
                        tx.blake2b_build_unverified(*self.blake2b_private_key().ok_or(
                            ToolError::Customize(
                                "The provided private key do not match the algorithm".to_string()
                            )
                        )?).write_to_bytes()
                            .map_err(ToolError::Proto)?
                    )
                ));
            }
            #[cfg(not(feature = "blake2b_hash"))]
            Err(ToolError::Customize(
                "The current version does not support ed25519 algorithm, \
                 should build with feature blake2b_hash"
                    .to_string(),
            ))
        } else {
            Ok(format!(
                "0x{}",
                encode(tx.sha3_build_unverified(*self.sha3_private_key().ok_or(
                    ToolError::Customize(
                        "The provided private key do not match the algorithm".to_string()
                    )
                )?).write_to_bytes()
                    .map_err(ToolError::Proto)?)
            ))
        }
    }

    /// Send a signed transaction
    pub fn send_signed_transaction(&mut self, param: &str) -> Result<JsonRpcResponse, ToolError> {
        let byte_code = format!(
            "0x{}",
            encode(parse_from_bytes::<UnverifiedTransaction>(
                decode(remove_0x(param))
                    .map_err(ToolError::Decode)?
                    .as_slice()
            ).map_err(ToolError::Proto)?
                .write_to_bytes()
                .map_err(ToolError::Proto)?)
        );
        let params = JsonRpcParams::new()
            .insert(
                "method",
                ParamsValue::String(String::from(SEND_RAW_TRANSACTION)),
            )
            .insert(
                "params",
                ParamsValue::List(vec![ParamsValue::String(byte_code)]),
            );
        Ok(self.send_request(vec![params].into_iter())?.pop().unwrap())
    }

    /// Send unsigned transactions
    pub fn send_transaction(
        &mut self,
        param: &str,
        blake2b: bool,
    ) -> Result<JsonRpcResponse, ToolError> {
        let tx: Transaction = parse_from_bytes(
            decode(remove_0x(param))
                .map_err(ToolError::Decode)?
                .as_slice(),
        ).map_err(ToolError::Proto)?;
        let byte_code = self.generate_sign_transaction(tx, blake2b)?;
        let params = JsonRpcParams::new()
            .insert(
                "method",
                ParamsValue::String(String::from(SEND_RAW_TRANSACTION)),
            )
            .insert(
                "params",
                ParamsValue::List(vec![ParamsValue::String(byte_code)]),
            );
        Ok(self.send_request(vec![params].into_iter())?.pop().unwrap())
    }

    /// Get chain id
    pub fn get_chain_id(&mut self) -> Result<u32, ToolError> {
        if self.chain_id.is_some() {
            Ok(self.chain_id.unwrap())
        } else {
            if let Some(ResponseValue::Map(mut value)) = self.get_metadata("latest")?.result() {
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
    pub fn get_current_height(&self) -> Result<Option<u64>, ToolError> {
        let params =
            JsonRpcParams::new().insert("method", ParamsValue::String(String::from(BLOCK_NUMBER)));
        let response = self.send_request(vec![params].into_iter())?.pop().unwrap();

        if let Some(ResponseValue::Singe(ParamsValue::String(height))) = response.result() {
            Ok(Some(u64::from_str_radix(remove_0x(&height), 16).unwrap()))
        } else {
            Err(ToolError::Customize(
                "Corresponding address does not respond".to_string(),
            ))
        }
    }

    /// Start run
    fn run(
        &self,
        reqs: JoinAll<
            Vec<Box<dyn Future<Item = hyper::Chunk, Error = ToolError> + 'static + Send>>,
        >,
    ) -> Result<Vec<JsonRpcResponse>, ToolError> {
        let responses = self.run_time.borrow_mut().block_on(reqs)?;
        Ok(responses
            .into_iter()
            .map(|response| {
                serde_json::from_slice::<JsonRpcResponse>(&response)
                    .map_err(ToolError::SerdeJson)
                    .unwrap()
            })
            .collect::<Vec<JsonRpcResponse>>())
    }

    fn debug_request<'a, T: Iterator<Item = &'a JsonRpcParams>>(params: T) {
        params.for_each(|param| {
            println!("<--{}", param);
        });
    }
}

/// High level jsonrpc call
///
/// [Documentation](https://cryptape.github.io/cita/zh/usage-guide/rpc/index.html)
///
/// JSONRPC methods:
///   * peerCount
///   * blockNumber
///   * sendTransaction
///   * getBlockByHash
///   * getBlockByNumber
///   * getTransactionReceipt
///   * getLogs
///   * call
///   * getTransaction
///   * getTransactionCount
///   * getCode
///   * getAbi
///   * getBalance
///   * newFilter
///   * newBlockFilter
///   * uninstallFilter
///   * getFilterChanges
///   * getFilterLogs
///   * getTransactionProof
///   * getMetaData
pub trait ClientExt<T, E>
where
    T: serde::Serialize + serde::Deserialize<'static> + ::std::fmt::Display,
    E: Fail,
{
    /// Rpc response
    type RpcResult;

    /// peerCount: Get network peer count
    fn get_peer_count(&self) -> Self::RpcResult;
    /// blockNumber: Get current height
    fn get_block_number(&self) -> Self::RpcResult;
    /// sendTransaction: Send a transaction return transaction hash
    fn send_raw_transaction(
        &mut self,
        transaction_option: TransactionOptions,
        blake2b: bool,
    ) -> Self::RpcResult;
    /// getBlockByHash: Get block by hash
    fn get_block_by_hash(&self, hash: &str, transaction_info: bool) -> Self::RpcResult;
    /// getBlockByNumber: Get block by number
    fn get_block_by_number(&self, height: &str, transaction_info: bool) -> Self::RpcResult;
    /// getTransactionReceipt: Get transaction receipt
    fn get_transaction_receipt(&self, hash: &str) -> Self::RpcResult;
    /// getLogs: Get logs
    fn get_logs(
        &self,
        topic: Option<Vec<&str>>,
        address: Option<Vec<&str>>,
        from: Option<&str>,
        to: Option<&str>,
    ) -> Self::RpcResult;
    /// call: (readonly, will not save state change)
    fn call(
        &self,
        from: Option<&str>,
        to: &str,
        data: Option<&str>,
        height: &str,
    ) -> Self::RpcResult;
    /// getTransaction: Get transaction by hash
    fn get_transaction(&self, hash: &str) -> Self::RpcResult;
    /// getTransactionCount: Get transaction count of an account
    fn get_transaction_count(&self, address: &str, height: &str) -> Self::RpcResult;
    /// getCode: Get the code of a contract
    fn get_code(&self, address: &str, height: &str) -> Self::RpcResult;
    /// getAbi: Get the ABI of a contract
    fn get_abi(&self, address: &str, height: &str) -> Self::RpcResult;
    /// getBalance: Get the balance of a contract (TODO: return U256)
    fn get_balance(&self, address: &str, height: &str) -> Self::RpcResult;
    /// newFilter:
    fn new_filter(
        &self,
        topic: Option<Vec<&str>>,
        address: Option<Vec<&str>>,
        from: Option<&str>,
        to: Option<&str>,
    ) -> Self::RpcResult;
    /// newBlockFilter:
    fn new_block_filter(&self) -> Self::RpcResult;
    /// uninstallFilter: Uninstall a filter by its id
    fn uninstall_filter(&self, filter_id: &str) -> Self::RpcResult;
    /// getFilterChanges: Get filter changes
    fn get_filter_changes(&self, filter_id: &str) -> Self::RpcResult;
    /// getFilterLogs: Get filter logs
    fn get_filter_logs(&self, filter_id: &str) -> Self::RpcResult;
    /// getTransactionProof: Get proof of a transaction
    fn get_transaction_proof(&self, hash: &str) -> Self::RpcResult;
    /// getMetaData: Get metadata
    fn get_metadata(&self, height: &str) -> Self::RpcResult;
}

impl ClientExt<JsonRpcResponse, ToolError> for Client {
    type RpcResult = Result<JsonRpcResponse, ToolError>;

    fn get_peer_count(&self) -> Self::RpcResult {
        let params =
            JsonRpcParams::new().insert("method", ParamsValue::String(String::from(PEER_COUNT)));
        Ok(self.send_request(vec![params].into_iter())?.pop().unwrap())
    }

    fn get_block_number(&self) -> Self::RpcResult {
        let params =
            JsonRpcParams::new().insert("method", ParamsValue::String(String::from(BLOCK_NUMBER)));
        Ok(self.send_request(vec![params].into_iter())?.pop().unwrap())
    }

    fn send_raw_transaction(
        &mut self,
        transaction_option: TransactionOptions,
        blake2b: bool,
    ) -> Self::RpcResult {
        let tx = self.generate_transaction(transaction_option)?;
        let byte_code = self.generate_sign_transaction(tx, blake2b)?;
        Ok(self.send_signed_transaction(&byte_code)?)
    }

    fn get_block_by_hash(&self, hash: &str, transaction_info: bool) -> Self::RpcResult {
        let params = JsonRpcParams::new()
            .insert(
                "method",
                ParamsValue::String(String::from(GET_BLOCK_BY_HASH)),
            )
            .insert(
                "params",
                ParamsValue::List(vec![
                    ParamsValue::String(String::from(hash)),
                    ParamsValue::Bool(transaction_info),
                ]),
            );
        Ok(self.send_request(vec![params].into_iter())?.pop().unwrap())
    }

    fn get_block_by_number(&self, height: &str, transaction_info: bool) -> Self::RpcResult {
        let params = JsonRpcParams::new()
            .insert(
                "method",
                ParamsValue::String(String::from(GET_BLOCK_BY_NUMBER)),
            )
            .insert(
                "params",
                ParamsValue::List(vec![
                    ParamsValue::String(String::from(height)),
                    ParamsValue::Bool(transaction_info),
                ]),
            );
        Ok(self.send_request(vec![params].into_iter())?.pop().unwrap())
    }

    fn get_transaction_receipt(&self, hash: &str) -> Self::RpcResult {
        let params = JsonRpcParams::new()
            .insert(
                "method",
                ParamsValue::String(String::from(GET_TRANSACTION_RECEIPT)),
            )
            .insert(
                "params",
                ParamsValue::List(vec![ParamsValue::String(String::from(hash))]),
            );
        Ok(self.send_request(vec![params].into_iter())?.pop().unwrap())
    }

    fn get_logs(
        &self,
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
            .insert("method", ParamsValue::String(String::from(GET_LOGS)))
            .insert("params", ParamsValue::List(vec![ParamsValue::Map(object)]));
        Ok(self.send_request(vec![params].into_iter())?.pop().unwrap())
    }

    fn call(
        &self,
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
            .insert("method", ParamsValue::String(String::from(CALL)))
            .insert("params", param);

        Ok(self.send_request(vec![params].into_iter())?.pop().unwrap())
    }

    fn get_transaction(&self, hash: &str) -> Self::RpcResult {
        let params = JsonRpcParams::new()
            .insert("method", ParamsValue::String(String::from(GET_TRANSACTION)))
            .insert(
                "params",
                ParamsValue::List(vec![ParamsValue::String(String::from(hash))]),
            );

        Ok(self.send_request(vec![params].into_iter())?.pop().unwrap())
    }

    fn get_transaction_count(&self, address: &str, height: &str) -> Self::RpcResult {
        let params = JsonRpcParams::new()
            .insert(
                "method",
                ParamsValue::String(String::from(GET_TRANSACTION_COUNT)),
            )
            .insert(
                "params",
                ParamsValue::List(vec![
                    ParamsValue::String(String::from(address)),
                    ParamsValue::String(String::from(height)),
                ]),
            );

        Ok(self.send_request(vec![params].into_iter())?.pop().unwrap())
    }

    fn get_code(&self, address: &str, height: &str) -> Self::RpcResult {
        let params = JsonRpcParams::new()
            .insert("method", ParamsValue::String(String::from(GET_CODE)))
            .insert(
                "params",
                ParamsValue::List(vec![
                    ParamsValue::String(String::from(address)),
                    ParamsValue::String(String::from(height)),
                ]),
            );

        Ok(self.send_request(vec![params].into_iter())?.pop().unwrap())
    }

    fn get_abi(&self, address: &str, height: &str) -> Self::RpcResult {
        let params = JsonRpcParams::new()
            .insert("method", ParamsValue::String(String::from(GET_ABI)))
            .insert(
                "params",
                ParamsValue::List(vec![
                    ParamsValue::String(String::from(address)),
                    ParamsValue::String(String::from(height)),
                ]),
            );

        Ok(self.send_request(vec![params].into_iter())?.pop().unwrap())
    }

    fn get_balance(&self, address: &str, height: &str) -> Self::RpcResult {
        let params = JsonRpcParams::new()
            .insert("method", ParamsValue::String(String::from(GET_BALANCE)))
            .insert(
                "params",
                ParamsValue::List(vec![
                    ParamsValue::String(String::from(address)),
                    ParamsValue::String(String::from(height)),
                ]),
            );

        Ok(self.send_request(vec![params].into_iter())?.pop().unwrap())
    }

    fn new_filter(
        &self,
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
            .insert("method", ParamsValue::String(String::from(NEW_FILTER)))
            .insert("params", ParamsValue::List(vec![ParamsValue::Map(object)]));
        Ok(self.send_request(vec![params].into_iter())?.pop().unwrap())
    }

    fn new_block_filter(&self) -> Self::RpcResult {
        let params = JsonRpcParams::new().insert(
            "method",
            ParamsValue::String(String::from(NEW_BLOCK_FILTER)),
        );
        Ok(self.send_request(vec![params].into_iter())?.pop().unwrap())
    }

    fn uninstall_filter(&self, filter_id: &str) -> Self::RpcResult {
        let params = JsonRpcParams::new()
            .insert(
                "method",
                ParamsValue::String(String::from(UNINSTALL_FILTER)),
            )
            .insert(
                "params",
                ParamsValue::List(vec![ParamsValue::String(String::from(filter_id))]),
            );

        Ok(self.send_request(vec![params].into_iter())?.pop().unwrap())
    }

    fn get_filter_changes(&self, filter_id: &str) -> Self::RpcResult {
        let params = JsonRpcParams::new()
            .insert(
                "method",
                ParamsValue::String(String::from(GET_FILTER_CHANGES)),
            )
            .insert(
                "params",
                ParamsValue::List(vec![ParamsValue::String(String::from(filter_id))]),
            );

        Ok(self.send_request(vec![params].into_iter())?.pop().unwrap())
    }

    fn get_filter_logs(&self, filter_id: &str) -> Self::RpcResult {
        let params = JsonRpcParams::new()
            .insert("method", ParamsValue::String(String::from(GET_FILTER_LOGS)))
            .insert(
                "params",
                ParamsValue::List(vec![ParamsValue::String(String::from(filter_id))]),
            );
        Ok(self.send_request(vec![params].into_iter())?.pop().unwrap())
    }

    fn get_transaction_proof(&self, hash: &str) -> Self::RpcResult {
        let params = JsonRpcParams::new()
            .insert(
                "method",
                ParamsValue::String(String::from(GET_TRANSACTION_PROOF)),
            )
            .insert(
                "params",
                ParamsValue::List(vec![ParamsValue::String(String::from(hash))]),
            );
        Ok(self.send_request(vec![params].into_iter())?.pop().unwrap())
    }

    fn get_metadata(&self, height: &str) -> Self::RpcResult {
        let params = JsonRpcParams::new()
            .insert(
                "params",
                ParamsValue::List(vec![ParamsValue::String(String::from(height))]),
            )
            .insert("method", ParamsValue::String(String::from(GET_META_DATA)));
        Ok(self.send_request(vec![params].into_iter())?.pop().unwrap())
    }
}

/// Store data or contract ABI to chain
pub trait StoreExt: ClientExt<JsonRpcResponse, ToolError> {
    /// Store data to chain, data can be get back by `getTransaction` rpc call
    fn store_data(&mut self, content: &str, quota: Option<u64>, blake2b: bool) -> Self::RpcResult;

    /// Store contract ABI to chain, ABI can be get back by `getAbi` rpc call
    fn store_abi(
        &mut self,
        address: &str,
        content: String,
        quota: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult;
}

impl StoreExt for Client {
    fn store_data(&mut self, content: &str, quota: Option<u64>, blake2b: bool) -> Self::RpcResult {
        let tx_options = TransactionOptions::new()
            .set_code(content)
            .set_address(STORE_ADDRESS)
            .set_quota(quota);
        self.send_raw_transaction(tx_options, blake2b)
    }

    fn store_abi(
        &mut self,
        address: &str,
        content: String,
        quota: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult {
        let address = remove_0x(address);
        let content_abi = encode_params(&["string".to_owned()], &[content], false)?;
        let data = format!("0x{}{}", address, content_abi);
        let tx_options = TransactionOptions::new()
            .set_code(&data)
            .set_address(ABI_ADDRESS)
            .set_quota(quota);
        self.send_raw_transaction(tx_options, blake2b)
    }
}

/// Amend(Update) ABI/contract code/H256KV
pub trait AmendExt: ClientExt<JsonRpcResponse, ToolError> {
    /// Amend contract code
    fn amend_code(
        &mut self,
        address: &str,
        content: &str,
        quota: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult;

    /// Amend contract ABI
    fn amend_abi(
        &mut self,
        address: &str,
        content: String,
        quota: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult;

    /// Amend H256KV
    fn amend_h256kv(
        &mut self,
        address: &str,
        h256_key: &str,
        h256_value: &str,
        quota: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult;

    /// Amend get H256KV
    fn amend_get_h256kv(
        &mut self,
        address: &str,
        h256_key: &str,
        quota: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult;
}

impl AmendExt for Client {
    fn amend_code(
        &mut self,
        address: &str,
        content: &str,
        quota: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult {
        let address = remove_0x(address);
        let content = remove_0x(content);
        let data = format!("0x{}{}", address, content);
        let tx_options = TransactionOptions::new()
            .set_code(&data)
            .set_address(AMEND_ADDRESS)
            .set_quota(quota)
            .set_value(Some(AMEND_CODE));
        self.send_raw_transaction(tx_options, blake2b)
    }

    fn amend_abi(
        &mut self,
        address: &str,
        content: String,
        quota: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult {
        let address = remove_0x(address);
        let content_abi = encode_params(&["string".to_owned()], &[content], false)?;
        let data = format!("0x{}{}", address, content_abi);
        let tx_options = TransactionOptions::new()
            .set_code(&data)
            .set_address(AMEND_ADDRESS)
            .set_quota(quota)
            .set_value(Some(AMEND_ABI));
        self.send_raw_transaction(tx_options, blake2b)
    }

    fn amend_h256kv(
        &mut self,
        address: &str,
        h256_key: &str,
        h256_value: &str,
        quota: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult {
        let address = remove_0x(address);
        let h256_key = remove_0x(h256_key);
        let h256_value = remove_0x(h256_value);
        let data = format!("0x{}{}{}", address, h256_key, h256_value);
        let tx_options = TransactionOptions::new()
            .set_code(&data)
            .set_address(AMEND_ADDRESS)
            .set_quota(quota)
            .set_value(Some(AMEND_KV_H256));
        self.send_raw_transaction(tx_options, blake2b)
    }

    fn amend_get_h256kv(
        &mut self,
        address: &str,
        h256_key: &str,
        quota: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult {
        let address = remove_0x(address);
        let h256_key = remove_0x(h256_key);
        let data = format!("0x{}{}", address, h256_key);
        let tx_options = TransactionOptions::new()
            .set_code(&data)
            .set_address(AMEND_ADDRESS)
            .set_quota(quota)
            .set_value(Some(AMEND_GET_KV_H256));
        self.send_raw_transaction(tx_options, blake2b)
    }
}

/// Account transfer, only applies to charge mode
pub trait Transfer: ClientExt<JsonRpcResponse, ToolError> {
    /// Account transfer, only applies to charge mode
    fn transfer(
        &mut self,
        value: &str,
        address: &str,
        quota: Option<u64>,
        blake2b: bool,
    ) -> Self::RpcResult {
        let tx_options = TransactionOptions::new()
            .set_address(address)
            .set_quota(quota)
            .set_value(Some(value));
        self.send_raw_transaction(tx_options, blake2b)
    }
}

impl Transfer for Client {}
