use std::collections::HashMap;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{str, u64};

use crate::LowerHex;
use failure::Fail;
use futures::{future::join_all, future::JoinAll, sync, Future, Stream};
use hex::{decode, encode};
use hyper::{client::HttpConnector, Body, Client as HyperClient, Request, Uri};
use protobuf::{parse_from_bytes, Message};
use serde;
use serde_json;
use tokio;
use types::U256;
use uuid::Uuid;

use crate::abi::encode_params;
use crate::client::{remove_0x, TransactionOptions};
use crate::crypto::PrivateKey;
use crate::error::ToolError;
use crate::protos::{Transaction, UnverifiedTransaction};
use crate::rpctypes::{JsonRpcParams, JsonRpcResponse, ParamsValue, ResponseValue};

const BLOCK_NUMBER: &str = "blockNumber";
const GET_META_DATA: &str = "getMetaData";
const SEND_RAW_TRANSACTION: &str = "sendRawTransaction";
const PEER_COUNT: &str = "peerCount";
const PEERS_INFO: &str = "peersInfo";
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

const GET_BLOCK_HEADER: &str = "getBlockHeader";
const GET_STATE_PROOF: &str = "getStateProof";
const GET_STORAGE_AT: &str = "getStorageAt";

const GET_VERSION: &str = "getVersion";

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
/// amend account balance
pub const AMEND_BALANCE: &str = "0x05";

/// Jsonrpc client, Only to one chain
pub struct Client {
    id: AtomicUsize,
    url: Uri,
    sender: sync::mpsc::UnboundedSender<Box<dyn Future<Item = (), Error = ()> + Send + 'static>>,
    chain_id: Option<U256>,
    private_key: Option<PrivateKey>,
    debug: bool,
}

impl Client {
    /// Create a client for CITA
    pub fn new() -> Self {
        let (sender, receiver) = sync::mpsc::unbounded();

        ::std::thread::spawn(move || {
            let task = receiver
                .map_err(|_| ::std::io::Error::new(::std::io::ErrorKind::Other, ""))
                .for_each(|item| {
                    tokio::spawn(item);
                    Ok(())
                })
                .map_err(|_| ());

            tokio::run(task);
        });

        Client {
            id: AtomicUsize::new(0),
            url: "http://127.0.0.1:1337".parse().unwrap(),
            sender,
            chain_id: None,
            private_key: None,
            debug: false,
        }
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
    pub fn set_chain_id(&mut self, chain_id: U256) -> &mut Self {
        self.chain_id = Some(chain_id);
        self
    }

    /// Set private key
    pub fn set_private_key(&mut self, private_key: &PrivateKey) -> &mut Self {
        match private_key {
            PrivateKey::Null => {}
            _ => self.private_key = Some(*private_key),
        }
        self
    }

    /// Get private key
    pub fn private_key(&self) -> Option<&PrivateKey> {
        self.private_key.as_ref()
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

        let reqs = self.make_requests_with_params_list(params.into_iter());

        self.run(reqs)
    }

    /// Send multiple params to one node
    pub fn send_request_with_multiple_url<T: Iterator<Item = Uri>>(
        &self,
        url: T,
        params: JsonRpcParams,
    ) -> Result<Vec<JsonRpcResponse>, ToolError> {
        let reqs = self.make_requests_with_all_url(url, params);

        self.run(reqs)
    }

    #[inline]
    fn make_requests_with_all_url<T: Iterator<Item = Uri>>(
        &self,
        urls: T,
        params: JsonRpcParams,
    ) -> JoinAll<Vec<Box<dyn Future<Item = JsonRpcResponse, Error = ToolError> + 'static + Send>>>
    {
        self.id.fetch_add(1, Ordering::Relaxed);
        let params = params.insert(
            "id",
            ParamsValue::Int(self.id.load(Ordering::Relaxed) as u64),
        );

        if self.debug {
            Self::debug_request(vec![&params].into_iter())
        }

        let client = create_client();
        let mut reqs = Vec::with_capacity(100);
        urls.for_each(|url| {
            let req: Request<Body> = Request::builder()
                .uri(url)
                .method("POST")
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_string(&params).unwrap()))
                .unwrap();
            let future: Box<
                dyn Future<Item = JsonRpcResponse, Error = ToolError> + 'static + Send,
            > = Box::new(
                client
                    .request(req)
                    .and_then(|res| res.into_body().concat2())
                    .map_err(ToolError::Hyper)
                    .and_then(|response| {
                        serde_json::from_slice::<JsonRpcResponse>(&response)
                            .map_err(ToolError::SerdeJson)
                    }),
            );
            reqs.push(future);
        });
        join_all(reqs)
    }

    #[inline]
    fn make_requests_with_params_list<T: Iterator<Item = JsonRpcParams>>(
        &self,
        params: T,
    ) -> JoinAll<Vec<Box<dyn Future<Item = JsonRpcResponse, Error = ToolError> + 'static + Send>>>
    {
        let client = create_client();
        let mut reqs = Vec::with_capacity(100);
        params
            .map(|param| {
                self.id.fetch_add(1, Ordering::Relaxed);
                let param = param.insert(
                    "id",
                    ParamsValue::Int(self.id.load(Ordering::Relaxed) as u64),
                );
                if self.debug {
                    Self::debug_request(vec![&param].into_iter())
                }
                param
            })
            .for_each(|param| {
                let req: Request<Body> = Request::builder()
                    .uri(self.url.clone())
                    .method("POST")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_string(&param).unwrap()))
                    .unwrap();
                let future: Box<
                    dyn Future<Item = JsonRpcResponse, Error = ToolError> + 'static + Send,
                > = Box::new(
                    client
                        .request(req)
                        .and_then(|res| res.into_body().concat2())
                        .map_err(ToolError::Hyper)
                        .and_then(|response| {
                            serde_json::from_slice::<JsonRpcResponse>(&response)
                                .map_err(ToolError::SerdeJson)
                        }),
                );
                reqs.push(future);
            });

        join_all(reqs)
    }

    /// Constructing a Transaction
    pub fn generate_transaction(
        &mut self,
        transaction_options: TransactionOptions,
    ) -> Result<Transaction, ToolError> {
        let data = decode(remove_0x(transaction_options.code())).map_err(ToolError::Decode)?;
        let current_height = transaction_options
            .current_height()
            .ok_or_else(|| ToolError::Customize("No height input".to_string()))
            .or_else(|_| self.get_current_height())?;

        let mut tx = Transaction::new();
        tx.set_data(data);

        tx.set_nonce(encode(Uuid::new_v4().as_bytes()));
        tx.set_valid_until_block(current_height + 88);
        tx.set_quota(transaction_options.quota().unwrap_or_else(|| 10_000_000));
        let value = transaction_options
            .value()
            .map(|value| value.completed_lower_hex())
            .unwrap_or_else(|| U256::zero().completed_lower_hex());
        tx.set_value(decode(value).map_err(ToolError::Decode)?);

        let version = transaction_options
            .version()
            .unwrap_or_else(|| self.get_version().unwrap_or_else(|_| 0));

        if version == 0 {
            // Create a contract if the target address is empty
            tx.set_to(remove_0x(transaction_options.address()).to_string());
            tx.set_chain_id(self.get_chain_id()?);
        } else if version < 3 {
            // Create a contract if the target address is empty
            tx.set_to_v1(
                decode(remove_0x(transaction_options.address())).map_err(ToolError::Decode)?,
            );
            tx.set_chain_id_v1(
                decode(self.get_chain_id_v1()?.completed_lower_hex()).map_err(ToolError::Decode)?,
            );
        } else {
            return Err(ToolError::Customize("Invalid version".to_string()));
        }

        tx.set_version(version);

        Ok(tx)
    }

    /// Constructing a UnverifiedTransaction hex string
    #[inline]
    pub fn generate_sign_transaction(&self, tx: &Transaction) -> Result<String, ToolError> {
        Ok(format!(
            "0x{}",
            encode(
                tx.build_unverified(*self.private_key().ok_or_else(|| ToolError::Customize(
                    "The provided private key do not match the algorithm".to_string(),
                ))?)
                .write_to_bytes()
                .map_err(ToolError::Proto)?
            )
        ))
    }

    /// Send a signed transaction
    pub fn send_signed_transaction(&mut self, param: &str) -> Result<JsonRpcResponse, ToolError> {
        let byte_code = format!(
            "0x{}",
            encode(
                parse_from_bytes::<UnverifiedTransaction>(
                    decode(remove_0x(param))
                        .map_err(ToolError::Decode)?
                        .as_slice()
                )
                .map_err(ToolError::Proto)?
                .write_to_bytes()
                .map_err(ToolError::Proto)?
            )
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
    pub fn send_transaction(&mut self, param: &str) -> Result<JsonRpcResponse, ToolError> {
        let tx: Transaction = parse_from_bytes(
            decode(remove_0x(param))
                .map_err(ToolError::Decode)?
                .as_slice(),
        )
        .map_err(ToolError::Proto)?;
        let byte_code = self.generate_sign_transaction(&tx)?;
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
        if self.chain_id.is_some() && self.check_chain_id() {
            Ok(self.chain_id.unwrap().low_u32())
        } else if let Some(ResponseValue::Map(mut value)) = self.get_metadata("latest")?.result() {
            match value.remove("chainId").unwrap() {
                ParamsValue::Int(chain_id) => {
                    self.chain_id = Some(U256::from(chain_id));
                    Ok(chain_id as u32)
                }
                _ => Ok(0),
            }
        } else {
            Ok(0)
        }
    }

    #[inline]
    fn check_chain_id(&self) -> bool {
        self.chain_id
            .map(|id| id > U256::from(u32::max_value()))
            .unwrap_or(false)
    }

    /// Get chain id v1
    pub fn get_chain_id_v1(&mut self) -> Result<U256, ToolError> {
        if self.chain_id.is_some() {
            Ok(self.chain_id.unwrap())
        } else if let Some(ResponseValue::Map(mut value)) = self.get_metadata("latest")?.result() {
            match value.remove("chainIdV1") {
                Some(ParamsValue::String(chain_id)) => {
                    let chain_id = U256::from_str(remove_0x(&chain_id))
                        .map_err(|e| ToolError::Customize(e.to_string()))?;
                    self.chain_id = Some(chain_id);
                    Ok(chain_id)
                }
                _ => Ok(U256::zero()),
            }
        } else {
            Ok(U256::zero())
        }
    }

    /// Get block height
    pub fn get_current_height(&self) -> Result<u64, ToolError> {
        let params =
            JsonRpcParams::new().insert("method", ParamsValue::String(String::from(BLOCK_NUMBER)));
        let response = self.send_request(vec![params].into_iter())?.pop().unwrap();

        if let Some(ResponseValue::Singe(ParamsValue::String(height))) = response.result() {
            Ok(u64::from_str_radix(remove_0x(&height), 16).map_err(ToolError::Parse)?)
        } else {
            Err(ToolError::Customize(
                "Corresponding address does not respond".to_string(),
            ))
        }
    }

    /// Get version
    pub fn get_version(&self) -> Result<u32, ToolError> {
        if let Some(ResponseValue::Singe(ParamsValue::String(version))) = self
            .call(
                None,
                "0xffffffffffffffffffffffffffffffffff020011",
                Some("0x0d8e6e2c"),
                "latest",
            )?
            .result()
        {
            Ok(u32::from_str_radix(remove_0x(&version), 16).map_err(ToolError::Parse)?)
        } else {
            Ok(0)
        }
    }

    /// Start run
    fn run(
        &self,
        reqs: JoinAll<
            Vec<Box<dyn Future<Item = JsonRpcResponse, Error = ToolError> + 'static + Send>>,
        >,
    ) -> Result<Vec<JsonRpcResponse>, ToolError> {
        let (tx, rx) = sync::oneshot::channel::<Result<Vec<JsonRpcResponse>, ToolError>>();
        let req = reqs
            .then(move |res| tx.send(res))
            .map(|_| ())
            .map_err(|_| ());
        self.sender
            .unbounded_send(Box::new(req))
            .map_err(|e| ToolError::Customize(e.to_string()))?;
        rx.wait().map_err(|e| ToolError::Customize(e.to_string()))?
    }

    fn debug_request<'a, T: Iterator<Item = &'a JsonRpcParams>>(params: T) {
        params.for_each(|param| {
            println!("<--{}", param);
        });
    }
}

impl Clone for Client {
    fn clone(&self) -> Self {
        Client {
            id: AtomicUsize::new(self.id.load(Ordering::Relaxed)),
            url: self.url.clone(),
            sender: self.sender.clone(),
            chain_id: None,
            private_key: self.private_key,
            debug: self.debug,
        }
    }
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

/// High level jsonrpc call
///
/// [Documentation](https://cryptape.github.io/cita/zh/usage-guide/rpc/index.html)
///
/// JSONRPC methods:
///   * peerCount
///   * peersInfo
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
///   * getBlockHeader
///   * getStateProof
///   * getStorageAt
///   * getVersion
pub trait ClientExt<T, E>
where
    T: serde::Serialize + serde::Deserialize<'static> + ::std::fmt::Display,
    E: Fail,
{
    /// peerCount: Get network peer count
    fn get_peer_count(&self) -> Result<T, E>;
    /// peersInfo: Get all peers information
    fn get_peers_info(&self) -> Result<T, E>;
    /// blockNumber: Get current height
    fn get_block_number(&self) -> Result<T, E>;
    /// sendTransaction: Send a transaction and return transaction hash
    fn send_raw_transaction(&mut self, transaction_option: TransactionOptions) -> Result<T, E>;
    /// getBlockByHash: Get block by hash
    fn get_block_by_hash(&self, hash: &str, transaction_info: bool) -> Result<T, E>;
    /// getBlockByNumber: Get block by number
    fn get_block_by_number(&self, height: &str, transaction_info: bool) -> Result<T, E>;
    /// getTransactionReceipt: Get transaction receipt
    fn get_transaction_receipt(&self, hash: &str) -> Result<T, E>;
    /// getLogs: Get logs
    fn get_logs(
        &self,
        topic: Option<Vec<&str>>,
        address: Option<Vec<&str>>,
        from: Option<&str>,
        to: Option<&str>,
    ) -> Result<T, E>;
    /// call: (readonly, will not save state change)
    fn call(&self, from: Option<&str>, to: &str, data: Option<&str>, height: &str) -> Result<T, E>;
    /// getTransaction: Get transaction by hash
    fn get_transaction(&self, hash: &str) -> Result<T, E>;
    /// getTransactionCount: Get transaction count of an account
    fn get_transaction_count(&self, address: &str, height: &str) -> Result<T, E>;
    /// getCode: Get the code of a contract
    fn get_code(&self, address: &str, height: &str) -> Result<T, E>;
    /// getAbi: Get the ABI of a contract
    fn get_abi(&self, address: &str, height: &str) -> Result<T, E>;
    /// getBalance: Get the balance of a contract (TODO: return U256)
    fn get_balance(&self, address: &str, height: &str) -> Result<T, E>;
    /// newFilter:
    fn new_filter(
        &self,
        topic: Option<Vec<&str>>,
        address: Option<Vec<&str>>,
        from: Option<&str>,
        to: Option<&str>,
    ) -> Result<T, E>;
    /// newBlockFilter:
    fn new_block_filter(&self) -> Result<T, E>;
    /// uninstallFilter: Uninstall a filter by its id
    fn uninstall_filter(&self, filter_id: &str) -> Result<T, E>;
    /// getFilterChanges: Get filter changes
    fn get_filter_changes(&self, filter_id: &str) -> Result<T, E>;
    /// getFilterLogs: Get filter logs
    fn get_filter_logs(&self, filter_id: &str) -> Result<T, E>;
    /// getTransactionProof: Get proof of a transaction
    fn get_transaction_proof(&self, hash: &str) -> Result<T, E>;
    /// getMetaData: Get metadata
    fn get_metadata(&self, height: &str) -> Result<T, E>;
    /// getBlockHeader: Get block headers based on block height
    fn get_block_header(&self, height: &str) -> Result<T, E>;
    /// getStateProof: Get the proof of the variable at the specified height
    fn get_state_proof(&self, address: &str, key: &str, height: &str) -> Result<T, E>;
    /// getStorageAt: Get the value of the key at the specified height
    fn get_storage_at(&self, address: &str, key: &str, height: &str) -> Result<T, E>;
    /// getVersion: Get release version info of all modules
    fn get_version(&self) -> Result<T, E>;
}

impl ClientExt<JsonRpcResponse, ToolError> for Client {
    fn get_peer_count(&self) -> Result<JsonRpcResponse, ToolError> {
        let params =
            JsonRpcParams::new().insert("method", ParamsValue::String(String::from(PEER_COUNT)));
        Ok(self.send_request(vec![params].into_iter())?.pop().unwrap())
    }

    fn get_peers_info(&self) -> Result<JsonRpcResponse, ToolError> {
        let params =
            JsonRpcParams::new().insert("method", ParamsValue::String(String::from(PEERS_INFO)));
        Ok(self.send_request(vec![params].into_iter())?.pop().unwrap())
    }

    fn get_block_number(&self) -> Result<JsonRpcResponse, ToolError> {
        let params =
            JsonRpcParams::new().insert("method", ParamsValue::String(String::from(BLOCK_NUMBER)));
        Ok(self.send_request(vec![params].into_iter())?.pop().unwrap())
    }

    fn send_raw_transaction(
        &mut self,
        transaction_option: TransactionOptions,
    ) -> Result<JsonRpcResponse, ToolError> {
        let tx = self.generate_transaction(transaction_option)?;
        let byte_code = self.generate_sign_transaction(&tx)?;
        Ok(self.send_signed_transaction(&byte_code)?)
    }

    fn get_block_by_hash(
        &self,
        hash: &str,
        transaction_info: bool,
    ) -> Result<JsonRpcResponse, ToolError> {
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

    fn get_block_by_number(
        &self,
        height: &str,
        transaction_info: bool,
    ) -> Result<JsonRpcResponse, ToolError> {
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

    fn get_transaction_receipt(&self, hash: &str) -> Result<JsonRpcResponse, ToolError> {
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
    ) -> Result<JsonRpcResponse, ToolError> {
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
    ) -> Result<JsonRpcResponse, ToolError> {
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

    fn get_transaction(&self, hash: &str) -> Result<JsonRpcResponse, ToolError> {
        let params = JsonRpcParams::new()
            .insert("method", ParamsValue::String(String::from(GET_TRANSACTION)))
            .insert(
                "params",
                ParamsValue::List(vec![ParamsValue::String(String::from(hash))]),
            );

        Ok(self.send_request(vec![params].into_iter())?.pop().unwrap())
    }

    fn get_transaction_count(
        &self,
        address: &str,
        height: &str,
    ) -> Result<JsonRpcResponse, ToolError> {
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

    fn get_code(&self, address: &str, height: &str) -> Result<JsonRpcResponse, ToolError> {
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

    fn get_abi(&self, address: &str, height: &str) -> Result<JsonRpcResponse, ToolError> {
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

    fn get_balance(&self, address: &str, height: &str) -> Result<JsonRpcResponse, ToolError> {
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
    ) -> Result<JsonRpcResponse, ToolError> {
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
            String::from("topics"),
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

    fn new_block_filter(&self) -> Result<JsonRpcResponse, ToolError> {
        let params = JsonRpcParams::new().insert(
            "method",
            ParamsValue::String(String::from(NEW_BLOCK_FILTER)),
        );
        Ok(self.send_request(vec![params].into_iter())?.pop().unwrap())
    }

    fn uninstall_filter(&self, filter_id: &str) -> Result<JsonRpcResponse, ToolError> {
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

    fn get_filter_changes(&self, filter_id: &str) -> Result<JsonRpcResponse, ToolError> {
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

    fn get_filter_logs(&self, filter_id: &str) -> Result<JsonRpcResponse, ToolError> {
        let params = JsonRpcParams::new()
            .insert("method", ParamsValue::String(String::from(GET_FILTER_LOGS)))
            .insert(
                "params",
                ParamsValue::List(vec![ParamsValue::String(String::from(filter_id))]),
            );
        Ok(self.send_request(vec![params].into_iter())?.pop().unwrap())
    }

    fn get_transaction_proof(&self, hash: &str) -> Result<JsonRpcResponse, ToolError> {
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

    fn get_metadata(&self, height: &str) -> Result<JsonRpcResponse, ToolError> {
        let params = JsonRpcParams::new()
            .insert(
                "params",
                ParamsValue::List(vec![ParamsValue::String(String::from(height))]),
            )
            .insert("method", ParamsValue::String(String::from(GET_META_DATA)));
        Ok(self.send_request(vec![params].into_iter())?.pop().unwrap())
    }

    fn get_block_header(&self, height: &str) -> Result<JsonRpcResponse, ToolError> {
        let params = JsonRpcParams::new()
            .insert(
                "params",
                ParamsValue::List(vec![ParamsValue::String(String::from(height))]),
            )
            .insert(
                "method",
                ParamsValue::String(String::from(GET_BLOCK_HEADER)),
            );
        Ok(self.send_request(vec![params].into_iter())?.pop().unwrap())
    }

    fn get_state_proof(
        &self,
        address: &str,
        key: &str,
        height: &str,
    ) -> Result<JsonRpcResponse, ToolError> {
        let params = JsonRpcParams::new()
            .insert(
                "params",
                ParamsValue::List(vec![
                    ParamsValue::String(String::from(address)),
                    ParamsValue::String(String::from(key)),
                    ParamsValue::String(String::from(height)),
                ]),
            )
            .insert("method", ParamsValue::String(String::from(GET_STATE_PROOF)));
        Ok(self.send_request(vec![params].into_iter())?.pop().unwrap())
    }

    fn get_storage_at(
        &self,
        address: &str,
        key: &str,
        height: &str,
    ) -> Result<JsonRpcResponse, ToolError> {
        let params = JsonRpcParams::new()
            .insert(
                "params",
                ParamsValue::List(vec![
                    ParamsValue::String(String::from(address)),
                    ParamsValue::String(String::from(key)),
                    ParamsValue::String(String::from(height)),
                ]),
            )
            .insert("method", ParamsValue::String(String::from(GET_STORAGE_AT)));
        Ok(self.send_request(vec![params].into_iter())?.pop().unwrap())
    }

    fn get_version(&self) -> Result<JsonRpcResponse, ToolError> {
        let params =
            JsonRpcParams::new().insert("method", ParamsValue::String(String::from(GET_VERSION)));
        Ok(self.send_request(vec![params].into_iter())?.pop().unwrap())
    }
}

/// Store data or contract ABI to chain
pub trait StoreExt<T, E>: ClientExt<T, E>
where
    T: serde::Serialize + serde::Deserialize<'static> + ::std::fmt::Display,
    E: Fail + From<ToolError>,
{
    /// Store data to chain, data can be get back by `getTransaction` rpc call
    fn store_data(&mut self, content: &str, quota: Option<u64>) -> Result<T, E> {
        let tx_options = TransactionOptions::new()
            .set_code(content)
            .set_address(STORE_ADDRESS)
            .set_quota(quota);
        self.send_raw_transaction(tx_options)
    }

    /// Store contract ABI to chain, ABI can be get back by `getAbi` rpc call
    fn store_abi(&mut self, address: &str, content: String, quota: Option<u64>) -> Result<T, E> {
        let address = remove_0x(address);
        let content_abi = encode_params(&["string".to_owned()], &[content], false)?;
        let data = format!("0x{}{}", address, content_abi);
        let tx_options = TransactionOptions::new()
            .set_code(&data)
            .set_address(ABI_ADDRESS)
            .set_quota(quota);
        self.send_raw_transaction(tx_options)
    }
}

impl StoreExt<JsonRpcResponse, ToolError> for Client {}

/// Amend(Update) ABI/contract code/H256KV
pub trait AmendExt<T, E>: ClientExt<T, E>
where
    T: serde::Serialize + serde::Deserialize<'static> + ::std::fmt::Display,
    E: Fail + From<ToolError>,
{
    /// Amend contract code
    fn amend_code(&mut self, address: &str, content: &str, quota: Option<u64>) -> Result<T, E> {
        let address = remove_0x(address);
        let content = remove_0x(content);
        let data = format!("0x{}{}", address, content);
        let tx_options = TransactionOptions::new()
            .set_code(&data)
            .set_address(AMEND_ADDRESS)
            .set_quota(quota)
            .set_value(Some(U256::from_str(remove_0x(AMEND_CODE)).unwrap()));
        self.send_raw_transaction(tx_options)
    }

    /// Amend contract ABI
    fn amend_abi(&mut self, address: &str, content: String, quota: Option<u64>) -> Result<T, E> {
        let address = remove_0x(address);
        let content_abi = encode_params(&["string".to_owned()], &[content], false)?;
        let data = format!("0x{}{}", address, content_abi);
        let tx_options = TransactionOptions::new()
            .set_code(&data)
            .set_address(AMEND_ADDRESS)
            .set_quota(quota)
            .set_value(Some(U256::from_str(remove_0x(AMEND_ABI)).unwrap()));
        self.send_raw_transaction(tx_options)
    }

    /// Amend H256KV
    fn amend_h256kv(&mut self, address: &str, h256_kv: &str, quota: Option<u64>) -> Result<T, E> {
        let address = remove_0x(address);
        let data = format!("0x{}{}", address, h256_kv);
        let tx_options = TransactionOptions::new()
            .set_code(&data)
            .set_address(AMEND_ADDRESS)
            .set_quota(quota)
            .set_value(Some(U256::from_str(remove_0x(AMEND_KV_H256)).unwrap()));
        self.send_raw_transaction(tx_options)
    }

    /// Amend account balance
    fn amend_balance(&mut self, address: &str, balance: U256, quota: Option<u64>) -> Result<T, E> {
        let address = remove_0x(address);
        let data = format!("0x{}{}", address, balance.completed_lower_hex());
        let tx_options = TransactionOptions::new()
            .set_code(&data)
            .set_address(AMEND_ADDRESS)
            .set_quota(quota)
            .set_value(Some(U256::from_str(remove_0x(AMEND_BALANCE)).unwrap()));
        self.send_raw_transaction(tx_options)
    }
}

impl AmendExt<JsonRpcResponse, ToolError> for Client {}

/// Account transfer, only applies to charge mode
pub trait Transfer<T, E>: ClientExt<T, E>
where
    T: serde::Serialize + serde::Deserialize<'static> + ::std::fmt::Display,
    E: Fail,
{
    /// Account transfer, only applies to charge mode
    fn transfer(&mut self, value: U256, address: &str, quota: Option<u64>) -> Result<T, E> {
        let tx_options = TransactionOptions::new()
            .set_address(address)
            .set_quota(quota)
            .set_value(Some(value));
        self.send_raw_transaction(tx_options)
    }
}

impl Transfer<JsonRpcResponse, ToolError> for Client {}

#[cfg(feature = "openssl")]
pub(crate) fn create_client() -> HyperClient<hyper_tls::HttpsConnector<HttpConnector>> {
    let https = hyper_tls::HttpsConnector::new(4).unwrap();
    HyperClient::builder().build::<_, Body>(https)
}

#[cfg(not(feature = "openssl"))]
pub(crate) fn create_client() -> HyperClient<hyper_rustls::HttpsConnector<HttpConnector>> {
    let https = hyper_rustls::HttpsConnector::new(4);
    HyperClient::builder().build::<_, Body>(https)
}
