use clap::{App, Arg, ArgMatches, SubCommand};

use cita_tool::{
    client::basic::{Client, ClientExt},
    error::ToolError,
    rpctypes::JsonRpcResponse,
    ParamsValue, ResponseValue, TransactionOptions, UnverifiedTransaction,
};

use crate::cli::{
    encryption, get_url, h256_validator, is_hex, key_validator, parse_address, parse_height,
    parse_privkey, parse_u256, parse_u32, parse_u64,
};
use crate::interactive::{set_output, GlobalConfig};
use crate::printer::Printer;
use std::str::FromStr;

/// Generate rpc sub command
pub fn rpc_command() -> App<'static, 'static> {
    App::new("rpc")
        .about("All cita jsonrpc interface commands")
        .subcommand(SubCommand::with_name("peerCount").about("Get network peer count"))
        .subcommand(SubCommand::with_name("peersInfo").about("Get all peers information"))
        .subcommand(SubCommand::with_name("blockNumber").about("Get current height"))
        .subcommand(
            SubCommand::with_name("sendRawTransaction")
                .about("Send a transaction and return transaction hash")
                .arg(
                    Arg::with_name("code")
                        .long("code")
                        .takes_value(true)
                        .required(true)
                        .validator(|code| is_hex(code.as_str()))
                        .help("Binary content of the transaction"),
                )
                .arg(
                    Arg::with_name("address")
                        .long("address")
                        .default_value("0x")
                        .takes_value(true)
                        .validator(|address| parse_address(address.as_str()))
                        .help(
                            "The address of the invoking contract, default is empty to \
                             create contract",
                        ),
                )
                .arg(
                    Arg::with_name("height")
                        .long("height")
                        .takes_value(true)
                        .validator(|height| parse_u64(height.as_ref()).map(|_| ()))
                        .help("Current chain height, default query to the chain"),
                )
                .arg(
                    Arg::with_name("chain-id")
                        .long("chain-id")
                        .takes_value(true)
                        .validator(|chain_id| parse_u256(chain_id.as_ref()).map(|_| ()))
                        .help("The chain_id of transaction"),
                )
                .arg(
                    Arg::with_name("private-key")
                        .long("private-key")
                        .takes_value(true)
                        .required(true)
                        .validator(|privkey| key_validator(privkey.as_ref()).map(|_| ()))
                        .help("The private key of transaction"),
                )
                .arg(
                    Arg::with_name("quota")
                        .long("quota")
                        .takes_value(true)
                        .validator(|quota| parse_u64(quota.as_ref()).map(|_| ()))
                        .help("Transaction quota costs, default 10_000_000"),
                )
                .arg(
                    Arg::with_name("value")
                        .long("value")
                        .takes_value(true)
                        .validator(|value| parse_u256(value.as_ref()).map(|_| ()))
                        .help("The value to send, default is 0"),
                )
                .arg(
                    Arg::with_name("version")
                        .long("version")
                        .takes_value(true)
                        .validator(|version| parse_u32(version.as_str()).map(|_| ()))
                        .help("The version of transaction, default is 0"),
                ),
        )
        .subcommand(
            SubCommand::with_name("getBlockByHash")
                .about("Get block by hash")
                .arg(
                    Arg::with_name("hash")
                        .long("hash")
                        .required(true)
                        .takes_value(true)
                        .help("The hash of the block"),
                )
                .arg(
                    Arg::with_name("with-txs")
                        .long("with-txs")
                        .help("Get transactions detail of the block"),
                ),
        )
        .subcommand(
            SubCommand::with_name("getBlockByNumber")
                .about("Get block by number")
                .arg(
                    Arg::with_name("height")
                        .long("height")
                        .required(true)
                        .validator(|s| parse_height(s.as_str()))
                        .takes_value(true)
                        .help("The number of the block"),
                )
                .arg(
                    Arg::with_name("with-txs")
                        .long("with-txs")
                        .help("Get transactions detail of the block"),
                ),
        )
        .subcommand(
            SubCommand::with_name("getCode")
                .about("Get the code of a contract")
                .arg(
                    Arg::with_name("address")
                        .long("address")
                        .required(true)
                        .validator(|address| parse_address(address.as_str()))
                        .takes_value(true)
                        .help("The address of the code"),
                )
                .arg(
                    Arg::with_name("height")
                        .long("height")
                        .default_value("latest")
                        .validator(|s| parse_height(s.as_str()))
                        .takes_value(true)
                        .help("The number of the block"),
                ),
        )
        .subcommand(
            SubCommand::with_name("getAbi")
                .about("Get the ABI of a contract")
                .arg(
                    Arg::with_name("address")
                        .long("address")
                        .required(true)
                        .validator(|address| parse_address(address.as_str()))
                        .takes_value(true)
                        .help("The address of the abi data"),
                )
                .arg(
                    Arg::with_name("height")
                        .long("height")
                        .default_value("latest")
                        .validator(|s| parse_height(s.as_str()))
                        .takes_value(true)
                        .help("The number of the block"),
                ),
        )
        .subcommand(
            SubCommand::with_name("getBalance")
                .about("Get the balance of a contract (TODO: return U256)")
                .arg(
                    Arg::with_name("address")
                        .long("address")
                        .required(true)
                        .validator(|address| parse_address(address.as_str()))
                        .takes_value(true)
                        .help("The address of the balance"),
                )
                .arg(
                    Arg::with_name("height")
                        .long("height")
                        .default_value("latest")
                        .validator(|s| parse_height(s.as_str()))
                        .takes_value(true)
                        .help("The number of the block"),
                ),
        )
        .subcommand(
            SubCommand::with_name("getTransactionReceipt")
                .about("Get transaction receipt")
                .arg(
                    Arg::with_name("hash")
                        .long("hash")
                        .required(true)
                        .takes_value(true)
                        .help("The hash of specific transaction"),
                ),
        )
        .subcommand(
            SubCommand::with_name("call")
                .about("Call a contract function (readonly, will not save state change)")
                .arg(
                    Arg::with_name("from")
                        .long("from")
                        .validator(|address| parse_address(address.as_str()))
                        .takes_value(true)
                        .help("From address"),
                )
                .arg(
                    Arg::with_name("to")
                        .long("to")
                        .validator(|address| parse_address(address.as_str()))
                        .takes_value(true)
                        .required(true)
                        .help("To address"),
                )
                .arg(
                    Arg::with_name("data")
                        .long("data")
                        .takes_value(true)
                        .help("The data"),
                )
                .arg(
                    Arg::with_name("height")
                        .long("height")
                        .takes_value(true)
                        .validator(|s| parse_height(s.as_str()))
                        .default_value("latest")
                        .help("The block number"),
                ),
        )
        .subcommand(
            SubCommand::with_name("getTransactionProof")
                .about("Get proof of a transaction")
                .arg(
                    Arg::with_name("hash")
                        .long("hash")
                        .required(true)
                        .takes_value(true)
                        .help("The hash of the transaction"),
                ),
        )
        .subcommand(
            SubCommand::with_name("getLogs")
                .about("Get logs")
                .arg(
                    Arg::with_name("topic")
                        .long("topic")
                        .takes_value(true)
                        .multiple(true)
                        .validator(|topic| is_hex(topic.as_ref()))
                        .help(
                            "Array of 32 Bytes DATA topics. Topics are order-dependent. \
                             Each topic can also be an array of DATA with 'or' options.",
                        ),
                )
                .arg(
                    Arg::with_name("address")
                        .long("address")
                        .takes_value(true)
                        .multiple(true)
                        .validator(|address| parse_address(address.as_str()))
                        .help("List of contract address"),
                )
                .arg(
                    Arg::with_name("from")
                        .long("from")
                        .takes_value(true)
                        .validator(|from| is_hex(from.as_ref()))
                        .help("Block height hex string, default is latest"),
                )
                .arg(
                    Arg::with_name("to")
                        .long("to")
                        .takes_value(true)
                        .validator(|to| is_hex(to.as_ref()))
                        .help("Block height hex string, default is latest"),
                ),
        )
        .subcommand(
            SubCommand::with_name("getMetaData")
                .about("Get metadata of current chain")
                .arg(
                    Arg::with_name("height")
                        .long("height")
                        .default_value("latest")
                        .validator(|s| parse_height(s.as_str()))
                        .takes_value(true)
                        .help("The height or tag"),
                ),
        )
        .subcommand(
            SubCommand::with_name("getTransaction")
                .about("Get transaction by hash")
                .arg(
                    Arg::with_name("hash")
                        .long("hash")
                        .required(true)
                        .takes_value(true)
                        .help("The hash of the transaction"),
                ),
        )
        .subcommand(
            SubCommand::with_name("getTransactionCount")
                .about("Get transaction count of an account")
                .arg(
                    Arg::with_name("address")
                        .long("address")
                        .required(true)
                        .validator(|address| parse_address(address.as_str()))
                        .takes_value(true)
                        .help("The hash of the account"),
                )
                .arg(
                    Arg::with_name("height")
                        .long("height")
                        .default_value("latest")
                        .validator(|s| parse_height(s.as_str()))
                        .takes_value(true)
                        .help("The height of chain, hex string or tag 'latest'"),
                ),
        )
        .subcommand(SubCommand::with_name("newBlockFilter").about("Create a block filter"))
        .subcommand(
            SubCommand::with_name("uninstallFilter")
                .about("Uninstall a filter by its id")
                .arg(
                    Arg::with_name("id")
                        .long("id")
                        .required(true)
                        .takes_value(true)
                        .validator(|id| is_hex(id.as_ref()))
                        .help("The filter id."),
                ),
        )
        .subcommand(
            SubCommand::with_name("getFilterChanges")
                .about("Get filter changes")
                .arg(
                    Arg::with_name("id")
                        .long("id")
                        .required(true)
                        .takes_value(true)
                        .validator(|id| is_hex(id.as_ref()))
                        .help("The filter id."),
                ),
        )
        .subcommand(
            SubCommand::with_name("getFilterLogs")
                .about("Get filter logs")
                .arg(
                    Arg::with_name("id")
                        .long("id")
                        .required(true)
                        .takes_value(true)
                        .validator(|id| is_hex(id.as_ref()))
                        .help("The filter id."),
                ),
        )
        .subcommand(
            SubCommand::with_name("newFilter")
                .about("Create a filter object")
                .arg(
                    Arg::with_name("address")
                        .long("address")
                        .validator(|address| parse_address(address.as_str()))
                        .takes_value(true)
                        .multiple(true)
                        .help("Contract Address"),
                )
                .arg(
                    Arg::with_name("topic")
                        .long("topic")
                        .validator(|address| is_hex(address.as_ref()))
                        .takes_value(true)
                        .multiple(true)
                        .help("Topic"),
                )
                .arg(
                    Arg::with_name("from")
                        .long("from")
                        .validator(|from| parse_height(from.as_ref()))
                        .takes_value(true)
                        .help("Starting block height"),
                )
                .arg(
                    Arg::with_name("to")
                        .long("to")
                        .validator(|from| parse_height(from.as_ref()))
                        .takes_value(true)
                        .help("Starting block height"),
                ),
        )
        .subcommand(
            SubCommand::with_name("getBlockHeader")
                .about("Get block headers based on block height")
                .arg(
                    Arg::with_name("height")
                        .long("height")
                        .default_value("latest")
                        .validator(|s| parse_height(s.as_str()))
                        .takes_value(true)
                        .help("The number of the block"),
                ),
        )
        .subcommand(
            SubCommand::with_name("getStateProof")
                .about("Get the proof of the variable at the specified height")
                .arg(
                    Arg::with_name("height")
                        .long("height")
                        .required(true)
                        .validator(|s| parse_height(s.as_str()))
                        .default_value("latest")
                        .help("The number of the block"),
                )
                .arg(
                    Arg::with_name("address")
                        .long("address")
                        .required(true)
                        .validator(|address| parse_address(address.as_str()))
                        .takes_value(true)
                        .help("Contract Address"),
                )
                .arg(
                    Arg::with_name("key")
                        .long("key")
                        .required(true)
                        .takes_value(true)
                        .validator(|key| h256_validator(key.as_str()))
                        .help("The position of the variable"),
                ),
        )
        .subcommand(
            SubCommand::with_name("getStorageAt")
                .about("Get the value of the key at the specified height")
                .arg(
                    Arg::with_name("height")
                        .long("height")
                        .default_value("latest")
                        .validator(|s| parse_height(s.as_str()))
                        .takes_value(true)
                        .help("The number of the block"),
                )
                .arg(
                    Arg::with_name("address")
                        .long("address")
                        .required(true)
                        .validator(|address| parse_address(address.as_str()))
                        .takes_value(true)
                        .help("Account Address"),
                )
                .arg(
                    Arg::with_name("key")
                        .long("key")
                        .required(true)
                        .takes_value(true)
                        .validator(|key| h256_validator(key.as_str()))
                        .help("The position of the variable"),
                ),
        )
        .subcommand(
            SubCommand::with_name("getVersion").about("Get release version info of all modules"),
        )
        .subcommand(
            SubCommand::with_name("estimateQuota")
                .about("Estimate a transaction's quota used.")
                .arg(
                    Arg::with_name("from")
                        .long("from")
                        .validator(|address| parse_address(address.as_str()))
                        .takes_value(true)
                        .help("From address"),
                )
                .arg(
                    Arg::with_name("to")
                        .long("to")
                        .validator(|address| parse_address(address.as_str()))
                        .takes_value(true)
                        .required(true)
                        .help("To address"),
                )
                .arg(
                    Arg::with_name("data")
                        .long("data")
                        .takes_value(true)
                        .help("The data"),
                )
                .arg(
                    Arg::with_name("height")
                        .long("height")
                        .takes_value(true)
                        .validator(|s| parse_height(s.as_str()))
                        .default_value("latest")
                        .help("The block number"),
                ),
        )
}

/// RPC processor
pub fn rpc_processor(
    sub_matches: &ArgMatches,
    printer: &Printer,
    config: &mut GlobalConfig,
    client: Client,
) -> Result<(), String> {
    let debug = sub_matches.is_present("debug") || config.debug();
    let is_color = !sub_matches.is_present("no-color") && config.color();
    let mut client = client
        .set_debug(debug)
        .set_uri(get_url(sub_matches, config));

    let result = match sub_matches.subcommand() {
        ("peerCount", _) => client.get_peer_count(),
        ("peersInfo", _) => client.get_peers_info(),
        ("blockNumber", _) => client.get_block_number(),
        ("sendRawTransaction", Some(m)) => {
            let encryption = encryption(m, config);

            if let Some(chain_id) = m.value_of("chain-id").map(|s| parse_u256(s).unwrap()) {
                client.set_chain_id(chain_id);
            }
            if let Some(private_key) = m.value_of("private-key") {
                client.set_private_key(&parse_privkey(private_key, encryption)?);
            }
            let code = m.value_of("code").unwrap();
            let address = m.value_of("address").unwrap();
            let current_height = m.value_of("height").map(|s| parse_u64(s).unwrap());
            let quota = m.value_of("quota").map(|s| parse_u64(s).unwrap());
            let value = m.value_of("value").map(|value| parse_u256(value).unwrap());
            let version = m
                .value_of("version")
                .map(|version| parse_u32(version).unwrap());
            let tx_options = TransactionOptions::new()
                .set_code(code)
                .set_address(address)
                .set_current_height(current_height)
                .set_quota(quota)
                .set_value(value)
                .set_version(version);
            client.send_raw_transaction(tx_options)
        }
        ("getBlockByHash", Some(m)) => {
            let hash = m.value_of("hash").unwrap();
            let with_txs = m.is_present("with-txs");
            client.get_block_by_hash(hash, with_txs)
        }
        ("getBlockByNumber", Some(m)) => {
            let height = m.value_of("height").unwrap();
            let with_txs = m.is_present("with-txs");
            client.get_block_by_number(height, with_txs)
        }
        ("getCode", Some(m)) => client.get_code(
            m.value_of("address").unwrap(),
            m.value_of("height").unwrap(),
        ),
        ("getAbi", Some(m)) => client.get_abi(
            m.value_of("address").unwrap(),
            m.value_of("height").unwrap(),
        ),
        ("getBalance", Some(m)) => client.get_balance(
            m.value_of("address").unwrap(),
            m.value_of("height").unwrap(),
        ),
        ("getTransactionReceipt", Some(m)) => {
            let hash = m.value_of("hash").unwrap();
            client.get_transaction_receipt(hash)
        }
        ("call", Some(m)) => client.call(
            m.value_of("from"),
            m.value_of("to").unwrap(),
            m.value_of("data"),
            m.value_of("height").unwrap(),
        ),
        ("getTransactionProof", Some(m)) => {
            client.get_transaction_proof(m.value_of("hash").unwrap())
        }
        ("getMetaData", Some(m)) => {
            let height = m.value_of("height").unwrap();
            client.get_metadata(height)
        }
        ("getLogs", Some(m)) => client.get_logs(
            m.values_of("topic").map(Iterator::collect),
            m.values_of("address").map(Iterator::collect),
            m.value_of("from"),
            m.value_of("to"),
        ),
        ("getTransaction", Some(m)) => {
            let encryption = encryption(m, config);
            let hash = m.value_of("hash").unwrap();
            let result = client.get_transaction(hash);
            if debug {
                if let Ok(ref resp) = result {
                    if let Some(ResponseValue::Map(map)) = resp.result() {
                        if let Some(ParamsValue::String(content)) = map.get("content") {
                            let tx = UnverifiedTransaction::from_str(&content).unwrap();
                            printer
                                .println(&"---- [UnverifiedTransaction] ----".to_owned(), is_color);
                            printer.println(&tx.to_json(encryption)?, is_color);
                            printer.println(
                                &"---- [UnverifiedTransaction] ----\n".to_owned(),
                                is_color,
                            );
                        }
                    }
                }
            }
            result
        }
        ("getTransactionCount", Some(m)) => {
            let address = m.value_of("address").unwrap();
            let height = m.value_of("height").unwrap();
            client.get_transaction_count(address, height)
        }
        ("newBlockFilter", _) => client.new_block_filter(),
        ("uninstallFilter", Some(m)) => client.uninstall_filter(m.value_of("id").unwrap()),
        ("getFilterChanges", Some(m)) => client.get_filter_changes(m.value_of("id").unwrap()),
        ("getFilterLogs", Some(m)) => client.get_filter_logs(m.value_of("id").unwrap()),
        ("newFilter", Some(m)) => {
            let address = m.values_of("address").map(Iterator::collect);
            let from = m.value_of("from");
            let to = m.value_of("to");
            let topic = m.values_of("topic").map(Iterator::collect);
            client.new_filter(topic, address, from, to)
        }
        ("getBlockHeader", Some(m)) => {
            let height = m.value_of("height").unwrap();
            client.get_block_header(height)
        }
        ("getStateProof", Some(m)) => {
            let height = m.value_of("height").unwrap();
            let address = m.value_of("address").unwrap();
            let key = m.value_of("key").unwrap();
            client.get_state_proof(address, key, height)
        }
        ("getStorageAt", Some(m)) => {
            let height = m.value_of("height").unwrap();
            let address = m.value_of("address").unwrap();
            let key = m.value_of("key").unwrap();
            client.get_storage_at(address, key, height)
        }
        ("getVersion", _) => {
            <Client as ClientExt<JsonRpcResponse, ToolError>>::get_version(&client)
        }
        ("estimateQuota", Some(m)) => client.estimate_quota(
            m.value_of("from"),
            m.value_of("to").unwrap(),
            m.value_of("data"),
            m.value_of("height").unwrap(),
        ),
        _ => {
            return Err(sub_matches.usage().to_owned());
        }
    };
    let resp = result.map_err(|err| format!("{}", err))?;
    printer.println(&resp, is_color);
    set_output(&resp, config);
    Ok(())
}
