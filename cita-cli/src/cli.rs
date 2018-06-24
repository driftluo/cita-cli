use std::fs;
use std::io::Read;

use ansi_term::Colour::Yellow;
use clap::{App, AppSettings, Arg, ArgGroup, ArgMatches, SubCommand};
use serde_json::{self, Value};

use cita_tool::{
    decode_params, encode_input, encode_params, pubkey_to_address, remove_0x, AmendExt, Client,
    ClientExt, ContractClient, ContractExt, GroupExt, GroupManagementExt, KeyPair, ParamsValue,
    PrivateKey, PubKey, ResponseValue, StoreExt, UnverifiedTransaction,
};

use interactive::GlobalConfig;
use printer::Printer;

/// Generate cli
pub fn build_cli<'a>(default_url: &'a str) -> App<'a, 'a> {
    let arg_url = Arg::with_name("url")
        .long("url")
        .default_value(default_url)
        .takes_value(true)
        .multiple(true)
        .global(true)
        .help("JSONRPC server URL (dotenv: JSONRPC_URL)");
    App::new("cita-cli")
        .version(crate_version!())
        .global_setting(AppSettings::ColoredHelp)
        .global_setting(AppSettings::DeriveDisplayOrder)
        .subcommand(rpc_command().arg(arg_url.clone()))
        .subcommand(contract_command().arg(arg_url.clone()))
        .subcommand(key_command())
        .subcommand(abi_command())
        .subcommand(transfer_command().arg(arg_url.clone()))
        .subcommand(store_command().arg(arg_url.clone()))
        .subcommand(amend_command().arg(arg_url.clone()))
        .arg(
            Arg::with_name("blake2b")
                .long("blake2b")
                .global(true)
                .help("Use blake2b encryption algorithm, must build with feature blake2b"),
        )
        .arg(
            Arg::with_name("no-color")
                .long("no-color")
                .global(true)
                .help("Do not highlight(color) output json"),
        )
        .arg(
            Arg::with_name("debug")
                .long("debug")
                .global(true)
                .help("Display request parameters"),
        )
}

/// Interactive parser
pub fn build_interactive() -> App<'static, 'static> {
    App::new("interactive")
        .version(crate_version!())
        .setting(AppSettings::NoBinaryName)
        .global_setting(AppSettings::ColoredHelp)
        .global_setting(AppSettings::DeriveDisplayOrder)
        .global_setting(AppSettings::DisableVersion)
        .subcommand(
            SubCommand::with_name("switch")
                .about("Switch environment variables, such as url/algorithm")
                .arg(
                    Arg::with_name("host")
                        .long("host")
                        .takes_value(true)
                        .help("Switch url"),
                )
                .arg(
                    Arg::with_name("color")
                        .long("color")
                        .help("Switching color for rpc interface"),
                )
                .arg(
                    Arg::with_name("algorithm")
                        .long("algorithm")
                        .help("Switching encryption algorithm"),
                )
                .arg(
                    Arg::with_name("debug")
                        .long("debug")
                        .help("Switching debug mode"),
                )
                .arg(
                    Arg::with_name("json")
                        .long("json")
                        .help("Switching json format"),
                ),
        )
        .subcommand(SubCommand::with_name("info").about("Display global variables"))
        .subcommand(rpc_command())
        .subcommand(key_command())
        .subcommand(abi_command())
        .subcommand(contract_command())
        .subcommand(transfer_command())
        .subcommand(store_command())
        .subcommand(amend_command())
        .subcommand(
            SubCommand::with_name("exit")
                .visible_alias("quit")
                .about("Exit the interactive interface"),
        )
}

/// Ethereum abi sub command
pub fn abi_command() -> App<'static, 'static> {
    let param_arg = Arg::with_name("param")
        .long("param")
        .takes_value(true)
        .multiple(true)
        .number_of_values(2)
        .help("Function parameters");
    let no_lenient_flag = Arg::with_name("no-lenient")
        .long("no-lenient")
        .help("Don't allow short representation of input params");

    App::new("ethabi")
        .about("ABI operation, encode parameter, generate code based on abi and parameters")
        .subcommand(
            SubCommand::with_name("encode")
                .subcommand(
                    SubCommand::with_name("function")
                        .arg(
                            Arg::with_name("file")
                                .required(true)
                                .index(1)
                                .help("ABI json file path"),
                        )
                        .arg(
                            Arg::with_name("name")
                                .required(true)
                                .index(2)
                                .help("function name"),
                        )
                        .arg(param_arg.clone().number_of_values(1).value_name("value"))
                        .arg(no_lenient_flag.clone()),
                )
                .subcommand(
                    SubCommand::with_name("params")
                        .arg(param_arg.value_names(&["type", "value"]))
                        .arg(no_lenient_flag),
                ),
        )
        .subcommand(
            SubCommand::with_name("decode").subcommand(
                SubCommand::with_name("params")
                    .arg(
                        Arg::with_name("type")
                            .long("type")
                            .takes_value(true)
                            .multiple(true)
                            .help("Decode types"),
                    )
                    .arg(
                        Arg::with_name("data")
                            .long("data")
                            .takes_value(true)
                            .help("Decode data"),
                    ),
            ),
        )
}

/// ABI processor
pub fn abi_processor(sub_matches: &ArgMatches, printer: &Printer) -> Result<(), String> {
    match sub_matches.subcommand() {
        ("encode", Some(em)) => match em.subcommand() {
            ("function", Some(m)) => {
                let file = m.value_of("file").unwrap();
                let name = m.value_of("name").unwrap();
                let lenient = !m.is_present("no-lenient");
                let values: Vec<String> = m.values_of("param")
                    .ok_or_else(|| format!("Please give at least one parameter."))?
                    .map(|s| s.to_owned())
                    .collect::<Vec<String>>();
                let output =
                    encode_input(file, name, &values, lenient).map_err(|err| format!("{}", err))?;
                printer.println(&Value::String(output), false);
            }
            ("params", Some(m)) => {
                let lenient = !m.is_present("no-lenient");
                let mut types: Vec<String> = Vec::new();
                let mut values: Vec<String> = Vec::new();
                let mut param_iter = m.values_of("param")
                    .ok_or_else(|| format!("Please give at least one parameter."))?
                    .peekable();
                while param_iter.peek().is_some() {
                    types.push(param_iter.next().unwrap().to_owned());
                    values.push(param_iter.next().unwrap().to_owned());
                }
                let output =
                    encode_params(&types, &values, lenient).map_err(|err| format!("{}", err))?;
                printer.println(&Value::String(output), false);
            }
            _ => {
                return Err(em.usage().to_owned());
            }
        },
        ("decode", Some(em)) => match em.subcommand() {
            ("params", Some(m)) => {
                let types: Vec<String> = m.values_of("type")
                    .ok_or_else(|| format!("Please give at least one parameter."))?
                    .map(|value| value.to_owned())
                    .collect();
                let data = remove_0x(m.value_of("data").unwrap());
                let output = decode_params(&types, data)
                    .map_err(|err| format!("{}", err))?
                    .iter()
                    .map(|value| serde_json::from_str(value).unwrap())
                    .collect();
                printer.println(&Value::Array(output), false);
            }
            _ => {
                return Err(em.usage().to_owned());
            }
        },
        _ => {
            return Err(sub_matches.usage().to_owned());
        }
    }
    Ok(())
}

/// Amend(Update) ABI/contract code/H256KV
pub fn amend_command() -> App<'static, 'static> {
    fn h256_validator(s: String) -> Result<(), String> {
        let s = remove_0x(s.as_str());
        if s.len() != 64 {
            Err(format!("Invalid H256 length={}", s.len()))
        } else {
            Ok(())
        }
    }

    let common_args = [
        Arg::with_name("chain-id")
            .long("chain-id")
            .takes_value(true)
            .validator(|chain_id| match chain_id.parse::<u32>() {
                Ok(_) => Ok(()),
                Err(err) => Err(format!("{:?}", err)),
            })
            .help("The chain_id of transaction"),
        Arg::with_name("admin-private-key")
            .long("admin-private-key")
            .takes_value(true)
            .required(true)
            .validator(|privkey| parse_privkey(privkey.as_ref()).map(|_| ()))
            .help("The private key of super admin"),
        Arg::with_name("quota")
            .long("quota")
            .takes_value(true)
            .validator(|quota| parse_u64(quota.as_ref()).map(|_| ()))
            .help("Transaction quota costs, default is 1_000_000"),
    ];
    App::new("amend")
        .about("Amend(update) ABI/contract code/H256KV")
        .subcommand(
            SubCommand::with_name("code")
                .about("Amend contract code")
                .arg(
                    Arg::with_name("address")
                        .long("address")
                        .required(true)
                        .takes_value(true)
                        .help("The contract address of the code"),
                )
                .arg(
                    Arg::with_name("content")
                        .long("content")
                        .takes_value(true)
                        .help("The contract code to amend"),
                )
                .args(&common_args),
        )
        .subcommand(
            SubCommand::with_name("abi")
                .about("Amend contract ABI data")
                .arg(
                    Arg::with_name("address")
                        .long("address")
                        .required(true)
                        .takes_value(true)
                        .help("The contract address of the ABI"),
                )
                .arg(
                    Arg::with_name("content")
                        .long("content")
                        .takes_value(true)
                        .help("The content of ABI data to amend (json)"),
                )
                .arg(
                    Arg::with_name("path")
                        .long("path")
                        .takes_value(true)
                        .help("The path of ABI json file to amend (.json)"),
                )
                .group(ArgGroup::with_name("the-abi").args(&["content", "path"]))
                .args(&common_args),
        )
        .subcommand(
            SubCommand::with_name("kv-h256")
                .about("Amend H256 Key,Value pair")
                .arg(
                    Arg::with_name("address")
                        .long("address")
                        .required(true)
                        .takes_value(true)
                        .help("The account address"),
                )
                .arg(
                    Arg::with_name("key")
                        .long("key")
                        .required(true)
                        .takes_value(true)
                        .validator(h256_validator)
                        .help("The key of pair"),
                )
                .arg(
                    Arg::with_name("value")
                        .long("value")
                        .required(true)
                        .takes_value(true)
                        .validator(h256_validator)
                        .help("The value of pair"),
                )
                .args(&common_args),
        )
}

/// Amend processor
pub fn amend_processor(
    sub_matches: &ArgMatches,
    printer: &Printer,
    url: Option<&str>,
    env_variable: &GlobalConfig,
) -> Result<(), String> {
    let debug = sub_matches.is_present("debug") || env_variable.debug();
    let mut client = Client::new()
        .map_err(|err| format!("{}", err))?
        .set_debug(debug);

    let result = match sub_matches.subcommand() {
        ("code", Some(m)) => {
            let blake2b = blake2b(m, env_variable);
            // TODO: this really should be fixed, private key must required
            if let Some(private_key) = m.value_of("admin-private-key") {
                client.set_private_key(parse_privkey(private_key)?);
            }
            let address = m.value_of("address").unwrap();
            let content = m.value_of("content").unwrap();
            let url = url.unwrap_or_else(|| get_url(m));
            let quota = m.value_of("quota").map(|s| s.parse::<u64>().unwrap());
            client.amend_code(url, address, content, quota, blake2b)
        }
        ("abi", Some(m)) => {
            let blake2b = blake2b(m, env_variable);
            // TODO: this really should be fixed, private key must required
            if let Some(private_key) = m.value_of("admin-private-key") {
                client.set_private_key(parse_privkey(private_key)?);
            }
            let content = match m.value_of("content") {
                Some(content) => content.to_owned(),
                None => {
                    let mut abi_content = String::new();
                    let path = m.value_of("path").unwrap();
                    let mut file = fs::File::open(path).map_err(|err| format!("{}", err))?;
                    file.read_to_string(&mut abi_content)
                        .map_err(|err| format!("{}", err))?;
                    abi_content
                }
            };
            let address = m.value_of("address").unwrap();
            let url = url.unwrap_or_else(|| get_url(m));
            let quota = m.value_of("quota").map(|s| s.parse::<u64>().unwrap());
            client.amend_abi(url, address, content, quota, blake2b)
        }
        ("kv-h256", Some(m)) => {
            let blake2b = blake2b(m, env_variable);
            // TODO: this really should be fixed, private key must required
            if let Some(private_key) = m.value_of("admin-private-key") {
                client.set_private_key(parse_privkey(private_key)?);
            }
            let url = url.unwrap_or_else(|| get_url(m));
            let address = m.value_of("address").unwrap();
            let h256_key = m.value_of("key").unwrap();
            let h256_value = m.value_of("value").unwrap();
            let quota = m.value_of("quota").map(|s| s.parse::<u64>().unwrap());
            client.amend_h256kv(url, address, h256_key, h256_value, quota, blake2b)
        }
        _ => {
            return Err(sub_matches.usage().to_owned());
        }
    };
    let resp = result.map_err(|err| format!("{}", err))?;
    let is_color = !sub_matches.is_present("no-color") && env_variable.color();
    printer.println(&resp, is_color);
    Ok(())
}

/// Store data, store contract ABI subcommand
pub fn store_command() -> App<'static, 'static> {
    let common_args = [
        Arg::with_name("chain-id")
            .long("chain-id")
            .takes_value(true)
            .validator(|chain_id| match chain_id.parse::<u32>() {
                Ok(_) => Ok(()),
                Err(err) => Err(format!("{:?}", err)),
            })
            .help("The chain_id of transaction"),
        Arg::with_name("private-key")
            .long("private-key")
            .takes_value(true)
            .required(true)
            .validator(|privkey| parse_privkey(privkey.as_ref()).map(|_| ()))
            .help("The private key of transaction"),
        Arg::with_name("quota")
            .long("quota")
            .takes_value(true)
            .validator(|quota| parse_u64(quota.as_ref()).map(|_| ()))
            .help("Transaction quota costs, default is 1_000_000"),
    ];

    App::new("store")
        .about("Store data, store contract ABI.")
        .subcommand(
            SubCommand::with_name("data")
                .about("Store data to: 0xffffffffffffffffffffffffffffffffffffffff")
                .arg(
                    Arg::with_name("content")
                        .long("content")
                        .required(true)
                        .validator(|content| is_hex(content.as_str()))
                        .takes_value(true)
                        .help("The content of data to store"),
                )
                .args(&common_args),
        )
        .subcommand(
            SubCommand::with_name("abi")
                .about("Store ABI to: 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .arg(
                    Arg::with_name("address")
                        .long("address")
                        .required(true)
                        .takes_value(true)
                        .help("The contract address of the ABI"),
                )
                .arg(
                    Arg::with_name("content")
                        .long("content")
                        .takes_value(true)
                        .help("The content of ABI data to store (json)"),
                )
                .arg(
                    Arg::with_name("path")
                        .long("path")
                        .takes_value(true)
                        .help("The path of ABI json file to store (.json)"),
                )
                .group(ArgGroup::with_name("the-abi").args(&["content", "path"]))
                .args(&common_args),
        )
}

/// Store data, store contract ABI processor
pub fn store_processor(
    sub_matches: &ArgMatches,
    printer: &Printer,
    url: Option<&str>,
    env_variable: &GlobalConfig,
) -> Result<(), String> {
    let debug = sub_matches.is_present("debug") || env_variable.debug();
    let mut client = Client::new()
        .map_err(|err| format!("{}", err))?
        .set_debug(debug);

    let result = match sub_matches.subcommand() {
        ("data", Some(m)) => {
            let blake2b = blake2b(m, env_variable);
            let url = url.unwrap_or_else(|| get_url(m));
            let quota = m.value_of("quota").map(|s| s.parse::<u64>().unwrap());
            let content = remove_0x(m.value_of("content").unwrap());
            // TODO: this really should be fixed, private key must required
            if let Some(private_key) = m.value_of("private-key") {
                client.set_private_key(parse_privkey(private_key)?);
            }
            client.store_data(url, content, quota, blake2b)
        }
        ("abi", Some(m)) => {
            let blake2b = blake2b(m, env_variable);
            let url = url.unwrap_or_else(|| get_url(m));
            let quota = m.value_of("quota").map(|s| s.parse::<u64>().unwrap());
            let content = match m.value_of("content") {
                Some(content) => content.to_owned(),
                None => {
                    let mut abi_content = String::new();
                    let path = m.value_of("path").unwrap();
                    let mut file = fs::File::open(path).map_err(|err| format!("{}", err))?;
                    file.read_to_string(&mut abi_content)
                        .map_err(|err| format!("{}", err))?;
                    abi_content
                }
            };
            let address = m.value_of("address").unwrap();
            // TODO: this really should be fixed, private key must required
            if let Some(private_key) = m.value_of("private-key") {
                client.set_private_key(parse_privkey(private_key)?);
            }
            client.store_abi(url, address, content, quota, blake2b)
        }
        _ => {
            return Err(sub_matches.usage().to_owned());
        }
    };
    let resp = result.map_err(|err| format!("{}", err))?;
    let is_color = !sub_matches.is_present("no-color") && env_variable.color();
    printer.println(&resp, is_color);
    Ok(())
}

/// Generate rpc sub command
pub fn rpc_command() -> App<'static, 'static> {
    App::new("rpc")
        .about("All cita jsonrpc interface commands")
        .subcommand(SubCommand::with_name("peerCount").about("Get network peer count"))
        .subcommand(SubCommand::with_name("blockNumber").about("Get current height"))
        .subcommand(
            SubCommand::with_name("sendRawTransaction")
                .about("Send a transaction return transaction hash")
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
                        .validator(|address| is_hex(address.as_str()))
                        .help(
                            "The address of the invoking contract, defalut is empty to \
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
                        .validator(|chain_id| match chain_id.parse::<u32>() {
                            Ok(_) => Ok(()),
                            Err(err) => Err(format!("{:?}", err)),
                        })
                        .help("The chain_id of transaction"),
                )
                .arg(
                    Arg::with_name("private-key")
                        .long("private-key")
                        .takes_value(true)
                        .required(true)
                        .validator(|privkey| parse_privkey(privkey.as_ref()).map(|_| ()))
                        .help("The private key of transaction"),
                )
                .arg(
                    Arg::with_name("quota")
                        .long("quota")
                        .takes_value(true)
                        .validator(|quota| parse_u64(quota.as_ref()).map(|_| ()))
                        .help("Transaction quota costs, default is 1_000_000"),
                )
                .arg(
                    Arg::with_name("value")
                        .long("value")
                        .takes_value(true)
                        .validator(|value| is_hex(value.as_ref()))
                        .help("The value to send, default is 0"),
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
                        .takes_value(true)
                        .help("From address"),
                )
                .arg(
                    Arg::with_name("to")
                        .long("to")
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
                        .validator(|address| is_hex(address.as_ref()))
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
                .about("Creates a filter object")
                .arg(
                    Arg::with_name("address")
                        .long("address")
                        .validator(|address| is_hex(address.as_ref()))
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
}

/// RPC processor
pub fn rpc_processor(
    sub_matches: &ArgMatches,
    printer: &Printer,
    url: Option<&str>,
    env_variable: &GlobalConfig,
) -> Result<(), String> {
    let debug = sub_matches.is_present("debug") || env_variable.debug();
    let is_color = !sub_matches.is_present("no-color") && env_variable.color();
    let mut client = Client::new()
        .map_err(|err| format!("{}", err))?
        .set_debug(debug);
    let result = match sub_matches.subcommand() {
        ("peerCount", Some(m)) => client.get_peer_count(url.unwrap_or_else(|| get_url(m))),
        ("blockNumber", Some(m)) => client.get_block_number(url.unwrap_or_else(|| get_url(m))),
        ("sendRawTransaction", Some(m)) => {
            let blake2b = blake2b(m, env_variable);

            if let Some(chain_id) = m.value_of("chain-id").map(|s| s.parse::<u32>().unwrap()) {
                client.set_chain_id(chain_id);
            }
            if let Some(private_key) = m.value_of("private-key") {
                client.set_private_key(parse_privkey(private_key)?);
            }
            let url = url.unwrap_or_else(|| get_url(m));
            let code = m.value_of("code").unwrap();
            let address = m.value_of("address").unwrap();
            let current_height = m.value_of("height").map(|s| parse_u64(s).unwrap());
            let quota = m.value_of("quota").map(|s| s.parse::<u64>().unwrap());
            let value = m.value_of("value");
            client.send_raw_transaction(url, code, address, current_height, quota, value, blake2b)
        }
        ("getBlockByHash", Some(m)) => {
            let hash = m.value_of("hash").unwrap();
            let with_txs = m.is_present("with-txs");
            client.get_block_by_hash(url.unwrap_or_else(|| get_url(m)), hash, with_txs)
        }
        ("getBlockByNumber", Some(m)) => {
            let height = m.value_of("height").unwrap();
            let with_txs = m.is_present("with-txs");
            client.get_block_by_number(url.unwrap_or_else(|| get_url(m)), height, with_txs)
        }
        ("getCode", Some(m)) => client.get_code(
            url.unwrap_or_else(|| get_url(m)),
            m.value_of("address").unwrap(),
            m.value_of("height").unwrap(),
        ),
        ("getAbi", Some(m)) => client.get_abi(
            url.unwrap_or_else(|| get_url(m)),
            m.value_of("address").unwrap(),
            m.value_of("height").unwrap(),
        ),
        ("getBalance", Some(m)) => client.get_balance(
            url.unwrap_or_else(|| get_url(m)),
            m.value_of("address").unwrap(),
            m.value_of("height").unwrap(),
        ),
        ("getTransactionReceipt", Some(m)) => {
            let hash = m.value_of("hash").unwrap();
            client.get_transaction_receipt(url.unwrap_or_else(|| get_url(m)), hash)
        }
        ("call", Some(m)) => client.call(
            url.unwrap_or_else(|| get_url(m)),
            m.value_of("from"),
            m.value_of("to").unwrap(),
            m.value_of("data"),
            m.value_of("height").unwrap(),
        ),
        ("getTransactionProof", Some(m)) => client.get_transaction_proof(
            url.unwrap_or_else(|| get_url(m)),
            m.value_of("hash").unwrap(),
        ),
        ("getMetaData", Some(m)) => {
            let height = m.value_of("height").unwrap();
            client.get_metadata(url.unwrap_or_else(|| get_url(m)), height)
        }
        ("getLogs", Some(m)) => client.get_logs(
            url.unwrap_or_else(|| get_url(m)),
            m.values_of("topic").map(|value| value.collect()),
            m.values_of("address").map(|value| value.collect()),
            m.value_of("from"),
            m.value_of("to"),
        ),
        ("getTransaction", Some(m)) => {
            let hash = m.value_of("hash").unwrap();
            let result = client.get_transaction(url.unwrap_or_else(|| get_url(m)), hash);
            if debug {
                if let Ok(ref resp) = result {
                    if let Some(ResponseValue::Map(map)) = resp.result() {
                        if let Some(ParamsValue::String(content)) = map.get("content") {
                            let tx = UnverifiedTransaction::from_str(&content).unwrap().to_json();
                            printer
                                .println(&"---- [UnverifiedTransaction] ----".to_owned(), is_color);
                            printer.println(&tx, is_color);
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
            client.get_transaction_count(url.unwrap_or_else(|| get_url(m)), address, height)
        }
        ("newBlockFilter", Some(m)) => client.new_block_filter(url.unwrap_or_else(|| get_url(m))),
        ("uninstallFilter", Some(m)) => {
            client.uninstall_filter(url.unwrap_or_else(|| get_url(m)), m.value_of("id").unwrap())
        }
        ("getFilterChanges", Some(m)) => {
            client.get_filter_changes(url.unwrap_or_else(|| get_url(m)), m.value_of("id").unwrap())
        }
        ("getFilterLogs", Some(m)) => {
            client.get_filter_logs(url.unwrap_or_else(|| get_url(m)), m.value_of("id").unwrap())
        }
        ("newFilter", Some(m)) => {
            let address = m.values_of("address").map(|value| value.collect());
            let from = m.value_of("from");
            let to = m.value_of("to");
            let topic = m.values_of("topic").map(|value| value.collect());
            let url = url.unwrap_or_else(|| get_url(m));
            client.new_filter(url, topic, address, from, to)
        }
        _ => {
            return Err(sub_matches.usage().to_owned());
        }
    };
    let resp = result.map_err(|err| format!("{}", err))?;
    printer.println(&resp, is_color);
    Ok(())
}

/// Key related commands
pub fn key_command() -> App<'static, 'static> {
    App::new("key")
        .about("Some key operations, such as generating address, public key")
        .subcommand(SubCommand::with_name("create"))
        .subcommand(
            SubCommand::with_name("from-private-key").arg(
                Arg::with_name("private-key")
                    .long("private-key")
                    .takes_value(true)
                    .required(true)
                    .validator(|privkey| parse_privkey(privkey.as_ref()).map(|_| ()))
                    .help("The private key of transaction"),
            ),
        )
        .subcommand(
            SubCommand::with_name("pub-to-address").arg(
                Arg::with_name("pubkey")
                    .long("pubkey")
                    .takes_value(true)
                    .required(true)
                    .validator(|pubkey| PubKey::from_str(remove_0x(&pubkey)).map(|_| ()))
                    .help("Pubkey"),
            ),
        )
}

/// Key processor
pub fn key_processor(
    sub_matches: &ArgMatches,
    printer: &Printer,
    env_variable: &GlobalConfig,
) -> Result<(), String> {
    match sub_matches.subcommand() {
        ("create", Some(m)) => {
            let blake2b = m.is_present("blake2b") || env_variable.blake2b();
            let key_pair = KeyPair::new(blake2b);
            let is_color = !sub_matches.is_present("no-color") && env_variable.color();
            printer.println(&key_pair, is_color);
        }
        ("from-private-key", Some(m)) => {
            let private_key = m.value_of("private-key").unwrap();
            let key_pair = KeyPair::from_str(remove_0x(private_key))?;
            let is_color = !sub_matches.is_present("no-color") && env_variable.color();
            printer.println(&key_pair, is_color);
        }
        ("pub-to-address", Some(m)) => {
            let pubkey = m.value_of("pubkey").unwrap();
            let address = pubkey_to_address(&PubKey::from_str(remove_0x(pubkey))?);
            if printer.color() {
                printer.println(
                    &format!("{} 0x{:#x}", Yellow.paint("[address]:"), address),
                    true,
                );
            } else {
                printer.println(&format!("{} 0x{:#x}", "[address]:", address), false);
            }
        }
        _ => {
            return Err(sub_matches.usage().to_owned());
        }
    }
    Ok(())
}

/// Account transfer command, only applies to charge mode
pub fn transfer_command() -> App<'static, 'static> {
    App::new("transfer")
        .about("Transfer value from address to address")
        .arg(
            Arg::with_name("address")
                .long("address")
                .takes_value(true)
                .required(true)
                .help("Transfer to address"),
        )
        .arg(
            Arg::with_name("private-key")
                .long("private-key")
                .validator(|private| parse_privkey(private.as_str()).map(|_| ()))
                .takes_value(true)
                .required(true)
                .help("Transfer Account Private Key"),
        )
        .arg(
            Arg::with_name("value")
                .long("value")
                .validator(|value| is_hex(value.as_str()))
                .takes_value(true)
                .required(true)
                .help("Transfer amount"),
        )
        .arg(
            Arg::with_name("quota")
                .long("quota")
                .default_value("1000")
                .validator(|quota| parse_u64(quota.as_str()).map(|_| ()))
                .takes_value(true)
                .help("Transaction quota costs, default 1000"),
        )
}

/// Account transfer processor
pub fn transfer_processor(
    sub_matches: &ArgMatches,
    printer: &Printer,
    url: Option<&str>,
    env_variable: &GlobalConfig,
) -> Result<(), String> {
    let debug = sub_matches.is_present("debug") || env_variable.debug();
    let mut client = Client::new()
        .map_err(|err| format!("{}", err))?
        .set_debug(debug);
    let blake2b = blake2b(sub_matches, env_variable);
    client.set_private_key(parse_privkey(sub_matches.value_of("private-key").unwrap())?);
    let url = url.unwrap_or_else(|| get_url(sub_matches));
    let address = sub_matches.value_of("address").unwrap();
    let quota = sub_matches
        .value_of("quota")
        .map(|quota| parse_u64(quota).unwrap());
    let value = sub_matches.value_of("value").unwrap();
    let is_color = !sub_matches.is_present("no-color") && env_variable.color();
    let response = client
        .transfer(url, value, address, quota, blake2b)
        .map_err(|err| format!("{}", err))?;
    printer.println(&response, is_color);
    Ok(())
}

/// System contract
pub fn contract_command() -> App<'static, 'static> {
    let group_address_arg = Arg::with_name("address")
        .long("address")
        .takes_value(true)
        .required(true)
        .validator(|address| is_hex(address.as_ref()))
        .help("Group address");
    let group_origin_arg = Arg::with_name("origin")
        .long("origin")
        .takes_value(true)
        .required(true)
        .validator(|address| is_hex(address.as_ref()))
        .help("Group origin address");
    let group_target_arg = Arg::with_name("target")
        .long("target")
        .takes_value(true)
        .required(true)
        .validator(|address| is_hex(address.as_ref()))
        .help("Group target address");
    let group_name_arg = Arg::with_name("name")
        .long("name")
        .takes_value(true)
        .required(true)
        .help("The group name");
    let group_accounts_arg = Arg::with_name("accounts")
        .long("accounts")
        .takes_value(true)
        .required(true)
        .help("Group account address list");

    App::new("scm")
        .about("System contract manager")
        .subcommand(
            SubCommand::with_name("NodeManager")
                .subcommand(SubCommand::with_name("listNode"))
                .subcommand(
                    SubCommand::with_name("getStatus").arg(
                        Arg::with_name("address")
                            .long("address")
                            .takes_value(true)
                            .required(true)
                            .validator(|address| is_hex(address.as_ref()))
                            .help("Node address"),
                    ),
                )
                .subcommand(
                    SubCommand::with_name("deleteNode")
                        .arg(
                            Arg::with_name("admin-private")
                                .long("admin-private")
                                .takes_value(true)
                                .required(true)
                                .validator(|private_key| {
                                    parse_privkey(private_key.as_ref()).map(|_| ())
                                })
                                .help("Private key must be admin"),
                        )
                        .arg(
                            Arg::with_name("address")
                                .long("address")
                                .takes_value(true)
                                .required(true)
                                .validator(|address| is_hex(address.as_ref()))
                                .help("Degraded node address"),
                        ),
                )
                .subcommand(
                    SubCommand::with_name("newNode")
                        .arg(
                            Arg::with_name("private")
                                .long("private")
                                .takes_value(true)
                                .required(true)
                                .validator(|private_key| {
                                    parse_privkey(private_key.as_ref()).map(|_| ())
                                })
                                .help("Private key"),
                        )
                        .arg(
                            Arg::with_name("address")
                                .long("address")
                                .takes_value(true)
                                .required(true)
                                .validator(|address| is_hex(address.as_ref()))
                                .help("node address"),
                        ),
                )
                .subcommand(
                    SubCommand::with_name("approveNode")
                        .arg(
                            Arg::with_name("admin-private")
                                .long("admin-private")
                                .takes_value(true)
                                .required(true)
                                .validator(|private_key| {
                                    parse_privkey(private_key.as_ref()).map(|_| ())
                                })
                                .help("Private key must be admin"),
                        )
                        .arg(
                            Arg::with_name("address")
                                .long("address")
                                .takes_value(true)
                                .required(true)
                                .validator(|address| is_hex(address.as_ref()))
                                .help("Approve node address"),
                        ),
                ),
        )
        .subcommand(
            SubCommand::with_name("QuotaManager")
                .subcommand(SubCommand::with_name("getBQL"))
                .subcommand(SubCommand::with_name("getDefaultAQL"))
                .subcommand(SubCommand::with_name("getAccounts"))
                .subcommand(SubCommand::with_name("getQuotas"))
                .subcommand(
                    SubCommand::with_name("getAQL").arg(
                        Arg::with_name("address")
                            .long("address")
                            .takes_value(true)
                            .required(true)
                            .validator(|address| is_hex(address.as_ref()))
                            .help("Account address"),
                    ),
                )
                .subcommand(
                    SubCommand::with_name("setBQL")
                        .arg(
                            Arg::with_name("quota")
                                .long("quota")
                                .validator(|quota| parse_u64(quota.as_str()).map(|_| ()))
                                .takes_value(true)
                                .required(true)
                                .help(
                                    "The quota value must be between 2 ** 63 - 1 and 2 ** 28 - 1",
                                ),
                        )
                        .arg(
                            Arg::with_name("admin-private")
                                .long("admin-private")
                                .takes_value(true)
                                .required(true)
                                .validator(|private_key| {
                                    parse_privkey(private_key.as_ref()).map(|_| ())
                                })
                                .help("Private key must be admin"),
                        ),
                )
                .subcommand(
                    SubCommand::with_name("setDefaultAQL")
                        .arg(
                            Arg::with_name("quota")
                                .long("quota")
                                .validator(|quota| parse_u64(quota.as_str()).map(|_| ()))
                                .takes_value(true)
                                .required(true)
                                .help(
                                    "The quota value must be between 2 ** 63 - 1 and 2 ** 22 - 1",
                                ),
                        )
                        .arg(
                            Arg::with_name("admin-private")
                                .long("admin-private")
                                .takes_value(true)
                                .required(true)
                                .validator(|private_key| {
                                    parse_privkey(private_key.as_ref()).map(|_| ())
                                })
                                .help("Private key must be admin"),
                        ),
                )
                .subcommand(
                    SubCommand::with_name("setAQL")
                        .arg(
                            Arg::with_name("quota")
                                .long("quota")
                                .validator(|quota| parse_u64(quota.as_str()).map(|_| ()))
                                .takes_value(true)
                                .required(true)
                                .help(
                                    "The quota value must be between 2 ** 63 - 1 and 2 ** 22 - 1",
                                ),
                        )
                        .arg(
                            Arg::with_name("admin-private")
                                .long("admin-private")
                                .takes_value(true)
                                .required(true)
                                .validator(|private_key| {
                                    parse_privkey(private_key.as_ref()).map(|_| ())
                                })
                                .help("Private key must be admin"),
                        )
                        .arg(
                            Arg::with_name("address")
                                .long("address")
                                .takes_value(true)
                                .required(true)
                                .validator(|address| is_hex(address.as_ref()))
                                .help("Account address"),
                        ),
                )
                .subcommand(
                    SubCommand::with_name("isAdmin").arg(
                        Arg::with_name("address")
                            .long("address")
                            .takes_value(true)
                            .required(true)
                            .validator(|address| is_hex(address.as_ref()))
                            .help("Account address"),
                    ),
                )
                .subcommand(
                    SubCommand::with_name("addAdmin")
                        .arg(
                            Arg::with_name("address")
                                .long("address")
                                .takes_value(true)
                                .required(true)
                                .validator(|address| is_hex(address.as_ref()))
                                .help("Account address"),
                        )
                        .arg(
                            Arg::with_name("admin-private")
                                .long("admin-private")
                                .takes_value(true)
                                .required(true)
                                .validator(|private_key| {
                                    parse_privkey(private_key.as_ref()).map(|_| ())
                                })
                                .help("Private key must be admin"),
                        ),
                ),
        )
        .subcommand(
            SubCommand::with_name("GroupManagement")
                .about("User management using group struct (group_management.sol)")
                .subcommand(
                    SubCommand::with_name("newGroup")
                        .arg(group_origin_arg.clone())
                        .arg(group_name_arg.clone())
                        .arg(group_accounts_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("deleteGroup")
                        .arg(group_origin_arg.clone())
                        .arg(group_target_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("updateGroupName")
                        .arg(group_origin_arg.clone())
                        .arg(group_target_arg.clone())
                        .arg(group_name_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("addAccounts")
                        .arg(group_origin_arg.clone())
                        .arg(group_target_arg.clone())
                        .arg(group_accounts_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("deleteAccounts")
                        .arg(group_origin_arg.clone())
                        .arg(group_target_arg.clone())
                        .arg(group_accounts_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("checkScope")
                        .arg(group_origin_arg.clone())
                        .arg(group_target_arg.clone()),
                )
                .subcommand(SubCommand::with_name("queryGroups")),
        )
        .subcommand(
            SubCommand::with_name("Group")
                .about("Group contract (group.sol)")
                .subcommand(
                    SubCommand::with_name("queryInfo")
                        .about("Query the information of the group")
                        .arg(group_address_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("queryName")
                        .about("Query the name of the group")
                        .arg(group_address_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("queryAccounts")
                        .about("Query the accounts of the group")
                        .arg(group_address_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("queryChild")
                        .about("Query the child of the group")
                        .arg(group_address_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("queryChildLength")
                        .about("Query the length of children of the group")
                        .arg(group_address_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("queryParent")
                        .about("Query the parent of the group")
                        .arg(group_address_arg.clone()),
                )
                .subcommand(
                    SubCommand::with_name("inGroup")
                        .about("Check the account in the group")
                        .arg(group_address_arg.clone()),
                ),
        )
}

/// System contract processor
pub fn contract_processor(
    sub_matches: &ArgMatches,
    printer: &Printer,
    url: Option<&str>,
    env_variable: &GlobalConfig,
) -> Result<(), String> {
    let debug = sub_matches.is_present("debug") || env_variable.debug();
    let mut client = Client::new()
        .map_err(|err| format!("{}", err))?
        .set_debug(debug);

    let result = match sub_matches.subcommand() {
        ("NodeManager", Some(m)) => match m.subcommand() {
            ("listNode", _) => {
                let authorities = client
                    .get_authorities(url.unwrap_or_else(|| get_url(m)))
                    .map_err(|err| format!("{}", err))?;
                let is_color = !sub_matches.is_present("no-color") && env_variable.color();
                printer.println(&json!(authorities), is_color);
                return Ok(());
            }
            ("getStatus", Some(m)) => {
                let url = url.unwrap_or_else(|| get_url(m));
                let address = m.value_of("address").unwrap();
                client.node_status(url, address)
            }
            ("deleteNode", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                client.set_private_key(parse_privkey(m.value_of("admin-private").unwrap())?);
                let url = url.unwrap_or_else(|| get_url(m));
                let address = m.value_of("address").unwrap();
                client.downgrade_consensus_node(url, address, blake2b)
            }
            ("newNode", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                client.set_private_key(parse_privkey(m.value_of("private").unwrap())?);
                let url = url.unwrap_or_else(|| get_url(m));
                let address = m.value_of("address").unwrap();
                client.new_consensus_node(url, address, blake2b)
            }
            ("approveNode", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                client.set_private_key(parse_privkey(m.value_of("admin-private").unwrap())?);
                let url = url.unwrap_or_else(|| get_url(m));
                let address = m.value_of("address").unwrap();
                client.approve_node(url, address, blake2b)
            }
            _ => return Err(m.usage().to_owned()),
        },
        ("QuotaManager", Some(m)) => match m.subcommand() {
            ("getBQL", _) => client.get_bql(url.unwrap_or_else(|| get_url(m))),
            ("getDefaultAQL", _) => client.get_default_bql(url.unwrap_or_else(|| get_url(m))),
            ("getAccounts", _) => client.get_accounts(url.unwrap_or_else(|| get_url(m))),
            ("getQuotas", _) => client.get_quotas(url.unwrap_or_else(|| get_url(m))),
            ("getAQL", Some(m)) => {
                let address = m.value_of("address").unwrap();
                let url = url.unwrap_or_else(|| get_url(m));
                client.get_aql(url, address)
            }
            ("setBQL", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                client.set_private_key(parse_privkey(m.value_of("admin-private").unwrap())?);
                let quota = parse_u64(m.value_of("quota").unwrap())?;
                let url = url.unwrap_or_else(|| get_url(m));
                client.set_bql(url, quota, blake2b)
            }
            ("setDefaultAQL", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                client.set_private_key(parse_privkey(m.value_of("admin-private").unwrap())?);
                let quota = parse_u64(m.value_of("quota").unwrap())?;
                let url = url.unwrap_or_else(|| get_url(m));
                client.set_default_aql(url, quota, blake2b)
            }
            ("setAQL", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                client.set_private_key(parse_privkey(m.value_of("admin-private").unwrap())?);
                let quota = parse_u64(m.value_of("quota").unwrap())?;
                let url = url.unwrap_or_else(|| get_url(m));
                let address = m.value_of("address").unwrap();
                client.set_aql(url, address, quota, blake2b)
            }
            ("isAdmin", Some(m)) => {
                let address = m.value_of("address").unwrap();
                let url = url.unwrap_or_else(|| get_url(m));
                client.is_admin(url, address)
            }
            ("addAdmin", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                client.set_private_key(parse_privkey(m.value_of("admin-private").unwrap())?);
                let url = url.unwrap_or_else(|| get_url(m));
                let address = m.value_of("address").unwrap();
                client.add_admin(url, address, blake2b)
            }
            _ => return Err(m.usage().to_owned()),
        },
        ("GroupManagement", Some(m)) => match m.subcommand() {
            ("newGroup", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                let url = url.unwrap_or_else(|| get_url(m));
                let origin = m.value_of("origin").unwrap();
                let name = m.value_of("name").unwrap();
                let accounts = m.value_of("accounts").unwrap();
                let mut client = ContractClient::group_management(Some(client));
                client.new_group(url, origin, name, accounts, blake2b)
            }
            ("deleteGroup", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                let url = url.unwrap_or_else(|| get_url(m));
                let origin = m.value_of("origin").unwrap();
                let target = m.value_of("target").unwrap();
                let mut client = ContractClient::group_management(Some(client));
                client.delete_group(url, origin, target, blake2b)
            }
            ("updateGroupName", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                let url = url.unwrap_or_else(|| get_url(m));
                let origin = m.value_of("origin").unwrap();
                let target = m.value_of("target").unwrap();
                let name = m.value_of("name").unwrap();
                let mut client = ContractClient::group_management(Some(client));
                client.update_group_name(url, origin, target, name, blake2b)
            }
            ("addAccounts", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                let url = url.unwrap_or_else(|| get_url(m));
                let origin = m.value_of("origin").unwrap();
                let target = m.value_of("target").unwrap();
                let accounts = m.value_of("accounts").unwrap();
                let mut client = ContractClient::group_management(Some(client));
                client.add_accounts(url, origin, target, accounts, blake2b)
            }
            ("deleteAccounts", Some(m)) => {
                let blake2b = blake2b(m, env_variable);
                let url = url.unwrap_or_else(|| get_url(m));
                let origin = m.value_of("origin").unwrap();
                let target = m.value_of("target").unwrap();
                let accounts = m.value_of("accounts").unwrap();
                let mut client = ContractClient::group_management(Some(client));
                client.delete_accounts(url, origin, target, accounts, blake2b)
            }
            ("checkScope", Some(m)) => {
                let url = url.unwrap_or_else(|| get_url(m));
                let origin = m.value_of("origin").unwrap();
                let target = m.value_of("target").unwrap();
                let mut client = ContractClient::group_management(Some(client));
                client.check_scope(url, origin, target)
            }
            ("queryGroups", Some(m)) => {
                let url = url.unwrap_or_else(|| get_url(m));
                let mut client = ContractClient::group_management(Some(client));
                client.query_groups(url)
            }
            _ => return Err(m.usage().to_owned()),
        },
        ("Group", Some(m)) => match m.subcommand() {
            ("queryInfo", Some(m)) => {
                let address = m.value_of("address").unwrap();
                let url = url.unwrap_or_else(|| get_url(m));
                client.group_query_info(url, address)
            }
            ("queryName", Some(m)) => {
                let address = m.value_of("address").unwrap();
                let url = url.unwrap_or_else(|| get_url(m));
                client.group_query_name(url, address)
            }
            ("queryAccounts", Some(m)) => {
                let address = m.value_of("address").unwrap();
                let url = url.unwrap_or_else(|| get_url(m));
                client.group_query_accounts(url, address)
            }
            ("queryChild", Some(m)) => {
                let address = m.value_of("address").unwrap();
                let url = url.unwrap_or_else(|| get_url(m));
                client.group_query_child(url, address)
            }
            ("queryChildLength", Some(m)) => {
                let address = m.value_of("address").unwrap();
                let url = url.unwrap_or_else(|| get_url(m));
                client.group_query_child_length(url, address)
            }
            ("queryParent", Some(m)) => {
                let address = m.value_of("address").unwrap();
                let url = url.unwrap_or_else(|| get_url(m));
                client.group_query_parent(url, address)
            }
            ("inGroup", Some(m)) => {
                let address = m.value_of("address").unwrap();
                let url = url.unwrap_or_else(|| get_url(m));
                client.group_in_group(url, address)
            }
            _ => return Err(m.usage().to_owned()),
        },
        _ => return Err(sub_matches.usage().to_owned()),
    };
    let is_color = !sub_matches.is_present("no-color") && env_variable.color();
    let response = result.map_err(|err| format!("{}", err))?;
    printer.println(&response, is_color);
    Ok(())
}

/// Get url from arg match
pub fn get_url<'a>(m: &'a ArgMatches) -> &'a str {
    m.value_of("url").unwrap()
}

/// The hexadecimal or numeric type string resolves to u64
fn parse_u64(height: &str) -> Result<u64, String> {
    match is_hex(height) {
        Ok(()) => Ok(u64::from_str_radix(remove_0x(height), 16).map_err(|err| format!("{}", err))?),
        _ => match height.parse::<u64>() {
            Ok(number) => Ok(number),
            Err(e) => Err(format!("{:?}", e)),
        },
    }
}

/// Attempt to resolve the private key
pub fn parse_privkey(hash: &str) -> Result<PrivateKey, String> {
    Ok(PrivateKey::from_str(remove_0x(hash))?)
}

fn is_hex(hex: &str) -> Result<(), String> {
    let tmp = hex.as_bytes();
    if tmp.len() < 2 {
        Err("Must not be a hexadecimal string".to_string())
    } else if tmp[..2] == b"0x"[..] || tmp[..2] == b"0X"[..] {
        Ok(())
    } else {
        Err("Must hex string".to_string())
    }
}

fn parse_height(height: &str) -> Result<(), String> {
    match height {
        "latest" | "earliest" => Ok(()),
        _ => match height.parse::<u64>() {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("{:?}", e)),
        },
    }
}

fn blake2b(_m: &ArgMatches, _env_variable: &GlobalConfig) -> bool {
    #[cfg(feature = "blake2b_hash")]
    let blake2b = _m.is_present("blake2b") || _env_variable.blake2b();
    #[cfg(not(feature = "blake2b_hash"))]
    let blake2b = false;
    blake2b
}
