use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};

use cita_tool::{pubkey_to_address, remove_0x, Client, ClientExt, KeyPair, PrivateKey, PubKey};

use abi;
use highlight;

/// Generate cli
pub fn build_cli<'a>(default_url: &'a str) -> App<'a, 'a> {
    App::new("cita-cli")
        .global_setting(AppSettings::ColoredHelp)
        .global_setting(AppSettings::DeriveDisplayOrder)
        .subcommand(
            rpc_command().arg(
                Arg::with_name("url")
                    .long("url")
                    .default_value(default_url)
                    .takes_value(true)
                    .multiple(true)
                    .global(true)
                    .help("JSONRPC server URL (dotenv: JSONRPC_URL)"),
            ),
        )
        .subcommand(key_command())
        .subcommand(abi_command())
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
}

/// Interactive parser
pub fn build_interactive() -> App<'static, 'static> {
    App::new("interactive")
        .setting(AppSettings::NoBinaryName)
        .global_setting(AppSettings::ColoredHelp)
        .global_setting(AppSettings::DeriveDisplayOrder)
        .global_setting(AppSettings::DisableVersion)
        .subcommand(
            SubCommand::with_name("switch").arg(
                Arg::with_name("host")
                    .long("host")
                    .takes_value(true)
                    .required(true)
                    .help("Switch url"),
            ),
        )
        .subcommand(SubCommand::with_name("exit").alias("quit"))
        .subcommand(rpc_command())
        .subcommand(key_command())
        .subcommand(abi_command())
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
}

/// Ethereum abi sub command
pub fn abi_command() -> App<'static, 'static> {
    let param_arg = Arg::with_name("param")
        .long("param")
        .short("p")
        .takes_value(true)
        .multiple(true)
        .number_of_values(2)
        .help("Function parameters");
    let no_lenient_flag = Arg::with_name("no-lenient")
        .long("no-lenient")
        .help("Don't allow short representation of input params");

    App::new("abi").subcommand(
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
                    .arg(param_arg.clone().number_of_values(1))
                    .arg(no_lenient_flag.clone()),
            )
            .subcommand(
                SubCommand::with_name("params")
                    .arg(param_arg)
                    .arg(no_lenient_flag),
            ),
    )
}

/// ABI processor
pub fn abi_processor(sub_matches: &ArgMatches) -> Result<(), String> {
    match sub_matches.subcommand() {
        ("encode", Some(em)) => match em.subcommand() {
            ("function", Some(m)) => {
                let file = m.value_of("file").unwrap();
                let name = m.value_of("name").unwrap();
                let lenient = !m.is_present("no-lenient");
                let values: Vec<String> = m.values_of("param")
                    .unwrap()
                    .map(|s| s.to_owned())
                    .collect::<Vec<String>>();
                println!(
                    "{}",
                    abi::encode_input(file, name, &values, lenient).unwrap()
                );
            }
            ("params", Some(m)) => {
                let lenient = !m.is_present("no-lenient");
                let mut types: Vec<String> = Vec::new();
                let mut values: Vec<String> = Vec::new();
                let mut param_iter = m.values_of("param").unwrap().peekable();
                while param_iter.peek().is_some() {
                    types.push(param_iter.next().unwrap().to_owned());
                    values.push(param_iter.next().unwrap().to_owned());
                }
                println!("{}", abi::encode_params(&types, &values, lenient).unwrap());
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

/// Generate rpc sub command
pub fn rpc_command() -> App<'static, 'static> {
    App::new("rpc")
        .subcommand(SubCommand::with_name("net_peerCount"))
        .subcommand(SubCommand::with_name("cita_blockNumber"))
        .subcommand(
            SubCommand::with_name("cita_sendTransaction")
                .arg(
                    Arg::with_name("code")
                        .long("code")
                        .takes_value(true)
                        .required(true)
                        .help("Binary content of the transaction"),
                )
                .arg(
                    Arg::with_name("address")
                        .long("address")
                        .default_value("")
                        .takes_value(true)
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
                ),
        )
        .subcommand(
            SubCommand::with_name("cita_getBlockByHash")
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
            SubCommand::with_name("cita_getBlockByNumber")
                .arg(
                    Arg::with_name("height")
                        .long("height")
                        .required(true)
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
            SubCommand::with_name("eth_getTransaction").arg(
                Arg::with_name("hash")
                    .long("hash")
                    .required(true)
                    .takes_value(true)
                    .help("The hash of specific transaction"),
            ),
        )
        .subcommand(
            SubCommand::with_name("eth_getCode")
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
                        .required(true)
                        .takes_value(true)
                        .help("The number of the block"),
                ),
        )
        .subcommand(
            SubCommand::with_name("eth_getAbi")
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
                        .required(true)
                        .takes_value(true)
                        .help("The number of the block"),
                ),
        )
        .subcommand(
            SubCommand::with_name("eth_getBalance")
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
                        .required(true)
                        .takes_value(true)
                        .help("The number of the block"),
                ),
        )
        .subcommand(
            SubCommand::with_name("eth_getTransactionReceipt").arg(
                Arg::with_name("hash")
                    .long("hash")
                    .required(true)
                    .takes_value(true)
                    .help("The hash of specific transaction"),
            ),
        )
        .subcommand(
            SubCommand::with_name("eth_call")
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
                        .required(true)
                        .help("The block number"),
                ),
        )
        .subcommand(
            SubCommand::with_name("cita_getTransactionProof").arg(
                Arg::with_name("hash")
                    .long("hash")
                    .required(true)
                    .takes_value(true)
                    .help("The hash of the transaction"),
            ),
        )
        .subcommand(
            SubCommand::with_name("eth_getLogs")
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
            SubCommand::with_name("cita_getMetaData").arg(
                Arg::with_name("height")
                    .long("height")
                    .default_value("latest")
                    .validator(|s| match s.as_str() {
                        "latest" | "earliest" => Ok(()),
                        _ => match s.parse::<u64>() {
                            Ok(_) => Ok(()),
                            Err(e) => Err(format!("{:?}", e)),
                        },
                    })
                    .takes_value(true)
                    .help("The height or tag"),
            ),
        )
        .subcommand(
            SubCommand::with_name("cita_getTransaction").arg(
                Arg::with_name("hash")
                    .long("hash")
                    .required(true)
                    .takes_value(true)
                    .help("The hash of the transaction"),
            ),
        )
        .subcommand(
            SubCommand::with_name("cita_getTransactionCount")
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
                        .required(true)
                        .takes_value(true)
                        .help("The height of chain, hex string or tag 'latest'"),
                ),
        )
        .subcommand(SubCommand::with_name("eth_newBlockFilter"))
        .subcommand(
            SubCommand::with_name("eth_uninstallFilter").arg(
                Arg::with_name("id")
                    .long("id")
                    .required(true)
                    .takes_value(true)
                    .validator(|id| is_hex(id.as_ref()))
                    .help("The filter id."),
            ),
        )
        .subcommand(
            SubCommand::with_name("eth_getFilterChanges").arg(
                Arg::with_name("id")
                    .long("id")
                    .required(true)
                    .takes_value(true)
                    .validator(|id| is_hex(id.as_ref()))
                    .help("The filter id."),
            ),
        )
        .subcommand(
            SubCommand::with_name("eth_getFilterLogs").arg(
                Arg::with_name("id")
                    .long("id")
                    .required(true)
                    .takes_value(true)
                    .validator(|id| is_hex(id.as_ref()))
                    .help("The filter id."),
            ),
        )
}

/// RPC processor
pub fn rpc_processor(sub_matches: &ArgMatches, url: Option<&str>) -> Result<(), String> {
    let mut client = Client::new().unwrap();
    let resp = match sub_matches.subcommand() {
        ("net_peerCount", Some(m)) => client.get_net_peer_count(url.unwrap_or_else(|| get_url(m))),
        ("cita_blockNumber", Some(m)) => client.get_block_number(url.unwrap_or_else(|| get_url(m))),
        ("cita_sendTransaction", Some(m)) => {
            #[cfg(feature = "blake2b_hash")]
            let blake2b = m.is_present("blake2b");

            if let Some(chain_id) = m.value_of("chain-id").map(|s| s.parse::<u32>().unwrap()) {
                client.set_chain_id(chain_id);
            }
            if let Some(private_key) = m.value_of("private-key") {
                client.set_private_key(parse_privkey(private_key).unwrap());
            }
            let url = url.unwrap_or_else(|| get_url(m));
            let code = m.value_of("code").unwrap();
            let address = m.value_of("address").unwrap();
            let current_height = m.value_of("height").map(|s| s.parse::<u64>().unwrap());
            let quota = m.value_of("quota").map(|s| s.parse::<u64>().unwrap());
            #[cfg(not(feature = "blake2b_hash"))]
            let response =
                client.send_transaction(url, code, address, current_height, quota, false);
            #[cfg(feature = "blake2b_hash")]
            let response =
                client.send_transaction(url, code, address, current_height, quota, blake2b);
            response
        }
        ("cita_getBlockByHash", Some(m)) => {
            let hash = m.value_of("hash").unwrap();
            let with_txs = m.is_present("with-txs");
            client.get_block_by_hash(url.unwrap_or_else(|| get_url(m)), hash, with_txs)
        }
        ("cita_getBlockByNumber", Some(m)) => {
            let height = m.value_of("height").unwrap();
            let with_txs = m.is_present("with-txs");
            client.get_block_by_number(url.unwrap_or_else(|| get_url(m)), height, with_txs)
        }
        ("eth_getTransaction", Some(m)) => {
            let hash = m.value_of("hash").unwrap();
            client.get_transaction(url.unwrap_or_else(|| get_url(m)), hash)
        }
        ("eth_getCode", Some(m)) => client.get_code(
            url.unwrap_or_else(|| get_url(m)),
            m.value_of("address").unwrap(),
            m.value_of("height").unwrap(),
        ),
        ("eth_getAbi", Some(m)) => client.get_abi(
            url.unwrap_or_else(|| get_url(m)),
            m.value_of("address").unwrap(),
            m.value_of("height").unwrap(),
        ),
        ("eth_getBalance", Some(m)) => client.get_balance(
            url.unwrap_or_else(|| get_url(m)),
            m.value_of("address").unwrap(),
            m.value_of("height").unwrap(),
        ),
        ("eth_getTransactionReceipt", Some(m)) => {
            let hash = m.value_of("hash").unwrap();
            client.get_transaction_receipt(url.unwrap_or_else(|| get_url(m)), hash)
        }
        ("eth_call", Some(m)) => client.call(
            url.unwrap_or_else(|| get_url(m)),
            m.value_of("from"),
            m.value_of("to").unwrap(),
            m.value_of("data"),
            m.value_of("height").unwrap(),
        ),
        ("cita_getTransactionProof", Some(m)) => client.get_transaction_proof(
            url.unwrap_or_else(|| get_url(m)),
            m.value_of("hash").unwrap(),
        ),
        ("cita_getMetaData", Some(m)) => {
            let height = m.value_of("height").unwrap();
            client.get_metadata(url.unwrap_or_else(|| get_url(m)), height)
        }
        ("eth_getLogs", Some(m)) => client.get_logs(
            url.unwrap_or_else(|| get_url(m)),
            m.values_of("topic").map(|value| value.collect()),
            m.values_of("address").map(|value| value.collect()),
            m.value_of("from"),
            m.value_of("to"),
        ),
        ("cita_getTransaction", Some(m)) => {
            let hash = m.value_of("hash").unwrap();
            client.get_transaction(url.unwrap_or_else(|| get_url(m)), hash)
        }
        ("cita_getTransactionCount", Some(m)) => {
            let address = m.value_of("address").unwrap();
            let height = m.value_of("height").unwrap();
            client.get_transaction_count(url.unwrap_or_else(|| get_url(m)), address, height)
        }
        ("eth_newBlockFilter", Some(m)) => {
            client.new_block_filter(url.unwrap_or_else(|| get_url(m)))
        }
        ("eth_uninstallFilter", Some(m)) => {
            client.uninstall_filter(url.unwrap_or_else(|| get_url(m)), m.value_of("id").unwrap())
        }
        ("eth_getFilterChanges", Some(m)) => {
            client.get_filter_changes(url.unwrap_or_else(|| get_url(m)), m.value_of("id").unwrap())
        }
        ("eth_getFilterLogs", Some(m)) => {
            client.get_filter_logs(url.unwrap_or_else(|| get_url(m)), m.value_of("id").unwrap())
        }
        _ => {
            return Err(sub_matches.usage().to_owned());
        }
    };
    let mut content = format!("{:?}", resp);
    if !sub_matches.is_present("no-color") {
        content = highlight::highlight(content.as_str(), "json")
    }
    println!("{}", content);
    Ok(())
}

/// Key related commands
pub fn key_command() -> App<'static, 'static> {
    App::new("key")
        .subcommand(SubCommand::with_name("create"))
        .subcommand(
            SubCommand::with_name("from-private-key").arg(
                Arg::with_name("private-key")
                    .long("private-key")
                    .takes_value(true)
                    .required(true)
                    .validator(|privkey| match parse_privkey(privkey.as_ref()) {
                        Ok(_) => Ok(()),
                        Err(err) => Err(err),
                    })
                    .help("The private key of transaction"),
            ),
        )
        .subcommand(
            SubCommand::with_name("pub-to-address").arg(
                Arg::with_name("pubkey")
                    .long("pubkey")
                    .takes_value(true)
                    .required(true)
                    .validator(|pubkey| match PubKey::from_str(remove_0x(&pubkey)) {
                        Ok(_) => Ok(()),
                        Err(err) => Err(err),
                    })
                    .help("Pubkey"),
            ),
        )
}

/// Key processor
pub fn key_processor(sub_matches: &ArgMatches) -> Result<(), String> {
    match sub_matches.subcommand() {
        ("create", Some(m)) => {
            let blake2b = m.is_present("blake2b");
            let key_pair = KeyPair::new(blake2b);

            println!(
                concat!(
                    "[private key]: 0x{}\n",
                    "[public key] : 0x{}\n",
                    "[address]    : 0x{:#x}"
                ),
                key_pair.privkey(),
                key_pair.pubkey(),
                key_pair.address()
            );
        }
        ("from-private-key", Some(m)) => {
            let private_key = m.value_of("private-key").unwrap();
            let key_pair = KeyPair::from_str(remove_0x(private_key)).unwrap();

            println!(
                concat!(
                    "[private key]: 0x{}\n",
                    "[public key] : 0x{}\n",
                    "[address]    : 0x{:#x}"
                ),
                key_pair.privkey(),
                key_pair.pubkey(),
                key_pair.address()
            );
        }
        ("pub-to-address", Some(m)) => {
            let pubkey = m.value_of("pubkey").unwrap();
            let address = pubkey_to_address(&PubKey::from_str(remove_0x(pubkey)).unwrap());
            println!("address: 0x{:#x}", address);
        }
        _ => {
            return Err(sub_matches.usage().to_owned());
        }
    }
    Ok(())
}

/// Get url from arg match
pub fn get_url<'a>(m: &'a ArgMatches) -> &'a str {
    m.value_of("url").unwrap()
}

fn parse_u64(height: &str) -> Result<u64, String> {
    Ok(u64::from_str_radix(remove_0x(height), 16).map_err(|err| format!("{}", err))?)
}

/// Attempt to resolve the private key
pub fn parse_privkey(hash: &str) -> Result<PrivateKey, String> {
    Ok(PrivateKey::from_str(remove_0x(hash))?)
}

fn is_hex(hex: &str) -> Result<(), String> {
    let tmp = hex.as_bytes();
    if tmp[..2] == b"0x"[..] || tmp[..2] == b"0X"[..] {
        Ok(())
    } else {
        Err("Must hex string".to_string())
    }
}
