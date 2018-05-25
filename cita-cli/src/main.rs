extern crate clap;
extern crate dotenv;
extern crate syntect;

extern crate cita_tool;

use std::env;
use std::collections::HashMap;
use std::iter::FromIterator;
use std::u64;

use dotenv::dotenv;

use cita_tool::{pubkey_to_address, Client, ClientExt, KeyPair, PrivateKey, PubKey, remove_0x};

const ENV_JSONRPC_URL: &'static str = "JSONRPC_URL";
const DEFAULT_JSONRPC_URL: &'static str = "http://127.0.0.1:1337";

fn main() {
    dotenv().ok();

    let mut env_map: HashMap<String, String> = HashMap::from_iter(env::vars());
    let default_jsonrpc_url = env_map
        .remove(ENV_JSONRPC_URL)
        .unwrap_or(DEFAULT_JSONRPC_URL.to_owned());

    let matches = clap::App::new("CITA CLI")
        .subcommand(
            clap::SubCommand::with_name("rpc")
                .subcommand(clap::SubCommand::with_name("net_peerCount"))
                .subcommand(clap::SubCommand::with_name("cita_blockNumber"))
                .subcommand(
                    clap::SubCommand::with_name("cita_sendTransaction")
                        .arg(
                            clap::Arg::with_name("code")
                                .long("code")
                                .takes_value(true)
                                .required(true)
                                .help("Binary content of the transaction"),
                        )
                        .arg(
                            clap::Arg::with_name("address")
                                .long("address")
                                .default_value("")
                                .takes_value(true)
                                .help(
                                    "The address of the invoking contract, defalut is empty to \
                                     create contract",
                                ),
                        )
                        .arg(
                            clap::Arg::with_name("height")
                                .long("height")
                                .takes_value(true)
                                .validator(|height| match parse_u64(height.as_ref()) {
                                    Ok(_) => Ok(()),
                                    Err(err) => Err(err),
                                })
                                .help("Current chain height, default query to the chain"),
                        )
                        .arg(
                            clap::Arg::with_name("chain-id")
                                .long("chain-id")
                                .takes_value(true)
                                .validator(|chain_id| match chain_id.parse::<u32>() {
                                    Ok(_) => Ok(()),
                                    Err(err) => Err(format!("{:?}", err)),
                                })
                                .help("The chain_id of transaction"),
                        )
                        .arg(
                            clap::Arg::with_name("private-key")
                                .long("private-key")
                                .takes_value(true)
                                .required(true)
                                .validator(|privkey| match parse_privkey(privkey.as_ref()) {
                                    Ok(_) => Ok(()),
                                    Err(err) => Err(err),
                                })
                                .help("The private key of transaction"),
                        )
                        .arg(
                            clap::Arg::with_name("quota")
                                .long("quota")
                                .takes_value(true)
                                .validator(|quota| match parse_u64(quota.as_ref()) {
                                    Ok(_) => Ok(()),
                                    Err(err) => Err(err),
                                })
                                .help("Transaction quota costs, default is 1_000_000"),
                        ),
                )
                .subcommand(
                    clap::SubCommand::with_name("cita_getBlockByHash")
                        .arg(
                            clap::Arg::with_name("hash")
                                .long("hash")
                                .required(true)
                                .takes_value(true)
                                .help("The hash of the block"),
                        )
                        .arg(
                            clap::Arg::with_name("with-txs")
                                .long("with-txs")
                                .help("Get transactions detail of the block"),
                        ),
                )
                .subcommand(
                    clap::SubCommand::with_name("cita_getBlockByNumber")
                        .arg(
                            clap::Arg::with_name("height")
                                .long("height")
                                .required(true)
                                .takes_value(true)
                                .help("The number of the block"),
                        )
                        .arg(
                            clap::Arg::with_name("with-txs")
                                .long("with-txs")
                                .help("Get transactions detail of the block"),
                        ),
                )
                .subcommand(
                    clap::SubCommand::with_name("eth_getTransaction").arg(
                        clap::Arg::with_name("hash")
                            .long("hash")
                            .required(true)
                            .takes_value(true)
                            .help("The hash of specific transaction"),
                    ),
                )
                .subcommand(
                    clap::SubCommand::with_name("eth_getCode")
                        .arg(
                            clap::Arg::with_name("address")
                                .long("address")
                                .required(true)
                                .takes_value(true)
                                .help("The address of the code"),
                        )
                        .arg(
                            clap::Arg::with_name("height")
                                .long("height")
                                .required(true)
                                .takes_value(true)
                                .help("The number of the block"),
                        ),
                )
                .subcommand(
                    clap::SubCommand::with_name("eth_getAbi")
                        .arg(
                            clap::Arg::with_name("address")
                                .long("address")
                                .required(true)
                                .takes_value(true)
                                .help("The address of the abi data"),
                        )
                        .arg(
                            clap::Arg::with_name("height")
                                .long("height")
                                .required(true)
                                .takes_value(true)
                                .help("The number of the block"),
                        ),
                )
                .subcommand(
                    clap::SubCommand::with_name("eth_getBalance")
                        .arg(
                            clap::Arg::with_name("address")
                                .long("address")
                                .required(true)
                                .takes_value(true)
                                .help("The address of the balance"),
                        )
                        .arg(
                            clap::Arg::with_name("height")
                                .long("height")
                                .required(true)
                                .takes_value(true)
                                .help("The number of the block"),
                        ),
                )
                .subcommand(
                    clap::SubCommand::with_name("eth_getTransactionReceipt").arg(
                        clap::Arg::with_name("hash")
                            .long("hash")
                            .required(true)
                            .takes_value(true)
                            .help("The hash of specific transaction"),
                    ),
                )
                .subcommand(
                    clap::SubCommand::with_name("eth_call")
                        .arg(
                            clap::Arg::with_name("from")
                                .long("from")
                                .takes_value(true)
                                .help("From address"),
                        )
                        .arg(
                            clap::Arg::with_name("to")
                                .long("to")
                                .takes_value(true)
                                .required(true)
                                .help("To address"),
                        )
                        .arg(
                            clap::Arg::with_name("data")
                                .long("data")
                                .takes_value(true)
                                .help("The data"),
                        )
                        .arg(
                            clap::Arg::with_name("height")
                                .long("height")
                                .takes_value(true)
                                .required(true)
                                .help("The block number"),
                        ),
                )
                .subcommand(
                    clap::SubCommand::with_name("cita_getTransactionProof").arg(
                        clap::Arg::with_name("hash")
                            .long("hash")
                            .required(true)
                            .takes_value(true)
                            .help("The hash of the transaction"),
                    ),
                )
                .subcommand(
                    clap::SubCommand::with_name("cita_getMetaData").arg(
                        clap::Arg::with_name("height")
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
                .arg(
                    clap::Arg::with_name("url")
                        .long("url")
                        .default_value(default_jsonrpc_url.as_str())
                        .takes_value(true)
                        .multiple(true)
                        .global(true)
                        .help(format!("JSONRPC server URL (dotenv: {})", ENV_JSONRPC_URL).as_str()),
                ),
        )
        .subcommand(
            clap::SubCommand::with_name("key")
                .subcommand(clap::SubCommand::with_name("create"))
                .subcommand(
                    clap::SubCommand::with_name("from-private-key").arg(
                        clap::Arg::with_name("private-key")
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
                    clap::SubCommand::with_name("pub-to-address").arg(
                        clap::Arg::with_name("pubkey")
                            .long("pubkey")
                            .takes_value(true)
                            .required(true)
                            .validator(|pubkey| match PubKey::from_str(remove_0x(&pubkey)) {
                                Ok(_) => Ok(()),
                                Err(err) => Err(err),
                            })
                            .help("Pubkey"),
                    ),
                ),
        )
        .arg(
            clap::Arg::with_name("blake2b")
                .long("blake2b")
                .global(true)
                .help("Use blake2b encryption algorithm, must build with feature blake2b"),
        )
        .get_matches();

    match matches.subcommand() {
        ("rpc", Some(sub_matches)) => {
            let mut client = Client::new().unwrap();
            let resp = match sub_matches.subcommand() {
                ("net_peerCount", Some(m)) => client.get_net_peer_count(get_url(m)),
                ("cita_blockNumber", Some(m)) => client.get_block_number(get_url(m)),
                ("cita_sendTransaction", Some(m)) => {
                    #[cfg(feature = "blake2b_hash")]
                    let blake2b = m.is_present("blake2b");

                    if let Some(chain_id) =
                        m.value_of("chain-id").map(|s| s.parse::<u32>().unwrap())
                    {
                        client.set_chain_id(chain_id);
                    }
                    if let Some(private_key) = m.value_of("private-key") {
                        client.set_private_key(parse_privkey(private_key).unwrap());
                    }
                    let url = get_url(m);
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
                    client.get_block_by_hash(get_url(m), hash, with_txs)
                }
                ("cita_getBlockByNumber", Some(m)) => {
                    let height = m.value_of("height").unwrap();
                    let with_txs = m.is_present("with-txs");
                    client.get_block_by_number(get_url(m), height, with_txs)
                }
                ("eth_getTransaction", Some(m)) => {
                    let hash = m.value_of("hash").unwrap();
                    client.get_transaction(get_url(m), hash)
                }
                ("eth_getCode", Some(m)) => client.get_code(
                    get_url(m),
                    m.value_of("address").unwrap(),
                    m.value_of("height").unwrap(),
                ),
                ("eth_getAbi", Some(m)) => client.get_abi(
                    get_url(m),
                    m.value_of("address").unwrap(),
                    m.value_of("height").unwrap(),
                ),
                ("eth_getBalance", Some(m)) => client.get_balance(
                    get_url(m),
                    m.value_of("address").unwrap(),
                    m.value_of("height").unwrap(),
                ),
                ("eth_getTransactionReceipt", Some(m)) => {
                    let hash = m.value_of("hash").unwrap();
                    client.get_transaction_receipt(get_url(m), hash)
                }
                ("eth_call", Some(m)) => client.call(
                    get_url(m),
                    m.value_of("from"),
                    m.value_of("to").unwrap(),
                    m.value_of("data"),
                    m.value_of("height").unwrap(),
                ),
                ("cita_getTransactionProof", Some(m)) => {
                    client.get_transaction_proof(get_url(m), m.value_of("hash").unwrap())
                }
                ("cita_getMetaData", Some(m)) => {
                    let height = m.value_of("height").unwrap();
                    client.get_metadata(get_url(m), height)
                }
                _ => unreachable!(),
            };
            println!("{}", format!("{:?}", resp).as_str());
        }
        ("key", Some(sub_matches)) => match sub_matches.subcommand() {
            ("create", Some(m)) => {
                let blake2b = m.is_present("blake2b");

                let key_pair = KeyPair::new(blake2b);

                println!(
                    "private key: 0x{}\npubkey: 0x{}\naddress: 0x{:#x}",
                    key_pair.privkey(),
                    key_pair.pubkey(),
                    key_pair.address()
                );
            }
            ("from-private-key", Some(m)) => {
                let private_key = m.value_of("private-key").unwrap();
                let key_pair = KeyPair::from_str(remove_0x(private_key)).unwrap();

                println!(
                    "private key: 0x{}\npubkey: 0x{}\naddress: 0x{:#x}",
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
            _ => unreachable!(),
        },
        _ => {
            println!("matches:\n {}", matches.usage());
        }
    }
}

fn get_url<'a>(m: &'a clap::ArgMatches) -> &'a str {
    m.value_of("url").unwrap()
}

fn parse_u64(height: &str) -> Result<u64, String> {
    Ok(u64::from_str_radix(remove_0x(height), 16).map_err(|err| format!("{}", err))?)
}

fn parse_privkey(hash: &str) -> Result<PrivateKey, String> {
    Ok(PrivateKey::from_str(remove_0x(hash))?)
}
