extern crate clap;
extern crate dotenv;

extern crate cita_tool;

use std::env;
use std::collections::HashMap;
use std::iter::FromIterator;
use std::u64;
use std::str::FromStr;

use dotenv::dotenv;

use cita_tool::{Client, ClientExt, PrivKey, remove_0x};

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
                                    "The address of the invoking contract, if it is empty, \
                                     it is regarded as creating a contract",
                                ),
                        )
                        .arg(
                            clap::Arg::with_name("height")
                                .long("height")
                                .takes_value(true)
                                .required(true)
                                .validator(|height| match parse_u64(height.as_ref()) {
                                    Ok(_) => Ok(()),
                                    Err(err) => Err(err),
                                })
                                .help("Current chain height"),
                        )
                        .arg(
                            clap::Arg::with_name("privkey")
                                .long("privkey")
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
                    clap::SubCommand::with_name("eth_getTransactionReceipt").arg(
                        clap::Arg::with_name("hash")
                            .long("hash")
                            .required(true)
                            .takes_value(true)
                            .help("The hash of specific transaction"),
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
        .get_matches();

    match matches.subcommand() {
        ("rpc", Some(sub_matches)) => {
            let mut client = Client::new().unwrap();
            match sub_matches.subcommand() {
                ("net_peerCount", Some(method_m)) => {
                    let url = method_m.value_of("url").unwrap();
                    println!("{}", client.get_net_peer_count(url));
                }
                ("cita_blockNumber", Some(method_m)) => {
                    let url = method_m.value_of("url").unwrap();
                    println!("{}", client.get_block_number(url));
                }
                ("cita_sendTransaction", Some(method_m)) => {
                    let url = method_m.value_of("url").unwrap();
                }
                ("eth_getTransactionReceipt", Some(method_m)) => {
                    let url = method_m.value_of("url").unwrap();
                }
                _ => unreachable!(),
            }
        }
        _ => {
            println!("matches:\n {}", matches.usage());
        }
    }
}

fn parse_u64(height: &str) -> Result<u64, String> {
    Ok(u64::from_str_radix(&remove_0x(height.to_string()), 16).map_err(|err| format!("{}", err))?)
}

fn parse_privkey(hash: &str) -> Result<PrivKey, String> {
    Ok(PrivKey::from_str(&remove_0x(hash.to_string())).map_err(|err| format!("{}", err))?)
}
