extern crate clap;
extern crate dotenv;

extern crate cita_tool;

use std::env;
use std::collections::HashMap;
use std::iter::FromIterator;

use dotenv::dotenv;

use cita_tool::{Client, ClientExt};

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
                .arg(
                    clap::Arg::with_name("url")
                        .long("url")
                        .default_value(default_jsonrpc_url.as_str())
                        .takes_value(true)
                        .multiple(true)
                        .global(true)
                        .help(format!("JSONRPC server URL (dotenv: {})", ENV_JSONRPC_URL).as_str()),
                )
        )
        .get_matches();

    match matches.subcommand() {
        ("rpc", Some(sub_matches)) => {
            let mut client = Client::new().unwrap();
            match sub_matches.subcommand() {
                ("net_peerCount", Some(method_m)) => {
                    let url = method_m.value_of("url").unwrap();
                    println!("{}", client.get_net_peer_count(url));
                },
                ("cita_blockNumber", Some(method_m)) => {
                    let url = method_m.value_of("url").unwrap();
                    println!("{}", client.get_block_number(url));
                },
                _ => unreachable!()
            }
        },
        _ => {
            println!("matches: {:#?}", matches);
        }
    }
}
