extern crate ansi_term;
extern crate cita_tool;
extern crate clap;
extern crate dotenv;
extern crate syntect;
extern crate linefeed;

mod cli;
mod highlight;
mod interactive;

use std::u64;
use std::collections::HashMap;
use std::env;
use std::iter::FromIterator;

use dotenv::dotenv;

use cita_tool::{pubkey_to_address, Client, ClientExt, KeyPair, PubKey, remove_0x};
use cli::{build_cli, get_url, parse_privkey};

const ENV_JSONRPC_URL: &'static str = "JSONRPC_URL";
const DEFAULT_JSONRPC_URL: &'static str = "http://127.0.0.1:1337";

fn main() {
    dotenv().ok();

    let mut env_map: HashMap<String, String> = HashMap::from_iter(env::vars());
    let default_jsonrpc_url = env_map
        .remove(ENV_JSONRPC_URL)
        .unwrap_or(DEFAULT_JSONRPC_URL.to_owned());

    let matches = build_cli(&default_jsonrpc_url).get_matches();

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
                ("eth_getLogs", Some(m)) => client.get_logs(
                    get_url(m),
                    m.values_of("topic").map(|value| value.collect()),
                    m.values_of("address").map(|value| value.collect()),
                    m.value_of("from"),
                    m.value_of("to"),
                ),
                ("cita_getTransaction", Some(m)) => {
                    let hash = m.value_of("hash").unwrap();
                    client.get_transaction(get_url(m), hash)
                }
                ("cita_getTransactionCount", Some(m)) => {
                    let address = m.value_of("address").unwrap();
                    let height = m.value_of("height").unwrap();
                    client.get_transaction_count(get_url(m), address, height)
                }
                ("eth_newBlockFilter", Some(m)) => client.new_block_filter(get_url(m)),
                ("eth_uninstallFilter", Some(m)) => {
                    client.uninstall_filter(get_url(m), m.value_of("id").unwrap())
                }
                ("eth_getFilterChanges", Some(m)) => {
                    client.get_filter_changes(get_url(m), m.value_of("id").unwrap())
                }
                ("eth_getFilterLogs", Some(m)) => {
                    client.get_filter_logs(get_url(m), m.value_of("id").unwrap())
                }
                _ => unreachable!(),
            };
            let mut content = format!("{:?}", resp);
            if !sub_matches.is_present("no-color") {
                content = highlight::highlight(content.as_str(), "json")
            }
            println!("{}", content);
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
