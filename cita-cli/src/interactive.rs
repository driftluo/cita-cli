use std::io;
use std::sync::Arc;

use super::{build_interactive, highlight, parse_privkey};
use linefeed::{Interface, Prompter, ReadResult};
use cita_tool::{pubkey_to_address, Client, ClientExt, KeyPair, PubKey, remove_0x};

/// Interactive command line
pub fn start(url: &str) -> io::Result<()> {
    let interface = Arc::new(Interface::new("cita-cli")?);
    let mut url = url.to_string();

    interface.set_prompt(&(url.to_owned() + "> "));

    let parser = build_interactive();

    while let ReadResult::Input(line) = interface.read_line()? {
        if line.trim() == "quite" || line.trim() == "exit" {
            break;
        }
        let cli = line.split_whitespace().collect::<Vec<&str>>();

        match parser.clone().get_matches_from_safe(cli) {
            Ok(args) => {
                match args.subcommand() {
                    ("switch", Some(m)) => {
                        let host = m.value_of("host").unwrap();
                        interface.set_prompt(&(host.to_owned() + "> "));
                        url = host.to_string();
                    },
                    ("rpc", Some(sub_matches)) => {
                        let mut client = Client::new().unwrap();
                        let resp = match sub_matches.subcommand() {
                            ("net_peerCount", _) => client.get_net_peer_count(&url),
                            ("cita_blockNumber", _) => client.get_block_number(&url),
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
                                let code = m.value_of("code").unwrap();
                                let address = m.value_of("address").unwrap();
                                let current_height = m.value_of("height").map(|s| s.parse::<u64>().unwrap());
                                let quota = m.value_of("quota").map(|s| s.parse::<u64>().unwrap());
                                #[cfg(not(feature = "blake2b_hash"))]
                                let response =
                                    client.send_transaction(&url, code, address, current_height, quota, false);
                                #[cfg(feature = "blake2b_hash")]
                                let response =
                                    client.send_transaction(&url, code, address, current_height, quota, blake2b);
                                response
                            }
                            ("cita_getBlockByHash", Some(m)) => {
                                let hash = m.value_of("hash").unwrap();
                                let with_txs = m.is_present("with-txs");
                                client.get_block_by_hash(&url, hash, with_txs)
                            }
                            ("cita_getBlockByNumber", Some(m)) => {
                                let height = m.value_of("height").unwrap();
                                let with_txs = m.is_present("with-txs");
                                client.get_block_by_number(&url, height, with_txs)
                            }
                            ("eth_getTransaction", Some(m)) => {
                                let hash = m.value_of("hash").unwrap();
                                client.get_transaction(&url, hash)
                            }
                            ("eth_getCode", Some(m)) => client.get_code(
                                &url,
                                m.value_of("address").unwrap(),
                                m.value_of("height").unwrap(),
                            ),
                            ("eth_getAbi", Some(m)) => client.get_abi(
                                &url,
                                m.value_of("address").unwrap(),
                                m.value_of("height").unwrap(),
                            ),
                            ("eth_getBalance", Some(m)) => client.get_balance(
                                &url,
                                m.value_of("address").unwrap(),
                                m.value_of("height").unwrap(),
                            ),
                            ("eth_getTransactionReceipt", Some(m)) => {
                                let hash = m.value_of("hash").unwrap();
                                client.get_transaction_receipt(&url, hash)
                            }
                            ("eth_call", Some(m)) => client.call(
                                &url,
                                m.value_of("from"),
                                m.value_of("to").unwrap(),
                                m.value_of("data"),
                                m.value_of("height").unwrap(),
                            ),
                            ("cita_getTransactionProof", Some(m)) => {
                                client.get_transaction_proof(&url, m.value_of("hash").unwrap())
                            }
                            ("cita_getMetaData", Some(m)) => {
                                let height = m.value_of("height").unwrap();
                                client.get_metadata(&url, height)
                            }
                            ("eth_getLogs", Some(m)) => client.get_logs(
                                &url,
                                m.values_of("topic").map(|value| value.collect()),
                                m.values_of("address").map(|value| value.collect()),
                                m.value_of("from"),
                                m.value_of("to"),
                            ),
                            ("cita_getTransaction", Some(m)) => {
                                let hash = m.value_of("hash").unwrap();
                                client.get_transaction(&url, hash)
                            }
                            ("cita_getTransactionCount", Some(m)) => {
                                let address = m.value_of("address").unwrap();
                                let height = m.value_of("height").unwrap();
                                client.get_transaction_count(&url, address, height)
                            }
                            ("eth_newBlockFilter", _) => client.new_block_filter(&url),
                            ("eth_uninstallFilter", Some(m)) => {
                                client.uninstall_filter(&url, m.value_of("id").unwrap())
                            }
                            ("eth_getFilterChanges", Some(m)) => {
                                client.get_filter_changes(&url, m.value_of("id").unwrap())
                            }
                            ("eth_getFilterLogs", Some(m)) => {
                                client.get_filter_logs(&url, m.value_of("id").unwrap())
                            }
                            _ => {
                                println!("{}", sub_matches.usage());
                                continue
                            }
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
                        _ => {
                            println!("{}", sub_matches.usage());
                        }
                    },
                    _ => {}
                }
            },
            Err(err) => println!("{}", err)
        }
    }

    Ok(())
}
