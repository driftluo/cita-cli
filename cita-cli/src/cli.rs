use clap::{App, Arg, ArgMatches, SubCommand};

use cita_tool::{PrivateKey, PubKey, remove_0x};

/// Generate cli
pub fn build_cli<'a>(default_url: &'a str) -> App<'a, 'a> {
    App::new("cita-cli")
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
                        .validator(|height| match parse_u64(height.as_ref()) {
                            Ok(_) => Ok(()),
                            Err(err) => Err(err),
                        })
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
                        .validator(|privkey| match parse_privkey(privkey.as_ref()) {
                            Ok(_) => Ok(()),
                            Err(err) => Err(err),
                        })
                        .help("The private key of transaction"),
                )
                .arg(
                    Arg::with_name("quota")
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
