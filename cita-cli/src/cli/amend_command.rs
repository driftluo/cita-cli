use clap::{App, Arg, ArgGroup, ArgMatches, SubCommand};

use cita_tool::client::basic::{AmendExt, Client};
use cita_tool::remove_0x;

use cli::{blake2b, get_url, h256_validator, parse_address, parse_privkey, parse_u256, parse_u64};
use interactive::GlobalConfig;
use printer::Printer;

use std::fs;
use std::io::Read;

/// Amend(Update) ABI/contract code/H256KV
pub fn amend_command() -> App<'static, 'static> {
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
                        .validator(|address| parse_address(address.as_str()))
                        .required(true)
                        .takes_value(true)
                        .help("The contract address of the code"),
                )
                .arg(
                    Arg::with_name("content")
                        .long("content")
                        .takes_value(true)
                        .required(true)
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
                        .validator(|address| parse_address(address.as_str()))
                        .required(true)
                        .takes_value(true)
                        .help("The contract address of the ABI"),
                )
                .arg(
                    Arg::with_name("content")
                        .long("content")
                        .required(true)
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
                        .validator(|address| parse_address(address.as_str()))
                        .required(true)
                        .takes_value(true)
                        .help("The account address"),
                )
                .arg(
                    Arg::with_name("kv")
                        .long("kv")
                        .required(true)
                        .takes_value(true)
                        .multiple(true)
                        .number_of_values(2)
                        .validator(|kv| h256_validator(kv.as_str()))
                        .help("The key value pair"),
                )
                .args(&common_args),
        )
        .subcommand(
            SubCommand::with_name("get-h256")
                .about("Get H256 Value, only write to log")
                .arg(
                    Arg::with_name("address")
                        .long("address")
                        .validator(|address| parse_address(address.as_str()))
                        .required(true)
                        .takes_value(true)
                        .help("The account address"),
                )
                .arg(
                    Arg::with_name("key")
                        .long("key")
                        .required(true)
                        .takes_value(true)
                        .validator(|key| h256_validator(key.as_str()))
                        .help("The key of pair"),
                )
                .args(&common_args),
        )
        .subcommand(
            SubCommand::with_name("balance")
                .about("Amend account balance")
                .arg(
                    Arg::with_name("address")
                        .long("address")
                        .validator(|address| parse_address(address.as_str()))
                        .required(true)
                        .takes_value(true)
                        .help("The account address"),
                )
                .arg(
                    Arg::with_name("balance")
                        .long("balance")
                        .required(true)
                        .takes_value(true)
                        .validator(|value| parse_u256(value.as_ref()).map(|_| ()))
                        .help("Account balance"),
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
        .set_debug(debug)
        .set_uri(url.unwrap_or_else(|| match sub_matches.subcommand() {
            (_, Some(m)) => get_url(m),
            _ => "http://127.0.0.1:1337",
        }));

    let result = match sub_matches.subcommand() {
        ("code", Some(m)) => {
            let blake2b = blake2b(m, env_variable);
            // TODO: this really should be fixed, private key must required
            if let Some(private_key) = m.value_of("admin-private-key") {
                client.set_private_key(&parse_privkey(private_key)?);
            }
            let address = m.value_of("address").unwrap();
            let content = m.value_of("content").unwrap();
            let quota = m.value_of("quota").map(|s| parse_u64(s).unwrap());
            client.amend_code(address, content, quota, blake2b)
        }
        ("abi", Some(m)) => {
            let blake2b = blake2b(m, env_variable);
            // TODO: this really should be fixed, private key must required
            if let Some(private_key) = m.value_of("admin-private-key") {
                client.set_private_key(&parse_privkey(private_key)?);
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
            let quota = m.value_of("quota").map(|s| parse_u64(s).unwrap());
            client.amend_abi(address, content, quota, blake2b)
        }
        ("kv-h256", Some(m)) => {
            let blake2b = blake2b(m, env_variable);
            // TODO: this really should be fixed, private key must required
            if let Some(private_key) = m.value_of("admin-private-key") {
                client.set_private_key(&parse_privkey(private_key)?);
            }
            let address = m.value_of("address").unwrap();
            let h256_kv = m
                .values_of("kv")
                .unwrap()
                .map(|s| remove_0x(s))
                .collect::<Vec<&str>>()
                .join("");
            let quota = m.value_of("quota").map(|s| parse_u64(s).unwrap());
            client.amend_h256kv(address, &h256_kv, quota, blake2b)
        }
        ("get-h256", Some(m)) => {
            let blake2b = blake2b(m, env_variable);
            if let Some(private_key) = m.value_of("admin-private-key") {
                client.set_private_key(&parse_privkey(private_key)?);
            }
            let address = m.value_of("address").unwrap();
            let h256_key = m.value_of("key").unwrap();
            let quota = m.value_of("quota").map(|s| parse_u64(s).unwrap());
            client.amend_get_h256kv(address, h256_key, quota, blake2b)
        }
        ("balance", Some(m)) => {
            let blake2b = blake2b(m, env_variable);
            if let Some(private_key) = m.value_of("admin-private-key") {
                client.set_private_key(&parse_privkey(private_key)?);
            }
            let address = m.value_of("address").unwrap();
            let balance = m
                .value_of("balance")
                .map(|value| parse_u256(value).unwrap())
                .unwrap();
            let quota = m.value_of("quota").map(|s| parse_u64(s).unwrap());
            client.amend_balance(address, balance, quota, blake2b)
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
