use clap::{App, Arg, ArgGroup, ArgMatches, SubCommand};

use cita_tool::client::basic::{AmendExt, Client};
use cita_tool::remove_0x;

use crate::cli::{
    encryption, get_url, h256_validator, key_validator, parse_address, parse_privkey, parse_u256,
    parse_u64,
};
use crate::interactive::{set_output, GlobalConfig};
use crate::printer::Printer;

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
            .validator(|privkey| key_validator(privkey.as_ref()).map(|_| ()))
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
            SubCommand::with_name("set-h256")
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
                    Arg::with_name("value")
                        .long("value")
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
    config: &mut GlobalConfig,
    client: Client,
) -> Result<(), String> {
    let debug = sub_matches.is_present("debug") || config.debug();
    let mut client = client
        .set_debug(debug)
        .set_uri(get_url(sub_matches, config));

    let result = match sub_matches.subcommand() {
        ("code", Some(m)) => {
            let encryption = encryption(m, config);
            if let Some(private_key) = m.value_of("admin-private-key") {
                client.set_private_key(&parse_privkey(private_key, encryption)?);
            }
            let address = m.value_of("address").unwrap();
            let content = m.value_of("content").unwrap();
            let quota = m.value_of("quota").map(|s| parse_u64(s).unwrap());
            client.amend_code(address, content, quota)
        }
        ("abi", Some(m)) => {
            let encryption = encryption(m, config);
            if let Some(private_key) = m.value_of("admin-private-key") {
                client.set_private_key(&parse_privkey(private_key, encryption)?);
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
            client.amend_abi(address, content, quota)
        }
        ("set-h256", Some(m)) => {
            let encryption = encryption(m, config);
            if let Some(private_key) = m.value_of("admin-private-key") {
                client.set_private_key(&parse_privkey(private_key, encryption)?);
            }
            let address = m.value_of("address").unwrap();
            let h256_kv = m
                .values_of("kv")
                .unwrap()
                .map(|s| remove_0x(s))
                .collect::<Vec<&str>>()
                .join("");
            let quota = m.value_of("quota").map(|s| parse_u64(s).unwrap());
            client.amend_h256kv(address, &h256_kv, quota)
        }
        ("balance", Some(m)) => {
            let encryption = encryption(m, config);
            if let Some(private_key) = m.value_of("admin-private-key") {
                client.set_private_key(&parse_privkey(private_key, encryption)?);
            }
            let address = m.value_of("address").unwrap();
            let balance = m
                .value_of("value")
                .map(|value| parse_u256(value).unwrap())
                .unwrap();
            let quota = m.value_of("quota").map(|s| parse_u64(s).unwrap());
            client.amend_balance(address, balance, quota)
        }
        _ => {
            return Err(sub_matches.usage().to_owned());
        }
    };
    let resp = result.map_err(|err| format!("{}", err))?;
    let is_color = !sub_matches.is_present("no-color") && config.color();
    printer.println(&resp, is_color);
    set_output(&resp, config);
    Ok(())
}
