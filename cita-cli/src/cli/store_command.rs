use clap::{App, Arg, ArgGroup, ArgMatches, SubCommand};

use cita_tool::client::basic::{Client, StoreExt};
use cita_tool::remove_0x;

use crate::cli::{
    encryption, get_url, is_hex, key_validator, parse_address, parse_privkey, parse_u64,
};
use crate::interactive::{set_output, GlobalConfig};
use crate::printer::Printer;

use std::fs;
use std::io::Read;

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
            .validator(|privkey| key_validator(privkey.as_ref()).map(|_| ()))
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
                .about("Store data to: 0xffffffffffffffffffffffffffffffffff010000")
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
                .about("Store ABI to: 0xffffffffffffffffffffffffffffffffff010001")
                .arg(
                    Arg::with_name("address")
                        .long("address")
                        .required(true)
                        .validator(|address| parse_address(address.as_str()))
                        .takes_value(true)
                        .help("The contract address of the ABI"),
                )
                .arg(
                    Arg::with_name("content")
                        .long("content")
                        .takes_value(true)
                        .required(true)
                        .conflicts_with("path")
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
    config: &mut GlobalConfig,
    client: Client,
) -> Result<(), String> {
    let debug = sub_matches.is_present("debug") || config.debug();
    let mut client = client
        .set_debug(debug)
        .set_uri(get_url(sub_matches, config));

    let result = match sub_matches.subcommand() {
        ("data", Some(m)) => {
            let encryption = encryption(m, config);
            let quota = m.value_of("quota").map(|s| parse_u64(s).unwrap());
            let content = remove_0x(m.value_of("content").unwrap());
            if let Some(private_key) = m.value_of("private-key") {
                client.set_private_key(&parse_privkey(private_key, encryption)?);
            }
            client.store_data(content, quota)
        }
        ("abi", Some(m)) => {
            let encryption = encryption(m, config);
            let quota = m.value_of("quota").map(|s| parse_u64(s).unwrap());
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
            if let Some(private_key) = m.value_of("private-key") {
                client.set_private_key(&parse_privkey(private_key, encryption)?);
            }
            client.store_abi(address, content, quota)
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
