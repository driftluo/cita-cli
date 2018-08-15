use clap::{App, Arg, ArgGroup, ArgMatches, SubCommand};

use cita_tool::client::basic::{Client, StoreExt};
use cita_tool::remove_0x;

use cli::{blake2b, get_url, is_hex, parse_privkey, parse_u64};
use interactive::GlobalConfig;
use printer::Printer;

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
            .validator(|privkey| parse_privkey(privkey.as_ref()).map(|_| ()))
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
                        .takes_value(true)
                        .help("The contract address of the ABI"),
                )
                .arg(
                    Arg::with_name("content")
                        .long("content")
                        .takes_value(true)
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
        ("data", Some(m)) => {
            let blake2b = blake2b(m, env_variable);
            let quota = m.value_of("quota").map(|s| parse_u64(s).unwrap());
            let content = remove_0x(m.value_of("content").unwrap());
            // TODO: this really should be fixed, private key must required
            if let Some(private_key) = m.value_of("private-key") {
                client.set_private_key(&parse_privkey(private_key)?);
            }
            client.store_data(content, quota, blake2b)
        }
        ("abi", Some(m)) => {
            let blake2b = blake2b(m, env_variable);
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
            // TODO: this really should be fixed, private key must required
            if let Some(private_key) = m.value_of("private-key") {
                client.set_private_key(&parse_privkey(private_key)?);
            }
            client.store_abi(address, content, quota, blake2b)
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
