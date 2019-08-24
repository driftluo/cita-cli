use clap::{App, Arg, ArgMatches, SubCommand};

use cita_tool::client::basic::Client;
use cita_tool::{encode, ProtoMessage, TransactionOptions, UnverifiedTransaction};

use crate::cli::{
    encryption, get_url, is_hex, key_validator, parse_address, parse_privkey, parse_u256,
    parse_u32, parse_u64,
};
use crate::interactive::{set_output, GlobalConfig};
use crate::printer::Printer;
use std::fs::File;
use std::io::Read;
use std::str::FromStr;

/// Transaction command
pub fn tx_command() -> App<'static, 'static> {
    App::new("tx")
        .about("Construct transactions, send signed transactions etc.")
        .subcommand(
            SubCommand::with_name("make")
                .about("Construct transaction")
                .arg(
                    Arg::with_name("code")
                        .long("code")
                        .default_value("0x")
                        .takes_value(true)
                        .validator(|code| is_hex(code.as_str()))
                        .help("Binary content of the transaction, default is empty"),
                )
                .arg(
                    Arg::with_name("address")
                        .long("address")
                        .default_value("0x")
                        .takes_value(true)
                        .validator(|address| parse_address(address.as_str()))
                        .help(
                            "The address of the invoking contract, default is empty to \
                             create contract",
                        ),
                )
                .arg(
                    Arg::with_name("height")
                        .long("height")
                        .takes_value(true)
                        .validator(|height| parse_u64(height.as_ref()).map(|_| ()))
                        .help("Current chain height, default query to the chain"),
                )
                .arg(
                    Arg::with_name("chain-id")
                        .long("chain-id")
                        .takes_value(true)
                        .validator(|chain_id| parse_u256(chain_id.as_ref()).map(|_| ()))
                        .help("The chain_id of transaction, default query to the chain"),
                )
                .arg(
                    Arg::with_name("quota")
                        .long("quota")
                        .takes_value(true)
                        .validator(|quota| parse_u64(quota.as_ref()).map(|_| ()))
                        .help("Transaction quota costs, default is 1_000_000"),
                )
                .arg(
                    Arg::with_name("value")
                        .long("value")
                        .takes_value(true)
                        .validator(|value| parse_u256(value.as_ref()).map(|_| ()))
                        .help("The value to send, default is 0"),
                )
                .arg(
                    Arg::with_name("version")
                        .long("version")
                        .takes_value(true)
                        .validator(|version| parse_u32(version.as_str()).map(|_| ()))
                        .help("The version of transaction, default is 0"),
                ),
        )
        .subcommand(
            SubCommand::with_name("sendSignedTransaction")
                .about("Send signed transaction")
                .arg(
                    Arg::with_name("byte-code")
                        .long("byte-code")
                        .takes_value(true)
                        .validator(|code| is_hex(code.as_str()))
                        .required(true)
                        .help("Signed transaction binary data"),
                ),
        )
        .subcommand(
            SubCommand::with_name("sendTransaction")
                .about("Send unsigned transaction")
                .arg(
                    Arg::with_name("byte-code")
                        .long("byte-code")
                        .takes_value(true)
                        .validator(|code| is_hex(code.as_str()))
                        .required(true)
                        .help("Unsigned transaction binary data"),
                )
                .arg(
                    Arg::with_name("private-key")
                        .long("private-key")
                        .validator(|private| key_validator(private.as_str()).map(|_| ()))
                        .takes_value(true)
                        .required(true)
                        .help("Transfer Account Private Key"),
                ),
        )
        .subcommand(
            SubCommand::with_name("decode-unverifiedTransaction")
                .about("Decode unverifiedTransaction")
                .arg(
                    Arg::with_name("content")
                        .long("content")
                        .takes_value(true)
                        .validator(|content| is_hex(content.as_str()))
                        .conflicts_with("file")
                        .required(true)
                        .help("UnverifiedTransaction content"),
                )
                .arg(
                    Arg::with_name("file")
                        .long("file")
                        .takes_value(true)
                        .help("content data file path"),
                ),
        )
}

pub fn tx_processor(
    sub_matches: &ArgMatches,
    printer: &Printer,
    config: &mut GlobalConfig,
    client: Client,
) -> Result<(), String> {
    let debug = sub_matches.is_present("debug") || config.debug();
    let is_color = !sub_matches.is_present("no-color") && config.color();
    let mut client = client
        .set_debug(debug)
        .set_uri(get_url(sub_matches, config));

    let result = match sub_matches.subcommand() {
        ("make", Some(m)) => {
            if let Some(chain_id) = m.value_of("chain-id").map(|s| parse_u256(s).unwrap()) {
                client.set_chain_id(chain_id);
            }
            let code = m.value_of("code").unwrap();
            let address = m.value_of("address").unwrap();
            let current_height = m.value_of("height").map(|s| parse_u64(s).unwrap());
            let quota = m.value_of("quota").map(|s| parse_u64(s).unwrap());
            let value = m.value_of("value").map(|value| parse_u256(value).unwrap());
            let version = m
                .value_of("version")
                .map(|version| parse_u32(version).unwrap());
            let tx_options = TransactionOptions::new()
                .set_code(code)
                .set_address(address)
                .set_current_height(current_height)
                .set_quota(quota)
                .set_value(value)
                .set_version(version);
            let tx = client
                .generate_transaction(tx_options)
                .map_err(|err| format!("{}", err))?;
            printer.println(
                &format!(
                    "0x{}",
                    encode(tx.write_to_bytes().map_err(|err| format!("{}", err))?)
                ),
                is_color,
            );
            return Ok(());
        }
        ("sendSignedTransaction", Some(m)) => {
            let byte_code = m.value_of("byte-code").unwrap();
            client.send_signed_transaction(byte_code)
        }
        ("sendTransaction", Some(m)) => {
            let encryption = encryption(sub_matches, config);
            if let Some(private_key) = m.value_of("private-key") {
                client.set_private_key(&parse_privkey(private_key, encryption)?);
            }
            let byte_code = m.value_of("byte-code").unwrap();
            client.send_transaction(byte_code)
        }
        ("decode-unverifiedTransaction", Some(m)) => {
            let encryption = encryption(sub_matches, config);
            let content = m.value_of("content");
            let content_file = m.value_of("file");
            let mut content_reader = get_content(content_file, content)?;
            let mut content_data = String::new();
            content_reader
                .read_to_string(&mut content_data)
                .map_err(|err| format!("{}", err))?;
            let content_data = content_data.trim();
            let tx =
                UnverifiedTransaction::from_str(&content_data).map_err(|err| format!("{}", err))?;
            printer.println(&tx.to_json(encryption)?, is_color);
            return Ok(());
        }
        _ => {
            return Err(sub_matches.usage().to_owned());
        }
    };
    let resp = result.map_err(|err| format!("{}", err))?;
    printer.println(&resp, is_color);
    set_output(&resp, config);
    Ok(())
}

fn get_content(path: Option<&str>, content: Option<&str>) -> Result<Box<dyn Read>, String> {
    match content {
        Some(data) => Ok(Box::new(::std::io::Cursor::new(data.to_owned()))),
        None => {
            let file = match path {
                Some(path) => File::open(path).map_err(|err| format!("{}", err))?,
                None => return Err("No input content".to_owned()),
            };
            Ok(Box::new(file))
        }
    }
}
