use ansi_term::Colour::Yellow;
use clap::{App, Arg, ArgMatches, SubCommand};

use cita_tool::client::basic::Client;
use cita_tool::{
    encode, pubkey_to_address, ProtoMessage, TransactionOptions, UnverifiedTransaction,
};

use cli::{blake2b, get_url, is_hex, parse_privkey, parse_u64};
use interactive::GlobalConfig;
use printer::Printer;

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
                        .takes_value(true)
                        .required(true)
                        .validator(|code| is_hex(code.as_str()))
                        .help("Binary content of the transaction"),
                )
                .arg(
                    Arg::with_name("address")
                        .long("address")
                        .default_value("0x")
                        .takes_value(true)
                        .validator(|address| is_hex(address.as_str()))
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
                        .validator(|chain_id| match chain_id.parse::<u32>() {
                            Ok(_) => Ok(()),
                            Err(err) => Err(format!("{:?}", err)),
                        })
                        .help("The chain_id of transaction"),
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
                        .validator(|value| is_hex(value.as_ref()))
                        .help("The value to send, default is 0"),
                ),
        )
        .subcommand(
            SubCommand::with_name("sendSignedTransaction")
                .about("Send signed transaction")
                .arg(
                    Arg::with_name("byte-code")
                        .long("byte-code")
                        .takes_value(true)
                        .validator(|address| is_hex(address.as_str()))
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
                        .validator(|address| is_hex(address.as_str()))
                        .required(true)
                        .help("Unsigned transaction binary data"),
                )
                .arg(
                    Arg::with_name("private-key")
                        .long("private-key")
                        .validator(|private| parse_privkey(private.as_str()).map(|_| ()))
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
                        .required(true)
                        .help("UnverifiedTransaction content"),
                ),
        )
}

pub fn tx_processor(
    sub_matches: &ArgMatches,
    printer: &Printer,
    url: Option<&str>,
    env_variable: &GlobalConfig,
) -> Result<(), String> {
    let debug = sub_matches.is_present("debug") || env_variable.debug();
    let is_color = !sub_matches.is_present("no-color") && env_variable.color();
    let mut client = Client::new()
        .map_err(|err| format!("{}", err))?
        .set_debug(debug)
        .set_uri(url.unwrap_or_else(|| match sub_matches.subcommand() {
            (_, Some(m)) => get_url(m),
            _ => "http://127.0.0.1:1337",
        }));
    let result = match sub_matches.subcommand() {
        ("make", Some(m)) => {
            if let Some(chain_id) = m.value_of("chain-id").map(|s| s.parse::<u32>().unwrap()) {
                client.set_chain_id(chain_id);
            }
            if let Some(private_key) = m.value_of("private-key") {
                client.set_private_key(parse_privkey(private_key)?);
            }
            let code = m.value_of("code").unwrap();
            let address = m.value_of("address").unwrap();
            let current_height = m.value_of("height").map(|s| parse_u64(s).unwrap());
            let quota = m.value_of("quota").map(|s| s.parse::<u64>().unwrap());
            let value = m.value_of("value");
            let tx_options = TransactionOptions::new()
                .set_code(code)
                .set_address(address)
                .set_current_height(current_height)
                .set_quota(quota)
                .set_value(value);
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
            let blake2b = blake2b(sub_matches, env_variable);
            if let Some(private_key) = m.value_of("private-key") {
                client.set_private_key(parse_privkey(private_key)?);
            }
            let byte_code = m.value_of("byte-code").unwrap();
            client.send_transaction(byte_code, blake2b)
        }
        ("decode-unverifiedTransaction", Some(m)) => {
            let blake2b = blake2b(sub_matches, env_variable);
            let content = m.value_of("content").unwrap();
            let tx = UnverifiedTransaction::from_str(&content).map_err(|err| format!("{}", err))?;
            let pub_key = tx.public_key(blake2b)?;
            printer.println(&tx.to_json(), is_color);
            printer.println(
                &format!(
                    "{} 0x{:#x}",
                    Yellow.paint("[from]:"),
                    pubkey_to_address(&pub_key)
                ),
                is_color,
            );
            return Ok(());
        }
        _ => {
            return Err(sub_matches.usage().to_owned());
        }
    };
    let resp = result.map_err(|err| format!("{}", err))?;
    printer.println(&resp, is_color);
    Ok(())
}
