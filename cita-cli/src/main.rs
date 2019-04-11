#![deny(warnings)]

mod cli;
mod interactive;
mod json_color;
mod printer;

use std::collections::HashMap;
use std::env;
use std::iter::FromIterator;
use std::process;
use std::rc::Rc;

use cita_tool::client::basic::Client;
use clap::crate_version;
use dotenv::dotenv;

include!(concat!(env!("OUT_DIR"), "/build_info.rs"));

use crate::cli::{
    abi_processor, amend_processor, benchmark_processor, build_cli, completion_processor,
    contract_processor, key_processor, rpc_processor, search_processor, store_processor,
    transfer_processor, tx_processor,
};
use crate::interactive::GlobalConfig;
use crate::printer::Printer;

const ENV_JSONRPC_URL: &str = "JSONRPC_URL";
const DEFAULT_JSONRPC_URL: &str = "http://127.0.0.1:1337";

fn main() {
    dotenv().ok();
    let version = format!(
        "{}+{}, {}",
        crate_version!(),
        get_commit_id(),
        feature_version()
    );

    let mut env_map: HashMap<String, String> = HashMap::from_iter(env::vars());
    let default_jsonrpc_url = env_map
        .remove(ENV_JSONRPC_URL)
        .unwrap_or_else(|| DEFAULT_JSONRPC_URL.to_owned());

    let printer = Printer::default();
    let mut config = GlobalConfig::new(default_jsonrpc_url.to_string());
    let mut parser = build_cli(version.as_str());
    let matches = parser.clone().get_matches();
    let client = Client::new();

    if let Err(err) = match matches.subcommand() {
        ("rpc", Some(m)) => rpc_processor(m, &printer, &mut config, client.clone()),
        ("ethabi", Some(m)) => abi_processor(m, &printer, &config),
        ("key", Some(m)) => key_processor(m, &printer, &config),
        ("scm", Some(m)) => contract_processor(m, &printer, &mut config, client.clone()),
        ("transfer", Some(m)) => transfer_processor(m, &printer, &mut config, client.clone()),
        ("store", Some(m)) => store_processor(m, &printer, &mut config, client.clone()),
        ("amend", Some(m)) => amend_processor(m, &printer, &mut config, client.clone()),
        ("search", Some(m)) => {
            search_processor(&parser, m);
            Ok(())
        }
        ("tx", Some(m)) => tx_processor(m, &printer, &mut config, client.clone()),
        ("benchmark", Some(m)) => benchmark_processor(m, &printer, &config, client.clone()),
        ("completions", Some(m)) => {
            completion_processor(&mut parser, m);
            Ok(())
        }
        _ => {
            if let Err(err) = interactive::start(&default_jsonrpc_url, &client) {
                eprintln!("Something error: kind {:?}, message {}", err.kind(), err)
            }
            Ok(())
        }
    } {
        printer.eprintln(&Rc::new(err.to_string()), true);
        process::exit(1);
    }
}

fn feature_version() -> String {
    if cfg!(feature = "tls") {
        "support tls".to_owned()
    } else {
        "no other support".to_owned()
    }
}
