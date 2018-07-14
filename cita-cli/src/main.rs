extern crate ansi_term;
extern crate atty;
extern crate cita_tool;
extern crate colored;
#[macro_use]
extern crate clap;
extern crate dotenv;
extern crate linefeed;
extern crate serde;
#[macro_use]
extern crate serde_json;
extern crate shell_words;
#[cfg(feature = "syntect")]
extern crate syntect;

mod cli;
#[cfg(feature = "syntect")]
#[allow(dead_code)]
mod highlight;
mod interactive;
mod json_color;
mod printer;

use std::collections::HashMap;
use std::env;
use std::iter::FromIterator;
use std::process;
use std::rc::Rc;
use std::sync::Arc;

use dotenv::dotenv;

use cli::{
    abi_processor, amend_processor, benchmark_processor, build_cli, contract_processor,
    key_processor, rpc_processor, search_processor, store_processor, transfer_processor,
    tx_processor,
};
use interactive::GlobalConfig;
use printer::Printer;

const ENV_JSONRPC_URL: &'static str = "JSONRPC_URL";
const DEFAULT_JSONRPC_URL: &'static str = "http://127.0.0.1:1337";

fn main() {
    dotenv().ok();

    let mut env_map: HashMap<String, String> = HashMap::from_iter(env::vars());
    let default_jsonrpc_url = env_map
        .remove(ENV_JSONRPC_URL)
        .unwrap_or(DEFAULT_JSONRPC_URL.to_owned());

    let printer = Printer::default();
    let env_variable = GlobalConfig::new();
    let parser = build_cli(&default_jsonrpc_url);
    let matches = parser.clone().get_matches();

    if let Err(err) = match matches.subcommand() {
        ("rpc", Some(m)) => rpc_processor(m, &printer, None, &env_variable),
        ("ethabi", Some(m)) => abi_processor(m, &printer, &env_variable),
        ("key", Some(m)) => key_processor(m, &printer, &env_variable),
        ("scm", Some(m)) => contract_processor(m, &printer, None, &env_variable),
        ("transfer", Some(m)) => transfer_processor(m, &printer, None, &env_variable),
        ("store", Some(m)) => store_processor(m, &printer, None, &env_variable),
        ("amend", Some(m)) => amend_processor(m, &printer, None, &env_variable),
        ("search", Some(m)) => {
            search_processor(Arc::new(parser), m);
            Ok(())
        }
        ("tx", Some(m)) => tx_processor(m, &printer, None, &env_variable),
        ("benchmark", Some(m)) => benchmark_processor(m, &printer, None, &env_variable),
        _ => {
            let _ = interactive::start(&default_jsonrpc_url);
            Ok(())
        }
    } {
        printer.eprintln(&Rc::new(format!("{}", err)), true);
        process::exit(1);
    }
}
