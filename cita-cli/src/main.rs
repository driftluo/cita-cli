extern crate ansi_term;
extern crate atty;
extern crate cita_tool;
extern crate colored;
#[macro_use]
extern crate clap;
extern crate dotenv;
extern crate rustyline;
extern crate serde;
#[macro_use]
extern crate serde_json;
extern crate dirs;
extern crate regex;
extern crate shell_words;

mod cli;
mod interactive;
mod json_color;
mod printer;

use std::collections::HashMap;
use std::env;
use std::iter::FromIterator;
use std::process;
use std::rc::Rc;

use dotenv::dotenv;

use cli::{
    abi_processor, amend_processor, benchmark_processor, build_cli, completion_processor,
    contract_processor, key_processor, rpc_processor, search_processor, store_processor,
    transfer_processor, tx_processor,
};
use interactive::GlobalConfig;
use printer::Printer;

const ENV_JSONRPC_URL: &str = "JSONRPC_URL";
const DEFAULT_JSONRPC_URL: &str = "http://127.0.0.1:1337";

fn main() {
    dotenv().ok();

    let mut env_map: HashMap<String, String> = HashMap::from_iter(env::vars());
    let default_jsonrpc_url = env_map
        .remove(ENV_JSONRPC_URL)
        .unwrap_or_else(|| DEFAULT_JSONRPC_URL.to_owned());

    let printer = Printer::default();
    let mut config = GlobalConfig::new(default_jsonrpc_url.to_string());
    let mut parser = build_cli();
    let matches = parser.clone().get_matches();

    if let Err(err) = match matches.subcommand() {
        ("rpc", Some(m)) => rpc_processor(m, &printer, &mut config),
        ("ethabi", Some(m)) => abi_processor(m, &printer, &config),
        ("key", Some(m)) => key_processor(m, &printer, &config),
        ("scm", Some(m)) => contract_processor(m, &printer, &mut config),
        ("transfer", Some(m)) => transfer_processor(m, &printer, &mut config),
        ("store", Some(m)) => store_processor(m, &printer, &mut config),
        ("amend", Some(m)) => amend_processor(m, &printer, &mut config),
        ("search", Some(m)) => {
            search_processor(&parser, m);
            Ok(())
        }
        ("tx", Some(m)) => tx_processor(m, &printer, &mut config),
        ("benchmark", Some(m)) => benchmark_processor(m, &printer, &config),
        ("completions", Some(m)) => {
            completion_processor(&mut parser, m);
            Ok(())
        }
        _ => {
            if let Err(err) = interactive::start(&default_jsonrpc_url) {
                eprintln!("Something error: kind {:?}, message {}", err.kind(), err)
            }
            Ok(())
        }
    } {
        printer.eprintln(&Rc::new(err.to_string()), true);
        process::exit(1);
    }
}
