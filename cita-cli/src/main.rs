extern crate ansi_term;
extern crate cita_tool;
extern crate clap;
extern crate dotenv;
extern crate ethabi;
extern crate linefeed;
extern crate rustc_hex as hex;
extern crate shell_words;
extern crate syntect;
#[macro_use]
extern crate lazy_static;

mod abi;
mod cli;
mod highlight;
mod interactive;

use std::collections::HashMap;
use std::env;
use std::iter::FromIterator;
use std::process;

use dotenv::dotenv;

use cli::{abi_processor, build_cli, key_processor, rpc_processor};

const ENV_JSONRPC_URL: &'static str = "JSONRPC_URL";
const DEFAULT_JSONRPC_URL: &'static str = "http://127.0.0.1:1337";

fn main() {
    dotenv().ok();

    let mut env_map: HashMap<String, String> = HashMap::from_iter(env::vars());
    let default_jsonrpc_url = env_map
        .remove(ENV_JSONRPC_URL)
        .unwrap_or(DEFAULT_JSONRPC_URL.to_owned());

    let matches = build_cli(&default_jsonrpc_url).get_matches();

    if let Err(err) = match matches.subcommand() {
        ("rpc", Some(m)) => rpc_processor(m, None),
        ("abi", Some(m)) => abi_processor(m),
        ("key", Some(m)) => key_processor(m),
        _ => {
            let _ = interactive::start(&default_jsonrpc_url);
            Ok(())
        }
    } {
        println!("{}", err);
        process::exit(1);
    }
}
