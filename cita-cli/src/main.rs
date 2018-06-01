extern crate ansi_term;
extern crate atty;
extern crate cita_tool;
extern crate clap;
extern crate dotenv;
extern crate ethabi;
extern crate linefeed;
extern crate rustc_hex as hex;
#[macro_use]
extern crate serde_json;
extern crate shell_words;
// #[cfg(feature = "color")]
extern crate syntect;

mod abi;
mod cli;
mod printer;
// #[cfg(feature = "color")]
mod highlight;
mod interactive;

use std::collections::HashMap;
use std::env;
use std::rc::Rc;
use std::iter::FromIterator;
use std::process;

use dotenv::dotenv;

use printer::Printer;
use cli::{abi_processor, build_cli, key_processor, rpc_processor};

const ENV_JSONRPC_URL: &'static str = "JSONRPC_URL";
const DEFAULT_JSONRPC_URL: &'static str = "http://127.0.0.1:1337";

fn main() {
    dotenv().ok();

    let mut env_map: HashMap<String, String> = HashMap::from_iter(env::vars());
    let default_jsonrpc_url = env_map
        .remove(ENV_JSONRPC_URL)
        .unwrap_or(DEFAULT_JSONRPC_URL.to_owned());

    let printer = Printer::default();
    let matches = build_cli(&default_jsonrpc_url).get_matches();

    if let Err(err) = match matches.subcommand() {
        ("rpc", Some(m)) => rpc_processor(m, &printer, None, false, true),
        ("abi", Some(m)) => abi_processor(m, &printer),
        ("key", Some(m)) => key_processor(m, &printer, false),
        _ => {
            let _ = interactive::start(&default_jsonrpc_url);
            Ok(())
        }
    } {
        printer.eprintln(&Rc::new(format!("{}", err)), true);
        process::exit(1);
    }
}
