extern crate dotenv;
extern crate clap;

extern crate cita_tool;

use std::env;
use std::collections::HashMap;

use dotenv::dotenv;

use cita_tool::{Client, JsonRpcParams, ParamsValue};


const ENV_JSONRPC_URL: &'static str = "JSONRPC_URL";
const DEFAULT_JSONRPC_URL: &'static str = "http://127.0.0.1:1337";

fn main() {
    dotenv().ok();

    let mut env_map = HashMap::new();
    for (key, value) in env::vars() {
        env_map.insert(key, value);
    }
    let default_jsonrpc_url = env_map
        .remove(ENV_JSONRPC_URL)
        .unwrap_or(DEFAULT_JSONRPC_URL.to_owned());

    let matches = clap::App::new("CITA CLI")
        .arg(
            clap::Arg::with_name("url")
                .long("url")
                .default_value(default_jsonrpc_url.as_str())
                .takes_value(true)
                .help(format!("JSONRPC server URL (dotenv: {})", ENV_JSONRPC_URL).as_str()),
        )
        .get_matches();
    let url = matches.value_of("url").unwrap();

    let mut client = Client::new().unwrap().add_url(url);
    let params = JsonRpcParams::new().insert(
        "method",
        ParamsValue::String(String::from("cita_blockNumber")),
    );

    let responses = client.send_request(params).unwrap();
    for response in responses {
        println!("{}", response);
    }
}
