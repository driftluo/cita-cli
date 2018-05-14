extern crate clap;

extern crate cita_tool;

use cita_tool::{Client, JsonRpcParams, ParamsValue};

fn main() {
    let matches = clap::App::new("CITA CLI")
        .arg(
            clap::Arg::with_name("url")
                .long("url")
                .default_value("http://127.0.0.1:1337")
                .takes_value(true)
                .help("JSONRPC server URL"),
        )
        .get_matches();
    let url = matches.value_of("url").unwrap();

    let mut client = Client::new().unwrap().add_url(url);
    let params = JsonRpcParams::new().insert(
        "method",
        ParamsValue::String(String::from("cita_blockNumber")),
    );
    let responses = client.send_request("cita_blockNumber", params).unwrap();
    for response in responses {
        println!("{:?}", response.result());
    }
}
