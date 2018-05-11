extern crate cita_cli;

use cita_cli::{JsonRpcParams, Client, ParamsValue};


fn main() {
    let mut client = Client::new().unwrap().add_url("http://127.0.0.1:1337");
    let mut params = JsonRpcParams::new();
    params.insert(String::from("method"), ParamsValue::String(String::from("cita_blockNumber")));
    client.send_requests("cita_blockNumber", params);
}
