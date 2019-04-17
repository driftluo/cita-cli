use clap::{App, Arg, ArgMatches, SubCommand};
use serde_json::json;

use cita_tool::client::basic::{Client, Transfer};
use cita_tool::{JsonRpcParams, ParamsValue, TransactionOptions};

use crate::cli::{
    encryption, get_url, is_hex, key_validator, parse_address, parse_privkey, parse_u256,
    parse_u32, parse_u64, search_app,
};
use crate::interactive::{set_output, GlobalConfig};
use crate::printer::Printer;

use std::collections::BTreeSet;
use std::io;
use std::time::SystemTime;

/// Search command tree
pub fn search_command() -> App<'static, 'static> {
    App::new("search").about("Search command tree").arg(
        Arg::with_name("keyword")
            .multiple(true)
            .takes_value(true)
            .required(true)
            .index(1),
    )
}

/// x is pattern string
pub fn fuzzy_match(x: &str, y: &str) -> bool {
    let len_pat = x.len();
    let len_a = y.len();
    let str_pat: Vec<char> = x.chars().collect();
    let str_a: Vec<char> = y.chars().collect();
    let m = vec![0; len_a];
    let mut matrix = vec![m; len_pat];

    for (j, item) in str_a.iter().enumerate() {
        if &str_pat[0] == item {
            matrix[0][j] = j + 1;
        }
    }

    for i in 1..len_pat {
        for (j, item) in str_a.iter().enumerate().skip(1) {
            if str_pat[i] == ' ' {
                if matrix[i - 1][j - 1] == 0 {
                    matrix[i][j] = matrix[i][j - 1];
                } else {
                    matrix[i][j] = matrix[i - 1][j - 1] + 1;
                }
            } else if &str_pat[i] == item && matrix[i - 1][j - 1] != 0 {
                matrix[i][j] = matrix[i - 1][j - 1] + 1;
            }
        }
    }

    for j in 0..len_a {
        if matrix[len_pat - 1][j] != 0 {
            return true;
        }
    }
    false
}

/// judge if y in x
pub fn string_include(x: &str, y: &str) -> bool {
    let len_pat = y.len();
    let p: Vec<char> = x.chars().collect();
    let q: Vec<char> = y.chars().collect();

    let mut sum = 0;

    for item in p {
        if item == q[sum] {
            sum += 1;
            if sum == len_pat {
                return true;
            }
        }
    }
    false
}

/// Processor search command
pub fn search_processor<'a, 'b>(app: &App<'a, 'b>, sub_matches: &ArgMatches) {
    let keywords = sub_matches
        .values_of("keyword")
        .unwrap()
        .map(str::to_lowercase)
        .collect::<Vec<String>>();
    let mut value: Vec<Vec<String>> = Vec::new();
    search_app(app, &None, &mut value);
    let result = value
        .into_iter()
        .map(|cmd| cmd.join(" "))
        .filter(|cmd| {
            let cmd_lower = cmd.to_lowercase();
            keywords.iter().all(|keyword| {
                if cmd_lower.contains(keyword) {
                    cmd_lower.contains(keyword)
                } else {
                    fuzzy_match(&keyword, &cmd_lower)
                }
            })
        })
        .collect::<BTreeSet<String>>()
        .into_iter()
        .collect::<Vec<String>>()
        .join("\n");
    println!("{}", result);
}

/// Account transfer command, only applies to charge mode
pub fn transfer_command() -> App<'static, 'static> {
    App::new("transfer")
        .about("Transfer value from address to address")
        .arg(
            Arg::with_name("address")
                .long("address")
                .takes_value(true)
                .validator(|address| parse_address(address.as_str()))
                .required(true)
                .help("Transfer to address"),
        )
        .arg(
            Arg::with_name("private-key")
                .long("private-key")
                .validator(|private| key_validator(private.as_str()).map(|_| ()))
                .takes_value(true)
                .required(true)
                .help("Transfer Account Private Key"),
        )
        .arg(
            Arg::with_name("value")
                .long("value")
                .validator(|value| parse_u256(value.as_str()).map(|_| ()))
                .takes_value(true)
                .required(true)
                .help("Transfer amount"),
        )
        .arg(
            Arg::with_name("quota")
                .long("quota")
                .default_value("30000")
                .validator(|quota| parse_u64(quota.as_str()).map(|_| ()))
                .takes_value(true)
                .help("Transaction quota costs, default 30000"),
        )
}

/// Account transfer processor
pub fn transfer_processor(
    sub_matches: &ArgMatches,
    printer: &Printer,
    config: &mut GlobalConfig,
    client: Client,
) -> Result<(), String> {
    let debug = sub_matches.is_present("debug") || config.debug();
    let mut client = client
        .set_debug(debug)
        .set_uri(get_url(sub_matches, config));

    let encryption = encryption(sub_matches, config);
    client.set_private_key(&parse_privkey(
        sub_matches.value_of("private-key").unwrap(),
        encryption,
    )?);
    let address = sub_matches.value_of("address").unwrap();
    let quota = sub_matches
        .value_of("quota")
        .map(|quota| parse_u64(quota).unwrap());
    let value = parse_u256(sub_matches.value_of("value").unwrap()).unwrap();
    let is_color = !sub_matches.is_present("no-color") && config.color();
    let response = client
        .transfer(value, address, quota)
        .map_err(|err| format!("{}", err))?;
    printer.println(&response, is_color);
    set_output(&response, config);
    Ok(())
}

/// Simple benchmark
pub fn benchmark_command() -> App<'static, 'static> {
    App::new("benchmark")
        .about("Simple performance test")
        .subcommand(SubCommand::with_name("get-height").about("Send 1,000 query height requests"))
        .subcommand(
            SubCommand::with_name("sendTransaction")
                .about("Send the same transaction at the same time and send n times")
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
                        .help("The chain_id of transaction"),
                )
                .arg(
                    Arg::with_name("private-key")
                        .long("private-key")
                        .takes_value(true)
                        .required(true)
                        .validator(|privkey| key_validator(privkey.as_ref()).map(|_| ()))
                        .help("The private key of transaction"),
                )
                .arg(
                    Arg::with_name("quota")
                        .long("quota")
                        .takes_value(true)
                        .validator(|quota| parse_u64(quota.as_ref()).map(|_| ()))
                        .help("Transaction quota costs, default 10_000_000"),
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
                )
                .arg(
                    Arg::with_name("number")
                        .long("number")
                        .takes_value(true)
                        .default_value("1000")
                        .validator(|version| parse_u32(version.as_str()).map(|_| ()))
                        .help("The number of transmissions, default is 1000"),
                ),
        )
}

/// Benchmark processor
pub fn benchmark_processor(
    sub_matches: &ArgMatches,
    printer: &Printer,
    config: &GlobalConfig,
    client: Client,
) -> Result<(), String> {
    let mut client = client.set_uri(get_url(sub_matches, config));

    match sub_matches.subcommand() {
        ("get-height", _) => {
            let params = JsonRpcParams::new()
                .insert("method", ParamsValue::String(String::from("blockNumber")));
            let start = SystemTime::now();
            let result = client
                .send_request(vec![params; 1000].into_iter())
                .map_err(|err| format!("{}", err))?;
            assert_eq!(result.len(), 1000);
            match start.elapsed() {
                Ok(elapsed) => {
                    let duration: f64 = f64::from_bits(elapsed.as_secs())
                        + (<f64 as From<u32>>::from(elapsed.subsec_nanos()) / 1_000_000_000.0);
                    printer.println(
                        &format!(
                            "A total of 1,000 requests were sent, which took {} seconds and tps is {}",
                            duration,
                            1000.0 / duration
                        ),
                        true,
                    );
                }
                Err(e) => {
                    // an error occurred!
                    return Err(format!("Error: {:?}", e));
                }
            }
        }
        ("sendTransaction", Some(m)) => {
            let encryption = encryption(m, config);
            if let Some(chain_id) = m.value_of("chain-id").map(|s| parse_u256(s).unwrap()) {
                client.set_chain_id(chain_id);
            }
            if let Some(private_key) = m.value_of("private-key") {
                client.set_private_key(&parse_privkey(private_key, encryption)?);
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
            let number = m
                .value_of("number")
                .map(|number| parse_u32(number).unwrap())
                .unwrap();

            let mut txs = Vec::with_capacity(number as usize);
            for _ in 0..number {
                let tx = client
                    .generate_transaction(tx_options)
                    .map_err(|err| format!("{}", err))?;
                let byte_code = client
                    .generate_sign_transaction(&tx)
                    .map_err(|err| format!("{}", err))?;
                let params = JsonRpcParams::new()
                    .insert(
                        "method",
                        ParamsValue::String(String::from("sendRawTransaction")),
                    )
                    .insert(
                        "params",
                        ParamsValue::List(vec![ParamsValue::String(byte_code)]),
                    );
                txs.push(params);
            }
            let result = client
                .send_request(txs.into_iter())
                .map_err(|err| format!("{}", err))?;
            printer.println(&json!(result), true);
        }
        _ => return Err(sub_matches.usage().to_owned()),
    }

    Ok(())
}

// Generate completion scripts
pub fn completion_command() -> App<'static, 'static> {
    App::new("completions")
        .about("Generates completion scripts for your shell")
        .arg(
            Arg::with_name("shell")
                .required(true)
                .possible_values(&["bash", "fish", "zsh"])
                .help("The shell to generate the script for"),
        )
}
pub fn completion_processor(app: &mut App, sub_matches: &ArgMatches) {
    let shell = sub_matches.value_of("shell").unwrap();
    app.gen_completions_to("cita-cli", shell.parse().unwrap(), &mut io::stdout());
}
#[cfg(test)]
mod test {
    use super::string_include;

    #[test]
    fn test_string_include() {
        assert_eq!(string_include("abcdef", "ace"), true);
        assert_eq!(string_include("abcdef", "acc"), false);
        assert_eq!(string_include("abcdef", "ack"), false);
        assert_eq!(string_include("ads fety", "af"), true);
        assert_eq!(string_include("ads fety", "ta"), false);
        assert_eq!(string_include("ads fety", "sa"), false);
        assert_eq!(string_include("ads fety", "yf"), false);
        assert_eq!(string_include("ads fety", "fy"), true);
        assert_eq!(string_include("ads fety", "a-"), false);
        assert_eq!(string_include("ads fety", "  "), false);
        assert_eq!(string_include("ads fety", " f"), true);
    }
}
