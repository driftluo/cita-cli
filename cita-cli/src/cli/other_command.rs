use clap::{App, Arg, ArgMatches, SubCommand};

use cita_tool::client::basic::{Client, Transfer};
use cita_tool::{JsonRpcParams, ParamsValue};

use cli::{
    encryption, get_url, parse_address, parse_privkey, parse_u256, parse_u64, privkey_validator,
    search_app,
};
use interactive::{set_output, GlobalConfig};
use printer::Printer;

use std::collections::BTreeSet;
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

/// Processor search command
pub fn search_processor<'a, 'b>(app: &App<'a, 'b>, sub_matches: &ArgMatches) {
    let keywords = sub_matches
        .values_of("keyword")
        .unwrap()
        .map(|s| s.to_lowercase())
        .collect::<Vec<String>>();
    let mut value: Vec<Vec<String>> = Vec::new();
    search_app(app, &None, &mut value);
    let result = value
        .into_iter()
        .map(|cmd| cmd.join(" "))
        .filter(|cmd| {
            let cmd_lower = cmd.to_lowercase();
            keywords.iter().all(|keyword| cmd_lower.contains(keyword))
        }).collect::<BTreeSet<String>>()
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
        ).arg(
            Arg::with_name("private-key")
                .long("private-key")
                .validator(|private| privkey_validator(private.as_str()).map(|_| ()))
                .takes_value(true)
                .required(true)
                .help("Transfer Account Private Key"),
        ).arg(
            Arg::with_name("value")
                .long("value")
                .validator(|value| parse_u256(value.as_str()).map(|_| ()))
                .takes_value(true)
                .required(true)
                .help("Transfer amount"),
        ).arg(
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
) -> Result<(), String> {
    let debug = sub_matches.is_present("debug") || config.debug();
    let mut client = Client::new()
        .map_err(|err| format!("{}", err))?
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
}

/// Benchmark processor
pub fn benchmark_processor(
    sub_matches: &ArgMatches,
    printer: &Printer,
    config: &GlobalConfig,
) -> Result<(), String> {
    let client = Client::new()
        .map_err(|err| format!("{}", err))?
        .set_uri(get_url(sub_matches, config));

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
        _ => return Err(sub_matches.usage().to_owned()),
    }

    Ok(())
}
