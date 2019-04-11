mod abi_command;
mod amend_command;
mod contract_command;
mod key_command;
mod other_command;
mod rpc_command;
mod store_command;
mod tx_command;
mod util;

pub(crate) use self::util::{
    encryption, get_url, h256_validator, is_hex, key_validator, parse_address, parse_height,
    parse_privkey, parse_u256, parse_u32, parse_u64, search_app,
};

pub use self::abi_command::{abi_command, abi_processor};
pub use self::amend_command::{amend_command, amend_processor};
pub use self::contract_command::{contract_command, contract_processor};
pub use self::key_command::{key_command, key_processor};
pub use self::other_command::{
    benchmark_command, benchmark_processor, completion_command, completion_processor,
    search_command, search_processor, string_include, transfer_command, transfer_processor,
};
pub use self::rpc_command::{rpc_command, rpc_processor};
pub use self::store_command::{store_command, store_processor};
pub use self::tx_command::{tx_command, tx_processor};

use cita_tool::parse_url;
use clap::{crate_version, App, AppSettings, Arg, SubCommand};

/// Generate cli
pub fn build_cli(version: &str) -> App {
    let arg_url = Arg::with_name("url")
        .long("url")
        .takes_value(true)
        .validator(|url| parse_url(url.as_ref()).map(|_| ()))
        .global(true)
        .help("JSONRPC server URL (dotenv: JSONRPC_URL)");
    App::new("cita-cli")
        .version(version)
        .global_setting(AppSettings::ColoredHelp)
        .global_setting(AppSettings::DeriveDisplayOrder)
        .subcommand(rpc_command().arg(arg_url.clone()))
        .subcommand(contract_command().arg(arg_url.clone()))
        .subcommand(key_command())
        .subcommand(abi_command())
        .subcommand(transfer_command().arg(arg_url.clone()))
        .subcommand(store_command().arg(arg_url.clone()))
        .subcommand(amend_command().arg(arg_url.clone()))
        .subcommand(search_command())
        .subcommand(tx_command().arg(arg_url.clone()))
        .subcommand(benchmark_command().arg(arg_url.clone()))
        .subcommand(completion_command())
        .arg(
            Arg::with_name("algorithm")
                .long("algorithm")
                .global(true)
                .takes_value(true)
                .possible_values(&["secp256k1", "ed25519", "sm2"])
                .help("Select the encryption algorithm you want, the default is secp256k1"),
        )
        .arg(
            Arg::with_name("no-color")
                .long("no-color")
                .global(true)
                .help("Do not highlight(color) output json"),
        )
        .arg(
            Arg::with_name("debug")
                .long("debug")
                .global(true)
                .help("Display request parameters"),
        )
}

/// Interactive parser
pub fn build_interactive() -> App<'static, 'static> {
    App::new("interactive")
        .version(crate_version!())
        .setting(AppSettings::NoBinaryName)
        .global_setting(AppSettings::ColoredHelp)
        .global_setting(AppSettings::DeriveDisplayOrder)
        .global_setting(AppSettings::DisableVersion)
        .subcommand(
            SubCommand::with_name("switch")
                .about("Switch environment variables, such as url/algorithm")
                .arg(
                    Arg::with_name("url")
                        .long("url")
                        .validator(|url| parse_url(url.as_ref()).map(|_| ()))
                        .takes_value(true)
                        .help("Switch url"),
                )
                .arg(
                    Arg::with_name("color")
                        .long("color")
                        .help("Switching color for rpc interface"),
                )
                .arg(
                    Arg::with_name("algorithm")
                        .long("algorithm")
                        .takes_value(true)
                        .possible_values(&["secp256k1", "ed25519", "sm2"])
                        .help("Select the encryption algorithm you want, the default is secp256k1"),
                )
                .arg(
                    Arg::with_name("debug")
                        .long("debug")
                        .help("Switching debug mode"),
                )
                .arg(
                    Arg::with_name("json")
                        .long("json")
                        .help("Switching json format"),
                )
                .arg(
                    Arg::with_name("completion_style")
                        .long("completion_style")
                        .help("Switching completion style"),
                )
                .arg(
                    Arg::with_name("edit_style")
                        .long("edit_style")
                        .help("Switching edit style"),
                )
                .arg(
                    Arg::with_name("save_private")
                        .long("save_private")
                        .help("Switching whether save private key"),
                ),
        )
        .subcommand(search_command())
        .subcommand(SubCommand::with_name("info").about("Display global variables"))
        .subcommand(rpc_command())
        .subcommand(key_command())
        .subcommand(abi_command())
        .subcommand(contract_command())
        .subcommand(transfer_command())
        .subcommand(store_command())
        .subcommand(amend_command())
        .subcommand(tx_command())
        .subcommand(benchmark_command())
        .subcommand(
            SubCommand::with_name("exit")
                .visible_alias("quit")
                .about("Exit the interactive interface"),
        )
        .subcommand(
            SubCommand::with_name("set")
                .about("Set temporary variables")
                .arg(
                    Arg::with_name("key")
                        .required(true)
                        .index(1)
                        .help("The name of variable"),
                )
                .arg(
                    Arg::with_name("value")
                        .required(true)
                        .index(2)
                        .help("Variable value"),
                ),
        )
        .subcommand(
            SubCommand::with_name("get")
                .about("Get variable value")
                .arg(Arg::with_name("key").index(1).help("The name of variable")),
        )
}
