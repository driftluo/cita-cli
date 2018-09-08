use ansi_term::Colour::Yellow;
use clap::{App, Arg, ArgMatches, SubCommand};

use cita_tool::{pubkey_to_address, remove_0x, KeyPair, PubKey};

use cli::{encryption, privkey_validator, pubkey_validator};
use interactive::GlobalConfig;
use printer::Printer;

/// Key related commands
pub fn key_command() -> App<'static, 'static> {
    App::new("key")
        .about("Some key operations, such as generating address, public key")
        .subcommand(SubCommand::with_name("create"))
        .subcommand(
            SubCommand::with_name("from-private-key").arg(
                Arg::with_name("private-key")
                    .long("private-key")
                    .takes_value(true)
                    .required(true)
                    .validator(|privkey| privkey_validator(privkey.as_ref()).map(|_| ()))
                    .help("The private key of transaction"),
            ),
        )
        .subcommand(
            SubCommand::with_name("pub-to-address").arg(
                Arg::with_name("pubkey")
                    .long("pubkey")
                    .takes_value(true)
                    .required(true)
                    .validator(|pubkey| pubkey_validator(remove_0x(&pubkey)).map(|_| ()))
                    .help("Pubkey"),
            ),
        )
}

/// Key processor
pub fn key_processor(
    sub_matches: &ArgMatches,
    printer: &Printer,
    config: &GlobalConfig,
) -> Result<(), String> {
    match sub_matches.subcommand() {
        ("create", Some(m)) => {
            let encryption = encryption(m, config);
            let key_pair = KeyPair::new(encryption);
            let is_color = !sub_matches.is_present("no-color") && config.color();
            printer.println(&key_pair, is_color);
        }
        ("from-private-key", Some(m)) => {
            let encryption = encryption(m, config);
            let private_key = m.value_of("private-key").unwrap();
            let key_pair = KeyPair::from_str(remove_0x(private_key), encryption)?;
            let is_color = !sub_matches.is_present("no-color") && config.color();
            printer.println(&key_pair, is_color);
        }
        ("pub-to-address", Some(m)) => {
            let encryption = encryption(m, config);
            let pubkey = m.value_of("pubkey").unwrap();
            let address = pubkey_to_address(&PubKey::from_str(remove_0x(pubkey), encryption)?);
            if printer.color() {
                printer.println(
                    &format!("{} 0x{:#x}", Yellow.paint("[address]:"), address),
                    true,
                );
            } else {
                printer.println(&format!("{} 0x{:#x}", "[address]:", address), false);
            }
        }
        _ => {
            return Err(sub_matches.usage().to_owned());
        }
    }
    Ok(())
}
