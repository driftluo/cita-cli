use std::sync::Arc;

use clap::{App, ArgMatches};

use cita_tool::{remove_0x, PrivateKey};

use interactive::GlobalConfig;

/// Get url from arg match
pub fn get_url<'a>(m: &'a ArgMatches) -> &'a str {
    m.value_of("url").unwrap()
}

/// The hexadecimal or numeric type string resolves to u64
pub fn parse_u64(height: &str) -> Result<u64, String> {
    match is_hex(height) {
        Ok(()) => Ok(u64::from_str_radix(remove_0x(height), 16).map_err(|err| format!("{}", err))?),
        _ => match height.parse::<u64>() {
            Ok(number) => Ok(number),
            Err(e) => Err(format!("{:?}", e)),
        },
    }
}

/// Attempt to resolve the private key
pub fn parse_privkey(hash: &str) -> Result<PrivateKey, String> {
    let _ = is_hex(hash)?;
    Ok(PrivateKey::from_str(remove_0x(hash))?)
}

pub fn is_hex(hex: &str) -> Result<(), String> {
    let tmp = hex.as_bytes();
    if tmp.len() < 2 {
        Err("Must be a hexadecimal string".to_string())
    } else if tmp[..2] == b"0x"[..] || tmp[..2] == b"0X"[..] {
        Ok(())
    } else {
        Err("Must hex string".to_string())
    }
}

pub fn parse_height(height: &str) -> Result<(), String> {
    match height {
        "latest" | "earliest" => Ok(()),
        _ => match parse_u64(height) {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("{:?}", e)),
        },
    }
}

pub fn blake2b(_m: &ArgMatches, _env_variable: &GlobalConfig) -> bool {
    #[cfg(feature = "blake2b_hash")]
    let blake2b = _m.is_present("blake2b") || _env_variable.blake2b();
    #[cfg(not(feature = "blake2b_hash"))]
    let blake2b = false;
    blake2b
}

/// Search command tree
pub fn search_app<'a, 'b>(
    app: Arc<App<'a, 'b>>,
    prefix: Option<Vec<String>>,
    commands: &mut Vec<Vec<String>>,
) {
    for inner_app in &app.p.subcommands {
        if inner_app.p.subcommands.is_empty() {
            if prefix.is_some() {
                let mut sub_command = prefix.clone().unwrap();
                sub_command.push(inner_app.p.meta.name.clone());
                commands.push(sub_command);
            } else {
                commands.push(vec![inner_app.p.meta.name.clone()]);
            }
        } else {
            let prefix: Option<Vec<String>> = if prefix.is_some() {
                prefix.clone().map(|mut x| {
                    x.push(inner_app.p.meta.name.clone());
                    x
                })
            } else {
                Some(vec![inner_app.p.meta.name.clone()])
            };

            search_app(Arc::new(inner_app.to_owned()), prefix, commands);
        };
    }
}
