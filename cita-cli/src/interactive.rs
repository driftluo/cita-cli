use std::env;
use std::io;
use std::sync::Arc;

use linefeed::{Interface, ReadResult};
use shell_words;

use cli::{abi_processor, build_interactive, key_processor, rpc_processor};

/// Interactive command line
pub fn start(url: &str) -> io::Result<()> {
    let interface = Arc::new(Interface::new("cita-cli")?);
    let mut url = url.to_string();

    let mut history_file = env::home_dir().unwrap();
    history_file.push(".cita-cli.history");
    let history_file = history_file.to_str().unwrap();

    interface.set_prompt(&(url.to_owned() + "> "));

    if let Err(e) = interface.load_history(history_file) {
        if e.kind() == io::ErrorKind::NotFound {
            println!(
                "History file {} doesn't exist, not loading history.",
                history_file
            );
        } else {
            eprintln!("Could not load history file {}: {}", history_file, e);
        }
    }

    let mut parser = build_interactive();

    while let ReadResult::Input(line) = interface.read_line()? {
        if line.trim() == "quite" || line.trim() == "exit" {
            break;
        }
        let args = shell_words::split(line.as_str()).unwrap();

        if let Err(err) = match parser.get_matches_from_safe_borrow(args) {
            Ok(matches) => match matches.subcommand() {
                ("switch", Some(m)) => {
                    let host = m.value_of("host").unwrap();
                    interface.set_prompt(&(host.to_owned() + "> "));
                    url = host.to_string();
                    Ok(())
                }
                ("rpc", Some(m)) => rpc_processor(m, Some(url.as_str())),
                ("abi", Some(m)) => abi_processor(m),
                ("key", Some(m)) => key_processor(m),
                _ => Ok(()),
            },
            Err(err) => Err(format!("{}", err)),
        } {
            println!("{}", err);
        }

        interface.add_history_unique(line.clone());
        if let Err(err) = interface.save_history(history_file) {
            println!("Save command history failed: {}", err);
        };
    }

    Ok(())
}
