use std::io;
use std::sync::Arc;

use linefeed::{Interface, ReadResult};

use cli::{abi_processor, build_interactive, key_processor, rpc_processor};

/// Interactive command line
pub fn start(url: &str) -> io::Result<()> {
    let interface = Arc::new(Interface::new("cita-cli")?);
    let mut url = url.to_string();

    interface.set_prompt(&(url.to_owned() + "> "));

    let parser = build_interactive();

    while let ReadResult::Input(line) = interface.read_line()? {
        if line.trim() == "quite" || line.trim() == "exit" {
            break;
        }
        let cli = line.split_whitespace().collect::<Vec<&str>>();

        match parser.clone().get_matches_from_safe(cli) {
            Ok(args) => match args.subcommand() {
                ("switch", Some(m)) => {
                    let host = m.value_of("host").unwrap();
                    interface.set_prompt(&(host.to_owned() + "> "));
                    url = host.to_string();
                }
                ("rpc", Some(sub_matches)) => {
                    if let Err(err) = rpc_processor(sub_matches, Some(url.as_str())) {
                        println!("{}", err);
                    }
                }
                ("abi", Some(sub_matches)) => {
                    if let Err(err) = abi_processor(sub_matches) {
                        println!("{}", err);
                    }
                }
                ("key", Some(sub_matches)) => {
                    if let Err(err) = key_processor(sub_matches) {
                        println!("{}", err);
                    }
                }
                _ => {}
            },
            Err(err) => println!("{}", err),
        }
    }

    Ok(())
}
