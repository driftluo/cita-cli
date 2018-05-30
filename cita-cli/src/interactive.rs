use std::env;
use std::io;
use std::sync::Arc;

use linefeed::complete::{Completer, Completion};
use linefeed::terminal::Terminal;
use linefeed::{Interface, Prompter, ReadResult};
use shell_words;

use cli::{abi_processor, build_interactive, key_processor, rpc_processor};

lazy_static! {
    static ref COMPLETION: CITACompleter<'static> = CITACompleter::new();
}

/// Interactive command line
pub fn start(url: &str) -> io::Result<()> {
    let interface = Arc::new(Interface::new("cita-cli")?);
    let mut url = url.to_string();

    let mut history_file = env::home_dir().unwrap();
    history_file.push(".cita-cli.history");
    let history_file = history_file.to_str().unwrap();

    interface.set_completer(Arc::new(CITACompletion));

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
                ("exit", _) => break,
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

struct CITACompleter<'a> {
    root: Vec<&'a str>,
    rpc: Vec<&'a str>,
    key: Vec<&'a str>,
    abi: Vec<&'a str>,
    sub_abi: Vec<&'a str>,
}

impl<'a> CITACompleter<'a> {
    fn new() -> Self {
        CITACompleter {
            root: vec!["exit", "quit", "rpc", "key", "abi"],
            rpc: vec![
                "net_peerCount",
                "cita_blockNumber",
                "cita_sendTransaction",
                "cita_getBlockByHash",
                "cita_getBlockByNumber",
                "eth_getTransaction",
                "eth_getCode",
                "eth_getAbi",
                "eth_getBalance",
                "eth_getTransactionReceipt",
                "eth_call",
                "cita_getTransactionProof",
                "eth_getLogs",
                "cita_getMetaData",
                "cita_getTransaction",
                "cita_getTransactionCount",
                "eth_newBlockFilter",
                "eth_getFilterChanges",
                "eth_getFilterLogs",
            ],
            key: vec!["create", "from-private-key", "pub-to-address"],
            abi: vec!["encode"],
            sub_abi: vec!["function", "params"],
        }
    }

    fn root_filter(&self, command: Option<String>) -> Vec<Completion> {
        if command.is_none() {
            self.root
                .iter()
                .map(|cmd| Completion::simple(cmd.to_string()))
                .collect()
        } else {
            self.root
                .iter()
                .filter(|cmd| cmd.starts_with(command.clone().unwrap().as_str()))
                .map(|cmd| Completion::simple(cmd.to_string()))
                .collect()
        }
    }

    fn rpc_filter(&self, command: &str) -> Vec<Completion> {
        if command.is_empty() {
            self.rpc
                .iter()
                .map(|cmd| Completion::simple(cmd.to_string()))
                .collect()
        } else {
            self.rpc
                .iter()
                .filter(|cmd| cmd.starts_with(command))
                .map(|cmd| Completion::simple(cmd.to_string()))
                .collect()
        }
    }

    fn abi_filter(&self, command: &str) -> Vec<Completion> {
        if command.is_empty() {
            self.abi
                .iter()
                .map(|cmd| Completion::simple(cmd.to_string()))
                .collect()
        } else {
            self.abi
                .iter()
                .filter(|cmd| cmd.starts_with(command))
                .map(|cmd| Completion::simple(cmd.to_string()))
                .collect()
        }
    }

    fn sub_abi_filter(&self, command: &str) -> Vec<Completion> {
        if command.is_empty() {
            self.sub_abi
                .iter()
                .map(|cmd| Completion::simple(cmd.to_string()))
                .collect()
        } else {
            self.sub_abi
                .iter()
                .filter(|cmd| cmd.starts_with(command))
                .map(|cmd| Completion::simple(cmd.to_string()))
                .collect()
        }
    }

    fn key_filter(&self, command: &str) -> Vec<Completion> {
        if command.is_empty() {
            self.key
                .iter()
                .map(|cmd| Completion::simple(cmd.to_string()))
                .collect()
        } else {
            self.key
                .iter()
                .filter(|cmd| cmd.starts_with(command))
                .map(|cmd| Completion::simple(cmd.to_string()))
                .collect()
        }
    }

    fn cmd_contain(&self, command: &str) -> bool {
        self.root.contains(&command) || self.rpc.contains(&command) || self.key.contains(&command) || self.abi.contains(&command) || self.sub_abi.contains(&command)
    }
}

struct CITACompletion;

impl<Term: Terminal> Completer<Term> for CITACompletion {
    fn complete(
        &self,
        _word: &str,
        prompter: &Prompter<Term>,
        _start: usize,
        _end: usize,
    ) -> Option<Vec<Completion>> {
        let line = prompter.buffer();

        let mut args = shell_words::split(line).unwrap();

        if args.is_empty() || (args.len() == 1 && args[0].len() < 3 && !COMPLETION.cmd_contain(&args[0])) {
            return Some(COMPLETION.root_filter(args.pop()));
        }

        match args[0].as_str() {
            "rpc" => {
                if args.len() == 1 {
                    Some(COMPLETION.rpc_filter(""))
                } else if args.len() == 2 && !COMPLETION.cmd_contain(&args[1]) {
                    Some(COMPLETION.rpc_filter(&args[1]))
                } else {
                    None
                }
            }
            "key" => {
                if args.len() == 1 {
                    Some(COMPLETION.key_filter(""))
                } else if args.len() == 2 && !COMPLETION.cmd_contain(&args[1]) {
                    Some(COMPLETION.key_filter(&args[1]))
                } else {
                    None
                }
            }
            "abi" => {
                if args.len() == 1 {
                    Some(COMPLETION.abi_filter(""))
                } else if args.len() == 2 && !COMPLETION.cmd_contain(&args[1]) {
                    Some(COMPLETION.abi_filter(&args[1]))
                } else {
                    None
                }
            }
            _ => None
        }
    }
}
