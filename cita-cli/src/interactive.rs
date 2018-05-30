use std::collections::BTreeMap;
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
    command: BTreeMap<&'a str, BTreeMap<&'a str, BTreeMap<&'a str, Vec<&'a str>>>>,
}

impl<'a> CITACompleter<'a> {
    fn new() -> Self {
        //        let sub_command = BTreeMap::new();
        //        let sub_sub_command = BTreeMap::new();
        let mut command = BTreeMap::new();
        let global_params = vec!["--blake2b", "--no-color"];
        command.insert("rpc", BTreeMap::new());
        command.insert("key", BTreeMap::new());
        command.insert("abi", BTreeMap::new());
        command.insert("switch", BTreeMap::new());
        command.insert("exit", BTreeMap::new());
        CITACompleter { command: command }
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

        let args = shell_words::split(line).unwrap();

        if args.len() == 0 {
            let key: Vec<Completion> = COMPLETION
                .command
                .keys()
                .map(|key| Completion::simple(key.to_string()))
                .collect();
            Some(key)
        } else {
            None
        }
    }
}
