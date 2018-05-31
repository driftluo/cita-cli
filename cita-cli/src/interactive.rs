use std::env;
use std::io;
use std::iter;
use std::sync::Arc;

use ansi_term::Colour::{Red, Yellow};
use clap::{self, ArgMatches};
use linefeed::complete::{Completer, Completion};
use linefeed::terminal::Terminal;
use linefeed::{Interface, Prompter, ReadResult};
use shell_words;

use cli::{abi_processor, build_interactive, key_processor, rpc_processor};

/// Interactive command line
pub fn start(url: &str) -> io::Result<()> {
    let interface = Arc::new(Interface::new("cita-cli")?);
    let mut url = url.to_string();
    let mut color = true;
    #[cfg(feature = "blake2b_hash")]
    let mut blake2b = false;
    #[cfg(not(feature = "blake2b_hash"))]
    let blake2b = false;

    let mut history_file = env::home_dir().unwrap();
    history_file.push(".cita-cli.history");
    let history_file = history_file.to_str().unwrap();

    let mut parser = build_interactive();

    interface.set_completer(Arc::new(CitaCompleter::new(parser.clone())));
    interface.set_prompt(format!("{} ", Red.bold().paint(">")).as_str());

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

    print_env_variables(&url, blake2b, color);
    while let ReadResult::Input(line) = interface.read_line()? {
        let args = shell_words::split(line.as_str()).unwrap();

        if let Err(err) = match parser.get_matches_from_safe_borrow(args) {
            Ok(matches) => {
                match matches.subcommand() {
                    ("switch", Some(m)) => {
                        m.value_of("host").and_then(|host| {
                            url = host.to_string();
                            Some(())
                        });
                        if m.is_present("color") {
                            color = !color;
                        }

                        #[cfg(feature = "blake2b_hash")]
                        {
                            if m.is_present("algorithm") {
                                blake2b = !blake2b;
                            }
                        }
                        #[cfg(not(feature = "blake2b_hash"))]
                        {
                            if m.is_present("algorithm") {
                                println!("[{}]", Red.paint("The current version does not support the blake2b algorithm. \
                                                    Open 'blak2b' feature and recompile cita-cli, please."));
                            }
                        }
                        print_env_variables(&url, blake2b, color);
                        Ok(())
                    }
                    ("rpc", Some(m)) => rpc_processor(m, Some(url.as_str()), blake2b, color),
                    ("abi", Some(m)) => abi_processor(m),
                    ("key", Some(m)) => key_processor(m, blake2b),
                    ("info", _) => {
                        print_env_variables(&url, blake2b, color);
                        Ok(())
                    }
                    ("exit", _) => break,
                    _ => Ok(()),
                }
            }
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

fn get_complete_strings<'a, 'b, 'p>(
    app: &'p clap::App<'a, 'b>,
    filter: Vec<&String>,
) -> Vec<String> {
    let mut strings: Vec<String> = vec![];
    strings.extend(
        app.p
            .subcommands()
            .map(|app| app.p.meta.name.clone())
            .collect::<Vec<String>>(),
    );
    strings.extend(
        app.p
            .flags()
            .map(|a| {
                let mut strings = vec![];
                a.s.short.map(|s| strings.push(format!("-{}", s)));
                a.s.long.map(|s| strings.push(format!("--{}", s)));
                strings
            })
            .fold(vec![], |mut all, part| {
                all.extend(part);
                all
            }),
    );
    strings.extend(
        app.p
            .opts()
            .map(|a| {
                let mut strings = vec![];
                a.s.short.map(|s| strings.push(format!("-{}", s)));
                a.s.long.map(|s| strings.push(format!("--{}", s)));
                strings
            })
            .fold(vec![], |mut all, part| {
                all.extend(part);
                all
            }),
    );
    strings
        .into_iter()
        .filter(|s| !filter.contains(&s))
        .collect()
}

fn _get_command_chain(matches: &ArgMatches) -> Vec<String> {
    let mut matches = Some(matches);
    let mut names: Vec<String> = vec![];
    while let Some(m) = matches {
        matches = m.subcommand_name()
            .map(|name| {
                names.push(name.to_owned());
                m.subcommand_matches(name)
            })
            .unwrap_or(None);
    }
    names
}

struct CitaCompleter<'a, 'b>
where
    'a: 'b,
{
    clap_app: clap::App<'a, 'b>,
}

impl<'a, 'b> CitaCompleter<'a, 'b> {
    fn new(clap_app: clap::App<'a, 'b>) -> Self {
        CitaCompleter { clap_app }
    }

    fn find_subcommand<'s, 'p, Iter: iter::Iterator<Item = &'s str>>(
        app: &'p clap::App<'a, 'b>,
        mut prefix_names: iter::Peekable<Iter>,
    ) -> Option<&'p clap::App<'a, 'b>> {
        if let Some(name) = prefix_names.next() {
            for inner_app in &(app.p.subcommands) {
                if inner_app.p.meta.name == name {
                    if prefix_names.peek().is_none() {
                        return Some(inner_app);
                    }
                    return Self::find_subcommand(inner_app, prefix_names);
                }
            }
        }
        None
    }
}

unsafe impl<'a, 'b> ::std::marker::Sync for CitaCompleter<'a, 'b> {}
unsafe impl<'a, 'b> ::std::marker::Send for CitaCompleter<'a, 'b> {}

impl<'a, 'b, Term: Terminal> Completer<Term> for CitaCompleter<'a, 'b> {
    fn complete(
        &self,
        word: &str,
        prompter: &Prompter<Term>,
        start: usize,
        _end: usize,
    ) -> Option<Vec<Completion>> {
        let line = prompter.buffer();
        let mut args = shell_words::split(&line[..start]).unwrap();
        let root = args.clone();
        let filter = root.iter()
            .filter(|s| s.starts_with("-"))
            .collect::<Vec<&String>>();
        if let Some(cmd) = root.first() {
            match cmd.as_str() {
                "abi" => args.truncate(3),
                _ => args.truncate(2),
            }
        }
        let current_app = if args.is_empty() {
            Some(&self.clap_app)
        } else {
            Self::find_subcommand(&self.clap_app, args.iter().map(|s| s.as_str()).peekable())
        };
        if let Some(current_app) = current_app {
            let strings = get_complete_strings(current_app, filter);
            let mut target: Option<String> = None;
            if &strings
                .iter()
                .filter(|s| {
                    let matched = s.to_lowercase().contains(&word.to_lowercase());
                    if matched {
                        target = Some(s.to_string());
                    }
                    matched
                })
                .count() == &1
            {
                return Some(vec![Completion::simple(target.unwrap())]);
            }

            if !strings.is_empty() {
                return Some(
                    strings
                        .into_iter()
                        .filter(|s| {
                            if word.is_empty() {
                                true
                            } else {
                                s.starts_with(&word)
                            }
                        })
                        .map(|s| Completion::simple(s))
                        .collect::<Vec<Completion>>(),
                );
            }
        }
        None
    }
}

fn print_env_variables(url: &str, encryption: bool, color: bool) {
    println!(
        "[url: {}] [encryption: {}] [color: {}]",
        Yellow.paint(url),
        Yellow.paint(if encryption {
            "blake2b_hash"
        } else {
            "sha3_hash"
        }),
        Yellow.paint(color.to_string())
    );
}
