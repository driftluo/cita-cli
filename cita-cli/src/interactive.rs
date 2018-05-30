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

    let mut history_file = env::home_dir().unwrap();
    history_file.push(".cita-cli.history");
    let history_file = history_file.to_str().unwrap();

    let mut parser = build_interactive();

    interface.set_completer(Arc::new(CitaCompleter::new(parser.clone())));
    interface.set_prompt(format!(
        "[{}]\n{} ",
        Yellow.paint(url.to_owned()),
        Red.bold().paint(">")
    ).as_str());

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

    while let ReadResult::Input(line) = interface.read_line()? {
        let args = shell_words::split(line.as_str()).unwrap();

        if let Err(err) = match parser.get_matches_from_safe_borrow(args) {
            Ok(matches) => match matches.subcommand() {
                ("switch", Some(m)) => {
                    let host = m.value_of("host").unwrap();
                    url = host.to_string();
                    interface.set_prompt(format!(
                        "[{}]\n{} ",
                        Yellow.paint(host.clone()),
                        Red.bold().paint(">")
                    ).as_str());
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

fn get_complete_strings<'a, 'b, 'p>(app: &'p clap::App<'a, 'b>) -> Vec<String> {
    let mut strings: Vec<String> = vec![];
    strings.extend(
        app.p.subcommands()
            .map(|app| app.p.meta.name.clone())
            .collect::<Vec<String>>()
    );
    strings.extend(
        app.p.flags()
            .map(|a| {
                let mut strings = vec![];
                a.s.short.map(|s| strings.push(format!("-{}", s)));
                a.s.long.map(|s| strings.push(format!("--{}", s)));
                strings
            })
            .fold(vec![], |mut all, part| {
                all.extend(part);
                all
            })
    );
    strings.extend(
        app.p.opts()
            .map(|a| {
                let mut strings = vec![];
                a.s.short.map(|s| strings.push(format!("-{}", s)));
                a.s.long.map(|s| strings.push(format!("--{}", s)));
                strings
            })
            .fold(vec![], |mut all, part| {
                all.extend(part);
                all
            })
    );
    strings
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
where 'a: 'b
{
    clap_app: clap::App<'a, 'b>
}

impl<'a, 'b> CitaCompleter<'a, 'b> {
    fn new(clap_app: clap::App<'a, 'b>) -> Self {
        CitaCompleter{ clap_app }
    }

    fn find_subcommand<'s, 'p, Iter: iter::Iterator<Item=&'s str>>(
        app: &'p clap::App<'a, 'b>,
        mut prefix_names: iter::Peekable<Iter>
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
        _end: usize
    ) -> Option<Vec<Completion>>
    {
        let line = prompter.buffer();
        let args = shell_words::split(&line[..start]).unwrap();
        let current_app = if args.is_empty() {
            Some(&self.clap_app)
        } else {
            Self::find_subcommand(
                &self.clap_app,
                args.iter().map(|s| s.as_str()).peekable()
            )
        };
        if let Some(current_app) = current_app {
            let strings = get_complete_strings(current_app);
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
                        .collect::<Vec<Completion>>()
                )
            }
        }
        None
    }
}
