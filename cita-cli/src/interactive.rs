use std::collections::HashSet;
use std::env;
use std::fs;
use std::io;
use std::io::{Read, Write};
use std::iter;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::Arc;

use ansi_term::Colour::{Red, Yellow};
use clap;
use linefeed::complete::{Completer, Completion};
use linefeed::terminal::Terminal;
use linefeed::{Interface, Prompter, ReadResult};
use serde_json;
use shell_words;

use cli::{abi_processor, amend_processor, build_interactive, contract_processor, key_processor,
          rpc_processor, store_processor, transfer_processor};
use printer::Printer;

const ASCII_WORD: &'static str = r#"
   ._____. ._____.  _. ._   ._____. ._____.   ._.   ._____. ._____.
   | .___| |___. | | | | |  |___. | |_____|   |_|   |___. | |_____|
   | |     ._. | | | |_| |  ._. | |   ._.   ._____. ._. | | ._____.
   | |     | | |_| \_____/  | | |_/   | |   | ,_, | | | |_/ |_____|
   | |___. | | ._.   ._.    | |       | |   | | | | | |     ._____.
   |_____| |_| |_|   |_|    |_|       |_|   |_| |_| |_|     |_____|
"#;

/// Interactive command line
pub fn start(url: &str) -> io::Result<()> {
    let interface = Arc::new(Interface::new("cita-cli")?);
    let mut url = url.to_string();
    let mut env_variable = GlobalConfig::new();

    let mut cita_cli_dir = env::home_dir().unwrap();
    cita_cli_dir.push(".cita-cli");
    if !cita_cli_dir.as_path().exists() {
        fs::create_dir(&cita_cli_dir)?;
    }
    let mut history_file = cita_cli_dir.clone();
    history_file.push("history");
    let history_file = history_file.to_str().unwrap();
    let mut config_file = cita_cli_dir.clone();
    config_file.push("config");
    if config_file.as_path().exists() {
        let mut file = fs::File::open(&config_file)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        let configs: serde_json::Value = serde_json::from_str(content.as_str()).unwrap();
        if let Some(value) = configs["url"].as_str() {
            url = value.to_string();
        }
        env_variable.set_debug(configs["debug"].as_bool().unwrap_or(false));
        env_variable.set_color(configs["color"].as_bool().unwrap_or(true));
        env_variable.set_blake2b(configs["blake2b"].as_bool().unwrap_or(false));
        env_variable.set_json_format(configs["json_format"].as_bool().unwrap_or(true));
    }

    let mut parser = build_interactive();

    interface.set_completer(Arc::new(CitaCompleter::new(parser.clone())));
    let style = Red.bold();
    let text = "cita> ";

    interface.set_prompt(&format!(
        "\x01{prefix}\x02{text}\x01{suffix}\x02",
        prefix = style.prefix(),
        text = text,
        suffix = style.suffix()
    ));

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

    let mut printer = Printer::default();
    if !env_variable.json_format() {
        printer.switch_format();
    }

    println!("{}", Red.bold().paint(ASCII_WORD));
    env_variable.print(&url);
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
                            env_variable.switch_color();
                        }

                        if m.is_present("json") {
                            printer.switch_format();
                            env_variable.switch_format();
                        }

                        if m.is_present("debug") {
                            env_variable.switch_debug();
                        }

                        #[cfg(feature = "blake2b_hash")]
                        {
                            if m.is_present("algorithm") {
                                env_variable.switch_encryption();
                            }
                        }
                        #[cfg(not(feature = "blake2b_hash"))]
                        {
                            if m.is_present("algorithm") {
                                println!("[{}]", Red.paint("The current version does not support the blake2b algorithm. \
                                                    Open 'blak2b' feature and recompile cita-cli, please."));
                            }
                        }
                        env_variable.print(&url);
                        let mut file = fs::File::create(config_file.as_path())?;
                        let content = serde_json::to_string_pretty(&json!({
                            "url": url,
                            "blake2b": env_variable.blake2b(),
                            "color": env_variable.color(),
                            "debug": env_variable.debug(),
                            "json_format": env_variable.json_format(),
                        })).unwrap();
                        file.write_all(content.as_bytes())?;
                        Ok(())
                    }
                    ("rpc", Some(m)) => {
                        rpc_processor(m, &printer, Some(url.as_str()), &env_variable)
                    }
                    ("ethabi", Some(m)) => abi_processor(m, &printer),
                    ("key", Some(m)) => key_processor(m, &printer, &env_variable),
                    ("scm", Some(m)) => {
                        contract_processor(m, &printer, Some(url.as_str()), &env_variable)
                    }
                    ("transfer", Some(m)) => {
                        transfer_processor(m, &printer, Some(url.as_str()), &env_variable)
                    }
                    ("store", Some(m)) => {
                        store_processor(m, &printer, Some(url.as_str()), &env_variable)
                    }
                    ("amend", Some(m)) => {
                        amend_processor(m, &printer, Some(url.as_str()), &env_variable)
                    }
                    ("info", _) => {
                        env_variable.print(&url);
                        Ok(())
                    }
                    ("exit", _) => break,
                    _ => Ok(()),
                }
            }
            Err(err) => Err(format!("{}", err)),
        } {
            printer.eprintln(&format!("{}", err), true);
        }

        interface.add_history_unique(line.clone());
        if let Err(err) = interface.save_history(history_file) {
            eprintln!("Save command history failed: {}", err);
        };
    }

    Ok(())
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

    fn get_completions<'p>(app: &'p clap::App<'a, 'b>, args: &[String]) -> Vec<Completion> {
        let args_set = args.iter().collect::<HashSet<&String>>();
        let switched_completions =
            |short: Option<char>, long: Option<&str>, multiple: bool, required: bool| {
                let names = vec![
                    short.map(|s| format!("-{}", s)),
                    long.map(|s| format!("--{}", s)),
                ].into_iter()
                    .filter_map(|s| s)
                    .map(|s| {
                        let display = if required {
                            Some(format!("{}(*)", s))
                        } else {
                            None
                        };
                        let mut completion = Completion::simple(s);
                        completion.display = display;
                        completion
                    })
                    .collect::<Vec<Completion>>();

                if !multiple && names.iter().any(|c| args_set.contains(&c.completion)) {
                    vec![]
                } else {
                    names
                }
            };
        app.p
            .subcommands()
            .map(|app| {
                [
                    vec![Completion::simple(app.p.meta.name.clone())],
                    app.p
                        .meta
                        .aliases
                        .as_ref()
                        .map(|aliases| {
                            aliases
                                .iter()
                                .map(|(alias, _)| Completion::simple(alias.to_string()))
                                .collect::<Vec<Completion>>()
                        })
                        .unwrap_or(vec![]),
                ].concat()
            })
            .chain(app.p.flags().map(|a| {
                switched_completions(
                    a.s.short,
                    a.s.long,
                    a.b.is_set(clap::ArgSettings::Multiple),
                    a.b.is_set(clap::ArgSettings::Required),
                )
            }))
            .chain(app.p.opts().map(|a| {
                switched_completions(
                    a.s.short,
                    a.s.long,
                    a.b.is_set(clap::ArgSettings::Multiple),
                    a.b.is_set(clap::ArgSettings::Required),
                )
            }))
            .collect::<Vec<Vec<Completion>>>()
            .concat()
    }

    fn find_subcommand<'s, 'p, Iter: iter::Iterator<Item = &'s str>>(
        app: &'p clap::App<'a, 'b>,
        mut prefix_names: iter::Peekable<Iter>,
    ) -> Option<&'p clap::App<'a, 'b>> {
        if let Some(name) = prefix_names.next() {
            for inner_app in &(app.p.subcommands) {
                if inner_app.p.meta.name == name
                    || inner_app
                        .p
                        .meta
                        .aliases
                        .as_ref()
                        .map(|aliases| aliases.iter().any(|&(alias, _)| alias == name))
                        .unwrap_or(false)
                {
                    return if prefix_names.peek().is_none() {
                        Some(inner_app)
                    } else {
                        Self::find_subcommand(inner_app, prefix_names)
                    };
                }
            }
        }
        if prefix_names.peek().is_none() || app.p.subcommands.is_empty() {
            Some(app)
        } else {
            None
        }
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
        let args = shell_words::split(&line[..start]).unwrap();
        Self::find_subcommand(&self.clap_app, args.iter().map(|s| s.as_str()).peekable()).map(
            |current_app| {
                let word_lower = word.to_lowercase();
                Self::get_completions(current_app, &args)
                    .into_iter()
                    .filter(|s| {
                        word.is_empty() || s.completion.to_lowercase().contains(&word_lower)
                    })
                    .collect::<Vec<_>>()
            },
        )
    }
}

pub struct GlobalConfig {
    blake2b: bool,
    color: bool,
    debug: bool,
    json_format: bool,
    path: PathBuf,
}

impl GlobalConfig {
    pub fn new() -> Self {
        GlobalConfig {
            blake2b: false,
            color: true,
            debug: false,
            json_format: true,
            path: env::current_dir().unwrap(),
        }
    }

    #[cfg(feature = "blake2b_hash")]
    fn switch_encryption(&mut self) {
        self.blake2b = !self.blake2b;
    }

    fn switch_color(&mut self) {
        self.color = !self.color;
    }

    fn switch_debug(&mut self) {
        self.debug = !self.debug;
    }

    fn switch_format(&mut self) {
        self.json_format = !self.json_format;
    }

    pub fn set_blake2b(&mut self, value: bool) {
        self.blake2b = value;
    }

    pub fn set_color(&mut self, value: bool) {
        self.color = value;
    }

    pub fn set_debug(&mut self, value: bool) {
        self.debug = value;
    }

    fn set_json_format(&mut self, value: bool) {
        self.json_format = value;
    }

    pub fn blake2b(&self) -> bool {
        self.blake2b
    }

    pub fn color(&self) -> bool {
        self.color
    }

    pub fn debug(&self) -> bool {
        self.debug
    }

    fn json_format(&self) -> bool {
        self.json_format
    }

    fn print(&self, url: &str) {
        let path = self.path.to_string_lossy();
        let encryption = if self.blake2b {
            "blake2b_hash"
        } else {
            "sha3_hash"
        };
        let color = self.color.to_string();
        let debug = self.debug.to_string();
        let json = self.json_format.to_string();
        let values = [
            ("url", url),
            ("pwd", path.deref()),
            ("color", color.as_str()),
            ("debug", debug.as_str()),
            ("json", json.as_str()),
            ("encryption", encryption),
        ];

        let max_width = values
            .iter()
            .map(|(name, _)| name.len())
            .max()
            .unwrap_or(20) + 2;
        let output = values
            .iter()
            .map(|(name, value)| {
                format!(
                    "[{:^width$}]: {}",
                    name,
                    Yellow.paint(*value),
                    width = max_width
                )
            })
            .collect::<Vec<String>>()
            .join("\n");
        println!("{}", output);
    }
}
