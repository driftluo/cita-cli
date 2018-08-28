use std::collections::{HashMap, HashSet};
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
use dirs;
use linefeed::complete::{Completer, Completion};
use linefeed::terminal::{DefaultTerminal, Terminal};
use linefeed::{Interface, Prompter, ReadResult};
use regex::{Captures, Regex};
use serde_json;
use shell_words;

use cita_tool::JsonRpcResponse;
use cli::{
    abi_processor, amend_processor, benchmark_processor, build_interactive, contract_processor,
    key_processor, parse_privkey, rpc_processor, search_processor, store_processor,
    transfer_processor, tx_processor,
};
use printer::Printer;

const ASCII_WORD: &str = r#"
   ._____. ._____.  _. ._   ._____. ._____.   ._.   ._____. ._____.
   | .___| |___. | | | | |  |___. | |_____|   |_|   |___. | |_____|
   | |     ._. | | | |_| |  ._. | |   ._.   ._____. ._. | | ._____.
   | |     | | |_| \_____/  | | |_/   | |   | ,_, | | | |_/ |_____|
   | |___. | | ._.   ._.    | |       | |   | | | | | |     ._____.
   |_____| |_| |_|   |_|    |_|       |_|   |_| |_| |_|     |_____|
"#;

const CMD_PATTERN: &str = r"\$\{\s*(?P<key>\S+)\s*\}";

/// Interactive command line
pub fn start(url: &str) -> io::Result<()> {
    let re = Regex::new(CMD_PATTERN).unwrap();
    let interface = Arc::new(Interface::new("cita-cli")?);
    let mut config = GlobalConfig::new(url.to_string());

    let mut cita_cli_dir = dirs::home_dir().unwrap();
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
            config.set_url(value.to_string());
        }
        config.set_debug(configs["debug"].as_bool().unwrap_or(false));
        config.set_color(configs["color"].as_bool().unwrap_or(true));
        config.set_blake2b(configs["blake2b"].as_bool().unwrap_or(false));
        config.set_json_format(configs["json_format"].as_bool().unwrap_or(true));
    }

    let mut parser = build_interactive();
    let complete = Arc::new(CitaCompleter::new(parser.clone()));

    interface.set_completer(complete.clone());
    let style = Red.bold();
    let text = "cita> ";

    interface.set_prompt(&format!(
        "\x01{prefix}\x02{text}\x01{suffix}\x02",
        prefix = style.prefix(),
        text = text,
        suffix = style.suffix()
    ))?;

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
    if !config.json_format() {
        printer.switch_format();
    }

    println!("{}", Red.bold().paint(ASCII_WORD));
    config.print();
    loop {
        match interface.read_line()? {
            ReadResult::Input(line) => {
                let args =
                    shell_words::split(replace_cmd(&re, line.as_str(), &config).as_str()).unwrap();

                if let Err(err) = match parser.get_matches_from_safe_borrow(args) {
                    Ok(matches) => match handle_commands(
                        &matches,
                        &mut config,
                        &mut printer,
                        (&config_file, history_file),
                        &interface,
                        &parser,
                    ) {
                        Ok(true) => {
                            break;
                        }
                        result => result,
                    },
                    Err(err) => Err(err.to_string()),
                } {
                    printer.eprintln(&err.to_string(), true);
                }

                interface.add_history_unique(remove_private(&line));
            }
            ReadResult::Eof => {
                if let Err(err) = interface.save_history(history_file) {
                    eprintln!("Save command history failed: {}", err);
                }
                break;
            }
            _ => {}
        }
    }
    Ok(())
}

fn handle_commands(
    matches: &clap::ArgMatches,
    config: &mut GlobalConfig,
    printer: &mut Printer,
    (config_file, history_file): (&PathBuf, &str),
    interface: &Arc<Interface<DefaultTerminal>>,
    parser: &clap::App<'static, 'static>,
) -> Result<bool, String> {
    let result = match matches.subcommand() {
        ("switch", Some(m)) => {
            m.value_of("host").and_then(|host| {
                config.set_url(host.to_string());
                Some(())
            });
            if m.is_present("color") {
                config.switch_color();
            }

            if m.is_present("json") {
                printer.switch_format();
                config.switch_format();
            }

            if m.is_present("debug") {
                config.switch_debug();
            }

            #[cfg(feature = "blake2b_hash")]
            {
                if m.is_present("algorithm") {
                    config.switch_encryption();
                }
            }
            #[cfg(not(feature = "blake2b_hash"))]
            {
                if m.is_present("algorithm") {
                    println!(
                        "[{}]",
                        Red.paint(
                            "The current version does not support the blake2b algorithm. \
                             Open 'blak2b' feature and recompile cita-cli, please."
                        )
                    );
                }
            }
            config.print();
            let mut file = fs::File::create(config_file.as_path())
                .map_err(|err| format!("open config error: {:?}", err))?;
            let content = serde_json::to_string_pretty(&json!({
                "url": config.get_url().clone(),
                "blake2b": config.blake2b(),
                "color": config.color(),
                "debug": config.debug(),
                "json_format": config.json_format(),
            })).unwrap();
            file.write_all(content.as_bytes())
                .map_err(|err| format!("save config error: {:?}", err))?;
            Ok(())
        }
        ("set", Some(m)) => {
            let key = m.value_of("key").unwrap().to_owned();
            let value = m.value_of("value").unwrap().to_owned();
            config.set(key, serde_json::Value::String(value));
            Ok(())
        }
        ("get", Some(m)) => {
            let key = m.value_of("key").unwrap();
            if let Some(value) = config.get(key) {
                printer.println(value, config.color());
            } else {
                println!("None");
            }
            Ok(())
        }
        ("rpc", Some(m)) => rpc_processor(m, &printer, config),
        ("ethabi", Some(m)) => abi_processor(m, &printer, &config),
        ("key", Some(m)) => key_processor(m, &printer, &config),
        ("scm", Some(m)) => contract_processor(m, &printer, config),
        ("transfer", Some(m)) => transfer_processor(m, &printer, config),
        ("store", Some(m)) => store_processor(m, &printer, config),
        ("amend", Some(m)) => amend_processor(m, &printer, config),
        ("info", _) => {
            config.print();
            Ok(())
        }
        ("search", Some(m)) => {
            search_processor(&parser, m);
            Ok(())
        }
        ("tx", Some(m)) => tx_processor(m, &printer, config),
        ("benchmark", Some(m)) => benchmark_processor(m, &printer, &config),
        ("exit", _) => {
            if let Err(err) = interface.save_history(history_file) {
                eprintln!("Save command history failed: {}", err);
            };
            return Ok(true);
        }
        _ => Ok(()),
    };
    result.map(|_| false)
}

struct CitaCompleter<'a, 'b>
where
    'a: 'b,
{
    clap_app: Arc<clap::App<'a, 'b>>,
}

impl<'a, 'b> CitaCompleter<'a, 'b> {
    fn new(clap_app: clap::App<'a, 'b>) -> Self {
        CitaCompleter {
            clap_app: Arc::new(clap_app),
        }
    }

    fn get_completions(app: &Arc<clap::App<'a, 'b>>, args: &[String]) -> Vec<Completion> {
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
                        .unwrap_or_else(|| vec![]),
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

    fn find_subcommand<'s, Iter: iter::Iterator<Item = &'s str>>(
        app: Arc<clap::App<'a, 'b>>,
        mut prefix_names: iter::Peekable<Iter>,
    ) -> Option<Arc<clap::App<'a, 'b>>> {
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
                        Some(Arc::new(inner_app.to_owned()))
                    } else {
                        Self::find_subcommand(Arc::new(inner_app.to_owned()), prefix_names)
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
        Self::find_subcommand(
            self.clap_app.clone(),
            args.iter().map(|s| s.as_str()).peekable(),
        ).map(|current_app| {
            let word_lower = word.to_lowercase();
            Self::get_completions(&current_app, &args)
                .into_iter()
                .filter(|s| word.is_empty() || s.completion.to_lowercase().contains(&word_lower))
                .collect::<Vec<_>>()
        })
    }
}

pub struct GlobalConfig {
    url: String,
    blake2b: bool,
    color: bool,
    debug: bool,
    json_format: bool,
    path: PathBuf,
    env_variable: HashMap<String, serde_json::Value>,
}

impl GlobalConfig {
    pub fn new(url: String) -> Self {
        GlobalConfig {
            url,
            blake2b: false,
            color: true,
            debug: false,
            json_format: true,
            path: env::current_dir().unwrap(),
            env_variable: HashMap::new(),
        }
    }

    pub fn set(&mut self, key: String, value: serde_json::Value) -> &mut Self {
        self.env_variable.insert(key, value);
        self
    }

    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        let mut parts_iter = key.split('.');
        if let Some(name) = parts_iter.next() {
            parts_iter
                .try_fold(
                    self.env_variable.get(name),
                    |value_opt: Option<&serde_json::Value>, part| match value_opt {
                        Some(value) => match part.parse::<usize>() {
                            Ok(index) => match value.get(index) {
                                None => Ok(value.get(part)),
                                result => Ok(result),
                            },
                            _ => Ok(value.get(part)),
                        },
                        None => Err(()),
                    },
                )
                .unwrap_or_default()
        } else {
            None
        }
    }

    pub fn set_url(&mut self, value: String) {
        self.url = value;
    }

    pub fn get_url(&self) -> &String {
        &self.url
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

    fn print(&self) {
        let path = self.path.to_string_lossy();
        let encryption = if self.blake2b { "ed25519" } else { "secp256k1" };
        let color = self.color.to_string();
        let debug = self.debug.to_string();
        let json = self.json_format.to_string();
        let values = [
            ("url", self.url.as_str()),
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

fn remove_private(line: &str) -> String {
    if line.contains("private") || line.contains("privkey") {
        shell_words::join(
            shell_words::split(line)
                .unwrap()
                .into_iter()
                .filter(|key| parse_privkey(key).is_err())
                .collect::<Vec<String>>(),
        )
    } else {
        line.to_string()
    }
}

fn replace_cmd(regex: &Regex, line: &str, config: &GlobalConfig) -> String {
    regex
        .replace_all(line, |caps: &Captures| match caps.name("key") {
            Some(key) => config
                .get(key.as_str())
                .map(|value| match value {
                    serde_json::Value::String(s) => s.to_owned(),
                    serde_json::Value::Number(n) => n.to_string(),
                    _ => String::new(),
                })
                .unwrap_or_else(String::new),
            None => String::new(),
        })
        .into_owned()
}

pub fn set_output(response: &JsonRpcResponse, config: &mut GlobalConfig) {
    if let Some(result) = response.result() {
        config.set(
            "result".to_string(),
            serde_json::from_str(serde_json::to_string(&result).unwrap().as_str()).unwrap(),
        );
    }
}

#[cfg(test)]
mod test {
    use super::CMD_PATTERN;
    use regex::{Captures, Regex};

    #[test]
    fn test_re() {
        fn capture(regex: &Regex, line: &str) -> String {
            let replaced = regex.replace_all(line, |caps: &Captures| {
                format!("{}", caps.name("key").unwrap().as_str())
            });
            replaced.into_owned()
        }

        let re = Regex::new(CMD_PATTERN).unwrap();
        let texts = [
            "${name1}",
            "${ name2 }",
            "${ name3}",
            "${name4 }",
            "${    name5 }",
            "${    name6}",
            "${ name7rd }",
            // Wrong case
            "${ name7 rd }",
            "abc${name8}def",
            "${name9a} ${name9b}",
            "abc${name10a} def ${name10b} xyz",
            "abc${name11a}jobs def clear${name11b}xyz",
        ];
        let replaced = [
            "name1",
            "name2",
            "name3",
            "name4",
            "name5",
            "name6",
            "name7rd",
            "${ name7 rd }",
            "abcname8def",
            "name9a name9b",
            "abcname10a def name10b xyz",
            "abcname11ajobs def clearname11bxyz",
        ];

        for (index, line) in texts.iter().enumerate() {
            assert_eq!(replaced[index], &capture(&re, line));
        }
    }
}
