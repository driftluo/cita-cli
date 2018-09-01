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
use linefeed::complete::{Completer as LinefeedCompleter, Completion};
use linefeed::terminal::Terminal;
use linefeed::{Interface, Prompter, ReadResult};

use rustyline::completion::{extract_word, Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::{Cmd, CompletionType, Config, EditMode, Editor, Helper, KeyPress};

use regex::{Captures, Regex};
use serde_json;
use shell_words;

use cita_tool::JsonRpcResponse;
use cli::{
    abi_processor, amend_processor, benchmark_processor, build_interactive, contract_processor,
    key_processor, parse_privkey, rpc_processor, search_processor, store_processor,
    transfer_processor, tx_processor,
};
use printer::{OutputFormat, Printable, Printer};

const ASCII_WORD: &str = r#"
   ._____. ._____.  _. ._   ._____. ._____.   ._.   ._____. ._____.
   | .___| |___. | | | | |  |___. | |_____|   |_|   |___. | |_____|
   | |     ._. | | | |_| |  ._. | |   ._.   ._____. ._. | | ._____.
   | |     | | |_| \_____/  | | |_/   | |   | ,_, | | | |_/ |_____|
   | |___. | | ._.   ._.    | |       | |   | | | | | |     ._____.
   |_____| |_| |_|   |_|    |_|       |_|   |_| |_| |_|     |_____|
"#;

const ENV_PATTERN: &str = r"\$\{\s*(?P<key>\S+)\s*\}";
#[cfg(unix)]
static DEFAULT_BREAK_CHARS: [u8; 18] = [
    b' ', b'\t', b'\n', b'"', b'\\', b'\'', b'`', b'@', b'$', b'>', b'<', b'=', b';', b'|', b'&',
    b'{', b'(', b'\0',
];
#[cfg(unix)]
static ESCAPE_CHAR: Option<char> = Some('\\');
// Remove \ to make file completion works on windows
#[cfg(windows)]
static DEFAULT_BREAK_CHARS: [u8; 17] = [
    b' ', b'\t', b'\n', b'"', b'\'', b'`', b'@', b'$', b'>', b'<', b'=', b';', b'|', b'&', b'{',
    b'(', b'\0',
];
#[cfg(windows)]
static ESCAPE_CHAR: Option<char> = None;

/// Interactive command line
pub fn start(url: &str, use_rustyline: bool) -> io::Result<()> {
    let env_regex = Regex::new(ENV_PATTERN).unwrap();
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
    let style = Red.bold();
    let text = "cita> ";
    let colored_prompt = format!(
        "\x01{prefix}\x02{text}\x01{suffix}\x02",
        prefix = style.prefix(),
        text = text,
        suffix = style.suffix()
    );

    let mut printer = Printer::default();
    if !config.json_format() {
        printer.switch_format();
    }
    println!("{}", Red.bold().paint(ASCII_WORD));
    config.print();

    if use_rustyline {
        start_rustyline(
            &mut parser,
            &mut config,
            &mut printer,
            &env_regex,
            colored_prompt.as_str(),
            &config_file,
            history_file,
        )
    } else {
        start_linefeed(
            &mut parser,
            &mut config,
            &mut printer,
            &env_regex,
            colored_prompt.as_str(),
            &config_file,
            history_file,
        )
    }
}

fn start_rustyline(
    parser: &mut clap::App<'static, 'static>,
    config: &mut GlobalConfig,
    printer: &mut Printer,
    env_regex: &Regex,
    colored_prompt: &str,
    config_file: &PathBuf,
    history_file: &str,
) -> io::Result<()> {
    let rl_config = Config::builder()
        .history_ignore_space(true)
        .completion_type(CompletionType::List)
        .edit_mode(EditMode::Emacs)
        .build();
    let helper = CitaCompleter::new(parser.clone());
    let mut rl = Editor::with_config(rl_config);
    rl.set_helper(Some(helper));
    rl.bind_sequence(KeyPress::Meta('N'), Cmd::HistorySearchForward);
    rl.bind_sequence(KeyPress::Meta('P'), Cmd::HistorySearchBackward);
    if rl.load_history(history_file).is_err() {
        eprintln!("No previous history.");
    }
    loop {
        match rl.readline(colored_prompt) {
            Ok(line) => {
                match handle_commands(
                    line.as_str(),
                    config,
                    printer,
                    parser,
                    env_regex,
                    config_file,
                ) {
                    Ok(true) => {
                        if let Err(err) = rl.save_history(history_file) {
                            eprintln!("Save command history failed: {}", err);
                        }
                        break;
                    }
                    Ok(false) => {}
                    Err(err) => {
                        printer.eprintln(&err.to_string(), true);
                    }
                }
                rl.add_history_entry(line.as_ref());
            }
            Err(ReadlineError::Interrupted) => {
                println!("CTRL-C");
            }
            Err(ReadlineError::Eof) => {
                println!("CTRL-D");
                break;
            }
            Err(err) => {
                eprintln!("Error: {:?}", err);
                break;
            }
        }
    }
    if let Err(err) = rl.save_history(history_file) {
        eprintln!("Save command history failed: {}", err);
    }
    Ok(())
}

fn start_linefeed(
    parser: &mut clap::App<'static, 'static>,
    config: &mut GlobalConfig,
    printer: &mut Printer,
    env_regex: &Regex,
    colored_prompt: &str,
    config_file: &PathBuf,
    history_file: &str,
) -> io::Result<()> {
    let complete = Arc::new(CitaCompleter::new(parser.clone()));
    let interface = Arc::new(Interface::new("cita-cli")?);
    interface.set_completer(complete.clone());
    interface.set_prompt(&colored_prompt)?;

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
    loop {
        match interface.read_line()? {
            ReadResult::Input(line) => {
                match handle_commands(&line, config, printer, parser, env_regex, config_file) {
                    Ok(true) => {
                        if let Err(err) = interface.save_history(history_file) {
                            eprintln!("Save command history failed: {}", err);
                        }
                        break;
                    }
                    Ok(false) => {}
                    Err(err) => {
                        printer.eprintln(&err.to_string(), true);
                    }
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
    line: &str,
    config: &mut GlobalConfig,
    printer: &mut Printer,
    parser: &mut clap::App<'static, 'static>,
    env_regex: &Regex,
    config_file: &PathBuf,
) -> Result<bool, String> {
    let args = shell_words::split(replace_cmd(&env_regex, line, &config).as_str()).unwrap();

    match parser.get_matches_from_safe_borrow(args) {
        Ok(matches) => match matches.subcommand() {
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
                let key = m.value_of("key");
                printer.println(&config.get(key).clone(), config.color());
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
                return Ok(true);
            }
            _ => Ok(()),
        },
        Err(err) => Err(err.to_string()),
    }.map(|_| false)
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

    fn get_completions(app: &Arc<clap::App<'a, 'b>>, args: &[String]) -> Vec<(String, String)> {
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
                            format!("{}(*)", s)
                        } else {
                            s.clone()
                        };
                        (display, s)
                    })
                    .collect::<Vec<(String, String)>>();

                if !multiple && names.iter().any(|(_, s)| args_set.contains(&s)) {
                    vec![]
                } else {
                    names
                }
            };
        app.p
            .subcommands()
            .map(|app| {
                [
                    vec![(app.p.meta.name.clone(), app.p.meta.name.clone())],
                    app.p
                        .meta
                        .aliases
                        .as_ref()
                        .map(|aliases| {
                            aliases
                                .iter()
                                .map(|(alias, _)| (alias.to_string(), alias.to_string()))
                                .collect::<Vec<(String, String)>>()
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
            .collect::<Vec<Vec<(String, String)>>>()
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

impl<'a, 'b, Term: Terminal> LinefeedCompleter<Term> for CitaCompleter<'a, 'b> {
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
                .filter(|(_, replacement)| {
                    word.is_empty() || replacement.to_lowercase().contains(&word_lower)
                })
                .map(|(display, replacement)| {
                    let mut completion = Completion::simple(replacement);
                    completion.display = Some(display);
                    completion
                })
                .collect::<Vec<_>>()
        })
    }
}

impl<'a, 'b> Completer for CitaCompleter<'a, 'b> {
    type Candidate = Pair;

    fn complete(&self, line: &str, pos: usize) -> Result<(usize, Vec<Pair>), ReadlineError> {
        let (start, word) = extract_word(line, pos, ESCAPE_CHAR, &DEFAULT_BREAK_CHARS);
        let args = shell_words::split(&line[..pos]).unwrap();
        let pairs = Self::find_subcommand(
            self.clap_app.clone(),
            args.iter().map(|s| s.as_str()).peekable(),
        ).map(|current_app| {
            let word_lower = word.to_lowercase();
            Self::get_completions(&current_app, &args)
                .into_iter()
                .filter(|(_, replacement)| {
                    word.is_empty() || replacement.to_lowercase().contains(&word_lower)
                })
                .map(|(display, replacement)| Pair {
                    display,
                    replacement,
                })
                .collect::<Vec<_>>()
        });
        Ok((start, pairs.unwrap_or_else(Vec::new)))
    }
}

impl<'a, 'b> Highlighter for CitaCompleter<'a, 'b> {}

impl<'a, 'b> Hinter for CitaCompleter<'a, 'b> {
    fn hint(&self, line: &str, _pos: usize) -> Option<String> {
        if line == "hello" {
            Some(" World".to_owned())
        } else {
            None
        }
    }
}

impl<'a, 'b> Helper for CitaCompleter<'a, 'b> {}

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

    fn set(&mut self, key: String, value: serde_json::Value) -> &mut Self {
        self.env_variable.insert(key, value);
        self
    }

    fn get(&self, key: Option<&str>) -> KV {
        match key {
            Some(key) => {
                let mut parts_iter = key.split('.');
                let value = match parts_iter.next() {
                    Some(name) => parts_iter
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
                        .unwrap_or_default(),
                    None => None,
                };
                KV::Value(value)
            }
            None => KV::Keys(
                self.env_variable
                    .keys()
                    .map(|key| key.as_str())
                    .collect::<Vec<&str>>(),
            ),
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
                .get(Some(key.as_str()))
                .map(|value| match value {
                    serde_json::Value::String(s) => s.to_owned(),
                    serde_json::Value::Number(n) => n.to_string(),
                    _ => String::new(),
                })
                .next()
                .unwrap_or_default(),
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

#[derive(Clone)]
enum KV<'a> {
    Value(Option<&'a serde_json::Value>),
    Keys(Vec<&'a str>),
}

impl<'a> Printable for KV<'a> {
    fn rc_string(&self, format: OutputFormat, color: bool) -> ::std::rc::Rc<String> {
        match self {
            KV::Value(Some(value)) => value.rc_string(format, color),
            KV::Keys(value) => ::std::rc::Rc::new(
                value
                    .iter()
                    .enumerate()
                    .map(|(index, key)| format!("{}) {}", index, key))
                    .collect::<Vec<String>>()
                    .join("\n"),
            ),
            KV::Value(None) => ::std::rc::Rc::new("None".to_string()),
        }
    }
}

impl<'a> ::std::iter::Iterator for KV<'a> {
    type Item = &'a serde_json::Value;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            KV::Value(value) => *value.deref(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod test {
    use super::ENV_PATTERN;
    use regex::{Captures, Regex};

    #[test]
    fn test_re() {
        fn capture(regex: &Regex, line: &str) -> String {
            let replaced = regex.replace_all(line, |caps: &Captures| {
                format!("{}", caps.name("key").unwrap().as_str())
            });
            replaced.into_owned()
        }

        let re = Regex::new(ENV_PATTERN).unwrap();
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
