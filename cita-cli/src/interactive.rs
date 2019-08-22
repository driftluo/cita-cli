use std::borrow::Cow::{self, Owned};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io;
use std::io::{Read, Write};
use std::iter;
use std::ops::Deref;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use ansi_term::Colour::{Green, Red, Yellow, RGB};
use clap;
use dirs;

use rustyline::completion::{extract_word, Completer, Pair};
use rustyline::config::Configurer;
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::{Cmd, CompletionType, Config, Context, EditMode, Editor, Helper, KeyPress};

use regex::{Captures, Regex};
use serde_json::{self, json};
use shell_words;

use crate::cli::{
    abi_processor, amend_processor, benchmark_processor, build_interactive, contract_processor,
    encryption, key_processor, key_validator, rpc_processor, search_processor, store_processor,
    string_include, transfer_processor, tx_processor,
};
use crate::printer::{OutputFormat, Printable, Printer};
use cita_tool::client::basic::Client;
use cita_tool::{Encryption, JsonRpcResponse};

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
pub fn start(url: &str, client: &Client) -> io::Result<()> {
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
        if let Some(value) = configs["encryption"].as_str() {
            let encryption = Encryption::from_str(value).unwrap_or(Encryption::Secp256k1);
            config.set_encryption(encryption)
        }

        config.set_debug(configs["debug"].as_bool().unwrap_or(false));
        config.set_color(configs["color"].as_bool().unwrap_or(true));
        config.set_json_format(configs["json_format"].as_bool().unwrap_or(true));
        config.set_completion_style(configs["completion_style"].as_bool().unwrap_or(true));
        config.set_edit_style(configs["edit_style"].as_bool().unwrap_or(true));
        config.set_save_private(configs["save_private"].as_bool().unwrap_or(false));
    }

    let mut env_file = cita_cli_dir.clone();
    env_file.push("env_vars");
    if env_file.as_path().exists() {
        let file = fs::File::open(&env_file)?;
        let env_vars_json = serde_json::from_reader(file).unwrap_or(json!(null));
        match env_vars_json {
            serde_json::Value::Object(env_vars) => config.env_variable.extend(env_vars),
            _ => eprintln!("Parse environment variable file failed."),
        }
    }

    let mut printer = Printer::default();
    if !config.json_format() {
        printer.switch_format();
    }
    println!("{}", Red.bold().paint(ASCII_WORD));
    config.print();

    start_rustyline(
        &mut config,
        &mut printer,
        &config_file,
        history_file,
        &client,
    )
}

fn start_rustyline(
    config: &mut GlobalConfig,
    printer: &mut Printer,
    config_file: &PathBuf,
    history_file: &str,
    client: &Client,
) -> io::Result<()> {
    let env_regex = Regex::new(ENV_PATTERN).unwrap();
    let parser = build_interactive();
    let colored_prompt = Red.bold().paint("cita> ").to_string();

    let rl_mode = |rl: &mut Editor<CitaCompleter>, config: &GlobalConfig| {
        if config.completion_style() {
            rl.set_completion_type(CompletionType::List)
        } else {
            rl.set_completion_type(CompletionType::Circular)
        }

        if config.edit_style() {
            rl.set_edit_mode(EditMode::Emacs)
        } else {
            rl.set_edit_mode(EditMode::Vi)
        }
    };

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
        rl_mode(&mut rl, &config);
        match rl.readline(&colored_prompt) {
            Ok(line) => {
                match handle_commands(
                    line.as_str(),
                    config,
                    printer,
                    &parser,
                    &env_regex,
                    config_file,
                    &client,
                ) {
                    Ok(true) => {
                        break;
                    }
                    Ok(false) => {}
                    Err(err) => {
                        printer.eprintln(&err.to_string(), true);
                    }
                }
                if config.save_private() {
                    rl.add_history_entry(&line);
                } else {
                    rl.add_history_entry(remove_private(line.as_ref()));
                }
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

fn handle_commands(
    line: &str,
    config: &mut GlobalConfig,
    printer: &mut Printer,
    parser: &clap::App<'static, 'static>,
    env_regex: &Regex,
    config_file: &PathBuf,
    client: &Client,
) -> Result<bool, String> {
    let args = match shell_words::split(replace_cmd(&env_regex, line, &config).as_str()) {
        Ok(args) => args,
        Err(e) => return Err(e.to_string()),
    };

    match parser.clone().get_matches_from_safe(args) {
        Ok(matches) => match matches.subcommand() {
            ("switch", Some(m)) => {
                m.value_of("url").and_then(|url| {
                    config.set_url(url.to_string());
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

                if m.is_present("edit_style") {
                    config.switch_edit_style();
                }

                if m.is_present("completion_style") {
                    config.switch_completion_style();
                }

                if m.is_present("save_private") {
                    config.switch_save_private();
                }

                let encryption = encryption(m, &config);
                config.set_encryption(encryption);

                config.print();
                let mut file = fs::File::create(config_file.as_path())
                    .map_err(|err| format!("open config error: {:?}", err))?;
                let content = serde_json::to_string_pretty(&json!({
                    "url": config.get_url().clone(),
                    "encryption": config.encryption().to_string(),
                    "color": config.color(),
                    "debug": config.debug(),
                    "json_format": config.json_format(),
                    "completion_style": config.completion_style(),
                    "edit_style": config.edit_style(),
                    "save_private": config.save_private(),
                }))
                .unwrap();
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
            ("rpc", Some(m)) => rpc_processor(m, &printer, config, client.clone()),
            ("ethabi", Some(m)) => abi_processor(m, &printer, &config),
            ("key", Some(m)) => key_processor(m, &printer, &config),
            ("scm", Some(m)) => contract_processor(m, &printer, config, client.clone()),
            ("transfer", Some(m)) => transfer_processor(m, &printer, config, client.clone()),
            ("store", Some(m)) => store_processor(m, &printer, config, client.clone()),
            ("amend", Some(m)) => amend_processor(m, &printer, config, client.clone()),
            ("info", _) => {
                config.print();
                Ok(())
            }
            ("search", Some(m)) => {
                search_processor(&parser, m);
                Ok(())
            }
            ("tx", Some(m)) => tx_processor(m, &printer, config, client.clone()),
            ("benchmark", Some(m)) => benchmark_processor(m, &printer, &config, client.clone()),
            ("exit", _) => {
                return Ok(true);
            }
            _ => Ok(()),
        },
        Err(err) => Err(err.to_string()),
    }
    .map(|_| false)
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
                ]
                .into_iter()
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
                ]
                .concat()
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

impl<'a, 'b> Completer for CitaCompleter<'a, 'b> {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &Context,
    ) -> Result<(usize, Vec<Pair>), ReadlineError> {
        let (start, word) = extract_word(line, pos, ESCAPE_CHAR, &DEFAULT_BREAK_CHARS);
        let args = shell_words::split(&line[..pos]).unwrap();
        let word_lower = word.to_lowercase();
        let tmp_pair = Self::find_subcommand(
            self.clap_app.clone(),
            args.iter().map(String::as_str).peekable(),
        )
        .map(|current_app| Self::get_completions(&current_app, &args))
        .unwrap_or_default();

        if word_lower.is_empty() {
            let pairs = tmp_pair
                .clone()
                .into_iter()
                .map(|(display, replacement)| Pair {
                    display,
                    replacement,
                })
                .collect::<Vec<_>>();
            Ok((start, pairs))
        } else {
            let pairs = tmp_pair
                .clone()
                .into_iter()
                .filter(|(_, replacement)| string_include(&replacement.to_lowercase(), &word_lower))
                .map(|(display, replacement)| Pair {
                    display,
                    replacement,
                })
                .collect::<Vec<_>>();

            if pairs
                .iter()
                .any(|ref mut x| x.replacement.to_lowercase().contains(&word_lower))
            {
                let pairs = tmp_pair
                    .clone()
                    .into_iter()
                    .filter(|(_, replacement)| replacement.to_lowercase().contains(&word_lower))
                    .map(|(display, replacement)| Pair {
                        display,
                        replacement,
                    })
                    .collect::<Vec<_>>();
                Ok((start, pairs))
            } else {
                let pairs = tmp_pair
                    .into_iter()
                    .filter(|(_, replacement)| {
                        string_include(&replacement.to_lowercase(), &word_lower)
                    })
                    .map(|(display, replacement)| Pair {
                        display,
                        replacement,
                    })
                    .collect::<Vec<_>>();
                Ok((start, pairs))
            }
        }
    }
}

impl<'a, 'b> Highlighter for CitaCompleter<'a, 'b> {
    fn highlight_hint<'h>(&self, hint: &'h str) -> Cow<'h, str> {
        Owned("\x1b[1m".to_owned() + hint + "\x1b[m")
    }

    fn highlight_candidate<'c>(
        &self,
        candidate: &'c str,
        _completion: CompletionType,
    ) -> Cow<'c, str> {
        let candidate_with_color = candidate
            .split('\n')
            .map(|param| {
                if param.contains('*') {
                    Red.paint(param).to_string()
                } else if !param.starts_with("--") {
                    Green.paint(param).to_string()
                } else {
                    param.to_string()
                }
            })
            .collect::<Vec<String>>()
            .join("\n");
        Owned(candidate_with_color)
    }
}

impl<'a, 'b> Hinter for CitaCompleter<'a, 'b> {
    fn hint(&self, line: &str, _pos: usize, _ctx: &Context) -> Option<String> {
        if line == "get" {
            Some(RGB(105, 105, 105).paint(" [key]").to_string())
        } else if line == "set" {
            Some(RGB(105, 105, 105).paint(" <key> <value>").to_string())
        } else if line == "ethabi encode params" {
            Some(
                RGB(105, 105, 105)
                    .paint(" --param <type> <value>")
                    .to_string(),
            )
        } else if line == "ethabi decode params" {
            Some(
                RGB(105, 105, 105)
                    .paint(" --type <type>... --data <data>")
                    .to_string(),
            )
        } else {
            None
        }
    }
}

impl<'a, 'b> Helper for CitaCompleter<'a, 'b> {}

pub struct GlobalConfig {
    url: String,
    encryption: Encryption,
    color: bool,
    debug: bool,
    save_private: bool,
    json_format: bool,
    path: PathBuf,
    completion_style: bool,
    edit_style: bool,
    env_variable: HashMap<String, serde_json::Value>,
}

impl GlobalConfig {
    pub fn new(url: String) -> Self {
        GlobalConfig {
            url,
            encryption: Encryption::Secp256k1,
            color: true,
            debug: false,
            save_private: false,
            json_format: true,
            path: env::current_dir().unwrap(),
            completion_style: true,
            edit_style: true,
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
                    .map(String::as_str)
                    .collect::<Vec<&str>>(),
            ),
        }
    }

    pub fn set_url(&mut self, value: String) {
        if value.starts_with("http://") || value.starts_with("https://") {
            self.url = value;
        } else {
            self.url = "http://".to_owned() + &value;
        }
    }

    pub fn get_url(&self) -> &String {
        &self.url
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

    fn switch_completion_style(&mut self) {
        self.completion_style = !self.completion_style;
    }

    fn switch_edit_style(&mut self) {
        self.edit_style = !self.edit_style;
    }

    fn switch_save_private(&mut self) {
        self.save_private = !self.save_private;
    }

    pub fn set_encryption(&mut self, encryption: Encryption) {
        self.encryption = encryption;
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

    fn set_completion_style(&mut self, value: bool) {
        self.completion_style = value;
    }

    fn set_edit_style(&mut self, value: bool) {
        self.edit_style = value;
    }

    fn set_save_private(&mut self, value: bool) {
        self.save_private = value;
    }

    pub fn encryption(&self) -> Encryption {
        self.encryption
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

    fn completion_style(&self) -> bool {
        self.completion_style
    }

    fn edit_style(&self) -> bool {
        self.edit_style
    }

    fn save_private(&self) -> bool {
        self.save_private
    }

    fn print(&self) {
        let path = self.path.to_string_lossy();
        let encryption = self.encryption.to_string();
        let color = self.color.to_string();
        let debug = self.debug.to_string();
        let json = self.json_format.to_string();
        let completion_style = if self.completion_style {
            "List"
        } else {
            "Circular"
        };
        let edit_style = if self.edit_style { "Emacs" } else { "Vi" };
        let save_private = self.save_private.to_string();
        let values = [
            ("url", self.url.as_str()),
            ("pwd", path.deref()),
            ("color", color.as_str()),
            ("debug", debug.as_str()),
            ("json", json.as_str()),
            ("encryption", encryption.as_str()),
            ("completion_style", completion_style),
            ("edit_style", edit_style),
            ("save_private", save_private.as_str()),
        ];

        let max_width = values
            .iter()
            .map(|(name, _)| name.len())
            .max()
            .unwrap_or(20)
            + 2;
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
                .filter(|key| key_validator(key).is_err())
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
                caps.name("key").unwrap().as_str().to_string()
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
