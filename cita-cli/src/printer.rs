use std::io;
use std::env;
use std::default;
use std::rc::Rc;

use atty;
use serde_json;
use ansi_term::Colour::Yellow;

use highlight;
use cita_tool::{JsonRpcResponse, KeyPair};


pub fn is_a_tty(stderr: bool) -> bool {
    let stream = if stderr {
        atty::Stream::Stderr
    } else {
        atty::Stream::Stdout
    };
    atty::is(stream)
}

pub fn is_term_dumb() -> bool { env::var("TERM").ok() == Some(String::from("dumb")) }


#[derive(Copy, Clone, Debug, PartialEq)]
pub enum OutputFormat {
    Raw,
    Json,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ColorWhen {
    Auto,
    #[allow(dead_code)]
    Always,
    Never,
}

impl default::Default for ColorWhen {
    fn default() -> Self {
        let is_a_tty = is_a_tty(false);
        let is_term_dumb = is_term_dumb();
        if is_a_tty && !is_term_dumb {
            ColorWhen::Auto
        } else {
            ColorWhen::Never
        }
    }
}

pub struct Printer {
    format: OutputFormat,
    color: ColorWhen,
}

impl default::Default for Printer {
    fn default() -> Self {
        Printer {
            format: OutputFormat::Json,
            color: ColorWhen::default()
        }
    }
}

impl Printer {
    pub fn color(&self) -> bool {
        self.color != ColorWhen::Never
    }
    pub fn set_format(&mut self, format: OutputFormat) -> &mut Self {
        self.format = format;
        self
    }

    pub fn set_color(&mut self, color: ColorWhen) -> &mut Self {
        self.color = color;
        self
    }

    pub fn print<W: io::Write, P: Printable>(
        &self,
        target: &mut W,
        content: &P,
        newline: bool,
        format: Option<OutputFormat>,
        color: Option<ColorWhen>
    ) -> io::Result<()> {
        let format = format.unwrap_or(self.format);
        let color = match color.unwrap_or(self.color) {
            ColorWhen::Always | ColorWhen::Auto => true,
            ColorWhen::Never => false
        };
        target.write_all(content.rc_string(format, color).as_bytes())?;
        if newline {
            target.write_all(&[b'\n'])?;
        }
        Ok(())
    }

    pub fn println<P: Printable>(&self, content: &P, color: bool) {
        let stdout = io::stdout();
        let color = if color { None } else { Some(ColorWhen::Never) };
        self.print(&mut stdout.lock(), content, true, None, color).unwrap();
    }

    pub fn eprintln<P: Printable>(&self, content: &P, color: bool) {
        let stderr = io::stderr();
        let color = if color { None } else { Some(ColorWhen::Never) };
        self.print(&mut stderr.lock(), content, true, None, color).unwrap();
    }
}

pub trait Printable {
    fn rc_string(&self, format: OutputFormat, color: bool) -> Rc<String>;
}

impl Printable for String {
    fn rc_string(&self, _format: OutputFormat, _color: bool) -> Rc<String> {
        Rc::new(self.clone())
    }
}

impl Printable for Rc<String> {
    fn rc_string(&self, _format: OutputFormat, _color: bool) -> Rc<String> {
        self.clone()
    }
}

impl Printable for JsonRpcResponse {
    fn rc_string(&self, _format: OutputFormat, color: bool) -> Rc<String> {
        let content = format!("{:?}", self);
        let content = if color {
            highlight::highlight(content.as_str(), "json")
        } else {
            content
        };
        Rc::new(content)
    }
}

impl Printable for serde_json::Value {
    fn rc_string(&self, _format: OutputFormat, color: bool) -> Rc<String> {
        let content = serde_json::to_string_pretty(self).unwrap();
        let content = if color {
            highlight::highlight(content.as_str(), "json")
        } else {
            content
        };
        Rc::new(content)
    }
}

impl Printable for KeyPair {
    fn rc_string(&self, format: OutputFormat, color: bool) -> Rc<String> {
         match format {
            OutputFormat::Json => {
                json!({
                    "private-key": format!("0x{}", self.privkey()),
                    "public-key": format!("0x{}", self.pubkey()),
                    "address": format!("0x{:#x}", self.address())
                }).rc_string(format, color)
            }
            OutputFormat::Raw => {
                let content = if color {
                    format!(
                        concat!("{} 0x{}\n", "{} 0x{}\n", "{} 0x{:#x}"),
                        Yellow.paint("[private key]:"),
                        self.privkey(),
                        Yellow.paint("[public key ]:"),
                        self.pubkey(),
                        Yellow.paint("[  address  ]:"),
                        self.address()
                    )
                } else {
                    format!(
                        concat!("{} 0x{}\n", "{} 0x{}\n", "{} 0x{:#x}"),
                        "[private key]:",
                        self.privkey(),
                        "[public key ]:",
                        self.pubkey(),
                        "[  address  ]:",
                        self.address()
                    )
                };
                Rc::new(content)
            }
        }
    }
}
