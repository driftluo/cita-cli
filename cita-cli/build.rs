extern crate cita_tool;
extern crate clap;

include!("src/cli.rs");
use clap::Shell;
use std::env;

fn main() {
    let mut app = build_cli("http://127.0.0.1:1337");
    let out_dir = env::var("OUT_DIR").unwrap();

    app.gen_completions("cita-cli", Shell::Bash, &out_dir);
    app.gen_completions("cita-cli", Shell::Fish, &out_dir);
    app.gen_completions("cita-cli", Shell::Zsh, &out_dir);
}
