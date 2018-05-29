use std::io;
use std::sync::Arc;

use linefeed::{Interface, Prompter, ReadResult};

pub fn interactive(url: &str) -> io::Result<()> {
    let interface = Arc::new(Interface::new("cita-cli")?);
    Ok(())
}
