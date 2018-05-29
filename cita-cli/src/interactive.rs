use std::sync::Arc;
use std::io;

use linefeed::{Interface, Prompter, ReadResult};

pub fn interactive(url: &str) -> io::Result<()> {
    let interface = Arc::new(Interface::new("cita-cli")?);
    Ok(())
}
