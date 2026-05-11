use glimmer::collect::keyring;

fn main() {

    let entries = match keyring::dump_keyring() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("keyring error: {}", e);
            return;
        }
    };

    println!("==> KeyRing entries: {}\n", entries.len());
    
    for entry in &entries {
        println!("  label: {}", entry.label);
        println!("  path:  {}", entry.path);
        println!("  type:  {}", entry.content_type);
        println!("  value: {}", String::from_utf8_lossy(&entry.secret));
        println!();
    }

}