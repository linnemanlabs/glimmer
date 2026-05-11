use glimmer::collect::{browser,CollectedData};

fn main() {

    println!("==> browser credentials:\n");

    let items = browser::collect();

    if items.is_empty() {
        println!("  no credentials found");
        return;
    }

    for item in &items {
        if let CollectedData::BrowserCred { browser, url, username, password } = &item.data {
            println!("  browser:  {}", browser);
            println!("  url:      {}", url);
            println!("  username: {}", username);
            println!("  password: {}", String::from_utf8_lossy(&password));
            println!();
        }
    }

}