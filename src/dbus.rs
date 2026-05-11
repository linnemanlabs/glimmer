use std::time::SystemTime;
use zbus::{connection, interface, Result};

struct TestService;

#[interface(name = "com.example.TestService")]
impl TestService {
    async fn ping(&self, msg: String) -> String {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        eprintln!("{:.6} Ping called with: {}", now, msg);
        format!("pong: {}", msg)
    }

    #[zbus(property)]
    async fn version(&self) -> String {
        "0.1.0".to_string()
    }
}

#[tokio::main]
pub async fn start_dbus_service() -> Result<()> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    eprintln!("{:.6} activated, PID={}", now, std::process::id());

    let _conn = connection::Builder::session()?
        .name("com.example.TestService")?
        .serve_at("/com/example/TestService", TestService)?
        .build()
        .await?;

    // Keep the process alive
    std::future::pending::<()>().await;
    Ok(())
}