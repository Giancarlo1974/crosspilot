// One-shot WinRM exec: esegue un comando powershell sul remote.
// Uso: CROSSPILOT_HOST=.. CROSSPILOT_USER=.. CROSSPILOT_PASS=.. cargo run --example winrm_exec -- "<ps>"
use winrm_rs::{WinrmClient, WinrmConfig, WinrmCredentials};

#[tokio::main]
async fn main() {
    let ps = std::env::args().nth(1).expect("passa lo script powershell");
    let host = std::env::var("CROSSPILOT_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port = std::env::var("CROSSPILOT_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5985u16);
    let user_raw = std::env::var("CROSSPILOT_USER").unwrap_or_default();
    let pass = std::env::var("CROSSPILOT_PASS").unwrap_or_default();
    // Split UPN/DOMAIN\user come bootstrap.rs
    let (user, domain) = if let Some(pos) = user_raw.rfind('@') {
        (user_raw[..pos].to_string(), String::new())
    } else if let Some(pos) = user_raw.rfind('\\') {
        (user_raw[pos + 1..].to_string(), user_raw[..pos].to_string())
    } else {
        (user_raw, String::new())
    };
    let config = WinrmConfig { port, use_tls: false, ..Default::default() };
    let creds = WinrmCredentials::new(user, pass, domain);
    let client = WinrmClient::new(config, creds).expect("winrm client");
    let out = client.run_powershell(&host, &ps).await.expect("run_powershell");
    println!("{}", String::from_utf8_lossy(&out.stdout));
    eprintln!("{}", String::from_utf8_lossy(&out.stderr));
}
