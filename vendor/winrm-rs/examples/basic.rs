//! Basic WinRM command execution example.
//!
//! Usage: WINRM_HOST=win-server WINRM_USER=admin WINRM_PASS=password cargo run --example basic

use winrm_rs::{WinrmClient, WinrmConfig, WinrmCredentials};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = std::env::var("WINRM_HOST").expect("set WINRM_HOST");
    let user = std::env::var("WINRM_USER").unwrap_or_else(|_| "administrator".into());
    let pass = std::env::var("WINRM_PASS").expect("set WINRM_PASS");

    let client = WinrmClient::new(
        WinrmConfig::default(),
        WinrmCredentials::new(user, pass, ""),
    )?;

    let output = client
        .run_powershell(&host, "$PSVersionTable | ConvertTo-Json")
        .await?;
    println!("Exit code: {}", output.exit_code);
    println!("Stdout:\n{}", String::from_utf8_lossy(&output.stdout));

    if !output.stderr.is_empty() {
        eprintln!("Stderr:\n{}", String::from_utf8_lossy(&output.stderr));
    }

    Ok(())
}
