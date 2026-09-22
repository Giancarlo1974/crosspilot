// Test di debug per l'autenticazione WinRM NTLM.
// Prova diverse combinazioni username/domain per isolare il bug HTTP 500.
use winrm_rs::{WinrmClient, WinrmConfig, WinrmCredentials};

#[tokio::main]
async fn main() {
    // Abilita tracing per vedere i dettagli del handshake NTLM/SOAP.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "winrm_rs=trace".into()),
        )
        .init();

    let host = "172.16.0.101";
    let pass = "Ottobre26_";

    // Combinazioni da provare: (username, domain)
    let combos: Vec<(&str, &str)> = vec![
        ("giancarloalbanese@ac-s-srl.it", ""),      // UPN intero come username
    ];

    for (user, domain) in combos {
        println!("=== TEST user={:?} domain={:?} ===", user, domain);
        let config = WinrmConfig {
            port: 5985,
            use_tls: false,
            ..Default::default()
        };
        let creds = WinrmCredentials::new(user, pass, domain);
        let client = match WinrmClient::new(config, creds) {
            Ok(c) => c,
            Err(e) => {
                println!("  client new failed: {}", e);
                continue;
            }
        };
        // Pulisci: uccidi server + elimina exe + elimina task
        let ps = "schtasks /Delete /TN crosspilot-server /F 2>&1; Get-Process crosspilot -ErrorAction SilentlyContinue | Stop-Process -Force; Remove-Item 'C:\\Users\\giancarloalbanese\\repos\\crosspilot\\target\\release\\crosspilot.exe' -Force -ErrorAction SilentlyContinue; 'pulito: ' + (Test-Path 'C:\\Users\\giancarloalbanese\\repos\\crosspilot\\target\\release\\crosspilot.exe')";
        match client.run_powershell(host, ps).await {
            Ok(out) => println!("  cleanup: {}", String::from_utf8_lossy(&out.stdout).trim()),
            Err(e) => println!("  cleanup FAIL: {}", e),
        }
    }
}
