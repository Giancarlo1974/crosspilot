//! SPIKE di fattibilità russh (docs/ssh-unified-prescan-bootstrap-spec.md §5 passo 0).
//!
//! Valida, contro un OpenSSH reale, le 3 primitive su cui si baserà
//! ssh_transport.rs: connect+auth (chiave), exec (stdout+exit code),
//! SFTP (write/read/delete — shell-independent, prerequisito SSH->Windows).
//!
//! Uso: cargo run --example ssh_spike -- <host> <user> <key_path>
//!   es: cargo run --example ssh_spike -- dock2 webmaster ~/.ssh/id_rsa
//!
//! check_server_key accetta tutto: e' uno SPIKE, la TOFU e' nel design §1.5.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use russh::client::{self, Handler};
use russh::keys::{load_secret_key, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{ChannelMsg, Disconnect};
use russh_sftp::client::SftpSession;

struct Client;

impl Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        // SPIKE: accept-all. Il fingerprint viene comunque stampato per
        // confronto manuale con `ssh-keyscan dock2 | ssh-keygen -lf -`.
        eprintln!(
            "[hostkey] {:?}",
            key.public_key()
                .fingerprint(russh::keys::HashAlg::Sha256)
        );
        Ok(true)
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let host = std::env::args().nth(1).unwrap_or_else(|| "dock2".into());
    let user = std::env::args().nth(2).unwrap_or_else(|| "webmaster".into());
    let key_path = std::env::args()
        .nth(3)
        .unwrap_or_else(|| format!("{}/.ssh/id_rsa", std::env::var("HOME").unwrap()));

    eprintln!("[1] connect+auth {}@{}:22 key={}", user, host, key_path);
    let t0 = Instant::now();
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(10)),
        ..Default::default()
    });
    let connect = client::connect(config, (host.as_str(), 22), Client);
    let mut session = tokio::time::timeout(Duration::from_secs(6), connect)
        .await
        .context("connect timeout 6s")??;
    let key = load_secret_key(&key_path, None).context("load_secret_key")?;
    let hash_alg = session.best_supported_rsa_hash().await?.flatten();
    let auth = session
        .authenticate_publickey(
            user.as_str(),
            PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg),
        )
        .await?;
    if !auth.success() {
        bail!("auth publickey fallita");
    }
    eprintln!("    OK connect+auth in {:?}", t0.elapsed());

    // --- exec: stdout + stderr + exit code ---
    eprintln!("[2] exec 'hostname; uname -sr; id -u; exit 42'");
    let mut channel = session.channel_open_session().await?;
    channel
        .exec(true, "hostname; uname -sr; id -u; exit 42")
        .await?;
    let mut stdout = Vec::new();
    let mut code = None;
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
            ChannelMsg::ExtendedData { data, .. } => {
                eprint!("    [stderr] {}", String::from_utf8_lossy(&data))
            }
            ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status),
            _ => {}
        }
    }
    eprintln!("    exit_code={:?}", code);
    eprint!("    stdout: {}", String::from_utf8_lossy(&stdout));
    if code != Some(42) {
        bail!("exit code inatteso: {:?}", code);
    }

    // --- SFTP: write -> read-back -> compare -> delete ---
    eprintln!("[3] SFTP write/read/delete /tmp/crosspilot_spike.bin");
    let channel = session.channel_open_session().await?;
    channel.request_subsystem(true, "sftp").await?;
    let sftp = SftpSession::new(channel.into_stream()).await?;
    eprintln!("    sftp session init ok");
    eprintln!("    exists /tmp: {:?}", sftp.try_exists("/tmp").await);
    // NOTA API: sftp.write() usa OpenFlags::WRITE senza CREATE -> solo
    // file esistenti. Per l'upload: create() (CREATE|TRUNCATE|WRITE)
    // + write_all sul File.
    let path = "/tmp/crosspilot_spike.bin";
    let payload: Vec<u8> = (0..=255u8).cycle().take(100_000).collect();
    let mut file = sftp.create(path).await.context("sftp create")?;
    tokio::io::AsyncWriteExt::write_all(&mut file, &payload)
        .await
        .context("sftp write_all")?;
    tokio::io::AsyncWriteExt::shutdown(&mut file).await?;
    eprintln!("    create+write ok");
    let back = sftp.read(path).await.context("sftp read")?;
    eprintln!("    read ok ({} byte)", back.len());
    if back != payload {
        bail!("SFTP read-back mismatch ({} vs {} byte)", back.len(), payload.len());
    }
    let meta = sftp.metadata(path).await?;
    sftp.remove_file(path).await?;
    if sftp.try_exists(path).await? {
        bail!("file ancora presente dopo remove_file");
    }
    eprintln!(
        "    OK {} byte scritti/riletti identici (meta={:?}B), delete ok",
        payload.len(),
        meta.size
    );

    session
        .disconnect(Disconnect::ByApplication, "", "en")
        .await?;
    println!("SPIKE OK: connect+auth+exec+sftp funzionanti contro OpenSSH reale");
    Ok(())
}
