//! Optional SOCKS5 egress. Every TCP dial in the stack (SMB here, plus RPC/LDAP/KDC/WinRM in the
//! crates that depend on this one) goes through [`dial`], which routes to a SOCKS5 proxy when one
//! has been registered with [`set_proxy`] — the pivot support real engagements need. Hand-rolled
//! (RFC 1928 CONNECT + RFC 1929 user/pass), consistent with the from-scratch stack.

use std::io::{Error, Result};
use std::sync::OnceLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// A SOCKS5 proxy: `host:port` plus optional username/password auth.
#[derive(Clone, Debug)]
pub struct Socks5 {
    pub proxy: String,
    pub auth: Option<(String, String)>,
}

impl Socks5 {
    /// Parse `[user:pass@]host:port`.
    pub fn parse(s: &str) -> Option<Socks5> {
        let (auth, hostport) = match s.rsplit_once('@') {
            Some((creds, hp)) => {
                let (u, p) = creds.split_once(':')?;
                (Some((u.to_string(), p.to_string())), hp.to_string())
            }
            None => (None, s.to_string()),
        };
        if !hostport.contains(':') {
            return None;
        }
        Some(Socks5 {
            proxy: hostport,
            auth,
        })
    }
}

static PROXY: OnceLock<Option<Socks5>> = OnceLock::new();

/// Register the process-wide SOCKS5 proxy (call once, at startup). `None` means direct connections.
pub fn set_proxy(cfg: Option<Socks5>) {
    let _ = PROXY.set(cfg);
}

/// The registered proxy, if any.
pub fn proxy() -> Option<&'static Socks5> {
    PROXY.get().and_then(|o| o.as_ref())
}

fn err(msg: &str) -> Error {
    Error::other(msg)
}

/// Split `host` into (host, port), defaulting the port when absent. IPv4/hostnames only.
fn host_port(host: &str, default_port: u16) -> (String, u16) {
    if let Some((h, p)) = host.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return (h.to_string(), port);
        }
    }
    (host.to_string(), default_port)
}

/// Dial `host` (with optional `:port`, else `default_port`), routing through the registered SOCKS5
/// proxy if one is set — otherwise a direct TCP connection. The **hostname is sent to the proxy**
/// (ATYP=domain) so internal names resolve on the pivot side.
pub async fn dial(host: &str, default_port: u16) -> Result<TcpStream> {
    let (h, p) = host_port(host, default_port);
    let s = match proxy() {
        Some(cfg) => socks5_connect(cfg, &h, p).await?,
        None => TcpStream::connect((h.as_str(), p)).await?,
    };
    // Disable Nagle: SMB/RPC does many small writes (opens/queries ~90-200B sealed);
    // Nagle+delayed-ACK adds up to 40ms per call. -300..500ms on secretsdump.
    let _ = s.set_nodelay(true);
    Ok(s)
}

async fn socks5_connect(cfg: &Socks5, dst_host: &str, dst_port: u16) -> Result<TcpStream> {
    let mut s = TcpStream::connect(&cfg.proxy).await?;

    // Greeting: offer no-auth (and user/pass if we have creds).
    if cfg.auth.is_some() {
        s.write_all(&[0x05, 0x02, 0x00, 0x02]).await?;
    } else {
        s.write_all(&[0x05, 0x01, 0x00]).await?;
    }
    let mut sel = [0u8; 2];
    s.read_exact(&mut sel).await?;
    if sel[0] != 0x05 {
        return Err(err("SOCKS: bad version in method reply"));
    }
    match sel[1] {
        0x00 => {}
        0x02 => {
            let (u, pw) = cfg
                .auth
                .as_ref()
                .ok_or_else(|| err("SOCKS: proxy demands auth but none given"))?;
            if u.len() > 255 || pw.len() > 255 {
                return Err(err("SOCKS: credential too long"));
            }
            let mut req = vec![0x01, u.len() as u8];
            req.extend_from_slice(u.as_bytes());
            req.push(pw.len() as u8);
            req.extend_from_slice(pw.as_bytes());
            s.write_all(&req).await?;
            let mut ar = [0u8; 2];
            s.read_exact(&mut ar).await?;
            if ar[1] != 0x00 {
                return Err(err("SOCKS: username/password auth rejected"));
            }
        }
        0xFF => return Err(err("SOCKS: proxy accepts no offered auth method")),
        m => return Err(err(&format!("SOCKS: unexpected auth method {m}"))),
    }

    // CONNECT to the destination as a domain name (proxy-side DNS).
    if dst_host.len() > 255 {
        return Err(err("SOCKS: destination host too long"));
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x03, dst_host.len() as u8];
    req.extend_from_slice(dst_host.as_bytes());
    req.extend_from_slice(&dst_port.to_be_bytes());
    s.write_all(&req).await?;

    // Reply: VER REP RSV ATYP BND.ADDR BND.PORT — consume the bound address so the stream is clean.
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[1] != 0x00 {
        return Err(err(&format!(
            "SOCKS: CONNECT to {dst_host}:{dst_port} failed (reply code {})",
            head[1]
        )));
    }
    let addr_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            l[0] as usize
        }
        a => return Err(err(&format!("SOCKS: bad ATYP {a} in reply"))),
    };
    let mut rest = vec![0u8; addr_len + 2];
    s.read_exact(&mut rest).await?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plain_and_authed() {
        let a = Socks5::parse("127.0.0.1:1080").unwrap();
        assert_eq!(a.proxy, "127.0.0.1:1080");
        assert!(a.auth.is_none());
        let b = Socks5::parse("bob:s3cret@10.0.0.5:9050").unwrap();
        assert_eq!(b.proxy, "10.0.0.5:9050");
        assert_eq!(b.auth, Some(("bob".into(), "s3cret".into())));
        assert!(Socks5::parse("nohost").is_none());
    }

    #[test]
    fn host_port_split() {
        assert_eq!(host_port("dc.corp:445", 999), ("dc.corp".into(), 445));
        assert_eq!(host_port("dc.corp", 445), ("dc.corp".into(), 445));
    }
}
