// Kerberos authentication for WinRM.
//
// Requires the `kerberos` feature. Uses `cross-krb5` which leverages
// the system Kerberos library (libkrb5 on Linux, SSPI on Windows).
//
// Prerequisites: `kinit user@REALM` must have been run to obtain a TGT.

use crate::auth::AuthTransport;
use crate::error::WinrmError;

pub(crate) struct KerberosAuth {
    // Used by the `kerberos` feature impl; the non-feature stub discards it.
    #[cfg_attr(not(feature = "kerberos"), allow(dead_code))]
    pub(crate) service_principal: String, // e.g. "HTTP/win-server.corp.local"
}

#[cfg(feature = "kerberos")]
impl AuthTransport for KerberosAuth {
    async fn send_authenticated(
        &self,
        http: &reqwest::Client,
        url: &str,
        body: String,
    ) -> Result<String, WinrmError> {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD as B64;
        use cross_krb5::{ClientCtx, InitiateFlags};
        use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};

        // Step 1: Initialize Kerberos context and get token
        let (ctx, token) = ClientCtx::new(
            InitiateFlags::empty(),
            None, // use default credentials (from kinit)
            &self.service_principal,
            None,
        )
        .map_err(|e| WinrmError::AuthFailed(format!("Kerberos init: {e}")))?;

        let auth_header = format!("Negotiate {}", B64.encode(&*token));

        // Step 2: Send with Kerberos token
        let resp = http
            .post(url)
            .header(CONTENT_TYPE, "application/soap+xml;charset=UTF-8")
            .header(AUTHORIZATION, &auth_header)
            .body(body)
            .send()
            .await
            .map_err(WinrmError::Http)?;

        // Handle mutual auth (server sends back a token).
        //
        // Verifying the server token is the GSS-API mutual-auth check: it
        // proves the server holds the SPN's keytab. Silently ignoring a
        // step() error would let an unauthenticated server pass.
        if let Some(www_auth) = resp
            .headers()
            .get("WWW-Authenticate")
            .and_then(|v| v.to_str().ok())
            && let Some(token_b64) = www_auth.strip_prefix("Negotiate ")
        {
            let server_token = B64.decode(token_b64.trim_ascii()).map_err(|e| {
                WinrmError::AuthFailed(format!("Kerberos: bad b64 in WWW-Authenticate: {e}"))
            })?;
            ctx.step(&server_token).map_err(|e| {
                WinrmError::AuthFailed(format!("Kerberos mutual authentication failed: {e}"))
            })?;
        }

        if resp.status().as_u16() == 401 {
            return Err(WinrmError::AuthFailed(
                "Kerberos authentication rejected".into(),
            ));
        }

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(WinrmError::AuthFailed(format!("HTTP {status}: {body}")));
        }

        resp.text().await.map_err(WinrmError::Http)
    }
}

#[cfg(not(feature = "kerberos"))]
impl AuthTransport for KerberosAuth {
    async fn send_authenticated(
        &self,
        _http: &reqwest::Client,
        _url: &str,
        _body: String,
    ) -> Result<String, WinrmError> {
        Err(WinrmError::AuthFailed(
            "Kerberos auth requires the 'kerberos' feature: \
             cargo add winrm-rs --features kerberos"
                .into(),
        ))
    }
}

#[cfg(test)]
#[cfg(not(feature = "kerberos"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stub_returns_auth_failed_error() {
        let auth = KerberosAuth {
            service_principal: "HTTP/test".into(),
        };
        let http = reqwest::Client::new();
        let result = auth
            .send_authenticated(&http, "http://unused", "body".into())
            .await;
        // Must be Err — kills the Ok(String::new()) and Ok("xyzzy") mutants.
        assert!(result.is_err(), "stub must return Err, got Ok");
        match result.unwrap_err() {
            WinrmError::AuthFailed(msg) => {
                assert!(
                    msg.contains("kerberos") && msg.contains("feature"),
                    "error should mention kerberos feature, got: {msg}"
                );
            }
            other => panic!("expected AuthFailed, got: {other}"),
        }
    }
}
