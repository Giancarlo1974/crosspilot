// Security regression tests.
//
// These tests pin specific defensive behaviours added during the security
// hardening pass so future refactors cannot silently regress them. They
// focus on behaviour observable through the public API + wiremock; deeper
// crypto / parser regressions live in unit tests next to the affected
// module.

use winrm_rs::{AuthMethod, WinrmClient, WinrmConfig, WinrmCredentials};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Parse a `MockServer::uri()` string of the form `http://127.0.0.1:PORT`
/// into a (host, port) tuple. Avoids pulling the `url` crate as a
/// dev-dependency just for the test harness.
fn split_host_port(uri: &str) -> (String, u16) {
    let stripped = uri.strip_prefix("http://").unwrap_or(uri);
    let stripped = stripped.strip_suffix('/').unwrap_or(stripped);
    let (host, port) = stripped.rsplit_once(':').expect("uri has port");
    (host.to_string(), port.parse().expect("port parses"))
}

fn basic_client(uri: &str) -> (WinrmClient, String) {
    let (host, port) = split_host_port(uri);
    let config = WinrmConfig {
        port,
        use_tls: false,
        accept_invalid_certs: false,
        connect_timeout_secs: 5,
        operation_timeout_secs: 5,
        auth_method: AuthMethod::Basic,
        max_retries: 0,
        ..Default::default()
    };
    let creds = WinrmCredentials::new("user", "pass", "");
    let client = WinrmClient::new(config, creds).expect("client builds");
    (client, host)
}

/// The transport must NOT follow HTTP redirects: WinRM endpoints are fixed
/// and a 30x is unexpected. Following it could leak the Authorization
/// header to an arbitrary target.
#[tokio::test]
async fn http_redirects_are_not_followed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", "http://attacker.invalid/x"),
        )
        .mount(&server)
        .await;

    let (client, host) = basic_client(&server.uri());
    let result = client.run_command(&host, "ipconfig", &[]).await;
    assert!(
        result.is_err(),
        "expected error on 302, got Ok({:?})",
        result.ok()
    );
}

/// `endpoint()` (transport-internal) sanitizes garbage host strings. Full
/// integration coverage requires a live SOAP responder; the behaviour is
/// pinned by `transport::tests::sanitize_host_*` unit tests. This sentinel
/// keeps the docstring discoverable so the unit tests are not removed
/// without updating this file.
#[tokio::test]
async fn host_sanitization_intent_is_documented() {
    // See src/transport.rs sanitize_host* unit tests.
}
