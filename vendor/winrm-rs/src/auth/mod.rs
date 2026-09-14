// Authentication transport abstraction for WinRM.
//
// Defines the `AuthTransport` trait and provides Basic, NTLM, Kerberos,
// and Certificate implementations.

pub(crate) mod basic;
pub(crate) mod certificate;
#[cfg(feature = "credssp")]
pub(crate) mod credssp;
pub(crate) mod kerberos;
pub(crate) mod ntlm;

use crate::error::WinrmError;

/// Internal trait for authenticated HTTP transport.
///
/// Each implementation handles its own authentication mechanism (Basic, NTLM,
/// Kerberos, Certificate) and returns the response body as a string.
pub(crate) trait AuthTransport {
    /// Send an authenticated SOAP request and return the response body.
    async fn send_authenticated(
        &self,
        http: &reqwest::Client,
        url: &str,
        body: String,
    ) -> Result<String, WinrmError>;
}
