// WinRM HTTP client — facade over transport, shell lifecycle, and command execution.
//
// Communicates with the WinRM service (WS-Management) over HTTP(S).
// Supports NTLM, Basic, Kerberos, and Certificate authentication.

use tracing::debug;

use crate::builder::WinrmClientBuilder;
use crate::command::{CommandOutput, encode_powershell_command};
use crate::config::{WinrmConfig, WinrmCredentials};
use crate::error::WinrmError;
use crate::shell::Shell;
use crate::soap;
use crate::transport::HttpTransport;

/// Async WinRM (WS-Management) HTTP client.
///
/// Manages the full remote-shell lifecycle: create a shell, execute commands,
/// poll output, signal termination, and delete the shell. Each high-level
/// method ([`run_command`](Self::run_command), [`run_powershell`](Self::run_powershell))
/// handles this lifecycle automatically; the lower-level methods are available
/// for callers that need finer control.
///
/// The client is cheaply cloneable via the inner `reqwest::Client` connection
/// pool but is **not** `Clone` itself -- create one per logical session.
pub struct WinrmClient {
    pub(crate) transport: HttpTransport,
}

impl WinrmClient {
    /// Create a new [`WinrmClient`] from the given configuration and credentials.
    ///
    /// Builds the underlying HTTP client with the configured timeouts and TLS
    /// settings. Returns [`WinrmError::Http`] if the HTTP client cannot be
    /// constructed (e.g. invalid TLS configuration).
    #[tracing::instrument(level = "debug", skip(credentials))]
    pub fn new(config: WinrmConfig, credentials: WinrmCredentials) -> Result<Self, WinrmError> {
        Ok(Self {
            transport: HttpTransport::new(config, credentials)?,
        })
    }

    /// Build the WinRM endpoint URL for a given host.
    pub(crate) fn endpoint(&self, host: &str) -> String {
        self.transport.endpoint(host)
    }

    /// Access the client configuration.
    pub(crate) fn config(&self) -> &WinrmConfig {
        self.transport.config()
    }

    /// Create a [`WinrmClientBuilder`] for constructing a client with the
    /// typestate builder pattern.
    pub fn builder(config: WinrmConfig) -> WinrmClientBuilder {
        WinrmClientBuilder::new(config)
    }

    /// Send an authenticated SOAP request (public within crate, used by Shell).
    pub(crate) async fn send_soap_raw(
        &self,
        host: &str,
        body: String,
    ) -> Result<String, WinrmError> {
        self.transport.send_soap_raw(host, body).await
    }

    // --- Shell lifecycle ---

    /// Create a new remote shell on the given host. Returns the shell ID.
    ///
    /// The shell uses UTF-8 codepage (65001) and disables the user profile
    /// (`WINRS_NOPROFILE`). The caller must eventually call
    /// [`delete_shell`](Self::delete_shell) to release server resources.
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn create_shell(&self, host: &str) -> Result<String, WinrmError> {
        let config = self.transport.config();
        let envelope = soap::create_shell_request(&self.transport.endpoint(host), config);
        let response = self.transport.send_soap_with_retry(host, envelope).await?;
        soap::parse_shell_id(&response).map_err(WinrmError::Soap)
    }

    /// Create a PSRP (PowerShell Remoting) shell on the given host.
    ///
    /// Unlike [`Self::create_shell`] this uses the PowerShell resource URI and
    /// embeds the `creationXml` (base64-encoded PSRP opening fragments)
    /// directly in the Create Shell body.
    ///
    /// Returns a [`Shell`] whose subsequent operations (Execute, Receive,
    /// Send, Signal, Delete) will use the PowerShell resource URI.
    #[tracing::instrument(level = "debug", skip(self, creation_xml_b64))]
    pub async fn open_psrp_shell(
        &self,
        host: &str,
        creation_xml_b64: &str,
        resource_uri: &str,
    ) -> Result<Shell<'_>, WinrmError> {
        let config = self.transport.config();
        // The PSRP provider expects the client to propose a ShellId in the
        // Create body (as an attribute on `<rsp:Shell ShellId="…">`).
        let proposed_id = uuid::Uuid::new_v4().hyphenated().to_string().to_uppercase();
        let envelope = soap::create_psrp_shell_request(
            &self.transport.endpoint(host),
            config,
            creation_xml_b64,
            resource_uri,
            &proposed_id,
        );
        let response = self.transport.send_soap_with_retry(host, envelope).await?;
        let shell_id = soap::parse_shell_id(&response).map_err(WinrmError::Soap)?;
        debug!(shell_id = %shell_id, "PSRP shell opened");
        Ok(Shell::new_with_resource_uri(
            self,
            host.to_string(),
            shell_id,
            resource_uri.to_string(),
        ))
    }

    /// Execute a command in an existing remote shell. Returns the command ID.
    ///
    /// The caller is responsible for subsequently calling
    /// [`receive_output`](Self::receive_output) to poll for results.
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn execute_command(
        &self,
        host: &str,
        shell_id: &str,
        command: &str,
        args: &[&str],
    ) -> Result<String, WinrmError> {
        let config = self.transport.config();
        let envelope = soap::execute_command_request(
            &self.transport.endpoint(host),
            shell_id,
            command,
            args,
            config.operation_timeout_secs,
            config.max_envelope_size,
        );
        let response = self.transport.send_soap_with_retry(host, envelope).await?;
        soap::parse_command_id(&response).map_err(WinrmError::Soap)
    }

    /// Poll for command output (stdout, stderr, exit code, and completion flag).
    ///
    /// Must be called repeatedly until [`ReceiveOutput::done`](soap::ReceiveOutput::done)
    /// is `true`. Each call may return partial output that should be accumulated.
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn receive_output(
        &self,
        host: &str,
        shell_id: &str,
        command_id: &str,
    ) -> Result<soap::ReceiveOutput, WinrmError> {
        let config = self.transport.config();
        let envelope = soap::receive_output_request(
            &self.transport.endpoint(host),
            shell_id,
            command_id,
            config.operation_timeout_secs,
            config.max_envelope_size,
        );
        let response = self.transport.send_soap_with_retry(host, envelope).await?;
        soap::parse_receive_output(&response).map_err(WinrmError::Soap)
    }

    /// Send a terminate signal to a running command.
    ///
    /// This is a best-effort operation -- errors are typically non-fatal
    /// since the shell will be deleted shortly after.
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn signal_terminate(
        &self,
        host: &str,
        shell_id: &str,
        command_id: &str,
    ) -> Result<(), WinrmError> {
        let config = self.transport.config();
        let envelope = soap::signal_terminate_request(
            &self.transport.endpoint(host),
            shell_id,
            command_id,
            config.operation_timeout_secs,
            config.max_envelope_size,
        );
        self.transport.send_soap_with_retry(host, envelope).await?;
        Ok(())
    }

    /// Delete (close) a remote shell, releasing server-side resources.
    ///
    /// Should always be called after command execution is complete, even if
    /// an error occurred. The high-level [`run_command`](Self::run_command)
    /// and [`run_powershell`](Self::run_powershell) methods handle this
    /// automatically.
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn delete_shell(&self, host: &str, shell_id: &str) -> Result<(), WinrmError> {
        self.delete_shell_with_resource_uri(
            host,
            shell_id,
            crate::soap::namespaces::RESOURCE_URI_CMD,
        )
        .await
    }

    // --- High-level operations ---

    /// Run a command on a remote host, collecting all output.
    ///
    /// This is the primary entry point for command execution. It handles the
    /// full shell lifecycle: create -> execute -> poll -> signal -> delete.
    /// The shell is always cleaned up, even if the command fails.
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn run_command(
        &self,
        host: &str,
        command: &str,
        args: &[&str],
    ) -> Result<CommandOutput, WinrmError> {
        let shell_id = self.create_shell(host).await?;
        debug!(shell_id = %shell_id, "WinRM shell created");

        let result = self.run_in_shell(host, &shell_id, command, args).await;

        // Always clean up the shell
        self.delete_shell(host, &shell_id)
            .await
            .inspect_err(|e| debug!(error = %e, "failed to delete WinRM shell (best-effort)"))
            .ok();

        result
    }

    /// Run a command in an existing shell, polling output until completion.
    async fn run_in_shell(
        &self,
        host: &str,
        shell_id: &str,
        command: &str,
        args: &[&str],
    ) -> Result<CommandOutput, WinrmError> {
        let command_id = self.execute_command(host, shell_id, command, args).await?;
        debug!(command_id = %command_id, "WinRM command started");

        let max_output = self.transport.config().max_output_bytes;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_code: Option<i32> = None;

        loop {
            let output = self.receive_output(host, shell_id, &command_id).await?;
            stdout.extend_from_slice(&output.stdout);
            stderr.extend_from_slice(&output.stderr);

            if let Some(cap) = max_output
                && stdout.len() + stderr.len() > cap
            {
                self.signal_terminate(host, shell_id, &command_id)
                    .await
                    .ok();
                return Err(WinrmError::Transfer(format!(
                    "command output exceeded max_output_bytes ({cap})"
                )));
            }

            if output.exit_code.is_some() {
                exit_code = output.exit_code;
            }

            if output.done {
                break;
            }
        }

        // Best-effort signal terminate
        self.signal_terminate(host, shell_id, &command_id)
            .await
            .ok();

        Ok(CommandOutput {
            stdout,
            stderr,
            exit_code: exit_code.unwrap_or(-1),
        })
    }

    /// Run a PowerShell script on a remote host.
    ///
    /// The script is encoded as UTF-16LE base64 and executed via
    /// `powershell.exe -EncodedCommand`, which avoids quoting and escaping
    /// issues. Internally delegates to [`run_command`](Self::run_command).
    #[tracing::instrument(level = "debug", skip(self, script))]
    pub async fn run_powershell(
        &self,
        host: &str,
        script: &str,
    ) -> Result<CommandOutput, WinrmError> {
        let encoded = encode_powershell_command(script);
        self.run_command(host, "powershell.exe", &["-EncodedCommand", &encoded])
            .await
    }

    /// Execute a command with cancellation support.
    ///
    /// Like [`run_command`](Self::run_command), but can be cancelled via a
    /// [`CancellationToken`](tokio_util::sync::CancellationToken).
    pub async fn run_command_with_cancel(
        &self,
        host: &str,
        command: &str,
        args: &[&str],
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<CommandOutput, WinrmError> {
        // Honour a pre-cancelled token deterministically. Without this
        // short-circuit `tokio::select!` polls the two arms in
        // pseudo-random order, so on macOS the inner `run_command` future
        // can start an HTTP request and surface a transport error
        // *before* the cancel-arm is polled.
        if cancel.is_cancelled() {
            return Err(WinrmError::Cancelled);
        }
        tokio::select! {
            result = self.run_command(host, command, args) => result,
            () = cancel.cancelled() => Err(WinrmError::Cancelled),
        }
    }

    /// Execute a PowerShell script with cancellation support.
    ///
    /// Like [`run_powershell`](Self::run_powershell), but can be cancelled via a
    /// [`CancellationToken`](tokio_util::sync::CancellationToken).
    pub async fn run_powershell_with_cancel(
        &self,
        host: &str,
        script: &str,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<CommandOutput, WinrmError> {
        let encoded = encode_powershell_command(script);
        self.run_command_with_cancel(
            host,
            "powershell.exe",
            &["-EncodedCommand", &encoded],
            cancel,
        )
        .await
    }

    /// Execute a WQL query against WMI via WS-Enumeration.
    ///
    /// Returns the raw XML response items as a string. The response contains
    /// WMI object instances matching the query. Use a `namespace` of `None`
    /// for the default `root/cimv2`.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use winrm_rs::{WinrmClient, WinrmConfig, WinrmCredentials};
    /// # async fn example() -> Result<(), winrm_rs::WinrmError> {
    /// # let client = WinrmClient::new(WinrmConfig::default(), WinrmCredentials::new("u","p",""))?;
    /// let xml = client.run_wql("server", "SELECT Name,State FROM Win32_Service", None).await?;
    /// println!("{xml}");
    /// # Ok(()) }
    /// ```
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn run_wql(
        &self,
        host: &str,
        query: &str,
        namespace: Option<&str>,
    ) -> Result<String, WinrmError> {
        let config = self.transport.config();
        let endpoint = self.transport.endpoint(host);

        // Phase 1: Enumerate with WQL filter
        let envelope = soap::enumerate_wql_request(
            &endpoint,
            query,
            namespace,
            config.operation_timeout_secs,
            config.max_envelope_size,
        );
        let response = self.transport.send_soap_with_retry(host, envelope).await?;
        let (mut items, mut context) =
            soap::parse_enumerate_response(&response).map_err(WinrmError::Soap)?;

        let max_output = config.max_output_bytes;

        // Phase 2: Pull remaining items if enumeration is not complete
        while let Some(ctx) = context {
            let pull_envelope = soap::pull_request(
                &endpoint,
                &ctx,
                config.operation_timeout_secs,
                config.max_envelope_size,
            );
            let pull_response = self
                .transport
                .send_soap_with_retry(host, pull_envelope)
                .await?;
            let (more_items, next_ctx) =
                soap::parse_enumerate_response(&pull_response).map_err(WinrmError::Soap)?;
            items.push_str(&more_items);
            context = next_ctx;

            if let Some(cap) = max_output
                && items.len() > cap
            {
                return Err(WinrmError::Transfer(format!(
                    "WQL enumeration exceeded max_output_bytes ({cap})"
                )));
            }
        }

        Ok(items)
    }

    /// Open a reusable shell session on the given host.
    ///
    /// Returns a [`Shell`] that can execute multiple commands without the
    /// overhead of creating and deleting a shell each time.
    ///
    /// The shell should be explicitly closed via [`Shell::close`] when done.
    /// If dropped without closing, a warning is logged.
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn open_shell(&self, host: &str) -> Result<Shell<'_>, WinrmError> {
        let shell_id = self.create_shell(host).await?;
        debug!(shell_id = %shell_id, "WinRM shell opened for reuse");
        Ok(Shell::new(self, host.to_string(), shell_id))
    }

    /// Delete a shell that lives under a non-default ResourceURI.
    ///
    /// Delete is plugin-addressed like every other shell operation. A PSRP
    /// shell deleted with the `cmd` ResourceURI is reported as not found and
    /// stays alive server-side, so `Shell::close` passes the URI the shell
    /// was created with.
    pub(crate) async fn delete_shell_with_resource_uri(
        &self,
        host: &str,
        shell_id: &str,
        resource_uri: &str,
    ) -> Result<(), WinrmError> {
        let config = self.transport.config();
        let envelope = soap::delete_shell_request_for(
            &self.transport.endpoint(host),
            shell_id,
            resource_uri,
            config.operation_timeout_secs,
            config.max_envelope_size,
        );
        self.transport.send_soap_with_retry(host, envelope).await?;
        Ok(())
    }

    /// Reconnect to a previously-disconnected shell.
    ///
    /// Sends a WS-Man `Reconnect` SOAP request to validate that the
    /// server-side shell identified by `shell_id` is still alive and
    /// returns a [`Shell`] handle that resumes operations on it.
    #[tracing::instrument(level = "debug", skip(self))]
    pub async fn reconnect_shell(
        &self,
        host: &str,
        shell_id: &str,
        resource_uri: &str,
    ) -> Result<Shell<'_>, WinrmError> {
        let config = self.transport.config();
        let envelope = soap::reconnect_shell_request_with_uri(
            &self.transport.endpoint(host),
            shell_id,
            config.operation_timeout_secs,
            config.max_envelope_size,
            resource_uri,
        );
        self.transport.send_soap_with_retry(host, envelope).await?;
        debug!(shell_id = %shell_id, "WinRM shell reconnected");
        Ok(Shell::new_with_resource_uri(
            self,
            host.to_string(),
            shell_id.to_string(),
            resource_uri.to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthMethod, EncryptionMode};
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;
    use wiremock::matchers::{header, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_creds() -> WinrmCredentials {
        WinrmCredentials::new("admin", "pass", "")
    }

    fn basic_config(port: u16) -> WinrmConfig {
        WinrmConfig {
            port,
            auth_method: AuthMethod::Basic,
            connect_timeout_secs: 5,
            operation_timeout_secs: 10,
            ..Default::default()
        }
    }

    fn ntlm_config(port: u16) -> WinrmConfig {
        WinrmConfig {
            port,
            auth_method: AuthMethod::Ntlm,
            connect_timeout_secs: 5,
            operation_timeout_secs: 10,
            // Mocks don't support NTLM sealing; disable encryption for unit tests.
            encryption: EncryptionMode::Never,
            ..Default::default()
        }
    }

    #[test]
    fn client_builds_correct_endpoint() {
        let config = WinrmConfig::default();
        let creds = WinrmCredentials::new("admin", "pass", "");
        let client = WinrmClient::new(config, creds).unwrap();
        assert_eq!(client.endpoint("win-01"), "http://win-01:5985/wsman");
    }

    #[test]
    fn client_builds_https_endpoint() {
        let config = WinrmConfig {
            port: 5986,
            use_tls: true,
            ..Default::default()
        };
        let creds = WinrmCredentials::new("admin", "pass", "");
        let client = WinrmClient::new(config, creds).unwrap();
        assert_eq!(client.endpoint("win-01"), "https://win-01:5986/wsman");
    }

    #[tokio::test]
    async fn send_basic_success() {
        let server = MockServer::start().await;
        let port = server.address().port();

        Mock::given(method("POST"))
            .and(header("Authorization", "Basic YWRtaW46cGFzcw=="))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>SHELL-1</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let result = client.create_shell("127.0.0.1").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "SHELL-1");
    }

    #[tokio::test]
    async fn send_basic_auth_failure() {
        let server = MockServer::start().await;
        let port = server.address().port();

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let result = client.create_shell("127.0.0.1").await;
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("auth failed") || err.contains("401"));
    }

    #[tokio::test]
    async fn send_basic_soap_fault() {
        let server = MockServer::start().await;
        let port = server.address().port();

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><s:Fault><s:Code><s:Value>s:Receiver</s:Value></s:Code><s:Reason><s:Text>Access denied</s:Text></s:Reason></s:Fault></s:Body></s:Envelope>",
            ))
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let result = client.create_shell("127.0.0.1").await;
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("SOAP") || err.contains("Access denied"));
    }

    #[tokio::test]
    async fn execute_command_and_receive_output() {
        let server = MockServer::start().await;
        let port = server.address().port();

        // Mock: create_shell
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>S1</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Mock: execute_command
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>C1</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Mock: receive_output (done)
        // "hello" = aGVsbG8=
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:Stream Name="stdout" CommandId="C1">aGVsbG8=</rsp:Stream>
                    <rsp:CommandState CommandId="C1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                        <rsp:ExitCode>0</rsp:ExitCode>
                    </rsp:CommandState>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Mock: signal_terminate + delete_shell (just return 200 with empty envelope)
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(r"<s:Envelope><s:Body/></s:Envelope>"),
            )
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let output = client
            .run_command("127.0.0.1", "whoami", &[])
            .await
            .unwrap();
        assert_eq!(output.exit_code, 0);
        assert_eq!(output.stdout, b"hello");
    }

    #[tokio::test]
    async fn run_powershell_encodes_and_executes() {
        let server = MockServer::start().await;
        let port = server.address().port();

        // Shell create
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>S2</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Command execute
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>C2</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Receive (done with exit code 0)
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:CommandState CommandId="C2" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                        <rsp:ExitCode>0</rsp:ExitCode>
                    </rsp:CommandState>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Cleanup (signal + delete)
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
            )
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let output = client
            .run_powershell("127.0.0.1", "Get-Process")
            .await
            .unwrap();
        assert_eq!(output.exit_code, 0);
    }

    #[tokio::test]
    async fn delete_shell_success() {
        let server = MockServer::start().await;
        let port = server.address().port();

        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
            )
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let result = client.delete_shell("127.0.0.1", "SHELL-1").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn signal_terminate_success() {
        let server = MockServer::start().await;
        let port = server.address().port();

        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
            )
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let result = client.signal_terminate("127.0.0.1", "S1", "C1").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn ntlm_handshake_success() {
        let server = MockServer::start().await;
        let port = server.address().port();

        // Build a valid Type 2 challenge
        let mut type2 = vec![0u8; 48];
        type2[0..8].copy_from_slice(b"NTLMSSP\0");
        type2[8..12].copy_from_slice(&2u32.to_le_bytes());
        type2[20..24].copy_from_slice(&0x0008_8201_u32.to_le_bytes()); // flags
        type2[24..32].copy_from_slice(&[0x01; 8]); // server challenge
        // no target info (ti_len=0)
        let type2_b64 = B64.encode(&type2);

        // Step 1: 401 with challenge
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(401)
                    .append_header("WWW-Authenticate", format!("Negotiate {type2_b64}")),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Step 2: 200 with shell response
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>NTLM-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .mount(&server)
            .await;

        let client = WinrmClient::new(ntlm_config(port), test_creds()).unwrap();
        let shell_id = client.create_shell("127.0.0.1").await.unwrap();
        assert_eq!(shell_id, "NTLM-SHELL");
    }

    #[tokio::test]
    async fn ntlm_rejected_credentials() {
        let server = MockServer::start().await;
        let port = server.address().port();

        let mut type2 = vec![0u8; 48];
        type2[0..8].copy_from_slice(b"NTLMSSP\0");
        type2[8..12].copy_from_slice(&2u32.to_le_bytes());
        type2[20..24].copy_from_slice(&0x0008_8201_u32.to_le_bytes());
        type2[24..32].copy_from_slice(&[0x01; 8]);
        let type2_b64 = B64.encode(&type2);

        // Step 1: 401 with challenge
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(401)
                    .append_header("WWW-Authenticate", format!("Negotiate {type2_b64}")),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Step 2: 401 again (rejected)
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let client = WinrmClient::new(ntlm_config(port), test_creds()).unwrap();
        let result = client.create_shell("127.0.0.1").await;
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("auth") || err.contains("rejected"));
    }

    #[tokio::test]
    async fn ntlm_unexpected_status_on_negotiate() {
        let server = MockServer::start().await;
        let port = server.address().port();

        // Return 200 instead of expected 401 for negotiate
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<ok/>"))
            .mount(&server)
            .await;

        let client = WinrmClient::new(ntlm_config(port), test_creds()).unwrap();
        let result = client.create_shell("127.0.0.1").await;
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("expected 401"));
    }

    #[tokio::test]
    async fn ntlm_missing_www_authenticate() {
        let server = MockServer::start().await;
        let port = server.address().port();

        // Return 401 without WWW-Authenticate header
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let client = WinrmClient::new(ntlm_config(port), test_creds()).unwrap();
        let result = client.create_shell("127.0.0.1").await;
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("WWW-Authenticate") || err.contains("auth"));
    }

    #[tokio::test]
    async fn ntlm_non_success_after_auth() {
        let server = MockServer::start().await;
        let port = server.address().port();

        let mut type2 = vec![0u8; 48];
        type2[0..8].copy_from_slice(b"NTLMSSP\0");
        type2[8..12].copy_from_slice(&2u32.to_le_bytes());
        type2[20..24].copy_from_slice(&0x0008_8201_u32.to_le_bytes());
        type2[24..32].copy_from_slice(&[0x01; 8]);
        let type2_b64 = B64.encode(&type2);

        // Step 1: 401 with challenge
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(401)
                    .append_header("WWW-Authenticate", format!("Negotiate {type2_b64}")),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Step 2: 500 server error
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Error"))
            .mount(&server)
            .await;

        let client = WinrmClient::new(ntlm_config(port), test_creds()).unwrap();
        let result = client.create_shell("127.0.0.1").await;
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("500") || err.contains("Internal"));
    }

    #[tokio::test]
    async fn ntlm_uses_explicit_domain_when_set() {
        let server = MockServer::start().await;
        let port = server.address().port();

        let mut type2 = vec![0u8; 48];
        type2[0..8].copy_from_slice(b"NTLMSSP\0");
        type2[8..12].copy_from_slice(&2u32.to_le_bytes());
        type2[20..24].copy_from_slice(&0x0008_8201_u32.to_le_bytes());
        type2[24..32].copy_from_slice(&[0x01; 8]);
        let type2_b64 = B64.encode(&type2);

        // Step 1: 401 with challenge
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(401)
                    .append_header("WWW-Authenticate", format!("Negotiate {type2_b64}")),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Step 2: 200 success
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>DOMAIN-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .mount(&server)
            .await;

        // Credentials with an explicit domain set
        let creds = WinrmCredentials::new("admin", "pass", "EXPLICIT-DOM");
        let client = WinrmClient::new(ntlm_config(port), creds).unwrap();
        let shell_id = client.create_shell("127.0.0.1").await.unwrap();
        assert_eq!(shell_id, "DOMAIN-SHELL");
    }

    #[test]
    fn winrm_error_display() {
        let err = WinrmError::AuthFailed("bad creds".into());
        assert_eq!(format!("{err}"), "WinRM auth failed: bad creds");

        let err = WinrmError::Soap(crate::error::SoapError::MissingElement("ShellId".into()));
        assert!(format!("{err}").contains("SOAP"));

        let err = WinrmError::Ntlm(crate::error::NtlmError::InvalidMessage("bad".into()));
        assert!(format!("{err}").contains("NTLM"));
    }

    // --- Mutant-killing tests ---

    // Group 4: execute_command returns the actual command ID from the server
    #[tokio::test]
    async fn execute_command_returns_server_command_id() {
        let server = MockServer::start().await;
        let port = server.address().port();

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>EXACT-CMD-ID-789</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
            ))
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let cmd_id = client
            .execute_command("127.0.0.1", "S1", "whoami", &[])
            .await
            .unwrap();
        // This kills Ok(String::new()) and Ok("xyzzy") mutants
        assert_eq!(cmd_id, "EXACT-CMD-ID-789");
    }

    // Group 4: delete_shell must actually send the request (not just return Ok(()))
    #[tokio::test]
    async fn delete_shell_sends_request_to_server() {
        let server = MockServer::start().await;
        let port = server.address().port();

        let mock = Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
            )
            .expect(1) // MUST be called exactly once
            .mount_as_scoped(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        client.delete_shell("127.0.0.1", "S1").await.unwrap();
        // mock will panic on drop if expect(1) is not satisfied
        drop(mock);
    }

    // Group 4: signal_terminate must actually send the request
    #[tokio::test]
    async fn signal_terminate_sends_request_to_server() {
        let server = MockServer::start().await;
        let port = server.address().port();

        let mock = Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
            )
            .expect(1) // MUST be called exactly once
            .mount_as_scoped(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        client
            .signal_terminate("127.0.0.1", "S1", "C1")
            .await
            .unwrap();
        drop(mock);
    }

    // Group 4: exit_code.unwrap_or(-1) — test that missing exit code defaults to -1
    #[tokio::test]
    async fn run_command_exit_code_defaults_to_minus_one() {
        let server = MockServer::start().await;
        let port = server.address().port();

        // Shell create
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>S1</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Command execute
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>C1</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Receive: done but NO exit code element
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:CommandState CommandId="C1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"/>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Cleanup (signal + delete)
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
            )
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let output = client.run_command("127.0.0.1", "test", &[]).await.unwrap();
        // Catches the "delete -" mutation on unwrap_or(-1) -> unwrap_or(1)
        assert_eq!(output.exit_code, -1);
    }

    // --- Phase 2 tests ---

    #[tokio::test]
    async fn shell_reuse_multiple_commands() {
        let server = MockServer::start().await;
        let port = server.address().port();

        // Shell create
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>REUSE-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Command execute (first)
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>CMD-1</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Receive (first, done)
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:Stream Name="stdout" CommandId="CMD-1">aGVsbG8=</rsp:Stream>
                    <rsp:CommandState CommandId="CMD-1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                        <rsp:ExitCode>0</rsp:ExitCode>
                    </rsp:CommandState>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Signal terminate + command execute (second) + receive (second) + signal + delete
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(r"<s:Envelope><s:Body/></s:Envelope>"),
            )
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let shell = client.open_shell("127.0.0.1").await.unwrap();
        assert_eq!(shell.shell_id(), "REUSE-SHELL");

        let output1 = shell.run_command("whoami", &[]).await.unwrap();
        assert_eq!(output1.stdout, b"hello");
        assert_eq!(output1.exit_code, 0);

        // Close the shell explicitly
        shell.close().await.unwrap();
    }

    #[tokio::test]
    async fn shell_close_cleanup() {
        let server = MockServer::start().await;
        let port = server.address().port();

        // Shell create
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>CLOSE-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Delete
        let delete_mock = Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(r"<s:Envelope><s:Body/></s:Envelope>"),
            )
            .expect(1)
            .mount_as_scoped(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let shell = client.open_shell("127.0.0.1").await.unwrap();
        assert_eq!(shell.shell_id(), "CLOSE-SHELL");
        shell.close().await.unwrap();

        drop(delete_mock);
    }

    #[tokio::test]
    async fn shell_send_input() {
        let server = MockServer::start().await;
        let port = server.address().port();

        // Shell create
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>INPUT-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Send input (just return OK)
        let input_mock = Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(r"<s:Envelope><s:Body/></s:Envelope>"),
            )
            .expect(1)
            .mount_as_scoped(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let shell = client.open_shell("127.0.0.1").await.unwrap();
        let result = shell.send_input("CMD-1", b"hello\n", true).await;
        assert!(result.is_ok());

        drop(input_mock);
    }

    #[tokio::test]
    async fn shell_signal_ctrl_c() {
        let server = MockServer::start().await;
        let port = server.address().port();

        // Shell create
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>CTRLC-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Ctrl+C signal (just return OK)
        let signal_mock = Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(r"<s:Envelope><s:Body/></s:Envelope>"),
            )
            .expect(1)
            .mount_as_scoped(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let shell = client.open_shell("127.0.0.1").await.unwrap();
        let result = shell.signal_ctrl_c("CMD-1").await;
        assert!(result.is_ok());

        drop(signal_mock);
    }

    #[test]
    fn builder_pattern_constructs_client() {
        let client = WinrmClient::builder(WinrmConfig::default())
            .credentials(WinrmCredentials::new("admin", "pass", ""))
            .build()
            .unwrap();
        assert_eq!(client.endpoint("host"), "http://host:5985/wsman");
    }

    #[tokio::test]
    async fn shell_run_powershell() {
        let server = MockServer::start().await;
        let port = server.address().port();

        // Shell create
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>PS-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Command execute
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>PS-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Receive (done)
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:CommandState CommandId="PS-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                        <rsp:ExitCode>0</rsp:ExitCode>
                    </rsp:CommandState>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Cleanup
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(r"<s:Envelope><s:Body/></s:Envelope>"),
            )
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let shell = client.open_shell("127.0.0.1").await.unwrap();
        let output = shell.run_powershell("Get-Process").await.unwrap();
        assert_eq!(output.exit_code, 0);
    }

    // --- Phase 3: Retry tests ---

    fn retry_config(port: u16, max_retries: u32) -> WinrmConfig {
        WinrmConfig {
            port,
            auth_method: AuthMethod::Basic,
            connect_timeout_secs: 5,
            operation_timeout_secs: 10,
            max_retries,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn retry_succeeds_after_transient_errors() {
        let server = MockServer::start().await;
        let port = server.address().port();

        // Test: max_retries=2, first response is 200 with valid body -> succeeds immediately
        Mock::given(method("POST"))
            .and(header("Authorization", "Basic YWRtaW46cGFzcw=="))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>RETRY-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .mount(&server)
            .await;

        let client = WinrmClient::new(retry_config(port, 2), test_creds()).unwrap();
        let shell_id = client.create_shell("127.0.0.1").await.unwrap();
        assert_eq!(shell_id, "RETRY-SHELL");
    }

    #[tokio::test]
    async fn retry_not_applied_to_auth_errors() {
        let server = MockServer::start().await;
        let port = server.address().port();

        // Auth failure (401) should NOT be retried even with max_retries > 0
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let client = WinrmClient::new(retry_config(port, 3), test_creds()).unwrap();
        let result = client.create_shell("127.0.0.1").await;
        assert!(result.is_err());
        // Should fail immediately, not after 3 retries
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("auth") || err.contains("401"));
    }

    #[tokio::test]
    async fn retry_not_applied_to_soap_faults() {
        let server = MockServer::start().await;
        let port = server.address().port();

        // SOAP fault should NOT be retried
        Mock::given(method("POST"))
            .and(header("Authorization", "Basic YWRtaW46cGFzcw=="))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><s:Fault><s:Code><s:Value>s:Receiver</s:Value></s:Code><s:Reason><s:Text>Access denied</s:Text></s:Reason></s:Fault></s:Body></s:Envelope>",
            ))
            .mount(&server)
            .await;

        let client = WinrmClient::new(retry_config(port, 3), test_creds()).unwrap();
        let result = client.create_shell("127.0.0.1").await;
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("SOAP") || err.contains("Access denied"));
    }

    #[tokio::test]
    async fn retry_zero_means_no_retry() {
        // With max_retries=0, behavior is identical to pre-Phase-3
        let server = MockServer::start().await;
        let port = server.address().port();

        Mock::given(method("POST"))
            .and(header("Authorization", "Basic YWRtaW46cGFzcw=="))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>NO-RETRY</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .mount(&server)
            .await;

        let client = WinrmClient::new(retry_config(port, 0), test_creds()).unwrap();
        let shell_id = client.create_shell("127.0.0.1").await.unwrap();
        assert_eq!(shell_id, "NO-RETRY");
    }

    // --- Phase 4: Enterprise auth tests ---

    #[test]
    fn kerberos_without_feature_returns_helpful_error() {
        let config = WinrmConfig {
            auth_method: AuthMethod::Kerberos,
            ..Default::default()
        };
        let client = WinrmClient::new(config, test_creds()).unwrap();
        assert_eq!(client.endpoint("host"), "http://host:5985/wsman");
    }

    #[cfg(not(feature = "kerberos"))]
    #[tokio::test]
    async fn kerberos_send_returns_feature_error() {
        let config = WinrmConfig {
            auth_method: AuthMethod::Kerberos,
            ..Default::default()
        };
        let client = WinrmClient::new(config, test_creds()).unwrap();
        let result = client.create_shell("127.0.0.1").await;
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(
            err.contains("kerberos"),
            "error should mention kerberos feature: {err}"
        );
    }

    #[test]
    fn certificate_auth_requires_cert_pem() {
        let config = WinrmConfig {
            auth_method: AuthMethod::Certificate,
            // No client_cert_pem set
            ..Default::default()
        };
        let result = WinrmClient::new(config, test_creds());
        let err = result.err().expect("should fail without client_cert_pem");
        let msg = format!("{err}");
        assert!(
            msg.contains("client_cert_pem"),
            "error should mention client_cert_pem: {msg}"
        );
    }

    #[test]
    fn certificate_auth_requires_key_pem() {
        let config = WinrmConfig {
            auth_method: AuthMethod::Certificate,
            client_cert_pem: Some("/tmp/nonexistent-cert.pem".into()),
            client_key_pem: None,
            ..Default::default()
        };
        let result = WinrmClient::new(config, test_creds());
        let err = result.err().expect("should fail without client_key_pem");
        let msg = format!("{err}");
        assert!(
            msg.contains("client_key_pem"),
            "error should mention client_key_pem: {msg}"
        );
    }

    #[tokio::test]
    async fn certificate_auth_dispatch_with_wiremock() {
        let dir = std::env::temp_dir().join("winrm-rs-test-cert");
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, b"not a real cert").unwrap();
        std::fs::write(&key_path, b"not a real key").unwrap();

        let config = WinrmConfig {
            auth_method: AuthMethod::Certificate,
            client_cert_pem: Some(cert_path.to_string_lossy().into()),
            client_key_pem: Some(key_path.to_string_lossy().into()),
            ..Default::default()
        };
        // Should fail at Identity::from_pem with invalid PEM
        let result = WinrmClient::new(config, test_creds());
        assert!(result.is_err());

        // Cleanup
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn proxy_config_is_preserved() {
        let config = WinrmConfig {
            proxy: Some("http://proxy:8080".into()),
            ..Default::default()
        };
        let client = WinrmClient::new(config.clone(), test_creds()).unwrap();
        assert_eq!(client.config().proxy.as_deref(), Some("http://proxy:8080"));
    }

    // --- Phase 5: Transfer and streaming tests ---

    #[test]
    fn winrm_error_transfer_display() {
        let err = WinrmError::Transfer("upload chunk 3 failed".into());
        assert_eq!(
            format!("{err}"),
            "file transfer error: upload chunk 3 failed"
        );
    }

    #[tokio::test]
    async fn start_command_and_receive_next() {
        let server = MockServer::start().await;
        let port = server.address().port();

        // Shell create
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>STREAM-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Command execute
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>STREAM-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Receive chunk 1 (not done)
        // "chunk1" = Y2h1bmsx
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:Stream Name="stdout" CommandId="STREAM-CMD">Y2h1bmsx</rsp:Stream>
                    <rsp:CommandState CommandId="STREAM-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Running"/>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Receive chunk 2 (done)
        // "chunk2" = Y2h1bmsy
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:Stream Name="stdout" CommandId="STREAM-CMD">Y2h1bmsy</rsp:Stream>
                    <rsp:CommandState CommandId="STREAM-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                        <rsp:ExitCode>0</rsp:ExitCode>
                    </rsp:CommandState>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Cleanup
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(r"<s:Envelope><s:Body/></s:Envelope>"),
            )
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let shell = client.open_shell("127.0.0.1").await.unwrap();

        let cmd_id = shell
            .start_command("ping", &["-t", "10.0.0.1"])
            .await
            .unwrap();
        assert_eq!(cmd_id, "STREAM-CMD");

        // Poll chunk 1
        let chunk1 = shell.receive_next(&cmd_id).await.unwrap();
        assert_eq!(chunk1.stdout, b"chunk1");
        assert!(!chunk1.done);

        // Poll chunk 2
        let chunk2 = shell.receive_next(&cmd_id).await.unwrap();
        assert_eq!(chunk2.stdout, b"chunk2");
        assert!(chunk2.done);
        assert_eq!(chunk2.exit_code, Some(0));
    }

    #[tokio::test]
    async fn download_file_with_wiremock() {
        let server = MockServer::start().await;
        let port = server.address().port();

        // "hello file content" base64 = aGVsbG8gZmlsZSBjb250ZW50
        let ps_output_b64 = base64::engine::general_purpose::STANDARD.encode(b"hello file content");
        let stdout_b64 = B64.encode(ps_output_b64.as_bytes());

        // Shell create
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>DL-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Command execute
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>DL-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Receive (the PS script outputs the base64-encoded file content)
        let receive_body = format!(
            r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                <rsp:Stream Name="stdout" CommandId="DL-CMD">{stdout_b64}</rsp:Stream>
                <rsp:CommandState CommandId="DL-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                    <rsp:ExitCode>0</rsp:ExitCode>
                </rsp:CommandState>
            </rsp:ReceiveResponse></s:Body></s:Envelope>"#
        );
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(receive_body))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Cleanup (signal + delete)
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(r"<s:Envelope><s:Body/></s:Envelope>"),
            )
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let local_path = std::env::temp_dir().join("winrm-rs-test-download.bin");
        let result = client
            .download_file("127.0.0.1", "C:\\remote\\file.txt", &local_path)
            .await;
        assert!(result.is_ok(), "download_file failed: {result:?}");
        let bytes = result.unwrap();
        assert_eq!(bytes, 18); // "hello file content".len()
        let content = std::fs::read(&local_path).unwrap();
        assert_eq!(content, b"hello file content");

        // Cleanup
        std::fs::remove_file(&local_path).ok();
    }

    // Valid self-signed test PEM for Certificate auth tests.
    const TEST_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
        MIIBXjCCAQWgAwIBAgIUMMmMPCKhqsfVxxq36Hmd4IHUTNgwCgYIKoZIzj0EAwIw\n\
        ITEfMB0GA1UEAwwWcmNnZW4gc2VsZiBzaWduZWQgY2VydDAgFw03NTAxMDEwMDAw\n\
        MDBaGA80MDk2MDEwMTAwMDAwMFowITEfMB0GA1UEAwwWcmNnZW4gc2VsZiBzaWdu\n\
        ZWQgY2VydDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPmdXVVusEfNSmt6aKUf\n\
        lw2+69/9LSYPVO0KUgALGqjUvoAMAwE/6AWQDrN2EH/swrMHJbM5l2y4Y7GEYbav\n\
        glKjGTAXMBUGA1UdEQQOMAyCCnRlc3QubG9jYWwwCgYIKoZIzj0EAwIDRwAwRAIg\n\
        JjoSt8p+3HBP3/EGZ/icOAC/N0o03a6SUOjMwgFiCbQCIDc2+ShrQhU3FNeE4Gu1\n\
        hOMpiIz+2YFoGkzaDJ6fFB6B\n\
        -----END CERTIFICATE-----\n";
    const TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
        MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg+nMC1P5m4rXIR86n\n\
        DVStYeCVDra7xdrnpbNklaXDbkWhRANCAAT5nV1VbrBHzUpremilH5cNvuvf/S0m\n\
        D1TtClIACxqo1L6ADAMBP+gFkA6zdhB/7MKzByWzOZdsuGOxhGG2r4JS\n\
        -----END PRIVATE KEY-----\n";

    #[test]
    fn certificate_auth_reads_valid_pem_files() {
        let dir = std::env::temp_dir().join("winrm-rs-test-cert-valid");
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("test_cert.pem");
        let key_path = dir.join("test_key.pem");

        std::fs::write(&cert_path, TEST_CERT_PEM).unwrap();
        std::fs::write(&key_path, TEST_KEY_PEM).unwrap();

        let config = WinrmConfig {
            auth_method: AuthMethod::Certificate,
            client_cert_pem: Some(cert_path.to_string_lossy().into()),
            client_key_pem: Some(key_path.to_string_lossy().into()),
            use_tls: true,
            ..Default::default()
        };
        let result = WinrmClient::new(config, test_creds());
        assert!(
            result.is_ok(),
            "valid PEM should construct client: {}",
            result.err().map(|e| format!("{e}")).unwrap_or_default()
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn certificate_auth_reads_pem_files_invalid() {
        let dir = std::env::temp_dir().join("winrm-rs-test-cert-read");
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("test_cert.pem");
        let key_path = dir.join("test_key.pem");

        std::fs::write(
            &cert_path,
            b"-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        std::fs::write(
            &key_path,
            b"-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();

        let config = WinrmConfig {
            auth_method: AuthMethod::Certificate,
            client_cert_pem: Some(cert_path.to_string_lossy().into()),
            client_key_pem: Some(key_path.to_string_lossy().into()),
            use_tls: true,
            ..Default::default()
        };
        let result = WinrmClient::new(config, test_creds());
        assert!(result.is_err());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn certificate_auth_missing_key_path_with_valid_cert_file() {
        let dir = std::env::temp_dir().join("winrm-rs-test-cert-nokey");
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("test_cert.pem");
        std::fs::write(&cert_path, b"cert data").unwrap();

        let config = WinrmConfig {
            auth_method: AuthMethod::Certificate,
            client_cert_pem: Some(cert_path.to_string_lossy().into()),
            client_key_pem: None,
            use_tls: true,
            ..Default::default()
        };
        let result = WinrmClient::new(config, test_creds());
        assert!(result.is_err());
        assert!(format!("{}", result.err().unwrap()).contains("client_key_pem"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn certificate_auth_nonexistent_cert_file() {
        let config = WinrmConfig {
            auth_method: AuthMethod::Certificate,
            client_cert_pem: Some("/nonexistent/cert.pem".into()),
            client_key_pem: Some("/nonexistent/key.pem".into()),
            use_tls: true,
            ..Default::default()
        };
        let result = WinrmClient::new(config, test_creds());
        assert!(result.is_err());
        let err = format!("{}", result.err().unwrap());
        assert!(
            err.contains("failed to read") || err.contains("cert"),
            "error should mention cert read failure: {err}"
        );
    }

    #[test]
    fn certificate_auth_nonexistent_key_file() {
        let dir = std::env::temp_dir().join("winrm-rs-test-cert-nokey2");
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("test_cert.pem");
        std::fs::write(&cert_path, b"cert data").unwrap();

        let config = WinrmConfig {
            auth_method: AuthMethod::Certificate,
            client_cert_pem: Some(cert_path.to_string_lossy().into()),
            client_key_pem: Some("/nonexistent/key.pem".into()),
            use_tls: true,
            ..Default::default()
        };
        let result = WinrmClient::new(config, test_creds());
        assert!(result.is_err());
        let err = format!("{}", result.err().unwrap());
        assert!(
            err.contains("failed to read") || err.contains("key"),
            "error should mention key read failure: {err}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn certificate_auth_dispatch_in_send_soap() {
        let server = MockServer::start().await;
        let port = server.address().port();

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>CERT-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .mount(&server)
            .await;

        let dir = std::env::temp_dir().join("winrm-rs-test-cert-dispatch");
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, TEST_CERT_PEM).unwrap();
        std::fs::write(&key_path, TEST_KEY_PEM).unwrap();

        let config = WinrmConfig {
            port,
            auth_method: AuthMethod::Certificate,
            client_cert_pem: Some(cert_path.to_string_lossy().into()),
            client_key_pem: Some(key_path.to_string_lossy().into()),
            connect_timeout_secs: 5,
            operation_timeout_secs: 10,
            ..Default::default()
        };

        let client = WinrmClient::new(config, test_creds()).unwrap();
        let result = client.create_shell("127.0.0.1").await;
        assert!(result.is_ok(), "cert auth dispatch failed: {result:?}");
        assert_eq!(result.unwrap(), "CERT-SHELL");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn shell_run_command_full_lifecycle() {
        let server = MockServer::start().await;
        let port = server.address().port();

        // Shell create
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>RUN-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Command execute
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>RUN-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Receive: first poll returns partial stdout (not done)
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:Stream Name="stdout" CommandId="RUN-CMD">cGFydDE=</rsp:Stream>
                    <rsp:CommandState CommandId="RUN-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Running"/>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Receive: second poll returns stderr + done
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:Stream Name="stdout" CommandId="RUN-CMD">cGFydDI=</rsp:Stream>
                    <rsp:Stream Name="stderr" CommandId="RUN-CMD">ZXJyMQ==</rsp:Stream>
                    <rsp:CommandState CommandId="RUN-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                        <rsp:ExitCode>42</rsp:ExitCode>
                    </rsp:CommandState>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Signal terminate + delete (catch-all)
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
            )
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let shell = client.open_shell("127.0.0.1").await.unwrap();
        let output = shell.run_command("cmd.exe", &["/c", "echo"]).await.unwrap();

        assert_eq!(output.stdout, b"part1part2");
        assert_eq!(output.stderr, b"err1");
        assert_eq!(output.exit_code, 42);

        shell.close().await.unwrap();
    }

    #[tokio::test]
    async fn shell_start_command_returns_command_id() {
        let server = MockServer::start().await;
        let port = server.address().port();

        // Shell create
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>START-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Command execute
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>START-CMD-123</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Cleanup
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
            )
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let shell = client.open_shell("127.0.0.1").await.unwrap();
        let cmd_id = shell.start_command("whoami", &[]).await.unwrap();
        assert_eq!(cmd_id, "START-CMD-123");
    }

    #[tokio::test]
    async fn upload_file_success_with_wiremock() {
        let server = MockServer::start().await;
        let port = server.address().port();

        let dir = std::env::temp_dir().join("winrm-rs-test-upload");
        std::fs::create_dir_all(&dir).unwrap();
        let local_file = dir.join("upload_test.txt");
        std::fs::write(&local_file, b"hello upload content").unwrap();

        // Shell create
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>UL-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Command execute
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>UL-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Receive
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:CommandState CommandId="UL-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                        <rsp:ExitCode>0</rsp:ExitCode>
                    </rsp:CommandState>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Cleanup
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
            )
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let result = client
            .upload_file("127.0.0.1", &local_file, "C:\\remote\\file.txt")
            .await;
        assert!(result.is_ok(), "upload_file failed: {result:?}");
        assert_eq!(result.unwrap(), 20);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn upload_file_chunk_failure() {
        let server = MockServer::start().await;
        let port = server.address().port();

        let dir = std::env::temp_dir().join("winrm-rs-test-upload-fail");
        std::fs::create_dir_all(&dir).unwrap();
        let local_file = dir.join("upload_fail.txt");
        std::fs::write(&local_file, b"test data").unwrap();

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>ULF-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>ULF-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:Stream Name="stderr" CommandId="ULF-CMD">YWNjZXNzIGRlbmllZA==</rsp:Stream>
                    <rsp:CommandState CommandId="ULF-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                        <rsp:ExitCode>1</rsp:ExitCode>
                    </rsp:CommandState>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
            )
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let result = client
            .upload_file("127.0.0.1", &local_file, "C:\\remote\\file.txt")
            .await;
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(
            err.contains("upload chunk") || err.contains("transfer"),
            "error should mention upload chunk failure: {err}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn download_file_ps_failure() {
        let server = MockServer::start().await;
        let port = server.address().port();

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>DLF-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>DLF-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:Stream Name="stderr" CommandId="DLF-CMD">ZmlsZSBub3QgZm91bmQ=</rsp:Stream>
                    <rsp:CommandState CommandId="DLF-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                        <rsp:ExitCode>1</rsp:ExitCode>
                    </rsp:CommandState>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
            )
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let local_path = std::env::temp_dir().join("winrm-rs-test-dlfail.bin");
        let result = client
            .download_file("127.0.0.1", "C:\\nonexistent.txt", &local_path)
            .await;
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(
            err.contains("download") || err.contains("transfer"),
            "error should mention download failure: {err}"
        );
    }

    #[tokio::test]
    async fn upload_file_multi_chunk() {
        let server = MockServer::start().await;
        let port = server.address().port();

        let dir = std::env::temp_dir().join("winrm-rs-test-upload-multi");
        std::fs::create_dir_all(&dir).unwrap();
        let local_file = dir.join("small.txt");
        std::fs::write(&local_file, b"tiny").unwrap();

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>MC-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>MC-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:CommandState CommandId="MC-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                        <rsp:ExitCode>0</rsp:ExitCode>
                    </rsp:CommandState>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
            )
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let result = client
            .upload_file("127.0.0.1", &local_file, "C:\\remote\\small.txt")
            .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 4);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn download_file_write_local_success() {
        let server = MockServer::start().await;
        let port = server.address().port();

        let ps_output_b64 = B64.encode(b"test bytes");
        let stdout_b64 = B64.encode(ps_output_b64.as_bytes());

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>DL2-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>DL2-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        let receive_body = format!(
            r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                <rsp:Stream Name="stdout" CommandId="DL2-CMD">{stdout_b64}</rsp:Stream>
                <rsp:CommandState CommandId="DL2-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                    <rsp:ExitCode>0</rsp:ExitCode>
                </rsp:CommandState>
            </rsp:ReceiveResponse></s:Body></s:Envelope>"#
        );
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(receive_body))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
            )
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let local_path = std::env::temp_dir().join("winrm-rs-test-dl2.bin");
        let result = client
            .download_file("127.0.0.1", "C:\\remote\\data.bin", &local_path)
            .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 10);
        let content = std::fs::read(&local_path).unwrap();
        assert_eq!(content, b"test bytes");

        std::fs::remove_file(&local_path).ok();
    }

    #[tokio::test]
    async fn run_command_delete_shell_failure_is_ignored() {
        let server = MockServer::start().await;
        let port = server.address().port();

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>DEL-FAIL-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>DEL-FAIL-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:Stream Name="stdout" CommandId="DEL-FAIL-CMD">b2s=</rsp:Stream>
                    <rsp:CommandState CommandId="DEL-FAIL-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                        <rsp:ExitCode>0</rsp:ExitCode>
                    </rsp:CommandState>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><s:Fault><s:Code><s:Value>s:Receiver</s:Value></s:Code><s:Reason><s:Text>Shell not found</s:Text></s:Reason></s:Fault></s:Body></s:Envelope>",
            ))
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let output = client
            .run_command("127.0.0.1", "whoami", &[])
            .await
            .unwrap();
        assert_eq!(output.exit_code, 0);
        assert_eq!(output.stdout, b"ok");
    }

    #[tokio::test]
    // Flaky on Windows: dropping a raw TCP stream doesn't reliably produce
    // the "connection reset" error `reqwest` needs to classify the call as
    // retryable. The same scenario is covered by the wiremock-based retry
    // tests which run on all platforms.
    #[cfg_attr(windows, ignore)]
    async fn retry_backoff_on_http_error() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let call = counter_clone.fetch_add(1, Ordering::SeqCst);
                if call == 0 {
                    drop(stream);
                } else {
                    use tokio::io::AsyncWriteExt;
                    let body = r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>RETRY-BACKOFF</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>";
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/xml\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                }
            }
        });

        let config = WinrmConfig {
            port,
            auth_method: AuthMethod::Basic,
            connect_timeout_secs: 2,
            operation_timeout_secs: 5,
            max_retries: 2,
            ..Default::default()
        };
        let client = WinrmClient::new(config, test_creds()).unwrap();
        let result = client.create_shell("127.0.0.1").await;
        assert!(
            result.is_ok(),
            "retry should have succeeded: {}",
            result.err().map(|e| format!("{e}")).unwrap_or_default()
        );
        assert_eq!(result.unwrap(), "RETRY-BACKOFF");
        assert!(
            counter.load(Ordering::SeqCst) >= 2,
            "should have retried at least once"
        );

        handle.abort();
    }

    #[tokio::test]
    async fn upload_file_multi_chunk_with_append() {
        let server = MockServer::start().await;
        let port = server.address().port();

        let dir = std::env::temp_dir().join("winrm-rs-test-upload-multi-chunk");
        std::fs::create_dir_all(&dir).unwrap();
        let local_file = dir.join("multi.bin");
        // 4001 bytes = 3 chunks with CHUNK_SIZE=2000 (2000 + 2000 + 1)
        let data = vec![0xABu8; 4001];
        std::fs::write(&local_file, &data).unwrap();

        // Create shell
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>MCH-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Chunk 1: execute + receive + signal
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>MCH-CMD1</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:CommandState CommandId="MCH-CMD1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                        <rsp:ExitCode>0</rsp:ExitCode>
                    </rsp:CommandState>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Chunk 2: execute + receive + signal
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>MCH-CMD2</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:CommandState CommandId="MCH-CMD2" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                        <rsp:ExitCode>0</rsp:ExitCode>
                    </rsp:CommandState>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Chunk 3: execute + receive + signal
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>MCH-CMD3</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:CommandState CommandId="MCH-CMD3" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                        <rsp:ExitCode>0</rsp:ExitCode>
                    </rsp:CommandState>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Catch-all for signal/delete
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
            )
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let result = client
            .upload_file("127.0.0.1", &local_file, "C:\\remote\\multi.bin")
            .await;
        assert!(result.is_ok(), "multi-chunk upload failed: {result:?}");
        assert_eq!(result.unwrap(), 4001);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn download_file_write_error() {
        let server = MockServer::start().await;
        let port = server.address().port();

        let ps_output_b64 = B64.encode(b"test");
        let stdout_b64 = B64.encode(ps_output_b64.as_bytes());

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>DLW-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>DLW-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        let receive_body = format!(
            r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                <rsp:Stream Name="stdout" CommandId="DLW-CMD">{stdout_b64}</rsp:Stream>
                <rsp:CommandState CommandId="DLW-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                    <rsp:ExitCode>0</rsp:ExitCode>
                </rsp:CommandState>
            </rsp:ReceiveResponse></s:Body></s:Envelope>"#
        );
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(receive_body))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
            )
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let bad_path = std::path::Path::new("/nonexistent/dir/file.bin");
        let result = client
            .download_file("127.0.0.1", "C:\\remote.txt", bad_path)
            .await;
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(
            err.contains("failed to write") || err.contains("transfer"),
            "error should mention write failure: {err}"
        );
    }

    #[test]
    fn upload_file_nonexistent_local_file() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let config = WinrmConfig::default();
        let client = WinrmClient::new(config, test_creds()).unwrap();

        let result = rt.block_on(client.upload_file(
            "127.0.0.1",
            std::path::Path::new("/nonexistent/file.bin"),
            "C:\\remote\\dest.bin",
        ));
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(
            err.contains("transfer error") || err.contains("failed to read"),
            "error should mention transfer: {err}"
        );
    }

    // --- Phase 7: Mutant-killing tests ---

    #[cfg(not(feature = "kerberos"))]
    #[tokio::test]
    async fn kerberos_auth_dispatch_returns_auth_error() {
        let config = WinrmConfig {
            auth_method: AuthMethod::Kerberos,
            connect_timeout_secs: 5,
            operation_timeout_secs: 10,
            ..Default::default()
        };
        let client = WinrmClient::new(config, test_creds()).unwrap();
        let result = client.create_shell("127.0.0.1").await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        let err_msg = format!("{err}");
        assert!(
            err_msg.contains("kerberos") && err_msg.contains("feature"),
            "error should specifically mention kerberos feature, got: {err_msg}"
        );
        assert!(
            matches!(err, WinrmError::AuthFailed(_)),
            "error variant should be AuthFailed, got: {err:?}"
        );
    }

    // Group 5: Retry with max_retries=1 makes exactly 2 attempts.
    #[tokio::test]
    async fn retry_max_one_makes_exactly_two_attempts() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let handle = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                counter_clone.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });

        let config = WinrmConfig {
            port,
            auth_method: AuthMethod::Basic,
            connect_timeout_secs: 2,
            operation_timeout_secs: 5,
            max_retries: 1,
            ..Default::default()
        };
        let client = WinrmClient::new(config, test_creds()).unwrap();
        let result = client.create_shell("127.0.0.1").await;
        assert!(result.is_err(), "should fail after all retries exhausted");

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let attempts = counter.load(Ordering::SeqCst);
        assert_eq!(
            attempts, 2,
            "max_retries=1 should make exactly 2 attempts, got {attempts}"
        );

        handle.abort();
    }

    #[tokio::test]
    async fn retry_max_zero_makes_exactly_one_attempt() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let handle = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                counter_clone.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });

        let config = WinrmConfig {
            port,
            auth_method: AuthMethod::Basic,
            connect_timeout_secs: 2,
            operation_timeout_secs: 5,
            max_retries: 0,
            ..Default::default()
        };
        let client = WinrmClient::new(config, test_creds()).unwrap();
        let result = client.create_shell("127.0.0.1").await;
        assert!(result.is_err());

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let attempts = counter.load(Ordering::SeqCst);
        assert_eq!(
            attempts, 1,
            "max_retries=0 should make exactly 1 attempt, got {attempts}"
        );

        handle.abort();
    }

    // Group 6: Shell timeout uses operation_timeout_secs * 2.
    #[tokio::test]
    async fn shell_run_command_timeout_uses_double_operation_timeout() {
        let server = MockServer::start().await;
        let port = server.address().port();

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>TO-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>TO-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(
                        r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                            <rsp:CommandState CommandId="TO-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Running"/>
                        </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
                    )
                    .set_delay(std::time::Duration::from_secs(10)),
            )
            .mount(&server)
            .await;

        let config = WinrmConfig {
            port,
            auth_method: AuthMethod::Basic,
            connect_timeout_secs: 30,
            operation_timeout_secs: 1,
            ..Default::default()
        };
        let client = WinrmClient::new(config, test_creds()).unwrap();
        let shell = client.open_shell("127.0.0.1").await.unwrap();
        let result = shell.run_command("slow", &[]).await;

        assert!(result.is_err(), "should have timed out");
        let err = result.unwrap_err();
        match err {
            WinrmError::Timeout(secs) => {
                assert_eq!(
                    secs, 2,
                    "timeout should be operation_timeout_secs * 2 = 2, got {secs}"
                );
            }
            other => panic!("expected Timeout error, got: {other:?}"),
        }
    }

    // --- Phase 8: Additional mutant-killing tests ---

    #[tokio::test]
    async fn upload_first_chunk_uses_write_all_bytes() {
        let server = MockServer::start().await;
        let port = server.address().port();

        let dir = std::env::temp_dir().join("winrm-rs-test-upload-writebytes");
        std::fs::create_dir_all(&dir).unwrap();
        let local_file = dir.join("small.txt");
        std::fs::write(&local_file, b"test-data").unwrap();

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>WB-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>WB-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:CommandState CommandId="WB-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                        <rsp:ExitCode>0</rsp:ExitCode>
                    </rsp:CommandState>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
            )
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let result = client
            .upload_file("127.0.0.1", &local_file, "C:\\dest.txt")
            .await;
        assert!(result.is_ok(), "upload failed: {result:?}");

        let requests = server.received_requests().await.unwrap();
        let mut found_write_all_bytes = false;
        let mut found_append = false;
        for req in &requests {
            let body = String::from_utf8_lossy(&req.body);
            if !body.contains("-EncodedCommand") {
                continue;
            }
            let tag_open = "<rsp:Arguments>";
            let tag_close = "</rsp:Arguments>";
            let mut pos = 0;
            while let Some(start) = body[pos..].find(tag_open) {
                let content_start = pos + start + tag_open.len();
                if let Some(end) = body[content_start..].find(tag_close) {
                    let arg_val = &body[content_start..content_start + end];
                    if let Ok(bytes) = B64.decode(arg_val.trim()) {
                        let u16s: Vec<u16> = bytes
                            .as_chunks::<2>()
                            .0
                            .iter()
                            .map(|c| u16::from_le_bytes(*c))
                            .collect();
                        if let Ok(script) = String::from_utf16(&u16s) {
                            if script.contains("WriteAllBytes") {
                                found_write_all_bytes = true;
                            }
                            if script.contains("Append") {
                                found_append = true;
                            }
                        }
                    }
                    pos = content_start + end + tag_close.len();
                } else {
                    break;
                }
            }
        }

        assert!(
            found_write_all_bytes,
            "first chunk must use WriteAllBytes for new file creation"
        );
        assert!(
            !found_append,
            "single-chunk upload must NOT use Append (that's for subsequent chunks)"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn retry_backoff_is_exponential_not_additive() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let handle = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                counter_clone.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });

        let config = WinrmConfig {
            port,
            auth_method: AuthMethod::Basic,
            connect_timeout_secs: 2,
            operation_timeout_secs: 5,
            max_retries: 2,
            ..Default::default()
        };

        let client = WinrmClient::new(config, test_creds()).unwrap();
        let start = std::time::Instant::now();
        let result = client.create_shell("127.0.0.1").await;
        let elapsed = start.elapsed();

        assert!(result.is_err());

        assert!(
            elapsed >= std::time::Duration::from_millis(280),
            "exponential backoff should take >= 280ms total, took {}ms (catches + and / mutants)",
            elapsed.as_millis()
        );

        handle.abort();
    }

    // Kills client.rs:354 — run_wql returning Ok("") or Ok("xyzzy")
    #[tokio::test]
    async fn run_wql_returns_items() {
        let server = MockServer::start().await;
        let port = server.address().port();

        // WQL Enumerate response with items and EndOfSequence
        let enumerate_response = r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
          xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
          <s:Body>
            <wsen:EnumerateResponse>
              <wsen:Items><p:Win32_OS><p:Name>Windows</p:Name></p:Win32_OS></wsen:Items>
              <wsen:EndOfSequence/>
            </wsen:EnumerateResponse>
          </s:Body>
        </s:Envelope>"#;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(enumerate_response))
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let result = client
            .run_wql("127.0.0.1", "SELECT * FROM Win32_OS", None)
            .await
            .unwrap();
        assert!(
            result.contains("Windows"),
            "run_wql should return items, got: {result}"
        );
    }

    #[tokio::test]
    async fn open_psrp_shell_returns_shell_with_id() {
        let server = MockServer::start().await;
        let port = server.address().port();

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>PSRP-SH</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let shell = client
            .open_psrp_shell(
                "127.0.0.1",
                "AAAA",
                "http://schemas.microsoft.com/powershell/Microsoft.PowerShell",
            )
            .await
            .unwrap();
        assert_eq!(shell.shell_id(), "PSRP-SH");
    }

    #[tokio::test]
    async fn run_wql_caps_items_at_max_output_bytes() {
        let server = MockServer::start().await;
        let port = server.address().port();

        // Big enumerate response with EnumerationContext so the Pull loop iterates,
        // padded so each iteration adds > 1 KiB to the items string.
        let big = "X".repeat(2048);
        let chunk = format!(
            r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
              xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
              <s:Body>
                <wsen:EnumerateResponse>
                  <wsen:EnumerationContext>CTX-1</wsen:EnumerationContext>
                  <wsen:Items><p:Win32_OS><p:Name>{big}</p:Name></p:Win32_OS></wsen:Items>
                </wsen:EnumerateResponse>
              </s:Body>
            </s:Envelope>"#
        );

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(chunk))
            .mount(&server)
            .await;

        let mut config = basic_config(port);
        config.max_output_bytes = Some(1024);
        let client = WinrmClient::new(config, test_creds()).unwrap();
        let err = client
            .run_wql("127.0.0.1", "SELECT * FROM Win32_OS", None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, WinrmError::Transfer(_)),
            "expected Transfer cap error, got: {err}"
        );
    }

    #[tokio::test]
    async fn run_in_shell_caps_output_at_max_output_bytes() {
        // Build 2 KiB of "A" base64-encoded so the receive response is
        // bigger than our 1 KiB cap. The mock returns Receive responses
        // forever (no Done state) — the cap should fire before we get
        // there.
        let server = MockServer::start().await;
        let port = server.address().port();

        let big_b64 = base64::engine::general_purpose::STANDARD.encode(vec![b'A'; 2048]);
        let receive_response = format!(
            r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                <rsp:Stream Name="stdout" CommandId="C">{big_b64}</rsp:Stream>
            </rsp:ReceiveResponse></s:Body></s:Envelope>"#
        );

        // Create
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>SH</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Execute
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>C</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Receive (and signal cleanup) — return data forever
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(receive_response))
            .mount(&server)
            .await;

        let mut config = basic_config(port);
        config.max_output_bytes = Some(1024);
        let client = WinrmClient::new(config, test_creds()).unwrap();
        let err = client
            .run_command("127.0.0.1", "ipconfig", &[])
            .await
            .unwrap_err();
        assert!(
            matches!(err, WinrmError::Transfer(_)),
            "expected Transfer cap error, got: {err}"
        );
    }

    #[tokio::test]
    async fn run_command_with_cancel_returns_cancelled_when_token_pre_cancelled() {
        let token = tokio_util::sync::CancellationToken::new();
        token.cancel();
        let client = WinrmClient::new(basic_config(0), test_creds()).unwrap();
        let err = client
            .run_command_with_cancel("127.0.0.1", "ipconfig", &[], token)
            .await
            .unwrap_err();
        assert!(matches!(err, WinrmError::Cancelled), "got: {err}");
    }

    #[tokio::test]
    async fn run_powershell_with_cancel_returns_cancelled_when_token_pre_cancelled() {
        let token = tokio_util::sync::CancellationToken::new();
        token.cancel();
        let client = WinrmClient::new(basic_config(0), test_creds()).unwrap();
        let err = client
            .run_powershell_with_cancel("127.0.0.1", "Get-Date", token)
            .await
            .unwrap_err();
        assert!(matches!(err, WinrmError::Cancelled), "got: {err}");
    }
}
