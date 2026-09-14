//! SOAP envelope builders for WS-Management shell lifecycle operations.

use std::fmt::Write;

use uuid::Uuid;

use super::namespaces::*;

/// Escape special XML characters to prevent injection in SOAP envelopes.
pub(crate) fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// XML namespace declarations used in envelopes that include the shell namespace.
const NS_DECL_WITH_RSP: &str = r#"xmlns:s="http://www.w3.org/2003/05/soap-envelope"
  xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
  xmlns:wsmv="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"
  xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell""#;

/// XML namespace declarations without the shell namespace (used by Delete).
const NS_DECL_NO_RSP: &str = r#"xmlns:s="http://www.w3.org/2003/05/soap-envelope"
  xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
  xmlns:wsmv="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd""#;

/// Stamp the client's `wsmv:SessionId` header (MS-WSMV 2.2.4.x) into a
/// built envelope.
///
/// Windows binds a shell to the session that created it: a Create without
/// this header yields a shell that refuses Disconnect/Reconnect ("created by
/// an older WinRS client"), and once a Create carried it, every later request
/// on that shell must carry the same value or the server answers 0x8033810F
/// (`does not contain a valid SessionID element`). The transport therefore
/// stamps every outgoing envelope with its own id, here, instead of threading
/// the value through every builder. Envelopes without a `</s:Header>` (raw
/// caller bodies) are returned unchanged.
pub(crate) fn with_session_id(envelope: &str, session_id: &str) -> String {
    let element = format!(
        "\n    <wsmv:SessionId s:mustUnderstand=\"false\">{}</wsmv:SessionId>\n  </s:Header>",
        xml_escape(session_id)
    );
    envelope.replacen("</s:Header>", &element, 1)
}

/// Build the common SOAP envelope header.
///
/// Most WS-Management operations share the same header structure.
/// This helper avoids duplicating ~15 lines of XML across 7+ functions.
fn build_header(
    endpoint: &str,
    action: &str,
    shell_id: Option<&str>,
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    build_header_for(
        endpoint,
        action,
        RESOURCE_URI_CMD,
        shell_id,
        timeout_secs,
        max_envelope_size,
    )
}

fn build_header_for(
    endpoint: &str,
    action: &str,
    resource_uri: &str,
    shell_id: Option<&str>,
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    let message_id = Uuid::new_v4();
    let selector = if let Some(sid) = shell_id {
        let escaped_sid = xml_escape(sid);
        format!(
            r#"
    <wsman:SelectorSet>
      <wsman:Selector Name="ShellId">{escaped_sid}</wsman:Selector>
    </wsman:SelectorSet>"#
        )
    } else {
        String::new()
    };
    let escaped_endpoint = xml_escape(endpoint);
    // The resource URI is caller-influenced: `run_wql` splices the WMI
    // namespace into it and the PSRP builders take a configuration name.
    // Escape it like every other interpolated value.
    let escaped_resource_uri = xml_escape(resource_uri);
    format!(
        r#"  <s:Header>
    <wsa:To>{escaped_endpoint}</wsa:To>
    <wsman:ResourceURI s:mustUnderstand="true">{escaped_resource_uri}</wsman:ResourceURI>
    <wsa:ReplyTo>
      <wsa:Address s:mustUnderstand="true">{REPLY_TO_ANONYMOUS}</wsa:Address>
    </wsa:ReplyTo>
    <wsa:Action s:mustUnderstand="true">{action}</wsa:Action>
    <wsman:MaxEnvelopeSize s:mustUnderstand="true">{max_envelope_size}</wsman:MaxEnvelopeSize>
    <wsa:MessageID>uuid:{message_id}</wsa:MessageID>
    <wsman:Locale xml:lang="en-US" s:mustUnderstand="false"/>
    <wsman:OperationTimeout>PT{timeout_secs}S</wsman:OperationTimeout>{selector}
  </s:Header>"#
    )
}

/// Build a WS-Management Create Shell SOAP envelope (MS-WSMV 3.1.4.1).
///
/// The returned XML creates a `cmd` shell with configurable codepage, optional
/// working directory, environment variables, and idle timeout. Each request gets
/// a unique `MessageID` (UUID v4).
///
/// # Arguments
/// * `endpoint` -- full WinRM URL, e.g. `http://host:5985/wsman`
/// * `config` -- WinRM configuration containing shell options
pub(crate) fn create_shell_request(endpoint: &str, config: &crate::config::WinrmConfig) -> String {
    let header = build_header(
        endpoint,
        ACTION_CREATE,
        None,
        config.operation_timeout_secs,
        config.max_envelope_size,
    );

    let codepage = config.codepage;

    let working_dir = config
        .working_directory
        .as_deref()
        .map(|dir| {
            format!(
                "\n      <rsp:WorkingDirectory>{}</rsp:WorkingDirectory>",
                xml_escape(dir)
            )
        })
        .unwrap_or_default();

    let env_block = if config.env_vars.is_empty() {
        String::new()
    } else {
        let mut buf = String::from("\n      <rsp:Environment>");
        for (key, val) in &config.env_vars {
            let _ = write!(
                buf,
                "\n        <rsp:Variable Name=\"{}\">{}</rsp:Variable>",
                xml_escape(key),
                xml_escape(val),
            );
        }
        buf.push_str("\n      </rsp:Environment>");
        buf
    };

    let idle_timeout = config
        .idle_timeout_secs
        .map(|secs| format!("\n      <rsp:IdleTimeOut>PT{secs}S</rsp:IdleTimeOut>"))
        .unwrap_or_default();

    // `header` ends with `</s:Header>` — the OptionSet must be INSIDE it
    // (SOAP 1.2 Envelope = Header? + Body only). Previously it was emitted
    // between </s:Header> and <s:Body>, producing an invalid envelope that
    // strict WinRM servers reject with HTTP 500 after NTLM auth.
    let header_with_options = header.replace(
        "</s:Header>",
        &format!(
            r#"
    <wsman:OptionSet xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <wsman:Option Name="WINRS_NOPROFILE">TRUE</wsman:Option>
      <wsman:Option Name="WINRS_CODEPAGE">{codepage}</wsman:Option>
    </wsman:OptionSet>
  </s:Header>"#
        ),
    );
    format!(
        r#"<s:Envelope {NS_DECL_WITH_RSP}>
{header_with_options}
  <s:Body>
    <rsp:Shell>
      <rsp:InputStreams>stdin</rsp:InputStreams>
      <rsp:OutputStreams>stdout stderr</rsp:OutputStreams>{working_dir}{env_block}{idle_timeout}
    </rsp:Shell>
  </s:Body>
</s:Envelope>"#
    )
}

/// Build a WS-Management Create Shell envelope for **PSRP** (PowerShell
/// Remoting Protocol).
///
/// The key differences from `create_shell_request` (used for CMD shells):
/// * Resource URI is `http://schemas.microsoft.com/powershell/Microsoft.PowerShell`
///   (or a custom configuration endpoint).
/// * The body contains `<creationXml>` with base64-encoded PSRP opening
///   fragments (SessionCapability + InitRunspacePool).
/// * Streams are `stdin stdout stderr` via `pr` (PowerShell Remoting) not
///   `rsp` (RemoteShell Protocol).
pub(crate) fn create_psrp_shell_request(
    endpoint: &str,
    config: &crate::config::WinrmConfig,
    creation_xml_b64: &str,
    ps_resource_uri: &str,
    shell_id: &str,
) -> String {
    let header = build_header_for(
        endpoint,
        ACTION_CREATE,
        ps_resource_uri,
        None,
        config.operation_timeout_secs,
        config.max_envelope_size,
    );
    let idle_timeout = config
        .idle_timeout_secs
        .map(|secs| format!("\n      <rsp:IdleTimeOut>PT{secs}S</rsp:IdleTimeOut>"))
        .unwrap_or_default();

    // `header` ends with `</s:Header>` — insert the OptionSet before it.
    let header_with_options = header.replace(
        "</s:Header>",
        r#"
    <wsman:OptionSet s:mustUnderstand="true">
      <wsman:Option Name="protocolversion" MustComply="true">2.3</wsman:Option>
    </wsman:OptionSet>
  </s:Header>"#,
    );
    // Escape ShellId defensively. The crate generates ShellIds via
    // uuid::Uuid::new_v4() so the value is currently always ASCII
    // [0-9a-f-], but escaping costs nothing and survives future
    // refactors that might let a caller-supplied id leak into here.
    let escaped_shell_id = xml_escape(shell_id);
    format!(
        r#"<s:Envelope {NS_DECL_WITH_RSP}>
{header_with_options}
  <s:Body>
    <rsp:Shell ShellId="{escaped_shell_id}">
      <rsp:InputStreams>stdin pr</rsp:InputStreams>
      <rsp:OutputStreams>stdout</rsp:OutputStreams>{idle_timeout}
      <creationXml xmlns="http://schemas.microsoft.com/powershell">{creation_xml_b64}</creationXml>
    </rsp:Shell>
  </s:Body>
</s:Envelope>"#
    )
}

/// Build a WS-Man Execute Command envelope with a caller-specified CommandId.
///
/// Used by PSRP where the CommandId must be the pipeline's UUID and
/// the first pipeline fragment is passed as a base64 argument.
#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_command_with_id_request(
    endpoint: &str,
    shell_id: &str,
    command: &str,
    args: &[&str],
    command_id: &str,
    timeout_secs: u64,
    max_envelope_size: u32,
    resource_uri: &str,
) -> String {
    let header = build_header_for(
        endpoint,
        ACTION_COMMAND,
        resource_uri,
        Some(shell_id),
        timeout_secs,
        max_envelope_size,
    );
    let mut args_xml = String::new();
    for a in args {
        let _ = write!(
            args_xml,
            "\n      <rsp:Arguments>{}</rsp:Arguments>",
            xml_escape(a)
        );
    }
    let escaped_command = xml_escape(command);
    let escaped_id = xml_escape(command_id);
    format!(
        r#"<s:Envelope {NS_DECL_WITH_RSP}>
{header}
  <s:Body>
    <rsp:CommandLine CommandId="{escaped_id}">
      <rsp:Command>{escaped_command}</rsp:Command>{args_xml}
    </rsp:CommandLine>
  </s:Body>
</s:Envelope>"#
    )
}

/// Build a PSRP-specific Receive SOAP envelope (stdout only, optional CommandId).
pub(crate) fn receive_psrp_request(
    endpoint: &str,
    shell_id: &str,
    command_id: Option<&str>,
    timeout_secs: u64,
    max_envelope_size: u32,
    resource_uri: &str,
) -> String {
    let header = build_header_for(
        endpoint,
        ACTION_RECEIVE,
        resource_uri,
        Some(shell_id),
        timeout_secs,
        max_envelope_size,
    );
    let stream = match command_id {
        Some(cid) => format!(
            "<rsp:DesiredStream CommandId=\"{}\">stdout</rsp:DesiredStream>",
            xml_escape(cid)
        ),
        None => "<rsp:DesiredStream>stdout</rsp:DesiredStream>".into(),
    };
    // Insert KEEPALIVE option inside the header (before </s:Header>).
    let header_with_opts = header.replace(
        "</s:Header>",
        r#"
    <wsman:OptionSet s:mustUnderstand="true">
      <wsman:Option Name="WSMAN_CMDSHELL_OPTION_KEEPALIVE">True</wsman:Option>
    </wsman:OptionSet>
  </s:Header>"#,
    );
    format!(
        r"<s:Envelope {NS_DECL_WITH_RSP}>
{header_with_opts}
  <s:Body>
    <rsp:Receive>
      {stream}
    </rsp:Receive>
  </s:Body>
</s:Envelope>"
    )
}

/// Build a WS-Management Execute Command SOAP envelope (MS-WSMV 3.1.4.5).
///
/// Runs the given command with optional arguments inside an existing shell
/// identified by `shell_id`. Returns XML containing the command line and
/// arguments as `<rsp:Arguments>` elements.
pub(crate) fn execute_command_request(
    endpoint: &str,
    shell_id: &str,
    command: &str,
    args: &[&str],
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    execute_command_request_with_uri(
        endpoint,
        shell_id,
        command,
        args,
        timeout_secs,
        max_envelope_size,
        RESOURCE_URI_CMD,
    )
}

pub(crate) fn execute_command_request_with_uri(
    endpoint: &str,
    shell_id: &str,
    command: &str,
    args: &[&str],
    timeout_secs: u64,
    max_envelope_size: u32,
    resource_uri: &str,
) -> String {
    let header = build_header_for(
        endpoint,
        ACTION_COMMAND,
        resource_uri,
        Some(shell_id),
        timeout_secs,
        max_envelope_size,
    );
    let mut args_xml = String::new();
    for (i, a) in args.iter().enumerate() {
        if i > 0 {
            args_xml.push('\n');
        }
        let _ = write!(
            args_xml,
            "      <rsp:Arguments>{}</rsp:Arguments>",
            xml_escape(a)
        );
    }
    let escaped_command = xml_escape(command);
    format!(
        r"<s:Envelope {NS_DECL_WITH_RSP}>
{header}
  <s:Body>
    <rsp:CommandLine>
      <rsp:Command>{escaped_command}</rsp:Command>
{args_xml}
    </rsp:CommandLine>
  </s:Body>
</s:Envelope>"
    )
}

/// Build a WS-Management Receive (poll output) SOAP envelope (MS-WSMV 3.1.4.7).
///
/// Requests stdout and stderr stream data for the given `command_id` within
/// `shell_id`. The server returns base64-encoded stream chunks and a
/// `CommandState` indicating whether the command has finished.
pub(crate) fn receive_output_request(
    endpoint: &str,
    shell_id: &str,
    command_id: &str,
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    receive_output_request_with_uri(
        endpoint,
        shell_id,
        command_id,
        timeout_secs,
        max_envelope_size,
        RESOURCE_URI_CMD,
    )
}

pub(crate) fn receive_output_request_with_uri(
    endpoint: &str,
    shell_id: &str,
    command_id: &str,
    timeout_secs: u64,
    max_envelope_size: u32,
    resource_uri: &str,
) -> String {
    let header = build_header_for(
        endpoint,
        ACTION_RECEIVE,
        resource_uri,
        Some(shell_id),
        timeout_secs,
        max_envelope_size,
    );
    let escaped_command_id = xml_escape(command_id);
    format!(
        r#"<s:Envelope {NS_DECL_WITH_RSP}>
{header}
  <s:Body>
    <rsp:Receive>
      <rsp:DesiredStream CommandId="{escaped_command_id}">stdout stderr</rsp:DesiredStream>
    </rsp:Receive>
  </s:Body>
</s:Envelope>"#
    )
}

/// Build a WS-Management Signal (terminate) SOAP envelope (MS-WSMV 3.1.4.9).
///
/// Sends a terminate signal to the command identified by `command_id` within
/// `shell_id`. This is a best-effort request typically sent before deleting
/// the shell.
pub(crate) fn signal_terminate_request(
    endpoint: &str,
    shell_id: &str,
    command_id: &str,
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    let header = build_header(
        endpoint,
        ACTION_SIGNAL,
        Some(shell_id),
        timeout_secs,
        max_envelope_size,
    );
    let escaped_command_id = xml_escape(command_id);
    format!(
        r#"<s:Envelope {NS_DECL_WITH_RSP}>
{header}
  <s:Body>
    <rsp:Signal CommandId="{escaped_command_id}">
      <rsp:Code>{SIGNAL_TERMINATE}</rsp:Code>
    </rsp:Signal>
  </s:Body>
</s:Envelope>"#
    )
}

/// Build a WS-Management Delete Shell SOAP envelope (MS-WSMV 3.1.4.3) for a
/// specific ResourceURI.
///
/// Deletes the remote shell identified by `shell_id`, releasing all
/// server-side resources. This is the WS-Transfer Delete operation.
///
/// Delete is addressed to a plugin, exactly like Create, Receive and Send. A
/// PSRP shell lives under the PowerShell ResourceURI, so deleting it with the
/// `cmd` URI makes the server answer `InvalidSelectors: the shell was not
/// found` — and leave the PSRP shell running. Those orphans accumulate until
/// `MaxShellsPerUser` is reached and every later Create fails with
/// `InternalError`.
pub(crate) fn delete_shell_request_for(
    endpoint: &str,
    shell_id: &str,
    resource_uri: &str,
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    let header = build_header_for(
        endpoint,
        ACTION_DELETE,
        resource_uri,
        Some(shell_id),
        timeout_secs,
        max_envelope_size,
    );
    format!(
        r"<s:Envelope {NS_DECL_NO_RSP}>
{header}
  <s:Body/>
</s:Envelope>"
    )
}

/// Build a WS-Management Disconnect Shell SOAP envelope (MS-WSMV 3.1.4.26).
///
/// Disconnects the client from a running shell while leaving the shell
/// alive on the server so it can be reconnected later.
#[allow(dead_code)] // Kept for CMD shell path; PSRP uses _with_uri variant.
pub(crate) fn disconnect_shell_request(
    endpoint: &str,
    shell_id: &str,
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    let header = build_header(
        endpoint,
        ACTION_DISCONNECT,
        Some(shell_id),
        timeout_secs,
        max_envelope_size,
    );
    // No IdleTimeOut in the body: the shell keeps the one it was created
    // with. Recycling the operation timeout here sent 20 s, and Windows
    // refuses anything under 60 s (`IdleTimeout of 20000 is outside the
    // allowed range`), which killed every Disconnect. pypsrp sends the bare
    // element too.
    format!(
        r"<s:Envelope {NS_DECL_WITH_RSP}>
{header}
  <s:Body>
    <rsp:Disconnect/>
  </s:Body>
</s:Envelope>"
    )
}

/// Build a WS-Management Reconnect Shell SOAP envelope (MS-WSMV 3.1.4.27).
///
/// Rejoins a previously disconnected shell identified by `shell_id`.
#[allow(dead_code)]
pub(crate) fn reconnect_shell_request(
    endpoint: &str,
    shell_id: &str,
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    reconnect_shell_request_with_uri(
        endpoint,
        shell_id,
        timeout_secs,
        max_envelope_size,
        RESOURCE_URI_CMD,
    )
}

pub(crate) fn disconnect_shell_request_with_uri(
    endpoint: &str,
    shell_id: &str,
    timeout_secs: u64,
    max_envelope_size: u32,
    resource_uri: &str,
) -> String {
    let header = build_header_for(
        endpoint,
        ACTION_DISCONNECT,
        resource_uri,
        Some(shell_id),
        timeout_secs,
        max_envelope_size,
    );
    // Bare element — see `disconnect_shell_request`.
    format!(
        r"<s:Envelope {NS_DECL_WITH_RSP}>
{header}
  <s:Body>
    <rsp:Disconnect/>
  </s:Body>
</s:Envelope>"
    )
}

pub(crate) fn reconnect_shell_request_with_uri(
    endpoint: &str,
    shell_id: &str,
    timeout_secs: u64,
    max_envelope_size: u32,
    resource_uri: &str,
) -> String {
    let header = build_header_for(
        endpoint,
        ACTION_RECONNECT,
        resource_uri,
        Some(shell_id),
        timeout_secs,
        max_envelope_size,
    );
    format!(
        r"<s:Envelope {NS_DECL_WITH_RSP}>
{header}
  <s:Body>
    <rsp:Reconnect/>
  </s:Body>
</s:Envelope>"
    )
}

/// Build a WS-Management Send Input SOAP envelope (MS-WSMV 3.1.4.6).
///
/// Sends stdin data to a running command. The data is base64-encoded
/// in the request body. Set `end_of_stream` to `true` to signal EOF.
#[allow(dead_code)] // Kept for existing tests; live code uses send_input_request_with_uri.
pub(crate) fn send_input_request(
    endpoint: &str,
    shell_id: &str,
    command_id: &str,
    data: &[u8],
    end_of_stream: bool,
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    send_input_request_with_uri(
        endpoint,
        shell_id,
        command_id,
        data,
        end_of_stream,
        timeout_secs,
        max_envelope_size,
        RESOURCE_URI_CMD,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn send_input_request_with_uri(
    endpoint: &str,
    shell_id: &str,
    command_id: &str,
    data: &[u8],
    end_of_stream: bool,
    timeout_secs: u64,
    max_envelope_size: u32,
    resource_uri: &str,
) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;

    let header = build_header_for(
        endpoint,
        ACTION_SEND,
        resource_uri,
        Some(shell_id),
        timeout_secs,
        max_envelope_size,
    );
    let encoded_data = B64.encode(data);
    let end_attr = if end_of_stream { r#" End="true""# } else { "" };
    let escaped_command_id = xml_escape(command_id);
    format!(
        r#"<s:Envelope {NS_DECL_WITH_RSP}>
{header}
  <s:Body>
    <rsp:Send>
      <rsp:Stream Name="stdin" CommandId="{escaped_command_id}"{end_attr}>{encoded_data}</rsp:Stream>
    </rsp:Send>
  </s:Body>
</s:Envelope>"#
    )
}

/// Build a PSRP-specific Send SOAP envelope (no CommandId on the stream).
pub(crate) fn send_psrp_request(
    endpoint: &str,
    shell_id: &str,
    data: &[u8],
    timeout_secs: u64,
    max_envelope_size: u32,
    resource_uri: &str,
) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;

    let header = build_header_for(
        endpoint,
        ACTION_SEND,
        resource_uri,
        Some(shell_id),
        timeout_secs,
        max_envelope_size,
    );
    let encoded_data = B64.encode(data);
    format!(
        r#"<s:Envelope {NS_DECL_WITH_RSP}>
{header}
  <s:Body>
    <rsp:Send>
      <rsp:Stream Name="stdin">{encoded_data}</rsp:Stream>
    </rsp:Send>
  </s:Body>
</s:Envelope>"#
    )
}

/// Build a WS-Management Signal (Ctrl+C) SOAP envelope.
///
/// Sends a Ctrl+C signal to the command identified by `command_id` within
/// `shell_id`, requesting graceful interruption.
pub(crate) fn signal_ctrl_c_request(
    endpoint: &str,
    shell_id: &str,
    command_id: &str,
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    let header = build_header(
        endpoint,
        ACTION_SIGNAL,
        Some(shell_id),
        timeout_secs,
        max_envelope_size,
    );
    let escaped_command_id = xml_escape(command_id);
    format!(
        r#"<s:Envelope {NS_DECL_WITH_RSP}>
{header}
  <s:Body>
    <rsp:Signal CommandId="{escaped_command_id}">
      <rsp:Code>{SIGNAL_CTRL_C}</rsp:Code>
    </rsp:Signal>
  </s:Body>
</s:Envelope>"#
    )
}

/// Build a WS-Enumeration Enumerate request with a WQL filter (MS-WSMV).
///
/// Used to query WMI classes via WQL (e.g., `SELECT * FROM Win32_Service`).
/// The `wql_namespace` defaults to `root/cimv2` if `None`.
pub(crate) fn enumerate_wql_request(
    endpoint: &str,
    wql_query: &str,
    wql_namespace: Option<&str>,
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    let ns = wql_namespace.unwrap_or("root/cimv2");
    let resource_uri = format!("http://schemas.microsoft.com/wbem/wsman/1/wmi/{ns}/*");
    let header = build_header_for(
        endpoint,
        ACTION_ENUMERATE,
        &resource_uri,
        None,
        timeout_secs,
        max_envelope_size,
    );
    let escaped_query = xml_escape(wql_query);
    format!(
        r#"<s:Envelope {NS_DECL_NO_RSP}
  xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
{header}
  <s:Body>
    <n:Enumerate>
      <wsman:OptimizeEnumeration/>
      <wsman:MaxElements>32000</wsman:MaxElements>
      <wsman:Filter Dialect="{WQL_DIALECT}">{escaped_query}</wsman:Filter>
    </n:Enumerate>
  </s:Body>
</s:Envelope>"#
    )
}

/// Build a WS-Enumeration Pull request to continue a WQL enumeration.
pub(crate) fn pull_request(
    endpoint: &str,
    enumeration_context: &str,
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    let header = build_header_for(
        endpoint,
        ACTION_PULL,
        RESOURCE_URI_WMI,
        None,
        timeout_secs,
        max_envelope_size,
    );
    let escaped_ctx = xml_escape(enumeration_context);
    format!(
        r#"<s:Envelope {NS_DECL_NO_RSP}
  xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
{header}
  <s:Body>
    <n:Pull>
      <n:EnumerationContext>{escaped_ctx}</n:EnumerationContext>
      <n:MaxElements>32000</n:MaxElements>
    </n:Pull>
  </s:Body>
</s:Envelope>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumerate_wql_request_default_namespace() {
        let xml = enumerate_wql_request(
            "http://h:5985/wsman",
            "SELECT * FROM Win32_Service",
            None,
            60,
            153_600,
        );
        assert!(xml.contains("wbem/wsman/1/wmi/root/cimv2/*"));
        assert!(xml.contains("SELECT * FROM Win32_Service"));
        assert!(xml.contains("OptimizeEnumeration"));
        assert!(xml.contains("Enumerate"));
    }

    #[test]
    fn enumerate_wql_request_custom_namespace_and_escapes() {
        let xml = enumerate_wql_request(
            "http://h/wsman",
            "a < b & c",
            Some("root/StandardCimv2"),
            30,
            153_600,
        );
        assert!(xml.contains("root/StandardCimv2"));
        assert!(xml.contains("a &lt; b &amp; c"));
    }

    // The WMI namespace is spliced into the ResourceURI element, which used
    // to be interpolated raw. A namespace carrying markup must not be able to
    // add elements to the header.
    #[test]
    fn enumerate_wql_request_escapes_resource_uri() {
        let xml = enumerate_wql_request(
            "http://h/wsman",
            "SELECT * FROM Win32_Service",
            Some("root/cimv2</wsman:ResourceURI><evil>x</evil><wsman:ResourceURI>"),
            30,
            153_600,
        );
        assert!(!xml.contains("<evil>"), "namespace injected an element");
        assert!(xml.contains("&lt;evil&gt;"));
        assert_eq!(
            xml.matches("<wsman:ResourceURI").count(),
            1,
            "namespace opened a second ResourceURI element"
        );
    }

    #[test]
    fn pull_request_includes_context() {
        let xml = pull_request("http://h/wsman", "ctx-<id>", 60, 153_600);
        assert!(xml.contains("Pull"));
        assert!(xml.contains("ctx-&lt;id&gt;"));
        assert!(xml.contains("EnumerationContext"));
    }

    #[test]
    fn create_shell_contains_required_elements() {
        let xml = create_shell_request(
            "http://host:5985/wsman",
            &crate::config::WinrmConfig::default(),
        );
        assert!(xml.contains("transfer/Create"));
        assert!(xml.contains("WINRS_CODEPAGE"));
        assert!(xml.contains("65001"));
        assert!(xml.contains("stdout stderr"));
        assert!(xml.contains("PT60S"));
    }

    #[test]
    fn execute_command_contains_shell_id() {
        let xml = execute_command_request(
            "http://host:5985/wsman",
            "SHELL-123",
            "powershell.exe",
            &["-EncodedCommand", "dGVzdA=="],
            60,
            153_600,
        );
        assert!(xml.contains("SHELL-123"));
        assert!(xml.contains("powershell.exe"));
        assert!(xml.contains("-EncodedCommand"));
        assert!(xml.contains("dGVzdA=="));
    }

    #[test]
    fn receive_request_contains_ids() {
        let xml = receive_output_request("http://host:5985/wsman", "SHELL-1", "CMD-1", 60, 153_600);
        assert!(xml.contains("SHELL-1"));
        assert!(xml.contains("CMD-1"));
        assert!(xml.contains("Receive"));
    }

    #[test]
    fn delete_shell_contains_shell_id() {
        let xml = delete_shell_request_for(
            "http://host:5985/wsman",
            "SHELL-1",
            RESOURCE_URI_CMD,
            60,
            153_600,
        );
        assert!(xml.contains("SHELL-1"));
        assert!(xml.contains("transfer/Delete"));
        assert!(xml.contains(RESOURCE_URI_CMD));
    }

    /// A PSRP shell must be deleted under the PowerShell ResourceURI. With the
    /// `cmd` URI the server answers `InvalidSelectors` and leaves the shell
    /// running until `MaxShellsPerUser` blocks every new Create.
    #[test]
    fn delete_shell_uses_the_given_resource_uri() {
        let xml = delete_shell_request_for(
            "http://host:5985/wsman",
            "SHELL-1",
            crate::soap::namespaces::RESOURCE_URI_PSRP,
            60,
            153_600,
        );
        assert!(
            xml.contains(crate::soap::namespaces::RESOURCE_URI_PSRP),
            "PSRP ResourceURI must reach the Delete envelope, got: {xml}"
        );
        assert!(
            !xml.contains(RESOURCE_URI_CMD),
            "cmd ResourceURI must not leak into a PSRP Delete, got: {xml}"
        );
    }

    #[test]
    fn signal_terminate_contains_required_elements() {
        let xml = signal_terminate_request("http://host:5985/wsman", "S1", "C1", 60, 153_600);
        assert!(xml.contains("Signal"));
        assert!(xml.contains("S1"));
        assert!(xml.contains("C1"));
        assert!(xml.contains("signal/terminate"));
    }

    #[test]
    fn max_envelope_size_appears_in_create_shell() {
        let config = crate::config::WinrmConfig {
            max_envelope_size: 512_000,
            ..Default::default()
        };
        let xml = create_shell_request("http://host:5985/wsman", &config);
        assert!(xml.contains("512000"));
        assert!(!xml.contains("153600"));
    }

    #[test]
    fn max_envelope_size_appears_in_execute_command() {
        let xml = execute_command_request("http://host:5985/wsman", "S1", "cmd", &[], 60, 256_000);
        assert!(xml.contains("256000"));
    }

    #[test]
    fn max_envelope_size_appears_in_receive_output() {
        let xml = receive_output_request("http://host:5985/wsman", "S1", "C1", 60, 999_999);
        assert!(xml.contains("999999"));
    }

    #[test]
    fn max_envelope_size_appears_in_signal_terminate() {
        let xml = signal_terminate_request("http://host:5985/wsman", "S1", "C1", 60, 200_000);
        assert!(xml.contains("200000"));
    }

    #[test]
    fn max_envelope_size_appears_in_delete_shell() {
        let xml = delete_shell_request_for(
            "http://host:5985/wsman",
            "S1",
            RESOURCE_URI_CMD,
            60,
            300_000,
        );
        assert!(xml.contains("300000"));
    }

    #[test]
    fn send_input_contains_required_elements() {
        let xml = send_input_request(
            "http://host:5985/wsman",
            "S1",
            "C1",
            b"hello",
            false,
            60,
            153_600,
        );
        assert!(xml.contains("Send"));
        assert!(xml.contains("S1"));
        assert!(xml.contains("C1"));
        assert!(xml.contains("stdin"));
        assert!(xml.contains("153600"));
        // "hello" in base64 = aGVsbG8=
        assert!(xml.contains("aGVsbG8="));
        assert!(!xml.contains(r#"End="true""#));
    }

    #[test]
    fn send_input_end_of_stream() {
        let xml = send_input_request(
            "http://host:5985/wsman",
            "S1",
            "C1",
            b"bye",
            true,
            60,
            153_600,
        );
        assert!(xml.contains(r#"End="true""#));
    }

    #[test]
    fn signal_ctrl_c_contains_required_elements() {
        let xml = signal_ctrl_c_request("http://host:5985/wsman", "S1", "C1", 60, 153_600);
        assert!(xml.contains("Signal"));
        assert!(xml.contains("S1"));
        assert!(xml.contains("C1"));
        assert!(xml.contains("signal/ctrl_c"));
        assert!(xml.contains("153600"));
    }

    #[test]
    fn signal_ctrl_c_max_envelope_size() {
        let xml = signal_ctrl_c_request("http://host:5985/wsman", "S1", "C1", 60, 400_000);
        assert!(xml.contains("400000"));
        assert!(!xml.contains("153600"));
    }

    #[test]
    fn send_input_max_envelope_size() {
        let xml = send_input_request(
            "http://host:5985/wsman",
            "S1",
            "C1",
            b"data",
            false,
            60,
            600_000,
        );
        assert!(xml.contains("600000"));
    }

    #[test]
    fn xml_escape_special_characters() {
        assert_eq!(xml_escape("<"), "&lt;");
        assert_eq!(xml_escape(">"), "&gt;");
        assert_eq!(xml_escape("&"), "&amp;");
        assert_eq!(xml_escape("\""), "&quot;");
        assert_eq!(xml_escape("'"), "&apos;");
        assert_eq!(
            xml_escape("a<b>c&d\"e'f"),
            "a&lt;b&gt;c&amp;d&quot;e&apos;f"
        );
        assert_eq!(xml_escape("normal text"), "normal text");
    }

    #[test]
    fn execute_command_escapes_xml_in_args() {
        let xml = execute_command_request(
            "http://host:5985/wsman",
            "SHELL-1",
            "cmd",
            &["arg</rsp:Arguments><injected>"],
            60,
            153_600,
        );
        assert!(!xml.contains("</rsp:Arguments><injected>"));
        assert!(xml.contains("&lt;/rsp:Arguments&gt;&lt;injected&gt;"));
    }

    #[test]
    fn execute_command_escapes_xml_in_command() {
        let xml = execute_command_request(
            "http://host:5985/wsman",
            "SHELL-1",
            "cmd<evil>",
            &[],
            60,
            153_600,
        );
        assert!(!xml.contains("<evil>"));
        assert!(xml.contains("cmd&lt;evil&gt;"));
    }

    #[test]
    fn build_header_escapes_shell_id() {
        let xml = receive_output_request(
            "http://host:5985/wsman",
            "SHELL<injected>",
            "CMD-1",
            60,
            153_600,
        );
        assert!(!xml.contains("SHELL<injected>"));
        assert!(xml.contains("SHELL&lt;injected&gt;"));
    }

    #[test]
    fn receive_output_escapes_command_id() {
        let xml =
            receive_output_request("http://host:5985/wsman", "S1", "CMD\"injected", 60, 153_600);
        assert!(!xml.contains("CMD\"injected"));
        assert!(xml.contains("CMD&quot;injected"));
    }

    #[test]
    fn create_shell_with_custom_codepage() {
        let config = crate::config::WinrmConfig {
            codepage: 437,
            ..Default::default()
        };
        let xml = create_shell_request("http://host:5985/wsman", &config);
        assert!(xml.contains("437"));
        assert!(!xml.contains("65001"));
    }

    #[test]
    fn create_shell_with_working_directory() {
        let config = crate::config::WinrmConfig {
            working_directory: Some("C:\\Users\\admin".into()),
            ..Default::default()
        };
        let xml = create_shell_request("http://host:5985/wsman", &config);
        assert!(xml.contains("<rsp:WorkingDirectory>C:\\Users\\admin</rsp:WorkingDirectory>"));
    }

    #[test]
    fn create_shell_without_working_directory() {
        let xml = create_shell_request(
            "http://host:5985/wsman",
            &crate::config::WinrmConfig::default(),
        );
        assert!(!xml.contains("WorkingDirectory"));
    }

    #[test]
    fn create_shell_with_env_vars() {
        let config = crate::config::WinrmConfig {
            env_vars: vec![
                ("PATH".into(), "C:\\bin".into()),
                ("FOO".into(), "bar&baz".into()),
            ],
            ..Default::default()
        };
        let xml = create_shell_request("http://host:5985/wsman", &config);
        assert!(xml.contains("<rsp:Environment>"));
        assert!(xml.contains(r#"<rsp:Variable Name="PATH">C:\bin</rsp:Variable>"#));
        assert!(xml.contains(r#"<rsp:Variable Name="FOO">bar&amp;baz</rsp:Variable>"#));
    }

    #[test]
    fn create_shell_without_env_vars() {
        let xml = create_shell_request(
            "http://host:5985/wsman",
            &crate::config::WinrmConfig::default(),
        );
        assert!(!xml.contains("Environment"));
    }

    #[test]
    fn create_shell_with_idle_timeout() {
        let config = crate::config::WinrmConfig {
            idle_timeout_secs: Some(300),
            ..Default::default()
        };
        let xml = create_shell_request("http://host:5985/wsman", &config);
        assert!(xml.contains("<rsp:IdleTimeOut>PT300S</rsp:IdleTimeOut>"));
    }

    #[test]
    fn create_shell_without_idle_timeout() {
        let xml = create_shell_request(
            "http://host:5985/wsman",
            &crate::config::WinrmConfig::default(),
        );
        assert!(!xml.contains("IdleTimeOut"));
    }

    #[test]
    fn create_psrp_shell_contains_required_elements() {
        let config = crate::config::WinrmConfig {
            idle_timeout_secs: Some(120),
            ..Default::default()
        };
        let xml = create_psrp_shell_request(
            "http://host:5985/wsman",
            &config,
            "AQAAAA==",
            "http://schemas.microsoft.com/powershell/Microsoft.PowerShell",
            "PSRP-SHELL-1",
        );
        assert!(xml.contains("transfer/Create"));
        assert!(xml.contains("schemas.microsoft.com/powershell/Microsoft.PowerShell"));
        assert!(xml.contains("PSRP-SHELL-1"));
        assert!(xml.contains("AQAAAA=="));
        assert!(xml.contains("creationXml"));
        assert!(xml.contains("stdin pr"));
        assert!(xml.contains("protocolversion"));
        assert!(xml.contains("<rsp:IdleTimeOut>PT120S</rsp:IdleTimeOut>"));
    }

    #[test]
    fn execute_command_with_id_contains_required_elements() {
        let xml = execute_command_with_id_request(
            "http://host:5985/wsman",
            "SHELL-1",
            "Invoke-Expression",
            &["arg1", "arg2"],
            "CMD-UUID-42",
            60,
            153_600,
            RESOURCE_URI_PSRP,
        );
        assert!(xml.contains("SHELL-1"));
        assert!(xml.contains("Invoke-Expression"));
        assert!(xml.contains("CMD-UUID-42"));
        assert!(xml.contains("arg1"));
        assert!(xml.contains("arg2"));
        assert!(xml.contains("CommandId=\"CMD-UUID-42\""));
        assert!(xml.contains("shell/Command"));
        assert!(xml.contains("schemas.microsoft.com/powershell/Microsoft.PowerShell"));

        // Verify the args are separated by a newline (kills > → >= and > → == mutants)
        let arg1_tag = "<rsp:Arguments>arg1</rsp:Arguments>";
        let arg2_tag = "<rsp:Arguments>arg2</rsp:Arguments>";
        let between =
            &xml[xml.find(arg1_tag).unwrap() + arg1_tag.len()..xml.find(arg2_tag).unwrap()];
        assert_eq!(
            between, "\n      ",
            "args should be separated by newline + indent"
        );
    }

    #[test]
    fn receive_psrp_request_with_command_id() {
        let xml = receive_psrp_request(
            "http://host:5985/wsman",
            "SHELL-1",
            Some("CMD-1"),
            60,
            153_600,
            RESOURCE_URI_PSRP,
        );
        assert!(xml.contains("SHELL-1"));
        assert!(xml.contains("CMD-1"));
        assert!(xml.contains("Receive"));
        assert!(xml.contains("shell/Receive"));
        assert!(xml.contains("WSMAN_CMDSHELL_OPTION_KEEPALIVE"));
        assert!(xml.contains("stdout"));
        assert!(xml.contains("schemas.microsoft.com/powershell/Microsoft.PowerShell"));
    }

    #[test]
    fn receive_psrp_request_without_command_id() {
        let xml = receive_psrp_request(
            "http://host:5985/wsman",
            "SHELL-1",
            None,
            60,
            153_600,
            RESOURCE_URI_PSRP,
        );
        assert!(xml.contains("<rsp:DesiredStream>stdout</rsp:DesiredStream>"));
        assert!(!xml.contains("CommandId"));
    }

    #[test]
    fn execute_command_request_with_uri_contains_required_elements() {
        let custom_uri = "http://schemas.microsoft.com/powershell/Custom";
        let xml = execute_command_request_with_uri(
            "http://host:5985/wsman",
            "SHELL-1",
            "Get-Process",
            &["-Name", "svchost"],
            60,
            153_600,
            custom_uri,
        );
        assert!(xml.contains("SHELL-1"));
        assert!(xml.contains("Get-Process"));
        assert!(xml.contains("-Name"));
        assert!(xml.contains("svchost"));
        assert!(xml.contains("shell/Command"));
        assert!(xml.contains("schemas.microsoft.com/powershell/Custom"));
    }

    #[test]
    fn receive_output_request_with_uri_contains_required_elements() {
        let custom_uri = "http://schemas.microsoft.com/powershell/Custom";
        let xml = receive_output_request_with_uri(
            "http://host:5985/wsman",
            "SHELL-1",
            "CMD-1",
            60,
            153_600,
            custom_uri,
        );
        assert!(xml.contains("SHELL-1"));
        assert!(xml.contains("CMD-1"));
        assert!(xml.contains("Receive"));
        assert!(xml.contains("stdout stderr"));
        assert!(xml.contains("schemas.microsoft.com/powershell/Custom"));
    }

    #[test]
    fn disconnect_shell_contains_required_elements() {
        let xml = disconnect_shell_request("http://host:5985/wsman", "SHELL-1", 60, 153_600);
        assert!(xml.contains("SHELL-1"));
        assert!(xml.contains("shell/Disconnect"));
        assert!(xml.contains("Disconnect"));
        // The body carries no IdleTimeOut: the shell keeps the one from its
        // Create, and Windows rejects anything under 60 s outright — the
        // operation timeout used to be recycled here and 20 s answered
        // `IdleTimeout of 20000 is outside the allowed range`.
        assert!(xml.contains("<rsp:Disconnect/>"), "{xml}");
        assert!(!xml.contains("IdleTimeOut"), "{xml}");
        assert!(xml.contains("<wsman:OperationTimeout>PT60S</wsman:OperationTimeout>"));
    }

    #[test]
    fn reconnect_shell_contains_required_elements() {
        let xml = reconnect_shell_request("http://host:5985/wsman", "SHELL-1", 60, 153_600);
        assert!(xml.contains("SHELL-1"));
        assert!(xml.contains("shell/Reconnect"));
        assert!(xml.contains("<rsp:Reconnect/>"));
        assert!(xml.contains(RESOURCE_URI_CMD));
    }

    #[test]
    fn disconnect_shell_with_uri_contains_required_elements() {
        let custom_uri = "http://schemas.microsoft.com/powershell/Custom";
        let xml = disconnect_shell_request_with_uri(
            "http://host:5985/wsman",
            "SHELL-1",
            90,
            153_600,
            custom_uri,
        );
        assert!(xml.contains("SHELL-1"));
        assert!(xml.contains("shell/Disconnect"));
        assert!(xml.contains("<rsp:Disconnect/>"), "{xml}");
        assert!(!xml.contains("IdleTimeOut"), "{xml}");
        assert!(xml.contains("<wsman:OperationTimeout>PT90S</wsman:OperationTimeout>"));
        assert!(xml.contains("schemas.microsoft.com/powershell/Custom"));
    }

    #[test]
    fn reconnect_shell_with_uri_contains_required_elements() {
        let custom_uri = "http://schemas.microsoft.com/powershell/Custom";
        let xml = reconnect_shell_request_with_uri(
            "http://host:5985/wsman",
            "SHELL-1",
            60,
            153_600,
            custom_uri,
        );
        assert!(xml.contains("SHELL-1"));
        assert!(xml.contains("shell/Reconnect"));
        assert!(xml.contains("<rsp:Reconnect/>"));
        assert!(xml.contains("schemas.microsoft.com/powershell/Custom"));
    }

    #[test]
    fn send_input_with_uri_contains_required_elements() {
        let custom_uri = "http://schemas.microsoft.com/powershell/Custom";
        let xml = send_input_request_with_uri(
            "http://host:5985/wsman",
            "SHELL-1",
            "CMD-1",
            b"hello",
            true,
            60,
            153_600,
            custom_uri,
        );
        assert!(xml.contains("SHELL-1"));
        assert!(xml.contains("CMD-1"));
        assert!(xml.contains("Send"));
        assert!(xml.contains("stdin"));
        assert!(xml.contains("aGVsbG8=")); // base64 of "hello"
        assert!(xml.contains(r#"End="true""#));
        assert!(xml.contains("schemas.microsoft.com/powershell/Custom"));
    }

    #[test]
    fn send_psrp_request_contains_required_elements() {
        let xml = send_psrp_request(
            "http://host:5985/wsman",
            "SHELL-1",
            b"psrp-data",
            60,
            153_600,
            RESOURCE_URI_PSRP,
        );
        assert!(xml.contains("SHELL-1"));
        assert!(xml.contains("Send"));
        assert!(xml.contains("stdin"));
        assert!(xml.contains("shell/Send"));
        assert!(xml.contains("schemas.microsoft.com/powershell/Microsoft.PowerShell"));
        // No CommandId on the stream element for PSRP send
        assert!(!xml.contains("CommandId"));
    }

    // --- wsmv:SessionId (MS-WSMV 2.2.4.x) ---
    //
    // Windows only grants Disconnect/Reconnect to a shell whose Create carried
    // a SessionId header — otherwise the shell is "created by an older WinRS
    // client". Measured against Server 2025 with pypsrp: strip SessionId from
    // the Create alone and Disconnect answers exactly that fault; keep it on
    // the Create and strip it from the follow-ups and every follow-up is
    // refused with 0x8033810F "does not contain a valid SessionID element".
    // So the element goes on every request of a session, and it is injected
    // at the transport chokepoint rather than threaded through 19 builders.

    #[test]
    fn with_session_id_inserts_element_before_header_end_once() {
        let env = create_shell_request(
            "http://h:5985/wsman",
            &crate::config::WinrmConfig::default(),
        );
        let out = with_session_id(&env, "uuid:9A85B009-AB3A-47D9-A357-EFCA4F6174B5");
        let needle = r#"<wsmv:SessionId s:mustUnderstand="false">uuid:9A85B009-AB3A-47D9-A357-EFCA4F6174B5</wsmv:SessionId>"#;
        assert_eq!(
            out.matches(needle).count(),
            1,
            "exactly one SessionId: {out}"
        );
        let pos_sid = out.find(needle).unwrap();
        let pos_hdr_end = out.find("</s:Header>").unwrap();
        assert!(
            pos_sid < pos_hdr_end,
            "SessionId must sit inside the header"
        );
        // Nothing else moved: body identical, header end still unique.
        let body = |s: &str| s[s.find("<s:Body>").unwrap()..].to_string();
        assert_eq!(body(&out), body(&env));
        assert_eq!(out.matches("</s:Header>").count(), 1);
    }

    #[test]
    fn with_session_id_is_a_no_op_without_a_header() {
        assert_eq!(with_session_id("<s:Envelope/>", "uuid:X"), "<s:Envelope/>");
    }

    #[test]
    fn with_session_id_escapes_the_value() {
        let out = with_session_id("<s:Header></s:Header>", "uuid:<x>&");
        assert!(out.contains("uuid:&lt;x&gt;&amp;"), "{out}");
    }

    #[test]
    fn every_envelope_declares_the_wsmv_prefix() {
        // The SessionId element uses the `wsmv` prefix, so both namespace
        // declaration sets must bind it — including the Delete one.
        for decl in [NS_DECL_WITH_RSP, NS_DECL_NO_RSP] {
            assert!(
                decl.contains(
                    r#"xmlns:wsmv="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd""#
                ),
                "missing wsmv declaration in {decl}"
            );
        }
        let del =
            delete_shell_request_for("http://h:5985/wsman", "S", RESOURCE_URI_CMD, 60, 153_600);
        assert!(del.contains("xmlns:wsmv="), "{del}");
    }
}
