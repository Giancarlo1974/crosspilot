//! Response parsers for shell IDs, command IDs, and output streams.

use super::namespaces::COMMAND_STATE_DONE;
use crate::error::SoapError;

/// Parsed output from a single WinRM Receive response.
///
/// Each Receive poll may return partial output. Callers should accumulate
/// [`stdout`](Self::stdout) and [`stderr`](Self::stderr) across polls and
/// stop when [`done`](Self::done) is `true`.
pub struct ReceiveOutput {
    /// Decoded stdout bytes from this poll (may be empty).
    pub stdout: Vec<u8>,
    /// Decoded stderr bytes from this poll (may be empty).
    pub stderr: Vec<u8>,
    /// Process exit code, present only when the command has finished.
    pub exit_code: Option<i32>,
    /// `true` when the server reports `CommandState/Done`, indicating no more
    /// output will follow.
    pub done: bool,
}

/// Extract the `ShellId` from a Create Shell response body.
///
/// Searches for a `<ShellId>` element (with or without namespace prefix) and
/// returns its text content. Returns [`SoapError::MissingElement`] if not found.
#[allow(unreachable_pub)] // re-exported under the `__internal` feature for fuzz targets
pub fn parse_shell_id(xml: &str) -> Result<String, SoapError> {
    extract_element_text(xml, "ShellId").ok_or_else(|| SoapError::MissingElement("ShellId".into()))
}

/// Extract the `CommandId` from an Execute Command response body.
///
/// Searches for a `<CommandId>` element (with or without namespace prefix) and
/// returns its text content. Returns [`SoapError::MissingElement`] if not found.
#[allow(unreachable_pub)] // re-exported under the `__internal` feature for fuzz targets
pub fn parse_command_id(xml: &str) -> Result<String, SoapError> {
    extract_element_text(xml, "CommandId")
        .ok_or_else(|| SoapError::MissingElement("CommandId".into()))
}

/// Parse a Receive response to extract stdout, stderr, exit code, and completion state.
///
/// Decodes base64 `<rsp:Stream>` elements for stdout and stderr, checks the
/// `CommandState` for the `Done` URI, and extracts the `ExitCode` if present.
/// Returns [`SoapError::ParseError`] if a stream contains invalid base64, or
/// a [`SoapError::Fault`] if the response body contains a SOAP fault.
#[allow(unreachable_pub)] // re-exported under the `__internal` feature for fuzz targets
pub fn parse_receive_output(xml: &str) -> Result<ReceiveOutput, SoapError> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit_code: Option<i32> = None;
    let mut done = false;

    // Parse Stream elements for stdout/stderr
    // Format: <rsp:Stream Name="stdout" CommandId="...">base64data</rsp:Stream>
    for (name, data) in extract_streams(xml) {
        let decoded = B64
            .decode(data.trim_ascii())
            .map_err(|e| SoapError::ParseError(format!("base64 decode: {e}")))?;
        match name.as_str() {
            "stdout" => stdout.extend_from_slice(&decoded),
            "stderr" => {
                if decoded.starts_with(b"#< CLIXML") {
                    stderr.extend_from_slice(&parse_clixml(&decoded));
                } else {
                    stderr.extend_from_slice(&decoded);
                }
            }
            _ => {}
        }
    }

    // Check CommandState for Done
    if xml.contains(COMMAND_STATE_DONE) {
        done = true;
    }

    // Extract ExitCode if present. A non-numeric ExitCode value from the
    // server is left as `None` (fail-soft), but a `tracing::warn` is emitted
    // so callers can distinguish "command still running" (no ExitCode element)
    // from "server returned ExitCode element with unparseable text" (possible
    // server malfunction or MITM tampering with the response).
    if let Some(code_str) = extract_element_text(xml, "ExitCode") {
        match code_str.parse::<i32>() {
            Ok(c) => exit_code = Some(c),
            Err(e) => {
                tracing::warn!(
                    raw = %code_str.escape_debug(),
                    error = %e,
                    "WinRM ExitCode element present but unparseable; treating as absent",
                );
            }
        }
    }

    // Check for SOAP faults
    if let Some(fault) = extract_soap_fault(xml) {
        return Err(fault);
    }

    Ok(ReceiveOutput {
        stdout,
        stderr,
        exit_code,
        done,
    })
}

/// Parse a WS-Enumeration Enumerate response.
///
/// Returns the XML items (raw text between `<w:Items>` tags) and an optional
/// `EnumerationContext` for continuation via Pull.
pub(crate) fn parse_enumerate_response(xml: &str) -> Result<(String, Option<String>), SoapError> {
    check_soap_fault(xml)?;

    // Extract items — may be inside <w:Items>, <wsen:Items>, or <n:Items>
    let items = extract_element_text(xml, "Items").unwrap_or_default();

    // Extract EnumerationContext for Pull continuation
    let context = extract_element_text(xml, "EnumerationContext");

    // Check for EndOfSequence — means no more items
    let end_of_seq = xml.contains("EndOfSequence");

    let context = if end_of_seq { None } else { context };

    Ok((items, context))
}

/// Check a SOAP response for fault elements and return an error if found.
///
/// Scans the XML for `<Fault>` or `<s:Fault>` elements and extracts the
/// fault code and reason text. Returns `Ok(())` if no fault is present.
#[allow(unreachable_pub)] // re-exported under the `__internal` feature for fuzz targets
pub fn check_soap_fault(xml: &str) -> Result<(), SoapError> {
    if let Some(fault) = extract_soap_fault(xml) {
        return Err(fault);
    }
    Ok(())
}

/// Parse PowerShell CLIXML stderr into human-readable text.
///
/// PowerShell wraps errors in CLIXML format (`#< CLIXML\r\n<Objs>...`).
/// This function extracts the text from `<S S="Error">` tags and decodes
/// CLIXML escape sequences like `_x000D_` (CR) and `_x000A_` (LF).
fn parse_clixml(data: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(data);
    let mut result = String::new();

    // Extract content from <S S="Error">...</S> tags
    let error_tag = "<S S=\"Error\">";
    let close_tag = "</S>";
    let mut search_from = 0;

    while let Some(start) = text[search_from..].find(error_tag) {
        let content_start = search_from + start + error_tag.len();
        if let Some(end) = text[content_start..].find(close_tag) {
            let fragment = &text[content_start..content_start + end];
            result.push_str(fragment);
            search_from = content_start + end + close_tag.len();
        } else {
            break;
        }
    }

    // Decode CLIXML escape sequences
    let result = result
        .replace("_x000D_", "\r")
        .replace("_x000A_", "\n")
        .replace("_x0009_", "\t")
        .replace("_x001B_", "\x1b");

    result.into_bytes()
}

// --- Helpers ---

/// Simple element text extraction by local name (namespace-agnostic).
///
/// Finds elements like `<prefix:Element>text</prefix:Element>` or `<Element>text</Element>`
/// regardless of namespace prefix.
fn extract_element_text(xml: &str, element: &str) -> Option<String> {
    // Search for ":Element>" or "<Element>" to handle any namespace prefix
    let suffixed = format!(":{element}>");
    let bare_open = format!("<{element}>");

    let mut search_from = 0;
    while search_from < xml.len() {
        let region = &xml[search_from..];

        // Find next occurrence of the element (with or without prefix)
        let (tag_content_start, ns_prefix) = if let Some(pos) = region.find(&suffixed) {
            // Found ":Element>" -- walk back to find the '<'
            let abs_pos = search_from + pos;
            let before = &xml[..abs_pos];
            let lt = before.rfind('<')?;
            // Make sure this is an opening tag, not a closing tag
            if xml[lt..].starts_with("</") {
                search_from = abs_pos + suffixed.len();
                continue;
            }
            let prefix = &xml[lt + 1..abs_pos];
            (abs_pos + suffixed.len(), Some(prefix.to_string()))
        } else {
            let pos = region.find(&bare_open)?;
            (search_from + pos + bare_open.len(), None)
        };

        // Build closing tag pattern
        let close_tag = match &ns_prefix {
            Some(p) => format!("</{p}:{element}>"),
            None => format!("</{element}>"),
        };

        if let Some(end) = xml[tag_content_start..].find(&close_tag) {
            let text = xml[tag_content_start..tag_content_start + end].trim();
            if !text.is_empty() {
                return Some(text.to_string());
            }
        }

        search_from = tag_content_start;
    }
    None
}

/// Extract all Stream elements with their Name attribute and base64 content.
fn extract_streams(xml: &str) -> Vec<(String, String)> {
    let mut streams = Vec::new();
    let mut search_from = 0;

    let stream_tags = ["<rsp:Stream ", "<Stream "];

    while search_from < xml.len() {
        let found = stream_tags
            .iter()
            .filter_map(|tag| {
                xml[search_from..]
                    .find(tag)
                    .map(|pos| (search_from + pos, *tag))
            })
            .min_by_key(|(pos, _)| *pos);

        let Some((tag_start, _)) = found else {
            break;
        };

        let tag_region = &xml[tag_start..];

        // Find the end of the opening tag
        let Some(tag_end) = tag_region.find('>') else {
            break;
        };
        let opening_tag = &tag_region[..tag_end];

        // Extract Name attribute
        let name = extract_attribute(opening_tag, "Name").unwrap_or_default();

        // Find content between > and closing tag
        let content_start = tag_start + tag_end + 1;

        let close_tags = ["</rsp:Stream>", "</Stream>"];
        let close_pos = close_tags
            .iter()
            .filter_map(|close| xml[content_start..].find(close))
            .min();

        if let Some(end_offset) = close_pos {
            let content = &xml[content_start..content_start + end_offset];
            if !content.trim_ascii().is_empty() {
                streams.push((name, content.to_string()));
            }
            search_from = content_start + end_offset + 1;
        } else {
            break;
        }
    }

    streams
}

/// Extract an XML attribute value from a tag string.
fn extract_attribute(tag: &str, attr_name: &str) -> Option<String> {
    let pattern = format!("{attr_name}=\"");
    let start = tag.find(&pattern)? + pattern.len();
    let end = tag[start..].find('"')? + start;
    Some(tag[start..end].to_string())
}

/// Extract a SOAP fault from the response, if present.
fn extract_soap_fault(xml: &str) -> Option<SoapError> {
    // Check for Fault element
    let has_fault = xml.contains(":Fault>") || xml.contains("<Fault>");
    if !has_fault {
        return None;
    }

    // Prefer the subcode value (e.g. `w:TimedOut`) over the top-level
    // SOAP code (`s:Receiver`/`s:Sender`) because it carries the
    // actionable WS-Management error.
    let code = extract_subcode_value(xml)
        .or_else(|| extract_element_text(xml, "Value"))
        .or_else(|| extract_element_text(xml, "faultcode"))
        .unwrap_or_else(|| "unknown".into());
    let reason = extract_element_text(xml, "Text")
        .or_else(|| extract_element_text(xml, "Message"))
        .or_else(|| extract_element_text(xml, "faultstring"))
        .unwrap_or_else(|| "SOAP fault".into());

    Some(SoapError::Fault { code, reason })
}

/// Extract the `<s:Subcode><s:Value>…</s:Value></s:Subcode>` text,
/// falling back to the WSManFault `Code` attribute if present.
fn extract_subcode_value(xml: &str) -> Option<String> {
    // Look for <Subcode>…<Value>X</Value>…</Subcode>
    let sub_start = xml.find("Subcode>")?;
    let rest = &xml[sub_start..];
    let inner = extract_element_text(rest, "Value")?;
    if inner.is_empty() {
        return None;
    }
    Some(inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_shell_id_from_response() {
        let xml = r"<s:Envelope><s:Body><rsp:Shell>
            <rsp:ShellId>ABC-DEF-123</rsp:ShellId>
        </rsp:Shell></s:Body></s:Envelope>";
        let id = parse_shell_id(xml).unwrap();
        assert_eq!(id, "ABC-DEF-123");
    }

    #[test]
    fn parse_command_id_from_response() {
        let xml = r"<s:Envelope><s:Body><rsp:CommandResponse>
            <rsp:CommandId>CMD-456</rsp:CommandId>
        </rsp:CommandResponse></s:Body></s:Envelope>";
        let id = parse_command_id(xml).unwrap();
        assert_eq!(id, "CMD-456");
    }

    #[test]
    fn parse_receive_output_with_streams() {
        // "hello" base64 = "aGVsbG8="
        // "err" base64 = "ZXJy"
        let xml = r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
            <rsp:Stream Name="stdout" CommandId="C1">aGVsbG8=</rsp:Stream>
            <rsp:Stream Name="stderr" CommandId="C1">ZXJy</rsp:Stream>
            <rsp:CommandState CommandId="C1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                <rsp:ExitCode>0</rsp:ExitCode>
            </rsp:CommandState>
        </rsp:ReceiveResponse></s:Body></s:Envelope>"#;

        let output = parse_receive_output(xml).unwrap();
        assert_eq!(output.stdout, b"hello");
        assert_eq!(output.stderr, b"err");
        assert_eq!(output.exit_code, Some(0));
        assert!(output.done);
    }

    #[test]
    fn parse_receive_output_not_done() {
        let xml = r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
            <rsp:Stream Name="stdout" CommandId="C1">dGVzdA==</rsp:Stream>
            <rsp:CommandState CommandId="C1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Running"/>
        </rsp:ReceiveResponse></s:Body></s:Envelope>"#;

        let output = parse_receive_output(xml).unwrap();
        assert_eq!(output.stdout, b"test");
        assert!(!output.done);
        assert!(output.exit_code.is_none());
    }

    #[test]
    fn detect_soap_fault() {
        let xml = r"<s:Envelope><s:Body><s:Fault>
            <s:Code><s:Value>s:Receiver</s:Value></s:Code>
            <s:Reason><s:Text>Access denied</s:Text></s:Reason>
        </s:Fault></s:Body></s:Envelope>";

        let result = check_soap_fault(xml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            SoapError::Fault { code, reason } => {
                assert_eq!(code, "s:Receiver");
                assert_eq!(reason, "Access denied");
            }
            _ => panic!("expected SoapFault"),
        }
    }

    #[test]
    fn extract_attribute_works() {
        let tag = r#"<rsp:Stream Name="stdout" CommandId="C1""#;
        assert_eq!(extract_attribute(tag, "Name"), Some("stdout".into()));
        assert_eq!(extract_attribute(tag, "CommandId"), Some("C1".into()));
        assert_eq!(extract_attribute(tag, "Missing"), None);
    }

    #[test]
    fn parse_receive_output_with_soap_fault() {
        let xml = r"<s:Envelope><s:Body>
            <s:Fault>
                <s:Code><s:Value>s:Sender</s:Value></s:Code>
                <s:Reason><s:Text>Invalid input</s:Text></s:Reason>
            </s:Fault>
        </s:Body></s:Envelope>";
        let result = parse_receive_output(xml);
        assert!(result.is_err());
    }

    #[test]
    fn check_soap_fault_no_fault() {
        let xml = r"<s:Envelope><s:Body><Data>ok</Data></s:Body></s:Envelope>";
        assert!(check_soap_fault(xml).is_ok());
    }

    #[test]
    fn extract_element_text_closing_tag_first() {
        // Test where closing tag appears before opening tag
        let xml = r"</rsp:ShellId><rsp:ShellId>ABC</rsp:ShellId>";
        let result = parse_shell_id(xml).unwrap();
        assert_eq!(result, "ABC");
    }

    #[test]
    fn extract_element_text_empty_content() {
        let xml = r"<rsp:ShellId></rsp:ShellId>";
        assert!(parse_shell_id(xml).is_err());
    }

    #[test]
    fn extract_streams_empty_stream() {
        // Stream with empty content should be skipped
        let xml = r#"<rsp:Stream Name="stdout" CommandId="C1"></rsp:Stream>"#;
        let streams = extract_streams(xml);
        assert!(streams.is_empty());
    }

    #[test]
    fn parse_receive_output_non_base64_stream() {
        let xml = r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
            <rsp:Stream Name="stdout" CommandId="C1">!!!not-base64!!!</rsp:Stream>
        </rsp:ReceiveResponse></s:Body></s:Envelope>"#;
        let result = parse_receive_output(xml);
        assert!(result.is_err());
    }

    #[test]
    fn soap_error_display() {
        let e = SoapError::MissingElement("ShellId".into());
        assert_eq!(format!("{e}"), "missing element: ShellId");

        let e = SoapError::ParseError("bad data".into());
        assert_eq!(format!("{e}"), "parse error: bad data");

        let e = SoapError::Fault {
            code: "s:Sender".into(),
            reason: "bad".into(),
        };
        assert_eq!(format!("{e}"), "SOAP fault [s:Sender]: bad");
    }

    #[test]
    fn extract_streams_bare_tag() {
        // Test with bare <Stream> (no namespace prefix)
        let xml = r#"<Stream Name="stdout">aGVsbG8=</Stream>"#;
        let streams = extract_streams(xml);
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].0, "stdout");
    }

    #[test]
    fn detect_soap_fault_with_legacy_tags() {
        let xml = r"<Fault><faultcode>s:Client</faultcode><faultstring>oops</faultstring></Fault>";
        let result = check_soap_fault(xml);
        assert!(result.is_err());
    }

    #[test]
    fn extract_streams_bare_before_namespaced() {
        // Both <Stream and <rsp:Stream in same XML, bare tag appears first.
        let xml =
            r#"<Stream Name="stdout">aGVsbG8=</Stream><rsp:Stream Name="stderr">ZXJy</rsp:Stream>"#;
        let streams = extract_streams(xml);
        assert_eq!(streams.len(), 2);
        assert_eq!(streams[0].0, "stdout");
        assert_eq!(streams[1].0, "stderr");
    }

    #[test]
    fn extract_streams_namespaced_before_bare_close() {
        // <rsp:Stream> with content closed by </Stream> (bare close appearing before </rsp:Stream>)
        let xml = r#"<rsp:Stream Name="stdout">dGVzdA==</Stream></rsp:Stream>"#;
        let streams = extract_streams(xml);
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].0, "stdout");
    }

    #[test]
    fn parse_receive_output_no_exit_code() {
        let xml = r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
            <rsp:CommandState CommandId="C1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"/>
        </rsp:ReceiveResponse></s:Body></s:Envelope>"#;
        let output = parse_receive_output(xml).unwrap();
        assert!(output.done);
        assert!(output.exit_code.is_none());
        assert!(output.stdout.is_empty());
    }

    // --- Mutant-killing tests ---

    #[test]
    fn extract_element_text_skips_empty_finds_second() {
        let xml = r"<rsp:ShellId></rsp:ShellId><rsp:ShellId>FOUND</rsp:ShellId>";
        assert_eq!(parse_shell_id(xml).unwrap(), "FOUND");
    }

    #[test]
    fn extract_element_bare_element() {
        let xml = r"<ShellId>BARE-ID</ShellId>";
        assert_eq!(parse_shell_id(xml).unwrap(), "BARE-ID");
    }

    #[test]
    fn parse_receive_output_multiple_stdout_chunks() {
        // "hel" = aGVs, "lo" = bG8=
        let xml = r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
            <rsp:Stream Name="stdout" CommandId="C1">aGVs</rsp:Stream>
            <rsp:Stream Name="stdout" CommandId="C1">bG8=</rsp:Stream>
            <rsp:CommandState CommandId="C1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                <rsp:ExitCode>0</rsp:ExitCode>
            </rsp:CommandState>
        </rsp:ReceiveResponse></s:Body></s:Envelope>"#;
        let output = parse_receive_output(xml).unwrap();
        assert_eq!(output.stdout, b"hello");
    }

    #[test]
    fn parse_receive_output_interleaved_streams() {
        // "AB" = QUI=, "err" = ZXJy, "CD" = Q0Q=
        let xml = r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
            <rsp:Stream Name="stdout" CommandId="C1">QUI=</rsp:Stream>
            <rsp:Stream Name="stderr" CommandId="C1">ZXJy</rsp:Stream>
            <rsp:Stream Name="stdout" CommandId="C1">Q0Q=</rsp:Stream>
            <rsp:CommandState CommandId="C1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                <rsp:ExitCode>1</rsp:ExitCode>
            </rsp:CommandState>
        </rsp:ReceiveResponse></s:Body></s:Envelope>"#;
        let output = parse_receive_output(xml).unwrap();
        assert_eq!(output.stdout, b"ABCD");
        assert_eq!(output.stderr, b"err");
        assert_eq!(output.exit_code, Some(1));
    }

    #[test]
    fn extract_element_text_multiple_closing_before_opening() {
        let xml = r"</rsp:CommandId></rsp:CommandId><rsp:CommandId>REAL-CMD</rsp:CommandId>";
        assert_eq!(parse_command_id(xml).unwrap(), "REAL-CMD");
    }

    #[test]
    fn extract_streams_three_sequential() {
        // "A" = QQ==, "B" = Qg==, "C" = Qw==
        let xml = r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
            <rsp:Stream Name="stdout" CommandId="C1">QQ==</rsp:Stream>
            <rsp:Stream Name="stderr" CommandId="C1">Qg==</rsp:Stream>
            <rsp:Stream Name="stdout" CommandId="C1">Qw==</rsp:Stream>
            <rsp:CommandState CommandId="C1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                <rsp:ExitCode>0</rsp:ExitCode>
            </rsp:CommandState>
        </rsp:ReceiveResponse></s:Body></s:Envelope>"#;
        let output = parse_receive_output(xml).unwrap();
        assert_eq!(output.stdout, b"AC");
        assert_eq!(output.stderr, b"B");
    }

    #[test]
    fn extract_element_text_trims_whitespace() {
        let xml = r"<rsp:ShellId>  TRIMMED  </rsp:ShellId>";
        assert_eq!(parse_shell_id(xml).unwrap(), "TRIMMED");
    }

    #[test]
    fn parse_receive_output_negative_exit_code() {
        let xml = r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
            <rsp:CommandState CommandId="C1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                <rsp:ExitCode>-1</rsp:ExitCode>
            </rsp:CommandState>
        </rsp:ReceiveResponse></s:Body></s:Envelope>"#;
        let output = parse_receive_output(xml).unwrap();
        assert!(output.done);
        assert_eq!(output.exit_code, Some(-1));
    }

    #[test]
    fn parse_receive_output_non_numeric_exit_code() {
        let xml = r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
            <rsp:CommandState CommandId="C1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                <rsp:ExitCode>notanumber</rsp:ExitCode>
            </rsp:CommandState>
        </rsp:ReceiveResponse></s:Body></s:Envelope>"#;
        let output = parse_receive_output(xml).unwrap();
        assert!(output.done);
        assert!(output.exit_code.is_none());
    }

    #[test]
    fn extract_element_text_at_end_of_string() {
        let xml = "<rsp:CommandId>VAL</rsp:CommandId>";
        assert_eq!(parse_command_id(xml).unwrap(), "VAL");
    }

    #[test]
    fn extract_element_bare_at_start_of_string() {
        let xml = "<CommandId>START-ID</CommandId>";
        assert_eq!(parse_command_id(xml).unwrap(), "START-ID");
    }

    #[test]
    fn extract_element_bare_with_prefix_text() {
        let xml = "X<ShellId>OFFSET-ID</ShellId>";
        assert_eq!(parse_shell_id(xml).unwrap(), "OFFSET-ID");
    }

    #[test]
    fn extract_streams_at_end_of_string() {
        // "ok" = b2s=
        let xml = r#"<rsp:Stream Name="stdout" CommandId="C1">b2s=</rsp:Stream>"#;
        let streams = extract_streams(xml);
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].0, "stdout");
    }

    #[test]
    fn extract_streams_rsp_before_bare_picks_first() {
        // "A" = QQ==, "B" = Qg==
        let xml =
            r#"<rsp:Stream Name="stdout">QQ==</rsp:Stream> <Stream Name="stderr">Qg==</Stream>"#;
        let streams = extract_streams(xml);
        assert_eq!(streams.len(), 2);
        assert_eq!(streams[0].0, "stdout");
        assert_eq!(streams[0].1, "QQ==");
        assert_eq!(streams[1].0, "stderr");
        assert_eq!(streams[1].1, "Qg==");
    }

    #[test]
    fn extract_streams_close_tag_ordering() {
        // "X" = WA==
        let xml = r#"<rsp:Stream Name="stdout">WA==</Stream>extra</rsp:Stream>"#;
        let streams = extract_streams(xml);
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].1, "WA==");
    }

    #[test]
    fn extract_streams_adjacent_streams_search_from_advance() {
        // "X" = WA==, "Y" = WQ==
        let xml = r#"<rsp:Stream Name="stdout">WA==</rsp:Stream><rsp:Stream Name="stderr">WQ==</rsp:Stream>"#;
        let streams = extract_streams(xml);
        assert_eq!(streams.len(), 2, "both adjacent streams must be found");
        assert_eq!(streams[0].0, "stdout");
        assert_eq!(streams[0].1, "WA==");
        assert_eq!(streams[1].0, "stderr");
        assert_eq!(streams[1].1, "WQ==");
    }

    #[test]
    fn extract_streams_three_adjacent_with_content() {
        // "A" = QQ==, "B" = Qg==, "C" = Qw==
        let xml = r#"<rsp:Stream Name="stdout">QQ==</rsp:Stream><rsp:Stream Name="stderr">Qg==</rsp:Stream><rsp:Stream Name="stdout">Qw==</rsp:Stream>"#;
        let streams = extract_streams(xml);
        assert_eq!(streams.len(), 3, "all three adjacent streams must be found");
        assert_eq!(streams[0].1, "QQ==");
        assert_eq!(streams[1].1, "Qg==");
        assert_eq!(streams[2].1, "Qw==");
    }

    #[test]
    fn extract_element_text_empty_then_filled_tight() {
        let xml = "<rsp:ShellId></rsp:ShellId><rsp:ShellId>OK</rsp:ShellId>";
        assert_eq!(parse_shell_id(xml).unwrap(), "OK");
    }

    #[test]
    fn parse_receive_output_stream_at_xml_end() {
        // "Z" = Wg==
        let xml = r#"<s:Envelope><s:Body><rsp:ReceiveResponse><rsp:Stream Name="stdout" CommandId="C1">Wg==</rsp:Stream><rsp:CommandState CommandId="C1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"><rsp:ExitCode>0</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse></s:Body></s:Envelope>"#;
        let output = parse_receive_output(xml).unwrap();
        assert_eq!(output.stdout, b"Z");
        assert_eq!(output.exit_code, Some(0));
        assert!(output.done);
    }

    // --- Phase 8 tests ---

    #[test]
    fn extract_streams_long_content_with_second_stream() {
        let long_b64 = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB"; // 40 chars
        let xml = format!(
            r#"<rsp:Stream Name="stdout">{long_b64}</rsp:Stream><rsp:Stream Name="stderr">ZXJy</rsp:Stream>"#
        );
        let streams = extract_streams(&xml);
        assert_eq!(streams.len(), 2, "must find both streams with long content");
        assert_eq!(streams[0].0, "stdout");
        assert_eq!(streams[0].1, long_b64);
        assert_eq!(streams[1].0, "stderr");
        assert_eq!(streams[1].1, "ZXJy");
    }

    #[test]
    fn parse_receive_output_long_stdout_with_stderr() {
        let long_b64 = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB";
        let xml = format!(
            r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                <rsp:Stream Name="stdout" CommandId="C1">{long_b64}</rsp:Stream>
                <rsp:Stream Name="stderr" CommandId="C1">ZXJy</rsp:Stream>
                <rsp:CommandState CommandId="C1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                    <rsp:ExitCode>0</rsp:ExitCode>
                </rsp:CommandState>
            </rsp:ReceiveResponse></s:Body></s:Envelope>"#
        );
        let output = parse_receive_output(&xml).unwrap();
        assert_eq!(output.stdout.len(), 30, "should decode 30 bytes of stdout");
        assert_eq!(output.stderr, b"err", "should decode stderr correctly");
        assert_eq!(output.exit_code, Some(0));
    }

    #[test]
    fn parse_clixml_basic_error() {
        let input = b"#< CLIXML\r\n<Objs Version=\"1.1.0.1\" xmlns=\"http://schemas.microsoft.com/powershell/2004/04\"><S S=\"Error\">Something went wrong</S></Objs>";
        let result = parse_clixml(input);
        assert_eq!(String::from_utf8_lossy(&result), "Something went wrong");
    }

    #[test]
    fn parse_clixml_escaped_newlines() {
        let input = b"#< CLIXML\r\n<Objs><S S=\"Error\">line1_x000D__x000A_line2</S></Objs>";
        let result = parse_clixml(input);
        assert_eq!(String::from_utf8_lossy(&result), "line1\r\nline2");
    }

    #[test]
    fn parse_clixml_multiple_errors() {
        let input = b"#< CLIXML\r\n<Objs><S S=\"Error\">err1</S><S S=\"Error\">err2</S></Objs>";
        let result = parse_clixml(input);
        assert_eq!(String::from_utf8_lossy(&result), "err1err2");
    }

    #[test]
    fn parse_clixml_not_clixml_passthrough() {
        // Non-CLIXML data should return empty (no <S S="Error"> tags)
        let input = b"plain error text without CLIXML";
        let result = parse_clixml(input);
        assert!(result.is_empty());
    }

    #[test]
    fn parse_receive_output_clixml_stderr() {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD as B64;

        let clixml = b"#< CLIXML\r\n<Objs><S S=\"Error\">PowerShell error_x000D__x000A_</S></Objs>";
        let encoded = B64.encode(clixml);
        let xml = format!(
            r#"<rsp:ReceiveResponse><rsp:Stream Name="stderr">{encoded}</rsp:Stream><rsp:CommandState State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"><rsp:ExitCode>1</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse>"#
        );
        let output = parse_receive_output(&xml).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&output.stderr),
            "PowerShell error\r\n"
        );
        assert_eq!(output.exit_code, Some(1));
    }

    // Kills extract_subcode_value returning None
    #[test]
    fn extract_subcode_from_soap_fault() {
        let xml = r"<s:Fault>
            <s:Code><s:Value>s:Sender</s:Value>
            <s:Subcode><s:Value>wsa:DestinationUnreachable</s:Value></s:Subcode></s:Code>
            <s:Reason><s:Text>no route</s:Text></s:Reason></s:Fault>";
        let val = extract_subcode_value(xml);
        assert_eq!(val.as_deref(), Some("wsa:DestinationUnreachable"));
    }

    // Kills extract_element_text:180 — < → <= on search_from
    #[test]
    fn extract_element_text_exact_boundary() {
        // Element at the very end of the string
        let xml = "<Root><Name>val</Name></Root>";
        assert_eq!(extract_element_text(xml, "Name").as_deref(), Some("val"));
    }

    // Kills extract_streams:227 — < → <= on search_from
    #[test]
    fn extract_streams_at_string_boundary() {
        // Streams that extend to the end of the XML
        let xml = r#"<rsp:Stream Name="stdout">YWJD</rsp:Stream>"#;
        let streams = extract_streams(xml);
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].0, "stdout");
        assert_eq!(streams[0].1, "YWJD");
    }

    // Tests parse_enumerate_response with and without continuation context
    #[test]
    fn parse_enumerate_response_with_items_and_end() {
        let xml = r#"<s:Envelope xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
            <s:Body><wsen:EnumerateResponse>
                <wsen:Items><data>hello</data></wsen:Items>
                <wsen:EndOfSequence/>
            </wsen:EnumerateResponse></s:Body></s:Envelope>"#;
        let (items, context) = parse_enumerate_response(xml).unwrap();
        assert!(items.contains("hello"));
        assert!(context.is_none(), "EndOfSequence means no continuation");
    }

    #[test]
    fn parse_enumerate_response_with_continuation() {
        let xml = r#"<s:Envelope xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
            <s:Body><wsen:EnumerateResponse>
                <wsen:Items><data>page1</data></wsen:Items>
                <wsen:EnumerationContext>ctx-123</wsen:EnumerationContext>
            </wsen:EnumerateResponse></s:Body></s:Envelope>"#;
        let (items, context) = parse_enumerate_response(xml).unwrap();
        assert!(items.contains("page1"));
        assert_eq!(context.as_deref(), Some("ctx-123"));
    }

    // parse_clixml with multiple error fragments to test offset arithmetic
    #[test]
    fn parse_clixml_consecutive_error_fragments() {
        let clixml = b"#< CLIXML\r\n<Objs><S S=\"Error\">aaa</S><S S=\"Error\">bbb</S></Objs>";
        let result = parse_clixml(clixml);
        assert_eq!(String::from_utf8_lossy(&result), "aaabbb");
    }

    #[test]
    fn parse_command_id_missing_returns_missing_element() {
        let xml = r"<s:Envelope><s:Body><something/></s:Body></s:Envelope>";
        let err = parse_command_id(xml).unwrap_err();
        assert!(matches!(err, SoapError::MissingElement(_)));
    }

    #[test]
    fn extract_soap_fault_falls_back_to_faultstring() {
        // Older SOAP 1.1 style fault uses <faultcode>/<faultstring>.
        let xml = r"<s:Envelope><s:Body><s:Fault>
            <faultcode>soap:Server</faultcode>
            <faultstring>old style</faultstring>
        </s:Fault></s:Body></s:Envelope>";
        let fault = extract_soap_fault(xml).expect("fault parsed");
        match fault {
            SoapError::Fault { code, reason } => {
                assert_eq!(code, "soap:Server");
                assert_eq!(reason, "old style");
            }
            _ => panic!("expected Fault variant"),
        }
    }

    #[test]
    fn extract_soap_fault_returns_none_when_absent() {
        let xml = "<s:Envelope><s:Body><something/></s:Body></s:Envelope>";
        assert!(extract_soap_fault(xml).is_none());
    }

    #[test]
    fn extract_subcode_value_empty_returns_none() {
        // Subcode element exists but Value is empty.
        let xml = r"<s:Subcode><s:Value></s:Value></s:Subcode>";
        assert!(extract_subcode_value(xml).is_none());
    }

    #[test]
    fn parse_enumerate_response_handles_empty_items() {
        let xml = r#"<s:Envelope xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
            <s:Body><wsen:EnumerateResponse>
                <wsen:EndOfSequence/>
            </wsen:EnumerateResponse></s:Body></s:Envelope>"#;
        let (items, context) = parse_enumerate_response(xml).unwrap();
        assert!(items.is_empty(), "no <Items> tag should yield empty");
        assert!(context.is_none());
    }
}
