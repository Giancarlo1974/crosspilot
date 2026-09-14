//! WS-Management namespace URIs and protocol constants.

/// WinRS command shell resource URI.
pub(crate) const RESOURCE_URI_CMD: &str =
    "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd";

/// PowerShell remoting plugin resource URI (the default PS configuration).
pub const RESOURCE_URI_PSRP: &str = "http://schemas.microsoft.com/powershell/Microsoft.PowerShell";

/// SOAP action for shell creation.
pub(crate) const ACTION_CREATE: &str = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create";

/// SOAP action for shell deletion.
pub(crate) const ACTION_DELETE: &str = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete";

/// SOAP action for command execution.
pub(crate) const ACTION_COMMAND: &str =
    "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command";

/// SOAP action for output polling.
pub(crate) const ACTION_RECEIVE: &str =
    "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive";

/// SOAP action for signal delivery.
pub(crate) const ACTION_SIGNAL: &str =
    "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal";

/// SOAP action for input delivery.
pub(crate) const ACTION_SEND: &str = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Send";

/// SOAP action for shell disconnect (leave server-side shell alive).
pub(crate) const ACTION_DISCONNECT: &str =
    "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Disconnect";

/// SOAP action for shell reconnect.
pub(crate) const ACTION_RECONNECT: &str =
    "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Reconnect";

/// Signal code: terminate command.
pub(crate) const SIGNAL_TERMINATE: &str =
    "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate";

/// Signal code: Ctrl+C.
pub(crate) const SIGNAL_CTRL_C: &str =
    "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/ctrl_c";

/// Command state indicating completion.
pub(crate) const COMMAND_STATE_DONE: &str =
    "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done";

/// Anonymous reply-to address.
pub(crate) const REPLY_TO_ANONYMOUS: &str =
    "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous";

/// WMI resource URI for WQL queries (root/cimv2 wildcard).
pub(crate) const RESOURCE_URI_WMI: &str =
    "http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/*";

/// SOAP action for WS-Enumeration Enumerate request.
pub(crate) const ACTION_ENUMERATE: &str =
    "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate";

/// SOAP action for WS-Enumeration Pull request.
pub(crate) const ACTION_PULL: &str = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull";

/// WQL filter dialect URI.
pub(crate) const WQL_DIALECT: &str = "http://schemas.microsoft.com/wbem/wsman/1/WQL";
