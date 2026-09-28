using Verifiable.Cryptography.Text;

namespace Verifiable.Core.Mcp;

/// <summary>
/// The closed current error catalog, with revision-aware rules and situation-specific status metadata.
/// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#error-codes">Error Codes</see>:
/// "MCP defines the following error codes:"
/// </summary>
/// <remarks>
/// MCP 2026-07-28 is the current revision.
/// <see cref="IsDefinedIn(int, McpProtocolRevision)"/> also identifies the two codes defined in
/// 2025-11-25 and retired in the current revision. They are deliberately absent from the current catalog.
/// <see cref="IsForbiddenIn(int, McpProtocolRevision)"/> describes allocation for new implementations,
/// including the current revision's SHOULD NOT for the legacy sub-range. A false answer is not permission
/// to emit a code in an arbitrary situation. Unknown revisions are unjudged by both predicates.
/// </remarks>
public sealed record McpErrorCode
{
    /// <summary>
    /// The UTF-8 source of <see cref="ParseError"/>'s <see cref="Name"/>.
    /// <see href="https://www.jsonrpc.org/specification#error_object">Error definition</see>: "Invalid JSON was received by the server."
    /// </summary>
    private static ReadOnlySpan<byte> ParseErrorNameUtf8 => "Parse error"u8;

    /// <summary>
    /// The Parse error error (-32700), with <see cref="Name"/> interned from <see cref="ParseErrorNameUtf8"/>.
    /// <see href="https://www.jsonrpc.org/specification#error_object">Error definition</see>: "Invalid JSON was received by the server."
    /// </summary>
    public static McpErrorCode ParseError { get; } = new(-32700, ParseErrorNameUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="InvalidRequest"/>'s <see cref="Name"/>.
    /// <see href="https://www.jsonrpc.org/specification#error_object">Error definition</see>: "The JSON sent is not a valid Request object."
    /// </summary>
    private static ReadOnlySpan<byte> InvalidRequestNameUtf8 => "Invalid Request"u8;

    /// <summary>
    /// The Invalid Request error (-32600), with <see cref="Name"/> interned from <see cref="InvalidRequestNameUtf8"/>.
    /// <see href="https://www.jsonrpc.org/specification#error_object">Error definition</see>: "The JSON sent is not a valid Request object."
    /// </summary>
    public static McpErrorCode InvalidRequest { get; } = new(-32600, InvalidRequestNameUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="MethodNotFound"/>'s <see cref="Name"/>.
    /// <see href="https://www.jsonrpc.org/specification#error_object">Error definition</see>: "The method does not exist / is not available."
    /// </summary>
    private static ReadOnlySpan<byte> MethodNotFoundNameUtf8 => "Method not found"u8;

    /// <summary>
    /// The Method not found error (-32601), with <see cref="Name"/> interned from <see cref="MethodNotFoundNameUtf8"/>.
    /// <see href="https://www.jsonrpc.org/specification#error_object">Error definition</see>: "The method does not exist / is not available."
    /// </summary>
    public static McpErrorCode MethodNotFound { get; } = new(-32601, MethodNotFoundNameUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="InvalidParams"/>'s <see cref="Name"/>.
    /// <see href="https://www.jsonrpc.org/specification#error_object">Error definition</see>: "Invalid method parameter(s)."
    /// </summary>
    private static ReadOnlySpan<byte> InvalidParamsNameUtf8 => "Invalid params"u8;

    /// <summary>
    /// The Invalid params error (-32602), with <see cref="Name"/> interned from <see cref="InvalidParamsNameUtf8"/>.
    /// <see href="https://www.jsonrpc.org/specification#error_object">Error definition</see>: "Invalid method parameter(s)."
    /// </summary>
    public static McpErrorCode InvalidParams { get; } = new(-32602, InvalidParamsNameUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="InternalError"/>'s <see cref="Name"/>.
    /// <see href="https://www.jsonrpc.org/specification#error_object">Error definition</see>: "Internal JSON-RPC error."
    /// </summary>
    private static ReadOnlySpan<byte> InternalErrorNameUtf8 => "Internal error"u8;

    /// <summary>
    /// The Internal error error (-32603), with <see cref="Name"/> interned from <see cref="InternalErrorNameUtf8"/>.
    /// <see href="https://www.jsonrpc.org/specification#error_object">Error definition</see>: "Internal JSON-RPC error."
    /// </summary>
    public static McpErrorCode InternalError { get; } = new(-32603, InternalErrorNameUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="HeaderMismatch"/>'s <see cref="Name"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#error-codes">Error definition</see>: "MCP defines the following error codes:"
    /// </summary>
    private static ReadOnlySpan<byte> HeaderMismatchNameUtf8 => "HeaderMismatch"u8;

    /// <summary>
    /// The HeaderMismatch error (-32020), with <see cref="Name"/> interned from <see cref="HeaderMismatchNameUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#error-codes">Error definition</see>: "MCP defines the following error codes:"
    /// </summary>
    public static McpErrorCode HeaderMismatch { get; } = new(-32020, HeaderMismatchNameUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="MissingRequiredClientCapability"/>'s <see cref="Name"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#error-codes">Error definition</see>: "MCP defines the following error codes:"
    /// </summary>
    private static ReadOnlySpan<byte> MissingRequiredClientCapabilityNameUtf8 => "MissingRequiredClientCapability"u8;

    /// <summary>
    /// The MissingRequiredClientCapability error (-32021), with <see cref="Name"/> interned from <see cref="MissingRequiredClientCapabilityNameUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#error-codes">Error definition</see>: "MCP defines the following error codes:"
    /// </summary>
    public static McpErrorCode MissingRequiredClientCapability { get; } = new(-32021, MissingRequiredClientCapabilityNameUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="UnsupportedProtocolVersion"/>'s <see cref="Name"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#error-codes">Error definition</see>: "MCP defines the following error codes:"
    /// </summary>
    private static ReadOnlySpan<byte> UnsupportedProtocolVersionNameUtf8 => "UnsupportedProtocolVersion"u8;

    /// <summary>
    /// The UnsupportedProtocolVersion error (-32022), with <see cref="Name"/> interned from <see cref="UnsupportedProtocolVersionNameUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#error-codes">Error definition</see>: "MCP defines the following error codes:"
    /// </summary>
    public static McpErrorCode UnsupportedProtocolVersion { get; } = new(-32022, UnsupportedProtocolVersionNameUtf8);

    /// <summary>
    /// The integer identifier of this error, used by <see cref="HttpStatusIn"/>.
    /// <see href="https://www.jsonrpc.org/specification#error_object">JSON-RPC 2.0 §5.1</see>:
    /// "A Number that indicates the error type that occurred."
    /// </summary>
    public int Code { get; }


    /// <summary>
    /// The interned defining name derived from <see cref="NameUtf8"/>; callers may choose a more detailed error message.
    /// <see href="https://www.jsonrpc.org/specification#error_object">JSON-RPC 2.0 §5.1</see>:
    /// "A String providing a short description of the error."
    /// </summary>
    public string Name { get; }


    /// <summary>
    /// The defining UTF-8 literal whose interned string is <see cref="Name"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#error-codes">Error Codes</see>:
    /// "MCP defines the following error codes:"
    /// </summary>
    public ReadOnlySpan<byte> NameUtf8 => Code switch
    {
        -32700 => ParseErrorNameUtf8,
        -32600 => InvalidRequestNameUtf8,
        -32601 => MethodNotFoundNameUtf8,
        -32602 => InvalidParamsNameUtf8,
        -32603 => InternalErrorNameUtf8,
        -32020 => HeaderMismatchNameUtf8,
        -32021 => MissingRequiredClientCapabilityNameUtf8,
        -32022 => UnsupportedProtocolVersionNameUtf8,
        _ => default
    };


    /// <summary>
    /// Creates a catalog value with an interned <see cref="Name"/> from its UTF-8 literal.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#error-codes">Error Codes</see>:
    /// "MCP defines the following error codes:"
    /// </summary>
    /// <param name="code">The defining integer identifier.</param>
    /// <param name="name">The UTF-8 spelling of the defining name.</param>
    private McpErrorCode(int code, ReadOnlySpan<byte> name)
    {
        Code = code;
        Name = Utf8Constants.ToInternedString(name);
    }


    /// <summary>
    /// Whether <see cref="Code"/> is defined by the named revision, using <see cref="IsDefinedIn(int, McpProtocolRevision)"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#error-codes">Error Codes</see>:
    /// "MCP defines the following error codes:"
    /// </summary>
    /// <param name="revision">The revision whose known definitions are queried.</param>
    public bool IsDefinedIn(McpProtocolRevision revision) => IsDefinedIn(Code, revision);


    /// <summary>
    /// Whether the named revision forbids new use of <see cref="Code"/>, using <see cref="IsForbiddenIn(int, McpProtocolRevision)"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#error-codes">Error Codes</see>:
    /// "Implementations of this protocol version MUST NOT emit these codes:"
    /// </summary>
    /// <param name="revision">The revision whose known allocation rules are queried.</param>
    public bool IsForbiddenIn(McpProtocolRevision revision) => IsForbiddenIn(Code, revision);


    /// <summary>
    /// Whether a raw code has a defined meaning in one of the two cataloged revisions.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#error-codes">Error Codes</see>:
    /// "MCP uses the standard JSON-RPC 2.0 error codes (-32700, -32600 to -32603) for general protocol failures."
    /// The same section names "resource not found (2025-11-25 and earlier; replaced by -32602)"
    /// and "URL elicitation required (2025-11-25 only)."
    /// </summary>
    /// <param name="code">A received or proposed integer error code.</param>
    /// <param name="revision">The revision; an unknown or default revision has no cataloged definitions.</param>
    public static bool IsDefinedIn(int code, McpProtocolRevision revision) => revision switch
    {
        var r when r == McpProtocolRevision.Revision20260728 => code is -32700 or -32600 or -32601 or -32602 or -32603 or -32020 or -32021 or -32022,
        var r when r == McpProtocolRevision.Revision20251125 => code is -32700 or -32600 or -32601 or -32602 or -32603 or -32002 or -32042,
        _ => false
    };


    /// <summary>
    /// Whether a raw code is unavailable for new use under a cataloged revision's allocation rules.
    /// <see href="https://www.jsonrpc.org/specification#error_object">JSON-RPC 2.0 §5.1</see>:
    /// "Any code within this range, but not defined explicitly below is reserved for future use."
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#error-codes">Error Codes</see>:
    /// "New codes MUST NOT be allocated in this sub-range, and new implementations SHOULD NOT use codes from this sub-range at all."
    /// "Implementations MUST NOT emit any code from this sub-range that is not defined by this specification and MUST use defined codes only with their specified meanings."
    /// For 2026-07-28, the first sentence applies to -32000 through -32019 and the second to -32020 through -32099;
    /// together they include the explicitly retired -32002 and -32042. JSON-RPC reserves the remaining undefined codes
    /// from -32768 through -32100 in both revisions. A false result for an unknown revision is unjudged, not permission.
    /// </summary>
    /// <param name="code">The integer code proposed for new use.</param>
    /// <param name="revision">The revision whose allocation rules are queried.</param>
    public static bool IsForbiddenIn(int code, McpProtocolRevision revision) => revision switch
    {
        var r when r == McpProtocolRevision.Revision20260728 => code is >= -32768 and <= -32000 && !IsDefinedIn(code, revision),
        var r when r == McpProtocolRevision.Revision20251125 => code is >= -32768 and <= -32100 && !IsDefinedIn(code, revision),
        _ => false
    };


    /// <summary>
    /// The status explicitly paired with this code and <see cref="McpErrorSituation"/>, or null when unspecified.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#protocol-version-header">Protocol Version Header</see>:
    /// "If the server does not implement the requested RPC method, it MUST respond with 404 Not Found and a JSON-RPC error with code -32601 (Method not found)."
    /// For unsupported versions the same section requires "400 Bad Request" and an "UnsupportedProtocolVersionError".
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#server-validation">Server Validation</see>:
    /// "When rejecting a request due to header validation failure, servers MUST return HTTP status 400 Bad Request and MUST include a JSON-RPC error response using the following error code:"
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">Metadata</see>:
    /// "A request missing any required field is malformed; the server MUST reject it with JSON-RPC error code -32602 (Invalid params). On HTTP, the response status MUST be 400 Bad Request."
    /// The missing-client-capability rule in that section also states: "On HTTP, the response status MUST be 400 Bad Request."
    /// The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// Every 2025-11-25 answer is null, as are unknown revisions, mismatched code/situation pairs and a null situation.
    /// </summary>
    /// <param name="revision">The revision under which the request is processed.</param>
    /// <param name="situation">The failure that triggered the error.</param>
    /// <returns>The specified status as data, without emitting a response.</returns>
    public int? HttpStatusIn(McpProtocolRevision revision, McpErrorSituation? situation) => (revision, Code, situation) switch
    {
        (var r, -32601, var s) when r == McpProtocolRevision.Revision20260728 && s == McpErrorSituation.UnknownMethod => 404,
        (var r, -32020, var s) when r == McpProtocolRevision.Revision20260728 && s == McpErrorSituation.HeaderMismatch => 400,
        (var r, -32021, var s) when r == McpProtocolRevision.Revision20260728 && s == McpErrorSituation.MissingRequiredClientCapability => 400,
        (var r, -32022, var s) when r == McpProtocolRevision.Revision20260728 && s == McpErrorSituation.UnsupportedProtocolVersion => 400,
        (var r, -32602, var s) when r == McpProtocolRevision.Revision20260728 && s == McpErrorSituation.MissingRequiredMetaField => 400,
        _ => null
    };
}


/// <summary>
/// A closed failure situation that constrains <see cref="McpErrorCode.HttpStatusIn"/>.
/// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">Metadata</see>:
/// "A request missing any required field is malformed; the server MUST reject it with JSON-RPC error code -32602 (Invalid params)."
/// </summary>
/// <remarks>
/// MCP 2026-07-28 is the current revision.
/// </remarks>
public sealed record McpErrorSituation
{
    /// <summary>
    /// A local descriptive name distinguishing situations for <see cref="McpErrorCode.HttpStatusIn"/>; it is not a wire token.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">Metadata</see>:
    /// "A request missing any required field is malformed; the server MUST reject it with JSON-RPC error code -32602 (Invalid params)."
    /// </summary>
    public string Name { get; }


    /// <summary>
    /// Creates a closed situation distinguished by <see cref="Name"/> for status lookup.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">Metadata</see>:
    /// "A request missing any required field is malformed; the server MUST reject it with JSON-RPC error code -32602 (Invalid params)."
    /// </summary>
    /// <param name="name">The local descriptive name, not a wire spelling.</param>
    private McpErrorSituation(string name)
    {
        Name = name;
    }

    /// <summary>
    /// The UnsupportedProtocolVersion situation for <see cref="McpErrorCode.HttpStatusIn"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#protocol-version-header">Failure condition</see>:
    /// "If the server does not implement the requested protocol version (whether the version is unknown to the server, or is a known version the server has chosen not to support), it MUST respond with 400 Bad Request and an UnsupportedProtocolVersionError listing its supported versions."
    /// </summary>
    public static McpErrorSituation UnsupportedProtocolVersion { get; } = new(nameof(UnsupportedProtocolVersion));

    /// <summary>
    /// The HeaderMismatch situation for <see cref="McpErrorCode.HttpStatusIn"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#server-validation">Failure condition</see>: "The HTTP headers do not match the corresponding values in the request body, or required headers are missing/malformed."
    /// </summary>
    public static McpErrorSituation HeaderMismatch { get; } = new(nameof(HeaderMismatch));

    /// <summary>
    /// The MissingRequiredClientCapability situation for <see cref="McpErrorCode.HttpStatusIn"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">Failure condition</see>: "A server MUST NOT rely on capabilities the client has not declared."
    /// </summary>
    public static McpErrorSituation MissingRequiredClientCapability { get; } = new(nameof(MissingRequiredClientCapability));

    /// <summary>
    /// The MissingRequiredMetaField situation for <see cref="McpErrorCode.HttpStatusIn"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">Failure condition</see>: "A request missing any required field is malformed; the server MUST reject it with JSON-RPC error code -32602 (Invalid params)."
    /// </summary>
    public static McpErrorSituation MissingRequiredMetaField { get; } = new(nameof(MissingRequiredMetaField));

    /// <summary>
    /// The UnknownMethod situation for <see cref="McpErrorCode.HttpStatusIn"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#protocol-version-header">Failure condition</see>: "If the server does not implement the requested RPC method, it MUST respond with 404 Not Found and a JSON-RPC error with code -32601 (Method not found)."
    /// </summary>
    public static McpErrorSituation UnknownMethod { get; } = new(nameof(UnknownMethod));
}
