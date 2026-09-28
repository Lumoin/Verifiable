using Verifiable.Cryptography.Text;

namespace Verifiable.Core.Mcp;

/// <summary>
/// Transport field names and encoding markers with UTF-8 twins and <see cref="Equals"/>.
/// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#case-sensitivity">MCP 2026-07-28</see>:
/// "Clients and servers MUST use case-insensitive comparisons for header names."
/// </summary>
/// <remarks>
/// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes. Encoding markers are values
/// and retain the case-sensitive spelling required by <see cref="Base64SentinelPrefix"/>.
/// </remarks>
public static class WellKnownMcpHeaderNames
{
    /// <summary>
    /// The UTF-8 source of <see cref="McpProtocolVersion"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#protocol-version-header">MCP 2026-07-28</see>: "Every POST request to the MCP endpoint MUST include an <c>MCP-Protocol-Version</c> header."
    /// </summary>
    /// <remarks>
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </remarks>
    public static ReadOnlySpan<byte> McpProtocolVersionUtf8 => "MCP-Protocol-Version"u8;

    /// <summary>
    /// The interned spelling derived from <see cref="McpProtocolVersionUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#protocol-version-header">MCP 2026-07-28</see>: "Every POST request to the MCP endpoint MUST include an <c>MCP-Protocol-Version</c> header."
    /// </summary>
    /// <remarks>
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </remarks>
    public static string McpProtocolVersion { get; } = Utf8Constants.ToInternedString(McpProtocolVersionUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="McpMethod"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#standard-request-headers">MCP 2026-07-28</see>: "These headers are REQUIRED for compliance."
    /// </summary>
    /// <remarks>
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </remarks>
    public static ReadOnlySpan<byte> McpMethodUtf8 => "Mcp-Method"u8;

    /// <summary>
    /// The interned spelling derived from <see cref="McpMethodUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#standard-request-headers">MCP 2026-07-28</see>: "These headers are REQUIRED for compliance."
    /// </summary>
    /// <remarks>
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </remarks>
    public static string McpMethod { get; } = Utf8Constants.ToInternedString(McpMethodUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="McpName"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#standard-request-headers">MCP 2026-07-28</see>: "These headers are REQUIRED for compliance."
    /// </summary>
    /// <remarks>
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </remarks>
    public static ReadOnlySpan<byte> McpNameUtf8 => "Mcp-Name"u8;

    /// <summary>
    /// The interned spelling derived from <see cref="McpNameUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#standard-request-headers">MCP 2026-07-28</see>: "These headers are REQUIRED for compliance."
    /// </summary>
    /// <remarks>
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </remarks>
    public static string McpName { get; } = Utf8Constants.ToInternedString(McpNameUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="McpSessionId"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#earlier-streamable-http-revisions">MCP 2026-07-28</see>: "An <c>Mcp-Session-Id</c> header on a request: ignore it, and do not mint or echo session IDs."
    /// </summary>
    /// <remarks>
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </remarks>
    public static ReadOnlySpan<byte> McpSessionIdUtf8 => "Mcp-Session-Id"u8;

    /// <summary>
    /// The interned spelling derived from <see cref="McpSessionIdUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#earlier-streamable-http-revisions">MCP 2026-07-28</see>: "An <c>Mcp-Session-Id</c> header on a request: ignore it, and do not mint or echo session IDs."
    /// </summary>
    /// <remarks>
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </remarks>
    public static string McpSessionId { get; } = Utf8Constants.ToInternedString(McpSessionIdUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="ParameterHeaderPrefix"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#schema-extension">MCP 2026-07-28</see>: "The <c>x-mcp-header</c> property specifies the name portion used to construct the header name <c>Mcp-Param-{name}</c>."
    /// </summary>
    /// <remarks>
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </remarks>
    public static ReadOnlySpan<byte> ParameterHeaderPrefixUtf8 => "Mcp-Param-"u8;

    /// <summary>
    /// The interned spelling derived from <see cref="ParameterHeaderPrefixUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#schema-extension">MCP 2026-07-28</see>: "The <c>x-mcp-header</c> property specifies the name portion used to construct the header name <c>Mcp-Param-{name}</c>."
    /// </summary>
    /// <remarks>
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </remarks>
    public static string ParameterHeaderPrefix { get; } = Utf8Constants.ToInternedString(ParameterHeaderPrefixUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="Base64SentinelPrefix"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#value-encoding">MCP 2026-07-28</see>: "The prefix <c>=?base64?</c> and suffix <c>?=</c> indicate that the value is Base64-encoded."
    /// </summary>
    /// <remarks>
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </remarks>
    public static ReadOnlySpan<byte> Base64SentinelPrefixUtf8 => "=?base64?"u8;

    /// <summary>
    /// The interned spelling derived from <see cref="Base64SentinelPrefixUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#value-encoding">MCP 2026-07-28</see>: "The prefix <c>=?base64?</c> and suffix <c>?=</c> indicate that the value is Base64-encoded."
    /// </summary>
    /// <remarks>
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </remarks>
    public static string Base64SentinelPrefix { get; } = Utf8Constants.ToInternedString(Base64SentinelPrefixUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="Base64SentinelSuffix"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#value-encoding">MCP 2026-07-28</see>: "These markers are case-sensitive and MUST appear exactly as shown (lowercase)."
    /// </summary>
    /// <remarks>
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </remarks>
    public static ReadOnlySpan<byte> Base64SentinelSuffixUtf8 => "?="u8;

    /// <summary>
    /// The interned spelling derived from <see cref="Base64SentinelSuffixUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#value-encoding">MCP 2026-07-28</see>: "These markers are case-sensitive and MUST appear exactly as shown (lowercase)."
    /// </summary>
    /// <remarks>
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </remarks>
    public static string Base64SentinelSuffix { get; } = Utf8Constants.ToInternedString(Base64SentinelSuffixUtf8);

    /// <summary>
    /// Whether <paramref name="name"/> equals <see cref="McpProtocolVersion"/> under <see cref="Equals"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#case-sensitivity">MCP 2026-07-28</see>: "Clients and servers MUST use case-insensitive comparisons for header names."
    /// </summary>
    /// <remarks>
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </remarks>
    public static bool IsMcpProtocolVersion(string? name) => Equals(name, McpProtocolVersion);

    /// <summary>
    /// Whether <paramref name="name"/> equals <see cref="McpMethod"/> under <see cref="Equals"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#case-sensitivity">MCP 2026-07-28</see>: "Clients and servers MUST use case-insensitive comparisons for header names."
    /// </summary>
    /// <remarks>
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </remarks>
    public static bool IsMcpMethod(string? name) => Equals(name, McpMethod);

    /// <summary>
    /// Whether <paramref name="name"/> equals <see cref="McpName"/> under <see cref="Equals"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#case-sensitivity">MCP 2026-07-28</see>: "Clients and servers MUST use case-insensitive comparisons for header names."
    /// </summary>
    /// <remarks>
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </remarks>
    public static bool IsMcpName(string? name) => Equals(name, McpName);

    /// <summary>
    /// Whether <paramref name="name"/> equals <see cref="McpSessionId"/> under <see cref="Equals"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#case-sensitivity">MCP 2026-07-28</see>: "Clients and servers MUST use case-insensitive comparisons for header names."
    /// </summary>
    /// <remarks>
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </remarks>
    public static bool IsMcpSessionId(string? name) => Equals(name, McpSessionId);

    /// <summary>
    /// Whether <paramref name="name"/> has <see cref="ParameterHeaderPrefix"/> followed by a nonempty HTTP field-name token. Prefix matching uses <see cref="StringComparison.OrdinalIgnoreCase"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#schema-extension">MCP 2026-07-28</see>: "MUST match HTTP field-name token syntax"
    /// and "MUST NOT be empty".
    /// </summary>
    /// <remarks>
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </remarks>
    public static bool IsParameterHeader(string? name)
    {
        if(name is null || name.Length <= ParameterHeaderPrefix.Length
            || !name.StartsWith(ParameterHeaderPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        foreach(char character in name.AsSpan(ParameterHeaderPrefix.Length))
        {
            if(!char.IsAsciiLetterOrDigit(character)
                && character is not ('!' or '#' or '$' or '%' or '&' or '\'' or '*' or '+' or '-' or '.' or '^' or '_' or '`' or '|' or '~'))
            {
                return false;
            }

        }

        return true;
    }

    /// <summary>
    /// Compares header names using <see cref="StringComparison.OrdinalIgnoreCase"/>; this comparison does not apply to the encoding marker values.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#case-sensitivity">MCP 2026-07-28</see>: "Clients and servers MUST use case-insensitive comparisons for header names."
    /// </summary>
    /// <remarks>
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </remarks>
    public static bool Equals(string? nameA, string? nameB) =>
        string.Equals(nameA, nameB, StringComparison.OrdinalIgnoreCase);
}
