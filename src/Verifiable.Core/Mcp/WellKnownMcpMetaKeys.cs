using Verifiable.Core.Transport;
using Verifiable.Cryptography.Text;

namespace Verifiable.Core.Mcp;

/// <summary>
/// Reserved metadata names with UTF-8 twins, <see cref="Equals"/>, <see cref="IsReservedKey"/> for a received key, and <see cref="IsReservedPrefix"/>.
/// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">MCP 2026-07-28</see>:
/// "The following <c>_meta</c> keys are reserved by this specification:"
/// </summary>
/// <remarks>
/// MCP 2026-07-28 is the current revision. Key comparison uses
/// <see cref="StringComparison.Ordinal"/> as the local catalog policy for JSON member names.
/// </remarks>
public static class WellKnownMcpMetaKeys
{
    /// <summary>
    /// The UTF-8 source of <see cref="ProgressToken"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">MCP 2026-07-28</see>: "Opts the request into progress notifications"
    /// </summary>
    public static ReadOnlySpan<byte> ProgressTokenUtf8 => "progressToken"u8;

    /// <summary>
    /// The interned metadata key derived from <see cref="ProgressTokenUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">MCP 2026-07-28</see>: "Opts the request into progress notifications"
    /// </summary>
    public static string ProgressToken { get; } = Utf8Constants.ToInternedString(ProgressTokenUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="ProtocolVersion"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">MCP 2026-07-28</see>: "Protocol version for a request"
    /// </summary>
    public static ReadOnlySpan<byte> ProtocolVersionUtf8 => "io.modelcontextprotocol/protocolVersion"u8;

    /// <summary>
    /// The interned metadata key derived from <see cref="ProtocolVersionUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">MCP 2026-07-28</see>: "Protocol version for a request"
    /// </summary>
    public static string ProtocolVersion { get; } = Utf8Constants.ToInternedString(ProtocolVersionUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="ClientInfo"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">MCP 2026-07-28</see>: "Client name and version"
    /// </summary>
    public static ReadOnlySpan<byte> ClientInfoUtf8 => "io.modelcontextprotocol/clientInfo"u8;

    /// <summary>
    /// The interned metadata key derived from <see cref="ClientInfoUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">MCP 2026-07-28</see>: "Client name and version"
    /// </summary>
    public static string ClientInfo { get; } = Utf8Constants.ToInternedString(ClientInfoUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="ClientCapabilities"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">MCP 2026-07-28</see>: "Client capabilities relevant to a request"
    /// </summary>
    public static ReadOnlySpan<byte> ClientCapabilitiesUtf8 => "io.modelcontextprotocol/clientCapabilities"u8;

    /// <summary>
    /// The interned metadata key derived from <see cref="ClientCapabilitiesUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">MCP 2026-07-28</see>: "Client capabilities relevant to a request"
    /// </summary>
    public static string ClientCapabilities { get; } = Utf8Constants.ToInternedString(ClientCapabilitiesUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="LogLevel"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">MCP 2026-07-28</see>: "Minimum log level the server should emit for a request"
    /// </summary>
    public static ReadOnlySpan<byte> LogLevelUtf8 => "io.modelcontextprotocol/logLevel"u8;

    /// <summary>
    /// The interned metadata key derived from <see cref="LogLevelUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">MCP 2026-07-28</see>: "Minimum log level the server should emit for a request"
    /// </summary>
    public static string LogLevel { get; } = Utf8Constants.ToInternedString(LogLevelUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="SubscriptionId"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">MCP 2026-07-28</see>: "Correlates a notification with its originating subscription"
    /// </summary>
    public static ReadOnlySpan<byte> SubscriptionIdUtf8 => "io.modelcontextprotocol/subscriptionId"u8;

    /// <summary>
    /// The interned metadata key derived from <see cref="SubscriptionIdUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">MCP 2026-07-28</see>: "Correlates a notification with its originating subscription"
    /// </summary>
    public static string SubscriptionId { get; } = Utf8Constants.ToInternedString(SubscriptionIdUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="ServerInfo"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">MCP 2026-07-28</see>: "Server name and version"
    /// </summary>
    public static ReadOnlySpan<byte> ServerInfoUtf8 => "io.modelcontextprotocol/serverInfo"u8;

    /// <summary>
    /// The interned metadata key derived from <see cref="ServerInfoUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">MCP 2026-07-28</see>: "Server name and version"
    /// </summary>
    public static string ServerInfo { get; } = Utf8Constants.ToInternedString(ServerInfoUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="TraceParent"/>. Shares <see cref="WellKnownHttpHeaderNames.TraceParentUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">MCP 2026-07-28</see>: "As an exception to the prefix requirement above, the keys <c>traceparent</c>, <c>tracestate</c>, and <c>baggage</c> are reserved"
    /// </summary>
    public static ReadOnlySpan<byte> TraceParentUtf8 => WellKnownHttpHeaderNames.TraceParentUtf8;

    /// <summary>
    /// The interned metadata key derived from <see cref="TraceParentUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">MCP 2026-07-28</see>: "As an exception to the prefix requirement above, the keys <c>traceparent</c>, <c>tracestate</c>, and <c>baggage</c> are reserved"
    /// </summary>
    public static string TraceParent { get; } = Utf8Constants.ToInternedString(TraceParentUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="TraceState"/>. Shares <see cref="WellKnownHttpHeaderNames.TraceStateUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">MCP 2026-07-28</see>: "As an exception to the prefix requirement above, the keys <c>traceparent</c>, <c>tracestate</c>, and <c>baggage</c> are reserved"
    /// </summary>
    public static ReadOnlySpan<byte> TraceStateUtf8 => WellKnownHttpHeaderNames.TraceStateUtf8;

    /// <summary>
    /// The interned metadata key derived from <see cref="TraceStateUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">MCP 2026-07-28</see>: "As an exception to the prefix requirement above, the keys <c>traceparent</c>, <c>tracestate</c>, and <c>baggage</c> are reserved"
    /// </summary>
    public static string TraceState { get; } = Utf8Constants.ToInternedString(TraceStateUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="Baggage"/>. Shares <see cref="WellKnownHttpHeaderNames.BaggageUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">MCP 2026-07-28</see>: "As an exception to the prefix requirement above, the keys <c>traceparent</c>, <c>tracestate</c>, and <c>baggage</c> are reserved"
    /// </summary>
    public static ReadOnlySpan<byte> BaggageUtf8 => WellKnownHttpHeaderNames.BaggageUtf8;

    /// <summary>
    /// The interned metadata key derived from <see cref="BaggageUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">MCP 2026-07-28</see>: "As an exception to the prefix requirement above, the keys <c>traceparent</c>, <c>tracestate</c>, and <c>baggage</c> are reserved"
    /// </summary>
    public static string Baggage { get; } = Utf8Constants.ToInternedString(BaggageUtf8);

    /// <summary>
    /// Whether <paramref name="name"/> equals <see cref="ProgressToken"/> under the local ordinal <see cref="Equals"/> policy.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">MCP 2026-07-28</see>: "Opts the request into progress notifications"
    /// </summary>
    public static bool IsProgressToken(string? name) => Equals(name, ProgressToken);

    /// <summary>
    /// Whether <paramref name="name"/> equals <see cref="ProtocolVersion"/> under the local ordinal <see cref="Equals"/> policy.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">MCP 2026-07-28</see>: "Protocol version for a request"
    /// </summary>
    public static bool IsProtocolVersion(string? name) => Equals(name, ProtocolVersion);

    /// <summary>
    /// Whether <paramref name="name"/> equals <see cref="ClientInfo"/> under the local ordinal <see cref="Equals"/> policy.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">MCP 2026-07-28</see>: "Client name and version"
    /// </summary>
    public static bool IsClientInfo(string? name) => Equals(name, ClientInfo);

    /// <summary>
    /// Whether <paramref name="name"/> equals <see cref="ClientCapabilities"/> under the local ordinal <see cref="Equals"/> policy.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">MCP 2026-07-28</see>: "Client capabilities relevant to a request"
    /// </summary>
    public static bool IsClientCapabilities(string? name) => Equals(name, ClientCapabilities);

    /// <summary>
    /// Whether <paramref name="name"/> equals <see cref="LogLevel"/> under the local ordinal <see cref="Equals"/> policy.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">MCP 2026-07-28</see>: "Minimum log level the server should emit for a request"
    /// </summary>
    public static bool IsLogLevel(string? name) => Equals(name, LogLevel);

    /// <summary>
    /// Whether <paramref name="name"/> equals <see cref="SubscriptionId"/> under the local ordinal <see cref="Equals"/> policy.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">MCP 2026-07-28</see>: "Correlates a notification with its originating subscription"
    /// </summary>
    public static bool IsSubscriptionId(string? name) => Equals(name, SubscriptionId);

    /// <summary>
    /// Whether <paramref name="name"/> equals <see cref="ServerInfo"/> under the local ordinal <see cref="Equals"/> policy.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">MCP 2026-07-28</see>: "Server name and version"
    /// </summary>
    public static bool IsServerInfo(string? name) => Equals(name, ServerInfo);

    /// <summary>
    /// Whether <paramref name="name"/> equals <see cref="TraceParent"/> under the local ordinal <see cref="Equals"/> policy.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">MCP 2026-07-28</see>: "As an exception to the prefix requirement above, the keys <c>traceparent</c>, <c>tracestate</c>, and <c>baggage</c> are reserved"
    /// </summary>
    public static bool IsTraceParent(string? name) => Equals(name, TraceParent);

    /// <summary>
    /// Whether <paramref name="name"/> equals <see cref="TraceState"/> under the local ordinal <see cref="Equals"/> policy.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">MCP 2026-07-28</see>: "As an exception to the prefix requirement above, the keys <c>traceparent</c>, <c>tracestate</c>, and <c>baggage</c> are reserved"
    /// </summary>
    public static bool IsTraceState(string? name) => Equals(name, TraceState);

    /// <summary>
    /// Whether <paramref name="name"/> equals <see cref="Baggage"/> under the local ordinal <see cref="Equals"/> policy.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">MCP 2026-07-28</see>: "As an exception to the prefix requirement above, the keys <c>traceparent</c>, <c>tracestate</c>, and <c>baggage</c> are reserved"
    /// </summary>
    public static bool IsBaggage(string? name) => Equals(name, Baggage);

    /// <summary>
    /// Whether the complete metadata <paramref name="key"/> is reserved for MCP: either one of the keys the
    /// specification reserves by name, or a key whose prefix <see cref="IsReservedPrefix"/> reserves.
    /// The prefix is the key up to and including its first slash, because a name holds no slash; a key
    /// without a slash has no prefix and is reserved only when the specification names it.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">MCP 2026-07-28</see>:
    /// "valid <c>_meta</c> key names have two segments: an optional prefix, and a name."
    /// "Any prefix where the second label is <c>modelcontextprotocol</c> or <c>mcp</c> is reserved for MCP use."
    /// "The following <c>_meta</c> keys are reserved by this specification:"
    /// "As an exception to the prefix requirement above, the keys <c>traceparent</c>, <c>tracestate</c>, and <c>baggage</c> are reserved"
    /// </summary>
    /// <remarks>
    /// A false answer for a key whose prefix is malformed says only that this rule does not recognize the
    /// prefix; it does not establish that the key lies outside the reserved namespace.
    /// </remarks>
    /// <param name="key">A complete metadata key as received, including a possible null value.</param>
    /// <returns><see langword="true"/> when the key is reserved for MCP.</returns>
    public static bool IsReservedKey(string? key)
    {
        if(key is null)
        {
            return false;
        }

        int slashIndex = key.IndexOf('/', StringComparison.Ordinal);
        if(slashIndex < 0)
        {
            return IsProgressToken(key) || IsTraceParent(key) || IsTraceState(key) || IsBaggage(key);
        }

        return IsReservedPrefixSpan(key.AsSpan(0, slashIndex + 1));
    }

    /// <summary>
    /// Whether <paramref name="prefix"/> is a complete slash-terminated prefix with valid labels and a reserved second label. This local parser uses ASCII letters and <see cref="StringComparison.Ordinal"/>; it accepts prefixes, not complete metadata keys, which <see cref="IsReservedKey"/> screens.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">MCP 2026-07-28</see>: "Any prefix where the second label is <c>modelcontextprotocol</c> or <c>mcp</c> is reserved for MCP use."
    /// "If specified, MUST be a series of labels separated by dots (<c>.</c>), followed by a slash (<c>/</c>)."
    /// "Labels MUST start with a letter and end with a letter or digit; interior characters can be letters, digits, or hyphens (<c>-</c>)."
    /// </summary>
    /// <remarks>
    /// A false answer for a malformed input says only that the input is not a well-formed reserved prefix;
    /// it does not establish that the input lies outside the reserved namespace.
    /// </remarks>
    /// <param name="prefix">A slash-terminated prefix, including a possible null value.</param>
    /// <returns><see langword="true"/> when the prefix is well formed and its second label is reserved.</returns>
    public static bool IsReservedPrefix(string? prefix) => prefix is not null && IsReservedPrefixSpan(prefix);

    /// <summary>
    /// The prefix rule shared by <see cref="IsReservedPrefix"/> and <see cref="IsReservedKey"/>: slash-terminated
    /// labels that each start with a letter, end with a letter or digit, hold only letters, digits and hyphens
    /// between, and whose second label is <c>modelcontextprotocol</c> or <c>mcp</c>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">MCP 2026-07-28</see>: "Any prefix where the second label is <c>modelcontextprotocol</c> or <c>mcp</c> is reserved for MCP use."
    /// </summary>
    /// <param name="prefix">The candidate prefix, slash included.</param>
    /// <returns><see langword="true"/> when the prefix is well formed and its second label is reserved.</returns>
    private static bool IsReservedPrefixSpan(ReadOnlySpan<char> prefix)
    {
        if(prefix.IsEmpty || prefix[^1] != '/')
        {
            return false;
        }

        ReadOnlySpan<char> labels = prefix[..^1];
        int labelIndex = 0;
        bool isReserved = false;
        foreach(Range labelRange in labels.Split('.'))
        {
            ReadOnlySpan<char> label = labels[labelRange];
            if(label.IsEmpty || !char.IsAsciiLetter(label[0]) || !char.IsAsciiLetterOrDigit(label[^1]))
            {
                return false;
            }

            foreach(char character in label)
            {
                if(!char.IsAsciiLetterOrDigit(character) && character != '-')
                {
                    return false;
                }
            }

            if(labelIndex == 1)
            {
                isReserved = label.SequenceEqual("modelcontextprotocol") || label.SequenceEqual("mcp");
            }

            ++labelIndex;
        }

        return isReserved;
    }

    /// <summary>
    /// Compares metadata keys using the local <see cref="StringComparison.Ordinal"/> policy for JSON member names.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">MCP 2026-07-28</see>: "The following <c>_meta</c> keys are reserved by this specification:"
    /// </summary>
    public static bool Equals(string? nameA, string? nameB) =>
        string.Equals(nameA, nameB, StringComparison.Ordinal);
}
