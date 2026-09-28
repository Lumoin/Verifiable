using System.Text;
using Verifiable.Core;
using Verifiable.Core.Mcp;

namespace Verifiable.Tests.Core;

/// <summary>
/// Literal vocabulary checks for <see cref="McpProtocolRevision"/> and the MCP catalogs of
/// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index">MCP 2026-07-28</see>,
/// the current revision. Each test quotes the clause it checks.
/// </summary>
[TestClass]
internal sealed class McpProtocolVocabularyTests
{
    /// <summary>
    /// The <see cref="McpErrorCode"/> entries paired with independently transcribed codes and names.
    /// <see href="https://www.jsonrpc.org/specification#error_object">JSON-RPC 2.0 §5.1</see>:
    /// "The error codes from and including -32768 to -32000 are reserved for pre-defined errors."
    /// Its table pairs -32700 with "Parse error", -32600 with "Invalid Request", -32601 with "Method not found",
    /// -32602 with "Invalid params" and -32603 with "Internal error".
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#error-codes">MCP 2026-07-28</see>:
    /// "MCP defines the following error codes:", pairing -32020 with "HeaderMismatch",
    /// -32021 with "MissingRequiredClientCapability" and -32022 with "UnsupportedProtocolVersion".
    /// </summary>
    public static IEnumerable<object[]> GetErrorCodes()
    {
        yield return new object[] { McpErrorCode.ParseError, -32700, "Parse error", true, new int?[] { null, null, null, null, null } };
        yield return new object[] { McpErrorCode.InvalidRequest, -32600, "Invalid Request", true, new int?[] { null, null, null, null, null } };
        yield return new object[] { McpErrorCode.MethodNotFound, -32601, "Method not found", true, new int?[] { null, null, null, null, 404 } };
        yield return new object[] { McpErrorCode.InvalidParams, -32602, "Invalid params", true, new int?[] { null, null, null, 400, null } };
        yield return new object[] { McpErrorCode.InternalError, -32603, "Internal error", true, new int?[] { null, null, null, null, null } };
        yield return new object[] { McpErrorCode.HeaderMismatch, -32020, "HeaderMismatch", false, new int?[] { null, 400, null, null, null } };
        yield return new object[] { McpErrorCode.MissingRequiredClientCapability, -32021, "MissingRequiredClientCapability", false, new int?[] { null, null, 400, null, null } };
        yield return new object[] { McpErrorCode.UnsupportedProtocolVersion, -32022, "UnsupportedProtocolVersion", false, new int?[] { 400, null, null, null, null } };
    }


    /// <summary>
    /// Literal code classifications for <see cref="McpErrorCode.IsDefinedIn(int, McpProtocolRevision)"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#error-codes">Specification</see>: "Implementations of this protocol version MUST NOT emit these codes:"
    /// <see href="https://www.jsonrpc.org/specification#error_object">JSON-RPC 2.0 §5.1</see>: "Any code within this range, but not defined explicitly below is reserved for future use."
    /// </summary>
    public static IEnumerable<object[]> GetCodeClassifications()
    {
        yield return new object[] { -32002, false, true, true, false };
        yield return new object[] { -32042, false, true, true, false };
        yield return new object[] { -32050, false, true, false, false };
        yield return new object[] { -32010, false, true, false, false };
        yield return new object[] { -32601, true, false, true, false };
        yield return new object[] { -32020, true, false, false, false };
        yield return new object[] { -32022, true, false, false, false };
        yield return new object[] { -32021, true, false, false, false };
        yield return new object[] { -1, false, false, false, false };
        yield return new object[] { -32604, false, true, false, true };
        yield return new object[] { -32000, false, true, false, false };
        yield return new object[] { -32019, false, true, false, false };
        yield return new object[] { -32099, false, true, false, false };
        yield return new object[] { -32100, false, true, false, true };
        yield return new object[] { -32700, true, false, true, false };
        yield return new object[] { -32768, false, true, false, true };
        yield return new object[] { -32769, false, false, false, false };
    }


    /// <summary>
    /// The literal transport names and comparison spellings for <see cref="WellKnownMcpHeaderNames"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#standard-request-headers">Specification</see>: "These headers are REQUIRED for compliance."
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#earlier-streamable-http-revisions">Specification</see>:
    /// "Protocol versions `2025-03-26` through `2025-11-25` also used the Streamable HTTP transport, but in a different shape: servers could assign a session via the `Mcp-Session-Id` header (terminated with HTTP DELETE)".
    /// </summary>
    public static IEnumerable<object[]> GetHeaderNames()
    {
        yield return new object[] { "MCP-Protocol-Version", WellKnownMcpHeaderNames.McpProtocolVersion, Encoding.UTF8.GetString(WellKnownMcpHeaderNames.McpProtocolVersionUtf8), "mcp-protocol-version", "MCP-PROTOCOL-VERSION", new Func<string, bool>(WellKnownMcpHeaderNames.IsMcpProtocolVersion) };
        yield return new object[] { "Mcp-Method", WellKnownMcpHeaderNames.McpMethod, Encoding.UTF8.GetString(WellKnownMcpHeaderNames.McpMethodUtf8), "mcp-method", "MCP-METHOD", new Func<string, bool>(WellKnownMcpHeaderNames.IsMcpMethod) };
        yield return new object[] { "Mcp-Name", WellKnownMcpHeaderNames.McpName, Encoding.UTF8.GetString(WellKnownMcpHeaderNames.McpNameUtf8), "mcp-name", "MCP-NAME", new Func<string, bool>(WellKnownMcpHeaderNames.IsMcpName) };
        yield return new object[] { "Mcp-Session-Id", WellKnownMcpHeaderNames.McpSessionId, Encoding.UTF8.GetString(WellKnownMcpHeaderNames.McpSessionIdUtf8), "mcp-session-id", "MCP-SESSION-ID", new Func<string, bool>(WellKnownMcpHeaderNames.IsMcpSessionId) };
    }


    /// <summary>
    /// The literal reserved names of <see cref="WellKnownMcpMetaKeys"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">Specification</see>: "The following `_meta` keys are reserved by this specification:"
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">Specification</see>: "identify themselves without relying on any prior connection state:"
    /// </summary>
    public static IEnumerable<object[]> GetMetaKeys()
    {
        yield return new object[] { "progressToken", WellKnownMcpMetaKeys.ProgressToken, Encoding.UTF8.GetString(WellKnownMcpMetaKeys.ProgressTokenUtf8), new Func<string, bool>(WellKnownMcpMetaKeys.IsProgressToken) };
        yield return new object[] { "io.modelcontextprotocol/protocolVersion", WellKnownMcpMetaKeys.ProtocolVersion, Encoding.UTF8.GetString(WellKnownMcpMetaKeys.ProtocolVersionUtf8), new Func<string, bool>(WellKnownMcpMetaKeys.IsProtocolVersion) };
        yield return new object[] { "io.modelcontextprotocol/clientInfo", WellKnownMcpMetaKeys.ClientInfo, Encoding.UTF8.GetString(WellKnownMcpMetaKeys.ClientInfoUtf8), new Func<string, bool>(WellKnownMcpMetaKeys.IsClientInfo) };
        yield return new object[] { "io.modelcontextprotocol/clientCapabilities", WellKnownMcpMetaKeys.ClientCapabilities, Encoding.UTF8.GetString(WellKnownMcpMetaKeys.ClientCapabilitiesUtf8), new Func<string, bool>(WellKnownMcpMetaKeys.IsClientCapabilities) };
        yield return new object[] { "io.modelcontextprotocol/logLevel", WellKnownMcpMetaKeys.LogLevel, Encoding.UTF8.GetString(WellKnownMcpMetaKeys.LogLevelUtf8), new Func<string, bool>(WellKnownMcpMetaKeys.IsLogLevel) };
        yield return new object[] { "io.modelcontextprotocol/subscriptionId", WellKnownMcpMetaKeys.SubscriptionId, Encoding.UTF8.GetString(WellKnownMcpMetaKeys.SubscriptionIdUtf8), new Func<string, bool>(WellKnownMcpMetaKeys.IsSubscriptionId) };
        yield return new object[] { "io.modelcontextprotocol/serverInfo", WellKnownMcpMetaKeys.ServerInfo, Encoding.UTF8.GetString(WellKnownMcpMetaKeys.ServerInfoUtf8), new Func<string, bool>(WellKnownMcpMetaKeys.IsServerInfo) };
        yield return new object[] { "traceparent", WellKnownMcpMetaKeys.TraceParent, Encoding.UTF8.GetString(WellKnownMcpMetaKeys.TraceParentUtf8), new Func<string, bool>(WellKnownMcpMetaKeys.IsTraceParent) };
        yield return new object[] { "tracestate", WellKnownMcpMetaKeys.TraceState, Encoding.UTF8.GetString(WellKnownMcpMetaKeys.TraceStateUtf8), new Func<string, bool>(WellKnownMcpMetaKeys.IsTraceState) };
        yield return new object[] { "baggage", WellKnownMcpMetaKeys.Baggage, Encoding.UTF8.GetString(WellKnownMcpMetaKeys.BaggageUtf8), new Func<string, bool>(WellKnownMcpMetaKeys.IsBaggage) };
    }


    /// <summary>
    /// The literal schema method names of <see cref="WellKnownMcpMethodNames"/>, each the constant <c>method</c> member of its schema interface.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#jsonrpcrequest-method">Schema</see>: <c>method: string</c>
    /// on <c>JSONRPCRequest</c>, fixed per interface, for example
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#calltoolrequest-method">CallToolRequest</see>: <c>method: "tools/call"</c>.
    /// </summary>
    public static IEnumerable<object[]> GetMethodNames()
    {
        yield return new object[] { "completion/complete", WellKnownMcpMethodNames.CompletionComplete, Encoding.UTF8.GetString(WellKnownMcpMethodNames.CompletionCompleteUtf8), new Func<string, bool>(WellKnownMcpMethodNames.IsCompletionComplete) };
        yield return new object[] { "elicitation/create", WellKnownMcpMethodNames.ElicitationCreate, Encoding.UTF8.GetString(WellKnownMcpMethodNames.ElicitationCreateUtf8), new Func<string, bool>(WellKnownMcpMethodNames.IsElicitationCreate) };
        yield return new object[] { "notifications/cancelled", WellKnownMcpMethodNames.NotificationsCancelled, Encoding.UTF8.GetString(WellKnownMcpMethodNames.NotificationsCancelledUtf8), new Func<string, bool>(WellKnownMcpMethodNames.IsNotificationsCancelled) };
        yield return new object[] { "notifications/message", WellKnownMcpMethodNames.NotificationsMessage, Encoding.UTF8.GetString(WellKnownMcpMethodNames.NotificationsMessageUtf8), new Func<string, bool>(WellKnownMcpMethodNames.IsNotificationsMessage) };
        yield return new object[] { "notifications/progress", WellKnownMcpMethodNames.NotificationsProgress, Encoding.UTF8.GetString(WellKnownMcpMethodNames.NotificationsProgressUtf8), new Func<string, bool>(WellKnownMcpMethodNames.IsNotificationsProgress) };
        yield return new object[] { "notifications/prompts/list_changed", WellKnownMcpMethodNames.NotificationsPromptsListChanged, Encoding.UTF8.GetString(WellKnownMcpMethodNames.NotificationsPromptsListChangedUtf8), new Func<string, bool>(WellKnownMcpMethodNames.IsNotificationsPromptsListChanged) };
        yield return new object[] { "notifications/resources/list_changed", WellKnownMcpMethodNames.NotificationsResourcesListChanged, Encoding.UTF8.GetString(WellKnownMcpMethodNames.NotificationsResourcesListChangedUtf8), new Func<string, bool>(WellKnownMcpMethodNames.IsNotificationsResourcesListChanged) };
        yield return new object[] { "notifications/resources/updated", WellKnownMcpMethodNames.NotificationsResourcesUpdated, Encoding.UTF8.GetString(WellKnownMcpMethodNames.NotificationsResourcesUpdatedUtf8), new Func<string, bool>(WellKnownMcpMethodNames.IsNotificationsResourcesUpdated) };
        yield return new object[] { "notifications/subscriptions/acknowledged", WellKnownMcpMethodNames.NotificationsSubscriptionsAcknowledged, Encoding.UTF8.GetString(WellKnownMcpMethodNames.NotificationsSubscriptionsAcknowledgedUtf8), new Func<string, bool>(WellKnownMcpMethodNames.IsNotificationsSubscriptionsAcknowledged) };
        yield return new object[] { "notifications/tools/list_changed", WellKnownMcpMethodNames.NotificationsToolsListChanged, Encoding.UTF8.GetString(WellKnownMcpMethodNames.NotificationsToolsListChangedUtf8), new Func<string, bool>(WellKnownMcpMethodNames.IsNotificationsToolsListChanged) };
        yield return new object[] { "prompts/get", WellKnownMcpMethodNames.PromptsGet, Encoding.UTF8.GetString(WellKnownMcpMethodNames.PromptsGetUtf8), new Func<string, bool>(WellKnownMcpMethodNames.IsPromptsGet) };
        yield return new object[] { "prompts/list", WellKnownMcpMethodNames.PromptsList, Encoding.UTF8.GetString(WellKnownMcpMethodNames.PromptsListUtf8), new Func<string, bool>(WellKnownMcpMethodNames.IsPromptsList) };
        yield return new object[] { "resources/list", WellKnownMcpMethodNames.ResourcesList, Encoding.UTF8.GetString(WellKnownMcpMethodNames.ResourcesListUtf8), new Func<string, bool>(WellKnownMcpMethodNames.IsResourcesList) };
        yield return new object[] { "resources/read", WellKnownMcpMethodNames.ResourcesRead, Encoding.UTF8.GetString(WellKnownMcpMethodNames.ResourcesReadUtf8), new Func<string, bool>(WellKnownMcpMethodNames.IsResourcesRead) };
        yield return new object[] { "resources/templates/list", WellKnownMcpMethodNames.ResourcesTemplatesList, Encoding.UTF8.GetString(WellKnownMcpMethodNames.ResourcesTemplatesListUtf8), new Func<string, bool>(WellKnownMcpMethodNames.IsResourcesTemplatesList) };
        yield return new object[] { "roots/list", WellKnownMcpMethodNames.RootsList, Encoding.UTF8.GetString(WellKnownMcpMethodNames.RootsListUtf8), new Func<string, bool>(WellKnownMcpMethodNames.IsRootsList) };
        yield return new object[] { "sampling/createMessage", WellKnownMcpMethodNames.SamplingCreateMessage, Encoding.UTF8.GetString(WellKnownMcpMethodNames.SamplingCreateMessageUtf8), new Func<string, bool>(WellKnownMcpMethodNames.IsSamplingCreateMessage) };
        yield return new object[] { "server/discover", WellKnownMcpMethodNames.ServerDiscover, Encoding.UTF8.GetString(WellKnownMcpMethodNames.ServerDiscoverUtf8), new Func<string, bool>(WellKnownMcpMethodNames.IsServerDiscover) };
        yield return new object[] { "subscriptions/listen", WellKnownMcpMethodNames.SubscriptionsListen, Encoding.UTF8.GetString(WellKnownMcpMethodNames.SubscriptionsListenUtf8), new Func<string, bool>(WellKnownMcpMethodNames.IsSubscriptionsListen) };
        yield return new object[] { "tools/call", WellKnownMcpMethodNames.ToolsCall, Encoding.UTF8.GetString(WellKnownMcpMethodNames.ToolsCallUtf8), new Func<string, bool>(WellKnownMcpMethodNames.IsToolsCall) };
        yield return new object[] { "tools/list", WellKnownMcpMethodNames.ToolsList, Encoding.UTF8.GetString(WellKnownMcpMethodNames.ToolsListUtf8), new Func<string, bool>(WellKnownMcpMethodNames.IsToolsList) };
    }


    /// <summary>
    /// Every <see cref="McpErrorCode"/> entry spells its defining code and name.
    /// <see href="https://www.jsonrpc.org/specification#error_object">JSON-RPC 2.0 §5.1</see>:
    /// "The error codes from and including -32768 to -32000 are reserved for pre-defined errors."
    /// Its table pairs -32700 with "Parse error", -32600 with "Invalid Request", -32601 with "Method not found",
    /// -32602 with "Invalid params" and -32603 with "Internal error".
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#error-codes">MCP 2026-07-28</see>:
    /// "MCP defines the following error codes:", pairing -32020 with "HeaderMismatch",
    /// -32021 with "MissingRequiredClientCapability" and -32022 with "UnsupportedProtocolVersion".
    /// </summary>
    /// <param name="error">The catalog entry.</param>
    /// <param name="expectedCode">The literal code.</param>
    /// <param name="expectedName">The literal name.</param>
    /// <param name="isLegacyDefined">Whether the earlier revision defines this entry.</param>
    /// <param name="expectedStatuses">The literal status pairings in situation order.</param>
    [TestMethod]
    [DynamicData(nameof(GetErrorCodes))]
    public void DefinedErrorCodesAreTheSpecificationsSet(McpErrorCode error, int expectedCode, string expectedName, bool isLegacyDefined, int?[] expectedStatuses)
    {
        Assert.AreEqual(expectedCode, error.Code);
        Assert.AreEqual(expectedName, error.Name);
        Assert.AreEqual(expectedName, Encoding.UTF8.GetString(error.NameUtf8));
    }


    /// <summary>
    /// Every <see cref="McpErrorCode"/> entry is defined by the current revision, and only the JSON-RPC codes are defined by 2025-11-25;
    /// a code a revision defines is not forbidden by it.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#error-codes">MCP 2026-07-28</see>:
    /// "MCP uses the standard JSON-RPC 2.0 error codes (-32700, -32600 to -32603) for general protocol failures."
    /// The same section continues "MCP defines the following error codes:" and lists -32020, -32021 and -32022,
    /// which the 2025-11-25 revision does not define.
    /// </summary>
    /// <param name="error">The catalog entry.</param>
    /// <param name="expectedCode">The literal code.</param>
    /// <param name="expectedName">The literal name.</param>
    /// <param name="isLegacyDefined">Whether the earlier revision defines this entry.</param>
    /// <param name="expectedStatuses">The literal status pairings in situation order.</param>
    [TestMethod]
    [DynamicData(nameof(GetErrorCodes))]
    public void ErrorCodeInstancesFollowTheirDefiningRevision(McpErrorCode error, int expectedCode, string expectedName, bool isLegacyDefined, int?[] expectedStatuses)
    {
        Assert.IsTrue(error.IsDefinedIn(McpProtocolRevision.Revision20260728));
        Assert.IsFalse(error.IsForbiddenIn(McpProtocolRevision.Revision20260728));
        Assert.AreEqual(isLegacyDefined, error.IsDefinedIn(McpProtocolRevision.Revision20251125));
        Assert.IsFalse(error.IsForbiddenIn(McpProtocolRevision.Revision20251125));
    }


    /// <summary>
    /// Definitions are revision-specific in <see cref="McpErrorCode"/>; an undefined code is not automatically an allowed code.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#error-codes">Specification</see>: "Codes defined by earlier protocol versions remain reserved and will not be reused."
    /// </summary>
    /// <param name="code">The literal error code.</param>
    /// <param name="isCurrentDefined">Whether the current revision defines the code.</param>
    /// <param name="isCurrentForbidden">Whether the current revision prohibits new emission.</param>
    /// <param name="isLegacyDefined">Whether the earlier revision defines the code.</param>
    /// <param name="isLegacyForbidden">Whether the earlier revision prohibits emission.</param>
    [TestMethod]
    [DynamicData(nameof(GetCodeClassifications))]
    public void CodesTheSpecificationDefinesAreRevisionSpecific(int code, bool isCurrentDefined, bool isCurrentForbidden, bool isLegacyDefined, bool isLegacyForbidden)
    {
        Assert.AreEqual(isCurrentDefined, McpErrorCode.IsDefinedIn(code, McpProtocolRevision.Revision20260728), $"Current revision definition of {code}.");
        Assert.AreEqual(isLegacyDefined, McpErrorCode.IsDefinedIn(code, McpProtocolRevision.Revision20251125), $"Earlier revision definition of {code}.");
    }


    /// <summary>
    /// Emission prohibitions in <see cref="McpErrorCode"/> retain both reserved-range boundaries.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#error-codes">Specification</see>: "New codes MUST NOT be allocated in this sub-range, and new implementations SHOULD NOT use codes from this sub-range at all."
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#error-codes">Specification</see>: "Implementations MUST NOT emit any code from this sub-range that is not defined by this specification and MUST use defined codes only with their specified meanings."
    /// <see href="https://www.jsonrpc.org/specification#error_object">JSON-RPC 2.0 §5.1</see>: "Any code within this range, but not defined explicitly below is reserved for future use."
    /// </summary>
    /// <param name="code">The literal error code.</param>
    /// <param name="isCurrentDefined">Whether the current revision defines the code.</param>
    /// <param name="isCurrentForbidden">Whether the current revision prohibits new emission.</param>
    /// <param name="isLegacyDefined">Whether the earlier revision defines the code.</param>
    /// <param name="isLegacyForbidden">Whether the earlier revision prohibits emission.</param>
    [TestMethod]
    [DynamicData(nameof(GetCodeClassifications))]
    public void CodesTheSpecificationForbidsAreRevisionSpecific(int code, bool isCurrentDefined, bool isCurrentForbidden, bool isLegacyDefined, bool isLegacyForbidden)
    {
        Assert.AreEqual(isCurrentForbidden, McpErrorCode.IsForbiddenIn(code, McpProtocolRevision.Revision20260728), $"Current revision emission of {code}.");
        Assert.AreEqual(isLegacyForbidden, McpErrorCode.IsForbiddenIn(code, McpProtocolRevision.Revision20251125), $"Earlier revision emission of {code}.");
    }


    /// <summary>
    /// An unknown method has the status specified for <see cref="McpErrorCode.MethodNotFound"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#protocol-version-header">Specification</see>: "If the server does not implement the requested RPC method, it MUST respond with `404 Not Found` and a JSON-RPC error with code `-32601` (`Method not found`)."
    /// </summary>
    /// <param name="revisionText">The revision being interpreted.</param>
    /// <param name="expectedStatus">The literal status or an unspecified pairing.</param>
    [TestMethod]
    [DataRow("2026-07-28", 404)]
    [DataRow("2025-11-25", null)]
    public void MethodNotFoundTravelsOver404OnlyInTheCurrentRevision(string revisionText, int? expectedStatus)
    {
        var revision = McpProtocolRevision.Parse(revisionText);

        Assert.IsTrue(revision.IsSuccess);
        Assert.AreEqual(expectedStatus, McpErrorCode.MethodNotFound.HttpStatusIn(revision.Value, McpErrorSituation.UnknownMethod));
    }


    /// <summary>
    /// Each status belongs to its exact <see cref="McpErrorSituation"/>, including every mismatched pairing.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#protocol-version-header">Specification</see>: "If the server does not implement the requested RPC method, it MUST respond with `404 Not Found` and a JSON-RPC error with code `-32601` (`Method not found`)."
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#server-validation">Specification</see>: "return HTTP status `400 Bad Request`"
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">Specification</see>: "A request missing any required field is malformed; the server MUST reject it with JSON-RPC error code `-32602` (Invalid params)."
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">Specification</see>: "On HTTP, the response status MUST be `400 Bad Request`."
    /// </summary>
    /// <param name="error">The catalog entry.</param>
    /// <param name="expectedCode">The literal code.</param>
    /// <param name="expectedName">The literal name.</param>
    /// <param name="isLegacyDefined">Whether the earlier revision defines this entry.</param>
    /// <param name="expectedStatuses">The literal status pairings in situation order.</param>
    [TestMethod]
    [DynamicData(nameof(GetErrorCodes))]
    public void StatusesFollowTheRevisionAndTheSituation(McpErrorCode error, int expectedCode, string expectedName, bool isLegacyDefined, int?[] expectedStatuses)
    {
        McpErrorSituation[] situations = GetSituations();
        for(int index = 0; index < situations.Length; ++index)
        {
            Assert.AreEqual(expectedStatuses[index], error.HttpStatusIn(McpProtocolRevision.Revision20260728, situations[index]),
                $"Code {expectedCode} in situation {situations[index].Name}.");
        }
    }


    /// <summary>
    /// The local unspecified-status result for <see cref="McpErrorCode"/> preserves the earlier transport's silence.
    /// <see href="https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#sending-messages-to-the-server">Specification</see>: "If the input is a JSON-RPC request, the server MUST either return `Content-Type: text/event-stream`, to initiate an SSE stream, or `Content-Type: application/json`, to return one JSON object."
    /// The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    /// <param name="error">The catalog entry.</param>
    /// <param name="expectedCode">The literal code.</param>
    /// <param name="expectedName">The literal name.</param>
    /// <param name="isLegacyDefined">Whether the earlier revision defines this entry.</param>
    /// <param name="expectedStatuses">The literal status pairings in situation order.</param>
    [TestMethod]
    [DynamicData(nameof(GetErrorCodes))]
    public void EarlierRevisionLeavesEveryErrorSituationStatusUnspecified(McpErrorCode error, int expectedCode, string expectedName, bool isLegacyDefined, int?[] expectedStatuses)
    {
        foreach(McpErrorSituation situation in GetSituations())
        {
            Assert.IsNull(error.HttpStatusIn(McpProtocolRevision.Revision20251125, situation));
        }
    }


    /// <summary>
    /// The local unknown-revision policy makes no classification or status claim through <see cref="McpErrorCode"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning#protocol-version-negotiation">Specification</see>:
    /// "If the server does not implement the requested version (whether the version is unknown to the server, or is a known version the server has chosen not to support), it MUST respond with an UnsupportedProtocolVersionError listing the versions it does support".
    /// A revision this catalog does not know therefore receives no definition, prohibition or status from it.
    /// </summary>
    [TestMethod]
    public void UnknownRevisionHasNoDefinedForbiddenOrStatusAnswer()
    {
        var parsed = McpProtocolRevision.Parse("2099-01-01");

        Assert.IsTrue(parsed.IsSuccess);
        foreach(object[] row in GetCodeClassifications())
        {
            int code = (int)row[0];
            Assert.IsFalse(McpErrorCode.IsDefinedIn(code, parsed.Value));
            Assert.IsFalse(McpErrorCode.IsForbiddenIn(code, parsed.Value));
            Assert.IsFalse(McpErrorCode.IsDefinedIn(code, default));
            Assert.IsFalse(McpErrorCode.IsForbiddenIn(code, default));
        }

        foreach(object[] row in GetErrorCodes())
        {
            McpErrorCode error = (McpErrorCode)row[0];
            Assert.IsFalse(error.IsDefinedIn(parsed.Value));
            Assert.IsFalse(error.IsForbiddenIn(parsed.Value));
            foreach(McpErrorSituation situation in GetSituations())
            {
                Assert.IsNull(error.HttpStatusIn(parsed.Value, situation));
                Assert.IsNull(error.HttpStatusIn(default, situation));
            }
        }
    }


    /// <summary>
    /// The local absence policy requires a <see cref="McpErrorSituation"/> before returning a status.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#server-validation">Specification</see>: "When rejecting a request due to header validation failure, servers MUST return HTTP status `400 Bad Request`"
    /// </summary>
    [TestMethod]
    public void MissingSituationHasNoStatusAnswer()
    {
        foreach(object[] row in GetErrorCodes())
        {
            McpErrorCode error = (McpErrorCode)row[0];
            Assert.IsNull(error.HttpStatusIn(McpProtocolRevision.Revision20260728, null));
            Assert.IsNull(error.HttpStatusIn(McpProtocolRevision.Revision20251125, null));
        }
    }


    /// <summary>
    /// The <see cref="WellKnownMcpHeaderNames"/> spellings match the named transport fields.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#protocol-version-header">Specification</see>: "Every POST request to the MCP endpoint MUST include an `MCP-Protocol-Version` header."
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#standard-request-headers">Specification</see>: "These headers are REQUIRED for compliance."
    /// </summary>
    /// <param name="expected">The literal field name.</param>
    /// <param name="tabledValue">The catalog string.</param>
    /// <param name="utf8Text">The decoded UTF-8 twin.</param>
    /// <param name="lowercase">The literal lowercase spelling.</param>
    /// <param name="uppercase">The literal uppercase spelling.</param>
    /// <param name="isHeader">The field's recognition predicate.</param>
    [TestMethod]
    [DynamicData(nameof(GetHeaderNames))]
    public void TransportHeaderNamesSpellTheFields(string expected, string tabledValue, string utf8Text, string lowercase, string uppercase, Func<string, bool> isHeader)
    {
        Assert.AreEqual(expected, tabledValue);
    }


    /// <summary>
    /// The <see cref="WellKnownMcpHeaderNames"/> predicates compare field-name content without case.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#case-sensitivity">Specification</see>: "Clients and servers MUST use case-insensitive comparisons for header names."
    /// </summary>
    /// <param name="expected">The literal field name.</param>
    /// <param name="tabledValue">The catalog string.</param>
    /// <param name="utf8Text">The decoded UTF-8 twin.</param>
    /// <param name="lowercase">The literal lowercase spelling.</param>
    /// <param name="uppercase">The literal uppercase spelling.</param>
    /// <param name="isHeader">The field's recognition predicate.</param>
    [TestMethod]
    [DynamicData(nameof(GetHeaderNames))]
    public void TransportHeaderNamesCompareCaseInsensitively(string expected, string tabledValue, string utf8Text, string lowercase, string uppercase, Func<string, bool> isHeader)
    {
        Assert.IsTrue(isHeader(new string(expected.ToCharArray())));
        Assert.IsTrue(isHeader(lowercase));
        Assert.IsTrue(isHeader(uppercase));
        Assert.IsFalse(isHeader(expected + "-Other"));
        Assert.IsTrue(WellKnownMcpHeaderNames.Equals(lowercase, uppercase));
        Assert.IsFalse(WellKnownMcpHeaderNames.Equals(expected, expected + "-Other"));
    }


    /// <summary>
    /// Parameter header recognition follows <see cref="WellKnownMcpHeaderNames.ParameterHeaderPrefix"/> and token syntax.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#schema-extension">Specification</see>: "The `x-mcp-header` property specifies the name portion used to construct the header name `Mcp-Param-{name}`."
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#schema-extension">Specification</see>: "MUST NOT be empty"
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#schema-extension">Specification</see>: "MUST match HTTP field-name token syntax"
    /// </summary>
    /// <param name="name">The supplied header name.</param>
    /// <param name="isExpectedParameter">Whether the name identifies a parameter header.</param>
    [TestMethod]
    [DataRow("Mcp-Param-Tenant", true)]
    [DataRow("MCP-PARAM-TENANT", true)]
    [DataRow("Mcp-Param-!#$%&'*+-.^_`|~09AZaz", true)]
    [DataRow("Mcp-Param-", false)]
    [DataRow("Other-Mcp-Param-Tenant", false)]
    [DataRow("Mcp-Parameter-Tenant", false)]
    [DataRow("Mcp-Param-Tenant Name", false)]
    [DataRow("Mcp-Param-Tenant/Name", false)]
    [DataRow("Mcp-Param-\u00E9", false)]
    [DataRow("Mcp-Param-Tenant\r\n", false)]
    [DataRow(null, false)]
    public void ParameterHeadersAreRecognizedByPrefix(string? name, bool isExpectedParameter)
    {
        Assert.AreEqual(isExpectedParameter, WellKnownMcpHeaderNames.IsParameterHeader(name));
    }


    /// <summary>
    /// <see cref="WellKnownMcpHeaderNames.ParameterHeaderPrefix"/> spells the name portion that precedes a parameter header's name.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#schema-extension">Specification</see>:
    /// "The `x-mcp-header` property specifies the name portion used to construct the header name `Mcp-Param-{name}`."
    /// </summary>
    [TestMethod]
    public void ParameterHeaderPrefixSpellsTheSchemaExtensionName()
    {
        Assert.AreEqual("Mcp-Param-", WellKnownMcpHeaderNames.ParameterHeaderPrefix);
    }


    /// <summary>
    /// The encoding delimiters in <see cref="WellKnownMcpHeaderNames"/> spell the transport's Base64 sentinel.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#value-encoding">Specification</see>: "Mcp-Param-{Name}: =?base64?{Base64EncodedValue}?="
    /// </summary>
    [TestMethod]
    public void ParameterHeaderEncodingSpellsTheBase64Sentinel()
    {
        Assert.AreEqual("=?base64?", WellKnownMcpHeaderNames.Base64SentinelPrefix);
        Assert.AreEqual("?=", WellKnownMcpHeaderNames.Base64SentinelSuffix);
    }


    /// <summary>
    /// The second label alone chooses the reservation recognized by <see cref="WellKnownMcpMetaKeys.IsReservedPrefix"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">Specification</see>: "Any prefix where the second label is `modelcontextprotocol` or `mcp` is reserved for MCP use."
    /// </summary>
    /// <param name="prefix">The complete prefix.</param>
    /// <param name="isExpectedReserved">Whether the prefix belongs to MCP.</param>
    [TestMethod]
    [DataRow("io.modelcontextprotocol/", true)]
    [DataRow("dev.mcp/", true)]
    [DataRow("org.modelcontextprotocol.api/", true)]
    [DataRow("com.mcp.tools/", true)]
    [DataRow("com.example.mcp/", false)]
    public void ReservedMetaPrefixesFollowTheSecondLabelRule(string prefix, bool isExpectedReserved)
    {
        Assert.AreEqual(isExpectedReserved, WellKnownMcpMetaKeys.IsReservedPrefix(prefix));
    }


    /// <summary>
    /// A prefix needs the specified syntax and a second label before <see cref="WellKnownMcpMetaKeys.IsReservedPrefix"/> can reserve it.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">Specification</see>: "If specified, MUST be a series of labels separated by dots (`.`), followed by a slash (`/`)."
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">Specification</see>: "Labels MUST start with a letter and end with a letter or digit; interior characters can be letters, digits, or hyphens (`-`)."
    /// </summary>
    /// <param name="prefix">The input without the required prefix shape or second label.</param>
    [TestMethod]
    [DataRow(null)]
    [DataRow("")]
    [DataRow("mcp/")]
    [DataRow("dev.mcp")]
    [DataRow(".mcp/")]
    [DataRow("1dev.mcp/")]
    [DataRow("dev.mcp./")]
    [DataRow("dev.mcp.-api/")]
    [DataRow("dev.mcp.api-/")]
    public void PrefixesWithoutTheRequiredShapeAreNotReserved(string? prefix)
    {
        Assert.IsFalse(WellKnownMcpMetaKeys.IsReservedPrefix(prefix));
    }


    /// <summary>
    /// A complete received key is reserved by <see cref="WellKnownMcpMetaKeys.IsReservedKey"/> when its prefix has a reserved second label.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">Specification</see>: "valid `_meta` key names have two segments: an optional **prefix**, and a **name**."
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">Specification</see>: "Any prefix where the second label is `modelcontextprotocol` or `mcp` is **reserved** for MCP use."
    /// </summary>
    /// <param name="key">The complete key as received.</param>
    /// <param name="isExpectedReserved">Whether the key's prefix belongs to MCP.</param>
    [TestMethod]
    [DataRow("io.modelcontextprotocol/protocolVersion", true)]
    [DataRow("dev.mcp/key", true)]
    [DataRow("org.modelcontextprotocol.api/x", true)]
    [DataRow("com.mcp.tools/y", true)]
    [DataRow("com.example.mcp/x", false)]
    [DataRow("com.example/x", false)]
    public void ReservedMetaKeysAreRecognizedByTheirPrefix(string key, bool isExpectedReserved)
    {
        Assert.AreEqual(isExpectedReserved, WellKnownMcpMetaKeys.IsReservedKey(key));
    }


    /// <summary>
    /// A complete received key without a prefix is reserved by <see cref="WellKnownMcpMetaKeys.IsReservedKey"/> only when the specification names it.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">Specification</see>: "The following `_meta` keys are reserved by this specification:"
    /// with the row "`progressToken`", and "As an exception to the prefix requirement above, the keys `traceparent`, `tracestate`, and `baggage` are reserved".
    /// </summary>
    /// <param name="key">The complete key as received.</param>
    /// <param name="isExpectedReserved">Whether the specification names the key.</param>
    [TestMethod]
    [DataRow("progressToken", true)]
    [DataRow("traceparent", true)]
    [DataRow("tracestate", true)]
    [DataRow("baggage", true)]
    [DataRow("customKey", false)]
    [DataRow(null, false)]
    public void UnprefixedMetaKeysAreReservedOnlyWhenNamed(string? key, bool isExpectedReserved)
    {
        Assert.AreEqual(isExpectedReserved, WellKnownMcpMetaKeys.IsReservedKey(key));
    }


    /// <summary>
    /// The local ordinal reservation policy of <see cref="WellKnownMcpMetaKeys"/> preserves second-label case.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">Specification</see>: "Any prefix where the second label is `modelcontextprotocol` or `mcp` is reserved for MCP use."
    /// </summary>
    /// <param name="prefix">The complete prefix.</param>
    /// <param name="isExpectedReserved">Whether the second label is the literal reserved label.</param>
    [TestMethod]
    [DataRow("dev.MCP/", false)]
    [DataRow("io.ModelContextProtocol/", false)]
    [DataRow("DEV.mcp/", true)]
    public void ReservedMetaPrefixesCompareTheSecondLabelOrdinally(string prefix, bool isExpectedReserved)
    {
        Assert.AreEqual(isExpectedReserved, WellKnownMcpMetaKeys.IsReservedPrefix(prefix));
    }


    /// <summary>
    /// The <see cref="WellKnownMcpMetaKeys"/> catalog spells the protocol fields literally.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">Specification</see>: "The following `_meta` keys are reserved by this specification:"
    /// </summary>
    /// <param name="expected">The literal name.</param>
    /// <param name="tabledValue">The catalog string.</param>
    /// <param name="utf8Text">The decoded UTF-8 twin.</param>
    /// <param name="isName">The name's recognition predicate.</param>
    [TestMethod]
    [DynamicData(nameof(GetMetaKeys))]
    public void ReservedMetaKeysSpellTheNames(string expected, string tabledValue, string utf8Text, Func<string, bool> isName)
    {
        Assert.AreEqual(expected, tabledValue);
    }


    /// <summary>
    /// The <see cref="WellKnownMcpMetaKeys"/> predicates apply the local ordinal JSON-member policy.
    /// <see href="https://www.jsonrpc.org/specification#conventions">JSON-RPC 2.0 §2</see>: "All member names exchanged between the Client and the Server that are considered for matching of any kind should be considered to be case-sensitive."
    /// </summary>
    /// <param name="expected">The literal name.</param>
    /// <param name="tabledValue">The catalog string.</param>
    /// <param name="utf8Text">The decoded UTF-8 twin.</param>
    /// <param name="isName">The name's recognition predicate.</param>
    [TestMethod]
    [DynamicData(nameof(GetMetaKeys))]
    public void ReservedMetaKeysCompareOrdinally(string expected, string tabledValue, string utf8Text, Func<string, bool> isName)
    {
        string received = new(expected.ToCharArray());

        Assert.IsTrue(isName(received));
        Assert.IsFalse(isName(expected.ToUpperInvariant()));
        Assert.IsTrue(WellKnownMcpMetaKeys.Equals(received, expected));
        Assert.IsFalse(WellKnownMcpMetaKeys.Equals(received, expected.ToUpperInvariant()));
    }


    /// <summary>
    /// The <see cref="WellKnownMcpMethodNames"/> catalog spells each schema interface's constant <c>method</c> member.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#jsonrpcrequest-method">Schema</see>: <c>method: string</c>
    /// on <c>JSONRPCRequest</c>, fixed per interface, for example
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#calltoolrequest-method">CallToolRequest</see>: <c>method: "tools/call"</c>.
    /// </summary>
    /// <param name="expected">The literal name.</param>
    /// <param name="tabledValue">The catalog string.</param>
    /// <param name="utf8Text">The decoded UTF-8 twin.</param>
    /// <param name="isName">The name's recognition predicate.</param>
    [TestMethod]
    [DynamicData(nameof(GetMethodNames))]
    public void MethodNamesSpellTheSchemasSet(string expected, string tabledValue, string utf8Text, Func<string, bool> isName)
    {
        Assert.AreEqual(expected, tabledValue);
    }


    /// <summary>
    /// The <see cref="WellKnownMcpMethodNames"/> predicates preserve the method's case-sensitive identity.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#case-sensitivity">Specification</see>: "Header values (such as method names) are case-sensitive."
    /// </summary>
    /// <param name="expected">The literal name.</param>
    /// <param name="tabledValue">The catalog string.</param>
    /// <param name="utf8Text">The decoded UTF-8 twin.</param>
    /// <param name="isName">The name's recognition predicate.</param>
    [TestMethod]
    [DynamicData(nameof(GetMethodNames))]
    public void MethodNamesCompareOrdinally(string expected, string tabledValue, string utf8Text, Func<string, bool> isName)
    {
        string received = new(expected.ToCharArray());

        Assert.IsTrue(isName(received));
        Assert.IsFalse(isName(expected.ToUpperInvariant()));
        Assert.IsFalse(isName(expected + "/other"));
        Assert.IsTrue(WellKnownMcpMethodNames.Equals(received, expected));
        Assert.IsFalse(WellKnownMcpMethodNames.Equals(received, expected.ToUpperInvariant()));
        Assert.AreSame(tabledValue, WellKnownMcpMethodNames.GetCanonicalizedValue(received));
    }


    /// <summary>
    /// The local storage contract for <see cref="WellKnownMcpMethodNames"/> and the other catalogs keeps UTF-8 literals equal to interned string values,
    /// so a reader of the UTF-8 wire bytes and a reader of strings name the same member.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.1">RFC 8259 Section 8.1</see>:
    /// "JSON text exchanged between systems that are not part of a closed ecosystem MUST be encoded using UTF-8".
    /// </summary>
    [TestMethod]
    public void CatalogNamesKeepUtf8TwinsAndInternedStrings()
    {
        foreach(object[] row in GetHeaderNames().Concat(GetMetaKeys()).Concat(GetMethodNames()))
        {
            Assert.AreEqual((string)row[0], (string)row[2]);
            Assert.AreSame(row[1], string.IsInterned((string)row[1]));
        }

        foreach(object[] row in GetErrorCodes())
        {
            McpErrorCode error = (McpErrorCode)row[0];
            Assert.AreEqual((string)row[2], Encoding.UTF8.GetString(error.NameUtf8));
            Assert.AreSame(error.Name, string.IsInterned(error.Name));
        }

        AssertUtf8Name("2026-07-28", McpProtocolRevision.Revision20260728Text, McpProtocolRevision.Revision20260728TextUtf8);
        AssertUtf8Name("2025-11-25", McpProtocolRevision.Revision20251125Text, McpProtocolRevision.Revision20251125TextUtf8);
        Assert.AreSame(McpProtocolRevision.Revision20260728Text, McpProtocolRevision.Revision20260728.Text);
        Assert.AreSame(McpProtocolRevision.Revision20251125Text, McpProtocolRevision.Revision20251125.Text);
        AssertUtf8Name("Mcp-Param-", WellKnownMcpHeaderNames.ParameterHeaderPrefix, WellKnownMcpHeaderNames.ParameterHeaderPrefixUtf8);
        AssertUtf8Name("=?base64?", WellKnownMcpHeaderNames.Base64SentinelPrefix, WellKnownMcpHeaderNames.Base64SentinelPrefixUtf8);
        AssertUtf8Name("?=", WellKnownMcpHeaderNames.Base64SentinelSuffix, WellKnownMcpHeaderNames.Base64SentinelSuffixUtf8);
    }


    /// <summary>
    /// The local trace-key aliases use the same catalog instances as <see cref="WellKnownHttpHeaderNames"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">Specification</see>: "the keys `traceparent`, `tracestate`, and `baggage` are reserved"
    /// </summary>
    [TestMethod]
    public void TraceMetaKeysShareTheHeaderCatalogNames()
    {
        Assert.AreSame(WellKnownHttpHeaderNames.TraceParent, WellKnownMcpMetaKeys.TraceParent);
        Assert.AreSame(WellKnownHttpHeaderNames.TraceState, WellKnownMcpMetaKeys.TraceState);
        Assert.AreSame(WellKnownHttpHeaderNames.Baggage, WellKnownMcpMetaKeys.Baggage);
    }


    /// <summary>
    /// The local <see cref="McpProtocolRevision.Parse"/> contract accepts real Gregorian dates in exactly YYYY-MM-DD form.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning#protocol-version-negotiation">Specification</see>: "Every request declares the protocol version it is using in its _meta field."
    /// The date format and calendar validation are local parser rules.
    /// </summary>
    /// <param name="text">The literal revision text.</param>
    [TestMethod]
    [DataRow("2026-07-28")]
    [DataRow("2025-11-25")]
    [DataRow("2024-02-29")]
    [DataRow("0001-01-01")]
    [DataRow("9999-12-31")]
    public void RevisionParseReturnsTheDateTextInASuccessResult(string text)
    {
        Result<McpProtocolRevision, McpProtocolRevisionParseError> result = McpProtocolRevision.Parse(text);

        Assert.IsTrue(result.IsSuccess);
        Assert.AreEqual(text, result.Value.Text);
    }


    /// <summary>
    /// The local <see cref="McpProtocolRevision.Parse"/> contract returns an invalid-format result for malformed date input.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning#protocol-version-negotiation">Specification</see>: "Every request declares the protocol version it is using in its _meta field."
    /// Null, whitespace, non-ASCII digits and invalid Gregorian dates are input failures.
    /// </summary>
    /// <param name="text">The malformed revision text.</param>
    [TestMethod]
    [DataRow(null)]
    [DataRow("")]
    [DataRow("2026-7-28")]
    [DataRow("2026/07/28")]
    [DataRow("2026-07-28 ")]
    [DataRow(" 2026-07-28")]
    [DataRow("2026-02-29")]
    [DataRow("2026-04-31")]
    [DataRow("2026-13-01")]
    [DataRow("0000-01-01")]
    [DataRow("\uFF12\uFF10\uFF12\uFF16-07-28")]
    public void RevisionParseReturnsFailureForInvalidInput(string? text)
    {
        Result<McpProtocolRevision, McpProtocolRevisionParseError> result = McpProtocolRevision.Parse(text);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(McpProtocolRevisionParseError.InvalidFormat, result.Error);
        Assert.IsNull(result.Value.Text);
    }


    /// <summary>
    /// The local record equality contract compares the text held by <see cref="McpProtocolRevision"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#case-sensitivity">Specification</see>: "Header values (such as method names) are case-sensitive."
    /// </summary>
    /// <param name="leftText">The first date text.</param>
    /// <param name="rightText">The separately allocated second date text.</param>
    /// <param name="isExpectedEqual">Whether the ordinal spellings are equal.</param>
    [TestMethod]
    [DataRow("2026-07-28", "2026-07-28", true)]
    [DataRow("2026-07-28", "2025-11-25", false)]
    [DataRow("2099-01-01", "2099-01-01", true)]
    public void RevisionRecordEqualityUsesTheText(string leftText, string rightText, bool isExpectedEqual)
    {
        var left = McpProtocolRevision.Parse(leftText);
        var right = McpProtocolRevision.Parse(new string(rightText.ToCharArray()));

        Assert.IsTrue(left.IsSuccess);
        Assert.IsTrue(right.IsSuccess);
        Assert.AreEqual(isExpectedEqual, left.Value == right.Value);
        Assert.AreEqual(isExpectedEqual, left.Value.Equals(right.Value));
    }


    /// <summary>
    /// The local <see cref="McpProtocolRevision"/> default is distinct from named protocol revisions.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning#protocol-version-negotiation">Specification</see>: "Every request declares the protocol version it is using in its _meta field."
    /// </summary>
    [TestMethod]
    public void DefaultRevisionCarriesNoRevisionText()
    {
        McpProtocolRevision revision = default;

        Assert.IsNull(revision.Text);
        Assert.AreNotEqual(McpProtocolRevision.Revision20260728, revision);
        Assert.AreNotEqual(McpProtocolRevision.Revision20251125, revision);
    }


    /// <summary>
    /// The named <see cref="McpErrorSituation"/> values set the explicit ordering of the literal status matrices.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/index#meta">Specification</see>: "A request missing any required field is malformed; the server MUST reject it with JSON-RPC error code `-32602` (Invalid params)."
    /// </summary>
    private static McpErrorSituation[] GetSituations() =>
    [
        McpErrorSituation.UnsupportedProtocolVersion,
        McpErrorSituation.HeaderMismatch,
        McpErrorSituation.MissingRequiredClientCapability,
        McpErrorSituation.MissingRequiredMetaField,
        McpErrorSituation.UnknownMethod
    ];


    /// <summary>
    /// The local UTF-8 storage assertion checks a literal name against both forms, including <see cref="McpProtocolRevision"/>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.1">RFC 8259 Section 8.1</see>:
    /// "JSON text exchanged between systems that are not part of a closed ecosystem MUST be encoded using UTF-8".
    /// </summary>
    /// <param name="expected">The literal expected wire text.</param>
    /// <param name="tabledValue">The interned string value.</param>
    /// <param name="utf8">The UTF-8 literal.</param>
    private static void AssertUtf8Name(string expected, string tabledValue, ReadOnlySpan<byte> utf8)
    {
        Assert.AreEqual(expected, tabledValue);
        Assert.AreEqual(expected, Encoding.UTF8.GetString(utf8));
        Assert.AreSame(tabledValue, string.IsInterned(tabledValue));
    }
}
