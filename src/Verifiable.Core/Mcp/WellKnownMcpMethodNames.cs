using Verifiable.Cryptography.Text;

namespace Verifiable.Core.Mcp;

/// <summary>
/// The method names in the MCP schema with UTF-8 twins, ordinal predicates, and
/// <see cref="GetCanonicalizedValue"/> for sharing their interned strings.
/// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#case-sensitivity">Case Sensitivity</see>:
/// "Header values (such as method names) are case-sensitive."
/// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
/// </summary>
public static class WellKnownMcpMethodNames
{
    /// <summary>
    /// The UTF-8 source of <see cref="CompletionComplete"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#completerequest">Schema</see>:
    /// "A request from the client to the server, to ask for completion options."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static ReadOnlySpan<byte> CompletionCompleteUtf8 => "completion/complete"u8;

    /// <summary>
    /// The interned method name derived from <see cref="CompletionCompleteUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#completerequest">Schema</see>:
    /// "A request from the client to the server, to ask for completion options."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static string CompletionComplete { get; } = Utf8Constants.ToInternedString(CompletionCompleteUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="ElicitationCreate"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#elicitrequest">Schema</see>:
    /// "A request from the server to elicit additional information from the user via the client."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static ReadOnlySpan<byte> ElicitationCreateUtf8 => "elicitation/create"u8;

    /// <summary>
    /// The interned method name derived from <see cref="ElicitationCreateUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#elicitrequest">Schema</see>:
    /// "A request from the server to elicit additional information from the user via the client."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static string ElicitationCreate { get; } = Utf8Constants.ToInternedString(ElicitationCreateUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="NotificationsCancelled"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#cancellednotification">Schema</see>:
    /// "This notification indicates that the result will be unused, so any associated processing SHOULD cease."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static ReadOnlySpan<byte> NotificationsCancelledUtf8 => "notifications/cancelled"u8;

    /// <summary>
    /// The interned method name derived from <see cref="NotificationsCancelledUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#cancellednotification">Schema</see>:
    /// "This notification indicates that the result will be unused, so any associated processing SHOULD cease."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static string NotificationsCancelled { get; } = Utf8Constants.ToInternedString(NotificationsCancelledUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="NotificationsMessage"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#loggingmessagenotification">Schema</see>:
    /// "JSONRPCNotification of a log message passed from server to client."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static ReadOnlySpan<byte> NotificationsMessageUtf8 => "notifications/message"u8;

    /// <summary>
    /// The interned method name derived from <see cref="NotificationsMessageUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#loggingmessagenotification">Schema</see>:
    /// "JSONRPCNotification of a log message passed from server to client."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static string NotificationsMessage { get; } = Utf8Constants.ToInternedString(NotificationsMessageUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="NotificationsProgress"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#progressnotification">Schema</see>:
    /// "An out-of-band notification used to inform the receiver of a progress update for a long-running request."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static ReadOnlySpan<byte> NotificationsProgressUtf8 => "notifications/progress"u8;

    /// <summary>
    /// The interned method name derived from <see cref="NotificationsProgressUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#progressnotification">Schema</see>:
    /// "An out-of-band notification used to inform the receiver of a progress update for a long-running request."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static string NotificationsProgress { get; } = Utf8Constants.ToInternedString(NotificationsProgressUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="NotificationsPromptsListChanged"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#promptlistchangednotification">Schema</see>:
    /// "An optional notification from the server to the client, informing it that the list of prompts it offers has changed."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static ReadOnlySpan<byte> NotificationsPromptsListChangedUtf8 => "notifications/prompts/list_changed"u8;

    /// <summary>
    /// The interned method name derived from <see cref="NotificationsPromptsListChangedUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#promptlistchangednotification">Schema</see>:
    /// "An optional notification from the server to the client, informing it that the list of prompts it offers has changed."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static string NotificationsPromptsListChanged { get; } = Utf8Constants.ToInternedString(NotificationsPromptsListChangedUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="NotificationsResourcesListChanged"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#resourcelistchangednotification">Schema</see>:
    /// "An optional notification from the server to the client, informing it that the list of resources it can read from has changed."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static ReadOnlySpan<byte> NotificationsResourcesListChangedUtf8 => "notifications/resources/list_changed"u8;

    /// <summary>
    /// The interned method name derived from <see cref="NotificationsResourcesListChangedUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#resourcelistchangednotification">Schema</see>:
    /// "An optional notification from the server to the client, informing it that the list of resources it can read from has changed."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static string NotificationsResourcesListChanged { get; } = Utf8Constants.ToInternedString(NotificationsResourcesListChangedUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="NotificationsResourcesUpdated"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#resourceupdatednotification">Schema</see>:
    /// "A notification from the server to the client, informing it that a resource has changed and may need to be read again."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static ReadOnlySpan<byte> NotificationsResourcesUpdatedUtf8 => "notifications/resources/updated"u8;

    /// <summary>
    /// The interned method name derived from <see cref="NotificationsResourcesUpdatedUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#resourceupdatednotification">Schema</see>:
    /// "A notification from the server to the client, informing it that a resource has changed and may need to be read again."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static string NotificationsResourcesUpdated { get; } = Utf8Constants.ToInternedString(NotificationsResourcesUpdatedUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="NotificationsSubscriptionsAcknowledged"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#subscriptionsacknowledgednotification">Schema</see>:
    /// "Sent by the server to acknowledge that a subscriptions/listen subscription has been established and to report which notification types it agreed to honor."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static ReadOnlySpan<byte> NotificationsSubscriptionsAcknowledgedUtf8 => "notifications/subscriptions/acknowledged"u8;

    /// <summary>
    /// The interned method name derived from <see cref="NotificationsSubscriptionsAcknowledgedUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#subscriptionsacknowledgednotification">Schema</see>:
    /// "Sent by the server to acknowledge that a subscriptions/listen subscription has been established and to report which notification types it agreed to honor."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static string NotificationsSubscriptionsAcknowledged { get; } = Utf8Constants.ToInternedString(NotificationsSubscriptionsAcknowledgedUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="NotificationsToolsListChanged"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#toollistchangednotification">Schema</see>:
    /// "An optional notification from the server to the client, informing it that the list of tools it offers has changed."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static ReadOnlySpan<byte> NotificationsToolsListChangedUtf8 => "notifications/tools/list_changed"u8;

    /// <summary>
    /// The interned method name derived from <see cref="NotificationsToolsListChangedUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#toollistchangednotification">Schema</see>:
    /// "An optional notification from the server to the client, informing it that the list of tools it offers has changed."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static string NotificationsToolsListChanged { get; } = Utf8Constants.ToInternedString(NotificationsToolsListChangedUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="PromptsGet"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#getpromptrequest">Schema</see>:
    /// "Used by the client to get a prompt provided by the server."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static ReadOnlySpan<byte> PromptsGetUtf8 => "prompts/get"u8;

    /// <summary>
    /// The interned method name derived from <see cref="PromptsGetUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#getpromptrequest">Schema</see>:
    /// "Used by the client to get a prompt provided by the server."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static string PromptsGet { get; } = Utf8Constants.ToInternedString(PromptsGetUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="PromptsList"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#listpromptsrequest">Schema</see>:
    /// "Sent from the client to request a list of prompts and prompt templates the server has."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static ReadOnlySpan<byte> PromptsListUtf8 => "prompts/list"u8;

    /// <summary>
    /// The interned method name derived from <see cref="PromptsListUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#listpromptsrequest">Schema</see>:
    /// "Sent from the client to request a list of prompts and prompt templates the server has."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static string PromptsList { get; } = Utf8Constants.ToInternedString(PromptsListUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="ResourcesList"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#listresourcesrequest">Schema</see>:
    /// "Sent from the client to request a list of resources the server has."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static ReadOnlySpan<byte> ResourcesListUtf8 => "resources/list"u8;

    /// <summary>
    /// The interned method name derived from <see cref="ResourcesListUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#listresourcesrequest">Schema</see>:
    /// "Sent from the client to request a list of resources the server has."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static string ResourcesList { get; } = Utf8Constants.ToInternedString(ResourcesListUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="ResourcesRead"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#readresourcerequest">Schema</see>:
    /// "Sent from the client to the server, to read a specific resource URI."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static ReadOnlySpan<byte> ResourcesReadUtf8 => "resources/read"u8;

    /// <summary>
    /// The interned method name derived from <see cref="ResourcesReadUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#readresourcerequest">Schema</see>:
    /// "Sent from the client to the server, to read a specific resource URI."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static string ResourcesRead { get; } = Utf8Constants.ToInternedString(ResourcesReadUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="ResourcesTemplatesList"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#listresourcetemplatesrequest">Schema</see>:
    /// "Sent from the client to request a list of resource templates the server has."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static ReadOnlySpan<byte> ResourcesTemplatesListUtf8 => "resources/templates/list"u8;

    /// <summary>
    /// The interned method name derived from <see cref="ResourcesTemplatesListUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#listresourcetemplatesrequest">Schema</see>:
    /// "Sent from the client to request a list of resource templates the server has."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static string ResourcesTemplatesList { get; } = Utf8Constants.ToInternedString(ResourcesTemplatesListUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="RootsList"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#listrootsrequest">Schema</see>:
    /// "Sent from the server to request a list of root URIs from the client."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static ReadOnlySpan<byte> RootsListUtf8 => "roots/list"u8;

    /// <summary>
    /// The interned method name derived from <see cref="RootsListUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#listrootsrequest">Schema</see>:
    /// "Sent from the server to request a list of root URIs from the client."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static string RootsList { get; } = Utf8Constants.ToInternedString(RootsListUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="SamplingCreateMessage"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#createmessagerequest">Schema</see>:
    /// "A request from the server to sample an LLM via the client."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static ReadOnlySpan<byte> SamplingCreateMessageUtf8 => "sampling/createMessage"u8;

    /// <summary>
    /// The interned method name derived from <see cref="SamplingCreateMessageUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#createmessagerequest">Schema</see>:
    /// "A request from the server to sample an LLM via the client."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static string SamplingCreateMessage { get; } = Utf8Constants.ToInternedString(SamplingCreateMessageUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="ServerDiscover"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#discoverrequest">Schema</see>:
    /// "A request from the client asking the server to advertise its supported protocol versions, capabilities, and other metadata."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static ReadOnlySpan<byte> ServerDiscoverUtf8 => "server/discover"u8;

    /// <summary>
    /// The interned method name derived from <see cref="ServerDiscoverUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#discoverrequest">Schema</see>:
    /// "A request from the client asking the server to advertise its supported protocol versions, capabilities, and other metadata."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static string ServerDiscover { get; } = Utf8Constants.ToInternedString(ServerDiscoverUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="SubscriptionsListen"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#subscriptionslistenrequest">Schema</see>:
    /// "Sent from the client to open a long-lived channel for receiving notifications outside the context of a specific request."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static ReadOnlySpan<byte> SubscriptionsListenUtf8 => "subscriptions/listen"u8;

    /// <summary>
    /// The interned method name derived from <see cref="SubscriptionsListenUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#subscriptionslistenrequest">Schema</see>:
    /// "Sent from the client to open a long-lived channel for receiving notifications outside the context of a specific request."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static string SubscriptionsListen { get; } = Utf8Constants.ToInternedString(SubscriptionsListenUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="ToolsCall"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#calltoolrequest">Schema</see>:
    /// "Used by the client to invoke a tool provided by the server."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static ReadOnlySpan<byte> ToolsCallUtf8 => "tools/call"u8;

    /// <summary>
    /// The interned method name derived from <see cref="ToolsCallUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#calltoolrequest">Schema</see>:
    /// "Used by the client to invoke a tool provided by the server."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static string ToolsCall { get; } = Utf8Constants.ToInternedString(ToolsCallUtf8);

    /// <summary>
    /// The UTF-8 source of <see cref="ToolsList"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#listtoolsrequest">Schema</see>:
    /// "Sent from the client to request a list of tools the server has."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static ReadOnlySpan<byte> ToolsListUtf8 => "tools/list"u8;

    /// <summary>
    /// The interned method name derived from <see cref="ToolsListUtf8"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#listtoolsrequest">Schema</see>:
    /// "Sent from the client to request a list of tools the server has."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static string ToolsList { get; } = Utf8Constants.ToInternedString(ToolsListUtf8);


    /// <summary>
    /// Whether <paramref name="value"/> equals <see cref="CompletionComplete"/> under <see cref="Equals"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#completerequest">Schema</see>:
    /// "A request from the client to the server, to ask for completion options."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static bool IsCompletionComplete(string value) => Equals(value, CompletionComplete);

    /// <summary>
    /// Whether <paramref name="value"/> equals <see cref="ElicitationCreate"/> under <see cref="Equals"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#elicitrequest">Schema</see>:
    /// "A request from the server to elicit additional information from the user via the client."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static bool IsElicitationCreate(string value) => Equals(value, ElicitationCreate);

    /// <summary>
    /// Whether <paramref name="value"/> equals <see cref="NotificationsCancelled"/> under <see cref="Equals"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#cancellednotification">Schema</see>:
    /// "This notification indicates that the result will be unused, so any associated processing SHOULD cease."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static bool IsNotificationsCancelled(string value) => Equals(value, NotificationsCancelled);

    /// <summary>
    /// Whether <paramref name="value"/> equals <see cref="NotificationsMessage"/> under <see cref="Equals"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#loggingmessagenotification">Schema</see>:
    /// "JSONRPCNotification of a log message passed from server to client."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static bool IsNotificationsMessage(string value) => Equals(value, NotificationsMessage);

    /// <summary>
    /// Whether <paramref name="value"/> equals <see cref="NotificationsProgress"/> under <see cref="Equals"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#progressnotification">Schema</see>:
    /// "An out-of-band notification used to inform the receiver of a progress update for a long-running request."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static bool IsNotificationsProgress(string value) => Equals(value, NotificationsProgress);

    /// <summary>
    /// Whether <paramref name="value"/> equals <see cref="NotificationsPromptsListChanged"/> under <see cref="Equals"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#promptlistchangednotification">Schema</see>:
    /// "An optional notification from the server to the client, informing it that the list of prompts it offers has changed."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static bool IsNotificationsPromptsListChanged(string value) => Equals(value, NotificationsPromptsListChanged);

    /// <summary>
    /// Whether <paramref name="value"/> equals <see cref="NotificationsResourcesListChanged"/> under <see cref="Equals"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#resourcelistchangednotification">Schema</see>:
    /// "An optional notification from the server to the client, informing it that the list of resources it can read from has changed."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static bool IsNotificationsResourcesListChanged(string value) => Equals(value, NotificationsResourcesListChanged);

    /// <summary>
    /// Whether <paramref name="value"/> equals <see cref="NotificationsResourcesUpdated"/> under <see cref="Equals"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#resourceupdatednotification">Schema</see>:
    /// "A notification from the server to the client, informing it that a resource has changed and may need to be read again."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static bool IsNotificationsResourcesUpdated(string value) => Equals(value, NotificationsResourcesUpdated);

    /// <summary>
    /// Whether <paramref name="value"/> equals <see cref="NotificationsSubscriptionsAcknowledged"/> under <see cref="Equals"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#subscriptionsacknowledgednotification">Schema</see>:
    /// "Sent by the server to acknowledge that a subscriptions/listen subscription has been established and to report which notification types it agreed to honor."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static bool IsNotificationsSubscriptionsAcknowledged(string value) => Equals(value, NotificationsSubscriptionsAcknowledged);

    /// <summary>
    /// Whether <paramref name="value"/> equals <see cref="NotificationsToolsListChanged"/> under <see cref="Equals"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#toollistchangednotification">Schema</see>:
    /// "An optional notification from the server to the client, informing it that the list of tools it offers has changed."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static bool IsNotificationsToolsListChanged(string value) => Equals(value, NotificationsToolsListChanged);

    /// <summary>
    /// Whether <paramref name="value"/> equals <see cref="PromptsGet"/> under <see cref="Equals"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#getpromptrequest">Schema</see>:
    /// "Used by the client to get a prompt provided by the server."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static bool IsPromptsGet(string value) => Equals(value, PromptsGet);

    /// <summary>
    /// Whether <paramref name="value"/> equals <see cref="PromptsList"/> under <see cref="Equals"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#listpromptsrequest">Schema</see>:
    /// "Sent from the client to request a list of prompts and prompt templates the server has."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static bool IsPromptsList(string value) => Equals(value, PromptsList);

    /// <summary>
    /// Whether <paramref name="value"/> equals <see cref="ResourcesList"/> under <see cref="Equals"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#listresourcesrequest">Schema</see>:
    /// "Sent from the client to request a list of resources the server has."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static bool IsResourcesList(string value) => Equals(value, ResourcesList);

    /// <summary>
    /// Whether <paramref name="value"/> equals <see cref="ResourcesRead"/> under <see cref="Equals"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#readresourcerequest">Schema</see>:
    /// "Sent from the client to the server, to read a specific resource URI."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static bool IsResourcesRead(string value) => Equals(value, ResourcesRead);

    /// <summary>
    /// Whether <paramref name="value"/> equals <see cref="ResourcesTemplatesList"/> under <see cref="Equals"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#listresourcetemplatesrequest">Schema</see>:
    /// "Sent from the client to request a list of resource templates the server has."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static bool IsResourcesTemplatesList(string value) => Equals(value, ResourcesTemplatesList);

    /// <summary>
    /// Whether <paramref name="value"/> equals <see cref="RootsList"/> under <see cref="Equals"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#listrootsrequest">Schema</see>:
    /// "Sent from the server to request a list of root URIs from the client."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static bool IsRootsList(string value) => Equals(value, RootsList);

    /// <summary>
    /// Whether <paramref name="value"/> equals <see cref="SamplingCreateMessage"/> under <see cref="Equals"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#createmessagerequest">Schema</see>:
    /// "A request from the server to sample an LLM via the client."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static bool IsSamplingCreateMessage(string value) => Equals(value, SamplingCreateMessage);

    /// <summary>
    /// Whether <paramref name="value"/> equals <see cref="ServerDiscover"/> under <see cref="Equals"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#discoverrequest">Schema</see>:
    /// "A request from the client asking the server to advertise its supported protocol versions, capabilities, and other metadata."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static bool IsServerDiscover(string value) => Equals(value, ServerDiscover);

    /// <summary>
    /// Whether <paramref name="value"/> equals <see cref="SubscriptionsListen"/> under <see cref="Equals"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#subscriptionslistenrequest">Schema</see>:
    /// "Sent from the client to open a long-lived channel for receiving notifications outside the context of a specific request."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static bool IsSubscriptionsListen(string value) => Equals(value, SubscriptionsListen);

    /// <summary>
    /// Whether <paramref name="value"/> equals <see cref="ToolsCall"/> under <see cref="Equals"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#calltoolrequest">Schema</see>:
    /// "Used by the client to invoke a tool provided by the server."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static bool IsToolsCall(string value) => Equals(value, ToolsCall);

    /// <summary>
    /// Whether <paramref name="value"/> equals <see cref="ToolsList"/> under <see cref="Equals"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/schema#listtoolsrequest">Schema</see>:
    /// "Sent from the client to request a list of tools the server has."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static bool IsToolsList(string value) => Equals(value, ToolsList);


    /// <summary>
    /// Returns the interned instance for an ordinally matching method name, or the input unchanged.
    /// This is the local storage policy using <see cref="Equals"/> under
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#case-sensitivity">Case Sensitivity</see>:
    /// "Header values (such as method names) are case-sensitive."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static string GetCanonicalizedValue(string value) => value switch
    {
        var v when IsCompletionComplete(v) => CompletionComplete,
        var v when IsElicitationCreate(v) => ElicitationCreate,
        var v when IsNotificationsCancelled(v) => NotificationsCancelled,
        var v when IsNotificationsMessage(v) => NotificationsMessage,
        var v when IsNotificationsProgress(v) => NotificationsProgress,
        var v when IsNotificationsPromptsListChanged(v) => NotificationsPromptsListChanged,
        var v when IsNotificationsResourcesListChanged(v) => NotificationsResourcesListChanged,
        var v when IsNotificationsResourcesUpdated(v) => NotificationsResourcesUpdated,
        var v when IsNotificationsSubscriptionsAcknowledged(v) => NotificationsSubscriptionsAcknowledged,
        var v when IsNotificationsToolsListChanged(v) => NotificationsToolsListChanged,
        var v when IsPromptsGet(v) => PromptsGet,
        var v when IsPromptsList(v) => PromptsList,
        var v when IsResourcesList(v) => ResourcesList,
        var v when IsResourcesRead(v) => ResourcesRead,
        var v when IsResourcesTemplatesList(v) => ResourcesTemplatesList,
        var v when IsRootsList(v) => RootsList,
        var v when IsSamplingCreateMessage(v) => SamplingCreateMessage,
        var v when IsServerDiscover(v) => ServerDiscover,
        var v when IsSubscriptionsListen(v) => SubscriptionsListen,
        var v when IsToolsCall(v) => ToolsCall,
        var v when IsToolsList(v) => ToolsList,
        _ => value
    };


    /// <summary>
    /// Compares method names using <see cref="StringComparison.Ordinal"/>.
    /// <see href="https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#case-sensitivity">Case Sensitivity</see>:
    /// "Header values (such as method names) are case-sensitive."
    /// MCP 2026-07-28 is the current revision. The 2025-11-25 transport page specifies no HTTP status pairing for the cataloged JSON-RPC request-error codes.
    /// </summary>
    public static bool Equals(string valueA, string valueB) =>
        ReferenceEquals(valueA, valueB) || string.Equals(valueA, valueB, StringComparison.Ordinal);
}
