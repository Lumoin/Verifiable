using Verifiable.Cryptography.Text;

namespace Verifiable.DidComm.ReturnRoute;

/// <summary>
/// The well-known names of the DIDComm Messaging Return-Route and Queue Transport extension — the
/// <c>return_route</c>/<c>return_route_thread</c> message headers, their <c>none</c>/<c>all</c>/<c>thread</c>
/// directive values, and the Queue Transport URI, per
/// <see href="https://github.com/decentralized-identity/didcomm-messaging/blob/main/extensions/return_route/main.md">DIDComm Messaging Return-Route and Queue Transport Extension</see>.
/// </summary>
/// <remarks>
/// Each name declares its single UTF-8 source literal as a <c>ReadOnlySpan&lt;byte&gt;</c> property and
/// derives the interned string view through <see cref="Utf8Constants.ToInternedString"/>, matching
/// <see cref="Verifiable.DidComm.Routing.WellKnownRoutingNames"/> and
/// <see cref="Verifiable.DidComm.TrustPing.WellKnownTrustPingNames"/>.
/// </remarks>
public static class WellKnownReturnRouteNames
{
    /// <summary>The UTF-8 source literal of <see cref="ReturnRoute"/>.</summary>
    public static ReadOnlySpan<byte> ReturnRouteUtf8 => "return_route"u8;

    /// <summary>
    /// The <c>return_route</c> message header — OPTIONAL. The directive controlling whether, and how, the
    /// receiving agent may use the inbound connection to return messages (§Return Route Header).
    /// </summary>
    public static readonly string ReturnRoute = Utf8Constants.ToInternedString(ReturnRouteUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ReturnRouteThread"/>.</summary>
    public static ReadOnlySpan<byte> ReturnRouteThreadUtf8 => "return_route_thread"u8;

    /// <summary>
    /// The <c>return_route_thread</c> message header — REQUIRED when <c>return_route</c> is <see cref="Thread"/>.
    /// Names the thread whose replies are returned over the connection (§Return Route Header: "thread: Send
    /// all messages matching the DID and thread specified in the return_route_thread attribute").
    /// </summary>
    public static readonly string ReturnRouteThread = Utf8Constants.ToInternedString(ReturnRouteThreadUtf8);

    /// <summary>The UTF-8 source literal of <see cref="None"/>.</summary>
    public static ReadOnlySpan<byte> NoneUtf8 => "none"u8;

    /// <summary>
    /// The <c>none</c> return-route directive — the default: no messages should be returned over this
    /// connection (§Return Route Header: "none: Default. No messages should be returned over this
    /// connection. If return_route is omitted, this is the default value.").
    /// </summary>
    public static readonly string None = Utf8Constants.ToInternedString(NoneUtf8);

    /// <summary>The UTF-8 source literal of <see cref="All"/>.</summary>
    public static ReadOnlySpan<byte> AllUtf8 => "all"u8;

    /// <summary>
    /// The <c>all</c> return-route directive — send all messages for this DID over the connection
    /// (§Return Route Header).
    /// </summary>
    public static readonly string All = Utf8Constants.ToInternedString(AllUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Thread"/>.</summary>
    public static ReadOnlySpan<byte> ThreadUtf8 => "thread"u8;

    /// <summary>
    /// The <c>thread</c> return-route directive — send all messages matching the DID and thread named by
    /// the <see cref="ReturnRouteThread"/> header over the connection (§Return Route Header).
    /// </summary>
    public static readonly string Thread = Utf8Constants.ToInternedString(ThreadUtf8);

    /// <summary>The UTF-8 source literal of <see cref="QueueTransportUri"/>.</summary>
    public static ReadOnlySpan<byte> QueueTransportUriUtf8 => "didcomm:transport/queue"u8;

    /// <summary>
    /// The Queue Transport URI — usable as a <c>serviceEndpoint</c> value to mark that messages addressed
    /// there are held at the sender for pickup by the recipient rather than transmitted (§Queue Transport:
    /// "The Queue Transport is a special form of transport where messages are held at the sender for
    /// pickup by the recipient."). It names a hold-at-sender policy, not a dispatchable transport target.
    /// </summary>
    public static readonly string QueueTransportUri = Utf8Constants.ToInternedString(QueueTransportUriUtf8);
}
