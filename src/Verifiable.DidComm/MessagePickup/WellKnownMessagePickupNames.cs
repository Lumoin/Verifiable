using Verifiable.Cryptography.Text;

namespace Verifiable.DidComm.MessagePickup;

/// <summary>
/// The well-known names of the DIDComm Message Pickup Protocol 3.0 — the protocol identifier URI, the six
/// Message Type URIs, the <c>body</c> member names, and the Live Mode problem code, per
/// <see href="https://didcomm.org/messagepickup/3.0/">DIDComm Message Pickup Protocol 3.0</see>.
/// </summary>
/// <remarks>
/// <para>
/// Each protocol identifier URI, MTURI, and body-member name declares its single UTF-8 source literal as a
/// <c>ReadOnlySpan&lt;byte&gt;</c> property and derives the interned string view through
/// <see cref="Utf8Constants.ToInternedString"/>, matching
/// <see cref="Verifiable.DidComm.TrustPing.WellKnownTrustPingNames"/> and
/// <see cref="Verifiable.DidComm.ReturnRoute.WellKnownReturnRouteNames"/>. The problem code
/// (<see cref="LiveModeNotSupported"/>) instead follows the
/// <see cref="Verifiable.DidComm.ProblemReports.WellKnownProblemCodes"/> convention — a plain
/// <c>public static string</c> property returning its literal directly, not a UTF-8/interned-string pair.
/// The PIURI path segment is <c>messagepickup</c> — NO hyphen; Message Pickup 4.0's <c>message-pickup</c>
/// spelling names a different, unimplemented protocol and must never appear here.
/// </para>
/// <para>
/// The spec's prose is inconsistent with its own wire tokens in two places that
/// <see cref="MessageTypeUri.IsSameMessageType(MessageTypeUri?)"/> absorbs rather than the constants
/// needing to track: the walkthrough calls the <see cref="DeliveryType"/> response "the message-delivery
/// message", but the actual type token is <c>delivery</c> (noted again on <see cref="DeliveryType"/>); and
/// §Live Mode / §Live Mode Change write <c>live_delivery_change</c>, <c>problem_report</c>, and
/// <c>status_request</c> with underscores in running prose while the wire MTURIs are hyphenated
/// (<c>live-delivery-change</c>, <c>problem-report</c>, <c>status-request</c>) — an inbound MTURI carrying
/// the underscored prose spelling still dispatches, because <c>IsSameMessageType</c> compares the protocol
/// and message-type-name tokens ignoring punctuation.
/// </para>
/// </remarks>
public static class WellKnownMessagePickupNames
{
    /// <summary>The UTF-8 source literal of <see cref="MessagePickupProtocol"/>.</summary>
    public static ReadOnlySpan<byte> MessagePickupProtocolUtf8 => "https://didcomm.org/messagepickup/3.0"u8;

    /// <summary>The protocol identifier URI (PIURI) of Message Pickup Protocol 3.0.</summary>
    public static string MessagePickupProtocol { get; } = Utf8Constants.ToInternedString(MessagePickupProtocolUtf8);

    /// <summary>The UTF-8 source literal of <see cref="StatusRequestType"/>.</summary>
    public static ReadOnlySpan<byte> StatusRequestTypeUtf8 => "https://didcomm.org/messagepickup/3.0/status-request"u8;

    /// <summary>The <c>status-request</c> Message Type URI — a recipient's query for how many messages are pending (§Status Request).</summary>
    public static string StatusRequestType { get; } = Utf8Constants.ToInternedString(StatusRequestTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="StatusType"/>.</summary>
    public static ReadOnlySpan<byte> StatusTypeUtf8 => "https://didcomm.org/messagepickup/3.0/status"u8;

    /// <summary>The <c>status</c> Message Type URI — the mediator's report of queue state (§Status).</summary>
    public static string StatusType { get; } = Utf8Constants.ToInternedString(StatusTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DeliveryRequestType"/>.</summary>
    public static ReadOnlySpan<byte> DeliveryRequestTypeUtf8 => "https://didcomm.org/messagepickup/3.0/delivery-request"u8;

    /// <summary>The <c>delivery-request</c> Message Type URI — a recipient's request that pending messages be delivered (§Delivery Request).</summary>
    public static string DeliveryRequestType { get; } = Utf8Constants.ToInternedString(DeliveryRequestTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DeliveryType"/>.</summary>
    public static ReadOnlySpan<byte> DeliveryTypeUtf8 => "https://didcomm.org/messagepickup/3.0/delivery"u8;

    /// <summary>
    /// The <c>delivery</c> Message Type URI — the batch-of-attachments response to a <c>delivery-request</c>
    /// (§Message Delivery). TRAP: the walkthrough prose calls this "the message-delivery message", but the
    /// actual wire type token is <c>delivery</c>, not <c>message-delivery</c>.
    /// </summary>
    public static string DeliveryType { get; } = Utf8Constants.ToInternedString(DeliveryTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="MessagesReceivedType"/>.</summary>
    public static ReadOnlySpan<byte> MessagesReceivedTypeUtf8 => "https://didcomm.org/messagepickup/3.0/messages-received"u8;

    /// <summary>
    /// The <c>messages-received</c> Message Type URI — the recipient's delivery acknowledgment (§Messages
    /// Received). TRAP: §Connectivity and §Basic Walkthrough prose call this the "message-received" message
    /// (singular), but the actual wire type token is <c>messages-received</c> (plural), not
    /// <c>message-received</c> — and unlike the delivery/underscore traps elsewhere in this protocol,
    /// <see cref="MessageTypeUri.IsSameMessageType(MessageTypeUri?)"/> does NOT absorb this one: comparison
    /// ignores case and punctuation, not a missing/extra letter, so "messagereceived" and "messagesreceived"
    /// are different message-type-name tokens.
    /// </summary>
    public static string MessagesReceivedType { get; } = Utf8Constants.ToInternedString(MessagesReceivedTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="LiveDeliveryChangeType"/>.</summary>
    public static ReadOnlySpan<byte> LiveDeliveryChangeTypeUtf8 => "https://didcomm.org/messagepickup/3.0/live-delivery-change"u8;

    /// <summary>
    /// The <c>live-delivery-change</c> Message Type URI — sets the <c>live_delivery</c> state (§Live Mode
    /// Change). Upon receiving one, the spec says the mediator "<c>**MUST*</c> respond with a <c>status</c>
    /// message" — the spec source carries a malformed triple-asterisk emphasis there rather than the usual
    /// double asterisk; this library reads it as MUST (§Live Mode Change).
    /// </summary>
    public static string LiveDeliveryChangeType { get; } = Utf8Constants.ToInternedString(LiveDeliveryChangeTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="RecipientDid"/>.</summary>
    public static ReadOnlySpan<byte> RecipientDidUtf8 => "recipient_did"u8;

    /// <summary>The <c>body.recipient_did</c> member — OPTIONAL on <c>status-request</c>/<c>delivery-request</c>, echoed on <c>status</c>/<c>delivery</c> (§Status Request, §Status, §Delivery Request, §Message Delivery).</summary>
    public static string RecipientDid { get; } = Utf8Constants.ToInternedString(RecipientDidUtf8);

    /// <summary>The UTF-8 source literal of <see cref="MessageCount"/>.</summary>
    public static ReadOnlySpan<byte> MessageCountUtf8 => "message_count"u8;

    /// <summary>The <c>status</c> body <c>message_count</c> member — REQUIRED, the only required status attribute (§Status).</summary>
    public static string MessageCount { get; } = Utf8Constants.ToInternedString(MessageCountUtf8);

    /// <summary>The UTF-8 source literal of <see cref="LongestWaitedSeconds"/>.</summary>
    public static ReadOnlySpan<byte> LongestWaitedSecondsUtf8 => "longest_waited_seconds"u8;

    /// <summary>The <c>status</c> body <c>longest_waited_seconds</c> member — OPTIONAL, the longest delay of any message in the queue, in seconds (§Status).</summary>
    public static string LongestWaitedSeconds { get; } = Utf8Constants.ToInternedString(LongestWaitedSecondsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="NewestReceivedTime"/>.</summary>
    public static ReadOnlySpan<byte> NewestReceivedTimeUtf8 => "newest_received_time"u8;

    /// <summary>The <c>status</c> body <c>newest_received_time</c> member — OPTIONAL, UTC epoch seconds as an integer (§Status).</summary>
    public static string NewestReceivedTime { get; } = Utf8Constants.ToInternedString(NewestReceivedTimeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="OldestReceivedTime"/>.</summary>
    public static ReadOnlySpan<byte> OldestReceivedTimeUtf8 => "oldest_received_time"u8;

    /// <summary>The <c>status</c> body <c>oldest_received_time</c> member — OPTIONAL, UTC epoch seconds as an integer (§Status).</summary>
    public static string OldestReceivedTime { get; } = Utf8Constants.ToInternedString(OldestReceivedTimeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TotalBytes"/>.</summary>
    public static ReadOnlySpan<byte> TotalBytesUtf8 => "total_bytes"u8;

    /// <summary>The <c>status</c> body <c>total_bytes</c> member — OPTIONAL, the total size of all queued messages (§Status).</summary>
    public static string TotalBytes { get; } = Utf8Constants.ToInternedString(TotalBytesUtf8);

    /// <summary>The UTF-8 source literal of <see cref="LiveDelivery"/>.</summary>
    public static ReadOnlySpan<byte> LiveDeliveryUtf8 => "live_delivery"u8;

    /// <summary>The <c>live_delivery</c> body member — on <c>status</c> the current Live Mode state, on <c>live-delivery-change</c> the requested state (§Status, §Live Mode Change).</summary>
    public static string LiveDelivery { get; } = Utf8Constants.ToInternedString(LiveDeliveryUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Limit"/>.</summary>
    public static ReadOnlySpan<byte> LimitUtf8 => "limit"u8;

    /// <summary>
    /// The <c>delivery-request</c> body <c>limit</c> member — REQUIRED (§Delivery Request). TRAP: Message
    /// Pickup 4.0 renames this member to <c>message_count_limit</c>; 3.0's name is <c>limit</c> — the two
    /// MUST NOT be cross-contaminated.
    /// </summary>
    public static string Limit { get; } = Utf8Constants.ToInternedString(LimitUtf8);

    /// <summary>The UTF-8 source literal of <see cref="MessageIdList"/>.</summary>
    public static ReadOnlySpan<byte> MessageIdListUtf8 => "message_id_list"u8;

    /// <summary>The <c>messages-received</c> body <c>message_id_list</c> member — the ids of received messages, taken verbatim from the delivery attachment descriptors (§Messages Received).</summary>
    public static string MessageIdList { get; } = Utf8Constants.ToInternedString(MessageIdListUtf8);

    /// <summary>
    /// The <c>e.m.live-mode-not-supported</c> problem code — sent when a <c>live-delivery-change</c> requests
    /// Live Mode on a connection incapable of it (§Live Mode Change). Message Pickup contributes only this
    /// constant; the problem report itself is built with the existing
    /// <see cref="Verifiable.DidComm.ProblemReports.DidCommProblemReportExtensions.CreateProblemReport"/> surface.
    /// </summary>
    public static string LiveModeNotSupported => "e.m.live-mode-not-supported";
}
