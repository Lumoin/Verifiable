using Verifiable.Cryptography.Text;

namespace Verifiable.DidComm.CoordinateMediation;

/// <summary>
/// The well-known names of the DIDComm Coordinate Mediation Protocol 2.0 — the protocol identifier URI, the
/// seven Message Type URIs, the <c>body</c> member names, and the closed <c>action</c>/<c>result</c> value
/// sets, per
/// <see href="https://didcomm.org/coordinate-mediation/2.0/">DIDComm Coordinate Mediation Protocol 2.0</see>.
/// </summary>
/// <remarks>
/// <para>
/// The PIURI, the seven MTURIs, and the thirteen body-member names each declare their single UTF-8 source
/// literal as a <c>ReadOnlySpan&lt;byte&gt;</c> property and derive the interned string view through
/// <see cref="Utf8Constants.ToInternedString"/>, matching
/// <see cref="Verifiable.DidComm.MessagePickup.WellKnownMessagePickupNames"/>. The six <c>action</c>/
/// <c>result</c> VALUES (<see cref="ActionAdd"/>, <see cref="ActionRemove"/>, <see cref="ResultClientError"/>,
/// <see cref="ResultServerError"/>, <see cref="ResultNoChange"/>, <see cref="ResultSuccess"/>) instead follow
/// the <see cref="Verifiable.DidComm.DiscoverFeatures.WellKnownDiscoverFeaturesNames.Protocol"/> convention —
/// plain <c>public static string</c> properties, not UTF-8/interned pairs, because they are enumerated
/// comparison/dispatch tokens rather than converter-matched wire keys.
/// </para>
/// <para>
/// TRAP: Coordinate Mediation 3.0 renamed the <c>keylist-*</c> vocabulary to <c>recipient-*</c>
/// (<c>recipient-update</c>, <c>recipient-update-response</c>, <c>recipient-query</c>, <c>recipient</c>).
/// This protocol is 2.0 — every constant here uses the <c>keylist-*</c> spelling, and none of the 3.0 names
/// appear anywhere in this library.
/// </para>
/// </remarks>
public static class WellKnownCoordinateMediationNames
{
    /// <summary>The UTF-8 source literal of <see cref="CoordinateMediationProtocol"/>.</summary>
    public static ReadOnlySpan<byte> CoordinateMediationProtocolUtf8 => "https://didcomm.org/coordinate-mediation/2.0"u8;

    /// <summary>The protocol identifier URI (PIURI) of Coordinate Mediation Protocol 2.0.</summary>
    public static string CoordinateMediationProtocol { get; } = Utf8Constants.ToInternedString(CoordinateMediationProtocolUtf8);

    /// <summary>The UTF-8 source literal of <see cref="MediateRequestType"/>.</summary>
    public static ReadOnlySpan<byte> MediateRequestTypeUtf8 => "https://didcomm.org/coordinate-mediation/2.0/mediate-request"u8;

    /// <summary>The <c>mediate-request</c> Message Type URI — a recipient's request for mediation permission (and routing information) (§Mediate Request).</summary>
    public static string MediateRequestType { get; } = Utf8Constants.ToInternedString(MediateRequestTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="MediateDenyType"/>.</summary>
    public static ReadOnlySpan<byte> MediateDenyTypeUtf8 => "https://didcomm.org/coordinate-mediation/2.0/mediate-deny"u8;

    /// <summary>
    /// The <c>mediate-deny</c> Message Type URI — the mediator's refusal of a <c>mediate-request</c> (§Mediate
    /// Deny). TRAP: the spec's own <c>mediate-deny</c> JSON sample carries a trailing comma after the
    /// <c>type</c> member and is therefore not valid JSON.
    /// </summary>
    public static string MediateDenyType { get; } = Utf8Constants.ToInternedString(MediateDenyTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="MediateGrantType"/>.</summary>
    public static ReadOnlySpan<byte> MediateGrantTypeUtf8 => "https://didcomm.org/coordinate-mediation/2.0/mediate-grant"u8;

    /// <summary>The <c>mediate-grant</c> Message Type URI — permission to distribute the carried <c>routing_did</c> as an inbound route (§Mediate Grant).</summary>
    public static string MediateGrantType { get; } = Utf8Constants.ToInternedString(MediateGrantTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="KeylistUpdateType"/>.</summary>
    public static ReadOnlySpan<byte> KeylistUpdateTypeUtf8 => "https://didcomm.org/coordinate-mediation/2.0/keylist-update"u8;

    /// <summary>
    /// The <c>keylist-update</c> Message Type URI — notifies the mediator of keys in use by the recipient
    /// (§Keylist Update). TRAP: the spec's own sample wraps its <c>recipient_did</c> value in backticks rather
    /// than quotes and is therefore not valid JSON.
    /// </summary>
    public static string KeylistUpdateType { get; } = Utf8Constants.ToInternedString(KeylistUpdateTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="KeylistUpdateResponseType"/>.</summary>
    public static ReadOnlySpan<byte> KeylistUpdateResponseTypeUtf8 => "https://didcomm.org/coordinate-mediation/2.0/keylist-update-response"u8;

    /// <summary>
    /// The <c>keylist-update-response</c> Message Type URI — confirmation of a requested <c>keylist-update</c>
    /// (§Keylist Response). TRAP: the section heading reads "Keylist Response" although the wire token is
    /// <c>keylist-update-response</c>, not <c>keylist-response</c> — the two are NOT absorbed by
    /// <see cref="MessageTypeUri.IsSameMessageType(MessageTypeUri?)"/> ("keylistresponse" and
    /// "keylistupdateresponse" are different message-type-name tokens once punctuation is stripped). TRAP:
    /// the spec's own sample carries a backtick-wrapped <c>recipient_did</c>, a <c>//</c> comment, and a
    /// missing comma, and is therefore not valid JSON.
    /// </summary>
    public static string KeylistUpdateResponseType { get; } = Utf8Constants.ToInternedString(KeylistUpdateResponseTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="KeylistQueryType"/>.</summary>
    public static ReadOnlySpan<byte> KeylistQueryTypeUtf8 => "https://didcomm.org/coordinate-mediation/2.0/keylist-query"u8;

    /// <summary>The <c>keylist-query</c> Message Type URI — queries the mediator for the keys registered for this connection (§Keylist Query).</summary>
    public static string KeylistQueryType { get; } = Utf8Constants.ToInternedString(KeylistQueryTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="KeylistType"/>.</summary>
    public static ReadOnlySpan<byte> KeylistTypeUtf8 => "https://didcomm.org/coordinate-mediation/2.0/keylist"u8;

    /// <summary>
    /// The <c>keylist</c> Message Type URI — the response to a <c>keylist-query</c>, containing the
    /// retrieved keys (§Keylist). TRAP: the spec's own sample wraps its <c>recipient_did</c> value in
    /// backticks rather than quotes and is therefore not valid JSON.
    /// </summary>
    public static string KeylistType { get; } = Utf8Constants.ToInternedString(KeylistTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="RoutingDid"/>.</summary>
    public static ReadOnlySpan<byte> RoutingDidUtf8 => "routing_did"u8;

    /// <summary>The <c>mediate-grant</c> body <c>routing_did</c> member — REQUIRED: the DID of the mediator where forwarded messages should be sent (§Mediate Grant).</summary>
    public static string RoutingDid { get; } = Utf8Constants.ToInternedString(RoutingDidUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Updates"/>.</summary>
    public static ReadOnlySpan<byte> UpdatesUtf8 => "updates"u8;

    /// <summary>The <c>keylist-update</c> body <c>updates</c> member — REQUIRED: the list of <c>{recipient_did, action}</c> entries (§Keylist Update).</summary>
    public static string Updates { get; } = Utf8Constants.ToInternedString(UpdatesUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Updated"/>.</summary>
    public static ReadOnlySpan<byte> UpdatedUtf8 => "updated"u8;

    /// <summary>The <c>keylist-update-response</c> body <c>updated</c> member — REQUIRED: the list of <c>{recipient_did, action, result}</c> entries (§Keylist Response).</summary>
    public static string Updated { get; } = Utf8Constants.ToInternedString(UpdatedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="RecipientDid"/>.</summary>
    public static ReadOnlySpan<byte> RecipientDidUtf8 => "recipient_did"u8;

    /// <summary>The <c>recipient_did</c> member — the DID subject of a keylist entry, update, or key (§Keylist Update, §Keylist Response, §Keylist).</summary>
    public static string RecipientDid { get; } = Utf8Constants.ToInternedString(RecipientDidUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Action"/>.</summary>
    public static ReadOnlySpan<byte> ActionUtf8 => "action"u8;

    /// <summary>The <c>action</c> member — one of <see cref="ActionAdd"/> or <see cref="ActionRemove"/> (§Keylist Update, §Keylist Response).</summary>
    public static string Action { get; } = Utf8Constants.ToInternedString(ActionUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Result"/>.</summary>
    public static ReadOnlySpan<byte> ResultUtf8 => "result"u8;

    /// <summary>The <c>result</c> member — one of <see cref="ResultClientError"/>, <see cref="ResultServerError"/>, <see cref="ResultNoChange"/>, or <see cref="ResultSuccess"/>, describing the resulting state of a keylist update (§Keylist Response).</summary>
    public static string Result { get; } = Utf8Constants.ToInternedString(ResultUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Keys"/>.</summary>
    public static ReadOnlySpan<byte> KeysUtf8 => "keys"u8;

    /// <summary>The <c>keylist</c> body <c>keys</c> member — REQUIRED, MAY be empty: the list of <c>{recipient_did}</c> entries registered for the connection (§Keylist).</summary>
    public static string Keys { get; } = Utf8Constants.ToInternedString(KeysUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Paginate"/>.</summary>
    public static ReadOnlySpan<byte> PaginateUtf8 => "paginate"u8;

    /// <summary>The <c>keylist-query</c> body <c>paginate</c> member — OPTIONAL; if present MUST include <see cref="Limit"/> and <see cref="Offset"/> (§Keylist Query).</summary>
    public static string Paginate { get; } = Utf8Constants.ToInternedString(PaginateUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Pagination"/>.</summary>
    public static ReadOnlySpan<byte> PaginationUtf8 => "pagination"u8;

    /// <summary>The <c>keylist</c> body <c>pagination</c> member — OPTIONAL; if present MUST include <see cref="Count"/>, <see cref="Offset"/>, and <see cref="Remaining"/> (§Keylist).</summary>
    public static string Pagination { get; } = Utf8Constants.ToInternedString(PaginationUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Limit"/>.</summary>
    public static ReadOnlySpan<byte> LimitUtf8 => "limit"u8;

    /// <summary>The <c>paginate</c> object's <c>limit</c> member (§Keylist Query).</summary>
    public static string Limit { get; } = Utf8Constants.ToInternedString(LimitUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Offset"/>.</summary>
    public static ReadOnlySpan<byte> OffsetUtf8 => "offset"u8;

    /// <summary>The <c>paginate</c> or <c>pagination</c> object's <c>offset</c> member (§Keylist Query, §Keylist).</summary>
    public static string Offset { get; } = Utf8Constants.ToInternedString(OffsetUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Count"/>.</summary>
    public static ReadOnlySpan<byte> CountUtf8 => "count"u8;

    /// <summary>The <c>pagination</c> object's <c>count</c> member (§Keylist).</summary>
    public static string Count { get; } = Utf8Constants.ToInternedString(CountUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Remaining"/>.</summary>
    public static ReadOnlySpan<byte> RemainingUtf8 => "remaining"u8;

    /// <summary>The <c>pagination</c> object's <c>remaining</c> member (§Keylist).</summary>
    public static string Remaining { get; } = Utf8Constants.ToInternedString(RemainingUtf8);


    /// <summary>The <c>add</c> action value — register a key with the mediator (§Keylist Update).</summary>
    public static string ActionAdd => "add";

    /// <summary>The <c>remove</c> action value — deregister a key from the mediator (§Keylist Update).</summary>
    public static string ActionRemove => "remove";

    /// <summary>The <c>client_error</c> result value — the update failed because of a problem attributable to the requester (§Keylist Response).</summary>
    public static string ResultClientError => "client_error";

    /// <summary>The <c>server_error</c> result value — the update failed because of a problem at the mediator (§Keylist Response).</summary>
    public static string ResultServerError => "server_error";

    /// <summary>The <c>no_change</c> result value — the requested state already held, so nothing changed (§Keylist Response).</summary>
    public static string ResultNoChange => "no_change";

    /// <summary>The <c>success</c> result value — the update applied (§Keylist Response).</summary>
    public static string ResultSuccess => "success";
}
