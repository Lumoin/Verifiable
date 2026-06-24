using Verifiable.Cryptography.Text;

namespace Verifiable.DidComm.TrustPing;

/// <summary>
/// The well-known names of the DIDComm Trust Ping Protocol 2.0 — the protocol identifier URI, the
/// <c>ping</c>/<c>ping-response</c> Message Type URIs, and the <c>response_requested</c> body member — per
/// <see href="https://didcomm.org/trust-ping/2.0/">DIDComm Trust Ping Protocol 2.0</see>.
/// </summary>
/// <remarks>
/// Trust Ping is a didcomm.org companion protocol, NOT part of the DIDComm Messaging v2.1 core
/// specification: it tests that a channel works end to end — that the other party's DID resolves, its keys
/// agree, any mediators forward, and the envelope round-trips — by sending a <c>ping</c> and (optionally)
/// receiving a <c>ping-response</c>. Each name declares its single UTF-8 source literal as a
/// <c>ReadOnlySpan&lt;byte&gt;</c> property and derives the interned string view through
/// <see cref="Utf8Constants.ToInternedString"/>, matching <see cref="WellKnownRoutingNames"/> and the other
/// protocol name tables.
/// </remarks>
public static class WellKnownTrustPingNames
{
    /// <summary>The UTF-8 source literal of <see cref="TrustPingProtocol"/>.</summary>
    public static ReadOnlySpan<byte> TrustPingProtocolUtf8 => "https://didcomm.org/trust-ping/2.0"u8;

    /// <summary>The protocol identifier URI (PIURI) of Trust Ping Protocol 2.0 (didcomm.org/trust-ping/2.0).</summary>
    public static readonly string TrustPingProtocol = Utf8Constants.ToInternedString(TrustPingProtocolUtf8);

    /// <summary>The UTF-8 source literal of <see cref="PingType"/>.</summary>
    public static ReadOnlySpan<byte> PingTypeUtf8 => "https://didcomm.org/trust-ping/2.0/ping"u8;

    /// <summary>
    /// The <c>ping</c> Message Type URI — the value of the <c>type</c> header that identifies a message as a
    /// Trust Ping Protocol 2.0 ping (didcomm.org/trust-ping/2.0 §ping).
    /// </summary>
    public static readonly string PingType = Utf8Constants.ToInternedString(PingTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="PingResponseType"/>.</summary>
    public static ReadOnlySpan<byte> PingResponseTypeUtf8 => "https://didcomm.org/trust-ping/2.0/ping-response"u8;

    /// <summary>
    /// The <c>ping-response</c> Message Type URI — the value of the <c>type</c> header that identifies a
    /// message as the response to a ping (didcomm.org/trust-ping/2.0 §ping-response).
    /// </summary>
    public static readonly string PingResponseType = Utf8Constants.ToInternedString(PingResponseTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ResponseRequested"/>.</summary>
    public static ReadOnlySpan<byte> ResponseRequestedUtf8 => "response_requested"u8;

    /// <summary>
    /// The ping body <c>response_requested</c> member — OPTIONAL boolean, default <see langword="true"/>:
    /// whether the sender wants a <c>ping-response</c> back. When <see langword="false"/> the receiver MUST
    /// NOT respond (didcomm.org/trust-ping/2.0 §ping).
    /// </summary>
    public static readonly string ResponseRequested = Utf8Constants.ToInternedString(ResponseRequestedUtf8);
}
