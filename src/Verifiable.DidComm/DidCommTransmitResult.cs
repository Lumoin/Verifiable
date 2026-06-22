namespace Verifiable.DidComm;

/// <summary>
/// Why a DIDComm transmission did not succeed, or <see cref="None"/> when the endpoint accepted the message.
/// Transport-neutral: the same outcomes describe an HTTPS POST, a WebSocket send, or any other channel
/// (DIDComm Messaging v2.1 §Transports).
/// </summary>
public enum DidCommTransmitError
{
    /// <summary>The endpoint accepted the message.</summary>
    None = 0,

    /// <summary>The endpoint was denied before contact by the outbound policy — an SSRF-blocked loopback/private address, or a scheme/host the policy forbids.</summary>
    DeniedByPolicy,

    /// <summary>The endpoint was reached but did not accept the message (e.g. an HTTPS non-2xx status, or a transport-level rejection).</summary>
    Rejected,

    /// <summary>The message could not be delivered — a socket/DNS/connection error, or no response was produced.</summary>
    TransportFailed
}


/// <summary>
/// The transport-neutral outcome of delivering a DIDComm message to an endpoint over any channel, per
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#transports">DIDComm Messaging v2.1 §Transports</see>.
/// </summary>
/// <remarks>
/// <para>
/// A delivery outcome is data, not a verification proof. <see cref="IsAccepted"/> is the single
/// channel-independent success signal. DIDComm transports are one-way: no application reply flows back on the
/// delivery channel (DIDComm v2.1 §HTTPS, §WebSockets), so a non-accepted result only distinguishes the failure
/// mode (<see cref="Error"/>) and carries no reply. A sender SHOULD fail over to another endpoint or retry
/// later (DIDComm v2.1 §Failover).
/// </para>
/// <para>
/// <see cref="TransportStatusCode"/> is an OPTIONAL transport-specific numeric code — an HTTPS status fills it;
/// a WebSocket or other channel without a numeric status leaves it <see langword="null"/>. The factories are
/// <see langword="public"/> so a transport defined outside this assembly can mint a result.
/// </para>
/// </remarks>
public sealed class DidCommTransmitResult
{
    private DidCommTransmitResult(bool isAccepted, int? transportStatusCode, DidCommTransmitError error)
    {
        IsAccepted = isAccepted;
        TransportStatusCode = transportStatusCode;
        Error = error;
    }


    /// <summary>Whether the endpoint accepted the message.</summary>
    public bool IsAccepted { get; }

    /// <summary>An OPTIONAL transport-specific numeric code (e.g. an HTTPS status), or <see langword="null"/> for a transport without one or when no response was received.</summary>
    public int? TransportStatusCode { get; }

    /// <summary>The reason the transmission did not succeed, or <see cref="DidCommTransmitError.None"/> when it was accepted.</summary>
    public DidCommTransmitError Error { get; }


    /// <summary>Mints an accepted outcome, optionally carrying the transport's numeric code.</summary>
    /// <param name="transportStatusCode">The transport's numeric code, or <see langword="null"/> for a channel without one.</param>
    /// <returns>An accepted result.</returns>
    public static DidCommTransmitResult Accepted(int? transportStatusCode = null)
    {
        return new DidCommTransmitResult(true, transportStatusCode, DidCommTransmitError.None);
    }


    /// <summary>Mints a rejected outcome — the endpoint was reached but did not accept — optionally carrying the transport's numeric code.</summary>
    /// <param name="transportStatusCode">The transport's numeric code, or <see langword="null"/> for a channel without one.</param>
    /// <returns>A rejected result.</returns>
    public static DidCommTransmitResult Rejected(int? transportStatusCode = null)
    {
        return new DidCommTransmitResult(false, transportStatusCode, DidCommTransmitError.Rejected);
    }


    /// <summary>Mints an outcome for an endpoint the outbound policy denied before contact.</summary>
    /// <returns>A policy-denied result.</returns>
    public static DidCommTransmitResult DeniedByPolicy()
    {
        return new DidCommTransmitResult(false, null, DidCommTransmitError.DeniedByPolicy);
    }


    /// <summary>Mints an outcome for a transport-level delivery failure (socket/DNS/connection error, or no response).</summary>
    /// <returns>A transport-failure result.</returns>
    public static DidCommTransmitResult TransportFailed()
    {
        return new DidCommTransmitResult(false, null, DidCommTransmitError.TransportFailed);
    }


    /// <summary>
    /// Maps an HTTPS status to an outcome: a 2xx is accepted, anything else is rejected (DIDComm v2.1 §HTTPS:
    /// "A successful message receipt MUST return a code in the 2xx HTTPS Status Code range"). A convenience for
    /// HTTP-family transports; other channels mint <see cref="Accepted(int?)"/>/<see cref="Rejected(int?)"/>
    /// directly. The 2xx-iff-accepted invariant is structural rather than relying on the caller.
    /// </summary>
    /// <param name="statusCode">The HTTPS status code the endpoint returned.</param>
    /// <returns>An accepted result for a 2xx, otherwise a rejected result, each carrying the status.</returns>
    public static DidCommTransmitResult FromStatus(int statusCode)
    {
        return statusCode is >= 200 and <= 299
            ? Accepted(statusCode)
            : Rejected(statusCode);
    }
}
