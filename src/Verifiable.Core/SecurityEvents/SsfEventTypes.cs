namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// The event-type URIs defined by the OpenID Shared Signals Framework (SSF) 1.0
/// itself — the framework-level events a Transmitter emits about the stream, as
/// opposed to the CAEP/RISC profile events carried over it.
/// </summary>
public static class SsfEventTypes
{
    private const string Prefix = "https://schemas.openid.net/secevent/ssf/event-type/";

    /// <summary>
    /// Verification (<c>verification</c>) — emitted in response to a verification
    /// request and echoing the supplied <c>state</c>. SSF 1.0 §8.1.4.1.
    /// </summary>
    public static readonly string Verification = Prefix + "verification";

    /// <summary>
    /// Stream Updated (<c>stream-updated</c>) — emitted when the Transmitter changes a
    /// stream's status (carrying <c>status</c> and an optional <c>reason</c>). SSF 1.0 §8.1.5.
    /// </summary>
    public static readonly string StreamUpdated = Prefix + "stream-updated";


    /// <summary>Whether <paramref name="eventType"/> is <see cref="Verification"/>.</summary>
    public static bool IsVerification(string eventType) => Equals(eventType, Verification);

    /// <summary>Whether <paramref name="eventType"/> is <see cref="StreamUpdated"/>.</summary>
    public static bool IsStreamUpdated(string eventType) => Equals(eventType, StreamUpdated);

    /// <summary>Whether <paramref name="eventType"/> is any SSF framework event-type URI.</summary>
    public static bool IsSsfEventType(string eventType) =>
        eventType is not null && eventType.StartsWith(Prefix, System.StringComparison.Ordinal);


    /// <summary>
    /// Returns the interned constant for a known SSF event-type URI, or the original
    /// string if unrecognized.
    /// </summary>
    public static string GetCanonicalizedValue(string eventType) => eventType switch
    {
        _ when IsVerification(eventType) => Verification,
        _ when IsStreamUpdated(eventType) => StreamUpdated,
        _ => eventType
    };


    /// <summary>Compares two event-type URIs for equality (case-sensitive).</summary>
    public static bool Equals(string eventTypeA, string eventTypeB) =>
        object.ReferenceEquals(eventTypeA, eventTypeB) || System.StringComparer.Ordinal.Equals(eventTypeA, eventTypeB);
}
