namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// The member NAMES of an Event Stream's configuration object, per OpenID Shared
/// Signals Framework 1.0 §8.1.1. Shared by the Receiver (which reads and supplies
/// parts of it) and the Transmitter (which owns and returns it).
/// </summary>
public static class SsfStreamConfigParameterNames
{
    /// <summary><c>stream_id</c> — Transmitter-supplied REQUIRED unique stream identifier.</summary>
    public static readonly string StreamId = "stream_id";

    /// <summary><c>iss</c> — Transmitter-supplied REQUIRED Issuer Identifier (equals the SET <c>iss</c>).</summary>
    public static readonly string Iss = "iss";

    /// <summary><c>aud</c> — Transmitter-supplied REQUIRED audience (string or array); immutable.</summary>
    public static readonly string Aud = "aud";

    /// <summary><c>events_supported</c> — Transmitter-supplied OPTIONAL event-type URIs supported for this Receiver.</summary>
    public static readonly string EventsSupported = "events_supported";

    /// <summary><c>events_requested</c> — Receiver-supplied OPTIONAL event-type URIs the Receiver wants.</summary>
    public static readonly string EventsRequested = "events_requested";

    /// <summary><c>events_delivered</c> — Transmitter-supplied REQUIRED event-type URIs actually delivered (subset of supported ∩ requested).</summary>
    public static readonly string EventsDelivered = "events_delivered";

    /// <summary><c>delivery</c> — REQUIRED delivery configuration object (see <see cref="SsfDeliveryParameterNames"/>).</summary>
    public static readonly string Delivery = "delivery";

    /// <summary><c>min_verification_interval</c> — Transmitter-supplied OPTIONAL minimum seconds between verification requests.</summary>
    public static readonly string MinVerificationInterval = "min_verification_interval";

    /// <summary><c>description</c> — Receiver-supplied OPTIONAL human-readable stream description.</summary>
    public static readonly string Description = "description";

    /// <summary><c>inactivity_timeout</c> — Transmitter-supplied OPTIONAL refreshable inactivity timeout in seconds.</summary>
    public static readonly string InactivityTimeout = "inactivity_timeout";
}
