using System;
using Verifiable.Cryptography.Text;

namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// The member NAMES of an Event Stream's configuration object, per OpenID Shared
/// Signals Framework 1.0 §8.1.1. Shared by the Receiver (which reads and supplies
/// parts of it) and the Transmitter (which owns and returns it).
/// </summary>
public static class SsfStreamConfigParameterNames
{
    /// <summary>The UTF-8 source literal of <see cref="StreamId"/>.</summary>
    public static ReadOnlySpan<byte> StreamIdUtf8 => "stream_id"u8;

    /// <summary><c>stream_id</c> — Transmitter-supplied REQUIRED unique stream identifier.</summary>
    public static readonly string StreamId = Utf8Constants.ToInternedString(StreamIdUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Iss"/>.</summary>
    public static ReadOnlySpan<byte> IssUtf8 => "iss"u8;

    /// <summary><c>iss</c> — Transmitter-supplied REQUIRED Issuer Identifier (equals the SET <c>iss</c>).</summary>
    public static readonly string Iss = Utf8Constants.ToInternedString(IssUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Aud"/>.</summary>
    public static ReadOnlySpan<byte> AudUtf8 => "aud"u8;

    /// <summary><c>aud</c> — Transmitter-supplied REQUIRED audience (string or array); immutable.</summary>
    public static readonly string Aud = Utf8Constants.ToInternedString(AudUtf8);

    /// <summary>The UTF-8 source literal of <see cref="EventsSupported"/>.</summary>
    public static ReadOnlySpan<byte> EventsSupportedUtf8 => "events_supported"u8;

    /// <summary><c>events_supported</c> — Transmitter-supplied OPTIONAL event-type URIs supported for this Receiver.</summary>
    public static readonly string EventsSupported = Utf8Constants.ToInternedString(EventsSupportedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="EventsRequested"/>.</summary>
    public static ReadOnlySpan<byte> EventsRequestedUtf8 => "events_requested"u8;

    /// <summary><c>events_requested</c> — Receiver-supplied OPTIONAL event-type URIs the Receiver wants.</summary>
    public static readonly string EventsRequested = Utf8Constants.ToInternedString(EventsRequestedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="EventsDelivered"/>.</summary>
    public static ReadOnlySpan<byte> EventsDeliveredUtf8 => "events_delivered"u8;

    /// <summary><c>events_delivered</c> — Transmitter-supplied REQUIRED event-type URIs actually delivered (subset of supported ∩ requested).</summary>
    public static readonly string EventsDelivered = Utf8Constants.ToInternedString(EventsDeliveredUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Delivery"/>.</summary>
    public static ReadOnlySpan<byte> DeliveryUtf8 => "delivery"u8;

    /// <summary><c>delivery</c> — REQUIRED delivery configuration object (see <see cref="SsfDeliveryParameterNames"/>).</summary>
    public static readonly string Delivery = Utf8Constants.ToInternedString(DeliveryUtf8);

    /// <summary>The UTF-8 source literal of <see cref="MinVerificationInterval"/>.</summary>
    public static ReadOnlySpan<byte> MinVerificationIntervalUtf8 => "min_verification_interval"u8;

    /// <summary><c>min_verification_interval</c> — Transmitter-supplied OPTIONAL minimum seconds between verification requests.</summary>
    public static readonly string MinVerificationInterval = Utf8Constants.ToInternedString(MinVerificationIntervalUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Description"/>.</summary>
    public static ReadOnlySpan<byte> DescriptionUtf8 => "description"u8;

    /// <summary><c>description</c> — Receiver-supplied OPTIONAL human-readable stream description.</summary>
    public static readonly string Description = Utf8Constants.ToInternedString(DescriptionUtf8);

    /// <summary>The UTF-8 source literal of <see cref="InactivityTimeout"/>.</summary>
    public static ReadOnlySpan<byte> InactivityTimeoutUtf8 => "inactivity_timeout"u8;

    /// <summary><c>inactivity_timeout</c> — Transmitter-supplied OPTIONAL refreshable inactivity timeout in seconds.</summary>
    public static readonly string InactivityTimeout = Utf8Constants.ToInternedString(InactivityTimeoutUtf8);
}
