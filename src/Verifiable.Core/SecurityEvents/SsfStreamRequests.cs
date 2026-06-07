using System.Collections.Generic;

namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// The body of a Create Stream request (POST to the Configuration Endpoint), per
/// OpenID Shared Signals Framework 1.0 §8.1.1.1 — the Receiver-supplied subset of
/// the stream configuration.
/// </summary>
/// <remarks>
/// All members are OPTIONAL on the wire. An absent <see cref="Delivery"/> means
/// the Transmitter MUST assume poll delivery (<c>urn:ietf:rfc:8936</c>) and
/// supply the polling <c>endpoint_url</c> in its response.
/// </remarks>
public sealed record SsfStreamCreateRequest
{
    /// <summary>The requested <c>delivery</c> configuration; <see langword="null"/> implies poll.</summary>
    public SsfDeliveryConfiguration? Delivery { get; init; }

    /// <summary>The <c>events_requested</c> URIs; <see langword="null"/> if absent.</summary>
    public IReadOnlyList<string>? EventsRequested { get; init; }

    /// <summary>The human-readable <c>description</c>; <see langword="null"/> if absent.</summary>
    public string? Description { get; init; }
}


/// <summary>
/// The body of an Update (PATCH, §8.1.1.3) or Replace (PUT, §8.1.1.4) Stream
/// request to the Configuration Endpoint: <c>stream_id</c> plus the
/// Receiver-supplied properties to change, and optionally Transmitter-supplied
/// properties that MUST then match the Transmitter's expected values.
/// </summary>
/// <remarks>
/// The PATCH/PUT semantics differ in the store, not in the wire shape: PATCH
/// leaves absent Receiver-supplied properties unchanged, PUT treats them as
/// requested deletions. The Transmitter validates any present
/// Transmitter-supplied property (<see cref="Issuer"/>, <see cref="Audiences"/>,
/// <see cref="EventsSupported"/>, <see cref="EventsDelivered"/>) against its
/// expected value and rejects a mismatch with 400.
/// </remarks>
public sealed record SsfStreamUpdateRequest
{
    /// <summary>The <c>stream_id</c> (REQUIRED) of the stream being updated.</summary>
    public required string StreamId { get; init; }

    /// <summary>The <c>delivery</c> configuration to set; <see langword="null"/> if absent.</summary>
    public SsfDeliveryConfiguration? Delivery { get; init; }

    /// <summary>The <c>events_requested</c> URIs to set; <see langword="null"/> if absent.</summary>
    public IReadOnlyList<string>? EventsRequested { get; init; }

    /// <summary>The <c>description</c> to set; <see langword="null"/> if absent.</summary>
    public string? Description { get; init; }

    /// <summary>A Transmitter-supplied <c>iss</c> echoed for matching; <see langword="null"/> if absent.</summary>
    public string? Issuer { get; init; }

    /// <summary>Transmitter-supplied <c>aud</c> values echoed for matching; <see langword="null"/> if absent.</summary>
    public IReadOnlyList<string>? Audiences { get; init; }

    /// <summary>Transmitter-supplied <c>events_supported</c> echoed for matching; <see langword="null"/> if absent.</summary>
    public IReadOnlyList<string>? EventsSupported { get; init; }

    /// <summary>Transmitter-supplied <c>events_delivered</c> echoed for matching; <see langword="null"/> if absent.</summary>
    public IReadOnlyList<string>? EventsDelivered { get; init; }
}
