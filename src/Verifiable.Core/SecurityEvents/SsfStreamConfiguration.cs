using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// The typed configuration of an Event Stream, per OpenID Shared Signals
/// Framework 1.0 §8.1.1 — the data, contributed by both parties, that describes
/// what flows over the stream. Shared by Receiver and Transmitter.
/// </summary>
/// <remarks>
/// Optional members are <see langword="null"/> when absent. <see cref="Audiences"/>
/// flattens the <c>aud</c> claim, which may be a single string or an array.
/// </remarks>
public sealed record SsfStreamConfiguration
{
    /// <summary>The <c>stream_id</c> (Transmitter-supplied, REQUIRED).</summary>
    public required string StreamId { get; init; }

    /// <summary>The <c>iss</c> Issuer Identifier (Transmitter-supplied, REQUIRED).</summary>
    public required string Issuer { get; init; }

    /// <summary>The <c>aud</c> audience values (Transmitter-supplied, REQUIRED; immutable). Never null; may be empty.</summary>
    public IReadOnlyList<string> Audiences { get; init; } = [];

    /// <summary>The <c>delivery</c> configuration (REQUIRED).</summary>
    public required SsfDeliveryConfiguration Delivery { get; init; }

    /// <summary>The <c>events_supported</c> URIs; <see langword="null"/> if absent.</summary>
    public IReadOnlyList<string>? EventsSupported { get; init; }

    /// <summary>The <c>events_requested</c> URIs; <see langword="null"/> if absent.</summary>
    public IReadOnlyList<string>? EventsRequested { get; init; }

    /// <summary>The <c>events_delivered</c> URIs; <see langword="null"/> if absent.</summary>
    public IReadOnlyList<string>? EventsDelivered { get; init; }

    /// <summary>The <c>min_verification_interval</c> in seconds; <see langword="null"/> if absent.</summary>
    public int? MinVerificationInterval { get; init; }

    /// <summary>The <c>description</c>; <see langword="null"/> if absent.</summary>
    public string? Description { get; init; }

    /// <summary>The <c>inactivity_timeout</c> in seconds; <see langword="null"/> if absent.</summary>
    public int? InactivityTimeout { get; init; }
}


/// <summary>
/// The <c>delivery</c> object of a stream configuration — the delivery method URI
/// and its parameters, per OpenID Shared Signals Framework 1.0 §6.1.
/// </summary>
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings", Justification = "endpoint_url is an opaque wire URL parsed verbatim; dereference is gated by the outbound-fetch policy, not by System.Uri construction.")]
public sealed record SsfDeliveryConfiguration
{
    /// <summary>The <c>method</c> delivery-method URI (REQUIRED) — see <see cref="SsfDeliveryMethods"/>.</summary>
    public required string Method { get; init; }

    /// <summary>
    /// The <c>endpoint_url</c>: for push the Receiver-set POST target, for poll the
    /// Transmitter-set retrieval URL. <see langword="null"/> if absent.
    /// </summary>
    public string? EndpointUrl { get; init; }

    /// <summary>
    /// The <c>authorization_header</c> the Transmitter includes on every push POST;
    /// <see langword="null"/> if absent.
    /// </summary>
    public string? AuthorizationHeader { get; init; }
}
