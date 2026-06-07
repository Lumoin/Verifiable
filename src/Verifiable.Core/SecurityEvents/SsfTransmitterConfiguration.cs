using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// The typed Transmitter Configuration Metadata a Shared Signals Transmitter
/// publishes at <c>/.well-known/ssf-configuration</c> (and, for backward
/// compatibility, <c>/.well-known/risc-configuration</c>), per OpenID Shared
/// Signals Framework 1.0 §7.1. A Receiver consumes it to locate the
/// Transmitter's keys and stream-management endpoints.
/// </summary>
/// <remarks>
/// Endpoint values are kept as wire strings rather than <see cref="System.Uri"/>:
/// the document is parsed faithfully and any dereference is gated by the
/// outbound-fetch policy at fetch time, not by URI construction here. Optional
/// members are <see langword="null"/> when absent.
/// </remarks>
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings", Justification = "Discovery-document endpoint URLs are opaque wire strings parsed verbatim; dereference is gated by the outbound-fetch policy, not by System.Uri construction.")]
public sealed record SsfTransmitterConfiguration
{
    /// <summary>The <c>spec_version</c>; <see langword="null"/> implies <c>1_0-ID1</c> (SSF §7.1).</summary>
    public string? SpecVersion { get; init; }

    /// <summary>The <c>issuer</c> (REQUIRED) — the Transmitter's https Issuer Identifier.</summary>
    public required string Issuer { get; init; }

    /// <summary>The <c>jwks_uri</c> — URL of the Transmitter's JWK Set; <see langword="null"/> if absent.</summary>
    public string? JwksUri { get; init; }

    /// <summary>The <c>delivery_methods_supported</c> URIs; <see langword="null"/> if absent.</summary>
    public IReadOnlyList<string>? DeliveryMethodsSupported { get; init; }

    /// <summary>The <c>configuration_endpoint</c> URL; <see langword="null"/> if absent.</summary>
    public string? ConfigurationEndpoint { get; init; }

    /// <summary>The <c>status_endpoint</c> URL; <see langword="null"/> if absent.</summary>
    public string? StatusEndpoint { get; init; }

    /// <summary>The <c>add_subject_endpoint</c> URL; <see langword="null"/> if absent.</summary>
    public string? AddSubjectEndpoint { get; init; }

    /// <summary>The <c>remove_subject_endpoint</c> URL; <see langword="null"/> if absent.</summary>
    public string? RemoveSubjectEndpoint { get; init; }

    /// <summary>The <c>verification_endpoint</c> URL; <see langword="null"/> if absent.</summary>
    public string? VerificationEndpoint { get; init; }

    /// <summary>The <c>critical_subject_members</c> names; <see langword="null"/> if absent.</summary>
    public IReadOnlyList<string>? CriticalSubjectMembers { get; init; }

    /// <summary>The <c>authorization_schemes</c> entries; <see langword="null"/> if absent.</summary>
    public IReadOnlyList<SsfAuthorizationScheme>? AuthorizationSchemes { get; init; }

    /// <summary>The <c>default_subjects</c> value (<c>ALL</c> or <c>NONE</c>); <see langword="null"/> if absent.</summary>
    public string? DefaultSubjects { get; init; }
}


/// <summary>
/// One entry of a Transmitter's <c>authorization_schemes</c>, naming the
/// authorization protocol used to secure the stream-management APIs, per OpenID
/// Shared Signals Framework 1.0 §7.1.1.
/// </summary>
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings", Justification = "spec_urn is a protocol-naming URN string (e.g. urn:ietf:rfc:6749), not a dereferenceable System.Uri.")]
public sealed record SsfAuthorizationScheme
{
    /// <summary>
    /// The <c>spec_urn</c> (REQUIRED) — a URN naming the authorization protocol, for example
    /// <c>urn:ietf:rfc:6749</c> (OAuth 2.0), under which the Receiver obtains credentials.
    /// </summary>
    public required string SpecUrn { get; init; }
}
