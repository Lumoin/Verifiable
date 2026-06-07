using System.Collections.Generic;

namespace Verifiable.OAuth.Ssf;

/// <summary>
/// Application-supplied values for the Shared Signals Transmitter Configuration
/// Metadata document (SSF 1.0 §7.1) that the library cannot derive from the
/// endpoint chain, returned through the
/// <see cref="Server.ContributeSsfTransmitterMetadataDelegate"/> seam.
/// </summary>
/// <remarks>
/// The library derives <c>issuer</c> (the resolved issuer), <c>spec_version</c>,
/// and the endpoint URLs (<c>jwks_uri</c> and, as the transmitter surface grows,
/// the stream-management endpoints) from the chain; everything here is
/// deployment policy. Absent members are omitted from the document.
/// </remarks>
public sealed record SsfTransmitterMetadataContribution
{
    /// <summary>The empty contribution — the document advertises only chain-derived values.</summary>
    public static SsfTransmitterMetadataContribution Empty { get; } = new();

    /// <summary>
    /// The <c>delivery_methods_supported</c> URIs (RECOMMENDED) — see
    /// <see cref="Core.SecurityEvents.SsfDeliveryMethods"/>.
    /// </summary>
    public IReadOnlyList<string>? DeliveryMethodsSupported { get; init; }

    /// <summary>
    /// The <c>critical_subject_members</c> Complex Subject member names a Receiver
    /// MUST interpret. OPTIONAL.
    /// </summary>
    public IReadOnlyList<string>? CriticalSubjectMembers { get; init; }

    /// <summary>
    /// The <c>spec_urn</c> values for the <c>authorization_schemes</c> entries (for
    /// example <c>urn:ietf:rfc:6749</c>). OPTIONAL.
    /// </summary>
    public IReadOnlyList<string>? AuthorizationSchemeSpecUrns { get; init; }

    /// <summary>
    /// The <c>default_subjects</c> behavior of newly created streams —
    /// <c>ALL</c> or <c>NONE</c> per SSF §7.1. OPTIONAL.
    /// </summary>
    public string? DefaultSubjects { get; init; }
}
