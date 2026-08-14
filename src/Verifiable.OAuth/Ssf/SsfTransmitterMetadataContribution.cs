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
/// deployment policy. Absent members are omitted from the document, except where
/// a profile makes the member mandatory — see
/// <see cref="SsfTransmitterJsonWriting.BuildTransmitterConfigurationJson"/> for
/// how the emission answers silence on the two members
/// <see href="https://openid.net/specs/openid-caep-interoperability-profile-1_0-01.html">OpenID
/// CAEP Interoperability Profile 1.0, draft 01, sections 2.3.2 and 2.3.7</see> raises to
/// MUST-include (no Final text exists; draft 01 is the document under public review).
/// </remarks>
public sealed record SsfTransmitterMetadataContribution
{
    /// <summary>The empty contribution — the document advertises only chain-derived values.</summary>
    /// <remarks>
    /// Not a profile-conformant contribution on its own: emission refuses it, because
    /// <see cref="DeliveryMethodsSupported"/> is MUST-include under CAEP Interoperability
    /// Profile 1.0 §2.3.2 and cannot be derived.
    /// </remarks>
    public static SsfTransmitterMetadataContribution Empty { get; } = new();

    /// <summary>
    /// The <c>delivery_methods_supported</c> URIs — see
    /// <see cref="Core.SecurityEvents.SsfDeliveryMethods"/>. RECOMMENDED by SSF §7.1;
    /// MUST-include under CAEP Interoperability Profile 1.0 §2.3.2, so leaving it unset
    /// makes the metadata emission fail closed.
    /// </summary>
    public IReadOnlyList<string>? DeliveryMethodsSupported { get; init; }

    /// <summary>
    /// The <c>critical_subject_members</c> Complex Subject member names a Receiver
    /// MUST interpret. OPTIONAL.
    /// </summary>
    public IReadOnlyList<string>? CriticalSubjectMembers { get; init; }

    /// <summary>
    /// The <c>spec_urn</c> values for the <c>authorization_schemes</c> entries. OPTIONAL
    /// under SSF §7.1; MUST-include under CAEP Interoperability Profile 1.0 §2.3.7, whose
    /// value MUST include <see cref="Core.SecurityEvents.SsfMetadataParameterNames.AuthorizationSchemeSpecUrnOAuth2"/>.
    /// Leaving it unset emits that spec-defined value; supplying it keeps the supplied
    /// values verbatim.
    /// </summary>
    public IReadOnlyList<string>? AuthorizationSchemeSpecUrns { get; init; }

    /// <summary>
    /// The <c>default_subjects</c> behavior of newly created streams —
    /// <c>ALL</c> or <c>NONE</c> per SSF §7.1. OPTIONAL.
    /// </summary>
    public string? DefaultSubjects { get; init; }
}
