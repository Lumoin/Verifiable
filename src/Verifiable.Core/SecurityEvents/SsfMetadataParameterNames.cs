using System;
using Verifiable.Cryptography.Text;

namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// The member NAMES of the Transmitter Configuration Metadata document a Shared
/// Signals Transmitter publishes at <c>/.well-known/ssf-configuration</c>, per
/// OpenID Shared Signals Framework 1.0 §7.1.
/// </summary>
/// <remarks>
/// These are NAMES (JSON keys), not values. A Transmitter that also serves the
/// legacy RISC discovery path publishes the same document at
/// <c>/.well-known/risc-configuration</c> (SSF §7.2.2 backward compatibility).
/// </remarks>
public static class SsfMetadataParameterNames
{
    /// <summary>The UTF-8 source literal of <see cref="SpecVersion"/>.</summary>
    public static ReadOnlySpan<byte> SpecVersionUtf8 => "spec_version"u8;

    /// <summary>
    /// <c>spec_version</c> — OPTIONAL version of the implemented spec. Absent implies
    /// <c>1_0-ID1</c>; the final 1.0 spec is <c>1_0</c>.
    /// </summary>
    public static readonly string SpecVersion = Utf8Constants.ToInternedString(SpecVersionUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Issuer"/>.</summary>
    public static ReadOnlySpan<byte> IssuerUtf8 => "issuer"u8;

    /// <summary><c>issuer</c> — REQUIRED https Issuer Identifier; equals the SET <c>iss</c>.</summary>
    public static readonly string Issuer = Utf8Constants.ToInternedString(IssuerUtf8);

    /// <summary>The UTF-8 source literal of <see cref="JwksUri"/>.</summary>
    public static ReadOnlySpan<byte> JwksUriUtf8 => "jwks_uri"u8;

    /// <summary><c>jwks_uri</c> — URL of the Transmitter's JWK Set (REQUIRED to issue signed SETs).</summary>
    public static readonly string JwksUri = Utf8Constants.ToInternedString(JwksUriUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DeliveryMethodsSupported"/>.</summary>
    public static ReadOnlySpan<byte> DeliveryMethodsSupportedUtf8 => "delivery_methods_supported"u8;

    /// <summary><c>delivery_methods_supported</c> — RECOMMENDED list of supported delivery-method URIs.</summary>
    public static readonly string DeliveryMethodsSupported = Utf8Constants.ToInternedString(DeliveryMethodsSupportedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ConfigurationEndpoint"/>.</summary>
    public static ReadOnlySpan<byte> ConfigurationEndpointUtf8 => "configuration_endpoint"u8;

    /// <summary><c>configuration_endpoint</c> — OPTIONAL Stream Configuration endpoint URL.</summary>
    public static readonly string ConfigurationEndpoint = Utf8Constants.ToInternedString(ConfigurationEndpointUtf8);

    /// <summary>The UTF-8 source literal of <see cref="StatusEndpoint"/>.</summary>
    public static ReadOnlySpan<byte> StatusEndpointUtf8 => "status_endpoint"u8;

    /// <summary><c>status_endpoint</c> — OPTIONAL Stream Status endpoint URL.</summary>
    public static readonly string StatusEndpoint = Utf8Constants.ToInternedString(StatusEndpointUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AddSubjectEndpoint"/>.</summary>
    public static ReadOnlySpan<byte> AddSubjectEndpointUtf8 => "add_subject_endpoint"u8;

    /// <summary><c>add_subject_endpoint</c> — OPTIONAL Add Subject endpoint URL.</summary>
    public static readonly string AddSubjectEndpoint = Utf8Constants.ToInternedString(AddSubjectEndpointUtf8);

    /// <summary>The UTF-8 source literal of <see cref="RemoveSubjectEndpoint"/>.</summary>
    public static ReadOnlySpan<byte> RemoveSubjectEndpointUtf8 => "remove_subject_endpoint"u8;

    /// <summary><c>remove_subject_endpoint</c> — OPTIONAL Remove Subject endpoint URL.</summary>
    public static readonly string RemoveSubjectEndpoint = Utf8Constants.ToInternedString(RemoveSubjectEndpointUtf8);

    /// <summary>The UTF-8 source literal of <see cref="VerificationEndpoint"/>.</summary>
    public static ReadOnlySpan<byte> VerificationEndpointUtf8 => "verification_endpoint"u8;

    /// <summary><c>verification_endpoint</c> — OPTIONAL Verification endpoint URL.</summary>
    public static readonly string VerificationEndpoint = Utf8Constants.ToInternedString(VerificationEndpointUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CriticalSubjectMembers"/>.</summary>
    public static ReadOnlySpan<byte> CriticalSubjectMembersUtf8 => "critical_subject_members"u8;

    /// <summary>
    /// <c>critical_subject_members</c> — OPTIONAL array of Complex Subject member names a
    /// Receiver MUST interpret if present.
    /// </summary>
    public static readonly string CriticalSubjectMembers = Utf8Constants.ToInternedString(CriticalSubjectMembersUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthorizationSchemes"/>.</summary>
    public static ReadOnlySpan<byte> AuthorizationSchemesUtf8 => "authorization_schemes"u8;

    /// <summary>
    /// <c>authorization_schemes</c> — OPTIONAL array of objects describing the supported
    /// authorization schemes for the stream-management APIs (each carries <see cref="SpecUrn"/>).
    /// </summary>
    public static readonly string AuthorizationSchemes = Utf8Constants.ToInternedString(AuthorizationSchemesUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SpecUrn"/>.</summary>
    public static ReadOnlySpan<byte> SpecUrnUtf8 => "spec_urn"u8;

    /// <summary>
    /// <c>spec_urn</c> — REQUIRED member of an <see cref="AuthorizationSchemes"/> entry; a URN
    /// naming the authorization protocol (for example <c>urn:ietf:rfc:6749</c>).
    /// </summary>
    public static readonly string SpecUrn = Utf8Constants.ToInternedString(SpecUrnUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DefaultSubjects"/>.</summary>
    public static ReadOnlySpan<byte> DefaultSubjectsUtf8 => "default_subjects"u8;

    /// <summary>
    /// <c>default_subjects</c> — OPTIONAL default new-stream behavior; one of
    /// <see cref="DefaultSubjectsAll"/> or <see cref="DefaultSubjectsNone"/>.
    /// </summary>
    public static readonly string DefaultSubjects = Utf8Constants.ToInternedString(DefaultSubjectsUtf8);


    /// <summary>The UTF-8 source literal of <see cref="DefaultSubjectsAll"/>.</summary>
    public static ReadOnlySpan<byte> DefaultSubjectsAllUtf8 => "ALL"u8;

    /// <summary>The <c>default_subjects</c> value <c>ALL</c> — new streams include all appropriate subjects.</summary>
    public static readonly string DefaultSubjectsAll = Utf8Constants.ToInternedString(DefaultSubjectsAllUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DefaultSubjectsNone"/>.</summary>
    public static ReadOnlySpan<byte> DefaultSubjectsNoneUtf8 => "NONE"u8;

    /// <summary>The <c>default_subjects</c> value <c>NONE</c> — new streams include no subjects by default.</summary>
    public static readonly string DefaultSubjectsNone = Utf8Constants.ToInternedString(DefaultSubjectsNoneUtf8);
}
