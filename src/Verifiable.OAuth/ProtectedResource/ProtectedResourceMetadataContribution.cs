using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.OAuth.ProtectedResource;

/// <summary>
/// Application-supplied values for an OAuth 2.0 Protected Resource Metadata
/// document (RFC 9728 §2) — everything the library cannot derive from the
/// endpoint chain. Returned from the
/// <see cref="Server.ContributeProtectedResourceMetadataDelegate"/> seam for the resource it is asked for. The
/// library derives <c>resource</c> and <c>jwks_uri</c> (the chain's JWKS endpoint, when https) itself. Every member
/// feeds the document whose <c>resource</c> is the issuer; for one of the library's own resources only the
/// human-readable and documentation members are read (<c>resource_name</c>, <c>resource_documentation</c>,
/// <c>resource_policy_uri</c>, <c>resource_tos_uri</c> and their language-tagged forms), and any other member stated is
/// answered <c>server_error</c> with no document.
/// </summary>
/// <remarks>
/// Per §3.2, parameters with zero values are omitted from the document: a
/// <see langword="null"/> or empty member here simply does not appear on the
/// wire, but for an empty <see cref="BearerMethodsSupported"/>, which is
/// written as <c>[]</c> (RFC 9728 Section 2: "The empty array [] can be used to
/// indicate that no bearer methods are supported."). URL-valued members stay
/// wire strings per the document's comparison rules (Section 6).
/// </remarks>
[DebuggerDisplay("ProtectedResourceMetadataContribution Scopes={ScopesSupported?.Count}")]
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "RFC 9728 metadata values are wire strings compared code point by code point (§6), not parsed URIs.")]
public sealed record ProtectedResourceMetadataContribution
{
    /// <summary>The empty contribution — only the derivable members are emitted.</summary>
    public static ProtectedResourceMetadataContribution Empty { get; } = new();

    /// <summary>The <c>authorization_servers</c> issuer identifiers (§2).</summary>
    public IReadOnlyList<string>? AuthorizationServers { get; init; }

    /// <summary>The <c>scopes_supported</c> values (§2, RECOMMENDED).</summary>
    public IReadOnlyList<string>? ScopesSupported { get; init; }

    /// <summary>
    /// The <c>bearer_methods_supported</c> values; see <see cref="BearerMethodValues"/>. An empty list is written as
    /// <c>[]</c>, no bearer method supported, and <see langword="null"/> omits the member.
    /// </summary>
    public IReadOnlyList<string>? BearerMethodsSupported { get; init; }

    /// <summary>
    /// The <c>resource_signing_alg_values_supported</c> values. The value <c>none</c> MUST NOT be used (Section 2): a list
    /// naming it is answered <c>server_error</c> with no document.
    /// </summary>
    public IReadOnlyList<string>? ResourceSigningAlgValuesSupported { get; init; }

    /// <summary>The <c>resource_name</c> (§2, RECOMMENDED).</summary>
    public string? ResourceName { get; init; }

    /// <summary>The <c>resource_documentation</c> URL (§2).</summary>
    public string? ResourceDocumentation { get; init; }

    /// <summary>The <c>resource_policy_uri</c> (§2).</summary>
    public string? ResourcePolicyUri { get; init; }

    /// <summary>The <c>resource_tos_uri</c> (§2).</summary>
    public string? ResourceTosUri { get; init; }

    /// <summary>The <c>tls_client_certificate_bound_access_tokens</c> boolean; omitted when <see langword="null"/>.</summary>
    public bool? TlsClientCertificateBoundAccessTokens { get; init; }

    /// <summary>The <c>authorization_details_types_supported</c> values (§2).</summary>
    public IReadOnlyList<string>? AuthorizationDetailsTypesSupported { get; init; }

    /// <summary>
    /// The <c>dpop_signing_alg_values_supported</c> values (RFC 9728 Section 2), read only when the server validates no DPoP proof (an
    /// application validating proofs itself); where the server validates proofs, the document carries the one list it
    /// holds every proof to and this member is not read.
    /// </summary>
    public IReadOnlyList<string>? DpopSigningAlgValuesSupported { get; init; }

    /// <summary>
    /// The <c>dpop_bound_access_tokens_required</c> boolean; omitted when <see langword="null"/>. The requirement of the
    /// library's own resources (<see cref="Server.AuthorizationServerIntegration.IsDpopBoundAccessTokenRequiredAtResources"/>)
    /// is stated by their own documents, never through this member.
    /// </summary>
    public bool? DpopBoundAccessTokensRequired { get; init; }

    /// <summary>
    /// Language-tagged human-readable variants (§2.1): full parameter names
    /// with their BCP47 tag (for example <c>resource_name#it</c>) mapped to
    /// values. Emitted verbatim after the typed members.
    /// </summary>
    public IReadOnlyDictionary<string, string>? LocalizedParameters { get; init; }
}
