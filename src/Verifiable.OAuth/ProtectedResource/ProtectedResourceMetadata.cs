using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.OAuth.ProtectedResource;

/// <summary>
/// A parsed OAuth 2.0 Protected Resource Metadata document (RFC 9728 §2) —
/// the consumer-side typed view of the JSON served at the resource's
/// <c>/.well-known/oauth-protected-resource</c> location (§3).
/// </summary>
/// <remarks>
/// URL-valued members stay wire strings: the §3.3 <c>resource</c> validation
/// is a code-point comparison (§6), not a parsed-URI comparison, and the
/// consumer decides what to dereference. Before using the document the
/// consumer MUST run <see cref="ProtectedResourceMetadataValidation.IsResourceMatch"/>
/// against the resource identifier it derived the metadata URL from (§3.3).
/// </remarks>
[DebuggerDisplay("ProtectedResourceMetadata Resource={Resource}")]
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "RFC 9728 metadata values are wire strings; §3.3/§6 compares them code point by code point, not as parsed URIs.")]
public sealed record ProtectedResourceMetadata
{
    /// <summary>The REQUIRED <c>resource</c> identifier (§1.2).</summary>
    public required string Resource { get; init; }

    /// <summary>The OPTIONAL <c>authorization_servers</c> issuer identifiers.</summary>
    public IReadOnlyList<string>? AuthorizationServers { get; init; }

    /// <summary>The OPTIONAL <c>jwks_uri</c>.</summary>
    public string? JwksUri { get; init; }

    /// <summary>The RECOMMENDED <c>scopes_supported</c> values.</summary>
    public IReadOnlyList<string>? ScopesSupported { get; init; }

    /// <summary>The OPTIONAL <c>bearer_methods_supported</c> values; see <see cref="BearerMethodValues"/>.</summary>
    public IReadOnlyList<string>? BearerMethodsSupported { get; init; }

    /// <summary>The OPTIONAL <c>resource_signing_alg_values_supported</c> values.</summary>
    public IReadOnlyList<string>? ResourceSigningAlgValuesSupported { get; init; }

    /// <summary>The RECOMMENDED <c>resource_name</c> (the untagged variant; see RFC 9728 §2.1).</summary>
    public string? ResourceName { get; init; }

    /// <summary>The OPTIONAL <c>resource_documentation</c> URL.</summary>
    public string? ResourceDocumentation { get; init; }

    /// <summary>The OPTIONAL <c>resource_policy_uri</c>.</summary>
    public string? ResourcePolicyUri { get; init; }

    /// <summary>The OPTIONAL <c>resource_tos_uri</c>.</summary>
    public string? ResourceTosUri { get; init; }

    /// <summary>The OPTIONAL <c>tls_client_certificate_bound_access_tokens</c>; absent defaults to false (§2).</summary>
    public bool? TlsClientCertificateBoundAccessTokens { get; init; }

    /// <summary>The OPTIONAL <c>authorization_details_types_supported</c> values.</summary>
    public IReadOnlyList<string>? AuthorizationDetailsTypesSupported { get; init; }

    /// <summary>The OPTIONAL <c>dpop_signing_alg_values_supported</c> values.</summary>
    public IReadOnlyList<string>? DpopSigningAlgValuesSupported { get; init; }

    /// <summary>The OPTIONAL <c>dpop_bound_access_tokens_required</c>; absent defaults to false (§2).</summary>
    public bool? DpopBoundAccessTokensRequired { get; init; }

    /// <summary>
    /// The OPTIONAL <c>signed_metadata</c> compact JWT (§2.2). A supporting
    /// consumer MUST verify the signature against a key belonging to the JWT's
    /// <c>iss</c> and give the signed claims precedence over the plain values.
    /// </summary>
    public string? SignedMetadata { get; init; }
}


/// <summary>
/// The RFC 9728 §3.3 validation a consumer MUST perform before using a
/// fetched Protected Resource Metadata document.
/// </summary>
public static class ProtectedResourceMetadataValidation
{
    /// <summary>
    /// Whether the document's <c>resource</c> value is identical to the
    /// resource identifier the metadata URL was derived from (§3.3). The
    /// comparison is code point by code point with no Unicode normalization
    /// (§6). When the values differ, the document MUST NOT be used.
    /// </summary>
    /// <param name="metadata">The fetched and parsed document.</param>
    /// <param name="expectedResourceIdentifier">
    /// The resource identifier into which the well-known path suffix was
    /// inserted to form the metadata URL — or, when the URL came from a
    /// <c>WWW-Authenticate</c> <c>resource_metadata</c> parameter, the URL the
    /// client used to make the resource request.
    /// </param>
    public static bool IsResourceMatch(ProtectedResourceMetadata metadata, string expectedResourceIdentifier)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedResourceIdentifier);

        return string.Equals(metadata.Resource, expectedResourceIdentifier, StringComparison.Ordinal);
    }
}
