namespace Verifiable.OAuth.Client;

/// <summary>
/// The <see href="https://www.rfc-editor.org/rfc/rfc8414#section-3.3">RFC 8414 §3.3</see> /
/// <see href="https://openid.net/specs/openid-connect-discovery-1_0.html">OpenID Connect
/// Discovery 1.0 §4.3</see> validation a consumer MUST perform before using a fetched
/// Authorization Server / OpenID Provider metadata document. The sibling of
/// <see cref="Verifiable.OAuth.ProtectedResource.ProtectedResourceMetadataValidation"/>
/// for RFC 9728.
/// </summary>
public static class AuthorizationServerMetadataValidation
{
    /// <summary>
    /// Whether the document's <c>issuer</c> value is identical to the issuer identifier the
    /// metadata URL was derived from. RFC 8414 §3.3 / OIDC Discovery §4.3 require this match,
    /// and the comparison is code point by code point — no Unicode normalization and no URI
    /// canonicalization (a <see cref="Uri"/> equality test would normalize host case and
    /// trailing slashes and is therefore too lax). When the values differ the metadata MUST
    /// NOT be used: this rejects, for example, a multi-tenant deployment that placed its
    /// tenant segment in the endpoint paths but not in the <c>issuer</c>, or a portless
    /// placeholder issuer that does not equal the per-tenant base the well-known URL came from.
    /// </summary>
    /// <remarks>
    /// This is the §3.3 issuer-match check only. <c>jwks_uri</c> reachability — the other half
    /// of an onboarding inspector's readiness verdict — is a separate runtime/SSRF-policy
    /// concern handled by the application's
    /// <see cref="ResolveAuthorizationServerJwksDelegate"/>, not a pure string comparison.
    /// </remarks>
    /// <param name="metadata">The fetched and parsed metadata.</param>
    /// <param name="expectedIssuerIdentifier">
    /// The issuer identifier into which the well-known path was inserted to form the metadata
    /// URL the client fetched.
    /// </param>
    public static bool IsIssuerMatch(AuthorizationServerMetadata metadata, Uri expectedIssuerIdentifier)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        ArgumentNullException.ThrowIfNull(expectedIssuerIdentifier);

        return IsIssuerIdentifierMatch(metadata.Issuer.OriginalString, expectedIssuerIdentifier);
    }


    /// <summary>
    /// The code-point-by-code-point issuer-identifier comparison
    /// <see href="https://www.rfc-editor.org/rfc/rfc8414#section-3.3">RFC 8414 §3.3</see> /
    /// <see href="https://www.rfc-editor.org/rfc/rfc9207#section-2.4">RFC 9207 §2.4</see>
    /// require — no Unicode normalization, no URI canonicalization. The single
    /// comparison rule shared by <see cref="IsIssuerMatch"/> (the metadata-issuer
    /// consistency gate) and <see cref="AuthorizationServerIssuerValidation.IsAuthorizationResponseIssuerValid"/>
    /// (the RFC 9207 §2.4 mix-up defense), so both apply the identical rule rather
    /// than each defining its own.
    /// </summary>
    /// <param name="issuerIdentifier">The issuer identifier under comparison.</param>
    /// <param name="expectedIssuerIdentifier">The issuer identifier it must equal.</param>
    internal static bool IsIssuerIdentifierMatch(string issuerIdentifier, Uri expectedIssuerIdentifier)
    {
        ArgumentNullException.ThrowIfNull(expectedIssuerIdentifier);

        return string.Equals(issuerIdentifier, expectedIssuerIdentifier.OriginalString, StringComparison.Ordinal);
    }
}
