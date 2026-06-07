namespace Verifiable.OAuth;

/// <summary>
/// Well-known parameter NAMES for the OpenID Provider metadata document
/// per OpenID Connect Discovery 1.0 §3. These are JSON keys appearing in
/// the metadata document published at <c>/.well-known/openid-configuration</c>.
/// </summary>
/// <remarks>
/// These are the NAMES of metadata parameters (e.g., <c>"userinfo_endpoint"</c>,
/// <c>"id_token_signing_alg_values_supported"</c>, <c>"subject_types_supported"</c>),
/// not their VALUES. Values are deployment-specific URLs, algorithm
/// identifiers, supported-feature lists. The OAuth-AS-side equivalent
/// lives in <see cref="AuthorizationServerMetadataParameterNames"/>.
/// </remarks>
public static class OpenIdProviderMetadataParameterNames
{
    /// <summary>
    /// URL of the OpenID Provider's UserInfo endpoint.
    /// </summary>
    public static readonly string UserinfoEndpoint = "userinfo_endpoint";

    /// <summary>
    /// JSON array of supported ID Token signing algorithms.
    /// </summary>
    public static readonly string IdTokenSigningAlgValuesSupported = "id_token_signing_alg_values_supported";

    /// <summary>
    /// JSON array of supported subject identifier types.
    /// </summary>
    public static readonly string SubjectTypesSupported = "subject_types_supported";

    /// <summary>
    /// JSON array of the Claim Names of the Claims that the OpenID Provider
    /// MAY be able to supply values for per OIDC Discovery 1.0 §3. Clients
    /// use the list to decide which claims to request; the OP is not
    /// guaranteed to populate every advertised claim for every request.
    /// </summary>
    public static readonly string ClaimsSupported = "claims_supported";

    /// <summary>
    /// JSON array of the Claim Types that the OpenID Provider supports per
    /// OIDC Core 1.0 §5.6. Defined values: <c>"normal"</c> (claim values
    /// supplied directly by the OP), <c>"aggregated"</c>, and
    /// <c>"distributed"</c>. Default per OIDC Discovery §3 when the field
    /// is absent: <c>["normal"]</c>. The library emits the explicit field
    /// because aggregated / distributed claims are not implemented.
    /// </summary>
    public static readonly string ClaimTypesSupported = "claim_types_supported";
}
