namespace Verifiable.OAuth;

/// <summary>
/// Well-known parameter NAMES for the OpenID Federation metadata
/// document per OpenID Federation 1.0. These are JSON keys appearing in
/// federation entity statements and federation endpoint discovery
/// documents.
/// </summary>
/// <remarks>
/// These are the NAMES of federation metadata parameters (e.g.,
/// <c>"federation_fetch_endpoint"</c>, <c>"federation_list_endpoint"</c>),
/// not their VALUES. Values are URLs of federation endpoints.
/// </remarks>
public static class FederationMetadataParameterNames
{
    /// <summary>
    /// URL of the federation fetch endpoint for retrieving subordinate statements.
    /// </summary>
    public static readonly string FetchEndpoint = "federation_fetch_endpoint";

    /// <summary>
    /// URL of the federation list endpoint for listing subordinate entities.
    /// </summary>
    public static readonly string ListEndpoint = "federation_list_endpoint";

    /// <summary>
    /// URL of the federation resolve endpoint.
    /// </summary>
    public static readonly string ResolveEndpoint = "federation_resolve_endpoint";

    /// <summary>
    /// URL of the federation trust mark status endpoint.
    /// </summary>
    public static readonly string TrustMarkStatusEndpoint = "federation_trust_mark_status_endpoint";

    /// <summary>
    /// URL of the federation trust mark listing endpoint.
    /// </summary>
    public static readonly string TrustMarkListingEndpoint = "federation_trust_mark_listing_endpoint";

    /// <summary>
    /// URL of the federation trust mark endpoint.
    /// </summary>
    public static readonly string TrustMarkEndpoint = "federation_trust_mark_endpoint";

    /// <summary>
    /// URL of the federation historical keys endpoint.
    /// </summary>
    public static readonly string HistoricalKeysEndpoint = "federation_historical_keys_endpoint";
}
