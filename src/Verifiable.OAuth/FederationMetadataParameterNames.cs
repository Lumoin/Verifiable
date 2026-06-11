using Verifiable.Cryptography.Text;


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
    /// <summary>The UTF-8 source literal of <see cref="FetchEndpoint"/>.</summary>
    public static ReadOnlySpan<byte> FetchEndpointUtf8 => "federation_fetch_endpoint"u8;

    /// <summary>
    /// URL of the federation fetch endpoint for retrieving subordinate statements.
    /// </summary>
    public static readonly string FetchEndpoint = Utf8Constants.ToInternedString(FetchEndpointUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ListEndpoint"/>.</summary>
    public static ReadOnlySpan<byte> ListEndpointUtf8 => "federation_list_endpoint"u8;

    /// <summary>
    /// URL of the federation list endpoint for listing subordinate entities.
    /// </summary>
    public static readonly string ListEndpoint = Utf8Constants.ToInternedString(ListEndpointUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ResolveEndpoint"/>.</summary>
    public static ReadOnlySpan<byte> ResolveEndpointUtf8 => "federation_resolve_endpoint"u8;

    /// <summary>
    /// URL of the federation resolve endpoint.
    /// </summary>
    public static readonly string ResolveEndpoint = Utf8Constants.ToInternedString(ResolveEndpointUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TrustMarkStatusEndpoint"/>.</summary>
    public static ReadOnlySpan<byte> TrustMarkStatusEndpointUtf8 => "federation_trust_mark_status_endpoint"u8;

    /// <summary>
    /// URL of the federation trust mark status endpoint.
    /// </summary>
    public static readonly string TrustMarkStatusEndpoint = Utf8Constants.ToInternedString(TrustMarkStatusEndpointUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TrustMarkListingEndpoint"/>.</summary>
    public static ReadOnlySpan<byte> TrustMarkListingEndpointUtf8 => "federation_trust_mark_listing_endpoint"u8;

    /// <summary>
    /// URL of the federation trust mark listing endpoint.
    /// </summary>
    public static readonly string TrustMarkListingEndpoint = Utf8Constants.ToInternedString(TrustMarkListingEndpointUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TrustMarkEndpoint"/>.</summary>
    public static ReadOnlySpan<byte> TrustMarkEndpointUtf8 => "federation_trust_mark_endpoint"u8;

    /// <summary>
    /// URL of the federation trust mark endpoint.
    /// </summary>
    public static readonly string TrustMarkEndpoint = Utf8Constants.ToInternedString(TrustMarkEndpointUtf8);

    /// <summary>The UTF-8 source literal of <see cref="HistoricalKeysEndpoint"/>.</summary>
    public static ReadOnlySpan<byte> HistoricalKeysEndpointUtf8 => "federation_historical_keys_endpoint"u8;

    /// <summary>
    /// URL of the federation historical keys endpoint.
    /// </summary>
    public static readonly string HistoricalKeysEndpoint = Utf8Constants.ToInternedString(HistoricalKeysEndpointUtf8);
}
