namespace Verifiable.Cbor.StatusList;

/// <summary>
/// CWT claim keys and CBOR map keys for the Token Status List specification.
/// </summary>
/// <remarks>
/// <para>
/// These constants correspond to the CBOR representations defined in Sections 4.3,
/// 5.2, and 6.3 of draft-ietf-oauth-status-list. CWT claims use registered integer
/// keys from the IANA CBOR Web Token Claims registry.
/// </para>
/// </remarks>
public static class StatusListCborConstants
{
    /// <summary>
    /// CWT claim key for <c>subject</c> (2), per RFC 8392 Section 3.1.2.
    /// </summary>
    public const int Subject = 2;

    /// <summary>
    /// CWT claim key for <c>expiration time</c> (4), per RFC 8392 Section 3.1.4.
    /// </summary>
    public const int ExpirationTime = 4;

    /// <summary>
    /// CWT claim key for <c>issued at</c> (6), per RFC 8392 Section 3.1.6.
    /// </summary>
    public const int IssuedAt = 6;

    /// <summary>
    /// CWT claim key for <c>time to live</c> (65534), registered by draft-ietf-oauth-status-list.
    /// </summary>
    public const int TimeToLive = 65534;

    /// <summary>
    /// CWT claim key for <c>status list</c> (65533), registered by draft-ietf-oauth-status-list.
    /// </summary>
    public const int StatusList = 65533;

    /// <summary>
    /// CWT claim key for <c>status</c> (65535) in Referenced Tokens,
    /// registered by draft-ietf-oauth-status-list.
    /// </summary>
    public const int Status = 65535;

    /// <summary>
    /// CBOR text string map key for <c>bits</c> within the Status List CBOR map.
    /// </summary>
    public const string Bits = "bits";

    /// <summary>
    /// CBOR text string map key for <c>lst</c> within the Status List CBOR map.
    /// </summary>
    public const string List = "lst";

    /// <summary>
    /// CBOR text string map key for <c>aggregation_uri</c> within the Status List CBOR map.
    /// </summary>
    public const string AggregationUri = "aggregation_uri";

    /// <summary>
    /// CBOR text string map key for <c>idx</c> within the Status List reference CBOR map.
    /// </summary>
    public const string Index = "idx";

    /// <summary>
    /// CBOR text string map key for <c>uri</c> within the Status List reference CBOR map.
    /// </summary>
    public const string Uri = "uri";
}