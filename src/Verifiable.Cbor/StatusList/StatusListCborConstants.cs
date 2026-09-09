namespace Verifiable.Cbor.StatusList;

/// <summary>
/// CWT claim keys and CBOR map keys for the Token Status List specification.
/// </summary>
/// <remarks>
/// <para>
/// These constants correspond to the CBOR representations defined in Sections 4.3,
/// 5.2, and 6.3 of draft-ietf-oauth-status-list. CWT claims use registered integer
/// keys from the IANA CBOR Web Token Claims registry — those have no JOSE-side
/// counterpart and stay their own literals here. The text string map keys
/// (<see cref="Bits"/>, <see cref="List"/>, <see cref="AggregationUri"/>, <see cref="Index"/>,
/// <see cref="Uri"/>) alias <see cref="Verifiable.Core.StatusList.StatusListMemberNames"/>, the same
/// member names the JOSE side reads — this leaf carries no second copy of those literals.
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
    public const string Bits = Verifiable.Core.StatusList.StatusListMemberNames.Bits;

    /// <summary>
    /// CBOR text string map key for <c>lst</c> within the Status List CBOR map.
    /// </summary>
    public const string List = Verifiable.Core.StatusList.StatusListMemberNames.List;

    /// <summary>
    /// CBOR text string map key for <c>aggregation_uri</c> within the Status List CBOR map.
    /// </summary>
    public const string AggregationUri = Verifiable.Core.StatusList.StatusListMemberNames.AggregationUri;

    /// <summary>
    /// CBOR text string map key for <c>idx</c> within the Status List reference CBOR map.
    /// </summary>
    public const string Index = Verifiable.Core.StatusList.StatusListMemberNames.Index;

    /// <summary>
    /// CBOR text string map key for <c>uri</c> within the Status List reference CBOR map.
    /// </summary>
    public const string Uri = Verifiable.Core.StatusList.StatusListMemberNames.Uri;
}
