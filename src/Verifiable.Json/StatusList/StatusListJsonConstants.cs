namespace Verifiable.Json.StatusList;

/// <summary>
/// JWT claim names and JSON member names for the Token Status List specification.
/// </summary>
/// <remarks>
/// <para>
/// These constants correspond to the JSON representations defined in Sections 4.2,
/// 5.1, 6.1, and 6.2 of draft-ietf-oauth-status-list. The claim names
/// (<see cref="StatusList"/>, <see cref="Status"/>, <see cref="TimeToLive"/>) alias
/// <see cref="Verifiable.JCose.WellKnownJwtClaimNames"/>; the object member names
/// (<see cref="Bits"/>, <see cref="List"/>, <see cref="AggregationUri"/>, <see cref="Index"/>,
/// <see cref="Uri"/>) alias <see cref="Verifiable.Core.StatusList.StatusListMemberNames"/> — this leaf
/// carries no second copy of either literal.
/// </para>
/// </remarks>
public static class StatusListJsonConstants
{
    /// <summary>
    /// The <c>status_list</c> claim name for the Status List in a JWT Status List Token
    /// and as a member in the Referenced Token <c>status</c> claim.
    /// </summary>
    public static string StatusList { get; } = Verifiable.JCose.WellKnownJwtClaimNames.StatusList;

    /// <summary>
    /// The <c>status</c> claim name in a Referenced Token.
    /// </summary>
    public static string Status { get; } = Verifiable.JCose.WellKnownJwtClaimNames.Status;

    /// <summary>
    /// The <c>bits</c> member name within the Status List JSON object.
    /// </summary>
    public const string Bits = Verifiable.Core.StatusList.StatusListMemberNames.Bits;

    /// <summary>
    /// The <c>lst</c> member name containing the base64url-encoded compressed byte array.
    /// </summary>
    public const string List = Verifiable.Core.StatusList.StatusListMemberNames.List;

    /// <summary>
    /// The <c>aggregation_uri</c> member name for the optional aggregation endpoint.
    /// </summary>
    public const string AggregationUri = Verifiable.Core.StatusList.StatusListMemberNames.AggregationUri;

    /// <summary>
    /// The <c>idx</c> member name for the index in a Status List reference.
    /// </summary>
    public const string Index = Verifiable.Core.StatusList.StatusListMemberNames.Index;

    /// <summary>
    /// The <c>uri</c> member name for the URI in a Status List reference.
    /// </summary>
    public const string Uri = Verifiable.Core.StatusList.StatusListMemberNames.Uri;

    /// <summary>
    /// The <c>ttl</c> claim name for time to live in seconds.
    /// </summary>
    public static string TimeToLive { get; } = Verifiable.JCose.WellKnownJwtClaimNames.TimeToLive;

    /// <summary>
    /// The <c>status_lists</c> member in the Status List Aggregation response. Distinct from every
    /// other member here: it names the Section 9 Aggregation endpoint's response array, not a JWT
    /// claim or a Status List object member, so it carries no alias.
    /// </summary>
    public const string StatusLists = "status_lists";
}
