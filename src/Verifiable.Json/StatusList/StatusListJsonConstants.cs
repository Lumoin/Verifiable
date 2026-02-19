namespace Verifiable.Json.StatusList;

/// <summary>
/// JWT claim names and JSON member names for the Token Status List specification.
/// </summary>
/// <remarks>
/// <para>
/// These constants correspond to the JSON representations defined in Sections 4.2,
/// 5.1, 6.1, and 6.2 of draft-ietf-oauth-status-list.
/// </para>
/// </remarks>
public static class StatusListJsonConstants
{
    /// <summary>
    /// The <c>status_list</c> claim name for the Status List in a JWT Status List Token
    /// and as a member in the Referenced Token <c>status</c> claim.
    /// </summary>
    public const string StatusList = "status_list";

    /// <summary>
    /// The <c>status</c> claim name in a Referenced Token.
    /// </summary>
    public const string Status = "status";

    /// <summary>
    /// The <c>bits</c> member name within the Status List JSON object.
    /// </summary>
    public const string Bits = "bits";

    /// <summary>
    /// The <c>lst</c> member name containing the base64url-encoded compressed byte array.
    /// </summary>
    public const string List = "lst";

    /// <summary>
    /// The <c>aggregation_uri</c> member name for the optional aggregation endpoint.
    /// </summary>
    public const string AggregationUri = "aggregation_uri";

    /// <summary>
    /// The <c>idx</c> member name for the index in a Status List reference.
    /// </summary>
    public const string Index = "idx";

    /// <summary>
    /// The <c>uri</c> member name for the URI in a Status List reference.
    /// </summary>
    public const string Uri = "uri";

    /// <summary>
    /// The <c>ttl</c> claim name for time to live in seconds.
    /// </summary>
    public const string TimeToLive = "ttl";

    /// <summary>
    /// The <c>status_lists</c> member in the Status List Aggregation response.
    /// </summary>
    public const string StatusLists = "status_lists";
}