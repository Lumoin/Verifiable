namespace Verifiable.JCose;

/// <summary>
/// Well-known JWT claim NAMES specific to a Security Event Token (SET) as
/// defined by <see href="https://www.rfc-editor.org/rfc/rfc8417">RFC 8417</see>
/// and the subject-identifier extension in
/// <see href="https://www.rfc-editor.org/rfc/rfc9493">RFC 9493</see>.
/// </summary>
/// <remarks>
/// <para>
/// A SET reuses the registered JWT claims (<c>iss</c>, <c>iat</c>, <c>jti</c>,
/// <c>aud</c>, <c>sub</c>, <c>exp</c>, <c>nbf</c>) from
/// <see cref="WellKnownJwtClaimNames"/>; this class carries only the claims the
/// SET specifications add on top. These are the NAMES of claims, not their
/// VALUES, and they are case-sensitive per RFC 7519.
/// </para>
/// </remarks>
public static class SecurityEventTokenClaimNames
{
    /// <summary>
    /// The <c>events</c> claim — a JSON object whose members are event-type URIs
    /// mapped to event payload objects. REQUIRED in every SET.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc8417#section-2.2">RFC 8417 §2.2</see>.
    /// </summary>
    public static readonly string Events = "events";

    /// <summary>
    /// The <c>toe</c> (Time of Event) claim — the time at which the event
    /// occurred, as a JSON number of seconds from the Unix epoch. OPTIONAL.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc8417#section-2.2">RFC 8417 §2.2</see>.
    /// </summary>
    public static readonly string Toe = "toe";

    /// <summary>
    /// The <c>txn</c> (Transaction Identifier) claim — an opaque value the issuer
    /// uses to correlate the SET with a transaction or process. OPTIONAL.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc8417#section-2.2">RFC 8417 §2.2</see>.
    /// </summary>
    public static readonly string Txn = "txn";

    /// <summary>
    /// The <c>sub_id</c> (Subject Identifier) claim — a Subject Identifier object
    /// (carrying a <c>format</c> member) that identifies the principal the SET is
    /// about, in place of the bare string <c>sub</c> claim. OPTIONAL.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 §3</see>.
    /// </summary>
    public static readonly string SubId = "sub_id";


    /// <summary>Whether <paramref name="claim"/> is <see cref="Events"/>.</summary>
    public static bool IsEvents(string claim) => WellKnownJwtClaimNames.Equals(claim, Events);

    /// <summary>Whether <paramref name="claim"/> is <see cref="Toe"/>.</summary>
    public static bool IsToe(string claim) => WellKnownJwtClaimNames.Equals(claim, Toe);

    /// <summary>Whether <paramref name="claim"/> is <see cref="Txn"/>.</summary>
    public static bool IsTxn(string claim) => WellKnownJwtClaimNames.Equals(claim, Txn);

    /// <summary>Whether <paramref name="claim"/> is <see cref="SubId"/>.</summary>
    public static bool IsSubId(string claim) => WellKnownJwtClaimNames.Equals(claim, SubId);


    /// <summary>
    /// Returns the interned constant for a known SET claim name, or the original
    /// string if unrecognized. Enables reference-equality fast paths downstream.
    /// </summary>
    public static string GetCanonicalizedValue(string claim) => claim switch
    {
        _ when IsEvents(claim) => Events,
        _ when IsToe(claim) => Toe,
        _ when IsTxn(claim) => Txn,
        _ when IsSubId(claim) => SubId,
        _ => claim
    };
}
