namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// The <c>ValidityInfo</c> sub-structure inside an MSO per ISO/IEC 18013-5
/// §9.1.2.4 — the temporal bounds the issuer commits to for this credential.
/// </summary>
/// <remarks>
/// <para>
/// All four fields are CBOR <c>tdate</c> (RFC 3339 date-time strings wrapped
/// in CBOR Tag 0). They flow through the data model as
/// <see cref="DateTimeOffset"/> values; the parser is responsible for
/// converting the tdate wire form to the parsed view.
/// </para>
/// <para>
/// The validator's job (M.4) is to check that <see cref="Signed"/> ≤
/// <see cref="ValidFrom"/> ≤ presentation-time ≤ <see cref="ValidUntil"/>,
/// and to surface <see cref="ExpectedUpdate"/> as a hint for clients that
/// want to refresh the credential proactively before it expires.
/// </para>
/// </remarks>
public sealed class MdocValidityInfo
{
    /// <summary>
    /// Initializes a <c>ValidityInfo</c> view from caller-supplied timestamps.
    /// </summary>
    /// <param name="signed">The moment the MSO was signed.</param>
    /// <param name="validFrom">The earliest moment the MSO is considered valid.</param>
    /// <param name="validUntil">The latest moment the MSO is considered valid.</param>
    /// <param name="expectedUpdate">
    /// Optional hint indicating when the issuer plans to issue a fresh MSO.
    /// Used by clients to schedule proactive refresh; carries no validity
    /// implication on its own.
    /// </param>
    public MdocValidityInfo(
        DateTimeOffset signed,
        DateTimeOffset validFrom,
        DateTimeOffset validUntil,
        DateTimeOffset? expectedUpdate = null)
    {
        Signed = signed;
        ValidFrom = validFrom;
        ValidUntil = validUntil;
        ExpectedUpdate = expectedUpdate;
    }


    /// <summary>The moment the issuer signed this MSO.</summary>
    public DateTimeOffset Signed { get; }

    /// <summary>The earliest moment the MSO is considered valid for presentation.</summary>
    public DateTimeOffset ValidFrom { get; }

    /// <summary>The latest moment the MSO is considered valid for presentation.</summary>
    public DateTimeOffset ValidUntil { get; }

    /// <summary>
    /// Optional advisory hint indicating when the issuer plans to issue a
    /// fresh MSO. Clients use it to schedule proactive refresh; it carries no
    /// hard validity implication.
    /// </summary>
    public DateTimeOffset? ExpectedUpdate { get; }
}
