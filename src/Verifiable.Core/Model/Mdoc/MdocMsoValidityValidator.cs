namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// Temporal gate validator for the MSO <see cref="MdocValidityInfo"/> per
/// ISO/IEC 18013-5 §9.1.2.4 — the "is this credential currently valid for
/// presentation" check a verifier runs alongside signature verification
/// (M.3) and digest binding (M.4).
/// </summary>
/// <remarks>
/// <para>
/// Three checks, in this order:
/// </para>
/// <list type="number">
///   <item><description>
///     Structural sanity — <see cref="MdocValidityInfo.ValidFrom"/> must
///     not be after <see cref="MdocValidityInfo.ValidUntil"/>. An inverted
///     window is a malformed MSO.
///   </description></item>
///   <item><description>
///     Lifecycle sanity — <see cref="MdocValidityInfo.Signed"/> must not
///     be after <see cref="MdocValidityInfo.ValidFrom"/>. The signature
///     can't pre-date its own validity window's opening; otherwise the
///     issuer's lifecycle is contradictory.
///   </description></item>
///   <item><description>
///     Currency — <paramref name="validationTime"/> must lie within
///     [<see cref="MdocValidityInfo.ValidFrom"/>,
///     <see cref="MdocValidityInfo.ValidUntil"/>]. Strict bounds at both
///     ends.
///   </description></item>
/// </list>
/// <para>
/// <see cref="MdocValidityInfo.ExpectedUpdate"/> is treated as an issuer
/// hint, not a hard constraint. Validation does not fail when the hint
/// has passed; the result surfaces it via
/// <see cref="MdocValidityResult.ExpectedUpdateAtOrPast"/> so callers can
/// trigger a proactive refresh.
/// </para>
/// <para>
/// Format-agnostic — operates on the parsed
/// <see cref="MdocValidityInfo"/> from the MSO, no CBOR dependency. Lives
/// in <see cref="Verifiable.Core.Model.Mdoc"/> next to
/// <see cref="MdocMsoDigestBindingValidator"/>.
/// </para>
/// </remarks>
public static class MdocMsoValidityValidator
{
    /// <summary>
    /// Validates the temporal gate on <paramref name="validityInfo"/>
    /// against <paramref name="validationTime"/>.
    /// </summary>
    /// <param name="validityInfo">
    /// The MSO's parsed <c>ValidityInfo</c>, typically reached via
    /// <c>MdocIssuerSigned.IssuerAuth.Mso.ValidityInfo</c>.
    /// </param>
    /// <param name="validationTime">
    /// The instant against which to evaluate validity. Production callers
    /// pass <see cref="TimeProvider.GetUtcNow"/> from their wallet/verifier
    /// time source; tests pass a deterministic value.
    /// </param>
    /// <returns>The validation outcome.</returns>
    public static MdocValidityResult Validate(
        MdocValidityInfo validityInfo,
        DateTimeOffset validationTime)
    {
        ArgumentNullException.ThrowIfNull(validityInfo);

        //Structural sanity first — an inverted window is a malformed MSO
        //regardless of validation time.
        if(validityInfo.ValidFrom > validityInfo.ValidUntil)
        {
            return MdocValidityResult.Failed(MdocValidityFailureReason.ValidFromAfterValidUntil);
        }

        if(validityInfo.Signed > validityInfo.ValidFrom)
        {
            return MdocValidityResult.Failed(MdocValidityFailureReason.SignedAfterValidFrom);
        }

        if(validationTime < validityInfo.ValidFrom)
        {
            return MdocValidityResult.Failed(MdocValidityFailureReason.NotYetValid);
        }

        if(validationTime > validityInfo.ValidUntil)
        {
            return MdocValidityResult.Failed(MdocValidityFailureReason.Expired);
        }

        bool expectedUpdateAtOrPast = validityInfo.ExpectedUpdate is DateTimeOffset expected
            && validationTime >= expected;

        return MdocValidityResult.Success(expectedUpdateAtOrPast);
    }
}
