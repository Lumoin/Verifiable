using System.Diagnostics;

namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// Enumerates the reasons MSO <see cref="MdocValidityInfo"/> temporal
/// validation can fail. Used by <see cref="MdocValidityResult.FailureReason"/>.
/// </summary>
public enum MdocValidityFailureReason
{
    /// <summary>No failure; the temporal gate passed.</summary>
    None = 0,

    /// <summary>
    /// Validation time is before
    /// <see cref="MdocValidityInfo.ValidFrom"/>. The credential is not yet
    /// valid for presentation.
    /// </summary>
    NotYetValid,

    /// <summary>
    /// Validation time is after <see cref="MdocValidityInfo.ValidUntil"/>.
    /// The credential has expired.
    /// </summary>
    Expired,

    /// <summary>
    /// <see cref="MdocValidityInfo.Signed"/> is after
    /// <see cref="MdocValidityInfo.ValidFrom"/>. Indicates a malformed
    /// validity-info structure — the signature timestamp claims the MSO
    /// was signed AFTER its own validity window opened, which contradicts
    /// the issuance lifecycle the spec assumes.
    /// </summary>
    SignedAfterValidFrom,

    /// <summary>
    /// <see cref="MdocValidityInfo.ValidFrom"/> is after
    /// <see cref="MdocValidityInfo.ValidUntil"/>. The validity window is
    /// inverted — semantically a malformed MSO.
    /// </summary>
    ValidFromAfterValidUntil
}


/// <summary>
/// Result of <see cref="MdocMsoValidityValidator.Validate"/> — the
/// MSO temporal gate per ISO/IEC 18013-5 §9.1.2.4. Carries the per-stage
/// outcome plus an advisory flag for the issuer's
/// <see cref="MdocValidityInfo.ExpectedUpdate"/> hint.
/// </summary>
/// <remarks>
/// <para>
/// Mirrors <see cref="MdocDigestBindingResult"/> on the digest-binding
/// side: same <c>readonly record struct</c> shape, same
/// <see cref="Success(bool)"/> / <see cref="Failed"/> factories. A wallet/
/// verifier composes both results sequentially in the
/// trust → signature → binding → temporal pipeline.
/// </para>
/// </remarks>
[DebuggerDisplay("{ToString()}")]
public readonly record struct MdocValidityResult
{
    /// <summary>
    /// Whether the credential's temporal gate passed.
    /// <see cref="ExpectedUpdateAtOrPast"/> being true does NOT make this
    /// false — the issuer's update hint is advisory.
    /// </summary>
    public bool IsValid { get; init; }

    /// <summary>The failure reason; <see cref="MdocValidityFailureReason.None"/> on success.</summary>
    public MdocValidityFailureReason FailureReason { get; init; }

    /// <summary>
    /// Whether the validation time is at or past the issuer's
    /// <see cref="MdocValidityInfo.ExpectedUpdate"/> hint. Advisory only —
    /// callers may surface this as "issuer suggests refresh" but should
    /// NOT block presentations on it. <see langword="false"/> when the
    /// MSO carries no <see cref="MdocValidityInfo.ExpectedUpdate"/>.
    /// </summary>
    public bool ExpectedUpdateAtOrPast { get; init; }


    /// <summary>Creates a successful validity result.</summary>
    /// <param name="expectedUpdateAtOrPast">
    /// Whether the issuer's <see cref="MdocValidityInfo.ExpectedUpdate"/>
    /// (if any) is at or past the validation time.
    /// </param>
    public static MdocValidityResult Success(bool expectedUpdateAtOrPast = false) => new()
    {
        IsValid = true,
        FailureReason = MdocValidityFailureReason.None,
        ExpectedUpdateAtOrPast = expectedUpdateAtOrPast
    };


    /// <summary>Creates a failed validity result.</summary>
    public static MdocValidityResult Failed(MdocValidityFailureReason reason)
    {
        if(reason == MdocValidityFailureReason.None)
        {
            throw new ArgumentException(
                "Failed result must carry a non-None reason.", nameof(reason));
        }

        return new()
        {
            IsValid = false,
            FailureReason = reason,
            ExpectedUpdateAtOrPast = false
        };
    }


    /// <inheritdoc/>
    public override string ToString()
    {
        if(IsValid)
        {
            return ExpectedUpdateAtOrPast
                ? "Valid (issuer suggests refresh)"
                : "Valid";
        }

        return $"Invalid ({FailureReason})";
    }
}
