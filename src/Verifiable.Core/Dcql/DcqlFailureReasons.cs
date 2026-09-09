using System.Collections.Generic;

namespace Verifiable.Core.Dcql;

/// <summary>
/// Named reasons a credential fails a <see cref="DcqlEvaluator"/> match, carried on
/// <see cref="DcqlEvaluationResult.FailureReason"/>.
/// </summary>
/// <remarks>
/// Every reason has one named home — a constant for a fixed reason, a formatting method for one
/// that names the offending value — so a caller recognises a reason by identity rather than by
/// parsing text. The fail-closed reasons (<see cref="CredentialTypeUnknown"/>,
/// <see cref="SdJwtVctValuesRequired"/>, <see cref="TrustedAuthorityEvidenceAbsent"/>,
/// <see cref="TrustedAuthorityUnmatched"/>) carry
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.4.2">
/// OpenID for Verifiable Presentations 1.0, Section 6.4.2</see>: "Credentials not matching the
/// respective constraints expressed within credentials MUST NOT be returned".
/// </remarks>
public static class DcqlFailureReasons
{
    /// <summary>
    /// The query's <c>meta.vct_values</c> (or <c>doctype_value</c>) constrains the credential
    /// type, and the credential's metadata declares no type at all — the credential's type
    /// cannot be shown to satisfy the constraint, so it does not match.
    /// </summary>
    public const string CredentialTypeUnknown =
        "the query constrains the credential type (meta.vct_values) and the credential declares none";

    /// <summary>
    /// The credential query names the <c>dc+sd-jwt</c> format but carries no non-empty
    /// <c>meta.vct_values</c>, which
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.3.5">
    /// OpenID for Verifiable Presentations 1.0, Appendix B.3.5</see> makes REQUIRED: "vct_values:
    /// REQUIRED. A non-empty array of strings that specifies allowed values for the type of the
    /// requested Verifiable Credential." A query that expresses no type constraint where the
    /// format demands one cannot be shown to be satisfied by any credential, so nothing matches
    /// it.
    /// </summary>
    public const string SdJwtVctValuesRequired =
        "the query names the dc+sd-jwt format but carries no meta.vct_values, which Appendix B.3.5 makes REQUIRED";

    /// <summary>
    /// The query's <c>trusted_authorities</c> constrains the issuing authority, and the
    /// credential carries no issuer evidence at all — the constraint cannot be shown to be
    /// satisfied, so it does not match.
    /// </summary>
    public const string TrustedAuthorityEvidenceAbsent =
        "the query names trusted authorities and the credential carries no issuer evidence";

    /// <summary>
    /// The query's <c>trusted_authorities</c> constrains the issuing authority, the credential
    /// carries trust evidence, but no entry's type matched a value in that evidence — per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1.1</see>, a match requires one of the
    /// provided values in one of the provided types, and none did.
    /// </summary>
    public const string TrustedAuthorityUnmatched =
        "the query names trusted authorities and the credential's evidence matches none of them";

    /// <summary>Formats the reason naming a <c>trusted_authorities</c> entry whose <c>type</c> is
    /// none of the three registered values — per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1.1</see>, an unregistered type cannot be
    /// evaluated and matches nothing.</summary>
    /// <param name="type">The unsupported <c>type</c> value.</param>
    public static string TrustedAuthorityTypeUnsupported(string? type) =>
        $"Trusted authority type '{type}' is not one of the registered types (aki, etsi_tl, openid_federation).";

    /// <summary>Formats the format-mismatch failure reason.</summary>
    /// <param name="expectedFormat">The credential query's <c>format</c>.</param>
    /// <param name="actualFormat">The credential metadata's <see cref="DcqlCredentialMetadata.Format"/>.</param>
    public static string FormatMismatch(string? expectedFormat, string? actualFormat) =>
        $"Format mismatch: expected '{expectedFormat}', got '{actualFormat}'.";

    /// <summary>Formats the credential-type-not-accepted failure reason.</summary>
    /// <param name="credentialType">The credential's declared type.</param>
    public static string CredentialTypeNotAccepted(string? credentialType) =>
        $"Credential type '{credentialType}' not in accepted types.";

    /// <summary>
    /// Formats the reason for a <c>meta</c> that constrains the credential type but names no
    /// value the query's own format reads — a <c>doctype_value</c> under an SD-JWT format, say.
    /// The constraint is unanswerable, and Section 6.4.2 treats unanswerable as no match.
    /// </summary>
    /// <param name="format">The credential query's <c>format</c>.</param>
    public static string TypeConstraintUnreadable(string? format) =>
        $"The query constrains the credential type but names no value the '{format}' format reads.";

    /// <summary>Formats the missing-required-claims failure reason.</summary>
    /// <param name="missingRequired">The required claim patterns the credential did not satisfy.</param>
    public static string MissingRequiredClaims(IReadOnlyList<Model.Dcql.DcqlClaimPattern> missingRequired) =>
        $"Missing required claims: {string.Join(", ", missingRequired)}";

    /// <summary>Formats the failed-value-constraints failure reason.</summary>
    /// <param name="failedValueConstraints">The claim patterns whose value constraint failed.</param>
    public static string ValueConstraintsFailed(IReadOnlyList<Model.Dcql.DcqlClaimPattern> failedValueConstraints) =>
        $"Value constraints failed: {string.Join(", ", failedValueConstraints)}";

    /// <summary>The failure reason for an unsatisfied required claim set.</summary>
    public const string RequiredClaimSetNotSatisfied = "Required claim set not satisfied.";
}
