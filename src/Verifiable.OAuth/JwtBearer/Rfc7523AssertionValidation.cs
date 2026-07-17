using System.Diagnostics;

using Verifiable.JCose;

namespace Verifiable.OAuth.JwtBearer;

/// <summary>
/// The reason a decoded assertion failed <see cref="Rfc7523AssertionValidation.Validate"/>. Every value
/// maps to the <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3.1">RFC 7523 §3.1</see>
/// <c>invalid_grant</c> rejection the processing rules mandate.
/// </summary>
public enum Rfc7523AssertionValidationFailureReason
{
    /// <summary>§3 item 1: the <c>iss</c> claim is absent.</summary>
    MissingIssuer,

    /// <summary>§3 item 2: the <c>sub</c> claim is absent.</summary>
    MissingSubject,

    /// <summary>§3 item 3: the <c>aud</c> claim is absent.</summary>
    MissingAudience,

    /// <summary>
    /// §3 item 3: the <c>aud</c> claim does not name the caller's own identity — either a string
    /// unequal to it, or an array that does not contain EXACTLY one element equal to it (a
    /// multi-element array is rejected even when one element matches, so an assertion crafted to also
    /// be valid at another audience can never be replayed here).
    /// </summary>
    AudienceMismatch,

    /// <summary>§3 item 4: the <c>exp</c> claim is absent.</summary>
    MissingExpiration,

    /// <summary>§3 item 4: the assertion has expired (<c>exp</c> at or before now, within skew).</summary>
    Expired,

    /// <summary>§3 item 5: the assertion is not yet valid (<c>nbf</c> after now, beyond skew).</summary>
    NotYetValid,

    /// <summary>
    /// The temporal claims are internally inconsistent — <c>exp</c> at or before <c>iat</c> or
    /// <c>nbf</c> (the validity window never opens, independent of the current clock), or an
    /// <c>exp</c>/<c>iat</c>/<c>nbf</c> claim that is present but not a numeric timestamp.
    /// </summary>
    InconsistentTemporalClaims
}


/// <summary>
/// The outcome of validating an assertion's <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC
/// 7523 §3</see> claim rules via <see cref="Rfc7523AssertionValidation.Validate"/>. A success carries the
/// claims a caller shapes its grant from; a failure carries the
/// <see cref="Rfc7523AssertionValidationFailureReason"/> the caller maps to <c>invalid_grant</c>
/// (RFC 7523 §3.1).
/// </summary>
/// <remarks>
/// The crypto layer (signature verification, key resolution — §3 item 9) and the trust decision over
/// <see cref="Issuer"/> (which issuers are trusted at all — §3 item 1's "issuer comparison") are the
/// caller's concern: this result describes only the claim-rule outcome over an already
/// signature-verified, decoded assertion.
/// </remarks>
[DebuggerDisplay("Rfc7523AssertionValidationResult IsValid={IsValid} Reason={FailureReason}")]
public sealed record Rfc7523AssertionValidationResult
{
    /// <summary>Whether the assertion satisfied every claim rule.</summary>
    public bool IsValid => FailureReason is null;

    /// <summary>The reason validation failed, or <see langword="null"/> on success.</summary>
    public Rfc7523AssertionValidationFailureReason? FailureReason { get; init; }

    /// <summary>A human-readable description of the failure, or <see langword="null"/> on success.</summary>
    public string? FailureDescription { get; init; }

    /// <summary>The <c>iss</c> claim (§3 item 1). Present on success.</summary>
    public string? Issuer { get; init; }

    /// <summary>The <c>sub</c> claim — the party the grant is requested for (§3 item 2). Present on success.</summary>
    public string? Subject { get; init; }

    /// <summary>The <c>aud</c> value that matched the caller's own identity (§3 item 3). Present on success.</summary>
    public string? Audience { get; init; }

    /// <summary>The <c>exp</c> claim (§3 item 4). Present on success.</summary>
    public DateTimeOffset? Expiration { get; init; }

    /// <summary>The <c>iat</c> claim, when present (§3 item 6).</summary>
    public DateTimeOffset? IssuedAt { get; init; }


    /// <summary>Builds a successful result carrying the validated claims.</summary>
    public static Rfc7523AssertionValidationResult Success(
        string issuer, string subject, string audience, DateTimeOffset expiration, DateTimeOffset? issuedAt) =>
        new()
        {
            Issuer = issuer,
            Subject = subject,
            Audience = audience,
            Expiration = expiration,
            IssuedAt = issuedAt
        };


    /// <summary>Builds a failed result with the given <paramref name="reason"/> and optional <paramref name="description"/>.</summary>
    public static Rfc7523AssertionValidationResult Failure(
        Rfc7523AssertionValidationFailureReason reason, string? description = null) =>
        new()
        {
            FailureReason = reason,
            FailureDescription = description
        };
}


/// <summary>The outcome of <see cref="Rfc7523AssertionValidation.ValidateAudience"/> — §3 item 3.</summary>
internal enum Rfc7523AudienceOutcome
{
    /// <summary>The <c>aud</c> claim names the expected audience.</summary>
    Match,

    /// <summary>The <c>aud</c> claim is absent.</summary>
    Missing,

    /// <summary>The <c>aud</c> claim is present but does not name the expected audience in an accepted shape.</summary>
    Mismatch
}


/// <summary>The outcome of <see cref="Rfc7523AssertionValidation.ValidateTemporalClaims"/> — §3 items 4–6.</summary>
internal enum Rfc7523TemporalOutcome
{
    /// <summary><c>exp</c> (and, when present, <c>nbf</c>/<c>iat</c>) satisfy every temporal rule.</summary>
    Valid,

    /// <summary>The <c>exp</c> claim is absent.</summary>
    MissingExpiration,

    /// <summary>The assertion has expired.</summary>
    Expired,

    /// <summary>The assertion is not yet valid.</summary>
    NotYetValid,

    /// <summary>The temporal claims are internally inconsistent or not numeric timestamps.</summary>
    InconsistentTemporalClaims
}


/// <summary>
/// Validates the <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523 §3</see>
/// "JWT Format and Processing Requirements" claim rules — <c>iss</c>/<c>sub</c>/<c>aud</c>/<c>exp</c>/
/// <c>nbf</c>/<c>iat</c> — that apply to ANY assertion presented under RFC 7523, independent of which
/// profile minted it. <see cref="IdJag.IdJagAssertionValidation"/> CONSUMES the per-rule methods below to
/// implement its own draft-ietf-oauth-identity-assertion-authz-grant-04 (21 May 2026) §4.4.1 claim set (which layers
/// additional ID-JAG-specific checks — <c>typ</c>, same-trust-domain, <c>client_id</c> — around the same
/// §3 rules), rather than re-implementing them.
/// </summary>
/// <remarks>
/// Out of scope, by design (the caller's concern): §3 item 9 (signature/MAC verification — this type
/// operates on an already signature-verified, decoded assertion), §3 item 1's "issuer comparison" (which
/// issuers are trusted at all), and §3 item 7 (<c>jti</c> replay defense — the library's
/// <see cref="Server.JtiReplayGuard"/> is the reusable surface for that, not this checker).
/// </remarks>
[DebuggerDisplay("Rfc7523AssertionValidation")]
public static class Rfc7523AssertionValidation
{
    /// <summary>
    /// Validates the full §3 claim set against <paramref name="payload"/> in the RFC's own numbered
    /// order (items 1, 2, 3, 4, 5, 6) and returns the first rule the assertion fails, or a success
    /// carrying the validated claims.
    /// </summary>
    /// <param name="payload">The decoded (signature-verified) JWT payload.</param>
    /// <param name="audience">The caller's own identity — the value <c>aud</c> (§3 item 3) must name.</param>
    /// <param name="now">The current instant for expiry / not-before evaluation.</param>
    /// <param name="clockSkew">Tolerance applied to the <c>exp</c> and <c>nbf</c> comparisons.</param>
    public static Rfc7523AssertionValidationResult Validate(
        JwtPayload payload, string audience, DateTimeOffset now, TimeSpan clockSkew)
    {
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentException.ThrowIfNullOrWhiteSpace(audience);

        if(!TryReadStringClaim(payload, WellKnownJwtClaimNames.Iss, out string? issuer))
        {
            return Rfc7523AssertionValidationResult.Failure(
                Rfc7523AssertionValidationFailureReason.MissingIssuer, "The assertion is missing the iss claim.");
        }

        if(!TryReadStringClaim(payload, WellKnownJwtClaimNames.Sub, out string? subject))
        {
            return Rfc7523AssertionValidationResult.Failure(
                Rfc7523AssertionValidationFailureReason.MissingSubject, "The assertion is missing the sub claim.");
        }

        Rfc7523AudienceOutcome audienceOutcome = ValidateAudience(payload, audience, out string? matchedAudience);
        if(audienceOutcome == Rfc7523AudienceOutcome.Missing)
        {
            return Rfc7523AssertionValidationResult.Failure(
                Rfc7523AssertionValidationFailureReason.MissingAudience, "The assertion is missing the aud claim.");
        }

        if(audienceOutcome == Rfc7523AudienceOutcome.Mismatch)
        {
            return Rfc7523AssertionValidationResult.Failure(
                Rfc7523AssertionValidationFailureReason.AudienceMismatch,
                "The assertion aud must name the expected audience as a string or single-element array.");
        }

        Rfc7523TemporalOutcome temporalOutcome = ValidateTemporalClaims(
            payload, now, clockSkew, out DateTimeOffset expiration, out DateTimeOffset? issuedAt, out string? temporalFailureDescription);
        if(temporalOutcome != Rfc7523TemporalOutcome.Valid)
        {
            return Rfc7523AssertionValidationResult.Failure(MapTemporalFailure(temporalOutcome), temporalFailureDescription);
        }

        return Rfc7523AssertionValidationResult.Success(issuer!, subject!, matchedAudience!, expiration, issuedAt);
    }


    /// <summary>Reads a non-empty string claim named <paramref name="claimName"/> from <paramref name="payload"/> (used for §3 items 1 and 2, and by callers for their own additional string claims).</summary>
    internal static bool TryReadStringClaim(JwtPayload payload, string claimName, out string? value)
    {
        if(payload.TryGetValue(claimName, out object? raw) && raw is string s && !string.IsNullOrEmpty(s))
        {
            value = s;

            return true;
        }

        value = null;

        return false;
    }


    /// <summary>
    /// §3 item 3: the <c>aud</c> claim MUST be present and MUST name <paramref name="audience"/>. The
    /// accepted shapes are a single string equal to <paramref name="audience"/>, or an array containing
    /// EXACTLY that one string and no other element — a multi-element array is rejected even when one
    /// element matches, which is the anti-audience-injection hardening
    /// <see cref="IdJag.IdJagAssertionValidation"/> already proved in production before this extraction.
    /// </summary>
    internal static Rfc7523AudienceOutcome ValidateAudience(JwtPayload payload, string audience, out string? matchedAudience)
    {
        matchedAudience = null;
        if(!payload.TryGetValue(WellKnownJwtClaimNames.Aud, out object? audRaw))
        {
            return Rfc7523AudienceOutcome.Missing;
        }

        string? extracted = ExtractSingleAudience(audRaw);
        if(extracted is null || !string.Equals(extracted, audience, StringComparison.Ordinal))
        {
            return Rfc7523AudienceOutcome.Mismatch;
        }

        matchedAudience = extracted;

        return Rfc7523AudienceOutcome.Match;
    }


    /// <summary>
    /// §3 items 4–6: <c>exp</c> MUST be present and the assertion MUST NOT be expired; <c>nbf</c> and
    /// <c>iat</c> are OPTIONAL but, when present, MUST be numeric timestamps consistent with <c>exp</c>.
    /// </summary>
    /// <param name="payload">The decoded JWT payload.</param>
    /// <param name="now">The current instant.</param>
    /// <param name="clockSkew">Tolerance applied to the <c>exp</c> and <c>nbf</c> comparisons.</param>
    /// <param name="expiration">The validated <c>exp</c> claim on <see cref="Rfc7523TemporalOutcome.Valid"/>.</param>
    /// <param name="issuedAt">The <c>iat</c> claim, when present, on <see cref="Rfc7523TemporalOutcome.Valid"/>.</param>
    /// <param name="failureDescription">A human-readable description of the specific rule that failed, or <see langword="null"/> on success.</param>
    internal static Rfc7523TemporalOutcome ValidateTemporalClaims(
        JwtPayload payload,
        DateTimeOffset now,
        TimeSpan clockSkew,
        out DateTimeOffset expiration,
        out DateTimeOffset? issuedAt,
        out string? failureDescription)
    {
        expiration = default;
        issuedAt = null;
        failureDescription = null;

        EpochReadResult expRead = TryReadEpochSeconds(payload, WellKnownJwtClaimNames.Exp, out DateTimeOffset exp);
        if(expRead != EpochReadResult.Value)
        {
            failureDescription = expRead == EpochReadResult.Absent
                ? "The assertion is missing the exp claim."
                : "The assertion exp claim is not a numeric timestamp.";

            return expRead == EpochReadResult.Absent
                ? Rfc7523TemporalOutcome.MissingExpiration
                : Rfc7523TemporalOutcome.InconsistentTemporalClaims;
        }

        EpochReadResult iatRead = TryReadEpochSeconds(payload, WellKnownJwtClaimNames.Iat, out DateTimeOffset iat);
        if(iatRead == EpochReadResult.Malformed)
        {
            failureDescription = "The assertion iat claim is not a numeric timestamp.";

            return Rfc7523TemporalOutcome.InconsistentTemporalClaims;
        }

        //Structural temporal consistency, independent of the clock: an exp at or before iat has no
        //positive lifetime and is nonsensical regardless of when it is checked.
        if(iatRead == EpochReadResult.Value && exp <= iat)
        {
            failureDescription = "The assertion exp is at or before iat (non-positive lifetime).";

            return Rfc7523TemporalOutcome.InconsistentTemporalClaims;
        }

        EpochReadResult nbfRead = TryReadEpochSeconds(payload, WellKnownJwtClaimNames.Nbf, out DateTimeOffset nbf);
        if(nbfRead == EpochReadResult.Malformed)
        {
            failureDescription = "The assertion nbf claim is not a numeric timestamp.";

            return Rfc7523TemporalOutcome.InconsistentTemporalClaims;
        }

        if(nbfRead == EpochReadResult.Value)
        {
            if(exp <= nbf)
            {
                failureDescription = "The assertion exp is at or before nbf (the validity window never opens).";

                return Rfc7523TemporalOutcome.InconsistentTemporalClaims;
            }

            if(nbf > now + clockSkew)
            {
                failureDescription = "The assertion nbf is in the future beyond the skew tolerance.";

                return Rfc7523TemporalOutcome.NotYetValid;
            }
        }

        if(exp + clockSkew <= now)
        {
            failureDescription = "The assertion has expired.";

            return Rfc7523TemporalOutcome.Expired;
        }

        expiration = exp;
        issuedAt = iatRead == EpochReadResult.Value ? iat : null;

        return Rfc7523TemporalOutcome.Valid;
    }


    private static Rfc7523AssertionValidationFailureReason MapTemporalFailure(Rfc7523TemporalOutcome outcome) => outcome switch
    {
        Rfc7523TemporalOutcome.MissingExpiration => Rfc7523AssertionValidationFailureReason.MissingExpiration,
        Rfc7523TemporalOutcome.Expired => Rfc7523AssertionValidationFailureReason.Expired,
        Rfc7523TemporalOutcome.NotYetValid => Rfc7523AssertionValidationFailureReason.NotYetValid,
        _ => Rfc7523AssertionValidationFailureReason.InconsistentTemporalClaims
    };


    /// <summary>
    /// Returns the single audience value from a decoded <c>aud</c> claim — the string itself, or the
    /// sole element of a single-element array — iff it is a non-empty string; otherwise
    /// <see langword="null"/>. A multi-element array, an array element that is not a non-empty string,
    /// or an empty value all yield <see langword="null"/> (no element is filtered out, so an extra
    /// non-string element cannot collapse the array to a single accepted entry).
    /// </summary>
    private static string? ExtractSingleAudience(object audRaw) => audRaw switch
    {
        string s => string.IsNullOrEmpty(s) ? null : s,
        IEnumerable<string> typed => SingleAudienceOrNull([.. typed]),
        IEnumerable<object> mixed => SingleAudienceOrNull([.. mixed]),
        _ => null
    };


    private static string? SingleAudienceOrNull(List<string> items) =>
        items.Count == 1 && !string.IsNullOrEmpty(items[0]) ? items[0] : null;


    private static string? SingleAudienceOrNull(List<object> items) =>
        items.Count == 1 && items[0] is string s && !string.IsNullOrEmpty(s) ? s : null;


    private enum EpochReadResult
    {
        Absent,
        Value,
        Malformed
    }


    private static EpochReadResult TryReadEpochSeconds(JwtPayload payload, string claimName, out DateTimeOffset value)
    {
        value = default;
        if(!payload.TryGetValue(claimName, out object? raw))
        {
            return EpochReadResult.Absent;
        }

        long? seconds = raw switch
        {
            long l => l,
            int i => i,
            double d => (long)d,
            decimal dec => (long)dec,
            _ => null
        };
        if(seconds is null)
        {
            return EpochReadResult.Malformed;
        }

        value = DateTimeOffset.FromUnixTimeSeconds(seconds.Value);

        return EpochReadResult.Value;
    }
}
