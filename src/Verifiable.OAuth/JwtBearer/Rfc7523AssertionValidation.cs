using System.Diagnostics;

using Verifiable.JCose;
using Verifiable.OAuth.Validation;

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

    /// <summary>
    /// The <c>sub</c> claim is absent or white space only
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523 Section 3</see> item 2: "The
    /// JWT MUST contain a "sub" (subject) claim identifying the principal that is the subject of the JWT.").
    /// A value of white space only identifies no principal; that reading is this library's, the one
    /// <see cref="IdJag.IdJagValidationFailureReason.MissingSubject"/> applies to the same claim.
    /// </summary>
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

    /// <summary>
    /// The assertion is not yet valid: its <c>nbf</c> or its <c>iat</c> lies after the current instant plus the
    /// skew. The <c>nbf</c> case is
    /// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523 Section 3</see> item 5. The <c>iat</c>
    /// case is this library's policy under that section's "Application of additional restrictions and policy are
    /// at the discretion of the authorization server.", since
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.6">RFC 7519 Section 4.1.6</see> reads "The
    /// "iat" (issued at) claim identifies the time at which the JWT was issued. This claim can be used to
    /// determine the age of the JWT. Its value MUST be a number containing a NumericDate value. Use of this claim
    /// is OPTIONAL." and a JWT issued beyond the skew after the current instant names a time that has not come.
    /// </summary>
    NotYetValid,

    /// <summary>
    /// The temporal claims are internally inconsistent — <c>exp</c> at or before <c>iat</c> or
    /// <c>nbf</c> (the validity window never opens, independent of the current clock), or an
    /// <c>exp</c>, <c>iat</c> or <c>nbf</c> claim that is present and is not a number, or is a NumericDate this
    /// server cannot represent.
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

    /// <summary>
    /// The assertion is not yet valid: its <c>nbf</c> or its <c>iat</c> lies after the current instant plus the
    /// skew (<see cref="Rfc7523AssertionValidationFailureReason.NotYetValid"/> states the clauses).
    /// </summary>
    NotYetValid,

    /// <summary>The temporal claims are internally inconsistent, not numbers, or NumericDates this server cannot represent.</summary>
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
public static class Rfc7523AssertionValidation
{
    /// <summary>
    /// Validates the full §3 claim set against <paramref name="payload"/> in the RFC's own numbered
    /// order (items 1, 2, 3, 4, 5, 6) and returns the first rule the assertion fails, or a success
    /// carrying the validated claims.
    /// </summary>
    /// <param name="payload">The decoded (signature-verified) JWT payload.</param>
    /// <param name="audience">The caller's own identity — the value <c>aud</c> (§3 item 3) must name.</param>
    /// <param name="now">The instant the exp, nbf and iat are evaluated against.</param>
    /// <param name="clockSkew">
    /// Tolerance applied to the <c>exp</c>, <c>nbf</c> and <c>iat</c> comparisons: an <c>nbf</c> or an <c>iat</c>
    /// later than the current instant plus this tolerance is
    /// <see cref="Rfc7523AssertionValidationFailureReason.NotYetValid"/>, and one equal to it is accepted.
    /// </param>
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

        //RFC 7523 Section 3 item 2 (https://www.rfc-editor.org/rfc/rfc7523#section-3): the subject the access is
        //requested for. A value of white space only identifies no principal (this library's reading of
        //"identifying the principal"; its token factories throw for such a subject), so it is refused here as no
        //subject rather than reaching them.
        if(!TryReadStringClaim(payload, WellKnownJwtClaimNames.Sub, out string? subject)
            || string.IsNullOrWhiteSpace(subject))
        {
            return Rfc7523AssertionValidationResult.Failure(
                Rfc7523AssertionValidationFailureReason.MissingSubject,
                "The assertion is missing the sub claim or carries one of white space only.");
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
    /// <c>iat</c> are OPTIONAL but, when present, MUST be numeric timestamps consistent with <c>exp</c>. An
    /// <c>nbf</c> or an <c>iat</c> later than the current instant plus <paramref name="clockSkew"/> is
    /// <see cref="Rfc7523TemporalOutcome.NotYetValid"/>; for the <c>iat</c> that refusal is this library's policy
    /// under <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523 Section 3</see>: "Application of
    /// additional restrictions and policy are at the discretion of the authorization server." No maximum age of
    /// the <c>iat</c> is applied: an <c>iat</c> unreasonably far in the past is the application's to judge.
    /// </summary>
    /// <param name="payload">The decoded JWT payload.</param>
    /// <param name="now">The current instant.</param>
    /// <param name="clockSkew">
    /// Tolerance applied to the <c>exp</c>, <c>nbf</c> and <c>iat</c> comparisons; an <c>nbf</c> or an <c>iat</c>
    /// equal to the current instant plus this tolerance is accepted.
    /// </param>
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

        NumericDateReadResult expRead = ReadNumericDate(payload, WellKnownJwtClaimNames.Exp, out bool isExpNumber, out DateTimeOffset exp);
        if(expRead != NumericDateReadResult.Value)
        {
            failureDescription = (expRead, isExpNumber) switch
            {
                (NumericDateReadResult.Absent, _) => "The assertion is missing the exp claim.",
                (_, true) => "The assertion exp claim is a NumericDate this server cannot represent.",
                _ => "The assertion exp claim is not a numeric timestamp."
            };

            return expRead == NumericDateReadResult.Absent
                ? Rfc7523TemporalOutcome.MissingExpiration
                : Rfc7523TemporalOutcome.InconsistentTemporalClaims;
        }

        NumericDateReadResult iatRead = ReadNumericDate(payload, WellKnownJwtClaimNames.Iat, out bool isIatNumber, out DateTimeOffset iat);
        if(iatRead == NumericDateReadResult.Malformed)
        {
            failureDescription = isIatNumber
                ? "The assertion iat claim is a NumericDate this server cannot represent."
                : "The assertion iat claim is not a numeric timestamp.";

            return Rfc7523TemporalOutcome.InconsistentTemporalClaims;
        }

        //Structural temporal consistency, independent of the clock: an exp at or before iat has no
        //positive lifetime and is nonsensical regardless of when it is checked.
        if(iatRead == NumericDateReadResult.Value && exp <= iat)
        {
            failureDescription = "The assertion exp is at or before iat (non-positive lifetime).";

            return Rfc7523TemporalOutcome.InconsistentTemporalClaims;
        }

        //An assertion issued later than the clock plus the skew names a time that has not come; refusing it is
        //this library's policy under RFC 7523 Section 3's additional restrictions. The instants are compared through
        //their difference, as the not-before is, so no sum leaves the representable range.
        if(iatRead == NumericDateReadResult.Value && iat - now > clockSkew)
        {
            failureDescription = "The assertion iat is in the future beyond the skew tolerance.";

            return Rfc7523TemporalOutcome.NotYetValid;
        }

        NumericDateReadResult nbfRead = ReadNumericDate(payload, WellKnownJwtClaimNames.Nbf, out bool isNbfNumber, out DateTimeOffset nbf);
        if(nbfRead == NumericDateReadResult.Malformed)
        {
            failureDescription = isNbfNumber
                ? "The assertion nbf claim is a NumericDate this server cannot represent."
                : "The assertion nbf claim is not a numeric timestamp.";

            return Rfc7523TemporalOutcome.InconsistentTemporalClaims;
        }

        if(nbfRead == NumericDateReadResult.Value)
        {
            if(exp <= nbf)
            {
                failureDescription = "The assertion exp is at or before nbf (the validity window never opens).";

                return Rfc7523TemporalOutcome.InconsistentTemporalClaims;
            }

            //The instants are compared through their difference, which every two instants a DateTimeOffset
            //holds can form, so a not-before at either edge of the representable range is compared rather than
            //added to.
            if(nbf - now > clockSkew)
            {
                failureDescription = "The assertion nbf is in the future beyond the skew tolerance.";

                return Rfc7523TemporalOutcome.NotYetValid;
            }
        }

        //The expiry plus the skew can pass the last instant a DateTimeOffset holds, so the expiry is compared with
        //the clock through their difference: an expiry within the skew of the largest instant is not expired.
        if(now - exp >= clockSkew)
        {
            failureDescription = "The assertion has expired.";

            return Rfc7523TemporalOutcome.Expired;
        }

        expiration = exp;
        issuedAt = iatRead == NumericDateReadResult.Value ? iat : null;

        return Rfc7523TemporalOutcome.Valid;
    }


    private static Rfc7523AssertionValidationFailureReason MapTemporalFailure(Rfc7523TemporalOutcome outcome) => outcome switch
    {
        Rfc7523TemporalOutcome.MissingExpiration => Rfc7523AssertionValidationFailureReason.MissingExpiration,
        Rfc7523TemporalOutcome.Expired => Rfc7523AssertionValidationFailureReason.Expired,
        Rfc7523TemporalOutcome.NotYetValid => Rfc7523AssertionValidationFailureReason.NotYetValid,
        Rfc7523TemporalOutcome.InconsistentTemporalClaims => Rfc7523AssertionValidationFailureReason.InconsistentTemporalClaims,
        Rfc7523TemporalOutcome.Valid => Rfc7523AssertionValidationFailureReason.InconsistentTemporalClaims,

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


    /// <summary>
    /// Reads a time claim, an <c>exp</c>, <c>nbf</c> or <c>iat</c>, as the NumericDate
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-2">RFC 7519 Section 2</see> defines, "A JSON
    /// numeric value representing the number of seconds from 1970-01-01T00:00:00Z UTC until the specified UTC
    /// date/time, ignoring leap seconds", where "non-integer values can be represented". This is the one reader
    /// of a time claim the RFC 7523 Section 3 claim rules here, <see cref="Server.PrivateKeyJwtClientAuthentication"/>,
    /// <see cref="Federation.FederationClientAuthentication"/>, <see cref="JwsAccessTokenValidator"/> and
    /// <see cref="Oidc10IdTokenValidator"/> (its <c>auth_time</c>) share.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4">RFC 7519 Section 4.1.4</see>, of the
    /// <c>exp</c>, <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5">Section 4.1.5</see>, of the
    /// <c>nbf</c>, and <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.6">Section 4.1.6</see>, of
    /// the <c>iat</c>, each read "Its value MUST be a number containing a NumericDate value.", so a JSON string is
    /// no time claim, digits included, and is malformed. A number a decoder hands in one of eight CLR shapes
    /// (<see cref="long"/>, <see cref="int"/>, <see cref="short"/>, <see cref="byte"/>, <see cref="ulong"/>,
    /// <see cref="uint"/>, <see cref="double"/>, <see cref="decimal"/>) is read. A <see cref="float"/> is a number
    /// the reader refuses as a NumericDate this server cannot represent: its 24 mantissa bits hold only one epoch
    /// second in 128 of this era exactly (between 2^30 and 2^31 seconds its spacing is 128 seconds, so an instant
    /// read from one is off by up to 64 seconds), and refusing the shape as a whole is this library's rule. A claim
    /// in any other shape is no number to this reader and is malformed. A number of the eight is read through
    /// <see cref="JwtTemporalChecks.TryFromUnixSeconds(decimal, out DateTimeOffset)"/> or its
    /// <see cref="double"/> overload, which keep the fraction to the tick and answer a value no
    /// <see cref="DateTimeOffset"/> can hold, or one that is not finite, as not representable rather than
    /// throwing. Such a number is a NumericDate this server cannot represent, and it is malformed as well:
    /// refusing it is this library's fail-closed reading, since no instant the checks compare can hold it.
    /// </summary>
    /// <param name="payload">The decoded JWT payload.</param>
    /// <param name="claimName">The name of the time claim: <c>exp</c>, <c>nbf</c>, <c>iat</c> or <c>auth_time</c>.</param>
    /// <param name="isNumber">
    /// Whether a present claim is a number to this reader, so a caller can tell a NumericDate this server cannot
    /// represent from a value that is no number: <see langword="true"/> for a claim in one of the eight shapes the
    /// reader reads and for a <see cref="float"/>, which it refuses; <see langword="false"/> for a claim in any
    /// other shape, a JSON string included, and for an absent claim.
    /// </param>
    /// <param name="value">The instant the claim names when the read answers <see cref="NumericDateReadResult.Value"/>.</param>
    /// <returns>Whether the claim is absent, names an instant, or is malformed.</returns>
    internal static NumericDateReadResult ReadNumericDate(
        JwtPayload payload, string claimName, out bool isNumber, out DateTimeOffset value)
    {
        value = default;
        isNumber = false;
        if(!payload.TryGetValue(claimName, out object? raw))
        {
            return NumericDateReadResult.Absent;
        }

        bool isRepresentable;
        (isNumber, isRepresentable) = raw switch
        {
            long l => (true, JwtTemporalChecks.TryFromUnixSeconds((decimal)l, out value)),
            int i => (true, JwtTemporalChecks.TryFromUnixSeconds((decimal)i, out value)),
            short s => (true, JwtTemporalChecks.TryFromUnixSeconds((decimal)s, out value)),
            byte b => (true, JwtTemporalChecks.TryFromUnixSeconds((decimal)b, out value)),
            ulong u => (true, JwtTemporalChecks.TryFromUnixSeconds((decimal)u, out value)),
            uint ui => (true, JwtTemporalChecks.TryFromUnixSeconds((decimal)ui, out value)),
            double d => (true, JwtTemporalChecks.TryFromUnixSeconds(d, out value)),
            decimal dec => (true, JwtTemporalChecks.TryFromUnixSeconds(dec, out value)),
            float => (true, false),
            _ => (false, false)
        };

        return isRepresentable ? NumericDateReadResult.Value : NumericDateReadResult.Malformed;
    }
}
