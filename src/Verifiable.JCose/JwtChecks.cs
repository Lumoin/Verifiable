using System.Diagnostics.CodeAnalysis;

namespace Verifiable.JCose;

/// <summary>
/// Pure structural and time-bound checks for JWT headers and payloads, surfaced as
/// extension methods on the four JWT types.
/// </summary>
/// <remarks>
/// <para>
/// These checks contain no I/O and carry no dependency on the assessment
/// infrastructure. They return <see langword="bool"/> and are intended to be
/// composed into higher-level validation pipelines by callers that own the
/// claim and assessment layer.
/// </para>
/// <para>
/// Four extension blocks enforce the trust boundary at compile time:
/// </para>
/// <list type="bullet">
///   <item>
///     <description>
///       Methods on <see cref="JwtHeader"/> and <see cref="JwtPayload"/> apply to
///       trusted, typed data — use these after the JWT structure has been accepted
///       and the signature verified.
///     </description>
///   </item>
///   <item>
///     <description>
///       Methods on <see cref="UnverifiedJwtHeader"/> and
///       <see cref="UnverifiedJwtPayload"/> apply to attacker-controlled data before
///       any verification. The type name carries the trust signal — no naming suffix
///       is required. Running expiry checks on an <see cref="UnverifiedJwtPayload"/>
///       before verifying the signature is a valid early-exit optimization, but the
///       result must still be treated as unverified until the signature check passes.
///     </description>
///   </item>
/// </list>
/// <para>
/// Clock skew parameters are applied symmetrically: expiry is extended by skew,
/// not-before is reduced by skew. Pass <see cref="TimeSpan.Zero"/> for strict
/// comparison.
/// </para>
/// <para>
/// A NumericDate claim is read by the library's one reading of the type
/// (<see cref="NumericDate"/>), every digit kept, and each bound is judged against
/// the date written exactly. An absent claim sets no bound; a claim present as no
/// NumericDate - a string of digits among them - is a bound that cannot be kept, so
/// the time-bound check it would answer reports the failure. Expiry is exclusive
/// (RFC 7519 Section 4.1.4: the present must be before <c>exp</c>).
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible",
    Justification = "The analyzer is not yet up to date with C# 14 extension syntax.")]
[SuppressMessage("Naming", "CA1708:Identifiers should differ by more than case",
    Justification = "The analyzer is not yet up to date with C# 14 extension syntax.")]
public static class JwtChecks
{
    extension(JwtHeader header)
    {
        /// <summary>
        /// Returns <see langword="true"/> when the <c>alg</c> header is absent or
        /// its value is <c>none</c>. A token with <c>alg=none</c> carries no
        /// integrity protection and must be rejected per
        /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-6.1">RFC 7519 §6.1</see>.
        /// </summary>
        public bool IsAlgNone() => IsAlgNoneCore(header);

        /// <summary>
        /// Returns <see langword="true"/> when the <c>alg</c> header is present and
        /// its value is not <c>none</c>.
        /// </summary>
        public bool HasValidAlg() => HasValidAlgCore(header);

        /// <summary>
        /// Returns <see langword="true"/> when the <c>kty</c> header is present and
        /// non-empty.
        /// </summary>
        public bool HasKty() => HasKtyCore(header);

        /// <summary>
        /// Returns <see langword="true"/> when the header contains the mandatory EC
        /// key fields: <c>crv</c>, <c>x</c>, and <c>y</c>.
        /// </summary>
        public bool HasRequiredEcFields() => HasRequiredEcFieldsCore(header);

        /// <summary>
        /// Returns <see langword="true"/> when the EC <c>alg</c> and <c>crv</c>
        /// values form a valid combination per
        /// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1.1">RFC 7518 §6.2.1.1</see>:
        /// ES256/P-256, ES384/P-384, ES512/P-521, ES256K/secp256k1.
        /// </summary>
        public bool IsValidEcAlgCrvCombination() => IsValidEcAlgCrvCombinationCore(header);

        /// <summary>
        /// Returns <see langword="true"/> when the header contains the mandatory OKP
        /// field <c>crv</c>.
        /// </summary>
        public bool HasRequiredOkpFields() => HasRequiredOkpFieldsCore(header);

        /// <summary>
        /// Returns <see langword="true"/> when the OKP <c>alg</c> and <c>crv</c>
        /// values form a valid combination: EdDSA/Ed25519 or absent-alg/X25519.
        /// X25519 is a key agreement curve and must not carry an <c>alg</c>.
        /// </summary>
        public bool IsValidOkpAlgCrvCombination() => IsValidOkpAlgCrvCombinationCore(header);

        /// <summary>
        /// Returns <see langword="true"/> when the header contains valid RSA fields:
        /// <c>e</c> (exponent) and <c>n</c> (modulus) with a modulus length
        /// corresponding to RSA-2048 or RSA-4096.
        /// </summary>
        public bool HasValidRsaFields() => HasValidRsaFieldsCore(header);
    }


    extension(UnverifiedJwtHeader header)
    {
        /// <summary>
        /// Returns <see langword="true"/> when the <c>alg</c> header is absent or
        /// its value is <c>none</c> in an unverified, attacker-controlled header.
        /// </summary>
        public bool IsAlgNone() => IsAlgNoneCore(header);

        /// <summary>
        /// Returns <see langword="true"/> when the <c>alg</c> header is present and
        /// its value is not <c>none</c> in an unverified header.
        /// </summary>
        public bool HasValidAlg() => HasValidAlgCore(header);

        /// <summary>
        /// Returns <see langword="true"/> when the <c>kty</c> header is present and
        /// non-empty in an unverified header.
        /// </summary>
        public bool HasKty() => HasKtyCore(header);

        /// <summary>
        /// Returns <see langword="true"/> when the unverified header contains the
        /// mandatory EC key fields: <c>crv</c>, <c>x</c>, and <c>y</c>.
        /// </summary>
        public bool HasRequiredEcFields() => HasRequiredEcFieldsCore(header);

        /// <summary>
        /// Returns <see langword="true"/> when the EC <c>alg</c> and <c>crv</c>
        /// values form a valid combination in an unverified header.
        /// </summary>
        public bool IsValidEcAlgCrvCombination() => IsValidEcAlgCrvCombinationCore(header);

        /// <summary>
        /// Returns <see langword="true"/> when the unverified header contains the
        /// mandatory OKP field <c>crv</c>.
        /// </summary>
        public bool HasRequiredOkpFields() => HasRequiredOkpFieldsCore(header);

        /// <summary>
        /// Returns <see langword="true"/> when the OKP <c>alg</c> and <c>crv</c>
        /// values form a valid combination in an unverified header.
        /// </summary>
        public bool IsValidOkpAlgCrvCombination() => IsValidOkpAlgCrvCombinationCore(header);

        /// <summary>
        /// Returns <see langword="true"/> when the unverified header contains valid
        /// RSA fields.
        /// </summary>
        public bool HasValidRsaFields() => HasValidRsaFieldsCore(header);
    }


    extension(JwtPayload payload)
    {
        /// <summary>
        /// Returns <see langword="true"/> when the <c>exp</c> claim is present and
        /// the token has expired relative to <paramref name="now"/> allowing for
        /// <paramref name="clockSkew"/>. Returns <see langword="false"/> when
        /// <c>exp</c> is absent — a token without expiry is treated as non-expired.
        /// </summary>
        public bool IsExpired(DateTimeOffset now, TimeSpan clockSkew) =>
            IsExpiredCore(payload, now, clockSkew);

        /// <summary>
        /// Returns <see langword="true"/> when the <c>nbf</c> claim is present and
        /// <paramref name="now"/> is before <c>nbf - clockSkew</c>.
        /// </summary>
        public bool IsNotYetValid(DateTimeOffset now, TimeSpan clockSkew) =>
            IsNotYetValidCore(payload, now, clockSkew);

        /// <summary>
        /// Returns <see langword="true"/> when the <c>iat</c> claim is present and
        /// its value is more than <paramref name="clockSkew"/> in the future. A
        /// future-issued token indicates a misconfigured server or a replay attempt.
        /// </summary>
        public bool IsIssuedInFuture(DateTimeOffset now, TimeSpan clockSkew) =>
            IsIssuedInFutureCore(payload, now, clockSkew);

        /// <summary>
        /// Returns <see langword="true"/> when the difference between <c>exp</c> and
        /// <c>nbf</c> (or <c>iat</c> when <c>nbf</c> is absent) exceeds
        /// <paramref name="maximum"/>. FAPI 2.0 / HAIP 1.0 require JAR tokens to
        /// have <c>exp - nbf</c> ≤ 60 seconds.
        /// </summary>
        public bool LifetimeExceeds(TimeSpan maximum) =>
            LifetimeExceedsCore(payload, maximum);

        /// <summary>
        /// Returns <see langword="true"/> when both <c>exp</c> and <c>nbf</c> are
        /// present and <c>exp</c> is not strictly after <c>nbf</c>. A token that
        /// expires at or before it becomes valid is malformed.
        /// </summary>
        public bool IsExpBeforeNbf() =>
            IsExpBeforeNbfCore(payload);
    }


    extension(UnverifiedJwtPayload payload)
    {
        /// <summary>
        /// Returns <see langword="true"/> when the <c>exp</c> claim is present and
        /// the token has expired in an unverified, attacker-controlled claims set.
        /// </summary>
        public bool IsExpired(DateTimeOffset now, TimeSpan clockSkew) =>
            IsExpiredCore(payload, now, clockSkew);

        /// <summary>
        /// Returns <see langword="true"/> when the <c>nbf</c> claim indicates the
        /// token is not yet valid in an unverified claims set.
        /// </summary>
        public bool IsNotYetValid(DateTimeOffset now, TimeSpan clockSkew) =>
            IsNotYetValidCore(payload, now, clockSkew);

        /// <summary>
        /// Returns <see langword="true"/> when the <c>iat</c> claim indicates future
        /// issuance in an unverified claims set.
        /// </summary>
        public bool IsIssuedInFuture(DateTimeOffset now, TimeSpan clockSkew) =>
            IsIssuedInFutureCore(payload, now, clockSkew);

        /// <summary>
        /// Returns <see langword="true"/> when the token lifetime exceeds
        /// <paramref name="maximum"/> in an unverified claims set.
        /// </summary>
        public bool LifetimeExceeds(TimeSpan maximum) =>
            LifetimeExceedsCore(payload, maximum);

        /// <summary>
        /// Returns <see langword="true"/> when <c>exp</c> is not after <c>nbf</c>
        /// in an unverified claims set.
        /// </summary>
        public bool IsExpBeforeNbf() =>
            IsExpBeforeNbfCore(payload);
    }


    //Private core implementations — shared by all four extension blocks.

    private static bool IsAlgNoneCore(IReadOnlyDictionary<string, object?> header)
    {
        if(!header.TryGetValue(WellKnownJwkMemberNames.Alg, out object? value) || value is not string alg)
        {
            return true;
        }

        return WellKnownJwaValues.IsNone(alg);
    }

    private static bool HasValidAlgCore(IReadOnlyDictionary<string, object?> header)
    {
        return header.TryGetValue(WellKnownJwkMemberNames.Alg, out object? value)
            && value is string alg
            && !string.IsNullOrEmpty(alg)
            && !WellKnownJwaValues.IsNone(alg);
    }

    private static bool HasKtyCore(IReadOnlyDictionary<string, object?> header)
    {
        return header.TryGetValue(WellKnownJwkMemberNames.Kty, out object? value)
            && value is string kty
            && !string.IsNullOrEmpty(kty);
    }

    private static bool HasRequiredEcFieldsCore(IReadOnlyDictionary<string, object?> header)
    {
        return header.TryGetValue(WellKnownJwkMemberNames.Crv, out object? crv)
            && crv is string crvStr && !string.IsNullOrEmpty(crvStr)
            && header.TryGetValue(WellKnownJwkMemberNames.X, out object? x)
            && x is string xStr && !string.IsNullOrEmpty(xStr)
            && header.TryGetValue(WellKnownJwkMemberNames.Y, out object? y)
            && y is string yStr && !string.IsNullOrEmpty(yStr);
    }

    private static bool IsValidEcAlgCrvCombinationCore(IReadOnlyDictionary<string, object?> header)
    {
        if(!header.TryGetValue(WellKnownJwkMemberNames.Crv, out object? crvValue) || crvValue is not string crv)
        {
            return false;
        }

        if(!header.TryGetValue(WellKnownJwkMemberNames.Alg, out object? algValue) || algValue is not string alg)
        {
            return false;
        }

        //RFC 7518 section 3.4's fixed alg/crv pairing table, one pair per disjunct; a named predicate per
        //pair would only rename the citation, not simplify it.
        return (WellKnownJwaValues.IsEs256(alg) && WellKnownCurveValues.IsP256(crv))
            || (WellKnownJwaValues.IsEs384(alg) && WellKnownCurveValues.IsP384(crv))
            || (WellKnownJwaValues.IsEs512(alg) && WellKnownCurveValues.IsP521(crv))
            || (WellKnownJwaValues.IsEs256K(alg) && WellKnownCurveValues.IsSecp256k1(crv));
    }

    private static bool HasRequiredOkpFieldsCore(IReadOnlyDictionary<string, object?> header)
    {
        return header.TryGetValue(WellKnownJwkMemberNames.Crv, out object? crv)
            && crv is string crvStr
            && !string.IsNullOrEmpty(crvStr);
    }

    private static bool IsValidOkpAlgCrvCombinationCore(IReadOnlyDictionary<string, object?> header)
    {
        if(!header.TryGetValue(WellKnownJwkMemberNames.Crv, out object? crvValue) || crvValue is not string crv)
        {
            return false;
        }

        //X25519 is a key agreement curve — alg must not be present.
        if(WellKnownCurveValues.IsX25519(crv))
        {
            return !header.ContainsKey(WellKnownJwkMemberNames.Alg);
        }

        //Ed25519 requires alg=EdDSA.
        if(WellKnownCurveValues.IsEd25519(crv))
        {
            return header.TryGetValue(WellKnownJwkMemberNames.Alg, out object? algValue)
                && algValue is string alg
                && WellKnownJwaValues.IsEdDsa(alg);
        }

        return false;
    }

    private static bool HasValidRsaFieldsCore(IReadOnlyDictionary<string, object?> header)
    {
        //RSA-2048: 256 bytes → Base64Url length ≈ 342 characters.
        //RSA-4096: 512 bytes → Base64Url length ≈ 683 characters.
        const int Rsa2048ModulusBase64UrlLength = 342;
        const int Rsa4096ModulusBase64UrlLength = 683;

        if(!header.TryGetValue(WellKnownJwkMemberNames.E, out object? eValue)
            || eValue is not string e
            || string.IsNullOrEmpty(e))
        {
            return false;
        }

        if(!header.TryGetValue(WellKnownJwkMemberNames.N, out object? nValue)
            || nValue is not string n
            || string.IsNullOrEmpty(n))
        {
            return false;
        }

        return n.Length is Rsa2048ModulusBase64UrlLength
            or Rsa4096ModulusBase64UrlLength;
    }

    /// <summary>
    /// Whether a claims set has expired: RFC 7519 Section 4.1.4 has the present before <c>exp</c>, so a present at or after
    /// <c>exp</c> extended by the tolerance is expired, the expiry instant itself among them.
    /// </summary>
    /// <param name="claims">The claims set.</param>
    /// <param name="now">The present.</param>
    /// <param name="clockSkew">The tolerance the expiry is extended by.</param>
    /// <returns><see langword="true"/> when the claims set has expired or its <c>exp</c> is present as no NumericDate.</returns>
    private static bool IsExpiredCore(
        IReadOnlyDictionary<string, object?> claims,
        DateTimeOffset now,
        TimeSpan clockSkew)
    {
        return ReadDate(claims, WellKnownJwtClaimNames.Exp, out var expiry) switch
        {
            ClaimDateReading.Absent => false,
            ClaimDateReading.Read => expiry!.CompareToEarlierBy(now, clockSkew) <= 0,
            _ => true
        };
    }

    /// <summary>
    /// Whether a claims set is not yet valid: RFC 7519 Section 4.1.5 has it accepted at or after <c>nbf</c>, so a present before
    /// <c>nbf</c> reduced by the tolerance is too early.
    /// </summary>
    /// <param name="claims">The claims set.</param>
    /// <param name="now">The present.</param>
    /// <param name="clockSkew">The tolerance the not-before date is reduced by.</param>
    /// <returns><see langword="true"/> when the claims set is not yet valid or its <c>nbf</c> is present as no NumericDate.</returns>
    private static bool IsNotYetValidCore(
        IReadOnlyDictionary<string, object?> claims,
        DateTimeOffset now,
        TimeSpan clockSkew)
    {
        return ReadDate(claims, WellKnownJwtClaimNames.Nbf, out var notBefore) switch
        {
            ClaimDateReading.Absent => false,
            ClaimDateReading.Read => notBefore!.CompareToLaterBy(now, clockSkew) > 0,
            _ => true
        };
    }

    /// <summary>Whether a claims set's <c>iat</c> lies after the present extended by the tolerance.</summary>
    /// <param name="claims">The claims set.</param>
    /// <param name="now">The present.</param>
    /// <param name="clockSkew">The tolerance the present is extended by.</param>
    /// <returns><see langword="true"/> when the claims set was issued in the future or its <c>iat</c> is present as no NumericDate.</returns>
    private static bool IsIssuedInFutureCore(
        IReadOnlyDictionary<string, object?> claims,
        DateTimeOffset now,
        TimeSpan clockSkew)
    {
        return ReadDate(claims, WellKnownJwtClaimNames.Iat, out var issuedAt) switch
        {
            ClaimDateReading.Absent => false,
            ClaimDateReading.Read => issuedAt!.CompareToLaterBy(now, clockSkew) > 0,
            _ => true
        };
    }

    /// <summary>
    /// Whether the window from <c>nbf</c>, or <c>iat</c> where no <c>nbf</c> is present, to <c>exp</c> is longer than the maximum,
    /// judged exactly: a window longer by any part of a tick exceeds it.
    /// </summary>
    /// <param name="claims">The claims set.</param>
    /// <param name="maximum">The longest window admitted.</param>
    /// <returns><see langword="true"/> when the window exceeds the maximum or a date bounding it is present as no NumericDate.</returns>
    private static bool LifetimeExceedsCore(
        IReadOnlyDictionary<string, object?> claims,
        TimeSpan maximum)
    {
        var expiryReading = ReadDate(claims, WellKnownJwtClaimNames.Exp, out var expiry);

        if(expiryReading == ClaimDateReading.Absent)
        {
            return false;
        }

        //Prefer nbf over iat as the validity window start.
        var startReading = ReadDate(claims, WellKnownJwtClaimNames.Nbf, out var start);

        if(startReading == ClaimDateReading.Absent)
        {
            startReading = ReadDate(claims, WellKnownJwtClaimNames.Iat, out start);
        }

        if(startReading == ClaimDateReading.Absent)
        {
            return false;
        }

        return expiryReading != ClaimDateReading.Read
            || startReading != ClaimDateReading.Read
            || expiry!.IsMoreThanAfter(start!, maximum);
    }

    /// <summary>Whether <c>exp</c> lies at or before <c>nbf</c>, a window that never opens, judged exactly.</summary>
    /// <param name="claims">The claims set.</param>
    /// <returns><see langword="true"/> when the window never opens or either date is present as no NumericDate.</returns>
    private static bool IsExpBeforeNbfCore(IReadOnlyDictionary<string, object?> claims)
    {
        var expiryReading = ReadDate(claims, WellKnownJwtClaimNames.Exp, out var expiry);
        var notBeforeReading = ReadDate(claims, WellKnownJwtClaimNames.Nbf, out var notBefore);

        if(expiryReading == ClaimDateReading.Absent || notBeforeReading == ClaimDateReading.Absent)
        {
            return false;
        }

        return expiryReading != ClaimDateReading.Read
            || notBeforeReading != ClaimDateReading.Read
            || expiry!.CompareTo(notBefore!) <= 0;
    }

    /// <summary>
    /// Reads a NumericDate claim as the date it names, every digit kept (RFC 7519 Section 2; <see cref="NumericDate.Of"/>), so
    /// each bound is judged against the date written.
    /// </summary>
    /// <param name="claims">The claims set.</param>
    /// <param name="key">The NumericDate claim to read.</param>
    /// <param name="date">The date the claim names when it is <see cref="ClaimDateReading.Read"/>.</param>
    /// <returns>Whether the claim is absent, names a date, or is present as no NumericDate.</returns>
    private static ClaimDateReading ReadDate(
        IReadOnlyDictionary<string, object?> claims,
        string key,
        out NumericDate? date)
    {
        date = null;

        if(!claims.TryGetValue(key, out var value))
        {
            return ClaimDateReading.Absent;
        }

        date = NumericDate.Of(value);

        return date is null ? ClaimDateReading.Unreadable : ClaimDateReading.Read;
    }

    /// <summary>What reading a NumericDate claim found.</summary>
    private enum ClaimDateReading
    {
        /// <summary>The claim is not present: it sets no bound, and the check it would bound does not fail.</summary>
        Absent,

        /// <summary>The claim names a date, which the check judges.</summary>
        Read,

        /// <summary>The claim is present as no NumericDate - a string of digits among them - so it is a bound that cannot be kept, and the check it bounds fails.</summary>
        Unreadable
    }
}
