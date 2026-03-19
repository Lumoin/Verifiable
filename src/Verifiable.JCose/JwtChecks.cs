using System;
using System.Collections.Generic;
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

    private static bool IsAlgNoneCore(IReadOnlyDictionary<string, object> header)
    {
        if(!header.TryGetValue(JwkProperties.Alg, out object? value) || value is not string alg)
        {
            return true;
        }

        return WellKnownJwaValues.IsNone(alg);
    }

    private static bool HasValidAlgCore(IReadOnlyDictionary<string, object> header)
    {
        return header.TryGetValue(JwkProperties.Alg, out object? value)
            && value is string alg
            && !string.IsNullOrEmpty(alg)
            && !WellKnownJwaValues.IsNone(alg);
    }

    private static bool HasKtyCore(IReadOnlyDictionary<string, object> header)
    {
        return header.TryGetValue(JwkProperties.Kty, out object? value)
            && value is string kty
            && !string.IsNullOrEmpty(kty);
    }

    private static bool HasRequiredEcFieldsCore(IReadOnlyDictionary<string, object> header)
    {
        return header.TryGetValue(JwkProperties.Crv, out object? crv)
            && crv is string crvStr && !string.IsNullOrEmpty(crvStr)
            && header.TryGetValue(JwkProperties.X, out object? x)
            && x is string xStr && !string.IsNullOrEmpty(xStr)
            && header.TryGetValue(JwkProperties.Y, out object? y)
            && y is string yStr && !string.IsNullOrEmpty(yStr);
    }

    private static bool IsValidEcAlgCrvCombinationCore(IReadOnlyDictionary<string, object> header)
    {
        if(!header.TryGetValue(JwkProperties.Crv, out object? crvValue) || crvValue is not string crv)
        {
            return false;
        }

        if(!header.TryGetValue(JwkProperties.Alg, out object? algValue) || algValue is not string alg)
        {
            return false;
        }

        return (WellKnownJwaValues.IsEs256(alg) && WellKnownCurveValues.IsP256(crv))
            || (WellKnownJwaValues.IsEs384(alg) && WellKnownCurveValues.IsP384(crv))
            || (WellKnownJwaValues.IsEs512(alg) && WellKnownCurveValues.IsP521(crv))
            || (WellKnownJwaValues.IsEs256k1(alg) && WellKnownCurveValues.IsSecp256k1(crv));
    }

    private static bool HasRequiredOkpFieldsCore(IReadOnlyDictionary<string, object> header)
    {
        return header.TryGetValue(JwkProperties.Crv, out object? crv)
            && crv is string crvStr
            && !string.IsNullOrEmpty(crvStr);
    }

    private static bool IsValidOkpAlgCrvCombinationCore(IReadOnlyDictionary<string, object> header)
    {
        if(!header.TryGetValue(JwkProperties.Crv, out object? crvValue) || crvValue is not string crv)
        {
            return false;
        }

        //X25519 is a key agreement curve — alg must not be present.
        if(WellKnownCurveValues.IsX25519(crv))
        {
            return !header.ContainsKey(JwkProperties.Alg);
        }

        //Ed25519 requires alg=EdDSA.
        if(WellKnownCurveValues.IsEd25519(crv))
        {
            return header.TryGetValue(JwkProperties.Alg, out object? algValue)
                && algValue is string alg
                && WellKnownJwaValues.IsEdDsa(alg);
        }

        return false;
    }

    private static bool HasValidRsaFieldsCore(IReadOnlyDictionary<string, object> header)
    {
        //RSA-2048: 256 bytes → Base64Url length ≈ 342 characters.
        //RSA-4096: 512 bytes → Base64Url length ≈ 683 characters.
        const int Rsa2048ModulusBase64UrlLength = 342;
        const int Rsa4096ModulusBase64UrlLength = 683;

        if(!header.TryGetValue(JwkProperties.E, out object? eValue)
            || eValue is not string e
            || string.IsNullOrEmpty(e))
        {
            return false;
        }

        if(!header.TryGetValue(JwkProperties.N, out object? nValue)
            || nValue is not string n
            || string.IsNullOrEmpty(n))
        {
            return false;
        }

        return n.Length == Rsa2048ModulusBase64UrlLength
            || n.Length == Rsa4096ModulusBase64UrlLength;
    }

    private static bool IsExpiredCore(
        IReadOnlyDictionary<string, object> claims,
        DateTimeOffset now,
        TimeSpan clockSkew)
    {
        if(!TryGetUnixTime(claims, JwkProperties.Exp, out long expSeconds))
        {
            return false;
        }

        return now > DateTimeOffset.FromUnixTimeSeconds(expSeconds) + clockSkew;
    }

    private static bool IsNotYetValidCore(
        IReadOnlyDictionary<string, object> claims,
        DateTimeOffset now,
        TimeSpan clockSkew)
    {
        if(!TryGetUnixTime(claims, JwkProperties.Nbf, out long nbfSeconds))
        {
            return false;
        }

        return now < DateTimeOffset.FromUnixTimeSeconds(nbfSeconds) - clockSkew;
    }

    private static bool IsIssuedInFutureCore(
        IReadOnlyDictionary<string, object> claims,
        DateTimeOffset now,
        TimeSpan clockSkew)
    {
        if(!TryGetUnixTime(claims, JwkProperties.Iat, out long iatSeconds))
        {
            return false;
        }

        return DateTimeOffset.FromUnixTimeSeconds(iatSeconds) > now + clockSkew;
    }

    private static bool LifetimeExceedsCore(
        IReadOnlyDictionary<string, object> claims,
        TimeSpan maximum)
    {
        if(!TryGetUnixTime(claims, JwkProperties.Exp, out long expSeconds))
        {
            return false;
        }

        //Prefer nbf over iat as the validity window start.
        if(!TryGetUnixTime(claims, JwkProperties.Nbf, out long startSeconds)
            && !TryGetUnixTime(claims, JwkProperties.Iat, out startSeconds))
        {
            return false;
        }

        return TimeSpan.FromSeconds(expSeconds - startSeconds) > maximum;
    }

    private static bool IsExpBeforeNbfCore(IReadOnlyDictionary<string, object> claims)
    {
        if(!TryGetUnixTime(claims, JwkProperties.Exp, out long expSeconds)
            || !TryGetUnixTime(claims, JwkProperties.Nbf, out long nbfSeconds))
        {
            return false;
        }

        return expSeconds <= nbfSeconds;
    }

    private static bool TryGetUnixTime(
        IReadOnlyDictionary<string, object> claims,
        string key,
        out long seconds)
    {
        seconds = 0;
        if(!claims.TryGetValue(key, out object? value))
        {
            return false;
        }

        return value switch
        {
            long l => (seconds = l) >= 0,
            int i => (seconds = i) >= 0,
            double d => (seconds = (long)d) >= 0,
            string s => long.TryParse(s, out seconds),
            _ => false
        };
    }
}