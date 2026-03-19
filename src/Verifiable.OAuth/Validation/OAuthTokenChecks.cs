using System;
using System.Collections.Generic;
using Verifiable.Core.Assessment;
using Verifiable.JCose;
using Verifiable.OAuth;

namespace Verifiable.OAuth.Validation;

/// <summary>
/// Static functions for validating JWT registered claims and token endpoint response
/// fields against the requirements of RFC 7519, RFC 9700, OIDC Core 1.0, and
/// FAPI 2.0 / HAIP 1.0.
/// </summary>
/// <remarks>
/// <para>
/// Each function appends one or more <see cref="Claim"/> instances to the supplied
/// <paramref name="claims"/> list. The caller assembles the list and decides how to
/// act on failures — typically by checking for any claim whose
/// <see cref="ClaimOutcome"/> is not <see cref="ClaimOutcome.Success"/>.
/// </para>
/// <para>
/// Functions accepting clock skew use it symmetrically:
/// expiry is extended by skew, not-before is reduced by skew. A value of
/// <see cref="TimeSpan.Zero"/> enforces exact comparison.
/// </para>
/// </remarks>
public static class OAuthTokenChecks
{
    //Issuer checks.

    /// <summary>
    /// Checks that the <c>iss</c> claim is present and non-empty.
    /// </summary>
    public static void CheckIssPresent(
        IReadOnlyDictionary<string, object> claims,
        List<Claim> results)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(results);

        ClaimOutcome outcome = claims.TryGetValue(WellKnownJwtClaims.Iss, out object? iss)
            && iss is string issStr
            && !string.IsNullOrEmpty(issStr)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        results.Add(new Claim(OAuthTokenClaimIds.IssPresent, outcome));
    }


    /// <summary>
    /// Checks that the <c>iss</c> value exactly matches <paramref name="expectedIssuer"/>.
    /// Exact string comparison is required per RFC 8414 §3.3 and RFC 9700 §4.4.
    /// </summary>
    public static void CheckIssMatchesExpected(
        IReadOnlyDictionary<string, object> claims,
        string expectedIssuer,
        List<Claim> results)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(expectedIssuer);
        ArgumentNullException.ThrowIfNull(results);

        bool issPresent = claims.TryGetValue(WellKnownJwtClaims.Iss, out object? iss)
            && iss is string issStr
            && !string.IsNullOrEmpty(issStr);

        ClaimOutcome outcome = issPresent
            && string.Equals((string)iss!, expectedIssuer, StringComparison.Ordinal)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        results.Add(new Claim(OAuthTokenClaimIds.IssMatchesExpected, outcome));
    }


    //Subject check.

    /// <summary>
    /// Checks that the <c>sub</c> claim is present and non-empty.
    /// </summary>
    public static void CheckSubPresent(
        IReadOnlyDictionary<string, object> claims,
        List<Claim> results)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(results);

        ClaimOutcome outcome = claims.TryGetValue(WellKnownJwtClaims.Sub, out object? sub)
            && sub is string subStr
            && !string.IsNullOrEmpty(subStr)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        results.Add(new Claim(OAuthTokenClaimIds.SubPresent, outcome));
    }


    //Audience checks.

    /// <summary>
    /// Checks that the <c>aud</c> claim is present.
    /// The value may be a string or an array per RFC 7519 §4.1.3.
    /// </summary>
    public static void CheckAudPresent(
        IReadOnlyDictionary<string, object> claims,
        List<Claim> results)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(results);

        ClaimOutcome outcome = claims.ContainsKey(WellKnownJwtClaims.Aud)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        results.Add(new Claim(OAuthTokenClaimIds.AudPresent, outcome));
    }


    /// <summary>
    /// Checks that the <c>aud</c> claim contains <paramref name="expectedClientId"/>.
    /// Handles both single-string and array representations per RFC 7519 §4.1.3.
    /// </summary>
    public static void CheckAudContainsClient(
        IReadOnlyDictionary<string, object> claims,
        string expectedClientId,
        List<Claim> results)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(expectedClientId);
        ArgumentNullException.ThrowIfNull(results);

        ClaimOutcome outcome = ClaimOutcome.Failure;
        if(claims.TryGetValue(WellKnownJwtClaims.Aud, out object? aud))
        {
            outcome = aud switch
            {
                string single => string.Equals(single, expectedClientId, StringComparison.Ordinal)
                    ? ClaimOutcome.Success
                    : ClaimOutcome.Failure,
                IEnumerable<object> array => ContainsClientId(array, expectedClientId)
                    ? ClaimOutcome.Success
                    : ClaimOutcome.Failure,
                _ => ClaimOutcome.Failure
            };
        }

        results.Add(new Claim(OAuthTokenClaimIds.AudContainsExpectedClient, outcome));
    }


    //Expiry and time-bound checks.

    /// <summary>
    /// Checks that the <c>exp</c> claim is present.
    /// </summary>
    public static void CheckExpPresent(
        IReadOnlyDictionary<string, object> claims,
        List<Claim> results)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(results);

        ClaimOutcome outcome = claims.ContainsKey(WellKnownJwtClaims.Exp)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        results.Add(new Claim(OAuthTokenClaimIds.ExpPresent, outcome));
    }


    /// <summary>
    /// Checks that the token has not expired. The <c>exp</c> value is interpreted
    /// as a Unix timestamp (seconds since epoch).
    /// </summary>
    /// <param name="claims">The JWT claims.</param>
    /// <param name="now">The current UTC time.</param>
    /// <param name="clockSkew">
    /// Permitted clock skew. The token is accepted if
    /// <c>now ≤ exp + clockSkew</c>. Use <see cref="TimeSpan.Zero"/> for strict
    /// comparison.
    /// </param>
    /// <param name="results">The list to append the claim to.</param>
    public static void CheckTokenNotExpired(
        IReadOnlyDictionary<string, object> claims,
        DateTimeOffset now,
        TimeSpan clockSkew,
        List<Claim> results)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(results);

        ClaimOutcome outcome = ClaimOutcome.Failure;
        if(claims.TryGetValue(WellKnownJwtClaims.Exp, out object? expValue)
            && TryGetUnixTime(expValue, out long expSeconds))
        {
            DateTimeOffset expiry = DateTimeOffset.FromUnixTimeSeconds(expSeconds);
            outcome = now <= expiry + clockSkew
                ? ClaimOutcome.Success
                : ClaimOutcome.Failure;
        }

        results.Add(new Claim(OAuthTokenClaimIds.TokenNotExpired, outcome));
    }


    /// <summary>
    /// Checks that the <c>nbf</c> claim is present.
    /// </summary>
    public static void CheckNbfPresent(
        IReadOnlyDictionary<string, object> claims,
        List<Claim> results)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(results);

        ClaimOutcome outcome = claims.ContainsKey(WellKnownJwtClaims.Nbf)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        results.Add(new Claim(OAuthTokenClaimIds.NbfPresent, outcome));
    }


    /// <summary>
    /// Checks that the current time is at or after <c>nbf</c>.
    /// </summary>
    public static void CheckTokenNotBeforeValid(
        IReadOnlyDictionary<string, object> claims,
        DateTimeOffset now,
        TimeSpan clockSkew,
        List<Claim> results)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(results);

        ClaimOutcome outcome = ClaimOutcome.Failure;
        if(claims.TryGetValue(WellKnownJwtClaims.Nbf, out object? nbfValue)
            && TryGetUnixTime(nbfValue, out long nbfSeconds))
        {
            DateTimeOffset notBefore = DateTimeOffset.FromUnixTimeSeconds(nbfSeconds);
            outcome = now >= notBefore - clockSkew
                ? ClaimOutcome.Success
                : ClaimOutcome.Failure;
        }

        results.Add(new Claim(OAuthTokenClaimIds.TokenNotBeforeValid, outcome));
    }


    /// <summary>
    /// Checks that the <c>iat</c> claim is present.
    /// </summary>
    public static void CheckIatPresent(
        IReadOnlyDictionary<string, object> claims,
        List<Claim> results)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(results);

        ClaimOutcome outcome = claims.ContainsKey(WellKnownJwtClaims.Iat)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        results.Add(new Claim(OAuthTokenClaimIds.IatPresent, outcome));
    }


    /// <summary>
    /// Checks that the <c>iat</c> value is not beyond <paramref name="clockSkew"/>
    /// in the future. A future-issued token indicates a misconfigured server or
    /// a replay attempt.
    /// </summary>
    public static void CheckIatNotInFuture(
        IReadOnlyDictionary<string, object> claims,
        DateTimeOffset now,
        TimeSpan clockSkew,
        List<Claim> results)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(results);

        ClaimOutcome outcome = ClaimOutcome.Failure;
        if(claims.TryGetValue(WellKnownJwtClaims.Iat, out object? iatValue)
            && TryGetUnixTime(iatValue, out long iatSeconds))
        {
            DateTimeOffset issuedAt = DateTimeOffset.FromUnixTimeSeconds(iatSeconds);
            outcome = issuedAt <= now + clockSkew
                ? ClaimOutcome.Success
                : ClaimOutcome.Failure;
        }

        results.Add(new Claim(OAuthTokenClaimIds.IatNotInFuture, outcome));
    }


    //Replay prevention checks.

    /// <summary>
    /// Checks that the <c>jti</c> claim is present.
    /// </summary>
    public static void CheckJtiPresent(
        IReadOnlyDictionary<string, object> claims,
        List<Claim> results)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(results);

        ClaimOutcome outcome = claims.TryGetValue(WellKnownJwtClaims.Jti, out object? jti)
            && jti is string jtiStr
            && !string.IsNullOrEmpty(jtiStr)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        results.Add(new Claim(OAuthTokenClaimIds.JtiPresent, outcome));
    }


    /// <summary>
    /// Checks that the <c>jti</c> value has not been seen before by consulting
    /// <paramref name="seenJtiValues"/>. The caller is responsible for maintaining
    /// and expiring the cache — typically keyed by <c>jti</c> with a TTL equal to
    /// the token's remaining lifetime.
    /// </summary>
    public static void CheckJtiNotReplayed(
        IReadOnlyDictionary<string, object> claims,
        IReadOnlySet<string> seenJtiValues,
        List<Claim> results)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(seenJtiValues);
        ArgumentNullException.ThrowIfNull(results);

        ClaimOutcome outcome = ClaimOutcome.Failure;
        if(claims.TryGetValue(WellKnownJwtClaims.Jti, out object? jti)
            && jti is string jtiStr
            && !string.IsNullOrEmpty(jtiStr))
        {
            outcome = !seenJtiValues.Contains(jtiStr)
                ? ClaimOutcome.Success
                : ClaimOutcome.Failure;
        }

        results.Add(new Claim(OAuthTokenClaimIds.JtiNotReplayed, outcome));
    }


    //Token lifetime range check.

    /// <summary>
    /// Checks that the difference between <c>exp</c> and <c>nbf</c> (or <c>iat</c>
    /// when <c>nbf</c> is absent) does not exceed <paramref name="maximumLifetime"/>.
    /// FAPI 2.0 / HAIP 1.0 require JAR <c>exp - nbf</c> ≤ 60 seconds.
    /// </summary>
    public static void CheckTokenLifetimeWithinMaximum(
        IReadOnlyDictionary<string, object> claims,
        TimeSpan maximumLifetime,
        List<Claim> results)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(results);

        ClaimOutcome outcome = ClaimOutcome.Failure;
        if(claims.TryGetValue(WellKnownJwtClaims.Exp, out object? expValue)
            && TryGetUnixTime(expValue, out long expSeconds))
        {
            //Prefer nbf over iat as the start of the validity window.
            long startSeconds = expSeconds;
            if(claims.TryGetValue(WellKnownJwtClaims.Nbf, out object? nbfValue)
                && TryGetUnixTime(nbfValue, out long nbfSeconds))
            {
                startSeconds = nbfSeconds;
            }
            else if(claims.TryGetValue(WellKnownJwtClaims.Iat, out object? iatValue)
                && TryGetUnixTime(iatValue, out long iatSeconds))
            {
                startSeconds = iatSeconds;
            }

            TimeSpan lifetime = TimeSpan.FromSeconds(expSeconds - startSeconds);
            outcome = lifetime <= maximumLifetime
                ? ClaimOutcome.Success
                : ClaimOutcome.Failure;
        }

        results.Add(new Claim(OAuthTokenClaimIds.TokenLifetimeWithinMaximum, outcome));
    }


    //Scope checks.

    /// <summary>
    /// Checks that the <c>scope</c> claim or field is present and non-empty.
    /// </summary>
    public static void CheckScopePresent(
        IReadOnlyDictionary<string, object> claims,
        List<Claim> results)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(results);

        ClaimOutcome outcome = claims.TryGetValue(WellKnownJwtClaims.Scope, out object? scope)
            && scope is string scopeStr
            && !string.IsNullOrEmpty(scopeStr)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        results.Add(new Claim(OAuthTokenClaimIds.ScopePresent, outcome));
    }


    /// <summary>
    /// Checks that the <c>scope</c> value contains <c>openid</c>, confirming that
    /// OIDC authentication was requested.
    /// </summary>
    public static void CheckScopeContainsOpenId(
        IReadOnlyDictionary<string, object> claims,
        List<Claim> results)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(results);

        ClaimOutcome outcome = claims.TryGetValue(WellKnownJwtClaims.Scope, out object? scope)
            && scope is string scopeStr
            && WellKnownScopes.ContainsOpenId(scopeStr)
            ? ClaimOutcome.Success
            : ClaimOutcome.Failure;

        results.Add(new Claim(OAuthTokenClaimIds.ScopeContainsOpenId, outcome));
    }


    /// <summary>
    /// Checks that the granted <c>scope</c> does not include values beyond those
    /// in <paramref name="requestedScope"/>. An authorization server must not expand
    /// scope beyond what was requested per RFC 6749 §3.3.
    /// </summary>
    public static void CheckScopeDoesNotExceedRequested(
        IReadOnlyDictionary<string, object> claims,
        string requestedScope,
        List<Claim> results)
    {
        ArgumentNullException.ThrowIfNull(claims);
        ArgumentNullException.ThrowIfNull(requestedScope);
        ArgumentNullException.ThrowIfNull(results);

        ClaimOutcome outcome = ClaimOutcome.Failure;
        if(claims.TryGetValue(WellKnownJwtClaims.Scope, out object? scope)
            && scope is string grantedScope)
        {
            outcome = ScopeIsSubset(grantedScope, requestedScope)
                ? ClaimOutcome.Success
                : ClaimOutcome.Failure;
        }

        results.Add(new Claim(OAuthTokenClaimIds.ScopeDoesNotExceedRequested, outcome));
    }


    //Private helpers.

    private static bool TryGetUnixTime(object value, out long seconds)
    {
        seconds = 0;
        return value switch
        {
            long l => (seconds = l) >= 0,
            int i => (seconds = i) >= 0,
            double d => (seconds = (long)d) >= 0,
            string s => long.TryParse(s, out seconds),
            _ => false
        };
    }

    private static bool ContainsClientId(IEnumerable<object> array, string clientId)
    {
        foreach(object item in array)
        {
            if(item is string s && string.Equals(s, clientId, StringComparison.Ordinal))
            {
                return true;
            }
        }
        return false;
    }

    private static bool ScopeIsSubset(string grantedScope, string requestedScope)
    {
        ReadOnlySpan<char> granted = grantedScope.AsSpan();
        while(!granted.IsEmpty)
        {
            int space = granted.IndexOf(' ');
            ReadOnlySpan<char> token = space < 0 ? granted : granted[..space];

            if(!string.IsNullOrEmpty(token.ToString())
                && !WellKnownScopes.ContainsScopeValue(requestedScope, token.ToString()))
            {
                return false;
            }

            granted = space < 0 ? [] : granted[(space + 1)..];
        }
        return true;
    }
}