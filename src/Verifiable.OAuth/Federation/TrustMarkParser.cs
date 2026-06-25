using System.Diagnostics;
using Verifiable.JCose;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Classifies a parsed JWT header + payload pair as a
/// <see cref="TrustMark"/> per OpenID Federation 1.0 §7.1's structural
/// rules.
/// </summary>
/// <remarks>
/// <para>
/// Mirrors <see cref="EntityStatementParser"/> in structure. Layered above
/// JCose's JWS parsing surface: the caller is expected to have already
/// invoked <see cref="JwsParsing.ParseCompact"/> (or a JSON-serialised
/// equivalent) and deserialised the payload bytes into an
/// <see cref="UnverifiedJwtPayload"/>. This parser inspects trust-mark-
/// specific structural prerequisites only.
/// </para>
/// <para>
/// Signature verification, issuer-authorisation against the chain's
/// <c>trust_mark_issuers</c> claim, and delegation-chain validation are
/// the <see cref="TrustMarkValidator"/>'s responsibilities.
/// </para>
/// </remarks>
[DebuggerDisplay("TrustMarkParser")]
public static class TrustMarkParser
{
    /// <summary>
    /// Classifies the given header + payload as a <see cref="TrustMark"/>,
    /// or reports a structural failure via
    /// <see cref="TrustMarkParseResult.Invalid"/>.
    /// </summary>
    public static TrustMarkParseResult Parse(
        UnverifiedJwtHeader header,
        UnverifiedJwtPayload payload)
    {
        ArgumentNullException.ThrowIfNull(header);
        ArgumentNullException.ThrowIfNull(payload);

        //RFC 8725 §3.11 explicit typing — trust marks carry typ=trust-mark+jwt.
        if(!header.TryGetValue(WellKnownJoseHeaderNames.Typ, out object? typObj)
            || typObj is not string typ
            || !string.Equals(typ, WellKnownFederationMediaTypes.TrustMarkJwt, StringComparison.Ordinal))
        {
            return TrustMarkParseResult.Invalid(
                $"JWT 'typ' header must equal '{WellKnownFederationMediaTypes.TrustMarkJwt}' per RFC 8725 §3.11.");
        }

        if(!payload.TryGetValue(WellKnownJwtClaimNames.Iss, out object? issObj)
            || issObj is not string issValue
            || string.IsNullOrWhiteSpace(issValue))
        {
            return TrustMarkParseResult.Invalid("Trust mark payload is missing the required 'iss' claim.");
        }

        if(!payload.TryGetValue(WellKnownJwtClaimNames.Sub, out object? subObj)
            || subObj is not string subValue
            || string.IsNullOrWhiteSpace(subValue))
        {
            return TrustMarkParseResult.Invalid("Trust mark payload is missing the required 'sub' claim.");
        }

        if(!payload.TryGetValue(WellKnownFederationClaimNames.TrustMarkType, out object? typeObj)
            || typeObj is not string typeValue
            || string.IsNullOrWhiteSpace(typeValue))
        {
            return TrustMarkParseResult.Invalid("Trust mark payload is missing the required 'trust_mark_type' claim.");
        }

        if(!TryReadUnixTime(payload, WellKnownJwtClaimNames.Iat, out DateTimeOffset iat))
        {
            return TrustMarkParseResult.Invalid("Trust mark payload is missing or malformed for the required 'iat' claim.");
        }

        DateTimeOffset? exp = null;
        if(payload.ContainsKey(WellKnownJwtClaimNames.Exp))
        {
            if(!TryReadUnixTime(payload, WellKnownJwtClaimNames.Exp, out DateTimeOffset expValue))
            {
                return TrustMarkParseResult.Invalid("Trust mark payload's 'exp' claim is malformed.");
            }
            exp = expValue;
        }

        EntityIdentifier issuer;
        EntityIdentifier subject;
        try
        {
            issuer = new EntityIdentifier(issValue);
            subject = new EntityIdentifier(subValue);
        }
        catch(ArgumentException ex)
        {
            return TrustMarkParseResult.Invalid(
                $"Trust mark iss/sub is not an absolute URL: {ex.Message}");
        }

        return TrustMarkParseResult.Parsed(new TrustMark
        {
            Issuer = issuer,
            Subject = subject,
            IssuedAt = iat,
            ExpiresAt = exp,
            MarkId = typeValue,
            Payload = payload,
        });
    }


    //Same NumericDate parser shape as EntityStatementParser; intentionally
    //duplicated to keep the two parsers independent.
    private static bool TryReadUnixTime(
        UnverifiedJwtPayload payload, string claimName, out DateTimeOffset value)
    {
        value = default;
        if(!payload.TryGetValue(claimName, out object? raw))
        {
            return false;
        }

        if(!EntityStatementParser.TryReadIntegralSeconds(raw, out long seconds))
        {
            return false;
        }

        value = DateTimeOffset.FromUnixTimeSeconds(seconds);
        return true;
    }
}
