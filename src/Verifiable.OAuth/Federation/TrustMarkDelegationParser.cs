using System.Diagnostics;
using Verifiable.JCose;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Classifies a parsed JWT header + payload pair as a
/// <see cref="TrustMarkDelegation"/> per OpenID Federation 1.0 §7.2.2's
/// structural rules.
/// </summary>
[DebuggerDisplay("TrustMarkDelegationParser")]
public static class TrustMarkDelegationParser
{
    /// <summary>
    /// Classifies the given header + payload as a
    /// <see cref="TrustMarkDelegation"/>, or reports structural failure.
    /// </summary>
    public static TrustMarkDelegationParseResult Parse(
        UnverifiedJwtHeader header,
        UnverifiedJwtPayload payload)
    {
        ArgumentNullException.ThrowIfNull(header);
        ArgumentNullException.ThrowIfNull(payload);

        if(!header.TryGetValue(WellKnownJoseHeaderNames.Typ, out object? typObj)
            || typObj is not string typ
            || !string.Equals(typ, WellKnownFederationMediaTypes.TrustMarkDelegationJwt, StringComparison.Ordinal))
        {
            return TrustMarkDelegationParseResult.Invalid(
                $"Delegation 'typ' header must equal '{WellKnownFederationMediaTypes.TrustMarkDelegationJwt}' per RFC 8725 §3.11.");
        }

        if(!payload.TryGetValue(WellKnownJwtClaimNames.Iss, out object? issObj)
            || issObj is not string issValue
            || string.IsNullOrWhiteSpace(issValue))
        {
            return TrustMarkDelegationParseResult.Invalid("Delegation payload is missing the required 'iss' claim.");
        }

        if(!payload.TryGetValue(WellKnownJwtClaimNames.Sub, out object? subObj)
            || subObj is not string subValue
            || string.IsNullOrWhiteSpace(subValue))
        {
            return TrustMarkDelegationParseResult.Invalid("Delegation payload is missing the required 'sub' claim.");
        }

        if(!payload.TryGetValue(WellKnownFederationClaimNames.TrustMarkType, out object? idObj)
            || idObj is not string idValue
            || string.IsNullOrWhiteSpace(idValue))
        {
            return TrustMarkDelegationParseResult.Invalid("Delegation payload is missing the required 'id' claim.");
        }

        if(!TryReadUnixTime(payload, WellKnownJwtClaimNames.Iat, out DateTimeOffset iat))
        {
            return TrustMarkDelegationParseResult.Invalid("Delegation 'iat' claim missing or malformed.");
        }

        DateTimeOffset? exp = null;
        if(payload.ContainsKey(WellKnownJwtClaimNames.Exp))
        {
            if(!TryReadUnixTime(payload, WellKnownJwtClaimNames.Exp, out DateTimeOffset expValue))
            {
                return TrustMarkDelegationParseResult.Invalid("Delegation 'exp' claim malformed.");
            }
            exp = expValue;
        }

        EntityIdentifier owner;
        EntityIdentifier issuer;
        try
        {
            owner = new EntityIdentifier(issValue);
            issuer = new EntityIdentifier(subValue);
        }
        catch(ArgumentException ex)
        {
            return TrustMarkDelegationParseResult.Invalid(
                $"Delegation iss/sub is not an absolute URL: {ex.Message}");
        }

        return TrustMarkDelegationParseResult.Parsed(new TrustMarkDelegation
        {
            Owner = owner,
            Issuer = issuer,
            IssuedAt = iat,
            ExpiresAt = exp,
            MarkId = idValue,
            Payload = payload,
        });
    }


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
