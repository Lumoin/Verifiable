using System.Diagnostics;
using Verifiable.JCose;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Classifies a parsed JWT header + payload pair as an
/// <see cref="EntityConfiguration"/> or <see cref="SubordinateStatement"/>
/// per the OpenID Federation 1.0 structural rules.
/// </summary>
/// <remarks>
/// <para>
/// Layered above JCose's JWS parsing surface. The caller is expected to
/// have already invoked
/// <see cref="JwsParsing.ParseCompact(string, DecodeDelegate, Func{ReadOnlySpan{byte}, IReadOnlyDictionary{string, object}}, System.Buffers.MemoryPool{byte})"/>
/// (or the JSON-serialised variants) and deserialised the payload bytes
/// into an <see cref="UnverifiedJwtPayload"/>. This parser inspects
/// federation-specific structural prerequisites only: the <c>typ</c>
/// header, the <c>iss</c>/<c>sub</c> relationship, and the presence of
/// <c>iat</c>/<c>exp</c>.
/// </para>
/// <para>
/// Signature verification is the responsibility of
/// <see cref="EntityStatementValidator"/>; this parser
/// produces a structural classification only, and the
/// <see cref="EntityStatement.Payload"/> on a successful
/// <see cref="EntityStatementParseResult.Parsed"/> result is the
/// unverified payload — every claim remains attacker-controlled until
/// validation runs.
/// </para>
/// </remarks>
[DebuggerDisplay("EntityStatementParser")]
public static class EntityStatementParser
{
    /// <summary>
    /// Classifies the given header + payload as an
    /// <see cref="EntityConfiguration"/> or
    /// <see cref="SubordinateStatement"/>, or reports a structural
    /// failure via <see cref="EntityStatementParseResult.Invalid"/>.
    /// </summary>
    public static EntityStatementParseResult Parse(
        UnverifiedJwtHeader header,
        UnverifiedJwtPayload payload)
    {
        ArgumentNullException.ThrowIfNull(header);
        ArgumentNullException.ThrowIfNull(payload);

        //RFC 8725 §3.11 explicit typing. Federation entity statements
        //carry typ=entity-statement+jwt; anything else is either a
        //different artefact (trust mark JWT, OAuth access token, ID
        //token) or a deliberately mistyped attempt at cross-JWT
        //confusion.
        if(!header.TryGetValue(WellKnownJoseHeaderNames.Typ, out object? typObj)
            || typObj is not string typ
            || !string.Equals(typ, WellKnownFederationMediaTypes.EntityStatementJwt, StringComparison.Ordinal))
        {
            return EntityStatementParseResult.Invalid(
                $"JWT 'typ' header must equal '{WellKnownFederationMediaTypes.EntityStatementJwt}' per RFC 8725 §3.11.");
        }

        if(!payload.TryGetValue(WellKnownJwtClaimNames.Iss, out object? issObj)
            || issObj is not string issValue
            || string.IsNullOrWhiteSpace(issValue))
        {
            return EntityStatementParseResult.Invalid(
                "Payload is missing the required 'iss' claim.");
        }

        if(!payload.TryGetValue(WellKnownJwtClaimNames.Sub, out object? subObj)
            || subObj is not string subValue
            || string.IsNullOrWhiteSpace(subValue))
        {
            return EntityStatementParseResult.Invalid(
                "Payload is missing the required 'sub' claim.");
        }

        if(!TryReadUnixTime(payload, WellKnownJwtClaimNames.Iat, out DateTimeOffset iat))
        {
            return EntityStatementParseResult.Invalid(
                "Payload is missing or malformed for the required 'iat' claim.");
        }

        if(!TryReadUnixTime(payload, WellKnownJwtClaimNames.Exp, out DateTimeOffset exp))
        {
            return EntityStatementParseResult.Invalid(
                "Payload is missing or malformed for the required 'exp' claim.");
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
            return EntityStatementParseResult.Invalid(
                $"Entity Identifier claim is not an absolute URL: {ex.Message}");
        }

        EntityStatement statement = string.Equals(issValue, subValue, StringComparison.Ordinal)
            ? new EntityConfiguration
            {
                Issuer = issuer,
                Subject = subject,
                IssuedAt = iat,
                ExpiresAt = exp,
                Payload = payload
            }
            : new SubordinateStatement
            {
                Issuer = issuer,
                Subject = subject,
                IssuedAt = iat,
                ExpiresAt = exp,
                Payload = payload
            };

        return EntityStatementParseResult.Parsed(statement);
    }


    //Unix-seconds claim parsing. JWT RFC 7519 §4.1.4 says iat/exp are
    //NumericDate (seconds since epoch); JSON parsers typically surface
    //these as long or int. JCose's serializer follows the same
    //convention. Accept both for robustness.
    private static bool TryReadUnixTime(
        UnverifiedJwtPayload payload, string claimName, out DateTimeOffset value)
    {
        value = default;
        if(!payload.TryGetValue(claimName, out object? raw))
        {
            return false;
        }

        if(!TryReadIntegralSeconds(raw, out long seconds))
        {
            return false;
        }

        value = DateTimeOffset.FromUnixTimeSeconds(seconds);
        return true;
    }


    //RFC 7519 §2 NumericDate is "a JSON numeric value representing the
    //number of seconds from 1970-01-01T00:00:00Z UTC". The JSON wire shape
    //is any numeric; the boxed type after deserialization depends on the
    //resolver (long via DictionaryStringObjectJsonConverter; Decimal via
    //source-gen default for object-typed properties; double via permissive
    //handlers). Accept any integer-valued numeric.
    internal static bool TryReadIntegralSeconds(object raw, out long seconds)
    {
        switch(raw)
        {
            case long l:
                seconds = l;
                return true;
            case int i:
                seconds = i;
                return true;
            case decimal d when d == decimal.Truncate(d) && d >= long.MinValue && d <= long.MaxValue:
                seconds = (long)d;
                return true;
            case double dbl when !double.IsNaN(dbl) && !double.IsInfinity(dbl)
                && dbl == Math.Truncate(dbl)
                && dbl >= long.MinValue && dbl <= long.MaxValue:
                seconds = (long)dbl;
                return true;
            default:
                seconds = 0;
                return false;
        }
    }
}
