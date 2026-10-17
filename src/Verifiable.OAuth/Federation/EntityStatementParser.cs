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
/// <see cref="JwsParsing.ParseCompact(string, Verifiable.Cryptography.DecodeDelegate, Func{ReadOnlySpan{byte}, IReadOnlyDictionary{string, object}}, Lumoin.Base.BaseMemoryPool)"/>
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
            || !WellKnownFederationMediaTypes.IsEntityStatementJwt(typ))
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


    /// <summary>
    /// Reads a NumericDate claim of a federation statement (RFC 7519 Section 2: a JSON number of seconds since the epoch, which
    /// may carry a fraction) as the instant it names, the fraction kept to the tick by the library's one reading of the type
    /// (<see cref="JwtNumericDates.InstantOf"/>), so the statement's window is judged as its issuer wrote it. A value that is
    /// no NumericDate, or one naming an instant no clock represents, is unreadable. The trust mark and trust mark delegation
    /// parsers read their dates by it too.
    /// </summary>
    /// <param name="payload">The statement's claims.</param>
    /// <param name="claimName">The NumericDate claim to read.</param>
    /// <param name="value">The instant the claim names, when present and readable.</param>
    /// <returns><see langword="true"/> when the claim is present and names an instant.</returns>
    internal static bool TryReadUnixTime(
        UnverifiedJwtPayload payload, string claimName, out DateTimeOffset value)
    {
        value = default;
        if(!payload.TryGetValue(claimName, out object? raw) || JwtNumericDates.InstantOf(claimName, raw) is not DateTimeOffset instant)
        {
            return false;
        }

        value = instant;
        return true;
    }
}
