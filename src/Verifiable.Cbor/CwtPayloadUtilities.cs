using System.Formats.Cbor;
using Verifiable.JCose;

namespace Verifiable.Cbor;

/// <summary>
/// Delegate for building a CWT payload from credential data.
/// </summary>
/// <param name="issuer">The issuer identifier.</param>
/// <param name="subject">The subject identifier.</param>
/// <param name="issuedAt">The issued-at timestamp as Unix epoch seconds.</param>
/// <param name="expiration">Optional expiration timestamp as Unix epoch seconds.</param>
/// <param name="additionalClaims">Optional additional claims to include.</param>
/// <returns>The CBOR-encoded CWT payload bytes.</returns>
public delegate byte[] CwtPayloadDelegate(
    string issuer,
    string? subject,
    long issuedAt,
    long? expiration = null,
    IReadOnlyDictionary<int, object>? additionalClaims = null);


/// <summary>
/// Utilities for building CWT (CBOR Web Token) payloads.
/// </summary>
/// <remarks>
/// <para>
/// CWT claims use integer keys as defined in RFC 8392. These utilities provide
/// convenient methods for constructing CWT payloads with standard claims.
/// </para>
/// <para>
/// <strong>Standard CWT Claims</strong>
/// </para>
/// <list type="bullet">
/// <item><description><c>iss</c> (1): Issuer</description></item>
/// <item><description><c>sub</c> (2): Subject</description></item>
/// <item><description><c>aud</c> (3): Audience</description></item>
/// <item><description><c>exp</c> (4): Expiration Time</description></item>
/// <item><description><c>nbf</c> (5): Not Before</description></item>
/// <item><description><c>iat</c> (6): Issued At</description></item>
/// <item><description><c>cti</c> (7): CWT ID</description></item>
/// </list>
/// <para>
/// See <see href="https://www.rfc-editor.org/rfc/rfc8392">RFC 8392 - CBOR Web Token (CWT)</see>.
/// </para>
/// </remarks>
public static class CwtPayloadUtilities
{
    /// <summary>
    /// Builds a CWT payload with the specified claims.
    /// </summary>
    /// <param name="issuer">The issuer identifier (claim key 1).</param>
    /// <param name="subject">Optional subject identifier (claim key 2).</param>
    /// <param name="issuedAt">The issued-at timestamp as Unix epoch seconds (claim key 6).</param>
    /// <param name="expiration">Optional expiration timestamp as Unix epoch seconds (claim key 4).</param>
    /// <param name="notBefore">Optional not-before timestamp as Unix epoch seconds (claim key 5).</param>
    /// <param name="audience">Optional audience (claim key 3).</param>
    /// <param name="cwtId">Optional CWT ID (claim key 7).</param>
    /// <param name="additionalClaims">Optional additional claims with integer keys.</param>
    /// <param name="conformanceMode">CBOR conformance mode for deterministic encoding.</param>
    /// <returns>The CBOR-encoded CWT payload bytes.</returns>
    public static byte[] Build(
        string issuer,
        string? subject = null,
        long? issuedAt = null,
        long? expiration = null,
        long? notBefore = null,
        string? audience = null,
        byte[]? cwtId = null,
        IReadOnlyDictionary<int, object>? additionalClaims = null,
        CborConformanceMode conformanceMode = CborConformanceMode.Canonical)
    {
        ArgumentException.ThrowIfNullOrEmpty(issuer);

        //Calculate map size.
        int mapSize = 1; //iss is required.
        if(subject is not null)
        {
            mapSize++;
        }

        if(audience is not null)
        {
            mapSize++;
        }

        if(expiration.HasValue)
        {
            mapSize++;
        }

        if(notBefore.HasValue)
        {
            mapSize++;
        }

        if(issuedAt.HasValue)
        {
            mapSize++;
        }

        if(cwtId is not null)
        {
            mapSize++;
        }

        if(additionalClaims is not null)
        {
            mapSize += additionalClaims.Count;
        }

        var writer = new CborWriter(conformanceMode);
        writer.WriteStartMap(mapSize);

        //Write standard claims in numeric order for canonical encoding.
        //iss (1).
        writer.WriteInt32(WellKnownCwtClaims.Iss);
        writer.WriteTextString(issuer);

        //sub (2).
        if(subject is not null)
        {
            writer.WriteInt32(WellKnownCwtClaims.Sub);
            writer.WriteTextString(subject);
        }

        //aud (3).
        if(audience is not null)
        {
            writer.WriteInt32(WellKnownCwtClaims.Aud);
            writer.WriteTextString(audience);
        }

        //exp (4).
        if(expiration.HasValue)
        {
            writer.WriteInt32(WellKnownCwtClaims.Exp);
            writer.WriteInt64(expiration.Value);
        }

        //nbf (5).
        if(notBefore.HasValue)
        {
            writer.WriteInt32(WellKnownCwtClaims.Nbf);
            writer.WriteInt64(notBefore.Value);
        }

        //iat (6).
        if(issuedAt.HasValue)
        {
            writer.WriteInt32(WellKnownCwtClaims.Iat);
            writer.WriteInt64(issuedAt.Value);
        }

        //cti (7).
        if(cwtId is not null)
        {
            writer.WriteInt32(WellKnownCwtClaims.Cti);
            writer.WriteByteString(cwtId);
        }

        //Additional claims.
        if(additionalClaims is not null)
        {
            foreach(var (key, value) in additionalClaims)
            {
                writer.WriteInt32(key);
                CborValueConverter.WriteValue(writer, value);
            }
        }

        writer.WriteEndMap();
        return writer.Encode();
    }


    /// <summary>
    /// Builds a CWT payload from a credential's core claims.
    /// </summary>
    /// <param name="issuerId">The issuer identifier (typically a DID).</param>
    /// <param name="subjectId">The subject identifier (typically a DID).</param>
    /// <param name="validFrom">The validity start time.</param>
    /// <param name="validUntil">Optional validity end time.</param>
    /// <param name="conformanceMode">CBOR conformance mode for deterministic encoding.</param>
    /// <returns>The CBOR-encoded CWT payload bytes.</returns>
    public static byte[] BuildFromCredential(
        string issuerId,
        string? subjectId,
        DateTimeOffset validFrom,
        DateTimeOffset? validUntil = null,
        CborConformanceMode conformanceMode = CborConformanceMode.Canonical)
    {
        return Build(
            issuer: issuerId,
            subject: subjectId,
            issuedAt: validFrom.ToUnixTimeSeconds(),
            expiration: validUntil?.ToUnixTimeSeconds(),
            conformanceMode: conformanceMode);
    }


    /// <summary>
    /// Creates a delegate for building CWT payloads.
    /// </summary>
    /// <param name="conformanceMode">CBOR conformance mode for deterministic encoding.</param>
    /// <returns>A delegate that builds CWT payloads.</returns>
    public static CwtPayloadDelegate CreateDelegate(
        CborConformanceMode conformanceMode = CborConformanceMode.Canonical)
    {
        return (issuer, subject, issuedAt, expiration, additionalClaims) =>
            Build(
                issuer: issuer,
                subject: subject,
                issuedAt: issuedAt,
                expiration: expiration,
                additionalClaims: additionalClaims,
                conformanceMode: conformanceMode);
    }
}