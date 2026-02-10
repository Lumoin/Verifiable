using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.Jose;

namespace Verifiable.JCose;

/// <summary>
/// An unsigned JWT consisting of a protected header and payload, ready for signing.
/// </summary>
/// <remarks>
/// <para>
/// This type is the primary anchor for extension methods that build JWT header and
/// payload pairs for specific use cases. The library provides core construction via
/// <see cref="ForSigning"/>, and domain-specific extensions (e.g., SD-JWT digests,
/// EUDI PID claims) can be added using C# 13 extension syntax without modifying
/// this class.
/// </para>
/// <para>
/// After construction, the unsigned JWT is signed via
/// <see cref="JwtSigningExtensions.SignAsync"/> to produce a <see cref="JwsMessage"/>.
/// </para>
/// <para>
/// Example usage:
/// </para>
/// <code>
/// var unsigned = UnsignedJwt.ForSigning(privateKey, keyId, payload);
/// using JwsMessage jws = await unsigned.SignAsync(
///     privateKey, headerSerializer, payloadSerializer, encoder, pool, ct);
/// string jwt = JwsSerialization.SerializeCompact(jws, encoder);
/// </code>
/// </remarks>
[DebuggerDisplay("UnsignedJwt(Header: {Header.Count} entries, Payload: {Payload.Count} claims)")]
public sealed class UnsignedJwt: IEquatable<UnsignedJwt>
{
    /// <summary>
    /// The JWT protected header.
    /// </summary>
    public JwtHeader Header { get; }

    /// <summary>
    /// The JWT payload (claims set).
    /// </summary>
    public JwtPayload Payload { get; }


    /// <summary>
    /// Creates an unsigned JWT from a header and payload.
    /// </summary>
    /// <param name="header">The JWT protected header.</param>
    /// <param name="payload">The JWT payload claims.</param>
    public UnsignedJwt(JwtHeader header, JwtPayload payload)
    {
        ArgumentNullException.ThrowIfNull(header);
        ArgumentNullException.ThrowIfNull(payload);

        Header = header;
        Payload = payload;
    }


    /// <summary>
    /// Creates an unsigned JWT with the header derived from the signing key's metadata.
    /// </summary>
    /// <param name="privateKey">
    /// The signing key whose <see cref="Tag"/> determines the <c>alg</c> header value
    /// via <see cref="CryptoFormatConversions.DefaultTagToJwaConverter"/>.
    /// </param>
    /// <param name="keyId">
    /// The key identifier for the <c>kid</c> header parameter,
    /// typically a DID URL such as <c>did:web:issuer.example#key-1</c>.
    /// </param>
    /// <param name="payload">The JWT payload claims.</param>
    /// <param name="mediaType">
    /// The <c>typ</c> header value. When <see langword="null"/>, defaults to
    /// <see cref="WellKnownMediaTypes.Jwt.VcLdJwt"/>.
    /// </param>
    /// <returns>An unsigned JWT ready for signing.</returns>
    public static UnsignedJwt ForSigning(
        PrivateKeyMemory privateKey,
        string keyId,
        JwtPayload payload,
        string? mediaType = null)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(keyId);
        ArgumentNullException.ThrowIfNull(payload);

        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(privateKey.Tag);

        var header = new JwtHeader
        {
            [JwkProperties.Alg] = algorithm,
            [JwkProperties.Typ] = mediaType ?? WellKnownMediaTypes.Jwt.VcLdJwt,
            [JwkProperties.Kid] = keyId
        };

        return new UnsignedJwt(header, payload);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(UnsignedJwt? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return Header.Equals(other.Header) && Payload.Equals(other.Payload);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj)
    {
        return obj is UnsignedJwt other && Equals(other);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        return HashCode.Combine(Header.GetHashCode(), Payload.GetHashCode());
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(UnsignedJwt? left, UnsignedJwt? right)
    {
        return left is null ? right is null : left.Equals(right);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(UnsignedJwt? left, UnsignedJwt? right)
    {
        return !(left == right);
    }


    /// <inheritdoc/>
    public override string ToString()
    {
        return $"UnsignedJwt[Header: {Header.Count} entries, Payload: {Payload.Count} claims]";
    }
}