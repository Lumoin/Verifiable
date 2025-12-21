using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography.Context;

/// <summary>
/// Represents the encoding scheme applied to cryptographic material.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The Context Problem: Making Opaque Bytes Meaningful</strong>
/// </para>
/// <para>
/// Cryptographic material is fundamentally just bytes. Without metadata, these bytes are opaque:
/// Is this P-256 or Ed25519? Public or private key? Raw bytes or DER-encoded? Should it be
/// processed by software or delegated to a TPM? The bytes alone cannot answer these questions.
/// </para>
/// <para>
/// Existing systems solve this with format-specific identifiers:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>OIDs</strong> (e.g., 1.2.840.10045.3.1.7 for P-256) - verbose, require parsing,
/// not human-readable, tied to ASN.1/X.509 infrastructure.
/// </description></item>
/// <item><description>
/// <strong>JWT/JWA values</strong> (e.g., "ES256") - string comparison overhead, occasional
/// ambiguity, limited to JOSE ecosystem.
/// </description></item>
/// <item><description>
/// <strong>Class hierarchies</strong> (e.g., <c>P256PrivateKey</c>, <c>Ed25519PublicKey</c>) -
/// type explosion, cannot add algorithms without new classes, complicates generic code.
/// </description></item>
/// </list>
/// <para>
/// This library takes a different approach: bytes remain opaque, but are paired with a
/// <see cref="Tag"/> containing normalized context types (<see cref="CryptoAlgorithm"/>,
/// <see cref="Purpose"/>, <see cref="EncodingScheme"/>, <see cref="MaterialSemantics"/>).
/// This provides:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>Format independence</strong> - same context system works across JOSE, COSE, DID,
/// X.509, and custom formats.
/// </description></item>
/// <item><description>
/// <strong>Fast routing</strong> - integer comparison, no string parsing or OID decoding.
/// </description></item>
/// <item><description>
/// <strong>Runtime extensibility</strong> - add custom algorithms or backends without new classes.
/// </description></item>
/// <item><description>
/// <strong>Separation of concerns</strong> - material storage, algorithm identity, and
/// cryptographic implementation are decoupled.
/// </description></item>
/// </list>
/// 
/// <para>
/// <strong>Design Rationale: Extensible Type-Safe Identifiers</strong>
/// </para>
/// <para>
/// This type follows a "dynamic enum" pattern used throughout the Context namespace.
/// Regular C# enums cannot be extended by library users without forking. This pattern
/// provides type safety while allowing runtime extension.
/// </para>
/// <para>
/// <strong>Extending with Custom Values</strong>
/// </para>
/// <para>
/// To add custom values, call <see cref="Create"/> during application initialization.
/// Use code values above 1000 to avoid collisions with future library additions:
/// </para>
/// <code>
/// // Application startup
/// public static class CustomEncodingSchemes
/// {
///     public static EncodingScheme Cose { get; } = EncodingScheme.Create(1001);
///     public static EncodingScheme Jwk { get; } = EncodingScheme.Create(1002);
/// }
/// </code>
/// <para>
/// <strong>Thread Safety</strong>
/// </para>
/// <para>
/// The <see cref="Create"/> method is not thread-safe. Call it only during
/// application startup before concurrent access begins, such as in static
/// initializers or early in <c>Program.cs</c>. Predefined values are immutable
/// and safe for concurrent read access.
/// </para>
/// 
/// <para>
/// <strong>What This Type Represents</strong>
/// </para>
/// <para>
/// <see cref="EncodingScheme"/> describes how cryptographic bytes are encoded or formatted.
/// Different systems expect different encodings: DER for X.509 certificates, raw bytes for
/// some protocols, compressed points for compact EC key representation, PEM for text-based
/// storage, etc.
/// </para>
/// 
/// <para>
/// <strong>Usage in Tag</strong>
/// </para>
/// <para>
/// These values are stored in <see cref="Tag"/> to describe key material:
/// </para>
/// <code>
/// var tag = new Tag(new Dictionary&lt;Type, object&gt;
/// {
///     [typeof(CryptoAlgorithm)] = CryptoAlgorithm.P256,
///     [typeof(Purpose)] = Purpose.Verification,
///     [typeof(EncodingScheme)] = EncodingScheme.EcCompressed,
///     [typeof(MaterialSemantics)] = MaterialSemantics.Direct
/// });
/// </code>
/// </remarks>
/// <seealso cref="CryptoAlgorithm"/>
/// <seealso cref="Purpose"/>
/// <seealso cref="MaterialSemantics"/>
/// <seealso cref="Tag"/>
[DebuggerDisplay("{EncodingSchemeNames.GetName(this),nq}")]
public readonly struct EncodingScheme: IEquatable<EncodingScheme>
{
    /// <summary>
    /// Gets the numeric code for this encoding scheme.
    /// </summary>
    public int Scheme { get; }


    private EncodingScheme(int scheme)
    {
        Scheme = scheme;
    }


    /// <summary>
    /// DER (Distinguished Encoding Rules) format.
    /// </summary>
    /// <remarks>
    /// Binary encoding used in X.509 certificates and many cryptographic standards.
    /// </remarks>
    public static EncodingScheme Der { get; } = new EncodingScheme(0);


    /// <summary>
    /// PEM (Privacy-Enhanced Mail) format.
    /// </summary>
    /// <remarks>
    /// Base64-encoded DER with header/footer lines. Common for certificates and keys in text form.
    /// </remarks>
    public static EncodingScheme Pem { get; } = new EncodingScheme(1);


    /// <summary>
    /// Compressed elliptic curve point encoding.
    /// </summary>
    /// <remarks>
    /// For EC public keys, stores only the X coordinate plus a sign bit.
    /// Reduces size by approximately half compared to uncompressed.
    /// </remarks>
    public static EncodingScheme EcCompressed { get; } = new EncodingScheme(2);


    /// <summary>
    /// Uncompressed elliptic curve point encoding.
    /// </summary>
    /// <remarks>
    /// For EC public keys, stores both X and Y coordinates prefixed with 0x04.
    /// </remarks>
    public static EncodingScheme EcUncompressed { get; } = new EncodingScheme(3);


    /// <summary>
    /// PKCS#1 format for RSA keys.
    /// </summary>
    /// <remarks>
    /// RSA-specific format defined in RFC 8017.
    /// </remarks>
    public static EncodingScheme Pkcs1 { get; } = new EncodingScheme(4);


    /// <summary>
    /// PKCS#8 format for private keys.
    /// </summary>
    /// <remarks>
    /// Algorithm-agnostic private key format defined in RFC 5958.
    /// </remarks>
    public static EncodingScheme Pkcs8 { get; } = new EncodingScheme(5);


    /// <summary>
    /// Raw bytes with no additional encoding structure.
    /// </summary>
    /// <remarks>
    /// The key material as plain bytes without any wrapper or metadata.
    /// Format depends on the algorithm (e.g., 32 bytes for Ed25519 private key).
    /// </remarks>
    public static EncodingScheme Raw { get; } = new EncodingScheme(6);


    private static readonly List<EncodingScheme> schemes = new([Der, Pem, EcCompressed, EcUncompressed, Pkcs1, Pkcs8, Raw]);


    /// <summary>
    /// Gets all registered encoding scheme values.
    /// </summary>
    public static IReadOnlyList<EncodingScheme> Schemes => schemes.AsReadOnly();


    /// <summary>
    /// Creates a new encoding scheme value for custom formats.
    /// </summary>
    /// <param name="scheme">The unique numeric code for this scheme.</param>
    /// <returns>The newly created encoding scheme.</returns>
    /// <exception cref="ArgumentException">Thrown when the code already exists.</exception>
    /// <remarks>
    /// <para>
    /// This method is not thread-safe. Call it only during application startup,
    /// such as in static initializers or early in <c>Program.cs</c>.
    /// Use code values above 1000 to avoid collisions with future library additions.
    /// </para>
    /// </remarks>
    public static EncodingScheme Create(int scheme)
    {
        for(int i = 0; i < schemes.Count; ++i)
        {
            if(schemes[i].Scheme == scheme)
            {
                throw new ArgumentException("Scheme already exists.");
            }
        }

        var newScheme = new EncodingScheme(scheme);
        schemes.Add(newScheme);

        return newScheme;
    }


    /// <inheritdoc />
    public override string ToString() => EncodingSchemeNames.GetName(this);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(EncodingScheme other)
    {
        return Scheme == other.Scheme;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj)
    {
        return obj is EncodingScheme other && Equals(other);
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(in EncodingScheme left, in EncodingScheme right)
    {
        return left.Equals(right);
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(in EncodingScheme left, in EncodingScheme right)
    {
        return !left.Equals(right);
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(in object left, in EncodingScheme right)
    {
        return Equals(left, right);
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(in EncodingScheme left, in object right)
    {
        return Equals(left, right);
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(in object left, in EncodingScheme right)
    {
        return !Equals(left, right);
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(in EncodingScheme left, in object right)
    {
        return !Equals(left, right);
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        return Scheme;
    }
}


/// <summary>
/// Provides human-readable names for <see cref="EncodingScheme"/> values.
/// </summary>
public static class EncodingSchemeNames
{
    /// <summary>
    /// Gets the name for the specified encoding scheme.
    /// </summary>
    /// <param name="scheme">The encoding scheme.</param>
    /// <returns>The human-readable name.</returns>
    public static string GetName(EncodingScheme scheme) => GetName(scheme.Scheme);


    /// <summary>
    /// Gets the name for the specified encoding scheme code.
    /// </summary>
    /// <param name="code">The numeric code.</param>
    /// <returns>The human-readable name.</returns>
    public static string GetName(int code) => code switch
    {
        var c when c == EncodingScheme.Der.Scheme => nameof(EncodingScheme.Der),
        var c when c == EncodingScheme.Pem.Scheme => nameof(EncodingScheme.Pem),
        var c when c == EncodingScheme.EcCompressed.Scheme => nameof(EncodingScheme.EcCompressed),
        var c when c == EncodingScheme.EcUncompressed.Scheme => nameof(EncodingScheme.EcUncompressed),
        var c when c == EncodingScheme.Pkcs1.Scheme => nameof(EncodingScheme.Pkcs1),
        var c when c == EncodingScheme.Pkcs8.Scheme => nameof(EncodingScheme.Pkcs8),
        var c when c == EncodingScheme.Raw.Scheme => nameof(EncodingScheme.Raw),
        _ => $"Custom: ('{code}')."
    };
}