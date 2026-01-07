using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography.Context;

/// <summary>
/// Attribute to mark properties for registration discovery.
/// </summary>
[AttributeUsage(AttributeTargets.Property, Inherited = false, AllowMultiple = false)]
public sealed class CryptoAlgorithmRegistrationAttribute: Attribute
{
}


/// <summary>
/// Represents a cryptographic algorithm used to generate or process key material.
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
/// public static class CustomCryptoAlgorithms
/// {
///     public static CryptoAlgorithm Kyber512 { get; } = CryptoAlgorithm.Create(1001);
///     public static CryptoAlgorithm Dilithium2 { get; } = CryptoAlgorithm.Create(1002);
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
/// <see cref="CryptoAlgorithm"/> identifies which cryptographic algorithm the material uses
/// (P-256, Ed25519, RSA-2048, etc.). This is one of the primary discriminators for
/// <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/> routing.
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
///     [typeof(Purpose)] = Purpose.Signing,
///     [typeof(EncodingScheme)] = EncodingScheme.Raw,
///     [typeof(MaterialSemantics)] = MaterialSemantics.Direct
/// });
/// </code>
/// </remarks>
/// <seealso cref="Purpose"/>
/// <seealso cref="EncodingScheme"/>
/// <seealso cref="MaterialSemantics"/>
/// <seealso cref="Tag"/>
[DebuggerDisplay("{CryptoAlgorithmNames.GetName(this),nq}")]
public readonly struct CryptoAlgorithm: IEquatable<CryptoAlgorithm>
{
    /// <summary>
    /// Gets the numeric code for this algorithm.
    /// </summary>
    public int Algorithm { get; }


    private CryptoAlgorithm(int algorithm)
    {
        Algorithm = algorithm;
    }


    /// <summary>
    /// The algorithm is unknown.
    /// </summary>         
    public static CryptoAlgorithm Unknown { get; } = new CryptoAlgorithm(-1);


    /// <summary>
    /// Secp256k1 elliptic curve.
    /// </summary>
    /// <remarks>
    /// Corresponds to <c>MulticodecHeaders.Secp256k1PublicKey</c> when used
    /// with <see cref="Purpose.Verification"/>, and <c>WellKnownJwaValues.Es256k1</c>.
    /// </remarks>
    [CryptoAlgorithmRegistration]
    public static CryptoAlgorithm Secp256k1 { get; } = new CryptoAlgorithm(0);


    /// <summary>
    /// BLS12-381 in the G1 field.
    /// </summary>
    /// <remarks>
    /// Corresponds to <c>MulticodecHeaders.Bls12381G1PublicKey</c> when used
    /// with <see cref="Purpose.Verification"/>.
    /// </remarks>
    public static CryptoAlgorithm Bls12381G1 { get; } = new CryptoAlgorithm(1);


    /// <summary>
    /// BLS12-381 in the G2 field.
    /// </summary>
    /// <remarks>
    /// Corresponds to <c>MulticodecHeaders.Bls12381G2PublicKey</c> when used
    /// with <see cref="Purpose.Verification"/>.
    /// </remarks>
    public static CryptoAlgorithm Bls12381G2 { get; } = new CryptoAlgorithm(2);


    /// <summary>
    /// Curve25519 for key exchange.
    /// </summary>
    /// <remarks>
    /// Corresponds to <c>MulticodecHeaders.X25519PublicKey</c> when used
    /// with <see cref="Purpose.Exchange"/>.
    /// </remarks>
    public static CryptoAlgorithm X25519 { get; } = new CryptoAlgorithm(3);


    /// <summary>
    /// Ed25519 for digital signatures.
    /// </summary>
    /// <remarks>
    /// Corresponds to <c>MulticodecHeaders.Ed25519PublicKey</c> and <c>WellKnownJwaValues.EdDsa</c>
    /// when used with <see cref="Purpose.Verification"/>.
    /// </remarks>
    public static CryptoAlgorithm Ed25519 { get; } = new CryptoAlgorithm(4);


    /// <summary>
    /// BLS12-381 in both G1 and G2 fields.
    /// </summary>
    /// <remarks>
    /// Corresponds to <c>MulticodecHeaders.Bls12381G1G2PublicKey</c> when used
    /// with <see cref="Purpose.Verification"/>.
    /// </remarks>
    public static CryptoAlgorithm Bls12381G1G2 { get; } = new CryptoAlgorithm(5);


    /// <summary>
    /// NIST P-256 (secp256r1) elliptic curve.
    /// </summary>
    /// <remarks>
    /// Corresponds to <c>MulticodecHeaders.P256PublicKey</c> when used
    /// with <see cref="Purpose.Verification"/>.
    /// </remarks>
    public static CryptoAlgorithm P256 { get; } = new CryptoAlgorithm(6);


    /// <summary>
    /// NIST P-384 (secp384r1) elliptic curve.
    /// </summary>
    /// <remarks>
    /// Corresponds to <c>MulticodecHeaders.P384PublicKey</c> when used
    /// with <see cref="Purpose.Verification"/>.
    /// </remarks>
    public static CryptoAlgorithm P384 { get; } = new CryptoAlgorithm(7);


    /// <summary>
    /// NIST P-521 (secp521r1) elliptic curve.
    /// </summary>
    /// <remarks>
    /// Corresponds to <c>MulticodecHeaders.P521PublicKey</c> when used
    /// with <see cref="Purpose.Verification"/>.
    /// </remarks>
    public static CryptoAlgorithm P521 { get; } = new CryptoAlgorithm(8);


    /// <summary>
    /// RSA with 2048-bit key.
    /// </summary>
    /// <remarks>
    /// Corresponds to <c>MulticodecHeaders.RsaPublicKey</c> when used
    /// with <see cref="Purpose.Verification"/>.
    /// </remarks>
    public static CryptoAlgorithm Rsa2048 { get; } = new CryptoAlgorithm(9);


    /// <summary>
    /// RSA with 4096-bit key.
    /// </summary>
    /// <remarks>
    /// Corresponds to <c>MulticodecHeaders.RsaPublicKey</c> when used
    /// with <see cref="Purpose.Verification"/>.
    /// </remarks>
    public static CryptoAlgorithm Rsa4096 { get; } = new CryptoAlgorithm(10);


    /// <summary>
    /// Windows platform encryption provider.
    /// </summary>
    public static CryptoAlgorithm WindowsPlatformEncrypted { get; } = new CryptoAlgorithm(11);


    private static readonly List<CryptoAlgorithm> algorithms = new([Rsa2048]);


    /// <summary>
    /// Gets all registered algorithm values.
    /// </summary>
    public static IReadOnlyList<CryptoAlgorithm> Algorithms => algorithms.AsReadOnly();


    /// <summary>
    /// Creates a new algorithm value for custom algorithms.
    /// </summary>
    /// <param name="algorithm">The unique numeric code for this algorithm.</param>
    /// <returns>The newly created algorithm.</returns>
    /// <exception cref="ArgumentException">Thrown when the code already exists.</exception>
    /// <remarks>
    /// <para>
    /// This method is not thread-safe. Call it only during application startup,
    /// such as in static initializers or early in <c>Program.cs</c>.
    /// Use code values above 1000 to avoid collisions with future library additions.
    /// </para>
    /// </remarks>
    public static CryptoAlgorithm Create(int algorithm)
    {
        for(int i = 0; i < algorithms.Count; ++i)
        {
            if(algorithms[i].Algorithm == algorithm)
            {
                throw new ArgumentException("Code already exists.");
            }
        }

        var newAlgorithm = new CryptoAlgorithm(algorithm);
        algorithms.Add(newAlgorithm);

        return newAlgorithm;
    }


    /// <inheritdoc />
    public override string ToString() => CryptoAlgorithmNames.GetName(this);


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(CryptoAlgorithm other)
    {
        return Algorithm == other.Algorithm;
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj)
    {
        return obj is CryptoAlgorithm other && Equals(other);
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(in CryptoAlgorithm left, in CryptoAlgorithm right)
    {
        return left.Equals(right);
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(in CryptoAlgorithm left, in CryptoAlgorithm right)
    {
        return !left.Equals(right);
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(in object left, in CryptoAlgorithm right)
    {
        return Equals(left, right);
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(in CryptoAlgorithm left, in object right)
    {
        return Equals(left, right);
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(in object left, in CryptoAlgorithm right)
    {
        return !Equals(left, right);
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(in CryptoAlgorithm left, in object right)
    {
        return !Equals(left, right);
    }


    /// <inheritdoc />
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        return Algorithm;
    }
}


/// <summary>
/// Provides human-readable names for <see cref="CryptoAlgorithm"/> values.
/// </summary>
public static class CryptoAlgorithmNames
{
    /// <summary>
    /// Gets the name for the specified algorithm.
    /// </summary>
    /// <param name="algorithm">The algorithm.</param>
    /// <returns>The human-readable name.</returns>
    public static string GetName(CryptoAlgorithm algorithm) => GetName(algorithm.Algorithm);


    /// <summary>
    /// Gets the name for the specified algorithm code.
    /// </summary>
    /// <param name="algorithm">The numeric code.</param>
    /// <returns>The human-readable name.</returns>
    public static string GetName(int algorithm) => algorithm switch
    {
        var a when a == CryptoAlgorithm.Unknown.Algorithm => nameof(CryptoAlgorithm.Unknown),
        var a when a == CryptoAlgorithm.Secp256k1.Algorithm => nameof(CryptoAlgorithm.Secp256k1),
        var a when a == CryptoAlgorithm.Bls12381G1.Algorithm => nameof(CryptoAlgorithm.Bls12381G1),
        var a when a == CryptoAlgorithm.Bls12381G2.Algorithm => nameof(CryptoAlgorithm.Bls12381G2),
        var a when a == CryptoAlgorithm.X25519.Algorithm => nameof(CryptoAlgorithm.X25519),
        var a when a == CryptoAlgorithm.Ed25519.Algorithm => nameof(CryptoAlgorithm.Ed25519),
        var a when a == CryptoAlgorithm.Bls12381G1G2.Algorithm => nameof(CryptoAlgorithm.Bls12381G1G2),
        var a when a == CryptoAlgorithm.P256.Algorithm => nameof(CryptoAlgorithm.P256),
        var a when a == CryptoAlgorithm.P384.Algorithm => nameof(CryptoAlgorithm.P384),
        var a when a == CryptoAlgorithm.P521.Algorithm => nameof(CryptoAlgorithm.P521),
        var a when a == CryptoAlgorithm.Rsa2048.Algorithm => nameof(CryptoAlgorithm.Rsa2048),
        var a when a == CryptoAlgorithm.Rsa4096.Algorithm => nameof(CryptoAlgorithm.Rsa4096),
        var a when a == CryptoAlgorithm.WindowsPlatformEncrypted.Algorithm => nameof(CryptoAlgorithm.WindowsPlatformEncrypted),
        _ => $"Custom: ('{algorithm}')."
    };
}