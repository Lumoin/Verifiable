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
///     public static CryptoAlgorithm SlhDsa128s { get; } = CryptoAlgorithm.Create(1002);
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
/// var tag = Tag.Create(CryptoAlgorithm.P256)
///     .With(Purpose.Signing)
///     .With(EncodingScheme.Raw)
///     .With(MaterialSemantics.Direct);
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
    /// with <see cref="Purpose.Verification"/>, and <c>WellKnownJwaValues.Es256K</c>.
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


    /// <summary>
    /// RSA with SHA-256 hash (PKCS#1 v1.5 padding).
    /// </summary>
    public static CryptoAlgorithm RsaSha256 { get; } = new CryptoAlgorithm(12);


    /// <summary>
    /// RSA with SHA-256 hash (PSS padding).
    /// </summary>
    public static CryptoAlgorithm RsaSha256Pss { get; } = new CryptoAlgorithm(13);


    /// <summary>
    /// RSA with SHA-384 hash (PKCS#1 v1.5 padding).
    /// </summary>
    public static CryptoAlgorithm RsaSha384 { get; } = new CryptoAlgorithm(14);


    /// <summary>
    /// RSA with SHA-384 hash (PSS padding).
    /// </summary>
    public static CryptoAlgorithm RsaSha384Pss { get; } = new CryptoAlgorithm(15);


    /// <summary>
    /// RSA with SHA-512 hash (PKCS#1 v1.5 padding).
    /// </summary>
    public static CryptoAlgorithm RsaSha512 { get; } = new CryptoAlgorithm(16);


    /// <summary>
    /// RSA with SHA-512 hash (PSS padding).
    /// </summary>
    public static CryptoAlgorithm RsaSha512Pss { get; } = new CryptoAlgorithm(17);


    /// <summary>
    /// ML-DSA-44 post-quantum digital signature algorithm (NIST FIPS 204, security level 2).
    /// </summary>
    /// <remarks>
    /// Corresponds to JWA identifier <c>"ML-DSA-44"</c> as defined in
    /// <see href="https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/">draft-ietf-cose-dilithium</see>.
    /// Public key size: 1312 bytes. Signature size: 2420 bytes.
    /// </remarks>
    public static CryptoAlgorithm MlDsa44 { get; } = new CryptoAlgorithm(18);


    /// <summary>
    /// ML-DSA-65 post-quantum digital signature algorithm (NIST FIPS 204, security level 3).
    /// </summary>
    /// <remarks>
    /// Corresponds to JWA identifier <c>"ML-DSA-65"</c> as defined in
    /// <see href="https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/">draft-ietf-cose-dilithium</see>.
    /// Public key size: 1952 bytes. Signature size: 3309 bytes.
    /// </remarks>
    public static CryptoAlgorithm MlDsa65 { get; } = new CryptoAlgorithm(19);


    /// <summary>
    /// ML-DSA-87 post-quantum digital signature algorithm (NIST FIPS 204, security level 5).
    /// </summary>
    /// <remarks>
    /// Corresponds to JWA identifier <c>"ML-DSA-87"</c> as defined in
    /// <see href="https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/">draft-ietf-cose-dilithium</see>.
    /// Public key size: 2592 bytes. Signature size: 4627 bytes.
    /// </remarks>
    public static CryptoAlgorithm MlDsa87 { get; } = new CryptoAlgorithm(20);


    /// <summary>
    /// ML-KEM-512 post-quantum key encapsulation mechanism (NIST FIPS 203, security level 1).
    /// </summary>
    /// <remarks>
    /// Public key size: 800 bytes. Ciphertext size: 768 bytes. Shared secret: 32 bytes.
    /// </remarks>
    public static CryptoAlgorithm MlKem512 { get; } = new CryptoAlgorithm(21);


    /// <summary>
    /// ML-KEM-768 post-quantum key encapsulation mechanism (NIST FIPS 203, security level 3).
    /// </summary>
    /// <remarks>
    /// Public key size: 1184 bytes. Ciphertext size: 1088 bytes. Shared secret: 32 bytes.
    /// </remarks>
    public static CryptoAlgorithm MlKem768 { get; } = new CryptoAlgorithm(22);


    /// <summary>
    /// ML-KEM-1024 post-quantum key encapsulation mechanism (NIST FIPS 203, security level 5).
    /// </summary>
    /// <remarks>
    /// Public key size: 1568 bytes. Ciphertext size: 1568 bytes. Shared secret: 32 bytes.
    /// </remarks>
    public static CryptoAlgorithm MlKem1024 { get; } = new CryptoAlgorithm(23);


    /// <summary>
    /// Brainpool P-256r1 elliptic curve (256-bit field, twisted prime curve)
    /// as defined in
    /// <see href="https://www.rfc-editor.org/rfc/rfc5639">RFC 5639</see>.
    /// </summary>
    /// <remarks>
    /// Paired with SHA-256 under RFC 9864 fully-specified ECDSA identifier
    /// <c>ESB256</c> (COSE algorithm <c>-265</c>). Used by EUDI Wallet ARF
    /// profiles that need EU-domestic curve parameters distinct from the
    /// NIST P-256 generator.
    /// </remarks>
    public static CryptoAlgorithm BrainpoolP256r1 { get; } = new CryptoAlgorithm(24);


    /// <summary>
    /// Brainpool P-320r1 elliptic curve (320-bit field, twisted prime curve)
    /// as defined in
    /// <see href="https://www.rfc-editor.org/rfc/rfc5639">RFC 5639</see>.
    /// </summary>
    /// <remarks>
    /// Paired with SHA-384 under RFC 9864 fully-specified ECDSA identifier
    /// <c>ESB320</c> (COSE algorithm <c>-266</c>). The 320-bit field has no
    /// direct NIST equivalent.
    /// </remarks>
    public static CryptoAlgorithm BrainpoolP320r1 { get; } = new CryptoAlgorithm(25);


    /// <summary>
    /// Brainpool P-384r1 elliptic curve (384-bit field, twisted prime curve)
    /// as defined in
    /// <see href="https://www.rfc-editor.org/rfc/rfc5639">RFC 5639</see>.
    /// </summary>
    /// <remarks>
    /// Paired with SHA-384 under RFC 9864 fully-specified ECDSA identifier
    /// <c>ESB384</c> (COSE algorithm <c>-267</c>).
    /// </remarks>
    public static CryptoAlgorithm BrainpoolP384r1 { get; } = new CryptoAlgorithm(26);


    /// <summary>
    /// Brainpool P-512r1 elliptic curve (512-bit field, twisted prime curve)
    /// as defined in
    /// <see href="https://www.rfc-editor.org/rfc/rfc5639">RFC 5639</see>.
    /// </summary>
    /// <remarks>
    /// Paired with SHA-512 under RFC 9864 fully-specified ECDSA identifier
    /// <c>ESB512</c> (COSE algorithm <c>-268</c>). Field size matches NIST
    /// P-521 in practice; the curve parameters differ.
    /// </remarks>
    public static CryptoAlgorithm BrainpoolP512r1 { get; } = new CryptoAlgorithm(27);


    /// <summary>
    /// Brainpool P-224r1 elliptic curve (224-bit field, twisted prime curve)
    /// as defined in
    /// <see href="https://www.rfc-editor.org/rfc/rfc5639">RFC 5639</see>.
    /// </summary>
    /// <remarks>
    /// Used for elliptic-curve Diffie–Hellman key agreement — notably eMRTD Chip Authentication, which
    /// announces the chip's static key in EF.DG14 — rather than signing: brainpoolP224r1 has no
    /// fully-specified ECDSA registration in RFC 9864 / IANA COSE, so it carries no COSE algorithm or
    /// COSE elliptic-curve identifier. The numeric identifier follows the symmetric algorithms because
    /// 28–30 were already taken when this curve was added.
    /// </remarks>
    public static CryptoAlgorithm BrainpoolP224r1 { get; } = new CryptoAlgorithm(31);


    /// <summary>
    /// AES with a 256-bit key as defined in
    /// <see href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf">FIPS 197</see>.
    /// </summary>
    /// <remarks>
    /// Identifies symmetric key material and the values produced under it regardless of
    /// the mode of operation — key wrapping per
    /// <see href="https://www.rfc-editor.org/rfc/rfc3394">RFC 3394</see>, AES-GCM, or
    /// AES-CBC with HMAC composition per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-5.2">RFC 7518 §5.2</see>.
    /// The <see cref="Purpose"/> component of a <see cref="Tag"/> distinguishes the role
    /// of the bytes within the operation.
    /// </remarks>
    public static CryptoAlgorithm Aes256 { get; } = new CryptoAlgorithm(28);


    /// <summary>
    /// Triple-DES (TDEA) as defined in
    /// <see href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-67r2.pdf">NIST SP 800-67</see>.
    /// </summary>
    /// <remarks>
    /// Identifies Triple-DES symmetric key material and the values produced under it
    /// regardless of keying option — the two-key (16-byte) variant is the one ICAO
    /// Doc 9303 Basic Access Control and 3DES Secure Messaging use, where it also keys
    /// the ISO/IEC 9797-1 MAC Algorithm 3 ("Retail MAC"). The <see cref="Purpose"/>
    /// component of a <see cref="Tag"/> distinguishes the role of the bytes
    /// (<see cref="Purpose.Encryption"/> for the CBC cipher, <see cref="Purpose.Mac"/>
    /// for the Retail MAC).
    /// </remarks>
    public static CryptoAlgorithm TripleDes { get; } = new CryptoAlgorithm(29);


    /// <summary>
    /// AES with a 128-bit key as defined in
    /// <see href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf">FIPS 197</see>.
    /// </summary>
    /// <remarks>
    /// Identifies 128-bit AES symmetric key material and the values produced under it
    /// regardless of the mode of operation — CBC and CMAC for ICAO Doc 9303 PACE and AES
    /// Secure Messaging. The <see cref="Purpose"/> component of a <see cref="Tag"/>
    /// distinguishes the role of the bytes (<see cref="Purpose.Encryption"/> for the cipher,
    /// <see cref="Purpose.Mac"/> for CMAC).
    /// </remarks>
    public static CryptoAlgorithm Aes128 { get; } = new CryptoAlgorithm(30);


    /// <summary>
    /// RSA signatures with message recovery per ISO/IEC 9796-2 Digital Signature scheme 1 — the scheme
    /// ICAO Doc 9303 Part 11 §6.1 Active Authentication uses for RSA chip keys.
    /// </summary>
    /// <remarks>
    /// Distinct from the PKCS#1 v1.5 and PSS RSA algorithms in two ways: the signature itself carries
    /// (recovers) part of the signed message, and the hash function is identified by the signature trailer
    /// rather than fixed by the algorithm. The hash is therefore not part of this identifier — a verifier
    /// reads it from the recovered trailer. The numeric identifier follows brainpoolP224r1 (31).
    /// </remarks>
    public static CryptoAlgorithm RsaIso9796d2 { get; } = new CryptoAlgorithm(32);


    /// <summary>
    /// BLAKE3 cryptographic hash as defined by the
    /// <see href="https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf">BLAKE3 specification</see>.
    /// </summary>
    /// <remarks>
    /// An extendable-output hash; the digest length is carried alongside the tag (e.g. 32 bytes for the 256-bit
    /// output). BLAKE3 is not a <see cref="System.Security.Cryptography.HashAlgorithmName"/>, so a digest tag names
    /// it through this identifier rather than a <c>HashAlgorithmName</c>. It is the default did:webplus self-hash
    /// algorithm (<c>MultihashHeaders.Blake3</c>). The numeric identifier follows RsaIso9796d2 (32).
    /// </remarks>
    public static CryptoAlgorithm Blake3 { get; } = new CryptoAlgorithm(33);


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


    /// <summary>
    /// Reconstructs a <see cref="CryptoAlgorithm"/> from its numeric <see cref="Algorithm"/> code.
    /// </summary>
    /// <param name="algorithm">The numeric algorithm code, e.g. obtained from a telemetry tag.</param>
    /// <returns>The <see cref="CryptoAlgorithm"/> with the given code.</returns>
    /// <remarks>
    /// The identity of a <see cref="CryptoAlgorithm"/> is its code: equality, <see cref="CryptoAlgorithmNames"/>,
    /// and consumers that switch on the well-known instances all compare by code. Reconstructing from a code
    /// therefore yields a value equal to the corresponding well-known instance. This is the inverse of stamping
    /// <see cref="Algorithm"/> onto a span, letting an observer resolve the algorithm a producer recorded.
    /// </remarks>
    public static CryptoAlgorithm FromCode(int algorithm) => new(algorithm);


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
        var a when a == CryptoAlgorithm.RsaSha256.Algorithm => nameof(CryptoAlgorithm.RsaSha256),
        var a when a == CryptoAlgorithm.RsaSha256Pss.Algorithm => nameof(CryptoAlgorithm.RsaSha256Pss),
        var a when a == CryptoAlgorithm.RsaSha384.Algorithm => nameof(CryptoAlgorithm.RsaSha384),
        var a when a == CryptoAlgorithm.RsaSha384Pss.Algorithm => nameof(CryptoAlgorithm.RsaSha384Pss),
        var a when a == CryptoAlgorithm.RsaSha512.Algorithm => nameof(CryptoAlgorithm.RsaSha512),
        var a when a == CryptoAlgorithm.RsaSha512Pss.Algorithm => nameof(CryptoAlgorithm.RsaSha512Pss),
        var a when a == CryptoAlgorithm.MlDsa44.Algorithm => nameof(CryptoAlgorithm.MlDsa44),
        var a when a == CryptoAlgorithm.MlDsa65.Algorithm => nameof(CryptoAlgorithm.MlDsa65),
        var a when a == CryptoAlgorithm.MlDsa87.Algorithm => nameof(CryptoAlgorithm.MlDsa87),
        var a when a == CryptoAlgorithm.MlKem512.Algorithm => nameof(CryptoAlgorithm.MlKem512),
        var a when a == CryptoAlgorithm.MlKem768.Algorithm => nameof(CryptoAlgorithm.MlKem768),
        var a when a == CryptoAlgorithm.MlKem1024.Algorithm => nameof(CryptoAlgorithm.MlKem1024),
        var a when a == CryptoAlgorithm.BrainpoolP224r1.Algorithm => nameof(CryptoAlgorithm.BrainpoolP224r1),
        var a when a == CryptoAlgorithm.BrainpoolP256r1.Algorithm => nameof(CryptoAlgorithm.BrainpoolP256r1),
        var a when a == CryptoAlgorithm.BrainpoolP320r1.Algorithm => nameof(CryptoAlgorithm.BrainpoolP320r1),
        var a when a == CryptoAlgorithm.BrainpoolP384r1.Algorithm => nameof(CryptoAlgorithm.BrainpoolP384r1),
        var a when a == CryptoAlgorithm.BrainpoolP512r1.Algorithm => nameof(CryptoAlgorithm.BrainpoolP512r1),
        var a when a == CryptoAlgorithm.Aes256.Algorithm => nameof(CryptoAlgorithm.Aes256),
        var a when a == CryptoAlgorithm.TripleDes.Algorithm => nameof(CryptoAlgorithm.TripleDes),
        var a when a == CryptoAlgorithm.Aes128.Algorithm => nameof(CryptoAlgorithm.Aes128),
        var a when a == CryptoAlgorithm.RsaIso9796d2.Algorithm => nameof(CryptoAlgorithm.RsaIso9796d2),
        var a when a == CryptoAlgorithm.Blake3.Algorithm => nameof(CryptoAlgorithm.Blake3),
        _ => $"Custom: ('{algorithm}')."
    };
}
