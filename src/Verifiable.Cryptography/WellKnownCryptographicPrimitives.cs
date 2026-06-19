namespace Verifiable.Cryptography;

/// <summary>
/// Well-known cryptographic primitive identifiers.
/// </summary>
/// <remarks>
/// <para>
/// These are the canonical names for the kind of cryptographic operation an algorithm
/// performs — a signature, a key-encapsulation mechanism, a hash, and so on. They are the
/// single source of truth shared across the codebase: producers stamp them onto telemetry
/// spans (see <see cref="CryptoTelemetry.Key.Primitive"/>), and consumers — the declarative
/// and observed Cryptographic Bill of Materials (CBOM) generators among them — read the same
/// constants, so the same string is used in every place.
/// </para>
/// <para>
/// The values mirror the <c>cryptoProperties.algorithmProperties.primitive</c> enumeration of
/// the CycloneDX 1.6 schema, so they can be emitted into a CBOM verbatim without translation.
/// See <see href="https://cyclonedx.org/docs/1.6/json/#components_items_cryptoProperties_algorithmProperties_primitive">CycloneDX 1.6 primitive</see>.
/// </para>
/// </remarks>
public static class WellKnownCryptographicPrimitives
{
    /// <summary>Deterministic random bit generator, e.g. <c>CTR_DRBG</c>.</summary>
    public const string Drbg = "drbg";

    /// <summary>Message authentication code, e.g. <c>HMAC</c>.</summary>
    public const string Mac = "mac";

    /// <summary>Block cipher, e.g. <c>AES</c>.</summary>
    public const string BlockCipher = "blockcipher";

    /// <summary>Stream cipher, e.g. <c>Salsa20</c>.</summary>
    public const string StreamCipher = "streamcipher";

    /// <summary>Digital signature, e.g. <c>ECDSA</c>, <c>Ed25519</c>, <c>RSA</c>, or <c>ML-DSA</c>.</summary>
    public const string Signature = "signature";

    /// <summary>Hash function, e.g. <c>SHA-256</c>.</summary>
    public const string Hash = "hash";

    /// <summary>Public-key encryption, e.g. <c>RSA-OAEP</c>.</summary>
    public const string PublicKeyEncryption = "pke";

    /// <summary>Extendable-output function, e.g. <c>SHAKE256</c>.</summary>
    public const string ExtendableOutputFunction = "xof";

    /// <summary>Key-derivation function, e.g. <c>HKDF</c>.</summary>
    public const string KeyDerivationFunction = "kdf";

    /// <summary>Key agreement, e.g. <c>ECDH</c> or <c>X25519</c>.</summary>
    public const string KeyAgreement = "keyagree";

    /// <summary>Key-encapsulation mechanism, e.g. <c>ML-KEM</c>.</summary>
    public const string KeyEncapsulationMechanism = "kem";

    /// <summary>Authenticated encryption, e.g. <c>AES-GCM</c>.</summary>
    public const string AuthenticatedEncryption = "ae";

    /// <summary>A primitive that combines other primitives, e.g. a hybrid KEM combiner.</summary>
    public const string Combiner = "combiner";

    /// <summary>A primitive whose kind is not one of the other well-known values.</summary>
    public const string Other = "other";

    /// <summary>A primitive whose kind is unknown.</summary>
    public const string Unknown = "unknown";
}
