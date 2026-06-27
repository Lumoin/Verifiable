using System.Collections.Generic;
using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography.Cbom;

/// <summary>
/// Describes a <see cref="CryptoAlgorithm"/> for CBOM rendering: its standard name,
/// CycloneDX primitive, parameter set / curve, supported functions, and security levels.
/// </summary>
/// <param name="Name">The human-readable algorithm name, e.g. <c>Ed25519</c>.</param>
/// <param name="Slug">A lowercase slug for bom-ref construction, e.g. <c>ed25519</c>.</param>
/// <param name="AlgorithmRef">The algorithm asset bom-ref, e.g. <c>crypto/algorithm/ed25519</c>.</param>
/// <param name="Primitive">The CycloneDX primitive, e.g. <c>signature</c>, <c>kem</c>, <c>keyagree</c>.</param>
/// <param name="ParameterSetIdentifier">The parameter set, e.g. <c>ML-DSA-44</c> or <c>2048</c>.</param>
/// <param name="Curve">The named curve, when applicable, e.g. <c>P-256</c>.</param>
/// <param name="CryptoFunctions">The supported functions, e.g. keygen / sign / verify.</param>
/// <param name="ClassicalSecurityLevel">The classical security level in bits.</param>
/// <param name="NistQuantumSecurityLevel">The NIST PQC category (1-5), when applicable.</param>
internal sealed record AlgorithmDescriptor(
    string Name,
    string Slug,
    string AlgorithmRef,
    string Primitive,
    string? ParameterSetIdentifier,
    string? Curve,
    IReadOnlyList<string> CryptoFunctions,
    int? ClassicalSecurityLevel,
    int? NistQuantumSecurityLevel);


/// <summary>
/// Maps <see cref="CryptoAlgorithm"/> values to <see cref="AlgorithmDescriptor"/> records.
/// </summary>
/// <remarks>
/// <para>
/// The mapping is an explicit, reflection-free <c>switch</c> over the curated algorithm
/// set. Security levels follow the cited standards: NIST P-curves and RSA use their
/// classical strengths; the post-quantum families carry NIST PQC categories (FIPS 203/204).
/// </para>
/// </remarks>
internal static class AlgorithmCatalog
{
    private static readonly string[] SignatureKeyFunctions = ["keygen", "sign", "verify"];
    private static readonly string[] KeyAgreementFunctions = ["keygen", "keyderive"];
    private static readonly string[] KemFunctions = ["keygen", "encapsulate", "decapsulate"];
    private static readonly string[] EncryptFunctions = ["encrypt", "decrypt"];


    public static AlgorithmDescriptor Describe(CryptoAlgorithm algorithm) => algorithm switch
    {
        var a when a == CryptoAlgorithm.P256 => Ec("P-256", "p256", 128),
        var a when a == CryptoAlgorithm.P384 => Ec("P-384", "p384", 192),
        var a when a == CryptoAlgorithm.P521 => Ec("P-521", "p521", 256),
        var a when a == CryptoAlgorithm.Secp256k1 => Ec("secp256k1", "secp256k1", 128),
        var a when a == CryptoAlgorithm.BrainpoolP224r1 => Ec("brainpoolP224r1", "brainpoolp224r1", 112),
        var a when a == CryptoAlgorithm.BrainpoolP256r1 => Ec("brainpoolP256r1", "brainpoolp256r1", 128),
        var a when a == CryptoAlgorithm.BrainpoolP320r1 => Ec("brainpoolP320r1", "brainpoolp320r1", 160),
        var a when a == CryptoAlgorithm.BrainpoolP384r1 => Ec("brainpoolP384r1", "brainpoolp384r1", 192),
        var a when a == CryptoAlgorithm.BrainpoolP512r1 => Ec("brainpoolP512r1", "brainpoolp512r1", 256),
        var a when a == CryptoAlgorithm.Ed25519 => new AlgorithmDescriptor(
            "Ed25519", "ed25519", "crypto/algorithm/ed25519",
            WellKnownCryptographicPrimitives.Signature, "Ed25519", "Curve25519", SignatureKeyFunctions, 128, null),
        var a when a == CryptoAlgorithm.X25519 => new AlgorithmDescriptor(
            "X25519", "x25519", "crypto/algorithm/x25519",
            WellKnownCryptographicPrimitives.KeyAgreement, "X25519", "Curve25519", KeyAgreementFunctions, 128, null),
        var a when a == CryptoAlgorithm.Rsa2048 => Rsa("RSA-2048", "rsa2048", "2048", 112),
        var a when a == CryptoAlgorithm.Rsa4096 => Rsa("RSA-4096", "rsa4096", "4096", 152),
        var a when a == CryptoAlgorithm.RsaSha256 => Rsa("RSA-SHA256", "rsasha256", "2048", 112),
        var a when a == CryptoAlgorithm.RsaSha256Pss => Rsa("RSA-SHA256-PSS", "rsasha256pss", "2048", 112),
        var a when a == CryptoAlgorithm.RsaSha384 => Rsa("RSA-SHA384", "rsasha384", "3072", 128),
        var a when a == CryptoAlgorithm.RsaSha384Pss => Rsa("RSA-SHA384-PSS", "rsasha384pss", "3072", 128),
        var a when a == CryptoAlgorithm.RsaSha512 => Rsa("RSA-SHA512", "rsasha512", "4096", 152),
        var a when a == CryptoAlgorithm.RsaSha512Pss => Rsa("RSA-SHA512-PSS", "rsasha512pss", "4096", 152),
        var a when a == CryptoAlgorithm.MlDsa44 => MlDsa("ML-DSA-44", "mldsa44", 2),
        var a when a == CryptoAlgorithm.MlDsa65 => MlDsa("ML-DSA-65", "mldsa65", 3),
        var a when a == CryptoAlgorithm.MlDsa87 => MlDsa("ML-DSA-87", "mldsa87", 5),
        var a when a == CryptoAlgorithm.MlKem512 => MlKem("ML-KEM-512", "mlkem512", 1),
        var a when a == CryptoAlgorithm.MlKem768 => MlKem("ML-KEM-768", "mlkem768", 3),
        var a when a == CryptoAlgorithm.MlKem1024 => MlKem("ML-KEM-1024", "mlkem1024", 5),
        var a when a == CryptoAlgorithm.WindowsPlatformEncrypted => new AlgorithmDescriptor(
            "WindowsPlatformEncrypted", "windowsplatformencrypted",
            "crypto/algorithm/windowsplatformencrypted",
            WellKnownCryptographicPrimitives.Other, null, null, EncryptFunctions, null, null),
        _ => new AlgorithmDescriptor(
            algorithm.ToString(), CbomIdentifiers.AsciiLower(algorithm.ToString()),
            $"crypto/algorithm/{CbomIdentifiers.AsciiLower(algorithm.ToString())}",
            WellKnownCryptographicPrimitives.Other, null, null, ["keygen"], null, null)
    };


    private static AlgorithmDescriptor Ec(string name, string slug, int classicalBits) =>
        new(
            name,
            slug,
            $"crypto/algorithm/{slug}",
            WellKnownCryptographicPrimitives.Signature,
            name,
            name,
            SignatureKeyFunctions,
            classicalBits,
            null);


    private static AlgorithmDescriptor Rsa(string name, string slug, string parameterSet, int classicalBits) =>
        new(
            name,
            slug,
            $"crypto/algorithm/{slug}",
            WellKnownCryptographicPrimitives.Signature,
            parameterSet,
            null,
            SignatureKeyFunctions,
            classicalBits,
            null);


    private static AlgorithmDescriptor MlDsa(string name, string slug, int nistCategory) =>
        new(
            name,
            slug,
            $"crypto/algorithm/{slug}",
            WellKnownCryptographicPrimitives.Signature,
            name,
            null,
            SignatureKeyFunctions,
            null,
            nistCategory);


    private static AlgorithmDescriptor MlKem(string name, string slug, int nistCategory) =>
        new(
            name,
            slug,
            $"crypto/algorithm/{slug}",
            WellKnownCryptographicPrimitives.KeyEncapsulationMechanism,
            name,
            null,
            KemFunctions,
            null,
            nistCategory);
}


/// <summary>
/// CBOM helpers for <see cref="HashAlgorithmName"/> values used by digest and HMAC tags.
/// </summary>
internal static class HashAlgorithmCbom
{
    public static string Name(HashAlgorithmName hashName) => hashName switch
    {
        var h when h == HashAlgorithmName.SHA256 => "SHA-256",
        var h when h == HashAlgorithmName.SHA384 => "SHA-384",
        var h when h == HashAlgorithmName.SHA512 => "SHA-512",
        var h when h == HashAlgorithmName.SHA1 => "SHA-1",
        _ => hashName.Name ?? "unknown-hash"
    };


    //Collision resistance is half the digest length; this is the classical strength a CBOM
    //consumer expects under cryptoProperties.algorithmProperties.classicalSecurityLevel.
    public static int? ClassicalSecurityLevel(HashAlgorithmName hashName) => hashName switch
    {
        var h when h == HashAlgorithmName.SHA256 => 128,
        var h when h == HashAlgorithmName.SHA384 => 192,
        var h when h == HashAlgorithmName.SHA512 => 256,
        var h when h == HashAlgorithmName.SHA1 => 80,
        _ => null
    };
}
