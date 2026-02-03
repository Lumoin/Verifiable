using System.Security.Cryptography;
using Verifiable.Cbor;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Serialization;

/// <summary>
/// Unit tests for ecdsa-sd-2023 CBOR serialization and configuration.
/// </summary>
/// <remarks>
/// <para>
/// These tests verify the internal serialization format for ecdsa-sd-2023 proofs.
/// For end-to-end workflow tests, see <see cref="DataIntegrity.CredentialSecuringMethodsTests"/>.
/// </para>
/// <para>
/// See <see href="https://w3c.github.io/vc-di-ecdsa/#ecdsa-sd-2023">
/// W3C VC DI ECDSA §3.3 ecdsa-sd-2023</see>.
/// </para>
/// </remarks>
[TestClass]
public sealed class EcdsaSd2023SerializerTests
{
    /// <summary>
    /// Tests ecdsa-sd-2023 base proof CBOR serialization round-trips correctly.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The base proof is created by the issuer and contains signatures for each non-mandatory statement.
    /// It includes the HMAC key needed for the holder to derive proofs later.
    /// </para>
    /// <para>
    /// See <see href="https://w3c.github.io/vc-di-ecdsa/#serializebaseproofvalue">
    /// W3C VC DI ECDSA §3.3.13 serializeBaseProofValue</see>.
    /// </para>
    /// </remarks>
    [TestMethod]
    public void BaseProofSerializationRoundTrips()
    {
        //Arrange - Create sample base proof components.
        var baseSignature = new byte[64];
        var rawPublicKey = new byte[33];
        var hmacKey = new byte[32];
        RandomNumberGenerator.Fill(baseSignature);
        RandomNumberGenerator.Fill(rawPublicKey);
        RandomNumberGenerator.Fill(hmacKey);

        //Create multikey-encoded public key with P-256 header for serialization.
        var publicKeyWithHeader = new byte[35];
        publicKeyWithHeader[0] = 0x80;
        publicKeyWithHeader[1] = 0x24;
        rawPublicKey.CopyTo(publicKeyWithHeader.AsSpan(2));

        var signatures = new List<byte[]>
        {
            new byte[64],
            new byte[64],
            new byte[64]
        };

        foreach(var sig in signatures)
        {
            RandomNumberGenerator.Fill(sig);
        }

        var mandatoryPointers = new List<string>
        {
            "/issuer",
            "/issuanceDate",
            "/credentialSubject/id"
        };

        //Act - Serialize with header, parse returns raw key.
        byte[] serialized = EcdsaSd2023CborSerializer.SerializeBaseProofBytes(
            baseSignature, publicKeyWithHeader, hmacKey, signatures, mandatoryPointers);
        using var parsed = EcdsaSd2023CborSerializer.ParseBaseProofBytes(
            serialized, SensitiveMemoryPool<byte>.Shared);

        //Assert - Verify header bytes per W3C spec §3.3.13.
        Assert.AreEqual(0xd9, serialized[0], "First header byte must be 0xd9.");
        Assert.AreEqual(0x5d, serialized[1], "Second header byte must be 0x5d.");
        Assert.AreEqual(0x00, serialized[2], "Third header byte must be 0x00 for base proof.");

        //Assert - Verify round-trip. Parser strips multicodec header from public key.
        Assert.IsTrue(baseSignature.AsSpan().SequenceEqual(parsed.BaseSignature.AsReadOnlySpan()), "Base signature must round-trip.");
        Assert.IsTrue(rawPublicKey.AsSpan().SequenceEqual(parsed.EphemeralPublicKey.AsReadOnlySpan()), "Public key must round-trip without multicodec header.");
        Assert.IsTrue(hmacKey.AsSpan().SequenceEqual(parsed.HmacKey), "HMAC key must round-trip.");
        Assert.HasCount(3, parsed.Signatures, "Signature count must match.");
        Assert.HasCount(3, parsed.MandatoryPointers, "Mandatory pointer count must match.");
        Assert.AreEqual("/issuer", parsed.MandatoryPointers[0].ToString());
        Assert.AreEqual("/issuanceDate", parsed.MandatoryPointers[1].ToString());
        Assert.AreEqual("/credentialSubject/id", parsed.MandatoryPointers[2].ToString());
    }


    /// <summary>
    /// Tests ecdsa-sd-2023 derived proof CBOR serialization round-trips correctly.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The derived proof is created by the holder from a base proof and sent to the verifier.
    /// It contains only signatures for the claims the holder chose to disclose.
    /// </para>
    /// <para>
    /// See <see href="https://w3c.github.io/vc-di-ecdsa/#serializederivedproofvalue">
    /// W3C VC DI ECDSA §3.3.18 serializeDerivedProofValue</see>.
    /// </para>
    /// </remarks>
    [TestMethod]
    public void DerivedProofSerializationRoundTrips()
    {
        //Arrange - Create sample derived proof components.
        var baseSignature = new byte[64];
        var rawPublicKey = new byte[33];
        RandomNumberGenerator.Fill(baseSignature);
        RandomNumberGenerator.Fill(rawPublicKey);

        //Create multikey-encoded public key with P-256 header for serialization.
        var publicKeyWithHeader = new byte[35];
        publicKeyWithHeader[0] = 0x80;
        publicKeyWithHeader[1] = 0x24;
        rawPublicKey.CopyTo(publicKeyWithHeader.AsSpan(2));

        var signatures = new List<byte[]>
    {
        new byte[64],
        new byte[64]
    };
        foreach(var sig in signatures)
        {
            RandomNumberGenerator.Fill(sig);
        }

        //Label map: canonical blank node IDs to HMAC-based IDs.
        var labelMap = new Dictionary<string, string>
        {
            ["c14n0"] = "u" + TestSetup.Base64UrlEncoder(RandomNumberGenerator.GetBytes(32)),
            ["c14n1"] = "u" + TestSetup.Base64UrlEncoder(RandomNumberGenerator.GetBytes(32)),
            ["c14n3"] = "u" + TestSetup.Base64UrlEncoder(RandomNumberGenerator.GetBytes(32))
        };

        var mandatoryIndexes = new List<int> { 0, 2, 5 };

        //Act - Serialize with header, parse returns raw key.
        byte[] serialized = EcdsaSd2023CborSerializer.SerializeDerivedProofBytes(
            baseSignature, publicKeyWithHeader, signatures, labelMap, mandatoryIndexes,
            TestSetup.Base64UrlDecoder, SensitiveMemoryPool<byte>.Shared);

        using var parsed = EcdsaSd2023CborSerializer.ParseDerivedProofBytes(serialized, TestSetup.Base64UrlEncoder, SensitiveMemoryPool<byte>.Shared);

        //Assert - Verify header bytes per W3C spec §3.3.18.
        Assert.AreEqual(0xd9, serialized[0], "First header byte must be 0xd9.");
        Assert.AreEqual(0x5d, serialized[1], "Second header byte must be 0x5d.");
        Assert.AreEqual(0x01, serialized[2], "Third header byte must be 0x01 for derived proof.");

        //Assert - Verify round-trip. Parser strips multicodec header from public key.
        Assert.IsTrue(baseSignature.AsSpan().SequenceEqual(parsed.BaseSignature.AsReadOnlySpan()), "Base signature must round-trip.");
        Assert.IsTrue(rawPublicKey.AsSpan().SequenceEqual(parsed.EphemeralPublicKey.AsReadOnlySpan()), "Public key must round-trip without multicodec header.");
        Assert.HasCount(2, parsed.Signatures, "Signature count must match.");
        Assert.HasCount(3, parsed.LabelMap, "Label map count must match.");
        Assert.HasCount(3, parsed.MandatoryIndexes, "Mandatory indexes count must match.");
        Assert.AreEqual(0, parsed.MandatoryIndexes[0]);
        Assert.AreEqual(2, parsed.MandatoryIndexes[1]);
        Assert.AreEqual(5, parsed.MandatoryIndexes[2]);
    }


    /// <summary>
    /// Tests that ecdsa-sd-2023 cryptosuite info is properly configured.
    /// </summary>
    [TestMethod]
    public void CryptosuiteInfoIsConfiguredCorrectly()
    {
        var cryptosuite = EcdsaSd2023CryptosuiteInfo.Instance;

        Assert.AreEqual("ecdsa-sd-2023", cryptosuite.CryptosuiteName);
        Assert.AreEqual(CanonicalizationAlgorithm.Rdfc10, cryptosuite.Canonicalization);
        Assert.AreEqual("SHA-256", cryptosuite.HashAlgorithm);
        Assert.AreEqual(CryptoAlgorithm.P256, cryptosuite.SignatureAlgorithm);
        Assert.IsTrue(cryptosuite.SupportsSelectiveDisclosure);

        //Verify compatible with Multikey verification method.
        Assert.IsTrue(cryptosuite.IsCompatibleWith(MultikeyVerificationMethodTypeInfo.Instance));
    }


    /// <summary>
    /// Tests multibase encoding of base proof value starts with 'u'.
    /// </summary>
    [TestMethod]
    public void BaseProofMultibaseEncodingStartsWithU()
    {
        //Arrange.
        var baseSignature = new byte[64];
        var publicKey = new byte[35];
        var hmacKey = new byte[32];

        //Act.
        string proofValue = EcdsaSd2023CborSerializer.SerializeBaseProof(
            baseSignature, publicKey, hmacKey, [], ["/issuer"], TestSetup.Base64UrlEncoder);

        //Assert - Must start with 'u' for base64url-no-pad multibase per W3C spec.
        Assert.StartsWith("u", proofValue, "Base proof value must start with 'u' multibase prefix.");
        Assert.IsGreaterThan(10, proofValue.Length, "Proof value should have substantial length.");
    }
}