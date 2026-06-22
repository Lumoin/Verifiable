using Verifiable.JCose;

namespace Verifiable.Tests.Cryptography.Aead;

/// <summary>
/// Tests the JWE <c>alg</c> (<see cref="JweAlgorithm"/>) and <c>enc</c>
/// (<see cref="JweContentEncryption"/>) descriptor records and their
/// <c>FromWellKnownName</c> parse-boundary mappings. The descriptors carry the
/// structural facts the JWE pipeline dispatches on — RFC 7516 §2 Key Management
/// Mode, key wrap length, and RFC 7518 §5.2/§5.3 CEK/IV/tag geometry — so these
/// tests pin every implemented row to its specification values and confirm the
/// rejected-by-design and later-chunk algorithms map to <see langword="null"/>.
/// </summary>
[TestClass]
internal sealed class JweDescriptorTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    [DataRow("ECDH-ES", JweKeyManagementMode.DirectKeyAgreement, 0)]
    [DataRow("ECDH-ES+A128KW", JweKeyManagementMode.KeyAgreementWithKeyWrapping, 128)]
    [DataRow("ECDH-ES+A192KW", JweKeyManagementMode.KeyAgreementWithKeyWrapping, 192)]
    [DataRow("ECDH-ES+A256KW", JweKeyManagementMode.KeyAgreementWithKeyWrapping, 256)]
    [DataRow("ECDH-1PU", JweKeyManagementMode.DirectKeyAgreement, 0)]
    [DataRow("ECDH-1PU+A128KW", JweKeyManagementMode.KeyAgreementWithKeyWrapping, 128)]
    [DataRow("ECDH-1PU+A192KW", JweKeyManagementMode.KeyAgreementWithKeyWrapping, 192)]
    [DataRow("ECDH-1PU+A256KW", JweKeyManagementMode.KeyAgreementWithKeyWrapping, 256)]
    [DataRow("A128KW", JweKeyManagementMode.KeyWrapping, 128)]
    [DataRow("A192KW", JweKeyManagementMode.KeyWrapping, 192)]
    [DataRow("A256KW", JweKeyManagementMode.KeyWrapping, 256)]
    [DataRow("dir", JweKeyManagementMode.DirectEncryption, 0)]
    public void JweAlgorithm_FromWellKnownName_MapsEveryImplementedAlg(
        string wireName,
        JweKeyManagementMode expectedMode,
        int expectedKeyWrapBits)
    {
        JweAlgorithm? descriptor = JweAlgorithm.FromWellKnownName(wireName);

        Assert.IsNotNull(descriptor,
            $"'{wireName}' is an implemented key management algorithm and must map to a descriptor.");
        Assert.AreEqual(wireName, descriptor.Value.Name,
            "The descriptor must carry the wire alg identifier verbatim.");
        Assert.AreEqual(expectedMode, descriptor.Value.Mode,
            $"'{wireName}' must carry its RFC 7516 §2 Key Management Mode.");
        Assert.AreEqual(expectedKeyWrapBits, descriptor.Value.KeyWrapBits,
            $"'{wireName}' must carry its key encryption key length in bits (0 for direct modes).");
    }


    [TestMethod]
    [DataRow("RSA1_5")]
    [DataRow("RSA-OAEP")]
    [DataRow("A128GCMKW")]
    [DataRow("PBES2-HS256+A128KW")]
    public void JweAlgorithm_FromWellKnownName_ReturnsNullForUnimplemented(string wireName)
    {
        JweAlgorithm? descriptor = JweAlgorithm.FromWellKnownName(wireName);

        Assert.IsNull(descriptor,
            $"'{wireName}' is rejected-by-design or implemented in a later chunk and must map to null.");
    }


    [TestMethod]
    [DataRow("A128CBC-HS256", 32, 16, 16, JweContentEncryptionFamily.AesCbcHmac)]
    [DataRow("A192CBC-HS384", 48, 16, 24, JweContentEncryptionFamily.AesCbcHmac)]
    [DataRow("A256CBC-HS512", 64, 16, 32, JweContentEncryptionFamily.AesCbcHmac)]
    [DataRow("A128GCM", 16, 12, 16, JweContentEncryptionFamily.AesGcm)]
    [DataRow("A192GCM", 24, 12, 16, JweContentEncryptionFamily.AesGcm)]
    [DataRow("A256GCM", 32, 12, 16, JweContentEncryptionFamily.AesGcm)]
    [DataRow("XC20P", 32, 24, 16, JweContentEncryptionFamily.XChaCha20Poly1305)]
    public void JweContentEncryption_FromWellKnownName_PinsAllImplemented(
        string wireName,
        int expectedCekByteLength,
        int expectedIvByteLength,
        int expectedTagByteLength,
        JweContentEncryptionFamily expectedFamily)
    {
        JweContentEncryption? descriptor = JweContentEncryption.FromWellKnownName(wireName);

        Assert.IsNotNull(descriptor,
            $"'{wireName}' is an implemented content encryption algorithm and must map to a descriptor.");
        Assert.AreEqual(wireName, descriptor.Value.Name,
            "The descriptor must carry the wire enc identifier verbatim.");
        Assert.AreEqual(expectedCekByteLength, descriptor.Value.CekByteLength,
            $"'{wireName}' CEK length must match RFC 7518 §5.2/§5.3.");
        Assert.AreEqual(expectedIvByteLength, descriptor.Value.IvByteLength,
            $"'{wireName}' IV length must be 16 for CBC, 12 for GCM, and 24 for XC20P.");
        Assert.AreEqual(expectedTagByteLength, descriptor.Value.TagByteLength,
            $"'{wireName}' authentication tag length must match the specification.");
        Assert.AreEqual(expectedFamily, descriptor.Value.Family,
            $"'{wireName}' must carry its AEAD construction family.");
    }


    [TestMethod]
    [DataRow("RSA-OAEP")]
    [DataRow("A128CBC")]
    [DataRow("not-an-enc")]
    public void JweContentEncryption_FromWellKnownName_ReturnsNullForUnknown(string wireName)
    {
        JweContentEncryption? descriptor = JweContentEncryption.FromWellKnownName(wireName);

        Assert.IsNull(descriptor,
            $"'{wireName}' is not an implemented content encryption algorithm and must map to null.");
    }


    [TestMethod]
    [DataRow(null)]
    [DataRow("")]
    [DataRow("   ")]
    public void JweContentEncryption_FromWellKnownName_ThrowsOnNullOrWhitespace(string? wireName)
    {
        Assert.Throws<ArgumentException>(() => JweContentEncryption.FromWellKnownName(wireName!),
            "A null or whitespace enc string must be rejected at the parse boundary.");
    }
}
