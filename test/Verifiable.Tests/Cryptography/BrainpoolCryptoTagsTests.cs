using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Tag-composition tests for the four Brainpool r1 curves landed in Q.2 —
/// BP-256r1, BP-320r1, BP-384r1, BP-512r1.
/// </summary>
/// <remarks>
/// <para>
/// Each Brainpool curve produces three tags: a verification public-key tag
/// (compressed encoding), a signing private-key tag (raw scalar), and a
/// signature tag (IEEE P1363 r || s). All three share the curve discriminator
/// and differ only in <see cref="Purpose"/> and <see cref="EncodingScheme"/>.
/// </para>
/// </remarks>
[TestClass]
internal sealed class BrainpoolCryptoTagsTests
{
    [TestMethod]
    public void BrainpoolP256r1TagsCarryExpectedComposition()
    {
        AssertEcKeyTagComposition(
            CryptoTags.BrainpoolP256r1PublicKey,
            CryptoTags.BrainpoolP256r1PrivateKey,
            CryptoTags.BrainpoolP256r1Signature,
            CryptoAlgorithm.BrainpoolP256r1);
    }


    [TestMethod]
    public void BrainpoolP320r1TagsCarryExpectedComposition()
    {
        AssertEcKeyTagComposition(
            CryptoTags.BrainpoolP320r1PublicKey,
            CryptoTags.BrainpoolP320r1PrivateKey,
            CryptoTags.BrainpoolP320r1Signature,
            CryptoAlgorithm.BrainpoolP320r1);
    }


    [TestMethod]
    public void BrainpoolP384r1TagsCarryExpectedComposition()
    {
        AssertEcKeyTagComposition(
            CryptoTags.BrainpoolP384r1PublicKey,
            CryptoTags.BrainpoolP384r1PrivateKey,
            CryptoTags.BrainpoolP384r1Signature,
            CryptoAlgorithm.BrainpoolP384r1);
    }


    [TestMethod]
    public void BrainpoolP512r1TagsCarryExpectedComposition()
    {
        AssertEcKeyTagComposition(
            CryptoTags.BrainpoolP512r1PublicKey,
            CryptoTags.BrainpoolP512r1PrivateKey,
            CryptoTags.BrainpoolP512r1Signature,
            CryptoAlgorithm.BrainpoolP512r1);
    }


    [TestMethod]
    public void BrainpoolAlgorithmNamesRoundTripThroughCryptoAlgorithmNames()
    {
        Assert.AreEqual(nameof(CryptoAlgorithm.BrainpoolP256r1),
            CryptoAlgorithmNames.GetName(CryptoAlgorithm.BrainpoolP256r1));
        Assert.AreEqual(nameof(CryptoAlgorithm.BrainpoolP320r1),
            CryptoAlgorithmNames.GetName(CryptoAlgorithm.BrainpoolP320r1));
        Assert.AreEqual(nameof(CryptoAlgorithm.BrainpoolP384r1),
            CryptoAlgorithmNames.GetName(CryptoAlgorithm.BrainpoolP384r1));
        Assert.AreEqual(nameof(CryptoAlgorithm.BrainpoolP512r1),
            CryptoAlgorithmNames.GetName(CryptoAlgorithm.BrainpoolP512r1));
    }


    private static void AssertEcKeyTagComposition(Tag publicKeyTag, Tag privateKeyTag, Tag signatureTag, CryptoAlgorithm expectedAlgorithm)
    {
        Assert.AreEqual(expectedAlgorithm, publicKeyTag.Get<CryptoAlgorithm>());
        Assert.AreEqual(Purpose.Verification, publicKeyTag.Get<Purpose>());
        Assert.AreEqual(EncodingScheme.EcCompressed, publicKeyTag.Get<EncodingScheme>());

        Assert.AreEqual(expectedAlgorithm, privateKeyTag.Get<CryptoAlgorithm>());
        Assert.AreEqual(Purpose.Signing, privateKeyTag.Get<Purpose>());
        Assert.AreEqual(EncodingScheme.Raw, privateKeyTag.Get<EncodingScheme>());

        Assert.AreEqual(expectedAlgorithm, signatureTag.Get<CryptoAlgorithm>());
        Assert.AreEqual(Purpose.Signature, signatureTag.Get<Purpose>());
        Assert.AreEqual(EncodingScheme.Raw, signatureTag.Get<EncodingScheme>());
    }
}
