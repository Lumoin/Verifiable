using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Tests.Cryptography;

[TestClass]
internal sealed class CryptoTagsHmacTests
{
    [TestMethod]
    public void HmacSha256KeyCarriesHashAlgorithmAndPurpose()
    {
        Tag tag = CryptoTags.HmacSha256Key;
        Assert.AreEqual(HashAlgorithmName.SHA256, tag.Get<HashAlgorithmName>());
        Assert.AreEqual(Purpose.Hmac, tag.Get<Purpose>());
        Assert.AreEqual(EncodingScheme.Raw, tag.Get<EncodingScheme>());
    }


    [TestMethod]
    public void HmacSha384KeyCarriesHashAlgorithmAndPurpose()
    {
        Tag tag = CryptoTags.HmacSha384Key;
        Assert.AreEqual(HashAlgorithmName.SHA384, tag.Get<HashAlgorithmName>());
        Assert.AreEqual(Purpose.Hmac, tag.Get<Purpose>());
    }


    [TestMethod]
    public void HmacSha512KeyCarriesHashAlgorithmAndPurpose()
    {
        Tag tag = CryptoTags.HmacSha512Key;
        Assert.AreEqual(HashAlgorithmName.SHA512, tag.Get<HashAlgorithmName>());
        Assert.AreEqual(Purpose.Hmac, tag.Get<Purpose>());
    }


    [TestMethod]
    public void HmacValueTagsMirrorKeyTagsBytewise()
    {
        Assert.AreEqual(
            CryptoTags.HmacSha256Key.Get<HashAlgorithmName>(),
            CryptoTags.HmacSha256Value.Get<HashAlgorithmName>());
        Assert.AreEqual(
            CryptoTags.HmacSha256Key.Get<Purpose>(),
            CryptoTags.HmacSha256Value.Get<Purpose>());
    }


    [TestMethod]
    public void Sha256DigestCarriesHashAlgorithmAndPurposeDigest()
    {
        Tag tag = CryptoTags.Sha256Digest;
        Assert.AreEqual(HashAlgorithmName.SHA256, tag.Get<HashAlgorithmName>());
        Assert.AreEqual(Purpose.Digest, tag.Get<Purpose>());
    }


    [TestMethod]
    public void Sha384DigestCarriesHashAlgorithmAndPurposeDigest()
    {
        Tag tag = CryptoTags.Sha384Digest;
        Assert.AreEqual(HashAlgorithmName.SHA384, tag.Get<HashAlgorithmName>());
        Assert.AreEqual(Purpose.Digest, tag.Get<Purpose>());
    }


    [TestMethod]
    public void Sha512DigestCarriesHashAlgorithmAndPurposeDigest()
    {
        Tag tag = CryptoTags.Sha512Digest;
        Assert.AreEqual(HashAlgorithmName.SHA512, tag.Get<HashAlgorithmName>());
        Assert.AreEqual(Purpose.Digest, tag.Get<Purpose>());
    }
}
