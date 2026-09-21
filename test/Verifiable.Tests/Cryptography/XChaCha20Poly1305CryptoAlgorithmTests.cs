using Verifiable.Cryptography.Context;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Tests for the <see cref="CryptoAlgorithm.XChaCha20Poly1305"/> catalog row.
/// </summary>
[TestClass]
internal sealed class XChaCha20Poly1305CryptoAlgorithmTests
{
    /// <summary>
    /// The row's numeric code is 34, and reconstructing a <see cref="CryptoAlgorithm"/> from
    /// that code with <see cref="CryptoAlgorithm.FromCode(int)"/> yields the well-known instance.
    /// </summary>
    [TestMethod]
    public void CodeIsThirtyFourAndFromCodeRoundTrips()
    {
        Assert.AreEqual(34, CryptoAlgorithm.XChaCha20Poly1305.Algorithm);
        Assert.AreEqual(CryptoAlgorithm.XChaCha20Poly1305, CryptoAlgorithm.FromCode(34));
    }


    /// <summary>
    /// <see cref="CryptoAlgorithm.ToString"/> and <see cref="CryptoAlgorithmNames.GetName(CryptoAlgorithm)"/>
    /// both give the row's member name.
    /// </summary>
    [TestMethod]
    public void ToStringAndGetNameGiveTheMemberName()
    {
        Assert.AreEqual(nameof(CryptoAlgorithm.XChaCha20Poly1305), CryptoAlgorithm.XChaCha20Poly1305.ToString());
        Assert.AreEqual(nameof(CryptoAlgorithm.XChaCha20Poly1305), CryptoAlgorithmNames.GetName(CryptoAlgorithm.XChaCha20Poly1305));
    }


    /// <summary>
    /// The row is distinct from <see cref="CryptoAlgorithm.Unknown"/>, from
    /// <see cref="CryptoAlgorithm.X25519"/>, and from <see cref="CryptoAlgorithm.Aes256"/>.
    /// </summary>
    [TestMethod]
    public void DiffersFromUnknownX25519AndAes256()
    {
        Assert.AreNotEqual(CryptoAlgorithm.Unknown, CryptoAlgorithm.XChaCha20Poly1305);
        Assert.AreNotEqual(CryptoAlgorithm.X25519, CryptoAlgorithm.XChaCha20Poly1305);
        Assert.AreNotEqual(CryptoAlgorithm.Aes256, CryptoAlgorithm.XChaCha20Poly1305);
    }


    /// <summary>
    /// A <see cref="Tag"/> created from the row with <see cref="Purpose.Encryption"/> reports the
    /// row as its algorithm.
    /// </summary>
    [TestMethod]
    public void TagCreatedWithEncryptionPurposeReportsTheAlgorithm()
    {
        Tag tag = Tag.Create(CryptoAlgorithm.XChaCha20Poly1305).With(Purpose.Encryption);

        Assert.AreEqual(CryptoAlgorithm.XChaCha20Poly1305, tag.Get<CryptoAlgorithm>());
    }
}
