using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Cryptography.Context;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Tag-level tests for the mdoc operation-component entries in
/// <see cref="CryptoTags"/>.
/// </summary>
/// <remarks>
/// <para>
/// The round-trip test through an actual <c>IssuerSignedItem</c> wire shape
/// is deferred to M.1 per the chunk plan. P.3 verifies only that the tag
/// composes the expected <see cref="Purpose"/> / <see cref="EncodingScheme"/>
/// pair and that allocation through <see cref="Salt.Generate"/> succeeds at
/// the ISO/IEC 18013-5 §9.1.2.5 minimum length.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CryptoTagsMdocTests
{
    [TestMethod]
    public void MdocIssuerSignedItemRandomCarriesSaltPurposeAndRawEncoding()
    {
        Tag tag = CryptoTags.MdocIssuerSignedItemRandom;

        Assert.AreEqual(Purpose.Salt, tag.Get<Purpose>(),
            "ISO/IEC 18013-5 §9.1.2.5 Random is salt-shaped " +
            "(precomputation prevention) — Tag must carry Purpose.Salt.");
        Assert.AreEqual(EncodingScheme.Raw, tag.Get<EncodingScheme>());
    }


    [TestMethod]
    public void MdocIssuerSignedItemRandomAllocatesAtIsoMinimumLength()
    {
        //ISO/IEC 18013-5 §9.1.2.5: Random is at least 16 bytes.
        const int IsoMinimumLength = 16;

        using Salt salt = TestSalts.Generate(
            IsoMinimumLength, CryptoTags.MdocIssuerSignedItemRandom, BaseMemoryPool.Shared);

        Assert.AreEqual(IsoMinimumLength, salt.Length);
        Assert.AreEqual(Purpose.Salt, salt.Tag.Get<Purpose>(),
            "Salt allocated with the mdoc tag must retain the Salt purpose.");
    }


    [TestMethod]
    public void TwoFreshlyGeneratedMdocRandomsDifferInValue()
    {
        //ISO 18013-5 §9.1.2.5 mandates uniqueness per IssuerSignedItem so
        //that identical claim values across credentials produce distinct
        //digests. Two fresh allocations must not collide for any
        //reasonably random generator — a 16-byte collision would be a
        //2^-128 event and is a real failure if it happens.
        using Salt first = MdocTestFixtures.ItemRandomSalt();
        using Salt second = MdocTestFixtures.ItemRandomSalt();

        Assert.IsFalse(first.AsReadOnlySpan().SequenceEqual(second.AsReadOnlySpan()),
            "Two freshly-generated mdoc IssuerSignedItem randoms must differ; " +
            "collision suggests a broken entropy source.");
    }
}
