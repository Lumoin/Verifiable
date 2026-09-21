using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Tag-level tests for <see cref="CryptoTags.ProtocolFreshnessValue"/> — the algorithm-free
/// entry for an unguessable value minted for a protocol exchange, such as an OAuth
/// <c>state</c>, an OpenID Connect <c>nonce</c>, or a PKCE <c>code_verifier</c>.
/// </summary>
[TestClass]
internal sealed class CryptoTagsProtocolFreshnessTests
{
    [TestMethod]
    public void ProtocolFreshnessValueCarriesNoncePurposeAndRawEncodingAndNoAlgorithm()
    {
        Tag tag = CryptoTags.ProtocolFreshnessValue;

        Assert.AreEqual(Purpose.Nonce, tag.Get<Purpose>());
        Assert.AreEqual(EncodingScheme.Raw, tag.Get<EncodingScheme>());
        Assert.IsFalse(tag.TryGet<CryptoAlgorithm>(out _),
            "A protocol freshness value is not key material and is not an input to any named " +
            "primitive, so the tag must carry no CryptoAlgorithm.");
    }
}
