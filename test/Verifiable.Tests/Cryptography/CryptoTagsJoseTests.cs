using System.Linq;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Tests for <see cref="CryptoTags.JoseEncodedProtectedHeader"/> — the JAdES/JOSE substrate carrier tag mirroring
/// <see cref="CryptoTags.CoseEncodedProtectedHeader"/>'s pattern.
/// </summary>
[TestClass]
internal sealed class CryptoTagsJoseTests
{
    [TestMethod]
    public void JoseEncodedProtectedHeaderCarriesDataPurposeAndJoseEncoding()
    {
        Tag tag = CryptoTags.JoseEncodedProtectedHeader;

        Assert.AreEqual(Purpose.Data, tag.Get<Purpose>(),
            "The base64url protected-header bytes are opaque signed-input data, not a signature/key value.");
        Assert.AreEqual(EncodingScheme.Jose, tag.Get<EncodingScheme>());
    }


    [TestMethod]
    public void JoseEncodedProtectedHeaderIsDistinctFromCoseEncodedProtectedHeader()
    {
        //The two carriers share Purpose.Data but differ by EncodingScheme -- CBOR-shaped vs. JSON-shaped
        //envelopes are not interchangeable, mirroring the Cbor/Cose distinction this tag's own remarks cite.
        Assert.AreEqual(EncodingScheme.Cose, CryptoTags.CoseEncodedProtectedHeader.Get<EncodingScheme>());
        Assert.AreEqual(EncodingScheme.Jose, CryptoTags.JoseEncodedProtectedHeader.Get<EncodingScheme>());
        Assert.AreNotEqual(
            CryptoTags.CoseEncodedProtectedHeader.Get<EncodingScheme>(),
            CryptoTags.JoseEncodedProtectedHeader.Get<EncodingScheme>());
    }


    [TestMethod]
    public void AllTagsContainsJoseEncodedProtectedHeaderExactlyOnce()
    {
        //CBOM generation (DeclarativeCbomGenerator) enumerates AllTags declaratively; a tag omitted here
        //is invisible to the CBOM, so membership is load-bearing, not cosmetic. Matched by composition
        //(Purpose + EncodingScheme) rather than Tag equality, mirroring how every call site reads a tag.
        int occurrences = CryptoTags.AllTags.Count(tag =>
            tag.Get<Purpose>() == Purpose.Data && tag.Get<EncodingScheme>() == EncodingScheme.Jose);

        Assert.AreEqual(1, occurrences);
    }
}
