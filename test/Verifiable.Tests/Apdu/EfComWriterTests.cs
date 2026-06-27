using System;
using Verifiable.Apdu;
using Verifiable.Apdu.Lds;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Validates the EF.COM writer: it encodes byte-for-byte as Doc 9303 Appendix D.4 and round-trips
/// through <see cref="EfCom.Parse"/>. This is the first piece of the owned eMRTD producer — minting LDS
/// files ourselves rather than depending on non-redistributable sample data.
/// </summary>
[TestClass]
internal sealed class EfComWriterTests
{
    [TestMethod]
    public void WritesAppendixD4EfComByteForByte()
    {
        using ElementaryFile efCom = EfCom.Write("0106", "040000", [0x61, 0x75], BaseMemoryPool.Shared);

        Assert.AreEqual("60145F0104303130365F36063034303030305C026175",
            Convert.ToHexString(efCom.AsReadOnlySpan()),
            "EF.COM must encode byte-for-byte as Doc 9303 Appendix D.4.");
    }


    [TestMethod]
    public void RoundTripsThroughParse()
    {
        using ElementaryFile efCom = EfCom.Write("0107", "040000", [0x61, 0x6E, 0x75], BaseMemoryPool.Shared);

        EfCom parsed = EfCom.Parse(efCom.AsReadOnlySpan());

        Assert.AreEqual("0107", parsed.LdsVersion, "The LDS version must round-trip.");
        Assert.AreEqual("040000", parsed.UnicodeVersion, "The Unicode version must round-trip.");
        Assert.AreEqual("616E75", Convert.ToHexString([.. parsed.DataGroupTags]), "The data-group tag list must round-trip.");
    }
}
