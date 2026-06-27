using System;
using Verifiable.Apdu.Lds;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Validates EF.COM parsing against the EF.COM read in the ICAO Doc 9303 Part 11 Appendix D.4
/// worked example.
/// </summary>
[TestClass]
internal sealed class EfComTests
{
    public required TestContext TestContext { get; set; }


    [TestMethod]
    public void ParsesTheAppendixD4EfCom()
    {
        //The EF.COM reassembled by the Appendix D.4 read example.
        EfCom efCom = EfCom.Parse(Convert.FromHexString("60145F0104303130365F36063034303030305C026175"));

        Assert.AreEqual("0106", efCom.LdsVersion, "The LDS version object DO'5F01' must decode to its ASCII value.");
        Assert.AreEqual("040000", efCom.UnicodeVersion, "The Unicode version object DO'5F36' must decode to its ASCII value.");

        byte[] tags = [.. efCom.DataGroupTags];
        Assert.AreEqual("6175", Convert.ToHexString(tags), "The tag list DO'5C' must list the present data-group tags (DG1, DG2).");
    }
}
