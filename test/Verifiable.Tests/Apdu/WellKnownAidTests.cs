using System;

using Verifiable.Apdu;

namespace Verifiable.Tests.Apdu;

[TestClass]
internal sealed class WellKnownAidTests
{
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public void PivAidHasCorrectValue()
    {
        ReadOnlySpan<byte> piv = WellKnownAid.Piv;

        Assert.HasCount(9, piv);
        Assert.AreEqual((byte)0xA0, piv[0]);
        Assert.AreEqual((byte)0x00, piv[8]);
    }

    [TestMethod]
    public void MrtdAidHasCorrectValue()
    {
        ReadOnlySpan<byte> mrtd = WellKnownAid.Mrtd;

        Assert.HasCount(7, mrtd);
        Assert.AreEqual((byte)0xA0, mrtd[0]);
        Assert.AreEqual((byte)0x01, mrtd[6]);
    }

    [TestMethod]
    public void FidoAidHasCorrectValue()
    {
        ReadOnlySpan<byte> fido = WellKnownAid.Fido;

        Assert.HasCount(8, fido);
        Assert.AreEqual((byte)0xA0, fido[0]);
        Assert.AreEqual((byte)0x01, fido[7]);
    }

    [TestMethod]
    public void ExactMatchSucceeds()
    {
        byte[] candidate = [0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00];

        Assert.IsTrue(WellKnownAid.Matches(candidate, WellKnownAid.Piv));
    }

    [TestMethod]
    public void PrefixMatchSucceeds()
    {
        //PIV RID only (first 5 bytes) matches the full PIV AID.
        byte[] ridOnly = [0xA0, 0x00, 0x00, 0x03, 0x08];

        Assert.IsTrue(WellKnownAid.Matches(ridOnly, WellKnownAid.Piv));
    }

    [TestMethod]
    public void LongerCandidateDoesNotMatch()
    {
        byte[] longer = [0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00];

        Assert.IsFalse(WellKnownAid.Matches(longer, WellKnownAid.Piv));
    }

    [TestMethod]
    public void DifferentAidDoesNotMatch()
    {
        Assert.IsFalse(WellKnownAid.Matches(WellKnownAid.Fido, WellKnownAid.Piv));
    }

    [TestMethod]
    public void PivAidFromTraceMatchesWellKnown()
    {
        //From the CardForensics trace exchange #5:
        //AID: A0 00 00 03 08 00 00 10 00 (labeled "NIST PIV").
        byte[] fromTrace = [0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00];

        Assert.IsTrue(WellKnownAid.Matches(fromTrace, WellKnownAid.Piv));
    }

    [TestMethod]
    public void EmptyCandidateMatchesAnything()
    {
        Assert.IsTrue(WellKnownAid.Matches(ReadOnlySpan<byte>.Empty, WellKnownAid.Piv));
    }
}
