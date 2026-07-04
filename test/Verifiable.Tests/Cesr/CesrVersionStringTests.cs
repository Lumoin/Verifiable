using Verifiable.Cesr;

namespace Verifiable.Tests.Cesr;

/// <summary>
/// Tests for <see cref="CesrVersionString"/> — locating and decoding the version string that prefixes an
/// interleaved non-native serialization. The serialization kind and the total length are read from both the
/// version 2.XX format (base-64 length, <c>.</c> terminator) and the legacy version 1.XX format (hexadecimal
/// length, <c>_</c> terminator); a buffer without a version string yields no match.
/// </summary>
[TestClass]
internal sealed class CesrVersionStringTests
{
    /// <summary>
    /// A version 2.XX version string is found, with its serialization kind and base-64 length.
    /// </summary>
    [TestMethod]
    public void FindsVersion2VersionString()
    {
        //KERI, protocol 2.00, genus 2.00, CBOR, four-character base-64 length 'ABAA' = 1 * 64^2 = 4096, terminator '.'.
        bool found = CesrVersionString.TryFind("{\"v\":\"KERICAACAACBORABAA.\"}", out CesrSerializationKind kind, out int totalLength, out int matchStart);

        Assert.IsTrue(found);
        Assert.AreEqual(CesrSerializationKind.Cbor, kind);
        Assert.AreEqual(4096, totalLength);
        Assert.AreEqual(6, matchStart, "The version string begins after the leading {\"v\":\" JSON framing.");
    }


    /// <summary>
    /// A legacy version 1.XX version string is found, with its serialization kind and hexadecimal length.
    /// </summary>
    [TestMethod]
    public void FindsLegacyVersion1VersionString()
    {
        //KERI, version 1.0, MGPK, length 0x000180 = 384, terminator '_'.
        bool found = CesrVersionString.TryFind("KERI10MGPK000180_rest", out CesrSerializationKind kind, out int totalLength, out int matchStart);

        Assert.IsTrue(found);
        Assert.AreEqual(CesrSerializationKind.Mgpk, kind);
        Assert.AreEqual(384, totalLength);
        Assert.AreEqual(0, matchStart, "The bare version string begins at the start of the text.");
    }


    /// <summary>
    /// Text with no version string yields no match.
    /// </summary>
    [TestMethod]
    public void ReturnsFalseWhenNoVersionString()
    {
        bool found = CesrVersionString.TryFind("{\"x\":\"no version string here\"}", out CesrSerializationKind kind, out int totalLength, out _);

        Assert.IsFalse(found);
        Assert.AreEqual(CesrSerializationKind.None, kind);
        Assert.AreEqual(0, totalLength);
    }


    /// <summary>
    /// Stamping a length into a version 2.XX string replaces only the base-64 length field: the ACDC specification's
    /// expanded Accreditation version string restamped to the compact byte count yields its compact version string.
    /// </summary>
    [TestMethod]
    public void StampsVersion2Length()
    {
        //The Accreditation ACDC's expanded form declares AAKX; restamped to the compact size 375 it becomes AAF3.
        Assert.AreEqual("ACDCCAACAAJSONAAF3.", CesrVersionString.WithLength("ACDCCAACAAJSONAAKX.", 375));
    }


    /// <summary>
    /// Stamping a length into a legacy version 1.XX string replaces only the hexadecimal length field.
    /// </summary>
    [TestMethod]
    public void StampsLegacyVersion1Length()
    {
        Assert.AreEqual("KERI10MGPK000180_", CesrVersionString.WithLength("KERI10MGPK000000_", 384));
    }


    /// <summary>
    /// A stamped length reads back as the same byte count.
    /// </summary>
    [TestMethod]
    public void StampedLengthRoundTrips()
    {
        bool found = CesrVersionString.TryFind(CesrVersionString.WithLength("ACDCCAACAAJSONAAAA.", 375), out _, out int totalLength, out _);

        Assert.IsTrue(found);
        Assert.AreEqual(375, totalLength);
    }
}
