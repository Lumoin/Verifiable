using System;
using Verifiable.Apdu;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Exhaustive tests for <see cref="BerTlvWriter"/> — our own iterative BER-TLV encoder. Covers one- and
/// two-byte tags, every definite-length form and its boundaries (short, <c>0x81</c>, <c>0x82</c>), value
/// and ASCII writing, the constructed-element header, and the size helpers, with a round trip back
/// through <see cref="ApduReader"/> to prove the encoding is what the parser reads.
/// </summary>
[TestClass]
internal sealed class BerTlvWriterTests
{
    [TestMethod]
    public void WritesOneByteTag()
    {
        byte[] buffer = new byte[4];
        var writer = new BerTlvWriter(buffer);

        writer.WriteTag(0x60);

        Assert.AreEqual(1, writer.Written, "A one-byte tag writes one byte.");
        Assert.AreEqual("60", Convert.ToHexString(buffer.AsSpan(0, writer.Written)), "The tag byte must be written verbatim.");
    }


    [TestMethod]
    public void WritesTwoByteTag()
    {
        byte[] buffer = new byte[4];
        var writer = new BerTlvWriter(buffer);

        writer.WriteTag(0x5F1F);

        Assert.AreEqual(2, writer.Written, "A two-byte tag writes two bytes, high byte first.");
        Assert.AreEqual("5F1F", Convert.ToHexString(buffer.AsSpan(0, writer.Written)), "The two-byte tag must be big-endian.");
    }


    [TestMethod]
    [DataRow(0, "00")]
    [DataRow(1, "01")]
    [DataRow(127, "7F")]
    public void WritesShortFormLength(int length, string expected)
    {
        AssertLengthEncodingRoundTrips(length, expected);
    }


    [TestMethod]
    [DataRow(128, "8180")]
    [DataRow(200, "81C8")]
    [DataRow(255, "81FF")]
    public void WritesLongFormSingleByteLength(int length, string expected)
    {
        AssertLengthEncodingRoundTrips(length, expected);
    }


    [TestMethod]
    [DataRow(256, "820100")]
    [DataRow(4660, "821234")]
    [DataRow(65535, "82FFFF")]
    public void WritesLongFormTwoByteLength(int length, string expected)
    {
        AssertLengthEncodingRoundTrips(length, expected);
    }


    [TestMethod]
    public void WriteElementProducesTagLengthValue()
    {
        byte[] buffer = new byte[8];
        var writer = new BerTlvWriter(buffer);

        writer.WriteElement(0x5F1F, [0x41, 0x42]);

        Assert.AreEqual("5F1F024142", Convert.ToHexString(buffer.AsSpan(0, writer.Written)),
            "A primitive element is tag, length, then value.");
    }


    [TestMethod]
    public void WriteAsciiEncodesAsciiBytes()
    {
        byte[] buffer = new byte[8];
        var writer = new BerTlvWriter(buffer);

        writer.WriteAscii("0106");

        Assert.AreEqual("30313036", Convert.ToHexString(buffer.AsSpan(0, writer.Written)),
            "WriteAscii must write the ASCII code points.");
    }


    [TestMethod]
    public void WritesConstructedElementHeaderThenContent()
    {
        byte[] buffer = new byte[16];
        var writer = new BerTlvWriter(buffer);

        //60 { 5C 02 6175 }
        writer.WriteHeader(0x60, BerTlvWriter.ElementSize(0x5C, 2));
        writer.WriteElement(0x5C, [0x61, 0x75]);

        ReadOnlySpan<byte> encoded = buffer.AsSpan(0, writer.Written);
        Assert.AreEqual("60045C026175", Convert.ToHexString(encoded), "The constructed element must wrap its content.");

        //And it round-trips through the parser.
        var reader = new ApduReader(encoded);
        Assert.AreEqual((byte)0x60, reader.ReadByte(), "Outer tag.");
        Assert.AreEqual(4, reader.ReadTlvLength(), "Outer length.");
        Assert.AreEqual((byte)0x5C, reader.ReadByte(), "Inner tag.");
        Assert.AreEqual(2, reader.ReadTlvLength(), "Inner length.");
        Assert.AreEqual("6175", Convert.ToHexString(reader.ReadBytes(2)), "Inner value.");
    }


    [TestMethod]
    public void TagSizeCountsTagBytes()
    {
        Assert.AreEqual(1, BerTlvWriter.TagSize(0x60), "A one-byte tag is one byte.");
        Assert.AreEqual(1, BerTlvWriter.TagSize(0xFF), "0xFF is the largest one-byte tag.");
        Assert.AreEqual(2, BerTlvWriter.TagSize(0x5F1F), "A two-byte tag is two bytes.");
    }


    [TestMethod]
    public void LengthFieldSizeMatchesEachForm()
    {
        Assert.AreEqual(1, BerTlvWriter.LengthFieldSize(0), "Length 0 is short form.");
        Assert.AreEqual(1, BerTlvWriter.LengthFieldSize(127), "Length 127 is the largest short form.");
        Assert.AreEqual(2, BerTlvWriter.LengthFieldSize(128), "Length 128 needs the 0x81 form.");
        Assert.AreEqual(2, BerTlvWriter.LengthFieldSize(255), "Length 255 is the largest 0x81 form.");
        Assert.AreEqual(3, BerTlvWriter.LengthFieldSize(256), "Length 256 needs the 0x82 form.");
        Assert.AreEqual(3, BerTlvWriter.LengthFieldSize(65535), "Length 65535 is the largest 0x82 form.");
    }


    [TestMethod]
    public void ElementSizeSumsTagLengthAndContent()
    {
        Assert.AreEqual(1 + 1 + 4, BerTlvWriter.ElementSize(0x60, 4), "One-byte tag, short length, four content bytes.");
        Assert.AreEqual(2 + 1 + 4, BerTlvWriter.ElementSize(0x5F01, 4), "Two-byte tag, short length, four content bytes.");
        Assert.AreEqual(1 + 2 + 200, BerTlvWriter.ElementSize(0x60, 200), "One-byte tag, 0x81 length, 200 content bytes.");
        Assert.AreEqual(1 + 3 + 300, BerTlvWriter.ElementSize(0x60, 300), "One-byte tag, 0x82 length, 300 content bytes.");
    }


    /// <summary>Writes <paramref name="length"/> as a length field, asserts the bytes, and reads it back through <see cref="ApduReader"/>.</summary>
    private static void AssertLengthEncodingRoundTrips(int length, string expectedHex)
    {
        byte[] buffer = new byte[4];
        var writer = new BerTlvWriter(buffer);

        writer.WriteLength(length);

        ReadOnlySpan<byte> encoded = buffer.AsSpan(0, writer.Written);
        Assert.AreEqual(expectedHex, Convert.ToHexString(encoded), $"Length {length} must encode as {expectedHex}.");

        var reader = new ApduReader(encoded);
        Assert.AreEqual(length, reader.ReadTlvLength(), $"Length {length} must read back through ApduReader.");
    }
}
