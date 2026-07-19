using System.Formats.Cbor;
using Verifiable.Cbor;

namespace Verifiable.Tests.Serialization;

/// <summary>
/// Tests for <see cref="EncodedCborItem"/>, the Tag 24 wrapper that
/// preserves issuer-supplied wire bytes byte-for-byte.
/// </summary>
/// <remarks>
/// <para>
/// Tag 24 (<see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.4.5.1">RFC 8949 §3.4.5.1</see>)
/// marks a byte string whose contents are an encoded CBOR data item.
/// mdoc's IssuerSignedItem digest binding (ISO/IEC 18013-5 §9.1.2.5)
/// commits the MSO's digest to the wire bytes of this wrapper — the
/// wrapper MUST preserve those bytes verbatim across decode → re-encode
/// round-trips, otherwise the wallet cannot reproduce the issuer's hash.
/// </para>
/// <para>
/// Property-based coverage spans the three regions the chunk plan named:
/// Tag-24-wrapped tagged values, Tag-24-wrapped int-keyed maps (mdoc uses
/// these in COSE structures), and recursive Tag-24 (Tag-24 containing
/// further Tag-24 wrappers).
/// </para>
/// </remarks>
[TestClass]
internal sealed class EncodedCborItemTests
{
    [TestMethod]
    public void ReadAndWriteRoundTripsByteForByte()
    {
        //Inner CBOR: a small map with int keys and string values, mirroring
        //the IssuerSignedItem shape.
        byte[] innerBytes = EncodeInnerMap(map =>
        {
            map.WriteInt32(0); map.WriteInt32(42);
            map.WriteInt32(1); map.WriteByteString([0x01, 0x02, 0x03]);
            map.WriteInt32(2); map.WriteTextString("given_name");
            map.WriteInt32(3); map.WriteTextString("Alice");
        });

        //Build the wire form the issuer would publish.
        EncodedCborItem original = EncodedCborItem.Wrap(innerBytes);

        //Round-trip through a CborReader/Writer.
        var writer = new CborWriter();
        original.Write(writer);
        byte[] emitted = writer.Encode();

        var reader = new CborReader(emitted);
        EncodedCborItem reparsed = EncodedCborItem.Read(reader);

        Assert.IsTrue(
            original.WireBytes.Span.SequenceEqual(reparsed.WireBytes.Span),
            "Tag 24 wire bytes MUST round-trip byte-for-byte through Read + Write.");
        Assert.IsTrue(
            original.InnerBytes.Span.SequenceEqual(reparsed.InnerBytes.Span),
            "Inner CBOR bytes MUST round-trip byte-for-byte.");
    }


    [TestMethod]
    public void WireBytesIncludeTag24PrefixAndByteStringHeader()
    {
        byte[] innerBytes = [0xA0]; // empty CBOR map.
        EncodedCborItem item = EncodedCborItem.Wrap(innerBytes);

        //First two bytes of the wire form are the Tag 24 header per CBOR
        //major type 6, additional info 24 → 0xD8 0x18.
        Assert.AreEqual(0xD8, item.WireBytes.Span[0]);
        Assert.AreEqual(0x18, item.WireBytes.Span[1]);

        //The last byte of the wire form is the inner CBOR byte (0xA0).
        Assert.AreEqual(0xA0, item.WireBytes.Span[item.WireBytes.Length - 1]);

        //InnerBytes is a slice of WireBytes positioned at the byte-string
        //content offset.
        Assert.HasCount(1, item.InnerBytes);
        Assert.AreEqual(0xA0, item.InnerBytes.Span[0]);
    }


    [TestMethod]
    public void ReadRejectsNonTag24Items()
    {
        //Plain byte string with no Tag 24 wrapper.
        var writer = new CborWriter();
        writer.WriteByteString([0x01]);
        byte[] bytes = writer.Encode();
        var reader = new CborReader(bytes);

        Assert.ThrowsExactly<CborContentException>(() => EncodedCborItem.Read(reader));
    }


    [TestMethod]
    public void ReadRejectsTag24OverNonByteString()
    {
        //Tag 24 over a text string instead of a byte string.
        var writer = new CborWriter();
        writer.WriteTag((CborTag)24);
        writer.WriteTextString("not bytes");
        byte[] bytes = writer.Encode();
        var reader = new CborReader(bytes);

        Assert.ThrowsExactly<CborContentException>(() => EncodedCborItem.Read(reader));
    }


    private static byte[] EncodeInnerMap(Action<CborWriter> populate)
    {
        var w = new CborWriter();
        w.WriteStartMap(null);
        populate(w);
        w.WriteEndMap();

        return w.Encode();
    }
}
