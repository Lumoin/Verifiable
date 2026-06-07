using System.Formats.Cbor;
using CsCheck;
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
        Assert.AreEqual(1, item.InnerBytes.Length);
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


    //Property: decode(encode(Tag24(x))) === Tag24(x). Across the three
    //coverage regions named in the chunk plan: tagged values nested inside
    //Tag-24, Tag-24 of int-keyed maps, recursive Tag-24.

    [TestMethod]
    public void Property_RoundTripPreservesBytesAcrossPayloadShapes()
    {
        Gen.OneOf(
            GenInnerScalar,
            GenInnerIntKeyedMap,
            GenInnerTaggedValue,
            GenInnerRecursiveTag24)
            .Sample(innerBytes =>
            {
                EncodedCborItem original = EncodedCborItem.Wrap(innerBytes);

                var writer = new CborWriter();
                original.Write(writer);
                byte[] emitted = writer.Encode();

                var reader = new CborReader(emitted);
                EncodedCborItem reparsed = EncodedCborItem.Read(reader);

                if(!original.WireBytes.Span.SequenceEqual(reparsed.WireBytes.Span))
                {
                    Assert.Fail("WireBytes diverged across round-trip.");
                }
            });
    }


    //Property: Wrap(InnerBytes).Write(...) and re-parsing yields the same
    //WireBytes regardless of which path produced the wrapper (Wrap vs Read).

    [TestMethod]
    public void Property_WrapAndReadProduceEquivalentWrappersForCanonicalInner()
    {
        GenInnerIntKeyedMap.Sample(innerBytes =>
        {
            EncodedCborItem wrapped = EncodedCborItem.Wrap(innerBytes);

            var writer = new CborWriter();
            wrapped.Write(writer);
            byte[] wireFromWrap = writer.Encode();

            var reader = new CborReader(wireFromWrap);
            EncodedCborItem readBack = EncodedCborItem.Read(reader);

            var writer2 = new CborWriter();
            readBack.Write(writer2);
            byte[] wireFromRead = writer2.Encode();

            if(!wireFromWrap.AsSpan().SequenceEqual(wireFromRead))
            {
                Assert.Fail("Wrap → Read → Write should round-trip byte-for-byte.");
            }
        });
    }


    //Generators — produce raw inner-CBOR byte arrays for the three regions.

    private static readonly Gen<byte[]> GenInnerScalar =
        Gen.Int[0, 0xFFFF].Select(n =>
        {
            var w = new CborWriter();
            w.WriteInt32(n);
            return w.Encode();
        });

    //Int-keyed map — mdoc uses these in COSE structures (IssuerSigned map
    //keys are integers per ISO 18013-5 §9.1.2). Generator produces maps
    //of 1..4 entries with int keys and mixed scalar values.
    private static readonly Gen<byte[]> GenInnerIntKeyedMap =
        Gen.Dictionary(
            Gen.Int[0, 50],
            Gen.OneOf<object>(
                Gen.Int[0, 1000].Select(i => (object)i),
                Gen.String[Gen.Char.AlphaNumeric, 1, 12].Select(s => (object)s),
                Gen.Bool.Select(b => (object)b)))
        [1, 4]
        .Select(dict =>
        {
            var w = new CborWriter();
            w.WriteStartMap(dict.Count);
            foreach(var kvp in dict)
            {
                w.WriteInt32(kvp.Key);
                switch(kvp.Value)
                {
                    case int i:
                        w.WriteInt32(i);
                        break;
                    case string s:
                        w.WriteTextString(s);
                        break;
                    case bool b:
                        w.WriteBoolean(b);
                        break;
                }
            }
            w.WriteEndMap();

            return w.Encode();
        });

    //Tag 24 of a tagged value (Tag 1004 ISO 8601 date wrapping a string,
    //or Tag 0 standard date-time string, etc.) — exercises the "tagged
    //value nested inside Tag-24" coverage region.
    private static readonly Gen<byte[]> GenInnerTaggedValue =
        Gen.Int[1, 5000].Select(tagNumber =>
        {
            var w = new CborWriter();
            w.WriteTag((CborTag)tagNumber);
            w.WriteTextString("inner-payload");

            return w.Encode();
        });

    //Recursive Tag-24: an outer Tag-24 wrapper that contains a CBOR map
    //one of whose values is itself another Tag-24 wrapper. Exercises the
    //"Tag-24 contains Tag-24" recursive coverage region.
    private static readonly Gen<byte[]> GenInnerRecursiveTag24 =
        Gen.Int[0, 100].Select(payloadValue =>
        {
            //Build a nested Tag 24 wrapper first.
            var innerWriter = new CborWriter();
            innerWriter.WriteInt32(payloadValue);
            byte[] innermost = innerWriter.Encode();

            EncodedCborItem nested = EncodedCborItem.Wrap(innermost);

            //Wrap the nested Tag 24 inside a CBOR map.
            var w = new CborWriter();
            w.WriteStartMap(2);
            w.WriteInt32(0);
            w.WriteInt32(payloadValue);
            w.WriteInt32(1);
            w.WriteEncodedValue(nested.WireBytes.Span);
            w.WriteEndMap();

            return w.Encode();
        });


    private static byte[] EncodeInnerMap(Action<CborWriter> populate)
    {
        var w = new CborWriter();
        w.WriteStartMap(null);
        populate(w);
        w.WriteEndMap();

        return w.Encode();
    }
}
