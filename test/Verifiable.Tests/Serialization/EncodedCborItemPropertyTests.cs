using System.Formats.Cbor;
using CsCheck;
using Verifiable.Cbor;

namespace Verifiable.Tests.Serialization;

/// <summary>
/// Property-based tests (CsCheck) for <see cref="EncodedCborItem"/>: the round-trip invariant that
/// decoding and re-encoding a Tag 24 wrapper reproduces the original wire bytes byte-for-byte, checked
/// across arbitrary inner-CBOR payload shapes rather than the hand-picked vectors in
/// <see cref="EncodedCborItemTests"/>.
/// </summary>
[TestClass]
internal sealed class EncodedCborItemPropertyTests
{
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
}
