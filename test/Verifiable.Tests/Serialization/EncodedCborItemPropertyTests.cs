using System.Buffers;
using Lumoin.Veritas.Cbor;
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

                var buffer = new ArrayBufferWriter<byte>();
                var writer = new CborWriter(buffer, CborOptions.Strict);
                original.Write(writer);
                byte[] emitted = buffer.WrittenSpan.ToArray();

                var reader = new CborReader(emitted, CborOptions.Strict);
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

            var buffer = new ArrayBufferWriter<byte>();
            var writer = new CborWriter(buffer, CborOptions.Strict);
            wrapped.Write(writer);
            byte[] wireFromWrap = buffer.WrittenSpan.ToArray();

            var reader = new CborReader(wireFromWrap, CborOptions.Strict);
            EncodedCborItem readBack = EncodedCborItem.Read(reader);

            var buffer2 = new ArrayBufferWriter<byte>();
            var writer2 = new CborWriter(buffer2, CborOptions.Strict);
            readBack.Write(writer2);
            byte[] wireFromRead = buffer2.WrittenSpan.ToArray();

            if(!wireFromWrap.AsSpan().SequenceEqual(wireFromRead))
            {
                Assert.Fail("Wrap → Read → Write should round-trip byte-for-byte.");
            }
        });
    }


    //Generators — produce raw inner-CBOR byte arrays for the three regions.

    private static Gen<byte[]> GenInnerScalar { get; } =
        Gen.Int[0, 0xFFFF].Select(n =>
        {
            var buffer = new ArrayBufferWriter<byte>();
            var w = new CborWriter(buffer, CborOptions.Strict);
            w.WriteInt32(n);
            return buffer.WrittenSpan.ToArray();
        });

    //Int-keyed map — mdoc uses these in COSE structures (IssuerSigned map
    //keys are integers per ISO 18013-5 §9.1.2). Generator produces maps
    //of 1..4 entries with int keys and mixed scalar values.
    private static Gen<byte[]> GenInnerIntKeyedMap { get; } =
        Gen.Dictionary(
            Gen.Int[0, 50],
            Gen.OneOf<object>(
                Gen.Int[0, 1000].Select(i => (object)i),
                Gen.String[Gen.Char.AlphaNumeric, 1, 12].Select(s => (object)s),
                Gen.Bool.Select(b => (object)b)))
        [1, 4]
        .Select(dict =>
        {
            var buffer = new ArrayBufferWriter<byte>();
            var w = new CborWriter(buffer, CborOptions.Strict);
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

            return buffer.WrittenSpan.ToArray();
        });

    //Tag 24 of a tagged value (Tag 1004 ISO 8601 date wrapping a string,
    //or Tag 0 standard date-time string, etc.) — exercises the "tagged
    //value nested inside Tag-24" coverage region.
    private static Gen<byte[]> GenInnerTaggedValue { get; } =
        Gen.Int[1, 5000].Select(tagNumber =>
        {
            var buffer = new ArrayBufferWriter<byte>();
            var w = new CborWriter(buffer, CborOptions.Strict);
            w.WriteTag(new CborTag((ulong)tagNumber));
            w.WriteTextString("inner-payload");

            return buffer.WrittenSpan.ToArray();
        });

    //Recursive Tag-24: an outer Tag-24 wrapper that contains a CBOR map
    //one of whose values is itself another Tag-24 wrapper. Exercises the
    //"Tag-24 contains Tag-24" recursive coverage region.
    private static Gen<byte[]> GenInnerRecursiveTag24 { get; } =
        Gen.Int[0, 100].Select(payloadValue =>
        {
            //Build a nested Tag 24 wrapper first.
            var innerBuffer = new ArrayBufferWriter<byte>();
            var innerWriter = new CborWriter(innerBuffer, CborOptions.Strict);
            innerWriter.WriteInt32(payloadValue);
            byte[] innermost = innerBuffer.WrittenSpan.ToArray();

            EncodedCborItem nested = EncodedCborItem.Wrap(innermost);

            //Wrap the nested Tag 24 inside a CBOR map.
            var buffer = new ArrayBufferWriter<byte>();
            var w = new CborWriter(buffer, CborOptions.Strict);
            w.WriteStartMap(2);
            w.WriteInt32(0);
            w.WriteInt32(payloadValue);
            w.WriteInt32(1);
            w.WriteEncodedValue(nested.WireBytes.Span);
            w.WriteEndMap();

            return buffer.WrittenSpan.ToArray();
        });
}
