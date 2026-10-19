using Lumoin.Veritas.Cbor;
using System.Buffers;
using Verifiable.Cbor;

namespace Verifiable.Tests.Serialization;

/// <summary>
/// Bare reader/writer round-trip tests over the RFC 8949 CBOR wire form, exercising the reader/writer
/// primitives directly rather than a converter — the byte-hand-typed cases salvaged from the retired
/// converter-quadruple test suite, each anchored to the RFC 8949 clause its bytes exercise.
/// </summary>
[TestClass]
internal sealed class CborRoundTripTests
{
    /// <summary>
    /// Verifies that CBOR byte arrays are equal, providing diagnostic output on failure.
    /// </summary>
    /// <param name="expected">The expected CBOR bytes.</param>
    /// <param name="actual">The actual CBOR bytes.</param>
    /// <param name="message">Optional failure message.</param>
    private static void AssertCborEqual(byte[] expected, byte[] actual, string? message = null)
    {
        if(expected.Length != actual.Length)
        {
            Assert.Fail($"{message ?? "CBOR mismatch"}: Expected length {expected.Length}, got {actual.Length}. " +
                $"Expected: {Convert.ToHexString(expected)}, Actual: {Convert.ToHexString(actual)}");
        }

        for(int i = 0; i < expected.Length; i++)
        {
            if(expected[i] != actual[i])
            {
                Assert.Fail($"{message ?? "CBOR mismatch"} at position {i}: Expected 0x{expected[i]:X2}, got 0x{actual[i]:X2}. " +
                    $"Expected: {Convert.ToHexString(expected)}, Actual: {Convert.ToHexString(actual)}");
            }
        }
    }


    /// <summary>
    /// A major-type-0 unsigned integer decodes and re-encodes to the same bytes.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.1">RFC 8949 §3.1</see> (major type 0).
    /// </remarks>
    [TestMethod]
    public void RoundtripCborInteger()
    {
        //CBOR encoding of integer 42: 0x182A (major type 0, additional info 24 means 1-byte follows).
        byte[] originalCbor = [0x18, 0x2A];

        var reader = new CborReader(originalCbor, CborOptions.Strict);
        int value = reader.ReadInt32();
        Assert.AreEqual(42, value);

        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        writer.WriteInt32(42);
        byte[] roundtrippedCbor = buffer.WrittenSpan.ToArray();

        AssertCborEqual(originalCbor, roundtrippedCbor);
    }


    /// <summary>
    /// A major-type-3 text string decodes and re-encodes to the same bytes.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.1">RFC 8949 §3.1</see> (major type 3).
    /// </remarks>
    [TestMethod]
    public void RoundtripCborTextString()
    {
        //CBOR encoding of "hello": 0x65 68 65 6C 6C 6F (major type 3, length 5).
        byte[] originalCbor = [0x65, 0x68, 0x65, 0x6C, 0x6C, 0x6F];

        var reader = new CborReader(originalCbor, CborOptions.Strict);
        string value = reader.ReadTextString();
        Assert.AreEqual("hello", value);

        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        writer.WriteTextString("hello");
        byte[] roundtrippedCbor = buffer.WrittenSpan.ToArray();

        AssertCborEqual(originalCbor, roundtrippedCbor);
    }


    /// <summary>
    /// A major-type-2 byte string decodes and re-encodes to the same bytes.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.1">RFC 8949 §3.1</see> (major type 2).
    /// </remarks>
    [TestMethod]
    public void RoundtripCborByteString()
    {
        //CBOR encoding of bytes [0x01, 0x02, 0x03]: 0x43 01 02 03 (major type 2, length 3).
        byte[] originalCbor = [0x43, 0x01, 0x02, 0x03];

        var reader = new CborReader(originalCbor, CborOptions.Strict);
        byte[] value = reader.ReadByteString();
        Assert.AreSequenceEqual(new byte[] { 0x01, 0x02, 0x03 }, value);

        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        writer.WriteByteString([0x01, 0x02, 0x03]);
        byte[] roundtrippedCbor = buffer.WrittenSpan.ToArray();

        AssertCborEqual(originalCbor, roundtrippedCbor);
    }


    /// <summary>
    /// A major-type-4 array of unsigned integers decodes and re-encodes to the same bytes.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.1">RFC 8949 §3.1</see> (major type 4).
    /// </remarks>
    [TestMethod]
    public void RoundtripCborIntArray()
    {
        //CBOR encoding of [1, 2, 3]: 0x83 01 02 03 (array of 3 items).
        byte[] originalCbor = [0x83, 0x01, 0x02, 0x03];

        var reader = new CborReader(originalCbor, CborOptions.Strict);
        var values = reader.ReadInt32Array();

        Assert.HasCount(3, values);
        Assert.AreEqual(1, values[0]);
        Assert.AreEqual(2, values[1]);
        Assert.AreEqual(3, values[2]);

        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        writer.WriteInt32Array(values);
        byte[] roundtrippedCbor = buffer.WrittenSpan.ToArray();

        AssertCborEqual(originalCbor, roundtrippedCbor);
    }


    /// <summary>
    /// A major-type-4 array of major-type-2 byte strings decodes and re-encodes to the same bytes.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.1">RFC 8949 §3.1</see> (major types 2 and 4).
    /// </remarks>
    [TestMethod]
    public void RoundtripCborByteStringArray()
    {
        //CBOR encoding of [[0x01], [0x02, 0x03]]: array of 2 byte strings.
        byte[] originalCbor = [0x82, 0x41, 0x01, 0x42, 0x02, 0x03];

        var reader = new CborReader(originalCbor, CborOptions.Strict);
        var values = reader.ReadByteStringArray();

        Assert.HasCount(2, values);
        Assert.AreSequenceEqual(new byte[] { 0x01 }, values[0]);
        Assert.AreSequenceEqual(new byte[] { 0x02, 0x03 }, values[1]);

        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        writer.WriteByteStringArray(values);
        byte[] roundtrippedCbor = buffer.WrittenSpan.ToArray();

        AssertCborEqual(originalCbor, roundtrippedCbor);
    }


    /// <summary>
    /// A major-type-5 map with integer keys decodes and re-encodes to the same bytes.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.1">RFC 8949 §3.1</see> (major type 5).
    /// </remarks>
    [TestMethod]
    public void RoundtripCborIntKeyedMap()
    {
        //CBOR encoding of {1: "a", 2: "b"}: map with 2 entries.
        //A1 = map(1), but we need map(2): A2 01 61 61 02 61 62.
        byte[] originalCbor = [0xA2, 0x01, 0x61, 0x61, 0x02, 0x61, 0x62];

        var reader = new CborReader(originalCbor, CborOptions.Strict);
        var map = reader.ReadIntKeyedMap(r => r.ReadTextString());

        Assert.HasCount(2, map);
        Assert.AreEqual("a", map[1]);
        Assert.AreEqual("b", map[2]);

        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        writer.WriteIntKeyedMap(map, (w, v) => w.WriteTextString(v));
        byte[] roundtrippedCbor = buffer.WrittenSpan.ToArray();

        AssertCborEqual(originalCbor, roundtrippedCbor);
    }


    /// <summary>
    /// A major-type-5 map with text-string keys already in canonical order decodes, and re-encoding the
    /// same pairs under the deterministic writer reproduces the identical canonical ordering.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.3">RFC 8949 §4.2.3</see> (canonical
    /// map key ordering: shorter-encoded keys sort before longer ones, ties broken bytewise).
    /// </remarks>
    [TestMethod]
    public void RoundtripCborStringKeyedMap()
    {
        //CBOR encoding of {"a": 1, "b": 2}: map with 2 entries.
        //Canonical ordering requires keys sorted by length then lexicographically.
        byte[] originalCbor = [0xA2, 0x61, 0x61, 0x01, 0x61, 0x62, 0x02];

        var reader = new CborReader(originalCbor, CborOptions.Strict);
        var map = reader.ReadStringKeyedMap(r => r.ReadInt32());

        Assert.HasCount(2, map);
        Assert.AreEqual(1, map["a"]);
        Assert.AreEqual(2, map["b"]);

        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(2);
        writer.WriteTextString("a");
        writer.WriteInt32(1);
        writer.WriteTextString("b");
        writer.WriteInt32(2);
        writer.WriteEndMap();
        byte[] roundtrippedCbor = buffer.WrittenSpan.ToArray();

        AssertCborEqual(originalCbor, roundtrippedCbor);
    }


    /// <summary>
    /// A map whose integer map key appears twice (in one width, or in two widths) is refused by
    /// <see cref="CborReaderExtensions.ReadIntKeyedMap{TValue}"/>, and one whose text map key appears twice
    /// by <see cref="CborReaderExtensions.ReadStringKeyedMap{TValue}"/>, under a reader that judges no map key.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.1">RFC 8949 Section 3.1</see>: "A map
    /// that has duplicate keys may be well-formed, but it is not valid, and thus it causes indeterminate
    /// decoding; see also Section 5.6."
    /// </remarks>
    /// <param name="encodedMap">The encoded map.</param>
    /// <param name="isTextKeyed">Whether the row drives the text-keyed reader.</param>
    [TestMethod]
    [DataRow(new byte[] { 0xA2, 0x01, 0x61, 0x61, 0x01, 0x61, 0x62 }, false, DisplayName = "integer map key twice")]
    [DataRow(new byte[] { 0xA2, 0x01, 0x61, 0x61, 0x18, 0x01, 0x61, 0x62 }, false, DisplayName = "integer map key twice, two widths")]
    [DataRow(new byte[] { 0xA2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02 }, true, DisplayName = "text map key twice")]
    public void KeyedMapReadersRefuseARepeatedMapKey(byte[] encodedMap, bool isTextKeyed)
    {
        var reader = new CborReader(encodedMap, CborOptions.Lax);

        _ = Assert.ThrowsExactly<CborContentException>(() => isTextKeyed switch
        {
            true => reader.ReadStringKeyedMap(r => r.ReadInt32()),
            false => reader.ReadIntKeyedMap(r => r.ReadTextString())
        });
    }


    /// <summary>
    /// A nested map read through <see cref="CborValueConverter.ReadValue(CborReader)"/> whose map key appears
    /// twice is refused: an integer map key in one width or in two widths, and a byte-string map key
    /// compared by its content.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.1">RFC 8949 Section 3.1</see>: "A map
    /// that has duplicate keys may be well-formed, but it is not valid, and thus it causes indeterminate
    /// decoding; see also Section 5.6."
    /// </remarks>
    /// <param name="encodedMap">The encoded map.</param>
    [TestMethod]
    [DataRow(new byte[] { 0xA2, 0x01, 0x00, 0x01, 0x01 }, DisplayName = "integer map key twice")]
    [DataRow(new byte[] { 0xA2, 0x01, 0x00, 0x18, 0x01, 0x01 }, DisplayName = "integer map key twice, two widths")]
    [DataRow(new byte[] { 0xA2, 0x41, 0x01, 0x00, 0x41, 0x01, 0x01 }, DisplayName = "byte-string map key twice")]
    public void ValueConverterRefusesARepeatedMapKey(byte[] encodedMap)
    {
        var reader = new CborReader(encodedMap, CborOptions.Lax);

        _ = Assert.ThrowsExactly<CborContentException>(() => CborValueConverter.ReadValue(reader));
    }


    /// <summary>
    /// A nested map read through <see cref="CborValueConverter.ReadValue(CborReader)"/> whose map key appears
    /// twice by the equivalence of map keys is refused: one floating-point value written in two widths,
    /// -0.0 and 0.0, two arrays equal element by element (one of them holding the simple value <c>null</c>), two
    /// maps holding the same pairs in another order, one tagged value twice, the simple value <c>true</c> twice,
    /// and two NaN values whose significands are equal after zero-extension, written in two widths.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-5.6.1">RFC 8949 Section 5.6.1</see>: "Within
    /// each of these groups, numeric values are distinct unless they are numerically equal (specifically, -0.0
    /// is equal to 0.0); for the purpose of map key equivalence, NaN values are equivalent if they have the same
    /// significand after zero-extending both significands at the right to 64 bits." and "Both byte strings and
    /// text strings are compared byte by byte, arrays are compared element by element, and are equal if they have
    /// the same number of bytes/elements and the same values at the same positions. Two maps are equal if they have
    /// the same set of pairs regardless of their order; pairs are equal if both the key and value are equal." and
    /// "Tagged values are equal if both the tag number and the tag content are equal." and "Simple values are equal
    /// if they simply have the same value."
    /// </remarks>
    /// <param name="encodedMap">The encoded map.</param>
    [TestMethod]
    [DataRow(new byte[] { 0xA2, 0xF9, 0x3C, 0x00, 0x00, 0xFA, 0x3F, 0x80, 0x00, 0x00, 0x01 }, DisplayName = "float map key 1.0 twice, half and single width")]
    [DataRow(new byte[] { 0xA2, 0xF9, 0x80, 0x00, 0x00, 0xFA, 0x00, 0x00, 0x00, 0x00, 0x01 }, DisplayName = "-0.0 and 0.0 as map keys")]
    [DataRow(new byte[] { 0xA2, 0x82, 0x01, 0x02, 0x00, 0x82, 0x01, 0x02, 0x01 }, DisplayName = "array map key twice")]
    [DataRow(new byte[] { 0xA2, 0x81, 0xF6, 0x00, 0x81, 0xF6, 0x01 }, DisplayName = "array map key [null] twice")]
    [DataRow(new byte[] { 0xA2, 0xA2, 0x01, 0x02, 0x03, 0x04, 0x00, 0xA2, 0x03, 0x04, 0x01, 0x02, 0x01 }, DisplayName = "map as map key twice, pairs in another order")]
    [DataRow(new byte[] { 0xA2, 0xC1, 0x05, 0x00, 0xC1, 0x05, 0x01 }, DisplayName = "tagged map key 1(5) twice")]
    [DataRow(new byte[] { 0xA2, 0xC2, 0x41, 0x01, 0x00, 0xC2, 0x41, 0x01, 0x01 }, DisplayName = "tagged map key 2(h'01') twice")]
    [DataRow(new byte[] { 0xA2, 0xF5, 0x00, 0xF5, 0x01 }, DisplayName = "true twice")]
    [DataRow(new byte[] { 0xA2, 0xF9, 0x7E, 0x00, 0x00, 0xFA, 0x7F, 0xC0, 0x00, 0x00, 0x01 }, DisplayName = "NaN twice, equal significands, half and single width")]
    public void ValueConverterRefusesAnEquivalentMapKey(byte[] encodedMap)
    {
        var reader = new CborReader(encodedMap, CborOptions.Lax);

        _ = Assert.ThrowsExactly<CborContentException>(() => CborValueConverter.ReadValue(reader));
    }


    /// <summary>
    /// Map keys of distinct groups are two map keys, so a map carrying one of each is read with both entries: a text
    /// string and a byte string of the same bytes, a tagged and an untagged value of the same content, one content
    /// under two tag numbers, and an integer and a Tag 2 big number of the same value.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-5.6.1">RFC 8949 Section 5.6.1</see>: "At the generic
    /// data model level, numerically equivalent integer and floating-point values are distinct from each other, as
    /// they are from the various big numbers (Tags 2 to 5). Similarly, text strings are distinct from byte strings,
    /// even if composed of the same bytes. A tagged value is distinct from an untagged value or from a value tagged
    /// with a different tag number."
    /// </remarks>
    /// <param name="encodedMap">The encoded map.</param>
    [TestMethod]
    [DataRow(new byte[] { 0xA2, 0x61, 0x61, 0x00, 0x41, 0x61, 0x01 }, DisplayName = "text string and byte string of the same bytes")]
    [DataRow(new byte[] { 0xA2, 0xC1, 0x05, 0x00, 0x05, 0x01 }, DisplayName = "tagged and untagged value of the same content")]
    [DataRow(new byte[] { 0xA2, 0xC1, 0x05, 0x00, 0xD8, 0x64, 0x05, 0x01 }, DisplayName = "one content under two tag numbers")]
    [DataRow(new byte[] { 0xA2, 0x01, 0x00, 0xC2, 0x41, 0x01, 0x01 }, DisplayName = "integer and Tag 2 big number of the same value")]
    public void ValueConverterReadsMapKeysOfDistinctGroupsAsTwo(byte[] encodedMap)
    {
        var reader = new CborReader(encodedMap, CborOptions.Lax);

        Dictionary<object, object?> map = Assert.IsInstanceOfType<Dictionary<object, object?>>(CborValueConverter.ReadValue(reader));

        Assert.HasCount(2, map, "Section 5.6.1: map keys of distinct groups are two map keys.");
    }


    /// <summary>
    /// A map whose map key is CBOR null is refused with the converter's own <see cref="CborContentException"/>: the
    /// decoded dictionary carries no null map key, one null map key or two.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-5.6">RFC 8949 Section 5.6</see>: "The encoding and
    /// decoding applications need to agree on what types of keys are going to be used in maps."
    /// </remarks>
    /// <param name="encodedMap">The encoded map.</param>
    [TestMethod]
    [DataRow(new byte[] { 0xA1, 0xF6, 0x00 }, DisplayName = "one null map key")]
    [DataRow(new byte[] { 0xA2, 0xF6, 0x00, 0xF6, 0x01 }, DisplayName = "null map key twice")]
    public void ValueConverterRefusesANullMapKey(byte[] encodedMap)
    {
        var reader = new CborReader(encodedMap, CborOptions.Lax);

        _ = Assert.ThrowsExactly<CborContentException>(() => CborValueConverter.ReadValue(reader));
    }


    /// <summary>
    /// A map key nested <paramref name="depth"/> maps deep (each map keyed by the one inside it) is decoded and judged
    /// within the reader's container-nesting bound, and refused by that bound past it, without exhausting the stack.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-5.6.1">RFC 8949 Section 5.6.1</see>: "Two maps are
    /// equal if they have the same set of pairs regardless of their order; pairs are equal if both the key and value
    /// are equal."
    /// </remarks>
    /// <param name="depth">How many maps the outermost map nests, itself included.</param>
    /// <param name="isWithinBound">Whether the nesting stays within the reader's bound.</param>
    [TestMethod]
    [DataRow(64, true, DisplayName = "64 maps deep")]
    [DataRow(65, false, DisplayName = "65 maps deep")]
    public void ValueConverterJudgesAMapKeyNestedToTheDepthBound(int depth, bool isWithinBound)
    {
        byte[] encodedMap = [.. Enumerable.Repeat((byte)0xA1, depth), 0x00, .. Enumerable.Repeat((byte)0x00, depth)];
        var reader = new CborReader(encodedMap, CborOptions.Lax);

        object outcome = isWithinBound switch
        {
            true => Assert.IsInstanceOfType<Dictionary<object, object?>>(read()),
            false => Assert.Throws<CborException>(read)
        };

        Assert.IsNotNull(outcome, "The nested map key is decoded, or the reader's own bound refuses it.");


        //Decodes the nested map key.
        object? read() => CborValueConverter.ReadValue(reader);
    }


    /// <summary>
    /// An integer map key and a floating-point map key of the same numeric value are two map keys, so a map
    /// carrying 1 and 1.0 is read with both entries.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-5.6.1">RFC 8949 Section 5.6.1</see>: "At the
    /// generic data model level, numerically equivalent integer and floating-point values are distinct from each
    /// other, as they are from the various big numbers (Tags 2 to 5)."
    /// </remarks>
    [TestMethod]
    public void ValueConverterReadsAnIntegerAndAFloatOfOneValueAsTwoMapKeys()
    {
        byte[] encodedMap = [0xA2, 0x01, 0x00, 0xF9, 0x3C, 0x00, 0x01];
        var reader = new CborReader(encodedMap, CborOptions.Lax);

        Dictionary<object, object?> map = Assert.IsInstanceOfType<Dictionary<object, object?>>(CborValueConverter.ReadValue(reader));

        Assert.HasCount(2, map, "Section 5.6.1: the integer 1 and the float 1.0 are distinct map keys.");
    }


    /// <summary>
    /// <see cref="CborValueConverter.WriteValue(CborWriter, object?)"/> refuses, as the caller's own argument, a
    /// dictionary whose entries would be written as the same map key twice: a boxed <see cref="int"/> 1 and a
    /// boxed <see cref="long"/> 1 are two dictionary entries but one CBOR integer.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9052#section-9">RFC 9052 Section 9</see>: "Applications MUST
    /// NOT generate messages with the same label used twice as a key in a single map."
    /// </remarks>
    [TestMethod]
    public void ValueConverterRefusesToWriteOneMapKeyTwice()
    {
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        Dictionary<object, object?> map = new()
        {
            [1] = "a",
            [1L] = "b"
        };

        _ = Assert.ThrowsExactly<ArgumentException>(() => CborValueConverter.WriteValue(writer, map));
    }


    /// <summary>
    /// A definite-length array read with the exact expected length succeeds; a mismatched expectation is
    /// rejected.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.1">RFC 8949 §3.1</see> (major type 4,
    /// definite-length array count).
    /// </remarks>
    [TestMethod]
    public void ReadStartArrayExpectLengthThrowsOnMismatch()
    {
        //CBOR array with 3 elements.
        byte[] cbor = [0x83, 0x01, 0x02, 0x03];

        var reader = new CborReader(cbor, CborOptions.Strict);

        _ = Assert.Throws<CborContentException>(() =>
        {
            reader.ReadStartArrayExpectLength(5);
        });
    }


    /// <summary>
    /// A definite-length array whose count falls inside the caller's expected range succeeds and reports
    /// the actual count.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.1">RFC 8949 §3.1</see> (major type 4,
    /// definite-length array count).
    /// </remarks>
    [TestMethod]
    public void ReadStartArrayExpectLengthRangeSucceedsInRange()
    {
        //CBOR array with 3 elements.
        byte[] cbor = [0x83, 0x01, 0x02, 0x03];

        var reader = new CborReader(cbor, CborOptions.Strict);
        int length = reader.ReadStartArrayExpectLengthRange(2, 5);

        Assert.AreEqual(3, length);
    }


    /// <summary>
    /// CBOR simple value 22 (null) reads as a null byte string.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.3">RFC 8949 §3.3</see> (the null
    /// simple value).
    /// </remarks>
    [TestMethod]
    public void ReadNullableByteStringReturnsNullForCborNull()
    {
        //CBOR null: 0xF6.
        byte[] cbor = [0xF6];

        var reader = new CborReader(cbor, CborOptions.Strict);
        byte[]? value = reader.ReadNullableByteString();

        Assert.IsNull(value);
    }


    /// <summary>
    /// A present major-type-2 byte string reads through the nullable helper as its value.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.1">RFC 8949 §3.1</see> (major type 2).
    /// </remarks>
    [TestMethod]
    public void ReadNullableByteStringReturnsValueForByteString()
    {
        //CBOR byte string [0x01, 0x02].
        byte[] cbor = [0x42, 0x01, 0x02];

        var reader = new CborReader(cbor, CborOptions.Strict);
        byte[]? value = reader.ReadNullableByteString();

        Assert.IsNotNull(value);
        Assert.AreSequenceEqual(new byte[] { 0x01, 0x02 }, value);
    }


    /// <summary>
    /// Two maps built from the same key/value pairs in different insertion orders produce byte-identical
    /// output once written under the deterministic writer, since the writer sorts entries by the
    /// canonical key order rather than emitting them in insertion order.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8949#section-4.2.3">RFC 8949 §4.2.3</see> (canonical
    /// map key ordering is a property of the wire form, independent of write order).
    /// </remarks>
    [TestMethod]
    public void CanonicalModeProducesDeterministicOutput()
    {
        var buffer1 = new ArrayBufferWriter<byte>();
        var writer1 = new CborWriter(buffer1, CborOptions.RfcCanonical);
        writer1.WriteStartMap(2);
        writer1.WriteTextString("b");
        writer1.WriteInt32(2);
        writer1.WriteTextString("a");
        writer1.WriteInt32(1);
        writer1.WriteEndMap();

        var buffer2 = new ArrayBufferWriter<byte>();
        var writer2 = new CborWriter(buffer2, CborOptions.RfcCanonical);
        writer2.WriteStartMap(2);
        writer2.WriteTextString("a");
        writer2.WriteInt32(1);
        writer2.WriteTextString("b");
        writer2.WriteInt32(2);
        writer2.WriteEndMap();

        byte[] encoded1 = buffer1.WrittenSpan.ToArray();
        byte[] encoded2 = buffer2.WrittenSpan.ToArray();

        //Both should produce the same canonical output with keys sorted.
        AssertCborEqual(encoded1, encoded2, "Canonical mode should produce deterministic output regardless of write order.");
    }
}
