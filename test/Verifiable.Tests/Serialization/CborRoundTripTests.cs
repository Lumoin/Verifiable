using System;
using System.Buffers;
using Lumoin.Veritas.Cbor;
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

        Assert.Throws<CborContentException>(() =>
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
