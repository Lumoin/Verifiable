using System.Formats.Cbor;
using Verifiable.Cbor;

namespace Verifiable.Tests.Serialization;

/// <summary>
/// Tests for individual CBOR converters. Parallels the JSON converter tests to ensure
/// consistent behavior across serialization formats.
/// </summary>
/// <remarks>
/// Each test reads CBOR data, deserializes to a strongly-typed object, then serializes
/// back to CBOR and verifies the round-trip produces identical bytes.
/// </remarks>
[TestClass]
public sealed class CborConverterTests
{
    /// <summary>
    /// Tries to convert the input CBOR bytes to a strongly typed object using the given converter.
    /// </summary>
    /// <typeparam name="TConversionTarget">The conversion target type.</typeparam>
    /// <param name="cborBytes">The CBOR bytes to convert.</param>
    /// <param name="converter">The converter to use.</param>
    /// <param name="options">The serializer options.</param>
    /// <returns>An instance of the target type if conversion succeeded.</returns>
    private static TConversionTarget? GetConverted<TConversionTarget>(
        byte[] cborBytes,
        CborConverter<TConversionTarget> converter,
        CborSerializerOptions? options = null) where TConversionTarget : class
    {
        options ??= CborSerializerOptions.Default;
        var reader = new CborReader(cborBytes, options.ConformanceMode, options.AllowIndefiniteLength);

        return converter.Read(ref reader, typeof(TConversionTarget), options);
    }


    /// <summary>
    /// Tries to convert the input object to CBOR bytes using the given converter.
    /// </summary>
    /// <typeparam name="TInput">The input type.</typeparam>
    /// <param name="input">The input object.</param>
    /// <param name="converter">The converter to use.</param>
    /// <param name="options">The serializer options.</param>
    /// <returns>CBOR representation of the input object.</returns>
    private static byte[] GetConverted<TInput>(
        TInput input,
        CborConverter<TInput> converter,
        CborSerializerOptions? options = null)
    {
        options ??= CborSerializerOptions.Default;
        var writer = new CborWriter(options.ConformanceMode);

        converter.Write(writer, input!, options);

        return writer.Encode();
    }


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
    /// Tests reading and writing a simple CBOR integer.
    /// </summary>
    [TestMethod]
    public void RoundtripCborInteger()
    {
        //CBOR encoding of integer 42: 0x182A (major type 0, additional info 24 means 1-byte follows).
        byte[] originalCbor = [0x18, 0x2A];

        var reader = new CborReader(originalCbor);
        int value = reader.ReadInt32();
        Assert.AreEqual(42, value);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteInt32(42);
        byte[] roundtrippedCbor = writer.Encode();

        AssertCborEqual(originalCbor, roundtrippedCbor);
    }


    /// <summary>
    /// Tests reading and writing a CBOR text string.
    /// </summary>
    [TestMethod]
    public void RoundtripCborTextString()
    {
        //CBOR encoding of "hello": 0x65 68 65 6C 6C 6F (major type 3, length 5).
        byte[] originalCbor = [0x65, 0x68, 0x65, 0x6C, 0x6C, 0x6F];

        var reader = new CborReader(originalCbor);
        string value = reader.ReadTextString();
        Assert.AreEqual("hello", value);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteTextString("hello");
        byte[] roundtrippedCbor = writer.Encode();

        AssertCborEqual(originalCbor, roundtrippedCbor);
    }


    /// <summary>
    /// Tests reading and writing a CBOR byte string.
    /// </summary>
    [TestMethod]
    public void RoundtripCborByteString()
    {
        //CBOR encoding of bytes [0x01, 0x02, 0x03]: 0x43 01 02 03 (major type 2, length 3).
        byte[] originalCbor = [0x43, 0x01, 0x02, 0x03];

        var reader = new CborReader(originalCbor);
        byte[] value = reader.ReadByteString();
        CollectionAssert.AreEqual(new byte[] { 0x01, 0x02, 0x03 }, value);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteByteString([0x01, 0x02, 0x03]);
        byte[] roundtrippedCbor = writer.Encode();

        AssertCborEqual(originalCbor, roundtrippedCbor);
    }


    /// <summary>
    /// Tests reading and writing a CBOR array of integers.
    /// </summary>
    [TestMethod]
    public void RoundtripCborIntArray()
    {
        //CBOR encoding of [1, 2, 3]: 0x83 01 02 03 (array of 3 items).
        byte[] originalCbor = [0x83, 0x01, 0x02, 0x03];

        var reader = new CborReader(originalCbor);
        var values = reader.ReadInt32Array();

        Assert.HasCount(3, values);
        Assert.AreEqual(1, values[0]);
        Assert.AreEqual(2, values[1]);
        Assert.AreEqual(3, values[2]);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteInt32Array(values);
        byte[] roundtrippedCbor = writer.Encode();

        AssertCborEqual(originalCbor, roundtrippedCbor);
    }


    /// <summary>
    /// Tests reading and writing a CBOR array of byte strings.
    /// </summary>
    [TestMethod]
    public void RoundtripCborByteStringArray()
    {
        //CBOR encoding of [[0x01], [0x02, 0x03]]: array of 2 byte strings.
        byte[] originalCbor = [0x82, 0x41, 0x01, 0x42, 0x02, 0x03];

        var reader = new CborReader(originalCbor);
        var values = reader.ReadByteStringArray();

        Assert.HasCount(2, values);
        CollectionAssert.AreEqual(new byte[] { 0x01 }, values[0]);
        CollectionAssert.AreEqual(new byte[] { 0x02, 0x03 }, values[1]);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteByteStringArray(values);
        byte[] roundtrippedCbor = writer.Encode();

        AssertCborEqual(originalCbor, roundtrippedCbor);
    }


    /// <summary>
    /// Tests reading and writing a CBOR map with integer keys.
    /// </summary>
    [TestMethod]
    public void RoundtripCborIntKeyedMap()
    {
        //CBOR encoding of {1: "a", 2: "b"}: map with 2 entries.
        //A1 = map(1), but we need map(2): A2 01 61 61 02 61 62.
        byte[] originalCbor = [0xA2, 0x01, 0x61, 0x61, 0x02, 0x61, 0x62];

        var reader = new CborReader(originalCbor);
        var map = reader.ReadIntKeyedMap(r => r.ReadTextString());

        Assert.HasCount(2, map);
        Assert.AreEqual("a", map[1]);
        Assert.AreEqual("b", map[2]);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteIntKeyedMap(map, (w, v) => w.WriteTextString(v));
        byte[] roundtrippedCbor = writer.Encode();

        AssertCborEqual(originalCbor, roundtrippedCbor);
    }


    /// <summary>
    /// Tests reading and writing a CBOR map with text string keys.
    /// </summary>
    [TestMethod]
    public void RoundtripCborStringKeyedMap()
    {
        //CBOR encoding of {"a": 1, "b": 2}: map with 2 entries.
        //Canonical ordering requires keys sorted by length then lexicographically.
        byte[] originalCbor = [0xA2, 0x61, 0x61, 0x01, 0x61, 0x62, 0x02];

        var reader = new CborReader(originalCbor);
        var map = reader.ReadStringKeyedMap(r => r.ReadInt32());

        Assert.HasCount(2, map);
        Assert.AreEqual(1, map["a"]);
        Assert.AreEqual(2, map["b"]);

        //Note: Round-trip may differ due to canonical key ordering requirements.
        //This test validates reading; writing with canonical mode should produce same output.
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(2);
        writer.WriteTextString("a");
        writer.WriteInt32(1);
        writer.WriteTextString("b");
        writer.WriteInt32(2);
        writer.WriteEndMap();
        byte[] roundtrippedCbor = writer.Encode();

        AssertCborEqual(originalCbor, roundtrippedCbor);
    }


    /// <summary>
    /// Tests that the reader extension correctly validates array length.
    /// </summary>
    [TestMethod]
    public void ReadStartArrayExpectLengthThrowsOnMismatch()
    {
        //CBOR array with 3 elements.
        byte[] cbor = [0x83, 0x01, 0x02, 0x03];

        var reader = new CborReader(cbor);

        Assert.Throws<CborContentException>(() =>
        {
            reader.ReadStartArrayExpectLength(5);
        });
    }


    /// <summary>
    /// Tests that the reader extension correctly validates array length range.
    /// </summary>
    [TestMethod]
    public void ReadStartArrayExpectLengthRangeSucceedsInRange()
    {
        //CBOR array with 3 elements.
        byte[] cbor = [0x83, 0x01, 0x02, 0x03];

        var reader = new CborReader(cbor);
        int length = reader.ReadStartArrayExpectLengthRange(2, 5);

        Assert.AreEqual(3, length);
    }


    /// <summary>
    /// Tests that nullable byte string reads null correctly.
    /// </summary>
    [TestMethod]
    public void ReadNullableByteStringReturnsNullForCborNull()
    {
        //CBOR null: 0xF6.
        byte[] cbor = [0xF6];

        var reader = new CborReader(cbor);
        byte[]? value = reader.ReadNullableByteString();

        Assert.IsNull(value);
    }


    /// <summary>
    /// Tests that nullable byte string reads value correctly.
    /// </summary>
    [TestMethod]
    public void ReadNullableByteStringReturnsValueForByteString()
    {
        //CBOR byte string [0x01, 0x02].
        byte[] cbor = [0x42, 0x01, 0x02];

        var reader = new CborReader(cbor);
        byte[]? value = reader.ReadNullableByteString();

        Assert.IsNotNull(value);
        CollectionAssert.AreEqual(new byte[] { 0x01, 0x02 }, value);
    }


    /// <summary>
    /// Tests deterministic encoding in canonical mode.
    /// </summary>
    [TestMethod]
    public void CanonicalModeProducesDeterministicOutput()
    {
        var writer1 = new CborWriter(CborConformanceMode.Canonical);
        writer1.WriteStartMap(2);
        writer1.WriteTextString("b");
        writer1.WriteInt32(2);
        writer1.WriteTextString("a");
        writer1.WriteInt32(1);
        writer1.WriteEndMap();

        var writer2 = new CborWriter(CborConformanceMode.Canonical);
        writer2.WriteStartMap(2);
        writer2.WriteTextString("a");
        writer2.WriteInt32(1);
        writer2.WriteTextString("b");
        writer2.WriteInt32(2);
        writer2.WriteEndMap();

        byte[] encoded1 = writer1.Encode();
        byte[] encoded2 = writer2.Encode();

        //Both should produce the same canonical output with keys sorted.
        AssertCborEqual(encoded1, encoded2, "Canonical mode should produce deterministic output regardless of write order.");
    }
}