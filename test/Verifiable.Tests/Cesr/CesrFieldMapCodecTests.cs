using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;
using Lumoin.Base;
using Verifiable.Cesr;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Cesr;

/// <summary>
/// Tests for <see cref="CesrFieldMapCodec"/> — the primitive layer of a CESR-native field map: decoding one field
/// label and one primitive field value into their serialization-neutral forms. The primary vector is the worked
/// flat field-map serialization <c>-IAQ0J_a6HABAAA10J_b1AAM0J_c0L_hello0J_d6HACAAA15p340J_e1AAL0J_f1AAK</c> for the
/// map <c>{a:1, b:true, c:"hello", d:15.34, e:false, f:null}</c>, decomposed primitive by primitive so the label
/// codec (compact tags), the number codec (a compact Base64 decimal string), the fixed markers (null, boolean),
/// and the text codec are each checked against an authoritative external serialization rather than a self-produced
/// one. A separate case pins the code-table sizings the field-map codes depend on.
/// </summary>
[TestClass]
internal sealed class CesrFieldMapCodecTests
{
    /// <summary>
    /// The worked flat field-map serialization for <c>{a:1, b:true, c:"hello", d:15.34, e:false, f:null}</c>: a
    /// generic map group (<c>-I</c>) of sixteen quadlets holding six (label, value) primitive pairs.
    /// </summary>
    private const string FlatFieldMapVector = "-IAQ0J_a6HABAAA10J_b1AAM0J_c0L_hello0J_d6HACAAA15p340J_e1AAL0J_f1AAK";

    /// <summary>The binary-domain (qb2) serialization of the flat field-map vector: the Base64URL decoding of its qb64.</summary>
    private const string FlatFieldMapVectorQb2Hex = "f88010d09fdae87001000035d09fdbd4000cd09fdcd0bfe17a5968d09fdde87002000035e69df8d09fded4000bd09fdfd4000a";

    /// <summary>The six field labels the flat field-map vector carries, in serialization order.</summary>
    private static string[] ExpectedFlatLabels { get; } = ["a", "b", "c", "d", "e", "f"];


    /// <summary>
    /// The flat field-map vector decomposes primitive by primitive: alternating a label and a value primitive
    /// across the whole map-group body recovers the six labels and their neutral values, consuming the body exactly.
    /// </summary>
    [TestMethod]
    public void DecodesCanonicalFlatFieldMapVectorPrimitiveByPrimitive()
    {
        ReadOnlySpan<char> vector = FlatFieldMapVector;

        CesrParsedCountCode frame = CesrCountCodeCodec.DecodeText(vector);
        Assert.AreEqual("-I", frame.Code);
        Assert.AreEqual(16, frame.Count);

        int codeLength = CesrCountCodeTables.SizingForSelector(vector[0], vector[1]).FullSize;
        int end = codeLength + (int)frame.TextCharCount;
        Assert.AreEqual(vector.Length, end);

        var labels = new List<string>();
        var values = new List<object?>();
        int offset = codeLength;
        while(offset < end)
        {
            string label = CesrFieldMapCodec.DecodeLabel(vector[offset..end], BaseMemoryPool.Shared, out int labelChars);
            offset += labelChars;
            object? value = CesrFieldMapCodec.DecodeValuePrimitive(vector[offset..end], BaseMemoryPool.Shared, out int valueChars);
            offset += valueChars;

            labels.Add(label);
            values.Add(value);
        }

        Assert.AreEqual(end, offset);
        Assert.AreSequenceEqual(ExpectedFlatLabels, labels);
        Assert.HasCount(6, values);
        Assert.AreEqual(1, values[0]);
        Assert.IsTrue((bool)values[1]!);
        Assert.AreEqual("hello", values[2]);
        Assert.AreEqual(15.34m, values[3]);
        Assert.IsFalse((bool)values[4]!);
        Assert.IsNull(values[5]);
    }


    /// <summary>
    /// Known-answer value primitives: the fixed markers, an integer and a float decimal, a compact-tag text, a
    /// raw-byte text, an escaped verbatim value, an empty value, and a qualified primitive carried through verbatim.
    /// </summary>
    /// <returns>The value-primitive vectors: the qb64 primitive and its expected neutral value.</returns>
    private static IEnumerable<object?[]> ValuePrimitiveVectors()
    {
        yield return ["1AAK", null];
        yield return ["1AAM", true];
        yield return ["1AAL", false];
        yield return ["6HABAAA1", 1];
        yield return ["6HACAAA15p34", 15.34m];
        yield return ["0L_hello", "hello"];
        yield return ["Xabc", "abc"];
        yield return ["1AAP", ""];
        yield return ["5BADAEhpIFRoZXJl", "Hi There"];
        yield return ["1AAO6HABAAA1", "6HABAAA1"];
        yield return ["ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux", "ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux"];
    }


    /// <summary>
    /// Each value primitive decodes to its neutral value, consuming exactly its own characters (and, for an
    /// escaped value, the primitive it escapes).
    /// </summary>
    /// <param name="qb64">The value primitive serialization.</param>
    /// <param name="expected">The expected neutral value.</param>
    [TestMethod]
    [DynamicData(nameof(ValuePrimitiveVectors))]
    public void DecodesValuePrimitive(string qb64, object? expected)
    {
        object? value = CesrFieldMapCodec.DecodeValuePrimitive(qb64, BaseMemoryPool.Shared, out int consumed);

        Assert.AreEqual(qb64.Length, consumed);
        Assert.AreEqual(expected, value);
    }


    /// <summary>
    /// Known-answer label primitives: single- and multi-character compact-tag labels decode to their label text.
    /// </summary>
    /// <returns>The label vectors: the qb64 label primitive and its expected label text.</returns>
    private static IEnumerable<object[]> LabelVectors()
    {
        yield return ["0J_a", "a"];
        yield return ["0J_z", "z"];
        yield return ["0Kab", "ab"];
        yield return ["Xabc", "abc"];
        yield return ["1AAFnest", "nest"];
    }


    /// <summary>
    /// Each compact-tag label primitive decodes to its label text, consuming exactly its own characters.
    /// </summary>
    /// <param name="qb64">The label primitive serialization.</param>
    /// <param name="expected">The expected label text.</param>
    [TestMethod]
    [DynamicData(nameof(LabelVectors))]
    public void DecodesLabel(string qb64, string expected)
    {
        string label = CesrFieldMapCodec.DecodeLabel(qb64, BaseMemoryPool.Shared, out int consumed);

        Assert.AreEqual(qb64.Length, consumed);
        Assert.AreEqual(expected, label);
    }


    /// <summary>
    /// The code-table sizings for the field-map label and value codes, as the reference master code table
    /// prescribes: the hard, soft, extra, full (null when variable), and lead sizes.
    /// </summary>
    /// <returns>The sizing vectors: code, hard, soft, extra, full (-1 for variable), lead.</returns>
    private static IEnumerable<object[]> FieldMapCodeSizings()
    {
        yield return ["0J", 2, 2, 1, 4, 0];
        yield return ["0K", 2, 2, 0, 4, 0];
        yield return ["0L", 2, 6, 1, 8, 0];
        yield return ["0M", 2, 6, 0, 8, 0];
        yield return ["0N", 2, 10, 1, 12, 0];
        yield return ["0O", 2, 10, 0, 12, 0];
        yield return ["X", 1, 3, 0, 4, 0];
        yield return ["Y", 1, 7, 0, 8, 0];
        yield return ["Z", 1, 11, 0, 12, 0];
        yield return ["1AAF", 4, 4, 0, 8, 0];
        yield return ["1AAN", 4, 8, 0, 12, 0];
        yield return ["1AAK", 4, 0, 0, 4, 0];
        yield return ["1AAL", 4, 0, 0, 4, 0];
        yield return ["1AAM", 4, 0, 0, 4, 0];
        yield return ["1AAO", 4, 0, 0, 4, 0];
        yield return ["1AAP", 4, 0, 0, 4, 0];
        yield return ["4H", 2, 2, 0, -1, 0];
        yield return ["5H", 2, 2, 0, -1, 1];
        yield return ["6H", 2, 2, 0, -1, 2];
    }


    /// <summary>
    /// The code table carries the exact reference sizing for every field-map label and value code, so the primitive
    /// codec partitions each one correctly.
    /// </summary>
    /// <param name="code">The stable (hard) code.</param>
    /// <param name="hard">The expected hard size.</param>
    /// <param name="soft">The expected soft size.</param>
    /// <param name="extra">The expected extra (prepad) size.</param>
    /// <param name="full">The expected full size, or -1 for a variable-size code.</param>
    /// <param name="lead">The expected lead size.</param>
    [TestMethod]
    [DynamicData(nameof(FieldMapCodeSizings))]
    public void CodeTableSizesFieldMapCode(string code, int hard, int soft, int extra, int full, int lead)
    {
        Assert.IsTrue(CesrCodeTables.Sizes.TryGetValue(code, out CesrCodeSizing sizing), $"Code '{code}' must be present in the CESR code table.");
        Assert.AreEqual(hard, sizing.HardSize);
        Assert.AreEqual(soft, sizing.SoftSize);
        Assert.AreEqual(extra, sizing.ExtraSize);
        Assert.AreEqual(full == -1 ? (int?)null : full, sizing.FullSize);
        Assert.AreEqual(lead, sizing.LeadSize);
    }


    /// <summary>
    /// A value that opens a nested group is not a value primitive: the field-map walk decodes it, so the primitive
    /// value decoder rejects it.
    /// </summary>
    [TestMethod]
    public void RejectsGroupAsValuePrimitive()
    {
        Assert.ThrowsExactly<CesrFormatException>(() => CesrFieldMapCodec.DecodeValuePrimitive("-IAA", BaseMemoryPool.Shared, out _));
    }


    /// <summary>
    /// A decimal-number primitive is a value, not a valid strict field-map label, so decoding it as a label is
    /// rejected.
    /// </summary>
    [TestMethod]
    public void RejectsNonLabelCodeAsLabel()
    {
        Assert.ThrowsExactly<CesrFormatException>(() => CesrFieldMapCodec.DecodeLabel("6HABAAA1", BaseMemoryPool.Shared, out _));
    }


    /// <summary>
    /// The flat field-map vector decodes through the map-group walk into a neutral field map that preserves field
    /// order and carries each value in its neutral form.
    /// </summary>
    [TestMethod]
    public void DecodesFlatFieldMap()
    {
        using AsciiText native = RentAscii(FlatFieldMapVector);

        MessageFieldMap fields = CesrFieldMapCodec.DecodeFieldMap(native.Memory, BaseMemoryPool.Shared);

        Assert.AreSequenceEqual(ExpectedFlatLabels, new List<string>(fields.Keys));
        Assert.AreEqual(1, fields["a"]);
        Assert.IsTrue((bool)fields["b"]!);
        Assert.AreEqual("hello", fields["c"]);
        Assert.AreEqual(15.34m, fields["d"]);
        Assert.IsFalse((bool)fields["e"]!);
        Assert.IsNull(fields["f"]);
    }


    /// <summary>
    /// The nested field-map vector decodes into nested field maps and lists: a text field, a map whose fields are
    /// a boolean list and a nested map, and a list mixing a list, a map, and a text element, matching the worked
    /// map <c>{a:"Hi There", nest:{a:[true,false,null], b:{z:true}}, icky:[["z","y"], {d:5}, "abc"]}</c>.
    /// </summary>
    [TestMethod]
    public void DecodesNestedFieldMap()
    {
        using AsciiText native = RentAscii(NestedFieldMapVector);

        MessageFieldMap fields = CesrFieldMapCodec.DecodeFieldMap(native.Memory, BaseMemoryPool.Shared);

        Assert.AreEqual("Hi There", fields["a"]);

        var nest = (MessageFieldMap)fields["nest"]!;
        var nestA = (IReadOnlyList<object?>)nest["a"]!;
        Assert.HasCount(3, nestA);
        Assert.IsTrue((bool)nestA[0]!);
        Assert.IsFalse((bool)nestA[1]!);
        Assert.IsNull(nestA[2]);
        var nestB = (MessageFieldMap)nest["b"]!;
        Assert.IsTrue((bool)nestB["z"]!);

        var icky = (IReadOnlyList<object?>)fields["icky"]!;
        Assert.HasCount(3, icky);
        var inner = (IReadOnlyList<object?>)icky[0]!;
        Assert.AreEqual("z", inner[0]);
        Assert.AreEqual("y", inner[1]);
        var innerMap = (MessageFieldMap)icky[1]!;
        Assert.AreEqual(5, innerMap["d"]);
        Assert.AreEqual("abc", icky[2]);
    }


    /// <summary>
    /// The empty map group decodes to an empty field map.
    /// </summary>
    [TestMethod]
    public void DecodesEmptyFieldMap()
    {
        using AsciiText native = RentAscii("-IAA");

        MessageFieldMap fields = CesrFieldMapCodec.DecodeFieldMap(native.Memory, BaseMemoryPool.Shared);

        Assert.IsEmpty(fields);
    }


    /// <summary>
    /// A serialization framed by a group code other than the generic map group is rejected.
    /// </summary>
    [TestMethod]
    public void RejectsNonMapFrame()
    {
        using AsciiText native = RentAscii("-JAA");

        Assert.ThrowsExactly<CesrFormatException>(() => CesrFieldMapCodec.DecodeFieldMap(native.Memory, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// A map group with characters trailing after its declared body is rejected.
    /// </summary>
    [TestMethod]
    public void RejectsTrailingCharacters()
    {
        using AsciiText native = RentAscii(FlatFieldMapVector + "1AAK");

        Assert.ThrowsExactly<CesrFormatException>(() => CesrFieldMapCodec.DecodeFieldMap(native.Memory, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// Builds the flat field map <c>{a:1, b:true, c:"hello", d:15.34, e:false, f:null}</c> the worked vector encodes.
    /// </summary>
    /// <returns>The flat field map.</returns>
    private static MessageFieldMap FlatMap() => new(StringComparer.Ordinal)
    {
        ["a"] = 1,
        ["b"] = true,
        ["c"] = "hello",
        ["d"] = 15.34m,
        ["e"] = false,
        ["f"] = null
    };


    /// <summary>
    /// The flat field map encodes to the worked flat vector: each fixed marker, the integer and float decimals, the
    /// compact-tag text, and the field labels serialize to the specification's bytes.
    /// </summary>
    [TestMethod]
    public void EncodesFlatFieldMap()
    {
        Assert.AreEqual(FlatFieldMapVector, Encode(FlatMap()));
    }


    /// <summary>
    /// The flat field map encodes to its binary-domain (qb2) serialization: the Base64URL decoding of the qb64 form,
    /// matching the worked binary vector.
    /// </summary>
    [TestMethod]
    public void EncodesFlatFieldMapToBinary()
    {
        var buffer = new ArrayBufferWriter<byte>();
        CesrFieldMapCodec.EncodeFieldMapBinary(FlatMap(), BaseMemoryPool.Shared, buffer);

        Assert.IsTrue(buffer.WrittenSpan.SequenceEqual(Convert.FromHexString(FlatFieldMapVectorQb2Hex)));
    }


    /// <summary>
    /// The binary-domain (qb2) flat vector decodes to the same field map as its text form, re-encoding to the worked
    /// qb64 vector.
    /// </summary>
    [TestMethod]
    public void DecodesFlatFieldMapFromBinary()
    {
        byte[] qb2 = Convert.FromHexString(FlatFieldMapVectorQb2Hex);

        MessageFieldMap decoded = CesrFieldMapCodec.DecodeFieldMapBinary(qb2, BaseMemoryPool.Shared);

        Assert.AreEqual(FlatFieldMapVector, Encode(decoded));
    }


    /// <summary>
    /// The nested field map encodes to the worked nested vector: a raw-byte text value, a nested map, and a list
    /// mixing a list, a map, and a text element all frame into their groups.
    /// </summary>
    [TestMethod]
    public void EncodesNestedFieldMap()
    {
        var map = new MessageFieldMap(StringComparer.Ordinal)
        {
            ["a"] = "Hi There",
            ["nest"] = new MessageFieldMap(StringComparer.Ordinal)
            {
                ["a"] = new List<object?> { true, false, null },
                ["b"] = new MessageFieldMap(StringComparer.Ordinal) { ["z"] = true }
            },
            ["icky"] = new List<object?>
            {
                new List<object?> { "z", "y" },
                new MessageFieldMap(StringComparer.Ordinal) { ["d"] = 5 },
                "abc"
            }
        };

        Assert.AreEqual(NestedFieldMapVector, Encode(map));
    }


    /// <summary>
    /// The empty field map encodes to the empty map group.
    /// </summary>
    [TestMethod]
    public void EncodesEmptyFieldMap()
    {
        Assert.AreEqual("-IAA", Encode(new MessageFieldMap(StringComparer.Ordinal)));
    }


    /// <summary>
    /// A field whose label and value are Base64 text longer than a compact tag round-trips through the Base64-string
    /// primitive: both are recovered exactly after encoding and decoding.
    /// </summary>
    [TestMethod]
    public void RoundTripsLongBase64LabelAndValue()
    {
        var map = new MessageFieldMap(StringComparer.Ordinal) { ["longFieldLabelName"] = "Non-commercial" };

        var buffer = new ArrayBufferWriter<byte>();
        CesrFieldMapCodec.EncodeFieldMap(map, BaseMemoryPool.Shared, buffer);

        MessageFieldMap decoded = CesrFieldMapCodec.DecodeFieldMap(buffer.WrittenMemory, BaseMemoryPool.Shared);
        Assert.IsTrue(decoded.TryGetString("longFieldLabelName", out string? value));
        Assert.AreEqual("Non-commercial", value);
    }


    /// <summary>
    /// A string value that is itself a complete typed primitive is escaped so it round-trips as text rather than as
    /// that typed value (the worked <c>-IAE0J_a1AAO6HABAAA1</c> vector, whose value is the literal text "6HABAAA1").
    /// </summary>
    [TestMethod]
    public void EncodesEscapedStringValue()
    {
        var map = new MessageFieldMap(StringComparer.Ordinal) { ["a"] = "6HABAAA1" };

        Assert.AreEqual("-IAE0J_a1AAO6HABAAA1", Encode(map));
    }


    /// <summary>
    /// A string value that is a complete qualified primitive with an ordinary code is carried verbatim (the worked
    /// <c>-IAM0J_a…</c> vector, whose value is a SAID).
    /// </summary>
    [TestMethod]
    public void EncodesVerbatimPrimitiveValue()
    {
        var map = new MessageFieldMap(StringComparer.Ordinal) { ["a"] = "ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux" };

        Assert.AreEqual("-IAM0J_aELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux", Encode(map));
    }


    /// <summary>
    /// Decoding a field map and re-encoding it reproduces the original bytes, for both the flat and the nested
    /// vectors: the decode and encode arms are inverses.
    /// </summary>
    /// <param name="vector">The field-map serialization to round-trip.</param>
    [TestMethod]
    [DataRow(FlatFieldMapVector)]
    [DataRow(NestedFieldMapVector)]
    public void RoundTripsFieldMap(string vector)
    {
        using AsciiText native = RentAscii(vector);

        MessageFieldMap decoded = CesrFieldMapCodec.DecodeFieldMap(native.Memory, BaseMemoryPool.Shared);

        Assert.AreEqual(vector, Encode(decoded));
    }


    //Encodes a field map to its CESR-native qb64 text via a pooled writer, the verifier-facing bytes read back as
    //ASCII for comparison against the worked vector.
    private static string Encode(MessageFieldMap map)
    {
        var writer = new ArrayBufferWriter<byte>();
        CesrFieldMapCodec.EncodeFieldMap(map, BaseMemoryPool.Shared, writer);

        return Encoding.ASCII.GetString(writer.WrittenSpan);
    }


    //Rents a pooled buffer holding the serialization's ASCII bytes — the verifier-facing input — owned by the
    //returned carrier and disposed by the caller rather than left as a naked array.
    private static AsciiText RentAscii(string serialization)
    {
        int length = Encoding.ASCII.GetByteCount(serialization);
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(length);
        Encoding.ASCII.GetBytes(serialization, owner.Memory.Span);

        return new AsciiText(owner, length);
    }


    //An ASCII serialization carried in a pooled buffer the test owns and disposes.
    private sealed class AsciiText: IDisposable
    {
        private readonly IMemoryOwner<byte> owner;
        private readonly int length;

        /// <summary>Initializes the carrier over a pooled buffer holding the given number of ASCII bytes.</summary>
        /// <param name="owner">The pooled buffer.</param>
        /// <param name="length">The number of valid bytes at the start of the buffer.</param>
        public AsciiText(IMemoryOwner<byte> owner, int length)
        {
            this.owner = owner;
            this.length = length;
        }

        /// <summary>The serialization's ASCII bytes.</summary>
        public ReadOnlyMemory<byte> Memory => owner.Memory[..length];

        /// <summary>Returns the pooled buffer to its pool.</summary>
        public void Dispose() => owner.Dispose();
    }


    /// <summary>
    /// The worked nested field-map serialization for
    /// <c>{a:"Hi There", nest:{a:[true,false,null], b:{z:true}}, icky:[["z","y"], {d:5}, "abc"]}</c>.
    /// </summary>
    private const string NestedFieldMapVector =
        "-IAc0J_a5BADAEhpIFRoZXJl1AAFnest-IAJ0J_a-JAD1AAM1AAL1AAK0J_b-IAC0J_z1AAM1AAFicky-JAI-JAC0J_z0J_y-IAD0J_d6HABAAA5Xabc";
}
