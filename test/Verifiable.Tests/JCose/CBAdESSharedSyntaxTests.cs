using System;
using System.Buffers;
using System.Collections.Generic;
using Lumoin.Veritas.Cbor;
using Verifiable.Cbor;
using Verifiable.Cryptography.Pki;
using Verifiable.Foundation;
using Verifiable.JCose;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Tests for the CB-AdES clause 5.4 shared-syntax types — <c>oId</c> (<see cref="AdESObjectIdentifier"/>),
/// <c>pkiOb</c> (<see cref="AdESPkiObject"/>), and <c>tstContainer</c>/<c>TstToken</c>
/// (<see cref="AdESTimestampContainer"/>/<see cref="AdESTimestampToken"/>) — through their
/// <see cref="CBAdESSerialization"/> encode/parse bindings, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>, clause 5.4.
/// </summary>
/// <remarks>
/// Every encode-side test builds its expected bytes with an independent oracle assembled directly from
/// <see cref="CborWriter"/> in canonical mode (never derived from <see cref="CBAdESSerialization"/> itself)
/// and byte-compares that oracle against the shipped <c>Encode*</c> output; every parse-side test then feeds
/// those same independently-built bytes to the shipped <c>TryParse*</c> method and reconstructs the model
/// purely from the returned value — never from the model that produced the bytes — satisfying this project's
/// firewalled-parse convention.
/// </remarks>
[TestClass]
internal sealed class CBAdESSharedSyntaxTests
{
    /// <summary>
    /// Encoding and parsing round-trip when only the required <c>id</c> member (map key 1) is present.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-5.2.3-07, CB-5.4.1-01, CB-5.4.1-05.
    /// </remarks>
    [TestMethod]
    public void ObjectIdentifierRoundTripsWithIdOnly()
    {
        var id = new Uri("https://example.org/cbades/oid/1");
        var model = new AdESObjectIdentifier(id.OriginalString);

        byte[] expected = BuildExpectedObjectIdentifierBytes(id, desc: null, docRefs: null);

        using PooledMemory encoded = CBAdESSerialization.EncodeObjectIdentifier(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");

        bool parsed = CBAdESSerialization.TryParseObjectIdentifier(expected, out AdESObjectIdentifier? result);
        Assert.IsTrue(parsed);
        Assert.IsNotNull(result);
        AssertObjectIdentifierMatches(id, expectedDesc: null, expectedDocRefs: null, result!);
    }


    /// <summary>Encoding and parsing round-trip when the optional <c>desc</c> member (map key 2) is also present.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-5.4.1-02, CB-5.4.1-07.
    /// </remarks>
    [TestMethod]
    public void ObjectIdentifierRoundTripsWithIdAndDesc()
    {
        var id = new Uri("https://example.org/cbades/oid/2");
        const string desc = "A short informal description of the identified object.";
        var model = new AdESObjectIdentifier(id.OriginalString, desc);

        byte[] expected = BuildExpectedObjectIdentifierBytes(id, desc, docRefs: null);

        using PooledMemory encoded = CBAdESSerialization.EncodeObjectIdentifier(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");

        bool parsed = CBAdESSerialization.TryParseObjectIdentifier(expected, out AdESObjectIdentifier? result);
        Assert.IsTrue(parsed);
        Assert.IsNotNull(result);
        AssertObjectIdentifierMatches(id, desc, expectedDocRefs: null, result!);
    }


    /// <summary>Encoding and parsing round-trip when the optional <c>docRefs</c> member (map key 3) is also present.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-5.4.1-03, CB-5.4.1-08.
    /// </remarks>
    [TestMethod]
    public void ObjectIdentifierRoundTripsWithIdAndDocRefs()
    {
        var id = new Uri("https://example.org/cbades/oid/3");
        Uri[] docRefs = [new Uri("https://example.org/docs/spec-1"), new Uri("https://example.org/docs/spec-2")];
        var model = new AdESObjectIdentifier(id.OriginalString, docRefs: docRefs);

        byte[] expected = BuildExpectedObjectIdentifierBytes(id, desc: null, docRefs);

        using PooledMemory encoded = CBAdESSerialization.EncodeObjectIdentifier(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");

        bool parsed = CBAdESSerialization.TryParseObjectIdentifier(expected, out AdESObjectIdentifier? result);
        Assert.IsTrue(parsed);
        Assert.IsNotNull(result);
        AssertObjectIdentifierMatches(id, expectedDesc: null, docRefs, result!);
    }


    /// <summary>Encoding and parsing round-trip when every CDDL member (<c>id</c>, <c>desc</c>, <c>docRefs</c>) is present.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-4.6-01, CB-5.4.1-08.
    /// </remarks>
    [TestMethod]
    public void ObjectIdentifierRoundTripsWithAllMembers()
    {
        var id = new Uri("https://example.org/cbades/oid/4");
        const string desc = "Technical specification defining the signature policy document syntax.";
        Uri[] docRefs = [new Uri("https://example.org/docs/spec-1")];
        var model = new AdESObjectIdentifier(id.OriginalString, desc, docRefs);

        byte[] expected = BuildExpectedObjectIdentifierBytes(id, desc, docRefs);

        using PooledMemory encoded = CBAdESSerialization.EncodeObjectIdentifier(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");

        bool parsed = CBAdESSerialization.TryParseObjectIdentifier(expected, out AdESObjectIdentifier? result);
        Assert.IsTrue(parsed);
        Assert.IsNotNull(result);
        AssertObjectIdentifierMatches(id, desc, docRefs, result!);
    }


    /// <summary>
    /// The CDDL's <c>+</c> occurrence operator (clause 5.4.1) requires a present <c>docRefs</c> member to be
    /// non-empty; constructing <see cref="AdESObjectIdentifier"/> with an empty <c>docRefs</c> array throws.
    /// </summary>
    [TestMethod]
    public void ConstructingObjectIdentifierWithEmptyDocRefsArrayThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            new AdESObjectIdentifier("https://example.org/cbades/oid/1", docRefs: []));
    }


    /// <summary>
    /// Two <see cref="AdESObjectIdentifier"/> instances built from equal <c>id</c>/<c>desc</c> and
    /// separately-allocated but element-equal <c>docRefs</c> lists compare equal under <see cref="object.Equals(object?)"/>,
    /// <c>==</c>, and <see cref="object.GetHashCode"/> — proving the type compares by value (clause 5.4.1)
    /// rather than by <see cref="AdESObjectIdentifier.DocRefs"/> list-instance identity.
    /// </summary>
    [TestMethod]
    public void ObjectIdentifiersWithSeparatelyAllocatedEqualDocRefsCompareEqual()
    {
        var left = new AdESObjectIdentifier(
            "https://example.org/cbades/oid/5",
            "A description.",
            new List<Uri> { new("https://example.org/docs/spec-1"), new("https://example.org/docs/spec-2") });
        var right = new AdESObjectIdentifier(
            "https://example.org/cbades/oid/5",
            "A description.",
            new Uri[] { new("https://example.org/docs/spec-1"), new("https://example.org/docs/spec-2") });

        Assert.AreNotSame(left.DocRefs, right.DocRefs, "The fixture must exercise separately-allocated docRefs list instances.");
        Assert.IsTrue(left.Equals(right), "Instances with element-equal docRefs must compare equal.");
        Assert.IsTrue(left == right, "The synthesized operator== must agree with Equals.");
        Assert.AreEqual(left.GetHashCode(), right.GetHashCode(), "Equal instances must produce equal hash codes.");
    }


    /// <summary>
    /// A <see langword="null"/> <c>docRefs</c> member and an otherwise-equal instance with a present
    /// <c>docRefs</c> member compare unequal, and two present <c>docRefs</c> members carrying the same URIs
    /// in a different order compare unequal — <see cref="AdESObjectIdentifier"/>'s equality is ordered and
    /// distinguishes absence from an empty/differently-ordered sequence.
    /// </summary>
    [TestMethod]
    public void ObjectIdentifiersWithNullDocRefsOrDifferentDocRefsOrderCompareUnequal()
    {
        var withoutDocRefs = new AdESObjectIdentifier("https://example.org/cbades/oid/6");
        var withDocRefs = new AdESObjectIdentifier(
            "https://example.org/cbades/oid/6",
            docRefs: [new Uri("https://example.org/docs/spec-1")]);

        Assert.IsFalse(withoutDocRefs.Equals(withDocRefs), "A null docRefs member must not compare equal to a present one.");
        Assert.IsFalse(withDocRefs.Equals(withoutDocRefs), "Equality must be symmetric for the null/present docRefs case.");

        var forwardOrder = new AdESObjectIdentifier(
            "https://example.org/cbades/oid/7",
            docRefs: [new Uri("https://example.org/docs/spec-1"), new Uri("https://example.org/docs/spec-2")]);
        var reverseOrder = new AdESObjectIdentifier(
            "https://example.org/cbades/oid/7",
            docRefs: [new Uri("https://example.org/docs/spec-2"), new Uri("https://example.org/docs/spec-1")]);

        Assert.IsFalse(forwardOrder.Equals(reverseOrder), "docRefs entries in a different order must not compare equal.");
    }


    /// <summary>Trailing bytes after a complete <c>oId</c> value must fail closed and must not leak a partial result.</summary>
    [TestMethod]
    public void ParseObjectIdentifierFailsClosedOnTrailingData()
    {
        byte[] valid = BuildExpectedObjectIdentifierBytes(new Uri("https://example.org/cbades/oid/1"), desc: null, docRefs: null);
        byte[] withTrailer = [.. valid, 0x00];

        bool parsed = CBAdESSerialization.TryParseObjectIdentifier(withTrailer, out AdESObjectIdentifier? result);

        Assert.IsFalse(parsed, "Trailing bytes after a complete oId value must fail closed.");
        Assert.IsNull(result, "A failed parse must not leak a partially-consumed result.");
    }


    /// <summary>The <c>id</c> member (map key 1) written as a plain integer instead of a tag-32 URI must fail closed.</summary>
    [TestMethod]
    public void ParseObjectIdentifierFailsClosedOnWrongMajorTypeForId()
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(1);
        writer.WriteInt32(42);
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseObjectIdentifier(writerBuffer.WrittenSpan.ToArray(), out AdESObjectIdentifier? result);

        Assert.IsFalse(parsed, "A non-tagged integer in place of the tag-32 URI 'id' member must fail closed.");
        Assert.IsNull(result);
    }


    /// <summary>One <c>docRefs</c> array element written as a plain integer instead of a tag-32 URI must fail closed.</summary>
    [TestMethod]
    public void ParseObjectIdentifierFailsClosedOnWrongMajorTypeForDocRefsEntry()
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(2);
        writer.WriteInt32(1);
        WriteUriTag(writer, new Uri("https://example.org/cbades/oid/1"));
        writer.WriteInt32(3);
        writer.WriteStartArray(1);
        writer.WriteInt32(7);
        writer.WriteEndArray();
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseObjectIdentifier(writerBuffer.WrittenSpan.ToArray(), out AdESObjectIdentifier? result);

        Assert.IsFalse(parsed, "A non-tagged integer in place of a docRefs URI entry must fail closed.");
        Assert.IsNull(result);
    }


    /// <summary>An indefinite-length <c>oId</c> map must fail closed under the canonical-mode reader.</summary>
    [TestMethod]
    public void ParseObjectIdentifierFailsClosedOnIndefiniteLengthMap()
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.Lax);
        writer.WriteStartMap(null);
        writer.WriteInt32(1);
        WriteUriTag(writer, new Uri("https://example.org/cbades/oid/1"));
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseObjectIdentifier(writerBuffer.WrittenSpan.ToArray(), out AdESObjectIdentifier? result);

        Assert.IsFalse(parsed, "An indefinite-length oId map must be rejected under canonical-mode parsing.");
        Assert.IsNull(result);
    }


    /// <summary>A text-string map key in place of the integer <c>id</c> key must fail closed.</summary>
    [TestMethod]
    public void ParseObjectIdentifierFailsClosedOnNonIntegerMapKey()
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(1);
        writer.WriteTextString("id");
        WriteUriTag(writer, new Uri("https://example.org/cbades/oid/1"));
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseObjectIdentifier(writerBuffer.WrittenSpan.ToArray(), out AdESObjectIdentifier? result);

        Assert.IsFalse(parsed, "A text-string map key must fail closed; oId map keys are integers only.");
        Assert.IsNull(result);
    }


    /// <summary>A map with only the optional <c>desc</c> member, omitting the required <c>id</c> member, must fail closed.</summary>
    [TestMethod]
    public void ParseObjectIdentifierFailsClosedOnMissingRequiredId()
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(2);
        writer.WriteTextString("description only, no id");
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseObjectIdentifier(writerBuffer.WrittenSpan.ToArray(), out AdESObjectIdentifier? result);

        Assert.IsFalse(parsed, "A map missing the required 'id' member must fail closed.");
        Assert.IsNull(result);
    }


    /// <summary>
    /// Adversarially deep CBOR array nesting at the top level must fail closed — not throw an uncaught
    /// exception or crash the process — even though the mismatch (an array where a map is expected) is
    /// detected at the very first token.
    /// </summary>
    [TestMethod]
    public void ParseObjectIdentifierFailsClosedOnDepthBombNesting()
    {
        byte[] deeplyNested = BuildDeeplyNestedArrayBytes(10_000);

        bool parsed = CBAdESSerialization.TryParseObjectIdentifier(deeplyNested, out AdESObjectIdentifier? result);

        Assert.IsFalse(parsed, "Adversarially deep top-level nesting must fail closed, not throw or crash.");
        Assert.IsNull(result);
    }


    /// <summary>Encoding and parsing round-trip when only the required <c>val</c> member (map key 1) is present.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-5.4.2-01, CB-5.4.2-03.
    /// </remarks>
    [TestMethod]
    public void PkiObjectRoundTripsWithValOnly()
    {
        byte[] val = [0x30, 0x82, 0x01, 0x0A]; // A plausible DER SEQUENCE prefix; opaque to this type either way.
        var model = new AdESPkiObject { Val = val };

        byte[] expected = BuildExpectedPkiObjectBytes(val, encoding: null, specRef: null);

        using PooledMemory encoded = CBAdESSerialization.EncodePkiObject(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");

        bool parsed = CBAdESSerialization.TryParsePkiObject(expected, out AdESPkiObject? result);
        Assert.IsTrue(parsed);
        Assert.IsNotNull(result);
        AssertPkiObjectMatches(val, expectedEncoding: null, expectedSpecRef: null, result!);
    }


    /// <summary>Encoding and parsing round-trip when the optional <c>encoding</c> member (map key 2) is also present.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-5.4.2-02, CB-5.4.2-03.
    /// </remarks>
    [TestMethod]
    public void PkiObjectRoundTripsWithValAndEncoding()
    {
        byte[] val = [0x30, 0x03, 0x02, 0x01, 0x01];
        var encoding = new Uri("http://uri.etsi.org/01903/v1.2.2#DER");
        var model = new AdESPkiObject { Val = val, Encoding = encoding.OriginalString };

        byte[] expected = BuildExpectedPkiObjectBytes(val, encoding, specRef: null);

        using PooledMemory encoded = CBAdESSerialization.EncodePkiObject(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");

        bool parsed = CBAdESSerialization.TryParsePkiObject(expected, out AdESPkiObject? result);
        Assert.IsTrue(parsed);
        Assert.IsNotNull(result);
        AssertPkiObjectMatches(val, encoding, expectedSpecRef: null, result!);
    }


    /// <summary>Encoding and parsing round-trip when the optional <c>specRef</c> member (map key 3) is also present.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-5.4.2-04.
    /// </remarks>
    [TestMethod]
    public void PkiObjectRoundTripsWithValAndSpecRef()
    {
        byte[] val = [0x04, 0x02, 0xCA, 0xFE];
        var specRef = new Uri("https://example.org/specs/other-cert-format");
        var model = new AdESPkiObject { Val = val, SpecRef = specRef.OriginalString };

        byte[] expected = BuildExpectedPkiObjectBytes(val, encoding: null, specRef);

        using PooledMemory encoded = CBAdESSerialization.EncodePkiObject(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");

        bool parsed = CBAdESSerialization.TryParsePkiObject(expected, out AdESPkiObject? result);
        Assert.IsTrue(parsed);
        Assert.IsNotNull(result);
        AssertPkiObjectMatches(val, expectedEncoding: null, specRef, result!);
    }


    /// <summary>Encoding and parsing round-trip when every CDDL member (<c>val</c>, <c>encoding</c>, <c>specRef</c>) is present.</summary>
    [TestMethod]
    public void PkiObjectRoundTripsWithAllMembers()
    {
        byte[] val = [0x30, 0x82, 0x02, 0x00];
        var encoding = new Uri("http://uri.etsi.org/01903/v1.2.2#DER");
        var specRef = new Uri("https://example.org/specs/x509-attribute-certificate");
        var model = new AdESPkiObject { Val = val, Encoding = encoding.OriginalString, SpecRef = specRef.OriginalString };

        byte[] expected = BuildExpectedPkiObjectBytes(val, encoding, specRef);

        using PooledMemory encoded = CBAdESSerialization.EncodePkiObject(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");

        bool parsed = CBAdESSerialization.TryParsePkiObject(expected, out AdESPkiObject? result);
        Assert.IsTrue(parsed);
        Assert.IsNotNull(result);
        AssertPkiObjectMatches(val, encoding, specRef, result!);
    }


    /// <summary>Trailing bytes after a complete <c>pkiOb</c> value must fail closed and must not leak a partial result.</summary>
    [TestMethod]
    public void ParsePkiObjectFailsClosedOnTrailingData()
    {
        byte[] valid = BuildExpectedPkiObjectBytes([0x01, 0x02, 0x03], encoding: null, specRef: null);
        byte[] withTrailer = [.. valid, 0x00];

        bool parsed = CBAdESSerialization.TryParsePkiObject(withTrailer, out AdESPkiObject? result);

        Assert.IsFalse(parsed, "Trailing bytes after a complete pkiOb value must fail closed.");
        Assert.IsNull(result, "A failed parse must not leak a partially-consumed result.");
    }


    /// <summary>The <c>val</c> member (map key 1) written as a text string instead of a byte string must fail closed.</summary>
    [TestMethod]
    public void ParsePkiObjectFailsClosedOnWrongMajorTypeForVal()
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(1);
        writer.WriteTextString("not a byte string");
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParsePkiObject(writerBuffer.WrittenSpan.ToArray(), out AdESPkiObject? result);

        Assert.IsFalse(parsed, "A text string in place of the byte-string 'val' member must fail closed.");
        Assert.IsNull(result);
    }


    /// <summary>The <c>encoding</c> member (map key 2) written as an untagged text string instead of a tag-32 URI must fail closed.</summary>
    [TestMethod]
    public void ParsePkiObjectFailsClosedOnWrongMajorTypeForEncoding()
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(2);
        writer.WriteInt32(1);
        writer.WriteByteString([0x01]);
        writer.WriteInt32(2);
        writer.WriteTextString("http://uri.etsi.org/01903/v1.2.2#DER"); // Missing the mandatory tag 32 wrapper.
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParsePkiObject(writerBuffer.WrittenSpan.ToArray(), out AdESPkiObject? result);

        Assert.IsFalse(parsed, "An untagged text string in place of the tag-32 URI 'encoding' member must fail closed.");
        Assert.IsNull(result);
    }


    /// <summary>An indefinite-length <c>pkiOb</c> map must fail closed under the canonical-mode reader.</summary>
    [TestMethod]
    public void ParsePkiObjectFailsClosedOnIndefiniteLengthMap()
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.Lax);
        writer.WriteStartMap(null);
        writer.WriteInt32(1);
        writer.WriteByteString([0x01, 0x02]);
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParsePkiObject(writerBuffer.WrittenSpan.ToArray(), out AdESPkiObject? result);

        Assert.IsFalse(parsed, "An indefinite-length pkiOb map must be rejected under canonical-mode parsing.");
        Assert.IsNull(result);
    }


    /// <summary>A text-string map key in place of the integer <c>val</c> key must fail closed.</summary>
    [TestMethod]
    public void ParsePkiObjectFailsClosedOnNonIntegerMapKey()
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(1);
        writer.WriteTextString("val");
        writer.WriteByteString([0x01]);
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParsePkiObject(writerBuffer.WrittenSpan.ToArray(), out AdESPkiObject? result);

        Assert.IsFalse(parsed, "A text-string map key must fail closed; pkiOb map keys are integers only.");
        Assert.IsNull(result);
    }


    /// <summary>A map with only the optional <c>encoding</c> member, omitting the required <c>val</c> member, must fail closed.</summary>
    [TestMethod]
    public void ParsePkiObjectFailsClosedOnMissingRequiredVal()
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(2);
        WriteUriTag(writer, new Uri("http://uri.etsi.org/01903/v1.2.2#DER"));
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParsePkiObject(writerBuffer.WrittenSpan.ToArray(), out AdESPkiObject? result);

        Assert.IsFalse(parsed, "A map missing the required 'val' member must fail closed.");
        Assert.IsNull(result);
    }


    /// <summary>
    /// Adversarially deep CBOR array nesting at the top level must fail closed — not throw an uncaught
    /// exception or crash the process.
    /// </summary>
    [TestMethod]
    public void ParsePkiObjectFailsClosedOnDepthBombNesting()
    {
        byte[] deeplyNested = BuildDeeplyNestedArrayBytes(10_000);

        bool parsed = CBAdESSerialization.TryParsePkiObject(deeplyNested, out AdESPkiObject? result);

        Assert.IsFalse(parsed, "Adversarially deep top-level nesting must fail closed, not throw or crash.");
        Assert.IsNull(result);
    }


    /// <summary>
    /// A single token carrying only the required <c>val</c> member round-trips — the legacy RFC 3161 shape,
    /// where <c>type</c>/<c>encoding</c>/<c>specRef</c> shall all be absent (clause 5.4.3.3).
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-5.4.3.3-01, CB-5.4.3.3-05, CB-5.4.3.3-06, CB-5.4.3.3-07, CB-5.4.3.3-08,
    /// CB-5.4.3.3-09.
    /// </remarks>
    [TestMethod]
    public void TimestampContainerRoundTripsWithRfc3161StyleToken()
    {
        TokenFixture[] tokens = [new([0x30, 0x82, 0x03, 0x00], Type: null, Encoding: null, SpecRef: null)];

        byte[] expected = BuildExpectedTimestampContainerBytes(tokens);

        using AdESTimestampContainer model = BuildTimestampContainerModel(tokens);
        using PooledMemory encoded = CBAdESSerialization.EncodeTimestampContainer(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");

        bool parsed = CBAdESSerialization.TryParseTimestampContainer(expected, out AdESTimestampContainer? result);
        Assert.IsTrue(parsed);
        Assert.IsNotNull(result);
        using(result)
        {
            AssertTimestampContainerMatches(tokens, result!);
        }
    }


    /// <summary>A single token additionally carrying the optional <c>type</c> member (map key 2) round-trips.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-5.4.3.3-01, CB-5.4.3.3-05.
    /// </remarks>
    [TestMethod]
    public void TimestampContainerRoundTripsWithTypedToken()
    {
        TokenFixture[] tokens = [new([0x01, 0x02], Type: "application/vnd.example.timestamp", Encoding: null, SpecRef: null)];

        byte[] expected = BuildExpectedTimestampContainerBytes(tokens);

        using AdESTimestampContainer model = BuildTimestampContainerModel(tokens);
        using PooledMemory encoded = CBAdESSerialization.EncodeTimestampContainer(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");

        bool parsed = CBAdESSerialization.TryParseTimestampContainer(expected, out AdESTimestampContainer? result);
        Assert.IsTrue(parsed);
        Assert.IsNotNull(result);
        using(result)
        {
            AssertTimestampContainerMatches(tokens, result!);
        }
    }


    /// <summary>A single token additionally carrying the optional <c>encoding</c> and <c>specRef</c> members (map keys 3, 4) round-trips.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-5.4.3.3-06, CB-5.4.3.3-07.
    /// </remarks>
    [TestMethod]
    public void TimestampContainerRoundTripsWithEncodingAndSpecRef()
    {
        TokenFixture[] tokens =
        [
            new(
                [0x03, 0x04],
                Type: null,
                Encoding: new Uri("https://example.org/encodings/example-tst"),
                SpecRef: new Uri("https://example.org/specs/example-tst-format"))
        ];

        byte[] expected = BuildExpectedTimestampContainerBytes(tokens);

        using AdESTimestampContainer model = BuildTimestampContainerModel(tokens);
        using PooledMemory encoded = CBAdESSerialization.EncodeTimestampContainer(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");

        bool parsed = CBAdESSerialization.TryParseTimestampContainer(expected, out AdESTimestampContainer? result);
        Assert.IsTrue(parsed);
        Assert.IsNotNull(result);
        using(result)
        {
            AssertTimestampContainerMatches(tokens, result!);
        }
    }


    /// <summary>A single token carrying every optional member (<c>type</c>, <c>encoding</c>, <c>specRef</c>) round-trips.</summary>
    [TestMethod]
    public void TimestampContainerRoundTripsWithAllOptionalMembers()
    {
        TokenFixture[] tokens =
        [
            new(
                [0x05, 0x06, 0x07],
                Type: "application/vnd.example.timestamp",
                Encoding: new Uri("https://example.org/encodings/example-tst"),
                SpecRef: new Uri("https://example.org/specs/example-tst-format"))
        ];

        byte[] expected = BuildExpectedTimestampContainerBytes(tokens);

        using AdESTimestampContainer model = BuildTimestampContainerModel(tokens);
        using PooledMemory encoded = CBAdESSerialization.EncodeTimestampContainer(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");

        bool parsed = CBAdESSerialization.TryParseTimestampContainer(expected, out AdESTimestampContainer? result);
        Assert.IsTrue(parsed);
        Assert.IsNotNull(result);
        using(result)
        {
            AssertTimestampContainerMatches(tokens, result!);
        }
    }


    /// <summary>
    /// Multiple tokens of independently varying shape (clause 5.4.3.3-03: more than one token for the same
    /// message imprint, e.g. one per Time-Stamping Authority) round-trip in their exact wire order.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-5.4.3.1-01, CB-5.4.3.3-03.
    /// </remarks>
    [TestMethod]
    public void TimestampContainerRoundTripsWithMultipleTokensInWireOrder()
    {
        TokenFixture[] tokens =
        [
            new([0x10], Type: null, Encoding: null, SpecRef: null),
            new([0x11, 0x12], Type: "application/vnd.example.timestamp", Encoding: null, SpecRef: null),
            new([0x13, 0x14, 0x15], Type: null, Encoding: new Uri("https://example.org/encodings/third-tst"), SpecRef: null)
        ];

        byte[] expected = BuildExpectedTimestampContainerBytes(tokens);

        using AdESTimestampContainer model = BuildTimestampContainerModel(tokens);
        using PooledMemory encoded = CBAdESSerialization.EncodeTimestampContainer(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");

        bool parsed = CBAdESSerialization.TryParseTimestampContainer(expected, out AdESTimestampContainer? result);
        Assert.IsTrue(parsed);
        Assert.IsNotNull(result);
        using(result)
        {
            AssertTimestampContainerMatches(tokens, result!);
        }
    }


    /// <summary>
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1, clause 5.4.3.3</see>: the CB-AdES <c>tstContainer</c> CDDL carries only
    /// <c>tstTokens</c> — no member states a canonicalization-algorithm identifier. Encoding a container built
    /// with a non-null <see cref="AdESTimestampContainer.CanonAlg"/> — JAdES-only syntax (ETSI TS 119 182-1
    /// V1.2.1, clause 5.4.3.3, JA-5.4.3.3-16) — is refused.
    /// </summary>
    [TestMethod]
    public void EncodeTimestampContainerThrowsWhenCanonAlgIsPresent()
    {
        using var model = new AdESTimestampContainer(
            [new AdESTimestampToken { Val = new byte[] { 0x30, 0x82, 0x03, 0x00 } }],
            canonAlg: "http://www.w3.org/2006/12/xml-c14n11");

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => CBAdESSerialization.EncodeTimestampContainer(model, BaseMemoryPool.Shared));

        Assert.IsTrue(exception.Message.Contains("5.4.3.3", StringComparison.Ordinal));
        Assert.IsTrue(exception.Message.Contains("canonAlg", StringComparison.Ordinal));
    }


    /// <summary>Trailing bytes after a complete <c>tstContainer</c> value must fail closed and must not leak a partial result.</summary>
    [TestMethod]
    public void ParseTimestampContainerFailsClosedOnTrailingData()
    {
        byte[] valid = BuildExpectedTimestampContainerBytes([new([0x01], Type: null, Encoding: null, SpecRef: null)]);
        byte[] withTrailer = [.. valid, 0x00];

        bool parsed = CBAdESSerialization.TryParseTimestampContainer(withTrailer, out AdESTimestampContainer? result);

        Assert.IsFalse(parsed, "Trailing bytes after a complete tstContainer value must fail closed.");
        Assert.IsNull(result, "A failed parse must not leak a partially-consumed result.");
        result?.Dispose();
    }


    /// <summary>A token's <c>val</c> member (map key 1) written as a text string instead of a byte string must fail closed.</summary>
    [TestMethod]
    public void ParseTimestampContainerFailsClosedOnWrongMajorTypeForTokenVal()
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(1);
        writer.WriteStartArray(1);
        writer.WriteStartMap(1);
        writer.WriteInt32(1);
        writer.WriteTextString("not a byte string");
        writer.WriteEndMap();
        writer.WriteEndArray();
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseTimestampContainer(writerBuffer.WrittenSpan.ToArray(), out AdESTimestampContainer? result);

        Assert.IsFalse(parsed, "A text string in place of a token's byte-string 'val' member must fail closed.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>An indefinite-length <c>tstContainer</c> map must fail closed under the canonical-mode reader.</summary>
    [TestMethod]
    public void ParseTimestampContainerFailsClosedOnIndefiniteLengthContainer()
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.Lax);
        writer.WriteStartMap(null);
        writer.WriteInt32(1);
        writer.WriteStartArray(1);
        writer.WriteStartMap(1);
        writer.WriteInt32(1);
        writer.WriteByteString([0x01]);
        writer.WriteEndMap();
        writer.WriteEndArray();
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseTimestampContainer(writerBuffer.WrittenSpan.ToArray(), out AdESTimestampContainer? result);

        Assert.IsFalse(parsed, "An indefinite-length tstContainer map must be rejected under canonical-mode parsing.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>A text-string map key in place of the integer <c>tstTokens</c> key must fail closed.</summary>
    [TestMethod]
    public void ParseTimestampContainerFailsClosedOnNonIntegerMapKey()
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(1);
        writer.WriteTextString("tstTokens");
        writer.WriteStartArray(1);
        writer.WriteStartMap(1);
        writer.WriteInt32(1);
        writer.WriteByteString([0x01]);
        writer.WriteEndMap();
        writer.WriteEndArray();
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseTimestampContainer(writerBuffer.WrittenSpan.ToArray(), out AdESTimestampContainer? result);

        Assert.IsFalse(parsed, "A text-string map key must fail closed; tstContainer map keys are integers only.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>An empty <c>tstTokens</c> array violates the CDDL's <c>+TstToken</c> non-empty cardinality and must fail closed.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
    /// ETSI TS 119 152-1 V1.1.1</see> CB-5.4.3.3-04.
    /// </remarks>
    [TestMethod]
    public void ParseTimestampContainerFailsClosedOnEmptyTokensArray()
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(1);
        writer.WriteStartArray(0);
        writer.WriteEndArray();
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseTimestampContainer(writerBuffer.WrittenSpan.ToArray(), out AdESTimestampContainer? result);

        Assert.IsFalse(parsed, "An empty tstTokens array violates the '+TstToken' cardinality and must fail closed.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>A token map with only the optional <c>type</c> member, omitting the required <c>val</c> member, must fail closed.</summary>
    [TestMethod]
    public void ParseTimestampContainerFailsClosedOnMissingRequiredVal()
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(1);
        writer.WriteStartArray(1);
        writer.WriteStartMap(1);
        writer.WriteInt32(2);
        writer.WriteTextString("type only, no val");
        writer.WriteEndMap();
        writer.WriteEndArray();
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseTimestampContainer(writerBuffer.WrittenSpan.ToArray(), out AdESTimestampContainer? result);

        Assert.IsFalse(parsed, "A token map missing the required 'val' member must fail closed.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>
    /// Adversarially deep CBOR array nesting at the top level must fail closed — not throw an uncaught
    /// exception or crash the process.
    /// </summary>
    [TestMethod]
    public void ParseTimestampContainerFailsClosedOnDepthBombNesting()
    {
        byte[] deeplyNested = BuildDeeplyNestedArrayBytes(10_000);

        bool parsed = CBAdESSerialization.TryParseTimestampContainer(deeplyNested, out AdESTimestampContainer? result);

        Assert.IsFalse(parsed, "Adversarially deep top-level nesting must fail closed, not throw or crash.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>
    /// Writes a CBOR tag-32 URI (<see href="https://www.rfc-editor.org/rfc/rfc8949#section-3.4.5.3">RFC 8949
    /// §3.4.5.3</see>) directly with <see cref="CborWriter"/> primitives — the shared fragment every oracle
    /// helper below uses for a <c>#6.32(tstr)</c>-typed CDDL member, kept independent of the library's own
    /// <c>WriteUri</c> extension method.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="uri">The absolute URI to write.</param>
    private static void WriteUriTag(CborWriter writer, Uri uri)
    {
        writer.WriteTag(CborTag.Uri);
        writer.WriteTextString(uri.AbsoluteUri);
    }


    /// <summary>
    /// Assembles the expected canonical CBOR bytes for an <c>oId</c> map (clause 5.4.1, Table 11), directly
    /// with <see cref="CborWriter"/> — this suite's independent encode oracle, never derived from
    /// <see cref="CBAdESSerialization"/>.
    /// </summary>
    /// <param name="id">The <c>id</c> member's value (map key 1, required).</param>
    /// <param name="desc">The <c>desc</c> member's value (map key 2), or <see langword="null"/> to omit it.</param>
    /// <param name="docRefs">The <c>docRefs</c> member's value (map key 3), or <see langword="null"/> to omit it.</param>
    /// <returns>The expected canonical CBOR bytes.</returns>
    private static byte[] BuildExpectedObjectIdentifierBytes(Uri id, string? desc, Uri[]? docRefs)
    {
        int memberCount = 1 + (desc is not null ? 1 : 0) + (docRefs is not null ? 1 : 0);

        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(memberCount);

        writer.WriteInt32(1);
        WriteUriTag(writer, id);

        if(desc is not null)
        {
            writer.WriteInt32(2);
            writer.WriteTextString(desc);
        }

        if(docRefs is not null)
        {
            writer.WriteInt32(3);
            writer.WriteStartArray(docRefs.Length);
            foreach(Uri docRef in docRefs)
            {
                WriteUriTag(writer, docRef);
            }

            writer.WriteEndArray();
        }

        writer.WriteEndMap();
        return writerBuffer.WrittenSpan.ToArray();
    }


    /// <summary>Asserts that a parsed <see cref="AdESObjectIdentifier"/>'s members match the expected values, field by field.</summary>
    /// <param name="expectedId">The expected <c>id</c> member.</param>
    /// <param name="expectedDesc">The expected <c>desc</c> member, or <see langword="null"/>.</param>
    /// <param name="expectedDocRefs">The expected <c>docRefs</c> member, or <see langword="null"/>.</param>
    /// <param name="actual">The parsed value.</param>
    private static void AssertObjectIdentifierMatches(Uri expectedId, string? expectedDesc, Uri[]? expectedDocRefs, AdESObjectIdentifier actual)
    {
        Assert.AreEqual(expectedId.OriginalString, actual.Id, "The 'id' member must round-trip.");
        Assert.AreEqual(expectedDesc, actual.Desc, "The 'desc' member must round-trip.");

        if(expectedDocRefs is null)
        {
            Assert.IsNull(actual.DocRefs, "An absent 'docRefs' member must round-trip as null.");
        }
        else
        {
            Assert.IsNotNull(actual.DocRefs);
            Assert.HasCount(expectedDocRefs.Length, actual.DocRefs!);
            for(int i = 0; i < expectedDocRefs.Length; i++)
            {
                Assert.AreEqual(expectedDocRefs[i], actual.DocRefs![i], $"docRefs[{i}] must round-trip.");
            }
        }
    }


    /// <summary>
    /// Assembles the expected canonical CBOR bytes for a <c>pkiOb</c> map (clause 5.4.2, Table 12), directly
    /// with <see cref="CborWriter"/> — this suite's independent encode oracle, never derived from
    /// <see cref="CBAdESSerialization"/>.
    /// </summary>
    /// <param name="val">The <c>val</c> member's value (map key 1, required).</param>
    /// <param name="encoding">The <c>encoding</c> member's value (map key 2), or <see langword="null"/> to omit it.</param>
    /// <param name="specRef">The <c>specRef</c> member's value (map key 3), or <see langword="null"/> to omit it.</param>
    /// <returns>The expected canonical CBOR bytes.</returns>
    private static byte[] BuildExpectedPkiObjectBytes(byte[] val, Uri? encoding, Uri? specRef)
    {
        int memberCount = 1 + (encoding is not null ? 1 : 0) + (specRef is not null ? 1 : 0);

        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(memberCount);

        writer.WriteInt32(1);
        writer.WriteByteString(val);

        if(encoding is not null)
        {
            writer.WriteInt32(2);
            WriteUriTag(writer, encoding);
        }

        if(specRef is not null)
        {
            writer.WriteInt32(3);
            WriteUriTag(writer, specRef);
        }

        writer.WriteEndMap();
        return writerBuffer.WrittenSpan.ToArray();
    }


    /// <summary>Asserts that a parsed <see cref="AdESPkiObject"/>'s members match the expected values, field by field.</summary>
    /// <param name="expectedVal">The expected <c>val</c> member bytes.</param>
    /// <param name="expectedEncoding">The expected <c>encoding</c> member, or <see langword="null"/>.</param>
    /// <param name="expectedSpecRef">The expected <c>specRef</c> member, or <see langword="null"/>.</param>
    /// <param name="actual">The parsed value.</param>
    private static void AssertPkiObjectMatches(byte[] expectedVal, Uri? expectedEncoding, Uri? expectedSpecRef, AdESPkiObject actual)
    {
        Assert.IsTrue(expectedVal.AsSpan().SequenceEqual(actual.Val.Span), "The 'val' member must round-trip byte-for-byte.");
        Assert.AreEqual(expectedEncoding?.OriginalString, actual.Encoding, "The 'encoding' member must round-trip.");
        Assert.AreEqual(expectedSpecRef?.OriginalString, actual.SpecRef, "The 'specRef' member must round-trip.");
    }


    /// <summary>One <c>TstToken</c> fixture: the four CDDL members (clause 5.4.3.3, Table 13) an oracle or model builder needs.</summary>
    /// <param name="Val">The <c>val</c> member's bytes (map key 1, required).</param>
    /// <param name="Type">The <c>type</c> member (map key 2), or <see langword="null"/> to omit it.</param>
    /// <param name="Encoding">The <c>encoding</c> member (map key 3), or <see langword="null"/> to omit it.</param>
    /// <param name="SpecRef">The <c>specRef</c> member (map key 4), or <see langword="null"/> to omit it.</param>
    private sealed record TokenFixture(byte[] Val, string? Type, Uri? Encoding, Uri? SpecRef);


    /// <summary>Builds a <see cref="AdESTimestampContainer"/> model instance directly from a set of <see cref="TokenFixture"/> values, in order.</summary>
    /// <param name="tokens">The token fixtures, in wire order.</param>
    /// <returns>The built model instance.</returns>
    private static AdESTimestampContainer BuildTimestampContainerModel(IReadOnlyList<TokenFixture> tokens)
    {
        var built = new List<AdESTimestampToken>(tokens.Count);
        foreach(TokenFixture token in tokens)
        {
            built.Add(new AdESTimestampToken { Val = token.Val, Type = token.Type, Encoding = token.Encoding?.OriginalString, SpecRef = token.SpecRef?.OriginalString });
        }

        return new AdESTimestampContainer(built);
    }


    /// <summary>
    /// Assembles the expected canonical CBOR bytes for a <c>tstContainer</c> map (clause 5.4.3.3, Table 13),
    /// directly with <see cref="CborWriter"/> — this suite's independent encode oracle, never derived from
    /// <see cref="CBAdESSerialization"/>.
    /// </summary>
    /// <param name="tokens">The token fixtures, in wire order.</param>
    /// <returns>The expected canonical CBOR bytes.</returns>
    private static byte[] BuildExpectedTimestampContainerBytes(IReadOnlyList<TokenFixture> tokens)
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(1);
        writer.WriteStartArray(tokens.Count);

        foreach(TokenFixture token in tokens)
        {
            int memberCount = 1
                + (token.Type is not null ? 1 : 0)
                + (token.Encoding is not null ? 1 : 0)
                + (token.SpecRef is not null ? 1 : 0);

            writer.WriteStartMap(memberCount);
            writer.WriteInt32(1);
            writer.WriteByteString(token.Val);

            if(token.Type is not null)
            {
                writer.WriteInt32(2);
                writer.WriteTextString(token.Type);
            }

            if(token.Encoding is not null)
            {
                writer.WriteInt32(3);
                WriteUriTag(writer, token.Encoding);
            }

            if(token.SpecRef is not null)
            {
                writer.WriteInt32(4);
                WriteUriTag(writer, token.SpecRef);
            }

            writer.WriteEndMap();
        }

        writer.WriteEndArray();
        writer.WriteEndMap();
        return writerBuffer.WrittenSpan.ToArray();
    }


    /// <summary>Asserts that a parsed <see cref="AdESTimestampContainer"/>'s tokens match the expected fixtures, field by field, in order.</summary>
    /// <param name="expected">The expected token fixtures, in wire order.</param>
    /// <param name="actual">The parsed container.</param>
    private static void AssertTimestampContainerMatches(IReadOnlyList<TokenFixture> expected, AdESTimestampContainer actual)
    {
        Assert.HasCount(expected.Count, actual.TstTokens);
        for(int i = 0; i < expected.Count; i++)
        {
            TokenFixture expectedToken = expected[i];
            AdESTimestampToken actualToken = actual.TstTokens[i];

            Assert.IsTrue(expectedToken.Val.AsSpan().SequenceEqual(actualToken.Val.Span), $"tstTokens[{i}]'s 'val' member must round-trip byte-for-byte.");
            Assert.AreEqual(expectedToken.Type, actualToken.Type, $"tstTokens[{i}]'s 'type' member must round-trip.");
            Assert.AreEqual(expectedToken.Encoding?.OriginalString, actualToken.Encoding, $"tstTokens[{i}]'s 'encoding' member must round-trip.");
            Assert.AreEqual(expectedToken.SpecRef?.OriginalString, actualToken.SpecRef, $"tstTokens[{i}]'s 'specRef' member must round-trip.");
        }
    }


    /// <summary>
    /// Builds well-formed but adversarially deep CBOR bytes — <paramref name="depth"/> singly-nested arrays,
    /// each containing exactly the next, with an integer at the innermost position — used by every
    /// depth-bomb negative test in this suite. Definite-length throughout, so it remains valid CBOR under
    /// canonical-mode conformance; only its nesting depth is adversarial.
    /// </summary>
    /// <param name="depth">The nesting depth.</param>
    /// <returns>The encoded bytes.</returns>
    private static byte[] BuildDeeplyNestedArrayBytes(int depth)
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        for(int i = 0; i < depth; i++)
        {
            writer.WriteStartArray(1);
        }

        writer.WriteInt32(0);

        for(int i = 0; i < depth; i++)
        {
            writer.WriteEndArray();
        }

        return writerBuffer.WrittenSpan.ToArray();
    }
}
