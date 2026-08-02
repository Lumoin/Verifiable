using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using Verifiable.Cbor;
using Verifiable.Cryptography.Pki;
using Verifiable.Foundation;
using Verifiable.JCose;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Tests for the CB-AdES stage-1 clause 5.4 shared-syntax types — <c>oId</c> (<see cref="CBAdESObjectIdentifier"/>),
/// <c>pkiOb</c> (<see cref="CBAdESPkiObject"/>), and <c>tstContainer</c>/<c>TstToken</c>
/// (<see cref="CBAdESTimestampContainer"/>/<see cref="CBAdESTimestampToken"/>) — through their
/// <see cref="CBAdESSerialization"/> encode/parse bindings, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>, clause 5.4.
/// </summary>
/// <remarks>
/// Every encode-side test builds its expected bytes with an independent oracle assembled directly from
/// <see cref="CborWriter"/> in canonical mode (never derived from <see cref="CBAdESSerialization"/> itself)
/// and byte-compares that oracle against the shipped <c>Encode*</c> output; every parse-side test then feeds
/// those same independently-built bytes to the shipped <c>TryParse*</c> method and reconstructs the model
/// purely from the returned value — never from the model that produced the bytes — satisfying this wave's
/// firewalled-parse convention.
/// </remarks>
[TestClass]
internal sealed class CBAdESSharedSyntaxTests
{
    /// <summary>
    /// Encoding and parsing round-trip when only the required <c>id</c> member (map key 1) is present.
    /// </summary>
    [TestMethod]
    public void ObjectIdentifierRoundTripsWithIdOnly()
    {
        var id = new Uri("https://example.org/cbades/oid/1");
        var model = new CBAdESObjectIdentifier(id);

        byte[] expected = BuildExpectedObjectIdentifierBytes(id, desc: null, docRefs: null);

        using PooledMemory encoded = CBAdESSerialization.EncodeObjectIdentifier(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");

        bool parsed = CBAdESSerialization.TryParseObjectIdentifier(expected, out CBAdESObjectIdentifier? result);
        Assert.IsTrue(parsed);
        Assert.IsNotNull(result);
        AssertObjectIdentifierMatches(id, expectedDesc: null, expectedDocRefs: null, result!);
    }


    /// <summary>Encoding and parsing round-trip when the optional <c>desc</c> member (map key 2) is also present.</summary>
    [TestMethod]
    public void ObjectIdentifierRoundTripsWithIdAndDesc()
    {
        var id = new Uri("https://example.org/cbades/oid/2");
        const string desc = "A short informal description of the identified object.";
        var model = new CBAdESObjectIdentifier(id, desc);

        byte[] expected = BuildExpectedObjectIdentifierBytes(id, desc, docRefs: null);

        using PooledMemory encoded = CBAdESSerialization.EncodeObjectIdentifier(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");

        bool parsed = CBAdESSerialization.TryParseObjectIdentifier(expected, out CBAdESObjectIdentifier? result);
        Assert.IsTrue(parsed);
        Assert.IsNotNull(result);
        AssertObjectIdentifierMatches(id, desc, expectedDocRefs: null, result!);
    }


    /// <summary>Encoding and parsing round-trip when the optional <c>docRefs</c> member (map key 3) is also present.</summary>
    [TestMethod]
    public void ObjectIdentifierRoundTripsWithIdAndDocRefs()
    {
        var id = new Uri("https://example.org/cbades/oid/3");
        Uri[] docRefs = [new Uri("https://example.org/docs/spec-1"), new Uri("https://example.org/docs/spec-2")];
        var model = new CBAdESObjectIdentifier(id, docRefs: docRefs);

        byte[] expected = BuildExpectedObjectIdentifierBytes(id, desc: null, docRefs);

        using PooledMemory encoded = CBAdESSerialization.EncodeObjectIdentifier(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");

        bool parsed = CBAdESSerialization.TryParseObjectIdentifier(expected, out CBAdESObjectIdentifier? result);
        Assert.IsTrue(parsed);
        Assert.IsNotNull(result);
        AssertObjectIdentifierMatches(id, expectedDesc: null, docRefs, result!);
    }


    /// <summary>Encoding and parsing round-trip when every CDDL member (<c>id</c>, <c>desc</c>, <c>docRefs</c>) is present.</summary>
    [TestMethod]
    public void ObjectIdentifierRoundTripsWithAllMembers()
    {
        var id = new Uri("https://example.org/cbades/oid/4");
        const string desc = "Technical specification defining the signature policy document syntax.";
        Uri[] docRefs = [new Uri("https://example.org/docs/spec-1")];
        var model = new CBAdESObjectIdentifier(id, desc, docRefs);

        byte[] expected = BuildExpectedObjectIdentifierBytes(id, desc, docRefs);

        using PooledMemory encoded = CBAdESSerialization.EncodeObjectIdentifier(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");

        bool parsed = CBAdESSerialization.TryParseObjectIdentifier(expected, out CBAdESObjectIdentifier? result);
        Assert.IsTrue(parsed);
        Assert.IsNotNull(result);
        AssertObjectIdentifierMatches(id, desc, docRefs, result!);
    }


    /// <summary>
    /// The CDDL's <c>+</c> occurrence operator (clause 5.4.1) requires a present <c>docRefs</c> member to be
    /// non-empty; constructing <see cref="CBAdESObjectIdentifier"/> with an empty <c>docRefs</c> array throws.
    /// </summary>
    [TestMethod]
    public void ConstructingObjectIdentifierWithEmptyDocRefsArrayThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() =>
            new CBAdESObjectIdentifier(new Uri("https://example.org/cbades/oid/1"), docRefs: []));
    }


    /// <summary>Trailing bytes after a complete <c>oId</c> value must fail closed and must not leak a partial result.</summary>
    [TestMethod]
    public void ParseObjectIdentifierFailsClosedOnTrailingData()
    {
        byte[] valid = BuildExpectedObjectIdentifierBytes(new Uri("https://example.org/cbades/oid/1"), desc: null, docRefs: null);
        byte[] withTrailer = [.. valid, 0x00];

        bool parsed = CBAdESSerialization.TryParseObjectIdentifier(withTrailer, out CBAdESObjectIdentifier? result);

        Assert.IsFalse(parsed, "Trailing bytes after a complete oId value must fail closed.");
        Assert.IsNull(result, "A failed parse must not leak a partially-consumed result.");
    }


    /// <summary>The <c>id</c> member (map key 1) written as a plain integer instead of a tag-32 URI must fail closed.</summary>
    [TestMethod]
    public void ParseObjectIdentifierFailsClosedOnWrongMajorTypeForId()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(1);
        writer.WriteInt32(42);
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseObjectIdentifier(writer.Encode(), out CBAdESObjectIdentifier? result);

        Assert.IsFalse(parsed, "A non-tagged integer in place of the tag-32 URI 'id' member must fail closed.");
        Assert.IsNull(result);
    }


    /// <summary>One <c>docRefs</c> array element written as a plain integer instead of a tag-32 URI must fail closed.</summary>
    [TestMethod]
    public void ParseObjectIdentifierFailsClosedOnWrongMajorTypeForDocRefsEntry()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(2);
        writer.WriteInt32(1);
        WriteUriTag(writer, new Uri("https://example.org/cbades/oid/1"));
        writer.WriteInt32(3);
        writer.WriteStartArray(1);
        writer.WriteInt32(7);
        writer.WriteEndArray();
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseObjectIdentifier(writer.Encode(), out CBAdESObjectIdentifier? result);

        Assert.IsFalse(parsed, "A non-tagged integer in place of a docRefs URI entry must fail closed.");
        Assert.IsNull(result);
    }


    /// <summary>An indefinite-length <c>oId</c> map must fail closed under the canonical-mode reader.</summary>
    [TestMethod]
    public void ParseObjectIdentifierFailsClosedOnIndefiniteLengthMap()
    {
        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteStartMap(null);
        writer.WriteInt32(1);
        WriteUriTag(writer, new Uri("https://example.org/cbades/oid/1"));
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseObjectIdentifier(writer.Encode(), out CBAdESObjectIdentifier? result);

        Assert.IsFalse(parsed, "An indefinite-length oId map must be rejected under canonical-mode parsing.");
        Assert.IsNull(result);
    }


    /// <summary>A text-string map key in place of the integer <c>id</c> key must fail closed.</summary>
    [TestMethod]
    public void ParseObjectIdentifierFailsClosedOnNonIntegerMapKey()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteTextString("id");
        WriteUriTag(writer, new Uri("https://example.org/cbades/oid/1"));
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseObjectIdentifier(writer.Encode(), out CBAdESObjectIdentifier? result);

        Assert.IsFalse(parsed, "A text-string map key must fail closed; oId map keys are integers only.");
        Assert.IsNull(result);
    }


    /// <summary>A map with only the optional <c>desc</c> member, omitting the required <c>id</c> member, must fail closed.</summary>
    [TestMethod]
    public void ParseObjectIdentifierFailsClosedOnMissingRequiredId()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(2);
        writer.WriteTextString("description only, no id");
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseObjectIdentifier(writer.Encode(), out CBAdESObjectIdentifier? result);

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

        bool parsed = CBAdESSerialization.TryParseObjectIdentifier(deeplyNested, out CBAdESObjectIdentifier? result);

        Assert.IsFalse(parsed, "Adversarially deep top-level nesting must fail closed, not throw or crash.");
        Assert.IsNull(result);
    }


    /// <summary>Encoding and parsing round-trip when only the required <c>val</c> member (map key 1) is present.</summary>
    [TestMethod]
    public void PkiObjectRoundTripsWithValOnly()
    {
        byte[] val = [0x30, 0x82, 0x01, 0x0A]; // A plausible DER SEQUENCE prefix; opaque to this type either way.
        var model = new CBAdESPkiObject { Val = val };

        byte[] expected = BuildExpectedPkiObjectBytes(val, encoding: null, specRef: null);

        using PooledMemory encoded = CBAdESSerialization.EncodePkiObject(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");

        bool parsed = CBAdESSerialization.TryParsePkiObject(expected, out CBAdESPkiObject? result);
        Assert.IsTrue(parsed);
        Assert.IsNotNull(result);
        AssertPkiObjectMatches(val, expectedEncoding: null, expectedSpecRef: null, result!);
    }


    /// <summary>Encoding and parsing round-trip when the optional <c>encoding</c> member (map key 2) is also present.</summary>
    [TestMethod]
    public void PkiObjectRoundTripsWithValAndEncoding()
    {
        byte[] val = [0x30, 0x03, 0x02, 0x01, 0x01];
        var encoding = new Uri("http://uri.etsi.org/01903/v1.2.2#DER");
        var model = new CBAdESPkiObject { Val = val, Encoding = encoding };

        byte[] expected = BuildExpectedPkiObjectBytes(val, encoding, specRef: null);

        using PooledMemory encoded = CBAdESSerialization.EncodePkiObject(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");

        bool parsed = CBAdESSerialization.TryParsePkiObject(expected, out CBAdESPkiObject? result);
        Assert.IsTrue(parsed);
        Assert.IsNotNull(result);
        AssertPkiObjectMatches(val, encoding, expectedSpecRef: null, result!);
    }


    /// <summary>Encoding and parsing round-trip when the optional <c>specRef</c> member (map key 3) is also present.</summary>
    [TestMethod]
    public void PkiObjectRoundTripsWithValAndSpecRef()
    {
        byte[] val = [0x04, 0x02, 0xCA, 0xFE];
        var specRef = new Uri("https://example.org/specs/other-cert-format");
        var model = new CBAdESPkiObject { Val = val, SpecRef = specRef };

        byte[] expected = BuildExpectedPkiObjectBytes(val, encoding: null, specRef);

        using PooledMemory encoded = CBAdESSerialization.EncodePkiObject(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");

        bool parsed = CBAdESSerialization.TryParsePkiObject(expected, out CBAdESPkiObject? result);
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
        var model = new CBAdESPkiObject { Val = val, Encoding = encoding, SpecRef = specRef };

        byte[] expected = BuildExpectedPkiObjectBytes(val, encoding, specRef);

        using PooledMemory encoded = CBAdESSerialization.EncodePkiObject(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");

        bool parsed = CBAdESSerialization.TryParsePkiObject(expected, out CBAdESPkiObject? result);
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

        bool parsed = CBAdESSerialization.TryParsePkiObject(withTrailer, out CBAdESPkiObject? result);

        Assert.IsFalse(parsed, "Trailing bytes after a complete pkiOb value must fail closed.");
        Assert.IsNull(result, "A failed parse must not leak a partially-consumed result.");
    }


    /// <summary>The <c>val</c> member (map key 1) written as a text string instead of a byte string must fail closed.</summary>
    [TestMethod]
    public void ParsePkiObjectFailsClosedOnWrongMajorTypeForVal()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(1);
        writer.WriteTextString("not a byte string");
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParsePkiObject(writer.Encode(), out CBAdESPkiObject? result);

        Assert.IsFalse(parsed, "A text string in place of the byte-string 'val' member must fail closed.");
        Assert.IsNull(result);
    }


    /// <summary>The <c>encoding</c> member (map key 2) written as an untagged text string instead of a tag-32 URI must fail closed.</summary>
    [TestMethod]
    public void ParsePkiObjectFailsClosedOnWrongMajorTypeForEncoding()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(2);
        writer.WriteInt32(1);
        writer.WriteByteString([0x01]);
        writer.WriteInt32(2);
        writer.WriteTextString("http://uri.etsi.org/01903/v1.2.2#DER"); // Missing the mandatory tag 32 wrapper.
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParsePkiObject(writer.Encode(), out CBAdESPkiObject? result);

        Assert.IsFalse(parsed, "An untagged text string in place of the tag-32 URI 'encoding' member must fail closed.");
        Assert.IsNull(result);
    }


    /// <summary>An indefinite-length <c>pkiOb</c> map must fail closed under the canonical-mode reader.</summary>
    [TestMethod]
    public void ParsePkiObjectFailsClosedOnIndefiniteLengthMap()
    {
        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteStartMap(null);
        writer.WriteInt32(1);
        writer.WriteByteString([0x01, 0x02]);
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParsePkiObject(writer.Encode(), out CBAdESPkiObject? result);

        Assert.IsFalse(parsed, "An indefinite-length pkiOb map must be rejected under canonical-mode parsing.");
        Assert.IsNull(result);
    }


    /// <summary>A text-string map key in place of the integer <c>val</c> key must fail closed.</summary>
    [TestMethod]
    public void ParsePkiObjectFailsClosedOnNonIntegerMapKey()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteTextString("val");
        writer.WriteByteString([0x01]);
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParsePkiObject(writer.Encode(), out CBAdESPkiObject? result);

        Assert.IsFalse(parsed, "A text-string map key must fail closed; pkiOb map keys are integers only.");
        Assert.IsNull(result);
    }


    /// <summary>A map with only the optional <c>encoding</c> member, omitting the required <c>val</c> member, must fail closed.</summary>
    [TestMethod]
    public void ParsePkiObjectFailsClosedOnMissingRequiredVal()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(2);
        WriteUriTag(writer, new Uri("http://uri.etsi.org/01903/v1.2.2#DER"));
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParsePkiObject(writer.Encode(), out CBAdESPkiObject? result);

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

        bool parsed = CBAdESSerialization.TryParsePkiObject(deeplyNested, out CBAdESPkiObject? result);

        Assert.IsFalse(parsed, "Adversarially deep top-level nesting must fail closed, not throw or crash.");
        Assert.IsNull(result);
    }


    /// <summary>
    /// A single token carrying only the required <c>val</c> member round-trips — the legacy RFC 3161 shape,
    /// where <c>type</c>/<c>encoding</c>/<c>specRef</c> shall all be absent (clause 5.4.3.3).
    /// </summary>
    [TestMethod]
    public void TimestampContainerRoundTripsWithRfc3161StyleToken()
    {
        TokenFixture[] tokens = [new([0x30, 0x82, 0x03, 0x00], Type: null, Encoding: null, SpecRef: null)];

        byte[] expected = BuildExpectedTimestampContainerBytes(tokens);

        using CBAdESTimestampContainer model = BuildTimestampContainerModel(tokens);
        using PooledMemory encoded = CBAdESSerialization.EncodeTimestampContainer(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");

        bool parsed = CBAdESSerialization.TryParseTimestampContainer(expected, out CBAdESTimestampContainer? result);
        Assert.IsTrue(parsed);
        Assert.IsNotNull(result);
        using(result)
        {
            AssertTimestampContainerMatches(tokens, result!);
        }
    }


    /// <summary>A single token additionally carrying the optional <c>type</c> member (map key 2) round-trips.</summary>
    [TestMethod]
    public void TimestampContainerRoundTripsWithTypedToken()
    {
        TokenFixture[] tokens = [new([0x01, 0x02], Type: "application/vnd.example.timestamp", Encoding: null, SpecRef: null)];

        byte[] expected = BuildExpectedTimestampContainerBytes(tokens);

        using CBAdESTimestampContainer model = BuildTimestampContainerModel(tokens);
        using PooledMemory encoded = CBAdESSerialization.EncodeTimestampContainer(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");

        bool parsed = CBAdESSerialization.TryParseTimestampContainer(expected, out CBAdESTimestampContainer? result);
        Assert.IsTrue(parsed);
        Assert.IsNotNull(result);
        using(result)
        {
            AssertTimestampContainerMatches(tokens, result!);
        }
    }


    /// <summary>A single token additionally carrying the optional <c>encoding</c> and <c>specRef</c> members (map keys 3, 4) round-trips.</summary>
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

        using CBAdESTimestampContainer model = BuildTimestampContainerModel(tokens);
        using PooledMemory encoded = CBAdESSerialization.EncodeTimestampContainer(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");

        bool parsed = CBAdESSerialization.TryParseTimestampContainer(expected, out CBAdESTimestampContainer? result);
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

        using CBAdESTimestampContainer model = BuildTimestampContainerModel(tokens);
        using PooledMemory encoded = CBAdESSerialization.EncodeTimestampContainer(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");

        bool parsed = CBAdESSerialization.TryParseTimestampContainer(expected, out CBAdESTimestampContainer? result);
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

        using CBAdESTimestampContainer model = BuildTimestampContainerModel(tokens);
        using PooledMemory encoded = CBAdESSerialization.EncodeTimestampContainer(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");

        bool parsed = CBAdESSerialization.TryParseTimestampContainer(expected, out CBAdESTimestampContainer? result);
        Assert.IsTrue(parsed);
        Assert.IsNotNull(result);
        using(result)
        {
            AssertTimestampContainerMatches(tokens, result!);
        }
    }


    /// <summary>Trailing bytes after a complete <c>tstContainer</c> value must fail closed and must not leak a partial result.</summary>
    [TestMethod]
    public void ParseTimestampContainerFailsClosedOnTrailingData()
    {
        byte[] valid = BuildExpectedTimestampContainerBytes([new([0x01], Type: null, Encoding: null, SpecRef: null)]);
        byte[] withTrailer = [.. valid, 0x00];

        bool parsed = CBAdESSerialization.TryParseTimestampContainer(withTrailer, out CBAdESTimestampContainer? result);

        Assert.IsFalse(parsed, "Trailing bytes after a complete tstContainer value must fail closed.");
        Assert.IsNull(result, "A failed parse must not leak a partially-consumed result.");
        result?.Dispose();
    }


    /// <summary>A token's <c>val</c> member (map key 1) written as a text string instead of a byte string must fail closed.</summary>
    [TestMethod]
    public void ParseTimestampContainerFailsClosedOnWrongMajorTypeForTokenVal()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(1);
        writer.WriteStartArray(1);
        writer.WriteStartMap(1);
        writer.WriteInt32(1);
        writer.WriteTextString("not a byte string");
        writer.WriteEndMap();
        writer.WriteEndArray();
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseTimestampContainer(writer.Encode(), out CBAdESTimestampContainer? result);

        Assert.IsFalse(parsed, "A text string in place of a token's byte-string 'val' member must fail closed.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>An indefinite-length <c>tstContainer</c> map must fail closed under the canonical-mode reader.</summary>
    [TestMethod]
    public void ParseTimestampContainerFailsClosedOnIndefiniteLengthContainer()
    {
        var writer = new CborWriter(CborConformanceMode.Lax);
        writer.WriteStartMap(null);
        writer.WriteInt32(1);
        writer.WriteStartArray(1);
        writer.WriteStartMap(1);
        writer.WriteInt32(1);
        writer.WriteByteString([0x01]);
        writer.WriteEndMap();
        writer.WriteEndArray();
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseTimestampContainer(writer.Encode(), out CBAdESTimestampContainer? result);

        Assert.IsFalse(parsed, "An indefinite-length tstContainer map must be rejected under canonical-mode parsing.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>A text-string map key in place of the integer <c>tstTokens</c> key must fail closed.</summary>
    [TestMethod]
    public void ParseTimestampContainerFailsClosedOnNonIntegerMapKey()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteTextString("tstTokens");
        writer.WriteStartArray(1);
        writer.WriteStartMap(1);
        writer.WriteInt32(1);
        writer.WriteByteString([0x01]);
        writer.WriteEndMap();
        writer.WriteEndArray();
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseTimestampContainer(writer.Encode(), out CBAdESTimestampContainer? result);

        Assert.IsFalse(parsed, "A text-string map key must fail closed; tstContainer map keys are integers only.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>An empty <c>tstTokens</c> array violates the CDDL's <c>+TstToken</c> non-empty cardinality and must fail closed.</summary>
    [TestMethod]
    public void ParseTimestampContainerFailsClosedOnEmptyTokensArray()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(1);
        writer.WriteStartArray(0);
        writer.WriteEndArray();
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseTimestampContainer(writer.Encode(), out CBAdESTimestampContainer? result);

        Assert.IsFalse(parsed, "An empty tstTokens array violates the '+TstToken' cardinality and must fail closed.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>A token map with only the optional <c>type</c> member, omitting the required <c>val</c> member, must fail closed.</summary>
    [TestMethod]
    public void ParseTimestampContainerFailsClosedOnMissingRequiredVal()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(1);
        writer.WriteStartArray(1);
        writer.WriteStartMap(1);
        writer.WriteInt32(2);
        writer.WriteTextString("type only, no val");
        writer.WriteEndMap();
        writer.WriteEndArray();
        writer.WriteEndMap();

        bool parsed = CBAdESSerialization.TryParseTimestampContainer(writer.Encode(), out CBAdESTimestampContainer? result);

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

        bool parsed = CBAdESSerialization.TryParseTimestampContainer(deeplyNested, out CBAdESTimestampContainer? result);

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

        var writer = new CborWriter(CborConformanceMode.Canonical);
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
        return writer.Encode();
    }


    /// <summary>Asserts that a parsed <see cref="CBAdESObjectIdentifier"/>'s members match the expected values, field by field.</summary>
    /// <param name="expectedId">The expected <c>id</c> member.</param>
    /// <param name="expectedDesc">The expected <c>desc</c> member, or <see langword="null"/>.</param>
    /// <param name="expectedDocRefs">The expected <c>docRefs</c> member, or <see langword="null"/>.</param>
    /// <param name="actual">The parsed value.</param>
    private static void AssertObjectIdentifierMatches(Uri expectedId, string? expectedDesc, Uri[]? expectedDocRefs, CBAdESObjectIdentifier actual)
    {
        Assert.AreEqual(expectedId, actual.Id, "The 'id' member must round-trip.");
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

        var writer = new CborWriter(CborConformanceMode.Canonical);
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
        return writer.Encode();
    }


    /// <summary>Asserts that a parsed <see cref="CBAdESPkiObject"/>'s members match the expected values, field by field.</summary>
    /// <param name="expectedVal">The expected <c>val</c> member bytes.</param>
    /// <param name="expectedEncoding">The expected <c>encoding</c> member, or <see langword="null"/>.</param>
    /// <param name="expectedSpecRef">The expected <c>specRef</c> member, or <see langword="null"/>.</param>
    /// <param name="actual">The parsed value.</param>
    private static void AssertPkiObjectMatches(byte[] expectedVal, Uri? expectedEncoding, Uri? expectedSpecRef, CBAdESPkiObject actual)
    {
        Assert.IsTrue(expectedVal.AsSpan().SequenceEqual(actual.Val.Span), "The 'val' member must round-trip byte-for-byte.");
        Assert.AreEqual(expectedEncoding, actual.Encoding, "The 'encoding' member must round-trip.");
        Assert.AreEqual(expectedSpecRef, actual.SpecRef, "The 'specRef' member must round-trip.");
    }


    /// <summary>One <c>TstToken</c> fixture: the four CDDL members (clause 5.4.3.3, Table 13) an oracle or model builder needs.</summary>
    /// <param name="Val">The <c>val</c> member's bytes (map key 1, required).</param>
    /// <param name="Type">The <c>type</c> member (map key 2), or <see langword="null"/> to omit it.</param>
    /// <param name="Encoding">The <c>encoding</c> member (map key 3), or <see langword="null"/> to omit it.</param>
    /// <param name="SpecRef">The <c>specRef</c> member (map key 4), or <see langword="null"/> to omit it.</param>
    private sealed record TokenFixture(byte[] Val, string? Type, Uri? Encoding, Uri? SpecRef);


    /// <summary>Builds a <see cref="CBAdESTimestampContainer"/> model instance directly from a set of <see cref="TokenFixture"/> values, in order.</summary>
    /// <param name="tokens">The token fixtures, in wire order.</param>
    /// <returns>The built model instance.</returns>
    private static CBAdESTimestampContainer BuildTimestampContainerModel(IReadOnlyList<TokenFixture> tokens)
    {
        var built = new List<CBAdESTimestampToken>(tokens.Count);
        foreach(TokenFixture token in tokens)
        {
            built.Add(new CBAdESTimestampToken { Val = token.Val, Type = token.Type, Encoding = token.Encoding, SpecRef = token.SpecRef });
        }

        return new CBAdESTimestampContainer { TstTokens = built };
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
        var writer = new CborWriter(CborConformanceMode.Canonical);
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
        return writer.Encode();
    }


    /// <summary>Asserts that a parsed <see cref="CBAdESTimestampContainer"/>'s tokens match the expected fixtures, field by field, in order.</summary>
    /// <param name="expected">The expected token fixtures, in wire order.</param>
    /// <param name="actual">The parsed container.</param>
    private static void AssertTimestampContainerMatches(IReadOnlyList<TokenFixture> expected, CBAdESTimestampContainer actual)
    {
        Assert.HasCount(expected.Count, actual.TstTokens);
        for(int i = 0; i < expected.Count; i++)
        {
            TokenFixture expectedToken = expected[i];
            CBAdESTimestampToken actualToken = actual.TstTokens[i];

            Assert.IsTrue(expectedToken.Val.AsSpan().SequenceEqual(actualToken.Val.Span), $"tstTokens[{i}]'s 'val' member must round-trip byte-for-byte.");
            Assert.AreEqual(expectedToken.Type, actualToken.Type, $"tstTokens[{i}]'s 'type' member must round-trip.");
            Assert.AreEqual(expectedToken.Encoding, actualToken.Encoding, $"tstTokens[{i}]'s 'encoding' member must round-trip.");
            Assert.AreEqual(expectedToken.SpecRef, actualToken.SpecRef, $"tstTokens[{i}]'s 'specRef' member must round-trip.");
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
        var writer = new CborWriter(CborConformanceMode.Canonical);
        for(int i = 0; i < depth; i++)
        {
            writer.WriteStartArray(1);
        }

        writer.WriteInt32(0);

        for(int i = 0; i < depth; i++)
        {
            writer.WriteEndArray();
        }

        return writer.Encode();
    }
}
