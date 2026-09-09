using System;
using System.Buffers;
using System.Collections.Generic;
using Lumoin.Veritas.Cbor;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Foundation;
using Verifiable.JCose;
using Verifiable.Tests.Foundation;

namespace Verifiable.Tests.JCose;

/// <summary>
/// Tests for the CB-AdES <c>uHeaders</c> unsigned header parameter — the ordered, append-only
/// element sequence model (<see cref="CBAdESUnsignedHeaders"/>, <c>Verifiable.Cryptography.Pki</c>) and its
/// <see cref="CBAdESSerialization"/> encode/parse bindings (<c>Verifiable.Cbor</c>), per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see>, clause 5.3.1, Table 8.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Independent oracle.</strong> Every encode-byte-comparison test builds its expected CBOR bytes
/// with a freshly constructed <see cref="CborWriter"/> in canonical mode, written directly against clause
/// 5.3.1's CDDL and Table 8's label assignments as SPEC-TABLE LITERAL integers (<c>1</c>, <c>2</c>, ...,
/// <c>33</c>) — never the <see cref="CBAdESUnsignedHeaderElement"/> label constants or any other
/// <see cref="CBAdESSerialization"/>-internal helper — so a defect shared between the codec and this
/// suite's own oracle cannot hide behind it.
/// </para>
/// <para>
/// <strong>Firewalled parsing.</strong> Every round-trip and negative parse test hands
/// <see cref="CBAdESSerialization.TryParseUnsignedHeaders"/> bytes assembled by this file's own oracle
/// helpers, never bytes produced by this file's own calls into
/// <see cref="CBAdESSerialization.EncodeUnsignedHeaders"/> — the parser is exercised from wire bytes only.
/// </para>
/// <para>
/// <strong>Digest fixtures.</strong> The one <see cref="DigestValue"/> fixture this file needs (the
/// <c>refs</c> element's <c>x5t</c> digest) is a real SHA-256 digest computed through the registered
/// <see cref="CryptographicKeyEvents"/> digest delegate seam, never a hand-rolled hash.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CBAdESUnsignedHeadersTests
{
    /// <summary>The MSTest context, carrying the cancellation token the one asynchronous test observes.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The repository-relative path declaring <see cref="CBAdESUnsignedHeaders"/>.</summary>
    private const string CBAdESUnsignedHeadersPath = "src/Verifiable.Cryptography/Pki/CBAdESUnsignedHeaders.cs";


    /// <summary>
    /// <see cref="CBAdESUnsignedHeaders"/>'s constructor throws on a <see langword="null"/> element sequence.
    /// </summary>
    [TestMethod]
    public void ConstructingUnsignedHeadersWithNullElementsThrows()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => new CBAdESUnsignedHeaders(null!));
    }


    /// <summary>
    /// CB-5.3.1-07: "The <c>uHeaders</c> header parameter shall be a non-empty array." Constructing
    /// <see cref="CBAdESUnsignedHeaders"/> from an empty sequence throws rather than representing an
    /// illegal empty-but-present value.
    /// </summary>
    [TestMethod]
    public void ConstructingUnsignedHeadersWithEmptyElementsThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new CBAdESUnsignedHeaders([]));
    }


    /// <summary>
    /// The constructor takes an owned snapshot of the supplied sequence (per its own documented remarks):
    /// mutating the caller's list afterwards must not be visible through the constructed instance.
    /// </summary>
    [TestMethod]
    public void ConstructingUnsignedHeadersTakesSnapshotOfSuppliedList()
    {
        var source = new List<CBAdESUnsignedHeaderElement> { MakeUnknownElement(1, [0x01]) };
        using var headers = new CBAdESUnsignedHeaders(source);

        source.Add(MakeUnknownElement(2, [0x02]));

        Assert.AreEqual(1, headers.Count, "Mutating the caller's list after construction must not affect the constructed instance.");
    }


    /// <summary>
    /// CB-5.3.1-03: "New unsigned attributes shall always be added at the end of the <c>uHeaders</c> header
    /// parameter." <see cref="CBAdESUnsignedHeaders.Append"/> returns a NEW instance with the supplied
    /// element placed last, leaving the receiver unchanged.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">ETSI TS 119 152-1 V1.1.1</see>
    /// CB-5.3.5.2-05.
    /// </remarks>
    [TestMethod]
    public void AppendReturnsNewInstanceLeavingOriginalUnchanged()
    {
        CBAdESUnsignedHeaderElement first = MakeUnknownElement(1, [0x01]);
        CBAdESUnsignedHeaderElement second = MakeUnknownElement(2, [0x02]);
        using var original = new CBAdESUnsignedHeaders([first]);

        using CBAdESUnsignedHeaders appended = original.Append(second);

        Assert.AreEqual(1, original.Count, "Append must not mutate the receiver.");
        Assert.AreEqual(2, appended.Count);
        Assert.AreSame(first, appended[0], "Every pre-existing element must precede the newly appended one.");
        Assert.AreSame(second, appended[1], "The appended element must be placed last.");
    }


    /// <summary><see cref="CBAdESUnsignedHeaders.Append"/> throws on a <see langword="null"/> element.</summary>
    [TestMethod]
    public void AppendWithNullElementThrows()
    {
        using var headers = new CBAdESUnsignedHeaders([MakeUnknownElement(1, [0x01])]);

        Assert.ThrowsExactly<ArgumentNullException>(() => headers.Append(null!));
    }


    /// <summary>
    /// <see cref="CBAdESUnsignedHeaders.ElementsBefore"/> returns the exact prefix at every meaningful
    /// boundary: the empty prefix at index 0, a genuine strict-prefix in the middle, and the full sequence
    /// at <see cref="CBAdESUnsignedHeaders.Count"/> — the generation-time full-sequence view clause 5.3.5.3
    /// relies on alongside the validation-time strict-prefix view.
    /// </summary>
    [TestMethod]
    public void ElementsBeforeReturnsExactPrefixAtEveryBoundary()
    {
        CBAdESUnsignedHeaderElement e0 = MakeUnknownElement(1, [0x01]);
        CBAdESUnsignedHeaderElement e1 = MakeUnknownElement(2, [0x02]);
        CBAdESUnsignedHeaderElement e2 = MakeUnknownElement(3, [0x03]);
        CBAdESUnsignedHeaderElement e3 = MakeUnknownElement(4, [0x04]);
        using var headers = new CBAdESUnsignedHeaders([e0, e1, e2, e3]);

        Assert.IsEmpty(headers.ElementsBefore(0), "Index 0 must yield the empty prefix.");

        IReadOnlyList<CBAdESUnsignedHeaderElement> prefixOfTwo = headers.ElementsBefore(2);
        Assert.HasCount(2, prefixOfTwo);
        Assert.AreSame(e0, prefixOfTwo[0]);
        Assert.AreSame(e1, prefixOfTwo[1]);

        IReadOnlyList<CBAdESUnsignedHeaderElement> everything = headers.ElementsBefore(headers.Count);
        Assert.HasCount(4, everything);
        Assert.AreSame(e3, everything[3], "ElementsBefore(Count) must be the full, generation-time sequence.");
    }


    /// <summary>
    /// <see cref="CBAdESUnsignedHeaders.ElementsBefore"/> throws on an index outside <c>[0, Count]</c>.
    /// </summary>
    [TestMethod]
    public void ElementsBeforeThrowsOnOutOfRangeIndex()
    {
        using var headers = new CBAdESUnsignedHeaders([MakeUnknownElement(1, [0x01])]);

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => headers.ElementsBefore(-1));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => headers.ElementsBefore(headers.Count + 1));
    }


    /// <summary>
    /// Indexer access and sequential enumeration must agree, position for position, on the wire
    /// (incorporation) order CB-5.3.1-01/03 requires.
    /// </summary>
    [TestMethod]
    public void IndexerAndEnumerationAgreeOnWireOrder()
    {
        CBAdESUnsignedHeaderElement e0 = MakeUnknownElement(1, [0x01]);
        CBAdESUnsignedHeaderElement e1 = MakeUnknownElement(2, [0x02]);
        CBAdESUnsignedHeaderElement e2 = MakeUnknownElement(3, [0x03]);
        using var headers = new CBAdESUnsignedHeaders([e0, e1, e2]);

        var viaEnumeration = new List<CBAdESUnsignedHeaderElement>();
        foreach(CBAdESUnsignedHeaderElement element in headers)
        {
            viaEnumeration.Add(element);
        }

        Assert.HasCount(3, viaEnumeration);
        for(int i = 0; i < headers.Count; i++)
        {
            Assert.AreSame(headers[i], viaEnumeration[i], $"Enumeration order must agree with the indexer at position {i}.");
        }
    }


    /// <summary>
    /// CB-5.3.1-03 ("New unsigned attributes shall always be added at the end") is enforced by API shape,
    /// not a runtime flag: <see cref="CBAdESUnsignedHeaders.Append"/> must remain the sole growth operation,
    /// and the public surface must never expose an insert-at/remove/reorder/sort member that could
    /// reintroduce a reordering hazard. Checked as a source scan of the declaring file's own public
    /// instance-method declaration lines, so a future edit that adds such a member fails this test rather
    /// than silently reopening the hazard — with no reflection over the loaded type.
    /// </summary>
    [TestMethod]
    public void PublicSurfaceExposesNoInsertRemoveOrReorderOperation()
    {
        string[] disallowedNameFragments = ["Insert", "Remove", "Sort", "Reverse", "Clear", "Reorder", "Replace", "SetItem", "Move"];
        string text = File.ReadAllText(Path.Combine(SourceHygieneScanner.FindRepositoryRoot(), CBAdESUnsignedHeadersPath));
        MatchCollection publicInstanceMethodDeclarations = Regex.Matches(
            text, @"(?m)^\s*public\s+(?!static\b)[\w<>\[\],\.\?]+\s+(\w+)\s*\(");

        string[] publicInstanceMethodNames = [.. publicInstanceMethodDeclarations.Select(static m => m.Groups[1].Value)];

        foreach(string methodName in publicInstanceMethodNames)
        {
            foreach(string fragment in disallowedNameFragments)
            {
                Assert.IsFalse(
                    methodName.Contains(fragment, StringComparison.OrdinalIgnoreCase),
                    $"Public method '{methodName}' looks like it could insert, remove, or reorder elements, " +
                    "which would break the CB-5.3.1-03 append-only invariant.");
            }
        }

        Assert.Contains("Append", publicInstanceMethodNames, "Append must remain the sole growth operation.");
    }


    /// <summary>
    /// A mixed <c>uHeaders</c> sequence — one instance of every Table 8 typed arm (labels <c>1</c>-<c>7</c>),
    /// the <c>x5chain</c> opaque arm (label <c>33</c>), an unrecognized integer label, and an unrecognized
    /// text label, ten elements in all — encodes to exactly this suite's independent oracle bytes, and the
    /// independently-built oracle bytes parse back with every element's kind, label, and content preserved
    /// in the exact original order (CB-5.3.1-01/03/04/11).
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">ETSI TS 119 152-1 V1.1.1</see>
    /// CB-4.7-01, CB-4.7-02, CB-5.1.8-01, CB-5.1.8-02, CB-5.1.8-05, CB-5.3.1-02, CB-5.3.1-05, CB-5.3.1-06,
    /// CB-5.3.5.2-05.
    /// </remarks>
    [TestMethod]
    public async Task RoundTripsMixedElementSequenceByteExactlyPreservingOrder()
    {
        byte[] sigTstVal = [0x30, 0x01];
        byte[] valDataCertBytes = [0x30, 0x02];
        byte[] arcTstVal = [0x30, 0x03];
        byte[] sigRTstVal = [0x30, 0x05];
        byte[] rfsTstVal = [0x30, 0x06];
        byte[] sigPStDocBytes = [0xAA, 0xBB, 0xCC];
        byte[] x5chainCertBytes = [0x30, 0x82, 0x01, 0x00];
        const int unknownIntLabel = 9999;
        const int unknownIntValue = 424242;
        const string unknownTextLabel = "x-custom-attribute";
        const string unknownTextValue = "opaque-custom-payload";

        DigestValue refsDigest = await CreateDigestAsync("refs certificate"u8.ToArray(), TestContext.CancellationToken).ConfigureAwait(false);
        byte[] refsDigestBytes = refsDigest.AsReadOnlySpan().ToArray();

        byte[] expected = BuildExpectedMixedUnsignedHeadersBytes(
            sigTstVal, valDataCertBytes, arcTstVal, WellKnownCoseAlgorithms.Sha256, refsDigestBytes,
            sigRTstVal, rfsTstVal, sigPStDocBytes, x5chainCertBytes,
            unknownIntLabel, unknownIntValue, unknownTextLabel, unknownTextValue);

        using CBAdESUnsignedHeaders model = BuildMixedUnsignedHeadersModel(
            sigTstVal, valDataCertBytes, arcTstVal, WellKnownCoseAlgorithms.Sha256, refsDigest,
            sigRTstVal, rfsTstVal, sigPStDocBytes, x5chainCertBytes,
            unknownIntLabel, unknownIntValue, unknownTextLabel, unknownTextValue);

        Assert.AreEqual(10, model.Count);

        using PooledMemory encoded = CBAdESSerialization.EncodeUnsignedHeaders(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");

        bool parsed = CBAdESSerialization.TryParseUnsignedHeaders(expected, BaseMemoryPool.Shared, out CBAdESUnsignedHeaders? result);
        Assert.IsTrue(parsed);
        Assert.IsNotNull(result);
        using(result)
        {
            CBAdESUnsignedHeaders header = result!;
            Assert.AreEqual(10, header.Count);
            Assert.IsTrue(header[0] is CBAdESUnsignedHeaderElementSignatureTimestamp, "Element 0 must be sigTst (label 1).");
            Assert.IsTrue(header[1] is CBAdESUnsignedHeaderElementValidationData, "Element 1 must be valData (label 2).");
            Assert.IsTrue(header[2] is CBAdESUnsignedHeaderElementArchiveTimestamp, "Element 2 must be arcTst (label 3).");
            Assert.IsTrue(header[3] is CBAdESUnsignedHeaderElementReferences, "Element 3 must be refs (label 4).");
            Assert.IsTrue(header[4] is CBAdESUnsignedHeaderElementSignatureAndReferencesTimestamp, "Element 4 must be sigRTst (label 5).");
            Assert.IsTrue(header[5] is CBAdESUnsignedHeaderElementReferencesTimestamp, "Element 5 must be rfsTst (label 6).");
            Assert.IsTrue(header[6] is CBAdESUnsignedHeaderElementSignaturePolicyStore, "Element 6 must be sigPSt (label 7).");
            Assert.IsTrue(header[7] is CBAdESUnsignedHeaderElementCertificateChain, "Element 7 must be x5chain (label 33).");
            Assert.IsTrue(header[8] is CBAdESUnsignedHeaderElementUnknown, "Element 8 must be the unrecognized-integer-label catch-all.");
            Assert.IsTrue(header[9] is CBAdESUnsignedHeaderElementUnknown, "Element 9 must be the unrecognized-text-label catch-all.");

            var certificateChain = (CBAdESUnsignedHeaderElementCertificateChain)header[7];
            Assert.IsTrue(
                EncodeX5ChainOpaqueValue(x5chainCertBytes).AsSpan().SequenceEqual(certificateChain.Value.Span),
                "x5chain (label 33) must round-trip byte-exactly, not be dropped as unrecognized.");

            var unknownInt = (CBAdESUnsignedHeaderElementUnknown)header[8];
            Assert.AreEqual(new CBAdESUnsignedHeaderElementIntegerLabel(unknownIntLabel), unknownInt.Label);
            Assert.IsTrue(
                EncodeIntValue(unknownIntValue).AsSpan().SequenceEqual(unknownInt.Value.Span),
                "An unrecognized integer label's element must round-trip byte-exactly, not be dropped.");

            var unknownText = (CBAdESUnsignedHeaderElementUnknown)header[9];
            Assert.AreEqual(new CBAdESUnsignedHeaderElementTextLabel(unknownTextLabel), unknownText.Label);
            Assert.IsTrue(
                EncodeTextValue(unknownTextValue).AsSpan().SequenceEqual(unknownText.Value.Span),
                "An unrecognized text label's element must round-trip byte-exactly, not be dropped.");

            using PooledMemory reencoded = CBAdESSerialization.EncodeUnsignedHeaders(header, BaseMemoryPool.Shared);
            Assert.IsTrue(expected.AsSpan().SequenceEqual(reencoded.AsReadOnlySpan()), "Re-encoding the parsed value must reproduce the original bytes exactly, order preserved.");
        }
    }


    /// <summary>CB-5.3.1-07: an empty <c>uHeaders</c> array must fail closed rather than parse as a zero-element instance.</summary>
    [TestMethod]
    public void TryParseUnsignedHeadersFailsClosedOnEmptyArray()
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartArray(0);
        writer.WriteEndArray();

        bool parsed = CBAdESSerialization.TryParseUnsignedHeaders(writerBuffer.WrittenSpan.ToArray(), BaseMemoryPool.Shared, out CBAdESUnsignedHeaders? result);

        Assert.IsFalse(parsed, "An empty 'uHeaders' array violates CB-5.3.1-07's non-empty-array requirement and must fail closed.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>CB-5.3.1-04: an array element that is not itself a CBOR byte string must fail closed.</summary>
    [TestMethod]
    public void TryParseUnsignedHeadersFailsClosedOnElementNotByteString()
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartArray(1);
        writer.WriteInt32(42); //Not a bstr -- CB-5.3.1-04 requires every element encapsulated in a CBOR byte string.
        writer.WriteEndArray();

        bool parsed = CBAdESSerialization.TryParseUnsignedHeaders(writerBuffer.WrittenSpan.ToArray(), BaseMemoryPool.Shared, out CBAdESUnsignedHeaders? result);

        Assert.IsFalse(parsed, "A non-bstr array element violates CB-5.3.1-04 and must fail closed.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>
    /// <c>UHeaderInstance</c> is structurally a ONE-entry map (clause 5.3.1 CDDL); a <c>bstr</c> array
    /// element wrapping a two-entry map must fail closed.
    /// </summary>
    [TestMethod]
    public void TryParseUnsignedHeadersFailsClosedOnElementWrappingTwoEntryMap()
    {
        var innerWriterBuffer = new ArrayBufferWriter<byte>();
        var innerWriter = new CborWriter(innerWriterBuffer, CborOptions.RfcCanonical);
        innerWriter.WriteStartMap(2);
        innerWriter.WriteInt32(1);
        innerWriter.WriteInt32(0);
        innerWriter.WriteInt32(2);
        innerWriter.WriteInt32(0);
        innerWriter.WriteEndMap();

        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartArray(1);
        writer.WriteByteString(innerWriterBuffer.WrittenSpan.ToArray());
        writer.WriteEndArray();

        bool parsed = CBAdESSerialization.TryParseUnsignedHeaders(writerBuffer.WrittenSpan.ToArray(), BaseMemoryPool.Shared, out CBAdESUnsignedHeaders? result);

        Assert.IsFalse(parsed, "A UHeaderInstance bstr wrapping a two-entry map violates the one-entry-map shape and must fail closed.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>
    /// CB-5.3.1-11: an unrecognized integer label's element round-trips byte-exactly through the catch-all
    /// arm — the extension escape hatch preserves, rather than drops, data this document does not itself
    /// specify.
    /// </summary>
    [TestMethod]
    public void TryParseUnsignedHeadersRoundTripsSingleUnrecognizedIntegerLabelElementByteExactly()
    {
        const int label = 12345;
        const int value = 777;
        byte[] expected = BuildSingleElementUnsignedHeadersBytes(EncodeUnknownIntElement(label, value));

        bool parsed = CBAdESSerialization.TryParseUnsignedHeaders(expected, BaseMemoryPool.Shared, out CBAdESUnsignedHeaders? result);

        Assert.IsTrue(parsed);
        Assert.IsNotNull(result);
        using(result)
        {
            CBAdESUnsignedHeaders header = result!;
            Assert.HasCount(1, header);
            Assert.IsTrue(header[0] is CBAdESUnsignedHeaderElementUnknown, "An unrecognized integer label must round-trip as the catch-all arm, not be dropped.");

            var unknown = (CBAdESUnsignedHeaderElementUnknown)header[0];
            Assert.AreEqual(new CBAdESUnsignedHeaderElementIntegerLabel(label), unknown.Label);
            Assert.IsTrue(EncodeIntValue(value).AsSpan().SequenceEqual(unknown.Value.Span));

            using PooledMemory reencoded = CBAdESSerialization.EncodeUnsignedHeaders(header, BaseMemoryPool.Shared);
            Assert.IsTrue(expected.AsSpan().SequenceEqual(reencoded.AsReadOnlySpan()), "Re-encoding must reproduce the original bytes exactly.");
        }
    }


    /// <summary>
    /// CB-5.3.1-11: an unrecognized TEXT label's element (the CDDL's <c>label = int / tstr</c> other arm)
    /// round-trips byte-exactly through the catch-all arm.
    /// </summary>
    [TestMethod]
    public void TryParseUnsignedHeadersRoundTripsSingleUnrecognizedTextLabelElementByteExactly()
    {
        const string label = "x-example-label";
        const string value = "example value";
        byte[] expected = BuildSingleElementUnsignedHeadersBytes(EncodeUnknownTextElement(label, value));

        bool parsed = CBAdESSerialization.TryParseUnsignedHeaders(expected, BaseMemoryPool.Shared, out CBAdESUnsignedHeaders? result);

        Assert.IsTrue(parsed);
        Assert.IsNotNull(result);
        using(result)
        {
            CBAdESUnsignedHeaders header = result!;
            Assert.HasCount(1, header);
            Assert.IsTrue(header[0] is CBAdESUnsignedHeaderElementUnknown, "An unrecognized text label must round-trip as the catch-all arm, not be dropped.");

            var unknown = (CBAdESUnsignedHeaderElementUnknown)header[0];
            Assert.AreEqual(new CBAdESUnsignedHeaderElementTextLabel(label), unknown.Label);
            Assert.IsTrue(EncodeTextValue(value).AsSpan().SequenceEqual(unknown.Value.Span));

            using PooledMemory reencoded = CBAdESSerialization.EncodeUnsignedHeaders(header, BaseMemoryPool.Shared);
            Assert.IsTrue(expected.AsSpan().SequenceEqual(reencoded.AsReadOnlySpan()), "Re-encoding must reproduce the original bytes exactly.");
        }
    }


    /// <summary>Trailing bytes after a complete <c>uHeaders</c> value must fail closed and must not leak a partial result.</summary>
    [TestMethod]
    public void TryParseUnsignedHeadersFailsClosedOnTrailingData()
    {
        byte[] valid = BuildSingleElementUnsignedHeadersBytes(EncodeTstContainerElement(1, [0x01]));
        byte[] withTrailer = [.. valid, 0x00];

        bool parsed = CBAdESSerialization.TryParseUnsignedHeaders(withTrailer, BaseMemoryPool.Shared, out CBAdESUnsignedHeaders? result);

        Assert.IsFalse(parsed, "Trailing bytes after a complete uHeaders value must fail closed.");
        Assert.IsNull(result, "A failed parse must not leak a partially-consumed result.");
        result?.Dispose();
    }


    /// <summary>Truncated <c>uHeaders</c> bytes (a well-formed single-element array with its final byte removed) must fail closed.</summary>
    [TestMethod]
    public void TryParseUnsignedHeadersFailsClosedOnTruncatedInput()
    {
        byte[] valid = BuildSingleElementUnsignedHeadersBytes(EncodeTstContainerElement(1, [0x01]));
        byte[] truncated = valid[..^1];

        bool parsed = CBAdESSerialization.TryParseUnsignedHeaders(truncated, BaseMemoryPool.Shared, out CBAdESUnsignedHeaders? result);

        Assert.IsFalse(parsed, "Truncated uHeaders input must fail closed.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>An indefinite-length <c>uHeaders</c> array must fail closed under the canonical-mode reader.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">ETSI TS 119 152-1 V1.1.1</see>
    /// CB-4.7-02.
    /// </remarks>
    [TestMethod]
    public void TryParseUnsignedHeadersFailsClosedOnIndefiniteLengthArray()
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.Lax);
        writer.WriteStartArray(null);
        writer.WriteByteString(EncodeTstContainerElement(1, [0x01]));
        writer.WriteEndArray();

        bool parsed = CBAdESSerialization.TryParseUnsignedHeaders(writerBuffer.WrittenSpan.ToArray(), BaseMemoryPool.Shared, out CBAdESUnsignedHeaders? result);

        Assert.IsFalse(parsed, "An indefinite-length uHeaders array must be rejected under canonical-mode parsing.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>
    /// Adversarially deep CBOR array nesting at the top level must fail closed — not throw an uncaught
    /// exception or crash the process.
    /// </summary>
    [TestMethod]
    public void TryParseUnsignedHeadersFailsClosedOnDepthBombNesting()
    {
        byte[] deeplyNested = BuildDeeplyNestedArrayBytes(10_000);

        bool parsed = CBAdESSerialization.TryParseUnsignedHeaders(deeplyNested, BaseMemoryPool.Shared, out CBAdESUnsignedHeaders? result);

        Assert.IsFalse(parsed, "Adversarially deep top-level nesting must fail closed, not throw or crash.");
        Assert.IsNull(result);
        result?.Dispose();
    }


    /// <summary>
    /// The full-counter-signature arm (label <c>11</c>, RFC 9338 <c>COSE_CounterSignature /
    /// [+COSE_CounterSignature]</c>) round-trips byte-exactly through <see cref="CBAdESSerialization.EncodeUnsignedHeaders"/>/
    /// <see cref="CBAdESSerialization.TryParseUnsignedHeaders"/> against an independently-built oracle — the
    /// codec arm (<see cref="CBAdESUnsignedHeaderElementFullCounterSignature"/>) had ZERO
    /// test coverage of any kind before this test.
    /// </summary>
    [TestMethod]
    public void FullCounterSignatureElementRoundTripsByteExactly()
    {
        //A single well-formed COSE_Countersignature value: [protected(bstr), unprotected(map), signature(bstr)]
        //-- RFC 9338 §3.1's "COSE_Countersignature = COSE_Signature" alias, written directly with a fresh
        //CborWriter, independent of the RFC 9338 substrate's own codec (CoseSerialization.WriteCounterSignatureV2).
        byte[] counterSignatureValue = EncodeSingleCounterSignatureValue([0xAA], [0x01, 0x02, 0x03]);

        byte[] expected = BuildSingleElementUnsignedHeadersBytes(EncodeFullCounterSignatureElement(counterSignatureValue));

        using var model = new CBAdESUnsignedHeaders([new CBAdESUnsignedHeaderElementFullCounterSignature(counterSignatureValue)]);

        using PooledMemory encoded = CBAdESSerialization.EncodeUnsignedHeaders(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");

        bool parsed = CBAdESSerialization.TryParseUnsignedHeaders(expected, BaseMemoryPool.Shared, out CBAdESUnsignedHeaders? result);
        Assert.IsTrue(parsed);
        Assert.IsNotNull(result);
        using(result)
        {
            Assert.AreEqual(1, result!.Count);
            var fullCounterSignature = Assert.IsInstanceOfType<CBAdESUnsignedHeaderElementFullCounterSignature>(result[0]);
            Assert.IsTrue(
                counterSignatureValue.AsSpan().SequenceEqual(fullCounterSignature.Value.Span),
                "The full-counter-signature element's raw value bytes must round-trip byte-exactly (needed downstream for a byte-exact imprint).");

            using PooledMemory reencoded = CBAdESSerialization.EncodeUnsignedHeaders(result, BaseMemoryPool.Shared);
            Assert.IsTrue(expected.AsSpan().SequenceEqual(reencoded.AsReadOnlySpan()), "Re-encoding the parsed value must reproduce the original bytes exactly.");
        }
    }


    /// <summary>
    /// The abbreviated-counter-signature arm (label <c>12</c>, RFC 9338
    /// <c>COSE_CounterSignature0 = bstr</c>) round-trips byte-exactly, mirroring
    /// <see cref="FullCounterSignatureElementRoundTripsByteExactly"/> for the bare-<c>bstr</c> abbreviated form.
    /// </summary>
    [TestMethod]
    public void AbbreviatedCounterSignatureElementRoundTripsByteExactly()
    {
        byte[] abbreviatedSignatureValue = EncodeBareByteString([0x01, 0x02, 0x03, 0x04]);

        byte[] expected = BuildSingleElementUnsignedHeadersBytes(EncodeAbbreviatedCounterSignatureElement(abbreviatedSignatureValue));

        using var model = new CBAdESUnsignedHeaders([new CBAdESUnsignedHeaderElementAbbreviatedCounterSignature(abbreviatedSignatureValue)]);

        using PooledMemory encoded = CBAdESSerialization.EncodeUnsignedHeaders(model, BaseMemoryPool.Shared);
        Assert.IsTrue(expected.AsSpan().SequenceEqual(encoded.AsReadOnlySpan()), "Encode must reproduce the independent oracle's bytes exactly.");

        bool parsed = CBAdESSerialization.TryParseUnsignedHeaders(expected, BaseMemoryPool.Shared, out CBAdESUnsignedHeaders? result);
        Assert.IsTrue(parsed);
        Assert.IsNotNull(result);
        using(result)
        {
            Assert.AreEqual(1, result!.Count);
            var abbreviatedCounterSignature = Assert.IsInstanceOfType<CBAdESUnsignedHeaderElementAbbreviatedCounterSignature>(result[0]);
            Assert.IsTrue(
                abbreviatedSignatureValue.AsSpan().SequenceEqual(abbreviatedCounterSignature.Value.Span),
                "The abbreviated-counter-signature element's raw value bytes must round-trip byte-exactly.");

            using PooledMemory reencoded = CBAdESSerialization.EncodeUnsignedHeaders(result, BaseMemoryPool.Shared);
            Assert.IsTrue(expected.AsSpan().SequenceEqual(reencoded.AsReadOnlySpan()), "Re-encoding the parsed value must reproduce the original bytes exactly.");
        }
    }


    /// <summary>Builds a trivial catch-all element for the pure-model tests, which need distinct elements but no real component content.</summary>
    /// <param name="label">The catch-all element's integer label.</param>
    /// <param name="value">The catch-all element's opaque value bytes.</param>
    /// <returns>The built element.</returns>
    private static CBAdESUnsignedHeaderElementUnknown MakeUnknownElement(int label, byte[] value)
    {
        return new CBAdESUnsignedHeaderElementUnknown(new CBAdESUnsignedHeaderElementIntegerLabel(label), value);
    }


    /// <summary>
    /// Computes a real SHA-256 digest over <paramref name="input"/> through the registered digest delegate,
    /// tagged with <see cref="CryptoTags.Sha256Digest"/> — the fixture the <c>refs</c> element's <c>x5t</c>
    /// digest is built from, rather than a hand-rolled hash.
    /// </summary>
    /// <param name="input">The bytes to digest.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The owned digest.</returns>
    private static async ValueTask<DigestValue> CreateDigestAsync(byte[] input, CancellationToken cancellationToken)
    {
        return await CryptographicKeyEvents.ComputeDigestAsync(
            new ReadOnlyMemory<byte>(input), 32, CryptoTags.Sha256Digest, BaseMemoryPool.Shared, cancellationToken: cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Builds a <see cref="CBAdESUnsignedHeaders"/> instance carrying one typed arm per Table 8 label
    /// (<c>1</c>-<c>7</c>), the <c>x5chain</c> opaque arm (label <c>33</c>), and one unrecognized integer- and
    /// text-labelled catch-all element, in that order, entirely through the library's own model types.
    /// </summary>
    /// <param name="sigTstVal">The <c>sigTst</c> element's RFC 3161-style token <c>val</c> bytes.</param>
    /// <param name="valDataCertBytes">The <c>valData</c> element's single <c>x509Cert</c> DER bytes.</param>
    /// <param name="arcTstVal">The <c>arcTst</c> element's RFC 3161-style token <c>val</c> bytes.</param>
    /// <param name="refsHashAlg">The <c>refs</c> element's <c>x5t</c> digest-algorithm identifier.</param>
    /// <param name="refsDigest">The <c>refs</c> element's <c>x5t</c> digest; ownership transfers into the result.</param>
    /// <param name="sigRTstVal">The <c>sigRTst</c> element's RFC 3161-style token <c>val</c> bytes.</param>
    /// <param name="rfsTstVal">The <c>rfsTst</c> element's RFC 3161-style token <c>val</c> bytes.</param>
    /// <param name="sigPStDocBytes">The <c>sigPSt</c> element's signature-policy document bytes.</param>
    /// <param name="x5chainCertBytes">The <c>x5chain</c> element's single-certificate bytes.</param>
    /// <param name="unknownIntLabel">The unrecognized integer label.</param>
    /// <param name="unknownIntValue">The unrecognized integer label's opaque integer value.</param>
    /// <param name="unknownTextLabel">The unrecognized text label.</param>
    /// <param name="unknownTextValue">The unrecognized text label's opaque text value.</param>
    /// <returns>The built, owned instance.</returns>
#pragma warning disable CA2000 // Dispose objects before losing scope
    //Every intermediate IDisposable constructed below (the thumbprint's digest, the thumbprint itself, the
    //certificate reference, and the references component) has its ownership transferred immediately into the
    //next enclosing constructor call, terminating in the returned CBAdESUnsignedHeaders, which the caller
    //disposes. The analyzer cannot see through this chain of owning-constructor calls.
    private static CBAdESUnsignedHeaders BuildMixedUnsignedHeadersModel(
        byte[] sigTstVal,
        byte[] valDataCertBytes,
        byte[] arcTstVal,
        int refsHashAlg,
        DigestValue refsDigest,
        byte[] sigRTstVal,
        byte[] rfsTstVal,
        byte[] sigPStDocBytes,
        byte[] x5chainCertBytes,
        int unknownIntLabel,
        int unknownIntValue,
        string unknownTextLabel,
        string unknownTextValue)
    {
        List<CBAdESUnsignedHeaderElement> elements =
        [
            new CBAdESUnsignedHeaderElementSignatureTimestamp(new CBAdESSignatureTimestamp(BuildRfc3161Container(sigTstVal))),
            new CBAdESUnsignedHeaderElementValidationData(
                new CBAdESValidationData(certificateValues: [new CBAdESX509Certificate(new AdESPkiObject { Val = valDataCertBytes })])),
            new CBAdESUnsignedHeaderElementArchiveTimestamp(new CBAdESArchiveTimestamp(BuildRfc3161Container(arcTstVal))),
            new CBAdESUnsignedHeaderElementReferences(
                new CBAdESReferences(certificateReferences:
                [
                    new CBAdESCertificateReference(new AdESCertificateThumbprint(new AdESDigestAlgorithmIntegerIdentifier(refsHashAlg), refsDigest))
                ])),
            new CBAdESUnsignedHeaderElementSignatureAndReferencesTimestamp(new CBAdESSignatureAndReferencesTimestamp(BuildRfc3161Container(sigRTstVal))),
            new CBAdESUnsignedHeaderElementReferencesTimestamp(new CBAdESReferencesTimestamp(BuildRfc3161Container(rfsTstVal))),
            new CBAdESUnsignedHeaderElementSignaturePolicyStore(new CBAdESSignaturePolicyStore(new CBAdESSignaturePolicyStoreDocument(sigPStDocBytes))),
            new CBAdESUnsignedHeaderElementCertificateChain(EncodeX5ChainOpaqueValue(x5chainCertBytes)),
            new CBAdESUnsignedHeaderElementUnknown(new CBAdESUnsignedHeaderElementIntegerLabel(unknownIntLabel), EncodeIntValue(unknownIntValue)),
            new CBAdESUnsignedHeaderElementUnknown(new CBAdESUnsignedHeaderElementTextLabel(unknownTextLabel), EncodeTextValue(unknownTextValue))
        ];

        return new CBAdESUnsignedHeaders(elements);
    }
#pragma warning restore CA2000 // Dispose objects before losing scope


    /// <summary>Builds a single-token, RFC 3161-style <c>tstContainer</c> value (<c>type</c>/<c>encoding</c>/<c>specRef</c> all absent).</summary>
    /// <param name="val">The token's <c>val</c> bytes.</param>
    /// <returns>The built container.</returns>
    private static AdESTimestampContainer BuildRfc3161Container(byte[] val)
    {
        return new AdESTimestampContainer([new AdESTimestampToken { Val = val }]);
    }


    /// <summary>
    /// Assembles this suite's independent oracle bytes for the ten-element mixed <c>uHeaders</c> sequence
    /// (clause 5.3.1, Table 8), directly with <see cref="CborWriter"/> and literal Table 8 labels — never
    /// derived from <see cref="CBAdESSerialization"/> or the model's own label constants.
    /// </summary>
    /// <returns>The expected canonical CBOR bytes for the whole <c>uHeaders</c> array.</returns>
    private static byte[] BuildExpectedMixedUnsignedHeadersBytes(
        byte[] sigTstVal,
        byte[] valDataCertBytes,
        byte[] arcTstVal,
        int refsHashAlg,
        byte[] refsDigestBytes,
        byte[] sigRTstVal,
        byte[] rfsTstVal,
        byte[] sigPStDocBytes,
        byte[] x5chainCertBytes,
        int unknownIntLabel,
        int unknownIntValue,
        string unknownTextLabel,
        string unknownTextValue)
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartArray(10);

        writer.WriteByteString(EncodeTstContainerElement(1, sigTstVal)); //sigTst_l = 1 (Table 8).
        writer.WriteByteString(EncodeValDataElement(valDataCertBytes)); //valData_l = 2 (Table 8).
        writer.WriteByteString(EncodeTstContainerElement(3, arcTstVal)); //arcTst_l = 3 (Table 8).
        writer.WriteByteString(EncodeRefsElement(refsHashAlg, refsDigestBytes)); //refs_l = 4 (Table 8).
        writer.WriteByteString(EncodeTstContainerElement(5, sigRTstVal)); //sigRTst_l = 5 (Table 8).
        writer.WriteByteString(EncodeTstContainerElement(6, rfsTstVal)); //rfsTst_l = 6 (Table 8).
        writer.WriteByteString(EncodeSigPStElement(sigPStDocBytes)); //sigPSt_l = 7 (Table 8).
        writer.WriteByteString(EncodeX5ChainElement(x5chainCertBytes)); //x5chain arm, label 33 (clause 5.3.1 CDDL).
        writer.WriteByteString(EncodeUnknownIntElement(unknownIntLabel, unknownIntValue)); //*label => value catch-all, int arm.
        writer.WriteByteString(EncodeUnknownTextElement(unknownTextLabel, unknownTextValue)); //*label => value catch-all, tstr arm.

        writer.WriteEndArray();
        return writerBuffer.WrittenSpan.ToArray();
    }


    /// <summary>Wraps a single, already-encoded <c>UHeaderInstance</c> map's content bytes into a one-element <c>uHeaders</c> array.</summary>
    /// <param name="elementContentBytes">One element's encoded <c>UHeaderInstance</c> map bytes.</param>
    /// <returns>The encoded one-element <c>uHeaders</c> array.</returns>
    private static byte[] BuildSingleElementUnsignedHeadersBytes(byte[] elementContentBytes)
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartArray(1);
        writer.WriteByteString(elementContentBytes);
        writer.WriteEndArray();
        return writerBuffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Encodes a <c>sigTst</c>/<c>arcTst</c>/<c>sigRTst</c>/<c>rfsTst</c>-shaped <c>UHeaderInstance</c>
    /// one-entry map: <c>{ label =&gt; tstContainer }</c> where <c>tstContainer</c> holds exactly one
    /// RFC 3161-style token (clause 5.3.1 Table 8; clause 5.4.3.3 Table 13). All four labels reuse this
    /// helper since <c>sigTst = arcTst = sigRTst = rfsTst = tstContainer</c> are straight CDDL aliases.
    /// </summary>
    /// <param name="label">The Table 8 label (<c>1</c>, <c>3</c>, <c>5</c>, or <c>6</c>).</param>
    /// <param name="tokenVal">The single token's <c>val</c> bytes.</param>
    /// <returns>The encoded <c>UHeaderInstance</c> map bytes.</returns>
    private static byte[] EncodeTstContainerElement(int label, byte[] tokenVal)
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(label);
        writer.WriteStartMap(1);
        writer.WriteInt32(1); //tstTokens (Table 13, clause 5.4.3.3).
        writer.WriteStartArray(1);
        writer.WriteStartMap(1);
        writer.WriteInt32(1); //val (Table 13, TstToken) -- RFC 3161-style: type/encoding/specRef all absent.
        writer.WriteByteString(tokenVal);
        writer.WriteEndMap();
        writer.WriteEndArray();
        writer.WriteEndMap();
        writer.WriteEndMap();
        return writerBuffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Encodes the <c>valData</c>-shaped <c>UHeaderInstance</c> one-entry map (label <c>2</c>, Table 8): a
    /// single <c>xVals</c> entry carrying one DER <c>x509Cert</c> (clause 5.3.4 Table 10, clause 5.4.2 Table 12).
    /// </summary>
    /// <param name="certBytes">The single certificate's DER bytes.</param>
    /// <returns>The encoded <c>UHeaderInstance</c> map bytes.</returns>
    private static byte[] EncodeValDataElement(byte[] certBytes)
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(2); //valData_l (Table 8).
        writer.WriteStartMap(1);
        writer.WriteInt32(1); //xVals (Table 10).
        writer.WriteStartArray(1);
        writer.WriteStartMap(1);
        writer.WriteInt32(1); //x509Cert (Table 10, X509OrOther).
        writer.WriteStartMap(1);
        writer.WriteInt32(1); //val (Table 12, pkiOb) -- DER is the default encoding, so 'encoding' is absent.
        writer.WriteByteString(certBytes);
        writer.WriteEndMap();
        writer.WriteEndMap();
        writer.WriteEndArray();
        writer.WriteEndMap();
        writer.WriteEndMap();
        return writerBuffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Encodes the <c>refs</c>-shaped <c>UHeaderInstance</c> one-entry map (label <c>4</c>, Table 8): a single
    /// <c>xRefs</c> entry carrying one <c>CertId</c> with just an <c>x5t</c> digest pair (Annex A.1.1, Table A.1).
    /// </summary>
    /// <param name="hashAlg">The <c>x5t</c> digest-algorithm identifier.</param>
    /// <param name="digestBytes">The <c>x5t</c> digest bytes.</param>
    /// <returns>The encoded <c>UHeaderInstance</c> map bytes.</returns>
    private static byte[] EncodeRefsElement(int hashAlg, byte[] digestBytes)
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(4); //refs_l (Table 8).
        writer.WriteStartMap(1);
        writer.WriteInt32(1); //xRefs (Table A.1, Annex A.1.1).
        writer.WriteStartArray(1);
        writer.WriteStartMap(1);
        writer.WriteInt32(1); //x5t (Table A.1, CertId) -- COSE_CertHash: [hashAlg, hashValue].
        writer.WriteStartArray(2);
        writer.WriteInt32(hashAlg);
        writer.WriteByteString(digestBytes);
        writer.WriteEndArray();
        writer.WriteEndMap();
        writer.WriteEndArray();
        writer.WriteEndMap();
        writer.WriteEndMap();
        return writerBuffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Encodes the <c>sigPSt</c>-shaped <c>UHeaderInstance</c> one-entry map (label <c>7</c>, Table 8): the
    /// <c>sigPolDoc</c> arm of <c>DocOrLocalURI</c>, no <c>spDSpec</c> (clause 5.3.2, Table 9).
    /// </summary>
    /// <param name="docBytes">The signature policy document's bytes.</param>
    /// <returns>The encoded <c>UHeaderInstance</c> map bytes.</returns>
    private static byte[] EncodeSigPStElement(byte[] docBytes)
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(7); //sigPSt_l (Table 8).
        writer.WriteStartMap(1);
        writer.WriteInt32(1); //docOrLocalUri (Table 9).
        writer.WriteStartMap(1);
        writer.WriteInt32(1); //sigPolDoc (Table 9, DocOrLocalURI).
        writer.WriteByteString(docBytes);
        writer.WriteEndMap();
        writer.WriteEndMap();
        writer.WriteEndMap();
        return writerBuffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Encodes the <c>x5chain</c>-shaped <c>UHeaderInstance</c> one-entry map (label <c>33</c>, clause 5.3.1
    /// CDDL): the single-certificate <c>bstr</c> arm.
    /// </summary>
    /// <param name="certBytes">The single certificate's bytes.</param>
    /// <returns>The encoded <c>UHeaderInstance</c> map bytes.</returns>
    private static byte[] EncodeX5ChainElement(byte[] certBytes)
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(33); //x5chain arm (clause 5.3.1 CDDL; IETF RFC 9360 section 2).
        writer.WriteByteString(certBytes);
        writer.WriteEndMap();
        return writerBuffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Encodes only the <c>x5chain</c> arm's VALUE bytes (the single-certificate <c>bstr</c>, with no
    /// enclosing one-entry map) — exactly what <see cref="CBAdESUnsignedHeaderElementCertificateChain.Value"/>
    /// carries, since the codec adds the <c>{33 =&gt; ...}</c> wrapper itself from the element's own label.
    /// </summary>
    /// <param name="certBytes">The single certificate's bytes.</param>
    /// <returns>The encoded value-only bytes.</returns>
    private static byte[] EncodeX5ChainOpaqueValue(byte[] certBytes)
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteByteString(certBytes);
        return writerBuffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Encodes the full-counter-signature-shaped <c>UHeaderInstance</c> one-entry map (label <c>11</c>, clause
    /// 5.3.1 CDDL; <see href="https://www.rfc-editor.org/rfc/rfc9338">IETF RFC 9338</see>).
    /// </summary>
    /// <param name="counterSignatureValueBytes">The already-encoded <c>COSE_CounterSignature</c>/array-of-them value bytes.</param>
    /// <returns>The encoded <c>UHeaderInstance</c> map bytes.</returns>
    private static byte[] EncodeFullCounterSignatureElement(byte[] counterSignatureValueBytes)
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(11); //Full-counter-signature arm (clause 5.3.1 CDDL; IETF RFC 9338).
        writer.WriteEncodedValue(counterSignatureValueBytes);
        writer.WriteEndMap();
        return writerBuffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Encodes the abbreviated-counter-signature-shaped <c>UHeaderInstance</c> one-entry map (label <c>12</c>,
    /// clause 5.3.1 CDDL; <see href="https://www.rfc-editor.org/rfc/rfc9338">IETF RFC 9338</see>).
    /// </summary>
    /// <param name="abbreviatedValueBytes">The already-encoded <c>COSE_CounterSignature0</c> (bare <c>bstr</c>) value bytes.</param>
    /// <returns>The encoded <c>UHeaderInstance</c> map bytes.</returns>
    private static byte[] EncodeAbbreviatedCounterSignatureElement(byte[] abbreviatedValueBytes)
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(12); //Abbreviated-counter-signature arm (clause 5.3.1 CDDL; IETF RFC 9338).
        writer.WriteEncodedValue(abbreviatedValueBytes);
        writer.WriteEndMap();
        return writerBuffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Encodes a single well-formed <c>COSE_Countersignature</c> value — RFC 9338 §3.1's
    /// <c>COSE_Countersignature = COSE_Signature</c> alias: <c>[protected(bstr), unprotected(map, here empty),
    /// signature(bstr)]</c> — independent of the RFC 9338 substrate's own codec.
    /// </summary>
    /// <param name="protectedHeaderBytes">The signer-layer protected header bytes.</param>
    /// <param name="signatureBytes">The signature value bytes.</param>
    /// <returns>The encoded value-only bytes (no enclosing <c>{11 =&gt; ...}</c> map).</returns>
    private static byte[] EncodeSingleCounterSignatureValue(byte[] protectedHeaderBytes, byte[] signatureBytes)
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartArray(3);
        writer.WriteByteString(protectedHeaderBytes);
        writer.WriteStartMap(0);
        writer.WriteEndMap();
        writer.WriteByteString(signatureBytes);
        writer.WriteEndArray();
        return writerBuffer.WrittenSpan.ToArray();
    }


    /// <summary>Encodes a bare canonical CBOR byte string, with no enclosing map -- the abbreviated-counter-signature arm's opaque VALUE bytes (RFC 9338 §3.2's <c>COSE_CounterSignature0 = bstr</c>).</summary>
    /// <param name="bytes">The byte-string content.</param>
    /// <returns>The encoded value-only bytes.</returns>
    private static byte[] EncodeBareByteString(byte[] bytes)
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteByteString(bytes);
        return writerBuffer.WrittenSpan.ToArray();
    }


    /// <summary>Encodes a bare canonical CBOR integer value, with no enclosing map -- an unrecognized-integer-label element's opaque VALUE bytes.</summary>
    /// <param name="value">The integer value.</param>
    /// <returns>The encoded value-only bytes.</returns>
    private static byte[] EncodeIntValue(int value)
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteInt32(value);
        return writerBuffer.WrittenSpan.ToArray();
    }


    /// <summary>Encodes a bare canonical CBOR text string value, with no enclosing map -- an unrecognized-text-label element's opaque VALUE bytes.</summary>
    /// <param name="value">The text value.</param>
    /// <returns>The encoded value-only bytes.</returns>
    private static byte[] EncodeTextValue(string value)
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteTextString(value);
        return writerBuffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Encodes the unrecognized-integer-label-shaped <c>UHeaderInstance</c> one-entry map: <c>{ label =&gt;
    /// value }</c>, the CDDL's <c>*label =&gt; value</c> catch-all's <c>int</c> arm (clause 5.3.1).
    /// </summary>
    /// <param name="label">The unrecognized integer label.</param>
    /// <param name="value">The opaque integer value.</param>
    /// <returns>The encoded <c>UHeaderInstance</c> map bytes.</returns>
    private static byte[] EncodeUnknownIntElement(int label, int value)
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(label);
        writer.WriteInt32(value);
        writer.WriteEndMap();
        return writerBuffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Encodes the unrecognized-text-label-shaped <c>UHeaderInstance</c> one-entry map: <c>{ label =&gt;
    /// value }</c>, the CDDL's <c>*label =&gt; value</c> catch-all's <c>tstr</c> arm (clause 5.3.1).
    /// </summary>
    /// <param name="label">The unrecognized text label.</param>
    /// <param name="value">The opaque text value.</param>
    /// <returns>The encoded <c>UHeaderInstance</c> map bytes.</returns>
    private static byte[] EncodeUnknownTextElement(string label, string value)
    {
        var writerBuffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(writerBuffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(1);
        writer.WriteTextString(label);
        writer.WriteTextString(value);
        writer.WriteEndMap();
        return writerBuffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Builds well-formed but adversarially deep CBOR bytes — <paramref name="depth"/> singly-nested arrays,
    /// each containing exactly the next, with an integer at the innermost position — used by the depth-bomb
    /// negative test in this suite. Definite-length throughout, so it remains valid CBOR under canonical-mode
    /// conformance; only its nesting depth is adversarial.
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
