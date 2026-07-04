using System.Buffers;
using Lumoin.Base;
using Verifiable.Acdc;
using Verifiable.Cbor;
using Verifiable.Cryptography;
using Verifiable.Json;

namespace Verifiable.Tests.Acdc;

/// <summary>
/// Tests for the ACDC CBOR serialization arm, <see cref="AcdcCbor"/>, and through it the serialization-agnostic
/// design. The specification's worked examples are JSON, so CBOR is checked not against a published CBOR vector but
/// against the JSON arm: a round-trip JSON → CBOR → JSON must reproduce the original bytes (the CBOR codec preserves
/// the same neutral field map the JSON arm produces), the reader folds a CBOR-decoded map to the same typed message
/// as the JSON-decoded one, and compaction derives a self-consistent SAID over the CBOR seam.
/// </summary>
[TestClass]
internal sealed class AcdcCborTests
{
    /// <summary>
    /// The most-compact Accreditation ACDC survives a JSON → CBOR → JSON round-trip unchanged.
    /// </summary>
    [TestMethod]
    public void CompactAcdcRoundTripsThroughCbor()
    {
        AssertJsonCborJsonRoundTrip(AcdcExampleVectors.CompactAcdc);
    }


    /// <summary>
    /// The fully expanded Accreditation ACDC, with nested section blocks, survives a JSON → CBOR → JSON round-trip
    /// unchanged — the nested blocks keep their field order through the CBOR encode and decode.
    /// </summary>
    [TestMethod]
    public void ExpandedAcdcRoundTripsThroughCbor()
    {
        AssertJsonCborJsonRoundTrip(AcdcExampleVectors.ExpandedAcdc);
    }


    /// <summary>
    /// The reader folds a CBOR-decoded field map to the same typed message as the JSON-decoded one: reading is
    /// independent of the serialization.
    /// </summary>
    [TestMethod]
    public void CborDecodedAcdcReadsToSameTypedMessage()
    {
        using AcdcTestSupport.EncodedSerialization input = AcdcTestSupport.Encode(AcdcExampleVectors.CompactAcdc);
        MessageFieldMap jsonMap = AcdcJson.DecodeFieldMap(input.Memory);

        var cbor = new ArrayBufferWriter<byte>();
        AcdcCbor.Encode(jsonMap, cbor);
        MessageFieldMap cborMap = AcdcCbor.DecodeFieldMap(cbor.WrittenMemory);

        Assert.AreEqual(AcdcReader.Read(jsonMap), AcdcReader.Read(cborMap));
    }


    /// <summary>
    /// Compaction derives a SAID over the CBOR seam that verifies against the compacted CBOR bytes; the CBOR-form
    /// SAID differs from the JSON-form SAID, since a SAID is over the serialization.
    /// </summary>
    [TestMethod]
    public async Task CompactionDerivesAndVerifiesOverTheCborSeam()
    {
        using AcdcTestSupport.EncodedSerialization input = AcdcTestSupport.Encode(AcdcExampleVectors.ExpandedAcdc);
        MessageFieldMap expanded = AcdcJson.DecodeFieldMap(input.Memory);

        //The worked example is published as JSON; retarget the version string's serialization kind to CBOR so the
        //compaction produces a CBOR ACDC (the size field is restamped by the compaction).
        expanded[AcdcMessageFields.Version] = "ACDCCAACAACBORAAAA.";

        MessageFieldMap compact = await AcdcCompaction.ToCompactFormAsync(expanded, AcdcCbor.Encode, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, CancellationToken.None);

        Assert.IsTrue(compact.TryGetString(AcdcMessageFields.Said, out string? said));
        Assert.AreNotEqual(AcdcExampleVectors.AccreditationSaid, said, "A SAID is over the serialization, so the CBOR-form SAID differs from the JSON-form SAID.");

        var serialized = new ArrayBufferWriter<byte>();
        AcdcCbor.Encode(compact, serialized);

        Assert.IsTrue(await AcdcSaid.VerifyAsync(serialized.WrittenMemory, said, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, CancellationToken.None));
    }


    private static void AssertJsonCborJsonRoundTrip(string json)
    {
        using AcdcTestSupport.EncodedSerialization input = AcdcTestSupport.Encode(json);

        MessageFieldMap map = AcdcJson.DecodeFieldMap(input.Memory);

        var cbor = new ArrayBufferWriter<byte>();
        AcdcCbor.Encode(map, cbor);

        MessageFieldMap roundTripped = AcdcCbor.DecodeFieldMap(cbor.WrittenMemory);

        var json2 = new ArrayBufferWriter<byte>();
        AcdcJson.Encode(roundTripped, json2);

        Assert.IsTrue(json2.WrittenSpan.SequenceEqual(input.Bytes), "JSON to CBOR to JSON must reproduce the original JSON bytes.");
    }
}
