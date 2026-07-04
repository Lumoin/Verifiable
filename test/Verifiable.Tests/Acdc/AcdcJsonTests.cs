using System.Buffers;
using Verifiable.Acdc;
using Verifiable.Cryptography;
using Verifiable.Json;

namespace Verifiable.Tests.Acdc;

/// <summary>
/// Tests for the ACDC JSON serialization seam, <see cref="AcdcJson"/>: the decode produces an order-preserving
/// field map at every level, and re-encoding a decoded ACDC reproduces the specification's canonical bytes exactly.
/// The byte-identical round-trip is what makes the encoder usable for the most-compact-form SAID computation: a
/// re-serialized section matches the bytes its SAID was taken over.
/// </summary>
[TestClass]
internal sealed class AcdcJsonTests
{
    /// <summary>
    /// The most-compact Accreditation ACDC decodes and re-encodes to the same canonical bytes.
    /// </summary>
    [TestMethod]
    public void CompactAcdcRoundTripsByteIdentical()
    {
        AssertRoundTripsByteIdentical(AcdcExampleVectors.CompactAcdc);
    }


    /// <summary>
    /// The fully expanded Accreditation ACDC, whose attribute and rule sections are nested blocks, decodes and
    /// re-encodes to the same canonical bytes — the nested blocks keep their field order through the round-trip.
    /// </summary>
    [TestMethod]
    public void ExpandedAcdcRoundTripsByteIdentical()
    {
        AssertRoundTripsByteIdentical(AcdcExampleVectors.ExpandedAcdc);
    }


    /// <summary>
    /// A nested section block decodes as an order-preserving field map, not a general dictionary, so the order its
    /// SAID is taken over is preserved.
    /// </summary>
    [TestMethod]
    public void NestedSectionBlockDecodesAsOrderedFieldMap()
    {
        using AcdcTestSupport.EncodedSerialization input = AcdcTestSupport.Encode(AcdcExampleVectors.ExpandedAcdc);

        MessageFieldMap map = AcdcJson.DecodeFieldMap(input.Memory);

        Assert.IsTrue(map.TryGetValue(AcdcMessageFields.Attribute, out object? attribute));
        Assert.IsInstanceOfType<MessageFieldMap>(attribute, "A nested section block must decode as an order-preserving field map.");
    }


    private static void AssertRoundTripsByteIdentical(string serialization)
    {
        using AcdcTestSupport.EncodedSerialization input = AcdcTestSupport.Encode(serialization);

        MessageFieldMap map = AcdcJson.DecodeFieldMap(input.Memory);

        var output = new ArrayBufferWriter<byte>();
        AcdcJson.Encode(map, output);

        Assert.IsTrue(output.WrittenSpan.SequenceEqual(input.Bytes), "Re-encoding the decoded ACDC must reproduce the canonical serialization byte for byte.");
    }
}
