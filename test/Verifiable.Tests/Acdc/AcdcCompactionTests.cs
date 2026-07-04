using System.Buffers;
using Lumoin.Base;
using Verifiable.Acdc;
using Verifiable.Cryptography;
using Verifiable.Json;

namespace Verifiable.Tests.Acdc;

/// <summary>
/// Conformance tests for <see cref="AcdcCompaction"/> against the ACDC specification's worked Accreditation ACDC
/// (<see cref="AcdcExampleVectors"/>). Starting from the fully expanded ACDC, compaction must DERIVE — not merely
/// verify — the published most-compact form: each section block reduced to its published SAID, the version string
/// restamped to the compact byte count, and the top-level SAID computed over the result, with the JSON encode arm
/// wired as the serialization seam and an independent BLAKE3 digest.
/// </summary>
[TestClass]
internal sealed class AcdcCompactionTests
{
    /// <summary>
    /// Compacting the expanded Accreditation ACDC derives its published compact field values and re-serializes to
    /// the specification's exact compact bytes.
    /// </summary>
    [TestMethod]
    public async Task CompactsExpandedAccreditationToPublishedForm()
    {
        using AcdcTestSupport.EncodedSerialization expanded = AcdcTestSupport.Encode(AcdcExampleVectors.ExpandedAcdc);

        MessageFieldMap compact = await AcdcCompaction.ToCompactFormAsync(
            AcdcJson.DecodeFieldMap(expanded.Memory),
            AcdcJson.Encode,
            AcdcTestSupport.AgileDigest,
            BaseMemoryPool.Shared,
            CancellationToken.None);

        Assert.IsTrue(compact.TryGetString(AcdcMessageFields.Version, out string? version));
        Assert.AreEqual(AcdcExampleVectors.CompactVersionString, version);
        Assert.IsTrue(compact.TryGetString(AcdcMessageFields.Said, out string? said));
        Assert.AreEqual(AcdcExampleVectors.AccreditationSaid, said);
        Assert.IsTrue(compact.TryGetString(AcdcMessageFields.Attribute, out string? attribute));
        Assert.AreEqual(AcdcExampleVectors.AttributeSectionSaid, attribute);
        Assert.IsTrue(compact.TryGetString(AcdcMessageFields.Rule, out string? rule));
        Assert.AreEqual(AcdcExampleVectors.RuleSectionSaid, rule);

        var serialized = new ArrayBufferWriter<byte>();
        AcdcJson.Encode(compact, serialized);
        using AcdcTestSupport.EncodedSerialization publishedCompact = AcdcTestSupport.Encode(AcdcExampleVectors.CompactAcdc);

        Assert.IsTrue(serialized.WrittenSpan.SequenceEqual(publishedCompact.Bytes), "The compacted ACDC must re-serialize to the specification's published compact bytes.");
    }


    /// <summary>
    /// Deriving the SAID of the specification's nested partially-disclosable rule section from its fully expanded
    /// form reproduces the published rule section SAID. This exercises the depth-first compaction through a
    /// rule-group that nests a rule-group (with two rules) and a rule, each compacted to its SAID before the
    /// enclosing block's SAID is taken.
    /// </summary>
    [TestMethod]
    public async Task DerivesNestedRuleSectionSaid()
    {
        using AcdcTestSupport.EncodedSerialization expanded = AcdcTestSupport.Encode(AcdcExampleVectors.NestedRuleSectionExpanded);

        string said = await AcdcCompaction.DeriveSectionSaidAsync(
            AcdcJson.DecodeFieldMap(expanded.Memory),
            AcdcJson.Encode,
            AcdcTestSupport.AgileDigest,
            BaseMemoryPool.Shared,
            CancellationToken.None);

        Assert.AreEqual(AcdcExampleVectors.NestedRuleSectionSaid, said);
    }


    /// <summary>
    /// Deriving the SAID of the specification's Transcript edge section from its fully expanded form reproduces the
    /// published edge section SAID. This exercises the depth-first compaction through an edge-group that nests an
    /// edge and an edge-group (with two edges), each compacted to its SAID before the enclosing block's SAID is
    /// taken.
    /// </summary>
    [TestMethod]
    public async Task DerivesEdgeSectionSaid()
    {
        using AcdcTestSupport.EncodedSerialization expanded = AcdcTestSupport.Encode(AcdcExampleVectors.EdgeSectionExpanded);

        string said = await AcdcCompaction.DeriveSectionSaidAsync(
            AcdcJson.DecodeFieldMap(expanded.Memory),
            AcdcJson.Encode,
            AcdcTestSupport.AgileDigest,
            BaseMemoryPool.Shared,
            CancellationToken.None);

        Assert.AreEqual(AcdcExampleVectors.EdgeSectionSaid, said);
    }


    /// <summary>
    /// Compacting the specification's fully expanded Transcript ACDC — a three-section ACDC whose attribute section
    /// nests a SAIDed grades block and whose edge section nests a multi-level edge sub-graph — derives the published
    /// most-compact form end to end: each section reduced to its published SAID (the attribute and edge sections via
    /// depth-first compaction), the version string restamped to the compact byte count, the top-level SAID computed
    /// over the result, and the whole re-serialized to the specification's exact compact bytes. This also exercises
    /// canonical number serialization, since the attribute's grade values survive the round-trip through compaction.
    /// </summary>
    [TestMethod]
    public async Task CompactsExpandedTranscriptToPublishedForm()
    {
        using AcdcTestSupport.EncodedSerialization expanded = AcdcTestSupport.Encode(AcdcExampleVectors.TranscriptExpanded);

        MessageFieldMap compact = await AcdcCompaction.ToCompactFormAsync(
            AcdcJson.DecodeFieldMap(expanded.Memory),
            AcdcJson.Encode,
            AcdcTestSupport.AgileDigest,
            BaseMemoryPool.Shared,
            CancellationToken.None);

        Assert.IsTrue(compact.TryGetString(AcdcMessageFields.Attribute, out string? attribute));
        Assert.AreEqual(AcdcExampleVectors.TranscriptAttributeSaid, attribute);
        Assert.IsTrue(compact.TryGetString(AcdcMessageFields.Edge, out string? edge));
        Assert.AreEqual(AcdcExampleVectors.EdgeSectionSaid, edge);
        Assert.IsTrue(compact.TryGetString(AcdcMessageFields.Rule, out string? rule));
        Assert.AreEqual(AcdcExampleVectors.RuleSectionSaid, rule);
        Assert.IsTrue(compact.TryGetString(AcdcMessageFields.Version, out string? version));
        Assert.AreEqual(AcdcExampleVectors.TranscriptCompactVersionString, version);
        Assert.IsTrue(compact.TryGetString(AcdcMessageFields.Said, out string? said));
        Assert.AreEqual(AcdcExampleVectors.TranscriptSaid, said);

        var serialized = new ArrayBufferWriter<byte>();
        AcdcJson.Encode(compact, serialized);
        using AcdcTestSupport.EncodedSerialization publishedCompact = AcdcTestSupport.Encode(AcdcExampleVectors.TranscriptCompact);

        Assert.IsTrue(serialized.WrittenSpan.SequenceEqual(publishedCompact.Bytes), "The compacted Transcript ACDC must re-serialize to the specification's published compact bytes.");
    }
}
