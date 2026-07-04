using System.Text;
using Lumoin.Base;
using Verifiable.Acdc;
using Verifiable.Cesr;
using Verifiable.Cryptography;
using Verifiable.Json;

namespace Verifiable.Tests.Acdc;

/// <summary>
/// Conformance tests for the ACDC aggregate section (<see cref="AcdcAggregate"/>, <see cref="AcdcAggregateReader"/>)
/// against the specification's worked JSON aggregate example (<see cref="AcdcExampleVectors"/>): three blinded
/// attribute blocks (Issuee, Score, Name) whose SAIDs aggregate into the published AGID
/// <c>EN5d44fT…</c>. The AGID is derived and verified over the blocks' SAIDs, a selective disclosure (Issuee and
/// Score revealed, Name blinded) is verified, and the reader folds the section's compact, list, and disclosed
/// forms, all with an independent BLAKE3 digest.
/// </summary>
[TestClass]
internal sealed class AcdcAggregateTests
{
    /// <summary>The three block SAIDs in order, the list the AGID is taken over.</summary>
    private static readonly string[] BlockSaids =
        [AcdcExampleVectors.AggregateIssueeBlockSaid, AcdcExampleVectors.AggregateScoreBlockSaid, AcdcExampleVectors.AggregateNameBlockSaid];


    /// <summary>
    /// The AGID derives from the ordered block SAIDs to the published value: the blinded list with the AGID slot
    /// dummied is digested with BLAKE3 and CESR-encoded.
    /// </summary>
    [TestMethod]
    public async Task DerivesAgidFromBlockSaids()
    {
        string agid = await AcdcAggregate.DeriveAgidAsync(BlockSaids, CesrDigestCodes.Blake3Bits256, AcdcJson.EncodeAggregateList, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, CancellationToken.None);

        Assert.AreEqual(AcdcExampleVectors.AggregateAgid, agid);
    }


    /// <summary>
    /// The published AGID verifies over the ordered block SAIDs, and a different AGID does not.
    /// </summary>
    [TestMethod]
    public async Task VerifiesAgid()
    {
        Assert.IsTrue(await AcdcAggregate.VerifyAgidAsync(AcdcExampleVectors.AggregateAgid, BlockSaids, AcdcJson.EncodeAggregateList, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, CancellationToken.None));

        string wrong = AcdcExampleVectors.AggregateAgid[..^1] + (AcdcExampleVectors.AggregateAgid[^1] == 'A' ? 'B' : 'A');
        Assert.IsFalse(await AcdcAggregate.VerifyAgidAsync(wrong, BlockSaids, AcdcJson.EncodeAggregateList, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, CancellationToken.None));
    }


    /// <summary>
    /// Each aggregate block's SAID recomputes over its detail block to its published value: the blocks are
    /// authentic, which the selective-disclosure verification relies on.
    /// </summary>
    [TestMethod]
    public async Task VerifiesAggregateBlockSaids()
    {
        await AssertBlockSaid(AcdcExampleVectors.AggregateIssueeBlock, AcdcExampleVectors.AggregateIssueeBlockSaid);
        await AssertBlockSaid(AcdcExampleVectors.AggregateScoreBlock, AcdcExampleVectors.AggregateScoreBlockSaid);
        await AssertBlockSaid(AcdcExampleVectors.AggregateNameBlock, AcdcExampleVectors.AggregateNameBlockSaid);

        static async Task AssertBlockSaid(string block, string expectedSaid)
        {
            using AcdcTestSupport.EncodedSerialization bytes = AcdcTestSupport.Encode(block);
            Assert.AreEqual(expectedSaid, await AcdcSaid.RecomputeAsync(bytes.Memory, expectedSaid, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, CancellationToken.None));
        }
    }


    /// <summary>
    /// The fully disclosed aggregate section folds into the AGID and three revealed detail blocks, in order.
    /// </summary>
    [TestMethod]
    public void ReadsDisclosedAggregate()
    {
        AcdcAggregateSection section = AcdcAggregateReader.Read(DecodeAggregate(AcdcExampleVectors.AggregateDisclosed));

        Assert.AreEqual(AcdcExampleVectors.AggregateAgid, section.Agid);
        Assert.HasCount(3, section.Blocks);

        var issuee = section.Blocks[0] as ExpandedAggregateBlock;
        Assert.IsNotNull(issuee, "The Issuee block is revealed.");
        Assert.IsTrue(issuee.Detail.TryGetString(AcdcMessageFields.Said, out string? issueeSaid));
        Assert.AreEqual(AcdcExampleVectors.AggregateIssueeBlockSaid, issueeSaid);
        Assert.IsTrue(issuee.Detail.TryGetString(AcdcMessageFields.Issuer, out string? issueeAid));
        Assert.AreEqual(AcdcExampleVectors.AggregateIssueeAid, issueeAid);

        Assert.IsInstanceOfType<ExpandedAggregateBlock>(section.Blocks[1]);
        Assert.IsInstanceOfType<ExpandedAggregateBlock>(section.Blocks[2]);
    }


    /// <summary>
    /// The compact aggregate section — the AGID alone — folds into the AGID with no disclosed blocks.
    /// </summary>
    [TestMethod]
    public void ReadsCompactAgid()
    {
        AcdcAggregateSection section = AcdcAggregateReader.Read(AcdcExampleVectors.AggregateAgid);

        Assert.AreEqual(AcdcExampleVectors.AggregateAgid, section.Agid);
        Assert.IsEmpty(section.Blocks, "The compact AGID discloses no blocks.");
    }


    /// <summary>
    /// The list-form aggregate section folds into the AGID and three blinded SAID blocks.
    /// </summary>
    [TestMethod]
    public void ReadsListForm()
    {
        AcdcAggregateSection section = AcdcAggregateReader.Read(DecodeAggregate(AcdcExampleVectors.AggregateListForm));

        Assert.AreEqual(AcdcExampleVectors.AggregateAgid, section.Agid);
        Assert.HasCount(3, section.Blocks);

        var name = section.Blocks[2] as CompactAggregateBlock;
        Assert.IsNotNull(name, "A list-form block is a blinded SAID.");
        Assert.AreEqual(AcdcExampleVectors.AggregateNameBlockSaid, name.Said);
    }


    /// <summary>
    /// The fully disclosed aggregate section verifies: every revealed block is authentic and the AGID matches over
    /// the reconstructed list of block SAIDs.
    /// </summary>
    [TestMethod]
    public async Task VerifiesFullDisclosure()
    {
        AcdcAggregateSection section = AcdcAggregateReader.Read(DecodeAggregate(AcdcExampleVectors.AggregateDisclosed));

        Assert.IsTrue(await AcdcAggregate.VerifyDisclosureAsync(section, AcdcJson.Encode, AcdcJson.EncodeAggregateList, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, CancellationToken.None));
    }


    /// <summary>
    /// A selective disclosure verifies: the Issuee and Score blocks are revealed and the Name block is blinded to
    /// its SAID, yet the AGID still matches over the reconstructed list, proving the revealed blocks are members
    /// without revealing the Name block.
    /// </summary>
    [TestMethod]
    public async Task VerifiesSelectiveDisclosure()
    {
        AcdcAggregateSection section = AcdcAggregateReader.Read(DecodeAggregate(AcdcExampleVectors.AggregateSelectiveDisclosure));

        var name = section.Blocks[2] as CompactAggregateBlock;
        Assert.IsNotNull(name, "The Name block is blinded in this selective disclosure.");
        Assert.IsTrue(await AcdcAggregate.VerifyDisclosureAsync(section, AcdcJson.Encode, AcdcJson.EncodeAggregateList, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, CancellationToken.None));
    }


    /// <summary>
    /// A disclosure whose revealed block was altered after issuance does not verify: the altered block no longer
    /// hashes to its claimed SAID.
    /// </summary>
    [TestMethod]
    public async Task RejectsTamperedRevealedBlock()
    {
        //Alter the Issuee block's AID while keeping its claimed SAID, so the block no longer hashes to that SAID.
        string tampered = AcdcExampleVectors.AggregateSelectiveDisclosure.Replace(
            AcdcExampleVectors.AggregateIssueeAid,
            "ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYma",
            System.StringComparison.Ordinal);

        AcdcAggregateSection section = AcdcAggregateReader.Read(DecodeAggregate(tampered));

        Assert.IsFalse(await AcdcAggregate.VerifyDisclosureAsync(section, AcdcJson.Encode, AcdcJson.EncodeAggregateList, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, CancellationToken.None));
    }


    /// <summary>
    /// An aggregate value that is neither a string nor a list is rejected.
    /// </summary>
    [TestMethod]
    public void RejectsNonStringNonListAggregate()
    {
        Assert.ThrowsExactly<AcdcException>(() => AcdcAggregateReader.Read(DecodeAggregate("""{"A":{"d":"d"}}""")));
    }


    /// <summary>
    /// An aggregate list whose zeroth element is not a string AGID is rejected.
    /// </summary>
    [TestMethod]
    public void RejectsListWithoutAgid()
    {
        Assert.ThrowsExactly<AcdcException>(() => AcdcAggregateReader.Read(DecodeAggregate("""{"A":[{"d":"d"}]}""")));
    }


    private static object? DecodeAggregate(string wrappedJson)
    {
        MessageFieldMap map = AcdcJson.DecodeFieldMap(Encoding.UTF8.GetBytes(wrappedJson));
        map.TryGetValue(AcdcMessageFields.AttributeAggregate, out object? aggregate);

        return aggregate;
    }
}
