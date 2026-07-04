using System;
using Lumoin.Base;
using Verifiable.Acdc;

namespace Verifiable.Tests.Acdc;

/// <summary>
/// Conformance tests for <see cref="AcdcSaid"/> against the ACDC specification's worked Accreditation ACDC example
/// (<see cref="AcdcExampleVectors"/>). The specification is the oracle: each published SAID is recomputed over the
/// example's exact byte serialization with an independent BLAKE3 digest and must reproduce the published value. This
/// exercises the SAID at two levels of the same ACDC — the top-level <c>d</c> over the most-compact form, and a
/// section's <c>d</c> over its expanded block — which is how a Verifier checks an ACDC's Graduated Disclosure tree.
/// </summary>
[TestClass]
internal sealed class AcdcSaidConformanceTests
{
    /// <summary>
    /// The top-level SAID recomputes over the most-compact form to the published value, and the reconstructed
    /// serialization is the exact byte length the version string declares.
    /// </summary>
    [TestMethod]
    public async Task VerifiesTopLevelSaidOfCompactAcdc()
    {
        using AcdcTestSupport.EncodedSerialization acdc = AcdcTestSupport.Encode(AcdcExampleVectors.CompactAcdc);

        Assert.AreEqual(AcdcExampleVectors.CompactByteSize, acdc.Length, "The reconstructed most-compact form must be the byte length the version string declares.");
        Assert.AreEqual(AcdcExampleVectors.AccreditationSaid, await AcdcSaid.RecomputeAsync(acdc.Memory, AcdcExampleVectors.AccreditationSaid, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, CancellationToken.None));
        Assert.IsTrue(await AcdcSaid.VerifyAsync(acdc.Memory, AcdcExampleVectors.AccreditationSaid, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, CancellationToken.None));
    }


    /// <summary>
    /// The attribute section SAID recomputes over the section's expanded block to the published value.
    /// </summary>
    [TestMethod]
    public async Task VerifiesAttributeSectionSaid()
    {
        using AcdcTestSupport.EncodedSerialization section = AcdcTestSupport.Encode(AcdcExampleVectors.AttributeSection);

        Assert.AreEqual(AcdcExampleVectors.AttributeSectionSaid, await AcdcSaid.RecomputeAsync(section.Memory, AcdcExampleVectors.AttributeSectionSaid, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, CancellationToken.None));
        Assert.IsTrue(await AcdcSaid.VerifyAsync(section.Memory, AcdcExampleVectors.AttributeSectionSaid, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, CancellationToken.None));
    }


    /// <summary>
    /// The rule section SAID recomputes over the section's expanded block to the published value.
    /// </summary>
    [TestMethod]
    public async Task VerifiesRuleSectionSaid()
    {
        using AcdcTestSupport.EncodedSerialization section = AcdcTestSupport.Encode(AcdcExampleVectors.RuleSection);

        Assert.AreEqual(AcdcExampleVectors.RuleSectionSaid, await AcdcSaid.RecomputeAsync(section.Memory, AcdcExampleVectors.RuleSectionSaid, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, CancellationToken.None));
        Assert.IsTrue(await AcdcSaid.VerifyAsync(section.Memory, AcdcExampleVectors.RuleSectionSaid, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, CancellationToken.None));
    }


    /// <summary>
    /// The specification's partially-disclosable nested rule section (a richer worked example than the
    /// Accreditation's single-clause rule) verifies level by level: each of the three leaf rules over its
    /// <c>{d, u, l}</c> block, the <c>disclaimers</c> rule-group over its block-level form with its two rules
    /// compacted to their SAIDs, and the rule section's top-level SAID over its most-compact (partially disclosed)
    /// form. This is the SAID tree a Verifier descends as a rule section's Graduated Disclosure is expanded.
    /// </summary>
    [TestMethod]
    public async Task VerifiesNestedRuleSectionSaidTree()
    {
        using AcdcTestSupport.EncodedSerialization warranty = AcdcTestSupport.Encode(AcdcExampleVectors.WarrantyDisclaimerRule);
        using AcdcTestSupport.EncodedSerialization liability = AcdcTestSupport.Encode(AcdcExampleVectors.LiabilityDisclaimerRule);
        using AcdcTestSupport.EncodedSerialization permittedUse = AcdcTestSupport.Encode(AcdcExampleVectors.PermittedUseRule);
        using AcdcTestSupport.EncodedSerialization disclaimers = AcdcTestSupport.Encode(AcdcExampleVectors.DisclaimersGroupBlock);
        using AcdcTestSupport.EncodedSerialization section = AcdcTestSupport.Encode(AcdcExampleVectors.NestedRuleSectionPartiallyDisclosed);

        Assert.AreEqual(AcdcExampleVectors.WarrantyDisclaimerSaid, await AcdcSaid.RecomputeAsync(warranty.Memory, AcdcExampleVectors.WarrantyDisclaimerSaid, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, CancellationToken.None), "The warrantyDisclaimer leaf rule SAID must recompute over its block.");
        Assert.AreEqual(AcdcExampleVectors.LiabilityDisclaimerSaid, await AcdcSaid.RecomputeAsync(liability.Memory, AcdcExampleVectors.LiabilityDisclaimerSaid, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, CancellationToken.None), "The liabilityDisclaimer leaf rule SAID must recompute over its block.");
        Assert.AreEqual(AcdcExampleVectors.PermittedUseSaid, await AcdcSaid.RecomputeAsync(permittedUse.Memory, AcdcExampleVectors.PermittedUseSaid, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, CancellationToken.None), "The permittedUse leaf rule SAID must recompute over its block.");
        Assert.AreEqual(AcdcExampleVectors.DisclaimersGroupSaid, await AcdcSaid.RecomputeAsync(disclaimers.Memory, AcdcExampleVectors.DisclaimersGroupSaid, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, CancellationToken.None), "The disclaimers rule-group SAID must recompute over its block-level form with its rules compacted to their SAIDs.");
        Assert.AreEqual(AcdcExampleVectors.NestedRuleSectionSaid, await AcdcSaid.RecomputeAsync(section.Memory, AcdcExampleVectors.NestedRuleSectionSaid, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, CancellationToken.None), "The rule section's top-level SAID must recompute over its most-compact form.");
        Assert.IsTrue(await AcdcSaid.VerifyAsync(section.Memory, AcdcExampleVectors.NestedRuleSectionSaid, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, CancellationToken.None));
    }


    /// <summary>
    /// The Transcript ACDC's edge section verifies level by level under an independent BLAKE3: each leaf edge over
    /// its block (the targeted <c>accreditation</c> edge and the two untargeted <c>research</c> and <c>project</c>
    /// edges), the <c>reports</c> edge-group over its block-level form with its two edges compacted to their SAIDs,
    /// and the edge section's top-level SAID over its most-compact form with both members compacted. This is the
    /// SAID tree a Verifier descends as an edge section's Graduated Disclosure is expanded.
    /// </summary>
    [TestMethod]
    public async Task VerifiesEdgeSectionSaidTree()
    {
        using AcdcTestSupport.EncodedSerialization accreditation = AcdcTestSupport.Encode(AcdcExampleVectors.AccreditationEdgeBlock);
        using AcdcTestSupport.EncodedSerialization research = AcdcTestSupport.Encode(AcdcExampleVectors.ResearchEdgeBlock);
        using AcdcTestSupport.EncodedSerialization project = AcdcTestSupport.Encode(AcdcExampleVectors.ProjectEdgeBlock);
        using AcdcTestSupport.EncodedSerialization reports = AcdcTestSupport.Encode(AcdcExampleVectors.ReportsGroupBlock);
        using AcdcTestSupport.EncodedSerialization section = AcdcTestSupport.Encode(AcdcExampleVectors.EdgeSectionPartiallyDisclosed);

        Assert.AreEqual(AcdcExampleVectors.AccreditationEdgeSaid, await AcdcSaid.RecomputeAsync(accreditation.Memory, AcdcExampleVectors.AccreditationEdgeSaid, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, CancellationToken.None), "The accreditation leaf edge SAID must recompute over its block.");
        Assert.AreEqual(AcdcExampleVectors.ResearchEdgeSaid, await AcdcSaid.RecomputeAsync(research.Memory, AcdcExampleVectors.ResearchEdgeSaid, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, CancellationToken.None), "The research leaf edge SAID must recompute over its block.");
        Assert.AreEqual(AcdcExampleVectors.ProjectEdgeSaid, await AcdcSaid.RecomputeAsync(project.Memory, AcdcExampleVectors.ProjectEdgeSaid, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, CancellationToken.None), "The project leaf edge SAID must recompute over its block.");
        Assert.AreEqual(AcdcExampleVectors.ReportsGroupSaid, await AcdcSaid.RecomputeAsync(reports.Memory, AcdcExampleVectors.ReportsGroupSaid, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, CancellationToken.None), "The reports edge-group SAID must recompute over its block-level form with its edges compacted to their SAIDs.");
        Assert.AreEqual(AcdcExampleVectors.EdgeSectionSaid, await AcdcSaid.RecomputeAsync(section.Memory, AcdcExampleVectors.EdgeSectionSaid, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, CancellationToken.None), "The edge section's top-level SAID must recompute over its most-compact form.");
        Assert.IsTrue(await AcdcSaid.VerifyAsync(section.Memory, AcdcExampleVectors.EdgeSectionSaid, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, CancellationToken.None));
    }


    /// <summary>
    /// A SAID does not verify against a serialization whose bytes were altered after the SAID was computed.
    /// </summary>
    [TestMethod]
    public async Task RejectsTamperedAcdc()
    {
        //Flip the last character of the UUID value, a field present in the compact form, keeping the byte length
        //so only the content differs.
        string tampered = AcdcExampleVectors.CompactAcdc.Replace(
            "\"u\":\"0ABhY2Rjc3BlY3dvcmtyYXdh\"",
            "\"u\":\"0ABhY2Rjc3BlY3dvcmtyYXdg\"",
            StringComparison.Ordinal);
        Assert.AreNotEqual(AcdcExampleVectors.CompactAcdc, tampered, "The tamper must actually alter the serialization for this test to be meaningful.");

        using AcdcTestSupport.EncodedSerialization acdc = AcdcTestSupport.Encode(tampered);

        Assert.IsFalse(await AcdcSaid.VerifyAsync(acdc.Memory, AcdcExampleVectors.AccreditationSaid, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, CancellationToken.None));
    }


    /// <summary>
    /// A claimed SAID that differs from the recomputed value does not verify.
    /// </summary>
    [TestMethod]
    public async Task RejectsWrongSaid()
    {
        using AcdcTestSupport.EncodedSerialization acdc = AcdcTestSupport.Encode(AcdcExampleVectors.CompactAcdc);
        string wrongSaid = AcdcExampleVectors.AccreditationSaid[..^1] + (AcdcExampleVectors.AccreditationSaid[^1] == 'A' ? 'B' : 'A');

        Assert.IsFalse(await AcdcSaid.VerifyAsync(acdc.Memory, wrongSaid, AcdcTestSupport.AgileDigest, BaseMemoryPool.Shared, CancellationToken.None));
    }
}
