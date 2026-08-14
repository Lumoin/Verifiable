using System.Collections.Generic;
using System.Linq;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Sanity tests for the <see cref="PAdESBaselineLevelTable"/> and <see cref="PAdESAdditionalRequirements"/>
/// registries: the row/letter counts and cross-references its own transcription states.
/// </summary>
[TestClass]
internal sealed class PAdESBaselineLevelTableTests
{
    /// <summary>Table 1 carries exactly 30 rows, PA-6.3-T01..T30.</summary>
    [TestMethod]
    public void RegistersExactlyThirtyRows()
    {
        Assert.HasCount(30, PAdESBaselineLevelTable.Rows);
    }


    /// <summary>Every requirement ID is unique.</summary>
    [TestMethod]
    public void EveryRequirementIdIsUnique()
    {
        List<string> duplicates = [.. PAdESBaselineLevelTable.Rows
            .GroupBy(row => row.RequirementId, System.StringComparer.Ordinal)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key)];

        Assert.IsEmpty(duplicates);
    }


    /// <summary>Exactly 9 of 30 rows are marked [CAdES-deferred] (T02-T07, T09, T10, T24) per its own reconciliation.</summary>
    [TestMethod]
    public void ExactlyNineRowsAreCAdESDeferred()
    {
        int deferredCount = PAdESBaselineLevelTable.Rows.Count(row => row.IsCAdESDeferred);

        Assert.AreEqual(9, deferredCount);

        string[] expectedIds = ["PA-6.3-T02", "PA-6.3-T03", "PA-6.3-T04", "PA-6.3-T05", "PA-6.3-T06", "PA-6.3-T07", "PA-6.3-T09", "PA-6.3-T10", "PA-6.3-T24"];
        foreach(string id in expectedIds)
        {
            Assert.IsTrue(PAdESBaselineLevelTable.FindByRequirementId(id)!.IsCAdESDeferred, $"{id} should be marked [CAdES-deferred].");
        }
    }


    /// <summary>
    /// PA-6.3-T01's own presence/cardinality/reference — <see cref="RegistersExactlyThirtyRows"/>'s bare count (30
    /// rows) does not discriminate this row's own values from any other; this test checks them directly.
    /// </summary>
    [TestMethod]
    public void SignedDataCertificatesRowCarriesTheExactPresenceCardinalityAndReferenceLeg2States()
    {
        AdESTableRow row = PAdESBaselineLevelTable.FindByRequirementId("PA-6.3-T01")!;

        Assert.AreEqual("SignedData.certificates", row.Name);
        Assert.AreEqual(AdESTableRowKind.CmsAttribute, row.Kind);
        Assert.AreEqual(AdESPresence.ShallBePresent, row.Presence.BB);
        Assert.AreEqual(AdESPresence.ShallBePresent, row.Presence.BT);
        Assert.AreEqual(AdESPresence.ShallBePresent, row.Presence.BLT);
        Assert.AreEqual(AdESPresence.ShallBePresent, row.Presence.BLTA);
        Assert.AreEqual(AdESCardinality.ExactlyOne, row.Cardinality!.ValuesAt(AdESBaselineLevel.BB).Single());
        Assert.AreEqual(new AdESExternalReference("IETF RFC 5652", "5.1"), row.Reference);
        Assert.IsFalse(row.IsCAdESDeferred);
        Assert.IsTrue(row.Annotations.RequirementLetters.SequenceEqual(["a", "b"]));
        Assert.IsTrue(row.Annotations.NoteNumbers.SequenceEqual([1, 2]));
    }


    /// <summary>PA-6.3-T27's own level-split cardinality (its EXAMPLE, clause 6.2.2): "B-B, B-T: &gt;= 0" and "B-LT, B-LTA: &gt;= 1".</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">
    /// ETSI EN 319 142-1 V1.2.1</see> PA-6.2.2-notation.
    /// </remarks>
    [TestMethod]
    public void DssRowCarriesTheLevelSplitCardinalityTheExampleStates()
    {
        AdESTableRow dss = PAdESBaselineLevelTable.FindByRequirementId("PA-6.3-T27")!;

        Assert.AreEqual(AdESCardinality.ZeroOrMore, dss.Cardinality!.ValuesAt(AdESBaselineLevel.BB).Single());
        Assert.AreEqual(AdESCardinality.ZeroOrMore, dss.Cardinality.ValuesAt(AdESBaselineLevel.BT).Single());
        Assert.AreEqual(AdESCardinality.OneOrMore, dss.Cardinality.ValuesAt(AdESBaselineLevel.BLT).Single());
        Assert.AreEqual(AdESCardinality.OneOrMore, dss.Cardinality.ValuesAt(AdESBaselineLevel.BLTA).Single());

        Assert.AreEqual(AdESPresence.ShouldNotBePresent, dss.Presence.BB);
        Assert.AreEqual(AdESPresence.ShallBePresent, dss.Presence.BLT);
    }


    /// <summary>PA-6.3-T30's own level-split cardinality: "&gt;= 0" below B-LTA, "&gt;= 1" at B-LTA.</summary>
    [TestMethod]
    public void DocumentTimestampForLtaCardinalitySplitsAtBLta()
    {
        AdESTableRow docTimeStamp = PAdESBaselineLevelTable.FindByRequirementId("PA-6.3-T30")!;

        Assert.AreEqual(AdESCardinality.ZeroOrMore, docTimeStamp.Cardinality!.ValuesAt(AdESBaselineLevel.BLT).Single());
        Assert.AreEqual(AdESCardinality.OneOrMore, docTimeStamp.Cardinality.ValuesAt(AdESBaselineLevel.BLTA).Single());
    }


    /// <summary>Service rows resolve their own SPO children through <see cref="PAdESBaselineLevelTable.FindByRequirementId"/>.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">
    /// ETSI EN 319 142-1 V1.2.1</see> PA-6.3-T08, PA-6.3-T11.
    /// </remarks>
    [TestMethod]
    public void ServiceRowsNameRegisteredSpoChildren()
    {
        IEnumerable<AdESTableRow> serviceRows = PAdESBaselineLevelTable.Rows.Where(row => row.Kind == AdESTableRowKind.Service);

        foreach(AdESTableRow service in serviceRows)
        {
            Assert.IsNotNull(service.ServiceProvisionOptionRequirementIds);
            foreach(string spoId in service.ServiceProvisionOptionRequirementIds!)
            {
                Assert.IsNotNull(PAdESBaselineLevelTable.FindByRequirementId(spoId), $"{service.RequirementId} names unregistered SPO '{spoId}'.");
            }
        }
    }


    /// <summary>The lettered-requirement registry carries all 30 letter-IDs Table 1's own a)-y) list mints (leg 2 §6.3, several letters split into sub-IDs).</summary>
    [TestMethod]
    public void AdditionalRequirementsRegistersThirtyLetterIds()
    {
        Assert.HasCount(30, PAdESAdditionalRequirements.All);
    }


    /// <summary>Letter d) splits into d1)/d2) — both resolve through the shared letter root.</summary>
    [TestMethod]
    public void FindByLetterRootResolvesSplitLetters()
    {
        IReadOnlyList<PAdESAdditionalRequirement> dRequirements = PAdESAdditionalRequirements.FindByLetterRoot("d");

        Assert.HasCount(2, dRequirements);
        Assert.Contains(r => r.Letter == "d1", dRequirements);
        Assert.Contains(r => r.Letter == "d2", dRequirements);
    }
}
