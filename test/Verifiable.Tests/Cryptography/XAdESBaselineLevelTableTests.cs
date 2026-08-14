using System;
using System.Collections.Generic;
using System.Linq;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Registry-integrity tests for <see cref="XAdESBaselineLevelTable"/> — the XAdES Table 2 (clause 6.3)
/// baseline-level/presence/cardinality model. These tests check the DATA the registry carries against Table 2
/// (clause 6.3) itself — not creation, augmentation, or validation behaviour, which <see cref="XAdESLevelRules"/>
/// composes this registry into.
/// </summary>
[TestClass]
internal sealed class XAdESBaselineLevelTableTests
{
    /// <summary>The registry carries all 46 Table 2 rows (XA-6.3-t01..t46), each with a unique requirement identifier.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> XA-6.2.2-01, XA-6.3-03 — Table 2 states every row's requirements, and the
    /// registry must carry all of them, each individually addressable.
    /// </remarks>
    [TestMethod]
    public void RegistryContainsExactlyFortySixRowsWithUniqueRequirementIdentifiers()
    {
        Assert.HasCount(46, XAdESBaselineLevelTable.Rows, "Table 2 has 46 distinct rows, counted directly against the published table.");

        var seenIds = new HashSet<string>(StringComparer.Ordinal);
        foreach(AdESTableRow row in XAdESBaselineLevelTable.Rows)
        {
            Assert.IsTrue(seenIds.Add(row.RequirementId), $"Requirement identifier '{row.RequirementId}' must be unique across the registry.");
        }

        Assert.AreEqual("XA-6.3-t01", XAdESBaselineLevelTable.Rows[0].RequirementId, "The first row is ds:KeyInfo/X509Data (XA-6.3-t01).");
        Assert.AreEqual("XA-6.3-t46", XAdESBaselineLevelTable.Rows[^1].RequirementId, "The last row is RenewedDigestsV2 (XA-6.3-t46).");
    }


    /// <summary>
    /// A representative set of level-invariant, internal-clause Table 2 rows (the clause 5.2.x family), each
    /// transcribed here as one (presence, cardinality, References-clause) triple read directly off the
    /// report, independent of and cross-checked against this registry's own data.
    /// </summary>
    private static IEnumerable<object[]> LevelInvariantInternalClauseRows
    {
        get
        {
            (string RequirementId, AdESPresence Presence, AdESCardinality Cardinality, string ReferenceClause)[] rows =
            [
                ("XA-6.3-t05", AdESPresence.ShallBePresent, AdESCardinality.ExactlyOne, "5.2.1"),
                ("XA-6.3-t06", AdESPresence.ShallBePresent, AdESCardinality.ExactlyOne, "5.2.2"),
                ("XA-6.3-t08", AdESPresence.ConditionedPresence, AdESCardinality.ZeroOrMore, "5.2.4"),
                ("XA-6.3-t09", AdESPresence.MayBePresent, AdESCardinality.ZeroOrOne, "5.2.4"),
                ("XA-6.3-t10", AdESPresence.MayBePresent, AdESCardinality.ZeroOrOne, "5.2.4"),
                ("XA-6.3-t11", AdESPresence.ShallBePresent, AdESCardinality.ExactlyOne, "5.2.4"),
                ("XA-6.3-t12", AdESPresence.MayBePresent, AdESCardinality.ZeroOrOne, "5.2.4"),
                ("XA-6.3-t13", AdESPresence.ShallBePresent, AdESCardinality.ExactlyOne, "5.2.4"),
                ("XA-6.3-t15", AdESPresence.MayBePresent, AdESCardinality.ZeroOrOne, "5.2.6"),
                ("XA-6.3-t16", AdESPresence.MayBePresent, AdESCardinality.ZeroOrMore, "5.2.3"),
                ("XA-6.3-t17", AdESPresence.MayBePresent, AdESCardinality.ZeroOrOne, "5.2.5"),
                ("XA-6.3-t19", AdESPresence.MayBePresent, AdESCardinality.ZeroOrMore, "5.2.7.2"),
                ("XA-6.3-t20", AdESPresence.MayBePresent, AdESCardinality.ZeroOrMore, "5.2.8.1"),
                ("XA-6.3-t21", AdESPresence.MayBePresent, AdESCardinality.ZeroOrMore, "5.2.8.2"),
                ("XA-6.3-t22", AdESPresence.MayBePresent, AdESCardinality.ZeroOrOne, "5.2.9"),
                ("XA-6.3-t23", AdESPresence.ConditionedPresence, AdESCardinality.ZeroOrOne, "5.2.10")
            ];

            foreach((string requirementId, AdESPresence presence, AdESCardinality cardinality, string referenceClause) in rows)
            {
                yield return [requirementId, presence, cardinality, referenceClause];
            }
        }
    }


    /// <summary>
    /// Asserts one Table 2 row's presence-per-level, cardinality-per-level, and internal References clause
    /// against its spec-transcribed expected values.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> XA-6.3-t05, XA-6.3-t06, XA-6.3-t08 through XA-6.3-t13, XA-6.3-t15 through
    /// XA-6.3-t17, XA-6.3-t19 through XA-6.3-t23.
    /// </remarks>
    [TestMethod]
    [DynamicData(nameof(LevelInvariantInternalClauseRows))]
    public void LevelInvariantRowMatchesItsSpecTranscribedPresenceCardinalityAndReference(
        string requirementId, AdESPresence expectedPresence, AdESCardinality expectedCardinality, string expectedReferenceClause)
    {
        AdESTableRow? row = XAdESBaselineLevelTable.FindByRequirementId(requirementId);
        Assert.IsNotNull(row, $"'{requirementId}' must be a registered Table 2 row.");

        foreach(AdESBaselineLevel level in AdESBaselineLevels.All)
        {
            Assert.AreEqual(expectedPresence, row.Presence.At(level), $"{requirementId} ({row.Name}) presence at {level}.");
            Assert.AreSequenceEqual([expectedCardinality], row.Cardinality!.ValuesAt(level).ToArray(), $"{requirementId} ({row.Name}) cardinality at {level}.");
        }

        Assert.IsInstanceOfType<AdESInternalClauseReference>(row.Reference);
        Assert.AreEqual(expectedReferenceClause, ((AdESInternalClauseReference)row.Reference!).Clause, $"{requirementId} ({row.Name}) References clause.");
    }


    /// <summary><see cref="XAdESBaselineLevelTable.FindByRequirementId"/> resolves every registered row by identity, and returns null for an unregistered identifier.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> XA-6.2.2-29 — every row's requirement identifier is a stable lookup key.
    /// </remarks>
    [TestMethod]
    public void FindByRequirementIdResolvesEveryRegisteredRowAndOnlyRegisteredRows()
    {
        foreach(AdESTableRow row in XAdESBaselineLevelTable.Rows)
        {
            Assert.AreSame(row, XAdESBaselineLevelTable.FindByRequirementId(row.RequirementId),
                $"Looking up '{row.RequirementId}' must resolve to the exact registered row instance.");
        }

        Assert.IsNull(XAdESBaselineLevelTable.FindByRequirementId("XA-6.3-t99"), "An unregistered requirement identifier must resolve to null.");
    }


    /// <summary>
    /// The four <see cref="AdESTableRowKind.XmlDsigElement"/> rows are exactly <c>ds:KeyInfo/X509Data</c>,
    /// <c>ds:SignedInfo/ds:CanonicalizationMethod</c>, <c>ds:Reference</c>, and <c>ds:Reference/ds:Transforms</c>
    /// — the XMLDSIG core elements Table 2 profiles by reference, never a XAdES-defined qualifying property.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> XA-6.3-t01 through XA-6.3-t04 — the four rows Table 2 cites to XMLDSIG,
    /// not to this document's own clauses.
    /// </remarks>
    [TestMethod]
    public void XmlDsigElementRowsAreExactlyTheFourDsPrefixedRows()
    {
        var expectedIds = new HashSet<string>(StringComparer.Ordinal) { "XA-6.3-t01", "XA-6.3-t02", "XA-6.3-t03", "XA-6.3-t04" };

        foreach(AdESTableRow row in XAdESBaselineLevelTable.Rows)
        {
            bool expectXmlDsig = expectedIds.Contains(row.RequirementId);
            Assert.AreEqual(expectXmlDsig, row.Kind == AdESTableRowKind.XmlDsigElement, $"{row.RequirementId}: Kind must be XmlDsigElement iff it is one of Table 2's four ds:-prefixed rows.");

            if(expectXmlDsig)
            {
                Assert.IsInstanceOfType<AdESExternalReference>(row.Reference);
                Assert.AreEqual("XMLDSIG", ((AdESExternalReference)row.Reference!).Document, $"{row.RequirementId} cites the XMLDSIG core specification.");
            }
        }
    }


    /// <summary>
    /// <see cref="XAdESBaselineLevelTable.DsCanonicalizationMethod"/>'s References cell is transcribed exactly
    /// as Table 2 prints it ("XMLDSIG [1], clause 4.4.1") despite the misprint: clause 4.4.1 of
    /// the XML Signature Syntax and Processing recommendation defines <c>KeyName</c>, not
    /// <c>CanonicalizationMethod</c>.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/#sec-CanonicalizationMethod">XML
    /// Signature Syntax and Processing (Second Edition), clause 4.3.1</see> is <c>CanonicalizationMethod</c>'s
    /// true defining clause — Table 2's own cell prints "4.4.1"; this row's own data honors that
    /// printed value rather than silently correcting it.
    /// </remarks>
    [TestMethod]
    public void CanonicalizationMethodReferenceCellIsTranscribedAsPrintedDespiteMisprint()
    {
        AdESTableRow row = XAdESBaselineLevelTable.DsCanonicalizationMethod;

        Assert.IsInstanceOfType<AdESExternalReference>(row.Reference);
        var reference = (AdESExternalReference)row.Reference!;
        Assert.AreEqual("XMLDSIG", reference.Document, "The row cites the XMLDSIG core specification.");
        Assert.AreEqual("4.4.1", reference.Clause, "Table 2's own printed cell reads '4.4.1', a misprint — transcribed verbatim, not corrected to the true clause 4.3.1.");

        foreach(AdESBaselineLevel level in AdESBaselineLevels.All)
        {
            Assert.AreEqual(AdESPresence.ShallBePresent, row.Presence.At(level), $"CanonicalizationMethod presence at {level}.");
        }
    }


    /// <summary>
    /// <see cref="XAdESBaselineLevelTable.DsReference"/>'s cardinality is <see cref="AdESCardinality.AtLeastTwo"/>
    /// at every level — the sixth cardinality token, minted for this row's own printed "&#8805; 2"
    /// cell (no CB-AdES/JAdES/PAdES row ever states a minimum above one).
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> XA-6.3-t03.
    /// </remarks>
    [TestMethod]
    public void DsReferenceCardinalityIsAtLeastTwoAtEveryLevel()
    {
        Assert.HasCount(6, Enum.GetValues<AdESCardinality>(), "The shared cardinality vocabulary gained a sixth token, AtLeastTwo, for this row.");
        Assert.HasCount(6, Enum.GetValues<AdESCardinality>().Distinct(), "None of the six cardinality tokens may alias another's underlying value.");

        AdESTableRow row = XAdESBaselineLevelTable.DsReference;
        foreach(AdESBaselineLevel level in AdESBaselineLevels.All)
        {
            Assert.AreEqual(AdESPresence.ShallBePresent, row.Presence.At(level), $"ds:Reference presence at {level}.");
            Assert.AreSequenceEqual([AdESCardinality.AtLeastTwo], row.Cardinality!.ValuesAt(level).ToArray(), $"ds:Reference cardinality at {level}.");
        }
    }


    /// <summary>
    /// The eight deprecated-V1 rows (<c>SigningCertificate</c>, <c>SignerRole</c>, <c>SignatureProductionPlace</c>,
    /// <c>CompleteCertificateRefs</c>, <c>AttributeCertificateRefs</c>, <c>SigAndRefsTimeStamp</c>,
    /// <c>RefsOnlyTimeStamp</c>, and the v1.3.2-namespace <c>ArchiveTimeStamp</c>) are each
    /// <see cref="AdESPresence.ShallNotBePresent"/>/<see cref="AdESCardinality.ExactlyZero"/> at every level with
    /// a null References cell.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> XA-6.3-t07, XA-6.3-t14, XA-6.3-t18, XA-6.3-t28, XA-6.3-t31, XA-6.3-t37,
    /// XA-6.3-t39, XA-6.3-t45 — every obsoleted V1 property Table 2 excludes from all four baseline levels.
    /// </remarks>
    [TestMethod]
    public void DeprecatedRowsAreAlwaysShallNotBePresentWithNullReference()
    {
        AdESTableRow[] deprecatedRows =
        [
            XAdESBaselineLevelTable.SigningCertificate,
            XAdESBaselineLevelTable.SignerRole,
            XAdESBaselineLevelTable.SignatureProductionPlace,
            XAdESBaselineLevelTable.CompleteCertificateRefs,
            XAdESBaselineLevelTable.AttributeCertificateRefs,
            XAdESBaselineLevelTable.SigAndRefsTimeStamp,
            XAdESBaselineLevelTable.RefsOnlyTimeStamp,
            XAdESBaselineLevelTable.ArchiveTimeStampV132
        ];

        Assert.HasCount(8, deprecatedRows);
        foreach(AdESTableRow row in deprecatedRows)
        {
            foreach(AdESBaselineLevel level in AdESBaselineLevels.All)
            {
                Assert.AreEqual(AdESPresence.ShallNotBePresent, row.Presence.At(level), $"{row.RequirementId} ({row.Name}) presence at {level}.");
                Assert.AreSequenceEqual([AdESCardinality.ExactlyZero], row.Cardinality!.ValuesAt(level).ToArray(), $"{row.RequirementId} ({row.Name}) cardinality at {level}.");
            }

            Assert.IsNull(row.Reference, $"{row.RequirementId} ({row.Name}) References cell is '-'.");
            Assert.AreEqual(AdESTableRowKind.QualifyingProperty, row.Kind, $"{row.RequirementId} ({row.Name}) is still an xades:-namespaced qualifying property, just an obsoleted one.");
        }
    }


    /// <summary>
    /// <c>CompleteRevocationRefs</c>/<c>AttributeRevocationRefs</c> carry no "V2" suffix and no deprecated
    /// V1 twin, unlike <c>CompleteCertificateRefsV2</c>/<c>AttributeCertificateRefsV2</c> — a genuine document
    /// structural asymmetry (revocation references never carried the <c>IssuerSerialV2</c>-shaped content that
    /// motivated the certificate-refs V1-to-V2 split).
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> XA-6.3-t33, XA-6.3-t35 — Table 2's own printed column-1 names carry no "V2".
    /// </remarks>
    [TestMethod]
    public void CompleteRevocationRefsAndAttributeRevocationRefsCarryNoVersionSuffixOrDeprecatedTwin()
    {
        Assert.AreEqual("CompleteRevocationRefs", XAdESBaselineLevelTable.CompleteRevocationRefs.Name);
        Assert.AreEqual("AttributeRevocationRefs", XAdESBaselineLevelTable.AttributeRevocationRefs.Name);

        Assert.AreEqual(2, XAdESBaselineLevelTable.Rows.Count(row => row.Name.Contains("RevocationRefs", StringComparison.Ordinal)),
            "Exactly two rows name a *RevocationRefs property — no third, deprecated-V1 twin exists for either.");
    }


    /// <summary>
    /// <see cref="AdESPresence.ShouldNotBePresent"/> (Table 2's "*") and <see cref="AdESPresence.ShallNotBePresent"/>
    /// are two distinct enum members, both exercised by registered rows, never collapsed into one value.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> XA-6.2.2-17, XA-6.2.2-21.
    /// </remarks>
    [TestMethod]
    public void ShouldNotBePresentIsTypeLevelDistinguishableFromShallNotBePresent()
    {
        Assert.HasCount(6, Enum.GetValues<AdESPresence>(), "Clause 6.2.2 declares exactly six presence constants (XA-6.2.2-16..21).");
        Assert.HasCount(6, Enum.GetValues<AdESPresence>().Distinct());

        //SignatureTimeStamp at B-B is the soft "*" - a component that upper levels still make mandatory.
        Assert.AreEqual(AdESPresence.ShouldNotBePresent, XAdESBaselineLevelTable.SignatureTimeStamp.Presence.At(AdESBaselineLevel.BB));

        //CompleteCertificateRefsV2 at B-LT/B-LTA is the hard exclusion - a property that must be stripped, never re-added.
        Assert.AreEqual(AdESPresence.ShallNotBePresent, XAdESBaselineLevelTable.CompleteCertificateRefsV2.Presence.At(AdESBaselineLevel.BLT));
        Assert.AreEqual(AdESPresence.ShallNotBePresent, XAdESBaselineLevelTable.CompleteCertificateRefsV2.Presence.At(AdESBaselineLevel.BLTA));
    }


    /// <summary>
    /// The six "*"-at-B-B/B-T-then-<see cref="AdESPresence.ShallNotBePresent"/>-at-B-LT/B-LTA rows
    /// (<c>CompleteCertificateRefsV2</c>, <c>AttributeCertificateRefsV2</c>, <c>CompleteRevocationRefs</c>,
    /// <c>AttributeRevocationRefs</c>, <c>SigAndRefsTimeStampV2</c>, <c>RefsOnlyTimeStampV2</c>) each carry a
    /// level-split cardinality: B-B/B-T the row's own early value, B-LT/B-LTA exactly zero.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> XA-6.3-t27, XA-6.3-t30, XA-6.3-t33, XA-6.3-t35, XA-6.3-t36, XA-6.3-t38.
    /// </remarks>
    [TestMethod]
    public void AnnexAReferenceFamilyRowsShareTheSameLevelSplitCardinalityShape()
    {
        AssertLevelSplit(XAdESBaselineLevelTable.CompleteCertificateRefsV2, AdESCardinality.ZeroOrOne);
        AssertLevelSplit(XAdESBaselineLevelTable.AttributeCertificateRefsV2, AdESCardinality.ZeroOrOne);
        AssertLevelSplit(XAdESBaselineLevelTable.CompleteRevocationRefs, AdESCardinality.ZeroOrOne);
        AssertLevelSplit(XAdESBaselineLevelTable.AttributeRevocationRefs, AdESCardinality.ZeroOrOne);
        AssertLevelSplit(XAdESBaselineLevelTable.SigAndRefsTimeStampV2, AdESCardinality.ZeroOrMore);
        AssertLevelSplit(XAdESBaselineLevelTable.RefsOnlyTimeStampV2, AdESCardinality.ZeroOrMore);

        static void AssertLevelSplit(AdESTableRow row, AdESCardinality earlyCardinality)
        {
            Assert.AreSequenceEqual([earlyCardinality], row.Cardinality!.ValuesAt(AdESBaselineLevel.BB).ToArray(), $"{row.RequirementId} at B-B.");
            Assert.AreSequenceEqual([earlyCardinality], row.Cardinality!.ValuesAt(AdESBaselineLevel.BT).ToArray(), $"{row.RequirementId} at B-T.");
            Assert.AreSequenceEqual([AdESCardinality.ExactlyZero], row.Cardinality!.ValuesAt(AdESBaselineLevel.BLT).ToArray(), $"{row.RequirementId} at B-LT.");
            Assert.AreSequenceEqual([AdESCardinality.ExactlyZero], row.Cardinality!.ValuesAt(AdESBaselineLevel.BLTA).ToArray(), $"{row.RequirementId} at B-LTA.");

            Assert.AreEqual(AdESPresence.ShouldNotBePresent, row.Presence.At(AdESBaselineLevel.BB));
            Assert.AreEqual(AdESPresence.ShouldNotBePresent, row.Presence.At(AdESBaselineLevel.BT));
            Assert.AreEqual(AdESPresence.ShallNotBePresent, row.Presence.At(AdESBaselineLevel.BLT));
            Assert.AreEqual(AdESPresence.ShallNotBePresent, row.Presence.At(AdESBaselineLevel.BLTA));
        }
    }


    /// <summary>
    /// <c>SignatureTimeStamp</c>'s cardinality is a single two-part cell (B-B &#8805; 0, B-T/B-LT/B-LTA
    /// &#8805; 1) — two statements, mirroring JAdES's own <c>sigTst</c> row shape, never a duplicated third/
    /// fourth line the way CB-AdES's own <c>sigTst</c> row prints one.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> XA-6.2.2-22, XA-6.3-t24.
    /// </remarks>
    [TestMethod]
    public void SignatureTimeStampCardinalityIsATwoPartLevelSplitWithNoDuplicateLine()
    {
        AdESRowCardinality cardinality = XAdESBaselineLevelTable.SignatureTimeStamp.Cardinality!;

        Assert.HasCount(2, cardinality.Statements, "SignatureTimeStamp's Table 2 cell states exactly two cardinality sub-lines.");
        Assert.AreSequenceEqual([AdESCardinality.ZeroOrMore], cardinality.ValuesAt(AdESBaselineLevel.BB).ToArray(), "SignatureTimeStamp at B-B: >=0.");
        Assert.AreSequenceEqual([AdESCardinality.OneOrMore], cardinality.ValuesAt(AdESBaselineLevel.BT).ToArray(), "SignatureTimeStamp at B-T: >=1.");
        Assert.AreSequenceEqual([AdESCardinality.OneOrMore], cardinality.ValuesAt(AdESBaselineLevel.BLT).ToArray(), "SignatureTimeStamp at B-LT: >=1 (cumulative, unchanged).");
        Assert.AreSequenceEqual([AdESCardinality.OneOrMore], cardinality.ValuesAt(AdESBaselineLevel.BLTA).ToArray(), "SignatureTimeStamp at B-LTA: >=1 (cumulative, unchanged).");
    }


    /// <summary><c>SignatureTimeStamp</c>'s presence is "*" only at B-B, and mandatory from B-T onward.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> XA-6.3-t24.
    /// </remarks>
    [TestMethod]
    public void SignatureTimeStampPresenceIsSoftNegativeAtBBAndMandatoryFromBTOnward()
    {
        AdESRowPresence presence = XAdESBaselineLevelTable.SignatureTimeStamp.Presence;

        Assert.AreEqual(AdESPresence.ShouldNotBePresent, presence.At(AdESBaselineLevel.BB));
        Assert.AreEqual(AdESPresence.ShallBePresent, presence.At(AdESBaselineLevel.BT));
        Assert.AreEqual(AdESPresence.ShallBePresent, presence.At(AdESBaselineLevel.BLT));
        Assert.AreEqual(AdESPresence.ShallBePresent, presence.At(AdESBaselineLevel.BLTA));
    }


    /// <summary>
    /// <c>CertificateValues</c>/<c>AnyValidationData</c>/<c>AttrAuthoritiesCertValues</c>/<c>RevocationValues</c>/
    /// <c>AttributeRevocationValues</c> each carry a level-invariant cardinality despite their level-split
    /// presence ("*" at B-B/B-T, conditioned presence at B-LT/B-LTA).
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> XA-6.2.2-26, XA-6.3-t25, XA-6.3-t26, XA-6.3-t29, XA-6.3-t32, XA-6.3-t34.
    /// </remarks>
    [TestMethod]
    public void ValidationDataValueRowsCardinalityIsLevelInvariantDespiteLevelSplitPresence()
    {
        AssertLevelInvariantCardinalityDespiteLevelSplitPresence(XAdESBaselineLevelTable.CertificateValues, AdESCardinality.ZeroOrOne);
        AssertLevelInvariantCardinalityDespiteLevelSplitPresence(XAdESBaselineLevelTable.AnyValidationData, AdESCardinality.ZeroOrMore);
        AssertLevelInvariantCardinalityDespiteLevelSplitPresence(XAdESBaselineLevelTable.AttrAuthoritiesCertValues, AdESCardinality.ZeroOrOne);
        AssertLevelInvariantCardinalityDespiteLevelSplitPresence(XAdESBaselineLevelTable.RevocationValues, AdESCardinality.ZeroOrOne);
        AssertLevelInvariantCardinalityDespiteLevelSplitPresence(XAdESBaselineLevelTable.AttributeRevocationValues, AdESCardinality.ZeroOrOne);

        static void AssertLevelInvariantCardinalityDespiteLevelSplitPresence(AdESTableRow row, AdESCardinality expected)
        {
            Assert.HasCount(1, row.Cardinality!.Statements, $"{row.RequirementId} carries a single row-wide cardinality statement.");
            foreach(AdESBaselineLevel level in AdESBaselineLevels.All)
            {
                Assert.AreSequenceEqual([expected], row.Cardinality.ValuesAt(level).ToArray());
            }

            Assert.AreEqual(AdESPresence.ShouldNotBePresent, row.Presence.At(AdESBaselineLevel.BB));
            Assert.AreEqual(AdESPresence.ShouldNotBePresent, row.Presence.At(AdESBaselineLevel.BT));
            Assert.AreEqual(AdESPresence.ConditionedPresence, row.Presence.At(AdESBaselineLevel.BLT));
            Assert.AreEqual(AdESPresence.ConditionedPresence, row.Presence.At(AdESBaselineLevel.BLTA));
        }
    }


    /// <summary><c>ArchiveTimeStamp</c> (v1.4.1 namespace) is B-LTA-exclusive and mandatory once reached, with a level-invariant "one or more" cardinality.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> XA-6.2.2-27, XA-6.3-t44.
    /// </remarks>
    [TestMethod]
    public void ArchiveTimeStampIsBLtaExclusiveAndMandatoryOnceReached()
    {
        AdESTableRow archiveTimeStamp = XAdESBaselineLevelTable.ArchiveTimeStamp;

        Assert.AreEqual(AdESPresence.ShouldNotBePresent, archiveTimeStamp.Presence.At(AdESBaselineLevel.BB));
        Assert.AreEqual(AdESPresence.ShouldNotBePresent, archiveTimeStamp.Presence.At(AdESBaselineLevel.BT));
        Assert.AreEqual(AdESPresence.ShouldNotBePresent, archiveTimeStamp.Presence.At(AdESBaselineLevel.BLT));
        Assert.AreEqual(AdESPresence.ShallBePresent, archiveTimeStamp.Presence.At(AdESBaselineLevel.BLTA));

        foreach(AdESBaselineLevel level in AdESBaselineLevels.All)
        {
            Assert.AreSequenceEqual([AdESCardinality.OneOrMore], archiveTimeStamp.Cardinality!.ValuesAt(level).ToArray());
        }
    }


    /// <summary>
    /// <c>RenewedDigestsV2</c> is only reachable (conditioned presence) at B-LTA; B-B/B-T/B-LT all print "*",
    /// a soft-negative that never hardens into an exclusion at any level.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> XA-6.3-t46.
    /// </remarks>
    [TestMethod]
    public void RenewedDigestsV2IsOnlyConditionedAtBLta()
    {
        AdESTableRow row = XAdESBaselineLevelTable.RenewedDigestsV2;

        Assert.AreEqual(AdESPresence.ShouldNotBePresent, row.Presence.At(AdESBaselineLevel.BB));
        Assert.AreEqual(AdESPresence.ShouldNotBePresent, row.Presence.At(AdESBaselineLevel.BT));
        Assert.AreEqual(AdESPresence.ShouldNotBePresent, row.Presence.At(AdESBaselineLevel.BLT));
        Assert.AreEqual(AdESPresence.ConditionedPresence, row.Presence.At(AdESBaselineLevel.BLTA));

        foreach(AdESBaselineLevel level in AdESBaselineLevels.All)
        {
            Assert.AreSequenceEqual([AdESCardinality.ZeroOrMore], row.Cardinality!.ValuesAt(level).ToArray());
        }
    }


    /// <summary>
    /// The validation-data-for-timestamps service groups its three "SPO:"-prefixed rows
    /// (<c>TimeStampValidationData</c>, the embedded-in-token option, <c>AnyValidationData</c>), resolvable
    /// through <see cref="XAdESBaselineLevelTable.ServiceProvisionOptionsFor"/>.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> XA-6.2.2-03, XA-6.2.2-04, XA-6.2.2-06, XA-6.2.2-09, XA-6.2.2-10, XA-6.3-t40
    /// through XA-6.3-t43.
    /// </remarks>
    [TestMethod]
    public void ValidationDataForTimestampsServiceGroupsItsThreeServiceProvisionOptionRows()
    {
        AdESTableRow service = XAdESBaselineLevelTable.ValidationDataForTimestampsService;

        Assert.IsTrue(XAdESBaselineLevelTable.IsServiceRow(service));
        Assert.IsFalse(XAdESBaselineLevelTable.IsServiceProvisionOptionRow(service));
        Assert.IsNull(service.Cardinality, "XA-6.3-t40's Cardinality column is '-' (n/a, service row).");
        Assert.IsNull(service.Reference, "XA-6.3-t40's References column is '-'.");

        Assert.AreEqual(AdESPresence.ShouldNotBePresent, service.Presence.At(AdESBaselineLevel.BB));
        Assert.AreEqual(AdESPresence.ShouldNotBePresent, service.Presence.At(AdESBaselineLevel.BT));
        Assert.AreEqual(AdESPresence.ShallBeProvided, service.Presence.At(AdESBaselineLevel.BLT));
        Assert.AreEqual(AdESPresence.ShallBeProvided, service.Presence.At(AdESBaselineLevel.BLTA));

        IReadOnlyList<AdESTableRow> options = XAdESBaselineLevelTable.ServiceProvisionOptionsFor(service);
        Assert.HasCount(3, options, "The service is satisfied by exactly three SPO rows (XA-6.3-t41..43).");
        Assert.AreSame(XAdESBaselineLevelTable.TimeStampValidationDataOption, options[0]);
        Assert.AreSame(XAdESBaselineLevelTable.EmbeddedValidationDataOption, options[1]);
        Assert.AreSame(XAdESBaselineLevelTable.AnyValidationDataOption, options[2]);

        foreach(AdESTableRow option in options)
        {
            Assert.IsTrue(XAdESBaselineLevelTable.IsServiceProvisionOptionRow(option));
            Assert.IsFalse(XAdESBaselineLevelTable.IsServiceRow(option));
        }
    }


    /// <summary><see cref="XAdESBaselineLevelTable.ServiceProvisionOptionsFor"/> refuses a non-service row.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> XA-6.2.2-01/02 — only a Service row carries SPO children to resolve.
    /// </remarks>
    [TestMethod]
    public void ServiceProvisionOptionsForRejectsANonServiceRow() =>
        Assert.ThrowsExactly<ArgumentException>(() => XAdESBaselineLevelTable.ServiceProvisionOptionsFor(XAdESBaselineLevelTable.SigningTime));


    /// <summary>
    /// Every row's lettered-requirement and note annotations exactly match Table 2's own
    /// per-row annotation list (all 46 rows, exhaustive).
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> XA-6.2.2-29 (the Additional-requirements-and-notes column) for every one
    /// of Table 2's 46 rows.
    /// </remarks>
    [TestMethod]
    public void AnnotationsMatchTheLegFourReportForEveryRow()
    {
        (string RequirementId, string[] Letters, int[] Notes)[] expected =
        [
            ("XA-6.3-t01", ["a", "b", "c"], [3, 4, 5]),
            ("XA-6.3-t02", ["d", "e"], [6]),
            ("XA-6.3-t03", [], []),
            ("XA-6.3-t04", ["f", "g"], []),
            ("XA-6.3-t05", ["h"], []),
            ("XA-6.3-t06", ["i", "j"], [7]),
            ("XA-6.3-t07", [], []),
            ("XA-6.3-t08", ["k"], []),
            ("XA-6.3-t09", ["l"], [8]),
            ("XA-6.3-t10", ["l"], []),
            ("XA-6.3-t11", ["l"], []),
            ("XA-6.3-t12", ["l"], []),
            ("XA-6.3-t13", ["l"], []),
            ("XA-6.3-t14", [], []),
            ("XA-6.3-t15", [], []),
            ("XA-6.3-t16", [], []),
            ("XA-6.3-t17", [], []),
            ("XA-6.3-t18", [], []),
            ("XA-6.3-t19", [], []),
            ("XA-6.3-t20", [], [10]),
            ("XA-6.3-t21", [], [10]),
            ("XA-6.3-t22", [], []),
            ("XA-6.3-t23", ["m"], []),
            ("XA-6.3-t24", ["n", "o"], [10]),
            ("XA-6.3-t25", ["p", "q"], []),
            ("XA-6.3-t26", ["q", "u", "v", "cc"], []),
            ("XA-6.3-t27", ["j"], []),
            ("XA-6.3-t28", [], []),
            ("XA-6.3-t29", ["q", "r"], []),
            ("XA-6.3-t30", ["j", "s"], []),
            ("XA-6.3-t31", [], []),
            ("XA-6.3-t32", ["t", "u", "v"], []),
            ("XA-6.3-t33", [], []),
            ("XA-6.3-t34", ["v", "w"], []),
            ("XA-6.3-t35", ["s"], []),
            ("XA-6.3-t36", [], []),
            ("XA-6.3-t37", [], []),
            ("XA-6.3-t38", [], []),
            ("XA-6.3-t39", [], []),
            ("XA-6.3-t40", ["x", "y"], [9]),
            ("XA-6.3-t41", ["y"], []),
            ("XA-6.3-t42", ["y"], []),
            ("XA-6.3-t43", ["y"], []),
            ("XA-6.3-t44", ["z", "aa"], []),
            ("XA-6.3-t45", [], []),
            ("XA-6.3-t46", ["bb"], [])
        ];

        Assert.HasCount(46, expected, "Every Table 2 row is accounted for.");
        foreach((string requirementId, string[] letters, int[] notes) in expected)
        {
            AdESTableRow? row = XAdESBaselineLevelTable.FindByRequirementId(requirementId);
            Assert.IsNotNull(row, $"'{requirementId}' must be a registered Table 2 row.");
            Assert.AreSequenceEqual(letters, row.Annotations.RequirementLetters.ToArray(), $"{requirementId} requirement letters.");
            Assert.AreSequenceEqual(notes, row.Annotations.NoteNumbers.ToArray(), $"{requirementId} note numbers.");
        }
    }


    /// <summary>Every one of the twenty-nine lettered additional requirements a) through cc) appears on at least one registered row.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> the clause 6.3 "Additional requirements" list — every lettered requirement
    /// a)-cc) must anchor to at least one Table 2 row.
    /// </remarks>
    [TestMethod]
    public void EveryLetteredRequirementFromAThroughCcAppearsOnAtLeastOneRow()
    {
        var seenLetters = new HashSet<string>(StringComparer.Ordinal);
        foreach(AdESTableRow row in XAdESBaselineLevelTable.Rows)
        {
            foreach(string letter in row.Annotations.RequirementLetters)
            {
                seenLetters.Add(letter);
            }
        }

        string[] expectedLetters = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "aa", "bb", "cc"];
        Assert.HasCount(29, expectedLetters, "Clause 6.3 defines exactly twenty-nine lettered additional requirements, a) through cc).");
        Assert.AreSequenceEqual(expectedLetters, seenLetters.ToArray(), SequenceOrder.InAnyOrder);
    }


    /// <summary>
    /// <see cref="AdESTableRow.Cardinality"/> is <see langword="null"/> for exactly the one row Table 2 marks
    /// "-" in the Cardinality column (<see cref="XAdESBaselineLevelTable.ValidationDataForTimestampsService"/>),
    /// and non-null for every other row.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> XA-6.2.2-22.
    /// </remarks>
    [TestMethod]
    public void CardinalityIsNullOnlyForTheOneDashServiceRow()
    {
        var expectedNullCardinalityIds = new HashSet<string>(StringComparer.Ordinal) { "XA-6.3-t40" };

        foreach(AdESTableRow row in XAdESBaselineLevelTable.Rows)
        {
            bool expectNull = expectedNullCardinalityIds.Contains(row.RequirementId);
            Assert.AreEqual(expectNull, row.Cardinality is null, $"{row.RequirementId}: Cardinality must be null iff Table 2 marks it '-'.");
        }
    }


    /// <summary>
    /// <see cref="AdESTableRow.Reference"/> is <see langword="null"/> for exactly the ten rows Table 2 marks
    /// "-" in the References column (the eight deprecated-V1 rows, the service row, and the embedded-in-token
    /// SPO), and non-null for every other row.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> XA-6.2.2-28.
    /// </remarks>
    [TestMethod]
    public void ReferenceIsNullOnlyForTheDocumentedDashRows()
    {
        var expectedNullReferenceIds = new HashSet<string>(StringComparer.Ordinal)
        {
            "XA-6.3-t07", "XA-6.3-t14", "XA-6.3-t18", "XA-6.3-t28", "XA-6.3-t31", "XA-6.3-t37", "XA-6.3-t39", "XA-6.3-t45",
            "XA-6.3-t40", "XA-6.3-t42"
        };

        foreach(AdESTableRow row in XAdESBaselineLevelTable.Rows)
        {
            bool expectNull = expectedNullReferenceIds.Contains(row.RequirementId);
            Assert.AreEqual(expectNull, row.Reference is null, $"{row.RequirementId}: Reference nullability must match Table 2's References column.");
        }
    }


    /// <summary>The registry's row-kind split matches the 4/38/1/3 count Table 2's own 46 rows yield.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> XA-6.2.2-08 through XA-6.2.2-11 — the column-1 kind taxonomy.
    /// </remarks>
    [TestMethod]
    public void RowKindCountsMatchTheDocumentedFourThirtyEightOneThreeSplit()
    {
        Assert.AreEqual(4, XAdESBaselineLevelTable.Rows.Count(row => row.Kind == AdESTableRowKind.XmlDsigElement));
        Assert.AreEqual(38, XAdESBaselineLevelTable.Rows.Count(row => row.Kind == AdESTableRowKind.QualifyingProperty));
        Assert.ContainsSingle(row => row.Kind == AdESTableRowKind.Service, XAdESBaselineLevelTable.Rows);
        Assert.AreEqual(3, XAdESBaselineLevelTable.Rows.Count(row => row.Kind == AdESTableRowKind.ServiceProvisionOption));
    }


    /// <summary><see cref="AdESRowPresence.Uniform"/> applies the same value at all four levels.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> XA-6.2.2-18.
    /// </remarks>
    [TestMethod]
    public void UniformPresenceAppliesTheSameValueAtAllFourLevels()
    {
        AdESRowPresence presence = AdESRowPresence.Uniform(AdESPresence.MayBePresent);

        foreach(AdESBaselineLevel level in AdESBaselineLevels.All)
        {
            Assert.AreEqual(AdESPresence.MayBePresent, presence.At(level));
        }
    }


    /// <summary><see cref="AdESRowCardinality.Uniform"/> produces a single statement scoped to every level.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> XA-6.2.2-22 through XA-6.2.2-27.
    /// </remarks>
    [TestMethod]
    public void UniformCardinalityAppliesTheSameValueAtAllFourLevels()
    {
        AdESRowCardinality cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne);

        Assert.HasCount(1, cardinality.Statements);
        Assert.AreEqual(AdESBaselineLevelSet.All, cardinality.Statements[0].Levels);
        foreach(AdESBaselineLevel level in AdESBaselineLevels.All)
        {
            Assert.AreSequenceEqual([AdESCardinality.ZeroOrOne], cardinality.ValuesAt(level).ToArray());
        }
    }


    /// <summary><see cref="AdESBaselineLevelSet"/> membership round-trips through <see cref="AdESBaselineLevels.ToLevelSet"/> for every level.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> XA-6.1-01 through XA-6.1-04, XA-6.2.2-12 through XA-6.2.2-15.
    /// </remarks>
    [TestMethod]
    public void LevelSetContainsReflectsSingleLevelMembership()
    {
        foreach(AdESBaselineLevel level in AdESBaselineLevels.All)
        {
            AdESBaselineLevelSet singleton = level.ToLevelSet();
            Assert.IsTrue(singleton.Contains(level), $"{level}'s own singleton set must contain {level}.");
            Assert.IsTrue(AdESBaselineLevelSet.All.Contains(level), $"'All' must contain {level}.");

            foreach(AdESBaselineLevel other in AdESBaselineLevels.All)
            {
                if(other != level)
                {
                    Assert.IsFalse(singleton.Contains(other), $"{level}'s own singleton set must not contain {other}.");
                }
            }
        }
    }


    /// <summary>
    /// Letter y)'s own SHOULD ("the validation data for electronic time-stamps should be included either in the
    /// <c>TimeStampValidationData</c> [...], or the <c>AnyValidationData</c> [...]") surfaces as a TWO-SPO
    /// preference — <see cref="AdESTableRow.PreferredServiceProvisionOptionRequirementIds"/> naming
    /// <c>TimeStampValidationData</c> (XA-6.3-t41) and <c>AnyValidationData</c> (XA-6.3-t43) but not the
    /// embedded-in-time-stamp option (XA-6.3-t42) — a widened, additive sibling of the singular <see
    /// cref="AdESTableRow.PreferredServiceProvisionOptionRequirementId"/> CB-AdES's own letter-i preference
    /// uses, per the "not silently narrowed" precedent.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
    /// ETSI EN 319 132-1 V1.3.1</see> clause 6.3, Table 2, XA-6.3-t40, letter y.
    /// </remarks>
    [TestMethod]
    public void ValidationDataForTimestampsServicePrefersTwoOfItsThreeServiceProvisionOptions()
    {
        AdESTableRow service = XAdESBaselineLevelTable.ValidationDataForTimestampsService;

        Assert.IsNull(service.PreferredServiceProvisionOptionRequirementId);
        Assert.IsNotNull(service.PreferredServiceProvisionOptionRequirementIds);
        Assert.AreSequenceEqual(["XA-6.3-t41", "XA-6.3-t43"], service.PreferredServiceProvisionOptionRequirementIds!);
        Assert.DoesNotContain("XA-6.3-t42", service.PreferredServiceProvisionOptionRequirementIds!);
        Assert.IsTrue(service.PreferredServiceProvisionOptionRequirementIds!.All(id => service.ServiceProvisionOptionRequirementIds!.Contains(id)),
            "Every preferred SPO must itself be one of the service's own SPOs.");
    }
}
