using System;
using System.Collections.Generic;
using System.Linq;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Registry-integrity tests for <see cref="JAdESBaselineLevelTable"/> — the JAdES Table 1 (clause 6.3)
/// baseline-level/presence/cardinality model. These tests check the DATA the registry carries against Table 1
/// (clause 6.3) itself — not creation, augmentation, or validation behaviour, which compose this registry
/// downstream.
/// </summary>
[TestClass]
internal sealed class JAdESBaselineLevelTableTests
{
    /// <summary>The registry carries all 38 Table 1 rows (JA-6.3-05..42), each with a unique requirement identifier.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.2.2-01, JA-6.3-02.
    /// </remarks>
    [TestMethod]
    public void RegistryContainsExactlyThirtyEightRowsWithUniqueRequirementIdentifiers()
    {
        Assert.HasCount(38, JAdESBaselineLevelTable.Rows, "Table 1 has 38 distinct rows, counted directly against the published table.");

        var seenIds = new HashSet<string>(StringComparer.Ordinal);
        foreach(AdESTableRow row in JAdESBaselineLevelTable.Rows)
        {
            Assert.IsTrue(seenIds.Add(row.RequirementId), $"Requirement identifier '{row.RequirementId}' must be unique across the registry.");
        }

        Assert.AreEqual("JA-6.3-05", JAdESBaselineLevelTable.Rows[0].RequirementId, "The first row is alg (JA-6.3-05).");
        Assert.AreEqual("JA-6.3-42", JAdESBaselineLevelTable.Rows[^1].RequirementId, "The last row is arcTst (JA-6.3-42).");
    }


    /// <summary>
    /// A representative set of level-invariant Table 1 rows, each transcribed here as one (presence,
    /// cardinality, References-clause) triple read directly off the report, independent of and
    /// cross-checked against this registry's own data (the CB-AdES table-test spec-transcribed-values
    /// discipline, this file's own remediation convention).
    /// </summary>
    private static IEnumerable<object[]> LevelInvariantTable1Rows
    {
        get
        {
            (string RequirementId, AdESPresence Presence, AdESCardinality Cardinality, string ReferenceClause)[] rows =
            [
                ("JA-6.3-05", AdESPresence.ShallBePresent, AdESCardinality.ExactlyOne, "5.1.2"),
                ("JA-6.3-06", AdESPresence.ConditionedPresence, AdESCardinality.ZeroOrOne, "5.1.3"),
                ("JA-6.3-07", AdESPresence.MayBePresent, AdESCardinality.ZeroOrOne, "5.1.4"),
                ("JA-6.3-08", AdESPresence.MayBePresent, AdESCardinality.ZeroOrOne, "5.1.5"),
                ("JA-6.3-09", AdESPresence.ConditionedPresence, AdESCardinality.ZeroOrOne, "5.1.8"),
                //Table 1's own printed Cardinality cell for crit is blank; the ruled reading is "0 or 1".
                ("JA-6.3-10", AdESPresence.ConditionedPresence, AdESCardinality.ZeroOrOne, "5.1.9"),
                ("JA-6.3-12", AdESPresence.ConditionedPresence, AdESCardinality.ZeroOrOne, "5.1.11"),
                ("JA-6.3-13", AdESPresence.ConditionedPresence, AdESCardinality.ZeroOrOne, "5.2.1"),
                ("JA-6.3-15", AdESPresence.ConditionedPresence, AdESCardinality.ZeroOrOne, "5.1.7"),
                ("JA-6.3-16", AdESPresence.ConditionedPresence, AdESCardinality.ZeroOrOne, "5.2.2"),
                ("JA-6.3-17", AdESPresence.ConditionedPresence, AdESCardinality.ZeroOrOne, "5.2.2"),
                ("JA-6.3-18", AdESPresence.MayBePresent, AdESCardinality.ZeroOrOne, "5.2.8"),
                ("JA-6.3-19", AdESPresence.MayBePresent, AdESCardinality.ZeroOrOne, "5.2.5"),
                ("JA-6.3-20", AdESPresence.MayBePresent, AdESCardinality.ZeroOrOne, "5.2.3"),
                ("JA-6.3-21", AdESPresence.MayBePresent, AdESCardinality.ZeroOrOne, "5.2.4"),
                ("JA-6.3-22", AdESPresence.MayBePresent, AdESCardinality.ZeroOrOne, "5.2.7"),
                ("JA-6.3-23", AdESPresence.MayBePresent, AdESCardinality.ZeroOrMore, "5.3.2"),
                //The ruled reading: the printed References cell reads "5.3.3" (sigPSt's own
                //clause, the very next row) rather than adoTst's own defining clause 5.2.6; transcribed here as
                //PRINTED, per this registry's own transcription discipline.
                ("JA-6.3-24", AdESPresence.MayBePresent, AdESCardinality.ZeroOrOne, "5.3.3"),
                ("JA-6.3-25", AdESPresence.ConditionedPresence, AdESCardinality.ZeroOrOne, "5.3.3")
            ];

            foreach((string requirementId, AdESPresence presence, AdESCardinality cardinality, string referenceClause) in rows)
            {
                yield return [requirementId, presence, cardinality, referenceClause];
            }
        }
    }


    /// <summary>
    /// Asserts one Table 1 row's presence-per-level, cardinality-per-level, and References clause against its
    /// spec-transcribed expected values.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.2.2-20, JA-6.2.2-25, JA-6.3-06, JA-6.3-07, JA-6.3-08, JA-6.3-09,
    /// JA-6.3-10, JA-6.3-18, JA-6.3-19, JA-6.3-20, JA-6.3-21.
    /// </remarks>
    [TestMethod]
    [DynamicData(nameof(LevelInvariantTable1Rows))]
    public void LevelInvariantRowMatchesItsSpecTranscribedPresenceCardinalityAndReference(
        string requirementId, AdESPresence expectedPresence, AdESCardinality expectedCardinality, string expectedReferenceClause)
    {
        AdESTableRow? row = JAdESBaselineLevelTable.FindByRequirementId(requirementId);
        Assert.IsNotNull(row, $"'{requirementId}' must be a registered Table 1 row.");

        foreach(AdESBaselineLevel level in AdESBaselineLevels.All)
        {
            Assert.AreEqual(expectedPresence, row.Presence.At(level), $"{requirementId} ({row.Name}) presence at {level}.");
            Assert.AreSequenceEqual([expectedCardinality], row.Cardinality!.ValuesAt(level).ToArray(), $"{requirementId} ({row.Name}) cardinality at {level}.");
        }

        Assert.IsInstanceOfType<AdESInternalClauseReference>(row.Reference);
        Assert.AreEqual(expectedReferenceClause, ((AdESInternalClauseReference)row.Reference!).Clause, $"{requirementId} ({row.Name}) References clause.");
    }


    /// <summary><see cref="JAdESBaselineLevelTable.FindByRequirementId"/> resolves every registered row by identity, and returns null for an unregistered identifier.</summary>
    [TestMethod]
    public void FindByRequirementIdResolvesEveryRegisteredRowAndOnlyRegisteredRows()
    {
        foreach(AdESTableRow row in JAdESBaselineLevelTable.Rows)
        {
            Assert.AreSame(row, JAdESBaselineLevelTable.FindByRequirementId(row.RequirementId),
                $"Looking up '{row.RequirementId}' must resolve to the exact registered row instance.");
        }

        Assert.IsNull(JAdESBaselineLevelTable.FindByRequirementId("JA-6.3-99"), "An unregistered requirement identifier must resolve to null.");
    }


    /// <summary>A representative level-invariant row (<c>alg</c>) exposes the same presence and cardinality at every baseline level.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.2.2-11, JA-6.2.2-16, JA-6.2.2-24, JA-6.2.2-28, JA-6.3-05.
    /// </remarks>
    [TestMethod]
    public void AlgIsMandatoryAndSingleValuedAtEveryLevel()
    {
        AdESTableRow alg = JAdESBaselineLevelTable.Alg;

        foreach(AdESBaselineLevel level in AdESBaselineLevels.All)
        {
            Assert.AreEqual(AdESPresence.ShallBePresent, alg.Presence.At(level), $"alg must be ShallBePresent at {level}.");
            Assert.AreSequenceEqual(new[] { AdESCardinality.ExactlyOne }, alg.Cardinality!.ValuesAt(level).ToArray(), $"alg's cardinality at {level} must be exactly one.");
        }

        Assert.AreEqual(AdESTableRowKind.HeaderParameter, alg.Kind);
        Assert.IsInstanceOfType<AdESInternalClauseReference>(alg.Reference);
        Assert.AreEqual("5.1.2", ((AdESInternalClauseReference)alg.Reference!).Clause);
    }


    /// <summary>
    /// <see cref="AdESPresence.ShouldNotBePresent"/> (Table 1's "*") and <see cref="AdESPresence.ShallNotBePresent"/>
    /// are two distinct enum members, both exercised by registered rows, never collapsed into one value.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.2.2-17, JA-6.2.2-21.
    /// </remarks>
    [TestMethod]
    public void ShouldNotBePresentIsTypeLevelDistinguishableFromShallNotBePresent()
    {
        Assert.HasCount(6, Enum.GetValues<AdESPresence>(), "Clause 6.2.2 declares exactly six presence constants (JA-6.2.2-16..21), including the '*' soft-negative and the hard 'shall not be present' exclusion.");
        Assert.HasCount(6, Enum.GetValues<AdESPresence>().Distinct(), "None of the six declared presence constants may alias another's underlying value.");

        //sigTst at B-B is the soft "*" - a component that upper levels still make mandatory.
        Assert.AreEqual(AdESPresence.ShouldNotBePresent, JAdESBaselineLevelTable.SigTst.Presence.At(AdESBaselineLevel.BB));

        //xRefs at B-LT/B-LTA is the hard exclusion - a component that must be stripped, never re-added.
        Assert.AreEqual(AdESPresence.ShallNotBePresent, JAdESBaselineLevelTable.XRefs.Presence.At(AdESBaselineLevel.BLT));
        Assert.AreEqual(AdESPresence.ShallNotBePresent, JAdESBaselineLevelTable.XRefs.Presence.At(AdESBaselineLevel.BLTA));
    }


    /// <summary>
    /// The four <c>refs</c>-family value rows (<c>xRefs</c>, <c>axRefs</c>, <c>rRefs</c>, <c>arRefs</c>) and the
    /// two time-stamp rows (<c>sigRTst</c>, <c>rfsTst</c>) share the identical level-split cardinality shape:
    /// B-B/B-T carry the row's own stated non-zero value, B-LT/B-LTA are exactly zero, and B-LT/B-LTA presence
    /// hard-forbids the row.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.2.2-23.
    /// </remarks>
    [TestMethod]
    public void RefsFamilyRowsShareTheSameLevelSplitCardinalityShape()
    {
        AssertLevelSplit(JAdESBaselineLevelTable.XRefs, AdESCardinality.ZeroOrOne);
        AssertLevelSplit(JAdESBaselineLevelTable.AxRefs, AdESCardinality.ZeroOrOne);
        AssertLevelSplit(JAdESBaselineLevelTable.RRefs, AdESCardinality.ZeroOrOne);
        AssertLevelSplit(JAdESBaselineLevelTable.ArRefs, AdESCardinality.ZeroOrOne);
        AssertLevelSplit(JAdESBaselineLevelTable.SigRTst, AdESCardinality.ZeroOrMore);
        AssertLevelSplit(JAdESBaselineLevelTable.RfsTst, AdESCardinality.ZeroOrMore);

        static void AssertLevelSplit(AdESTableRow row, AdESCardinality earlyCardinality)
        {
            Assert.AreSequenceEqual(new[] { earlyCardinality }, row.Cardinality!.ValuesAt(AdESBaselineLevel.BB).ToArray(), $"{row.RequirementId} at B-B.");
            Assert.AreSequenceEqual(new[] { earlyCardinality }, row.Cardinality!.ValuesAt(AdESBaselineLevel.BT).ToArray(), $"{row.RequirementId} at B-T.");
            Assert.AreSequenceEqual(new[] { AdESCardinality.ExactlyZero }, row.Cardinality!.ValuesAt(AdESBaselineLevel.BLT).ToArray(), $"{row.RequirementId} at B-LT.");
            Assert.AreSequenceEqual(new[] { AdESCardinality.ExactlyZero }, row.Cardinality!.ValuesAt(AdESBaselineLevel.BLTA).ToArray(), $"{row.RequirementId} at B-LTA.");

            Assert.AreEqual(AdESPresence.ShouldNotBePresent, row.Presence.At(AdESBaselineLevel.BB));
            Assert.AreEqual(AdESPresence.ShouldNotBePresent, row.Presence.At(AdESBaselineLevel.BT));
            Assert.AreEqual(AdESPresence.ShallNotBePresent, row.Presence.At(AdESBaselineLevel.BLT));
            Assert.AreEqual(AdESPresence.ShallNotBePresent, row.Presence.At(AdESBaselineLevel.BLTA));
        }
    }


    /// <summary>
    /// <c>sigTst</c>'s cardinality is a single two-part cell (B-B ≥ 0, B-T/B-LT/B-LTA ≥ 1) — two statements,
    /// never a duplicated third/fourth line the way CB-AdES's own <c>sigTst</c> row prints one.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.2.2-22.
    /// </remarks>
    [TestMethod]
    public void SigTstCardinalityIsATwoPartLevelSplitWithNoDuplicateLine()
    {
        AdESRowCardinality cardinality = JAdESBaselineLevelTable.SigTst.Cardinality!;

        Assert.HasCount(2, cardinality.Statements, "sigTst's Table 1 cell states exactly two cardinality sub-lines.");
        Assert.AreSequenceEqual(new[] { AdESCardinality.ZeroOrMore }, cardinality.ValuesAt(AdESBaselineLevel.BB).ToArray(), "sigTst at B-B: >=0.");
        Assert.AreSequenceEqual(new[] { AdESCardinality.OneOrMore }, cardinality.ValuesAt(AdESBaselineLevel.BT).ToArray(), "sigTst at B-T: >=1.");
        Assert.AreSequenceEqual(new[] { AdESCardinality.OneOrMore }, cardinality.ValuesAt(AdESBaselineLevel.BLT).ToArray(), "sigTst at B-LT: >=1 (cumulative, unchanged).");
        Assert.AreSequenceEqual(new[] { AdESCardinality.OneOrMore }, cardinality.ValuesAt(AdESBaselineLevel.BLTA).ToArray(), "sigTst at B-LTA: >=1 (cumulative, unchanged).");
    }


    /// <summary><c>sigTst</c>'s presence is "*" only at B-B, and mandatory from B-T onward.</summary>
    [TestMethod]
    public void SigTstPresenceIsSoftNegativeAtBBAndMandatoryFromBTOnward()
    {
        AdESRowPresence presence = JAdESBaselineLevelTable.SigTst.Presence;

        Assert.AreEqual(AdESPresence.ShouldNotBePresent, presence.At(AdESBaselineLevel.BB));
        Assert.AreEqual(AdESPresence.ShallBePresent, presence.At(AdESBaselineLevel.BT));
        Assert.AreEqual(AdESPresence.ShallBePresent, presence.At(AdESBaselineLevel.BLT));
        Assert.AreEqual(AdESPresence.ShallBePresent, presence.At(AdESBaselineLevel.BLTA));
    }


    /// <summary><c>xVals</c>/<c>axVals</c>/<c>rVals</c>/<c>arVals</c>/<c>anyValData</c> carry a level-invariant cardinality despite their level-split presence.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.2.2-26.
    /// </remarks>
    [TestMethod]
    public void ValidationDataValueRowsCardinalityIsLevelInvariantDespiteLevelSplitPresence()
    {
        AssertLevelInvariantCardinalityDespiteLevelSplitPresence(JAdESBaselineLevelTable.XVals, AdESCardinality.ZeroOrOne);
        AssertLevelInvariantCardinalityDespiteLevelSplitPresence(JAdESBaselineLevelTable.AxVals, AdESCardinality.ZeroOrOne);
        AssertLevelInvariantCardinalityDespiteLevelSplitPresence(JAdESBaselineLevelTable.RVals, AdESCardinality.ZeroOrOne);
        AssertLevelInvariantCardinalityDespiteLevelSplitPresence(JAdESBaselineLevelTable.ArVals, AdESCardinality.ZeroOrOne);
        AssertLevelInvariantCardinalityDespiteLevelSplitPresence(JAdESBaselineLevelTable.AnyValData, AdESCardinality.ZeroOrMore);

        static void AssertLevelInvariantCardinalityDespiteLevelSplitPresence(AdESTableRow row, AdESCardinality expected)
        {
            Assert.HasCount(1, row.Cardinality!.Statements, $"{row.RequirementId} carries a single row-wide cardinality statement.");
            foreach(AdESBaselineLevel level in AdESBaselineLevels.All)
            {
                Assert.AreSequenceEqual(new[] { expected }, row.Cardinality.ValuesAt(level).ToArray());
            }

            Assert.AreEqual(AdESPresence.ShouldNotBePresent, row.Presence.At(AdESBaselineLevel.BB));
            Assert.AreEqual(AdESPresence.ShouldNotBePresent, row.Presence.At(AdESBaselineLevel.BT));
            Assert.AreEqual(AdESPresence.ConditionedPresence, row.Presence.At(AdESBaselineLevel.BLT));
            Assert.AreEqual(AdESPresence.ConditionedPresence, row.Presence.At(AdESBaselineLevel.BLTA));
        }
    }


    /// <summary><c>arcTst</c> is B-LTA-exclusive and mandatory once reached, with a level-invariant "one or more" cardinality.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.2.2-27.
    /// </remarks>
    [TestMethod]
    public void ArcTstIsBLtaExclusiveAndMandatoryOnceReached()
    {
        AdESTableRow arcTst = JAdESBaselineLevelTable.ArcTst;

        Assert.AreEqual(AdESPresence.ShouldNotBePresent, arcTst.Presence.At(AdESBaselineLevel.BB));
        Assert.AreEqual(AdESPresence.ShouldNotBePresent, arcTst.Presence.At(AdESBaselineLevel.BT));
        Assert.AreEqual(AdESPresence.ShouldNotBePresent, arcTst.Presence.At(AdESBaselineLevel.BLT));
        Assert.AreEqual(AdESPresence.ShallBePresent, arcTst.Presence.At(AdESBaselineLevel.BLTA));

        foreach(AdESBaselineLevel level in AdESBaselineLevels.All)
        {
            Assert.AreSequenceEqual(new[] { AdESCardinality.OneOrMore }, arcTst.Cardinality!.ValuesAt(level).ToArray());
        }
    }


    /// <summary>
    /// <see cref="JAdESBaselineLevelTable.SigningCertificateReferenceService"/> groups its three literally
    /// "SPO:"-prefixed rows, resolvable through <see cref="JAdESBaselineLevelTable.ServiceProvisionOptionsFor"/>.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.2.2-03, JA-6.2.2-04, JA-6.2.2-06, JA-6.2.2-09, JA-6.2.2-10, JA-6.3-14,
    /// JA-6.3-15, JA-6.3-16, JA-6.3-17, JA-6.3-30.
    /// </remarks>
    [TestMethod]
    public void SigningCertificateReferenceServiceGroupsItsThreeServiceProvisionOptionRows()
    {
        AdESTableRow service = JAdESBaselineLevelTable.SigningCertificateReferenceService;

        Assert.IsTrue(JAdESBaselineLevelTable.IsServiceRow(service));
        Assert.IsFalse(JAdESBaselineLevelTable.IsServiceProvisionOptionRow(service));
        Assert.IsNotNull(service.Cardinality, "Unlike CB-AdES's own service rows, JA-6.3-14's Cardinality column states an actual value ('1'), not '-'.");
        Assert.AreSequenceEqual(new[] { AdESCardinality.ExactlyOne }, service.Cardinality!.ValuesAt(AdESBaselineLevel.BB).ToArray());
        Assert.IsNull(service.Reference, "JA-6.3-14's References column is '-'.");

        IReadOnlyList<AdESTableRow> options = JAdESBaselineLevelTable.ServiceProvisionOptionsFor(service);
        Assert.HasCount(3, options, "The service is satisfied by exactly three SPO rows (JA-6.3-15..17).");
        Assert.AreSame(JAdESBaselineLevelTable.X5tHashS256Option, options[0]);
        Assert.AreSame(JAdESBaselineLevelTable.X5tHashOOption, options[1]);
        Assert.AreSame(JAdESBaselineLevelTable.SigX5tsOption, options[2]);

        foreach(AdESTableRow option in options)
        {
            Assert.IsTrue(JAdESBaselineLevelTable.IsServiceProvisionOptionRow(option));
            Assert.IsFalse(JAdESBaselineLevelTable.IsServiceRow(option));
        }
    }


    /// <summary>
    /// <see cref="JAdESBaselineLevelTable.ValidationDataForTimestampsService"/> groups its three literally
    /// "SPO:"-prefixed rows.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.2.2-05, JA-6.2.2-19, JA-6.3-39.
    /// </remarks>
    [TestMethod]
    public void ValidationDataForTimestampsServiceGroupsItsThreeServiceProvisionOptionRows()
    {
        AdESTableRow service = JAdESBaselineLevelTable.ValidationDataForTimestampsService;

        Assert.IsTrue(JAdESBaselineLevelTable.IsServiceRow(service));
        Assert.IsNull(service.Cardinality, "JA-6.3-38's Cardinality column is '-' (n/a, service row).");
        Assert.IsNull(service.Reference, "JA-6.3-38's References column is '-'.");

        Assert.AreEqual(AdESPresence.ShouldNotBePresent, service.Presence.At(AdESBaselineLevel.BB));
        Assert.AreEqual(AdESPresence.ShouldNotBePresent, service.Presence.At(AdESBaselineLevel.BT));
        Assert.AreEqual(AdESPresence.ShallBeProvided, service.Presence.At(AdESBaselineLevel.BLT));
        Assert.AreEqual(AdESPresence.ShallBeProvided, service.Presence.At(AdESBaselineLevel.BLTA));

        IReadOnlyList<AdESTableRow> options = JAdESBaselineLevelTable.ServiceProvisionOptionsFor(service);
        Assert.HasCount(3, options, "The service is satisfied by exactly three SPO rows (JA-6.3-39..41).");
        Assert.AreSame(JAdESBaselineLevelTable.TstVdOption, options[0]);
        Assert.AreSame(JAdESBaselineLevelTable.EmbeddedValidationDataOption, options[1]);
        Assert.AreSame(JAdESBaselineLevelTable.AnyValDataOption, options[2]);
    }


    /// <summary>
    /// <see cref="JAdESBaselineLevelTable.SigningTimeService"/> is a service row whose two satisfying children
    /// (<c>iat</c>/<c>sigT</c>) print with no "SPO:" column-1 prefix — <see cref="AdESTableRow.ServiceProvisionOptionRequirementIds"/>
    /// is <see langword="null"/>, and resolving its SPOs therefore throws.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.3-11.
    /// </remarks>
    [TestMethod]
    public void SigningTimeServiceHasNoRegisteredServiceProvisionOptionChildren()
    {
        AdESTableRow service = JAdESBaselineLevelTable.SigningTimeService;

        Assert.IsTrue(JAdESBaselineLevelTable.IsServiceRow(service));
        Assert.IsNull(service.ServiceProvisionOptionRequirementIds);
        Assert.IsNull(service.Cardinality);
        Assert.IsNull(service.Reference);

        Assert.ThrowsExactly<ArgumentException>(() => JAdESBaselineLevelTable.ServiceProvisionOptionsFor(service));

        //iat and sigT are ordinary HeaderParameter rows, per Table 1's own column-1 convention.
        Assert.AreEqual(AdESTableRowKind.HeaderParameter, JAdESBaselineLevelTable.IssuedAt.Kind);
        Assert.AreEqual(AdESTableRowKind.HeaderParameter, JAdESBaselineLevelTable.SigT.Kind);
    }


    /// <summary><see cref="JAdESBaselineLevelTable.ServiceProvisionOptionsFor"/> refuses a non-service row.</summary>
    [TestMethod]
    public void ServiceProvisionOptionsForRejectsANonServiceRow() =>
        Assert.ThrowsExactly<ArgumentException>(() => JAdESBaselineLevelTable.ServiceProvisionOptionsFor(JAdESBaselineLevelTable.Alg));


    /// <summary>
    /// Every row's lettered-requirement and note annotations exactly match Table 1's own per-row annotation
    /// list — spot-checked across every row that carries at least one annotation, plus a handful that carry
    /// none.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.2.2-29, JA-6.3-12, JA-6.3-13.
    /// </remarks>
    [TestMethod]
    public void AnnotationsMatchTheLegFourReportForEveryAnnotatedRow()
    {
        AssertAnnotations(JAdESBaselineLevelTable.Alg, [], []);
        AssertAnnotations(JAdESBaselineLevelTable.ContentType, [], [2]);
        AssertAnnotations(JAdESBaselineLevelTable.X5Chain, [], [3]);
        AssertAnnotations(JAdESBaselineLevelTable.Crit, [], [4]);
        AssertAnnotations(JAdESBaselineLevelTable.IssuedAt, ["a"], []);
        AssertAnnotations(JAdESBaselineLevelTable.SigT, ["a"], []);
        AssertAnnotations(JAdESBaselineLevelTable.SigningCertificateReferenceService, [], [3]);
        AssertAnnotations(JAdESBaselineLevelTable.SrCms, [], [5]);
        AssertAnnotations(JAdESBaselineLevelTable.AdoTst, [], [6]);
        AssertAnnotations(JAdESBaselineLevelTable.SigPSt, ["b"], []);
        AssertAnnotations(JAdESBaselineLevelTable.SigTst, ["c", "d"], [7]);
        AssertAnnotations(JAdESBaselineLevelTable.XVals, ["e"], []);
        AssertAnnotations(JAdESBaselineLevelTable.AnyValData, ["e", "i"], []);
        AssertAnnotations(JAdESBaselineLevelTable.XRefs, ["f", "g"], []);
        AssertAnnotations(JAdESBaselineLevelTable.AxRefs, ["f", "g", "h"], []);
        AssertAnnotations(JAdESBaselineLevelTable.RVals, ["i"], []);
        AssertAnnotations(JAdESBaselineLevelTable.RRefs, [], []);
        AssertAnnotations(JAdESBaselineLevelTable.ArRefs, ["h"], []);
        AssertAnnotations(JAdESBaselineLevelTable.SigRTst, [], []);
        AssertAnnotations(JAdESBaselineLevelTable.RfsTst, [], []);
        AssertAnnotations(JAdESBaselineLevelTable.ValidationDataForTimestampsService, ["j", "k"], [8]);
        AssertAnnotations(JAdESBaselineLevelTable.AnyValDataOption, ["j", "k"], []);
        AssertAnnotations(JAdESBaselineLevelTable.ArcTst, ["l", "m"], []);

        static void AssertAnnotations(AdESTableRow row, string[] expectedLetters, int[] expectedNotes)
        {
            Assert.AreSequenceEqual(expectedLetters, row.Annotations.RequirementLetters.ToArray(), $"{row.RequirementId} requirement letters.");
            Assert.AreSequenceEqual(expectedNotes, row.Annotations.NoteNumbers.ToArray(), $"{row.RequirementId} note numbers.");
        }
    }


    /// <summary>Every one of the thirteen lettered additional requirements a)-m) appears on at least one registered row.</summary>
    [TestMethod]
    public void EveryLetteredRequirementFromAThroughMAppearsOnAtLeastOneRow()
    {
        var seenLetters = new HashSet<string>(StringComparer.Ordinal);
        foreach(AdESTableRow row in JAdESBaselineLevelTable.Rows)
        {
            foreach(string letter in row.Annotations.RequirementLetters)
            {
                seenLetters.Add(letter);
            }
        }

        string[] expectedLetters = "abcdefghijklm".Select(c => c.ToString()).ToArray();
        Assert.AreSequenceEqual(expectedLetters, seenLetters.ToArray(), SequenceOrder.InAnyOrder, "Clause 6.3 defines exactly thirteen lettered additional requirements, a) through m).");
    }


    /// <summary>
    /// <see cref="AdESTableRow.Cardinality"/> is null for exactly the two rows Table 1 marks "-"
    /// (<see cref="JAdESBaselineLevelTable.SigningTimeService"/>, <see cref="JAdESBaselineLevelTable.ValidationDataForTimestampsService"/>),
    /// and non-null for every other row — including <see cref="JAdESBaselineLevelTable.SigningCertificateReferenceService"/>,
    /// whose own Cardinality column states an actual value.
    /// </summary>
    [TestMethod]
    public void CardinalityIsNullOnlyForTheTwoDashServiceRows()
    {
        var expectedNullCardinalityIds = new HashSet<string>(StringComparer.Ordinal) { "JA-6.3-11", "JA-6.3-38" };

        foreach(AdESTableRow row in JAdESBaselineLevelTable.Rows)
        {
            bool expectNull = expectedNullCardinalityIds.Contains(row.RequirementId);
            Assert.AreEqual(expectNull, row.Cardinality is null, $"{row.RequirementId}: Cardinality must be null iff Table 1 marks it '-'.");
        }
    }


    /// <summary>
    /// <see cref="AdESTableRow.Reference"/> is null for exactly the four rows Table 1 marks "-" in the
    /// References column, and non-null for every other row.
    /// </summary>
    [TestMethod]
    public void ReferenceIsNullOnlyForTheDocumentedDashRows()
    {
        var expectedNullReferenceIds = new HashSet<string>(StringComparer.Ordinal) { "JA-6.3-11", "JA-6.3-14", "JA-6.3-38", "JA-6.3-40" };

        foreach(AdESTableRow row in JAdESBaselineLevelTable.Rows)
        {
            bool expectNull = expectedNullReferenceIds.Contains(row.RequirementId);
            Assert.AreEqual(expectNull, row.Reference is null, $"{row.RequirementId}: Reference nullability must match Table 1's References column.");
        }
    }


    /// <summary>The registry's row-kind split matches the 8/21/3/6 count this library's implementation record documents.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.2.2-02, JA-6.2.2-08.
    /// </remarks>
    [TestMethod]
    public void RowKindCountsMatchTheDocumentedEightTwentyOneThreeSixSplit()
    {
        Assert.AreEqual(8, JAdESBaselineLevelTable.Rows.Count(row => row.Kind == AdESTableRowKind.HeaderParameter));
        Assert.AreEqual(21, JAdESBaselineLevelTable.Rows.Count(row => row.Kind == AdESTableRowKind.Component));
        Assert.AreEqual(3, JAdESBaselineLevelTable.Rows.Count(row => row.Kind == AdESTableRowKind.Service));
        Assert.AreEqual(6, JAdESBaselineLevelTable.Rows.Count(row => row.Kind == AdESTableRowKind.ServiceProvisionOption));
    }


    /// <summary><see cref="AdESRowPresence.Uniform"/> applies the same value at all four levels.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.2.2-18.
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
    [TestMethod]
    public void UniformCardinalityAppliesTheSameValueAtAllFourLevels()
    {
        AdESRowCardinality cardinality = AdESRowCardinality.Uniform(AdESCardinality.ZeroOrOne);

        Assert.HasCount(1, cardinality.Statements);
        Assert.AreEqual(AdESBaselineLevelSet.All, cardinality.Statements[0].Levels);
        foreach(AdESBaselineLevel level in AdESBaselineLevels.All)
        {
            Assert.AreSequenceEqual(new[] { AdESCardinality.ZeroOrOne }, cardinality.ValuesAt(level).ToArray());
        }
    }


    /// <summary><see cref="AdESBaselineLevelSet"/> membership round-trips through <see cref="AdESBaselineLevels.ToLevelSet"/> for every level.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf">
    /// ETSI TS 119 182-1 V1.2.1</see> JA-6.1-04, JA-6.2.2-12, JA-6.2.2-13, JA-6.2.2-14, JA-6.2.2-15.
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
}
