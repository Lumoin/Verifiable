using System;
using System.Collections.Generic;
using System.Linq;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Registry-integrity tests for <see cref="CBAdESBaselineLevelTable"/> — the CB-AdES Table 14 (clause 6.3)
/// baseline-level/presence/cardinality model shipped as COSE/CBOR-free data. These tests check the DATA the
/// registry carries against Table 14 (clause 6.3) itself — not creation, augmentation, or validation
/// behaviour, which compose this registry downstream.
/// </summary>
[TestClass]
internal sealed class CBAdESBaselineLevelTableTests
{
    /// <summary>The registry carries all 26 Table 14 rows (CB-6.3-04..29), each with a unique requirement identifier.</summary>
    [TestMethod]
    public void RegistryContainsExactlyTwentySixRowsWithUniqueRequirementIdentifiers()
    {
        Assert.HasCount(26, CBAdESBaselineLevelTable.Rows, "Table 14 has 26 distinct rows, counted directly against the published table.");

        var seenIds = new HashSet<string>(StringComparer.Ordinal);
        foreach(AdESTableRow row in CBAdESBaselineLevelTable.Rows)
        {
            Assert.IsTrue(seenIds.Add(row.RequirementId), $"Requirement identifier '{row.RequirementId}' must be unique across the registry.");
        }

        Assert.AreEqual("CB-6.3-04", CBAdESBaselineLevelTable.Rows[0].RequirementId, "The first row is alg (CB-6.3-04).");
        Assert.AreEqual("CB-6.3-29", CBAdESBaselineLevelTable.Rows[^1].RequirementId, "The last row is arcTst (CB-6.3-29).");
    }


    /// <summary>
    /// The 15 Table 14 rows minted — <c>CB-6.3-04..09</c>, <c>-11..17</c>, <c>-19..20</c> — each
    /// transcribed here as one (presence, cardinality, References-clause) triple read directly off the source
    /// table, independent of and cross-checked against this registry's own data, so each row's
    /// presence/cardinality/reference cell is proven against the specification's own text rather than only by the
    /// undifferentiated whole-registry check <see
    /// cref="RegistryContainsExactlyTwentySixRowsWithUniqueRequirementIdentifiers"/>.
    /// </summary>
    private static IEnumerable<object[]> NewTable14Rows
    {
        get
        {
            (string RequirementId, AdESPresence Presence, AdESCardinality Cardinality, string ReferenceClause)[] rows =
            [
                ("CB-6.3-04", AdESPresence.ShallBePresent, AdESCardinality.ExactlyOne, "5.1.2"),
                ("CB-6.3-05", AdESPresence.ConditionedPresence, AdESCardinality.ZeroOrOne, "5.1.3"),
                ("CB-6.3-06", AdESPresence.MayBePresent, AdESCardinality.ZeroOrOne, "5.1.4"),
                ("CB-6.3-07", AdESPresence.MayBePresent, AdESCardinality.ZeroOrOne, "5.1.5"),
                ("CB-6.3-08", AdESPresence.ConditionedPresence, AdESCardinality.ZeroOrOne, "5.1.8"),
                ("CB-6.3-09", AdESPresence.ConditionedPresence, AdESCardinality.ZeroOrOne, "5.1.10"),
                ("CB-6.3-11", AdESPresence.ConditionedPresence, AdESCardinality.ZeroOrOne, "5.1.7"),
                ("CB-6.3-12", AdESPresence.ConditionedPresence, AdESCardinality.ZeroOrOne, "5.2.2"),
                ("CB-6.3-13", AdESPresence.MayBePresent, AdESCardinality.ZeroOrOne, "5.2.8"),
                ("CB-6.3-14", AdESPresence.MayBePresent, AdESCardinality.ZeroOrOne, "5.2.5"),
                ("CB-6.3-15", AdESPresence.MayBePresent, AdESCardinality.ZeroOrOne, "5.2.3"),
                ("CB-6.3-16", AdESPresence.MayBePresent, AdESCardinality.ZeroOrOne, "5.2.4"),
                ("CB-6.3-17", AdESPresence.MayBePresent, AdESCardinality.ZeroOrOne, "5.2.7"),
                //Table 14's own printed References cell reads "5.3.2" (sigPSt's clause, the copy-paste
                //origin) rather than adoTst's own defining clause 5.2.6; transcribed here as PRINTED, per this
                //registry's own transcription discipline (reading "5.2.6" here would be a reading
                //correction, not a change to the data recorded).
                ("CB-6.3-19", AdESPresence.MayBePresent, AdESCardinality.ZeroOrOne, "5.3.2"),
                ("CB-6.3-20", AdESPresence.ConditionedPresence, AdESCardinality.ZeroOrOne, "5.3.2")
            ];

            foreach((string requirementId, AdESPresence presence, AdESCardinality cardinality, string referenceClause) in rows)
            {
                yield return [requirementId, presence, cardinality, referenceClause];
            }
        }
    }


    /// <summary>
    /// Asserts one Table 14 row's presence-per-level, cardinality-per-level, and References clause against its
    /// spec-transcribed expected values.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">ETSI TS 119 152-1 V1.1.1</see>
    /// CB-6.3-04, CB-6.3-05, CB-6.3-06, CB-6.3-07, CB-6.3-08, CB-6.3-09, CB-6.3-11, CB-6.3-12, CB-6.3-13,
    /// CB-6.3-14, CB-6.3-15, CB-6.3-16, CB-6.3-17, CB-6.3-19, CB-6.3-20.
    /// </remarks>
    /// <param name="requirementId">The row's requirement identifier.</param>
    /// <param name="expectedPresence">The presence value the source table states, uniform across all 4 levels for every one of these 15 rows.</param>
    /// <param name="expectedCardinality">The cardinality value the source table states, likewise uniform.</param>
    /// <param name="expectedReferenceClause">The References column's clause, as printed.</param>
    [TestMethod]
    [DynamicData(nameof(NewTable14Rows))]
    public void NewTable14RowMatchesItsSpecTranscribedPresenceCardinalityAndReference(
        string requirementId, AdESPresence expectedPresence, AdESCardinality expectedCardinality, string expectedReferenceClause)
    {
        AdESTableRow? row = CBAdESBaselineLevelTable.FindByRequirementId(requirementId);
        Assert.IsNotNull(row, $"'{requirementId}' must be a registered Table 14 row.");

        foreach(AdESBaselineLevel level in AdESBaselineLevels.All)
        {
            Assert.AreEqual(expectedPresence, row.Presence.At(level), $"{requirementId} ({row.Name}) presence at {level}.");
            Assert.AreSequenceEqual([expectedCardinality], row.Cardinality!.ValuesAt(level).ToArray(), $"{requirementId} ({row.Name}) cardinality at {level}.");
        }

        Assert.IsInstanceOfType<AdESInternalClauseReference>(row.Reference);
        Assert.AreEqual(expectedReferenceClause, ((AdESInternalClauseReference)row.Reference!).Clause, $"{requirementId} ({row.Name}) References clause.");
    }


    /// <summary><see cref="CBAdESBaselineLevelTable.FindByRequirementId"/> resolves every registered row by identity, and returns null for an unregistered identifier.</summary>
    [TestMethod]
    public void FindByRequirementIdResolvesEveryRegisteredRowAndOnlyRegisteredRows()
    {
        foreach(AdESTableRow row in CBAdESBaselineLevelTable.Rows)
        {
            Assert.AreSame(row, CBAdESBaselineLevelTable.FindByRequirementId(row.RequirementId),
                $"Looking up '{row.RequirementId}' must resolve to the exact registered row instance.");
        }

        Assert.IsNull(CBAdESBaselineLevelTable.FindByRequirementId("CB-6.3-99"), "An unregistered requirement identifier must resolve to null.");
    }


    /// <summary>
    /// A representative level-invariant row (<c>alg</c>) exposes the same presence and cardinality at every
    /// baseline level.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">ETSI TS 119 152-1 V1.1.1</see>
    /// CB-6.2.2-03, CB-6.2.2-10, CB-6.3-04.
    /// </remarks>
    [TestMethod]
    public void AlgIsMandatoryAndSingleValuedAtEveryLevel()
    {
        AdESTableRow alg = CBAdESBaselineLevelTable.Alg;

        foreach(AdESBaselineLevel level in AdESBaselineLevels.All)
        {
            Assert.AreEqual(AdESPresence.ShallBePresent, alg.Presence.At(level), $"alg must be ShallBePresent at {level}.");
            Assert.AreSequenceEqual(new[] { AdESCardinality.ExactlyOne }, alg.Cardinality!.ValuesAt(level).ToArray(), $"alg's cardinality at {level} must be exactly one.");
        }

        Assert.AreEqual(AdESTableRowKind.HeaderParameter, alg.Kind);
        Assert.IsInstanceOfType<AdESInternalClauseReference>(alg.Reference);
        Assert.AreEqual("5.1.2", ((AdESInternalClauseReference)alg.Reference!).Clause);
    }


    /// <summary>The single-element condition-clause array every tri-way row's <see cref="AdESTableRow.PresenceConditionClauses"/> is compared against, held once (CA1861) since the same literal is asserted repeatedly.</summary>
    private static string[] TriWayConditionClause { get; } = ["5.2.2"];


    /// <summary>A representative conditioned-presence row (<c>x5chain</c>) records condition clause distinct from its own References clause.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">ETSI TS 119 152-1 V1.1.1</see>
    /// CB-6.2.2-07, CB-6.3-08, CB-6.3-11, CB-6.3-12.
    /// </remarks>
    [TestMethod]
    public void X5ChainRecordsItsConditionClauseSeparatelyFromItsOwnReferenceClauseTrap2()
    {
        AdESTableRow x5chain = CBAdESBaselineLevelTable.X5Chain;

        Assert.AreEqual(AdESPresence.ConditionedPresence, x5chain.Presence.At(AdESBaselineLevel.BB));
        Assert.AreEqual("5.1.8", ((AdESInternalClauseReference)x5chain.Reference!).Clause, "x5chain's own References clause is 5.1.8.");
        Assert.AreSequenceEqual(TriWayConditionClause, x5chain.PresenceConditionClauses!.ToArray(), "x5chain's presence CONDITION lives in clause 5.2.2 (note 3), not its own References clause.");

        //x5t and x5ts are part of the same tri-way condition group: all three cite 5.2.2 as the condition clause.
        Assert.AreSequenceEqual(TriWayConditionClause, CBAdESBaselineLevelTable.X5T.PresenceConditionClauses!.ToArray());
        Assert.AreSequenceEqual(TriWayConditionClause, CBAdESBaselineLevelTable.X5Ts.PresenceConditionClauses!.ToArray());
    }


    /// <summary>
    /// <see cref="AdESPresence.ShouldNotBePresent"/> (Table 14's "*") and <see cref="AdESPresence.ShallNotBePresent"/>
    /// are two distinct enum members, both exercised by registered rows, never collapsed into one value.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">ETSI TS 119 152-1 V1.1.1</see>
    /// CB-6.2.2-04, CB-6.2.2-08.
    /// </remarks>
    [TestMethod]
    public void ShouldNotBePresentIsTypeLevelDistinguishableFromShallNotBePresent()
    {
        // Two guards, each pinning its own half of the claim above. A pairwise Assert.AreNotEqual on two named enum
        // members is a compile-time-constant comparison (MSTEST0032 flags it as always-true), so neither half
        // below is provable that way. Half one: the declared-constant count -- exactly six presence members
        // are defined at all, so a seventh, ALIASING member added later is caught even though it introduces no
        // new underlying value.
        Assert.HasCount(6, Enum.GetValues<AdESPresence>(), "Clause 6.2.2 declares exactly six presence constants (CB-6.2.2-03..08), including the '*' soft-negative and the hard 'shall not be present' exclusion.");

        //Half two: the distinct-value count -- no two of those six declared constants may alias the same
        //underlying value.
        Assert.HasCount(6, Enum.GetValues<AdESPresence>().Distinct(), "None of the six declared presence constants may alias another's underlying value.");

        //sigTst at B-B is the soft "*" - a component that upper levels still make mandatory.
        Assert.AreEqual(AdESPresence.ShouldNotBePresent, CBAdESBaselineLevelTable.SigTst.Presence.At(AdESBaselineLevel.BB));

        //refs at B-LT/B-LTA is the hard exclusion - a component that must be stripped, never re-added.
        Assert.AreEqual(AdESPresence.ShallNotBePresent, CBAdESBaselineLevelTable.Refs.Presence.At(AdESBaselineLevel.BLT));
        Assert.AreEqual(AdESPresence.ShallNotBePresent, CBAdESBaselineLevelTable.Refs.Presence.At(AdESBaselineLevel.BLTA));
    }


    /// <summary>
    /// The three Annex A B-B/B-T-only rows (<c>refs</c>, <c>sigRTst</c>, <c>rfsTst</c>) share the identical
    /// level-split cardinality shape: zero-or-more at B-B/B-T, exactly zero at B-LT/B-LTA.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">ETSI TS 119 152-1 V1.1.1</see>
    /// CB-6.2.2-04, CB-6.2.2-09, CB-6.3-23, CB-6.3-24, CB-6.3-25.
    /// </remarks>
    [TestMethod]
    public void RefsSigRTstAndRfsTstShareTheSameLevelSplitCardinalityShape()
    {
        foreach(AdESTableRow row in new[] { CBAdESBaselineLevelTable.Refs, CBAdESBaselineLevelTable.SigRTst, CBAdESBaselineLevelTable.RfsTst })
        {
            Assert.AreSequenceEqual(new[] { AdESCardinality.ZeroOrMore }, row.Cardinality!.ValuesAt(AdESBaselineLevel.BB).ToArray(), $"{row.RequirementId} at B-B.");
            Assert.AreSequenceEqual(new[] { AdESCardinality.ZeroOrMore }, row.Cardinality!.ValuesAt(AdESBaselineLevel.BT).ToArray(), $"{row.RequirementId} at B-T.");
            Assert.AreSequenceEqual(new[] { AdESCardinality.ExactlyZero }, row.Cardinality!.ValuesAt(AdESBaselineLevel.BLT).ToArray(), $"{row.RequirementId} at B-LT.");
            Assert.AreSequenceEqual(new[] { AdESCardinality.ExactlyZero }, row.Cardinality!.ValuesAt(AdESBaselineLevel.BLTA).ToArray(), $"{row.RequirementId} at B-LTA.");

            Assert.AreEqual(AdESPresence.ShouldNotBePresent, row.Presence.At(AdESBaselineLevel.BB));
            Assert.AreEqual(AdESPresence.ShouldNotBePresent, row.Presence.At(AdESBaselineLevel.BT));
            Assert.AreEqual(AdESPresence.ShallNotBePresent, row.Presence.At(AdESBaselineLevel.BLT));
            Assert.AreEqual(AdESPresence.ShallNotBePresent, row.Presence.At(AdESBaselineLevel.BLTA));
        }
    }


    /// <summary>
    /// <c>sigTst</c>'s cardinality reproduces the source table's genuine duplicate "B-LT, B-LTA: 0" line
    /// verbatim rather than silently deduplicating it: four statements total, and <see
    /// cref="AdESRowCardinality.ValuesAt"/> at B-LT/B-LTA returns the cumulative "≥1" plus the incremental
    /// "0" TWICE.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">ETSI TS 119 152-1 V1.1.1</see>
    /// CB-6.2.2-09, CB-6.3-21.
    /// </remarks>
    [TestMethod]
    public void SigTstReproducesTheDuplicatedD2CardinalityLineWithoutDeduplication()
    {
        AdESRowCardinality cardinality = CBAdESBaselineLevelTable.SigTst.Cardinality!;

        Assert.HasCount(4, cardinality.Statements, "sigTst's Table 14 cell stacks four cardinality sub-lines, including one genuine duplicate.");

        Assert.AreSequenceEqual(new[] { AdESCardinality.ZeroOrMore }, cardinality.ValuesAt(AdESBaselineLevel.BB).ToArray(), "sigTst at B-B: the cumulative '*'-adjacent reading is >=0.");
        Assert.AreSequenceEqual(new[] { AdESCardinality.OneOrMore }, cardinality.ValuesAt(AdESBaselineLevel.BT).ToArray(), "sigTst at B-T: the cumulative reading is >=1.");

        //At B-LT and B-LTA, the cumulative >=1 statement AND the duplicated incremental "0" statement both apply - not deduplicated.
        Assert.AreSequenceEqual(
            new[] { AdESCardinality.OneOrMore, AdESCardinality.ExactlyZero, AdESCardinality.ExactlyZero },
            cardinality.ValuesAt(AdESBaselineLevel.BLT).ToArray(),
            "sigTst at B-LT must reproduce the cumulative statement plus the duplicated 'zero new instances' statement twice.");
        Assert.AreSequenceEqual(
            new[] { AdESCardinality.OneOrMore, AdESCardinality.ExactlyZero, AdESCardinality.ExactlyZero },
            cardinality.ValuesAt(AdESBaselineLevel.BLTA).ToArray(),
            "sigTst at B-LTA must reproduce the cumulative statement plus the duplicated 'zero new instances' statement twice.");

        //The two duplicate statements are equal in value (same record equality), confirming the duplication is a genuine repeat, not two different readings.
        Assert.AreEqual(cardinality.Statements[2], cardinality.Statements[3], "The two duplicated sub-lines must carry identical level-set and value.");
    }


    /// <summary><c>sigTst</c>'s presence is "*" only at B-B, and mandatory from B-T onward.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">ETSI TS 119 152-1 V1.1.1</see>
    /// CB-6.2.2-08, CB-6.3-21.
    /// </remarks>
    [TestMethod]
    public void SigTstPresenceIsSoftNegativeAtBBAndMandatoryFromBTOnward()
    {
        AdESRowPresence presence = CBAdESBaselineLevelTable.SigTst.Presence;

        Assert.AreEqual(AdESPresence.ShouldNotBePresent, presence.At(AdESBaselineLevel.BB));
        Assert.AreEqual(AdESPresence.ShallBePresent, presence.At(AdESBaselineLevel.BT));
        Assert.AreEqual(AdESPresence.ShallBePresent, presence.At(AdESBaselineLevel.BLT));
        Assert.AreEqual(AdESPresence.ShallBePresent, presence.At(AdESBaselineLevel.BLTA));
    }


    /// <summary><c>valData</c> carries a single level-invariant cardinality despite its level-split presence.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">ETSI TS 119 152-1 V1.1.1</see>
    /// CB-6.2.2-07, CB-6.2.2-09, CB-6.3-22.
    /// </remarks>
    [TestMethod]
    public void ValDataCardinalityIsLevelInvariantDespiteLevelSplitPresence()
    {
        AdESTableRow valData = CBAdESBaselineLevelTable.ValData;

        Assert.HasCount(1, valData.Cardinality!.Statements, "valData carries a single row-wide cardinality statement, unlike the four level-split rows.");
        foreach(AdESBaselineLevel level in AdESBaselineLevels.All)
        {
            Assert.AreSequenceEqual(new[] { AdESCardinality.ZeroOrMore }, valData.Cardinality.ValuesAt(level).ToArray());
        }

        Assert.AreEqual(AdESPresence.ShouldNotBePresent, valData.Presence.At(AdESBaselineLevel.BB));
        Assert.AreEqual(AdESPresence.ShouldNotBePresent, valData.Presence.At(AdESBaselineLevel.BT));
        Assert.AreEqual(AdESPresence.ConditionedPresence, valData.Presence.At(AdESBaselineLevel.BLT));
        Assert.AreEqual(AdESPresence.ConditionedPresence, valData.Presence.At(AdESBaselineLevel.BLTA));
    }


    /// <summary><c>arcTst</c> is B-LTA-exclusive and mandatory once reached, with a level-invariant "one or more" cardinality.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">ETSI TS 119 152-1 V1.1.1</see>
    /// CB-6.2.2-09, CB-6.3-29.
    /// </remarks>
    [TestMethod]
    public void ArcTstIsBLtaExclusiveAndMandatoryOnceReached()
    {
        AdESTableRow arcTst = CBAdESBaselineLevelTable.ArcTst;

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
    /// The service row groups its two SPO rows, resolvable through <see cref="CBAdESBaselineLevelTable.ServiceProvisionOptionsFor"/>,
    /// with the documented OR-satisfaction (CB-6.3-h) and valData preference (CB-6.3-i) recorded as data.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">ETSI TS 119 152-1 V1.1.1</see>
    /// CB-6.2.2-01, CB-6.2.2-02, CB-6.2.2-06, CB-6.3-26.
    /// </remarks>
    [TestMethod]
    public void ServiceRowGroupsItsTwoServiceProvisionOptionRowsWithOrSatisfactionAndValDataPreference()
    {
        AdESTableRow service = CBAdESBaselineLevelTable.ValidationDataForTimestampsService;

        Assert.IsTrue(CBAdESBaselineLevelTable.IsServiceRow(service));
        Assert.IsFalse(CBAdESBaselineLevelTable.IsServiceProvisionOptionRow(service));
        Assert.IsNull(service.Cardinality, "A service row's Cardinality column is '-' (n/a, CB-6.3-26).");
        Assert.IsNull(service.Reference, "A service row's References column is '-' (CB-6.3-26).");

        // CB-6.3-26's own presence column: "*" (should-not) at B-B/B-T, shall-be-provided from B-LT onward --
        // the service obligation only starts once long-term validation data is required at all.
        Assert.AreEqual(AdESPresence.ShouldNotBePresent, service.Presence.At(AdESBaselineLevel.BB));
        Assert.AreEqual(AdESPresence.ShouldNotBePresent, service.Presence.At(AdESBaselineLevel.BT));
        Assert.AreEqual(AdESPresence.ShallBeProvided, service.Presence.At(AdESBaselineLevel.BLT));
        Assert.AreEqual(AdESPresence.ShallBeProvided, service.Presence.At(AdESBaselineLevel.BLTA));

        IReadOnlyList<AdESTableRow> options = CBAdESBaselineLevelTable.ServiceProvisionOptionsFor(service);
        Assert.HasCount(2, options, "The service is satisfied by exactly two SPO rows (CB-6.3-27/-28).");
        Assert.AreSame(CBAdESBaselineLevelTable.ValDataServiceProvisionOption, options[0]);
        Assert.AreSame(CBAdESBaselineLevelTable.EmbeddedValidationDataServiceProvisionOption, options[1]);

        foreach(AdESTableRow option in options)
        {
            Assert.IsTrue(CBAdESBaselineLevelTable.IsServiceProvisionOptionRow(option));
            Assert.IsFalse(CBAdESBaselineLevelTable.IsServiceRow(option));
        }

        Assert.AreEqual("CB-6.3-27", service.PreferredServiceProvisionOptionRequirementId, "CB-6.3-i: valData should be preferred over the embedded-in-TST SPO.");
    }


    /// <summary><see cref="CBAdESBaselineLevelTable.ServiceProvisionOptionsFor"/> refuses a non-service row.</summary>
    [TestMethod]
    public void ServiceProvisionOptionsForRejectsANonServiceRow() =>
        Assert.ThrowsExactly<ArgumentException>(() => CBAdESBaselineLevelTable.ServiceProvisionOptionsFor(CBAdESBaselineLevelTable.Alg));


    /// <summary>
    /// Every row's lettered-requirement and note annotations exactly match Table 14's own per-row
    /// annotation list (CB-6.2.2-11) — spot-checked across every row that carries at least one
    /// annotation, plus a handful that carry none.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">ETSI TS 119 152-1 V1.1.1</see>
    /// CB-6.3-05, CB-6.3-09, CB-6.3-11, CB-6.3-12, CB-6.3-15, CB-6.3-19, CB-6.3-20.
    /// </remarks>
    [TestMethod]
    public void AnnotationsMatchTheLegFourReportForEveryAnnotatedRow()
    {
        AssertAnnotations(CBAdESBaselineLevelTable.Alg, [], []);
        AssertAnnotations(CBAdESBaselineLevelTable.ContentType, [], [2]);
        AssertAnnotations(CBAdESBaselineLevelTable.X5Chain, [], [3]);
        AssertAnnotations(CBAdESBaselineLevelTable.Crit, [], [4]);
        AssertAnnotations(CBAdESBaselineLevelTable.CwtClaims, ["a"], []);
        AssertAnnotations(CBAdESBaselineLevelTable.X5T, [], [3]);
        AssertAnnotations(CBAdESBaselineLevelTable.X5Ts, [], [3]);
        AssertAnnotations(CBAdESBaselineLevelTable.SrCms, [], [5]);
        AssertAnnotations(CBAdESBaselineLevelTable.AdoTst, [], [6]);
        AssertAnnotations(CBAdESBaselineLevelTable.SigPSt, ["b"], []);
        AssertAnnotations(CBAdESBaselineLevelTable.SigTst, ["c", "d"], [7]);
        AssertAnnotations(CBAdESBaselineLevelTable.ValData, ["e", "f"], []);
        AssertAnnotations(CBAdESBaselineLevelTable.Refs, ["g"], []);
        AssertAnnotations(CBAdESBaselineLevelTable.SigRTst, [], []);
        AssertAnnotations(CBAdESBaselineLevelTable.RfsTst, [], []);
        AssertAnnotations(CBAdESBaselineLevelTable.ValidationDataForTimestampsService, ["h", "i"], [8]);
        AssertAnnotations(CBAdESBaselineLevelTable.ValDataServiceProvisionOption, [], []);
        AssertAnnotations(CBAdESBaselineLevelTable.EmbeddedValidationDataServiceProvisionOption, ["i"], []);
        AssertAnnotations(CBAdESBaselineLevelTable.ArcTst, ["j", "k"], []);

        static void AssertAnnotations(AdESTableRow row, string[] expectedLetters, int[] expectedNotes)
        {
            Assert.AreSequenceEqual(expectedLetters, row.Annotations.RequirementLetters.ToArray(), $"{row.RequirementId} requirement letters.");
            Assert.AreSequenceEqual(expectedNotes, row.Annotations.NoteNumbers.ToArray(), $"{row.RequirementId} note numbers.");
        }
    }


    /// <summary>Every one of the eleven lettered additional requirements (a)-(k) appears on at least one registered row.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">ETSI TS 119 152-1 V1.1.1</see>
    /// CB-6.2.2-11.
    /// </remarks>
    [TestMethod]
    public void EveryLetteredRequirementFromAThroughKAppearsOnAtLeastOneRow()
    {
        var seenLetters = new HashSet<string>(StringComparer.Ordinal);
        foreach(AdESTableRow row in CBAdESBaselineLevelTable.Rows)
        {
            foreach(string letter in row.Annotations.RequirementLetters)
            {
                seenLetters.Add(letter);
            }
        }

        string[] expectedLetters = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"];
        Assert.AreSequenceEqual(expectedLetters, seenLetters.ToArray(), SequenceOrder.InAnyOrder, "Clause 6.3 defines exactly eleven lettered additional requirements, a) through k).");
    }


    /// <summary>
    /// <see cref="AdESTableRow.Cardinality"/> is null for exactly the one service row Table 14 marks "-",
    /// and non-null for every other row.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">ETSI TS 119 152-1 V1.1.1</see>
    /// CB-6.3-06, CB-6.3-07, CB-6.3-13, CB-6.3-14, CB-6.3-16, CB-6.3-17.
    /// </remarks>
    [TestMethod]
    public void CardinalityIsNullOnlyForTheServiceRow()
    {
        foreach(AdESTableRow row in CBAdESBaselineLevelTable.Rows)
        {
            bool expectNull = row.Kind == AdESTableRowKind.Service;
            Assert.AreEqual(expectNull, row.Cardinality is null, $"{row.RequirementId}: Cardinality must be null iff the row is a service row.");
        }
    }


    /// <summary>
    /// <see cref="AdESTableRow.Reference"/> is null for exactly the rows Table 14 marks "-" in the
    /// References column (the service row and the embedded-in-TST SPO row), and non-null for every other row.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">ETSI TS 119 152-1 V1.1.1</see>
    /// CB-6.2.2-10, CB-6.3-05.
    /// </remarks>
    [TestMethod]
    public void ReferenceIsNullOnlyForTheDocumentedDashRows()
    {
        var expectedNullReferenceIds = new HashSet<string>(StringComparer.Ordinal) { "CB-6.3-26", "CB-6.3-28" };

        foreach(AdESTableRow row in CBAdESBaselineLevelTable.Rows)
        {
            bool expectNull = expectedNullReferenceIds.Contains(row.RequirementId);
            Assert.AreEqual(expectNull, row.Reference is null, $"{row.RequirementId}: Reference nullability must match Table 14's References column.");
        }
    }


    /// <summary>The registry's row-kind split matches the 10/13/1/2 count this library's implementation record documents.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">ETSI TS 119 152-1 V1.1.1</see>
    /// CB-6.2.2-01, CB-6.2.2-02.
    /// </remarks>
    [TestMethod]
    public void RowKindCountsMatchTheDocumentedTenThirteenOneTwoSplit()
    {
        Assert.AreEqual(10, CBAdESBaselineLevelTable.Rows.Count(row => row.Kind == AdESTableRowKind.HeaderParameter));
        Assert.AreEqual(13, CBAdESBaselineLevelTable.Rows.Count(row => row.Kind == AdESTableRowKind.Component));
        Assert.ContainsSingle(row => row.Kind == AdESTableRowKind.Service, CBAdESBaselineLevelTable.Rows);
        Assert.AreEqual(2, CBAdESBaselineLevelTable.Rows.Count(row => row.Kind == AdESTableRowKind.ServiceProvisionOption));
    }


    /// <summary><see cref="AdESRowPresence.Uniform"/> applies the same value at all four levels.</summary>
    /// <remarks>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">ETSI TS 119 152-1 V1.1.1</see>
    /// CB-6.2.2-05.
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
    /// Proves <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">ETSI TS 119 152-1 V1.1.1</see>
    /// CB-6.1-01.
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
