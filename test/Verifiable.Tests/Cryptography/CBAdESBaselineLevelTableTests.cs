using System;
using System.Collections.Generic;
using System.Linq;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Registry-integrity tests for <see cref="CBAdESBaselineLevelTable"/> — the CB-AdES Table 14 (clause 6.3)
/// baseline-level/presence/cardinality model shipped as COSE/CBOR-free data (wavecb-contract.md ruling R-1(a),
/// coordinator ruling 1 for wave S4). These tests check the DATA the registry carries against the leg-4
/// CB-AdES preflight report (<c>wavecb-leg-4-clause6-baseline-levels-table14.md</c>) — not creation,
/// augmentation, or validation behaviour, which compose this registry from a later stage.
/// </summary>
[TestClass]
internal sealed class CBAdESBaselineLevelTableTests
{
    /// <summary>The registry carries all 26 Table 14 rows (CB-6.3-04..29), each with a unique requirement identifier.</summary>
    [TestMethod]
    public void RegistryContainsExactlyTwentySixRowsWithUniqueRequirementIdentifiers()
    {
        Assert.AreEqual(26, CBAdESBaselineLevelTable.Rows.Count, "Table 14 has 26 distinct rows per the leg-4 CB-AdES preflight report.");

        var seenIds = new HashSet<string>(StringComparer.Ordinal);
        foreach(CBAdESTableRow row in CBAdESBaselineLevelTable.Rows)
        {
            Assert.IsTrue(seenIds.Add(row.RequirementId), $"Requirement identifier '{row.RequirementId}' must be unique across the registry.");
        }

        Assert.AreEqual("CB-6.3-04", CBAdESBaselineLevelTable.Rows[0].RequirementId, "The first row is alg (CB-6.3-04).");
        Assert.AreEqual("CB-6.3-29", CBAdESBaselineLevelTable.Rows[^1].RequirementId, "The last row is arcTst (CB-6.3-29).");
    }


    /// <summary><see cref="CBAdESBaselineLevelTable.FindByRequirementId"/> resolves every registered row by identity, and returns null for an unregistered identifier.</summary>
    [TestMethod]
    public void FindByRequirementIdResolvesEveryRegisteredRowAndOnlyRegisteredRows()
    {
        foreach(CBAdESTableRow row in CBAdESBaselineLevelTable.Rows)
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
    [TestMethod]
    public void AlgIsMandatoryAndSingleValuedAtEveryLevel()
    {
        CBAdESTableRow alg = CBAdESBaselineLevelTable.Alg;

        foreach(CBAdESBaselineLevel level in CBAdESBaselineLevels.All)
        {
            Assert.AreEqual(CBAdESPresence.ShallBePresent, alg.Presence.At(level), $"alg must be ShallBePresent at {level}.");
            CollectionAssert.AreEqual(new[] { CBAdESCardinality.ExactlyOne }, alg.Cardinality!.ValuesAt(level).ToArray(), $"alg's cardinality at {level} must be exactly one.");
        }

        Assert.AreEqual(CBAdESTableRowKind.HeaderParameter, alg.Kind);
        Assert.IsInstanceOfType<CBAdESInternalClauseReference>(alg.Reference);
        Assert.AreEqual("5.1.2", ((CBAdESInternalClauseReference)alg.Reference!).Clause);
    }


    /// <summary>A representative conditioned-presence row (<c>x5chain</c>) records Trap 2's condition clause distinct from its own References clause.</summary>
    [TestMethod]
    public void X5ChainRecordsItsConditionClauseSeparatelyFromItsOwnReferenceClauseTrap2()
    {
        CBAdESTableRow x5chain = CBAdESBaselineLevelTable.X5Chain;

        Assert.AreEqual(CBAdESPresence.ConditionedPresence, x5chain.Presence.At(CBAdESBaselineLevel.BB));
        Assert.AreEqual("5.1.8", ((CBAdESInternalClauseReference)x5chain.Reference!).Clause, "x5chain's own References clause is 5.1.8.");
        CollectionAssert.AreEqual(new[] { "5.2.2" }, x5chain.PresenceConditionClauses!.ToArray(), "x5chain's presence CONDITION lives in clause 5.2.2 (note 3, leg-4 Trap 2), not its own References clause.");

        //x5t and x5ts are part of the same tri-way condition group (D9): all three cite 5.2.2 as the condition clause.
        CollectionAssert.AreEqual(new[] { "5.2.2" }, CBAdESBaselineLevelTable.X5T.PresenceConditionClauses!.ToArray());
        CollectionAssert.AreEqual(new[] { "5.2.2" }, CBAdESBaselineLevelTable.X5Ts.PresenceConditionClauses!.ToArray());
    }


    /// <summary>
    /// <see cref="CBAdESPresence.ShouldNotBePresent"/> (Table 14's "*") and <see cref="CBAdESPresence.ShallNotBePresent"/>
    /// are two distinct enum members, both exercised by registered rows, never collapsed into one value
    /// (leg-4 preflight Trap 4).
    /// </summary>
    [TestMethod]
    public void ShouldNotBePresentIsTypeLevelDistinguishableFromShallNotBePresent()
    {
        Assert.AreNotEqual(CBAdESPresence.ShouldNotBePresent, CBAdESPresence.ShallNotBePresent, "The '*' soft-negative and the hard 'shall not be present' exclusion must be distinct enum members.");
        Assert.AreEqual(6, Enum.GetValues<CBAdESPresence>().Length, "Clause 6.2.2 defines exactly six presence values (CB-6.2.2-03..08).");

        //sigTst at B-B is the soft "*" - a component that upper levels still make mandatory.
        Assert.AreEqual(CBAdESPresence.ShouldNotBePresent, CBAdESBaselineLevelTable.SigTst.Presence.At(CBAdESBaselineLevel.BB));

        //refs at B-LT/B-LTA is the hard exclusion - a component that must be stripped, never re-added.
        Assert.AreEqual(CBAdESPresence.ShallNotBePresent, CBAdESBaselineLevelTable.Refs.Presence.At(CBAdESBaselineLevel.BLT));
        Assert.AreEqual(CBAdESPresence.ShallNotBePresent, CBAdESBaselineLevelTable.Refs.Presence.At(CBAdESBaselineLevel.BLTA));
    }


    /// <summary>
    /// The three Annex A B-B/B-T-only rows (<c>refs</c>, <c>sigRTst</c>, <c>rfsTst</c>) share the identical
    /// level-split cardinality shape: zero-or-more at B-B/B-T, exactly zero at B-LT/B-LTA.
    /// </summary>
    [TestMethod]
    public void RefsSigRTstAndRfsTstShareTheSameLevelSplitCardinalityShape()
    {
        foreach(CBAdESTableRow row in new[] { CBAdESBaselineLevelTable.Refs, CBAdESBaselineLevelTable.SigRTst, CBAdESBaselineLevelTable.RfsTst })
        {
            CollectionAssert.AreEqual(new[] { CBAdESCardinality.ZeroOrMore }, row.Cardinality!.ValuesAt(CBAdESBaselineLevel.BB).ToArray(), $"{row.RequirementId} at B-B.");
            CollectionAssert.AreEqual(new[] { CBAdESCardinality.ZeroOrMore }, row.Cardinality!.ValuesAt(CBAdESBaselineLevel.BT).ToArray(), $"{row.RequirementId} at B-T.");
            CollectionAssert.AreEqual(new[] { CBAdESCardinality.ExactlyZero }, row.Cardinality!.ValuesAt(CBAdESBaselineLevel.BLT).ToArray(), $"{row.RequirementId} at B-LT.");
            CollectionAssert.AreEqual(new[] { CBAdESCardinality.ExactlyZero }, row.Cardinality!.ValuesAt(CBAdESBaselineLevel.BLTA).ToArray(), $"{row.RequirementId} at B-LTA.");

            Assert.AreEqual(CBAdESPresence.ShouldNotBePresent, row.Presence.At(CBAdESBaselineLevel.BB));
            Assert.AreEqual(CBAdESPresence.ShouldNotBePresent, row.Presence.At(CBAdESBaselineLevel.BT));
            Assert.AreEqual(CBAdESPresence.ShallNotBePresent, row.Presence.At(CBAdESBaselineLevel.BLT));
            Assert.AreEqual(CBAdESPresence.ShallNotBePresent, row.Presence.At(CBAdESBaselineLevel.BLTA));
        }
    }


    /// <summary>
    /// <c>sigTst</c>'s cardinality reproduces the source table's genuine duplicate "B-LT, B-LTA: 0" line
    /// verbatim (defect D2, wavecb-contract.md ruling R-6) rather than silently deduplicating it: four
    /// statements total, and <see cref="CBAdESRowCardinality.ValuesAt"/> at B-LT/B-LTA returns the cumulative
    /// "≥1" plus the incremental "0" TWICE.
    /// </summary>
    [TestMethod]
    public void SigTstReproducesTheDuplicatedD2CardinalityLineWithoutDeduplication()
    {
        CBAdESRowCardinality cardinality = CBAdESBaselineLevelTable.SigTst.Cardinality!;

        Assert.AreEqual(4, cardinality.Statements.Count, "sigTst's Table 14 cell stacks four cardinality sub-lines, including one genuine duplicate (leg-4 Trap 5).");

        CollectionAssert.AreEqual(new[] { CBAdESCardinality.ZeroOrMore }, cardinality.ValuesAt(CBAdESBaselineLevel.BB).ToArray(), "sigTst at B-B: the cumulative '*'-adjacent reading is >=0.");
        CollectionAssert.AreEqual(new[] { CBAdESCardinality.OneOrMore }, cardinality.ValuesAt(CBAdESBaselineLevel.BT).ToArray(), "sigTst at B-T: the cumulative reading is >=1.");

        //D2: at B-LT and B-LTA, the cumulative >=1 statement AND the duplicated incremental "0" statement both apply - not deduplicated.
        CollectionAssert.AreEqual(
            new[] { CBAdESCardinality.OneOrMore, CBAdESCardinality.ExactlyZero, CBAdESCardinality.ExactlyZero },
            cardinality.ValuesAt(CBAdESBaselineLevel.BLT).ToArray(),
            "sigTst at B-LT must reproduce the cumulative statement plus the duplicated 'zero new instances' statement twice (D2).");
        CollectionAssert.AreEqual(
            new[] { CBAdESCardinality.OneOrMore, CBAdESCardinality.ExactlyZero, CBAdESCardinality.ExactlyZero },
            cardinality.ValuesAt(CBAdESBaselineLevel.BLTA).ToArray(),
            "sigTst at B-LTA must reproduce the cumulative statement plus the duplicated 'zero new instances' statement twice (D2).");

        //The two duplicate statements are equal in value (same record equality), confirming the duplication is a genuine repeat, not two different readings.
        Assert.AreEqual(cardinality.Statements[2], cardinality.Statements[3], "The two duplicated sub-lines must carry identical level-set and value (D2).");
    }


    /// <summary><c>sigTst</c>'s presence is "*" only at B-B, and mandatory from B-T onward.</summary>
    [TestMethod]
    public void SigTstPresenceIsSoftNegativeAtBBAndMandatoryFromBTOnward()
    {
        CBAdESRowPresence presence = CBAdESBaselineLevelTable.SigTst.Presence;

        Assert.AreEqual(CBAdESPresence.ShouldNotBePresent, presence.At(CBAdESBaselineLevel.BB));
        Assert.AreEqual(CBAdESPresence.ShallBePresent, presence.At(CBAdESBaselineLevel.BT));
        Assert.AreEqual(CBAdESPresence.ShallBePresent, presence.At(CBAdESBaselineLevel.BLT));
        Assert.AreEqual(CBAdESPresence.ShallBePresent, presence.At(CBAdESBaselineLevel.BLTA));
    }


    /// <summary><c>valData</c> carries a single level-invariant cardinality despite its level-split presence.</summary>
    [TestMethod]
    public void ValDataCardinalityIsLevelInvariantDespiteLevelSplitPresence()
    {
        CBAdESTableRow valData = CBAdESBaselineLevelTable.ValData;

        Assert.AreEqual(1, valData.Cardinality!.Statements.Count, "valData carries a single row-wide cardinality statement (leg-4 preflight report), unlike the four level-split rows.");
        foreach(CBAdESBaselineLevel level in CBAdESBaselineLevels.All)
        {
            CollectionAssert.AreEqual(new[] { CBAdESCardinality.ZeroOrMore }, valData.Cardinality.ValuesAt(level).ToArray());
        }

        Assert.AreEqual(CBAdESPresence.ShouldNotBePresent, valData.Presence.At(CBAdESBaselineLevel.BB));
        Assert.AreEqual(CBAdESPresence.ShouldNotBePresent, valData.Presence.At(CBAdESBaselineLevel.BT));
        Assert.AreEqual(CBAdESPresence.ConditionedPresence, valData.Presence.At(CBAdESBaselineLevel.BLT));
        Assert.AreEqual(CBAdESPresence.ConditionedPresence, valData.Presence.At(CBAdESBaselineLevel.BLTA));
    }


    /// <summary><c>arcTst</c> is B-LTA-exclusive and mandatory once reached, with a level-invariant "one or more" cardinality.</summary>
    [TestMethod]
    public void ArcTstIsBLtaExclusiveAndMandatoryOnceReached()
    {
        CBAdESTableRow arcTst = CBAdESBaselineLevelTable.ArcTst;

        Assert.AreEqual(CBAdESPresence.ShouldNotBePresent, arcTst.Presence.At(CBAdESBaselineLevel.BB));
        Assert.AreEqual(CBAdESPresence.ShouldNotBePresent, arcTst.Presence.At(CBAdESBaselineLevel.BT));
        Assert.AreEqual(CBAdESPresence.ShouldNotBePresent, arcTst.Presence.At(CBAdESBaselineLevel.BLT));
        Assert.AreEqual(CBAdESPresence.ShallBePresent, arcTst.Presence.At(CBAdESBaselineLevel.BLTA));

        foreach(CBAdESBaselineLevel level in CBAdESBaselineLevels.All)
        {
            CollectionAssert.AreEqual(new[] { CBAdESCardinality.OneOrMore }, arcTst.Cardinality!.ValuesAt(level).ToArray());
        }
    }


    /// <summary>
    /// The service row groups its two SPO rows, resolvable through <see cref="CBAdESBaselineLevelTable.ServiceProvisionOptionsFor"/>,
    /// with the documented OR-satisfaction (CB-6.3-h) and valData preference (CB-6.3-i) recorded as data.
    /// </summary>
    [TestMethod]
    public void ServiceRowGroupsItsTwoServiceProvisionOptionRowsWithOrSatisfactionAndValDataPreference()
    {
        CBAdESTableRow service = CBAdESBaselineLevelTable.ValidationDataForTimestampsService;

        Assert.IsTrue(CBAdESBaselineLevelTable.IsServiceRow(service));
        Assert.IsFalse(CBAdESBaselineLevelTable.IsServiceProvisionOptionRow(service));
        Assert.IsNull(service.Cardinality, "A service row's Cardinality column is '-' (n/a, CB-6.3-26).");
        Assert.IsNull(service.Reference, "A service row's References column is '-' (CB-6.3-26).");

        IReadOnlyList<CBAdESTableRow> options = CBAdESBaselineLevelTable.ServiceProvisionOptionsFor(service);
        Assert.AreEqual(2, options.Count, "The service is satisfied by exactly two SPO rows (CB-6.3-27/-28).");
        Assert.AreSame(CBAdESBaselineLevelTable.ValDataServiceProvisionOption, options[0]);
        Assert.AreSame(CBAdESBaselineLevelTable.EmbeddedValidationDataServiceProvisionOption, options[1]);

        foreach(CBAdESTableRow option in options)
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
    /// Every row's lettered-requirement and note annotations exactly match the leg-4 CB-AdES preflight
    /// report's per-row annotation list (CB-6.2.2-11) — spot-checked across every row that carries at least
    /// one annotation, plus a handful that carry none.
    /// </summary>
    [TestMethod]
    public void AnnotationsMatchTheLegFourReportForEveryAnnotatedRow()
    {
        AssertAnnotations(CBAdESBaselineLevelTable.Alg, [], []);
        AssertAnnotations(CBAdESBaselineLevelTable.ContentType, [], [2]);
        AssertAnnotations(CBAdESBaselineLevelTable.X5Chain, [], [3]);
        AssertAnnotations(CBAdESBaselineLevelTable.Crit, [], [4]);
        AssertAnnotations(CBAdESBaselineLevelTable.CwtClaims, ['a'], []);
        AssertAnnotations(CBAdESBaselineLevelTable.X5T, [], [3]);
        AssertAnnotations(CBAdESBaselineLevelTable.X5Ts, [], [3]);
        AssertAnnotations(CBAdESBaselineLevelTable.SrCms, [], [5]);
        AssertAnnotations(CBAdESBaselineLevelTable.AdoTst, [], [6]);
        AssertAnnotations(CBAdESBaselineLevelTable.SigPSt, ['b'], []);
        AssertAnnotations(CBAdESBaselineLevelTable.SigTst, ['c', 'd'], [7]);
        AssertAnnotations(CBAdESBaselineLevelTable.ValData, ['e', 'f'], []);
        AssertAnnotations(CBAdESBaselineLevelTable.Refs, ['g'], []);
        AssertAnnotations(CBAdESBaselineLevelTable.SigRTst, [], []);
        AssertAnnotations(CBAdESBaselineLevelTable.RfsTst, [], []);
        AssertAnnotations(CBAdESBaselineLevelTable.ValidationDataForTimestampsService, ['h', 'i'], [8]);
        AssertAnnotations(CBAdESBaselineLevelTable.ValDataServiceProvisionOption, [], []);
        AssertAnnotations(CBAdESBaselineLevelTable.EmbeddedValidationDataServiceProvisionOption, ['i'], []);
        AssertAnnotations(CBAdESBaselineLevelTable.ArcTst, ['j', 'k'], []);

        static void AssertAnnotations(CBAdESTableRow row, char[] expectedLetters, int[] expectedNotes)
        {
            CollectionAssert.AreEqual(expectedLetters, row.Annotations.RequirementLetters.ToArray(), $"{row.RequirementId} requirement letters.");
            CollectionAssert.AreEqual(expectedNotes, row.Annotations.NoteNumbers.ToArray(), $"{row.RequirementId} note numbers.");
        }
    }


    /// <summary>Every one of the eleven lettered additional requirements (a)-(k) appears on at least one registered row.</summary>
    [TestMethod]
    public void EveryLetteredRequirementFromAThroughKAppearsOnAtLeastOneRow()
    {
        var seenLetters = new HashSet<char>();
        foreach(CBAdESTableRow row in CBAdESBaselineLevelTable.Rows)
        {
            foreach(char letter in row.Annotations.RequirementLetters)
            {
                seenLetters.Add(letter);
            }
        }

        CollectionAssert.AreEquivalent("abcdefghijk".ToCharArray(), seenLetters.ToArray(), "Clause 6.3 defines exactly eleven lettered additional requirements, a) through k).");
    }


    /// <summary>
    /// <see cref="CBAdESTableRow.Cardinality"/> is null for exactly the one service row Table 14 marks "-",
    /// and non-null for every other row.
    /// </summary>
    [TestMethod]
    public void CardinalityIsNullOnlyForTheServiceRow()
    {
        foreach(CBAdESTableRow row in CBAdESBaselineLevelTable.Rows)
        {
            bool expectNull = row.Kind == CBAdESTableRowKind.Service;
            Assert.AreEqual(expectNull, row.Cardinality is null, $"{row.RequirementId}: Cardinality must be null iff the row is a service row.");
        }
    }


    /// <summary>
    /// <see cref="CBAdESTableRow.Reference"/> is null for exactly the rows Table 14 marks "-" in the
    /// References column (the service row and the embedded-in-TST SPO row), and non-null for every other row.
    /// </summary>
    [TestMethod]
    public void ReferenceIsNullOnlyForTheDocumentedDashRows()
    {
        var expectedNullReferenceIds = new HashSet<string>(StringComparer.Ordinal) { "CB-6.3-26", "CB-6.3-28" };

        foreach(CBAdESTableRow row in CBAdESBaselineLevelTable.Rows)
        {
            bool expectNull = expectedNullReferenceIds.Contains(row.RequirementId);
            Assert.AreEqual(expectNull, row.Reference is null, $"{row.RequirementId}: Reference nullability must match Table 14's References column.");
        }
    }


    /// <summary>The registry's row-kind split matches the 10/13/1/2 count this stage's implementation record documents.</summary>
    [TestMethod]
    public void RowKindCountsMatchTheDocumentedTenThirteenOneTwoSplit()
    {
        Assert.AreEqual(10, CBAdESBaselineLevelTable.Rows.Count(row => row.Kind == CBAdESTableRowKind.HeaderParameter));
        Assert.AreEqual(13, CBAdESBaselineLevelTable.Rows.Count(row => row.Kind == CBAdESTableRowKind.Component));
        Assert.AreEqual(1, CBAdESBaselineLevelTable.Rows.Count(row => row.Kind == CBAdESTableRowKind.Service));
        Assert.AreEqual(2, CBAdESBaselineLevelTable.Rows.Count(row => row.Kind == CBAdESTableRowKind.ServiceProvisionOption));
    }


    /// <summary><see cref="CBAdESRowPresence.Uniform"/> applies the same value at all four levels.</summary>
    [TestMethod]
    public void UniformPresenceAppliesTheSameValueAtAllFourLevels()
    {
        CBAdESRowPresence presence = CBAdESRowPresence.Uniform(CBAdESPresence.MayBePresent);

        foreach(CBAdESBaselineLevel level in CBAdESBaselineLevels.All)
        {
            Assert.AreEqual(CBAdESPresence.MayBePresent, presence.At(level));
        }
    }


    /// <summary><see cref="CBAdESRowCardinality.Uniform"/> produces a single statement scoped to every level.</summary>
    [TestMethod]
    public void UniformCardinalityAppliesTheSameValueAtAllFourLevels()
    {
        CBAdESRowCardinality cardinality = CBAdESRowCardinality.Uniform(CBAdESCardinality.ZeroOrOne);

        Assert.AreEqual(1, cardinality.Statements.Count);
        Assert.AreEqual(CBAdESBaselineLevelSet.All, cardinality.Statements[0].Levels);
        foreach(CBAdESBaselineLevel level in CBAdESBaselineLevels.All)
        {
            CollectionAssert.AreEqual(new[] { CBAdESCardinality.ZeroOrOne }, cardinality.ValuesAt(level).ToArray());
        }
    }


    /// <summary><see cref="CBAdESBaselineLevelSet"/> membership round-trips through <see cref="CBAdESBaselineLevels.ToLevelSet"/> for every level.</summary>
    [TestMethod]
    public void LevelSetContainsReflectsSingleLevelMembership()
    {
        foreach(CBAdESBaselineLevel level in CBAdESBaselineLevels.All)
        {
            CBAdESBaselineLevelSet singleton = level.ToLevelSet();
            Assert.IsTrue(singleton.Contains(level), $"{level}'s own singleton set must contain {level}.");
            Assert.IsTrue(CBAdESBaselineLevelSet.All.Contains(level), $"'All' must contain {level}.");

            foreach(CBAdESBaselineLevel other in CBAdESBaselineLevels.All)
            {
                if(other != level)
                {
                    Assert.IsFalse(singleton.Contains(other), $"{level}'s own singleton set must not contain {other}.");
                }
            }
        }
    }
}
