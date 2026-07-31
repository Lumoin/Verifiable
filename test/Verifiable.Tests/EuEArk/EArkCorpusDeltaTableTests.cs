using System.Reflection;
using Verifiable.Core.Assessment;
using Verifiable.Core.Assessment.EArchiving;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.EuEArk;

/// <summary>
/// The edition-delta table asserted against the specification family's own published catalogues: every row it
/// states is a difference the two editions really carry, and every difference the two editions carry is a row it
/// states.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Both directions, and the second one is the point.</strong> A table that merely restated true facts
/// could still omit the one difference that matters, and the sweep built on it would then be quietly wrong. The
/// completeness test below therefore recomputes the whole difference between the two published catalogues —
/// identifier space, requirement level, element location, cardinality and heading — and asserts that what it
/// finds is exactly what the table names.
/// </para>
/// <para>
/// The catalogues are the machine-readable halves of the published editions of
/// <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP</see>, read by
/// <see cref="EArkProfileCatalogueSource"/>. They are optional local reference material, so every test here
/// reports inconclusive when they are absent.
/// </para>
/// </remarks>
[TestClass]
internal sealed class EArkCorpusDeltaTableTests
{
    /// <summary>
    /// Every row of the table is stated once, names a requirement, states a kind, and says what it does to a
    /// swept case — the shape check that keeps a row from being added as a bare identifier.
    /// </summary>
    [TestMethod]
    public void EveryRowIsStatedOnceAndSaysWhatItDoesToASweptCase()
    {
        var seen = new List<string>();
        foreach(EArkCorpusDeltaRow row in EArkCorpusDeltaTable.Rows)
        {
            Assert.IsNotEmpty(row.Id, "A row without a name cannot be cited by a case.");
            Assert.IsNotEmpty(row.RequirementId, $"Row {row.Id} names no requirement.");
            Assert.AreNotEqual(EArkCorpusDeltaKind.NotEvaluated, row.Kind, $"Row {row.Id} states no kind of difference.");
            Assert.IsNotEmpty(row.BaselineReading, $"Row {row.Id} does not say how the corpus's edition reads the requirement.");
            Assert.IsNotEmpty(row.RuleReading, $"Row {row.Id} does not say how the shipped rules read it.");
            Assert.IsNotEmpty(row.Effect, $"Row {row.Id} does not say what the difference does to a case.");
            Assert.IsNotEmpty(row.Evidence, $"Row {row.Id} states no evidence.");

            Assert.DoesNotContain(row.RequirementId, seen, $"Row {row.Id} states a requirement another row already states.");
            seen.Add(row.RequirementId);
        }

        Assert.HasCount(9, EArkCorpusDeltaTable.Rows);
        Assert.AreEqual("2.1.0", EArkCorpusDeltaTable.BaselineVersion);
        Assert.AreEqual("2.2.0", EArkCorpusDeltaTable.RuleVersion);
    }


    /// <summary>
    /// The difference between the two published catalogues is exactly what the table names: three softened
    /// requirement levels, and nothing else moved at all.
    /// </summary>
    [TestMethod]
    public void TheTwoPublishedCataloguesDifferInExactlyTheWaysTheTableNames()
    {
        EArkProfileCatalogue? baseline = EArkProfileCatalogueSource.FindCatalogue(EArkCorpusDeltaTable.BaselineVersion);
        EArkProfileCatalogue? current = EArkProfileCatalogueSource.FindCatalogue(EArkCorpusDeltaTable.RuleVersion);
        if(baseline is null || current is null)
        {
            Assert.Inconclusive(EArkProfileCatalogueSource.MissingCataloguesMessage);
            return;
        }

        Assert.HasCount(118, baseline.Rows, "The earlier edition's whole catalogue.");
        Assert.HasCount(118, current.Rows, "The later edition's whole catalogue.");

        var softened = new List<string>();
        var otherDifferences = new List<string>();
        foreach(EArkProfileRequirementRow row in baseline.Rows)
        {
            EArkProfileRequirementRow? later = current.Find(row.RequirementId);
            if(later is null)
            {
                otherDifferences.Add($"{row.RequirementId}: dropped by the later edition.");
                continue;
            }

            if(!string.Equals(row.Level, later.Level, StringComparison.Ordinal))
            {
                if(string.Equals(row.Level, "MUST", StringComparison.Ordinal) && string.Equals(later.Level, "SHOULD", StringComparison.Ordinal))
                {
                    softened.Add(row.RequirementId);
                }
                else
                {
                    otherDifferences.Add($"{row.RequirementId}: level {row.Level} became {later.Level}.");
                }
            }

            if(!string.Equals(row.Location, later.Location, StringComparison.Ordinal))
            {
                otherDifferences.Add($"{row.RequirementId}: location moved.");
            }

            if(!string.Equals(row.Cardinality, later.Cardinality, StringComparison.Ordinal))
            {
                otherDifferences.Add($"{row.RequirementId}: cardinality changed.");
            }

            if(!string.Equals(row.Head, later.Head, StringComparison.Ordinal))
            {
                otherDifferences.Add($"{row.RequirementId}: heading changed.");
            }
        }

        foreach(EArkProfileRequirementRow row in current.Rows)
        {
            if(baseline.Find(row.RequirementId) is null)
            {
                otherDifferences.Add($"{row.RequirementId}: added by the later edition.");
            }
        }

        Assert.IsEmpty(otherDifferences, $"The two editions differ in ways the table does not name: {string.Join("; ", otherDifferences)}.");

        var named = new List<string>();
        foreach(EArkCorpusDeltaRow row in EArkCorpusDeltaTable.Rows)
        {
            if(row.Kind == EArkCorpusDeltaKind.RequirementLevelSoftened)
            {
                named.Add(row.RequirementId);
                Assert.AreEqual("MUST", row.BaselineReading, $"Row {row.Id} states the earlier level.");
                Assert.AreEqual("SHOULD", row.RuleReading, $"Row {row.Id} states the later level.");
            }
        }

        softened.Sort(StringComparer.Ordinal);
        named.Sort(StringComparer.Ordinal);
        Assert.AreSequenceEqual(named, softened, "The softened requirements are exactly the ones the table names.");
    }


    /// <summary>
    /// Each retired row names an identifier neither published catalogue states, for which the corpus
    /// nevertheless carries a requirement directory and this repository allocates no claim.
    /// </summary>
    [TestMethod]
    public void EveryRetiredRowNamesAnIdentifierNeitherCatalogueStates()
    {
        EArkProfileCatalogue? baseline = EArkProfileCatalogueSource.FindCatalogue(EArkCorpusDeltaTable.BaselineVersion);
        EArkProfileCatalogue? current = EArkProfileCatalogueSource.FindCatalogue(EArkCorpusDeltaTable.RuleVersion);
        IReadOnlyList<EArkCorpusTestCase> cases = EArkCorpusSource.FindTestCases();
        if(baseline is null || current is null || cases.Count == 0)
        {
            Assert.Inconclusive(EArkProfileCatalogueSource.MissingCataloguesMessage);
            return;
        }

        int retiredRows = 0;
        foreach(EArkCorpusDeltaRow row in EArkCorpusDeltaTable.Rows)
        {
            if(row.Kind != EArkCorpusDeltaKind.RequirementRetired)
            {
                continue;
            }

            ++retiredRows;
            Assert.IsNull(current.Find(row.RequirementId), $"Row {row.Id} calls {row.RequirementId} retired and the later edition states it.");
            Assert.IsNull(baseline.Find(row.RequirementId), $"Row {row.Id} calls {row.RequirementId} retired and the earlier edition states it too.");
            Assert.IsNotNull(FindCase(cases, row.RequirementId), $"Row {row.Id} exists because the corpus carries a directory for {row.RequirementId}.");
            Assert.IsFalse(
                IsAllocated(row.RequirementId),
                $"Row {row.Id} states that no claim identifier is allocated for {row.RequirementId}.");
        }

        Assert.AreEqual(2, retiredRows, "The corpus carries directories for exactly two retired numbers.");
    }


    /// <summary>
    /// Each divergence row names a requirement whose corpus case states a text both published catalogues
    /// contradict — the corpus's own reading, not this library's.
    /// </summary>
    [TestMethod]
    public void EveryDivergenceRowNamesACaseBothCataloguesContradict()
    {
        EArkProfileCatalogue? baseline = EArkProfileCatalogueSource.FindCatalogue(EArkCorpusDeltaTable.BaselineVersion);
        EArkProfileCatalogue? current = EArkProfileCatalogueSource.FindCatalogue(EArkCorpusDeltaTable.RuleVersion);
        IReadOnlyList<EArkCorpusTestCase> cases = EArkCorpusSource.FindTestCases();
        if(baseline is null || current is null || cases.Count == 0)
        {
            Assert.Inconclusive(EArkProfileCatalogueSource.MissingCataloguesMessage);
            return;
        }

        int divergences = 0;
        foreach(EArkCorpusDeltaRow row in EArkCorpusDeltaTable.Rows)
        {
            if(row.Kind != EArkCorpusDeltaKind.RequirementTextDiverged)
            {
                continue;
            }

            ++divergences;
            EArkCorpusTestCase? corpusCase = FindCase(cases, row.RequirementId);
            EArkProfileRequirementRow? earlier = baseline.Find(row.RequirementId);
            EArkProfileRequirementRow? later = current.Find(row.RequirementId);

            Assert.IsNotNull(corpusCase, $"Row {row.Id} is about a corpus case.");
            Assert.IsNotNull(earlier, $"Row {row.Id} is about a requirement both editions state.");
            Assert.IsNotNull(later, $"Row {row.Id} is about a requirement both editions state.");

            bool locationDiffers = corpusCase.StatedLocation.Length > 0
                && !string.Equals(Compact(corpusCase.StatedLocation), Compact(later.Location), StringComparison.Ordinal);
            bool cardinalityDiffers = corpusCase.StatedCardinality.Length > 0
                && !string.Equals(corpusCase.StatedCardinality, later.Cardinality, StringComparison.Ordinal);

            Assert.IsTrue(
                locationDiffers || cardinalityDiffers,
                $"Row {row.Id} states a divergence the corpus case and the later edition do not carry.");

            Assert.AreEqual(earlier.Location, later.Location, $"Row {row.Id} states that both editions agree with each other on the location.");
            Assert.AreEqual(earlier.Cardinality, later.Cardinality, $"Row {row.Id} states that both editions agree with each other on the cardinality.");
        }

        Assert.AreEqual(2, divergences, "Two corpus cases carry a requirement text both editions contradict.");
    }


    /// <summary>
    /// The row for the requirement the corpus never wrote a case for names a requirement this repository does
    /// allocate a claim for and a directory the corpus really does not carry — so the gap is the corpus's, not
    /// this library's.
    /// </summary>
    [TestMethod]
    public void TheRequirementWithoutACaseIsAllocatedHereAndAbsentThere()
    {
        IReadOnlyList<EArkCorpusTestCase> cases = EArkCorpusSource.FindTestCases();
        if(cases.Count == 0)
        {
            Assert.Inconclusive(EArkCorpusSource.MissingCorpusMessage);
            return;
        }

        int rows = 0;
        foreach(EArkCorpusDeltaRow row in EArkCorpusDeltaTable.Rows)
        {
            if(row.Kind != EArkCorpusDeltaKind.RequirementWithoutCorpusCase)
            {
                continue;
            }

            ++rows;
            Assert.IsNull(FindCase(cases, row.RequirementId), $"Row {row.Id} says the corpus carries no case for {row.RequirementId}.");
            Assert.IsTrue(
                IsAllocated(row.RequirementId),
                $"Row {row.Id} says this repository allocates a claim identifier for {row.RequirementId}.");
        }

        Assert.AreEqual(1, rows);
        Assert.AreEqual("CSIPSTR2", EArkClaimIds.CsipStr2.ToString(), "The claim the row is about is the folder-naming recommendation.");
    }


    /// <summary>
    /// The row for the number no edition ever allocated names a number neither catalogue states, the corpus
    /// carries no case for, and this repository allocates no claim for — three absences, so the gap in the
    /// numbering cannot be read as a transcription loss anywhere.
    /// </summary>
    [TestMethod]
    public void TheNeverAllocatedNumberIsAbsentFromAllThreeInventories()
    {
        EArkProfileCatalogue? baseline = EArkProfileCatalogueSource.FindCatalogue(EArkCorpusDeltaTable.BaselineVersion);
        EArkProfileCatalogue? current = EArkProfileCatalogueSource.FindCatalogue(EArkCorpusDeltaTable.RuleVersion);
        IReadOnlyList<EArkCorpusTestCase> cases = EArkCorpusSource.FindTestCases();
        if(baseline is null || current is null || cases.Count == 0)
        {
            Assert.Inconclusive(EArkProfileCatalogueSource.MissingCataloguesMessage);
            return;
        }

        int rows = 0;
        foreach(EArkCorpusDeltaRow row in EArkCorpusDeltaTable.Rows)
        {
            if(row.Kind != EArkCorpusDeltaKind.RequirementNumberNeverAllocated)
            {
                continue;
            }

            ++rows;
            Assert.IsNull(baseline.Find(row.RequirementId));
            Assert.IsNull(current.Find(row.RequirementId));
            Assert.IsNull(FindCase(cases, row.RequirementId));
            Assert.IsFalse(IsAllocated(row.RequirementId));
        }

        Assert.AreEqual(1, rows);
    }


    /// <summary>
    /// The corpus states its cases against several editions at once, and the sweep has to know it: the versions
    /// the cases cite are asserted here so a case that moved to a newer edition changes a number rather than
    /// quietly changing what the sweep means.
    /// </summary>
    [TestMethod]
    public void TheCorpusStatesItsCasesAgainstSeveralEditionsAtOnce()
    {
        IReadOnlyList<EArkCorpusTestCase> cases = EArkCorpusSource.FindTestCases();
        if(cases.Count == 0)
        {
            Assert.Inconclusive(EArkCorpusSource.MissingCorpusMessage);
            return;
        }

        var versions = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach(EArkCorpusTestCase testCase in cases)
        {
            versions[testCase.StatedVersion] = versions.TryGetValue(testCase.StatedVersion, out int existing) ? existing + 1 : 1;
        }

        Assert.AreEqual(11, versions["2.0-DRAFT"], "Cases still citing a draft of the first edition.");
        Assert.AreEqual(1, versions["2.0.3"]);
        Assert.AreEqual(61, versions["2.0.4"]);
        Assert.AreEqual(59, versions["2.1.0"]);
        Assert.AreEqual(2, versions["2.1.1"]);
        Assert.AreEqual(13, versions["2.2.0"], "Cases already written against the edition the shipped rules read.");
        Assert.HasCount(6, versions, "Six editions are cited across the corpus, which is why a delta table is needed at all.");
    }


    /// <summary>
    /// States whether this repository allocates a claim identifier described by one requirement identifier.
    /// </summary>
    /// <param name="requirementId">The requirement identifier, as the specification spells it.</param>
    /// <returns><see langword="true"/> when an allocation describes itself with exactly that identifier.</returns>
    /// <remarks>
    /// The allocations are read by reflection off the well-known class rather than out of the claim registry,
    /// whose description map is private — the same route
    /// <see cref="EArkClaimIdAllocationTests"/> takes, for the same reason.
    /// </remarks>
    private static bool IsAllocated(string requirementId)
    {
        foreach(PropertyInfo property in typeof(EArkClaimIds).GetProperties(BindingFlags.Public | BindingFlags.Static))
        {
            if(property.PropertyType == typeof(ClaimId)
                && string.Equals(((ClaimId)property.GetValue(null)!).ToString(), requirementId, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>Finds one requirement's case, if the corpus carries it.</summary>
    /// <param name="cases">Every case the corpus carries.</param>
    /// <param name="requirementId">The requirement identifier to look for.</param>
    /// <returns>The case, or <see langword="null"/>.</returns>
    private static EArkCorpusTestCase? FindCase(IReadOnlyList<EArkCorpusTestCase> cases, string requirementId)
    {
        for(int i = 0; i < cases.Count; ++i)
        {
            if(string.Equals(cases[i].RequirementId, requirementId, StringComparison.Ordinal))
            {
                return cases[i];
            }
        }

        return null;
    }


    /// <summary>Removes the whitespace an element location may be wrapped with.</summary>
    /// <param name="value">The value to compact.</param>
    /// <returns>The value with every whitespace character removed.</returns>
    private static string Compact(string value) =>
        value.Replace(" ", string.Empty, StringComparison.Ordinal)
            .Replace("\t", string.Empty, StringComparison.Ordinal)
            .Replace("\r", string.Empty, StringComparison.Ordinal)
            .Replace("\n", string.Empty, StringComparison.Ordinal);
}
