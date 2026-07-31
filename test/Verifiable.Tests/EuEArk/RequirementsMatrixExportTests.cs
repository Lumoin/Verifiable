using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using Verifiable.Core.Assessment;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.EuEArk;

/// <summary>
/// Writes every requirements matrix this test assembly ships into ONE machine-readable artifact, and checks
/// that what was written says the same thing the matrices do.
/// </summary>
/// <remarks>
/// <para>
/// The matrices are this repository's record of which normative statement of which specification is driven by
/// which test. A system outside the repository that assembles a provenance graph of requirements mapped to
/// code needs exactly that record — keyed on the specifications' own identifiers, with the evidence citations
/// resolvable and the stable claim-identifier codes attached — and re-deriving it by parsing C# source would
/// be brittle where reading the compiled matrices is not.
/// </para>
/// <para>
/// The export is test-side on purpose: every shipped library of this repository is free of serialization
/// dependencies by rule, the matrices are themselves test code, and so their artifact is written here.
/// <see cref="RequirementsMatrixExport"/> holds the reader and the writer; this class drives them and is where
/// the artifact's shape is asserted.
/// </para>
/// </remarks>
[TestClass]
internal sealed class RequirementsMatrixExportTests
{
    /// <summary>The name the repeat artifact carries while determinism is being checked.</summary>
    private const string RepeatArtifactName = "requirements-matrix.repeat.json";


    /// <summary>
    /// Writes every matrix's rows to the deterministic artifact path and reads the artifact back, asserting
    /// that each matrix is present with the row count its own class states, that no row reaches the artifact
    /// without an identifier, a requirement, a disposition and evidence, that no row is exported as having no
    /// disposition at all, and that writing twice produces the identical document.
    /// </summary>
    /// <remarks>
    /// The re-read is what makes this an assertion about the artifact rather than about the objects that
    /// produced it: a consuming system sees the file, so the file is what is checked.
    /// </remarks>
    [TestMethod]
    public void TheExportWritesEveryMatrixsRowsAsOneMachineReadableArtifact()
    {
        IReadOnlyList<ExportedRequirementMatrix> matrices = RequirementsMatrixExport.WriteArtifact();

        Assert.IsTrue(File.Exists(RequirementsMatrixExport.ArtifactPath), $"The artifact was not written to {RequirementsMatrixExport.ArtifactPath}.");
        Assert.HasCount(RequirementsMatrixExport.MatrixTypes.Count, matrices);

        string written = File.ReadAllText(RequirementsMatrixExport.ArtifactPath);
        using JsonDocument artifact = JsonDocument.Parse(written);
        JsonElement root = artifact.RootElement;

        Assert.AreEqual(1, root.GetProperty("schemaVersion").GetInt32());
        Assert.AreEqual("verifiable-requirements-matrix", root.GetProperty("artifact").GetString());
        Assert.AreEqual(RequirementsMatrixExport.MatrixTypes.Count, root.GetProperty("matrixCount").GetInt32());

        int totalRows = 0;
        int totalWithAnEvidenceMethod = 0;
        int totalWithAClaimIdCode = 0;
        List<string> exportedMatrixNames = [];
        foreach(JsonElement matrix in root.GetProperty("matrices").EnumerateArray())
        {
            string name = matrix.GetProperty("name").GetString()!;
            exportedMatrixNames.Add(name);

            int rowCount = matrix.GetProperty("rowCount").GetInt32();
            Assert.AreEqual(RowCountOf(name), rowCount, $"{name} exported a different number of rows than it states.");
            Assert.IsGreaterThan(0, rowCount, $"{name} exported no rows at all.");
            Assert.IsFalse(string.IsNullOrWhiteSpace(matrix.GetProperty("namespace").GetString()), $"{name} exported no namespace.");

            int rowsSeen = 0;
            int statusCountTotal = matrix.GetProperty("statusCounts").EnumerateObject().Sum(status => status.Value.GetInt32());
            foreach(JsonElement row in matrix.GetProperty("rows").EnumerateArray())
            {
                ++rowsSeen;
                string id = row.GetProperty("id").GetString()!;
                Assert.IsFalse(string.IsNullOrWhiteSpace(id), $"{name} exported a row with no identifier.");
                Assert.IsFalse(string.IsNullOrWhiteSpace(row.GetProperty("requirement").GetString()), $"{name}: row {id} exported no requirement text.");
                Assert.IsFalse(string.IsNullOrWhiteSpace(row.GetProperty("evidence").GetString()), $"{name}: row {id} exported no evidence.");

                string status = row.GetProperty("status").GetString()!;
                Assert.AreNotEqual("Untested", status, $"{name}: row {id} reached the artifact with no coverage disposition.");

                if(row.TryGetProperty("evidenceMethod", out JsonElement evidenceMethod))
                {
                    Assert.Contains(".", evidenceMethod.GetString()!, StringComparison.Ordinal, $"{name}: row {id} exported an evidence method that names no class.");
                    ++totalWithAnEvidenceMethod;
                }

                if(row.TryGetProperty("claimIdCode", out JsonElement claimIdCode))
                {
                    Assert.IsGreaterThan(0, claimIdCode.GetInt32(), $"{name}: row {id} exported a claim identifier code that is not one this repository allocates.");
                    ++totalWithAClaimIdCode;
                }
            }

            Assert.AreEqual(rowCount, rowsSeen, $"{name} states one row count and carries another.");
            Assert.AreEqual(rowCount, statusCountTotal, $"{name}'s status counts do not add up to its rows.");
            totalRows += rowsSeen;
        }

        Assert.AreEqual(root.GetProperty("rowCount").GetInt32(), totalRows, "The artifact's own total does not match the rows it carries.");
        Assert.IsGreaterThan(0, totalWithAnEvidenceMethod, "No exported row resolved its evidence to a test method, which is the join a consuming graph is built on.");
        Assert.IsGreaterThan(400, totalWithAClaimIdCode, "The eArchiving matrices alone allocate more than four hundred claim identifier codes, and the artifact carries them so a consumer can key on the code rather than on the string.");

        foreach(Type matrixType in RequirementsMatrixExport.MatrixTypes)
        {
            Assert.Contains(matrixType.Name, exportedMatrixNames, $"{matrixType.Name} was listed for export but is not in the artifact.");
        }

        string repeatPath = Path.Combine(Path.GetDirectoryName(RequirementsMatrixExport.ArtifactPath)!, RepeatArtifactName);
        try
        {
            RequirementsMatrixExport.Write(repeatPath, RequirementsMatrixExport.Read());
            Assert.AreEqual(written, File.ReadAllText(repeatPath), "Two exports of one build produced different documents, so a consuming system could not tell a requirement change from run noise.");
        }
        finally
        {
            File.Delete(repeatPath);
        }
    }


    /// <summary>
    /// Every requirements-matrix class this assembly ships is listed for export. A matrix written by a later
    /// wave and never added to the list would leave its specification out of the consuming system's graph
    /// without anything saying so.
    /// </summary>
    [TestMethod]
    public void EveryRequirementsMatrixOfTheAssemblyIsListedForExport()
    {
        IReadOnlyList<Type> discovered = RequirementsMatrixExport.DiscoverMatrixTypes();
        Assert.IsNotEmpty(discovered);

        List<string> unlisted = [.. discovered
            .Where(candidate => !RequirementsMatrixExport.MatrixTypes.Contains(candidate))
            .Select(candidate => candidate.FullName!)];

        Assert.IsEmpty(unlisted, $"These requirements matrices are not listed for export: {string.Join(", ", unlisted)}.");
        Assert.HasCount(discovered.Count, RequirementsMatrixExport.MatrixTypes);
    }


    /// <summary>
    /// Every claim-identifier registry of the eArchiving namespace is listed for the export's join. A registry
    /// a later wave allocates in and never adds to the list would leave every one of its requirements without a
    /// code in the consuming system's graph, and nothing today would say so — the sibling list of matrix
    /// classes has had that guard since the wave shipped and this one had not.
    /// </summary>
    [TestMethod]
    public void EveryClaimIdRegistryOfTheEArchivingNamespaceIsListedForTheJoin()
    {
        IReadOnlyList<Type> discovered = RequirementsMatrixExport.DiscoverClaimIdRegistries();
        Assert.IsNotEmpty(discovered);

        List<string> unlisted = [.. discovered
            .Where(candidate => !RequirementsMatrixExport.ClaimIdRegistries.Contains(candidate))
            .Select(candidate => candidate.FullName!)];

        Assert.IsEmpty(unlisted, $"These claim-identifier registries are not listed for the export's join: {string.Join(", ", unlisted)}.");
        Assert.HasCount(discovered.Count, RequirementsMatrixExport.ClaimIdRegistries);
    }


    /// <summary>
    /// The export joins a matrix row to a claim-identifier code through the description each allocation carries,
    /// and the registry that mints those allocations enforces uniqueness on the CODE alone — so two codes may
    /// carry one description without anything in the library objecting. The export refuses that outright rather
    /// than letting the last allocation the reflection walk happened to visit win the join.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The failure this refuses is silent and order-dependent: a requirement's exported <c>claimIdCode</c> would
    /// name a different requirement's allocation, and <c>Type.GetProperties</c> does not specify its order, so
    /// which one it named could differ between runtimes. Every assertion the artifact carries on the field — the
    /// code is positive, and more than four hundred rows have one — is satisfied by the wrong code.
    /// </para>
    /// <para>
    /// The two registries are stated here rather than found in the shipped ones, because the shipped ones do not
    /// collide: the point is what the export does when a later allocation does.
    /// </para>
    /// </remarks>
    [TestMethod]
    public void TwoAllocationsSharingOneDescriptionAreRefusedRatherThanJoinedToWhicheverWasReadLast()
    {
        //A registry with no collision joins every allocation it carries, keyed on the description.
        IReadOnlyDictionary<string, int> joined = RequirementsMatrixExport.ReadClaimIdCodes([typeof(DistinctlyDescribedAllocations)]);

        Assert.HasCount(2, joined);
        Assert.AreEqual(DistinctlyDescribedAllocations.First.Code, joined["RF3-EXPORT-JOIN-FIRST"]);
        Assert.AreEqual(DistinctlyDescribedAllocations.Second.Code, joined["RF3-EXPORT-JOIN-SECOND"]);

        //Two codes carrying one description are what the library itself does not refuse, so the export must.
        var refused = Assert.Throws<InvalidOperationException>(
            () => RequirementsMatrixExport.ReadClaimIdCodes([typeof(AllocationsSharingOneDescription)]));

        Assert.Contains("RF3-EXPORT-JOIN-SHARED", refused.Message, StringComparison.Ordinal);
        Assert.Contains(AllocationsSharingOneDescription.First.Code.ToString(System.Globalization.CultureInfo.InvariantCulture), refused.Message, StringComparison.Ordinal);
        Assert.Contains(AllocationsSharingOneDescription.Second.Code.ToString(System.Globalization.CultureInfo.InvariantCulture), refused.Message, StringComparison.Ordinal);

        //And the same registry listed twice is a malformed list rather than a duplicate allocation, which the
        //code-keyed primary table is what catches.
        var listedTwice = Assert.Throws<InvalidOperationException>(
            () => RequirementsMatrixExport.ReadClaimIdCodes([typeof(DistinctlyDescribedAllocations), typeof(DistinctlyDescribedAllocations)]));

        Assert.Contains(DistinctlyDescribedAllocations.First.Code.ToString(System.Globalization.CultureInfo.InvariantCulture), listedTwice.Message, StringComparison.Ordinal);
    }


    /// <summary>Two allocations describing themselves differently, which the export's join accepts.</summary>
    private static class DistinctlyDescribedAllocations
    {
        /// <summary>The first allocation.</summary>
        public static ClaimId First { get; } = ClaimId.Create(1_600_001, "RF3-EXPORT-JOIN-FIRST");

        /// <summary>The second allocation, described differently.</summary>
        public static ClaimId Second { get; } = ClaimId.Create(1_600_002, "RF3-EXPORT-JOIN-SECOND");
    }


    /// <summary>
    /// Two allocations of different codes describing themselves identically — the state the claim-identifier
    /// registry accepts, because it enforces uniqueness on the code and never on the description.
    /// </summary>
    private static class AllocationsSharingOneDescription
    {
        /// <summary>The first allocation.</summary>
        public static ClaimId First { get; } = ClaimId.Create(1_600_003, "RF3-EXPORT-JOIN-SHARED");

        /// <summary>The second allocation, carrying the first one's description.</summary>
        public static ClaimId Second { get; } = ClaimId.Create(1_600_004, "RF3-EXPORT-JOIN-SHARED");
    }


    /// <summary>Reads the number of rows a matrix class states, through the same member the export reads.</summary>
    /// <param name="matrixName">The matrix class's simple name.</param>
    /// <returns>The number of rows the class states.</returns>
    private static int RowCountOf(string matrixName)
    {
        Type matrixType = RequirementsMatrixExport.MatrixTypes
            .Single(candidate => string.Equals(candidate.Name, matrixName, StringComparison.Ordinal));

        PropertyInfo rowData = matrixType.GetProperty(
            "RowData", BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static)!;

        return ((Array)rowData.GetValue(null)!).Length;
    }
}
