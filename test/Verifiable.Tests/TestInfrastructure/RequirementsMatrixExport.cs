using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Verifiable.Core.Assessment;
using Verifiable.Core.Assessment.EArchiving;
using Verifiable.Tests.Cryptography;
using Verifiable.Tests.EuEArk;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// One exported requirement row: what a requirements matrix states about one requirement of one source
/// specification, in a shape a system outside this repository can read without compiling it.
/// </summary>
/// <param name="Id">The source specification's own requirement identifier, verbatim — the key a consuming graph joins on.</param>
/// <param name="Requirement">The matrix's digest of the normative statement.</param>
/// <param name="Status">The coverage disposition, as the matrix's own enumeration names it.</param>
/// <param name="Evidence">The evidence the matrix cites: a test citation, a stated reason, or the statement that no primitive exists.</param>
/// <param name="EvidenceMethod">The <c>ClassName.MethodName</c> the evidence leads with when it resolves to a real test method of this assembly, otherwise <see langword="null"/>.</param>
/// <param name="ClaimIdCode">The stable claim-identifier code this repository allocates for the requirement, where one is allocated, otherwise <see langword="null"/>.</param>
internal sealed record ExportedRequirementRow(
    string Id,
    string Requirement,
    string Status,
    string Evidence,
    string? EvidenceMethod,
    int? ClaimIdCode);


/// <summary>One exported requirements matrix: every row of one matrix class, in the class's own order.</summary>
/// <param name="Name">The matrix class's simple name, which is also its identity in the artifact.</param>
/// <param name="Namespace">The namespace the matrix class lives in, so a reader can find it in the repository.</param>
/// <param name="Rows">Every row, in the order the matrix states them.</param>
internal sealed record ExportedRequirementMatrix(string Name, string Namespace, IReadOnlyList<ExportedRequirementRow> Rows);


/// <summary>
/// Reads every requirements matrix this test assembly ships and writes them as ONE machine-readable artifact,
/// so a system outside this repository can ingest the requirements-to-code mapping instead of re-deriving it
/// from source.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Why it exists.</strong> The matrices are the wave's record of which normative statement of which
/// specification is driven by which test. A consuming system assembling a provenance graph of requirements
/// mapped to code needs exactly that record, keyed on the specifications' own identifiers. Re-deriving it by
/// parsing C# source would be brittle; reading the compiled matrices is not.
/// </para>
/// <para>
/// <strong>Why it is test-side.</strong> Serialization is deliberately absent from every shipped library of
/// this repository — the libraries carry delegate seams and no JSON, XML or CBOR reference. The matrices
/// themselves are test code, so their export is test code too, and nothing in <c>src/</c> gains a dependency.
/// </para>
/// <para>
/// <strong>Determinism.</strong> The artifact carries no timestamp, no machine name and no run identifier, and
/// its matrices and rows are written in a stated order. Two runs over the same commit therefore produce
/// byte-identical output, so a consuming system can diff two artifacts and see requirement changes rather than
/// run noise.
/// </para>
/// <para>
/// <strong>Reading a matrix.</strong> Every matrix class of this assembly states its rows as a private static
/// array of four-element tuples — identifier, requirement digest, coverage status, evidence — and each has its
/// own coverage enumeration. This reader takes them through the tuple interface rather than through a shared
/// type, which is what lets one reader serve matrices that were written independently of it and of each other.
/// </para>
/// </remarks>
internal static class RequirementsMatrixExport
{
    /// <summary>The name of the private static member every matrix class states its rows in.</summary>
    private const string RowDataMemberName = "RowData";

    /// <summary>The suffix every requirements-matrix class of this assembly carries, by which a matrix that has not been listed for export can be found.</summary>
    internal const string MatrixClassSuffix = "RequirementsMatrixTests";


    /// <summary>
    /// Every requirements matrix this assembly ships, in the order the artifact writes them: the two of the
    /// eArchiving wave first, then the earlier signature and container waves in the order they were built.
    /// </summary>
    /// <remarks>
    /// The list is stated rather than discovered so the artifact's order is stable across runtimes;
    /// a test asserts that no matrix class of the assembly is missing from it.
    /// </remarks>
    internal static IReadOnlyList<Type> MatrixTypes { get; } =
    [
        typeof(EArkRequirementsMatrixTests),
        typeof(PreservationRequirementsMatrixTests),
        typeof(SignatureValidationRequirementsMatrixTests),
        typeof(CAdESRequirementsMatrixTests),
        typeof(AsicRequirementsMatrixTests),
        typeof(EvidenceRecordRequirementsMatrixTests)
    ];


    /// <summary>
    /// The claim-identifier registries whose allocations a row identifier is looked up in, so a consuming
    /// system can join a requirement to the stable integer code this repository allocates for it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The registries describe every allocation with the source specification's own identifier string, which
    /// is the same string a matrix row is keyed on — that identity is what makes the join possible at all, and
    /// it is asserted by the matrix classes themselves in both directions.
    /// </para>
    /// <para>
    /// The list is stated rather than discovered, for the same reason <see cref="MatrixTypes"/> is; a test
    /// asserts that no claim-identifier registry of the eArchiving namespace is missing from it, because a
    /// registry left off would leave every requirement it allocates for without a code in the consuming
    /// system's graph.
    /// </para>
    /// </remarks>
    internal static IReadOnlyList<Type> ClaimIdRegistries { get; } =
    [
        typeof(EArkClaimIds),
        typeof(PremisClaimIds),
        typeof(AipClaimIds),
        typeof(PreservationClaimIds)
    ];


    /// <summary>
    /// The deterministic path the artifact is written to: <c>requirements-matrix.json</c> under the test
    /// results directory beside the test binaries.
    /// </summary>
    /// <remarks>
    /// The path is derived from the test assembly's own location rather than from a runner-supplied directory,
    /// so the same run of the same build always writes the same file and a consuming system can fetch it by a
    /// path it knows in advance.
    /// </remarks>
    internal static string ArtifactPath { get; } =
        Path.Combine(AppContext.BaseDirectory, "TestResults", "requirements-matrix.json");


    /// <summary>Reads every matrix of <see cref="MatrixTypes"/>.</summary>
    /// <returns>The matrices, in the order <see cref="MatrixTypes"/> states them.</returns>
    internal static IReadOnlyList<ExportedRequirementMatrix> Read()
    {
        IReadOnlyDictionary<string, int> claimIdCodes = ReadClaimIdCodes();
        List<ExportedRequirementMatrix> matrices = new(MatrixTypes.Count);
        foreach(Type matrixType in MatrixTypes)
        {
            matrices.Add(ReadMatrix(matrixType, claimIdCodes));
        }

        return matrices;
    }


    /// <summary>Reads one matrix class's rows.</summary>
    /// <param name="matrixType">The matrix class.</param>
    /// <param name="claimIdCodes">The allocated claim-identifier codes, keyed on the specifications' own identifier strings.</param>
    /// <returns>The matrix, with its rows in the class's own order.</returns>
    internal static ExportedRequirementMatrix ReadMatrix(Type matrixType, IReadOnlyDictionary<string, int> claimIdCodes)
    {
        ArgumentNullException.ThrowIfNull(matrixType);
        ArgumentNullException.ThrowIfNull(claimIdCodes);

        PropertyInfo? rowData = matrixType.GetProperty(
            RowDataMemberName, BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static);
        if(rowData?.GetValue(null) is not Array rows)
        {
            throw new InvalidOperationException(
                $"{matrixType.Name} states no static {RowDataMemberName} member, so its rows cannot be exported.");
        }

        List<ExportedRequirementRow> exported = new(rows.Length);
        foreach(object? row in rows)
        {
            if(row is not ITuple tuple || tuple.Length != 4)
            {
                throw new InvalidOperationException(
                    $"{matrixType.Name}.{RowDataMemberName} holds something other than four-element rows.");
            }

            string id = (string)tuple[0]!;
            string requirement = (string)tuple[1]!;
            string status = tuple[2]!.ToString()!;
            string evidence = (string)tuple[3]!;

            exported.Add(new ExportedRequirementRow(
                Id: id,
                Requirement: requirement,
                Status: status,
                Evidence: evidence,
                EvidenceMethod: ResolveEvidenceMethod(evidence),
                ClaimIdCode: claimIdCodes.TryGetValue(id, out int code) ? code : null));
        }

        return new ExportedRequirementMatrix(matrixType.Name, matrixType.Namespace ?? string.Empty, exported);
    }


    /// <summary>
    /// Writes the matrices as one artifact at <paramref name="path"/>, creating the directory when it is not
    /// there and replacing any earlier artifact.
    /// </summary>
    /// <param name="path">Where to write.</param>
    /// <param name="matrices">The matrices to write.</param>
    internal static void Write(string path, IReadOnlyList<ExportedRequirementMatrix> matrices)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(matrices);

        string? directory = Path.GetDirectoryName(path);
        if(!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        using FileStream file = File.Create(path);
        using Utf8JsonWriter writer = new(file, new JsonWriterOptions { Indented = true });

        writer.WriteStartObject();
        writer.WriteNumber("schemaVersion"u8, 1);
        writer.WriteString("artifact"u8, "verifiable-requirements-matrix");
        writer.WriteNumber("matrixCount"u8, matrices.Count);
        writer.WriteNumber("rowCount"u8, matrices.Sum(matrix => matrix.Rows.Count));

        writer.WriteStartArray("matrices"u8);
        foreach(ExportedRequirementMatrix matrix in matrices)
        {
            writer.WriteStartObject();
            writer.WriteString("name"u8, matrix.Name);
            writer.WriteString("namespace"u8, matrix.Namespace);
            writer.WriteNumber("rowCount"u8, matrix.Rows.Count);

            writer.WriteStartObject("statusCounts"u8);
            foreach(IGrouping<string, ExportedRequirementRow> group in matrix.Rows
                .GroupBy(row => row.Status, StringComparer.Ordinal)
                .OrderBy(group => group.Key, StringComparer.Ordinal))
            {
                writer.WriteNumber(group.Key, group.Count());
            }

            writer.WriteEndObject();

            writer.WriteStartArray("rows"u8);
            foreach(ExportedRequirementRow row in matrix.Rows)
            {
                writer.WriteStartObject();
                writer.WriteString("id"u8, row.Id);
                writer.WriteString("requirement"u8, row.Requirement);
                writer.WriteString("status"u8, row.Status);
                writer.WriteString("evidence"u8, row.Evidence);

                if(row.EvidenceMethod is not null)
                {
                    writer.WriteString("evidenceMethod"u8, row.EvidenceMethod);
                }

                if(row.ClaimIdCode is int code)
                {
                    writer.WriteNumber("claimIdCode"u8, code);
                }

                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        writer.WriteEndObject();
        writer.Flush();
    }


    /// <summary>Reads the matrices and writes them to <see cref="ArtifactPath"/>.</summary>
    /// <returns>The matrices that were written.</returns>
    internal static IReadOnlyList<ExportedRequirementMatrix> WriteArtifact()
    {
        IReadOnlyList<ExportedRequirementMatrix> matrices = Read();
        Write(ArtifactPath, matrices);

        return matrices;
    }


    /// <summary>
    /// Finds every claim-identifier registry of the eArchiving namespace, so a registry that was allocated in
    /// but never listed for the join can be reported rather than leaving its requirements without a code in the
    /// consuming system's graph.
    /// </summary>
    /// <returns>Every type of <see cref="EArkClaimIds"/>' own namespace that allocates at least one <see cref="ClaimId"/>.</returns>
    internal static IReadOnlyList<Type> DiscoverClaimIdRegistries() =>
        [.. typeof(EArkClaimIds).Assembly.GetTypes()
            .Where(candidate =>
                string.Equals(candidate.Namespace, typeof(EArkClaimIds).Namespace, StringComparison.Ordinal)
                && candidate.GetProperties(BindingFlags.Public | BindingFlags.Static)
                    .Any(property => property.PropertyType == typeof(ClaimId)))
            .OrderBy(candidate => candidate.FullName, StringComparer.Ordinal)];


    /// <summary>
    /// Finds every requirements-matrix class of this assembly by its name, so a matrix that was written but
    /// never listed for export can be reported rather than silently omitted from the artifact.
    /// </summary>
    /// <returns>Every type whose name ends with <see cref="MatrixClassSuffix"/>.</returns>
    internal static IReadOnlyList<Type> DiscoverMatrixTypes() =>
        [.. typeof(RequirementsMatrixExport).Assembly.GetTypes()
            .Where(candidate => candidate.Name.EndsWith(MatrixClassSuffix, StringComparison.Ordinal))
            .OrderBy(candidate => candidate.FullName, StringComparer.Ordinal)];


    /// <summary>
    /// Reads every claim-identifier allocation the listed registries carry and derives the description-keyed
    /// lookup a matrix row joins through.
    /// </summary>
    /// <returns>The codes, keyed on the specifications' identifiers.</returns>
    internal static IReadOnlyDictionary<string, int> ReadClaimIdCodes() => ReadClaimIdCodes(ClaimIdRegistries);


    /// <summary>Reads the claim-identifier allocations of the registries given.</summary>
    /// <param name="registries">The classes whose public static <see cref="ClaimId"/> allocations are read.</param>
    /// <returns>The codes, keyed on the specifications' identifiers.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the allocations cannot be joined unambiguously: a code read twice, which means a registry is
    /// listed more than once, or one description carried by two codes, which means the key a matrix row joins
    /// through names two requirements.
    /// </exception>
    /// <remarks>
    /// <para>
    /// <strong>The walk is keyed on the code and the join is derived from it.</strong> The code is the only key
    /// the claim-identifier registry itself enforces uniqueness on — <c>ClaimId.Create</c> refuses an already
    /// allocated code and never examines the description — so the code is what an allocation is read under here,
    /// and the description travels with it as payload. The description-keyed lookup a matrix row needs is then
    /// built from that table, and a description two codes share is refused rather than resolved.
    /// </para>
    /// <para>
    /// <strong>Why refusing is the only sound answer.</strong> Writing the collision into the dictionary would
    /// leave the exported code of one requirement naming another requirement's allocation, chosen by whichever
    /// allocation the reflection walk visited last — and <c>Type.GetProperties</c> does not specify its order, so
    /// the artifact's byte-identical-across-runs guarantee would weaken without anything saying so. Every
    /// assertion the export carries on the field is satisfied by the wrong code, which is what makes the silent
    /// form of this unfindable.
    /// </para>
    /// </remarks>
    internal static IReadOnlyDictionary<string, int> ReadClaimIdCodes(IReadOnlyList<Type> registries)
    {
        ArgumentNullException.ThrowIfNull(registries);

        Dictionary<int, string> descriptionsByCode = [];
        Dictionary<string, int> codesByDescription = new(StringComparer.Ordinal);
        List<string> collisions = [];
        foreach(Type registry in registries)
        {
            foreach(PropertyInfo property in registry.GetProperties(BindingFlags.Public | BindingFlags.Static))
            {
                if(property.PropertyType != typeof(ClaimId))
                {
                    continue;
                }

                var claimId = (ClaimId)property.GetValue(null)!;
                string description = claimId.ToString();
                if(!descriptionsByCode.TryAdd(claimId.Code, description))
                {
                    collisions.Add(
                        $"code {claimId.Code} is read twice, as '{descriptionsByCode[claimId.Code]}' and as "
                        + $"{registry.Name}.{property.Name} ('{description}'), so a registry is listed more than once");

                    continue;
                }

                if(!codesByDescription.TryAdd(description, claimId.Code))
                {
                    collisions.Add(
                        $"description '{description}' is carried by both code {codesByDescription[description]} and "
                        + $"code {claimId.Code} ({registry.Name}.{property.Name}), so the key a matrix row joins "
                        + "through names two requirements");
                }
            }
        }

        if(collisions.Count > 0)
        {
            throw new InvalidOperationException(
                $"The claim-identifier allocations cannot be joined to the requirements matrices: {string.Join("; ", collisions)}.");
        }

        return codesByDescription;
    }


    /// <summary>
    /// Resolves the <c>ClassName.MethodName</c> token an evidence citation leads with, when it names a real
    /// test method of this assembly.
    /// </summary>
    /// <param name="evidence">The evidence citation.</param>
    /// <returns>The resolved <c>ClassName.MethodName</c>, or <see langword="null"/> when the evidence states a reason rather than a citation.</returns>
    private static string? ResolveEvidenceMethod(string evidence)
    {
        string[] parts = evidence.Split([' ', '('], 2, StringSplitOptions.RemoveEmptyEntries);
        if(parts.Length == 0)
        {
            return null;
        }

        string token = parts[0];
        int separatorIndex = token.LastIndexOf('.');
        if(separatorIndex <= 0 || separatorIndex == token.Length - 1)
        {
            return null;
        }

        string className = token[..separatorIndex];
        string methodName = token[(separatorIndex + 1)..];
        Type? evidenceType = typeof(RequirementsMatrixExport).Assembly.GetTypes()
            .FirstOrDefault(candidate => string.Equals(candidate.Name, className, StringComparison.Ordinal));
        if(evidenceType is null)
        {
            return null;
        }

        MethodInfo? evidenceMethod = evidenceType.GetMethod(
            methodName, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static);

        return evidenceMethod is not null && evidenceMethod.GetCustomAttributes(typeof(TestMethodAttribute), inherit: false).Length > 0
            ? $"{className}.{methodName}"
            : null;
    }
}
