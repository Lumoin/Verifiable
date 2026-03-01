using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Rfc6901JsonPointer = Verifiable.JsonPointer.JsonPointer;

namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// Delegate for selecting a JSON-LD fragment using a JSON Pointer.
/// </summary>
/// <param name="document">The compact JSON-LD document.</param>
/// <param name="pointer">The JSON Pointer identifying the fragment.</param>
/// <returns>
/// A valid JSON-LD document containing only the selected fragment,
/// wrapped with the original context and necessary path structure.
/// </returns>
public delegate string SelectJsonLdFragmentDelegate(string document, Rfc6901JsonPointer pointer);


/// <summary>
/// Delegate for selecting multiple JSON-LD fragments and merging them.
/// </summary>
/// <param name="document">The compact JSON-LD document.</param>
/// <param name="pointers">The JSON Pointers identifying fragments.</param>
/// <returns>
/// A valid JSON-LD document containing all selected fragments merged together.
/// </returns>
public delegate string SelectJsonLdFragmentsDelegate(string document, IEnumerable<Rfc6901JsonPointer> pointers);


/// <summary>
/// Delegate for partitioning N-Quad statements into mandatory and non-mandatory sets.
/// </summary>
/// <param name="document">The compact JSON-LD document.</param>
/// <param name="mandatoryPointers">JSON Pointers identifying mandatory claims.</param>
/// <param name="canonicalize">The canonicalization delegate (JSON-LD → N-Quads).</param>
/// <param name="contextResolver">
/// Optional delegate for resolving JSON-LD contexts during canonicalization.
/// Required for RDFC canonicalization, ignored by JCS canonicalization.
/// </param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>A task that resolves to the partition result containing statements and their indexes.</returns>
public delegate ValueTask<StatementPartitionResult> PartitionStatementsDelegate(
    string document,
    IReadOnlyList<Rfc6901JsonPointer> mandatoryPointers,
    CanonicalizationDelegate canonicalize,
    ContextResolverDelegate? contextResolver,
    CancellationToken cancellationToken = default);


/// <summary>
/// Result of partitioning N-Quad statements into mandatory and non-mandatory sets.
/// </summary>
/// <param name="AllStatements">All canonical N-Quad statements.</param>
/// <param name="MandatoryIndexes">Indexes of mandatory statements.</param>
/// <param name="NonMandatoryIndexes">Indexes of non-mandatory statements.</param>
/// <param name="LabelMap">
/// The RDFC label map from canonicalization, mapping canonical blank node identifiers
/// (e.g., <c>"c14n0"</c>) to original blank node identifiers. This is <see langword="null"/>
/// when JCS canonicalization was used.
/// </param>
/// <remarks>
/// <para>
/// The indexes can be applied to HMAC-relabeled statements since relabeling
/// preserves statement order.
/// </para>
/// <para>
/// The <paramref name="LabelMap"/> is passed through from the
/// <see cref="CanonicalizationResult.LabelMap"/> produced during canonicalization.
/// Selective disclosure cryptosuites use this to compute correct blank node mappings
/// when the reduced credential is canonicalized independently of the full credential.
/// </para>
/// </remarks>
public readonly record struct StatementPartitionResult(
    IReadOnlyList<string> AllStatements,
    IReadOnlyList<int> MandatoryIndexes,
    IReadOnlyList<int> NonMandatoryIndexes,
    IReadOnlyDictionary<string, string>? LabelMap = null)
{
    /// <summary>
    /// Gets the mandatory statements.
    /// </summary>
    public IReadOnlyList<string> MandatoryStatements
    {
        get
        {
            var result = new List<string>(MandatoryIndexes.Count);
            foreach(int index in MandatoryIndexes)
            {
                result.Add(AllStatements[index]);
            }

            return result;
        }
    }

    /// <summary>
    /// Gets the non-mandatory statements.
    /// </summary>
    public IReadOnlyList<string> NonMandatoryStatements
    {
        get
        {
            var result = new List<string>(NonMandatoryIndexes.Count);
            foreach(int index in NonMandatoryIndexes)
            {
                result.Add(AllStatements[index]);
            }

            return result;
        }
    }


    /// <summary>
    /// Applies the partition indexes to a list of (possibly relabeled) statements.
    /// </summary>
    /// <param name="statements">The statements to partition.</param>
    /// <returns>A tuple of (mandatory statements, non-mandatory statements).</returns>
    public (IReadOnlyList<string> Mandatory, IReadOnlyList<string> NonMandatory) ApplyTo(
        IReadOnlyList<string> statements)
    {
        ArgumentNullException.ThrowIfNull(statements);

        var mandatorySet = new HashSet<int>(MandatoryIndexes);
        var mandatory = new List<string>();
        var nonMandatory = new List<string>();

        for(int i = 0; i < statements.Count; i++)
        {
            if(mandatorySet.Contains(i))
            {
                mandatory.Add(statements[i]);
            }
            else
            {
                nonMandatory.Add(statements[i]);
            }
        }

        return (mandatory, nonMandatory);
    }
}