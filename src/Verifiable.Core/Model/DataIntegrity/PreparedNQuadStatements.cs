using System;
using System.Collections.Generic;
using System.Linq;
using Verifiable.Cryptography;

namespace Verifiable.Core.Model.DataIntegrity;


/// <summary>
/// Prepared N-Quad statements for ECDSA-SD-2023 selective disclosure.
/// </summary>
/// <remarks>
/// <para>
/// This type contains statements that have been HMAC-relabeled and sorted alphabetically
/// as required by the W3C ecdsa-sd-2023 specification. The indexes refer to positions
/// in the sorted statement list.
/// </para>
/// <para>
/// Use <see cref="NQuadStatementPreparation.Prepare"/> to create instances.
/// </para>
/// </remarks>
public sealed class PreparedNQuadStatements
{
    /// <summary>
    /// HMAC-relabeled statements sorted alphabetically.
    /// </summary>
    public required IReadOnlyList<string> SortedStatements { get; init; }

    /// <summary>
    /// Mapping from canonical blank node IDs (e.g., "c14n0") to HMAC-derived IDs (e.g., "u...").
    /// </summary>
    public required IReadOnlyDictionary<string, string> LabelMap { get; init; }

    /// <summary>
    /// Indexes of mandatory statements in the sorted list.
    /// </summary>
    public required IReadOnlySet<int> MandatoryIndexes { get; init; }

    /// <summary>
    /// Indexes of non-mandatory (disclosable) statements in the sorted list.
    /// </summary>
    public required IReadOnlySet<int> NonMandatoryIndexes { get; init; }
}


/// <summary>
/// Prepares N-Quad statements for ECDSA-SD-2023 selective disclosure.
/// </summary>
/// <remarks>
/// <para>
/// This class transforms canonicalized N-Quad statements into the form required by
/// the W3C ecdsa-sd-2023 specification:
/// </para>
/// <list type="number">
/// <item><description>HMAC-relabel blank node identifiers for privacy.</description></item>
/// <item><description>Sort statements alphabetically.</description></item>
/// <item><description>Compute indexes into the sorted list.</description></item>
/// </list>
/// <para>
/// The input is a <c>StatementPartitionResult</c> from JSON-LD selection, which contains
/// pre-HMAC canonical indexes. The output contains indexes into the final sorted list.
/// </para>
/// </remarks>
public static class NQuadStatementPreparation
{
    /// <summary>
    /// Prepares statements by HMAC-relabeling and sorting.
    /// </summary>
    /// <param name="allStatements">All canonical N-Quad statements.</param>
    /// <param name="mandatoryIndexes">Indexes of mandatory statements in the canonical (unsorted) list.</param>
    /// <param name="hmacKey">The 32-byte HMAC key for blank node relabeling.</param>
    /// <param name="hmac">The HMAC function (typically HMAC-SHA256).</param>
    /// <param name="encoder">Base64URL encoder for HMAC label generation.</param>
    /// <returns>Prepared statements with sorted indexes.</returns>
    /// <remarks>
    /// <para>
    /// The <paramref name="mandatoryIndexes"/> refer to positions in <paramref name="allStatements"/>
    /// (the canonical, unsorted list). The returned <see cref="PreparedNQuadStatements.MandatoryIndexes"/>
    /// refer to positions in the sorted, HMAC-relabeled list.
    /// </para>
    /// <para>
    /// Use this method when creating a base proof (issuer side) where new HMAC labels are computed.
    /// For derived proofs where an existing label map must be applied, use
    /// <see cref="PrepareWithLabelMap"/> instead.
    /// </para>
    /// </remarks>
    public static PreparedNQuadStatements Prepare(
        IReadOnlyList<string> allStatements,
        IReadOnlyList<int> mandatoryIndexes,
        ReadOnlySpan<byte> hmacKey,
        HmacComputeDelegate hmac,
        EncodeDelegate encoder)
    {
        ArgumentNullException.ThrowIfNull(allStatements);
        ArgumentNullException.ThrowIfNull(mandatoryIndexes);
        ArgumentNullException.ThrowIfNull(hmac);
        ArgumentNullException.ThrowIfNull(encoder);

        //HMAC relabel blank nodes.
        var relabelingResult = BlankNodeRelabeling.RelabelNQuadsWithMap(
            allStatements,
            hmacKey,
            hmac,
            encoder);

        var relabeledStatements = relabelingResult.Statements.ToList();

        //Sort relabeled statements alphabetically as required by W3C ecdsa-sd-2023 spec.
        var sortedStatements = relabeledStatements
            .OrderBy(s => s, StringComparer.Ordinal)
            .ToList();

        //Build set of mandatory relabeled statements to find their sorted indexes.
        var mandatoryRelabeled = new HashSet<string>(StringComparer.Ordinal);
        foreach(int idx in mandatoryIndexes)
        {
            mandatoryRelabeled.Add(relabeledStatements[idx]);
        }

        //Compute mandatory and non-mandatory indexes in the sorted list.
        var sortedMandatoryIndexes = new HashSet<int>();
        var sortedNonMandatoryIndexes = new HashSet<int>();

        for(int i = 0; i < sortedStatements.Count; i++)
        {
            if(mandatoryRelabeled.Contains(sortedStatements[i]))
            {
                sortedMandatoryIndexes.Add(i);
            }
            else
            {
                sortedNonMandatoryIndexes.Add(i);
            }
        }

        return new PreparedNQuadStatements
        {
            SortedStatements = sortedStatements,
            LabelMap = relabelingResult.LabelMap,
            MandatoryIndexes = sortedMandatoryIndexes,
            NonMandatoryIndexes = sortedNonMandatoryIndexes
        };
    }


    /// <summary>
    /// Prepares statements by applying an existing label map and sorting.
    /// </summary>
    /// <param name="allStatements">All canonical N-Quad statements.</param>
    /// <param name="mandatoryIndexes">Indexes of mandatory statements in the canonical (unsorted) list.</param>
    /// <param name="labelMap">Existing label map from the base proof to apply.</param>
    /// <returns>Prepared statements with sorted indexes.</returns>
    /// <remarks>
    /// <para>
    /// Use this method when deriving a proof from a reduced credential. The reduced credential
    /// may have different canonical blank node assignments than the full credential, but must use
    /// the same HMAC-derived labels from the original base proof to ensure signature matching.
    /// </para>
    /// <para>
    /// The <paramref name="labelMap"/> should come from the parsed base proof and maps canonical
    /// identifiers (e.g., "c14n0") to HMAC-derived identifiers (e.g., "uXYZ...").
    /// </para>
    /// </remarks>
    public static PreparedNQuadStatements PrepareWithLabelMap(
        IReadOnlyList<string> allStatements,
        IReadOnlyList<int> mandatoryIndexes,
        IReadOnlyDictionary<string, string> labelMap)
    {
        ArgumentNullException.ThrowIfNull(allStatements);
        ArgumentNullException.ThrowIfNull(mandatoryIndexes);
        ArgumentNullException.ThrowIfNull(labelMap);

        //Apply existing label map to relabel blank nodes.
        var relabeledStatements = BlankNodeRelabelingExtensions.ApplyLabelMap(allStatements, labelMap);

        //Sort relabeled statements alphabetically as required by W3C ecdsa-sd-2023 spec.
        var sortedStatements = relabeledStatements
            .OrderBy(s => s, StringComparer.Ordinal)
            .ToList();

        //Build set of mandatory relabeled statements to find their sorted indexes.
        var mandatoryRelabeled = new HashSet<string>(StringComparer.Ordinal);
        foreach(int idx in mandatoryIndexes)
        {
            mandatoryRelabeled.Add(relabeledStatements[idx]);
        }

        //Compute mandatory and non-mandatory indexes in the sorted list.
        var sortedMandatoryIndexes = new HashSet<int>();
        var sortedNonMandatoryIndexes = new HashSet<int>();

        for(int i = 0; i < sortedStatements.Count; i++)
        {
            if(mandatoryRelabeled.Contains(sortedStatements[i]))
            {
                sortedMandatoryIndexes.Add(i);
            }
            else
            {
                sortedNonMandatoryIndexes.Add(i);
            }
        }

        return new PreparedNQuadStatements
        {
            SortedStatements = sortedStatements,
            LabelMap = labelMap.ToDictionary(kvp => kvp.Key, kvp => kvp.Value),
            MandatoryIndexes = sortedMandatoryIndexes,
            NonMandatoryIndexes = sortedNonMandatoryIndexes
        };
    }
}