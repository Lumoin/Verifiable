using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.Model.DataIntegrity;


/// <summary>
/// Result of blank node relabeling, containing both relabeled statements and the label map.
/// </summary>
/// <remarks>
/// <para>
/// This type captures the complete output of the blank node relabeling process,
/// which is needed for both creating base proofs and derived proofs in ECDSA-SD-2023.
/// </para>
/// <para>
/// <strong>Label Map:</strong> Maps canonical blank node identifiers (e.g., "_:c14n0")
/// to their HMAC-derived replacements (e.g., "_:uXYZ..."). This mapping is required
/// when creating derived proofs to enable the verifier to reconstruct the statements.
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-di-ecdsa/#add-base-proof-ecdsa-sd-2023">
/// VC Data Integrity ECDSA Cryptosuites: Add Base Proof (ecdsa-sd-2023)</see>.
/// </para>
/// </remarks>
[DebuggerDisplay("Statements: {Statements.Count}, Labels: {LabelMap.Count}")]
public readonly struct RelabelingResult: IEquatable<RelabelingResult>
{
    /// <summary>
    /// The relabeled N-Quad statements with HMAC-derived blank node identifiers.
    /// </summary>
    public IReadOnlyList<string> Statements { get; }

    /// <summary>
    /// Mapping from canonical blank node identifiers to HMAC-derived identifiers.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Keys are in the format <c>"c14n0"</c>, <c>"c14n1"</c>, etc. Values are in the format
    /// <c>"uXYZ..."</c>. Both use bare identifiers without the <c>"_:"</c> prefix, matching
    /// the compressed label map format defined in
    /// <see href="https://www.w3.org/TR/vc-di-ecdsa/#compresslabelmap">
    /// VC Data Integrity ECDSA §3.5.5 compressLabelMap</see>.
    /// </para>
    /// <para>
    /// Note that the RDFC specification (<see href="https://www.w3.org/TR/rdf-canon/">W3C
    /// Recommendation §4.3</see>) uses <c>"_:"</c>-prefixed identifiers in its issued identifiers
    /// map. The <c>"_:"</c> prefix is stripped during HMAC relabeling to match the VC DI ECDSA
    /// wire format. See <see cref="CanonicalizationResult.LabelMap"/> for the RDFC-format map.
    /// </para>
    /// </remarks>
    public IReadOnlyDictionary<string, string> LabelMap { get; }


    /// <summary>
    /// Creates a new relabeling result.
    /// </summary>
    /// <param name="statements">The relabeled N-Quad statements.</param>
    /// <param name="labelMap">The mapping from canonical to HMAC-derived identifiers.</param>
    public RelabelingResult(IReadOnlyList<string> statements, IReadOnlyDictionary<string, string> labelMap)
    {
        Statements = statements ?? throw new ArgumentNullException(nameof(statements));
        LabelMap = labelMap ?? throw new ArgumentNullException(nameof(labelMap));
    }


    /// <summary>
    /// Deconstructs the result into its components.
    /// </summary>
    public void Deconstruct(out IReadOnlyList<string> statements, out IReadOnlyDictionary<string, string> labelMap)
    {
        statements = Statements;
        labelMap = LabelMap;
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(RelabelingResult other)
    {
        if(Statements.Count != other.Statements.Count || LabelMap.Count != other.LabelMap.Count)
        {
            return false;
        }

        for(int i = 0; i < Statements.Count; i++)
        {
            if(Statements[i] != other.Statements[i])
            {
                return false;
            }
        }

        foreach(var kvp in LabelMap)
        {
            if(!other.LabelMap.TryGetValue(kvp.Key, out var otherValue) || kvp.Value != otherValue)
            {
                return false;
            }
        }

        return true;
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is RelabelingResult other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Statements.Count);
        hash.Add(LabelMap.Count);
        return hash.ToHashCode();
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(RelabelingResult left, RelabelingResult right) => left.Equals(right);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(RelabelingResult left, RelabelingResult right) => !left.Equals(right);
}