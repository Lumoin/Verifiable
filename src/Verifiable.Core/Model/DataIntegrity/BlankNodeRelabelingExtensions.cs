namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// Extension methods and utilities for blank node relabeling operations.
/// </summary>
/// <remarks>
/// <para>
/// This class provides utility functions for working with blank node relabeling results,
/// including extracting label maps from already-relabeled statements and parsing
/// blank node identifiers.
/// </para>
/// </remarks>
public static class BlankNodeRelabelingExtensions
{
    /// <summary>
    /// Applies an existing label map to relabel blank nodes in N-Quad statements.
    /// </summary>
    /// <param name="nquads">The canonical N-Quad statements with <c>_:c14nN</c> identifiers.</param>
    /// <param name="labelMap">
    /// Mapping from canonical identifiers to HMAC-derived identifiers in bare format
    /// (e.g., <c>"c14n0" → "uXYZ"</c>) per
    /// <see href="https://www.w3.org/TR/vc-di-ecdsa/#compresslabelmap">
    /// VC Data Integrity ECDSA §3.5.5 compressLabelMap</see>.
    /// </param>
    /// <returns>The relabeled statements with HMAC-derived blank node identifiers.</returns>
    /// <remarks>
    /// <para>
    /// This method is used by verifiers who receive a label map in the derived proof
    /// and need to apply it to re-canonicalized statements. Unlike
    /// <see cref="BlankNodeRelabeling.RelabelNQuadsWithMapAsync"/>, this does not compute
    /// HMAC values - it uses the pre-computed mappings from the label map.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-di-ecdsa/#verify-derived-proof-ecdsa-sd-2023">
    /// VC Data Integrity ECDSA Cryptosuites: Verify Derived Proof (ecdsa-sd-2023)</see>.
    /// </para>
    /// </remarks>
    public static IReadOnlyList<string> ApplyLabelMap(
        IEnumerable<string> nquads,
        IReadOnlyDictionary<string, string> labelMap)
    {
        ArgumentNullException.ThrowIfNull(nquads);
        ArgumentNullException.ThrowIfNull(labelMap);

        var statements = new List<string>();
        foreach(var nquad in nquads)
        {
            statements.Add(ApplyLabelMapToStatement(nquad, labelMap));
        }

        return statements;
    }


    /// <summary>
    /// Applies an existing label map to relabel blank nodes in a single N-Quad statement.
    /// </summary>
    /// <param name="nquad">The canonical N-Quad statement with <c>_:c14nN</c> identifiers.</param>
    /// <param name="labelMap">
    /// Mapping from canonical identifiers to HMAC-derived identifiers in bare format
    /// (e.g., <c>"c14n0" → "uXYZ"</c>) per
    /// <see href="https://www.w3.org/TR/vc-di-ecdsa/#compresslabelmap">
    /// VC Data Integrity ECDSA §3.5.5 compressLabelMap</see>.
    /// </param>
    /// <returns>The relabeled statement with HMAC-derived blank node identifiers.</returns>
    public static string ApplyLabelMapToStatement(
        string nquad,
        IReadOnlyDictionary<string, string> labelMap)
    {
        ArgumentNullException.ThrowIfNull(nquad);
        ArgumentNullException.ThrowIfNull(labelMap);

        var result = nquad;
        var searchStart = 0;
        while(NQuadBlankNodeScanner.FindNext(result, searchStart) is (int markerStart, int identifierEnd))
        {
            //A blank node term at a position that is not canonical (_:c14nN) carries nothing to
            //relabel here; move past it.
            var fullBlankNodeId = result[markerStart..identifierEnd];
            if(!IsCanonicalBlankNode(fullBlankNodeId))
            {
                searchStart = identifierEnd;
                continue;
            }

            var canonicalId = fullBlankNodeId[2..];

            //Look up the HMAC-derived identifier.
            if(labelMap.TryGetValue(canonicalId, out var hmacId))
            {
                var hmacFullId = "_:" + hmacId;
                result = string.Concat(result.AsSpan(0, markerStart), hmacFullId, result.AsSpan(identifierEnd));
                searchStart = markerStart + hmacFullId.Length;
            }
            else
            {
                //No mapping found, skip this blank node.
                searchStart = identifierEnd;
            }
        }

        return result;
    }


    /// <summary>
    /// Extracts the label map by comparing original and relabeled N-Quad statements.
    /// </summary>
    /// <param name="originalStatements">The canonicalized statements with <c>_:c14nN</c> identifiers.</param>
    /// <param name="relabeledStatements">The relabeled statements with HMAC-derived identifiers.</param>
    /// <returns>
    /// Mapping from canonical labels to HMAC-derived labels in bare format per
    /// <see href="https://www.w3.org/TR/vc-di-ecdsa/#compresslabelmap">
    /// VC Data Integrity ECDSA §3.5.5 compressLabelMap</see>.
    /// </returns>
    /// <exception cref="ArgumentException">
    /// Thrown if the statement counts don't match or if blank node counts differ within a statement.
    /// </exception>
    /// <remarks>
    /// <para>
    /// This method is useful when you have already relabeled statements but did not capture
    /// the label map during the relabeling process. It reconstructs the mapping by comparing
    /// blank node identifiers at corresponding positions.
    /// </para>
    /// <para>
    /// The method assumes that blank nodes appear in the same order in both the original
    /// and relabeled statements, which is guaranteed by the relabeling algorithm.
    /// </para>
    /// </remarks>
    public static IReadOnlyDictionary<string, string> ExtractLabelMap(
        IReadOnlyList<string> originalStatements,
        IReadOnlyList<string> relabeledStatements)
    {
        ArgumentNullException.ThrowIfNull(originalStatements);
        ArgumentNullException.ThrowIfNull(relabeledStatements);

        if(originalStatements.Count != relabeledStatements.Count)
        {
            throw new ArgumentException(
                $"Statement counts must match. Original: {originalStatements.Count}, Relabeled: {relabeledStatements.Count}.");
        }

        var labelMap = new Dictionary<string, string>();

        for(int i = 0; i < originalStatements.Count; i++)
        {
            var originalNodes = ExtractBlankNodes(originalStatements[i]);
            var relabeledNodes = ExtractBlankNodes(relabeledStatements[i]);
            if(originalNodes.Count != relabeledNodes.Count)
            {
                throw new ArgumentException(
                    $"Blank node counts must match in statement {i}. " +
                    $"Original: {originalNodes.Count}, Relabeled: {relabeledNodes.Count}.");
            }

            for(int j = 0; j < originalNodes.Count; j++)
            {
                var originalId = originalNodes[j];
                var relabeledId = relabeledNodes[j];

                //Only add canonical -> HMAC mappings (skip if already HMAC or same).
                //Store in bare format per VC DI ECDSA §3.5.5 compressLabelMap.
                if(originalId.StartsWith(BlankNodeRelabeling.CanonicalBlankNodePrefix, StringComparison.Ordinal))
                {
                    var canonicalKey = originalId[2..]; //Strip "_:" prefix for bare format.
                    var hmacValue = relabeledId[2..]; //Strip "_:" prefix for bare format.
                    _ = labelMap.TryAdd(canonicalKey, hmacValue);
                }
            }
        }

        return labelMap;
    }


    /// <summary>
    /// Extracts all blank node identifiers from an N-Quad statement.
    /// </summary>
    /// <param name="nquad">The N-Quad statement.</param>
    /// <returns>
    /// A list of blank node identifiers in order of appearance, with the <c>"_:"</c>
    /// prefix included (e.g., <c>"_:c14n0"</c>, <c>"_:uXYZ..."</c>).
    /// </returns>
    public static IReadOnlyList<string> ExtractBlankNodes(string nquad)
    {
        ArgumentNullException.ThrowIfNull(nquad);

        var result = new List<string>();
        var searchStart = 0;
        while(NQuadBlankNodeScanner.FindNext(nquad, searchStart) is (int markerStart, int identifierEnd))
        {
            result.Add(nquad[markerStart..identifierEnd]);
            searchStart = identifierEnd;
        }

        return result;
    }


    /// <summary>
    /// Checks if a blank node identifier is in canonical format (<c>_:c14nN</c>).
    /// </summary>
    /// <param name="blankNodeId">The blank node identifier to check.</param>
    /// <returns><see langword="true"/> if canonical; otherwise <see langword="false"/>.</returns>
    public static bool IsCanonicalBlankNode(string blankNodeId)
    {
        ArgumentNullException.ThrowIfNull(blankNodeId);

        return blankNodeId.StartsWith(BlankNodeRelabeling.CanonicalBlankNodePrefix, StringComparison.Ordinal);
    }


    /// <summary>
    /// Checks if a blank node identifier is in HMAC-relabeled format (<c>_:uXXX</c>).
    /// </summary>
    /// <param name="blankNodeId">The blank node identifier to check.</param>
    /// <returns><see langword="true"/> if HMAC-relabeled; otherwise <see langword="false"/>.</returns>
    public static bool IsHmacBlankNode(string blankNodeId)
    {
        ArgumentNullException.ThrowIfNull(blankNodeId);

        return blankNodeId.StartsWith(BlankNodeRelabeling.HmacBlankNodePrefix, StringComparison.Ordinal);
    }


    /// <summary>
    /// Determines whether any canonical (<c>_:c14nN</c>) blank node in <paramref name="nquads"/>
    /// has no entry in <paramref name="labelMap"/>.
    /// </summary>
    /// <param name="nquads">The canonical N-Quad statements to check.</param>
    /// <param name="labelMap">
    /// Mapping from canonical identifiers to relabeled identifiers, keyed in bare format
    /// (e.g., <c>"c14n0"</c>) per
    /// <see href="https://www.w3.org/TR/vc-di-ecdsa/#compresslabelmap">
    /// VC Data Integrity ECDSA §3.5.5 compressLabelMap</see>.
    /// </param>
    /// <returns>
    /// <see langword="true"/> if some canonical blank node in <paramref name="nquads"/> has no
    /// corresponding entry in <paramref name="labelMap"/>; otherwise <see langword="false"/>.
    /// </returns>
    /// <remarks>
    /// <para>
    /// A verifier canonicalizes the disclosed document with its own RDF Dataset Canonicalization
    /// implementation, which is not required to assign a graph's blank nodes the same canonical
    /// labels a different conformant implementation assigned to the same graph
    /// (<see href="https://www.w3.org/TR/rdf-canon/">RDF Dataset Canonicalization 1.0</see>
    /// defines a deterministic result per conformant implementation, not a label assignment
    /// shared across implementations). When the proof's label map does not cover every canonical
    /// blank node the verifier's own canonicalization produced, applying it would leave one or
    /// more blank nodes under a label the base signature never bound, so verification refuses
    /// rather than check content that was not what was signed.
    /// </para>
    /// </remarks>
    public static bool HasUnmappedCanonicalBlankNode(
        IEnumerable<string> nquads,
        IReadOnlyDictionary<string, string> labelMap)
    {
        ArgumentNullException.ThrowIfNull(nquads);
        ArgumentNullException.ThrowIfNull(labelMap);

        foreach(var nquad in nquads)
        {
            foreach(var blankNode in ExtractBlankNodes(nquad))
            {
                if(IsCanonicalBlankNode(blankNode) && !labelMap.ContainsKey(blankNode[2..]))
                {
                    return true;
                }
            }
        }

        return false;
    }
}
