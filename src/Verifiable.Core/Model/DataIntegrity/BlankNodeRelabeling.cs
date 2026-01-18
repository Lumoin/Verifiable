using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Text.RegularExpressions;
using Verifiable.Cryptography;

namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// Delegate for computing an HMAC over data.
/// </summary>
/// <param name="key">The HMAC key.</param>
/// <param name="data">The data to compute the HMAC over.</param>
/// <returns>The HMAC result bytes.</returns>
/// <remarks>
/// <para>
/// This delegate abstracts the HMAC computation, allowing different implementations
/// (e.g., <c>HMACSHA256.HashData</c> from System.Security.Cryptography) to be plugged in.
/// </para>
/// </remarks>
public delegate byte[] HmacComputeDelegate(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data);


/// <summary>
/// Delegate for relabeling a single blank node identifier using HMAC.
/// </summary>
/// <param name="blankNodeId">The original blank node identifier (e.g., "c14n0").</param>
/// <param name="hmacKey">The HMAC key for generating the new identifier.</param>
/// <param name="hmacCompute">The HMAC computation function.</param>
/// <param name="base64UrlEncode">The Base64Url encoding function.</param>
/// <returns>The relabeled blank node identifier (e.g., "uXXX...").</returns>
/// <remarks>
/// <para>
/// ECDSA-SD-2023 uses HMAC-based blank node relabeling to provide unlinkability
/// between the base proof and derived proofs. The canonical blank node identifiers
/// (c14n0, c14n1, etc.) are replaced with HMAC-derived identifiers.
/// </para>
/// </remarks>
public delegate string BlankNodeRelabelDelegate(
    string blankNodeId,
    ReadOnlySpan<byte> hmacKey,
    HmacComputeDelegate hmacCompute,
    EncodeDelegate base64UrlEncode);


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
    /// Keys are in the format "c14n0", "c14n1", etc. (without the "_:" prefix).
    /// Values are in the format "uXYZ..." (without the "_:" prefix).
    /// This compact format is used for CBOR serialization efficiency.
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


/// <summary>
/// Utilities for blank node relabeling in selective disclosure cryptosuites.
/// </summary>
/// <remarks>
/// <para>
/// This class provides the algorithm for relabeling blank nodes in N-Quad statements,
/// as required by ECDSA-SD-2023 and similar selective disclosure cryptosuites.
/// </para>
/// <para>
/// The relabeling process:
/// </para>
/// <list type="number">
/// <item><description>Find blank node references in the format <c>_:c14nN</c>.</description></item>
/// <item><description>Compute HMAC over the identifier (e.g., "c14n0").</description></item>
/// <item><description>Base64Url encode the HMAC result.</description></item>
/// <item><description>Replace with <c>_:uXXX</c> format.</description></item>
/// </list>
/// <para>
/// See <see href="https://w3c.github.io/vc-di-ecdsa/#hmac-and-signatures">
/// W3C VC DI ECDSA §3.3.5 HMAC and Signatures</see>.
/// </para>
/// </remarks>
public static class BlankNodeRelabeling
{
    /// <summary>
    /// The prefix for canonical blank node identifiers from RDF canonicalization.
    /// </summary>
    public const string CanonicalBlankNodePrefix = "_:c14n";

    /// <summary>
    /// The prefix for HMAC-relabeled blank node identifiers.
    /// </summary>
    public const string HmacBlankNodePrefix = "_:u";


    /// <summary>
    /// Relabels all blank nodes in an N-Quad statement using HMAC.
    /// </summary>
    /// <param name="nquad">The N-Quad statement containing blank nodes.</param>
    /// <param name="hmacKey">The HMAC key for generating new identifiers.</param>
    /// <param name="hmacCompute">The HMAC computation function.</param>
    /// <param name="base64UrlEncode">The Base64Url encoding function.</param>
    /// <returns>The N-Quad with all blank nodes relabeled.</returns>
    /// <remarks>
    /// <para>
    /// This method finds all occurrences of <c>_:c14nN</c> patterns in the N-Quad
    /// and replaces them with HMAC-derived identifiers in <c>_:uXXX</c> format.
    /// </para>
    /// </remarks>
    public static string RelabelNQuad(
        string nquad,
        ReadOnlySpan<byte> hmacKey,
        HmacComputeDelegate hmacCompute,
        EncodeDelegate base64UrlEncode)
    {
        return RelabelNQuadWithMap(nquad, hmacKey, hmacCompute, base64UrlEncode, labelMap: null);
    }


    /// <summary>
    /// Relabels all blank nodes in an N-Quad statement using HMAC and records the mapping.
    /// </summary>
    /// <param name="nquad">The N-Quad statement containing blank nodes.</param>
    /// <param name="hmacKey">The HMAC key for generating new identifiers.</param>
    /// <param name="hmacCompute">The HMAC computation function.</param>
    /// <param name="base64UrlEncode">The Base64Url encoding function.</param>
    /// <param name="labelMap">
    /// Optional dictionary to populate with the label mappings. If provided, mappings
    /// from canonical identifiers (e.g., "_:c14n0") to HMAC identifiers (e.g., "_:uXYZ")
    /// will be added.
    /// </param>
    /// <returns>The N-Quad with all blank nodes relabeled.</returns>
    public static string RelabelNQuadWithMap(
        string nquad,
        ReadOnlySpan<byte> hmacKey,
        HmacComputeDelegate hmacCompute,
        EncodeDelegate base64UrlEncode,
        Dictionary<string, string>? labelMap)
    {
        ArgumentNullException.ThrowIfNull(nquad);
        ArgumentNullException.ThrowIfNull(hmacCompute);
        ArgumentNullException.ThrowIfNull(base64UrlEncode);

        var result = nquad;
        var searchStart = 0;

        while(true)
        {
            //Find the next blank node pattern "_:c".
            var index = result.IndexOf("_:c", searchStart, StringComparison.Ordinal);
            if(index < 0)
            {
                break;
            }

            //Find the end of the blank node identifier (digits after "c14n" or similar).
            var endIndex = index + 3;
            while(endIndex < result.Length && (char.IsLetterOrDigit(result[endIndex]) || result[endIndex] == 'n'))
            {
                endIndex++;
            }

            //Extract the blank node identifier (without the "_:" prefix).
            var blankNodeId = result[(index + 2)..endIndex];
            var canonicalId = blankNodeId;

            //Compute HMAC and encode.
            var hmacBytes = hmacCompute(hmacKey, System.Text.Encoding.UTF8.GetBytes(blankNodeId));
            var hmacId = "u" + base64UrlEncode(hmacBytes);
            var hmacFullId = "_:" + hmacId;

            //Record the mapping if requested. Keys are stored without "_:" prefix for CBOR compactness.
            labelMap?.TryAdd(canonicalId, hmacId);

            //Replace in result.
            result = string.Concat(result.AsSpan(0, index), hmacFullId, result.AsSpan(endIndex));
            searchStart = index + hmacFullId.Length;
        }

        return result;
    }


    /// <summary>
    /// Relabels all blank nodes in a collection of N-Quad statements.
    /// </summary>
    /// <param name="nquads">The N-Quad statements.</param>
    /// <param name="hmacKey">The HMAC key for generating new identifiers.</param>
    /// <param name="hmacCompute">The HMAC computation function.</param>
    /// <param name="base64UrlEncode">The Base64Url encoding function.</param>
    /// <returns>The relabeled N-Quad statements.</returns>
    public static IReadOnlyList<string> RelabelNQuads(
        IEnumerable<string> nquads,
        ReadOnlySpan<byte> hmacKey,
        HmacComputeDelegate hmacCompute,
        EncodeDelegate base64UrlEncode)
    {
        return RelabelNQuadsWithMap(nquads, hmacKey, hmacCompute, base64UrlEncode).Statements;
    }


    /// <summary>
    /// Relabels all blank nodes in a collection of N-Quad statements and returns the label map.
    /// </summary>
    /// <param name="nquads">The N-Quad statements.</param>
    /// <param name="hmacKey">The HMAC key for generating new identifiers.</param>
    /// <param name="hmacCompute">The HMAC computation function.</param>
    /// <param name="base64UrlEncode">The Base64Url encoding function.</param>
    /// <returns>
    /// A <see cref="RelabelingResult"/> containing both the relabeled statements
    /// and the mapping from canonical to HMAC-derived identifiers.
    /// </returns>
    /// <remarks>
    /// <para>
    /// Use this method when you need both the relabeled statements and the label map,
    /// such as when creating ECDSA-SD-2023 base proofs.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-di-ecdsa/#add-base-proof-ecdsa-sd-2023">
    /// VC Data Integrity ECDSA Cryptosuites: Add Base Proof (ecdsa-sd-2023)</see>.
    /// </para>
    /// </remarks>
    public static RelabelingResult RelabelNQuadsWithMap(
        IEnumerable<string> nquads,
        ReadOnlySpan<byte> hmacKey,
        HmacComputeDelegate hmacCompute,
        EncodeDelegate base64UrlEncode)
    {
        ArgumentNullException.ThrowIfNull(nquads);

        var statements = new List<string>();
        var labelMap = new Dictionary<string, string>();

        foreach(var nquad in nquads)
        {
            statements.Add(RelabelNQuadWithMap(nquad, hmacKey, hmacCompute, base64UrlEncode, labelMap));
        }

        return new RelabelingResult(statements, labelMap);
    }


    /// <summary>
    /// Creates a default blank node relabeling function.
    /// </summary>
    /// <param name="hmacCompute">The HMAC computation function.</param>
    /// <param name="base64UrlEncode">The Base64Url encoding function.</param>
    /// <returns>A delegate that relabels a single blank node identifier.</returns>
    public static BlankNodeRelabelDelegate CreateRelabeler(
        HmacComputeDelegate hmacCompute,
        EncodeDelegate base64UrlEncode)
    {
        ArgumentNullException.ThrowIfNull(hmacCompute);
        ArgumentNullException.ThrowIfNull(base64UrlEncode);

        return (blankNodeId, hmacKey, compute, encode) =>
        {
            var hmacBytes = compute(hmacKey, System.Text.Encoding.UTF8.GetBytes(blankNodeId));
            return "u" + encode(hmacBytes);
        };
    }
}


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
    /// Regular expression pattern for matching blank node identifiers.
    /// Matches patterns like "_:c14n0", "_:c14n123", "_:uXYZ...", etc.
    /// </summary>
    /// <remarks>
    /// <para>
    /// HMAC-relabeled identifiers use the format <c>u</c> followed by a base64url-no-pad
    /// encoded HMAC digest. Base64url encoding uses the alphabet <c>A-Za-z0-9-_</c>
    /// per <see href="https://datatracker.ietf.org/doc/html/rfc4648#section-5">RFC 4648 §5</see>.
    /// </para>
    /// <para>
    /// See <see href="https://www.w3.org/TR/vc-di-ecdsa/#createhmacidlabelmapfunction">
    /// W3C VC DI ECDSA: createHmacIdLabelMapFunction</see>.
    /// </para>
    /// </remarks>
    private static readonly Regex BlankNodePattern = new(
        @"_:[a-zA-Z0-9_-]+",
        RegexOptions.Compiled);


    /// <summary>
    /// Applies an existing label map to relabel blank nodes in N-Quad statements.
    /// </summary>
    /// <param name="nquads">The canonical N-Quad statements with <c>_:c14nN</c> identifiers.</param>
    /// <param name="labelMap">
    /// Mapping from canonical identifiers to HMAC-derived identifiers.
    /// Keys are without the <c>_:</c> prefix (e.g., "c14n0").
    /// Values are without the <c>_:</c> prefix (e.g., "uXXX").
    /// </param>
    /// <returns>The relabeled statements with HMAC-derived blank node identifiers.</returns>
    /// <remarks>
    /// <para>
    /// This method is used by verifiers who receive a label map in the derived proof
    /// and need to apply it to re-canonicalized statements. Unlike
    /// <see cref="BlankNodeRelabeling.RelabelNQuadsWithMap"/>, this does not compute
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
    /// Mapping from canonical identifiers to HMAC-derived identifiers.
    /// Keys are without the <c>_:</c> prefix (e.g., "c14n0").
    /// Values are without the <c>_:</c> prefix (e.g., "uXXX").
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

        while(true)
        {
            //Find the next canonical blank node pattern "_:c".
            var index = result.IndexOf("_:c", searchStart, StringComparison.Ordinal);
            if(index < 0)
            {
                break;
            }

            //Find the end of the blank node identifier.
            var endIndex = index + 3;
            while(endIndex < result.Length && (char.IsLetterOrDigit(result[endIndex]) || result[endIndex] == 'n'))
            {
                endIndex++;
            }

            //Extract the blank node identifier (without the "_:" prefix).
            var canonicalId = result[(index + 2)..endIndex];

            //Look up the HMAC-derived identifier.
            if(labelMap.TryGetValue(canonicalId, out var hmacId))
            {
                var hmacFullId = "_:" + hmacId;
                result = string.Concat(result.AsSpan(0, index), hmacFullId, result.AsSpan(endIndex));
                searchStart = index + hmacFullId.Length;
            }
            else
            {
                //No mapping found, skip this blank node.
                searchStart = endIndex;
            }
        }

        return result;
    }


    /// <summary>
    /// Extracts the label map by comparing original and relabeled N-Quad statements.
    /// </summary>
    /// <param name="originalStatements">The canonicalized statements with _:c14nN identifiers.</param>
    /// <param name="relabeledStatements">The relabeled statements with HMAC-derived identifiers.</param>
    /// <returns>Mapping from canonical labels to HMAC-derived labels.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown if the statement counts don't match or if blank node counts differ within a statement.
    /// </exception>
    /// <remarks>
    /// <para>
    /// This method is useful when you have already relabeled statements but didn't capture
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
                //Strip "_:" prefix for CBOR serialization compactness.
                if(originalId.StartsWith(BlankNodeRelabeling.CanonicalBlankNodePrefix, StringComparison.Ordinal))
                {
                    var canonicalKey = originalId[2..]; //Strip "_:" prefix.
                    var hmacValue = relabeledId[2..]; //Strip "_:" prefix.
                    labelMap.TryAdd(canonicalKey, hmacValue);
                }
            }
        }

        return labelMap;
    }


    /// <summary>
    /// Extracts all blank node identifiers from an N-Quad statement.
    /// </summary>
    /// <param name="nquad">The N-Quad statement.</param>
    /// <returns>A list of blank node identifiers in order of appearance.</returns>
    /// <remarks>
    /// <para>
    /// Blank node identifiers are returned with the "_:" prefix included
    /// (e.g., "_:c14n0", "_:uXYZ...").
    /// </para>
    /// </remarks>
    public static IReadOnlyList<string> ExtractBlankNodes(string nquad)
    {
        ArgumentNullException.ThrowIfNull(nquad);

        var matches = BlankNodePattern.Matches(nquad);
        var result = new List<string>(matches.Count);

        foreach(Match match in matches)
        {
            result.Add(match.Value);
        }

        return result;
    }


    /// <summary>
    /// Checks if a blank node identifier is in canonical format (_:c14nN).
    /// </summary>
    /// <param name="blankNodeId">The blank node identifier to check.</param>
    /// <returns><see langword="true"/> if canonical; otherwise <see langword="false"/>.</returns>
    public static bool IsCanonicalBlankNode(string blankNodeId)
    {
        return blankNodeId.StartsWith(BlankNodeRelabeling.CanonicalBlankNodePrefix, StringComparison.Ordinal);
    }


    /// <summary>
    /// Checks if a blank node identifier is in HMAC-relabeled format (_:uXXX).
    /// </summary>
    /// <param name="blankNodeId">The blank node identifier to check.</param>
    /// <returns><see langword="true"/> if HMAC-relabeled; otherwise <see langword="false"/>.</returns>
    public static bool IsHmacBlankNode(string blankNodeId)
    {
        return blankNodeId.StartsWith(BlankNodeRelabeling.HmacBlankNodePrefix, StringComparison.Ordinal);
    }
}