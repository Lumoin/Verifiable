using System;
using System.Buffers;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;

namespace Verifiable.Core.Model.DataIntegrity;

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
/// HMAC computation routes through the registered
/// <see cref="ComputeHmacDelegate"/> so the same observability, CBOM provenance,
/// and backend substitutability apply as to every other cryptographic operation
/// in the library.
/// </para>
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
    /// <param name="hmacCompute">
    /// HMAC computation delegate. Wired to a provider-side implementation
    /// registered on <see cref="CryptographicKeyFactory"/> such as
    /// <c>MicrosoftHmacFunctions.ComputeHmacAsync</c>.
    /// </param>
    /// <param name="base64UrlEncode">The Base64Url encoding function.</param>
    /// <param name="pool">Memory pool for cryptographic allocations.</param>
    /// <param name="cancellationToken">Token to observe while awaiting HMAC computation.</param>
    /// <returns>The N-Quad with all blank nodes relabeled.</returns>
    /// <remarks>
    /// <para>
    /// This method finds all occurrences of <c>_:c14nN</c> patterns in the N-Quad
    /// and replaces them with HMAC-derived identifiers in <c>_:uXXX</c> format.
    /// </para>
    /// </remarks>
    public static ValueTask<string> RelabelNQuadAsync(
        string nquad,
        ReadOnlyMemory<byte> hmacKey,
        ComputeHmacDelegate hmacCompute,
        EncodeDelegate base64UrlEncode,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        return RelabelNQuadWithMapAsync(nquad, hmacKey, hmacCompute, base64UrlEncode, pool, labelMap: null, cancellationToken);
    }


    /// <summary>
    /// Relabels all blank nodes in an N-Quad statement using HMAC and records the mapping.
    /// </summary>
    /// <param name="nquad">The N-Quad statement containing blank nodes.</param>
    /// <param name="hmacKey">The HMAC key for generating new identifiers.</param>
    /// <param name="hmacCompute">
    /// HMAC computation delegate. Wired to a provider-side implementation
    /// registered on <see cref="CryptographicKeyFactory"/>.
    /// </param>
    /// <param name="base64UrlEncode">The Base64Url encoding function.</param>
    /// <param name="pool">Memory pool for cryptographic allocations.</param>
    /// <param name="labelMap">
    /// Optional dictionary to populate with the label mappings. If provided, mappings
    /// from canonical identifiers (e.g., "_:c14n0") to HMAC identifiers (e.g., "_:uXYZ")
    /// will be added.
    /// </param>
    /// <param name="cancellationToken">Token to observe while awaiting HMAC computation.</param>
    /// <returns>The N-Quad with all blank nodes relabeled.</returns>
    public static async ValueTask<string> RelabelNQuadWithMapAsync(
        string nquad,
        ReadOnlyMemory<byte> hmacKey,
        ComputeHmacDelegate hmacCompute,
        EncodeDelegate base64UrlEncode,
        MemoryPool<byte> pool,
        Dictionary<string, string>? labelMap,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(nquad);
        ArgumentNullException.ThrowIfNull(hmacCompute);
        ArgumentNullException.ThrowIfNull(base64UrlEncode);
        ArgumentNullException.ThrowIfNull(pool);

        Tag hmacTag = CryptoTags.HmacSha256Value;
        const int outputByteLength = 32;

        string result = nquad;
        int searchStart = 0;

        while(true)
        {
            //Find the next blank node pattern "_:c".
            int index = result.IndexOf("_:c", searchStart, StringComparison.Ordinal);
            if(index < 0)
            {
                break;
            }

            //Find the end of the blank node identifier (digits after "c14n" or similar).
            int endIndex = index + 3;
            while(endIndex < result.Length && (char.IsLetterOrDigit(result[endIndex]) || result[endIndex] == 'n'))
            {
                endIndex++;
            }

            //Extract the blank node identifier (without the "_:" prefix).
            string blankNodeId = result[(index + 2)..endIndex];
            string canonicalId = blankNodeId;

            //Compute HMAC and encode through the registered HMAC primitive.
            string hmacId;
            int messageByteCount = System.Text.Encoding.UTF8.GetByteCount(blankNodeId);
            using(IMemoryOwner<byte> messageOwner = pool.Rent(messageByteCount))
            {
                System.Text.Encoding.UTF8.GetBytes(blankNodeId, messageOwner.Memory.Span);
                ReadOnlyMemory<byte> messageMemory = messageOwner.Memory[..messageByteCount];

                (HmacValue hmac, _) = await hmacCompute(
                    new ReadOnlySequence<byte>(messageMemory),
                    hmacKey,
                    outputByteLength,
                    hmacTag,
                    pool,
                    null,
                    cancellationToken).ConfigureAwait(false);

                using(hmac)
                {
                    hmacId = "u" + base64UrlEncode(hmac.AsReadOnlySpan());
                }
            }

            string hmacFullId = "_:" + hmacId;

            //Record the mapping if requested. Keys stored in bare format per VC DI ECDSA §3.5.5.
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
    /// <param name="hmacCompute">
    /// HMAC computation delegate. Wired to a provider-side implementation
    /// registered on <see cref="CryptographicKeyFactory"/>.
    /// </param>
    /// <param name="base64UrlEncode">The Base64Url encoding function.</param>
    /// <param name="pool">Memory pool for cryptographic allocations.</param>
    /// <param name="cancellationToken">Token to observe while awaiting HMAC computation.</param>
    /// <returns>The relabeled N-Quad statements.</returns>
    public static async ValueTask<IReadOnlyList<string>> RelabelNQuadsAsync(
        IEnumerable<string> nquads,
        ReadOnlyMemory<byte> hmacKey,
        ComputeHmacDelegate hmacCompute,
        EncodeDelegate base64UrlEncode,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        RelabelingResult relabeling = await RelabelNQuadsWithMapAsync(
            nquads, hmacKey, hmacCompute, base64UrlEncode, pool, cancellationToken).ConfigureAwait(false);
        return relabeling.Statements;
    }


    /// <summary>
    /// Relabels all blank nodes in a collection of N-Quad statements and returns the label map.
    /// </summary>
    /// <param name="nquads">The N-Quad statements.</param>
    /// <param name="hmacKey">The HMAC key for generating new identifiers.</param>
    /// <param name="hmacCompute">
    /// HMAC computation delegate. Wired to a provider-side implementation
    /// registered on <see cref="CryptographicKeyFactory"/>.
    /// </param>
    /// <param name="base64UrlEncode">The Base64Url encoding function.</param>
    /// <param name="pool">Memory pool for cryptographic allocations.</param>
    /// <param name="cancellationToken">Token to observe while awaiting HMAC computation.</param>
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
    public static async ValueTask<RelabelingResult> RelabelNQuadsWithMapAsync(
        IEnumerable<string> nquads,
        ReadOnlyMemory<byte> hmacKey,
        ComputeHmacDelegate hmacCompute,
        EncodeDelegate base64UrlEncode,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(nquads);

        List<string> statements = new();
        Dictionary<string, string> labelMap = new();

        foreach(string nquad in nquads)
        {
            string relabeled = await RelabelNQuadWithMapAsync(
                nquad, hmacKey, hmacCompute, base64UrlEncode, pool, labelMap, cancellationToken).ConfigureAwait(false);
            statements.Add(relabeled);
        }

        return new RelabelingResult(statements, labelMap);
    }
}
