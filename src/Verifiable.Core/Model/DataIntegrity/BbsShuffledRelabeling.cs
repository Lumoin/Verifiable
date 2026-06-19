using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;

namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// Blank node relabeling for the bbs-2023 cryptosuite using the shuffled-identifier label map.
/// </summary>
/// <remarks>
/// <para>
/// The bbs-2023 cryptosuite uses <c>createShuffledIdLabelMapFunction</c>
/// (<see href="https://www.w3.org/TR/vc-di-bbs/#createshuffledidlabelmapfunction">W3C VC DI BBS §3.2.1</see>)
/// rather than the ecdsa-sd <c>createHmacIdLabelMapFunction</c>. Both compute an HMAC digest per
/// canonical blank node identifier, but bbs-2023 then SHUFFLES: it sorts the per-identifier HMAC
/// digests and replaces each canonical identifier with <c>"b" + index-of-its-digest-in-the-sorted-list</c>.
/// The resulting relabeled statements therefore carry <c>_:b0</c>, <c>_:b1</c>, … identifiers, and the
/// label map is <c>c14nN → bM</c> (both integer-suffixed), which is what the derived proof's compressed
/// int → int label map encodes.
/// </para>
/// <para>
/// The shuffle step (step 1.2 of §3.2.1) is identical to the ecdsa-sd HMAC digest computation, so the
/// per-identifier digest is reused via the same registered <see cref="ComputeHmacDelegate"/> seam.
/// </para>
/// </remarks>
public static class BbsShuffledRelabeling
{
    private const string CanonicalBlankNodeMarker = "_:c";
    private const string ShuffledBlankNodePrefix = "b";


    /// <summary>
    /// Computes the shuffled label map for a set of canonical N-Quad statements.
    /// </summary>
    /// <param name="canonicalStatements">The canonical N-Quad statements with <c>_:c14nN</c> identifiers.</param>
    /// <param name="hmacKey">The 32-byte HMAC key.</param>
    /// <param name="hmacCompute">The registered HMAC computation delegate.</param>
    /// <param name="encoder">Base64URL encoder for the HMAC digest.</param>
    /// <param name="pool">Memory pool for cryptographic allocations.</param>
    /// <param name="cancellationToken">Token to observe while awaiting HMAC computation.</param>
    /// <returns>
    /// A label map from canonical identifiers (e.g. <c>"c14n0"</c>) to shuffled identifiers
    /// (e.g. <c>"b2"</c>), ordered by canonical identifier.
    /// </returns>
    /// <remarks>
    /// <para>
    /// The set of canonical identifiers is collected from the statements in first-seen order, which
    /// matches the canonical bnode identifier map a conformant RDF canonicalizer produces.
    /// </para>
    /// </remarks>
    public static async ValueTask<IReadOnlyDictionary<string, string>> ComputeShuffledLabelMapAsync(
        IReadOnlyList<string> canonicalStatements,
        ReadOnlyMemory<byte> hmacKey,
        ComputeHmacDelegate hmacCompute,
        EncodeDelegate encoder,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(canonicalStatements);
        ArgumentNullException.ThrowIfNull(hmacCompute);
        ArgumentNullException.ThrowIfNull(encoder);
        ArgumentNullException.ThrowIfNull(pool);

        //Collect the distinct canonical identifiers in first-seen order.
        var canonicalIds = CollectCanonicalIds(canonicalStatements);

        //Step 1.2 of §3.2.1: compute the HMAC digest per canonical identifier as "u" + base64url(digest).
        var hmacByCanonical = new Dictionary<string, string>(canonicalIds.Count, StringComparer.Ordinal);
        foreach(string canonicalId in canonicalIds)
        {
            string hmacId = await ComputeHmacIdAsync(canonicalId, hmacKey, hmacCompute, encoder, pool, cancellationToken).ConfigureAwait(false);
            hmacByCanonical[canonicalId] = hmacId;
        }

        //Step 1.3 of §3.2.1: sort the HMAC digests, then replace each canonical identifier's value with
        //"b" + index-of-its-digest-in-the-sorted-list.
        var sortedHmacIds = hmacByCanonical.Values.OrderBy(v => v, StringComparer.Ordinal).ToList();
        var labelMap = new Dictionary<string, string>(canonicalIds.Count, StringComparer.Ordinal);
        foreach(string canonicalId in canonicalIds)
        {
            int shuffledIndex = sortedHmacIds.IndexOf(hmacByCanonical[canonicalId]);
            labelMap[canonicalId] = ShuffledBlankNodePrefix + shuffledIndex;
        }

        return labelMap;
    }


    /// <summary>
    /// Collects the distinct canonical blank node identifiers from a set of statements in first-seen order.
    /// </summary>
    private static List<string> CollectCanonicalIds(IReadOnlyList<string> canonicalStatements)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var ordered = new List<string>();

        foreach(string statement in canonicalStatements)
        {
            int searchStart = 0;
            while(true)
            {
                int index = statement.IndexOf(CanonicalBlankNodeMarker, searchStart, StringComparison.Ordinal);
                if(index < 0)
                {
                    break;
                }

                int endIndex = index + 2;
                while(endIndex < statement.Length && (char.IsLetterOrDigit(statement[endIndex]) || statement[endIndex] == 'n'))
                {
                    endIndex++;
                }

                string canonicalId = statement[(index + 2)..endIndex];
                if(seen.Add(canonicalId))
                {
                    ordered.Add(canonicalId);
                }

                searchStart = endIndex;
            }
        }

        return ordered;
    }


    /// <summary>
    /// Computes the HMAC identifier for a single canonical blank node identifier as
    /// <c>"u" + base64url-no-pad(HMAC(hmacKey, canonicalId))</c>.
    /// </summary>
    private static async ValueTask<string> ComputeHmacIdAsync(
        string canonicalId,
        ReadOnlyMemory<byte> hmacKey,
        ComputeHmacDelegate hmacCompute,
        EncodeDelegate encoder,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        Tag hmacTag = CryptoTags.HmacSha256Value;
        const int outputByteLength = 32;

        int messageByteCount = System.Text.Encoding.UTF8.GetByteCount(canonicalId);
        using IMemoryOwner<byte> messageOwner = pool.Rent(messageByteCount);
        System.Text.Encoding.UTF8.GetBytes(canonicalId, messageOwner.Memory.Span);
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
            return "u" + encoder(hmac.AsReadOnlySpan());
        }
    }
}
