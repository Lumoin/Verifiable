using System.Buffers;
using System.Diagnostics;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.OAuth.Oid4Vp.Wallet;

/// <summary>
/// Computes the <c>transaction_data_hashes</c> array a Wallet binds into the
/// KB-JWT per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.4">OID4VP 1.0 §8.4</see>.
/// </summary>
/// <remarks>
/// <para>
/// Each input entry is the verbatim base64url-encoded JSON string the Verifier
/// sent in the <c>transaction_data</c> Authorization Request parameter. The
/// hash is computed over the ASCII byte form of that exact string (base64url
/// is ASCII by definition); the Wallet must never re-encode the decoded JSON
/// before hashing, because whitespace and member ordering would diverge from
/// the Verifier's wire form and break the round-trip comparison.
/// </para>
/// <para>
/// Defaults to SHA-256 per §8.4; alternative algorithms are reached via the
/// <see cref="Tag"/> argument tied to the Verifier-allowed
/// <c>transaction_data_hashes_alg</c> set on the descriptor.
/// </para>
/// </remarks>
[DebuggerDisplay("TransactionDataHasher")]
public static class TransactionDataHasher
{
    private const int Sha256DigestLength = 32;


    /// <summary>
    /// Computes one base64url-encoded SHA-256 digest per entry of
    /// <paramref name="transactionData"/>, positionally aligned with the
    /// input.
    /// </summary>
    /// <param name="transactionData">
    /// The verbatim base64url-encoded JSON descriptor strings carried in the
    /// Authorization Request's <c>transaction_data</c> parameter.
    /// </param>
    /// <param name="encoder">Base64url encoder.</param>
    /// <param name="pool">Memory pool for transient digest buffers.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// An array of base64url-encoded digests, one per input entry, in the
    /// same positional order as the input. Empty when the input is empty.
    /// </returns>
    public static async ValueTask<IReadOnlyList<string>> ComputeSha256Async(
        IReadOnlyList<string> transactionData,
        EncodeDelegate encoder,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transactionData);
        ArgumentNullException.ThrowIfNull(encoder);
        ArgumentNullException.ThrowIfNull(pool);

        if(transactionData.Count == 0)
        {
            return [];
        }

        string[] result = new string[transactionData.Count];
        for(int i = 0; i < transactionData.Count; i++)
        {
            string entry = transactionData[i];
            if(string.IsNullOrEmpty(entry))
            {
                throw new ArgumentException(
                    $"transaction_data entry at index {i} is empty; OID4VP 1.0 §8.4 requires non-empty base64url-encoded JSON.",
                    nameof(transactionData));
            }

            int byteCount = Encoding.ASCII.GetByteCount(entry);
            using IMemoryOwner<byte> inputOwner = pool.Rent(byteCount);
            Span<byte> inputBytes = inputOwner.Memory.Span[..byteCount];
            Encoding.ASCII.GetBytes(entry, inputBytes);

            using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
                inputOwner.Memory[..byteCount],
                Sha256DigestLength,
                CryptoTags.Sha256Digest,
                pool,
                cancellationToken: cancellationToken).ConfigureAwait(false);

            result[i] = encoder(digest.AsReadOnlySpan());
        }

        return result;
    }
}
