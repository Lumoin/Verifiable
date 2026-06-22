using System;
using System.Buffers;
using System.Text;
using System.Threading.Tasks;
using Verifiable.Core.EventLogs;
using Verifiable.Cryptography;

namespace Verifiable.Core.Did.Methods.WebVh;

/// <summary>
/// Verifies the entryHash chain of a did:webvh DID Log: each entry's <c>versionId</c> carries an entryHash
/// computed over the entry with its <c>versionId</c> set to its predecessor's, linking the entries into a
/// tamper-evident microledger (did:webvh v1.0, Entry Hash Generation and Verification).
/// </summary>
/// <remarks>
/// <para>
/// This supplies the <see cref="VerifyChainIntegrityDelegate{TOperation,TProof}"/> for the
/// <see cref="LogReplayer{TState,TOperation,TProof,TContext}"/>. The replayer threads the authoritative
/// predecessor <c>versionId</c> forward as the previous entry's digest, so an entry that builds on a
/// tampered predecessor fails to reproduce its own entryHash and the chain breaks at the point of tampering.
/// </para>
/// <para>
/// The predecessor for the first entry is the SCID declared in that entry; for every subsequent entry it is
/// the previous entry's full <c>versionId</c>. The version number is required to be one for the first entry
/// and to increment by one per entry.
/// </para>
/// </remarks>
public static class WebVhChainVerification
{
    /// <summary>
    /// Creates the entryHash chain integrity delegate for did:webvh replay.
    /// </summary>
    /// <param name="entryHashInput">Produces the JCS-canonical entry-hash input (proof removed, versionId set to the predecessor).</param>
    /// <param name="hashFunction">The SHA-256 hash function fixed by did:webvh v1.0.</param>
    /// <param name="base58Encoder">The raw base58btc encoder (no multibase prefix).</param>
    /// <param name="base58Decoder">The raw base58btc decoder, used to parse the claimed entryHash's multihash algorithm prefix.</param>
    /// <param name="pool">The pool the decoded multihash bytes are rented from.</param>
    /// <returns>A delegate that verifies one entry's position in the entryHash chain.</returns>
    public static VerifyChainIntegrityDelegate<WebVhRawEntry, WebVhProof> Create(
        WebVhEntryHashInput entryHashInput,
        HashFunctionDelegate hashFunction,
        EncodeDelegate base58Encoder,
        DecodeDelegate base58Decoder,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(entryHashInput);
        ArgumentNullException.ThrowIfNull(hashFunction);
        ArgumentNullException.ThrowIfNull(base58Encoder);
        ArgumentNullException.ThrowIfNull(base58Decoder);
        ArgumentNullException.ThrowIfNull(pool);

        return (entry, previousEntryDigest, cancellationToken) =>
            ValueTask.FromResult(Verify(entry, previousEntryDigest, entryHashInput, hashFunction, base58Encoder, base58Decoder, pool));
    }


    private static string? Verify(
        LogEntry<WebVhRawEntry, WebVhProof> entry,
        ReadOnlyMemory<byte>? previousEntryDigest,
        WebVhEntryHashInput entryHashInput,
        HashFunctionDelegate hashFunction,
        EncodeDelegate base58Encoder,
        DecodeDelegate base58Decoder,
        MemoryPool<byte> pool)
    {
        if(entry.Operation is not WebVhRawEntry rawEntry)
        {
            return "The did:webvh log entry carries no parsed content.";
        }

        if(!WebVhVersionId.TryParse(rawEntry.VersionId, out int versionNumber, out string claimedEntryHash))
        {
            return $"The did:webvh versionId '{rawEntry.VersionId}' is not a well-formed '<versionNumber>-<entryHash>' value.";
        }

        //The entryHash is a self-describing multihash; did:webvh v1.0 fixes SHA-256, so a claimed entryHash
        //whose multihash algorithm prefix is not sha2-256 is rejected by algorithm before the recomputed-value
        //comparison (did:webvh v1.0, Cryptographic Agility: the algorithm is determined from the data itself).
        if(!WebVhHash.IsSha256Multihash(claimedEntryHash, base58Decoder, pool))
        {
            return $"The did:webvh entryHash for versionId '{rawEntry.VersionId}' is not a SHA-256 multihash, the only algorithm did:webvh v1.0 permits.";
        }

        //The version number starts at one for the first entry and increments by one per entry.
        ulong expectedVersionNumber = entry.Index + 1;
        if((ulong)versionNumber != expectedVersionNumber)
        {
            return $"The did:webvh entry at index {entry.Index} declares version number {versionNumber}; expected {expectedVersionNumber}.";
        }

        string? predecessorVersionId = ResolvePredecessor(entry.Index, rawEntry, previousEntryDigest, out string? predecessorError);
        if(predecessorVersionId is null)
        {
            return predecessorError;
        }

        TaggedMemory<byte> canonicalInput = entryHashInput(entry.CanonicalBytes, predecessorVersionId);
        string computedEntryHash = WebVhHash.ComputeBase58(canonicalInput.Span, hashFunction, base58Encoder);

        if(!string.Equals(computedEntryHash, claimedEntryHash, StringComparison.Ordinal))
        {
            return $"The did:webvh entryHash for versionId '{rawEntry.VersionId}' does not verify; computed '{computedEntryHash}'.";
        }

        return null;
    }


    private static string? ResolvePredecessor(
        ulong index,
        WebVhRawEntry rawEntry,
        ReadOnlyMemory<byte>? previousEntryDigest,
        out string? error)
    {
        error = null;

        if(index == 0)
        {
            //The predecessor of the first entry is the SCID it declares.
            if(rawEntry.DeclaredParameters.Scid is not { Length: > 0 } scid)
            {
                error = "The first did:webvh log entry MUST declare the scid parameter used as the entryHash predecessor.";

                return null;
            }

            return scid;
        }

        if(previousEntryDigest is not { } digest)
        {
            error = $"The did:webvh entry at index {index} has no predecessor versionId to verify the entryHash against.";

            return null;
        }

        return Encoding.UTF8.GetString(digest.Span);
    }
}
