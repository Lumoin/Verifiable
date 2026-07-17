using System;
using System.Buffers;
using System.Collections.Immutable;
using System.Globalization;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography.EventLogs;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Core.Did.Methods.WebVh;

/// <summary>
/// Validates a did:webvh log entry's authorization: the self-certifying identifier (first entry), the
/// Data Integrity controller proof against the active <c>updateKeys</c>, the pre-rotation key-hash
/// commitments, and the monotonic <c>versionTime</c> (did:webvh v1.0, Read (Resolve), SCID, Authorized Keys
/// and Pre-Rotation Key Hash Generation and Verification).
/// </summary>
/// <remarks>
/// <para>
/// This is the security core of did:webvh resolution. It supplies the
/// <see cref="ValidateProofDelegate{TState,TOperation,TProof,TContext}"/> the
/// <see cref="LogReplayer{TState,TOperation,TProof,TContext}"/> runs after the entryHash chain check and
/// before the entry is applied, so the authorized key set used to verify an entry is the one established
/// by the entries verified before it.
/// </para>
/// <para>
/// did:webvh v1.0 fixes SHA-256 and the <c>eddsa-jcs-2022</c> cryptosuite (Ed25519). Every failure path
/// returns a non-null error so replay terminates fail-closed at the first entry that does not verify.
/// </para>
/// </remarks>
public static class WebVhProofVerification
{
    private const string DataIntegrityProofType = "DataIntegrityProof";
    private const string EddsaJcs2022Cryptosuite = "eddsa-jcs-2022";
    private const string AssertionMethodPurpose = "assertionMethod";
    private const string DidKeyPrefix = "did:key:";

    private const int Sha256DigestLength = 32;
    private const int HashDataLength = 2 * Sha256DigestLength;


    /// <summary>
    /// The <see cref="ValidateProofDelegate{TState,TOperation,TProof,TContext}"/> for did:webvh replay.
    /// </summary>
    /// <param name="entry">The entry whose authorization is being validated.</param>
    /// <param name="currentState">The accumulated state before this entry is applied.</param>
    /// <param name="context">The cryptographic seams and clock.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns><see langword="null"/> when the entry is authorized; otherwise an error message.</returns>
    public static async ValueTask<string?> ValidateProofAsync(
        LogEntry<WebVhRawEntry, WebVhProof> entry,
        LogState<WebVhState> currentState,
        WebVhValidationContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(currentState);
        ArgumentNullException.ThrowIfNull(context);

        if(entry.Operation is not WebVhRawEntry rawEntry)
        {
            return "The did:webvh log entry carries no parsed content.";
        }

        (WebVhState? prior, string? deactivatedError) = currentState switch
        {
            EmptyLogState<WebVhState> => ((WebVhState?)null, (string?)null),
            ActiveLogState<WebVhState> active => (active.Value, null),
            _ => (null, "The did:webvh DID is deactivated; no further log entries are permitted.")
        };

        if(deactivatedError is not null)
        {
            return deactivatedError;
        }

        WebVhDeclaredParameters declared = rawEntry.DeclaredParameters;

        (WebVhParameters? effectiveOrNull, string? foldError) = prior is null
            ? WebVhParameters.FoldGenesis(declared)
            : WebVhParameters.Fold(prior.Parameters, declared);

        if(effectiveOrNull is not WebVhParameters effective)
        {
            return foldError;
        }

        string? versionTimeError = ValidateVersionTime(rawEntry, prior, context.TimeProvider);
        if(versionTimeError is not null)
        {
            return versionTimeError;
        }

        ReadOnlyMemory<byte> rawLine = entry.CanonicalBytes;

        //Every nextKeyHashes commitment declared by this entry is a self-describing multihash; did:webvh v1.0
        //fixes SHA-256, so a commitment whose multihash algorithm prefix is not sha2-256 invalidates the entry
        //by algorithm before it can ever match a future updateKey hash.
        if(declared.NextKeyHashes is { } declaredNextKeyHashes)
        {
            foreach(string nextKeyHash in declaredNextKeyHashes)
            {
                if(!WebVhHash.IsSha256Multihash(nextKeyHash, context.Base58Decoder, context.MemoryPool))
                {
                    return $"The did:webvh nextKeyHashes commitment '{nextKeyHash}' is not a SHA-256 multihash, the only algorithm did:webvh v1.0 permits.";
                }
            }
        }

        if(prior is null)
        {
            string? scidError = await VerifyScidAsync(rawLine, effective, context, cancellationToken).ConfigureAwait(false);
            if(scidError is not null)
            {
                return scidError;
            }
        }
        else if(prior.Parameters.IsPreRotationActive)
        {
            string? preRotationError = await VerifyPreRotationAsync(declared, prior.Parameters, context, cancellationToken).ConfigureAwait(false);
            if(preRotationError is not null)
            {
                return preRotationError;
            }
        }

        ImmutableArray<string> activeUpdateKeys = ResolveActiveUpdateKeys(prior, effective);

        return await VerifyControllerProofAsync(entry, rawLine, activeUpdateKeys, context, cancellationToken).ConfigureAwait(false);
    }


    //The active updateKeys that MUST have signed this entry: the first entry's own keys, the current
    //entry's keys while pre-rotation is active, otherwise the most recent prior keys.
    private static ImmutableArray<string> ResolveActiveUpdateKeys(WebVhState? prior, WebVhParameters effective)
    {
        if(prior is null || prior.Parameters.IsPreRotationActive)
        {
            return effective.UpdateKeys;
        }

        return prior.Parameters.UpdateKeys;
    }


    private static string? ValidateVersionTime(WebVhRawEntry rawEntry, WebVhState? prior, TimeProvider timeProvider)
    {
        if(rawEntry.VersionTime is not { Length: > 0 } versionTime
            || !TryParseVersionTime(versionTime, out DateTimeOffset entryTime))
        {
            return $"The did:webvh entry '{rawEntry.VersionId}' has no valid UTC ISO8601 versionTime.";
        }

        if(entryTime > timeProvider.GetUtcNow())
        {
            return $"The did:webvh entry '{rawEntry.VersionId}' has a versionTime in the future.";
        }

        if(prior?.VersionTime is { Length: > 0 } priorVersionTime
            && TryParseVersionTime(priorVersionTime, out DateTimeOffset priorTime)
            && entryTime <= priorTime)
        {
            return $"The did:webvh entry '{rawEntry.VersionId}' versionTime is not greater than the previous entry's.";
        }

        return null;
    }


    //did:webvh v1.0 requires versionTime to be a UTC ISO8601 date/time with an explicit 'Z' designator, for
    //example "2024-04-05T07:32:58Z" (The DID Log File, Read (Resolve)). Offset-bearing, date-only and locale
    //forms are rejected so the monotonic and not-in-the-future comparisons run on the asserted instant and
    //match a conformant resolver rather than silently coercing an offset-less value to UTC.
    private static string[] VersionTimeFormats { get; } =
    [
        "yyyy-MM-dd'T'HH:mm:ss'Z'",
        "yyyy-MM-dd'T'HH:mm:ss.FFFFFFF'Z'"
    ];

    //Internal so version SELECTION (WebVhDidResolver.TryGetEntryTime) parses versionTime with the SAME strict
    //grammar as verification — a lenient selection parser could pick a different (still-verified) entry than a
    //conformant resolver, diverging the resolved version from the spec.
    internal static bool TryParseVersionTime(string versionTime, out DateTimeOffset value)
    {
        return DateTimeOffset.TryParseExact(
            versionTime,
            VersionTimeFormats,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out value);
    }


    //An XML Schema dateTimeStamp is an ISO8601 date/time that MUST carry an explicit timezone (a 'Z' designator
    //or a numeric offset); the proof options 'created' and 'expires' use this lexical space. A value without a
    //timezone, or one that does not parse as a round-trippable instant, is not a valid dateTimeStamp.
    private static bool TryParseDateTimeStamp(string value, out DateTimeOffset instant)
    {
        return DateTimeOffset.TryParse(
            value,
            CultureInfo.InvariantCulture,
            DateTimeStyles.RoundtripKind,
            out instant);
    }


    private static bool IsValidDateTimeStamp(string value)
    {
        return TryParseDateTimeStamp(value, out _);
    }


    private static async ValueTask<string?> VerifyScidAsync(ReadOnlyMemory<byte> rawLine, WebVhParameters effective, WebVhValidationContext context, CancellationToken cancellationToken)
    {
        //The SCID is a self-describing multihash; did:webvh v1.0 fixes SHA-256, so a claimed SCID whose
        //multihash algorithm prefix is not sha2-256 is rejected by algorithm before any value comparison.
        if(!WebVhHash.IsSha256Multihash(effective.Scid, context.Base58Decoder, context.MemoryPool))
        {
            return $"The did:webvh scid '{effective.Scid}' is not a SHA-256 multihash, the only algorithm did:webvh v1.0 permits.";
        }

        TaggedMemory<byte> scidInput = context.Canonicalizer.ScidInput(rawLine, effective.Scid);
        string computedScid = await WebVhHash.ComputeBase58Async(scidInput.Memory, context.ComputeDigest, context.Base58Encoder, context.MemoryPool, cancellationToken).ConfigureAwait(false);

        if(!string.Equals(computedScid, effective.Scid, StringComparison.Ordinal))
        {
            return $"The did:webvh scid '{effective.Scid}' does not verify; computed '{computedScid}'.";
        }

        return null;
    }


    //Pre-rotation: while active, both updateKeys and nextKeyHashes MUST be present in the entry, and every
    //updateKey MUST have its multihash committed in the previous entry's nextKeyHashes.
    private static async ValueTask<string?> VerifyPreRotationAsync(WebVhDeclaredParameters declared, WebVhParameters prior, WebVhValidationContext context, CancellationToken cancellationToken)
    {
        if(declared.UpdateKeys is not { Length: > 0 } declaredUpdateKeys)
        {
            return "Key Pre-Rotation is active; the did:webvh log entry MUST declare a non-empty updateKeys array.";
        }

        if(declared.NextKeyHashes is null)
        {
            return "Key Pre-Rotation is active; the did:webvh log entry MUST declare nextKeyHashes.";
        }

        foreach(string updateKey in declaredUpdateKeys)
        {
            int byteCount = Encoding.UTF8.GetByteCount(updateKey);
            using IMemoryOwner<byte> updateKeyBytes = context.MemoryPool.Rent(byteCount);
            Encoding.UTF8.GetBytes(updateKey, updateKeyBytes.Memory.Span[..byteCount]);

            string keyHash = await WebVhHash.ComputeBase58Async(updateKeyBytes.Memory[..byteCount], context.ComputeDigest, context.Base58Encoder, context.MemoryPool, cancellationToken).ConfigureAwait(false);
            if(!prior.NextKeyHashes.Contains(keyHash))
            {
                return $"The did:webvh updateKey '{updateKey}' was not pre-rotation committed in the previous entry's nextKeyHashes.";
            }
        }

        return null;
    }


    private static async ValueTask<string?> VerifyControllerProofAsync(
        LogEntry<WebVhRawEntry, WebVhProof> entry,
        ReadOnlyMemory<byte> rawLine,
        ImmutableArray<string> activeUpdateKeys,
        WebVhValidationContext context,
        CancellationToken cancellationToken)
    {
        if(entry.Proofs.IsDefaultOrEmpty)
        {
            return "The did:webvh log entry MUST carry a Data Integrity controller proof.";
        }

        //The unsecured document (entry minus proof) is the same for every proof on the entry.
        TaggedMemory<byte> document = context.Canonicalizer.DocumentInput(rawLine);

        string? lastError = "The did:webvh log entry has no Data Integrity proof signed by an active updateKey.";
        for(int proofIndex = 0; proofIndex < entry.Proofs.Length; proofIndex++)
        {
            string? proofError = await VerifySingleProofAsync(
                entry.Proofs[proofIndex], proofIndex, rawLine, document.Memory, activeUpdateKeys, context, cancellationToken).ConfigureAwait(false);
            if(proofError is null)
            {
                return null;
            }

            lastError = proofError;
        }

        return lastError;
    }


    private static async ValueTask<string?> VerifySingleProofAsync(
        WebVhProof proof,
        int proofIndex,
        ReadOnlyMemory<byte> rawLine,
        ReadOnlyMemory<byte> document,
        ImmutableArray<string> activeUpdateKeys,
        WebVhValidationContext context,
        CancellationToken cancellationToken)
    {
        if(!string.Equals(proof.Type, DataIntegrityProofType, StringComparison.Ordinal))
        {
            return $"A did:webvh proof MUST be a {DataIntegrityProofType}.";
        }

        if(!string.Equals(proof.Cryptosuite, EddsaJcs2022Cryptosuite, StringComparison.Ordinal))
        {
            return $"A did:webvh v1.0 proof MUST use the {EddsaJcs2022Cryptosuite} cryptosuite.";
        }

        if(!string.Equals(proof.ProofPurpose, AssertionMethodPurpose, StringComparison.Ordinal))
        {
            return $"A did:webvh proof MUST have proofPurpose '{AssertionMethodPurpose}'.";
        }

        //The Data Integrity proof options have temporal semantics beyond the signature. When 'created' is
        //present it MUST be a valid XML dateTimeStamp; when 'expires' is present it MUST be a valid
        //dateTimeStamp AND MUST be in the future relative to the resolution clock — a proof whose validity
        //window has closed does not verify (VC Data Integrity, proof options 'created'/'expires').
        if(proof.Created is { Length: > 0 } created && !IsValidDateTimeStamp(created))
        {
            return "A did:webvh proof 'created' MUST be a valid XML dateTimeStamp.";
        }

        if(proof.Expires is { Length: > 0 } expires)
        {
            if(!TryParseDateTimeStamp(expires, out DateTimeOffset expiresTime))
            {
                return "A did:webvh proof 'expires' MUST be a valid XML dateTimeStamp.";
            }

            if(expiresTime < context.TimeProvider.GetUtcNow())
            {
                return "A did:webvh proof has expired; its 'expires' time is in the past.";
            }
        }

        if(proof.ProofValue is not { Length: > 0 } proofValue)
        {
            return "A did:webvh proof MUST carry a proofValue.";
        }

        if(ExtractDidKeyMultikey(proof.VerificationMethod) is not { } multikey
            || !activeUpdateKeys.Contains(multikey))
        {
            return "A did:webvh proof MUST be signed by a key in the active updateKeys list.";
        }

        try
        {
            return await VerifySignatureAsync(proof, proofIndex, rawLine, document, multikey, context, cancellationToken).ConfigureAwait(false);
        }
        catch(Exception exception) when(exception is FormatException or ArgumentException)
        {
            return $"The did:webvh proof signature could not be verified: {exception.Message}";
        }
    }


    private static async ValueTask<string?> VerifySignatureAsync(
        WebVhProof proof,
        int proofIndex,
        ReadOnlyMemory<byte> rawLine,
        ReadOnlyMemory<byte> document,
        string multikey,
        WebVhValidationContext context,
        CancellationToken cancellationToken)
    {
        TaggedMemory<byte> proofOptions = context.Canonicalizer.ProofOptionsInput(rawLine, proofIndex);
        using IMemoryOwner<byte> signatureOwner = ProofValueCodecs.DecodeBase58Btc(proof.ProofValue!, context.Base58Decoder, context.MemoryPool);
        (IMemoryOwner<byte> keyData, CryptoAlgorithm algorithm) = MultibaseSerializer.DecodeKey(multikey, context.Base58Decoder, context.MemoryPool);

        using(keyData)
        {
            if(algorithm != CryptoAlgorithm.Ed25519)
            {
                return "A did:webvh v1.0 update key MUST be an Ed25519 multikey.";
            }

            //eddsa-jcs-2022 signs SHA-256(JCS(proofOptions)) concatenated with SHA-256(JCS(document)). Both digests
            //flow through the registered ComputeDigestDelegate (telemetry, CBOM stamping, event emission); this method
            //is already async, so it awaits the digest rather than bridging it synchronously. The two digests are
            //computed before the hashData span is taken, so no Span local spans an await.
            using IMemoryOwner<byte> hashOwner = context.MemoryPool.Rent(HashDataLength);
            using(DigestValue proofOptionsDigest = await CryptographicKeyEvents.ComputeDigestAsync(
                context.ComputeDigest, new System.Buffers.ReadOnlySequence<byte>(proofOptions.Memory), Sha256DigestLength, CryptoTags.Sha256Digest, context.MemoryPool, cancellationToken: cancellationToken).ConfigureAwait(false))
            using(DigestValue documentDigest = await CryptographicKeyEvents.ComputeDigestAsync(
                context.ComputeDigest, new System.Buffers.ReadOnlySequence<byte>(document), Sha256DigestLength, CryptoTags.Sha256Digest, context.MemoryPool, cancellationToken: cancellationToken).ConfigureAwait(false))
            {
                Span<byte> hashData = hashOwner.Memory.Span[..HashDataLength];
                proofOptionsDigest.AsReadOnlySpan().CopyTo(hashData[..Sha256DigestLength]);
                documentDigest.AsReadOnlySpan().CopyTo(hashData[Sha256DigestLength..]);
            }

            VerificationDelegate verify = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, Purpose.Verification);
            (bool isValid, CryptoEvent? evt) = await verify(hashOwner.Memory[..HashDataLength], signatureOwner.Memory, keyData.Memory, null, cancellationToken).ConfigureAwait(false);

            CryptographicKeyEvents.Emit(evt);

            return isValid ? null : "The did:webvh proof signature is invalid.";
        }
    }


    //Extracts the multikey (the did:key method-specific identifier) from a verificationMethod, dropping any
    //fragment. did:webvh updateKeys are bare multikeys, which a controller proof references as a did:key.
    private static string? ExtractDidKeyMultikey(string? verificationMethod)
    {
        if(string.IsNullOrEmpty(verificationMethod) || !verificationMethod.StartsWith(DidKeyPrefix, StringComparison.Ordinal))
        {
            return null;
        }

        string idAndFragment = verificationMethod[DidKeyPrefix.Length..];
        int fragmentIndex = idAndFragment.IndexOf('#', StringComparison.Ordinal);

        return fragmentIndex >= 0 ? idAndFragment[..fragmentIndex] : idAndFragment;
    }
}