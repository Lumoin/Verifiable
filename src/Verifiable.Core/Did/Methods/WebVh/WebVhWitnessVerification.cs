using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Core.Did.Methods.WebVh;

/// <summary>
/// Verifies the did:webvh witness proofs (<c>did-witness.json</c>): that every DID Log entry which has an
/// active witness rule is approved by a threshold of the then-active witnesses (did:webvh v1.0, DID
/// Witnesses, Verifying Witness Proofs During Resolution). This is the second security gate of did:webvh
/// resolution — it runs after the per-entry replay (entryHash chain, controller proof, pre-rotation) has
/// succeeded, and it terminates resolution fail-closed when any required threshold is not met.
/// </summary>
/// <remarks>
/// <para>
/// Witnesses defend against a combined compromise of the DID Controller's update key(s) <em>and</em> the web
/// server hosting the DID Log: even with both, an attacker cannot rewrite history without also compromising a
/// threshold of the independent witnesses, because each historical entry has to carry threshold witness
/// approvals. A witness approval is an <c>eddsa-jcs-2022</c> Data Integrity proof signed by a witness's
/// <c>did:key</c> over the single-property object <c>{"versionId": "&lt;n-hash&gt;"}</c>; a valid proof for a
/// given <c>versionId</c> implies approval of that entry and (by the hash chain) all prior entries.
/// </para>
/// <para>
/// <strong>Which witness rule must witness a given entry — the fold-timing decision.</strong> The witness
/// rule that an entry must satisfy is NOT necessarily the rule that entry declares. The did:webvh
/// specification states this in two places that pull in different directions:
/// </para>
/// <list type="bullet">
///   <item><description>
///     The generic parameter-update rule (Read (Resolve), step 1): <em>"updates to the <c>witnesses</c> array
///     take effect only AFTER the entry in which they are defined has been published."</em> Read literally for
///     all witness changes, an entry that changes the witness list is witnessed by the <em>prior</em> active
///     list, and the new list governs the <em>next</em> entry.
///   </description></item>
///   <item><description>
///     The witness-specific rule (Parameters, the witness parameter): <em>"If the witness property is updated
///     from <c>{}</c>, the change is immediately active, and the corresponding log entry MUST be witnessed."</em>
///     Read literally, an entry that first activates witnesses is witnessed by its own newly-declared list.
///   </description></item>
/// </list>
/// <para>
/// These two clauses conflict for one case only — a mid-log entry that first activates witnesses from the
/// empty <c>{}</c> default. The two reference implementations resolve the conflict in opposite ways and agree
/// with neither each other nor the spec on both counts: <c>didwebvh-py</c> (<c>(prev_state or state).witness_rule</c>)
/// always uses the prior rule, so it does not require a mid-log activation entry to be witnessed; <c>didwebvh-ts</c>
/// (<c>getRequiredWitnessForEntry</c>) uses the newly-declared rule whenever an entry declares one, so it also
/// requires a <em>replacement</em> entry to be witnessed by the new (not the prior) list. The area is a known
/// under-specified one — it is the subject of an active cross-implementation security-audit clarification
/// (didwebvh PR&#160;#282) and was raised in review (didwebvh issue&#160;#140).
/// </para>
/// <para>
/// This resolver resolves the witnessing rule for an entry as <c>prior is null ? effective : prior</c> — the
/// genesis entry is witnessed by its own folded rule (it has no prior), and every later entry is witnessed by
/// the rule active <em>before</em> its own declaration. This matches <c>didwebvh-py</c> and the generic
/// "take effect after publication" rule. The choice is deliberate on two grounds. First, it is
/// <strong>security-neutral</strong> relative to requiring a mid-log activation entry to be witnessed:
/// requiring an entry to be witnessed by witnesses <em>it itself introduces</em> protects nothing, because an
/// attacker forging that entry would simply introduce their own witnesses. The security-meaningful invariant
/// is that any change to an <em>already-active</em> witness set — a replacement or a disable — MUST be approved
/// by the <em>prior</em> (established) set, and that invariant is preserved here (a replacement/disable entry
/// is witnessed by the prior rule). Second, it is the most interoperable choice: it accepts logs produced by
/// both reference implementations (a witness proof present on an activation entry is simply not required, never
/// rejected).
/// </para>
/// </remarks>
public static class WebVhWitnessVerification
{
    private const string DataIntegrityProofType = "DataIntegrityProof";
    private const string EddsaJcs2022Cryptosuite = "eddsa-jcs-2022";
    private const string AssertionMethodPurpose = "assertionMethod";
    private const string DidKeyPrefix = "did:key:";

    private const int Sha256DigestLength = 32;
    private const int HashDataLength = 2 * Sha256DigestLength;


    /// <summary>
    /// The witness rule that MUST witness the entry at <paramref name="index"/>, or <see langword="null"/>
    /// when that entry needs no witnessing. See the fold-timing remarks on
    /// <see cref="WebVhWitnessVerification"/> for why this is the prior rule rather than the entry's own.
    /// </summary>
    /// <param name="states">The verified replay states, in order; <c>states[i]</c> is the state after entry i.</param>
    /// <param name="index">The zero-based entry index.</param>
    /// <returns>The active witness rule governing the entry, or <see langword="null"/>.</returns>
    public static WebVhWitnessRule? ResolveWitnessingRule(IReadOnlyList<WebVhState> states, int index)
    {
        ArgumentNullException.ThrowIfNull(states);

        //prior is null only for the genesis entry, which is witnessed by its own folded rule; every later
        //entry is witnessed by the rule active before its declaration (didwebvh-py (prev_state or state)).
        WebVhWitnessRule? prior = index == 0 ? null : states[index - 1].Parameters.Witness;

        return prior ?? (index == 0 ? states[index].Parameters.Witness : null);
    }


    /// <summary>
    /// Whether any entry in the replay requires witnessing, so the resolver knows to retrieve and verify the
    /// <c>did-witness.json</c> file (did:webvh v1.0: the file is fetched only when witnesses are active).
    /// </summary>
    /// <param name="states">The verified replay states, in order.</param>
    /// <returns><see langword="true"/> when at least one entry has an active witness rule.</returns>
    public static bool RequiresWitnessing(IReadOnlyList<WebVhState> states)
    {
        ArgumentNullException.ThrowIfNull(states);

        for(int index = 0; index < states.Count; index++)
        {
            if(ResolveWitnessingRule(states, index) is not null)
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Confirms a threshold of the then-active witnesses approves every entry that requires witnessing, and
    /// terminates fail-closed otherwise (did:webvh v1.0, Verifying Witness Proofs During Resolution).
    /// </summary>
    /// <param name="states">The verified replay states up to and including the resolved target, in order.</param>
    /// <param name="witnessFile">The fetched <c>did-witness.json</c> file: parsed records plus its tagged source bytes.</param>
    /// <param name="context">The cryptographic seams (canonicalizers, hash, coders, pool).</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns><see langword="null"/> when every required threshold is met; otherwise an error message.</returns>
    public static async ValueTask<string?> VerifyAsync(
        IReadOnlyList<WebVhState> states,
        WebVhWitnessFile witnessFile,
        WebVhValidationContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(states);
        ArgumentNullException.ThrowIfNull(witnessFile);
        ArgumentNullException.ThrowIfNull(context);

        //The published versionIds, indexed by version number - 1. A witness proof only counts when its
        //versionId matches the entry actually published at that position (did:webvh v1.0: "Resolvers MUST
        //ignore proofs with versionIds not in the DID Log file").
        string[] publishedVersionIds = new string[states.Count];
        for(int index = 0; index < states.Count; index++)
        {
            publishedVersionIds[index] = states[index].VersionId;
        }

        //witnessId -> the published version numbers that witness has a verified approval for. A witness is
        //recorded at most once per version (one approval per witness per entry), so the set collapses duplicates.
        var validated = new Dictionary<string, HashSet<int>>(StringComparer.Ordinal);

        for(int entryIndex = 0; entryIndex < witnessFile.Entries.Length; entryIndex++)
        {
            WebVhWitnessProofEntry witnessEntry = witnessFile.Entries[entryIndex];

            //A proof can only be attributed to a published entry: the versionId MUST parse to a version number
            //whose published versionId matches byte-for-byte. Unpublished or foreign versionIds are ignored.
            if(!WebVhVersionId.TryParse(witnessEntry.VersionId, out int versionNumber, out _)
                || versionNumber < 1
                || versionNumber > publishedVersionIds.Length
                || !string.Equals(publishedVersionIds[versionNumber - 1], witnessEntry.VersionId, StringComparison.Ordinal))
            {
                continue;
            }

            for(int proofIndex = 0; proofIndex < witnessEntry.Proofs.Length; proofIndex++)
            {
                //An individual invalid witness proof is tolerated: it is dropped from the count, and the
                //threshold may still be met by other valid proofs (did:webvh v1.0, MAY ignore invalid proofs).
                string? witnessId = await VerifyWitnessProofAsync(
                    witnessEntry.Proofs[proofIndex], witnessFile, entryIndex, proofIndex, witnessEntry.VersionId, context, cancellationToken).ConfigureAwait(false);
                if(witnessId is null)
                {
                    continue;
                }

                if(!validated.TryGetValue(witnessId, out HashSet<int>? approvedVersions))
                {
                    approvedVersions = new HashSet<int>();
                    validated[witnessId] = approvedVersions;
                }

                approvedVersions.Add(versionNumber);
            }
        }

        for(int index = 0; index < states.Count; index++)
        {
            if(ResolveWitnessingRule(states, index) is not WebVhWitnessRule rule)
            {
                continue;
            }

            //A valid proof for the entry's own version, OR for any later published version, satisfies it: a
            //later approval implies approval of all prior entries (did:webvh v1.0: "current or any later
            //published log entries"). The entry at index i has version number i + 1.
            int entryVersionNumber = index + 1;
            int approvals = 0;
            foreach(string witness in rule.Witnesses)
            {
                if(validated.TryGetValue(witness, out HashSet<int>? approvedVersions) && HasApprovalAtOrAfter(approvedVersions, entryVersionNumber))
                {
                    approvals++;
                }
            }

            if(approvals < rule.Threshold)
            {
                return $"The did:webvh entry '{publishedVersionIds[index]}' has {approvals} witness approval(s); the active witness rule requires {rule.Threshold}.";
            }
        }

        return null;
    }


    private static bool HasApprovalAtOrAfter(HashSet<int> approvedVersions, int entryVersionNumber)
    {
        foreach(int approvedVersion in approvedVersions)
        {
            if(approvedVersion >= entryVersionNumber)
            {
                return true;
            }
        }

        return false;
    }


    //Verifies one witness proof over JCS({"versionId": versionId}) and returns the witness did:key identity
    //(did:key:<multikey>) on success, or null when the proof does not verify or is structurally invalid.
    private static async ValueTask<string?> VerifyWitnessProofAsync(
        WebVhProof proof,
        WebVhWitnessFile witnessFile,
        int entryIndex,
        int proofIndex,
        string versionId,
        WebVhValidationContext context,
        CancellationToken cancellationToken)
    {
        if(!string.Equals(proof.Type, DataIntegrityProofType, StringComparison.Ordinal)
            || !string.Equals(proof.Cryptosuite, EddsaJcs2022Cryptosuite, StringComparison.Ordinal)
            || !string.Equals(proof.ProofPurpose, AssertionMethodPurpose, StringComparison.Ordinal))
        {
            return null;
        }

        if(proof.ProofValue is not { Length: > 0 })
        {
            return null;
        }

        if(ExtractWitnessMultikey(proof.VerificationMethod) is not { } multikey)
        {
            return null;
        }

        try
        {
            return await VerifyWitnessSignatureAsync(proof, witnessFile, entryIndex, proofIndex, versionId, multikey, context, cancellationToken).ConfigureAwait(false);
        }
        catch(Exception exception) when(exception is FormatException or ArgumentException)
        {
            return null;
        }
    }


    private static async ValueTask<string?> VerifyWitnessSignatureAsync(
        WebVhProof proof,
        WebVhWitnessFile witnessFile,
        int entryIndex,
        int proofIndex,
        string versionId,
        string multikey,
        WebVhValidationContext context,
        CancellationToken cancellationToken)
    {
        TaggedMemory<byte> document = context.Canonicalizer.WitnessDocumentInput(versionId);
        TaggedMemory<byte> proofOptions = context.Canonicalizer.WitnessProofOptionsInput(witnessFile, entryIndex, proofIndex);
        using IMemoryOwner<byte> signatureOwner = ProofValueCodecs.DecodeBase58Btc(proof.ProofValue!, context.Base58Decoder, context.MemoryPool);
        (IMemoryOwner<byte> keyData, CryptoAlgorithm algorithm) = MultibaseSerializer.DecodeKey(multikey, context.Base58Decoder, context.MemoryPool);

        using(keyData)
        {
            //A witness did:key MUST decode to an Ed25519 key compatible with the eddsa-jcs-2022 cryptosuite.
            if(algorithm != CryptoAlgorithm.Ed25519)
            {
                return null;
            }

            //eddsa-jcs-2022 signs SHA-256(JCS(proofOptions)) concatenated with SHA-256(JCS(document)). Both digests
            //flow through the registered ComputeDigestDelegate (telemetry, CBOM stamping, event emission); this method
            //is already async, so it awaits the digest. The digests are computed before the hashData span is taken,
            //so no Span local spans an await.
            using IMemoryOwner<byte> hashOwner = context.MemoryPool.Rent(HashDataLength);
            using(DigestValue proofOptionsDigest = await CryptographicKeyEvents.ComputeDigestAsync(
                context.ComputeDigest, new System.Buffers.ReadOnlySequence<byte>(proofOptions.Memory), Sha256DigestLength, CryptoTags.Sha256Digest, context.MemoryPool, cancellationToken: cancellationToken).ConfigureAwait(false))
            using(DigestValue documentDigest = await CryptographicKeyEvents.ComputeDigestAsync(
                context.ComputeDigest, new System.Buffers.ReadOnlySequence<byte>(document.Memory), Sha256DigestLength, CryptoTags.Sha256Digest, context.MemoryPool, cancellationToken: cancellationToken).ConfigureAwait(false))
            {
                Span<byte> hashData = hashOwner.Memory.Span[..HashDataLength];
                proofOptionsDigest.AsReadOnlySpan().CopyTo(hashData[..Sha256DigestLength]);
                documentDigest.AsReadOnlySpan().CopyTo(hashData[Sha256DigestLength..]);
            }

            VerificationDelegate verify = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, Purpose.Verification);
            (bool isValid, CryptoEvent? evt) = await verify(hashOwner.Memory[..HashDataLength], signatureOwner.Memory, keyData.Memory, null, cancellationToken).ConfigureAwait(false);

            CryptographicKeyEvents.Emit(evt);

            return isValid ? DidKeyPrefix + multikey : null;
        }
    }


    //Extracts the multikey from a witness proof's verificationMethod. A witness verificationMethod is a
    //did:key verification-method reference of the form did:key:<multikey>#<multikey>; the multibase body and
    //fragment MUST both be present and byte-equal, because the body authoritatively defines the key while the
    //fragment is only the method id — permitting them to diverge would let a proof claim it was made by one
    //key while signed by another (did:webvh v1.0, Witness DIDs; the did:key body/fragment binding). The bare
    //did:key DID with no fragment is not a verification-method reference and is rejected, matching the
    //didwebvh-py and -ts resolvers.
    private static string? ExtractWitnessMultikey(string? verificationMethod)
    {
        if(string.IsNullOrEmpty(verificationMethod) || !verificationMethod.StartsWith(DidKeyPrefix, StringComparison.Ordinal))
        {
            return null;
        }

        string idAndFragment = verificationMethod[DidKeyPrefix.Length..];
        int fragmentIndex = idAndFragment.IndexOf('#', StringComparison.Ordinal);
        if(fragmentIndex < 0)
        {
            return null;
        }

        string body = idAndFragment[..fragmentIndex];
        string fragment = idAndFragment[(fragmentIndex + 1)..];

        return body.Length > 0 && string.Equals(body, fragment, StringComparison.Ordinal) ? body : null;
    }
}
