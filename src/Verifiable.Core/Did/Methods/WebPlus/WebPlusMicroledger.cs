using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography.EventLogs;

namespace Verifiable.Core.Did.Methods.WebPlus;

/// <summary>
/// The did:webplus microledger verification: the delegates the
/// <see cref="LogReplayer{TState,TOperation,TProof,TContext}"/> drives to replay a <c>did-documents.jsonl</c>
/// history and decide its validity (did:webplus Draft v0.4, Validation of DID Documents). This is the
/// did:webplus cousin of <see cref="WebVh.WebVhChainVerification"/> and <see cref="WebVh.WebVhProofVerification"/>.
/// </summary>
/// <remarks>
/// <para>
/// Each <c>did-documents.jsonl</c> line is one verified link: its <c>selfHash</c> commits the document to itself,
/// its <c>prevDIDDocumentSelfHash</c> chains it to its predecessor, and its proofs authorize the change under the
/// predecessor's <c>updateRules</c>. The verification fails closed — the first link that does not hold ends the
/// verified chain.
/// </para>
/// <para>
/// The work is split across the replay delegates: <see cref="ClassifyEntry"/> labels each entry,
/// <see cref="CreateChainVerification"/> checks the self-hash and the <c>prevDIDDocumentSelfHash</c> chain,
/// <see cref="ValidateProofAsync"/> runs the single-document data-model validation, verifies every proof
/// (WP-VAL-6) and the non-root cross-document obligations (WP-VAL-7a–e), and <see cref="ApplyEntry"/> folds the
/// document's control fields into the carried <see cref="WebPlusState"/>.
/// </para>
/// </remarks>
public static class WebPlusMicroledger
{
    /// <summary>
    /// Classifies a microledger entry: the first entry is the genesis (root) document; a document whose
    /// <c>updateRules</c> is the <c>{}</c> disallow form is a deactivation (tombstone); every other entry is an
    /// update (did:webplus Draft v0.4, DID Deactivate).
    /// </summary>
    /// <param name="entry">The entry to classify.</param>
    /// <returns>The entry's classification.</returns>
    public static LogEntryClassification ClassifyEntry(LogEntry<WebPlusRawEntry, string> entry)
    {
        ArgumentNullException.ThrowIfNull(entry);

        if(entry.Index == 0)
        {
            return LogEntryClassification.Genesis;
        }

        if(entry.Operation?.UpdateRules is DisallowUpdateRule)
        {
            return LogEntryClassification.Deactivate;
        }

        return LogEntryClassification.Update;
    }


    /// <summary>
    /// Builds the <see cref="VerifyChainIntegrityDelegate{TOperation,TProof}"/> for did:webplus replay: each
    /// document MUST be validly self-hashed (WP-SH), and its <c>prevDIDDocumentSelfHash</c> MUST equal the
    /// <c>selfHash</c> of the entry the replayer actually verified before it (WP-VAL-7b and the genesis/non-root
    /// classification). The configuration is bound from <paramref name="context"/>; the per-entry inputs arrive
    /// as the delegate's parameters.
    /// </summary>
    /// <param name="context">The verification seams and self-hash algorithm.</param>
    /// <returns>The chain-integrity delegate.</returns>
    public static VerifyChainIntegrityDelegate<WebPlusRawEntry, string> CreateChainVerification(WebPlusValidationContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        return (entry, previousEntryDigest, cancellationToken) => VerifyChainAsync(entry, previousEntryDigest, context, cancellationToken);
    }


    //The chain-integrity check for one did:webplus microledger entry: the document MUST be validly self-hashed
    //(WP-SH) and, for a non-root entry, its prevDIDDocumentSelfHash MUST equal the verified predecessor's selfHash
    //(WP-VAL-7b). The self-hash digest is awaited through the async seam.
    private static async ValueTask<string?> VerifyChainAsync(
        LogEntry<WebPlusRawEntry, string> entry,
        ReadOnlyMemory<byte>? previousEntryDigest,
        WebPlusValidationContext context,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if(entry.Operation is not WebPlusRawEntry raw)
        {
            return "The did:webplus microledger entry carries no parsed content.";
        }

        if(raw.Document.SelfHash is not { Length: > 0 } selfHash)
        {
            return "The did:webplus DID document MUST have a 'selfHash'.";
        }

        //WP-SH: the document MUST be validly self-hashed — it commits to its own content.
        bool selfHashVerifies = await WebPlusSelfHash.VerifyAsync(
            entry.CanonicalBytes, selfHash.AsMemory(), context.MultihashCode, context.DigestLength, context.ComputeDigest, context.DigestTag, context.Base64UrlEncoder, context.MemoryPool, cancellationToken).ConfigureAwait(false);
        if(!selfHashVerifies)
        {
            return $"The did:webplus DID document 'selfHash' '{selfHash}' does not verify against its content.";
        }

        string? prevDidDocumentSelfHash = raw.Document.PrevDidDocumentSelfHash;
        if(previousEntryDigest is null)
        {
            //Genesis: a root document MUST NOT reference a predecessor.
            return prevDidDocumentSelfHash is null
                ? null
                : "The did:webplus root DID document MUST NOT have a 'prevDIDDocumentSelfHash'.";
        }

        //Non-root: prevDIDDocumentSelfHash MUST equal the selfHash of the entry verified before it. The
        //replayer threads the authoritative predecessor digest (its UTF-8 selfHash), so a forged
        //prevDIDDocumentSelfHash that does not match the verified predecessor is rejected (WP-VAL-7b).
        if(prevDidDocumentSelfHash is null)
        {
            return "The did:webplus non-root DID document MUST have a 'prevDIDDocumentSelfHash'.";
        }

        string predecessorSelfHash = Encoding.UTF8.GetString(previousEntryDigest.Value.Span);

        return string.Equals(prevDidDocumentSelfHash, predecessorSelfHash, StringComparison.Ordinal)
            ? null
            : $"The did:webplus 'prevDIDDocumentSelfHash' '{prevDidDocumentSelfHash}' does not equal the verified predecessor's selfHash '{predecessorSelfHash}'.";
    }


    /// <summary>
    /// The <see cref="ValidateProofDelegate{TState,TOperation,TProof,TContext}"/> for did:webplus replay: the
    /// single-document data-model validation (WP-VAL-1–5,10), the proof verification (WP-VAL-6), and — for a
    /// non-root document — the cross-document obligations against its verified predecessor (WP-VAL-7a–e).
    /// </summary>
    /// <param name="entry">The entry whose authorization is validated.</param>
    /// <param name="currentState">The accumulated state of the verified predecessor (empty for the genesis entry).</param>
    /// <param name="context">The verification seams and self-hash algorithm.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns><see langword="null"/> when the document is valid; otherwise the reason it is invalid.</returns>
    public static async ValueTask<string?> ValidateProofAsync(
        LogEntry<WebPlusRawEntry, string> entry,
        LogState<WebPlusState> currentState,
        WebPlusValidationContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(currentState);
        ArgumentNullException.ThrowIfNull(context);

        if(entry.Operation is not WebPlusRawEntry raw)
        {
            return "The did:webplus microledger entry carries no parsed content.";
        }

        WebPlusDidDocument document = raw.Document;

        //Steps 1–5 and the root versionId constraint: the single-document obligations decided in isolation.
        string? dataModelError = WebPlusDataModelValidation.Validate(entry.CanonicalBytes, context.Parser, context.Canonicalizer);
        if(dataModelError is not null)
        {
            return dataModelError;
        }

        //WP-VAL-6: the document MUST be validly self-hashed-signed-data — every proof MUST verify. The keys that
        //produced the valid proofs feed the predecessor's update-rule evaluation below (WP-VAL-7e).
        WebPlusProofVerificationResult proofResult = await WebPlusProofs.VerifyAllAsync(
            entry.CanonicalBytes,
            document.SelfHash!,
            context.MultihashCode,
            context.DigestLength,
            context.ProofExtractor,
            context.Base64UrlDecoder,
            context.Base64UrlEncoder,
            context.Base58Decoder,
            context.MemoryPool,
            cancellationToken).ConfigureAwait(false);
        if(proofResult.Error is not null)
        {
            return proofResult.Error;
        }

        switch(currentState)
        {
            case EmptyLogState<WebPlusState>:
            {
                //The genesis (root) document: the root versionId==0 constraint is enforced by the data-model
                //validation, and a root carries no predecessor to check against.
                return null;
            }
            case ActiveLogState<WebPlusState> active:
            {
                return await ValidateAgainstPredecessorAsync(document, active.Value, proofResult.SatisfiedKeys, context, cancellationToken).ConfigureAwait(false);
            }
            default:
            {
                //A deactivated DID is a tombstone; no further document is authorized.
                return "The did:webplus DID is deactivated; no further updates are permitted.";
            }
        }
    }


    //The non-root cross-document obligations against the verified predecessor (did:webplus Validation of DID
    //Documents, step 7 — non-root branch).
    private static async ValueTask<string?> ValidateAgainstPredecessorAsync(
        WebPlusDidDocument document,
        WebPlusState predecessor,
        IReadOnlySet<string> satisfiedKeys,
        WebPlusValidationContext context,
        CancellationToken cancellationToken)
    {
        //did:webplus Draft v0.4, Validation of DID Documents / L1406: a non-root DID document "contains proofs
        //that are required to satisfy the update rules of the previous DID document" — only the root MAY omit
        //proofs. A non-root document that carried no valid proof produces an empty satisfied-key set; rejecting it
        //here makes the requirement explicit, so a degenerate predecessor updateRules can never authorize a
        //zero-proof update (a defence-in-depth complement to rejecting such rules at parse).
        if(satisfiedKeys.Count == 0)
        {
            return "The did:webplus non-root DID document MUST carry at least one valid proof.";
        }

        //WP-VAL-7a: the id MUST be identical to the predecessor's id.
        if(!string.Equals(document.Id?.Id, predecessor.Id, StringComparison.Ordinal))
        {
            return $"The did:webplus DID document 'id' MUST be identical to its predecessor's; '{document.Id?.Id}' != '{predecessor.Id}'.";
        }

        //WP-VAL-7b: prevDIDDocumentSelfHash MUST equal the predecessor's selfHash. (Also enforced against the
        //replayer-threaded digest by the chain-integrity check; restated here per the spec's step 7.)
        if(!string.Equals(document.PrevDidDocumentSelfHash, predecessor.SelfHash, StringComparison.Ordinal))
        {
            return $"The did:webplus 'prevDIDDocumentSelfHash' MUST equal the predecessor's selfHash; '{document.PrevDidDocumentSelfHash}' != '{predecessor.SelfHash}'.";
        }

        //WP-VAL-7c: validFrom MUST be strictly later than the predecessor's validFrom.
        if(!IsStrictlyLater(document.ValidFrom, predecessor.ValidFrom))
        {
            return $"The did:webplus 'validFrom' '{document.ValidFrom}' MUST be strictly later than the predecessor's '{predecessor.ValidFrom}'.";
        }

        //WP-VAL-7d: versionId MUST be exactly one greater than the predecessor's.
        if(document.VersionId != predecessor.VersionId + 1)
        {
            return $"The did:webplus 'versionId' '{document.VersionId}' MUST be one greater than the predecessor's '{predecessor.VersionId}'.";
        }

        //WP-VAL-7e: the proofs MUST satisfy the predecessor's updateRules. Extraneous valid proofs not needed by
        //the rules are allowed and simply ignored (WP-VAL-9), which the set-based evaluation does naturally.
        if(!await WebPlusUpdateRuleEvaluation.IsSatisfiedAsync(predecessor.UpdateRules, satisfiedKeys, context.HashedKeyMatcher, cancellationToken).ConfigureAwait(false))
        {
            return "The did:webplus proofs do not satisfy the predecessor's updateRules.";
        }

        return null;
    }


    /// <summary>
    /// The <see cref="ApplyDelegate{TState,TOperation,TProof}"/> for did:webplus replay: folds the verified
    /// document's control fields into the carried <see cref="WebPlusState"/>, advancing to the active (or, for a
    /// deactivation, terminal) state.
    /// </summary>
    /// <param name="classification">The entry's classification.</param>
    /// <param name="currentState">The current log state before this entry is applied.</param>
    /// <param name="entry">The entry to apply.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The new log state and <see langword="null"/> on success, or the unchanged state and an error.</returns>
    public static ValueTask<(LogState<WebPlusState> State, string? Error)> ApplyEntry(
        LogEntryClassification classification,
        LogState<WebPlusState> currentState,
        LogEntry<WebPlusRawEntry, string> entry,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(currentState);
        ArgumentNullException.ThrowIfNull(entry);
        cancellationToken.ThrowIfCancellationRequested();

        if(entry.Operation is not WebPlusRawEntry raw)
        {
            return ValueTask.FromResult((currentState, (string?)"The did:webplus microledger entry carries no parsed content."));
        }

        WebPlusDidDocument document = raw.Document;
        if(document.Id?.Id is not { Length: > 0 } id || document.SelfHash is not { Length: > 0 } selfHash
            || document.ValidFrom is not { Length: > 0 } validFrom || document.VersionId is not { } versionId)
        {
            return ValueTask.FromResult((currentState, (string?)"The did:webplus DID document is missing a control field required to fold its state."));
        }

        //A genesis entry starts the active state; an update or deactivation advances it; both require the
        //corresponding prior state, which proof validation already established. Any other combination is a
        //malformed log.
        bool validTransition = classification == LogEntryClassification.Genesis
            ? currentState is EmptyLogState<WebPlusState>
            : (classification == LogEntryClassification.Update || classification == LogEntryClassification.Deactivate)
                && currentState is ActiveLogState<WebPlusState>;

        if(!validTransition)
        {
            return ValueTask.FromResult((currentState, (string?)$"The did:webplus entry at index {entry.Index} cannot be applied to state '{currentState.GetType().Name}'."));
        }

        WebPlusState state = new(id, selfHash, validFrom, versionId, raw.UpdateRules);
        LogState<WebPlusState> nextState = classification == LogEntryClassification.Deactivate
            ? new DeactivatedLogState<WebPlusState>(state)
            : new ActiveLogState<WebPlusState>(state);

        return ValueTask.FromResult((nextState, (string?)null));
    }


    //WP-VAL-7c: whether validFrom is strictly later than the predecessor's. Both are RFC 3339 timestamps the
    //single-document validation already accepted; a value that does not parse cannot be ordered, so it is not
    //strictly later.
    private static bool IsStrictlyLater(string? validFrom, string? predecessorValidFrom)
    {
        return validFrom is { Length: > 0 } value
            && predecessorValidFrom is { Length: > 0 } previous
            && DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out DateTimeOffset valueTime)
            && DateTimeOffset.TryParse(previous, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out DateTimeOffset previousTime)
            && valueTime > previousTime;
    }
}
