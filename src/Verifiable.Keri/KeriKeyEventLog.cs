using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cesr;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Cryptography.EventLogs;

namespace Verifiable.Keri;

/// <summary>
/// Resolves the delegating seal that authorizes a delegated establishment event: given the delegated event,
/// returns the key event seal anchoring it in the delegator's KEL, or <see langword="null"/> when none does. A
/// caller that has verified the delegator's KEL builds this over that KEL's anchored seals (with
/// <see cref="KeriDelegation.FindDelegationSeal"/>), so the cross-log delegation check rides through one seam the
/// replayer drops out to rather than the replayer reaching across logs itself.
/// </summary>
/// <param name="delegatedEvent">The delegated inception or rotation whose delegating seal is sought.</param>
/// <returns>The delegating key event seal from the delegator's verified KEL, or <see langword="null"/> when it anchors none for this event.</returns>
public delegate KeriKeyEventSeal? DelegationSealResolver(KeriKeyEvent delegatedEvent);

/// <summary>
/// The verification context a KERI Key Event Log (KEL) needs when it is replayed through the generic
/// <see cref="LogReplayer{TState,TOperation,TProof,TContext}"/>: the digest seam and pool the proof-validation
/// step uses to verify a rotation's pre-rotation commitments and an event's SAID over its received bytes, and an
/// optional resolver for the delegating seal a delegated event requires.
/// </summary>
/// <remarks>
/// The seams ride in this context, the replayer's single injection point for proof-validation inputs, rather than
/// being captured in a delegate closure, so the apply step stays seam-free and no caller data is hidden in a
/// lambda.
/// </remarks>
public sealed class KeriReplayValidationContext
{
    /// <summary>Gets the digest implementation used to verify pre-rotation commitments and event SAIDs.</summary>
    public required ComputeDigestDelegate ComputeDigest { get; init; }

    /// <summary>Gets the pool the digest buffers are rented from.</summary>
    public required MemoryPool<byte> MemoryPool { get; init; }

    /// <summary>
    /// Gets the resolver for a delegated event's delegating seal, supplied by a caller that has verified the
    /// delegator's KEL. When it is <see langword="null"/>, the replay has no delegator KEL, so a delegated event
    /// fails closed; when present, a delegated event is accepted only if the resolver finds its delegating seal.
    /// </summary>
    public DelegationSealResolver? ResolveDelegationSeal { get; init; }
}

/// <summary>
/// Replays a KERI Key Event Log (KEL) as an instantiation of the generic authenticated append-only log: it builds
/// the <see cref="LogReplayContext{TState,TOperation,TProof,TContext}"/> whose delegates fold KERI key events into
/// <see cref="KeriKeyState"/>, verify the prior-event hash chain, and validate each event's SAID, controller
/// signature threshold, and pre-rotation against the evolving key state. A KEL is therefore verified by the same
/// engine that verifies did:webvh and did:webplus microledgers, not by a hand-rolled chain walker.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the KERI specification's key event processing. The replay maps onto the engine as follows: an
/// inception (<c>icp</c>) at index zero is the genesis; rotations (<c>rot</c>) and interactions (<c>ixn</c>) are
/// updates; the proof type is the neutral <see cref="CryptoProof"/>, so KERI controller signatures verify through
/// the same <c>CryptoFunctionRegistry</c> seam as every other domain. The chain-integrity step compares an event's
/// prior SAID (field <c>p</c>) against the SAID the replayer threaded from the verified predecessor; the
/// proof-validation step verifies the event SAID over its received bytes, the pre-rotation commitments for a
/// rotation, and that a threshold of the event's authorizing keys signed it; the apply step folds the event into
/// key state.
/// </para>
/// <para>
/// The authorizing key set is resolved per event type, because an establishment event is signed by the keys it
/// itself establishes: an inception and a rotation are signed by their own current keys (<c>k</c>), while an
/// interaction is signed by the current keys carried in the accumulated state. The signing threshold (<c>kt</c>)
/// is read from the same place. A rotation additionally proves rotation authority: its signatures must satisfy
/// the prior establishment event's next threshold (<c>nt</c>) over the exposed pre-rotated keys, which supports
/// partial, reserve, and augmented rotation. Both unweighted and fractionally weighted thresholds are honored. A
/// delegated event (<c>dip</c> or <c>drt</c>) additionally requires a delegating seal in the delegator's KEL: when
/// the context carries a <see cref="DelegationSealResolver"/> (built by a caller that has verified the delegator's
/// KEL), the event is accepted only if the resolver finds that seal; without a resolver, a delegated event fails
/// closed, because a single-KEL replay cannot reach the delegator's KEL.
/// </para>
/// </remarks>
public static class KeriKeyEventLog
{
    /// <summary>
    /// Builds the replay context for a KERI Key Event Log.
    /// </summary>
    /// <param name="computeDigest">The digest implementation (caller-supplied or the registered default) the SAID and pre-rotation checks use.</param>
    /// <param name="pool">The pool the digest buffers are rented from.</param>
    /// <param name="timeProvider">The clock the replay uses (KERI key events carry no version time, so it is currently unused by the folds but kept for parity with the engine).</param>
    /// <param name="resolveDelegationSeal">An optional resolver for a delegated event's delegating seal, supplied by a caller that has verified the delegator's KEL; when omitted, a delegated event fails closed.</param>
    /// <returns>The replay context to pass to <see cref="LogReplayer{TState,TOperation,TProof,TContext}.ReplayAsync"/>.</returns>
    public static LogReplayContext<KeriKeyState, KeriKeyEvent, CryptoProof, KeriReplayValidationContext> CreateReplayContext(
        ComputeDigestDelegate computeDigest,
        MemoryPool<byte> pool,
        TimeProvider timeProvider,
        DelegationSealResolver? resolveDelegationSeal = null)
    {
        ArgumentNullException.ThrowIfNull(computeDigest);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(timeProvider);

        return new LogReplayContext<KeriKeyState, KeriKeyEvent, CryptoProof, KeriReplayValidationContext>
        {
            Classify = OperationClassifiers.ByIndex<KeriKeyEvent, CryptoProof>(),
            VerifyChainIntegrity = VerifyChainIntegrity,
            ValidateProof = ValidateProofAsync,
            ValidationContext = new KeriReplayValidationContext { ComputeDigest = computeDigest, MemoryPool = pool, ResolveDelegationSeal = resolveDelegationSeal },
            Apply = Apply,
            TimeProvider = timeProvider
        };
    }


    /// <summary>
    /// Verifies a KERI event's hash-chain position: its claimed prior SAID (field <c>p</c>, carried as the entry's
    /// previous digest) MUST equal the SAID the replayer threaded forward from the verified predecessor. The
    /// genesis inception has no predecessor, so both are absent.
    /// </summary>
    private static ValueTask<string?> VerifyChainIntegrity(
        LogEntry<KeriKeyEvent, CryptoProof> entry,
        ReadOnlyMemory<byte>? previousEntryDigest,
        CancellationToken cancellationToken)
    {
        bool matches = NullableSpanEqual(entry.PreviousDigest, previousEntryDigest);

        return ValueTask.FromResult(matches
            ? null
            : $"The KERI event at sequence {entry.Index} does not chain to its verified predecessor.");
    }


    /// <summary>
    /// Validates a KERI event cryptographically against the accumulated key state: the event's SAID over its
    /// received bytes, a rotation's pre-rotation commitments, and the event's signatures. An event proves signing
    /// authority by satisfying its own signing threshold; a rotation additionally proves rotation authority by
    /// satisfying the prior establishment event's next threshold over its exposed pre-rotated keys.
    /// </summary>
    private static async ValueTask<string?> ValidateProofAsync(
        LogEntry<KeriKeyEvent, CryptoProof> entry,
        LogState<KeriKeyState> currentState,
        KeriReplayValidationContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(entry);
        ArgumentNullException.ThrowIfNull(context);

        if(entry.Operation is not KeriKeyEvent keyEvent)
        {
            return $"The KERI log entry at sequence {entry.Index} carries no key event.";
        }

        //A delegated establishment event is valid only when the delegator's KEL anchors a delegating seal of it
        //(KERI specification, Cooperative Delegation). The resolver, supplied by a caller that has verified the
        //delegator's KEL, finds that seal: with no resolver the replay has no delegator KEL and a delegated event
        //fails closed; with a resolver that finds none, the event is unanchored and also fails closed. When the
        //seal is found, the event still proceeds through the SAID, signature, and pre-rotation checks below.
        if(keyEvent is KeriDelegatedInceptionEvent or KeriDelegatedRotationEvent)
        {
            if(context.ResolveDelegationSeal is null)
            {
                return $"The KERI delegated event at sequence {entry.Index} requires its delegating seal to be verified in the delegator's KEL, which this replay was not given a resolver for.";
            }

            if(context.ResolveDelegationSeal(keyEvent) is null)
            {
                return $"The KERI delegated event at sequence {entry.Index} is not anchored by a delegating seal in the delegator's KEL.";
            }
        }

        //The SAID binds the event to its serialization: recompute it over the received bytes with the field reset
        //to the placeholder and require it to equal the claimed SAID before any field is trusted.
        if(!await KeriEventSaid.VerifyAsync(entry.CanonicalBytes, keyEvent.Said, context.ComputeDigest, context.MemoryPool, cancellationToken).ConfigureAwait(false))
        {
            return $"The KERI event SAID '{keyEvent.Said}' does not verify over its serialization.";
        }

        (IReadOnlyList<string>? authorizingKeys, KeriThreshold? threshold, string? keyError) = ResolveAuthorizingKeys(keyEvent, currentState);
        if(keyError is not null)
        {
            return keyError;
        }

        //A rotation establishes two control authorities (KERI specification, General Pre-rotation): rotation
        //authority, proven by signatures from the exposed pre-rotated keys satisfying the prior establishment
        //event's next threshold, and signing authority, proven by signatures satisfying the rotation's own current
        //threshold. The pre-rotation step verifies the revealed keys' commitments where the digest seam and the
        //prior key state are both in hand, and yields the exposed keys placed at their committed positions.
        IReadOnlyList<string?>? exposedPriorNextKeys = null;
        KeriThreshold? priorNextThreshold = null;
        if(keyEvent is KeriRotationEvent rotation && currentState is ActiveLogState<KeriKeyState> priorState)
        {
            try
            {
                exposedPriorNextKeys = await KeriKeyStateMachine.VerifyPreRotationAsync(priorState.Value, rotation, context.ComputeDigest, context.MemoryPool, cancellationToken).ConfigureAwait(false);
                priorNextThreshold = priorState.Value.NextThreshold;
            }
            catch(KeriException exception)
            {
                return exception.Message;
            }
        }

        if(entry.Proofs.IsDefaultOrEmpty)
        {
            return $"The KERI event at sequence {entry.Index} carries no signatures.";
        }

        IReadOnlyList<CryptoProof> verifiedProofs = await CollectVerifiedProofsAsync(entry, cancellationToken).ConfigureAwait(false);

        try
        {
            //Signing authority: a threshold of the event's own authorizing keys signed it.
            if(!SatisfiesThreshold(verifiedProofs, authorizingKeys!, threshold!, context.MemoryPool))
            {
                return $"The KERI event at sequence {entry.Index} was not signed by keys that satisfy its signing threshold.";
            }

            //Rotation authority: a threshold of the exposed prior next keys signed it.
            if(exposedPriorNextKeys is not null && !SatisfiesThreshold(verifiedProofs, exposedPriorNextKeys, priorNextThreshold!, context.MemoryPool))
            {
                return $"The KERI rotation at sequence {entry.Index} was not signed by exposed pre-rotated keys that satisfy the prior next (rotation) threshold.";
            }
        }
        catch(KeriException exception)
        {
            //A weighted threshold whose accumulated rational denominator exceeds its bound is rejected here
            //(KeriThreshold.Fraction) rather than allowed to impose super-linear arbitrary-precision cost on the
            //verifier, so a hostile key event log cannot amplify verification effort through a crafted threshold.
            return exception.Message;
        }

        return null;
    }


    /// <summary>
    /// Resolves the keys and threshold that authorize an event. An establishment event (inception or rotation) is
    /// signed by the keys it itself establishes; an interaction is signed by the current keys in the accumulated
    /// state.
    /// </summary>
    private static (IReadOnlyList<string>? Keys, KeriThreshold? Threshold, string? Error) ResolveAuthorizingKeys(
        KeriKeyEvent keyEvent,
        LogState<KeriKeyState> currentState)
    {
        return keyEvent switch
        {
            KeriInceptionEvent inception => (inception.SigningKeys, inception.SigningThreshold, null),
            KeriRotationEvent rotation => (rotation.SigningKeys, rotation.SigningThreshold, null),
            KeriInteractionEvent interaction => currentState is ActiveLogState<KeriKeyState> active
                ? (active.Value.SigningKeys, active.Value.SigningThreshold, null)
                : (null, null, $"The KERI interaction event at sequence {interaction.SequenceNumber} has no established key state to authorize it."),
            _ => (null, null, "The KERI event is not a modeled key event.")
        };
    }


    /// <summary>
    /// Collects the proofs that produced a valid signature over the event's received bytes: each proof's signer key
    /// is verified once against the canonical bytes, and the proofs that verify are returned so each threshold an
    /// event must satisfy (a rotation must satisfy both its own signing threshold and the prior next rotation
    /// threshold) is tested against the same set, so a signature is never verified more than once.
    /// </summary>
    private static async ValueTask<IReadOnlyList<CryptoProof>> CollectVerifiedProofsAsync(
        LogEntry<KeriKeyEvent, CryptoProof> entry,
        CancellationToken cancellationToken)
    {
        var verifiedProofs = new List<CryptoProof>(entry.Proofs.Length);
        for(int proofIndex = 0; proofIndex < entry.Proofs.Length; proofIndex++)
        {
            CryptoProof proof = entry.Proofs[proofIndex];
            VerificationDelegate verify = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(proof.Algorithm, Purpose.Verification);

            //This resolves and invokes the registry delegate directly rather than through
            //PublicKey.VerifyAsync (no PublicKey is constructed for a bare CryptoProof signer key here), so the
            //VerificationCompletedEvent the delegate constructs is discarded rather than emitted: the emit hook
            //is internal to Verifiable.Cryptography by design (only PrivateKey.SignAsync/PublicKey.VerifyAsync
            //are the sole intended choke points).
            (bool isVerified, CryptoEvent? _) = await verify(
                entry.CanonicalBytes, proof.Signature.AsReadOnlyMemory(), proof.SignerKey.AsReadOnlyMemory(), null, cancellationToken).ConfigureAwait(false);

            if(isVerified)
            {
                verifiedProofs.Add(proof);
            }
        }

        return verifiedProofs;
    }


    /// <summary>
    /// Whether the verified proofs satisfy a threshold over a given key list: each list position whose key produced
    /// one of the verified signatures is a signing position (a <see langword="null"/> entry is a position held in
    /// reserve that no key occupies), and the set of signing positions is tested against the threshold (an
    /// unweighted count or weighted clauses). A proof is matched to a position by the key's canonical identity — its
    /// algorithm and raw public-key bytes, decoded through the one forward verification-key seam
    /// (<see cref="CesrVerificationKeyCodes"/>) — rather than by re-encoding the proof key to a qb64 string, so the
    /// match honors every code the seam admits (both Ed25519 codes today, each registered algorithm as it is added)
    /// with no inverse algorithm-to-code map to drift from it. A list key whose code the seam does not know, or that
    /// is not well-formed CESR, names no verifier and matches nothing (fail closed).
    /// </summary>
    private static bool SatisfiesThreshold(IReadOnlyList<CryptoProof> verifiedProofs, IReadOnlyList<string?> keyList, KeriThreshold threshold, MemoryPool<byte> pool)
    {
        var signingPositions = new HashSet<int>();
        for(int position = 0; position < keyList.Count; position++)
        {
            if(keyList[position] is string key && SignedByAnyProof(key, verifiedProofs, pool))
            {
                _ = signingPositions.Add(position);
            }
        }

        return threshold.IsSatisfiedBy(signingPositions, keyList.Count);

        static bool SignedByAnyProof(string qualifiedKey, IReadOnlyList<CryptoProof> verifiedProofs, MemoryPool<byte> pool)
        {
            CesrParsedPrimitive parsedKey;
            try
            {
                parsedKey = CesrPrimitiveCodec.DecodeText(qualifiedKey, pool);
            }
            catch(CesrFormatException)
            {
                return false;
            }

            using(parsedKey)
            {
                if(!CesrVerificationKeyCodes.TryGetVerificationKeyInfo(parsedKey.Code, out CesrVerificationKeyInfo? keyInfo))
                {
                    return false;
                }

                for(int proofIndex = 0; proofIndex < verifiedProofs.Count; proofIndex++)
                {
                    CryptoProof proof = verifiedProofs[proofIndex];
                    if(proof.Algorithm == keyInfo.Algorithm && proof.SignerKey.AsReadOnlyMemory().Span.SequenceEqual(parsedKey.Raw))
                    {
                        return true;
                    }
                }

                return false;
            }
        }
    }


    /// <summary>
    /// Folds a verified KERI event into key state: an inception establishes it, an interaction advances it, and a
    /// rotation rolls the keys forward (its pre-rotation commitments were verified in the proof-validation step).
    /// </summary>
    private static ValueTask<(LogState<KeriKeyState> State, string? Error)> Apply(
        LogEntryClassification classification,
        LogState<KeriKeyState> currentState,
        LogEntry<KeriKeyEvent, CryptoProof> entry,
        CancellationToken cancellationToken)
    {
        if(entry.Operation is not KeriKeyEvent keyEvent)
        {
            return Result(currentState, $"The KERI log entry at sequence {entry.Index} carries no key event.");
        }

        try
        {
            return keyEvent switch
            {
                KeriInceptionEvent inception => currentState is EmptyLogState<KeriKeyState>
                    ? Result(new ActiveLogState<KeriKeyState>(KeriKeyStateMachine.Incept(inception)), null)
                    : Result(currentState, $"The KERI inception at sequence {inception.SequenceNumber} is not the genesis event."),
                KeriInteractionEvent interaction => currentState is ActiveLogState<KeriKeyState> active
                    ? Result(new ActiveLogState<KeriKeyState>(KeriKeyStateMachine.Interact(active.Value, interaction)), null)
                    : Result(currentState, $"The KERI interaction at sequence {interaction.SequenceNumber} has no established key state."),
                KeriRotationEvent rotation => currentState is ActiveLogState<KeriKeyState> active
                    ? Result(new ActiveLogState<KeriKeyState>(KeriKeyStateMachine.RollKeys(active.Value, rotation)), null)
                    : Result(currentState, $"The KERI rotation at sequence {rotation.SequenceNumber} has no established key state."),
                _ => Result(currentState, "The KERI event is not a modeled key event.")
            };
        }
        catch(KeriException exception)
        {
            return Result(currentState, exception.Message);
        }
    }


    private static bool NullableSpanEqual(ReadOnlyMemory<byte>? left, ReadOnlyMemory<byte>? right)
    {
        if(left is null && right is null)
        {
            return true;
        }

        if(left is null || right is null)
        {
            return false;
        }

        return left.Value.Span.SequenceEqual(right.Value.Span);
    }


    private static ValueTask<(LogState<KeriKeyState> State, string? Error)> Result(LogState<KeriKeyState> state, string? error)
    {
        return ValueTask.FromResult((state, error));
    }
}
