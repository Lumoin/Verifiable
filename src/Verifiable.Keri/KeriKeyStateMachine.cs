using System.Buffers;
using System.Collections.Generic;
using System.Text;
using Verifiable.Cesr;
using Verifiable.Cryptography;

namespace Verifiable.Keri;

/// <summary>
/// Folds KERI key events into key state: establishes the initial <see cref="KeriKeyState"/> from an inception
/// event, and advances it through interaction events. These are the pure state transitions a key event log
/// replayer's apply step invokes once an event's signatures and hash chaining have been verified.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the KERI specification's key event processing. The fold enforces the ordering invariants that are
/// the apply step's responsibility — an inception is the first event (sequence number zero), and each subsequent
/// event advances the sequence by exactly one for the same identifier. Verifying an event's signatures against
/// the current keys and verifying the prior-SAID hash chain are separate steps a replayer performs before the
/// fold (the chain-integrity step compares an event's prior SAID against <see cref="KeriKeyState.LastEventSaid"/>).
/// Rotation additionally verifies pre-rotation — the revealed keys against the prior establishment event's next-key
/// commitments — under KERI general pre-rotation, which admits partial, reserve, and augmented rotation.
/// </para>
/// </remarks>
public static class KeriKeyStateMachine
{
    /// <summary>
    /// Establishes the initial key state from an inception event.
    /// </summary>
    /// <param name="inception">The inception event.</param>
    /// <returns>The key state the inception establishes.</returns>
    /// <exception cref="KeriException">The inception is not the first event, or carries no signing keys.</exception>
    public static KeriKeyState Incept(KeriInceptionEvent inception)
    {
        ArgumentNullException.ThrowIfNull(inception);

        if(inception.SequenceNumber != 0)
        {
            throw new KeriException($"An inception event must have sequence number 0, not {inception.SequenceNumber}.");
        }

        if(inception.SigningKeys.Count == 0)
        {
            throw new KeriException("An inception event must establish at least one signing key.");
        }

        //A self-addressing identifier is bound to its inception: the identifier (i) equals the SAID (d) of the
        //inception event, both co-derived with each occurrence dummied before digesting (KERI specification,
        //Self-Addressing IDentifier derivation). Every inception this library admits carries pre-rotation
        //commitments, so its AID is self-addressing and this binding MUST hold. It is enforced explicitly because
        //the SAID recomputation resets only occurrences of the SAID's own value in the serialization: were the
        //identifier left free, an inception could claim any i (a victim's AID) while its d still verified over a
        //body carrying that i and attacker-chosen keys — a KEL forgery / AID substitution that self-certification
        //exists to prevent.
        if(!string.Equals(inception.Prefix, inception.Said, StringComparison.Ordinal))
        {
            throw new KeriException($"A self-addressing inception's identifier (i) '{inception.Prefix}' must equal its SAID (d) '{inception.Said}'; an inception whose identifier is not its own self-addressing digest is not self-certifying.");
        }

        //A delegated inception additionally binds the delegated AID to its delegator; a plain inception has none.
        string? delegatorPrefix = inception is KeriDelegatedInceptionEvent delegated ? delegated.DelegatorPrefix : null;

        return new KeriKeyState(
            inception.Prefix,
            inception.SigningThreshold,
            inception.SigningKeys,
            inception.NextThreshold,
            inception.NextKeyDigests,
            inception.BackerThreshold,
            inception.Backers,
            inception.ConfigurationTraits,
            inception.SequenceNumber,
            inception.Said,
            delegatorPrefix);
    }


    /// <summary>
    /// Advances the key state through an interaction event. The keys, thresholds, and backers are unchanged — an
    /// interaction only advances the sequence and records the new last event SAID.
    /// </summary>
    /// <param name="state">The current key state.</param>
    /// <param name="interaction">The interaction event to fold.</param>
    /// <returns>The advanced key state.</returns>
    /// <exception cref="KeriException">The event is for a different identifier or does not advance the sequence by one.</exception>
    public static KeriKeyState Interact(KeriKeyState state, KeriInteractionEvent interaction)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(interaction);

        if(!string.Equals(interaction.Prefix, state.Prefix, StringComparison.Ordinal))
        {
            throw new KeriException($"Interaction event identifier '{interaction.Prefix}' does not match the key state identifier '{state.Prefix}'.");
        }

        if(interaction.SequenceNumber != state.SequenceNumber + 1)
        {
            throw new KeriException($"Interaction event sequence number {interaction.SequenceNumber} does not advance the key state sequence number {state.SequenceNumber} by one.");
        }

        return state with
        {
            SequenceNumber = interaction.SequenceNumber,
            LastEventSaid = interaction.Said
        };
    }


    /// <summary>
    /// Rotates the key state with a rotation event, verifying pre-rotation: the revealed current keys that unblind
    /// prior next-key commitments must form a subset capable of satisfying the prior establishment event's next
    /// (rotation) threshold, supporting partial, reserve, and augmented rotation. On success the keys, thresholds,
    /// next-key commitments, and backers are rolled forward and the sequence advances. This is the combined fold
    /// for standalone use; a key event log replayer instead verifies pre-rotation in its proof-validation step
    /// (<see cref="VerifyPreRotationAsync"/>, which has the digest seam and the prior state) and rolls the keys in its
    /// apply step (<see cref="RollKeys"/>, which needs no seam), mirroring the engine's verify-then-apply split.
    /// </summary>
    /// <param name="state">The current key state.</param>
    /// <param name="rotation">The rotation event to fold.</param>
    /// <param name="computeDigest">The digest implementation (caller-supplied or the registered default) used to verify the pre-rotation commitments.</param>
    /// <param name="pool">The pool the digest buffers are rented from.</param>
    /// <param name="cancellationToken">Cancels an in-flight digest on a hardware-async backend (TPM2_Hash, KMS).</param>
    /// <returns>The rotated key state.</returns>
    /// <exception cref="KeriException">
    /// The event is for a different identifier, does not advance the sequence by one, reveals no keys, or reveals a
    /// subset of the prior next keys too small to satisfy the prior next (rotation) threshold.
    /// </exception>
    public static async ValueTask<KeriKeyState> RotateAsync(KeriKeyState state, KeriRotationEvent rotation, ComputeDigestDelegate computeDigest, MemoryPool<byte> pool, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(rotation);
        ArgumentNullException.ThrowIfNull(computeDigest);
        ArgumentNullException.ThrowIfNull(pool);

        EnsureRotatable(state, rotation);
        _ = await VerifyPreRotationAsync(state, rotation, computeDigest, pool, cancellationToken).ConfigureAwait(false);

        return RollKeysCore(state, rotation);
    }


    /// <summary>
    /// Rolls the key state forward with a rotation event WITHOUT verifying pre-rotation: the keys, thresholds,
    /// next-key commitments, and backers are replaced and the sequence advances. This is the apply step a key
    /// event log replayer runs once the rotation's signatures and pre-rotation commitments have already been
    /// verified in its proof-validation step; it needs no digest seam. Callers that have not separately verified
    /// pre-rotation MUST use <see cref="Rotate"/> instead.
    /// </summary>
    /// <param name="state">The current key state.</param>
    /// <param name="rotation">The rotation event to roll forward.</param>
    /// <returns>The rotated key state.</returns>
    /// <exception cref="KeriException">The event is for a different identifier, does not advance the sequence by one, or reveals no keys.</exception>
    public static KeriKeyState RollKeys(KeriKeyState state, KeriRotationEvent rotation)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(rotation);

        EnsureRotatable(state, rotation);

        return RollKeysCore(state, rotation);
    }


    /// <summary>
    /// Verifies a rotation's pre-rotation against the prior key state under KERI general pre-rotation (partial,
    /// reserve, and augmented rotation): each revealed current key whose qualified digest (under the algorithm
    /// named by a committed digest's own derivation code) unblinds one of the prior next-key commitments is an
    /// exposed pre-rotated key, matched by digest identity rather than by position; a revealed key that matches no
    /// commitment is an augmented (newly added) key with no rotation authority, which a partial+augmented rotation
    /// permits. The exposed subset of the prior next keys MUST be capable of satisfying the prior next (rotation)
    /// threshold — this is the rotation-control-authority gate. Returns the prior next key list with each exposed
    /// key placed at its committed position and a <see langword="null"/> at each position held in reserve, so a key
    /// event log replayer can additionally require that signatures from the exposed keys satisfy that same prior
    /// next threshold. This is the cryptographic half of the rotation fold, the step a replayer runs in proof
    /// validation (where it has the digest seam and the prior state).
    /// </summary>
    /// <param name="state">The current key state, carrying the next-key commitments to verify against.</param>
    /// <param name="rotation">The rotation event whose revealed keys are verified.</param>
    /// <param name="computeDigest">The digest implementation (caller-supplied or the registered default).</param>
    /// <param name="pool">The pool the digest buffers are rented from.</param>
    /// <param name="cancellationToken">Cancels an in-flight digest on a hardware-async backend (TPM2_Hash, KMS).</param>
    /// <returns>
    /// The prior next key list, indexed by committed position: the revealed (unblinded) key at each exposed
    /// position, or <see langword="null"/> at each position whose committed key was held in reserve.
    /// </returns>
    /// <exception cref="KeriException">
    /// The rotation's exposed pre-rotated keys do not satisfy the prior next (rotation) threshold.
    /// </exception>
    public static async ValueTask<IReadOnlyList<string?>> VerifyPreRotationAsync(KeriKeyState state, KeriRotationEvent rotation, ComputeDigestDelegate computeDigest, MemoryPool<byte> pool, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(rotation);
        ArgumentNullException.ThrowIfNull(computeDigest);
        ArgumentNullException.ThrowIfNull(pool);

        int committedCount = state.NextKeyDigests.Count;

        //Each committed next-key digest maps to its position in the prior next key list.
        var positionOf = new Dictionary<string, int>(StringComparer.Ordinal);
        for(int i = 0; i < committedCount; i++)
        {
            _ = positionOf.TryAdd(state.NextKeyDigests[i], i);
        }

        //A next-key digest names its own derivation algorithm, so a revealed key is digested under each distinct
        //committed code to test whether it unblinds a commitment (normally one code is shared by all commitments).
        var codes = new HashSet<string>(StringComparer.Ordinal);
        foreach(string commitment in state.NextKeyDigests)
        {
            _ = codes.Add(CesrSaid.DigestCodeOf(commitment));
        }

        //Place each revealed key that unblinds a commitment at its committed position; reserve positions stay null.
        var exposed = new string?[committedCount];
        var exposedPositions = new HashSet<int>();
        foreach(string revealedKey in rotation.SigningKeys)
        {
            ReadOnlyMemory<byte> qualifiedKey = Encoding.UTF8.GetBytes(revealedKey);
            foreach(string code in codes)
            {
                string computed = await CesrSaid.ComputeAsync(qualifiedKey, code, computeDigest, pool, cancellationToken).ConfigureAwait(false);
                if(positionOf.TryGetValue(computed, out int position) && exposed[position] is null)
                {
                    exposed[position] = revealedKey;
                    _ = exposedPositions.Add(position);
                    break;
                }
            }
        }

        //Rotation control authority: the exposed (unblinded) subset of the prior next keys must be capable of
        //satisfying the prior next threshold over its key positions. A standalone fold has no signatures, so the
        //structural subset is the gate here; a replayer additionally requires signatures from these exposed keys to
        //satisfy this same threshold (KERI specification, General Pre-rotation).
        if(!state.NextThreshold.IsSatisfiedBy(exposedPositions, committedCount))
        {
            throw new KeriException($"Pre-rotation violation: the rotation's exposed pre-rotated keys do not satisfy the prior next (rotation) threshold over the {committedCount} committed next keys.");
        }

        return exposed;
    }


    /// <summary>
    /// Enforces the structural rotation invariants that need no digest seam: the event is for the same identifier,
    /// advances the sequence by exactly one, and reveals at least one key.
    /// </summary>
    private static void EnsureRotatable(KeriKeyState state, KeriRotationEvent rotation)
    {
        if(!string.Equals(rotation.Prefix, state.Prefix, StringComparison.Ordinal))
        {
            throw new KeriException($"Rotation event identifier '{rotation.Prefix}' does not match the key state identifier '{state.Prefix}'.");
        }

        if(rotation.SequenceNumber != state.SequenceNumber + 1)
        {
            throw new KeriException($"Rotation event sequence number {rotation.SequenceNumber} does not advance the key state sequence number {state.SequenceNumber} by one.");
        }

        if(rotation.SigningKeys.Count == 0)
        {
            throw new KeriException("A rotation event must reveal at least one signing key.");
        }
    }


    /// <summary>
    /// Constructs the rolled-forward key state from a rotation event, assuming the structural and pre-rotation
    /// invariants have already been enforced.
    /// </summary>
    private static KeriKeyState RollKeysCore(KeriKeyState state, KeriRotationEvent rotation)
    {
        return new KeriKeyState(
            state.Prefix,
            rotation.SigningThreshold,
            rotation.SigningKeys,
            rotation.NextThreshold,
            rotation.NextKeyDigests,
            rotation.BackerThreshold,
            ApplyBackerChanges(state.Backers, rotation.BackersToRemove, rotation.BackersToAdd),
            rotation.ConfigurationTraits,
            rotation.SequenceNumber,
            rotation.Said,
            state.DelegatorPrefix);
    }


    /// <summary>
    /// Applies a rotation's backer changes: removes the backers in the remove list, then appends the backers in
    /// the add list, preserving order.
    /// </summary>
    private static List<string> ApplyBackerChanges(IReadOnlyList<string> current, IReadOnlyList<string> remove, IReadOnlyList<string> add)
    {
        var removals = new HashSet<string>(remove, StringComparer.Ordinal);
        var result = new List<string>(current.Count + add.Count);
        foreach(string backer in current)
        {
            if(!removals.Contains(backer))
            {
                result.Add(backer);
            }
        }

        result.AddRange(add);

        return result;
    }
}
