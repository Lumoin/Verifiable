using System.Collections.Generic;

namespace Verifiable.Keri;

/// <summary>
/// The cooperative-delegation binding between a delegated establishment event and the delegating seal that
/// authorizes it in the delegator's KEL. A delegated inception or rotation is valid only when the delegator's KEL
/// anchors a key event seal of that exact event — the seal commits, by digest, to the delegated event and all its
/// configuration. This holds the pure matching of a delegated event to such a seal; locating the delegator's KEL
/// and replaying it to find the anchoring event is a cross-log step a multi-KEL validator performs.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the KERI specification's <see href="https://trustoverip.github.io/kswg-keri-specification/#cooperative-delegation">
/// cooperative delegation</see>. Delegation is cooperative because it requires two bindings: the delegated AID's
/// inception names its delegator (field <c>di</c>), and the delegator's KEL carries a key event seal
/// (<see cref="KeriKeyEventSeal"/>, fields <c>[i, s, d]</c>) of the delegated establishment event — the delegatee
/// AID, the delegated event's sequence number, and its SAID. Both MUST be present; neither party can establish the
/// delegation alone, which is the security property that makes a delegated AID recoverable by its delegator.
/// </para>
/// </remarks>
public static class KeriDelegation
{
    /// <summary>
    /// Whether a key event seal is the delegating seal for a delegated event: the seal's identifier, sequence
    /// number, and SAID (fields <c>[i, s, d]</c>) MUST equal the delegated event's AID, sequence number, and SAID.
    /// </summary>
    /// <param name="seal">A key event seal taken from the delegator's KEL anchors.</param>
    /// <param name="delegatedEvent">The delegated establishment event the seal is tested against.</param>
    /// <returns><see langword="true"/> when the seal anchors exactly this delegated event.</returns>
    public static bool IsDelegationSealFor(KeriKeyEventSeal seal, KeriKeyEvent delegatedEvent)
    {
        ArgumentNullException.ThrowIfNull(seal);
        ArgumentNullException.ThrowIfNull(delegatedEvent);

        return string.Equals(seal.Prefix, delegatedEvent.Prefix, StringComparison.Ordinal)
            && seal.SequenceNumber == delegatedEvent.SequenceNumber
            && string.Equals(seal.Said, delegatedEvent.Said, StringComparison.Ordinal);
    }


    /// <summary>
    /// Finds the delegating seal for a delegated event among a delegator event's anchored seals: the first key
    /// event seal that anchors exactly this delegated event, or <see langword="null"/> when none does.
    /// </summary>
    /// <param name="delegatorAnchors">The seals anchored in a delegator key event (its <c>a</c> field, read by <see cref="KeriSealReader"/>).</param>
    /// <param name="delegatedEvent">The delegated establishment event to find a delegating seal for.</param>
    /// <returns>The delegating key event seal, or <see langword="null"/> when the anchors carry none for this event.</returns>
    public static KeriKeyEventSeal? FindDelegationSeal(IEnumerable<KeriSeal> delegatorAnchors, KeriKeyEvent delegatedEvent)
    {
        ArgumentNullException.ThrowIfNull(delegatorAnchors);
        ArgumentNullException.ThrowIfNull(delegatedEvent);

        foreach(KeriSeal anchor in delegatorAnchors)
        {
            if(anchor is KeriKeyEventSeal seal && IsDelegationSealFor(seal, delegatedEvent))
            {
                return seal;
            }
        }

        return null;
    }
}
