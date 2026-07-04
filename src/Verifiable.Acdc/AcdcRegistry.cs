using System.Collections.Generic;

namespace Verifiable.Acdc;

/// <summary>
/// Validates the hash-chain integrity of an ACDC transaction-event-log registry: a registry begins with an
/// inception event and continues with update events, each chained to the prior event by its prior SAID and sequence
/// number and bound to the registry by its registry SAID. This checks the structural chain — that the events form a
/// well-formed sequence — independently of verifying each event's SAID over its bytes (with <see cref="AcdcSaid"/>)
/// and confirming each event is anchored in the Issuer's KEL (with <see cref="AcdcKeriBinding"/>), which together
/// give the full registry verification.
/// </summary>
/// <remarks>
/// Anchored on the ACDC specification's <see href="https://trustoverip.github.io/kswg-acdc-specification/#public-non-blindable-state-update-registry-example">
/// registry chaining</see>: the first event is the registry inception with sequence number zero, and each update's
/// prior SAID <c>p</c> equals the immediately prior event's SAID, its sequence number <c>n</c> is one greater than
/// the prior event's, and its registry SAID <c>rd</c> equals the inception's SAID. The transaction state each update
/// carries (for example <c>issued</c> or <c>revoked</c>) is interpreted by the registry's governance, not enforced
/// here, because the state set is registry-specific.
/// </remarks>
public static class AcdcRegistry
{
    /// <summary>
    /// Validates a registry's chain integrity and returns the registry's SAID.
    /// </summary>
    /// <param name="events">The registry events in order: an inception followed by zero or more updates.</param>
    /// <returns>The registry SAID (the inception event's SAID), which every update is bound to.</returns>
    /// <exception cref="AcdcException">The registry is empty, does not begin with an inception at sequence zero, or an update is out of sequence, does not chain to its prior event, or is bound to a different registry.</exception>
    public static string ValidateChain(IReadOnlyList<AcdcRegistryEvent> events)
    {
        ArgumentNullException.ThrowIfNull(events);

        if(events.Count == 0)
        {
            throw new AcdcException("An ACDC registry is empty; it MUST begin with a registry inception event.");
        }

        if(events[0] is not RegistryInceptionEvent inception)
        {
            throw new AcdcException("An ACDC registry MUST begin with a registry inception 'rip' event.");
        }

        if(inception.SequenceNumber != 0)
        {
            throw new AcdcException($"An ACDC registry inception MUST have sequence number 0, not {inception.SequenceNumber}.");
        }

        string registrySaid = inception.Said;
        AcdcRegistryEvent prior = inception;
        for(int index = 1; index < events.Count; index++)
        {
            if(events[index] is not RegistryUpdateEvent update)
            {
                throw new AcdcException($"An ACDC registry event at sequence {index} is not a registry update 'upd' event; only the inception is not an update.");
            }

            if(update.SequenceNumber != index)
            {
                throw new AcdcException($"An ACDC registry update has sequence number {update.SequenceNumber} at position {index}; the sequence number MUST increase by one from the prior event.");
            }

            if(!string.Equals(update.PriorSaid, prior.Said, StringComparison.Ordinal))
            {
                throw new AcdcException($"An ACDC registry update at sequence {index} does not chain to its prior event; its prior SAID does not match the prior event's SAID.");
            }

            if(!string.Equals(update.RegistryDigest, registrySaid, StringComparison.Ordinal))
            {
                throw new AcdcException($"An ACDC registry update at sequence {index} is bound to a different registry; its registry SAID does not match the inception's SAID.");
            }

            prior = update;
        }

        return registrySaid;
    }
}
