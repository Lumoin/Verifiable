using System.Collections.Generic;

namespace Verifiable.Keri;

/// <summary>
/// A KERI key event message body: the common identity of every event in an AID's key event log. Concrete events
/// (inception, interaction, rotation, and the delegated inception and rotation) add their own fields.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the KERI specification's <see href="https://trustoverip.github.io/kswg-keri-specification/#message-type-field">
/// key event message bodies</see>. These records carry the post-verification key-state-bearing fields of an
/// event; the field labels are <see cref="KeriMessageFields"/>. The version string and the anchored seal field
/// maps (the data plane, which does not bear on key state) are deliberately not modeled here. Deserializing a
/// wire field map into these records is a serializer-seam concern handled outside this layer.
/// </para>
/// </remarks>
/// <param name="Said">The event's self-addressing digest (field <c>d</c>).</param>
/// <param name="Prefix">The controller identifier the event belongs to (field <c>i</c>).</param>
/// <param name="SequenceNumber">The event's sequence number in the log (field <c>s</c>, decoded from hexadecimal).</param>
public abstract record KeriKeyEvent(string Said, string Prefix, long SequenceNumber);

/// <summary>
/// An inception (<c>icp</c>) event: the genesis event that incepts an AID and establishes its initial key state.
/// </summary>
/// <remarks>
/// Field order on the wire is <c>[v, t, d, i, s, kt, k, nt, n, bt, b, c, a]</c> (KERI specification, Inception
/// Event Message Body). An inception has no prior event, so it carries no prior SAID; for a self-addressing AID
/// the <see cref="KeriKeyEvent.Prefix"/> equals the <see cref="KeriKeyEvent.Said"/>.
/// </remarks>
/// <param name="Said">The event SAID (field <c>d</c>).</param>
/// <param name="Prefix">The incepted AID (field <c>i</c>).</param>
/// <param name="SequenceNumber">The sequence number (field <c>s</c>); MUST be zero for an inception.</param>
/// <param name="SigningThreshold">The current keys signing threshold (field <c>kt</c>).</param>
/// <param name="SigningKeys">The ordered current signing keys (field <c>k</c>).</param>
/// <param name="NextThreshold">The next keys signing threshold (field <c>nt</c>).</param>
/// <param name="NextKeyDigests">The ordered digests of the pre-rotated next keys (field <c>n</c>).</param>
/// <param name="BackerThreshold">The backer (witness) threshold (field <c>bt</c>).</param>
/// <param name="Backers">The ordered backer (witness) AIDs (field <c>b</c>).</param>
/// <param name="ConfigurationTraits">The configuration traits / modes (field <c>c</c>).</param>
public record KeriInceptionEvent(
    string Said,
    string Prefix,
    long SequenceNumber,
    KeriThreshold SigningThreshold,
    IReadOnlyList<string> SigningKeys,
    KeriThreshold NextThreshold,
    IReadOnlyList<string> NextKeyDigests,
    string BackerThreshold,
    IReadOnlyList<string> Backers,
    IReadOnlyList<string> ConfigurationTraits): KeriKeyEvent(Said, Prefix, SequenceNumber);

/// <summary>
/// An interaction (<c>ixn</c>) event: a non-establishment event that seals data to the current key state without
/// changing the keys.
/// </summary>
/// <remarks>
/// Field order on the wire is <c>[v, t, d, i, s, p, a]</c> (KERI specification, Interaction Event Message Body).
/// The prior SAID (field <c>p</c>) is carried for the hash-chain check, which a key event log replayer performs
/// in its chain-integrity step rather than in the key-state fold.
/// </remarks>
/// <param name="Said">The event SAID (field <c>d</c>).</param>
/// <param name="Prefix">The AID the event belongs to (field <c>i</c>).</param>
/// <param name="SequenceNumber">The sequence number (field <c>s</c>).</param>
/// <param name="PriorSaid">The SAID of the prior event in the log (field <c>p</c>).</param>
public sealed record KeriInteractionEvent(
    string Said,
    string Prefix,
    long SequenceNumber,
    string PriorSaid): KeriKeyEvent(Said, Prefix, SequenceNumber);

/// <summary>
/// A rotation (<c>rot</c>) event: an establishment event that revokes the current signing keys and replaces them
/// with the pre-rotated next keys, committing to a fresh next set.
/// </summary>
/// <remarks>
/// Field order on the wire is <c>[v, t, d, i, s, p, kt, k, nt, n, bt, br, ba, c, a]</c> (KERI specification,
/// Rotation Event Message Body). The newly current keys (<c>k</c>) are the unblinded prior next keys: each MUST
/// match a digest the prior establishment event committed in its next-key digest list, which the rotation fold
/// verifies. The backer changes are expressed as a remove list (<c>br</c>) and an add list (<c>ba</c>) rather
/// than a full replacement.
/// </remarks>
/// <param name="Said">The event SAID (field <c>d</c>).</param>
/// <param name="Prefix">The AID the event belongs to (field <c>i</c>).</param>
/// <param name="SequenceNumber">The sequence number (field <c>s</c>).</param>
/// <param name="PriorSaid">The SAID of the prior event in the log (field <c>p</c>).</param>
/// <param name="SigningThreshold">The new current keys signing threshold (field <c>kt</c>).</param>
/// <param name="SigningKeys">The new current signing keys, unblinded from the prior next set (field <c>k</c>).</param>
/// <param name="NextThreshold">The new next keys signing threshold (field <c>nt</c>).</param>
/// <param name="NextKeyDigests">The digests of the freshly pre-rotated next keys (field <c>n</c>).</param>
/// <param name="BackerThreshold">The new backer (witness) threshold (field <c>bt</c>).</param>
/// <param name="BackersToRemove">The backer AIDs to remove (field <c>br</c>).</param>
/// <param name="BackersToAdd">The backer AIDs to add (field <c>ba</c>).</param>
/// <param name="ConfigurationTraits">The configuration traits / modes (field <c>c</c>).</param>
public record KeriRotationEvent(
    string Said,
    string Prefix,
    long SequenceNumber,
    string PriorSaid,
    KeriThreshold SigningThreshold,
    IReadOnlyList<string> SigningKeys,
    KeriThreshold NextThreshold,
    IReadOnlyList<string> NextKeyDigests,
    string BackerThreshold,
    IReadOnlyList<string> BackersToRemove,
    IReadOnlyList<string> BackersToAdd,
    IReadOnlyList<string> ConfigurationTraits): KeriKeyEvent(Said, Prefix, SequenceNumber);

/// <summary>
/// A delegated inception (<c>dip</c>) event: the genesis event of a delegated AID. It establishes the delegated
/// AID's initial key state exactly as an inception does, and additionally names its delegator (field <c>di</c>),
/// binding the delegated AID to a unique delegator. As an establishment event of a delegated AID, it is valid only
/// when a delegating seal of this event is anchored in the delegator's KEL — a cooperative delegation requiring
/// both parties.
/// </summary>
/// <remarks>
/// Field order on the wire is <c>[v, t, d, i, s, kt, k, nt, n, bt, b, c, a, di]</c> (KERI specification, Delegated
/// Inception Event Message Body) — the inception fields followed by the delegator AID. The delegated AID
/// (<see cref="KeriKeyEvent.Prefix"/>) is the self-addressing digest of this event, which includes the delegator
/// reference, so the AID is cryptographically bound to its delegator.
/// </remarks>
/// <param name="Said">The event SAID (field <c>d</c>).</param>
/// <param name="Prefix">The incepted delegated AID (field <c>i</c>).</param>
/// <param name="SequenceNumber">The sequence number (field <c>s</c>); MUST be zero for a delegated inception.</param>
/// <param name="SigningThreshold">The current keys signing threshold (field <c>kt</c>).</param>
/// <param name="SigningKeys">The ordered current signing keys (field <c>k</c>).</param>
/// <param name="NextThreshold">The next keys signing threshold (field <c>nt</c>).</param>
/// <param name="NextKeyDigests">The ordered digests of the pre-rotated next keys (field <c>n</c>).</param>
/// <param name="BackerThreshold">The backer (witness) threshold (field <c>bt</c>).</param>
/// <param name="Backers">The ordered backer (witness) AIDs (field <c>b</c>).</param>
/// <param name="ConfigurationTraits">The configuration traits / modes (field <c>c</c>).</param>
/// <param name="DelegatorPrefix">The delegator's AID (field <c>di</c>).</param>
public sealed record KeriDelegatedInceptionEvent(
    string Said,
    string Prefix,
    long SequenceNumber,
    KeriThreshold SigningThreshold,
    IReadOnlyList<string> SigningKeys,
    KeriThreshold NextThreshold,
    IReadOnlyList<string> NextKeyDigests,
    string BackerThreshold,
    IReadOnlyList<string> Backers,
    IReadOnlyList<string> ConfigurationTraits,
    string DelegatorPrefix): KeriInceptionEvent(
        Said, Prefix, SequenceNumber, SigningThreshold, SigningKeys, NextThreshold, NextKeyDigests, BackerThreshold, Backers, ConfigurationTraits);

/// <summary>
/// A delegated rotation (<c>drt</c>) event: rotates a delegated AID's key state. Its field set is identical to a
/// non-delegated rotation — the delegator AID is not repeated, because it is supplied by the delegated inception —
/// but the <c>drt</c> message type signals to a validator that the event must be validated under the rules for
/// delegated events, which additionally require a delegating seal of this event in the delegator's KEL.
/// </summary>
/// <remarks>
/// Field order on the wire is <c>[v, t, d, i, s, p, kt, k, nt, n, bt, br, ba, c, a]</c> (KERI specification,
/// Delegated Rotation Event Message Body), the same as a rotation; only the message type distinguishes it.
/// </remarks>
/// <param name="Said">The event SAID (field <c>d</c>).</param>
/// <param name="Prefix">The delegated AID the event belongs to (field <c>i</c>).</param>
/// <param name="SequenceNumber">The sequence number (field <c>s</c>).</param>
/// <param name="PriorSaid">The SAID of the prior event in the log (field <c>p</c>).</param>
/// <param name="SigningThreshold">The new current keys signing threshold (field <c>kt</c>).</param>
/// <param name="SigningKeys">The new current signing keys, unblinded from the prior next set (field <c>k</c>).</param>
/// <param name="NextThreshold">The new next keys signing threshold (field <c>nt</c>).</param>
/// <param name="NextKeyDigests">The digests of the freshly pre-rotated next keys (field <c>n</c>).</param>
/// <param name="BackerThreshold">The new backer (witness) threshold (field <c>bt</c>).</param>
/// <param name="BackersToRemove">The backer AIDs to remove (field <c>br</c>).</param>
/// <param name="BackersToAdd">The backer AIDs to add (field <c>ba</c>).</param>
/// <param name="ConfigurationTraits">The configuration traits / modes (field <c>c</c>).</param>
public sealed record KeriDelegatedRotationEvent(
    string Said,
    string Prefix,
    long SequenceNumber,
    string PriorSaid,
    KeriThreshold SigningThreshold,
    IReadOnlyList<string> SigningKeys,
    KeriThreshold NextThreshold,
    IReadOnlyList<string> NextKeyDigests,
    string BackerThreshold,
    IReadOnlyList<string> BackersToRemove,
    IReadOnlyList<string> BackersToAdd,
    IReadOnlyList<string> ConfigurationTraits): KeriRotationEvent(
        Said, Prefix, SequenceNumber, PriorSaid, SigningThreshold, SigningKeys, NextThreshold, NextKeyDigests, BackerThreshold, BackersToRemove, BackersToAdd, ConfigurationTraits);
