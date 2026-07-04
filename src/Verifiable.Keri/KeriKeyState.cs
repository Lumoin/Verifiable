using System.Collections.Generic;

namespace Verifiable.Keri;

/// <summary>
/// The key state of an AID at a point in its key event log: the accumulated, verified result of folding the key
/// events seen so far. This is the domain state a key event log replayer carries forward — the current keys and
/// thresholds against which the next event's signatures are checked, the pre-rotation commitments a rotation
/// must reveal, and the sequence position and last event SAID the next event must chain to.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the KERI specification's key event message bodies (the fields are <see cref="KeriMessageFields"/>).
/// The delegator AID and the witness-change bookkeeping of rotation are added in a later slice along with the
/// rotation fold; this carries the fields an inception and an interaction establish and maintain.
/// </para>
/// </remarks>
/// <param name="Prefix">The controller AID (field <c>i</c>).</param>
/// <param name="SigningThreshold">The current keys signing threshold (field <c>kt</c>).</param>
/// <param name="SigningKeys">The ordered current signing keys (field <c>k</c>).</param>
/// <param name="NextThreshold">The next keys signing threshold (field <c>nt</c>).</param>
/// <param name="NextKeyDigests">The ordered digests of the pre-rotated next keys (field <c>n</c>).</param>
/// <param name="BackerThreshold">The backer (witness) threshold (field <c>bt</c>).</param>
/// <param name="Backers">The ordered backer (witness) AIDs (field <c>b</c>).</param>
/// <param name="ConfigurationTraits">The configuration traits / modes (field <c>c</c>).</param>
/// <param name="SequenceNumber">The sequence number of the most recently folded event (field <c>s</c>).</param>
/// <param name="LastEventSaid">The SAID of the most recently folded event, which the next event chains to (field <c>d</c>).</param>
/// <param name="DelegatorPrefix">The delegator's AID (field <c>di</c>) when this is a delegated AID's key state; <see langword="null"/> for a non-delegated AID.</param>
public sealed record KeriKeyState(
    string Prefix,
    KeriThreshold SigningThreshold,
    IReadOnlyList<string> SigningKeys,
    KeriThreshold NextThreshold,
    IReadOnlyList<string> NextKeyDigests,
    string BackerThreshold,
    IReadOnlyList<string> Backers,
    IReadOnlyList<string> ConfigurationTraits,
    long SequenceNumber,
    string LastEventSaid,
    string? DelegatorPrefix = null);
