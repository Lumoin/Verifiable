namespace Verifiable.Keri;

/// <summary>
/// A KERI anchored seal paired with the AID a key event log replay independently established for the verified
/// event that carried it.
/// </summary>
/// <remarks>
/// <para>
/// The AID is never a caller's claim. A self-addressing inception's identifier MUST equal its own SAID
/// (<see cref="KeriKeyStateMachine.Incept"/>), and every later event's identifier is checked against the running
/// key state (<see cref="KeriKeyStateMachine.Interact"/>, <see cref="KeriKeyStateMachine.RollKeys"/>) before a key
/// event log replayer applies it — a mismatch fails the replay rather than being silently accepted. <see cref="Aid"/>
/// is read off the verified event itself only after that replay has succeeded.
/// </para>
/// <para>
/// The constructor is <see langword="private"/>; the sole producer is <see cref="KeriIssuerAnchors.ReplayAsync"/>,
/// which builds one only after the event that carried <see cref="Seal"/> has actually verified. No caller —
/// outside this assembly, or within it — can construct a <see cref="KeriAnchoredSeal"/> asserting an AID for a
/// seal it did not independently replay: this is the same asserted-vs-bound structural distinction
/// <c>Verifiable.Cryptography.BoundProvenance</c> and <c>Verifiable.Cryptography.Verified{T}</c> make one level
/// up, applied here to the KERI anchor itself.
/// </para>
/// </remarks>
public sealed record KeriAnchoredSeal
{
    /// <summary>The AID the replay independently established for the verified event that carried <see cref="Seal"/>.</summary>
    public string Aid { get; }

    /// <summary>The anchored seal.</summary>
    public KeriSeal Seal { get; }


    private KeriAnchoredSeal(string aid, KeriSeal seal)
    {
        Aid = aid;
        Seal = seal;
    }


    /// <summary>
    /// Produces a <see cref="KeriAnchoredSeal"/>. Intentionally <see langword="internal"/>, and called only from
    /// <see cref="KeriIssuerAnchors.ReplayAsync"/> immediately after the event that carried <paramref name="seal"/>
    /// has verified under the shipped key event log replayer.
    /// </summary>
    /// <param name="aid">The AID of the verified event that carried <paramref name="seal"/>.</param>
    /// <param name="seal">The anchored seal.</param>
    /// <returns>The anchored seal, paired with its verified AID.</returns>
    internal static KeriAnchoredSeal Create(string aid, KeriSeal seal) => new(aid, seal);
}
