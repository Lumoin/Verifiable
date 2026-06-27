namespace Verifiable.Apdu.Automata;

/// <summary>
/// The operational phases of the eMRTD card simulator — the backbone of its pushdown automaton, the
/// APDU-card analogue of the TPM simulator's lifecycle phases.
/// </summary>
/// <remarks>
/// <para>
/// This first slice models a card that serves transparent elementary files in the clear, so it has the
/// single <see cref="Operational"/> phase. Access control is layered on as the inverse responders are
/// added: Basic Access Control and PACE establish a Secure Messaging session, and Chip Authentication
/// re-keys it. Those introduce further phases (and a Secure-Messaging session held as state), at which
/// point command admissibility is gated on the phase the way the TPM simulator gates on its lifecycle.
/// </para>
/// </remarks>
public enum CardLifecyclePhase
{
    /// <summary>
    /// The card is powered and serving commands, with no access protocol in progress. Every file is
    /// readable without access control in this slice; gating protected files behind Secure Messaging
    /// arrives with the SM-wrapped read responder.
    /// </summary>
    Operational,

    /// <summary>
    /// The card has issued a challenge (RND.IC via GET CHALLENGE) and is awaiting the terminal's EXTERNAL
    /// AUTHENTICATE — the middle of the Basic Access Control mutual authentication.
    /// </summary>
    ChallengeIssued,

    /// <summary>
    /// The terminal has selected the PACE mechanism (MSE:Set AT) and the chained GENERAL AUTHENTICATE rounds
    /// are in progress (encrypted nonce, mapping, key agreement, token).
    /// </summary>
    Pace,

    /// <summary>
    /// An access protocol (Basic Access Control) has established a Secure Messaging session; the card holds
    /// the session keys and send-sequence counter.
    /// </summary>
    SecureMessaging
}
