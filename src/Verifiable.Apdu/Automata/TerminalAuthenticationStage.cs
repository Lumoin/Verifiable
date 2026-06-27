namespace Verifiable.Apdu.Automata;

/// <summary>
/// The progress of a Terminal Authentication exchange within the card simulator's Secure Messaging phase.
/// Terminal Authentication runs over the established session, so it does not replace the
/// <see cref="CardLifecyclePhase.SecureMessaging"/> phase (which keeps routing commands through the session);
/// this sub-stage gates the steps that follow the certificate-chain presentation — MSE:Set AT, GET CHALLENGE,
/// and EXTERNAL AUTHENTICATE — so the chip's GET CHALLENGE and EXTERNAL AUTHENTICATE serve Terminal
/// Authentication rather than Basic Access Control.
/// </summary>
public enum TerminalAuthenticationStage
{
    /// <summary>No Terminal Authentication EXTERNAL AUTHENTICATE is pending (the certificate chain may still be in presentation).</summary>
    None,

    /// <summary>MSE:Set AT selected the imported terminal certificate's key; the chip awaits GET CHALLENGE.</summary>
    TerminalKeySelected,

    /// <summary>The chip issued the Terminal Authentication challenge and awaits the terminal's EXTERNAL AUTHENTICATE signature.</summary>
    ChallengeIssued
}
