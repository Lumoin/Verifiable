using Verifiable.Foundation.Automata;

namespace Verifiable.Apdu.Automata;

/// <summary>
/// Base type for the effectful actions a card command transition can declare. A <see cref="CardAction"/>
/// is produced by the pure transition function as part of the next state (carried in
/// <see cref="CardSimulatorState.NextAction"/>); the effectful loop in <see cref="CardSimulator"/>
/// dispatches it to a backend and feeds the result back as the next input.
/// </summary>
/// <remarks>
/// The plaintext read commands (SELECT, READ BINARY) declare no effects and leave
/// <see cref="NullAction.Instance"/> in place. The first command that needs an effect is GET CHALLENGE,
/// whose <see cref="CardRngAction"/> draws the card nonce (RND.IC) from the injected RNG backend — the
/// same pattern as the TPM simulator's <c>TpmRngAction</c>.
/// </remarks>
public abstract record CardAction: PdaAction;

/// <summary>
/// Declares that the simulator must draw <paramref name="ByteCount"/> random octets from its RNG backend
/// before the next transition. Emitted by the GET CHALLENGE transition; the effectful loop fills a pooled
/// buffer via the injected backend and feeds the octets back as a <see cref="CardEntropyGenerated"/> input.
/// </summary>
/// <param name="ByteCount">The number of octets to produce (the challenge length the terminal requested).</param>
public sealed record CardRngAction(int ByteCount): CardAction;

/// <summary>
/// Declares that the simulator must run the Basic Access Control mutual authentication: verify the
/// terminal's EXTERNAL AUTHENTICATE token against the card's MRZ-derived keys and the issued RND.IC, then
/// produce the card's response token and establish the Secure Messaging session. Emitted by the EXTERNAL
/// AUTHENTICATE transition; the effectful loop runs the inverse BAC crypto and feeds the outcome back as a
/// <see cref="BacAuthenticationCompleted"/> or <see cref="BacAuthenticationFailed"/> input.
/// </summary>
/// <param name="TerminalToken">The terminal's authentication token <c>EIFD || MIFD</c> (a view into the command APDU).</param>
public sealed record BacAuthenticateAction(System.ReadOnlyMemory<byte> TerminalToken): CardAction;

/// <summary>
/// Declares that the simulator must capture the PACE mechanism selected by MSE:Set AT — the protocol OID,
/// retained for the round-4 authentication tokens. Emitted by the MSE:Set AT transition; the effectful loop
/// stores the OID as device state and feeds a <see cref="PaceMechanismSelected"/> input back.
/// </summary>
/// <param name="ObjectIdentifier">The PACE protocol OID value bytes from DO'80' (a view into the command APDU).</param>
public sealed record PaceSelectMechanismAction(System.ReadOnlyMemory<byte> ObjectIdentifier): CardAction;

/// <summary>
/// Declares that the simulator must run the PACE encrypted-nonce round: derive the password key from the
/// card's MRZ, draw the nonce, and encrypt it. Emitted by the first GENERAL AUTHENTICATE; the effectful loop
/// runs the crypto and feeds the encrypted nonce back as a <see cref="PaceRoundCompleted"/> input.
/// </summary>
public sealed record PaceEncryptNonceAction: CardAction;

/// <summary>
/// Declares that the simulator must run the PACE nonce-mapping round, mapping the nonce to the ephemeral
/// generator by the mechanism the selected OID names. Emitted by the GENERAL AUTHENTICATE carrying DO'81';
/// the effectful loop runs the crypto and feeds the mapping response back as a <see cref="PaceRoundCompleted"/>
/// input. For Generic Mapping the chip generates a mapping key pair and answers with its mapping public key;
/// for Integrated Mapping the chip maps the nonce directly and answers with an empty DO'82'.
/// </summary>
/// <param name="TerminalMappingData">
/// The terminal's DO'81' mapping data (a view into the command APDU): the mapping public key for Generic
/// Mapping, or the additional nonce <c>t</c> for Integrated Mapping.
/// </param>
public sealed record PaceMapAction(System.ReadOnlyMemory<byte> TerminalMappingData): CardAction;

/// <summary>
/// Declares that the simulator must run the PACE key-agreement round: generate the chip's ephemeral key pair
/// over the mapped generator, agree the shared secret, derive the session keys, and answer with the chip's
/// ephemeral public key. Emitted by the GENERAL AUTHENTICATE carrying DO'83'; the effectful loop runs the
/// crypto and feeds the agreement response back as a <see cref="PaceRoundCompleted"/> input.
/// </summary>
/// <param name="TerminalEphemeralPublicKey">The terminal's ephemeral public key (a view into the command APDU).</param>
public sealed record PaceAgreeAction(System.ReadOnlyMemory<byte> TerminalEphemeralPublicKey): CardAction;

/// <summary>
/// Declares that the simulator must run the PACE mutual-authentication round: verify the terminal's token,
/// answer with the chip's token, and establish the AES Secure Messaging session. Emitted by the GENERAL
/// AUTHENTICATE carrying DO'85'; the effectful loop runs the crypto and feeds the outcome back as a
/// <see cref="PaceRoundCompleted"/> (establishing Secure Messaging) or <see cref="PaceExchangeFailed"/> input.
/// </summary>
/// <param name="TerminalToken">The terminal's authentication token T_IFD (a view into the command APDU).</param>
public sealed record PaceAuthenticateAction(System.ReadOnlyMemory<byte> TerminalToken): CardAction;

/// <summary>
/// Declares that the simulator must run EACv1 Chip Authentication: agree the static–ephemeral ECDH secret
/// between the card's static DG14 key and the terminal's ephemeral key, derive the new Secure Messaging
/// keys, and build the re-keyed session (held pending until the response is framed under the old session).
/// Emitted by MSE:Set KAT; the effectful loop runs the crypto and feeds the outcome back as a
/// <see cref="ChipAuthenticationCompleted"/> or <see cref="ChipAuthenticationFailed"/> input.
/// </summary>
/// <param name="TerminalEphemeralPublicKey">The terminal's ephemeral public key from DO'91' (a view into the recovered command).</param>
/// <param name="KeyId">The chip key identifier from DO'84', or <see langword="null"/> when MSE:Set KAT carried none.</param>
public sealed record ChipAuthenticateAction(System.ReadOnlyMemory<byte> TerminalEphemeralPublicKey, int? KeyId): CardAction;

/// <summary>
/// Declares that the simulator must run Active Authentication: sign the terminal's challenge with the
/// chip's EF.DG15 private key. Emitted by INTERNAL AUTHENTICATE; the effectful loop reads the curve from
/// the card's own EF.DG15, resolves the registered ECDSA signing function, and feeds the outcome back as
/// an <see cref="ActiveAuthenticationSigned"/> or <see cref="ActiveAuthenticationFailed"/> input.
/// </summary>
/// <param name="Challenge">The terminal's challenge RND.IFD to sign (a view into the command APDU).</param>
public sealed record ActiveAuthenticateAction(System.ReadOnlyMemory<byte> Challenge): CardAction;

/// <summary>
/// Declares that the simulator must record the Terminal Authentication MSE:Set DST public-key reference —
/// validating that a certificate with that holder reference is available (the trusted CVCA or a previously
/// imported certificate) and selecting it as the verifier for the next PSO:Verify Certificate. Emitted by
/// MSE:Set DST; the effectful loop validates and stores the reference and feeds a
/// <see cref="TerminalAuthenticationStepCompleted"/> input back.
/// </summary>
/// <param name="PublicKeyReference">The certificate holder reference of the verifying key from DO'83' (a view into the recovered command).</param>
public sealed record SetDigitalSignatureTemplateAction(System.ReadOnlyMemory<byte> PublicKeyReference): CardAction;

/// <summary>
/// Declares that the simulator must verify a presented card-verifiable certificate against the public key the
/// preceding MSE:Set DST selected, and import it on success. Emitted by PSO:Verify Certificate; the effectful
/// loop parses the certificate, runs one chain-verification step, and feeds a
/// <see cref="TerminalAuthenticationStepCompleted"/> input back.
/// </summary>
/// <param name="CertificateContent">The certificate content <c>7F4E ‖ 5F37</c> from the command data field (a view into the recovered command).</param>
public sealed record VerifyCertificateAction(System.ReadOnlyMemory<byte> CertificateContent): CardAction;

/// <summary>
/// Declares that the simulator must select, by holder reference, the imported terminal certificate's key for
/// the Terminal Authentication EXTERNAL AUTHENTICATE. Emitted by MSE:Set AT (P1 <c>0x81</c>); the effectful
/// loop validates the named terminal certificate is imported and feeds a
/// <see cref="TerminalAuthenticationTemplateSet"/> input back.
/// </summary>
/// <param name="ObjectIdentifier">The Terminal Authentication protocol object identifier from DO'80' (a view into the recovered command).</param>
/// <param name="TerminalReference">The terminal certificate holder reference from DO'83' (a view into the recovered command).</param>
public sealed record SetTerminalAuthenticationTemplateAction(System.ReadOnlyMemory<byte> ObjectIdentifier, System.ReadOnlyMemory<byte> TerminalReference): CardAction;

/// <summary>
/// Declares that the simulator must verify the terminal's EXTERNAL AUTHENTICATE signature against the imported
/// terminal certificate's key — the signature over <c>ID_IC ‖ r_IC ‖ Comp(PK_DH,IFD)</c>, where the chip
/// identifier comes from its own EF.DG1, the challenge from its GET CHALLENGE, and the ephemeral key from the
/// preceding Chip Authentication. Emitted by EXTERNAL AUTHENTICATE during Terminal Authentication; the
/// effectful loop verifies and feeds a <see cref="TerminalAuthenticationCompleted"/> or
/// <see cref="TerminalAuthenticationFailed"/> input back.
/// </summary>
/// <param name="Signature">The terminal's signature s_IFD from the EXTERNAL AUTHENTICATE data field (a view into the recovered command).</param>
public sealed record TerminalAuthenticateAction(System.ReadOnlyMemory<byte> Signature): CardAction;
