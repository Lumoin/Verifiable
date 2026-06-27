using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Apdu.Eac;

namespace Verifiable.Apdu.Automata;

/// <summary>
/// The input alphabet of the eMRTD card simulator's pushdown automaton: the commands a terminal sends
/// (parsed from the wire by <see cref="CardSimulator"/> before they enter the automaton) and the
/// action-result records fed back by the effectful loop. This slice models the plaintext read path —
/// SELECT of an elementary file and READ BINARY — plus GET CHALLENGE (the first command needing entropy)
/// and a catch-all for the instructions it does not yet implement.
/// </summary>
public abstract record CardSimulatorInput;

/// <summary>
/// A SELECT command selecting a transparent elementary file by its two-byte file identifier
/// (ISO/IEC 7816-4 SELECT, P1 <c>0x02</c> / P2 <c>0x0C</c>), the form an eMRTD reader uses to choose a
/// data group, EF.COM, or EF.SOD before reading it.
/// </summary>
/// <param name="FileIdentifier">The two-byte elementary file identifier to select.</param>
public sealed record SelectElementaryFileRequested(ushort FileIdentifier): CardSimulatorInput;

/// <summary>
/// A READ BINARY command reading from the currently selected elementary file (ISO/IEC 7816-4 READ BINARY
/// with a 15-bit offset in P1-P2).
/// </summary>
/// <param name="Offset">The octet offset into the selected file at which to start reading.</param>
/// <param name="Length">The number of octets requested (the expected length Le; 256 when the field was zero).</param>
public sealed record ReadBinaryRequested(int Offset, int Length): CardSimulatorInput;

/// <summary>
/// A GET CHALLENGE command (ISO/IEC 7816-4, INS <c>0x84</c>) asking the card for fresh random octets — the
/// chip nonce RND.IC that seeds the Basic Access Control mutual authentication.
/// </summary>
/// <param name="Length">The number of challenge octets requested (the expected length Le; eMRTD BAC uses 8).</param>
public sealed record GetChallengeRequested(int Length): CardSimulatorInput;

/// <summary>
/// The result of executing a <see cref="CardRngAction"/>: the random octets produced by the RNG backend,
/// fed back into the automaton by the effectful loop so the transition can frame the GET CHALLENGE response
/// and retain the issued challenge. This input is internal to the effect loop and never arrives from the
/// command transport.
/// </summary>
/// <param name="Bytes">
/// The pooled buffer holding the produced octets. Ownership flows to the <see cref="ChallengeResponse"/> the
/// transition produces and is released by <see cref="CardSimulator"/> once the response is framed.
/// </param>
/// <param name="Length">The number of valid octets in <paramref name="Bytes"/>.</param>
[DebuggerDisplay("CardEntropyGenerated({Length} bytes)")]
public sealed record CardEntropyGenerated(IMemoryOwner<byte> Bytes, int Length): CardSimulatorInput;

/// <summary>
/// An EXTERNAL AUTHENTICATE command (ISO/IEC 7816-4, INS <c>0x82</c>) carrying the terminal's Basic Access
/// Control authentication token <c>EIFD || MIFD</c>.
/// </summary>
/// <param name="TerminalToken">The 40-byte terminal token (a view into the command APDU).</param>
public sealed record ExternalAuthenticateRequested(ReadOnlyMemory<byte> TerminalToken): CardSimulatorInput;

/// <summary>
/// The successful result of a <see cref="BacAuthenticateAction"/>: the card's response token <c>EIC || MIC</c>,
/// fed back so the transition frames the EXTERNAL AUTHENTICATE response. The Secure Messaging session it
/// established is held by <see cref="CardSimulator"/> as device state. Internal to the effect loop.
/// </summary>
/// <param name="ResponseToken">The pooled buffer holding <c>EIC || MIC</c>; disposed by <see cref="CardSimulator"/> after framing.</param>
/// <param name="Length">The number of valid octets in <paramref name="ResponseToken"/>.</param>
[DebuggerDisplay("BacAuthenticationCompleted({Length} bytes)")]
public sealed record BacAuthenticationCompleted(IMemoryOwner<byte> ResponseToken, int Length): CardSimulatorInput;

/// <summary>
/// The failed result of a <see cref="BacAuthenticateAction"/> (a bad MAC, an unechoed nonce, or missing
/// personalisation), fed back so the transition frames the rejection status word. Internal to the effect loop.
/// </summary>
/// <param name="StatusWord">The status word to return for the rejected EXTERNAL AUTHENTICATE.</param>
public sealed record BacAuthenticationFailed(StatusWord StatusWord): CardSimulatorInput;

/// <summary>
/// An MSE:Set AT command (MANAGE SECURITY ENVIRONMENT, INS <c>0x22</c>, P1 <c>0xC1</c>, P2 <c>0xA4</c>)
/// selecting the PACE mechanism before the GENERAL AUTHENTICATE rounds.
/// </summary>
/// <param name="ObjectIdentifier">The PACE protocol OID value bytes from DO'80' (a view into the command APDU), retained for the round-4 authentication tokens.</param>
public sealed record ManageSecurityEnvironmentRequested(ReadOnlyMemory<byte> ObjectIdentifier): CardSimulatorInput;

/// <summary>
/// A GENERAL AUTHENTICATE command (ISO/IEC 7816-4, INS <c>0x86</c>) carrying a PACE dynamic authentication
/// data object. The inner BER-TLV tag selects the round (an empty object is the encrypted-nonce round); the
/// inner value carries the terminal's contribution for that round (a mapping or ephemeral public key, or a
/// token).
/// </summary>
/// <param name="InnerTag">The context tag of the dynamic authentication data's single inner object, or <c>0</c> when the object is empty (the encrypted-nonce round).</param>
/// <param name="InnerValue">The value of the inner object (a view into the command APDU), or empty for the encrypted-nonce round.</param>
public sealed record GeneralAuthenticateRequested(byte InnerTag, ReadOnlyMemory<byte> InnerValue): CardSimulatorInput;

/// <summary>
/// The result of executing a <see cref="PaceSelectMechanismAction"/>: the PACE mechanism has been captured,
/// fed back so the transition enters the PACE phase. Internal to the effect loop.
/// </summary>
public sealed record PaceMechanismSelected: CardSimulatorInput;

/// <summary>
/// The successful result of a PACE GENERAL AUTHENTICATE round: the response dynamic authentication data
/// object (the encrypted nonce, a public key, or a token), already wrapped, fed back so the transition frames
/// it. Internal to the effect loop.
/// </summary>
/// <param name="ResponseData">The pooled buffer holding the <c>7C</c> response object; disposed by <see cref="CardSimulator"/> after framing.</param>
/// <param name="Length">The number of valid octets in <paramref name="ResponseData"/>.</param>
/// <param name="EstablishesSecureMessaging">Whether this round established the AES Secure Messaging session (the round-4 mutual authentication).</param>
[DebuggerDisplay("PaceRoundCompleted({Length} bytes, EstablishesSecureMessaging={EstablishesSecureMessaging})")]
public sealed record PaceRoundCompleted(IMemoryOwner<byte> ResponseData, int Length, bool EstablishesSecureMessaging): CardSimulatorInput;

/// <summary>
/// The failed result of a PACE GENERAL AUTHENTICATE round (a missing prerequisite or a token that did not
/// verify), fed back so the transition frames the rejection status word and abandons the exchange. Internal
/// to the effect loop.
/// </summary>
/// <param name="StatusWord">The status word to return for the rejected round.</param>
public sealed record PaceExchangeFailed(StatusWord StatusWord): CardSimulatorInput;

/// <summary>
/// An MSE:Set KAT command (MANAGE SECURITY ENVIRONMENT, INS <c>0x22</c>, P1 <c>0x41</c>, P2 <c>0xA6</c>)
/// carrying the terminal's ephemeral public key for EACv1 Chip Authentication — arrives over the established
/// Secure Messaging session.
/// </summary>
/// <param name="TerminalEphemeralPublicKey">The terminal's ephemeral public key from DO'91' (a view into the recovered command).</param>
/// <param name="KeyId">The chip key identifier from DO'84', or <see langword="null"/> when none was carried.</param>
public sealed record ChipAuthenticationKeyAgreementRequested(ReadOnlyMemory<byte> TerminalEphemeralPublicKey, int? KeyId): CardSimulatorInput;

/// <summary>
/// The successful result of a <see cref="ChipAuthenticateAction"/>: the static–ephemeral ECDH secret agreed
/// and the re-keyed Secure Messaging session built (held pending by <see cref="CardSimulator"/> until the
/// MSE:Set KAT response is framed under the old session). Fed back so the transition frames the <c>9000</c>.
/// Internal to the effect loop.
/// </summary>
public sealed record ChipAuthenticationCompleted: CardSimulatorInput;

/// <summary>
/// The failed result of a <see cref="ChipAuthenticateAction"/> (no matching key, an unsupported cipher, or a
/// malformed DG14), fed back so the transition frames the rejection status word; the established session is
/// left intact. Internal to the effect loop.
/// </summary>
/// <param name="StatusWord">The status word to return for the rejected MSE:Set KAT.</param>
public sealed record ChipAuthenticationFailed(StatusWord StatusWord): CardSimulatorInput;

/// <summary>
/// An INTERNAL AUTHENTICATE command (ISO/IEC 7816-4, INS <c>0x88</c>) carrying the terminal's Active
/// Authentication challenge RND.IFD, which the chip signs with its EF.DG15 key.
/// </summary>
/// <param name="Challenge">The challenge to sign (a view into the command APDU).</param>
public sealed record ActiveAuthenticateRequested(ReadOnlyMemory<byte> Challenge): CardSimulatorInput;

/// <summary>
/// The successful result of an <see cref="ActiveAuthenticateAction"/>: the chip's signature over the
/// challenge, fed back so the transition frames the INTERNAL AUTHENTICATE response. Internal to the effect
/// loop.
/// </summary>
/// <param name="Signature">The pooled buffer holding the signature; disposed by <see cref="CardSimulator"/> after framing.</param>
/// <param name="Length">The number of valid octets in <paramref name="Signature"/>.</param>
[DebuggerDisplay("ActiveAuthenticationSigned({Length} bytes)")]
public sealed record ActiveAuthenticationSigned(IMemoryOwner<byte> Signature, int Length): CardSimulatorInput;

/// <summary>
/// The failed result of an <see cref="ActiveAuthenticateAction"/> (no Active Authentication key, no EF.DG15,
/// or an unsupported curve), fed back so the transition frames the rejection status word. Internal to the
/// effect loop.
/// </summary>
/// <param name="StatusWord">The status word to return for the rejected INTERNAL AUTHENTICATE.</param>
public sealed record ActiveAuthenticationFailed(StatusWord StatusWord): CardSimulatorInput;

/// <summary>
/// An MSE:Set DST command (MANAGE SECURITY ENVIRONMENT, INS <c>0x22</c>, P1 <c>0x81</c>, P2 <c>0xB6</c>)
/// naming, by holder reference (DO'83'), the public key that verifies the next PSO:Verify Certificate during
/// Terminal Authentication — arrives over the established Secure Messaging session.
/// </summary>
/// <param name="PublicKeyReference">The certificate holder reference of the verifying key from DO'83' (a view into the recovered command).</param>
public sealed record SetDigitalSignatureTemplateRequested(ReadOnlyMemory<byte> PublicKeyReference): CardSimulatorInput;

/// <summary>
/// A PSO:Verify Certificate command (PERFORM SECURITY OPERATION, INS <c>0x2A</c>, P1 <c>0x00</c>, P2
/// <c>0xBE</c>) presenting a card-verifiable certificate (its body and signature data objects) for the chip
/// to verify against the public key the preceding MSE:Set DST named — arrives over Secure Messaging.
/// </summary>
/// <param name="CertificateContent">The certificate content <c>7F4E ‖ 5F37</c> from the command data field (a view into the recovered command).</param>
public sealed record VerifyCertificateRequested(ReadOnlyMemory<byte> CertificateContent): CardSimulatorInput;

/// <summary>
/// The result of a Terminal Authentication certificate-chain step (a <see cref="SetDigitalSignatureTemplateAction"/>
/// or <see cref="VerifyCertificateAction"/>), fed back so the transition frames the status word. The verified
/// certificate, when accepted, is imported as device state by <see cref="CardSimulator"/>. Internal to the effect loop.
/// </summary>
/// <param name="StatusWord">The status word to return for the MSE:Set DST or PSO:Verify Certificate.</param>
public sealed record TerminalAuthenticationStepCompleted(StatusWord StatusWord): CardSimulatorInput;

/// <summary>
/// An MSE:Set AT command (MANAGE SECURITY ENVIRONMENT, INS <c>0x22</c>, P1 <c>0x81</c>, P2 <c>0xA4</c>)
/// selecting, by holder reference (DO'83'), the imported terminal certificate's key for the EXTERNAL
/// AUTHENTICATE that completes Terminal Authentication — arrives over Secure Messaging.
/// </summary>
/// <param name="ObjectIdentifier">The Terminal Authentication protocol object identifier from DO'80' (a view into the recovered command).</param>
/// <param name="TerminalReference">The terminal certificate holder reference from DO'83' (a view into the recovered command).</param>
public sealed record SetTerminalAuthenticationTemplateRequested(ReadOnlyMemory<byte> ObjectIdentifier, ReadOnlyMemory<byte> TerminalReference): CardSimulatorInput;

/// <summary>
/// The result of a <see cref="SetTerminalAuthenticationTemplateAction"/>, fed back so the transition frames
/// the status word and, on success, arms the Terminal Authentication EXTERNAL AUTHENTICATE. Internal to the effect loop.
/// </summary>
/// <param name="StatusWord">The status word to return for the MSE:Set AT.</param>
public sealed record TerminalAuthenticationTemplateSet(StatusWord StatusWord): CardSimulatorInput;

/// <summary>
/// The successful result of a <see cref="TerminalAuthenticateAction"/>: the terminal's EXTERNAL AUTHENTICATE
/// signature verified against the imported terminal certificate's key. Fed back so the transition frames the
/// <c>9000</c> and grants the terminal the effective sensitive-data read access. Internal to the effect loop.
/// </summary>
/// <param name="GrantedReadAccess">The effective Inspection System read authorization (the bitwise AND of the verified chain's Certificate Holder Authorization Templates, BSI TR-03110-3 §2.7) the chip grants the now-authenticated terminal for subsequent EF.DG3/EF.DG4 reads.</param>
public sealed record TerminalAuthenticationCompleted(InspectionSystemAccess GrantedReadAccess): CardSimulatorInput;

/// <summary>
/// The failed result of a <see cref="TerminalAuthenticateAction"/> (a signature that did not verify, or a
/// missing prerequisite), fed back so the transition frames the rejection status word. Internal to the effect loop.
/// </summary>
/// <param name="StatusWord">The status word to return for the rejected EXTERNAL AUTHENTICATE.</param>
public sealed record TerminalAuthenticationFailed(StatusWord StatusWord): CardSimulatorInput;

/// <summary>
/// A command whose instruction byte this slice does not model. It is dispatched like any other command so
/// the rejection is recorded in the trace, and answered with <c>6D00</c> (instruction not supported).
/// </summary>
/// <param name="Instruction">The instruction byte parsed from the command header.</param>
public sealed record UnsupportedCommandReceived(byte Instruction): CardSimulatorInput;
