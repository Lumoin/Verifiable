using System;
using System.Buffers;
using System.Collections.Generic;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.Fido2.Ctap.Authenticator.Automata;

/// <summary>
/// The input alphabet of the CTAP2 authenticator simulator's pushdown automaton: the commands a
/// platform sends, already parsed from the wire by <see cref="CtapAuthenticatorSimulator"/> before
/// they enter the automaton, plus the effect fold-back inputs the effectful loop feeds back after
/// running a <see cref="CtapAction"/>. This slice models <c>authenticatorGetInfo</c> (0x04),
/// <c>authenticatorMakeCredential</c> (0x01), <c>authenticatorGetAssertion</c> (0x02),
/// <c>authenticatorGetNextAssertion</c> (0x08), and a catch-all for every other command byte.
/// </summary>
public abstract record CtapAuthenticatorInput;

/// <summary>
/// An <c>authenticatorGetInfo</c> (<c>0x04</c>) request. The command itself takes no wire parameters;
/// <see cref="SupportedAlgorithms"/> is a composition-time fact resolved before dispatch (the same
/// "the pure transition has no access to the backend" reason
/// <see cref="MakeCredentialRequested.SelectedAlgorithm"/> is resolved outside the automaton for).
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetInfo">
/// CTAP 2.3, section 6.4: authenticatorGetInfo (0x04)</see>.
/// </remarks>
/// <param name="SupportedAlgorithms">
/// The credential-signing backend's supported COSE algorithm identifiers
/// (<see cref="CtapCredentialSigningBackend.SupportedAlgorithms"/>), or <see langword="null"/> when no
/// backend is injected — the source <c>CtapAuthenticatorTransitions.BuildGetInfoResponse</c> builds
/// the <c>algorithms</c> (<c>0x0A</c>) getInfo member from (CTAP 2.3, snapshot lines 4424-4427).
/// </param>
public sealed record GetInfoRequested(IReadOnlyList<int>? SupportedAlgorithms = null): CtapAuthenticatorInput;

/// <summary>
/// An <c>authenticatorClientPIN</c> (<c>0x06</c>) request, already CBOR-decoded by
/// <see cref="CtapAuthenticatorSimulator"/>.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorClientPIN">
/// CTAP 2.3, section 6.5.5: authenticatorClientPIN (0x06) Command Definition</see>. This authenticator
/// handles the three read-only subcommands (<c>getPINRetries</c>, <c>getKeyAgreement</c>,
/// <c>getUVRetries</c>) and the four PIN-path subcommands (<c>setPIN</c>, <c>changePIN</c>,
/// <c>getPinToken</c>, <c>getPinUvAuthTokenUsingPinWithPermissions</c>); every other <c>subCommand</c>
/// value is rejected.
/// </remarks>
/// <param name="Request">The decoded request.</param>
/// <param name="Now">
/// The time this command was received, read once from the simulator's threaded
/// <see cref="TimeProvider"/> before this input was built — the value the token-issuing subcommands'
/// <c>beginUsingPinUvAuthToken</c> call stamps as a fresh token's usage-timer start. The pure transition
/// never reads a clock itself.
/// </param>
public sealed record ClientPinRequested(CtapClientPinRequest Request, DateTimeOffset Now): CtapAuthenticatorInput;

/// <summary>
/// The effect fold-back of a <see cref="CtapComputeKeyAgreementPublicKeyAction"/>: the computed
/// <c>getPublicKey()</c> view of the requested protocol's key-agreement key pair, ready to complete a
/// <c>getKeyAgreement</c> response.
/// </summary>
/// <param name="PublicKey">The computed COSE_Key view.</param>
public sealed record ClientPinKeyAgreementComputed(CoseKey PublicKey): CtapAuthenticatorInput;

/// <summary>
/// A command byte this simulator does not implement.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#message-encoding">
/// CTAP 2.3, section 8: Message Encoding</see>: "If an authenticator receives a command code it does
/// not implement, it MUST return CTAP1_ERR_INVALID_COMMAND." Dispatched like any other command so
/// the rejection is recorded in the automaton's trace.
/// </remarks>
/// <param name="CommandByte">The unrecognized command byte.</param>
public sealed record UnsupportedCtapCommandReceived(byte CommandByte): CtapAuthenticatorInput;

/// <summary>
/// An <c>authenticatorMakeCredential</c> (<c>0x01</c>) request, already CBOR-decoded by
/// <see cref="CtapAuthenticatorSimulator"/>.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorMakeCredential">
/// CTAP 2.3, section 6.1: authenticatorMakeCredential (0x01)</see>.
/// </remarks>
/// <param name="Request">The decoded request.</param>
/// <param name="SelectedAlgorithm">
/// The algorithm the pubKeyCredParams selection loop chose (CTAP 2.3 section 6.1.2, step 3: the first
/// element of <see cref="CtapMakeCredentialRequest.PubKeyCredParams"/> whose algorithm the injected
/// <see cref="CtapCredentialSigningBackend"/> supports), or <see langword="null"/> if none of them are
/// supported. Resolved by <see cref="CtapAuthenticatorSimulator"/> before dispatch, since the pure
/// transition has no access to the backend's supported-algorithm set.
/// </param>
/// <param name="Now">
/// The time this command was received, read once from the simulator's threaded
/// <see cref="TimeProvider"/> before this input was built, mirroring <see cref="GetAssertionRequested.Now"/>
/// — a presented <c>pinUvAuthToken</c>'s usage-timer expiry (<see cref="CtapPinUvAuthTokenState.EvaluateExpiry"/>)
/// is evaluated against this value ahead of the token being trusted, and it is the stamp a successful
/// verify writes into the token's <see cref="CtapPinUvAuthTokenState.LastUsedAt"/>. The pure transition
/// never reads a clock itself.
/// </param>
/// <param name="IsUserPresenceDeferralAllowed">
/// Whether the transport that decoded this request supports parking a user-presence wait across
/// separate wire round trips (R2) — threaded as data from <see cref="CtapAuthenticatorSimulator.BeginDeferredTransceiveAsync"/>,
/// never ambient state. Defaults to <see langword="false"/>: a plain <see cref="Ctap2TransceiveDelegate"/>
/// call processes synchronously to completion, so <see cref="CtapUserPresenceDecision.Pending"/> resolves
/// to <see cref="WellKnownCtapStatusCodes.UserActionTimeout"/> rather than parking.
/// </param>
public sealed record MakeCredentialRequested(
    CtapMakeCredentialRequest Request, int? SelectedAlgorithm, DateTimeOffset Now, bool IsUserPresenceDeferralAllowed = false): CtapAuthenticatorInput;

/// <summary>
/// An <c>authenticatorGetAssertion</c> (<c>0x02</c>) request, already CBOR-decoded by
/// <see cref="CtapAuthenticatorSimulator"/>.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetAssertion">
/// CTAP 2.3, section 6.2: authenticatorGetAssertion (0x02)</see>.
/// </remarks>
/// <param name="Request">The decoded request.</param>
/// <param name="Now">
/// The time this command was received, read once from the simulator's threaded
/// <see cref="TimeProvider"/> before this input was built — becomes a new sequence's
/// <see cref="CtapRememberedGetAssertionState.LastActivityAt"/> when the request locates more than one
/// applicable credential; a presented <c>pinUvAuthToken</c>'s usage-timer expiry
/// (<see cref="CtapPinUvAuthTokenState.EvaluateExpiry"/>) is evaluated against this value ahead of the
/// token being trusted, and it is the stamp a successful verify writes into the token's
/// <see cref="CtapPinUvAuthTokenState.LastUsedAt"/>. The pure transition never reads a clock itself.
/// </param>
/// <param name="IsUserPresenceDeferralAllowed">
/// Whether the transport that decoded this request supports parking a user-presence wait across
/// separate wire round trips (R2) — see <see cref="MakeCredentialRequested.IsUserPresenceDeferralAllowed"/>'s
/// identical remark. Defaults to <see langword="false"/>.
/// </param>
public sealed record GetAssertionRequested(
    CtapGetAssertionRequest Request, DateTimeOffset Now, bool IsUserPresenceDeferralAllowed = false): CtapAuthenticatorInput;

/// <summary>
/// An <c>authenticatorGetNextAssertion</c> (<c>0x08</c>) request. The command takes no parameters, so
/// this input carries only the precomputed fact its pure transition needs.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetNextAssertion">
/// CTAP 2.3, section 6.3: authenticatorGetNextAssertion (0x08)</see>: "It takes no arguments."
/// </remarks>
/// <param name="Now">
/// The time this command was received, read once from the simulator's threaded
/// <see cref="TimeProvider"/> before this input was built. Compared against the remembered sequence's
/// <see cref="CtapRememberedGetAssertionState.LastActivityAt"/> for the 30-second timer check — an
/// ordinary comparison of two already-known values, not a clock read, so the pure transition stays
/// time-free.
/// </param>
public sealed record GetNextAssertionRequested(DateTimeOffset Now): CtapAuthenticatorInput;

/// <summary>
/// An <c>authenticatorConfig</c> (<c>0x0D</c>) request, already CBOR-decoded by
/// <see cref="CtapAuthenticatorSimulator"/>.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorConfig">
/// CTAP 2.3, section 6.11: authenticatorConfig (0x0D)</see>. This authenticator supports
/// <c>toggleAlwaysUv</c> and <c>setMinPINLength</c>; every other <c>subCommand</c> value is rejected.
/// </remarks>
/// <param name="Request">The decoded request.</param>
/// <param name="Now">
/// The time this command was received, read once from the simulator's threaded
/// <see cref="TimeProvider"/> before this input was built — the value a presented
/// <c>pinUvAuthToken</c>'s usage-timer expiry (<see cref="CtapPinUvAuthTokenState.EvaluateExpiry"/>) is
/// evaluated against ahead of trusting it, and the stamp a successful verify writes into the token's
/// <see cref="CtapPinUvAuthTokenState.LastUsedAt"/>. The pure transition never reads a clock itself.
/// </param>
public sealed record AuthenticatorConfigRequested(CtapAuthenticatorConfigRequest Request, DateTimeOffset Now): CtapAuthenticatorInput;

/// <summary>
/// The effect fold-back of a <see cref="CtapResetPinUvAuthTokensAction"/>: two freshly minted, not-in-use
/// <c>pinUvAuthToken</c> states, one per PIN/UV auth protocol.
/// </summary>
/// <remarks>
/// Carries no persistent-state fields of its own (<c>MinPinCodePointLength</c>/
/// <c>IsForcePinChangeRequired</c>) because <c>OnSetMinPinLengthRequested</c> already applies those
/// plain scalar writes to <see cref="CtapAuthenticatorState"/> BEFORE declaring the action — the
/// effectful loop preserves every field the fold-back's own <c>with</c> copy does not touch, so those
/// values survive the round trip unchanged, mirroring <see cref="ClientPinKeyAgreementComputed"/>'s
/// equally minimal fold-back shape.
/// </remarks>
/// <param name="FreshProtocolOneToken">PIN/UV auth protocol one's freshly reset token state.</param>
/// <param name="FreshProtocolTwoToken">PIN/UV auth protocol two's freshly reset token state.</param>
public sealed record PinUvAuthTokensReset(
    CtapPinUvAuthTokenState FreshProtocolOneToken, CtapPinUvAuthTokenState FreshProtocolTwoToken): CtapAuthenticatorInput;

/// <summary>
/// The effect fold-back of a <see cref="CtapGenerateCredentialKeyAction"/>: the completed
/// <c>authenticatorMakeCredential</c> response and the credential record to persist.
/// </summary>
/// <param name="Response">The completed response, ready to be CBOR-encoded.</param>
/// <param name="Record">The credential record to add to the store.</param>
public sealed record CredentialMinted(CtapMakeCredentialResponse Response, CtapCredentialRecord Record): CtapAuthenticatorInput;

/// <summary>
/// The effect fold-back of a <see cref="CtapSignAssertionAction"/>: the completed
/// <c>authenticatorGetAssertion</c>/<c>authenticatorGetNextAssertion</c> response and the
/// signature-counter update to persist.
/// </summary>
/// <param name="Response">The completed response, ready to be CBOR-encoded.</param>
/// <param name="CredentialId">The signed credential's identifier, identifying which store entry to update.</param>
/// <param name="NewSignCount">The incremented signature counter value to persist.</param>
/// <param name="RememberedState">
/// A freshly minted remembered <c>authenticatorGetAssertion</c> sequence to install onto
/// <see cref="CtapAuthenticatorState.RememberedGetAssertion"/>, when this sign completed the first
/// response of a multi-account <c>authenticatorGetAssertion</c>; <see langword="null"/> otherwise, in
/// which case the transition preserves whatever the state already carries (unchanged for a
/// single-credential <c>authenticatorGetAssertion</c>, already advanced in place for an
/// <c>authenticatorGetNextAssertion</c> sign).
/// </param>
public sealed record AssertionSigned(
    CtapGetAssertionResponse Response, CredentialId CredentialId, uint NewSignCount, CtapRememberedGetAssertionState? RememberedState): CtapAuthenticatorInput;

/// <summary>
/// The discriminants a <see cref="CtapSignAssertionAction.HmacSecret"/> crypto sequence can conclude
/// with (CTAP 2.3 §12.7, snapshot lines 13292-13307).
/// </summary>
public enum CtapGetAssertionHmacSecretOutcomeKind
{
    /// <summary><c>verify(sharedSecret, saltEnc, saltAuth)</c> failed (snapshot line 13304) → <see cref="WellKnownCtapStatusCodes.PinAuthInvalid"/> (trap 2).</summary>
    VerifyFailed,

    /// <summary>
    /// <c>decrypt(sharedSecret, saltEnc)</c> failed, or the decrypted plaintext is not exactly 32 or 64
    /// bytes long (snapshot line 13307) → <see cref="WellKnownCtapStatusCodes.InvalidParameter"/> (trap
    /// 3) — the length gate is on the DECRYPTED plaintext, never <c>saltEnc</c>'s own ciphertext length
    /// (trap 7).
    /// </summary>
    DecryptFailed,

    /// <summary>Every hmac-secret crypto step succeeded (or <see cref="CtapSignAssertionAction.HmacSecret"/> was absent); the assertion signing proceeds.</summary>
    Success
}

/// <summary>
/// The effect fold-back of a <see cref="CtapSignAssertionAction"/> whose <see cref="CtapSignAssertionAction.HmacSecret"/>
/// crypto sequence did NOT conclude with <see cref="CtapGetAssertionHmacSecretOutcomeKind.Success"/>:
/// aborts the whole <c>authenticatorGetAssertion</c>/<c>authenticatorGetNextAssertion</c> command with
/// the resolved status code — no assertion is ever signed, and no signature-counter update is ever
/// persisted, since <see cref="AssertionSigned"/> is never produced on this path.
/// </summary>
/// <param name="Kind">Which hmac-secret crypto step failed (never <see cref="CtapGetAssertionHmacSecretOutcomeKind.Success"/>).</param>
public sealed record GetAssertionHmacSecretFailed(CtapGetAssertionHmacSecretOutcomeKind Kind): CtapAuthenticatorInput;

/// <summary>
/// The effect fold-back of a <see cref="CtapGenerateCredentialKeyAction"/> whose
/// <see cref="CtapGenerateCredentialKeyAction.HmacSecretMc"/> crypto delegation (CTAP 2.3 §12.8,
/// snapshot line 13402: the SAME routine <see cref="CtapSignAssertionAction.HmacSecret"/>'s own effect
/// runs) did NOT conclude with <see cref="CtapGetAssertionHmacSecretOutcomeKind.Success"/>: aborts the
/// whole <c>authenticatorMakeCredential</c> command with the resolved status code — no credential is
/// ever minted, since <see cref="CredentialMinted"/> is never produced on this path.
/// </summary>
/// <param name="Kind">Which hmac-secret-mc crypto step failed (never <see cref="CtapGetAssertionHmacSecretOutcomeKind.Success"/>).</param>
public sealed record MakeCredentialHmacSecretMcFailed(CtapGetAssertionHmacSecretOutcomeKind Kind): CtapAuthenticatorInput;

/// <summary>
/// The effect fold-back of a <see cref="CtapVerifyPinUvAuthTokenAction"/>: whether the presented
/// <c>pinUvAuthParam</c> verified against the selected protocol's in-use <c>pinUvAuthToken</c> (CTAP
/// 2.3 §6.1.2 step 11.1.1 / §6.2.2 step 6.1.1).
/// </summary>
/// <param name="Verified"><see langword="true"/> when verification succeeded; otherwise <see langword="false"/>.</param>
/// <param name="Continuation">The interrupted command's own decoded-request context to resume.</param>
public sealed record PinUvAuthTokenVerified(bool Verified, CtapVerifyPinUvAuthTokenContinuation Continuation): CtapAuthenticatorInput;

/// <summary>
/// An <c>authenticatorCredentialManagement</c> (<c>0x0A</c>) request, already CBOR-decoded by
/// <see cref="CtapAuthenticatorSimulator"/>.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorCredentialManagement">
/// CTAP 2.3, section 6.8: authenticatorCredentialManagement (0x0A)</see>. This authenticator supports
/// all seven subcommands.
/// </remarks>
/// <param name="Request">The decoded request.</param>
/// <param name="Now">
/// The time this command was received, read once from the simulator's threaded
/// <see cref="TimeProvider"/> before this input was built — the value a presented
/// <c>pinUvAuthToken</c>'s usage-timer expiry (<see cref="CtapPinUvAuthTokenState.EvaluateExpiry"/>) is
/// evaluated against ahead of trusting it, the stamp a successful verify writes into the token's
/// <see cref="CtapPinUvAuthTokenState.LastUsedAt"/>, and the value a freshly initialized enumeration
/// sequence's own <see cref="CtapRememberedEnumerateRpsState.LastActivityAt"/>/
/// <see cref="CtapRememberedEnumerateCredentialsState.LastActivityAt"/> starts from. The pure transition
/// never reads a clock itself.
/// </param>
public sealed record CredentialManagementRequested(CtapCredentialManagementRequest Request, DateTimeOffset Now): CtapAuthenticatorInput;

/// <summary>
/// The effect fold-back of a <see cref="CtapEmitCredentialManagementRpAction"/>: one fully assembled
/// <c>authenticatorCredentialManagement</c> response — <c>enumerateRPsBegin</c>'s or
/// <c>enumerateRPsGetNextRP</c>'s own <c>rp</c>/<c>rpIDHash</c>(/<c>totalRPs</c>) payload, the freshly
/// computed <c>rpIDHash</c> bytes having required the effectful loop's own memory pool.
/// </summary>
/// <param name="Response">The completed response, ready to be CBOR-encoded.</param>
public sealed record CredentialManagementResponseComputed(CtapCredentialManagementResponse Response): CtapAuthenticatorInput;

/// <summary>
/// The effect fold-back of a <see cref="CtapLocateCredentialManagementCredentialsAction"/>:
/// <c>enumerateCredentialsBegin</c>'s own by-hash resident-credential match, ordered
/// <see cref="CtapCredentialRecord.CreationSequence"/>-ascending (R9) — the per-candidate
/// <c>rpIDHash</c> recomputation having required the effectful loop's own memory pool.
/// </summary>
/// <param name="MatchedCredentialIds">
/// Every resident credential whose relying party identifier's freshly computed hash matched the
/// request's <c>rpIDHash</c>, in the chosen enumeration order; empty when none matched.
/// </param>
/// <param name="Now">Echoed from <see cref="CtapLocateCredentialManagementCredentialsAction.Now"/> — the freshly initialized sequence's starting activity timestamp.</param>
/// <param name="AuthenticatingPinUvAuthProtocol">Echoed from <see cref="CtapLocateCredentialManagementCredentialsAction.AuthenticatingPinUvAuthProtocol"/>.</param>
public sealed record CredentialManagementCredentialsLocated(
    IReadOnlyList<CredentialId> MatchedCredentialIds,
    DateTimeOffset Now,
    CtapPinUvAuthProtocolId AuthenticatingPinUvAuthProtocol): CtapAuthenticatorInput;

/// <summary>
/// The discriminants a <see cref="CtapEstablishPinAction"/>'s crypto sequence can conclude with
/// (CTAP 2.3 §6.5.5.5, lines 5570-5593).
/// </summary>
public enum CtapSetPinOutcomeKind
{
    /// <summary><c>decapsulate</c> failed (line 5570) → <see cref="WellKnownCtapStatusCodes.InvalidParameter"/>.</summary>
    DecapsulationFailed,

    /// <summary><c>verify(sharedSecret, newPinEnc, pinUvAuthParam)</c> failed (line 5572-5575) → <see cref="WellKnownCtapStatusCodes.PinAuthInvalid"/>.</summary>
    VerifyFailed,

    /// <summary><c>decrypt(sharedSecret, newPinEnc)</c> failed (line 5578) → <see cref="WellKnownCtapStatusCodes.PinAuthInvalid"/>.</summary>
    DecryptFailed,

    /// <summary><c>paddedNewPin</c> is not exactly 64 bytes (line 5580) → <see cref="WellKnownCtapStatusCodes.InvalidParameter"/>.</summary>
    PaddedLengthInvalid,

    /// <summary><c>newPin</c>'s code-point length is below the minimum (line 5584) → <see cref="WellKnownCtapStatusCodes.PinPolicyViolation"/>.</summary>
    PolicyViolation,

    /// <summary>Every check passed; the new PIN was stored (lines 5590-5593).</summary>
    Success
}

/// <summary>
/// The effect fold-back of a <see cref="CtapEstablishPinAction"/>.
/// </summary>
/// <param name="Kind">Which outcome the crypto sequence concluded with.</param>
/// <param name="NewPinCodePointLength">
/// The new PIN's length in Unicode code points, computed whenever the decrypted PIN was successfully
/// UTF-8-decoded (<see cref="CtapSetPinOutcomeKind.PolicyViolation"/> and
/// <see cref="CtapSetPinOutcomeKind.Success"/>); 0 otherwise.
/// </param>
/// <param name="NewPinHash">
/// The new stored PIN hash (<c>LEFT(SHA-256(newPin), 16)</c>), owned and pooled — present only when
/// <paramref name="Kind"/> is <see cref="CtapSetPinOutcomeKind.Success"/>; ownership transfers to
/// <see cref="CtapAuthenticatorState.CurrentStoredPin"/>. <see langword="null"/> otherwise.
/// </param>
public sealed record PinEstablishmentCompleted(
    CtapSetPinOutcomeKind Kind,
    int NewPinCodePointLength,
    DigestValue? NewPinHash): CtapAuthenticatorInput;

/// <summary>
/// The discriminants a <see cref="CtapChangePinAction"/>'s crypto sequence can conclude with
/// (CTAP 2.3 §6.5.5.6, lines 5658-5716).
/// </summary>
public enum CtapChangePinOutcomeKind
{
    /// <summary><c>decapsulate</c> failed (line 5658) → <see cref="WellKnownCtapStatusCodes.InvalidParameter"/>.</summary>
    DecapsulationFailed,

    /// <summary><c>verify(sharedSecret, newPinEnc || pinHashEnc, pinUvAuthParam)</c> failed (lines 5660-5663), with NO retries decrement → <see cref="WellKnownCtapStatusCodes.PinAuthInvalid"/>.</summary>
    VerifyFailed,

    /// <summary>
    /// <c>decrypt(sharedSecret, pinHashEnc)</c> failed (line 5671: "If an error results, or a mismatch is
    /// detected, the authenticator performs the following operations") — handled identically to
    /// <see cref="CurrentPinMismatch"/>: <c>regenerate()</c>, decrement, then
    /// <see cref="WellKnownCtapStatusCodes.PinBlocked"/>/<see cref="WellKnownCtapStatusCodes.PinAuthBlocked"/>/
    /// <see cref="WellKnownCtapStatusCodes.PinInvalid"/> (lines 5678-5685).
    /// </summary>
    CurrentPinDecryptFailed,

    /// <summary>The decrypted <c>pinHashEnc</c> did not match the stored PIN hash (lines 5670-5687).</summary>
    CurrentPinMismatch,

    /// <summary><c>decrypt(sharedSecret, newPinEnc)</c> failed after a confirmed current-PIN match (line 5692) → <see cref="WellKnownCtapStatusCodes.PinAuthInvalid"/>.</summary>
    NewPinDecryptFailed,

    /// <summary>The decrypted <c>paddedNewPin</c> is not exactly 64 bytes (line 5694) → <see cref="WellKnownCtapStatusCodes.InvalidParameter"/>.</summary>
    NewPinPaddedLengthInvalid,

    /// <summary>The new PIN's code-point length is below the minimum (line 5698) → <see cref="WellKnownCtapStatusCodes.PinPolicyViolation"/>.</summary>
    NewPinPolicyViolation,

    /// <summary>
    /// <see cref="CtapChangePinAction.IsForcePinChangeRequired"/> is <see langword="true"/> and the new
    /// PIN's hash equals the stored current PIN's hash (line 5700, <c>FixedTimeEquals</c>) →
    /// <see cref="WellKnownCtapStatusCodes.PinPolicyViolation"/>. Checked after the length check (line
    /// 5698) and before minting fresh tokens, matching the spec's own step order.
    /// </summary>
    NewPinSameAsCurrentUnderForce,

    /// <summary>Every check passed; the new PIN was stored and every <c>pinUvAuthToken</c> was reset (lines 5706-5716).</summary>
    Success
}

/// <summary>
/// The effect fold-back of a <see cref="CtapChangePinAction"/>.
/// </summary>
/// <param name="Kind">Which outcome the crypto sequence concluded with.</param>
/// <param name="ProtocolId">
/// The selected protocol, echoed from the action — identifies which key-agreement pair a
/// <see cref="CtapChangePinOutcomeKind.CurrentPinDecryptFailed"/> or
/// <see cref="CtapChangePinOutcomeKind.CurrentPinMismatch"/> outcome regenerated.
/// </param>
/// <param name="RegeneratedKeyPair">
/// The freshly minted key-agreement key pair for <paramref name="ProtocolId"/>
/// (<c>regenerate()</c>), owned — present only when <paramref name="Kind"/> is
/// <see cref="CtapChangePinOutcomeKind.CurrentPinDecryptFailed"/> or
/// <see cref="CtapChangePinOutcomeKind.CurrentPinMismatch"/> (line 5671: both conditions receive
/// identical handling). <see langword="null"/> otherwise.
/// </param>
/// <param name="NewPinCodePointLength">The new PIN's code-point length — present (non-zero) only alongside <see cref="NewPinHash"/>.</param>
/// <param name="NewPinHash">
/// The new stored PIN hash, owned and pooled — present only when <paramref name="Kind"/> is
/// <see cref="CtapChangePinOutcomeKind.Success"/>. <see langword="null"/> otherwise.
/// </param>
/// <param name="FreshProtocolOneToken">
/// PIN/UV auth protocol one's freshly reset (not begun-using) <c>pinUvAuthToken</c> state — present
/// only when <paramref name="Kind"/> is <see cref="CtapChangePinOutcomeKind.Success"/>, since a
/// successful <c>changePIN</c> invalidates every outstanding token system-wide (line 5714).
/// </param>
/// <param name="FreshProtocolTwoToken">PIN/UV auth protocol two's freshly reset token state — see <see cref="FreshProtocolOneToken"/>.</param>
public sealed record PinChangeCompleted(
    CtapChangePinOutcomeKind Kind,
    CtapPinUvAuthProtocolId ProtocolId,
    CtapPinUvAuthKeyAgreementKeyPair? RegeneratedKeyPair,
    int NewPinCodePointLength,
    DigestValue? NewPinHash,
    CtapPinUvAuthTokenState? FreshProtocolOneToken,
    CtapPinUvAuthTokenState? FreshProtocolTwoToken): CtapAuthenticatorInput;

/// <summary>
/// The discriminants the shared <c>getPinToken</c>/<c>getPinUvAuthTokenUsingPinWithPermissions</c>
/// crypto sequence (<see cref="CtapIssuePinTokenAction"/>) can conclude with (CTAP 2.3 §6.5.5.7.1 lines
/// 5873-5915, §6.5.5.7.2 lines 5975-6026).
/// </summary>
public enum CtapPinTokenIssuanceOutcomeKind
{
    /// <summary><c>decapsulate</c> failed → <see cref="WellKnownCtapStatusCodes.InvalidParameter"/>.</summary>
    DecapsulationFailed,

    /// <summary>
    /// <c>decrypt(sharedSecret, pinHashEnc)</c> failed (CTAP 2.3 §6.5.5.7.1 line 5883, §6.5.5.7.2 line
    /// 5985: "If an error results, or a mismatch is detected, the authenticator performs the following
    /// operations") — handled identically to <see cref="CurrentPinMismatch"/>: <c>regenerate()</c>,
    /// decrement, then <see cref="WellKnownCtapStatusCodes.PinBlocked"/>/
    /// <see cref="WellKnownCtapStatusCodes.PinAuthBlocked"/>/<see cref="WellKnownCtapStatusCodes.PinInvalid"/>.
    /// </summary>
    CurrentPinDecryptFailed,

    /// <summary>The decrypted <c>pinHashEnc</c> did not match the stored PIN hash.</summary>
    CurrentPinMismatch,

    /// <summary>
    /// The current PIN matched and <c>pinRetries</c> was reset to maximum, but
    /// <see cref="CtapIssuePinTokenAction.IsForcePinChangeRequired"/> is <see langword="true"/>: no
    /// token is minted (CTAP 2.3 §6.5.5.7.1 line 5904 / §6.5.5.7.2 line 6006, checked strictly AFTER
    /// the current-PIN match succeeds and the retries reset, strictly BEFORE <c>resetPinUvAuthToken()</c>
    /// for all protocols).
    /// </summary>
    ForcePinChangeRequired,

    /// <summary>Every check passed; a fresh <c>pinUvAuthToken</c> was issued for the selected protocol.</summary>
    Success
}

/// <summary>
/// The effect fold-back of a <see cref="CtapIssuePinTokenAction"/>.
/// </summary>
/// <param name="Kind">Which outcome the crypto sequence concluded with.</param>
/// <param name="ProtocolId">
/// The selected protocol, echoed from the action — identifies which key-agreement pair a
/// <see cref="CtapPinTokenIssuanceOutcomeKind.CurrentPinDecryptFailed"/> or
/// <see cref="CtapPinTokenIssuanceOutcomeKind.CurrentPinMismatch"/> outcome regenerated.
/// </param>
/// <param name="RegeneratedKeyPair">
/// The freshly minted key-agreement key pair for <paramref name="ProtocolId"/> (<c>regenerate()</c>),
/// owned — present only when <paramref name="Kind"/> is
/// <see cref="CtapPinTokenIssuanceOutcomeKind.CurrentPinDecryptFailed"/> or
/// <see cref="CtapPinTokenIssuanceOutcomeKind.CurrentPinMismatch"/> (both conditions receive identical
/// handling). <see langword="null"/> otherwise.
/// </param>
/// <param name="FreshProtocolOneToken">
/// PIN/UV auth protocol one's freshly reset <c>pinUvAuthToken</c> state — present only when
/// <paramref name="Kind"/> is <see cref="CtapPinTokenIssuanceOutcomeKind.Success"/>. The selected
/// protocol's token has already had <c>beginUsingPinUvAuthToken(userIsPresent: false)</c> applied and
/// its permissions/permissions-RP-ID assigned; the other protocol's token is fresh and unused.
/// </param>
/// <param name="FreshProtocolTwoToken">PIN/UV auth protocol two's freshly reset token state — see <see cref="FreshProtocolOneToken"/>.</param>
/// <param name="EncryptedToken">
/// The selected protocol's freshly issued token, encrypted under the shared secret
/// (<c>encrypt(sharedSecret, pinUvAuthToken)</c>) — ciphertext, non-secret. Present only when
/// <paramref name="Kind"/> is <see cref="CtapPinTokenIssuanceOutcomeKind.Success"/>.
/// </param>
/// <param name="ForcePinChangeDeniedStatusCode">
/// The status code to reject with, echoed from <see cref="CtapIssuePinTokenAction.ForcePinChangeDeniedStatusCode"/> —
/// present only when <paramref name="Kind"/> is <see cref="CtapPinTokenIssuanceOutcomeKind.ForcePinChangeRequired"/>.
/// Different subcommands answer this identical condition with different codes (<see cref="WellKnownCtapStatusCodes.PinInvalid"/>
/// for <c>getPinToken</c>, <see cref="WellKnownCtapStatusCodes.PinPolicyViolation"/> for
/// <c>getPinUvAuthTokenUsingPinWithPermissions</c>), so the pure fold-back cannot resolve it from
/// <paramref name="Kind"/> alone.
/// </param>
public sealed record PinTokenIssuanceCompleted(
    CtapPinTokenIssuanceOutcomeKind Kind,
    CtapPinUvAuthProtocolId ProtocolId,
    CtapPinUvAuthKeyAgreementKeyPair? RegeneratedKeyPair,
    CtapPinUvAuthTokenState? FreshProtocolOneToken,
    CtapPinUvAuthTokenState? FreshProtocolTwoToken,
    ReadOnlyMemory<byte>? EncryptedToken,
    byte? ForcePinChangeDeniedStatusCode = null): CtapAuthenticatorInput;

/// <summary>
/// The effect fold-back of a <see cref="CtapPerformBuiltInUvAction"/>: the simulated attempt loop's
/// final outcome and how many <see cref="CtapAuthenticatorState.UvRetries"/> decrements it consumed —
/// <c>authenticatorMakeCredential</c>/<c>authenticatorGetAssertion</c>'s own <c>options.uv = true</c>
/// fallback (CTAP 2.3 §6.1.2 step 11.2.3 / §6.2.2 step 6.2.3).
/// </summary>
/// <param name="Outcome">The attempt loop's final outcome.</param>
/// <param name="AttemptsConsumed">
/// How many attempts the loop made before concluding — the pure fold-back decrements
/// <see cref="CtapAuthenticatorState.UvRetries"/> by exactly this amount (or resets it to
/// <see cref="CtapAuthenticatorState.MaxUvRetries"/> on <see cref="CtapBuiltInUvAttemptOutcome.Success"/>).
/// </param>
/// <param name="Continuation">The interrupted command's own decoded-request context to resume.</param>
public sealed record BuiltInUvAttempted(
    CtapBuiltInUvAttemptOutcome Outcome, int AttemptsConsumed, CtapPerformBuiltInUvContinuation Continuation): CtapAuthenticatorInput;

/// <summary>
/// The discriminants a <see cref="CtapIssueUvTokenAction"/>'s crypto sequence can conclude with (CTAP
/// 2.3 §6.5.5.7.3).
/// </summary>
public enum CtapUvTokenIssuanceOutcomeKind
{
    /// <summary><c>decapsulate</c> failed → <see cref="WellKnownCtapStatusCodes.InvalidParameter"/>.</summary>
    DecapsulationFailed,

    /// <summary>
    /// The attempt loop concluded with <see cref="CtapBuiltInUvAttemptOutcome.MatchFailure"/> — maps to
    /// <see cref="WellKnownCtapStatusCodes.UvBlocked"/> if the decremented <c>uvRetries</c> reached zero,
    /// otherwise <see cref="WellKnownCtapStatusCodes.UvInvalid"/> (§6.5.5.7.3 step 10, lines 6095-6099).
    /// </summary>
    MatchFailure,

    /// <summary>
    /// The attempt loop concluded with <see cref="CtapBuiltInUvAttemptOutcome.UserActionTimeout"/> →
    /// <see cref="WellKnownCtapStatusCodes.UserActionTimeout"/> (§6.5.5.7.3 step 10.1, line 6093-6094).
    /// </summary>
    UserActionTimeout,

    /// <summary>Every check passed; a fresh <c>pinUvAuthToken</c> was issued for the selected protocol (§6.5.5.7.3 steps 12-17).</summary>
    Success
}

/// <summary>
/// The effect fold-back of a <see cref="CtapIssueUvTokenAction"/>.
/// </summary>
/// <param name="Kind">Which outcome the crypto sequence concluded with.</param>
/// <param name="ProtocolId">The selected protocol, echoed from the action.</param>
/// <param name="AttemptsConsumed">
/// How many attempts the loop made before concluding — the pure fold-back decrements
/// <see cref="CtapAuthenticatorState.UvRetries"/> by exactly this amount on every
/// <paramref name="Kind"/> except <see cref="CtapUvTokenIssuanceOutcomeKind.DecapsulationFailed"/>
/// (which never entered the loop) and <see cref="CtapUvTokenIssuanceOutcomeKind.Success"/> (which resets
/// the counter to <see cref="CtapAuthenticatorState.MaxUvRetries"/> instead).
/// </param>
/// <param name="FreshProtocolOneToken">
/// PIN/UV auth protocol one's freshly reset <c>pinUvAuthToken</c> state — present only when
/// <paramref name="Kind"/> is <see cref="CtapUvTokenIssuanceOutcomeKind.Success"/>. The selected
/// protocol's token has already had <c>beginUsingPinUvAuthToken(userIsPresent: true)</c> applied and its
/// permissions/permissions-RP-ID assigned; the other protocol's token is fresh and unused.
/// </param>
/// <param name="FreshProtocolTwoToken">PIN/UV auth protocol two's freshly reset token state — see <see cref="FreshProtocolOneToken"/>.</param>
/// <param name="EncryptedToken">
/// The selected protocol's freshly issued token, encrypted under the shared secret — ciphertext,
/// non-secret. Present only when <paramref name="Kind"/> is <see cref="CtapUvTokenIssuanceOutcomeKind.Success"/>.
/// </param>
public sealed record UvTokenIssuanceCompleted(
    CtapUvTokenIssuanceOutcomeKind Kind,
    CtapPinUvAuthProtocolId ProtocolId,
    int AttemptsConsumed,
    CtapPinUvAuthTokenState? FreshProtocolOneToken,
    CtapPinUvAuthTokenState? FreshProtocolTwoToken,
    ReadOnlyMemory<byte>? EncryptedToken): CtapAuthenticatorInput;

/// <summary>
/// An <c>authenticatorReset</c> (<c>0x07</c>) request. The command takes no parameters at all — no
/// request-parameter table, no <c>subCommand</c> — so this input carries only the precomputed fact its
/// pure transition needs to enforce the power-up window.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorReset">
/// CTAP 2.3, section 6.6: authenticatorReset (0x07)</see>.
/// </remarks>
/// <param name="Now">
/// The time this command was received, read once from the simulator's threaded <see cref="TimeProvider"/>
/// before this input was built — compared against <see cref="CtapAuthenticatorState.PoweredOnAt"/> for
/// the 10-second power-up-window check (CTAP 2.3, section 6.6, lines 6365-6366/6374). The pure transition
/// never reads a clock itself.
/// </param>
/// <param name="Pool">
/// The memory pool available to this command, threaded from <see cref="Ctap2TransceiveDelegate"/>'s own
/// pool parameter before this input was built — the value <see cref="CtapAuthenticatorState.FactoryReset"/>
/// rents the restored <see cref="CtapAuthenticatorState.SerializedLargeBlobArray"/> from (R7: the
/// array's restoration is entropy-free, so it needs no <see cref="Ctap.Authenticator.Automata.CtapAction"/>
/// round-trip — only a pool reference the pure transition graph has nowhere else to obtain, mirroring
/// <see cref="MakeCredentialRequested.SelectedAlgorithm"/>'s own "precompute outside, use inside"
/// precedent for a composition-time dependency the pure transition cannot construct itself).
/// </param>
public sealed record ResetRequested(DateTimeOffset Now, MemoryPool<byte> Pool): CtapAuthenticatorInput;

/// <summary>
/// The effect fold-back of a <see cref="CtapFactoryResetKeyMaterialAction"/>: a freshly minted
/// key-agreement key pair and a freshly minted, not-in-use <c>pinUvAuthToken</c> for each PIN/UV auth
/// protocol — a factory reset's entropy-consuming half, structurally a superset of
/// <see cref="PinUvAuthTokensReset"/>'s own two-token shape (CTAP 2.3, line 6138: the
/// <c>pinUvAuthToken</c> "is generated afresh at power-on and reset").
/// </summary>
/// <param name="FreshProtocolOneKeyPair">PIN/UV auth protocol one's freshly minted key-agreement key pair.</param>
/// <param name="FreshProtocolTwoKeyPair">PIN/UV auth protocol two's freshly minted key-agreement key pair.</param>
/// <param name="FreshProtocolOneToken">PIN/UV auth protocol one's freshly minted token state.</param>
/// <param name="FreshProtocolTwoToken">PIN/UV auth protocol two's freshly minted token state.</param>
public sealed record AuthenticatorResetKeyMaterialMinted(
    CtapPinUvAuthKeyAgreementKeyPair FreshProtocolOneKeyPair,
    CtapPinUvAuthKeyAgreementKeyPair FreshProtocolTwoKeyPair,
    CtapPinUvAuthTokenState FreshProtocolOneToken,
    CtapPinUvAuthTokenState FreshProtocolTwoToken): CtapAuthenticatorInput;

/// <summary>
/// An <c>authenticatorBioEnrollment</c> (<c>0x09</c>) request, already CBOR-decoded by
/// <see cref="CtapAuthenticatorSimulator"/>.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorBioEnrollment">
/// CTAP 2.3, section 6.7: authenticatorBioEnrollment (0x09)</see>. The token-free trio
/// (<c>getModality</c>, <c>getFingerprintSensorInfo</c>, <c>cancelCurrentEnrollment</c>) is served
/// without any <c>pinUvAuthToken</c>; every be-permission-gated subcommand
/// (<c>enrollBegin</c>/<c>enrollCaptureNextSample</c>/<c>enumerateEnrollments</c>/
/// <c>setFriendlyName</c>/<c>removeEnrollment</c>) runs the full preamble/verify/permission ladder
/// against the live fingerprint template store (R12).
/// </remarks>
/// <param name="Request">The decoded request.</param>
/// <param name="Now">
/// The time this command was received, read once from the simulator's threaded
/// <see cref="TimeProvider"/> before this input was built, mirroring <see cref="CredentialManagementRequested.Now"/>
/// — the value a presented <c>pinUvAuthToken</c>'s usage-timer expiry
/// (<see cref="CtapPinUvAuthTokenState.EvaluateExpiry"/>) is evaluated against ahead of trusting it, and
/// the stamp a successful verify writes into the token's <see cref="CtapPinUvAuthTokenState.LastUsedAt"/>.
/// The pure transition never reads a clock itself.
/// </param>
public sealed record BioEnrollmentRequested(CtapBioEnrollmentRequest Request, DateTimeOffset Now): CtapAuthenticatorInput;

/// <summary>
/// The effect fold-back of a <see cref="CtapBeginBioEnrollmentCaptureAction"/>: a freshly minted
/// template identifier and its first sample capture's outcome, produced by <c>enrollBegin</c>'s own
/// effectful step (CTAP 2.3 §6.7.4, steps 8-9).
/// </summary>
/// <param name="TemplateId">
/// The newly minted template identifier (CTAP 2.3 §6.7.4, step 8), drawn from the simulator's entropy
/// provider exactly the way a fresh <see cref="CredentialId"/> is minted. Owned by this input; ownership
/// transfers to a new <see cref="CtapRememberedBioEnrollmentState"/> once the pure transition folds this
/// back.
/// </param>
/// <param name="LastEnrollSampleStatus">
/// The first sample's capture outcome, one of <see cref="WellKnownCtapLastEnrollSampleStatuses"/> — a
/// response FIELD value, never a protocol error (bio scout Finding 9).
/// </param>
public sealed record BioEnrollmentCaptureStarted(BioEnrollmentTemplateId TemplateId, int LastEnrollSampleStatus): CtapAuthenticatorInput;

/// <summary>
/// The effect fold-back of a <see cref="CtapContinueBioEnrollmentCaptureAction"/>: the
/// in-progress enrollment's next sample capture outcome, produced by <c>enrollCaptureNextSample</c>'s own
/// effectful step (CTAP 2.3 §6.7.4).
/// </summary>
/// <param name="LastEnrollSampleStatus">
/// The captured sample's outcome, one of <see cref="WellKnownCtapLastEnrollSampleStatuses"/> — a response
/// FIELD value, never a protocol error (bio scout Finding 9). The template identifier itself is not
/// echoed here: the pure transition already knows it from <see cref="CtapAuthenticatorState.RememberedBioEnrollment"/>,
/// matched against the request before this action was ever declared.
/// </param>
public sealed record BioEnrollmentSampleCaptured(int LastEnrollSampleStatus): CtapAuthenticatorInput;

/// <summary>
/// An <c>authenticatorLargeBlobs</c> (<c>0x0C</c>) request, already CBOR-decoded by
/// <see cref="CtapAuthenticatorSimulator"/>.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorLargeBlobs">
/// CTAP 2.3, section 6.10: authenticatorLargeBlobs (0x0C)</see>. <c>get</c> is fully served
/// unauthenticated (a substring of the already-seeded <see cref="CtapAuthenticatorState.SerializedLargeBlobArray"/>);
/// <c>set</c> runs the complete §6.10.2 algorithm — the R5 conditional token gate, the volatile
/// <c>expectedLength</c>/<c>expectedNextOffset</c> state machine, and the commit-time integrity check —
/// via <see cref="CtapVerifyLargeBlobsTokenAction"/>/<see cref="CtapCommitLargeBlobArrayAction"/>'s own
/// fold-back inputs.
/// </remarks>
/// <param name="Request">The decoded request.</param>
/// <param name="Now">
/// The time this command was received, read once from the simulator's threaded
/// <see cref="TimeProvider"/> before this input was built, mirroring <see cref="CredentialManagementRequested.Now"/>
/// — the value the R5 gate's presented <c>pinUvAuthToken</c> usage-timer expiry check is evaluated
/// against ahead of trusting it, and the stamp a successful verify writes into the token's
/// <see cref="CtapPinUvAuthTokenState.LastUsedAt"/>.
/// </param>
public sealed record LargeBlobsRequested(CtapLargeBlobsRequest Request, DateTimeOffset Now): CtapAuthenticatorInput;

/// <summary>
/// The effect fold-back of a <see cref="CtapCommitLargeBlobArrayAction"/>: whether the appended fragment
/// completed the pending serialized large-blob array and, if so, whether its commit-time integrity check
/// passed (CTAP 2.3 §6.10.2, lines 7659-7671).
/// </summary>
/// <param name="IsComplete">
/// <see langword="true"/> once the pending buffer's length has reached <paramref name="ExpectedLength"/>
/// (line 7663); <see langword="false"/> when more fragments are still needed ("Await further writes",
/// line 7678), in which case <paramref name="IsIntegrityValid"/>/<paramref name="CommittedArray"/> are
/// unused.
/// </param>
/// <param name="PendingBuffer">
/// The still-in-progress pending buffer to remember for the next fragment, owned — present only when
/// <paramref name="IsComplete"/> is <see langword="false"/>; <see langword="null"/> once the sequence has
/// concluded (committed or failed integrity), since the executor has already consumed or discarded it.
/// </param>
/// <param name="PendingNextOffset">
/// The pending buffer's new length after this fragment — the next remembered <c>expectedNextOffset</c>
/// when <paramref name="IsComplete"/> is <see langword="false"/>; unused otherwise.
/// </param>
/// <param name="ExpectedLength">Echoed from <see cref="CtapCommitLargeBlobArrayAction.ExpectedLength"/> — the remembered sequence's fixed total length.</param>
/// <param name="AuthenticatingPinUvAuthProtocol">
/// Echoed from <see cref="CtapCommitLargeBlobArrayAction.AuthenticatingPinUvAuthProtocol"/> — threaded
/// into a still-in-progress <see cref="CtapRememberedLargeBlobWriteState"/> unchanged.
/// </param>
/// <param name="IsIntegrityValid">
/// <see langword="true"/> when the completed buffer's trailing 16 bytes equal
/// <c>LEFT(SHA-256(preceding bytes), 16)</c> (line 7666); meaningless when <paramref name="IsComplete"/>
/// is <see langword="false"/>.
/// </param>
/// <param name="CommittedArray">
/// The completed, integrity-verified serialized large-blob array, ready to adopt as the new
/// <see cref="CtapAuthenticatorState.SerializedLargeBlobArray"/> — present only when
/// <paramref name="IsComplete"/> and <paramref name="IsIntegrityValid"/> are both <see langword="true"/>;
/// <see langword="null"/> otherwise (the executor has already disposed the pending buffer on an
/// integrity failure, since no domain wrapper ever adopts it).
/// </param>
public sealed record CtapLargeBlobArrayCommitAttempted(
    bool IsComplete,
    IMemoryOwner<byte>? PendingBuffer,
    int PendingNextOffset,
    int ExpectedLength,
    CtapPinUvAuthProtocolId? AuthenticatingPinUvAuthProtocol,
    bool IsIntegrityValid,
    PooledMemory? CommittedArray): CtapAuthenticatorInput;

/// <summary>
/// The effect fold-back of a <see cref="CtapCollectUserPresenceAction"/>: the injected
/// <see cref="SimulateUserPresenceDelegate"/>'s decision and the instant it was collected (CTAP 2.3
/// :2840). The interrupted command's own continuation is not carried here — it lives on
/// <see cref="CtapAuthenticatorState.PendingUserPresenceWait"/>, armed before the collect action was
/// declared, so this same fold-back shape resumes both the initial synchronous collection and every
/// later <see cref="UserPresencePollRequested"/> re-declaration unchanged.
/// </summary>
/// <param name="Decision">The collected decision.</param>
/// <param name="Now">
/// The time this decision was collected, read once from the simulator's threaded
/// <see cref="TimeProvider"/> by the executor — the pure transition never reads a clock itself.
/// </param>
public sealed record UserPresenceDecisionCollected(CtapUserPresenceDecision Decision, DateTimeOffset Now): CtapAuthenticatorInput;

/// <summary>
/// A platform poll for a parked <c>authenticatorMakeCredential</c>/<c>authenticatorGetAssertion</c>
/// user-presence wait (the NFC <c>NFCCTAP_GETRESPONSE</c> polling instruction's authenticator-side
/// model, CTAP 2.3 :10818). Consumed only by <see cref="CtapAuthenticatorSimulator.PollDeferredTransceiveAsync"/>;
/// fed to the automaton only when <see cref="CtapAuthenticatorState.PendingUserPresenceWait"/> is
/// non-null, since the pure transition itself never throws.
/// </summary>
/// <param name="Now">
/// The time this poll arrived, read once from the simulator's threaded <see cref="TimeProvider"/>
/// before this input was built — compared against <see cref="CtapPendingUserPresenceState.ArmedAt"/> for
/// the :2840 timeout check. The pure transition never reads a clock itself.
/// </param>
public sealed record UserPresencePollRequested(DateTimeOffset Now): CtapAuthenticatorInput;

/// <summary>
/// A platform cancel of a parked <c>authenticatorMakeCredential</c>/<c>authenticatorGetAssertion</c>
/// user-presence wait (the NFC <c>NFCCTAP_GETRESPONSE</c> cancel variant's authenticator-side model,
/// CTAP 2.3 :10821). Consumed only by <see cref="CtapAuthenticatorSimulator.CancelDeferredTransceiveAsync"/>;
/// fed to the automaton only when <see cref="CtapAuthenticatorState.PendingUserPresenceWait"/> is
/// non-null, since the pure transition itself never throws.
/// </summary>
/// <param name="Now">
/// The time this cancel arrived, read once from the simulator's threaded <see cref="TimeProvider"/>
/// before this input was built. The pure transition never reads a clock itself.
/// </param>
public sealed record UserPresenceCancelRequested(DateTimeOffset Now): CtapAuthenticatorInput;
