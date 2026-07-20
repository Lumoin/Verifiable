using System;
using System.Buffers;
using System.Collections.Generic;
using System.Collections.Immutable;
using Verifiable.Cryptography;
using Verifiable.Foundation.Automata;
using Verifiable.JCose;

namespace Verifiable.Fido2.Ctap.Authenticator.Automata;

/// <summary>
/// Base type for the effectful actions a CTAP2 authenticator command transition can declare. A
/// <see cref="CtapAction"/> is produced by the pure transition function as part of the next state
/// (carried in <see cref="CtapAuthenticatorState.NextAction"/>); the effectful loop in
/// <see cref="CtapAuthenticatorSimulator"/> dispatches it to the injected credential-signing backend and
/// entropy provider, then feeds the result back as the next input.
/// </summary>
/// <remarks>
/// Wave 1's single command (<c>authenticatorGetInfo</c>) declared no effects and left
/// <see cref="NullAction.Instance"/> in place throughout. <c>authenticatorMakeCredential</c> and
/// <c>authenticatorGetAssertion</c> are the first commands that need one, mirroring
/// <c>Verifiable.Tpm.Automata.TpmAction</c>'s role in <c>Verifiable.Tpm.Automata.TpmSimulator</c>.
/// </remarks>
public abstract record CtapAction: PdaAction;

/// <summary>
/// Declares that the simulator must consult the injected <see cref="SimulateUserPresenceDelegate"/> for a
/// user-presence decision before continuing an <c>authenticatorMakeCredential</c>/
/// <c>authenticatorGetAssertion</c> that requires evidence of user interaction (CTAP 2.3 :2840). Emitted
/// by the pure transition once every earlier pure pre-check has passed, and declared again — unchanged —
/// by <c>UserPresencePollRequested</c>'s own handling while a wait remains parked; the effectful loop
/// folds the seam's answer back as a <see cref="UserPresenceDecisionCollected"/> input. Carries no fields:
/// the continuation to resume once a decision arrives lives on
/// <see cref="CtapAuthenticatorState.PendingUserPresenceWait"/>, armed by the transition BEFORE this
/// action is ever declared, so re-declaring this SAME action across a poll needs no re-supplied
/// continuation — mirroring <see cref="CtapBeginBioEnrollmentCaptureAction"/>'s own no-fields shape.
/// </summary>
public sealed record CtapCollectUserPresenceAction: CtapAction;

/// <summary>
/// Declares that the simulator must mint a fresh credential key pair before the next transition. Emitted
/// by the <c>authenticatorMakeCredential</c> transition once every non-effectful validation step has
/// passed; the effectful loop draws a fresh credential identifier from the injected entropy provider,
/// mints the key pair through the injected <see cref="CtapCredentialSigningBackend"/>, assembles
/// <c>attestedCredentialData</c> and the <c>authData</c> response bytes, builds <c>attStmt</c> per
/// <see cref="AttestationFormat"/> — signing a packed self-attestation with the just-minted key through
/// <see cref="Fido2CredentialSigner.SignAssertionAsync"/> when it resolves to
/// <see cref="CtapAttestationFormatChoice.PackedSelf"/> — and feeds the completed response and store
/// record back as a <see cref="CredentialMinted"/> input.
/// </summary>
/// <remarks>
/// The action carries every field the effect needs to build the response and the persisted
/// <see cref="CtapCredentialRecord"/> — the relying party identifier, the (borrowed, still-owned-by-the-
/// request) user handle and display fields, the algorithm chosen by the pubKeyCredParams selection loop,
/// the resolved <c>rk</c> value, and the client data hash and attestation format the response's
/// <c>attStmt</c> construction needs — so no creation context has to be stashed on
/// <see cref="CtapAuthenticatorState"/> across the effect.
/// </remarks>
/// <param name="RpId">The relying party identifier the new credential is scoped to.</param>
/// <param name="UserId">
/// The user handle the new credential is associated with, borrowed from the still-alive decoded request
/// (not yet copied into a store-owned instance — the effect copies it once minting succeeds).
/// </param>
/// <param name="UserName">The user name supplied at registration, or <see langword="null"/> if none was given.</param>
/// <param name="UserDisplayName">The user display name supplied at registration, or <see langword="null"/> if none was given.</param>
/// <param name="Algorithm">The COSE algorithm identifier chosen by the pubKeyCredParams selection loop.</param>
/// <param name="ResidentKey">Whether the credential being created is to be discoverable (the resolved <c>rk</c> option value).</param>
/// <param name="UserPresent">Whether the <c>up</c> flag must be set in the response's <c>authData</c>.</param>
/// <param name="UserVerified">Whether the <c>uv</c> flag must be set in the response's <c>authData</c>.</param>
/// <param name="ClientDataHash">
/// The request's client data hash, borrowed from the still-alive decoded request (not owned by this
/// action) — the message a packed self-attestation signature covers alongside the freshly built
/// <c>authData</c>. Unread when <see cref="AttestationFormat"/> resolves to either <c>none</c> outcome.
/// </param>
/// <param name="AttestationFormat">
/// The attestation statement shape the effect must produce, resolved by the pure transition from the
/// request's <c>attestationFormatsPreference</c> (CTAP 2.3 section 6.1.2, step 17).
/// </param>
/// <param name="CredProtectLevel">
/// The <c>credProtect</c> level to persist with the new credential (CTAP 2.3 §12.1) — ALWAYS present,
/// regardless of <see cref="CredProtectRequested"/>, since every credential carries a level from the
/// moment it is minted. Not itself an authData-output signal: see <see cref="CredProtectRequested"/> for
/// whether the effect also echoes this value in the extensions output map.
/// </param>
/// <param name="CredProtectRequested">
/// Whether the mc request carried a valid <c>credProtect</c> entry — the effect emits the
/// <c>credProtect</c> authData extensions-output key (value <see cref="CredProtectLevel"/>) iff this is
/// <see langword="true"/> (CTAP 2.3 §12.1 line 12648's MUST NOT: no unsolicited output).
/// </param>
/// <param name="MinPinLengthOutputValue">
/// The <c>minPinLength</c> authData extensions-output value to emit, or <see langword="null"/> to omit
/// the key entirely (requested but the RP is unauthorized, or not requested at all — CTAP 2.3 §12.5's
/// own authorized/not-authorized switch collapses to this single nullable value for the effect).
/// </param>
/// <param name="HmacSecretRequested">
/// Whether the mc request's <c>hmac-secret</c> extension value was the literal <see langword="true"/>
/// (CTAP 2.3 §12.7, snapshot line 13194's "has sent" gate, RULED as "sent with the value
/// <see langword="true"/>" — contract R3: a request of <see langword="false"/> is treated as
/// not-requested, since answering it with an affirmative annotation would be actively misleading). The
/// effect mints <see cref="CtapCredentialRecord.CredRandomWithUV"/>/<see cref="CtapCredentialRecord.CredRandomWithoutUV"/>
/// UNCONDITIONALLY regardless of this flag's value (snapshot line 13192's SHOULD, adopted); this flag
/// controls only whether the mc authData extensions map's <c>"hmac-secret"</c> key is emitted (never
/// <see langword="false"/> — snapshot lines 13204-13209 are antecedent-false-by-construction in this
/// profile, since CredRandom generation never fails).
/// </param>
/// <param name="LargeBlobKeyRequested">
/// Whether the mc request's <c>largeBlobKey</c> extension resolved to <see langword="true"/> with
/// <see cref="ResidentKey"/> also <see langword="true"/> (CTAP 2.3 §12.3, lines 12847/12849 — both
/// already validated by the pure transition before this action is declared). The effect mints a fresh
/// 32-byte pooled key from the entropy provider iff this is <see langword="true"/>, stores it on the new
/// <see cref="CtapCredentialRecord"/>, and echoes it as the mc response's TOP-LEVEL <c>largeBlobKey</c>
/// (<c>0x05</c>) member.
/// </param>
/// <param name="HmacSecretMc">
/// The resolved <c>hmac-secret-mc</c> crypto request (CTAP 2.3 §12.8), already assembled by the pure
/// transition from the mc request's compound extension input, or <see langword="null"/> when the
/// request carried no <c>hmac-secret-mc</c> extension. The R6 pairing gate (<c>hmac-secret-mc</c>
/// present while <see cref="HmacSecretRequested"/> is <see langword="false"/> is a request-shape error,
/// snapshot line 13370, rejected before this action is ever declared) has already run by the time this
/// field is non-null. The effect completes this partial request with the freshly minted
/// <see cref="CtapCredentialRecord.CredRandomWithUV"/>/<see cref="CtapCredentialRecord.CredRandomWithoutUV"/>
/// pair (which does not exist until the SAME effect mints it) and runs the SAME crypto routine
/// <see cref="CtapSignAssertionAction.HmacSecret"/>'s own effect runs (contract R6, snapshot line
/// 13402's pure delegation), keyed off THIS mint's own <see cref="UserVerified"/> bit.
/// </param>
public sealed record CtapGenerateCredentialKeyAction(
    string RpId,
    UserHandle UserId,
    string? UserName,
    string? UserDisplayName,
    int Algorithm,
    bool ResidentKey,
    bool UserPresent,
    bool UserVerified,
    DigestValue ClientDataHash,
    CtapAttestationFormatChoice AttestationFormat,
    int CredProtectLevel,
    bool CredProtectRequested,
    int? MinPinLengthOutputValue,
    bool HmacSecretRequested,
    bool LargeBlobKeyRequested,
    CtapMakeCredentialHmacSecretMcRequest? HmacSecretMc = null): CtapAction;

/// <summary>
/// The resolved inputs <see cref="CtapGenerateCredentialKeyAction"/>'s effect needs to run the
/// <c>hmac-secret-mc</c> delegation (CTAP 2.3 §12.8, snapshot line 13402: "the same as the hmac secret
/// extension's getAssertion processing") — every field <see cref="CtapGetAssertionHmacSecretRequest"/>
/// carries EXCEPT the CredRandom pair, which does not exist until the SAME
/// <c>authenticatorMakeCredential</c> effect mints it (contract R2): the effect combines this partial
/// request with the freshly minted pair before delegating to the shared crypto routine.
/// </summary>
/// <param name="ProtocolId">
/// The PIN/UV auth protocol this hmac-secret-mc request uses — the compound input's own
/// <c>pinUvAuthProtocol</c> value if present, or protocol one by the snapshot line 13279 default
/// otherwise; already validated supported by the pure transition before this action is declared.
/// </param>
/// <param name="OwnPrivateKey"><see cref="ProtocolId"/>'s key-agreement private key, borrowed from <see cref="CtapAuthenticatorState"/>.</param>
/// <param name="PeerKeyAgreement">The platform's ephemeral key-agreement COSE_Key (the compound input's <c>keyAgreement</c> member).</param>
/// <param name="SaltEnc">The compound input's <c>saltEnc</c> member: the encrypted one- or two-salt plaintext.</param>
/// <param name="SaltAuth">The compound input's <c>saltAuth</c> member: <c>authenticate(sharedSecret, saltEnc)</c>, verified before any decrypt is attempted.</param>
public sealed record CtapMakeCredentialHmacSecretMcRequest(
    CtapPinUvAuthProtocolId ProtocolId,
    PrivateKeyMemory OwnPrivateKey,
    CoseKey PeerKeyAgreement,
    ReadOnlyMemory<byte> SaltEnc,
    ReadOnlyMemory<byte> SaltAuth);

/// <summary>
/// Declares that the simulator must sign an assertion with a stored credential's private key before the
/// next transition. Emitted by the <c>authenticatorGetAssertion</c> transition once a credential has been
/// resolved from the store; the effectful loop builds the signed-over <c>authData</c>, signs
/// <c>authData ‖ clientDataHash</c> through <see cref="Fido2CredentialSigner.SignAssertionAsync"/>, and
/// feeds the completed response back as an <see cref="AssertionSigned"/> input.
/// </summary>
/// <remarks>
/// <see cref="CredentialId"/> and <see cref="CredentialKey"/> are borrowed from the store's own
/// <see cref="CtapCredentialRecord"/> — the effect neither copies nor disposes them, since the record
/// continues to own them for the credential's whole lifetime.
/// </remarks>
/// <param name="RpId">The relying party identifier the assertion is scoped to.</param>
/// <param name="CredentialId">The resolved credential's identifier, borrowed from the store.</param>
/// <param name="CredentialKey">The resolved credential's private key, borrowed from the store.</param>
/// <param name="Algorithm">The resolved credential's COSE algorithm identifier.</param>
/// <param name="NewSignCount">
/// The signature counter value to embed in the signed <c>authData</c> and persist back into the store —
/// the stored value incremented by one.
/// </param>
/// <param name="UserPresent">Whether the <c>up</c> flag must be set in the signed <c>authData</c>.</param>
/// <param name="UserVerified">Whether the <c>uv</c> flag must be set in the signed <c>authData</c>.</param>
/// <param name="ClientDataHash">The client data hash the assertion signature covers alongside <c>authData</c>.</param>
/// <param name="ResponseUser">
/// The <c>user</c> member to include in the response, or <see langword="null"/> to omit it — resolved by
/// the transition from whether the request was satisfied via <c>allowList</c> (omitted) or a resident
/// lookup (included, Id only, per CTAP 2.3 section 6.2's response table).
/// </param>
/// <param name="NumberOfCredentials">
/// The <c>numberOfCredentials</c> value to embed in the response, or <see langword="null"/> to omit the
/// member — set only on the first response of a multi-account <c>authenticatorGetAssertion</c> (more than
/// one applicable credential located, <c>allowList</c> absent); every single-credential
/// <c>authenticatorGetAssertion</c> response and every <c>authenticatorGetNextAssertion</c> response
/// omits it (CTAP 2.3, section 6.2's response table and section 6.3's own response shape).
/// </param>
/// <param name="RememberOnCompletion">
/// When this sign completes the FIRST response of a multi-account <c>authenticatorGetAssertion</c>, the
/// information the effect needs to mint a fresh, independently owned
/// <see cref="CtapRememberedGetAssertionState"/> for <c>authenticatorGetNextAssertion</c> to consume;
/// <see langword="null"/> for a single-credential <c>authenticatorGetAssertion</c> or any
/// <c>authenticatorGetNextAssertion</c> sign, neither of which mints new remembered state (a
/// getNextAssertion sign advances the existing remembered state directly in the pure transition, since
/// that update needs no new pooled memory).
/// </param>
/// <param name="LargeBlobKey">
/// The resolved credential's stored <c>largeBlobKey</c>, borrowed from its
/// <see cref="CtapCredentialRecord"/> — already resolved by the pure transition to
/// <see langword="null"/> unless BOTH the ga request's <c>largeBlobKey</c> extension was <c>true</c> AND
/// the credential carries a key (CTAP 2.3 §12.3, line 12867). The effect echoes this value verbatim as
/// the ga response's TOP-LEVEL <c>largeBlobKey</c> (<c>0x07</c>) member — no further lookup or decision
/// needed at the effect layer.
/// </param>
/// <param name="HmacSecret">
/// The resolved <c>hmac-secret</c> crypto request (CTAP 2.3 §12.7), already assembled by the pure
/// transition from the ga request's compound extension input plus the resolved credential's own
/// <see cref="CtapCredentialRecord.CredRandomWithUV"/>/<see cref="CtapCredentialRecord.CredRandomWithoutUV"/>
/// pair, or <see langword="null"/> when the request carried no <c>hmac-secret</c> extension (or this
/// sign is an <c>authenticatorGetNextAssertion</c> continuation — the compound input belongs to the
/// ORIGINATING <c>authenticatorGetAssertion</c> request alone; that command carries no parameters of its
/// own to re-supply it, so this profile does not replay hmac-secret across a multi-account sequence).
/// The effect runs the full CTAP 2.3 §12.7 processing algorithm's crypto half (steps 4-9, contract R4)
/// exactly ONCE, computed after <see cref="UserVerified"/> is already resolved and threaded straight
/// into the signed authData — never recomputed (trap 5).
/// </param>
public sealed record CtapSignAssertionAction(
    string RpId,
    CredentialId CredentialId,
    PrivateKey CredentialKey,
    int Algorithm,
    uint NewSignCount,
    bool UserPresent,
    bool UserVerified,
    DigestValue ClientDataHash,
    CtapPublicKeyCredentialUserEntity? ResponseUser,
    int? NumberOfCredentials,
    CtapRememberGetAssertionRequest? RememberOnCompletion,
    ReadOnlyMemory<byte>? LargeBlobKey,
    CtapGetAssertionHmacSecretRequest? HmacSecret = null): CtapAction;

/// <summary>
/// The resolved inputs <see cref="CtapSignAssertionAction"/>'s effect needs to run CTAP 2.3 §12.7's
/// <c>hmac-secret</c> processing algorithm's crypto half (steps 4-9, snapshot lines 13292-13339): the
/// authenticator's own key-agreement key pair for <see cref="ProtocolId"/> (already selected by the
/// pure transition, mirroring <c>CtapIssuePinTokenAction.OwnPrivateKey</c>'s own borrowed-from-state
/// shape), the platform's ephemeral key and encrypted salts straight off the wire, and the resolved
/// credential's own CredRandom pair — CredRandom SELECTION (which of the two the effect uses) is not
/// decided here: it depends on THIS response's own <c>uv</c> bit, known only once the effect runs
/// (<see cref="CtapSignAssertionAction.UserVerified"/>), so both values travel and the effect chooses
/// (contract R4 step 7, trap 4).
/// </summary>
/// <param name="ProtocolId">
/// The PIN/UV auth protocol this hmac-secret request uses — the request's own <c>pinUvAuthProtocol</c>
/// value if present, or protocol one by the snapshot line 13279 default otherwise; already validated
/// supported by the pure transition before this action was declared.
/// </param>
/// <param name="OwnPrivateKey">
/// <see cref="ProtocolId"/>'s key-agreement private key, borrowed from <see cref="CtapAuthenticatorState"/>.
/// </param>
/// <param name="PeerKeyAgreement">The platform's ephemeral key-agreement COSE_Key (the request's <c>hmac-secret</c> extension's <c>keyAgreement</c> member).</param>
/// <param name="SaltEnc">The request's <c>saltEnc</c> member: the encrypted one- or two-salt plaintext.</param>
/// <param name="SaltAuth">The request's <c>saltAuth</c> member: <c>authenticate(sharedSecret, saltEnc)</c>, verified before any decrypt is attempted (trap 2).</param>
/// <param name="CredRandomWithUV">The resolved credential's <see cref="CtapCredentialRecord.CredRandomWithUV"/>, borrowed — selected when the response's <c>uv</c> bit is set.</param>
/// <param name="CredRandomWithoutUV">The resolved credential's <see cref="CtapCredentialRecord.CredRandomWithoutUV"/>, borrowed — selected when the response's <c>uv</c> bit is clear.</param>
public sealed record CtapGetAssertionHmacSecretRequest(
    CtapPinUvAuthProtocolId ProtocolId,
    PrivateKeyMemory OwnPrivateKey,
    CoseKey PeerKeyAgreement,
    ReadOnlyMemory<byte> SaltEnc,
    ReadOnlyMemory<byte> SaltAuth,
    IMemoryOwner<byte> CredRandomWithUV,
    IMemoryOwner<byte> CredRandomWithoutUV);

/// <summary>
/// The information <see cref="CtapSignAssertionAction"/>'s effect needs to mint a fresh
/// <see cref="CtapRememberedGetAssertionState"/> once the first response of a multi-account
/// <c>authenticatorGetAssertion</c> has been signed — everything except the independently pooled client
/// data hash copy, which the effect alone can allocate (the pure transition has no memory pool).
/// </summary>
/// <param name="ApplicableCredentialIds">
/// The complete applicable-credential list located by the <c>authenticatorGetAssertion</c> transition,
/// most-recently-created first.
/// </param>
/// <param name="UserPresent">The <c>up</c> option resolution to remember for every following <c>authenticatorGetNextAssertion</c>.</param>
/// <param name="UserVerified">
/// The <c>uv</c> bit the originating <c>authenticatorGetAssertion</c> resolved (CTAP 2.3, section 6.2.2,
/// step 6.1's <c>getUserVerifiedFlagValue()</c> result), remembered for every following
/// <c>authenticatorGetNextAssertion</c> response in the sequence. <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetNextAssertion">
/// CTAP 2.3, section 6.3</see>: "On success, the authenticator returns the same structure as returned by
/// the authenticatorGetAssertion method" — a continuation whose originating call verified user presence
/// AND user verification must itself report <c>uv=1</c>, not silently downgrade to <c>uv=0</c>.
/// </param>
/// <param name="StartedAt">
/// The time this <c>authenticatorGetAssertion</c> command was processed, precomputed from the simulator's
/// threaded <see cref="TimeProvider"/> before the pure transition ran — the sequence's initial
/// <see cref="CtapRememberedGetAssertionState.LastActivityAt"/> value.
/// </param>
/// <param name="AuthenticatingPinUvAuthProtocol">
/// The PIN/UV auth protocol whose <c>pinUvAuthToken</c> authenticated the originating
/// <c>authenticatorGetAssertion</c>, or <see langword="null"/> when the series was not token-authenticated
/// (no <c>pinUvAuthParam</c> presented, or the authenticator was not protected by any form of user
/// verification). CTAP 2.3, section 6, item 3 (line 2873): "An authenticator MUST discard the state for a
/// stateful command command if the pinUvAuthToken that authenticated the state initializing command
/// expires" — remembered for every following <c>authenticatorGetNextAssertion</c> to fold that token's
/// own expiry into the discard decision.
/// </param>
/// <param name="LargeBlobKeyRequested">
/// Whether the originating <c>authenticatorGetAssertion</c> request's <c>largeBlobKey</c> extension
/// resolved to <see langword="true"/> (CTAP 2.3 §12.3) — remembered for every following
/// <c>authenticatorGetNextAssertion</c> in the sequence, since that command carries no parameters of its
/// own to re-request the extension with. Each continuation still emits the <c>largeBlobKey</c> response
/// member only for its OWN resolved credential (never a stale value borrowed from the first response).
/// </param>
public sealed record CtapRememberGetAssertionRequest(
    IReadOnlyList<CredentialId> ApplicableCredentialIds,
    bool UserPresent,
    bool UserVerified,
    DateTimeOffset StartedAt,
    CtapPinUvAuthProtocolId? AuthenticatingPinUvAuthProtocol,
    bool LargeBlobKeyRequested);

/// <summary>
/// Declares that the simulator must compute the <c>getPublicKey()</c> view of a per-protocol
/// key-agreement key pair before completing an <c>authenticatorClientPIN</c> <c>getKeyAgreement</c>
/// (<c>0x02</c>) subcommand response. Emitted once the <c>authenticatorClientPIN</c> transition has
/// validated <c>subCommand</c>/<c>pinUvAuthProtocol</c>; the effectful loop resolves a
/// <see cref="CtapPinUvAuthProtocol"/> instance for <see cref="ProtocolId"/> and calls
/// <see cref="CtapPinUvAuthProtocol.GetPublicKey"/> against <see cref="OwnPublicKey"/>, folding the
/// result back as a <see cref="ClientPinKeyAgreementComputed"/> input.
/// </summary>
/// <remarks>
/// <see cref="CtapPinUvAuthProtocol.GetPublicKey"/> performs no I/O, reads no time, and draws no
/// randomness — it is EC-point arithmetic over already-known key bytes, resolved through
/// <see cref="CtapPinUvAuthProtocol.CreateDefault"/> — but it is still routed through the effectful
/// loop rather than called inline from the pure transition, mirroring how every other crypto operation
/// in this automaton (credential minting, assertion signing) is declared as an action rather than
/// invoked directly from <c>CtapAuthenticatorTransitions</c>.
/// </remarks>
/// <param name="ProtocolId">Which PIN/UV auth protocol's key-agreement public key to report.</param>
/// <param name="OwnPublicKey">
/// The authenticator's own per-protocol key-agreement public key, borrowed from
/// <see cref="CtapAuthenticatorState"/> — the effect neither copies nor disposes it.
/// </param>
public sealed record CtapComputeKeyAgreementPublicKeyAction(
    CtapPinUvAuthProtocolId ProtocolId,
    PublicKeyMemory OwnPublicKey): CtapAction;

/// <summary>
/// Declares that the simulator must run <c>setPIN</c>'s crypto sequence (CTAP 2.3 §6.5.5.5, lines
/// 5570-5593): <c>decapsulate</c>, <c>verify</c>, <c>decrypt</c>, and — only if every subsequent
/// pure-length/policy check on the decrypted PIN passes — hash it, before completing an
/// <c>authenticatorClientPIN</c> <c>setPIN</c> (<c>0x03</c>) subcommand response. Emitted once every
/// pure pre-check (mandatory parameters, protocol support, "PIN already set", the power-cycle latch)
/// has passed; the effectful loop folds back a <see cref="PinEstablishmentCompleted"/> input.
/// </summary>
/// <param name="ProtocolId">The selected PIN/UV auth protocol.</param>
/// <param name="OwnPrivateKey">
/// The selected protocol's key-agreement private key, borrowed from <see cref="CtapAuthenticatorState"/>.
/// </param>
/// <param name="PeerKeyAgreement">The platform's ephemeral key-agreement COSE_Key (the request's <c>keyAgreement</c> parameter).</param>
/// <param name="PinUvAuthParam">The request's <c>pinUvAuthParam</c>: the signature <c>verify</c> checks.</param>
/// <param name="NewPinEnc">The request's <c>newPinEnc</c>: both the message <c>verify</c> covers and the ciphertext <c>decrypt</c> recovers the new PIN from.</param>
/// <param name="MinPinCodePointLength">
/// The current minimum PIN length in Unicode code points, borrowed from
/// <see cref="CtapAuthenticatorState.MinPinCodePointLength"/> (CTAP 2.3 §6.5.5.5, line 5584: "the
/// authenticator checks the length of newPin against the current minimum PIN length") — the policy
/// threshold <c>setMinPINLength</c> may have raised above its pre-configured default.
/// </param>
public sealed record CtapEstablishPinAction(
    CtapPinUvAuthProtocolId ProtocolId,
    PrivateKeyMemory OwnPrivateKey,
    CoseKey PeerKeyAgreement,
    ReadOnlyMemory<byte> PinUvAuthParam,
    ReadOnlyMemory<byte> NewPinEnc,
    int MinPinCodePointLength): CtapAction;

/// <summary>
/// Declares that the simulator must run <c>changePIN</c>'s crypto sequence (CTAP 2.3 §6.5.5.6, lines
/// 5658-5716): <c>decapsulate</c>, <c>verify</c> over <c>newPinEnc || pinHashEnc</c>, decrypt and
/// constant-time-compare <c>pinHashEnc</c> against the stored PIN hash, then — on a match — decrypt
/// and validate <c>newPinEnc</c> and hash the new PIN, or — on a mismatch — mint a fresh key-agreement
/// key pair for <see cref="ProtocolId"/> (<c>regenerate()</c>, line 5674). Emitted once every pure
/// pre-check has passed; the effectful loop folds back a <see cref="PinChangeCompleted"/> input.
/// </summary>
/// <param name="ProtocolId">The selected PIN/UV auth protocol.</param>
/// <param name="OwnPrivateKey">
/// The selected protocol's key-agreement private key, borrowed from <see cref="CtapAuthenticatorState"/>.
/// </param>
/// <param name="PeerKeyAgreement">The platform's ephemeral key-agreement COSE_Key.</param>
/// <param name="PinUvAuthParam">The request's <c>pinUvAuthParam</c>: the signature <c>verify</c> checks against <c>newPinEnc || pinHashEnc</c>.</param>
/// <param name="NewPinEnc">The request's <c>newPinEnc</c>.</param>
/// <param name="PinHashEnc">The request's <c>pinHashEnc</c>: the encrypted proof of knowledge of the current PIN.</param>
/// <param name="CurrentStoredPin">
/// The authenticator's current stored PIN hash, borrowed from <see cref="CtapAuthenticatorState"/> — the
/// effect compares against it but neither copies nor disposes it.
/// </param>
/// <param name="MinPinCodePointLength">
/// The current minimum PIN length in Unicode code points, borrowed from
/// <see cref="CtapAuthenticatorState.MinPinCodePointLength"/> (CTAP 2.3 §6.5.5.6, line 5698: "the
/// authenticator checks the length of newPin against the current minimum PIN length") — the policy
/// threshold <c>setMinPINLength</c> may have raised above its pre-configured default.
/// </param>
/// <param name="IsForcePinChangeRequired">
/// The current value of <see cref="CtapAuthenticatorState.IsForcePinChangeRequired"/>, borrowed at
/// declare time — gates the line-5700 same-PIN-under-force rejection (CTAP 2.3 §6.11.4's
/// <c>setMinPINLength</c> is the only way this becomes <see langword="true"/>): when
/// <see langword="true"/>, a new PIN whose hash equals the stored current PIN's hash is rejected
/// rather than accepted as a no-op "change".
/// </param>
public sealed record CtapChangePinAction(
    CtapPinUvAuthProtocolId ProtocolId,
    PrivateKeyMemory OwnPrivateKey,
    CoseKey PeerKeyAgreement,
    ReadOnlyMemory<byte> PinUvAuthParam,
    ReadOnlyMemory<byte> NewPinEnc,
    ReadOnlyMemory<byte> PinHashEnc,
    DigestValue CurrentStoredPin,
    int MinPinCodePointLength,
    bool IsForcePinChangeRequired): CtapAction;

/// <summary>
/// Declares that the simulator must run the shared <c>getPinToken</c>/
/// <c>getPinUvAuthTokenUsingPinWithPermissions</c> crypto sequence (CTAP 2.3 §6.5.5.7.1 lines 5873-5915,
/// §6.5.5.7.2 lines 5975-6026): <c>decapsulate</c>, decrypt and constant-time-compare <c>pinHashEnc</c>
/// against the stored PIN hash, then — on a match — mint a fresh <c>pinUvAuthToken</c> for both PIN/UV
/// auth protocols (<c>resetPinUvAuthToken()</c> "for all"), call <c>beginUsingPinUvAuthToken</c> on
/// <see cref="ProtocolId"/>'s fresh token, assign it <see cref="PermissionsToAssign"/>/
/// <see cref="PermissionsRpId"/>, and encrypt it for the response — or, on a mismatch, mint a fresh
/// key-agreement key pair for <see cref="ProtocolId"/> (<c>regenerate()</c>). Emitted once every pure
/// pre-check (including the two subcommands' own differing mandatory-parameter and permission-gating
/// rules) has resolved <see cref="PermissionsToAssign"/>/<see cref="PermissionsRpId"/>; the effectful
/// loop folds back a <see cref="PinTokenIssuanceCompleted"/> input.
/// </summary>
/// <param name="ProtocolId">The selected PIN/UV auth protocol.</param>
/// <param name="OwnPrivateKey">
/// The selected protocol's key-agreement private key, borrowed from <see cref="CtapAuthenticatorState"/>.
/// </param>
/// <param name="PeerKeyAgreement">The platform's ephemeral key-agreement COSE_Key.</param>
/// <param name="PinHashEnc">The request's <c>pinHashEnc</c>: the encrypted proof of knowledge of the current PIN.</param>
/// <param name="CurrentStoredPin">
/// The authenticator's current stored PIN hash, borrowed from <see cref="CtapAuthenticatorState"/> — the
/// effect compares against it but neither copies nor disposes it.
/// </param>
/// <param name="PermissionsToAssign">
/// The permissions bitfield to assign to the issued token — already resolved by the pure pre-check:
/// the default <c>mc|ga</c> (<c>0x03</c>) for <c>getPinToken</c>, or the requested set minus undefined
/// bits for <c>getPinUvAuthTokenUsingPinWithPermissions</c>.
/// </param>
/// <param name="PermissionsRpId">
/// The permissions RP ID to bind the issued token to, or <see langword="null"/> for an unbound token
/// (always <see langword="null"/> for <c>getPinToken</c>, which issues unbound tokens).
/// </param>
/// <param name="Now">
/// The time this command was received, precomputed by the pure transition from the simulator's own
/// threaded <see cref="TimeProvider"/> — the value <c>beginUsingPinUvAuthToken</c> stamps as the fresh
/// token's usage-timer start.
/// </param>
/// <param name="IsForcePinChangeRequired">
/// The current value of <see cref="CtapAuthenticatorState.IsForcePinChangeRequired"/>, borrowed at
/// declare time — when <see langword="true"/>, the executor denies token issuance with
/// <see cref="ForcePinChangeDeniedStatusCode"/> once the current PIN has ALREADY matched and
/// <c>pinRetries</c> has already been reset to maximum, strictly before minting any fresh token (CTAP
/// 2.3 §6.5.5.7.1 line 5904 / §6.5.5.7.2 line 6006 — both checked at the identical position in each
/// subcommand's own step order, immediately after the "set pinRetries to maximum" step and immediately
/// before "create a new pinUvAuthToken").
/// </param>
/// <param name="ForcePinChangeDeniedStatusCode">
/// The status code to reject with when <see cref="IsForcePinChangeRequired"/> denies issuance —
/// <see cref="WellKnownCtapStatusCodes.PinInvalid"/> for <c>getPinToken</c> (CTAP2.0 back-compat, line
/// 5904) or <see cref="WellKnownCtapStatusCodes.PinPolicyViolation"/> for
/// <c>getPinUvAuthTokenUsingPinWithPermissions</c> (the CTAP2.1-correct code, line 6006) — the two
/// subcommands share this one action/executor but answer the identical condition differently.
/// </param>
public sealed record CtapIssuePinTokenAction(
    CtapPinUvAuthProtocolId ProtocolId,
    PrivateKeyMemory OwnPrivateKey,
    CoseKey PeerKeyAgreement,
    ReadOnlyMemory<byte> PinHashEnc,
    DigestValue CurrentStoredPin,
    int PermissionsToAssign,
    string? PermissionsRpId,
    DateTimeOffset Now,
    bool IsForcePinChangeRequired,
    byte ForcePinChangeDeniedStatusCode): CtapAction;

/// <summary>
/// The decoded-request context a <see cref="CtapVerifyPinUvAuthTokenAction"/>'s fold-back needs to
/// resume the command it interrupted. One subclass per command, since
/// <c>authenticatorMakeCredential</c> and <c>authenticatorGetAssertion</c> each complete their own
/// literal remaining step sequence once verification returns (CTAP 2.3 §6.1.2 step 11.1 vs §6.2.2
/// step 6.1 — different literal order, wire-equivalent outcome; see
/// <c>CtapAuthenticatorTransitions.OnMakeCredentialPinUvAuthTokenVerified</c>/
/// <c>OnGetAssertionPinUvAuthTokenVerified</c>).
/// </summary>
public abstract record CtapVerifyPinUvAuthTokenContinuation;

/// <summary>
/// Resumes an interrupted <c>authenticatorMakeCredential</c> once its presented <c>pinUvAuthParam</c>
/// has been verified.
/// </summary>
/// <param name="Requested">
/// The original decoded request and pre-resolved algorithm selection, borrowed unchanged from the
/// input that declared the verify action.
/// </param>
/// <param name="EnterpriseAttestationGranted">
/// The mc Step 9 enterprise-attestation grant decision, computed ONCE in <c>OnMakeCredentialRequested</c>
/// before this verify action was declared, and threaded here so it survives the async verify round trip
/// unchanged (waveep R6, trap 12) — never recomputed once the verify completes.
/// </param>
public sealed record CtapMakeCredentialVerifyContinuation(MakeCredentialRequested Requested, bool EnterpriseAttestationGranted): CtapVerifyPinUvAuthTokenContinuation;

/// <summary>
/// Resumes an interrupted <c>authenticatorGetAssertion</c> once its presented <c>pinUvAuthParam</c>
/// has been verified.
/// </summary>
/// <param name="Requested">
/// The original decoded request, borrowed unchanged from the input that declared the verify action.
/// </param>
public sealed record CtapGetAssertionVerifyContinuation(GetAssertionRequested Requested): CtapVerifyPinUvAuthTokenContinuation;

/// <summary>
/// Resumes an interrupted <c>authenticatorConfig</c> once its presented <c>pinUvAuthParam</c> has been
/// verified.
/// </summary>
/// <param name="Requested">
/// The original decoded request, borrowed unchanged from the input that declared the verify action.
/// </param>
public sealed record CtapAuthenticatorConfigVerifyContinuation(AuthenticatorConfigRequested Requested): CtapVerifyPinUvAuthTokenContinuation;

/// <summary>
/// Declares that the simulator must run CTAP 2.3's state-aware <c>verify</c> composition
/// (<see cref="CtapPinUvAuthTokenVerificationExtensions.VerifyPinUvAuthTokenAsync"/>) over a presented
/// <c>pinUvAuthParam</c> before continuing an interrupted <c>authenticatorMakeCredential</c>/
/// <c>authenticatorGetAssertion</c> (CTAP 2.3 §6.1.2 step 11.1.1 / §6.2.2 step 6.1.1: "Call
/// verify(pinUvAuthToken, clientDataHash, pinUvAuthParam)"). Emitted once the pure transition has
/// determined the authenticator is protected by some form of user verification (CTAP 2.3's own
/// "protected by some form of User Verification" definition) and a <c>pinUvAuthParam</c> is present;
/// the effectful loop folds the boolean result back as a <see cref="PinUvAuthTokenVerified"/> input,
/// which the pure transition dispatches to <see cref="Continuation"/>'s own command-specific remaining
/// sequence.
/// </summary>
/// <param name="ProtocolId">The selected PIN/UV auth protocol, named by the interrupted request's <c>pinUvAuthProtocol</c> parameter.</param>
/// <param name="TokenState">
/// The selected protocol's <c>pinUvAuthToken</c> lifecycle state, borrowed from
/// <see cref="CtapAuthenticatorState"/> AFTER its usage-timer expiry has already been evaluated by the
/// request-arm transition (<see cref="CtapPinUvAuthTokenState.EvaluateExpiry"/>) — never copied; the
/// effect neither disposes nor mutates it.
/// </param>
/// <param name="ClientDataHash">
/// The request's client data hash — the verify message, ALONE (CTAP 2.3 §6.1.2 line 3383 / §6.2.2 line
/// 3969: <c>verify(pinUvAuthToken, clientDataHash, pinUvAuthParam)</c>), never a compound message.
/// </param>
/// <param name="PinUvAuthParam">The request's presented <c>pinUvAuthParam</c>: the signature <c>verify</c> checks.</param>
/// <param name="Continuation">The interrupted command's own decoded-request context to resume once verification completes.</param>
public sealed record CtapVerifyPinUvAuthTokenAction(
    CtapPinUvAuthProtocolId ProtocolId,
    CtapPinUvAuthTokenState TokenState,
    DigestValue ClientDataHash,
    ReadOnlyMemory<byte> PinUvAuthParam,
    CtapVerifyPinUvAuthTokenContinuation Continuation): CtapAction;

/// <summary>
/// Declares that the simulator must run CTAP 2.3's state-aware <c>verify</c> composition
/// (<see cref="CtapPinUvAuthTokenVerificationExtensions.VerifyPinUvAuthTokenAsync"/>) over
/// <c>authenticatorConfig</c>'s own compound verify message before continuing an interrupted
/// <c>authenticatorConfig</c> (CTAP 2.3 §6.11 step 4.4, line 7978: "Call verify(pinUvAuthToken,
/// 32×0xff || 0x0d || uint8(subCommand) || subCommandParams, pinUvAuthParam)"). A SIBLING of
/// <see cref="CtapVerifyPinUvAuthTokenAction"/>, not a rework of it: <c>authenticatorMakeCredential</c>/
/// <c>authenticatorGetAssertion</c>'s verify message is <c>clientDataHash</c> ALONE, while
/// <c>authenticatorConfig</c>'s is this fixed-prefix-plus-fields compound — two records that each state
/// their own command's message construction plainly, rather than one record with a misleadingly named
/// field. The effectful executor (<c>VerifyAuthenticatorConfigTokenAsync</c>) assembles the message in a
/// pooled buffer (the pure transition has no memory pool to rent from) and calls the SAME
/// <see cref="CtapPinUvAuthTokenVerificationExtensions.VerifyPinUvAuthTokenAsync"/> extension
/// <see cref="CtapVerifyPinUvAuthTokenAction"/>'s own executor uses.
/// </summary>
/// <param name="ProtocolId">The selected PIN/UV auth protocol, named by the interrupted request's <c>pinUvAuthProtocol</c> parameter.</param>
/// <param name="TokenState">
/// The selected protocol's <c>pinUvAuthToken</c> lifecycle state, borrowed from
/// <see cref="CtapAuthenticatorState"/> AFTER its usage-timer expiry has already been evaluated by the
/// request-arm transition — never copied; the effect neither disposes nor mutates it.
/// </param>
/// <param name="SubCommand">The request's <c>subCommand</c> value — the single byte the verify message's third segment carries.</param>
/// <param name="SubCommandParams">
/// The request's RAW, still-CBOR-encoded <c>subCommandParams</c> bytes as received; empty
/// (<see cref="ReadOnlyMemory{T}.Empty"/>) when the member was absent — the message then elides this
/// segment entirely (R5 ruling), contributing zero bytes rather than an encoded empty map.
/// </param>
/// <param name="PinUvAuthParam">The request's presented <c>pinUvAuthParam</c>: the signature <c>verify</c> checks.</param>
/// <param name="Continuation">The interrupted <c>authenticatorConfig</c> request context to resume once verification completes.</param>
public sealed record CtapVerifyAuthenticatorConfigTokenAction(
    CtapPinUvAuthProtocolId ProtocolId,
    CtapPinUvAuthTokenState TokenState,
    int SubCommand,
    ReadOnlyMemory<byte> SubCommandParams,
    ReadOnlyMemory<byte> PinUvAuthParam,
    CtapVerifyPinUvAuthTokenContinuation Continuation): CtapAction;

/// <summary>
/// Resumes an interrupted <c>authenticatorCredentialManagement</c> once its presented
/// <c>pinUvAuthParam</c> has been verified.
/// </summary>
/// <param name="Requested">
/// The original decoded request, borrowed unchanged from the input that declared the verify action.
/// </param>
public sealed record CtapCredentialManagementVerifyContinuation(CredentialManagementRequested Requested): CtapVerifyPinUvAuthTokenContinuation;

/// <summary>
/// Declares that the simulator must run CTAP 2.3's state-aware <c>verify</c> composition
/// (<see cref="CtapPinUvAuthTokenVerificationExtensions.VerifyPinUvAuthTokenAsync"/>) over
/// <c>authenticatorCredentialManagement</c>'s own THIRD verify-message shape before continuing an
/// interrupted <c>authenticatorCredentialManagement</c> (CTAP 2.3 §6.5.8, line 6309-6315:
/// <c>uint8(subCommand) [|| subCommandParams]</c> — no 32-byte <c>0xff</c> prefix, no command byte,
/// unlike <see cref="CtapVerifyAuthenticatorConfigTokenAction"/>'s own compound message). A FOURTH
/// sibling of <see cref="CtapVerifyPinUvAuthTokenAction"/>, not a rework of it. The effectful executor
/// (<c>VerifyCredentialManagementTokenAsync</c>) assembles the message in a pooled buffer (the pure
/// transition has no memory pool to rent from) and calls the SAME
/// <see cref="CtapPinUvAuthTokenVerificationExtensions.VerifyPinUvAuthTokenAsync"/> extension the other
/// three verify actions' own executors use.
/// </summary>
/// <param name="ProtocolId">The selected PIN/UV auth protocol, named by the interrupted request's <c>pinUvAuthProtocol</c> parameter.</param>
/// <param name="TokenState">
/// The selected protocol's <c>pinUvAuthToken</c> lifecycle state, borrowed from
/// <see cref="CtapAuthenticatorState"/> AFTER its usage-timer expiry has already been evaluated by the
/// request-arm transition — never copied; the effect neither disposes nor mutates it.
/// </param>
/// <param name="SubCommand">The request's <c>subCommand</c> value — the single byte the verify message's leading segment carries.</param>
/// <param name="SubCommandParams">
/// The request's RAW, still-CBOR-encoded <c>subCommandParams</c> bytes as received; empty
/// (<see cref="ReadOnlyMemory{T}.Empty"/>) for <c>getCredsMetadata</c>/<c>enumerateRPsBegin</c>, which
/// structurally never carry one — the message then elides this segment entirely, contributing zero
/// trailing bytes.
/// </param>
/// <param name="PinUvAuthParam">The request's presented <c>pinUvAuthParam</c>: the signature <c>verify</c> checks.</param>
/// <param name="Continuation">The interrupted <c>authenticatorCredentialManagement</c> request context to resume once verification completes.</param>
public sealed record CtapVerifyCredentialManagementTokenAction(
    CtapPinUvAuthProtocolId ProtocolId,
    CtapPinUvAuthTokenState TokenState,
    int SubCommand,
    ReadOnlyMemory<byte> SubCommandParams,
    ReadOnlyMemory<byte> PinUvAuthParam,
    CtapVerifyPinUvAuthTokenContinuation Continuation): CtapAction;

/// <summary>
/// Resumes an interrupted <c>authenticatorBioEnrollment</c> once its presented <c>pinUvAuthParam</c> has
/// been verified.
/// </summary>
/// <param name="Requested">
/// The original decoded request, borrowed unchanged from the input that declared the verify action.
/// </param>
public sealed record CtapBioEnrollmentVerifyContinuation(BioEnrollmentRequested Requested): CtapVerifyPinUvAuthTokenContinuation;

/// <summary>
/// Declares that the simulator must run CTAP 2.3's state-aware <c>verify</c> composition
/// (<see cref="CtapPinUvAuthTokenVerificationExtensions.VerifyPinUvAuthTokenAsync"/>) over
/// <c>authenticatorBioEnrollment</c>'s own FOURTH verify-message shape before continuing an interrupted
/// <c>authenticatorBioEnrollment</c> (CTAP 2.3 §6.7.4-§6.7.8, bio scout Finding C):
/// <c>uint8(modality) || uint8(subCommand) [|| subCommandParams]</c> — a TWO-byte leading prefix, unlike
/// <see cref="CtapVerifyCredentialManagementTokenAction"/>'s single leading byte. A FIFTH sibling of
/// <see cref="CtapVerifyPinUvAuthTokenAction"/>, not a rework of it. The effectful executor
/// (<c>VerifyBioEnrollmentTokenAsync</c>) assembles the message in a pooled buffer (the pure transition
/// has no memory pool to rent from) and calls the SAME
/// <see cref="CtapPinUvAuthTokenVerificationExtensions.VerifyPinUvAuthTokenAsync"/> extension the other
/// four verify actions' own executors use.
/// </summary>
/// <param name="ProtocolId">The selected PIN/UV auth protocol, named by the interrupted request's <c>pinUvAuthProtocol</c> parameter.</param>
/// <param name="TokenState">
/// The selected protocol's <c>pinUvAuthToken</c> lifecycle state, borrowed from
/// <see cref="CtapAuthenticatorState"/> AFTER its usage-timer expiry has already been evaluated by the
/// request-arm transition — never copied; the effect neither disposes nor mutates it.
/// </param>
/// <param name="Modality">
/// The request's own <c>modality</c> value — the verify message's own leading byte (already validated
/// <see cref="WellKnownCtapBioEnrollmentModalities.Fingerprint"/> by the request arm before this action
/// is declared).
/// </param>
/// <param name="SubCommand">The request's <c>subCommand</c> value — the verify message's second byte.</param>
/// <param name="SubCommandParams">
/// The request's RAW, still-CBOR-encoded <c>subCommandParams</c> bytes as received; empty
/// (<see cref="ReadOnlyMemory{T}.Empty"/>) for <c>enumerateEnrollments</c>, which structurally never
/// carries one (bio scout §1.11, PRF pattern <c>0104</c>) — the message then elides this segment
/// entirely, contributing zero trailing bytes.
/// </param>
/// <param name="PinUvAuthParam">The request's presented <c>pinUvAuthParam</c>: the signature <c>verify</c> checks.</param>
/// <param name="Continuation">The interrupted <c>authenticatorBioEnrollment</c> request context to resume once verification completes.</param>
public sealed record CtapVerifyBioEnrollmentTokenAction(
    CtapPinUvAuthProtocolId ProtocolId,
    CtapPinUvAuthTokenState TokenState,
    int Modality,
    int SubCommand,
    ReadOnlyMemory<byte> SubCommandParams,
    ReadOnlyMemory<byte> PinUvAuthParam,
    CtapVerifyPinUvAuthTokenContinuation Continuation): CtapAction;

/// <summary>
/// Declares that the simulator must mint a fresh fingerprint template identifier and simulate the
/// enrollment's first sample capture before completing an <c>enrollBegin</c> response (CTAP 2.3 §6.7.4,
/// steps 8-9). Emitted once <c>enrollBegin</c>'s own pure pre-checks (preamble, verify, <c>be</c>
/// permission, auto-cancel of any unfinished enrollment, storage-space check) have passed; the effectful
/// loop draws 16 bytes from the injected entropy provider exactly the way a fresh <see cref="CredentialId"/>
/// is minted, then calls the injected <see cref="SimulateFingerprintCaptureDelegate"/> once, folding the
/// result back as a <see cref="BioEnrollmentCaptureStarted"/> input. Carries no fields: every value the
/// effect needs (the entropy provider, the capture-outcome delegate, the memory pool) comes from the
/// simulator's own composition-time context, mirroring <see cref="CtapResetPinUvAuthTokensAction"/>'s
/// no-fields shape.
/// </summary>
public sealed record CtapBeginBioEnrollmentCaptureAction: CtapAction;

/// <summary>
/// Declares that the simulator must simulate one more sample capture for the in-progress enrollment
/// before completing an <c>enrollCaptureNextSample</c> response (CTAP 2.3 §6.7.4). Emitted once
/// <c>enrollCaptureNextSample</c>'s own pure pre-checks (preamble, verify, <c>be</c> permission, the
/// remembered template's own identifier match) have passed; the effectful loop calls the injected
/// <see cref="SimulateFingerprintCaptureDelegate"/> once — no entropy draw, since the template identifier
/// already exists — folding the result back as a <see cref="BioEnrollmentSampleCaptured"/> input. Carries
/// no fields, mirroring <see cref="CtapBeginBioEnrollmentCaptureAction"/>'s own shape.
/// </summary>
public sealed record CtapContinueBioEnrollmentCaptureAction: CtapAction;

/// <summary>
/// Declares that the simulator must compute one relying party's fresh <c>rpIDHash</c> before completing
/// an <c>enumerateRPsBegin</c> or <c>enumerateRPsGetNextRP</c> response (CTAP 2.3 §6.8.3, lines
/// 7218/7242). Emitted by the credMgmt transition once the RP to report has already been resolved (the
/// group-by-RP scan for <c>enumerateRPsBegin</c>, or the remembered sequence's own advance for
/// <c>enumerateRPsGetNextRP</c>) — the effectful loop computes the digest through the SAME
/// <c>ComputeRpIdHash</c> helper <c>authenticatorMakeCredential</c>/<c>authenticatorGetAssertion</c>
/// already use, assembles the complete response, and folds it back as a
/// <see cref="CredentialManagementResponseComputed"/> input.
/// </summary>
/// <param name="RpId">The relying party identifier to report and hash.</param>
/// <param name="TotalRps">
/// The <c>totalRPs</c> (<c>0x05</c>) value to embed — present only for <c>enumerateRPsBegin</c>'s own
/// response (line 7220); <see langword="null"/> for <c>enumerateRPsGetNextRP</c>, whose own response
/// never reports it (line 7242's own field list omits it).
/// </param>
public sealed record CtapEmitCredentialManagementRpAction(string RpId, int? TotalRps): CtapAction;

/// <summary>
/// Declares that the simulator must locate every resident credential whose relying party identifier's
/// freshly computed <c>rpIDHash</c> matches <see cref="RequestRpIdHash"/> before completing an
/// <c>enumerateCredentialsBegin</c> response (CTAP 2.3 §6.8.4, line 7297: "If no discoverable credentials
/// for this RP ID hash exist..."). No by-hash index exists on the store, so this recomputes
/// <c>ComputeRpIdHash</c> once per resident candidate — the same reason
/// <see cref="CtapEmitCredentialManagementRpAction"/> needs the effectful loop's own memory pool. The
/// effectful loop sorts the matches <see cref="CtapCredentialRecord.CreationSequence"/>-ascending (R9)
/// and folds back a <see cref="CredentialManagementCredentialsLocated"/> input; the pure transition
/// resolves the step-7 <c>CTAP2_ERR_NO_CREDENTIALS</c> decision and assembles the response from the
/// already-known, already-stored fields of the first match.
/// </summary>
/// <param name="RequestRpIdHash">The request's own <c>rpIDHash</c> (<c>subCommandParams</c> <c>0x01</c>) to match candidates against.</param>
/// <param name="CredentialsByCredentialId">The credential store to scan, borrowed unchanged from <see cref="CtapAuthenticatorState"/>.</param>
/// <param name="Now">The time this command was received, threaded through unchanged for the freshly initialized sequence's <c>LastActivityAt</c>.</param>
/// <param name="AuthenticatingPinUvAuthProtocol">The verified <c>pinUvAuthToken</c>'s own protocol, threaded through unchanged for the freshly initialized sequence's own expiry-fold field.</param>
public sealed record CtapLocateCredentialManagementCredentialsAction(
    ReadOnlyMemory<byte> RequestRpIdHash,
    ImmutableDictionary<string, CtapCredentialRecord> CredentialsByCredentialId,
    DateTimeOffset Now,
    CtapPinUvAuthProtocolId AuthenticatingPinUvAuthProtocol): CtapAction;

/// <summary>
/// Declares that the simulator must mint a fresh <c>pinUvAuthToken</c> for BOTH PIN/UV auth protocols —
/// <c>resetPinUvAuthToken()</c> "for all" (CTAP 2.3 §6.11.4 step 7, lines 8171-8177) — before completing
/// a <c>setMinPINLength</c> invocation whose (possibly just-raised) <c>forcePINChange</c> value is
/// <see langword="true"/>. Carries no fields: <c>OnSetMinPinLengthRequested</c> already applies every
/// plain scalar state write (<c>MinPinCodePointLength</c>, <c>IsForcePinChangeRequired</c>) to
/// <see cref="CtapAuthenticatorState"/> BEFORE declaring this action, so the effectful loop's own
/// "every field the fold-back does not touch survives unchanged" behavior carries them through — minting
/// fresh token VALUES is the only piece of this step that needs entropy, hence the only piece routed
/// through the effectful loop at all.
/// </summary>
public sealed record CtapResetPinUvAuthTokensAction: CtapAction;

/// <summary>
/// Declares that the simulator must mint a fresh key-agreement key pair and a fresh
/// <c>pinUvAuthToken</c> for BOTH PIN/UV auth protocols before completing a successful
/// <c>authenticatorReset</c> — the entropy-consuming half of a factory reset (CTAP 2.3, line 6138: the
/// <c>pinUvAuthToken</c> "is generated afresh at power-on and reset"; the key-agreement regeneration
/// mirrors <see cref="CtapAuthenticatorState.PowerCycle"/>'s own <c>initialize()</c> parity). Carries no
/// fields: every entropy-free clear <see cref="CtapAuthenticatorState.FactoryReset"/> performs has
/// already been applied to the state before this action is declared, mirroring how
/// <see cref="CtapResetPinUvAuthTokensAction"/> carries none of <c>setMinPINLength</c>'s own plain scalar
/// writes either.
/// </summary>
/// <remarks>
/// NAMED DISTINCTLY from <see cref="CtapResetPinUvAuthTokensAction"/>: that action mints ONLY fresh
/// tokens (<c>setMinPINLength</c>'s own step-7 side effect), never key-agreement key pairs, for a
/// different command entirely. This action mints BOTH key-agreement key pairs AND both tokens — a
/// strict superset — for <c>authenticatorReset</c> alone.
/// </remarks>
public sealed record CtapFactoryResetKeyMaterialAction: CtapAction;

/// <summary>
/// The interrupted command context a <see cref="CtapPerformBuiltInUvAction"/>'s fold-back needs to
/// resume once the simulated gesture concludes. One subclass per command, mirroring
/// <see cref="CtapVerifyPinUvAuthTokenContinuation"/>'s own per-command shape (CTAP 2.3 §6.1.2 step
/// 11.2 vs §6.2.2 step 6.2 — near-identical literal shape, unlike the verify continuations' genuinely
/// different step orders).
/// </summary>
public abstract record CtapPerformBuiltInUvContinuation;

/// <summary>
/// Resumes an interrupted <c>authenticatorMakeCredential</c> once its <c>options.uv = true</c> built-in
/// user verification attempt (CTAP 2.3 §6.1.2 step 11.2) has concluded.
/// </summary>
/// <param name="Requested">
/// The original decoded request and pre-resolved algorithm selection, borrowed unchanged from the input
/// that declared the attempt action.
/// </param>
/// <param name="EnterpriseAttestationGranted">
/// The mc Step 9 enterprise-attestation grant decision, computed ONCE in <c>OnMakeCredentialRequested</c>
/// before this built-in-UV action was declared, and threaded here so it survives the async gesture round
/// trip unchanged (waveep R6, trap 12) — never recomputed once the gesture concludes.
/// </param>
public sealed record CtapMakeCredentialBuiltInUvContinuation(MakeCredentialRequested Requested, bool EnterpriseAttestationGranted): CtapPerformBuiltInUvContinuation;

/// <summary>
/// Resumes an interrupted <c>authenticatorGetAssertion</c> once its <c>options.uv = true</c> built-in
/// user verification attempt (CTAP 2.3 §6.2.2 step 6.2) has concluded.
/// </summary>
/// <param name="Requested">The original decoded request, borrowed unchanged from the input that declared the attempt action.</param>
/// <param name="UserPresent">
/// The effective <c>up</c> option value already resolved by the request arm (absent normalizes to
/// <see langword="true"/>, CTAP 2.3 line 3910-3913) — threaded through since <c>ga</c>'s own
/// <c>userPresent</c> resolution happens before this attempt is declared, unlike <c>mc</c>'s, which is
/// always <see langword="true"/> by this point.
/// </param>
public sealed record CtapGetAssertionBuiltInUvContinuation(GetAssertionRequested Requested, bool UserPresent): CtapPerformBuiltInUvContinuation;

/// <summary>
/// Declares that the simulator must run <c>performBuiltInUv(internalRetry)</c>'s attempt loop (CTAP 2.3
/// §6.5.3.1) for <c>authenticatorMakeCredential</c>/<c>authenticatorGetAssertion</c>'s own
/// <c>options.uv = true</c> fallback (§6.1.2 step 11.2 / §6.2.2 step 6.2). Emitted once the pure
/// transition has confirmed the authenticator is protected by some form of user verification, the
/// built-in UV method is configured (≥1 fingerprint enrollment), and — for this command family only —
/// <see cref="InternalRetry"/> is HARDCODED <see langword="true"/> at the declaring call site (mc
/// 11.2.1 / ga 6.2.1 verbatim), NEVER computed by a helper shared with
/// <see cref="CtapIssueUvTokenAction"/>'s own <c>preferredPlatformUvAttempts</c>-derived value (uv scout
/// trap 2). <see cref="CtapAuthenticatorSimulator"/>'s executor calls the shared attempt-loop helper —
/// the loop mechanics ARE shared (a plain I/O composition), only the two callers' <c>internalRetry</c>
/// VALUES are never computed by one function.
/// </summary>
/// <param name="InternalRetry">Always <see langword="true"/> here — see the type's own remarks.</param>
/// <param name="StartingUvRetries">
/// <see cref="CtapAuthenticatorState.UvRetries"/>'s value at declare time, already confirmed non-zero
/// (and not subject to the pinRetries-exhaustion drag-down, §6.5.3.1 step 3) by the pure transition
/// before this action was ever declared — the executor's attempt loop decrements a LOCAL copy of this
/// value, never re-reading state mid-loop.
/// </param>
/// <param name="Continuation">The interrupted command's own decoded-request context to resume once the attempt loop concludes.</param>
public sealed record CtapPerformBuiltInUvAction(
    bool InternalRetry,
    int StartingUvRetries,
    CtapPerformBuiltInUvContinuation Continuation): CtapAction;

/// <summary>
/// Declares that the simulator must run <c>getPinUvAuthTokenUsingUvWithPermissions</c>'s (<c>0x06</c>)
/// full crypto sequence (CTAP 2.3 §6.5.5.7.3): <c>decapsulate</c>, <c>performBuiltInUv(internalRetry)</c>'s
/// attempt loop, then — on success — mint fresh <c>pinUvAuthToken</c>s for BOTH PIN/UV auth protocols
/// (<c>resetPinUvAuthToken()</c> "for all", step 12), call <c>beginUsingPinUvAuthToken(userIsPresent:
/// true)</c> on <see cref="ProtocolId"/>'s fresh token (steps 13-14 — the simulated gesture always
/// supplies evidence of user interaction here, so this is the ONE token-issuance action in this codebase
/// that begins using a token with <c>userIsPresent</c> already <see langword="true"/>, uv scout delta
/// (a)), assign it <see cref="PermissionsToAssign"/>/<see cref="PermissionsRpId"/> (steps 15-16), and
/// encrypt it for the response (step 17) — mirroring <see cref="CtapIssuePinTokenAction"/>'s own
/// token-mint tail exactly, with the PIN-hash decrypt/compare step replaced by the attempt loop.
/// <see cref="InternalRetry"/> is COMPUTED from <see cref="CtapAuthenticatorState.PreferredPlatformUvAttempts"/>
/// by the pure request arm — NEVER the mc/ga-shared hardcoded-true value <see cref="CtapPerformBuiltInUvAction"/>
/// carries (uv scout trap 2).
/// </summary>
/// <param name="ProtocolId">The selected PIN/UV auth protocol.</param>
/// <param name="OwnPrivateKey">The selected protocol's key-agreement private key, borrowed from <see cref="CtapAuthenticatorState"/>.</param>
/// <param name="PeerKeyAgreement">The platform's ephemeral key-agreement COSE_Key (the request's <c>keyAgreement</c> parameter).</param>
/// <param name="PermissionsToAssign">The requested permissions, already masked to this profile's grantable set (<c>mc|ga|cm|be</c>, R5), undefined bits ignored.</param>
/// <param name="PermissionsRpId">The permissions RP ID to bind the issued token to, or <see langword="null"/> when the request's own <c>rpId</c> was absent.</param>
/// <param name="Now">
/// The time this command was received, precomputed by the pure transition — the value
/// <c>beginUsingPinUvAuthToken</c> stamps as the fresh token's usage-timer start.
/// </param>
/// <param name="InternalRetry">Computed from <see cref="CtapAuthenticatorState.PreferredPlatformUvAttempts"/> — see the type's own remarks.</param>
/// <param name="StartingUvRetries">
/// <see cref="CtapAuthenticatorState.UvRetries"/>'s value at declare time, already confirmed non-zero
/// (and not subject to the pinRetries-exhaustion drag-down) by the pure transition — see
/// <see cref="CtapPerformBuiltInUvAction.StartingUvRetries"/>'s identical remark.
/// </param>
public sealed record CtapIssueUvTokenAction(
    CtapPinUvAuthProtocolId ProtocolId,
    PrivateKeyMemory OwnPrivateKey,
    CoseKey PeerKeyAgreement,
    int PermissionsToAssign,
    string? PermissionsRpId,
    DateTimeOffset Now,
    bool InternalRetry,
    int StartingUvRetries): CtapAction;

/// <summary>
/// Resumes an interrupted <c>authenticatorLargeBlobs</c> <c>set</c> once its presented
/// <c>pinUvAuthParam</c> has been verified.
/// </summary>
/// <param name="Requested">
/// The original decoded request, borrowed unchanged from the input that declared the verify action.
/// </param>
/// <param name="ExpectedLength">
/// The <c>expectedLength</c> already resolved by <see cref="CtapAuthenticatorTransitions.OnLargeBlobsRequested"/>
/// before the gate ran (either the fragment's own <c>length</c> parameter for an <c>offset == 0</c>
/// sequence, or the already-remembered sequence's own value for a continuation) — carried through rather
/// than re-derived, since the pre-gate checks that produced it must not re-run after verification.
/// </param>
/// <param name="ExpectedNextOffset">
/// The <c>expectedNextOffset</c> already resolved and matched against the fragment's own <c>offset</c>
/// before the gate ran — see <paramref name="ExpectedLength"/>'s identical carry-through reasoning.
/// </param>
public sealed record CtapLargeBlobsVerifyContinuation(
    LargeBlobsRequested Requested, int ExpectedLength, int ExpectedNextOffset): CtapVerifyPinUvAuthTokenContinuation;

/// <summary>
/// Declares that the simulator must run CTAP 2.3's state-aware <c>verify</c> composition
/// (<see cref="CtapPinUvAuthTokenVerificationExtensions.VerifyPinUvAuthTokenAsync"/>) over
/// <c>authenticatorLargeBlobs</c>' own per-fragment verify message before continuing an interrupted
/// <c>set</c> (CTAP 2.3 §6.10.2, lines 7578/7646: <c>authenticate(pinUvAuthToken, 32×0xff ||
/// h'0c00' || uint32LittleEndian(offset) || SHA-256(contents of set byte string))</c>). The SIXTH verify
/// action in this codebase (seams Finding D), and uniquely among its siblings NOT a pure byte
/// concatenation: the message embeds a live SHA-256 digest of <see cref="Fragment"/> and a
/// LITTLE-endian <see cref="Offset"/> — the surface's ONLY little-endian integer — so
/// <see cref="CtapAuthenticatorSimulator.BuildLargeBlobsMessage"/> cannot be a pure static
/// byte-assembler like <c>BuildAuthenticatorConfigMessage</c>/<c>BuildCredentialManagementMessage</c>/
/// <c>BuildBioEnrollmentMessage</c>; the digest is computed in the effectful executor
/// (<c>VerifyLargeBlobsTokenAsync</c>).
/// </summary>
/// <param name="ProtocolId">The selected PIN/UV auth protocol, named by the interrupted request's <c>pinUvAuthProtocol</c> parameter.</param>
/// <param name="TokenState">
/// The selected protocol's <c>pinUvAuthToken</c> lifecycle state, borrowed from
/// <see cref="CtapAuthenticatorState"/> AFTER its usage-timer expiry has already been evaluated by the
/// request-arm transition — never copied; the effect neither disposes nor mutates it.
/// </param>
/// <param name="Offset">The request's <c>offset</c> value — the verify message's LITTLE-endian 32-bit segment.</param>
/// <param name="Fragment">The request's <c>set</c> byte string CONTENTS (never including the outer CBOR major-type-2 tag) — the bytes <c>SHA-256</c> is computed over.</param>
/// <param name="PinUvAuthParam">The request's presented <c>pinUvAuthParam</c>: the signature <c>verify</c> checks.</param>
/// <param name="Continuation">The interrupted <c>set</c> request context to resume once verification completes.</param>
public sealed record CtapVerifyLargeBlobsTokenAction(
    CtapPinUvAuthProtocolId ProtocolId,
    CtapPinUvAuthTokenState TokenState,
    uint Offset,
    ReadOnlyMemory<byte> Fragment,
    ReadOnlyMemory<byte> PinUvAuthParam,
    CtapVerifyPinUvAuthTokenContinuation Continuation): CtapAction;

/// <summary>
/// Declares that the simulator must append <see cref="Fragment"/> into the pending serialized large-blob
/// array — renting a fresh buffer sized <see cref="ExpectedLength"/> up front when
/// <see cref="ExistingPendingBuffer"/> is <see langword="null"/> (a fresh <c>offset == 0</c> sequence,
/// seams Q5), otherwise writing into the already-rented buffer at <see cref="Offset"/> — and, once the
/// pending length reaches <see cref="ExpectedLength"/>, run the commit-time integrity check (CTAP 2.3
/// §6.10.2, lines 7659-7671): <c>LEFT(SHA-256(preceding bytes), 16)</c> compared against the completed
/// buffer's trailing 16 bytes (seams Finding E — the OTHER SHA-256 on this surface, whole-array-minus-16
/// truncated-16, never conflated with <see cref="CtapVerifyLargeBlobsTokenAction"/>'s per-fragment
/// digest). Declared on BOTH the gate-armed path (after <see cref="CtapVerifyLargeBlobsTokenAction"/>'s
/// fold-back and the <c>lbw</c> permission check) and the tokenless path (R5's unarmed-gate direct
/// invoke) — the commit-time integrity check runs on a completed TOKENLESS write exactly as it does on a
/// verified one.
/// </summary>
/// <param name="Offset">The accepted fragment's <c>offset</c> — where in the pending buffer <see cref="Fragment"/> is written.</param>
/// <param name="Fragment">The accepted fragment's contents to append.</param>
/// <param name="ExpectedLength">
/// The remembered sequence's fixed total length — both the size a fresh rent uses and the length the
/// pending buffer must reach before the integrity check runs.
/// </param>
/// <param name="AuthenticatingPinUvAuthProtocol">
/// The protocol that authenticated this fragment, or <see langword="null"/> for a tokenless fragment —
/// echoed unchanged into the fold-back so a still-in-progress sequence's own
/// <see cref="CtapRememberedLargeBlobWriteState.AuthenticatingPinUvAuthProtocol"/> stays correct across
/// every fragment of one sequence.
/// </param>
/// <param name="ExistingPendingBuffer">
/// The already-rented pending buffer to reuse for a continuation fragment (<see cref="Offset"/> non-zero),
/// borrowed from <see cref="CtapAuthenticatorState.RememberedLargeBlobWrite"/> — ownership returns via
/// the fold-back either way; <see langword="null"/> for a fresh <c>offset == 0</c> sequence, which the
/// executor rents anew.
/// </param>
public sealed record CtapCommitLargeBlobArrayAction(
    int Offset,
    ReadOnlyMemory<byte> Fragment,
    int ExpectedLength,
    CtapPinUvAuthProtocolId? AuthenticatingPinUvAuthProtocol,
    IMemoryOwner<byte>? ExistingPendingBuffer): CtapAction;
