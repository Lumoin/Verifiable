using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Context;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Foundation.Automata;
using Verifiable.JCose;

namespace Verifiable.Fido2.Ctap.Authenticator.Automata;

/// <summary>
/// A behavioral CTAP2 authenticator simulator built on a <see cref="PushdownAutomaton{TState, TInput, TStackSymbol}"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="TransceiveAsync"/> has exactly the <see cref="Ctap2TransceiveDelegate"/> shape (CTAP2
/// request bytes in, CTAP2 response bytes out, pooled carriers) — the same
/// method-group-conversion precedent <c>Verifiable.Apdu.Automata.CardSimulator.TransceiveAsync</c>
/// establishes for <c>Verifiable.Apdu.TransceiveDelegate</c>, and identical to
/// <c>Verifiable.Apdu.Ctap.CtapPayloadTransceiveDelegate</c>'s shape, so this same method binds
/// directly to <c>Verifiable.Apdu.Ctap.CtapNfcResponder.Create</c> on the transport side with no
/// shared type between the two projects. This type is transport-agnostic itself: it knows nothing of
/// NFC, USB, or BLE framing, only the transport-neutral CTAP2 request/response envelope.
/// </para>
/// <para>
/// <strong>Scope.</strong> This simulator models <c>authenticatorGetInfo</c> (<c>0x04</c>),
/// <c>authenticatorMakeCredential</c> (<c>0x01</c>), <c>authenticatorGetAssertion</c> (<c>0x02</c>),
/// <c>authenticatorGetNextAssertion</c> (<c>0x08</c>), <c>authenticatorClientPIN</c>'s three
/// read-only subcommands (<c>getPINRetries</c>, <c>getKeyAgreement</c>, <c>getUVRetries</c>) plus its
/// four PIN-path subcommands (<c>setPIN</c>, <c>changePIN</c>, <c>getPinToken</c>,
/// <c>getPinUvAuthTokenUsingPinWithPermissions</c>), <c>authenticatorConfig</c>'s (<c>0x0D</c>)
/// <c>toggleAlwaysUv</c>/<c>setMinPINLength</c> subcommands, <c>authenticatorBioEnrollment</c>'s
/// (<c>0x09</c>) FULL command surface — the token-free trio (<c>getModality</c>,
/// <c>getFingerprintSensorInfo</c>, <c>cancelCurrentEnrollment</c>) and its five <c>be</c>-permission-
/// gated subcommands (<c>enrollBegin</c>/<c>enrollCaptureNextSample</c>/<c>enumerateEnrollments</c>/
/// <c>setFriendlyName</c>/<c>removeEnrollment</c>) against a real fingerprint template store — and the
/// built-in-UV cluster: <c>getPinUvAuthTokenUsingUvWithPermissions</c> (<c>0x06</c>) once at least one
/// fingerprint enrollment is provisioned, <c>performBuiltInUv</c>'s live <c>uvRetries</c> lockout/retry
/// machinery, and <c>options.uv = true</c> on mc/ga once built-in UV is configured; and
/// <c>authenticatorLargeBlobs</c> (<c>0x0C</c>) FULLY — <c>get</c> (public, unauthenticated substring
/// reads of the stored serialized large-blob array) and the complete <c>set</c> write state machine (CTAP
/// 2.3 §6.10.2): the R5 conditional token gate (tokenless when the authenticator is unprotected and
/// <c>alwaysUv</c> is off), the volatile <c>expectedLength</c>/<c>expectedNextOffset</c> sequencing, and
/// the commit-time truncated-SHA-256 integrity check; every other command
/// byte is answered with an error, per
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#message-encoding">
/// CTAP 2.3, section 8: Message Encoding</see>. A <c>pinUvAuthParam</c> on
/// <c>authenticatorMakeCredential</c>/<c>authenticatorGetAssertion</c> is verified against the token
/// issued by <c>authenticatorClientPIN</c>'s PIN-path subcommands once the authenticator is protected
/// by some form of user verification (a PIN is set OR a fingerprint is enrolled) — see
/// <c>Ctap.Authenticator.Automata.CtapAuthenticatorTransitions.OnMakeCredentialRequested</c>/
/// <c>OnGetAssertionRequested</c>.
/// </para>
/// <para>
/// <strong>Multi-account residents.</strong> This simulator can hold resident (discoverable) credentials
/// for multiple accounts at the same relying party, keyed by the pair (<c>rp.id</c>, account); a
/// same-(<c>rp.id</c>, account) resident registration still overwrites the existing credential
/// unconditionally (CTAP 2.3, section 6.1.2, step 16). <see cref="CtapAuthenticatorState.ResidentCredentialCapacity"/>
/// bounds how many resident credentials may exist at once — a resident registration that would exceed
/// it (an overwrite never counts against it) answers <c>CTAP2_ERR_KEY_STORE_FULL</c>. When an
/// <c>allowList</c>-absent <c>authenticatorGetAssertion</c> locates more than one applicable resident
/// credential for a relying party, it signs and returns the most recently created one together with
/// <c>numberOfCredentials</c>, and remembers the rest for <c>authenticatorGetNextAssertion</c> to walk
/// through in most-recent-first order (CTAP 2.3, sections 6.2 and 6.3) — subject to the stateful-command
/// rules: any other authenticator operation, or more than 30 seconds of inactivity, discards the
/// remembered sequence.
/// </para>
/// <para>
/// <strong>Attestation format.</strong> This simulator supports exactly three attestation statement
/// shapes — <c>packed</c> self-attestation, <c>packed</c> certified (enterprise) attestation, and
/// <c>none</c> — and resolves which one <c>authenticatorMakeCredential</c> emits from the request's
/// <c>attestationFormatsPreference</c>, per CTAP 2.3, section 6.1.2, step 17 (see
/// <see cref="CtapAttestationFormatChoice"/> and <c>CtapAuthenticatorTransitions.ResolveAttestationFormat</c>):
/// packed self-attestation is this authenticator's own default choice when the preference is absent,
/// empty, or names no supported format; a preference of exactly <c>["none"]</c> omits <c>attStmt</c> from
/// the CTAP response entirely. The certified shape (waveep §7.1) is never a direct product of this
/// preference resolution — it is the self-attestation resolution UPGRADED by mc Step 9's own enterprise-
/// attestation grant, signed with the SEEDED enterprise attestation private key rather than the
/// credential's own key (never the credential key — trap 11), and carrying the seeded <c>x5c</c> chain.
/// </para>
/// <para>
/// Credential key generation and assertion signing are routed through the production cryptography
/// registries via <see cref="Ctap.Authenticator.Automata.CtapCredentialSigningBackend"/> (constructor-
/// injected, optional; a <see langword="null"/> backend answers every <c>authenticatorMakeCredential</c>
/// request with <c>CTAP2_ERR_UNSUPPORTED_ALGORITHM</c>, since its supported-algorithm set is then empty)
/// — the same optional-backend shape <c>Verifiable.Tpm.Automata.TpmSimulator</c> uses for its own
/// injected ECC/RSA signing backends.
/// </para>
/// <para>
/// The simulator is a stateful device processed serially, as a physical authenticator is; it is not
/// safe for concurrent calls — the same convention <c>TpmSimulator</c>/<c>CardSimulator</c> document.
/// </para>
/// <para>
/// <strong>Disposal.</strong> Every minted credential owns pooled memory (its credential identifier,
/// user handle, and private key) — <see cref="Dispose"/> walks the credential store and releases all of
/// it. <see cref="TransceiveAsync"/> throws <see cref="ObjectDisposedException"/> once disposed, mirroring
/// <c>Verifiable.Apdu.Ctap.CtapNfcResponder</c>'s own disposed-flag shape.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class CtapAuthenticatorSimulator: IObservable<TraceEntry<CtapAuthenticatorState, CtapAuthenticatorInput>>, IDisposable
{
    /// <summary>The length in bytes of an AAGUID, drawn from the entropy provider at construction.</summary>
    private const int AaguidLength = 16;

    /// <summary>
    /// The length in bytes of a minted credential identifier, drawn from the entropy provider on every
    /// <c>authenticatorMakeCredential</c> command.
    /// </summary>
    private const int CredentialIdLength = 32;

    /// <summary>
    /// The length in bytes of a minted fingerprint template identifier, drawn from the entropy provider
    /// on every <c>enrollBegin</c> command (CTAP 2.3 §6.7.4 step 8) — mirroring
    /// <see cref="CredentialIdLength"/>'s own minting shape at a shorter, template-id-sized length.
    /// </summary>
    private const int BioEnrollmentTemplateIdLength = 16;

    /// <summary>
    /// The length in bytes of a freshly minted <c>largeBlobKey</c>, drawn from the entropy provider
    /// alongside the credential identifier on an <c>authenticatorMakeCredential</c> whose §12.3 extension
    /// processing resolved <see cref="CtapGenerateCredentialKeyAction.LargeBlobKeyRequested"/> to
    /// <see langword="true"/> — CTAP 2.3 §12.3, line 12827: "32 bytes of opaque storage" / line 12851:
    /// "a freshly generated 32-byte key". Single-sourced (D4) rather than a bare literal at the mint site.
    /// </summary>
    private const int LargeBlobKeyLength = 32;

    /// <summary>
    /// The length in bytes of each freshly minted <c>hmac-secret</c> CredRandom value, drawn from the
    /// entropy provider on EVERY <c>authenticatorMakeCredential</c> regardless of whether the request
    /// carried the extension (CTAP 2.3 section 12.7, snapshot line 13191: "two random 32-byte values";
    /// line 13192's SHOULD, adopted — contract R2). Single-sourced (D4) rather than a bare literal at the
    /// two mint sites (<see cref="CtapCredentialRecord.CredRandomWithUV"/>/
    /// <see cref="CtapCredentialRecord.CredRandomWithoutUV"/>).
    /// </summary>
    private const int CredRandomLength = 32;

    /// <summary>The SHA-256 digest length in bytes, used to size a computed <c>rpIdHash</c> or the full digest a stored PIN hash truncates.</summary>
    private const int Sha256Length = 32;

    /// <summary>
    /// The exact decrypted-plaintext length in bytes a ONE-salt <c>hmac-secret</c> ga request must
    /// produce (CTAP 2.3 §12.7, snapshot line 13307) — also each individual salt's own length and each
    /// <c>HMAC-SHA-256(CredRandom, salt)</c> output's length (snapshot lines 13099-13100/13321-13327).
    /// </summary>
    private const int HmacSecretSaltLength = 32;

    /// <summary>
    /// The exact decrypted-plaintext length in bytes a TWO-salt <c>hmac-secret</c> ga request must
    /// produce (CTAP 2.3 §12.7, snapshot line 13307): <c>salt1 || salt2</c>.
    /// </summary>
    private const int HmacSecretTwoSaltLength = HmacSecretSaltLength * 2;

    /// <summary>The exact byte length a <c>setPIN</c>/<c>changePIN</c> decrypted <c>paddedNewPin</c> must be (CTAP 2.3, lines 5580/5694).</summary>
    private const int PaddedPinLength = 64;

    /// <summary>The stored PIN hash length in bytes: <c>LEFT(SHA-256(newPin), 16)</c> (CTAP 2.3, lines 5592/5710).</summary>
    private const int StoredPinHashLength = 16;

    /// <summary>
    /// The serialized large-blob array's trailing truncated-hash length in bytes: <c>LEFT(SHA-256(array
    /// bytes), 16)</c> (CTAP 2.3 §6.10, line 7540/7666) — the OTHER truncate-to-16 quantity on this
    /// surface, numerically identical to <see cref="StoredPinHashLength"/> but a distinct semantic value
    /// (a whole-array commit check, not a PIN hash), named separately so the two are never conflated
    /// (seams trap 3).
    /// </summary>
    private const int LargeBlobArrayTrailingHashLength = 16;

    /// <summary>
    /// The live automaton holding this authenticator's state of record. Reassigned (never mutated in
    /// place) by <see cref="PowerCycle"/>, which hydrates a fresh automaton from the current one's
    /// snapshot (run id, stack, step count) around a power-cycled <see cref="CtapAuthenticatorState"/> —
    /// the same "construct from snapshot" seam <see cref="PushdownAutomaton{TState, TInput, TStackSymbol}"/>
    /// itself documents for resuming a computation without replaying its inputs.
    /// </summary>
    private PushdownAutomaton<CtapAuthenticatorState, CtapAuthenticatorInput, CtapAuthenticatorStackSymbol> Automaton { get; set; }

    /// <summary>The time source threaded to the effectful runner for trace timestamps.</summary>
    private TimeProvider TimeProvider { get; }

    /// <summary>The codec seam that CBOR-encodes an <c>authenticatorGetInfo</c> response model.</summary>
    private EncodeCtapGetInfoResponseDelegate EncodeGetInfoResponse { get; }

    /// <summary>The codec seam that CBOR-decodes an <c>authenticatorMakeCredential</c> request.</summary>
    private DecodeCtapMakeCredentialRequestDelegate DecodeMakeCredentialRequest { get; }

    /// <summary>The codec seam that CBOR-encodes an <c>authenticatorMakeCredential</c> response model.</summary>
    private EncodeCtapMakeCredentialResponseDelegate EncodeMakeCredentialResponse { get; }

    /// <summary>The codec seam that CBOR-decodes an <c>authenticatorGetAssertion</c> request.</summary>
    private DecodeCtapGetAssertionRequestDelegate DecodeGetAssertionRequest { get; }

    /// <summary>The codec seam that CBOR-encodes an <c>authenticatorGetAssertion</c> response model.</summary>
    private EncodeCtapGetAssertionResponseDelegate EncodeGetAssertionResponse { get; }

    /// <summary>
    /// The codec seam that CBOR-decodes an <c>authenticatorClientPIN</c> request — a required
    /// composition-time dependency (decision 9: the advertises-but-<c>INVALID_COMMAND</c>s configuration
    /// is unrepresentable), since <c>authenticatorGetInfo</c> always advertises <c>clientPin</c> and
    /// <c>pinUvAuthToken</c>.
    /// </summary>
    private DecodeCtapClientPinRequestDelegate DecodeClientPinRequest { get; }

    /// <summary>
    /// The codec seam that CBOR-encodes an <c>authenticatorClientPIN</c> response model — see
    /// <see cref="DecodeClientPinRequest"/>.
    /// </summary>
    private EncodeCtapClientPinResponseDelegate EncodeClientPinResponse { get; }

    /// <summary>
    /// The codec seam that CBOR-decodes an <c>authenticatorConfig</c> request — a required
    /// composition-time dependency (R7: <c>authnrCfg</c> is always advertised <see langword="true"/> in
    /// this profile, so an advertises-but-cannot-decode configuration is unrepresentable).
    /// </summary>
    private DecodeCtapAuthenticatorConfigRequestDelegate DecodeAuthenticatorConfigRequest { get; }

    /// <summary>
    /// The codec seam that CBOR-decodes an <c>authenticatorCredentialManagement</c> request — a required
    /// composition-time dependency (R1: <c>credMgmt</c> is always advertised <see langword="true"/> in
    /// this profile, so an advertises-but-cannot-decode configuration is unrepresentable).
    /// </summary>
    private DecodeCtapCredentialManagementRequestDelegate DecodeCredentialManagementRequest { get; }

    /// <summary>
    /// The codec seam that CBOR-encodes an <c>authenticatorCredentialManagement</c> response model — see
    /// <see cref="DecodeCredentialManagementRequest"/>.
    /// </summary>
    private EncodeCtapCredentialManagementResponseDelegate EncodeCredentialManagementResponse { get; }

    /// <summary>
    /// The codec seam that CBOR-decodes an <c>authenticatorBioEnrollment</c> request — a required
    /// composition-time dependency: this authenticator advertises <c>bioEnroll</c> present
    /// (true-or-false tri-state) unconditionally from this wave on, so an advertises-but-cannot-decode
    /// configuration is unrepresentable, the exact posture <see cref="DecodeCredentialManagementRequest"/>
    /// establishes for <c>credMgmt</c>.
    /// </summary>
    private DecodeCtapBioEnrollmentRequestDelegate DecodeBioEnrollmentRequest { get; }

    /// <summary>
    /// The codec seam that CBOR-encodes an <c>authenticatorBioEnrollment</c> response model — see
    /// <see cref="DecodeBioEnrollmentRequest"/>.
    /// </summary>
    private EncodeCtapBioEnrollmentResponseDelegate EncodeBioEnrollmentResponse { get; }

    /// <summary>
    /// The codec seam that CBOR-decodes an <c>authenticatorLargeBlobs</c> request — a required
    /// composition-time dependency: this authenticator advertises <c>largeBlobs:true</c>
    /// unconditionally, so an advertises-but-cannot-decode configuration is unrepresentable, the exact
    /// posture <see cref="DecodeBioEnrollmentRequest"/> establishes for <c>bioEnroll</c>.
    /// </summary>
    private DecodeCtapLargeBlobsRequestDelegate DecodeLargeBlobsRequest { get; }

    /// <summary>
    /// The codec seam that CBOR-encodes an <c>authenticatorLargeBlobs</c> <c>get</c> response model —
    /// see <see cref="DecodeLargeBlobsRequest"/>.
    /// </summary>
    private EncodeCtapLargeBlobsResponseDelegate EncodeLargeBlobsResponse { get; }

    /// <summary>The codec seam that CBOR-encodes a minted credential's public key for <c>attestedCredentialData</c>.</summary>
    private EncodeCredentialPublicKeyDelegate EncodeCredentialPublicKey { get; }

    /// <summary>The codec seam that CBOR-encodes a self-attestation packed <c>attStmt</c>.</summary>
    private EncodePackedSelfAttestationStatementDelegate EncodePackedSelfAttestationStatement { get; }

    /// <summary>
    /// The codec seam that CBOR-encodes a certified (enterprise) packed <c>attStmt</c>, or
    /// <see langword="null"/> if none was injected. Only ever consulted when mc Step 9 has granted an
    /// enterprise attestation (waveep R6/R7) — which itself requires
    /// <see cref="CtapAuthenticatorState.EnterpriseAttestationProvisioning"/> to be non-null — so a
    /// composition that seeds enterprise attestation provisioning without also injecting this seam is a
    /// genuine composition-time error, surfaced when <see cref="BuildAttestationResponseAsync"/> reaches
    /// the certified branch.
    /// </summary>
    private EncodePackedCertifiedAttestationStatementDelegate? EncodePackedCertifiedAttestationStatement { get; }

    /// <summary>
    /// The codec seam that CBOR-encodes the resolved <c>credProtect</c>/<c>hmac-secret</c>/
    /// <c>minPinLength</c>/<c>hmac-secret-mc</c> authData extensions output map — a required
    /// composition-time dependency, since <c>authenticatorGetInfo</c> always advertises every one of
    /// these extensions (R1) and a simulator must be able to encode the output of every extension it
    /// advertises.
    /// </summary>
    private EncodeCtapMakeCredentialExtensionOutputsDelegate EncodeMakeCredentialExtensionOutputs { get; }

    /// <summary>
    /// The codec seam that CBOR-encodes the resolved <c>hmac-secret</c> <c>authenticatorGetAssertion</c>
    /// authData extensions output map — a required composition-time dependency, mirroring
    /// <see cref="EncodeMakeCredentialExtensionOutputs"/>'s own "always advertised, so always encodable"
    /// posture (CTAP 2.3 §9 item 1, contract R1).
    /// </summary>
    private EncodeCtapGetAssertionExtensionOutputsDelegate EncodeGetAssertionExtensionOutputs { get; }

    /// <summary>The entropy provider the AAGUID and every minted credential identifier are drawn from.</summary>
    private FillEntropyDelegate Rng { get; }

    /// <summary>
    /// The R8 outcome-injection knob for <c>enrollBegin</c>'s/<c>enrollCaptureNextSample</c>'s own
    /// fingerprint sensor simulation — a composition-time personalization, never a test-only seam.
    /// Defaults to always <see cref="WellKnownCtapLastEnrollSampleStatuses.Good"/> (an ideal sensor).
    /// </summary>
    private SimulateFingerprintCaptureDelegate SimulateFingerprintCapture { get; }

    /// <summary>
    /// The shipped default for <see cref="SimulateFingerprintCapture"/>: an ideal sensor that always
    /// captures a <see cref="WellKnownCtapLastEnrollSampleStatuses.Good"/> sample.
    /// </summary>
    private static int DefaultSimulateFingerprintCapture() => WellKnownCtapLastEnrollSampleStatuses.Good;

    /// <summary>
    /// The R8 outcome-injection knob for <c>performBuiltInUv</c>'s own simulated gesture — a
    /// composition-time personalization, never a test-only seam. Defaults to always
    /// <see cref="CtapBuiltInUvAttemptOutcome.Success"/> (an ideal, always-matching sensor). Consumed by
    /// <c>getPinUvAuthTokenUsingUvWithPermissions</c>'s (<c>0x06</c>) token-issuance effect and by
    /// <c>authenticatorMakeCredential</c>/<c>authenticatorGetAssertion</c>'s own <c>options.uv</c>
    /// built-in-UV fallback effect — the SAME delegate instance, never two separately configured knobs.
    /// </summary>
    private SimulateBuiltInUvDelegate SimulateBuiltInUv { get; }

    /// <summary>
    /// The shipped default for <see cref="SimulateBuiltInUv"/>: an ideal sensor that always reports
    /// <see cref="CtapBuiltInUvAttemptOutcome.Success"/>.
    /// </summary>
    private static CtapBuiltInUvAttemptOutcome DefaultSimulateBuiltInUv() => CtapBuiltInUvAttemptOutcome.Success;

    /// <summary>
    /// The R1 user-presence decision seam for <c>authenticatorMakeCredential</c>'s/
    /// <c>authenticatorGetAssertion</c>'s own :2840 user-action collection — a composition-time
    /// personalization, never a test-only seam. Defaults to always <see cref="CtapUserPresenceDecision.Granted"/>
    /// (an ideal, always-present user), preserving the byte-for-byte behavior of every existing test and
    /// of mc's own historical hardcoded <c>userPresent: true</c>. Consumed ONLY by the
    /// <see cref="CtapCollectUserPresenceAction"/> executor.
    /// </summary>
    private SimulateUserPresenceDelegate SimulateUserPresence { get; }

    /// <summary>
    /// The shipped default for <see cref="SimulateUserPresence"/>: an ideal, always-present user that
    /// always reports <see cref="CtapUserPresenceDecision.Granted"/>.
    /// </summary>
    private static ValueTask<CtapUserPresenceDecision> DefaultSimulateUserPresence(CancellationToken cancellationToken) =>
        ValueTask.FromResult(CtapUserPresenceDecision.Granted);

    /// <summary>
    /// The credential-minting backend for <c>authenticatorMakeCredential</c>, or <see langword="null"/> if
    /// none was injected (every <c>authenticatorMakeCredential</c> request then answers
    /// <c>CTAP2_ERR_UNSUPPORTED_ALGORITHM</c>).
    /// </summary>
    private CtapCredentialSigningBackend? CredentialSigningBackend { get; }

    /// <summary>Whether this instance has been disposed. Guards every public member against post-dispose use.</summary>
    private bool disposed;


    /// <summary>
    /// Gets the authenticator's claimed AAGUID, fixed for this instance's lifetime.
    /// </summary>
    public Guid Aaguid => Automaton.CurrentState.Aaguid;


    /// <summary>
    /// Creates a CTAP2 authenticator simulator.
    /// </summary>
    /// <param name="runId">A stable identifier for this simulated authenticator; also the automaton's run identifier.</param>
    /// <param name="encodeGetInfoResponse">The codec seam that CBOR-encodes an <c>authenticatorGetInfo</c> response model.</param>
    /// <param name="decodeMakeCredentialRequest">The codec seam that CBOR-decodes an <c>authenticatorMakeCredential</c> request.</param>
    /// <param name="encodeMakeCredentialResponse">The codec seam that CBOR-encodes an <c>authenticatorMakeCredential</c> response model.</param>
    /// <param name="decodeGetAssertionRequest">The codec seam that CBOR-decodes an <c>authenticatorGetAssertion</c> request.</param>
    /// <param name="encodeGetAssertionResponse">The codec seam that CBOR-encodes an <c>authenticatorGetAssertion</c> response model.</param>
    /// <param name="encodeCredentialPublicKey">The codec seam that CBOR-encodes a minted credential's public key.</param>
    /// <param name="encodePackedSelfAttestationStatement">The codec seam that CBOR-encodes a self-attestation packed <c>attStmt</c>.</param>
    /// <param name="decodeClientPinRequest">
    /// The codec seam that CBOR-decodes an <c>authenticatorClientPIN</c> request — required (decision 9):
    /// <c>authenticatorGetInfo</c> always advertises <c>clientPin</c>/<c>pinUvAuthToken</c>, and a
    /// simulator must be able to decode every command it advertises.
    /// </param>
    /// <param name="encodeClientPinResponse">
    /// The codec seam that CBOR-encodes an <c>authenticatorClientPIN</c> response model — see
    /// <paramref name="decodeClientPinRequest"/>.
    /// </param>
    /// <param name="decodeAuthenticatorConfigRequest">
    /// The codec seam that CBOR-decodes an <c>authenticatorConfig</c> request — required (R7):
    /// <c>authenticatorGetInfo</c> always advertises <c>authnrCfg</c>, and a simulator must be able to
    /// decode every command it advertises.
    /// </param>
    /// <param name="decodeCredentialManagementRequest">
    /// The codec seam that CBOR-decodes an <c>authenticatorCredentialManagement</c> request — required
    /// (R1): <c>authenticatorGetInfo</c> always advertises <c>credMgmt</c>, and a simulator must be able
    /// to decode every command it advertises.
    /// </param>
    /// <param name="encodeCredentialManagementResponse">
    /// The codec seam that CBOR-encodes an <c>authenticatorCredentialManagement</c> response model — see
    /// <paramref name="decodeCredentialManagementRequest"/>.
    /// </param>
    /// <param name="decodeBioEnrollmentRequest">
    /// The codec seam that CBOR-decodes an <c>authenticatorBioEnrollment</c> request — required:
    /// <c>authenticatorGetInfo</c> always advertises <c>bioEnroll</c> present (true-or-false tri-state)
    /// from this wave on, and a simulator must be able to decode every command it advertises.
    /// </param>
    /// <param name="encodeBioEnrollmentResponse">
    /// The codec seam that CBOR-encodes an <c>authenticatorBioEnrollment</c> response model — see
    /// <paramref name="decodeBioEnrollmentRequest"/>.
    /// </param>
    /// <param name="decodeLargeBlobsRequest">
    /// The codec seam that CBOR-decodes an <c>authenticatorLargeBlobs</c> request — required:
    /// <c>authenticatorGetInfo</c> always advertises <c>largeBlobs:true</c>, and a simulator must be
    /// able to decode every command it advertises.
    /// </param>
    /// <param name="encodeLargeBlobsResponse">
    /// The codec seam that CBOR-encodes an <c>authenticatorLargeBlobs</c> <c>get</c> response model —
    /// see <paramref name="decodeLargeBlobsRequest"/>.
    /// </param>
    /// <param name="encodeMakeCredentialExtensionOutputs">
    /// The codec seam that CBOR-encodes the resolved <c>credProtect</c>/<c>hmac-secret</c>/
    /// <c>minPinLength</c>/<c>hmac-secret-mc</c> authData extensions output map — required, mirroring
    /// <paramref name="decodeCredentialManagementRequest"/>'s own "always advertised, so always
    /// decodable/encodable" posture: <c>authenticatorGetInfo</c> always advertises every one of these
    /// extensions (R1).
    /// </param>
    /// <param name="encodeGetAssertionExtensionOutputs">
    /// The codec seam that CBOR-encodes the resolved <c>hmac-secret</c> <c>authenticatorGetAssertion</c>
    /// authData extensions output map — required, see <paramref name="encodeMakeCredentialExtensionOutputs"/>.
    /// </param>
    /// <param name="aaguid">
    /// The authenticator's claimed AAGUID. When <see langword="null"/>, one is drawn from
    /// <paramref name="rng"/> instead of an inline magic value, matching CTAP 2.3 section 6.4's
    /// "claimed AAGUID" wording (the simulator's own model identifier, not a value borrowed from a
    /// real device).
    /// </param>
    /// <param name="supportedExtensions">
    /// The extension identifiers this authenticator model advertises in
    /// <c>authenticatorGetInfo</c>'s <c>extensions</c> member — a personalization knob, the same
    /// role a card simulator's constructor-supplied elementary files play. <see langword="null"/>
    /// (the default) resolves to <see cref="CtapAuthenticatorState.DefaultSupportedExtensions"/>
    /// (<see cref="CtapAuthenticatorState.Initial"/>'s own resolution), the real, unconditionally
    /// advertised list — not an omitted member.
    /// </param>
    /// <param name="residentCredentialCapacity">
    /// The maximum number of resident (discoverable) credentials this authenticator can hold at once,
    /// enforced as <c>CTAP2_ERR_KEY_STORE_FULL</c>. CTAP 2.3 mandates no specific number for this bound
    /// (only that SOME finite capacity exists) — this is a simulator-realism knob, defaulted to a small
    /// value so capacity exhaustion is reachable in a test without minting thousands of credentials.
    /// </param>
    /// <param name="rng">
    /// The random-number backend the AAGUID and every minted credential identifier are drawn from.
    /// Defaults to <see cref="RandomNumberGenerator.Fill(Span{byte})"/>. Tests inject a fixed-pattern
    /// delegate for deterministic, independently-reproducible values.
    /// </param>
    /// <param name="credentialSigningBackend">
    /// The credential-minting backend for <c>authenticatorMakeCredential</c>. When <see langword="null"/>
    /// (the default), every <c>authenticatorMakeCredential</c> request answers
    /// <c>CTAP2_ERR_UNSUPPORTED_ALGORITHM</c>, mirroring <c>Verifiable.Tpm.Automata.TpmSimulator</c>'s
    /// "no backend, no crypto commands" convention.
    /// </param>
    /// <param name="timeProvider">The time source for trace timestamps. Defaults to <see cref="System.TimeProvider.System"/>.</param>
    /// <param name="pinUvAuthKeyAgreementPool">
    /// The memory pool the two PIN/UV auth protocol key-agreement key pairs (CTAP 2.3 §6.5.6/§6.5.7)
    /// are minted from at construction — a one-time event, independent of any later command's own
    /// pool. Defaults to <see cref="Lumoin.Base.BaseMemoryPool.Shared"/> when <see langword="null"/>.
    /// </param>
    /// <param name="simulateFingerprintCapture">
    /// The R8 outcome-injection knob for <c>enrollBegin</c>'s/<c>enrollCaptureNextSample</c>'s own
    /// fingerprint sensor simulation. Defaults to always <see cref="WellKnownCtapLastEnrollSampleStatuses.Good"/>
    /// (the ideal-sensor personalization) when <see langword="null"/>. A composition-time
    /// personalization knob, never a test-only seam — mirroring <paramref name="rng"/>'s own posture.
    /// </param>
    /// <param name="simulateBuiltInUv">
    /// The R8 outcome-injection knob for <c>performBuiltInUv</c>'s own simulated gesture. Defaults to
    /// always <see cref="CtapBuiltInUvAttemptOutcome.Success"/> (the ideal-sensor personalization) when
    /// <see langword="null"/>. A composition-time personalization knob, never a test-only seam — mirroring
    /// <paramref name="simulateFingerprintCapture"/>'s own posture.
    /// </param>
    /// <param name="simulateUserPresence">
    /// The R1 outcome-injection knob for <c>authenticatorMakeCredential</c>'s/
    /// <c>authenticatorGetAssertion</c>'s own :2840 user-presence collection. Defaults to always
    /// <see cref="CtapUserPresenceDecision.Granted"/> (the ideal-user personalization) when
    /// <see langword="null"/> — preserving every existing test's and mc's own historical hardcoded
    /// <c>userPresent: true</c> behavior byte-for-byte. A composition-time personalization knob, never a
    /// test-only seam — mirroring <paramref name="simulateBuiltInUv"/>'s own posture.
    /// </param>
    /// <param name="enterpriseAttestationProvisioning">
    /// The vendor-burned-in enterprise attestation material (waveep R1), threaded verbatim into
    /// <see cref="CtapAuthenticatorState.Initial"/>. <see langword="null"/> (the default) yields a
    /// non-enterprise-attestation-capable authenticator — the same personalization-knob posture as
    /// <paramref name="aaguid"/>/<paramref name="supportedExtensions"/>. When supplied, ownership
    /// transfers to this simulator: <see cref="Dispose"/> disposes it alongside every other
    /// construction-time-minted secret.
    /// </param>
    /// <param name="encodePackedCertifiedAttestationStatement">
    /// The codec seam that CBOR-encodes a certified (enterprise) packed <c>attStmt</c> (waveep R7).
    /// <see langword="null"/> (the default) is only safe when <paramref name="enterpriseAttestationProvisioning"/>
    /// is ALSO <see langword="null"/> — mc Step 9 can never grant an enterprise attestation without
    /// provisioning material, so the certified branch is then structurally unreachable.
    /// </param>
    /// <param name="firmwareVersion">
    /// The authenticator model's firmware version (getInfo member <c>0x0E</c>, CTAP 2.3 snapshot lines
    /// 4469-4475), threaded verbatim into <see cref="CtapAuthenticatorState.Initial"/> — a
    /// per-device-build identity value, the same personalization-knob posture as
    /// <paramref name="aaguid"/>. Defaults to <c>1</c>, the lowest legal value for a version that "MUST
    /// increase" on every firmware release.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// Any of <paramref name="encodeGetInfoResponse"/>, <paramref name="decodeMakeCredentialRequest"/>,
    /// <paramref name="encodeMakeCredentialResponse"/>, <paramref name="decodeGetAssertionRequest"/>,
    /// <paramref name="encodeGetAssertionResponse"/>, <paramref name="encodeCredentialPublicKey"/>,
    /// <paramref name="encodePackedSelfAttestationStatement"/>, <paramref name="decodeClientPinRequest"/>,
    /// <paramref name="encodeClientPinResponse"/>, <paramref name="decodeAuthenticatorConfigRequest"/>,
    /// <paramref name="decodeCredentialManagementRequest"/>, <paramref name="encodeCredentialManagementResponse"/>,
    /// <paramref name="decodeBioEnrollmentRequest"/>, <paramref name="encodeBioEnrollmentResponse"/>,
    /// <paramref name="decodeLargeBlobsRequest"/>, <paramref name="encodeLargeBlobsResponse"/>,
    /// <paramref name="encodeMakeCredentialExtensionOutputs"/>, or
    /// <paramref name="encodeGetAssertionExtensionOutputs"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="residentCredentialCapacity"/> is negative, or <paramref name="firmwareVersion"/>
    /// is not positive.
    /// </exception>
    public CtapAuthenticatorSimulator(
        string runId,
        EncodeCtapGetInfoResponseDelegate encodeGetInfoResponse,
        DecodeCtapMakeCredentialRequestDelegate decodeMakeCredentialRequest,
        EncodeCtapMakeCredentialResponseDelegate encodeMakeCredentialResponse,
        DecodeCtapGetAssertionRequestDelegate decodeGetAssertionRequest,
        EncodeCtapGetAssertionResponseDelegate encodeGetAssertionResponse,
        EncodeCredentialPublicKeyDelegate encodeCredentialPublicKey,
        EncodePackedSelfAttestationStatementDelegate encodePackedSelfAttestationStatement,
        DecodeCtapClientPinRequestDelegate decodeClientPinRequest,
        EncodeCtapClientPinResponseDelegate encodeClientPinResponse,
        DecodeCtapAuthenticatorConfigRequestDelegate decodeAuthenticatorConfigRequest,
        DecodeCtapCredentialManagementRequestDelegate decodeCredentialManagementRequest,
        EncodeCtapCredentialManagementResponseDelegate encodeCredentialManagementResponse,
        DecodeCtapBioEnrollmentRequestDelegate decodeBioEnrollmentRequest,
        EncodeCtapBioEnrollmentResponseDelegate encodeBioEnrollmentResponse,
        DecodeCtapLargeBlobsRequestDelegate decodeLargeBlobsRequest,
        EncodeCtapLargeBlobsResponseDelegate encodeLargeBlobsResponse,
        EncodeCtapMakeCredentialExtensionOutputsDelegate encodeMakeCredentialExtensionOutputs,
        EncodeCtapGetAssertionExtensionOutputsDelegate encodeGetAssertionExtensionOutputs,
        Guid? aaguid = null,
        IReadOnlyList<string>? supportedExtensions = null,
        int residentCredentialCapacity = 8,
        FillEntropyDelegate? rng = null,
        CtapCredentialSigningBackend? credentialSigningBackend = null,
        TimeProvider? timeProvider = null,
        MemoryPool<byte>? pinUvAuthKeyAgreementPool = null,
        SimulateFingerprintCaptureDelegate? simulateFingerprintCapture = null,
        SimulateBuiltInUvDelegate? simulateBuiltInUv = null,
        SimulateUserPresenceDelegate? simulateUserPresence = null,
        CtapEnterpriseAttestationProvisioning? enterpriseAttestationProvisioning = null,
        EncodePackedCertifiedAttestationStatementDelegate? encodePackedCertifiedAttestationStatement = null,
        int firmwareVersion = 1)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(runId);
        ArgumentNullException.ThrowIfNull(encodeGetInfoResponse);
        ArgumentNullException.ThrowIfNull(decodeMakeCredentialRequest);
        ArgumentNullException.ThrowIfNull(encodeMakeCredentialResponse);
        ArgumentNullException.ThrowIfNull(decodeGetAssertionRequest);
        ArgumentNullException.ThrowIfNull(encodeGetAssertionResponse);
        ArgumentNullException.ThrowIfNull(encodeCredentialPublicKey);
        ArgumentNullException.ThrowIfNull(encodePackedSelfAttestationStatement);
        ArgumentNullException.ThrowIfNull(decodeClientPinRequest);
        ArgumentNullException.ThrowIfNull(encodeClientPinResponse);
        ArgumentNullException.ThrowIfNull(decodeAuthenticatorConfigRequest);
        ArgumentNullException.ThrowIfNull(decodeCredentialManagementRequest);
        ArgumentNullException.ThrowIfNull(encodeCredentialManagementResponse);
        ArgumentNullException.ThrowIfNull(decodeBioEnrollmentRequest);
        ArgumentNullException.ThrowIfNull(encodeBioEnrollmentResponse);
        ArgumentNullException.ThrowIfNull(decodeLargeBlobsRequest);
        ArgumentNullException.ThrowIfNull(encodeLargeBlobsResponse);
        ArgumentNullException.ThrowIfNull(encodeMakeCredentialExtensionOutputs);
        ArgumentNullException.ThrowIfNull(encodeGetAssertionExtensionOutputs);
        ArgumentOutOfRangeException.ThrowIfNegative(residentCredentialCapacity);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(firmwareVersion);

        EncodeGetInfoResponse = encodeGetInfoResponse;
        DecodeMakeCredentialRequest = decodeMakeCredentialRequest;
        EncodeMakeCredentialResponse = encodeMakeCredentialResponse;
        DecodeGetAssertionRequest = decodeGetAssertionRequest;
        EncodeGetAssertionResponse = encodeGetAssertionResponse;
        EncodeCredentialPublicKey = encodeCredentialPublicKey;
        EncodePackedSelfAttestationStatement = encodePackedSelfAttestationStatement;
        EncodePackedCertifiedAttestationStatement = encodePackedCertifiedAttestationStatement;
        CredentialSigningBackend = credentialSigningBackend;
        TimeProvider = timeProvider ?? TimeProvider.System;
        Rng = rng ?? RandomNumberGenerator.Fill;
        SimulateFingerprintCapture = simulateFingerprintCapture ?? DefaultSimulateFingerprintCapture;
        SimulateBuiltInUv = simulateBuiltInUv ?? DefaultSimulateBuiltInUv;
        SimulateUserPresence = simulateUserPresence ?? DefaultSimulateUserPresence;
        DecodeClientPinRequest = decodeClientPinRequest;
        EncodeClientPinResponse = encodeClientPinResponse;
        DecodeAuthenticatorConfigRequest = decodeAuthenticatorConfigRequest;
        DecodeCredentialManagementRequest = decodeCredentialManagementRequest;
        EncodeCredentialManagementResponse = encodeCredentialManagementResponse;
        DecodeBioEnrollmentRequest = decodeBioEnrollmentRequest;
        EncodeBioEnrollmentResponse = encodeBioEnrollmentResponse;
        DecodeLargeBlobsRequest = decodeLargeBlobsRequest;
        EncodeLargeBlobsResponse = encodeLargeBlobsResponse;
        EncodeMakeCredentialExtensionOutputs = encodeMakeCredentialExtensionOutputs;
        EncodeGetAssertionExtensionOutputs = encodeGetAssertionExtensionOutputs;

        Guid resolvedAaguid = aaguid ?? DrawAaguid(Rng);

        Automaton = new PushdownAutomaton<CtapAuthenticatorState, CtapAuthenticatorInput, CtapAuthenticatorStackSymbol>(
            runId: runId,
            initialState: CtapAuthenticatorState.Initial(
                resolvedAaguid, TimeProvider.GetUtcNow(), supportedExtensions, residentCredentialCapacity, pinUvAuthKeyAgreementPool,
                enterpriseAttestationProvisioning, firmwareVersion),
            initialStackSymbol: CtapAuthenticatorStackSymbol.Session,
            transition: CtapAuthenticatorTransitions.Create(),
            acceptPredicate: static _ => true,
            timeProvider: TimeProvider);
    }


    /// <inheritdoc />
    public IDisposable Subscribe(IObserver<TraceEntry<CtapAuthenticatorState, CtapAuthenticatorInput>> observer) =>
        Automaton.Subscribe(observer);


    /// <summary>
    /// Simulates a power cycle of the authenticator (CTAP 2.3 §6.5.5.1's power-up <c>initialize()</c>):
    /// mints a fresh key-agreement key pair and a fresh <c>pinUvAuthToken</c> for both PIN/UV auth
    /// protocols, disposing the material they replace, and clears the power-cycle latch and the
    /// consecutive-mismatch counter — see <see cref="CtapAuthenticatorState.PowerCycle"/> for exactly
    /// what is preserved and what is refreshed. This is a simulator-level seam, not a CTAP2 command:
    /// it takes effect immediately, outside <see cref="TransceiveAsync"/> and the automaton's transition
    /// graph, the same way unplugging and replugging a real security key is not itself a wire request.
    /// </summary>
    /// <remarks>
    /// Reassigns <see cref="Automaton"/> to a freshly hydrated <see cref="PushdownAutomaton{TState, TInput, TStackSymbol}"/>
    /// carrying the power-cycled state, same run id/stack/step count as before. An observer already
    /// subscribed via <see cref="Subscribe"/> before this call remains attached to the PRIOR automaton
    /// instance and will not see trace entries for commands processed after the power cycle; this
    /// simulator has no production consumer that subscribes and then power-cycles, so the gap is
    /// unobserved in practice.
    /// </remarks>
    /// <param name="keyAgreementPool">
    /// The memory pool the refreshed key-agreement key pairs and tokens are minted from. Defaults to
    /// <see cref="BaseMemoryPool.Shared"/> when <see langword="null"/>.
    /// </param>
    /// <exception cref="ObjectDisposedException">This instance has been disposed.</exception>
    public void PowerCycle(MemoryPool<byte>? keyAgreementPool = null)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        CtapAuthenticatorState powerCycledState = Automaton.CurrentState.PowerCycle(TimeProvider.GetUtcNow(), keyAgreementPool);

        Automaton = new PushdownAutomaton<CtapAuthenticatorState, CtapAuthenticatorInput, CtapAuthenticatorStackSymbol>(
            runId: Automaton.RunId,
            savedState: powerCycledState,
            savedStack: Automaton.GetStack(),
            savedStepCount: Automaton.StepCount,
            transition: CtapAuthenticatorTransitions.Create(),
            acceptPredicate: static _ => true,
            timeProvider: TimeProvider);
    }


    /// <summary>
    /// Processes one complete CTAP2 request envelope and produces its response. Has the
    /// <see cref="Ctap2TransceiveDelegate"/> shape.
    /// </summary>
    /// <param name="request">The complete CTAP2 request envelope (command byte plus CBOR parameters).</param>
    /// <param name="pool">The memory pool available for allocating the response buffer.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>
    /// The complete CTAP2 response envelope (status byte plus CBOR response data), in a
    /// <see cref="PooledMemory"/> rented from <paramref name="pool"/>; the caller owns it and must
    /// dispose it.
    /// </returns>
    /// <remarks>
    /// Never allows a user-presence wait to defer (<see cref="MakeCredentialRequested.IsUserPresenceDeferralAllowed"/>/
    /// <see cref="GetAssertionRequested.IsUserPresenceDeferralAllowed"/> stay <see langword="false"/> on
    /// every input this call builds, R2) — use <see cref="BeginDeferredTransceiveAsync"/> for a transport
    /// that supports deferral.
    /// </remarks>
    /// <exception cref="ObjectDisposedException">This instance has been disposed.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    public async ValueTask<PooledMemory> TransceiveAsync(ReadOnlyMemory<byte> request, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        if(request.IsEmpty)
        {
            return FrameError(WellKnownCtapStatusCodes.InvalidCommand, pool);
        }

        CtapMakeCredentialRequest? makeCredentialRequest;
        CtapGetAssertionRequest? getAssertionRequest;
        CtapCredentialManagementRequest? credentialManagementRequest;
        CtapAuthenticatorInput input;
        try
        {
            input = DecodeRequest(request, pool, out makeCredentialRequest, out getAssertionRequest, out credentialManagementRequest);
        }
        catch(Fido2FormatException exception)
        {
            return FrameError(MapDecodeFailureToStatusCode(exception.FailureKind), pool);
        }

        try
        {
            await RunWithEffectsAsync(input, pool, cancellationToken).ConfigureAwait(false);

            CtapAuthenticatorResponseIntent intent = Automaton.CurrentState.ResponseIntent
                ?? throw new InvalidOperationException("The automaton completed a step without producing a response intent.");

            return FrameFinalResponse(intent, pool);
        }
        finally
        {
            DisposeRequestCarriers(makeCredentialRequest, getAssertionRequest, credentialManagementRequest);
        }
    }


    /// <summary>
    /// Processes one complete CTAP2 request envelope over a transport that supports deferring a
    /// user-presence wait across separate wire round trips (CTAP 2.3 :10798, R2): decodes exactly like
    /// <see cref="TransceiveAsync"/>, but sets <see cref="MakeCredentialRequested.IsUserPresenceDeferralAllowed"/>/
    /// <see cref="GetAssertionRequested.IsUserPresenceDeferralAllowed"/> <see langword="true"/> on
    /// <c>authenticatorMakeCredential</c>/<c>authenticatorGetAssertion</c> inputs — every other command's
    /// input is unaffected and processes synchronously to completion exactly like <see cref="TransceiveAsync"/>.
    /// If the command's own user-presence collection concludes <see cref="CtapUserPresenceDecision.Pending"/>,
    /// this call PARKS it on <see cref="CtapAuthenticatorState.PendingUserPresenceWait"/> and returns
    /// immediately — see <see cref="PollDeferredTransceiveAsync"/>/<see cref="CancelDeferredTransceiveAsync"/>.
    /// </summary>
    /// <param name="request">The complete CTAP2 request envelope (command byte plus CBOR parameters).</param>
    /// <param name="pool">The memory pool available for allocating the response buffer.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>
    /// The complete CTAP2 response envelope, exactly like <see cref="TransceiveAsync"/>'s own return — OR
    /// a ZERO-LENGTH <see cref="PooledMemory"/> marking "the command parked awaiting user presence": every
    /// real CTAP2 response carries at least one status byte, so an empty result is unambiguous (the
    /// existing client wrappers already treat an empty response as a <see cref="Fido2FormatException"/>,
    /// i.e. never a legal final response, on the non-deferred <see cref="Ctap2TransceiveDelegate"/> shape).
    /// </returns>
    /// <exception cref="ObjectDisposedException">This instance has been disposed.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    public async ValueTask<PooledMemory> BeginDeferredTransceiveAsync(ReadOnlyMemory<byte> request, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        if(request.IsEmpty)
        {
            return FrameError(WellKnownCtapStatusCodes.InvalidCommand, pool);
        }

        CtapMakeCredentialRequest? makeCredentialRequest;
        CtapGetAssertionRequest? getAssertionRequest;
        CtapCredentialManagementRequest? credentialManagementRequest;
        CtapAuthenticatorInput input;
        try
        {
            input = DecodeRequest(request, pool, out makeCredentialRequest, out getAssertionRequest, out credentialManagementRequest);
        }
        catch(Fido2FormatException exception)
        {
            return FrameError(MapDecodeFailureToStatusCode(exception.FailureKind), pool);
        }

        //Only mc/ga ever collect user presence (R1) — every other command's input is unaffected.
        input = input switch
        {
            MakeCredentialRequested makeCredential => makeCredential with { IsUserPresenceDeferralAllowed = true },
            GetAssertionRequested getAssertion => getAssertion with { IsUserPresenceDeferralAllowed = true },
            _ => input
        };

        bool parked = false;
        try
        {
            try
            {
                await RunWithEffectsAsync(input, pool, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                //C-1: the pure transition commits an armed PendingUserPresenceWait to Automaton.CurrentState
                //in the SAME step that declares the collect action — the effectful loop steps first and
                //executes the action second, so a fault or cancellation out of SimulateUserPresence here
                //leaves the wait already resumable while parked stays false (no UserPresencePending intent
                //was ever produced) and this method's own finally is about to dispose the same carriers the
                //wait references. Tear the wait down before the fault propagates, so a later poll finds
                //nothing pending rather than resuming over disposed carriers.
                DisarmPendingUserPresenceWaitAfterCollectEffectFault();
                throw;
            }

            CtapAuthenticatorResponseIntent intent = Automaton.CurrentState.ResponseIntent
                ?? throw new InvalidOperationException("The automaton completed a step without producing a response intent.");

            if(intent is UserPresencePending)
            {
                //Ownership of the decoded request's carriers transferred into
                //Automaton.CurrentState.PendingUserPresenceWait (R2, trap 2) — this call must NOT dispose
                //them; they are released once the wait resolves, is cancelled, is superseded, or is
                //discarded by PowerCycle/FactoryReset.
                parked = true;

                return FrameDeferralPendingMarker(pool);
            }

            return FrameFinalResponse(intent, pool);
        }
        finally
        {
            if(!parked)
            {
                DisposeRequestCarriers(makeCredentialRequest, getAssertionRequest, credentialManagementRequest);
            }
        }
    }


    /// <summary>
    /// Tears down an armed <see cref="CtapAuthenticatorState.PendingUserPresenceWait"/> after
    /// <see cref="BeginDeferredTransceiveAsync"/>'s own user-presence collect effect faults or is
    /// cancelled (C-1): disposes it and rebuilds <see cref="Automaton"/> around the cleared slot — the
    /// same "reassign around a modified snapshot" seam <see cref="PowerCycle"/> uses to force state
    /// without replaying a transition — so no later <see cref="PollDeferredTransceiveAsync"/>/
    /// <see cref="CancelDeferredTransceiveAsync"/> can resume the wait over the carriers
    /// <see cref="BeginDeferredTransceiveAsync"/>'s own <c>finally</c> is about to dispose. A no-op when
    /// nothing is armed — the ordinary fault path for every command that never collects user presence, or
    /// one whose collect action already resolved (granted/denied/timed out) before a LATER effect in the
    /// same call faulted.
    /// </summary>
    private void DisarmPendingUserPresenceWaitAfterCollectEffectFault()
    {
        CtapPendingUserPresenceState? armed = Automaton.CurrentState.PendingUserPresenceWait;
        if(armed is null)
        {
            return;
        }

        armed.Dispose();

        Automaton = new PushdownAutomaton<CtapAuthenticatorState, CtapAuthenticatorInput, CtapAuthenticatorStackSymbol>(
            runId: Automaton.RunId,
            savedState: Automaton.CurrentState with { PendingUserPresenceWait = null },
            savedStack: Automaton.GetStack(),
            savedStepCount: Automaton.StepCount,
            transition: CtapAuthenticatorTransitions.Create(),
            acceptPredicate: static _ => true,
            timeProvider: TimeProvider);
    }


    /// <summary>
    /// Polls a parked user-presence wait (CTAP 2.3 :2840/:10818, R2).
    /// </summary>
    /// <param name="pool">The memory pool available for allocating the response buffer.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>
    /// A ZERO-LENGTH <see cref="PooledMemory"/> if the wait is still pending, otherwise the final CTAP2
    /// response envelope (success payload, <c>[0x27]</c>, <c>[0x2F]</c>, …) — see
    /// <see cref="BeginDeferredTransceiveAsync"/>'s identical empty-marker convention.
    /// </returns>
    /// <exception cref="ObjectDisposedException">This instance has been disposed.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">No user-presence wait is currently pending (internal-misuse guard: the pure transition itself never throws).</exception>
    public async ValueTask<PooledMemory> PollDeferredTransceiveAsync(MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        CtapPendingUserPresenceState? pendingBeforePoll = Automaton.CurrentState.PendingUserPresenceWait;
        if(pendingBeforePoll is null)
        {
            throw new InvalidOperationException("PollDeferredTransceiveAsync was called with no user-presence wait pending.");
        }

        await RunWithEffectsAsync(new UserPresencePollRequested(TimeProvider.GetUtcNow()), pool, cancellationToken).ConfigureAwait(false);

        CtapAuthenticatorResponseIntent intent = Automaton.CurrentState.ResponseIntent
            ?? throw new InvalidOperationException("The automaton completed a step without producing a response intent.");

        if(intent is UserPresencePending)
        {
            //Still parked — the pure transition kept PendingUserPresenceWait armed for the next poll.
            return FrameDeferralPendingMarker(pool);
        }

        //Resolved this call. A denied/timed-out resolution already disposed pendingBeforePoll's carriers
        //via the pure transition's own terminal discard; a granted-then-completed resolution left them
        //undisposed on purpose (ContinueMakeCredential/ContinueGetAssertion, and the credential-
        //generation/assertion-signing effect that followed, read them throughout this SAME call — see
        //CtapAuthenticatorTransitions.ClearPendingUserPresenceWait). This disposes them unconditionally:
        //SensitiveMemory's Dispose is idempotent, so an already-disposed carrier tolerates the second
        //call, and a granted-then-completed one is released exactly here, now that the resumed command's
        //own effectful loop has fully returned.
        pendingBeforePoll.Dispose();

        return FrameFinalResponse(intent, pool);
    }


    /// <summary>
    /// Cancels a parked user-presence wait (CTAP 2.3 :10821, R2).
    /// </summary>
    /// <param name="pool">The memory pool available for allocating the response buffer.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The final CTAP2 response envelope — always <c>[<see cref="WellKnownCtapStatusCodes.KeepaliveCancel"/>]</c>.</returns>
    /// <exception cref="ObjectDisposedException">This instance has been disposed.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">No user-presence wait is currently pending (internal-misuse guard: the pure transition itself never throws).</exception>
    public async ValueTask<PooledMemory> CancelDeferredTransceiveAsync(MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        if(Automaton.CurrentState.PendingUserPresenceWait is null)
        {
            throw new InvalidOperationException("CancelDeferredTransceiveAsync was called with no user-presence wait pending.");
        }

        await RunWithEffectsAsync(new UserPresenceCancelRequested(TimeProvider.GetUtcNow()), pool, cancellationToken).ConfigureAwait(false);

        CtapAuthenticatorResponseIntent intent = Automaton.CurrentState.ResponseIntent
            ?? throw new InvalidOperationException("The automaton completed a step without producing a response intent.");

        return FrameFinalResponse(intent, pool);
    }


    /// <summary>
    /// Decodes a CTAP2 request envelope's command byte and parameters into a
    /// <see cref="CtapAuthenticatorInput"/> — the shared decode switch <see cref="TransceiveAsync"/>/
    /// <see cref="BeginDeferredTransceiveAsync"/> both use.
    /// </summary>
    /// <param name="request">The complete CTAP2 request envelope, already confirmed non-empty by the caller.</param>
    /// <param name="pool">The memory pool available for decoding.</param>
    /// <param name="makeCredentialRequest">The decoded <c>authenticatorMakeCredential</c> request, if the command byte named one.</param>
    /// <param name="getAssertionRequest">The decoded <c>authenticatorGetAssertion</c> request, if the command byte named one.</param>
    /// <param name="credentialManagementRequest">The decoded <c>authenticatorCredentialManagement</c> request, if the command byte named one.</param>
    /// <returns>The decoded input.</returns>
    /// <exception cref="Fido2FormatException">The request's parameters did not decode.</exception>
    private CtapAuthenticatorInput DecodeRequest(
        ReadOnlyMemory<byte> request,
        MemoryPool<byte> pool,
        out CtapMakeCredentialRequest? makeCredentialRequest,
        out CtapGetAssertionRequest? getAssertionRequest,
        out CtapCredentialManagementRequest? credentialManagementRequest)
    {
        byte commandByte = request.Span[0];
        ReadOnlyMemory<byte> parameters = request[1..];

        makeCredentialRequest = null;
        getAssertionRequest = null;
        credentialManagementRequest = null;

        //Decoded here (outside the pure automaton) so the credential-signing backend's supported-
        //algorithm set — a composition-time dependency the pure transition has no access to — can be
        //consulted before the input is built, mirroring TpmSimulator's own "check backend presence
        //before entering the automaton" precedent for its object/signing commands. Every decode
        //delegate below throws Fido2FormatException uniformly on a malformed or incomplete request, so
        //that failure is caught once by each caller rather than duplicated per command.
        return commandByte switch
        {
            var command when WellKnownCtapCommands.IsGetInfo(command) => new GetInfoRequested(CredentialSigningBackend?.SupportedAlgorithms),
            var command when WellKnownCtapCommands.IsMakeCredential(command) =>
                BuildMakeCredentialInput(parameters, pool, DecodeMakeCredentialRequest, CredentialSigningBackend?.SupportedAlgorithms, TimeProvider, out makeCredentialRequest),
            var command when WellKnownCtapCommands.IsGetAssertion(command) =>
                BuildGetAssertionInput(parameters, pool, DecodeGetAssertionRequest, TimeProvider, out getAssertionRequest),
            var command when WellKnownCtapCommands.IsGetNextAssertion(command) => new GetNextAssertionRequested(TimeProvider.GetUtcNow()),
            var command when WellKnownCtapCommands.IsClientPin(command) =>
                new ClientPinRequested(DecodeClientPinRequest(parameters), TimeProvider.GetUtcNow()),
            var command when WellKnownCtapCommands.IsReset(command) => new ResetRequested(TimeProvider.GetUtcNow(), pool),

            //Step 1 (line 7953): subCommand absent -> CTAP2_ERR_MISSING_PARAMETER, realized at the
            //decode boundary — mirroring every other command's required-field-absence handling
            //(e.g. CtapClientPinRequestCborReader's own subCommand throw) rather than as a separate
            //pure-transition check, since a decoded request model has no way to represent "subCommand
            //was absent" once decoding has already failed. R7's classification (via
            //MapDecodeFailureToStatusCode) now discriminates that case from a genuinely malformed or
            //wrong-typed request instead of collapsing every decode failure onto MissingParameter; the
            //subCommand-absent sub-case this profile's own test matrix pins still resolves to the
            //identical status byte it always has.
            var command when WellKnownCtapCommands.IsAuthenticatorConfig(command) =>
                new AuthenticatorConfigRequested(DecodeAuthenticatorConfigRequest(parameters), TimeProvider.GetUtcNow()),

            //Step 1's equivalent (the required subCommand member absent) is realized at the decode
            //boundary, mirroring authenticatorConfig's own identical handling above.
            var command when WellKnownCtapCommands.IsCredentialManagement(command) =>
                BuildCredentialManagementInput(parameters, pool, DecodeCredentialManagementRequest, TimeProvider, out credentialManagementRequest),

            var command when WellKnownCtapCommands.IsBioEnrollment(command) =>
                new BioEnrollmentRequested(DecodeBioEnrollmentRequest(parameters), TimeProvider.GetUtcNow()),
            var command when WellKnownCtapCommands.IsLargeBlobs(command) =>
                new LargeBlobsRequested(DecodeLargeBlobsRequest(parameters), TimeProvider.GetUtcNow()),
            _ => new UnsupportedCtapCommandReceived(commandByte)
        };
    }


    /// <summary>
    /// Frames a completed automaton response intent into its final CTAP2 wire envelope — the shared
    /// mapping <see cref="TransceiveAsync"/>/<see cref="PollDeferredTransceiveAsync"/>/
    /// <see cref="CancelDeferredTransceiveAsync"/> use.
    /// </summary>
    /// <param name="intent">The completed intent.</param>
    /// <param name="pool">The memory pool available for allocating the response buffer.</param>
    /// <returns>The final CTAP2 response envelope.</returns>
    /// <exception cref="InvalidOperationException">
    /// <paramref name="intent"/> is <see cref="UserPresencePending"/> — never a legal FINAL response.
    /// <see cref="TransceiveAsync"/>'s own inputs never allow deferral, so it can never observe this
    /// intent; <see cref="BeginDeferredTransceiveAsync"/>/<see cref="PollDeferredTransceiveAsync"/> check
    /// for it themselves and map it to the empty "still pending" marker before ever reaching this method.
    /// </exception>
    private PooledMemory FrameFinalResponse(CtapAuthenticatorResponseIntent intent, MemoryPool<byte> pool) =>
        intent switch
        {
            GetInfoResponseReady getInfo => FrameSuccess(EncodeGetInfoResponse(getInfo.Response), pool),
            MakeCredentialResponseReady makeCredential => FrameSuccess(EncodeMakeCredentialResponse(makeCredential.Response), pool),
            GetAssertionResponseReady getAssertion => FrameSuccess(EncodeGetAssertionResponse(getAssertion.Response), pool),
            ClientPinResponseReady clientPin => FrameSuccess(EncodeClientPinResponse(clientPin.Response), pool),
            AuthenticatorConfigResponseReady => FrameError(WellKnownCtapStatusCodes.Ok, pool),
            AuthenticatorResetResponseReady => FrameError(WellKnownCtapStatusCodes.Ok, pool),
            CredentialManagementResponseReady credentialManagement => credentialManagement.Response is CtapCredentialManagementResponse response
                ? FrameSuccess(EncodeCredentialManagementResponse(response), pool)
                : FrameError(WellKnownCtapStatusCodes.Ok, pool),
            BioEnrollmentResponseReady bioEnrollment => bioEnrollment.Response is CtapBioEnrollmentResponse bioEnrollmentResponse
                ? FrameSuccess(EncodeBioEnrollmentResponse(bioEnrollmentResponse), pool)
                : FrameError(WellKnownCtapStatusCodes.Ok, pool),
            LargeBlobsResponseReady largeBlobs => largeBlobs.Response is CtapLargeBlobsResponse largeBlobsResponse
                ? FrameSuccess(EncodeLargeBlobsResponse(largeBlobsResponse), pool)
                : FrameError(WellKnownCtapStatusCodes.Ok, pool),
            CtapErrorResponse error => FrameError(error.StatusCode, pool),
            UnsupportedCommandResponse => FrameError(WellKnownCtapStatusCodes.InvalidCommand, pool),
            UserPresencePending => throw new InvalidOperationException(
                "UserPresencePending is not a legal final response; callers that allow deferral must check for it before calling FrameFinalResponse."),
            _ => throw new NotSupportedException($"No response framing is registered for intent '{intent.GetType().Name}'.")
        };


    /// <summary>
    /// Prefixes a CBOR-encoded response payload with the CTAP2_OK status byte, per CTAP 2.3 section 8's
    /// "status byte followed by CBOR-encoded response data" response shape, into a buffer rented from
    /// the pool: the one copy of the payload's bytes happens here, out of the codec seam's own wrapped
    /// array and into the pooled envelope the caller owns.
    /// </summary>
    private static PooledMemory FrameSuccess(TaggedMemory<byte> payload, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> storage = pool.Rent(payload.Length + 1);
        try
        {
            Span<byte> framed = storage.Memory.Span;
            framed[0] = WellKnownCtapStatusCodes.Ok;
            payload.Span.CopyTo(framed[1..]);

            return new PooledMemory(storage, payload.Length + 1, Fido2BufferTags.CtapResponseEnvelope);
        }
        catch
        {
            storage.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Frames a bare status-byte error response (CTAP 2.3 section 8.2: Status codes) with no CBOR body,
    /// into a one-byte buffer rented from the pool.
    /// </summary>
    private static PooledMemory FrameError(byte statusCode, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> storage = pool.Rent(1);
        try
        {
            storage.Memory.Span[0] = statusCode;

            return new PooledMemory(storage, 1, Fido2BufferTags.CtapResponseEnvelope);
        }
        catch
        {
            storage.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Builds the "command parked awaiting user presence" marker (R2): a ZERO-LENGTH <see cref="PooledMemory"/>,
    /// unambiguous since every real CTAP2 response carries at least one status byte.
    /// </summary>
    private static PooledMemory FrameDeferralPendingMarker(MemoryPool<byte> pool) =>
        PooledMemory.FromBytes(ReadOnlySpan<byte>.Empty, pool, Fido2BufferTags.CtapResponseEnvelope);


    /// <summary>
    /// Maps a decode-boundary Fido2FormatException's classification to its CTAP2 status byte (R7): the
    /// tri-code split ships uniformly across every body-carrying command boundary <see cref="DecodeRequest"/>
    /// covers, so this one method is the entire classification-to-status-byte seam this wave adds.
    /// </summary>
    private static byte MapDecodeFailureToStatusCode(Fido2FormatFailureKind failureKind) => failureKind switch
    {
        Fido2FormatFailureKind.MissingRequiredParameter => WellKnownCtapStatusCodes.MissingParameter,
        Fido2FormatFailureKind.UnexpectedStructure => WellKnownCtapStatusCodes.CborUnexpectedType,
        Fido2FormatFailureKind.MalformedCbor => WellKnownCtapStatusCodes.InvalidCbor,
        _ => throw new NotSupportedException($"No status code is registered for decode failure kind '{failureKind}'.")
    };


    /// <summary>
    /// Decodes an authenticatorMakeCredential request and selects the algorithm identifier — the first
    /// PubKeyCredParams entry the credential-signing backend's supported-algorithm set contains (CTAP
    /// 2.3, section 6.1.2, step 3). The decoded request is also handed back through makeCredentialRequest
    /// so DisposeRequestCarriers can release its pooled carriers regardless of what happens once the
    /// automaton takes over.
    /// </summary>
    private static MakeCredentialRequested BuildMakeCredentialInput(
        ReadOnlyMemory<byte> parameters,
        MemoryPool<byte> pool,
        DecodeCtapMakeCredentialRequestDelegate decodeMakeCredentialRequest,
        IReadOnlyList<int>? supportedAlgorithms,
        TimeProvider timeProvider,
        out CtapMakeCredentialRequest makeCredentialRequest)
    {
        makeCredentialRequest = decodeMakeCredentialRequest(parameters, pool);
        int? selectedAlgorithm = SelectSupportedAlgorithm(makeCredentialRequest.PubKeyCredParams, supportedAlgorithms);

        return new MakeCredentialRequested(makeCredentialRequest, selectedAlgorithm, timeProvider.GetUtcNow());
    }


    /// <summary>
    /// Decodes an authenticatorGetAssertion request, handing it back through getAssertionRequest so
    /// DisposeRequestCarriers can release its pooled carriers regardless of what happens once the
    /// automaton takes over.
    /// </summary>
    private static GetAssertionRequested BuildGetAssertionInput(
        ReadOnlyMemory<byte> parameters,
        MemoryPool<byte> pool,
        DecodeCtapGetAssertionRequestDelegate decodeGetAssertionRequest,
        TimeProvider timeProvider,
        out CtapGetAssertionRequest getAssertionRequest)
    {
        getAssertionRequest = decodeGetAssertionRequest(parameters, pool);

        return new GetAssertionRequested(getAssertionRequest, timeProvider.GetUtcNow());
    }


    /// <summary>
    /// Decodes an authenticatorCredentialManagement request, handing it back through
    /// credentialManagementRequest so DisposeRequestCarriers can release its pooled carriers regardless
    /// of what happens once the automaton takes over.
    /// </summary>
    private static CredentialManagementRequested BuildCredentialManagementInput(
        ReadOnlyMemory<byte> parameters,
        MemoryPool<byte> pool,
        DecodeCtapCredentialManagementRequestDelegate decodeCredentialManagementRequest,
        TimeProvider timeProvider,
        out CtapCredentialManagementRequest credentialManagementRequest)
    {
        credentialManagementRequest = decodeCredentialManagementRequest(parameters, pool);

        return new CredentialManagementRequested(credentialManagementRequest, timeProvider.GetUtcNow());
    }


    /// <summary>
    /// Disposes whichever of the decoded request's own SensitiveMemory carriers the credential store did
    /// not adopt: the store always copies what it needs to keep (a fresh UserHandle; a freshly minted
    /// CredentialId never derived from the request at all), so every carrier the decode delegate handed
    /// back is disposed here regardless of whether the command succeeded, was rejected, or never reached
    /// the credential store. NOT called for a command that PARKED — see <see cref="BeginDeferredTransceiveAsync"/>.
    /// </summary>
    private static void DisposeRequestCarriers(
        CtapMakeCredentialRequest? makeCredentialRequest, CtapGetAssertionRequest? getAssertionRequest, CtapCredentialManagementRequest? credentialManagementRequest)
    {
        if(makeCredentialRequest is not null)
        {
            makeCredentialRequest.ClientDataHash.Dispose();
            makeCredentialRequest.User.Id.Dispose();

            if(makeCredentialRequest.ExcludeList is not null)
            {
                foreach(PublicKeyCredentialDescriptor descriptor in makeCredentialRequest.ExcludeList)
                {
                    descriptor.Id.Dispose();
                }
            }
        }

        if(getAssertionRequest is not null)
        {
            getAssertionRequest.ClientDataHash.Dispose();

            if(getAssertionRequest.AllowList is not null)
            {
                foreach(PublicKeyCredentialDescriptor descriptor in getAssertionRequest.AllowList)
                {
                    descriptor.Id.Dispose();
                }
            }
        }

        if(credentialManagementRequest is not null)
        {
            credentialManagementRequest.CredentialId?.Id.Dispose();
            credentialManagementRequest.User?.Id.Dispose();
        }
    }


    /// <summary>
    /// Drives the automaton through the effectful loop: step, execute any action the new state
    /// declares, feed the result back, repeat until no action remains.
    /// </summary>
    private async ValueTask RunWithEffectsAsync(CtapAuthenticatorInput input, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        _ = await PdaRunner.StepWithEffectsAsync<CtapAuthenticatorState, CtapAuthenticatorInput, CtapActionContext>(
            Automaton.CurrentState,
            Automaton.StepCount,
            input,
            step: StepCoreAsync,
            actionExtractor: static state => state.NextAction,
            actionExecutor: static (action, context, token) => ExecuteAction(action, context, token),
            actionContext: new CtapActionContext(
                Rng, pool, Aaguid, CredentialSigningBackend, EncodeCredentialPublicKey, EncodePackedSelfAttestationStatement,
                EncodePackedCertifiedAttestationStatement, Automaton.CurrentState.EnterpriseAttestationProvisioning,
                EncodeMakeCredentialExtensionOutputs, EncodeGetAssertionExtensionOutputs, SimulateFingerprintCapture, SimulateBuiltInUv,
                SimulateUserPresence, TimeProvider),
            TimeProvider,
            cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Bridges the runner's value-threaded step to the live automaton (one live automaton per
    /// simulated authenticator holds the state of record). A step that does not apply — the
    /// transition faulted or halted — is surfaced as a thrown exception rather than folded back into
    /// <see cref="Foundation.Automata.PdaRunner.StepWithEffectsAsync{TState, TInput, TContext}"/>'s
    /// action loop: on a fault or halt, <see cref="PushdownAutomaton{TState, TInput, TStackSymbol}.StepAsync"/>
    /// leaves <see cref="PushdownAutomaton{TState, TInput, TStackSymbol}.CurrentState"/> exactly as it
    /// was before the call, including whatever <c>NextAction</c> the prior successful transition left
    /// in place; returning that unchanged state here (rather than throwing) would make the action loop
    /// re-dispatch the same already-executed action forever, since the loop's only exit condition is
    /// the state's <c>NextAction</c> clearing to <see cref="NullAction"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// The transition faulted — see <see cref="PushdownAutomaton{TState, TInput, TStackSymbol}.FaultException"/>
    /// for the original exception, carried as this exception's <see cref="Exception.InnerException"/> —
    /// or halted (no transition is defined for the current input).
    /// </exception>
    private async ValueTask<(CtapAuthenticatorState State, int StepCount)> StepCoreAsync(
        CtapAuthenticatorState currentState, int currentStepCount, CtapAuthenticatorInput input, TimeProvider time, CancellationToken cancellationToken)
    {
        bool stepped = await Automaton.StepAsync(input, cancellationToken).ConfigureAwait(false);
        if(!stepped)
        {
            throw Automaton.IsFaulted
                ? new InvalidOperationException("The CTAP authenticator automaton's transition faulted.", Automaton.FaultException)
                : new InvalidOperationException("The CTAP authenticator automaton halted: no transition is defined for the current input.");
        }

        return (Automaton.CurrentState, Automaton.StepCount);
    }


    /// <summary>
    /// Executes the effectful work a transition declared and feeds the result back as the next input:
    /// <c>authenticatorMakeCredential</c> mints a fresh credential key pair, <c>authenticatorGetAssertion</c>
    /// signs an assertion with a stored credential's private key, a presented <c>pinUvAuthParam</c> is
    /// verified against its selected protocol's <c>pinUvAuthToken</c>, <c>authenticatorClientPIN</c>'s
    /// <c>getKeyAgreement</c> computes a key-agreement key pair's COSE_Key view, and <c>setPIN</c>/
    /// <c>changePIN</c>/<c>getPinToken</c>/<c>getPinUvAuthTokenUsingPinWithPermissions</c> each run their
    /// own <c>decapsulate</c>/<c>verify</c>/<c>decrypt</c>/hash-or-mint crypto sequence.
    /// </summary>
    private static async ValueTask<CtapAuthenticatorInput> ExecuteAction(PdaAction action, CtapActionContext context, CancellationToken cancellationToken) =>
        action switch
        {
            CtapGenerateCredentialKeyAction generateAction => await GenerateCredentialAsync(generateAction, context, cancellationToken).ConfigureAwait(false),
            CtapSignAssertionAction signAction => await SignAssertionAsync(signAction, context, cancellationToken).ConfigureAwait(false),
            CtapVerifyPinUvAuthTokenAction verifyAction => await VerifyPinUvAuthTokenAsync(verifyAction, context, cancellationToken).ConfigureAwait(false),
            CtapComputeKeyAgreementPublicKeyAction keyAgreementAction => await ComputeKeyAgreementPublicKeyAsync(keyAgreementAction, cancellationToken).ConfigureAwait(false),
            CtapEstablishPinAction establishPinAction => await EstablishPinAsync(establishPinAction, context, cancellationToken).ConfigureAwait(false),
            CtapChangePinAction changePinAction => await ChangePinAsync(changePinAction, context, cancellationToken).ConfigureAwait(false),
            CtapIssuePinTokenAction issuePinTokenAction => await IssuePinTokenAsync(issuePinTokenAction, context, cancellationToken).ConfigureAwait(false),
            CtapIssueUvTokenAction issueUvTokenAction => await IssueUvTokenAsync(issueUvTokenAction, context, cancellationToken).ConfigureAwait(false),
            CtapPerformBuiltInUvAction performBuiltInUvAction => await PerformBuiltInUvAsync(performBuiltInUvAction, context, cancellationToken).ConfigureAwait(false),
            CtapVerifyAuthenticatorConfigTokenAction verifyConfigAction => await VerifyAuthenticatorConfigTokenAsync(verifyConfigAction, context, cancellationToken).ConfigureAwait(false),
            CtapResetPinUvAuthTokensAction resetTokensAction => await ResetPinUvAuthTokensAsync(resetTokensAction, context, cancellationToken).ConfigureAwait(false),
            CtapFactoryResetKeyMaterialAction factoryResetAction => await FactoryResetKeyMaterialAsync(factoryResetAction, context, cancellationToken).ConfigureAwait(false),
            CtapVerifyCredentialManagementTokenAction verifyCredentialManagementAction =>
                await VerifyCredentialManagementTokenAsync(verifyCredentialManagementAction, context, cancellationToken).ConfigureAwait(false),
            CtapEmitCredentialManagementRpAction emitRpAction => await EmitCredentialManagementRpAsync(emitRpAction, context, cancellationToken).ConfigureAwait(false),
            CtapLocateCredentialManagementCredentialsAction locateAction =>
                await LocateCredentialManagementCredentialsAsync(locateAction, context, cancellationToken).ConfigureAwait(false),
            CtapVerifyBioEnrollmentTokenAction verifyBioEnrollmentAction =>
                await VerifyBioEnrollmentTokenAsync(verifyBioEnrollmentAction, context, cancellationToken).ConfigureAwait(false),
            CtapBeginBioEnrollmentCaptureAction =>
                await BeginBioEnrollmentCaptureAsync(context, cancellationToken).ConfigureAwait(false),
            CtapContinueBioEnrollmentCaptureAction =>
                await ContinueBioEnrollmentCaptureAsync(context, cancellationToken).ConfigureAwait(false),
            CtapVerifyLargeBlobsTokenAction verifyLargeBlobsAction =>
                await VerifyLargeBlobsTokenAsync(verifyLargeBlobsAction, context, cancellationToken).ConfigureAwait(false),
            CtapCommitLargeBlobArrayAction commitLargeBlobArrayAction =>
                await CommitLargeBlobArrayAsync(commitLargeBlobArrayAction, context, cancellationToken).ConfigureAwait(false),
            CtapCollectUserPresenceAction => await CollectUserPresenceAsync(context, cancellationToken).ConfigureAwait(false),
            _ => throw new NotSupportedException($"No executor is registered for action '{action.GetType().Name}'.")
        };


    /// <summary>
    /// The user-presence collection effect (CTAP 2.3 :2840, R1): consults the injected
    /// <see cref="SimulateUserPresenceDelegate"/> and folds its answer back with the instant it was
    /// collected — the pure transition never reads a clock itself.
    /// </summary>
    private static async ValueTask<CtapAuthenticatorInput> CollectUserPresenceAsync(CtapActionContext context, CancellationToken cancellationToken)
    {
        CtapUserPresenceDecision decision = await context.SimulateUserPresence(cancellationToken).ConfigureAwait(false);

        return new UserPresenceDecisionCollected(decision, context.TimeProvider.GetUtcNow());
    }


    /// <summary>
    /// <c>authenticatorClientPIN</c>'s <c>getKeyAgreement</c> effect: resolves a
    /// <see cref="CtapPinUvAuthProtocol"/> instance for <see cref="CtapComputeKeyAgreementPublicKeyAction.ProtocolId"/>
    /// through the registered production crypto primitives and calls <see cref="CtapPinUvAuthProtocol.GetPublicKey"/>
    /// against <see cref="CtapComputeKeyAgreementPublicKeyAction.OwnPublicKey"/>.
    /// </summary>
    private static ValueTask<CtapAuthenticatorInput> ComputeKeyAgreementPublicKeyAsync(CtapComputeKeyAgreementPublicKeyAction action, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        CtapPinUvAuthProtocol protocol = CtapPinUvAuthProtocol.CreateDefault(action.ProtocolId);
        CoseKey publicKey = protocol.GetPublicKey(action.OwnPublicKey);

        return ValueTask.FromResult<CtapAuthenticatorInput>(new ClientPinKeyAgreementComputed(publicKey));
    }


    /// <summary>
    /// <c>setPIN</c>'s effect (CTAP 2.3 §6.5.5.5, lines 5570-5593): <c>decapsulate</c> against
    /// <see cref="CtapEstablishPinAction.PeerKeyAgreement"/>, <c>verify(sharedSecret, newPinEnc,
    /// pinUvAuthParam)</c>, <c>decrypt(sharedSecret, newPinEnc)</c>, then the pure length/policy checks
    /// and <c>LEFT(SHA-256(newPin), 16)</c> hash — all over the decrypted PIN plaintext, which never
    /// crosses the fold-back boundary (only the outcome discriminant, the code-point count, and the
    /// owned hash carrier do). The shared secret is zeroed and disposed on every path.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A <c>newPinEnc</c> that decrypts successfully but is not well-formed UTF-8 makes
    /// <see cref="CountUtf8CodePoints"/> throw <see cref="Fido2FormatException"/>, which the same guard
    /// that catches <c>decrypt(sharedSecret, newPinEnc)</c>'s own failures
    /// (<see cref="IsPinCryptoOperationFailure"/>) also catches, folding both into the identical
    /// <see cref="CtapSetPinOutcomeKind.DecryptFailed"/> outcome and, downstream, the CTAP2_ERR_PIN_AUTH_INVALID
    /// status line 5578 assigns to a <c>decrypt</c> error. This is the adopted fail-closed disposition:
    /// the spec defines no distinct status for a malformed-UTF-8 <c>newPin</c>, and the only party who can
    /// ever construct a <c>newPinEnc</c> that decrypts to malformed UTF-8 is a platform that already holds
    /// the shared secret, so collapsing the case into the neighboring decrypt-error status neither hides a
    /// reachable-by-an-attacker branch nor invents a status the spec does not define.
    /// </para>
    /// <para>
    /// CTAP 2.3 §6.5.5.5 (lines 5586-5588) lets an authenticator "impose arbitrary, additional
    /// constraints on PINs" beyond the mandatory 64-byte <c>paddedNewPin</c> length, trailing-0x00
    /// strip, and <see cref="CtapAuthenticatorState.MinPinCodePointLength"/> checks already applied
    /// above. This is the adopted disposition: the MAY is declined, so
    /// <see cref="CtapSetPinOutcomeKind.PolicyViolation"/> is returned only for the minimum-length
    /// failure, and no additional constraint ever rejects a <c>newPin</c> that already satisfies it.
    /// </para>
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "ComputeStoredPinHash's returned DigestValue transfers ownership into the returned PinEstablishmentCompleted.NewPinHash on the Success path; the analyzer cannot see the ownership transfer through the record construction.")]
    private static async ValueTask<CtapAuthenticatorInput> EstablishPinAsync(CtapEstablishPinAction action, CtapActionContext context, CancellationToken cancellationToken)
    {
        CtapPinUvAuthProtocol protocol = CtapPinUvAuthProtocol.CreateDefault(action.ProtocolId);
        IMemoryOwner<byte>? sharedSecret = null;
        try
        {
            try
            {
                sharedSecret = await protocol.DecapsulateAsync(action.OwnPrivateKey, action.PeerKeyAgreement, context.Pool, cancellationToken).ConfigureAwait(false);
            }
            catch(Exception exception) when(IsPinCryptoOperationFailure(exception))
            {
                return new PinEstablishmentCompleted(CtapSetPinOutcomeKind.DecapsulationFailed, 0, null);
            }

            bool isVerified = await protocol.VerifyAsync(
                sharedSecret.Memory, action.NewPinEnc, action.PinUvAuthParam, context.Pool, cancellationToken).ConfigureAwait(false);
            if(!isVerified)
            {
                return new PinEstablishmentCompleted(CtapSetPinOutcomeKind.VerifyFailed, 0, null);
            }

            try
            {
                using DecryptedContent paddedNewPin = await protocol.DecryptAsync(
                    sharedSecret.Memory, action.NewPinEnc, context.Pool, cancellationToken).ConfigureAwait(false);
                if(paddedNewPin.Length != PaddedPinLength)
                {
                    return new PinEstablishmentCompleted(CtapSetPinOutcomeKind.PaddedLengthInvalid, 0, null);
                }

                ReadOnlySpan<byte> newPin = StripTrailingZeroes(paddedNewPin.AsReadOnlySpan());
                int codePointLength = CountUtf8CodePoints(newPin);
                if(codePointLength < action.MinPinCodePointLength)
                {
                    return new PinEstablishmentCompleted(CtapSetPinOutcomeKind.PolicyViolation, codePointLength, null);
                }

                DigestValue newPinHash = ComputeStoredPinHash(newPin, context.Pool);

                return new PinEstablishmentCompleted(CtapSetPinOutcomeKind.Success, codePointLength, newPinHash);
            }
            catch(Exception exception) when(IsPinCryptoOperationFailure(exception))
            {
                return new PinEstablishmentCompleted(CtapSetPinOutcomeKind.DecryptFailed, 0, null);
            }
        }
        finally
        {
            if(sharedSecret is not null)
            {
                sharedSecret.Memory.Span.Clear();
                sharedSecret.Dispose();
            }
        }
    }


    /// <summary>
    /// <c>changePIN</c>'s effect (CTAP 2.3 §6.5.5.6, lines 5658-5716): <c>decapsulate</c>,
    /// <c>verify(sharedSecret, newPinEnc || pinHashEnc, pinUvAuthParam)</c>, decrypt and
    /// constant-time-compare <c>pinHashEnc</c> against <see cref="CtapChangePinAction.CurrentStoredPin"/>,
    /// then — on a decrypt error OR a mismatch (line 5671: both conditions receive identical handling) —
    /// mint a fresh key-agreement key pair for the selected protocol (<c>regenerate()</c>), or — on a
    /// match — decrypt and validate <c>newPinEnc</c>, hash the new PIN, apply line 5700's same-PIN-under-force
    /// rejection (<see cref="CtapChangePinAction.IsForcePinChangeRequired"/>, <c>FixedTimeEquals</c>
    /// against <see cref="CtapChangePinAction.CurrentStoredPin"/>), and — once that passes too — mint
    /// fresh (not begun-using) <c>pinUvAuthToken</c>s for both protocols (<c>resetPinUvAuthToken()</c>
    /// "for all"). No decrypted PIN material crosses the fold-back boundary. The shared secret is zeroed
    /// and disposed on every path.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A <c>newPinEnc</c> that decrypts successfully but is not well-formed UTF-8 makes
    /// <see cref="CountUtf8CodePoints"/> throw <see cref="Fido2FormatException"/>, which the same guard
    /// that catches this step's own <c>decrypt(sharedSecret, newPinEnc)</c> failures
    /// (<see cref="IsPinCryptoOperationFailure"/>) also catches, folding both into the identical
    /// <see cref="CtapChangePinOutcomeKind.NewPinDecryptFailed"/> outcome and, downstream, the
    /// CTAP2_ERR_PIN_AUTH_INVALID status line 5692 assigns to a <c>decrypt</c> error on the NEW PIN (a
    /// separate step from, and unrelated to, the CURRENT-PIN <c>pinHashEnc</c> decrypt/mismatch handling
    /// at line 5671 above). This is the adopted fail-closed disposition: the spec defines no distinct
    /// status for a malformed-UTF-8 <c>newPin</c>, and the only party who can ever construct a
    /// <c>newPinEnc</c> that decrypts to malformed UTF-8 is a platform that already holds the shared
    /// secret, so collapsing the case into the neighboring decrypt-error status neither hides a
    /// reachable-by-an-attacker branch nor invents a status the spec does not define.
    /// </para>
    /// <para>
    /// CTAP 2.3 §6.5.5.6 (lines 5702-5704) lets an authenticator "impose arbitrary, additional
    /// constraints on PINs" beyond the mandatory 64-byte <c>paddedNewPin</c> length, trailing-0x00
    /// strip, and <see cref="CtapAuthenticatorState.MinPinCodePointLength"/> checks already applied
    /// above. This is the adopted disposition: the MAY is declined, so
    /// <see cref="CtapChangePinOutcomeKind.NewPinPolicyViolation"/> is returned only for the
    /// minimum-length failure, and no additional constraint ever rejects a <c>newPin</c> that already
    /// satisfies it.
    /// </para>
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "MintSingleKeyAgreementKeyPair's returned key pair transfers ownership into PinChangeCompleted.RegeneratedKeyPair on a decrypt failure or a mismatch, ComputeStoredPinHash's returned DigestValue transfers into PinChangeCompleted.NewPinHash on Success, and both CtapPinUvAuthTokenState.Initial() calls transfer into PinChangeCompleted.FreshProtocolOneToken/FreshProtocolTwoToken on Success (disposed in the catch block on failure); the analyzer cannot see these transfers through the record construction.")]
    private static async ValueTask<CtapAuthenticatorInput> ChangePinAsync(CtapChangePinAction action, CtapActionContext context, CancellationToken cancellationToken)
    {
        CtapPinUvAuthProtocol protocol = CtapPinUvAuthProtocol.CreateDefault(action.ProtocolId);
        IMemoryOwner<byte>? sharedSecret = null;
        try
        {
            try
            {
                sharedSecret = await protocol.DecapsulateAsync(action.OwnPrivateKey, action.PeerKeyAgreement, context.Pool, cancellationToken).ConfigureAwait(false);
            }
            catch(Exception exception) when(IsPinCryptoOperationFailure(exception))
            {
                return new PinChangeCompleted(CtapChangePinOutcomeKind.DecapsulationFailed, action.ProtocolId, null, 0, null, null, null);
            }

            using IMemoryOwner<byte> verifyMessage = BuildConcatenatedMessage(action.NewPinEnc, action.PinHashEnc, context.Pool);
            bool isVerified = await protocol.VerifyAsync(
                sharedSecret.Memory, verifyMessage.Memory, action.PinUvAuthParam, context.Pool, cancellationToken).ConfigureAwait(false);
            if(!isVerified)
            {
                return new PinChangeCompleted(CtapChangePinOutcomeKind.VerifyFailed, action.ProtocolId, null, 0, null, null, null);
            }

            bool isCurrentPinMatch;
            try
            {
                using DecryptedContent decryptedCurrentPinHash = await protocol.DecryptAsync(
                    sharedSecret.Memory, action.PinHashEnc, context.Pool, cancellationToken).ConfigureAwait(false);
                isCurrentPinMatch = CryptographicOperations.FixedTimeEquals(
                    decryptedCurrentPinHash.AsReadOnlySpan(), action.CurrentStoredPin.AsReadOnlySpan());
            }
            catch(Exception exception) when(IsPinCryptoOperationFailure(exception))
            {
                CtapPinUvAuthKeyAgreementKeyPair regeneratedOnDecryptFailure = MintSingleKeyAgreementKeyPair(context.Pool);

                return new PinChangeCompleted(CtapChangePinOutcomeKind.CurrentPinDecryptFailed, action.ProtocolId, regeneratedOnDecryptFailure, 0, null, null, null);
            }

            if(!isCurrentPinMatch)
            {
                CtapPinUvAuthKeyAgreementKeyPair regenerated = MintSingleKeyAgreementKeyPair(context.Pool);

                return new PinChangeCompleted(CtapChangePinOutcomeKind.CurrentPinMismatch, action.ProtocolId, regenerated, 0, null, null, null);
            }

            DigestValue? newPinHash = null;
            int codePointLength = 0;
            try
            {
                using DecryptedContent paddedNewPin = await protocol.DecryptAsync(
                    sharedSecret.Memory, action.NewPinEnc, context.Pool, cancellationToken).ConfigureAwait(false);
                if(paddedNewPin.Length != PaddedPinLength)
                {
                    return new PinChangeCompleted(CtapChangePinOutcomeKind.NewPinPaddedLengthInvalid, action.ProtocolId, null, 0, null, null, null);
                }

                ReadOnlySpan<byte> newPin = StripTrailingZeroes(paddedNewPin.AsReadOnlySpan());
                codePointLength = CountUtf8CodePoints(newPin);
                if(codePointLength < action.MinPinCodePointLength)
                {
                    return new PinChangeCompleted(CtapChangePinOutcomeKind.NewPinPolicyViolation, action.ProtocolId, null, codePointLength, null, null, null);
                }

                newPinHash = ComputeStoredPinHash(newPin, context.Pool);
            }
            catch(Exception exception) when(IsPinCryptoOperationFailure(exception))
            {
                return new PinChangeCompleted(CtapChangePinOutcomeKind.NewPinDecryptFailed, action.ProtocolId, null, 0, null, null, null);
            }

            //Line 5700: forcePINChange:true and the new PIN's hash equals the stored current PIN's hash
            //-> PinPolicyViolation, checked after the length check (line 5698) and before minting fresh
            //tokens, constant-time since both operands are PIN-hash-derived.
            if(action.IsForcePinChangeRequired && CryptographicOperations.FixedTimeEquals(newPinHash!.AsReadOnlySpan(), action.CurrentStoredPin.AsReadOnlySpan()))
            {
                newPinHash.Dispose();

                return new PinChangeCompleted(CtapChangePinOutcomeKind.NewPinSameAsCurrentUnderForce, action.ProtocolId, null, codePointLength, null, null, null);
            }

            CtapPinUvAuthTokenState freshProtocolOneToken = CtapPinUvAuthTokenState.Initial(context.Pool);
            CtapPinUvAuthTokenState freshProtocolTwoToken;
            try
            {
                freshProtocolTwoToken = CtapPinUvAuthTokenState.Initial(context.Pool);
            }
            catch
            {
                freshProtocolOneToken.Dispose();
                newPinHash?.Dispose();
                throw;
            }

            return new PinChangeCompleted(
                CtapChangePinOutcomeKind.Success, action.ProtocolId, null, codePointLength, newPinHash, freshProtocolOneToken, freshProtocolTwoToken);
        }
        finally
        {
            if(sharedSecret is not null)
            {
                sharedSecret.Memory.Span.Clear();
                sharedSecret.Dispose();
            }
        }
    }


    /// <summary>
    /// The shared <c>getPinToken</c>/<c>getPinUvAuthTokenUsingPinWithPermissions</c> effect (CTAP 2.3
    /// §6.5.5.7.1 lines 5873-5915, §6.5.5.7.2 lines 5975-6026): <c>decapsulate</c>, decrypt and
    /// constant-time-compare <c>pinHashEnc</c> against <see cref="CtapIssuePinTokenAction.CurrentStoredPin"/>,
    /// then — on a decrypt error OR a mismatch (lines 5883/5985: both conditions receive identical
    /// handling) — mint a fresh key-agreement key pair for the selected protocol, or — on a match —
    /// apply line 5904/6006's <c>forcePINChange</c> gate
    /// (<see cref="CtapIssuePinTokenAction.IsForcePinChangeRequired"/>), and — once that passes too —
    /// mint fresh <c>pinUvAuthToken</c>s for both protocols (<c>resetPinUvAuthToken()</c> "for all"),
    /// call <c>beginUsingPinUvAuthToken(userIsPresent: false)</c> on the selected protocol's fresh
    /// token, assign it <see cref="CtapIssuePinTokenAction.PermissionsToAssign"/>/
    /// <see cref="CtapIssuePinTokenAction.PermissionsRpId"/>, and encrypt it for the response. The shared
    /// secret is zeroed and disposed on every path.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "MintSingleKeyAgreementKeyPair's returned key pair transfers ownership into PinTokenIssuanceCompleted.RegeneratedKeyPair on a decrypt failure or a mismatch, and both CtapPinUvAuthTokenState.Initial() calls transfer into PinTokenIssuanceCompleted.FreshProtocolOneToken/FreshProtocolTwoToken on Success (disposed in the catch block on failure); the analyzer cannot see these transfers through the record construction.")]
    private static async ValueTask<CtapAuthenticatorInput> IssuePinTokenAsync(CtapIssuePinTokenAction action, CtapActionContext context, CancellationToken cancellationToken)
    {
        CtapPinUvAuthProtocol protocol = CtapPinUvAuthProtocol.CreateDefault(action.ProtocolId);
        IMemoryOwner<byte>? sharedSecret = null;
        try
        {
            try
            {
                sharedSecret = await protocol.DecapsulateAsync(action.OwnPrivateKey, action.PeerKeyAgreement, context.Pool, cancellationToken).ConfigureAwait(false);
            }
            catch(Exception exception) when(IsPinCryptoOperationFailure(exception))
            {
                return new PinTokenIssuanceCompleted(CtapPinTokenIssuanceOutcomeKind.DecapsulationFailed, action.ProtocolId, null, null, null, null);
            }

            bool isCurrentPinMatch;
            try
            {
                using DecryptedContent decryptedCurrentPinHash = await protocol.DecryptAsync(
                    sharedSecret.Memory, action.PinHashEnc, context.Pool, cancellationToken).ConfigureAwait(false);
                isCurrentPinMatch = CryptographicOperations.FixedTimeEquals(
                    decryptedCurrentPinHash.AsReadOnlySpan(), action.CurrentStoredPin.AsReadOnlySpan());
            }
            catch(Exception exception) when(IsPinCryptoOperationFailure(exception))
            {
                CtapPinUvAuthKeyAgreementKeyPair regeneratedOnDecryptFailure = MintSingleKeyAgreementKeyPair(context.Pool);

                return new PinTokenIssuanceCompleted(CtapPinTokenIssuanceOutcomeKind.CurrentPinDecryptFailed, action.ProtocolId, regeneratedOnDecryptFailure, null, null, null);
            }

            if(!isCurrentPinMatch)
            {
                CtapPinUvAuthKeyAgreementKeyPair regenerated = MintSingleKeyAgreementKeyPair(context.Pool);

                return new PinTokenIssuanceCompleted(CtapPinTokenIssuanceOutcomeKind.CurrentPinMismatch, action.ProtocolId, regenerated, null, null, null);
            }

            //Lines 5904/6006: checked strictly after the current-PIN match succeeds (pinRetries := maximum
            //is applied unconditionally by the pure fold-back regardless of this outcome) and strictly
            //before minting a fresh token — the two subcommands share this action/executor but answer the
            //identical condition with different status codes (action.ForcePinChangeDeniedStatusCode).
            if(action.IsForcePinChangeRequired)
            {
                return new PinTokenIssuanceCompleted(
                    CtapPinTokenIssuanceOutcomeKind.ForcePinChangeRequired, action.ProtocolId, null, null, null, null, action.ForcePinChangeDeniedStatusCode);
            }

            CtapPinUvAuthTokenState freshProtocolOneToken = CtapPinUvAuthTokenState.Initial(context.Pool);
            CtapPinUvAuthTokenState freshProtocolTwoToken;
            try
            {
                freshProtocolTwoToken = CtapPinUvAuthTokenState.Initial(context.Pool);
            }
            catch
            {
                freshProtocolOneToken.Dispose();
                throw;
            }

            CtapPinUvAuthTokenState selectedToken = (action.ProtocolId == CtapPinUvAuthProtocolId.One ? freshProtocolOneToken : freshProtocolTwoToken)
                .BeginUsing(userIsPresent: false, action.Now) with
                {
                    Permissions = action.PermissionsToAssign,
                    PermissionsRpId = action.PermissionsRpId
                };

            if(action.ProtocolId == CtapPinUvAuthProtocolId.One)
            {
                freshProtocolOneToken = selectedToken;
            }
            else
            {
                freshProtocolTwoToken = selectedToken;
            }

            TaggedMemory<byte> encryptedToken;
            using(Ciphertext ciphertext = await protocol.EncryptAsync(
                sharedSecret.Memory, selectedToken.Token.AsReadOnlyMemory(), context.Pool, cancellationToken).ConfigureAwait(false))
            {
                //Rented from context.Pool rather than a bare `new byte[]` (no-naked-bytes-uniform), mirroring
                //IssueUvTokenAsync's identical shape: the rental is never disposed back, since
                //PinTokenIssuanceCompleted.EncryptedToken is a bare ReadOnlyMemory<byte>? with no disposal
                //contract that outlives this method, so the copy must detach from the pool rental rather
                //than alias memory a `using` block could hand back.
                IMemoryOwner<byte> encryptedTokenStorage = context.Pool.Rent(ciphertext.Length);
                try
                {
                    ciphertext.AsReadOnlySpan().CopyTo(encryptedTokenStorage.Memory.Span);
                    encryptedToken = new TaggedMemory<byte>(encryptedTokenStorage.Memory[..ciphertext.Length], ciphertext.Tag);
                }
                catch
                {
                    encryptedTokenStorage.Dispose();
                    throw;
                }
            }

            return new PinTokenIssuanceCompleted(
                CtapPinTokenIssuanceOutcomeKind.Success, action.ProtocolId, null, freshProtocolOneToken, freshProtocolTwoToken, encryptedToken.Memory);
        }
        finally
        {
            if(sharedSecret is not null)
            {
                sharedSecret.Memory.Span.Clear();
                sharedSecret.Dispose();
            }
        }
    }


    /// <summary>
    /// Runs <c>performBuiltInUv(internalRetry)</c>'s attempt loop (CTAP 2.3 §6.5.3.1, steps 4-11),
    /// shared by <see cref="IssueUvTokenAsync"/> (0x06) and <see cref="PerformBuiltInUvAsync"/> (mc/ga) —
    /// the loop MECHANICS are a plain I/O composition and are shared; each caller's own
    /// <paramref name="internalRetry"/> VALUE is never computed by this or any other shared helper (uv
    /// scout trap 2). The caller has already confirmed <paramref name="startingUvRetries"/> is non-zero
    /// and evaluated the pinRetries-exhaustion drag-down (step 3) purely, without ever reaching this
    /// loop — so step 4's own "uvRetries is 0" check here only ever fires MID-loop, after an earlier
    /// iteration's own decrement.
    /// </summary>
    /// <param name="simulateBuiltInUv">The per-attempt outcome delegate (R8).</param>
    /// <param name="internalRetry">Whether the caller intends multiple internal attempts (step 1-2).</param>
    /// <param name="startingUvRetries">The confirmed-non-zero <c>uvRetries</c> value to decrement a local copy of.</param>
    /// <returns>The loop's final outcome and how many attempts (decrements) it consumed.</returns>
    private static (CtapBuiltInUvAttemptOutcome Outcome, int AttemptsConsumed) PerformBuiltInUvAttempts(
        SimulateBuiltInUvDelegate simulateBuiltInUv, bool internalRetry, int startingUvRetries)
    {
        int attemptsBeforeReturning = internalRetry ? CtapAuthenticatorState.MaxUvAttemptsForInternalRetries : 1;
        int remainingUvRetries = startingUvRetries;
        int attemptsConsumed = 0;
        CtapBuiltInUvAttemptOutcome outcome = CtapBuiltInUvAttemptOutcome.MatchFailure;

        while(remainingUvRetries > 0 && attemptsBeforeReturning > 0)
        {
            remainingUvRetries--;
            attemptsBeforeReturning--;
            attemptsConsumed++;

            outcome = simulateBuiltInUv();
            if(outcome != CtapBuiltInUvAttemptOutcome.MatchFailure)
            {
                break;
            }
        }

        return (outcome, attemptsConsumed);
    }


    /// <summary>
    /// <c>getPinUvAuthTokenUsingUvWithPermissions</c>'s (<c>0x06</c>) effect (CTAP 2.3 §6.5.5.7.3):
    /// <c>decapsulate</c>, run <see cref="PerformBuiltInUvAttempts"/>'s shared attempt loop, then — on
    /// success — mint fresh <c>pinUvAuthToken</c>s for both protocols, begin using the selected one with
    /// <c>userIsPresent: true</c> (steps 13-14 — the simulated gesture always supplies evidence of user
    /// interaction here), assign it <see cref="CtapIssueUvTokenAction.PermissionsToAssign"/>/
    /// <see cref="CtapIssueUvTokenAction.PermissionsRpId"/>, and encrypt it for the response — mirroring
    /// <see cref="IssuePinTokenAsync"/>'s own token-mint tail exactly, with the PIN-hash decrypt/compare
    /// replaced by the attempt loop. The shared secret is zeroed and disposed on every path.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Both CtapPinUvAuthTokenState.Initial() calls transfer ownership into UvTokenIssuanceCompleted.FreshProtocolOneToken/FreshProtocolTwoToken on Success (disposed in the catch block on failure); the analyzer cannot see this transfer through the record construction.")]
    private static async ValueTask<CtapAuthenticatorInput> IssueUvTokenAsync(CtapIssueUvTokenAction action, CtapActionContext context, CancellationToken cancellationToken)
    {
        CtapPinUvAuthProtocol protocol = CtapPinUvAuthProtocol.CreateDefault(action.ProtocolId);
        IMemoryOwner<byte>? sharedSecret = null;
        try
        {
            try
            {
                sharedSecret = await protocol.DecapsulateAsync(action.OwnPrivateKey, action.PeerKeyAgreement, context.Pool, cancellationToken).ConfigureAwait(false);
            }
            catch(Exception exception) when(IsPinCryptoOperationFailure(exception))
            {
                return new UvTokenIssuanceCompleted(CtapUvTokenIssuanceOutcomeKind.DecapsulationFailed, action.ProtocolId, 0, null, null, null);
            }

            (CtapBuiltInUvAttemptOutcome outcome, int attemptsConsumed) =
                PerformBuiltInUvAttempts(context.SimulateBuiltInUv, action.InternalRetry, action.StartingUvRetries);

            if(outcome == CtapBuiltInUvAttemptOutcome.UserActionTimeout)
            {
                return new UvTokenIssuanceCompleted(CtapUvTokenIssuanceOutcomeKind.UserActionTimeout, action.ProtocolId, attemptsConsumed, null, null, null);
            }

            if(outcome == CtapBuiltInUvAttemptOutcome.MatchFailure)
            {
                return new UvTokenIssuanceCompleted(CtapUvTokenIssuanceOutcomeKind.MatchFailure, action.ProtocolId, attemptsConsumed, null, null, null);
            }

            CtapPinUvAuthTokenState freshProtocolOneToken = CtapPinUvAuthTokenState.Initial(context.Pool);
            CtapPinUvAuthTokenState freshProtocolTwoToken;
            try
            {
                freshProtocolTwoToken = CtapPinUvAuthTokenState.Initial(context.Pool);
            }
            catch
            {
                freshProtocolOneToken.Dispose();
                throw;
            }

            //Steps 13-14 (lines 6111-6115): the simulated fingerprint touch supplies evidence of user
            //interaction, so this token begins using with userIsPresent TRUE — the FIRST tokens in this
            //codebase minted that way (uv scout delta (a), R9); PIN-path tokens still begin with FALSE.
            CtapPinUvAuthTokenState selectedToken = (action.ProtocolId == CtapPinUvAuthProtocolId.One ? freshProtocolOneToken : freshProtocolTwoToken)
                .BeginUsing(userIsPresent: true, action.Now) with
                {
                    Permissions = action.PermissionsToAssign,
                    PermissionsRpId = action.PermissionsRpId
                };

            if(action.ProtocolId == CtapPinUvAuthProtocolId.One)
            {
                freshProtocolOneToken = selectedToken;
            }
            else
            {
                freshProtocolTwoToken = selectedToken;
            }

            TaggedMemory<byte> encryptedToken;
            using(Ciphertext ciphertext = await protocol.EncryptAsync(
                sharedSecret.Memory, selectedToken.Token.AsReadOnlyMemory(), context.Pool, cancellationToken).ConfigureAwait(false))
            {
                //Rented from context.Pool rather than a bare `new byte[]` (no-naked-bytes-uniform: every
                //buffer routes through the pool for CBOM/OTel/perf uniformity regardless of secrecy). The
                //rental is never disposed back: UvTokenIssuanceCompleted.EncryptedToken is a bare
                //ReadOnlyMemory<byte>? with no disposal contract that outlives this method, so — mirroring
                //EmitCredentialManagementRpAsync's identical rpIdHashCarrier detach rationale — the copy
                //must detach from the pool rental rather than alias memory a `using` block could hand back.
                IMemoryOwner<byte> encryptedTokenStorage = context.Pool.Rent(ciphertext.Length);
                try
                {
                    ciphertext.AsReadOnlySpan().CopyTo(encryptedTokenStorage.Memory.Span);
                    encryptedToken = new TaggedMemory<byte>(encryptedTokenStorage.Memory[..ciphertext.Length], ciphertext.Tag);
                }
                catch
                {
                    encryptedTokenStorage.Dispose();
                    throw;
                }
            }

            return new UvTokenIssuanceCompleted(
                CtapUvTokenIssuanceOutcomeKind.Success, action.ProtocolId, attemptsConsumed, freshProtocolOneToken, freshProtocolTwoToken, encryptedToken.Memory);
        }
        finally
        {
            if(sharedSecret is not null)
            {
                sharedSecret.Memory.Span.Clear();
                sharedSecret.Dispose();
            }
        }
    }


    /// <summary>
    /// <c>authenticatorMakeCredential</c>/<c>authenticatorGetAssertion</c>'s own <c>options.uv = true</c>
    /// built-in-UV fallback effect (CTAP 2.3 §6.1.2 step 11.2 / §6.2.2 step 6.2): runs
    /// <see cref="PerformBuiltInUvAttempts"/>'s shared attempt loop and folds the outcome straight back —
    /// unlike <see cref="IssueUvTokenAsync"/>, no token is minted here; mc/ga's own <c>uv</c> response
    /// bit is set by the PURE fold-back (<c>OnBuiltInUvAttempted</c>) from the outcome alone.
    /// </summary>
    private static ValueTask<CtapAuthenticatorInput> PerformBuiltInUvAsync(CtapPerformBuiltInUvAction action, CtapActionContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        (CtapBuiltInUvAttemptOutcome outcome, int attemptsConsumed) =
            PerformBuiltInUvAttempts(context.SimulateBuiltInUv, action.InternalRetry, action.StartingUvRetries);

        return ValueTask.FromResult<CtapAuthenticatorInput>(new BuiltInUvAttempted(outcome, attemptsConsumed, action.Continuation));
    }


    /// <summary>
    /// Whether <paramref name="exception"/> is one of the recognized failure shapes a PIN-path
    /// subcommand's <c>decapsulate</c>/<c>decrypt</c> step can throw for malformed or mismatched input —
    /// the "if an error results" clauses CTAP 2.3 attaches to those steps (lines 5570/5578/5658/5692), and
    /// the "if an error results, or a mismatch is detected" clause the current-PIN <c>pinHashEnc</c>
    /// decrypt/compare step carries in <c>changePIN</c> (line 5671), <c>getPinToken</c> (line 5883), and
    /// <c>getPinUvAuthTokenUsingPinWithPermissions</c> (line 5985) — a decrypt error on that step is
    /// routed to the identical <c>regenerate()</c>/counter handling a mismatch receives.
    /// </summary>
    private static bool IsPinCryptoOperationFailure(Exception exception) =>
        exception is ArgumentException or CryptographicException or Fido2FormatException;


    /// <summary>
    /// Drops every trailing <c>0x00</c> byte from <paramref name="paddedNewPin"/> (CTAP 2.3, line 5582/
    /// 5696: "drops all trailing 0x00 bytes from paddedNewPin to produce newPin").
    /// </summary>
    private static ReadOnlySpan<byte> StripTrailingZeroes(ReadOnlySpan<byte> paddedNewPin)
    {
        int length = paddedNewPin.Length;
        while(length > 0 && paddedNewPin[length - 1] == 0)
        {
            length--;
        }

        return paddedNewPin[..length];
    }


    /// <summary>
    /// Counts the Unicode code points <paramref name="utf8"/> decodes to, without ever materializing a
    /// managed <see cref="string"/> holding the decrypted PIN — CTAP 2.3, line 5590/5706's
    /// <c>PINCodePointLength</c>, "the length in Unicode CODE POINTS, not UTF-8 bytes".
    /// </summary>
    /// <exception cref="Fido2FormatException"><paramref name="utf8"/> is not well-formed UTF-8.</exception>
    private static int CountUtf8CodePoints(ReadOnlySpan<byte> utf8)
    {
        int count = 0;
        int index = 0;
        while(index < utf8.Length)
        {
            OperationStatus status = Rune.DecodeFromUtf8(utf8[index..], out _, out int bytesConsumed);
            if(status != OperationStatus.Done)
            {
                throw new Fido2FormatException("The decrypted new PIN is not well-formed UTF-8.");
            }

            index += bytesConsumed;
            count++;
        }

        return count;
    }


    /// <summary>
    /// Computes the stored PIN hash <c>LEFT(SHA-256(newPin), 16)</c> (CTAP 2.3, line 5592/5710): hashes
    /// the full 32-byte SHA-256 digest of <paramref name="newPin"/>, copies its leftmost 16 bytes into a
    /// freshly rented carrier, and disposes (zeroing) the full-length intermediate — the registered
    /// digest primitive always produces its algorithm's native output length, so the truncation happens
    /// as a separate copy rather than by requesting a short digest.
    /// </summary>
    private static DigestValue ComputeStoredPinHash(ReadOnlySpan<byte> newPin, MemoryPool<byte> pool)
    {
        using DigestValue fullDigest = CryptographicKeyEvents.ComputeDigest(newPin, Sha256Length, CryptoTags.Sha256Digest, pool);

        IMemoryOwner<byte> truncated = pool.Rent(StoredPinHashLength);
        try
        {
            fullDigest.AsReadOnlySpan()[..StoredPinHashLength].CopyTo(truncated.Memory.Span);

            return new DigestValue(truncated, CryptoTags.Sha256Digest);
        }
        catch
        {
            truncated.Memory.Span.Clear();
            truncated.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Mints a fresh P-256 key-agreement key pair for a single PIN/UV auth protocol — the mismatch-path
    /// <c>regenerate()</c> effect (CTAP 2.3, line 5674 and analogously for <c>getPinToken</c>/
    /// <c>getPinUvAuthTokenUsingPinWithPermissions</c>), which replaces only the SELECTED protocol's pair.
    /// </summary>
    private static CtapPinUvAuthKeyAgreementKeyPair MintSingleKeyAgreementKeyPair(MemoryPool<byte> pool)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            CryptographicKeyEvents.CreateKeyPair(CryptoAlgorithm.P256, Purpose.Exchange, pool);

        return new CtapPinUvAuthKeyAgreementKeyPair(keys.PublicKey, keys.PrivateKey);
    }


    /// <summary>
    /// Builds <c>left || right</c> in a single pool-rented buffer — <c>changePIN</c>'s <c>verify</c>
    /// message, <c>newPinEnc || pinHashEnc</c> (CTAP 2.3, line 5660). Both halves are already ciphertext
    /// (non-secret), but the buffer is still pool-allocated rather than a bare <c>byte[]</c>, matching
    /// this library's uniform pooled-buffer convention.
    /// </summary>
    private static SlicedMemoryOwner BuildConcatenatedMessage(ReadOnlyMemory<byte> left, ReadOnlyMemory<byte> right, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> combined = pool.Rent(left.Length + right.Length);
        try
        {
            left.CopyTo(combined.Memory);
            right.CopyTo(combined.Memory[left.Length..]);

            return new SlicedMemoryOwner(combined, left.Length + right.Length);
        }
        catch
        {
            combined.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Wraps a pool-rented <see cref="IMemoryOwner{T}"/> whose usable content is shorter than the
    /// rented (possibly over-allocated) buffer, exposing only the requested length while still
    /// disposing the whole underlying rental.
    /// </summary>
    private sealed class SlicedMemoryOwner: IMemoryOwner<byte>
    {
        /// <summary>The wrapped pool rental, disposed in full by <see cref="Dispose"/> regardless of the exposed <see cref="Memory"/> length.</summary>
        private IMemoryOwner<byte> Inner { get; }

        /// <inheritdoc />
        public Memory<byte> Memory { get; }

        /// <summary>Wraps <paramref name="inner"/>, exposing only its leading <paramref name="length"/> bytes.</summary>
        /// <param name="inner">The rented owner to wrap.</param>
        /// <param name="length">The usable content length, no greater than <paramref name="inner"/>'s rented length.</param>
        public SlicedMemoryOwner(IMemoryOwner<byte> inner, int length)
        {
            this.Inner = inner;
            Memory = inner.Memory[..length];
        }

        /// <inheritdoc />
        public void Dispose() => Inner.Dispose();
    }


    /// <summary>
    /// <c>authenticatorMakeCredential</c>'s effect: mints the key pair through the injected
    /// <see cref="CtapCredentialSigningBackend"/>, draws a fresh credential identifier,
    /// UNCONDITIONALLY two fresh 32-byte CredRandom values (CTAP 2.3 §12.7, snapshot line 13191/13192's
    /// SHOULD adopted — contract R2, regardless of <see cref="CtapGenerateCredentialKeyAction.HmacSecretRequested"/>)
    /// and, iff §12.3's <c>largeBlobKey</c> extension was validated-and-requested, a fresh 32-byte
    /// largeBlobKey (R8); when <see cref="CtapGenerateCredentialKeyAction.HmacSecretMc"/> is present,
    /// completes it with the just-minted CredRandom pair and runs <see cref="ComputeHmacSecretOutputAsync"/>
    /// — the SAME crypto routine the <c>authenticatorGetAssertion</c> effect runs (contract R6, snapshot
    /// line 13402's pure delegation) — aborting the whole command with
    /// <see cref="MakeCredentialHmacSecretMcFailed"/> on anything short of success; encodes the
    /// <c>credProtect</c>/<c>hmac-secret</c>/<c>minPinLength</c>/<c>hmac-secret-mc</c> extensions output
    /// map (see <see cref="EncodeCtapMakeCredentialExtensionOutputsDelegate"/>), assembles the
    /// <c>attestedCredentialData</c>-and-<c>extensions</c>-bearing <c>authData</c>, and builds the
    /// response's <c>fmt</c>/<c>attStmt</c> per <see cref="CtapGenerateCredentialKeyAction.AttestationFormat"/>
    /// (see <see cref="BuildAttestationResponseAsync"/>) before splicing the minted largeBlobKey onto the
    /// response as its TOP-LEVEL <c>0x05</c> member.
    /// </summary>
    /// <remarks>
    /// <paramref name="keyPair"/>, <paramref name="credentialId"/>, <paramref name="storedUserId"/>,
    /// <paramref name="credRandomWithUV"/>, <paramref name="credRandomWithoutUV"/>, and
    /// <paramref name="largeBlobKey"/> are tracked in locals spanning the whole method (rather than
    /// disposed with <c>using</c> at their point of creation) so a later step's failure — including
    /// cancellation, or a <see cref="CtapGenerateCredentialKeyAction.HmacSecretMc"/> crypto sequence that
    /// concludes without success — can dispose exactly what was actually constructed, mirroring
    /// <c>CtapGetAssertionResponseCborReader.Read</c>'s own "track outside the try, dispose on failure"
    /// convention. On success, ownership of all six transfers to the returned
    /// <see cref="CtapCredentialRecord"/>, which the credential store disposes; <see cref="CoseKey"/>
    /// carries no pooled memory of its own and needs no disposal.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "keyPair/credentialId/storedUserId/credRandomWithUV/credRandomWithoutUV/largeBlobKey are disposed in the catch block on every failure path and otherwise transfer ownership to the returned CtapCredentialRecord on success; the analyzer cannot see the try/catch's disposal across the nullable-local pattern.")]
    private static async ValueTask<CtapAuthenticatorInput> GenerateCredentialAsync(CtapGenerateCredentialKeyAction action, CtapActionContext context, CancellationToken cancellationToken)
    {
        CtapCredentialSigningBackend backend = context.CredentialSigningBackend
            ?? throw new InvalidOperationException("authenticatorMakeCredential requires a credential-signing backend, but none was supplied.");

        CtapCredentialKeyPair? keyPair = null;
        CredentialId? credentialId = null;
        UserHandle? storedUserId = null;
        IMemoryOwner<byte>? credRandomWithUV = null;
        IMemoryOwner<byte>? credRandomWithoutUV = null;
        IMemoryOwner<byte>? largeBlobKey = null;
        try
        {
            keyPair = await backend.GenerateCredentialKeyPair(action.Algorithm, context.Pool, cancellationToken).ConfigureAwait(false);

            Span<byte> credentialIdBytes = stackalloc byte[CredentialIdLength];
            context.Rng(credentialIdBytes);
            credentialId = CredentialId.Create(credentialIdBytes, context.Pool);

            //R2/§12.7 lines 13191-13192: two fresh, independently random 32-byte CredRandom values,
            //minted on EVERY mint regardless of action.HmacSecretRequested — the LargeBlobKey mint/dispose
            //shape below (stackalloc scratch -> pool rental -> copy -> clear scratch), run twice.
            Span<byte> credRandomWithUVBytes = stackalloc byte[CredRandomLength];
            context.Rng(credRandomWithUVBytes);
            credRandomWithUV = context.Pool.Rent(CredRandomLength);
            credRandomWithUVBytes.CopyTo(credRandomWithUV.Memory.Span);
            credRandomWithUVBytes.Clear();

            Span<byte> credRandomWithoutUVBytes = stackalloc byte[CredRandomLength];
            context.Rng(credRandomWithoutUVBytes);
            credRandomWithoutUV = context.Pool.Rent(CredRandomLength);
            credRandomWithoutUVBytes.CopyTo(credRandomWithoutUV.Memory.Span);
            credRandomWithoutUVBytes.Clear();

            //R8/§12.3 line 12851: "store a freshly generated 32-byte key" — minted from the SAME entropy
            //provider as the credential identifier, beside it, iff the pure transition already validated
            //the request's largeBlobKey extension (value true AND options.rk true).
            if(action.LargeBlobKeyRequested)
            {
                //The key is a real AEAD_AES_256_GCM secret (§6.10.3 line 7742): the pooled copy is the
                //authoritative custody home, so the stack scratch is cleared the moment the copy lands.
                Span<byte> largeBlobKeyBytes = stackalloc byte[LargeBlobKeyLength];
                context.Rng(largeBlobKeyBytes);
                largeBlobKey = context.Pool.Rent(LargeBlobKeyLength);
                largeBlobKeyBytes.CopyTo(largeBlobKey.Memory.Span);
                largeBlobKeyBytes.Clear();
            }

            TaggedMemory<byte> credentialPublicKeyCbor = context.EncodeCredentialPublicKey(keyPair.PublicKey);

            //R6/§12.8 line 13402: hmac-secret-mc's processing is the SAME routine
            //(ComputeHmacSecretOutputAsync, delegated) hmac-secret's own authenticatorGetAssertion effect
            //runs — executed here, against the CredRandom pair just minted above, since that pair does
            //not exist until this point. The response's own uv bit (action.UserVerified) selects which
            //CredRandom half feeds the HMAC (trap 4), exactly as ComputeHmacSecretOutputAsync's ga caller
            //does. A non-Success outcome aborts the whole authenticatorMakeCredential command outright —
            //CredentialMinted is never produced on this path, so every resource minted so far is disposed
            //explicitly here rather than relying on the method's own catch block, which never runs for an
            //early return.
            ReadOnlyMemory<byte>? hmacSecretMcOutput = null;
            IMemoryOwner<byte>? hmacSecretMcOutputOwner = null;
            if(action.HmacSecretMc is CtapMakeCredentialHmacSecretMcRequest hmacSecretMcRequest)
            {
                CtapGetAssertionHmacSecretRequest delegatedRequest = new(
                    hmacSecretMcRequest.ProtocolId, hmacSecretMcRequest.OwnPrivateKey, hmacSecretMcRequest.PeerKeyAgreement,
                    hmacSecretMcRequest.SaltEnc, hmacSecretMcRequest.SaltAuth, credRandomWithUV, credRandomWithoutUV);

                (CtapGetAssertionHmacSecretOutcomeKind mcOutcomeKind, hmacSecretMcOutputOwner, int mcOutputLength) =
                    await ComputeHmacSecretOutputAsync(delegatedRequest, action.UserVerified, context, cancellationToken).ConfigureAwait(false);

                if(mcOutcomeKind != CtapGetAssertionHmacSecretOutcomeKind.Success)
                {
                    keyPair.Dispose();
                    credentialId.Dispose();
                    credRandomWithUV.Dispose();
                    credRandomWithoutUV.Dispose();
                    largeBlobKey?.Dispose();

                    return new MakeCredentialHmacSecretMcFailed(mcOutcomeKind);
                }

                hmacSecretMcOutput = hmacSecretMcOutputOwner!.Memory[..mcOutputLength];
            }

            //R6/R3: the credProtect key is emitted iff the request carried a valid credProtect entry
            //(action.CredProtectRequested), never unsolicited; the minPinLength key is emitted iff the
            //pure transition resolved an authorized output value; the hmac-secret key is emitted iff the
            //request's own value was literal true (action.HmacSecretRequested) — NEVER false, since
            //CredRandom generation above never fails (contract R2b, snapshot lines 13204-13209
            //antecedent-false-by-construction). hmac-secret-mc's own slot carries the just-computed
            //encrypted output, or stays null when the request carried no hmac-secret-mc extension. All
            //four null (no extension requested, or requested but unauthorized/unsolicited) resolves to an
            //empty encoded map — TaggedMemory<byte>.Empty — which keeps ED at zero, matching every
            //pre-wave mc response byte-for-byte (trap 17).
            int? credProtectOutput = action.CredProtectRequested ? action.CredProtectLevel : null;
            bool? hmacSecretOutput = action.HmacSecretRequested ? true : null;
            TaggedMemory<byte> extensionsOutput;
            try
            {
                extensionsOutput = context.EncodeMakeCredentialExtensionOutputs(
                    credProtectOutput, hmacSecretOutput, action.MinPinLengthOutputValue, hmacSecretMcOutput);
            }
            finally
            {
                hmacSecretMcOutputOwner?.Dispose();
            }

            using DigestValue rpIdHash = ComputeRpIdHash(action.RpId, context.Pool);
            AuthenticatorDataFlags flags = BuildFlags(
                userPresent: action.UserPresent, userVerified: action.UserVerified, attestedCredentialDataIncluded: true, extensionDataIncluded: !extensionsOutput.IsEmpty);
            AttestedCredentialDataToWrite attestedCredentialData = new(context.Aaguid, credentialId, credentialPublicKeyCbor.Memory);
            TaggedMemory<byte> authData = AuthenticatorDataWriter.Write(
                rpIdHash, flags, signCount: 0, attestedCredentialData: attestedCredentialData, extensions: extensionsOutput.Memory);

            storedUserId = UserHandle.Create(action.UserId.AsReadOnlySpan(), context.Pool);

            //CreationSequence is a placeholder here: only the pure transition (OnCredentialMinted) knows
            //the state's current counter value, and stamps the real one via a `with` copy once this
            //record is folded back — mint order is decided by the store, not by the effect that builds
            //the record's other fields.
            CtapCredentialRecord record = new(
                credentialId, action.RpId, storedUserId, action.UserName, action.UserDisplayName,
                action.Algorithm, action.ResidentKey, keyPair.PrivateKey, SignCount: 0, CreationSequence: 0,
                PublicKey: keyPair.PublicKey, CredProtectLevel: action.CredProtectLevel,
                CredRandomWithUV: credRandomWithUV!, CredRandomWithoutUV: credRandomWithoutUV!, LargeBlobKey: largeBlobKey);

            CtapMakeCredentialResponse response = await BuildAttestationResponseAsync(
                action, keyPair.PrivateKey, authData.Memory, context, cancellationToken).ConfigureAwait(false);

            //R8/§12.3 line 12853: the TOP-LEVEL mc response member, never routed through the
            //authData-extensions writer above (line 12857's "not in the extensions field"). CredRandom
            //never appears in this or any other response (trap 9) — deliberately absent here.
            if(largeBlobKey is not null)
            {
                response = response with { LargeBlobKey = largeBlobKey.Memory };
            }

            return new CredentialMinted(response, record);
        }
        catch
        {
            keyPair?.Dispose();
            credentialId?.Dispose();
            storedUserId?.Dispose();
            credRandomWithUV?.Dispose();
            credRandomWithoutUV?.Dispose();
            largeBlobKey?.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Builds the <c>authenticatorMakeCredential</c> response's <c>fmt</c>/<c>attStmt</c>/<c>epAtt</c> per
    /// <paramref name="action"/>'s resolved <see cref="CtapAttestationFormatChoice"/> (CTAP 2.3, section
    /// 6.1.2, step 17; waveep R7/R9 for the certified branch): a packed self-attestation statement signed
    /// over <paramref name="authData"/> and <see cref="CtapGenerateCredentialKeyAction.ClientDataHash"/>
    /// with the just-minted credential key through <see cref="Fido2CredentialSigner.SignAssertionAsync"/>,
    /// a packed CERTIFIED statement over the same transcript signed with the SEEDED enterprise
    /// attestation private key (never the credential key), the standard
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-none-attestation">WebAuthn L3 section 8.7</see>
    /// empty-map <c>none</c> statement, or an omitted <c>attStmt</c> for the CTAP step-17 "omit
    /// attestation from the output" instruction.
    /// </summary>
    private static async ValueTask<CtapMakeCredentialResponse> BuildAttestationResponseAsync(
        CtapGenerateCredentialKeyAction action, PrivateKey credentialKey, ReadOnlyMemory<byte> authData, CtapActionContext context, CancellationToken cancellationToken)
    {
        return action.AttestationFormat switch
        {
            CtapAttestationFormatChoice.PackedSelf => await BuildPackedSelfResponseAsync(action, credentialKey, authData, context, cancellationToken).ConfigureAwait(false),
            CtapAttestationFormatChoice.PackedCertified => await BuildPackedCertifiedResponseAsync(action, authData, context, cancellationToken).ConfigureAwait(false),
            CtapAttestationFormatChoice.NoneWithStatement => new CtapMakeCredentialResponse(WellKnownWebAuthnAttestationFormats.None, authData, new byte[] { NoneAttestation.CanonicalEmptyMap }),
            CtapAttestationFormatChoice.NoneOmitted => new CtapMakeCredentialResponse(WellKnownWebAuthnAttestationFormats.None, authData, AttStmt: null),
            _ => throw new NotSupportedException($"No attestation response is defined for format choice '{action.AttestationFormat}'.")
        };

        static async ValueTask<CtapMakeCredentialResponse> BuildPackedSelfResponseAsync(
            CtapGenerateCredentialKeyAction action, PrivateKey credentialKey, ReadOnlyMemory<byte> authData, CtapActionContext context, CancellationToken cancellationToken)
        {
            Signature selfAttestationSignature = await Fido2CredentialSigner.SignAssertionAsync(
                credentialKey, authData, action.ClientDataHash, action.Algorithm, context.Pool, cancellationToken).ConfigureAwait(false);

            TaggedMemory<byte> attStmt;
            using(selfAttestationSignature)
            {
                attStmt = context.EncodePackedSelfAttestationStatement(action.Algorithm, selfAttestationSignature.AsReadOnlySpan());
            }

            return new CtapMakeCredentialResponse(WellKnownWebAuthnAttestationFormats.Packed, authData, attStmt.Memory);
        }

        //Waveep R7: signs authData || clientDataHash with the SEEDED enterprise attestation private key
        //(never action's credential key, trap 11) via the SAME project signing delegate the self path
        //uses, over the SAME transcript-building helper (Fido2CredentialSigner.SignAssertionAsync is
        //generic over which PrivateKey is handed to it). R9: epAtt is set true exactly here, the ONLY
        //site that ever produces this format choice.
        static async ValueTask<CtapMakeCredentialResponse> BuildPackedCertifiedResponseAsync(
            CtapGenerateCredentialKeyAction action, ReadOnlyMemory<byte> authData, CtapActionContext context, CancellationToken cancellationToken)
        {
            CtapEnterpriseAttestationProvisioning provisioning = context.EnterpriseAttestationProvisioning
                ?? throw new InvalidOperationException(
                    "A packed certified attestation was resolved for a request whose authenticator carries no seeded enterprise attestation provisioning.");
            EncodePackedCertifiedAttestationStatementDelegate encodeCertifiedStatement = context.EncodePackedCertifiedAttestationStatement
                ?? throw new InvalidOperationException(
                    "A packed certified attestation was resolved, but no EncodePackedCertifiedAttestationStatementDelegate was injected into this simulator.");

            Signature certifiedAttestationSignature = await Fido2CredentialSigner.SignAssertionAsync(
                provisioning.AttestationKey, authData, action.ClientDataHash, provisioning.Algorithm, context.Pool, cancellationToken).ConfigureAwait(false);

            TaggedMemory<byte> attStmt;
            using(certifiedAttestationSignature)
            {
                attStmt = encodeCertifiedStatement(provisioning.Algorithm, certifiedAttestationSignature.AsReadOnlySpan(), provisioning.X5c);
            }

            return new CtapMakeCredentialResponse(WellKnownWebAuthnAttestationFormats.Packed, authData, attStmt.Memory, EpAtt: true);
        }
    }


    /// <summary>
    /// <c>authenticatorGetAssertion</c>/<c>authenticatorGetNextAssertion</c>'s shared effect: when
    /// <see cref="CtapSignAssertionAction.HmacSecret"/> is present, runs CTAP 2.3 §12.7's processing
    /// algorithm's crypto half (<see cref="ComputeHmacSecretOutputAsync"/>, steps 4-9 — decapsulate,
    /// verify, decrypt, CredRandom selection, HMAC, encrypt) exactly ONCE and aborts the whole command
    /// with <see cref="GetAssertionHmacSecretFailed"/> on anything short of success (trap 5); otherwise
    /// builds the signed-over <c>authData</c> — with the hmac-secret authData extensions map embedded
    /// and the <c>ED</c> flag set iff that map is non-empty, mirroring
    /// <see cref="GenerateCredentialAsync"/>'s own mc-side composition — and signs
    /// <c>authData ‖ clientDataHash</c> with the resolved credential's private key through
    /// <see cref="Fido2CredentialSigner.SignAssertionAsync"/>. When
    /// <see cref="CtapSignAssertionAction.RememberOnCompletion"/> is present (the first response of a
    /// multi-account <c>authenticatorGetAssertion</c>), also mints a fresh, independently pooled copy of
    /// the client data hash for <see cref="CtapRememberedGetAssertionState"/> to own across commands —
    /// the pure transition cannot allocate that copy itself, since it has no memory pool. When
    /// <see cref="CtapSignAssertionAction.HmacSecret"/> is absent, <c>authData</c>'s <c>ED</c> flag stays
    /// zero and the encode call returns <see cref="TaggedMemory{T}.Empty"/> — BYTE-IDENTICAL to every
    /// pre-existing <c>authenticatorGetAssertion</c> test's authData (trap 16); neither <c>credProtect</c>
    /// nor <c>minPinLength</c> defines an <c>authenticatorGetAssertion</c> output (both are
    /// registration-only extensions, CTAP 2.3 §12.1/§12.5). <see cref="CtapSignAssertionAction.LargeBlobKey"/>
    /// (§12.3, R8) travels the SAME TOP-LEVEL-not-authData path <c>credProtect</c>/<c>minPinLength</c>
    /// use on the mc side — echoed verbatim onto the response's own <c>0x07</c> member, needing no
    /// further resolution here (the pure transition already decided its final value).
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The Signature returned by SignAssertionAsync is disposed within this method once its bytes are copied into the pooled rental the response's Signature field carries as a bare ReadOnlyMemory<byte>; that rental is never disposed back (it detaches from the pool the same way IssueUvTokenAsync's own encrypted-token copy does). The independently pooled client data hash copy transfers ownership into the returned AssertionSigned/CtapRememberedGetAssertionState, which the pure transition installs onto CtapAuthenticatorState and which is disposed when that remembered sequence is later discarded or replaced.")]
    private static async ValueTask<CtapAuthenticatorInput> SignAssertionAsync(CtapSignAssertionAction action, CtapActionContext context, CancellationToken cancellationToken)
    {
        ReadOnlyMemory<byte>? hmacSecretOutput = null;
        IMemoryOwner<byte>? hmacSecretOutputOwner = null;
        if(action.HmacSecret is CtapGetAssertionHmacSecretRequest hmacSecretRequest)
        {
            (CtapGetAssertionHmacSecretOutcomeKind outcomeKind, hmacSecretOutputOwner, int hmacSecretOutputLength) =
                await ComputeHmacSecretOutputAsync(hmacSecretRequest, action.UserVerified, context, cancellationToken).ConfigureAwait(false);

            if(outcomeKind != CtapGetAssertionHmacSecretOutcomeKind.Success)
            {
                return new GetAssertionHmacSecretFailed(outcomeKind);
            }

            hmacSecretOutput = hmacSecretOutputOwner!.Memory[..hmacSecretOutputLength];
        }

        TaggedMemory<byte> authData;
        try
        {
            TaggedMemory<byte> extensionsOutput = context.EncodeGetAssertionExtensionOutputs(hmacSecretOutput);

            using DigestValue rpIdHash = ComputeRpIdHash(action.RpId, context.Pool);
            AuthenticatorDataFlags flags = BuildFlags(
                userPresent: action.UserPresent, userVerified: action.UserVerified, attestedCredentialDataIncluded: false,
                extensionDataIncluded: !extensionsOutput.IsEmpty);
            authData = AuthenticatorDataWriter.Write(rpIdHash, flags, action.NewSignCount, extensions: extensionsOutput.Memory);
        }
        finally
        {
            hmacSecretOutputOwner?.Dispose();
        }

        Signature signature = await Fido2CredentialSigner.SignAssertionAsync(
            action.CredentialKey, authData.Memory, action.ClientDataHash, action.Algorithm, context.Pool, cancellationToken).ConfigureAwait(false);

        TaggedMemory<byte> signatureBytes;
        using(signature)
        {
            //Rented from context.Pool rather than a bare `new byte[]` (no-naked-bytes-uniform), mirroring
            //IssueUvTokenAsync's identical shape: the rental is never disposed back, since the response's
            //Signature field is a bare ReadOnlyMemory<byte> with no disposal contract that outlives this
            //method, so the copy must detach from the pool rental rather than alias memory a `using` block
            //could hand back.
            IMemoryOwner<byte> signatureStorage = context.Pool.Rent(signature.Length);
            try
            {
                signature.AsReadOnlySpan().CopyTo(signatureStorage.Memory.Span);
                signatureBytes = new TaggedMemory<byte>(signatureStorage.Memory[..signature.Length], signature.Tag);
            }
            catch
            {
                signatureStorage.Dispose();
                throw;
            }
        }

        PublicKeyCredentialDescriptor descriptor = new() { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = action.CredentialId };

        //R8/§12.3 line 12867: the TOP-LEVEL ga response member, already resolved by the pure transition
        //(DeclareSignAssertion) to null unless requested-AND-present — never routed through authData.
        CtapGetAssertionResponse response = new(
            descriptor, authData.Memory, signatureBytes.Memory, action.ResponseUser, action.NumberOfCredentials, UserSelected: null, LargeBlobKey: action.LargeBlobKey);

        CtapRememberedGetAssertionState? rememberedState = action.RememberOnCompletion is CtapRememberGetAssertionRequest rememberOnCompletion
            ? new CtapRememberedGetAssertionState(
                rememberOnCompletion.ApplicableCredentialIds,
                CopyClientDataHash(action.ClientDataHash, context.Pool),
                rememberOnCompletion.UserPresent,
                rememberOnCompletion.UserVerified,
                CredentialCounter: 1,
                rememberOnCompletion.StartedAt,
                rememberOnCompletion.AuthenticatingPinUvAuthProtocol,
                rememberOnCompletion.LargeBlobKeyRequested)
            : null;

        return new AssertionSigned(response, action.CredentialId, action.NewSignCount, rememberedState);
    }


    /// <summary>
    /// Runs CTAP 2.3 §12.7's <c>hmac-secret</c> processing algorithm's crypto half (snapshot lines
    /// 13292-13339, contract R4 steps 4-9), composed entirely from <paramref name="request"/>'s already
    /// selected <see cref="CtapPinUvAuthProtocol"/> operations (trap 22 — no second ECDH/AES/HMAC path).
    /// Called from <see cref="SignAssertionAsync"/> for <c>authenticatorGetAssertion</c>'s own
    /// <c>hmac-secret</c> extension AND from <see cref="GenerateCredentialAsync"/> for
    /// <c>authenticatorMakeCredential</c>'s <c>hmac-secret-mc</c> extension (CTAP 2.3 §12.8, snapshot
    /// line 13402 — contract R6's pure delegation: the identical routine, never a second implementation):
    /// <c>decapsulate</c> → <c>verify(sharedSecret, saltEnc, saltAuth)</c> (failure →
    /// <see cref="CtapGetAssertionHmacSecretOutcomeKind.VerifyFailed"/>, trap 2, checked BEFORE decrypt
    /// is ever attempted, trap 5) → <c>decrypt(sharedSecret, saltEnc)</c>, gated on the DECRYPTED
    /// plaintext being exactly 32 or 64 bytes (failure or wrong length →
    /// <see cref="CtapGetAssertionHmacSecretOutcomeKind.DecryptFailed"/>, trap 3; never gated on
    /// <paramref name="request"/>'s own <see cref="CtapGetAssertionHmacSecretRequest.SaltEnc"/> ciphertext
    /// length, which is IV-prefixed and longer for protocol two, trap 7) → CredRandom selection keyed on
    /// <paramref name="userVerified"/> — THIS response's own resolved <c>uv</c> bit, not any cached value
    /// (trap 4) → <c>HMAC-SHA-256(CredRandom, salt)</c> per salt via
    /// <see cref="CryptographicKeyEvents"/>'s <c>ComputeHmacAsync</c> convenience wrapper (the same
    /// registered <see cref="ComputeHmacDelegate"/> <see cref="CtapPinUvAuthProtocol.ComputeHmac"/>
    /// itself resolves — trap 22's "ComputeHmacDelegate is the only HMAC entry") → <c>encrypt(sharedSecret,
    /// output1 [|| output2])</c>. Every pooled intermediate (the shared secret, the decrypted salts, both
    /// HMAC outputs, the assembled plaintext) is cleared before disposal (R10); the resolved credential's
    /// borrowed CredRandom pair is never cleared or disposed here — the record retains ownership for its
    /// whole lifetime.
    /// </summary>
    /// <returns>
    /// The outcome and, on <see cref="CtapGetAssertionHmacSecretOutcomeKind.Success"/>, a pool-owned
    /// buffer holding the encrypted output (<paramref name="request"/>'s protocol prefixes a fresh
    /// 16-byte IV for protocol two — trap 6) together with its exact length (the rental may be
    /// longer-than-requested; the caller slices). <see langword="null"/>/<c>0</c> on any other outcome.
    /// Ownership of a non-null buffer transfers to the caller.
    /// </returns>
    private static async ValueTask<(CtapGetAssertionHmacSecretOutcomeKind Kind, IMemoryOwner<byte>? EncryptedOutput, int EncryptedOutputLength)> ComputeHmacSecretOutputAsync(
        CtapGetAssertionHmacSecretRequest request, bool userVerified, CtapActionContext context, CancellationToken cancellationToken)
    {
        CtapPinUvAuthProtocol protocol = CtapPinUvAuthProtocol.CreateDefault(request.ProtocolId);

        IMemoryOwner<byte> sharedSecret = await protocol.DecapsulateAsync(
            request.OwnPrivateKey, request.PeerKeyAgreement, context.Pool, cancellationToken).ConfigureAwait(false);
        try
        {
            bool verified = await protocol.VerifyAsync(
                sharedSecret.Memory, request.SaltEnc, request.SaltAuth, context.Pool, cancellationToken).ConfigureAwait(false);
            if(!verified)
            {
                return (CtapGetAssertionHmacSecretOutcomeKind.VerifyFailed, null, 0);
            }

            DecryptedContent salts;
            try
            {
                salts = await protocol.DecryptAsync(sharedSecret.Memory, request.SaltEnc, context.Pool, cancellationToken).ConfigureAwait(false);
            }
            catch(Exception exception) when(IsPinCryptoOperationFailure(exception))
            {
                return (CtapGetAssertionHmacSecretOutcomeKind.DecryptFailed, null, 0);
            }

            try
            {
                if(salts.Length != HmacSecretSaltLength && salts.Length != HmacSecretTwoSaltLength)
                {
                    return (CtapGetAssertionHmacSecretOutcomeKind.DecryptFailed, null, 0);
                }

                IMemoryOwner<byte> credRandom = userVerified ? request.CredRandomWithUV : request.CredRandomWithoutUV;

                IMemoryOwner<byte> plaintext = await ComputeHmacSecretPlaintextAsync(salts, credRandom, context, cancellationToken).ConfigureAwait(false);
                try
                {
                    using Ciphertext ciphertext = await protocol.EncryptAsync(
                        sharedSecret.Memory, plaintext.Memory, context.Pool, cancellationToken).ConfigureAwait(false);

                    IMemoryOwner<byte> encryptedOutput = context.Pool.Rent(ciphertext.Length);
                    try
                    {
                        ciphertext.AsReadOnlySpan().CopyTo(encryptedOutput.Memory.Span);

                        return (CtapGetAssertionHmacSecretOutcomeKind.Success, encryptedOutput, ciphertext.Length);
                    }
                    catch
                    {
                        encryptedOutput.Dispose();
                        throw;
                    }
                }
                finally
                {
                    plaintext.Memory.Span.Clear();
                    plaintext.Dispose();
                }
            }
            finally
            {
                salts.Dispose();
            }
        }
        finally
        {
            sharedSecret.Memory.Span.Clear();
            sharedSecret.Dispose();
        }
    }


    /// <summary>
    /// Computes CTAP 2.3 §12.7's <c>output1</c> (and, for a two-salt request, <c>output2</c>) — each
    /// <c>HMAC-SHA-256(CredRandom, salt)</c> — and assembles the plaintext <see cref="ComputeHmacSecretOutputAsync"/>
    /// encrypts (snapshot lines 13321-13328): <c>output1</c> alone (32 bytes) or <c>output1 || output2</c>
    /// (64 bytes).
    /// </summary>
    /// <param name="salts">The decrypted salt1 (and, for a two-salt request, salt2) plaintext — already length-validated by the caller.</param>
    /// <param name="credRandom">The selected CredRandom (contract R4 step 7), borrowed — read, never cleared or disposed.</param>
    /// <param name="context">The action context supplying the memory pool every allocation rents from.</param>
    /// <param name="cancellationToken">A token observed across both HMAC computations.</param>
    /// <returns>A pool-owned buffer holding the assembled plaintext. Ownership transfers to the caller, which must clear and dispose it.</returns>
    private static async ValueTask<IMemoryOwner<byte>> ComputeHmacSecretPlaintextAsync(
        DecryptedContent salts, IMemoryOwner<byte> credRandom, CtapActionContext context, CancellationToken cancellationToken)
    {
        ReadOnlyMemory<byte> saltBytes = salts.AsReadOnlyMemory();
        ReadOnlyMemory<byte> salt1 = saltBytes[..HmacSecretSaltLength];

        using HmacValue output1 = await CryptographicKeyEvents.ComputeHmacAsync(
            salt1, credRandom.Memory, HmacSecretSaltLength, CryptoTags.HmacSha256Value, context.Pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        if(saltBytes.Length == HmacSecretSaltLength)
        {
            IMemoryOwner<byte> plaintext = context.Pool.Rent(HmacSecretSaltLength);
            output1.AsReadOnlySpan().CopyTo(plaintext.Memory.Span);

            return plaintext;
        }

        ReadOnlyMemory<byte> salt2 = saltBytes[HmacSecretSaltLength..];
        using HmacValue output2 = await CryptographicKeyEvents.ComputeHmacAsync(
            salt2, credRandom.Memory, HmacSecretSaltLength, CryptoTags.HmacSha256Value, context.Pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        IMemoryOwner<byte> twoSaltPlaintext = context.Pool.Rent(HmacSecretTwoSaltLength);
        output1.AsReadOnlySpan().CopyTo(twoSaltPlaintext.Memory.Span);
        output2.AsReadOnlySpan().CopyTo(twoSaltPlaintext.Memory.Span[HmacSecretSaltLength..]);

        return twoSaltPlaintext;
    }


    /// <summary>
    /// <c>authenticatorMakeCredential</c>/<c>authenticatorGetAssertion</c>'s shared verify effect (CTAP
    /// 2.3 §6.1.2 step 11.1.1 / §6.2.2 step 6.1.1): resolves <see cref="CtapVerifyPinUvAuthTokenAction.ProtocolId"/>'s
    /// crypto operations and runs the state-aware <c>verify</c> composition
    /// (<see cref="CtapPinUvAuthTokenVerificationExtensions.VerifyPinUvAuthTokenAsync"/>) with the
    /// presented token itself as the HMAC key, over the client data hash alone, folding the boolean
    /// result back with <see cref="CtapVerifyPinUvAuthTokenAction.Continuation"/> unchanged.
    /// </summary>
    private static async ValueTask<CtapAuthenticatorInput> VerifyPinUvAuthTokenAsync(
        CtapVerifyPinUvAuthTokenAction action, CtapActionContext context, CancellationToken cancellationToken)
    {
        CtapPinUvAuthProtocol protocol = CtapPinUvAuthProtocol.CreateDefault(action.ProtocolId);
        bool verified = await protocol.VerifyPinUvAuthTokenAsync(
            action.TokenState,
            action.TokenState.Token.AsReadOnlyMemory(),
            action.ClientDataHash.AsReadOnlyMemory(),
            action.PinUvAuthParam,
            context.Pool,
            cancellationToken).ConfigureAwait(false);

        return new PinUvAuthTokenVerified(verified, action.Continuation);
    }


    /// <summary>
    /// <c>authenticatorConfig</c>'s own verify effect (CTAP 2.3 §6.11 step 4.4, lines 7978-7981):
    /// assembles the compound verify message <c>32×0xff || 0x0d || uint8(subCommand) || subCommandParams</c>
    /// in a pooled buffer (<see cref="BuildAuthenticatorConfigMessage"/>), then runs the SAME
    /// state-aware <c>verify</c> composition <see cref="VerifyPinUvAuthTokenAsync"/> uses. The assembled
    /// message is non-secret wire data (the platform's own request bytes), but is still cleared and
    /// disposed in <see langword="finally"/> rather than left to the pool's own reuse, per R6.
    /// </summary>
    private static async ValueTask<CtapAuthenticatorInput> VerifyAuthenticatorConfigTokenAsync(
        CtapVerifyAuthenticatorConfigTokenAction action, CtapActionContext context, CancellationToken cancellationToken)
    {
        CtapPinUvAuthProtocol protocol = CtapPinUvAuthProtocol.CreateDefault(action.ProtocolId);
        IMemoryOwner<byte> message = BuildAuthenticatorConfigMessage(action.SubCommand, action.SubCommandParams, context.Pool);
        bool verified;
        try
        {
            verified = await protocol.VerifyPinUvAuthTokenAsync(
                action.TokenState,
                action.TokenState.Token.AsReadOnlyMemory(),
                message.Memory,
                action.PinUvAuthParam,
                context.Pool,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            message.Memory.Span.Clear();
            message.Dispose();
        }

        return new PinUvAuthTokenVerified(verified, action.Continuation);
    }


    /// <summary>
    /// Assembles <c>authenticatorConfig</c>'s pinUvAuthParam verify message (CTAP 2.3 §6.11, lines
    /// 7947/6321): <c>32×0xff || 0x0d || uint8(subCommand) || subCommandParams</c>. R5's elision ruling:
    /// <paramref name="subCommandParams"/> is empty when the platform sent none, contributing zero
    /// trailing bytes rather than an encoded empty CBOR map — the caller resolves that emptiness before
    /// calling this method (<see cref="OnAuthenticatorConfigRequested"/>'s <c>?? ReadOnlyMemory&lt;byte&gt;.Empty</c>).
    /// A private sibling of <see cref="BuildConcatenatedMessage"/> rather than a generalized overload of
    /// it, since this message has a fixed 32-byte prefix and a command byte <c>BuildConcatenatedMessage</c>'s
    /// two-segment shape does not carry.
    /// </summary>
    private static SlicedMemoryOwner BuildAuthenticatorConfigMessage(int subCommand, ReadOnlyMemory<byte> subCommandParams, MemoryPool<byte> pool)
    {
        const int PrefixLength = 32;
        IMemoryOwner<byte> combined = pool.Rent(PrefixLength + 1 + 1 + subCommandParams.Length);
        try
        {
            Span<byte> span = combined.Memory.Span;
            span[..PrefixLength].Fill(0xff);
            span[PrefixLength] = WellKnownCtapCommands.AuthenticatorConfig;
            span[PrefixLength + 1] = (byte)subCommand;
            subCommandParams.Span.CopyTo(span[(PrefixLength + 2)..]);

            return new SlicedMemoryOwner(combined, PrefixLength + 2 + subCommandParams.Length);
        }
        catch
        {
            combined.Dispose();
            throw;
        }
    }


    /// <summary>
    /// <c>authenticatorCredentialManagement</c>'s own verify effect (CTAP 2.3 §6.5.8, line 6309-6315):
    /// assembles the THIRD verify-message shape <c>uint8(subCommand) [|| subCommandParams]</c> in a
    /// pooled buffer (<see cref="BuildCredentialManagementMessage"/>), then runs the SAME state-aware
    /// <c>verify</c> composition <see cref="VerifyPinUvAuthTokenAsync"/>/<see cref="VerifyAuthenticatorConfigTokenAsync"/>
    /// use. The assembled message is non-secret wire data (the platform's own request bytes), but is
    /// still cleared and disposed in <see langword="finally"/>, mirroring
    /// <see cref="VerifyAuthenticatorConfigTokenAsync"/>'s own convention.
    /// </summary>
    private static async ValueTask<CtapAuthenticatorInput> VerifyCredentialManagementTokenAsync(
        CtapVerifyCredentialManagementTokenAction action, CtapActionContext context, CancellationToken cancellationToken)
    {
        CtapPinUvAuthProtocol protocol = CtapPinUvAuthProtocol.CreateDefault(action.ProtocolId);
        IMemoryOwner<byte> message = BuildCredentialManagementMessage(action.SubCommand, action.SubCommandParams, context.Pool);
        bool verified;
        try
        {
            verified = await protocol.VerifyPinUvAuthTokenAsync(
                action.TokenState,
                action.TokenState.Token.AsReadOnlyMemory(),
                message.Memory,
                action.PinUvAuthParam,
                context.Pool,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            message.Memory.Span.Clear();
            message.Dispose();
        }

        return new PinUvAuthTokenVerified(verified, action.Continuation);
    }


    /// <summary>
    /// Assembles <c>authenticatorCredentialManagement</c>'s pinUvAuthParam verify message (CTAP 2.3
    /// §6.5.8, line 6309-6315): <c>uint8(subCommand) [|| subCommandParams]</c> — NO 32-byte <c>0xff</c>
    /// prefix, NO command byte, unlike <see cref="BuildAuthenticatorConfigMessage"/>'s own compound
    /// shape (R4). <paramref name="subCommandParams"/> is empty for <c>getCredsMetadata</c>/
    /// <c>enumerateRPsBegin</c>, which structurally never carry one — the message then elides this
    /// segment entirely, contributing zero trailing bytes.
    /// </summary>
    private static SlicedMemoryOwner BuildCredentialManagementMessage(int subCommand, ReadOnlyMemory<byte> subCommandParams, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> combined = pool.Rent(1 + subCommandParams.Length);
        try
        {
            Span<byte> span = combined.Memory.Span;
            span[0] = (byte)subCommand;
            subCommandParams.Span.CopyTo(span[1..]);

            return new SlicedMemoryOwner(combined, 1 + subCommandParams.Length);
        }
        catch
        {
            combined.Dispose();
            throw;
        }
    }


    /// <summary>
    /// <c>authenticatorBioEnrollment</c>'s own verify effect (CTAP 2.3 §6.7, bio scout Finding C):
    /// assembles the FOURTH verify-message shape <c>uint8(modality) || uint8(subCommand) [||
    /// subCommandParams]</c> in a pooled buffer (<see cref="BuildBioEnrollmentMessage"/>), then runs the
    /// SAME state-aware <c>verify</c> composition every other verify executor uses.
    /// </summary>
    private static async ValueTask<CtapAuthenticatorInput> VerifyBioEnrollmentTokenAsync(
        CtapVerifyBioEnrollmentTokenAction action, CtapActionContext context, CancellationToken cancellationToken)
    {
        CtapPinUvAuthProtocol protocol = CtapPinUvAuthProtocol.CreateDefault(action.ProtocolId);
        IMemoryOwner<byte> message = BuildBioEnrollmentMessage(action.Modality, action.SubCommand, action.SubCommandParams, context.Pool);
        bool verified;
        try
        {
            verified = await protocol.VerifyPinUvAuthTokenAsync(
                action.TokenState,
                action.TokenState.Token.AsReadOnlyMemory(),
                message.Memory,
                action.PinUvAuthParam,
                context.Pool,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            message.Memory.Span.Clear();
            message.Dispose();
        }

        return new PinUvAuthTokenVerified(verified, action.Continuation);
    }


    /// <summary>
    /// Assembles <c>authenticatorBioEnrollment</c>'s pinUvAuthParam verify message (bio scout Finding C):
    /// <c>uint8(modality) || uint8(subCommand) [|| subCommandParams]</c> — a TWO-byte leading prefix,
    /// unlike <see cref="BuildCredentialManagementMessage"/>'s single leading byte.
    /// <paramref name="subCommandParams"/> is empty for <c>enumerateEnrollments</c>, which structurally
    /// never carries one — the message then elides this segment entirely, contributing zero trailing
    /// bytes.
    /// </summary>
    private static SlicedMemoryOwner BuildBioEnrollmentMessage(int modality, int subCommand, ReadOnlyMemory<byte> subCommandParams, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> combined = pool.Rent(2 + subCommandParams.Length);
        try
        {
            Span<byte> span = combined.Memory.Span;
            span[0] = (byte)modality;
            span[1] = (byte)subCommand;
            subCommandParams.Span.CopyTo(span[2..]);

            return new SlicedMemoryOwner(combined, 2 + subCommandParams.Length);
        }
        catch
        {
            combined.Dispose();
            throw;
        }
    }


    /// <summary>
    /// <c>authenticatorLargeBlobs</c>' own per-fragment verify effect (CTAP 2.3 §6.10.2, lines 7578/7646):
    /// assembles the SIXTH verify-message shape <c>32×0xff || h'0c00' || uint32LittleEndian(offset) ||
    /// SHA-256(fragment)</c> (<see cref="BuildLargeBlobsMessage"/>), then runs the SAME state-aware
    /// <c>verify</c> composition every other verify executor uses. The assembled message is non-secret
    /// wire data (the platform's own request bytes plus a digest derived from them), but is still cleared
    /// and disposed in <see langword="finally"/>, mirroring <see cref="VerifyAuthenticatorConfigTokenAsync"/>'s
    /// own convention.
    /// </summary>
    private static async ValueTask<CtapAuthenticatorInput> VerifyLargeBlobsTokenAsync(
        CtapVerifyLargeBlobsTokenAction action, CtapActionContext context, CancellationToken cancellationToken)
    {
        CtapPinUvAuthProtocol protocol = CtapPinUvAuthProtocol.CreateDefault(action.ProtocolId);
        IMemoryOwner<byte> message = BuildLargeBlobsMessage(action.Offset, action.Fragment.Span, context.Pool);
        bool verified;
        try
        {
            verified = await protocol.VerifyPinUvAuthTokenAsync(
                action.TokenState,
                action.TokenState.Token.AsReadOnlyMemory(),
                message.Memory,
                action.PinUvAuthParam,
                context.Pool,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            message.Memory.Span.Clear();
            message.Dispose();
        }

        return new PinUvAuthTokenVerified(verified, action.Continuation);
    }


    /// <summary>
    /// Assembles <c>authenticatorLargeBlobs</c>' pinUvAuthParam verify message (CTAP 2.3 §6.10.2, lines
    /// 7578/7646, §6.5.8 line 6317-6318): <c>32×0xff || h'0c00' || uint32LittleEndian(offset) ||
    /// SHA-256(contents of the <c>set</c> byte string, i.e. not including the outer CBOR major-type-two
    /// tag)</c>. Reuses <see cref="BuildAuthenticatorConfigMessage"/>'s own 32-byte <c>0xff</c> prefix
    /// (<c>span[..PrefixLength].Fill(0xff)</c>), but the command segment is TWO fixed bytes
    /// (<c>0x0c 0x00</c>, not a bare command byte), <paramref name="offset"/> is written
    /// LITTLE-endian — the surface's ONLY little-endian integer (seams trap 2;
    /// <see cref="BinaryPrimitives.WriteUInt32LittleEndian"/>) — and the final segment is a live SHA-256
    /// digest of <paramref name="fragment"/> (<see cref="CryptographicKeyEvents.ComputeDigest"/>, the
    /// <see cref="ComputeStoredPinHash"/> precedent's digest primitive), computed here because a digest
    /// is not a pure byte concatenation the pure transition function could assemble itself (D3, seams
    /// Finding D).
    /// </summary>
    private static SlicedMemoryOwner BuildLargeBlobsMessage(uint offset, ReadOnlySpan<byte> fragment, MemoryPool<byte> pool)
    {
        const int PrefixLength = 32;
        const int CommandSegmentLength = 2;
        const int OffsetLength = 4;

        using DigestValue fragmentDigest = CryptographicKeyEvents.ComputeDigest(fragment, Sha256Length, CryptoTags.Sha256Digest, pool);

        IMemoryOwner<byte> combined = pool.Rent(PrefixLength + CommandSegmentLength + OffsetLength + Sha256Length);
        try
        {
            Span<byte> span = combined.Memory.Span;
            span[..PrefixLength].Fill(0xff);
            span[PrefixLength] = WellKnownCtapCommands.LargeBlobs;
            span[PrefixLength + 1] = 0x00;
            BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(PrefixLength + CommandSegmentLength, OffsetLength), offset);
            fragmentDigest.AsReadOnlySpan().CopyTo(span[(PrefixLength + CommandSegmentLength + OffsetLength)..]);

            return new SlicedMemoryOwner(combined, PrefixLength + CommandSegmentLength + OffsetLength + Sha256Length);
        }
        catch
        {
            combined.Dispose();
            throw;
        }
    }


    /// <summary>
    /// <c>authenticatorLargeBlobs</c> <c>set</c>'s append/commit effect (CTAP 2.3 §6.10.2, lines
    /// 7657-7671, seams Finding E): writes <see cref="CtapCommitLargeBlobArrayAction.Fragment"/> into the
    /// pending buffer at <see cref="CtapCommitLargeBlobArrayAction.Offset"/> — renting a fresh buffer
    /// sized <see cref="CtapCommitLargeBlobArrayAction.ExpectedLength"/> when
    /// <see cref="CtapCommitLargeBlobArrayAction.ExistingPendingBuffer"/> is <see langword="null"/> (a
    /// fresh <c>offset == 0</c> sequence, seams Q5's up-front-rent reading), otherwise reusing it. If the
    /// pending length has not yet reached <see cref="CtapCommitLargeBlobArrayAction.ExpectedLength"/>,
    /// folds back the still-owned buffer to remember. Otherwise runs the commit-time integrity check —
    /// <c>LEFT(SHA-256(preceding bytes), 16)</c> compared, in constant time, against the completed
    /// buffer's own trailing <see cref="LargeBlobArrayTrailingHashLength"/> bytes (line 7666) — the OTHER
    /// SHA-256 on this surface, distinct from <see cref="BuildLargeBlobsMessage"/>'s per-fragment digest
    /// (seams trap 3): on success, adopts the buffer into a <see cref="PooledMemory"/> with NO further
    /// copy (ownership transfers directly); on failure, disposes the buffer — the previously stored
    /// <see cref="CtapAuthenticatorState.SerializedLargeBlobArray"/> is never touched either way (line
    /// 7666's "the stored array UNCHANGED"). Runs identically whether <see cref="CtapCommitLargeBlobArrayAction.AuthenticatingPinUvAuthProtocol"/>
    /// is <see langword="null"/> (a tokenless write) or set: the integrity check has no auth dependency.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The constructed PooledMemory transfers ownership into the returned CtapLargeBlobArrayCommitAttempted.CommittedArray, which OnLargeBlobArrayCommitAttempted adopts as CtapAuthenticatorState.SerializedLargeBlobArray; the analyzer cannot see this transfer through the record construction.")]
    private static ValueTask<CtapAuthenticatorInput> CommitLargeBlobArrayAsync(
        CtapCommitLargeBlobArrayAction action, CtapActionContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        IMemoryOwner<byte> buffer = action.ExistingPendingBuffer ?? context.Pool.Rent(action.ExpectedLength);
        action.Fragment.Span.CopyTo(buffer.Memory.Span.Slice(action.Offset, action.Fragment.Length));

        int newNextOffset = action.Offset + action.Fragment.Length;
        if(newNextOffset != action.ExpectedLength)
        {
            return ValueTask.FromResult<CtapAuthenticatorInput>(new CtapLargeBlobArrayCommitAttempted(
                IsComplete: false, PendingBuffer: buffer, PendingNextOffset: newNextOffset, action.ExpectedLength,
                action.AuthenticatingPinUvAuthProtocol, IsIntegrityValid: false, CommittedArray: null));
        }

        ReadOnlySpan<byte> completedArray = buffer.Memory.Span[..action.ExpectedLength];
        int trailingHashStart = action.ExpectedLength - LargeBlobArrayTrailingHashLength;
        ReadOnlySpan<byte> precedingBytes = completedArray[..trailingHashStart];
        ReadOnlySpan<byte> storedTrailingHash = completedArray[trailingHashStart..];

        bool isIntegrityValid;
        using(DigestValue fullDigest = CryptographicKeyEvents.ComputeDigest(precedingBytes, Sha256Length, CryptoTags.Sha256Digest, context.Pool))
        {
            isIntegrityValid = CryptographicOperations.FixedTimeEquals(fullDigest.AsReadOnlySpan()[..LargeBlobArrayTrailingHashLength], storedTrailingHash);
        }

        if(!isIntegrityValid)
        {
            buffer.Dispose();

            return ValueTask.FromResult<CtapAuthenticatorInput>(new CtapLargeBlobArrayCommitAttempted(
                IsComplete: true, PendingBuffer: null, PendingNextOffset: newNextOffset, action.ExpectedLength,
                action.AuthenticatingPinUvAuthProtocol, IsIntegrityValid: false, CommittedArray: null));
        }

        var committedArray = new PooledMemory(buffer, action.ExpectedLength, Fido2BufferTags.CtapSerializedLargeBlobArrayPayload);

        return ValueTask.FromResult<CtapAuthenticatorInput>(new CtapLargeBlobArrayCommitAttempted(
            IsComplete: true, PendingBuffer: null, PendingNextOffset: newNextOffset, action.ExpectedLength,
            action.AuthenticatingPinUvAuthProtocol, IsIntegrityValid: true, committedArray));
    }


    /// <summary>
    /// <c>enrollBegin</c>'s own effect (CTAP 2.3 §6.7.4, steps 8-9): mints a fresh 16-byte template
    /// identifier from the entropy provider — mirroring <see cref="GenerateCredentialAsync"/>'s own
    /// credential-identifier minting exactly (R6) — then simulates the enrollment's first sample capture
    /// through the injected <see cref="SimulateFingerprintCaptureDelegate"/> (R8).
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the minted BioEnrollmentTemplateId transfers to the returned BioEnrollmentCaptureStarted input (disposed in the catch block on capture-simulation failure); the analyzer cannot see this transfer through the record construction.")]
    private static ValueTask<CtapAuthenticatorInput> BeginBioEnrollmentCaptureAsync(CtapActionContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        Span<byte> templateIdBytes = stackalloc byte[BioEnrollmentTemplateIdLength];
        context.Rng(templateIdBytes);
        BioEnrollmentTemplateId templateId = BioEnrollmentTemplateId.Create(templateIdBytes, context.Pool);
        try
        {
            int lastEnrollSampleStatus = context.SimulateFingerprintCapture();

            return ValueTask.FromResult<CtapAuthenticatorInput>(new BioEnrollmentCaptureStarted(templateId, lastEnrollSampleStatus));
        }
        catch
        {
            templateId.Dispose();
            throw;
        }
    }


    /// <summary>
    /// <c>enrollCaptureNextSample</c>'s own effect (CTAP 2.3 §6.7.4): simulates the in-progress
    /// enrollment's next sample capture through the injected <see cref="SimulateFingerprintCaptureDelegate"/>
    /// (R8) — no entropy draw, since the template identifier was already minted by <c>enrollBegin</c>.
    /// </summary>
    private static ValueTask<CtapAuthenticatorInput> ContinueBioEnrollmentCaptureAsync(CtapActionContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        int lastEnrollSampleStatus = context.SimulateFingerprintCapture();

        return ValueTask.FromResult<CtapAuthenticatorInput>(new BioEnrollmentSampleCaptured(lastEnrollSampleStatus));
    }


    /// <summary>
    /// <c>enumerateRPsBegin</c>/<c>enumerateRPsGetNextRP</c>'s shared effect: computes one relying
    /// party's fresh <c>rpIDHash</c> through the SAME <see cref="ComputeRpIdHash"/> helper
    /// <c>authenticatorMakeCredential</c>/<c>authenticatorGetAssertion</c> already use, then assembles
    /// the complete response — the pure transition has no memory pool to compute a digest from. The
    /// digest is copied into a SECOND pool rental rather than aliased: <see cref="ComputeRpIdHash"/>'s
    /// pool-backed <see cref="DigestValue"/> is disposed and returned to <see cref="CtapActionContext.Pool"/>
    /// at the end of the <c>using</c> block below, while <see cref="CtapCredentialManagementResponse.RpIdHash"/>
    /// is a bare <c>ReadOnlyMemory&lt;byte&gt;</c> that carries no disposal contract of its own and outlives
    /// this method, so the copy must detach from the first pool rental rather than alias memory the block's
    /// disposal hands back to the pool — the second rental is itself never disposed back, mirroring
    /// <see cref="IssueUvTokenAsync"/>'s identical detach rationale for its own encrypted-token copy.
    /// </summary>
    private static ValueTask<CtapAuthenticatorInput> EmitCredentialManagementRpAsync(
        CtapEmitCredentialManagementRpAction action, CtapActionContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        TaggedMemory<byte> rpIdHashCarrier;
        using(DigestValue rpIdHash = ComputeRpIdHash(action.RpId, context.Pool))
        {
            IMemoryOwner<byte> rpIdHashStorage = context.Pool.Rent(rpIdHash.Length);
            try
            {
                rpIdHash.AsReadOnlySpan().CopyTo(rpIdHashStorage.Memory.Span);
                rpIdHashCarrier = new TaggedMemory<byte>(rpIdHashStorage.Memory[..rpIdHash.Length], rpIdHash.Tag);
            }
            catch
            {
                rpIdHashStorage.Dispose();
                throw;
            }
        }

        CtapCredentialManagementResponse response = new(
            Rp: new CtapPublicKeyCredentialRpEntity(action.RpId),
            RpIdHash: rpIdHashCarrier.Memory,
            TotalRps: action.TotalRps);

        return ValueTask.FromResult<CtapAuthenticatorInput>(new CredentialManagementResponseComputed(response));
    }


    /// <summary>
    /// <c>enumerateCredentialsBegin</c>'s own effect: since no by-hash index exists on the store, matches
    /// the request's <c>rpIDHash</c> against every resident credential's own freshly computed hash (CTAP
    /// 2.3 §6.8.4, line 7297), one <see cref="ComputeRpIdHash"/> call per candidate, ordering the matches
    /// <see cref="CtapCredentialRecord.CreationSequence"/>-ascending (R9) before folding back.
    /// </summary>
    private static ValueTask<CtapAuthenticatorInput> LocateCredentialManagementCredentialsAsync(
        CtapLocateCredentialManagementCredentialsAction action, CtapActionContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        List<CtapCredentialRecord> matches = [];
        foreach(CtapCredentialRecord candidate in action.CredentialsByCredentialId.Values)
        {
            if(!candidate.IsResident)
            {
                continue;
            }

            using DigestValue candidateHash = ComputeRpIdHash(candidate.RpId, context.Pool);
            if(candidateHash.AsReadOnlySpan().SequenceEqual(action.RequestRpIdHash.Span))
            {
                matches.Add(candidate);
            }
        }

        matches.Sort(static (left, right) => left.CreationSequence.CompareTo(right.CreationSequence));

        List<CredentialId> matchedCredentialIds = new(matches.Count);
        foreach(CtapCredentialRecord match in matches)
        {
            matchedCredentialIds.Add(match.CredentialId);
        }

        return ValueTask.FromResult<CtapAuthenticatorInput>(
            new CredentialManagementCredentialsLocated(matchedCredentialIds, action.Now, action.AuthenticatingPinUvAuthProtocol));
    }


    /// <summary>
    /// <c>setMinPINLength</c> step 7's effect (CTAP 2.3 §6.11.4, lines 8171-8177): mints a fresh
    /// <c>pinUvAuthToken</c> for both PIN/UV auth protocols — the only entropy-consuming piece of that
    /// step, hence the only piece routed through the effectful loop.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Both CtapPinUvAuthTokenState.Initial() calls transfer ownership into the returned PinUvAuthTokensReset's FreshProtocolOneToken/FreshProtocolTwoToken (disposed in the catch block on failure); the analyzer cannot see this transfer through the record construction.")]
    private static ValueTask<CtapAuthenticatorInput> ResetPinUvAuthTokensAsync(
        CtapResetPinUvAuthTokensAction action, CtapActionContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        CtapPinUvAuthTokenState freshProtocolOneToken = CtapPinUvAuthTokenState.Initial(context.Pool);
        CtapPinUvAuthTokenState freshProtocolTwoToken;
        try
        {
            freshProtocolTwoToken = CtapPinUvAuthTokenState.Initial(context.Pool);
        }
        catch
        {
            freshProtocolOneToken.Dispose();
            throw;
        }

        return ValueTask.FromResult<CtapAuthenticatorInput>(new PinUvAuthTokensReset(freshProtocolOneToken, freshProtocolTwoToken));
    }


    /// <summary>
    /// <c>authenticatorReset</c>'s effect: mints a fresh key-agreement key pair and a fresh
    /// <c>pinUvAuthToken</c> for each PIN/UV auth protocol — the SAME underlying
    /// <see cref="CryptographicKeyEvents.CreateKeyPair"/>/<see cref="CtapPinUvAuthTokenState.Initial"/>
    /// calls <see cref="CtapAuthenticatorState.Initial"/>/<see cref="CtapAuthenticatorState.PowerCycle"/>
    /// make — the only entropy-consuming piece of a factory reset, hence the only piece routed through
    /// the effectful loop.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Every minted key pair/token transfers ownership into the returned AuthenticatorResetKeyMaterialMinted input (disposed in the catch blocks below on a later mint's failure); the analyzer cannot see the ownership transfer through the record construction.")]
    private static ValueTask<CtapAuthenticatorInput> FactoryResetKeyMaterialAsync(
        CtapFactoryResetKeyMaterialAction action, CtapActionContext context, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        CtapPinUvAuthKeyAgreementKeyPair freshProtocolOneKeyPair = MintSingleKeyAgreementKeyPair(context.Pool);
        CtapPinUvAuthKeyAgreementKeyPair freshProtocolTwoKeyPair;
        try
        {
            freshProtocolTwoKeyPair = MintSingleKeyAgreementKeyPair(context.Pool);
        }
        catch
        {
            freshProtocolOneKeyPair.Dispose();
            throw;
        }

        CtapPinUvAuthTokenState freshProtocolOneToken;
        try
        {
            freshProtocolOneToken = CtapPinUvAuthTokenState.Initial(context.Pool);
        }
        catch
        {
            freshProtocolOneKeyPair.Dispose();
            freshProtocolTwoKeyPair.Dispose();
            throw;
        }

        CtapPinUvAuthTokenState freshProtocolTwoToken;
        try
        {
            freshProtocolTwoToken = CtapPinUvAuthTokenState.Initial(context.Pool);
        }
        catch
        {
            freshProtocolOneKeyPair.Dispose();
            freshProtocolTwoKeyPair.Dispose();
            freshProtocolOneToken.Dispose();
            throw;
        }

        return ValueTask.FromResult<CtapAuthenticatorInput>(
            new AuthenticatorResetKeyMaterialMinted(freshProtocolOneKeyPair, freshProtocolTwoKeyPair, freshProtocolOneToken, freshProtocolTwoToken));
    }


    /// <summary>
    /// Copies <paramref name="source"/>'s bytes into a freshly rented, independently owned
    /// <see cref="DigestValue"/> — used to persist a client data hash beyond the lifetime of the
    /// decoded <c>authenticatorGetAssertion</c> request that carried it, which the transport layer
    /// disposes once that single command completes.
    /// </summary>
    private static DigestValue CopyClientDataHash(DigestValue source, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(source.Length);
        try
        {
            source.AsReadOnlySpan().CopyTo(owner.Memory.Span);

            return new DigestValue(owner, CryptoTags.Sha256Digest);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Computes <c>rpIdHash</c>: the SHA-256 digest of the relying party identifier's UTF-8 bytes
    /// (WebAuthn L3, section 6.1: Authenticator Data), through the synchronous digest seam — like
    /// <c>clientDataHash</c>, this is a public-data digest sent openly on the wire, not a trust/custody
    /// hash.
    /// </summary>
    private static DigestValue ComputeRpIdHash(string rpId, MemoryPool<byte> pool)
    {
        int maxByteCount = Encoding.UTF8.GetMaxByteCount(rpId.Length);
        using IMemoryOwner<byte> rpIdBytes = pool.Rent(maxByteCount);
        int byteCount = Encoding.UTF8.GetBytes(rpId, rpIdBytes.Memory.Span);

        return CryptographicKeyEvents.ComputeDigest(rpIdBytes.Memory.Span[..byteCount], Sha256Length, CryptoTags.Sha256Digest, pool);
    }


    /// <summary>
    /// Builds the <c>authData</c> flags byte this simulator ever produces: <c>BE</c> and <c>BS</c> are
    /// always zero (single-device credentials — no backup-eligible/backed-up credential ever exists in
    /// this profile, independent of the built-in-UV cluster), leaving <c>UP</c>,
    /// <c>UV</c>, <c>AT</c>, and <c>ED</c> as per-command inputs. <c>ED</c> is caller-resolved rather
    /// than derived here, since only the caller knows whether its own extensions-output encode actually
    /// produced a non-empty map (<see cref="AuthenticatorDataWriter.Write"/>'s own fail-closed check
    /// enforces the two agree); <see cref="SignAssertionAsync"/> passes <see langword="false"/>
    /// unconditionally, since neither chartered extension defines an <c>authenticatorGetAssertion</c>
    /// output (both are registration-only).
    /// </summary>
    private static AuthenticatorDataFlags BuildFlags(bool userPresent, bool userVerified, bool attestedCredentialDataIncluded, bool extensionDataIncluded)
    {
        byte value = 0;
        if(userPresent)
        {
            value |= AuthenticatorDataFlags.UserPresentBit;
        }

        if(userVerified)
        {
            value |= AuthenticatorDataFlags.UserVerifiedBit;
        }

        if(attestedCredentialDataIncluded)
        {
            value |= AuthenticatorDataFlags.AttestedCredentialDataIncludedBit;
        }

        if(extensionDataIncluded)
        {
            value |= AuthenticatorDataFlags.ExtensionDataIncludedBit;
        }

        return new AuthenticatorDataFlags(value);
    }


    /// <summary>
    /// Selects the first element of <paramref name="pubKeyCredParams"/> whose algorithm the backend
    /// supports (CTAP 2.3, section 6.1.2, step 3: "the first occurrence of an algorithm identifier
    /// supported by this authenticator", iterating every element regardless of where a match is found).
    /// </summary>
    /// <returns>The chosen COSE algorithm identifier, or <see langword="null"/> if none is supported.</returns>
    private static int? SelectSupportedAlgorithm(IReadOnlyList<PublicKeyCredentialParameters> pubKeyCredParams, IReadOnlyList<int>? supportedAlgorithms)
    {
        if(supportedAlgorithms is null || supportedAlgorithms.Count == 0)
        {
            return null;
        }

        foreach(PublicKeyCredentialParameters parameter in pubKeyCredParams)
        {
            if(supportedAlgorithms.Contains(parameter.Alg))
            {
                return parameter.Alg;
            }
        }

        return null;
    }


    /// <summary>
    /// Draws a 16-byte AAGUID from the entropy provider, encoded the same way
    /// <see cref="AuthenticatorDataReader"/> reads an AAGUID (big-endian).
    /// </summary>
    /// <param name="rng">The entropy provider to draw from.</param>
    /// <returns>The drawn AAGUID.</returns>
    private static Guid DrawAaguid(FillEntropyDelegate rng)
    {
        Span<byte> aaguidBytes = stackalloc byte[AaguidLength];
        rng(aaguidBytes);

        return new Guid(aaguidBytes, bigEndian: true);
    }


    /// <inheritdoc />
    /// <remarks>
    /// Idempotent: a second call is a no-op. Walks the credential store and disposes every credential's
    /// owned <see cref="CredentialId"/>, <see cref="UserHandle"/>, and <see cref="PrivateKey"/> — the
    /// credential-ID-keyed store is the complete set (every resident credential also appears there), so
    /// no credential is disposed twice — walks the fingerprint template store and disposes every
    /// provisioned template's own <see cref="BioEnrollmentTemplateId"/>, disposes an in-progress
    /// remembered <c>authenticatorGetAssertion</c> sequence's independently pooled client data hash copy
    /// and an in-progress remembered <c>authenticatorBioEnrollment</c> capture's own not-yet-persisted
    /// template identifier, if either exists, disposes both PIN/UV auth protocols' key-agreement key
    /// pairs and <c>pinUvAuthToken</c>s, disposes the stored PIN hash, if a PIN has been set, and
    /// disposes the persistent <see cref="CtapAuthenticatorState.SerializedLargeBlobArray"/> buffer
    /// (always present — seeded by <see cref="CtapAuthenticatorState.Initial"/>, never
    /// <see langword="null"/>), disposes the vendor-burned-in
    /// <see cref="CtapAuthenticatorState.EnterpriseAttestationProvisioning"/> record, if this simulator
    /// was constructed enterprise-attestation-capable, and disposes a parked
    /// <see cref="CtapAuthenticatorState.PendingUserPresenceWait"/>'s own request carriers, if a wait was
    /// left pending (R2).
    /// </remarks>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        disposed = true;

        foreach(CtapCredentialRecord record in Automaton.CurrentState.CredentialsByCredentialId.Values)
        {
            record.Dispose();
        }

        foreach(CtapBioEnrollmentTemplateRecord template in Automaton.CurrentState.BioEnrollmentTemplatesByTemplateId.Values)
        {
            template.Dispose();
        }

        Automaton.CurrentState.RememberedGetAssertion?.Dispose();
        Automaton.CurrentState.RememberedBioEnrollment?.Dispose();
        Automaton.CurrentState.PendingUserPresenceWait?.Dispose();
        Automaton.CurrentState.ProtocolOneKeyAgreementKeyPair.Dispose();
        Automaton.CurrentState.ProtocolTwoKeyAgreementKeyPair.Dispose();
        Automaton.CurrentState.ProtocolOneToken.Dispose();
        Automaton.CurrentState.ProtocolTwoToken.Dispose();
        Automaton.CurrentState.CurrentStoredPin?.Dispose();
        Automaton.CurrentState.SerializedLargeBlobArray.Dispose();
        Automaton.CurrentState.EnterpriseAttestationProvisioning?.Dispose();
    }


    /// <summary>
    /// Per-call context threaded to <see cref="ExecuteAction"/> without closure capture: the entropy
    /// provider, the memory pool, the authenticator's own AAGUID, the optional credential-signing
    /// backend, and the COSE_Key encode seam — mirrors <c>Verifiable.Tpm.Automata.TpmSimulator</c>'s
    /// own <c>TpmActionContext</c> shape.
    /// </summary>
    /// <param name="rng">The entropy provider credential identifiers are drawn from.</param>
    /// <param name="pool">The memory pool backing every effect's allocations.</param>
    /// <param name="aaguid">The authenticator's own AAGUID, embedded in every minted credential's <c>attestedCredentialData</c>.</param>
    /// <param name="credentialSigningBackend">The credential-minting backend, or <see langword="null"/> if none was injected.</param>
    /// <param name="encodeCredentialPublicKey">The codec seam that CBOR-encodes a minted credential's public key.</param>
    /// <param name="encodePackedSelfAttestationStatement">The codec seam that CBOR-encodes a self-attestation packed <c>attStmt</c>.</param>
    /// <param name="encodePackedCertifiedAttestationStatement">The codec seam that CBOR-encodes a certified (enterprise) packed <c>attStmt</c>, or <see langword="null"/> if none was injected.</param>
    /// <param name="enterpriseAttestationProvisioning">The vendor-burned-in enterprise attestation material, or <see langword="null"/> if this authenticator was never provisioned with any.</param>
    /// <param name="encodeMakeCredentialExtensionOutputs">The codec seam that CBOR-encodes the resolved <c>credProtect</c>/<c>hmac-secret</c>/<c>minPinLength</c>/<c>hmac-secret-mc</c> authData extensions output map.</param>
    /// <param name="encodeGetAssertionExtensionOutputs">The codec seam that CBOR-encodes the resolved <c>hmac-secret</c> <c>authenticatorGetAssertion</c> authData extensions output map.</param>
    /// <param name="simulateFingerprintCapture">The R8 outcome-injection knob for a simulated fingerprint sensor capture.</param>
    /// <param name="simulateBuiltInUv">The R8 outcome-injection knob for a simulated built-in user verification gesture.</param>
    /// <param name="simulateUserPresence">The R1 outcome-injection knob for a simulated :2840 user-presence collection.</param>
    /// <param name="timeProvider">The time source the <see cref="CtapCollectUserPresenceAction"/> executor stamps a collected decision's <c>Now</c> with.</param>
    private readonly struct CtapActionContext(
        FillEntropyDelegate rng,
        MemoryPool<byte> pool,
        Guid aaguid,
        CtapCredentialSigningBackend? credentialSigningBackend,
        EncodeCredentialPublicKeyDelegate encodeCredentialPublicKey,
        EncodePackedSelfAttestationStatementDelegate encodePackedSelfAttestationStatement,
        EncodePackedCertifiedAttestationStatementDelegate? encodePackedCertifiedAttestationStatement,
        CtapEnterpriseAttestationProvisioning? enterpriseAttestationProvisioning,
        EncodeCtapMakeCredentialExtensionOutputsDelegate encodeMakeCredentialExtensionOutputs,
        EncodeCtapGetAssertionExtensionOutputsDelegate encodeGetAssertionExtensionOutputs,
        SimulateFingerprintCaptureDelegate simulateFingerprintCapture,
        SimulateBuiltInUvDelegate simulateBuiltInUv,
        SimulateUserPresenceDelegate simulateUserPresence,
        TimeProvider timeProvider)
    {
        /// <summary>The entropy provider credential identifiers are drawn from.</summary>
        public FillEntropyDelegate Rng { get; } = rng;

        /// <summary>The memory pool backing every effect's allocations.</summary>
        public MemoryPool<byte> Pool { get; } = pool;

        /// <summary>The authenticator's own AAGUID, embedded in every minted credential's <c>attestedCredentialData</c>.</summary>
        public Guid Aaguid { get; } = aaguid;

        /// <summary>The credential-minting backend, or <see langword="null"/> if none was injected.</summary>
        public CtapCredentialSigningBackend? CredentialSigningBackend { get; } = credentialSigningBackend;

        /// <summary>The codec seam that CBOR-encodes a minted credential's public key.</summary>
        public EncodeCredentialPublicKeyDelegate EncodeCredentialPublicKey { get; } = encodeCredentialPublicKey;

        /// <summary>The codec seam that CBOR-encodes a self-attestation packed <c>attStmt</c>.</summary>
        public EncodePackedSelfAttestationStatementDelegate EncodePackedSelfAttestationStatement { get; } = encodePackedSelfAttestationStatement;

        /// <summary>The codec seam that CBOR-encodes a certified (enterprise) packed <c>attStmt</c>, or <see langword="null"/> if none was injected.</summary>
        public EncodePackedCertifiedAttestationStatementDelegate? EncodePackedCertifiedAttestationStatement { get; } = encodePackedCertifiedAttestationStatement;

        /// <summary>The vendor-burned-in enterprise attestation material, or <see langword="null"/> if this authenticator was never provisioned with any.</summary>
        public CtapEnterpriseAttestationProvisioning? EnterpriseAttestationProvisioning { get; } = enterpriseAttestationProvisioning;

        /// <summary>The codec seam that CBOR-encodes the resolved <c>credProtect</c>/<c>hmac-secret</c>/<c>minPinLength</c>/<c>hmac-secret-mc</c> authData extensions output map.</summary>
        public EncodeCtapMakeCredentialExtensionOutputsDelegate EncodeMakeCredentialExtensionOutputs { get; } = encodeMakeCredentialExtensionOutputs;

        /// <summary>The codec seam that CBOR-encodes the resolved <c>hmac-secret</c> <c>authenticatorGetAssertion</c> authData extensions output map.</summary>
        public EncodeCtapGetAssertionExtensionOutputsDelegate EncodeGetAssertionExtensionOutputs { get; } = encodeGetAssertionExtensionOutputs;

        /// <summary>The R8 outcome-injection knob for a simulated fingerprint sensor capture.</summary>
        public SimulateFingerprintCaptureDelegate SimulateFingerprintCapture { get; } = simulateFingerprintCapture;

        /// <summary>The R8 outcome-injection knob for a simulated built-in user verification gesture.</summary>
        public SimulateBuiltInUvDelegate SimulateBuiltInUv { get; } = simulateBuiltInUv;

        /// <summary>The R1 outcome-injection knob for a simulated :2840 user-presence collection.</summary>
        public SimulateUserPresenceDelegate SimulateUserPresence { get; } = simulateUserPresence;

        /// <summary>The time source the <see cref="CtapCollectUserPresenceAction"/> executor stamps a collected decision's <c>Now</c> with.</summary>
        public TimeProvider TimeProvider { get; } = timeProvider;
    }


    /// <summary>
    /// A debugger-friendly summary of the authenticator's AAGUID, current automaton step count, and disposed state.
    /// </summary>
    private string DebuggerDisplay => $"CtapAuthenticatorSimulator(Aaguid={Aaguid}, Step={Automaton.StepCount}, Disposed={disposed})";
}
