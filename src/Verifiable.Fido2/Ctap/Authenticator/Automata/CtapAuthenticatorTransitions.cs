using System;
using System.Buffers;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Text;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Fido2.Ctap;
using Verifiable.Foundation.Automata;
using Verifiable.JCose;

namespace Verifiable.Fido2.Ctap.Authenticator.Automata;

/// <summary>
/// Builds the pure transition function of the CTAP2 authenticator simulator's pushdown automaton.
/// </summary>
/// <remarks>
/// Mirrors <c>Verifiable.Tpm.Automata.TpmLifecycleTransitions</c>'s shape: a <see langword="static"/>
/// lambda matching <see cref="TransitionDelegate{TState, TInput, TStackSymbol}"/>, switch-expression
/// dispatching on the input's runtime type, with one private static method per non-trivial dispatch arm.
/// The function performs no I/O, reads no time, and draws no randomness — <c>authenticatorMakeCredential</c>,
/// <c>authenticatorGetAssertion</c>, and <c>authenticatorGetNextAssertion</c>'s effectful work (key
/// generation, signing, entropy) is declared as a <see cref="CtapAction"/> and executed by
/// <see cref="CtapAuthenticatorSimulator"/>'s effectful loop, which feeds the result back as a
/// <see cref="CredentialMinted"/>/<see cref="AssertionSigned"/> input; this function only ever
/// repackages already-computed values into the next state and response intent. The one exception to
/// "reads no time" is comparison, not reading: <see cref="GetAssertionRequested.Now"/> and
/// <see cref="GetNextAssertionRequested.Now"/> are <see cref="DateTimeOffset"/> facts the simulator
/// precomputes from its own threaded <c>TimeProvider</c> before dispatch, mirroring the same
/// "precompute outside, compare inside" shape <c>MakeCredentialRequested.SelectedAlgorithm</c> already
/// uses for the pubKeyCredParams selection the transition cannot itself perform.
/// </remarks>
public static class CtapAuthenticatorTransitions
{
    /// <summary>
    /// The <c>authenticatorGetNextAssertion</c> statefulness timer (CTAP 2.3, section 6.3): "If timer
    /// since the last call to authenticatorGetAssertion/authenticatorGetNextAssertion is greater than 30
    /// seconds, discard the current authenticatorGetAssertion state and return CTAP2_ERR_NOT_ALLOWED."
    /// </summary>
    /// <remarks>
    /// Section 6.3 also carves out an exemption "if transport is done over NFC" for arming, checking, and
    /// resetting this timer — deliberately NOT relied on here: this simulator is transport-agnostic
    /// behind <see cref="Ctap2TransceiveDelegate"/> and has no way to know, from inside a command
    /// handler, which transport carried the request. Applying the 30-second bound unconditionally is the
    /// strictest honest reading available to a transport-agnostic authenticator.
    /// </remarks>
    private static TimeSpan GetNextAssertionTimerDuration => TimeSpan.FromSeconds(30);


    /// <summary>
    /// The <c>enumerateRPsGetNextRP</c>/<c>enumerateCredentialsGetNextCredential</c> statefulness timer
    /// (CTAP 2.3, section 6, item 2, line 2871): the same 30-second value as
    /// <see cref="GetNextAssertionTimerDuration"/>, exercised here as the general, discretionary MAY the
    /// stateful-commands preamble grants every stateful command family (unlike
    /// <c>authenticatorGetNextAssertion</c>'s own section 6.3, which elevates it to a MUST) — a
    /// dedicated getter, not a shared call site, so <see cref="GetNextAssertionTimerDuration"/>'s own
    /// callers stay untouched.
    /// </summary>
    private static TimeSpan CredentialManagementEnumerationTimerDuration => TimeSpan.FromSeconds(30);


    /// <summary>
    /// <c>authenticatorReset</c>'s power-up window (CTAP 2.3 §6.6, lines 6365-6366): "In case of
    /// authenticators with no display, request MUST have come to the authenticator within 10 seconds of
    /// powering up of the authenticator." A dedicated getter, not a shared call site, mirroring
    /// <see cref="GetNextAssertionTimerDuration"/>'s/<see cref="CredentialManagementEnumerationTimerDuration"/>'s
    /// own placement convention. Elapsed exactly equal to this value still SUCCEEDS (line 6365's "within
    /// 10 seconds"); only strictly greater fails (line 6374's "after 10 seconds").
    /// </summary>
    private static TimeSpan ResetPowerUpWindowDuration => TimeSpan.FromSeconds(10);


    /// <summary>
    /// The <c>credProtect</c> wire value for <c>userVerificationOptional</c> (CTAP 2.3 §12.1, line
    /// 12609's value table): the default level every credential carries when the mc request never
    /// mentions <c>credProtect</c> (line 12648's SHOULD). Never filters mc's excludeList or ga's
    /// credential-location steps.
    /// </summary>
    private static int CredProtectUserVerificationOptional => 1;


    /// <summary>
    /// The <c>credProtect</c> wire value for <c>userVerificationOptionalWithCredentialIDList</c> (CTAP
    /// 2.3 §12.1, line 12609's value table): filtered from ga's discoverable-scan (no-<c>allowList</c>)
    /// path when <c>uv</c> is <see langword="false"/>, but NOT from the <c>allowList</c> path (R10) —
    /// knowledge of the specific credential ID exempts it.
    /// </summary>
    private static int CredProtectUserVerificationOptionalWithCredentialIdList => 2;


    /// <summary>
    /// The <c>credProtect</c> wire value for <c>userVerificationRequired</c> (CTAP 2.3 §12.1, line
    /// 12609's value table): excluded from every ga credential-location branch (allowList or
    /// discoverable-scan alike) when <c>uv</c> is <see langword="false"/> (R10), and exempted — not
    /// excluded — from mc's excludeList match when <c>uv</c> was not collected in the same call (R9's
    /// inversion).
    /// </summary>
    private static int CredProtectUserVerificationRequired => 3;


    /// <summary>
    /// Builds the transition function.
    /// </summary>
    /// <returns>A transition function suitable for constructing one authenticator simulator's automaton.</returns>
    public static TransitionDelegate<CtapAuthenticatorState, CtapAuthenticatorInput, CtapAuthenticatorStackSymbol> Create() =>
        static (state, input, stackTop, cancellationToken) =>
        {
            cancellationToken.ThrowIfCancellationRequested();

            TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> result = input switch
            {
                GetInfoRequested => Respond(
                    DiscardAllRememberedSequences(state),
                    new GetInfoResponseReady(BuildGetInfoResponse(
                        state.Aaguid,
                        state.SupportedExtensions,
                        isClientPinSet: state.CurrentStoredPin is not null,
                        isAlwaysUvEnabled: state.IsAlwaysUvEnabled,
                        minPinCodePointLength: state.MinPinCodePointLength,
                        isForcePinChangeRequired: state.IsForcePinChangeRequired,
                        remainingDiscoverableCredentials: state.ResidentCredentialCapacity - CountResidentCredentials(state.CredentialsByCredentialId),
                        hasProvisionedBioEnrollments: state.HasProvisionedBioEnrollments,
                        isEnterpriseAttestationCapable: state.IsEnterpriseAttestationCapable,
                        isEnterpriseAttestationEnabled: state.IsEnterpriseAttestationEnabled)),
                    "GetInfo"),
                MakeCredentialRequested requested => OnMakeCredentialRequested(state, requested),
                GetAssertionRequested requested => OnGetAssertionRequested(state, requested),
                GetNextAssertionRequested requested => OnGetNextAssertionRequested(state, requested),
                AuthenticatorConfigRequested requested => OnAuthenticatorConfigRequested(state, requested),
                ResetRequested requested => OnAuthenticatorResetRequested(state, requested),
                AuthenticatorResetKeyMaterialMinted minted => OnAuthenticatorResetKeyMaterialMinted(state, minted),
                PinUvAuthTokenVerified verified => OnPinUvAuthTokenVerified(state, verified),
                PinUvAuthTokensReset reset => OnPinUvAuthTokensReset(state, reset),
                ClientPinRequested requested => OnClientPinRequested(state, requested),
                ClientPinKeyAgreementComputed computed => OnClientPinKeyAgreementComputed(state, computed),
                PinEstablishmentCompleted completed => OnPinEstablishmentCompleted(state, completed),
                PinChangeCompleted completed => OnPinChangeCompleted(state, completed),
                PinTokenIssuanceCompleted completed => OnPinTokenIssuanceCompleted(state, completed),
                BuiltInUvAttempted attempted => OnBuiltInUvAttempted(state, attempted),
                UvTokenIssuanceCompleted completed => OnUvTokenIssuanceCompleted(state, completed),
                CredentialMinted minted => OnCredentialMinted(state, minted),
                AssertionSigned signed => OnAssertionSigned(state, signed),
                GetAssertionHmacSecretFailed failed => OnGetAssertionHmacSecretFailed(state, failed),
                MakeCredentialHmacSecretMcFailed failed => OnMakeCredentialHmacSecretMcFailed(state, failed),
                CredentialManagementRequested requested => OnCredentialManagementRequested(state, requested),
                CredentialManagementResponseComputed computed => OnCredentialManagementResponseComputed(state, computed),
                CredentialManagementCredentialsLocated located => OnCredentialManagementCredentialsLocated(state, located),
                BioEnrollmentRequested requested => OnBioEnrollmentRequested(state, requested),
                BioEnrollmentCaptureStarted started => OnBioEnrollmentCaptureStarted(state, started),
                BioEnrollmentSampleCaptured captured => OnBioEnrollmentSampleCaptured(state, captured),
                LargeBlobsRequested requested => OnLargeBlobsRequested(state, requested),
                CtapLargeBlobArrayCommitAttempted attempted => OnLargeBlobArrayCommitAttempted(state, attempted),
                UnsupportedCtapCommandReceived unsupported => Respond(DiscardAllRememberedSequences(state), new UnsupportedCommandResponse(unsupported.CommandByte), "UnsupportedCommand"),
                _ => throw new NotSupportedException($"No transition is defined for input '{input.GetType().Name}'.")
            };

            return ValueTask.FromResult<TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol>?>(result);
        };


    /// <summary>
    /// Frames the new state around a produced response intent — every dispatch arm that completes a
    /// command (successfully or with a rejection) shares this one place that clears
    /// <see cref="CtapAuthenticatorState.NextAction"/> and leaves the stack untouched (this automaton
    /// never pushes or pops: every command completes within one bottom-of-stack session).
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> Respond(
        CtapAuthenticatorState state, CtapAuthenticatorResponseIntent intent, string label)
    {
        CtapAuthenticatorState nextState = state with { NextAction = NullAction.Instance, ResponseIntent = intent };

        return new TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol>(
            nextState, StackAction<CtapAuthenticatorStackSymbol>.None, label);
    }


    /// <summary>
    /// Rejects the current command with a bare CTAP2 status code, no CBOR body.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> Reject(
        CtapAuthenticatorState state, byte statusCode, string label) =>
        Respond(state, new CtapErrorResponse(statusCode), label);


    /// <summary>
    /// Discards any remembered <c>authenticatorGetAssertion</c> sequence, disposing its independently
    /// pooled client data hash copy. Called at the start of every command other than
    /// <c>authenticatorGetNextAssertion</c> itself: CTAP 2.3's stateful-commands rules permit an
    /// authenticator to fail a stateful command when "no other authenticator operation occurs in between"
    /// is violated (section 2.3, "Implementation Considerations for Stateful Commands"); this simulator
    /// adopts that permission as its own strictest, most honest reading — <c>authenticatorGetInfo</c>,
    /// <c>authenticatorMakeCredential</c>, and any unrecognized command byte CLEAR a remembered sequence
    /// outright (even when the intervening command itself goes on to fail its own validation), and a
    /// fresh <c>authenticatorGetAssertion</c> REPLACES it with whatever that new request produces.
    /// </summary>
    private static CtapAuthenticatorState DiscardRememberedGetAssertion(CtapAuthenticatorState state)
    {
        if(state.RememberedGetAssertion is null)
        {
            return state;
        }

        state.RememberedGetAssertion.Dispose();

        return state with { RememberedGetAssertion = null };
    }


    /// <summary>
    /// Discards a remembered <c>enumerateRPsBegin</c> sequence, if any. Unlike
    /// <see cref="DiscardRememberedGetAssertion"/>, no disposal is needed: neither this record nor its
    /// own RP-identifier list owns pooled memory.
    /// </summary>
    private static CtapAuthenticatorState DiscardRememberedEnumerateRps(CtapAuthenticatorState state) =>
        state.RememberedEnumerateRps is null ? state : state with { RememberedEnumerateRps = null };


    /// <summary>
    /// Discards a remembered <c>enumerateCredentialsBegin</c> sequence, if any — see
    /// <see cref="DiscardRememberedEnumerateRps"/>'s own no-disposal-needed remark; this record's
    /// credential identifiers are borrowed from the store, not owned.
    /// </summary>
    private static CtapAuthenticatorState DiscardRememberedEnumerateCredentials(CtapAuthenticatorState state) =>
        state.RememberedEnumerateCredentials is null ? state : state with { RememberedEnumerateCredentials = null };


    /// <summary>
    /// Discards a remembered <c>authenticatorLargeBlobs</c> <c>set</c> sequence, if any, disposing its
    /// not-yet-committed pending buffer (R7, seams Q4: the GLOBAL discipline, unlike
    /// <see cref="DiscardRememberedBioEnrollment"/>'s own narrower one).
    /// </summary>
    private static CtapAuthenticatorState DiscardRememberedLargeBlobWrite(CtapAuthenticatorState state)
    {
        if(state.RememberedLargeBlobWrite is null)
        {
            return state;
        }

        state.RememberedLargeBlobWrite.Dispose();

        return state with { RememberedLargeBlobWrite = null };
    }


    /// <summary>
    /// Discards all FOUR remembered stateful-command sequences (<see cref="DiscardRememberedGetAssertion"/>,
    /// <see cref="DiscardRememberedEnumerateRps"/>, <see cref="DiscardRememberedEnumerateCredentials"/>,
    /// <see cref="DiscardRememberedLargeBlobWrite"/>) — R10's global discard rule (CTAP 2.3, section 6,
    /// item 2, line 2871: "An authenticator MAY assume this globally"): every command arm OTHER than a
    /// stateful command's own continuation treats any other authenticator operation as invalidating every
    /// remembered sequence. Called at the entry of every command arm except <c>authenticatorGetNextAssertion</c>,
    /// <c>enumerateRPsGetNextRP</c>, <c>enumerateCredentialsGetNextCredential</c>, and a genuine
    /// <c>authenticatorLargeBlobs</c> <c>set</c> continuation fragment, each of which discards only the
    /// OTHER slots to preserve its own (<see cref="OnLargeBlobsRequested"/> uses
    /// <see cref="DiscardRememberedSequencesExceptLargeBlobWrite"/> for that narrower case).
    /// </summary>
    private static CtapAuthenticatorState DiscardAllRememberedSequences(CtapAuthenticatorState state) =>
        DiscardRememberedLargeBlobWrite(DiscardRememberedEnumerateCredentials(DiscardRememberedEnumerateRps(DiscardRememberedGetAssertion(state))));


    /// <summary>
    /// Discards the three OTHER remembered stateful-command sequences (<see cref="DiscardRememberedGetAssertion"/>,
    /// <see cref="DiscardRememberedEnumerateRps"/>, <see cref="DiscardRememberedEnumerateCredentials"/>)
    /// while preserving <see cref="CtapAuthenticatorState.RememberedLargeBlobWrite"/> — the narrow
    /// counterpart <see cref="DiscardAllRememberedSequences"/>'s own broad discard, used by
    /// <see cref="OnLargeBlobsRequested"/> exactly when the current request is a genuine continuation
    /// candidate (a <c>set</c> with a non-zero <c>offset</c>), mirroring <c>authenticatorGetNextAssertion</c>'s/
    /// <c>enumerateRPsGetNextRP</c>'s own "preserve just my own slot" shape. Every OTHER shape reaching
    /// <see cref="OnLargeBlobsRequested"/> — a <c>get</c>, or a <c>set</c> with <c>offset == 0</c> (which
    /// starts a brand-new sequence per line 7657 regardless) — goes through the full
    /// <see cref="DiscardAllRememberedSequences"/> instead, the same GLOBAL-discipline posture every other
    /// command's own entry takes (R7).
    /// </summary>
    private static CtapAuthenticatorState DiscardRememberedSequencesExceptLargeBlobWrite(CtapAuthenticatorState state) =>
        DiscardRememberedEnumerateCredentials(DiscardRememberedEnumerateRps(DiscardRememberedGetAssertion(state)));


    /// <summary>
    /// Discards an in-progress <c>authenticatorBioEnrollment</c> enrollment, if any, disposing its
    /// not-yet-persisted template identifier. UNLIKE <see cref="DiscardAllRememberedSequences"/>'s own
    /// three slots, this is NOT called at the entry of every other command — CTAP 2.3 §6.7 names no
    /// broader intervening-operation rule for this sequence (R7); only <c>cancelCurrentEnrollment</c>, a
    /// fresh <c>enrollBegin</c>'s own auto-cancel step, <see cref="CtapAuthenticatorState.PowerCycle"/>,
    /// and <see cref="CtapAuthenticatorState.FactoryReset"/> discard it.
    /// </summary>
    private static CtapAuthenticatorState DiscardRememberedBioEnrollment(CtapAuthenticatorState state)
    {
        if(state.RememberedBioEnrollment is null)
        {
            return state;
        }

        state.RememberedBioEnrollment.Dispose();

        return state with { RememberedBioEnrollment = null };
    }


    /// <summary>
    /// The <c>authenticatorConfig</c> subcommand values this authenticator implements, in ascending
    /// order, reported as the <c>authenticatorConfigCommands</c> getInfo member (line 4618) —
    /// STATE-DERIVED (R2), never a fixed literal: <c>[0x01, 0x02, 0x03]</c>
    /// (<c>enableEnterpriseAttestation</c>, <c>toggleAlwaysUv</c>, <c>setMinPINLength</c>) when
    /// <paramref name="isEnterpriseAttestationCapable"/>, else <c>[0x02, 0x03]</c>
    /// (<c>enableLongTouchForReset</c>/<c>vendorPrototype</c> stay unsupported and reject via the
    /// command's own step 2 regardless of capability). This is the SAME single predicate
    /// (<see cref="CtapAuthenticatorState.IsEnterpriseAttestationCapable"/>) row 7995 ("the getInfo
    /// member authenticatorConfigCommands MUST contain an array member with the value 0x01 if this
    /// subcommand is supported") shares with the <c>ep</c> option's own emission (R2's tri-site MUST).
    /// </summary>
    /// <param name="isEnterpriseAttestationCapable">
    /// Whether the authenticator is enterprise attestation capable
    /// (<see cref="CtapAuthenticatorState.IsEnterpriseAttestationCapable"/>).
    /// </param>
    private static IReadOnlyList<int> SupportedAuthenticatorConfigCommands(bool isEnterpriseAttestationCapable) =>
        isEnterpriseAttestationCapable ? [0x01, 0x02, 0x03] : [0x02, 0x03];


    /// <summary>
    /// Builds the authenticatorGetInfo response: the two Required members (versions, aaguid) per CTAP 2.3
    /// section 6.4, the authenticator model's advertised extensions if any were configured at
    /// construction, the options member's <c>rk:true</c> (this simulator can create discoverable
    /// credentials; <c>plat</c> stays absent per the cross-platform model), <c>alwaysUv</c> set to
    /// <paramref name="isAlwaysUvEnabled"/> (present ALWAYS — CTAP 2.3, lines 4944-4946: supported but
    /// disabled reports present-false, never absent), <c>credMgmt:true</c> unconditionally (§9 item 3,
    /// support is a static capability of this build — the <c>authnrCfg</c> precedent), <c>authnrCfg:true</c>
    /// unconditionally, <c>clientPin</c> set to <paramref name="isClientPinSet"/>
    /// (CTAP 2.3 §9 item 2: this MUST be an explicit boolean once FIDO_2_3 is claimed —
    /// <see langword="true"/> once a PIN has been set via <c>setPIN</c>, <see langword="false"/>
    /// otherwise), <c>pinUvAuthToken:true</c> (§9 item 5, mandatory once <c>clientPin</c> or <c>uv</c>
    /// is present at all), <c>setMinPINLength:true</c> unconditionally (its own line-4909 gate, "only
    /// present if the clientPin option ID is present", is always satisfied once <c>Initial()</c> has
    /// run), and <c>makeCredUvNotRqd</c> DERIVED as <c>!isAlwaysUvEnabled</c> (line 4951's MUST: present
    /// and true forces <c>makeCredUvNotRqd</c> false; this also closes the option's own separate
    /// "Authenticators SHOULD include this option with the value true" for the <c>alwaysUv</c>-disabled
    /// state, keeping non-discoverable <c>authenticatorMakeCredential</c> usable without a token once a
    /// PIN is set). <c>pinUvAuthProtocols:[2,1]</c> (§9 item 6: protocol 2 MUST be included and is this
    /// authenticator's preferred protocol, listed first). <c>forcePINChange</c> set to
    /// <paramref name="isForcePinChangeRequired"/>; <c>minPINLength</c> set to
    /// <paramref name="minPinCodePointLength"/> (the current minimum, line 4459);
    /// <c>remainingDiscoverableCredentials</c> set to <paramref name="remainingDiscoverableCredentials"/>
    /// (member 0x14, ALWAYS present alongside <c>credMgmt</c> — the same live capacity-minus-count value
    /// <c>getCredsMetadata</c>'s own <c>maxPossibleRemainingResidentCredentialsCount</c> reports, R9's
    /// single-source-of-truth choice); <c>authenticatorConfigCommands</c> =
    /// <see cref="SupportedAuthenticatorConfigCommands(bool)"/>; <c>maxRPIDsForSetMinPINLength</c> =
    /// <see cref="CtapAuthenticatorState.MaxRpIdsForSetMinPinLengthCapacity"/> (the same fixed constant
    /// <c>setMinPINLength</c>'s own bound check consumes — single-sourced, never two literals).
    /// <c>uv</c> and <c>bioEnroll</c> are BOTH ALWAYS PRESENT, DERIVED from the SAME
    /// <paramref name="hasProvisionedBioEnrollments"/> source (wavebio R2): <see langword="false"/> with
    /// zero enrollments, <see langword="true"/> with at least one — closing §9 row 9076's second MUST
    /// ("clientPin and uv MUST have either the values true or false, depending on if a pin has been set
    /// or a biometric template enrolled"). <c>uvBioEnroll:true</c> unconditionally (a static build
    /// capability — 0x06's own <c>be</c> gate bullet is wired). <c>largeBlobs:true</c> unconditionally
    /// (BINARY, never tri-state — R2; support is a static capability of this build) and
    /// <c>maxSerializedLargeBlobArray</c> = <see cref="CtapAuthenticatorState.MaxSerializedLargeBlobArrayCapacity"/>
    /// (member <c>0x0B</c>, always emitted alongside — the "MUST be specified iff supported" pair, line
    /// 4434, is always satisfied since this command is always supported). <c>preferredPlatformUvAttempts</c> =
    /// <see cref="CtapAuthenticatorState.PreferredPlatformUvAttempts"/>; <c>uvModality</c> =
    /// <see cref="CtapAuthenticatorState.UvModality"/> — both single-sourced static getters, always
    /// present.
    /// </summary>
    /// <param name="aaguid">The authenticator's claimed AAGUID.</param>
    /// <param name="supportedExtensions">The authenticator model's advertised extension identifiers, or <see langword="null"/> to omit the member.</param>
    /// <param name="isClientPinSet">Whether a PIN has been set (<see cref="CtapAuthenticatorState.CurrentStoredPin"/> is non-<see langword="null"/>).</param>
    /// <param name="isAlwaysUvEnabled">Whether the Always Require User Verification feature is enabled (<see cref="CtapAuthenticatorState.IsAlwaysUvEnabled"/>).</param>
    /// <param name="minPinCodePointLength">The current minimum PIN length in Unicode code points (<see cref="CtapAuthenticatorState.MinPinCodePointLength"/>).</param>
    /// <param name="isForcePinChangeRequired">Whether a PIN change is currently required (<see cref="CtapAuthenticatorState.IsForcePinChangeRequired"/>).</param>
    /// <param name="remainingDiscoverableCredentials">
    /// The estimated number of additional discoverable credentials that can still be stored
    /// (<see cref="CtapAuthenticatorState.ResidentCredentialCapacity"/> minus the current resident
    /// credential count); zero is a legal value.
    /// </param>
    /// <param name="hasProvisionedBioEnrollments">
    /// Whether the fingerprint template store holds at least one provisioned enrollment
    /// (<see cref="CtapAuthenticatorState.HasProvisionedBioEnrollments"/>) — the single source both
    /// <c>uv</c> and <c>bioEnroll</c> derive from.
    /// </param>
    /// <param name="isEnterpriseAttestationCapable">
    /// Whether this authenticator is enterprise attestation capable
    /// (<see cref="CtapAuthenticatorState.IsEnterpriseAttestationCapable"/>) — the single source (R2)
    /// gating both <c>ep</c>'s presence and <see cref="SupportedAuthenticatorConfigCommands(bool)"/>'s
    /// conditional inclusion of <c>0x01</c>.
    /// </param>
    /// <param name="isEnterpriseAttestationEnabled">
    /// Whether the enterprise attestation feature is currently enabled
    /// (<see cref="CtapAuthenticatorState.IsEnterpriseAttestationEnabled"/>) — only consulted when
    /// <paramref name="isEnterpriseAttestationCapable"/>; <c>ep</c>'s tri-state value is
    /// <c>capable ? enabled : null</c> (R9's getInfo half).
    /// </param>
    /// <remarks>
    /// This closes CTAP 2.3 §9's full mandatory-feature set for a <c>FIDO_2_3</c> claimant: <c>hmac-secret</c>
    /// (item 1 — the LAST item to close) is processed end to end (§12.7's mc annotation and ga
    /// compound-input pipeline) and unconditionally advertised in
    /// <see cref="CtapAuthenticatorState.DefaultSupportedExtensions"/> (contract R1); every other item
    /// closed in an earlier wave — <c>credProtect</c> (item 4) is processed end to end (mc persistence,
    /// ga/excludeList enforcement, credMgmt enumeration) and likewise unconditionally advertised.
    /// <c>uvAcfg</c> stays permanently absent (a `getPinUvAuthTokenUsingUvWithPermissions`-only option
    /// this authenticator never grants <c>acfg</c> through). §9 item 8 (line 9088, <c>ep</c> present
    /// implies <c>enableEnterpriseAttestation</c> MUST be supported) closed together with row 7995/8278
    /// once <see cref="SupportedAuthenticatorConfigCommands(bool)"/>'s conditional array shipped.
    /// </remarks>
    private static CtapGetInfoResponse BuildGetInfoResponse(
        Guid aaguid,
        IReadOnlyList<string>? supportedExtensions,
        bool isClientPinSet,
        bool isAlwaysUvEnabled,
        int minPinCodePointLength,
        bool isForcePinChangeRequired,
        int remainingDiscoverableCredentials,
        bool hasProvisionedBioEnrollments,
        bool isEnterpriseAttestationCapable,
        bool isEnterpriseAttestationEnabled) =>
        new(
            Versions: [WellKnownCtapVersions.Fido23],
            Aaguid: aaguid,
            Extensions: supportedExtensions,
            Options: new CtapGetInfoOptions(
                Ep: isEnterpriseAttestationCapable ? isEnterpriseAttestationEnabled : null,
                ResidentKey: true,
                Uv: hasProvisionedBioEnrollments,
                AlwaysUv: isAlwaysUvEnabled,
                CredMgmt: true,
                AuthnrCfg: true,
                BioEnroll: hasProvisionedBioEnrollments,
                ClientPin: isClientPinSet,
                LargeBlobs: true,
                UvBioEnroll: true,
                PinUvAuthToken: true,
                SetMinPinLength: true,
                MakeCredUvNotRqd: !isAlwaysUvEnabled),
            PinUvAuthProtocols: [(int)CtapPinUvAuthProtocolId.Two, (int)CtapPinUvAuthProtocolId.One],
            MaxSerializedLargeBlobArray: CtapAuthenticatorState.MaxSerializedLargeBlobArrayCapacity,
            ForcePinChange: isForcePinChangeRequired,
            MinPinLength: minPinCodePointLength,
            MaxRpIdsForSetMinPinLength: CtapAuthenticatorState.MaxRpIdsForSetMinPinLengthCapacity,
            PreferredPlatformUvAttempts: CtapAuthenticatorState.PreferredPlatformUvAttempts,
            UvModality: CtapAuthenticatorState.UvModality,
            RemainingDiscoverableCredentials: remainingDiscoverableCredentials,
            AuthenticatorConfigCommands: SupportedAuthenticatorConfigCommands(isEnterpriseAttestationCapable));


    /// <summary>
    /// The pure request-arm of <c>authenticatorMakeCredential</c> (CTAP 2.3, section 6.1.2), in the
    /// spec's own literal step order: the zero-length <c>pinUvAuthParam</c> probe (step 1), the protocol
    /// guard (step 2), the pubKeyCredParams algorithm-selection result (step 3, resolved by the
    /// simulator before dispatch), the <c>uv</c>/<c>rk</c>/<c>up</c> option checks with the
    /// <c>pinUvAuthParam</c>-takes-precedence rule (step 5), <c>alwaysUv</c> (step 6, LIVE — see the
    /// remarks), the <c>makeCredUvNotRqd</c>-gated rejection (step 7) and its structurally false sibling
    /// (step 8), <c>enterpriseAttestation</c>'s full clause tree (step 9, waveep R4-R6: capability/
    /// enablement gate, value validation, then the ordered vendor-facilitated/platform-managed grant
    /// cases — see the remarks), the <c>makeCredUvNotRqd</c> fast path (step 10),
    /// and step 11's three-way split: a presented <c>pinUvAuthParam</c> declares a
    /// <see cref="CtapVerifyPinUvAuthTokenAction"/> (step 11.1); an effective <c>uv:true</c> declares a
    /// <see cref="CtapPerformBuiltInUvAction"/> (step 11.2, R11 LIVE); neither resumes at
    /// <see cref="ContinueMakeCredential"/> directly with the <c>uv</c> bit false. Every exit eventually
    /// resumes at <see cref="ContinueMakeCredential"/>, which implements the excludeList/keystore/
    /// attestation-format/generate tail (steps 12/14/17) shared by all three paths.
    /// <c>authenticatorMakeCredential</c> is an intervening operation that discards any remembered
    /// <c>authenticatorGetAssertion</c> sequence regardless of whether this command itself succeeds.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <strong>Step 1's decline/timeout branch is never taken.</strong> The spec names two different
    /// status codes for the same "the user did not grant evidence of user interaction" event: step
    /// 1.2 itself says <c>CTAP2_ERR_OPERATION_DENIED</c> (line 3160), while the NFC-transport
    /// "evidence of user interaction" procedure step 1.1 invokes (lines 2799-2823, this simulator's
    /// actual transport) resolves the analogous failure to <c>CTAP2_ERR_UP_REQUIRED</c> (line 2817).
    /// This authenticator never has to choose between them: evidence of user interaction is ALWAYS
    /// granted here (a deterministic simulator with no decline/timeout seam — the wave-2 modeling this
    /// program has used since <c>authenticatorMakeCredential</c>'s own step 14 evidence collection), so
    /// the probe below goes straight from the length check to the <see cref="WellKnownCtapStatusCodes.PinNotSet"/>/
    /// <see cref="WellKnownCtapStatusCodes.PinInvalid"/> decision (step 1.3) — the decline branch is
    /// structurally unreachable, and no seam is added to make it reachable.
    /// </para>
    /// <para>
    /// <strong>Step 5.3 (lines 3208-3214) is now CONDITIONAL, not unconditional.</strong> A request-level
    /// <c>uv:true</c> (no <c>pinUvAuthParam</c>) rejects with <see cref="WellKnownCtapStatusCodes.InvalidOption"/>
    /// ONLY when the built-in UV method is not yet configured (zero fingerprint enrollments) — once
    /// configured, this early gate does not fire, and <c>effectiveUserVerification</c> flows through to
    /// step 11.2 below (wavebio's R11 flip of the old, permanently-unconditional reject).
    /// </para>
    /// <para>
    /// <strong>Step 6 (<c>alwaysUv</c>, lines 3236-3276) is fully LIVE once <c>authenticatorConfig</c>'s
    /// <c>toggleAlwaysUv</c> subcommand enables <see cref="CtapAuthenticatorState.IsAlwaysUvEnabled"/>.</strong>
    /// Sub-step 6.1 ("treat makeCredUvNotRqd as false", line 3240) needs no code of its own here: R8's
    /// getInfo derivation (<see cref="BuildGetInfoResponse"/>, <c>MakeCredUvNotRqd: !isAlwaysUvEnabled</c>)
    /// already reports it false whenever <c>alwaysUv</c> is true, satisfying line 4951's MUST directly.
    /// Sub-step 6.3 (line 3258) is a REAL FORCING step, re-read against the snapshot's own hrefs: "If
    /// pinUvAuthParam is not present, and THE GETINFO <c>uv</c> OPTION ID is true, let the REQUEST'S
    /// <c>uv</c> option be treated as present-true" — i.e. whenever built-in UV is configured, a
    /// param-absent request under <c>alwaysUv</c> is force-upgraded to <c>uv:true</c> regardless of what
    /// the platform actually asked for (R11's REQUIRED test: <c>alwaysUv</c> on, an enrollment present,
    /// neither <c>pinUvAuthParam</c> nor <c>options.uv</c> requested, the call still succeeds via forced
    /// built-in UV). Sub-step 6.4 (line 3261) then rejects only when, even after 6.3's forcing,
    /// <c>effectiveUserVerification</c> is still false — both this branch and 6.2's not-protected branch
    /// reject with <see cref="WellKnownCtapStatusCodes.PuatRequired"/> (R2's clientPin-present branch;
    /// <c>OperationDenied</c>'s "clientPin not supported" sibling never fires, since <c>clientPin</c> is
    /// always present once any enrollment exists in this profile).
    /// </para>
    /// <para>
    /// <strong>Step 7</strong> (lines 3277-3300, the <c>makeCredUvNotRqd</c>-present-true, <c>rk</c>-gated
    /// rejection) is reachable exactly when <c>alwaysUv</c> is disabled (R8's derivation makes
    /// <c>makeCredUvNotRqd</c> present-true only then) and <c>effectiveUserVerification</c> is false —
    /// this step's own code needs no further changes for R11, since it already guards on
    /// <c>!effectiveUserVerification</c>.
    /// </para>
    /// <para>
    /// <strong>Step 8</strong> (lines 3301-3322, the <c>makeCredUvNotRqd</c> false-or-absent general
    /// rejection, no <c>rk</c> condition) stays structurally unreachable for the same two-legged reason
    /// as before R11: under <c>alwaysUv</c> OFF, <c>makeCredUvNotRqd</c> reports present-true (R8); under
    /// <c>alwaysUv</c> ON, step 6.4 already rejects every still-not-effectively-verified, param-absent
    /// request first.
    /// </para>
    /// <para>
    /// <strong>Step 9</strong> (lines 3323-3360, waveep R4-R6 LIVE) sits between steps 7/8 and 10, exactly
    /// where the spec places it. Sub-step 1 (not capable, OR capable-but-disabled) rejects with
    /// <see cref="WellKnownCtapStatusCodes.InvalidParameter"/> STRICTLY BEFORE the value is inspected at
    /// all (R5's order-pin, trap 5) — a non-capable authenticator receiving ANY value, in-range or not,
    /// gets this code. Only once capable-and-enabled does sub-step 2.1 validate the value against
    /// {1, 2}, rejecting with <see cref="WellKnownCtapStatusCodes.InvalidOption"/> otherwise. A legal
    /// value then resolves the grant CANDIDATE via the two live ordered cases (R4: value 1 with rp.id on
    /// the pre-configured list, or value 2 unconditionally) — case 1's vendor-facilitated-ONLY antecedent
    /// is documented false, never coded. This candidate is computed EXACTLY ONCE here and threaded,
    /// unchanged, through every one of this method's own exits into <see cref="ContinueMakeCredential"/>
    /// (directly, or via <see cref="CtapMakeCredentialVerifyContinuation"/>/
    /// <see cref="CtapMakeCredentialBuiltInUvContinuation"/> across the two async continuations, trap 12)
    /// — where R8's own none-family discretionary decline is the final word on whether an enterprise
    /// attestation is actually minted.
    /// </para>
    /// </remarks>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnMakeCredentialRequested(
        CtapAuthenticatorState state, MakeCredentialRequested requested)
    {
        state = DiscardAllRememberedSequences(state);

        CtapMakeCredentialRequest request = requested.Request;

        if(request.PinUvAuthParam is { Length: 0 })
        {
            byte probeStatus = state.CurrentStoredPin is null ? WellKnownCtapStatusCodes.PinNotSet : WellKnownCtapStatusCodes.PinInvalid;

            return Reject(state, probeStatus, "MakeCredential:ZeroLengthPinUvAuthParamProbe");
        }

        byte? pinUvAuthError = EvaluatePinUvAuthGuard(request.PinUvAuthParam, request.PinUvAuthProtocol);
        if(pinUvAuthError is byte pinError)
        {
            return Reject(state, pinError, "MakeCredential:PinUvAuthRejected");
        }

        if(requested.SelectedAlgorithm is null)
        {
            return Reject(state, WellKnownCtapStatusCodes.UnsupportedAlgorithm, "MakeCredential:UnsupportedAlgorithm");
        }

        bool pinUvAuthParamPresent = request.PinUvAuthParam is not null;
        bool effectiveUserVerification = !pinUvAuthParamPresent && request.Options?.UserVerification == true;

        //Step 5.3 (lines 3208-3214, R11 LIVE): rejects ONLY when built-in UV is not yet configured; a
        //configured request flows through to step 11.2 below instead of rejecting here (wavebio flip).
        if(effectiveUserVerification && !state.HasProvisionedBioEnrollments)
        {
            return Reject(state, WellKnownCtapStatusCodes.InvalidOption, "MakeCredential:UvNotConfigured");
        }

        if(request.Options?.UserPresence == false)
        {
            return Reject(state, WellKnownCtapStatusCodes.InvalidOption, "MakeCredential:UpFalseRejected");
        }

        bool residentKey = request.Options?.ResidentKey ?? false;
        bool isProtectedByUserVerification = IsProtectedByUserVerification(state);

        //Step 6 (lines 3236-3276, R11 LIVE): sub-step 6.3 force-upgrades a param-absent request to
        //effective uv:true whenever built-in UV is configured (see the method's own remarks); 6.4 then
        //rejects only if it is STILL not effectively verified.
        if(state.IsAlwaysUvEnabled)
        {
            if(!isProtectedByUserVerification)
            {
                return Reject(state, WellKnownCtapStatusCodes.PuatRequired, "MakeCredential:AlwaysUvNotProtected");
            }

            if(!pinUvAuthParamPresent && !effectiveUserVerification && state.HasProvisionedBioEnrollments)
            {
                effectiveUserVerification = true;
            }

            if(!pinUvAuthParamPresent && !effectiveUserVerification)
            {
                return Reject(state, WellKnownCtapStatusCodes.PuatRequired, "MakeCredential:AlwaysUvRequiresPinUvAuthToken");
            }
        }

        //Step 7 (lines 3277-3300): reachable exactly when alwaysUv is disabled (R8's derivation makes
        //makeCredUvNotRqd present-true only then; step 6 above already returned for the alwaysUv-on
        //case). R2: the "clientPin not supported" split never resolves to OperationDenied in this
        //profile — isProtectedByUserVerification true implies clientPin is present-true EITHER directly
        //(a PIN is set) OR because any provisioned enrollment itself required a prior PIN-path be token
        //(the only route to a first enrollment in this profile, wavebio) — clientPin, once true, is
        //never unset again short of a factory reset. noMcGaPermissionsWithClientPin is never advertised
        //(absent), so PuatRequired is the only reachable outcome.
        if(isProtectedByUserVerification && !effectiveUserVerification && !pinUvAuthParamPresent && residentKey)
        {
            return Reject(state, WellKnownCtapStatusCodes.PuatRequired, "MakeCredential:ResidentKeyRequiresPinUvAuthToken");
        }

        //Step 9 (lines 3323-3360, R4/R5/R6 LIVE): the grant decision is computed EXACTLY ONCE here and
        //threaded through every exit below (trap 12) — never recomputed downstream.
        bool enterpriseAttestationGranted = false;
        if(request.EnterpriseAttestation is int enterpriseAttestationValue)
        {
            //Sub-step 1 (lines 3329-3331, R5's order-pin, trap 5): capability/enablement is checked
            //STRICTLY BEFORE the value is validated, regardless of what value was supplied — a
            //non-capable authenticator receiving value 7 rejects here with InvalidParameter, never
            //reaching the InvalidOption check below.
            if(!state.IsEnterpriseAttestationCapable || !state.IsEnterpriseAttestationEnabled)
            {
                return Reject(state, WellKnownCtapStatusCodes.InvalidParameter, "MakeCredential:EnterpriseAttestationNotCapableOrDisabled");
            }

            //Sub-step 2.1 (line 3336): capable AND enabled, but the value is neither 1 nor 2.
            if(enterpriseAttestationValue != 1 && enterpriseAttestationValue != 2)
            {
                return Reject(state, WellKnownCtapStatusCodes.InvalidOption, "MakeCredential:EnterpriseAttestationInvalidValue");
            }

            //Sub-step 2.2's ordered cases (R4): case 1 (line 3342, "supports ONLY vendor-facilitated") is
            //antecedent-FALSE in this profile — a capable authenticator here always also supports
            //platform-managed EA (R13's provisioning record is the single source both flavors share), so
            //that antecedent never holds; it is documented here, never coded as a reachable branch. The
            //two LIVE cases: value 1 with rp.id matching the pre-configured list (line 3345), and value 2
            //with NO list check at all (line 3347 — the platform is assumed to have already vetted the
            //rp.id, this simulator's own test harness standing in for that platform). The line 8261 "treat
            //enterpriseAttestation=2 the same as =1" MAY is likewise DECLINED with a documented
            //antecedent-false: that MAY is only available to an authenticator supporting ONLY vendor-
            //facilitated EA, which this profile never is (both flavors are always live together).
            CtapEnterpriseAttestationProvisioning provisioning = state.EnterpriseAttestationProvisioning!;
            bool rpIdOnPreConfiguredList = IsRpIdOnPreConfiguredList(provisioning.PreConfiguredRpIds, request.Rp.Id);
            enterpriseAttestationGranted = (enterpriseAttestationValue == 1 && rpIdOnPreConfiguredList) || enterpriseAttestationValue == 2;

            //Sub-step 2.3 (line 3350): value 1 with an rp.id NOT on the list falls through here with
            //enterpriseAttestationGranted left false — parameter treated as absent, regular (self)
            //attestation, epAtt absent (row 3339's own non-vacuous MUST NOT proof: this is a genuine case
            //where EA could have been requested but was not granted).
        }

        //Step 10 (lines 3361-3374): rk and uv both false/omitted, makeCredUvNotRqd present-true
        //(alwaysUv disabled — step 6 above already returned for the alwaysUv-on case), pinUvAuthParam
        //not present — skip step 11 entirely; the "uv" bit stays false (step 4 already initialized it).
        if(!residentKey && !effectiveUserVerification && !pinUvAuthParamPresent)
        {
            return ContinueMakeCredential(state, requested, request, userVerified: false, userPresent: true, enterpriseAttestationGranted);
        }

        if(isProtectedByUserVerification && pinUvAuthParamPresent)
        {
            CtapPinUvAuthProtocolId protocolId = (CtapPinUvAuthProtocolId)request.PinUvAuthProtocol!.Value;
            CtapPinUvAuthTokenState presentedToken = SelectPinUvAuthTokenState(state, protocolId).EvaluateExpiry(requested.Now);
            state = WithPinUvAuthTokenState(state, protocolId, presentedToken);

            CtapAuthenticatorState nextState = state with
            {
                NextAction = new CtapVerifyPinUvAuthTokenAction(
                    protocolId, presentedToken, request.ClientDataHash, request.PinUvAuthParam!.Value,
                    new CtapMakeCredentialVerifyContinuation(requested, enterpriseAttestationGranted)),
                ResponseIntent = null
            };

            return Transition(nextState, "MakeCredential:VerifyPinUvAuthToken");
        }

        //Step 11.2 (lines 3413-3438, R11 LIVE): uv:true, no param, built-in UV configured (guaranteed
        //protected by the widened IsProtectedByUserVerification). internalRetry is HARDCODED true here
        //(mc 11.2.1 verbatim) — never computed by a helper shared with 0x06 (uv scout trap 2).
        if(effectiveUserVerification)
        {
            if(ShouldDragDownUvRetriesOnPinLockout(state))
            {
                return Reject(state with { UvRetries = 0 }, WellKnownCtapStatusCodes.PuatRequired, "MakeCredential:BuiltInUvPinLockoutDragDown");
            }

            if(state.UvRetries == 0)
            {
                return Reject(state, WellKnownCtapStatusCodes.PuatRequired, "MakeCredential:BuiltInUvRetriesExhausted");
            }

            CtapAuthenticatorState uvState = state with
            {
                NextAction = new CtapPerformBuiltInUvAction(InternalRetry: true, state.UvRetries, new CtapMakeCredentialBuiltInUvContinuation(requested, enterpriseAttestationGranted)),
                ResponseIntent = null
            };

            return Transition(uvState, "MakeCredential:PerformBuiltInUv");
        }

        //Not protected, or protected-but-neither-param-nor-uv-present: proceed with the "uv" bit false
        //(line 3440's note — any junk pinUvAuthParam is ignored when not protected).
        return ContinueMakeCredential(state, requested, request, userVerified: false, userPresent: true, enterpriseAttestationGranted);
    }


    /// <summary>
    /// Completes an <c>authenticatorMakeCredential</c> whose presented <c>pinUvAuthParam</c> has been
    /// verified (CTAP 2.3 §6.1.2 step 11.1, lines 3383-3410), in this command's own literal order:
    /// verify (already run by the executor) → <c>mc</c> permission → permissions-RP-ID match (only if
    /// already bound) → <c>userVerifiedFlagValue</c> → set the <c>uv</c> bit → bind the permissions RP
    /// ID (only if unbound) → stamp <see cref="CtapPinUvAuthTokenState.LastUsedAt"/> → continue at
    /// <see cref="ContinueMakeCredential"/>. Every failure returns the identical
    /// <see cref="WellKnownCtapStatusCodes.PinAuthInvalid"/> (line 3386/3389/3395/3400) — no finer-grained
    /// code exists for a bad signature, a missing permission, or a mismatched RP ID.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnMakeCredentialPinUvAuthTokenVerified(
        CtapAuthenticatorState state, bool verified, MakeCredentialRequested requested, bool enterpriseAttestationGranted)
    {
        if(!verified)
        {
            return Reject(state, WellKnownCtapStatusCodes.PinAuthInvalid, "MakeCredential:VerifyFailed");
        }

        CtapMakeCredentialRequest request = requested.Request;
        CtapPinUvAuthProtocolId protocolId = (CtapPinUvAuthProtocolId)request.PinUvAuthProtocol!.Value;
        CtapPinUvAuthTokenState token = SelectPinUvAuthTokenState(state, protocolId);

        if((token.Permissions & WellKnownCtapPinUvAuthTokenPermissions.Mc) == 0)
        {
            return Reject(state, WellKnownCtapStatusCodes.PinAuthInvalid, "MakeCredential:McPermissionDenied");
        }

        if(token.PermissionsRpId is not null && !string.Equals(token.PermissionsRpId, request.Rp.Id, StringComparison.Ordinal))
        {
            return Reject(state, WellKnownCtapStatusCodes.PinAuthInvalid, "MakeCredential:PermissionsRpIdMismatch");
        }

        if(!token.GetUserVerifiedFlagValue())
        {
            return Reject(state, WellKnownCtapStatusCodes.PinAuthInvalid, "MakeCredential:UserVerifiedFlagFalse");
        }

        if(token.PermissionsRpId is null)
        {
            token = token with { PermissionsRpId = request.Rp.Id };
        }

        token = token with { LastUsedAt = requested.Now };
        state = WithPinUvAuthTokenState(state, protocolId, token);

        return ContinueMakeCredential(state, requested, request, userVerified: true, userPresent: true, enterpriseAttestationGranted);
    }


    /// <summary>
    /// The <c>authenticatorMakeCredential</c> continuation shared by the <c>makeCredUvNotRqd</c> fast
    /// path, the not-protected fallback, and <see cref="OnMakeCredentialPinUvAuthTokenVerified"/>'s
    /// success exit (decision 5's continuation helper), in the spec's own literal order: excludeList
    /// membership (CTAP 2.3 §6.1.2 step 12, R9 LIVE), flag clearing on every success (step 14.4, line
    /// 3545 — <c>up</c> is always true in-profile by this point, since <c>up=false</c> was already
    /// rejected in the request arm), extensions processing (op-makecred-step-extensions, lines 3548-3559,
    /// R6 LIVE: <c>credProtect</c> value validation/default, <c>minPinLength</c> RP-ID authorization,
    /// §12.7's <c>hmac-secret</c> literal-true gate (snapshot line 13194, contract R3), and §12.3's
    /// <c>largeBlobKey</c> value/rk validation, wavelb R8), then the step-17 resident-credential
    /// key-store-full decision (line 3579) and attestation format resolution before declaring a
    /// <see cref="CtapGenerateCredentialKeyAction"/> carrying the resolved extension output values
    /// alongside <paramref name="userVerified"/>/<paramref name="userPresent"/>.
    /// The clearing runs BEFORE the key-store-full check because step 14 precedes step 17 in the spec's
    /// own numbering: a presented <c>pinUvAuthToken</c> is already consumed (permissions stripped, cached
    /// UP/UV cleared) by the time a <see cref="WellKnownCtapStatusCodes.KeyStoreFull"/> rejection can
    /// fire.
    /// </summary>
    /// <param name="enterpriseAttestationGranted">
    /// Step 9's own grant candidate (waveep R6), threaded from <c>OnMakeCredentialRequested</c> (directly,
    /// or via <see cref="CtapMakeCredentialVerifyContinuation"/>/<see cref="CtapMakeCredentialBuiltInUvContinuation"/>
    /// across an async round trip) — never recomputed here (trap 12). Combined with this call's own
    /// attestation-format resolution below (waveep R8): a none-family resolution declines the grant
    /// regardless of this parameter's value.
    /// </param>
    /// <remarks>
    /// ExcludeList's credProtect-aware branch (CTAP 2.3 lines 3441-3499, R9): a match at level
    /// <see cref="CredProtectUserVerificationOptional"/>/<see cref="CredProtectUserVerificationOptionalWithCredentialIdList"/>,
    /// or at <see cref="CredProtectUserVerificationRequired"/> with <paramref name="userVerified"/>
    /// (threading THIS call's already-resolved value — the spec's own "uv bit... in the response", no
    /// second lookup) already <see langword="true"/>, reaches
    /// <see cref="WellKnownCtapStatusCodes.CredentialExcluded"/> unconditionally — the spec's own
    /// presence-wait-then-exclude-regardless (lines 3450-3466) collapses to immediate exclusion under
    /// this simulator's presence model, which grants evidence of user interaction unconditionally. A
    /// level-<see cref="CredProtectUserVerificationRequired"/> match with NO <c>uv</c> collected in this
    /// same call is the spec's own inversion (lines 3497-3498): "remove the credential from the
    /// excludeList and continue parsing the rest of the list" — the exemption is per-ENTRY, not a
    /// whole-list short-circuit, so <see cref="ExcludeListHasMatch"/> skips such an entry and keeps
    /// scanning; <c>authenticatorMakeCredential</c> proceeds only when EVERY entry the excludeList names
    /// for this <c>rp.id</c> is exempted, and a later entry naming a level-1/2 (or UV-collected level-3)
    /// credential still excludes.
    /// </remarks>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> ContinueMakeCredential(
        CtapAuthenticatorState state, MakeCredentialRequested requested, CtapMakeCredentialRequest request, bool userVerified, bool userPresent,
        bool enterpriseAttestationGranted)
    {
        CtapCredentialRecord? excludedMatch = ExcludeListHasMatch(request.ExcludeList, request.Rp.Id, state.CredentialsByCredentialId, userVerified);
        if(excludedMatch is not null)
        {
            return Reject(state, WellKnownCtapStatusCodes.CredentialExcluded, "MakeCredential:CredentialExcluded");
        }

        state = ClearPinUvAuthTokenFlags(state);

        //R6/§12.1 line 12648: absent credProtect defaults to level 1; a present value outside the three
        //legal wire values {1, 2, 3} (line 12609's table) is a protection-policy request this
        //authenticator cannot honor and is not ignorable — §12.1 itself defines no error path, so the
        //general invalid-parameter posture governs (a documented deviation, contract R5/R6). A present,
        //legal value is both the persisted level AND the authData output value (line 12632's MUST: the
        //authenticator never sets a DIFFERENT level than what it "set for the created credential" — this
        //profile never exercises line 12539's stricter unilateral-default MAY).
        int credProtectLevel = CredProtectUserVerificationOptional;
        bool credProtectRequested = false;
        if(request.CredProtect is int requestedCredProtect)
        {
            bool isLegalCredProtectValue = requestedCredProtect == CredProtectUserVerificationOptional
                || requestedCredProtect == CredProtectUserVerificationOptionalWithCredentialIdList
                || requestedCredProtect == CredProtectUserVerificationRequired;
            if(!isLegalCredProtectValue)
            {
                return Reject(state, WellKnownCtapStatusCodes.InvalidParameter, "MakeCredential:CredProtectInvalidValue");
            }

            credProtectLevel = requestedCredProtect;
            credProtectRequested = true;
        }

        //R6/§12.5: "minPinLength": true authorizes the output only when rp.id is already on the stored
        //minPinLengthRPIDs list (R7); an unauthorized or absent request resolves to the key being
        //omitted entirely inside an otherwise-successful response — §12.5 defines no error path for
        //this case (extraction trap 8). "minPinLength": false is semantically not-asking (the reader
        //already preserves the explicit-false-vs-absent distinction; both resolve identically here).
        int? minPinLengthOutputValue = request.MinPinLength == true && IsRpIdAuthorizedForMinPinLength(state.MinPinLengthRpIds, request.Rp.Id)
            ? state.MinPinCodePointLength
            : null;

        //R3/§12.7 line 13194: the mc "hmac-secret" gate is read as "sent with the value true" — a
        //present false is treated as not-requested (not-emitting the annotation), since answering a
        //false request with "hmac-secret": true would be actively misleading. CredRandom itself is
        //minted unconditionally regardless of this flag (line 13192's SHOULD, adopted) — see
        //GenerateCredentialAsync; this flag only gates the mc authData annotation.
        bool hmacSecretRequested = request.HmacSecret == true;

        //R6/§12.8 lines 13369-13370: the hmac-secret-mc pairing gate runs BEFORE any crypto (trap 8) —
        //present while hmac-secret is absent, or present-but-not-exactly-true (hmacSecretRequested
        //already collapses both negative shapes), is a platform-side protocol violation this
        //authenticator rejects outright rather than silently ignoring.
        if(request.HmacSecretMc is not null && !hmacSecretRequested)
        {
            return Reject(state, WellKnownCtapStatusCodes.MissingParameter, "MakeCredential:HmacSecretMcUnpaired");
        }

        //R6/§12.8 line 13402: "processing is the same as the hmac secret extension's getAssertion
        //processing" — step 1's protocol resolution (absent defaults to protocol one, snapshot line
        //13279; a present-but-unsupported value is the clientPIN §6.5.5 analog rejection) governs this
        //compound input identically to ContinueGetAssertion's own hmacSecretProtocol resolution. The
        //CredRandom pair this delegation ultimately needs does not exist yet (this credential has not
        //been minted), so only the protocol-independent half assembles here — GenerateCredentialAsync
        //completes it once minting produces the pair.
        CtapMakeCredentialHmacSecretMcRequest? hmacSecretMcRequest = null;
        if(request.HmacSecretMc is CtapGetAssertionHmacSecretInput hmacSecretMcInput)
        {
            CtapPinUvAuthProtocolId resolvedHmacSecretMcProtocol;
            if(hmacSecretMcInput.PinUvAuthProtocol is int requestedHmacSecretMcProtocol)
            {
                if(!IsSupportedPinUvAuthProtocol(requestedHmacSecretMcProtocol))
                {
                    return Reject(state, WellKnownCtapStatusCodes.InvalidParameter, "MakeCredential:HmacSecretMcUnsupportedProtocol");
                }

                resolvedHmacSecretMcProtocol = (CtapPinUvAuthProtocolId)requestedHmacSecretMcProtocol;
            }
            else
            {
                resolvedHmacSecretMcProtocol = CtapPinUvAuthProtocolId.One;
            }

            hmacSecretMcRequest = new CtapMakeCredentialHmacSecretMcRequest(
                resolvedHmacSecretMcProtocol, SelectOwnPrivateKey(state, resolvedHmacSecretMcProtocol), hmacSecretMcInput.KeyAgreement,
                hmacSecretMcInput.SaltEnc, hmacSecretMcInput.SaltAuth);
        }

        bool residentKey = request.Options?.ResidentKey ?? false;

        //R8/§12.3 lines 12845-12849: a present largeBlobKey value that is not exactly true is a
        //request-shape error (the extension should be omitted rather than asserted false), checked
        //BEFORE the rk co-requirement; a present-true value additionally requires options.rk == true.
        //Absent stays unrequested — no error, no key minted.
        bool largeBlobKeyRequested = false;
        if(request.LargeBlobKey is bool largeBlobKeyValue)
        {
            if(largeBlobKeyValue != true)
            {
                return Reject(state, WellKnownCtapStatusCodes.InvalidOption, "MakeCredential:LargeBlobKeyNotTrue");
            }

            if(!residentKey)
            {
                return Reject(state, WellKnownCtapStatusCodes.InvalidOption, "MakeCredential:LargeBlobKeyRequiresResidentKey");
            }

            largeBlobKeyRequested = true;
        }

        if(residentKey
            && FindResidentCredential(state.CredentialsByCredentialId, request.Rp.Id, request.User.Id) is null
            && CountResidentCredentials(state.CredentialsByCredentialId) >= state.ResidentCredentialCapacity)
        {
            return Reject(state, WellKnownCtapStatusCodes.KeyStoreFull, "MakeCredential:KeyStoreFull");
        }

        CtapAttestationFormatChoice attestationFormat = ResolveAttestationFormat(request.AttestationFormatsPreference);

        //Sub-steps 2.4-2.5 (lines 3352-3354, waveep R8): the ONE adopted additional discretionary
        //constraint this authenticator applies is "none-family formats never carry EA" — a granted
        //request whose OWN attestationFormatsPreference resolution is a none-family choice
        //(NoneWithStatement/NoneOmitted) declines the grant outright and proceeds with that none output,
        //epAtt absent. No other discretionary constraint is adopted. A granted request whose resolution
        //is PackedSelf upgrades to PackedCertified here — this IS the R9 epAtt decision (the response
        //writer reads it back from this same field, never a second stored flag).
        if(enterpriseAttestationGranted && attestationFormat == CtapAttestationFormatChoice.PackedSelf)
        {
            attestationFormat = CtapAttestationFormatChoice.PackedCertified;
        }

        CtapAuthenticatorState nextState = state with
        {
            NextAction = new CtapGenerateCredentialKeyAction(
                request.Rp.Id, request.User.Id, request.User.Name, request.User.DisplayName, requested.SelectedAlgorithm!.Value, residentKey,
                userPresent, userVerified, request.ClientDataHash, attestationFormat,
                CredProtectLevel: credProtectLevel, CredProtectRequested: credProtectRequested, MinPinLengthOutputValue: minPinLengthOutputValue,
                HmacSecretRequested: hmacSecretRequested, LargeBlobKeyRequested: largeBlobKeyRequested, HmacSecretMc: hmacSecretMcRequest),
            ResponseIntent = null
        };

        return Transition(nextState, "MakeCredential:Requested");
    }


    /// <summary>
    /// Completes <c>authenticatorMakeCredential</c> once the effectful loop has minted the credential:
    /// stamps the mint-order <see cref="CtapCredentialRecord.CreationSequence"/> from the state's own
    /// counter, installs the new record into the credential-ID-keyed store, disposing (and removing by
    /// credential ID) any credential it overwrites for the same relying party and account (CTAP 2.3
    /// section 6.1.2, step 16), and advances the sequence counter for the next mint.
    /// </summary>
    /// <remarks>
    /// Line 3572's overwrite-erase MAY ("If the existing credential contains a largeBlobKey, an
    /// authenticator MAY erase any associated large-blob data") is DECLINED: <c>overwritten?.Dispose()</c>
    /// below releases only the OVERWRITTEN credential's own <see cref="CtapCredentialRecord.LargeBlobKey"/>
    /// field (credential-record custody), never any entry inside the serialized large-blob array itself.
    /// Erasing array entries is structurally incompatible with line 7704's MUST NOT ("act on the contents
    /// of the serialized large-blob array except for checking the trailing hash"): locating which array
    /// entries belong to an overwritten credential requires trial-decrypting each entry against its
    /// largeBlobKey, a platform-only operation (Finding 1/4) this authenticator never performs. Line
    /// 3572's own second sentence anticipates exactly this: "Platforms MUST NOT assume that authenticators
    /// will do this."
    /// </remarks>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnCredentialMinted(
        CtapAuthenticatorState state, CredentialMinted minted)
    {
        CtapCredentialRecord record = minted.Record with { CreationSequence = state.NextCredentialSequence };
        ImmutableDictionary<string, CtapCredentialRecord> byId = state.CredentialsByCredentialId;

        CtapCredentialRecord? overwritten = record.IsResident
            ? FindResidentCredential(byId, record.RpId, record.UserId)
            : null;
        if(overwritten is not null)
        {
            byId = byId.Remove(CredentialIdKey(overwritten.CredentialId));
        }

        byId = byId.SetItem(CredentialIdKey(record.CredentialId), record);
        overwritten?.Dispose();

        CtapAuthenticatorState nextState = state with
        {
            NextAction = NullAction.Instance,
            CredentialsByCredentialId = byId,
            NextCredentialSequence = state.NextCredentialSequence + 1,
            ResponseIntent = new MakeCredentialResponseReady(minted.Response)
        };

        return Transition(nextState, "MakeCredential:Completed");
    }


    /// <summary>
    /// The pure request-arm of <c>authenticatorGetAssertion</c> (CTAP 2.3, section 6.2.2), mirroring
    /// <see cref="OnMakeCredentialRequested"/>'s treatment: the zero-length <c>pinUvAuthParam</c> probe
    /// (step 1), the protocol guard (step 2), the <c>uv</c>/<c>rk</c> option checks with the
    /// <c>pinUvAuthParam</c>-takes-precedence rule (step 4 — <c>rk</c> is rejected unconditionally,
    /// regardless of value, per the spec's own unqualified rejection), <c>alwaysUv</c> (step 5, LIVE —
    /// see the remarks), and step 6's three-way split: a presented <c>pinUvAuthParam</c> declares a
    /// <see cref="CtapVerifyPinUvAuthTokenAction"/> (step 6.1); an effective <c>uv:true</c> declares a
    /// <see cref="CtapPerformBuiltInUvAction"/> (step 6.2, R11 LIVE); neither resumes at
    /// <see cref="ContinueGetAssertion"/> directly with the <c>uv</c> bit false — which implements the
    /// locate-credentials/declare-sign tail (step 7) shared by all three paths. A fresh
    /// <c>authenticatorGetAssertion</c> is itself an intervening operation: it discards (and, when it
    /// locates more than one applicable credential, immediately replaces) any remembered sequence from
    /// an earlier command.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <strong>Step 1's decline/timeout branch is never taken</strong>, for the identical reason as
    /// <c>authenticatorMakeCredential</c>'s step 1 (see <see cref="OnMakeCredentialRequested"/>'s
    /// remarks for the full competing-anchor citation: step 1.2 here names
    /// <c>CTAP2_ERR_OPERATION_DENIED</c> at line 3865, the NFC transport procedure names
    /// <c>CTAP2_ERR_UP_REQUIRED</c> at line 2817) — evidence of user interaction is always granted, so
    /// the probe below goes straight to the <see cref="WellKnownCtapStatusCodes.PinNotSet"/>/
    /// <see cref="WellKnownCtapStatusCodes.PinInvalid"/> decision.
    /// </para>
    /// <para>
    /// <strong>Step 4.3 (lines 3896-3902) is now CONDITIONAL</strong>, mirroring mc's own step 5.3 flip:
    /// a request-level <c>uv:true</c> rejects with <see cref="WellKnownCtapStatusCodes.InvalidOption"/>
    /// ONLY when built-in UV is not yet configured; once configured, it flows through to step 6.2.
    /// </para>
    /// <para>
    /// <strong>Step 5 (<c>alwaysUv</c>, lines 3916-3960) is fully LIVE once <c>authenticatorConfig</c>'s
    /// <c>toggleAlwaysUv</c> subcommand enables <see cref="CtapAuthenticatorState.IsAlwaysUvEnabled"/> —
    /// gated additionally on the "up" option being effectively true (line 3917), unlike mc's step 6.</strong>
    /// The "up" option's own effective value is already resolved by this method's existing
    /// <c>request.Options?.UserPresence ?? true</c> read (step 4.5, lines 3910-3913 — absent normalizes
    /// to <see langword="true"/> BEFORE step 5 is ever reached), so a preflight/silent <c>ga</c> call
    /// (<c>up: false</c>) is NEVER subject to <c>alwaysUv</c> enforcement — the carve-out this
    /// authenticator preserves. When the gate applies: sub-step 5.1 (line 3920) rejects unconditionally
    /// when not protected (R2's clientPin-present branch — <c>OperationDenied</c>'s sibling never
    /// fires); sub-step 5.4 (line 3940-3946) is ga's OWN genuine forcing step — re-read against the
    /// snapshot's own hrefs, its condition is the REQUEST'S own <c>uv</c> option being false AND the
    /// authenticator supporting AND having enabled built-in UV (i.e. configured): force-upgrades to
    /// <c>uv:true</c> exactly the way mc's step 6.3 does (R11's shared REQUIRED test);
    /// sub-step 5.5 (lines 3948-3959, still not effectively verified after 5.2-5.4) rejects with
    /// <see cref="WellKnownCtapStatusCodes.PuatRequired"/>.
    /// </para>
    /// </remarks>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnGetAssertionRequested(
        CtapAuthenticatorState state, GetAssertionRequested requested)
    {
        state = DiscardAllRememberedSequences(state);

        CtapGetAssertionRequest request = requested.Request;

        if(request.PinUvAuthParam is { Length: 0 })
        {
            byte probeStatus = state.CurrentStoredPin is null ? WellKnownCtapStatusCodes.PinNotSet : WellKnownCtapStatusCodes.PinInvalid;

            return Reject(state, probeStatus, "GetAssertion:ZeroLengthPinUvAuthParamProbe");
        }

        byte? pinUvAuthError = EvaluatePinUvAuthGuard(request.PinUvAuthParam, request.PinUvAuthProtocol);
        if(pinUvAuthError is byte pinError)
        {
            return Reject(state, pinError, "GetAssertion:PinUvAuthRejected");
        }

        bool pinUvAuthParamPresent = request.PinUvAuthParam is not null;
        bool effectiveUserVerification = !pinUvAuthParamPresent && request.Options?.UserVerification == true;

        //Step 4.3 (lines 3896-3902, R11 LIVE): rejects ONLY when built-in UV is not yet configured.
        if(effectiveUserVerification && !state.HasProvisionedBioEnrollments)
        {
            return Reject(state, WellKnownCtapStatusCodes.InvalidOption, "GetAssertion:UvNotConfigured");
        }

        if(request.Options?.ResidentKey is not null)
        {
            return Reject(state, WellKnownCtapStatusCodes.UnsupportedOption, "GetAssertion:ResidentKeyOptionRejected");
        }

        bool userPresent = request.Options?.UserPresence ?? true;
        bool isProtectedByUserVerification = IsProtectedByUserVerification(state);

        //Step 5 (lines 3916-3960, R11 LIVE): gated additionally on the effective "up" value (absent ⇒
        //true, already resolved above) — the up:false carve-out this authenticator preserves. Sub-step
        //5.4 force-upgrades a false/absent request uv option to true whenever built-in UV is configured
        //(see the method's own remarks) — ga's own genuine forcing step, distinct from mc's restatement.
        if(state.IsAlwaysUvEnabled && userPresent)
        {
            if(!isProtectedByUserVerification)
            {
                return Reject(state, WellKnownCtapStatusCodes.PuatRequired, "GetAssertion:AlwaysUvNotProtected");
            }

            if(!pinUvAuthParamPresent && !effectiveUserVerification)
            {
                if(state.HasProvisionedBioEnrollments)
                {
                    effectiveUserVerification = true;
                }
                else
                {
                    return Reject(state, WellKnownCtapStatusCodes.PuatRequired, "GetAssertion:AlwaysUvRequiresPinUvAuthToken");
                }
            }
        }

        if(isProtectedByUserVerification && pinUvAuthParamPresent)
        {
            CtapPinUvAuthProtocolId protocolId = (CtapPinUvAuthProtocolId)request.PinUvAuthProtocol!.Value;
            CtapPinUvAuthTokenState presentedToken = SelectPinUvAuthTokenState(state, protocolId).EvaluateExpiry(requested.Now);
            state = WithPinUvAuthTokenState(state, protocolId, presentedToken);

            CtapAuthenticatorState nextState = state with
            {
                NextAction = new CtapVerifyPinUvAuthTokenAction(
                    protocolId, presentedToken, request.ClientDataHash, request.PinUvAuthParam!.Value,
                    new CtapGetAssertionVerifyContinuation(requested)),
                ResponseIntent = null
            };

            return Transition(nextState, "GetAssertion:VerifyPinUvAuthToken");
        }

        //Step 6.2 (lines 3997-4023, R11 LIVE): uv effectively true, no param, built-in UV configured.
        //internalRetry is HARDCODED true here (ga 6.2.1 verbatim) — never computed by a helper shared
        //with 0x06 (uv scout trap 2).
        if(effectiveUserVerification)
        {
            if(ShouldDragDownUvRetriesOnPinLockout(state))
            {
                return Reject(state with { UvRetries = 0 }, WellKnownCtapStatusCodes.PuatRequired, "GetAssertion:BuiltInUvPinLockoutDragDown");
            }

            if(state.UvRetries == 0)
            {
                return Reject(state, WellKnownCtapStatusCodes.PuatRequired, "GetAssertion:BuiltInUvRetriesExhausted");
            }

            CtapAuthenticatorState uvState = state with
            {
                NextAction = new CtapPerformBuiltInUvAction(InternalRetry: true, state.UvRetries, new CtapGetAssertionBuiltInUvContinuation(requested, userPresent)),
                ResponseIntent = null
            };

            return Transition(uvState, "GetAssertion:PerformBuiltInUv");
        }

        //Not protected, or protected-but-neither-param-nor-uv-present: proceed with the "uv" bit false
        //(line 4025's note — any junk pinUvAuthParam is ignored when not protected).
        return ContinueGetAssertion(state, requested, request, userVerified: false, userPresent, authenticatingProtocol: null);
    }


    /// <summary>
    /// Completes an <c>authenticatorGetAssertion</c> whose presented <c>pinUvAuthParam</c> has been
    /// verified (CTAP 2.3 §6.2.2 step 6.1, lines 3969-3995), in this command's own literal order — DIFFERENT
    /// from <c>authenticatorMakeCredential</c>'s (see <see cref="OnMakeCredentialPinUvAuthTokenVerified"/>'s
    /// remarks for the equivalence argument): verify (already run by the executor, "sets the uv bit
    /// immediately on success" per the spec text) → <c>userVerifiedFlagValue</c> → <c>ga</c> permission →
    /// permissions-RP-ID match (only if already bound) → bind the permissions RP ID (only if unbound) →
    /// stamp <see cref="CtapPinUvAuthTokenState.LastUsedAt"/> → continue at <see cref="ContinueGetAssertion"/>.
    /// Every failure returns the identical <see cref="WellKnownCtapStatusCodes.PinAuthInvalid"/>
    /// (line 3972/3979/3981/3986).
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnGetAssertionPinUvAuthTokenVerified(
        CtapAuthenticatorState state, bool verified, GetAssertionRequested requested)
    {
        if(!verified)
        {
            return Reject(state, WellKnownCtapStatusCodes.PinAuthInvalid, "GetAssertion:VerifyFailed");
        }

        CtapGetAssertionRequest request = requested.Request;
        CtapPinUvAuthProtocolId protocolId = (CtapPinUvAuthProtocolId)request.PinUvAuthProtocol!.Value;
        CtapPinUvAuthTokenState token = SelectPinUvAuthTokenState(state, protocolId);

        if(!token.GetUserVerifiedFlagValue())
        {
            return Reject(state, WellKnownCtapStatusCodes.PinAuthInvalid, "GetAssertion:UserVerifiedFlagFalse");
        }

        if((token.Permissions & WellKnownCtapPinUvAuthTokenPermissions.Ga) == 0)
        {
            return Reject(state, WellKnownCtapStatusCodes.PinAuthInvalid, "GetAssertion:GaPermissionDenied");
        }

        if(token.PermissionsRpId is not null && !string.Equals(token.PermissionsRpId, request.RpId, StringComparison.Ordinal))
        {
            return Reject(state, WellKnownCtapStatusCodes.PinAuthInvalid, "GetAssertion:PermissionsRpIdMismatch");
        }

        if(token.PermissionsRpId is null)
        {
            token = token with { PermissionsRpId = request.RpId };
        }

        token = token with { LastUsedAt = requested.Now };
        state = WithPinUvAuthTokenState(state, protocolId, token);

        bool userPresent = request.Options?.UserPresence ?? true;

        return ContinueGetAssertion(state, requested, request, userVerified: true, userPresent, authenticatingProtocol: protocolId);
    }


    /// <summary>
    /// The <c>authenticatorGetAssertion</c> continuation shared by the not-protected fallback and
    /// <see cref="OnGetAssertionPinUvAuthTokenVerified"/>'s success exit (decision 5's continuation
    /// helper): the CTAP 2.3 §12.7 hmac-secret PURE pre-checks (steps 1-2, below), the credential-location
    /// step (allowList match, or the full applicable-resident-credentials list ordered most-recent-first
    /// per CTAP 2.3 section 6.2 step 12), R10's credProtect filtering (CTAP 2.3 §12.1, lines 4038-4048,
    /// applied AFTER each locate call — see <see cref="IsCredProtectLevelThreeUvExcluded"/> and
    /// <see cref="FilterUnverifiedCredProtectFromDiscoverableScan"/>), flag clearing on every success
    /// whose <paramref name="userPresent"/> is not false (step 9.4, line 4098), and declaring a
    /// <see cref="CtapSignAssertionAction"/> with the resolved <paramref name="userVerified"/>/
    /// <paramref name="userPresent"/> flags. <paramref name="authenticatingProtocol"/> names which
    /// protocol's <c>pinUvAuthToken</c> authenticated this call — the caller's own selected protocol on
    /// the verified path, <see langword="null"/> on the not-protected fallback — and is threaded into any
    /// minted <see cref="CtapRememberGetAssertionRequest"/> so <c>authenticatorGetNextAssertion</c> can
    /// later fold that token's own expiry into its discard decision (CTAP 2.3, section 6, item 3, line
    /// 2873).
    /// </summary>
    /// <remarks>
    /// hmac-secret steps 1-2 (contract R4) run here, ONCE, before either credential-location branch —
    /// both checks are pure (no crypto, no credential lookup) and this method is the single funnel both
    /// callers share, so placing them here matches the spec's own step order (protocol/up validated
    /// before the "wait for consent" step this authenticator's uv/up resolution has already completed by
    /// the time either caller reaches this method) without duplicating the checks per branch. Step 1:
    /// <c>pinUvAuthProtocol</c> absent defaults to protocol one (snapshot line 13279 — protocol one is
    /// always supported here, so line 13281's "protocol one unsupported" branch is antecedent-false, never
    /// coded as reachable); present-but-unsupported (e.g. <c>3</c>) rejects with
    /// <see cref="WellKnownCtapStatusCodes.InvalidParameter"/> — no hmac-secret-specific clause names this
    /// case, so this ruled reading reuses the clientPIN §6.5.5 analog (<see cref="EvaluatePinUvAuthGuard"/>'s
    /// own present-but-unsupported disposition). Step 2: <paramref name="userPresent"/> false with the
    /// extension present rejects with <see cref="WellKnownCtapStatusCodes.UnsupportedOption"/> (snapshot
    /// line 13283) — this authenticator's own general <c>up</c> handling does not already produce this
    /// code for a bare <c>up:false</c> ga request (unlike <c>authenticatorMakeCredential</c>, ga's
    /// <c>up:false</c> is otherwise legal), so hmac-secret's own check is the only source of it
    /// (<c>HmacSecretUpFalseReturnsUnsupportedOption</c>).
    /// </remarks>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> ContinueGetAssertion(
        CtapAuthenticatorState state, GetAssertionRequested requested, CtapGetAssertionRequest request, bool userVerified, bool userPresent,
        CtapPinUvAuthProtocolId? authenticatingProtocol)
    {
        CtapPinUvAuthProtocolId? hmacSecretProtocol = null;
        if(request.HmacSecret is CtapGetAssertionHmacSecretInput hmacSecretInput)
        {
            if(hmacSecretInput.PinUvAuthProtocol is int requestedHmacSecretProtocol)
            {
                if(!IsSupportedPinUvAuthProtocol(requestedHmacSecretProtocol))
                {
                    return Reject(state, WellKnownCtapStatusCodes.InvalidParameter, "GetAssertion:HmacSecretUnsupportedProtocol");
                }

                hmacSecretProtocol = (CtapPinUvAuthProtocolId)requestedHmacSecretProtocol;
            }
            else
            {
                hmacSecretProtocol = CtapPinUvAuthProtocolId.One;
            }

            if(!userPresent)
            {
                return Reject(state, WellKnownCtapStatusCodes.UnsupportedOption, "GetAssertion:HmacSecretUpFalse");
            }
        }

        bool allowListPresent = request.AllowList is { Count: > 0 };
        if(allowListPresent)
        {
            CtapCredentialRecord? credential = LocateAllowListCredential(state, request);
            if(credential is null || IsCredProtectLevelThreeUvExcluded(credential, userVerified))
            {
                return Reject(state, WellKnownCtapStatusCodes.NoCredentials, "GetAssertion:NoCredentials");
            }

            //R8/§12.3 line 12865: a present largeBlobKey value that is not exactly true is a
            //request-shape error, checked once a credential has actually been located (CTAP 2.3's own
            //extension-processing step follows credential location, mirroring mc's own placement).
            if(request.LargeBlobKey is bool allowListLargeBlobKeyValue && allowListLargeBlobKeyValue != true)
            {
                return Reject(state, WellKnownCtapStatusCodes.InvalidOption, "GetAssertion:LargeBlobKeyNotTrue");
            }

            state = ApplyPinUvAuthTokenFlagClearingIfUserPresent(state, userPresent);

            //Per CTAP 2.3 section 6.2's response table, an allowList-denoted assertion never gets a
            //user member, and numberOfCredentials/remembered state are never produced on this branch.
            return DeclareSignAssertion(
                state, credential, request.ClientDataHash, userPresent, userVerified, responseUser: null, numberOfCredentials: null, rememberOnCompletion: null,
                largeBlobKeyRequested: request.LargeBlobKey == true, hmacSecretInput: request.HmacSecret, hmacSecretProtocol: hmacSecretProtocol);
        }

        List<CtapCredentialRecord> applicable = FilterUnverifiedCredProtectFromDiscoverableScan(
            LocateApplicableResidentCredentials(state, request.RpId), userVerified);
        if(applicable.Count == 0)
        {
            return Reject(state, WellKnownCtapStatusCodes.NoCredentials, "GetAssertion:NoCredentials");
        }

        if(request.LargeBlobKey is bool discoverableLargeBlobKeyValue && discoverableLargeBlobKeyValue != true)
        {
            return Reject(state, WellKnownCtapStatusCodes.InvalidOption, "GetAssertion:LargeBlobKeyNotTrue");
        }

        bool largeBlobKeyRequested = request.LargeBlobKey == true;

        state = ApplyPinUvAuthTokenFlagClearingIfUserPresent(state, userPresent);

        CtapCredentialRecord mostRecent = applicable[0];
        CtapPublicKeyCredentialUserEntity responseUser = new(mostRecent.UserId);
        if(applicable.Count == 1)
        {
            return DeclareSignAssertion(
                state, mostRecent, request.ClientDataHash, userPresent, userVerified, responseUser, numberOfCredentials: null, rememberOnCompletion: null,
                largeBlobKeyRequested: largeBlobKeyRequested, hmacSecretInput: request.HmacSecret, hmacSecretProtocol: hmacSecretProtocol);
        }

        List<CredentialId> applicableCredentialIds = new(applicable.Count);
        foreach(CtapCredentialRecord candidate in applicable)
        {
            applicableCredentialIds.Add(candidate.CredentialId);
        }

        CtapRememberGetAssertionRequest rememberOnCompletion = new(
            applicableCredentialIds, userPresent, userVerified, requested.Now, authenticatingProtocol, largeBlobKeyRequested);

        return DeclareSignAssertion(
            state, mostRecent, request.ClientDataHash, userPresent, userVerified, responseUser, applicable.Count, rememberOnCompletion,
            largeBlobKeyRequested: largeBlobKeyRequested, hmacSecretInput: request.HmacSecret, hmacSecretProtocol: hmacSecretProtocol);
    }


    /// <summary>
    /// The pure half of <c>authenticatorGetNextAssertion</c> (CTAP 2.3, section 6.3): both error paths —
    /// no remembered sequence, and the sequence already exhausted — return
    /// <see cref="WellKnownCtapStatusCodes.NotAllowed"/> without disturbing the remembered state; a timer
    /// expiry (more than 30 seconds since the last stateful step) also returns
    /// <see cref="WellKnownCtapStatusCodes.NotAllowed"/> but additionally discards it, per section 6.3's
    /// own explicit "discard the current authenticatorGetAssertion state" instruction. When the sequence
    /// is token-authenticated (<see cref="CtapRememberedGetAssertionState.AuthenticatingPinUvAuthProtocol"/>
    /// is not <see langword="null"/>), that protocol's <see cref="CtapPinUvAuthTokenState.EvaluateExpiry"/>
    /// is folded into state before either timer check: a token no longer in use also discards the
    /// remembered state and returns <see cref="WellKnownCtapStatusCodes.NotAllowed"/> — CTAP 2.3, section
    /// 6, item 3 (line 2873): "An authenticator MUST discard the state for a stateful command command if
    /// the pinUvAuthToken that authenticated the state initializing command expires". Otherwise, selects
    /// <c>credentials[credentialCounter]</c>, advances the counter and the activity timestamp directly
    /// (no new pooled memory is needed for either), and declares a <see cref="CtapSignAssertionAction"/>
    /// exactly as a single-credential <c>authenticatorGetAssertion</c> would.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnGetNextAssertionRequested(
        CtapAuthenticatorState state, GetNextAssertionRequested requested)
    {
        //R7: authenticatorGetNextAssertion is "another operation" relative to a pending largeBlobs write
        //(a DIFFERENT stateful sequence, not its own), so it discards RememberedLargeBlobWrite under the
        //GLOBAL discipline exactly as every command other than a largeBlobs continuation itself does —
        //only RememberedGetAssertion, this method's OWN sequence, is preserved.
        state = DiscardRememberedLargeBlobWrite(DiscardRememberedEnumerateCredentials(DiscardRememberedEnumerateRps(state)));

        CtapRememberedGetAssertionState? remembered = state.RememberedGetAssertion;
        if(remembered is null)
        {
            return Reject(state, WellKnownCtapStatusCodes.NotAllowed, "GetNextAssertion:NoRememberedState");
        }

        if(remembered.AuthenticatingPinUvAuthProtocol is CtapPinUvAuthProtocolId authenticatingProtocol)
        {
            CtapPinUvAuthTokenState evaluatedToken = SelectPinUvAuthTokenState(state, authenticatingProtocol).EvaluateExpiry(requested.Now);
            state = WithPinUvAuthTokenState(state, authenticatingProtocol, evaluatedToken);

            if(!evaluatedToken.IsInUse)
            {
                return Reject(DiscardRememberedGetAssertion(state), WellKnownCtapStatusCodes.NotAllowed, "GetNextAssertion:AuthenticatingTokenExpired");
            }
        }

        if(requested.Now - remembered.LastActivityAt > GetNextAssertionTimerDuration)
        {
            return Reject(DiscardRememberedGetAssertion(state), WellKnownCtapStatusCodes.NotAllowed, "GetNextAssertion:TimerExpired");
        }

        if(remembered.CredentialCounter >= remembered.ApplicableCredentialIds.Count)
        {
            return Reject(state, WellKnownCtapStatusCodes.NotAllowed, "GetNextAssertion:CounterExhausted");
        }

        CredentialId nextCredentialId = remembered.ApplicableCredentialIds[remembered.CredentialCounter];
        CtapCredentialRecord credential = state.CredentialsByCredentialId[CredentialIdKey(nextCredentialId)];
        CtapPublicKeyCredentialUserEntity responseUser = new(credential.UserId);

        CtapAuthenticatorState advancedState = state with
        {
            RememberedGetAssertion = remembered with { CredentialCounter = remembered.CredentialCounter + 1, LastActivityAt = requested.Now }
        };

        return DeclareSignAssertion(
            advancedState, credential, remembered.ClientDataHash, remembered.UserPresent, remembered.UserVerified, responseUser, numberOfCredentials: null, rememberOnCompletion: null,
            largeBlobKeyRequested: remembered.LargeBlobKeyRequested);
    }


    /// <summary>
    /// The pure half of <c>authenticatorClientPIN</c> (CTAP 2.3, section 6.5.5): dispatches on
    /// <c>subCommand</c> to the three read-only subcommands (<see cref="WellKnownCtapClientPinSubCommands.GetPinRetries"/>,
    /// <see cref="WellKnownCtapClientPinSubCommands.GetKeyAgreement"/>,
    /// <see cref="WellKnownCtapClientPinSubCommands.GetUvRetries"/>), the four PIN-path subcommands
    /// (<see cref="WellKnownCtapClientPinSubCommands.SetPin"/>, <see cref="WellKnownCtapClientPinSubCommands.ChangePin"/>,
    /// <see cref="WellKnownCtapClientPinSubCommands.GetPinToken"/>,
    /// <see cref="WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingPinWithPermissions"/>), and the
    /// built-in-UV token-issuance subcommand
    /// (<see cref="WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingUvWithPermissions"/>); every
    /// other <c>subCommand</c> value is rejected with <see cref="WellKnownCtapStatusCodes.InvalidSubcommand"/>
    /// (R1 ruling: section 6.5.5's own command definition names no subcommand-not-supported status of
    /// its own — the general dispatch rule at section 8.1, line 8810, "MUST return
    /// CTAP2_ERR_INVALID_SUBCOMMAND", governs this event by default). <c>authenticatorClientPIN</c> is
    /// an intervening operation like every other command: it discards any remembered
    /// <c>authenticatorGetAssertion</c> sequence regardless of whether the subcommand itself succeeds.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnClientPinRequested(
        CtapAuthenticatorState state, ClientPinRequested requested)
    {
        state = DiscardAllRememberedSequences(state);

        CtapClientPinRequest request = requested.Request;

        return request.SubCommand switch
        {
            _ when request.SubCommand == WellKnownCtapClientPinSubCommands.GetPinRetries =>
                Respond(state, new ClientPinResponseReady(new CtapClientPinResponse(PinRetries: state.PinRetries, PowerCycleState: state.IsPowerCycleRequired)), "ClientPin:GetPinRetries"),
            _ when request.SubCommand == WellKnownCtapClientPinSubCommands.GetUvRetries =>
                Respond(state, new ClientPinResponseReady(new CtapClientPinResponse(UvRetries: state.UvRetries)), "ClientPin:GetUvRetries"),
            _ when request.SubCommand == WellKnownCtapClientPinSubCommands.GetKeyAgreement =>
                OnGetKeyAgreementRequested(state, request),
            _ when request.SubCommand == WellKnownCtapClientPinSubCommands.SetPin =>
                OnSetPinRequested(state, request),
            _ when request.SubCommand == WellKnownCtapClientPinSubCommands.ChangePin =>
                OnChangePinRequested(state, request),
            _ when request.SubCommand == WellKnownCtapClientPinSubCommands.GetPinToken =>
                OnGetPinTokenRequested(state, request, requested.Now),
            _ when request.SubCommand == WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingPinWithPermissions =>
                OnGetPinUvAuthTokenUsingPinWithPermissionsRequested(state, request, requested.Now),
            _ when request.SubCommand == WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingUvWithPermissions =>
                OnGetPinUvAuthTokenUsingUvWithPermissionsRequested(state, request, requested.Now),
            _ => Reject(state, WellKnownCtapStatusCodes.InvalidSubcommand, "ClientPin:UnsupportedSubCommand")
        };
    }


    /// <summary>
    /// The <c>getKeyAgreement</c> subcommand (CTAP 2.3, section 6.5.5.4): the mandatory-parameter check
    /// ("if the authenticator does not receive mandatory parameters for this subcommand, end the
    /// operation by returning CTAP2_ERR_MISSING_PARAMETER" — <c>pinUvAuthProtocol</c> is the mandatory
    /// parameter here, selecting which protocol's key-agreement public key to report), the
    /// protocol-support check ("if the authenticator does not support the selected pinUvAuthProtocol, it
    /// returns CTAP1_ERR_INVALID_PARAMETER"), then declaring a
    /// <see cref="CtapComputeKeyAgreementPublicKeyAction"/> against the selected protocol's key-agreement
    /// key pair, borrowed from state.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnGetKeyAgreementRequested(
        CtapAuthenticatorState state, CtapClientPinRequest request)
    {
        if(request.PinUvAuthProtocol is not int protocolValue)
        {
            return Reject(state, WellKnownCtapStatusCodes.MissingParameter, "ClientPin:GetKeyAgreementMissingProtocol");
        }

        PublicKeyMemory? ownPublicKey = (CtapPinUvAuthProtocolId)protocolValue switch
        {
            CtapPinUvAuthProtocolId.One => state.ProtocolOneKeyAgreementKeyPair.PublicKey,
            CtapPinUvAuthProtocolId.Two => state.ProtocolTwoKeyAgreementKeyPair.PublicKey,
            _ => null
        };

        if(ownPublicKey is null)
        {
            return Reject(state, WellKnownCtapStatusCodes.InvalidParameter, "ClientPin:GetKeyAgreementUnsupportedProtocol");
        }

        CtapAuthenticatorState nextState = state with
        {
            NextAction = new CtapComputeKeyAgreementPublicKeyAction((CtapPinUvAuthProtocolId)protocolValue, ownPublicKey),
            ResponseIntent = null
        };

        return Transition(nextState, "ClientPin:GetKeyAgreementRequested");
    }


    /// <summary>
    /// Completes an <c>authenticatorClientPIN</c> <c>getKeyAgreement</c> subcommand once the effectful
    /// loop has computed the selected protocol's <c>getPublicKey()</c> COSE_Key view.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnClientPinKeyAgreementComputed(
        CtapAuthenticatorState state, ClientPinKeyAgreementComputed computed)
    {
        CtapAuthenticatorState nextState = state with
        {
            NextAction = NullAction.Instance,
            ResponseIntent = new ClientPinResponseReady(new CtapClientPinResponse(KeyAgreement: computed.PublicKey))
        };

        return Transition(nextState, "ClientPin:GetKeyAgreementCompleted");
    }


    /// <summary>
    /// The pure pre-checks and effectful-action declaration for <c>setPIN</c> (CTAP 2.3 §6.5.5.5, lines
    /// 5563-5570): missing mandatory parameters (<c>pinUvAuthProtocol</c>, <c>keyAgreement</c>,
    /// <c>pinUvAuthParam</c>, <c>newPinEnc</c>) → <see cref="WellKnownCtapStatusCodes.MissingParameter"/>;
    /// an unsupported protocol → <see cref="WellKnownCtapStatusCodes.InvalidParameter"/>; the power-cycle
    /// latch (decision 7, one of "the four" PIN-auth subcommands) → <see cref="WellKnownCtapStatusCodes.PinAuthBlocked"/>;
    /// a PIN already set (line 5568) → <see cref="WellKnownCtapStatusCodes.PinAuthInvalid"/>. Once every
    /// check passes, declares a <see cref="CtapEstablishPinAction"/> and returns before the crypto
    /// sequence runs.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnSetPinRequested(
        CtapAuthenticatorState state, CtapClientPinRequest request)
    {
        if(request.PinUvAuthProtocol is null || request.KeyAgreement is null || request.PinUvAuthParam is null || request.NewPinEnc is null)
        {
            return Reject(state, WellKnownCtapStatusCodes.MissingParameter, "ClientPin:SetPinMissingParameter");
        }

        if(!IsSupportedPinUvAuthProtocol(request.PinUvAuthProtocol.Value))
        {
            return Reject(state, WellKnownCtapStatusCodes.InvalidParameter, "ClientPin:SetPinUnsupportedProtocol");
        }

        if(state.IsPowerCycleRequired)
        {
            return Reject(state, WellKnownCtapStatusCodes.PinAuthBlocked, "ClientPin:SetPinLatched");
        }

        if(state.CurrentStoredPin is not null)
        {
            return Reject(state, WellKnownCtapStatusCodes.PinAuthInvalid, "ClientPin:SetPinAlreadySet");
        }

        CtapPinUvAuthProtocolId protocolId = (CtapPinUvAuthProtocolId)request.PinUvAuthProtocol.Value;
        CtapAuthenticatorState nextState = state with
        {
            NextAction = new CtapEstablishPinAction(
                protocolId, SelectOwnPrivateKey(state, protocolId), request.KeyAgreement, request.PinUvAuthParam.Value, request.NewPinEnc.Value,
                state.MinPinCodePointLength),
            ResponseIntent = null
        };

        return Transition(nextState, "ClientPin:SetPinRequested");
    }


    /// <summary>
    /// Completes <c>setPIN</c> once the effectful loop has run its crypto sequence: maps
    /// <see cref="PinEstablishmentCompleted.Kind"/> to its status code, or — on
    /// <see cref="CtapSetPinOutcomeKind.Success"/> — stores the new PIN hash, its code-point length, and
    /// resets <c>pinRetries</c> to maximum (CTAP 2.3 §6.5.5.5, lines 5590-5593). Does NOT touch
    /// <see cref="CtapAuthenticatorState.UvRetries"/>: line 5071-5072's "each correct PIN entry" reset
    /// applies to an ALREADY-ESTABLISHED PIN being re-entered (<c>changePIN</c>/token issuance, R10) —
    /// <c>setPIN</c> is the FIRST PIN ever set, with no prior correct entry to speak of, a documented
    /// reading over the clause's own silence on initial establishment.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnPinEstablishmentCompleted(
        CtapAuthenticatorState state, PinEstablishmentCompleted completed)
    {
        byte? errorStatus = completed.Kind switch
        {
            CtapSetPinOutcomeKind.DecapsulationFailed => WellKnownCtapStatusCodes.InvalidParameter,
            CtapSetPinOutcomeKind.VerifyFailed => WellKnownCtapStatusCodes.PinAuthInvalid,
            CtapSetPinOutcomeKind.DecryptFailed => WellKnownCtapStatusCodes.PinAuthInvalid,
            CtapSetPinOutcomeKind.PaddedLengthInvalid => WellKnownCtapStatusCodes.InvalidParameter,
            CtapSetPinOutcomeKind.PolicyViolation => WellKnownCtapStatusCodes.PinPolicyViolation,
            CtapSetPinOutcomeKind.Success => null,
            _ => throw new NotSupportedException($"No setPIN outcome handling is defined for '{completed.Kind}'.")
        };

        if(errorStatus is byte status)
        {
            return Reject(state, status, "ClientPin:SetPinFailed");
        }

        CtapAuthenticatorState nextState = state with
        {
            NextAction = NullAction.Instance,
            CurrentStoredPin = completed.NewPinHash,
            PinCodePointLength = completed.NewPinCodePointLength,
            PinRetries = CtapAuthenticatorState.MaxPinRetries,
            ResponseIntent = new ClientPinResponseReady(new CtapClientPinResponse())
        };

        return Transition(nextState, "ClientPin:SetPinCompleted");
    }


    /// <summary>
    /// The pure pre-checks and effectful-action declaration for <c>changePIN</c> (CTAP 2.3 §6.5.5.6, lines
    /// 5651-5658): missing mandatory parameters (<c>pinUvAuthProtocol</c>, <c>keyAgreement</c>,
    /// <c>pinUvAuthParam</c>, <c>newPinEnc</c>, <c>pinHashEnc</c>) → <see cref="WellKnownCtapStatusCodes.MissingParameter"/>;
    /// an unsupported protocol → <see cref="WellKnownCtapStatusCodes.InvalidParameter"/>; no PIN set (the
    /// wave-5b no-PIN ruling, decision 6, grounded in §8.2's <c>PIN_NOT_SET</c> semantics and §6.5.5.7.2's
    /// <c>clientPin=true</c> mandate antecedent) → <see cref="WellKnownCtapStatusCodes.PinNotSet"/>,
    /// checked BEFORE any crypto action and never decrementing; <c>pinRetries</c> exhausted (line 5656)
    /// → <see cref="WellKnownCtapStatusCodes.PinBlocked"/>, checked before the power-cycle latch (decision
    /// 7: permanent lockout beats the recoverable one) → <see cref="WellKnownCtapStatusCodes.PinAuthBlocked"/>.
    /// Once every check passes, declares a <see cref="CtapChangePinAction"/>, threading the CURRENT
    /// <see cref="CtapAuthenticatorState.IsForcePinChangeRequired"/> value so the effectful sequence can
    /// apply line 5700's same-PIN-under-force rejection at the exact point the spec's own step order
    /// places it (after the current-PIN match, before minting fresh tokens).
    /// </summary>
    /// <remarks>
    /// This subcommand's <c>forcePINChange</c>-gated status (<see cref="WellKnownCtapStatusCodes.PinPolicyViolation"/>,
    /// line 5700) differs from <c>getPinToken</c>'s (<see cref="WellKnownCtapStatusCodes.PinInvalid"/>,
    /// line 5904) and shares its wire value with, but is a textually distinct clause from,
    /// <c>getPinUvAuthTokenUsingPinWithPermissions</c>'s own gate (line 6006) — the codes and positions
    /// are subcommand-specific, not one shared check.
    /// </remarks>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnChangePinRequested(
        CtapAuthenticatorState state, CtapClientPinRequest request)
    {
        if(request.PinUvAuthProtocol is null || request.KeyAgreement is null || request.PinUvAuthParam is null
            || request.NewPinEnc is null || request.PinHashEnc is null)
        {
            return Reject(state, WellKnownCtapStatusCodes.MissingParameter, "ClientPin:ChangePinMissingParameter");
        }

        if(!IsSupportedPinUvAuthProtocol(request.PinUvAuthProtocol.Value))
        {
            return Reject(state, WellKnownCtapStatusCodes.InvalidParameter, "ClientPin:ChangePinUnsupportedProtocol");
        }

        if(state.CurrentStoredPin is null)
        {
            return Reject(state, WellKnownCtapStatusCodes.PinNotSet, "ClientPin:ChangePinNoPinSet");
        }

        if(state.PinRetries == 0)
        {
            return Reject(state, WellKnownCtapStatusCodes.PinBlocked, "ClientPin:ChangePinBlocked");
        }

        if(state.IsPowerCycleRequired)
        {
            return Reject(state, WellKnownCtapStatusCodes.PinAuthBlocked, "ClientPin:ChangePinLatched");
        }

        CtapPinUvAuthProtocolId protocolId = (CtapPinUvAuthProtocolId)request.PinUvAuthProtocol.Value;
        CtapAuthenticatorState nextState = state with
        {
            NextAction = new CtapChangePinAction(
                protocolId, SelectOwnPrivateKey(state, protocolId), request.KeyAgreement, request.PinUvAuthParam.Value,
                request.NewPinEnc.Value, request.PinHashEnc.Value, state.CurrentStoredPin, state.MinPinCodePointLength,
                state.IsForcePinChangeRequired),
            ResponseIntent = null
        };

        return Transition(nextState, "ClientPin:ChangePinRequested");
    }


    /// <summary>
    /// Completes <c>changePIN</c> once the effectful loop has run its crypto sequence: a
    /// <see cref="CtapChangePinOutcomeKind.VerifyFailed"/> outcome rejects with NO retries decrement
    /// (line 5666's decrement point is never reached); <see cref="CtapChangePinOutcomeKind.CurrentPinDecryptFailed"/>
    /// and <see cref="CtapChangePinOutcomeKind.CurrentPinMismatch"/> both apply the identical shared
    /// mismatch counter/latch semantics (<see cref="ApplyPinMismatch"/>) — CTAP 2.3 line 5671: "If an
    /// error results, or a mismatch is detected, the authenticator performs the following operations"
    /// routes both to the same <c>regenerate()</c>/decrement/latch handling; every other outcome
    /// (<see cref="CtapChangePinOutcomeKind.NewPinDecryptFailed"/>,
    /// <see cref="CtapChangePinOutcomeKind.NewPinPaddedLengthInvalid"/>,
    /// <see cref="CtapChangePinOutcomeKind.NewPinPolicyViolation"/>, <see cref="CtapChangePinOutcomeKind.Success"/>)
    /// is reached only once the current PIN has been confirmed to match — CTAP 2.3 line 5690's
    /// <c>pinRetries := maximum</c> reset fires BEFORE the new-PIN validation steps (lines 5692-5712) run,
    /// so it applies even when the new PIN goes on to fail its own validation.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnPinChangeCompleted(
        CtapAuthenticatorState state, PinChangeCompleted completed)
    {
        if(completed.Kind == CtapChangePinOutcomeKind.DecapsulationFailed)
        {
            return Reject(state, WellKnownCtapStatusCodes.InvalidParameter, "ClientPin:ChangePinDecapsulationFailed");
        }

        if(completed.Kind == CtapChangePinOutcomeKind.VerifyFailed)
        {
            return Reject(state, WellKnownCtapStatusCodes.PinAuthInvalid, "ClientPin:ChangePinVerifyFailed");
        }

        if(completed.Kind is CtapChangePinOutcomeKind.CurrentPinDecryptFailed or CtapChangePinOutcomeKind.CurrentPinMismatch)
        {
            (CtapAuthenticatorState mismatchState, byte statusCode) = ApplyPinMismatch(state, completed.ProtocolId, completed.RegeneratedKeyPair!);
            string label = completed.Kind == CtapChangePinOutcomeKind.CurrentPinDecryptFailed
                ? "ClientPin:ChangePinCurrentPinDecryptFailed"
                : "ClientPin:ChangePinMismatch";

            return Reject(mismatchState, statusCode, label);
        }

        CtapAuthenticatorState matchedState = state with { PinRetries = CtapAuthenticatorState.MaxPinRetries, ConsecutivePinMismatches = 0 };

        return completed.Kind switch
        {
            CtapChangePinOutcomeKind.NewPinDecryptFailed =>
                Reject(matchedState, WellKnownCtapStatusCodes.PinAuthInvalid, "ClientPin:ChangePinNewPinDecryptFailed"),
            CtapChangePinOutcomeKind.NewPinPaddedLengthInvalid =>
                Reject(matchedState, WellKnownCtapStatusCodes.InvalidParameter, "ClientPin:ChangePinNewPinPaddedLengthInvalid"),
            CtapChangePinOutcomeKind.NewPinPolicyViolation =>
                Reject(matchedState, WellKnownCtapStatusCodes.PinPolicyViolation, "ClientPin:ChangePinNewPinPolicyViolation"),
            CtapChangePinOutcomeKind.NewPinSameAsCurrentUnderForce =>
                Reject(matchedState, WellKnownCtapStatusCodes.PinPolicyViolation, "ClientPin:ChangePinNewPinSameAsCurrentUnderForce"),
            CtapChangePinOutcomeKind.Success => ApplyChangePinSuccess(matchedState, completed),
            _ => throw new NotSupportedException($"No changePIN outcome handling is defined for '{completed.Kind}'.")
        };
    }


    /// <summary>
    /// Installs a successful <c>changePIN</c>'s new PIN hash and code-point length, restores
    /// <c>uvRetries</c> to its own maximum (line 5071-5072: a correct PIN entry resets BOTH counters,
    /// R10), resets every <c>pinUvAuthToken</c> (CTAP 2.3 §6.5.5.6, line 5714 —
    /// <c>resetPersistentPinUvAuthToken()</c>, line 5716, is a structurally-empty operation in this
    /// profile: no <c>persistentPinUvAuthToken</c> exists to clear), clears
    /// <see cref="CtapAuthenticatorState.IsForcePinChangeRequired"/> (line 5708: "sets the value of the
    /// forcePINChange member ... to false"), and completes with a bare CTAP2_OK — an empty CBOR map,
    /// since the shared <see cref="CtapAuthenticatorClientPinClient.ClientPinAsync"/> RP-side operation
    /// always decodes a response body.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> ApplyChangePinSuccess(
        CtapAuthenticatorState state, PinChangeCompleted completed)
    {
        state.CurrentStoredPin?.Dispose();
        state.ProtocolOneToken.Dispose();
        state.ProtocolTwoToken.Dispose();

        CtapAuthenticatorState nextState = state with
        {
            NextAction = NullAction.Instance,
            CurrentStoredPin = completed.NewPinHash,
            PinCodePointLength = completed.NewPinCodePointLength,
            UvRetries = CtapAuthenticatorState.MaxUvRetries,
            ProtocolOneToken = completed.FreshProtocolOneToken!,
            ProtocolTwoToken = completed.FreshProtocolTwoToken!,
            IsForcePinChangeRequired = false,
            ResponseIntent = new ClientPinResponseReady(new CtapClientPinResponse())
        };

        return Transition(nextState, "ClientPin:ChangePinCompleted");
    }


    /// <summary>
    /// The pure pre-checks and effectful-action declaration for <c>getPinToken</c> (CTAP 2.3 §6.5.5.7.1,
    /// lines 5860-5873): missing mandatory parameters (<c>pinUvAuthProtocol</c>, <c>keyAgreement</c>,
    /// <c>pinHashEnc</c>) → <see cref="WellKnownCtapStatusCodes.MissingParameter"/>; an unsupported
    /// protocol → <see cref="WellKnownCtapStatusCodes.InvalidParameter"/>; <c>permissions</c> present
    /// (lines 5865-5866) or <c>rpId</c> present (lines 5868-5869) → <see cref="WellKnownCtapStatusCodes.InvalidParameter"/>;
    /// no PIN set (decision 6) → <see cref="WellKnownCtapStatusCodes.PinNotSet"/>; <c>pinRetries</c>
    /// exhausted (line 5871) → <see cref="WellKnownCtapStatusCodes.PinBlocked"/>; the power-cycle latch
    /// (decision 7) → <see cref="WellKnownCtapStatusCodes.PinAuthBlocked"/>. Once every check passes,
    /// declares a <see cref="CtapIssuePinTokenAction"/> with the default <c>mc|ga</c> permissions (line
    /// 5912: <c>noMcGaPermissionsWithClientPin</c> absent under this profile's getInfo ⇒ default
    /// permissions are assigned), no permissions RP ID (lines 5830-5834: a <c>getPinToken</c>-issued
    /// token is unbound; the RP ID binds on first use), and the CURRENT
    /// <see cref="CtapAuthenticatorState.IsForcePinChangeRequired"/> value paired with
    /// <see cref="WellKnownCtapStatusCodes.PinInvalid"/> — line 5904's back-compat gate, checked by the
    /// executor strictly after the current-PIN match succeeds and <c>pinRetries</c> resets to maximum,
    /// strictly before minting a fresh token.
    /// </summary>
    /// <remarks>
    /// One of §6.5.5.7.1's steps is structurally false: the display-consent step (lines 5875-5876, "if
    /// the authenticator has a display, request user consent ... if not approved, return
    /// <c>CTAP2_ERR_OPERATION_DENIED</c>") never fires, since this simulator has no display.
    /// </remarks>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnGetPinTokenRequested(
        CtapAuthenticatorState state, CtapClientPinRequest request, DateTimeOffset now)
    {
        if(request.PinUvAuthProtocol is null || request.KeyAgreement is null || request.PinHashEnc is null)
        {
            return Reject(state, WellKnownCtapStatusCodes.MissingParameter, "ClientPin:GetPinTokenMissingParameter");
        }

        if(!IsSupportedPinUvAuthProtocol(request.PinUvAuthProtocol.Value))
        {
            return Reject(state, WellKnownCtapStatusCodes.InvalidParameter, "ClientPin:GetPinTokenUnsupportedProtocol");
        }

        if(request.Permissions is not null)
        {
            return Reject(state, WellKnownCtapStatusCodes.InvalidParameter, "ClientPin:GetPinTokenPermissionsPresent");
        }

        if(request.RpId is not null)
        {
            return Reject(state, WellKnownCtapStatusCodes.InvalidParameter, "ClientPin:GetPinTokenRpIdPresent");
        }

        if(state.CurrentStoredPin is null)
        {
            return Reject(state, WellKnownCtapStatusCodes.PinNotSet, "ClientPin:GetPinTokenNoPinSet");
        }

        if(state.PinRetries == 0)
        {
            return Reject(state, WellKnownCtapStatusCodes.PinBlocked, "ClientPin:GetPinTokenBlocked");
        }

        if(state.IsPowerCycleRequired)
        {
            return Reject(state, WellKnownCtapStatusCodes.PinAuthBlocked, "ClientPin:GetPinTokenLatched");
        }

        CtapPinUvAuthProtocolId protocolId = (CtapPinUvAuthProtocolId)request.PinUvAuthProtocol.Value;
        int defaultPermissions = WellKnownCtapPinUvAuthTokenPermissions.Mc | WellKnownCtapPinUvAuthTokenPermissions.Ga;

        CtapAuthenticatorState nextState = state with
        {
            NextAction = new CtapIssuePinTokenAction(
                protocolId, SelectOwnPrivateKey(state, protocolId), request.KeyAgreement, request.PinHashEnc.Value,
                state.CurrentStoredPin, defaultPermissions, PermissionsRpId: null, now,
                state.IsForcePinChangeRequired, WellKnownCtapStatusCodes.PinInvalid),
            ResponseIntent = null
        };

        return Transition(nextState, "ClientPin:GetPinTokenRequested");
    }


    /// <summary>
    /// The pure pre-checks and effectful-action declaration for
    /// <c>getPinUvAuthTokenUsingPinWithPermissions</c> (CTAP 2.3 §6.5.5.7.2, lines 5948-5973): missing
    /// mandatory parameters (<c>pinUvAuthProtocol</c>, <c>keyAgreement</c>, <c>pinHashEnc</c>,
    /// <c>permissions</c>) or an <c>mc</c>/<c>ga</c> permission requested without <c>rpId</c> (the
    /// conditionally-mandatory reading of line 5942 and the permission table's "RP ID Required" column)
    /// → <see cref="WellKnownCtapStatusCodes.MissingParameter"/>; an unsupported protocol →
    /// <see cref="WellKnownCtapStatusCodes.InvalidParameter"/>; <c>permissions == 0</c> (line 5953) →
    /// <see cref="WellKnownCtapStatusCodes.InvalidParameter"/>; the permission-statement gate (lines
    /// 5955-5971, <see cref="EvaluatePinUvAuthTokenPermissionGate"/>) → <see cref="WellKnownCtapStatusCodes.UnauthorizedPermission"/>;
    /// no PIN set (decision 6) → <see cref="WellKnownCtapStatusCodes.PinNotSet"/>; <c>pinRetries</c>
    /// exhausted (line 5973) → <see cref="WellKnownCtapStatusCodes.PinBlocked"/>; the power-cycle latch
    /// (decision 7) → <see cref="WellKnownCtapStatusCodes.PinAuthBlocked"/>. Once every check passes,
    /// declares a <see cref="CtapIssuePinTokenAction"/> with the requested permissions masked to this
    /// profile's grantable bits (<c>mc|ga|acfg|cm|be|lbw</c> — <c>acfg</c>/<c>cm</c> join once
    /// <c>authnrCfg</c>/<c>credMgmt</c> are advertised true, <c>be</c> joins once <c>bioEnroll</c> is
    /// advertised present (line 5960), <c>lbw</c> joins once <c>largeBlobs</c> is advertised true (line
    /// 5962, wavelb R4), undefined bits ignored, line 6022), the
    /// request's <c>rpId</c> as the permissions RP ID (line 6024) — <c>acfg</c>'s own RP ID column is
    /// "Ignored" (line 5814) and <c>cm</c>'s is "Optional" (line 5788), so neither participates in the
    /// <c>mc</c>/<c>ga</c>-only "RP ID Required" check above — and the CURRENT
    /// <see cref="CtapAuthenticatorState.IsForcePinChangeRequired"/> value paired with
    /// <see cref="WellKnownCtapStatusCodes.PinPolicyViolation"/> — line 6006's CTAP2.1-correct gate,
    /// checked by the executor at the identical position as <c>getPinToken</c>'s own (after the
    /// current-PIN match, before minting a fresh token) but with a DIFFERENT status code (line 5904's
    /// <c>PIN_INVALID</c> is <c>getPinToken</c>'s own back-compat value).
    /// </summary>
    /// <remarks>
    /// One of §6.5.5.7.2's steps is structurally false: the display-consent step (lines 5977-5978,
    /// mirroring <c>getPinToken</c>'s own — see <see cref="OnGetPinTokenRequested"/>) never fires, since
    /// this simulator has no display.
    /// </remarks>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnGetPinUvAuthTokenUsingPinWithPermissionsRequested(
        CtapAuthenticatorState state, CtapClientPinRequest request, DateTimeOffset now)
    {
        if(request.PinUvAuthProtocol is null || request.KeyAgreement is null || request.PinHashEnc is null || request.Permissions is null)
        {
            return Reject(state, WellKnownCtapStatusCodes.MissingParameter, "ClientPin:PinUvAuthTokenMissingParameter");
        }

        int requestedPermissions = request.Permissions.Value;
        int mcGaMask = WellKnownCtapPinUvAuthTokenPermissions.Mc | WellKnownCtapPinUvAuthTokenPermissions.Ga;
        if((requestedPermissions & mcGaMask) != 0 && request.RpId is null)
        {
            return Reject(state, WellKnownCtapStatusCodes.MissingParameter, "ClientPin:PinUvAuthTokenMcGaMissingRpId");
        }

        if(!IsSupportedPinUvAuthProtocol(request.PinUvAuthProtocol.Value))
        {
            return Reject(state, WellKnownCtapStatusCodes.InvalidParameter, "ClientPin:PinUvAuthTokenUnsupportedProtocol");
        }

        if(requestedPermissions == 0)
        {
            return Reject(state, WellKnownCtapStatusCodes.InvalidParameter, "ClientPin:PinUvAuthTokenPermissionsZero");
        }

        byte? gateError = EvaluatePinUvAuthTokenPermissionGate(requestedPermissions);
        if(gateError is byte gateStatus)
        {
            return Reject(state, gateStatus, "ClientPin:PinUvAuthTokenPermissionDenied");
        }

        if(state.CurrentStoredPin is null)
        {
            return Reject(state, WellKnownCtapStatusCodes.PinNotSet, "ClientPin:PinUvAuthTokenNoPinSet");
        }

        if(state.PinRetries == 0)
        {
            return Reject(state, WellKnownCtapStatusCodes.PinBlocked, "ClientPin:PinUvAuthTokenBlocked");
        }

        if(state.IsPowerCycleRequired)
        {
            return Reject(state, WellKnownCtapStatusCodes.PinAuthBlocked, "ClientPin:PinUvAuthTokenLatched");
        }

        CtapPinUvAuthProtocolId protocolId = (CtapPinUvAuthProtocolId)request.PinUvAuthProtocol.Value;
        int grantableMask = mcGaMask | WellKnownCtapPinUvAuthTokenPermissions.Acfg | WellKnownCtapPinUvAuthTokenPermissions.Cm
            | WellKnownCtapPinUvAuthTokenPermissions.Be | WellKnownCtapPinUvAuthTokenPermissions.Lbw;
        int grantedPermissions = requestedPermissions & grantableMask;

        CtapAuthenticatorState nextState = state with
        {
            NextAction = new CtapIssuePinTokenAction(
                protocolId, SelectOwnPrivateKey(state, protocolId), request.KeyAgreement, request.PinHashEnc.Value,
                state.CurrentStoredPin, grantedPermissions, request.RpId, now,
                state.IsForcePinChangeRequired, WellKnownCtapStatusCodes.PinPolicyViolation),
            ResponseIntent = null
        };

        return Transition(nextState, "ClientPin:PinUvAuthTokenRequested");
    }


    /// <summary>
    /// The pure pre-checks and effectful-action declaration for
    /// <c>getPinUvAuthTokenUsingUvWithPermissions</c> (CTAP 2.3 §6.5.5.7.3), mirroring
    /// <see cref="OnGetPinUvAuthTokenUsingPinWithPermissionsRequested"/>'s three-piece pipeline shape
    /// with <c>uvRetries</c> substituted for <c>pinRetries</c> and the pinHash decrypt/compare replaced
    /// by a simulated built-in UV gesture (R9), in the spec's own literal step order: missing mandatory
    /// parameters (<c>pinUvAuthProtocol</c>/<c>keyAgreement</c>/<c>permissions</c> — NO
    /// <c>pinHashEnc</c>, step 3.1) or an <c>mc</c>/<c>ga</c> permission requested without <c>rpId</c>
    /// (the identical conditionally-mandatory rule the PIN path applies) →
    /// <see cref="WellKnownCtapStatusCodes.MissingParameter"/>; an unsupported protocol (step 3.2) →
    /// <see cref="WellKnownCtapStatusCodes.InvalidParameter"/>; <c>permissions == 0</c> (step 3.3) →
    /// <see cref="WellKnownCtapStatusCodes.InvalidParameter"/>; 0x06's OWN permission-statement gate
    /// (step 3.4, <see cref="EvaluateUvTokenPermissionGate"/> — a SEPARATE statement list from the PIN
    /// path's, R5) → <see cref="WellKnownCtapStatusCodes.UnauthorizedPermission"/>; zero fingerprint
    /// enrollments (step 3.5: "built-in user verification method is supported but not configured") →
    /// <see cref="WellKnownCtapStatusCodes.NotAllowed"/> (DISTINCT from mc/ga's
    /// <see cref="WellKnownCtapStatusCodes.InvalidOption"/> for the identical underlying state, uv scout
    /// trap 7); <c>internalRetry</c> COMPUTED from <see cref="CtapAuthenticatorState.PreferredPlatformUvAttempts"/>
    /// (step 3.6 — <see langword="false"/> here, since this profile's constant is 3; NEVER the mc/ga-shared
    /// hardcoded-true value, uv scout trap 2); <c>uvRetries == 0</c> (step 3.7) →
    /// <see cref="WellKnownCtapStatusCodes.UvBlocked"/>; step 3.8's display-consent request is a
    /// documented no-op (no display is modeled); <c>performBuiltInUv</c>'s OWN step 3
    /// (<see cref="ShouldDragDownUvRetriesOnPinLockout"/>, evaluated here since step 3.9 calls it
    /// directly) → <see cref="WellKnownCtapStatusCodes.UvBlocked"/> with <c>uvRetries</c> dragged to
    /// zero (R10's REQUIRED cross-counter test). Once every check passes, masks the requested permissions
    /// to this subcommand's own grantable set (<c>mc|ga|cm|be|lbw</c> — NOT <c>acfg</c>, R5; <c>lbw</c>
    /// joins per wavelb R4, the identical line-6070 bullet) and declares a
    /// <see cref="CtapIssueUvTokenAction"/>.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnGetPinUvAuthTokenUsingUvWithPermissionsRequested(
        CtapAuthenticatorState state, CtapClientPinRequest request, DateTimeOffset now)
    {
        if(request.PinUvAuthProtocol is null || request.KeyAgreement is null || request.Permissions is null)
        {
            return Reject(state, WellKnownCtapStatusCodes.MissingParameter, "ClientPin:UvTokenMissingParameter");
        }

        int requestedPermissions = request.Permissions.Value;
        int mcGaMask = WellKnownCtapPinUvAuthTokenPermissions.Mc | WellKnownCtapPinUvAuthTokenPermissions.Ga;
        if((requestedPermissions & mcGaMask) != 0 && request.RpId is null)
        {
            return Reject(state, WellKnownCtapStatusCodes.MissingParameter, "ClientPin:UvTokenMcGaMissingRpId");
        }

        if(!IsSupportedPinUvAuthProtocol(request.PinUvAuthProtocol.Value))
        {
            return Reject(state, WellKnownCtapStatusCodes.InvalidParameter, "ClientPin:UvTokenUnsupportedProtocol");
        }

        if(requestedPermissions == 0)
        {
            return Reject(state, WellKnownCtapStatusCodes.InvalidParameter, "ClientPin:UvTokenPermissionsZero");
        }

        byte? gateError = EvaluateUvTokenPermissionGate(requestedPermissions);
        if(gateError is byte gateStatus)
        {
            return Reject(state, gateStatus, "ClientPin:UvTokenPermissionDenied");
        }

        if(!state.HasProvisionedBioEnrollments)
        {
            return Reject(state, WellKnownCtapStatusCodes.NotAllowed, "ClientPin:UvTokenNotConfigured");
        }

        //Step 3.6 (lines 6080-6082): computed from preferredPlatformUvAttempts, never shared with mc/ga's
        //own hardcoded-true value (uv scout trap 2).
        bool internalRetry = CtapAuthenticatorState.PreferredPlatformUvAttempts <= 1;

        if(state.UvRetries == 0)
        {
            return Reject(state, WellKnownCtapStatusCodes.UvBlocked, "ClientPin:UvTokenBlocked");
        }

        if(ShouldDragDownUvRetriesOnPinLockout(state))
        {
            return Reject(state with { UvRetries = 0 }, WellKnownCtapStatusCodes.UvBlocked, "ClientPin:UvTokenPinLockoutDragDown");
        }

        int grantableMask = mcGaMask | WellKnownCtapPinUvAuthTokenPermissions.Cm | WellKnownCtapPinUvAuthTokenPermissions.Be
            | WellKnownCtapPinUvAuthTokenPermissions.Lbw;
        int grantedPermissions = requestedPermissions & grantableMask;

        CtapPinUvAuthProtocolId protocolId = (CtapPinUvAuthProtocolId)request.PinUvAuthProtocol.Value;
        CtapAuthenticatorState nextState = state with
        {
            NextAction = new CtapIssueUvTokenAction(
                protocolId, SelectOwnPrivateKey(state, protocolId), request.KeyAgreement, grantedPermissions, request.RpId, now,
                internalRetry, state.UvRetries),
            ResponseIntent = null
        };

        return Transition(nextState, "ClientPin:UvTokenRequested");
    }


    /// <summary>
    /// Evaluates <c>getPinUvAuthTokenUsingUvWithPermissions</c>'s OWN permission-statement gate (CTAP 2.3
    /// §6.5.5.7.3, lines 6063-6075) — a SEPARATE statement list from
    /// <see cref="EvaluatePinUvAuthTokenPermissionGate"/>'s (R5, never conflated, uv scout trap 4): "The
    /// mc and ga permissions are always considered authorized, thus they are not listed below" (line
    /// 6063) — under this profile's <c>authenticatorGetInfo</c> (<c>credMgmt</c>/<c>uvBioEnroll</c>/
    /// <c>largeBlobs</c> always advertised <see langword="true"/>, <c>uvAcfg</c> permanently absent, no
    /// <c>perCredMgmtRO</c>), <c>cm</c>'s statement ("credMgmt is false or absent") and <c>be</c>'s
    /// ("uvBioEnroll is false or absent") never hold, and <c>lbw</c>'s ("largeBlobs is false or absent",
    /// line 6070 — VERBATIM IDENTICAL to the PIN path's own line 5962 bullet, wavelb R4) never holds
    /// either — no <c>uvLargeBlobs</c> analogue exists, so this single getInfo flip grants <c>lbw</c> on
    /// BOTH token paths at once — while <c>acfg</c>'s denial bullet has no antecedent
    /// to fail — <c>uvAcfg</c> is simply absent, so <c>acfg</c> is unconditionally denied — and
    /// <c>pcmr</c> is unconditionally denied identically to the PIN path's own gate.
    /// Undefined bits are not examined here: the caller masks them out separately.
    /// </summary>
    /// <returns><see cref="WellKnownCtapStatusCodes.UnauthorizedPermission"/> if any denied bit is present; otherwise <see langword="null"/>.</returns>
    private static byte? EvaluateUvTokenPermissionGate(int requestedPermissions)
    {
        int deniedBits = WellKnownCtapPinUvAuthTokenPermissions.Acfg
            | WellKnownCtapPinUvAuthTokenPermissions.Pcmr;

        return (requestedPermissions & deniedBits) != 0 ? WellKnownCtapStatusCodes.UnauthorizedPermission : null;
    }


    /// <summary>
    /// <c>performBuiltInUv</c>'s OWN step 3 (CTAP 2.3 §6.5.3.1, line 5108): "If clientPIN is true and
    /// pinRetries is 0, then let the uvRetries counter be set to 0 and return error." A cross-counter
    /// effect — the ONE place <c>performBuiltInUv</c> itself reads <c>pinRetries</c>/<c>clientPin</c>
    /// (R10) — evaluated purely, without ever declaring an attempt action or consulting
    /// <see cref="SimulateBuiltInUvDelegate"/>, by every <c>performBuiltInUv</c> call site (0x06, mc, ga)
    /// immediately before it would otherwise declare one.
    /// </summary>
    private static bool ShouldDragDownUvRetriesOnPinLockout(CtapAuthenticatorState state) =>
        state.CurrentStoredPin is not null && state.PinRetries == 0;


    /// <summary>
    /// Completes <c>getPinUvAuthTokenUsingUvWithPermissions</c> once the effectful loop has run its
    /// attempt loop (and, on success, its token-mint tail): <see cref="CtapUvTokenIssuanceOutcomeKind.DecapsulationFailed"/>
    /// rejects with no counter change (the loop never ran); <see cref="CtapUvTokenIssuanceOutcomeKind.UserActionTimeout"/>
    /// and <see cref="CtapUvTokenIssuanceOutcomeKind.MatchFailure"/> both decrement
    /// <see cref="CtapAuthenticatorState.UvRetries"/> by <see cref="UvTokenIssuanceCompleted.AttemptsConsumed"/>
    /// before resolving their own status (§6.5.5.7.3 step 10: timeout →
    /// <see cref="WellKnownCtapStatusCodes.UserActionTimeout"/>; otherwise <c>uvRetries == 0</c> →
    /// <see cref="WellKnownCtapStatusCodes.UvBlocked"/>, else → <see cref="WellKnownCtapStatusCodes.UvInvalid"/>);
    /// <see cref="CtapUvTokenIssuanceOutcomeKind.Success"/> resets <see cref="CtapAuthenticatorState.UvRetries"/>
    /// to <see cref="CtapAuthenticatorState.MaxUvRetries"/> (step 9), resets every <c>pinUvAuthToken</c>
    /// for BOTH protocols (step 12, already performed by the executor — this fold-back only installs the
    /// two fresh states), and returns the encrypted token (step 17).
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnUvTokenIssuanceCompleted(
        CtapAuthenticatorState state, UvTokenIssuanceCompleted completed)
    {
        if(completed.Kind == CtapUvTokenIssuanceOutcomeKind.DecapsulationFailed)
        {
            return Reject(state, WellKnownCtapStatusCodes.InvalidParameter, "ClientPin:UvTokenIssuanceDecapsulationFailed");
        }

        if(completed.Kind == CtapUvTokenIssuanceOutcomeKind.Success)
        {
            state.ProtocolOneToken.Dispose();
            state.ProtocolTwoToken.Dispose();

            CtapAuthenticatorState successState = state with
            {
                NextAction = NullAction.Instance,
                UvRetries = CtapAuthenticatorState.MaxUvRetries,
                ProtocolOneToken = completed.FreshProtocolOneToken!,
                ProtocolTwoToken = completed.FreshProtocolTwoToken!,
                ResponseIntent = new ClientPinResponseReady(new CtapClientPinResponse(PinUvAuthToken: completed.EncryptedToken))
            };

            return Transition(successState, "ClientPin:UvTokenIssuanceCompleted");
        }

        int decrementedUvRetries = Math.Max(state.UvRetries - completed.AttemptsConsumed, 0);
        CtapAuthenticatorState decrementedState = state with { UvRetries = decrementedUvRetries };

        byte status = completed.Kind == CtapUvTokenIssuanceOutcomeKind.UserActionTimeout
            ? WellKnownCtapStatusCodes.UserActionTimeout
            : decrementedUvRetries == 0
                ? WellKnownCtapStatusCodes.UvBlocked
                : WellKnownCtapStatusCodes.UvInvalid;

        return Reject(decrementedState, status, "ClientPin:UvTokenIssuanceFailed");
    }


    /// <summary>
    /// Completes <c>authenticatorMakeCredential</c>/<c>authenticatorGetAssertion</c>'s own
    /// <c>options.uv = true</c> built-in-UV fallback (CTAP 2.3 §6.1.2 step 11.2.3-11.2.4 / §6.2.2 step
    /// 6.2.3-6.2.4) once the effectful loop has run <c>performBuiltInUv</c>'s attempt loop:
    /// <see cref="CtapBuiltInUvAttemptOutcome.Success"/> resets <see cref="CtapAuthenticatorState.UvRetries"/>
    /// to <see cref="CtapAuthenticatorState.MaxUvRetries"/> and resumes the interrupted command with the
    /// <c>uv</c> bit true; every other outcome decrements <see cref="CtapAuthenticatorState.UvRetries"/>
    /// by <see cref="BuiltInUvAttempted.AttemptsConsumed"/> and resolves the mc/ga-specific ladder: a
    /// timeout → <see cref="WellKnownCtapStatusCodes.UserActionTimeout"/>; otherwise, since
    /// <c>clientPin</c> is set whenever this branch is reachable in this profile (the only route to a
    /// first fingerprint enrollment is the PIN-path <c>be</c> token, uv scout reachability note) →
    /// <see cref="WellKnownCtapStatusCodes.PuatRequired"/> (mc line 3428/ga line 4013's own
    /// <c>noMcGaPermissionsWithClientPin</c> conjunct is vacuously satisfied — this option is never
    /// modeled/advertised in this profile). The ladder's remaining two arms —
    /// <c>uvRetries == 0</c> → <see cref="WellKnownCtapStatusCodes.PinBlocked"/>, else →
    /// <see cref="WellKnownCtapStatusCodes.OperationDenied"/> — are coded spec-exact (mc line 3428/3430,
    /// ga line 4013/4023) but are DOCUMENTED UNREACHABLE in this profile for the same reason (R11): do
    /// not assert either fires.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnBuiltInUvAttempted(
        CtapAuthenticatorState state, BuiltInUvAttempted attempted)
    {
        int finalUvRetries = attempted.Outcome == CtapBuiltInUvAttemptOutcome.Success
            ? CtapAuthenticatorState.MaxUvRetries
            : Math.Max(state.UvRetries - attempted.AttemptsConsumed, 0);
        CtapAuthenticatorState nextState = state with { UvRetries = finalUvRetries };

        if(attempted.Outcome == CtapBuiltInUvAttemptOutcome.Success)
        {
            return attempted.Continuation switch
            {
                CtapMakeCredentialBuiltInUvContinuation mc =>
                    ContinueMakeCredential(nextState, mc.Requested, mc.Requested.Request, userVerified: true, userPresent: true, mc.EnterpriseAttestationGranted),
                CtapGetAssertionBuiltInUvContinuation ga =>
                    ContinueGetAssertion(nextState, ga.Requested, ga.Requested.Request, userVerified: true, ga.UserPresent, authenticatingProtocol: null),
                _ => throw new NotSupportedException($"No built-in-UV continuation is defined for '{attempted.Continuation.GetType().Name}'.")
            };
        }

        if(attempted.Outcome == CtapBuiltInUvAttemptOutcome.UserActionTimeout)
        {
            return Reject(nextState, WellKnownCtapStatusCodes.UserActionTimeout, "BuiltInUv:UserActionTimeout");
        }

        //MatchFailure: clientPin is set whenever this branch is reachable in this profile (a first
        //enrollment always requires a prior PIN-path be token), so PuatRequired is the sole reachable
        //arm — the PinBlocked/OperationDenied ladder arms below are documented unreachable (R11).
        bool isClientPinSet = nextState.CurrentStoredPin is not null;
        byte status = isClientPinSet
            ? WellKnownCtapStatusCodes.PuatRequired
            : finalUvRetries == 0
                ? WellKnownCtapStatusCodes.PinBlocked
                : WellKnownCtapStatusCodes.OperationDenied;

        return Reject(nextState, status, "BuiltInUv:MatchFailure");
    }


    /// <summary>
    /// Completes <c>getPinToken</c>/<c>getPinUvAuthTokenUsingPinWithPermissions</c> once the effectful
    /// loop has run their shared crypto sequence: <see cref="CtapPinTokenIssuanceOutcomeKind.CurrentPinDecryptFailed"/>
    /// and <see cref="CtapPinTokenIssuanceOutcomeKind.CurrentPinMismatch"/> both apply the identical
    /// shared mismatch counter/latch semantics (<see cref="ApplyPinMismatch"/>) — CTAP 2.3 §6.5.5.7.1
    /// line 5883/§6.5.5.7.2 line 5985: "If an error results, or a mismatch is detected, the authenticator
    /// performs the following operations" routes both to the same <c>regenerate()</c>/decrement/latch
    /// handling; a <see cref="CtapPinTokenIssuanceOutcomeKind.ForcePinChangeRequired"/> outcome rejects
    /// with <see cref="PinTokenIssuanceCompleted.ForcePinChangeDeniedStatusCode"/> AFTER still applying
    /// the "pinRetries := maximum" reset (line 5895/5997, which the spec's own step order places BEFORE
    /// the forcePINChange check), issuing no token; a <see cref="CtapPinTokenIssuanceOutcomeKind.Success"/>
    /// outcome installs the two freshly reset token states (the selected protocol's already begun-using
    /// and permissioned, CTAP 2.3 lines 5908-5915/6018-6026), resets <c>pinRetries</c> to maximum, ALSO
    /// resets <c>uvRetries</c> to its own maximum (line 5071-5072: "Each correct PIN entry resets the
    /// pinRetries and the uvRetries counters back to their maximum values" — R10), and returns the
    /// encrypted token.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnPinTokenIssuanceCompleted(
        CtapAuthenticatorState state, PinTokenIssuanceCompleted completed)
    {
        if(completed.Kind == CtapPinTokenIssuanceOutcomeKind.DecapsulationFailed)
        {
            return Reject(state, WellKnownCtapStatusCodes.InvalidParameter, "ClientPin:PinTokenIssuanceDecapsulationFailed");
        }

        if(completed.Kind is CtapPinTokenIssuanceOutcomeKind.CurrentPinDecryptFailed or CtapPinTokenIssuanceOutcomeKind.CurrentPinMismatch)
        {
            (CtapAuthenticatorState mismatchState, byte statusCode) = ApplyPinMismatch(state, completed.ProtocolId, completed.RegeneratedKeyPair!);
            string label = completed.Kind == CtapPinTokenIssuanceOutcomeKind.CurrentPinDecryptFailed
                ? "ClientPin:PinTokenIssuanceCurrentPinDecryptFailed"
                : "ClientPin:PinTokenIssuanceMismatch";

            return Reject(mismatchState, statusCode, label);
        }

        if(completed.Kind == CtapPinTokenIssuanceOutcomeKind.ForcePinChangeRequired)
        {
            CtapAuthenticatorState forcedState = state with { PinRetries = CtapAuthenticatorState.MaxPinRetries, ConsecutivePinMismatches = 0 };

            return Reject(forcedState, completed.ForcePinChangeDeniedStatusCode!.Value, "ClientPin:PinTokenIssuanceForcePinChangeRequired");
        }

        state.ProtocolOneToken.Dispose();
        state.ProtocolTwoToken.Dispose();

        CtapAuthenticatorState nextState = state with
        {
            NextAction = NullAction.Instance,
            PinRetries = CtapAuthenticatorState.MaxPinRetries,
            UvRetries = CtapAuthenticatorState.MaxUvRetries,
            ConsecutivePinMismatches = 0,
            ProtocolOneToken = completed.FreshProtocolOneToken!,
            ProtocolTwoToken = completed.FreshProtocolTwoToken!,
            ResponseIntent = new ClientPinResponseReady(new CtapClientPinResponse(PinUvAuthToken: completed.EncryptedToken))
        };

        return Transition(nextState, "ClientPin:PinTokenIssuanceCompleted");
    }


    /// <summary>
    /// The pure request-arm of <c>authenticatorConfig</c> (CTAP 2.3, section 6.11), in the spec's own
    /// literal step order: step 1 (<c>subCommand</c> absent) is enforced at the decode boundary (see
    /// <see cref="CtapAuthenticatorSimulator.TransceiveAsync"/>'s <c>authenticatorConfig</c> dispatch
    /// branch, which maps a decode failure to <see cref="WellKnownCtapStatusCodes.MissingParameter"/>
    /// before this input is ever built — mirroring how <see cref="CtapClientPinRequest.SubCommand"/>'s
    /// own required-field decode throws); step 2 (unsupported subcommand) →
    /// <see cref="WellKnownCtapStatusCodes.InvalidSubcommand"/> (R1: line 8810's general dispatch MUST
    /// governs over line 7955's bare-pseudocode <c>InvalidParameter</c>, both anchors cited on
    /// <see cref="WellKnownCtapStatusCodes.InvalidSubcommand"/> itself) — waveep R12 adds a CAPABILITY-GATED
    /// third disjunct: <c>enableEnterpriseAttestation</c> is supported exactly when
    /// <see cref="CtapAuthenticatorState.IsEnterpriseAttestationCapable"/>, so a non-capable authenticator's
    /// <c>0x01</c> keeps rejecting via this same step (falsification #8); step 3 (the <c>toggleAlwaysUv</c>
    /// bypass, the EXACT three-way conjunction: <c>subCommand==toggleAlwaysUv &amp;&amp; !protected &amp;&amp;
    /// alwaysUv</c>) skips step 4 entirely; step 4 (the shared token gate, firing when
    /// <c>protected || alwaysUv</c>) declares a <see cref="CtapVerifyAuthenticatorConfigTokenAction"/>
    /// that interrupts this request to run its own verify+permission check; the final clause (neither
    /// protected nor <c>alwaysUv</c>) invokes the subcommand directly, ignoring any presented
    /// <c>pinUvAuthParam</c> as junk (line 7992's own "can be invoked without user verification"
    /// wording). <c>authenticatorConfig</c> is an intervening operation that discards any remembered
    /// <c>authenticatorGetAssertion</c> sequence regardless of whether this command itself succeeds.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <strong>Step 3's bypass is NOT "if alwaysUv, skip the gate for toggleAlwaysUv".</strong> Its
    /// second conjunct — the authenticator must NOT already be protected by some form of user
    /// verification — is load-bearing (trap 2): once a PIN is set, <c>toggleAlwaysUv</c> falls through
    /// to the ordinary step-4 gate exactly like every other subcommand, even with <c>alwaysUv</c>
    /// already true. The bypass exists solely so a factory-default-<c>alwaysUv</c>-enabled device with
    /// NO PIN yet can be turned off (or otherwise configured) once, tokenless.
    /// </para>
    /// <para>
    /// <strong>Step 4.5's <c>acfg</c> permission check has no RP-ID component at all</strong> (trap 6):
    /// <c>acfg</c>'s own RP ID column is "Ignored" (line 5814) and this command's own input parameters
    /// have no <c>rpId</c> field (§1.1's table). A token bound to any <c>rpId</c> by an earlier mc/ga
    /// call still passes this gate. <strong>No flag or permission clearing happens on success</strong>
    /// (trap 3): <c>authenticatorConfig</c> is not "an operation that tests user presence" in the
    /// line-5828 sense — no <c>clearUserPresentFlag</c>/<c>clearUserVerifiedFlag</c>/
    /// <c>clearPinUvAuthTokenPermissionsExceptLbw</c> reference exists anywhere in §6.11's text — so a
    /// token used to complete <c>authenticatorConfig</c> retains every other permission afterward,
    /// provably by a subsequent mc/ga call succeeding with the SAME token.
    /// </para>
    /// <para>
    /// <strong>R2 — <c>OperationDenied</c> never fires here</strong>, for the identical reason mc/ga's
    /// own "clientPin not supported" splits never resolve to it: <c>clientPin</c> is always present in
    /// this profile, so the not-protected branch's clientPin-present half (→ <c>PuatRequired</c>) is the
    /// only reachable outcome.
    /// </para>
    /// </remarks>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnAuthenticatorConfigRequested(
        CtapAuthenticatorState state, AuthenticatorConfigRequested requested)
    {
        state = DiscardAllRememberedSequences(state);

        CtapAuthenticatorConfigRequest request = requested.Request;

        //Step 2 (line 7955 / R1's 0x3E, line 8810): this authenticator supports toggleAlwaysUv and
        //setMinPINLength unconditionally (R3), and enableEnterpriseAttestation exactly when the
        //authenticator is enterprise attestation capable (waveep R12, R2's single-sourced predicate) —
        //every other value, including out-of-table integers, is unsupported.
        bool isSupportedSubCommand = WellKnownCtapAuthenticatorConfigSubCommands.IsToggleAlwaysUv(request.SubCommand)
            || WellKnownCtapAuthenticatorConfigSubCommands.IsSetMinPinLength(request.SubCommand)
            || (WellKnownCtapAuthenticatorConfigSubCommands.IsEnableEnterpriseAttestation(request.SubCommand) && state.IsEnterpriseAttestationCapable);
        if(!isSupportedSubCommand)
        {
            return Reject(state, WellKnownCtapStatusCodes.InvalidSubcommand, "AuthenticatorConfig:UnsupportedSubCommand");
        }

        bool isProtectedByUserVerification = IsProtectedByUserVerification(state);

        //Step 3 (lines 7957-7967): the exact three-way conjunction — trap 2.
        bool bypassesTokenGate = WellKnownCtapAuthenticatorConfigSubCommands.IsToggleAlwaysUv(request.SubCommand)
            && !isProtectedByUserVerification
            && state.IsAlwaysUvEnabled;

        //Step 4 (lines 7968-7985): fires whenever protected-by-UV OR alwaysUv is true, unless step 3's
        //bypass already applies.
        bool tokenGateApplies = !bypassesTokenGate && (isProtectedByUserVerification || state.IsAlwaysUvEnabled);

        if(!tokenGateApplies)
        {
            //Line 7992: neither protected nor alwaysUv — invoke the subcommand directly, any presented
            //pinUvAuthParam (junk or otherwise) is ignored.
            return InvokeAuthenticatorConfigSubCommand(state, request);
        }

        if(request.PinUvAuthParam is not ReadOnlyMemory<byte> pinUvAuthParam)
        {
            return Reject(state, WellKnownCtapStatusCodes.PuatRequired, "AuthenticatorConfig:PuatRequired");
        }

        if(request.PinUvAuthProtocol is not int protocolValue)
        {
            return Reject(state, WellKnownCtapStatusCodes.MissingParameter, "AuthenticatorConfig:MissingProtocol");
        }

        if(!IsSupportedPinUvAuthProtocol(protocolValue))
        {
            return Reject(state, WellKnownCtapStatusCodes.InvalidParameter, "AuthenticatorConfig:UnsupportedProtocol");
        }

        CtapPinUvAuthProtocolId protocolId = (CtapPinUvAuthProtocolId)protocolValue;
        CtapPinUvAuthTokenState presentedToken = SelectPinUvAuthTokenState(state, protocolId).EvaluateExpiry(requested.Now);
        state = WithPinUvAuthTokenState(state, protocolId, presentedToken);

        CtapAuthenticatorState nextState = state with
        {
            NextAction = new CtapVerifyAuthenticatorConfigTokenAction(
                protocolId, presentedToken, request.SubCommand, request.SubCommandParams ?? ReadOnlyMemory<byte>.Empty, pinUvAuthParam,
                new CtapAuthenticatorConfigVerifyContinuation(requested)),
            ResponseIntent = null
        };

        return Transition(nextState, "AuthenticatorConfig:VerifyPinUvAuthToken");
    }


    /// <summary>
    /// Completes an <c>authenticatorConfig</c> whose presented <c>pinUvAuthParam</c> has been verified
    /// (CTAP 2.3 §6.11 step 4.4-4.5, lines 7978-7985): verify (already run by the executor) →
    /// <c>acfg</c> permission → invoke the subcommand. NO RP-ID check (trap 6, <c>acfg</c>'s own RP ID
    /// column is "Ignored"), NO flag/permission stripping (trap 3, <c>authenticatorConfig</c> is not "an
    /// operation that tests user presence"). <see cref="CtapPinUvAuthTokenState.LastUsedAt"/> is stamped
    /// on success, mirroring mc/ga's own verified-token bookkeeping — the token remains fully usable for
    /// mc/ga afterward, unlike them the config permission is never cleared here either way.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnAuthenticatorConfigPinUvAuthTokenVerified(
        CtapAuthenticatorState state, bool verified, AuthenticatorConfigRequested requested)
    {
        if(!verified)
        {
            return Reject(state, WellKnownCtapStatusCodes.PinAuthInvalid, "AuthenticatorConfig:VerifyFailed");
        }

        CtapAuthenticatorConfigRequest request = requested.Request;
        CtapPinUvAuthProtocolId protocolId = (CtapPinUvAuthProtocolId)request.PinUvAuthProtocol!.Value;
        CtapPinUvAuthTokenState token = SelectPinUvAuthTokenState(state, protocolId);

        if((token.Permissions & WellKnownCtapPinUvAuthTokenPermissions.Acfg) == 0)
        {
            return Reject(state, WellKnownCtapStatusCodes.PinAuthInvalid, "AuthenticatorConfig:AcfgPermissionDenied");
        }

        token = token with { LastUsedAt = requested.Now };
        state = WithPinUvAuthTokenState(state, protocolId, token);

        return InvokeAuthenticatorConfigSubCommand(state, request);
    }


    /// <summary>
    /// Dispatches to the requested subcommand's own handler (CTAP 2.3 §6.11 step 5, line 7986: "Invoke
    /// subCommand ... passing it the subCommandParams map"). The <c>_ =&gt;</c> arm is unreachable —
    /// <see cref="OnAuthenticatorConfigRequested"/>'s own step 2 already rejected every value besides
    /// <see cref="WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv"/>/
    /// <see cref="WellKnownCtapAuthenticatorConfigSubCommands.SetMinPinLength"/>/(a capability-gated)
    /// <see cref="WellKnownCtapAuthenticatorConfigSubCommands.EnableEnterpriseAttestation"/> before either
    /// fold-back path (the direct invoke or the post-verify continuation) could ever reach here.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> InvokeAuthenticatorConfigSubCommand(
        CtapAuthenticatorState state, CtapAuthenticatorConfigRequest request) =>
        request.SubCommand switch
        {
            _ when WellKnownCtapAuthenticatorConfigSubCommands.IsToggleAlwaysUv(request.SubCommand) => OnToggleAlwaysUvRequested(state),
            _ when WellKnownCtapAuthenticatorConfigSubCommands.IsSetMinPinLength(request.SubCommand) => OnSetMinPinLengthRequested(state, request),
            _ when WellKnownCtapAuthenticatorConfigSubCommands.IsEnableEnterpriseAttestation(request.SubCommand) => OnEnableEnterpriseAttestationRequested(state),
            _ => throw new NotSupportedException($"authenticatorConfig subCommand '{request.SubCommand}' reached subcommand dispatch unsupported.")
        };


    /// <summary>
    /// <c>toggleAlwaysUv</c> (CTAP 2.3 §6.11.2, lines 8008-8032): a plain if/else on the current
    /// <c>alwaysUv</c> feature state. Disabled → enable (step 1.2, line 8015); enabled → disabling is
    /// supported in this profile (the line-8032 SHOULD is followed, not merely permitted) → disable
    /// (step 2.1.2, line 8027). <c>makeCredUvNotRqd</c>'s own forced-false-on-enable (step 1.1, line
    /// 8013)/restored-default-on-disable (step 2.1.1, line 8025) needs no code here at all: R8's getInfo
    /// derivation (<c>MakeCredUvNotRqd: !isAlwaysUvEnabled</c>) already implements both directions as a
    /// pure function of <see cref="CtapAuthenticatorState.IsAlwaysUvEnabled"/>. Step 2.2's
    /// <c>OperationDenied</c> (line 8030, "disabling is unsupported") is documented-unreachable — this
    /// authenticator always supports disabling.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnToggleAlwaysUvRequested(CtapAuthenticatorState state)
    {
        CtapAuthenticatorState nextState = state with { IsAlwaysUvEnabled = !state.IsAlwaysUvEnabled };

        return Respond(nextState, new AuthenticatorConfigResponseReady(), "AuthenticatorConfig:ToggleAlwaysUv");
    }


    /// <summary>
    /// <c>enableEnterpriseAttestation</c> (CTAP 2.3 §6.11.1, lines 7999-8002): idempotent-enable, NOT a
    /// toggle (trap 7/waveep R12) — disabled → re-enable and <c>CTAP2_OK</c> (line 7999); already-enabled
    /// → no-op and <c>CTAP2_OK</c> (line 8002) — both collapse to the SAME unconditional
    /// <see langword="true"/> assignment, since re-setting an already-<see langword="true"/> flag to
    /// <see langword="true"/> is itself a no-op. Reachable only when
    /// <see cref="CtapAuthenticatorState.IsEnterpriseAttestationCapable"/> (guaranteed by
    /// <see cref="OnAuthenticatorConfigRequested"/>'s own step-2 gate before dispatch ever reaches here),
    /// so no capability re-check is needed in this handler's own body. <c>request.SubCommandParams</c> is
    /// deliberately never read (line 7994: "this subcommand does not take any parameters:
    /// subCommandParams is ignored" — trap 1); line 8000's own note is the observable proof: the very
    /// next <c>authenticatorGetInfo</c> reports <c>ep:true</c>.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnEnableEnterpriseAttestationRequested(CtapAuthenticatorState state)
    {
        CtapAuthenticatorState nextState = state with { IsEnterpriseAttestationEnabled = true };

        return Respond(nextState, new AuthenticatorConfigResponseReady(), "AuthenticatorConfig:EnableEnterpriseAttestation");
    }


    /// <summary>
    /// <c>setMinPINLength</c> (CTAP 2.3 §6.11.4, lines 8131-8192), the full nine-step behavioral matrix
    /// in literal order: step 1 (line 8134) defaults an absent <c>newMinPINLength</c> to the current
    /// minimum; step 2 (lines 8105/8136, R7 LIVE) imposes no rejection — see this method's own remarks;
    /// step 3 (lines 8138-8141) rejects a DECREASE (equal is a no-op success — "minimum PIN lengths may
    /// only be increased"); step 4 (lines 8143-8149) <c>forceChangePin:true</c> with no PIN set →
    /// <see cref="WellKnownCtapStatusCodes.PinNotSet"/>, else unconditionally forces a change; step 5
    /// (lines 8152-8166, R3) decodes but IGNORES <c>pinComplexityPolicy</c> — this profile's getInfo
    /// <c>pinComplexityPolicy</c> member is absent, so it is never configurable via this subcommand (the
    /// line-8442 MUST); step 6 (line 8169, TRAP 12) forces a change ONLY when the stored PIN is now too
    /// short for the just-raised minimum — raising the minimum to at or below an already-compliant PIN's
    /// own length does NOT force a change on its own; the <c>minPinLengthRPIDs</c> bound check/store
    /// (step 8, lines 8179-8190, R7 LIVE — evaluated here, ahead of step 7's own effectful fork, since its
    /// rejection is independent of step 7's entropy-consuming token reset) folds its resulting list into
    /// the same state update step 1/3/4/6 already assemble; step 7 (lines 8171-8177) resets every
    /// <c>pinUvAuthToken</c> (both protocols) whenever the CURRENT <c>forcePINChange</c> value (from step
    /// 4 or step 6, or already true from an earlier call) is true, via
    /// <see cref="CtapResetPinUvAuthTokensAction"/> (entropy-consuming, routed through the effectful
    /// loop); step 9 (line 8192) returns <c>CTAP2_OK</c>.
    /// </summary>
    /// <remarks>
    /// Step 2's rejection branch is REMOVED (R7): the line-8136 gate — "If minPinLengthRPIDs is present
    /// and the authenticator does not support the minPinLength extension or the PIN Complexity Policy
    /// extension, return CTAP1_ERR_INVALID_PARAMETER" — is a disjunctive ("...or...") antecedent read
    /// under De Morgan ("reject iff the authenticator supports NEITHER extension"); this profile now
    /// supports <c>minPinLength</c>, so the antecedent is FALSE regardless of <c>pinComplexityPolicy</c>'s
    /// continued absence, and line 8105's own "MUST NOT be used unless the minPinLength extension is
    /// supported" table-row MUST NOT is satisfied (not violated) by accepting the parameter. Step 8's
    /// storage posture (lines 8179-8190): this simulator has no pre-configured immutable list, so a
    /// non-empty supplied <c>minPinLengthRPIDs</c> REPLACES <see cref="CtapAuthenticatorState.MinPinLengthRpIds"/>
    /// wholesale (line 8184 — the only posture available when no pre-configured list exists; line 8186's
    /// "adds to the immutable pre-configured list" posture never applies here). Step 8's own guard
    /// ("present and contains at least one string", line 8179) means an ABSENT list is a no-op, and a
    /// PRESENT-BUT-EMPTY list is ALSO a no-op (the guard requires both present AND non-empty) — neither
    /// is a rejection, and the stored list is left unchanged in both cases. The bound check (line 8182,
    /// unnamed status) and line 8189's "cannot store or add... returns CTAP2_ERR_KEY_STORE_FULL" (the same
    /// step-family's own named storage-failure code) together justify rejecting a supplied list larger
    /// than <see cref="CtapAuthenticatorState.MaxRpIdsForSetMinPinLengthCapacity"/> with
    /// <see cref="WellKnownCtapStatusCodes.KeyStoreFull"/> — a two-anchor documented ruling, no nearer
    /// named status exists in 8179-8190's own text.
    /// </remarks>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnSetMinPinLengthRequested(
        CtapAuthenticatorState state, CtapAuthenticatorConfigRequest request)
    {
        //Step 1 (line 8134): absent newMinPINLength defaults to the current minimum.
        int newMinPinLength = request.NewMinPinLength ?? state.MinPinCodePointLength;

        //Step 3 (lines 8138-8141): a decrease is rejected; equal is allowed (a no-op success).
        if(newMinPinLength < state.MinPinCodePointLength)
        {
            return Reject(state, WellKnownCtapStatusCodes.PinPolicyViolation, "AuthenticatorConfig:SetMinPinLengthDecreaseRejected");
        }

        bool isClientPinSet = state.CurrentStoredPin is not null;
        bool forcePinChange = state.IsForcePinChangeRequired;

        //Step 4 (lines 8143-8149): forceChangePin:true with no PIN set -> PinNotSet; else force unconditionally.
        if(request.ForceChangePin == true)
        {
            if(!isClientPinSet)
            {
                return Reject(state, WellKnownCtapStatusCodes.PinNotSet, "AuthenticatorConfig:SetMinPinLengthForceChangeNoPin");
            }

            forcePinChange = true;
        }

        //Step 5 (lines 8152-8166, R3): pinComplexityPolicy is decoded (request.PinComplexityPolicy) but
        //never consulted here — this profile's getInfo pinComplexityPolicy member is absent, so it is
        //not configurable via this subcommand (line 8442's MUST).

        //Step 6 (line 8169, TRAP 12): forces a change ONLY when the stored PIN is now too short for the
        //just-raised minimum — NOT merely because the minimum was raised.
        if(isClientPinSet && state.PinCodePointLength < newMinPinLength)
        {
            forcePinChange = true;
        }

        //Step 8 (lines 8179-8190, R7): see this method's own remarks for the guard/posture/bound-check
        //derivation. Evaluated here, ahead of step 7's effectful fork below.
        IReadOnlyList<string> minPinLengthRpIds = state.MinPinLengthRpIds;
        if(request.MinPinLengthRpIds is { Count: > 0 } suppliedMinPinLengthRpIds)
        {
            if(suppliedMinPinLengthRpIds.Count > CtapAuthenticatorState.MaxRpIdsForSetMinPinLengthCapacity)
            {
                return Reject(state, WellKnownCtapStatusCodes.KeyStoreFull, "AuthenticatorConfig:SetMinPinLengthRpIdsKeyStoreFull");
            }

            minPinLengthRpIds = suppliedMinPinLengthRpIds;
        }

        CtapAuthenticatorState updatedState = state with
        {
            MinPinCodePointLength = newMinPinLength,
            IsForcePinChangeRequired = forcePinChange,
            MinPinLengthRpIds = minPinLengthRpIds
        };

        //Step 7 (lines 8171-8177): the CURRENT forcePINChange value (freshly set above, or already true
        //from an earlier call) resets every pinUvAuthToken for both protocols — entropy-consuming, so
        //routed through the effectful loop rather than minted inline here.
        if(forcePinChange)
        {
            CtapAuthenticatorState resettingState = updatedState with
            {
                NextAction = new CtapResetPinUvAuthTokensAction(),
                ResponseIntent = null
            };

            return Transition(resettingState, "AuthenticatorConfig:SetMinPinLengthResettingTokens");
        }

        //Step 9 (line 8192): CTAP2_OK.
        return Respond(updatedState, new AuthenticatorConfigResponseReady(), "AuthenticatorConfig:SetMinPinLength");
    }


    /// <summary>
    /// Completes <c>setMinPINLength</c>'s step 7 once the effectful loop has minted two fresh
    /// <c>pinUvAuthToken</c>s: installs them (disposing the stale ones) and completes with
    /// <c>CTAP2_OK</c>. <see cref="CtapAuthenticatorState.MinPinCodePointLength"/>/
    /// <see cref="CtapAuthenticatorState.IsForcePinChangeRequired"/>/<see cref="CtapAuthenticatorState.MinPinLengthRpIds"/>
    /// were already applied by <see cref="OnSetMinPinLengthRequested"/> before this action was declared,
    /// so this fold-back's own <c>with</c> copy does not need to repeat them.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnPinUvAuthTokensReset(
        CtapAuthenticatorState state, PinUvAuthTokensReset reset)
    {
        state.ProtocolOneToken.Dispose();
        state.ProtocolTwoToken.Dispose();

        CtapAuthenticatorState nextState = state with
        {
            NextAction = NullAction.Instance,
            ProtocolOneToken = reset.FreshProtocolOneToken,
            ProtocolTwoToken = reset.FreshProtocolTwoToken,
            ResponseIntent = new AuthenticatorConfigResponseReady()
        };

        return Transition(nextState, "AuthenticatorConfig:SetMinPinLengthTokensReset");
    }


    /// <summary>
    /// The pure request-arm of <c>authenticatorReset</c> (CTAP 2.3, section 6.6): opens with the
    /// family-standard <see cref="DiscardAllRememberedSequences"/> call (R10's global-discard convention
    /// applies here like every other command arm), then the power-up-window check (lines 6365-6366/6374)
    /// FIRST — <c>request.Now - state.PoweredOnAt</c> strictly greater than
    /// <see cref="ResetPowerUpWindowDuration"/> rejects with <see cref="WellKnownCtapStatusCodes.NotAllowed"/>
    /// and NO further state mutation (a failed reset leaves the PIN, credentials, config, retries, and
    /// tokens exactly as the discard call above left them). On pass, applies
    /// <see cref="CtapAuthenticatorState.FactoryReset"/>'s entropy-free clear and declares a
    /// <see cref="CtapFactoryResetKeyMaterialAction"/> to mint the fresh key-agreement key pairs and
    /// <c>pinUvAuthToken</c>s the pure transform cannot draw itself.
    /// </summary>
    /// <remarks>
    /// The four other outcomes lines 6371-6373 name are all documented-unreachable, mirroring the
    /// mc/ga precedent (evidence of user interaction is unconditionally granted in this deterministic
    /// simulator, the same modeling <c>authenticatorMakeCredential</c>/<c>authenticatorGetAssertion</c>
    /// already use): "disabled for the transport used" (line 6371) — this simulator supports reset
    /// unconditionally on its sole transport; "user presence explicitly denied" (line 6372) and "a user
    /// action timeout occurs" (line 6373) — no simulated-decline/timeout seam exists anywhere in this
    /// codebase, and none is added here (the no-test-seams-in-production rule). Consequently
    /// <c>CTAP2_ERR_OPERATION_DENIED</c>/<c>CTAP2_ERR_USER_ACTION_TIMEOUT</c> are never emitted by this
    /// arm, and the ordering question among all four denial conditions the spec never states explicitly
    /// is moot here — the power-up window is the only LIVE gate this command has.
    /// </remarks>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnAuthenticatorResetRequested(
        CtapAuthenticatorState state, ResetRequested requested)
    {
        state = DiscardAllRememberedSequences(state);

        if(requested.Now - state.PoweredOnAt > ResetPowerUpWindowDuration)
        {
            return Reject(state, WellKnownCtapStatusCodes.NotAllowed, "Reset:PowerUpWindowElapsed");
        }

        CtapAuthenticatorState resettingState = state.FactoryReset(requested.Pool) with
        {
            NextAction = new CtapFactoryResetKeyMaterialAction(),
            ResponseIntent = null
        };

        return Transition(resettingState, "Reset:FactoryResetPending");
    }


    /// <summary>
    /// Completes <c>authenticatorReset</c> once the effectful loop has minted both PIN/UV auth
    /// protocols' fresh key-agreement key pairs and <c>pinUvAuthToken</c>s: disposes the OLD material
    /// (untouched by <see cref="CtapAuthenticatorState.FactoryReset"/>'s own pure clear, since those four
    /// fields are non-nullable), installs the fresh material, and completes with
    /// <see cref="AuthenticatorResetResponseReady"/> (CTAP 2.3 §6.6, lines 6370-6374: a bare
    /// <c>CTAP2_OK</c>, no response map).
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnAuthenticatorResetKeyMaterialMinted(
        CtapAuthenticatorState state, AuthenticatorResetKeyMaterialMinted minted)
    {
        state.ProtocolOneKeyAgreementKeyPair.Dispose();
        state.ProtocolTwoKeyAgreementKeyPair.Dispose();
        state.ProtocolOneToken.Dispose();
        state.ProtocolTwoToken.Dispose();

        CtapAuthenticatorState nextState = state with
        {
            NextAction = NullAction.Instance,
            ProtocolOneKeyAgreementKeyPair = minted.FreshProtocolOneKeyPair,
            ProtocolTwoKeyAgreementKeyPair = minted.FreshProtocolTwoKeyPair,
            ProtocolOneToken = minted.FreshProtocolOneToken,
            ProtocolTwoToken = minted.FreshProtocolTwoToken,
            ResponseIntent = new AuthenticatorResetResponseReady()
        };

        return Transition(nextState, "Reset:KeyMaterialMinted");
    }


    /// <summary>
    /// The pure request-arm of <c>authenticatorCredentialManagement</c> (CTAP 2.3, section 6.8), the
    /// SIMPLEST of the three token-gated command families in this codebase (R2 — seams §3.7): command
    /// level, <c>subCommand</c> outside {getCredsMetadata..updateUserInformation} rejects with
    /// <see cref="WellKnownCtapStatusCodes.InvalidSubcommand"/> (§8.1, line 8810 — the sole source, no
    /// two-source conflict exists for this command). <c>enumerateRPsGetNextRP</c>/
    /// <c>enumerateCredentialsGetNextCredential</c> (the two stateful continuations) have NO gate of any
    /// kind — no <c>pinUvAuthParam</c> processing at all, dispatched directly, gate-free, off the
    /// remembered state (R10). Every other subcommand's own procedure opens IDENTICALLY and
    /// UNCONDITIONALLY (no protected-check, no tokenless fallback, unlike mc/ga/acfg): step 1
    /// (<c>pinUvAuthParam</c> missing) → <see cref="WellKnownCtapStatusCodes.PuatRequired"/> — even when
    /// no PIN is set and even when the store is empty (the gate precedes any no-credentials check); step
    /// 2 (per-subcommand mandatory <c>subCommandParams</c> member absent, or <c>pinUvAuthProtocol</c>
    /// absent) → <see cref="WellKnownCtapStatusCodes.MissingParameter"/>; step 3 (protocol unsupported) →
    /// <see cref="WellKnownCtapStatusCodes.InvalidParameter"/>; step 4 declares the R4 verify action that
    /// interrupts this request to run <see cref="OnCredentialManagementPinUvAuthTokenVerified"/>'s own
    /// remaining steps (cm permission → R3's RP-ID sub-check → the subcommand's own handler).
    /// <c>authenticatorCredentialManagement</c> is an intervening operation like every other command:
    /// its FIVE gated subcommands discard ALL THREE remembered stateful-command sequences regardless of
    /// whether the command itself succeeds (R10's global discard rule); the two GetNext continuations
    /// discard only the OTHER two slots, preserving their own.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnCredentialManagementRequested(
        CtapAuthenticatorState state, CredentialManagementRequested requested)
    {
        CtapCredentialManagementRequest request = requested.Request;

        if(WellKnownCtapCredentialManagementSubCommands.IsEnumerateRpsGetNextRp(request.SubCommand))
        {
            //R7: a pending largeBlobs write is a DIFFERENT stateful sequence from this one's own
            //RememberedEnumerateRps, so it discards under the GLOBAL discipline exactly as every other
            //intervening command does.
            state = DiscardRememberedLargeBlobWrite(DiscardRememberedEnumerateCredentials(DiscardRememberedGetAssertion(state)));

            return OnEnumerateRpsGetNextRpRequested(state, requested.Now);
        }

        if(WellKnownCtapCredentialManagementSubCommands.IsEnumerateCredentialsGetNextCredential(request.SubCommand))
        {
            state = DiscardRememberedLargeBlobWrite(DiscardRememberedEnumerateRps(DiscardRememberedGetAssertion(state)));

            return OnEnumerateCredentialsGetNextCredentialRequested(state, requested.Now);
        }

        state = DiscardAllRememberedSequences(state);

        bool isSupportedGatedSubCommand = WellKnownCtapCredentialManagementSubCommands.IsGetCredsMetadata(request.SubCommand)
            || WellKnownCtapCredentialManagementSubCommands.IsEnumerateRpsBegin(request.SubCommand)
            || WellKnownCtapCredentialManagementSubCommands.IsEnumerateCredentialsBegin(request.SubCommand)
            || WellKnownCtapCredentialManagementSubCommands.IsDeleteCredential(request.SubCommand)
            || WellKnownCtapCredentialManagementSubCommands.IsUpdateUserInformation(request.SubCommand);
        if(!isSupportedGatedSubCommand)
        {
            return Reject(state, WellKnownCtapStatusCodes.InvalidSubcommand, "CredentialManagement:UnsupportedSubCommand");
        }

        //Step 1: unconditional, no protected-check, no tokenless fallback — the simplest of the three
        //token-gate shapes in this codebase.
        if(request.PinUvAuthParam is not ReadOnlyMemory<byte> pinUvAuthParam)
        {
            return Reject(state, WellKnownCtapStatusCodes.PuatRequired, "CredentialManagement:PuatRequired");
        }

        //Step 2: per-subcommand mandatory subCommandParams member.
        byte? missingParameterStatus = EvaluateMandatoryCredentialManagementParams(request);
        if(missingParameterStatus is byte missingStatus)
        {
            return Reject(state, missingStatus, "CredentialManagement:MissingParameter");
        }

        if(request.PinUvAuthProtocol is not int protocolValue)
        {
            return Reject(state, WellKnownCtapStatusCodes.MissingParameter, "CredentialManagement:MissingProtocol");
        }

        //Step 3.
        if(!IsSupportedPinUvAuthProtocol(protocolValue))
        {
            return Reject(state, WellKnownCtapStatusCodes.InvalidParameter, "CredentialManagement:UnsupportedProtocol");
        }

        CtapPinUvAuthProtocolId protocolId = (CtapPinUvAuthProtocolId)protocolValue;
        CtapPinUvAuthTokenState presentedToken = SelectPinUvAuthTokenState(state, protocolId).EvaluateExpiry(requested.Now);
        state = WithPinUvAuthTokenState(state, protocolId, presentedToken);

        CtapAuthenticatorState nextState = state with
        {
            NextAction = new CtapVerifyCredentialManagementTokenAction(
                protocolId, presentedToken, request.SubCommand, request.SubCommandParams ?? ReadOnlyMemory<byte>.Empty, pinUvAuthParam,
                new CtapCredentialManagementVerifyContinuation(requested)),
            ResponseIntent = null
        };

        return Transition(nextState, "CredentialManagement:VerifyPinUvAuthToken");
    }


    /// <summary>
    /// Evaluates step 2's per-subcommand mandatory <c>subCommandParams</c> requirement (CTAP 2.3 §6.8,
    /// each verifying subcommand's own step 2): <c>enumerateCredentialsBegin</c> requires
    /// <c>rpIDHash</c>; <c>deleteCredential</c> requires <c>credentialID</c>; <c>updateUserInformation</c>
    /// requires BOTH <c>credentialID</c> AND <c>user</c>; <c>getCredsMetadata</c>/<c>enumerateRPsBegin</c>
    /// require none.
    /// </summary>
    /// <param name="request">The decoded request to check.</param>
    /// <returns><see cref="WellKnownCtapStatusCodes.MissingParameter"/> if a mandatory member is absent; otherwise <see langword="null"/>.</returns>
    private static byte? EvaluateMandatoryCredentialManagementParams(CtapCredentialManagementRequest request)
    {
        if(WellKnownCtapCredentialManagementSubCommands.IsEnumerateCredentialsBegin(request.SubCommand) && request.RpIdHash is null)
        {
            return WellKnownCtapStatusCodes.MissingParameter;
        }

        if(WellKnownCtapCredentialManagementSubCommands.IsDeleteCredential(request.SubCommand) && request.CredentialId is null)
        {
            return WellKnownCtapStatusCodes.MissingParameter;
        }

        if(WellKnownCtapCredentialManagementSubCommands.IsUpdateUserInformation(request.SubCommand) && (request.CredentialId is null || request.User is null))
        {
            return WellKnownCtapStatusCodes.MissingParameter;
        }

        return null;
    }


    /// <summary>
    /// Completes an <c>authenticatorCredentialManagement</c> whose presented <c>pinUvAuthParam</c> has
    /// been verified: verify (already run by the executor) → step 5, the <c>cm</c> permission bit (line
    /// 5958's own bullet has already made <c>cm</c> unconditionally grantable — see
    /// <see cref="EvaluatePinUvAuthTokenPermissionGate"/>) → step 6, R3's RP-ID sub-check, folded into
    /// each subcommand's own handler. NO flag/permission clearing on success (extraction §2.5 —
    /// <c>authenticatorCredentialManagement</c> is not "an operation that tests user presence"): a token
    /// used to complete any cm subcommand retains every other permission afterward.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnCredentialManagementPinUvAuthTokenVerified(
        CtapAuthenticatorState state, bool verified, CredentialManagementRequested requested)
    {
        if(!verified)
        {
            return Reject(state, WellKnownCtapStatusCodes.PinAuthInvalid, "CredentialManagement:VerifyFailed");
        }

        CtapCredentialManagementRequest request = requested.Request;
        CtapPinUvAuthProtocolId protocolId = (CtapPinUvAuthProtocolId)request.PinUvAuthProtocol!.Value;
        CtapPinUvAuthTokenState token = SelectPinUvAuthTokenState(state, protocolId);

        if((token.Permissions & WellKnownCtapPinUvAuthTokenPermissions.Cm) == 0)
        {
            return Reject(state, WellKnownCtapStatusCodes.PinAuthInvalid, "CredentialManagement:CmPermissionDenied");
        }

        token = token with { LastUsedAt = requested.Now };
        state = WithPinUvAuthTokenState(state, protocolId, token);

        return InvokeCredentialManagementSubCommand(state, request, token.PermissionsRpId, requested.Now, protocolId);
    }


    /// <summary>
    /// Dispatches to the requested subcommand's own handler after step 5's <c>cm</c> permission check
    /// (CTAP 2.3 §6.8 step 6, R3): C1 (<c>getCredsMetadata</c>/<c>enumerateRPsBegin</c>/
    /// <c>enumerateCredentialsBegin</c>) rejects a BOUND token unconditionally — INVERTED polarity from
    /// mc/ga, even when the token is bound to the very RP being enumerated; C2 (<c>deleteCredential</c>/
    /// <c>updateUserInformation</c>) accepts an unbound token OR one bound to the ADDRESSED credential's
    /// own stored RP ID, evaluated as part of each handler's own existence-and-match conjunction. The
    /// final <see langword="throw"/> is unreachable — <see cref="OnCredentialManagementRequested"/>'s own
    /// step 2 already rejected every value besides these five before either fold-back path could reach
    /// here.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> InvokeCredentialManagementSubCommand(
        CtapAuthenticatorState state, CtapCredentialManagementRequest request, string? tokenPermissionsRpId, DateTimeOffset now, CtapPinUvAuthProtocolId protocolId)
    {
        if(WellKnownCtapCredentialManagementSubCommands.IsGetCredsMetadata(request.SubCommand))
        {
            return tokenPermissionsRpId is not null
                ? Reject(state, WellKnownCtapStatusCodes.PinAuthInvalid, "CredentialManagement:GetCredsMetadataBoundTokenRejected")
                : OnGetCredsMetadataRequested(state);
        }

        if(WellKnownCtapCredentialManagementSubCommands.IsEnumerateRpsBegin(request.SubCommand))
        {
            return tokenPermissionsRpId is not null
                ? Reject(state, WellKnownCtapStatusCodes.PinAuthInvalid, "CredentialManagement:EnumerateRpsBeginBoundTokenRejected")
                : OnEnumerateRpsBeginRequested(state, now, protocolId);
        }

        if(WellKnownCtapCredentialManagementSubCommands.IsEnumerateCredentialsBegin(request.SubCommand))
        {
            return tokenPermissionsRpId is not null
                ? Reject(state, WellKnownCtapStatusCodes.PinAuthInvalid, "CredentialManagement:EnumerateCredentialsBeginBoundTokenRejected")
                : OnEnumerateCredentialsBeginRequested(state, request, now, protocolId);
        }

        if(WellKnownCtapCredentialManagementSubCommands.IsDeleteCredential(request.SubCommand))
        {
            return OnDeleteCredentialRequested(state, request, tokenPermissionsRpId);
        }

        if(WellKnownCtapCredentialManagementSubCommands.IsUpdateUserInformation(request.SubCommand))
        {
            return OnUpdateUserInformationRequested(state, request, tokenPermissionsRpId);
        }

        throw new NotSupportedException($"authenticatorCredentialManagement subCommand '{request.SubCommand}' reached subcommand dispatch unsupported.");
    }


    /// <summary>
    /// <c>getCredsMetadata</c> (CTAP 2.3 §6.8.2, lines 7154-7161): no no-credentials rejection exists —
    /// an empty store SUCCEEDS with <c>{existingResidentCredentialsCount: 0,
    /// maxPossibleRemainingResidentCredentialsCount: capacity}</c>. Both counts derive from the SAME
    /// source <c>getInfo</c>'s own <c>remainingDiscoverableCredentials</c> uses (R9's single-source-of-truth
    /// choice). R5: the spec's own dual-path verify (lines 7134-7152, <c>persistentPinUvAuthToken</c>
    /// first, falling back to <c>pinUvAuthToken</c>) is documented-unreachable here — this authenticator
    /// implements the step-6 <c>pinUvAuthToken</c> path directly, since <c>persistentPinUvAuthToken</c>/
    /// <c>pcmr</c>/<c>perCredMgmtRO</c> are unmodeled and issuance of the former is unreachable.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnGetCredsMetadataRequested(CtapAuthenticatorState state)
    {
        int existingCount = CountResidentCredentials(state.CredentialsByCredentialId);
        int remainingCount = state.ResidentCredentialCapacity - existingCount;

        CtapCredentialManagementResponse response = new(
            ExistingResidentCredentialsCount: existingCount,
            MaxPossibleRemainingResidentCredentialsCount: remainingCount);

        return Respond(state, new CredentialManagementResponseReady(response), "CredentialManagement:GetCredsMetadata");
    }


    /// <summary>
    /// <c>enumerateRPsBegin</c> (CTAP 2.3 §6.8.3, lines 7211-7222): step 7, no discoverable credentials →
    /// <see cref="WellKnownCtapStatusCodes.NoCredentials"/>; otherwise initializes the RPs sequence state
    /// (R9's <see cref="CtapCredentialRecord.CreationSequence"/>-ascending-by-first-created-credential
    /// order, <see cref="GroupResidentCredentialsByRpId"/>) and declares
    /// <see cref="CtapEmitCredentialManagementRpAction"/> for the first RP, carrying <c>totalRPs</c>
    /// (line 7220). R5: the spec's own dual-path verify (lines 7191-7208) is documented-unreachable —
    /// see <see cref="OnGetCredsMetadataRequested"/>'s own identical remark.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnEnumerateRpsBeginRequested(
        CtapAuthenticatorState state, DateTimeOffset now, CtapPinUvAuthProtocolId protocolId)
    {
        List<string> rpIds = GroupResidentCredentialsByRpId(state.CredentialsByCredentialId);
        if(rpIds.Count == 0)
        {
            return Reject(state, WellKnownCtapStatusCodes.NoCredentials, "CredentialManagement:EnumerateRpsBeginNoCredentials");
        }

        CtapAuthenticatorState nextState = state with
        {
            RememberedEnumerateRps = new CtapRememberedEnumerateRpsState(rpIds, RpCounter: 1, now, protocolId),
            NextAction = new CtapEmitCredentialManagementRpAction(rpIds[0], rpIds.Count),
            ResponseIntent = null
        };

        return Transition(nextState, "CredentialManagement:EnumerateRpsBegin");
    }


    /// <summary>
    /// <c>enumerateRPsGetNextRP</c> (CTAP 2.3 §6.8.3, lines 7236-7242): no live sequence (never begun,
    /// discarded, timer-expired, or authenticating-token-expired) → <see cref="WellKnownCtapStatusCodes.NotAllowed"/>
    /// (the <c>authenticatorGetNextAssertion</c> precedent); token expiry is folded FIRST (CTAP 2.3,
    /// section 6, item 3, line 2873), THEN the 30-second timer (item 2, line 2871 — an exercised MAY,
    /// unlike <c>authenticatorGetNextAssertion</c>'s own mandatory override); otherwise advances
    /// <see cref="CtapRememberedEnumerateRpsState.RpCounter"/> and declares
    /// <see cref="CtapEmitCredentialManagementRpAction"/> for the next RP, WITHOUT <c>totalRPs</c> (line
    /// 7242's own field list omits it).
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnEnumerateRpsGetNextRpRequested(
        CtapAuthenticatorState state, DateTimeOffset now)
    {
        CtapRememberedEnumerateRpsState? remembered = state.RememberedEnumerateRps;
        if(remembered is null)
        {
            return Reject(state, WellKnownCtapStatusCodes.NotAllowed, "CredentialManagement:EnumerateRpsGetNextRpNoRememberedState");
        }

        CtapPinUvAuthTokenState evaluatedToken = SelectPinUvAuthTokenState(state, remembered.AuthenticatingPinUvAuthProtocol).EvaluateExpiry(now);
        state = WithPinUvAuthTokenState(state, remembered.AuthenticatingPinUvAuthProtocol, evaluatedToken);

        if(!evaluatedToken.IsInUse)
        {
            return Reject(DiscardRememberedEnumerateRps(state), WellKnownCtapStatusCodes.NotAllowed, "CredentialManagement:EnumerateRpsGetNextRpTokenExpired");
        }

        if(now - remembered.LastActivityAt > CredentialManagementEnumerationTimerDuration)
        {
            return Reject(DiscardRememberedEnumerateRps(state), WellKnownCtapStatusCodes.NotAllowed, "CredentialManagement:EnumerateRpsGetNextRpTimerExpired");
        }

        if(remembered.RpCounter >= remembered.ApplicableRpIds.Count)
        {
            return Reject(state, WellKnownCtapStatusCodes.NotAllowed, "CredentialManagement:EnumerateRpsGetNextRpCounterExhausted");
        }

        string nextRpId = remembered.ApplicableRpIds[remembered.RpCounter];

        CtapAuthenticatorState nextState = state with
        {
            RememberedEnumerateRps = remembered with { RpCounter = remembered.RpCounter + 1, LastActivityAt = now },
            NextAction = new CtapEmitCredentialManagementRpAction(nextRpId, TotalRps: null),
            ResponseIntent = null
        };

        return Transition(nextState, "CredentialManagement:EnumerateRpsGetNextRp");
    }


    /// <summary>
    /// <c>enumerateCredentialsBegin</c> (CTAP 2.3 §6.8.4, lines 7268-7316): declares
    /// <see cref="CtapLocateCredentialManagementCredentialsAction"/> to match the request's own
    /// <c>rpIDHash</c> against every resident credential's freshly computed hash (no by-hash index
    /// exists — a fresh compare per candidate). The step-7 no-credentials decision and the response/
    /// remembered-state assembly happen once the match completes, in
    /// <see cref="OnCredentialManagementCredentialsLocated"/>. R5: the spec's own dual-path verify
    /// (lines 7277-7294) is documented-unreachable — see <see cref="OnGetCredsMetadataRequested"/>'s own
    /// identical remark.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnEnumerateCredentialsBeginRequested(
        CtapAuthenticatorState state, CtapCredentialManagementRequest request, DateTimeOffset now, CtapPinUvAuthProtocolId protocolId)
    {
        CtapAuthenticatorState nextState = state with
        {
            NextAction = new CtapLocateCredentialManagementCredentialsAction(request.RpIdHash!.Value, state.CredentialsByCredentialId, now, protocolId),
            ResponseIntent = null
        };

        return Transition(nextState, "CredentialManagement:EnumerateCredentialsBeginLocate");
    }


    /// <summary>
    /// <c>enumerateCredentialsGetNextCredential</c> (CTAP 2.3 §6.8.4, lines 7330-7343): no live sequence
    /// → <see cref="WellKnownCtapStatusCodes.NotAllowed"/>, with the identical expiry-then-timer fold
    /// order as <see cref="OnEnumerateRpsGetNextRpRequested"/>; otherwise advances
    /// <see cref="CtapRememberedEnumerateCredentialsState.CredentialCounter"/> and returns the next
    /// credential's <c>user</c>/<c>credentialID</c>/<c>publicKey</c>, WITHOUT <c>totalCredentials</c>.
    /// Fully pure: the next credential's fields are already stored on its
    /// <see cref="CtapCredentialRecord"/>, borrowed directly — no fresh hash computation is needed here.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnEnumerateCredentialsGetNextCredentialRequested(
        CtapAuthenticatorState state, DateTimeOffset now)
    {
        CtapRememberedEnumerateCredentialsState? remembered = state.RememberedEnumerateCredentials;
        if(remembered is null)
        {
            return Reject(state, WellKnownCtapStatusCodes.NotAllowed, "CredentialManagement:EnumerateCredentialsGetNextNoRememberedState");
        }

        CtapPinUvAuthTokenState evaluatedToken = SelectPinUvAuthTokenState(state, remembered.AuthenticatingPinUvAuthProtocol).EvaluateExpiry(now);
        state = WithPinUvAuthTokenState(state, remembered.AuthenticatingPinUvAuthProtocol, evaluatedToken);

        if(!evaluatedToken.IsInUse)
        {
            return Reject(DiscardRememberedEnumerateCredentials(state), WellKnownCtapStatusCodes.NotAllowed, "CredentialManagement:EnumerateCredentialsGetNextTokenExpired");
        }

        if(now - remembered.LastActivityAt > CredentialManagementEnumerationTimerDuration)
        {
            return Reject(DiscardRememberedEnumerateCredentials(state), WellKnownCtapStatusCodes.NotAllowed, "CredentialManagement:EnumerateCredentialsGetNextTimerExpired");
        }

        if(remembered.CredentialCounter >= remembered.ApplicableCredentialIds.Count)
        {
            return Reject(state, WellKnownCtapStatusCodes.NotAllowed, "CredentialManagement:EnumerateCredentialsGetNextCounterExhausted");
        }

        CredentialId nextCredentialId = remembered.ApplicableCredentialIds[remembered.CredentialCounter];
        CtapCredentialRecord record = state.CredentialsByCredentialId[CredentialIdKey(nextCredentialId)];
        CtapCredentialManagementResponse response = BuildCredentialEnumerationResponse(record, totalCredentials: null);

        CtapAuthenticatorState nextState = state with
        {
            RememberedEnumerateCredentials = remembered with { CredentialCounter = remembered.CredentialCounter + 1, LastActivityAt = now }
        };

        return Respond(nextState, new CredentialManagementResponseReady(response), "CredentialManagement:EnumerateCredentialsGetNext");
    }


    /// <summary>
    /// <c>deleteCredential</c> (CTAP 2.3 §6.8.5, lines 7370-7392): R3-C2's existence-and-match
    /// conjunction — a BOUND token evaluates "exists and matches" as ONE check (nonexistent or
    /// RP-mismatched ⇒ <see cref="WellKnownCtapStatusCodes.PinAuthInvalid"/>, no existence oracle); an
    /// UNBOUND token reaches step 7 regardless (nonexistent ⇒ <see cref="WellKnownCtapStatusCodes.NoCredentials"/>).
    /// Removes the credential and disposes it — the <c>OnCredentialMinted</c> overwrite-removal idiom —
    /// then returns a bare <c>CTAP2_OK</c> (step 9, line 7392; no response map). The 128-bit credential
    /// store state regeneration (line 7390) is NOT modeled — dead state, its only consumer
    /// (<c>encCredStoreState</c>) is <c>persistentPinUvAuthToken</c>-gated and structurally unreachable
    /// in this profile (R5). A subsequent <c>authenticatorGetAssertion</c> naming this credential is
    /// unaffected by any secondary index (there is none): it simply no longer finds a match.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnDeleteCredentialRequested(
        CtapAuthenticatorState state, CtapCredentialManagementRequest request, string? tokenPermissionsRpId)
    {
        CtapCredentialRecord? record = LookupCredentialManagementCredential(state, request.CredentialId!.Id);

        if(tokenPermissionsRpId is not null && (record is null || !string.Equals(record.RpId, tokenPermissionsRpId, StringComparison.Ordinal)))
        {
            return Reject(state, WellKnownCtapStatusCodes.PinAuthInvalid, "CredentialManagement:DeleteCredentialBoundTokenRejected");
        }

        if(record is null)
        {
            return Reject(state, WellKnownCtapStatusCodes.NoCredentials, "CredentialManagement:DeleteCredentialNoCredentials");
        }

        ImmutableDictionary<string, CtapCredentialRecord> byId = state.CredentialsByCredentialId.Remove(CredentialIdKey(record.CredentialId));
        record.Dispose();

        return Respond(state with { CredentialsByCredentialId = byId }, new CredentialManagementResponseReady(null), "CredentialManagement:DeleteCredential");
    }


    /// <summary>
    /// <c>updateUserInformation</c> (CTAP 2.3 §6.8.6, lines 7420-7450): R3-C2's identical
    /// existence-and-match conjunction (see <see cref="OnDeleteCredentialRequested"/>'s own remark);
    /// <see cref="WellKnownCtapStatusCodes.KeyStoreFull"/> (line 7442) is documented-unreachable — this
    /// simulator's capacity is credential-COUNT-based, and an in-place field update never grows the
    /// store; the supplied <c>user.id</c> mismatching the matched credential's own stored user ID (line
    /// 7444) → <see cref="WellKnownCtapStatusCodes.InvalidParameter"/> via a PLAIN ordinal byte compare
    /// (user IDs are not secret material); the THREE-WAY <c>name</c>/<c>displayName</c> mapping (line
    /// 7446, trap 16): absent OR present-and-empty → remove (<see langword="null"/>); present-non-empty →
    /// replace. Installed via a record-<c>with</c> replacement — the OLD record is NOT disposed, since
    /// its pooled fields (<see cref="CtapCredentialRecord.CredentialId"/>/<see cref="CtapCredentialRecord.UserId"/>/
    /// <see cref="CtapCredentialRecord.CredentialKey"/>) are carried unchanged onto the new record, the
    /// SAME custody the record's own <c>with</c> semantics already establish elsewhere. The store-state
    /// regeneration (line 7448) shares <see cref="OnDeleteCredentialRequested"/>'s own not-modeled
    /// disposition.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnUpdateUserInformationRequested(
        CtapAuthenticatorState state, CtapCredentialManagementRequest request, string? tokenPermissionsRpId)
    {
        CtapCredentialRecord? record = LookupCredentialManagementCredential(state, request.CredentialId!.Id);

        if(tokenPermissionsRpId is not null && (record is null || !string.Equals(record.RpId, tokenPermissionsRpId, StringComparison.Ordinal)))
        {
            return Reject(state, WellKnownCtapStatusCodes.PinAuthInvalid, "CredentialManagement:UpdateUserInformationBoundTokenRejected");
        }

        if(record is null)
        {
            return Reject(state, WellKnownCtapStatusCodes.NoCredentials, "CredentialManagement:UpdateUserInformationNoCredentials");
        }

        //Line 7442: structurally unreachable — this simulator's capacity is credential-count-based, and
        //an in-place name/displayName update never grows the store.

        CtapPublicKeyCredentialUserEntity suppliedUser = request.User!;
        if(suppliedUser.Id != record.UserId)
        {
            return Reject(state, WellKnownCtapStatusCodes.InvalidParameter, "CredentialManagement:UpdateUserInformationUserIdMismatch");
        }

        string? newName = string.IsNullOrEmpty(suppliedUser.Name) ? null : suppliedUser.Name;
        string? newDisplayName = string.IsNullOrEmpty(suppliedUser.DisplayName) ? null : suppliedUser.DisplayName;

        CtapCredentialRecord updated = record with { UserName = newName, UserDisplayName = newDisplayName };
        ImmutableDictionary<string, CtapCredentialRecord> byId = state.CredentialsByCredentialId.SetItem(CredentialIdKey(record.CredentialId), updated);

        return Respond(state with { CredentialsByCredentialId = byId }, new CredentialManagementResponseReady(null), "CredentialManagement:UpdateUserInformation");
    }


    /// <summary>
    /// Completes an <c>enumerateRPsBegin</c>/<c>enumerateRPsGetNextRP</c> response once the effectful
    /// loop has computed the reported RP's fresh <c>rpIDHash</c>: the response is already fully
    /// assembled (the fold-back input carries it), so this arm only frames it.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnCredentialManagementResponseComputed(
        CtapAuthenticatorState state, CredentialManagementResponseComputed computed) =>
        Respond(state, new CredentialManagementResponseReady(computed.Response), "CredentialManagement:ResponseComputed");


    /// <summary>
    /// Completes <c>enumerateCredentialsBegin</c> once the effectful loop has located every resident
    /// credential matching the request's <c>rpIDHash</c> (CTAP 2.3 §6.8.4 step 7, line 7297): no match →
    /// <see cref="WellKnownCtapStatusCodes.NoCredentials"/>; otherwise assembles the response from the
    /// first match's already-stored fields (borrowed, no new pooled memory) and initializes the
    /// credentials sequence state.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnCredentialManagementCredentialsLocated(
        CtapAuthenticatorState state, CredentialManagementCredentialsLocated located)
    {
        if(located.MatchedCredentialIds.Count == 0)
        {
            return Reject(state, WellKnownCtapStatusCodes.NoCredentials, "CredentialManagement:EnumerateCredentialsBeginNoCredentials");
        }

        CtapCredentialRecord first = state.CredentialsByCredentialId[CredentialIdKey(located.MatchedCredentialIds[0])];
        CtapCredentialManagementResponse response = BuildCredentialEnumerationResponse(first, located.MatchedCredentialIds.Count);

        CtapAuthenticatorState nextState = state with
        {
            RememberedEnumerateCredentials = new CtapRememberedEnumerateCredentialsState(
                located.MatchedCredentialIds, CredentialCounter: 1, located.Now, located.AuthenticatingPinUvAuthProtocol)
        };

        return Respond(nextState, new CredentialManagementResponseReady(response), "CredentialManagement:EnumerateCredentialsBegin");
    }


    /// <summary>
    /// Builds <c>enumerateCredentialsBegin</c>/<c>enumerateCredentialsGetNextCredential</c>'s shared
    /// response shape: <c>user</c>/<c>credentialID</c>/<c>publicKey</c>/<c>credProtect</c>/<c>largeBlobKey</c>,
    /// all borrowed directly from <paramref name="record"/>'s own already-stored fields (R11's
    /// <see cref="CtapCredentialRecord.CredProtectLevel"/>; wavelb R8's
    /// <see cref="CtapCredentialRecord.LargeBlobKey"/> — "the contents, if any", lines 7312/7341, so
    /// <see langword="null"/> when the credential carries no key), plus <paramref name="totalCredentials"/>
    /// when present (Begin only — line 7220's parallel field, omitted on every GetNext). NO
    /// <c>thirdPartyPayment</c> (R8). Deliberately no <see cref="CtapCredentialRecord.CredRandomWithUV"/>/
    /// <see cref="CtapCredentialRecord.CredRandomWithoutUV"/> either (contract R2c, trap 9): unlike
    /// <see cref="CtapCredentialRecord.LargeBlobKey"/>, no CTAP 2.3 §6.8.4 clause spec-mandates echoing
    /// CredRandom back to the platform through <c>authenticatorCredentialManagement</c> — it is SECRET
    /// material that appears in no response this authenticator builds, this one included.
    /// </summary>
    private static CtapCredentialManagementResponse BuildCredentialEnumerationResponse(CtapCredentialRecord record, int? totalCredentials) =>
        new(
            User: new CtapPublicKeyCredentialUserEntity(record.UserId, record.UserName, record.UserDisplayName),
            CredentialId: new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = record.CredentialId },
            PublicKey: record.PublicKey,
            TotalCredentials: totalCredentials,
            CredProtect: record.CredProtectLevel,
            LargeBlobKey: record.LargeBlobKey?.Memory);


    /// <summary>
    /// Groups every resident credential by relying party identifier, returning the distinct RP IDs
    /// ordered by each RP's OWN first-created credential (R9's <see cref="CtapCredentialRecord.CreationSequence"/>-ascending
    /// choice — an implementation decision, since CTAP 2.3 states no ordering requirement for RP
    /// enumeration). No cached secondary index exists — a fresh scan of the store per call, mirroring
    /// <see cref="LocateApplicableResidentCredentials"/>'s own style.
    /// </summary>
    private static List<string> GroupResidentCredentialsByRpId(ImmutableDictionary<string, CtapCredentialRecord> credentialsByCredentialId)
    {
        List<CtapCredentialRecord> residentCredentials = [];
        foreach(CtapCredentialRecord candidate in credentialsByCredentialId.Values)
        {
            if(candidate.IsResident)
            {
                residentCredentials.Add(candidate);
            }
        }

        residentCredentials.Sort(static (left, right) => left.CreationSequence.CompareTo(right.CreationSequence));

        List<string> rpIds = [];
        var seenRpIds = new HashSet<string>(StringComparer.Ordinal);
        foreach(CtapCredentialRecord candidate in residentCredentials)
        {
            if(seenRpIds.Add(candidate.RpId))
            {
                rpIds.Add(candidate.RpId);
            }
        }

        return rpIds;
    }


    /// <summary>
    /// Resolves <paramref name="credentialId"/> to its stored <see cref="CtapCredentialRecord"/>, if any —
    /// <c>deleteCredential</c>/<c>updateUserInformation</c>'s own credential-lookup step, mirroring
    /// <see cref="LocateAllowListCredential"/>'s <c>TryGetValue</c> idiom.
    /// </summary>
    private static CtapCredentialRecord? LookupCredentialManagementCredential(CtapAuthenticatorState state, CredentialId credentialId) =>
        state.CredentialsByCredentialId.TryGetValue(CredentialIdKey(credentialId), out CtapCredentialRecord? record) ? record : null;


    /// <summary>
    /// Applies the mismatch counter/latch semantics shared by <c>changePIN</c>, <c>getPinToken</c>, and
    /// <c>getPinUvAuthTokenUsingPinWithPermissions</c> (CTAP 2.3, lines 5678-5685/5893/5995, identical
    /// structure in all three): decrements <c>pinRetries</c>, increments the consecutive-mismatch
    /// counter, disposes the mismatched protocol's stale key-agreement pair and installs the freshly
    /// regenerated one, and resolves the status code in the spec's own order — retries exhausted
    /// (<see cref="WellKnownCtapStatusCodes.PinBlocked"/>) beats three consecutive mismatches
    /// (<see cref="WellKnownCtapStatusCodes.PinAuthBlocked"/>, which also latches) beats the ordinary
    /// case (<see cref="WellKnownCtapStatusCodes.PinInvalid"/>). Every caller applies this identically
    /// whether the triggering condition was a decoded-hash mismatch or a <c>pinHashEnc</c> decrypt error
    /// (CTAP 2.3 lines 5671/5883/5985: "If an error results, or a mismatch is detected") — the caller has
    /// already minted <paramref name="regeneratedKeyPair"/> either way.
    /// </summary>
    private static (CtapAuthenticatorState State, byte StatusCode) ApplyPinMismatch(
        CtapAuthenticatorState state, CtapPinUvAuthProtocolId protocolId, CtapPinUvAuthKeyAgreementKeyPair regeneratedKeyPair)
    {
        int retries = state.PinRetries - 1;
        int mismatches = state.ConsecutivePinMismatches + 1;

        (byte statusCode, bool isLatched) = retries == 0
            ? (WellKnownCtapStatusCodes.PinBlocked, state.IsPowerCycleRequired)
            : mismatches >= 3
                ? (WellKnownCtapStatusCodes.PinAuthBlocked, true)
                : (WellKnownCtapStatusCodes.PinInvalid, state.IsPowerCycleRequired);

        CtapPinUvAuthKeyAgreementKeyPair staleKeyPair = protocolId == CtapPinUvAuthProtocolId.One
            ? state.ProtocolOneKeyAgreementKeyPair
            : state.ProtocolTwoKeyAgreementKeyPair;
        staleKeyPair.Dispose();

        CtapAuthenticatorState nextState = protocolId == CtapPinUvAuthProtocolId.One
            ? state with { ProtocolOneKeyAgreementKeyPair = regeneratedKeyPair, PinRetries = retries, ConsecutivePinMismatches = mismatches, IsPowerCycleRequired = isLatched }
            : state with { ProtocolTwoKeyAgreementKeyPair = regeneratedKeyPair, PinRetries = retries, ConsecutivePinMismatches = mismatches, IsPowerCycleRequired = isLatched };

        return (nextState, statusCode);
    }


    /// <summary>
    /// Evaluates whether <paramref name="value"/> names a PIN/UV auth protocol this authenticator
    /// supports (both <see cref="CtapPinUvAuthProtocolId.One"/> and <see cref="CtapPinUvAuthProtocolId.Two"/>).
    /// </summary>
    private static bool IsSupportedPinUvAuthProtocol(int value) => value is (int)CtapPinUvAuthProtocolId.One or (int)CtapPinUvAuthProtocolId.Two;


    /// <summary>
    /// Selects <paramref name="protocolId"/>'s key-agreement private key, borrowed from
    /// <paramref name="state"/> — the effectful crypto sequence neither copies nor disposes it.
    /// </summary>
    private static PrivateKeyMemory SelectOwnPrivateKey(CtapAuthenticatorState state, CtapPinUvAuthProtocolId protocolId) =>
        protocolId switch
        {
            CtapPinUvAuthProtocolId.One => state.ProtocolOneKeyAgreementKeyPair.PrivateKey,
            CtapPinUvAuthProtocolId.Two => state.ProtocolTwoKeyAgreementKeyPair.PrivateKey,
            _ => throw new NotSupportedException($"Unsupported CTAP PIN/UV auth protocol id '{protocolId}'.")
        };


    /// <summary>
    /// Evaluates <c>getPinUvAuthTokenUsingPinWithPermissions</c>'s permission-statement gate (CTAP 2.3
    /// §6.5.5.7.2, lines 5955-5971): "for each pinUvAuthToken permission present in the permissions
    /// parameter, if the statement corresponding to the permission is currently true, ... return
    /// CTAP2_ERR_UNAUTHORIZED_PERMISSION." Under this profile's <c>authenticatorGetInfo</c> (no
    /// <c>perCredMgmtRO</c> option, and <c>noMcGaPermissionsWithClientPin</c>
    /// absent, but <c>authnrCfg</c>/<c>credMgmt</c>/<c>largeBlobs</c> always advertised true and
    /// <c>bioEnroll</c> always present), <c>pcmr</c>'s statement is the ONLY one unconditionally true and
    /// <c>mc</c>/<c>ga</c>/<c>acfg</c>/<c>cm</c>/<c>be</c>/<c>lbw</c>'s are unconditionally false (line
    /// 5964: "acfg: authnrCfg is false or absent" never holds once <c>authnrCfg:true</c> is always
    /// advertised; line 5958: "cm: credMgmt is false or absent" never holds once <c>credMgmt:true</c> is
    /// always advertised; line 5960: "be: bioEnroll is absent" never holds once <c>bioEnroll</c> is
    /// always present; line 5962: "lbw: largeBlobs is false or absent" never holds once
    /// <c>largeBlobs:true</c> is always advertised, wavelb R4) — so only <see cref="WellKnownCtapPinUvAuthTokenPermissions.Pcmr"/>
    /// can ever deny, and <c>mc</c>/<c>ga</c>/<c>acfg</c>/
    /// <c>cm</c>/<c>be</c>/<c>lbw</c> are always grantable. Undefined bits (for example <c>0x80</c>) are not
    /// examined here at all: the caller masks them out separately when resolving the granted set, never
    /// denying on their account.
    /// </summary>
    /// <returns>
    /// <see cref="WellKnownCtapStatusCodes.UnauthorizedPermission"/> if any denied bit is present;
    /// otherwise <see langword="null"/>.
    /// </returns>
    private static byte? EvaluatePinUvAuthTokenPermissionGate(int requestedPermissions)
    {
        int deniedBits = WellKnownCtapPinUvAuthTokenPermissions.Pcmr;

        return (requestedPermissions & deniedBits) != 0 ? WellKnownCtapStatusCodes.UnauthorizedPermission : null;
    }


    /// <summary>
    /// Declares the <see cref="CtapSignAssertionAction"/> shared by every <c>authenticatorGetAssertion</c>
    /// and <c>authenticatorGetNextAssertion</c> success path, computing the next signature counter and
    /// packaging every value the effect and the response need.
    /// </summary>
    /// <param name="largeBlobKeyRequested">
    /// Whether the platform requested the <c>largeBlobKey</c> extension for this call (CTAP 2.3 §12.3,
    /// already validated by the caller). Resolved here, against THIS specific <paramref name="credential"/>,
    /// to the final response value: <paramref name="credential"/>'s stored key iff requested AND present,
    /// <see langword="null"/> otherwise (line 12867's MUST NOT unsolicited output).
    /// </param>
    /// <param name="hmacSecretInput">
    /// The request's decoded <c>hmac-secret</c> compound extension input, already validated by
    /// <see cref="ContinueGetAssertion"/>'s own steps 1-2, or <see langword="null"/> when absent (or this
    /// is an <c>authenticatorGetNextAssertion</c> continuation — <see cref="OnGetNextAssertionRequested"/>
    /// always passes <see langword="null"/>, since that command carries no request of its own to
    /// re-supply the compound input).
    /// </param>
    /// <param name="hmacSecretProtocol">
    /// The already-resolved (defaulted or validated-supported) protocol <paramref name="hmacSecretInput"/>
    /// uses — non-<see langword="null"/> exactly when <paramref name="hmacSecretInput"/> is.
    /// </param>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> DeclareSignAssertion(
        CtapAuthenticatorState state,
        CtapCredentialRecord credential,
        DigestValue clientDataHash,
        bool userPresent,
        bool userVerified,
        CtapPublicKeyCredentialUserEntity? responseUser,
        int? numberOfCredentials,
        CtapRememberGetAssertionRequest? rememberOnCompletion,
        bool largeBlobKeyRequested,
        CtapGetAssertionHmacSecretInput? hmacSecretInput = null,
        CtapPinUvAuthProtocolId? hmacSecretProtocol = null)
    {
        uint newSignCount = credential.SignCount + 1;

        //Assigned via a nested if rather than a `cond ? credential.LargeBlobKey.Memory : null` ternary:
        //the ternary's "present" branch has type Memory<byte> (IMemoryOwner<byte>.Memory), and Memory<T>'s
        //own implicit conversion to ReadOnlyMemory<T> does not lift correctly across the ternary's null
        //branch — the resulting Nullable<ReadOnlyMemory<byte>> observably has HasValue=true even when the
        //condition is false (verified empirically; the exact class of footgun
        //CtapMakeCredentialRequestCborReader's own extensions-decode remarks document for byte[]). An
        //explicit if-statement assigns the null literal directly to the Nullable<ReadOnlyMemory<byte>>
        //local, with no intervening struct conversion to go wrong.
        ReadOnlyMemory<byte>? largeBlobKeyOutput = null;
        if(largeBlobKeyRequested && credential.LargeBlobKey is IMemoryOwner<byte> largeBlobKey)
        {
            largeBlobKeyOutput = largeBlobKey.Memory;
        }

        //hmac-secret's own crypto request (CTAP 2.3 §12.7 steps 4-9), assembled against THIS resolved
        //credential's own CredRandom pair — CredRandom selection by the response's own uv bit (step 7,
        //trap 4) happens in the effect, not here, since it depends on userVerified which is already known
        //but the effect is where the crypto actually runs.
        CtapGetAssertionHmacSecretRequest? hmacSecretRequest = null;
        if(hmacSecretInput is not null && hmacSecretProtocol is CtapPinUvAuthProtocolId resolvedHmacSecretProtocol)
        {
            hmacSecretRequest = new CtapGetAssertionHmacSecretRequest(
                resolvedHmacSecretProtocol, SelectOwnPrivateKey(state, resolvedHmacSecretProtocol), hmacSecretInput.KeyAgreement,
                hmacSecretInput.SaltEnc, hmacSecretInput.SaltAuth, credential.CredRandomWithUV, credential.CredRandomWithoutUV);
        }

        CtapAuthenticatorState nextState = state with
        {
            NextAction = new CtapSignAssertionAction(
                credential.RpId, credential.CredentialId, credential.CredentialKey, credential.Algorithm,
                newSignCount, userPresent, userVerified, clientDataHash, responseUser, numberOfCredentials, rememberOnCompletion, largeBlobKeyOutput,
                hmacSecretRequest),
            ResponseIntent = null
        };

        return Transition(nextState, "GetAssertion:Requested");
    }


    /// <summary>
    /// Completes <c>authenticatorGetAssertion</c>/<c>authenticatorGetNextAssertion</c> once the effectful
    /// loop has signed the assertion: persists the incremented signature counter back into the
    /// credential-ID-keyed store, and installs a freshly minted remembered sequence when this sign
    /// completed the first response of a multi-account <c>authenticatorGetAssertion</c> — otherwise
    /// preserves whatever <see cref="CtapAuthenticatorState.RememberedGetAssertion"/> already carries
    /// (already advanced in place for an <c>authenticatorGetNextAssertion</c> sign).
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnAssertionSigned(
        CtapAuthenticatorState state, AssertionSigned signed)
    {
        string key = CredentialIdKey(signed.CredentialId);
        CtapCredentialRecord updated = state.CredentialsByCredentialId[key] with { SignCount = signed.NewSignCount };
        ImmutableDictionary<string, CtapCredentialRecord> byId = state.CredentialsByCredentialId.SetItem(key, updated);

        CtapAuthenticatorState nextState = state with
        {
            NextAction = NullAction.Instance,
            CredentialsByCredentialId = byId,
            RememberedGetAssertion = signed.RememberedState ?? state.RememberedGetAssertion,
            ResponseIntent = new GetAssertionResponseReady(signed.Response)
        };

        return Transition(nextState, "GetAssertion:Completed");
    }


    /// <summary>
    /// Completes <c>authenticatorGetAssertion</c>/<c>authenticatorGetNextAssertion</c> once the effectful
    /// loop's <c>hmac-secret</c> crypto sequence (CTAP 2.3 §12.7 steps 4-9) concluded WITHOUT success:
    /// maps <paramref name="failed"/>'s <see cref="GetAssertionHmacSecretFailed.Kind"/> to its status
    /// code (snapshot lines 13304/13307) and rejects the whole command — no assertion was ever signed, so
    /// no store mutation (signature-counter increment, remembered-sequence installation) occurs.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnGetAssertionHmacSecretFailed(
        CtapAuthenticatorState state, GetAssertionHmacSecretFailed failed) =>
        Reject(state, MapHmacSecretOutcomeToStatusCode(failed.Kind), "GetAssertion:HmacSecretFailed");


    /// <summary>
    /// Completes <c>authenticatorMakeCredential</c> once the effectful loop's <c>hmac-secret-mc</c>
    /// crypto delegation (CTAP 2.3 §12.8 snapshot line 13402 — the SAME routine
    /// <see cref="OnGetAssertionHmacSecretFailed"/>'s own <c>hmac-secret</c> crypto sequence runs)
    /// concluded WITHOUT success: maps <paramref name="failed"/>'s
    /// <see cref="MakeCredentialHmacSecretMcFailed.Kind"/> to its status code and rejects the whole
    /// command — no credential is ever minted, since <see cref="CredentialMinted"/> is never produced on
    /// this path.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnMakeCredentialHmacSecretMcFailed(
        CtapAuthenticatorState state, MakeCredentialHmacSecretMcFailed failed) =>
        Reject(state, MapHmacSecretOutcomeToStatusCode(failed.Kind), "MakeCredential:HmacSecretMcFailed");


    /// <summary>
    /// Maps a <see cref="CtapGetAssertionHmacSecretOutcomeKind"/> crypto-sequence failure to its CTAP2
    /// status code (CTAP 2.3 §12.7, snapshot lines 13304/13307) — shared by
    /// <see cref="OnGetAssertionHmacSecretFailed"/> (the ga effect's own crypto sequence) and
    /// <see cref="OnMakeCredentialHmacSecretMcFailed"/> (the mc-time <c>hmac-secret-mc</c> delegation,
    /// contract R6: the SAME crypto routine, so the SAME failure-to-status-code mapping applies).
    /// </summary>
    private static byte MapHmacSecretOutcomeToStatusCode(CtapGetAssertionHmacSecretOutcomeKind kind) => kind switch
    {
        CtapGetAssertionHmacSecretOutcomeKind.VerifyFailed => WellKnownCtapStatusCodes.PinAuthInvalid,
        CtapGetAssertionHmacSecretOutcomeKind.DecryptFailed => WellKnownCtapStatusCodes.InvalidParameter,
        _ => throw new NotSupportedException($"No status code is defined for hmac-secret outcome '{kind}'.")
    };


    /// <summary>
    /// Evaluates CTAP 2.3 section 6.1.2/6.2.2 step 2, the shared <c>pinUvAuthParam</c> protocol-support
    /// guard: a present-but-unsupported-protocol pinUvAuthParam fails with
    /// <see cref="WellKnownCtapStatusCodes.InvalidParameter"/>; a present-pinUvAuthParam-with-absent-protocol
    /// fails with <see cref="WellKnownCtapStatusCodes.MissingParameter"/>; a supported protocol, or an
    /// absent <c>pinUvAuthParam</c> altogether, passes. Callers run this AFTER the zero-length
    /// <c>pinUvAuthParam</c> probe (step 1) has already intercepted every zero-length <c>pinUvAuthParam</c>,
    /// so <paramref name="pinUvAuthParam"/> here is always either absent or non-zero-length.
    /// </summary>
    /// <remarks>
    /// CTAP 2.3, section 6.1.2/6.2.2, step 2: "If the pinUvAuthProtocol parameter's value is not
    /// supported, return CTAP1_ERR_INVALID_PARAMETER error. If the pinUvAuthProtocol parameter is absent,
    /// return CTAP2_ERR_MISSING_PARAMETER error."
    /// </remarks>
    /// <returns>The status code to reject with, or <see langword="null"/> if the guard does not fire.</returns>
    private static byte? EvaluatePinUvAuthGuard(ReadOnlyMemory<byte>? pinUvAuthParam, int? pinUvAuthProtocol)
    {
        if(pinUvAuthParam is null)
        {
            return null;
        }

        if(pinUvAuthProtocol is not int protocolValue)
        {
            return WellKnownCtapStatusCodes.MissingParameter;
        }

        return IsSupportedPinUvAuthProtocol(protocolValue) ? null : WellKnownCtapStatusCodes.InvalidParameter;
    }


    /// <summary>
    /// Evaluates CTAP 2.3's "Protected by some form of User Verification" definition (terminology
    /// section, line 2831-2834): "Either or both clientPin or built-in user verification methods are
    /// supported and enabled" — <c>pinUvAuthToken</c> present-true AND either <c>clientPin</c> or
    /// <c>uv</c> present-true. This authenticator's <c>pinUvAuthToken</c> option is unconditionally
    /// advertised <see langword="true"/> (wave-5a); <c>clientPin</c> is present-true once a PIN is set
    /// (<paramref name="state"/>'s own <see cref="CtapAuthenticatorState.CurrentStoredPin"/>) and
    /// <c>uv</c> is present-true once at least one fingerprint enrollment is provisioned
    /// (<see cref="CtapAuthenticatorState.HasProvisionedBioEnrollments"/>, wavebio R2/R11) — this helper
    /// is the ONE seam feeding both, so the widening propagates to mc/ga's protected-block gates, both
    /// <c>alwaysUv</c> gates, and <c>toggleAlwaysUv</c>'s own token-gate derivation without a second edit
    /// anywhere.
    /// </summary>
    private static bool IsProtectedByUserVerification(CtapAuthenticatorState state) =>
        state.CurrentStoredPin is not null || state.HasProvisionedBioEnrollments;


    /// <summary>
    /// Selects <paramref name="protocolId"/>'s <c>pinUvAuthToken</c> lifecycle state, borrowed from
    /// <paramref name="state"/> — the counterpart read to <see cref="WithPinUvAuthTokenState"/>'s write.
    /// </summary>
    private static CtapPinUvAuthTokenState SelectPinUvAuthTokenState(CtapAuthenticatorState state, CtapPinUvAuthProtocolId protocolId) =>
        protocolId switch
        {
            CtapPinUvAuthProtocolId.One => state.ProtocolOneToken,
            CtapPinUvAuthProtocolId.Two => state.ProtocolTwoToken,
            _ => throw new NotSupportedException($"Unsupported CTAP PIN/UV auth protocol id '{protocolId}'.")
        };


    /// <summary>
    /// Installs <paramref name="token"/> as <paramref name="protocolId"/>'s current <c>pinUvAuthToken</c>
    /// lifecycle state on <paramref name="state"/> — the counterpart write to
    /// <see cref="SelectPinUvAuthTokenState"/>'s read.
    /// </summary>
    private static CtapAuthenticatorState WithPinUvAuthTokenState(CtapAuthenticatorState state, CtapPinUvAuthProtocolId protocolId, CtapPinUvAuthTokenState token) =>
        protocolId switch
        {
            CtapPinUvAuthProtocolId.One => state with { ProtocolOneToken = token },
            CtapPinUvAuthProtocolId.Two => state with { ProtocolTwoToken = token },
            _ => throw new NotSupportedException($"Unsupported CTAP PIN/UV auth protocol id '{protocolId}'.")
        };


    /// <summary>
    /// Applies <see cref="CtapPinUvAuthTokenState.ClearUserPresentFlag"/>,
    /// <see cref="CtapPinUvAuthTokenState.ClearUserVerifiedFlag"/>, and
    /// <see cref="CtapPinUvAuthTokenState.ClearPinUvAuthTokenPermissionsExceptLbw"/> to BOTH PIN/UV auth
    /// protocol tokens — CTAP 2.3's line 5828 permission-stripping rule ("When a pinUvAuthToken is used
    /// with an operation that tests user presence, it is updated to remove all permissions except lbw"),
    /// realized by <c>authenticatorMakeCredential</c> step 14.4 (line 3545) and
    /// <c>authenticatorGetAssertion</c> step 9.4 (line 4098). Each of the three functions is a no-op on
    /// whichever protocol's token is not currently in use (§6.5.3, lines 5199/5205/5211), so applying all
    /// three to both tokens unconditionally is exactly what the spec's own "these functions are no-ops if
    /// there is not an in-use pinUvAuthToken" note (line 3546/4099) already permits.
    /// </summary>
    private static CtapAuthenticatorState ClearPinUvAuthTokenFlags(CtapAuthenticatorState state) =>
        state with
        {
            ProtocolOneToken = state.ProtocolOneToken.ClearUserPresentFlag().ClearUserVerifiedFlag().ClearPinUvAuthTokenPermissionsExceptLbw(),
            ProtocolTwoToken = state.ProtocolTwoToken.ClearUserPresentFlag().ClearUserVerifiedFlag().ClearPinUvAuthTokenPermissionsExceptLbw()
        };


    /// <summary>
    /// <see cref="ClearPinUvAuthTokenFlags"/>, gated on <paramref name="userPresent"/> — the
    /// <c>authenticatorGetAssertion</c>-specific condition (CTAP 2.3 §6.2.2 step 9: "If the 'up' option
    /// is set to true or not present") that <c>authenticatorMakeCredential</c> does not need, since its
    /// own <c>up: false</c> request is already rejected in the request arm (step 5.6), making <c>up</c>
    /// unconditionally true by the time its own continuation runs.
    /// </summary>
    private static CtapAuthenticatorState ApplyPinUvAuthTokenFlagClearingIfUserPresent(CtapAuthenticatorState state, bool userPresent) =>
        userPresent ? ClearPinUvAuthTokenFlags(state) : state;


    /// <summary>
    /// Dispatches a <see cref="PinUvAuthTokenVerified"/> fold-back to the interrupted command's own
    /// remaining sequence, by <see cref="PinUvAuthTokenVerified.Continuation"/>'s runtime type.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnPinUvAuthTokenVerified(
        CtapAuthenticatorState state, PinUvAuthTokenVerified verified) =>
        verified.Continuation switch
        {
            CtapMakeCredentialVerifyContinuation makeCredential => OnMakeCredentialPinUvAuthTokenVerified(state, verified.Verified, makeCredential.Requested, makeCredential.EnterpriseAttestationGranted),
            CtapGetAssertionVerifyContinuation getAssertion => OnGetAssertionPinUvAuthTokenVerified(state, verified.Verified, getAssertion.Requested),
            CtapAuthenticatorConfigVerifyContinuation authenticatorConfig => OnAuthenticatorConfigPinUvAuthTokenVerified(state, verified.Verified, authenticatorConfig.Requested),
            CtapCredentialManagementVerifyContinuation credentialManagement => OnCredentialManagementPinUvAuthTokenVerified(state, verified.Verified, credentialManagement.Requested),
            CtapBioEnrollmentVerifyContinuation bioEnrollment => OnBioEnrollmentPinUvAuthTokenVerified(state, verified.Verified, bioEnrollment.Requested),
            CtapLargeBlobsVerifyContinuation largeBlobs => OnLargeBlobsPinUvAuthTokenVerified(state, verified.Verified, largeBlobs),
            _ => throw new NotSupportedException($"No pinUvAuthToken verification continuation is defined for '{verified.Continuation.GetType().Name}'.")
        };


    /// <summary>
    /// Resolves the attestation statement shape an <c>authenticatorMakeCredential</c> effect must produce
    /// from the request's <c>attestationFormatsPreference</c> (CTAP 2.3, section 6.1.2, step 17). This
    /// simulator supports exactly two formats, <c>packed</c> (self-attestation) and <c>none</c>, and
    /// implements the step's own three-bullet order: an absent or empty preference draws the
    /// authenticator's own default (<see cref="CtapAttestationFormatChoice.PackedSelf"/>); a preference
    /// list containing only the single entry <c>"none"</c> triggers the step's "omit attestation from the
    /// output" instruction (<see cref="CtapAttestationFormatChoice.NoneOmitted"/>) — checked independently
    /// of whether this authenticator supports multiple formats, per the step's own wording; any other
    /// present preference list is walked in order for the lowest-index entry naming a supported format,
    /// falling back to <see cref="CtapAttestationFormatChoice.PackedSelf"/> (this authenticator's chosen
    /// "any other means") when nothing on the list is supported.
    /// </summary>
    private static CtapAttestationFormatChoice ResolveAttestationFormat(IReadOnlyList<string>? attestationFormatsPreference)
    {
        if(attestationFormatsPreference is null || attestationFormatsPreference.Count == 0)
        {
            return CtapAttestationFormatChoice.PackedSelf;
        }

        if(attestationFormatsPreference.Count == 1 && attestationFormatsPreference[0] == WellKnownWebAuthnAttestationFormats.None)
        {
            return CtapAttestationFormatChoice.NoneOmitted;
        }

        foreach(string candidate in attestationFormatsPreference)
        {
            if(candidate == WellKnownWebAuthnAttestationFormats.Packed)
            {
                return CtapAttestationFormatChoice.PackedSelf;
            }

            if(candidate == WellKnownWebAuthnAttestationFormats.None)
            {
                return CtapAttestationFormatChoice.NoneWithStatement;
            }
        }

        return CtapAttestationFormatChoice.PackedSelf;
    }


    /// <summary>
    /// Locates the first credential <paramref name="excludeList"/> names that this authenticator already
    /// holds for <paramref name="rpId"/> AND that is not exempted from exclusion (CTAP 2.3, section
    /// 6.1.2, step 12: "the excludeList parameter is present and contains a credential ID created by
    /// this authenticator, that is bound to the specified rp.id"; lines 3441-3499's credProtect-aware
    /// branch). A level-<see cref="CredProtectUserVerificationRequired"/> match with NO
    /// <paramref name="userVerified"/> collected in this same call is the exempted case (lines 3497-3498:
    /// "remove the credential from the excludeList and continue parsing the rest of the list") — this
    /// scan skips such an entry and keeps looking, so a LATER entry naming a level-1/2 (or UV-collected
    /// level-3) credential for the same <paramref name="rpId"/> still yields a match. Returns
    /// <see langword="null"/> only when the list contains no match at all, or when every match found is
    /// exempted; <see cref="ContinueMakeCredential"/> excludes unconditionally on any non-null result.
    /// </summary>
    private static CtapCredentialRecord? ExcludeListHasMatch(
        IReadOnlyList<PublicKeyCredentialDescriptor>? excludeList, string rpId, ImmutableDictionary<string, CtapCredentialRecord> credentialsByCredentialId,
        bool userVerified)
    {
        if(excludeList is null)
        {
            return null;
        }

        foreach(PublicKeyCredentialDescriptor descriptor in excludeList)
        {
            if(credentialsByCredentialId.TryGetValue(CredentialIdKey(descriptor.Id), out CtapCredentialRecord? record)
                && string.Equals(record.RpId, rpId, StringComparison.Ordinal))
            {
                bool isExemptedLevelThreeMatch = record.CredProtectLevel == CredProtectUserVerificationRequired && !userVerified;
                if(!isExemptedLevelThreeMatch)
                {
                    return record;
                }
            }
        }

        return null;
    }


    /// <summary>
    /// Determines whether <paramref name="rpId"/> is present on <paramref name="minPinLengthRpIds"/> —
    /// the <c>minPinLength</c> extension's own authorization check (CTAP 2.3 §12.5, lines 12998-13000:
    /// "checks whether the... rp.id parameter is present on its minPinLengthRPIDs list").
    /// </summary>
    private static bool IsRpIdAuthorizedForMinPinLength(IReadOnlyList<string> minPinLengthRpIds, string rpId)
    {
        foreach(string authorizedRpId in minPinLengthRpIds)
        {
            if(string.Equals(authorizedRpId, rpId, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Determines whether <paramref name="rpId"/> matches an entry on <paramref name="preConfiguredRpIds"/>
    /// — mc Step 9's own vendor-facilitated gate (CTAP 2.3 §7.1, lines 3341-3345: "the request's rp.id
    /// matches an entry on the authenticator's pre-configured RP ID list"). Mirrors
    /// <see cref="IsRpIdAuthorizedForMinPinLength"/>'s identical membership-check shape over a different
    /// (constructor-fixed, never runtime-settable, trap 8) list.
    /// </summary>
    private static bool IsRpIdOnPreConfiguredList(IReadOnlyList<string> preConfiguredRpIds, string rpId)
    {
        foreach(string listedRpId in preConfiguredRpIds)
        {
            if(string.Equals(listedRpId, rpId, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Locates the credential an <c>allowList</c>-present <c>authenticatorGetAssertion</c> request
    /// resolves to (CTAP 2.3, section 6.2.2, step 7): the first denoted credential this authenticator
    /// holds for the request's <c>rpId</c>, regardless of discoverability.
    /// </summary>
    private static CtapCredentialRecord? LocateAllowListCredential(CtapAuthenticatorState state, CtapGetAssertionRequest request)
    {
        foreach(PublicKeyCredentialDescriptor descriptor in request.AllowList!)
        {
            if(state.CredentialsByCredentialId.TryGetValue(CredentialIdKey(descriptor.Id), out CtapCredentialRecord? record)
                && string.Equals(record.RpId, request.RpId, StringComparison.Ordinal))
            {
                return record;
            }
        }

        return null;
    }


    /// <summary>
    /// Locates every resident credential this authenticator holds for <paramref name="rpId"/> — the
    /// applicable-credentials list an <c>allowList</c>-absent <c>authenticatorGetAssertion</c> resolves to
    /// (CTAP 2.3, section 6.2.2, step 7) — ordered most-recently-created first (section 6.2, step 12:
    /// "order the credentials... by the time when they were created in reverse order").
    /// </summary>
    private static List<CtapCredentialRecord> LocateApplicableResidentCredentials(CtapAuthenticatorState state, string rpId)
    {
        List<CtapCredentialRecord> applicable = [];
        foreach(CtapCredentialRecord candidate in state.CredentialsByCredentialId.Values)
        {
            if(candidate.IsResident && string.Equals(candidate.RpId, rpId, StringComparison.Ordinal))
            {
                applicable.Add(candidate);
            }
        }

        applicable.Sort(static (left, right) => right.CreationSequence.CompareTo(left.CreationSequence));

        return applicable;
    }


    /// <summary>
    /// Determines whether <paramref name="credential"/> must be treated as not found because it is
    /// protected at level <see cref="CredProtectUserVerificationRequired"/> and <paramref name="userVerified"/>
    /// is <see langword="false"/> (CTAP 2.3 §12.1, lines 4040-4043) — the ONE filter shared by both
    /// <c>authenticatorGetAssertion</c> credential-location branches (R10). Level
    /// <see cref="CredProtectUserVerificationOptionalWithCredentialIdList"/> is NEVER excluded by this
    /// predicate: its own filter (lines 4045-4048) applies only to the discoverable-scan branch — see
    /// <see cref="FilterUnverifiedCredProtectFromDiscoverableScan"/> — never to an <c>allowList</c>-resolved
    /// credential, which already proves the platform's own knowledge of the specific credential ID.
    /// </summary>
    private static bool IsCredProtectLevelThreeUvExcluded(CtapCredentialRecord credential, bool userVerified) =>
        credential.CredProtectLevel == CredProtectUserVerificationRequired && !userVerified;


    /// <summary>
    /// Filters <paramref name="applicable"/> for the discoverable-scan (no-<c>allowList</c>)
    /// <c>authenticatorGetAssertion</c> branch (CTAP 2.3 §12.1, lines 4038-4048, R10): removes every
    /// <see cref="CredProtectUserVerificationRequired"/> credential (shared with the <c>allowList</c>
    /// branch via <see cref="IsCredProtectLevelThreeUvExcluded"/>) AND every
    /// <see cref="CredProtectUserVerificationOptionalWithCredentialIdList"/> credential (this branch's
    /// OWN additional filter, never applied to the <c>allowList</c> branch) whenever <paramref name="userVerified"/>
    /// is <see langword="false"/>. Returns <paramref name="applicable"/> unfiltered when
    /// <paramref name="userVerified"/> is <see langword="true"/> — neither filter's antecedent holds.
    /// </summary>
    private static List<CtapCredentialRecord> FilterUnverifiedCredProtectFromDiscoverableScan(List<CtapCredentialRecord> applicable, bool userVerified)
    {
        if(userVerified)
        {
            return applicable;
        }

        List<CtapCredentialRecord> filtered = new(applicable.Count);
        foreach(CtapCredentialRecord candidate in applicable)
        {
            bool isLevelTwoUvLessDiscoverableExcluded = candidate.CredProtectLevel == CredProtectUserVerificationOptionalWithCredentialIdList;
            if(!IsCredProtectLevelThreeUvExcluded(candidate, userVerified) && !isLevelTwoUvLessDiscoverableExcluded)
            {
                filtered.Add(candidate);
            }
        }

        return filtered;
    }


    /// <summary>
    /// Finds the resident credential already stored for the pair (<paramref name="rpId"/>,
    /// <paramref name="userId"/>), if any — the overwrite target a resident
    /// <c>authenticatorMakeCredential</c> registration for that same pair replaces (CTAP 2.3, section
    /// 6.1.2, step 16), and the exemption from the capacity check that overwrite receives.
    /// </summary>
    private static CtapCredentialRecord? FindResidentCredential(
        ImmutableDictionary<string, CtapCredentialRecord> credentialsByCredentialId, string rpId, UserHandle userId)
    {
        foreach(CtapCredentialRecord candidate in credentialsByCredentialId.Values)
        {
            if(candidate.IsResident && candidate.UserId == userId && string.Equals(candidate.RpId, rpId, StringComparison.Ordinal))
            {
                return candidate;
            }
        }

        return null;
    }


    /// <summary>
    /// Counts every resident credential currently in the store, for the
    /// <see cref="CtapAuthenticatorState.ResidentCredentialCapacity"/> comparison
    /// <c>authenticatorMakeCredential</c>'s key-store-full decision makes.
    /// </summary>
    private static int CountResidentCredentials(ImmutableDictionary<string, CtapCredentialRecord> credentialsByCredentialId)
    {
        int count = 0;
        foreach(CtapCredentialRecord candidate in credentialsByCredentialId.Values)
        {
            if(candidate.IsResident)
            {
                count++;
            }
        }

        return count;
    }


    /// <summary>
    /// The credential store's dictionary key for a <see cref="CredentialId"/>: a lowercase-hex encoding of
    /// its bytes, so the store need not depend on <see cref="CredentialId"/>'s own equality/hash-code
    /// contract for dictionary correctness.
    /// </summary>
    private static string CredentialIdKey(CredentialId credentialId) => Convert.ToHexStringLower(credentialId.AsReadOnlySpan());


    /// <summary>
    /// The pure entry point for <c>authenticatorBioEnrollment</c> (CTAP 2.3 §6.7, bio scout §1.4-§1.6/R12),
    /// in spec dispatch order: (1) <c>getModality:true</c> serves the token-free bio-modality read
    /// IMMEDIATELY (modality = fingerprint) — WINS over any accompanying <c>subCommand</c> (a documented
    /// posture over the spec's own silence on the mixed-member case, snapshot line 6417's own MUST binds
    /// only the platform's SEND value; a <c>getModality:false</c> request is treated as the member being
    /// absent, not an error); (2) neither <c>getModality:true</c> nor a <c>subCommand</c> at all →
    /// <see cref="WellKnownCtapStatusCodes.MissingParameter"/> (the general mandatory-params disposition
    /// — the nearest family precedent, since §6.7 itself names no top-level "nothing was requested"
    /// status); (3) the three token-free subcommands — <c>getFingerprintSensorInfo</c> (returns the fixed
    /// sensor statics) and <c>cancelCurrentEnrollment</c> (unconditionally
    /// <see cref="WellKnownCtapStatusCodes.Ok"/>, snapshot line 6799 names no error path at all; discards
    /// any in-progress capture slot) — are served without ANY authentication (bio scout Finding 5/trap 7);
    /// (4) every other <c>subCommand</c> value not one of the five <c>be</c>-permission-gated subcommands
    /// answers <see cref="WellKnownCtapStatusCodes.InvalidSubcommand"/> (credMgmt's allow-list precedent);
    /// (5) the five gated subcommands (<c>enrollBegin</c>/<c>enrollCaptureNextSample</c>/
    /// <c>enumerateEnrollments</c>/<c>setFriendlyName</c>/<c>removeEnrollment</c>) run the preamble in
    /// spec order: <c>pinUvAuthParam</c> missing → <see cref="WellKnownCtapStatusCodes.PuatRequired"/> →
    /// per-subcommand mandatory params, INCLUDING <c>modality</c> on every gated flow, via
    /// <see cref="EvaluateMandatoryBioEnrollmentParams"/> → <see cref="WellKnownCtapStatusCodes.MissingParameter"/>
    /// → <c>modality</c> present but not <see cref="WellKnownCtapBioEnrollmentModalities.Fingerprint"/> →
    /// <see cref="WellKnownCtapStatusCodes.InvalidParameter"/> (documented posture over spec silence) →
    /// <c>pinUvAuthProtocol</c> missing → <see cref="WellKnownCtapStatusCodes.MissingParameter"/> →
    /// protocol unsupported → <see cref="WellKnownCtapStatusCodes.InvalidParameter"/> →
    /// <c>setFriendlyName</c> ONLY: the friendly-name byte-length check runs HERE, BEFORE <c>verify()</c>
    /// (bio scout Finding 7/trap 5 — the pre-auth ordering is spec-mandated by §6.7.7's own step order,
    /// snapshot lines 6874-6892; <see cref="WellKnownCtapStatusCodes.InvalidLength"/> is the spec's own
    /// "e.g." example, adopted as this profile's documented choice) → declares
    /// <see cref="CtapVerifyBioEnrollmentTokenAction"/> (bio scout Finding C: the TWO-byte
    /// <c>modality || subCommand [|| subCommandParams]</c> verify-message prefix, distinct from every
    /// other command's own verify-message shape), resumed by <see cref="OnBioEnrollmentPinUvAuthTokenVerified"/>.
    /// <c>enrollCaptureNextSample</c> is NOT a GetNext-style pre-verified continuation (R7): every call
    /// runs this SAME full preamble, re-verifying its own <c>pinUvAuthParam</c> — only the capture
    /// PROGRESS is remembered on <see cref="CtapAuthenticatorState.RememberedBioEnrollment"/>, never the
    /// authorization.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnBioEnrollmentRequested(
        CtapAuthenticatorState state, BioEnrollmentRequested requested)
    {
        state = DiscardAllRememberedSequences(state);

        CtapBioEnrollmentRequest request = requested.Request;

        if(request.GetModality == true)
        {
            return Respond(
                state,
                new BioEnrollmentResponseReady(new CtapBioEnrollmentResponse(Modality: WellKnownCtapBioEnrollmentModalities.Fingerprint)),
                "BioEnrollment:GetModality");
        }

        if(request.SubCommand is not int subCommand)
        {
            return Reject(state, WellKnownCtapStatusCodes.MissingParameter, "BioEnrollment:MissingSubCommandOrGetModality");
        }

        if(WellKnownCtapBioEnrollmentSubCommands.IsGetFingerprintSensorInfo(subCommand))
        {
            return Respond(
                state,
                new BioEnrollmentResponseReady(new CtapBioEnrollmentResponse(
                    FingerprintKind: CtapAuthenticatorState.FingerprintKind,
                    MaxCaptureSamplesRequiredForEnroll: CtapAuthenticatorState.MaxCaptureSamplesRequiredForEnroll,
                    MaxTemplateFriendlyName: CtapAuthenticatorState.MaxTemplateFriendlyNameByteLength)),
                "BioEnrollment:GetFingerprintSensorInfo");
        }

        if(WellKnownCtapBioEnrollmentSubCommands.IsCancelCurrentEnrollment(subCommand))
        {
            return Respond(DiscardRememberedBioEnrollment(state), new BioEnrollmentResponseReady(null), "BioEnrollment:CancelCurrentEnrollment");
        }

        bool isSupportedGatedSubCommand = WellKnownCtapBioEnrollmentSubCommands.IsEnrollBegin(subCommand)
            || WellKnownCtapBioEnrollmentSubCommands.IsEnrollCaptureNextSample(subCommand)
            || WellKnownCtapBioEnrollmentSubCommands.IsEnumerateEnrollments(subCommand)
            || WellKnownCtapBioEnrollmentSubCommands.IsSetFriendlyName(subCommand)
            || WellKnownCtapBioEnrollmentSubCommands.IsRemoveEnrollment(subCommand);
        if(!isSupportedGatedSubCommand)
        {
            return Reject(state, WellKnownCtapStatusCodes.InvalidSubcommand, "BioEnrollment:UnsupportedSubCommand");
        }

        if(request.PinUvAuthParam is not ReadOnlyMemory<byte> pinUvAuthParam)
        {
            return Reject(state, WellKnownCtapStatusCodes.PuatRequired, "BioEnrollment:PuatRequired");
        }

        byte? missingParameterStatus = EvaluateMandatoryBioEnrollmentParams(subCommand, request);
        if(missingParameterStatus is byte missingStatus)
        {
            return Reject(state, missingStatus, "BioEnrollment:MissingParameter");
        }

        if(!WellKnownCtapBioEnrollmentModalities.IsFingerprint(request.Modality!.Value))
        {
            return Reject(state, WellKnownCtapStatusCodes.InvalidParameter, "BioEnrollment:UnsupportedModality");
        }

        if(request.PinUvAuthProtocol is not int protocolValue)
        {
            return Reject(state, WellKnownCtapStatusCodes.MissingParameter, "BioEnrollment:MissingProtocol");
        }

        if(!IsSupportedPinUvAuthProtocol(protocolValue))
        {
            return Reject(state, WellKnownCtapStatusCodes.InvalidParameter, "BioEnrollment:UnsupportedProtocol");
        }

        if(WellKnownCtapBioEnrollmentSubCommands.IsSetFriendlyName(subCommand))
        {
            int friendlyNameByteLength = request.TemplateFriendlyName is string friendlyName ? Encoding.UTF8.GetByteCount(friendlyName) : 0;
            if(friendlyNameByteLength > CtapAuthenticatorState.MaxTemplateFriendlyNameByteLength)
            {
                return Reject(state, WellKnownCtapStatusCodes.InvalidLength, "BioEnrollment:FriendlyNameTooLong");
            }
        }

        CtapPinUvAuthProtocolId protocolId = (CtapPinUvAuthProtocolId)protocolValue;
        CtapPinUvAuthTokenState presentedToken = SelectPinUvAuthTokenState(state, protocolId).EvaluateExpiry(requested.Now);
        state = WithPinUvAuthTokenState(state, protocolId, presentedToken);

        CtapAuthenticatorState nextState = state with
        {
            NextAction = new CtapVerifyBioEnrollmentTokenAction(
                protocolId, presentedToken, request.Modality!.Value, subCommand,
                request.SubCommandParams ?? ReadOnlyMemory<byte>.Empty, pinUvAuthParam,
                new CtapBioEnrollmentVerifyContinuation(requested)),
            ResponseIntent = null
        };

        return Transition(nextState, "BioEnrollment:VerifyPinUvAuthToken");
    }


    /// <summary>
    /// Evaluates the gated subcommands' per-subcommand mandatory-parameter requirement (CTAP 2.3 §6.7.4-
    /// §6.7.8, each gated subcommand's own step 2): <c>modality</c> is mandatory on every gated flow (bio
    /// scout R12); <c>enrollCaptureNextSample</c> additionally requires <c>templateId</c>;
    /// <c>setFriendlyName</c> additionally requires BOTH <c>templateId</c> AND <c>templateFriendlyName</c>;
    /// <c>removeEnrollment</c> additionally requires <c>templateId</c>; <c>enrollBegin</c>/
    /// <c>enumerateEnrollments</c> need nothing beyond the envelope's own <c>modality</c>.
    /// </summary>
    /// <param name="subCommand">The requested subCommand.</param>
    /// <param name="request">The decoded request to check.</param>
    /// <returns><see cref="WellKnownCtapStatusCodes.MissingParameter"/> if a mandatory member is absent; otherwise <see langword="null"/>.</returns>
    private static byte? EvaluateMandatoryBioEnrollmentParams(int subCommand, CtapBioEnrollmentRequest request)
    {
        if(request.Modality is null)
        {
            return WellKnownCtapStatusCodes.MissingParameter;
        }

        if(WellKnownCtapBioEnrollmentSubCommands.IsEnrollCaptureNextSample(subCommand) && request.TemplateId is null)
        {
            return WellKnownCtapStatusCodes.MissingParameter;
        }

        if(WellKnownCtapBioEnrollmentSubCommands.IsSetFriendlyName(subCommand) && (request.TemplateId is null || request.TemplateFriendlyName is null))
        {
            return WellKnownCtapStatusCodes.MissingParameter;
        }

        if(WellKnownCtapBioEnrollmentSubCommands.IsRemoveEnrollment(subCommand) && request.TemplateId is null)
        {
            return WellKnownCtapStatusCodes.MissingParameter;
        }

        return null;
    }


    /// <summary>
    /// Completes an <c>authenticatorBioEnrollment</c> whose presented <c>pinUvAuthParam</c> has been
    /// verified: verify (already run by the executor) → the <c>be</c> permission bit (bio scout Finding B
    /// — the PIN-path unauthorized-gate antecedent, snapshot line 5960, is the ONLY reachable gate this
    /// profile has) → dispatch to the requested subcommand's own handler.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnBioEnrollmentPinUvAuthTokenVerified(
        CtapAuthenticatorState state, bool verified, BioEnrollmentRequested requested)
    {
        if(!verified)
        {
            return Reject(state, WellKnownCtapStatusCodes.PinAuthInvalid, "BioEnrollment:VerifyFailed");
        }

        CtapBioEnrollmentRequest request = requested.Request;
        CtapPinUvAuthProtocolId protocolId = (CtapPinUvAuthProtocolId)request.PinUvAuthProtocol!.Value;
        CtapPinUvAuthTokenState token = SelectPinUvAuthTokenState(state, protocolId);

        if((token.Permissions & WellKnownCtapPinUvAuthTokenPermissions.Be) == 0)
        {
            return Reject(state, WellKnownCtapStatusCodes.PinAuthInvalid, "BioEnrollment:BePermissionDenied");
        }

        token = token with { LastUsedAt = requested.Now };
        state = WithPinUvAuthTokenState(state, protocolId, token);

        return InvokeBioEnrollmentSubCommand(state, request);
    }


    /// <summary>
    /// Dispatches to the requested gated subcommand's own handler, after step 5's <c>be</c> permission
    /// check. The final <see langword="throw"/> is unreachable — <see cref="OnBioEnrollmentRequested"/>'s
    /// own allow-list already rejected every value besides these five before either fold-back path could
    /// reach here.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> InvokeBioEnrollmentSubCommand(
        CtapAuthenticatorState state, CtapBioEnrollmentRequest request)
    {
        int subCommand = request.SubCommand!.Value;

        if(WellKnownCtapBioEnrollmentSubCommands.IsEnrollBegin(subCommand))
        {
            return OnEnrollBeginRequested(state);
        }

        if(WellKnownCtapBioEnrollmentSubCommands.IsEnrollCaptureNextSample(subCommand))
        {
            return OnEnrollCaptureNextSampleRequested(state, request);
        }

        if(WellKnownCtapBioEnrollmentSubCommands.IsEnumerateEnrollments(subCommand))
        {
            return OnEnumerateBioEnrollmentsRequested(state);
        }

        if(WellKnownCtapBioEnrollmentSubCommands.IsSetFriendlyName(subCommand))
        {
            return OnSetBioEnrollmentFriendlyNameRequested(state, request);
        }

        if(WellKnownCtapBioEnrollmentSubCommands.IsRemoveEnrollment(subCommand))
        {
            return OnRemoveBioEnrollmentRequested(state, request);
        }

        throw new NotSupportedException($"authenticatorBioEnrollment subCommand '{subCommand}' reached subcommand dispatch unsupported.");
    }


    /// <summary>
    /// <c>enrollBegin</c> (CTAP 2.3 §6.7.4, steps 6-9): the storage-space check (step 6, snapshot line
    /// 6711) → <see cref="WellKnownCtapStatusCodes.FpDatabaseFull"/> runs BEFORE the auto-cancel of any
    /// unfinished enrollment (step 7, snapshot line 6713, "The authenticator cancels any unfinished
    /// ongoing enrollment" — NOT an error, disposing its not-yet-persisted template identifier) — the
    /// snapshot's own literal step order, followed exactly rather than the contract's own prose (which
    /// states the reverse order; the two checks read disjoint state — the count of PERSISTED templates
    /// versus the in-progress capture slot — so their relative order has no observable effect, and the
    /// snapshot's literal order governs); otherwise declares <see cref="CtapBeginBioEnrollmentCaptureAction"/>
    /// (steps 8-9: mint a fresh templateId, capture the first sample), resumed by
    /// <see cref="OnBioEnrollmentCaptureStarted"/>.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnEnrollBeginRequested(CtapAuthenticatorState state)
    {
        if(state.BioEnrollmentTemplatesByTemplateId.Count >= CtapAuthenticatorState.MaxEnrolledTemplatesCapacity)
        {
            return Reject(state, WellKnownCtapStatusCodes.FpDatabaseFull, "BioEnrollment:EnrollBeginDatabaseFull");
        }

        state = DiscardRememberedBioEnrollment(state);

        CtapAuthenticatorState nextState = state with { NextAction = new CtapBeginBioEnrollmentCaptureAction(), ResponseIntent = null };

        return Transition(nextState, "BioEnrollment:EnrollBeginCapture");
    }


    /// <summary>
    /// <c>enrollCaptureNextSample</c> (CTAP 2.3 §6.7.4): no enrollment currently in progress, or the
    /// request's own <c>templateId</c> does not match the in-progress one, →
    /// <see cref="WellKnownCtapStatusCodes.InvalidOption"/> — a DOCUMENTED profile posture over genuine
    /// spec silence (bio scout trap 6; the spec never states this authenticator's behavior for either
    /// case), mirroring the in-family "no enrollment for the passed templateId" analogues
    /// (<c>setFriendlyName</c>/<c>removeEnrollment</c>, snapshot lines 6890/6936). The snapshot's own
    /// algorithm ALSO names a storage-space check here (line 6771: "If there is no space available,
    /// authenticator returns CTAP2_ERR_FP_DATABASE_FULL") — the contract's own R12 text scopes
    /// <c>FpDatabaseFull</c> to <c>enrollBegin</c> only, but the snapshot's literal per-subcommand
    /// algorithm names it on THIS subcommand too, so it is implemented spec-exact here as well. It is
    /// PROVABLY UNREACHABLE in this profile: <c>enrollBegin</c>'s own gate already denies admission
    /// whenever <see cref="CtapAuthenticatorState.BioEnrollmentTemplatesByTemplateId"/> is at capacity,
    /// and this profile allows at most ONE in-progress enrollment at a time (auto-cancel forecloses a
    /// second), so the persisted count can never grow between a successful <c>enrollBegin</c> and this
    /// enrollment's own eventual completion — matching R11's own "documented unreachable arm" precedent
    /// (no test asserts this arm fires). Otherwise declares <see cref="CtapContinueBioEnrollmentCaptureAction"/>,
    /// resumed by <see cref="OnBioEnrollmentSampleCaptured"/>.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnEnrollCaptureNextSampleRequested(
        CtapAuthenticatorState state, CtapBioEnrollmentRequest request)
    {
        CtapRememberedBioEnrollmentState? remembered = state.RememberedBioEnrollment;
        if(remembered is null || !remembered.TemplateId.AsReadOnlySpan().SequenceEqual(request.TemplateId!.Value.Span))
        {
            return Reject(state, WellKnownCtapStatusCodes.InvalidOption, "BioEnrollment:CaptureNextNoMatchingEnrollment");
        }

        if(state.BioEnrollmentTemplatesByTemplateId.Count >= CtapAuthenticatorState.MaxEnrolledTemplatesCapacity)
        {
            return Reject(state, WellKnownCtapStatusCodes.FpDatabaseFull, "BioEnrollment:EnrollCaptureNextDatabaseFull");
        }

        CtapAuthenticatorState nextState = state with { NextAction = new CtapContinueBioEnrollmentCaptureAction(), ResponseIntent = null };

        return Transition(nextState, "BioEnrollment:EnrollCaptureNextCapture");
    }


    /// <summary>
    /// Folds back <see cref="CtapBeginBioEnrollmentCaptureAction"/>'s effect (CTAP 2.3 §6.7.4, steps
    /// 8-10): installs the freshly minted template identifier as a new
    /// <see cref="CtapAuthenticatorState.RememberedBioEnrollment"/> sequence, its own
    /// <c>remainingSamples</c> resolved from the first capture's outcome (GOOD → one sample consumed;
    /// otherwise unchanged, bio scout Finding 9), and responds with <c>templateId</c>/
    /// <c>lastEnrollSampleStatus</c>/<c>remainingSamples</c> — <c>enrollBegin</c>'s own response is the
    /// ONLY bioEnroll response that ever carries <c>templateId</c> (<see cref="WellKnownCtapBioEnrollmentResponseKeys.TemplateId"/>).
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnBioEnrollmentCaptureStarted(
        CtapAuthenticatorState state, BioEnrollmentCaptureStarted started)
    {
        int remainingSamples = WellKnownCtapLastEnrollSampleStatuses.IsGood(started.LastEnrollSampleStatus)
            ? CtapAuthenticatorState.MaxCaptureSamplesRequiredForEnroll - 1
            : CtapAuthenticatorState.MaxCaptureSamplesRequiredForEnroll;

        CtapAuthenticatorState nextState = state with
        {
            RememberedBioEnrollment = new CtapRememberedBioEnrollmentState(started.TemplateId, remainingSamples)
        };

        CtapBioEnrollmentResponse response = new(
            TemplateId: started.TemplateId.AsReadOnlyMemory(),
            LastEnrollSampleStatus: started.LastEnrollSampleStatus,
            RemainingSamples: remainingSamples);

        return Respond(nextState, new BioEnrollmentResponseReady(response), "BioEnrollment:EnrollBeginCaptured");
    }


    /// <summary>
    /// Folds back <see cref="CtapContinueBioEnrollmentCaptureAction"/>'s effect (CTAP 2.3 §6.7.4):
    /// advances <see cref="CtapAuthenticatorState.RememberedBioEnrollment"/>'s own <c>remainingSamples</c>
    /// on a GOOD capture only (bio scout Finding 9 — a non-GOOD capture leaves it unchanged, still a
    /// successful <see cref="WellKnownCtapStatusCodes.Ok"/> response); once <c>remainingSamples</c> reaches
    /// zero, persists the completed template (friendly name <see langword="null"/> until
    /// <c>setFriendlyName</c> assigns one — the <see cref="CtapRememberedBioEnrollmentState.TemplateId"/>
    /// ownership transfers into the new <see cref="CtapBioEnrollmentTemplateRecord"/>) and clears the
    /// slot; otherwise keeps the slot with the updated count. Neither response carries <c>templateId</c>
    /// (§6.7.4's own continuation response field list omits it, snapshot lines 6777-6783: only
    /// <c>lastEnrollSampleStatus</c> and <c>remainingSamples</c> are named).
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnBioEnrollmentSampleCaptured(
        CtapAuthenticatorState state, BioEnrollmentSampleCaptured captured)
    {
        CtapRememberedBioEnrollmentState remembered = state.RememberedBioEnrollment!;

        int remainingSamples = WellKnownCtapLastEnrollSampleStatuses.IsGood(captured.LastEnrollSampleStatus)
            ? remembered.RemainingSamples - 1
            : remembered.RemainingSamples;

        if(remainingSamples <= 0)
        {
            string templateKey = BioEnrollmentTemplateKey(remembered.TemplateId);
            CtapBioEnrollmentTemplateRecord record = new(remembered.TemplateId, FriendlyName: null);

            CtapAuthenticatorState completedState = state with
            {
                BioEnrollmentTemplatesByTemplateId = state.BioEnrollmentTemplatesByTemplateId.Add(templateKey, record),
                RememberedBioEnrollment = null
            };

            CtapBioEnrollmentResponse completedResponse = new(LastEnrollSampleStatus: captured.LastEnrollSampleStatus, RemainingSamples: 0);

            return Respond(completedState, new BioEnrollmentResponseReady(completedResponse), "BioEnrollment:EnrollCaptureNextCompleted");
        }

        CtapAuthenticatorState advancedState = state with { RememberedBioEnrollment = remembered with { RemainingSamples = remainingSamples } };
        CtapBioEnrollmentResponse advancedResponse = new(LastEnrollSampleStatus: captured.LastEnrollSampleStatus, RemainingSamples: remainingSamples);

        return Respond(advancedState, new BioEnrollmentResponseReady(advancedResponse), "BioEnrollment:EnrollCaptureNextAdvanced");
    }


    /// <summary>
    /// <c>enumerateEnrollments</c> (CTAP 2.3 §6.7.6): zero provisioned templates →
    /// <see cref="WellKnownCtapStatusCodes.InvalidOption"/> — the spec's own exact code here, NOT a
    /// "not found" invention (snapshot line 6836); otherwise responds with every provisioned template's
    /// REAL persisted identifier and friendly name as <c>templateInfos</c>.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnEnumerateBioEnrollmentsRequested(CtapAuthenticatorState state)
    {
        if(state.BioEnrollmentTemplatesByTemplateId.IsEmpty)
        {
            return Reject(state, WellKnownCtapStatusCodes.InvalidOption, "BioEnrollment:EnumerateNoEnrollments");
        }

        List<CtapBioEnrollmentTemplateInfo> templateInfos = new(state.BioEnrollmentTemplatesByTemplateId.Count);
        foreach(CtapBioEnrollmentTemplateRecord record in state.BioEnrollmentTemplatesByTemplateId.Values)
        {
            templateInfos.Add(new CtapBioEnrollmentTemplateInfo(record.TemplateId.AsReadOnlyMemory(), record.FriendlyName));
        }

        CtapBioEnrollmentResponse response = new(TemplateInfos: templateInfos);

        return Respond(state, new BioEnrollmentResponseReady(response), "BioEnrollment:EnumerateEnrollments");
    }


    /// <summary>
    /// <c>setFriendlyName</c> (CTAP 2.3 §6.7.7): no enrollment for the passed <c>templateId</c> →
    /// <see cref="WellKnownCtapStatusCodes.InvalidOption"/> (snapshot line 6890); otherwise renames the
    /// matched template's <see cref="CtapBioEnrollmentTemplateRecord.FriendlyName"/> via the <c>with{}</c>
    /// discipline and responds bare <see cref="WellKnownCtapStatusCodes.Ok"/>. The friendly-name
    /// byte-length bound was already checked, pre-verify, by the request arm (bio scout Finding 7).
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnSetBioEnrollmentFriendlyNameRequested(
        CtapAuthenticatorState state, CtapBioEnrollmentRequest request)
    {
        string templateKey = BioEnrollmentTemplateKey(request.TemplateId!.Value.Span);
        if(!state.BioEnrollmentTemplatesByTemplateId.TryGetValue(templateKey, out CtapBioEnrollmentTemplateRecord? record))
        {
            return Reject(state, WellKnownCtapStatusCodes.InvalidOption, "BioEnrollment:SetFriendlyNameNoSuchEnrollment");
        }

        CtapBioEnrollmentTemplateRecord renamed = record with { FriendlyName = request.TemplateFriendlyName };

        CtapAuthenticatorState nextState = state with
        {
            BioEnrollmentTemplatesByTemplateId = state.BioEnrollmentTemplatesByTemplateId.SetItem(templateKey, renamed)
        };

        return Respond(nextState, new BioEnrollmentResponseReady(null), "BioEnrollment:SetFriendlyName");
    }


    /// <summary>
    /// <c>removeEnrollment</c> (CTAP 2.3 §6.7.8): no enrollment for the passed <c>templateId</c> →
    /// <see cref="WellKnownCtapStatusCodes.InvalidOption"/> (snapshot line 6936); otherwise removes and
    /// disposes the matched template record and responds bare <see cref="WellKnownCtapStatusCodes.Ok"/>.
    /// Removing the LAST template flips <see cref="CtapAuthenticatorState.HasProvisionedBioEnrollments"/>
    /// back to <see langword="false"/> — a subsequent <c>authenticatorGetInfo</c> reports
    /// <c>bioEnroll</c>/<c>uv</c> false, per R2's single-source derivation.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnRemoveBioEnrollmentRequested(
        CtapAuthenticatorState state, CtapBioEnrollmentRequest request)
    {
        string templateKey = BioEnrollmentTemplateKey(request.TemplateId!.Value.Span);
        if(!state.BioEnrollmentTemplatesByTemplateId.TryGetValue(templateKey, out CtapBioEnrollmentTemplateRecord? record))
        {
            return Reject(state, WellKnownCtapStatusCodes.InvalidOption, "BioEnrollment:RemoveEnrollmentNoSuchEnrollment");
        }

        ImmutableDictionary<string, CtapBioEnrollmentTemplateRecord> remaining = state.BioEnrollmentTemplatesByTemplateId.Remove(templateKey);
        record.Dispose();

        return Respond(state with { BioEnrollmentTemplatesByTemplateId = remaining }, new BioEnrollmentResponseReady(null), "BioEnrollment:RemoveEnrollment");
    }


    /// <summary>
    /// The fingerprint template store's dictionary key for a <see cref="BioEnrollmentTemplateId"/>: a
    /// lowercase-hex encoding of its bytes, mirroring <see cref="CredentialIdKey"/>'s own keying
    /// convention exactly (R6).
    /// </summary>
    private static string BioEnrollmentTemplateKey(BioEnrollmentTemplateId templateId) => Convert.ToHexStringLower(templateId.AsReadOnlySpan());


    /// <summary>
    /// The fingerprint template store's dictionary key for a raw, request-decoded <c>templateId</c> span
    /// — see <see cref="BioEnrollmentTemplateKey(BioEnrollmentTemplateId)"/>.
    /// </summary>
    private static string BioEnrollmentTemplateKey(ReadOnlySpan<byte> templateId) => Convert.ToHexStringLower(templateId);


    /// <summary>
    /// <c>authenticatorLargeBlobs</c>' complete §6.10.2 algorithm (CTAP 2.3, lines 7587-7680), pinned to
    /// the spec's own literal step order throughout (R6): the THREE shared shape checks (steps 1-3),
    /// <c>get</c>'s FULL algorithm (step 4), then <c>set</c>'s pre-auth checks → the R5 conditional token
    /// gate → the sum check → append/commit (continued by <see cref="ContinueLargeBlobsSet"/> once the
    /// gate resolves, on either the tokenless or the verified path).
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>offset</c> absent → <see cref="WellKnownCtapStatusCodes.InvalidParameter"/> (line 7590, via
    /// <see cref="CtapLargeBlobsRequest.Offset"/>'s nullability rather than a decode-boundary throw —
    /// trap 6/7); neither <c>get</c> nor <c>set</c> present (line 7592) or both present (line 7594) →
    /// <see cref="WellKnownCtapStatusCodes.InvalidParameter"/>.
    /// </para>
    /// <para>
    /// <c>get</c> branch: <c>length</c> present (line 7599) or either <c>pinUvAuthParam</c>/
    /// <c>pinUvAuthProtocol</c> present (line 7601, trap 5 — reads are deliberately public, supplying
    /// auth material is an ERROR not a tolerated no-op) → <see cref="WellKnownCtapStatusCodes.InvalidParameter"/>;
    /// <c>get</c>'s value exceeding <see cref="CtapAuthenticatorState.MaxFragmentLength"/> (line 7603) →
    /// <see cref="WellKnownCtapStatusCodes.InvalidLength"/>; <c>offset</c> greater than the stored
    /// array's length (line 7605) → <see cref="WellKnownCtapStatusCodes.InvalidParameter"/>; otherwise a
    /// substring starting at <c>offset</c>, up to <c>get</c> bytes, SHORT-READ-TRUNCATED if fewer remain
    /// — a ZERO-LENGTH substring when <c>offset</c> equals the stored length is a SUCCESS, not an error
    /// (line 7607, trap 8). The substring is a zero-copy slice of the already-owned
    /// <see cref="CtapAuthenticatorState.SerializedLargeBlobArray"/> — no pool rent, no hashing, fully
    /// pure (D3).
    /// </para>
    /// <para>
    /// <c>set</c> branch (lines 7610-7655): fragment length exceeding
    /// <see cref="CtapAuthenticatorState.MaxFragmentLength"/> (line 7613, "the contents ... not
    /// including the outer CBOR tag") → <see cref="WellKnownCtapStatusCodes.InvalidLength"/>. If
    /// <c>offset</c> is zero (steps 7615-7627): <c>length</c> absent (line 7618) →
    /// <see cref="WellKnownCtapStatusCodes.InvalidParameter"/>; <c>length</c> &gt; 1024 AND exceeds
    /// <see cref="CtapAuthenticatorState.MaxSerializedLargeBlobArrayCapacity"/> (line 7620) →
    /// <see cref="WellKnownCtapStatusCodes.LargeBlobStorageFull"/>; <c>length</c> &lt; 17 (line 7622, the
    /// 17-byte minimum a valid serialized large-blob array can ever be, trap 9) →
    /// <see cref="WellKnownCtapStatusCodes.InvalidParameter"/>; otherwise this operation's own
    /// <c>expectedLength</c>/<c>expectedNextOffset</c> resolve to (<c>length</c>, 0) (steps 7624/7626 —
    /// NOT yet persisted onto <see cref="CtapAuthenticatorState.RememberedLargeBlobWrite"/>, which only
    /// happens once <see cref="ContinueLargeBlobsSet"/>'s own declared action's fold-back returns; D3: no
    /// pool op runs here, only two local integers). Else (<c>offset</c> non-zero, line 7632): <c>length</c>
    /// present → <see cref="WellKnownCtapStatusCodes.InvalidParameter"/>; otherwise <c>expectedLength</c>/
    /// <c>expectedNextOffset</c> are read from the already-remembered sequence, defaulting to (0, 0) when
    /// none exists — the "no sequence ever existed" and "an intervening command discarded it" cases
    /// collapse to the identical outcome — after FIRST folding in the 2873 token-expiry discard when the
    /// remembered sequence was gate-armed (mirroring <see cref="OnGetNextAssertionRequested"/>'s own
    /// <c>AuthenticatingPinUvAuthProtocol</c> expiry-fold pattern, R7: tokenless sequences have no token
    /// to expire, so this fold is skipped for them). <c>offset != expectedNextOffset</c> (line 7635) →
    /// <see cref="WellKnownCtapStatusCodes.InvalidSeq"/> — reached identically whether the mismatch is a
    /// genuinely wrong offset, a just-discarded sequence, or an expired authenticating token (seams
    /// trap: an interleaved command between fragments produces this exact status on the next fragment).
    /// </para>
    /// <para>
    /// The R5 gate (line 7637): <c>IsProtectedByUserVerification(state) || state.IsAlwaysUvEnabled</c> —
    /// mirroring <see cref="OnAuthenticatorConfigRequested"/>'s own step-4 gate WITHOUT its step-3
    /// <c>toggleAlwaysUv</c> bypass, which has no largeBlobs analogue; <see cref="IsProtectedByUserVerification"/>
    /// is consumed AS-IS (zero edits). Unarmed → the write proceeds TOKENLESS via
    /// <see cref="ContinueLargeBlobsSet"/> directly (line 7682's note: "a serialized large-blob array can
    /// be written without user verification if user verification is not configured"). Armed →
    /// <c>pinUvAuthParam</c> absent (line 7640) → <see cref="WellKnownCtapStatusCodes.PuatRequired"/>;
    /// <c>pinUvAuthProtocol</c> absent (line 7642) → <see cref="WellKnownCtapStatusCodes.MissingParameter"/>;
    /// protocol unsupported (line 7644) → <see cref="WellKnownCtapStatusCodes.InvalidParameter"/>;
    /// otherwise a <see cref="CtapVerifyLargeBlobsTokenAction"/> is declared, carrying <c>expectedLength</c>/
    /// <c>expectedNextOffset</c> through <see cref="CtapLargeBlobsVerifyContinuation"/> so
    /// <see cref="OnLargeBlobsPinUvAuthTokenVerified"/> need not re-run the checks above (the sum check,
    /// line 7655, runs strictly AFTER verification succeeds — never here, trap 6/7 of the seams scout).
    /// </para>
    /// </remarks>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnLargeBlobsRequested(
        CtapAuthenticatorState state, LargeBlobsRequested requested)
    {
        CtapLargeBlobsRequest request = requested.Request;

        //A genuine set continuation (a non-zero offset) preserves RememberedLargeBlobWrite; every other
        //shape reaching this command — a get, or a set with offset == 0, which always starts a brand-new
        //sequence per line 7657 regardless — takes the same GLOBAL discard every other command's entry
        //takes (R7).
        bool isContinuationCandidate = request.Set is not null && request.Offset is int candidateOffset && candidateOffset != 0;
        state = isContinuationCandidate ? DiscardRememberedSequencesExceptLargeBlobWrite(state) : DiscardAllRememberedSequences(state);

        if(request.Offset is not int offset)
        {
            return Reject(state, WellKnownCtapStatusCodes.InvalidParameter, "LargeBlobs:OffsetMissing");
        }

        if(request.Get is null && request.Set is null)
        {
            return Reject(state, WellKnownCtapStatusCodes.InvalidParameter, "LargeBlobs:NeitherGetNorSet");
        }

        if(request.Get is not null && request.Set is not null)
        {
            return Reject(state, WellKnownCtapStatusCodes.InvalidParameter, "LargeBlobs:BothGetAndSet");
        }

        if(request.Get is int getLength)
        {
            if(request.Length is not null)
            {
                return Reject(state, WellKnownCtapStatusCodes.InvalidParameter, "LargeBlobs:GetWithLength");
            }

            if(request.PinUvAuthParam is not null || request.PinUvAuthProtocol is not null)
            {
                return Reject(state, WellKnownCtapStatusCodes.InvalidParameter, "LargeBlobs:GetWithAuthMaterial");
            }

            if(getLength > CtapAuthenticatorState.MaxFragmentLength)
            {
                return Reject(state, WellKnownCtapStatusCodes.InvalidLength, "LargeBlobs:GetExceedsMaxFragmentLength");
            }

            int storedLength = state.SerializedLargeBlobArray.Length;
            if(offset > storedLength)
            {
                return Reject(state, WellKnownCtapStatusCodes.InvalidParameter, "LargeBlobs:GetOffsetPastStoredLength");
            }

            int available = storedLength - offset;
            int takeLength = Math.Min(getLength, available);
            ReadOnlyMemory<byte> config = state.SerializedLargeBlobArray.AsReadOnlyMemory().Slice(offset, takeLength);

            return Respond(state, new LargeBlobsResponseReady(new CtapLargeBlobsResponse(config)), "LargeBlobs:Get");
        }

        ReadOnlyMemory<byte> fragment = request.Set!.Value;
        if(fragment.Length > CtapAuthenticatorState.MaxFragmentLength)
        {
            return Reject(state, WellKnownCtapStatusCodes.InvalidLength, "LargeBlobs:SetFragmentExceedsMaxFragmentLength");
        }

        int expectedLength;
        int expectedNextOffset;

        if(offset == 0)
        {
            if(request.Length is not int length)
            {
                return Reject(state, WellKnownCtapStatusCodes.InvalidParameter, "LargeBlobs:SetOffsetZeroMissingLength");
            }

            if(length > 1024 && length > CtapAuthenticatorState.MaxSerializedLargeBlobArrayCapacity)
            {
                return Reject(state, WellKnownCtapStatusCodes.LargeBlobStorageFull, "LargeBlobs:SetLengthExceedsCapacity");
            }

            if(length < 17)
            {
                return Reject(state, WellKnownCtapStatusCodes.InvalidParameter, "LargeBlobs:SetLengthTooShort");
            }

            expectedLength = length;
            expectedNextOffset = 0;
        }
        else
        {
            if(request.Length is not null)
            {
                return Reject(state, WellKnownCtapStatusCodes.InvalidParameter, "LargeBlobs:SetOffsetNonZeroWithLength");
            }

            CtapRememberedLargeBlobWriteState? remembered = state.RememberedLargeBlobWrite;
            if(remembered?.AuthenticatingPinUvAuthProtocol is CtapPinUvAuthProtocolId authenticatingProtocol)
            {
                CtapPinUvAuthTokenState evaluatedToken = SelectPinUvAuthTokenState(state, authenticatingProtocol).EvaluateExpiry(requested.Now);
                state = WithPinUvAuthTokenState(state, authenticatingProtocol, evaluatedToken);

                if(!evaluatedToken.IsInUse)
                {
                    state = DiscardRememberedLargeBlobWrite(state);
                    remembered = null;
                }
            }

            expectedLength = remembered?.ExpectedLength ?? 0;
            expectedNextOffset = remembered?.ExpectedNextOffset ?? 0;

            if(offset != expectedNextOffset)
            {
                return Reject(state, WellKnownCtapStatusCodes.InvalidSeq, "LargeBlobs:OffsetMismatch");
            }
        }

        bool tokenGateApplies = IsProtectedByUserVerification(state) || state.IsAlwaysUvEnabled;
        if(!tokenGateApplies)
        {
            return ContinueLargeBlobsSet(state, offset, fragment, expectedLength, authenticatingProtocol: null);
        }

        if(request.PinUvAuthParam is not ReadOnlyMemory<byte> pinUvAuthParam)
        {
            return Reject(state, WellKnownCtapStatusCodes.PuatRequired, "LargeBlobs:SetPuatRequired");
        }

        if(request.PinUvAuthProtocol is not int protocolValue)
        {
            return Reject(state, WellKnownCtapStatusCodes.MissingParameter, "LargeBlobs:SetMissingProtocol");
        }

        if(!IsSupportedPinUvAuthProtocol(protocolValue))
        {
            return Reject(state, WellKnownCtapStatusCodes.InvalidParameter, "LargeBlobs:SetUnsupportedProtocol");
        }

        CtapPinUvAuthProtocolId protocolId = (CtapPinUvAuthProtocolId)protocolValue;
        CtapPinUvAuthTokenState presentedToken = SelectPinUvAuthTokenState(state, protocolId).EvaluateExpiry(requested.Now);
        state = WithPinUvAuthTokenState(state, protocolId, presentedToken);

        CtapAuthenticatorState nextState = state with
        {
            NextAction = new CtapVerifyLargeBlobsTokenAction(
                protocolId, presentedToken, (uint)offset, fragment, pinUvAuthParam,
                new CtapLargeBlobsVerifyContinuation(requested, expectedLength, expectedNextOffset)),
            ResponseIntent = null
        };

        return Transition(nextState, "LargeBlobs:VerifyPinUvAuthToken");
    }


    /// <summary>
    /// Completes an <c>authenticatorLargeBlobs</c> <c>set</c> whose presented <c>pinUvAuthParam</c> has
    /// been verified (CTAP 2.3 §6.10.2, lines 7646-7655): verify (already run by the executor) →
    /// <c>lbw</c> permission (line 7652 — <see cref="WellKnownCtapStatusCodes.PinAuthInvalid"/>, NOT
    /// <see cref="WellKnownCtapStatusCodes.UnauthorizedPermission"/>, trap 4; mirrors
    /// <see cref="OnAuthenticatorConfigPinUvAuthTokenVerified"/>'s identical-shape <c>acfg</c> check) →
    /// <see cref="ContinueLargeBlobsSet"/> for the sum check and append/commit. NO flag/permission
    /// stripping on success: <c>set</c> is not "an operation that tests user presence" (§6.10.2 names no
    /// <c>up</c> test anywhere in its algorithm), so <see cref="ClearPinUvAuthTokenFlags"/> is never
    /// called here — the SAME token, still carrying <c>lbw</c> (and whatever else it holds), remains
    /// usable for the next fragment, the lbw carve-out's own observable proof (seams Finding C).
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnLargeBlobsPinUvAuthTokenVerified(
        CtapAuthenticatorState state, bool verified, CtapLargeBlobsVerifyContinuation continuation)
    {
        if(!verified)
        {
            return Reject(state, WellKnownCtapStatusCodes.PinAuthInvalid, "LargeBlobs:VerifyFailed");
        }

        LargeBlobsRequested requested = continuation.Requested;
        CtapLargeBlobsRequest request = requested.Request;
        CtapPinUvAuthProtocolId protocolId = (CtapPinUvAuthProtocolId)request.PinUvAuthProtocol!.Value;
        CtapPinUvAuthTokenState token = SelectPinUvAuthTokenState(state, protocolId);

        if((token.Permissions & WellKnownCtapPinUvAuthTokenPermissions.Lbw) == 0)
        {
            return Reject(state, WellKnownCtapStatusCodes.PinAuthInvalid, "LargeBlobs:LbwPermissionDenied");
        }

        token = token with { LastUsedAt = requested.Now };
        state = WithPinUvAuthTokenState(state, protocolId, token);

        int offset = request.Offset!.Value;
        ReadOnlyMemory<byte> fragment = request.Set!.Value;

        return ContinueLargeBlobsSet(state, offset, fragment, continuation.ExpectedLength, authenticatingProtocol: protocolId);
    }


    /// <summary>
    /// The tail both the tokenless and the verified <c>set</c> path share (CTAP 2.3 §6.10.2, lines
    /// 7655-7661): the sum check — <c>offset + |fragment| &gt; expectedLength</c> (line 7655) →
    /// <see cref="WellKnownCtapStatusCodes.InvalidParameter"/>, run AFTER token verification when the
    /// gate is armed (trap 6/7) — then declares a <see cref="CtapCommitLargeBlobArrayAction"/> to append
    /// the fragment (and, once complete, run the commit-time integrity check) — D3: no pool op, no
    /// hashing, runs here; both live in the executor.
    /// </summary>
    /// <param name="state">The current state, already past every pre-auth and gate check.</param>
    /// <param name="offset">The accepted fragment's <c>offset</c>.</param>
    /// <param name="fragment">The accepted fragment's contents.</param>
    /// <param name="expectedLength">The resolved <c>expectedLength</c> for this sequence.</param>
    /// <param name="authenticatingProtocol">
    /// The protocol that authenticated this fragment, or <see langword="null"/> for a tokenless
    /// fragment — becomes (or remains) <see cref="CtapRememberedLargeBlobWriteState.AuthenticatingPinUvAuthProtocol"/>
    /// once the declared action's fold-back installs or advances the remembered sequence.
    /// </param>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> ContinueLargeBlobsSet(
        CtapAuthenticatorState state, int offset, ReadOnlyMemory<byte> fragment, int expectedLength, CtapPinUvAuthProtocolId? authenticatingProtocol)
    {
        if(offset + fragment.Length > expectedLength)
        {
            return Reject(state, WellKnownCtapStatusCodes.InvalidParameter, "LargeBlobs:SumExceedsExpectedLength");
        }

        IMemoryOwner<byte>? existingPendingBuffer = offset == 0 ? null : state.RememberedLargeBlobWrite?.PendingBuffer;

        CtapAuthenticatorState nextState = state with
        {
            RememberedLargeBlobWrite = null,
            NextAction = new CtapCommitLargeBlobArrayAction(offset, fragment, expectedLength, authenticatingProtocol, existingPendingBuffer),
            ResponseIntent = null
        };

        return Transition(nextState, "LargeBlobs:AppendFragment");
    }


    /// <summary>
    /// Folds back a <see cref="CtapCommitLargeBlobArrayAction"/>'s outcome (CTAP 2.3 §6.10.2, lines
    /// 7663-7678): incomplete → remembers the advanced sequence and responds with an empty success
    /// ("Await further writes", line 7678); complete and integrity-INVALID → discards the sequence and
    /// rejects with <see cref="WellKnownCtapStatusCodes.IntegrityFailure"/> WITHOUT touching
    /// <see cref="CtapAuthenticatorState.SerializedLargeBlobArray"/> (line 7666's own "the stored array
    /// UNCHANGED" posture — the pending buffer was independently rented, never aliasing the stored one);
    /// complete and VALID → discards the sequence, disposes the superseded stored array, and adopts
    /// <see cref="CtapLargeBlobArrayCommitAttempted.CommittedArray"/> as the new one, responding with an
    /// empty success (line 7670). No pool op, no hashing — both already ran in the executor (D3); this
    /// method only disposes and swaps already-owned references, mirroring <see cref="FactoryReset"/>'s
    /// own direct-disposal shape.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> OnLargeBlobArrayCommitAttempted(
        CtapAuthenticatorState state, CtapLargeBlobArrayCommitAttempted attempted)
    {
        if(!attempted.IsComplete)
        {
            CtapRememberedLargeBlobWriteState remembered = new(
                attempted.ExpectedLength, attempted.PendingNextOffset, attempted.PendingBuffer!, attempted.AuthenticatingPinUvAuthProtocol);

            return Respond(state with { RememberedLargeBlobWrite = remembered }, new LargeBlobsResponseReady(null), "LargeBlobs:AwaitFurtherWrites");
        }

        state = state with { RememberedLargeBlobWrite = null };

        if(!attempted.IsIntegrityValid)
        {
            return Reject(state, WellKnownCtapStatusCodes.IntegrityFailure, "LargeBlobs:IntegrityFailure");
        }

        state.SerializedLargeBlobArray.Dispose();
        state = state with { SerializedLargeBlobArray = attempted.CommittedArray! };

        return Respond(state, new LargeBlobsResponseReady(null), "LargeBlobs:Commit");
    }


    /// <summary>
    /// Wraps a fully computed next state and label into a <see cref="TransitionResult{TState, TStackSymbol}"/>
    /// with no stack action — this automaton never pushes or pops.
    /// </summary>
    private static TransitionResult<CtapAuthenticatorState, CtapAuthenticatorStackSymbol> Transition(CtapAuthenticatorState nextState, string label) =>
        new(nextState, StackAction<CtapAuthenticatorStackSymbol>.None, label);
}
