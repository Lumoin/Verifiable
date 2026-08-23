using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Foundation.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// The transition function (δ) of the TPM lifecycle simulator: a pure mapping from
/// (state, input) to the next state and stack action, mirroring TPM 2.0 Library Part 1, clause 10.
/// </summary>
/// <remarks>
/// <para>
/// The function performs no I/O, reads no time, and uses no randomness — the only buffer-touching work
/// (parsing requests, framing responses) happens in <see cref="TpmSimulator"/>. Command admissibility
/// is decided by <see cref="TpmCommandPreconditions"/> before any command is dispatched; a rejected
/// command transitions into a state whose response carries the rejection code, and the lifecycle phase
/// is left unchanged. The automaton never halts in this skeleton (a transition is defined for every
/// input), so a returned <see langword="null"/> would signal a genuinely unexpected input.
/// </para>
/// </remarks>
public static class TpmLifecycleTransitions
{
    /// <summary>
    /// The largest number of octets the simulated TPM returns from a single <c>TPM2_GetRandom()</c>.
    /// </summary>
    /// <remarks>
    /// TPM 2.0 Library Part 3, clause 16.1: a request larger than fits in a <c>TPM2B_DIGEST</c> is not
    /// an error — the TPM returns only as much as fits, which is the largest digest it can produce. The
    /// simulator models a TPM whose largest digest is SHA-512 (64 octets), so a request is clamped here.
    /// </remarks>
    public const int MaxRandomBytes = 64;

    /// <summary>
    /// The largest value <c>TPM2_ClockSet()</c> may set <c>Clock</c> to (TPM 2.0 Library Part 1, clause 36.3:
    /// "the value of Clock may not be advanced beyond FF FF 00 00 00 00 00 00(16)").
    /// </summary>
    public const ulong MaxClockValue = 0xFFFF_0000_0000_0000UL;

    /// <summary>
    /// The declared data size (in octets) a Counter, Bit Field, PIN Fail, or PIN Pass NV Index must have
    /// (TPM 2.0 Library Part 2, clause 13.2).
    /// </summary>
    private const ushort EightOctetDataSize = 8;

    /// <summary>
    /// Creates the transition delegate for a TPM lifecycle automaton.
    /// </summary>
    /// <returns>The transition function.</returns>
    public static TransitionDelegate<TpmSimulatorState, TpmSimulatorInput, TpmSimulatorStackSymbol> Create() =>
        static (state, input, stackTop, cancellationToken) =>
        {
            //The effect fold-backs (TpmRandomGenerated, TpmPrimaryKeyCreated, TpmMessageSigned) each carry a
            //disposable owner the framing step releases, so they must always be consumed into their response
            //intent rather than dropped: they are neither cancellation-gated nor NextAction-reset here. Every
            //externally-supplied input honours cancellation and starts from a cleared NextAction, so an action
            //left pending by an aborted prior effect cannot re-fire against a later command.
            TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol>? result = input switch
            {
                TpmRandomGenerated generated => OnRandomGenerated(state, generated),
                TpmPrimaryKeyCreated created => OnPrimaryKeyCreated(state, created),
                TpmMessageSigned signed => OnMessageSigned(state, signed),
                TpmObjectSealed objectSealed => OnObjectSealed(state, objectSealed),
                TpmObjectLoaded objectLoaded => OnObjectLoaded(state, objectLoaded),
                TpmObjectCertified objectCertified => OnObjectCertified(state, objectCertified),
                TpmObjectCreationCertified objectCreationCertified => OnObjectCreationCertified(state, objectCreationCertified),
                TpmObjectQuoted objectQuoted => OnObjectQuoted(state, objectQuoted),
                TpmTimeAttested timeAttested => OnTimeAttested(state, timeAttested),
                TpmNvIndexCertified nvIndexCertified => OnNvIndexCertified(state, nvIndexCertified),
                TpmAttestedOverSessions nvIndexCertifiedOverSessions => OnAttestedOverSessions(state, nvIndexCertifiedOverSessions),
                TpmSignatureVerified signatureVerified => OnSignatureVerified(state, signatureVerified),
                TpmHmacSessionStarted hmacSessionStarted => OnHmacSessionStarted(state, hmacSessionStarted),
                TpmCommandHmacVerified commandHmacVerified => OnCommandHmacVerified(state, commandHmacVerified),
                TpmEncryptedRandomProduced encryptedRandom => OnEncryptedRandomProduced(state, encryptedRandom),
                TpmPolicySecretSessionResponseFramed policySecretSessionResponseFramed => OnPolicySecretSessionResponseFramed(state, policySecretSessionResponseFramed),
                TpmUnsealedOverSessions unsealedOverSessions => OnUnsealedOverSessions(state, unsealedOverSessions),
                TpmCredentialMade credentialMade => OnCredentialMade(state, credentialMade),
                TpmCredentialActivated credentialActivated => OnCredentialActivated(state, credentialActivated),
                TpmNvNameComputedForPolicy nvNameComputedForPolicy => OnNvNameComputedForPolicy(state, nvNameComputedForPolicy),
                TpmNvPublicNameComputed nvPublicNameComputed => OnNvPublicNameComputed(state, nvPublicNameComputed),
                TpmNvIndexNameComputed nvIndexNameComputed => OnNvIndexNameComputed(state, nvIndexNameComputed),
                TpmNvSessionResponseFramed nvSessionResponseFramed => OnNvSessionResponseFramed(state, nvSessionResponseFramed),
                TpmPolicySignedVerified policySignedVerified => OnPolicySignedVerified(state, policySignedVerified),
                TpmPolicyAuthorizeVerified policyAuthorizeVerified => OnPolicyAuthorizeVerified(state, policyAuthorizeVerified),
                TpmPolicySecretTicketMinted policySecretTicketMinted => OnPolicySecretTicketMinted(state, policySecretTicketMinted),
                TpmPolicyTicketVerified policyTicketVerified => OnPolicyTicketVerified(state, policyTicketVerified),
                TpmPolicyDigestFolded policyDigestFolded => OnPolicyDigestFolded(state, policyDigestFolded),
                TpmCreateSensitiveDecrypted sensitiveDecrypted => OnCreateSensitiveDecrypted(state, sensitiveDecrypted),
                TpmNvDefineAuthDecrypted nvDefineAuthDecrypted => OnNvDefineAuthDecrypted(state, nvDefineAuthDecrypted),
                TpmNvChangeAuthDecrypted nvChangeAuthDecrypted => OnNvChangeAuthDecrypted(state, nvChangeAuthDecrypted),
                TpmNvChangeAuthResponseFramed nvChangeAuthResponseFramed => OnNvChangeAuthResponseFramed(state, nvChangeAuthResponseFramed),
                TpmHierarchyChangeAuthDecrypted hierarchyChangeAuthDecrypted => OnHierarchyChangeAuthDecrypted(state, hierarchyChangeAuthDecrypted),
                TpmAttestQualifyingDataDecrypted attestQualifyingDataDecrypted => OnAttestQualifyingDataDecrypted(state, attestQualifyingDataDecrypted),
                TpmStorageProofSeedGenerated storageProofSeedGenerated => OnStorageProofSeedGenerated(state, storageProofSeedGenerated),
                TpmObjectPersisted objectPersisted => OnObjectPersisted(state, objectPersisted),
                TpmObjectSealedOverSessions sealedOverSessions => OnObjectSealedOverSessions(state, sealedOverSessions),
                _ => OnExternalInput(state, input, cancellationToken)
            };

            return ValueTask.FromResult(result);
        };

    /// <summary>
    /// Handles inputs that arrive from outside the effect loop — the platform <c>_TPM_Init</c> signal and
    /// parsed command requests.
    /// </summary>
    /// <remarks>
    /// These honour cancellation and start from a cleared <c>NextAction</c>. A cancellation observed here
    /// fires before any dispatch, so ownership of a parse-rented carrier cannot yet have transferred into
    /// durable state: the input is the carrier's only owner and is released before the throw unwinds
    /// through <c>SubmitAsync</c>, which holds no other reference to it.
    /// </remarks>
    /// <param name="state">The current simulator state.</param>
    /// <param name="input">The externally-supplied input to dispatch.</param>
    /// <param name="cancellationToken">Honoured before any state mutation.</param>
    /// <returns>The resulting transition, if the input is admissible.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol>? OnExternalInput(
        TpmSimulatorState state, TpmSimulatorInput input, System.Threading.CancellationToken cancellationToken)
    {
        if(cancellationToken.IsCancellationRequested)
        {
            (input as IDisposable)?.Dispose();
            cancellationToken.ThrowIfCancellationRequested();
        }

        TpmSimulatorState ready = state with { NextAction = NullAction.Instance };

        return input switch
        {
            TpmInitSignal => OnInit(ready),
            _ => OnCommand(ready, input)
        };
    }

    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnInit(TpmSimulatorState state) =>
        Transition(
            state with
            {
                Phase = TpmLifecyclePhase.Initializing,
                SelfTest = TpmSelfTestStatus.NotRun,
                ResponseIntent = null
            },
            "TpmInit");

    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol>? OnCommand(TpmSimulatorState state, TpmSimulatorInput input)
    {
        TpmCcConstants commandCode = CommandCodeOf(input);
        TpmRcConstants? rejection = TpmCommandPreconditions.Evaluate(commandCode, state.Phase);
        if(rejection is TpmRcConstants responseCode)
        {
            //An input refused before its handler runs still owns whatever carriers its parse rented;
            //the inputs that own any implement IDisposable over exactly those fields (never borrows).
            if(input is IDisposable ownedInFlight)
            {
                return Reject(state, commandCode, responseCode, ownedInFlight);
            }

            return Reject(state, commandCode, responseCode);
        }

        //Every admitted command advances the free-running Time/Clock counters by one fixed quantum before
        //dispatch (TPM 2.0 Library Part 1, clause 36.1: "Time advances when the Time circuit is powered").
        //This models a real TPM's oscillator as one quantum per submitted command rather than reading a real
        //wall clock, preserving this function's no-I/O, no-randomness contract. A rejected command (handled
        //above) performs no Clock-relevant work, matching real-TPM behaviour; TPM2_Startup() overrides Time
        //back to zero for the Reset/Restart/Resume sequence it completes, but never Clock.
        state = state with
        {
            Time = state.Time + state.ClockAdvanceQuantumMs,
            Clock = state.Clock + state.ClockAdvanceQuantumMs
        };

        //Dictionary-attack self-healing rides the same per-command Time advance (TPM 2.0 Library Part 1, clause
        //17.8.4): applied before dispatch so the command about to run observes any decrement/re-arm the elapsed
        //Time already earned.
        state = ApplyDictionaryAttackSelfHeal(state);

        return input switch
        {
            TpmStartupRequested startup => OnStartup(state, startup.StartupType),
            TpmShutdownRequested shutdown => OnShutdown(state, shutdown.ShutdownType),
            TpmSelfTestRequested => OnSelfTest(state),
            TpmTestResultRequested => OnTestResult(state),
            TpmGetRandomRequested getRandom => OnGetRandom(state, getRandom.BytesRequested),
            TpmGetCapabilityRequested getCapability => OnGetCapability(state, getCapability.Capability, getCapability.Property, getCapability.PropertyCount),
            TpmNvDefineSpaceRequested defineSpace => OnNvDefineSpace(state, defineSpace),
            TpmNvReadRequested nvRead => OnNvRead(state, nvRead),
            TpmNvWriteRequested nvWrite => OnNvWrite(state, nvWrite),
            TpmNvUndefineSpaceRequested nvUndefine => OnNvUndefineSpace(state, nvUndefine),
            TpmNvIncrementRequested nvIncrement => OnNvIncrement(state, nvIncrement),
            TpmNvReadPublicRequested nvReadPublic => OnNvReadPublic(state, nvReadPublic),
            TpmNvReadOverSessionRequested nvReadOverSession => OnNvReadOverSession(state, nvReadOverSession),
            TpmNvWriteOverSessionRequested nvWriteOverSession => OnNvWriteOverSession(state, nvWriteOverSession),
            TpmNvDefineSpaceOverSessionRequested nvDefineSpaceOverSession => OnNvDefineSpaceOverSession(state, nvDefineSpaceOverSession),
            TpmNvUndefineSpaceOverSessionRequested nvUndefineSpaceOverSession => OnNvUndefineSpaceOverSession(state, nvUndefineSpaceOverSession),
            TpmNvIncrementOverSessionRequested nvIncrementOverSession => OnNvIncrementOverSession(state, nvIncrementOverSession),
            TpmNvCertifyOverSessionRequested nvCertifyOverSession => OnNvCertifyOverSession(state, nvCertifyOverSession),
            TpmNvChangeAuthOverSessionRequested nvChangeAuthOverSession => OnNvChangeAuthOverSession(state, nvChangeAuthOverSession),
            TpmEvictControlRequested evictControl => OnEvictControl(state, evictControl),
            TpmCreatePrimaryRequested createPrimary => OnCreatePrimary(state, createPrimary),
            TpmCreateRsaPrimaryRequested createRsaPrimary => OnCreateRsaPrimary(state, createRsaPrimary),
            TpmCreateStorageParentRequested createStorageParent => OnCreateStorageParent(state, createStorageParent),
            TpmCreateRsaStorageParentRequested createRsaStorageParent => OnCreateRsaStorageParent(state, createRsaStorageParent),
            TpmSignRequested sign => OnSign(state, sign),
            TpmCreateSealedObjectRequested createSealed => OnCreateSealedObject(state, createSealed),
            TpmCreateSealedObjectOverSessionsRequested createSealedOverSessions => OnCreateSealedObjectOverSessions(state, createSealedOverSessions),
            TpmLoadObjectRequested loadObject => OnLoadObject(state, loadObject),
            TpmUnsealRequested unseal => OnUnseal(state, unseal),
            TpmUnsealOverSessionsRequested unsealOverSessions => OnUnsealOverSessions(state, unsealOverSessions),
            TpmCertifyRequested certify => OnCertify(state, certify),
            TpmCertifyOverSessionRequested certifyOverSession => OnCertifyOverSession(state, certifyOverSession),
            TpmCertifyCreationRequested certifyCreation => OnCertifyCreation(state, certifyCreation),
            TpmCertifyCreationOverSessionRequested certifyCreationOverSession => OnCertifyCreationOverSession(state, certifyCreationOverSession),
            TpmPcrReadRequested pcrRead => OnPcrRead(state, pcrRead),
            TpmQuoteRequested quote => OnQuote(state, quote),
            TpmQuoteOverSessionRequested quoteOverSession => OnQuoteOverSession(state, quoteOverSession),
            TpmGetTimeRequested getTime => OnGetTime(state, getTime),
            TpmGetTimeOverSessionRequested getTimeOverSession => OnGetTimeOverSession(state, getTimeOverSession),
            TpmReadClockRequested => OnReadClock(state),
            TpmClockSetRequested clockSet => OnClockSet(state, clockSet),
            TpmDictionaryAttackLockResetRequested dictionaryAttackLockReset => OnDictionaryAttackLockReset(state, dictionaryAttackLockReset),
            TpmDictionaryAttackParametersRequested dictionaryAttackParameters => OnDictionaryAttackParameters(state, dictionaryAttackParameters),
            TpmClearRequested clear => OnClear(state, clear),
            TpmClearOverSessionRequested clearOverSession => OnClearOverSession(state, clearOverSession),
            TpmClearControlRequested clearControl => OnClearControl(state, clearControl),
            TpmClearControlOverSessionRequested clearControlOverSession => OnClearControlOverSession(state, clearControlOverSession),
            TpmHierarchyControlRequested hierarchyControl => OnHierarchyControl(state, hierarchyControl),
            TpmHierarchyControlOverSessionRequested hierarchyControlOverSession => OnHierarchyControlOverSession(state, hierarchyControlOverSession),
            TpmSetPrimaryPolicyRequested setPrimaryPolicy => OnSetPrimaryPolicy(state, setPrimaryPolicy),
            TpmSetPrimaryPolicyOverSessionRequested setPrimaryPolicyOverSession => OnSetPrimaryPolicyOverSession(state, setPrimaryPolicyOverSession),
            TpmHierarchyChangeAuthRequested hierarchyChangeAuth => OnHierarchyChangeAuth(state, hierarchyChangeAuth),
            TpmHierarchyChangeAuthOverSessionRequested hierarchyChangeAuthOverSession => OnHierarchyChangeAuthOverSession(state, hierarchyChangeAuthOverSession),
            TpmNvCertifyRequested nvCertify => OnNvCertify(state, nvCertify),
            TpmVerifySignatureRequested verifySignature => OnVerifySignature(state, verifySignature),
            TpmStartAuthSessionRequested startAuthSession => OnStartAuthSession(state, startAuthSession),
            TpmStartHmacSessionRequested startHmacSession => OnStartHmacSession(state, startHmacSession),
            TpmGetRandomOverSessionRequested getRandomOverSession => OnGetRandomOverSession(state, getRandomOverSession),
            TpmPolicyCommandCodeRequested policyCommandCode => OnPolicyCommandCode(state, policyCommandCode),
            TpmPolicyAuthValueRequested policyAuthValue => OnPolicyAuthValue(state, policyAuthValue),
            TpmPolicyGetDigestRequested policyGetDigest => OnPolicyGetDigest(state, policyGetDigest),
            TpmPolicyPcrRequested policyPcr => OnPolicyPcr(state, policyPcr),
            TpmPolicyOrRequested policyOr => OnPolicyOr(state, policyOr),
            TpmPolicySecretRequested policySecret => OnPolicySecret(state, policySecret),
            TpmPolicySecretOverSessionRequested policySecretOverSession => OnPolicySecretOverSession(state, policySecretOverSession),
            TpmPolicySignedRequested policySigned => OnPolicySigned(state, policySigned),
            TpmPolicyAuthorizeRequested policyAuthorize => OnPolicyAuthorize(state, policyAuthorize),
            TpmPolicyTicketRequested policyTicket => OnPolicyTicket(state, policyTicket),
            TpmPolicyNvRequested policyNv => OnPolicyNv(state, policyNv),
            TpmPolicyCounterTimerRequested policyCounterTimer => OnPolicyCounterTimer(state, policyCounterTimer),
            TpmMakeCredentialRequested makeCredential => OnMakeCredential(state, makeCredential),
            TpmActivateCredentialRequested activateCredential => OnActivateCredential(state, activateCredential),
            TpmActivateCredentialOverSessionRequested activateCredentialOverSession => OnActivateCredentialOverSession(state, activateCredentialOverSession),
            TpmFlushContextRequested flushContext => OnFlushContext(state, flushContext),
            _ => throw new System.InvalidOperationException($"Command input '{input.GetType().Name}' passed precondition gating but has no dispatch handler.")
        };
    }

    /// <summary>
    /// Dispatches <c>TPM2_Startup()</c>: <c>Startup(CLEAR)</c> is a TPM Reset when it is preceded by
    /// <c>Shutdown(CLEAR)</c> or no orderly shutdown at all, or a TPM Restart when it is preceded by
    /// <c>Shutdown(STATE)</c>; <c>Startup(STATE)</c> after a <c>Shutdown(STATE)</c> is a TPM Resume (Part 3,
    /// clause 9.3).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Restart and Resume increment restartCount and leave resetCount untouched; a Reset increments
    /// resetCount and resets restartCount to zero (Part 1, clauses 36.4-36.5). Every one of the three resets Time
    /// to zero (Time counts from the last <c>_TPM_Init</c>/Startup, clause 36.2) but never Clock (clause 36.3) —
    /// overriding only the Time half of the per-command advance <c>OnCommand</c> already applied for this very
    /// Startup dispatch.
    /// </para>
    /// <para>
    /// A Reset's ClockSafe becomes YES when it followed an orderly <c>Shutdown(CLEAR)</c> or is this TPM's very
    /// first Reset (resetCount was zero, so no prior Clock value could ever have been reported, per clause 36.3's
    /// "not a repeat of a previously reported value" definition); otherwise NO — a Reset with neither of those
    /// conditions is a disorderly restart this simulator cannot distinguish further (the skeleton's own
    /// disorderly-power-loss simplification, noted on <c>LastOrderlyShutdown</c>).
    /// </para>
    /// <para>
    /// Two further simplifications, tracked on the roadmap rather than modelled: no periodic NV Clock save is
    /// modelled (Part 1, clause 36.3's volatile/non-volatile Clock split collapses to the one volatile field),
    /// and the clause 36.7 resetCount/restartCount/firmwareVersion obfuscation for a signer outside the
    /// Platform/Endorsement hierarchy is not applied — every attestation reports the raw counters and firmware
    /// version regardless of which hierarchy the signing key belongs to.
    /// </para>
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="startupType">The requested startup type.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnStartup(TpmSimulatorState state, TpmSuConstants startupType) =>
        startupType switch
        {
            //Startup(CLEAR) after Shutdown(STATE): TPM Restart. The dictionary-attack self-heal anchors are reset
            //to zero alongside Time (clause 17.8.4/17.8.5): both are Time-relative timestamps, and Time itself
            //resets here, so an anchor left at its pre-Restart value would underflow against the new, smaller Time.
            //A Restart carries the same hierarchy and platform-authorization reset a Reset does (Part 3, clause
            //9.3's Restart bullets: "phEnableNV, shEnable and ehEnable shall be SET" and "platformAuth and
            //platformPolicy shall be set to the Empty Buffer"), joined by the every-Startup rule "phEnable shall
            //be SET" — Restart and Reset are indistinguishable in this respect, and only a Resume carries the
            //three non-platform enables and the platform authorization forward as they were. Active sessions
            //and loaded objects survive NO Startup form — see FlushSessionsAtStartup and
            //FlushLoadedObjectsAtStartup; a Restart also clears TPMA_NV_WRITTEN on the Indexes that elected
            //it — see ApplyNvStartupAttributes.
            TpmSuConstants.TPM_SU_CLEAR when state.LastOrderlyShutdown == TpmSuConstants.TPM_SU_STATE => Transition(
                ApplyNvStartupAttributes(FlushLoadedObjectsAtStartup(FlushSessionsAtStartup(state, clearPlatformAuth: true)), isReset: false) with
                {
                    Phase = TpmLifecyclePhase.Operational,
                    LastOrderlyShutdown = null,
                    Time = 0ul,
                    TimeEpoch = RegenerateTimeEpoch(state.TimeEpoch, state.Clock),
                    RestartCount = state.RestartCount + 1,
                    PhEnable = true,
                    ShEnable = true,
                    EhEnable = true,
                    PhEnableNV = true,
                    LastFailedTriesRecoveryTime = 0ul,
                    LastLockoutAuthFailureTime = 0ul,
                    ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
                },
                "Startup:Restart"),

            //Startup(CLEAR) after Shutdown(CLEAR) or no orderly shutdown: TPM Reset. A TPM Reset invalidates every
            //policy session (Part 1, clause 10.2.2's general Reset semantics; a session's captured StartTime is
            //meaningless once Time itself resets to zero below) — cleared here rather than left to go stale, which
            //also makes PolicySessionState's absent time-epoch concept structurally sound (see its StartTime doc
            //comment): no session can survive from before a Reset to be checked against a post-Reset Time. The
            //self-heal anchors reset to zero with Time for the same reason as the Restart arm above. A TPM Reset is
            //also the one event that re-arms a disabled LockoutAuthEnabled when LockoutRecovery is zero (clause
            //17.8.5): with LockoutRecovery nonzero, only the elapsed-Time self-heal in
            //ApplyDictionaryAttackSelfHeal re-enables it, so this leaves an already-true value untouched.
            //The four hierarchy enables are restored here too (Part 3, clause 9.3's Reset bullets: "phEnableNV,
            //shEnable and ehEnable shall be SET", alongside the every-Startup rule "phEnable shall be SET"),
            //which is what makes CLEARing phEnable a one-way act: no command can ever SET it (clause 24.2.1,
            //"phEnable may not be SET using this command"), so a Startup is the only route back — and phEnable
            //alone comes back on every one of the three, the other three enables on a Reset and a Restart but not
            //a Resume, which carries them forward as they were.
            //platformAuth and platformPolicy return to the Empty Buffer here as well ("platformAuth and
            //platformPolicy shall be set to the Empty Buffer", the same clause's Reset bullets, restated at Part 1,
            //clause 11.3: "On TPM Reset or TPM Restart, platformAuth is set to an EmptyAuth, and platformPolicy is
            //set to an Empty Policy"). The policy's hash algorithm follows its digest back to TPM_ALG_NULL, since
            //an empty policy is exactly a null-algorithm policy (clause 24.3.2). This is what makes platform
            //authorization a per-boot secret rather than a persistent one: unlike ownerAuth or lockoutAuth, which
            //survive every power cycle and only TPM2_Clear() returns, platformAuth is the platform firmware's to
            //install afresh after each Reset or Restart.
            TpmSuConstants.TPM_SU_CLEAR => Transition(
                ApplyNvStartupAttributes(FlushLoadedObjectsAtStartup(FlushSessionsAtStartup(state, clearPlatformAuth: true)), isReset: true) with
                {
                    Phase = TpmLifecyclePhase.Operational,
                    LastOrderlyShutdown = null,
                    Time = 0ul,
                    TimeEpoch = RegenerateTimeEpoch(state.TimeEpoch, state.Clock),
                    ResetCount = state.ResetCount + 1,
                    RestartCount = 0u,
                    PhEnable = true,
                    ShEnable = true,
                    EhEnable = true,
                    PhEnableNV = true,
                    ClockSafe = state.LastOrderlyShutdown == TpmSuConstants.TPM_SU_CLEAR || state.ResetCount == 0u
                        ? TpmiYesNo.Yes
                        : TpmiYesNo.No,
                    LockoutAuthEnabled = state.LockoutAuthEnabled || state.LockoutRecovery == 0u,
                    LastFailedTriesRecoveryTime = 0ul,
                    LastLockoutAuthFailureTime = 0ul,
                    ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
                },
                "Startup:Reset"),

            //Startup(STATE) after a Shutdown(STATE): TPM Resume. The self-heal anchors reset to zero with Time for
            //the same reason as the Restart arm above. This is the "what survives" path for the CONTROLS: Part 3,
            //clause 9.3's Resume bullets name neither the three non-platform enables nor
            //platformAuth/platformPolicy, so a hierarchy disabled before an orderly shutdown is still disabled
            //after the resume and a platform authorization installed before it still authorizes. phEnable is the
            //one exception, restored here as everywhere else by the every-Startup rule "On any TPM2_Startup(),
            //phEnable shall be SET". Active sessions and loaded objects survive NO Startup form — see
            //FlushSessionsAtStartup and FlushLoadedObjectsAtStartup; a Resume leaves every NV attribute as it
            //was (the reference's NvEntityStartup returns early only for SU_RESUME).
            TpmSuConstants.TPM_SU_STATE when state.LastOrderlyShutdown == TpmSuConstants.TPM_SU_STATE => Transition(
                FlushLoadedObjectsAtStartup(FlushSessionsAtStartup(state, clearPlatformAuth: false)) with
                {
                    Phase = TpmLifecyclePhase.Operational,
                    LastOrderlyShutdown = null,
                    Time = 0ul,
                    TimeEpoch = RegenerateTimeEpoch(state.TimeEpoch, state.Clock),
                    RestartCount = state.RestartCount + 1,
                    PhEnable = true,
                    LastFailedTriesRecoveryTime = 0ul,
                    LastLockoutAuthFailureTime = 0ul,
                    ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
                },
                "Startup:Resume"),

            //Startup(STATE) without a preserved Shutdown(STATE): no state to restore (clause 10.2.3.2).
            TpmSuConstants.TPM_SU_STATE => Reject(state, TpmCcConstants.TPM_CC_Startup, TpmRcConstants.TPM_RC_VALUE),

            //An out-of-range startupType value.
            _ => Reject(state, TpmCcConstants.TPM_CC_Startup, TpmRcConstants.TPM_RC_VALUE)
        };

    /// <summary>
    /// Terminates every active session for a completed <c>TPM2_Startup()</c> of ANY form — Reset, Restart,
    /// and Resume alike — releasing each session's owned carriers and emptying both session tables, and
    /// (for Reset and Restart) releasing the per-boot platform authorization on its way to the Empty
    /// Buffer.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The all-three-forms flush is normative, not a modelling choice: "Session contexts in TPM RAM are
    /// flushed on any TPM2_Startup()" (TPM 2.0 Library Part 1, clause 28.5), and clause 17.6.17 names the
    /// two restoring forms explicitly — "on TPM Resume or TPM Restart, authorization sessions in TPM
    /// memory will be terminated but sessions context saved off the TPM will remain active". The
    /// reference's <c>SessionStartup()</c> realizes it as an unconditional slot-clearing loop that runs
    /// identically for <c>SU_RESET</c>, <c>SU_RESTART</c>, and <c>SU_RESUME</c>; only the bookkeeping for
    /// SAVED (off-TPM) contexts is startup-type-differentiated. This simulator's two session dictionaries
    /// model sessions in TPM RAM — it has no session context save/load — so every completed startup empties
    /// both, and the saved-context half of clause 28.5 has nothing here to act on.
    /// </para>
    /// <para>
    /// The time epoch is deliberately NOT part of this: the reference regenerates it on a platform-timer
    /// discontinuity (<c>TimeNewEpoch()</c>), never per startup type, and uses it only for policy
    /// timeout/ticket staleness — a Reset invalidates saved contexts through <c>nullProof</c> regeneration
    /// and the reset counters, not the epoch. The arms' own <c>RegenerateTimeEpoch</c> serves this model's
    /// per-boot timeout-ticket staleness and is independent of the session flush.
    /// </para>
    /// </remarks>
    /// <param name="state">The state whose sessions are terminated.</param>
    /// <param name="clearPlatformAuth">Whether the per-boot platform authorization — both the authValue and the policy digest Part 3, clause 9.3 empties beside it — is also released and reset to the Empty Buffer (TPM Reset and TPM Restart; a TPM Resume carries it forward).</param>
    /// <returns>The state with both session tables empty and, when requested, both halves of the platform authorization at the Empty Buffer.</returns>
    private static TpmSimulatorState FlushSessionsAtStartup(TpmSimulatorState state, bool clearPlatformAuth)
    {
        foreach(HmacSessionState session in state.HmacSessions.Values)
        {
            session.Dispose();
        }

        foreach(PolicySessionState session in state.PolicySessions.Values)
        {
            session.Dispose();
        }

        if(clearPlatformAuth)
        {
            //Part 3, clause 9.3 empties platformAuth and platformPolicy together, so both owned carriers are
            //released here before the with-copy installs the dispose-immune empties in their place.
            state.PlatformAuth.Dispose();
            state.PlatformAuthPolicy.Dispose();
        }

        return state with
        {
            HmacSessions = ImmutableDictionary<TpmiShHmac, HmacSessionState>.Empty,
            PolicySessions = ImmutableDictionary<TpmiShPolicy, PolicySessionState>.Empty,
            PlatformAuth = clearPlatformAuth ? Tpm2bAuth.Empty : state.PlatformAuth,
            PlatformAuthPolicy = clearPlatformAuth ? Tpm2bDigest.Empty : state.PlatformAuthPolicy,
            PlatformAuthPolicyHashAlg = clearPlatformAuth ? TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_NULL) : state.PlatformAuthPolicyHashAlg
        };
    }

    /// <summary>
    /// Flushes every loaded object for a completed <c>TPM2_Startup()</c> of ANY form — Reset, Restart, and
    /// Resume alike — releasing each transient key's and loaded sealed object's owned carriers, emptying both
    /// RAM-object tables, and returning the transient handle counter to the base of its range.
    /// </summary>
    /// <remarks>
    /// The all-three-forms flush is the object half of the rule <see cref="FlushSessionsAtStartup"/> realizes
    /// for sessions: "An object context is only removed from TPM memory with TPM2_FlushContext(), deletion of
    /// the associated hierarchy seed, or TPM2_Startup()" (TPM 2.0 Library Part 1, clause 28.4), and the
    /// reference's <c>ObjectStartup()</c> clears every RAM object slot with no startup-type test, one call
    /// after the session clear this pairs with. Persistent objects are NV-resident, not object contexts in
    /// TPM RAM, so <c>PersistentObjects</c> is untouched and a persisted copy keeps answering across every
    /// power cycle. With every RAM slot free again the next transient handle restarts at the range base,
    /// as a real TPM's first-free-slot assignment does after a reboot.
    /// </remarks>
    /// <param name="state">The state whose loaded objects are flushed.</param>
    /// <returns>The state with both RAM-object tables empty and the transient handle counter at its base.</returns>
    private static TpmSimulatorState FlushLoadedObjectsAtStartup(TpmSimulatorState state)
    {
        foreach(TransientKeyState transient in state.TransientObjects.Values)
        {
            transient.Dispose();
        }

        foreach(SealedObjectState sealedObject in state.LoadedSealedObjects.Values)
        {
            sealedObject.Dispose();
        }

        return state with
        {
            TransientObjects = ImmutableDictionary<TpmiDhObject, TransientKeyState>.Empty,
            LoadedSealedObjects = ImmutableDictionary<TpmiDhObject, SealedObjectState>.Empty,
            NextObjectHandle = TpmSimulatorState.TransientHandleBase
        };
    }

    /// <summary>
    /// Applies the per-Index startup attribute pass for a completed TPM Reset or TPM Restart: every
    /// non-counter Index with <c>TPMA_NV_CLEAR_STCLEAR</c> SET — joined on a Reset by every non-counter
    /// Index with <c>TPMA_NV_ORDERLY</c> SET — has <c>TPMA_NV_WRITTEN</c> CLEARed, so its data answers
    /// <c>TPM_RC_NV_UNINITIALIZED</c> again until rewritten and its Name reverts to the unwritten form.
    /// </summary>
    /// <remarks>
    /// The pass is normative per attribute definition, not a modelling choice: "TPMA_NV_WRITTEN for the
    /// Index is CLEAR by TPM Reset or TPM Restart" (TPM 2.0 Library Part 2, clause 13.4's
    /// <c>TPMA_NV_CLEAR_STCLEAR</c>), and the reference's <c>NvSetStartupAttributes</c> additionally clears
    /// an orderly non-counter Index's <c>TPMA_NV_WRITTEN</c> on <c>SU_RESET</c> alone, with
    /// <c>NvEntityStartup</c> running the pass for Reset and Restart and returning early only for
    /// <c>SU_RESUME</c>. Counters are exempt: <c>TPMA_NV_CLEAR_STCLEAR</c> cannot reach one (refused at
    /// definition, clause 37.2.4.2), while <c>TPMA_NV_ORDERLY</c> IS admissible on a counter, so the
    /// exemption is enforced here by the counter test — the same <c>IsNvCounterIndex</c> guard the
    /// reference applies (a counter is restored or advanced across a startup, never cleared; the
    /// orderly-counter startup advance itself is unmodelled, noted at the increment arm). The same
    /// reference routine's read/write-lock clearing has nothing to act on here: lock commands are
    /// unmodelled, noted at the NV read and write arms. The replaced record's carriers move to the clone
    /// wholesale, so nothing is disposed on this path.
    /// </remarks>
    /// <param name="state">The state whose NV Indexes receive the startup attribute pass.</param>
    /// <param name="isReset">Whether this startup is a TPM Reset, which extends the pass to <c>TPMA_NV_ORDERLY</c> Indexes.</param>
    /// <returns>The state with the electing Indexes' <c>TPMA_NV_WRITTEN</c> CLEARed.</returns>
    private static TpmSimulatorState ApplyNvStartupAttributes(TpmSimulatorState state, bool isReset)
    {
        ImmutableDictionary<TpmiRhNvIndex, NvIndexState> indexes = state.NvIndexes;
        foreach(NvIndexState index in state.NvIndexes.Values)
        {
            bool isCounter = TpmaNvFields.GetTpmNt(index.Attributes) == TpmNt.TPM_NT_COUNTER;
            bool isClearElected = (index.Attributes & TpmaNv.TPMA_NV_CLEAR_STCLEAR) != 0
                || (isReset && (index.Attributes & TpmaNv.TPMA_NV_ORDERLY) != 0);
            if(!isCounter && isClearElected && index.IsWritten)
            {
                indexes = indexes.SetItem(index.NvIndex, index with { Attributes = index.Attributes & ~TpmaNv.TPMA_NV_WRITTEN });
            }
        }

        return state with { NvIndexes = indexes };
    }

    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnShutdown(TpmSimulatorState state, TpmSuConstants shutdownType) =>
        shutdownType switch
        {
            //Record the orderly shutdown type so a later Startup can decide what to restore (clause 10.2.4).
            //The TPM stays operational until the next _TPM_Init; saved-state invalidation by a later
            //state-modifying command is modelled when such commands are added.
            TpmSuConstants.TPM_SU_CLEAR or TpmSuConstants.TPM_SU_STATE => Transition(
                state with
                {
                    LastOrderlyShutdown = shutdownType,
                    ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
                },
                shutdownType == TpmSuConstants.TPM_SU_CLEAR ? "Shutdown:Clear" : "Shutdown:State"),

            _ => Reject(state, TpmCcConstants.TPM_CC_Shutdown, TpmRcConstants.TPM_RC_VALUE)
        };

    /// <summary>
    /// Regenerates <c>TimeEpoch</c> across a completed <c>TPM2_Startup()</c> — Reset, Restart, and Resume alike,
    /// since Time itself resets to zero in all three under this simulator's model (TPM 2.0 Library Part 1,
    /// clause 17.7.12's own stated purpose for timeEpoch is invalidating a time-based assertion, live or
    /// ticketed, across "a discontinuity in the TPM's time measurement", and every completed Startup is exactly
    /// that discontinuity here, not Reset alone — closing a replay gap Reset-only regeneration would leave open:
    /// a policy ticket is an off-TPM blob the caller retains, so it survives every Startup form even though the
    /// sessions themselves do not (<see cref="FlushSessionsAtStartup"/>), and only the epoch fold keeps such a
    /// ticket from authorizing a brand-new post-Startup session against a rewound Time).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The reference draws fresh platform entropy at each such discontinuity; doing the same here would call the
    /// injected Rng delegate on the hottest, most heavily exercised transition in the whole simulator, perturbing
    /// <c>TPM2_GetRandom()</c>'s deterministic counter stream that existing byte-exact test assertions rely on,
    /// for a value that carries no secrecy requirement of its own (see <c>TimeEpoch</c>'s doc comment on
    /// <see cref="TpmSimulatorState"/>). This simulator's simplification: bit-mix the current epoch forward with
    /// a discriminant that is unique to every Startup dispatch — the free-running Clock, already advanced for
    /// this very command by <c>OnCommand</c> before dispatch — via the well-known MurmurHash3 64-bit finalizer,
    /// deterministic, pool-free, and Rng-free, so no pure transition ever touches randomness (this function's own
    /// class-level contract).
    /// </para>
    /// <para>
    /// The "unique discriminant" property this construction relies on holds only when
    /// <c>ClockAdvanceQuantumMs</c> (an unvalidated constructor parameter) is nonzero: Clock is then genuinely
    /// free-running and does not repeat within any realistic run length. At <c>ClockAdvanceQuantumMs == 0</c> —
    /// a valid configuration this simulator's own equation-12 (Part 2, Table 111) KAT uses — Clock never advances, the discriminant
    /// is permanently 0, and <see cref="RegenerateTimeEpoch"/> degenerates to a fixed 32-bit self-map of
    /// <paramref name="currentEpoch"/> alone: it is NOT collision-free in that configuration (the map's
    /// functional-graph orbit eventually revisits an earlier epoch, and epoch 0 is an absorbing fixed point of
    /// the degenerate map). A caller relying on <c>TimeEpoch</c> to make a very long-running,
    /// repeatedly-restarted simulator's regenerated epochs pairwise distinct must configure a nonzero quantum.
    /// </para>
    /// </remarks>
    /// <param name="currentEpoch">The epoch value in effect before this Startup.</param>
    /// <param name="discriminant">The free-running Clock value, already advanced for this dispatch.</param>
    /// <returns>The regenerated epoch value.</returns>
    private static uint RegenerateTimeEpoch(uint currentEpoch, ulong discriminant)
    {
        ulong mixed = ((ulong)currentEpoch << 32) ^ discriminant;
        mixed ^= mixed >> 33;
        mixed *= 0xff51afd7ed558ccdUL;
        mixed ^= mixed >> 33;
        mixed *= 0xc4ceb9fe1a85ec53UL;
        mixed ^= mixed >> 33;

        return (uint)mixed;
    }

    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnSelfTest(TpmSimulatorState state) =>
        state.ConfiguredSelfTest switch
        {
            //A failed self-test returns TPM_RC_FAILURE and enters Failure Mode (clause 10.3, Figure 5).
            TpmSelfTestBehavior.Fails => Transition(
                state with
                {
                    Phase = TpmLifecyclePhase.FailureMode,
                    SelfTest = TpmSelfTestStatus.Failed,
                    ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_FAILURE)
                },
                "SelfTest:Failed"),

            _ => Transition(
                state with
                {
                    SelfTest = TpmSelfTestStatus.Passed,
                    ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
                },
                "SelfTest:Passed")
        };

    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnTestResult(TpmSimulatorState state)
    {
        TpmRcConstants testResult = state.SelfTest == TpmSelfTestStatus.Failed
            ? TpmRcConstants.TPM_RC_FAILURE
            : TpmRcConstants.TPM_RC_SUCCESS;

        return Transition(
            state with { ResponseIntent = new TpmTestResultResponse(TpmRcConstants.TPM_RC_SUCCESS, testResult) },
            "GetTestResult");
    }

    /// <summary>
    /// Dispatches <c>TPM2_GetRandom()</c>, the first command that needs an effect: the pure transition cannot
    /// draw random octets, so it declares a <c>TpmRngAction</c> and leaves no response yet.
    /// </summary>
    /// <remarks>
    /// The effectful loop fills a pooled buffer via the injected RNG backend and feeds the octets back as a
    /// <c>TpmRandomGenerated</c> input, which <c>OnRandomGenerated</c> turns into the framed response.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="bytesRequested">The number of random octets requested, clamped to <see cref="MaxRandomBytes"/>.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the RNG action.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnGetRandom(TpmSimulatorState state, ushort bytesRequested)
    {
        //A request larger than the largest digest is clamped, not rejected (clause 16.1).
        int byteCount = System.Math.Min((int)bytesRequested, MaxRandomBytes);

        return Transition(
            state with
            {
                NextAction = new TpmRngAction(byteCount),
                ResponseIntent = null
            },
            "GetRandom:Requested");
    }

    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnRandomGenerated(TpmSimulatorState state, TpmRandomGenerated generated) =>
        Transition(
            state with
            {
                NextAction = NullAction.Instance,
                ResponseIntent = new TpmRandomResponse(TpmRcConstants.TPM_RC_SUCCESS, generated.Bytes)
            },
            "GetRandom:Completed");

    /// <summary>
    /// The sim-side fixed family indicator device-identity property value.
    /// </summary>
    /// <remarks>
    /// Part of the fixed device-identity property block alongside <see cref="SimSpecLevel"/>,
    /// <see cref="SimSpecRevision"/>, and <see cref="SimManufacturer"/>; the lockout/DA variable properties are
    /// read from the live state instead.
    /// </remarks>
    private const uint SimFamilyIndicator = 0x322E_3000;  //"2.0\0" packed as a UINT32.
    private const uint SimSpecLevel = 0u;
    private const uint SimSpecRevision = 184u;            //Mirrors the v184 spec corpus this models.
    private const uint SimManufacturer = 0x53_49_4D_55;   //"SIMU" — the simulator's synthetic vendor id.

    /// <summary>
    /// Dispatches <c>TPM2_GetCapability()</c>, a pure, state-derived response (no action layer): it reports a
    /// window of <c>TPM_PT</c> properties starting at the requested tag (Part 3, clause 30.2), the prerequisite
    /// for reading the dictionary-attack/lockout state the PIN flow exercises.
    /// </summary>
    /// <param name="state">The state to derive the response from.</param>
    /// <param name="capability">The requested capability category.</param>
    /// <param name="property">The starting <c>TPM_PT</c> tag.</param>
    /// <param name="propertyCount">The maximum number of properties to return.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the capability data transfers to the TpmCapabilityResponse intent and is disposed by TpmSimulator.SerializeResponse after the response is framed.")]
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnGetCapability(TpmSimulatorState state, TpmCapConstants capability, uint property, uint propertyCount)
    {
        //Only the TPM-properties capability is modelled (it carries the lockout/DA state the PIN flow
        //reads). A conformant TPM answers a valid-but-unimplemented capability with TPM_RC_SUCCESS and
        //an empty list (Part 3, 30.2); the simulator instead returns TPM_RC_VALUE as a deliberate
        //"not modelled" signal until further capability arms are added.
        if(capability != TpmCapConstants.TPM_CAP_TPM_PROPERTIES)
        {
            return Reject(state, TpmCcConstants.TPM_CC_GetCapability, TpmRcConstants.TPM_RC_VALUE);
        }

        //Return the supported properties whose tag is at or after the requested start, in ascending
        //order, up to propertyCount; moreData signals that the window was truncated (Part 3, 30.2).
        //Sort defensively so the windowing/paging contract does not silently depend on the literal
        //order of BuildTpmProperties.
        List<TpmsTaggedProperty> all = BuildTpmProperties(state);
        all.Sort(static (left, right) => left.Property.CompareTo(right.Property));
        List<TpmsTaggedProperty> selected = new();
        bool moreData = false;
        for(int i = 0; i < all.Count; i++)
        {
            TpmsTaggedProperty candidate = all[i];
            if(candidate.Property < property)
            {
                continue;
            }

            if((uint)selected.Count >= propertyCount)
            {
                moreData = true;

                break;
            }

            selected.Add(candidate);
        }

        TpmsCapabilityData data = TpmsCapabilityData.CreateTpmProperties(selected);

        return Transition(
            state with { ResponseIntent = new TpmCapabilityResponse(TpmRcConstants.TPM_RC_SUCCESS, data, moreData ? TpmiYesNo.Yes : TpmiYesNo.No) },
            "GetCapability");
    }

    /// <summary>
    /// The <c>TPM_PT</c> properties the simulator reports, in ascending tag order: fixed device identity
    /// (constants) followed by the variable provisioning, hierarchy-enable, and lockout/DA properties read from
    /// the live state (Part 1, 11.2 and 17.8).
    /// </summary>
    /// <param name="state">The state to read the variable properties from.</param>
    /// <returns>The full, unsorted list of reported properties.</returns>
    private static List<TpmsTaggedProperty> BuildTpmProperties(TpmSimulatorState state)
    {
        //TPMA_PERMANENT (Part 2, clause 8.6). The three *_AUTH_SET bits are worded in the specification as a
        //history of TPM2_HierarchyChangeAuth() since the last TPM2_Clear(); they are reported here from the
        //authValues themselves, which is the same answer for every sequence except one — a rotation that
        //installs the Empty Buffer as the new authValue reads back CLEAR here where a TPM tracking the history
        //would report SET. The remaining defined bit, TPM_GENERATED_EPS, is not modelled: this simulator has no
        //Endorsement Primary Seed provenance to report.
        uint permanent =
            (state.OwnerAuth.IsEmpty ? 0u : (uint)TpmaPermanent.OWNER_AUTH_SET)
            | (state.EndorsementAuth.IsEmpty ? 0u : (uint)TpmaPermanent.ENDORSEMENT_AUTH_SET)
            | (state.LockoutAuth.IsEmpty ? 0u : (uint)TpmaPermanent.LOCKOUT_AUTH_SET)
            | (state.DisableClear ? (uint)TpmaPermanent.DISABLE_CLEAR : 0u)
            | (state.IsInLockout ? (uint)TpmaPermanent.IN_LOCKOUT : 0u);

        //TPMA_STARTUP_CLEAR (Part 2, clause 8.7): the four hierarchy enables, which are the only way a caller
        //can observe that a hierarchy has been disabled — a disabled hierarchy refuses both its authValue and
        //its authPolicy (Part 1, clause 11.2), so nothing else in the response surface distinguishes it from a
        //wrong-secret failure. READ_ONLY and ORDERLY are not modelled: this simulator implements no
        //TPM2_ReadOnlyControl() and reports orderly-shutdown provenance through the lifecycle phase instead.
        uint startupClear =
            (state.PhEnable ? (uint)TpmaStartupClear.PH_ENABLE : 0u)
            | (state.ShEnable ? (uint)TpmaStartupClear.SH_ENABLE : 0u)
            | (state.EhEnable ? (uint)TpmaStartupClear.EH_ENABLE : 0u)
            | (state.PhEnableNV ? (uint)TpmaStartupClear.PH_ENABLE_NV : 0u);

        return new List<TpmsTaggedProperty>
        {
            new(TpmPtConstants.TPM_PT_FAMILY_INDICATOR, SimFamilyIndicator),
            new(TpmPtConstants.TPM_PT_LEVEL, SimSpecLevel),
            new(TpmPtConstants.TPM_PT_REVISION, SimSpecRevision),
            new(TpmPtConstants.TPM_PT_MANUFACTURER, SimManufacturer),

            //"the maximum data size in one NV write, NV read, NV extend, or NV certify command" (Part 2, clause
            //6.13, Table 30) — this TPM's own MAX_NV_BUFFER_SIZE, the bound Table 99 leaves TPM-dependent and
            //the NV data-parameter sites refuse above. Reported so a caller can size its transfers without
            //discovering the bound by being refused.
            new(TpmPtConstants.TPM_PT_NV_BUFFER_MAX, Tpm2bMaxNvBuffer.MaxSize),
            new(TpmPtConstants.TPM_PT_PERMANENT, permanent),
            new(TpmPtConstants.TPM_PT_STARTUP_CLEAR, startupClear),
            new(TpmPtConstants.TPM_PT_LOCKOUT_COUNTER, state.FailedTries),
            new(TpmPtConstants.TPM_PT_MAX_AUTH_FAIL, state.MaxTries),
            new(TpmPtConstants.TPM_PT_LOCKOUT_INTERVAL, state.RecoveryTime),
            new(TpmPtConstants.TPM_PT_LOCKOUT_RECOVERY, state.LockoutRecovery)
        };
    }

    /// <summary>
    /// Applies dictionary-attack self-healing (TPM 2.0 Library Part 1, clause 17.8.4/17.8.5), applied on every
    /// dispatched command right after the Time advance in <c>OnCommand</c>.
    /// </summary>
    /// <remarks>
    /// Two independent healing effects share the elapsed-Time accounting: <c>FailedTries</c> decrements by one
    /// for every <c>RecoveryTime</c> seconds elapsed since the last counted failure (<c>RecoveryTime == 0</c>
    /// disables the decrement entirely — dictionary-attack protection is off, so
    /// <c>TPM2_DictionaryAttackLockReset()</c> is the only way <c>FailedTries</c> moves), and a
    /// <c>LockoutAuthEnabled</c> disabled by a failed lockoutAuth use flips back to enabled once
    /// <c>LockoutRecovery</c> seconds have elapsed since that failure (<c>LockoutRecovery == 0</c> disables this
    /// re-arm — <c>OnStartup</c>'s Reset arm is then the only way it re-enables).
    /// </remarks>
    /// <param name="state">The state to apply self-healing to.</param>
    /// <returns>The state with any healed counters/flags applied.</returns>
    private static TpmSimulatorState ApplyDictionaryAttackSelfHeal(TpmSimulatorState state)
    {
        if(state.RecoveryTime > 0 && state.FailedTries > 0)
        {
            ulong intervalMs = (ulong)state.RecoveryTime * 1000ul;
            ulong elapsedMs = state.Time - state.LastFailedTriesRecoveryTime;
            ulong decrements = elapsedMs / intervalMs;
            if(decrements > 0)
            {
                uint healedFailedTries = decrements >= state.FailedTries ? 0u : state.FailedTries - (uint)decrements;
                state = state with
                {
                    FailedTries = healedFailedTries,
                    LastFailedTriesRecoveryTime = state.LastFailedTriesRecoveryTime + (decrements * intervalMs)
                };
            }
        }

        if(!state.LockoutAuthEnabled && state.LockoutRecovery > 0)
        {
            ulong elapsedMs = state.Time - state.LastLockoutAuthFailureTime;
            if(elapsedMs / 1000ul >= state.LockoutRecovery)
            {
                state = state with { LockoutAuthEnabled = true };
            }
        }

        return state;
    }

    /// <summary>
    /// Reserves an NV Index for <c>TPM2_NV_DefineSpace()</c>, authorized by the owner hierarchy.
    /// </summary>
    /// <remarks>
    /// The DA/PIN flow uses such an Index as the dictionary-attack-protected entity (Part 1, clause 17.8.1), so
    /// the simulator records its handle, authValue, attributes, size, Name algorithm, and access policy (the
    /// full set of fields <c>TPM2_NV_ReadPublic()</c>'s Name computation and cpHash's Name2 term need,
    /// TPM 2.0 Library Part 1, Table 6); the data area and written-ness arrive with <c>TPM2_NV_Write()</c>.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_NV_DefineSpace()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of request.IndexAuth transfers to the stored NvIndexState, which eviction (TPM2_NV_UndefineSpace, TPM2_Clear, simulator teardown) or the next rotation disposes; every refusing arm releases it through the input's own Dispose instead.")]
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnNvDefineSpace(TpmSimulatorState state, TpmNvDefineSpaceRequested request)
    {
        //Authorization is resolved before the command body runs, mirroring the reference dispatcher which
        //validates the handle area and session authorization (Part 3, clause 5.5) ahead of the command
        //actions. So provisioning-handle and owner-authValue checks precede the nvIndex-range/already-defined
        //body checks; a request that is both mis-authorized and malformed answers the authorization failure.

        //Only the owner hierarchy is modelled as the provisioning authority this slice; the platform
        //hierarchy carries its own authValue and arrives later. The authorization handle is resolved in the
        //handle area, so an invalid provisioning handle is rejected first.
        if(request.AuthHandle.Value != (uint)TpmRh.TPM_RH_OWNER)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        //While shEnable is CLEAR neither ownerAuth nor ownerPolicy can authorize anything (Part 1, clause 11.2),
        //so a provisioning command that names the owner hierarchy is refused before its authValue is even
        //consulted — the same availability gate every hierarchy-authorized command applies, and the reason a
        //disabled storage hierarchy cannot be provisioned into behind the enable's back.
        if(!state.IsHierarchyEnabled(request.AuthHandle.Value))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_HIERARCHY, request);
        }

        //Owner authorization is not dictionary-attack protected (clause 17.8.1): a wrong owner authValue is
        //a plain bad-authorization, never an auth-failure that feeds the lockout counter. The comparison is
        //constant-time so a mismatch leaks no timing about the secret, and both sides are compared in their
        //trailing-zero-stripped form (Part 1, clause 17.6.4.3).
        if(!CryptographicOperations.FixedTimeEquals(StripTrailingZeros(request.OwnerAuthSupplied.AsReadOnlySpan()), StripTrailingZeros(state.OwnerAuth.AsReadOnlySpan())))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_BAD_AUTH, request);
        }

        //The wire-supplied nameAlg must be a hash this TPM implements: on a real TPM the TPMI_ALG_HASH
        //interface type refuses anything else while unmarshaling publicInfo (TPM 2.0 Library Part 2, clause 9.27),
        //so nothing downstream ever sees an unimplementable algorithm. It is retained on the Index and drives
        //every Name this model computes, so it is gated here — the same TPM_RC_HASH the object-creation
        //transitions answer — rather than left to surface as an unhandled digest-size failure.
        if(!IsSupportedNameAlg(request.NameAlg))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_HASH, request);
        }

        //Command body: the handle must lie in the NV-Index range, its most-significant octet being
        //TPM_HT_NV_INDEX (Part 2, 7.2).
        if((byte)(request.NvIndex.Value >> 24) != (byte)TpmHt.TPM_HT_NV_INDEX)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        //Past that gate the handle also satisfies TPMI_RH_NV_INDEX (Part 2, clause 9.25, Table 72), the wider
        //interface type the durable NV state is keyed by — every other NV command addresses a defined Index
        //through it, so the Index is installed and looked up under that key rather than the narrower
        //TPMI_RH_NV_LEGACY_INDEX the public area's nvIndex field carries.
        TpmiRhNvIndex indexHandle = TpmiRhNvIndex.FromValue(request.NvIndex.Value);

        //A handle that is already defined cannot be redefined (Part 3, clause 31.3).
        if(state.NvIndexes.ContainsKey(indexHandle))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_NV_DEFINED, request);
        }

        //authPolicy is a TPM2B_DIGEST under nameAlg: either absent, or exactly that algorithm's digest size
        //(TPM 2.0 Library Part 3, clause 31.3.1's TPM_RC_SIZE condition, "publicInfo->authPolicy.size is larger
        //than the digest size of publicInfo->nameAlg"; the reference's NvDefineSpace refuses any nonzero size
        //that differs from it). The value is retained and hashed into every Name the model computes, so a
        //definition carrying an inconsistent policy would produce Names no hardware can ever produce.
        if(!request.AuthPolicy.IsEmpty && request.AuthPolicy.Size != TpmPolicyDigest.Size(request.NameAlg.Value))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_SIZE, request);
        }

        //TPMA_NV_WRITTEN, TPMA_NV_READLOCKED and TPMA_NV_WRITELOCKED are TPM-maintained status bits, never
        //caller input: "The TPM shall return TPM_RC_ATTRIBUTES if TPMA_NV_WRITTEN, TPMA_NV_READLOCKED, or
        //TPMA_NV_WRITELOCKED is SET" (TPM 2.0 Library Part 3, clause 31.3.1). Enforcing this is what keeps the
        //Counter Index rollback protection sound: TPM2_NV_Increment() seeds an UNWRITTEN counter from the
        //phantom high-water mark (clause 37.2.6.3 NOTE 2/NOTE 6), so a definition that arrived already claiming
        //TPMA_NV_WRITTEN over an empty data area would read back as counter value zero and restart the count,
        //defeating the "a counter with a particular Name cannot be rolled back by deleting it and redefining
        //it" invariant (clause 37.2.6.3 NOTE 4). A definition claiming TPMA_NV_WRITELOCKED would likewise
        //arrive permanently unincrementable.
        if((request.Attributes & (TpmaNv.TPMA_NV_WRITTEN | TpmaNv.TPMA_NV_READLOCKED | TpmaNv.TPMA_NV_WRITELOCKED)) != 0)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_ATTRIBUTES, request);
        }

        //TPMA_NV_PLATFORMCREATE records which authority defined the Index, and the TPM sets it from the
        //authorization the definition actually carried — it is not a caller-elected property. This arm is
        //authorized by TPM_RH_OWNER (checked above), so a definition asking for the bit is asking to be treated
        //as platform-created while proving only Owner Authorization, which the attributes cannot support:
        //TPM_RC_ATTRIBUTES. The consequences the bit would wrongly confer are concrete — such an Index survives
        //TPM2_Clear()'s "delete any NV Index with TPMA_NV_PLATFORMCREATE == CLEAR" (TPM 2.0 Library Part 3,
        //clause 24.6.1), refuses owner-authorized TPM2_NV_UndefineSpace() (Part 2, clause 13.4), and is gated by
        //phEnableNV instead of shEnable (Part 3, clause 24.2.1) — so an owner-created Index carrying it would be
        //undeletable by the very authority that made it.
        if((request.Attributes & TpmaNv.TPMA_NV_PLATFORMCREATE) != 0)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_ATTRIBUTES, request);
        }

        //The Index type (TPM_NT, TPMA_NV bits 7:4) must be one this TPM implements a modifying command for
        //(Part 2, clause 13.2); any other 4-bit pattern, or a type whose modifying command is unimplemented,
        //is rejected as an attribute error (see IsSupportedIndexType's own remarks below).
        TpmNt indexType = TpmaNvFields.GetTpmNt(request.Attributes);
        if(!IsSupportedIndexType(indexType))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_ATTRIBUTES, request);
        }

        //A Counter, PIN Fail, or PIN Pass Index's data area is always eight octets (TPM 2.0 Library Part 2,
        //clause 13.2). Part 3, clause 31.3.1 NOTE 2 is an explicit erratum here: the corrected response for a
        //mismatched declared size is TPM_RC_SIZE, not TPM_RC_ATTRIBUTES (some reference code predating the
        //erratum answered the latter).
        if(RequiresEightOctetDataSize(indexType) && request.DataSize != EightOctetDataSize)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_SIZE, request);
        }

        //TPMA_NV_CLEAR_STCLEAR is illegal on a Counter Index (TPM 2.0 Library Part 3, clause 31.3.1; Part 2,
        //Table 214; Part 1, clause 37.2.4.2 NOTE): a counter is either restored on an orderly startup or
        //advanced past MAX_ORDERLY_COUNT on a non-orderly one, never cleared by a Reset/Restart.
        if(indexType == TpmNt.TPM_NT_COUNTER && (request.Attributes & TpmaNv.TPMA_NV_CLEAR_STCLEAR) != 0)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_ATTRIBUTES, request);
        }

        //A PIN Fail Index requires TPMA_NV_NO_DA SET (Part 2, clause 13.4; Part 1, clause 37.2.6.6): this
        //keeps a PIN Fail Index's own pinCount/pinLimit defense (clause 37.2.8.2) disjoint from the TPM-wide
        //dictionary-attack mechanism by construction, never by caller discipline.
        if(indexType == TpmNt.TPM_NT_PIN_FAIL && (request.Attributes & TpmaNv.TPMA_NV_NO_DA) == 0)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_ATTRIBUTES, request);
        }

        //A PIN Index (Fail or Pass) forbids TPMA_NV_AUTHWRITE (Part 1, clause 37.2.6.1): its own authValue
        //authorizes reads only, never writes — provisioning and recovery are owner/platform/policy-authorized
        //administrative acts (OnNvWrite's owner-auth arm). Enforced here, at definition, rather than trusted to
        //caller discipline; without it, an unthrottled correct/incorrect-PIN oracle survives on TPM2_NV_Write().
        if((indexType == TpmNt.TPM_NT_PIN_FAIL || indexType == TpmNt.TPM_NT_PIN_PASS) && (request.Attributes & TpmaNv.TPMA_NV_AUTHWRITE) != 0)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_ATTRIBUTES, request);
        }

        //"The size of auth is limited to be no larger than the size of the digest produced by the NV Index's
        //nameAlg (TPM_RC_SIZE)" — Part 3, clause 31.3.1. Enforced on the supplied size, before any
        //trailing-zero stripping, exactly as the reference checks the unmarshaled TPM2B_AUTH; this is also what
        //keeps every stored authValue inside the bound-entity fold's fixed width (SessionBoundEntity).
        if(request.IndexAuth.Length > TpmPolicyDigest.Size(request.NameAlg.Value))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_SIZE, request);
        }

        var index = new NvIndexState(
            indexHandle, request.IndexAuth, request.Attributes, request.DataSize, request.IndexData,
            request.NameAlg, request.AuthPolicy);

        //The compare above was the owner credential's only use, so this transition is its terminal owner;
        //every arm that refuses before this point releases it through the request's own Dispose.
        request.OwnerAuthSupplied.Dispose();

        return Transition(
            state with
            {
                NvIndexes = state.NvIndexes.SetItem(indexHandle, index),
                ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
            },
            "NvDefineSpace");

        //Of the six TPM_NT values the specification defines (Part 2, clause 13.2, Table 212), only the types
        //this simulator has a modifying command for are accepted: TPM_NT_ORDINARY (TPM2_NV_Write()),
        //TPM_NT_COUNTER (TPM2_NV_Increment()), and TPM_NT_PIN_FAIL/TPM_NT_PIN_PASS (also
        //TPM2_NV_Write(), gated separately below). TPM_NT_BITS and TPM_NT_EXTEND are rejected here because
        //TPM2_NV_SetBits()/TPM2_NV_Extend() are unimplemented: TPM 2.0 Library Part 3, clause 31.3.1's
        //unsupported-command gate requires a TPM that does not implement a type's modifying command to refuse
        //that type at TPM2_NV_DefineSpace() rather than accept a definition it can never subsequently modify.
        //Every other 4-bit pattern is reserved and rejected the same way.
        static bool IsSupportedIndexType(TpmNt indexType) => indexType switch
        {
            TpmNt.TPM_NT_ORDINARY or TpmNt.TPM_NT_COUNTER or TpmNt.TPM_NT_PIN_FAIL or TpmNt.TPM_NT_PIN_PASS => true,
            _ => false
        };

        //TPM 2.0 Library Part 2, clause 13.2: Counter, Bit Field, PIN Fail, and PIN Pass Indexes all store an
        //8-octet value. TPM_NT_BITS is listed for spec fidelity even though IsSupportedIndexType above already
        //refuses it before this is ever consulted (no command modifies a TPM_NT_BITS Index in this simulator).
        static bool RequiresEightOctetDataSize(TpmNt indexType) => indexType switch
        {
            TpmNt.TPM_NT_COUNTER or TpmNt.TPM_NT_BITS or TpmNt.TPM_NT_PIN_FAIL or TpmNt.TPM_NT_PIN_PASS => true,
            _ => false
        };
    }

    /// <summary>
    /// Whether an Index authValue attempt must be refused outright, before any comparison, because the Index is
    /// dictionary-attack protected and the TPM is already in general Lockout mode (TPM 2.0 Library Part 1,
    /// clause 17.8.3: "any use of a DA-protected authValue returns TPM_RC_LOCKOUT" while locked out — checked
    /// strictly ahead of the actual credential check).
    /// </summary>
    /// <remarks>
    /// A non-DA Index (<c>TPMA_NV_NO_DA</c> set) is never subject to this gate, matching how its own auth
    /// failures never feed the counter either. Shared by every Index-authValue arm across the NV family: the
    /// read, write, increment, and certify handlers and <c>TPM2_PolicyNV()</c> on their password entries, and
    /// the read, increment, certify, and change-auth handlers on their session entries.
    /// </remarks>
    /// <param name="state">The current simulator state.</param>
    /// <param name="index">The NV Index being authorized.</param>
    /// <returns><see langword="true"/> when the attempt must be refused outright.</returns>
    private static bool IsNvIndexLockedOut(TpmSimulatorState state, NvIndexState index) =>
        index.IsDaProtected && state.IsInLockout;

    /// <summary>
    /// Whether a session must be refused outright, before its authorization is evaluated at all, because of the
    /// entity it was BOUND to at <c>TPM2_StartAuthSession()</c> rather than the entity it is authorizing now
    /// (TPM 2.0 Library Part 1, clause 17.8.3: "While in Lockout mode, any use of a DA protected authValue will
    /// return TPM_RC_LOCKOUT").
    /// </summary>
    /// <remarks>
    /// <para>
    /// A bound session's key folds the bind entity's authValue through the session-key KDFa (clause 17.6.10
    /// equation 20), which clause 17.8.1 counts as one of the three ways an authValue is used for authorization
    /// — and "All uses of a DA protected authValue receive DA protection". Using such a session is therefore a
    /// use of the bind entity's secret whatever the DA status of the entity being authorized: Part 3, clause
    /// 11.1.1 states it directly — "If a bind entity is subject to DA protection, use of the session is subject
    /// to DA regardless of the DA status of the entity being authorized."
    /// </para>
    /// <para>
    /// The two arms answer the two lockout states the spec distinguishes. A session bound to lockoutAuth is
    /// refused while lockoutAuth is disabled, the special state clause 17.8.5 enters on a lockoutAuth
    /// authorization failure "regardless of the setting of failedTries and maxTries", in which "the TPM will not
    /// allow use of lockoutAuth". Any other DA-protected bind entity is refused while the TPM is in general
    /// Lockout mode (failedTries equal to maxTries, clause 17.8.3). The response code is the bare warning-class
    /// <c>TPM_RC_LOCKOUT</c> Part 3, clause 6.2, Table 3 defines, never session-index encoded, matching how the
    /// entity-side gates answer the same condition.
    /// </para>
    /// <para>
    /// This gate is additive: it never replaces the entity-side gates
    /// (<see cref="IsNvIndexLockedOut"/> and the parent, sealed-item, and hierarchy lockout checks), because
    /// clause 17.8.7 composes the two sides as an OR — the failure counter moves "if either the entity being
    /// authorized is subject to DA protection or if the session is bound to an entity that has DA protection".
    /// It applies at USE and never at session start: Part 3, clause 11.1.1's "No authorization is required for
    /// tpmKey or bind" makes starting a session bound to a locked-out entity legal, and its error enumeration
    /// names no <c>TPM_RC_LOCKOUT</c> at all.
    /// </para>
    /// </remarks>
    /// <param name="state">The current simulator state.</param>
    /// <param name="isBoundEntityDaProtected">Whether the session's bind entity receives dictionary-attack protection.</param>
    /// <param name="isBoundToLockout">Whether the session's bind entity is <c>TPM_RH_LOCKOUT</c>.</param>
    /// <returns><see langword="true"/> when use of the session must be refused with <c>TPM_RC_LOCKOUT</c>.</returns>
    private static bool IsBoundSessionLockedOut(TpmSimulatorState state, bool isBoundEntityDaProtected, bool isBoundToLockout) =>
        (isBoundToLockout && !state.LockoutAuthEnabled) || (isBoundEntityDaProtected && state.IsInLockout);

    /// <summary>
    /// The <see cref="HmacSessionState"/> reading of the bind-side lockout gate, delegating to
    /// <see cref="IsBoundSessionLockedOut(TpmSimulatorState, bool, bool)"/> with the state the session recorded
    /// at <c>TPM2_StartAuthSession()</c> (TPM 2.0 Library Part 1, clause 17.6.10).
    /// </summary>
    /// <param name="state">The current simulator state.</param>
    /// <param name="session">The resolved HMAC session, whether it authorizes an entity or rides along as a decrypt/encrypt companion.</param>
    /// <returns><see langword="true"/> when use of the session must be refused with <c>TPM_RC_LOCKOUT</c>.</returns>
    private static bool IsBoundSessionLockedOut(TpmSimulatorState state, HmacSessionState session) =>
        IsBoundSessionLockedOut(state, session.IsBoundEntityDaProtected, session.IsBoundToLockout);

    /// <summary>
    /// The <see cref="PolicySessionState"/> reading of the bind-side lockout gate, delegating to
    /// <see cref="IsBoundSessionLockedOut(TpmSimulatorState, bool, bool)"/>. A policy session's sessionKey folds
    /// the bind entity's authValue through the same KDFa an HMAC session's does (TPM 2.0 Library Part 3, Section
    /// 11.1.1: "For all session types, this command will cause initialization of the sessionKey"), so the same
    /// gate binds it.
    /// </summary>
    /// <param name="state">The current simulator state.</param>
    /// <param name="session">The resolved policy session.</param>
    /// <returns><see langword="true"/> when use of the session must be refused with <c>TPM_RC_LOCKOUT</c>.</returns>
    private static bool IsBoundSessionLockedOut(TpmSimulatorState state, PolicySessionState session) =>
        IsBoundSessionLockedOut(state, session.IsBoundEntityDaProtected, session.IsBoundToLockout);

    /// <summary>
    /// Registers a genuine Index-authValue mismatch and rejects with the matching response code (clause
    /// 17.8.1/17.8.3).
    /// </summary>
    /// <remarks>
    /// A DA-protected Index's failure increments <c>FailedTries</c> and re-anchors the self-heal clock to the
    /// current Time (mirroring the reference <c>DARegisterFailure</c> timestamp reset) — unless dictionary-attack
    /// protection is globally disabled (<c>RecoveryTime == 0</c>), in which case the failure is still reported
    /// but the counter never moves; a non-DA Index (<c>TPMA_NV_NO_DA</c> set) never affects the counter at all.
    /// Shared by the password-arm Index-authValue mismatch sites (read, write, increment, certify, and
    /// <c>TPM2_PolicyNV()</c>); the session arms register the same failure through
    /// <c>RejectNvSessionAuthFailure</c> instead.
    /// </remarks>
    /// <param name="state">The state to reject from.</param>
    /// <param name="index">The NV Index whose authValue failed to match.</param>
    /// <param name="commandCode">The command being rejected.</param>
    /// <returns>The rejection <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> RejectNvAuthFailure(
        TpmSimulatorState state, NvIndexState index, TpmCcConstants commandCode)
    {
        if(!index.IsDaProtected)
        {
            return Reject(state, commandCode, TpmRcConstants.TPM_RC_BAD_AUTH);
        }

        if(state.RecoveryTime == 0)
        {
            return Reject(state, commandCode, TpmRcConstants.TPM_RC_AUTH_FAIL);
        }

        TpmSimulatorState registered = state with
        {
            FailedTries = state.FailedTries + 1,
            LastFailedTriesRecoveryTime = state.Time
        };

        return Reject(registered, commandCode, TpmRcConstants.TPM_RC_AUTH_FAIL);
    }

    /// <summary>
    /// Every bit <c>TPMA_SESSION</c> defines (TPM 2.0 Library Part 2, clause 8.4, Table 40): <c>continueSession</c>,
    /// <c>auditExclusive</c>, <c>auditReset</c>, <c>decrypt</c>, <c>encrypt</c>, and <c>audit</c>.
    /// </summary>
    /// <remarks>
    /// Derived from the enumeration rather than written as a literal, and stated ONCE for every site that needs
    /// it, so the mask and the type it describes cannot drift apart. <c>TPMA_SESSION</c> carries no member for
    /// the reserved field because Table 40 names none.
    /// </remarks>
    private const TpmaSession DefinedSessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT_EXCLUSIVE
        | TpmaSession.AUDIT_RESET | TpmaSession.DECRYPT | TpmaSession.ENCRYPT | TpmaSession.AUDIT;

    /// <summary>
    /// The complement of <see cref="DefinedSessionAttributes"/> — Table 40's reserved 4:3 field, which "shall be
    /// CLEAR" (TPM 2.0 Library Part 2, clause 8.4).
    /// </summary>
    /// <remarks>
    /// An octet carrying a bit <c>TPMA_SESSION</c> does not define is malformed before any attribute in it has a
    /// meaning, so every site that reads a session-attributes octet tests this first.
    /// </remarks>
    private const TpmaSession ReservedSessionAttributes = (TpmaSession)unchecked((byte)~(byte)DefinedSessionAttributes);

    /// <summary>
    /// The format-one session-index encoding (TPM 2.0 Library Part 2, clause 6.6.2): the P bit clear, N field
    /// 8..15 selecting a session by its zero-based index via <c>TPM_RC_S</c> (flips the N field's meaning from
    /// handle to session) plus <c>TPM_RC_n</c> (the 1-based additive block, <c>N = index + 1</c>).
    /// </summary>
    /// <remarks>
    /// Shared by every session-area and session-command-HMAC failure site that can name the offending slot,
    /// including the wire-parse helper that settles a password slot's structural rules before any lookup. A site
    /// that cannot attribute a failure to one slot answers the bare code instead.
    /// </remarks>
    /// <param name="baseRc">The unencoded base response code.</param>
    /// <param name="sessionIndex">The offending session's zero-based index.</param>
    /// <returns>The session-index-encoded response code.</returns>
    internal static TpmRcConstants SessionEncodedRc(TpmRcConstants baseRc, int sessionIndex) =>
        (TpmRcConstants)((uint)baseRc + (uint)TpmRcConstants.TPM_RC_S + (0x100u * (uint)(sessionIndex + 1)));

    /// <summary>
    /// The two rules a <c>TPM_RS_PW</c> authorization slot answers on its wire shape alone, at whatever index in
    /// the authorization area it occupies: its <c>sessionAttributes</c> octet and its <c>nonceCaller</c> width.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A password authorization has no session key, so it can key neither parameter encryption nor an audit
    /// digest: <c>decrypt</c> and <c>encrypt</c> are each "required to be CLEAR in a password session" because
    /// "there is no session key for the decrypt operation", and <c>audit</c> "has no meaning for a password
    /// authorization and is required to be CLEAR" (TPM 2.0 Library Part 1, clause 16.6.4, Table 12);
    /// <c>auditExclusive</c> and <c>auditReset</c> ride the same rule, being claims about an audit digest such a
    /// slot never keeps. Only <c>continueSession</c> is left, and for a password authorization even that "has no
    /// effect". Table 40's reserved 4:3 field joins them through the shared
    /// <see cref="ReservedSessionAttributes"/>: an octet carrying a bit <c>TPMA_SESSION</c> does not define is
    /// malformed before any attribute in it has a meaning.
    /// </para>
    /// <para>
    /// A password authorization carries no nonce either — the caller's field must be zero-length, and the TPM's
    /// echo of it is likewise zero (Part 1, clause 16.6.2.2, Table 11) — so a splicing transport that plants
    /// octets there is refused structurally, before any credential is compared, and the planted value is never
    /// keyed into anything.
    /// </para>
    /// <para>
    /// Both refusals are session-index-encoded to the offending slot, exactly as the reference's
    /// <c>RetrieveSessionData</c> encodes them: it applies this same pair to every slot it unmarshals, before it
    /// looks anything up, answering <c>TPM_RCS_ATTRIBUTES</c> and then <c>TPM_RCS_NONCE</c> ("The nonce size must
    /// be zero") at that slot's own error index. This one helper is the whole rule for the simulator: the wire
    /// readers apply it at the slot they are reading, where the data is, and <see cref="ValidateSessionArea"/>
    /// applies it again as the backstop for an area assembled from a record's already-parsed fields.
    /// </para>
    /// </remarks>
    /// <param name="attributes">The slot's <c>TPMA_SESSION</c> attributes as they arrived on the wire.</param>
    /// <param name="nonceLength">The octet count of the slot's <c>nonceCaller</c> as it arrived on the wire.</param>
    /// <param name="sessionIndex">The slot's zero-based index in the authorization area, for the response encoding.</param>
    /// <param name="refusal">The session-index-encoded response code when this returns <see langword="false"/>; meaningless otherwise.</param>
    /// <returns><see langword="true"/> when the password slot's shape is admissible.</returns>
    internal static bool TryValidatePasswordSlot(TpmaSession attributes, int nonceLength, int sessionIndex, out TpmRcConstants refusal)
    {
        const TpmaSession forbiddenAttributes = TpmaSession.DECRYPT | TpmaSession.ENCRYPT | TpmaSession.AUDIT
            | TpmaSession.AUDIT_EXCLUSIVE | TpmaSession.AUDIT_RESET;

        if((attributes & (ReservedSessionAttributes | forbiddenAttributes)) != 0)
        {
            refusal = SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex);

            return false;
        }

        if(nonceLength != 0)
        {
            refusal = SessionEncodedRc(TpmRcConstants.TPM_RC_NONCE, sessionIndex);

            return false;
        }

        refusal = TpmRcConstants.TPM_RC_SUCCESS;

        return true;
    }

    /// <summary>
    /// The format-zero "session not loaded" warning for the session at <paramref name="sessionIndex"/>
    /// (<c>TPM_RC_REFERENCE_S0..S6</c>, TPM 2.0 Library Part 2, clause 6.6.2) — a contiguous block of distinct
    /// codes, unlike the format-one additive encoding <see cref="SessionEncodedRc"/> builds.
    /// </summary>
    /// <param name="sessionIndex">The offending session's zero-based index.</param>
    /// <returns>The matching <c>TPM_RC_REFERENCE_S*</c> response code.</returns>
    private static TpmRcConstants SessionReferenceMissRc(int sessionIndex) =>
        (TpmRcConstants)((uint)TpmRcConstants.TPM_RC_REFERENCE_S0 + (uint)sessionIndex);

    /// <summary>
    /// Registers a genuine session command-HMAC mismatch and rejects with the matching, session-index-encoded
    /// response code (TPM 2.0 Library Part 3, clause 5.6, check 9).
    /// </summary>
    /// <remarks>
    /// Mirrors <c>RejectNvAuthFailure</c>'s shape (a DA-protected entity's failure increments FailedTries and
    /// re-anchors the self-heal clock to the current Time, unless dictionary-attack protection is globally
    /// disabled — RecoveryTime == 0 — in which case the failure is still reported but the counter never moves); an
    /// entity that is not DA-protected, or no entity was authorized at all, never affects the counter
    /// (TPM_RC_BAD_AUTH). The state-mutation boundary (clause 5.6): only a confirmed AUTH_FAIL may ever touch
    /// FailedTries. <c>TPM_RH_LOCKOUT</c> is the one DA-protected entity this does NOT feed into FailedTries
    /// (clause 17.8's own carve-out — every other permanent hierarchy is DA-exempt, so never reaches here with
    /// <paramref name="isDaProtected"/> SET at all): a mismatch against it instead disables LockoutAuthEnabled and
    /// anchors the self-heal timer (clause 17.8.5), the identical one-strike shape
    /// TPM2_DictionaryAttackLockReset()/TPM2_DictionaryAttackParameters() and TPM2_PolicySecret()'s own password
    /// arm already apply for the same secret — <paramref name="isLockoutEntity"/> carries that distinction into
    /// the one generic mismatch handler every session-authorized command shares.
    /// </remarks>
    /// <param name="state">The state to reject from.</param>
    /// <param name="commandCode">The command being rejected.</param>
    /// <param name="sessionIndex">The offending session's index, for the session-encoded response code.</param>
    /// <param name="isDaProtected">Whether the entity the failed session authorized is dictionary-attack protected.</param>
    /// <param name="isLockoutEntity">Whether the failed session authorized <c>TPM_RH_LOCKOUT</c>, which takes the one-strike disable path instead of incrementing FailedTries.</param>
    /// <returns>The rejection <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> RejectSessionAuthFailure(
        TpmSimulatorState state, TpmCcConstants commandCode, int sessionIndex, bool isDaProtected, bool isLockoutEntity = false)
    {
        if(!isDaProtected)
        {
            return Reject(state, commandCode, SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex));
        }

        if(isLockoutEntity)
        {
            TpmSimulatorState disabled = state with { LockoutAuthEnabled = false, LastLockoutAuthFailureTime = state.Time };

            return Reject(disabled, commandCode, SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex));
        }

        if(state.RecoveryTime == 0)
        {
            return Reject(state, commandCode, SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex));
        }

        TpmSimulatorState registered = state with
        {
            FailedTries = state.FailedTries + 1,
            LastFailedTriesRecoveryTime = state.Time
        };

        return Reject(registered, commandCode, SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex));
    }

    /// <summary>
    /// Registers a genuine session authorization mismatch exactly as
    /// <see cref="RejectSessionAuthFailure(TpmSimulatorState, TpmCcConstants, int, bool, bool)"/> does, first
    /// releasing the in-flight request's owned carriers — the compare-mismatch arm of a command whose request
    /// record owns parse-rented carriers routes through this so no refusal orphans a pinned rental.
    /// </summary>
    /// <param name="state">The state to reject from.</param>
    /// <param name="commandCode">The command being rejected.</param>
    /// <param name="sessionIndex">The offending session's index, for the session-encoded response code.</param>
    /// <param name="isDaProtected">Whether the entity the failed session authorized is dictionary-attack protected.</param>
    /// <param name="ownedInFlight">The request whose owned carriers the refusal releases.</param>
    /// <param name="isLockoutEntity">Whether the failed session authorized <c>TPM_RH_LOCKOUT</c>, which takes the one-strike disable path instead of incrementing FailedTries.</param>
    /// <returns>The rejection <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> RejectSessionAuthFailure(
        TpmSimulatorState state, TpmCcConstants commandCode, int sessionIndex, bool isDaProtected, IDisposable ownedInFlight, bool isLockoutEntity = false)
    {
        ownedInFlight.Dispose();

        return RejectSessionAuthFailure(state, commandCode, sessionIndex, isDaProtected, isLockoutEntity);
    }

    /// <summary>
    /// Validates a command's session area against its structural attribute rules (TPM 2.0 Library Part 3, clause
    /// 5.5), strictly before any command-HMAC is evaluated (clause 5.5 precedes clause 5.6, confirmed against
    /// the reference session-processing routine's own two-phase structure: its per-session
    /// decrypt/encrypt/attribute checks all run during initial session-array retrieval, entirely before its
    /// later per-session authorization loop).
    /// </summary>
    /// <remarks>
    /// <para>
    /// At most one session may set decrypt, at most one may set encrypt; a session authorizing no entity must
    /// set at least one of decrypt/encrypt/audit; decrypt/encrypt SET when the command's corresponding parameter
    /// is not encryptable is <c>TPM_RC_ATTRIBUTES</c>; decrypt/encrypt SET with a negotiated <c>TPM_ALG_NULL</c>
    /// symmetric is <c>TPM_RC_SYMMETRIC</c>. Every rejection is session-index-encoded to the OFFENDING session
    /// (Part 2, clause 6.6.2), sessions checked in order so a session re-setting an already-claimed attribute is
    /// blamed on itself, never the session that claimed it first. Shared by every session-authorized command
    /// transition that carries a session possibly requesting parameter encryption.
    /// </para>
    /// <para>
    /// One rule here is about the area rather than about any one session's attributes: "For a given command, the
    /// handle associated with a specific HMAC or policy session can occur only once in the Authorization Area. The
    /// handle representing a password authorization (TPM_RS_PW) can occur multiple times" (Part 1, clause 16.6.3).
    /// A repeated real handle would have one session's nonceTPM answer two entries and roll once, so it is refused
    /// structurally here, before any authorization work. Part 1 names no response code for the violation, but the
    /// reference does: its <c>RetrieveSessionData</c>, walking the area a slot at a time, answers
    /// <c>TPM_RCS_HANDLE + errorIndex</c> for a handle already seen at an earlier index — the offending entry, by
    /// the same "blame the session that repeats" rule the decrypt/encrypt duplicate checks below follow (Part 2,
    /// clause 6.6.2 for the encoding).
    /// </para>
    /// <para>
    /// A third slot is admitted for a session that authorizes nothing and exists only to carry decrypt, encrypt,
    /// or audit: an authorization area holds "at least one but no more than three" blocks (Part 1, clause 16.6.1),
    /// and Table 9's position 3 may be encryption, decryption, or audit only, with "authorization sessions come
    /// before sessions used only for encryption, decryption, or audit". No defined command requires more than two
    /// authorizations, so the third slot never authorizes an entity and the catch-all rule below — a session
    /// authorizing nothing must claim at least one of the three attributes — always applies to it. The
    /// decrypt/encrypt claims accumulate across the slots in area order, so the third slot is blamed for
    /// re-claiming what an earlier one took, never the other way round. A third slot presupposes a second: the
    /// area is read positionally, so position 3 cannot arrive without position 2.
    /// </para>
    /// <para>
    /// Per-session bit rules follow Part 2, clause 8.4, Table 40 in the table's own bit order: the reserved 4:3
    /// field "shall be CLEAR"; <c>auditExclusive</c> (bit 1) and <c>auditReset</c> (bit 2) are "only allowed if
    /// the audit attribute is SET (TPM_RC_ATTRIBUTES)". Both are refused rather than masked off, because a caller
    /// that set them believes something about how the command is being audited.
    /// </para>
    /// <para>
    /// A <c>TPM_RS_PW</c> slot carries no session key and no nonce, so two further rules apply to it alone. Its
    /// attributes: <c>decrypt</c> and <c>encrypt</c> are each "required to be CLEAR in a password session. If SET
    /// in a password session, then the TPM will return an error because there is no session key for the
    /// decrypt operation", and <c>audit</c> "has no meaning for a password authorization and is required to be
    /// CLEAR" (Part 1, clause 16.6.4, Table 12) — the reference refuses all five of <c>decrypt</c>,
    /// <c>encrypt</c>, <c>audit</c>, <c>auditExclusive</c>, and <c>auditReset</c> on such a slot with
    /// <c>TPM_RCS_ATTRIBUTES</c>. Its nonce: a password authorization has none, so a non-empty
    /// <c>nonceCaller</c> is <c>TPM_RCS_NONCE</c> at that slot (the reference's "The nonce size must be zero";
    /// the response side of the same fact is Part 1, clause 16.6.2.2, Table 11's "will be zero for a password
    /// authorization"). Both are settled before the per-attribute gates below, so a password slot claiming
    /// <c>decrypt</c> is blamed for the attribute it may not carry rather than for a symmetric algorithm it
    /// never negotiated.
    /// </para>
    /// </remarks>
    /// <param name="firstAttributes">The first session's <c>TPMA_SESSION</c> attributes octet.</param>
    /// <param name="firstAuthorizesEntity">Whether the first session authorizes an entity.</param>
    /// <param name="firstSymmetric">The first session's negotiated symmetric algorithm.</param>
    /// <param name="hasSecondSession">Whether a second session is present in the area.</param>
    /// <param name="secondAttributes">The second session's <c>TPMA_SESSION</c> attributes octet.</param>
    /// <param name="secondSymmetric">The second session's negotiated symmetric algorithm.</param>
    /// <param name="firstCommandParameterIsEncryptable">Whether the command's first parameter accepts decrypt.</param>
    /// <param name="firstResponseParameterIsEncryptable">Whether the response's first parameter accepts encrypt.</param>
    /// <param name="auditIsSupported">
    /// Whether the calling transition models command audit. When it does not, a session claiming the
    /// <c>audit</c> attribute is refused with <c>TPM_RC_ATTRIBUTES</c> rather than admitted and silently
    /// unaudited — the same fail-closed posture the decrypt/encrypt flags express for parameter encryption.
    /// </param>
    /// <param name="secondAuthorizesEntity">
    /// Whether the SECOND session authorizes an entity of its own. Every command that admitted a second session
    /// before <c>TPM2_NV_Certify()</c> admitted it as a decrypt/encrypt/audit companion authorizing nothing, so
    /// this defaults to <see langword="false"/>; <c>TPM2_NV_Certify()</c> is the first with two authorized
    /// handles (Part 3, clause 31.16.2, Table 254: <c>@signHandle</c> Auth Index 1 and <c>@authHandle</c> Auth
    /// Index 2, both USER role), and its second session would otherwise be refused by the catch-all rule that a
    /// session authorizing nothing must claim at least one attribute.
    /// </param>
    /// <param name="firstSessionHandle">
    /// The first slot's session handle, for the once-only handle rule of Part 1, clause 16.6.3 and for the
    /// password-slot attribute and nonce rules of Part 1, clause 16.6.4, Table 12. It defaults to zero, which is
    /// no handle at all (Part 2, clause 9.8, Table 55 admits only HMAC sessions, policy sessions, and
    /// <c>TPM_RS_PW</c>), so a caller naming no handles asserts nothing about its slots and those rules find
    /// nothing to test — which is what a command whose single real authorization session cannot collide with
    /// itself wants.
    /// </param>
    /// <param name="secondSessionHandle">The second slot's session handle, defaulting to the same "asserts nothing" zero for the same reason.</param>
    /// <param name="hasThirdSession">
    /// Whether a third slot is present in the area — a companion authorizing no entity, carried only for
    /// decrypt, encrypt, or audit (Part 1, clause 16.6.1, Table 9, position 3). It presupposes
    /// <paramref name="hasSecondSession"/>, since the area is read positionally.
    /// </param>
    /// <param name="thirdAttributes">The third slot's <c>TPMA_SESSION</c> attributes octet.</param>
    /// <param name="thirdSymmetric">
    /// The third slot's negotiated symmetric algorithm, or <see langword="null"/> when no third slot is present.
    /// It is nullable rather than defaulted because <c>default(TpmtSymDef)</c> carries <c>Algorithm</c> zero —
    /// <c>TPM_ALG_ERROR</c>, not <c>TPM_ALG_NULL</c> — and so would read as a NEGOTIATED algorithm, silently
    /// admitting a decrypt or encrypt claim that <see cref="TpmtSymDef.Null"/> refuses with
    /// <c>TPM_RC_SYMMETRIC</c>.
    /// </param>
    /// <param name="thirdSessionHandle">The third slot's session handle, for the once-only handle rule against both earlier slots and for the password-slot attribute and nonce rules; defaults to the same "asserts nothing" zero.</param>
    /// <param name="firstNonceLength">
    /// The octet count of the first slot's <c>nonceCaller</c> as it arrived on the wire, for the password-slot
    /// nonce rule. It matters only where <paramref name="firstSessionHandle"/> names <c>TPM_RS_PW</c>, since a
    /// real session's nonce width is settled by its own KDFa rather than by this area check, and it defaults to
    /// zero so a caller asserting nothing about its slots asserts nothing here either.
    /// </param>
    /// <param name="secondNonceLength">The second slot's <c>nonceCaller</c> octet count, defaulting to zero for the same reason.</param>
    /// <param name="thirdNonceLength">The third slot's <c>nonceCaller</c> octet count, defaulting to zero for the same reason.</param>
    /// <returns>The session-index-encoded rejection code, or <see langword="null"/> when the area is valid.</returns>
    private static TpmRcConstants? ValidateSessionArea(
        TpmaSession firstAttributes, bool firstAuthorizesEntity, TpmtSymDef firstSymmetric,
        bool hasSecondSession, TpmaSession secondAttributes, TpmtSymDef secondSymmetric,
        bool firstCommandParameterIsEncryptable, bool firstResponseParameterIsEncryptable,
        bool auditIsSupported = true, bool secondAuthorizesEntity = false,
        TpmiShAuthSession firstSessionHandle = default, TpmiShAuthSession secondSessionHandle = default,
        bool hasThirdSession = false, TpmaSession thirdAttributes = default, TpmtSymDef? thirdSymmetric = null,
        TpmiShAuthSession thirdSessionHandle = default,
        int firstNonceLength = 0, int secondNonceLength = 0, int thirdNonceLength = 0)
    {
        TpmRcConstants? firstError = ValidateSessionAttributes(
            firstAttributes, firstAuthorizesEntity, firstSymmetric, IsPasswordSlot(firstSessionHandle), firstNonceLength, sessionIndex: 0,
            decryptClaimed: false, encryptClaimed: false,
            firstCommandParameterIsEncryptable, firstResponseParameterIsEncryptable, auditIsSupported);
        if(firstError is not null)
        {
            return firstError;
        }

        if(!hasSecondSession)
        {
            return null;
        }

        //A specific HMAC or policy session handle can occur only once in the area, while TPM_RS_PW may repeat
        //(Part 1, clause 16.6.3). Part 1 names no response code, but the reference does: RetrieveSessionData
        //answers TPM_RCS_HANDLE + errorIndex when a slot names a handle an earlier slot already named. It is
        //encoded to the SECOND occurrence — the offending entry, by the same "blame the session that repeats"
        //rule the decrypt/encrypt duplicate checks below follow (Part 2, clause 6.6.2).
        bool isFirstSlotReal = IsRealSessionSlot(firstSessionHandle);
        if(isFirstSlotReal && firstSessionHandle == secondSessionHandle)
        {
            return SessionEncodedRc(TpmRcConstants.TPM_RC_HANDLE, sessionIndex: 1);
        }

        bool decryptClaimedByFirst = (firstAttributes & TpmaSession.DECRYPT) != 0;
        bool encryptClaimedByFirst = (firstAttributes & TpmaSession.ENCRYPT) != 0;

        TpmRcConstants? secondError = ValidateSessionAttributes(
            secondAttributes, secondAuthorizesEntity, secondSymmetric, IsPasswordSlot(secondSessionHandle), secondNonceLength, sessionIndex: 1,
            decryptClaimedByFirst, encryptClaimedByFirst,
            firstCommandParameterIsEncryptable, firstResponseParameterIsEncryptable, auditIsSupported);
        if(secondError is not null)
        {
            return secondError;
        }

        if(!hasThirdSession)
        {
            return null;
        }

        //The once-only handle rule again, now against BOTH earlier slots: a third occurrence of a real handle is
        //the offending entry whichever of the two it repeats (Part 1, clause 16.6.3; the reference's
        //RetrieveSessionData compares each slot against every earlier one and answers TPM_RCS_HANDLE).
        bool isSecondSlotReal = IsRealSessionSlot(secondSessionHandle);
        if((isFirstSlotReal && firstSessionHandle == thirdSessionHandle)
            || (isSecondSlotReal && secondSessionHandle == thirdSessionHandle))
        {
            return SessionEncodedRc(TpmRcConstants.TPM_RC_HANDLE, sessionIndex: 2);
        }

        //Slot 2 authorizes nothing: "no command requires more than two authorizations" (Part 1, clause 16.6.1),
        //so Table 9's position 3 is a companion carried for decrypt, encrypt, or audit alone and the catch-all
        //rule below always applies to it. The decrypt/encrypt claims accumulate across slots 0 and 1 first, so a
        //third slot re-claiming what an earlier one took is blamed on itself.
        return ValidateSessionAttributes(
            thirdAttributes, authorizesEntity: false, thirdSymmetric ?? TpmtSymDef.Null, IsPasswordSlot(thirdSessionHandle), thirdNonceLength, sessionIndex: 2,
            decryptClaimedByFirst || (secondAttributes & TpmaSession.DECRYPT) != 0,
            encryptClaimedByFirst || (secondAttributes & TpmaSession.ENCRYPT) != 0,
            firstCommandParameterIsEncryptable, firstResponseParameterIsEncryptable, auditIsSupported);

        //Whether a slot the caller named holds a real (HMAC or policy) session, which the once-only handle rule
        //governs; a slot the caller left unnamed (zero, no handle at all) asserts nothing and a TPM_RS_PW slot is
        //the one Part 1, clause 16.6.3 exempts because it may repeat.
        static bool IsRealSessionSlot(TpmiShAuthSession sessionHandle) => sessionHandle.Value != 0 && !sessionHandle.IsPasswordSession;

        //Whether a slot the caller named is a password authorization; a slot left unnamed asserts nothing.
        static bool IsPasswordSlot(TpmiShAuthSession sessionHandle) => sessionHandle.IsPasswordSession;

        //One session's own attribute checks: the reserved field first, since an octet carrying a bit TPMA_SESSION
        //does not define is malformed before any attribute in it has a meaning, then the password-slot rules (the
        //reference settles a password slot's attributes and its nonce, in that order, and moves to the next slot
        //without reaching the per-attribute gates), then the reference's own per-attribute order (decrypt, then
        //encrypt, then the audit family, then the "must authorize or be decrypt/encrypt/audit" catch-all).
        static TpmRcConstants? ValidateSessionAttributes(
            TpmaSession attributes, bool authorizesEntity, TpmtSymDef symmetric, bool isPasswordSlot, int nonceLength, int sessionIndex,
            bool decryptClaimed, bool encryptClaimed,
            bool commandParameterIsEncryptable, bool responseParameterIsEncryptable, bool auditIsSupported)
        {
            //Table 40's reserved 4:3 field, which "shall be CLEAR" (Part 2, clause 8.4), read from the shared
            //ReservedSessionAttributes so the mask this backstop applies and the mask the wire readers apply are
            //literally the same octet.
            if((attributes & ReservedSessionAttributes) != 0)
            {
                return SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex);
            }

            bool decrypt = (attributes & TpmaSession.DECRYPT) != 0;
            bool encrypt = (attributes & TpmaSession.ENCRYPT) != 0;
            bool audit = (attributes & TpmaSession.AUDIT) != 0;
            bool isAuditExclusive = (attributes & TpmaSession.AUDIT_EXCLUSIVE) != 0;
            bool isAuditReset = (attributes & TpmaSession.AUDIT_RESET) != 0;

            //A password slot's structural rules are the ONE shared rule (TryValidatePasswordSlot, Part 1, clause
            //16.6.4, Table 12), applied here as the backstop for an area assembled from a record's fields: the
            //wire readers already applied it at the slot they read. The refusal is TPM_RC_ATTRIBUTES about the
            //attribute the slot may not carry, never TPM_RC_SYMMETRIC about the algorithm it never negotiated, so
            //it is settled before the per-attribute gates below.
            if(isPasswordSlot && !TryValidatePasswordSlot(attributes, nonceLength, sessionIndex, out TpmRcConstants passwordSlotRefusal))
            {
                return passwordSlotRefusal;
            }

            if(decrypt)
            {
                if(!commandParameterIsEncryptable)
                {
                    return SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex);
                }

                if(decryptClaimed)
                {
                    return SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex);
                }

                if(symmetric.IsNull)
                {
                    return SessionEncodedRc(TpmRcConstants.TPM_RC_SYMMETRIC, sessionIndex);
                }
            }

            if(encrypt)
            {
                if(!responseParameterIsEncryptable)
                {
                    return SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex);
                }

                if(encryptClaimed)
                {
                    return SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex);
                }

                if(symmetric.IsNull)
                {
                    return SessionEncodedRc(TpmRcConstants.TPM_RC_SYMMETRIC, sessionIndex);
                }
            }

            //A transition that models no audit trail refuses the attribute outright rather than accepting a
            //session that claims the command is being audited, echoing the claim back in the response session
            //entry, and auditing nothing: a caller reading that echo would believe an audit digest exists.
            if(audit && !auditIsSupported)
            {
                return SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex);
            }

            //auditExclusive and auditReset have meaning only for an audit session: both are "only allowed if the
            //audit attribute is SET (TPM_RC_ATTRIBUTES)" (Part 2, clause 8.4, Table 40, bits 1 and 2). A
            //transition that models no audit has already refused the audit bit above, so with audit CLEAR here
            //these two are the caller's own contradiction — a claim about an audit digest that this command's area
            //never establishes — and are refused rather than ignored.
            if((isAuditExclusive || isAuditReset) && !audit)
            {
                return SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex);
            }

            if(!authorizesEntity && !decrypt && !encrypt && !audit)
            {
                return SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex);
            }

            return null;
        }
    }

    /// <summary>
    /// Finds the ONE slot of a command's authorization area claiming a parameter-encryption attribute, searching
    /// in area order (TPM 2.0 Library Part 1, clause 19.1: "The encrypt attribute can only be SET in one session
    /// that is used in a command and the decrypt attribute can only be SET in one session per command. The
    /// attributes can be SET in different sessions or in the same session").
    /// </summary>
    /// <remarks>
    /// Keyed on the attribute BIT, never on a slot's kind or its mere presence: either attribute may ride an
    /// authorizing session or a companion that authorizes nothing (Part 1, Table 12: "A session with this
    /// attribute does not need to be associated with an entity identified in the handle area"), and a companion
    /// may equally carry audit alone and decrypt nothing. <see cref="ValidateSessionArea"/> has already refused a
    /// second claimer, so the first match in area order is the only one.
    /// </remarks>
    /// <param name="slotAttributes">Every slot's command session-attributes octet, in authorization-area order.</param>
    /// <param name="attribute">The attribute to find — <c>TPMA_SESSION.decrypt</c> or <c>TPMA_SESSION.encrypt</c>.</param>
    /// <returns>The claiming slot's zero-based index, or <c>-1</c> when no slot claims it.</returns>
    private static int FindClaimingSlot(ReadOnlySpan<TpmaSession> slotAttributes, TpmaSession attribute)
    {
        for(int index = 0; index < slotAttributes.Length; index++)
        {
            if((slotAttributes[index] & attribute) != 0)
            {
                return index;
            }
        }

        return -1;
    }

    /// <summary>
    /// Assembles the two nonceTPM terms an attest command's FIRST session folds into its command HMAC when
    /// another slot carries a parameter-encryption attribute (TPM 2.0 Library Part 1, clause 17.6.3.4: "To
    /// prevent removal of extra encrypting sessions, the nonceTPM of each of these sessions is included in the
    /// HMAC computation of the first authorization session of a command").
    /// </summary>
    /// <remarks>
    /// <para>
    /// Equation 17 (clause 17.6.5) orders the terms decrypt-then-encrypt and takes the same session's nonceTPM
    /// ONCE: "If the same session (not the first session) is used for decrypt and encrypt, its nonceTPM is only
    /// used once. If different sessions are used for decrypt and encrypt, both nonceTPMs are included." A slot
    /// never folds its OWN nonceTPM, so a claim riding session 0 itself contributes nothing — the same reading
    /// the host executor applies, and the two sides must agree octet for octet or every command over an
    /// encrypting session fails its HMAC.
    /// </para>
    /// <para>
    /// The two terms stay separate rather than being concatenated here because a pure transition holds no memory
    /// pool: each is a borrow of the durable session record's own nonceTPM, and the verifying effect lays them
    /// end to end inside the pooled scratch it already assembles.
    /// </para>
    /// </remarks>
    /// <param name="slotSessions">Every slot's resolved session in authorization-area order, <see langword="null"/> where a slot is a password or resolved to no session at all.</param>
    /// <param name="decryptIndex">The slot claiming <c>decrypt</c>, or <c>-1</c>.</param>
    /// <param name="encryptIndex">The slot claiming <c>encrypt</c>, or <c>-1</c>.</param>
    /// <returns>The decrypt session's nonceTPM term and the encrypt session's, each the shared empty carrier where it does not apply; both are borrows the durable session records own.</returns>
    private static (Tpm2bNonce Decrypt, Tpm2bNonce Encrypt) FoldedSessionNonces(
        ReadOnlySpan<HmacSessionState?> slotSessions, int decryptIndex, int encryptIndex)
    {
        //Total in both arguments: a slot index is answered with what that slot actually resolved to, so a slot
        //holding no session contributes an empty term rather than being asserted to hold one. Nothing here
        //decides whether the area is well formed — the caller's own gates do that, and this must stay
        //answerable for every index they can hand it.
        Tpm2bNonce decrypt = decryptIndex > 0 && slotSessions[decryptIndex] is HmacSessionState decryptSession
            ? decryptSession.NonceTpm
            : Tpm2bNonce.Empty;
        Tpm2bNonce encrypt = encryptIndex > 0 && encryptIndex != decryptIndex && slotSessions[encryptIndex] is HmacSessionState encryptSession
            ? encryptSession.NonceTpm
            : Tpm2bNonce.Empty;

        return (decrypt, encrypt);
    }

    /// <summary>
    /// Removes trailing zero octets from an authorization value before it is used in an authorization
    /// computation or compare (TPM 2.0 Library Part 1, clause 17.6.4.3) — applied to both sides of a password
    /// compare and to an authValue folded into a command- or response-HMAC key alike.
    /// </summary>
    /// <param name="value">The authorization value to strip.</param>
    /// <returns>The value with any trailing zero octets removed.</returns>
    internal static ReadOnlySpan<byte> StripTrailingZeros(ReadOnlySpan<byte> value)
    {
        int end = value.Length;
        while(end > 0 && value[end - 1] == 0)
        {
            end--;
        }

        return value[..end];
    }

    /// <summary>
    /// Removes trailing zero octets from an authorization value held in durable model memory, returning a SLICE
    /// of that same memory rather than a copy (TPM 2.0 Library Part 1, clause 17.6.4) — the stripped form an
    /// in-flight verification or framing record borrows. No secret ever lands on the garbage-collected heap
    /// here: the durable state's buffer is the single owner, every field is only ever replaced wholesale (never
    /// mutated in place), so a borrowed slice is a stable snapshot of the value as it stood when taken.
    /// </summary>
    /// <param name="value">The authorization value to strip.</param>
    /// <returns>A slice of <paramref name="value"/> with any trailing zero octets excluded.</returns>
    internal static ReadOnlyMemory<byte> StripTrailingZeros(ReadOnlyMemory<byte> value)
    {
        return value[..StripTrailingZeros(value.Span).Length];
    }

    /// <summary>
    /// Whether a PIN Index's own authValue is currently unusable for authorization — unwritten, or its pinCount
    /// has reached pinLimit (TPM 2.0 Library Part 1, clause 37.2.6.6).
    /// </summary>
    /// <remarks>
    /// Checked strictly ahead of the credential compare, mirroring <c>IsNvIndexLockedOut</c>'s own "refuse before
    /// comparing" shape; a non-PIN Index is never subject to this gate. <c>TPM2_NV_Write()</c> is deliberately
    /// not one of this gate's call sites: a PIN Index now forbids <c>TPMA_NV_AUTHWRITE</c> outright (clause
    /// 37.2.6.1, enforced at <c>TPM2_NV_DefineSpace()</c>), so its own authValue never reaches
    /// <c>OnNvWrite</c>'s index-authValue arm at all; recovery is the owner-authorized arm's administrative
    /// rewrite of the retained pinCount/pinLimit data (clause 37.2.8.1: no automatic self-heal exists "until
    /// pinCount is reduced or pinLimit increased using TPM2_NV_Write()"), which is never gated by this property.
    /// Shared by every arm that resolves authorization against a PIN Index's own authValue: the read and
    /// certify handlers and <c>TPM2_PolicyNV()</c> on their password entries, and the read, certify, and
    /// change-auth handlers on their session entries.
    /// </remarks>
    /// <param name="index">The NV Index being authorized.</param>
    /// <returns><see langword="true"/> when the Index's own authValue is currently unusable.</returns>
    private static bool IsPinAuthUnavailable(NvIndexState index) =>
        index.IsPinIndex && !index.IsPinAuthAvailable;

    /// <summary>
    /// Applies a PIN Index's own pinCount update for the outcome of an authorization attempt against it (TPM
    /// 2.0 Library Part 1, clause 37.2.6.6): a PIN Fail Index resets pinCount to zero on success and increments
    /// it on failure; a PIN Pass Index increments pinCount on success and leaves it unchanged on failure.
    /// </summary>
    /// <remarks>
    /// A non-PIN Index is returned unchanged. Shared by every arm that compares a PIN Index's own authValue:
    /// the password handlers apply it inline on either outcome, while a session-authorized area splits it —
    /// the success side in the continuation that resumes once the authorization is proven, the failure side in
    /// <c>RejectNvSessionAuthFailure</c> for a mismatching command HMAC and in <c>OnNvCertifyOverSession</c>'s
    /// own inline update for a mismatching password slot in its session area.
    /// </remarks>
    /// <param name="index">The NV Index to update.</param>
    /// <param name="authMatched">Whether the authorization attempt against <paramref name="index"/> succeeded.</param>
    /// <returns>The Index with its pinCount updated for the outcome.</returns>
    private static NvIndexState ApplyPinAuthOutcome(NvIndexState index, bool authMatched)
    {
        if(index.IsPinFail)
        {
            return index.WithPinCount(authMatched ? 0u : index.PinCount + 1);
        }

        if(index.IsPinPass && authMatched)
        {
            return index.WithPinCount(index.PinCount + 1);
        }

        return index;
    }

    /// <summary>
    /// Authorizes against an NV Index and reads its data for <c>TPM2_NV_Read()</c>.
    /// </summary>
    /// <remarks>
    /// This slice models Index authorization (the authorization handle is the Index itself, its
    /// <c>TPMA_NV_AUTHREAD</c> availability gated ahead of the value compare per Part 3, clause 5.6's check
    /// 7.2.2), the owner-authorized arm (<c>authHandle == TPM_RH_OWNER</c>, gated on <c>TPMA_NV_OWNERREAD</c>,
    /// Part 3, clause 31.13's "Proper authorizations ... determined by TPMA_NV_PPREAD, TPMA_NV_OWNERREAD,
    /// TPMA_NV_AUTHREAD"), and the authorization outcomes that the DA/PIN flow turns on; the data-returning
    /// path is here, and the lockout-counter coupling (clause 17.8.3) is wired through
    /// <c>IsNvIndexLockedOut</c>/<c>RejectNvAuthFailure</c> above.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_NV_Read()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnNvRead(TpmSimulatorState state, TpmNvReadRequested request)
    {
        //The Index must exist (Part 3, clause 31.13).
        if(!state.NvIndexes.TryGetValue(request.NvIndex, out NvIndexState? index))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Read, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        //An owner-authorized read is administrative: compared against the owner hierarchy's own authValue,
        //which is never dictionary-attack protected (Part 1, clause 17.8.1: "the authValue associated with a
        //permanent entity, other than TPM_RH_LOCKOUT, does not receive DA protection"), so a mismatch is a
        //plain bad-authorization. On a match the read proceeds directly - none of IsNvIndexLockedOut/
        //IsPinAuthUnavailable/ApplyPinAuthOutcome apply, since this arm authorizes the OWNER, not the
        //Index's own authValue/PIN: pinCount moves only when the INDEX's own authValue resolves the
        //authorization (Part 1, clause 37.2.6.6), never on the administrative owner path. Mirrors
        //TPM2_NV_Write()'s owner arm exactly.
        if(request.AuthHandle.Value == (uint)TpmRh.TPM_RH_OWNER)
        {
            //With TPMA_NV_OWNERREAD clear owner authorization cannot read this Index (Part 3, clause 31.13) -
            //checked BEFORE the owner-auth compare below, the same non-leaking order the owner-write arm's
            //TPMA_NV_OWNERWRITE gate uses.
            if(!index.IsOwnerReadAllowed)
            {
                return Reject(state, TpmCcConstants.TPM_CC_NV_Read, TpmRcConstants.TPM_RC_NV_AUTHORIZATION, request);
            }

            if(!CryptographicOperations.FixedTimeEquals(StripTrailingZeros(request.AuthSupplied.AsReadOnlySpan()), StripTrailingZeros(state.OwnerAuth.AsReadOnlySpan())))
            {
                return Reject(state, TpmCcConstants.TPM_CC_NV_Read, TpmRcConstants.TPM_RC_BAD_AUTH, request);
            }

            //The compare above was this credential's only use, so this transition is its terminal owner;
            //every arm that refuses before this point releases it through the request's own Dispose.
            request.AuthSupplied.Dispose();

            return ReadIndexWindow(state, index, request.Offset, request.Size);
        }

        //Otherwise only Index authorization (authHandle == nvIndex) is modelled this slice; policy-authorized
        //reads against the same Index arrive later.
        if(request.AuthHandle.Value != request.NvIndex.Value)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Read, TpmRcConstants.TPM_RC_AUTH_TYPE, request);
        }

        //Already-locked-out DA-protected Index: refuse before even comparing (clause 17.8.3), no further increment.
        if(IsNvIndexLockedOut(state, index))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Read, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        //A PIN Index's own authValue is not usable while unwritten or once pinCount has reached pinLimit
        //(clause 37.2.6.6) — refused before even comparing, the same shape as the general-lockout gate above
        //but scoped to this Index's own localized counter rather than the TPM-wide one. This gate is
        //Index-arm-only: it never applies to the owner-read arm above, which has already returned by this
        //point (Part 1, clause 37.2.6.6 ties pinCount availability to the Index's OWN authValue).
        if(IsPinAuthUnavailable(index))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Read, TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, request);
        }

        //With TPMA_NV_AUTHREAD clear, the Index's own authValue is not an available authorization mechanism
        //for this read-role command at all (Part 1, clause 35.2.5), and access control precedes authorization
        //(Part 1, clause 14): Part 3, clause 5.6's check 7.2.2 (an NV Index authorized by an HMAC session or a
        //password needs TPMA_NV_AUTHREAD SET, TPM_RC_AUTH_UNAVAILABLE) is ordered ahead of its check 9/10
        //credential comparison, so a correct and a wrong value are refused identically, no comparison outcome
        //can charge the dictionary-attack counter, and a PIN Index's pinCount never moves for an Index no
        //authValue-based read is permitted against — the same early availability gate, in the same position,
        //that TPM2_NV_Certify()'s and TPM2_PolicyNV()'s Index arms apply.
        if(!index.IsAuthReadAllowed)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Read, TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, request);
        }

        //Constant-time comparison of the supplied authorization against the Index authValue. A mismatch is
        //an auth-failure for a DA-protected Index (clause 17.8.3 — feeds the lockout counter) and a plain
        //bad-authorization for a non-DA Index (clause 17.8.1). A PIN Index's own pinCount is updated on
        //either outcome (clause 37.2.6.6) ahead of the DA-counter check below: authorization is resolved
        //before the command body runs, so the update applies regardless of what the body itself later
        //decides (Part 1, clause 17).
        bool authMatched = CryptographicOperations.FixedTimeEquals(StripTrailingZeros(request.AuthSupplied.AsReadOnlySpan()), StripTrailingZeros(index.AuthValue.AsReadOnlySpan()));
        if(index.IsPinIndex)
        {
            index = ApplyPinAuthOutcome(index, authMatched);
            state = state with { NvIndexes = state.NvIndexes.SetItem(index.NvIndex, index) };
        }

        if(!authMatched)
        {
            request.Dispose();

            return RejectNvAuthFailure(state, index, TpmCcConstants.TPM_CC_NV_Read);
        }

        //The compare above was this credential's only use, so this transition is its terminal owner;
        //every arm that refuses before this point releases it through the request's own Dispose.
        request.AuthSupplied.Dispose();

        return ReadIndexWindow(state, index, request.Offset, request.Size);

        //Authorization has already been resolved by either arm above. An Index that has never been written
        //(TPMA_NV_WRITTEN clear) is uninitialized, so a read of it answers TPM_RC_NV_UNINITIALIZED (Part 3,
        //clause 31.13) - for the owner arm this is reachable (a PIN Index's IsPinAuthUnavailable gate is
        //Index-arm-only, so an unwritten Index's owner-read is NOT pre-empted by AUTH_UNAVAILABLE the way the
        //Index arm's is). The requested window must then lie within the octets the Index has been written
        //with (TPM_RC_NV_RANGE on overrun); the endorsement-provisioning flow reads back exactly what it
        //wrote. Shared by both authorization arms above, so this body runs once, after either arm has
        //already resolved authorization.
        static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> ReadIndexWindow(
            TpmSimulatorState state, NvIndexState index, ushort offset, ushort size)
        {
            if(!TryValidateNvReadWindow(index, offset, size, out TpmRcConstants rejectCode))
            {
                return Reject(state, TpmCcConstants.TPM_CC_NV_Read, rejectCode);
            }

            //Return the stored octets at the requested offset/length as a BORROW of the Index's own data
            //carrier, framed into the response as a TPM2B_MAX_NV_BUFFER by the serializer, which copies the
            //window's octets and releases nothing — the Index outlives the command and stays the owner.
            return Transition(
                state with { ResponseIntent = new TpmNvReadDataResponse(TpmRcConstants.TPM_RC_SUCCESS, new TpmNvDataWindow(index.Data, offset, size)) },
                "NvRead");
        }
    }

    /// <summary>
    /// Validates a requested read window against a defined NV Index's written extent (TPM 2.0 Library Part 3,
    /// clause 31.13): an Index that has never been written (<c>TPMA_NV_WRITTEN</c> clear) answers
    /// <c>TPM_RC_NV_UNINITIALIZED</c>; a requested size wider than a <c>TPM2B_MAX_NV_BUFFER</c> can carry answers
    /// <c>TPM_RC_VALUE</c>; otherwise the window must lie within the octets actually written
    /// (<c>TPM_RC_NV_RANGE</c> on overrun).
    /// </summary>
    /// <remarks>
    /// Shared by the password-authorized <c>OnNvRead</c> (via its own <c>ReadIndexWindow</c> local function) and
    /// the HMAC-session-authorized <c>ContinueNvReadOverSession</c>, whose success framing differs (a direct
    /// response vs. a session-authorized one) but whose range checks are identical — extracted so both arms stay
    /// byte-for-byte consistent rather than risking two independently-maintained copies of the same check. The
    /// three checks run in the order the reference's own <c>TPM2_NV_Read</c> runs them: the access checks that
    /// produce <c>TPM_RC_NV_UNINITIALIZED</c>, then the buffer bound ("Make sure the data will fit the return
    /// buffer", <c>in-&gt;size &gt; MAX_NV_BUFFER_SIZE</c> answering <c>TPM_RC_VALUE</c>), then the
    /// within-the-Index range. Clause 31.13.1 states the range rule and the offset rule but names no buffer
    /// bound of its own; the bound is Table 249's response parameter being a <c>TPM2B_MAX_NV_BUFFER</c>, which
    /// Part 2, clause 10.4.9, Table 99 limits to <c>MAX_NV_BUFFER_SIZE</c> — the value this library fixes at
    /// <see cref="Tpm2bMaxNvBuffer.MaxSize"/> and reports through <c>TPM_PT_NV_BUFFER_MAX</c>. The code is
    /// answered bare, as every other refusal these two arms frame is.
    /// <para>
    /// The range the last check applies is the Index's WRITTEN extent (<see cref="TpmNvIndexData.Length"/>),
    /// where the clause states the rule over the Index's declared size: "If offset and the size field of data
    /// add to a value that is greater than the dataSize field of the NV Index referenced by nvIndex, the TPM
    /// shall return an error (TPM_RC_NV_RANGE)" (clause 31.13.1). A window that lies inside the declared
    /// <c>dataSize</c> but reaches past the octets a store has written is therefore <c>TPM_RC_NV_RANGE</c> in
    /// this model, where the clause admits it.
    /// </para>
    /// </remarks>
    /// <param name="index">The NV Index being read.</param>
    /// <param name="offset">The requested octet offset into the Index data area.</param>
    /// <param name="size">The requested number of octets.</param>
    /// <param name="rejectCode">The response code to reject with when the window is invalid.</param>
    /// <returns><see langword="true"/> when the window is valid.</returns>
    private static bool TryValidateNvReadWindow(NvIndexState index, ushort offset, ushort size, out TpmRcConstants rejectCode)
    {
        if(!index.IsWritten)
        {
            rejectCode = TpmRcConstants.TPM_RC_NV_UNINITIALIZED;

            return false;
        }

        //The buffer bound answers TPM_RC_VALUE ahead of clause 31.13.1's TPM_RC_NV_RANGE "shall", the order the
        //reference's own TPM2_NV_Read applies; the clause itself names no buffer bound, which comes instead from
        //Table 249's response parameter being a TPM2B_MAX_NV_BUFFER and Part 2, clause 10.4.9, Table 99's
        //MAX_NV_BUFFER_SIZE limit on that structure.
        if(size > Tpm2bMaxNvBuffer.MaxSize)
        {
            rejectCode = TpmRcConstants.TPM_RC_VALUE;

            return false;
        }

        if((long)offset + size > index.Data.Length)
        {
            rejectCode = TpmRcConstants.TPM_RC_NV_RANGE;

            return false;
        }

        rejectCode = TpmRcConstants.TPM_RC_SUCCESS;

        return true;
    }

    /// <summary>
    /// Writes data to a defined NV Index at an offset for <c>TPM2_NV_Write()</c>, then sets
    /// <c>TPMA_NV_WRITTEN</c> (Part 3, clause 31.7).
    /// </summary>
    /// <remarks>
    /// This slice models two authorization arms: Index authorization (<c>authHandle == nvIndex</c>, gated by
    /// <c>TPMA_NV_AUTHWRITE</c>) and owner authorization (<c>authHandle == TPM_RH_OWNER</c>, administrative and
    /// never DA/PIN gated — the sole write path for a PIN Index, whose own authValue forbids AUTHWRITE outright,
    /// Part 1, clause 37.2.6.1). Policy-authorized writes arrive later. The write itself is a pure state
    /// transition over the retained data area with no crypto, so a successful write is a header-only response
    /// (as <c>NV_UndefineSpace</c> is).
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_NV_Write()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnNvWrite(TpmSimulatorState state, TpmNvWriteRequested request)
    {
        //The Index must exist (Part 3, clause 31.7).
        if(!state.NvIndexes.TryGetValue(request.NvIndex, out NvIndexState? index))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Write, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        //An owner-authorized write is administrative: compared against the owner hierarchy's own authValue, which
        //is never dictionary-attack protected (clause 17.8.1), so a mismatch is a plain bad-authorization. On a
        //match the write proceeds directly — none of IsNvIndexLockedOut/IsPinAuthUnavailable/ApplyPinAuthOutcome
        //apply, since this arm authorizes the OWNER, not the Index's own authValue/PIN.
        if(request.AuthHandle.Value == (uint)TpmRh.TPM_RH_OWNER)
        {
            //With TPMA_NV_OWNERWRITE clear owner authorization cannot write this Index (Part 2, clause 13.4) —
            //checked BEFORE the owner-auth compare below (the same non-leaking order the index-auth arm uses for
            //TPMA_NV_AUTHWRITE), so an owner write against an Index that does not permit it rejects identically
            //regardless of the supplied owner authValue.
            if(!index.IsOwnerWriteAllowed)
            {
                return Reject(state, TpmCcConstants.TPM_CC_NV_Write, TpmRcConstants.TPM_RC_NV_AUTHORIZATION, request);
            }

            if(!CryptographicOperations.FixedTimeEquals(StripTrailingZeros(request.AuthSupplied.AsReadOnlySpan()), StripTrailingZeros(state.OwnerAuth.AsReadOnlySpan())))
            {
                return Reject(state, TpmCcConstants.TPM_CC_NV_Write, TpmRcConstants.TPM_RC_BAD_AUTH, request);
            }

            return WriteIndexData(state, index, request);
        }

        //Otherwise only Index authorization (authHandle == nvIndex) is modelled; policy-authorized writes against
        //the same Index arrive later, mirroring TPM2_NV_Read().
        if(request.AuthHandle.Value != request.NvIndex.Value)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Write, TpmRcConstants.TPM_RC_AUTH_TYPE, request);
        }

        //Already-locked-out DA-protected Index: refuse before even comparing (clause 17.8.3), no further increment.
        if(IsNvIndexLockedOut(state, index))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Write, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        //With TPMA_NV_AUTHWRITE clear the Index's own authValue is not an available authorization mechanism for
        //a write at all (Part 1, clause 35.2.6.1): Part 3, clause 5.6's check 7.2.2 (an NV Index authorized by
        //an HMAC session or a password needs TPMA_NV_AUTHWRITE SET for a command that modifies it,
        //TPM_RC_AUTH_UNAVAILABLE) is ordered ahead of its check 9/10 credential comparison, so an
        //AUTHWRITE-clear Index (every PIN Index, per TPM2_NV_DefineSpace()'s mandate) rejects a correct and an
        //incorrect authValue identically and no comparison outcome ever leaks which one it was.
        if(!index.IsAuthWriteAllowed)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Write, TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, request);
        }

        //Constant-time comparison of the supplied authorization against the Index authValue. A mismatch is an
        //auth-failure for a DA-protected Index (clause 17.8.3) and a plain bad-authorization for a non-DA Index
        //(clause 17.8.1), the same outcomes TPM2_NV_Read() turns on.
        if(!CryptographicOperations.FixedTimeEquals(StripTrailingZeros(request.AuthSupplied.AsReadOnlySpan()), StripTrailingZeros(index.AuthValue.AsReadOnlySpan())))
        {
            //RejectNvAuthFailure has no disposing overload, so the request's own carrier is released here — the
            //rejection framing below it reads only handles and dictionary state, never the carrier.
            request.Dispose();

            return RejectNvAuthFailure(state, index, TpmCcConstants.TPM_CC_NV_Write);
        }

        return WriteIndexData(state, index, request);

        //Range-checks the write against the Index's declared data area (Part 3, clause 31.7: offset + size must
        //not exceed the size established at TPM2_NV_DefineSpace()), then stores it and sets TPMA_NV_WRITTEN.
        //Shared by both the owner-authorized and the index-authValue write arms above, so the type gate below
        //runs once, after either arm has already resolved authorization. It is also the parsed data carrier's
        //terminal owner: the merge into the Index's own area is the carrier's only use.
        //TPMA_NV_WRITEALL's own rule is outside this model: "If the TPMA_NV_WRITEALL attribute of the NV Index
        //is SET, then the TPM shall return TPM_RC_NV_RANGE if the size of the data parameter of the command is
        //not the same as the data field of the NV Index" (clause 31.7.1) — a partial write of an Index carrying
        //that attribute is stored here rather than refused.
        static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> WriteIndexData(
            TpmSimulatorState state, NvIndexState index, TpmNvWriteRequested request)
        {
            //TPM2_NV_Write() updates an Ordinary or PIN Index only; a Counter, Bit Field, or Extend Index is
            //modified through its own dedicated command instead (TPM2_NV_Increment()/SetBits()/Extend()) — TPM
            //2.0 Library Part 3, clause 31.7.1: the four update commands partition NV Index types, and each
            //rejects every type but its own with TPM_RC_ATTRIBUTES. TPM_NT_BITS/TPM_NT_EXTEND are listed for
            //spec fidelity even though TPM2_NV_DefineSpace() already refuses those types outright.
            if(index.IndexType is TpmNt.TPM_NT_COUNTER or TpmNt.TPM_NT_BITS or TpmNt.TPM_NT_EXTEND)
            {
                return Reject(state, TpmCcConstants.TPM_CC_NV_Write, TpmRcConstants.TPM_RC_ATTRIBUTES, request);
            }

            if((long)request.Offset + request.Data.Length > index.DataSize)
            {
                return Reject(state, TpmCcConstants.TPM_CC_NV_Write, TpmRcConstants.TPM_RC_NV_RANGE, request);
            }

            NvIndexState updated = index.WriteData(request.Offset, request.Data.Span);
            request.Dispose();

            return Transition(
                state with
                {
                    NvIndexes = state.NvIndexes.SetItem(index.NvIndex, updated),
                    ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
                },
                "NvWrite");
        }
    }

    /// <summary>
    /// Removes a defined NV Index and frees its handle for <c>TPM2_NV_UndefineSpace()</c> (Part 3, clause 31.4).
    /// </summary>
    /// <remarks>
    /// A pure state transition: drop the Index from the table. An undefined handle is <c>TPM_RC_HANDLE</c>.
    /// Owner authorization is modelled; the policy-delete variant (<c>UndefineSpaceSpecial</c>, clause 31.5) is
    /// not. Part 3, clause 5.4 permits its handle checks in any order among themselves while requiring the
    /// handle area as a whole ahead of the authorization checks; this handler resolves the authorizing
    /// hierarchy's own handle-area outcomes first — admit, then enable — before probing the Index handle's
    /// presence, the same convention <c>OnEvictControl</c> holds: the authorizing hierarchy's availability is a
    /// handle-area outcome on <c>@authHandle</c>, resolved before the next handle's presence.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_NV_UndefineSpace()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnNvUndefineSpace(TpmSimulatorState state, TpmNvUndefineSpaceRequested request)
    {
        //Only the owner hierarchy is modelled as the provisioning authority this slice - the same
        //TPMI_RH_PROVISION-typed @authHandle TPM2_NV_DefineSpace() carries (Part 3, clause 31.3); the
        //platform hierarchy carries its own authValue and arrives later. Clause 31.4 states no distinct
        //response code for a caller-supplied @authHandle outside {TPM_RH_OWNER, TPM_RH_PLATFORM}, so this
        //mirrors OnNvDefineSpace's identical handle-type-check gate exactly: TPM_RC_HANDLE.
        if(request.AuthHandle.Value != (uint)TpmRh.TPM_RH_OWNER)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        //While shEnable is CLEAR ownerAuth cannot authorize anything (Part 1, clause 11.2), so the deletion is
        //refused before the authValue is consulted, exactly as the matching definition arm refuses one.
        if(!state.IsHierarchyEnabled(request.AuthHandle.Value))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmRcConstants.TPM_RC_HIERARCHY, request);
        }

        //The wire type admits the ordinary and external NV Index ranges (TPMI_RH_NV_DEFINED_INDEX, Part 2,
        //clause 9.26, Table 73); the durable NV state is keyed by the wider TPMI_RH_NV_INDEX every other NV
        //command addresses a defined Index through, so the handle widens for the lookup.
        TpmiRhNvIndex indexHandle = TpmiRhNvIndex.FromValue(request.NvIndex.Value);

        //The Index handle's presence is probed after the authorizing hierarchy's own handle-area outcomes above
        //(Part 3, clause 5.4 permits any order within the handle area; the house convention resolves
        //@authHandle's availability first).
        if(!state.NvIndexes.TryGetValue(indexHandle, out NvIndexState? index))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        //Owner authorization is not dictionary-attack protected (Part 1, clause 17.8.1: "the authValue
        //associated with a permanent entity, other than TPM_RH_LOCKOUT, does not receive DA protection"): a
        //wrong owner authValue is a plain bad-authorization, never an auth-failure that feeds the lockout
        //counter, and the comparison is constant-time so a mismatch leaks no timing about the secret. This
        //closes the previously discarded authorization-area residual: without this compare, any caller able
        //to address the wire command at all could undefine-then-redefine any Index regardless of the supplied
        //owner authValue - a direct throttle-reset primitive against a PIN Fail Index, since the phantom
        //high-water mark below is COUNTER-only (Part 1, clause 37.2.6.6).
        if(!CryptographicOperations.FixedTimeEquals(StripTrailingZeros(request.AuthSupplied.AsReadOnlySpan()), StripTrailingZeros(state.OwnerAuth.AsReadOnlySpan())))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmRcConstants.TPM_RC_BAD_AUTH, request);
        }

        //Deleting a written Counter Index retires its value into the phantom high-water mark (TPM 2.0 Library
        //Part 1, clause 37.2.6.3 NOTE 2/NOTE 6): a later redefinition of the same handle can never seed its
        //first TPM2_NV_Increment() at or below a value this Name has already reported, closing the
        //delete-then-redefine rollback the increment's own initialization rule (clause 31.2) depends on.
        ulong highWaterMark = RetireNvCounterHighWaterMark(index, state.NvCounterHighWaterMark);

        //Undefining is the Index's ownership-end boundary: its owned authValue carrier is released before
        //the dictionary drops the last live reference.
        index.Dispose();

        //The compare above was this credential's only use, so this transition is its terminal owner;
        //every arm that refuses before this point releases it through the request's own Dispose.
        request.AuthSupplied.Dispose();

        return Transition(
            state with
            {
                NvIndexes = state.NvIndexes.Remove(indexHandle),
                NvCounterHighWaterMark = highWaterMark,
                ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
            },
            "NvUndefineSpace");
    }

    /// <summary>
    /// Increments a Counter Index's 8-octet value by one for <c>TPM2_NV_Increment()</c>, authorized by either
    /// the owner hierarchy or the Index's own authValue (Part 3, clause 31.8).
    /// </summary>
    /// <remarks>
    /// This slice models the same two authorization arms as <c>TPM2_NV_Write()</c> (owner-administrative and
    /// Index-authValue); policy- and platform-authorized increments arrive later. <c>TPMA_NV_ORDERLY</c> is
    /// accepted and retained raw at <c>TPM2_NV_DefineSpace()</c> but has no observable effect here: every
    /// increment writes synchronously to the retained NV data (the <c>TPMA_NV_ORDERLY</c>-CLEAR path, Part 1,
    /// clause 37.2.6.3), so no RAM-shadow counter or MAX_ORDERLY_COUNT batching is modelled — a deliberate
    /// scope decision (SPEC OQ-3), not a gap: the counter's externally observed value is unaffected either way,
    /// since ORDERLY is a write-endurance optimization, not a correctness-relevant semantic.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_NV_Increment()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnNvIncrement(TpmSimulatorState state, TpmNvIncrementRequested request)
    {
        //The Index must exist (Part 3, clause 31.8).
        if(!state.NvIndexes.TryGetValue(request.NvIndex, out NvIndexState? index))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Increment, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        //An owner-authorized increment is administrative: compared against the owner hierarchy's own authValue,
        //which is never dictionary-attack protected (clause 17.8.1), so a mismatch is a plain bad-authorization.
        //None of the Index-entity DA gates (IsNvIndexLockedOut/RejectNvAuthFailure) apply on this arm — the
        //clause 5.6 lockout gate binds the entity whose authValue is compared, and here that is the OWNER, not
        //the Index; the same posture TPM2_NV_Write()'s owner arm takes.
        if(request.AuthHandle.Value == (uint)TpmRh.TPM_RH_OWNER)
        {
            //With TPMA_NV_OWNERWRITE clear owner authorization cannot increment this Index (Part 2, clause
            //13.4) - checked BEFORE the owner-auth compare, mirroring OnNvWrite's owner arm.
            if(!index.IsOwnerWriteAllowed)
            {
                return Reject(state, TpmCcConstants.TPM_CC_NV_Increment, TpmRcConstants.TPM_RC_NV_AUTHORIZATION, request);
            }

            if(!CryptographicOperations.FixedTimeEquals(StripTrailingZeros(request.AuthSupplied.AsReadOnlySpan()), StripTrailingZeros(state.OwnerAuth.AsReadOnlySpan())))
            {
                return Reject(state, TpmCcConstants.TPM_CC_NV_Increment, TpmRcConstants.TPM_RC_BAD_AUTH, request);
            }
        }
        else
        {
            //Otherwise only Index authorization (authHandle == nvIndex) is modelled; policy/platform-authorized
            //increments against the same Index arrive later, mirroring TPM2_NV_Write() (Part 3, clause 31.1: an
            //Index-authorization authHandle that does not equal the Index itself is TPM_RC_NV_AUTHORIZATION).
            if(request.AuthHandle.Value != request.NvIndex.Value)
            {
                return Reject(state, TpmCcConstants.TPM_CC_NV_Increment, TpmRcConstants.TPM_RC_NV_AUTHORIZATION, request);
            }

            //Already-locked-out DA-protected Index: refuse before even comparing (clause 17.8.3) - the clause
            //5.6 lockout gate binds this arm because the entity whose authValue is compared here IS the
            //DA-protected Index, mirroring OnNvWrite's index arm.
            if(IsNvIndexLockedOut(state, index))
            {
                return Reject(state, TpmCcConstants.TPM_CC_NV_Increment, TpmRcConstants.TPM_RC_LOCKOUT, request);
            }

            //With TPMA_NV_AUTHWRITE clear the Index's own authValue is not an available authorization mechanism
            //for an increment at all (Part 1, clause 35.2.6.1) - Part 3, clause 5.6's check 7.2.2 orders this
            //availability check ahead of its check 9/10 value compare (TPM_RC_AUTH_UNAVAILABLE), mirroring
            //OnNvWrite's index arm.
            if(!index.IsAuthWriteAllowed)
            {
                return Reject(state, TpmCcConstants.TPM_CC_NV_Increment, TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, request);
            }

            //Constant-time comparison of the supplied authorization against the Index authValue. A mismatch is
            //an auth-failure for a DA-protected Index (clause 17.8.3) and a plain bad-authorization for a
            //non-DA Index (clause 17.8.1) - TPMA_NV_NO_DA applies uniformly, with no counter-type carve-out.
            if(!CryptographicOperations.FixedTimeEquals(StripTrailingZeros(request.AuthSupplied.AsReadOnlySpan()), StripTrailingZeros(index.AuthValue.AsReadOnlySpan())))
            {
                request.Dispose();

                return RejectNvAuthFailure(state, index, TpmCcConstants.TPM_CC_NV_Increment);
            }
        }

        //TPM2_NV_Increment() modifies a Counter Index only; every other type is refused (Part 3, clause
        //31.8.1: "If nvIndexType is not TPM_NT_COUNTER... the TPM shall return TPM_RC_ATTRIBUTES").
        if(index.IndexType != TpmNt.TPM_NT_COUNTER)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Increment, TpmRcConstants.TPM_RC_ATTRIBUTES, request);
        }

        //A write-locked Index cannot be incremented (Part 3, clause 31.8.1). No command in this simulator can
        //SET TPMA_NV_WRITELOCKED today (TPM2_NV_WriteLock() is unmodelled), so this branch is presently
        //unreachable in practice, but the gate lands fail-closed rather than being silently omitted.
        if((index.Attributes & TpmaNv.TPMA_NV_WRITELOCKED) != 0)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Increment, TpmRcConstants.TPM_RC_NV_LOCKED, request);
        }

        //Unwritten counter: seed from the highest value any counter Index with this Name has ever held,
        //including one already deleted (the phantom-counter mechanism on NvCounterHighWaterMark, TPM 2.0
        //Library Part 1, clause 37.2.6.3 NOTE 2/NOTE 6), then increment. A written counter simply increments
        //its stored value. TPM2_NV_Increment() never answers TPM_RC_NV_UNINITIALIZED for an unwritten counter
        //- performing the first write IS its contract (Part 3, clause 31.8.1).
        ulong seed = index.IsWritten ? index.CounterValue : state.NvCounterHighWaterMark;
        NvIndexState updated = index.WithCounterValue(seed + 1);

        //The compare above was this credential's only use, so this transition is its terminal owner;
        //every arm that refuses before this point releases it through the request's own Dispose.
        request.AuthSupplied.Dispose();

        return Transition(
            state with
            {
                NvIndexes = state.NvIndexes.SetItem(index.NvIndex, updated),
                ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
            },
            "NvIncrement");
    }

    /// <summary>
    /// Reads an NV Index's public area and computes its Name for <c>TPM2_NV_ReadPublic()</c> (TPM 2.0 Library
    /// Part 3, clause 31.6).
    /// </summary>
    /// <remarks>
    /// <c>Auth Index: None</c> ("The public area of an Index is not privacy-sensitive, and no authorization is
    /// required to read this data", clause 31.6.1): the only gate is that the Index must exist
    /// (<c>TPM_RC_HANDLE</c>, the generic clause 5.4 handle-validation check). Deliberately NOT gated on
    /// <c>TPMA_NV_WRITELOCKED</c>/<c>TPMA_NV_READLOCKED</c>/<c>TPMA_NV_WRITTEN</c> — those lock gates condition on
    /// "the command requires write/read access to the index DATA" (clause 5.4), and this command reads only the
    /// public area and computes the Name, never the data area, so it succeeds even for a never-written Index.
    /// The handle's own out-of-range case (<c>TPM_RC_VALUE</c>) is caught at parse time, mirroring
    /// <c>TPMI_RH_NV_INDEX</c>'s own interface-type unmarshal check (Part 2, Table 72).
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_NV_ReadPublic()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the Name-computation action.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnNvReadPublic(TpmSimulatorState state, TpmNvReadPublicRequested request)
    {
        if(!state.NvIndexes.TryGetValue(request.NvIndex, out NvIndexState? index))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_ReadPublic, TpmRcConstants.TPM_RC_HANDLE);
        }

        //The Name needs the asynchronous digest seam (TPM digests belong there, not the sync seam a pure
        //transition could reach on its own), so the transition declares a TpmComputeNvPublicNameAction carrying
        //the Index's own retained public-area fields and leaves no response yet; OnNvPublicNameComputed frames
        //the response once the Name comes back.
        return Transition(
            state with
            {
                NextAction = new TpmComputeNvPublicNameAction(index.NvIndex, index.NameAlg, index.Attributes, index.AuthPolicy, index.DataSize),
                ResponseIntent = null
            },
            "NvReadPublic:NameComputeRequested");
    }

    /// <summary>
    /// Frames the <c>TPM2_NV_ReadPublic()</c> response once the effect has built the public area and computed
    /// the Name (TPM 2.0 Library Part 3, clause 31.6).
    /// </summary>
    /// <param name="state">The state to transition from.</param>
    /// <param name="computed">The effect's result carrying the built public area and computed Name.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnNvPublicNameComputed(TpmSimulatorState state, TpmNvPublicNameComputed computed) =>
        Transition(
            state with
            {
                NextAction = NullAction.Instance,
                ResponseIntent = new TpmNvReadPublicResponse(TpmRcConstants.TPM_RC_SUCCESS, computed.NvPublic, computed.Name)
            },
            "NvReadPublic:Completed");

    /// <summary>
    /// Authorizes <c>TPM2_NV_Read()</c> over an HMAC session on either arm (TPM 2.0 Library Part 3, clause
    /// 31.13; Part 1, clause 35.2.6.6's PIN-over-HMAC semantic).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Resolves the Index (<c>TPM_RC_HANDLE</c> if unknown) and the authorizing HMAC session (the generic
    /// session-not-loaded warning if unknown, Part 2, clause 6.6.2) exactly as <c>OnPolicySecretOverSession</c>
    /// does, then validates the session area (clause 5.5): decrypt/encrypt fail closed with
    /// <c>TPM_RC_ATTRIBUTES</c> — this simulator does not yet implement parameter encryption for the NV family's
    /// HMAC arms (the reference command-attribute table marks NV_Read's response <c>data</c> ENCRYPT_2-eligible,
    /// tracked, not implemented). The <c>audit</c> attribute fails closed on the same five arms and for the same
    /// reason: no audit digest is modelled, so a session claiming the command is audited is refused rather than
    /// admitted and left unaudited.
    /// </para>
    /// <para>
    /// The owner arm's <c>TPMA_NV_OWNERREAD</c> gate runs BEFORE any HMAC work (the same non-leaking order the
    /// password arm uses); the Index arm's dictionary-attack lockout gate (<c>IsNvIndexLockedOut</c>), PIN
    /// at-limit gate (<c>IsPinAuthUnavailable</c>), and <c>TPMA_NV_AUTHREAD</c> availability gate (Part 3,
    /// clause 5.6's check 7.2.2, <c>TPM_RC_AUTH_UNAVAILABLE</c>) likewise run strictly before the
    /// Name-computation hop that precedes the HMAC compare — "the authorization will fail" (clause 35.2.6.6's
    /// first sentence) is a
    /// condition entirely distinct from, and checked ahead of, "the authorization succeeds/fails" (its second
    /// sentence), for either session kind (Part 1, clause 17.8.1's own uniformity: password, ordinary HMAC
    /// keying, and bound-session sessionKey derivation are three interchangeable ways an authValue is "used for
    /// authorization"). Both arms then declare a <c>TpmComputeNvIndexNameAction</c> to compute the real Index
    /// Name cpHash's Name1/Name2 terms need (<c>OnNvIndexNameComputed</c> builds them and declares the HMAC
    /// verification); <c>ContinueNvReadOverSession</c> resumes once it matches.
    /// </para>
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_NV_Read()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the Name-computation action, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnNvReadOverSession(TpmSimulatorState state, TpmNvReadOverSessionRequested request)
    {
        if(!state.NvIndexes.TryGetValue(request.NvIndex, out NvIndexState? index))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Read, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        if(!state.HmacSessions.TryGetValue(TpmiShHmac.FromValue(request.AuthorizingSessionHandle.Value), out HmacSessionState? session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Read, SessionReferenceMissRc(sessionIndex: 0), request);
        }

        TpmRcConstants? sessionAreaError = ValidateSessionArea(
            request.SessionAttributes, firstAuthorizesEntity: true, session.Symmetric,
            hasSecondSession: false, secondAttributes: default, secondSymmetric: TpmtSymDef.Null,
            firstCommandParameterIsEncryptable: false, firstResponseParameterIsEncryptable: false,
            auditIsSupported: false,
            firstSessionHandle: request.AuthorizingSessionHandle, firstNonceLength: request.NonceCaller.Size);
        if(sessionAreaError is TpmRcConstants sessionAreaRc)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Read, sessionAreaRc, request);
        }

        //The bind-side lockout gate applies to BOTH arms, since it speaks to the entity the session was bound to
        //rather than the one it authorizes now (Part 3, clause 11.1.1: "regardless of the DA status of the entity
        //being authorized"), which is also why it sits ahead of the owner-arm branch.
        if(IsBoundSessionLockedOut(state, session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Read, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        if(request.AuthHandle.Value == (uint)TpmRh.TPM_RH_OWNER)
        {
            if(!index.IsOwnerReadAllowed)
            {
                return Reject(state, TpmCcConstants.TPM_CC_NV_Read, TpmRcConstants.TPM_RC_NV_AUTHORIZATION, request);
            }

            return Transition(
                state with
                {
                    NextAction = new TpmComputeNvIndexNameAction(index.NvIndex, index.NameAlg, index.Attributes, index.AuthPolicy, index.DataSize, request),
                    ResponseIntent = null
                },
                "NvRead:OverSession:OwnerNameRequested");
        }

        if(request.AuthHandle.Value != request.NvIndex.Value)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Read, TpmRcConstants.TPM_RC_AUTH_TYPE, request);
        }

        if(IsNvIndexLockedOut(state, index))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Read, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        if(IsPinAuthUnavailable(index))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Read, TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, request);
        }

        //With TPMA_NV_AUTHREAD clear, the Index's own authValue is not an available authorization mechanism
        //for this read-role command over any session kind (Part 1, clause 35.2.5; Part 3, clause 5.6's check
        //7.2.2 is ordered ahead of its check 9 command-HMAC verification), so this arm refuses here — before
        //the Name hop, before any HMAC work, and before any authorization outcome could charge the
        //dictionary-attack counter — the identical early gate, at the identical position, that
        //OnNvCertifyOverSession applies. ContinueNvReadOverSession's own check is retained only as an
        //unreachable fail-closed backstop.
        if(!index.IsAuthReadAllowed)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Read, TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, request);
        }

        return Transition(
            state with
            {
                NextAction = new TpmComputeNvIndexNameAction(index.NvIndex, index.NameAlg, index.Attributes, index.AuthPolicy, index.DataSize, request),
                ResponseIntent = null
            },
            "NvRead:OverSession:IndexNameRequested");
    }

    /// <summary>
    /// Resumes <c>TPM2_NV_Read()</c> once its authorizing HMAC session's command HMAC has verified
    /// (<see cref="TpmVerifyCommandHmacAction"/>'s continuation).
    /// </summary>
    /// <remarks>
    /// The Index arm's pinCount is updated for a SUCCESSFUL match here (reset for PIN Fail, increment for PIN
    /// Pass, Part 1, clause 35.2.6.6) — the mismatch update runs earlier, in <c>RejectNvSessionAuthFailure</c>,
    /// since a mismatch never reaches this continuation at all (<c>OnCommandHmacVerified</c> short-circuits
    /// before <c>NextRequest</c> dispatch). The Index arm's <c>TPMA_NV_AUTHREAD</c> check here is a fail-closed
    /// backstop, never the answer a caller actually sees: <c>OnNvReadOverSession</c>'s early availability gate
    /// (Part 1, clause 35.2.5; Part 3, clause 5.6's check 7.2.2) already refuses a read-forbidden Index with
    /// <c>TPM_RC_AUTH_UNAVAILABLE</c> before the Name hop and any HMAC work, exactly as
    /// <c>ContinueNvCertifyOverSession</c>'s backstop is guarded by <c>OnNvCertifyOverSession</c>'s. The owner
    /// arm has no further gate: its <c>TPMA_NV_OWNERREAD</c> check already ran in <c>OnNvReadOverSession</c>.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_NV_Read()</c> request, its command HMAC now verified.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the response-framing action.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> ContinueNvReadOverSession(TpmSimulatorState state, TpmNvReadOverSessionRequested request)
    {
        NvIndexState index = state.NvIndexes[request.NvIndex];
        bool isIndexArm = request.AuthHandle.Value == request.NvIndex.Value;

        if(isIndexArm && index.IsPinIndex)
        {
            index = ApplyPinAuthOutcome(index, authMatched: true);
            state = state with { NvIndexes = state.NvIndexes.SetItem(index.NvIndex, index) };
        }

        if(isIndexArm && !index.IsAuthReadAllowed)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Read, TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, request);
        }

        if(!TryValidateNvReadWindow(index, request.Offset, request.Size, out TpmRcConstants rejectCode))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Read, rejectCode, request);
        }

        //This continuation is the terminal owner of the parse-rented parameter area and of the Index Name the
        //Name-computation step transferred here: the command HMAC that read them has verified, and nothing
        //downstream reads either again.
        request.Hmac.Dispose();
        request.RawParameterArea.Dispose();
        request.ResolvedIndexName.Dispose();

        HmacSessionState session = state.HmacSessions[TpmiShHmac.FromValue(request.AuthorizingSessionHandle.Value)];

        //The response parameter rides as a BORROW of the Index's own data carrier plus the requested window;
        //the framing effect, which holds the pool this pure transition does not, is what lays the
        //TPM2B_MAX_NV_BUFFER into a rental of its own.
        return Transition(
            state with
            {
                NextAction = new TpmFrameNvSessionResponseAction(
                    TpmCcConstants.TPM_CC_NV_Read, TpmiShAuthSession.FromValue(session.Handle.Value), session.SessionAlg, session.SessionKey, request.ResolvedAuthValue ?? Tpm2bAuth.Empty,
                    request.NonceCaller, request.SessionAttributes, new TpmNvDataWindow(index.Data, request.Offset, request.Size)),
                ResponseIntent = null
            },
            "NvRead:OverSession:ResponseRequested");
    }

    /// <summary>
    /// Authorizes <c>TPM2_NV_Write()</c>'s owner arm over an HMAC session (TPM 2.0 Library Part 3, clause 31.7).
    /// </summary>
    /// <remarks>
    /// Only the owner arm is modelled over a session. An Index-authValue write arm does exist — <c>OnNvWrite</c>'s
    /// own, gated on <c>TPMA_NV_AUTHWRITE</c> and comparing the Index's authValue — but only over a password
    /// session; its HMAC-session variant is outside the PIN channel this arm serves, because a PIN Index forbids
    /// <c>TPMA_NV_AUTHWRITE</c> outright (clause 35.2.6.1, enforced at <c>TPM2_NV_DefineSpace()</c>) and so can
    /// never author a write with its own authValue on either path. The consequence, stated plainly: an ordinary
    /// Index carrying <c>TPMA_NV_AUTHWRITE</c> is writable with its own authValue over <c>TPM_RS_PW</c> and
    /// answers <c>TPM_RC_AUTH_TYPE</c> for the same authorization over an HMAC session. A non-owner
    /// <c>authHandle</c> is therefore <c>TPM_RC_AUTH_TYPE</c> here. Owner is DA-exempt, so no lockout gate applies; the
    /// <c>TPMA_NV_OWNERWRITE</c> gate runs BEFORE any HMAC work, the same non-leaking order the password arm's
    /// owner-write gate uses. Declares a <c>TpmComputeNvIndexNameAction</c> exactly as the Read owner arm does.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_NV_Write()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the Name-computation action, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnNvWriteOverSession(TpmSimulatorState state, TpmNvWriteOverSessionRequested request)
    {
        if(!state.NvIndexes.TryGetValue(request.NvIndex, out NvIndexState? index))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Write, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        if(!state.HmacSessions.TryGetValue(TpmiShHmac.FromValue(request.AuthorizingSessionHandle.Value), out HmacSessionState? session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Write, SessionReferenceMissRc(sessionIndex: 0), request);
        }

        TpmRcConstants? sessionAreaError = ValidateSessionArea(
            request.SessionAttributes, firstAuthorizesEntity: true, session.Symmetric,
            hasSecondSession: false, secondAttributes: default, secondSymmetric: TpmtSymDef.Null,
            firstCommandParameterIsEncryptable: false, firstResponseParameterIsEncryptable: false,
            auditIsSupported: false,
            firstSessionHandle: request.AuthorizingSessionHandle, firstNonceLength: request.NonceCaller.Size);
        if(sessionAreaError is TpmRcConstants sessionAreaRc)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Write, sessionAreaRc, request);
        }

        //Owner is dictionary-attack exempt, but the SESSION may be bound to an entity that is not: use of such a
        //session is subject to DA whatever it authorizes (Part 3, clause 11.1.1).
        if(IsBoundSessionLockedOut(state, session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Write, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        if(request.AuthHandle.Value != (uint)TpmRh.TPM_RH_OWNER)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Write, TpmRcConstants.TPM_RC_AUTH_TYPE, request);
        }

        if(!index.IsOwnerWriteAllowed)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Write, TpmRcConstants.TPM_RC_NV_AUTHORIZATION, request);
        }

        return Transition(
            state with
            {
                NextAction = new TpmComputeNvIndexNameAction(index.NvIndex, index.NameAlg, index.Attributes, index.AuthPolicy, index.DataSize, request),
                ResponseIntent = null
            },
            "NvWrite:OverSession:OwnerNameRequested");
    }

    /// <summary>
    /// Resumes <c>TPM2_NV_Write()</c>'s owner arm once its command HMAC has verified, writing the data and
    /// declaring the session-response framing action (TPM 2.0 Library Part 3, clause 31.7).
    /// </summary>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_NV_Write()</c> request, its command HMAC now verified.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the response-framing action, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> ContinueNvWriteOverSession(TpmSimulatorState state, TpmNvWriteOverSessionRequested request)
    {
        NvIndexState index = state.NvIndexes[request.NvIndex];

        //TPM2_NV_Write() updates an Ordinary or PIN Index only (clause 31.7.1), mirroring the password arm exactly.
        if(index.IndexType is TpmNt.TPM_NT_COUNTER or TpmNt.TPM_NT_BITS or TpmNt.TPM_NT_EXTEND)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Write, TpmRcConstants.TPM_RC_ATTRIBUTES, request);
        }

        if((long)request.Offset + request.Data.Length > index.DataSize)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Write, TpmRcConstants.TPM_RC_NV_RANGE, request);
        }

        NvIndexState updated = index.WriteData(request.Offset, request.Data.Span);

        //This continuation is the terminal owner of the parse-rented parameter area, of the parsed data carrier,
        //and of the Index Name the Name-computation step transferred here: the command HMAC that read them has
        //verified, the octets have been merged into the Index's own area, and nothing downstream reads any of
        //them again.
        request.Hmac.Dispose();
        request.RawParameterArea.Dispose();
        request.Data.Dispose();
        request.ResolvedIndexName.Dispose();

        HmacSessionState session = state.HmacSessions[TpmiShHmac.FromValue(request.AuthorizingSessionHandle.Value)];

        return Transition(
            state with
            {
                NvIndexes = state.NvIndexes.SetItem(updated.NvIndex, updated),
                NextAction = new TpmFrameNvSessionResponseAction(
                    TpmCcConstants.TPM_CC_NV_Write, TpmiShAuthSession.FromValue(session.Handle.Value), session.SessionAlg, session.SessionKey, request.ResolvedAuthValue ?? Tpm2bAuth.Empty,
                    request.NonceCaller, request.SessionAttributes, ReadWindow: null),
                ResponseIntent = null
            },
            "NvWrite:OverSession:ResponseRequested");
    }

    /// <summary>
    /// Authorizes <c>TPM2_NV_DefineSpace()</c>'s owner arm over an HMAC session (TPM 2.0 Library Part 3, clause
    /// 31.3).
    /// </summary>
    /// <remarks>
    /// Single-handle: there is no pre-existing Index yet, so cpHash needs no Name2 term and no Name-computation
    /// hop precedes the command-HMAC verification — this goes straight from session-area validation to
    /// declaring <c>TpmVerifyCommandHmacAction</c> with cpHash's Name1 = the owner's raw 4-octet handle (Part 1,
    /// Table 6: a permanent handle's Name IS its handle value). Owner is DA-exempt, so no lockout gate applies.
    /// The <c>auth</c> first command parameter is decrypt-eligible (Part 3, clause 31.3, Table 228 orders
    /// <c>auth</c> ahead of <c>publicInfo</c>; Part 3, clause 5.7's first-sized-parameter rule) — the ONLY NV
    /// arm whose <c>firstCommandParameterIsEncryptable</c> gate is open, since only <c>NV_DefineSpace</c> carries
    /// a sensitive value (the new Index's authValue) as a command parameter. When the authorizing session sets
    /// the <c>decrypt</c> attribute, that parameter is decrypted after the command HMAC verifies (Part 1, clause
    /// 21) in <c>ContinueNvDefineSpaceOverSession</c>. The <c>encrypt</c> and <c>audit</c> attributes stay
    /// fail-closed (no response parameter is encryptable, no audit trail is modelled).
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_NV_DefineSpace()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the HMAC-verification action, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnNvDefineSpaceOverSession(TpmSimulatorState state, TpmNvDefineSpaceOverSessionRequested request)
    {
        if(!state.HmacSessions.TryGetValue(TpmiShHmac.FromValue(request.AuthorizingSessionHandle.Value), out HmacSessionState? session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, SessionReferenceMissRc(sessionIndex: 0), request);
        }

        TpmRcConstants? sessionAreaError = ValidateSessionArea(
            request.SessionAttributes, firstAuthorizesEntity: true, session.Symmetric,
            hasSecondSession: false, secondAttributes: default, secondSymmetric: TpmtSymDef.Null,
            firstCommandParameterIsEncryptable: true, firstResponseParameterIsEncryptable: false,
            auditIsSupported: false,
            firstSessionHandle: request.AuthorizingSessionHandle, firstNonceLength: request.NonceCaller.Size);
        if(sessionAreaError is TpmRcConstants sessionAreaRc)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, sessionAreaRc, request);
        }

        //Owner is dictionary-attack exempt, but the SESSION may be bound to an entity that is not: use of such a
        //session is subject to DA whatever it authorizes (Part 3, clause 11.1.1).
        if(IsBoundSessionLockedOut(state, session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        if(request.AuthHandle.Value != (uint)TpmRh.TPM_RH_OWNER)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        //The same availability gate the password arm applies: while shEnable is CLEAR the owner hierarchy can
        //authorize nothing (Part 1, clause 11.2), whatever the session proves.
        if(!state.IsHierarchyEnabled(request.AuthHandle.Value))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_HIERARCHY, request);
        }

        //Trailing zeros are removed from the owner authValue where it keys the command/response HMAC (TPM 2.0
        //Library Part 1, clause 17.6.5's authValue term note) — the HMAC primitive takes the stripped view of
        //the borrowed carrier, matching OnNvIndexNameComputed's identical fold on the three Name-carrying NV
        //arms. The bind-omission recomputes the bound-entity value from the owner's LIVE authValue (Part 4,
        //IsSessionBindEntity), so a rotated ownerAuth ends the binding.
        bool bindOmits = MatchesHandleFormBoundEntity(session.BoundEntity, request.AuthHandle.Value, StripTrailingZeros(state.OwnerAuth.AsReadOnlySpan()));
        Tpm2bAuth authValueForHmac = bindOmits
            ? Tpm2bAuth.Empty
            : state.OwnerAuth;

        //The owner hierarchy is dictionary-attack exempt (Part 1, clause 17.8.1), so the charge here comes from
        //the session's bind side alone: clause 17.8.7's OR increments failedTries "if either the entity being
        //authorized is subject to DA protection or if the session is bound to an entity that has DA protection".
        var pending = new TpmPendingSessionVerification(
            SessionHandle: TpmiShAuthSession.FromValue(session.Handle.Value), SessionIndex: 0, SessionAlg: session.SessionAlg, SessionKey: session.SessionKey,
            AuthValue: authValueForHmac, IsDaProtected: session.IsBoundEntityDaProtected, NonceCaller: request.NonceCaller, NonceTpm: session.NonceTpm,
            FoldedNonceDecrypt: Tpm2bNonce.Empty, FoldedNonceEncrypt: Tpm2bNonce.Empty, SessionAttributes: request.SessionAttributes, SuppliedHmac: request.Hmac,
            IsLockoutEntity: session.IsBoundToLockout);

        return Transition(
            state with
            {
                NextAction = new TpmVerifyCommandHmacAction(
                    TpmCcConstants.TPM_CC_NV_DefineSpace, TpmCommandHandleNames.Of(TpmHandleName.FromHandle(request.AuthHandle.Value)), request.RawParameterArea, pending,
                    ImmutableArray<TpmPendingSessionVerification>.Empty, request with { ResolvedAuthValue = authValueForHmac }),
                ResponseIntent = null
            },
            "NvDefineSpace:OverSession:HmacVerifyRequested");
    }

    /// <summary>
    /// Resumes <c>TPM2_NV_DefineSpace()</c>'s owner arm once its command HMAC has verified, defining the Index
    /// and declaring the session-response framing action (TPM 2.0 Library Part 3, clause 31.3).
    /// </summary>
    /// <remarks>
    /// Runs the identical command-body checks <c>OnNvDefineSpace</c>'s password arm runs (supported nameAlg,
    /// handle range, already defined, authPolicy size consistent with nameAlg, TPM-maintained-attribute
    /// rejection, PLATFORMCREATE prohibition under owner authorization, supported index type, fixed 8-octet data
    /// size, CLEAR_STCLEAR legality, PIN Fail NO_DA mandate, PIN AUTHWRITE prohibition) — only the authorization
    /// mechanism differs. Each check's reasoning is carried once, at the password arm's corresponding site.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_NV_DefineSpace()</c> request, its command HMAC now verified.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the response-framing action, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> ContinueNvDefineSpaceOverSession(TpmSimulatorState state, TpmNvDefineSpaceOverSessionRequested request)
    {
        if(!IsSupportedNameAlg(request.NameAlg))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_HASH, request);
        }

        if((byte)(request.NvIndex.Value >> 24) != (byte)TpmHt.TPM_HT_NV_INDEX)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        //The durable NV state is keyed by TPMI_RH_NV_INDEX, the wider interface type every other NV command
        //addresses a defined Index through; past the MSO gate above the handle satisfies it.
        TpmiRhNvIndex indexHandle = TpmiRhNvIndex.FromValue(request.NvIndex.Value);

        if(state.NvIndexes.ContainsKey(indexHandle))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_NV_DEFINED, request);
        }

        if(!request.AuthPolicy.IsEmpty && request.AuthPolicy.Size != TpmPolicyDigest.Size(request.NameAlg.Value))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_SIZE, request);
        }

        if((request.Attributes & (TpmaNv.TPMA_NV_WRITTEN | TpmaNv.TPMA_NV_READLOCKED | TpmaNv.TPMA_NV_WRITELOCKED)) != 0)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_ATTRIBUTES, request);
        }

        if((request.Attributes & TpmaNv.TPMA_NV_PLATFORMCREATE) != 0)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_ATTRIBUTES, request);
        }

        TpmNt indexType = TpmaNvFields.GetTpmNt(request.Attributes);
        if(indexType is not (TpmNt.TPM_NT_ORDINARY or TpmNt.TPM_NT_COUNTER or TpmNt.TPM_NT_PIN_FAIL or TpmNt.TPM_NT_PIN_PASS))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_ATTRIBUTES, request);
        }

        bool requiresEightOctets = indexType is TpmNt.TPM_NT_COUNTER or TpmNt.TPM_NT_BITS or TpmNt.TPM_NT_PIN_FAIL or TpmNt.TPM_NT_PIN_PASS;
        if(requiresEightOctets && request.DataSize != EightOctetDataSize)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_SIZE, request);
        }

        if(indexType == TpmNt.TPM_NT_COUNTER && (request.Attributes & TpmaNv.TPMA_NV_CLEAR_STCLEAR) != 0)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_ATTRIBUTES, request);
        }

        if(indexType == TpmNt.TPM_NT_PIN_FAIL && (request.Attributes & TpmaNv.TPMA_NV_NO_DA) == 0)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_ATTRIBUTES, request);
        }

        if((indexType == TpmNt.TPM_NT_PIN_FAIL || indexType == TpmNt.TPM_NT_PIN_PASS) && (request.Attributes & TpmaNv.TPMA_NV_AUTHWRITE) != 0)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_ATTRIBUTES, request);
        }

        //A decrypt-attributed authorizing session encrypted the auth first parameter (Part 1, clause 19.1): its
        //plaintext value cannot become the Index authValue until it is decrypted, which must follow the
        //now-complete command-HMAC verification (Part 3, clause 5.6 precedes clause 5.8, exactly as
        //TPM2_Create()'s inSensitive decrypt does). The auth session and the decrypt session are ONE here, so the
        //keystream folds the authorized entity's authValue after the session key — and it folds the owner
        //hierarchy's LIVE value, not the bind-omission-resolved term the command HMAC key used, because "the
        //binding of the session is ignored" for parameter encryption (clause 19.1) while the HMAC key omits the
        //term under equation 22 (clause 17.6.10). Two keys, one session.
        if((request.SessionAttributes & TpmaSession.DECRYPT) != 0)
        {
            HmacSessionState decryptSession = state.HmacSessions[TpmiShHmac.FromValue(request.AuthorizingSessionHandle.Value)];

            return Transition(
                state with
                {
                    NextAction = new TpmDecryptNvDefineAuthAction(
                        request, request.RawParameterArea, decryptSession.SessionAlg, decryptSession.Symmetric,
                        decryptSession.SessionKey, state.OwnerAuth,
                        request.NonceCaller, decryptSession.NonceTpm),
                    ResponseIntent = null
                },
                "NvDefineSpace:OverSession:AuthDecryptRequested");
        }

        //No decrypt session: the auth parameter crossed in the clear, so its parsed carrier becomes the Index
        //authValue directly (ownership transfers; stored wire-exact, stripped at the point it keys an
        //authorization, exactly as the password arm's OnNvDefineSpace stores it).
        return DefineNvIndexOverSession(state, request, request.IndexAuth);
    }

    /// <summary>
    /// Completes <c>TPM2_NV_DefineSpace()</c> over an HMAC session once its <c>auth</c> parameter has been
    /// decrypted (<see cref="TpmDecryptNvDefineAuthAction"/>'s continuation, TPM 2.0 Library Part 3, clause 31.3):
    /// installs the recovered plaintext value as the new Index's authValue and frames the session-authorized
    /// response.
    /// </summary>
    /// <remarks>
    /// The command-body checks all ran already in <c>ContinueNvDefineSpaceOverSession</c> (they read only the
    /// never-encrypted <c>publicInfo</c> fields), so the only failure reachable here is a malformed encrypted
    /// <c>auth</c> size field. The recovered carrier is installed wire-exact and every authorization computation
    /// takes its trailing-zero-stripped view (Part 1, clause 17.6.4.3) — a wrong decryption key is not itself
    /// detectable here (a corrupted authValue merely fails a later authorization). The request's own parsed
    /// carrier held ciphertext on this path and is released once the recovered value supersedes it.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="decrypted">The effect's result carrying the decrypted <c>auth</c> value and the request to resume.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the response-framing action, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnNvDefineAuthDecrypted(TpmSimulatorState state, TpmNvDefineAuthDecrypted decrypted)
    {
        if(decrypted.ResponseCode != TpmRcConstants.TPM_RC_SUCCESS)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, decrypted.ResponseCode, decrypted);
        }

        //"The size of auth is limited to be no larger than the size of the digest produced by the NV Index's
        //nameAlg (TPM_RC_SIZE)" — Part 3, clause 31.3.1, checked on the raw recovered size (the declared
        //TPM2B_AUTH size, before trailing-zero stripping), exactly as the reference checks the unmarshaled form.
        if(decrypted.DecryptedAuth.Length > TpmPolicyDigest.Size(decrypted.Request.NameAlg.Value))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_SIZE, decrypted);
        }

        decrypted.Request.IndexAuth.Dispose();

        return DefineNvIndexOverSession(state, decrypted.Request, decrypted.DecryptedAuth);
    }

    /// <summary>
    /// Stores the new Index (with <paramref name="indexAuth"/> as its authValue) and declares the session-response
    /// framing action for <c>TPM2_NV_DefineSpace()</c>'s owner arm — the tail shared by the plaintext
    /// (<see cref="ContinueNvDefineSpaceOverSession"/>) and decrypted (<see cref="OnNvDefineAuthDecrypted"/>) auth
    /// paths, which reach it with an authValue that is respectively the parsed and the recovered form.
    /// </summary>
    /// <param name="state">The state to transition from, with every command-body check already passed.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_NV_DefineSpace()</c> request.</param>
    /// <param name="indexAuth">The authorization value to install on the new Index, in an owned carrier whose ownership transfers to the Index; a refusing arm releases it (and the request's own carriers) instead.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the response-framing action.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of indexAuth and of the request's policy-digest and data-area carriers transfers to the stored NvIndexState, which eviction (TPM2_NV_UndefineSpace, TPM2_Clear, simulator teardown) or the next rotation disposes; the refusing arm releases indexAuth explicitly and the rest through the request's own Dispose before rejecting.")]
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> DefineNvIndexOverSession(
        TpmSimulatorState state, TpmNvDefineSpaceOverSessionRequested request, Tpm2bAuth indexAuth)
    {
        //"The size of auth is limited to be no larger than the size of the digest produced by the NV Index's
        //nameAlg (TPM_RC_SIZE)" — Part 3, clause 31.3.1, applied at the shared tail so the plaintext-session
        //and decrypted-auth paths both pass through it (the decrypted path additionally gates the identical
        //recovered size in OnNvDefineAuthDecrypted).
        if(indexAuth.Length > TpmPolicyDigest.Size(request.NameAlg.Value))
        {
            //Exactly one owner per carrier on the way out: the authValue this tail was handed is released here,
            //and the request the cascade releases has its own authValue slot swapped to the dispose-immune empty
            //sentinel — on the plaintext path that slot IS this carrier, and on the decrypted path the decrypt
            //continuation already superseded it.
            indexAuth.Dispose();

            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_SIZE, request with { IndexAuth = Tpm2bAuth.Empty });
        }

        //This tail is the parse-rented parameter area's terminal owner: the command HMAC that read it has
        //verified, any decryption that transformed it in place has run, and nothing downstream reads it again.
        request.Hmac.Dispose();
        request.RawParameterArea.Dispose();

        //The handle cleared ContinueNvDefineSpaceOverSession's TPM_HT_NV_INDEX gate before this tail runs, so
        //it also satisfies TPMI_RH_NV_INDEX — the interface type the durable NV state is keyed by.
        TpmiRhNvIndex indexHandle = TpmiRhNvIndex.FromValue(request.NvIndex.Value);

        var index = new NvIndexState(
            indexHandle, indexAuth, request.Attributes, request.DataSize, request.IndexData,
            request.NameAlg, request.AuthPolicy);

        HmacSessionState session = state.HmacSessions[TpmiShHmac.FromValue(request.AuthorizingSessionHandle.Value)];

        return Transition(
            state with
            {
                NvIndexes = state.NvIndexes.SetItem(indexHandle, index),
                NextAction = new TpmFrameNvSessionResponseAction(
                    TpmCcConstants.TPM_CC_NV_DefineSpace, TpmiShAuthSession.FromValue(session.Handle.Value), session.SessionAlg, session.SessionKey, request.ResolvedAuthValue ?? Tpm2bAuth.Empty,
                    request.NonceCaller, request.SessionAttributes, ReadWindow: null),
                ResponseIntent = null
            },
            "NvDefineSpace:OverSession:ResponseRequested");
    }

    /// <summary>
    /// Authorizes <c>TPM2_NV_UndefineSpace()</c>'s owner arm over an HMAC session (TPM 2.0 Library Part 3,
    /// clause 31.4).
    /// </summary>
    /// <remarks>
    /// Owner is the only provisioning authority modelled (the platform hierarchy arrives later, mirroring
    /// <c>OnNvDefineSpaceOverSession</c>); a non-owner <c>authHandle</c> is <c>TPM_RC_HANDLE</c>, the same fixed
    /// gate the password arm uses. The handle area resolves in full before the session area and the
    /// authorization checks (Part 3, clause 5.4 requires handle-area validation before the authorization
    /// checks; within the handle area it permits any order, and the authorizing hierarchy's own outcomes —
    /// admit, then enable — resolve before the Index handle's presence, the convention the password arm and
    /// <c>OnEvictControl</c> hold). Owner is DA-exempt, so no entity-side lockout gate applies; the bind-side
    /// lockout gate is a clause 5.6 authorization check and so runs after the handle area. Declares a
    /// <c>TpmComputeNvIndexNameAction</c> for cpHash's Name2 term, exactly as the Read/Write owner arms do.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_NV_UndefineSpace()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the Name-computation action, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnNvUndefineSpaceOverSession(TpmSimulatorState state, TpmNvUndefineSpaceOverSessionRequested request)
    {
        //The handle area resolves in full before the session area and the authorization checks (Part 3,
        //clause 5.4: "A TPM is required to perform the handle area validation before the authorization
        //checks"). Within it clause 5.4 permits any order: @authHandle's own outcomes (admit, then enable)
        //resolve before the Index handle's presence, the same convention the password arm and OnEvictControl
        //hold.
        if(request.AuthHandle.Value != (uint)TpmRh.TPM_RH_OWNER)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        //While shEnable is CLEAR the owner hierarchy can authorize nothing (Part 1, clause 11.2), whatever
        //the session proves.
        if(!state.IsHierarchyEnabled(request.AuthHandle.Value))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmRcConstants.TPM_RC_HIERARCHY, request);
        }

        //TPMI_RH_NV_DEFINED_INDEX widens to the TPMI_RH_NV_INDEX the durable NV state is keyed by, exactly as
        //on the password arm.
        if(!state.NvIndexes.TryGetValue(TpmiRhNvIndex.FromValue(request.NvIndex.Value), out NvIndexState? index))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        if(!state.HmacSessions.TryGetValue(TpmiShHmac.FromValue(request.AuthorizingSessionHandle.Value), out HmacSessionState? session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_UndefineSpace, SessionReferenceMissRc(sessionIndex: 0), request);
        }

        TpmRcConstants? sessionAreaError = ValidateSessionArea(
            request.SessionAttributes, firstAuthorizesEntity: true, session.Symmetric,
            hasSecondSession: false, secondAttributes: default, secondSymmetric: TpmtSymDef.Null,
            firstCommandParameterIsEncryptable: false, firstResponseParameterIsEncryptable: false,
            auditIsSupported: false,
            firstSessionHandle: request.AuthorizingSessionHandle, firstNonceLength: request.NonceCaller.Size);
        if(sessionAreaError is TpmRcConstants sessionAreaRc)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_UndefineSpace, sessionAreaRc, request);
        }

        //Owner is dictionary-attack exempt, but the SESSION may be bound to an entity that is not: use of such a
        //session is subject to DA whatever it authorizes (Part 3, clause 11.1.1) — a clause 5.6 authorization
        //check, run after the handle area above.
        if(IsBoundSessionLockedOut(state, session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        return Transition(
            state with
            {
                NextAction = new TpmComputeNvIndexNameAction(index.NvIndex, index.NameAlg, index.Attributes, index.AuthPolicy, index.DataSize, request),
                ResponseIntent = null
            },
            "NvUndefineSpace:OverSession:OwnerNameRequested");
    }

    /// <summary>
    /// Resumes <c>TPM2_NV_UndefineSpace()</c>'s owner arm once its command HMAC has verified, removing the
    /// Index and declaring the session-response framing action (TPM 2.0 Library Part 3, clause 31.4).
    /// </summary>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_NV_UndefineSpace()</c> request, its command HMAC now verified.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the response-framing action.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> ContinueNvUndefineSpaceOverSession(TpmSimulatorState state, TpmNvUndefineSpaceOverSessionRequested request)
    {
        //This continuation is the terminal owner of the parse-rented parameter area and of the Index Name the
        //Name-computation step transferred here: the command HMAC that read them has verified, and nothing
        //downstream reads either again.
        request.Hmac.Dispose();
        request.RawParameterArea.Dispose();
        request.ResolvedIndexName.Dispose();

        TpmiRhNvIndex indexHandle = TpmiRhNvIndex.FromValue(request.NvIndex.Value);
        NvIndexState index = state.NvIndexes[indexHandle];

        //Deleting a written Counter Index retires its value into the phantom high-water mark, through the same
        //rule the password arm applies (TPM 2.0 Library Part 1, clause 37.2.6.3 NOTE 2/NOTE 6).
        ulong highWaterMark = RetireNvCounterHighWaterMark(index, state.NvCounterHighWaterMark);

        HmacSessionState session = state.HmacSessions[TpmiShHmac.FromValue(request.AuthorizingSessionHandle.Value)];

        //Undefining is the Index's ownership-end boundary; the response framing below borrows the OWNER's
        //authValue carrier (this arm is owner-authorized), never the Index's, so releasing the Index's own
        //carrier here cannot touch what the response HMAC reads.
        index.Dispose();

        return Transition(
            state with
            {
                NvIndexes = state.NvIndexes.Remove(indexHandle),
                NvCounterHighWaterMark = highWaterMark,
                NextAction = new TpmFrameNvSessionResponseAction(
                    TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmiShAuthSession.FromValue(session.Handle.Value), session.SessionAlg, session.SessionKey, request.ResolvedAuthValue ?? Tpm2bAuth.Empty,
                    request.NonceCaller, request.SessionAttributes, ReadWindow: null),
                ResponseIntent = null
            },
            "NvUndefineSpace:OverSession:ResponseRequested");
    }

    /// <summary>
    /// Authorizes <c>TPM2_NV_Increment()</c> over an HMAC session on either arm — the owner hierarchy or the
    /// Counter Index's own authValue (TPM 2.0 Library Part 3, clause 31.8).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every gate the password arm (<c>OnNvIncrement</c>) applies before comparing an authValue is applied here in
    /// the identical order, which is what makes the two arms answer identically: the entity-existence check
    /// (<c>TPM_RC_HANDLE</c>), the session-area attribute gate, then on the owner arm <c>TPMA_NV_OWNERWRITE</c>
    /// alone, and on the Index arm the <c>authHandle == nvIndex</c> rule, the dictionary-attack lockout gate, and
    /// <c>TPMA_NV_AUTHWRITE</c>, in that sequence. The gates that follow the authorization instead of conditioning
    /// it — the <c>TPM_NT_COUNTER</c> type check and the write-lock check — live in
    /// <c>ContinueNvIncrementOverSession</c>, which is where the write-role access check and the counter-type
    /// check sit relative to each other for this command (Part 4, and Part 3, clause 31.8.1's own sequence).
    /// </para>
    /// <para>
    /// <c>decrypt</c>, <c>encrypt</c>, and <c>audit</c> all fail closed with <c>TPM_RC_ATTRIBUTES</c> through
    /// <see cref="ValidateSessionArea"/>, and for this command the first two are load-bearing rather than
    /// boilerplate: <c>TPM2_NV_Increment()</c> has no parameter in either direction (Part 3, clause 31.8.2,
    /// Tables 238-239), so a session claiming either attribute names an operation with nothing to act on, which
    /// Part 3, clause 5.7 requires be refused rather than silently ignored.
    /// </para>
    /// <para>
    /// The stranger-<c>authHandle</c> answer is preserved verbatim from the password arm: an <c>authHandle</c>
    /// that is neither the owner hierarchy nor the Index itself is <c>TPM_RC_NV_AUTHORIZATION</c>, which is what
    /// Part 3, clause 31.1 states for that case ("If authHandle is an NV Index, it must be the same as nvIndex
    /// (TPM_RC_NV_AUTHORIZATION)") — deliberately NOT the <c>TPM_RC_AUTH_TYPE</c> that
    /// <c>OnNvWriteOverSession</c> answers, whose own divergence is recorded rather than harmonized.
    /// </para>
    /// <para>
    /// Dictionary-attack behaviour is mechanism-blind (Part 1, clause 17.8.1: "All uses of a DA protected
    /// authValue receive DA protection"), and it is routed through the shared helpers rather than reimplemented:
    /// the pre-authorization Lockout-mode refusal is <see cref="IsNvIndexLockedOut"/>, the very predicate the
    /// password arm calls, and the mismatch itself is registered by <see cref="RejectSessionAuthFailure"/> once
    /// the effect reports it — the session-index-encoding counterpart of <see cref="RejectNvAuthFailure"/>,
    /// carrying the identical AUTH_FAIL-versus-BAD_AUTH and <c>FailedTries</c> rules, fed the
    /// <c>IsDaProtected</c> flag <c>OnNvIndexNameComputed</c> derives for the entity actually authorizing. The
    /// owner arm keeps its deliberate DA exemption: a permanent entity's authValue receives no DA protection
    /// (clause 17.8.1), so no lockout gate binds it and no failure of it moves <c>FailedTries</c>.
    /// </para>
    /// <para>
    /// Both arms declare a <c>TpmComputeNvIndexNameAction</c> over the Index as this command found it, so
    /// cpHash's Name terms hash the pre-increment <c>TPMA_NV_WRITTEN</c> state the caller signed over (Part 1,
    /// clause 16.7 equation 15; a first increment SETs that attribute, Part 1, clause 35.2.6.3); the increment
    /// itself lands only in the continuation, strictly after the command HMAC has verified.
    /// </para>
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_NV_Increment()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the Name-computation action, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnNvIncrementOverSession(TpmSimulatorState state, TpmNvIncrementOverSessionRequested request)
    {
        if(!state.NvIndexes.TryGetValue(request.NvIndex, out NvIndexState? index))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Increment, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        if(!state.HmacSessions.TryGetValue(TpmiShHmac.FromValue(request.AuthorizingSessionHandle.Value), out HmacSessionState? session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Increment, SessionReferenceMissRc(sessionIndex: 0), request);
        }

        TpmRcConstants? sessionAreaError = ValidateSessionArea(
            request.SessionAttributes, firstAuthorizesEntity: true, session.Symmetric,
            hasSecondSession: false, secondAttributes: default, secondSymmetric: TpmtSymDef.Null,
            firstCommandParameterIsEncryptable: false, firstResponseParameterIsEncryptable: false,
            auditIsSupported: false,
            firstSessionHandle: request.AuthorizingSessionHandle, firstNonceLength: request.NonceCaller.Size);
        if(sessionAreaError is TpmRcConstants sessionAreaRc)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Increment, sessionAreaRc, request);
        }

        //The bind-side lockout gate applies to BOTH arms, since it speaks to the entity the session was bound to
        //rather than the one it authorizes now (Part 3, clause 11.1.1: "regardless of the DA status of the entity
        //being authorized"), which is also why it sits ahead of the owner-arm branch.
        if(IsBoundSessionLockedOut(state, session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Increment, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        if(request.AuthHandle.Value == (uint)TpmRh.TPM_RH_OWNER)
        {
            //With TPMA_NV_OWNERWRITE clear owner authorization cannot increment this Index (Part 2, clause 13.4)
            //— checked BEFORE any HMAC work, the same non-leaking order the password arm's owner gate uses.
            if(!index.IsOwnerWriteAllowed)
            {
                return Reject(state, TpmCcConstants.TPM_CC_NV_Increment, TpmRcConstants.TPM_RC_NV_AUTHORIZATION, request);
            }

            return Transition(
                state with
                {
                    NextAction = new TpmComputeNvIndexNameAction(index.NvIndex, index.NameAlg, index.Attributes, index.AuthPolicy, index.DataSize, request),
                    ResponseIntent = null
                },
                "NvIncrement:OverSession:OwnerNameRequested");
        }

        //Part 3, clause 31.1: an Index-authorization authHandle that does not equal the Index itself is
        //TPM_RC_NV_AUTHORIZATION. This is the answer the password arm gives for the identical case and it is
        //preserved rather than harmonized with TPM2_NV_Write()'s TPM_RC_AUTH_TYPE (see this method's remarks).
        if(request.AuthHandle.Value != request.NvIndex.Value)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Increment, TpmRcConstants.TPM_RC_NV_AUTHORIZATION, request);
        }

        //Already-locked-out DA-protected Index: refuse before the authorization is evaluated at all (Part 1,
        //clause 17.8.3; Part 3, clause 5.6's check 3 precedes its check 9), the same gate and the same helper the
        //password arm's Index arm uses — the entity whose authValue this arm consumes IS the DA-protected Index.
        if(IsNvIndexLockedOut(state, index))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Increment, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        //With TPMA_NV_AUTHWRITE clear the Index's own authValue is not an available authorization mechanism for
        //an increment at all (Part 1, clause 35.2.6.1) — checked BEFORE the HMAC, mirroring the password arm's
        //placement of the identical gate ahead of its value compare, and matching where Part 3, clause 5.6's
        //check 7.2.2 (TPM_RC_AUTH_UNAVAILABLE) sits relative to its check 9.
        if(!index.IsAuthWriteAllowed)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Increment, TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, request);
        }

        return Transition(
            state with
            {
                NextAction = new TpmComputeNvIndexNameAction(index.NvIndex, index.NameAlg, index.Attributes, index.AuthPolicy, index.DataSize, request),
                ResponseIntent = null
            },
            "NvIncrement:OverSession:IndexNameRequested");
    }

    /// <summary>
    /// Resumes <c>TPM2_NV_Increment()</c> once its authorizing HMAC session's command HMAC has verified,
    /// incrementing the counter and declaring the session-response framing action (TPM 2.0 Library Part 3,
    /// clause 31.8).
    /// </summary>
    /// <remarks>
    /// The counter semantics are the password arm's, unchanged: a Counter Index only (<c>TPM_RC_ATTRIBUTES</c>
    /// otherwise, clause 31.8.1), never while write-locked (<c>TPM_RC_NV_LOCKED</c>), and an unwritten counter
    /// seeds from the phantom high-water mark rather than from zero so no Name can ever repeat a value it has
    /// already reported (Part 1, clause 35.2.6.3). Both type gates run here rather than in
    /// <c>OnNvIncrementOverSession</c> because they follow the authorization rather than conditioning it, which is
    /// also why an unwritten counter never answers <c>TPM_RC_NV_UNINITIALIZED</c> — performing the first write IS
    /// this command's contract. The response HMAC is keyed on the same <c>sessionKey ‖ authValue</c> the command
    /// HMAC verified against, carried in <c>ResolvedAuthValue</c> (Part 1, clause 17.6.5), and its rpHash covers
    /// an empty parameter area because the response has no parameters at all (clause 16.8 equation 16).
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_NV_Increment()</c> request, its command HMAC now verified.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the response-framing action, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> ContinueNvIncrementOverSession(TpmSimulatorState state, TpmNvIncrementOverSessionRequested request)
    {
        NvIndexState index = state.NvIndexes[request.NvIndex];

        //TPM2_NV_Increment() modifies a Counter Index only; every other type is refused (Part 3, clause 31.8.1:
        //"If nvIndexType is not TPM_NT_COUNTER... the TPM shall return TPM_RC_ATTRIBUTES"), mirroring the
        //password arm exactly.
        if(index.IndexType != TpmNt.TPM_NT_COUNTER)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Increment, TpmRcConstants.TPM_RC_ATTRIBUTES, request);
        }

        //A write-locked Index cannot be incremented (Part 3, clause 31.8.1). As on the password arm, no command
        //in this simulator can SET TPMA_NV_WRITELOCKED today, so the branch lands fail-closed rather than being
        //omitted for being presently unreachable.
        if((index.Attributes & TpmaNv.TPMA_NV_WRITELOCKED) != 0)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Increment, TpmRcConstants.TPM_RC_NV_LOCKED, request);
        }

        //Unwritten counter: seed from the highest value any counter Index has ever held, including a deleted one
        //(the phantom-counter mechanism on NvCounterHighWaterMark, Part 1, clause 35.2.6.3 NOTE 2/NOTE 6), then
        //increment; a written counter simply increments its stored value. Identical to the password arm — this
        //arm changes how the command is authorized, never what the counter does.
        //This continuation is the terminal owner of the parse-rented parameter area and of the Index Name the
        //Name-computation step transferred here: the command HMAC that read them has verified, and nothing
        //downstream reads either again.
        request.Hmac.Dispose();
        request.RawParameterArea.Dispose();
        request.ResolvedIndexName.Dispose();

        ulong seed = index.IsWritten ? index.CounterValue : state.NvCounterHighWaterMark;
        NvIndexState updated = index.WithCounterValue(seed + 1);

        HmacSessionState session = state.HmacSessions[TpmiShHmac.FromValue(request.AuthorizingSessionHandle.Value)];

        return Transition(
            state with
            {
                NvIndexes = state.NvIndexes.SetItem(updated.NvIndex, updated),
                NextAction = new TpmFrameNvSessionResponseAction(
                    TpmCcConstants.TPM_CC_NV_Increment, TpmiShAuthSession.FromValue(session.Handle.Value), session.SessionAlg, session.SessionKey, request.ResolvedAuthValue ?? Tpm2bAuth.Empty,
                    request.NonceCaller, request.SessionAttributes, ReadWindow: null),
                ResponseIntent = null
            },
            "NvIncrement:OverSession:ResponseRequested");
    }

    /// <summary>
    /// Authorizes <c>TPM2_NV_ChangeAuth()</c> — the atomic, in-place replacement of an NV Index's authorization
    /// value (TPM 2.0 Library Part 3, clause 31.15) — and, once every structural gate has passed, declares the
    /// Index Name computation cpHash needs.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the first command in this simulator whose ADMIN Auth Role is load-bearing rather than
    /// fail-closed-refused (<c>TPM2_Certify()</c> and <c>TPM2_ActivateCredential()</c> carry the role on a
    /// handle whose <c>adminWithPolicy</c> is CLEAR, so their arms never consult a policy's command code):
    /// clause 31.15.1 requires unconditionally that "a policy session be used for
    /// authorization of nvIndex so that the ADMIN role may be asserted and that commandCode in the policy
    /// session context shall be TPM_CC_NV_ChangeAuth". An NV Index has no <c>adminWithPolicy</c>-style attribute
    /// that could open an authValue fallback the way a loaded object's CLEAR bit does (Part 1, clause 17.2's
    /// ADMIN bullet is written for objects; clause 35.2.3 states the NV form with no such escape), so a
    /// <c>TPM_RS_PW</c> or HMAC session is refused with <c>TPM_RC_AUTH_TYPE</c> — the type of authorization is
    /// simply not one this entity accepts for this command.
    /// </para>
    /// <para>
    /// The policy gates then run in the order the ADMIN Note (clause 17.2) states them, and each is a distinct
    /// answer: a policyDigest that does not equal the Index's authPolicy is <c>TPM_RC_POLICY_FAIL</c>; a session
    /// that never asserted <c>TPM2_PolicyCommandCode()</c> at all is also <c>TPM_RC_POLICY_FAIL</c> (the second,
    /// independent half of the Note's conjunction is unsatisfiable, not merely unmatched); a session that
    /// asserted the wrong command code is <c>TPM_RC_POLICY_CC</c>. The two codes are kept apart deliberately:
    /// collapsing them would hide from a caller whether the policy is the wrong SHAPE or merely scoped to
    /// another command. A consequence worth stating plainly: an Index defined with an Empty authPolicy can never
    /// satisfy the digest gate — a policyDigest is always a full hash width and an Empty Buffer is zero-length
    /// (Part 1, clause 11.2) — so such an Index's authValue is fixed for its entire lifetime, and rotation
    /// capability is a decision made once, at <c>TPM2_NV_DefineSpace()</c>.
    /// </para>
    /// <para>
    /// The digest/commandCode checks run HERE, before the command HMAC, rather than in the continuation where
    /// <c>ContinueUnsealOverSessions</c>/<c>OnActivateCredentialOverSession</c> place their own digest match.
    /// That divergence is deliberate and follows the role: for a USER-role entity the digest gate is an
    /// additional check on an already-authorized command, whereas for ADMIN role it IS the authorization, so it
    /// belongs with the other pre-HMAC session-processing gates (Part 3, clause 5.6's checks precede check 9).
    /// The dictionary-attack and PIN at-limit gates that follow are conditional on the policy having asserted
    /// <c>TPM2_PolicyAuthValue()</c>, because only then is the Index's authValue "used for authorization" at all
    /// (Part 1, clause 17.6.5's policy Note) — a rotation under a command-code-only policy is DA- and
    /// throttle-neutral in both directions.
    /// </para>
    /// <para>
    /// <c>decrypt</c> or <c>encrypt</c> on the AUTHORIZING policy session is refused with
    /// <c>TPM_RC_ATTRIBUTES</c> rather than modelled. Part 1, clause 19.1's Note is the reason: "A policy session
    /// that is used for parameter encryption uses authValue to calculate sessionValue even if the policy does not
    /// include TPM2_PolicyAuthValue()" — a rule entirely separate from the authorization-HMAC-key rule above. An
    /// unbound, unsalted session of that shape would therefore derive its whole encryption key from the very
    /// authValue being rotated away from, which protects <c>newAuth</c> against nobody who could not already
    /// guess the old value. A caller that wants <c>newAuth</c> confidential supplies a SEPARATE decrypt session,
    /// whose sessionValue is its own session key.
    /// </para>
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_NV_ChangeAuth()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the Name-computation action, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnNvChangeAuthOverSession(TpmSimulatorState state, TpmNvChangeAuthOverSessionRequested request)
    {
        if(!state.NvIndexes.TryGetValue(request.NvIndex, out NvIndexState? index))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_ChangeAuth, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        if(!state.PolicySessions.TryGetValue(TpmiShPolicy.FromValue(request.AuthorizingSessionHandle.Value), out PolicySessionState? policySession))
        {
            //A password or HMAC session is a KIND of authorization this entity does not accept for this command,
            //which is what TPM_RC_AUTH_TYPE says; a handle that resolves to no loaded session at all is the
            //generic session-not-loaded warning instead (Part 2, clause 6.6.2), the same distinction every other
            //session-authorized arm draws.
            bool isAuthorizationTypeRefused = request.AuthorizingSessionHandle.IsPasswordSession
                || state.HmacSessions.ContainsKey(TpmiShHmac.FromValue(request.AuthorizingSessionHandle.Value));

            return Reject(
                state,
                TpmCcConstants.TPM_CC_NV_ChangeAuth,
                isAuthorizationTypeRefused ? TpmRcConstants.TPM_RC_AUTH_TYPE : SessionReferenceMissRc(sessionIndex: 0),
                request);
        }

        //A trial session (TPM_SE_TRIAL) accumulates a policyDigest for prediction but authorizes nothing, so it
        //is refused before the Index's authPolicy is ever consulted — the same order and the same response code
        //ContinueUnsealOverSessions uses for the other policy-session-authorized entity in this model.
        if(policySession.IsTrial)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_ChangeAuth, TpmRcConstants.TPM_RC_POLICY_FAIL, request);
        }

        //Whether the second block arrived is a structural fact the parser settled from authorizationSize, so it is
        //read from the record rather than guessed from the handle, and the slot is then resolved and validated for
        //every value it can hold: a handle that is not a session handle at all is TPM_RC_HANDLE and a well-typed
        //handle naming no loaded session is TPM_RC_REFERENCE_S*, both blamed on this index (Part 3, clause 5.5,
        //step 4).
        bool hasDecryptSession = request.HasDecryptSlot;
        HmacSessionState? decryptSession = null;
        if(hasDecryptSession
            && !TryResolveCommandSession(state, request.DecryptSessionHandle, sessionIndex: 1, out decryptSession, out TpmRcConstants decryptSlotRefusal))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_ChangeAuth, decryptSlotRefusal, request);
        }

        //Part 1, clause 19.1's Note (see this method's remarks): a policy session carrying decrypt or encrypt
        //would key parameter encryption on the authValue being rotated, so the shape fails closed here rather
        //than reaching ValidateSessionArea, whose generic answer for a POLICY session's absent symmetric
        //definition would be TPM_RC_SYMMETRIC and would misattribute the refusal to algorithm negotiation.
        if((request.SessionAttributes & (TpmaSession.DECRYPT | TpmaSession.ENCRYPT)) != 0)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_ChangeAuth, SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), request);
        }

        //newAuth is the sole, and so the first, sized command parameter, which is exactly the structural
        //condition that makes it decrypt-eligible (Part 1, clause 19.1); the response has no parameters at all,
        //so encrypt stays closed, and no audit trail is modelled. A POLICY session carries no negotiated
        //symmetric definition, mirroring what OnPolicySecretOverSession passes for the same reason.
        TpmRcConstants? sessionAreaError = ValidateSessionArea(
            request.SessionAttributes, firstAuthorizesEntity: true, TpmtSymDef.Null,
            hasDecryptSession, request.DecryptSessionAttributes, decryptSession?.Symmetric ?? TpmtSymDef.Null,
            firstCommandParameterIsEncryptable: true, firstResponseParameterIsEncryptable: false,
            auditIsSupported: false,
            firstSessionHandle: request.AuthorizingSessionHandle, secondSessionHandle: request.DecryptSessionHandle,
            firstNonceLength: request.NonceCaller.Size, secondNonceLength: request.DecryptNonceCaller.Size);
        if(sessionAreaError is TpmRcConstants sessionAreaRc)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_ChangeAuth, sessionAreaRc, request);
        }

        if(!policySession.PolicyDigest.AsReadOnlySpan().SequenceEqual(index.AuthPolicy.AsReadOnlySpan()))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_ChangeAuth, TpmRcConstants.TPM_RC_POLICY_FAIL, request);
        }

        if(policySession.CommandCode is not TpmCcConstants restrictedCommand)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_ChangeAuth, TpmRcConstants.TPM_RC_POLICY_FAIL, request);
        }

        if(restrictedCommand != TpmCcConstants.TPM_CC_NV_ChangeAuth)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_ChangeAuth, TpmRcConstants.TPM_RC_POLICY_CC, request);
        }

        //The bind-side gate is unconditional, unlike the Index-side one below: a policy session's sessionKey folds
        //its bind entity's authValue whether or not the policy went on to assert TPM2_PolicyAuthValue() (Part 3,
        //Section 11.1.1's "For all session types"), and so does a decrypt companion's, so use of either is a use
        //of that bound secret (Part 1, clause 17.8.1's third way an authValue is used).
        if(IsBoundSessionLockedOut(state, policySession))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_ChangeAuth, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        if(decryptSession is not null && IsBoundSessionLockedOut(state, decryptSession))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_ChangeAuth, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        if(policySession.IsAuthValueNeeded)
        {
            if(IsNvIndexLockedOut(state, index))
            {
                return Reject(state, TpmCcConstants.TPM_CC_NV_ChangeAuth, TpmRcConstants.TPM_RC_LOCKOUT, request);
            }

            if(IsPinAuthUnavailable(index))
            {
                return Reject(state, TpmCcConstants.TPM_CC_NV_ChangeAuth, TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, request);
            }
        }

        return Transition(
            state with
            {
                NextAction = new TpmComputeNvIndexNameAction(index.NvIndex, index.NameAlg, index.Attributes, index.AuthPolicy, index.DataSize, request),
                ResponseIntent = null
            },
            "NvChangeAuth:OverSession:IndexNameRequested");
    }

    /// <summary>
    /// Builds cpHash's handle-Name area and queues every authorization-area session's command-HMAC verification
    /// for <c>TPM2_NV_ChangeAuth()</c>, once the Index's Name has been computed.
    /// </summary>
    /// <remarks>
    /// The command carries a single handle, so cpHash's Name area is the Index's own Name alone (TPM 2.0 Library
    /// Part 1, clause 16.7 equation 15) — no Name1/Name2 pair and no owner-arm branch, which is why this does not
    /// share <c>OnNvIndexNameComputed</c>'s body with the five USER-role NV arms. The authorizing session's HMAC
    /// key folds the Index's CURRENT authValue exactly when the policy asserted <c>TPM2_PolicyAuthValue()</c>
    /// (equation 26 versus equation 27, Part 1, clause 17.6.12); a POLICY session never applies the HMAC
    /// session's bind-omission optimization, since it is never bound (Part 3, Section 11.1.1). A separate
    /// decrypt session authorizes nothing, so its own key is its session key alone — but it still owes a command
    /// HMAC like every other session in the area (Part 3, clause 5.6), and its nonceTPM folds into the
    /// authorizing session's HMAC as the session at index 1.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="indexName">The Index's computed Name, TRANSFERRED onto <paramref name="request"/> so it outlives this transition and can be laid out into cpHash by the verifying effect.</param>
    /// <param name="request">The parsed <c>TPM2_NV_ChangeAuth()</c> request to resume.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the first command-HMAC verification.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> ContinueNvChangeAuthNameComputed(
        TpmSimulatorState state, Tpm2bName indexName, TpmNvChangeAuthOverSessionRequested request)
    {
        PolicySessionState policySession = state.PolicySessions[TpmiShPolicy.FromValue(request.AuthorizingSessionHandle.Value)];
        NvIndexState index = state.NvIndexes[request.NvIndex];

        //Trailing zeros are removed from an authValue where it keys an authorization computation (Part 1,
        //clause 17.6.4.3) — the HMAC primitive takes the stripped view of the borrowed carrier, the same fold
        //every other NV arm applies to the term it contributes.
        Tpm2bAuth authValueForHmac = policySession.IsAuthValueNeeded
            ? index.AuthValue
            : Tpm2bAuth.Empty;

        bool hasDecryptSession = request.HasDecryptSlot;
        HmacSessionState? decryptSession = hasDecryptSession ? state.HmacSessions[TpmiShHmac.FromValue(request.DecryptSessionHandle.Value)] : null;

        var pending = ImmutableArray.CreateBuilder<TpmPendingSessionVerification>(hasDecryptSession ? 2 : 1);

        //Part 1, clause 17.8.7's OR: the failure counter moves "if either the entity being authorized is subject
        //to DA protection or if the session is bound to an entity that has DA protection", so the Index-side term
        //(which the policy folds only under TPM2_PolicyAuthValue()) and the session's own bind-side term are
        //independent grounds for the charge.
        pending.Add(new TpmPendingSessionVerification(
            SessionHandle: TpmiShAuthSession.FromValue(policySession.Handle.Value), SessionIndex: 0, SessionAlg: policySession.PolicyHash, SessionKey: policySession.SessionKey,
            AuthValue: authValueForHmac,
            IsDaProtected: (policySession.IsAuthValueNeeded && index.IsDaProtected) || policySession.IsBoundEntityDaProtected,
            NonceCaller: request.NonceCaller, NonceTpm: policySession.NonceTpm,
            FoldedNonceDecrypt: hasDecryptSession ? decryptSession!.NonceTpm : Tpm2bNonce.Empty,
            FoldedNonceEncrypt: Tpm2bNonce.Empty,
            SessionAttributes: request.SessionAttributes, SuppliedHmac: request.Hmac,
            IsLockoutEntity: policySession.IsBoundToLockout));

        if(hasDecryptSession)
        {
            //A decrypt companion authorizes no entity, so its whole dictionary-attack standing comes from its own
            //bind: its HMAC keys on a session key that folded that entity's authValue, and a mismatch on it is
            //evidence against that secret exactly as one on the authorizing session is (clause 17.8.1's third way
            //an authValue is used for authorization).
            pending.Add(new TpmPendingSessionVerification(
                SessionHandle: TpmiShAuthSession.FromValue(decryptSession!.Handle.Value), SessionIndex: 1, SessionAlg: decryptSession.SessionAlg, SessionKey: decryptSession.SessionKey,
                AuthValue: Tpm2bAuth.Empty, IsDaProtected: decryptSession.IsBoundEntityDaProtected,
                NonceCaller: request.DecryptNonceCaller, NonceTpm: decryptSession.NonceTpm,
                FoldedNonceDecrypt: Tpm2bNonce.Empty, FoldedNonceEncrypt: Tpm2bNonce.Empty,
                SessionAttributes: request.DecryptSessionAttributes, SuppliedHmac: request.DecryptHmac,
                IsLockoutEntity: decryptSession.IsBoundToLockout));
        }

        ImmutableArray<TpmPendingSessionVerification> queue = pending.ToImmutable();

        return Transition(
            state with
            {
                NextAction = new TpmVerifyCommandHmacAction(
                    TpmCcConstants.TPM_CC_NV_ChangeAuth, TpmCommandHandleNames.Of(TpmHandleName.FromName(indexName)), request.RawParameterArea,
                    queue[0], queue.RemoveAt(0), request with { ResolvedAuthValue = authValueForHmac, ResolvedIndexName = indexName }),
                ResponseIntent = null
            },
            "NvChangeAuth:OverSession:HmacVerifyRequested");
    }

    /// <summary>
    /// Resumes <c>TPM2_NV_ChangeAuth()</c> once every session in its authorization area has verified: settles the
    /// PIN throttle for the proven authorization, then either declares the <c>newAuth</c> decryption or completes
    /// the rotation directly.
    /// </summary>
    /// <remarks>
    /// The PIN outcome is applied here, before the <c>newAuth</c> size check that can still reject the command,
    /// because the throttle tracks the AUTHORIZATION rather than the command's success: a caller that proved the
    /// current PIN has earned the reset (TPM 2.0 Library Part 1, clause 35.2.6.6) even if the value they then
    /// asked to rotate to was malformed. As on the failure path, the update is conditional on the policy having
    /// folded the authValue — see <see cref="IsNvChangeAuthValueFolded"/>.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_NV_ChangeAuth()</c> request, its sessions now verified.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the decrypt action, or the completed rotation.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> ContinueNvChangeAuthOverSession(TpmSimulatorState state, TpmNvChangeAuthOverSessionRequested request)
    {
        NvIndexState index = state.NvIndexes[request.NvIndex];
        if(index.IsPinIndex && IsNvChangeAuthValueFolded(state, request))
        {
            NvIndexState settled = ApplyPinAuthOutcome(index, authMatched: true);
            state = state with { NvIndexes = state.NvIndexes.SetItem(settled.NvIndex, settled) };
        }

        //A decrypt-attributed companion session encrypted newAuth (Part 1, clause 19.1): its plaintext cannot
        //become the Index authValue until it is decrypted, which follows the now-complete command-HMAC
        //verification of BOTH sessions (Part 3, clause 5.6 precedes clause 5.8). The keystream is derived from
        //that session's own key alone, never the authorizing session's material.
        if(request.HasDecryptSlot && (request.DecryptSessionAttributes & TpmaSession.DECRYPT) != 0)
        {
            HmacSessionState decryptSession = state.HmacSessions[TpmiShHmac.FromValue(request.DecryptSessionHandle.Value)];

            return Transition(
                state with
                {
                    NextAction = new TpmDecryptNvChangeAuthAction(
                        request, request.RawParameterArea, decryptSession.SessionAlg, decryptSession.Symmetric,
                        decryptSession.SessionKey, Tpm2bAuth.Empty, request.DecryptNonceCaller, decryptSession.NonceTpm),
                    ResponseIntent = null
                },
                "NvChangeAuth:OverSession:NewAuthDecryptRequested");
        }

        //No decrypt session: newAuth crossed in the clear, so its parsed value is the replacement authValue.
        return CompleteNvChangeAuth(state, request, request.NewAuth);
    }

    /// <summary>
    /// Completes <c>TPM2_NV_ChangeAuth()</c> once its <c>newAuth</c> parameter has been decrypted
    /// (<see cref="TpmDecryptNvChangeAuthAction"/>'s continuation, TPM 2.0 Library Part 3, clause 31.15).
    /// </summary>
    /// <remarks>
    /// The only failure reachable here is a malformed encrypted <c>newAuth</c> size field, reported bare exactly
    /// as <c>OnNvDefineAuthDecrypted</c> reports its own: a wrong decryption key is not itself detectable (a
    /// corrupted authValue merely fails a later authorization), so nothing here distinguishes it from an honest
    /// caller's malformed buffer.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="decrypted">The effect's result carrying the decrypted <c>newAuth</c> and the request to resume.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> completing the rotation, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnNvChangeAuthDecrypted(TpmSimulatorState state, TpmNvChangeAuthDecrypted decrypted)
    {
        if(decrypted.ResponseCode != TpmRcConstants.TPM_RC_SUCCESS)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_ChangeAuth, decrypted.ResponseCode, decrypted);
        }

        //The request's parsed carrier held ciphertext on this path; the recovered value supersedes it.
        decrypted.Request.NewAuth.Dispose();

        return CompleteNvChangeAuth(state, decrypted.Request, decrypted.DecryptedNewAuth);
    }

    /// <summary>
    /// Applies <c>TPM2_NV_ChangeAuth()</c>'s size gate and its effect — the tail shared by the plaintext
    /// (<see cref="ContinueNvChangeAuthOverSession"/>) and decrypted (<see cref="OnNvChangeAuthDecrypted"/>)
    /// paths, which reach it with a <paramref name="newAuth"/> that is respectively the parsed and the recovered
    /// form.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The strip-then-compare ORDER is normative, not an optimization: trailing octets of zero are removed from
    /// any string before it is used as an authValue (TPM 2.0 Library Part 1, clause 17.6.4.3), and only the
    /// remainder is measured against the Index's nameAlg digest size (clause 17.6.4.2; clause 31.15.1's "the
    /// size of the newAuth value may be no larger than the size of the digest produced by the nameAlg of the NV
    /// Index"). A 32-octet value padded to 40 with zeros is therefore accepted against a SHA-256 Index while a
    /// genuine 33-octet value is <c>TPM_RC_SIZE</c>. The hash-if-too-long convention for an over-long passphrase
    /// is the caller's to apply (clause 17.6.4.3: "The TPM does not enforce this transformation"), so an
    /// over-long value is refused here rather than silently digested.
    /// </para>
    /// <para>
    /// The effect replaces the authValue and nothing else: the data area, and so a PIN Index's pinCount/pinLimit
    /// and its <c>TPMA_NV_WRITTEN</c> bit, survive untouched, and the Index's Name is unchanged by construction
    /// (see <see cref="NvIndexState.WithAuthValue"/>). This is what makes rotation atomic in the sense that
    /// matters: the Index never ceases to exist, so no window opens in which its throttle history is lost.
    /// </para>
    /// <para>
    /// The rotation is committed BEFORE the response is framed, which is why the authorizing session's response
    /// entry is keyed on the NEW authValue whenever the policy folded one at all (clause 31.15.1: "Since the NV
    /// Index authorization is changed before the response HMAC is calculated, the newAuth value is used when
    /// generating the response HMAC key if required"). A response keyed on the old value would verify against a
    /// host that had not yet swapped, which is precisely the mistake this ordering forecloses.
    /// </para>
    /// </remarks>
    /// <param name="state">The state to transition from, with authorization already established.</param>
    /// <param name="request">The parsed <c>TPM2_NV_ChangeAuth()</c> request.</param>
    /// <param name="newAuth">The replacement authorization value in an owned carrier, trailing zeros not yet removed; ownership transfers to the Index at install, and the refusing arm releases it instead.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the response-framing action, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> CompleteNvChangeAuth(
        TpmSimulatorState state, TpmNvChangeAuthOverSessionRequested request, Tpm2bAuth newAuth)
    {
        NvIndexState index = state.NvIndexes[request.NvIndex];
        ReadOnlySpan<byte> strippedNewAuth = StripTrailingZeros(newAuth.AsReadOnlySpan());

        //An Index's nameAlg was validated when it was defined, so the digest size always resolves; the
        //zero fallback keeps the gate fail-closed rather than throwing on a value that cannot arise.
        int nameAlgDigestSize = index.NameAlg.DigestSize ?? 0;
        if(strippedNewAuth.Length > nameAlgDigestSize)
        {
            //Exactly one owner per carrier on the way out: the authValue this tail was handed is released here,
            //and the request the cascade releases has its own authValue slot swapped to the dispose-immune empty
            //sentinel — on the plaintext path that slot IS this carrier, and on the decrypted path the decrypt
            //continuation already superseded it.
            newAuth.Dispose();

            return Reject(state, TpmCcConstants.TPM_CC_NV_ChangeAuth, TpmRcConstants.TPM_RC_SIZE, request with { NewAuth = Tpm2bAuth.Empty });
        }

        //This tail is the terminal owner of the parse-rented parameter area and of the Index Name the
        //Name-computation step transferred onto the request: the command HMAC that read them has verified,
        //any decryption that transformed the area in place has run, and nothing downstream reads either again.
        request.Hmac.Dispose();
        request.DecryptHmac.Dispose();
        request.RawParameterArea.Dispose();
        request.ResolvedIndexName.Dispose();

        NvIndexState rotated = index.WithAuthValue(newAuth);
        PolicySessionState policySession = state.PolicySessions[TpmiShPolicy.FromValue(request.AuthorizingSessionHandle.Value)];
        bool hasDecryptSession = request.HasDecryptSlot;

        var responseSessions = ImmutableArray.CreateBuilder<TpmNvChangeAuthResponseSession>(hasDecryptSession ? 2 : 1);

        responseSessions.Add(new TpmNvChangeAuthResponseSession(
            IsPasswordPlaceholder: false,
            SessionHandle: TpmiShAuthSession.FromValue(policySession.Handle.Value), IsPolicySession: true, SessionAlg: policySession.PolicyHash,
            SessionKey: policySession.SessionKey,
            AuthValue: policySession.IsAuthValueNeeded ? rotated.AuthValue : Tpm2bAuth.Empty,
            NonceCaller: request.NonceCaller, SessionAttributes: request.SessionAttributes));

        if(hasDecryptSession)
        {
            HmacSessionState decryptSession = state.HmacSessions[TpmiShHmac.FromValue(request.DecryptSessionHandle.Value)];

            responseSessions.Add(new TpmNvChangeAuthResponseSession(
                IsPasswordPlaceholder: false,
                SessionHandle: TpmiShAuthSession.FromValue(decryptSession.Handle.Value), IsPolicySession: false, SessionAlg: decryptSession.SessionAlg,
                SessionKey: decryptSession.SessionKey, AuthValue: Tpm2bAuth.Empty,
                NonceCaller: request.DecryptNonceCaller, SessionAttributes: request.DecryptSessionAttributes));
        }

        return Transition(
            state with
            {
                NvIndexes = state.NvIndexes.SetItem(rotated.NvIndex, rotated),
                NextAction = new TpmFrameNvChangeAuthResponseAction(TpmCcConstants.TPM_CC_NV_ChangeAuth, responseSessions.ToImmutable()),
                ResponseIntent = null
            },
            "NvChangeAuth:OverSession:ResponseRequested");
    }

    /// <summary>
    /// Rolls every authorization-area session's nonceTPM and frames an authValue rotation's response once the
    /// effect has computed each entry — <c>TPM2_NV_ChangeAuth()</c> or <c>TPM2_HierarchyChangeAuth()</c>, which
    /// share this shape (TPM 2.0 Library Part 1, clause 16.6.1).
    /// </summary>
    /// <remarks>
    /// The authorizing policy session additionally undergoes the full policy-context reset a successful
    /// authorization triggers (<see cref="ResetPolicySessionContext"/>, Part 3, Section 23.2.4) — this is the
    /// success-only point where that lands, so a command rejected anywhere in the ladder above leaves the
    /// session's accumulated assertions intact for a retry. Each session is looked up defensively before its
    /// table is updated: a session flushed meanwhile still gets its framed response returned, only the table
    /// update is skipped, mirroring <c>OnEncryptedRandomProduced</c>'s convention.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="framed">The effect's result carrying each session's rolled nonceTPM and response HMAC.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> carrying the framed response.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnNvChangeAuthResponseFramed(TpmSimulatorState state, TpmNvChangeAuthResponseFramed framed)
    {
        ImmutableDictionary<TpmiShHmac, HmacSessionState> hmacSessions = state.HmacSessions;
        ImmutableDictionary<TpmiShPolicy, PolicySessionState> policySessions = state.PolicySessions;

        foreach(TpmNvChangeAuthFramedSessionEntry entry in framed.Entries)
        {
            //A password slot carries no session state at all, so there is no nonceTPM to roll and no table to
            //find it in; its entry exists only to hold its wire position (Part 1, clause 16.6.1).
            if(entry.IsPasswordPlaceholder)
            {
                continue;
            }

            if(entry.IsPolicySession)
            {
                policySessions = RollPolicySessionNonce(policySessions, entry.SessionHandle, state.Time, entry.RetainedNonceTpm);
            }
            else
            {
                hmacSessions = RollHmacSessionNonce(hmacSessions, entry.SessionHandle, entry.RetainedNonceTpm);
            }
        }

        return Transition(
            state with
            {
                NextAction = NullAction.Instance,
                HmacSessions = hmacSessions,
                PolicySessions = policySessions,
                ResponseIntent = new TpmNvChangeAuthResponse(TpmRcConstants.TPM_RC_SUCCESS, framed.Entries)
            },
            "NvChangeAuth:OverSession:ResponseCompleted");
    }

    /// <summary>
    /// Builds cpHash's handle-Name area and declares the command-HMAC verification for a session-authorized NV
    /// command once its Index's Name has been computed (TPM 2.0 Library Part 1, clause 16.7 equation 15; clause
    /// 17.6.10 equations 21/22) — the shared continuation <c>OnNvReadOverSession</c>/<c>OnNvWriteOverSession</c>/
    /// <c>OnNvUndefineSpaceOverSession</c>/<c>OnNvIncrementOverSession</c> all resume through
    /// (<c>TpmComputeNvIndexNameAction</c>'s effect feedback), plus the entry point
    /// <c>TPM2_NV_ChangeAuth()</c>'s ADMIN-role arm and <c>TPM2_NV_Certify()</c>'s two-authorized-handle arm each
    /// take to their own continuation.
    /// <c>TPM2_NV_DefineSpace()</c> never reaches this — its single-handle cpHash needs no Index
    /// Name at all, so it declares <c>TpmVerifyCommandHmacAction</c> directly.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Name1/Name2 per the digest's Table 6 reading: the owner arm's Name1 is the owner's raw 4-octet handle and
    /// Name2 is the Index's computed Name; the Index arm's Name1 and Name2 are BOTH the Index's own computed
    /// Name (the same handle authorizes and is being addressed). The bind-omission decision (equation 22) — the
    /// authValue term drops when the authorizing session is bound to the SAME entity now authorizing — is
    /// resolved here, once, and threaded onward via <c>ResolvedAuthValue</c> so the eventual response HMAC
    /// (<c>ContinueNvReadOverSession</c>/<c>ContinueNvWriteOverSession</c>/<c>ContinueNvUndefineSpaceOverSession</c>/
    /// <c>ContinueNvIncrementOverSession</c>)
    /// reuses the identical key without recomputing the Index's Name a second time (Part 1, clause 17.6.5, which keys the HMAC of a command
    /// or a response alike on sessionKey concatenated to authValue).
    /// </para>
    /// <para>
    /// The Name folded in is the Index's Name as the command found it, which is the only reading that keeps
    /// cpHash a digest of the command as sent (equation 15): <c>TPM2_NV_Increment()</c>'s first increment SETs
    /// <c>TPMA_NV_WRITTEN</c> (Part 1, clause 35.2.6.3) and so changes the very Name the caller hashed, which is
    /// why every arm resuming here declares its <c>TpmComputeNvIndexNameAction</c> before applying any state
    /// change of its own.
    /// </para>
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="computed">The effect's result carrying the computed Index Name and the request to resume.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the command-HMAC verification.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnNvIndexNameComputed(TpmSimulatorState state, TpmNvIndexNameComputed computed)
    {
        //The computed Name is the cpHash Name term the command HMAC is verified against, and that verification
        //runs in an effect after this transition returns, so the carrier is TRANSFERRED onto the request being
        //resumed rather than released here; the request owns it for the rest of the command and every terminal
        //path releases it through that record.

        //TPM2_NV_ChangeAuth() shares the Name computation but nothing after it: its cpHash has a single
        //handle (no Name1/Name2 pair, no owner arm) and its authValue term is decided by the authorizing
        //policy session's own assertions rather than by HMAC-session bind-omission, so it takes its own
        //continuation instead of being folded into the five USER-role arms' shared body below.
        if(computed.Resume is TpmNvChangeAuthOverSessionRequested changeAuth)
        {
            return ContinueNvChangeAuthNameComputed(state, computed.Name, changeAuth);
        }

        //TPM2_NV_Certify() likewise shares only the Name computation. Its cpHash carries THREE Names — the
        //signing key's, the authorizing entity's, and the Index's (Part 3, clause 31.16.2, Table 254's handle
        //order; Part 1, clause 16.7 equation 15) — and its authorizing session sits at index 1 rather than
        //index 0, so neither the Name1/Name2 pair nor the SessionIndex: 0 encoding of the shared body below
        //fits it; it takes its own continuation the way TPM2_NV_ChangeAuth() does.
        if(computed.Resume is TpmNvCertifyOverSessionRequested certify)
        {
            return ContinueNvCertifyNameComputed(state, computed.Name, certify);
        }

        //The authorizing handle rides this shared body as its raw value because the four commands declare it
        //under different interface types — TPMI_RH_NV_AUTH for NV_Read, NV_Write, and NV_Increment (Part 3,
        //Tables 248, 236, and 238) but TPMI_RH_PROVISION for NV_UndefineSpace (Table 230) — and all the body
        //needs of it is the owner-arm comparison and the four Name octets it folds into cpHash. The Index
        //handle diverges the same way — TPMI_RH_NV_INDEX for the three, TPMI_RH_NV_DEFINED_INDEX for
        //NV_UndefineSpace (Table 230) — and rides as the wider of the two, which is also the interface type
        //the durable NV state below is keyed by.
        (uint authHandle, TpmiRhNvIndex nvIndex, TpmiShAuthSession authorizingSessionHandle, Tpm2bNonce nonceCaller, TpmaSession sessionAttributes, Tpm2bAuth hmac, TpmParameterArea rawParameterArea, TpmCcConstants commandCode) resolved;
        try
        {
            resolved = computed.Resume switch
            {
                TpmNvReadOverSessionRequested r => (r.AuthHandle.Value, r.NvIndex, r.AuthorizingSessionHandle, r.NonceCaller, r.SessionAttributes, r.Hmac, r.RawParameterArea, TpmCcConstants.TPM_CC_NV_Read),
                TpmNvWriteOverSessionRequested w => (w.AuthHandle.Value, w.NvIndex, w.AuthorizingSessionHandle, w.NonceCaller, w.SessionAttributes, w.Hmac, w.RawParameterArea, TpmCcConstants.TPM_CC_NV_Write),
                TpmNvUndefineSpaceOverSessionRequested u => (u.AuthHandle.Value, TpmiRhNvIndex.FromValue(u.NvIndex.Value), u.AuthorizingSessionHandle, u.NonceCaller, u.SessionAttributes, u.Hmac, u.RawParameterArea, TpmCcConstants.TPM_CC_NV_UndefineSpace),
                TpmNvIncrementOverSessionRequested i => (i.AuthHandle.Value, i.NvIndex, i.AuthorizingSessionHandle, i.NonceCaller, i.SessionAttributes, i.Hmac, i.RawParameterArea, TpmCcConstants.TPM_CC_NV_Increment),
                _ => throw new System.InvalidOperationException($"No NV Index Name-computed resume is defined for '{computed.Resume.GetType().Name}'.")
            };
        }
        catch
        {
            //Nothing downstream can adopt the Name once the resume shape is unrecognized, so this frame is
            //its last owner.
            computed.Name.Dispose();
            throw;
        }

        (uint authHandle, TpmiRhNvIndex nvIndex, TpmiShAuthSession authorizingSessionHandle, Tpm2bNonce nonceCaller, TpmaSession sessionAttributes, Tpm2bAuth hmac, TpmParameterArea rawParameterArea, TpmCcConstants commandCode) = resolved;

        bool isOwnerArm = authHandle == (uint)TpmRh.TPM_RH_OWNER;

        //Trailing zeros are removed from an authValue where it is used in an authorization computation
        //(TPM 2.0 Library Part 1, clause 17.6.5's authValue term note, and clause 17.6.4.3: "Trailing
        //octets of zero are to be removed from any string before it is used as an authValue") — the fold
        //below and the HMAC primitive each take the stripped view of the borrowed carrier, the same
        //stripping the Unseal arm applies to a sealed object's userAuth, and the same the reference
        //applies unconditionally through EntityGetAuthValue on both the command and response HMAC keys.
        Tpm2bAuth entityAuthValue = isOwnerArm ? state.OwnerAuth : state.NvIndexes[nvIndex].AuthValue;

        //Name1/Name2 per the digest's Table 6 reading: the owner arm's Name1 is the owner's raw 4-octet
        //handle, the Index arm's is the Index's own computed Name, and Name2 is that computed Name either way.
        TpmCommandHandleNames handleNames = TpmCommandHandleNames.Of(
            isOwnerArm ? TpmHandleName.FromHandle(authHandle) : TpmHandleName.FromName(computed.Name),
            TpmHandleName.FromName(computed.Name));

        //Equation 22 (Part 1, clause 17.6.10)'s omission: the authorizing entity's authValue drops out of the HMAC key when the session
        //is bound to that same entity, because binding already folded it into the session key. The recorded
        //bound-entity value is recomputed from the entity's Name and its LIVE authValue (Part 4,
        //IsSessionBindEntity), so a rotated authValue or a same-Name squatter ends the binding — and for an
        //NV Index this model records the bind-form Name as the Index's raw 4-octet handle
        //(TryResolveBindEntity's documented approximation), never the computed nameAlg ‖ H(TPMS_NV_PUBLIC)
        //form Name1 carries here. Recomputing only over Name1 would therefore never match on the Index arm,
        //folding an authValue a spec-correct client legitimately omitted and answering an authorization
        //failure that also charges the TPM-wide dictionary-attack counter for an honest command. Both forms
        //of the same entity's Name are recomputed and accepted, so the omission fires exactly when the
        //session is bound to the entity now authorizing.
        HmacSessionState session = state.HmacSessions[TpmiShHmac.FromValue(authorizingSessionHandle.Value)];
        ReadOnlySpan<byte> strippedEntityAuthValue = StripTrailingZeros(entityAuthValue.AsReadOnlySpan());
        bool bindOmits = (!isOwnerArm && session.BoundEntity.Matches(computed.Name.Span, strippedEntityAuthValue))
            || MatchesHandleFormBoundEntity(session.BoundEntity, authHandle, strippedEntityAuthValue);
        Tpm2bAuth authValueForHmac = bindOmits ? Tpm2bAuth.Empty : entityAuthValue;

        //Part 1, clause 17.8.7's OR, both disjuncts: the entity being authorized (the Index arm's Index; the
        //owner arm's hierarchy is DA-exempt per clause 17.8.1) and the entity the session was BOUND to. Either
        //alone is enough for a mismatch to charge the failure counter.
        bool isDaProtected = (!isOwnerArm && state.NvIndexes[nvIndex].IsDaProtected) || session.IsBoundEntityDaProtected;

        var pending = new TpmPendingSessionVerification(
            SessionHandle: TpmiShAuthSession.FromValue(session.Handle.Value), SessionIndex: 0, SessionAlg: session.SessionAlg, SessionKey: session.SessionKey,
            AuthValue: authValueForHmac, IsDaProtected: isDaProtected, NonceCaller: nonceCaller, NonceTpm: session.NonceTpm,
            FoldedNonceDecrypt: Tpm2bNonce.Empty, FoldedNonceEncrypt: Tpm2bNonce.Empty, SessionAttributes: sessionAttributes, SuppliedHmac: hmac,
            IsLockoutEntity: session.IsBoundToLockout);

        //The Name carrier transfers here: the resumed request becomes its owner for the rest of the command.
        TpmSimulatorInput resolvedResume = computed.Resume switch
        {
            TpmNvReadOverSessionRequested r => r with { ResolvedAuthValue = authValueForHmac, ResolvedIndexName = computed.Name },
            TpmNvWriteOverSessionRequested w => w with { ResolvedAuthValue = authValueForHmac, ResolvedIndexName = computed.Name },
            TpmNvUndefineSpaceOverSessionRequested u => u with { ResolvedAuthValue = authValueForHmac, ResolvedIndexName = computed.Name },
            TpmNvIncrementOverSessionRequested i => i with { ResolvedAuthValue = authValueForHmac, ResolvedIndexName = computed.Name },
            _ => computed.Resume
        };

        return Transition(
            state with
            {
                NextAction = new TpmVerifyCommandHmacAction(commandCode, handleNames, rawParameterArea, pending, ImmutableArray<TpmPendingSessionVerification>.Empty, resolvedResume),
                ResponseIntent = null
            },
            "Nv:OverSession:HmacVerifyRequested");
    }

    /// <summary>
    /// Rolls the authorizing HMAC session's nonceTPM and frames a session-authorized command's response once the
    /// effect has computed it (TPM 2.0 Library Part 1, clause 16.6.1) — the counterpart of
    /// <c>OnPolicySecretSessionResponseFramed</c>, simpler because the five USER-role NV arms and the four
    /// parameter-free hierarchy and provisioning commands it serves each carry exactly one authorizing HMAC
    /// session. The two authValue rotations, whose area may carry a second (decrypt) session, frame through
    /// <c>OnNvChangeAuthResponseFramed</c> instead.
    /// </summary>
    /// <param name="state">The state to transition from.</param>
    /// <param name="framed">The effect's result carrying the rolled nonceTPM and the framed response parameter area and HMAC.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> carrying the framed session-authorized response.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnNvSessionResponseFramed(TpmSimulatorState state, TpmNvSessionResponseFramed framed)
    {
        ImmutableDictionary<TpmiShHmac, HmacSessionState> hmacSessions = RollHmacSessionNonce(state.HmacSessions, framed.SessionHandle, framed.RetainedNonceTpm);

        return Transition(
            state with
            {
                NextAction = NullAction.Instance,
                HmacSessions = hmacSessions,
                ResponseIntent = new TpmNvSessionResponse(
                    TpmRcConstants.TPM_RC_SUCCESS, framed.ParameterArea, framed.NewNonceTpm,
                    framed.SessionAttributes, framed.Hmac)
            },
            "Nv:OverSession:ResponseCompleted");
    }

    /// <summary>
    /// Registers a genuine session command-HMAC mismatch against an NV Index-authorizing session and rejects
    /// with the matching, session-index-encoded response code — the NV-family specialization of
    /// <c>RejectSessionAuthFailure</c> for the three arms among the session-authorized NV commands whose entity
    /// can be a PIN Index: <c>TPM2_NV_Read()</c>'s Index arm, <c>TPM2_NV_Certify()</c>'s Index arm, and
    /// <c>TPM2_NV_ChangeAuth()</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A genuine PIN Index mismatch must still throttle pinCount (TPM 2.0 Library Part 1, clause 35.2.6.6: "If
    /// the authorization fails, pinCount is incremented for a PIN Fail Index and left unchanged for a PIN Pass
    /// Index") even though <c>OnCommandHmacVerified</c>'s generic dispatcher never reaches
    /// <c>ContinueNvReadOverSession</c> on a mismatch (it short-circuits to rejection before ever consulting
    /// <c>NextRequest</c>) — so this is the one point that update can still land, mirroring where the password
    /// arm applies the identical update, just fed by this async outcome instead of a synchronous compare. Every
    /// other session-authorized NV request (the owner arm of Read/Write/DefineSpace/UndefineSpace) has no such
    /// per-entity counter, so it falls straight through to the generic rejection unchanged.
    /// </para>
    /// <para>
    /// <c>TPM2_NV_ChangeAuth()</c>'s update is conditional on two things. First, on the authorizing policy having
    /// asserted <c>TPM2_PolicyAuthValue()</c>, because only then did the Index's own authValue key the command
    /// HMAC at all (Part 1, clause 17.6.5's policy Note): a rotation authorized by a policy that folds no
    /// authValue proves nothing about the current PIN, so it must neither burn a retry on failure nor clear the
    /// throttle on success. That conditionality is what makes rotation under a <c>PolicyAuthValue</c>-carrying
    /// policy behave the way a PIN change is expected to: a wrong old PIN costs a retry, a right one is rewarded.
    /// Second, on the FAILING session being the one that authorized the Index (index 0): this command's area may
    /// also carry a decrypt session, whose own command-HMAC failure says nothing about whether the caller knew
    /// the PIN and so must not consume a retry.
    /// </para>
    /// </remarks>
    /// <param name="state">The state to reject from.</param>
    /// <param name="verified">The effect's result carrying the mismatch outcome and the original request.</param>
    /// <returns>The rejection <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> RejectNvSessionAuthFailure(TpmSimulatorState state, TpmCommandHmacVerified verified)
    {
        if(verified.NextRequest is TpmNvReadOverSessionRequested nvRead && nvRead.AuthHandle.Value == nvRead.NvIndex.Value
            && state.NvIndexes.TryGetValue(nvRead.NvIndex, out NvIndexState? index) && index.IsPinIndex)
        {
            NvIndexState updated = ApplyPinAuthOutcome(index, authMatched: false);
            state = state with { NvIndexes = state.NvIndexes.SetItem(updated.NvIndex, updated) };
        }

        //TPM2_NV_Certify()'s Index arm throttles the same way TPM2_NV_Read()'s does — both consume the Index's own
        //authValue for a READ-role use (Part 1, clause 35.2.5) — but its authorizing session is index 1, not 0:
        //the sign slot occupies index 0 and its failure, were one ever evaluated, would say nothing about whether
        //the caller knew the Index's PIN.
        if(verified.NextRequest is TpmNvCertifyOverSessionRequested nvCertify
            && verified.SessionIndex == 1
            && nvCertify.AuthHandle.Value == nvCertify.NvIndex.Value
            && state.NvIndexes.TryGetValue(nvCertify.NvIndex, out NvIndexState? certifiedIndex) && certifiedIndex.IsPinIndex)
        {
            NvIndexState updated = ApplyPinAuthOutcome(certifiedIndex, authMatched: false);
            state = state with { NvIndexes = state.NvIndexes.SetItem(updated.NvIndex, updated) };
        }

        if(verified.NextRequest is TpmNvChangeAuthOverSessionRequested nvChangeAuth
            && verified.SessionIndex == 0
            && IsNvChangeAuthValueFolded(state, nvChangeAuth)
            && state.NvIndexes.TryGetValue(nvChangeAuth.NvIndex, out NvIndexState? rotatingIndex) && rotatingIndex.IsPinIndex)
        {
            NvIndexState updated = ApplyPinAuthOutcome(rotatingIndex, authMatched: false);
            state = state with { NvIndexes = state.NvIndexes.SetItem(updated.NvIndex, updated) };
        }

        return RejectSessionAuthFailure(state, verified.CommandCode, verified.SessionIndex, verified.IsDaProtected, verified.IsLockoutEntity);
    }

    /// <summary>
    /// Whether a <c>TPM2_NV_ChangeAuth()</c> request's authorizing policy session folds the Index's own authValue
    /// into the authorization computation — true exactly when that session asserted
    /// <c>TPM2_PolicyAuthValue()</c> (TPM 2.0 Library Part 1, clause 17.6.5's Note: "For policy sessions, the
    /// authValue is not included in the HMAC calculation unless the policy session include
    /// TPM2_PolicyAuthValue()").
    /// </summary>
    /// <remarks>
    /// This one predicate decides four coupled behaviours, which is why it is asked in one place rather than
    /// re-derived at each: whether the PIN at-limit gate applies before the HMAC, whether the dictionary-attack
    /// counter is in play, whether the command HMAC key carries the OLD authValue, and whether the PIN throttle
    /// moves on the outcome. A handle that resolves to no live session (one flushed between command stages)
    /// answers <see langword="false"/>, the conservative direction: no counter moves for an authorization that
    /// cannot be attributed to a session still in the table.
    /// </remarks>
    /// <param name="state">The current simulator state.</param>
    /// <param name="request">The parsed <c>TPM2_NV_ChangeAuth()</c> request.</param>
    /// <returns><see langword="true"/> when the Index's current authValue participates in this command's authorization.</returns>
    private static bool IsNvChangeAuthValueFolded(TpmSimulatorState state, TpmNvChangeAuthOverSessionRequested request) =>
        state.PolicySessions.TryGetValue(TpmiShPolicy.FromValue(request.AuthorizingSessionHandle.Value), out PolicySessionState? session) && session.IsAuthValueNeeded;

    /// <summary>
    /// Persists a loaded transient object to a persistent handle, or evicts a persistent object addressed by
    /// that handle, for <c>TPM2_EvictControl()</c> (Part 3, clause 28.5).
    /// </summary>
    /// <remarks>
    /// The handle area resolves first (Part 3, clause 5.4): @auth must be a provisioning hierarchy
    /// (<c>TPMI_RH_PROVISION</c>, else <c>TPM_RC_VALUE</c>) whose enable is SET (else <c>TPM_RC_HIERARCHY</c> —
    /// a disabled hierarchy's authValue can authorize nothing, Part 1, clause 11.2), and objectHandle must name
    /// a loaded transient object or an existing persistent one (else <c>TPM_RC_HANDLE</c>). The supplied
    /// password is then verified against the named hierarchy's retained authorization value (clause 5.6).
    /// Persisting copies the object (the transient stays loaded), evicting removes it; the persistent handle
    /// must be in the <c>TPM_HT_PERSISTENT</c> range (MSO 0x81), a parameter check that follows authorization.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_EvictControl()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnEvictControl(TpmSimulatorState state, TpmEvictControlRequested request)
    {
        //@auth must name a provisioning hierarchy (TPMI_RH_PROVISION: owner or platform, Part 2, clause 9.21)
        //— checked before the authorization ladder so no other permanent handle (the lockout hierarchy's
        //one-strike path included) is reachable through this command.
        if(request.AuthHandle.Value != (uint)TpmRh.TPM_RH_OWNER && request.AuthHandle.Value != (uint)TpmRh.TPM_RH_PLATFORM)
        {
            return Reject(state, TpmCcConstants.TPM_CC_EvictControl, TpmRcConstants.TPM_RC_VALUE, request);
        }

        //The authorizing hierarchy's availability is a handle-area outcome on @auth, resolved before the next
        //handle's presence (Part 3, clause 5.4): while its enable is CLEAR the hierarchy's authValue can
        //authorize nothing (Part 1, clause 11.2).
        if(!state.IsHierarchyEnabled(request.AuthHandle.Value))
        {
            return Reject(state, TpmCcConstants.TPM_CC_EvictControl, TpmRcConstants.TPM_RC_HIERARCHY, request);
        }

        //Handle-area presence validation precedes the authorization checks (Part 3, clauses 5.4 and 5.6):
        //objectHandle must name a loaded transient object (the persist arm) or an existing persistent one (the
        //evict arm) before the supplied password is ever compared.
        bool isTransient = state.TransientObjects.TryGetValue(request.ObjectHandle, out TransientKeyState? transient);
        TransientKeyState? persistent = null;
        if(!isTransient && !state.PersistentObjects.TryGetValue(TpmiDhPersistent.FromValue(request.ObjectHandle.Value), out persistent))
        {
            return Reject(state, TpmCcConstants.TPM_CC_EvictControl, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        //The supplied password must authorize the named provisioning hierarchy (Part 3, clause 5.6). A
        //provisioning hierarchy's authValue is never dictionary-attack protected (Part 1, clause 17.8.1), so a
        //mismatch is an uncharged TPM_RC_BAD_AUTH.
        (TpmRcConstants? authError, TpmSimulatorState authorized) = VerifyHierarchyAuthorization(state, request.AuthHandle.Value, request.SuppliedAuthPassword.AsReadOnlyMemory());
        if(authError is TpmRcConstants authRc)
        {
            return Reject(authorized, TpmCcConstants.TPM_CC_EvictControl, authRc, request);
        }

        //Persist: the object is a loaded transient object, copied to the persistent handle under its new
        //handle. Persisting is a genuine COPY (the transient stays loaded, and a real TPM's persist writes a
        //second, NV-resident instance), so the persistent entry must own a deep-copied private-key carrier —
        //two dictionary entries must never co-own a buffer, or whichever is evicted first would free memory
        //the survivor still signs with. The copy needs a pool rental, so it runs as an effect
        //(TpmPersistObjectAction) and OnObjectPersisted installs the result.
        if(isTransient)
        {
            if((request.PersistentHandle.Value >> 24) != (TpmSimulatorState.PersistentHandleBase >> 24))
            {
                return Reject(authorized, TpmCcConstants.TPM_CC_EvictControl, TpmRcConstants.TPM_RC_VALUE, request);
            }

            //The transition is the password carrier's terminal owner — the hierarchy compare was its only use.
            request.SuppliedAuthPassword.Dispose();

            return Transition(
                authorized with
                {
                    NextAction = new TpmPersistObjectAction(transient!, request.PersistentHandle),
                    ResponseIntent = null
                },
                "EvictControl:PersistRequested");
        }

        //Evict: the object handle is itself an existing persistent object, and evicting is its
        //ownership-end boundary — its own deep-copied carrier is released before the dictionary drops the
        //last live reference (the still-loaded transient original, if any, owns a separate carrier).
        persistent!.Dispose();
        request.SuppliedAuthPassword.Dispose();

        return Transition(
            authorized with
            {
                PersistentObjects = authorized.PersistentObjects.Remove(TpmiDhPersistent.FromValue(request.ObjectHandle.Value)),
                ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
            },
            "EvictControl:Evict");
    }

    /// <summary>
    /// Installs the deep-copied persistent object <see cref="TpmPersistObjectAction"/>'s effect produced —
    /// <c>TPM2_EvictControl()</c>'s persist arm's completion (TPM 2.0 Library Part 3, clause 28.5).
    /// </summary>
    /// <remarks>
    /// A persistent entry already at the handle is replaced and its owned carrier released — the same
    /// dispose-the-superseded discipline every rotation site applies.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="persisted">The effect's result carrying the persistent copy, whose ownership transfers to the dictionary here.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnObjectPersisted(TpmSimulatorState state, TpmObjectPersisted persisted)
    {
        if(state.PersistentObjects.TryGetValue(TpmiDhPersistent.FromValue(persisted.PersistentCopy.Handle.Value), out TransientKeyState? superseded))
        {
            superseded.Dispose();
        }

        return Transition(
            state with
            {
                NextAction = NullAction.Instance,
                PersistentObjects = state.PersistentObjects.SetItem(TpmiDhPersistent.FromValue(persisted.PersistentCopy.Handle.Value), persisted.PersistentCopy),
                ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
            },
            "EvictControl:Persisted");
    }

    /// <summary>
    /// Checks that a <c>TPM2_CreatePrimary()</c> request names a hierarchy that can hold a primary object and
    /// that the hierarchy is currently enabled — the two conditions every one of that command's template arms
    /// shares (TPM 2.0 Library Part 2, clause 9.20's <c>TPMI_RH_HIERARCHY</c>; Part 1, clause 11.2).
    /// </summary>
    /// <remarks>
    /// A handle outside the interface type's value set is that type's own unmarshal failure,
    /// <c>TPM_RC_VALUE</c>; a handle inside it whose enable is CLEAR is <c>TPM_RC_HIERARCHY</c>, because while an
    /// enable is FALSE neither the hierarchy's authValue nor its authPolicy can authorize anything and no object
    /// may be created under it. The null hierarchy has no enable and is always available, which is what keeps it
    /// usable as the temporary-object parent it exists to be.
    /// </remarks>
    /// <param name="state">The state the availability is evaluated against.</param>
    /// <param name="hierarchy">The requested primary handle.</param>
    /// <returns>The refusal, or <see langword="null"/> when a primary may be created under that hierarchy.</returns>
    private static TpmRcConstants? ValidatePrimaryHierarchy(TpmSimulatorState state, uint hierarchy)
    {
        if(!TpmSimulatorState.IsPrimaryHierarchyHandle(hierarchy))
        {
            return TpmRcConstants.TPM_RC_VALUE;
        }

        return state.IsHierarchyEnabled(hierarchy)
            ? null
            : TpmRcConstants.TPM_RC_HIERARCHY;
    }

    /// <summary>
    /// Dispatches <c>TPM2_CreatePrimary()</c>, which needs an effect: the pure transition cannot generate a key,
    /// so it allocates the transient handle, declares a <c>TpmCreateEccKeyAction</c> carrying the template
    /// fields the effect needs, and leaves no response yet.
    /// </summary>
    /// <remarks>
    /// The effectful loop draws the key from the injected backend, builds the exported public area and the
    /// durable key state, and feeds them back as a <c>TpmPrimaryKeyCreated</c> input.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_CreatePrimary()</c> request for an ECC key.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the key-creation action.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnCreatePrimary(TpmSimulatorState state, TpmCreatePrimaryRequested request)
    {
        //The handle area is resolved before the command body on a real TPM (Part 3, clause 5.4), so the
        //hierarchy's admissibility and availability are settled ahead of the template checks.
        if(ValidatePrimaryHierarchy(state, request.Hierarchy.Value) is TpmRcConstants hierarchyRc)
        {
            return Reject(state, TpmCcConstants.TPM_CC_CreatePrimary, hierarchyRc, request);
        }

        //Handle-area authorization follows the hierarchy's admissibility (Part 3, clause 5.6): the supplied
        //password must authorize the named hierarchy. The null hierarchy has no authValue slot — its
        //authorization value is structurally empty (Part 2, clause 7.4), so a non-empty supplied password is
        //an uncharged TPM_RC_BAD_AUTH — while the other three hierarchies ride the shared ladder, whose
        //mismatch is likewise uncharged (a permanent entity's authValue other than lockoutAuth is never
        //dictionary-attack protected, Part 1, clause 17.8.1).
        if(request.Hierarchy.Value == (uint)TpmRh.TPM_RH_NULL)
        {
            if(StripTrailingZeros(request.SuppliedHierarchyPassword.AsReadOnlySpan()).Length != 0)
            {
                return Reject(state, TpmCcConstants.TPM_CC_CreatePrimary, TpmRcConstants.TPM_RC_BAD_AUTH, request);
            }
        }
        else
        {
            (TpmRcConstants? authError, TpmSimulatorState authorized) = VerifyHierarchyAuthorization(state, request.Hierarchy.Value, request.SuppliedHierarchyPassword.AsReadOnlyMemory());
            if(authError is TpmRcConstants authRc)
            {
                return Reject(authorized, TpmCcConstants.TPM_CC_CreatePrimary, authRc, request);
            }

            state = authorized;
        }

        //An unsupported nameAlg cannot be computed (TpmObjectName), so it is rejected up front rather than
        //defaulted (TPM 2.0 Library Part 3, CreatePrimary error conditions: an unsupported hash is TPM_RC_HASH).
        if(!IsSupportedNameAlg(request.NameAlg))
        {
            return Reject(state, TpmCcConstants.TPM_CC_CreatePrimary, TpmRcConstants.TPM_RC_HASH, request);
        }

        //An authValue "should not be larger than the digest size of the algorithm used to compute the Name of
        //the object" (Part 1, clause 17.6.4.2); enforced on inSensitive.userAuth's supplied size with
        //TPM_RC_SIZE before any trailing-zero stripping, exactly as TPM2_Create does, which also keeps the
        //retained authValue inside the bound-entity fold's fixed width (SessionBoundEntity) once this object
        //binds a session.
        if(request.UserAuth.Length > TpmPolicyDigest.Size(request.NameAlg.Value))
        {
            return Reject(state, TpmCcConstants.TPM_CC_CreatePrimary, TpmRcConstants.TPM_RC_SIZE, request);
        }

        //The transition is the password carrier's terminal owner — the hierarchy compare was its only use —
        //while the policy digest and UserAuth transfer into the create action, whose effect installs them on the
        //durable key state.
        request.SuppliedHierarchyPassword.Dispose();

        uint handle = state.NextObjectHandle;

        return Transition(
            state with
            {
                NextObjectHandle = state.NextObjectHandle + 1,
                NextAction = new TpmCreateEccKeyAction(TpmiDhObject.FromValue(handle), request.Hierarchy, request.NameAlg, request.Attributes, request.Curve, request.SchemeHashAlg, request.AuthPolicy, request.UserAuth),
                ResponseIntent = null
            },
            "CreatePrimary:Requested");
    }

    /// <summary>
    /// The RSA counterpart of <see cref="OnCreatePrimary"/>: allocates the transient handle and declares a
    /// <c>TpmCreateRsaKeyAction</c> so the effectful loop generates the RSA key, builds the exported public area
    /// carrying the modulus, and feeds it back as the same <c>TpmPrimaryKeyCreated</c> input the ECC path uses.
    /// </summary>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_CreatePrimary()</c> request for an RSA key.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the key-creation action.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnCreateRsaPrimary(TpmSimulatorState state, TpmCreateRsaPrimaryRequested request)
    {
        if(ValidatePrimaryHierarchy(state, request.Hierarchy.Value) is TpmRcConstants hierarchyRc)
        {
            return Reject(state, TpmCcConstants.TPM_CC_CreatePrimary, hierarchyRc, request);
        }

        //Handle-area authorization follows the hierarchy's admissibility (Part 3, clause 5.6) — the
        //OnCreatePrimary arm's shape: the null hierarchy's authorization value is structurally empty (Part 2,
        //clause 7.4) and the other three ride the shared ladder, every mismatch an uncharged TPM_RC_BAD_AUTH
        //(Part 1, clause 17.8.1).
        if(request.Hierarchy.Value == (uint)TpmRh.TPM_RH_NULL)
        {
            if(StripTrailingZeros(request.SuppliedHierarchyPassword.AsReadOnlySpan()).Length != 0)
            {
                return Reject(state, TpmCcConstants.TPM_CC_CreatePrimary, TpmRcConstants.TPM_RC_BAD_AUTH, request);
            }
        }
        else
        {
            (TpmRcConstants? authError, TpmSimulatorState authorized) = VerifyHierarchyAuthorization(state, request.Hierarchy.Value, request.SuppliedHierarchyPassword.AsReadOnlyMemory());
            if(authError is TpmRcConstants authRc)
            {
                return Reject(authorized, TpmCcConstants.TPM_CC_CreatePrimary, authRc, request);
            }

            state = authorized;
        }

        if(!IsSupportedNameAlg(request.NameAlg))
        {
            return Reject(state, TpmCcConstants.TPM_CC_CreatePrimary, TpmRcConstants.TPM_RC_HASH, request);
        }

        //An authValue "should not be larger than the digest size of the algorithm used to compute the Name of
        //the object" (Part 1, clause 17.6.4.2); enforced on inSensitive.userAuth's supplied size with
        //TPM_RC_SIZE before any trailing-zero stripping, exactly as TPM2_Create does, which also keeps the
        //retained authValue inside the bound-entity fold's fixed width (SessionBoundEntity) once this object
        //binds a session.
        if(request.UserAuth.Length > TpmPolicyDigest.Size(request.NameAlg.Value))
        {
            return Reject(state, TpmCcConstants.TPM_CC_CreatePrimary, TpmRcConstants.TPM_RC_SIZE, request);
        }

        //The transition is the password carrier's terminal owner — the hierarchy compare was its only use —
        //while the policy digest and UserAuth transfer into the create action, whose effect installs them on the
        //durable key state.
        request.SuppliedHierarchyPassword.Dispose();

        uint handle = state.NextObjectHandle;

        return Transition(
            state with
            {
                NextObjectHandle = state.NextObjectHandle + 1,
                NextAction = new TpmCreateRsaKeyAction(TpmiDhObject.FromValue(handle), request.Hierarchy, request.NameAlg, request.Attributes, request.KeyBits, request.Scheme, request.AuthPolicy, request.UserAuth),
                ResponseIntent = null
            },
            "CreatePrimary:Requested");
    }

    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnPrimaryKeyCreated(TpmSimulatorState state, TpmPrimaryKeyCreated created) =>
        Transition(
            state with
            {
                NextAction = NullAction.Instance,
                TransientObjects = state.TransientObjects.SetItem(created.KeyState.Handle, created.KeyState),
                ResponseIntent = new TpmCreatePrimaryResponse(
                    TpmRcConstants.TPM_RC_SUCCESS, created.KeyState.Handle, created.OutPublic, created.CreationData, created.CreationHash, created.CreationTicket, created.Name)
            },
            "CreatePrimary:Completed");

    /// <summary>
    /// Resolves the key handle for <c>TPM2_Sign()</c>, then declares the signing action matching the key's
    /// algorithm so the effectful loop signs the digest with the retained key through the injected backend;
    /// <c>OnMessageSigned</c> frames the result.
    /// </summary>
    /// <remarks>
    /// The signing scheme comes from the command (an unrestricted key signs under the caller's scheme).
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_Sign()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the signing action.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnSign(TpmSimulatorState state, TpmSignRequested request)
    {
        //The key must be a loaded transient object (Part 3, clause 20.2). The scheme/curve compatibility a TPM
        //also checks arrives with richer key models.
        if(!state.TransientObjects.TryGetValue(request.KeyHandle, out TransientKeyState? key))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Sign, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        //DA/Lockout for the key precedes the compare (Part 3, clause 5.6, check 3) — a locked-out TPM never
        //signs with a DA-protected key.
        if(key.IsDaProtected && state.IsInLockout)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Sign, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        //USER role gate (Part 3, clause 5.6, check 7.1): a key whose userWithAuth attribute is CLEAR may have
        //its USER role authorized only by a policy session, never by a password — the session-shape gate
        //precedes the credential compare (checks 9/10) in clause 5.6's mandatory order, so the refusal is
        //uncharged and the key's authValue is never tested.
        if((key.Attributes & TpmaObject.USER_WITH_AUTH) == 0)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Sign, TpmRcConstants.TPM_RC_POLICY_FAIL, request);
        }

        //The key slot's USER-role authorization (Part 3, clause 20.2: @keyHandle, Auth Index 1, Auth Role
        //USER): the supplied password is compared against the key's retained authValue, both sides
        //trailing-zero-stripped (Part 1, clause 17.6.4.3), in fixed time — the OnCreateSealedObject discipline.
        ReadOnlySpan<byte> suppliedStripped = StripTrailingZeros(request.SuppliedKeyPassword.AsReadOnlySpan());
        ReadOnlySpan<byte> keyAuthStripped = StripTrailingZeros(key.AuthValue.AsReadOnlySpan());

        if(!CryptographicOperations.FixedTimeEquals(suppliedStripped, keyAuthStripped))
        {
            return RejectSessionAuthFailure(state, TpmCcConstants.TPM_CC_Sign, sessionIndex: 0, key.IsDaProtected, request);
        }

        //The transition is the password carrier's terminal owner — the key-slot compare was its only use.
        request.SuppliedKeyPassword.Dispose();

        TpmAction action = key.KeyType.Value == TpmAlgIdConstants.TPM_ALG_RSA
            ? new TpmRsaSignAction(key.PrivateKey, request.Digest, request.SignatureScheme, request.SchemeHashAlg)
            : new TpmEccSignAction(key.PrivateKey, request.Digest, key.Curve, request.SchemeHashAlg);

        return Transition(
            state with
            {
                NextAction = action,
                ResponseIntent = null
            },
            "Sign:Requested");
    }

    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnMessageSigned(TpmSimulatorState state, TpmMessageSigned signed) =>
        Transition(
            state with
            {
                NextAction = NullAction.Instance,
                ResponseIntent = new TpmSignResponse(TpmRcConstants.TPM_RC_SUCCESS, signed.Signature)
            },
            "Sign:Completed");

    /// <summary>
    /// Dispatches <c>TPM2_CreatePrimary()</c> for an ECC storage parent, which needs an effect: the pure
    /// transition cannot generate a key, so it allocates the transient handle and declares a
    /// <c>TpmCreateStorageParentAction</c> carrying the storage template fields.
    /// </summary>
    /// <remarks>
    /// The effectful loop draws a real key from the injected backend and builds the exported storage public area
    /// carrying its actual public point plus the durable parent state — the simulator still does not wrap
    /// children under a parent key (a storage parent here is only ever used as a handle for
    /// <c>TPM2_Create()</c>), but the exported point is genuine, matching what an endorsement-key certificate
    /// would be issued over — and feeds them back as the same <c>TpmPrimaryKeyCreated</c> input the signing
    /// paths use.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_CreatePrimary()</c> request for an ECC storage parent.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the key-creation action.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnCreateStorageParent(TpmSimulatorState state, TpmCreateStorageParentRequested request)
    {
        if(ValidatePrimaryHierarchy(state, request.Hierarchy.Value) is TpmRcConstants hierarchyRc)
        {
            return Reject(state, TpmCcConstants.TPM_CC_CreatePrimary, hierarchyRc, request);
        }

        //Handle-area authorization follows the hierarchy's admissibility (Part 3, clause 5.6) — the
        //OnCreatePrimary arm's shape: the null hierarchy's authorization value is structurally empty (Part 2,
        //clause 7.4) and the other three ride the shared ladder, every mismatch an uncharged TPM_RC_BAD_AUTH
        //(Part 1, clause 17.8.1).
        if(request.Hierarchy.Value == (uint)TpmRh.TPM_RH_NULL)
        {
            if(StripTrailingZeros(request.SuppliedHierarchyPassword.AsReadOnlySpan()).Length != 0)
            {
                return Reject(state, TpmCcConstants.TPM_CC_CreatePrimary, TpmRcConstants.TPM_RC_BAD_AUTH, request);
            }
        }
        else
        {
            (TpmRcConstants? authError, TpmSimulatorState authorized) = VerifyHierarchyAuthorization(state, request.Hierarchy.Value, request.SuppliedHierarchyPassword.AsReadOnlyMemory());
            if(authError is TpmRcConstants authRc)
            {
                return Reject(authorized, TpmCcConstants.TPM_CC_CreatePrimary, authRc, request);
            }

            state = authorized;
        }

        if(!IsSupportedNameAlg(request.NameAlg))
        {
            return Reject(state, TpmCcConstants.TPM_CC_CreatePrimary, TpmRcConstants.TPM_RC_HASH, request);
        }

        //An authValue "should not be larger than the digest size of the algorithm used to compute the Name of
        //the object" (Part 1, clause 17.6.4.2); enforced on inSensitive.userAuth's supplied size with
        //TPM_RC_SIZE before any trailing-zero stripping, exactly as TPM2_Create does, which also keeps the
        //retained authValue inside the bound-entity fold's fixed width (SessionBoundEntity) once this object
        //binds a session.
        if(request.UserAuth.Length > TpmPolicyDigest.Size(request.NameAlg.Value))
        {
            return Reject(state, TpmCcConstants.TPM_CC_CreatePrimary, TpmRcConstants.TPM_RC_SIZE, request);
        }

        //The transition is the password carrier's terminal owner — the hierarchy compare was its only use —
        //while the policy digest and UserAuth transfer into the create action, whose effect installs them on the
        //durable key state.
        request.SuppliedHierarchyPassword.Dispose();

        uint handle = state.NextObjectHandle;

        return Transition(
            state with
            {
                NextObjectHandle = state.NextObjectHandle + 1,
                NextAction = new TpmCreateStorageParentAction(TpmiDhObject.FromValue(handle), request.Hierarchy, request.NameAlg, request.Attributes, request.Curve, request.NoDa, request.AuthPolicy, request.UserAuth),
                ResponseIntent = null
            },
            "CreatePrimary:Requested");
    }

    /// <summary>
    /// The RSA counterpart of <see cref="OnCreateStorageParent"/>: allocates the transient handle and declares a
    /// <c>TpmCreateRsaStorageParentAction</c> so the effectful loop generates the RSA key, builds the exported
    /// storage public area carrying the modulus, retains the modulus on the durable parent state, and feeds it
    /// back as the same <c>TpmPrimaryKeyCreated</c> input the other CreatePrimary paths use.
    /// </summary>
    /// <remarks>
    /// This is the path the standard RSA endorsement key (TCG EK Credential Profile, Annex B.3.3, Template L-1)
    /// rides.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_CreatePrimary()</c> request for an RSA storage parent.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the key-creation action.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnCreateRsaStorageParent(TpmSimulatorState state, TpmCreateRsaStorageParentRequested request)
    {
        if(ValidatePrimaryHierarchy(state, request.Hierarchy.Value) is TpmRcConstants hierarchyRc)
        {
            return Reject(state, TpmCcConstants.TPM_CC_CreatePrimary, hierarchyRc, request);
        }

        //Handle-area authorization follows the hierarchy's admissibility (Part 3, clause 5.6) — the
        //OnCreatePrimary arm's shape: the null hierarchy's authorization value is structurally empty (Part 2,
        //clause 7.4) and the other three ride the shared ladder, every mismatch an uncharged TPM_RC_BAD_AUTH
        //(Part 1, clause 17.8.1).
        if(request.Hierarchy.Value == (uint)TpmRh.TPM_RH_NULL)
        {
            if(StripTrailingZeros(request.SuppliedHierarchyPassword.AsReadOnlySpan()).Length != 0)
            {
                return Reject(state, TpmCcConstants.TPM_CC_CreatePrimary, TpmRcConstants.TPM_RC_BAD_AUTH, request);
            }
        }
        else
        {
            (TpmRcConstants? authError, TpmSimulatorState authorized) = VerifyHierarchyAuthorization(state, request.Hierarchy.Value, request.SuppliedHierarchyPassword.AsReadOnlyMemory());
            if(authError is TpmRcConstants authRc)
            {
                return Reject(authorized, TpmCcConstants.TPM_CC_CreatePrimary, authRc, request);
            }

            state = authorized;
        }

        if(!IsSupportedNameAlg(request.NameAlg))
        {
            return Reject(state, TpmCcConstants.TPM_CC_CreatePrimary, TpmRcConstants.TPM_RC_HASH, request);
        }

        //An authValue "should not be larger than the digest size of the algorithm used to compute the Name of
        //the object" (Part 1, clause 17.6.4.2); enforced on inSensitive.userAuth's supplied size with
        //TPM_RC_SIZE before any trailing-zero stripping, exactly as TPM2_Create does, which also keeps the
        //retained authValue inside the bound-entity fold's fixed width (SessionBoundEntity) once this object
        //binds a session.
        if(request.UserAuth.Length > TpmPolicyDigest.Size(request.NameAlg.Value))
        {
            return Reject(state, TpmCcConstants.TPM_CC_CreatePrimary, TpmRcConstants.TPM_RC_SIZE, request);
        }

        //The transition is the password carrier's terminal owner — the hierarchy compare was its only use —
        //while the policy digest and UserAuth transfer into the create action, whose effect installs them on the
        //durable key state.
        request.SuppliedHierarchyPassword.Dispose();

        uint handle = state.NextObjectHandle;

        return Transition(
            state with
            {
                NextObjectHandle = state.NextObjectHandle + 1,
                NextAction = new TpmCreateRsaStorageParentAction(TpmiDhObject.FromValue(handle), request.Hierarchy, request.NameAlg, request.Attributes, request.KeyBits, request.NoDa, request.AuthPolicy, request.UserAuth),
                ResponseIntent = null
            },
            "CreatePrimary:Requested");
    }

    /// <summary>
    /// Seals caller-supplied data into a KEYEDHASH object under a loaded storage parent for <c>TPM2_Create()</c>
    /// (Part 3, clause 12.1).
    /// </summary>
    /// <remarks>
    /// The parent must be a loaded restricted storage object; a missing handle is <c>TPM_RC_HANDLE</c> and a
    /// non-storage parent is <c>TPM_RC_TYPE</c>. DA/Lockout for the parent is checked before any further
    /// processing (Part 3, clause 5.6, check 3) — a locked-out TPM never performs the Create, matching
    /// <c>OnUnseal</c> and the over-sessions form's identical, unconditional gate. The parent slot's USER-role
    /// password (Part 3, clause 12.1: <c>@parentHandle</c>, Auth Index 1, Auth Role USER) is then compared
    /// against the parent's retained <see cref="TransientKeyState.AuthValue"/> — both sides
    /// trailing-zero-stripped (Part 1, clause 17.6.4.3), in fixed time, the <c>OnUnseal</c> discipline — and a
    /// mismatch registers through <c>RejectSessionAuthFailure</c>, releasing the request's owned carriers and
    /// charging failedTries when the parent is DA-protected. The seal needs an effect (the
    /// wrapped blob and the faithful by-products), so the transition declares a <c>TpmSealDataAction</c> and
    /// leaves no response yet; <c>OnObjectSealed</c> frames the result. The created object is not loaded, so no
    /// transient handle is allocated here.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_Create()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the seal action.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnCreateSealedObject(TpmSimulatorState state, TpmCreateSealedObjectRequested request)
    {
        if(!state.TransientObjects.TryGetValue(request.ParentHandle, out TransientKeyState? parent))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Create, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        if(!IsStorageParent(parent.Attributes))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Create, TpmRcConstants.TPM_RC_TYPE, request);
        }

        if(parent.IsDaProtected && state.IsInLockout)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Create, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        //USER role gate (Part 3, clause 5.6, check 7.1): a parent whose userWithAuth attribute is CLEAR may
        //have its USER role authorized only by a policy session, never by a password — refused before the
        //compare below, uncharged, per clause 5.6's mandatory check order. The standard endorsement-key
        //storage-parent templates carry exactly this shape (userWithAuth CLEAR, adminWithPolicy SET), so
        //child creation under them is policy-session-only by construction.
        if((parent.Attributes & TpmaObject.USER_WITH_AUTH) == 0)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Create, TpmRcConstants.TPM_RC_POLICY_FAIL, request);
        }

        //The parent slot's USER-role authorization (Part 3, clause 12.1: @parentHandle, Auth Index 1, Auth Role
        //USER): the supplied password is compared against the parent's retained authValue, both sides
        //trailing-zero-stripped (Part 1, clause 17.6.4.3), in fixed time — the OnUnseal discipline. The
        //reference enforces this slot generically before the command body ever runs, so the compare precedes
        //the template judgments below.
        ReadOnlySpan<byte> suppliedStripped = StripTrailingZeros(request.SuppliedParentPassword.AsReadOnlySpan());
        ReadOnlySpan<byte> parentAuthStripped = StripTrailingZeros(parent.AuthValue.AsReadOnlySpan());

        if(!CryptographicOperations.FixedTimeEquals(suppliedStripped, parentAuthStripped))
        {
            return RejectSessionAuthFailure(state, TpmCcConstants.TPM_CC_Create, sessionIndex: 0, parent.IsDaProtected, request);
        }

        if(!IsSupportedNameAlg(request.NameAlg))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Create, TpmRcConstants.TPM_RC_HASH, request);
        }

        //An authValue "should not be larger than the digest size of the algorithm used to compute the Name of
        //the object" (Part 1, clause 17.6.4.2); the reference's TPM2_Create enforces it on
        //inSensitive.userAuth's supplied size with TPM_RC_SIZE, before any trailing-zero stripping.
        if(request.UserAuth.Length > TpmPolicyDigest.Size(request.NameAlg.Value))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Create, TpmRcConstants.TPM_RC_SIZE, request);
        }

        //The transition is the password carrier's terminal owner — the parent-slot compare is its only use —
        //while SecretData/UserAuth transfer into the seal action, whose effect packs and releases them.
        request.SuppliedParentPassword.Dispose();

        return Transition(
            state with
            {
                NextAction = new TpmSealDataAction(request.ParentHandle, parent.Hierarchy, request.NameAlg, request.AuthPolicy, request.NoDa, request.UserWithAuth, request.SecretData, request.UserAuth),
                ResponseIntent = null
            },
            "Create:Requested");
    }

    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnObjectSealed(TpmSimulatorState state, TpmObjectSealed sealedObject) =>
        Transition(
            state with
            {
                NextAction = NullAction.Instance,
                ResponseIntent = new TpmCreateResponse(
                    TpmRcConstants.TPM_RC_SUCCESS, sealedObject.PrivateBlob, sealedObject.OutPublic, sealedObject.CreationData, sealedObject.CreationHash, sealedObject.CreationTicket)
            },
            "Create:Completed");

    /// <summary>
    /// Dispatches <c>TPM2_Create()</c> whose parent authorization is a bound HMAC session or <c>TPM_RS_PW</c>,
    /// optionally paired with a SEPARATE bound HMAC session carrying the decrypt attribute that protects
    /// inSensitive (Part 3, clause 12.1; Part 1, clauses 19 and 21).
    /// </summary>
    /// <remarks>
    /// The parent must be a loaded restricted storage object (<c>TPM_RC_HANDLE</c>/<c>TPM_RC_TYPE</c> as
    /// <c>OnCreateSealedObject</c>). The session area's own attribute rules (clause 5.5) are validated before any
    /// HMAC is evaluated; DA/Lockout for the parent is checked before any HMAC is evaluated (clause 5.6, check
    /// 3). The parent slot's USER-role entity term is the parent's retained authValue
    /// (<see cref="TransientKeyState.AuthValue"/>): an HMAC first session folds it into session 0's command
    /// HMAC with bind omission (equation 22, Part 1, clause 17.6.10) exactly as <c>OnUnsealOverSessions</c>
    /// folds its item slot, while a <c>TPM_RS_PW</c> first slot (admitted only alongside a decrypt companion —
    /// a lone password parent-auth parses as the plain form) is compared inline, the
    /// <c>OnNvCertifyOverSession</c> password-slot discipline. Every session that resolves
    /// in <c>state.HmacSessions</c> needs its command HMAC verified through the shared mechanism
    /// (<c>TpmVerifyCommandHmacAction</c>); <c>ContinueCreateOverSessions</c> resumes once the queue empties.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_Create()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the first HMAC verification.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnCreateSealedObjectOverSessions(TpmSimulatorState state, TpmCreateSealedObjectOverSessionsRequested request)
    {
        if(!state.TransientObjects.TryGetValue(request.ParentHandle, out TransientKeyState? parent))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Create, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        if(!IsStorageParent(parent.Attributes))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Create, TpmRcConstants.TPM_RC_TYPE, request);
        }

        //inPublic (and so its Name algorithm) is not decoded until TpmDecryptCreateSensitiveAction runs, strictly
        //after the command HMAC(s) verify; OnCreateSensitiveDecrypted checks IsSupportedNameAlg once it is known.
        bool firstIsHmac = state.HmacSessions.TryGetValue(TpmiShHmac.FromValue(request.FirstSession.Value), out HmacSessionState? firstHmacSession);
        if(!firstIsHmac && !request.FirstSession.IsPasswordSession)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Create, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        //Whether the second block arrived is a structural fact the parser settled from authorizationSize, so it is
        //read from the record rather than guessed from the handle, and the slot is then resolved and validated for
        //every value it can hold: a handle that is not a session handle at all is TPM_RC_HANDLE and a well-typed
        //handle naming no loaded session is TPM_RC_REFERENCE_S*, both blamed on this index (Part 3, clause 5.5,
        //step 4).
        bool hasSecondSession = request.HasDecryptSlot;
        HmacSessionState? secondSession = null;
        if(hasSecondSession
            && !TryResolveCommandSession(state, request.DecryptSession, sessionIndex: 1, out secondSession, out TpmRcConstants secondSlotRefusal))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Create, secondSlotRefusal, request);
        }

        TpmRcConstants? sessionAreaError = ValidateSessionArea(
            request.FirstAttributes, firstAuthorizesEntity: true, firstIsHmac ? firstHmacSession!.Symmetric : TpmtSymDef.Null,
            hasSecondSession, request.DecryptAttributes, secondSession?.Symmetric ?? TpmtSymDef.Null,
            firstCommandParameterIsEncryptable: true, firstResponseParameterIsEncryptable: false,
            firstSessionHandle: request.FirstSession, secondSessionHandle: request.DecryptSession,
            firstNonceLength: request.FirstNonceCaller.Size, secondNonceLength: request.DecryptNonceCaller.Size);
        if(sessionAreaError is TpmRcConstants sessionAreaRc)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Create, sessionAreaRc, request);
        }

        //DA/Lockout is checked before any credential is evaluated (Part 3, clause 5.6, check 3) — unconditionally,
        //regardless of whether the parent's authorizing session is a bound HMAC session or plain TPM_RS_PW. A
        //locked-out TPM must never perform the Create merely because the parent happened to be authorized by a
        //password rather than an HMAC session.
        if(parent.IsDaProtected && state.IsInLockout)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Create, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        //The same check from the session side, for every real session in the area: a session bound to a
        //DA-protected entity may not be used while that entity's protection is in force, whatever the parent's own
        //noDA attribute says (Part 3, clause 11.1.1's "regardless of the DA status of the entity being
        //authorized"; Part 1, clause 17.8.3). A TPM_RS_PW parent-auth slot carries no session and no bind.
        if(firstIsHmac && IsBoundSessionLockedOut(state, firstHmacSession!))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Create, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        if(secondSession is not null && IsBoundSessionLockedOut(state, secondSession))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Create, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        //USER role gate (Part 3, clause 5.6, check 7.1): a parent whose userWithAuth attribute is CLEAR may
        //have its USER role authorized only by a policy session — never by an HMAC session (bound or not) and
        //never by a password, so this one gate covers both credential shapes the first slot can take below.
        //Refused before any HMAC verification is queued and before the inline compare, uncharged, per clause
        //5.6's mandatory check order (check 7.1 precedes checks 9/10).
        if((parent.Attributes & TpmaObject.USER_WITH_AUTH) == 0)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Create, TpmRcConstants.TPM_RC_POLICY_FAIL, request);
        }

        //Whether the second session (if present) actually requests decryption: the fold (clause 17.6.3.4) and the
        //decrypt step itself (ContinueCreateOverSessions) are keyed on the session's OWN decrypt attribute, not
        //merely on whether a second session is present in the authorization area (it could instead be an
        //audit-only companion, which ValidateSessionArea admits but which must never trigger a decrypt attempt).
        bool secondSessionDecrypts = hasSecondSession && (request.DecryptAttributes & TpmaSession.DECRYPT) != 0;

        var pending = ImmutableArray.CreateBuilder<TpmPendingSessionVerification>(2);

        if(firstIsHmac)
        {
            //The first session authorizes the parent (USER role, Part 3, clause 5.6): the parent's retained
            //authValue is the entity term, and the bind-omission (equation 22, Part 1, clause 17.6.10) drops it
            //from the HMAC key precisely when this session is bound to the parent itself — the fold
            //OnUnsealOverSessions applies to its item slot, here against the parent's Name and live authValue.
            ReadOnlySpan<byte> strippedParentAuth = StripTrailingZeros(parent.AuthValue.AsReadOnlySpan());
            bool bindOmits = firstHmacSession!.BoundEntity.Matches(parent.Name.Span, strippedParentAuth);

            //The decrypt session (when the second session actually sets decrypt) authorizes no entity and sits at
            //index 1, so its nonceTPM folds into session 0's HMAC as equation 17's nonceTPMdecrypt term (clause
            //17.6.3.4) — session 0 itself authorizes the parent. This command has no encryptable response
            //parameter, so the equation's nonceTPMencrypt term never has a session to name.
            Tpm2bNonce foldedNonceDecrypt = secondSessionDecrypts ? secondSession!.NonceTpm : Tpm2bNonce.Empty;

            //Clause 17.8.7's OR: the parent's own noDA attribute and the session's bind-side state are independent
            //grounds for a mismatch to charge the failure counter.
            pending.Add(new TpmPendingSessionVerification(
                TpmiShAuthSession.FromValue(firstHmacSession.Handle.Value), SessionIndex: 0, firstHmacSession.SessionAlg, firstHmacSession.SessionKey,
                bindOmits ? Tpm2bAuth.Empty : parent.AuthValue,
                parent.IsDaProtected || firstHmacSession.IsBoundEntityDaProtected,
                request.FirstNonceCaller, firstHmacSession.NonceTpm, foldedNonceDecrypt, Tpm2bNonce.Empty,
                request.FirstAttributes, request.FirstHmac, IsLockoutEntity: firstHmacSession.IsBoundToLockout));
        }
        else
        {
            //Session 0 is TPM_RS_PW (admitted only alongside a decrypt companion — a lone password parent-auth
            //parses as the plain form): its hmac field is the plaintext parent password, compared inline since
            //a password authorization computes no cpHash (Part 1, clause 17.6.4.1) — both sides
            //trailing-zero-stripped (Part 1, clause 17.6.4.3), in fixed time, the OnNvCertifyOverSession
            //password-slot discipline. A mismatch rejects before the companion's HMAC verification is queued.
            if(!CryptographicOperations.FixedTimeEquals(
                StripTrailingZeros(request.FirstHmac.AsReadOnlySpan()), StripTrailingZeros(parent.AuthValue.AsReadOnlySpan())))
            {
                return RejectSessionAuthFailure(state, TpmCcConstants.TPM_CC_Create, sessionIndex: 0, parent.IsDaProtected, request);
            }
        }

        if(hasSecondSession)
        {
            //The second session authorizes no entity, so its whole dictionary-attack standing comes from its own
            //bind (clause 17.8.1's third way an authValue is used for authorization is the sessionKey computation
            //of a bound session, and "All uses of a DA protected authValue receive DA protection"), and its HMAC
            //key is the session key alone. Session index 1 never folds (the fold only ever targets session index
            //0). It still needs its own command HMAC verified regardless of which attribute (decrypt or audit) it
            //carries (clause 5.6 applies to every session in the authorization area).
            pending.Add(new TpmPendingSessionVerification(
                TpmiShAuthSession.FromValue(secondSession!.Handle.Value), SessionIndex: 1, secondSession.SessionAlg, secondSession.SessionKey,
                AuthValue: Tpm2bAuth.Empty, IsDaProtected: secondSession.IsBoundEntityDaProtected, request.DecryptNonceCaller,
                secondSession.NonceTpm, FoldedNonceDecrypt: Tpm2bNonce.Empty, FoldedNonceEncrypt: Tpm2bNonce.Empty, request.DecryptAttributes, request.DecryptHmac,
                IsLockoutEntity: secondSession.IsBoundToLockout));
        }

        //Every reachable combination needs at least one command-HMAC verification: a lone password parent-auth
        //session with no decrypt session parses as TpmCreateSealedObjectRequested instead (never reaches here),
        //so pending is never empty.
        ImmutableArray<TpmPendingSessionVerification> queue = pending.ToImmutable();

        return Transition(
            state with
            {
                NextAction = new TpmVerifyCommandHmacAction(
                    TpmCcConstants.TPM_CC_Create, HandleNames: TpmCommandHandleNames.Of(TpmHandleName.FromName(parent.Name)), ParameterArea: request.RawParameterArea,
                    queue[0], queue.RemoveAt(0), request),
                ResponseIntent = null
            },
            "Create:HmacVerifyRequested");
    }

    /// <summary>
    /// Resumes <c>TPM2_Create()</c> over sessions once every session in its authorization area has verified:
    /// declares the decrypt effect, which validates inSensitive's own declared size AND decodes every parameter
    /// field.
    /// </summary>
    /// <remarks>
    /// None of that can happen any earlier, since inPublic's start offset depends on inSensitive's
    /// (only-now-validated) declared size, and clause 5.8 field interpretation must in any case follow clause 5.6
    /// HMAC verification. This step releases none of the request's carriers: the decrypt it declares can still
    /// end on an arm that releases the whole request, so every carrier's single release site sits past that arm,
    /// in <c>OnCreateSensitiveDecrypted</c>.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_Create()</c> request, its sessions now verified.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the decrypt action.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> ContinueCreateOverSessions(TpmSimulatorState state, TpmCreateSealedObjectOverSessionsRequested request)
    {
        //Nothing the request owns is released here. The decrypt step declared below resumes into arms that
        //refuse by releasing the whole request, so both slots' supplied credentials — like the parameter area —
        //are released at the single site past the last such arm, and each slot's caller nonce is borrowed by the
        //decrypt step and then transferred into that slot's response-session entry by the resume that builds it.

        //Which slot decrypts is read from the attribute BITS in area order, never from a slot's position: "a
        //session with this attribute does not need to be associated with an entity identified in the handle
        //area" (Part 1, clause 16.6.4, Table 12), so the parent's own authorizing session may carry decrypt just
        //as a companion may, and ValidateSessionArea admits either. The slot that claims it supplies the whole
        //cipher key.
        int decryptIndex = CreateDecryptSlotIndex(request);

        //The decrypt slot's own authorized entity supplies the cipher key's authValue term, UNRESOLVED by the
        //session's bind (Part 1, clause 19.1: "The binding of the session is ignored"); a companion authorizes
        //none and folds nothing. Slot 0 authorizes the parent, so the parent's LIVE authValue is that term.
        //The nonce rides the action as a BORROW: the request keeps owning it across the decrypt step.
        (HmacSessionState? Session, Tpm2bAuth EntityAuthValue, Tpm2bNonce NonceCaller) decrypt = decryptIndex switch
        {
            0 => (state.HmacSessions[TpmiShHmac.FromValue(request.FirstSession.Value)], state.TransientObjects[request.ParentHandle].AuthValue, request.FirstNonceCaller),
            1 => (state.HmacSessions[TpmiShHmac.FromValue(request.DecryptSession.Value)], Tpm2bAuth.Empty, request.DecryptNonceCaller),
            _ => (null, Tpm2bAuth.Empty, Tpm2bNonce.Empty)
        };

        return Transition(
            state with
            {
                NextAction = new TpmDecryptCreateSensitiveAction(
                    request, request.RawParameterArea, decrypt.Session is not null,
                    decrypt.Session?.SessionAlg ?? TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_NULL),
                    decrypt.Session?.Symmetric ?? TpmtSymDef.Null,
                    decrypt.Session?.SessionKey ?? TpmSimulatorState.EmptySessionKey,
                    decrypt.EntityAuthValue,
                    decrypt.NonceCaller,
                    decrypt.Session?.NonceTpm ?? Tpm2bNonce.Empty),
                ResponseIntent = null
            },
            "Create:DecryptRequested");
    }

    /// <summary>
    /// The slot of a session-authorized <c>TPM2_Create()</c>'s authorization area carrying the <c>decrypt</c>
    /// attribute, searched over the slots the area actually carried, in area order.
    /// </summary>
    /// <remarks>
    /// Shared by the transition that declares the decrypt step and the one that blames a failure on the slot
    /// that asked for it, so the two cannot disagree about which slot decrypts. Either slot may claim it —
    /// "a session with this attribute does not need to be associated with an entity identified in the handle
    /// area" (TPM 2.0 Library Part 1, clause 16.6.4, Table 12) — and the area-level gate has already refused a
    /// second claimer.
    /// </remarks>
    /// <param name="request">The parsed session-authorized <c>TPM2_Create()</c> request.</param>
    /// <returns>The claiming slot's zero-based index, or <c>-1</c> when no slot claims it.</returns>
    private static int CreateDecryptSlotIndex(TpmCreateSealedObjectOverSessionsRequested request)
    {
        ReadOnlySpan<TpmaSession> allSlotAttributes = [(TpmaSession)request.FirstAttributes, (TpmaSession)request.DecryptAttributes];

        return FindClaimingSlot(allSlotAttributes[..(request.HasDecryptSlot ? 2 : 1)], TpmaSession.DECRYPT);
    }

    /// <summary>
    /// Resumes <c>TPM2_Create()</c> over sessions once inSensitive has been decrypted (if applicable) and
    /// decoded: a malformed result (a wrong decryption key's garbage bytes failing to decode as
    /// <c>TPMS_SENSITIVE_CREATE</c>) rejects directly; otherwise the seal proceeds, declaring
    /// <c>TpmSealDataOverSessionsAction</c> rather than the plain password form's <c>TpmSealDataAction</c>.
    /// </summary>
    /// <remarks>
    /// The response must carry a <c>TPM_ST_SESSIONS</c> envelope with a real per-session entry (or a
    /// <c>TPM_RS_PW</c> placeholder) for every session in the command's authorization area (Part 1, clause
    /// 18.6), exactly mirroring <c>TPM2_Unseal()</c>'s two-form split. This resume is also where the request's
    /// parameter area and both slots' supplied credentials are released, at a point past the last arm that
    /// refuses — each of those arms releases the whole request, so releasing any earlier would put two release
    /// sites on the same carrier.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="decrypted">The effect's result carrying the decrypted (or failed) inSensitive.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the seal action, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnCreateSensitiveDecrypted(TpmSimulatorState state, TpmCreateSensitiveDecrypted decrypted)
    {
        if(decrypted.ResponseCode != TpmRcConstants.TPM_RC_SUCCESS)
        {
            //A truncated/oversized inSensitive declared size is session-index-encoded to the slot that CLAIMED
            //decrypt (the size problem surfaces only while attempting to decrypt, Part 1, clause 21) — which is
            //the parent's own authorizing slot when that slot carried the attribute, not a fixed position; every
            //other malformation (a generic parameter error, or the same size problem with no decrypt session
            //present to blame) is reported bare, exactly as the plain password form's parser already does.
            TpmRcConstants responseCode = decrypted.SizeFailureBlamesDecryptSession
                ? SessionEncodedRc(decrypted.ResponseCode, CreateDecryptSlotIndex(decrypted.Request))
                : decrypted.ResponseCode;

            return Reject(state, TpmCcConstants.TPM_CC_Create, responseCode, decrypted);
        }

        if(!IsSupportedNameAlg(decrypted.NameAlg))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Create, TpmRcConstants.TPM_RC_HASH, decrypted);
        }

        //An authValue "should not be larger than the digest size of the algorithm used to compute the Name of
        //the object" (Part 1, clause 17.6.4.2); the reference's TPM2_Create enforces it on
        //inSensitive.userAuth's supplied size with TPM_RC_SIZE — checked here on the decrypted form, before
        //any trailing-zero stripping, mirroring the plain arm's own gate.
        if(decrypted.UserAuth.Length > TpmPolicyDigest.Size(decrypted.NameAlg.Value))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Create, TpmRcConstants.TPM_RC_SIZE, decrypted);
        }

        TpmCreateSealedObjectOverSessionsRequested request = decrypted.Request;

        //This resume is the terminal owner of the parse-rented parameter area and of both slots' supplied
        //credentials: the command HMAC read the area as ciphertext, the decrypt effect transformed it in place,
        //the body has been decoded from it, every queued command HMAC that read a slot's hmac has verified, and
        //nothing downstream reads any of the three again. Each slot's caller nonce is NOT released here — it
        //transfers into that slot's response-session entry below.
        request.RawParameterArea.Dispose();
        request.FirstHmac.Dispose();
        request.DecryptHmac.Dispose();

        //The parent is guaranteed loaded: the entry transition resolved it and nothing between the verification
        //queue and this resume can evict it (the ContinueUnsealOverSessions re-lookup rationale). Its hierarchy
        //is what the creation ticket names (Part 2, clause 10.7.3, Table 109), and its live authValue is the
        //response HMAC's entity term, so it is read once here for both.
        TransientKeyState parent = state.TransientObjects[request.ParentHandle];

        bool firstIsHmac = state.HmacSessions.TryGetValue(TpmiShHmac.FromValue(request.FirstSession.Value), out HmacSessionState? firstHmacSession);
        bool hasPasswordPlaceholder = !firstIsHmac;

        var responseSessions = ImmutableArray.CreateBuilder<TpmCreateResponseSession>(2);
        if(firstIsHmac)
        {
            //The same HMAC key the command-HMAC verification used: the parent's entity term, recomputed from
            //its LIVE retained authValue exactly as the command-side decision was — TPM2_Create() rotates no
            //authValue, so this recomputation and the recorded command-time decision are the same value
            //(Part 1, clause 17.6.10's response rule: the response omits precisely when the command did).
            ReadOnlySpan<byte> strippedParentAuth = StripTrailingZeros(parent.AuthValue.AsReadOnlySpan());
            bool bindOmits = firstHmacSession!.BoundEntity.Matches(parent.Name.Span, strippedParentAuth);

            //The slot's caller nonce TRANSFERS into the entry here; the seal effect's finally is its terminal
            //owner once the response HMAC has keyed its nonceOlder term on it.
            responseSessions.Add(new TpmCreateResponseSession(
                TpmiShAuthSession.FromValue(firstHmacSession.Handle.Value), firstHmacSession.SessionAlg, firstHmacSession.SessionKey,
                bindOmits ? Tpm2bAuth.Empty : parent.AuthValue, request.FirstNonceCaller, request.FirstAttributes));
        }
        else
        {
            //A TPM_RS_PW slot 0 gets a placeholder entry that carries no nonce, and an HMAC slot 0 whose session
            //was flushed between the verification queue and this resume gets no entry at all: either way nothing
            //takes the slot's nonce, so this arm is its terminal owner.
            request.FirstNonceCaller.Dispose();
        }

        if(request.HasDecryptSlot && state.HmacSessions.TryGetValue(TpmiShHmac.FromValue(request.DecryptSession.Value), out HmacSessionState? secondSession))
        {
            responseSessions.Add(new TpmCreateResponseSession(
                TpmiShAuthSession.FromValue(secondSession.Handle.Value), secondSession.SessionAlg, secondSession.SessionKey,
                AuthValue: Tpm2bAuth.Empty, request.DecryptNonceCaller, request.DecryptAttributes));
        }
        else
        {
            //No second slot at all, or one whose session was flushed mid-command: no entry is built for it, so
            //this arm is the terminal owner of whatever nonce that slot carried.
            request.DecryptNonceCaller.Dispose();
        }

        return Transition(
            state with
            {
                NextAction = new TpmSealDataOverSessionsAction(
                    request.ParentHandle, parent.Hierarchy, decrypted.NameAlg, decrypted.AuthPolicy, decrypted.NoDa, decrypted.UserWithAuth,
                    decrypted.SecretData, decrypted.UserAuth,
                    //A password session's response unconditionally SETs continueSession (Part 1, clause 17.6.4) —
                    //never echoing whatever the command happened to carry.
                    hasPasswordPlaceholder, hasPasswordPlaceholder ? TpmaSession.CONTINUE_SESSION : default,
                    responseSessions.ToImmutable()),
                ResponseIntent = null
            },
            "Create:SensitiveDecrypted");
    }

    /// <summary>
    /// Rolls every real session's stored nonceTPM and frames the session-authorized response of
    /// <c>TPM2_Create()</c> the seal effect assembled (TPM 2.0 Library Part 1, clause 17.6.5).
    /// </summary>
    /// <remarks>
    /// Each session record is replaced wholesale because its nonceTPM is immutable model state, replaced once per
    /// command — the same pattern <c>OnAttestedOverSessions</c> and <c>OnEncryptedRandomProduced</c> use. The
    /// retained half of each entry's nonce pair moves into the session record; a session flushed between stages
    /// leaves the table unchanged and that half is released, while the response is still framed from the other
    /// half.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="sealedObject">The effect's result carrying the framed parameter area and every session's response entry.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> carrying the framed session-authorized response.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnObjectSealedOverSessions(TpmSimulatorState state, TpmObjectSealedOverSessions sealedObject)
    {
        ImmutableDictionary<TpmiShHmac, HmacSessionState> sessions = state.HmacSessions;
        foreach(TpmCreateFramedSessionEntry entry in sealedObject.Entries)
        {
            sessions = RollHmacSessionNonce(sessions, entry.SessionHandle, entry.RetainedNonceTpm);
        }

        return Transition(
            state with
            {
                NextAction = NullAction.Instance,
                HmacSessions = sessions,
                ResponseIntent = new TpmCreateOverSessionsResponse(
                    TpmRcConstants.TPM_RC_SUCCESS, sealedObject.ParameterArea,
                    sealedObject.HasPasswordPlaceholder, sealedObject.PasswordPlaceholderAttributes, sealedObject.Entries)
            },
            "Create:CompletedOverSessions");
    }

    /// <summary>
    /// Brings a wrapped sealed object back into a transient slot under its storage parent for
    /// <c>TPM2_Load()</c> (Part 3, clause 12.2).
    /// </summary>
    /// <remarks>
    /// The parent must be a loaded restricted storage object; a missing handle is <c>TPM_RC_HANDLE</c> and a
    /// non-storage parent is <c>TPM_RC_TYPE</c>. Only a sealed KEYEDHASH object is modelled this slice, so
    /// another object type is <c>TPM_RC_TYPE</c>. The object Name needs the digest seam, so the transition
    /// allocates the transient handle and declares a <c>TpmLoadObjectAction</c>; <c>OnObjectLoaded</c> stores
    /// the object and frames the response.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_Load()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the load action.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnLoadObject(TpmSimulatorState state, TpmLoadObjectRequested request)
    {
        if(!state.TransientObjects.TryGetValue(request.ParentHandle, out TransientKeyState? parent))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Load, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        if(!IsStorageParent(parent.Attributes))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Load, TpmRcConstants.TPM_RC_TYPE, request);
        }

        //DA/Lockout for the parent precedes the compare (Part 3, clause 5.6, check 3) — a locked-out TPM never
        //performs the Load, matching OnCreateSealedObject's identical gate on the same parent class.
        if(parent.IsDaProtected && state.IsInLockout)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Load, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        //USER role gate (Part 3, clause 5.6, check 7.1): a parent whose userWithAuth attribute is CLEAR may
        //have its USER role authorized only by a policy session, never by a password — refused before the
        //compare below, uncharged, per clause 5.6's mandatory check order.
        if((parent.Attributes & TpmaObject.USER_WITH_AUTH) == 0)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Load, TpmRcConstants.TPM_RC_POLICY_FAIL, request);
        }

        //The parent slot's USER-role authorization (Part 3, clause 12.2: @parentHandle, Auth Index 1, Auth
        //Role USER): the supplied password is compared against the parent's retained authValue, both sides
        //trailing-zero-stripped (Part 1, clause 17.6.4.3), in fixed time — the OnCreateSealedObject
        //discipline, on the same parent slot TPM2_Create() verifies.
        ReadOnlySpan<byte> suppliedStripped = StripTrailingZeros(request.SuppliedParentPassword.AsReadOnlySpan());
        ReadOnlySpan<byte> parentAuthStripped = StripTrailingZeros(parent.AuthValue.AsReadOnlySpan());

        if(!CryptographicOperations.FixedTimeEquals(suppliedStripped, parentAuthStripped))
        {
            return RejectSessionAuthFailure(state, TpmCcConstants.TPM_CC_Load, sessionIndex: 0, parent.IsDaProtected, request);
        }

        //The simulator recovers sealed data from its own blob encoding; only a sealed KEYEDHASH object is modelled.
        if(request.ObjectType.Value != TpmAlgIdConstants.TPM_ALG_KEYEDHASH)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Load, TpmRcConstants.TPM_RC_TYPE, request);
        }

        if(!IsSupportedNameAlg(request.NameAlg))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Load, TpmRcConstants.TPM_RC_HASH, request);
        }

        //The private blob is this simulator's own [UINT16 userAuth-length ‖ userAuth ‖ data] encoding
        //(PackSealedPrivateBlob) and arrives attacker-controlled: an empty blob, a declared userAuth length that
        //overruns the blob, or one wider than a TPM2B_AUTH can hold at all (sizeof(TPMU_HA), TPM 2.0 Library
        //Part 2, clause 10.4.5, Table 95 over clause 10.4.2, Table 92) is a structure of the wrong size, refused
        //here — before the unpack effect is ever declared — rather than left to crash the recovery arithmetic.
        if(request.PrivateBlob.Length < sizeof(ushort)
            || BinaryPrimitives.ReadUInt16BigEndian(request.PrivateBlob.Span) > request.PrivateBlob.Length - sizeof(ushort)
            || BinaryPrimitives.ReadUInt16BigEndian(request.PrivateBlob.Span) > Tpm2bAuth.MaxSize)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Load, TpmRcConstants.TPM_RC_SIZE, request);
        }

        //The transition is the password carrier's terminal owner — the parent-slot compare was its only use.
        request.SuppliedParentPassword.Dispose();

        uint handle = state.NextObjectHandle;

        return Transition(
            state with
            {
                NextObjectHandle = state.NextObjectHandle + 1,
                NextAction = new TpmLoadObjectAction(TpmiDhObject.FromValue(handle), request.NameAlg, request.AuthPolicy, request.NoDa, request.UserWithAuth, request.InPublic, request.PrivateBlob),
                ResponseIntent = null
            },
            "Load:Requested");
    }

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of loadedObject's RetainedName, Data, and UserAuth carriers transfers to the stored SealedObjectState, which eviction (TPM2_FlushContext, simulator teardown) disposes, and of its Name carrier to the framed response; the refusing arm releases them all through the input's own Dispose instead.")]
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnObjectLoaded(TpmSimulatorState state, TpmObjectLoaded loadedObject)
    {
        //The recovered sensitive area's authValue is bounded by the digest size of the object's nameAlg
        //(Part 1, clause 17.6.4.2; the reference's sensitive-area unmarshal enforces the same bound): this
        //model's private blob carries no integrity wrap yet (roadmap W3), so a hand-crafted blob must not be
        //able to install a wider authValue than TPM2_Create()'s own gate admits. The Name's 2-octet prefix IS
        //the nameAlg (Part 1, clause 14, Table 6), already validated supported before the load action was declared.
        var loadedNameAlg = (TpmAlgIdConstants)BinaryPrimitives.ReadUInt16BigEndian(loadedObject.Name.Span[..sizeof(ushort)]);
        if(loadedObject.UserAuth.Length > TpmPolicyDigest.Size(loadedNameAlg))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Load, TpmRcConstants.TPM_RC_SIZE, loadedObject);
        }

        var sealedObject = new SealedObjectState(
            loadedObject.Handle,
            loadedObject.RetainedName,
            loadedObject.Data,
            loadedObject.AuthPolicy,
            loadedObject.UserAuth,
            loadedObject.NoDa,
            loadedObject.UserWithAuth);

        return Transition(
            state with
            {
                NextAction = NullAction.Instance,
                LoadedSealedObjects = state.LoadedSealedObjects.SetItem(loadedObject.Handle, sealedObject),
                ResponseIntent = new TpmLoadResponse(TpmRcConstants.TPM_RC_SUCCESS, loadedObject.Handle, loadedObject.Name)
            },
            "Load:Completed");
    }

    /// <summary>
    /// Returns the data sealed in a loaded KEYEDHASH object for <c>TPM2_Unseal()</c>, authorized by a plain
    /// <c>TPM_RS_PW</c> password session (Part 3, clause 12.7).
    /// </summary>
    /// <remarks>
    /// An unloaded handle is <c>TPM_RC_HANDLE</c>. userWithAuth CLEAR rejects with <c>TPM_RC_POLICY_FAIL</c>
    /// before any password is ever compared (Part 3, clause 5.6, check 7.1) — a policy/PCR-sealed object (empty
    /// userAuth, non-empty authPolicy) is never recoverable via a bare password, no matter what value is
    /// supplied. Otherwise the supplied password is compared against the object's retained userAuth — both sides
    /// trailing-zero-stripped (Part 1, clause 17.6.4) — a real compare rather than the vacuous "any password
    /// accepted" this path previously had; a DA-protected object's mismatch counts (Part 3, clause 5.6). The
    /// policy-gated, encrypted-channel form is <c>OnUnsealOverSessions</c>.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_Unseal()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnUnseal(TpmSimulatorState state, TpmUnsealRequested request)
    {
        if(!state.LoadedSealedObjects.TryGetValue(request.ItemHandle, out SealedObjectState? sealedObject))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Unseal, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        //DA/Lockout is checked strictly before any credential compare (Part 3, clause 5.6, check 3) — a locked-out
        //TPM never even compares the password for a DA-protected object.
        if(sealedObject.IsDaProtected && state.IsInLockout)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Unseal, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        //USER role, userWithAuth CLEAR ⇒ a policy session is required; no password may ever authorize this object
        //(Part 3, clause 5.6, check 7.1). This must precede the password compare below: a userWithAuth-CLEAR sealed
        //object (PCR/policy-gated, empty userAuth) would otherwise accept an empty TPM_RS_PW password and return
        //the secret in the clear, bypassing the policy the object was sealed under entirely. The HMAC-authorized
        //path enforces the identical check at the same pre-credential position (OnUnsealOverSessions, before the
        //command HMAC is queued).
        if(!sealedObject.UserWithAuth)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Unseal, TpmRcConstants.TPM_RC_POLICY_FAIL, request);
        }

        ReadOnlySpan<byte> suppliedStripped = StripTrailingZeros(request.SuppliedPassword.AsReadOnlySpan());
        ReadOnlySpan<byte> userAuthStripped = StripTrailingZeros(sealedObject.UserAuth.AsReadOnlySpan());

        if(!CryptographicOperations.FixedTimeEquals(suppliedStripped, userAuthStripped))
        {
            return RejectSessionAuthFailure(state, TpmCcConstants.TPM_CC_Unseal, sessionIndex: 0, sealedObject.IsDaProtected, request);
        }

        //The compare above was this credential's only use, so this transition is its terminal owner; every arm
        //that refuses before this point releases it through the request's own Dispose.
        request.SuppliedPassword.Dispose();

        return Transition(
            state with { ResponseIntent = new TpmUnsealResponse(TpmRcConstants.TPM_RC_SUCCESS, sealedObject.Data) },
            "Unseal");
    }

    /// <summary>
    /// Dispatches <c>TPM2_Unseal()</c> whose first session is either a satisfied policy session or a bound HMAC
    /// session (the primary authorizer), optionally carrying a second bound HMAC session with the encrypt
    /// attribute that protects outData (Part 3, clause 12.7; Part 1, clauses 16.7 and 19).
    /// </summary>
    /// <remarks>
    /// The item must be loaded (<c>TPM_RC_HANDLE</c> otherwise). Every session that resolves in
    /// <c>state.HmacSessions</c> needs its command HMAC verified through the shared mechanism
    /// (<c>TpmVerifyCommandHmacAction</c>); a policy session at index 0 keeps its existing, unverified-HMAC
    /// digest gate (Part 1, clause 17.6 — policy-session command-HMAC verification remains out of scope). The
    /// session area's own attribute rules (clause 5.5) are validated before any HMAC is evaluated: Unseal
    /// carries no command parameters, so a decrypt-attributed session here is always rejected. DA/Lockout for a
    /// DA-protected item is checked before any HMAC is evaluated (clause 5.6, check 3). When session 0 is the
    /// primary HMAC authorizer AND a separate encrypt session is present, session 0's command HMAC folds the
    /// encrypt session's nonceTPM (clause 17.6.3.4) — the fold this wiring makes observable end to end.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_Unseal()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnUnsealOverSessions(TpmSimulatorState state, TpmUnsealOverSessionsRequested request)
    {
        if(!state.LoadedSealedObjects.TryGetValue(request.ItemHandle, out SealedObjectState? sealedObject))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Unseal, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        bool firstIsHmac = state.HmacSessions.TryGetValue(TpmiShHmac.FromValue(request.FirstSession.Value), out HmacSessionState? firstHmacSession);
        if(!firstIsHmac && !state.PolicySessions.ContainsKey(TpmiShPolicy.FromValue(request.FirstSession.Value)))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Unseal, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        //Whether the second block arrived is a structural fact the parser settled from authorizationSize, so it is
        //read from the record rather than guessed from the handle, and the slot is then resolved and validated for
        //every value it can hold: a handle that is not a session handle at all is TPM_RC_HANDLE and a well-typed
        //handle naming no loaded session is TPM_RC_REFERENCE_S*, both blamed on this index (Part 3, clause 5.5,
        //step 4).
        bool hasEncryptSession = request.HasEncryptSlot;
        HmacSessionState? encryptSession = null;
        if(hasEncryptSession
            && !TryResolveCommandSession(state, request.EncryptSession, sessionIndex: 1, out encryptSession, out TpmRcConstants encryptSlotRefusal))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Unseal, encryptSlotRefusal, request);
        }

        TpmRcConstants? sessionAreaError = ValidateSessionArea(
            request.PolicyAttributes, firstAuthorizesEntity: true, firstIsHmac ? firstHmacSession!.Symmetric : TpmtSymDef.Null,
            hasEncryptSession, request.EncryptAttributes, encryptSession?.Symmetric ?? TpmtSymDef.Null,
            firstCommandParameterIsEncryptable: false, firstResponseParameterIsEncryptable: true,
            firstSessionHandle: request.FirstSession, secondSessionHandle: request.EncryptSession,
            firstNonceLength: request.FirstNonceCaller.Size, secondNonceLength: request.EncryptNonceCaller.Size);
        if(sessionAreaError is TpmRcConstants sessionAreaRc)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Unseal, sessionAreaRc, request);
        }

        //The bind-side lockout gate, for every real session in the area and both kinds the first slot can take:
        //use of a session bound to a DA-protected entity is subject to DA "regardless of the DA status of the
        //entity being authorized" (Part 3, clause 11.1.1), so it precedes the item-side gate below rather than
        //riding inside the HMAC-only branch.
        if(firstIsHmac && IsBoundSessionLockedOut(state, firstHmacSession!))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Unseal, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        if(!firstIsHmac && IsBoundSessionLockedOut(state, state.PolicySessions[TpmiShPolicy.FromValue(request.FirstSession.Value)]))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Unseal, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        if(encryptSession is not null && IsBoundSessionLockedOut(state, encryptSession))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Unseal, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        var pending = ImmutableArray.CreateBuilder<TpmPendingSessionVerification>(2);

        if(firstIsHmac)
        {
            //The first session authorizes the item (USER role, Part 3, clause 5.6): a DA-protected item gates
            //lockout before the HMAC is ever evaluated, and the bind-omission (equation 22, Part 1, clause 17.6.10) drops the item's
            //authValue from the HMAC key precisely when this session is bound to the item itself.
            if(sealedObject.IsDaProtected && state.IsInLockout)
            {
                return Reject(state, TpmCcConstants.TPM_CC_Unseal, TpmRcConstants.TPM_RC_LOCKOUT, request);
            }

            //USER role gate (Part 3, clause 5.6, check 7.1): an item whose userWithAuth attribute is CLEAR may
            //have its USER role authorized only by a policy session — an HMAC session, bound or not, is refused
            //HERE, before its command HMAC is ever queued for verification, because check 7.1 precedes check 9
            //in clause 5.6's mandatory order: a wrong authValue guess against such an item must answer the same
            //uncharged TPM_RC_POLICY_FAIL as a correct one, never TPM_RC_AUTH_FAIL with a dictionary-attack
            //charge — the item's authValue is not a live credential at all. ContinueUnsealOverSessions retains
            //the same check as an unreachable fail-closed backstop.
            if(!sealedObject.UserWithAuth)
            {
                return Reject(state, TpmCcConstants.TPM_CC_Unseal, TpmRcConstants.TPM_RC_POLICY_FAIL, request);
            }

            ReadOnlySpan<byte> strippedUserAuth = StripTrailingZeros(sealedObject.UserAuth.AsReadOnlySpan());
            bool bindOmits = firstHmacSession!.BoundEntity.Matches(sealedObject.Name.Span, strippedUserAuth);

            //The second session (if present) folds into session 0's HMAC only when it actually carries decrypt or
            //encrypt (clause 17.6.3.4) — never merely because a second session is present in the authorization
            //area (it could instead be an audit-only companion, which ValidateSessionArea admits but which must
            //never fold): session 0 itself authorizes the item, satisfying the fold's own precondition. Equation
            //17 names the two terms separately and in this order, and "if the same session (not the first
            //session) is used for decrypt and encrypt, its nonceTPM is only used once" (clause 17.6.5) — so a
            //companion claiming both contributes through the decrypt term alone.
            bool secondSessionDecrypts = hasEncryptSession && (request.EncryptAttributes & TpmaSession.DECRYPT) != 0;
            bool secondSessionEncrypts = hasEncryptSession && (request.EncryptAttributes & TpmaSession.ENCRYPT) != 0;
            Tpm2bNonce foldedNonceDecrypt = secondSessionDecrypts ? encryptSession!.NonceTpm : Tpm2bNonce.Empty;
            Tpm2bNonce foldedNonceEncrypt = secondSessionEncrypts && !secondSessionDecrypts ? encryptSession!.NonceTpm : Tpm2bNonce.Empty;

            //Clause 17.8.7's OR: the item's own noDA attribute and the session's bind-side state are independent
            //grounds for a mismatch to charge the failure counter.
            pending.Add(new TpmPendingSessionVerification(
                TpmiShAuthSession.FromValue(firstHmacSession.Handle.Value), SessionIndex: 0, firstHmacSession.SessionAlg, firstHmacSession.SessionKey,
                bindOmits ? Tpm2bAuth.Empty : sealedObject.UserAuth,
                sealedObject.IsDaProtected || firstHmacSession.IsBoundEntityDaProtected,
                request.FirstNonceCaller, firstHmacSession.NonceTpm, foldedNonceDecrypt, foldedNonceEncrypt,
                request.PolicyAttributes, request.FirstHmac, IsLockoutEntity: firstHmacSession.IsBoundToLockout));
        }

        if(hasEncryptSession)
        {
            //The encrypt session authorizes no entity, so its whole dictionary-attack standing comes from its own
            //bind (clause 17.8.1: the sessionKey computation of a bound session is itself a use of the bind
            //entity's authValue, and "All uses of a DA protected authValue receive DA protection"), and its HMAC
            //key is the session key alone. Session index 1 never folds (the fold only ever targets session index 0).
            pending.Add(new TpmPendingSessionVerification(
                TpmiShAuthSession.FromValue(encryptSession!.Handle.Value), SessionIndex: 1, encryptSession.SessionAlg, encryptSession.SessionKey,
                AuthValue: Tpm2bAuth.Empty, IsDaProtected: encryptSession.IsBoundEntityDaProtected, request.EncryptNonceCaller,
                encryptSession.NonceTpm, FoldedNonceDecrypt: Tpm2bNonce.Empty, FoldedNonceEncrypt: Tpm2bNonce.Empty, request.EncryptAttributes, request.EncryptHmac,
                IsLockoutEntity: encryptSession.IsBoundToLockout));
        }

        if(pending.Count == 0)
        {
            //Neither session needs a command-HMAC verification (session 0 is a policy session and there is no
            //encrypt session): proceed straight to the existing policy-digest gate.
            return ContinueUnsealOverSessions(state, request);
        }

        ImmutableArray<TpmPendingSessionVerification> queue = pending.ToImmutable();

        return Transition(
            state with
            {
                NextAction = new TpmVerifyCommandHmacAction(
                    TpmCcConstants.TPM_CC_Unseal, HandleNames: TpmCommandHandleNames.Of(TpmHandleName.FromName(sealedObject.Name)), ParameterArea: TpmParameterArea.Empty,
                    queue[0], queue.RemoveAt(0), request),
                ResponseIntent = null
            },
            "Unseal:HmacVerifyRequested");
    }

    /// <summary>
    /// Resumes <c>TPM2_Unseal()</c> once every session in its authorization area has verified: runs the
    /// policy-digest match a policy session at index 0 still owes (an HMAC session's userWithAuth gate,
    /// Part 3, clause 5.6, check 7.1, already ran in <c>OnUnsealOverSessions</c> before the HMAC was queued;
    /// this continuation keeps only a fail-closed backstop), then either returns outData in the clear or
    /// declares the response-framing effect for the confidentiality-protected form.
    /// </summary>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_Unseal()</c> request, its sessions now verified.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> ContinueUnsealOverSessions(TpmSimulatorState state, TpmUnsealOverSessionsRequested request)
    {
        //Both handles are guaranteed to resolve (the entry transition already checked); a re-lookup mirrors
        //ContinueGetRandomOverSession's rationale for not threading resolved records through the verify queue.
        SealedObjectState sealedObject = state.LoadedSealedObjects[request.ItemHandle];

        PolicySessionState? policySession = null;
        if(state.PolicySessions.TryGetValue(TpmiShPolicy.FromValue(request.FirstSession.Value), out policySession))
        {
            //A trial policy session (Part 1, clause 19.3) accumulates a policyDigest for prediction but authorizes
            //nothing; a trial session presented to authorize the unseal is rejected before the object's authPolicy
            //is consulted.
            if(policySession.IsTrial)
            {
                return Reject(state, TpmCcConstants.TPM_CC_Unseal, TpmRcConstants.TPM_RC_POLICY_FAIL, request);
            }

            //Policy gate (Part 3, clause 12.7; Part 1, clause 17.7): an object with a non-empty authPolicy is
            //authorized only when the authorizing policy session's accumulated policyDigest equals that authPolicy.
            if(!sealedObject.AuthPolicy.IsEmpty
                && !sealedObject.AuthPolicy.AsReadOnlySpan().SequenceEqual(policySession.PolicyDigest.AsReadOnlySpan()))
            {
                return Reject(state, TpmCcConstants.TPM_CC_Unseal, TpmRcConstants.TPM_RC_POLICY_FAIL, request);
            }
        }
        else
        {
            //The first session is an HMAC session whose command HMAC has already verified (USER role). Its
            //userWithAuth gate (Part 3, clause 5.6, check 7.1) already ran in OnUnsealOverSessions before the
            //HMAC was queued — check 7.1 precedes check 9 in clause 5.6's mandatory order — so this repeat can
            //never be reached with userWithAuth CLEAR; it stays as a fail-closed backstop only.
            if(!sealedObject.UserWithAuth)
            {
                return Reject(state, TpmCcConstants.TPM_CC_Unseal, TpmRcConstants.TPM_RC_POLICY_FAIL, request);
            }
        }

        //Past the last refusing arm this continuation is the terminal owner of both slots' supplied credentials:
        //every queued command HMAC that read them has verified, and nothing downstream reads them again. Each
        //slot's caller nonce is settled separately below, since only a slot that gets a response-session entry
        //transfers its nonce onward.
        request.FirstHmac.Dispose();
        request.EncryptHmac.Dispose();

        if(!request.HasEncryptSlot && policySession is not null)
        {
            //Gate passed, no encrypt session, first session is a policy session: return the recovered secret in the
            //clear exactly as the plain form does (the executor does not verify a keyless policy session's response
            //auth, so a no-sessions response is accepted). No response-session entry is built at all, so this arm
            //is the terminal owner of both slots' caller nonces.
            request.FirstNonceCaller.Dispose();
            request.EncryptNonceCaller.Dispose();

            return Transition(
                state with { ResponseIntent = new TpmUnsealResponse(TpmRcConstants.TPM_RC_SUCCESS, sealedObject.Data) },
                "Unseal:PolicyAuthorized");
        }

        //Every other combination needs the response-framing effect: a real HMAC session (session 0, session 1, or
        //both) needs its own rolled nonce and response HMAC; a policy session at index 0 still needs its zero-nonce
        //placeholder entry when an encrypt session follows it.
        var hmacResponseSessions = ImmutableArray.CreateBuilder<TpmUnsealResponseSession>(2);
        if(policySession is null)
        {
            HmacSessionState firstHmacSession = state.HmacSessions[TpmiShHmac.FromValue(request.FirstSession.Value)];
            //Recomputed from the item's LIVE userAuth exactly as the command-side decision was — TPM2_Unseal()
            //rotates no authValue, so this recomputation and the recorded command-time decision are the same
            //value (Part 1, clause 17.6.10's response rule: the response omits precisely when the command did).
            ReadOnlySpan<byte> strippedUserAuth = StripTrailingZeros(sealedObject.UserAuth.AsReadOnlySpan());
            bool bindOmits = firstHmacSession.BoundEntity.Matches(sealedObject.Name.Span, strippedUserAuth);

            //The authorizing slot's own encrypt bit is honoured here, not assumed clear: Table 12 lets any slot
            //carry the attribute, and ValidateSessionArea admits it on this slot because outData is an
            //encryptable first response parameter. Its cipher key folds the item's LIVE userAuth (Part 1, clause
            //19.1, the binding ignored), while its response HMAC key keeps the bind-omission decision above.
            //The slot's caller nonce TRANSFERS into the entry here; the framing effect's finally is its terminal
            //owner once the response HMAC (and, where the slot encrypts, the keystream) has keyed its nonceOlder
            //term on it.
            hmacResponseSessions.Add(new TpmUnsealResponseSession(
                TpmiShAuthSession.FromValue(firstHmacSession.Handle.Value), firstHmacSession.SessionAlg, firstHmacSession.SessionKey,
                bindOmits ? Tpm2bAuth.Empty : sealedObject.UserAuth, sealedObject.UserAuth, request.FirstNonceCaller,
                request.PolicyAttributes, (request.PolicyAttributes & TpmaSession.ENCRYPT) != 0, firstHmacSession.Symmetric));
        }
        else
        {
            //A policy session at index 0 gets a zero-nonce placeholder entry rather than a real one, so nothing
            //takes its own caller nonce and this arm is that nonce's terminal owner.
            request.FirstNonceCaller.Dispose();
        }

        if(request.HasEncryptSlot)
        {
            //The second session authorizes no entity, so it is admitted by ValidateSessionArea on its audit
            //attribute alone (Part 3, clause 5.5) without ever claiming encrypt — response encryption (Part 1,
            //clause 21.1) is a per-session OPT-IN, keyed on that session's own encrypt bit specifically, never on
            //the mere presence of a second session in the authorization area (an audit-only companion must never
            //have response encryption applied on its behalf, matching TpmCommandExecutor's own
            //FindParameterEncryptionSessions, which resolves the host's encrypt session the identical way).
            HmacSessionState encryptSession = state.HmacSessions[TpmiShHmac.FromValue(request.EncryptSession.Value)];
            bool encrypts = (request.EncryptAttributes & TpmaSession.ENCRYPT) != 0;
            hmacResponseSessions.Add(new TpmUnsealResponseSession(
                TpmiShAuthSession.FromValue(encryptSession.Handle.Value), encryptSession.SessionAlg, encryptSession.SessionKey, AuthValue: Tpm2bAuth.Empty,
                EntityAuthValue: Tpm2bAuth.Empty, request.EncryptNonceCaller, request.EncryptAttributes, encrypts, encryptSession.Symmetric));
        }
        else
        {
            //There is no second slot, so nothing takes its nonce; the sentinel released here owns nothing.
            request.EncryptNonceCaller.Dispose();
        }

        return Transition(
            state with
            {
                NextAction = new TpmUnsealDataAction(
                    sealedObject.Data,
                    hmacResponseSessions.ToImmutable(),
                    HasPolicyPlaceholder: policySession is not null,
                    policySession?.PolicyHash ?? default,
                    request.PolicyAttributes),
                ResponseIntent = null
            },
            "Unseal:ResponseRequested");
    }

    /// <summary>
    /// Rolls every real session's nonceTPM to its freshly generated value and frames the <c>TPM2_Unseal()</c>
    /// response (the possibly-encrypted outData and the response session area the effect assembled).
    /// </summary>
    /// <remarks>
    /// Each session record is replaced wholesale because its nonceTPM is immutable model state, replaced once
    /// per command (Part 1, clause 17.6.5); a policy session carries no per-command state to roll.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="produced">The effect's result carrying the framed response and rolled nonces.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnUnsealedOverSessions(TpmSimulatorState state, TpmUnsealedOverSessions produced)
    {
        //Every real session is present under normal flow (the request resolved it before declaring the action); if
        //one was flushed meanwhile the produced buffers are still released by SerializeResponse, so frame the
        //response regardless and update the table only for sessions that still exist.
        ImmutableDictionary<TpmiShHmac, HmacSessionState> sessions = state.HmacSessions;
        foreach(TpmUnsealFramedSessionEntry entry in produced.Entries)
        {
            sessions = RollHmacSessionNonce(sessions, entry.SessionHandle, entry.RetainedNonceTpm);
        }

        return Transition(
            state with
            {
                NextAction = NullAction.Instance,
                HmacSessions = sessions,
                ResponseIntent = new TpmUnsealOverSessionsResponse(
                    TpmRcConstants.TPM_RC_SUCCESS,
                    produced.ParameterArea,
                    produced.HasPolicyPlaceholder,
                    produced.PolicyNonceLength,
                    produced.PolicyAttributes,
                    produced.Entries)
            },
            "Unseal:ResponseCompleted");
    }

    /// <summary>
    /// Has a signing key attest that another loaded object's Name is present in the same TPM, over a caller
    /// nonce, for <c>TPM2_Certify()</c> (Part 3, clause 18.2).
    /// </summary>
    /// <remarks>
    /// Both handles must resolve to loaded transient objects; a missing one is <c>TPM_RC_HANDLE</c>.
    /// qualifyingData over the <c>TPM2B_DATA</c> bound (Part 2, clause 10.4.3) is <c>TPM_RC_SIZE</c>; a signer
    /// missing the sign attribute (Part 3, clause 18.1) is <c>TPM_RC_KEY</c>; an unsupported scheme hash
    /// algorithm is <c>TPM_RC_HASH</c>. The signing scheme is dispatched on the signer's key type —
    /// <c>TPM_ALG_ECDSA</c> for an ECC key, <c>TPM_ALG_RSASSA</c>/<c>TPM_ALG_RSAPSS</c> for an RSA key
    /// (mirroring <c>OnSign</c>) — and a scheme incompatible with the key's type is <c>TPM_RC_SCHEME</c>. The
    /// attestation needs an effect (compute the Qualified Names, marshal, and sign), so the transition resolves
    /// both objects, folds their retained fields into the matching action, and leaves no response yet;
    /// <c>OnObjectCertified</c> frames the result. No handle is allocated — <c>TPM2_Certify()</c> returns no
    /// object handle.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_Certify()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the certify action, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnCertify(TpmSimulatorState state, TpmCertifyRequested request)
    {
        if(!state.TransientObjects.TryGetValue(request.ObjectHandle, out TransientKeyState? subject))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Certify, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        if(!state.TransientObjects.TryGetValue(request.SignHandle, out TransientKeyState? signer))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Certify, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        //Both slots' authorizations resolve in session order after the handles (Part 3, clause 5.6), each with
        //its own DA/Lockout gate (check 3) then the fixed-time trailing-zero-stripped compare against that
        //entity's retained authValue (Part 1, clause 17.6.4.3) — the OnCreateSealedObject discipline. Session 0
        //authorizes the certified object (ADMIN role), session 1 the signing key (USER role) — Part 3, clause
        //18.2, Table 89. Only the USER-role slot carries the check 7.1 userWithAuth gate below; the ADMIN slot's
        //own session-shape rule is check 5.1 (a password is admissible only while the object's adminWithPolicy
        //attribute is CLEAR), which this arm does not model — the ADMIN slot's compare runs regardless of that
        //attribute.
        if(subject.IsDaProtected && state.IsInLockout)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Certify, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        if(!CryptographicOperations.FixedTimeEquals(
            StripTrailingZeros(request.SuppliedObjectPassword.AsReadOnlySpan()),
            StripTrailingZeros(subject.AuthValue.AsReadOnlySpan())))
        {
            return RejectSessionAuthFailure(state, TpmCcConstants.TPM_CC_Certify, sessionIndex: 0, subject.IsDaProtected, request);
        }

        if(signer.IsDaProtected && state.IsInLockout)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Certify, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        //USER role gate (Part 3, clause 5.6, check 7.1): a signer whose userWithAuth attribute is CLEAR may
        //have its USER role authorized only by a policy session, never by a password — refused before the
        //compare below, uncharged, per clause 5.6's mandatory check order.
        if((signer.Attributes & TpmaObject.USER_WITH_AUTH) == 0)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Certify, TpmRcConstants.TPM_RC_POLICY_FAIL, request);
        }

        if(!CryptographicOperations.FixedTimeEquals(
            StripTrailingZeros(request.SuppliedSignPassword.AsReadOnlySpan()),
            StripTrailingZeros(signer.AuthValue.AsReadOnlySpan())))
        {
            return RejectSessionAuthFailure(state, TpmCcConstants.TPM_CC_Certify, sessionIndex: 1, signer.IsDaProtected, request);
        }

        if(request.QualifyingData.Length > Tpm2bData.MaxSize)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Certify, TpmRcConstants.TPM_RC_SIZE, request);
        }

        if(!CanSign(signer.Attributes))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Certify, TpmRcConstants.TPM_RC_KEY, request);
        }

        if(!IsSupportedAttestHashAlg(request.SchemeHashAlg))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Certify, TpmRcConstants.TPM_RC_HASH, request);
        }

        TpmsClockInfo clockSnapshot = new(state.Clock, state.ResetCount, state.RestartCount, state.ClockSafe);
        TpmAction? action = (signer.KeyType.Value, request.SignatureScheme.Value) switch
        {
            (TpmAlgIdConstants.TPM_ALG_RSA, TpmAlgIdConstants.TPM_ALG_RSASSA or TpmAlgIdConstants.TPM_ALG_RSAPSS) =>
                new TpmRsaCertifyAction(
                    subject.Name, subject.Hierarchy, signer.Name, signer.Hierarchy, request.QualifyingData, signer.PrivateKey, request.SignatureScheme, request.SchemeHashAlg, clockSnapshot),
            (TpmAlgIdConstants.TPM_ALG_ECC, TpmAlgIdConstants.TPM_ALG_ECDSA) =>
                new TpmCertifyAction(
                    subject.Name, subject.Hierarchy, signer.Name, signer.Hierarchy, request.QualifyingData, signer.PrivateKey, signer.Curve, request.SignatureScheme, request.SchemeHashAlg, clockSnapshot),
            _ => null
        };

        if(action is null)
        {
            //A scheme incompatible with the signer's key type — e.g. an ECDSA scheme against an RSA key, or vice
            //versa — fails closed rather than silently coercing to the key's native scheme.
            return Reject(state, TpmCcConstants.TPM_CC_Certify, TpmRcConstants.TPM_RC_SCHEME, request);
        }

        //The transition is both password carriers' terminal owner — the per-slot compares were their only use —
        //while the qualifying data has transferred into the action the effect releases it from.
        request.SuppliedObjectPassword.Dispose();
        request.SuppliedSignPassword.Dispose();

        return Transition(
            state with
            {
                NextAction = action,
                ResponseIntent = null
            },
            "Certify:Requested");
    }

    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnObjectCertified(TpmSimulatorState state, TpmObjectCertified certified) =>
        Transition(
            state with
            {
                NextAction = NullAction.Instance,
                ResponseIntent = new TpmCertifyResponse(
                    TpmRcConstants.TPM_RC_SUCCESS, certified.CertifyInfo, certified.Signature)
            },
            "Certify:Completed");

    /// <summary>
    /// Has a signing key attest that objectHandle was created by the TPM with a given creation hash,
    /// re-verifying the caller-supplied creation ticket, for <c>TPM2_CertifyCreation()</c> (Part 3, clause
    /// 18.3).
    /// </summary>
    /// <remarks>
    /// Only signHandle and objectHandle need resolve to loaded transient objects; a missing one is
    /// <c>TPM_RC_HANDLE</c> — this scopes objectHandle to <c>TPM2_CreatePrimary()</c>/<c>TPM2_Create()</c>-minted
    /// keys (the TransientObjects table), matching the actual attestation-key use case; a
    /// <c>TPM2_Load()</c>-ed sealed object (which retains no Name) is out of scope and likewise answers
    /// <c>TPM_RC_HANDLE</c>, since it lives in a different table. qualifyingData over the <c>TPM2B_DATA</c>
    /// bound (Part 2, clause 10.4.3) is <c>TPM_RC_SIZE</c>; a signer missing the sign attribute (Part 3, clause
    /// 18.1) is <c>TPM_RC_KEY</c>; an unsupported scheme hash algorithm is <c>TPM_RC_HASH</c>. The signing
    /// scheme is dispatched on the signer's key type exactly as <c>OnCertify</c> does, and a scheme incompatible
    /// with the key's type is <c>TPM_RC_SCHEME</c>. The creation-ticket re-verification needs the asynchronous
    /// digest/HMAC seam, so it is folded into the effect
    /// (<c>TpmCertifyCreationAction</c>/<c>TpmRsaCertifyCreationAction</c>) rather than checked here; the
    /// transition resolves both objects, folds their retained fields into the matching action, and leaves no
    /// response yet.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_CertifyCreation()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the certify action, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnCertifyCreation(TpmSimulatorState state, TpmCertifyCreationRequested request)
    {
        if(!state.TransientObjects.TryGetValue(request.SignHandle, out TransientKeyState? signer))
        {
            return Reject(state, TpmCcConstants.TPM_CC_CertifyCreation, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        if(!state.TransientObjects.TryGetValue(request.ObjectHandle, out TransientKeyState? subject))
        {
            return Reject(state, TpmCcConstants.TPM_CC_CertifyCreation, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        //The sign slot's USER-role authorization (Part 3, clause 18.3: @signHandle, Auth Index 1, Auth Role
        //USER; objectHandle carries no authorization): DA/Lockout gate (clause 5.6, check 3) then the
        //fixed-time trailing-zero-stripped compare against the signer's retained authValue (Part 1, clause
        //17.6.4.3) — the OnCreateSealedObject discipline.
        if(signer.IsDaProtected && state.IsInLockout)
        {
            return Reject(state, TpmCcConstants.TPM_CC_CertifyCreation, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        //USER role gate (Part 3, clause 5.6, check 7.1): a signer whose userWithAuth attribute is CLEAR may
        //have its USER role authorized only by a policy session, never by a password — refused before the
        //compare below, uncharged, per clause 5.6's mandatory check order.
        if((signer.Attributes & TpmaObject.USER_WITH_AUTH) == 0)
        {
            return Reject(state, TpmCcConstants.TPM_CC_CertifyCreation, TpmRcConstants.TPM_RC_POLICY_FAIL, request);
        }

        if(!CryptographicOperations.FixedTimeEquals(
            StripTrailingZeros(request.SuppliedSignPassword.AsReadOnlySpan()),
            StripTrailingZeros(signer.AuthValue.AsReadOnlySpan())))
        {
            return RejectSessionAuthFailure(state, TpmCcConstants.TPM_CC_CertifyCreation, sessionIndex: 0, signer.IsDaProtected, request);
        }

        if(request.QualifyingData.Length > Tpm2bData.MaxSize)
        {
            return Reject(state, TpmCcConstants.TPM_CC_CertifyCreation, TpmRcConstants.TPM_RC_SIZE, request);
        }

        if(!CanSign(signer.Attributes))
        {
            return Reject(state, TpmCcConstants.TPM_CC_CertifyCreation, TpmRcConstants.TPM_RC_KEY, request);
        }

        if(!IsSupportedAttestHashAlg(request.SchemeHashAlg))
        {
            return Reject(state, TpmCcConstants.TPM_CC_CertifyCreation, TpmRcConstants.TPM_RC_HASH, request);
        }

        TpmsClockInfo clockSnapshot = new(state.Clock, state.ResetCount, state.RestartCount, state.ClockSafe);
        TpmAction? action = (signer.KeyType.Value, request.SignatureScheme.Value) switch
        {
            (TpmAlgIdConstants.TPM_ALG_RSA, TpmAlgIdConstants.TPM_ALG_RSASSA or TpmAlgIdConstants.TPM_ALG_RSAPSS) =>
                new TpmRsaCertifyCreationAction(
                    subject.Name, subject.Hierarchy, signer.Name, signer.Hierarchy, request.QualifyingData, request.CreationHash,
                    request.TicketDigest, signer.PrivateKey, request.SignatureScheme, request.SchemeHashAlg, clockSnapshot),
            (TpmAlgIdConstants.TPM_ALG_ECC, TpmAlgIdConstants.TPM_ALG_ECDSA) =>
                new TpmCertifyCreationAction(
                    subject.Name, subject.Hierarchy, signer.Name, signer.Hierarchy, request.QualifyingData, request.CreationHash,
                    request.TicketDigest, signer.PrivateKey, signer.Curve, request.SignatureScheme, request.SchemeHashAlg, clockSnapshot),
            _ => null
        };

        if(action is null)
        {
            //A scheme incompatible with the signer's key type — e.g. an ECDSA scheme against an RSA key, or vice
            //versa — fails closed rather than silently coercing to the key's native scheme.
            return Reject(state, TpmCcConstants.TPM_CC_CertifyCreation, TpmRcConstants.TPM_RC_SCHEME, request);
        }

        //The transition is the password carrier's terminal owner — the sign-slot compare was its only use. The
        //qualifying data, the creation hash, and the ticket digest transfer into the action, whose effect
        //releases them.
        request.SuppliedSignPassword.Dispose();

        return Transition(
            state with
            {
                NextAction = action,
                ResponseIntent = null
            },
            "CertifyCreation:Requested");
    }

    /// <summary>
    /// Frames the <c>TPM2_CertifyCreation()</c> response the effect produced: the signed attestation on a
    /// reproduced creation ticket, or the ticket-mismatch rejection (<c>TPM_RC_TICKET</c>) the effect's
    /// constant-time comparison found — mirroring <c>OnCredentialActivated</c>'s success/rejection split, the
    /// only other place a rejection is decided inside the effect rather than the pure transition.
    /// </summary>
    /// <param name="state">The state to transition from.</param>
    /// <param name="certified">The effect's result carrying the attestation or the ticket-mismatch outcome.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnObjectCreationCertified(TpmSimulatorState state, TpmObjectCreationCertified certified) =>
        certified.CertifyInfo is { } certifyInfo
            ? Transition(
                state with
                {
                    NextAction = NullAction.Instance,
                    ResponseIntent = new TpmCertifyCreationResponse(
                        TpmRcConstants.TPM_RC_SUCCESS, certifyInfo, certified.Signature!)
                },
                "CertifyCreation:Completed")
            : Transition(
                state with
                {
                    NextAction = NullAction.Instance,
                    ResponseIntent = new TpmHeaderOnlyResponse(certified.ResponseCode)
                },
                "CertifyCreation:Rejected");

    /// <summary>
    /// Wraps a credential secret to a credential key's public area, bound to an object's Name, for
    /// <c>TPM2_MakeCredential()</c> (Part 3, clause 12.6; the credential protection scheme is Part 1, clause
    /// 24).
    /// </summary>
    /// <remarks>
    /// The credential key (the endorsement key) must be a loaded restricted-decrypt Storage Key, ECC or RSA
    /// (Part 3, clause 12.6: "Storage Key" is an attribute-shaped predicate, not an algorithm-shaped one),
    /// carrying the exported public key material its algorithm needs; a missing handle is <c>TPM_RC_HANDLE</c>
    /// and a wrong key type/shape is <c>TPM_RC_TYPE</c>. The seed exchange (ECDH+KDFe for ECC, a fresh random
    /// seed OAEP-encrypted for RSA), the shared KDFa derivations, symmetric encryption, and outer HMAC all need
    /// the matching signing backend and the registered digest/HMAC seams, so the transition dispatches on the
    /// credential key's type — mirroring <c>OnCertify</c> — and folds its retained fields into the matching
    /// action, leaving no response yet; <c>OnCredentialMade</c> frames the result. MakeCredential takes no
    /// authorization, so no session is consulted.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_MakeCredential()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the wrap action, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnMakeCredential(TpmSimulatorState state, TpmMakeCredentialRequested request)
    {
        if(!state.TransientObjects.TryGetValue(request.KeyHandle, out TransientKeyState? key))
        {
            return Reject(state, TpmCcConstants.TPM_CC_MakeCredential, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        if(!IsStorageParent(key.Attributes))
        {
            return Reject(state, TpmCcConstants.TPM_CC_MakeCredential, TpmRcConstants.TPM_RC_TYPE, request);
        }

        TpmAction? action = key.KeyType.Value switch
        {
            TpmAlgIdConstants.TPM_ALG_ECC when !key.PublicPoint.IsEmpty =>
                new TpmMakeCredentialAction(request.Credential, request.ObjectName, key.PublicPoint, key.Curve, TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256)),
            TpmAlgIdConstants.TPM_ALG_RSA when !key.PublicModulus.IsEmpty =>
                new TpmRsaMakeCredentialAction(request.Credential, request.ObjectName, key.PublicModulus, TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256)),
            _ => null
        };

        if(action is null)
        {
            //Either a key type this credential-protection slice does not model, or the right type but carrying
            //no exported public key material (the storage-parent effect that would have populated it never ran).
            //No arm above built an action, so the object Name never transferred and the request still owns it.
            return Reject(state, TpmCcConstants.TPM_CC_MakeCredential, TpmRcConstants.TPM_RC_TYPE, request);
        }

        return Transition(
            state with
            {
                NextAction = action,
                ResponseIntent = null
            },
            "MakeCredential:Requested");
    }

    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnCredentialMade(TpmSimulatorState state, TpmCredentialMade made) =>
        Transition(
            state with
            {
                NextAction = NullAction.Instance,
                ResponseIntent = new TpmMakeCredentialResponse(
                    TpmRcConstants.TPM_RC_SUCCESS, made.CredentialBlob, made.Secret)
            },
            "MakeCredential:Completed");

    /// <summary>
    /// Recovers a wrapped credential for <c>TPM2_ActivateCredential()</c>, proving the activate object (the
    /// attestation key) and the credential key (the endorsement key) co-reside in one TPM (Part 3, clause 12.5).
    /// </summary>
    /// <remarks>
    /// Both handles must resolve to loaded objects (a missing one is <c>TPM_RC_HANDLE</c>); the credential key
    /// must be a restricted-decrypt Storage Key, ECC or RSA, carrying both its retained private key and the
    /// exported public key material its algorithm needs (else <c>TPM_RC_TYPE</c>) —
    /// <c>TryResolveActivateCredentialObjects</c> shares this plus the ADMIN-role fail-closed check with
    /// <c>OnActivateCredentialOverSession</c>. The USER-role gate here is form-specific: a password session on
    /// @keyHandle authorizes USER role only when the key's userWithAuth attribute is SET (Part 3, clause 5.6); a
    /// standard endorsement key clears it, so a password session there is <c>TPM_RC_POLICY_FAIL</c> and must
    /// instead go through <c>OnActivateCredentialOverSession</c>. The seed recovery and integrity check need the
    /// matching signing backend and the digest/HMAC seams, so the transition dispatches on the credential key's
    /// type through <c>BuildActivateCredentialAction</c> and leaves no response yet;
    /// <c>OnCredentialActivated</c> frames the recovered secret or the integrity-failure rejection. Both slots'
    /// supplied passwords are compared against their entities' retained authValues — both sides
    /// trailing-zero-stripped (Part 1, clause 17.6.4.3), in fixed time, each behind its own DA/Lockout gate —
    /// and a mismatch registers through <c>RejectSessionAuthFailure</c> with that slot's session-encoded index.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_ActivateCredential()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the recovery action, or a rejection.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The resolved records are borrowed references to entries the live automaton state owns and create no carrier here; the request's two owned password carriers are released exactly once — every refusing arm through the disposing Reject/RejectSessionAuthFailure overloads, the success arm by its terminal release before the transition.")]
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnActivateCredential(TpmSimulatorState state, TpmActivateCredentialRequested request)
    {
        if(!TryResolveActivateCredentialObjects(state, request.ActivateHandle.Value, request.KeyHandle.Value, out TransientKeyState? activateObject, out TransientKeyState? key, out TpmRcConstants rejectionCode))
        {
            return Reject(state, TpmCcConstants.TPM_CC_ActivateCredential, rejectionCode, request);
        }

        //Session 0's ADMIN-role authorization of the activate object (Part 3, clause 12.5, Table 26): DA/Lockout
        //gate (clause 5.6, check 3) then the fixed-time trailing-zero-stripped compare against the object's
        //retained authValue (Part 1, clause 17.6.4.3) — the OnCreateSealedObject discipline. The resolver's
        //adminWithPolicy fail-closed check has already run, so a password is an admissible session shape here.
        if(activateObject.IsDaProtected && state.IsInLockout)
        {
            return Reject(state, TpmCcConstants.TPM_CC_ActivateCredential, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        if(!CryptographicOperations.FixedTimeEquals(
            StripTrailingZeros(request.SuppliedActivatePassword.AsReadOnlySpan()),
            StripTrailingZeros(activateObject.AuthValue.AsReadOnlySpan())))
        {
            return RejectSessionAuthFailure(state, TpmCcConstants.TPM_CC_ActivateCredential, sessionIndex: 0, activateObject.IsDaProtected, request);
        }

        //Session 1's USER-role authorization of the credential key, same discipline as session 0's arm above:
        //the DA/Lockout gate (clause 5.6, check 3) runs first — clause 5.6's checks run in their numbered
        //order, so a locked-out TPM answers TPM_RC_LOCKOUT for a DA-protected key even when the key's
        //session shape could never authorize it.
        if(key.IsDaProtected && state.IsInLockout)
        {
            return Reject(state, TpmCcConstants.TPM_CC_ActivateCredential, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        //USER role gate (Part 3, clause 5.6, check 7.1): "If the entity being authorized is an object and its
        //userWithAuth attribute is CLEAR, then the associated authorization session is a policy session
        //(TPM_RC_POLICY_FAIL)." Objects with userWithAuth SET keep today's behavior. The session-shape gate
        //precedes the key's value compare, the OnUnseal ordering, so a userWithAuth-CLEAR key never has its
        //authValue tested by a password at all.
        if((key.Attributes & TpmaObject.USER_WITH_AUTH) == 0)
        {
            return Reject(state, TpmCcConstants.TPM_CC_ActivateCredential, TpmRcConstants.TPM_RC_POLICY_FAIL, request);
        }

        if(!CryptographicOperations.FixedTimeEquals(
            StripTrailingZeros(request.SuppliedKeyPassword.AsReadOnlySpan()),
            StripTrailingZeros(key.AuthValue.AsReadOnlySpan())))
        {
            return RejectSessionAuthFailure(state, TpmCcConstants.TPM_CC_ActivateCredential, sessionIndex: 1, key.IsDaProtected, request);
        }

        //The transition is both password carriers' terminal owner — the per-slot compares were their only use.
        request.SuppliedActivatePassword.Dispose();
        request.SuppliedKeyPassword.Dispose();

        return Transition(
            state with
            {
                NextAction = BuildActivateCredentialAction(activateObject, key, request.CredentialBlob, request.Secret),
                ResponseIntent = null
            },
            "ActivateCredential:Requested");
    }

    /// <summary>
    /// Dispatches <c>TPM2_ActivateCredential()</c> whose @keyHandle session is a policy session
    /// (<c>TpmActivateCredentialOverSessionRequested</c>) — the form a standard endorsement key (userWithAuth
    /// CLEAR, authPolicy = "PolicyA") requires.
    /// </summary>
    /// <remarks>
    /// Shares handle resolution, the ADMIN-role fail-closed check, and the key type/shape check with
    /// <c>OnActivateCredential</c> via <c>TryResolveActivateCredentialObjects</c>; only the USER-role gate
    /// differs (a policy-digest comparison here instead of an attribute check). Mirrors
    /// <c>OnUnsealOverSessions</c>'s policy gate (Part 3, clause 5.6, check 8.4): the policy
    /// session must resolve (else <c>TPM_RC_HANDLE</c>), must not be a trial session (Part 1, clause 19.3: a
    /// trial session authorizes nothing), and its accumulated policyDigest must reproduce the key's authPolicy
    /// when one is set.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed policy-session-authorized <c>TPM2_ActivateCredential()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the recovery action, or a rejection.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The resolved records are borrowed references to entries the live automaton state owns and create no carrier here; the request's owned activate-password carrier is released exactly once — every refusing arm through the disposing Reject/RejectSessionAuthFailure overloads, the success arm by its terminal release before the transition.")]
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnActivateCredentialOverSession(TpmSimulatorState state, TpmActivateCredentialOverSessionRequested request)
    {
        if(!TryResolveActivateCredentialObjects(state, request.ActivateHandle.Value, request.KeyHandle.Value, out TransientKeyState? activateObject, out TransientKeyState? key, out TpmRcConstants rejectionCode))
        {
            return Reject(state, TpmCcConstants.TPM_CC_ActivateCredential, rejectionCode, request);
        }

        //Session 0's ADMIN-role password authorization of the activate object resolves first, in session order
        //(Part 3, clause 5.6): DA/Lockout gate (check 3) then the fixed-time trailing-zero-stripped compare
        //against the object's retained authValue (Part 1, clause 17.6.4.3) — the same arm the plain form runs;
        //only session 1's authorization differs between the forms.
        if(activateObject.IsDaProtected && state.IsInLockout)
        {
            return Reject(state, TpmCcConstants.TPM_CC_ActivateCredential, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        if(!CryptographicOperations.FixedTimeEquals(
            StripTrailingZeros(request.SuppliedActivatePassword.AsReadOnlySpan()),
            StripTrailingZeros(activateObject.AuthValue.AsReadOnlySpan())))
        {
            return RejectSessionAuthFailure(state, TpmCcConstants.TPM_CC_ActivateCredential, sessionIndex: 0, activateObject.IsDaProtected, request);
        }

        //The wire slot is TPMI_SH_AUTH_SESSION (Part 2, clause 10.13.2, Table 153), so the handle reaches here
        //unnarrowed; only a policy session is modelled on this arm, and the narrowing is exactly this lookup —
        //a handle naming no live policy session is the same TPM_RC_HANDLE an unknown policy handle answers.
        if(!state.PolicySessions.TryGetValue(TpmiShPolicy.FromValue(request.KeyPolicySession.Value), out PolicySessionState? policySession))
        {
            return Reject(state, TpmCcConstants.TPM_CC_ActivateCredential, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        if(policySession.IsTrial)
        {
            return Reject(state, TpmCcConstants.TPM_CC_ActivateCredential, TpmRcConstants.TPM_RC_POLICY_FAIL, request);
        }

        //Even though this authorization is a policy-digest match that tests no authValue, the session's own key
        //folded the bind entity's authValue when it started, and use of such a session is subject to DA
        //"regardless of the DA status of the entity being authorized" (Part 3, clause 11.1.1) — so a session
        //bound to a DA-protected entity is refused here while the TPM is in Lockout mode, before any policy
        //evaluation, exactly as on every other session-authorized arm.
        if(IsBoundSessionLockedOut(state, policySession))
        {
            return Reject(state, TpmCcConstants.TPM_CC_ActivateCredential, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        //Policy gate: a satisfying policy session authorizes USER role regardless of userWithAuth (Part 1, clause
        //19.2: "A policy session that satisfies the authPolicy of the entity may be used regardless of the setting
        //of userWithAuth."). An empty authPolicy leaves the key outside the policy path entirely, mirroring
        //OnUnsealOverSessions's identical opt-in guard.
        if(!key.AuthPolicy.IsEmpty
            && !key.AuthPolicy.AsReadOnlySpan().SequenceEqual(policySession.PolicyDigest.AsReadOnlySpan()))
        {
            return Reject(state, TpmCcConstants.TPM_CC_ActivateCredential, TpmRcConstants.TPM_RC_POLICY_FAIL, request);
        }

        //The transition is the password carrier's terminal owner — the activate-slot compare was its only use.
        request.SuppliedActivatePassword.Dispose();

        //The effect and response need ZERO changes from the password form: TpmActivateCredentialResponse is already
        //framed TPM_ST_NO_SESSIONS, and the executor accepts a no-sessions response regardless of how many sessions
        //authorized the request (the same simplification OnUnsealOverSessions's no-encrypt-session branch relies on).
        return Transition(
            state with
            {
                NextAction = BuildActivateCredentialAction(activateObject, key, request.CredentialBlob, request.Secret),
                ResponseIntent = null
            },
            "ActivateCredentialOverSession:Requested");
    }

    /// <summary>
    /// Shared by <see cref="OnActivateCredential"/> and <see cref="OnActivateCredentialOverSession"/>: resolves
    /// both handles (<c>TPM_RC_HANDLE</c> if either is unloaded), fails closed on an ADMIN-role policy
    /// requirement this slice does not model on @activateHandle (Part 3, clause 5.6, check 5.1: adminWithPolicy SET
    /// requires a policy session there — the standard endorsement-key templates set the bit, so an EK-shaped
    /// object presented at @activateHandle is refused here), and checks the credential key's type/shape (Part 1, clause 24: a
    /// restricted-decrypt Storage Key, ECC or RSA, carrying both its retained private key and the exported
    /// public key material its algorithm needs).
    /// </summary>
    /// <param name="state">The current simulator state.</param>
    /// <param name="activateHandle">The handle of the activate object (the attestation key).</param>
    /// <param name="keyHandle">The handle of the credential key (the endorsement key).</param>
    /// <param name="activateObject">The resolved activate object, when resolution succeeds.</param>
    /// <param name="key">The resolved credential key, when resolution succeeds.</param>
    /// <param name="rejectionCode">The rejection code, when resolution fails.</param>
    /// <returns><see langword="true"/> when both handles resolved and the credential key's type/shape check passed.</returns>
    private static bool TryResolveActivateCredentialObjects(
        TpmSimulatorState state,
        uint activateHandle,
        uint keyHandle,
        [NotNullWhen(true)] out TransientKeyState? activateObject,
        [NotNullWhen(true)] out TransientKeyState? key,
        out TpmRcConstants rejectionCode)
    {
        key = null;
        rejectionCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(!state.TransientObjects.TryGetValue(TpmiDhObject.FromValue(activateHandle), out activateObject))
        {
            rejectionCode = TpmRcConstants.TPM_RC_HANDLE;

            return false;
        }

        if(!state.TransientObjects.TryGetValue(TpmiDhObject.FromValue(keyHandle), out key))
        {
            rejectionCode = TpmRcConstants.TPM_RC_HANDLE;

            return false;
        }

        if((activateObject.Attributes & TpmaObject.ADMIN_WITH_POLICY) != 0)
        {
            rejectionCode = TpmRcConstants.TPM_RC_AUTH_TYPE;

            return false;
        }

        bool hasCredentialKeyMaterial = key.KeyType.Value switch
        {
            TpmAlgIdConstants.TPM_ALG_ECC => !key.PublicPoint.IsEmpty,
            TpmAlgIdConstants.TPM_ALG_RSA => !key.PublicModulus.IsEmpty,
            _ => false
        };

        if(!hasCredentialKeyMaterial || !IsStorageParent(key.Attributes) || key.PrivateKey.IsEmpty)
        {
            rejectionCode = TpmRcConstants.TPM_RC_TYPE;

            return false;
        }

        return true;
    }

    /// <summary>
    /// Builds the RSA/ECC <see cref="TpmAction"/> for <c>TPM2_ActivateCredential()</c> from the resolved
    /// activate object and credential key, dispatching on the credential key's type (mirrors
    /// <see cref="OnCertify"/>'s key-type dispatch). Shared by <see cref="OnActivateCredential"/> and
    /// <see cref="OnActivateCredentialOverSession"/> so both authorization forms drive the same RSA/ECC
    /// seed-recovery effect.
    /// </summary>
    /// <param name="activateObject">The resolved activate object (the attestation key), whose Name re-keys the credential.</param>
    /// <param name="key">The resolved credential key (the endorsement key); <see cref="TryResolveActivateCredentialObjects"/> has already gate-checked its type and public key material.</param>
    /// <param name="credentialBlob">The credential blob (<c>TPMS_ID_OBJECT</c>) from the request.</param>
    /// <param name="secret">The encrypted seed transport (<c>TPM2B_ENCRYPTED_SECRET</c>) from the request.</param>
    /// <returns>A <see cref="TpmRsaActivateCredentialAction"/> for an RSA credential key, otherwise a <see cref="TpmActivateCredentialAction"/>.</returns>
    private static TpmAction BuildActivateCredentialAction(
        TransientKeyState activateObject, TransientKeyState key, ReadOnlyMemory<byte> credentialBlob, ReadOnlyMemory<byte> secret) =>
        key.KeyType.Value switch
        {
            TpmAlgIdConstants.TPM_ALG_RSA => new TpmRsaActivateCredentialAction(
                credentialBlob, secret, activateObject.Name, key.PrivateKey, TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256)),
            _ => new TpmActivateCredentialAction(
                credentialBlob, secret, activateObject.Name, key.PrivateKey, key.PublicPoint, key.Curve, TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256))
        };

    /// <summary>
    /// Frames the <c>TPM2_ActivateCredential()</c> response the effect produced: the recovered secret on
    /// success, or the integrity-failure rejection (<c>TPM_RC_INTEGRITY</c>) when the credential's outer HMAC
    /// did not verify against the activate object's Name (Part 3, clause 12.5) — the "wrong object" case the
    /// negative test turns on.
    /// </summary>
    /// <param name="state">The state to transition from.</param>
    /// <param name="activated">The effect's result carrying the recovered secret or the integrity-failure outcome.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnCredentialActivated(TpmSimulatorState state, TpmCredentialActivated activated) =>
        activated.CertInfo is { } certInfo
            ? Transition(
                state with
                {
                    NextAction = NullAction.Instance,
                    ResponseIntent = new TpmActivateCredentialResponse(activated.ResponseCode, certInfo)
                },
                "ActivateCredential:Completed")
            : Transition(
                state with
                {
                    NextAction = NullAction.Instance,
                    ResponseIntent = new TpmHeaderOnlyResponse(activated.ResponseCode)
                },
                "ActivateCredential:Rejected");

    /// <summary>
    /// Returns the current values of the selected PCRs for <c>TPM2_PCR_Read()</c> (Part 3, clause 22.4).
    /// </summary>
    /// <remarks>
    /// A pure, state-derived response — no action layer and no authorization: the values are read straight from
    /// the durable SHA-256 bank and framed alongside the echoed selection and
    /// <see cref="TpmSimulatorState.PcrUpdateCounter"/>. The counter is the TPM-wide PCR-change count, not a
    /// per-selection one: a caller reads it here and compares it after the fact to learn that some PCR moved,
    /// which is why <c>TPM2_Clear()</c> increments it (TPM 2.0 Library Part 3, clause 24.6.1) even though it
    /// extends nothing. This simulator models no <c>TPM2_PCR_Extend()</c>, so a TPM that has never been cleared
    /// reports zero.
    /// </remarks>
    /// <param name="state">The state to derive the response from.</param>
    /// <param name="request">The parsed <c>TPM2_PCR_Read()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnPcrRead(TpmSimulatorState state, TpmPcrReadRequested request)
    {
        ImmutableArray<ReadOnlyMemory<byte>> values = GatherSelectedPcrValues(state.Sha256PcrBank, request.SelectionBytes);

        return Transition(
            state with { ResponseIntent = new TpmPcrReadResponse(TpmRcConstants.TPM_RC_SUCCESS, state.PcrUpdateCounter, request.SelectionBytes, values) },
            "PcrRead");
    }

    /// <summary>
    /// Has a signing key attest the composite digest of a selected set of PCRs, over a caller nonce, for
    /// <c>TPM2_Quote()</c> (Part 3, clause 18.4).
    /// </summary>
    /// <remarks>
    /// The signHandle must resolve to a loaded transient object; a missing one is <c>TPM_RC_HANDLE</c>.
    /// qualifyingData over the <c>TPM2B_DATA</c> bound (Part 2, clause 10.4.3) is <c>TPM_RC_SIZE</c>; a signer
    /// missing the sign attribute (Part 3, clause 18.1) is <c>TPM_RC_KEY</c>; an unsupported scheme hash
    /// algorithm is <c>TPM_RC_HASH</c>. The signing scheme is dispatched on the signer's key type —
    /// <c>TPM_ALG_ECDSA</c> for an ECC key, <c>TPM_ALG_RSASSA</c>/<c>TPM_ALG_RSAPSS</c> for an RSA key
    /// (mirroring <c>OnCertify</c>) — and a scheme incompatible with the key's type is <c>TPM_RC_SCHEME</c>. The
    /// attestation needs an effect (compute the composite, marshal, and sign), so the transition resolves the
    /// signer, gathers the selected PCR values from the durable bank, folds them into the matching action, and
    /// leaves no response yet; <c>OnObjectQuoted</c> frames the result. No handle is allocated —
    /// <c>TPM2_Quote()</c> returns no object handle.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_Quote()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the quote action, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnQuote(TpmSimulatorState state, TpmQuoteRequested request)
    {
        if(!state.TransientObjects.TryGetValue(request.SignHandle, out TransientKeyState? signer))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Quote, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        //The sign slot's USER-role authorization (Part 3, clause 18.4: @signHandle, Auth Index 1, Auth Role
        //USER): DA/Lockout gate (clause 5.6, check 3) then the fixed-time trailing-zero-stripped compare
        //against the signer's retained authValue (Part 1, clause 17.6.4.3) — the OnCreateSealedObject
        //discipline.
        if(signer.IsDaProtected && state.IsInLockout)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Quote, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        //USER role gate (Part 3, clause 5.6, check 7.1): a signer whose userWithAuth attribute is CLEAR may
        //have its USER role authorized only by a policy session, never by a password — refused before the
        //compare below, uncharged, per clause 5.6's mandatory check order.
        if((signer.Attributes & TpmaObject.USER_WITH_AUTH) == 0)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Quote, TpmRcConstants.TPM_RC_POLICY_FAIL, request);
        }

        if(!CryptographicOperations.FixedTimeEquals(
            StripTrailingZeros(request.SuppliedSignPassword.AsReadOnlySpan()),
            StripTrailingZeros(signer.AuthValue.AsReadOnlySpan())))
        {
            return RejectSessionAuthFailure(state, TpmCcConstants.TPM_CC_Quote, sessionIndex: 0, signer.IsDaProtected, request);
        }

        if(request.QualifyingData.Length > Tpm2bData.MaxSize)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Quote, TpmRcConstants.TPM_RC_SIZE, request);
        }

        if(!CanSign(signer.Attributes))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Quote, TpmRcConstants.TPM_RC_KEY, request);
        }

        if(!IsSupportedAttestHashAlg(request.SchemeHashAlg))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Quote, TpmRcConstants.TPM_RC_HASH, request);
        }

        //TPMS_QUOTE_INFO.pcrSelect carries "information on algID, PCR selected and digest" (Part 2, clause 10.12.4,
        //Table 143) — the selection the pcrDigest standing beside it was taken over, so the attested list is the
        //one the digest actually covers, not the one the caller asked for: a bit naming a register this model does
        //not hold, and every bit of a bank it has not allocated, is cleared before the selection is gathered over
        //and before it is echoed. The reference does the same filtering in place inside PCRComputeCurrentDigest
        //and then copies the MODIFIED list into the attestation. It happens here, where the model's bank
        //allocation is in hand, rather than in the effect: the mask is written into the carrier's own rented
        //storage, so no pool is needed and the marshaled width is unchanged. The gather below already skips
        //unheld indexes and unallocated banks, so the composite digest is untouched by it.
        ReadOnlySpan<TpmAlgIdConstants> implementedBanks = [state.Sha256PcrBank.HashAlgorithm];
        request.PcrSelection.RetainImplementedPcrs(implementedBanks, PcrBankState.PcrCount);

        ImmutableArray<ReadOnlyMemory<byte>> pcrValues = GatherSelectedPcrValues(state.Sha256PcrBank, request.PcrSelection);
        TpmsClockInfo clockSnapshot = new(state.Clock, state.ResetCount, state.RestartCount, state.ClockSafe);

        TpmAction? action = (signer.KeyType.Value, request.SignatureScheme.Value) switch
        {
            (TpmAlgIdConstants.TPM_ALG_RSA, TpmAlgIdConstants.TPM_ALG_RSASSA or TpmAlgIdConstants.TPM_ALG_RSAPSS) =>
                new TpmRsaQuoteAction(
                    signer.Name, signer.Hierarchy, request.QualifyingData, signer.PrivateKey, request.SignatureScheme, request.SchemeHashAlg, request.PcrSelection, pcrValues, clockSnapshot),
            (TpmAlgIdConstants.TPM_ALG_ECC, TpmAlgIdConstants.TPM_ALG_ECDSA) =>
                new TpmQuoteAction(
                    signer.Name, signer.Hierarchy, request.QualifyingData, signer.PrivateKey, signer.Curve, request.SignatureScheme, request.SchemeHashAlg, request.PcrSelection, pcrValues, clockSnapshot),
            _ => null
        };

        if(action is null)
        {
            //A scheme incompatible with the signer's key type — e.g. an ECDSA scheme against an RSA key, or vice
            //versa — fails closed rather than silently coercing to the key's native scheme (mirrors OnCertify).
            return Reject(state, TpmCcConstants.TPM_CC_Quote, TpmRcConstants.TPM_RC_SCHEME, request);
        }

        //The transition is the password carrier's terminal owner — the sign-slot compare was its only use. The
        //qualifying data and the PCR selection transfer into the action, whose effect releases them.
        request.SuppliedSignPassword.Dispose();

        return Transition(
            state with
            {
                NextAction = action,
                ResponseIntent = null
            },
            "Quote:Requested");
    }

    /// <summary>
    /// Frames the plain <c>TPM2_Quote()</c> response once the quote effect has marshaled and signed the
    /// attestation (TPM 2.0 Library Part 3, clause 18.4, Table 92): the <c>TPM2B_ATTEST</c> and the
    /// <c>TPMT_SIGNATURE</c> over its digest, carried into the response intent that serializes and releases them.
    /// The session-authorized arm frames itself through <c>OnAttestedOverSessions</c> instead, because its
    /// response also owes one entry per authorization slot.
    /// </summary>
    /// <param name="state">The state to transition from.</param>
    /// <param name="quoted">The effect's result carrying the marshaled attestation and its signature.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> carrying the framed response.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnObjectQuoted(TpmSimulatorState state, TpmObjectQuoted quoted) =>
        Transition(
            state with
            {
                NextAction = NullAction.Instance,
                ResponseIntent = new TpmQuoteResponse(
                    TpmRcConstants.TPM_RC_SUCCESS, quoted.Quoted, quoted.Signature)
            },
            "Quote:Completed");

    /// <summary>
    /// Has a signing key attest the TPM's current time, over a caller nonce, for <c>TPM2_GetTime()</c> (Part 3,
    /// clause 18.7).
    /// </summary>
    /// <remarks>
    /// privacyAdminHandle is fixed to <c>TPM_RH_ENDORSEMENT</c> (its <c>TPMI_RH_ENDORSEMENT</c> interface type's
    /// only legal value); any other value is rejected the same way <c>OnNvDefineSpace</c> rejects an authHandle
    /// other than <c>TPM_RH_OWNER</c> (<c>TPM_RC_HANDLE</c>) — the map carried no explicit RC for this case, so
    /// this mirrors that identical fixed-handle precedent. signHandle must resolve to a loaded transient object;
    /// a missing one is <c>TPM_RC_HANDLE</c>. qualifyingData over the <c>TPM2B_DATA</c> bound is
    /// <c>TPM_RC_SIZE</c>; a signer missing the sign attribute is <c>TPM_RC_KEY</c>; an unsupported scheme hash
    /// algorithm is <c>TPM_RC_HASH</c>. The signing scheme is dispatched on the signer's key type exactly as
    /// <c>OnCertify</c>/<c>OnQuote</c> do, and a scheme incompatible with the key's type is <c>TPM_RC_SCHEME</c>.
    /// The attestation needs an effect (marshal the real time/clockInfo image and sign), so the transition
    /// resolves the signer, folds its retained fields plus the already-advanced <c>state.Time</c> and clock
    /// snapshot into the matching action, and leaves no response yet.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_GetTime()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the attestation action, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnGetTime(TpmSimulatorState state, TpmGetTimeRequested request)
    {
        if(request.PrivacyAdminHandle.Value != (uint)TpmRh.TPM_RH_ENDORSEMENT)
        {
            return Reject(state, TpmCcConstants.TPM_CC_GetTime, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        if(!state.TransientObjects.TryGetValue(request.SignHandle, out TransientKeyState? signer))
        {
            return Reject(state, TpmCcConstants.TPM_CC_GetTime, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        //Both slots' authorizations resolve in session order after the handles (Part 3, clause 5.6). Session 0
        //authorizes the endorsement hierarchy (USER role — both GetTime slots are USER, Part 3, clause 18.7):
        //the shared hierarchy ladder, whose mismatch is an uncharged TPM_RC_BAD_AUTH (a permanent entity's
        //authValue other than lockoutAuth is never dictionary-attack protected, Part 1, clause 17.8.1).
        (TpmRcConstants? authError, TpmSimulatorState authorized) = VerifyHierarchyAuthorization(state, request.PrivacyAdminHandle.Value, request.SuppliedPrivacyAdminPassword.AsReadOnlyMemory());
        if(authError is TpmRcConstants authRc)
        {
            return Reject(authorized, TpmCcConstants.TPM_CC_GetTime, authRc, request);
        }

        state = authorized;

        //Session 1 authorizes the signing key (USER role): DA/Lockout gate (clause 5.6, check 3) then the
        //fixed-time trailing-zero-stripped compare against the signer's retained authValue (Part 1, clause
        //17.6.4.3) — the OnCreateSealedObject discipline.
        if(signer.IsDaProtected && state.IsInLockout)
        {
            return Reject(state, TpmCcConstants.TPM_CC_GetTime, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        //USER role gate (Part 3, clause 5.6, check 7.1): a signer whose userWithAuth attribute is CLEAR may
        //have its USER role authorized only by a policy session, never by a password — refused before the
        //compare below, uncharged, per clause 5.6's mandatory check order. The privacy-admin slot above is a
        //hierarchy, which clause 5.6's own note exempts ("a hierarchy operates as if userWithAuth is SET").
        if((signer.Attributes & TpmaObject.USER_WITH_AUTH) == 0)
        {
            return Reject(state, TpmCcConstants.TPM_CC_GetTime, TpmRcConstants.TPM_RC_POLICY_FAIL, request);
        }

        if(!CryptographicOperations.FixedTimeEquals(
            StripTrailingZeros(request.SuppliedSignPassword.AsReadOnlySpan()),
            StripTrailingZeros(signer.AuthValue.AsReadOnlySpan())))
        {
            return RejectSessionAuthFailure(state, TpmCcConstants.TPM_CC_GetTime, sessionIndex: 1, signer.IsDaProtected, request);
        }

        if(request.QualifyingData.Length > Tpm2bData.MaxSize)
        {
            return Reject(state, TpmCcConstants.TPM_CC_GetTime, TpmRcConstants.TPM_RC_SIZE, request);
        }

        if(!CanSign(signer.Attributes))
        {
            return Reject(state, TpmCcConstants.TPM_CC_GetTime, TpmRcConstants.TPM_RC_KEY, request);
        }

        if(!IsSupportedAttestHashAlg(request.SchemeHashAlg))
        {
            return Reject(state, TpmCcConstants.TPM_CC_GetTime, TpmRcConstants.TPM_RC_HASH, request);
        }

        TpmsClockInfo clockSnapshot = new(state.Clock, state.ResetCount, state.RestartCount, state.ClockSafe);
        TpmAction? action = (signer.KeyType.Value, request.SignatureScheme.Value) switch
        {
            (TpmAlgIdConstants.TPM_ALG_RSA, TpmAlgIdConstants.TPM_ALG_RSASSA or TpmAlgIdConstants.TPM_ALG_RSAPSS) =>
                new TpmRsaGetTimeAction(signer.Name, signer.Hierarchy, request.QualifyingData, signer.PrivateKey, request.SignatureScheme, request.SchemeHashAlg, state.Time, clockSnapshot),
            (TpmAlgIdConstants.TPM_ALG_ECC, TpmAlgIdConstants.TPM_ALG_ECDSA) =>
                new TpmGetTimeAction(signer.Name, signer.Hierarchy, request.QualifyingData, signer.PrivateKey, signer.Curve, request.SignatureScheme, request.SchemeHashAlg, state.Time, clockSnapshot),
            _ => null
        };

        if(action is null)
        {
            //A scheme incompatible with the signer's key type — e.g. an ECDSA scheme against an RSA key, or vice
            //versa — fails closed rather than silently coercing to the key's native scheme (mirrors OnCertify).
            return Reject(state, TpmCcConstants.TPM_CC_GetTime, TpmRcConstants.TPM_RC_SCHEME, request);
        }

        //The transition is both password carriers' terminal owner — the per-slot compares were their only use —
        //while the qualifying data has transferred into the action the effect releases it from.
        request.SuppliedPrivacyAdminPassword.Dispose();
        request.SuppliedSignPassword.Dispose();

        return Transition(
            state with
            {
                NextAction = action,
                ResponseIntent = null
            },
            "GetTime:Requested");
    }

    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnTimeAttested(TpmSimulatorState state, TpmTimeAttested attested) =>
        Transition(
            state with
            {
                NextAction = NullAction.Instance,
                ResponseIntent = new TpmGetTimeResponse(
                    TpmRcConstants.TPM_RC_SUCCESS, attested.TimeInfo, attested.Signature)
            },
            "GetTime:Completed");

    /// <summary>
    /// Resolves one authorization slot's session handle, in the order TPM 2.0 Library Part 3, clause 5.5, step 4
    /// prescribes for the whole area: the handle's TYPE first (step 4.1), then whether it names something loaded
    /// (step 4.2).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Step 4.1: "If the session handle is not a handle for an HMAC session, a handle for a policy session, or,
    /// TPM_RS_PW then the TPM shall return TPM_RC_HANDLE" — a structural fact about the octets, so it is settled
    /// before anything is looked up, and it is session-index-encoded to the offending slot (Part 2, clause
    /// 6.6.2). Handle zero, a transient-object handle, and an NV Index handle all land here. The reference's own
    /// unmarshaler answers <c>TPM_RC_VALUE</c> for the same octets, which is a deviation from the clause it
    /// implements; the spec text is followed.
    /// </para>
    /// <para>
    /// Step 4.2: "If the session is not loaded, the TPM will return the warning TPM_RC_REFERENCE_S0 + N where N
    /// is the number of the session" — reached only by a well-typed handle, so a caller naming a plausible but
    /// dead session is told that, while a caller naming something that was never a session handle is told the
    /// handle is wrong. A loaded POLICY session is a kind of authorization these arms do not model yet and keeps
    /// its bare <c>TPM_RC_AUTH_TYPE</c> marker.
    /// </para>
    /// </remarks>
    /// <param name="state">The state the handle is resolved against.</param>
    /// <param name="sessionHandle">The slot's session handle from the wire.</param>
    /// <param name="sessionIndex">The slot's zero-based index, for the session-index-encoded response codes.</param>
    /// <param name="session">The resolved HMAC session when the slot names one; <see langword="null"/> for a password slot or an unresolved handle.</param>
    /// <param name="refusal">The response code to reject with when this returns <see langword="false"/>; meaningless otherwise.</param>
    /// <returns><see langword="true"/> when the slot is a password (session <see langword="null"/>) or a live HMAC session; <see langword="false"/> with <paramref name="refusal"/> set when the handle resolves to neither.</returns>
    private static bool TryResolveCommandSession(TpmSimulatorState state, TpmiShAuthSession sessionHandle, int sessionIndex, out HmacSessionState? session, out TpmRcConstants refusal)
    {
        session = null;
        refusal = TpmRcConstants.TPM_RC_SUCCESS;

        if(sessionHandle.IsPasswordSession)
        {
            return true;
        }

        if(!sessionHandle.IsHmacSession && !sessionHandle.IsPolicySession)
        {
            refusal = SessionEncodedRc(TpmRcConstants.TPM_RC_HANDLE, sessionIndex);

            return false;
        }

        if(sessionHandle.IsHmacSession && state.HmacSessions.TryGetValue(TpmiShHmac.FromValue(sessionHandle.Value), out session))
        {
            return true;
        }

        refusal = sessionHandle.IsPolicySession && state.PolicySessions.ContainsKey(TpmiShPolicy.FromValue(sessionHandle.Value))
            ? TpmRcConstants.TPM_RC_AUTH_TYPE
            : SessionReferenceMissRc(sessionIndex);

        return false;
    }

    /// <summary>
    /// Recomputes a session's bound-entity value over an entity whose Name is its own 4-octet big-endian handle
    /// value — every permanent entity, and in this model an NV Index as well (TPM 2.0 Library Part 1, clause 14, Table 6;
    /// Part 4, <c>SessionComputeBoundEntity()</c>) — and reports whether it equals the value the session
    /// recorded at <c>TPM2_StartAuthSession()</c>, which is equation 22's bind-omission test (clause 17.6.10).
    /// </summary>
    /// <param name="boundEntity">The session's recorded bound-entity value.</param>
    /// <param name="handle">The entity's handle, whose big-endian octets are its Name.</param>
    /// <param name="strippedAuthValue">The entity's CURRENT authorization value with trailing zeros already removed (clause 17.6.4.3).</param>
    /// <returns><see langword="true"/> when the session is bound to this entity as it now stands.</returns>
    private static bool MatchesHandleFormBoundEntity(SessionBoundEntity boundEntity, uint handle, ReadOnlySpan<byte> strippedAuthValue)
    {
        Span<byte> handleName = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(handleName, handle);

        return boundEntity.Matches(handleName, strippedAuthValue);
    }

    /// <summary>
    /// Has a signing key attest the composite digest of a selected set of PCRs over a bound or unbound HMAC
    /// session, for the session-authorized form of <c>TPM2_Quote()</c> (TPM 2.0 Library Part 3, clause 18.4; the
    /// authorization mechanics are Part 3, clause 5.6). The parser routes a LONE password area to the plain
    /// <see cref="OnQuote"/>, so this arm's <c>@signHandle</c> slot is a real HMAC session — or a
    /// <c>TPM_RS_PW</c> slot accompanied by a companion, the one shape that brings a password slot here.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The USER-role gate (check 7.1) refuses a <c>userWithAuth</c>-CLEAR signer uncharged BEFORE any HMAC is
    /// queued, exactly as the password arm does before its inline compare; the remaining ladder
    /// (<c>TPM_RC_SIZE</c>/<c>TPM_RC_KEY</c>/<c>TPM_RC_HASH</c>/<c>TPM_RC_SCHEME</c>) runs in
    /// <see cref="ContinueQuoteOverSession"/> once the command HMAC has verified, so authorization precedes the
    /// parameter checks exactly as the reference's session flow orders them.
    /// </para>
    /// <para>
    /// A companion slot (Part 1, clause 16.6.1, Table 9) authorizes nothing and is admitted for the
    /// <c>decrypt</c>/<c>encrypt</c>/<c>audit</c> attributes alone; it still presents a real command HMAC of its
    /// own, keyed on its session key with no authValue term, and owes its own response entry (clause 16.6.1).
    /// This command authorizes ONE handle, so Table 9's positions 2 and 3 are both free for such a slot and the
    /// area may carry TWO companions — one decrypting and one encrypting, say — within clause 16.6.1's "no more
    /// than three" blocks. Either parameter-encryption attribute may equally ride the authorizing sign slot (Table
    /// 12: "A session with this attribute does not need to be associated with an entity identified in the handle
    /// area"), so which slot decrypts and which encrypts is decided from the attribute BITS in area order, never
    /// from a slot's kind. This arm models no command audit, so that one attribute is still refused with
    /// <c>TPM_RC_ATTRIBUTES</c> at the claiming slot.
    /// </para>
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_Quote()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the command-HMAC verification, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnQuoteOverSession(TpmSimulatorState state, TpmQuoteOverSessionRequested request)
    {
        if(!state.TransientObjects.TryGetValue(request.SignHandle, out TransientKeyState? signer))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Quote, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        if(!TryResolveCommandSession(state, request.SignSessionHandle, sessionIndex: 0, out HmacSessionState? signSession, out TpmRcConstants slotRefusal))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Quote, slotRefusal, request);
        }

        //The companion slot, when the area carried one, authorizes nothing and sits at index 1 (Part 1, clause
        //16.6.1, Table 9). Whether it arrived is a structural fact the parser settled from authorizationSize, so
        //it is read from the record rather than guessed from the handle: the block is resolved and validated for
        //every value it can hold. Resolution is the same as any other slot's, so a handle that is not a session
        //handle at all is TPM_RC_HANDLE and a well-typed handle naming no loaded session is TPM_RC_REFERENCE_S*,
        //both blamed on this index (Part 3, clause 5.5, step 4; Part 2, clause 6.6.2).
        bool hasCompanion = request.HasCompanionSlot;
        HmacSessionState? companionSession = null;
        if(hasCompanion
            && !TryResolveCommandSession(state, request.CompanionSessionHandle, sessionIndex: 1, out companionSession, out TpmRcConstants companionRefusal))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Quote, companionRefusal, request);
        }

        //The second companion, when the area carried one, sits at index 2 — Table 9's last position, open here
        //because this command authorizes a single handle.
        //Whether the block arrived is a structural fact the parser settled from authorizationSize, so it is read
        //from the record rather than guessed from the handle, and it is resolved and validated for every value
        //it can hold: a handle that is not a session handle at all is TPM_RC_HANDLE and a well-typed handle
        //naming no loaded session is TPM_RC_REFERENCE_S*, both blamed on this index (Part 3, clause 5.5, step 4).
        bool hasSecondCompanion = request.HasSecondCompanionSlot;
        HmacSessionState? secondCompanionSession = null;
        if(hasSecondCompanion
            && !TryResolveCommandSession(state, request.SecondCompanionSessionHandle, sessionIndex: 2, out secondCompanionSession, out TpmRcConstants secondCompanionRefusal))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Quote, secondCompanionRefusal, request);
        }

        TpmRcConstants? sessionAreaError = ValidateSessionArea(
            request.SignSessionAttributes, firstAuthorizesEntity: true, signSession?.Symmetric ?? TpmtSymDef.Null,
            hasCompanion, request.CompanionSessionAttributes, companionSession?.Symmetric ?? TpmtSymDef.Null,
            firstCommandParameterIsEncryptable: true, firstResponseParameterIsEncryptable: true,
            auditIsSupported: false, secondAuthorizesEntity: false,
            firstSessionHandle: request.SignSessionHandle, secondSessionHandle: request.CompanionSessionHandle,
            hasThirdSession: hasSecondCompanion, thirdAttributes: request.SecondCompanionSessionAttributes,
            thirdSymmetric: secondCompanionSession?.Symmetric, thirdSessionHandle: request.SecondCompanionSessionHandle,
            firstNonceLength: request.SignNonceCaller.Size, secondNonceLength: request.CompanionNonceCaller.Size,
            thirdNonceLength: request.SecondCompanionNonceCaller.Size);
        if(sessionAreaError is TpmRcConstants areaRc)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Quote, areaRc, request);
        }

        //Which slot decrypts qualifyingData and which encrypts the TPM2B_ATTEST, in area order. Both parameters
        //are eligible (Part 3, clause 18.4, Tables 93 and 94: qualifyingData is the first command parameter and
        //quoted the first response parameter, both TPM2B), and the area-level gates above have already refused a
        //second claimer of either, so each search finds the only slot there is to find.
        int slotCount = 1 + (hasCompanion ? 1 : 0) + (hasSecondCompanion ? 1 : 0);
        ReadOnlySpan<TpmaSession> allSlotAttributes = [request.SignSessionAttributes, request.CompanionSessionAttributes, request.SecondCompanionSessionAttributes];
        ReadOnlySpan<TpmaSession> slotAttributes = allSlotAttributes[..slotCount];
        ReadOnlySpan<HmacSessionState?> slotSessions = [signSession, companionSession, secondCompanionSession];
        (Tpm2bNonce foldedNonceDecrypt, Tpm2bNonce foldedNonceEncrypt) = FoldedSessionNonces(
            slotSessions, FindClaimingSlot(slotAttributes, TpmaSession.DECRYPT), FindClaimingSlot(slotAttributes, TpmaSession.ENCRYPT));

        if(signSession is not null && IsBoundSessionLockedOut(state, signSession))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Quote, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        //A companion's key folded whatever entity it was bound to, so its own bind side is gated exactly as an
        //authorizing session's is (Part 3, clause 11.1.1; Part 1, clause 17.8.3).
        if(companionSession is not null && IsBoundSessionLockedOut(state, companionSession))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Quote, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        if(secondCompanionSession is not null && IsBoundSessionLockedOut(state, secondCompanionSession))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Quote, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        //The signing key's own DA/Lockout gate (Part 3, clause 5.6, check 3), then the USER-role gate (check
        //7.1), uncharged and before any HMAC is queued — the Create/Unseal precedent.
        if(signer.IsDaProtected && state.IsInLockout)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Quote, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        if((signer.Attributes & TpmaObject.USER_WITH_AUTH) == 0)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Quote, TpmRcConstants.TPM_RC_POLICY_FAIL, request);
        }

        //A TPM_RS_PW sign slot reaches this arm only alongside a companion (a lone password area parsed to
        //TpmQuoteRequested): its hmac field is the plaintext authValue, compared inline since a password
        //authorization computes no cpHash (Part 1, clause 17.6.4.1), both sides trailing-zero-stripped (clause
        //17.6.4.3), in fixed time — the OnCertifyOverSession sign-slot discipline.
        bool signIsPassword = request.SignSessionHandle.IsPasswordSession;
        if(signIsPassword
            && !CryptographicOperations.FixedTimeEquals(StripTrailingZeros(request.SuppliedSignHmac.AsReadOnlySpan()), StripTrailingZeros(signer.AuthValue.AsReadOnlySpan())))
        {
            return RejectSessionAuthFailure(state, TpmCcConstants.TPM_CC_Quote, sessionIndex: 0, signer.IsDaProtected, request);
        }

        //One pending verification per REAL slot, in wire session order. The sign slot's bind-omission (Part 1,
        //clause 17.6.10 equation 22) is resolved once here against the signer's own Name and threaded onward so
        //the response HMAC reuses the identical key (clause 17.6.5).
        var pendings = ImmutableArray.CreateBuilder<TpmPendingSessionVerification>(3);
        Tpm2bAuth? resolvedSignAuthValue = null;

        if(!signIsPassword)
        {
            HmacSessionState session = signSession!;
            bool bindOmits = session.BoundEntity.Matches(signer.Name.Span, StripTrailingZeros(signer.AuthValue.AsReadOnlySpan()));
            Tpm2bAuth authForHmac = bindOmits ? Tpm2bAuth.Empty : signer.AuthValue;
            resolvedSignAuthValue = authForHmac;

            pendings.Add(new TpmPendingSessionVerification(
                SessionHandle: TpmiShAuthSession.FromValue(session.Handle.Value), SessionIndex: 0, SessionAlg: session.SessionAlg, SessionKey: session.SessionKey,
                AuthValue: authForHmac, IsDaProtected: signer.IsDaProtected || session.IsBoundEntityDaProtected,
                NonceCaller: request.SignNonceCaller, NonceTpm: session.NonceTpm,
                FoldedNonceDecrypt: foldedNonceDecrypt, FoldedNonceEncrypt: foldedNonceEncrypt,
                SessionAttributes: request.SignSessionAttributes, SuppliedHmac: request.SuppliedSignHmac,
                IsLockoutEntity: session.IsBoundToLockout));
        }

        //The companion authorizes no entity, so its HMAC key folds no authValue (the reference clears
        //includeAuth for exactly this slot) and its whole dictionary-attack standing comes from its own bind
        //(Part 1, clause 17.8.1's third way an authValue is used for authorization). It still owes a command
        //HMAC like every other session in the area (Part 3, clause 5.6). Only the FIRST session folds another
        //slot's nonceTPM (clause 17.6.3.4), so this one folds nothing.
        if(companionSession is not null)
        {
            pendings.Add(new TpmPendingSessionVerification(
                SessionHandle: TpmiShAuthSession.FromValue(companionSession.Handle.Value), SessionIndex: 1, SessionAlg: companionSession.SessionAlg, SessionKey: companionSession.SessionKey,
                AuthValue: Tpm2bAuth.Empty, IsDaProtected: companionSession.IsBoundEntityDaProtected,
                NonceCaller: request.CompanionNonceCaller, NonceTpm: companionSession.NonceTpm,
                FoldedNonceDecrypt: Tpm2bNonce.Empty, FoldedNonceEncrypt: Tpm2bNonce.Empty,
                SessionAttributes: request.CompanionSessionAttributes, SuppliedHmac: request.SuppliedCompanionHmac,
                IsLockoutEntity: companionSession.IsBoundToLockout));
        }

        //The second companion stands on exactly the same footing as the first: no authValue term, its own bind
        //deciding its dictionary-attack standing, its own command HMAC, and no other slot's nonceTPM folded in.
        if(secondCompanionSession is not null)
        {
            pendings.Add(new TpmPendingSessionVerification(
                SessionHandle: TpmiShAuthSession.FromValue(secondCompanionSession.Handle.Value), SessionIndex: 2, SessionAlg: secondCompanionSession.SessionAlg, SessionKey: secondCompanionSession.SessionKey,
                AuthValue: Tpm2bAuth.Empty, IsDaProtected: secondCompanionSession.IsBoundEntityDaProtected,
                NonceCaller: request.SecondCompanionNonceCaller, NonceTpm: secondCompanionSession.NonceTpm,
                FoldedNonceDecrypt: Tpm2bNonce.Empty, FoldedNonceEncrypt: Tpm2bNonce.Empty,
                SessionAttributes: request.SecondCompanionSessionAttributes, SuppliedHmac: request.SuppliedSecondCompanionHmac,
                IsLockoutEntity: secondCompanionSession.IsBoundToLockout));
        }

        //Every reachable combination leaves at least one queued verification: a lone password sign slot parses to
        //TpmQuoteRequested instead of reaching here, and a companion alongside it is admitted only when it is a
        //real session (a TPM_RS_PW companion authorizes nothing and may claim no attribute, so the session-area
        //validation above already refused it).
        ImmutableArray<TpmPendingSessionVerification> queue = pendings.ToImmutable();

        //cpHash's single handle-Name term (Part 1, clause 16.7 equation 15) is the signer's Name, borrowed
        //zero-copy through Tpm2bName.AsReadOnlyMemory (the aliasing accessor built for exactly a cpHash
        //handle-name area): the signer stays loaded for the whole of its own attest command, so the aliased
        //carrier is valid across every verify round-trip. The two-handle arms instead concatenate into a fresh
        //buffer because two Names must land contiguously, not because a borrow would be unsafe.
        return Transition(
            state with
            {
                NextAction = new TpmVerifyCommandHmacAction(
                    TpmCcConstants.TPM_CC_Quote, TpmCommandHandleNames.Of(TpmHandleName.FromName(signer.Name)), request.RawParameterArea, queue[0],
                    queue.RemoveAt(0), request with { ResolvedSignAuthValue = resolvedSignAuthValue }),
                ResponseIntent = null
            },
            "Quote:OverSession:HmacVerifyRequested");
    }

    /// <summary>
    /// Resumes the session-authorized <c>TPM2_Quote()</c> once its command HMAC has verified, by declaring the
    /// step that recovers <c>qualifyingData</c> in plaintext (TPM 2.0 Library Part 3, clause 5.6's authorization
    /// precedes clause 5.7's decryption, which precedes clause 5.8's unmarshaling).
    /// </summary>
    /// <remarks>
    /// Declared for every arrival, not only an encrypted one, so the value the ladder reads has a single origin;
    /// <see cref="CompleteQuoteOverSession"/> is the ladder itself. Which slot decrypts is read from the
    /// attribute bits the request carries, so the entry transition's own reading and this one cannot drift.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_Quote()</c> request, its sessions now verified.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the decryption step.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> ContinueQuoteOverSession(TpmSimulatorState state, TpmQuoteOverSessionRequested request)
    {
        int slotCount = 1 + (request.HasCompanionSlot ? 1 : 0) + (request.HasSecondCompanionSlot ? 1 : 0);
        ReadOnlySpan<TpmaSession> allSlotAttributes = [request.SignSessionAttributes, request.CompanionSessionAttributes, request.SecondCompanionSessionAttributes];
        ReadOnlySpan<TpmaSession> slotAttributes = allSlotAttributes[..slotCount];
        int decryptIndex = FindClaimingSlot(slotAttributes, TpmaSession.DECRYPT);

        //The decrypt slot's own authorized entity supplies the cipher key's authValue term, UNRESOLVED by the
        //session's bind (Part 1, clause 19.1); a companion authorizes none and folds nothing.
        (HmacSessionState? Session, Tpm2bAuth EntityAuthValue, Tpm2bNonce NonceCaller) decrypt = decryptIndex switch
        {
            0 => (state.HmacSessions[TpmiShHmac.FromValue(request.SignSessionHandle.Value)], state.TransientObjects[request.SignHandle].AuthValue, request.SignNonceCaller),
            1 => (state.HmacSessions[TpmiShHmac.FromValue(request.CompanionSessionHandle.Value)], Tpm2bAuth.Empty, request.CompanionNonceCaller),
            2 => (state.HmacSessions[TpmiShHmac.FromValue(request.SecondCompanionSessionHandle.Value)], Tpm2bAuth.Empty, request.SecondCompanionNonceCaller),
            _ => (null, Tpm2bAuth.Empty, Tpm2bNonce.Empty)
        };

        return DeclareAttestQualifyingDataDecryption(
            state, TpmCcConstants.TPM_CC_Quote, request, request.RawParameterArea, decryptIndex,
            decrypt.Session, decrypt.EntityAuthValue, decrypt.NonceCaller, "Quote:OverSession:QualifyingDataDecryptRequested");
    }

    /// <summary>
    /// Runs the session-authorized <c>TPM2_Quote()</c> ladder once <c>qualifyingData</c> has been recovered: the
    /// password arm's remaining ladder verbatim, then the attestation carrying the single real session's response
    /// entry (TPM 2.0 Library Part 3, clause 18.4; Part 1, clause 16.6.1). This transition is the terminal owner
    /// of every slot's supplied HMAC, transfers each slot's caller nonce into that slot's response-session entry,
    /// and transfers the qualifying data and the PCR selection into the quote action; the attest effect releases
    /// every transferred carrier, and a refusing arm releases them all through the request's own
    /// <see cref="IDisposable.Dispose"/>.
    /// </summary>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_Quote()</c> request, carrying the recovered qualifying data.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the quote action, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> CompleteQuoteOverSession(TpmSimulatorState state, TpmQuoteOverSessionRequested request)
    {
        TransientKeyState signer = state.TransientObjects[request.SignHandle];

        //Fail-closed USER-role backstop (unreachable: OnQuoteOverSession refuses a userWithAuth-CLEAR signer
        //before the HMAC is queued); placed first so even an unreachable arrival moves no state.
        if((signer.Attributes & TpmaObject.USER_WITH_AUTH) == 0)
        {
            request.Dispose();

            return Reject(state, TpmCcConstants.TPM_CC_Quote, TpmRcConstants.TPM_RC_POLICY_FAIL);
        }

        if(request.QualifyingData.Length > Tpm2bData.MaxSize)
        {
            request.Dispose();

            return Reject(state, TpmCcConstants.TPM_CC_Quote, TpmRcConstants.TPM_RC_SIZE);
        }

        if(!CanSign(signer.Attributes))
        {
            request.Dispose();

            return Reject(state, TpmCcConstants.TPM_CC_Quote, TpmRcConstants.TPM_RC_KEY);
        }

        if(!IsSupportedAttestHashAlg(request.SchemeHashAlg))
        {
            request.Dispose();

            return Reject(state, TpmCcConstants.TPM_CC_Quote, TpmRcConstants.TPM_RC_HASH);
        }

        //TPMS_QUOTE_INFO.pcrSelect carries "information on algID, PCR selected and digest" (Part 2, clause 10.12.4,
        //Table 143) — the selection the pcrDigest standing beside it was taken over, so the attested list is the
        //one the digest actually covers, not the one the caller asked for: a bit naming a register this model does
        //not hold, and every bit of a bank it has not allocated, is cleared before the selection is gathered over
        //and before it is echoed. The reference does the same filtering in place inside PCRComputeCurrentDigest
        //and then copies the MODIFIED list into the attestation. It happens here, where the model's bank
        //allocation is in hand, rather than in the effect: the mask is written into the carrier's own rented
        //storage, so no pool is needed and the marshaled width is unchanged. The gather below already skips
        //unheld indexes and unallocated banks, so the composite digest is untouched by it.
        ReadOnlySpan<TpmAlgIdConstants> implementedBanks = [state.Sha256PcrBank.HashAlgorithm];
        request.PcrSelection.RetainImplementedPcrs(implementedBanks, PcrBankState.PcrCount);

        ImmutableArray<ReadOnlyMemory<byte>> pcrValues = GatherSelectedPcrValues(state.Sha256PcrBank, request.PcrSelection);
        TpmsClockInfo clockSnapshot = new(state.Clock, state.ResetCount, state.RestartCount, state.ClockSafe);
        ImmutableArray<TpmAttestResponseSession> responseSessions = BuildQuoteResponseSessions(state, request);

        TpmAction? action = (signer.KeyType.Value, request.SignatureScheme.Value) switch
        {
            (TpmAlgIdConstants.TPM_ALG_RSA, TpmAlgIdConstants.TPM_ALG_RSASSA or TpmAlgIdConstants.TPM_ALG_RSAPSS) =>
                new TpmRsaQuoteAction(
                    signer.Name, signer.Hierarchy, request.QualifyingData, signer.PrivateKey, request.SignatureScheme, request.SchemeHashAlg, request.PcrSelection, pcrValues, clockSnapshot, responseSessions),
            (TpmAlgIdConstants.TPM_ALG_ECC, TpmAlgIdConstants.TPM_ALG_ECDSA) =>
                new TpmQuoteAction(
                    signer.Name, signer.Hierarchy, request.QualifyingData, signer.PrivateKey, signer.Curve, request.SignatureScheme, request.SchemeHashAlg, request.PcrSelection, pcrValues, clockSnapshot, responseSessions),
            _ => null
        };

        if(action is null)
        {
            request.Dispose();

            return Reject(state, TpmCcConstants.TPM_CC_Quote, TpmRcConstants.TPM_RC_SCHEME);
        }

        //The continuation is every supplied HMAC's and the parameter area's terminal owner — their verification
        //was the only use — while each slot's caller nonce has transferred into that slot's response-session
        //entry and the qualifying data and the PCR selection into the action, all of which the effect releases.
        request.SuppliedSignHmac.Dispose();
        request.SuppliedCompanionHmac.Dispose();
        request.SuppliedSecondCompanionHmac.Dispose();
        request.RawParameterArea.Dispose();

        return Transition(
            state with
            {
                NextAction = action,
                ResponseIntent = null
            },
            "Quote:OverSession:AttestRequested");
    }

    /// <summary>
    /// Assembles every <c>TPM2_Quote()</c> slot's response-session material in command-session order (TPM 2.0
    /// Library Part 1, clause 16.6.1): the <c>@signHandle</c> slot — a <c>TPM_RS_PW</c> placeholder or a real
    /// session keyed on the same authValue term its command HMAC used (clause 17.6.5) — then each companion the
    /// area carried, every one of which owes a real entry of its own because it presented a real command HMAC.
    /// </summary>
    /// <param name="state">The state the sessions are resolved against.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_Quote()</c> request.</param>
    /// <returns>Every slot's response-session material, in command-session order.</returns>
    private static ImmutableArray<TpmAttestResponseSession> BuildQuoteResponseSessions(TpmSimulatorState state, TpmQuoteOverSessionRequested request)
    {
        var sessions = ImmutableArray.CreateBuilder<TpmAttestResponseSession>(3);

        sessions.Add(request.SignSessionHandle.IsPasswordSession
            ? AttestPasswordPlaceholderSession(request.SignSessionHandle.Value, request.SignNonceCaller)
            : AttestRealResponseSession(
                state.HmacSessions[TpmiShHmac.FromValue(request.SignSessionHandle.Value)], request.ResolvedSignAuthValue ?? Tpm2bAuth.Empty,
                state.TransientObjects[request.SignHandle].AuthValue, request.SignNonceCaller, request.SignSessionAttributes,
                encrypts: (request.SignSessionAttributes & TpmaSession.ENCRYPT) != 0));

        if(request.HasCompanionSlot)
        {
            sessions.Add(AttestRealResponseSession(
                state.HmacSessions[TpmiShHmac.FromValue(request.CompanionSessionHandle.Value)], Tpm2bAuth.Empty, Tpm2bAuth.Empty, request.CompanionNonceCaller, request.CompanionSessionAttributes,
                encrypts: (request.CompanionSessionAttributes & TpmaSession.ENCRYPT) != 0));
        }

        if(request.HasSecondCompanionSlot)
        {
            sessions.Add(AttestRealResponseSession(
                state.HmacSessions[TpmiShHmac.FromValue(request.SecondCompanionSessionHandle.Value)], Tpm2bAuth.Empty, Tpm2bAuth.Empty, request.SecondCompanionNonceCaller, request.SecondCompanionSessionAttributes,
                encrypts: (request.SecondCompanionSessionAttributes & TpmaSession.ENCRYPT) != 0));
        }

        return sessions.ToImmutable();
    }

    /// <summary>
    /// Has a signing key attest another object's creation over a bound or unbound HMAC session, re-verifying the
    /// caller-supplied creation ticket, for the session-authorized form of <c>TPM2_CertifyCreation()</c> (TPM 2.0
    /// Library Part 3, clause 18.3). <c>objectHandle</c> carries no authorization, so only <c>@signHandle</c>'s
    /// slot authorizes; the parser routes a LONE password area to the plain <see cref="OnCertifyCreation"/>, so
    /// this arm's slot is a real HMAC session — or a <c>TPM_RS_PW</c> slot accompanied by a companion.
    /// </summary>
    /// <remarks>
    /// A companion slot (Part 1, clause 16.6.1, Table 9) authorizes nothing and is admitted for the
    /// <c>decrypt</c>/<c>encrypt</c>/<c>audit</c> attributes alone; it still presents a real command HMAC of its
    /// own and owes its own response entry (clause 16.6.1). Only <c>@signHandle</c> authorizes here, so Table 9's
    /// positions 2 and 3 are both free for such a slot and the area may carry TWO companions within clause
    /// 16.6.1's "no more than three" blocks. Either parameter-encryption attribute may equally ride an authorizing
    /// slot (Table 12: "A session with this attribute does not need to be associated with an entity identified in
    /// the handle area"), so which slot decrypts and which encrypts is decided from the attribute BITS in area
    /// order, never from a slot's kind. This arm models no command audit, so that one attribute is still refused
    /// with <c>TPM_RC_ATTRIBUTES</c> at the claiming slot.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_CertifyCreation()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the command-HMAC verification, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnCertifyCreationOverSession(TpmSimulatorState state, TpmCertifyCreationOverSessionRequested request)
    {
        if(!state.TransientObjects.TryGetValue(request.SignHandle, out TransientKeyState? signer))
        {
            return Reject(state, TpmCcConstants.TPM_CC_CertifyCreation, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        if(!state.TransientObjects.TryGetValue(request.ObjectHandle, out TransientKeyState? subject))
        {
            return Reject(state, TpmCcConstants.TPM_CC_CertifyCreation, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        if(!TryResolveCommandSession(state, request.SignSessionHandle, sessionIndex: 0, out HmacSessionState? signSession, out TpmRcConstants slotRefusal))
        {
            return Reject(state, TpmCcConstants.TPM_CC_CertifyCreation, slotRefusal, request);
        }

        //The companion slot, when the area carried one, authorizes nothing and sits at index 1 (Part 1, clause
        //16.6.1, Table 9).
        //Whether the block arrived is a structural fact the parser settled from authorizationSize, so it is read
        //from the record rather than guessed from the handle, and it is resolved and validated for every value
        //it can hold: a handle that is not a session handle at all is TPM_RC_HANDLE and a well-typed handle
        //naming no loaded session is TPM_RC_REFERENCE_S*, both blamed on this index (Part 3, clause 5.5, step 4).
        bool hasCompanion = request.HasCompanionSlot;
        HmacSessionState? companionSession = null;
        if(hasCompanion
            && !TryResolveCommandSession(state, request.CompanionSessionHandle, sessionIndex: 1, out companionSession, out TpmRcConstants companionRefusal))
        {
            return Reject(state, TpmCcConstants.TPM_CC_CertifyCreation, companionRefusal, request);
        }

        //The second companion, when the area carried one, sits at index 2 — Table 9's last position, open here
        //because only @signHandle authorizes this command.
        //Whether the block arrived is a structural fact the parser settled from authorizationSize, so it is read
        //from the record rather than guessed from the handle, and it is resolved and validated for every value
        //it can hold: a handle that is not a session handle at all is TPM_RC_HANDLE and a well-typed handle
        //naming no loaded session is TPM_RC_REFERENCE_S*, both blamed on this index (Part 3, clause 5.5, step 4).
        bool hasSecondCompanion = request.HasSecondCompanionSlot;
        HmacSessionState? secondCompanionSession = null;
        if(hasSecondCompanion
            && !TryResolveCommandSession(state, request.SecondCompanionSessionHandle, sessionIndex: 2, out secondCompanionSession, out TpmRcConstants secondCompanionRefusal))
        {
            return Reject(state, TpmCcConstants.TPM_CC_CertifyCreation, secondCompanionRefusal, request);
        }

        TpmRcConstants? sessionAreaError = ValidateSessionArea(
            request.SignSessionAttributes, firstAuthorizesEntity: true, signSession?.Symmetric ?? TpmtSymDef.Null,
            hasCompanion, request.CompanionSessionAttributes, companionSession?.Symmetric ?? TpmtSymDef.Null,
            firstCommandParameterIsEncryptable: true, firstResponseParameterIsEncryptable: true,
            auditIsSupported: false, secondAuthorizesEntity: false,
            firstSessionHandle: request.SignSessionHandle, secondSessionHandle: request.CompanionSessionHandle,
            hasThirdSession: hasSecondCompanion, thirdAttributes: request.SecondCompanionSessionAttributes,
            thirdSymmetric: secondCompanionSession?.Symmetric, thirdSessionHandle: request.SecondCompanionSessionHandle,
            firstNonceLength: request.SignNonceCaller.Size, secondNonceLength: request.CompanionNonceCaller.Size,
            thirdNonceLength: request.SecondCompanionNonceCaller.Size);
        if(sessionAreaError is TpmRcConstants areaRc)
        {
            return Reject(state, TpmCcConstants.TPM_CC_CertifyCreation, areaRc, request);
        }

        //Both of this command's first parameters are encryption-eligible (Part 3, clause 18.3, Tables 91 and 92:
        //qualifyingData is the first command parameter and certifyInfo the first response parameter, both TPM2B),
        //and the area-level gates above have already refused a second claimer of either, so each search below
        //finds the only slot there is to find. creationHash and creationTicket sit behind the first parameter and
        //are never protected.
        int slotCount = 1 + (hasCompanion ? 1 : 0) + (hasSecondCompanion ? 1 : 0);
        ReadOnlySpan<TpmaSession> allSlotAttributes = [request.SignSessionAttributes, request.CompanionSessionAttributes, request.SecondCompanionSessionAttributes];
        ReadOnlySpan<TpmaSession> slotAttributes = allSlotAttributes[..slotCount];
        ReadOnlySpan<HmacSessionState?> slotSessions = [signSession, companionSession, secondCompanionSession];
        (Tpm2bNonce foldedNonceDecrypt, Tpm2bNonce foldedNonceEncrypt) = FoldedSessionNonces(
            slotSessions, FindClaimingSlot(slotAttributes, TpmaSession.DECRYPT), FindClaimingSlot(slotAttributes, TpmaSession.ENCRYPT));

        if(signSession is not null && IsBoundSessionLockedOut(state, signSession))
        {
            return Reject(state, TpmCcConstants.TPM_CC_CertifyCreation, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        if(companionSession is not null && IsBoundSessionLockedOut(state, companionSession))
        {
            return Reject(state, TpmCcConstants.TPM_CC_CertifyCreation, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        if(secondCompanionSession is not null && IsBoundSessionLockedOut(state, secondCompanionSession))
        {
            return Reject(state, TpmCcConstants.TPM_CC_CertifyCreation, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        if(signer.IsDaProtected && state.IsInLockout)
        {
            return Reject(state, TpmCcConstants.TPM_CC_CertifyCreation, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        if((signer.Attributes & TpmaObject.USER_WITH_AUTH) == 0)
        {
            return Reject(state, TpmCcConstants.TPM_CC_CertifyCreation, TpmRcConstants.TPM_RC_POLICY_FAIL, request);
        }

        //A TPM_RS_PW sign slot reaches this arm only alongside a companion (a lone password area parsed to
        //TpmCertifyCreationRequested): its hmac field is the plaintext authValue, compared inline in fixed time
        //with both sides trailing-zero-stripped (Part 1, clauses 17.6.4.1 and 17.6.4.3).
        bool signIsPassword = request.SignSessionHandle.IsPasswordSession;
        if(signIsPassword
            && !CryptographicOperations.FixedTimeEquals(StripTrailingZeros(request.SuppliedSignHmac.AsReadOnlySpan()), StripTrailingZeros(signer.AuthValue.AsReadOnlySpan())))
        {
            return RejectSessionAuthFailure(state, TpmCcConstants.TPM_CC_CertifyCreation, sessionIndex: 0, signer.IsDaProtected, request);
        }

        var pendings = ImmutableArray.CreateBuilder<TpmPendingSessionVerification>(3);
        Tpm2bAuth? resolvedSignAuthValue = null;

        if(!signIsPassword)
        {
            HmacSessionState session = signSession!;
            bool bindOmits = session.BoundEntity.Matches(signer.Name.Span, StripTrailingZeros(signer.AuthValue.AsReadOnlySpan()));
            Tpm2bAuth authForHmac = bindOmits ? Tpm2bAuth.Empty : signer.AuthValue;
            resolvedSignAuthValue = authForHmac;

            pendings.Add(new TpmPendingSessionVerification(
                SessionHandle: TpmiShAuthSession.FromValue(session.Handle.Value), SessionIndex: 0, SessionAlg: session.SessionAlg, SessionKey: session.SessionKey,
                AuthValue: authForHmac, IsDaProtected: signer.IsDaProtected || session.IsBoundEntityDaProtected,
                NonceCaller: request.SignNonceCaller, NonceTpm: session.NonceTpm,
                FoldedNonceDecrypt: foldedNonceDecrypt, FoldedNonceEncrypt: foldedNonceEncrypt,
                SessionAttributes: request.SignSessionAttributes, SuppliedHmac: request.SuppliedSignHmac,
                IsLockoutEntity: session.IsBoundToLockout));
        }

        //The companion authorizes no entity, so its HMAC key folds no authValue and its dictionary-attack
        //standing comes from its own bind alone (Part 1, clause 17.8.1). It still owes a command HMAC (Part 3,
        //clause 5.6). Only the FIRST session folds another slot's nonceTPM (clause 17.6.3.4), so this one folds
        //nothing.
        if(companionSession is not null)
        {
            pendings.Add(new TpmPendingSessionVerification(
                SessionHandle: TpmiShAuthSession.FromValue(companionSession.Handle.Value), SessionIndex: 1, SessionAlg: companionSession.SessionAlg, SessionKey: companionSession.SessionKey,
                AuthValue: Tpm2bAuth.Empty, IsDaProtected: companionSession.IsBoundEntityDaProtected,
                NonceCaller: request.CompanionNonceCaller, NonceTpm: companionSession.NonceTpm,
                FoldedNonceDecrypt: Tpm2bNonce.Empty, FoldedNonceEncrypt: Tpm2bNonce.Empty,
                SessionAttributes: request.CompanionSessionAttributes, SuppliedHmac: request.SuppliedCompanionHmac,
                IsLockoutEntity: companionSession.IsBoundToLockout));
        }

        //The second companion stands on exactly the same footing as the first: no authValue term, its own bind
        //deciding its dictionary-attack standing, its own command HMAC, and no other slot's nonceTPM folded in.
        if(secondCompanionSession is not null)
        {
            pendings.Add(new TpmPendingSessionVerification(
                SessionHandle: TpmiShAuthSession.FromValue(secondCompanionSession.Handle.Value), SessionIndex: 2, SessionAlg: secondCompanionSession.SessionAlg, SessionKey: secondCompanionSession.SessionKey,
                AuthValue: Tpm2bAuth.Empty, IsDaProtected: secondCompanionSession.IsBoundEntityDaProtected,
                NonceCaller: request.SecondCompanionNonceCaller, NonceTpm: secondCompanionSession.NonceTpm,
                FoldedNonceDecrypt: Tpm2bNonce.Empty, FoldedNonceEncrypt: Tpm2bNonce.Empty,
                SessionAttributes: request.SecondCompanionSessionAttributes, SuppliedHmac: request.SuppliedSecondCompanionHmac,
                IsLockoutEntity: secondCompanionSession.IsBoundToLockout));
        }

        //Non-empty for the same reason OnQuoteOverSession's queue is: a lone password sign slot never reaches
        //here, and a TPM_RS_PW companion is refused by the session-area validation above.
        ImmutableArray<TpmPendingSessionVerification> queue = pendings.ToImmutable();

        //cpHash handle order follows the command's own (Part 3, clause 18.3, Table 88): Name1 the signing key's,
        //Name2 the certified object's (which carries no authorization but is still named in cpHash).
        TpmCommandHandleNames handleNames = TpmCommandHandleNames.Of(TpmHandleName.FromName(signer.Name), TpmHandleName.FromName(subject.Name));

        return Transition(
            state with
            {
                NextAction = new TpmVerifyCommandHmacAction(
                    TpmCcConstants.TPM_CC_CertifyCreation, handleNames, request.RawParameterArea, queue[0],
                    queue.RemoveAt(0), request with { ResolvedSignAuthValue = resolvedSignAuthValue }),
                ResponseIntent = null
            },
            "CertifyCreation:OverSession:HmacVerifyRequested");
    }

    /// <summary>
    /// Resumes the session-authorized <c>TPM2_CertifyCreation()</c> once its command HMAC has verified, by
    /// declaring the step that recovers <c>qualifyingData</c> in plaintext (TPM 2.0 Library Part 3, clause 5.6's
    /// authorization precedes clause 5.7's decryption, which precedes clause 5.8's unmarshaling).
    /// </summary>
    /// <remarks>
    /// Declared for every arrival, not only an encrypted one, so the value the ladder reads has a single origin;
    /// <see cref="CompleteCertifyCreationOverSession"/> is the ladder itself.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_CertifyCreation()</c> request, its sessions now verified.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the decryption step.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> ContinueCertifyCreationOverSession(TpmSimulatorState state, TpmCertifyCreationOverSessionRequested request)
    {
        int slotCount = 1 + (request.HasCompanionSlot ? 1 : 0) + (request.HasSecondCompanionSlot ? 1 : 0);
        ReadOnlySpan<TpmaSession> allSlotAttributes = [request.SignSessionAttributes, request.CompanionSessionAttributes, request.SecondCompanionSessionAttributes];
        ReadOnlySpan<TpmaSession> slotAttributes = allSlotAttributes[..slotCount];
        int decryptIndex = FindClaimingSlot(slotAttributes, TpmaSession.DECRYPT);

        //The decrypt slot's own authorized entity supplies the cipher key's authValue term, UNRESOLVED by the
        //session's bind (Part 1, clause 19.1); a companion authorizes none and folds nothing.
        (HmacSessionState? Session, Tpm2bAuth EntityAuthValue, Tpm2bNonce NonceCaller) decrypt = decryptIndex switch
        {
            0 => (state.HmacSessions[TpmiShHmac.FromValue(request.SignSessionHandle.Value)], state.TransientObjects[request.SignHandle].AuthValue, request.SignNonceCaller),
            1 => (state.HmacSessions[TpmiShHmac.FromValue(request.CompanionSessionHandle.Value)], Tpm2bAuth.Empty, request.CompanionNonceCaller),
            2 => (state.HmacSessions[TpmiShHmac.FromValue(request.SecondCompanionSessionHandle.Value)], Tpm2bAuth.Empty, request.SecondCompanionNonceCaller),
            _ => (null, Tpm2bAuth.Empty, Tpm2bNonce.Empty)
        };

        return DeclareAttestQualifyingDataDecryption(
            state, TpmCcConstants.TPM_CC_CertifyCreation, request, request.RawParameterArea, decryptIndex,
            decrypt.Session, decrypt.EntityAuthValue, decrypt.NonceCaller, "CertifyCreation:OverSession:QualifyingDataDecryptRequested");
    }

    /// <summary>
    /// Runs the session-authorized <c>TPM2_CertifyCreation()</c> ladder once <c>qualifyingData</c> has been
    /// recovered: the password arm's remaining ladder verbatim, then the attestation carrying the single real
    /// session's response entry. The creation-ticket re-verification stays inside the effect; a ticket mismatch
    /// feeds back <c>TPM_RC_TICKET</c> with no attestation and therefore no session area (Part 3, clause 18.3;
    /// <see cref="OnObjectCreationCertified"/>'s header-only rejection). This transition is the terminal owner
    /// of every slot's supplied HMAC, transfers each slot's caller nonce into that slot's response-session entry,
    /// and transfers the qualifying data, the creation hash, and the ticket digest into the certify-creation
    /// action; the attest effect releases every transferred carrier, and a refusing arm releases them all through
    /// the request's own <see cref="IDisposable.Dispose"/>.
    /// </summary>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_CertifyCreation()</c> request, carrying the recovered qualifying data.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the certify-creation action, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> CompleteCertifyCreationOverSession(TpmSimulatorState state, TpmCertifyCreationOverSessionRequested request)
    {
        TransientKeyState signer = state.TransientObjects[request.SignHandle];
        TransientKeyState subject = state.TransientObjects[request.ObjectHandle];

        if((signer.Attributes & TpmaObject.USER_WITH_AUTH) == 0)
        {
            request.Dispose();

            return Reject(state, TpmCcConstants.TPM_CC_CertifyCreation, TpmRcConstants.TPM_RC_POLICY_FAIL);
        }

        if(request.QualifyingData.Length > Tpm2bData.MaxSize)
        {
            request.Dispose();

            return Reject(state, TpmCcConstants.TPM_CC_CertifyCreation, TpmRcConstants.TPM_RC_SIZE);
        }

        if(!CanSign(signer.Attributes))
        {
            request.Dispose();

            return Reject(state, TpmCcConstants.TPM_CC_CertifyCreation, TpmRcConstants.TPM_RC_KEY);
        }

        if(!IsSupportedAttestHashAlg(request.SchemeHashAlg))
        {
            request.Dispose();

            return Reject(state, TpmCcConstants.TPM_CC_CertifyCreation, TpmRcConstants.TPM_RC_HASH);
        }

        TpmsClockInfo clockSnapshot = new(state.Clock, state.ResetCount, state.RestartCount, state.ClockSafe);
        ImmutableArray<TpmAttestResponseSession> responseSessions = BuildCertifyCreationResponseSessions(state, request);

        TpmAction? action = (signer.KeyType.Value, request.SignatureScheme.Value) switch
        {
            (TpmAlgIdConstants.TPM_ALG_RSA, TpmAlgIdConstants.TPM_ALG_RSASSA or TpmAlgIdConstants.TPM_ALG_RSAPSS) =>
                new TpmRsaCertifyCreationAction(
                    subject.Name, subject.Hierarchy, signer.Name, signer.Hierarchy, request.QualifyingData, request.CreationHash,
                    request.TicketDigest, signer.PrivateKey, request.SignatureScheme, request.SchemeHashAlg, clockSnapshot, responseSessions),
            (TpmAlgIdConstants.TPM_ALG_ECC, TpmAlgIdConstants.TPM_ALG_ECDSA) =>
                new TpmCertifyCreationAction(
                    subject.Name, subject.Hierarchy, signer.Name, signer.Hierarchy, request.QualifyingData, request.CreationHash,
                    request.TicketDigest, signer.PrivateKey, signer.Curve, request.SignatureScheme, request.SchemeHashAlg, clockSnapshot, responseSessions),
            _ => null
        };

        if(action is null)
        {
            request.Dispose();

            return Reject(state, TpmCcConstants.TPM_CC_CertifyCreation, TpmRcConstants.TPM_RC_SCHEME);
        }

        //The continuation is every supplied HMAC's and the parameter area's terminal owner — their verification
        //was the only use — while each slot's caller nonce has transferred into that slot's response-session
        //entry and the qualifying data, the creation hash, and the ticket digest into the action, all of which
        //the effect releases.
        request.SuppliedSignHmac.Dispose();
        request.SuppliedCompanionHmac.Dispose();
        request.SuppliedSecondCompanionHmac.Dispose();
        request.RawParameterArea.Dispose();

        return Transition(
            state with
            {
                NextAction = action,
                ResponseIntent = null
            },
            "CertifyCreation:OverSession:AttestRequested");
    }

    /// <summary>
    /// Assembles every <c>TPM2_CertifyCreation()</c> slot's response-session material in command-session order
    /// (TPM 2.0 Library Part 1, clause 16.6.1): the <c>@signHandle</c> slot — a <c>TPM_RS_PW</c> placeholder or a
    /// real session keyed on the same authValue term its command HMAC used (clause 17.6.5) — then each companion
    /// the area carried, every one of which owes a real entry of its own.
    /// </summary>
    /// <param name="state">The state the sessions are resolved against.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_CertifyCreation()</c> request.</param>
    /// <returns>Every slot's response-session material, in command-session order.</returns>
    private static ImmutableArray<TpmAttestResponseSession> BuildCertifyCreationResponseSessions(TpmSimulatorState state, TpmCertifyCreationOverSessionRequested request)
    {
        var sessions = ImmutableArray.CreateBuilder<TpmAttestResponseSession>(3);

        sessions.Add(request.SignSessionHandle.IsPasswordSession
            ? AttestPasswordPlaceholderSession(request.SignSessionHandle.Value, request.SignNonceCaller)
            : AttestRealResponseSession(
                state.HmacSessions[TpmiShHmac.FromValue(request.SignSessionHandle.Value)], request.ResolvedSignAuthValue ?? Tpm2bAuth.Empty,
                state.TransientObjects[request.SignHandle].AuthValue, request.SignNonceCaller, request.SignSessionAttributes,
                encrypts: (request.SignSessionAttributes & TpmaSession.ENCRYPT) != 0));

        if(request.HasCompanionSlot)
        {
            sessions.Add(AttestRealResponseSession(
                state.HmacSessions[TpmiShHmac.FromValue(request.CompanionSessionHandle.Value)], Tpm2bAuth.Empty, Tpm2bAuth.Empty, request.CompanionNonceCaller, request.CompanionSessionAttributes,
                encrypts: (request.CompanionSessionAttributes & TpmaSession.ENCRYPT) != 0));
        }

        if(request.HasSecondCompanionSlot)
        {
            sessions.Add(AttestRealResponseSession(
                state.HmacSessions[TpmiShHmac.FromValue(request.SecondCompanionSessionHandle.Value)], Tpm2bAuth.Empty, Tpm2bAuth.Empty, request.SecondCompanionNonceCaller, request.SecondCompanionSessionAttributes,
                encrypts: (request.SecondCompanionSessionAttributes & TpmaSession.ENCRYPT) != 0));
        }

        return sessions.ToImmutable();
    }

    /// <summary>
    /// Has a signing key attest another loaded object's Name over one or two authorization sessions, for the
    /// session-authorized form of <c>TPM2_Certify()</c> (TPM 2.0 Library Part 3, clause 18.2): <c>@objectHandle</c>
    /// (Auth Index 1, ADMIN role) then <c>@signHandle</c> (Auth Index 2, USER role). Each slot independently is a
    /// password or a real HMAC session; the parser routes an all-password area to the plain <see cref="OnCertify"/>,
    /// so at least one slot here is real.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The slots' ladders run in session order, each complete before the next (Part 3, clause 5.6): the ADMIN
    /// object slot carries a DA/Lockout gate but no check-7.1 gate (its own session-shape rule is check 5.1,
    /// unmodelled on both shapes); the USER sign slot carries both. A password slot's hmac is compared inline; a
    /// real slot's command HMAC is queued and verified in <see cref="ContinueCertifyOverSession"/>. cpHash's
    /// handle Names are the certified object's then the signer's (handle order).
    /// </para>
    /// <para>
    /// A third, companion slot (Part 1, clause 16.6.1, Table 9) authorizes nothing and is admitted for the
    /// <c>decrypt</c>/<c>encrypt</c>/<c>audit</c> attributes alone; it still presents a real command HMAC of its
    /// own and owes its own response entry (clause 16.6.1). Either parameter-encryption attribute may equally
    /// ride one of the two authorizing slots (Table 12: "A session with this attribute does not need to be
    /// associated with an entity identified in the handle area"), so which slot decrypts and which encrypts is
    /// decided from the attribute BITS in area order, never from a slot's kind. This arm models no command
    /// audit, so that one attribute is still refused with <c>TPM_RC_ATTRIBUTES</c> at the claiming slot.
    /// </para>
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_Certify()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the command-HMAC verification, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnCertifyOverSession(TpmSimulatorState state, TpmCertifyOverSessionRequested request)
    {
        if(!state.TransientObjects.TryGetValue(request.ObjectHandle, out TransientKeyState? subject))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Certify, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        if(!state.TransientObjects.TryGetValue(request.SignHandle, out TransientKeyState? signer))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Certify, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        if(!TryResolveCommandSession(state, request.ObjectSessionHandle, sessionIndex: 0, out HmacSessionState? objectSession, out TpmRcConstants objectRefusal))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Certify, objectRefusal, request);
        }

        if(!TryResolveCommandSession(state, request.SignSessionHandle, sessionIndex: 1, out HmacSessionState? signSession, out TpmRcConstants signRefusal))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Certify, signRefusal, request);
        }

        //The companion slot, when the area carried one, authorizes nothing and sits at index 2 — the position
        //Table 9 reserves for encryption, decryption, or audit alone (Part 1, clause 16.6.1).
        //Whether the block arrived is a structural fact the parser settled from authorizationSize, so it is read
        //from the record rather than guessed from the handle, and it is resolved and validated for every value
        //it can hold: a handle that is not a session handle at all is TPM_RC_HANDLE and a well-typed handle
        //naming no loaded session is TPM_RC_REFERENCE_S*, both blamed on this index (Part 3, clause 5.5, step 4).
        bool hasCompanion = request.HasCompanionSlot;
        HmacSessionState? companionSession = null;
        if(hasCompanion
            && !TryResolveCommandSession(state, request.CompanionSessionHandle, sessionIndex: 2, out companionSession, out TpmRcConstants companionRefusal))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Certify, companionRefusal, request);
        }

        TpmRcConstants? sessionAreaError = ValidateSessionArea(
            request.ObjectSessionAttributes, firstAuthorizesEntity: true, objectSession?.Symmetric ?? TpmtSymDef.Null,
            hasSecondSession: true, request.SignSessionAttributes, signSession?.Symmetric ?? TpmtSymDef.Null,
            firstCommandParameterIsEncryptable: true, firstResponseParameterIsEncryptable: true,
            auditIsSupported: false, secondAuthorizesEntity: true,
            firstSessionHandle: request.ObjectSessionHandle, secondSessionHandle: request.SignSessionHandle,
            hasThirdSession: hasCompanion, thirdAttributes: request.CompanionSessionAttributes,
            thirdSymmetric: companionSession?.Symmetric, thirdSessionHandle: request.CompanionSessionHandle,
            firstNonceLength: request.ObjectNonceCaller.Size, secondNonceLength: request.SignNonceCaller.Size,
            thirdNonceLength: request.CompanionNonceCaller.Size);
        if(sessionAreaError is TpmRcConstants areaRc)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Certify, areaRc, request);
        }

        //Both of this command's first parameters are encryption-eligible (Part 3, clause 18.2, Tables 89 and 90:
        //qualifyingData is the first command parameter and certifyInfo the first response parameter, both TPM2B),
        //and the area-level gates above have already refused a second claimer of either, so each search below
        //finds the only slot there is to find.
        ReadOnlySpan<TpmaSession> allSlotAttributes = [request.ObjectSessionAttributes, request.SignSessionAttributes, request.CompanionSessionAttributes];
        ReadOnlySpan<TpmaSession> slotAttributes = allSlotAttributes[..(hasCompanion ? 3 : 2)];
        ReadOnlySpan<HmacSessionState?> slotSessions = [objectSession, signSession, companionSession];
        (Tpm2bNonce foldedNonceDecrypt, Tpm2bNonce foldedNonceEncrypt) = FoldedSessionNonces(
            slotSessions, FindClaimingSlot(slotAttributes, TpmaSession.DECRYPT), FindClaimingSlot(slotAttributes, TpmaSession.ENCRYPT));

        if(objectSession is not null && IsBoundSessionLockedOut(state, objectSession))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Certify, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        if(signSession is not null && IsBoundSessionLockedOut(state, signSession))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Certify, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        if(companionSession is not null && IsBoundSessionLockedOut(state, companionSession))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Certify, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        //Object slot (index 0, ADMIN role): entity lockout (check 3) then, for a password slot, the inline
        //compare against the certified object's retained authValue. No check-7.1 gate on the ADMIN slot.
        if(subject.IsDaProtected && state.IsInLockout)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Certify, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        bool objectIsPassword = request.ObjectSessionHandle.IsPasswordSession;
        if(objectIsPassword
            && !CryptographicOperations.FixedTimeEquals(StripTrailingZeros(request.SuppliedObjectHmac.AsReadOnlySpan()), StripTrailingZeros(subject.AuthValue.AsReadOnlySpan())))
        {
            return RejectSessionAuthFailure(state, TpmCcConstants.TPM_CC_Certify, sessionIndex: 0, subject.IsDaProtected, request);
        }

        //Sign slot (index 1, USER role): entity lockout (check 3), the check-7.1 gate uncharged and before the
        //compare, then a password slot's inline compare against the signing key's retained authValue.
        if(signer.IsDaProtected && state.IsInLockout)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Certify, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        if((signer.Attributes & TpmaObject.USER_WITH_AUTH) == 0)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Certify, TpmRcConstants.TPM_RC_POLICY_FAIL, request);
        }

        bool signIsPassword = request.SignSessionHandle.IsPasswordSession;
        if(signIsPassword
            && !CryptographicOperations.FixedTimeEquals(StripTrailingZeros(request.SuppliedSignHmac.AsReadOnlySpan()), StripTrailingZeros(signer.AuthValue.AsReadOnlySpan())))
        {
            return RejectSessionAuthFailure(state, TpmCcConstants.TPM_CC_Certify, sessionIndex: 1, signer.IsDaProtected, request);
        }

        TpmCommandHandleNames handleNames = TpmCommandHandleNames.Of(TpmHandleName.FromName(subject.Name), TpmHandleName.FromName(signer.Name));

        //One pending verification per REAL slot, in wire session order (object at index 0, sign at index 1); a
        //password slot was compared inline above. Each slot's bind-omission is resolved once and threaded onward
        //so the response HMAC reuses the identical key (Part 1, clause 17.6.5).
        var pendings = ImmutableArray.CreateBuilder<TpmPendingSessionVerification>(2);
        Tpm2bAuth? resolvedObjectAuthValue = null;
        Tpm2bAuth? resolvedSignAuthValue = null;

        if(!objectIsPassword)
        {
            HmacSessionState session = objectSession!;
            bool bindOmits = session.BoundEntity.Matches(subject.Name.Span, StripTrailingZeros(subject.AuthValue.AsReadOnlySpan()));
            Tpm2bAuth authForHmac = bindOmits ? Tpm2bAuth.Empty : subject.AuthValue;
            resolvedObjectAuthValue = authForHmac;

            pendings.Add(new TpmPendingSessionVerification(
                SessionHandle: TpmiShAuthSession.FromValue(session.Handle.Value), SessionIndex: 0, SessionAlg: session.SessionAlg, SessionKey: session.SessionKey,
                AuthValue: authForHmac, IsDaProtected: subject.IsDaProtected || session.IsBoundEntityDaProtected,
                NonceCaller: request.ObjectNonceCaller, NonceTpm: session.NonceTpm, FoldedNonceDecrypt: foldedNonceDecrypt, FoldedNonceEncrypt: foldedNonceEncrypt,
                SessionAttributes: request.ObjectSessionAttributes, SuppliedHmac: request.SuppliedObjectHmac,
                IsLockoutEntity: session.IsBoundToLockout));
        }

        if(!signIsPassword)
        {
            HmacSessionState session = signSession!;
            bool bindOmits = session.BoundEntity.Matches(signer.Name.Span, StripTrailingZeros(signer.AuthValue.AsReadOnlySpan()));
            Tpm2bAuth authForHmac = bindOmits ? Tpm2bAuth.Empty : signer.AuthValue;
            resolvedSignAuthValue = authForHmac;

            pendings.Add(new TpmPendingSessionVerification(
                SessionHandle: TpmiShAuthSession.FromValue(session.Handle.Value), SessionIndex: 1, SessionAlg: session.SessionAlg, SessionKey: session.SessionKey,
                AuthValue: authForHmac, IsDaProtected: signer.IsDaProtected || session.IsBoundEntityDaProtected,
                NonceCaller: request.SignNonceCaller, NonceTpm: session.NonceTpm, FoldedNonceDecrypt: Tpm2bNonce.Empty, FoldedNonceEncrypt: Tpm2bNonce.Empty,
                SessionAttributes: request.SignSessionAttributes, SuppliedHmac: request.SuppliedSignHmac,
                IsLockoutEntity: session.IsBoundToLockout));
        }

        //The companion authorizes no entity, so its HMAC key folds no authValue and its dictionary-attack
        //standing comes from its own bind alone (Part 1, clause 17.8.1). It still owes a command HMAC (Part 3,
        //clause 5.6).
        if(companionSession is not null)
        {
            pendings.Add(new TpmPendingSessionVerification(
                SessionHandle: TpmiShAuthSession.FromValue(companionSession.Handle.Value), SessionIndex: 2, SessionAlg: companionSession.SessionAlg, SessionKey: companionSession.SessionKey,
                AuthValue: Tpm2bAuth.Empty, IsDaProtected: companionSession.IsBoundEntityDaProtected,
                NonceCaller: request.CompanionNonceCaller, NonceTpm: companionSession.NonceTpm,
                FoldedNonceDecrypt: Tpm2bNonce.Empty, FoldedNonceEncrypt: Tpm2bNonce.Empty,
                SessionAttributes: request.CompanionSessionAttributes, SuppliedHmac: request.SuppliedCompanionHmac,
                IsLockoutEntity: companionSession.IsBoundToLockout));
        }

        //Non-empty for the same reason the single-slot arms' queues are: two LONE password slots parse to
        //TpmCertifyRequested instead of reaching here, and a TPM_RS_PW companion is refused by the session-area
        //validation above.
        ImmutableArray<TpmPendingSessionVerification> queue = pendings.ToImmutable();

        return Transition(
            state with
            {
                NextAction = new TpmVerifyCommandHmacAction(
                    TpmCcConstants.TPM_CC_Certify, handleNames, request.RawParameterArea, queue[0], queue.RemoveAt(0),
                    request with { ResolvedObjectAuthValue = resolvedObjectAuthValue, ResolvedSignAuthValue = resolvedSignAuthValue }),
                ResponseIntent = null
            },
            "Certify:OverSession:HmacVerifyRequested");
    }

    /// <summary>
    /// Assembles both <c>TPM2_Certify()</c> authorization slots' response-session material in command-session
    /// order (TPM 2.0 Library Part 1, clause 16.6.1): a <c>TPM_RS_PW</c> slot's placeholder, or a real session's
    /// key material for a rolled-nonce entry keyed on the same authValue term the command HMAC used (clause
    /// 17.6.5).
    /// </summary>
    /// <param name="state">The state the sessions are resolved against.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_Certify()</c> request.</param>
    /// <returns>Every slot's response-session material, in command-session order.</returns>
    private static ImmutableArray<TpmAttestResponseSession> BuildCertifyResponseSessions(TpmSimulatorState state, TpmCertifyOverSessionRequested request)
    {
        var sessions = ImmutableArray.CreateBuilder<TpmAttestResponseSession>(3);

        sessions.Add(request.ObjectSessionHandle.IsPasswordSession
            ? AttestPasswordPlaceholderSession(request.ObjectSessionHandle.Value, request.ObjectNonceCaller)
            : AttestRealResponseSession(
                state.HmacSessions[TpmiShHmac.FromValue(request.ObjectSessionHandle.Value)], request.ResolvedObjectAuthValue ?? Tpm2bAuth.Empty,
                state.TransientObjects[request.ObjectHandle].AuthValue, request.ObjectNonceCaller, request.ObjectSessionAttributes,
                encrypts: (request.ObjectSessionAttributes & TpmaSession.ENCRYPT) != 0));

        sessions.Add(request.SignSessionHandle.IsPasswordSession
            ? AttestPasswordPlaceholderSession(request.SignSessionHandle.Value, request.SignNonceCaller)
            : AttestRealResponseSession(
                state.HmacSessions[TpmiShHmac.FromValue(request.SignSessionHandle.Value)], request.ResolvedSignAuthValue ?? Tpm2bAuth.Empty,
                state.TransientObjects[request.SignHandle].AuthValue, request.SignNonceCaller, request.SignSessionAttributes,
                encrypts: (request.SignSessionAttributes & TpmaSession.ENCRYPT) != 0));

        if(request.HasCompanionSlot)
        {
            sessions.Add(AttestRealResponseSession(
                state.HmacSessions[TpmiShHmac.FromValue(request.CompanionSessionHandle.Value)], Tpm2bAuth.Empty, Tpm2bAuth.Empty, request.CompanionNonceCaller, request.CompanionSessionAttributes,
                encrypts: (request.CompanionSessionAttributes & TpmaSession.ENCRYPT) != 0));
        }

        return sessions.ToImmutable();
    }

    /// <summary>
    /// Resumes the session-authorized <c>TPM2_Certify()</c> once every queued command HMAC has verified, by
    /// declaring the step that recovers <c>qualifyingData</c> in plaintext (TPM 2.0 Library Part 3, clause 5.6's
    /// authorization precedes clause 5.7's decryption, which precedes clause 5.8's unmarshaling).
    /// </summary>
    /// <remarks>
    /// Declared for every arrival, not only an encrypted one, so the value the ladder reads has a single origin;
    /// <see cref="CompleteCertifyOverSession"/> is the ladder itself. Either authorizing slot may carry the
    /// attribute, and each folds its OWN entity's authValue into the cipher key.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_Certify()</c> request, its sessions now verified.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the decryption step.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> ContinueCertifyOverSession(TpmSimulatorState state, TpmCertifyOverSessionRequested request)
    {
        ReadOnlySpan<TpmaSession> allSlotAttributes = [request.ObjectSessionAttributes, request.SignSessionAttributes, request.CompanionSessionAttributes];
        ReadOnlySpan<TpmaSession> slotAttributes = allSlotAttributes[..(request.HasCompanionSlot ? 3 : 2)];
        int decryptIndex = FindClaimingSlot(slotAttributes, TpmaSession.DECRYPT);

        //The decrypt slot's own authorized entity supplies the cipher key's authValue term, UNRESOLVED by the
        //session's bind (Part 1, clause 19.1): the certified object's for slot 0, the signing key's for slot 1,
        //none for a companion.
        (HmacSessionState? Session, Tpm2bAuth EntityAuthValue, Tpm2bNonce NonceCaller) decrypt = decryptIndex switch
        {
            0 => (state.HmacSessions[TpmiShHmac.FromValue(request.ObjectSessionHandle.Value)], state.TransientObjects[request.ObjectHandle].AuthValue, request.ObjectNonceCaller),
            1 => (state.HmacSessions[TpmiShHmac.FromValue(request.SignSessionHandle.Value)], state.TransientObjects[request.SignHandle].AuthValue, request.SignNonceCaller),
            2 => (state.HmacSessions[TpmiShHmac.FromValue(request.CompanionSessionHandle.Value)], Tpm2bAuth.Empty, request.CompanionNonceCaller),
            _ => (null, Tpm2bAuth.Empty, Tpm2bNonce.Empty)
        };

        return DeclareAttestQualifyingDataDecryption(
            state, TpmCcConstants.TPM_CC_Certify, request, request.RawParameterArea, decryptIndex,
            decrypt.Session, decrypt.EntityAuthValue, decrypt.NonceCaller, "Certify:OverSession:QualifyingDataDecryptRequested");
    }

    /// <summary>
    /// Runs the session-authorized <c>TPM2_Certify()</c> ladder once <c>qualifyingData</c> has been recovered:
    /// the password arm's remaining ladder verbatim, then the attestation carrying both slots' response entries.
    /// This transition is the terminal owner of both slots' supplied HMACs, transfers each slot's caller nonce
    /// into its own response-session entry, and transfers the qualifying data into the certify action; the attest
    /// effect releases all three transferred carriers, and a refusing arm releases every one of the five through
    /// the request's own <see cref="IDisposable.Dispose"/>.
    /// </summary>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_Certify()</c> request, carrying the recovered qualifying data.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the certify action, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> CompleteCertifyOverSession(TpmSimulatorState state, TpmCertifyOverSessionRequested request)
    {
        TransientKeyState subject = state.TransientObjects[request.ObjectHandle];
        TransientKeyState signer = state.TransientObjects[request.SignHandle];

        if((signer.Attributes & TpmaObject.USER_WITH_AUTH) == 0)
        {
            request.Dispose();

            return Reject(state, TpmCcConstants.TPM_CC_Certify, TpmRcConstants.TPM_RC_POLICY_FAIL);
        }

        if(request.QualifyingData.Length > Tpm2bData.MaxSize)
        {
            request.Dispose();

            return Reject(state, TpmCcConstants.TPM_CC_Certify, TpmRcConstants.TPM_RC_SIZE);
        }

        if(!CanSign(signer.Attributes))
        {
            request.Dispose();

            return Reject(state, TpmCcConstants.TPM_CC_Certify, TpmRcConstants.TPM_RC_KEY);
        }

        if(!IsSupportedAttestHashAlg(request.SchemeHashAlg))
        {
            request.Dispose();

            return Reject(state, TpmCcConstants.TPM_CC_Certify, TpmRcConstants.TPM_RC_HASH);
        }

        TpmsClockInfo clockSnapshot = new(state.Clock, state.ResetCount, state.RestartCount, state.ClockSafe);
        ImmutableArray<TpmAttestResponseSession> responseSessions = BuildCertifyResponseSessions(state, request);

        TpmAction? action = (signer.KeyType.Value, request.SignatureScheme.Value) switch
        {
            (TpmAlgIdConstants.TPM_ALG_RSA, TpmAlgIdConstants.TPM_ALG_RSASSA or TpmAlgIdConstants.TPM_ALG_RSAPSS) =>
                new TpmRsaCertifyAction(
                    subject.Name, subject.Hierarchy, signer.Name, signer.Hierarchy, request.QualifyingData, signer.PrivateKey, request.SignatureScheme, request.SchemeHashAlg, clockSnapshot, responseSessions),
            (TpmAlgIdConstants.TPM_ALG_ECC, TpmAlgIdConstants.TPM_ALG_ECDSA) =>
                new TpmCertifyAction(
                    subject.Name, subject.Hierarchy, signer.Name, signer.Hierarchy, request.QualifyingData, signer.PrivateKey, signer.Curve, request.SignatureScheme, request.SchemeHashAlg, clockSnapshot, responseSessions),
            _ => null
        };

        if(action is null)
        {
            request.Dispose();

            return Reject(state, TpmCcConstants.TPM_CC_Certify, TpmRcConstants.TPM_RC_SCHEME);
        }

        //The continuation is every supplied HMAC's and the parameter area's terminal owner — their verification
        //was their only use — while each slot's caller nonce has transferred into that slot's response-session
        //entry and the qualifying data into the action, all of which the effect releases.
        request.SuppliedObjectHmac.Dispose();
        request.SuppliedSignHmac.Dispose();
        request.SuppliedCompanionHmac.Dispose();
        request.RawParameterArea.Dispose();

        return Transition(
            state with
            {
                NextAction = action,
                ResponseIntent = null
            },
            "Certify:OverSession:AttestRequested");
    }

    /// <summary>
    /// Has a signing key attest the TPM's current time over one or two authorization sessions, for the
    /// session-authorized form of <c>TPM2_GetTime()</c> (TPM 2.0 Library Part 3, clause 18.7):
    /// <c>@privacyAdminHandle</c> (Auth Index 1, USER role; fixed to <c>TPM_RH_ENDORSEMENT</c>) then
    /// <c>@signHandle</c> (Auth Index 2, USER role). Each slot independently is a password or a real HMAC
    /// session; the parser routes an area of two LONE password slots to the plain <see cref="OnGetTime"/>, so at
    /// least one slot here is real or a companion accompanies them.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The privacy-administrator slot authorizes the endorsement HIERARCHY: its enable and authValue availability
    /// gates run first (<c>TPM_RC_HIERARCHY</c>/<c>TPM_RC_VALUE</c>), then a password compares inline (bare
    /// <c>TPM_RC_BAD_AUTH</c>, DA-exempt) or a real session's command HMAC keys on the 4-octet handle Name. The
    /// <c>BeginHierarchyAuthorization</c> ladder is inlined here rather than called, because that helper fixes
    /// session index 0 with a single-authorizing-slot decrypt-companion shape and GetTime carries a SECOND
    /// authorizing slot. The sign slot then carries the ordinary USER-role DA and check-7.1 gates.
    /// </para>
    /// <para>
    /// A third, companion slot (Part 1, clause 16.6.1, Table 9) authorizes nothing and is admitted for the
    /// <c>decrypt</c>/<c>encrypt</c>/<c>audit</c> attributes alone; it still presents a real command HMAC of its
    /// own and owes its own response entry (clause 16.6.1). Either parameter-encryption attribute may equally
    /// ride one of the two authorizing slots (Table 12: "A session with this attribute does not need to be
    /// associated with an entity identified in the handle area"), so which slot decrypts and which encrypts is
    /// decided from the attribute BITS in area order, never from a slot's kind. This arm models no command
    /// audit, so that one attribute is still refused with <c>TPM_RC_ATTRIBUTES</c> at the claiming slot.
    /// </para>
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_GetTime()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the command-HMAC verification, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnGetTimeOverSession(TpmSimulatorState state, TpmGetTimeOverSessionRequested request)
    {
        if(request.PrivacyAdminHandle.Value != (uint)TpmRh.TPM_RH_ENDORSEMENT)
        {
            return Reject(state, TpmCcConstants.TPM_CC_GetTime, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        if(!state.TransientObjects.TryGetValue(request.SignHandle, out TransientKeyState? signer))
        {
            return Reject(state, TpmCcConstants.TPM_CC_GetTime, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        if(!TryResolveCommandSession(state, request.PrivacyAdminSessionHandle, sessionIndex: 0, out HmacSessionState? privacyAdminSession, out TpmRcConstants privacyAdminRefusal))
        {
            return Reject(state, TpmCcConstants.TPM_CC_GetTime, privacyAdminRefusal, request);
        }

        if(!TryResolveCommandSession(state, request.SignSessionHandle, sessionIndex: 1, out HmacSessionState? signSession, out TpmRcConstants signRefusal))
        {
            return Reject(state, TpmCcConstants.TPM_CC_GetTime, signRefusal, request);
        }

        //The companion slot, when the area carried one, authorizes nothing and sits at index 2 — the position
        //Table 9 reserves for encryption, decryption, or audit alone (Part 1, clause 16.6.1).
        //Whether the block arrived is a structural fact the parser settled from authorizationSize, so it is read
        //from the record rather than guessed from the handle, and it is resolved and validated for every value
        //it can hold: a handle that is not a session handle at all is TPM_RC_HANDLE and a well-typed handle
        //naming no loaded session is TPM_RC_REFERENCE_S*, both blamed on this index (Part 3, clause 5.5, step 4).
        bool hasCompanion = request.HasCompanionSlot;
        HmacSessionState? companionSession = null;
        if(hasCompanion
            && !TryResolveCommandSession(state, request.CompanionSessionHandle, sessionIndex: 2, out companionSession, out TpmRcConstants companionRefusal))
        {
            return Reject(state, TpmCcConstants.TPM_CC_GetTime, companionRefusal, request);
        }

        TpmRcConstants? sessionAreaError = ValidateSessionArea(
            request.PrivacyAdminSessionAttributes, firstAuthorizesEntity: true, privacyAdminSession?.Symmetric ?? TpmtSymDef.Null,
            hasSecondSession: true, request.SignSessionAttributes, signSession?.Symmetric ?? TpmtSymDef.Null,
            firstCommandParameterIsEncryptable: true, firstResponseParameterIsEncryptable: true,
            auditIsSupported: false, secondAuthorizesEntity: true,
            firstSessionHandle: request.PrivacyAdminSessionHandle, secondSessionHandle: request.SignSessionHandle,
            hasThirdSession: hasCompanion, thirdAttributes: request.CompanionSessionAttributes,
            thirdSymmetric: companionSession?.Symmetric, thirdSessionHandle: request.CompanionSessionHandle,
            firstNonceLength: request.PrivacyAdminNonceCaller.Size, secondNonceLength: request.SignNonceCaller.Size,
            thirdNonceLength: request.CompanionNonceCaller.Size);
        if(sessionAreaError is TpmRcConstants areaRc)
        {
            return Reject(state, TpmCcConstants.TPM_CC_GetTime, areaRc, request);
        }

        //Both of this command's first parameters are encryption-eligible (Part 3, clause 18.7, Tables 99 and 100:
        //qualifyingData is the first command parameter and timeInfo the first response parameter, both TPM2B),
        //and the area-level gates above have already refused a second claimer of either, so each search below
        //finds the only slot there is to find.
        ReadOnlySpan<TpmaSession> allSlotAttributes = [request.PrivacyAdminSessionAttributes, request.SignSessionAttributes, request.CompanionSessionAttributes];
        ReadOnlySpan<TpmaSession> slotAttributes = allSlotAttributes[..(hasCompanion ? 3 : 2)];
        ReadOnlySpan<HmacSessionState?> slotSessions = [privacyAdminSession, signSession, companionSession];
        (Tpm2bNonce foldedNonceDecrypt, Tpm2bNonce foldedNonceEncrypt) = FoldedSessionNonces(
            slotSessions, FindClaimingSlot(slotAttributes, TpmaSession.DECRYPT), FindClaimingSlot(slotAttributes, TpmaSession.ENCRYPT));

        if(privacyAdminSession is not null && IsBoundSessionLockedOut(state, privacyAdminSession))
        {
            return Reject(state, TpmCcConstants.TPM_CC_GetTime, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        if(signSession is not null && IsBoundSessionLockedOut(state, signSession))
        {
            return Reject(state, TpmCcConstants.TPM_CC_GetTime, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        if(companionSession is not null && IsBoundSessionLockedOut(state, companionSession))
        {
            return Reject(state, TpmCcConstants.TPM_CC_GetTime, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        //Privacy-administrator slot (index 0, endorsement hierarchy, USER role): the enable and authValue
        //availability gates first (an enable FALSE makes the authValue unusable, Part 1, clause 11.2), then a
        //password compares inline against the endorsement authValue. A permanent hierarchy other than lockoutAuth
        //is never dictionary-attack protected (clause 17.8.1), so a mismatch is uncharged TPM_RC_BAD_AUTH — but
        //in this session-authorized area it is index-encoded to slot 0 (Part 2, clause 6.6.2), the same shape the
        //NV_Certify owner-arm password mismatch takes; RejectSessionAuthFailure with isDaProtected FALSE gives
        //exactly that session-encoded, uncharged BAD_AUTH.
        if(!state.IsHierarchyEnabled(request.PrivacyAdminHandle.Value))
        {
            return Reject(state, TpmCcConstants.TPM_CC_GetTime, TpmRcConstants.TPM_RC_HIERARCHY, request);
        }

        if(!state.TryGetHierarchyAuthValue(request.PrivacyAdminHandle.Value, out Tpm2bAuth endorsementAuth))
        {
            return Reject(state, TpmCcConstants.TPM_CC_GetTime, TpmRcConstants.TPM_RC_VALUE, request);
        }

        bool privacyAdminIsPassword = request.PrivacyAdminSessionHandle.IsPasswordSession;
        if(privacyAdminIsPassword
            && !CryptographicOperations.FixedTimeEquals(StripTrailingZeros(request.SuppliedPrivacyAdminHmac.AsReadOnlySpan()), StripTrailingZeros(endorsementAuth.AsReadOnlySpan())))
        {
            return RejectSessionAuthFailure(state, TpmCcConstants.TPM_CC_GetTime, sessionIndex: 0, isDaProtected: false, request);
        }

        //Sign slot (index 1, USER role): entity lockout (check 3), the check-7.1 gate uncharged and before the
        //compare, then a password slot's inline compare against the signing key's retained authValue.
        if(signer.IsDaProtected && state.IsInLockout)
        {
            return Reject(state, TpmCcConstants.TPM_CC_GetTime, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        if((signer.Attributes & TpmaObject.USER_WITH_AUTH) == 0)
        {
            return Reject(state, TpmCcConstants.TPM_CC_GetTime, TpmRcConstants.TPM_RC_POLICY_FAIL, request);
        }

        bool signIsPassword = request.SignSessionHandle.IsPasswordSession;
        if(signIsPassword
            && !CryptographicOperations.FixedTimeEquals(StripTrailingZeros(request.SuppliedSignHmac.AsReadOnlySpan()), StripTrailingZeros(signer.AuthValue.AsReadOnlySpan())))
        {
            return RejectSessionAuthFailure(state, TpmCcConstants.TPM_CC_GetTime, sessionIndex: 1, signer.IsDaProtected, request);
        }

        //cpHash's Name1/Name2 (Part 1, clause 16.7 equation 15): the privacy administration hierarchy's own
        //4-octet handle, which IS a permanent entity's Name (Part 1, clause 14, Table 6), then the signing key's Name.
        TpmCommandHandleNames handleNames = TpmCommandHandleNames.Of(
            TpmHandleName.FromHandle(request.PrivacyAdminHandle.Value), TpmHandleName.FromName(signer.Name));

        var pendings = ImmutableArray.CreateBuilder<TpmPendingSessionVerification>(2);
        Tpm2bAuth? resolvedPrivacyAdminAuthValue = null;
        Tpm2bAuth? resolvedSignAuthValue = null;

        if(!privacyAdminIsPassword)
        {
            HmacSessionState session = privacyAdminSession!;
            bool bindOmits = MatchesHandleFormBoundEntity(session.BoundEntity, request.PrivacyAdminHandle.Value, StripTrailingZeros(endorsementAuth.AsReadOnlySpan()));
            Tpm2bAuth authForHmac = bindOmits ? Tpm2bAuth.Empty : endorsementAuth;
            resolvedPrivacyAdminAuthValue = authForHmac;

            pendings.Add(new TpmPendingSessionVerification(
                SessionHandle: TpmiShAuthSession.FromValue(session.Handle.Value), SessionIndex: 0, SessionAlg: session.SessionAlg, SessionKey: session.SessionKey,
                AuthValue: authForHmac, IsDaProtected: session.IsBoundEntityDaProtected,
                NonceCaller: request.PrivacyAdminNonceCaller, NonceTpm: session.NonceTpm, FoldedNonceDecrypt: foldedNonceDecrypt, FoldedNonceEncrypt: foldedNonceEncrypt,
                SessionAttributes: request.PrivacyAdminSessionAttributes, SuppliedHmac: request.SuppliedPrivacyAdminHmac,
                IsLockoutEntity: session.IsBoundToLockout));
        }

        if(!signIsPassword)
        {
            HmacSessionState session = signSession!;
            bool bindOmits = session.BoundEntity.Matches(signer.Name.Span, StripTrailingZeros(signer.AuthValue.AsReadOnlySpan()));
            Tpm2bAuth authForHmac = bindOmits ? Tpm2bAuth.Empty : signer.AuthValue;
            resolvedSignAuthValue = authForHmac;

            pendings.Add(new TpmPendingSessionVerification(
                SessionHandle: TpmiShAuthSession.FromValue(session.Handle.Value), SessionIndex: 1, SessionAlg: session.SessionAlg, SessionKey: session.SessionKey,
                AuthValue: authForHmac, IsDaProtected: signer.IsDaProtected || session.IsBoundEntityDaProtected,
                NonceCaller: request.SignNonceCaller, NonceTpm: session.NonceTpm, FoldedNonceDecrypt: Tpm2bNonce.Empty, FoldedNonceEncrypt: Tpm2bNonce.Empty,
                SessionAttributes: request.SignSessionAttributes, SuppliedHmac: request.SuppliedSignHmac,
                IsLockoutEntity: session.IsBoundToLockout));
        }

        //The companion authorizes no entity, so its HMAC key folds no authValue and its dictionary-attack
        //standing comes from its own bind alone (Part 1, clause 17.8.1). It still owes a command HMAC (Part 3,
        //clause 5.6).
        if(companionSession is not null)
        {
            pendings.Add(new TpmPendingSessionVerification(
                SessionHandle: TpmiShAuthSession.FromValue(companionSession.Handle.Value), SessionIndex: 2, SessionAlg: companionSession.SessionAlg, SessionKey: companionSession.SessionKey,
                AuthValue: Tpm2bAuth.Empty, IsDaProtected: companionSession.IsBoundEntityDaProtected,
                NonceCaller: request.CompanionNonceCaller, NonceTpm: companionSession.NonceTpm,
                FoldedNonceDecrypt: Tpm2bNonce.Empty, FoldedNonceEncrypt: Tpm2bNonce.Empty,
                SessionAttributes: request.CompanionSessionAttributes, SuppliedHmac: request.SuppliedCompanionHmac,
                IsLockoutEntity: companionSession.IsBoundToLockout));
        }

        //Non-empty for the same reason the other attest arms' queues are: two LONE password slots parse to
        //TpmGetTimeRequested instead of reaching here, and a TPM_RS_PW companion is refused by the session-area
        //validation above.
        ImmutableArray<TpmPendingSessionVerification> queue = pendings.ToImmutable();

        return Transition(
            state with
            {
                NextAction = new TpmVerifyCommandHmacAction(
                    TpmCcConstants.TPM_CC_GetTime, handleNames, request.RawParameterArea, queue[0], queue.RemoveAt(0),
                    request with { ResolvedPrivacyAdminAuthValue = resolvedPrivacyAdminAuthValue, ResolvedSignAuthValue = resolvedSignAuthValue }),
                ResponseIntent = null
            },
            "GetTime:OverSession:HmacVerifyRequested");
    }

    /// <summary>
    /// Assembles both <c>TPM2_GetTime()</c> authorization slots' response-session material in command-session
    /// order (TPM 2.0 Library Part 1, clause 16.6.1): a <c>TPM_RS_PW</c> slot's placeholder, or a real session's
    /// key material keyed on the same authValue term its command HMAC used (clause 17.6.5) — the endorsement
    /// hierarchy's for the privacy-administrator slot, the signing key's for the sign slot.
    /// </summary>
    /// <param name="state">The state the sessions are resolved against.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_GetTime()</c> request.</param>
    /// <returns>Both slots' response-session material, in command-session order.</returns>
    private static ImmutableArray<TpmAttestResponseSession> BuildGetTimeResponseSessions(TpmSimulatorState state, TpmGetTimeOverSessionRequested request)
    {
        var sessions = ImmutableArray.CreateBuilder<TpmAttestResponseSession>(3);
        _ = state.TryGetHierarchyAuthValue(request.PrivacyAdminHandle.Value, out Tpm2bAuth endorsementAuth);

        sessions.Add(request.PrivacyAdminSessionHandle.IsPasswordSession
            ? AttestPasswordPlaceholderSession(request.PrivacyAdminSessionHandle.Value, request.PrivacyAdminNonceCaller)
            : AttestRealResponseSession(
                state.HmacSessions[TpmiShHmac.FromValue(request.PrivacyAdminSessionHandle.Value)], request.ResolvedPrivacyAdminAuthValue ?? Tpm2bAuth.Empty,
                endorsementAuth, request.PrivacyAdminNonceCaller, request.PrivacyAdminSessionAttributes,
                encrypts: (request.PrivacyAdminSessionAttributes & TpmaSession.ENCRYPT) != 0));

        sessions.Add(request.SignSessionHandle.IsPasswordSession
            ? AttestPasswordPlaceholderSession(request.SignSessionHandle.Value, request.SignNonceCaller)
            : AttestRealResponseSession(
                state.HmacSessions[TpmiShHmac.FromValue(request.SignSessionHandle.Value)], request.ResolvedSignAuthValue ?? Tpm2bAuth.Empty,
                state.TransientObjects[request.SignHandle].AuthValue, request.SignNonceCaller, request.SignSessionAttributes,
                encrypts: (request.SignSessionAttributes & TpmaSession.ENCRYPT) != 0));

        if(request.HasCompanionSlot)
        {
            sessions.Add(AttestRealResponseSession(
                state.HmacSessions[TpmiShHmac.FromValue(request.CompanionSessionHandle.Value)], Tpm2bAuth.Empty, Tpm2bAuth.Empty, request.CompanionNonceCaller, request.CompanionSessionAttributes,
                encrypts: (request.CompanionSessionAttributes & TpmaSession.ENCRYPT) != 0));
        }

        return sessions.ToImmutable();
    }

    /// <summary>
    /// Resumes the session-authorized <c>TPM2_GetTime()</c> once every queued command HMAC has verified, by
    /// declaring the step that recovers <c>qualifyingData</c> in plaintext (TPM 2.0 Library Part 3, clause 5.6's
    /// authorization precedes clause 5.7's decryption, which precedes clause 5.8's unmarshaling).
    /// </summary>
    /// <remarks>
    /// Declared for every arrival, not only an encrypted one, so the value the ladder reads has a single origin;
    /// <see cref="CompleteGetTimeOverSession"/> is the ladder itself. The privacy-administrator slot authorizes a
    /// hierarchy, so a decrypt attribute riding it folds that hierarchy's authValue into the cipher key.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_GetTime()</c> request, its sessions now verified.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the decryption step.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> ContinueGetTimeOverSession(TpmSimulatorState state, TpmGetTimeOverSessionRequested request)
    {
        ReadOnlySpan<TpmaSession> allSlotAttributes = [request.PrivacyAdminSessionAttributes, request.SignSessionAttributes, request.CompanionSessionAttributes];
        ReadOnlySpan<TpmaSession> slotAttributes = allSlotAttributes[..(request.HasCompanionSlot ? 3 : 2)];
        int decryptIndex = FindClaimingSlot(slotAttributes, TpmaSession.DECRYPT);
        _ = state.TryGetHierarchyAuthValue(request.PrivacyAdminHandle.Value, out Tpm2bAuth endorsementAuth);

        //The decrypt slot's own authorized entity supplies the cipher key's authValue term, UNRESOLVED by the
        //session's bind (Part 1, clause 19.1): the endorsement hierarchy's for slot 0, the signing key's for slot
        //1, none for a companion.
        (HmacSessionState? Session, Tpm2bAuth EntityAuthValue, Tpm2bNonce NonceCaller) decrypt = decryptIndex switch
        {
            0 => (state.HmacSessions[TpmiShHmac.FromValue(request.PrivacyAdminSessionHandle.Value)], endorsementAuth, request.PrivacyAdminNonceCaller),
            1 => (state.HmacSessions[TpmiShHmac.FromValue(request.SignSessionHandle.Value)], state.TransientObjects[request.SignHandle].AuthValue, request.SignNonceCaller),
            2 => (state.HmacSessions[TpmiShHmac.FromValue(request.CompanionSessionHandle.Value)], Tpm2bAuth.Empty, request.CompanionNonceCaller),
            _ => (null, Tpm2bAuth.Empty, Tpm2bNonce.Empty)
        };

        return DeclareAttestQualifyingDataDecryption(
            state, TpmCcConstants.TPM_CC_GetTime, request, request.RawParameterArea, decryptIndex,
            decrypt.Session, decrypt.EntityAuthValue, decrypt.NonceCaller, "GetTime:OverSession:QualifyingDataDecryptRequested");
    }

    /// <summary>
    /// Runs the session-authorized <c>TPM2_GetTime()</c> ladder once <c>qualifyingData</c> has been recovered:
    /// the password arm's remaining ladder verbatim, then the attestation carrying both slots' response entries.
    /// This transition is the terminal owner of both slots' supplied HMACs, transfers each slot's caller nonce
    /// into its own response-session entry, and transfers the qualifying data into the time-attestation action;
    /// the attest effect releases all three transferred carriers, and a refusing arm releases every one of the
    /// five through the request's own <see cref="IDisposable.Dispose"/>.
    /// </summary>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_GetTime()</c> request, carrying the recovered qualifying data.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the attestation action, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> CompleteGetTimeOverSession(TpmSimulatorState state, TpmGetTimeOverSessionRequested request)
    {
        TransientKeyState signer = state.TransientObjects[request.SignHandle];

        if((signer.Attributes & TpmaObject.USER_WITH_AUTH) == 0)
        {
            request.Dispose();

            return Reject(state, TpmCcConstants.TPM_CC_GetTime, TpmRcConstants.TPM_RC_POLICY_FAIL);
        }

        if(request.QualifyingData.Length > Tpm2bData.MaxSize)
        {
            request.Dispose();

            return Reject(state, TpmCcConstants.TPM_CC_GetTime, TpmRcConstants.TPM_RC_SIZE);
        }

        if(!CanSign(signer.Attributes))
        {
            request.Dispose();

            return Reject(state, TpmCcConstants.TPM_CC_GetTime, TpmRcConstants.TPM_RC_KEY);
        }

        if(!IsSupportedAttestHashAlg(request.SchemeHashAlg))
        {
            request.Dispose();

            return Reject(state, TpmCcConstants.TPM_CC_GetTime, TpmRcConstants.TPM_RC_HASH);
        }

        TpmsClockInfo clockSnapshot = new(state.Clock, state.ResetCount, state.RestartCount, state.ClockSafe);
        ImmutableArray<TpmAttestResponseSession> responseSessions = BuildGetTimeResponseSessions(state, request);

        TpmAction? action = (signer.KeyType.Value, request.SignatureScheme.Value) switch
        {
            (TpmAlgIdConstants.TPM_ALG_RSA, TpmAlgIdConstants.TPM_ALG_RSASSA or TpmAlgIdConstants.TPM_ALG_RSAPSS) =>
                new TpmRsaGetTimeAction(signer.Name, signer.Hierarchy, request.QualifyingData, signer.PrivateKey, request.SignatureScheme, request.SchemeHashAlg, state.Time, clockSnapshot, responseSessions),
            (TpmAlgIdConstants.TPM_ALG_ECC, TpmAlgIdConstants.TPM_ALG_ECDSA) =>
                new TpmGetTimeAction(signer.Name, signer.Hierarchy, request.QualifyingData, signer.PrivateKey, signer.Curve, request.SignatureScheme, request.SchemeHashAlg, state.Time, clockSnapshot, responseSessions),
            _ => null
        };

        if(action is null)
        {
            request.Dispose();

            return Reject(state, TpmCcConstants.TPM_CC_GetTime, TpmRcConstants.TPM_RC_SCHEME);
        }

        //The continuation is every supplied HMAC's and the parameter area's terminal owner — their verification
        //was their only use — while each slot's caller nonce has transferred into that slot's response-session
        //entry and the qualifying data into the action, all of which the effect releases.
        request.SuppliedPrivacyAdminHmac.Dispose();
        request.SuppliedSignHmac.Dispose();
        request.SuppliedCompanionHmac.Dispose();
        request.RawParameterArea.Dispose();

        return Transition(
            state with
            {
                NextAction = action,
                ResponseIntent = null
            },
            "GetTime:OverSession:AttestRequested");
    }

    /// <summary>
    /// Returns the current <c>TPMS_TIME_INFO</c> straight from state for <c>TPM2_ReadClock()</c>: no handles,
    /// no authorization, and no signature (Part 3, clause 29.1) — structurally identical to <c>OnPcrRead</c>,
    /// the other command answerable purely from already-resident state.
    /// </summary>
    /// <param name="state">The state to derive the response from.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnReadClock(TpmSimulatorState state) =>
        Transition(
            state with
            {
                ResponseIntent = new TpmReadClockResponse(
                    TpmRcConstants.TPM_RC_SUCCESS,
                    new TpmsTimeInfo(state.Time, new TpmsClockInfo(state.Clock, state.ResetCount, state.RestartCount, state.ClockSafe)))
            },
            "ReadClock");

    /// <summary>
    /// Advances Clock forward for <c>TPM2_ClockSet()</c>, authorized by the owner hierarchy (Part 3, clause
    /// 29.2).
    /// </summary>
    /// <remarks>
    /// The Platform-hierarchy arm (<c>TPM_RH_PLATFORM</c> plus physical presence) is not modelled this slice, so
    /// a non-owner handle is <c>TPM_RC_HANDLE</c>, mirroring <c>OnNvDefineSpace</c>'s fixed-provisioning-handle
    /// precedent. Owner authorization is not dictionary-attack protected (clause 17.8.1), so a wrong owner
    /// authValue is a plain bad-authorization, compared constant-time so a mismatch leaks no timing about the
    /// secret. newTime older than the current (already per-command-advanced) Clock, or past the clause 36.3
    /// ceiling of <c>FF FF 00 00 00 00 00 00(16)</c>, is <c>TPM_RC_VALUE</c> with Clock left unchanged. A
    /// successful set marks ClockSafe YES: an explicitly caller-set Clock is, by construction, a value never
    /// previously reported.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_ClockSet()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnClockSet(TpmSimulatorState state, TpmClockSetRequested request)
    {
        if(request.AuthHandle.Value != (uint)TpmRh.TPM_RH_OWNER)
        {
            return Reject(state, TpmCcConstants.TPM_CC_ClockSet, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        if(!CryptographicOperations.FixedTimeEquals(StripTrailingZeros(request.OwnerAuthSupplied.AsReadOnlySpan()), StripTrailingZeros(state.OwnerAuth.AsReadOnlySpan())))
        {
            return Reject(state, TpmCcConstants.TPM_CC_ClockSet, TpmRcConstants.TPM_RC_BAD_AUTH, request);
        }

        //The compare above was this credential's only use, so this transition is its terminal owner; every arm
        //that refuses before this point releases it through the request's own Dispose.
        request.OwnerAuthSupplied.Dispose();

        if(request.NewTime < state.Clock || request.NewTime > MaxClockValue)
        {
            return Reject(state, TpmCcConstants.TPM_CC_ClockSet, TpmRcConstants.TPM_RC_VALUE);
        }

        return Transition(
            state with
            {
                Clock = request.NewTime,
                ClockSafe = TpmiYesNo.Yes,
                ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
            },
            "ClockSet");
    }

    /// <summary>
    /// Resets <c>FailedTries</c> to zero for <c>TPM2_DictionaryAttackLockReset()</c>, authorized by the lockout
    /// hierarchy (Part 3, clause 25.2).
    /// </summary>
    /// <remarks>
    /// Deliberately does NOT check <c>state.IsInLockout</c> (general Lockout mode): this command is the escape
    /// hatch out of it, so it is permitted regardless of FailedTries/MaxTries — the only gate is
    /// <c>LockoutAuthEnabled</c>, the wholly independent state a wrong lockoutAuth use disables (clause 17.8.5).
    /// A wrong lockoutAuth value here disables <c>LockoutAuthEnabled</c> and anchors its own self-heal timer
    /// exactly like the NV auth-failure sites do for <c>FailedTries</c>, but returns <c>TPM_RC_AUTH_FAIL</c>
    /// rather than <c>TPM_RC_BAD_AUTH</c>: lockoutAuth is itself dictionary-attack protected (clause 17.8's own
    /// carve-out — every other permanent handle is DA-exempt, lockoutAuth is the one that is not). A successful
    /// reset never touches <c>LockoutAuthEnabled</c>: it is already true on this path (the gate above already
    /// refused a disabled one), so there is nothing to re-arm.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_DictionaryAttackLockReset()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnDictionaryAttackLockReset(TpmSimulatorState state, TpmDictionaryAttackLockResetRequested request)
    {
        if(request.LockHandle.Value != (uint)TpmRh.TPM_RH_LOCKOUT)
        {
            return Reject(state, TpmCcConstants.TPM_CC_DictionaryAttackLockReset, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        if(!state.LockoutAuthEnabled)
        {
            return Reject(state, TpmCcConstants.TPM_CC_DictionaryAttackLockReset, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        if(!CryptographicOperations.FixedTimeEquals(StripTrailingZeros(request.LockoutAuthSupplied.AsReadOnlySpan()), StripTrailingZeros(state.LockoutAuth.AsReadOnlySpan())))
        {
            TpmSimulatorState disabled = state with { LockoutAuthEnabled = false, LastLockoutAuthFailureTime = state.Time };

            return Reject(disabled, TpmCcConstants.TPM_CC_DictionaryAttackLockReset, TpmRcConstants.TPM_RC_AUTH_FAIL, request);
        }

        //The compare above was this credential's only use, so this transition is its terminal owner; every arm
        //that refuses before this point releases it through the request's own Dispose.
        request.LockoutAuthSupplied.Dispose();

        return Transition(
            state with
            {
                FailedTries = 0u,
                ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
            },
            "DictionaryAttackLockReset");
    }

    /// <summary>
    /// Sets MaxTries/RecoveryTime/LockoutRecovery for <c>TPM2_DictionaryAttackParameters()</c>, authorized by
    /// the lockout hierarchy exactly like <c>TPM2_DictionaryAttackLockReset()</c> above — same handle check,
    /// same <c>LockoutAuthEnabled</c> gate ahead of <c>state.IsInLockout</c>, same lockoutAuth compare and
    /// disable-on-mismatch (Part 3, clause 25.3).
    /// </summary>
    /// <remarks>
    /// Deliberately does NOT reset <c>FailedTries</c> (Part 1, clause 17.8.6's errata correction to an earlier
    /// design): lowering newMaxTries to at or below the current <c>FailedTries</c> takes the TPM into Lockout
    /// mode immediately — <c>IsInLockout</c>'s own "FailedTries >= MaxTries" formula already reflects it on the
    /// very next read, with no distinct error code for that transition.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_DictionaryAttackParameters()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnDictionaryAttackParameters(TpmSimulatorState state, TpmDictionaryAttackParametersRequested request)
    {
        if(request.LockHandle.Value != (uint)TpmRh.TPM_RH_LOCKOUT)
        {
            return Reject(state, TpmCcConstants.TPM_CC_DictionaryAttackParameters, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        if(!state.LockoutAuthEnabled)
        {
            return Reject(state, TpmCcConstants.TPM_CC_DictionaryAttackParameters, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        if(!CryptographicOperations.FixedTimeEquals(StripTrailingZeros(request.LockoutAuthSupplied.AsReadOnlySpan()), StripTrailingZeros(state.LockoutAuth.AsReadOnlySpan())))
        {
            TpmSimulatorState disabled = state with { LockoutAuthEnabled = false, LastLockoutAuthFailureTime = state.Time };

            return Reject(disabled, TpmCcConstants.TPM_CC_DictionaryAttackParameters, TpmRcConstants.TPM_RC_AUTH_FAIL, request);
        }

        //The compare above was this credential's only use, so this transition is its terminal owner; every arm
        //that refuses before this point releases it through the request's own Dispose.
        request.LockoutAuthSupplied.Dispose();

        return Transition(
            state with
            {
                MaxTries = request.NewMaxTries,
                RecoveryTime = request.NewRecoveryTime,
                LockoutRecovery = request.NewLockoutRecovery,
                ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
            },
            "DictionaryAttackParameters");
    }

    /// <summary>
    /// Verifies a caller-supplied authorization value against the one <paramref name="authHandle"/> names, for
    /// the password arm of the hierarchy and provisioning commands — the single place their shared authorization
    /// ladder lives (TPM 2.0 Library Part 1, clause 11.2; clause 17.8).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The enable gate comes first because it is not an authorization outcome but an availability one: "When an
    /// enable is FALSE, the corresponding authValue and authPolicy cannot be used to authorize any TPM action"
    /// (clause 11.2, Table 5), so the handle resolves to no usable entity at all and the answer is
    /// <c>TPM_RC_HIERARCHY</c> — the code Part 3, clause 24.3.1 states for exactly this condition and the one
    /// every other command in this family inherits by the same rule. This is also what makes CLEARing
    /// <c>phEnable</c> one-way: only platformAuth may SET it (clause 24.2.1), and platformAuth is unusable while
    /// it is CLEAR, so nothing short of a TPM Reset restores it.
    /// </para>
    /// <para>
    /// The lockout entity is the one permanent handle inside dictionary-attack protection (Part 1, clause 17.8.1),
    /// so it carries two gates the other three do not: Lockout mode itself (clause 17.8.3, "While in Lockout mode,
    /// any use of a DA-protected authValue will return TPM_RC_LOCKOUT" — <c>TPM2_DictionaryAttackLockReset()</c>
    /// is the sole carve-out, clause 25.2, and is not one of these commands) and the one-strike state a failed
    /// lockoutAuth use enters regardless of the counters (clause 17.8.5). Its mismatch is therefore
    /// <c>TPM_RC_AUTH_FAIL</c> and disables further lockoutAuth use, where the other three answer the plain
    /// <c>TPM_RC_BAD_AUTH</c> of a dictionary-attack-exempt entity and move no counter at all. Platform
    /// authorization is categorically exempt (Part 3, clause 25.1), which is what keeps it the recovery path when
    /// every other hierarchy is locked.
    /// </para>
    /// </remarks>
    /// <param name="state">The state the authorization is evaluated against.</param>
    /// <param name="authHandle">The hierarchy handle presented as the authorization, already checked against the command's own admissible set.</param>
    /// <param name="suppliedAuth">The authorization value supplied in the password session.</param>
    /// <returns>
    /// The refusal and the state to reject from (a failed lockoutAuth use carries its one-strike update), or
    /// <see langword="null"/> with the state unchanged when the authorization holds.
    /// </returns>
    private static (TpmRcConstants? ResponseCode, TpmSimulatorState State) VerifyHierarchyAuthorization(
        TpmSimulatorState state, uint authHandle, ReadOnlyMemory<byte> suppliedAuth)
    {
        if(!state.IsHierarchyEnabled(authHandle))
        {
            return (TpmRcConstants.TPM_RC_HIERARCHY, state);
        }

        //A handle with no authValue slot cannot be authorized by one; the fail-closed answer keeps a caller from
        //ever comparing a supplied secret against the structurally empty fallback.
        if(!state.TryGetHierarchyAuthValue(authHandle, out Tpm2bAuth authValue))
        {
            return (TpmRcConstants.TPM_RC_VALUE, state);
        }

        if(authHandle == (uint)TpmRh.TPM_RH_LOCKOUT)
        {
            if(!state.LockoutAuthEnabled || state.IsInLockout)
            {
                return (TpmRcConstants.TPM_RC_LOCKOUT, state);
            }

            if(!CryptographicOperations.FixedTimeEquals(StripTrailingZeros(suppliedAuth.Span), StripTrailingZeros(authValue.AsReadOnlySpan())))
            {
                TpmSimulatorState disabled = state with { LockoutAuthEnabled = false, LastLockoutAuthFailureTime = state.Time };

                return (TpmRcConstants.TPM_RC_AUTH_FAIL, disabled);
            }

            return (null, state);
        }

        //The comparison is constant-time so a mismatch leaks no timing about the secret, exactly as every other
        //authValue compare in this model is, and both operands enter with trailing zero octets removed (TPM 2.0
        //Library Part 1, clause 17.6.4.3) — the carrier holds whatever form the installing command received, so
        //a caller supplying the zero-padded shape of the same secret must still authorize.
        if(!CryptographicOperations.FixedTimeEquals(StripTrailingZeros(suppliedAuth.Span), StripTrailingZeros(authValue.AsReadOnlySpan())))
        {
            return (TpmRcConstants.TPM_RC_BAD_AUTH, state);
        }

        return (null, state);
    }

    /// <summary>
    /// Runs the authorization-area processing the session arms of the hierarchy and provisioning commands share
    /// and builds the authorizing session's pending command-HMAC verification (TPM 2.0 Library Part 3, clause
    /// 5.5 and clause 5.6, checks 3 and 9) — the session-arm counterpart of
    /// <see cref="VerifyHierarchyAuthorization"/>, carrying the same enable and Lockout-mode gates because they
    /// precede the HMAC rather than depending on it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A permanent handle's Name is its own 4-octet handle value (Part 1, clause 14, Table 6), so the authValue term of
    /// the HMAC key drops out exactly when the session is bound to the hierarchy it now authorizes (equation 22's
    /// omission, Part 1, clause 17.6.10): binding already folded that secret into the session key through the KDFa.
    /// Otherwise the term is the hierarchy's live carrier, borrowed; the HMAC primitive takes its
    /// trailing-zero-stripped view, the same fold every authorization computation in this model applies
    /// (clause 17.6.4.3).
    /// </para>
    /// <para>
    /// The pending record is marked dictionary-attack protected for the lockout entity, and marked as the
    /// lockout entity besides, so a command-HMAC mismatch takes the one-strike branch of
    /// <see cref="RejectSessionAuthFailure"/> — the identical discipline the password arm applies — instead of
    /// feeding the ordinary failure counter that the three dictionary-attack-exempt hierarchies never touch.
    /// </para>
    /// <para>
    /// Both marks are also raised by the SESSION's own bind, independently of which hierarchy it authorizes:
    /// Part 1, clause 17.8.7 makes the charge an OR over the authorized entity and the bind entity, and Part 3,
    /// clause 11.1.1 states that a DA-protected bind subjects use of the session to DA "regardless of the DA
    /// status of the entity being authorized". A session bound to lockoutAuth therefore carries the one-strike
    /// discipline into a command authorized by an exempt hierarchy, because the failed HMAC is evidence against
    /// lockoutAuth itself.
    /// </para>
    /// </remarks>
    /// <param name="state">The state the authorization is evaluated against.</param>
    /// <param name="authHandle">The hierarchy handle presented as the authorization, already checked against the command's own admissible set.</param>
    /// <param name="session">The resolved authorizing HMAC session.</param>
    /// <param name="sessionAttributes">The authorizing session's command session-attributes octet.</param>
    /// <param name="nonceCaller">The authorizing session's caller nonce for this command (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.13.2, Table 153) — a borrowed reference to the carrier the request owns; this frame reads it into the pending verification and never disposes it, the accepted continuation transferring it into that slot's response entry instead.</param>
    /// <param name="hmac">The supplied command <c>hmac</c> field for the authorizing session (<c>TPM2B_AUTH</c>, Table 153) — a borrowed reference to the carrier the request owns; this frame reads it into the pending verification as the value to compare against and never disposes it, the accepted continuation being its terminal owner.</param>
    /// <param name="hasDecryptSession">Whether a second, decrypt-attributed session accompanies the command.</param>
    /// <param name="decryptSessionAttributes">The decrypt session's command session-attributes octet, meaningful only when <paramref name="hasDecryptSession"/> is set.</param>
    /// <param name="decryptSessionHandle">The decrypt slot's session handle, for the once-only handle rule of TPM 2.0 Library Part 1, clause 16.6.3 and the password-slot rules of clause 16.6.4, Table 12; zero when no such slot accompanies the command.</param>
    /// <param name="decryptNonceCaller">The decrypt slot's caller nonce as it arrived on the wire (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.13.2, Table 153), whose length answers the password-slot nonce rule — a borrowed reference to the carrier the request owns; only the length is read here and nothing is disposed, the accepted continuation transferring the carrier into that slot's response entry. The shared empty carrier when no such slot accompanies the command.</param>
    /// <param name="decryptSymmetric">The decrypt session's negotiated symmetric definition, meaningful only when <paramref name="hasDecryptSession"/> is set.</param>
    /// <param name="decryptNonceTpm">The decrypt session's stored nonceTPM (<c>TPM2B_NONCE</c>, TPM 2.0 Library Part 2, clause 10.4.4, Table 94), folded into the authorizing session's HMAC as the nonce of the session at index 1 (Part 1, clause 17.6.3.4); a borrowed reference to the carrier that session record owns.</param>
    /// <param name="firstCommandParameterIsEncryptable">Whether the command's first sized command parameter may be decrypt-protected.</param>
    /// <param name="refusal">The response code to reject with when this returns <see langword="null"/>.</param>
    /// <param name="bindOmitsAuthValue">
    /// Whether the bind-omission applied to this command's HMAC key — the fact TPM 2.0 Library Part 1, clause
    /// 17.6.10 requires be RECORDED for the response ("The TPM will record the fact that the authValue was not
    /// used in the HMAC computation of the authorization and not include it in the HMAC computation on the
    /// response"): the two commands in this family that rotate the very authValue mid-command
    /// (<c>TPM2_HierarchyChangeAuth()</c>, <c>TPM2_Clear()</c>) thread it to their response framing, where a
    /// post-effect recomputation would wrongly flip the decision. Meaningless when this returns <see langword="null"/>.
    /// </param>
    /// <returns>The authorizing session's pending verification, or <see langword="null"/> when the authorization area is refused.</returns>
    private static TpmPendingSessionVerification? BeginHierarchyAuthorization(
        TpmSimulatorState state,
        uint authHandle,
        HmacSessionState session,
        TpmaSession sessionAttributes,
        Tpm2bNonce nonceCaller,
        Tpm2bAuth hmac,
        bool hasDecryptSession,
        TpmaSession decryptSessionAttributes,
        TpmiShAuthSession decryptSessionHandle,
        Tpm2bNonce decryptNonceCaller,
        TpmtSymDef decryptSymmetric,
        Tpm2bNonce decryptNonceTpm,
        bool firstCommandParameterIsEncryptable,
        out TpmRcConstants refusal,
        out bool bindOmitsAuthValue)
    {
        refusal = TpmRcConstants.TPM_RC_SUCCESS;
        bindOmitsAuthValue = false;

        TpmRcConstants? sessionAreaError = ValidateSessionArea(
            sessionAttributes, firstAuthorizesEntity: true, session.Symmetric,
            hasDecryptSession, decryptSessionAttributes, decryptSymmetric,
            firstCommandParameterIsEncryptable, firstResponseParameterIsEncryptable: false,
            auditIsSupported: false,
            firstSessionHandle: TpmiShAuthSession.FromValue(session.Handle.Value), secondSessionHandle: decryptSessionHandle,
            firstNonceLength: nonceCaller.Size, secondNonceLength: decryptNonceCaller.Size);
        if(sessionAreaError is TpmRcConstants sessionAreaRc)
        {
            refusal = sessionAreaRc;

            return null;
        }

        if(!state.IsHierarchyEnabled(authHandle))
        {
            refusal = TpmRcConstants.TPM_RC_HIERARCHY;

            return null;
        }

        if(!state.TryGetHierarchyAuthValue(authHandle, out Tpm2bAuth authValue))
        {
            refusal = TpmRcConstants.TPM_RC_VALUE;

            return null;
        }

        bool isLockoutEntity = authHandle == (uint)TpmRh.TPM_RH_LOCKOUT;
        if(isLockoutEntity && (!state.LockoutAuthEnabled || state.IsInLockout))
        {
            refusal = TpmRcConstants.TPM_RC_LOCKOUT;

            return null;
        }

        //The same refusal from the session's bind side, which the entity-side gate above cannot see: three of the
        //four hierarchies are dictionary-attack exempt, but a session BOUND to a protected entity is subject to DA
        //whatever it now authorizes (Part 3, clause 11.1.1; Part 1, clause 17.8.3).
        if(IsBoundSessionLockedOut(state, session))
        {
            refusal = TpmRcConstants.TPM_RC_LOCKOUT;

            return null;
        }

        //The bound-entity value is recomputed from the hierarchy's LIVE authValue (Part 4, IsSessionBindEntity),
        //so a rotated hierarchy secret ends the binding; the decision is recorded through bindOmitsAuthValue for
        //the rotating commands' response framing (clause 17.6.10's record-and-mirror rule).
        bool bindOmits = MatchesHandleFormBoundEntity(session.BoundEntity, authHandle, StripTrailingZeros(authValue.AsReadOnlySpan()));
        bindOmitsAuthValue = bindOmits;
        Tpm2bAuth authValueForHmac = bindOmits
            ? Tpm2bAuth.Empty
            : authValue;

        //Clause 17.8.7's OR on both axes: the authorized hierarchy's own protection (lockoutAuth alone among them)
        //and the session's bind-side state. A session whose key folded lockoutAuth takes the one-strike branch of
        //RejectSessionAuthFailure even when the hierarchy it authorizes is one of the exempt three, because the
        //failed HMAC is evidence against lockoutAuth itself (clause 17.8.5).
        return new TpmPendingSessionVerification(
            SessionHandle: TpmiShAuthSession.FromValue(session.Handle.Value), SessionIndex: 0, SessionAlg: session.SessionAlg, SessionKey: session.SessionKey,
            AuthValue: authValueForHmac, IsDaProtected: isLockoutEntity || session.IsBoundEntityDaProtected,
            NonceCaller: nonceCaller, NonceTpm: session.NonceTpm,
            FoldedNonceDecrypt: hasDecryptSession ? decryptNonceTpm : Tpm2bNonce.Empty,
            FoldedNonceEncrypt: Tpm2bNonce.Empty,
            SessionAttributes: sessionAttributes, SuppliedHmac: hmac, IsLockoutEntity: isLockoutEntity || session.IsBoundToLockout);
    }

    /// <summary>
    /// Resolves the authValue term a hierarchy-authorized command's RESPONSE HMAC is keyed on, reading the
    /// hierarchy's authValue from the state as it stands AFTER the command's effect (TPM 2.0 Library Part 1,
    /// clause 17.6.5 keys the HMAC of a command or a response alike on sessionKey concatenated to authValue, which
    /// stays the same key only for commands that change no authValue).
    /// </summary>
    /// <remarks>
    /// Two commands in this family deliberately break that default and are the reason this reads post-effect
    /// state rather than reusing the threaded command-HMAC term: <c>TPM2_HierarchyChangeAuth()</c> ("The HMAC in
    /// the response shall use the new authorization value when computing the response HMAC", Part 3, clause
    /// 24.8.1) and <c>TPM2_Clear()</c> ("If this command is authorized using lockoutAuth, the HMAC in the
    /// response shall use the new lockoutAuth value (that is, the Empty Buffer)", clause 24.6.1). A host that
    /// keyed the response check on the old value would reject a correct response, which is precisely the trap
    /// both sentences exist to close. The bind-omission half of the decision is the opposite: it is the
    /// COMMAND-TIME fact, threaded here rather than re-derived, per clause 17.6.10's own rule ("The TPM will
    /// record the fact that the authValue was not used in the HMAC computation of the authorization and not
    /// include it in the HMAC computation on the response") — recomputing the bound-entity value against the
    /// just-rotated authValue would wrongly flip the decision for the very command the binding authorized.
    /// </remarks>
    /// <param name="state">The state as it stands after the command's effect has been applied.</param>
    /// <param name="authHandle">The hierarchy whose authValue keyed the authorization.</param>
    /// <param name="bindOmitsAuthValue">The command-time bind-omission decision, recorded by <see cref="BeginHierarchyAuthorization"/> and threaded through the request.</param>
    /// <returns>The authValue term for the response HMAC key — a borrowed reference to the post-effect carrier; the HMAC primitive takes its trailing-zero-stripped view.</returns>
    private static Tpm2bAuth ResolveHierarchyResponseAuthValue(TpmSimulatorState state, uint authHandle, bool bindOmitsAuthValue)
    {
        if(bindOmitsAuthValue)
        {
            return Tpm2bAuth.Empty;
        }

        _ = state.TryGetHierarchyAuthValue(authHandle, out Tpm2bAuth authValue);

        return authValue;
    }

    /// <summary>
    /// Declares the response-framing action for a hierarchy-authorized command whose authorization area carries
    /// exactly one session and whose response carries no parameters (TPM 2.0 Library Part 1, clause 16.6.1) — the
    /// shape <c>TPM2_Clear()</c>, <c>TPM2_ClearControl()</c>, <c>TPM2_HierarchyControl()</c>, and
    /// <c>TPM2_SetPrimaryPolicy()</c> all share.
    /// </summary>
    /// <param name="state">The state the effect has already been applied to.</param>
    /// <param name="commandCode">The command code, folded into rpHash.</param>
    /// <param name="authorizingSessionHandle">The authorizing session, guaranteed resolvable (its command HMAC just verified).</param>
    /// <param name="responseAuthValue">The authValue term for the response HMAC key, resolved from post-effect state — a borrowed carrier reference, <see langword="null"/> (read as empty) when the request never resolved one.</param>
    /// <param name="nonceCaller">The authorizing session's command caller nonce (the response HMAC's nonceOlder), TRANSFERRED out of the request record into the framing action, whose effect is its terminal owner.</param>
    /// <param name="sessionAttributes">The authorizing session's command session-attributes octet, echoed into its response entry.</param>
    /// <param name="label">The transition label.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the response-framing action.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> FrameHierarchySessionResponse(
        TpmSimulatorState state, TpmCcConstants commandCode, uint authorizingSessionHandle,
        Tpm2bAuth? responseAuthValue, Tpm2bNonce nonceCaller, TpmaSession sessionAttributes, string label)
    {
        HmacSessionState session = state.HmacSessions[TpmiShHmac.FromValue(authorizingSessionHandle)];

        return Transition(
            state with
            {
                NextAction = new TpmFrameNvSessionResponseAction(
                    commandCode, TpmiShAuthSession.FromValue(session.Handle.Value), session.SessionAlg, session.SessionKey, responseAuthValue ?? Tpm2bAuth.Empty,
                    nonceCaller, sessionAttributes, ReadWindow: null),
                ResponseIntent = null
            },
            label);
    }

    /// <summary>
    /// Authorizes the password arm of <c>TPM2_Clear()</c> and declares the storage-primary-seed draw its effect
    /// list opens with (TPM 2.0 Library Part 3, clause 24.6).
    /// </summary>
    /// <remarks>
    /// The order is the specification's own: the handle set (<c>TPMI_RH_CLEAR</c>) and the authorization resolve
    /// first, and only an authorized caller ever reaches the <c>TPMA_PERMANENT.disableClear</c> gate — "If
    /// TPM2_ClearControl() has disabled this command, the TPM shall return TPM_RC_DISABLED" (clause 24.6.1). A
    /// caller who cannot authorize the command learns nothing about whether clearing is currently permitted, and
    /// a refused clear never draws from the random stream.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_Clear()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the seed draw, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnClear(TpmSimulatorState state, TpmClearRequested request)
    {
        //TPMI_RH_CLEAR admits only the lockout entity and the platform hierarchy; an out-of-range value is the
        //interface type's own unmarshal failure (Part 2, clause 9.24), which this model answers at the transition
        //because the parser reads the handle area generically.
        if(!TpmSimulatorState.IsClearAuthHandle(request.AuthHandle.Value))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Clear, TpmRcConstants.TPM_RC_VALUE, request);
        }

        (TpmRcConstants? authError, TpmSimulatorState authorized) = VerifyHierarchyAuthorization(state, request.AuthHandle.Value, request.AuthSupplied.AsReadOnlyMemory());
        if(authError is TpmRcConstants authRc)
        {
            return Reject(authorized, TpmCcConstants.TPM_CC_Clear, authRc, request);
        }

        if(authorized.DisableClear)
        {
            return Reject(authorized, TpmCcConstants.TPM_CC_Clear, TpmRcConstants.TPM_RC_DISABLED, request);
        }

        //The compare above was this credential's only use, so this transition is its terminal owner;
        //every arm that refuses before this point releases it through the request's own Dispose.
        request.AuthSupplied.Dispose();

        return Transition(
            authorized with
            {
                NextAction = new TpmGenerateStorageProofSeedAction(TpmSimulatorState.ContextIntegrityDigestSize, request),
                ResponseIntent = null
            },
            "Clear:StorageProofSeedRequested");
    }

    /// <summary>
    /// Authorizes <c>TPM2_Clear()</c> over an HMAC session, declaring the command-HMAC verification (TPM 2.0
    /// Library Part 3, clause 24.6; clause 5.6, check 9).
    /// </summary>
    /// <remarks>
    /// The command takes no parameters at all, so nothing is encryptable in either direction and cpHash's Name
    /// area is the authorizing hierarchy's own 4-octet handle alone (Part 1, clause 16.7 equation 15). The
    /// <c>disableClear</c> gate is deliberately NOT checked here but in the continuation: on a real TPM the
    /// session processing of clause 5.6 completes before the command body's own input validation runs, so a
    /// caller with a wrong session HMAC gets the authorization failure whether or not clearing is permitted.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_Clear()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the HMAC verification, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnClearOverSession(TpmSimulatorState state, TpmClearOverSessionRequested request)
    {
        if(!TpmSimulatorState.IsClearAuthHandle(request.AuthHandle.Value))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Clear, TpmRcConstants.TPM_RC_VALUE, request);
        }

        //Only an HMAC session can authorize these commands in this model: a policy-session authorizer would need
        //the hierarchy authPolicy gate that TPM2_PolicySecret()'s own arm already carries, and the wire shape of
        //a TPMS_AUTH_COMMAND does not distinguish the kinds, so an unresolvable handle is the generic
        //session-not-loaded warning (Part 2, clause 6.6.2) exactly as the NV owner arms answer it.
        if(!state.HmacSessions.TryGetValue(TpmiShHmac.FromValue(request.AuthorizingSessionHandle.Value), out HmacSessionState? session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Clear, SessionReferenceMissRc(sessionIndex: 0), request);
        }

        TpmPendingSessionVerification? pending = BeginHierarchyAuthorization(
            state, request.AuthHandle.Value, session, request.SessionAttributes, request.NonceCaller, request.Hmac,
            hasDecryptSession: false, decryptSessionAttributes: default, decryptSessionHandle: default, Tpm2bNonce.Empty,
            TpmtSymDef.Null, Tpm2bNonce.Empty,
            firstCommandParameterIsEncryptable: false, out TpmRcConstants refusal, out bool bindOmitsAuthValue);
        if(pending is null)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Clear, refusal, request);
        }

        return Transition(
            state with
            {
                NextAction = new TpmVerifyCommandHmacAction(
                    TpmCcConstants.TPM_CC_Clear, TpmCommandHandleNames.Of(TpmHandleName.FromHandle(request.AuthHandle.Value)), request.RawParameterArea, pending,
                    ImmutableArray<TpmPendingSessionVerification>.Empty,
                    request with { ResolvedAuthValue = pending.AuthValue, BindOmitsAuthValue = bindOmitsAuthValue }),
                ResponseIntent = null
            },
            "Clear:OverSession:HmacVerifyRequested");
    }

    /// <summary>
    /// Resumes <c>TPM2_Clear()</c> over an HMAC session once its command HMAC has verified: applies the
    /// <c>disableClear</c> gate and declares the storage-primary-seed draw (TPM 2.0 Library Part 3, clause 24.6.1).
    /// </summary>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_Clear()</c> request, its session now verified.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the seed draw, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> ContinueClearOverSession(TpmSimulatorState state, TpmClearOverSessionRequested request)
    {
        if(state.DisableClear)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Clear, TpmRcConstants.TPM_RC_DISABLED, request);
        }

        //The verification queue is done with the slot credential this continuation owns, so it is its
        //terminal owner; the caller nonce is NOT released here, transferring instead into the response
        //framing the seed draw leads to.
        request.Hmac.Dispose();

        return Transition(
            state with
            {
                NextAction = new TpmGenerateStorageProofSeedAction(TpmSimulatorState.ContextIntegrityDigestSize, request),
                ResponseIntent = null
            },
            "Clear:OverSession:StorageProofSeedRequested");
    }

    /// <summary>
    /// Applies every effect <c>TPM2_Clear()</c> owes once its replacement storage primary seed has been drawn
    /// (<see cref="TpmGenerateStorageProofSeedAction"/>'s continuation), then frames the response the arm that
    /// requested it calls for.
    /// </summary>
    /// <param name="state">The state to transition from, with authorization already established.</param>
    /// <param name="generated">The effect's result carrying the fresh seed and the request to resume.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnStorageProofSeedGenerated(TpmSimulatorState state, TpmStorageProofSeedGenerated generated)
    {
        TpmSimulatorState cleared = ApplyClear(state, generated.StorageProofSeed);

        return generated.Resume switch
        {
            TpmClearOverSessionRequested overSession => FrameHierarchySessionResponse(
                cleared, TpmCcConstants.TPM_CC_Clear, overSession.AuthorizingSessionHandle.Value,
                //The lockoutAuth this response is keyed on is the one the clear just installed — the Empty
                //Buffer (Part 3, clause 24.6.1's closing sentence), read back from the post-clear state — while
                //the bind-omission half mirrors the recorded command-time decision (clause 17.6.10).
                ResolveHierarchyResponseAuthValue(cleared, overSession.AuthHandle.Value, overSession.BindOmitsAuthValue),
                overSession.NonceCaller, overSession.SessionAttributes, "Clear:OverSession:ResponseRequested"),

            TpmClearRequested => Transition(
                cleared with
                {
                    NextAction = NullAction.Instance,
                    ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
                },
                "Clear:Completed"),

            _ => throw new System.InvalidOperationException($"No storage-proof-seed continuation is defined for '{generated.Resume.GetType().Name}'.")
        };
    }

    /// <summary>
    /// Applies <c>TPM2_Clear()</c>'s effect list (TPM 2.0 Library Part 3, clause 24.6.1) in one step: the owner
    /// change itself.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every item of the clause's own list is applied here — resident storage- and endorsement-hierarchy objects
    /// flushed, every NV Index with <c>TPMA_NV_PLATFORMCREATE</c> CLEAR deleted, the storage primary seed
    /// replaced from the random-number generator (and with it <c>shProof</c> and <c>ehProof</c>, since both
    /// derive from it), <c>shEnable</c> and <c>ehEnable</c> SET, ownerAuth/endorsementAuth/lockoutAuth and their
    /// three policies returned to the Empty Buffer, Clock and resetCount and restartCount zeroed, Safe asserted,
    /// and pcrUpdateCounter incremented. Nothing else moves: the platform hierarchy, its authValue and policy,
    /// the platform proof seed, and <c>DisableClear</c> itself all survive, which is what leaves the platform the
    /// authority that can undo a clear's consequences.
    /// </para>
    /// <para>
    /// The proof rotation is the whole of how outstanding owner and endorsement tickets and saved contexts die
    /// (Part 1, clause 12.5): they are HMACs keyed by a proof derived from the seed, so a new seed stops them
    /// verifying with no revocation pass over any list. The <c>pcrUpdateCounter</c> increment invalidates
    /// something different and complementary — a policy session that asserted <c>TPM2_PolicyPCR()</c>, "even if
    /// the PCR selection is empty" (clause 24.6.1) — which is why both appear in the same list.
    /// </para>
    /// <para>
    /// Two deliberate divergences, both recorded rather than silently taken. First, the configured
    /// dictionary-attack parameters (<c>MaxTries</c>, <c>RecoveryTime</c>, <c>LockoutRecovery</c>) are RETAINED:
    /// clause 24.6.1's list and Part 1, clause 17.8.2 name only the failure counter ("TPM2_Clear() will reset
    /// this counter to zero"), so an administrator's chosen thresholds survive an owner change here where a TPM
    /// restoring manufacturer defaults would discard them. <c>LockoutAuthEnabled</c> is nonetheless re-asserted,
    /// because a TPM that arrived from a clear with a known-Empty lockoutAuth that it refuses to accept would be
    /// unable to administer its own dictionary-attack state. The two self-heal anchors are left where they are
    /// because a zeroed counter and an enabled lockoutAuth make both inert: each is re-anchored at the moment a
    /// future failure sets them moving again (clause 17.8.4/17.8.5). Second, loaded sealed data objects are left in
    /// place: <see cref="SealedObjectState"/> records no hierarchy, and the parent it was loaded under is not
    /// retained, so there is nothing to filter on — a modelling gap, not a reading of the clause, which would
    /// flush them with the rest of the storage hierarchy's residents.
    /// </para>
    /// </remarks>
    /// <param name="state">The state to clear, with authorization already established.</param>
    /// <param name="storageProofSeed">The freshly drawn replacement storage primary seed, in an owned carrier whose ownership transfers to the cleared state.</param>
    /// <returns>The cleared state.</returns>
    private static TpmSimulatorState ApplyClear(TpmSimulatorState state, StorageProofSeed storageProofSeed)
    {
        //Each evicted entry's owned carriers are released as the loop visits it — eviction is the
        //ownership-end boundary, and after TPM2_EvictControl()'s deep-copying persist arm no two entries
        //ever co-own a buffer, so the two object loops cannot double-dispose.
        ImmutableDictionary<TpmiDhObject, TransientKeyState> transientObjects = state.TransientObjects;
        foreach(KeyValuePair<TpmiDhObject, TransientKeyState> entry in state.TransientObjects)
        {
            if(IsClearedHierarchy(entry.Value.Hierarchy.Value))
            {
                entry.Value.Dispose();
                transientObjects = transientObjects.Remove(entry.Key);
            }
        }

        //A persistent object is evicted rather than merely disabled: the clause flushes "resident objects
        //(persistent and volatile) in the Storage and Endorsement hierarchies", and the seed rotation would in
        //any case leave a surviving entry unusable.
        ImmutableDictionary<TpmiDhPersistent, TransientKeyState> persistentObjects = state.PersistentObjects;
        foreach(KeyValuePair<TpmiDhPersistent, TransientKeyState> entry in state.PersistentObjects)
        {
            if(IsClearedHierarchy(entry.Value.Hierarchy.Value))
            {
                entry.Value.Dispose();
                persistentObjects = persistentObjects.Remove(entry.Key);
            }
        }

        //Each owner-created Index is deleted through the same retirement rule TPM2_NV_UndefineSpace() applies, so
        //the phantom counter high-water mark composes: a counter deleted by a clear raises the mark exactly as one
        //deleted by hand does, and a counter redefined under a new owner therefore still cannot restart below a
        //value its Name has already reported (Part 1, clause 37.2.6.3 NOTE 2/NOTE 6). The mark itself survives the
        //clear — it is not owner state but a monotonicity commitment the TPM has already made to the world.
        ImmutableDictionary<TpmiRhNvIndex, NvIndexState> nvIndexes = state.NvIndexes;
        ulong nvCounterHighWaterMark = state.NvCounterHighWaterMark;
        foreach(KeyValuePair<TpmiRhNvIndex, NvIndexState> entry in state.NvIndexes)
        {
            if(entry.Value.IsPlatformCreated)
            {
                continue;
            }

            nvCounterHighWaterMark = RetireNvCounterHighWaterMark(entry.Value, nvCounterHighWaterMark);
            entry.Value.Dispose();
            nvIndexes = nvIndexes.Remove(entry.Key);
        }

        //The three rotated hierarchy authorizations, the three policy digests cleared beside them, and the
        //superseded seed are released on their way to their replacements; the empty carriers installed below
        //are the dispose-immune singletons.
        state.OwnerAuth.Dispose();
        state.EndorsementAuth.Dispose();
        state.LockoutAuth.Dispose();
        state.OwnerAuthPolicy.Dispose();
        state.EndorsementAuthPolicy.Dispose();
        state.LockoutAuthPolicy.Dispose();
        state.StorageProofSeed.Dispose();

        return state with
        {
            TransientObjects = transientObjects,
            PersistentObjects = persistentObjects,
            NvIndexes = nvIndexes,
            NvCounterHighWaterMark = nvCounterHighWaterMark,
            StorageProofSeed = storageProofSeed,
            ShEnable = true,
            EhEnable = true,
            OwnerAuth = Tpm2bAuth.Empty,
            EndorsementAuth = Tpm2bAuth.Empty,
            LockoutAuth = Tpm2bAuth.Empty,
            OwnerAuthPolicy = Tpm2bDigest.Empty,
            OwnerAuthPolicyHashAlg = TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_NULL),
            EndorsementAuthPolicy = Tpm2bDigest.Empty,
            EndorsementAuthPolicyHashAlg = TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_NULL),
            LockoutAuthPolicy = Tpm2bDigest.Empty,
            LockoutAuthPolicyHashAlg = TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_NULL),
            FailedTries = 0u,
            LockoutAuthEnabled = true,
            Clock = 0ul,
            ResetCount = 0u,
            RestartCount = 0u,
            ClockSafe = TpmiYesNo.Yes,
            PcrUpdateCounter = state.PcrUpdateCounter + 1u
        };

        //The two hierarchies whose residents a clear flushes: the storage hierarchy whose primary seed is being
        //replaced, and the endorsement hierarchy whose ordinary objects are protected by a proof derived from
        //that same seed (Part 1, clause 12.5). Platform- and null-hierarchy objects are untouched.
        static bool IsClearedHierarchy(uint hierarchy) =>
            hierarchy is (uint)TpmRh.TPM_RH_OWNER or (uint)TpmRh.TPM_RH_ENDORSEMENT;
    }

    /// <summary>
    /// Retires a deleted NV Index's counter value into the phantom counter high-water mark (TPM 2.0 Library
    /// Part 1, clause 37.2.6.3 NOTE 2/NOTE 6) — the one rule every deletion path shares, so a counter can never
    /// be rolled back by deleting and redefining the handle that carried it.
    /// </summary>
    /// <remarks>
    /// Only a written Counter Index contributes, and only when its value exceeds the mark: the mark is a
    /// monotone ceiling over every counter value this TPM has ever reported under any Name, so it never falls.
    /// An Index of any other type, or an unwritten counter, has reported nothing and leaves it where it was.
    /// </remarks>
    /// <param name="index">The Index being deleted.</param>
    /// <param name="currentHighWaterMark">The mark as it stands before this deletion.</param>
    /// <returns>The mark after this deletion.</returns>
    private static ulong RetireNvCounterHighWaterMark(NvIndexState index, ulong currentHighWaterMark) =>
        index.IndexType == TpmNt.TPM_NT_COUNTER && index.IsWritten && index.CounterValue > currentHighWaterMark
            ? index.CounterValue
            : currentHighWaterMark;

    /// <summary>
    /// Sets or clears <c>TPMA_PERMANENT.disableClear</c> for the password arm of <c>TPM2_ClearControl()</c>
    /// (TPM 2.0 Library Part 3, clause 24.7).
    /// </summary>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_ClearControl()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnClearControl(TpmSimulatorState state, TpmClearControlRequested request)
    {
        if(!TpmSimulatorState.IsClearAuthHandle(request.AuthHandle.Value))
        {
            return Reject(state, TpmCcConstants.TPM_CC_ClearControl, TpmRcConstants.TPM_RC_VALUE, request);
        }

        (TpmRcConstants? authError, TpmSimulatorState authorized) = VerifyHierarchyAuthorization(state, request.AuthHandle.Value, request.AuthSupplied.AsReadOnlyMemory());
        if(authError is TpmRcConstants authRc)
        {
            return Reject(authorized, TpmCcConstants.TPM_CC_ClearControl, authRc, request);
        }

        if(ValidateClearControlDirection(request.AuthHandle.Value, request.Disable) is TpmRcConstants directionRc)
        {
            return Reject(authorized, TpmCcConstants.TPM_CC_ClearControl, directionRc, request);
        }

        //The compare above was this credential's only use, so this transition is its terminal owner;
        //every arm that refuses before this point releases it through the request's own Dispose.
        request.AuthSupplied.Dispose();

        return Transition(
            authorized with
            {
                DisableClear = request.Disable.IsYes,
                ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
            },
            "ClearControl");
    }

    /// <summary>
    /// Authorizes <c>TPM2_ClearControl()</c> over an HMAC session, declaring the command-HMAC verification
    /// (TPM 2.0 Library Part 3, clause 24.7).
    /// </summary>
    /// <remarks>
    /// <c>disable</c> is a single unsized octet, so it is not the sized first command parameter a decrypt session
    /// could protect (Part 1, clause 19.1), and the response carries no parameters — both directions of parameter
    /// encryption stay closed.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_ClearControl()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the HMAC verification, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnClearControlOverSession(TpmSimulatorState state, TpmClearControlOverSessionRequested request)
    {
        if(!TpmSimulatorState.IsClearAuthHandle(request.AuthHandle.Value))
        {
            return Reject(state, TpmCcConstants.TPM_CC_ClearControl, TpmRcConstants.TPM_RC_VALUE, request);
        }

        if(!state.HmacSessions.TryGetValue(TpmiShHmac.FromValue(request.AuthorizingSessionHandle.Value), out HmacSessionState? session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_ClearControl, SessionReferenceMissRc(sessionIndex: 0), request);
        }

        TpmPendingSessionVerification? pending = BeginHierarchyAuthorization(
            state, request.AuthHandle.Value, session, request.SessionAttributes, request.NonceCaller, request.Hmac,
            hasDecryptSession: false, decryptSessionAttributes: default, decryptSessionHandle: default, Tpm2bNonce.Empty,
            TpmtSymDef.Null, Tpm2bNonce.Empty,
            firstCommandParameterIsEncryptable: false, out TpmRcConstants refusal, out _);
        if(pending is null)
        {
            return Reject(state, TpmCcConstants.TPM_CC_ClearControl, refusal, request);
        }

        return Transition(
            state with
            {
                NextAction = new TpmVerifyCommandHmacAction(
                    TpmCcConstants.TPM_CC_ClearControl, TpmCommandHandleNames.Of(TpmHandleName.FromHandle(request.AuthHandle.Value)), request.RawParameterArea, pending,
                    ImmutableArray<TpmPendingSessionVerification>.Empty, request with { ResolvedAuthValue = pending.AuthValue }),
                ResponseIntent = null
            },
            "ClearControl:OverSession:HmacVerifyRequested");
    }

    /// <summary>
    /// Resumes <c>TPM2_ClearControl()</c> over an HMAC session once its command HMAC has verified: applies the
    /// direction rule and the attribute change, then declares the response framing (TPM 2.0 Library Part 3,
    /// clause 24.7.1).
    /// </summary>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_ClearControl()</c> request, its session now verified.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the response framing, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> ContinueClearControlOverSession(TpmSimulatorState state, TpmClearControlOverSessionRequested request)
    {
        if(ValidateClearControlDirection(request.AuthHandle.Value, request.Disable) is TpmRcConstants directionRc)
        {
            return Reject(state, TpmCcConstants.TPM_CC_ClearControl, directionRc, request);
        }

        //This continuation is the parse-rented parameter area's terminal owner: the command HMAC that read it
        //has verified, and nothing downstream reads it again.
        request.Hmac.Dispose();
        request.RawParameterArea.Dispose();

        TpmSimulatorState controlled = state with { DisableClear = request.Disable.IsYes };

        return FrameHierarchySessionResponse(
            controlled, TpmCcConstants.TPM_CC_ClearControl, request.AuthorizingSessionHandle.Value,
            request.ResolvedAuthValue, request.NonceCaller, request.SessionAttributes,
            "ClearControl:OverSession:ResponseRequested");
    }

    /// <summary>
    /// Enforces <c>TPM2_ClearControl()</c>'s one-way rule for lockout authorization: "Lockout Authorization may
    /// be used to SET disableClear but not to CLEAR it. Platform Authorization may be used to SET or CLEAR
    /// disableClear" (TPM 2.0 Library Part 3, clause 24.7.1).
    /// </summary>
    /// <remarks>
    /// The refusal is <c>TPM_RC_AUTH_FAIL</c>, and deliberately not the <c>TPM_RC_AUTH_TYPE</c> that its sibling
    /// <c>TPM2_HierarchyControl()</c> answers for a comparable wrong-authority combination: the clause names no
    /// response code at all for this case, and the code chosen here treats the authorization as simply not valid
    /// for the requested action. It is emphatically NOT the dictionary-attack-counting compare failure that the
    /// same code means when it comes out of an authValue comparison — no counter moves, no one-strike state is
    /// entered, and the lockout entity remains usable — because nothing about the caller's knowledge of
    /// lockoutAuth was in doubt. The asymmetry itself is a ratchet: lockout may tighten the control toward "no
    /// clear possible" but only the platform may loosen it, which is what stops a compromised lockoutAuth from
    /// re-enabling a clear the platform deliberately disabled.
    /// </remarks>
    /// <param name="authHandle">The authorizing handle.</param>
    /// <param name="disable">The requested direction.</param>
    /// <returns>The refusal, or <see langword="null"/> when the direction is permitted for that authority.</returns>
    private static TpmRcConstants? ValidateClearControlDirection(uint authHandle, TpmiYesNo disable) =>
        authHandle == (uint)TpmRh.TPM_RH_LOCKOUT && disable.IsNo
            ? TpmRcConstants.TPM_RC_AUTH_FAIL
            : null;

    /// <summary>
    /// Enables or disables a hierarchy for the password arm of <c>TPM2_HierarchyControl()</c> (TPM 2.0 Library
    /// Part 3, clause 24.2).
    /// </summary>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_HierarchyControl()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnHierarchyControl(TpmSimulatorState state, TpmHierarchyControlRequested request)
    {
        //TPMI_RH_BASE_HIERARCHY for the authorization, TPMI_RH_ENABLES for the bit being written: two different
        //interface types over the same handle constants, so both are checked, and an out-of-range value in either
        //is that type's own unmarshal failure.
        if(!TpmSimulatorState.IsBaseHierarchyHandle(request.AuthHandle.Value) || !TpmSimulatorState.IsEnablesHandle(request.Enable.Value))
        {
            return Reject(state, TpmCcConstants.TPM_CC_HierarchyControl, TpmRcConstants.TPM_RC_VALUE, request);
        }

        (TpmRcConstants? authError, TpmSimulatorState authorized) = VerifyHierarchyAuthorization(state, request.AuthHandle.Value, request.AuthSupplied.AsReadOnlyMemory());
        if(authError is TpmRcConstants authRc)
        {
            return Reject(authorized, TpmCcConstants.TPM_CC_HierarchyControl, authRc, request);
        }

        if(ValidateHierarchyControlAuthority(request.AuthHandle.Value, request.Enable.Value) is TpmRcConstants authorityRc)
        {
            return Reject(authorized, TpmCcConstants.TPM_CC_HierarchyControl, authorityRc, request);
        }

        //The compare above was this credential's only use, so this transition is its terminal owner;
        //every arm that refuses before this point releases it through the request's own Dispose.
        request.AuthSupplied.Dispose();

        TpmSimulatorState controlled = ApplyHierarchyEnable(authorized, request.Enable.Value, request.State);

        return Transition(
            controlled with
            {
                ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
            },
            "HierarchyControl");
    }

    /// <summary>
    /// Authorizes <c>TPM2_HierarchyControl()</c> over an HMAC session, declaring the command-HMAC verification
    /// (TPM 2.0 Library Part 3, clause 24.2).
    /// </summary>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_HierarchyControl()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the HMAC verification, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnHierarchyControlOverSession(TpmSimulatorState state, TpmHierarchyControlOverSessionRequested request)
    {
        if(!TpmSimulatorState.IsBaseHierarchyHandle(request.AuthHandle.Value) || !TpmSimulatorState.IsEnablesHandle(request.Enable.Value))
        {
            return Reject(state, TpmCcConstants.TPM_CC_HierarchyControl, TpmRcConstants.TPM_RC_VALUE, request);
        }

        if(!state.HmacSessions.TryGetValue(TpmiShHmac.FromValue(request.AuthorizingSessionHandle.Value), out HmacSessionState? session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_HierarchyControl, SessionReferenceMissRc(sessionIndex: 0), request);
        }

        TpmPendingSessionVerification? pending = BeginHierarchyAuthorization(
            state, request.AuthHandle.Value, session, request.SessionAttributes, request.NonceCaller, request.Hmac,
            hasDecryptSession: false, decryptSessionAttributes: default, decryptSessionHandle: default, Tpm2bNonce.Empty,
            TpmtSymDef.Null, Tpm2bNonce.Empty,
            firstCommandParameterIsEncryptable: false, out TpmRcConstants refusal, out _);
        if(pending is null)
        {
            return Reject(state, TpmCcConstants.TPM_CC_HierarchyControl, refusal, request);
        }

        return Transition(
            state with
            {
                NextAction = new TpmVerifyCommandHmacAction(
                    TpmCcConstants.TPM_CC_HierarchyControl, TpmCommandHandleNames.Of(TpmHandleName.FromHandle(request.AuthHandle.Value)), request.RawParameterArea, pending,
                    ImmutableArray<TpmPendingSessionVerification>.Empty, request with { ResolvedAuthValue = pending.AuthValue }),
                ResponseIntent = null
            },
            "HierarchyControl:OverSession:HmacVerifyRequested");
    }

    /// <summary>
    /// Resumes <c>TPM2_HierarchyControl()</c> over an HMAC session once its command HMAC has verified: applies
    /// the authority rule and the enable change, then declares the response framing (TPM 2.0 Library Part 3,
    /// clause 24.2.1).
    /// </summary>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_HierarchyControl()</c> request, its session now verified.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the response framing, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> ContinueHierarchyControlOverSession(TpmSimulatorState state, TpmHierarchyControlOverSessionRequested request)
    {
        if(ValidateHierarchyControlAuthority(request.AuthHandle.Value, request.Enable.Value) is TpmRcConstants authorityRc)
        {
            return Reject(state, TpmCcConstants.TPM_CC_HierarchyControl, authorityRc, request);
        }

        //This continuation is the parse-rented parameter area's terminal owner: the command HMAC that read it
        //has verified, and nothing downstream reads it again.
        request.Hmac.Dispose();
        request.RawParameterArea.Dispose();

        TpmSimulatorState controlled = ApplyHierarchyEnable(state, request.Enable.Value, request.State);

        return FrameHierarchySessionResponse(
            controlled, TpmCcConstants.TPM_CC_HierarchyControl, request.AuthorizingSessionHandle.Value,
            request.ResolvedAuthValue, request.NonceCaller, request.SessionAttributes,
            "HierarchyControl:OverSession:ResponseRequested");
    }

    /// <summary>
    /// Enforces which authority may write which enable (TPM 2.0 Library Part 3, clause 24.2.1): the platform
    /// hierarchy's two enables answer to platformAuth alone, while the storage and endorsement enables may be
    /// CLEARed by their own hierarchy as well.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The refusal is <c>TPM_RC_AUTH_TYPE</c> — the authorization is a kind this action does not accept, rather
    /// than a value that failed to verify — which is why it is checked after the authorization has already been
    /// proven rather than in its place.
    /// </para>
    /// <para>
    /// The other half of the clause, "If shEnable is disabled, then it may only be enabled if
    /// platformAuth/platformPolicy is provided", needs no rule of its own here and deliberately has none: while
    /// an enable is CLEAR its hierarchy's authValue and authPolicy cannot authorize anything at all (Part 1,
    /// clause 11.2), so an owner-authorized attempt to re-enable the storage hierarchy never reaches this check —
    /// the availability gate has already answered <c>TPM_RC_HIERARCHY</c>. The same structure is what makes
    /// <c>phEnable</c> unrecoverable by command: the only authority that could SET it is the one it disables.
    /// </para>
    /// </remarks>
    /// <param name="authHandle">The authorizing hierarchy.</param>
    /// <param name="enable">The enable being written.</param>
    /// <returns>The refusal, or <see langword="null"/> when that authority may write that enable.</returns>
    private static TpmRcConstants? ValidateHierarchyControlAuthority(uint authHandle, uint enable) =>
        enable switch
        {
            (uint)TpmRh.TPM_RH_PLATFORM or (uint)TpmRh.TPM_RH_PLATFORM_NV when authHandle != (uint)TpmRh.TPM_RH_PLATFORM => TpmRcConstants.TPM_RC_AUTH_TYPE,
            (uint)TpmRh.TPM_RH_OWNER when authHandle is not ((uint)TpmRh.TPM_RH_PLATFORM or (uint)TpmRh.TPM_RH_OWNER) => TpmRcConstants.TPM_RC_AUTH_TYPE,
            (uint)TpmRh.TPM_RH_ENDORSEMENT when authHandle is not ((uint)TpmRh.TPM_RH_PLATFORM or (uint)TpmRh.TPM_RH_ENDORSEMENT) => TpmRcConstants.TPM_RC_AUTH_TYPE,
            _ => null
        };

    /// <summary>
    /// Writes one of the four <c>TPMA_STARTUP_CLEAR</c> enables and, when the write disables a hierarchy, flushes
    /// that hierarchy's loaded transient objects (TPM 2.0 Library Part 3, clause 24.2.1: "the TPM will disable use
    /// of any persistent entity associated with the disabled hierarchy and will flush any transient objects
    /// associated with the disabled hierarchy").
    /// </summary>
    /// <remarks>
    /// <para>
    /// Only the transient flush is an observable state change: persistent entities are DISABLED, not evicted, and
    /// so are left in place — a re-enable must find them again, which eviction would prevent. Disabling the
    /// platform NV enable flushes nothing at all, since it governs NV Indexes rather than objects. The enable is
    /// authoritative for authorization and for the provisioning commands that consult it; a command holding an
    /// already-resolved persistent object handle still uses it, so "disable use of any persistent entity" is
    /// modelled only to the extent that the hierarchy can no longer authorize anything.
    /// </para>
    /// <para>
    /// <b>Recorded deviation — the clause's NV half is not modelled.</b> Clause 24.2.1 gives the two enables an
    /// NV reach this function does not reproduce: while <c>shEnable</c> is CLEAR the TPM returns an error to any
    /// command that operates on an NV Index whose <c>TPMA_NV_PLATFORMCREATE</c> is CLEAR (an Owner-defined Index),
    /// and while <c>phEnableNV</c> is CLEAR it does the same for any Index whose <c>TPMA_NV_PLATFORMCREATE</c> is
    /// SET (a Platform-defined Index) — in both cases for the whole time the enable stays CLEAR, not merely at the
    /// moment it is written. Here the enables gate authorization and the provisioning commands that read them, so
    /// an Index reached by its own authValue or policy remains operable across a hierarchy that clause 24.2.1 says
    /// has been closed over it. This is the same shape as the persistent-entity limitation above and belongs with
    /// it: closing both means threading the two enables plus each Index's <c>TPMA_NV_PLATFORMCREATE</c> through
    /// every NV command's availability check, a family-wide sweep deliberately outside this command's own ladder
    /// and deferred to it rather than approximated here.
    /// </para>
    /// </remarks>
    /// <param name="state">The state to write the enable on.</param>
    /// <param name="enable">The enable being written.</param>
    /// <param name="enableState">YES to SET the enable, NO to CLEAR it.</param>
    /// <returns>The state with the enable written and any disabled hierarchy's transient objects flushed.</returns>
    private static TpmSimulatorState ApplyHierarchyEnable(TpmSimulatorState state, uint enable, TpmiYesNo enableState)
    {
        bool isSet = enableState.IsYes;

        TpmSimulatorState controlled = enable switch
        {
            (uint)TpmRh.TPM_RH_OWNER => state with { ShEnable = isSet },
            (uint)TpmRh.TPM_RH_ENDORSEMENT => state with { EhEnable = isSet },
            (uint)TpmRh.TPM_RH_PLATFORM => state with { PhEnable = isSet },
            (uint)TpmRh.TPM_RH_PLATFORM_NV => state with { PhEnableNV = isSet },
            _ => state
        };

        if(isSet || enable == (uint)TpmRh.TPM_RH_PLATFORM_NV)
        {
            return controlled;
        }

        ImmutableDictionary<TpmiDhObject, TransientKeyState> transientObjects = controlled.TransientObjects;
        foreach(KeyValuePair<TpmiDhObject, TransientKeyState> entry in controlled.TransientObjects)
        {
            if(entry.Value.Hierarchy.Value == enable)
            {
                //Disabling the hierarchy evicts its residents for good, so each entry's owned private-key
                //carrier is released as the loop visits it.
                entry.Value.Dispose();
                transientObjects = transientObjects.Remove(entry.Key);
            }
        }

        return controlled with { TransientObjects = transientObjects };
    }

    /// <summary>
    /// Installs a hierarchy's authorization policy for the password arm of <c>TPM2_SetPrimaryPolicy()</c>
    /// (TPM 2.0 Library Part 3, clause 24.3).
    /// </summary>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_SetPrimaryPolicy()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnSetPrimaryPolicy(TpmSimulatorState state, TpmSetPrimaryPolicyRequested request)
    {
        //TPMI_RH_HIERARCHY_POLICY also admits the Authenticated Countdown Timer range, which this simulator does
        //not model; an ACT handle therefore lands here with every other out-of-range value and answers the
        //interface type's own unmarshal failure rather than being silently accepted into a slot that does not exist.
        if(!TpmSimulatorState.IsHierarchyAuthHandle(request.AuthHandle.Value))
        {
            return Reject(state, TpmCcConstants.TPM_CC_SetPrimaryPolicy, TpmRcConstants.TPM_RC_VALUE, request);
        }

        (TpmRcConstants? authError, TpmSimulatorState authorized) = VerifyHierarchyAuthorization(state, request.AuthHandle.Value, request.AuthSupplied.AsReadOnlyMemory());
        if(authError is TpmRcConstants authRc)
        {
            return Reject(authorized, TpmCcConstants.TPM_CC_SetPrimaryPolicy, authRc, request);
        }

        if(ValidateAuthPolicyShape(request.AuthPolicy, request.HashAlg) is TpmRcConstants shapeRc)
        {
            return Reject(authorized, TpmCcConstants.TPM_CC_SetPrimaryPolicy, shapeRc, request);
        }

        TpmSimulatorState installed = authorized.WithHierarchyAuthPolicy(request.AuthHandle.Value, request.AuthPolicy, request.HashAlg);

        //The compare above was this credential's only use, so this transition is its terminal owner;
        //every arm that refuses before this point releases it through the request's own Dispose.
        request.AuthSupplied.Dispose();

        return Transition(
            installed with
            {
                ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
            },
            "SetPrimaryPolicy");
    }

    /// <summary>
    /// Authorizes <c>TPM2_SetPrimaryPolicy()</c> over an HMAC session, declaring the command-HMAC verification
    /// (TPM 2.0 Library Part 3, clause 24.3).
    /// </summary>
    /// <remarks>
    /// <c>authPolicy</c> is a sized first command parameter and so structurally decrypt-eligible, but it is a
    /// public digest — any holder of the resulting policy can compute it, and a policy session reveals it through
    /// <c>TPM2_PolicyGetDigest()</c> — so no decrypt shape is offered and the gate stays closed rather than
    /// carrying machinery that would protect nothing.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_SetPrimaryPolicy()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the HMAC verification, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnSetPrimaryPolicyOverSession(TpmSimulatorState state, TpmSetPrimaryPolicyOverSessionRequested request)
    {
        if(!TpmSimulatorState.IsHierarchyAuthHandle(request.AuthHandle.Value))
        {
            return Reject(state, TpmCcConstants.TPM_CC_SetPrimaryPolicy, TpmRcConstants.TPM_RC_VALUE, request);
        }

        if(!state.HmacSessions.TryGetValue(TpmiShHmac.FromValue(request.AuthorizingSessionHandle.Value), out HmacSessionState? session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_SetPrimaryPolicy, SessionReferenceMissRc(sessionIndex: 0), request);
        }

        TpmPendingSessionVerification? pending = BeginHierarchyAuthorization(
            state, request.AuthHandle.Value, session, request.SessionAttributes, request.NonceCaller, request.Hmac,
            hasDecryptSession: false, decryptSessionAttributes: default, decryptSessionHandle: default, Tpm2bNonce.Empty,
            TpmtSymDef.Null, Tpm2bNonce.Empty,
            firstCommandParameterIsEncryptable: false, out TpmRcConstants refusal, out _);
        if(pending is null)
        {
            return Reject(state, TpmCcConstants.TPM_CC_SetPrimaryPolicy, refusal, request);
        }

        return Transition(
            state with
            {
                NextAction = new TpmVerifyCommandHmacAction(
                    TpmCcConstants.TPM_CC_SetPrimaryPolicy, TpmCommandHandleNames.Of(TpmHandleName.FromHandle(request.AuthHandle.Value)), request.RawParameterArea, pending,
                    ImmutableArray<TpmPendingSessionVerification>.Empty, request with { ResolvedAuthValue = pending.AuthValue }),
                ResponseIntent = null
            },
            "SetPrimaryPolicy:OverSession:HmacVerifyRequested");
    }

    /// <summary>
    /// Resumes <c>TPM2_SetPrimaryPolicy()</c> over an HMAC session once its command HMAC has verified: applies
    /// the policy/algorithm consistency gate and installs the policy, then declares the response framing.
    /// </summary>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_SetPrimaryPolicy()</c> request, its session now verified.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the response framing, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> ContinueSetPrimaryPolicyOverSession(TpmSimulatorState state, TpmSetPrimaryPolicyOverSessionRequested request)
    {
        if(ValidateAuthPolicyShape(request.AuthPolicy, request.HashAlg) is TpmRcConstants shapeRc)
        {
            return Reject(state, TpmCcConstants.TPM_CC_SetPrimaryPolicy, shapeRc, request);
        }

        //This continuation is the parse-rented parameter area's terminal owner: the command HMAC that read it
        //has verified, and nothing downstream reads it again.
        request.Hmac.Dispose();
        request.RawParameterArea.Dispose();

        TpmSimulatorState installed = state.WithHierarchyAuthPolicy(request.AuthHandle.Value, request.AuthPolicy, request.HashAlg);

        return FrameHierarchySessionResponse(
            installed, TpmCcConstants.TPM_CC_SetPrimaryPolicy, request.AuthorizingSessionHandle.Value,
            request.ResolvedAuthValue, request.NonceCaller, request.SessionAttributes,
            "SetPrimaryPolicy:OverSession:ResponseRequested");
    }

    /// <summary>
    /// Checks that a <c>TPM2_SetPrimaryPolicy()</c> policy digest and its hash algorithm agree (TPM 2.0 Library
    /// Part 3, clause 24.3.1: "When hashAlg is not TPM_ALG_NULL, if the size of authPolicy is not consistent with
    /// the hash algorithm, the TPM returns TPM_RC_SIZE").
    /// </summary>
    /// <remarks>
    /// One comparison covers both directions the clause's own table states, because the null algorithm's digest
    /// size is zero: a non-empty digest offered with <c>TPM_ALG_NULL</c> fails it ("If hashAlg is TPM_ALG_NULL,
    /// then this shall be an Empty Buffer", clause 24.3.2) and so does an Empty Buffer offered with a real
    /// algorithm ("If the authPolicy is an Empty Buffer, then this field shall be TPM_ALG_NULL"). An algorithm
    /// this model cannot compute a policy digest under is refused first and separately, with
    /// <c>TPM_RC_HASH</c> — installing a policy under such an algorithm would store a digest no session could
    /// ever be measured against, which is a silently unsatisfiable policy rather than a size error.
    /// </remarks>
    /// <param name="authPolicy">The policy digest offered, in the request's owned carrier — read here, never disposed.</param>
    /// <param name="hashAlg">The hash algorithm offered alongside it.</param>
    /// <returns>The refusal, or <see langword="null"/> when the pair is consistent.</returns>
    private static TpmRcConstants? ValidateAuthPolicyShape(Tpm2bDigest authPolicy, TpmiAlgHash hashAlg)
    {
        if(!hashAlg.IsNull && !IsSupportedPolicyHash(hashAlg))
        {
            return TpmRcConstants.TPM_RC_HASH;
        }

        return authPolicy.Size != (hashAlg.DigestSize ?? 0)
            ? TpmRcConstants.TPM_RC_SIZE
            : null;
    }

    /// <summary>
    /// Replaces a hierarchy's authorization value for the password arm of <c>TPM2_HierarchyChangeAuth()</c>,
    /// authorized by the value being replaced (TPM 2.0 Library Part 3, clause 24.8).
    /// </summary>
    /// <remarks>
    /// The response carries no session, so the clause's response-HMAC rule has nothing to key here; it is the
    /// session arm that has to honour it. A disabled hierarchy is refused before the rotation is even considered:
    /// "TPM2_HierarchyChangeAuth() can change the authValue associated with a hierarchy but only if the hierarchy
    /// is enabled" (Part 1, clause 11.2). That refusal is <c>TPM_RC_HIERARCHY</c> by analogy with the code Part 3,
    /// clause 24.3.1 states for the identical condition on its sibling command; clause 24.8 names no code for it
    /// itself, so the choice is an inference from the shared availability rule rather than a quotation.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_HierarchyChangeAuth()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnHierarchyChangeAuth(TpmSimulatorState state, TpmHierarchyChangeAuthRequested request)
    {
        if(!TpmSimulatorState.IsHierarchyAuthHandle(request.AuthHandle.Value))
        {
            return Reject(state, TpmCcConstants.TPM_CC_HierarchyChangeAuth, TpmRcConstants.TPM_RC_VALUE, request);
        }

        (TpmRcConstants? authError, TpmSimulatorState authorized) = VerifyHierarchyAuthorization(state, request.AuthHandle.Value, request.AuthSupplied.AsReadOnlyMemory());
        if(authError is TpmRcConstants authRc)
        {
            return Reject(authorized, TpmCcConstants.TPM_CC_HierarchyChangeAuth, authRc, request);
        }

        ReadOnlySpan<byte> strippedNewAuth = StripTrailingZeros(request.NewAuth.AsReadOnlySpan());
        if(strippedNewAuth.Length > TpmSimulatorState.ContextIntegrityDigestSize)
        {
            return Reject(authorized, TpmCcConstants.TPM_CC_HierarchyChangeAuth, TpmRcConstants.TPM_RC_SIZE, request);
        }

        TpmSimulatorState rotated = authorized.WithHierarchyAuthValue(request.AuthHandle.Value, request.NewAuth);

        //The compare above was this credential's only use, so this transition is its terminal owner;
        //every arm that refuses before this point releases it through the request's own Dispose.
        request.AuthSupplied.Dispose();

        return Transition(
            rotated with
            {
                ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
            },
            "HierarchyChangeAuth");
    }

    /// <summary>
    /// Authorizes a <c>TPM2_HierarchyChangeAuth()</c> whose authorization area is more than a lone password slot,
    /// declaring the command-HMAC verification for every real session in it (TPM 2.0 Library Part 3, clause 24.8;
    /// clause 5.6, checks 9 and 10).
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>decrypt</c> or <c>encrypt</c> on the AUTHORIZING session is refused with <c>TPM_RC_ATTRIBUTES</c>
    /// rather than modelled, for the same reason the NV family's own authValue rotation refuses it: such a
    /// session, unbound and unsalted, derives its whole parameter-encryption key from the very authValue being
    /// rotated away from (Part 1, clause 19.1), so it protects <c>newAuth</c> against nobody who could not
    /// already guess the old value. A caller wanting <c>newAuth</c> confidential supplies a SEPARATE decrypt
    /// session, whose sessionValue is its own session key; that session authorizes nothing but still owes a
    /// command HMAC like every other session in the area, and its nonceTPM folds into the authorizing session's
    /// HMAC as the session at index 1 (clause 17.6.3.4).
    /// </para>
    /// <para>
    /// Slot 0 may equally be <c>TPM_RS_PW</c>, which reaches this arm only alongside that companion (a lone
    /// password area parses to <see cref="TpmHierarchyChangeAuthRequested"/>): its <c>hmac</c> field is the
    /// plaintext current authValue, compared INLINE because a password authorization computes no cpHash (Part 1,
    /// clause 17.6.4.1) — the <c>OnCreateSealedObjectOverSessions</c> password-slot discipline, running the same
    /// hierarchy ladder <see cref="VerifyHierarchyAuthorization"/> gives the plain arm so the two forms cannot
    /// answer a wrong password differently. Only the companion is then queued for HMAC verification, and the
    /// response owes a placeholder entry at slot 0 beside the companion's real one (clause 16.6.1: "the response
    /// has the same number of sessions in the same order as the request").
    /// </para>
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_HierarchyChangeAuth()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the HMAC verification, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnHierarchyChangeAuthOverSession(TpmSimulatorState state, TpmHierarchyChangeAuthOverSessionRequested request)
    {
        if(!TpmSimulatorState.IsHierarchyAuthHandle(request.AuthHandle.Value))
        {
            return Reject(state, TpmCcConstants.TPM_CC_HierarchyChangeAuth, TpmRcConstants.TPM_RC_VALUE, request);
        }

        //Slot 0 is resolved for every value it can hold, in the order Part 3, clause 5.5, step 4 prescribes: a
        //handle that is not a session handle at all is TPM_RC_HANDLE, a well-typed handle naming no loaded
        //session is TPM_RC_REFERENCE_S*, and TPM_RS_PW resolves to no session record at all — the password slot
        //this arm admits only alongside a companion.
        if(!TryResolveCommandSession(state, request.AuthorizingSessionHandle, sessionIndex: 0, out HmacSessionState? session, out TpmRcConstants authorizingSlotRefusal))
        {
            return Reject(state, TpmCcConstants.TPM_CC_HierarchyChangeAuth, authorizingSlotRefusal, request);
        }

        //Whether the second block arrived is a structural fact the parser settled from authorizationSize, so it is
        //read from the record rather than guessed from the handle, and the slot is then resolved and validated for
        //every value it can hold: a handle that is not a session handle at all is TPM_RC_HANDLE and a well-typed
        //handle naming no loaded session is TPM_RC_REFERENCE_S*, both blamed on this index (Part 3, clause 5.5,
        //step 4).
        bool hasDecryptSession = request.HasDecryptSlot;
        HmacSessionState? decryptSession = null;
        if(hasDecryptSession
            && !TryResolveCommandSession(state, request.DecryptSessionHandle, sessionIndex: 1, out decryptSession, out TpmRcConstants decryptSlotRefusal))
        {
            return Reject(state, TpmCcConstants.TPM_CC_HierarchyChangeAuth, decryptSlotRefusal, request);
        }

        if((request.SessionAttributes & (TpmaSession.DECRYPT | TpmaSession.ENCRYPT)) != 0)
        {
            return Reject(state, TpmCcConstants.TPM_CC_HierarchyChangeAuth, SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), request);
        }

        //The decrypt companion's own bind-side lockout gate; an HMAC slot 0's runs inside
        //BeginHierarchyAuthorization below, and a password slot 0 has no bind to gate. A companion's key folded
        //whatever entity it was bound to (Part 1, clause 17.8.1's third way an authValue is used for
        //authorization).
        if(decryptSession is not null && IsBoundSessionLockedOut(state, decryptSession))
        {
            return Reject(state, TpmCcConstants.TPM_CC_HierarchyChangeAuth, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        TpmSimulatorState authorized = state;
        TpmPendingSessionVerification? pending = null;
        bool bindOmitsAuthValue = false;

        if(session is null)
        {
            //A password slot 0 skips BeginHierarchyAuthorization — it has no session key, no bind, and no cpHash
            //(Part 1, clause 17.6.4.1) — so the area validation that helper performs runs here in its own right,
            //where TryValidatePasswordSlot settles the slot's attributes and its nonce width (clause 16.6.4,
            //Table 12) and the companion's claims are checked against it.
            TpmRcConstants? passwordAreaError = ValidateSessionArea(
                request.SessionAttributes, firstAuthorizesEntity: true, TpmtSymDef.Null,
                hasDecryptSession, request.DecryptSessionAttributes, decryptSession?.Symmetric ?? TpmtSymDef.Null,
                firstCommandParameterIsEncryptable: true, firstResponseParameterIsEncryptable: false,
                auditIsSupported: false,
                firstSessionHandle: request.AuthorizingSessionHandle, secondSessionHandle: request.DecryptSessionHandle,
                firstNonceLength: request.NonceCaller.Size, secondNonceLength: request.DecryptNonceCaller.Size);
            if(passwordAreaError is TpmRcConstants passwordAreaRc)
            {
                return Reject(state, TpmCcConstants.TPM_CC_HierarchyChangeAuth, passwordAreaRc, request);
            }

            //The identical hierarchy ladder the plain arm runs — enable gate, authValue slot, the lockout
            //entity's own two gates, then the fixed-time trailing-zero-stripped compare (Part 1, clause 17.6.4.3)
            //with its one-strike update for lockoutAuth. Only the CREDENTIAL outcome is session-index-encoded to
            //this slot, the way OnCreateSealedObjectOverSessions encodes its own inline password mismatch
            //(Part 3, clause 5.6, check 10; Part 2, clause 6.6.2); an availability refusal is about the handle
            //rather than about a slot, so it stays bare exactly as it does on the HMAC path.
            (TpmRcConstants? passwordError, TpmSimulatorState afterCompare) = VerifyHierarchyAuthorization(state, request.AuthHandle.Value, request.Hmac.AsReadOnlyMemory());
            if(passwordError is TpmRcConstants passwordRc)
            {
                TpmRcConstants encoded = passwordRc switch
                {
                    TpmRcConstants.TPM_RC_BAD_AUTH or TpmRcConstants.TPM_RC_AUTH_FAIL => SessionEncodedRc(passwordRc, sessionIndex: 0),
                    _ => passwordRc
                };

                return Reject(afterCompare, TpmCcConstants.TPM_CC_HierarchyChangeAuth, encoded, request);
            }

            authorized = afterCompare;
        }
        else
        {
            pending = BeginHierarchyAuthorization(
                state, request.AuthHandle.Value, session, request.SessionAttributes, request.NonceCaller, request.Hmac,
                hasDecryptSession, request.DecryptSessionAttributes, request.DecryptSessionHandle, request.DecryptNonceCaller,
                decryptSession?.Symmetric ?? TpmtSymDef.Null, decryptSession?.NonceTpm ?? Tpm2bNonce.Empty,
                firstCommandParameterIsEncryptable: true, out TpmRcConstants refusal, out bindOmitsAuthValue);
            if(pending is null)
            {
                return Reject(state, TpmCcConstants.TPM_CC_HierarchyChangeAuth, refusal, request);
            }
        }

        var pendings = ImmutableArray.CreateBuilder<TpmPendingSessionVerification>(2);
        if(pending is not null)
        {
            pendings.Add(pending);
        }

        //The decrypt companion authorizes no entity, so its whole dictionary-attack standing comes from its own
        //bind: a wrong HMAC on it is evidence against the authValue its session key folded, which for a session
        //bound to the hierarchy being rotated is that hierarchy's own secret (clause 17.8.1's use 3). It owes its
        //own command HMAC whatever slot 0 turned out to be (Part 3, clause 5.6 applies to every session in the
        //area).
        if(decryptSession is not null)
        {
            pendings.Add(new TpmPendingSessionVerification(
                SessionHandle: TpmiShAuthSession.FromValue(decryptSession.Handle.Value), SessionIndex: 1, SessionAlg: decryptSession.SessionAlg, SessionKey: decryptSession.SessionKey,
                AuthValue: Tpm2bAuth.Empty, IsDaProtected: decryptSession.IsBoundEntityDaProtected,
                NonceCaller: request.DecryptNonceCaller, NonceTpm: decryptSession.NonceTpm,
                FoldedNonceDecrypt: Tpm2bNonce.Empty, FoldedNonceEncrypt: Tpm2bNonce.Empty,
                SessionAttributes: request.DecryptSessionAttributes, SuppliedHmac: request.DecryptHmac,
                IsLockoutEntity: decryptSession.IsBoundToLockout));
        }

        //Every reachable combination leaves at least one queued verification: a lone password area parses to
        //TpmHierarchyChangeAuthRequested and never arrives here, and a TPM_RS_PW companion authorizes nothing yet
        //may claim no attribute, so the session-area validation above already refused it.
        ImmutableArray<TpmPendingSessionVerification> queue = pendings.ToImmutable();

        return Transition(
            authorized with
            {
                NextAction = new TpmVerifyCommandHmacAction(
                    TpmCcConstants.TPM_CC_HierarchyChangeAuth, TpmCommandHandleNames.Of(TpmHandleName.FromHandle(request.AuthHandle.Value)), request.RawParameterArea, queue[0],
                    queue.RemoveAt(0), request with { ResolvedAuthValue = pending?.AuthValue, BindOmitsAuthValue = bindOmitsAuthValue }),
                ResponseIntent = null
            },
            "HierarchyChangeAuth:OverSession:HmacVerifyRequested");
    }

    /// <summary>
    /// Resumes <c>TPM2_HierarchyChangeAuth()</c> once every session in its authorization area has verified:
    /// either declares the <c>newAuth</c> decryption or completes the rotation directly.
    /// </summary>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_HierarchyChangeAuth()</c> request, its sessions now verified.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the decrypt action, or the completed rotation.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> ContinueHierarchyChangeAuthOverSession(TpmSimulatorState state, TpmHierarchyChangeAuthOverSessionRequested request)
    {
        //A decrypt-attributed companion session encrypted newAuth (Part 1, clause 19.1): its plaintext cannot
        //become the hierarchy's authValue until it is decrypted, which follows the now-complete command-HMAC
        //verification of BOTH sessions (Part 3, clause 5.6 precedes clause 5.8). The keystream is derived from
        //that session's own key alone, never the authorizing session's material.
        if(request.HasDecryptSlot && (request.DecryptSessionAttributes & TpmaSession.DECRYPT) != 0)
        {
            HmacSessionState decryptSession = state.HmacSessions[TpmiShHmac.FromValue(request.DecryptSessionHandle.Value)];

            return Transition(
                state with
                {
                    NextAction = new TpmDecryptHierarchyChangeAuthAction(
                        request, request.RawParameterArea, decryptSession.SessionAlg, decryptSession.Symmetric,
                        decryptSession.SessionKey, Tpm2bAuth.Empty, request.DecryptNonceCaller, decryptSession.NonceTpm),
                    ResponseIntent = null
                },
                "HierarchyChangeAuth:OverSession:NewAuthDecryptRequested");
        }

        //No decrypt session: newAuth crossed in the clear, so its parsed value is the replacement authValue.
        return CompleteHierarchyChangeAuth(state, request, request.NewAuth);
    }

    /// <summary>
    /// Completes <c>TPM2_HierarchyChangeAuth()</c> once its <c>newAuth</c> parameter has been decrypted
    /// (<see cref="TpmDecryptHierarchyChangeAuthAction"/>'s continuation, TPM 2.0 Library Part 3, clause 24.8).
    /// </summary>
    /// <param name="state">The state to transition from.</param>
    /// <param name="decrypted">The effect's result carrying the decrypted <c>newAuth</c> and the request to resume.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> completing the rotation, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnHierarchyChangeAuthDecrypted(TpmSimulatorState state, TpmHierarchyChangeAuthDecrypted decrypted)
    {
        if(decrypted.ResponseCode != TpmRcConstants.TPM_RC_SUCCESS)
        {
            return Reject(state, TpmCcConstants.TPM_CC_HierarchyChangeAuth, decrypted.ResponseCode, decrypted);
        }

        //The request's parsed carrier held ciphertext on this path; the recovered value supersedes it.
        decrypted.Request.NewAuth.Dispose();

        return CompleteHierarchyChangeAuth(state, decrypted.Request, decrypted.DecryptedNewAuth);
    }

    /// <summary>
    /// Applies <c>TPM2_HierarchyChangeAuth()</c>'s size gate and its effect over a session — the tail shared by
    /// the plaintext (<see cref="ContinueHierarchyChangeAuthOverSession"/>) and decrypted
    /// (<see cref="OnHierarchyChangeAuthDecrypted"/>) paths, which reach it with a <paramref name="newAuth"/>
    /// that is respectively the parsed and the recovered form.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The strip-then-compare ORDER is normative, not an optimization: trailing octets of zero are removed from
    /// any string before it is used as an authValue (TPM 2.0 Library Part 1, clause 17.6.4.3), and only the
    /// remainder is measured. A value padded with zeros past the bound is therefore accepted while a genuinely
    /// longer one is <c>TPM_RC_SIZE</c>. The bound is the context-integrity digest size rather than a Name
    /// algorithm's, because a hierarchy has no Name algorithm — clause 17.6.4.2 names that substitute explicitly,
    /// and Part 3, clause 24.8.1 restates it as this command's own rule. The hash-if-too-long convention for an
    /// over-long passphrase is the caller's to apply ("The TPM does not enforce this transformation"), so an
    /// over-long value is refused here rather than silently digested.
    /// </para>
    /// <para>
    /// The rotation is committed BEFORE the response is framed, which is the whole point of resolving the
    /// response's authValue term from the post-rotation state: "The HMAC in the response shall use the new
    /// authorization value when computing the response HMAC" (clause 24.8.1). A response keyed on the old value
    /// would verify against a host that had not yet swapped, which is precisely the mistake that sentence
    /// forecloses.
    /// </para>
    /// <para>
    /// The response session list mirrors the command's authorization area one for one: a real slot 0 gets its own
    /// keyed entry, a <c>TPM_RS_PW</c> slot 0 gets the empty-nonce, empty-HMAC placeholder it is owed, and a
    /// decrypt companion always gets its own entry after it — "If the responseCode is TPM_RC_SUCCESS, the
    /// response has the same number of sessions in the same order as the request" (Part 1, clause 16.6.1).
    /// </para>
    /// </remarks>
    /// <param name="state">The state to transition from, with authorization already established.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_HierarchyChangeAuth()</c> request.</param>
    /// <param name="newAuth">The replacement authorization value in an owned carrier, trailing zeros not yet removed; ownership transfers to the hierarchy slot at install, and the refusing arm releases it instead.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the response framing, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> CompleteHierarchyChangeAuth(
        TpmSimulatorState state, TpmHierarchyChangeAuthOverSessionRequested request, Tpm2bAuth newAuth)
    {
        ReadOnlySpan<byte> strippedNewAuth = StripTrailingZeros(newAuth.AsReadOnlySpan());
        if(strippedNewAuth.Length > TpmSimulatorState.ContextIntegrityDigestSize)
        {
            //Exactly one owner per carrier on the way out: the authValue this tail was handed is released here,
            //and the request the cascade releases has its own authValue slot swapped to the dispose-immune empty
            //sentinel — on the plaintext path that slot IS this carrier, and on the decrypted path the decrypt
            //continuation already superseded it.
            newAuth.Dispose();

            return Reject(state, TpmCcConstants.TPM_CC_HierarchyChangeAuth, TpmRcConstants.TPM_RC_SIZE, request with { NewAuth = Tpm2bAuth.Empty });
        }

        //This tail is the parse-rented parameter area's terminal owner: the command HMAC that read it has
        //verified, any decryption that transformed it in place has run, and nothing downstream reads it again.
        request.Hmac.Dispose();
        request.DecryptHmac.Dispose();
        request.RawParameterArea.Dispose();

        TpmSimulatorState rotated = state.WithHierarchyAuthValue(request.AuthHandle.Value, newAuth);
        bool hasDecryptSession = request.HasDecryptSlot;

        var responseSessions = ImmutableArray.CreateBuilder<TpmNvChangeAuthResponseSession>(hasDecryptSession ? 2 : 1);

        if(rotated.HmacSessions.TryGetValue(TpmiShHmac.FromValue(request.AuthorizingSessionHandle.Value), out HmacSessionState? session))
        {
            responseSessions.Add(new TpmNvChangeAuthResponseSession(
                IsPasswordPlaceholder: false,
                SessionHandle: TpmiShAuthSession.FromValue(session.Handle.Value), IsPolicySession: false, SessionAlg: session.SessionAlg,
                SessionKey: session.SessionKey,
                AuthValue: ResolveHierarchyResponseAuthValue(rotated, request.AuthHandle.Value, request.BindOmitsAuthValue),
                NonceCaller: request.NonceCaller, SessionAttributes: request.SessionAttributes));
        }
        else
        {
            //Slot 0 was TPM_RS_PW, which holds no session state and computes no response HMAC, yet still owes an
            //entry at its own position (Part 1, clause 16.6.1). Its continueSession attribute is SET rather than
            //echoed: "This attribute will always be SET in a response associated with a password authorization"
            //(clause 16.6.4, Table 12).
            //A placeholder entry keys no response HMAC, so it takes the shared empty carrier rather than the
            //slot's own nonce, and this branch is that nonce's terminal owner. A TPM_RS_PW slot parsed to the
            //empty carrier anyway; the branch is also reached when a real slot 0's session was flushed between
            //the verification and this tail, and then the carrier it rented is genuinely released here.
            request.NonceCaller.Dispose();

            responseSessions.Add(new TpmNvChangeAuthResponseSession(
                IsPasswordPlaceholder: true,
                SessionHandle: request.AuthorizingSessionHandle, IsPolicySession: false, SessionAlg: TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_NULL),
                SessionKey: TpmSimulatorState.EmptySessionKey, AuthValue: Tpm2bAuth.Empty,
                NonceCaller: Tpm2bNonce.Empty, SessionAttributes: TpmaSession.CONTINUE_SESSION));
        }

        if(hasDecryptSession)
        {
            HmacSessionState decryptSession = rotated.HmacSessions[TpmiShHmac.FromValue(request.DecryptSessionHandle.Value)];

            responseSessions.Add(new TpmNvChangeAuthResponseSession(
                IsPasswordPlaceholder: false,
                SessionHandle: TpmiShAuthSession.FromValue(decryptSession.Handle.Value), IsPolicySession: false, SessionAlg: decryptSession.SessionAlg,
                SessionKey: decryptSession.SessionKey, AuthValue: Tpm2bAuth.Empty,
                NonceCaller: request.DecryptNonceCaller, SessionAttributes: request.DecryptSessionAttributes));
        }

        return Transition(
            rotated with
            {
                NextAction = new TpmFrameNvChangeAuthResponseAction(TpmCcConstants.TPM_CC_HierarchyChangeAuth, responseSessions.ToImmutable()),
                ResponseIntent = null
            },
            "HierarchyChangeAuth:OverSession:ResponseRequested");
    }

    /// <summary>
    /// Has a signing key attest the contents of an NV Index at a caller-chosen offset/size, over a caller
    /// nonce, for <c>TPM2_NV_Certify()</c> (Part 3, clause 31.16).
    /// </summary>
    /// <remarks>
    /// Only the <c>TPMS_NV_CERTIFY_INFO</c> form is modelled (decision: a caller request for the
    /// zero-size/zero-offset <c>TPMS_NV_DIGEST_CERTIFY_INFO</c> form is unmodelled and rejected fail-closed with
    /// <c>TPM_RC_COMMAND_CODE</c> — the nearest documented "not implemented" code, mirroring how an unmodelled
    /// backend capability answers elsewhere in this simulator). signHandle must resolve to a loaded transient
    /// object and nvIndex to a defined Index; either missing is <c>TPM_RC_HANDLE</c>.
    /// qualifyingData/CanSign/hash-algorithm checks mirror <c>OnCertify</c>/<c>OnQuote</c>/<c>OnGetTime</c>
    /// exactly. The NV-specific checks then mirror <c>OnNvRead</c>: only Index authorization
    /// (<c>authHandle == nvIndex</c>) is modelled (else <c>TPM_RC_AUTH_TYPE</c>), an already-locked-out
    /// DA-protected Index is refused <c>TPM_RC_LOCKOUT</c> before anything is compared, and an Index whose
    /// <c>TPMA_NV_AUTHREAD</c> is CLEAR admits no authValue-based read of its contents at all — refused
    /// <c>TPM_RC_AUTH_UNAVAILABLE</c> before the authValue is even compared, because availability precedes the
    /// credential compare (Part 1, clause 35.2.5; Part 3, clause 5.6's check 7.2.2 is ordered ahead of its
    /// checks 9/10), the same early gate, in the same position, that the session-shaped area's
    /// <c>OnNvCertifyOverSession</c> applies, so neither authorization shape ever charges a credential
    /// compare — right or wrong — against a read-forbidden Index. Only once that gate has passed is the sign
    /// slot authorized: the signing key's own DA/Lockout gate (clause 5.6, check 3), its userWithAuth gate
    /// (check 7.1 — CLEAR refuses <c>TPM_RC_POLICY_FAIL</c>, uncharged, a policy session being the only
    /// admissible shape), then the fixed-time compare of the captured sign password against the key's retained
    /// authValue (a mismatch charges the dictionary-attack counter for a DA-protected signer and, arriving
    /// before the Index compare, never moves a PIN Index's pinCount). Then the supplied Index authorization is
    /// compared constant-time against the Index authValue (a mismatch is
    /// <c>TPM_RC_AUTH_FAIL</c> for a DA-protected Index, <c>TPM_RC_BAD_AUTH</c> otherwise), an unwritten Index is
    /// <c>TPM_RC_NV_UNINITIALIZED</c>, and the requested window must lie within the Index's retained written
    /// extent (<c>TPM_RC_NV_RANGE</c>) — the model retains only the octets actually written (as
    /// <c>OnNvRead</c>'s own bound already does), so this is the bound checked against rather than the Index's
    /// full declared dataSize. The signing scheme is dispatched on the signer's key type, and a scheme
    /// incompatible with the key's type is <c>TPM_RC_SCHEME</c>. The attestation needs an effect (compute the
    /// Index's Name, marshal, and sign), so the transition resolves both, slices the requested window, folds
    /// everything into the matching action, and leaves no response yet. The Index's own <c>NameAlg</c> and
    /// <c>AuthPolicy</c> travel with that action because both are fields of the <c>TPMS_NV_PUBLIC</c> the Name
    /// recipe hashes (Part 1, clause 14 and Table 6): the attested <c>TPMS_NV_CERTIFY_INFO.indexName</c> is the
    /// Index's real Name, so a verifier can bind the attestation to an Index it independently resolved through
    /// <c>TPM2_NV_ReadPublic()</c> whatever nameAlg or policy that Index was defined with.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_NV_Certify()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the certify action, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnNvCertify(TpmSimulatorState state, TpmNvCertifyRequested request)
    {
        if(!state.TransientObjects.TryGetValue(request.SignHandle, out TransientKeyState? signer))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        if(!state.NvIndexes.TryGetValue(request.NvIndex, out NvIndexState? index))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        if(request.QualifyingData.Length > Tpm2bData.MaxSize)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_SIZE, request);
        }

        if(!CanSign(signer.Attributes))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_KEY, request);
        }

        if(!IsSupportedAttestHashAlg(request.SchemeHashAlg))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_HASH, request);
        }

        //The TPMS_NV_DIGEST_CERTIFY_INFO form (size and offset both zero, Part 3, clause 31.16) is not modelled.
        if(request.Size == 0 && request.Offset == 0)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_COMMAND_CODE, request);
        }

        //Only Index authorization (authHandle == nvIndex) is modelled this slice, mirroring OnNvRead/OnNvWrite.
        if(request.AuthHandle.Value != request.NvIndex.Value)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_AUTH_TYPE, request);
        }

        //Already-locked-out DA-protected Index: refuse before even comparing (clause 17.8.3), no further increment.
        if(IsNvIndexLockedOut(state, index))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        //A PIN Index's own authValue is not usable while unwritten or once pinCount has reached pinLimit
        //(clause 37.2.6.6) — refused before even comparing, mirroring OnNvRead's own gate.
        if(IsPinAuthUnavailable(index))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, request);
        }

        //With TPMA_NV_AUTHREAD clear, the Index's own authValue is not an available authorization mechanism for
        //this read-role command at all (Part 1, clause 35.2.5), and availability precedes credential comparison:
        //Part 3, clause 5.6's check 7.2.2 (an NV Index authorized by an HMAC session or a password needs
        //TPMA_NV_AUTHREAD SET, else TPM_RC_AUTH_UNAVAILABLE) is ordered ahead of its checks 9/10, which perform
        //the HMAC/password credential compare — and it governs the password and HMAC mechanisms identically, so
        //this gate now MIRRORS OnNvCertifyOverSession's own early availability gate for the Index arm: both
        //certify arms answer a read-forbidden Index identically, with TPM_RC_AUTH_UNAVAILABLE, no dictionary-attack
        //charge, and no pinCount touch, regardless of whether the supplied authValue is correct. Refusing here —
        //before the compare below and before any PIN-count update — is what keeps that true; a wrong authValue
        //against a read-forbidden Index must not surface as an auth-failure/bad-auth, and a correct one must not
        //buy a signed attestation of the Index's contents.
        if(!index.IsAuthReadAllowed)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, request);
        }

        //The signing key's own DA/Lockout gate (Part 3, clause 5.6, check 3): a DA-protected signer under
        //lockout is refused before its password is compared, matching the sign slot's discipline in
        //OnSign/OnCertify/OnQuote/OnGetTime.
        if(signer.IsDaProtected && state.IsInLockout)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        //USER role gate (Part 3, clause 5.6, check 7.1): a signer whose userWithAuth attribute is CLEAR may
        //have its USER role authorized only by a policy session, never by a password — refused before the
        //compare below, uncharged, per clause 5.6's mandatory check order. Mirrors OnNvCertifyOverSession's
        //own sign-slot gate at the same pre-credential position.
        if((signer.Attributes & TpmaObject.USER_WITH_AUTH) == 0)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_POLICY_FAIL, request);
        }

        //The sign slot's USER-role authorization (session index 0, Part 3, clause 31.16's @signHandle): the
        //supplied password is compared against the signing key's retained authValue, both sides
        //trailing-zero-stripped (Part 1, clause 17.6.4.3), in fixed time — the same compare
        //OnNvCertifyOverSession applies to a password sign slot. Rejected before the Index compare below, so a
        //wrong sign password never moves a PIN Index's pinCount (clause 35.2.6.6 binds pinCount to the Index
        //authValue comparison's own outcome).
        if(!CryptographicOperations.FixedTimeEquals(
            StripTrailingZeros(request.SuppliedSignPassword.AsReadOnlySpan()),
            StripTrailingZeros(signer.AuthValue.AsReadOnlySpan())))
        {
            return RejectSessionAuthFailure(state, TpmCcConstants.TPM_CC_NV_Certify, sessionIndex: 0, signer.IsDaProtected, request);
        }

        //A PIN Index's own pinCount is updated on either outcome (clause 37.2.6.6) ahead of the DA-counter
        //check below, mirroring OnNvRead's own ordering.
        bool authMatched = CryptographicOperations.FixedTimeEquals(
            StripTrailingZeros(request.SuppliedIndexPassword.AsReadOnlySpan()),
            StripTrailingZeros(index.AuthValue.AsReadOnlySpan()));
        if(index.IsPinIndex)
        {
            index = ApplyPinAuthOutcome(index, authMatched);
            state = state with { NvIndexes = state.NvIndexes.SetItem(index.NvIndex, index) };
        }

        if(!authMatched)
        {
            //RejectNvAuthFailure has no disposing overload, so the request's carriers are released here — the
            //rejection framing below it reads only handles and dictionary state, never a carrier.
            request.Dispose();

            return RejectNvAuthFailure(state, index, TpmCcConstants.TPM_CC_NV_Certify);
        }

        if(!index.IsWritten)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_NV_UNINITIALIZED, request);
        }

        //The model retains only the octets actually written (its NvIndexState.Data grows with each write), so —
        //as OnNvRead already does — the bound checked here is the retained written extent, not the Index's full
        //declared dataSize; a request beyond it is equally TPM_RC_NV_RANGE.
        if((long)request.Offset + request.Size > index.Data.Length)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_NV_RANGE, request);
        }

        //"The implementation may return an error (TPM_RC_VALUE) if it performs an additional check and
        //determines that offset is greater than the dataSize field of the NV Index, or if size is greater than
        //MAX_NV_BUFFER_SIZE" (Part 3, clause 31.16.1). The certified content rides a TPM2B_MAX_NV_BUFFER inside
        //TPMS_NV_CERTIFY_INFO (Part 2, clause 10.12.8, Table 147), whose Table 99 bound this library fixes at
        //Tpm2bMaxNvBuffer.MaxSize and reports through TPM_PT_NV_BUFFER_MAX. The clause states the range rule as
        //a "shall" and this one as the additional check, and the reference's own TPM2_NV_Certify runs them in
        //that same order, so a window that is both out of range and over the bound answers TPM_RC_NV_RANGE.
        if(request.Size > Tpm2bMaxNvBuffer.MaxSize)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_VALUE, request);
        }

        //The certified window is a live view of the Index's own pooled area — borrowed, never copied — carried
        //across the signing effect, which is safe because the automaton processes one command at a time: no
        //store can reach the area between this slice and the attestation being signed over it, and the Index
        //remains the area's only owner throughout.
        ReadOnlyMemory<byte> window = index.Data.AsReadOnlyMemory().Slice(request.Offset, request.Size);
        TpmsClockInfo clockSnapshot = new(state.Clock, state.ResetCount, state.RestartCount, state.ClockSafe);

        TpmAction? action = (signer.KeyType.Value, request.SignatureScheme.Value) switch
        {
            (TpmAlgIdConstants.TPM_ALG_RSA, TpmAlgIdConstants.TPM_ALG_RSASSA or TpmAlgIdConstants.TPM_ALG_RSAPSS) =>
                new TpmRsaNvCertifyAction(
                    signer.Name, signer.Hierarchy, request.QualifyingData, signer.PrivateKey, request.SignatureScheme, request.SchemeHashAlg,
                    index.NvIndex, index.NameAlg, index.Attributes, index.AuthPolicy, index.DataSize, window, request.Offset, clockSnapshot),
            (TpmAlgIdConstants.TPM_ALG_ECC, TpmAlgIdConstants.TPM_ALG_ECDSA) =>
                new TpmNvCertifyAction(
                    signer.Name, signer.Hierarchy, request.QualifyingData, signer.PrivateKey, signer.Curve, request.SignatureScheme, request.SchemeHashAlg,
                    index.NvIndex, index.NameAlg, index.Attributes, index.AuthPolicy, index.DataSize, window, request.Offset, clockSnapshot),
            _ => null
        };

        if(action is null)
        {
            //A scheme incompatible with the signer's key type — e.g. an ECDSA scheme against an RSA key, or vice
            //versa — fails closed rather than silently coercing to the key's native scheme (mirrors OnCertify).
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_SCHEME, request);
        }

        //The transition is both password carriers' terminal owner — the per-slot compares were their only use —
        //while the qualifying data has transferred into the action the effect releases it from.
        request.SuppliedSignPassword.Dispose();
        request.SuppliedIndexPassword.Dispose();

        return Transition(
            state with
            {
                NextAction = action,
                ResponseIntent = null
            },
            "NvCertify:Requested");
    }

    /// <summary>
    /// Frames the plain <c>TPM2_NV_Certify()</c> response the effect produced: the marshaled attestation and the
    /// signature over its digest, with no response session area (Part 3, clause 31.16.2, Table 255).
    /// </summary>
    /// <param name="state">The state to transition from.</param>
    /// <param name="certified">The effect's result carrying the marshaled attest and its signature.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> carrying the attestation response.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnNvIndexCertified(TpmSimulatorState state, TpmNvIndexCertified certified) =>
        Transition(
            state with
            {
                NextAction = NullAction.Instance,
                ResponseIntent = new TpmNvCertifyResponse(
                    TpmRcConstants.TPM_RC_SUCCESS, certified.CertifyInfo, certified.Signature)
            },
            "NvCertify:Completed");

    /// <summary>
    /// Authorizes <c>TPM2_NV_Certify()</c> whose authorization area carries at least one real session, on either
    /// arm the wire may name for the Index's read authorization — the owner hierarchy or the Index's own
    /// authValue (TPM 2.0 Library Part 3, clause 31.16; Part 1, clause 35.2.5).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The two authorization slots are handled independently, because Table 254 makes them independent:
    /// <c>@signHandle</c> is Auth Index 1 and <c>@authHandle</c> Auth Index 2, both USER role, and neither
    /// handle's authorization mechanism constrains the other's. Slot 1 may therefore be a password while slot 2
    /// is an HMAC session, or the reverse, and both forms are authorized here rather than refused as unmodelled.
    /// </para>
    /// <para>
    /// BOTH slots' authorizations are verified: the signing key's own authValue is retained on
    /// <see cref="TransientKeyState.AuthValue"/> (from the <c>inSensitive</c> its <c>TPM2_CreatePrimary()</c>
    /// carried), so a password sign slot's plaintext hmac is compared against it here, and a real sign-slot HMAC
    /// session folds it into a command HMAC verified over cpHash — the same one queue every session-authorized
    /// command routes through, now carrying up to two entries (the sign slot at index 0, the authorizing slot at
    /// index 1). A verified sign slot closes a dictionary-attack oracle: a real session's response entry is a genuine HMAC
    /// over rpHash keyed on the session key (Part 1, clause 17.6.5 equation 17), and a bound session keys it on
    /// the bound entity's authValue (clause 17.6.10), so an unverified sign slot would emit an output an attacker
    /// recomputes from a guessed authValue with no throttle — a distinguisher against a value that "receives DA
    /// protection" (clause 17.8.1's use 3). Verifying the sign slot's command HMAC makes a wrong bound-entity
    /// guess FAIL and, when the guessed entity is DA-protected, CHARGE the dictionary-attack counter (clause
    /// 17.8.7's OR: the signer's own noDA, or the bound entity's DA), exactly as the authorizing slot already
    /// does — so the oracle is closed by verification rather than by refusing the session outright.
    /// </para>
    /// <para>
    /// <see cref="ValidateSessionArea"/> runs before any authorization work (Part 3, clause 5.5 precedes clause
    /// 5.6), and admits the area's optional third slot: a companion authorizing nothing, carried for
    /// <c>decrypt</c>, <c>encrypt</c>, or <c>audit</c> alone (Part 1, clause 16.6.1, Table 9), which still
    /// presents a real command HMAC of its own and owes its own response entry. <c>decrypt</c> and
    /// <c>encrypt</c> then fail closed with <c>TPM_RC_ATTRIBUTES</c> at the claiming slot even though this
    /// command's first command parameter (<c>qualifyingData</c>) and first response parameter
    /// (<c>certifyInfo</c>) are both encryption-eligible in principle (Part 1, clause 19.1): parameter
    /// encryption is not implemented for this arm, and Part 3, clause 5.7 requires an attribute the command
    /// cannot honour be refused rather than accepted and ignored. <c>audit</c> fails closed for the same reason
    /// every other arm refuses it — no audit digest is modelled.
    /// </para>
    /// <para>
    /// Read-role gating follows the authorizing handle the wire names (Part 1, clause 35.2.5) and both arms of it
    /// are settled BEFORE any authorization work, because access control precedes authorization (Part 1, clause
    /// 14; Part 3, clause 5.6's check 7.2.2 precedes its checks 9 and 10): the owner arm is gated on
    /// <c>TPMA_NV_OWNERREAD</c>, answering <c>TPM_RC_NV_AUTHORIZATION</c>, and the Index arm on
    /// <c>TPMA_NV_AUTHREAD</c>, answering the <c>TPM_RC_AUTH_UNAVAILABLE</c> check 7.2.2 names for an
    /// authValue-based mechanism the Index does not admit — so a read-forbidden Index is refused without any
    /// credential being examined and without the dictionary-attack counter being charged. <c>OnNvCertify</c>'s
    /// all-password area applies the identical early availability gate at the identical position, so both
    /// certify arms answer a read-forbidden Index the same way regardless of authorization shape.
    /// <c>ContinueNvCertifyOverSession</c> retains its own <c>TPMA_NV_AUTHREAD</c> check
    /// (<c>TPM_RC_AUTH_UNAVAILABLE</c>) only as an unreachable fail-closed backstop: the early gate above already
    /// refuses every read-forbidden Index arm ever reaches it with. The clause's remaining arm,
    /// <c>TPMA_NV_PPREAD</c> under Platform Authorization, is not modelled: no NV command in this simulator has a
    /// platform-authorized arm on either its password or its session path, so an <c>authHandle</c> that is neither
    /// the owner hierarchy nor the Index itself answers <c>TPM_RC_AUTH_TYPE</c> — the same answer this command's
    /// password arm already gives for that case, preserved rather than diverged from.
    /// </para>
    /// <para>
    /// The sign slot's own structural gates run next, before either credential shape it can take is evaluated:
    /// the signing key's DA/Lockout gate (Part 3, clause 5.6, check 3) and its userWithAuth gate (check 7.1 —
    /// CLEAR refuses <c>TPM_RC_POLICY_FAIL</c>, uncharged, because only a policy session may then authorize the
    /// USER role), so neither a password compare nor a queued command-HMAC verification ever tests a credential
    /// against a signer no authValue-based mechanism may authorize.
    /// <c>ContinueNvCertifyOverSession</c> retains the userWithAuth check only as an unreachable fail-closed
    /// backstop, exactly like its <c>TPMA_NV_AUTHREAD</c> one.
    /// </para>
    /// <para>
    /// Dictionary-attack behaviour is mechanism-blind (Part 1, clause 17.8.1: "All uses of a DA protected
    /// authValue receive DA protection") and routed through the shared helpers rather than reimplemented: the
    /// pre-authorization Lockout-mode refusal is <see cref="IsNvIndexLockedOut"/>, and a mismatch is registered
    /// by <see cref="RejectSessionAuthFailure"/> — via <see cref="RejectNvSessionAuthFailure"/>, which first
    /// applies a PIN Index's own throttle — carrying the identical AUTH_FAIL-versus-BAD_AUTH and
    /// <c>FailedTries</c> rules the password arm's <see cref="RejectNvAuthFailure"/> applies. The owner arm keeps
    /// the permanent-entity DA exemption (clause 17.8.1), so no lockout gate binds it and no failure of it moves
    /// the counter.
    /// </para>
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_NV_Certify()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the Name-computation action, resuming directly for a password-authorized Index slot, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnNvCertifyOverSession(TpmSimulatorState state, TpmNvCertifyOverSessionRequested request)
    {
        if(!state.TransientObjects.TryGetValue(request.SignHandle, out TransientKeyState? signer))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        if(!state.NvIndexes.TryGetValue(request.NvIndex, out NvIndexState? index))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        //Both authorizing slots resolve through the one shared rule every other over-session arm uses, in the
        //order Part 3, clause 5.5, step 4 gives it: a TPM_RS_PW slot names no session table entry at all; a handle
        //that is no session handle to begin with is TPM_RC_HANDLE (step 4.1, checked on the handle's TYPE before
        //anything is looked up); a well-typed handle naming nothing loaded is TPM_RC_REFERENCE_S* (step 4.2); and
        //a loaded POLICY session on a slot only an authValue-based mechanism can satisfy is TPM_RC_AUTH_TYPE,
        //which names the kind rather than the slot. Each of the first three is blamed on the offending index.
        bool isSignSlotPassword = request.SignSessionHandle.IsPasswordSession;
        if(!TryResolveCommandSession(state, request.SignSessionHandle, sessionIndex: 0, out HmacSessionState? signSession, out TpmRcConstants signSlotRefusal))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, signSlotRefusal, request);
        }

        bool isAuthSlotPassword = request.AuthorizingSessionHandle.IsPasswordSession;
        if(!TryResolveCommandSession(state, request.AuthorizingSessionHandle, sessionIndex: 1, out HmacSessionState? authSession, out TpmRcConstants authSlotRefusal))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, authSlotRefusal, request);
        }

        //The companion slot, when the area carried one, authorizes nothing and sits at index 2 — the position
        //Table 9 reserves for encryption, decryption, or audit alone (Part 1, clause 16.6.1).
        //Whether the block arrived is a structural fact the parser settled from authorizationSize, so it is read
        //from the record rather than guessed from the handle, and it is resolved and validated for every value
        //it can hold: a handle that is not a session handle at all is TPM_RC_HANDLE and a well-typed handle
        //naming no loaded session is TPM_RC_REFERENCE_S*, both blamed on this index (Part 3, clause 5.5, step 4).
        bool hasCompanion = request.HasCompanionSlot;
        HmacSessionState? companionSession = null;
        if(hasCompanion
            && !TryResolveCommandSession(state, request.CompanionSessionHandle, sessionIndex: 2, out companionSession, out TpmRcConstants companionRefusal))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, companionRefusal, request);
        }

        //This command's area carries two authorizing slots and may carry a companion behind them, so it is the
        //caller that names every slot's handle: the once-only handle rule (Part 1, clause 16.6.3) has the most to
        //compare here.
        TpmRcConstants? sessionAreaError = ValidateSessionArea(
            request.SignSessionAttributes, firstAuthorizesEntity: true, signSession?.Symmetric ?? TpmtSymDef.Null,
            hasSecondSession: true, request.AuthorizingSessionAttributes, authSession?.Symmetric ?? TpmtSymDef.Null,
            firstCommandParameterIsEncryptable: true, firstResponseParameterIsEncryptable: true,
            auditIsSupported: false, secondAuthorizesEntity: true,
            firstSessionHandle: request.SignSessionHandle, secondSessionHandle: request.AuthorizingSessionHandle,
            hasThirdSession: hasCompanion, thirdAttributes: request.CompanionSessionAttributes,
            thirdSymmetric: companionSession?.Symmetric, thirdSessionHandle: request.CompanionSessionHandle,
            firstNonceLength: request.SignNonceCaller.Size, secondNonceLength: request.AuthorizingNonceCaller.Size,
            thirdNonceLength: request.CompanionNonceCaller.Size);
        if(sessionAreaError is TpmRcConstants sessionAreaRc)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, sessionAreaRc, request);
        }

        //Every slot that can hold a real session folded whatever entity it was bound to into its key, so each is
        //gated on its own bind side before any authorization is evaluated (Part 3, clause 11.1.1; Part 1, clause
        //17.8.3). A TPM_RS_PW slot names no session and carries no bind.
        if(signSession is not null && IsBoundSessionLockedOut(state, signSession))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        if(authSession is not null && IsBoundSessionLockedOut(state, authSession))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        if(companionSession is not null && IsBoundSessionLockedOut(state, companionSession))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        //Every structural gate the password arm applies before it evaluates an authorization, in the identical
        //order, so the two arms answer identically for every input that never reaches an authorization decision.
        //qualifyingData's own TPM2B_DATA bound is not among them on this arm: the value is still ciphertext here,
        //so the bound is applied to the RECOVERED one instead (Part 3, clause 5.7 precedes clause 5.8).
        if(!CanSign(signer.Attributes))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_KEY, request);
        }

        if(!IsSupportedAttestHashAlg(request.SchemeHashAlg))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_HASH, request);
        }

        //The TPMS_NV_DIGEST_CERTIFY_INFO form (size and offset both zero, Part 3, clause 31.16.1) stays
        //unmodelled and fail-closed on this arm too: a session authorizes the command, it does not widen what
        //the command can attest.
        if(request.Size == 0 && request.Offset == 0)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_COMMAND_CODE, request);
        }

        bool isOwnerArm = request.AuthHandle.Value == (uint)TpmRh.TPM_RH_OWNER;
        if(isOwnerArm)
        {
            //With TPMA_NV_OWNERREAD clear, owner authorization cannot read this Index (Part 1, clause 35.2.5) —
            //checked before any authorization work, the same non-leaking order OnNvReadOverSession's owner arm
            //uses.
            if(!index.IsOwnerReadAllowed)
            {
                return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_NV_AUTHORIZATION, request);
            }
        }
        else
        {
            if(request.AuthHandle.Value != request.NvIndex.Value)
            {
                return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_AUTH_TYPE, request);
            }

            //Already-locked-out DA-protected Index: refuse before the authorization is evaluated at all (Part 1,
            //clause 17.8.3; Part 3, clause 5.6's check 3 precedes its check 9).
            if(IsNvIndexLockedOut(state, index))
            {
                return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_LOCKOUT, request);
            }

            //A PIN Index's own authValue is unusable while unwritten or once pinCount has reached pinLimit
            //(Part 1, clause 35.2.6.6) — refused before it is evaluated, mirroring the password arm's own gate.
            if(IsPinAuthUnavailable(index))
            {
                return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, request);
            }

            //With TPMA_NV_AUTHREAD clear, the Index's own authValue is not an available authorization mechanism
            //for this read-role command at all (Part 1, clause 35.2.5), and access control precedes authorization:
            //Part 1, clause 14 states the requirement outright — "The TPM must check access control before
            //checking authorization. For example, it should reject a read to a read locked NV Index before doing
            //an authorization check that might trigger the dictionary attack protection" — and Part 3, clause
            //5.6's check 7.2.2 (an NV Index authorized by an HMAC session or a password needs TPMA_NV_AUTHREAD
            //SET, TPM_RC_AUTH_UNAVAILABLE) is ordered ahead of its check 9/10 credential comparison. So this arm
            //refuses HERE: before the Name hop, before any command-HMAC or password comparison, and therefore
            //before any authorization outcome can charge the dictionary-attack counter for an Index no
            //authValue-based read is permitted against in the first place. OnNvCertify's all-password area
            //applies the identical early availability gate at the identical position, so an area that returns
            //here never reaches a body whose own TPMA_NV_AUTHREAD check (ContinueNvCertifyOverSession's,
            //TPM_RC_AUTH_UNAVAILABLE) could answer instead — that check is retained only as an unreachable
            //fail-closed backstop.
            if(!index.IsAuthReadAllowed)
            {
                return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, request);
            }
        }

        //The signing key's own DA/Lockout gate (Part 3, clause 5.6, check 3): a DA-protected signer under
        //lockout is refused before either credential shape the sign slot can take is evaluated — the
        //bound-session gates above cover only each session's bind entity, not the signer itself.
        if(signer.IsDaProtected && state.IsInLockout)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        //USER role gate (Part 3, clause 5.6, check 7.1): a signer whose userWithAuth attribute is CLEAR may
        //have its USER role authorized only by a policy session — never by a password and never by an HMAC
        //session, bound or not — so this gate runs before the inline compare below AND before any sign-slot
        //command HMAC is queued via the Name hop, uncharged, per clause 5.6's mandatory check order.
        //ContinueNvCertifyOverSession retains the same check as an unreachable fail-closed backstop.
        if((signer.Attributes & TpmaObject.USER_WITH_AUTH) == 0)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_POLICY_FAIL, request);
        }

        //The sign slot (session index 0) authorizes the signing key, a USER-role authorization (Part 3, clause
        //31.16's @signHandle). A password sign slot's hmac field IS the plaintext authValue (Part 1, clause
        //17.6.4.1), compared here against the signing key's OWN authValue and charged to the dictionary-attack
        //counter when that key is DA-protected (clause 17.8.1); a real HMAC sign slot instead owes a command
        //HMAC over cpHash, verified after the Name hop, where a wrong bound-entity guess fails verification and
        //is throttled — which is what closes the dictionary-attack oracle by verification rather than by refusal.
        if(isSignSlotPassword
            && !CryptographicOperations.FixedTimeEquals(StripTrailingZeros(request.SuppliedSignHmac.AsReadOnlySpan()), StripTrailingZeros(signer.AuthValue.AsReadOnlySpan())))
        {
            return RejectSessionAuthFailure(state, TpmCcConstants.TPM_CC_NV_Certify, sessionIndex: 0, signer.IsDaProtected, request);
        }

        //The Index/owner authorization slot (session index 1). A password slot's hmac field is likewise the
        //plaintext authValue, compared inline here since a password authorization computes no cpHash (Part 1,
        //clause 17.6.4.1): the owner hierarchy's authValue is DA-exempt (clause 17.8.1), so its mismatch is a
        //plain bad authorization moving no counter, while an Index slot's mismatch charges the counter and, for a
        //PIN Index, owns the FAILURE side of the once-per-authorization pinCount update (clause 35.2.6.6) whose
        //success side is ContinueNvCertifyOverSession's. A real HMAC auth slot instead owes a command HMAC,
        //verified after the Name hop.
        if(isAuthSlotPassword)
        {
            if(isOwnerArm)
            {
                if(!CryptographicOperations.FixedTimeEquals(StripTrailingZeros(request.SuppliedAuthorizingHmac.AsReadOnlySpan()), StripTrailingZeros(state.OwnerAuth.AsReadOnlySpan())))
                {
                    return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 1), request);
                }
            }
            else if(!CryptographicOperations.FixedTimeEquals(StripTrailingZeros(request.SuppliedAuthorizingHmac.AsReadOnlySpan()), StripTrailingZeros(index.AuthValue.AsReadOnlySpan())))
            {
                if(index.IsPinIndex)
                {
                    index = ApplyPinAuthOutcome(index, authMatched: false);
                    state = state with { NvIndexes = state.NvIndexes.SetItem(index.NvIndex, index) };
                }

                return RejectSessionAuthFailure(state, TpmCcConstants.TPM_CC_NV_Certify, sessionIndex: 1, index.IsDaProtected, request);
            }
        }

        //Any real session in the area still owes a command-HMAC verification over cpHash, whose Name3 term (and,
        //on the Index arm, its Name2 term) is the Index's computed Name (Part 1, clause 16.7 equation 15): route
        //through the Name hop, where ContinueNvCertifyNameComputed queues one verification per real slot — the
        //sign slot at index 0, the authorizing slot at index 1, the companion at index 2. Both password slots
        //have already matched above, so a both-password area with no companion skips the hop and attests
        //directly; a companion behind them owes an HMAC of its own and so needs the hop.
        if(!isSignSlotPassword || !isAuthSlotPassword || hasCompanion)
        {
            return Transition(
                state with
                {
                    NextAction = new TpmComputeNvIndexNameAction(index.NvIndex, index.NameAlg, index.Attributes, index.AuthPolicy, index.DataSize, request),
                    ResponseIntent = null
                },
                isOwnerArm ? "NvCertify:OverSession:OwnerNameRequested" : "NvCertify:OverSession:IndexNameRequested");
        }

        return ContinueNvCertifyOverSession(state, request);
    }

    /// <summary>
    /// Builds cpHash's three-Name handle area and declares the command-HMAC verification for
    /// <c>TPM2_NV_Certify()</c> once the Index's Name has been computed (TPM 2.0 Library Part 1, clause 16.7
    /// equation 15; clause 17.6.10 equations 21/22).
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the only NV continuation that builds a <c>Name1 ‖ Name2 ‖ Name3</c> area, because
    /// <c>TPM2_NV_Certify()</c> is the only NV command with three handles (Part 3, clause 31.16.2, Table 254).
    /// The terms follow the command's own handle order: Name1 is the signing key's Name, Name2 is the
    /// authorizing entity's — the owner hierarchy's raw 4-octet handle value, or the Index's computed Name on
    /// the Index arm (Part 1, clause 14, Table 6) — and Name3 is always the Index's computed Name.
    /// </para>
    /// <para>
    /// The verification queue holds ONE entry per REAL session slot (a password slot was compared inline in
    /// <c>OnNvCertifyOverSession</c> and is not queued), in wire session order: the sign slot at index 0, the
    /// authorizing slot at index 1. Both verifications HMAC over the identical cpHash; <c>OnCommandHmacVerified</c>
    /// advances the queue and, on any mismatch, blames the offending index and takes the dictionary-attack
    /// decision from that slot's own <c>IsDaProtected</c>/<c>IsLockoutEntity</c>. Each slot's bind-omission
    /// (equation 22) is resolved here, once — the sign slot against the signer's own Name, the authorizing slot
    /// against either recorded bind-Name form (for the same two-form reason <c>OnNvIndexNameComputed</c> accepts
    /// both: this model records a bound NV Index's Name as its raw handle) — and threaded onward via
    /// <c>ResolvedSignAuthValue</c>/<c>ResolvedAuthValue</c> so each response HMAC reuses its identical key
    /// (clause 17.6.5). The nonce fold (clause 17.6.3.4) applies to the FIRST slot alone, and only where another
    /// slot carries a parameter-encryption attribute: the sign slot's verification then also covers the decrypt
    /// session's nonceTPM and the encrypt session's, in that order and each once (clause 17.6.5, equation 17), so
    /// removing such a session from the wire breaks the sign slot's HMAC.
    /// </para>
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="indexName">The Index's computed Name, TRANSFERRED onto <paramref name="request"/> so it outlives this transition and can be laid out into cpHash by the verifying effect.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_NV_Certify()</c> request to resume.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the command-HMAC verification.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> ContinueNvCertifyNameComputed(
        TpmSimulatorState state, Tpm2bName indexName, TpmNvCertifyOverSessionRequested request)
    {
        TransientKeyState signer = state.TransientObjects[request.SignHandle];

        bool isOwnerArm = request.AuthHandle.Value == (uint)TpmRh.TPM_RH_OWNER;
        bool isSignSlotPassword = request.SignSessionHandle.IsPasswordSession;
        bool isAuthSlotPassword = request.AuthorizingSessionHandle.IsPasswordSession;

        //The handle-Name area is cpHash's Name1..3 (Part 1, clause 16.7 equation 15) — Name1 the signing key's,
        //Name2 the authorizing entity's (the owner hierarchy's raw handle value, which IS its Name, or the
        //Index's computed Name), Name3 the Index's Name — and both slots' command HMACs verify over the
        //identical cpHash.
        TpmHandleName name2 = isOwnerArm ? TpmHandleName.FromHandle(request.AuthHandle.Value) : TpmHandleName.FromName(indexName);
        TpmCommandHandleNames handleNames = TpmCommandHandleNames.Of(TpmHandleName.FromName(signer.Name), name2, TpmHandleName.FromName(indexName));

        //One pending verification per REAL session slot, in wire session order (the sign slot at index 0, the
        //authorizing slot at index 1); a password slot was compared inline in OnNvCertifyOverSession and is not
        //queued. Trailing zeros are removed from an authValue where it is used in an authorization computation
        //(Part 1, clause 17.6.4.3): the bind folds and the HMAC primitive each take the stripped view of the
        //borrowed carrier.
        //Which slot decrypts qualifyingData and which encrypts the TPM2B_ATTEST, in area order (Part 3, clause
        //31.16.2, Tables 254 and 255: both are the first parameter of their direction and both TPM2B). The
        //area-level gates in OnNvCertifyOverSession have already refused a second claimer of either.
        ReadOnlySpan<TpmaSession> allSlotAttributes = [request.SignSessionAttributes, request.AuthorizingSessionAttributes, request.CompanionSessionAttributes];
        ReadOnlySpan<TpmaSession> slotAttributes = allSlotAttributes[..(request.HasCompanionSlot ? 3 : 2)];
        ReadOnlySpan<HmacSessionState?> slotSessions =
        [
            isSignSlotPassword ? null : state.HmacSessions[TpmiShHmac.FromValue(request.SignSessionHandle.Value)],
            isAuthSlotPassword ? null : state.HmacSessions[TpmiShHmac.FromValue(request.AuthorizingSessionHandle.Value)],
            request.HasCompanionSlot ? state.HmacSessions[TpmiShHmac.FromValue(request.CompanionSessionHandle.Value)] : null
        ];
        (Tpm2bNonce foldedNonceDecrypt, Tpm2bNonce foldedNonceEncrypt) = FoldedSessionNonces(
            slotSessions, FindClaimingSlot(slotAttributes, TpmaSession.DECRYPT), FindClaimingSlot(slotAttributes, TpmaSession.ENCRYPT));

        var pendings = ImmutableArray.CreateBuilder<TpmPendingSessionVerification>(2);
        Tpm2bAuth? resolvedSignAuthValue = null;
        Tpm2bAuth? resolvedAuthValue = null;

        //Sign slot (Auth Index 0): folds the signing key's OWN authValue, omitted (equation 22) when the session
        //was bound to the signer itself. A wrong bound-entity guess fails this verification and is charged
        //(clause 17.8.7's OR: the signer's own noDA, or the bound entity's DA) — the dictionary-attack oracle closed by
        //verification. The response HMAC reuses the same resolved value (clause 17.6.5) via ResolvedSignAuthValue.
        if(!isSignSlotPassword)
        {
            HmacSessionState signSession = state.HmacSessions[TpmiShHmac.FromValue(request.SignSessionHandle.Value)];
            ReadOnlySpan<byte> strippedSignerAuthValue = StripTrailingZeros(signer.AuthValue.AsReadOnlySpan());
            bool signBindOmits = signSession.BoundEntity.Matches(signer.Name.Span, strippedSignerAuthValue);
            Tpm2bAuth signAuthForHmac = signBindOmits ? Tpm2bAuth.Empty : signer.AuthValue;
            resolvedSignAuthValue = signAuthForHmac;

            pendings.Add(new TpmPendingSessionVerification(
                SessionHandle: TpmiShAuthSession.FromValue(signSession.Handle.Value), SessionIndex: 0, SessionAlg: signSession.SessionAlg, SessionKey: signSession.SessionKey,
                AuthValue: signAuthForHmac, IsDaProtected: signer.IsDaProtected || signSession.IsBoundEntityDaProtected,
                NonceCaller: request.SignNonceCaller, NonceTpm: signSession.NonceTpm, FoldedNonceDecrypt: foldedNonceDecrypt, FoldedNonceEncrypt: foldedNonceEncrypt,
                SessionAttributes: request.SignSessionAttributes, SuppliedHmac: request.SuppliedSignHmac,
                IsLockoutEntity: signSession.IsBoundToLockout));
        }

        //Authorizing slot (Auth Index 1): folds the owner hierarchy's or the Index's live authValue, omitted
        //against either recorded bind-Name form (Part 4, IsSessionBindEntity), for the same two-form reason
        //OnNvIndexNameComputed accepts both. clause 17.8.7's OR: the authorized entity (the Index; the owner
        //hierarchy is DA-exempt per clause 17.8.1) or the bound entity.
        if(!isAuthSlotPassword)
        {
            HmacSessionState session = state.HmacSessions[TpmiShHmac.FromValue(request.AuthorizingSessionHandle.Value)];
            Tpm2bAuth entityAuthValue = isOwnerArm ? state.OwnerAuth : state.NvIndexes[request.NvIndex].AuthValue;
            ReadOnlySpan<byte> strippedEntityAuthValue = StripTrailingZeros(entityAuthValue.AsReadOnlySpan());
            bool bindOmits = (!isOwnerArm && session.BoundEntity.Matches(indexName.Span, strippedEntityAuthValue))
                || MatchesHandleFormBoundEntity(session.BoundEntity, request.AuthHandle.Value, strippedEntityAuthValue);
            Tpm2bAuth authValueForHmac = bindOmits ? Tpm2bAuth.Empty : entityAuthValue;
            resolvedAuthValue = authValueForHmac;

            bool isDaProtected = (!isOwnerArm && state.NvIndexes[request.NvIndex].IsDaProtected) || session.IsBoundEntityDaProtected;

            pendings.Add(new TpmPendingSessionVerification(
                SessionHandle: TpmiShAuthSession.FromValue(session.Handle.Value), SessionIndex: 1, SessionAlg: session.SessionAlg, SessionKey: session.SessionKey,
                AuthValue: authValueForHmac, IsDaProtected: isDaProtected, NonceCaller: request.AuthorizingNonceCaller, NonceTpm: session.NonceTpm,
                FoldedNonceDecrypt: Tpm2bNonce.Empty, FoldedNonceEncrypt: Tpm2bNonce.Empty, SessionAttributes: request.AuthorizingSessionAttributes, SuppliedHmac: request.SuppliedAuthorizingHmac,
                IsLockoutEntity: session.IsBoundToLockout));
        }

        //Companion slot (index 2): it authorizes no entity, so its HMAC key folds no authValue and its
        //dictionary-attack standing comes from its own bind alone (Part 1, clause 17.8.1). It still owes a
        //command HMAC over the identical cpHash (Part 3, clause 5.6 applies to every session in the area).
        if(request.HasCompanionSlot)
        {
            HmacSessionState companionSession = state.HmacSessions[TpmiShHmac.FromValue(request.CompanionSessionHandle.Value)];

            pendings.Add(new TpmPendingSessionVerification(
                SessionHandle: TpmiShAuthSession.FromValue(companionSession.Handle.Value), SessionIndex: 2, SessionAlg: companionSession.SessionAlg, SessionKey: companionSession.SessionKey,
                AuthValue: Tpm2bAuth.Empty, IsDaProtected: companionSession.IsBoundEntityDaProtected,
                NonceCaller: request.CompanionNonceCaller, NonceTpm: companionSession.NonceTpm,
                FoldedNonceDecrypt: Tpm2bNonce.Empty, FoldedNonceEncrypt: Tpm2bNonce.Empty,
                SessionAttributes: request.CompanionSessionAttributes, SuppliedHmac: request.SuppliedCompanionHmac,
                IsLockoutEntity: companionSession.IsBoundToLockout));
        }

        ImmutableArray<TpmPendingSessionVerification> queue = pendings.ToImmutable();

        return Transition(
            state with
            {
                NextAction = new TpmVerifyCommandHmacAction(
                    TpmCcConstants.TPM_CC_NV_Certify, handleNames, request.RawParameterArea, queue[0], queue.RemoveAt(0),
                    request with { ResolvedAuthValue = resolvedAuthValue, ResolvedSignAuthValue = resolvedSignAuthValue, ResolvedIndexName = indexName }),
                ResponseIntent = null
            },
            "NvCertify:OverSession:HmacVerifyRequested");
    }

    /// <summary>
    /// Resumes <c>TPM2_NV_Certify()</c> once the Index's authorization has been proven — by a verified command
    /// HMAC, or by the password compare <c>OnNvCertifyOverSession</c> performed for a password-authorized Index
    /// slot — and declares the attestation, carrying the response-session list the framing step needs (TPM 2.0
    /// Library Part 3, clause 31.16).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every gate here is the password arm's, in the password arm's order, because none of them conditions the
    /// authorization: a PIN Index's success-side pinCount update (Part 1, clause 35.2.6.6), the Index arm's
    /// <c>TPMA_NV_AUTHREAD</c> gate (clause 35.2.5, checked after the authorization exactly as
    /// <c>ContinueNvReadOverSession</c> checks it), the unwritten-Index refusal
    /// (<c>TPM_RC_NV_UNINITIALIZED</c>, clause 31.16.1), and the window bound against the retained written
    /// extent (<c>TPM_RC_NV_RANGE</c>). What the attestation itself contains is untouched by the arm: the
    /// Index's real Name, the requested window, and the caller's qualifyingData, exactly as the password arm
    /// attests them.
    /// </para>
    /// <para>
    /// This continuation is the SINGLE success-side owner of the pinCount update for both shapes the Index slot
    /// can take, so one authorization moves the counter once (clause 35.2.6.6): an HMAC-authorized Index slot
    /// arrives here once its command HMAC verified, and a password-authorized one once
    /// <c>OnNvCertifyOverSession</c>'s compare matched, neither of them having touched pinCount on the way. The
    /// failure side has two owners for the same reason, one per shape — <see cref="RejectNvSessionAuthFailure"/>
    /// for a mismatching HMAC (a mismatch never reaches this continuation at all, since
    /// <c>OnCommandHmacVerified</c> short-circuits before <c>NextRequest</c> dispatch) and
    /// <c>OnNvCertifyOverSession</c>'s own inline update for a mismatching password.
    /// </para>
    /// <para>
    /// The <c>TPMA_NV_AUTHREAD</c> check here is a fail-closed backstop, never the answer a caller actually
    /// sees: <c>OnNvCertifyOverSession</c>'s own early availability gate — the identical gate, at the identical
    /// early position, that <c>OnNvCertify</c>'s all-password area now applies too — already refuses a
    /// read-forbidden Index with <c>TPM_RC_AUTH_UNAVAILABLE</c> (Part 1, clause 35.2.5; Part 3, clause 5.6's
    /// check 7.2.2) before any authorization work, so no authorization work — and hence no dictionary-attack
    /// charge — happens for such an Index on either arm, and this continuation's own check can never be reached
    /// with a read-forbidden Index in practice.
    /// </para>
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_NV_Certify()</c> request, its Index authorization now proven.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the decryption step.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> ContinueNvCertifyOverSession(TpmSimulatorState state, TpmNvCertifyOverSessionRequested request)
    {
        ReadOnlySpan<TpmaSession> allSlotAttributes = [request.SignSessionAttributes, request.AuthorizingSessionAttributes, request.CompanionSessionAttributes];
        ReadOnlySpan<TpmaSession> slotAttributes = allSlotAttributes[..(request.HasCompanionSlot ? 3 : 2)];
        int decryptIndex = FindClaimingSlot(slotAttributes, TpmaSession.DECRYPT);

        //The decrypt slot's own authorized entity supplies the cipher key's authValue term, UNRESOLVED by the
        //session's bind (Part 1, clause 19.1): the signing key's for slot 0, the owner hierarchy's or the Index's
        //for slot 1 — whichever @authHandle named — and none for a companion.
        (HmacSessionState? Session, Tpm2bAuth EntityAuthValue, Tpm2bNonce NonceCaller) decrypt = decryptIndex switch
        {
            0 => (state.HmacSessions[TpmiShHmac.FromValue(request.SignSessionHandle.Value)], state.TransientObjects[request.SignHandle].AuthValue, request.SignNonceCaller),
            1 => (state.HmacSessions[TpmiShHmac.FromValue(request.AuthorizingSessionHandle.Value)],
                request.AuthHandle.Value == (uint)TpmRh.TPM_RH_OWNER ? state.OwnerAuth : state.NvIndexes[request.NvIndex].AuthValue,
                request.AuthorizingNonceCaller),
            2 => (state.HmacSessions[TpmiShHmac.FromValue(request.CompanionSessionHandle.Value)], Tpm2bAuth.Empty, request.CompanionNonceCaller),
            _ => (null, Tpm2bAuth.Empty, Tpm2bNonce.Empty)
        };

        return DeclareAttestQualifyingDataDecryption(
            state, TpmCcConstants.TPM_CC_NV_Certify, request, request.RawParameterArea, decryptIndex,
            decrypt.Session, decrypt.EntityAuthValue, decrypt.NonceCaller, "NvCertify:OverSession:QualifyingDataDecryptRequested");
    }

    /// <summary>
    /// Runs the session-authorized <c>TPM2_NV_Certify()</c> ladder once <c>qualifyingData</c> has been recovered
    /// (TPM 2.0 Library Part 3, clause 31.16), declaring the attestation with the response-session list the
    /// framing step needs.
    /// </summary>
    /// <remarks>
    /// <c>qualifyingData</c>'s own <c>TPM2B_DATA</c> width bound is applied here rather than in
    /// <c>OnNvCertifyOverSession</c> alongside the other structural gates, because on this arm the value is still
    /// ciphertext there — the decrypt step, which answers the bound first, is what makes a plaintext exist at all.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_NV_Certify()</c> request, carrying the recovered qualifying data.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the attestation action, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> CompleteNvCertifyOverSession(TpmSimulatorState state, TpmNvCertifyOverSessionRequested request)
    {
        TransientKeyState signer = state.TransientObjects[request.SignHandle];
        NvIndexState index = state.NvIndexes[request.NvIndex];
        bool isIndexArm = request.AuthHandle.Value == request.NvIndex.Value;

        //Fail-closed backstop for the sign slot's USER role gate (Part 3, clause 5.6, check 7.1):
        //OnNvCertifyOverSession refuses a userWithAuth-CLEAR signer before any sign-slot credential is
        //evaluated or queued, so this repeat can never be reached; placed before the pinCount update below so
        //that even an unreachable arrival moves no state.
        if((signer.Attributes & TpmaObject.USER_WITH_AUTH) == 0)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_POLICY_FAIL, request);
        }

        //Fail-closed backstop for qualifyingData's TPM2B_DATA width bound (Part 2, clause 10.4.3, Table 93),
        //which the decrypt step answers first on the recovered value; likewise before the pinCount update.
        if(request.QualifyingData.Length > Tpm2bData.MaxSize)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_SIZE, request);
        }

        if(isIndexArm && index.IsPinIndex)
        {
            index = ApplyPinAuthOutcome(index, authMatched: true);
            state = state with { NvIndexes = state.NvIndexes.SetItem(index.NvIndex, index) };
        }

        if(isIndexArm && !index.IsAuthReadAllowed)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, request);
        }

        if(!index.IsWritten)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_NV_UNINITIALIZED, request);
        }

        //The model retains only the octets actually written, so — as the password arm already does — the bound
        //checked here is the retained written extent, not the Index's full declared dataSize.
        if((long)request.Offset + request.Size > index.Data.Length)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_NV_RANGE, request);
        }

        //"The implementation may return an error (TPM_RC_VALUE) if it performs an additional check and
        //determines that offset is greater than the dataSize field of the NV Index, or if size is greater than
        //MAX_NV_BUFFER_SIZE" (Part 3, clause 31.16.1). The certified content rides a TPM2B_MAX_NV_BUFFER inside
        //TPMS_NV_CERTIFY_INFO (Part 2, clause 10.12.8, Table 147), whose Table 99 bound this library fixes at
        //Tpm2bMaxNvBuffer.MaxSize and reports through TPM_PT_NV_BUFFER_MAX. The clause states the range rule as
        //a "shall" and this one as the additional check, and the reference's own TPM2_NV_Certify runs them in
        //that same order, so a window that is both out of range and over the bound answers TPM_RC_NV_RANGE.
        if(request.Size > Tpm2bMaxNvBuffer.MaxSize)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_VALUE, request);
        }

        //The certified window is a live view of the Index's own pooled area — borrowed, never copied — carried
        //across the signing effect, which is safe because the automaton processes one command at a time: no
        //store can reach the area between this slice and the attestation being signed over it, and the Index
        //remains the area's only owner throughout.
        ReadOnlyMemory<byte> window = index.Data.AsReadOnlyMemory().Slice(request.Offset, request.Size);
        TpmsClockInfo clockSnapshot = new(state.Clock, state.ResetCount, state.RestartCount, state.ClockSafe);
        ImmutableArray<TpmAttestResponseSession> responseSessions = BuildNvCertifyResponseSessions(state, request);

        TpmAction? action = (signer.KeyType.Value, request.SignatureScheme.Value) switch
        {
            (TpmAlgIdConstants.TPM_ALG_RSA, TpmAlgIdConstants.TPM_ALG_RSASSA or TpmAlgIdConstants.TPM_ALG_RSAPSS) =>
                new TpmRsaNvCertifyAction(
                    signer.Name, signer.Hierarchy, request.QualifyingData, signer.PrivateKey, request.SignatureScheme, request.SchemeHashAlg,
                    index.NvIndex, index.NameAlg, index.Attributes, index.AuthPolicy, index.DataSize, window, request.Offset, clockSnapshot, responseSessions),
            (TpmAlgIdConstants.TPM_ALG_ECC, TpmAlgIdConstants.TPM_ALG_ECDSA) =>
                new TpmNvCertifyAction(
                    signer.Name, signer.Hierarchy, request.QualifyingData, signer.PrivateKey, signer.Curve, request.SignatureScheme, request.SchemeHashAlg,
                    index.NvIndex, index.NameAlg, index.Attributes, index.AuthPolicy, index.DataSize, window, request.Offset, clockSnapshot, responseSessions),
            _ => null
        };

        if(action is null)
        {
            //A scheme incompatible with the signer's key type fails closed rather than silently coercing to the
            //key's native scheme, mirroring the password arm.
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_SCHEME, request);
        }

        //This continuation is every supplied-credential carrier's, the parameter area's and the Index Name's
        //terminal owner — each slot's verification was their only use — while each slot's caller nonce has
        //transferred into that slot's response-session entry and the qualifying data into the action, all of
        //which the effect releases.
        request.SuppliedSignHmac.Dispose();
        request.SuppliedAuthorizingHmac.Dispose();
        request.SuppliedCompanionHmac.Dispose();
        request.RawParameterArea.Dispose();
        request.ResolvedIndexName.Dispose();

        return Transition(
            state with
            {
                NextAction = action,
                ResponseIntent = null
            },
            "NvCertify:OverSession:AttestRequested");
    }

    /// <summary>
    /// Resolves what each of <c>TPM2_NV_Certify()</c>'s two authorization slots is owed in the response session
    /// area, in command-session order (TPM 2.0 Library Part 1, clause 16.6.1): a <c>TPM_RS_PW</c> slot's
    /// placeholder, or a real session's key material for a genuine rolled-nonce entry.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Each real slot's entity term is the bind-omission-resolved value its own command HMAC used (clause
    /// 17.6.5), so its response HMAC keys on the identical <c>sessionKey ‖ authValue</c>: the sign slot's from
    /// <see cref="TpmNvCertifyOverSessionRequested.ResolvedSignAuthValue"/> (the signing key's own authValue, or
    /// empty when the session was bound to the signer), the authorizing slot's from
    /// <see cref="TpmNvCertifyOverSessionRequested.ResolvedAuthValue"/> — each empty when that slot was a
    /// password and so keyed nothing. A password slot's response attributes are the unconditionally SET
    /// <c>continueSession</c> the TPM returns for one (Part 2, clause 8.4, Table 40: "Has no meaning for a
    /// password session — the TPM allows any setting in the command, SETs it in the response"), never an echo of
    /// whatever the command carried.
    /// </para>
    /// </remarks>
    /// <param name="state">The state the sessions are resolved against.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_NV_Certify()</c> request.</param>
    /// <returns>Every slot's response-session material, in command-session order.</returns>
    private static ImmutableArray<TpmAttestResponseSession> BuildNvCertifyResponseSessions(TpmSimulatorState state, TpmNvCertifyOverSessionRequested request)
    {
        var sessions = ImmutableArray.CreateBuilder<TpmAttestResponseSession>(3);

        sessions.Add(request.SignSessionHandle.IsPasswordSession
            ? AttestPasswordPlaceholderSession(request.SignSessionHandle.Value, request.SignNonceCaller)
            : AttestRealResponseSession(
                state.HmacSessions[TpmiShHmac.FromValue(request.SignSessionHandle.Value)], request.ResolvedSignAuthValue ?? Tpm2bAuth.Empty,
                state.TransientObjects[request.SignHandle].AuthValue, request.SignNonceCaller, request.SignSessionAttributes,
                encrypts: (request.SignSessionAttributes & TpmaSession.ENCRYPT) != 0));

        sessions.Add(request.AuthorizingSessionHandle.IsPasswordSession
            ? AttestPasswordPlaceholderSession(request.AuthorizingSessionHandle.Value, request.AuthorizingNonceCaller)
            : AttestRealResponseSession(
                state.HmacSessions[TpmiShHmac.FromValue(request.AuthorizingSessionHandle.Value)], request.ResolvedAuthValue ?? Tpm2bAuth.Empty,
                request.AuthHandle.Value == (uint)TpmRh.TPM_RH_OWNER ? state.OwnerAuth : state.NvIndexes[request.NvIndex].AuthValue,
                request.AuthorizingNonceCaller, request.AuthorizingSessionAttributes,
                encrypts: (request.AuthorizingSessionAttributes & TpmaSession.ENCRYPT) != 0));

        if(request.HasCompanionSlot)
        {
            sessions.Add(AttestRealResponseSession(
                state.HmacSessions[TpmiShHmac.FromValue(request.CompanionSessionHandle.Value)], Tpm2bAuth.Empty, Tpm2bAuth.Empty, request.CompanionNonceCaller, request.CompanionSessionAttributes,
                encrypts: (request.CompanionSessionAttributes & TpmaSession.ENCRYPT) != 0));
        }

        return sessions.ToImmutable();
    }

    /// <summary>
    /// Declares the step that recovers an attest command's <c>qualifyingData</c> in plaintext — the one shape
    /// shared by <c>TPM2_Certify()</c>, <c>TPM2_CertifyCreation()</c>, <c>TPM2_Quote()</c>, <c>TPM2_GetTime()</c>,
    /// and <c>TPM2_NV_Certify()</c>, which differ only in which slot may carry the <c>decrypt</c> attribute and
    /// whose authValue that slot folds.
    /// </summary>
    /// <remarks>
    /// Reached only from a continuation, never from an entry transition: cpHash covers the CIPHERTEXT (TPM 2.0
    /// Library Part 1, clause 19.1), so every session's command HMAC must have verified before the parameter is
    /// touched (Part 3, clause 5.6 precedes clause 5.7). A caller that sent plaintext takes the same path with
    /// <paramref name="decryptSession"/> <see langword="null"/>, so the recovered value has one origin whatever
    /// the area claimed.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="commandCode">The attest command being resumed.</param>
    /// <param name="request">The parsed session-authorized request, threaded through to the resuming transition.</param>
    /// <param name="rawParameterArea">The parameter-area carrier captured at parse time, which the transform mutates in place; a borrow of the request's own carrier.</param>
    /// <param name="decryptIndex">The zero-based slot claiming <c>decrypt</c>, or <c>-1</c>; a failure of the step is session-index-encoded to it.</param>
    /// <param name="decryptSession">The claiming slot's session, or <see langword="null"/> when no slot claimed the attribute.</param>
    /// <param name="entityAuthValue">The authValue of the entity that slot authorizes, unresolved by its bind, or the shared empty carrier for a companion.</param>
    /// <param name="nonceCaller">That slot's caller nonce for this command — the decryption's nonceNewer (Part 1, clause 19.2); a borrow of the request's own carrier.</param>
    /// <param name="label">The transition label naming the command.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the decryption step.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> DeclareAttestQualifyingDataDecryption(
        TpmSimulatorState state, TpmCcConstants commandCode, TpmSimulatorInput request, TpmParameterArea rawParameterArea,
        int decryptIndex, HmacSessionState? decryptSession, Tpm2bAuth entityAuthValue, Tpm2bNonce nonceCaller, string label)
    {
        bool decrypts = decryptSession is not null;

        return Transition(
            state with
            {
                NextAction = new TpmDecryptAttestQualifyingDataAction(
                    commandCode, request, rawParameterArea, decrypts, decryptIndex,
                    decrypts ? decryptSession!.SessionAlg : TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_NULL),
                    decrypts ? decryptSession!.Symmetric : TpmtSymDef.Null,
                    decrypts ? decryptSession!.SessionKey : TpmSimulatorState.EmptySessionKey,
                    decrypts ? entityAuthValue : Tpm2bAuth.Empty,
                    decrypts ? nonceCaller : Tpm2bNonce.Empty,
                    decrypts ? decryptSession!.NonceTpm : Tpm2bNonce.Empty),
                ResponseIntent = null
            },
            label);
    }

    /// <summary>
    /// Resumes an attest command once its <c>qualifyingData</c> has been recovered in plaintext: adopts the
    /// recovered carrier into the request and runs that command's own remaining ladder (TPM 2.0 Library Part 3,
    /// clause 5.8's unmarshaling and the per-command clause behind it).
    /// </summary>
    /// <remarks>
    /// A failure of the decryption step is session-index-encoded to the slot that claimed the attribute, because
    /// that is the slot whose keying made the failure surface (Part 2, clause 6.6.2; the reference blames the
    /// decrypt session's own index), and reported bare when no slot claimed it and there is nothing to blame. A
    /// refusing arm releases the recovered carrier and the request's own through the feedback's
    /// <see cref="IDisposable.Dispose"/>; the accepted arm hands both on to the per-command ladder, which owns
    /// them from there.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="decrypted">The effect's result carrying the recovered qualifying data and the request to resume.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> from the per-command ladder, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnAttestQualifyingDataDecrypted(TpmSimulatorState state, TpmAttestQualifyingDataDecrypted decrypted)
    {
        if(decrypted.ResponseCode != TpmRcConstants.TPM_RC_SUCCESS)
        {
            TpmRcConstants responseCode = decrypted.DecryptSessionIndex >= 0
                ? SessionEncodedRc(decrypted.ResponseCode, decrypted.DecryptSessionIndex)
                : decrypted.ResponseCode;

            return Reject(state, decrypted.CommandCode, responseCode, decrypted);
        }

        return decrypted.Request switch
        {
            TpmQuoteOverSessionRequested quote => CompleteQuoteOverSession(state, quote with { QualifyingData = decrypted.QualifyingData }),
            TpmCertifyCreationOverSessionRequested certifyCreation => CompleteCertifyCreationOverSession(state, certifyCreation with { QualifyingData = decrypted.QualifyingData }),
            TpmCertifyOverSessionRequested certify => CompleteCertifyOverSession(state, certify with { QualifyingData = decrypted.QualifyingData }),
            TpmGetTimeOverSessionRequested getTime => CompleteGetTimeOverSession(state, getTime with { QualifyingData = decrypted.QualifyingData }),
            TpmNvCertifyOverSessionRequested nvCertify => CompleteNvCertifyOverSession(state, nvCertify with { QualifyingData = decrypted.QualifyingData }),
            _ => throw new System.InvalidOperationException($"No attest ladder is defined for '{decrypted.Request.GetType().Name}'.")
        };
    }

    /// <summary>
    /// The response-session marker for a <c>TPM_RS_PW</c> slot of an attest command: an entry the framing step
    /// emits as an empty nonceTPM, the SET <c>continueSession</c> attribute, and an empty HMAC (TPM 2.0 Library
    /// Part 2, clause 8.4, Table 40).
    /// </summary>
    /// <remarks>
    /// A password slot never encrypts: it has no session key to derive a keystream from, which is why the
    /// <c>encrypt</c> attribute is "required to be CLEAR in a password session" (Part 1, clause 16.6.4, Table
    /// 12; Part 2, clause 8.4, Table 40 carries the bit's own layout). So the entry claims no encryption and
    /// names no symmetric definition.
    /// </remarks>
    /// <param name="sessionHandle">The slot's <c>TPM_RS_PW</c> handle, carried so the entry stays identifiable in command-session order.</param>
    /// <param name="nonceCaller">
    /// The slot's own command caller nonce, TRANSFERRED out of the request record into this entry. Nothing in the
    /// framing reads it — a placeholder computes no HMAC — but a password slot may still present a non-empty
    /// <c>nonceCaller</c> on the wire (Part 1, clause 17.6.4.1 constrains what a password authorization MEANS, not
    /// what its <c>TPMS_AUTH_COMMAND</c> may carry), and the entry owning it is what lets the attest effect's one
    /// uniform release cover every slot of a mixed authorization area.
    /// </param>
    /// <returns>The placeholder marker.</returns>
    private static TpmAttestResponseSession AttestPasswordPlaceholderSession(uint sessionHandle, Tpm2bNonce nonceCaller) =>
        new(IsPasswordPlaceholder: true, TpmiShAuthSession.FromValue(sessionHandle), TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_NULL),
            TpmSimulatorState.EmptySessionKey, Tpm2bAuth.Empty, Tpm2bAuth.Empty, nonceCaller, TpmaSession.CONTINUE_SESSION,
            Encrypts: false, TpmtSymDef.Null);

    /// <summary>
    /// The response-session material for a real session slot of an attest command: the session's own key, the
    /// authValue term its response HMAC is keyed with alongside it, and the nonce and attributes its entry echoes
    /// (TPM 2.0 Library Part 1, clause 16.6.1).
    /// </summary>
    /// <param name="session">The resolved session.</param>
    /// <param name="authValue">
    /// The authValue term folded into the response HMAC key alongside the session key (Part 1, clause 17.6.5
    /// equation 17) — the slot's resolved entity authValue exactly as its command-side verification used it (a
    /// signing key's or certified object's retained authValue, an NV Index's authValue, or a hierarchy's), or the
    /// dispose-immune empty sentinel when the slot folds no term (a password slot, or a session bound to the very
    /// entity it authorizes).
    /// </param>
    /// <param name="nonceCaller">
    /// The slot's command caller nonce (the response HMAC's nonceOlder), TRANSFERRED out of the request record
    /// into this entry: the framing effect reads it after this transition has returned, so the transition must not
    /// release it, and the effect that framed it is its terminal owner.
    /// </param>
    /// <param name="entityAuthValue">
    /// The authValue term the CIPHER key folds when this slot is the encrypting one — the authorized entity's
    /// LIVE value, unresolved by the session's bind, because parameter encryption ignores the binding (Part 1,
    /// clause 19.1) where the response HMAC key in <paramref name="authValue"/> keeps equation 22's omission
    /// (clause 17.6.10). The shared empty carrier for a companion, which authorizes nothing. The two terms are
    /// separate parameters precisely because they can differ for the same session.
    /// </param>
    /// <param name="sessionAttributes">The slot's command session attributes (<c>TPMA_SESSION</c>, TPM 2.0 Library Part 2, clause 8.4, Table 40), echoed into its response entry.</param>
    /// <param name="encrypts">
    /// Whether this slot is the one carrying the <c>encrypt</c> attribute, so the framing step protects the
    /// response's first parameter over it (Part 1, clause 19.1: at most one session per command may). The
    /// session's own negotiated symmetric definition travels with the entry either way, since only a slot that
    /// negotiated one could have claimed the attribute at all.
    /// </param>
    /// <returns>The real session's response material.</returns>
    private static TpmAttestResponseSession AttestRealResponseSession(
        HmacSessionState session, Tpm2bAuth authValue, Tpm2bAuth entityAuthValue, Tpm2bNonce nonceCaller, TpmaSession sessionAttributes, bool encrypts = false) =>
        new(IsPasswordPlaceholder: false, TpmiShAuthSession.FromValue(session.Handle.Value), session.SessionAlg, session.SessionKey, authValue, entityAuthValue, nonceCaller, sessionAttributes,
            encrypts, session.Symmetric);

    /// <summary>
    /// Rolls every real session's stored nonceTPM and frames the session-authorized response of an attest
    /// command — <c>TPM2_Certify()</c>, <c>TPM2_CertifyCreation()</c>, <c>TPM2_Quote()</c>, <c>TPM2_GetTime()</c>,
    /// <c>TPM2_NV_Certify()</c> — the effect assembled (TPM 2.0 Library Part 1, clause 16.6.1).
    /// </summary>
    /// <remarks>
    /// Each session record is replaced wholesale because its nonceTPM is immutable model state, replaced once per
    /// command — the same pattern <c>OnObjectSealedOverSessions</c> uses. A <c>TPM_RS_PW</c> slot's placeholder
    /// carries no session state to roll, and a session flushed between stages simply leaves the table unchanged
    /// while the response is still framed, so its buffers are released. The transition label names the command
    /// through <see cref="AttestCommandLabel"/>, so one arm serves every attest command.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="certified">The effect's result carrying the command, the framed parameter area, and every session's response entry.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> carrying the framed session-authorized response.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnAttestedOverSessions(TpmSimulatorState state, TpmAttestedOverSessions certified)
    {
        ImmutableDictionary<TpmiShHmac, HmacSessionState> sessions = state.HmacSessions;
        foreach(TpmAttestFramedSessionEntry entry in certified.Entries)
        {
            if(entry.IsPasswordPlaceholder)
            {
                continue;
            }

            sessions = RollHmacSessionNonce(sessions, entry.SessionHandle, entry.RetainedNonceTpm);
        }

        return Transition(
            state with
            {
                NextAction = NullAction.Instance,
                HmacSessions = sessions,
                ResponseIntent = new TpmAttestOverSessionsResponse(
                    TpmRcConstants.TPM_RC_SUCCESS, certified.ParameterArea, certified.Entries)
            },
            $"{AttestCommandLabel(certified.CommandCode)}:OverSession:Completed");
    }

    /// <summary>
    /// The transition-label subject of an attest command, for the one session-authorized completion arm every
    /// attest command shares (<see cref="OnAttestedOverSessions"/>).
    /// </summary>
    /// <param name="commandCode">The attest command.</param>
    /// <returns>The label subject, matching the command's own plain-arm labels.</returns>
    /// <exception cref="System.ArgumentOutOfRangeException"><paramref name="commandCode"/> is not an attest command.</exception>
    private static string AttestCommandLabel(TpmCcConstants commandCode) => commandCode switch
    {
        TpmCcConstants.TPM_CC_Certify => "Certify",
        TpmCcConstants.TPM_CC_CertifyCreation => "CertifyCreation",
        TpmCcConstants.TPM_CC_Quote => "Quote",
        TpmCcConstants.TPM_CC_GetTime => "GetTime",
        TpmCcConstants.TPM_CC_NV_Certify => "NvCertify",
        _ => throw new System.ArgumentOutOfRangeException(nameof(commandCode), commandCode, "Not an attest command.")
    };

    /// <summary>
    /// Checks that a caller-supplied signature is valid over a caller-supplied digest for the key referenced by
    /// keyHandle, for <c>TPM2_VerifySignature()</c> (Part 3, clause 20.1).
    /// </summary>
    /// <remarks>
    /// Unlike every attest-producing command, this is a public-key operation: keyHandle needs no authorization,
    /// and — deliberately, unlike <c>OnCertify</c>/<c>OnCertifyCreation</c> and friends — the signer's sign
    /// attribute is never consulted, because verifying a signature does not use the private part of the key at
    /// all. keyHandle must resolve in TransientObjects (<c>TPM_RC_HANDLE</c>); the scheme hash algorithm is
    /// restricted to SHA-256/384/512 (<c>TPM_RC_HASH</c>), mirroring every other attest command; the signature
    /// algorithm must be compatible with the resolved key's type (<c>TPM_RC_SCHEME</c> on mismatch, mirroring
    /// <c>OnCertify</c>'s dispatch). The actual verification needs the asynchronous verify-delegate seam, so it
    /// is folded into the effect (<c>TpmVerifySignatureAction</c>/<c>TpmRsaVerifySignatureAction</c>) rather
    /// than checked here; the transition resolves the key, folds its retained fields into the matching action,
    /// and leaves no response yet.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_VerifySignature()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the verify action, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnVerifySignature(TpmSimulatorState state, TpmVerifySignatureRequested request)
    {
        if(!state.TransientObjects.TryGetValue(request.KeyHandle, out TransientKeyState? signer))
        {
            return Reject(state, TpmCcConstants.TPM_CC_VerifySignature, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        if(!IsSupportedAttestHashAlg(request.SchemeHashAlg))
        {
            return Reject(state, TpmCcConstants.TPM_CC_VerifySignature, TpmRcConstants.TPM_RC_HASH, request);
        }

        TpmAction? action = (signer.KeyType.Value, request.SignatureScheme.Value) switch
        {
            (TpmAlgIdConstants.TPM_ALG_RSA, TpmAlgIdConstants.TPM_ALG_RSASSA or TpmAlgIdConstants.TPM_ALG_RSAPSS) =>
                new TpmRsaVerifySignatureAction(
                    signer.Name, signer.Hierarchy, signer.PrivateKey, request.Digest, request.Signature, request.SignatureScheme, request.SchemeHashAlg),
            (TpmAlgIdConstants.TPM_ALG_ECC, TpmAlgIdConstants.TPM_ALG_ECDSA) =>
                new TpmVerifySignatureAction(
                    signer.Name, signer.Hierarchy, signer.PublicPoint, signer.Curve, request.Digest, request.Signature, request.SchemeHashAlg),
            _ => null
        };

        if(action is null)
        {
            //A scheme incompatible with the key's type — e.g. an ECDSA signature against an RSA key, or vice
            //versa — fails closed rather than silently coercing to the key's native scheme (mirrors OnCertify).
            //No arm above built an action, so the digest never transferred and the request still owns it.
            return Reject(state, TpmCcConstants.TPM_CC_VerifySignature, TpmRcConstants.TPM_RC_SCHEME, request);
        }

        return Transition(
            state with
            {
                NextAction = action,
                ResponseIntent = null
            },
            "VerifySignature:Requested");
    }

    /// <summary>
    /// Frames the <c>TPM2_VerifySignature()</c> response the effect produced: the <c>TPMT_TK_VERIFIED</c>
    /// validation ticket, or the signature-mismatch rejection (<c>TPM_RC_SIGNATURE</c>) the effect's verify
    /// delegate found — mirroring <c>OnObjectCreationCertified</c>'s success/rejection split, the only other
    /// place a rejection is decided inside the effect rather than the pure transition.
    /// </summary>
    /// <param name="state">The state to transition from.</param>
    /// <param name="verified">The effect's result carrying the validation ticket or the mismatch outcome.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnSignatureVerified(TpmSimulatorState state, TpmSignatureVerified verified) =>
        verified.Validation is { } validation
            ? Transition(
                state with
                {
                    NextAction = NullAction.Instance,
                    ResponseIntent = new TpmVerifySignatureResponse(TpmRcConstants.TPM_RC_SUCCESS, validation)
                },
                "VerifySignature:Completed")
            : Transition(
                state with
                {
                    NextAction = NullAction.Instance,
                    ResponseIntent = new TpmHeaderOnlyResponse(verified.ResponseCode)
                },
                "VerifySignature:Rejected");

    /// <summary>
    /// Decodes a <c>TPML_PCR_SELECTION</c> and gathers the selected SHA-256 bank register values in ascending
    /// PCR-index order — the order the PCR composite hashes them in (TPM 2.0 Library Part 4,
    /// <c>PCRComputeCurrentDigest</c>) and the order <c>TPM2_PCR_Read()</c> returns them.
    /// </summary>
    /// <remarks>
    /// A selection naming a bank other than the modelled SHA-256 bank contributes no values. The selection bytes
    /// were validated for structure when the command was parsed, so the reader walks them without bounds
    /// surprises.
    /// </remarks>
    /// <param name="bank">The SHA-256 PCR bank to read from.</param>
    /// <param name="selectionBytes">The marshaled <c>TPML_PCR_SELECTION</c> bytes.</param>
    /// <returns>The selected register values, in ascending PCR-index order.</returns>
    private static ImmutableArray<ReadOnlyMemory<byte>> GatherSelectedPcrValues(PcrBankState bank, ReadOnlyMemory<byte> selectionBytes)
    {
        ImmutableArray<ReadOnlyMemory<byte>>.Builder builder = ImmutableArray.CreateBuilder<ReadOnlyMemory<byte>>();
        var reader = new TpmReader(selectionBytes.Span);
        uint count = reader.ReadUInt32();
        for(uint selection = 0; selection < count; selection++)
        {
            var hash = (TpmAlgIdConstants)reader.ReadUInt16();
            byte sizeofSelect = reader.ReadByte();
            ReadOnlySpan<byte> select = reader.ReadBytes(sizeofSelect);
            if(hash != bank.HashAlgorithm)
            {
                continue;
            }

            AppendSelectedPcrValues(builder, bank, select);
        }

        return builder.ToImmutable();
    }

    /// <summary>
    /// Gathers the selected SHA-256 bank register values in ascending PCR-index order from a parsed
    /// <c>TPML_PCR_SELECTION</c> (TPM 2.0 Library Part 2, clause 10.9.7, Table 125) — the structure-typed
    /// counterpart of <see cref="GatherSelectedPcrValues(PcrBankState, ReadOnlyMemory{byte})"/>, for the attest
    /// commands whose selection rides an owned carrier.
    /// </summary>
    /// <remarks>A selection naming a bank other than the modelled SHA-256 bank contributes no values.</remarks>
    /// <param name="bank">The SHA-256 PCR bank to read from.</param>
    /// <param name="selection">The parsed selection list.</param>
    /// <returns>The selected register values, in ascending PCR-index order.</returns>
    private static ImmutableArray<ReadOnlyMemory<byte>> GatherSelectedPcrValues(PcrBankState bank, TpmlPcrSelection selection)
    {
        ImmutableArray<ReadOnlyMemory<byte>>.Builder builder = ImmutableArray.CreateBuilder<ReadOnlyMemory<byte>>();
        foreach(TpmsPcrSelection entry in selection.Selections)
        {
            if(entry.HashAlgorithm != bank.HashAlgorithm)
            {
                continue;
            }

            AppendSelectedPcrValues(builder, bank, entry.PcrSelect.Span);
        }

        return builder.ToImmutable();
    }

    /// <summary>
    /// Appends the register values one <c>TPMS_PCR_SELECTION</c> bitmap selects, in ascending PCR-index order —
    /// the bit walk both <c>TPML_PCR_SELECTION</c> gather forms share (TPM 2.0 Library Part 2, clause 10.6.2:
    /// the octet at index <c>n</c> carries PCRs <c>8n</c> to <c>8n + 7</c>, least significant bit first).
    /// </summary>
    /// <remarks>A selected index beyond the modelled bank's register count contributes no value.</remarks>
    /// <param name="builder">The builder collecting the selected values.</param>
    /// <param name="bank">The PCR bank to read from.</param>
    /// <param name="select">The selection bitmap.</param>
    private static void AppendSelectedPcrValues(ImmutableArray<ReadOnlyMemory<byte>>.Builder builder, PcrBankState bank, ReadOnlySpan<byte> select)
    {
        for(int byteIndex = 0; byteIndex < select.Length; byteIndex++)
        {
            byte bits = select[byteIndex];
            for(int bitIndex = 0; bitIndex < 8; bitIndex++)
            {
                if((bits & (1 << bitIndex)) == 0)
                {
                    continue;
                }

                int pcr = (byteIndex * 8) + bitIndex;
                if(pcr < bank.Values.Length)
                {
                    builder.Add(bank.Values[pcr]);
                }
            }
        }
    }

    /// <summary>
    /// Starts a TPM2_StartAuthSession() POLICY or TRIAL session (Part 3, clause 11.1).
    /// </summary>
    /// <remarks>
    /// Allocates a session handle in the TPM_HT_POLICY_SESSION range and captures the session-relative Time base,
    /// then runs the SAME bind/salt validation ladder <c>OnStartHmacSession</c> does (<c>TryBuildSessionStartAction</c>
    /// — Section 11.1.1: "For all session types, this command will cause initialization of the sessionKey") with a
    /// <see cref="TpmPolicySessionKeyContext"/> attached, so the effectful loop derives a real session key exactly
    /// as an HMAC session's start would; <c>OnHmacSessionStarted</c> records the resulting <see cref="PolicySessionState"/>
    /// (all-zero initial policyDigest, unlatched cpHash, isAuthValueNeeded/isPasswordNeeded CLEAR) and frames the
    /// response once the key/nonce come back. TPM2_PolicySigned()'s aHash binds to the returned nonceTPM (Part 3,
    /// Section 23.3), so it can no longer be a fixed placeholder.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed TPM2_StartAuthSession() request for a POLICY or TRIAL session.</param>
    /// <returns>The <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the session-start action.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnStartAuthSession(TpmSimulatorState state, TpmStartAuthSessionRequested request)
    {
        //Only the digest sizes the policy formula supports are modelled; an unsupported authHash is TPM_RC_HASH.
        if(!IsSupportedPolicyHash(request.AuthHash))
        {
            return Reject(state, TpmCcConstants.TPM_CC_StartAuthSession, TpmRcConstants.TPM_RC_HASH, request);
        }

        uint handle = state.NextSessionHandle;
        bool isTrial = request.SessionType == TpmSeConstants.TPM_SE_TRIAL;
        var policyContext = new TpmPolicySessionKeyContext(isTrial, state.Time);

        if(!TryBuildSessionStartAction(
            state, handle, request.AuthHash, request.Bind.Value, request.NonceCaller, request.Symmetric, request.TpmKey.Value, request.EncryptedSalt,
            policyContext, out TpmAction? action, out TpmRcConstants rejectCode))
        {
            return Reject(state, TpmCcConstants.TPM_CC_StartAuthSession, rejectCode, request);
        }

        return Transition(
            state with
            {
                NextSessionHandle = handle + 1,
                NextAction = action,
                ResponseIntent = null
            },
            "StartAuthSession:PolicyRequested");
    }

    /// <summary>
    /// Restricts a policy session to a single command for <c>TPM2_PolicyCommandCode()</c> (Part 3, clause 23.11).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The policy session is a command handle with no authorization; an unknown handle is <c>TPM_RC_HANDLE</c>.
    /// </para>
    /// <para>
    /// The restricted code is recorded on the session (<see cref="PolicySessionState.CommandCode"/>) as well as
    /// folded into the policyDigest. A USER-role entity's authorization consults only the digest, so for those
    /// commands the field is inert; an ADMIN-role authorization consults it directly, because Part 1, clause
    /// 17.2's ADMIN Note requires the session's commandCode to match the authorized command as a condition
    /// SEPARATE from the digest match — which is also what makes "no command code was ever asserted"
    /// distinguishable from "the wrong one was asserted" at that gate.
    /// </para>
    /// <para>
    /// DESIGN: <c>TpmPolicyDigest</c> is the single source of truth for the enhanced-authorization policyDigest
    /// formula (the exact <c>H(...)</c> construction of Part 1, clause 17.7; validated when it was built and
    /// independently unit-tested). The simulator advances each session's accumulated digest by calling the SAME
    /// <c>TpmPolicyDigest</c> methods the host predictor uses, so the on-device digest and the host prediction
    /// cannot diverge by construction. The in-house acceptance test therefore covers the wire round-trip, the
    /// production command path, and assertion composition — not the raw formula, whose independent-oracle role
    /// lives in <c>TpmPolicyDigest</c>'s unit tests. Every policy assertion below shares this rationale.
    /// </para>
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_PolicyCommandCode()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnPolicyCommandCode(TpmSimulatorState state, TpmPolicyCommandCodeRequested request)
    {
        if(!state.PolicySessions.TryGetValue(request.PolicySession, out PolicySessionState? session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicyCommandCode, TpmRcConstants.TPM_RC_HANDLE);
        }

        //The restriction lands on the session before the fold is declared, so the resuming transition reads it
        //back from state and only installs the advanced digest.
        session = session with { CommandCode = request.Code };

        return DeclarePolicyDigestFold(
            state with { PolicySessions = state.PolicySessions.SetItem(session.Handle, session) },
            session, TpmPolicyDigestFold.CommandCode, "PolicyCommandCode", restrictedCommand: request.Code);
    }

    /// <summary>
    /// Binds a policy to the authorized object's authValue via TPM2_PolicyAuthValue() (Part 3, clause 23.17).
    /// </summary>
    /// <remarks>
    /// SETs the session's isAuthValueNeeded flag (Part 1, clause 17.7.8), CLEARing isPasswordNeeded — the mutual
    /// exclusion TPM2_PolicyPassword() would apply the other way around, were it modelled (it is constants-only in
    /// this simulator, so that CLEAR direction is unreachable in practice; the assignment is still made here for
    /// spec fidelity, matching Part 1, clause 17.7.8's own "It will also be CLEAR by TPM2_PolicyPassword()"
    /// wording read symmetrically). This is what lets a later TPM2_PolicySecret() authorized by THIS session apply
    /// eq. 26 (Part 1, clause 17.6.12) instead of failing TPM_RC_MODE (Part 3, Section 23.4.1). See the
    /// single-source-of-truth note on <c>OnPolicyCommandCode</c> for the digest fold itself.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed TPM2_PolicyAuthValue() request.</param>
    /// <returns>The <see cref="TransitionResult{TState, TStackSymbol}"/> reflecting the extended policyDigest and the flipped session flags.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnPolicyAuthValue(TpmSimulatorState state, TpmPolicyAuthValueRequested request)
    {
        if(!state.PolicySessions.TryGetValue(request.PolicySession, out PolicySessionState? session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicyAuthValue, TpmRcConstants.TPM_RC_HANDLE);
        }

        //The flags land on the session before the fold is declared, so the resuming transition reads them back
        //from state and only installs the advanced digest.
        session = session with { IsAuthValueNeeded = true, IsPasswordNeeded = false };

        return DeclarePolicyDigestFold(
            state with { PolicySessions = state.PolicySessions.SetItem(session.Handle, session) },
            session, TpmPolicyDigestFold.AuthValue, "PolicyAuthValue");
    }

    /// <summary>
    /// Returns the session's current policyDigest for <c>TPM2_PolicyGetDigest()</c> (Part 3, clause 23.19).
    /// </summary>
    /// <remarks>
    /// A pure read; an unknown handle is <c>TPM_RC_HANDLE</c>.
    /// </remarks>
    /// <param name="state">The state to read from.</param>
    /// <param name="request">The parsed <c>TPM2_PolicyGetDigest()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnPolicyGetDigest(TpmSimulatorState state, TpmPolicyGetDigestRequested request)
    {
        if(!state.PolicySessions.TryGetValue(request.PolicySession, out PolicySessionState? session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicyGetDigest, TpmRcConstants.TPM_RC_HANDLE);
        }

        //The response BORROWS the session's own carrier: the session keeps accumulating after this command, so
        //it stays the digest's single owner and the framing step only copies the octets out.
        return Transition(
            state with { ResponseIntent = new TpmPolicyGetDigestResponse(TpmRcConstants.TPM_RC_SUCCESS, session.PolicyDigest) },
            "PolicyGetDigest");
    }

    /// <summary>
    /// Binds a policy to a set of PCRs for <c>TPM2_PolicyPCR()</c> (Part 3, clause 23.7).
    /// </summary>
    /// <remarks>
    /// The trial and real forms differ in where the bound pcrDigest comes from. On a TRIAL session the caller's
    /// pcrDigest is folded in verbatim (the session authorizes nothing, so the TPM does not consult live PCR
    /// state). On a REAL session the TPM computes the digest of the CURRENTLY selected PCR values and binds the
    /// policy to THAT value — so a session started on a different PCR state produces a different policyDigest
    /// (Part 3, clause 23.7; Part 4, <c>PolicyPCR</c> / <c>PCRComputeCurrentDigest</c>). A real-session caller
    /// may also supply the expected digest; when non-empty it must match the live value or the assertion is
    /// rejected with <c>TPM_RC_VALUE</c>. The marshaled <c>TPML_PCR_SELECTION</c> was captured verbatim from the
    /// wire, so it folds into the policyDigest exactly as the host prediction does. See the single-source-of-truth
    /// note on <c>OnPolicyCommandCode</c>.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_PolicyPCR()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnPolicyPcr(TpmSimulatorState state, TpmPolicyPcrRequested request)
    {
        if(!state.PolicySessions.TryGetValue(request.PolicySession, out PolicySessionState? session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicyPCR, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        //The caller-supplied digest transfers into the fold, whose effect compares it against the live composite
        //it computes for a real session and is its terminal owner either way; the selected register values ride
        //along as borrows of the durable bank's own memory, exactly as TPM2_Quote()'s action carries them.
        return DeclarePolicyDigestFold(
            state, session, TpmPolicyDigestFold.Pcr, "PolicyPCR",
            pcrSelectionBytes: request.PcrSelectionBytes,
            pcrDigest: request.PcrDigest,
            pcrValues: GatherSelectedPcrValues(state.Sha256PcrBank, request.PcrSelectionBytes));
    }

    /// <summary>
    /// Authorizes the session when its current digest matches one of the branches for <c>TPM2_PolicyOR()</c>,
    /// then collapses it to <c>H(0…0 || TPM_CC_PolicyOR || branches)</c> (Part 3, clause 23.6).
    /// </summary>
    /// <remarks>
    /// On a real (non-trial) session a current digest matching no branch is <c>TPM_RC_VALUE</c>; a trial session
    /// skips the match. See the note on <c>OnPolicyCommandCode</c>.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_PolicyOR()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnPolicyOr(TpmSimulatorState state, TpmPolicyOrRequested request)
    {
        if(!state.PolicySessions.TryGetValue(request.PolicySession, out PolicySessionState? session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicyOR, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        if(!session.IsTrial && !MatchesAnyBranch(session.PolicyDigest.AsReadOnlySpan(), request.Branches))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicyOR, TpmRcConstants.TPM_RC_VALUE, request);
        }

        //The branch list transfers into the fold, whose effect is its terminal owner.
        return DeclarePolicyDigestFold(state, session, TpmPolicyDigestFold.Or, "PolicyOR", branches: request.Branches);
    }

    /// <summary>
    /// Binds a policy to the authorization of a permanent entity via TPM2_PolicySecret() (Part 3, clause 23.4).
    /// </summary>
    /// <remarks>
    /// This slice authorizes permanent hierarchies (empty auth by default), whose Name is the 4-byte handle value
    /// (Part 1, clause 14, Table 6); PolicySecret(TPM_RH_ENDORSEMENT) with an empty policyRef yields the well-known EK
    /// authorization policy. The supplied authValue is genuinely, constant-time verified against the hierarchy's
    /// own authValue — checked BEFORE the trial/real split and before any other check, even for a trial session
    /// (Section 23.4.1: "The authorization is checked even for a trial policy session" — the one carve-out from
    /// the general "trial sessions skip real checks" default). Owner/Endorsement/Platform/Null are never
    /// dictionary-attack gated (clause 17.8.1), mirroring the existing owner-auth posture (<c>OnNvDefineSpace</c>'s
    /// own OwnerAuth check); <c>TPM_RH_LOCKOUT</c> is the sole exception (clause 17.8's own carve-out) and is
    /// checked with the same LockoutAuthEnabled gate and disable-on-mismatch shape as
    /// TPM2_DictionaryAttackLockReset()/TPM2_DictionaryAttackParameters(). <c>TPM_RH_NULL</c> is a permanent handle
    /// with structurally empty auth, so it is accepted here like every other modelled non-Lockout hierarchy; its
    /// ticket binds to the null-hierarchy proof. Authorization proven, this hands off to
    /// <c>ContinuePolicySecretAuthorized</c> — the same post-auth ladder (trial fold / nonceTPM / expiration /
    /// cpHashA / ticket-mint dispatch) an HMAC- or POLICY-session-authorized call
    /// (<c>OnPolicySecretOverSession</c>/<c>ContinuePolicySecretOverSession</c>) shares, since none of it depends
    /// on HOW authorization was proven, only on whether it was (authorizingSession: null keeps this arm's response
    /// the direct <see cref="TpmPolicySecretResponse"/> it always was, unlike the other two arms).
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed TPM2_PolicySecret() password-arm request.</param>
    /// <returns>The <see cref="TransitionResult{TState, TStackSymbol}"/> for the authorization outcome.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnPolicySecret(TpmSimulatorState state, TpmPolicySecretRequested request)
    {
        if(!state.PolicySessions.TryGetValue(request.PolicySession, out PolicySessionState? session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicySecret, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        //This slice models PolicySecret only for permanent hierarchies, whose Name is the 4-byte handle value
        //(Part 1, clause 14, Table 6). A non-permanent authHandle (an NV Index or object) has a computed Name and its
        //own authValue; folding the raw handle bytes for such an entity would both diverge from the TPM Name
        //formula and skip the authorization it requires, so an unsupported authorization entity is rejected
        //rather than silently advancing the policyDigest as if its secret had been proven.
        if(!IsPermanentHandle(request.AuthHandle.Value))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicySecret, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        //The authValue is resolved from the one field the handle names, so each of the four hierarchies that
        //carry one is compared against its OWN secret — the alternative, defaulting anything but the owner
        //hierarchy to the Empty Buffer, would let a caller authorize as ENDORSEMENT or PLATFORM with an empty
        //value the moment TPM2_HierarchyChangeAuth() gives those hierarchies a real one. TPM_RH_NULL and every
        //other permanent constant have no authValue slot and keep the structurally empty one.
        _ = state.TryGetHierarchyAuthValue(request.AuthHandle.Value, out Tpm2bAuth hierarchyAuthValue);

        //Owner authorization is not dictionary-attack protected (clause 17.8.1): a wrong authValue is a plain
        //bad-authorization, never an auth-failure that feeds a lockout counter, and the comparison is
        //constant-time so a mismatch leaks no timing about the secret. TPM_RH_LOCKOUT is the one permanent
        //handle this does NOT apply to — clause 17.8's own carve-out is that every OTHER permanent handle is
        //DA-exempt, lockoutAuth is the one that is not (Section 23.4.1: "If the authorization check fails, then
        //the normal dictionary attack logic is invoked") — so it is checked separately below, refusing outright
        //while disabled and disabling-on-mismatch with the identical shape OnDictionaryAttackLockReset/
        //OnDictionaryAttackParameters already use for the same secret.
        if(request.AuthHandle.Value == (uint)TpmRh.TPM_RH_LOCKOUT)
        {
            if(!state.LockoutAuthEnabled)
            {
                return Reject(state, TpmCcConstants.TPM_CC_PolicySecret, TpmRcConstants.TPM_RC_LOCKOUT, request);
            }

            if(!CryptographicOperations.FixedTimeEquals(StripTrailingZeros(request.AuthValueSupplied.AsReadOnlySpan()), StripTrailingZeros(state.LockoutAuth.AsReadOnlySpan())))
            {
                TpmSimulatorState disabled = state with { LockoutAuthEnabled = false, LastLockoutAuthFailureTime = state.Time };

                return Reject(disabled, TpmCcConstants.TPM_CC_PolicySecret, TpmRcConstants.TPM_RC_AUTH_FAIL, request);
            }
        }
        else if(!CryptographicOperations.FixedTimeEquals(StripTrailingZeros(request.AuthValueSupplied.AsReadOnlySpan()), StripTrailingZeros(hierarchyAuthValue.AsReadOnlySpan())))
        {
            //Both sides compare with trailing zero octets removed (Part 1, clause 17.6.4.3), matching the
            //sealed-object password compare — whatever form the installing command stored.
            return Reject(state, TpmCcConstants.TPM_CC_PolicySecret, TpmRcConstants.TPM_RC_BAD_AUTH, request);
        }

        //The caller-supplied nonceTPM is compared and released HERE rather than inside the shared ladder, which
        //has six-plus arms that would each have to hand-dispose it (Part 3, Section 23.2.2). Only its emptiness
        //travels on, as the deadline base and the ticket's session-unbound flag.
        if(!TryConsumePolicySecretNonceTpm(session, request.NonceTpm, out bool isNonceTpmEmpty))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicySecret, TpmRcConstants.TPM_RC_VALUE, request);
        }

        //The compare above was this credential's only use, so this transition is its terminal owner; every arm
        //that refuses before this point releases it through the request's own Dispose.
        request.AuthValueSupplied.Dispose();

        //The Name of a permanent handle is its 4-byte handle value (Part 1, clause 14, Table 6); the octets are
        //materialized by the effect that hashes them, which is the frame that holds a memory pool.
        TpmHandleName authName = TpmHandleName.FromHandle(request.AuthHandle.Value);

        return ContinuePolicySecretAuthorized(
            state, session, request.AuthHandle.Value, authName, isNonceTpmEmpty, request.CpHashA, request.PolicyRef, request.Expiration,
            authorizingSession: null);
    }

    /// <summary>
    /// Answers <c>TPM2_PolicySecret()</c>'s and <c>TPM2_PolicySigned()</c>'s shared nonceTPM rule (TPM 2.0
    /// Library Part 3, Section 23.2.2) and releases the caller-supplied carrier, leaving only the emptiness the
    /// rest of the ladder reads.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A non-empty caller nonce binds the authorization to the session's current nonceTPM and must equal it; an
    /// empty one is a session-unbound authorization and always passes. A trial session runs no part of the
    /// nonceTPM/expiration/cpHashA ladder at all (Section 23.4.1's carve-out is the authorization check alone),
    /// so the comparison is skipped there exactly as the ladder itself skips it. The carrier is released on
    /// every path, because its value is never needed past this comparison — the deadline base and the ticket's
    /// session-unbound flag both read only whether it was empty.
    /// </para>
    /// <para>
    /// A mismatch is <c>TPM_RC_VALUE</c>, which is what the rule itself names — Part 3, clause 23.2.2, printed
    /// page 189, rule 1: "nonceTPM - If this parameter is not the Empty Buffer, and it does not match
    /// policySession→nonceTPM, then the TPM shall return TPM_RC_VALUE." <c>TPM_RC_NONCE</c> stays where the
    /// specification names it instead: a <c>TPM_RS_PW</c> authorization slot that carries a non-empty nonce
    /// (see <see cref="TryValidatePasswordSlot"/>).
    /// </para>
    /// </remarks>
    /// <param name="session">The policy session being extended, whose retained nonceTPM the caller nonce must match.</param>
    /// <param name="nonceTpm">The caller-supplied nonceTPM in an owned carrier; released here once the rule is satisfied, and left with the request otherwise so the caller's disposing refusal releases it exactly once.</param>
    /// <param name="isNonceTpmEmpty">Whether the caller supplied an empty nonceTPM — the session-unbound form.</param>
    /// <returns><see langword="true"/> when the rule is satisfied; otherwise <see langword="false"/>, which the caller answers with <c>TPM_RC_VALUE</c>.</returns>
    private static bool TryConsumePolicySecretNonceTpm(PolicySessionState session, Tpm2bNonce nonceTpm, out bool isNonceTpmEmpty)
    {
        isNonceTpmEmpty = nonceTpm.IsEmpty;

        if(!session.IsTrial && !isNonceTpmEmpty && !nonceTpm.AsReadOnlySpan().SequenceEqual(session.NonceTpm.AsReadOnlySpan()))
        {
            return false;
        }

        nonceTpm.Dispose();

        return true;
    }

    /// <summary>
    /// Authorizes TPM2_PolicySecret() over an HMAC or POLICY session on authHandle (Part 3, Section 23.4.1: "A
    /// password session, an HMAC session, or a policy session containing TPM2_PolicyAuthValue() or
    /// TPM2_PolicyPassword() will satisfy this requirement").
    /// </summary>
    /// <remarks>
    /// <para>
    /// Resolves policySession (the session being extended, TPM_RC_HANDLE if unknown) and authHandle's permanence
    /// (TPM_RC_HANDLE) exactly as the password arm does, then resolves the authorizing session by handle in EITHER
    /// session table (TPM 2.0 Library Part 2, clause 6.6.2's session-not-loaded warning when neither resolves —
    /// this command's authorizing session genuinely authorizes an entity, unlike GetRandom's decrypt-only
    /// companion, but the "handle does not resolve" outcome is still the generic session-reference warning, not a
    /// HANDLE rejection). Clause 5.5's session-area attribute rules are validated next (decrypt/encrypt on this
    /// session is refused with TPM_RC_ATTRIBUTES: the reference command-attribute table marks PolicySecret's
    /// nonceTPM/timeout DECRYPT_2/ENCRYPT_2-eligible, but this simulator does not yet implement parameter
    /// encryption for this command, so it fails closed rather than silently accepting-but-not-encrypting). A
    /// POLICY authorizer additionally needs isAuthValueNeeded/isPasswordNeeded SET (TPM_RC_MODE otherwise —
    /// Section 23.4.1 verbatim, PolicySecret-scoped only, never generalized to other policy-session-authorized
    /// commands) before the eq. 26/27 key decision (Part 1, clause 17.6.12); an HMAC authorizer instead applies
    /// the ordinary bind-omission optimization (equation 22, Part 1, clause 17.6.10) when it is bound to authHandle itself — a POLICY
    /// session never does (Section 11.1.1's "the session is not bound"). TPM_RH_LOCKOUT's dictionary-attack gate
    /// (clause 17.8's carve-out) is checked last, strictly before the command HMAC is ever evaluated, mirroring
    /// the password arm's own D2 gate.
    /// </para>
    /// <para>
    /// A POLICY authorizer is measured against authHandle's own installed authorization policy, the part of
    /// Part 3, clause 5.6's check-8 checklist that turns on entity state: an entity whose authPolicy is the Empty
    /// Buffer is outside the policy path entirely — "When the authPolicy is empty, it cannot match any
    /// policyDigest value so the use of authPolicy is disabled" (Part 1, clause 11.2, Table 5) — so a POLICY
    /// authorizer against it is refused with TPM_RC_AUTH_UNAVAILABLE, and a hierarchy carrying a policy installed
    /// by TPM2_SetPrimaryPolicy() authorizes exactly when the session's accumulated policyDigest reproduces it,
    /// TPM_RC_POLICY_FAIL otherwise. The remaining two items of that checklist, timeOut/TPM_RC_EXPIRED and the
    /// latched cpHash/TPM_RC_POLICY_FAIL, are session state rather than entity state and are not applied to the
    /// authorizer here.
    /// POLICY sessions also carry no negotiated symmetric definition (<see cref="PolicySessionState"/> has no such
    /// member — see its own remarks), so this always passes <c>TpmtSymDef.Null</c> to <c>ValidateSessionArea</c>
    /// below; a decrypt/encrypt POLICY session fails closed with TPM_RC_ATTRIBUTES rather than silently
    /// accepting-but-not-encrypting, the same posture the reference command-attribute table's DECRYPT_2/ENCRYPT_2
    /// legality on PolicySecret would otherwise call for.
    /// </para>
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed TPM2_PolicySecret() HMAC/POLICY-session-arm request.</param>
    /// <returns>The <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the command-HMAC verification action, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnPolicySecretOverSession(TpmSimulatorState state, TpmPolicySecretOverSessionRequested request)
    {
        if(!state.PolicySessions.ContainsKey(request.PolicySession))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicySecret, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        if(!IsPermanentHandle(request.AuthHandle.Value))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicySecret, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        bool isHmacSession = state.HmacSessions.TryGetValue(TpmiShHmac.FromValue(request.AuthorizingSessionHandle.Value), out HmacSessionState? hmacSession);
        PolicySessionState? policySession = null;
        bool isPolicySession = !isHmacSession && state.PolicySessions.TryGetValue(TpmiShPolicy.FromValue(request.AuthorizingSessionHandle.Value), out policySession);
        if(!isHmacSession && !isPolicySession)
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicySecret, SessionReferenceMissRc(sessionIndex: 0), request);
        }

        //A trial session (TPM_SE_TRIAL, Part 3, clause 11.1.1) computes a policyDigest but authorizes nothing; a
        //real TPM refuses ANY trial session presented in a command's session area before any authorization
        //processing, session-index-encoded TPM_RC_ATTRIBUTES, which this mirrors. The session being EXTENDED (the
        //policySession parameter) may of course be trial; only the AUTHORIZER may not.
        if(isPolicySession && policySession!.IsTrial)
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicySecret, SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), request);
        }

        TpmRcConstants? sessionAreaError = ValidateSessionArea(
            request.SessionAttributes, firstAuthorizesEntity: true, isHmacSession ? hmacSession!.Symmetric : TpmtSymDef.Null,
            hasSecondSession: false, secondAttributes: default, secondSymmetric: TpmtSymDef.Null,
            firstCommandParameterIsEncryptable: false, firstResponseParameterIsEncryptable: false,
            firstSessionHandle: request.AuthorizingSessionHandle, firstNonceLength: request.NonceCaller.Size);
        if(sessionAreaError is TpmRcConstants sessionAreaRc)
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicySecret, sessionAreaRc, request);
        }

        //The authorizing slot may hold either session kind, and both record the bind entity's dictionary-attack
        //state, so both are gated on it before any authorization work: use of a session bound to a DA-protected
        //entity is subject to DA "regardless of the DA status of the entity being authorized" (Part 3, clause
        //11.1.1), which here can be one of the three exempt hierarchies.
        bool isBoundSessionLockedOut = isHmacSession
            ? IsBoundSessionLockedOut(state, hmacSession!)
            : IsBoundSessionLockedOut(state, policySession!);
        if(isBoundSessionLockedOut)
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicySecret, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        //Resolved from the one field the handle names, so ENDORSEMENT and PLATFORM authorize against their own
        //secrets rather than the Empty Buffer once TPM2_HierarchyChangeAuth() has given them one.
        _ = state.TryGetHierarchyAuthValue(request.AuthHandle.Value, out Tpm2bAuth hierarchyAuthValue);

        TpmiAlgHash sessionAlg;
        SymmetricKeyMemory sessionKey;
        Tpm2bNonce sessionNonceTpm;
        Tpm2bAuth authValueForHmac;

        if(isPolicySession)
        {
            //Whether authHandle can be authorized by a policy at all is entity state, so it is settled before the
            //command's own rule below: an Empty authPolicy disables policy authorization of that entity outright
            //(Part 1, clause 11.2, Table 5), which is TPM_RC_AUTH_UNAVAILABLE rather than a failed match, while a
            //policy installed by TPM2_SetPrimaryPolicy() must be reproduced exactly by the session's accumulated
            //digest. Both directions are reachable only because the hierarchy authPolicy slots are real state.
            _ = state.TryGetHierarchyAuthPolicy(request.AuthHandle.Value, out Tpm2bDigest hierarchyAuthPolicy, out _);
            if(hierarchyAuthPolicy.IsEmpty)
            {
                return Reject(state, TpmCcConstants.TPM_CC_PolicySecret, TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, request);
            }

            if(!policySession!.PolicyDigest.AsReadOnlySpan().SequenceEqual(hierarchyAuthPolicy.AsReadOnlySpan()))
            {
                return Reject(state, TpmCcConstants.TPM_CC_PolicySecret, TpmRcConstants.TPM_RC_POLICY_FAIL, request);
            }

            //Part 3, Section 23.4.1 verbatim: "If a policy session is used and use of the authValue of
            //authHandle is not required, the TPM will return TPM_RC_MODE. That is, the session for authHandle
            //must have either isAuthValueNeeded or isPasswordNeeded SET." isPasswordNeeded is reserved (never
            //SET in this model — TPM2_PolicyPassword is constants-only), so isAuthValueNeeded alone decides in
            //practice; the check still names both flags to match the spec's own wording.
            if(!policySession.IsAuthValueNeeded && !policySession.IsPasswordNeeded)
            {
                return Reject(state, TpmCcConstants.TPM_CC_PolicySecret, TpmRcConstants.TPM_RC_MODE, request);
            }

            sessionAlg = policySession.PolicyHash;
            sessionKey = policySession.SessionKey;
            sessionNonceTpm = policySession.NonceTpm;

            //Eq. 26 (isAuthValueNeeded SET: HMAC(sessionKey ‖ authValue, ...)) vs. eq. 27 (CLEAR: HMAC(sessionKey,
            //...)) — Part 1, clause 17.6.12. The authValue term enters stripped of trailing zero octets
            //(clause 17.6.4.3) at the HMAC primitive, matching the host session's own SetAuthValue discipline —
            //the two sides must agree byte for byte once TPM2_HierarchyChangeAuth() installs a real hierarchy secret.
            authValueForHmac = policySession.IsAuthValueNeeded
                ? hierarchyAuthValue
                : Tpm2bAuth.Empty;
        }
        else
        {
            sessionAlg = hmacSession!.SessionAlg;
            sessionKey = hmacSession.SessionKey;
            sessionNonceTpm = hmacSession.NonceTpm;

            //Equation 22 (Part 1, clause 17.6.10) bind-omission: the authValue term drops when this HMAC session is bound to authHandle
            //itself — binding already proved knowledge of the authValue once via the session-key KDFa. The
            //recomputation folds the hierarchy's LIVE authValue (Part 4, IsSessionBindEntity), so a rotation
            //since the bind ends the omission.
            bool bindOmits = MatchesHandleFormBoundEntity(hmacSession.BoundEntity, request.AuthHandle.Value, StripTrailingZeros(hierarchyAuthValue.AsReadOnlySpan()));
            authValueForHmac = bindOmits ? Tpm2bAuth.Empty : hierarchyAuthValue;
        }

        bool isLockoutEntity = request.AuthHandle.Value == (uint)TpmRh.TPM_RH_LOCKOUT;
        if(isLockoutEntity && !state.LockoutAuthEnabled)
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicySecret, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        //cpHash's Name1/Name2 (Part 1, clause 16.7 equation 15; Table 6): authHandle's own raw handle, then the
        //policySession PARAMETER's raw handle — NEVER the authorizing session's handle, even when the two differ.
        TpmCommandHandleNames handleNames = TpmCommandHandleNames.Of(
            TpmHandleName.FromHandle(request.AuthHandle.Value), TpmHandleName.FromHandle(request.PolicySession.Value));

        //Clause 17.8.7's OR on both axes: the authorized entity (lockoutAuth alone among the permanent entities is
        //protected) and the session's own bind. A session whose key folded lockoutAuth takes the one-strike branch
        //even when it authorizes one of the exempt hierarchies, since the failed HMAC is evidence against
        //lockoutAuth itself (clause 17.8.5).
        bool isBoundEntityDaProtected = isHmacSession ? hmacSession!.IsBoundEntityDaProtected : policySession!.IsBoundEntityDaProtected;
        bool isBoundToLockout = isHmacSession ? hmacSession!.IsBoundToLockout : policySession!.IsBoundToLockout;

        var pending = new TpmPendingSessionVerification(
            SessionHandle: request.AuthorizingSessionHandle, SessionIndex: 0, SessionAlg: sessionAlg, SessionKey: sessionKey,
            AuthValue: authValueForHmac, IsDaProtected: isLockoutEntity || isBoundEntityDaProtected,
            NonceCaller: request.NonceCaller, NonceTpm: sessionNonceTpm,
            FoldedNonceDecrypt: Tpm2bNonce.Empty, FoldedNonceEncrypt: Tpm2bNonce.Empty, SessionAttributes: request.SessionAttributes, SuppliedHmac: request.Hmac,
            IsLockoutEntity: isLockoutEntity || isBoundToLockout);

        return Transition(
            state with
            {
                NextAction = new TpmVerifyCommandHmacAction(
                    TpmCcConstants.TPM_CC_PolicySecret, handleNames, request.RawParameterArea, pending,
                    ImmutableArray<TpmPendingSessionVerification>.Empty, request),
                ResponseIntent = null
            },
            "PolicySecret:HmacVerifyRequested");
    }

    /// <summary>
    /// Resumes TPM2_PolicySecret() once its authHandle-authorizing session's command HMAC has verified
    /// (<see cref="TpmVerifyCommandHmacAction"/>'s continuation).
    /// </summary>
    /// <remarks>
    /// Re-resolves the authorizing session (guaranteed present — verification just resolved it — mirroring
    /// <c>ContinueGetRandomOverSession</c>'s own re-lookup convention rather than threading the resolved record
    /// through the verify queue) to recover the SAME authValue-inclusion decision the command HMAC used, which the
    /// eventual response HMAC needs again (Part 1, clause 17.6.5, which keys the HMAC of a command or a
    /// response alike on sessionKey concatenated to authValue). A POLICY authorizer's context reset (Part 3, Section 23.2.4: "successfully used to authorize
    /// a command") is NOT applied here — a command that still fails one of the checks below
    /// (nonceTPM/expiration/cpHashA) must leave the authorizer untouched, so the reset is deferred all the way to
    /// <c>OnPolicySecretSessionResponseFramed</c>, the same success-only point where nonceTPM rolls. This function
    /// only reads the authorizer's PRE-reset isAuthValueNeeded to reproduce the eq. 26/27 (Part 1, clause 17.6.12) key decision the command
    /// HMAC already used.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed TPM2_PolicySecret() HMAC/POLICY-session-arm request, its command HMAC now verified.</param>
    /// <returns>The <see cref="TransitionResult{TState, TStackSymbol}"/> from <c>ContinuePolicySecretAuthorized</c>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> ContinuePolicySecretOverSession(TpmSimulatorState state, TpmPolicySecretOverSessionRequested request)
    {
        PolicySessionState session = state.PolicySessions[request.PolicySession];

        //The caller-supplied nonceTPM is compared and released HERE, ahead of the transfer below, so the shared
        //ladder never has to hand-dispose it on any of its arms (Part 3, Section 23.2.2). It runs before the two
        //releases below so a refusal here releases every carrier exactly once, through the request's own Dispose.
        if(!TryConsumePolicySecretNonceTpm(session, request.NonceTpm, out bool isNonceTpmEmpty))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicySecret, TpmRcConstants.TPM_RC_VALUE, request);
        }

        //This continuation is the terminal owner of the parse-rented parameter area and of the slot's supplied
        //credential: the command HMAC that read both has verified, and the shared post-authorization ladder
        //below takes only the parsed values. The slot's caller nonce is NOT released here — it transfers into
        //the authorizing-session entry built at the end of this frame.
        request.RawParameterArea.Dispose();
        request.Hmac.Dispose();

        //The same resolution the entry transition used, so the response HMAC reproduces the command HMAC's key.
        _ = state.TryGetHierarchyAuthValue(request.AuthHandle.Value, out Tpm2bAuth hierarchyAuthValue);

        //The Name of a permanent handle is its 4-byte handle value (Part 1, clause 14, Table 6); the octets are
        //materialized by the effect that hashes them, which is the frame that holds a memory pool.
        TpmHandleName authName = TpmHandleName.FromHandle(request.AuthHandle.Value);

        TpmiAlgHash sessionAlg;
        SymmetricKeyMemory sessionKey;
        Tpm2bAuth authValueUsed;
        bool isPolicySession = state.PolicySessions.TryGetValue(TpmiShPolicy.FromValue(request.AuthorizingSessionHandle.Value), out PolicySessionState? authorizingPolicySession);

        if(isPolicySession)
        {
            sessionAlg = authorizingPolicySession!.PolicyHash;
            sessionKey = authorizingPolicySession.SessionKey;
            authValueUsed = authorizingPolicySession.IsAuthValueNeeded ? hierarchyAuthValue : Tpm2bAuth.Empty;
        }
        else
        {
            HmacSessionState authorizingHmacSession = state.HmacSessions[TpmiShHmac.FromValue(request.AuthorizingSessionHandle.Value)];
            sessionAlg = authorizingHmacSession.SessionAlg;
            sessionKey = authorizingHmacSession.SessionKey;

            //Recomputed exactly as the command-side decision was — TPM2_PolicySecret() rotates no authValue, so
            //this recomputation and the recorded command-time decision are the same value (Part 1, clause
            //17.6.10's response rule: the response omits precisely when the command did).
            bool bindOmits = MatchesHandleFormBoundEntity(authorizingHmacSession.BoundEntity, request.AuthHandle.Value, StripTrailingZeros(hierarchyAuthValue.AsReadOnlySpan()));
            authValueUsed = bindOmits ? Tpm2bAuth.Empty : hierarchyAuthValue;
        }

        //The slot's caller nonce TRANSFERS into the authorizing-session entry here; from there it rides the fold
        //and ticket-mint hops into the response-framing action, whose effect's finally is terminal — and the
        //shared ladder below releases it at every arm that refuses instead of framing.
        var authorizingSession = new PolicySecretAuthorizingSession(
            request.AuthorizingSessionHandle, isPolicySession, sessionAlg, sessionKey, authValueUsed, request.NonceCaller, request.SessionAttributes);

        return ContinuePolicySecretAuthorized(
            state, session, request.AuthHandle.Value, authName, isNonceTpmEmpty, request.CpHashA, request.PolicyRef, request.Expiration,
            authorizingSession);
    }

    /// <summary>
    /// Runs TPM2_PolicySecret()'s shared post-authorization ladder once authHandle's authorization has been
    /// established by whichever mechanism proved it (Part 3, Section 23.4.1).
    /// </summary>
    /// <remarks>
    /// Shared by the password arm (<c>OnPolicySecret</c>) and the HMAC/POLICY-session arm
    /// (<c>ContinuePolicySecretOverSession</c>). A trial session folds unconditionally (the carve-out already ran
    /// in either caller before this is reached), skipping the nonceTPM/expiration/cpHashA checks and never minting
    /// a ticket. A non-trial session runs the same shared parameter-check ladder TPM2_PolicySigned() uses —
    /// nonceTPM, expiration/deadline, cpHashA size+first-writer-wins latch (Section 23.2.2) — and, on a negative
    /// expiration, mints a real TPM_ST_AUTH_SECRET ticket per equation 12 (Part 2, Table 111) through an async effect (the HMAC needs
    /// the registered digest/HMAC seam a pure transition cannot reach). <paramref name="authorizingSession"/> is
    /// <see langword="null"/> for the password arm (<c>FoldPolicySecret</c> frames the response directly) or the
    /// resolved HMAC/POLICY session context for the other arm (<c>FoldPolicySecret</c> instead rolls that
    /// session's nonceTPM and frames a real response session entry). See the single-source-of-truth note on
    /// <c>OnPolicyCommandCode</c> for the digest fold itself.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="session">The policy session being extended.</param>
    /// <param name="authHandle">The permanent handle whose authorization was proven.</param>
    /// <param name="authName">The authorizing entity's Name term, folded into the policyDigest; a borrow or a handle value, never owned here.</param>
    /// <param name="isNonceTpmEmpty">Whether the caller supplied an empty nonceTPM — the session-unbound form. The carrier itself was compared and released by the caller, so this ladder holds no nonce of its own.</param>
    /// <param name="cpHashA">The caller-supplied command parameter hash in an owned carrier, or the empty sentinel when not command-restricted; ownership TRANSFERS here from the request, and this function is its terminal owner on every arm that does not latch it onto the session.</param>
    /// <param name="policyRef">The policy reference, folded into the policyDigest, in an owned carrier; ownership TRANSFERS here from the request, and this function releases it on every refusing arm and transfers it onward otherwise.</param>
    /// <param name="expiration">The requested ticket expiration; negative mints a ticket, zero requests none.</param>
    /// <param name="authorizingSession">The HMAC/POLICY session context authorizing this call, or <see langword="null"/> for the password arm. Its caller nonce is owned there, so every refusing arm below releases it alongside the two parameter carriers.</param>
    /// <returns>The <see cref="TransitionResult{TState, TStackSymbol}"/> for the authorization outcome.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of cpHashA transfers either onto the session's first-writer-wins latch or into this function's own release; policyRef transfers into the declared fold or mint action, whose effect is its terminal owner, and is released here on every refusing arm, as is the authorizing session entry's caller nonce.")]
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> ContinuePolicySecretAuthorized(
        TpmSimulatorState state, PolicySessionState session, uint authHandle, TpmHandleName authName,
        bool isNonceTpmEmpty, Tpm2bDigest cpHashA, Tpm2bNonce policyRef, int expiration,
        PolicySecretAuthorizingSession? authorizingSession)
    {
        if(session.IsTrial)
        {
            //A trial session skips the expiration/cpHashA ladder entirely, so its cpHashA carrier has
            //no later owner and is released here.
            cpHashA.Dispose();

            return DeclarePolicySecretFold(state, session, authName, policyRef, 0ul, authorizingSession);
        }

        TpmSimulatorState checkedState = state;

        //(1) nonceTPM was compared and released by the caller (TryConsumePolicySecretNonceTpm), which answers
        //TPM_RC_VALUE itself; only its emptiness reaches here, as the deadline base and the ticket's
        //session-unbound flag (Part 3, clause 23.2.2).

        //(2) expiration -> inline deadline, identical math to OnPolicySigned's own (Section 23.2.2): an empty
        //caller nonce means an absolute Time-base deadline; a non-empty one means a deadline relative to the
        //session's captured StartTime. The sign of expiration is purely the "mint a ticket" signal.
        ulong timeout = 0ul;
        if(expiration != 0)
        {
            ulong magnitudeMs = (ulong)System.Math.Abs((long)expiration) * 1000UL;
            ulong deadline = isNonceTpmEmpty ? magnitudeMs + (state.Time % 1000UL) : session.StartTime + magnitudeMs;

            if(deadline < state.Time)
            {
                cpHashA.Dispose();
                policyRef.Dispose();
                authorizingSession?.NonceCaller.Dispose();

                return Reject(state, TpmCcConstants.TPM_CC_PolicySecret, TpmRcConstants.TPM_RC_EXPIRED);
            }

            timeout = deadline;
        }

        //(3) cpHashA: only checked when non-empty. Size must equal the session's digest width, and the session's
        //cpHash latch is first-writer-wins (Part 3, Section 23.2.4), so an already-latched value that differs is
        //rejected here. What remains once both refusals have passed — transfer onto an unlatched session,
        //release otherwise — is LatchSessionCpHash's one rule, so this arm calls it rather than restating it.
        if(!cpHashA.IsEmpty)
        {
            if(cpHashA.Size != TpmPolicyDigest.Size(session.PolicyHash.Value))
            {
                cpHashA.Dispose();
                policyRef.Dispose();
                authorizingSession?.NonceCaller.Dispose();

                return Reject(state, TpmCcConstants.TPM_CC_PolicySecret, TpmRcConstants.TPM_RC_SIZE);
            }

            if(!session.CpHash.IsEmpty && !cpHashA.AsReadOnlySpan().SequenceEqual(session.CpHash.AsReadOnlySpan()))
            {
                cpHashA.Dispose();
                policyRef.Dispose();
                authorizingSession?.NonceCaller.Dispose();

                return Reject(state, TpmCcConstants.TPM_CC_PolicySecret, TpmRcConstants.TPM_RC_CPHASH);
            }
        }

        PolicySessionState latchedSession = LatchSessionCpHash(session, cpHashA);
        if(!ReferenceEquals(latchedSession, session))
        {
            session = latchedSession;
            checkedState = checkedState with { PolicySessions = checkedState.PolicySessions.SetItem(session.Handle, session) };
        }

        //A negative expiration requests a ticket: mint the real TPM_ST_AUTH_SECRET ticket per equation 12
        //(Part 2, Table 111) through an async effect (the HMAC needs the registered digest/HMAC seam a pure transition cannot
        //reach — minting has no failure mode of its own, so the continuation always folds); a non-negative
        //expiration folds immediately with a NULL ticket (Part 3, Section 23.2.5). Either way the ticket's own
        //hierarchy field is authHandle's OWNING hierarchy (EntityGetHierarchyForPermanentHandle), never the raw
        //authHandle — TPM_RH_LOCKOUT (and any other non-hierarchy permanent handle this slice admits) is not
        //itself a legal TPMI_RH_HIERARCHY+ value.
        if(expiration < 0)
        {
            //The ticket HMAC's cpHash term is the session's own latched carrier, borrowed: the latch above has
            //already made the session its single owner, and an unrestricted call folds the empty sentinel — the
            //same octets the caller supplied either way.
            var action = new TpmMintPolicySecretTicketAction(
                session.Handle, authName, policyRef, session.PolicyHash, session.PolicyDigest, session.CpHash,
                TpmiRhHierarchy.FromValue(EntityGetHierarchyForPermanentHandle(authHandle)), timeout, isNonceTpmEmpty, checkedState.TimeEpoch, checkedState.ResetCount,
                authorizingSession);

            return Transition(
                checkedState with
                {
                    NextAction = action,
                    ResponseIntent = null
                },
                "PolicySecret:Requested");
        }

        //No ticket requested, but the deadline (when the caller supplied a non-zero expiration) still
        //participates in the session's timeout tracking (Part 3, Section 23.2.4) — only the response's
        //TPM2B_TIMEOUT/TPMT_TK_AUTH fields are NULL, per Section 23.2.5.
        return DeclarePolicySecretFold(checkedState, session, authName, policyRef, timeout, authorizingSession);
    }

    /// <summary>
    /// Declares <c>TPM2_PolicySecret()</c>'s policyDigest fold for the two arms that mint no ticket — a trial
    /// session and a non-negative expiration (TPM 2.0 Library Part 3, Section 23.4) — carrying the response
    /// payload those arms frame.
    /// </summary>
    /// <param name="state">The state to transition from.</param>
    /// <param name="session">The policy session being extended.</param>
    /// <param name="authName">The authorizing entity's Name term, folded into the policyDigest; a borrow or a handle value, never owned here.</param>
    /// <param name="policyRef">The policy reference in an owned carrier; ownership transfers into the fold action, whose effect is its terminal owner.</param>
    /// <param name="timeout">The session's own tracked deadline magnitude, ranked at the resume under Section 23.2.4's min-with-existing rule.</param>
    /// <param name="authorizingSession">The HMAC/POLICY session context to frame a session-authorized response for, or <see langword="null"/> for the password arm's direct response.</param>
    /// <returns>The <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the fold.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> DeclarePolicySecretFold(
        TpmSimulatorState state, PolicySessionState session, TpmHandleName authName, Tpm2bNonce policyRef,
        ulong timeout, PolicySecretAuthorizingSession? authorizingSession) =>
        DeclarePolicyDigestFold(
            state, session, TpmPolicyDigestFold.Secret, PolicySecretFoldLabel(authorizingSession),
            nameTerm: authName, policyRef: policyRef, timeoutMagnitude: timeout, authorizingSession: authorizingSession);

    /// <summary>
    /// The transition label <c>TPM2_PolicySecret()</c>'s fold emits, which differs by whether the response is
    /// the password arm's direct one or a session-authorized one that still needs a framing effect.
    /// </summary>
    /// <param name="authorizingSession">The session that authorized the call, or <see langword="null"/> for the password arm.</param>
    /// <returns>The label.</returns>
    private static string PolicySecretFoldLabel(PolicySecretAuthorizingSession? authorizingSession) =>
        authorizingSession is null ? "PolicySecret" : "PolicySecret:SessionResponseRequested";

    /// <summary>
    /// Installs the advanced policyDigest on the session and frames the PolicySecret response (Part 3, Section
    /// 23.4).
    /// </summary>
    /// <remarks>
    /// A NULL ticket is framed when <paramref name="ticketDigest"/> is <see langword="null"/> (a trial session,
    /// the immediate form, or a non-negative expiration); otherwise the real TPM_ST_AUTH_SECRET ticket is framed.
    /// Shared by the trial-session fold, the non-trial no-ticket fold, and the ticket-mint continuation, so every
    /// path installs the digest identically. Also applies Section 23.2.4's min-with-existing rule to the
    /// session's own tracked timeout (<c>ApplySessionTimeout</c>) — the trial fold always passes a zero timeout,
    /// so this is a no-op there, exactly as <c>PolicyContextUpdate</c>'s own "policyTimeout != 0" gate would
    /// produce. <paramref name="authorizingSession"/> <see langword="null"/> frames the password arm's direct
    /// response; otherwise a <see cref="TpmFramePolicySecretSessionResponseAction"/> is declared to roll that
    /// session's nonceTPM and frame a real response session entry (TPM 2.0 Library Part 1, clause 16.6.1) before
    /// the response is final.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="session">The policy session being extended.</param>
    /// <param name="foldedDigest">The advanced policyDigest in an owned carrier; ownership transfers to the session record.</param>
    /// <param name="timeout">The session's own tracked deadline magnitude, applied via <c>ApplySessionTimeout</c>; carried separately from <paramref name="framedTimeout"/> because a no-ticket fold still ranks a real deadline while framing a NULL one.</param>
    /// <param name="framedTimeout">The deadline as the <c>TPM2B_TIMEOUT</c> the response frames; owned, and the shared empty carrier when no ticket was minted.</param>
    /// <param name="hierarchy">The ticket's owning hierarchy.</param>
    /// <param name="ticketDigest">The minted ticket digest, or <see langword="null"/> for a NULL ticket; owned.</param>
    /// <param name="authorizingSession">The HMAC/POLICY session context to frame a session-authorized response for, or <see langword="null"/> for the password arm's direct response.</param>
    /// <returns>The <see cref="TransitionResult{TState, TStackSymbol}"/> carrying the framed response or the declared framing action.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of foldedDigest transfers to the installed PolicySessionState; the framed timeout and ticket digest transfer to the response intent or to the framing action, whose effect releases them once their octets are framed.")]
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> CompletePolicySecretFold(
        TpmSimulatorState state, PolicySessionState session, Tpm2bDigest foldedDigest,
        ulong timeout, Tpm2bTimeout framedTimeout, uint hierarchy, Tpm2bDigest? ticketDigest,
        PolicySecretAuthorizingSession? authorizingSession)
    {
        session = ApplySessionTimeout(session, timeout);

        TpmSimulatorState folded = state with { PolicySessions = state.PolicySessions.SetItem(session.Handle, session.WithPolicyDigest(foldedDigest)) };

        if(authorizingSession is null)
        {
            return Transition(
                folded with
                {
                    ResponseIntent = new TpmPolicySecretResponse(TpmRcConstants.TPM_RC_SUCCESS, framedTimeout, TpmiRhHierarchy.FromValue(hierarchy), ticketDigest)
                },
                PolicySecretFoldLabel(authorizingSession));
        }

        var action = new TpmFramePolicySecretSessionResponseAction(
            authorizingSession.SessionHandle, authorizingSession.IsPolicySession, authorizingSession.SessionAlg,
            authorizingSession.SessionKey, authorizingSession.AuthValue, authorizingSession.NonceCaller, authorizingSession.SessionAttributes,
            framedTimeout, TpmiRhHierarchy.FromValue(hierarchy), ticketDigest);

        return Transition(
            folded with
            {
                NextAction = action,
                ResponseIntent = null
            },
            PolicySecretFoldLabel(authorizingSession));
    }

    /// <summary>
    /// Frames the <c>TPM2_PolicySecret()</c> response once the effect has minted the requested ticket.
    /// </summary>
    /// <remarks>
    /// Minting an HMAC has no failure mode of its own, so this always proceeds to fold — there is no rejection
    /// branch (unlike <c>OnPolicySignedVerified</c>/<c>OnPolicyTicketVerified</c>, which react to a real
    /// verification outcome).
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="minted">The effect's result carrying the minted ticket.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnPolicySecretTicketMinted(TpmSimulatorState state, TpmPolicySecretTicketMinted minted)
    {
        TpmSimulatorState cleared = state with { NextAction = NullAction.Instance };
        PolicySessionState session = cleared.PolicySessions[minted.PolicySession];

        return CompletePolicySecretFold(
            cleared, session, minted.FoldedDigest, minted.Timeout.Magnitude, minted.Timeout, minted.Hierarchy.Value,
            minted.TicketDigest, minted.AuthorizingSession);
    }

    /// <summary>
    /// Rolls the authorizing session's nonceTPM to the freshly generated value and frames the session-authorized
    /// TPM2_PolicySecret() response (the effect's framed timeout/ticket parameter area and response session area).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The session record is replaced wholesale because its nonceTPM is immutable model state, replaced once per
    /// command (Part 1, clause 17.6.5) — routed to PolicySessions or HmacSessions per <c>IsPolicySession</c>,
    /// mirroring <c>OnEncryptedRandomProduced</c>'s own defensive "still present" re-check (a meanwhile-flushed
    /// session's framed response is still returned; only the table update is skipped).
    /// </para>
    /// <para>
    /// This is also the ONLY point a POLICY authorizer's context resets — the SessionResetPolicyData +
    /// SessionSetStartTime routines of TPM 2.0 Library Part 4, invoked from its UpdateInternalSession on every
    /// successful use of a policy session (Part 3, Section 23.2.4; Part 4's UpdateInternalSession/
    /// BuildSingleResponseAuth run only once the command dispatcher already returned success), applied here
    /// through the shared <see cref="ResetPolicySessionContext"/>, which enumerates exactly which of this model's
    /// <see cref="PolicySessionState"/> fields the reset clears and which it preserves. A self-referential
    /// PolicySecret (the authorizer IS the policySession parameter
    /// being extended) reads the just-folded PolicyDigest from PolicySessions before overwriting it here, so its
    /// own extension is legitimately wiped by this same reset — matching the reference exactly, since
    /// UpdateInternalSession fires unconditionally for the auth-area session regardless of what the command itself
    /// did to that session's digest.
    /// </para>
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="framed">The effect's result carrying the rolled nonceTPM and the framed response parameter area and HMAC.</param>
    /// <returns>The <see cref="TransitionResult{TState, TStackSymbol}"/> carrying the framed session-authorized response.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnPolicySecretSessionResponseFramed(TpmSimulatorState state, TpmPolicySecretSessionResponseFramed framed)
    {
        ImmutableDictionary<TpmiShHmac, HmacSessionState> hmacSessions = state.HmacSessions;
        ImmutableDictionary<TpmiShPolicy, PolicySessionState> policySessions = state.PolicySessions;

        if(framed.IsPolicySession)
        {
            policySessions = RollPolicySessionNonce(policySessions, framed.SessionHandle, state.Time, framed.RetainedNonceTpm);
        }
        else
        {
            hmacSessions = RollHmacSessionNonce(hmacSessions, framed.SessionHandle, framed.RetainedNonceTpm);
        }

        return Transition(
            state with
            {
                NextAction = NullAction.Instance,
                HmacSessions = hmacSessions,
                PolicySessions = policySessions,
                ResponseIntent = new TpmPolicySecretOverSessionResponse(
                    TpmRcConstants.TPM_RC_SUCCESS, framed.ParameterArea, framed.NewNonceTpm,
                    framed.SessionAttributes, framed.Hmac)
            },
            "PolicySecret:SessionResponseCompleted");
    }

    /// <summary>
    /// Binds a policy session to a signature over
    /// <c>aHash = H_authAlg(nonceTPM || expiration || cpHashA || policyRef)</c> made by the key at authObject,
    /// for <c>TPM2_PolicySigned()</c> (Part 3, Section 23.3).
    /// </summary>
    /// <remarks>
    /// Neither handle requires authorization; unlike <c>TPM2_VerifySignature()</c>, authObject's sign attribute
    /// is never consulted (any loaded public key validates — <c>CryptValidateSignature</c>'s own design,
    /// deliberately different from VerifySignature's <c>TPMA_OBJECT.sign</c> gate). A trial session skips every
    /// parameter/signature check and folds unconditionally (the whole point of a trial session: predicting the
    /// digest a real signed authorization would produce without holding the private key). A non-trial session
    /// runs the checks in spec order — nonceTPM, expiration/deadline, cpHashA size+first-writer-wins latch,
    /// scheme-hash support, then key-type dispatch — before the signature verification itself is folded into an
    /// effect (<c>TpmVerifyPolicySignedAction</c>/<c>TpmRsaVerifyPolicySignedAction</c>), since that needs the
    /// async digest/verify seam a pure transition cannot reach. See the single-source-of-truth note on
    /// <c>OnPolicyCommandCode</c> for the digest fold itself.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_PolicySigned()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnPolicySigned(TpmSimulatorState state, TpmPolicySignedRequested request)
    {
        if(!state.PolicySessions.TryGetValue(request.PolicySession, out PolicySessionState? session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicySigned, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        if(!state.TransientObjects.TryGetValue(request.AuthObject, out TransientKeyState? authObject))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicySigned, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        //Trial session: skip ALL parameter and signature checks (Part 3, Section 23.3: "If policySession is a
        //trial session, the TPM will not check the signature... as if a properly signed authorization was
        //received") and fold unconditionally, using whatever authObjectName/policyRef the caller supplied. A
        //trial session never mints a ticket regardless of the caller's expiration, and inspects neither nonceTPM
        //nor cpHashA, so those two carriers have no later owner and are released here; policyRef transfers into
        //the fold below.
        if(session.IsTrial)
        {
            request.NonceTpm.Dispose();
            request.CpHashA.Dispose();

            return DeclarePolicyDigestFold(
                state, session, TpmPolicyDigestFold.Signed, "PolicySigned",
                nameTerm: TpmHandleName.FromName(authObject.Name), policyRef: request.PolicyRef);
        }

        //(1) nonceTPM: only checked when the caller supplies a non-empty value; an empty caller nonce always
        //passes (a session-unbound authorization, Part 3, clause 23.2.2). The carrier stays owned by the
        //request until the accepting arm below transfers it into the verification action. A mismatch answers
        //the code the rule itself names — clause 23.2.2, printed page 189, rule 1: "nonceTPM - If this parameter
        //is not the Empty Buffer, and it does not match policySession->nonceTPM, then the TPM shall return
        //TPM_RC_VALUE."
        if(!request.NonceTpm.IsEmpty && !request.NonceTpm.AsReadOnlySpan().SequenceEqual(session.NonceTpm.AsReadOnlySpan()))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicySigned, TpmRcConstants.TPM_RC_VALUE, request);
        }

        //(2) expiration -> inline deadline: an empty caller nonce means an absolute Time-base deadline; a
        //non-empty one means a deadline relative to the session's captured StartTime. The sign of expiration
        //marks "ticket requested" (negative) — its magnitude is threaded into the mint below, not recomputed.
        ulong timeout = 0ul;
        if(request.Expiration != 0)
        {
            ulong magnitudeMs = (ulong)System.Math.Abs((long)request.Expiration) * 1000UL;

            //The absolute (empty-nonce) deadline is aligned to the current sub-second remainder of Time so the
            //expiration granularity stays whole seconds from "now" rather than from the Time base's zero point
            //(Part 3, Section 23.2.2's timeout derivation); the session-relative form needs no alignment because
            //StartTime already carries the sub-second component.
            ulong deadline = request.NonceTpm.IsEmpty ? magnitudeMs + (state.Time % 1000UL) : session.StartTime + magnitudeMs;

            if(deadline < state.Time)
            {
                return Reject(state, TpmCcConstants.TPM_CC_PolicySigned, TpmRcConstants.TPM_RC_EXPIRED, request);
            }

            timeout = deadline;
        }

        //(3) cpHashA: only checked when non-empty. Size must equal the session's digest width; a differing value
        //already latched onto the session is rejected. An UNLATCHED session's cpHash is deliberately NOT
        //written here — the signature has not been verified yet, and the latch is part of Section 23.2.4's
        //"first-writer-wins" state, not a pre-verification side effect. Only OnPolicySignedVerified's success
        //arm writes it, so a TPM_RC_SIGNATURE rejection truly leaves the session unchanged, matching this
        //function's own doc comment and OnPolicySignedVerified's.
        if(!request.CpHashA.IsEmpty)
        {
            if(request.CpHashA.Size != TpmPolicyDigest.Size(session.PolicyHash.Value))
            {
                return Reject(state, TpmCcConstants.TPM_CC_PolicySigned, TpmRcConstants.TPM_RC_SIZE, request);
            }

            if(!session.CpHash.IsEmpty && !request.CpHashA.AsReadOnlySpan().SequenceEqual(session.CpHash.AsReadOnlySpan()))
            {
                return Reject(state, TpmCcConstants.TPM_CC_PolicySigned, TpmRcConstants.TPM_RC_CPHASH, request);
            }
        }

        //Scheme-hash support (Part 3, Section 23.3): an unsupported/zero-width scheme hash fails closed with
        //TPM_RC_SCHEME before any verification is attempted, mirroring TPM2_VerifySignature()'s own gate.
        if(!IsSupportedAttestHashAlg(request.SchemeHashAlg))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicySigned, TpmRcConstants.TPM_RC_SCHEME, request);
        }

        //The cpHashA and policyRef carriers transfer into the action, whose effect folds the policyDigest and
        //hands cpHashA on to the continuation that latches or releases it.
        TpmAction? action = (authObject.KeyType.Value, request.SignatureScheme.Value) switch
        {
            (TpmAlgIdConstants.TPM_ALG_RSA, TpmAlgIdConstants.TPM_ALG_RSASSA or TpmAlgIdConstants.TPM_ALG_RSAPSS) =>
                new TpmRsaVerifyPolicySignedAction(
                    request.PolicySession, authObject.Name, request.PolicyRef, session.PolicyHash, session.PolicyDigest, request.NonceTpm, request.Expiration,
                    request.CpHashA, authObject.PrivateKey, request.Signature, request.SignatureScheme, request.SchemeHashAlg,
                    authObject.Hierarchy, timeout, state.TimeEpoch, state.ResetCount),
            (TpmAlgIdConstants.TPM_ALG_ECC, TpmAlgIdConstants.TPM_ALG_ECDSA) =>
                new TpmVerifyPolicySignedAction(
                    request.PolicySession, authObject.Name, request.PolicyRef, session.PolicyHash, session.PolicyDigest, request.NonceTpm, request.Expiration,
                    request.CpHashA, authObject.PublicPoint, authObject.Curve, request.Signature, request.SchemeHashAlg,
                    authObject.Hierarchy, timeout, state.TimeEpoch, state.ResetCount),
            _ => null
        };

        if(action is null)
        {
            //A scheme incompatible with authObject's key type — e.g. an ECDSA scheme against an RSA key, or vice
            //versa — fails closed rather than silently coercing to the key's native scheme (mirrors OnVerifySignature).
            return Reject(state, TpmCcConstants.TPM_CC_PolicySigned, TpmRcConstants.TPM_RC_SCHEME, request);
        }

        return Transition(
            state with
            {
                NextAction = action,
                ResponseIntent = null
            },
            "PolicySigned:Requested");
    }

    /// <summary>
    /// Installs the advanced policyDigest on the session and frames the PolicySigned response — a NULL ticket
    /// when ticketDigest is null (a trial session, or a non-negative expiration, Part 3, Section 23.2.5), or the
    /// real <c>TPM_ST_AUTH_SIGNED</c> ticket otherwise.
    /// </summary>
    /// <remarks>
    /// Shared by the trial-session fold and the non-trial continuation's success branch, so both paths install
    /// the digest identically. Also applies Section 23.2.4's min-with-existing rule to the session's own tracked
    /// timeout (<c>ApplySessionTimeout</c>) — the trial fold always passes a zero timeout, so this is a no-op
    /// there, exactly as <c>PolicyContextUpdate</c>'s own "policyTimeout != 0" gate would produce.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="session">The session whose policyDigest is being installed.</param>
    /// <param name="foldedDigest">The advanced policyDigest in an owned carrier; ownership transfers to the session record.</param>
    /// <param name="timeout">The requested deadline magnitude to apply via <c>ApplySessionTimeout</c>; carried separately from <paramref name="framedTimeout"/> because a no-ticket fold still ranks a real deadline while framing a NULL one.</param>
    /// <param name="framedTimeout">The deadline as the <c>TPM2B_TIMEOUT</c> the response frames; owned, and the shared empty carrier when no ticket was minted.</param>
    /// <param name="hierarchy">The ticket's hierarchy, when a ticket is minted.</param>
    /// <param name="ticketDigest">The minted ticket digest, or <see langword="null"/> for no ticket; owned.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> carrying the framed response.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> CompletePolicySignedFold(
        TpmSimulatorState state, PolicySessionState session, Tpm2bDigest foldedDigest,
        ulong timeout, Tpm2bTimeout framedTimeout, uint hierarchy, Tpm2bDigest? ticketDigest) =>
        StorePolicyDigest(
            state, ApplySessionTimeout(session, timeout), foldedDigest,
            new TpmPolicySignedResponse(TpmRcConstants.TPM_RC_SUCCESS, framedTimeout, TpmiRhHierarchy.FromValue(hierarchy), ticketDigest),
            "PolicySigned");

    /// <summary>
    /// Frames the <c>TPM2_PolicySigned()</c> response the effect produced: on a successful verification,
    /// latches <c>verified.CpHashA</c> onto the session's first-writer-wins cpHash (Part 3, Section 23.2.4) if
    /// it is not already latched, then folds the policyDigest via <c>FoldPolicySigned</c> (threading through
    /// whatever ticket the effect minted, if any); on <c>TPM_RC_SIGNATURE</c>, rejects with no change to the
    /// session (mirroring <c>OnSignatureVerified</c>'s success/rejection split).
    /// </summary>
    /// <remarks>
    /// The cpHash latch is written ONLY here, on success, never by the pure pre-dispatch transition, so a
    /// failed signature verification cannot poison a session it never actually authorized. Either way
    /// NextAction is cleared here — this transition runs as effect feedback, not through
    /// <c>OnExternalInput</c>, so nothing else resets it.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="verified">The effect's result carrying the verification outcome.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnPolicySignedVerified(TpmSimulatorState state, TpmPolicySignedVerified verified)
    {
        TpmSimulatorState cleared = state with { NextAction = NullAction.Instance };

        if(verified.ResponseCode != TpmRcConstants.TPM_RC_SUCCESS)
        {
            //Nothing was folded and nothing latches, so this arm is the relayed cpHashA carrier's terminal owner.
            verified.CpHashA.Dispose();

            return Transition(
                cleared with { ResponseIntent = new TpmHeaderOnlyResponse(verified.ResponseCode) },
                "PolicySigned:Rejected");
        }

        PolicySessionState session = cleared.PolicySessions[verified.PolicySession];
        session = LatchSessionCpHash(session, verified.CpHashA);

        return CompletePolicySignedFold(
            cleared, session, verified.FoldedDigest,
            verified.Timeout, verified.FramedTimeout, verified.Hierarchy.Value, verified.TicketDigest);
    }

    /// <summary>
    /// Applies TPM 2.0 Library Part 3, Section 23.2.4's first-writer-wins cpHash latch to a session that has
    /// just successfully authorized: an unlatched session TAKES OWNERSHIP of <paramref name="cpHashA"/>, and any
    /// other outcome releases it here.
    /// </summary>
    /// <remarks>
    /// The differing-value rejection is not this function's: every caller answers it first — the verification
    /// continuations because their own pre-dispatch transition did, which is what keeps a failed verification
    /// from poisoning a session it never authorized, and <c>TPM2_PolicySecret()</c>'s authorization ladder in
    /// the step just above its call. What is left here is the accepted arm's one rule — transfer when
    /// unlatched, release when the session already carries the same value or the caller restricted nothing.
    /// </remarks>
    /// <param name="session">The session to latch.</param>
    /// <param name="cpHashA">The verified cpHashA in an owned carrier; ownership transfers to the session or ends here.</param>
    /// <returns>The session, latched when it was not already.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of cpHashA transfers to the returned session through WithCpHash on the unlatched arm; every other arm releases it here, so the carrier has exactly one terminal owner either way.")]
    private static PolicySessionState LatchSessionCpHash(PolicySessionState session, Tpm2bDigest cpHashA)
    {
        if(cpHashA.IsEmpty || !session.CpHash.IsEmpty)
        {
            cpHashA.Dispose();

            return session;
        }

        return session.WithCpHash(cpHashA);
    }

    /// <summary>
    /// Lets an object's fixed authPolicy accept a policy the authority can revise at will, for
    /// <c>TPM2_PolicyAuthorize()</c> (Part 3, Section 23.16): when the session's current policyDigest equals the
    /// caller-supplied approvedPolicy and checkTicket proves keySign signed
    /// <c>H(approvedPolicy || policyRef)</c>, the policyDigest is NOT folded onto the accumulated value — it is
    /// RESET to zero and refolded from keySign and policyRef alone (<c>ExtendForAuthorize</c>), so the result
    /// depends only on the authority's key and the qualifier, never on whatever policy actually produced
    /// approvedPolicy.
    /// </summary>
    /// <remarks>
    /// The keySign hash-algorithm/size checks run for a trial session too; the approvedPolicy-equality and
    /// ticket-re-verification checks are non-trial only, and the re-verification itself is folded into an
    /// effect (<c>TpmVerifyPolicyAuthorizeTicketAction</c>) since it needs the async digest/HMAC seam a pure
    /// transition cannot reach. See the single-source-of-truth note on <c>OnPolicyCommandCode</c> for the digest
    /// fold itself.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_PolicyAuthorize()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnPolicyAuthorize(TpmSimulatorState state, TpmPolicyAuthorizeRequested request)
    {
        if(!state.PolicySessions.TryGetValue(request.PolicySession, out PolicySessionState? session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicyAuthorize, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        //(1) hashAlg = the first two octets of keySign (Part 2, Section 10.5.3); unrecognized -> TPM_RC_HASH.
        //The remainder must be exactly that hash's digest width -> TPM_RC_SIZE. Both run for a trial session too.
        if(request.KeySign.Size < sizeof(ushort))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicyAuthorize, TpmRcConstants.TPM_RC_SIZE, request);
        }

        TpmiAlgHash hashAlg = TpmiAlgHash.FromValue((TpmAlgIdConstants)BinaryPrimitives.ReadUInt16BigEndian(request.KeySign.Span));
        if(!IsSupportedAttestHashAlg(hashAlg))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicyAuthorize, TpmRcConstants.TPM_RC_HASH, request);
        }

        if(request.KeySign.Size - sizeof(ushort) != TpmPolicyDigest.Size(hashAlg.Value))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicyAuthorize, TpmRcConstants.TPM_RC_SIZE, request);
        }

        //Trial session: skip the approvedPolicy equality check and the ticket re-verification (Part 3, Section
        //23.16: "policySession->policyDigest is extended as if the ticket is valid without actual verification")
        //and fold unconditionally. The Name and qualifier carriers transfer into the fold, whose effect is their
        //terminal owner; the approved policy and the caller's ticket digest are never read on this arm.
        if(session.IsTrial)
        {
            request.ApprovedPolicy.Dispose();
            request.CheckTicketDigest.Dispose();

            return DeclarePolicyDigestFold(
                state, session, TpmPolicyDigestFold.Authorize, "PolicyAuthorize",
                policyRef: request.PolicyRef, keySign: request.KeySign);
        }

        //(2) approvedPolicy must equal the session's current policyDigest (Part 3, Section 23.16).
        if(!CryptographicOperations.FixedTimeEquals(request.ApprovedPolicy.AsReadOnlySpan(), session.PolicyDigest.AsReadOnlySpan()))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicyAuthorize, TpmRcConstants.TPM_RC_VALUE, request);
        }

        //All four carriers transfer into the action, whose effect re-verifies the ticket, folds the policyDigest,
        //and is their terminal owner.
        var action = new TpmVerifyPolicyAuthorizeTicketAction(
            request.PolicySession, request.ApprovedPolicy, request.PolicyRef, request.KeySign, hashAlg,
            request.CheckTicketHierarchy, request.CheckTicketDigest, session.PolicyHash);

        return Transition(
            state with
            {
                NextAction = action,
                ResponseIntent = null
            },
            "PolicyAuthorize:Requested");
    }

    /// <summary>
    /// Frames the <c>TPM2_PolicyAuthorize()</c> response the effect produced: on a successful ticket
    /// re-verification, folds the policyDigest via <c>FoldPolicyAuthorize</c>; on <c>TPM_RC_VALUE</c>, rejects
    /// with no change to the session (mirroring <c>OnPolicySignedVerified</c>'s success/rejection split).
    /// </summary>
    /// <remarks>
    /// Either way NextAction is cleared here — this transition runs as effect feedback, not through
    /// <c>OnExternalInput</c>, so nothing else resets it.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="verified">The effect's result carrying the re-verification outcome.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnPolicyAuthorizeVerified(TpmSimulatorState state, TpmPolicyAuthorizeVerified verified)
    {
        TpmSimulatorState cleared = state with { NextAction = NullAction.Instance };

        if(verified.ResponseCode != TpmRcConstants.TPM_RC_SUCCESS)
        {
            return Transition(
                cleared with { ResponseIntent = new TpmHeaderOnlyResponse(verified.ResponseCode) },
                "PolicyAuthorize:Rejected");
        }

        PolicySessionState session = cleared.PolicySessions[verified.PolicySession];

        return StorePolicyDigest(
            cleared, session, verified.FoldedDigest, new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS), "PolicyAuthorize");
    }

    /// <summary>
    /// Authorizes a policy session by replaying a ticket a prior <c>TPM2_PolicySigned()</c> or
    /// <c>TPM2_PolicySecret()</c> produced, for <c>TPM2_PolicyTicket()</c> (TPM 2.0 Library Part 3, Section
    /// 23.5).
    /// </summary>
    /// <remarks>
    /// <para>
    /// A TRIAL session is rejected outright with <c>TPM_RC_ATTRIBUTES</c> (Section 23.5.1's own prose says
    /// nothing about trial sessions; the general "trial sessions always succeed" default of Section 23.1 would
    /// predict this command succeeds too — but the ticket IS the real authorization material a trial session
    /// exists to predict without holding, so "predicting" via a ticket is meaningless; this rejection is a
    /// genuine, deliberate exception the reference implementation enforces explicitly, not inferable from this
    /// command's own prose).
    /// </para>
    /// <para>
    /// Two distinct size rules bound the wire timeout, and they answer at different places. The generic
    /// <c>TPM2B_TIMEOUT</c> bound of <c>sizeof(UINT64)</c> (Part 2, clause 10.4.10, Table 100) is answered at
    /// the parse, ahead of this command body entirely, which is where the reference's own unmarshal applies it —
    /// so a timeout wider than 8 octets is <c>TPM_RC_SIZE</c> regardless of the session it names, trial
    /// included. The command-specific "exactly 8 octets" rule is this transition's, and it runs
    /// AFTER the trial-session rejection, so a timeout of 0 to 7 octets on a trial session answers
    /// <c>TPM_RC_ATTRIBUTES</c>. Bit 63 (expires on reset) is extracted and cleared before anything else
    /// consumes the raw value.
    /// </para>
    /// <para>
    /// There is no nonceTPM here (unlike PolicySigned/PolicySecret) — the session-binding-vs-absolute
    /// distinction was baked into the timeout at mint time. The live-clock expiry check (this simulator's own
    /// <c>state.Time</c>) and the cpHashA size+first-writer-wins latch mirror PolicySigned's own shared-function
    /// checks exactly; the reference's separate "session->epoch != g_timeEpoch" pre-check has no equivalent
    /// here (<see cref="PolicySessionState"/> carries no per-session epoch field, and this simulator's own
    /// StartTime doc comment argues that a session-level epoch would be moot regardless, since every TPM Reset
    /// already clears PolicySessions wholesale) — instead, epoch consistency is enforced entirely by the
    /// ticket-HMAC recompute below, which uses the TPM's CURRENT TimeEpoch: a ticket minted under a
    /// since-regenerated epoch simply fails to recompute and answers <c>TPM_RC_TICKET</c>, achieving the same
    /// cross-discontinuity replay defense equation 12 (Part 2, Table 111)'s [timeEpoch] term exists for. The recompute-and-compare
    /// itself needs the async digest/HMAC seam a pure transition cannot reach, so it is folded into an effect
    /// (<c>TpmVerifyPolicyTicketAction</c>).
    /// </para>
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_PolicyTicket()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnPolicyTicket(TpmSimulatorState state, TpmPolicyTicketRequested request)
    {
        if(!state.PolicySessions.TryGetValue(request.PolicySession, out PolicySessionState? session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicyTicket, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        if(session.IsTrial)
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicyTicket, TpmRcConstants.TPM_RC_ATTRIBUTES, request);
        }

        if(request.Timeout.Length != sizeof(ulong))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicyTicket, TpmRcConstants.TPM_RC_SIZE, request);
        }

        ulong rawTimeout = request.Timeout.Value;
        bool expiresOnReset = (rawTimeout & TpmSimulator.TimeoutExpiresOnResetBit) != 0;
        ulong authTimeout = rawTimeout & ~TpmSimulator.TimeoutExpiresOnResetBit;

        //Expiry against the live clock (Part 3, Section 23.2.2, shared with PolicySigned/PolicySecret): not
        //evaluated when authTimeout is zero (a replayed ticket with no expiration at all).
        if(authTimeout != 0 && authTimeout < state.Time)
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicyTicket, TpmRcConstants.TPM_RC_EXPIRED, request);
        }

        //cpHashA: only checked when non-empty. Size must equal the session's digest width; a differing value
        //already latched onto the session is rejected. An UNLATCHED session's cpHash is deliberately NOT
        //written here — the ticket has not been re-verified yet, and the latch is part of Section 23.2.4's
        //"first-writer-wins" state, not a pre-verification side effect. Only OnPolicyTicketVerified's success
        //arm writes it, so a TPM_RC_TICKET rejection truly leaves the session unchanged, matching this
        //function's own doc comment and OnPolicyTicketVerified's.
        if(!request.CpHashA.IsEmpty)
        {
            if(request.CpHashA.Size != TpmPolicyDigest.Size(session.PolicyHash.Value))
            {
                return Reject(state, TpmCcConstants.TPM_CC_PolicyTicket, TpmRcConstants.TPM_RC_SIZE, request);
            }

            if(!session.CpHash.IsEmpty && !request.CpHashA.AsReadOnlySpan().SequenceEqual(session.CpHash.AsReadOnlySpan()))
            {
                return Reject(state, TpmCcConstants.TPM_CC_PolicyTicket, TpmRcConstants.TPM_RC_CPHASH, request);
            }
        }

        //The wire timeout has been consumed into authTimeout/expiresOnReset above, so this arm is its terminal
        //owner; the remaining four carriers transfer into the action, whose effect re-verifies the ticket, folds
        //the policyDigest, and hands cpHashA on to the continuation that latches or releases it.
        request.Timeout.Dispose();

        var action = new TpmVerifyPolicyTicketAction(
            request.PolicySession, request.TicketTag, request.TicketHierarchy, request.TicketDigest, request.CpHashA,
            request.PolicyRef, request.AuthName, session.PolicyDigest, authTimeout, expiresOnReset, state.TimeEpoch, state.ResetCount, session.PolicyHash);

        return Transition(
            state with
            {
                NextAction = action,
                ResponseIntent = null
            },
            "PolicyTicket:Requested");
    }

    /// <summary>
    /// Frames the <c>TPM2_PolicyTicket()</c> response the effect produced: on a successful re-verification,
    /// latches <c>verified.CpHashA</c> onto the session's first-writer-wins cpHash (Part 3, Section 23.2.4) if
    /// it is not already latched, applies Section 23.2.4's min-with-existing rule to the session's own tracked
    /// timeout (<c>ApplySessionTimeout</c>), then folds the policyDigest via the ORIGINAL command's own fold —
    /// <c>ExtendForSigned</c> when the ticket's tag is <c>TPM_ST_AUTH_SIGNED</c>, <c>ExtendForSecret</c> when
    /// <c>TPM_ST_AUTH_SECRET</c> (Part 3, Section 23.5.1's own <c>PolicyUpdate(commandCode, authName,
    /// policyRef)</c> dispatch) — NEVER a <c>TPM_CC_PolicyTicket</c>-keyed fold, so a session that reaches a
    /// given policyDigest via the ticket ends up identical to one that reached it via the original
    /// PolicySigned()/PolicySecret() call. On <c>TPM_RC_TICKET</c>, rejects with no change to the session
    /// (mirroring <c>OnPolicySignedVerified</c>/<c>OnPolicyAuthorizeVerified</c>'s own success/rejection split).
    /// </summary>
    /// <remarks>
    /// The cpHash latch and timeout update are written ONLY here, on success, never by the pure pre-dispatch
    /// transition, so a failed re-verification cannot poison a session it never actually authorized. Either way
    /// NextAction is cleared here — this transition runs as effect feedback, not through
    /// <c>OnExternalInput</c>, so nothing else resets it.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="verified">The effect's result carrying the re-verification outcome.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnPolicyTicketVerified(TpmSimulatorState state, TpmPolicyTicketVerified verified)
    {
        TpmSimulatorState cleared = state with { NextAction = NullAction.Instance };

        if(verified.ResponseCode != TpmRcConstants.TPM_RC_SUCCESS)
        {
            //Nothing was folded and nothing latches, so this arm is the relayed cpHashA carrier's terminal owner.
            verified.CpHashA.Dispose();

            return Transition(
                cleared with { ResponseIntent = new TpmHeaderOnlyResponse(verified.ResponseCode) },
                "PolicyTicket:Rejected");
        }

        PolicySessionState session = cleared.PolicySessions[verified.PolicySession];
        session = ApplySessionTimeout(LatchSessionCpHash(session, verified.CpHashA), verified.Timeout);

        return StorePolicyDigest(cleared, session, verified.FoldedDigest, new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS), "PolicyTicket");
    }

    /// <summary>
    /// Binds a policy to a comparison against an NV Index's contents for <c>TPM2_PolicyNV()</c> (Part 3, clause
    /// 23.9).
    /// </summary>
    /// <remarks>
    /// The Index must be defined; an unknown Index or session handle is <c>TPM_RC_HANDLE</c>. The read is
    /// authorized by the entity <c>authHandle</c> names, resolved before the command body for trial and real
    /// sessions alike (Part 3, clause 5.6) with <c>OnNvRead</c>'s owner arm (gated on
    /// <c>TPMA_NV_OWNERREAD</c>, its compare dictionary-attack exempt per Part 1, clause 17.8.1) or the
    /// Index's own authValue behind the Index's DA/PIN/<c>TPMA_NV_AUTHREAD</c> availability gates, all ahead
    /// of the compare, which then feeds <c>RejectNvAuthFailure</c> and the PIN counter on the outcome —
    /// <c>OnNvCertify</c>'s Index-arm placement.
    /// On a REAL (non-trial) session the retained Index data at the offset is then compared to operandB per the
    /// <c>TPM_EO</c> operation (<c>TPM_RC_POLICY</c> on a false result) before the digest folds; a TRIAL
    /// session skips the comparison entirely — only the Index Name and the arguments drive the digest. See the
    /// note on <c>OnPolicyCommandCode</c>.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_PolicyNV()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the Name-computation action, or a rejection.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnPolicyNv(TpmSimulatorState state, TpmPolicyNvRequested request)
    {
        if(!state.PolicySessions.TryGetValue(request.PolicySession, out PolicySessionState? session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicyNV, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        if(!state.NvIndexes.TryGetValue(request.NvIndex, out NvIndexState? index))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicyNV, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        //An owner-authorized read is administrative: compared against the owner hierarchy's own authValue,
        //which is never dictionary-attack protected (Part 1, clause 17.8.1), so a mismatch is a plain
        //bad-authorization; none of the Index-arm gates below apply (pinCount moves only when the INDEX's own
        //authValue resolves the authorization, Part 1, clause 37.2.6.6). Mirrors OnNvRead's owner arm exactly.
        if(request.AuthHandle.Value == (uint)TpmRh.TPM_RH_OWNER)
        {
            //With TPMA_NV_OWNERREAD clear owner authorization cannot read this Index (Part 3, clause 23.9) —
            //checked BEFORE the owner-auth compare, the same non-leaking order OnNvRead's owner arm uses.
            if(!index.IsOwnerReadAllowed)
            {
                return Reject(state, TpmCcConstants.TPM_CC_PolicyNV, TpmRcConstants.TPM_RC_NV_AUTHORIZATION, request);
            }

            if(!CryptographicOperations.FixedTimeEquals(
                StripTrailingZeros(request.SuppliedAuthPassword.AsReadOnlySpan()),
                StripTrailingZeros(state.OwnerAuth.AsReadOnlySpan())))
            {
                return Reject(state, TpmCcConstants.TPM_CC_PolicyNV, TpmRcConstants.TPM_RC_BAD_AUTH, request);
            }
        }
        else if(request.AuthHandle.Value != request.NvIndex.Value)
        {
            //Only Index authorization (authHandle == nvIndex) and the owner arm are modelled this slice,
            //matching OnNvRead; policy-authorized reads against the same Index arrive later.
            return Reject(state, TpmCcConstants.TPM_CC_PolicyNV, TpmRcConstants.TPM_RC_AUTH_TYPE, request);
        }
        else
        {
            //Already-locked-out DA-protected Index: refuse before even comparing (clause 17.8.3), no further
            //increment.
            if(IsNvIndexLockedOut(state, index))
            {
                return Reject(state, TpmCcConstants.TPM_CC_PolicyNV, TpmRcConstants.TPM_RC_LOCKOUT, request);
            }

            //A PIN Index's own authValue is not usable while unwritten or once pinCount has reached pinLimit
            //(clause 37.2.6.6) — refused before even comparing, OnNvRead's Index-arm gate.
            if(IsPinAuthUnavailable(index))
            {
                return Reject(state, TpmCcConstants.TPM_CC_PolicyNV, TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, request);
            }

            //With TPMA_NV_AUTHREAD clear the Index authValue cannot authorize a read (Part 2, clause 13.4), so
            //the assertion is refused BEFORE the compare (Part 3, clause 5.6, check 7.2.2, ordered ahead of the
            //authValue checks) — no dictionary-attack charge and no pinCount touch, regardless of whether the
            //supplied value is correct. The OnNvCertify sign-arm placement.
            if(!index.IsAuthReadAllowed)
            {
                return Reject(state, TpmCcConstants.TPM_CC_PolicyNV, TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, request);
            }

            //Constant-time comparison of the supplied authorization against the Index authValue. A mismatch is
            //an auth-failure for a DA-protected Index (clause 17.8.3 — feeds the lockout counter) and a plain
            //bad-authorization for a non-DA Index (clause 17.8.1). A PIN Index's own pinCount is updated on
            //either outcome (clause 37.2.6.6), exactly as OnNvRead.
            bool authMatched = CryptographicOperations.FixedTimeEquals(
                StripTrailingZeros(request.SuppliedAuthPassword.AsReadOnlySpan()),
                StripTrailingZeros(index.AuthValue.AsReadOnlySpan()));
            if(index.IsPinIndex)
            {
                index = ApplyPinAuthOutcome(index, authMatched);
                state = state with { NvIndexes = state.NvIndexes.SetItem(index.NvIndex, index) };
            }

            if(!authMatched)
            {
                request.Dispose();

                return RejectNvAuthFailure(state, index, TpmCcConstants.TPM_CC_PolicyNV);
            }
        }

        if(!session.IsTrial)
        {
            //The model retains only the octets actually written (its NvIndexState.Data grows with each write, as
            //OnNvRead's own bound already treats it), so a compared window beyond the retained extent — including
            //an unwritten Index's empty Data — is out of range (TPM_RC_NV_RANGE, Part 3, clause 31.13).
            if((long)request.Offset + request.OperandB.Length > index.Data.Length)
            {
                return Reject(state, TpmCcConstants.TPM_CC_PolicyNV, TpmRcConstants.TPM_RC_NV_RANGE, request);
            }

            ReadOnlySpan<byte> comparand = index.Data.Span.Slice(request.Offset, request.OperandB.Length);
            if(!TpmEoComparator.TryEvaluate(comparand, request.OperandB.Span, (TpmEoConstants)request.Operation, out bool matched, out TpmRcConstants rejectionCode))
            {
                return Reject(state, TpmCcConstants.TPM_CC_PolicyNV, rejectionCode, request);
            }

            if(!matched)
            {
                return Reject(state, TpmCcConstants.TPM_CC_PolicyNV, TpmRcConstants.TPM_RC_POLICY, request);
            }
        }

        //The transition is the password carrier's terminal owner — the authorization arm was its only use.
        request.SuppliedAuthPassword.Dispose();

        //The Index's Name needs the asynchronous digest seam (TPM digests belong there, not the sync seam a pure
        //transition could reach on its own), so the transition declares a TpmComputeNvNameAction carrying the
        //Index's own retained public-area fields (its real NameAlg and AuthPolicy, TPM 2.0 Library Part 1,
        //Table 6 — never a fixed assumption) and the pending assertion's arguments, and leaves no response yet;
        //OnNvNameComputedForPolicy extends the policyDigest once the Name comes back.
        return Transition(
            state with
            {
                NextAction = new TpmComputeNvNameAction(
                    request.PolicySession, index.NvIndex, index.Attributes, index.DataSize, index.NameAlg, index.AuthPolicy,
                    request.OperandB, request.Offset, request.Operation, session.PolicyHash, session.PolicyDigest),
                ResponseIntent = null
            },
            "PolicyNV:Requested");
    }

    /// <summary>
    /// Extends the policy session's policyDigest with the NV Index's computed Name and completes
    /// <c>TPM2_PolicyNV()</c> (TPM 2.0 Library Part 3, clause 23.9). See the single-source-of-truth note on
    /// <c>OnPolicyCommandCode</c>.
    /// </summary>
    /// <remarks>
    /// The session was already resolved by <c>OnPolicyNv</c> and cannot vanish before this feedback arrives
    /// (the automaton is single-threaded, so no other command interleaves), exactly as every other action
    /// feedback in this file trusts its resolved state without re-checking.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="computed">The effect's result carrying the computed NV Index Name.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the folded policyDigest transfers to the installed PolicySessionState, which releases it at the next assertion or at eviction.")]
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnNvNameComputedForPolicy(TpmSimulatorState state, TpmNvNameComputedForPolicy computed)
    {
        PolicySessionState session = state.PolicySessions[computed.PolicySession];

        return Transition(
            state with
            {
                NextAction = NullAction.Instance,
                PolicySessions = state.PolicySessions.SetItem(session.Handle, session.WithPolicyDigest(computed.FoldedDigest)),
                ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
            },
            "PolicyNV:Completed");
    }

    /// <summary>
    /// Binds a policy to a comparison against the TPM's live <c>TPMS_TIME_INFO</c> (Time, Clock, resetCount,
    /// restartCount, Safe) for <c>TPM2_PolicyCounterTimer()</c> (Part 3, clause 23.10).
    /// </summary>
    /// <remarks>
    /// Unlike PolicyNV, this needs no Name computation (the compared value is TPM-global state, not a named
    /// entity), so it is a PURE transition shaped exactly like <c>OnPolicyCommandCode</c>: resolve the session,
    /// then extend. The offset/size range checks run for trial and real sessions alike; only the comparison
    /// itself is skipped for a trial session. See the single-source-of-truth note on
    /// <c>OnPolicyCommandCode</c>.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_PolicyCounterTimer()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnPolicyCounterTimer(TpmSimulatorState state, TpmPolicyCounterTimerRequested request)
    {
        if(!state.PolicySessions.TryGetValue(request.PolicySession, out PolicySessionState? session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicyCounterTimer, TpmRcConstants.TPM_RC_HANDLE, request);
        }

        //offset > 25 is TPM_RC_VALUE (Part 3, clause 23.10); offset == 25 (a zero-length window at the very end) is
        //legal. These two range checks run even for a trial session — the policy would not make sense otherwise.
        if(request.Offset > TpmsTimeInfo.SerializedSize)
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicyCounterTimer, TpmRcConstants.TPM_RC_VALUE, request);
        }

        //offset + operandB.Length overflowing the 25-octet structure is TPM_RC_RANGE. Widened to a wider integer
        //defensively, mirroring the spec's own choice of arithmetic width for this sum.
        if((uint)request.Offset + (uint)request.OperandB.Length > TpmsTimeInfo.SerializedSize)
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicyCounterTimer, TpmRcConstants.TPM_RC_RANGE, request);
        }

        if(!session.IsTrial)
        {
            //The compared value is the live TPMS_TIME_INFO the TPM itself would report from TPM2_ReadClock() right
            //now (25 octets, no padding), marshaled fresh into a small stack buffer — non-secret clock/reset state,
            //never spanning an await in this synchronous transition.
            Span<byte> timeInfo = stackalloc byte[TpmsTimeInfo.SerializedSize];
            var timeInfoWriter = new TpmWriter(timeInfo);
            new TpmsTimeInfo(state.Time, new TpmsClockInfo(state.Clock, state.ResetCount, state.RestartCount, state.ClockSafe)).WriteTo(ref timeInfoWriter);

            ReadOnlySpan<byte> comparand = timeInfo.Slice(request.Offset, request.OperandB.Length);
            if(!TpmEoComparator.TryEvaluate(comparand, request.OperandB.Span, (TpmEoConstants)request.Operation, out bool matched, out TpmRcConstants rejectionCode))
            {
                return Reject(state, TpmCcConstants.TPM_CC_PolicyCounterTimer, rejectionCode, request);
            }

            if(!matched)
            {
                return Reject(state, TpmCcConstants.TPM_CC_PolicyCounterTimer, TpmRcConstants.TPM_RC_POLICY, request);
            }
        }

        //The accepted arm transfers the operand into the shared fold action, whose effect is its terminal owner;
        //the request record owns nothing else, so nothing is released here.

        return DeclarePolicyDigestFold(
            state, session, TpmPolicyDigestFold.CounterTimer, "PolicyCounterTimer",
            operandB: request.OperandB, offset: request.Offset, operation: request.Operation);
    }

    /// <summary>
    /// Removes a loaded session or transient object from TPM memory for <c>TPM2_FlushContext()</c> (Part 3,
    /// clause 28.4).
    /// </summary>
    /// <remarks>
    /// A pure state transition: drop the handle from whichever table holds it — policy sessions, HMAC sessions,
    /// transient keys, and loaded sealed objects are all flushable transient state. An unknown handle is
    /// <c>TPM_RC_HANDLE</c>.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed <c>TPM2_FlushContext()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnFlushContext(TpmSimulatorState state, TpmFlushContextRequested request)
    {
        //Each arm captures the evicted record and releases its owned carriers before the dictionary drops
        //the last live reference: flushing IS the ownership-end boundary (TPM 2.0 Library Part 1, clause
        //17.6.17's "clear all associated context"), and a snapshot an observer retained reads the disposed
        //carriers loudly rather than recycled pool memory.
        if(state.PolicySessions.TryGetValue(TpmiShPolicy.FromValue(request.FlushHandle.Value), out PolicySessionState? policySession))
        {
            policySession.Dispose();

            return Transition(
                state with
                {
                    PolicySessions = state.PolicySessions.Remove(TpmiShPolicy.FromValue(request.FlushHandle.Value)),
                    ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
                },
                "FlushContext:Session");
        }

        if(state.HmacSessions.TryGetValue(TpmiShHmac.FromValue(request.FlushHandle.Value), out HmacSessionState? hmacSession))
        {
            hmacSession.Dispose();

            return Transition(
                state with
                {
                    HmacSessions = state.HmacSessions.Remove(TpmiShHmac.FromValue(request.FlushHandle.Value)),
                    ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
                },
                "FlushContext:HmacSession");
        }

        if(state.TransientObjects.TryGetValue(TpmiDhObject.FromValue(request.FlushHandle.Value), out TransientKeyState? transientObject))
        {
            transientObject.Dispose();

            return Transition(
                state with
                {
                    TransientObjects = state.TransientObjects.Remove(TpmiDhObject.FromValue(request.FlushHandle.Value)),
                    ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
                },
                "FlushContext:Object");
        }

        if(state.LoadedSealedObjects.TryGetValue(TpmiDhObject.FromValue(request.FlushHandle.Value), out SealedObjectState? sealedObject))
        {
            sealedObject.Dispose();

            return Transition(
                state with
                {
                    LoadedSealedObjects = state.LoadedSealedObjects.Remove(TpmiDhObject.FromValue(request.FlushHandle.Value)),
                    ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
                },
                "FlushContext:SealedObject");
        }

        return Reject(state, TpmCcConstants.TPM_CC_FlushContext, TpmRcConstants.TPM_RC_HANDLE);
    }

    /// <summary>
    /// The fixed nonceCaller floor at <c>TPM2_StartAuthSession()</c> (TPM 2.0 Library Part 3, clause 11.1; Part
    /// 1, clause 17.6.3.2): 16 octets regardless of authHash — only the ceiling scales with the session hash's
    /// digest size.
    /// </summary>
    private const int SessionStartNonceCallerMinimumSize = 16;

    /// <summary>
    /// Starts a TPM2_StartAuthSession() bound and/or salted HMAC session with parameter encryption (Part 3, clause
    /// 11.1; Part 1, clauses 17.6 and 19).
    /// </summary>
    /// <remarks>
    /// The precondition ladder and action dispatch are shared with a POLICY/TRIAL session's start
    /// (<c>OnStartAuthSession</c>) via <c>TryBuildSessionStartAction</c> — Section 11.1.1's own "for all session
    /// types" — passing <c>policyContext: null</c> keeps this call's own behavior exactly as before.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed TPM2_StartAuthSession() request for an HMAC session.</param>
    /// <returns>The <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the session-start action.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnStartHmacSession(TpmSimulatorState state, TpmStartHmacSessionRequested request)
    {
        if(!IsSupportedPolicyHash(request.AuthHash))
        {
            return Reject(state, TpmCcConstants.TPM_CC_StartAuthSession, TpmRcConstants.TPM_RC_HASH, request);
        }

        uint handle = state.NextHmacSessionHandle;
        if(!TryBuildSessionStartAction(
            state, handle, request.AuthHash, request.Bind.Value, request.NonceCaller, request.Symmetric, request.TpmKey.Value, request.EncryptedSalt,
            policyContext: null, out TpmAction? action, out TpmRcConstants rejectCode))
        {
            return Reject(state, TpmCcConstants.TPM_CC_StartAuthSession, rejectCode, request);
        }

        return Transition(
            state with
            {
                NextHmacSessionHandle = handle + 1,
                NextAction = action,
                ResponseIntent = null
            },
            "StartAuthSession:HmacRequested");
    }

    /// <summary>
    /// Runs the shared TPM2_StartAuthSession() bind/salt validation ladder and builds the action to dispatch (TPM
    /// 2.0 Library Part 3, clause 11.1.1).
    /// </summary>
    /// <remarks>
    /// The nonceCaller floor/ceiling is checked first (unconditional, ahead of tpmKey/bind entirely); then
    /// tpmKey's asymmetric-type/handle/decrypt-attribute checks (secret recovery itself is asynchronous — the RSA
    /// and ECC arms dispatch to <see cref="TpmRecoverRsaSessionSaltAction"/>/<see cref="TpmRecoverEccSessionSaltAction"/>,
    /// whose any internal recovery failure reports TPM_RC_VALUE immediately, never poisoned-and-deferred); then
    /// the bind entity (a PIN Fail/Pass NV Index can never bind, closing the PIN-extraction vector the NV PIN
    /// Fail/Pass indexes would otherwise open); then the negotiated symmetric definition's mode — identical for an
    /// HMAC session and a POLICY/TRIAL session (Section 11.1.1: "For all session types, this command will cause
    /// initialization of the sessionKey"). <paramref name="policyContext"/> is <see langword="null"/> for an HMAC
    /// session (<c>OnStartHmacSession</c>) or carries the POLICY/TRIAL session's own context
    /// (<c>OnStartAuthSession</c>) so <c>OnHmacSessionStarted</c> can route the derived key/nonce to the right
    /// session table once the effectful loop's result comes back.
    /// </remarks>
    /// <param name="state">The state to validate against.</param>
    /// <param name="handle">The session handle allocated for this start.</param>
    /// <param name="authHash">The session's requested hash algorithm.</param>
    /// <param name="bind">The bind entity's handle, or <c>TPM_RH_NULL</c> for unbound.</param>
    /// <param name="nonceCaller">The caller-supplied nonceCaller, owned by the request; on success it TRANSFERS into the built action, whose effect is its terminal owner, and on every failure it stays with the request for the refusing arm to release.</param>
    /// <param name="symmetric">The requested symmetric definition for parameter encryption.</param>
    /// <param name="tpmKey">The salting key's handle, or <c>TPM_RH_NULL</c> for unsalted.</param>
    /// <param name="encryptedSalt">The caller-encrypted salt, or the empty sentinel when unsalted, owned by the request; the salted arms TRANSFER it into the built action, and the unsalted arm leaves the sentinel — which rents nothing — with the request.</param>
    /// <param name="policyContext">The POLICY/TRIAL session context to attach, or <see langword="null"/> for an HMAC session.</param>
    /// <param name="action">The built action to dispatch on success.</param>
    /// <param name="rejectCode">The response code to reject with on failure.</param>
    /// <returns><see langword="true"/> when the ladder passes and <paramref name="action"/> was built; otherwise <see langword="false"/>.</returns>
    private static bool TryBuildSessionStartAction(
        TpmSimulatorState state, uint handle, TpmiAlgHash authHash, uint bind, Tpm2bNonce nonceCaller,
        TpmtSymDef symmetric, uint tpmKey, Tpm2bEncryptedSecret encryptedSalt, TpmPolicySessionKeyContext? policyContext,
        [NotNullWhen(true)] out TpmAction? action, out TpmRcConstants rejectCode)
    {
        action = null;
        rejectCode = TpmRcConstants.TPM_RC_SUCCESS;

        int authHashDigestSize = TpmPolicyDigest.Size(authHash.Value);
        if(nonceCaller.Size < SessionStartNonceCallerMinimumSize || nonceCaller.Size > authHashDigestSize)
        {
            rejectCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //tpmKey: TPM_RH_NULL means unsalted (an unsalted request naming a non-empty encryptedSalt is malformed).
        //Otherwise the handle must resolve to a loaded asymmetric (RSA/ECC) key carrying the decrypt attribute,
        //and encryptedSalt must be non-empty.
        TransientKeyState? tpmKeyState = null;
        if(tpmKey != (uint)TpmRh.TPM_RH_NULL)
        {
            if(IsPermanentHandle(tpmKey) || state.LoadedSealedObjects.ContainsKey(TpmiDhObject.FromValue(tpmKey)))
            {
                //A hierarchy or a sealed (KEYEDHASH) object is never an asymmetric key.
                rejectCode = TpmRcConstants.TPM_RC_KEY;

                return false;
            }

            if(!state.TransientObjects.TryGetValue(TpmiDhObject.FromValue(tpmKey), out tpmKeyState) && !state.PersistentObjects.TryGetValue(TpmiDhPersistent.FromValue(tpmKey), out tpmKeyState))
            {
                rejectCode = TpmRcConstants.TPM_RC_HANDLE;

                return false;
            }

            if(encryptedSalt.IsEmpty)
            {
                rejectCode = TpmRcConstants.TPM_RC_VALUE;

                return false;
            }

            if((tpmKeyState.Attributes & TpmaObject.DECRYPT) == 0)
            {
                rejectCode = TpmRcConstants.TPM_RC_ATTRIBUTES;

                return false;
            }
        }
        else if(!encryptedSalt.IsEmpty)
        {
            rejectCode = TpmRcConstants.TPM_RC_VALUE;

            return false;
        }

        //bind: resolves the entity's real authorization value and Name for the session-key KDFa and (for an
        //HMAC session only) the later command-HMAC bind-omission check (Part 1, clause 17.6.10 equations
        //21/22/25/26) — a POLICY/TRIAL session never applies that optimization (Section 11.1.1's own "the
        //session is not bound"), so its Name is resolved but goes unused past this point. The entity's
        //dictionary-attack state, by contrast, is recorded on every session type (clause 17.6.10: "The noDA
        //attribute of the bind entity is recorded in the session context").
        if(!TryResolveBindEntity(
            state, bind, out TpmRcConstants bindRejectCode, out Tpm2bAuth boundAuthValue, out TpmHandleName boundEntityName,
            out bool isBoundEntityDaProtected, out bool isBoundToLockout))
        {
            rejectCode = bindRejectCode;

            return false;
        }

        //symmetric: TPM_ALG_NULL and XOR need no mode. A block cipher this model can key parameter encryption
        //with (AES) must negotiate CFB specifically, else TPM_RC_MODE; any other negotiated algorithm entirely
        //(unsupported by this model) is TPM_RC_SYMMETRIC. Between the two sits the key width, which the union's
        //own interface type bounds: TPMI_AES_KEY_BITS admits $AES_KEY_SIZES_BITS and answers TPM_RC_VALUE for
        //"key size is not supported" (Part 2, clause 11.1.2, Table 155, replicated for AES in clause 4.12.5,
        //Table 1; the reference's AES_KEY_SIZES_BITS is 128, 192, 256). The three codes divide the definition
        //cleanly — the algorithm, then its key size, then its mode — and each names the field it is about.
        if(!symmetric.IsNull && !symmetric.IsXor)
        {
            if(symmetric.Algorithm != TpmAlgIdConstants.TPM_ALG_AES)
            {
                rejectCode = TpmRcConstants.TPM_RC_SYMMETRIC;

                return false;
            }

            if(symmetric.KeyBits is not (128 or 192 or 256))
            {
                rejectCode = TpmRcConstants.TPM_RC_VALUE;

                return false;
            }

            if(symmetric.Mode != TpmAlgIdConstants.TPM_ALG_CFB)
            {
                rejectCode = TpmRcConstants.TPM_RC_MODE;

                return false;
            }
        }

        action = tpmKeyState switch
        {
            null => new TpmStartHmacSessionAction(
                TpmiShAuthSession.FromValue(handle), authHash, symmetric, nonceCaller, boundAuthValue, boundEntityName, ReadOnlyMemory<byte>.Empty, policyContext,
                isBoundEntityDaProtected, isBoundToLockout),
            { KeyType.Value: TpmAlgIdConstants.TPM_ALG_RSA } rsaKey => new TpmRecoverRsaSessionSaltAction(
                TpmiShAuthSession.FromValue(handle), authHash, symmetric, nonceCaller, boundAuthValue, boundEntityName,
                encryptedSalt, rsaKey.PrivateKey, TpmKeyNameAlg(rsaKey), policyContext,
                isBoundEntityDaProtected, isBoundToLockout),
            _ => new TpmRecoverEccSessionSaltAction(
                TpmiShAuthSession.FromValue(handle), authHash, symmetric, nonceCaller, boundAuthValue, boundEntityName,
                encryptedSalt, tpmKeyState.PrivateKey, tpmKeyState.PublicPoint, tpmKeyState.Curve, TpmKeyNameAlg(tpmKeyState), policyContext,
                isBoundEntityDaProtected, isBoundToLockout)
        };

        return true;
    }

    /// <summary>
    /// Resolves a bind entity's real authorization value and Name for the session-key KDFa (TPM 2.0 Library
    /// Part 1, clause 17.6.10 equations 20/23/25) and the later command-HMAC bind-omission check (equations
    /// 21/22/25/26).
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>TPM_RH_NULL</c> is unbound (both empty); a permanent hierarchy's Name is its own 4-octet big-endian
    /// handle value, with a real authorization value for each of the four hierarchies that carry one and the
    /// structurally empty value for every other permanent constant. A PIN Fail/Pass NV Index can never bind
    /// (<c>TPM_RC_HANDLE</c>) — TPM 2.0 Library
    /// Part 1, clause 35.2.8.3: "If a PIN Pass or PIN Fail Index is referenced as a bind entity, the TPM must
    /// return TPM_RC_HANDLE. Otherwise, the sequence in which the TPM processes authorizations would enable a
    /// hammering attack on the Index." — a spec-mandated refusal, not an unimplemented-scope carve-out, so it
    /// stays even once ordinary NV Index binding and the PIN-over-HMAC channel are both modelled. Every other NV
    /// Index binds with its real authValue, and its Name is recorded here as the Index's raw 4-octet handle value
    /// rather than the computed <c>nameAlg ‖ H(TPMS_NV_PUBLIC)</c> form, since the Name needs the asynchronous
    /// digest seam a pure transition cannot reach. <c>OnNvIndexNameComputed</c> recomputes the bound-entity fold
    /// over that recorded form when it decides equation 22's omission, so a session bound to the Index it
    /// authorizes omits the authValue exactly as a real TPM does — and because the fold carries the Index's LIVE
    /// authValue (Part 4, <c>SessionComputeBoundEntity()</c>), an authValue rotation or an undefine-then-recreate
    /// under a different authValue ends the binding exactly as clause 17.6.10 requires. What the handle-form
    /// approximation still does not track is a Name CHANGE alone — the first write flipping
    /// <c>TPMA_NV_WRITTEN</c> changes an Index's Name, which ends the binding on a real TPM while this model
    /// keeps the handle matching for as long as the authValue is unchanged. That residue never widens
    /// authorization: the session key already incorporates that same Index's authValue through the bind KDFa, so
    /// the omission proves the same secret either way. A sealed object's Name and userAuth are both exact
    /// (<c>TPM2_Create()</c>/<c>TPM2_Load()</c> already retain them); a signing/storage object carries no modelled
    /// authValue (empty).
    /// </para>
    /// <para>
    /// The entity's dictionary-attack state is resolved here too, once, because TPM 2.0 Library Part 1, clause
    /// 17.6.10 requires it be captured at session start rather than re-derived per use: "The noDA attribute of
    /// the bind entity is recorded in the session context." The per-branch answers are the ones clause 17.8.1
    /// gives for each entity kind — an object is protected unless its <c>noDA</c> attribute is SET, an NV Index
    /// unless <c>TPMA_NV_NO_DA</c> is SET, and "The authValue associated with a permanent entity, other than
    /// TPM_RH_LOCKOUT, does not receive DA protection", with <c>TPM_RH_LOCKOUT</c> itself protected because
    /// "lockoutAuth is DA protected even though it is a permanent entity". Clause 17.8.7 states the permanent
    /// case a second time from the session's side ("If a session is bound to a permanent entity other than
    /// TPM_RH_LOCKOUT, then the session is not bound to an entity that has DA protection"). No object kind is
    /// exempted by its role: a signing or storage key resolves through the same <c>noDA</c> formula a sealed
    /// object and a <c>TPM2_Create()</c> parent do.
    /// </para>
    /// </remarks>
    /// <param name="state">The current simulator state.</param>
    /// <param name="bind">The bind entity's handle, or <c>TPM_RH_NULL</c> for unbound.</param>
    /// <param name="rejectCode">The response code to reject with on failure.</param>
    /// <param name="boundAuthValue">The resolved entity's real authorization value — a borrowed reference to the carrier the durable state owns, wire-exact; the session-start effects take trailing-zero-stripped views at the KDFa and bound-entity fold primitives (Part 1, clause 17.6.4.3), so a retained trace snapshot of the declaring step fails loud once the entity rotates or is evicted.</param>
    /// <param name="boundEntityName">The resolved entity's Name term — a borrow of the entity's own Name carrier, or the entity's handle value where the Name IS the handle (Part 1, clause 14, Table 6) — absent for an unbound start.</param>
    /// <param name="isBoundEntityDaProtected">Whether the resolved entity receives dictionary-attack protection; <see langword="false"/> for an unbound session and on every failure path.</param>
    /// <param name="isBoundToLockout">Whether the resolved entity is <c>TPM_RH_LOCKOUT</c>, which is never set without <paramref name="isBoundEntityDaProtected"/> also being set.</param>
    /// <returns><see langword="true"/> when the bind entity resolved successfully.</returns>
    private static bool TryResolveBindEntity(
        TpmSimulatorState state,
        uint bind,
        out TpmRcConstants rejectCode,
        out Tpm2bAuth boundAuthValue,
        out TpmHandleName boundEntityName,
        out bool isBoundEntityDaProtected,
        out bool isBoundToLockout)
    {
        rejectCode = TpmRcConstants.TPM_RC_SUCCESS;
        isBoundEntityDaProtected = false;
        isBoundToLockout = false;

        if(bind == (uint)TpmRh.TPM_RH_NULL)
        {
            boundAuthValue = Tpm2bAuth.Empty;
            boundEntityName = TpmHandleName.None;

            return true;
        }

        if(IsPermanentHandle(bind))
        {
            boundEntityName = TpmHandleName.FromHandle(bind);

            //TPM_RH_LOCKOUT is the sole permanent entity whose authValue is dictionary-attack protected (clause
            //17.8.1), and it is protected in the stricter one-strike sense of clause 17.8.5, so both flags rise
            //together for it and neither rises for any other permanent constant.
            isBoundToLockout = bind == (uint)TpmRh.TPM_RH_LOCKOUT;
            isBoundEntityDaProtected = isBoundToLockout;

            //The carrier rides as a wire-exact borrow; the session-start effects take the trailing-zero-stripped
            //view at the KDFa and bound-entity fold primitives (TPM 2.0 Library Part 1, clause 17.6.4.3; the
            //reference reaches every entity's authValue through EntityGetAuthValue, which strips unconditionally).
            //Resolved from the one field the handle names: a session bound to ENDORSEMENT or PLATFORM must fold
            //that hierarchy's real authValue into its session key, not the Empty Buffer, or the binding would
            //prove nothing once TPM2_HierarchyChangeAuth() has set one.
            _ = state.TryGetHierarchyAuthValue(bind, out Tpm2bAuth hierarchyAuth);
            boundAuthValue = hierarchyAuth;

            return true;
        }

        if(state.NvIndexes.TryGetValue(TpmiRhNvIndex.FromValue(bind), out NvIndexState? nvIndex))
        {
            if(nvIndex.IsPinIndex)
            {
                //A PIN Pass/Fail Index can never be a bind entity (TPM 2.0 Library Part 1, clause 35.2.8.3) —
                //spec-mandated, so VerifyPinAsync's own HMAC session for the PIN channel (Part 1, clause 17.8.1's
                //authValue-in-HMAC-key mechanics) is necessarily unbound, never bind-to-self.
                boundAuthValue = Tpm2bAuth.Empty;
                boundEntityName = TpmHandleName.None;
                rejectCode = TpmRcConstants.TPM_RC_HANDLE;

                return false;
            }

            //This model records a bound NV Index's Name in the handle form a permanent entity uses (Part 1,
            //clause 14, Table 6), where Part 4's SessionComputeBoundEntity() reaches the Index's Name through
            //EntityGetName() and would give nameAlg ‖ H(TPMS_NV_PUBLIC) instead. Both forms are accepted at every
            //bind-omission comparison against an NV Index, so the recorded form is self-consistent.
            boundAuthValue = nvIndex.AuthValue;
            boundEntityName = TpmHandleName.FromHandle(bind);
            isBoundEntityDaProtected = nvIndex.IsDaProtected;

            return true;
        }

        if(state.LoadedSealedObjects.TryGetValue(TpmiDhObject.FromValue(bind), out SealedObjectState? sealedObject))
        {
            boundAuthValue = sealedObject.UserAuth;
            boundEntityName = TpmHandleName.FromName(sealedObject.Name);
            isBoundEntityDaProtected = sealedObject.IsDaProtected;

            return true;
        }

        if(state.TransientObjects.TryGetValue(TpmiDhObject.FromValue(bind), out TransientKeyState? transient))
        {
            boundAuthValue = transient.AuthValue;
            boundEntityName = TpmHandleName.FromName(transient.Name);
            isBoundEntityDaProtected = transient.IsDaProtected;

            return true;
        }

        if(state.PersistentObjects.TryGetValue(TpmiDhPersistent.FromValue(bind), out TransientKeyState? persistent))
        {
            boundAuthValue = persistent.AuthValue;
            boundEntityName = TpmHandleName.FromName(persistent.Name);
            isBoundEntityDaProtected = persistent.IsDaProtected;

            return true;
        }

        boundAuthValue = Tpm2bAuth.Empty;
        boundEntityName = TpmHandleName.None;
        rejectCode = TpmRcConstants.TPM_RC_HANDLE;

        return false;
    }

    /// <summary>
    /// Extracts a loaded key's real Name algorithm from its retained Name (<c>nameAlg ‖ H_nameAlg(TPMT_PUBLIC)</c>,
    /// TPM 2.0 Library Part 1, clause 14, Table 6 — the 2-octet big-endian prefix IS the Name algorithm), rather than
    /// assuming a fixed value: a salted session's tpmKey may have been created with any supported nameAlg, and
    /// KDFe/OAEP must key on THIS key's own algorithm, never the session's authHash (Part 1, Annex
    /// C.6.1/B.10.1).
    /// </summary>
    /// <param name="tpmKey">The loaded key to extract the Name algorithm from.</param>
    /// <returns>The key's Name algorithm.</returns>
    private static TpmiAlgHash TpmKeyNameAlg(TransientKeyState tpmKey) =>
        TpmiAlgHash.FromValue((TpmAlgIdConstants)BinaryPrimitives.ReadUInt16BigEndian(tpmKey.Name.Span[..sizeof(ushort)]));

    /// <summary>
    /// Records a started bound and/or salted HMAC, POLICY, or TRIAL session and frames the TPM2_StartAuthSession()
    /// response with the real nonceTPM (TPM 2.0 Library Part 3, clause 11.1).
    /// </summary>
    /// <remarks>
    /// The nonceTPM is the value the session-key KDFa consumed, which the host must receive verbatim to derive
    /// the same key — or, when a salted arm's secret recovery failed, this rejects with that failure code instead.
    /// <c>started.PolicyContext</c> (set only by <c>OnStartAuthSession</c>, never <c>OnStartHmacSession</c>)
    /// decides which session table the derived key/nonce become durable state in — a POLICY/TRIAL session starts
    /// with an all-zero policyDigest, an unlatched cpHash, and isAuthValueNeeded/isPasswordNeeded CLEAR (Part 1,
    /// clause 17.7.8's default), exactly as the session-key-less path used to record it, now carrying a real
    /// SessionKey too. Both session kinds record the bind entity's dictionary-attack state (Part 1, clause
    /// 17.6.10: "The noDA attribute of the bind entity is recorded in the session context"), since clause
    /// 17.8.7's failure accounting for a bound session is stated without qualification by session type.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="started">The effect's result carrying the derived key, nonce, and either a POLICY/TRIAL context or an HMAC bind entity.</param>
    /// <returns>The <see cref="TransitionResult{TState, TStackSymbol}"/> recording the started session, or a rejection when recovery failed.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the started session's key and bound-entity carriers transfers to the session record installed into the live dictionary, which eviction (TPM2_FlushContext, any TPM2_Startup's session flush, simulator teardown) disposes.")]
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnHmacSessionStarted(TpmSimulatorState state, TpmHmacSessionStarted started)
    {
        if(started.ResponseCode != TpmRcConstants.TPM_RC_SUCCESS)
        {
            return Reject(state, TpmCcConstants.TPM_CC_StartAuthSession, started.ResponseCode);
        }

        if(started.PolicyContext is TpmPolicySessionKeyContext policyContext)
        {
            //A session starts at the Zero Digest of its own hash width (Part 1, clause 17.7) with its cpHash
            //unlatched: both are the shared dispose-immune sentinels, so a starting session rents nothing for
            //either and the first assertion's dispose-the-superseded install is safe.
            var policySession = new PolicySessionState(
                TpmiShPolicy.FromValue(started.SessionHandle.Value), started.SessionAlg, policyContext.IsTrial,
                Tpm2bDigest.Zero(started.SessionAlg), started.RetainedNonceTpm,
                Tpm2bDigest.Empty, policyContext.StartTime, Timeout: 0ul, SessionKey: started.SessionKey,
                IsBoundEntityDaProtected: started.IsBoundEntityDaProtected, IsBoundToLockout: started.IsBoundToLockout);

            return Transition(
                state with
                {
                    NextAction = NullAction.Instance,
                    PolicySessions = state.PolicySessions.SetItem(TpmiShPolicy.FromValue(started.SessionHandle.Value), policySession),
                    ResponseIntent = new TpmStartAuthSessionResponse(TpmRcConstants.TPM_RC_SUCCESS, started.SessionHandle, started.NonceTpm)
                },
                "StartAuthSession:PolicyCompleted");
        }

        var session = new HmacSessionState(
            TpmiShHmac.FromValue(started.SessionHandle.Value), started.SessionAlg, started.Symmetric, started.SessionKey, started.RetainedNonceTpm, started.BoundEntity,
            started.IsBoundEntityDaProtected, started.IsBoundToLockout);

        return Transition(
            state with
            {
                NextAction = NullAction.Instance,
                HmacSessions = state.HmacSessions.SetItem(TpmiShHmac.FromValue(started.SessionHandle.Value), session),
                ResponseIntent = new TpmStartAuthSessionResponse(
                    TpmRcConstants.TPM_RC_SUCCESS, started.SessionHandle, started.NonceTpm)
            },
            "StartAuthSession:HmacCompleted");
    }

    /// <summary>
    /// Dispatches <c>TPM2_GetRandom()</c> over a bound HMAC session with the encrypt attribute (Part 3, clause
    /// 16.1; Part 1, clauses 16.7 and 19).
    /// </summary>
    /// <remarks>
    /// The session must resolve (an unknown handle is the session-not-loaded warning, Part 2, clause 6.6.2).
    /// GetRandom authorizes no entity, so its command-HMAC key is the session key alone and no ENTITY-side
    /// dictionary-attack gate applies; the session's own bind still carries one, since the sessionKey computation
    /// of a bound session is itself a use of the bind entity's authValue (Part 1, clause 17.8.1). A single session
    /// never folds (the fold only ever targets ANOTHER session, Part 1, clause 17.6.3.4). The session area's own
    /// attribute rules (clause 5.5) are validated before any HMAC is
    /// evaluated, uniformly with <c>TPM2_Unseal()</c> and <c>TPM2_Create()</c>: GetRandom has no @-handle, so
    /// its lone session never authorizes an entity and MUST set at least one of decrypt/encrypt/audit (confirmed
    /// against the reference session-processing routine — a lone, attribute-less session is genuinely rejected
    /// there too, not merely an artifact of this simulator's own modelling). Verification needs the registered
    /// HMAC seam, so this declares a <c>TpmVerifyCommandHmacAction</c>; <c>ContinueGetRandomOverSession</c>
    /// resumes once it matches.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_GetRandom()</c> request.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the HMAC verification.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnGetRandomOverSession(TpmSimulatorState state, TpmGetRandomOverSessionRequested request)
    {
        if(!state.HmacSessions.TryGetValue(TpmiShHmac.FromValue(request.SessionHandle.Value), out HmacSessionState? session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_GetRandom, SessionReferenceMissRc(sessionIndex: 0), request);
        }

        TpmRcConstants? sessionAreaError = ValidateSessionArea(
            request.SessionAttributes, firstAuthorizesEntity: false, session.Symmetric,
            hasSecondSession: false, secondAttributes: default, secondSymmetric: TpmtSymDef.Null,
            firstCommandParameterIsEncryptable: false, firstResponseParameterIsEncryptable: true,
            firstSessionHandle: request.SessionHandle, firstNonceLength: request.NonceCaller.Size);
        if(sessionAreaError is TpmRcConstants sessionAreaRc)
        {
            return Reject(state, TpmCcConstants.TPM_CC_GetRandom, sessionAreaRc, request);
        }

        //GetRandom authorizes no entity, so the session's whole dictionary-attack standing is its bind: its HMAC
        //keys on a session key that folded the bind entity's authValue, which clause 17.8.1 counts as a use of
        //that authValue, and "All uses of a DA protected authValue receive DA protection".
        if(IsBoundSessionLockedOut(state, session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_GetRandom, TpmRcConstants.TPM_RC_LOCKOUT, request);
        }

        var pending = new TpmPendingSessionVerification(
            TpmiShAuthSession.FromValue(session.Handle.Value), SessionIndex: 0, session.SessionAlg, session.SessionKey, AuthValue: Tpm2bAuth.Empty,
            IsDaProtected: session.IsBoundEntityDaProtected, request.NonceCaller, session.NonceTpm, FoldedNonceDecrypt: Tpm2bNonce.Empty, FoldedNonceEncrypt: Tpm2bNonce.Empty,
            request.SessionAttributes, request.Hmac, IsLockoutEntity: session.IsBoundToLockout);

        return Transition(
            state with
            {
                NextAction = new TpmVerifyCommandHmacAction(
                    TpmCcConstants.TPM_CC_GetRandom, HandleNames: TpmCommandHandleNames.None, request.RawParameterArea,
                    pending, ImmutableArray<TpmPendingSessionVerification>.Empty, request),
                ResponseIntent = null
            },
            "GetRandom:HmacVerifyRequested");
    }

    /// <summary>
    /// Resumes <c>TPM2_GetRandom()</c> over a bound HMAC session once its command HMAC has verified: the random
    /// draw, nonce roll, parameter encryption, rpHash, and response HMAC all need the RNG and the registered
    /// digest/HMAC seams, so this declares a <c>TpmEncryptRandomAction</c>; the effectful loop frames the
    /// encrypted response and feeds it back as a <c>TpmEncryptedRandomProduced</c> input
    /// (<c>OnEncryptedRandomProduced</c>).
    /// </summary>
    /// <param name="state">The state to transition from.</param>
    /// <param name="request">The parsed session-authorized <c>TPM2_GetRandom()</c> request, its session now verified.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the encrypt action.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> ContinueGetRandomOverSession(TpmSimulatorState state, TpmGetRandomOverSessionRequested request)
    {
        //This continuation is the terminal owner of the parse-rented parameter area and of the slot's supplied
        //credential: the command HMAC that read both has verified, and nothing downstream reads them again. The
        //caller nonce is NOT released here — it transfers into the response-encryption action below.
        request.RawParameterArea.Dispose();
        request.Hmac.Dispose();

        //The session is guaranteed present (verification just resolved it); a re-lookup is used rather than
        //threading the resolved record through the verify queue, keeping TpmPendingSessionVerification's shape
        //uniform across every session-authorized command this simulator handles.
        HmacSessionState session = state.HmacSessions[TpmiShHmac.FromValue(request.SessionHandle.Value)];

        //A request larger than the largest digest is clamped, not rejected (clause 16.1), as in the no-session form.
        int byteCount = System.Math.Min((int)request.BytesRequested, MaxRandomBytes);

        return Transition(
            state with
            {
                NextAction = new TpmEncryptRandomAction(
                    TpmiShAuthSession.FromValue(session.Handle.Value), session.SessionAlg, session.Symmetric, session.SessionKey, request.NonceCaller, request.SessionAttributes, byteCount),
                ResponseIntent = null
            },
            "GetRandom:EncryptedRequested");
    }

    /// <summary>
    /// Advances a command's session-verification queue (<c>TpmVerifyCommandHmacAction</c>'s continuation, TPM
    /// 2.0 Library Part 3, clause 5.6, check 9): a mismatch rejects, dictionary-attack-aware and
    /// session-index-encoded; a match either declares the next queued session's verification or, once the queue
    /// empties, resumes the original command — the one shared mechanism every session-authorized command
    /// transition routes through.
    /// </summary>
    /// <param name="state">The state to transition from.</param>
    /// <param name="verified">The effect's result carrying the match outcome and the remaining verification queue.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnCommandHmacVerified(TpmSimulatorState state, TpmCommandHmacVerified verified)
    {
        if(!verified.Matched)
        {
            //A mismatch terminates the command before any transition arm sees the queued request again, so a
            //request that owns a parse-rented carrier (NV_DefineSpace's indexAuth, NV_ChangeAuth's and
            //HierarchyChangeAuth's newAuth, the attest family's supplied session credentials and qualifying
            //data) has no later owner. It is released here, ahead of rejection framing that reads only handles
            //and dictionary state, never the carrier.
            if(verified.NextRequest is IDisposable ownedInFlight)
            {
                ownedInFlight.Dispose();
            }

            //NV Index-authorizing session-HMAC commands additionally throttle the Index's own pinCount on a
            //genuine mismatch (Part 1, clause 35.2.6.6) before the generic session-encoded rejection fires —
            //see RejectNvSessionAuthFailure's own remarks for why this must be intercepted here rather than in
            //a per-request continuation. Every other session-authorized command has no such per-entity counter,
            //so it falls through to the generic rejection unchanged.
            if(verified.NextRequest is TpmNvReadOverSessionRequested or TpmNvWriteOverSessionRequested
                or TpmNvDefineSpaceOverSessionRequested or TpmNvUndefineSpaceOverSessionRequested
                or TpmNvCertifyOverSessionRequested or TpmNvChangeAuthOverSessionRequested)
            {
                return RejectNvSessionAuthFailure(state, verified);
            }

            return RejectSessionAuthFailure(state, verified.CommandCode, verified.SessionIndex, verified.IsDaProtected, verified.IsLockoutEntity);
        }

        if(!verified.Remaining.IsEmpty)
        {
            TpmPendingSessionVerification next = verified.Remaining[0];
            ImmutableArray<TpmPendingSessionVerification> rest = verified.Remaining.RemoveAt(0);

            return Transition(
                state with
                {
                    NextAction = new TpmVerifyCommandHmacAction(verified.CommandCode, verified.HandleNames, verified.ParameterArea, next, rest, verified.NextRequest),
                    ResponseIntent = null
                },
                "CommandHmac:NextSessionRequested");
        }

        return verified.NextRequest switch
        {
            TpmGetRandomOverSessionRequested getRandom => ContinueGetRandomOverSession(state, getRandom),
            TpmUnsealOverSessionsRequested unseal => ContinueUnsealOverSessions(state, unseal),
            TpmCreateSealedObjectOverSessionsRequested createOverSessions => ContinueCreateOverSessions(state, createOverSessions),
            TpmPolicySecretOverSessionRequested policySecretOverSession => ContinuePolicySecretOverSession(state, policySecretOverSession),
            TpmNvReadOverSessionRequested nvReadOverSession => ContinueNvReadOverSession(state, nvReadOverSession),
            TpmNvWriteOverSessionRequested nvWriteOverSession => ContinueNvWriteOverSession(state, nvWriteOverSession),
            TpmNvDefineSpaceOverSessionRequested nvDefineSpaceOverSession => ContinueNvDefineSpaceOverSession(state, nvDefineSpaceOverSession),
            TpmNvUndefineSpaceOverSessionRequested nvUndefineSpaceOverSession => ContinueNvUndefineSpaceOverSession(state, nvUndefineSpaceOverSession),
            TpmNvIncrementOverSessionRequested nvIncrementOverSession => ContinueNvIncrementOverSession(state, nvIncrementOverSession),
            TpmNvCertifyOverSessionRequested nvCertifyOverSession => ContinueNvCertifyOverSession(state, nvCertifyOverSession),
            TpmNvChangeAuthOverSessionRequested nvChangeAuthOverSession => ContinueNvChangeAuthOverSession(state, nvChangeAuthOverSession),
            TpmQuoteOverSessionRequested quoteOverSession => ContinueQuoteOverSession(state, quoteOverSession),
            TpmCertifyCreationOverSessionRequested certifyCreationOverSession => ContinueCertifyCreationOverSession(state, certifyCreationOverSession),
            TpmCertifyOverSessionRequested certifyOverSession => ContinueCertifyOverSession(state, certifyOverSession),
            TpmGetTimeOverSessionRequested getTimeOverSession => ContinueGetTimeOverSession(state, getTimeOverSession),
            TpmClearOverSessionRequested clearOverSession => ContinueClearOverSession(state, clearOverSession),
            TpmClearControlOverSessionRequested clearControlOverSession => ContinueClearControlOverSession(state, clearControlOverSession),
            TpmHierarchyControlOverSessionRequested hierarchyControlOverSession => ContinueHierarchyControlOverSession(state, hierarchyControlOverSession),
            TpmSetPrimaryPolicyOverSessionRequested setPrimaryPolicyOverSession => ContinueSetPrimaryPolicyOverSession(state, setPrimaryPolicyOverSession),
            TpmHierarchyChangeAuthOverSessionRequested hierarchyChangeAuthOverSession => ContinueHierarchyChangeAuthOverSession(state, hierarchyChangeAuthOverSession),
            _ => throw new System.InvalidOperationException($"No command-HMAC-verified continuation is defined for '{verified.NextRequest.GetType().Name}'.")
        };
    }

    /// <summary>
    /// Rolls the session's nonceTPM to the freshly generated value and frames the encrypt-attributed response
    /// (the encrypted parameter area and the response session area the effect assembled).
    /// </summary>
    /// <remarks>
    /// The session record is replaced wholesale because its nonceTPM is immutable model state, replaced once
    /// per command (Part 1, clause 17.6.5).
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="produced">The effect's result carrying the framed response and rolled nonce.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnEncryptedRandomProduced(TpmSimulatorState state, TpmEncryptedRandomProduced produced)
    {
        //The session is present under normal flow (the request resolved it before declaring the action); if it was
        //flushed meanwhile the produced buffers are still released by SerializeResponse, so frame the response
        //regardless and update the table only when the session still exists.
        ImmutableDictionary<TpmiShHmac, HmacSessionState> sessions = RollHmacSessionNonce(state.HmacSessions, produced.SessionHandle, produced.RetainedNonceTpm);

        return Transition(
            state with
            {
                NextAction = NullAction.Instance,
                HmacSessions = sessions,
                ResponseIntent = new TpmEncryptedRandomResponse(
                    TpmRcConstants.TPM_RC_SUCCESS,
                    produced.ParameterArea,
                    produced.NewNonceTpm,
                    produced.SessionAttributes,
                    produced.Hmac)
            },
            "GetRandom:EncryptedCompleted");
    }

    /// <summary>
    /// Whether a handle addresses a permanent entity (most-significant octet <c>TPM_HT_PERMANENT</c>, TPM 2.0
    /// Library Part 2, clause 7.2): the reserved handles such as the hierarchies, whose Name is the 4-byte
    /// handle value.
    /// </summary>
    /// <param name="handle">The handle to test.</param>
    /// <returns><see langword="true"/> when the handle addresses a permanent entity.</returns>
    private static bool IsPermanentHandle(uint handle) => (handle >> 24) == (uint)TpmHt.TPM_HT_PERMANENT;

    /// <summary>
    /// Maps a permanent handle to its OWNING hierarchy (the reference's <c>EntityGetHierarchy</c>,
    /// permanent-handle arm — TPM 2.0 Library Part 1, clause 12.5): Platform/Endorsement/Null are their own
    /// hierarchy; every other permanent handle this slice admits as a PolicySecret authHandle — today only
    /// <c>TPM_RH_LOCKOUT</c> — belongs to the Owner hierarchy ("all other permanent handles are associated with
    /// the owner hierarchy... should only be TPM_RH_OWNER and TPM_RH_LOCKOUT", the reference's own comment).
    /// </summary>
    /// <remarks>
    /// <c>TPMT_TK_AUTH.hierarchy</c> (Part 2, Table 111) is typed <c>TPMI_RH_HIERARCHY+</c>, whose legal set is
    /// exactly {Owner, Platform, Endorsement, Null} — the raw authHandle is not itself always a member of that
    /// set (<c>TPM_RH_LOCKOUT</c> is not), so a minted ticket's hierarchy field must go through this mapping,
    /// never the raw handle.
    /// </remarks>
    /// <param name="handle">The permanent handle to map.</param>
    /// <returns>The owning hierarchy's handle.</returns>
    private static uint EntityGetHierarchyForPermanentHandle(uint handle) =>
        handle switch
        {
            (uint)TpmRh.TPM_RH_PLATFORM or (uint)TpmRh.TPM_RH_ENDORSEMENT or (uint)TpmRh.TPM_RH_NULL => handle,
            _ => (uint)TpmRh.TPM_RH_OWNER
        };

    /// <summary>
    /// Applies Part 3, Section 23.2.4's min-with-existing rule to a policy session's tracked timeout
    /// (<c>PolicyContextUpdate</c>'s own "<c>if(session-&gt;timeout == 0 || session-&gt;timeout &gt; policyTimeout)
    /// session-&gt;timeout = policyTimeout</c>").
    /// </summary>
    /// <remarks>
    /// A zero timeout never updates anything (the trial-session and no-expiration folds always pass zero here,
    /// matching the reference's own "policyTimeout != 0" gate), and a nonzero timeout only ever moves the
    /// tracked value smaller-or-first-write, never larger. This stores the value; nothing in this simulator yet
    /// consults it to answer <c>TPM_RC_EXPIRED</c> at authorization time (a companion gap in the same rule, out
    /// of this slice's scope).
    /// </remarks>
    /// <param name="session">The session whose timeout is being applied.</param>
    /// <param name="timeout">The requested timeout, or zero for none.</param>
    /// <returns>The session with its timeout updated, when the new value is smaller or first-write.</returns>
    private static PolicySessionState ApplySessionTimeout(PolicySessionState session, ulong timeout) =>
        timeout != 0 && (session.Timeout == 0 || session.Timeout > timeout)
            ? session with { Timeout = timeout }
            : session;

    /// <summary>
    /// Applies the policy-session context reset a session undergoes once it has been successfully used to
    /// authorize a command (TPM 2.0 Library Part 3, Section 23.2.4), rolling its nonceTPM to the value framed
    /// with that command's response in the same step (Part 1, clause 17.6.5).
    /// </summary>
    /// <remarks>
    /// The reset clears the accumulated policyDigest back to a Zero Digest of the session's own hash width, the
    /// latched cpHash back to unlatched, the tracked timeout back to zero, the recorded commandCode back to
    /// unasserted, and both isAuthValueNeeded/isPasswordNeeded back to CLEAR, and re-anchors startTime to the
    /// current Time. Handle, PolicyHash, IsTrial, and SessionKey are preserved: a reset never re-derives a
    /// session key (that happens only at <c>TPM2_StartAuthSession()</c>) and never converts a trial session into
    /// a real one. The consequence a caller sees is that a policy session is single-use — every assertion must
    /// be replayed before it can authorize a second command.
    /// </remarks>
    /// <param name="session">The policy session that just authorized a command.</param>
    /// <param name="time">The simulator's current Time, the reset session's new startTime anchor.</param>
    /// <param name="rolledNonceTpm">The freshly drawn nonceTPM in an owned carrier, whose ownership transfers to the returned session through <see cref="PolicySessionState.WithNonceTpm(Tpm2bNonce)"/>; the superseded carrier is released there.</param>
    /// <returns>The session with its policy context reset and its nonceTPM rolled.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of rolledNonceTpm transfers to the returned PolicySessionState through WithNonceTpm, which releases the superseded carrier as the replacement lands; the digest and cpHash the reset installs are the shared dispose-immune sentinels, and the With* calls release the carriers they supersede.")]
    private static PolicySessionState ResetPolicySessionContext(PolicySessionState session, ulong time, Tpm2bNonce rolledNonceTpm) =>
        session
            .WithNonceTpm(rolledNonceTpm)
            .WithPolicyDigest(Tpm2bDigest.Zero(session.PolicyHash))
            .WithCpHash(Tpm2bDigest.Empty) with
        {
            Timeout = 0ul,
            StartTime = time,
            IsAuthValueNeeded = false,
            IsPasswordNeeded = false,
            CommandCode = null
        };

    /// <summary>
    /// Installs a freshly rolled nonceTPM on the HMAC session it belongs to (TPM 2.0 Library Part 1, clause
    /// 17.6.5), or releases the carrier when that session has already left the table.
    /// </summary>
    /// <remarks>
    /// A session flushed while its response was being framed still gets that response returned; only the table
    /// update is skipped. The rolled carrier then has no durable owner, so this step is its terminal owner —
    /// the framed carrier the response intent holds is a separate rental and is unaffected.
    /// </remarks>
    /// <param name="sessions">The HMAC-session table to update.</param>
    /// <param name="sessionHandle">The session whose nonceTPM rolls.</param>
    /// <param name="rolledNonceTpm">The freshly drawn nonceTPM in an owned carrier; ownership transfers to the session record, or is consumed here.</param>
    /// <returns>The table with the roll applied, or unchanged when the session is gone.</returns>
    private static ImmutableDictionary<TpmiShHmac, HmacSessionState> RollHmacSessionNonce(
        ImmutableDictionary<TpmiShHmac, HmacSessionState> sessions, TpmiShAuthSession sessionHandle, Tpm2bNonce rolledNonceTpm)
    {
        TpmiShHmac handle = TpmiShHmac.FromValue(sessionHandle.Value);
        if(!sessions.TryGetValue(handle, out HmacSessionState? session))
        {
            rolledNonceTpm.Dispose();

            return sessions;
        }

        return sessions.SetItem(handle, session.WithNonceTpm(rolledNonceTpm));
    }

    /// <summary>
    /// Applies the policy-session context reset and the nonceTPM roll to the policy session an authorization
    /// used (TPM 2.0 Library Part 3, Section 23.2.4; Part 1, clause 17.6.5), or releases the rolled carrier when
    /// that session has already left the table.
    /// </summary>
    /// <param name="sessions">The policy-session table to update.</param>
    /// <param name="sessionHandle">The session whose context resets and whose nonceTPM rolls.</param>
    /// <param name="time">The simulator's current Time, the reset session's new startTime anchor.</param>
    /// <param name="rolledNonceTpm">The freshly drawn nonceTPM in an owned carrier; ownership transfers to the session record, or is consumed here.</param>
    /// <returns>The table with the reset applied, or unchanged when the session is gone.</returns>
    private static ImmutableDictionary<TpmiShPolicy, PolicySessionState> RollPolicySessionNonce(
        ImmutableDictionary<TpmiShPolicy, PolicySessionState> sessions, TpmiShAuthSession sessionHandle, ulong time, Tpm2bNonce rolledNonceTpm)
    {
        TpmiShPolicy handle = TpmiShPolicy.FromValue(sessionHandle.Value);
        if(!sessions.TryGetValue(handle, out PolicySessionState? session))
        {
            rolledNonceTpm.Dispose();

            return sessions;
        }

        return sessions.SetItem(handle, ResetPolicySessionContext(session, time, rolledNonceTpm));
    }

    /// <summary>
    /// Declares the shared policyDigest fold for an assertion whose fold has no effect of its own on its path,
    /// carrying the terms that assertion's <c>PolicyUpdate</c> formula reads (TPM 2.0 Library Part 3, clause 23).
    /// </summary>
    /// <remarks>
    /// The step exists because the fold's destination must be rented at the session's own digest width and a
    /// pure transition holds no memory pool. Terms the selected formula does not read are passed as their type's
    /// inert placeholder — the dispose-immune empty carrier, <see langword="null"/>, or zero — exactly as the
    /// attest family's shared decrypt step already does.
    /// </remarks>
    /// <param name="state">The state to transition from, with any session-field updates this assertion makes already applied.</param>
    /// <param name="session">The policy session being extended, whose current digest the fold borrows.</param>
    /// <param name="fold">The formula to apply.</param>
    /// <param name="label">The assertion's own transition label, which the resuming transition emits verbatim.</param>
    /// <param name="restrictedCommand">The command code <c>TPM2_PolicyCommandCode()</c> restricts to.</param>
    /// <param name="nameTerm">The Name term the fold hashes, as a borrow of a Name another owner holds or as a permanent entity's handle value.</param>
    /// <param name="policyRef">The policy qualifier in an owned carrier; ownership transfers into the action.</param>
    /// <param name="keySign">The approving key's Name in an owned carrier; ownership transfers into the action.</param>
    /// <param name="branches">The <c>TPM2_PolicyOR()</c> branch list in an owned carrier; ownership transfers into the action.</param>
    /// <param name="pcrSelectionBytes">The marshaled <c>TPML_PCR_SELECTION</c> exactly as sent.</param>
    /// <param name="pcrDigest">The caller-supplied expected PCR digest in an owned carrier; ownership transfers into the action.</param>
    /// <param name="pcrValues">The currently selected PCR values, as borrows of the durable bank's own memory.</param>
    /// <param name="operandB">The comparison operand the argHash covers.</param>
    /// <param name="offset">The octet offset the argHash covers.</param>
    /// <param name="operation">The <c>TPM_EO</c> comparison the argHash covers.</param>
    /// <param name="timeoutMagnitude">The deadline magnitude the resuming transition ranks under Section 23.2.4's min-with-existing rule.</param>
    /// <param name="authorizingSession">The session that authorized <c>TPM2_PolicySecret()</c>, or <see langword="null"/>.</param>
    /// <returns>The <see cref="TransitionResult{TState, TStackSymbol}"/> declaring the fold.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of every owned term carrier transfers into the declared TpmFoldPolicyDigestAction, whose effect is their terminal owner on every path.")]
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> DeclarePolicyDigestFold(
        TpmSimulatorState state,
        PolicySessionState session,
        TpmPolicyDigestFold fold,
        string label,
        TpmCcConstants restrictedCommand = default,
        TpmHandleName nameTerm = default,
        Tpm2bNonce? policyRef = null,
        Tpm2bName? keySign = null,
        TpmlDigest? branches = null,
        ReadOnlyMemory<byte> pcrSelectionBytes = default,
        Tpm2bDigest? pcrDigest = null,
        ImmutableArray<ReadOnlyMemory<byte>> pcrValues = default,
        Tpm2bOperand? operandB = null,
        ushort offset = 0,
        ushort operation = 0,
        ulong timeoutMagnitude = 0ul,
        PolicySecretAuthorizingSession? authorizingSession = null) =>
        Transition(
            state with
            {
                NextAction = new TpmFoldPolicyDigestAction(
                    fold, session.Handle, session.PolicyHash, session.PolicyDigest, label, restrictedCommand,
                    nameTerm, policyRef ?? Tpm2bNonce.Empty, keySign ?? Tpm2bName.Empty, branches,
                    pcrSelectionBytes, pcrDigest ?? Tpm2bDigest.Empty,
                    pcrValues.IsDefault ? ImmutableArray<ReadOnlyMemory<byte>>.Empty : pcrValues,
                    session.IsTrial, operandB ?? Tpm2bOperand.Empty, offset, operation, timeoutMagnitude, authorizingSession),
                ResponseIntent = null
            },
            "Policy:FoldRequested");

    /// <summary>
    /// Installs the policyDigest the shared fold advanced and frames the assertion's own response (TPM 2.0
    /// Library Part 3, clause 23).
    /// </summary>
    /// <remarks>
    /// The label the fold carried is emitted verbatim, so each assertion's trace reads exactly as it did before
    /// the fold moved into an effect; only an additional entry for the fold request precedes it. The one failure
    /// this step can carry is a real <c>TPM2_PolicyPCR()</c> whose caller-supplied digest did not match the live
    /// composite (clause 23.7).
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="folded">The effect's result carrying the advanced digest and the assertion's response payload.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnPolicyDigestFolded(TpmSimulatorState state, TpmPolicyDigestFolded folded)
    {
        TpmSimulatorState cleared = state with { NextAction = NullAction.Instance };

        if(folded.ResponseCode != TpmRcConstants.TPM_RC_SUCCESS)
        {
            return Reject(cleared, PolicyFoldCommandCode(folded.Fold), folded.ResponseCode);
        }

        PolicySessionState session = cleared.PolicySessions[folded.PolicySession];

        return folded.Fold switch
        {
            TpmPolicyDigestFold.Secret => CompletePolicySecretFold(
                cleared, session, folded.FoldedDigest, folded.TimeoutMagnitude, Tpm2bTimeout.Empty, (uint)TpmRh.TPM_RH_NULL,
                ticketDigest: null, folded.AuthorizingSession),
            TpmPolicyDigestFold.Signed => CompletePolicySignedFold(
                cleared, session, folded.FoldedDigest, folded.TimeoutMagnitude, Tpm2bTimeout.Empty, (uint)TpmRh.TPM_RH_NULL,
                ticketDigest: null),
            _ => StorePolicyDigest(cleared, session, folded.FoldedDigest, new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS), folded.Label)
        };
    }

    /// <summary>
    /// The command code a shared policyDigest fold's refusal is framed under, so the rejection names the
    /// assertion the caller actually sent rather than the fold step.
    /// </summary>
    /// <param name="fold">The formula that was applied.</param>
    /// <returns>The command code.</returns>
    /// <exception cref="InvalidOperationException"><paramref name="fold"/> names a formula that has no failure of its own, so no refusal can carry it.</exception>
    private static TpmCcConstants PolicyFoldCommandCode(TpmPolicyDigestFold fold) => fold switch
    {
        TpmPolicyDigestFold.Pcr => TpmCcConstants.TPM_CC_PolicyPCR,
        _ => throw new InvalidOperationException($"The '{fold}' policyDigest fold has no refusing arm to frame.")
    };

    /// <summary>
    /// Stores an advanced policyDigest back onto its session and frames the command's response (a header-only
    /// success for the assertion commands, or the PolicySecret timeout/ticket response).
    /// </summary>
    /// <remarks>
    /// The session record is replaced wholesale because its digest is immutable model state; the install is the
    /// TRANSFER that makes the session the advanced carrier's owner, and
    /// <see cref="PolicySessionState.WithPolicyDigest(Tpm2bDigest)"/> releases the superseded one as it lands.
    /// </remarks>
    /// <param name="state">The state to transition from.</param>
    /// <param name="session">The session whose policyDigest is being stored.</param>
    /// <param name="updatedDigest">The newly-extended policyDigest in an owned carrier; ownership transfers to the session.</param>
    /// <param name="response">The response to frame.</param>
    /// <param name="label">The transition label.</param>
    /// <returns>The resulting <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of updatedDigest transfers to the installed PolicySessionState, which releases it at the next assertion or at eviction.")]
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> StorePolicyDigest(
        TpmSimulatorState state, PolicySessionState session, Tpm2bDigest updatedDigest, TpmResponseIntent response, string label) =>
        Transition(
            state with
            {
                PolicySessions = state.PolicySessions.SetItem(session.Handle, session.WithPolicyDigest(updatedDigest)),
                ResponseIntent = response
            },
            label);

    /// <summary>
    /// Whether the running policyDigest equals one of the OR branches (TPM 2.0 Library Part 3, clause 23.6).
    /// </summary>
    /// <remarks>
    /// The branches are public policy digests, so a plain byte comparison is sufficient. The list is read as a
    /// borrow — the request still owns it here, and it transfers into the fold only once the match has passed.
    /// </remarks>
    /// <param name="current">The session's current policyDigest.</param>
    /// <param name="branches">The OR branches to compare against.</param>
    /// <returns><see langword="true"/> when <paramref name="current"/> matches any branch.</returns>
    private static bool MatchesAnyBranch(ReadOnlySpan<byte> current, TpmlDigest branches)
    {
        for(int i = 0; i < branches.Count; i++)
        {
            if(current.SequenceEqual(branches[i].AsReadOnlySpan()))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// The policy hash algorithms the enhanced-authorization digest formula actually computes
    /// (<c>TpmPolicyDigest.Hash</c>).
    /// </summary>
    /// <remarks>
    /// SHA-1 is intentionally excluded: advertising it here while the fold cannot compute it left a session that
    /// faulted on its first assertion, so StartAuthSession now rejects it up front with <c>TPM_RC_HASH</c>.
    /// </remarks>
    /// <param name="hash">The algorithm to test.</param>
    /// <returns><see langword="true"/> when the policy digest formula supports <paramref name="hash"/>.</returns>
    private static bool IsSupportedPolicyHash(TpmiAlgHash hash) =>
        hash.Value is TpmAlgIdConstants.TPM_ALG_SHA256
            or TpmAlgIdConstants.TPM_ALG_SHA384
            or TpmAlgIdConstants.TPM_ALG_SHA512;

    /// <summary>
    /// The Name algorithms <c>TpmObjectName</c> can actually compute (TPM 2.0 Library Part 1, clause 14, Table 6).
    /// </summary>
    /// <remarks>
    /// SHA-1 is included here (unlike <see cref="IsSupportedPolicyHash"/>'s exclusion) because the profile this
    /// model serves still lists it as a valid object nameAlg; an unsupported value is rejected up front with
    /// <c>TPM_RC_HASH</c> rather than defaulted, so a caller can never silently get a SHA-256 Name for a
    /// different requested nameAlg.
    /// </remarks>
    /// <param name="nameAlg">The algorithm to test.</param>
    /// <returns><see langword="true"/> when <c>TpmObjectName</c> supports <paramref name="nameAlg"/>.</returns>
    private static bool IsSupportedNameAlg(TpmiAlgHash nameAlg) =>
        nameAlg.Value is TpmAlgIdConstants.TPM_ALG_SHA1
            or TpmAlgIdConstants.TPM_ALG_SHA256
            or TpmAlgIdConstants.TPM_ALG_SHA384
            or TpmAlgIdConstants.TPM_ALG_SHA512;

    /// <summary>
    /// A signing key must carry the sign attribute to attest with <c>TPM2_Certify()</c> or <c>TPM2_Quote()</c>
    /// (TPM 2.0 Library Part 3, clause 18.1: "If the sign attribute is not SET in the key referenced by
    /// signHandle then the TPM shall return TPM_RC_KEY").
    /// </summary>
    /// <remarks>
    /// restricted does not gate either command (Part 1, clause 25.1, Table 24), so only SIGN_ENCRYPT is checked
    /// here.
    /// </remarks>
    /// <param name="attributes">The key's object attributes.</param>
    /// <returns><see langword="true"/> when the key may sign.</returns>
    private static bool CanSign(TpmaObject attributes) =>
        (attributes & TpmaObject.SIGN_ENCRYPT) == TpmaObject.SIGN_ENCRYPT;

    /// <summary>
    /// The signing-scheme hash algorithms the attest digest computations actually hash with
    /// (<c>TpmAlgIdExtensions</c>' digest-tag mapping, which <c>TpmSimulator</c>'s Certify/Quote effects use to
    /// drive the registered digest seam).
    /// </summary>
    /// <remarks>
    /// SHA-1 is intentionally excluded from the signing-digest path in this codebase (mirrors
    /// <see cref="IsSupportedPolicyHash"/>); an unsupported value is rejected up front with <c>TPM_RC_HASH</c>
    /// rather than silently defaulted to SHA-256.
    /// </remarks>
    /// <param name="hashAlg">The algorithm to test.</param>
    /// <returns><see langword="true"/> when the attest digest computations support <paramref name="hashAlg"/>.</returns>
    private static bool IsSupportedAttestHashAlg(TpmiAlgHash hashAlg) =>
        hashAlg.Value is TpmAlgIdConstants.TPM_ALG_SHA256
            or TpmAlgIdConstants.TPM_ALG_SHA384
            or TpmAlgIdConstants.TPM_ALG_SHA512;

    /// <summary>
    /// A storage parent is a restricted decryption key (RESTRICTED and DECRYPT both set) — the only object type
    /// that can parent (and, on a real TPM, wrap) a <c>TPM2_Create()</c> child (TPM 2.0 Library Part 1, clause
    /// 25.2).
    /// </summary>
    /// <param name="attributes">The object's attributes.</param>
    /// <returns><see langword="true"/> when the object is a storage parent.</returns>
    private static bool IsStorageParent(TpmaObject attributes) =>
        (attributes & (TpmaObject.RESTRICTED | TpmaObject.DECRYPT)) == (TpmaObject.RESTRICTED | TpmaObject.DECRYPT);

    private static TpmCcConstants CommandCodeOf(TpmSimulatorInput input) =>
        input switch
        {
            TpmStartupRequested => TpmCcConstants.TPM_CC_Startup,
            TpmShutdownRequested => TpmCcConstants.TPM_CC_Shutdown,
            TpmSelfTestRequested => TpmCcConstants.TPM_CC_SelfTest,
            TpmTestResultRequested => TpmCcConstants.TPM_CC_GetTestResult,
            TpmGetRandomRequested => TpmCcConstants.TPM_CC_GetRandom,
            TpmGetCapabilityRequested => TpmCcConstants.TPM_CC_GetCapability,
            TpmNvDefineSpaceRequested => TpmCcConstants.TPM_CC_NV_DefineSpace,
            TpmNvReadRequested => TpmCcConstants.TPM_CC_NV_Read,
            TpmNvWriteRequested => TpmCcConstants.TPM_CC_NV_Write,
            TpmNvUndefineSpaceRequested => TpmCcConstants.TPM_CC_NV_UndefineSpace,
            TpmNvIncrementRequested => TpmCcConstants.TPM_CC_NV_Increment,
            TpmNvReadPublicRequested => TpmCcConstants.TPM_CC_NV_ReadPublic,
            TpmNvReadOverSessionRequested => TpmCcConstants.TPM_CC_NV_Read,
            TpmNvWriteOverSessionRequested => TpmCcConstants.TPM_CC_NV_Write,
            TpmNvDefineSpaceOverSessionRequested => TpmCcConstants.TPM_CC_NV_DefineSpace,
            TpmNvUndefineSpaceOverSessionRequested => TpmCcConstants.TPM_CC_NV_UndefineSpace,
            TpmNvIncrementOverSessionRequested => TpmCcConstants.TPM_CC_NV_Increment,
            TpmNvCertifyOverSessionRequested => TpmCcConstants.TPM_CC_NV_Certify,
            TpmNvChangeAuthOverSessionRequested => TpmCcConstants.TPM_CC_NV_ChangeAuth,
            TpmEvictControlRequested => TpmCcConstants.TPM_CC_EvictControl,
            TpmCreatePrimaryRequested => TpmCcConstants.TPM_CC_CreatePrimary,
            TpmCreateRsaPrimaryRequested => TpmCcConstants.TPM_CC_CreatePrimary,
            TpmCreateStorageParentRequested => TpmCcConstants.TPM_CC_CreatePrimary,
            TpmCreateRsaStorageParentRequested => TpmCcConstants.TPM_CC_CreatePrimary,
            TpmSignRequested => TpmCcConstants.TPM_CC_Sign,
            TpmCreateSealedObjectRequested => TpmCcConstants.TPM_CC_Create,
            TpmCreateSealedObjectOverSessionsRequested => TpmCcConstants.TPM_CC_Create,
            TpmLoadObjectRequested => TpmCcConstants.TPM_CC_Load,
            TpmUnsealRequested => TpmCcConstants.TPM_CC_Unseal,
            TpmUnsealOverSessionsRequested => TpmCcConstants.TPM_CC_Unseal,
            TpmCertifyRequested => TpmCcConstants.TPM_CC_Certify,
            TpmCertifyOverSessionRequested => TpmCcConstants.TPM_CC_Certify,
            TpmCertifyCreationRequested => TpmCcConstants.TPM_CC_CertifyCreation,
            TpmCertifyCreationOverSessionRequested => TpmCcConstants.TPM_CC_CertifyCreation,
            TpmPcrReadRequested => TpmCcConstants.TPM_CC_PCR_Read,
            TpmQuoteRequested => TpmCcConstants.TPM_CC_Quote,
            TpmQuoteOverSessionRequested => TpmCcConstants.TPM_CC_Quote,
            TpmGetTimeRequested => TpmCcConstants.TPM_CC_GetTime,
            TpmGetTimeOverSessionRequested => TpmCcConstants.TPM_CC_GetTime,
            TpmReadClockRequested => TpmCcConstants.TPM_CC_ReadClock,
            TpmClockSetRequested => TpmCcConstants.TPM_CC_ClockSet,
            TpmDictionaryAttackLockResetRequested => TpmCcConstants.TPM_CC_DictionaryAttackLockReset,
            TpmDictionaryAttackParametersRequested => TpmCcConstants.TPM_CC_DictionaryAttackParameters,
            TpmClearRequested => TpmCcConstants.TPM_CC_Clear,
            TpmClearOverSessionRequested => TpmCcConstants.TPM_CC_Clear,
            TpmClearControlRequested => TpmCcConstants.TPM_CC_ClearControl,
            TpmClearControlOverSessionRequested => TpmCcConstants.TPM_CC_ClearControl,
            TpmHierarchyControlRequested => TpmCcConstants.TPM_CC_HierarchyControl,
            TpmHierarchyControlOverSessionRequested => TpmCcConstants.TPM_CC_HierarchyControl,
            TpmSetPrimaryPolicyRequested => TpmCcConstants.TPM_CC_SetPrimaryPolicy,
            TpmSetPrimaryPolicyOverSessionRequested => TpmCcConstants.TPM_CC_SetPrimaryPolicy,
            TpmHierarchyChangeAuthRequested => TpmCcConstants.TPM_CC_HierarchyChangeAuth,
            TpmHierarchyChangeAuthOverSessionRequested => TpmCcConstants.TPM_CC_HierarchyChangeAuth,
            TpmNvCertifyRequested => TpmCcConstants.TPM_CC_NV_Certify,
            TpmVerifySignatureRequested => TpmCcConstants.TPM_CC_VerifySignature,
            TpmStartAuthSessionRequested => TpmCcConstants.TPM_CC_StartAuthSession,
            TpmStartHmacSessionRequested => TpmCcConstants.TPM_CC_StartAuthSession,
            TpmGetRandomOverSessionRequested => TpmCcConstants.TPM_CC_GetRandom,
            TpmPolicyCommandCodeRequested => TpmCcConstants.TPM_CC_PolicyCommandCode,
            TpmPolicyAuthValueRequested => TpmCcConstants.TPM_CC_PolicyAuthValue,
            TpmPolicyGetDigestRequested => TpmCcConstants.TPM_CC_PolicyGetDigest,
            TpmPolicyPcrRequested => TpmCcConstants.TPM_CC_PolicyPCR,
            TpmPolicyOrRequested => TpmCcConstants.TPM_CC_PolicyOR,
            TpmPolicySecretRequested => TpmCcConstants.TPM_CC_PolicySecret,
            TpmPolicySecretOverSessionRequested => TpmCcConstants.TPM_CC_PolicySecret,
            TpmPolicySignedRequested => TpmCcConstants.TPM_CC_PolicySigned,
            TpmPolicyAuthorizeRequested => TpmCcConstants.TPM_CC_PolicyAuthorize,
            TpmPolicyTicketRequested => TpmCcConstants.TPM_CC_PolicyTicket,
            TpmPolicyNvRequested => TpmCcConstants.TPM_CC_PolicyNV,
            TpmPolicyCounterTimerRequested => TpmCcConstants.TPM_CC_PolicyCounterTimer,
            TpmMakeCredentialRequested => TpmCcConstants.TPM_CC_MakeCredential,
            TpmActivateCredentialRequested => TpmCcConstants.TPM_CC_ActivateCredential,
            TpmActivateCredentialOverSessionRequested => TpmCcConstants.TPM_CC_ActivateCredential,
            TpmFlushContextRequested => TpmCcConstants.TPM_CC_FlushContext,
            TpmUnsupportedCommandReceived unsupported => unsupported.CommandCode,
            _ => throw new System.InvalidOperationException($"Input '{input.GetType().Name}' is not a command and must not reach command dispatch.")
        };

    /// <summary>
    /// Explicitly clears NextAction alongside framing the rejection.
    /// </summary>
    /// <remarks>
    /// Every existing single-step call site already runs from a freshly-reset NextAction (<c>OnExternalInput</c>
    /// clears it before <c>OnCommand</c> dispatches), so this is a no-op there, but it is REQUIRED for a
    /// multi-step verify-then-reject chain (<c>TpmVerifyCommandHmacAction</c>'s continuation,
    /// <c>OnCommandHmacVerified</c>) — without it, the effect loop would see the just-executed action still
    /// present on the returned state and re-dispatch it without bound (mirrors
    /// <c>OnCredentialActivated</c>'s and <c>OnSignatureVerified</c>'s explicit NextAction reset on their own
    /// rejection path).
    /// </remarks>
    /// <param name="state">The state to reject from.</param>
    /// <param name="commandCode">The command being rejected.</param>
    /// <param name="responseCode">The rejection response code.</param>
    /// <returns>The rejection <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> Reject(TpmSimulatorState state, TpmCcConstants commandCode, TpmRcConstants responseCode) =>
        Transition(
            state with { NextAction = NullAction.Instance, ResponseIntent = new TpmHeaderOnlyResponse(responseCode) },
            $"Reject:{commandCode}");

    /// <summary>
    /// Rejects a command whose in-flight input owns pooled carriers that never reached durable state,
    /// releasing them before the rejection is framed — the refusing counterpart of an install's ownership
    /// transfer, so no refusing arm leaks a parse- or effect-rented carrier. Delegates to
    /// <see cref="Reject(TpmSimulatorState, TpmCcConstants, TpmRcConstants)"/> after the release; borrowed
    /// references are never carried by an input's <see cref="IDisposable.Dispose"/>, so disposing here can
    /// only touch what the input genuinely owns.
    /// </summary>
    /// <param name="state">The state to reject from.</param>
    /// <param name="commandCode">The command being rejected.</param>
    /// <param name="responseCode">The rejection response code.</param>
    /// <param name="ownedInFlight">The input whose owned carriers are released.</param>
    /// <returns>The rejection <see cref="TransitionResult{TState, TStackSymbol}"/>.</returns>
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> Reject(TpmSimulatorState state, TpmCcConstants commandCode, TpmRcConstants responseCode, IDisposable ownedInFlight)
    {
        ownedInFlight.Dispose();

        return Reject(state, commandCode, responseCode);
    }

    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> Transition(TpmSimulatorState nextState, string label) =>
        new(nextState, StackAction<TpmSimulatorStackSymbol>.None, label);
}
