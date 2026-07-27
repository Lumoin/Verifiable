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
                TpmSignatureVerified signatureVerified => OnSignatureVerified(state, signatureVerified),
                TpmHmacSessionStarted hmacSessionStarted => OnHmacSessionStarted(state, hmacSessionStarted),
                TpmPolicySessionStarted policySessionStarted => OnPolicySessionStarted(state, policySessionStarted),
                TpmCommandHmacVerified commandHmacVerified => OnCommandHmacVerified(state, commandHmacVerified),
                TpmEncryptedRandomProduced encryptedRandom => OnEncryptedRandomProduced(state, encryptedRandom),
                TpmUnsealedOverSessions unsealedOverSessions => OnUnsealedOverSessions(state, unsealedOverSessions),
                TpmCredentialMade credentialMade => OnCredentialMade(state, credentialMade),
                TpmCredentialActivated credentialActivated => OnCredentialActivated(state, credentialActivated),
                TpmNvNameComputedForPolicy nvNameComputedForPolicy => OnNvNameComputedForPolicy(state, nvNameComputedForPolicy),
                TpmPolicySignedVerified policySignedVerified => OnPolicySignedVerified(state, policySignedVerified),
                TpmPolicyAuthorizeVerified policyAuthorizeVerified => OnPolicyAuthorizeVerified(state, policyAuthorizeVerified),
                TpmCreateSensitiveDecrypted sensitiveDecrypted => OnCreateSensitiveDecrypted(state, sensitiveDecrypted),
                TpmObjectSealedOverSessions sealedOverSessions => OnObjectSealedOverSessions(state, sealedOverSessions),
                _ => OnExternalInput(state, input, cancellationToken)
            };

            return ValueTask.FromResult(result);
        };

    //Handles inputs that arrive from outside the effect loop — the platform _TPM_Init signal and parsed
    //command requests. These honour cancellation and start from a cleared NextAction.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol>? OnExternalInput(
        TpmSimulatorState state, TpmSimulatorInput input, System.Threading.CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

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
            TpmCertifyCreationRequested certifyCreation => OnCertifyCreation(state, certifyCreation),
            TpmPcrReadRequested pcrRead => OnPcrRead(state, pcrRead),
            TpmQuoteRequested quote => OnQuote(state, quote),
            TpmGetTimeRequested getTime => OnGetTime(state, getTime),
            TpmReadClockRequested => OnReadClock(state),
            TpmClockSetRequested clockSet => OnClockSet(state, clockSet),
            TpmDictionaryAttackLockResetRequested dictionaryAttackLockReset => OnDictionaryAttackLockReset(state, dictionaryAttackLockReset),
            TpmDictionaryAttackParametersRequested dictionaryAttackParameters => OnDictionaryAttackParameters(state, dictionaryAttackParameters),
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
            TpmPolicySignedRequested policySigned => OnPolicySigned(state, policySigned),
            TpmPolicyAuthorizeRequested policyAuthorize => OnPolicyAuthorize(state, policyAuthorize),
            TpmPolicyNvRequested policyNv => OnPolicyNv(state, policyNv),
            TpmPolicyCounterTimerRequested policyCounterTimer => OnPolicyCounterTimer(state, policyCounterTimer),
            TpmMakeCredentialRequested makeCredential => OnMakeCredential(state, makeCredential),
            TpmActivateCredentialRequested activateCredential => OnActivateCredential(state, activateCredential),
            TpmActivateCredentialOverSessionRequested activateCredentialOverSession => OnActivateCredentialOverSession(state, activateCredentialOverSession),
            TpmFlushContextRequested flushContext => OnFlushContext(state, flushContext),
            _ => throw new System.InvalidOperationException($"Command input '{input.GetType().Name}' passed precondition gating but has no dispatch handler.")
        };
    }

    //Startup(CLEAR) is a TPM Reset when it is preceded by Shutdown(CLEAR) or no orderly shutdown at all, or a
    //TPM Restart when it is preceded by Shutdown(STATE); Startup(STATE) after a Shutdown(STATE) is a TPM
    //Resume (Part 3, clause 9.3). Restart and Resume increment restartCount and leave resetCount untouched; a
    //Reset increments resetCount and resets restartCount to zero (Part 1, clauses 36.4-36.5). Every one of the
    //three resets Time to zero (Time counts from the last _TPM_Init/Startup, clause 36.2) but never Clock
    //(clause 36.3) — overriding only the Time half of the per-command advance OnCommand already applied for
    //this very Startup dispatch. A Reset's ClockSafe becomes YES when it followed an orderly Shutdown(CLEAR)
    //or is this TPM's very first Reset (resetCount was zero, so no prior Clock value could ever have been
    //reported, per clause 36.3's "not a repeat of a previously reported value" definition); otherwise NO — a
    //Reset with neither of those conditions is a disorderly restart this simulator cannot distinguish further
    //(the skeleton's own disorderly-power-loss simplification, noted on LastOrderlyShutdown). Two further
    //simplifications, tracked on the roadmap rather than modelled: no periodic NV Clock save is modelled (Part
    //1, clause 36.3's volatile/non-volatile Clock split collapses to the one volatile field), and the clause
    //36.7 resetCount/restartCount/firmwareVersion obfuscation for a signer outside the Platform/Endorsement
    //hierarchy is not applied — every attestation reports the raw counters and firmware version regardless of
    //which hierarchy the signing key belongs to.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnStartup(TpmSimulatorState state, TpmSuConstants startupType) =>
        startupType switch
        {
            //Startup(CLEAR) after Shutdown(STATE): TPM Restart. The dictionary-attack self-heal anchors are reset
            //to zero alongside Time (clause 17.8.4/17.8.5): both are Time-relative timestamps, and Time itself
            //resets here, so an anchor left at its pre-Restart value would underflow against the new, smaller Time.
            TpmSuConstants.TPM_SU_CLEAR when state.LastOrderlyShutdown == TpmSuConstants.TPM_SU_STATE => Transition(
                state with
                {
                    Phase = TpmLifecyclePhase.Operational,
                    LastOrderlyShutdown = null,
                    Time = 0ul,
                    RestartCount = state.RestartCount + 1,
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
            TpmSuConstants.TPM_SU_CLEAR => Transition(
                state with
                {
                    Phase = TpmLifecyclePhase.Operational,
                    LastOrderlyShutdown = null,
                    Time = 0ul,
                    ResetCount = state.ResetCount + 1,
                    RestartCount = 0u,
                    ClockSafe = state.LastOrderlyShutdown == TpmSuConstants.TPM_SU_CLEAR || state.ResetCount == 0u
                        ? TpmiYesNo.Yes
                        : TpmiYesNo.No,
                    LockoutAuthEnabled = state.LockoutAuthEnabled || state.LockoutRecovery == 0u,
                    LastFailedTriesRecoveryTime = 0ul,
                    LastLockoutAuthFailureTime = 0ul,
                    PolicySessions = ImmutableDictionary<uint, PolicySessionState>.Empty,
                    //A TPM Reset invalidates every session, HMAC sessions included (TPM 2.0 Library Part 1, clause
                    //14.2/28's general Reset semantics: nothing survives from before a Reset) — this closes the gap
                    //left when PolicySessions above was first cleared: a session started before Reset must not be
                    //usable afterward, whether it authorizes by policy digest or by HMAC.
                    HmacSessions = ImmutableDictionary<uint, HmacSessionState>.Empty,
                    ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
                },
                "Startup:Reset"),

            //Startup(STATE) after a Shutdown(STATE): TPM Resume. The self-heal anchors reset to zero with Time for
            //the same reason as the Restart arm above.
            TpmSuConstants.TPM_SU_STATE when state.LastOrderlyShutdown == TpmSuConstants.TPM_SU_STATE => Transition(
                state with
                {
                    Phase = TpmLifecyclePhase.Operational,
                    LastOrderlyShutdown = null,
                    Time = 0ul,
                    RestartCount = state.RestartCount + 1,
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

    //TPM2_GetRandom() is the first command that needs an effect: the pure transition cannot draw
    //random octets, so it declares a TpmRngAction and leaves no response yet. The effectful loop
    //fills a pooled buffer via the injected RNG backend and feeds the octets back as a
    //TpmRandomGenerated input, which OnRandomGenerated turns into the framed response.
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
                ResponseIntent = new TpmRandomResponse(TpmRcConstants.TPM_RC_SUCCESS, generated.Bytes, generated.Length)
            },
            "GetRandom:Completed");

    //Sim-side fixed device-identity property values; the lockout/DA variable properties are read from
    //the live state instead.
    private const uint SimFamilyIndicator = 0x322E_3000;  //"2.0\0" packed as a UINT32.
    private const uint SimSpecLevel = 0u;
    private const uint SimSpecRevision = 184u;            //Mirrors the v184 spec corpus this models.
    private const uint SimManufacturer = 0x53_49_4D_55;   //"SIMU" — the simulator's synthetic vendor id.

    //TPM2_GetCapability() is a pure, state-derived response (no action layer): it reports a window of
    //TPM_PT properties starting at the requested tag (Part 3, clause 30.2), the prerequisite for
    //reading the dictionary-attack/lockout state the PIN flow exercises.
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

    //The TPM_PT properties the simulator reports, in ascending tag order: fixed device identity
    //(constants) followed by the variable lockout/DA properties read from the live state (Part 1, 17.8).
    private static List<TpmsTaggedProperty> BuildTpmProperties(TpmSimulatorState state)
    {
        uint permanent = state.IsInLockout ? (uint)TpmaPermanent.IN_LOCKOUT : 0u;

        return new List<TpmsTaggedProperty>
        {
            new(TpmPtConstants.TPM_PT_FAMILY_INDICATOR, SimFamilyIndicator),
            new(TpmPtConstants.TPM_PT_LEVEL, SimSpecLevel),
            new(TpmPtConstants.TPM_PT_REVISION, SimSpecRevision),
            new(TpmPtConstants.TPM_PT_MANUFACTURER, SimManufacturer),
            new(TpmPtConstants.TPM_PT_PERMANENT, permanent),
            new(TpmPtConstants.TPM_PT_LOCKOUT_COUNTER, state.FailedTries),
            new(TpmPtConstants.TPM_PT_MAX_AUTH_FAIL, state.MaxTries),
            new(TpmPtConstants.TPM_PT_LOCKOUT_INTERVAL, state.RecoveryTime),
            new(TpmPtConstants.TPM_PT_LOCKOUT_RECOVERY, state.LockoutRecovery)
        };
    }

    //Dictionary-attack self-healing (TPM 2.0 Library Part 1, clause 17.8.4/17.8.5), applied on every dispatched
    //command right after the Time advance in OnCommand. Two independent healing effects share the elapsed-Time
    //accounting: FailedTries decrements by one for every RecoveryTime seconds elapsed since the last counted
    //failure (RecoveryTime == 0 disables the decrement entirely — dictionary-attack protection is off, so
    //TPM2_DictionaryAttackLockReset() is the only way FailedTries moves), and a LockoutAuthEnabled disabled by a
    //failed lockoutAuth use flips back to enabled once LockoutRecovery seconds have elapsed since that failure
    //(LockoutRecovery == 0 disables this re-arm — OnStartup's Reset arm is then the only way it re-enables).
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

    //TPM2_NV_DefineSpace() reserves an NV Index, authorized by the owner hierarchy. The DA/PIN flow uses
    //such an Index as the dictionary-attack-protected entity (Part 1, clause 17.8.1), so the simulator
    //records its handle, authValue, attributes, and size; the data area and written-ness arrive with
    //TPM2_NV_Write().
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnNvDefineSpace(TpmSimulatorState state, TpmNvDefineSpaceRequested request)
    {
        //Authorization is resolved before the command body runs, mirroring the reference dispatcher which
        //validates the handle area and session authorization (Part 3, clause 5.5) ahead of the command
        //actions. So provisioning-handle and owner-authValue checks precede the nvIndex-range/already-defined
        //body checks; a request that is both mis-authorized and malformed answers the authorization failure.

        //Only the owner hierarchy is modelled as the provisioning authority this slice; the platform
        //hierarchy carries its own authValue and arrives later. The authorization handle is resolved in the
        //handle area, so an invalid provisioning handle is rejected first.
        if(request.AuthHandle != (uint)TpmRh.TPM_RH_OWNER)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_HANDLE);
        }

        //Owner authorization is not dictionary-attack protected (clause 17.8.1): a wrong owner authValue is
        //a plain bad-authorization, never an auth-failure that feeds the lockout counter. The comparison is
        //constant-time so a mismatch leaks no timing about the secret.
        if(!CryptographicOperations.FixedTimeEquals(request.OwnerAuthSupplied.Span, state.OwnerAuth.Span))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_BAD_AUTH);
        }

        //Command body: the handle must lie in the NV-Index range, its most-significant octet being
        //TPM_HT_NV_INDEX (Part 2, 7.2).
        if((byte)(request.NvIndex >> 24) != (byte)TpmHt.TPM_HT_NV_INDEX)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_HANDLE);
        }

        //A handle that is already defined cannot be redefined (Part 3, clause 31.3).
        if(state.NvIndexes.ContainsKey(request.NvIndex))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_NV_DEFINED);
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
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_ATTRIBUTES);
        }

        //The Index type (TPM_NT, TPMA_NV bits 7:4) must be one this TPM implements a modifying command for
        //(Part 2, clause 13.2); any other 4-bit pattern, or a type whose modifying command is unimplemented,
        //is rejected as an attribute error (see IsSupportedIndexType's own remarks below).
        TpmNt indexType = TpmaNvFields.GetTpmNt(request.Attributes);
        if(!IsSupportedIndexType(indexType))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_ATTRIBUTES);
        }

        //A Counter, PIN Fail, or PIN Pass Index's data area is always eight octets (TPM 2.0 Library Part 2,
        //clause 13.2). Part 3, clause 31.3.1 NOTE 2 is an explicit erratum here: the corrected response for a
        //mismatched declared size is TPM_RC_SIZE, not TPM_RC_ATTRIBUTES (some reference code predating the
        //erratum answered the latter).
        if(RequiresEightOctetDataSize(indexType) && request.DataSize != EightOctetDataSize)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_SIZE);
        }

        //TPMA_NV_CLEAR_STCLEAR is illegal on a Counter Index (TPM 2.0 Library Part 3, clause 31.3.1; Part 2,
        //Table 214; Part 1, clause 37.2.4.2 NOTE): a counter is either restored on an orderly startup or
        //advanced past MAX_ORDERLY_COUNT on a non-orderly one, never cleared by a Reset/Restart.
        if(indexType == TpmNt.TPM_NT_COUNTER && (request.Attributes & TpmaNv.TPMA_NV_CLEAR_STCLEAR) != 0)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_ATTRIBUTES);
        }

        //A PIN Fail Index requires TPMA_NV_NO_DA SET (Part 2, clause 13.4; Part 1, clause 37.2.6.6): this
        //keeps a PIN Fail Index's own pinCount/pinLimit defense (clause 37.2.8.2) disjoint from the TPM-wide
        //dictionary-attack mechanism by construction, never by caller discipline.
        if(indexType == TpmNt.TPM_NT_PIN_FAIL && (request.Attributes & TpmaNv.TPMA_NV_NO_DA) == 0)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_ATTRIBUTES);
        }

        //A PIN Index (Fail or Pass) forbids TPMA_NV_AUTHWRITE (Part 1, clause 37.2.6.1): its own authValue
        //authorizes reads only, never writes — provisioning and recovery are owner/platform/policy-authorized
        //administrative acts (OnNvWrite's owner-auth arm). Enforced here, at definition, rather than trusted to
        //caller discipline; without it, an unthrottled correct/incorrect-PIN oracle survives on TPM2_NV_Write().
        if((indexType == TpmNt.TPM_NT_PIN_FAIL || indexType == TpmNt.TPM_NT_PIN_PASS) && (request.Attributes & TpmaNv.TPMA_NV_AUTHWRITE) != 0)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_DefineSpace, TpmRcConstants.TPM_RC_ATTRIBUTES);
        }

        var index = new NvIndexState(request.NvIndex, request.IndexAuth, request.Attributes, request.DataSize, ReadOnlyMemory<byte>.Empty);

        return Transition(
            state with
            {
                NvIndexes = state.NvIndexes.SetItem(request.NvIndex, index),
                ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
            },
            "NvDefineSpace");

        //Of the six TPM_NT values the specification defines (Part 2, clause 13.2, Table 212), only the types
        //this simulator has a modifying command for are accepted: TPM_NT_ORDINARY (TPM2_NV_Write()),
        //TPM_NT_COUNTER (TPM2_NV_Increment(), added this wave), and TPM_NT_PIN_FAIL/TPM_NT_PIN_PASS (also
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

    //Whether an Index authValue attempt must be refused outright, before any comparison, because the Index is
    //dictionary-attack protected and the TPM is already in general Lockout mode (TPM 2.0 Library Part 1, clause
    //17.8.3: "any use of a DA-protected authValue returns TPM_RC_LOCKOUT" while locked out — checked strictly
    //ahead of the actual credential check). A non-DA Index (TPMA_NV_NO_DA set) is never subject to this gate,
    //matching how its own auth failures never feed the counter either. Shared by OnNvRead, OnNvWrite, and
    //OnNvCertify.
    private static bool IsNvIndexLockedOut(TpmSimulatorState state, NvIndexState index) =>
        index.IsDaProtected && state.IsInLockout;

    //Registers a genuine Index-authValue mismatch and rejects with the matching response code (clause
    //17.8.1/17.8.3): a DA-protected Index's failure increments FailedTries and re-anchors the self-heal clock to
    //the current Time (mirroring the reference DARegisterFailure timestamp reset) — unless dictionary-attack
    //protection is globally disabled (RecoveryTime == 0), in which case the failure is still reported but the
    //counter never moves; a non-DA Index (TPMA_NV_NO_DA set) never affects the counter at all. Shared by
    //OnNvRead, OnNvWrite, and OnNvCertify — the three Index-authorization sites the DA counter is wired to.
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

    //The format-one session-index encoding (TPM 2.0 Library Part 2, clause 6.6.2): the P bit clear, N field 8..15
    //selecting a session by its zero-based index via TPM_RC_S (flips the N field's meaning from handle to session)
    //plus TPM_RC_n (the 1-based additive block, N = index + 1). Shared by every new session-command-HMAC failure
    //site this wave adds; pre-existing bare-RC password sites (the W2b NV paths) are untouched.
    private static TpmRcConstants SessionEncodedRc(TpmRcConstants baseRc, int sessionIndex) =>
        (TpmRcConstants)((uint)baseRc + (uint)TpmRcConstants.TPM_RC_S + (0x100u * (uint)(sessionIndex + 1)));

    //The format-zero "session not loaded" warning for the session at sessionIndex (TPM_RC_REFERENCE_S0..S6, TPM 2.0
    //Library Part 2, clause 6.6.2) — a contiguous block of distinct codes, unlike the format-one additive encoding
    //SessionEncodedRc builds.
    private static TpmRcConstants SessionReferenceMissRc(int sessionIndex) =>
        (TpmRcConstants)((uint)TpmRcConstants.TPM_RC_REFERENCE_S0 + (uint)sessionIndex);

    //Registers a genuine session command-HMAC mismatch and rejects with the matching, session-index-encoded
    //response code (TPM 2.0 Library Part 3, clause 5.6, check 8): mirrors RejectNvAuthFailure's shape (a
    //DA-protected entity's failure increments FailedTries and re-anchors the self-heal clock to the current Time,
    //unless dictionary-attack protection is globally disabled — RecoveryTime == 0 — in which case the failure is
    //still reported but the counter never moves); an entity that is not DA-protected, or no entity was authorized
    //at all, never affects the counter (TPM_RC_BAD_AUTH). The state-mutation boundary (clause 5.6): only a
    //confirmed AUTH_FAIL may ever touch FailedTries.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> RejectSessionAuthFailure(
        TpmSimulatorState state, TpmCcConstants commandCode, int sessionIndex, bool isDaProtected)
    {
        if(!isDaProtected)
        {
            return Reject(state, commandCode, SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex));
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

    //Validates a command's session area against its structural attribute rules (TPM 2.0 Library Part 3, clause
    //5.5), strictly before any command-HMAC is evaluated (clause 5.5 precedes clause 5.6, confirmed against the
    //reference session-processing routine's own two-phase structure: its per-session decrypt/encrypt/attribute
    //checks all run during initial session-array retrieval, entirely before its later per-session authorization
    //loop): at most one session may set decrypt, at most one may set encrypt; a session authorizing no entity
    //must set at least one of decrypt/encrypt/audit; decrypt/encrypt SET when the command's corresponding
    //parameter is not encryptable is TPM_RC_ATTRIBUTES; decrypt/encrypt SET with a negotiated TPM_ALG_NULL
    //symmetric is TPM_RC_SYMMETRIC. Every rejection is session-index-encoded to the OFFENDING session (Part 2,
    //clause 6.6.2), sessions checked in order so a session re-setting an already-claimed attribute is blamed on
    //itself, never the session that claimed it first. Shared by every session-authorized command transition that
    //carries a session possibly requesting parameter encryption.
    private static TpmRcConstants? ValidateSessionArea(
        byte firstAttributes, bool firstAuthorizesEntity, TpmtSymDef firstSymmetric,
        bool hasSecondSession, byte secondAttributes, TpmtSymDef secondSymmetric,
        bool firstCommandParameterIsEncryptable, bool firstResponseParameterIsEncryptable)
    {
        TpmRcConstants? firstError = ValidateSessionAttributes(
            firstAttributes, firstAuthorizesEntity, firstSymmetric, sessionIndex: 0,
            decryptClaimed: false, encryptClaimed: false,
            firstCommandParameterIsEncryptable, firstResponseParameterIsEncryptable);
        if(firstError is not null)
        {
            return firstError;
        }

        if(!hasSecondSession)
        {
            return null;
        }

        bool decryptClaimedByFirst = (firstAttributes & (byte)TpmaSession.DECRYPT) != 0;
        bool encryptClaimedByFirst = (firstAttributes & (byte)TpmaSession.ENCRYPT) != 0;

        return ValidateSessionAttributes(
            secondAttributes, authorizesEntity: false, secondSymmetric, sessionIndex: 1,
            decryptClaimedByFirst, encryptClaimedByFirst,
            firstCommandParameterIsEncryptable, firstResponseParameterIsEncryptable);

        //One session's own decrypt/encrypt/audit attribute checks, in the reference's own per-attribute order
        //(decrypt, then encrypt, then the "must authorize or be decrypt/encrypt/audit" catch-all).
        static TpmRcConstants? ValidateSessionAttributes(
            byte attributes, bool authorizesEntity, TpmtSymDef symmetric, int sessionIndex,
            bool decryptClaimed, bool encryptClaimed,
            bool commandParameterIsEncryptable, bool responseParameterIsEncryptable)
        {
            bool decrypt = (attributes & (byte)TpmaSession.DECRYPT) != 0;
            bool encrypt = (attributes & (byte)TpmaSession.ENCRYPT) != 0;
            bool audit = (attributes & (byte)TpmaSession.AUDIT) != 0;

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

            if(!authorizesEntity && !decrypt && !encrypt && !audit)
            {
                return SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex);
            }

            return null;
        }
    }

    //Removes trailing zero octets from an authorization value before it is used in an authorization computation or
    //compare (TPM 2.0 Library Part 1, clause 19.4) — applied to both sides of a password compare and to an
    //authValue folded into a command- or response-HMAC key alike.
    private static ReadOnlySpan<byte> StripTrailingZeros(ReadOnlySpan<byte> value)
    {
        int end = value.Length;
        while(end > 0 && value[end - 1] == 0)
        {
            end--;
        }

        return value[..end];
    }

    //Whether a PIN Index's own authValue is currently unusable for authorization — unwritten, or its pinCount
    //has reached pinLimit (TPM 2.0 Library Part 1, clause 37.2.6.6). Checked strictly ahead of the credential
    //compare, mirroring IsNvIndexLockedOut's own "refuse before comparing" shape; a non-PIN Index is never
    //subject to this gate. TPM2_NV_Write() is deliberately not one of this gate's call sites: a PIN Index now
    //forbids TPMA_NV_AUTHWRITE outright (clause 37.2.6.1, enforced at TPM2_NV_DefineSpace()), so its own
    //authValue never reaches OnNvWrite's index-authValue arm at all; recovery is the owner-authorized arm's
    //administrative rewrite of the retained pinCount/pinLimit data (clause 37.2.8.1: no automatic self-heal
    //exists "until pinCount is reduced or pinLimit increased using TPM2_NV_Write()"), which is never gated by
    //this property. Shared by OnNvRead and OnNvCertify.
    private static bool IsPinAuthUnavailable(NvIndexState index) =>
        index.IsPinIndex && !index.IsPinAuthAvailable;

    //Applies a PIN Index's own pinCount update for the outcome of an authorization attempt against it (TPM
    //2.0 Library Part 1, clause 37.2.6.6): a PIN Fail Index resets pinCount to zero on success and increments
    //it on failure; a PIN Pass Index increments pinCount on success and leaves it unchanged on failure. A
    //non-PIN Index is returned unchanged. Shared by OnNvRead and OnNvCertify.
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

    //TPM2_NV_Read() authorizes against an NV Index, then reads its data. This slice models Index
    //authorization (the authorization handle is the Index itself), the owner-authorized arm (authHandle ==
    //TPM_RH_OWNER, gated on TPMA_NV_OWNERREAD, Part 3, clause 31.13's "Proper authorizations ... determined
    //by TPMA_NV_PPREAD, TPMA_NV_OWNERREAD, TPMA_NV_AUTHREAD"), and the authorization outcomes that the DA/PIN
    //flow turns on; the data-returning path is here, and the lockout-counter coupling (clause 17.8.3) is
    //wired through IsNvIndexLockedOut/RejectNvAuthFailure above.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnNvRead(TpmSimulatorState state, TpmNvReadRequested request)
    {
        //The Index must exist (Part 3, clause 31.13).
        if(!state.NvIndexes.TryGetValue(request.NvIndex, out NvIndexState? index))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Read, TpmRcConstants.TPM_RC_HANDLE);
        }

        //An owner-authorized read is administrative: compared against the owner hierarchy's own authValue,
        //which is never dictionary-attack protected (Part 1, clause 19.8.1: "the authValue associated with a
        //permanent entity, other than TPM_RH_LOCKOUT, does not receive DA protection"), so a mismatch is a
        //plain bad-authorization. On a match the read proceeds directly - none of IsNvIndexLockedOut/
        //IsPinAuthUnavailable/ApplyPinAuthOutcome apply, since this arm authorizes the OWNER, not the
        //Index's own authValue/PIN: pinCount moves only when the INDEX's own authValue resolves the
        //authorization (Part 1, clause 37.2.6.6), never on the administrative owner path. Mirrors
        //TPM2_NV_Write()'s owner arm exactly.
        if(request.AuthHandle == (uint)TpmRh.TPM_RH_OWNER)
        {
            //With TPMA_NV_OWNERREAD clear owner authorization cannot read this Index (Part 3, clause 31.13) -
            //checked BEFORE the owner-auth compare below, the same non-leaking order the owner-write arm's
            //TPMA_NV_OWNERWRITE gate uses.
            if(!index.IsOwnerReadAllowed)
            {
                return Reject(state, TpmCcConstants.TPM_CC_NV_Read, TpmRcConstants.TPM_RC_NV_AUTHORIZATION);
            }

            if(!CryptographicOperations.FixedTimeEquals(request.AuthSupplied.Span, state.OwnerAuth.Span))
            {
                return Reject(state, TpmCcConstants.TPM_CC_NV_Read, TpmRcConstants.TPM_RC_BAD_AUTH);
            }

            return ReadIndexWindow(state, index, request.Offset, request.Size);
        }

        //Otherwise only Index authorization (authHandle == nvIndex) is modelled this slice; policy-authorized
        //reads against the same Index arrive later.
        if(request.AuthHandle != request.NvIndex)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Read, TpmRcConstants.TPM_RC_AUTH_TYPE);
        }

        //Already-locked-out DA-protected Index: refuse before even comparing (clause 17.8.3), no further increment.
        if(IsNvIndexLockedOut(state, index))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Read, TpmRcConstants.TPM_RC_LOCKOUT);
        }

        //A PIN Index's own authValue is not usable while unwritten or once pinCount has reached pinLimit
        //(clause 37.2.6.6) — refused before even comparing, the same shape as the general-lockout gate above
        //but scoped to this Index's own localized counter rather than the TPM-wide one. This gate is
        //Index-arm-only: it never applies to the owner-read arm above, which has already returned by this
        //point (Part 1, clause 37.2.6.6 ties pinCount availability to the Index's OWN authValue).
        if(IsPinAuthUnavailable(index))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Read, TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE);
        }

        //Constant-time comparison of the supplied authorization against the Index authValue. A mismatch is
        //an auth-failure for a DA-protected Index (clause 17.8.3 — feeds the lockout counter) and a plain
        //bad-authorization for a non-DA Index (clause 17.8.1). A PIN Index's own pinCount is updated on
        //either outcome (clause 37.2.6.6) ahead of the DA-counter/access-permission checks below: authorization
        //is resolved before the command body runs, so the update applies regardless of what the body itself
        //later decides (Part 1, clause 17).
        bool authMatched = CryptographicOperations.FixedTimeEquals(request.AuthSupplied.Span, index.AuthValue.Span);
        if(index.IsPinIndex)
        {
            index = ApplyPinAuthOutcome(index, authMatched);
            state = state with { NvIndexes = state.NvIndexes.SetItem(index.NvIndex, index) };
        }

        if(!authMatched)
        {
            return RejectNvAuthFailure(state, index, TpmCcConstants.TPM_CC_NV_Read);
        }

        //The session authValue matched; the command body then checks that the Index permits authValue-based
        //reading. With TPMA_NV_AUTHREAD clear the Index authValue cannot authorize a read (Part 2, clause
        //13.4), so the read is refused with TPM_RC_NV_AUTHORIZATION even though the value matched (Part 3,
        //clause 31.13 access checks). A wrong value still fails earlier as an auth-failure/bad-auth, so this
        //is reached only on a correct value against a non-AUTHREAD Index.
        if(!index.IsAuthReadAllowed)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Read, TpmRcConstants.TPM_RC_NV_AUTHORIZATION);
        }

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
            if(!index.IsWritten)
            {
                return Reject(state, TpmCcConstants.TPM_CC_NV_Read, TpmRcConstants.TPM_RC_NV_UNINITIALIZED);
            }

            if((long)offset + size > index.Data.Length)
            {
                return Reject(state, TpmCcConstants.TPM_CC_NV_Read, TpmRcConstants.TPM_RC_NV_RANGE);
            }

            //Return the stored octets at the requested offset/length; the data references durable model
            //state, framed into the response as a TPM2B_MAX_NV_BUFFER by the serializer.
            ReadOnlyMemory<byte> window = index.Data.Slice(offset, size);

            return Transition(
                state with { ResponseIntent = new TpmNvReadDataResponse(TpmRcConstants.TPM_RC_SUCCESS, window) },
                "NvRead");
        }
    }

    //TPM2_NV_Write() writes data to a defined NV Index at an offset, then sets TPMA_NV_WRITTEN (Part 3, clause
    //31.7). This slice models two authorization arms: Index authorization (authHandle == nvIndex, gated by
    //TPMA_NV_AUTHWRITE) and owner authorization (authHandle == TPM_RH_OWNER, administrative and never DA/PIN
    //gated — the sole write path for a PIN Index, whose own authValue forbids AUTHWRITE outright, Part 1, clause
    //37.2.6.1). Policy-authorized writes arrive later. The write itself is a pure state transition over the
    //retained data area with no crypto, so a successful write is a header-only response (as NV_UndefineSpace is).
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnNvWrite(TpmSimulatorState state, TpmNvWriteRequested request)
    {
        //The Index must exist (Part 3, clause 31.7).
        if(!state.NvIndexes.TryGetValue(request.NvIndex, out NvIndexState? index))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Write, TpmRcConstants.TPM_RC_HANDLE);
        }

        //An owner-authorized write is administrative: compared against the owner hierarchy's own authValue, which
        //is never dictionary-attack protected (clause 17.8.1), so a mismatch is a plain bad-authorization. On a
        //match the write proceeds directly — none of IsNvIndexLockedOut/IsPinAuthUnavailable/ApplyPinAuthOutcome
        //apply, since this arm authorizes the OWNER, not the Index's own authValue/PIN.
        if(request.AuthHandle == (uint)TpmRh.TPM_RH_OWNER)
        {
            //With TPMA_NV_OWNERWRITE clear owner authorization cannot write this Index (Part 2, clause 13.4) —
            //checked BEFORE the owner-auth compare below (the same non-leaking order the index-auth arm uses for
            //TPMA_NV_AUTHWRITE), so an owner write against an Index that does not permit it rejects identically
            //regardless of the supplied owner authValue.
            if(!index.IsOwnerWriteAllowed)
            {
                return Reject(state, TpmCcConstants.TPM_CC_NV_Write, TpmRcConstants.TPM_RC_NV_AUTHORIZATION);
            }

            if(!CryptographicOperations.FixedTimeEquals(request.AuthSupplied.Span, state.OwnerAuth.Span))
            {
                return Reject(state, TpmCcConstants.TPM_CC_NV_Write, TpmRcConstants.TPM_RC_BAD_AUTH);
            }

            return WriteIndexData(state, index, request.Offset, request.Data);
        }

        //Otherwise only Index authorization (authHandle == nvIndex) is modelled; policy-authorized writes against
        //the same Index arrive later, mirroring TPM2_NV_Read().
        if(request.AuthHandle != request.NvIndex)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Write, TpmRcConstants.TPM_RC_AUTH_TYPE);
        }

        //Already-locked-out DA-protected Index: refuse before even comparing (clause 17.8.3), no further increment.
        if(IsNvIndexLockedOut(state, index))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Write, TpmRcConstants.TPM_RC_LOCKOUT);
        }

        //With TPMA_NV_AUTHWRITE clear the Index authValue cannot authorize a write at all (Part 2, clause 13.4) —
        //checked BEFORE the value compare below (not after, as TPM2_NV_Read()'s AUTHREAD-equivalent check runs):
        //an AUTHWRITE-clear Index (every PIN Index, per TPM2_NV_DefineSpace()'s mandate) rejects a correct and an
        //incorrect authValue with the identical TPM_RC_NV_AUTHORIZATION, so no comparison outcome ever leaks which
        //one it was.
        if(!index.IsAuthWriteAllowed)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Write, TpmRcConstants.TPM_RC_NV_AUTHORIZATION);
        }

        //Constant-time comparison of the supplied authorization against the Index authValue. A mismatch is an
        //auth-failure for a DA-protected Index (clause 17.8.3) and a plain bad-authorization for a non-DA Index
        //(clause 17.8.1), the same outcomes TPM2_NV_Read() turns on.
        if(!CryptographicOperations.FixedTimeEquals(request.AuthSupplied.Span, index.AuthValue.Span))
        {
            return RejectNvAuthFailure(state, index, TpmCcConstants.TPM_CC_NV_Write);
        }

        return WriteIndexData(state, index, request.Offset, request.Data);

        //Range-checks the write against the Index's declared data area (Part 3, clause 31.7: offset + size must
        //not exceed the size established at TPM2_NV_DefineSpace()), then stores it and sets TPMA_NV_WRITTEN.
        //Shared by both the owner-authorized and the index-authValue write arms above, so the type gate below
        //runs once, after either arm has already resolved authorization.
        static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> WriteIndexData(
            TpmSimulatorState state, NvIndexState index, ushort offset, ReadOnlyMemory<byte> data)
        {
            //TPM2_NV_Write() updates an Ordinary or PIN Index only; a Counter, Bit Field, or Extend Index is
            //modified through its own dedicated command instead (TPM2_NV_Increment()/SetBits()/Extend()) — TPM
            //2.0 Library Part 3, clause 31.7.1: the four update commands partition NV Index types, and each
            //rejects every type but its own with TPM_RC_ATTRIBUTES. TPM_NT_BITS/TPM_NT_EXTEND are listed for
            //spec fidelity even though TPM2_NV_DefineSpace() already refuses those types outright.
            if(index.IndexType is TpmNt.TPM_NT_COUNTER or TpmNt.TPM_NT_BITS or TpmNt.TPM_NT_EXTEND)
            {
                return Reject(state, TpmCcConstants.TPM_CC_NV_Write, TpmRcConstants.TPM_RC_ATTRIBUTES);
            }

            if((long)offset + data.Length > index.DataSize)
            {
                return Reject(state, TpmCcConstants.TPM_CC_NV_Write, TpmRcConstants.TPM_RC_NV_RANGE);
            }

            NvIndexState updated = index.WriteData(offset, data.Span);

            return Transition(
                state with
                {
                    NvIndexes = state.NvIndexes.SetItem(index.NvIndex, updated),
                    ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
                },
                "NvWrite");
        }
    }

    //TPM2_NV_UndefineSpace() removes a defined NV Index and frees its handle (Part 3, clause 31.4). A
    //pure state transition: drop the Index from the table. An undefined handle is TPM_RC_HANDLE. Owner
    //authorization is modelled; the policy-delete variant (UndefineSpaceSpecial, clause 31.5) is not.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnNvUndefineSpace(TpmSimulatorState state, TpmNvUndefineSpaceRequested request)
    {
        if(!state.NvIndexes.TryGetValue(request.NvIndex, out NvIndexState? index))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmRcConstants.TPM_RC_HANDLE);
        }

        //Only the owner hierarchy is modelled as the provisioning authority this slice - the same
        //TPMI_RH_PROVISION-typed @authHandle TPM2_NV_DefineSpace() carries (Part 3, clause 31.3); the
        //platform hierarchy carries its own authValue and arrives later. Clause 31.4 states no distinct
        //response code for a caller-supplied @authHandle outside {TPM_RH_OWNER, TPM_RH_PLATFORM}, so this
        //mirrors OnNvDefineSpace's identical handle-type-check gate exactly: TPM_RC_HANDLE.
        if(request.AuthHandle != (uint)TpmRh.TPM_RH_OWNER)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmRcConstants.TPM_RC_HANDLE);
        }

        //Owner authorization is not dictionary-attack protected (Part 1, clause 19.8.1: "the authValue
        //associated with a permanent entity, other than TPM_RH_LOCKOUT, does not receive DA protection"): a
        //wrong owner authValue is a plain bad-authorization, never an auth-failure that feeds the lockout
        //counter, and the comparison is constant-time so a mismatch leaks no timing about the secret. This
        //closes the previously discarded authorization-area residual: without this compare, any caller able
        //to address the wire command at all could undefine-then-redefine any Index regardless of the supplied
        //owner authValue - a direct throttle-reset primitive against a PIN Fail Index, since the phantom
        //high-water mark below is COUNTER-only (Part 1, clause 37.2.6.6).
        if(!CryptographicOperations.FixedTimeEquals(request.AuthSupplied.Span, state.OwnerAuth.Span))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmRcConstants.TPM_RC_BAD_AUTH);
        }

        //Deleting a written Counter Index retires its value into the phantom high-water mark (TPM 2.0 Library
        //Part 1, clause 37.2.6.3 NOTE 2/NOTE 6): a later redefinition of the same handle can never seed its
        //first TPM2_NV_Increment() at or below a value this Name has already reported, closing the
        //delete-then-redefine rollback the increment's own initialization rule (clause 31.2) depends on.
        ulong highWaterMark = index.IndexType == TpmNt.TPM_NT_COUNTER && index.IsWritten && index.CounterValue > state.NvCounterHighWaterMark
            ? index.CounterValue
            : state.NvCounterHighWaterMark;

        return Transition(
            state with
            {
                NvIndexes = state.NvIndexes.Remove(request.NvIndex),
                NvCounterHighWaterMark = highWaterMark,
                ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
            },
            "NvUndefineSpace");
    }

    //TPM2_NV_Increment() increments a Counter Index's 8-octet value by one, authorized by either the owner
    //hierarchy or the Index's own authValue (Part 3, clause 31.8). This slice models the same two
    //authorization arms as TPM2_NV_Write() (owner-administrative and Index-authValue); policy- and
    //platform-authorized increments arrive later. TPMA_NV_ORDERLY is accepted and retained raw at
    //TPM2_NV_DefineSpace() but has no observable effect here: every increment writes synchronously to the
    //retained NV data (the TPMA_NV_ORDERLY-CLEAR path, Part 1, clause 37.2.6.3), so no RAM-shadow counter or
    //MAX_ORDERLY_COUNT batching is modelled — a deliberate scope decision (SPEC OQ-3), not a gap: the
    //counter's externally observed value is unaffected either way, since ORDERLY is a write-endurance
    //optimization, not a correctness-relevant semantic.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnNvIncrement(TpmSimulatorState state, TpmNvIncrementRequested request)
    {
        //The Index must exist (Part 3, clause 31.8).
        if(!state.NvIndexes.TryGetValue(request.NvIndex, out NvIndexState? index))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Increment, TpmRcConstants.TPM_RC_HANDLE);
        }

        //An owner-authorized increment is administrative: compared against the owner hierarchy's own authValue,
        //which is never dictionary-attack protected (clause 17.8.1), so a mismatch is a plain bad-authorization.
        //None of the Index-entity DA gates (IsNvIndexLockedOut/RejectNvAuthFailure) apply on this arm — the
        //clause 5.6 lockout gate binds the entity whose authValue is compared, and here that is the OWNER, not
        //the Index; the same posture TPM2_NV_Write()'s owner arm takes.
        if(request.AuthHandle == (uint)TpmRh.TPM_RH_OWNER)
        {
            //With TPMA_NV_OWNERWRITE clear owner authorization cannot increment this Index (Part 2, clause
            //13.4) - checked BEFORE the owner-auth compare, mirroring OnNvWrite's owner arm.
            if(!index.IsOwnerWriteAllowed)
            {
                return Reject(state, TpmCcConstants.TPM_CC_NV_Increment, TpmRcConstants.TPM_RC_NV_AUTHORIZATION);
            }

            if(!CryptographicOperations.FixedTimeEquals(request.AuthSupplied.Span, state.OwnerAuth.Span))
            {
                return Reject(state, TpmCcConstants.TPM_CC_NV_Increment, TpmRcConstants.TPM_RC_BAD_AUTH);
            }
        }
        else
        {
            //Otherwise only Index authorization (authHandle == nvIndex) is modelled; policy/platform-authorized
            //increments against the same Index arrive later, mirroring TPM2_NV_Write() (Part 3, clause 31.1: an
            //Index-authorization authHandle that does not equal the Index itself is TPM_RC_NV_AUTHORIZATION).
            if(request.AuthHandle != request.NvIndex)
            {
                return Reject(state, TpmCcConstants.TPM_CC_NV_Increment, TpmRcConstants.TPM_RC_NV_AUTHORIZATION);
            }

            //Already-locked-out DA-protected Index: refuse before even comparing (clause 17.8.3) - the clause
            //5.6 lockout gate binds this arm because the entity whose authValue is compared here IS the
            //DA-protected Index, mirroring OnNvWrite's index arm.
            if(IsNvIndexLockedOut(state, index))
            {
                return Reject(state, TpmCcConstants.TPM_CC_NV_Increment, TpmRcConstants.TPM_RC_LOCKOUT);
            }

            //With TPMA_NV_AUTHWRITE clear the Index authValue cannot authorize an increment at all (Part 2,
            //clause 13.4) - checked BEFORE the value compare, mirroring OnNvWrite's index arm.
            if(!index.IsAuthWriteAllowed)
            {
                return Reject(state, TpmCcConstants.TPM_CC_NV_Increment, TpmRcConstants.TPM_RC_NV_AUTHORIZATION);
            }

            //Constant-time comparison of the supplied authorization against the Index authValue. A mismatch is
            //an auth-failure for a DA-protected Index (clause 17.8.3) and a plain bad-authorization for a
            //non-DA Index (clause 17.8.1) - TPMA_NV_NO_DA applies uniformly, with no counter-type carve-out.
            if(!CryptographicOperations.FixedTimeEquals(request.AuthSupplied.Span, index.AuthValue.Span))
            {
                return RejectNvAuthFailure(state, index, TpmCcConstants.TPM_CC_NV_Increment);
            }
        }

        //TPM2_NV_Increment() modifies a Counter Index only; every other type is refused (Part 3, clause
        //31.8.1: "If nvIndexType is not TPM_NT_COUNTER... the TPM shall return TPM_RC_ATTRIBUTES").
        if(index.IndexType != TpmNt.TPM_NT_COUNTER)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Increment, TpmRcConstants.TPM_RC_ATTRIBUTES);
        }

        //A write-locked Index cannot be incremented (Part 3, clause 31.8.1). No command in this simulator can
        //SET TPMA_NV_WRITELOCKED today (TPM2_NV_WriteLock() is unmodelled), so this branch is presently
        //unreachable in practice, but the gate lands fail-closed rather than being silently omitted.
        if((index.Attributes & TpmaNv.TPMA_NV_WRITELOCKED) != 0)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Increment, TpmRcConstants.TPM_RC_NV_LOCKED);
        }

        //Unwritten counter: seed from the highest value any counter Index with this Name has ever held,
        //including one already deleted (the phantom-counter mechanism on NvCounterHighWaterMark, TPM 2.0
        //Library Part 1, clause 37.2.6.3 NOTE 2/NOTE 6), then increment. A written counter simply increments
        //its stored value. TPM2_NV_Increment() never answers TPM_RC_NV_UNINITIALIZED for an unwritten counter
        //- performing the first write IS its contract (Part 3, clause 31.8.1).
        ulong seed = index.IsWritten ? index.CounterValue : state.NvCounterHighWaterMark;
        NvIndexState updated = index.WithCounterValue(seed + 1);

        return Transition(
            state with
            {
                NvIndexes = state.NvIndexes.SetItem(index.NvIndex, updated),
                ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
            },
            "NvIncrement");
    }

    //TPM2_EvictControl() persists a loaded transient object to a persistent handle, or evicts a persistent
    //object addressed by that handle (Part 3, clause 28.5). A pure state transition over the persistent-objects
    //table: persisting copies the object (the transient stays loaded), evicting removes it. The persistent
    //handle must be in the TPM_HT_PERSISTENT range (MSO 0x81); an object that is neither loaded transient nor
    //persistent is TPM_RC_HANDLE.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnEvictControl(TpmSimulatorState state, TpmEvictControlRequested request)
    {
        //Persist: the object is a loaded transient object, copied to the persistent handle under its new handle.
        if(state.TransientObjects.TryGetValue(request.ObjectHandle, out TransientKeyState? transient))
        {
            if((request.PersistentHandle >> 24) != (TpmSimulatorState.PersistentHandleBase >> 24))
            {
                return Reject(state, TpmCcConstants.TPM_CC_EvictControl, TpmRcConstants.TPM_RC_VALUE);
            }

            return Transition(
                state with
                {
                    PersistentObjects = state.PersistentObjects.SetItem(request.PersistentHandle, transient with { Handle = request.PersistentHandle }),
                    ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
                },
                "EvictControl:Persist");
        }

        //Evict: the object handle is itself an existing persistent object.
        if(state.PersistentObjects.ContainsKey(request.ObjectHandle))
        {
            return Transition(
                state with
                {
                    PersistentObjects = state.PersistentObjects.Remove(request.ObjectHandle),
                    ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
                },
                "EvictControl:Evict");
        }

        return Reject(state, TpmCcConstants.TPM_CC_EvictControl, TpmRcConstants.TPM_RC_HANDLE);
    }

    //TPM2_CreatePrimary() needs an effect: the pure transition cannot generate a key, so it allocates the
    //transient handle, declares a TpmCreateEccKeyAction carrying the template fields the effect needs, and
    //leaves no response yet. The effectful loop draws the key from the injected backend, builds the exported
    //public area and the durable key state, and feeds them back as a TpmPrimaryKeyCreated input.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnCreatePrimary(TpmSimulatorState state, TpmCreatePrimaryRequested request)
    {
        //An unsupported nameAlg cannot be computed (TpmObjectName), so it is rejected up front rather than
        //defaulted (TPM 2.0 Library Part 3, CreatePrimary error conditions: an unsupported hash is TPM_RC_HASH).
        if(!IsSupportedNameAlg(request.NameAlg))
        {
            return Reject(state, TpmCcConstants.TPM_CC_CreatePrimary, TpmRcConstants.TPM_RC_HASH);
        }

        uint handle = state.NextObjectHandle;

        return Transition(
            state with
            {
                NextObjectHandle = state.NextObjectHandle + 1,
                NextAction = new TpmCreateEccKeyAction(handle, request.Hierarchy, request.NameAlg, request.Attributes, request.Curve, request.SchemeHashAlg, request.AuthPolicy),
                ResponseIntent = null
            },
            "CreatePrimary:Requested");
    }

    //The RSA counterpart of OnCreatePrimary: allocate the transient handle and declare a TpmCreateRsaKeyAction
    //so the effectful loop generates the RSA key, builds the exported public area carrying the modulus, and
    //feeds it back as the same TpmPrimaryKeyCreated input the ECC path uses.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnCreateRsaPrimary(TpmSimulatorState state, TpmCreateRsaPrimaryRequested request)
    {
        if(!IsSupportedNameAlg(request.NameAlg))
        {
            return Reject(state, TpmCcConstants.TPM_CC_CreatePrimary, TpmRcConstants.TPM_RC_HASH);
        }

        uint handle = state.NextObjectHandle;

        return Transition(
            state with
            {
                NextObjectHandle = state.NextObjectHandle + 1,
                NextAction = new TpmCreateRsaKeyAction(handle, request.Hierarchy, request.NameAlg, request.Attributes, request.KeyBits, request.Scheme, request.AuthPolicy),
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
                    TpmRcConstants.TPM_RC_SUCCESS, created.KeyState.Handle, created.OutPublic, created.CreationByProducts, created.CreationByProductsLength)
            },
            "CreatePrimary:Completed");

    //TPM2_Sign() resolves the key handle, then declares the signing action matching the key's algorithm so the
    //effectful loop signs the digest with the retained key through the injected backend; OnMessageSigned frames
    //the result. The signing scheme comes from the command (an unrestricted key signs under the caller's scheme).
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnSign(TpmSimulatorState state, TpmSignRequested request)
    {
        //The key must be a loaded transient object (Part 3, clause 20.2). The scheme/curve compatibility a TPM
        //also checks arrives with richer key models.
        if(!state.TransientObjects.TryGetValue(request.KeyHandle, out TransientKeyState? key))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Sign, TpmRcConstants.TPM_RC_HANDLE);
        }

        TpmAction action = key.KeyType == TpmAlgIdConstants.TPM_ALG_RSA
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
                ResponseIntent = new TpmSignResponse(TpmRcConstants.TPM_RC_SUCCESS, signed.Signature, signed.SignatureScheme, signed.HashAlg)
            },
            "Sign:Completed");

    //TPM2_CreatePrimary() for an ECC storage parent needs an effect: the pure transition cannot generate a key, so
    //it allocates the transient handle and declares a TpmCreateStorageParentAction carrying the storage template
    //fields. The effectful loop draws a real key from the injected backend and builds the exported storage public
    //area carrying its actual public point plus the durable parent state — the simulator still does not wrap
    //children under a parent key (a storage parent here is only ever used as a handle for TPM2_Create()), but the
    //exported point is genuine, matching what an endorsement-key certificate would be issued over — and feeds
    //them back as the same TpmPrimaryKeyCreated input the signing paths use.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnCreateStorageParent(TpmSimulatorState state, TpmCreateStorageParentRequested request)
    {
        if(!IsSupportedNameAlg(request.NameAlg))
        {
            return Reject(state, TpmCcConstants.TPM_CC_CreatePrimary, TpmRcConstants.TPM_RC_HASH);
        }

        uint handle = state.NextObjectHandle;

        return Transition(
            state with
            {
                NextObjectHandle = state.NextObjectHandle + 1,
                NextAction = new TpmCreateStorageParentAction(handle, request.Hierarchy, request.NameAlg, request.Attributes, request.Curve, request.NoDa, request.AuthPolicy),
                ResponseIntent = null
            },
            "CreatePrimary:Requested");
    }

    //The RSA counterpart of OnCreateStorageParent: allocate the transient handle and declare a
    //TpmCreateRsaStorageParentAction so the effectful loop generates the RSA key, builds the exported storage
    //public area carrying the modulus, retains the modulus on the durable parent state, and feeds it back as the
    //same TpmPrimaryKeyCreated input the other CreatePrimary paths use. This is the path the standard RSA
    //endorsement key (TCG EK Credential Profile, Annex B.3.3, Template L-1) rides.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnCreateRsaStorageParent(TpmSimulatorState state, TpmCreateRsaStorageParentRequested request)
    {
        if(!IsSupportedNameAlg(request.NameAlg))
        {
            return Reject(state, TpmCcConstants.TPM_CC_CreatePrimary, TpmRcConstants.TPM_RC_HASH);
        }

        uint handle = state.NextObjectHandle;

        return Transition(
            state with
            {
                NextObjectHandle = state.NextObjectHandle + 1,
                NextAction = new TpmCreateRsaStorageParentAction(handle, request.Hierarchy, request.NameAlg, request.Attributes, request.KeyBits, request.NoDa, request.AuthPolicy),
                ResponseIntent = null
            },
            "CreatePrimary:Requested");
    }

    //TPM2_Create() seals caller-supplied data into a KEYEDHASH object under a loaded storage parent (Part 3,
    //clause 12.1). The parent must be a loaded restricted storage object; a missing handle is TPM_RC_HANDLE and a
    //non-storage parent is TPM_RC_TYPE. DA/Lockout for the parent is checked before any further processing (Part
    //3, clause 5.6, check 3) — a locked-out TPM never performs the Create, matching OnUnseal and the
    //over-sessions form's identical, unconditional gate. The seal needs an effect (the wrapped blob and the
    //faithful by-products), so the transition declares a TpmSealDataAction and leaves no response yet;
    //OnObjectSealed frames the result. The created object is not loaded, so no transient handle is allocated here.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnCreateSealedObject(TpmSimulatorState state, TpmCreateSealedObjectRequested request)
    {
        if(!state.TransientObjects.TryGetValue(request.ParentHandle, out TransientKeyState? parent))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Create, TpmRcConstants.TPM_RC_HANDLE);
        }

        if(!IsStorageParent(parent.Attributes))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Create, TpmRcConstants.TPM_RC_TYPE);
        }

        bool parentIsDaProtected = (parent.Attributes & TpmaObject.NO_DA) == 0;
        if(parentIsDaProtected && state.IsInLockout)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Create, TpmRcConstants.TPM_RC_LOCKOUT);
        }

        if(!IsSupportedNameAlg(request.NameAlg))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Create, TpmRcConstants.TPM_RC_HASH);
        }

        return Transition(
            state with
            {
                NextAction = new TpmSealDataAction(request.ParentHandle, request.NameAlg, request.AuthPolicy, request.NoDa, request.UserWithAuth, request.SecretData, request.UserAuth),
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
                    TpmRcConstants.TPM_RC_SUCCESS, sealedObject.PrivateBlob, sealedObject.PrivateBlobLength, sealedObject.OutPublic, sealedObject.CreationByProducts, sealedObject.CreationByProductsLength)
            },
            "Create:Completed");

    //TPM2_Create() whose parent authorization is a bound HMAC session or TPM_RS_PW, optionally paired with a
    //SEPARATE bound HMAC session carrying the decrypt attribute that protects inSensitive (Part 3, clause 12.1;
    //Part 1, clauses 19 and 21). The parent must be a loaded restricted storage object (TPM_RC_HANDLE/TPM_RC_TYPE
    //as OnCreateSealedObject). The session area's own attribute rules (clause 5.5) are validated before any HMAC
    //is evaluated; DA/Lockout for the parent is checked before any HMAC is evaluated (clause 5.6, check 3) —
    //the parent carries no retained authValue in this model, so the entity term always folds to Empty, but the
    //bind-omission and dictionary-attack mechanisms still run uniformly. Every session that resolves in
    //state.HmacSessions needs its command HMAC verified through the shared mechanism (TpmVerifyCommandHmacAction);
    //ContinueCreateOverSessions resumes once the queue empties.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnCreateSealedObjectOverSessions(TpmSimulatorState state, TpmCreateSealedObjectOverSessionsRequested request)
    {
        if(!state.TransientObjects.TryGetValue(request.ParentHandle, out TransientKeyState? parent))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Create, TpmRcConstants.TPM_RC_HANDLE);
        }

        if(!IsStorageParent(parent.Attributes))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Create, TpmRcConstants.TPM_RC_TYPE);
        }

        //inPublic (and so its Name algorithm) is not decoded until TpmDecryptCreateSensitiveAction runs, strictly
        //after the command HMAC(s) verify; OnCreateSensitiveDecrypted checks IsSupportedNameAlg once it is known.
        bool firstIsHmac = state.HmacSessions.TryGetValue(request.FirstSession, out HmacSessionState? firstHmacSession);
        if(!firstIsHmac && request.FirstSession != (uint)TpmRh.TPM_RH_PW)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Create, TpmRcConstants.TPM_RC_HANDLE);
        }

        bool hasSecondSession = request.DecryptSession != 0;
        HmacSessionState? secondSession = null;
        if(hasSecondSession && !state.HmacSessions.TryGetValue(request.DecryptSession, out secondSession))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Create, TpmRcConstants.TPM_RC_HANDLE);
        }

        TpmRcConstants? sessionAreaError = ValidateSessionArea(
            request.FirstAttributes, firstAuthorizesEntity: true, firstIsHmac ? firstHmacSession!.Symmetric : TpmtSymDef.Null,
            hasSecondSession, request.DecryptAttributes, secondSession?.Symmetric ?? TpmtSymDef.Null,
            firstCommandParameterIsEncryptable: true, firstResponseParameterIsEncryptable: false);
        if(sessionAreaError is TpmRcConstants sessionAreaRc)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Create, sessionAreaRc);
        }

        //DA/Lockout is checked before any credential is evaluated (Part 3, clause 5.6, check 3) — unconditionally,
        //regardless of whether the parent's authorizing session is a bound HMAC session or plain TPM_RS_PW. A
        //locked-out TPM must never perform the Create merely because the parent happened to be authorized by a
        //password rather than an HMAC session.
        bool parentIsDaProtected = (parent.Attributes & TpmaObject.NO_DA) == 0;
        if(parentIsDaProtected && state.IsInLockout)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Create, TpmRcConstants.TPM_RC_LOCKOUT);
        }

        //Whether the second session (if present) actually requests decryption: the fold (clause 19.6.3.4) and the
        //decrypt step itself (ContinueCreateOverSessions) are keyed on the session's OWN decrypt attribute, not
        //merely on whether a second session is present in the authorization area (it could instead be an
        //audit-only companion, which ValidateSessionArea admits but which must never trigger a decrypt attempt).
        bool secondSessionDecrypts = hasSecondSession && (request.DecryptAttributes & (byte)TpmaSession.DECRYPT) != 0;

        var pending = ImmutableArray.CreateBuilder<TpmPendingSessionVerification>(2);

        if(firstIsHmac)
        {
            //The parent carries no retained authValue in this model (TransientKeyState has no such field, unlike
            //SealedObjectState's UserAuth), so the HMAC key's entity term is always Empty regardless of the
            //bind-omission comparison (equation 22) — the mechanism this general-purpose queue entry exercises
            //identically to Unseal's, just with a permanently-empty entity authValue here.
            ReadOnlyMemory<byte> parentAuthValue = ReadOnlyMemory<byte>.Empty;

            //The decrypt session (when the second session actually sets decrypt) authorizes no entity and sits at
            //index 1, so its nonceTPM folds into session 0's HMAC (clause 19.6.3.4) — session 0 itself authorizes
            //the parent.
            ReadOnlyMemory<byte> foldedNonces = secondSessionDecrypts ? secondSession!.NonceTpm : ReadOnlyMemory<byte>.Empty;

            pending.Add(new TpmPendingSessionVerification(
                firstHmacSession!.Handle, SessionIndex: 0, firstHmacSession.SessionAlg, firstHmacSession.SessionKey,
                parentAuthValue, parentIsDaProtected,
                request.FirstNonceCaller, firstHmacSession.NonceTpm, foldedNonces,
                request.FirstAttributes, request.FirstHmac));
        }

        if(hasSecondSession)
        {
            //The second session authorizes no entity, so no dictionary-attack gate applies and its HMAC key is
            //the session key alone. Session index 1 never folds (the fold only ever targets session index 0).
            //It still needs its own command HMAC verified regardless of which attribute (decrypt or audit) it
            //carries (clause 5.6 applies to every session in the authorization area).
            pending.Add(new TpmPendingSessionVerification(
                secondSession!.Handle, SessionIndex: 1, secondSession.SessionAlg, secondSession.SessionKey,
                AuthValue: ReadOnlyMemory<byte>.Empty, IsDaProtected: false, request.DecryptNonceCaller,
                secondSession.NonceTpm, FoldedNonces: ReadOnlyMemory<byte>.Empty, request.DecryptAttributes, request.DecryptHmac));
        }

        //Every reachable combination needs at least one command-HMAC verification: a lone password parent-auth
        //session with no decrypt session parses as TpmCreateSealedObjectRequested instead (never reaches here),
        //so pending is never empty.
        ImmutableArray<TpmPendingSessionVerification> queue = pending.ToImmutable();

        return Transition(
            state with
            {
                NextAction = new TpmVerifyCommandHmacAction(
                    TpmCcConstants.TPM_CC_Create, HandleNames: parent.Name, ParameterArea: request.RawParameterArea,
                    queue[0], queue.RemoveAt(0), request),
                ResponseIntent = null
            },
            "Create:HmacVerifyRequested");
    }

    //Resumes TPM2_Create() over sessions once every session in its authorization area has verified: declares the
    //decrypt effect, which validates inSensitive's own declared size AND decodes every parameter field — none of
    //that can happen any earlier, since inPublic's start offset depends on inSensitive's (only-now-validated)
    //declared size, and clause 5.8 field interpretation must in any case follow clause 5.6 HMAC verification.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> ContinueCreateOverSessions(TpmSimulatorState state, TpmCreateSealedObjectOverSessionsRequested request)
    {
        HmacSessionState? secondSession = request.DecryptSession != 0 ? state.HmacSessions[request.DecryptSession] : null;
        bool decrypts = secondSession is not null && (request.DecryptAttributes & (byte)TpmaSession.DECRYPT) != 0;

        return Transition(
            state with
            {
                NextAction = new TpmDecryptCreateSensitiveAction(
                    request, request.RawParameterArea, decrypts,
                    decrypts ? secondSession!.SessionAlg : TpmAlgIdConstants.TPM_ALG_NULL,
                    decrypts ? secondSession!.Symmetric : TpmtSymDef.Null,
                    decrypts ? secondSession!.SessionKey : ReadOnlyMemory<byte>.Empty,
                    decrypts ? request.DecryptNonceCaller : ReadOnlyMemory<byte>.Empty,
                    decrypts ? secondSession!.NonceTpm : ReadOnlyMemory<byte>.Empty),
                ResponseIntent = null
            },
            "Create:DecryptRequested");
    }

    //Resumes TPM2_Create() over sessions once inSensitive has been decrypted (if applicable) and decoded: a
    //malformed result (a wrong decryption key's garbage bytes failing to decode as TPMS_SENSITIVE_CREATE) rejects
    //directly; otherwise the seal proceeds, declaring TpmSealDataOverSessionsAction rather than the plain password
    //form's TpmSealDataAction — the response must carry a TPM_ST_SESSIONS envelope with a real per-session entry
    //(or a TPM_RS_PW placeholder) for every session in the command's authorization area (Part 1, clause 18.6),
    //exactly mirroring TPM2_Unseal()'s two-form split.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnCreateSensitiveDecrypted(TpmSimulatorState state, TpmCreateSensitiveDecrypted decrypted)
    {
        if(decrypted.ResponseCode != TpmRcConstants.TPM_RC_SUCCESS)
        {
            //A truncated/oversized inSensitive declared size is session-index-encoded to the decrypt session
            //(the size problem surfaces only while attempting to decrypt, Part 1, clause 21); every other
            //malformation (a generic parameter error, or the same size problem with no decrypt session present
            //to blame) is reported bare, exactly as the plain password form's parser already does.
            TpmRcConstants responseCode = decrypted.SizeFailureBlamesDecryptSession
                ? SessionEncodedRc(decrypted.ResponseCode, sessionIndex: 1)
                : decrypted.ResponseCode;

            return Reject(state, TpmCcConstants.TPM_CC_Create, responseCode);
        }

        if(!IsSupportedNameAlg(decrypted.NameAlg))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Create, TpmRcConstants.TPM_RC_HASH);
        }

        TpmCreateSealedObjectOverSessionsRequested request = decrypted.Request;

        bool firstIsHmac = state.HmacSessions.TryGetValue(request.FirstSession, out HmacSessionState? firstHmacSession);
        bool hasPasswordPlaceholder = !firstIsHmac;

        var responseSessions = ImmutableArray.CreateBuilder<TpmCreateResponseSession>(2);
        if(firstIsHmac)
        {
            //The same HMAC key the command-HMAC verification used (Part 1, clause 19.6.8): the parent carries no
            //retained authValue in this model, so the entity term is always Empty regardless of bind-omission.
            responseSessions.Add(new TpmCreateResponseSession(
                firstHmacSession!.Handle, firstHmacSession.SessionAlg, firstHmacSession.SessionKey,
                AuthValue: ReadOnlyMemory<byte>.Empty, request.FirstNonceCaller, request.FirstAttributes));
        }

        if(request.DecryptSession != 0 && state.HmacSessions.TryGetValue(request.DecryptSession, out HmacSessionState? secondSession))
        {
            responseSessions.Add(new TpmCreateResponseSession(
                secondSession.Handle, secondSession.SessionAlg, secondSession.SessionKey,
                AuthValue: ReadOnlyMemory<byte>.Empty, request.DecryptNonceCaller, request.DecryptAttributes));
        }

        return Transition(
            state with
            {
                NextAction = new TpmSealDataOverSessionsAction(
                    request.ParentHandle, decrypted.NameAlg, decrypted.AuthPolicy, decrypted.NoDa, decrypted.UserWithAuth,
                    decrypted.SecretData, decrypted.UserAuth,
                    //A password session's response unconditionally SETs continueSession (Part 1, clause 19.4) —
                    //never echoing whatever the command happened to carry.
                    hasPasswordPlaceholder, hasPasswordPlaceholder ? (byte)TpmaSession.CONTINUE_SESSION : (byte)0,
                    responseSessions.ToImmutable()),
                ResponseIntent = null
            },
            "Create:SensitiveDecrypted");
    }

    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnObjectSealedOverSessions(TpmSimulatorState state, TpmObjectSealedOverSessions sealedObject)
    {
        //Roll every real session's stored nonceTPM to the fresh value the effect drew for it (Part 1, clause
        //17.6.7) — the same replace-wholesale pattern OnEncryptedRandomProduced/ContinueUnsealOverSessions use.
        ImmutableDictionary<uint, HmacSessionState> sessions = state.HmacSessions;
        foreach(TpmCreateFramedSessionEntry entry in sealedObject.Entries)
        {
            if(sessions.TryGetValue(entry.SessionHandle, out HmacSessionState? session))
            {
                sessions = sessions.SetItem(entry.SessionHandle, session with { NonceTpm = entry.NewNonceTpm });
            }
        }

        return Transition(
            state with
            {
                NextAction = NullAction.Instance,
                HmacSessions = sessions,
                ResponseIntent = new TpmCreateOverSessionsResponse(
                    TpmRcConstants.TPM_RC_SUCCESS, sealedObject.ParameterArea, sealedObject.ParameterLength,
                    sealedObject.HasPasswordPlaceholder, sealedObject.PasswordPlaceholderAttributes, sealedObject.Entries)
            },
            "Create:CompletedOverSessions");
    }

    //TPM2_Load() brings a wrapped sealed object back into a transient slot under its storage parent (Part 3,
    //clause 12.2). The parent must be a loaded restricted storage object; a missing handle is TPM_RC_HANDLE and a
    //non-storage parent is TPM_RC_TYPE. Only a sealed KEYEDHASH object is modelled this slice, so another object
    //type is TPM_RC_TYPE. The object Name needs the digest seam, so the transition allocates the transient handle
    //and declares a TpmLoadObjectAction; OnObjectLoaded stores the object and frames the response.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnLoadObject(TpmSimulatorState state, TpmLoadObjectRequested request)
    {
        if(!state.TransientObjects.TryGetValue(request.ParentHandle, out TransientKeyState? parent))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Load, TpmRcConstants.TPM_RC_HANDLE);
        }

        if(!IsStorageParent(parent.Attributes))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Load, TpmRcConstants.TPM_RC_TYPE);
        }

        //The simulator recovers sealed data from its own blob encoding; only a sealed KEYEDHASH object is modelled.
        if(request.ObjectType != TpmAlgIdConstants.TPM_ALG_KEYEDHASH)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Load, TpmRcConstants.TPM_RC_TYPE);
        }

        if(!IsSupportedNameAlg(request.NameAlg))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Load, TpmRcConstants.TPM_RC_HASH);
        }

        uint handle = state.NextObjectHandle;

        return Transition(
            state with
            {
                NextObjectHandle = state.NextObjectHandle + 1,
                NextAction = new TpmLoadObjectAction(handle, request.NameAlg, request.AuthPolicy, request.NoDa, request.UserWithAuth, request.PublicAreaBytes, request.PrivateBlob),
                ResponseIntent = null
            },
            "Load:Requested");
    }

    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnObjectLoaded(TpmSimulatorState state, TpmObjectLoaded loadedObject)
    {
        var sealedObject = new SealedObjectState(
            loadedObject.Handle,
            loadedObject.Name.Memory[..loadedObject.NameLength].ToArray(),
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
                ResponseIntent = new TpmLoadResponse(TpmRcConstants.TPM_RC_SUCCESS, loadedObject.Handle, loadedObject.Name, loadedObject.NameLength)
            },
            "Load:Completed");
    }

    //TPM2_Unseal() returns the data sealed in a loaded KEYEDHASH object, authorized by a plain TPM_RS_PW password
    //session (Part 3, clause 12.7). An unloaded handle is TPM_RC_HANDLE. userWithAuth CLEAR rejects with
    //TPM_RC_POLICY_FAIL before any password is ever compared (Part 3, clause 5.6, check 6) — a policy/PCR-sealed
    //object (empty userAuth, non-empty authPolicy) is never recoverable via a bare password, no matter what value
    //is supplied. Otherwise the supplied password is compared against the object's retained userAuth — both sides
    //trailing-zero-stripped (Part 1, clause 19.4) — a real compare rather than the vacuous "any password accepted"
    //this path had before this wave; a DA-protected object's mismatch counts (Part 3, clause 5.6). The
    //policy-gated, encrypted-channel form is OnUnsealOverSessions.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnUnseal(TpmSimulatorState state, TpmUnsealRequested request)
    {
        if(!state.LoadedSealedObjects.TryGetValue(request.ItemHandle, out SealedObjectState? sealedObject))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Unseal, TpmRcConstants.TPM_RC_HANDLE);
        }

        //DA/Lockout is checked strictly before any credential compare (Part 3, clause 5.6, check 3) — a locked-out
        //TPM never even compares the password for a DA-protected object.
        if(sealedObject.IsDaProtected && state.IsInLockout)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Unseal, TpmRcConstants.TPM_RC_LOCKOUT);
        }

        //USER role, userWithAuth CLEAR ⇒ a policy session is required; no password may ever authorize this object
        //(Part 3, clause 5.6, check 6). This must precede the password compare below: a userWithAuth-CLEAR sealed
        //object (PCR/policy-gated, empty userAuth) would otherwise accept an empty TPM_RS_PW password and return
        //the secret in the clear, bypassing the policy the object was sealed under entirely. The HMAC-authorized
        //path (ContinueUnsealOverSessions) already enforces this identical check.
        if(!sealedObject.UserWithAuth)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Unseal, TpmRcConstants.TPM_RC_POLICY_FAIL);
        }

        ReadOnlySpan<byte> suppliedStripped = StripTrailingZeros(request.SuppliedPassword.Span);
        ReadOnlySpan<byte> userAuthStripped = StripTrailingZeros(sealedObject.UserAuth.Span);

        if(!CryptographicOperations.FixedTimeEquals(suppliedStripped, userAuthStripped))
        {
            return RejectSessionAuthFailure(state, TpmCcConstants.TPM_CC_Unseal, sessionIndex: 0, sealedObject.IsDaProtected);
        }

        return Transition(
            state with { ResponseIntent = new TpmUnsealResponse(TpmRcConstants.TPM_RC_SUCCESS, sealedObject.Data) },
            "Unseal");
    }

    //TPM2_Unseal() whose first session is either a satisfied policy session or a bound HMAC session (the primary
    //authorizer), optionally carrying a second bound HMAC session with the encrypt attribute that protects outData
    //(Part 3, clause 12.7; Part 1, clauses 18.7 and 19). The item must be loaded (TPM_RC_HANDLE otherwise). Every
    //session that resolves in state.HmacSessions needs its command HMAC verified through the shared mechanism
    //(TpmVerifyCommandHmacAction); a policy session at index 0 keeps its existing, unverified-HMAC digest gate
    //(Part 1, clause 19.6 — policy-session command-HMAC verification remains out of this wave's scope). The
    //session area's own attribute rules (clause 5.5) are validated before any HMAC is evaluated: Unseal carries no
    //command parameters, so a decrypt-attributed session here is always rejected. DA/Lockout for a DA-protected
    //item is checked before any HMAC is evaluated (clause 5.6, check 3). When session 0 is the primary HMAC
    //authorizer AND a separate encrypt session is present, session 0's command HMAC folds the encrypt session's
    //nonceTPM (clause 19.6.3.4) — the fold this wave's Package B wiring makes observable end to end.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnUnsealOverSessions(TpmSimulatorState state, TpmUnsealOverSessionsRequested request)
    {
        if(!state.LoadedSealedObjects.TryGetValue(request.ItemHandle, out SealedObjectState? sealedObject))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Unseal, TpmRcConstants.TPM_RC_HANDLE);
        }

        bool firstIsHmac = state.HmacSessions.TryGetValue(request.FirstSession, out HmacSessionState? firstHmacSession);
        if(!firstIsHmac && !state.PolicySessions.ContainsKey(request.FirstSession))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Unseal, TpmRcConstants.TPM_RC_HANDLE);
        }

        bool hasEncryptSession = request.EncryptSession != 0;
        HmacSessionState? encryptSession = null;
        if(hasEncryptSession && !state.HmacSessions.TryGetValue(request.EncryptSession, out encryptSession))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Unseal, TpmRcConstants.TPM_RC_HANDLE);
        }

        TpmRcConstants? sessionAreaError = ValidateSessionArea(
            request.PolicyAttributes, firstAuthorizesEntity: true, firstIsHmac ? firstHmacSession!.Symmetric : TpmtSymDef.Null,
            hasEncryptSession, request.EncryptAttributes, encryptSession?.Symmetric ?? TpmtSymDef.Null,
            firstCommandParameterIsEncryptable: false, firstResponseParameterIsEncryptable: true);
        if(sessionAreaError is TpmRcConstants sessionAreaRc)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Unseal, sessionAreaRc);
        }

        var pending = ImmutableArray.CreateBuilder<TpmPendingSessionVerification>(2);

        if(firstIsHmac)
        {
            //The first session authorizes the item (USER role, Part 3, clause 5.6): a DA-protected item gates
            //lockout before the HMAC is ever evaluated, and the bind-omission (equation 22) drops the item's
            //authValue from the HMAC key precisely when this session is bound to the item itself.
            if(sealedObject.IsDaProtected && state.IsInLockout)
            {
                return Reject(state, TpmCcConstants.TPM_CC_Unseal, TpmRcConstants.TPM_RC_LOCKOUT);
            }

            ReadOnlyMemory<byte> strippedUserAuth = StripTrailingZeros(sealedObject.UserAuth.Span).ToArray();
            bool bindOmits = !firstHmacSession!.BoundEntityName.IsEmpty
                && firstHmacSession.BoundEntityName.Span.SequenceEqual(sealedObject.Name.Span);

            //The second session (if present) folds into session 0's HMAC only when it actually carries decrypt or
            //encrypt (clause 19.6.3.4) — never merely because a second session is present in the authorization
            //area (it could instead be an audit-only companion, which ValidateSessionArea admits but which must
            //never fold): session 0 itself authorizes the item, satisfying the fold's own precondition.
            bool secondSessionFolds = hasEncryptSession && (request.EncryptAttributes & (byte)(TpmaSession.DECRYPT | TpmaSession.ENCRYPT)) != 0;
            ReadOnlyMemory<byte> foldedNonces = secondSessionFolds ? encryptSession!.NonceTpm : ReadOnlyMemory<byte>.Empty;

            pending.Add(new TpmPendingSessionVerification(
                firstHmacSession.Handle, SessionIndex: 0, firstHmacSession.SessionAlg, firstHmacSession.SessionKey,
                bindOmits ? ReadOnlyMemory<byte>.Empty : strippedUserAuth, sealedObject.IsDaProtected,
                request.FirstNonceCaller, firstHmacSession.NonceTpm, foldedNonces,
                request.PolicyAttributes, request.FirstHmac));
        }

        if(hasEncryptSession)
        {
            //The encrypt session authorizes no entity, so no dictionary-attack gate applies and its HMAC key is the
            //session key alone. Session index 1 never folds (the fold only ever targets session index 0).
            pending.Add(new TpmPendingSessionVerification(
                encryptSession!.Handle, SessionIndex: 1, encryptSession.SessionAlg, encryptSession.SessionKey,
                AuthValue: ReadOnlyMemory<byte>.Empty, IsDaProtected: false, request.EncryptNonceCaller,
                encryptSession.NonceTpm, FoldedNonces: ReadOnlyMemory<byte>.Empty, request.EncryptAttributes, request.EncryptHmac));
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
                    TpmCcConstants.TPM_CC_Unseal, HandleNames: sealedObject.Name, ParameterArea: ReadOnlyMemory<byte>.Empty,
                    queue[0], queue.RemoveAt(0), request),
                ResponseIntent = null
            },
            "Unseal:HmacVerifyRequested");
    }

    //Resumes TPM2_Unseal() once every session in its authorization area has verified: runs whichever gate session
    //index 0 still owes (the policy-digest match, or — for an HMAC session, already verified — the userWithAuth
    //check, Part 3, clause 5.6, check 6), then either returns outData in the clear or declares the response-framing
    //effect for the confidentiality-protected form.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> ContinueUnsealOverSessions(TpmSimulatorState state, TpmUnsealOverSessionsRequested request)
    {
        //Both handles are guaranteed to resolve (the entry transition already checked); a re-lookup mirrors
        //ContinueGetRandomOverSession's rationale for not threading resolved records through the verify queue.
        SealedObjectState sealedObject = state.LoadedSealedObjects[request.ItemHandle];

        PolicySessionState? policySession = null;
        if(state.PolicySessions.TryGetValue(request.FirstSession, out policySession))
        {
            //A trial policy session (Part 1, clause 19.3) accumulates a policyDigest for prediction but authorizes
            //nothing; a trial session presented to authorize the unseal is rejected before the object's authPolicy
            //is consulted.
            if(policySession.IsTrial)
            {
                return Reject(state, TpmCcConstants.TPM_CC_Unseal, TpmRcConstants.TPM_RC_POLICY_FAIL);
            }

            //Policy gate (Part 3, clause 12.7; Part 1, clause 19.7): an object with a non-empty authPolicy is
            //authorized only when the authorizing policy session's accumulated policyDigest equals that authPolicy.
            if(!sealedObject.AuthPolicy.IsEmpty
                && !sealedObject.AuthPolicy.Span.SequenceEqual(policySession.PolicyDigest.Span))
            {
                return Reject(state, TpmCcConstants.TPM_CC_Unseal, TpmRcConstants.TPM_RC_POLICY_FAIL);
            }
        }
        else
        {
            //The first session is an HMAC session whose command HMAC has already verified (USER role): userWithAuth
            //CLEAR requires a policy session instead (Part 3, clause 5.6, check 6).
            if(!sealedObject.UserWithAuth)
            {
                return Reject(state, TpmCcConstants.TPM_CC_Unseal, TpmRcConstants.TPM_RC_POLICY_FAIL);
            }
        }

        if(request.EncryptSession == 0 && policySession is not null)
        {
            //Gate passed, no encrypt session, first session is a policy session: return the recovered secret in the
            //clear exactly as the plain form does (the executor does not verify a keyless policy session's response
            //auth, so a no-sessions response is accepted).
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
            HmacSessionState firstHmacSession = state.HmacSessions[request.FirstSession];
            ReadOnlyMemory<byte> strippedUserAuth = StripTrailingZeros(sealedObject.UserAuth.Span).ToArray();
            bool bindOmits = !firstHmacSession.BoundEntityName.IsEmpty
                && firstHmacSession.BoundEntityName.Span.SequenceEqual(sealedObject.Name.Span);

            hmacResponseSessions.Add(new TpmUnsealResponseSession(
                firstHmacSession.Handle, firstHmacSession.SessionAlg, firstHmacSession.SessionKey,
                bindOmits ? ReadOnlyMemory<byte>.Empty : strippedUserAuth, request.FirstNonceCaller,
                request.PolicyAttributes, Encrypts: false, firstHmacSession.Symmetric));
        }

        if(request.EncryptSession != 0)
        {
            //The second session authorizes no entity, so it is admitted by ValidateSessionArea on its audit
            //attribute alone (Part 3, clause 5.5) without ever claiming encrypt — response encryption (Part 1,
            //clause 21.1) is a per-session OPT-IN, keyed on that session's own encrypt bit specifically, never on
            //the mere presence of a second session in the authorization area (an audit-only companion must never
            //have response encryption applied on its behalf, matching TpmCommandExecutor's own
            //FindParameterEncryptionSessions, which resolves the host's encrypt session the identical way).
            HmacSessionState encryptSession = state.HmacSessions[request.EncryptSession];
            bool encrypts = (request.EncryptAttributes & (byte)TpmaSession.ENCRYPT) != 0;
            hmacResponseSessions.Add(new TpmUnsealResponseSession(
                encryptSession.Handle, encryptSession.SessionAlg, encryptSession.SessionKey, AuthValue: ReadOnlyMemory<byte>.Empty,
                request.EncryptNonceCaller, request.EncryptAttributes, encrypts, encryptSession.Symmetric));
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

    //Rolls every real session's nonceTPM to its freshly generated value and frames the TPM2_Unseal() response (the
    //possibly-encrypted outData and the response session area the effect assembled). Each session record is
    //replaced wholesale because its nonceTPM is immutable model state, replaced once per command (Part 1, clause
    //17.6.7); a policy session carries no per-command state to roll.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnUnsealedOverSessions(TpmSimulatorState state, TpmUnsealedOverSessions produced)
    {
        //Every real session is present under normal flow (the request resolved it before declaring the action); if
        //one was flushed meanwhile the produced buffers are still released by SerializeResponse, so frame the
        //response regardless and update the table only for sessions that still exist.
        ImmutableDictionary<uint, HmacSessionState> sessions = state.HmacSessions;
        foreach(TpmUnsealFramedSessionEntry entry in produced.Entries)
        {
            if(sessions.TryGetValue(entry.SessionHandle, out HmacSessionState? session))
            {
                sessions = sessions.SetItem(entry.SessionHandle, session with { NonceTpm = entry.NewNonceTpm });
            }
        }

        return Transition(
            state with
            {
                NextAction = NullAction.Instance,
                HmacSessions = sessions,
                ResponseIntent = new TpmUnsealOverSessionsResponse(
                    TpmRcConstants.TPM_RC_SUCCESS,
                    produced.ParameterArea,
                    produced.ParameterLength,
                    produced.HasPolicyPlaceholder,
                    produced.PolicyNonceLength,
                    produced.PolicyAttributes,
                    produced.Entries)
            },
            "Unseal:ResponseCompleted");
    }

    //TPM2_Certify() has a signing key attest that another loaded object's Name is present in the same TPM, over a
    //caller nonce (Part 3, clause 18.2). Both handles must resolve to loaded transient objects; a missing one is
    //TPM_RC_HANDLE. qualifyingData over the TPM2B_DATA bound (Part 2, clause 10.4.3) is TPM_RC_SIZE; a signer
    //missing the sign attribute (Part 3, clause 18.1) is TPM_RC_KEY; an unsupported scheme hash algorithm is
    //TPM_RC_HASH. The signing scheme is dispatched on the signer's key type — TPM_ALG_ECDSA for an ECC key,
    //TPM_ALG_RSASSA/TPM_ALG_RSAPSS for an RSA key (mirroring OnSign) — and a scheme incompatible with the key's
    //type is TPM_RC_SCHEME. The attestation needs an effect (compute the Qualified Names, marshal, and sign), so
    //the transition resolves both objects, folds their retained fields into the matching action, and leaves no
    //response yet; OnObjectCertified frames the result. No handle is allocated — TPM2_Certify() returns no
    //object handle.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnCertify(TpmSimulatorState state, TpmCertifyRequested request)
    {
        if(!state.TransientObjects.TryGetValue(request.ObjectHandle, out TransientKeyState? subject))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Certify, TpmRcConstants.TPM_RC_HANDLE);
        }

        if(!state.TransientObjects.TryGetValue(request.SignHandle, out TransientKeyState? signer))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Certify, TpmRcConstants.TPM_RC_HANDLE);
        }

        if(request.QualifyingData.Length > Tpm2bData.MaxSize)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Certify, TpmRcConstants.TPM_RC_SIZE);
        }

        if(!CanSign(signer.Attributes))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Certify, TpmRcConstants.TPM_RC_KEY);
        }

        if(!IsSupportedAttestHashAlg(request.SchemeHashAlg))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Certify, TpmRcConstants.TPM_RC_HASH);
        }

        TpmsClockInfo clockSnapshot = new(state.Clock, state.ResetCount, state.RestartCount, state.ClockSafe);
        TpmAction? action = (signer.KeyType, request.SignatureScheme) switch
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
            return Reject(state, TpmCcConstants.TPM_CC_Certify, TpmRcConstants.TPM_RC_SCHEME);
        }

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
                    TpmRcConstants.TPM_RC_SUCCESS, certified.CertifyInfo, certified.CertifyInfoLength, certified.Signature, certified.SignatureScheme, certified.HashAlg)
            },
            "Certify:Completed");

    //TPM2_CertifyCreation() has a signing key attest that objectHandle was created by the TPM with a given
    //creation hash, re-verifying the caller-supplied creation ticket (Part 3, clause 18.3). Only signHandle and
    //objectHandle need resolve to loaded transient objects; a missing one is TPM_RC_HANDLE — this scopes
    //objectHandle to TPM2_CreatePrimary()/TPM2_Create()-minted keys (the TransientObjects table), matching the
    //actual attestation-key use case; a TPM2_Load()-ed sealed object (which retains no Name) is out of scope and
    //likewise answers TPM_RC_HANDLE, since it lives in a different table. qualifyingData over the TPM2B_DATA
    //bound (Part 2, clause 10.4.3) is TPM_RC_SIZE; a signer missing the sign attribute (Part 3, clause 18.1) is
    //TPM_RC_KEY; an unsupported scheme hash algorithm is TPM_RC_HASH. The signing scheme is dispatched on the
    //signer's key type exactly as OnCertify does, and a scheme incompatible with the key's type is TPM_RC_SCHEME.
    //The creation-ticket re-verification needs the asynchronous digest/HMAC seam, so it is folded into the
    //effect (TpmCertifyCreationAction/TpmRsaCertifyCreationAction) rather than checked here; the transition
    //resolves both objects, folds their retained fields into the matching action, and leaves no response yet.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnCertifyCreation(TpmSimulatorState state, TpmCertifyCreationRequested request)
    {
        if(!state.TransientObjects.TryGetValue(request.SignHandle, out TransientKeyState? signer))
        {
            return Reject(state, TpmCcConstants.TPM_CC_CertifyCreation, TpmRcConstants.TPM_RC_HANDLE);
        }

        if(!state.TransientObjects.TryGetValue(request.ObjectHandle, out TransientKeyState? subject))
        {
            return Reject(state, TpmCcConstants.TPM_CC_CertifyCreation, TpmRcConstants.TPM_RC_HANDLE);
        }

        if(request.QualifyingData.Length > Tpm2bData.MaxSize)
        {
            return Reject(state, TpmCcConstants.TPM_CC_CertifyCreation, TpmRcConstants.TPM_RC_SIZE);
        }

        if(!CanSign(signer.Attributes))
        {
            return Reject(state, TpmCcConstants.TPM_CC_CertifyCreation, TpmRcConstants.TPM_RC_KEY);
        }

        if(!IsSupportedAttestHashAlg(request.SchemeHashAlg))
        {
            return Reject(state, TpmCcConstants.TPM_CC_CertifyCreation, TpmRcConstants.TPM_RC_HASH);
        }

        TpmsClockInfo clockSnapshot = new(state.Clock, state.ResetCount, state.RestartCount, state.ClockSafe);
        TpmAction? action = (signer.KeyType, request.SignatureScheme) switch
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
            return Reject(state, TpmCcConstants.TPM_CC_CertifyCreation, TpmRcConstants.TPM_RC_SCHEME);
        }

        return Transition(
            state with
            {
                NextAction = action,
                ResponseIntent = null
            },
            "CertifyCreation:Requested");
    }

    //Frames the TPM2_CertifyCreation() response the effect produced: the signed attestation on a reproduced
    //creation ticket, or the ticket-mismatch rejection (TPM_RC_TICKET) the effect's constant-time comparison
    //found — mirroring OnCredentialActivated's success/rejection split, the only other place a rejection is
    //decided inside the effect rather than the pure transition.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnObjectCreationCertified(TpmSimulatorState state, TpmObjectCreationCertified certified) =>
        certified.CertifyInfo is { } certifyInfo
            ? Transition(
                state with
                {
                    NextAction = NullAction.Instance,
                    ResponseIntent = new TpmCertifyCreationResponse(
                        TpmRcConstants.TPM_RC_SUCCESS, certifyInfo, certified.CertifyInfoLength, certified.Signature!, certified.SignatureScheme, certified.HashAlg)
                },
                "CertifyCreation:Completed")
            : Transition(
                state with
                {
                    NextAction = NullAction.Instance,
                    ResponseIntent = new TpmHeaderOnlyResponse(certified.ResponseCode)
                },
                "CertifyCreation:Rejected");

    //TPM2_MakeCredential() wraps a credential secret to a credential key's public area, bound to an object's Name
    //(Part 3, clause 12.6; the credential protection scheme is Part 1, clause 24). The credential key (the
    //endorsement key) must be a loaded restricted-decrypt Storage Key, ECC or RSA (Part 3, clause 12.6: "Storage
    //Key" is an attribute-shaped predicate, not an algorithm-shaped one), carrying the exported public key
    //material its algorithm needs; a missing handle is TPM_RC_HANDLE and a wrong key type/shape is TPM_RC_TYPE.
    //The seed exchange (ECDH+KDFe for ECC, a fresh random seed OAEP-encrypted for RSA), the shared KDFa
    //derivations, symmetric encryption, and outer HMAC all need the matching signing backend and the registered
    //digest/HMAC seams, so the transition dispatches on the credential key's type — mirroring OnCertify — and
    //folds its retained fields into the matching action, leaving no response yet; OnCredentialMade frames the
    //result. MakeCredential takes no authorization, so no session is consulted.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnMakeCredential(TpmSimulatorState state, TpmMakeCredentialRequested request)
    {
        if(!state.TransientObjects.TryGetValue(request.KeyHandle, out TransientKeyState? key))
        {
            return Reject(state, TpmCcConstants.TPM_CC_MakeCredential, TpmRcConstants.TPM_RC_HANDLE);
        }

        if(!IsStorageParent(key.Attributes))
        {
            return Reject(state, TpmCcConstants.TPM_CC_MakeCredential, TpmRcConstants.TPM_RC_TYPE);
        }

        TpmAction? action = key.KeyType switch
        {
            TpmAlgIdConstants.TPM_ALG_ECC when !key.PublicPoint.IsEmpty =>
                new TpmMakeCredentialAction(request.Credential, request.ObjectName, key.PublicPoint, key.Curve, TpmAlgIdConstants.TPM_ALG_SHA256),
            TpmAlgIdConstants.TPM_ALG_RSA when !key.PublicModulus.IsEmpty =>
                new TpmRsaMakeCredentialAction(request.Credential, request.ObjectName, key.PublicModulus, TpmAlgIdConstants.TPM_ALG_SHA256),
            _ => null
        };

        if(action is null)
        {
            //Either a key type this credential-protection slice does not model, or the right type but carrying
            //no exported public key material (the storage-parent effect that would have populated it never ran).
            return Reject(state, TpmCcConstants.TPM_CC_MakeCredential, TpmRcConstants.TPM_RC_TYPE);
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
                    TpmRcConstants.TPM_RC_SUCCESS, made.CredentialBlob, made.CredentialBlobLength, made.Secret, made.SecretLength)
            },
            "MakeCredential:Completed");

    //TPM2_ActivateCredential() recovers a wrapped credential, proving the activate object (the attestation key) and
    //the credential key (the endorsement key) co-reside in one TPM (Part 3, clause 12.5). Both handles must resolve
    //to loaded objects (a missing one is TPM_RC_HANDLE); the credential key must be a restricted-decrypt Storage
    //Key, ECC or RSA, carrying both its retained private key and the exported public key material its algorithm
    //needs (else TPM_RC_TYPE) — TryResolveActivateCredentialObjects shares this plus the ADMIN-role fail-closed
    //check with OnActivateCredentialOverSession. The USER-role gate here is form-specific: a password session on
    //@keyHandle authorizes USER role only when the key's userWithAuth attribute is SET (Part 3, clause 5.6); a
    //standard endorsement key clears it, so a password session there is TPM_RC_POLICY_FAIL and must instead go
    //through OnActivateCredentialOverSession. The seed recovery and integrity check need the matching signing
    //backend and the digest/HMAC seams, so the transition dispatches on the credential key's type through
    //BuildActivateCredentialAction and leaves no response yet; OnCredentialActivated frames the recovered secret
    //or the integrity-failure rejection. The two handles' supplied authorization values are consumed but not
    //retained (the objects this slice authorizes by password carry empty auth).
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnActivateCredential(TpmSimulatorState state, TpmActivateCredentialRequested request)
    {
        if(!TryResolveActivateCredentialObjects(state, request.ActivateHandle, request.KeyHandle, out TransientKeyState? activateObject, out TransientKeyState? key, out TpmRcConstants rejectionCode))
        {
            return Reject(state, TpmCcConstants.TPM_CC_ActivateCredential, rejectionCode);
        }

        //USER role gate (Part 3, clause 5.6, item 1): "If the entity being authorized is an object and its
        //userWithAuth attribute is CLEAR, then the associated authorization session is a policy session
        //(TPM_RC_POLICY_FAIL)." Objects with userWithAuth SET keep today's behavior.
        if((key.Attributes & TpmaObject.USER_WITH_AUTH) == 0)
        {
            return Reject(state, TpmCcConstants.TPM_CC_ActivateCredential, TpmRcConstants.TPM_RC_POLICY_FAIL);
        }

        return Transition(
            state with
            {
                NextAction = BuildActivateCredentialAction(activateObject, key, request.CredentialBlob, request.Secret),
                ResponseIntent = null
            },
            "ActivateCredential:Requested");
    }

    //TPM2_ActivateCredential() whose @keyHandle session is a policy session (TpmActivateCredentialOverSessionRequested)
    //— the form a standard endorsement key (userWithAuth CLEAR, authPolicy = "PolicyA") requires. Shares handle
    //resolution, the ADMIN-role fail-closed check, and the key type/shape check with OnActivateCredential via
    //TryResolveActivateCredentialObjects; only the USER-role gate differs (a policy-digest comparison here instead
    //of an attribute check). Mirrors OnUnsealOverSessions's policy gate (Part 3, clause 5.6, item 4; Part 1, clause
    //19.7): the policy session must resolve (else TPM_RC_HANDLE), must not be a trial session (Part 1, clause 19.3:
    //a trial session authorizes nothing), and its accumulated policyDigest must reproduce the key's authPolicy when
    //one is set.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnActivateCredentialOverSession(TpmSimulatorState state, TpmActivateCredentialOverSessionRequested request)
    {
        if(!TryResolveActivateCredentialObjects(state, request.ActivateHandle, request.KeyHandle, out TransientKeyState? activateObject, out TransientKeyState? key, out TpmRcConstants rejectionCode))
        {
            return Reject(state, TpmCcConstants.TPM_CC_ActivateCredential, rejectionCode);
        }

        if(!state.PolicySessions.TryGetValue(request.KeyPolicySession, out PolicySessionState? policySession))
        {
            return Reject(state, TpmCcConstants.TPM_CC_ActivateCredential, TpmRcConstants.TPM_RC_HANDLE);
        }

        if(policySession.IsTrial)
        {
            return Reject(state, TpmCcConstants.TPM_CC_ActivateCredential, TpmRcConstants.TPM_RC_POLICY_FAIL);
        }

        //Policy gate: a satisfying policy session authorizes USER role regardless of userWithAuth (Part 1, clause
        //19.2: "A policy session that satisfies the authPolicy of the entity may be used regardless of the setting
        //of userWithAuth."). An empty authPolicy leaves the key outside the policy path entirely, mirroring
        //OnUnsealOverSessions's identical opt-in guard.
        if(!key.AuthPolicy.IsEmpty
            && !key.AuthPolicy.Span.SequenceEqual(policySession.PolicyDigest.Span))
        {
            return Reject(state, TpmCcConstants.TPM_CC_ActivateCredential, TpmRcConstants.TPM_RC_POLICY_FAIL);
        }

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

    //Shared by OnActivateCredential and OnActivateCredentialOverSession: resolves both handles (TPM_RC_HANDLE if
    //either is unloaded), fails closed on an ADMIN-role policy requirement this slice does not model on
    //@activateHandle (Part 3, clause 5.6, item 1: adminWithPolicy SET requires a policy session there — no template
    //this simulator builds sets the bit today, so this is pure fail-closed guarding for when one does), and checks
    //the credential key's type/shape (Part 1, clause 24: a restricted-decrypt Storage Key, ECC or RSA, carrying
    //both its retained private key and the exported public key material its algorithm needs).
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

        if(!state.TransientObjects.TryGetValue(activateHandle, out activateObject))
        {
            rejectionCode = TpmRcConstants.TPM_RC_HANDLE;

            return false;
        }

        if(!state.TransientObjects.TryGetValue(keyHandle, out key))
        {
            rejectionCode = TpmRcConstants.TPM_RC_HANDLE;

            return false;
        }

        if((activateObject.Attributes & TpmaObject.ADMIN_WITH_POLICY) != 0)
        {
            rejectionCode = TpmRcConstants.TPM_RC_AUTH_TYPE;

            return false;
        }

        bool hasCredentialKeyMaterial = key.KeyType switch
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
        key.KeyType switch
        {
            TpmAlgIdConstants.TPM_ALG_RSA => new TpmRsaActivateCredentialAction(
                credentialBlob, secret, activateObject.Name, key.PrivateKey, TpmAlgIdConstants.TPM_ALG_SHA256),
            _ => new TpmActivateCredentialAction(
                credentialBlob, secret, activateObject.Name, key.PrivateKey, key.PublicPoint, key.Curve, TpmAlgIdConstants.TPM_ALG_SHA256)
        };

    //Frames the TPM2_ActivateCredential() response the effect produced: the recovered secret on success, or the
    //integrity-failure rejection (TPM_RC_INTEGRITY) when the credential's outer HMAC did not verify against the
    //activate object's Name (Part 3, clause 12.5) — the "wrong object" case the negative test turns on.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnCredentialActivated(TpmSimulatorState state, TpmCredentialActivated activated) =>
        activated.CertInfo is { } certInfo
            ? Transition(
                state with
                {
                    NextAction = NullAction.Instance,
                    ResponseIntent = new TpmActivateCredentialResponse(activated.ResponseCode, certInfo, activated.CertInfoLength)
                },
                "ActivateCredential:Completed")
            : Transition(
                state with
                {
                    NextAction = NullAction.Instance,
                    ResponseIntent = new TpmHeaderOnlyResponse(activated.ResponseCode)
                },
                "ActivateCredential:Rejected");

    //TPM2_PCR_Read() returns the current values of the selected PCRs (Part 3, clause 22.4). A pure, state-derived
    //response — no action layer and no authorization: the values are read straight from the durable SHA-256 bank
    //and framed alongside the echoed selection and the PCR update counter. The counter is zero because no register
    //has been extended (this slice models no TPM2_PCR_Extend()); a later extend slice advances it.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnPcrRead(TpmSimulatorState state, TpmPcrReadRequested request)
    {
        ImmutableArray<ReadOnlyMemory<byte>> values = GatherSelectedPcrValues(state.Sha256PcrBank, request.SelectionBytes);

        return Transition(
            state with { ResponseIntent = new TpmPcrReadResponse(TpmRcConstants.TPM_RC_SUCCESS, PcrUpdateCounter: 0u, request.SelectionBytes, values) },
            "PcrRead");
    }

    //TPM2_Quote() has a signing key attest the composite digest of a selected set of PCRs, over a caller nonce
    //(Part 3, clause 18.4). The signHandle must resolve to a loaded transient object; a missing one is
    //TPM_RC_HANDLE. qualifyingData over the TPM2B_DATA bound (Part 2, clause 10.4.3) is TPM_RC_SIZE; a signer
    //missing the sign attribute (Part 3, clause 18.1) is TPM_RC_KEY; an unsupported scheme hash algorithm is
    //TPM_RC_HASH. The signing scheme is dispatched on the signer's key type — TPM_ALG_ECDSA for an ECC key,
    //TPM_ALG_RSASSA/TPM_ALG_RSAPSS for an RSA key (mirroring OnCertify) — and a scheme incompatible with the
    //key's type is TPM_RC_SCHEME. The attestation needs an effect (compute the composite, marshal, and sign), so
    //the transition resolves the signer, gathers the selected PCR values from the durable bank, folds them into
    //the matching action, and leaves no response yet; OnObjectQuoted frames the result. No handle is allocated —
    //TPM2_Quote() returns no object handle.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnQuote(TpmSimulatorState state, TpmQuoteRequested request)
    {
        if(!state.TransientObjects.TryGetValue(request.SignHandle, out TransientKeyState? signer))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Quote, TpmRcConstants.TPM_RC_HANDLE);
        }

        if(request.QualifyingData.Length > Tpm2bData.MaxSize)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Quote, TpmRcConstants.TPM_RC_SIZE);
        }

        if(!CanSign(signer.Attributes))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Quote, TpmRcConstants.TPM_RC_KEY);
        }

        if(!IsSupportedAttestHashAlg(request.SchemeHashAlg))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Quote, TpmRcConstants.TPM_RC_HASH);
        }

        ImmutableArray<ReadOnlyMemory<byte>> pcrValues = GatherSelectedPcrValues(state.Sha256PcrBank, request.PcrSelection);
        TpmsClockInfo clockSnapshot = new(state.Clock, state.ResetCount, state.RestartCount, state.ClockSafe);

        TpmAction? action = (signer.KeyType, request.SignatureScheme) switch
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
            return Reject(state, TpmCcConstants.TPM_CC_Quote, TpmRcConstants.TPM_RC_SCHEME);
        }

        return Transition(
            state with
            {
                NextAction = action,
                ResponseIntent = null
            },
            "Quote:Requested");
    }

    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnObjectQuoted(TpmSimulatorState state, TpmObjectQuoted quoted) =>
        Transition(
            state with
            {
                NextAction = NullAction.Instance,
                ResponseIntent = new TpmQuoteResponse(
                    TpmRcConstants.TPM_RC_SUCCESS, quoted.Quoted, quoted.QuotedLength, quoted.Signature, quoted.SignatureScheme, quoted.HashAlg)
            },
            "Quote:Completed");

    //TPM2_GetTime() has a signing key attest the TPM's current time, over a caller nonce (Part 3, clause 18.7).
    //privacyAdminHandle is fixed to TPM_RH_ENDORSEMENT (its TPMI_RH_ENDORSEMENT interface type's only legal
    //value); any other value is rejected the same way OnNvDefineSpace rejects an authHandle other than
    //TPM_RH_OWNER (TPM_RC_HANDLE) — the map carried no explicit RC for this case, so this mirrors that identical
    //fixed-handle precedent. signHandle must resolve to a loaded transient object; a missing one is
    //TPM_RC_HANDLE. qualifyingData over the TPM2B_DATA bound is TPM_RC_SIZE; a signer missing the sign attribute
    //is TPM_RC_KEY; an unsupported scheme hash algorithm is TPM_RC_HASH. The signing scheme is dispatched on the
    //signer's key type exactly as OnCertify/OnQuote do, and a scheme incompatible with the key's type is
    //TPM_RC_SCHEME. The attestation needs an effect (marshal the real time/clockInfo image and sign), so the
    //transition resolves the signer, folds its retained fields plus the already-advanced state.Time and clock
    //snapshot into the matching action, and leaves no response yet.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnGetTime(TpmSimulatorState state, TpmGetTimeRequested request)
    {
        if(request.PrivacyAdminHandle != (uint)TpmRh.TPM_RH_ENDORSEMENT)
        {
            return Reject(state, TpmCcConstants.TPM_CC_GetTime, TpmRcConstants.TPM_RC_HANDLE);
        }

        if(!state.TransientObjects.TryGetValue(request.SignHandle, out TransientKeyState? signer))
        {
            return Reject(state, TpmCcConstants.TPM_CC_GetTime, TpmRcConstants.TPM_RC_HANDLE);
        }

        if(request.QualifyingData.Length > Tpm2bData.MaxSize)
        {
            return Reject(state, TpmCcConstants.TPM_CC_GetTime, TpmRcConstants.TPM_RC_SIZE);
        }

        if(!CanSign(signer.Attributes))
        {
            return Reject(state, TpmCcConstants.TPM_CC_GetTime, TpmRcConstants.TPM_RC_KEY);
        }

        if(!IsSupportedAttestHashAlg(request.SchemeHashAlg))
        {
            return Reject(state, TpmCcConstants.TPM_CC_GetTime, TpmRcConstants.TPM_RC_HASH);
        }

        TpmsClockInfo clockSnapshot = new(state.Clock, state.ResetCount, state.RestartCount, state.ClockSafe);
        TpmAction? action = (signer.KeyType, request.SignatureScheme) switch
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
            return Reject(state, TpmCcConstants.TPM_CC_GetTime, TpmRcConstants.TPM_RC_SCHEME);
        }

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
                    TpmRcConstants.TPM_RC_SUCCESS, attested.TimeInfo, attested.TimeInfoLength, attested.Signature, attested.SignatureScheme, attested.HashAlg)
            },
            "GetTime:Completed");

    //TPM2_ReadClock() returns the current TPMS_TIME_INFO straight from state: no handles, no authorization, and
    //no signature (Part 3, clause 29.1) — structurally identical to OnPcrRead, the other command answerable
    //purely from already-resident state.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnReadClock(TpmSimulatorState state) =>
        Transition(
            state with
            {
                ResponseIntent = new TpmReadClockResponse(
                    TpmRcConstants.TPM_RC_SUCCESS,
                    new TpmsTimeInfo(state.Time, new TpmsClockInfo(state.Clock, state.ResetCount, state.RestartCount, state.ClockSafe)))
            },
            "ReadClock");

    //TPM2_ClockSet() advances Clock forward, authorized by the owner hierarchy (Part 3, clause 29.2); the
    //Platform-hierarchy arm (TPM_RH_PLATFORM plus physical presence) is not modelled this slice, so a non-owner
    //handle is TPM_RC_HANDLE, mirroring OnNvDefineSpace's fixed-provisioning-handle precedent. Owner
    //authorization is not dictionary-attack protected (clause 17.8.1), so a wrong owner authValue is a plain
    //bad-authorization, compared constant-time so a mismatch leaks no timing about the secret. newTime older
    //than the current (already per-command-advanced) Clock, or past the clause 36.3 ceiling of
    //FF FF 00 00 00 00 00 00(16), is TPM_RC_VALUE with Clock left unchanged. A successful set marks ClockSafe
    //YES: an explicitly caller-set Clock is, by construction, a value never previously reported.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnClockSet(TpmSimulatorState state, TpmClockSetRequested request)
    {
        if(request.AuthHandle != (uint)TpmRh.TPM_RH_OWNER)
        {
            return Reject(state, TpmCcConstants.TPM_CC_ClockSet, TpmRcConstants.TPM_RC_HANDLE);
        }

        if(!CryptographicOperations.FixedTimeEquals(request.OwnerAuthSupplied.Span, state.OwnerAuth.Span))
        {
            return Reject(state, TpmCcConstants.TPM_CC_ClockSet, TpmRcConstants.TPM_RC_BAD_AUTH);
        }

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

    //TPM2_DictionaryAttackLockReset() resets FailedTries to zero, authorized by the lockout hierarchy (Part 3,
    //clause 25.2). Deliberately does NOT check state.IsInLockout (general Lockout mode): this command is the
    //escape hatch out of it, so it is permitted regardless of FailedTries/MaxTries — the only gate is
    //LockoutAuthEnabled, the wholly independent state a wrong lockoutAuth use disables (clause 17.8.5). A wrong
    //lockoutAuth value here disables LockoutAuthEnabled and anchors its own self-heal timer exactly like the NV
    //auth-failure sites do for FailedTries, but returns TPM_RC_AUTH_FAIL rather than TPM_RC_BAD_AUTH: lockoutAuth
    //is itself dictionary-attack protected (clause 17.8's own carve-out — every other permanent handle is
    //DA-exempt, lockoutAuth is the one that is not). A successful reset never touches LockoutAuthEnabled: it is
    //already true on this path (the gate above already refused a disabled one), so there is nothing to re-arm.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnDictionaryAttackLockReset(TpmSimulatorState state, TpmDictionaryAttackLockResetRequested request)
    {
        if(request.LockHandle != (uint)TpmRh.TPM_RH_LOCKOUT)
        {
            return Reject(state, TpmCcConstants.TPM_CC_DictionaryAttackLockReset, TpmRcConstants.TPM_RC_HANDLE);
        }

        if(!state.LockoutAuthEnabled)
        {
            return Reject(state, TpmCcConstants.TPM_CC_DictionaryAttackLockReset, TpmRcConstants.TPM_RC_LOCKOUT);
        }

        if(!CryptographicOperations.FixedTimeEquals(request.LockoutAuthSupplied.Span, state.LockoutAuth.Span))
        {
            TpmSimulatorState disabled = state with { LockoutAuthEnabled = false, LastLockoutAuthFailureTime = state.Time };

            return Reject(disabled, TpmCcConstants.TPM_CC_DictionaryAttackLockReset, TpmRcConstants.TPM_RC_AUTH_FAIL);
        }

        return Transition(
            state with
            {
                FailedTries = 0u,
                ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
            },
            "DictionaryAttackLockReset");
    }

    //TPM2_DictionaryAttackParameters() sets MaxTries/RecoveryTime/LockoutRecovery, authorized by the lockout
    //hierarchy exactly like TPM2_DictionaryAttackLockReset() above — same handle check, same LockoutAuthEnabled
    //gate ahead of state.IsInLockout, same lockoutAuth compare and disable-on-mismatch (Part 3, clause 25.3).
    //Deliberately does NOT reset FailedTries (Part 1, clause 17.8.6's errata correction to an earlier design):
    //lowering newMaxTries to at or below the current FailedTries takes the TPM into Lockout mode immediately —
    //IsInLockout's own "FailedTries >= MaxTries" formula already reflects it on the very next read, with no
    //distinct error code for that transition.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnDictionaryAttackParameters(TpmSimulatorState state, TpmDictionaryAttackParametersRequested request)
    {
        if(request.LockHandle != (uint)TpmRh.TPM_RH_LOCKOUT)
        {
            return Reject(state, TpmCcConstants.TPM_CC_DictionaryAttackParameters, TpmRcConstants.TPM_RC_HANDLE);
        }

        if(!state.LockoutAuthEnabled)
        {
            return Reject(state, TpmCcConstants.TPM_CC_DictionaryAttackParameters, TpmRcConstants.TPM_RC_LOCKOUT);
        }

        if(!CryptographicOperations.FixedTimeEquals(request.LockoutAuthSupplied.Span, state.LockoutAuth.Span))
        {
            TpmSimulatorState disabled = state with { LockoutAuthEnabled = false, LastLockoutAuthFailureTime = state.Time };

            return Reject(disabled, TpmCcConstants.TPM_CC_DictionaryAttackParameters, TpmRcConstants.TPM_RC_AUTH_FAIL);
        }

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

    //TPM2_NV_Certify() has a signing key attest the contents of an NV Index at a caller-chosen offset/size, over a
    //caller nonce (Part 3, clause 31.16). Only the TPMS_NV_CERTIFY_INFO form is modelled (decision: a caller
    //request for the zero-size/zero-offset TPMS_NV_DIGEST_CERTIFY_INFO form is unmodelled and rejected fail-closed
    //with TPM_RC_COMMAND_CODE — the nearest documented "not implemented" code, mirroring how an unmodelled backend
    //capability answers elsewhere in this simulator). signHandle must resolve to a loaded transient object and
    //nvIndex to a defined Index; either missing is TPM_RC_HANDLE. qualifyingData/CanSign/hash-algorithm checks
    //mirror OnCertify/OnQuote/OnGetTime exactly. The NV-specific checks then mirror OnNvRead: only Index
    //authorization (authHandle == nvIndex) is modelled (else TPM_RC_AUTH_TYPE), the supplied authorization is
    //compared constant-time against the Index authValue (a mismatch is TPM_RC_AUTH_FAIL for a DA-protected Index,
    //TPM_RC_BAD_AUTH otherwise), an unwritten Index is TPM_RC_NV_UNINITIALIZED, and the requested window must lie
    //within the Index's retained written extent (TPM_RC_NV_RANGE) — the model retains only the octets actually
    //written (as OnNvRead's own bound already does), so this is the bound checked against rather than the
    //Index's full declared dataSize. The signing scheme is dispatched on the signer's key type, and a scheme
    //incompatible with the key's type is TPM_RC_SCHEME. The attestation needs an effect (compute the Index's Name,
    //marshal, and sign), so the transition resolves both, slices the requested window, folds everything into the
    //matching action, and leaves no response yet.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnNvCertify(TpmSimulatorState state, TpmNvCertifyRequested request)
    {
        if(!state.TransientObjects.TryGetValue(request.SignHandle, out TransientKeyState? signer))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_HANDLE);
        }

        if(!state.NvIndexes.TryGetValue(request.NvIndex, out NvIndexState? index))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_HANDLE);
        }

        if(request.QualifyingData.Length > Tpm2bData.MaxSize)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_SIZE);
        }

        if(!CanSign(signer.Attributes))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_KEY);
        }

        if(!IsSupportedAttestHashAlg(request.SchemeHashAlg))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_HASH);
        }

        //The TPMS_NV_DIGEST_CERTIFY_INFO form (size and offset both zero, Part 3, clause 31.16) is not modelled.
        if(request.Size == 0 && request.Offset == 0)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_COMMAND_CODE);
        }

        //Only Index authorization (authHandle == nvIndex) is modelled this slice, mirroring OnNvRead/OnNvWrite.
        if(request.AuthHandle != request.NvIndex)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_AUTH_TYPE);
        }

        //Already-locked-out DA-protected Index: refuse before even comparing (clause 17.8.3), no further increment.
        if(IsNvIndexLockedOut(state, index))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_LOCKOUT);
        }

        //A PIN Index's own authValue is not usable while unwritten or once pinCount has reached pinLimit
        //(clause 37.2.6.6) — refused before even comparing, mirroring OnNvRead's own gate.
        if(IsPinAuthUnavailable(index))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE);
        }

        //A PIN Index's own pinCount is updated on either outcome (clause 37.2.6.6) ahead of the DA-counter
        //check below, mirroring OnNvRead's own ordering.
        bool authMatched = CryptographicOperations.FixedTimeEquals(request.AuthSupplied.Span, index.AuthValue.Span);
        if(index.IsPinIndex)
        {
            index = ApplyPinAuthOutcome(index, authMatched);
            state = state with { NvIndexes = state.NvIndexes.SetItem(index.NvIndex, index) };
        }

        if(!authMatched)
        {
            return RejectNvAuthFailure(state, index, TpmCcConstants.TPM_CC_NV_Certify);
        }

        if(!index.IsWritten)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_NV_UNINITIALIZED);
        }

        //The model retains only the octets actually written (its NvIndexState.Data grows with each write), so —
        //as OnNvRead already does — the bound checked here is the retained written extent, not the Index's full
        //declared dataSize; a request beyond it is equally TPM_RC_NV_RANGE.
        if((long)request.Offset + request.Size > index.Data.Length)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_NV_RANGE);
        }

        ReadOnlyMemory<byte> window = index.Data.Slice(request.Offset, request.Size);
        TpmsClockInfo clockSnapshot = new(state.Clock, state.ResetCount, state.RestartCount, state.ClockSafe);

        TpmAction? action = (signer.KeyType, request.SignatureScheme) switch
        {
            (TpmAlgIdConstants.TPM_ALG_RSA, TpmAlgIdConstants.TPM_ALG_RSASSA or TpmAlgIdConstants.TPM_ALG_RSAPSS) =>
                new TpmRsaNvCertifyAction(
                    signer.Name, signer.Hierarchy, request.QualifyingData, signer.PrivateKey, request.SignatureScheme, request.SchemeHashAlg,
                    index.NvIndex, index.Attributes, index.DataSize, window, request.Offset, clockSnapshot),
            (TpmAlgIdConstants.TPM_ALG_ECC, TpmAlgIdConstants.TPM_ALG_ECDSA) =>
                new TpmNvCertifyAction(
                    signer.Name, signer.Hierarchy, request.QualifyingData, signer.PrivateKey, signer.Curve, request.SignatureScheme, request.SchemeHashAlg,
                    index.NvIndex, index.Attributes, index.DataSize, window, request.Offset, clockSnapshot),
            _ => null
        };

        if(action is null)
        {
            //A scheme incompatible with the signer's key type — e.g. an ECDSA scheme against an RSA key, or vice
            //versa — fails closed rather than silently coercing to the key's native scheme (mirrors OnCertify).
            return Reject(state, TpmCcConstants.TPM_CC_NV_Certify, TpmRcConstants.TPM_RC_SCHEME);
        }

        return Transition(
            state with
            {
                NextAction = action,
                ResponseIntent = null
            },
            "NvCertify:Requested");
    }

    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnNvIndexCertified(TpmSimulatorState state, TpmNvIndexCertified certified) =>
        Transition(
            state with
            {
                NextAction = NullAction.Instance,
                ResponseIntent = new TpmNvCertifyResponse(
                    TpmRcConstants.TPM_RC_SUCCESS, certified.CertifyInfo, certified.CertifyInfoLength, certified.Signature, certified.SignatureScheme, certified.HashAlg)
            },
            "NvCertify:Completed");

    //TPM2_VerifySignature() checks that a caller-supplied signature is valid over a caller-supplied digest for the
    //key referenced by keyHandle (Part 3, clause 20.1). Unlike every attest-producing command, this is a
    //public-key operation: keyHandle needs no authorization, and — deliberately, unlike OnCertify/OnCertifyCreation
    //and friends — the signer's sign attribute is never consulted, because verifying a signature does not use the
    //private part of the key at all. keyHandle must resolve in TransientObjects (TPM_RC_HANDLE); the scheme hash
    //algorithm is restricted to SHA-256/384/512 (TPM_RC_HASH), mirroring every other attest command; the signature
    //algorithm must be compatible with the resolved key's type (TPM_RC_SCHEME on mismatch, mirroring OnCertify's
    //dispatch). The actual verification needs the asynchronous verify-delegate seam, so it is folded into the
    //effect (TpmVerifySignatureAction/TpmRsaVerifySignatureAction) rather than checked here; the transition resolves
    //the key, folds its retained fields into the matching action, and leaves no response yet.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnVerifySignature(TpmSimulatorState state, TpmVerifySignatureRequested request)
    {
        if(!state.TransientObjects.TryGetValue(request.KeyHandle, out TransientKeyState? signer))
        {
            return Reject(state, TpmCcConstants.TPM_CC_VerifySignature, TpmRcConstants.TPM_RC_HANDLE);
        }

        if(!IsSupportedAttestHashAlg(request.SchemeHashAlg))
        {
            return Reject(state, TpmCcConstants.TPM_CC_VerifySignature, TpmRcConstants.TPM_RC_HASH);
        }

        TpmAction? action = (signer.KeyType, request.SignatureScheme) switch
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
            return Reject(state, TpmCcConstants.TPM_CC_VerifySignature, TpmRcConstants.TPM_RC_SCHEME);
        }

        return Transition(
            state with
            {
                NextAction = action,
                ResponseIntent = null
            },
            "VerifySignature:Requested");
    }

    //Frames the TPM2_VerifySignature() response the effect produced: the TPMT_TK_VERIFIED validation ticket, or
    //the signature-mismatch rejection (TPM_RC_SIGNATURE) the effect's verify delegate found — mirroring
    //OnObjectCreationCertified's success/rejection split, the only other place a rejection is decided inside the
    //effect rather than the pure transition.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnSignatureVerified(TpmSimulatorState state, TpmSignatureVerified verified) =>
        verified.TicketDigest is { } ticketDigest
            ? Transition(
                state with
                {
                    NextAction = NullAction.Instance,
                    ResponseIntent = new TpmVerifySignatureResponse(TpmRcConstants.TPM_RC_SUCCESS, verified.Hierarchy, ticketDigest, verified.TicketDigestLength)
                },
                "VerifySignature:Completed")
            : Transition(
                state with
                {
                    NextAction = NullAction.Instance,
                    ResponseIntent = new TpmHeaderOnlyResponse(verified.ResponseCode)
                },
                "VerifySignature:Rejected");

    //Decodes a TPML_PCR_SELECTION and gathers the selected SHA-256 bank register values in ascending PCR-index
    //order — the order the PCR composite hashes them in (TPM 2.0 Library Part 4, PCRComputeCurrentDigest) and the
    //order TPM2_PCR_Read() returns them. A selection naming a bank other than the modelled SHA-256 bank
    //contributes no values. The selection bytes were validated for structure when the command was parsed, so the
    //reader walks them without bounds surprises.
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

            for(int byteIndex = 0; byteIndex < sizeofSelect; byteIndex++)
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

        return builder.ToImmutable();
    }

    //TPM2_StartAuthSession() starts a policy or trial session (Part 3, clause 11.1). Allocates a session handle in
    //the TPM_HT_POLICY_SESSION range and captures the session-relative Time base, but the session's retained
    //nonceTPM needs the RNG — an effect, not something this pure transition can reach — so it declares a
    //TpmStartPolicySessionAction and leaves no response yet; OnPolicySessionStarted records the session (all-zero
    //initial policyDigest, unlatched cpHash) and frames the response once the nonce comes back. TPM2_PolicySigned()'s
    //aHash binds to this exact nonceTPM (Part 3, Section 23.3), so it can no longer be a fixed placeholder. The
    //tests start unbound, unsalted sessions (tpmKey and bind both TPM_RH_NULL, TPM_ALG_NULL symmetric), so no
    //salt/bind material is modelled.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnStartAuthSession(TpmSimulatorState state, TpmStartAuthSessionRequested request)
    {
        //Only the digest sizes the policy formula supports are modelled; an unsupported authHash is TPM_RC_HASH.
        if(!IsSupportedPolicyHash(request.AuthHash))
        {
            return Reject(state, TpmCcConstants.TPM_CC_StartAuthSession, TpmRcConstants.TPM_RC_HASH);
        }

        uint handle = state.NextSessionHandle;
        bool isTrial = request.SessionType == TpmSeConstants.TPM_SE_TRIAL;

        return Transition(
            state with
            {
                NextSessionHandle = state.NextSessionHandle + 1,
                NextAction = new TpmStartPolicySessionAction(handle, request.AuthHash, isTrial, state.Time),
                ResponseIntent = null
            },
            "StartAuthSession:PolicyRequested");
    }

    //Records a started policy or trial session and frames the TPM2_StartAuthSession() response with the real,
    //retained nonceTPM (TPM 2.0 Library Part 3, clause 11.1): the value TPM2_PolicySigned()'s aHash later binds to
    //(Part 3, Section 23.3), so it must reach the host verbatim. The session starts with an all-zero policyDigest
    //of the hash width, an unlatched (empty) cpHash (Part 3, Section 23.2.4), and the captured session-start Time
    //(Part 1, clause 36.2) for a later session-relative expiration deadline.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnPolicySessionStarted(TpmSimulatorState state, TpmPolicySessionStarted started)
    {
        int size = TpmPolicyDigest.Size(started.AuthHash);
        var session = new PolicySessionState(
            started.SessionHandle, started.AuthHash, started.IsTrial, new byte[size], started.NonceTpm, ReadOnlyMemory<byte>.Empty, started.StartTime);

        return Transition(
            state with
            {
                NextAction = NullAction.Instance,
                PolicySessions = state.PolicySessions.SetItem(started.SessionHandle, session),
                ResponseIntent = new TpmStartAuthSessionResponse(TpmRcConstants.TPM_RC_SUCCESS, started.SessionHandle, size, started.NonceTpm)
            },
            "StartAuthSession:PolicyCompleted");
    }

    //TPM2_PolicyCommandCode() restricts a policy session to a single command (Part 3, clause 23.4). The policy
    //session is a command handle with no authorization; an unknown handle is TPM_RC_HANDLE.
    //
    //DESIGN: TpmPolicyDigest is the single source of truth for the enhanced-authorization policyDigest formula
    //(the exact H(...) construction of Part 1, clause 19.7; validated when it was built and independently
    //unit-tested). The simulator advances each session's accumulated digest by calling the SAME TpmPolicyDigest
    //methods the host predictor uses, so the on-device digest and the host prediction cannot diverge by
    //construction. The in-house acceptance test therefore covers the wire round-trip, the production command path,
    //and assertion composition — not the raw formula, whose independent-oracle role lives in TpmPolicyDigest's
    //unit tests. Every policy assertion below shares this rationale.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnPolicyCommandCode(TpmSimulatorState state, TpmPolicyCommandCodeRequested request)
    {
        if(!state.PolicySessions.TryGetValue(request.PolicySession, out PolicySessionState? session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicyCommandCode, TpmRcConstants.TPM_RC_HANDLE);
        }

        byte[] updated = new byte[TpmPolicyDigest.Size(session.PolicyHash)];
        _ = TpmPolicyDigest.ExtendForCommandCode(session.PolicyDigest.Span, request.Code, session.PolicyHash, updated);

        return StorePolicyDigest(state, session, updated, new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS), "PolicyCommandCode");
    }

    //TPM2_PolicyAuthValue() binds a policy to the authorized object's authValue (Part 3, clause 23.18). See the
    //single-source-of-truth note on OnPolicyCommandCode.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnPolicyAuthValue(TpmSimulatorState state, TpmPolicyAuthValueRequested request)
    {
        if(!state.PolicySessions.TryGetValue(request.PolicySession, out PolicySessionState? session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicyAuthValue, TpmRcConstants.TPM_RC_HANDLE);
        }

        byte[] updated = new byte[TpmPolicyDigest.Size(session.PolicyHash)];
        _ = TpmPolicyDigest.ExtendForAuthValue(session.PolicyDigest.Span, session.PolicyHash, updated);

        return StorePolicyDigest(state, session, updated, new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS), "PolicyAuthValue");
    }

    //TPM2_PolicyGetDigest() returns the session's current policyDigest (Part 3, clause 23.6). A pure read; an
    //unknown handle is TPM_RC_HANDLE.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnPolicyGetDigest(TpmSimulatorState state, TpmPolicyGetDigestRequested request)
    {
        if(!state.PolicySessions.TryGetValue(request.PolicySession, out PolicySessionState? session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicyGetDigest, TpmRcConstants.TPM_RC_HANDLE);
        }

        return Transition(
            state with { ResponseIntent = new TpmPolicyGetDigestResponse(TpmRcConstants.TPM_RC_SUCCESS, session.PolicyDigest) },
            "PolicyGetDigest");
    }

    //TPM2_PolicyPCR() binds a policy to a set of PCRs (Part 3, clause 23.7). The trial and real forms differ in
    //where the bound pcrDigest comes from. On a TRIAL session the caller's pcrDigest is folded in verbatim (the
    //session authorizes nothing, so the TPM does not consult live PCR state). On a REAL session the TPM computes the
    //digest of the CURRENTLY selected PCR values and binds the policy to THAT value — so a session started on a
    //different PCR state produces a different policyDigest (Part 3, clause 23.7; Part 4, PolicyPCR /
    //PCRComputeCurrentDigest). A real-session caller may also supply the expected digest; when non-empty it must
    //match the live value or the assertion is rejected with TPM_RC_VALUE. The marshaled TPML_PCR_SELECTION was
    //captured verbatim from the wire, so it folds into the policyDigest exactly as the host prediction does. See the
    //single-source-of-truth note on OnPolicyCommandCode.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnPolicyPcr(TpmSimulatorState state, TpmPolicyPcrRequested request)
    {
        if(!state.PolicySessions.TryGetValue(request.PolicySession, out PolicySessionState? session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicyPCR, TpmRcConstants.TPM_RC_HANDLE);
        }

        ReadOnlySpan<byte> pcrDigest = request.PcrDigest.Span;
        byte[]? liveDigest = null;
        if(!session.IsTrial)
        {
            liveDigest = ComputeLivePcrDigest(state.Sha256PcrBank, request.PcrSelectionBytes);

            if(!pcrDigest.IsEmpty && !pcrDigest.SequenceEqual(liveDigest))
            {
                return Reject(state, TpmCcConstants.TPM_CC_PolicyPCR, TpmRcConstants.TPM_RC_VALUE);
            }

            pcrDigest = liveDigest;
        }

        byte[] updated = new byte[TpmPolicyDigest.Size(session.PolicyHash)];
        _ = TpmPolicyDigest.ExtendForPcr(session.PolicyDigest.Span, request.PcrSelectionBytes.Span, pcrDigest, session.PolicyHash, updated);

        return StorePolicyDigest(state, session, updated, new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS), "PolicyPCR");
    }

    //Computes the live PCR composite digest a real (non-trial) TPM2_PolicyPCR binds to:
    //pcrDigest = H(concatenation of the selected PCR values in ascending PCR-index order) (TPM 2.0 Library Part 4,
    //PCRComputeCurrentDigest). The composite is assembled from the durable SHA-256 bank in the same ascending order
    //TPM2_Quote() gathers, then hashed through the registered digest seam (never a direct framework hash), exactly
    //as ComputeNvName computes the Index Name. The simulator models a SHA-256 PCR bank and takes the composite with
    //SHA-256 (the bank's hash, which for the SHA-256 policy sessions this path serves is also the session hash the
    //policyDigest folds it in with), so the seal-time and unseal-time digests agree by construction over the reset
    //(all-zero) bank. Synchronous, with its scratch buffer pooled and released before returning.
    private static byte[] ComputeLivePcrDigest(PcrBankState bank, ReadOnlyMemory<byte> selectionBytes)
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        const int digestSize = 32;                  //SHA-256 composite width — the bank's (and these sessions') hash.
        ImmutableArray<ReadOnlyMemory<byte>> values = GatherSelectedPcrValues(bank, selectionBytes);

        int total = 0;
        for(int i = 0; i < values.Length; i++)
        {
            total += values[i].Length;
        }

        using IMemoryOwner<byte> composite = pool.Rent(Math.Max(total, 1));
        Span<byte> destination = composite.Memory.Span;
        int offset = 0;
        for(int i = 0; i < values.Length; i++)
        {
            values[i].Span.CopyTo(destination[offset..]);
            offset += values[i].Length;
        }

        using DigestValue digest = CryptographicKeyEvents.ComputeDigest(
            composite.Memory.Span[..total], digestSize, CryptoTags.Sha256Digest, pool);

        return digest.AsReadOnlySpan().ToArray();
    }

    //TPM2_PolicyOR() authorizes the session when its current digest matches one of the branches, then collapses it
    //to H(0…0 || TPM_CC_PolicyOR || branches) (Part 3, clause 23.6). On a real (non-trial) session a current digest
    //matching no branch is TPM_RC_VALUE; a trial session skips the match. See the note on OnPolicyCommandCode.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnPolicyOr(TpmSimulatorState state, TpmPolicyOrRequested request)
    {
        if(!state.PolicySessions.TryGetValue(request.PolicySession, out PolicySessionState? session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicyOR, TpmRcConstants.TPM_RC_HANDLE);
        }

        if(!session.IsTrial && !MatchesAnyBranch(session.PolicyDigest.Span, request.Branches))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicyOR, TpmRcConstants.TPM_RC_VALUE);
        }

        byte[] updated = new byte[TpmPolicyDigest.Size(session.PolicyHash)];
        _ = TpmPolicyDigest.ExtendForOr(request.Branches, session.PolicyHash, updated);

        return StorePolicyDigest(state, session, updated, new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS), "PolicyOR");
    }

    //TPM2_PolicySecret() binds a policy to the authorization of a permanent entity (Part 3, clause 23.4). This
    //slice authorizes permanent hierarchies (empty auth), whose Name is the 4-byte handle value (Part 1, clause
    //26.6); PolicySecret(TPM_RH_ENDORSEMENT) with an empty policyRef yields the well-known EK authorization policy.
    //The returned timeout/ticket are framed by the serializer (a NULL ticket in this immediate form). See the note
    //on OnPolicyCommandCode.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnPolicySecret(TpmSimulatorState state, TpmPolicySecretRequested request)
    {
        if(!state.PolicySessions.TryGetValue(request.PolicySession, out PolicySessionState? session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicySecret, TpmRcConstants.TPM_RC_HANDLE);
        }

        //This slice models PolicySecret only for permanent hierarchies (empty auth), whose Name is the 4-byte
        //handle value (Part 1, clause 16). A non-permanent authHandle (an NV Index or object) has a computed
        //Name and its own authValue; folding the raw handle bytes for such an entity would both diverge from the
        //TPM Name formula and skip the authorization it requires, so an unsupported authorization entity is rejected
        //rather than silently advancing the policyDigest as if its secret had been proven.
        if(!IsPermanentHandle(request.AuthHandle))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicySecret, TpmRcConstants.TPM_RC_HANDLE);
        }

        //The Name of a permanent handle is its 4-byte handle value (Part 1, clause 16).
        Span<byte> authName = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(authName, request.AuthHandle);

        byte[] updated = new byte[TpmPolicyDigest.Size(session.PolicyHash)];
        _ = TpmPolicyDigest.ExtendForSecret(session.PolicyDigest.Span, authName, ReadOnlySpan<byte>.Empty, session.PolicyHash, updated);

        return StorePolicyDigest(state, session, updated, new TpmPolicySecretResponse(TpmRcConstants.TPM_RC_SUCCESS), "PolicySecret");
    }

    //TPM2_PolicySigned() binds a policy session to a signature over aHash = H_authAlg(nonceTPM || expiration ||
    //cpHashA || policyRef) made by the key at authObject (Part 3, Section 23.3). Neither handle requires
    //authorization; unlike TPM2_VerifySignature(), authObject's sign attribute is never consulted (any loaded
    //public key validates — CryptValidateSignature's own design, deliberately different from VerifySignature's
    //TPMA_OBJECT.sign gate). A trial session skips every parameter/signature check and folds unconditionally
    //(the whole point of a trial session: predicting the digest a real signed authorization would produce without
    //holding the private key). A non-trial session runs the checks in spec order — nonceTPM, expiration/deadline,
    //cpHashA size+first-writer-wins latch, scheme-hash support, then key-type dispatch — before the signature
    //verification itself is folded into an effect (TpmVerifyPolicySignedAction/TpmRsaVerifyPolicySignedAction),
    //since that needs the async digest/verify seam a pure transition cannot reach. See the single-source-of-truth
    //note on OnPolicyCommandCode for the digest fold itself.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnPolicySigned(TpmSimulatorState state, TpmPolicySignedRequested request)
    {
        if(!state.PolicySessions.TryGetValue(request.PolicySession, out PolicySessionState? session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicySigned, TpmRcConstants.TPM_RC_HANDLE);
        }

        if(!state.TransientObjects.TryGetValue(request.AuthObject, out TransientKeyState? authObject))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicySigned, TpmRcConstants.TPM_RC_HANDLE);
        }

        //Trial session: skip ALL parameter and signature checks (Part 3, Section 23.3: "If policySession is a
        //trial session, the TPM will not check the signature... as if a properly signed authorization was
        //received") and fold unconditionally, using whatever authObjectName/policyRef the caller supplied.
        if(session.IsTrial)
        {
            return FoldPolicySigned(state, session, authObject.Name, request.PolicyRef);
        }

        TpmSimulatorState checkedState = state;

        //(1) nonceTPM: only checked when the caller supplies a non-empty value; an empty caller nonce always
        //passes (a session-unbound authorization, Part 3, Section 23.2.2).
        if(!request.NonceTpm.IsEmpty && !request.NonceTpm.Span.SequenceEqual(session.NonceTpm.Span))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicySigned, TpmRcConstants.TPM_RC_NONCE);
        }

        //(2) expiration -> inline deadline: an empty caller nonce means an absolute Time-base deadline; a
        //non-empty one means a deadline relative to the session's captured StartTime. The sign of expiration only
        //marks "ticket requested" (deferred this wave) — the magnitude is what the deadline check consumes.
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
                return Reject(state, TpmCcConstants.TPM_CC_PolicySigned, TpmRcConstants.TPM_RC_EXPIRED);
            }
        }

        //(3) cpHashA: only checked when non-empty. Size must equal the session's digest width; the session's
        //cpHash latch is first-writer-wins (Part 3, Section 23.2.4) — an already-latched, differing value is
        //rejected, an unlatched session latches this value.
        if(!request.CpHashA.IsEmpty)
        {
            if(request.CpHashA.Length != TpmPolicyDigest.Size(session.PolicyHash))
            {
                return Reject(state, TpmCcConstants.TPM_CC_PolicySigned, TpmRcConstants.TPM_RC_SIZE);
            }

            if(!session.CpHash.IsEmpty)
            {
                if(!request.CpHashA.Span.SequenceEqual(session.CpHash.Span))
                {
                    return Reject(state, TpmCcConstants.TPM_CC_PolicySigned, TpmRcConstants.TPM_RC_CPHASH);
                }
            }
            else
            {
                session = session with { CpHash = request.CpHashA };
                checkedState = state with { PolicySessions = state.PolicySessions.SetItem(session.Handle, session) };
            }
        }

        //Scheme-hash support (Part 3, Section 23.3): an unsupported/zero-width scheme hash fails closed with
        //TPM_RC_SCHEME before any verification is attempted, mirroring TPM2_VerifySignature()'s own gate.
        if(!IsSupportedAttestHashAlg(request.SchemeHashAlg))
        {
            return Reject(checkedState, TpmCcConstants.TPM_CC_PolicySigned, TpmRcConstants.TPM_RC_SCHEME);
        }

        TpmAction? action = (authObject.KeyType, request.SignatureScheme) switch
        {
            (TpmAlgIdConstants.TPM_ALG_RSA, TpmAlgIdConstants.TPM_ALG_RSASSA or TpmAlgIdConstants.TPM_ALG_RSAPSS) =>
                new TpmRsaVerifyPolicySignedAction(
                    request.PolicySession, authObject.Name, request.PolicyRef, session.PolicyHash, request.NonceTpm, request.Expiration,
                    request.CpHashA, authObject.PrivateKey, request.Signature, request.SignatureScheme, request.SchemeHashAlg),
            (TpmAlgIdConstants.TPM_ALG_ECC, TpmAlgIdConstants.TPM_ALG_ECDSA) =>
                new TpmVerifyPolicySignedAction(
                    request.PolicySession, authObject.Name, request.PolicyRef, session.PolicyHash, request.NonceTpm, request.Expiration,
                    request.CpHashA, authObject.PublicPoint, authObject.Curve, request.Signature, request.SchemeHashAlg),
            _ => null
        };

        if(action is null)
        {
            //A scheme incompatible with authObject's key type — e.g. an ECDSA scheme against an RSA key, or vice
            //versa — fails closed rather than silently coercing to the key's native scheme (mirrors OnVerifySignature).
            return Reject(checkedState, TpmCcConstants.TPM_CC_PolicySigned, TpmRcConstants.TPM_RC_SCHEME);
        }

        return Transition(
            checkedState with
            {
                NextAction = action,
                ResponseIntent = null
            },
            "PolicySigned:Requested");
    }

    //Folds authObjectName + policyRef into the session's policyDigest via TpmPolicyDigest.ExtendForSigned and
    //frames the always-NULL-ticket PolicySigned response (the real TPMT_TK_AUTH mint is deferred to a future
    //wave, mirroring PolicySecret's shipped immediate-form slice). Shared by the trial-session immediate fold and
    //the non-trial continuation's success branch, so both paths advance the digest identically.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> FoldPolicySigned(
        TpmSimulatorState state, PolicySessionState session, ReadOnlyMemory<byte> authObjectName, ReadOnlyMemory<byte> policyRef)
    {
        byte[] updated = new byte[TpmPolicyDigest.Size(session.PolicyHash)];
        _ = TpmPolicyDigest.ExtendForSigned(session.PolicyDigest.Span, authObjectName.Span, policyRef.Span, session.PolicyHash, updated);

        return StorePolicyDigest(state, session, updated, new TpmPolicySignedResponse(TpmRcConstants.TPM_RC_SUCCESS), "PolicySigned");
    }

    //Frames the TPM2_PolicySigned() response the effect produced: on a successful verification, folds the
    //policyDigest via FoldPolicySigned; on TPM_RC_SIGNATURE, rejects with no change to the session (mirroring
    //OnSignatureVerified's success/rejection split). Either way NextAction is cleared here — this transition runs
    //as effect feedback, not through OnExternalInput, so nothing else resets it.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnPolicySignedVerified(TpmSimulatorState state, TpmPolicySignedVerified verified)
    {
        TpmSimulatorState cleared = state with { NextAction = NullAction.Instance };

        if(verified.ResponseCode != TpmRcConstants.TPM_RC_SUCCESS)
        {
            return Transition(
                cleared with { ResponseIntent = new TpmHeaderOnlyResponse(verified.ResponseCode) },
                "PolicySigned:Rejected");
        }

        PolicySessionState session = cleared.PolicySessions[verified.PolicySession];

        return FoldPolicySigned(cleared, session, verified.AuthObjectName, verified.PolicyRef);
    }

    //TPM2_PolicyAuthorize() lets an object's fixed authPolicy accept a policy the authority can revise at will
    //(Part 3, Section 23.16): when the session's current policyDigest equals the caller-supplied approvedPolicy
    //and checkTicket proves keySign signed H(approvedPolicy || policyRef), the policyDigest is NOT folded onto
    //the accumulated value — it is RESET to zero and refolded from keySign and policyRef alone
    //(ExtendForAuthorize), so the result depends only on the authority's key and the qualifier, never on
    //whatever policy actually produced approvedPolicy. The keySign hash-algorithm/size checks run for a trial
    //session too; the approvedPolicy-equality and ticket-re-verification checks are non-trial only, and the
    //re-verification itself is folded into an effect (TpmVerifyPolicyAuthorizeTicketAction) since it needs the
    //async digest/HMAC seam a pure transition cannot reach. See the single-source-of-truth note on
    //OnPolicyCommandCode for the digest fold itself.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnPolicyAuthorize(TpmSimulatorState state, TpmPolicyAuthorizeRequested request)
    {
        if(!state.PolicySessions.TryGetValue(request.PolicySession, out PolicySessionState? session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicyAuthorize, TpmRcConstants.TPM_RC_HANDLE);
        }

        //(1) hashAlg = the first two octets of keySign (Part 2, Section 10.5.3); unrecognized -> TPM_RC_HASH.
        //The remainder must be exactly that hash's digest width -> TPM_RC_SIZE. Both run for a trial session too.
        if(request.KeySign.Length < sizeof(ushort))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicyAuthorize, TpmRcConstants.TPM_RC_SIZE);
        }

        var hashAlg = (TpmAlgIdConstants)BinaryPrimitives.ReadUInt16BigEndian(request.KeySign.Span);
        if(!IsSupportedAttestHashAlg(hashAlg))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicyAuthorize, TpmRcConstants.TPM_RC_HASH);
        }

        if(request.KeySign.Length - sizeof(ushort) != TpmPolicyDigest.Size(hashAlg))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicyAuthorize, TpmRcConstants.TPM_RC_SIZE);
        }

        //Trial session: skip the approvedPolicy equality check and the ticket re-verification (Part 3, Section
        //23.16: "policySession->policyDigest is extended as if the ticket is valid without actual verification")
        //and fold unconditionally.
        if(session.IsTrial)
        {
            return FoldPolicyAuthorize(state, session, request.KeySign, request.PolicyRef);
        }

        //(2) approvedPolicy must equal the session's current policyDigest (Part 3, Section 23.16).
        if(!CryptographicOperations.FixedTimeEquals(request.ApprovedPolicy.Span, session.PolicyDigest.Span))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicyAuthorize, TpmRcConstants.TPM_RC_VALUE);
        }

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

    //Resets and folds keySign + policyRef into the session's policyDigest via TpmPolicyDigest.ExtendForAuthorize
    //and frames the header-only PolicyAuthorize response (Part 3, Section 23.16 has no response parameters at
    //all). Shared by the trial-session immediate fold and the non-trial continuation's success branch, so both
    //paths advance the digest identically.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> FoldPolicyAuthorize(
        TpmSimulatorState state, PolicySessionState session, ReadOnlyMemory<byte> keySign, ReadOnlyMemory<byte> policyRef)
    {
        byte[] updated = new byte[TpmPolicyDigest.Size(session.PolicyHash)];
        _ = TpmPolicyDigest.ExtendForAuthorize(keySign.Span, policyRef.Span, session.PolicyHash, updated);

        return StorePolicyDigest(state, session, updated, new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS), "PolicyAuthorize");
    }

    //Frames the TPM2_PolicyAuthorize() response the effect produced: on a successful ticket re-verification,
    //folds the policyDigest via FoldPolicyAuthorize; on TPM_RC_VALUE, rejects with no change to the session
    //(mirroring OnPolicySignedVerified's success/rejection split). Either way NextAction is cleared here — this
    //transition runs as effect feedback, not through OnExternalInput, so nothing else resets it.
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

        return FoldPolicyAuthorize(cleared, session, verified.KeySign, verified.PolicyRef);
    }

    //TPM2_PolicyNV() binds a policy to a comparison against an NV Index's contents (Part 3, clause 23.9). The
    //Index must be defined; an unknown Index or session handle is TPM_RC_HANDLE. On a REAL (non-trial) session the
    //retained Index data at the offset is compared to operandB per the TPM_EO operation (TPM_RC_POLICY on a false
    //result) before the digest folds; a TRIAL session skips the comparison entirely — only the Index Name and the
    //arguments drive the digest. See the note on OnPolicyCommandCode.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnPolicyNv(TpmSimulatorState state, TpmPolicyNvRequested request)
    {
        if(!state.PolicySessions.TryGetValue(request.PolicySession, out PolicySessionState? session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicyNV, TpmRcConstants.TPM_RC_HANDLE);
        }

        if(!state.NvIndexes.TryGetValue(request.NvIndex, out NvIndexState? index))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicyNV, TpmRcConstants.TPM_RC_HANDLE);
        }

        if(!session.IsTrial)
        {
            //The model retains only the octets actually written (its NvIndexState.Data grows with each write, as
            //OnNvRead's own bound already treats it), so a compared window beyond the retained extent — including
            //an unwritten Index's empty Data — is out of range (TPM_RC_NV_RANGE, Part 3, clause 31.13).
            if((long)request.Offset + request.OperandB.Length > index.Data.Length)
            {
                return Reject(state, TpmCcConstants.TPM_CC_PolicyNV, TpmRcConstants.TPM_RC_NV_RANGE);
            }

            ReadOnlySpan<byte> comparand = index.Data.Span.Slice(request.Offset, request.OperandB.Length);
            if(!TpmEoComparator.TryEvaluate(comparand, request.OperandB.Span, (TpmEoConstants)request.Operation, out bool matched, out TpmRcConstants rejectionCode))
            {
                return Reject(state, TpmCcConstants.TPM_CC_PolicyNV, rejectionCode);
            }

            if(!matched)
            {
                return Reject(state, TpmCcConstants.TPM_CC_PolicyNV, TpmRcConstants.TPM_RC_POLICY);
            }
        }

        //The Index's Name needs the asynchronous digest seam (TPM digests belong there, not the sync seam a pure
        //transition could reach on its own), so the transition declares a TpmComputeNvNameAction carrying the
        //Index's public-area fields and the pending assertion's arguments, and leaves no response yet;
        //OnNvNameComputedForPolicy extends the policyDigest once the Name comes back.
        return Transition(
            state with
            {
                NextAction = new TpmComputeNvNameAction(
                    request.PolicySession, index.NvIndex, index.Attributes, index.DataSize, TpmAlgIdConstants.TPM_ALG_SHA256, request.OperandB, request.Offset, request.Operation),
                ResponseIntent = null
            },
            "PolicyNV:Requested");
    }

    //Extends the policy session's policyDigest with the NV Index's computed Name and completes TPM2_PolicyNV()
    //(TPM 2.0 Library Part 3, clause 23.9). See the single-source-of-truth note on OnPolicyCommandCode. The
    //session was already resolved by OnPolicyNv and cannot vanish before this feedback arrives (the automaton is
    //single-threaded, so no other command interleaves), exactly as every other action feedback in this file
    //trusts its resolved state without re-checking.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnNvNameComputedForPolicy(TpmSimulatorState state, TpmNvNameComputedForPolicy computed)
    {
        using(computed.NvName)
        {
            PolicySessionState session = state.PolicySessions[computed.PolicySession];
            byte[] updated = new byte[TpmPolicyDigest.Size(session.PolicyHash)];
            _ = TpmPolicyDigest.ExtendForNv(
                session.PolicyDigest.Span, computed.OperandB.Span, computed.Offset, computed.Operation,
                computed.NvName.Memory.Span[..computed.NvNameLength], session.PolicyHash, updated);

            return Transition(
                state with
                {
                    NextAction = NullAction.Instance,
                    PolicySessions = state.PolicySessions.SetItem(session.Handle, session with { PolicyDigest = updated }),
                    ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
                },
                "PolicyNV:Completed");
        }
    }

    //TPM2_PolicyCounterTimer() binds a policy to a comparison against the TPM's live TPMS_TIME_INFO (Time, Clock,
    //resetCount, restartCount, Safe — Part 3, clause 23.10). Unlike PolicyNV, this needs no Name computation (the
    //compared value is TPM-global state, not a named entity), so it is a PURE transition shaped exactly like
    //OnPolicyCommandCode: resolve the session, then extend. The offset/size range checks run for trial and real
    //sessions alike; only the comparison itself is skipped for a trial session. See the single-source-of-truth
    //note on OnPolicyCommandCode.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnPolicyCounterTimer(TpmSimulatorState state, TpmPolicyCounterTimerRequested request)
    {
        if(!state.PolicySessions.TryGetValue(request.PolicySession, out PolicySessionState? session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicyCounterTimer, TpmRcConstants.TPM_RC_HANDLE);
        }

        //offset > 25 is TPM_RC_VALUE (Part 3, clause 23.10); offset == 25 (a zero-length window at the very end) is
        //legal. These two range checks run even for a trial session — the policy would not make sense otherwise.
        if(request.Offset > TpmsTimeInfo.SerializedSize)
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicyCounterTimer, TpmRcConstants.TPM_RC_VALUE);
        }

        //offset + operandB.Length overflowing the 25-octet structure is TPM_RC_RANGE. Widened to a wider integer
        //defensively, mirroring the spec's own choice of arithmetic width for this sum.
        if((uint)request.Offset + (uint)request.OperandB.Length > TpmsTimeInfo.SerializedSize)
        {
            return Reject(state, TpmCcConstants.TPM_CC_PolicyCounterTimer, TpmRcConstants.TPM_RC_RANGE);
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
                return Reject(state, TpmCcConstants.TPM_CC_PolicyCounterTimer, rejectionCode);
            }

            if(!matched)
            {
                return Reject(state, TpmCcConstants.TPM_CC_PolicyCounterTimer, TpmRcConstants.TPM_RC_POLICY);
            }
        }

        byte[] updated = new byte[TpmPolicyDigest.Size(session.PolicyHash)];
        _ = TpmPolicyDigest.ExtendForCounterTimer(session.PolicyDigest.Span, request.OperandB.Span, request.Offset, request.Operation, session.PolicyHash, updated);

        return StorePolicyDigest(state, session, updated, new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS), "PolicyCounterTimer");
    }

    //TPM2_FlushContext() removes a loaded session or transient object from TPM memory (Part 3, clause 28.4).
    //A pure state transition: drop the handle from whichever table holds it — policy sessions, HMAC sessions,
    //transient keys, and loaded sealed objects are all flushable transient state. An unknown handle is
    //TPM_RC_HANDLE.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnFlushContext(TpmSimulatorState state, TpmFlushContextRequested request)
    {
        if(state.PolicySessions.ContainsKey(request.FlushHandle))
        {
            return Transition(
                state with
                {
                    PolicySessions = state.PolicySessions.Remove(request.FlushHandle),
                    ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
                },
                "FlushContext:Session");
        }

        if(state.HmacSessions.ContainsKey(request.FlushHandle))
        {
            return Transition(
                state with
                {
                    HmacSessions = state.HmacSessions.Remove(request.FlushHandle),
                    ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
                },
                "FlushContext:HmacSession");
        }

        if(state.TransientObjects.ContainsKey(request.FlushHandle))
        {
            return Transition(
                state with
                {
                    TransientObjects = state.TransientObjects.Remove(request.FlushHandle),
                    ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
                },
                "FlushContext:Object");
        }

        if(state.LoadedSealedObjects.ContainsKey(request.FlushHandle))
        {
            return Transition(
                state with
                {
                    LoadedSealedObjects = state.LoadedSealedObjects.Remove(request.FlushHandle),
                    ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
                },
                "FlushContext:SealedObject");
        }

        return Reject(state, TpmCcConstants.TPM_CC_FlushContext, TpmRcConstants.TPM_RC_HANDLE);
    }

    //The fixed nonceCaller floor at TPM2_StartAuthSession() (TPM 2.0 Library Part 3, clause 11.1; Part 1, clause
    //19.6.3.2): 16 octets regardless of authHash — only the ceiling scales with the session hash's digest size.
    private const int SessionStartNonceCallerMinimumSize = 16;

    //TPM2_StartAuthSession() for a bound and/or salted HMAC session with parameter encryption (Part 3, clause
    //11.1; Part 1, clauses 17.6 and 19). The precondition ladder below follows clause 11.1's normative order: the
    //nonceCaller floor/ceiling first (unconditional, ahead of tpmKey/bind entirely); then tpmKey's asymmetric-
    //type/handle/decrypt-attribute checks (secret recovery itself is asynchronous — the RSA and ECC arms dispatch
    //to TpmRecoverRsaSessionSaltAction/TpmRecoverEccSessionSaltAction, whose any internal recovery failure reports
    //TPM_RC_VALUE immediately, never poisoned-and-deferred); then the bind entity (a PIN Fail/Pass NV Index can
    //never bind, closing the PIN-extraction vector the dictionary-attack wave's indexes would otherwise open);
    //then the negotiated symmetric definition's mode. The session key derivation (KDFa keyed on bindAuthValue ‖
    //salt) and nonceTPM generation need the RNG and the HMAC seam, so this allocates a handle in the
    //TPM_HT_HMAC_SESSION range and declares whichever action the ladder selects; the effectful loop feeds the
    //result back as a TpmHmacSessionStarted input (OnHmacSessionStarted), which reports a deferred recovery
    //failure or completes the session.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnStartHmacSession(TpmSimulatorState state, TpmStartHmacSessionRequested request)
    {
        if(!IsSupportedPolicyHash(request.AuthHash))
        {
            return Reject(state, TpmCcConstants.TPM_CC_StartAuthSession, TpmRcConstants.TPM_RC_HASH);
        }

        int authHashDigestSize = TpmPolicyDigest.Size(request.AuthHash);
        if(request.NonceCaller.Length < SessionStartNonceCallerMinimumSize || request.NonceCaller.Length > authHashDigestSize)
        {
            return Reject(state, TpmCcConstants.TPM_CC_StartAuthSession, TpmRcConstants.TPM_RC_SIZE);
        }

        //tpmKey: TPM_RH_NULL means unsalted (an unsalted request naming a non-empty encryptedSalt is malformed).
        //Otherwise the handle must resolve to a loaded asymmetric (RSA/ECC) key carrying the decrypt attribute,
        //and encryptedSalt must be non-empty.
        TransientKeyState? tpmKeyState = null;
        if(request.TpmKey != (uint)TpmRh.TPM_RH_NULL)
        {
            if(IsPermanentHandle(request.TpmKey) || state.LoadedSealedObjects.ContainsKey(request.TpmKey))
            {
                //A hierarchy or a sealed (KEYEDHASH) object is never an asymmetric key.
                return Reject(state, TpmCcConstants.TPM_CC_StartAuthSession, TpmRcConstants.TPM_RC_KEY);
            }

            if(!state.TransientObjects.TryGetValue(request.TpmKey, out tpmKeyState) && !state.PersistentObjects.TryGetValue(request.TpmKey, out tpmKeyState))
            {
                return Reject(state, TpmCcConstants.TPM_CC_StartAuthSession, TpmRcConstants.TPM_RC_HANDLE);
            }

            if(request.EncryptedSalt.IsEmpty)
            {
                return Reject(state, TpmCcConstants.TPM_CC_StartAuthSession, TpmRcConstants.TPM_RC_VALUE);
            }

            if((tpmKeyState.Attributes & TpmaObject.DECRYPT) == 0)
            {
                return Reject(state, TpmCcConstants.TPM_CC_StartAuthSession, TpmRcConstants.TPM_RC_ATTRIBUTES);
            }
        }
        else if(!request.EncryptedSalt.IsEmpty)
        {
            return Reject(state, TpmCcConstants.TPM_CC_StartAuthSession, TpmRcConstants.TPM_RC_VALUE);
        }

        //bind: resolves the entity's real authorization value and Name for the session-key KDFa and the later
        //command-HMAC bind-omission check (Part 1, clause 17.6.10 equations 21/22/25/26).
        if(!TryResolveBindEntity(state, request.Bind, out TpmRcConstants bindRejectCode, out ReadOnlyMemory<byte> boundAuthValue, out ReadOnlyMemory<byte> boundEntityName))
        {
            return Reject(state, TpmCcConstants.TPM_CC_StartAuthSession, bindRejectCode);
        }

        //symmetric: TPM_ALG_NULL and XOR need no mode. A block cipher this model can key parameter encryption
        //with (AES) must negotiate CFB specifically, else TPM_RC_MODE; any other negotiated algorithm entirely
        //(unsupported by this model) is TPM_RC_SYMMETRIC.
        if(!request.Symmetric.IsNull && !request.Symmetric.IsXor)
        {
            if(request.Symmetric.Algorithm != TpmAlgIdConstants.TPM_ALG_AES)
            {
                return Reject(state, TpmCcConstants.TPM_CC_StartAuthSession, TpmRcConstants.TPM_RC_SYMMETRIC);
            }

            if(request.Symmetric.Mode != TpmAlgIdConstants.TPM_ALG_CFB)
            {
                return Reject(state, TpmCcConstants.TPM_CC_StartAuthSession, TpmRcConstants.TPM_RC_MODE);
            }
        }

        uint handle = state.NextHmacSessionHandle;
        TpmAction action = tpmKeyState switch
        {
            null => new TpmStartHmacSessionAction(
                handle, request.AuthHash, request.Symmetric, request.NonceCaller, boundAuthValue, boundEntityName, ReadOnlyMemory<byte>.Empty),
            { KeyType: TpmAlgIdConstants.TPM_ALG_RSA } rsaKey => new TpmRecoverRsaSessionSaltAction(
                handle, request.AuthHash, request.Symmetric, request.NonceCaller, boundAuthValue, boundEntityName,
                request.EncryptedSalt, rsaKey.PrivateKey, TpmKeyNameAlg(rsaKey)),
            _ => new TpmRecoverEccSessionSaltAction(
                handle, request.AuthHash, request.Symmetric, request.NonceCaller, boundAuthValue, boundEntityName,
                request.EncryptedSalt, tpmKeyState.PrivateKey, tpmKeyState.PublicPoint, tpmKeyState.Curve, TpmKeyNameAlg(tpmKeyState))
        };

        return Transition(
            state with
            {
                NextHmacSessionHandle = state.NextHmacSessionHandle + 1,
                NextAction = action,
                ResponseIntent = null
            },
            "StartAuthSession:HmacRequested");
    }

    //Resolves a bind entity's real authorization value and Name for the session-key KDFa (TPM 2.0 Library Part 1,
    //clause 17.6.10 equations 20/23/25) and the later command-HMAC bind-omission check (equations 21/22/25/26).
    //TPM_RH_NULL is unbound (both empty); a permanent hierarchy's Name is its own 4-octet big-endian handle
    //value, with a real authorization value only for the owner and lockout hierarchies (the only two this model
    //tracks). A PIN Fail/Pass NV Index can never bind (TPM_RC_HANDLE); every other NV Index binds with its real
    //authValue, though its Name here is approximated as the raw handle value rather than nameAlg ‖
    //H(TPMS_NV_PUBLIC) — a residual: no test exercises the bind-omission check against an NV-Index-bound
    //session, and the approximation only risks a spurious inclusion of authValue where the real omission would
    //apply (a false AUTH_FAIL on an unexercised path), never an authorization bypass. A sealed object's Name and
    //userAuth are both exact (TPM2_Create()/TPM2_Load() already retain them); a signing/storage object carries no
    //modelled authValue (empty).
    private static bool TryResolveBindEntity(
        TpmSimulatorState state,
        uint bind,
        out TpmRcConstants rejectCode,
        out ReadOnlyMemory<byte> boundAuthValue,
        out ReadOnlyMemory<byte> boundEntityName)
    {
        rejectCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(bind == (uint)TpmRh.TPM_RH_NULL)
        {
            boundAuthValue = ReadOnlyMemory<byte>.Empty;
            boundEntityName = ReadOnlyMemory<byte>.Empty;

            return true;
        }

        if(IsPermanentHandle(bind))
        {
            byte[] handleBytes = new byte[sizeof(uint)];
            BinaryPrimitives.WriteUInt32BigEndian(handleBytes, bind);
            boundEntityName = handleBytes;
            boundAuthValue = bind switch
            {
                (uint)TpmRh.TPM_RH_OWNER => state.OwnerAuth,
                (uint)TpmRh.TPM_RH_LOCKOUT => state.LockoutAuth,
                _ => ReadOnlyMemory<byte>.Empty
            };

            return true;
        }

        if(state.NvIndexes.TryGetValue(bind, out NvIndexState? nvIndex))
        {
            if(nvIndex.IsPinIndex)
            {
                boundAuthValue = ReadOnlyMemory<byte>.Empty;
                boundEntityName = ReadOnlyMemory<byte>.Empty;
                rejectCode = TpmRcConstants.TPM_RC_HANDLE;

                return false;
            }

            byte[] handleBytes = new byte[sizeof(uint)];
            BinaryPrimitives.WriteUInt32BigEndian(handleBytes, bind);
            boundAuthValue = nvIndex.AuthValue;
            boundEntityName = handleBytes;

            return true;
        }

        if(state.LoadedSealedObjects.TryGetValue(bind, out SealedObjectState? sealedObject))
        {
            boundAuthValue = sealedObject.UserAuth;
            boundEntityName = sealedObject.Name;

            return true;
        }

        if(state.TransientObjects.TryGetValue(bind, out TransientKeyState? transient))
        {
            boundAuthValue = ReadOnlyMemory<byte>.Empty;
            boundEntityName = transient.Name;

            return true;
        }

        if(state.PersistentObjects.TryGetValue(bind, out TransientKeyState? persistent))
        {
            boundAuthValue = ReadOnlyMemory<byte>.Empty;
            boundEntityName = persistent.Name;

            return true;
        }

        boundAuthValue = ReadOnlyMemory<byte>.Empty;
        boundEntityName = ReadOnlyMemory<byte>.Empty;
        rejectCode = TpmRcConstants.TPM_RC_HANDLE;

        return false;
    }

    //Extracts a loaded key's real Name algorithm from its retained Name (nameAlg ‖ H_nameAlg(TPMT_PUBLIC), TPM
    //2.0 Library Part 1, clause 16 — the 2-octet big-endian prefix IS the Name algorithm), rather than assuming a
    //fixed value: a salted session's tpmKey may have been created with any supported nameAlg, and KDFe/OAEP must
    //key on THIS key's own algorithm, never the session's authHash (Part 1, Annex C.6.1/B.10.1).
    private static TpmAlgIdConstants TpmKeyNameAlg(TransientKeyState tpmKey) =>
        (TpmAlgIdConstants)BinaryPrimitives.ReadUInt16BigEndian(tpmKey.Name.Span[..sizeof(ushort)]);

    //Records a started bound and/or salted HMAC session and frames the TPM2_StartAuthSession() response with the
    //real nonceTPM (the value the session-key KDFa consumed, which the host must receive verbatim to derive the
    //same key) — or, when a salted arm's secret recovery failed, rejects with that failure code (TPM 2.0 Library
    //Part 3, clause 11.1). The session key and nonce become durable model state, exactly as a transient key's
    //private scalar does.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnHmacSessionStarted(TpmSimulatorState state, TpmHmacSessionStarted started)
    {
        if(started.ResponseCode != TpmRcConstants.TPM_RC_SUCCESS)
        {
            return Reject(state, TpmCcConstants.TPM_CC_StartAuthSession, started.ResponseCode);
        }

        var session = new HmacSessionState(started.SessionHandle, started.SessionAlg, started.Symmetric, started.SessionKey, started.NonceTpm, started.BoundEntityName);

        return Transition(
            state with
            {
                NextAction = NullAction.Instance,
                HmacSessions = state.HmacSessions.SetItem(started.SessionHandle, session),
                ResponseIntent = new TpmStartAuthSessionResponse(
                    TpmRcConstants.TPM_RC_SUCCESS, started.SessionHandle, started.NonceTpm.Length, started.NonceTpm)
            },
            "StartAuthSession:HmacCompleted");
    }

    //TPM2_GetRandom() over a bound HMAC session with the encrypt attribute (Part 3, clause 16.1; Part 1, clauses
    //18.7 and 19). The session must resolve (an unknown handle is the session-not-loaded warning, Part 2, clause
    //6.6.2). GetRandom authorizes no entity, so its command-HMAC key is the session key alone and no
    //dictionary-attack gate applies; a single session never folds (the fold only ever targets ANOTHER session,
    //Part 1, clause 19.6.3.4). The session area's own attribute rules (clause 5.5) are validated before any HMAC
    //is evaluated, uniformly with TPM2_Unseal() and TPM2_Create(): GetRandom has no @-handle, so its lone session
    //never authorizes an entity and MUST set at least one of decrypt/encrypt/audit (confirmed against the
    //reference session-processing routine — a lone, attribute-less session is genuinely rejected there too, not
    //merely an artifact of this simulator's own modelling). Verification needs the registered HMAC seam, so this
    //declares a TpmVerifyCommandHmacAction; ContinueGetRandomOverSession resumes once it matches.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnGetRandomOverSession(TpmSimulatorState state, TpmGetRandomOverSessionRequested request)
    {
        if(!state.HmacSessions.TryGetValue(request.SessionHandle, out HmacSessionState? session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_GetRandom, SessionReferenceMissRc(sessionIndex: 0));
        }

        TpmRcConstants? sessionAreaError = ValidateSessionArea(
            request.SessionAttributes, firstAuthorizesEntity: false, session.Symmetric,
            hasSecondSession: false, secondAttributes: 0, secondSymmetric: TpmtSymDef.Null,
            firstCommandParameterIsEncryptable: false, firstResponseParameterIsEncryptable: true);
        if(sessionAreaError is TpmRcConstants sessionAreaRc)
        {
            return Reject(state, TpmCcConstants.TPM_CC_GetRandom, sessionAreaRc);
        }

        var pending = new TpmPendingSessionVerification(
            session.Handle, SessionIndex: 0, session.SessionAlg, session.SessionKey, AuthValue: ReadOnlyMemory<byte>.Empty,
            IsDaProtected: false, request.NonceCaller, session.NonceTpm, FoldedNonces: ReadOnlyMemory<byte>.Empty,
            request.SessionAttributes, request.Hmac);

        return Transition(
            state with
            {
                NextAction = new TpmVerifyCommandHmacAction(
                    TpmCcConstants.TPM_CC_GetRandom, HandleNames: ReadOnlyMemory<byte>.Empty, request.RawParameterArea,
                    pending, ImmutableArray<TpmPendingSessionVerification>.Empty, request),
                ResponseIntent = null
            },
            "GetRandom:HmacVerifyRequested");
    }

    //Resumes TPM2_GetRandom() over a bound HMAC session once its command HMAC has verified: the random draw, nonce
    //roll, parameter encryption, rpHash, and response HMAC all need the RNG and the registered digest/HMAC seams,
    //so this declares a TpmEncryptRandomAction; the effectful loop frames the encrypted response and feeds it back
    //as a TpmEncryptedRandomProduced input (OnEncryptedRandomProduced).
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> ContinueGetRandomOverSession(TpmSimulatorState state, TpmGetRandomOverSessionRequested request)
    {
        //The session is guaranteed present (verification just resolved it); a re-lookup is used rather than
        //threading the resolved record through the verify queue, keeping TpmPendingSessionVerification's shape
        //uniform across every session-authorized command this wave touches.
        HmacSessionState session = state.HmacSessions[request.SessionHandle];

        //A request larger than the largest digest is clamped, not rejected (clause 16.1), as in the no-session form.
        int byteCount = System.Math.Min((int)request.BytesRequested, MaxRandomBytes);

        return Transition(
            state with
            {
                NextAction = new TpmEncryptRandomAction(
                    session.Handle, session.SessionAlg, session.Symmetric, session.SessionKey, request.NonceCaller, request.SessionAttributes, byteCount),
                ResponseIntent = null
            },
            "GetRandom:EncryptedRequested");
    }

    //Advances a command's session-verification queue (TpmVerifyCommandHmacAction's continuation, TPM 2.0 Library
    //Part 3, clause 5.6, check 8): a mismatch rejects, dictionary-attack-aware and session-index-encoded; a match
    //either declares the next queued session's verification or, once the queue empties, resumes the original
    //command — the one shared mechanism every session-authorized command transition in this wave routes through.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnCommandHmacVerified(TpmSimulatorState state, TpmCommandHmacVerified verified)
    {
        if(!verified.Matched)
        {
            return RejectSessionAuthFailure(state, verified.CommandCode, verified.SessionIndex, verified.IsDaProtected);
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
            _ => throw new System.InvalidOperationException($"No command-HMAC-verified continuation is defined for '{verified.NextRequest.GetType().Name}'.")
        };
    }

    //Rolls the session's nonceTPM to the freshly generated value and frames the encrypt-attributed response (the
    //encrypted parameter area and the response session area the effect assembled). The session record is replaced
    //wholesale because its nonceTPM is immutable model state, replaced once per command (Part 1, clause 17.6.7).
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnEncryptedRandomProduced(TpmSimulatorState state, TpmEncryptedRandomProduced produced)
    {
        //The session is present under normal flow (the request resolved it before declaring the action); if it was
        //flushed meanwhile the produced buffers are still released by SerializeResponse, so frame the response
        //regardless and update the table only when the session still exists.
        ImmutableDictionary<uint, HmacSessionState> sessions = state.HmacSessions;
        if(sessions.TryGetValue(produced.SessionHandle, out HmacSessionState? session))
        {
            sessions = sessions.SetItem(produced.SessionHandle, session with { NonceTpm = produced.NewNonceTpm });
        }

        return Transition(
            state with
            {
                NextAction = NullAction.Instance,
                HmacSessions = sessions,
                ResponseIntent = new TpmEncryptedRandomResponse(
                    TpmRcConstants.TPM_RC_SUCCESS,
                    produced.ParameterArea,
                    produced.ParameterLength,
                    produced.NewNonceTpm,
                    produced.SessionAttributes,
                    produced.Hmac,
                    produced.HmacLength)
            },
            "GetRandom:EncryptedCompleted");
    }

    //Whether a handle addresses a permanent entity (most-significant octet TPM_HT_PERMANENT, TPM 2.0 Library Part
    //2, clause 7.2): the reserved handles such as the hierarchies, whose Name is the 4-byte handle value.
    private static bool IsPermanentHandle(uint handle) => (handle >> 24) == (uint)TpmHt.TPM_HT_PERMANENT;

    //Stores an advanced policyDigest back onto its session and frames the command's response (a header-only success
    //for the assertion commands, or the PolicySecret timeout/ticket response). The session record is replaced
    //wholesale because its digest is immutable model state.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> StorePolicyDigest(
        TpmSimulatorState state, PolicySessionState session, byte[] updatedDigest, TpmResponseIntent response, string label) =>
        Transition(
            state with
            {
                PolicySessions = state.PolicySessions.SetItem(session.Handle, session with { PolicyDigest = updatedDigest }),
                ResponseIntent = response
            },
            label);

    //Whether the running policyDigest equals one of the OR branches (TPM 2.0 Library Part 3, clause 23.6). The
    //branches are public policy digests, so a plain byte comparison is sufficient.
    private static bool MatchesAnyBranch(ReadOnlySpan<byte> current, ImmutableArray<ReadOnlyMemory<byte>> branches)
    {
        for(int i = 0; i < branches.Length; i++)
        {
            if(current.SequenceEqual(branches[i].Span))
            {
                return true;
            }
        }

        return false;
    }

    //The policy hash algorithms the enhanced-authorization digest formula actually computes (TpmPolicyDigest.Hash).
    //SHA-1 is intentionally excluded: advertising it here while the fold cannot compute it left a session that
    //faulted on its first assertion, so StartAuthSession now rejects it up front with TPM_RC_HASH.
    private static bool IsSupportedPolicyHash(TpmAlgIdConstants hash) =>
        hash is TpmAlgIdConstants.TPM_ALG_SHA256
            or TpmAlgIdConstants.TPM_ALG_SHA384
            or TpmAlgIdConstants.TPM_ALG_SHA512;

    //The Name algorithms TpmObjectName can actually compute (TPM 2.0 Library Part 1, clause 16). SHA-1 is
    //included here (unlike IsSupportedPolicyHash's exclusion) because the profile this model serves still lists
    //it as a valid object nameAlg; an unsupported value is rejected up front with TPM_RC_HASH rather than
    //defaulted, so a caller can never silently get a SHA-256 Name for a different requested nameAlg.
    private static bool IsSupportedNameAlg(TpmAlgIdConstants nameAlg) =>
        nameAlg is TpmAlgIdConstants.TPM_ALG_SHA1
            or TpmAlgIdConstants.TPM_ALG_SHA256
            or TpmAlgIdConstants.TPM_ALG_SHA384
            or TpmAlgIdConstants.TPM_ALG_SHA512;

    //A signing key must carry the sign attribute to attest with TPM2_Certify() or TPM2_Quote() (TPM 2.0 Library
    //Part 3, clause 18.1: "If the sign attribute is not SET in the key referenced by signHandle then the TPM
    //shall return TPM_RC_KEY"). restricted does not gate either command (Part 1, clause 25.1, Table 24), so only
    //SIGN_ENCRYPT is checked here.
    private static bool CanSign(TpmaObject attributes) =>
        (attributes & TpmaObject.SIGN_ENCRYPT) == TpmaObject.SIGN_ENCRYPT;

    //The signing-scheme hash algorithms the attest digest computations actually hash with (TpmAlgIdExtensions'
    //digest-tag mapping, which TpmSimulator's Certify/Quote effects use to drive the registered digest seam).
    //SHA-1 is intentionally excluded from the signing-digest path in this codebase (mirrors
    //IsSupportedPolicyHash); an unsupported value is rejected up front with TPM_RC_HASH rather than silently
    //defaulted to SHA-256.
    private static bool IsSupportedAttestHashAlg(TpmAlgIdConstants hashAlg) =>
        hashAlg is TpmAlgIdConstants.TPM_ALG_SHA256
            or TpmAlgIdConstants.TPM_ALG_SHA384
            or TpmAlgIdConstants.TPM_ALG_SHA512;

    //A storage parent is a restricted decryption key (RESTRICTED and DECRYPT both set) — the only object type
    //that can parent (and, on a real TPM, wrap) a TPM2_Create() child (TPM 2.0 Library Part 1, clause 25.2).
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
            TpmCertifyCreationRequested => TpmCcConstants.TPM_CC_CertifyCreation,
            TpmPcrReadRequested => TpmCcConstants.TPM_CC_PCR_Read,
            TpmQuoteRequested => TpmCcConstants.TPM_CC_Quote,
            TpmGetTimeRequested => TpmCcConstants.TPM_CC_GetTime,
            TpmReadClockRequested => TpmCcConstants.TPM_CC_ReadClock,
            TpmClockSetRequested => TpmCcConstants.TPM_CC_ClockSet,
            TpmDictionaryAttackLockResetRequested => TpmCcConstants.TPM_CC_DictionaryAttackLockReset,
            TpmDictionaryAttackParametersRequested => TpmCcConstants.TPM_CC_DictionaryAttackParameters,
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
            TpmPolicySignedRequested => TpmCcConstants.TPM_CC_PolicySigned,
            TpmPolicyAuthorizeRequested => TpmCcConstants.TPM_CC_PolicyAuthorize,
            TpmPolicyNvRequested => TpmCcConstants.TPM_CC_PolicyNV,
            TpmPolicyCounterTimerRequested => TpmCcConstants.TPM_CC_PolicyCounterTimer,
            TpmMakeCredentialRequested => TpmCcConstants.TPM_CC_MakeCredential,
            TpmActivateCredentialRequested => TpmCcConstants.TPM_CC_ActivateCredential,
            TpmActivateCredentialOverSessionRequested => TpmCcConstants.TPM_CC_ActivateCredential,
            TpmFlushContextRequested => TpmCcConstants.TPM_CC_FlushContext,
            TpmUnsupportedCommandReceived unsupported => unsupported.CommandCode,
            _ => throw new System.InvalidOperationException($"Input '{input.GetType().Name}' is not a command and must not reach command dispatch.")
        };

    //Explicitly clears NextAction alongside framing the rejection: every existing single-step call site already
    //runs from a freshly-reset NextAction (OnExternalInput clears it before OnCommand dispatches), so this is a
    //no-op there, but it is REQUIRED for a multi-step verify-then-reject chain (TpmVerifyCommandHmacAction's
    //continuation, OnCommandHmacVerified) — without it, the effect loop would see the just-executed action still
    //present on the returned state and re-dispatch it without bound (mirrors OnCredentialActivated's and
    //OnSignatureVerified's explicit NextAction reset on their own rejection path).
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> Reject(TpmSimulatorState state, TpmCcConstants commandCode, TpmRcConstants responseCode) =>
        Transition(
            state with { NextAction = NullAction.Instance, ResponseIntent = new TpmHeaderOnlyResponse(responseCode) },
            $"Reject:{commandCode}");

    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> Transition(TpmSimulatorState nextState, string label) =>
        new(nextState, StackAction<TpmSimulatorStackSymbol>.None, label);
}
