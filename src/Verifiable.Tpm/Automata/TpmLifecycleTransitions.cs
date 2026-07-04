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
using Verifiable.Tpm.Infrastructure.Spec.Attributes;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

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
                TpmObjectQuoted objectQuoted => OnObjectQuoted(state, objectQuoted),
                TpmHmacSessionStarted hmacSessionStarted => OnHmacSessionStarted(state, hmacSessionStarted),
                TpmEncryptedRandomProduced encryptedRandom => OnEncryptedRandomProduced(state, encryptedRandom),
                TpmUnsealedOverSessions unsealedOverSessions => OnUnsealedOverSessions(state, unsealedOverSessions),
                TpmCredentialMade credentialMade => OnCredentialMade(state, credentialMade),
                TpmCredentialActivated credentialActivated => OnCredentialActivated(state, credentialActivated),
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
            TpmEvictControlRequested evictControl => OnEvictControl(state, evictControl),
            TpmCreatePrimaryRequested createPrimary => OnCreatePrimary(state, createPrimary),
            TpmCreateRsaPrimaryRequested createRsaPrimary => OnCreateRsaPrimary(state, createRsaPrimary),
            TpmCreateStorageParentRequested createStorageParent => OnCreateStorageParent(state, createStorageParent),
            TpmSignRequested sign => OnSign(state, sign),
            TpmCreateSealedObjectRequested createSealed => OnCreateSealedObject(state, createSealed),
            TpmLoadObjectRequested loadObject => OnLoadObject(state, loadObject),
            TpmUnsealRequested unseal => OnUnseal(state, unseal),
            TpmUnsealOverSessionsRequested unsealOverSessions => OnUnsealOverSessions(state, unsealOverSessions),
            TpmCertifyRequested certify => OnCertify(state, certify),
            TpmPcrReadRequested pcrRead => OnPcrRead(state, pcrRead),
            TpmQuoteRequested quote => OnQuote(state, quote),
            TpmStartAuthSessionRequested startAuthSession => OnStartAuthSession(state, startAuthSession),
            TpmStartHmacSessionRequested startHmacSession => OnStartHmacSession(state, startHmacSession),
            TpmGetRandomOverSessionRequested getRandomOverSession => OnGetRandomOverSession(state, getRandomOverSession),
            TpmPolicyCommandCodeRequested policyCommandCode => OnPolicyCommandCode(state, policyCommandCode),
            TpmPolicyAuthValueRequested policyAuthValue => OnPolicyAuthValue(state, policyAuthValue),
            TpmPolicyGetDigestRequested policyGetDigest => OnPolicyGetDigest(state, policyGetDigest),
            TpmPolicyPcrRequested policyPcr => OnPolicyPcr(state, policyPcr),
            TpmPolicyOrRequested policyOr => OnPolicyOr(state, policyOr),
            TpmPolicySecretRequested policySecret => OnPolicySecret(state, policySecret),
            TpmPolicyNvRequested policyNv => OnPolicyNv(state, policyNv),
            TpmMakeCredentialRequested makeCredential => OnMakeCredential(state, makeCredential),
            TpmActivateCredentialRequested activateCredential => OnActivateCredential(state, activateCredential),
            TpmFlushContextRequested flushContext => OnFlushContext(state, flushContext),
            _ => throw new System.InvalidOperationException($"Command input '{input.GetType().Name}' passed precondition gating but has no dispatch handler.")
        };
    }

    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnStartup(TpmSimulatorState state, TpmSuConstants startupType) =>
        startupType switch
        {
            //Startup(CLEAR): TPM Reset or TPM Restart — always becomes operational (clause 10.2.3.2).
            TpmSuConstants.TPM_SU_CLEAR => Transition(
                state with
                {
                    Phase = TpmLifecyclePhase.Operational,
                    LastOrderlyShutdown = null,
                    ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
                },
                "Startup:Clear"),

            //Startup(STATE) after a Shutdown(STATE): TPM Resume.
            TpmSuConstants.TPM_SU_STATE when state.LastOrderlyShutdown == TpmSuConstants.TPM_SU_STATE => Transition(
                state with
                {
                    Phase = TpmLifecyclePhase.Operational,
                    LastOrderlyShutdown = null,
                    ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
                },
                "Startup:State"),

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

        var index = new NvIndexState(request.NvIndex, request.IndexAuth, request.Attributes, request.DataSize, ReadOnlyMemory<byte>.Empty);

        return Transition(
            state with
            {
                NvIndexes = state.NvIndexes.SetItem(request.NvIndex, index),
                ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
            },
            "NvDefineSpace");
    }

    //TPM2_NV_Read() authorizes against an NV Index, then reads its data. This slice models Index
    //authorization (the authorization handle is the Index itself) and the authorization outcomes that the
    //DA/PIN flow turns on; the data-returning path and the lockout-counter coupling (clause 17.8.3) arrive
    //with TPM2_NV_Write() and the DA-machinery slice respectively.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnNvRead(TpmSimulatorState state, TpmNvReadRequested request)
    {
        //The Index must exist (Part 3, clause 31.13).
        if(!state.NvIndexes.TryGetValue(request.NvIndex, out NvIndexState? index))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Read, TpmRcConstants.TPM_RC_HANDLE);
        }

        //Only Index authorization (authHandle == nvIndex) is modelled this slice; owner- and
        //policy-authorized reads against the same Index arrive later.
        if(request.AuthHandle != request.NvIndex)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Read, TpmRcConstants.TPM_RC_AUTH_TYPE);
        }

        //Constant-time comparison of the supplied authorization against the Index authValue. A mismatch is
        //an auth-failure for a DA-protected Index (clause 17.8.3 — feeds the lockout counter in the
        //DA-machinery slice) and a plain bad-authorization for a non-DA Index (clause 17.8.1).
        if(!CryptographicOperations.FixedTimeEquals(request.AuthSupplied.Span, index.AuthValue.Span))
        {
            TpmRcConstants failureCode = index.IsDaProtected
                ? TpmRcConstants.TPM_RC_AUTH_FAIL
                : TpmRcConstants.TPM_RC_BAD_AUTH;

            return Reject(state, TpmCcConstants.TPM_CC_NV_Read, failureCode);
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

        //Authorization succeeded. An Index that has never been written (TPMA_NV_WRITTEN clear) is uninitialized,
        //so a read of it answers TPM_RC_NV_UNINITIALIZED (Part 3, clause 31.13).
        if(!index.IsWritten)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Read, TpmRcConstants.TPM_RC_NV_UNINITIALIZED);
        }

        //The requested window must lie within the octets the Index has been written with. The model retains the
        //written extent of the data area (grown by TPM2_NV_Write()), so a read past it is out of range
        //(TPM_RC_NV_RANGE, Part 3, clause 31.13); the endorsement-provisioning flow reads back exactly what it wrote.
        if((long)request.Offset + request.Size > index.Data.Length)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Read, TpmRcConstants.TPM_RC_NV_RANGE);
        }

        //Return the stored octets at the requested offset/length; the data references durable model state, framed
        //into the response as a TPM2B_MAX_NV_BUFFER by the serializer.
        ReadOnlyMemory<byte> window = index.Data.Slice(request.Offset, request.Size);

        return Transition(
            state with { ResponseIntent = new TpmNvReadDataResponse(TpmRcConstants.TPM_RC_SUCCESS, window) },
            "NvRead");
    }

    //TPM2_NV_Write() writes data to a defined NV Index at an offset, then sets TPMA_NV_WRITTEN (Part 3, clause
    //31.7). This slice models Index authorization (the authorization handle is the Index itself) and the
    //TPMA_NV_AUTHWRITE access check; the write is a pure state transition over the retained data area with no
    //crypto, so a successful write is a header-only response (as NV_UndefineSpace is).
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnNvWrite(TpmSimulatorState state, TpmNvWriteRequested request)
    {
        //The Index must exist (Part 3, clause 31.7).
        if(!state.NvIndexes.TryGetValue(request.NvIndex, out NvIndexState? index))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Write, TpmRcConstants.TPM_RC_HANDLE);
        }

        //Only Index authorization (authHandle == nvIndex) is modelled this slice; owner- and policy-authorized
        //writes against the same Index arrive later, mirroring TPM2_NV_Read().
        if(request.AuthHandle != request.NvIndex)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Write, TpmRcConstants.TPM_RC_AUTH_TYPE);
        }

        //Constant-time comparison of the supplied authorization against the Index authValue. A mismatch is an
        //auth-failure for a DA-protected Index (clause 17.8.3) and a plain bad-authorization for a non-DA Index
        //(clause 17.8.1), the same outcomes TPM2_NV_Read() turns on.
        if(!CryptographicOperations.FixedTimeEquals(request.AuthSupplied.Span, index.AuthValue.Span))
        {
            TpmRcConstants failureCode = index.IsDaProtected
                ? TpmRcConstants.TPM_RC_AUTH_FAIL
                : TpmRcConstants.TPM_RC_BAD_AUTH;

            return Reject(state, TpmCcConstants.TPM_CC_NV_Write, failureCode);
        }

        //The session authValue matched; with TPMA_NV_AUTHWRITE clear the Index authValue cannot authorize a
        //write (Part 2, clause 13.4), so the write is refused with TPM_RC_NV_AUTHORIZATION even though the value
        //matched (Part 3, clause 31.7 access checks).
        if(!index.IsAuthWriteAllowed)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Write, TpmRcConstants.TPM_RC_NV_AUTHORIZATION);
        }

        //The write must fit within the declared data area (Part 3, clause 31.7): offset + size must not exceed
        //the size established at TPM2_NV_DefineSpace().
        if((long)request.Offset + request.Data.Length > index.DataSize)
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_Write, TpmRcConstants.TPM_RC_NV_RANGE);
        }

        //Store the data into the retained data area at the offset (growing/patching it) and set TPMA_NV_WRITTEN.
        NvIndexState updated = index.WriteData(request.Offset, request.Data.Span);

        return Transition(
            state with
            {
                NvIndexes = state.NvIndexes.SetItem(request.NvIndex, updated),
                ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
            },
            "NvWrite");
    }

    //TPM2_NV_UndefineSpace() removes a defined NV Index and frees its handle (Part 3, clause 31.4). A
    //pure state transition: drop the Index from the table. An undefined handle is TPM_RC_HANDLE. Owner
    //authorization is modelled; the policy-delete variant (UndefineSpaceSpecial) is not.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnNvUndefineSpace(TpmSimulatorState state, TpmNvUndefineSpaceRequested request)
    {
        if(!state.NvIndexes.ContainsKey(request.NvIndex))
        {
            return Reject(state, TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmRcConstants.TPM_RC_HANDLE);
        }

        return Transition(
            state with
            {
                NvIndexes = state.NvIndexes.Remove(request.NvIndex),
                ResponseIntent = new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS)
            },
            "NvUndefineSpace");
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
        uint handle = state.NextObjectHandle;

        return Transition(
            state with
            {
                NextObjectHandle = state.NextObjectHandle + 1,
                NextAction = new TpmCreateEccKeyAction(handle, request.Hierarchy, request.NameAlg, request.Attributes, request.Curve, request.SchemeHashAlg),
                ResponseIntent = null
            },
            "CreatePrimary:Requested");
    }

    //The RSA counterpart of OnCreatePrimary: allocate the transient handle and declare a TpmCreateRsaKeyAction
    //so the effectful loop generates the RSA key, builds the exported public area carrying the modulus, and
    //feeds it back as the same TpmPrimaryKeyCreated input the ECC path uses.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnCreateRsaPrimary(TpmSimulatorState state, TpmCreateRsaPrimaryRequested request)
    {
        uint handle = state.NextObjectHandle;

        return Transition(
            state with
            {
                NextObjectHandle = state.NextObjectHandle + 1,
                NextAction = new TpmCreateRsaKeyAction(handle, request.Hierarchy, request.NameAlg, request.Attributes, request.KeyBits, request.Scheme),
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

    //TPM2_CreatePrimary() for an ECC storage parent needs an effect only for the faithful creation by-products:
    //the transition allocates the transient handle and declares a TpmCreateStorageParentAction carrying the storage
    //template fields. The effectful loop builds the exported storage public area and the durable parent state (no
    //key material — the simulator does not wrap children under a parent key, so the parent needs none) and feeds
    //them back as the same TpmPrimaryKeyCreated input the signing paths use.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnCreateStorageParent(TpmSimulatorState state, TpmCreateStorageParentRequested request)
    {
        uint handle = state.NextObjectHandle;

        return Transition(
            state with
            {
                NextObjectHandle = state.NextObjectHandle + 1,
                NextAction = new TpmCreateStorageParentAction(handle, request.Hierarchy, request.NameAlg, request.Attributes, request.Curve, request.NoDa),
                ResponseIntent = null
            },
            "CreatePrimary:Requested");
    }

    //TPM2_Create() seals caller-supplied data into a KEYEDHASH object under a loaded storage parent (Part 3,
    //clause 12.1). The parent must be a loaded restricted storage object; a missing handle is TPM_RC_HANDLE and a
    //non-storage parent is TPM_RC_TYPE. The seal needs an effect (the wrapped blob and the faithful by-products),
    //so the transition declares a TpmSealDataAction and leaves no response yet; OnObjectSealed frames the result.
    //The created object is not loaded, so no transient handle is allocated here.
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

        return Transition(
            state with
            {
                NextAction = new TpmSealDataAction(request.ParentHandle, request.NameAlg, request.AuthPolicy, request.NoDa, request.SecretData),
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

        uint handle = state.NextObjectHandle;

        return Transition(
            state with
            {
                NextObjectHandle = state.NextObjectHandle + 1,
                NextAction = new TpmLoadObjectAction(handle, request.NameAlg, request.AuthPolicy, request.PublicAreaBytes, request.PrivateBlob),
                ResponseIntent = null
            },
            "Load:Requested");
    }

    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnObjectLoaded(TpmSimulatorState state, TpmObjectLoaded loadedObject) =>
        Transition(
            state with
            {
                NextAction = NullAction.Instance,
                LoadedSealedObjects = state.LoadedSealedObjects.SetItem(loadedObject.Handle, new SealedObjectState(loadedObject.Handle, loadedObject.Data, loadedObject.AuthPolicy)),
                ResponseIntent = new TpmLoadResponse(TpmRcConstants.TPM_RC_SUCCESS, loadedObject.Handle, loadedObject.Name, loadedObject.NameLength)
            },
            "Load:Completed");

    //TPM2_Unseal() returns the data sealed in a loaded KEYEDHASH object (Part 3, clause 12.7). This is the plain
    //form authorized by a single password session: look up the loaded sealed object and frame its data. An unloaded
    //handle is TPM_RC_HANDLE. The object's authValue (empty for the seals this form models) is not checked, and
    //outData is returned in the clear; the policy-gated, encrypted-channel form is OnUnsealOverSessions.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnUnseal(TpmSimulatorState state, TpmUnsealRequested request)
    {
        if(!state.LoadedSealedObjects.TryGetValue(request.ItemHandle, out SealedObjectState? sealedObject))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Unseal, TpmRcConstants.TPM_RC_HANDLE);
        }

        return Transition(
            state with { ResponseIntent = new TpmUnsealResponse(TpmRcConstants.TPM_RC_SUCCESS, sealedObject.Data) },
            "Unseal");
    }

    //TPM2_Unseal() authorized by a policy session, with outData protected over a second bound HMAC (encrypt)
    //session (Part 3, clause 12.7; Part 1, clauses 18.7 and 19). The item must be loaded (TPM_RC_HANDLE otherwise),
    //and both sessions must resolve (an unknown session handle is TPM_RC_HANDLE). The policy gate: an object with a
    //non-empty authPolicy is authorized only when the policy session's accumulated policyDigest reproduces it; a
    //mismatch is TPM_RC_POLICY_FAIL (the "wrong state => no access" half of PCR-gated sealing). Framing the encrypted
    //response needs the RNG and the digest/HMAC seams, so the transition declares a TpmUnsealDataAction and leaves no
    //response yet; OnUnsealedOverSessions frames the two-session result.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnUnsealOverSessions(TpmSimulatorState state, TpmUnsealOverSessionsRequested request)
    {
        if(!state.LoadedSealedObjects.TryGetValue(request.ItemHandle, out SealedObjectState? sealedObject))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Unseal, TpmRcConstants.TPM_RC_HANDLE);
        }

        if(!state.PolicySessions.TryGetValue(request.PolicySession, out PolicySessionState? policySession))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Unseal, TpmRcConstants.TPM_RC_HANDLE);
        }

        //The encrypt session is optional: a two-session unseal pairs the policy session with a bound HMAC (encrypt)
        //session that protects outData; a lone policy session (EncryptSession == 0) recovers outData in the clear.
        //Resolve it before the gate so a bad session handle is TPM_RC_HANDLE regardless of the gate outcome.
        HmacSessionState? encryptSession = null;
        if(request.EncryptSession != 0 && !state.HmacSessions.TryGetValue(request.EncryptSession, out encryptSession))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Unseal, TpmRcConstants.TPM_RC_HANDLE);
        }

        //A trial policy session (Part 1, clause 19.3) accumulates a policyDigest for prediction but authorizes
        //nothing; folding a caller-chosen pcrDigest into a trial session (the trial PolicyPCR takes the caller's
        //digest verbatim) would otherwise reproduce any authPolicy byte-for-byte, so a trial session presented to
        //authorize the unseal is rejected before the object's authPolicy is consulted.
        if(policySession.IsTrial)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Unseal, TpmRcConstants.TPM_RC_POLICY_FAIL);
        }

        //Policy gate (Part 3, clause 12.7; Part 1, clause 19.7): an object with a non-empty authPolicy is authorized
        //only when the authorizing policy session's accumulated policyDigest equals that authPolicy. On mismatch the
        //TPM answers TPM_RC_POLICY_FAIL. That is a format-one code a real TPM annotates with the offending session
        //(TPM_RC_S | the session number in TPM_RC_N_MASK, Part 2, clause 6.6.3); the simulator returns the base code
        //bare, mirroring how it returns the other format-one codes (TPM_RC_HANDLE / TPM_RC_TYPE / TPM_RC_VALUE)
        //without the parameter/handle/session modifier. An empty authPolicy leaves the object outside the policy path.
        if(!sealedObject.AuthPolicy.IsEmpty
            && !sealedObject.AuthPolicy.Span.SequenceEqual(policySession.PolicyDigest.Span))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Unseal, TpmRcConstants.TPM_RC_POLICY_FAIL);
        }

        //Gate passed with no encrypt session: return the recovered secret in the clear, exactly as the plain form
        //does (the executor does not verify a keyless policy session's response auth, so a no-sessions response is
        //accepted). The confidentiality-protected two-session form runs the effect below.
        if(encryptSession is null)
        {
            return Transition(
                state with { ResponseIntent = new TpmUnsealResponse(TpmRcConstants.TPM_RC_SUCCESS, sealedObject.Data) },
                "Unseal:PolicyAuthorized");
        }

        return Transition(
            state with
            {
                NextAction = new TpmUnsealDataAction(
                    sealedObject.Data,
                    encryptSession.Handle,
                    encryptSession.SessionAlg,
                    encryptSession.Symmetric,
                    encryptSession.SessionKey,
                    request.EncryptNonceCaller,
                    request.EncryptAttributes,
                    policySession.PolicyHash,
                    request.PolicyAttributes),
                ResponseIntent = null
            },
            "Unseal:EncryptedRequested");
    }

    //Rolls the encrypt session's nonceTPM to the freshly generated value and frames the policy-gated two-session
    //TPM2_Unseal() response (the encrypted outData and the response session area the effect assembled). The session
    //record is replaced wholesale because its nonceTPM is immutable model state, replaced once per command (Part 1,
    //clause 17.6.7); the policy session carries no per-command state to roll.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnUnsealedOverSessions(TpmSimulatorState state, TpmUnsealedOverSessions produced)
    {
        //The encrypt session is present under normal flow (the request resolved it before declaring the action); if
        //it was flushed meanwhile the produced buffers are still released by SerializeResponse, so frame the response
        //regardless and update the table only when the session still exists.
        ImmutableDictionary<uint, HmacSessionState> sessions = state.HmacSessions;
        if(sessions.TryGetValue(produced.EncryptSessionHandle, out HmacSessionState? session))
        {
            sessions = sessions.SetItem(produced.EncryptSessionHandle, session with { NonceTpm = produced.NewNonceTpm });
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
                    produced.PolicyNonceLength,
                    produced.PolicyAttributes,
                    produced.NewNonceTpm,
                    produced.EncryptAttributes,
                    produced.Hmac,
                    produced.HmacLength)
            },
            "Unseal:EncryptedCompleted");
    }

    //TPM2_Certify() has a signing key attest that another loaded object's Name is present in the same TPM, over a
    //caller nonce (Part 3, clause 18.2). Both handles must resolve to loaded transient objects; a missing one is
    //TPM_RC_HANDLE. This slice signs with an ECC attestation key, so a non-ECC signer is TPM_RC_SCHEME (the ECDSA
    //scheme is incompatible with the key). The attestation needs an effect (marshal and sign), so the transition
    //resolves both objects, folds their retained fields into a TpmCertifyAction, and leaves no response yet;
    //OnObjectCertified frames the result. No handle is allocated — TPM2_Certify() returns no object handle.
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

        if(signer.KeyType != TpmAlgIdConstants.TPM_ALG_ECC)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Certify, TpmRcConstants.TPM_RC_SCHEME);
        }

        return Transition(
            state with
            {
                NextAction = new TpmCertifyAction(
                    subject.Name, signer.Name, request.QualifyingData, signer.PrivateKey, signer.Curve, request.SignatureScheme, request.SchemeHashAlg),
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

    //TPM2_MakeCredential() wraps a credential secret to a credential key's public area, bound to an object's Name
    //(Part 3, clause 12.6; the credential protection scheme is Part 1, clause 24). The credential key (the
    //endorsement key) must be a loaded restricted-decrypt ECC key carrying an exported point; a missing handle is
    //TPM_RC_HANDLE and a wrong key type is TPM_RC_TYPE. The seed exchange, KDFa/KDFe derivations, symmetric
    //encryption, and outer HMAC all need the ECC backend and the registered digest/HMAC seams, so the transition
    //folds the credential key's public point and curve into a TpmMakeCredentialAction and leaves no response yet;
    //OnCredentialMade frames the result. MakeCredential takes no authorization, so no session is consulted.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnMakeCredential(TpmSimulatorState state, TpmMakeCredentialRequested request)
    {
        if(!state.TransientObjects.TryGetValue(request.KeyHandle, out TransientKeyState? key))
        {
            return Reject(state, TpmCcConstants.TPM_CC_MakeCredential, TpmRcConstants.TPM_RC_HANDLE);
        }

        //The credential key transports the seed as a restricted-decrypt (storage) ECC key (Part 1, clause 24): a
        //non-ECC or non-storage key, or one carrying no exported point, cannot protect the credential (TPM_RC_TYPE).
        if(key.KeyType != TpmAlgIdConstants.TPM_ALG_ECC || !IsStorageParent(key.Attributes) || key.PublicPoint.IsEmpty)
        {
            return Reject(state, TpmCcConstants.TPM_CC_MakeCredential, TpmRcConstants.TPM_RC_TYPE);
        }

        return Transition(
            state with
            {
                NextAction = new TpmMakeCredentialAction(
                    request.Credential, request.ObjectName, key.PublicPoint, key.Curve, TpmAlgIdConstants.TPM_ALG_SHA256),
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
    //to loaded objects (a missing one is TPM_RC_HANDLE); the credential key must be a restricted-decrypt ECC key
    //carrying both its private scalar and its exported point (else TPM_RC_TYPE). The seed recovery and integrity
    //check need the ECC backend and the digest/HMAC seams, so the transition folds the activate object's Name and
    //the credential key's scalar/point/curve into a TpmActivateCredentialAction and leaves no response yet;
    //OnCredentialActivated frames the recovered secret or the integrity-failure rejection. The two handles are
    //password-authorized (empty auth), so the supplied authorization values are consumed but not retained.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnActivateCredential(TpmSimulatorState state, TpmActivateCredentialRequested request)
    {
        if(!state.TransientObjects.TryGetValue(request.ActivateHandle, out TransientKeyState? activateObject))
        {
            return Reject(state, TpmCcConstants.TPM_CC_ActivateCredential, TpmRcConstants.TPM_RC_HANDLE);
        }

        if(!state.TransientObjects.TryGetValue(request.KeyHandle, out TransientKeyState? key))
        {
            return Reject(state, TpmCcConstants.TPM_CC_ActivateCredential, TpmRcConstants.TPM_RC_HANDLE);
        }

        if(key.KeyType != TpmAlgIdConstants.TPM_ALG_ECC || !IsStorageParent(key.Attributes) || key.PublicPoint.IsEmpty || key.PrivateKey.IsEmpty)
        {
            return Reject(state, TpmCcConstants.TPM_CC_ActivateCredential, TpmRcConstants.TPM_RC_TYPE);
        }

        return Transition(
            state with
            {
                NextAction = new TpmActivateCredentialAction(
                    request.CredentialBlob, request.Secret, activateObject.Name, key.PrivateKey, key.PublicPoint, key.Curve, TpmAlgIdConstants.TPM_ALG_SHA256),
                ResponseIntent = null
            },
            "ActivateCredential:Requested");
    }

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
    //TPM_RC_HANDLE. This slice signs with an ECC signing key, so a non-ECC signer is TPM_RC_SCHEME (the ECDSA
    //scheme is incompatible with the key). The attestation needs an effect (compute the composite, marshal, and
    //sign), so the transition resolves the signer, gathers the selected PCR values from the durable bank, folds
    //them into a TpmQuoteAction, and leaves no response yet; OnObjectQuoted frames the result. No handle is
    //allocated — TPM2_Quote() returns no object handle.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnQuote(TpmSimulatorState state, TpmQuoteRequested request)
    {
        if(!state.TransientObjects.TryGetValue(request.SignHandle, out TransientKeyState? signer))
        {
            return Reject(state, TpmCcConstants.TPM_CC_Quote, TpmRcConstants.TPM_RC_HANDLE);
        }

        if(signer.KeyType != TpmAlgIdConstants.TPM_ALG_ECC)
        {
            return Reject(state, TpmCcConstants.TPM_CC_Quote, TpmRcConstants.TPM_RC_SCHEME);
        }

        ImmutableArray<ReadOnlyMemory<byte>> pcrValues = GatherSelectedPcrValues(state.Sha256PcrBank, request.PcrSelection);

        return Transition(
            state with
            {
                NextAction = new TpmQuoteAction(
                    signer.Name, request.QualifyingData, signer.PrivateKey, signer.Curve, request.SignatureScheme, request.SchemeHashAlg, request.PcrSelection, pcrValues),
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

    //TPM2_StartAuthSession() starts a policy or trial session (Part 3, clause 11.1). A pure, state-derived
    //response: allocate a session handle in the TPM_HT_POLICY_SESSION range, record the policy hash and the trial
    //flag, and seed the policyDigest to all-zeros of the hash width — the value from which every assertion extends.
    //The tests start unbound, unsalted sessions (tpmKey and bind both TPM_RH_NULL, TPM_ALG_NULL symmetric), so no
    //salt/bind material is modelled. The returned nonceTPM is framed by the serializer.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnStartAuthSession(TpmSimulatorState state, TpmStartAuthSessionRequested request)
    {
        //Only the digest sizes the policy formula supports are modelled; an unsupported authHash is TPM_RC_HASH.
        if(!IsSupportedPolicyHash(request.AuthHash))
        {
            return Reject(state, TpmCcConstants.TPM_CC_StartAuthSession, TpmRcConstants.TPM_RC_HASH);
        }

        uint handle = state.NextSessionHandle;
        int size = TpmPolicyDigest.Size(request.AuthHash);
        bool isTrial = request.SessionType == TpmSeConstants.TPM_SE_TRIAL;
        var session = new PolicySessionState(handle, request.AuthHash, isTrial, new byte[size]);

        return Transition(
            state with
            {
                NextSessionHandle = state.NextSessionHandle + 1,
                PolicySessions = state.PolicySessions.SetItem(handle, session),
                ResponseIntent = new TpmStartAuthSessionResponse(TpmRcConstants.TPM_RC_SUCCESS, handle, size)
            },
            "StartAuthSession");
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

    //TPM2_PolicyNV() binds a policy to a comparison against an NV Index's contents (Part 3, clause 23.9). The
    //Index must be defined; an unknown Index or session handle is TPM_RC_HANDLE. On a trial session no live NV data
    //comparison is performed — only the Index Name and the arguments drive the digest. See the note on
    //OnPolicyCommandCode.
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

        byte[] nvName = ComputeNvName(index);
        byte[] updated = new byte[TpmPolicyDigest.Size(session.PolicyHash)];
        _ = TpmPolicyDigest.ExtendForNv(session.PolicyDigest.Span, request.OperandB.Span, request.Offset, request.Operation, nvName, session.PolicyHash, updated);

        return StorePolicyDigest(state, session, updated, new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_SUCCESS), "PolicyNV");
    }

    //TPM2_FlushContext() removes a loaded policy session or transient object from TPM memory (Part 3, clause 28.4).
    //A pure state transition: drop the handle from whichever table holds it. An unknown handle is TPM_RC_HANDLE.
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

        return Reject(state, TpmCcConstants.TPM_CC_FlushContext, TpmRcConstants.TPM_RC_HANDLE);
    }

    //TPM2_StartAuthSession() for a bound HMAC session with parameter encryption (Part 3, clause 11.1; Part 1,
    //clauses 17.6 and 19). The session key derivation and nonceTPM generation need the RNG and the HMAC seam, so
    //this allocates a handle in the TPM_HT_HMAC_SESSION range and declares a TpmStartHmacSessionAction; the
    //effectful loop derives the key and feeds it back as a TpmHmacSessionStarted input (OnHmacSessionStarted).
    //
    //DESIGN: the session key is KDFa(authHash, bindAuthValue, "ATH", nonceTPM, nonceCaller, bits) — the SAME
    //derivation the host TpmSession performs, computed here through the SAME registered HMAC seam, so the two keys
    //agree by construction. This slice models bind entities whose authorization value is empty (the objects it
    //creates carry empty auth), so bindAuthValue is empty; the bind handle is still resolved so an unknown entity
    //is rejected as a real TPM would (TPM_RC_HANDLE). An unsupported hash is TPM_RC_HASH; a symmetric definition
    //this slice cannot key parameter encryption with is TPM_RC_SYMMETRIC.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnStartHmacSession(TpmSimulatorState state, TpmStartHmacSessionRequested request)
    {
        if(!IsSupportedPolicyHash(request.AuthHash))
        {
            return Reject(state, TpmCcConstants.TPM_CC_StartAuthSession, TpmRcConstants.TPM_RC_HASH);
        }

        //Only the parameter-encryption schemes the response path implements are accepted: XOR obfuscation
        //(mandatory) and AES-CFB (platform specific), plus a null definition (Part 1, clause 19; Part 2, clause
        //11.1.6). Any other negotiated symmetric algorithm is TPM_RC_SYMMETRIC.
        bool symmetricSupported =
            request.Symmetric.IsNull
            || request.Symmetric.IsXor
            || (request.Symmetric.Algorithm == TpmAlgIdConstants.TPM_ALG_AES && request.Symmetric.Mode == TpmAlgIdConstants.TPM_ALG_CFB);
        if(!symmetricSupported)
        {
            return Reject(state, TpmCcConstants.TPM_CC_StartAuthSession, TpmRcConstants.TPM_RC_SYMMETRIC);
        }

        //Resolve the bind entity so an unknown one is rejected. A permanent handle (most-significant octet
        //TPM_HT_PERMANENT) carries an empty auth in this slice, as do the transient/persistent objects it creates,
        //so the bind authorization value is empty either way (Part 1, clause 17.6.10).
        if(request.Bind != (uint)TpmRh.TPM_RH_NULL
            && !IsPermanentHandle(request.Bind)
            && !state.TransientObjects.ContainsKey(request.Bind)
            && !state.PersistentObjects.ContainsKey(request.Bind))
        {
            return Reject(state, TpmCcConstants.TPM_CC_StartAuthSession, TpmRcConstants.TPM_RC_HANDLE);
        }

        uint handle = state.NextHmacSessionHandle;

        return Transition(
            state with
            {
                NextHmacSessionHandle = state.NextHmacSessionHandle + 1,
                NextAction = new TpmStartHmacSessionAction(handle, request.AuthHash, request.Symmetric, request.NonceCaller, ReadOnlyMemory<byte>.Empty),
                ResponseIntent = null
            },
            "StartAuthSession:HmacRequested");
    }

    //Records a started bound HMAC session and frames the TPM2_StartAuthSession() response with the real nonceTPM
    //(the value the session-key KDFa consumed, which the host must receive verbatim to derive the same key). The
    //session key and nonce become durable model state, exactly as a transient key's private scalar does.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnHmacSessionStarted(TpmSimulatorState state, TpmHmacSessionStarted started)
    {
        var session = new HmacSessionState(started.SessionHandle, started.SessionAlg, started.Symmetric, started.SessionKey, started.NonceTpm);

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
    //18.7 and 19). The random draw, nonce roll, parameter encryption, rpHash, and response HMAC all need the RNG
    //and the registered digest/HMAC seams, so this resolves the session and declares a TpmEncryptRandomAction; the
    //effectful loop frames the encrypted response and feeds it back as a TpmEncryptedRandomProduced input
    //(OnEncryptedRandomProduced). An unknown session handle is TPM_RC_HANDLE.
    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> OnGetRandomOverSession(TpmSimulatorState state, TpmGetRandomOverSessionRequested request)
    {
        if(!state.HmacSessions.TryGetValue(request.SessionHandle, out HmacSessionState? session))
        {
            return Reject(state, TpmCcConstants.TPM_CC_GetRandom, TpmRcConstants.TPM_RC_HANDLE);
        }

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

    //Computes an NV Index Name (nameAlg || H_nameAlg(TPMS_NV_PUBLIC)) from the simulator's NV Index state (TPM 2.0
    //Library Part 1, clause 16). The hash is taken through the registered digest seam (never a direct framework
    //hash), as the object-Name computation is. The simulator models SHA-256 as its universal Name algorithm and the
    //modelled Indexes carry an empty authPolicy, so the marshaled TPMS_NV_PUBLIC reproduces the host prediction
    //exactly. Synchronous, with its scratch buffer pooled and released before returning.
    private static byte[] ComputeNvName(NvIndexState index)
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        const int nameAlgSize = 32;                 //SHA-256 digest width — the sim's universal Name algorithm.

        using var nvPublic = new TpmsNvPublic(index.NvIndex, TpmAlgIdConstants.TPM_ALG_SHA256, index.Attributes, Tpm2bDigest.Empty, index.DataSize);
        int publicSize = nvPublic.SerializedSize;
        using IMemoryOwner<byte> owner = pool.Rent(publicSize);
        Span<byte> publicArea = owner.Memory.Span[..publicSize];
        var writer = new TpmWriter(publicArea);
        nvPublic.WriteTo(ref writer);

        using DigestValue digest = CryptographicKeyEvents.ComputeDigest(
            owner.Memory.Span[..publicSize], nameAlgSize, CryptoTags.Sha256Digest, pool);

        byte[] name = new byte[sizeof(ushort) + nameAlgSize];
        BinaryPrimitives.WriteUInt16BigEndian(name, (ushort)TpmAlgIdConstants.TPM_ALG_SHA256);
        digest.AsReadOnlySpan().CopyTo(name.AsSpan(sizeof(ushort)));

        return name;
    }

    //The policy hash algorithms the enhanced-authorization digest formula actually computes (TpmPolicyDigest.Hash).
    //SHA-1 is intentionally excluded: advertising it here while the fold cannot compute it left a session that
    //faulted on its first assertion, so StartAuthSession now rejects it up front with TPM_RC_HASH.
    private static bool IsSupportedPolicyHash(TpmAlgIdConstants hash) =>
        hash is TpmAlgIdConstants.TPM_ALG_SHA256
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
            TpmEvictControlRequested => TpmCcConstants.TPM_CC_EvictControl,
            TpmCreatePrimaryRequested => TpmCcConstants.TPM_CC_CreatePrimary,
            TpmCreateRsaPrimaryRequested => TpmCcConstants.TPM_CC_CreatePrimary,
            TpmCreateStorageParentRequested => TpmCcConstants.TPM_CC_CreatePrimary,
            TpmSignRequested => TpmCcConstants.TPM_CC_Sign,
            TpmCreateSealedObjectRequested => TpmCcConstants.TPM_CC_Create,
            TpmLoadObjectRequested => TpmCcConstants.TPM_CC_Load,
            TpmUnsealRequested => TpmCcConstants.TPM_CC_Unseal,
            TpmUnsealOverSessionsRequested => TpmCcConstants.TPM_CC_Unseal,
            TpmCertifyRequested => TpmCcConstants.TPM_CC_Certify,
            TpmPcrReadRequested => TpmCcConstants.TPM_CC_PCR_Read,
            TpmQuoteRequested => TpmCcConstants.TPM_CC_Quote,
            TpmStartAuthSessionRequested => TpmCcConstants.TPM_CC_StartAuthSession,
            TpmStartHmacSessionRequested => TpmCcConstants.TPM_CC_StartAuthSession,
            TpmGetRandomOverSessionRequested => TpmCcConstants.TPM_CC_GetRandom,
            TpmPolicyCommandCodeRequested => TpmCcConstants.TPM_CC_PolicyCommandCode,
            TpmPolicyAuthValueRequested => TpmCcConstants.TPM_CC_PolicyAuthValue,
            TpmPolicyGetDigestRequested => TpmCcConstants.TPM_CC_PolicyGetDigest,
            TpmPolicyPcrRequested => TpmCcConstants.TPM_CC_PolicyPCR,
            TpmPolicyOrRequested => TpmCcConstants.TPM_CC_PolicyOR,
            TpmPolicySecretRequested => TpmCcConstants.TPM_CC_PolicySecret,
            TpmPolicyNvRequested => TpmCcConstants.TPM_CC_PolicyNV,
            TpmMakeCredentialRequested => TpmCcConstants.TPM_CC_MakeCredential,
            TpmActivateCredentialRequested => TpmCcConstants.TPM_CC_ActivateCredential,
            TpmFlushContextRequested => TpmCcConstants.TPM_CC_FlushContext,
            TpmUnsupportedCommandReceived unsupported => unsupported.CommandCode,
            _ => throw new System.InvalidOperationException($"Input '{input.GetType().Name}' is not a command and must not reach command dispatch.")
        };

    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> Reject(TpmSimulatorState state, TpmCcConstants commandCode, TpmRcConstants responseCode) =>
        Transition(
            state with { ResponseIntent = new TpmHeaderOnlyResponse(responseCode) },
            $"Reject:{commandCode}");

    private static TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol> Transition(TpmSimulatorState nextState, string label) =>
        new(nextState, StackAction<TpmSimulatorStackSymbol>.None, label);
}
