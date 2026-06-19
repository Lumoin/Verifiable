using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Foundation.Automata;
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
            //TpmRandomGenerated is the internal RNG fold-back: it must always be consumed into the
            //disposable TpmRandomResponse so the pooled buffer is never orphaned, so it is neither
            //cancellation-gated nor NextAction-reset here. Every externally-supplied input honours
            //cancellation and starts from a cleared NextAction, so an action left pending by an aborted
            //prior effect (e.g. an RNG backend that threw) cannot re-fire against a later command.
            TransitionResult<TpmSimulatorState, TpmSimulatorStackSymbol>? result;
            if(input is TpmRandomGenerated generated)
            {
                result = OnRandomGenerated(state, generated);
            }
            else
            {
                cancellationToken.ThrowIfCancellationRequested();

                TpmSimulatorState ready = state with { NextAction = NullAction.Instance };
                result = input switch
                {
                    TpmInitSignal => OnInit(ready),
                    _ => OnCommand(ready, input)
                };
            }

            return ValueTask.FromResult(result);
        };

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

        var index = new NvIndexState(request.NvIndex, request.IndexAuth, request.Attributes, request.DataSize);

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

        //Authorization succeeded. TPM2_NV_Write() — the only command that sets TPMA_NV_WRITTEN — is not
        //modelled this slice, so every defined Index is still uninitialized and a read returns
        //TPM_RC_NV_UNINITIALIZED (Part 3, clause 31.13). The data-returning response lands with NV_Write.
        return Reject(state, TpmCcConstants.TPM_CC_NV_Read, TpmRcConstants.TPM_RC_NV_UNINITIALIZED);
    }

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
