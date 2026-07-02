using System;
using System.Collections.Immutable;
using Verifiable.Foundation.Automata;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// The complete state of the TPM simulator's pushdown automaton: the lifecycle phase plus the
/// persistent characteristics and results that command admissibility and responses depend on.
/// </summary>
/// <remarks>
/// <para>
/// This is the single "fat" operational record carried by one <c>PushdownAutomaton</c> per simulated
/// TPM (design decision D2: one automaton, one run identifier, one trace stream). The lifecycle
/// skeleton keeps persistent and volatile data flat; the persistent/volatile partition (NV blobs,
/// sessions, transient objects) is introduced when those features are modelled.
/// </para>
/// <para>
/// <see cref="NextAction"/> carries the effectful work the runner must perform before the next input,
/// following the PDA action convention; the lifecycle commands need no effects, so it is
/// <see cref="NullAction.Instance"/> throughout this skeleton. <see cref="ResponseIntent"/> carries the
/// logical response produced by the command that was just processed.
/// </para>
/// </remarks>
/// <param name="TpmId">The stable identifier of this simulated TPM; also the automaton's run identifier.</param>
/// <param name="Phase">The current lifecycle phase.</param>
/// <param name="ConfiguredSelfTest">
/// The modelled self-test behaviour of this TPM (a fixed hardware characteristic), used to decide the
/// outcome of <c>TPM2_SelfTest()</c>.
/// </param>
/// <param name="SelfTest">The self-test outcome since the last <c>_TPM_Init</c>.</param>
/// <param name="LastOrderlyShutdown">
/// The startup type recorded by the most recent <c>TPM2_Shutdown()</c>, or <see langword="null"/> when
/// no orderly Shutdown(STATE) is pending — either none was recorded or a startup has consumed it.
/// Determines whether a subsequent <c>Startup(STATE)</c> can resume (TPM 2.0 Library Part 1, clause
/// 10.2.3.2). A disorderly power loss is not modelled in this skeleton: power-on is always the orderly
/// <c>_TPM_Init</c>, which preserves a recorded shutdown until a startup consumes it.
/// </param>
/// <param name="FailedTries">
/// The dictionary-attack failure counter (<c>failedTries</c>, reported as <c>TPM_PT_LOCKOUT_COUNTER</c>):
/// incremented on each <c>TPM_RC_AUTH_FAIL</c>, reset by <c>TPM2_DictionaryAttackLockReset()</c>
/// (TPM 2.0 Library Part 1, clause 17.8).
/// </param>
/// <param name="MaxTries">
/// The number of authorization failures tolerated before lockout engages (<c>maxTries</c>, reported as
/// <c>TPM_PT_MAX_AUTH_FAIL</c>). The TPM is in Lockout mode once <see cref="FailedTries"/> reaches this
/// value (clause 17.8.3 states <c>failedTries == maxTries</c>; see <see cref="IsInLockout"/> for the
/// defensive <c>&gt;=</c> comparison).
/// </param>
/// <param name="RecoveryTime">
/// The seconds between automatic decrements of <see cref="FailedTries"/> (<c>recoveryTime</c>, reported
/// as <c>TPM_PT_LOCKOUT_INTERVAL</c>).
/// </param>
/// <param name="LockoutRecovery">
/// The seconds to wait after a failed <c>lockoutAuth</c> use before it may be retried
/// (<c>lockoutRecovery</c>, reported as <c>TPM_PT_LOCKOUT_RECOVERY</c>).
/// </param>
/// <param name="NvIndexes">
/// The defined NV Indexes, keyed by handle. Populated by <c>TPM2_NV_DefineSpace()</c> and consulted by
/// <c>TPM2_NV_Read()</c>; the dictionary-attack/PIN flow drives authorization failures through a
/// DA-protected NV Index (TPM 2.0 Library Part 1, clause 17.8.1).
/// </param>
/// <param name="OwnerAuth">
/// The owner-hierarchy authorization value. Owner authorization is not dictionary-attack protected
/// (clause 17.8.1), so a wrong owner authValue is a plain bad-authorization, never a counter-feeding
/// auth-failure. Empty by default; <c>TPM2_HierarchyChangeAuth()</c> (a later slice) sets it.
/// </param>
/// <param name="TransientObjects">
/// The loaded transient objects, keyed by handle. Populated by <c>TPM2_CreatePrimary()</c> and consulted by
/// <c>TPM2_Sign()</c>; the object/signing path the create-then-sign slice exercises (TPM 2.0 Library Part 3,
/// clauses 24.1 and 20.2).
/// </param>
/// <param name="PersistentObjects">
/// The persistent objects, keyed by their persistent handle (<c>TPM_HT_PERSISTENT</c>, MSO <c>0x81</c>).
/// <c>TPM2_EvictControl()</c> persists a transient object here (a copy, the transient stays loaded) and evicts
/// one from here; this is the object-persistence half of a provisioning flow (TPM 2.0 Library Part 3, clause 28.5).
/// </param>
/// <param name="LoadedSealedObjects">
/// The loaded sealed data objects, keyed by transient handle. Populated by <c>TPM2_Load()</c> of a wrapped
/// KEYEDHASH object and consulted by <c>TPM2_Unseal()</c>; the seal-then-unseal path the create/load/unseal
/// slice exercises (TPM 2.0 Library Part 3, clauses 12.1, 12.2, and 12.7).
/// </param>
/// <param name="Sha256PcrBank">
/// The SHA-256 Platform Configuration Register bank. Read by <c>TPM2_PCR_Read()</c> and hashed into the
/// composite digest <c>TPM2_Quote()</c> signs (TPM 2.0 Library Part 1, clause 17.1). Initialized to its reset
/// image at power-on; this slice models no <c>TPM2_PCR_Extend()</c>, so the registers stay at their reset value.
/// </param>
/// <param name="PolicySessions">
/// The started policy (enhanced authorization) sessions, keyed by session handle. Populated by
/// <c>TPM2_StartAuthSession()</c>, driven by the <c>TPM2_Policy*()</c> command family (each advancing the
/// session's policyDigest), read by <c>TPM2_PolicyGetDigest()</c>, and released by <c>TPM2_FlushContext()</c>
/// (TPM 2.0 Library Part 1, clause 19.7).
/// </param>
/// <param name="NextObjectHandle">
/// The handle the next created transient object receives, advanced on each <c>TPM2_CreatePrimary()</c>. Starts
/// at <see cref="TransientHandleBase"/> (the base of the <c>TPM_HT_TRANSIENT</c> range, TPM 2.0 Library Part 2,
/// clause 7.2).
/// </param>
/// <param name="NextSessionHandle">
/// The handle the next started policy session receives, advanced on each <c>TPM2_StartAuthSession()</c>. Starts
/// at <see cref="PolicySessionHandleBase"/> (the base of the <c>TPM_HT_POLICY_SESSION</c> range, TPM 2.0 Library
/// Part 2, clause 7.2), disjoint from the transient-object range so a session handle never collides with an object.
/// </param>
/// <param name="HmacSessions">
/// The started bound HMAC sessions with parameter encryption, keyed by session handle. Populated by
/// <c>TPM2_StartAuthSession()</c> for an HMAC session, driven by encrypt-attributed commands (each rolling the
/// session's nonceTPM), and released by <c>TPM2_FlushContext()</c> (TPM 2.0 Library Part 1, clauses 17.6 and 19).
/// </param>
/// <param name="NextHmacSessionHandle">
/// The handle the next started HMAC session receives, advanced on each HMAC <c>TPM2_StartAuthSession()</c>. Starts
/// at <see cref="HmacSessionHandleBase"/> (the base of the <c>TPM_HT_HMAC_SESSION</c> range, TPM 2.0 Library Part
/// 2, clause 7.2), disjoint from the policy-session and transient-object ranges.
/// </param>
/// <param name="NextAction">The effectful action the runner must execute next; <see cref="NullAction.Instance"/> when none.</param>
/// <param name="ResponseIntent">The logical response produced by the last command, or <see langword="null"/> when none (e.g. after <c>_TPM_Init</c>).</param>
public sealed record TpmSimulatorState(
    string TpmId,
    TpmLifecyclePhase Phase,
    TpmSelfTestBehavior ConfiguredSelfTest,
    TpmSelfTestStatus SelfTest,
    TpmSuConstants? LastOrderlyShutdown,
    uint FailedTries,
    uint MaxTries,
    uint RecoveryTime,
    uint LockoutRecovery,
    ImmutableDictionary<uint, NvIndexState> NvIndexes,
    ReadOnlyMemory<byte> OwnerAuth,
    ImmutableDictionary<uint, TransientKeyState> TransientObjects,
    ImmutableDictionary<uint, TransientKeyState> PersistentObjects,
    ImmutableDictionary<uint, SealedObjectState> LoadedSealedObjects,
    PcrBankState Sha256PcrBank,
    ImmutableDictionary<uint, PolicySessionState> PolicySessions,
    ImmutableDictionary<uint, HmacSessionState> HmacSessions,
    uint NextObjectHandle,
    uint NextSessionHandle,
    uint NextHmacSessionHandle,
    PdaAction NextAction,
    TpmResponseIntent? ResponseIntent)
{
    /// <summary>The default <see cref="MaxTries"/> for a freshly powered-off simulated TPM.</summary>
    public const uint DefaultMaxTries = 32;

    /// <summary>
    /// The base handle of the <c>TPM_HT_TRANSIENT</c> range (TPM 2.0 Library Part 2, clause 7.2): the handle the
    /// first created transient object receives.
    /// </summary>
    public const uint TransientHandleBase = 0x8000_0000;

    /// <summary>
    /// The base handle of the <c>TPM_HT_PERSISTENT</c> range (TPM 2.0 Library Part 2, clause 7.2): a persistent
    /// handle has the most-significant octet <c>0x81</c>. <c>TPM2_EvictControl()</c> assigns handles in this range.
    /// </summary>
    public const uint PersistentHandleBase = 0x8100_0000;

    /// <summary>
    /// The base handle of the <c>TPM_HT_POLICY_SESSION</c> range (TPM 2.0 Library Part 2, clause 7.2): a policy
    /// session handle has the most-significant octet <c>0x03</c>. <c>TPM2_StartAuthSession()</c> assigns handles in
    /// this range, disjoint from the <c>TPM_HT_TRANSIENT</c> object range (<see cref="TransientHandleBase"/>).
    /// </summary>
    public const uint PolicySessionHandleBase = 0x0300_0000;

    /// <summary>
    /// The base handle of the <c>TPM_HT_HMAC_SESSION</c> range (TPM 2.0 Library Part 2, clause 7.2): an HMAC
    /// session handle has the most-significant octet <c>0x02</c>. <c>TPM2_StartAuthSession()</c> assigns HMAC
    /// session handles in this range, disjoint from the policy-session (<see cref="PolicySessionHandleBase"/>) and
    /// transient-object (<see cref="TransientHandleBase"/>) ranges so a handle never collides across kinds.
    /// </summary>
    public const uint HmacSessionHandleBase = 0x0200_0000;

    /// <summary>The default <see cref="RecoveryTime"/> in seconds for a freshly powered-off simulated TPM.</summary>
    public const uint DefaultRecoveryTimeSeconds = 7200;

    /// <summary>The default <see cref="LockoutRecovery"/> in seconds for a freshly powered-off simulated TPM.</summary>
    public const uint DefaultLockoutRecoverySeconds = 86400;

    /// <summary>
    /// Gets a value indicating whether the TPM is in dictionary-attack Lockout mode, i.e. the failure
    /// counter has reached the tolerated maximum (TPM 2.0 Library Part 1, clause 17.8.3). The spec
    /// states <c>failedTries == maxTries</c>; this uses <c>&gt;=</c> defensively so an overshoot can
    /// never read as "out of lockout". Always <see langword="false"/> when <see cref="MaxTries"/> is
    /// zero (DA protection disabled).
    /// </summary>
    public bool IsInLockout => MaxTries > 0 && FailedTries >= MaxTries;

    /// <summary>
    /// Creates the initial state of a simulated TPM: powered off, awaiting <c>_TPM_Init</c>, with the
    /// default dictionary-attack parameters.
    /// </summary>
    /// <param name="tpmId">The stable identifier of this simulated TPM.</param>
    /// <param name="configuredSelfTest">The modelled self-test behaviour.</param>
    /// <returns>A powered-off state.</returns>
    public static TpmSimulatorState PoweredOff(string tpmId, TpmSelfTestBehavior configuredSelfTest) =>
        new(
            tpmId,
            TpmLifecyclePhase.PoweredOff,
            configuredSelfTest,
            TpmSelfTestStatus.NotRun,
            null,
            0u,
            DefaultMaxTries,
            DefaultRecoveryTimeSeconds,
            DefaultLockoutRecoverySeconds,
            ImmutableDictionary<uint, NvIndexState>.Empty,
            ReadOnlyMemory<byte>.Empty,
            ImmutableDictionary<uint, TransientKeyState>.Empty,
            ImmutableDictionary<uint, TransientKeyState>.Empty,
            ImmutableDictionary<uint, SealedObjectState>.Empty,
            PcrBankState.Sha256AtReset(),
            ImmutableDictionary<uint, PolicySessionState>.Empty,
            ImmutableDictionary<uint, HmacSessionState>.Empty,
            TransientHandleBase,
            PolicySessionHandleBase,
            HmacSessionHandleBase,
            NullAction.Instance,
            null);
}
