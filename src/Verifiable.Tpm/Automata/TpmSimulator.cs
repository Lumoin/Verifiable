using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Foundation.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// A behavioural TPM simulator built on a <see cref="PushdownAutomaton{TState, TInput, TStackSymbol}"/>.
/// Unlike <see cref="TpmVirtualDevice"/>, which replays recorded bytes, this models TPM behaviour and
/// computes responses from state, so command sequences that depend on lifecycle and per-command
/// preconditions behave correctly.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="SubmitAsync"/> has the <see cref="TpmSubmitHandler"/> shape, so the simulator plugs
/// straight into <see cref="TpmDevice.Create(TpmSubmitHandler, Action?)"/>:
/// </para>
/// <code>
/// var simulator = new TpmSimulator("tpm-under-test");
/// await simulator.PowerOnAsync();
/// using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
/// </code>
/// <para>
/// The device owns a single live automaton with one run identifier and one trace stream,
/// reachable via <see cref="Subscribe"/>. Commands are processed serially, as a
/// physical TPM does; the simulator is not safe for concurrent calls to <see cref="SubmitAsync"/>.
/// </para>
/// <para>
/// <strong>Scope.</strong> The simulator models the lifecycle commands <c>_TPM_Init</c>,
/// <c>TPM2_Startup()</c>, <c>TPM2_Shutdown()</c>, <c>TPM2_SelfTest()</c>, and
/// <c>TPM2_GetTestResult()</c>, plus <c>TPM2_GetRandom()</c>, which is the first command driven through
/// the fine-grained action layer: its transition declares a <see cref="TpmRngAction"/>, the effectful
/// loop draws octets from the injected RNG backend, and the transition frames the
/// <c>TPM2B_DIGEST</c> response. Its primary value is letting destructive and lockout state-machine
/// scenarios be exercised in software, never against real hardware.
/// </para>
/// <para>
/// <strong>Skeleton limitations.</strong> Failure Mode is reachable only via an explicit
/// <c>TPM2_SelfTest()</c> on a TPM configured to fail, not via init-time power-on self-test.
/// <c>TPM2_Shutdown()</c> records the orderly shutdown type and leaves the TPM operational until the
/// next <c>_TPM_Init</c>; the rule that a state-modifying command issued after Shutdown(STATE)
/// invalidates the saved state (Part 1, clause 10.2.4) is modelled when such commands are added.
/// A disorderly power loss is not modelled — power-on is always the orderly <c>_TPM_Init</c>.
/// </para>
/// </remarks>
/// <seealso cref="TpmVirtualDevice"/>
/// <seealso cref="TpmDevice"/>
public sealed class TpmSimulator: IObservable<TraceEntry<TpmSimulatorState, TpmSimulatorInput>>, IDisposable
{
    /// <summary>The live automaton holding this TPM's state of record.</summary>
    private PushdownAutomaton<TpmSimulatorState, TpmSimulatorInput, TpmSimulatorStackSymbol> Automaton { get; }

    /// <summary>Guards <see cref="Dispose"/>'s teardown walk so a second call is a safe no-op.</summary>
    private bool Disposed { get; set; }

    /// <summary>The time source threaded to the effectful runner for trace timestamps.</summary>
    private TimeProvider TimeProvider { get; }

    /// <summary>The TPM's RNG backend, drawn on for TPM2_GetRandom().</summary>
    private FillEntropyDelegate Rng { get; }

    /// <summary>
    /// The TPM's elliptic-curve signing backend, drawn on for TPM2_CreatePrimary() and TPM2_Sign() over an ECC
    /// key, or <see langword="null"/> when none was supplied.
    /// </summary>
    private TpmEccSigningBackend? SigningBackend { get; }

    /// <summary>
    /// The TPM's RSA signing backend, drawn on for TPM2_CreatePrimary() and TPM2_Sign() over an RSA key, or
    /// <see langword="null"/> when none was supplied. When both this and <see cref="SigningBackend"/> are
    /// <see langword="null"/>, the object/signing commands answer <c>TPM_RC_COMMAND_CODE</c>.
    /// </summary>
    private TpmRsaSigningBackend? RsaSigningBackend { get; }

    /// <summary>
    /// The per-TPM seed from which the platform hierarchy's proof derives — the simulator's stand-in for the
    /// Platform Primary Seed a real TPM fixes at manufacture and keeps in NV (TPM 2.0 Library Part 1, clause
    /// 12.5: "phProof changes when the PPS changes"). It is a construction-time constant because nothing this
    /// simulator models changes the PPS, which is exactly why a platform-hierarchy ticket outlives a
    /// <c>TPM2_Clear()</c>; the rotatable storage/endorsement counterpart is
    /// <see cref="TpmSimulatorState.StorageProofSeed"/>.
    /// </summary>
    private ReadOnlyMemory<byte> ProofSeed { get; }

    /// <summary>The counter backing the deterministic RNG default; advances once per drawn block.</summary>
    private ulong RngCounter { get; set; }

    /// <summary>
    /// Creates a simulator for a TPM that is powered off and awaiting <c>_TPM_Init</c>.
    /// </summary>
    /// <param name="tpmId">A stable identifier for this simulated TPM; also the automaton's run identifier.</param>
    /// <param name="selfTest">The modelled self-test behaviour, used to drive Failure Mode deterministically.</param>
    /// <param name="rng">
    /// The random-number backend used by <c>TPM2_GetRandom()</c>. The simulator models the device's RNG,
    /// not a real entropy source, so the default is a deterministic counter stream seeded per instance —
    /// reproducible for replay yet distinct across successive draws (so nonces and salts do not collide).
    /// Tests inject a fixed pattern or a platform CSPRNG via this delegate. The delegate must fill the
    /// entire destination span.
    /// </param>
    /// <param name="timeProvider">The time source for trace timestamps. Defaults to <see cref="TimeProvider.System"/>.</param>
    /// <param name="signingBackend">
    /// The elliptic-curve signing backend used by <c>TPM2_CreatePrimary()</c> and <c>TPM2_Sign()</c> over an
    /// ECC key. The simulator models a TPM's key generation and signing, not a concrete crypto provider, so
    /// this is supplied through a seam — as the RNG backend is — keeping this assembly provider-agnostic.
    /// </param>
    /// <param name="rsaSigningBackend">
    /// The RSA signing backend used by <c>TPM2_CreatePrimary()</c> and <c>TPM2_Sign()</c> over an RSA key,
    /// supplied through the same kind of seam. When both this and <paramref name="signingBackend"/> are
    /// <see langword="null"/> (the default), those commands answer <c>TPM_RC_COMMAND_CODE</c>, leaving the
    /// lifecycle, NV, and entropy surfaces usable without any asymmetric backend.
    /// </param>
    /// <param name="seed">
    /// The per-TPM secret from which the hierarchy creation-ticket proofs derive — the analog of the random
    /// hierarchy proof a real TPM fixes at manufacture and keeps in NV. Supply random bytes for genuine
    /// entropy, or a fixed value to make the creation tickets reproducible. When empty (the default), the seed
    /// defaults to the TPM identifier, keeping the default deterministic and reproducible. Copied on capture.
    /// </param>
    /// <param name="clockAdvanceQuantumMs">
    /// The fixed number of milliseconds <c>Clock</c> and <c>Time</c> advance for every admitted command — the
    /// simulator's stand-in for a real TPM's free-running Time oscillator (TPM 2.0 Library Part 1, clause
    /// 36.1), fixed at construction like <paramref name="selfTest"/>. Defaults to one millisecond per command.
    /// </param>
    public TpmSimulator(
        string tpmId,
        TpmSelfTestBehavior selfTest = TpmSelfTestBehavior.Passes,
        FillEntropyDelegate? rng = null,
        TimeProvider? timeProvider = null,
        TpmEccSigningBackend? signingBackend = null,
        TpmRsaSigningBackend? rsaSigningBackend = null,
        ReadOnlyMemory<byte> seed = default,
        ulong clockAdvanceQuantumMs = TpmSimulatorState.DefaultClockAdvanceQuantumMs)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tpmId);

        TimeProvider = timeProvider ?? TimeProvider.System;
        Rng = rng ?? FillDeterministic;
        SigningBackend = signingBackend;
        RsaSigningBackend = rsaSigningBackend;
        ProofSeed = seed.IsEmpty ? Encoding.UTF8.GetBytes(tpmId) : seed.ToArray();

        //TimeEpoch's initial value is drawn from the same injected entropy seam as ProofSeed (random when the
        //caller supplies random seed bytes, reproducible when it does not), folded to a UINT32 here at
        //construction — never from Rng, which would perturb TPM2_GetRandom()'s deterministic counter stream
        //that existing byte-exact test assertions rely on, for a value that needs no such entropy source of
        //its own (see TimeEpoch's doc comment on TpmSimulatorState). Every later regeneration
        //(TpmLifecycleTransitions.RegenerateTimeEpoch) bit-mixes this seed forward instead of drawing again.
        uint initialTimeEpoch = FoldSeedToEpoch(ProofSeed.Span);

        Automaton = new PushdownAutomaton<TpmSimulatorState, TpmSimulatorInput, TpmSimulatorStackSymbol>(
            runId: tpmId,
            //A freshly manufactured TPM's storage/endorsement proof seed is the same value the platform proof
            //derives from, so every hierarchy's proof is what one shared seed yields until TPM2_Clear() draws a
            //new storage seed and parts them (TPM 2.0 Library Part 3, clause 24.6.1). The state starts with the
            //not-yet-generated sentinel and SelectHierarchyProofSeed falls back to the platform seed for it —
            //no pool exists at construction to rent a distinct carrier, and a distinct storage seed only comes
            //into being when TPM2_Clear() draws one.
            initialState: TpmSimulatorState.PoweredOff(tpmId, selfTest, clockAdvanceQuantumMs, initialTimeEpoch),
            initialStackSymbol: TpmSimulatorStackSymbol.Lifecycle,
            transition: TpmLifecycleTransitions.Create(),
            acceptPredicate: static state => state.Phase == TpmLifecyclePhase.Operational,
            timeProvider: TimeProvider);
    }

    /// <summary>
    /// Gets the current lifecycle phase of the simulated TPM.
    /// </summary>
    public TpmLifecyclePhase CurrentPhase => Automaton.CurrentState.Phase;

    /// <inheritdoc />
    /// <remarks>
    /// A <see cref="TraceEntry{TState, TInput}"/> carries full state snapshots whose sensitive fields are
    /// pooled, owned carriers. Eviction, rotation, and <see cref="Dispose"/> release those carriers, so a
    /// snapshot an observer retains stays structurally readable but its sensitive carriers become
    /// unreadable the moment their owner released them — reading one throws
    /// <see cref="ObjectDisposedException"/> rather than ever exposing recycled pool memory. An observer
    /// that needs a secret's durable value must copy it out of the entry before the automaton moves on.
    /// </remarks>
    public IDisposable Subscribe(IObserver<TraceEntry<TpmSimulatorState, TpmSimulatorInput>> observer) =>
        Automaton.Subscribe(observer);

    /// <summary>
    /// Releases every owned carrier the live state still holds: all five entity dictionaries' records, the
    /// four hierarchy authorization values, the four hierarchy authorization policy digests, and the storage
    /// proof seed. The dispose-immune shared empties
    /// make the blanket walk safe, and carrier disposal is idempotent, so state already released by
    /// eviction or rotation is a no-op here — the walk only has to reach everything once, mirroring
    /// <c>CtapAuthenticatorSimulator.Dispose</c>'s teardown discipline.
    /// </summary>
    /// <remarks>
    /// The one-caller-at-a-time contract the type states for <see cref="SubmitAsync"/> covers this member too:
    /// no member may run concurrently with any other. The teardown walk returns pooled storage that an in-flight
    /// command's own borrows alias — an Index's data area, a session's nonces and policy digest — so a
    /// <see cref="Dispose"/> racing a command reads octets a later renter already owns rather than failing loudly.
    /// </remarks>
    public void Dispose()
    {
        if(Disposed)
        {
            return;
        }

        TpmSimulatorState state = Automaton.CurrentState;
        foreach(HmacSessionState session in state.HmacSessions.Values)
        {
            session.Dispose();
        }

        foreach(PolicySessionState session in state.PolicySessions.Values)
        {
            session.Dispose();
        }

        foreach(TransientKeyState transient in state.TransientObjects.Values)
        {
            transient.Dispose();
        }

        foreach(TransientKeyState persistent in state.PersistentObjects.Values)
        {
            persistent.Dispose();
        }

        foreach(SealedObjectState sealedObject in state.LoadedSealedObjects.Values)
        {
            sealedObject.Dispose();
        }

        foreach(NvIndexState index in state.NvIndexes.Values)
        {
            index.Dispose();
        }

        state.OwnerAuth.Dispose();
        state.EndorsementAuth.Dispose();
        state.PlatformAuth.Dispose();
        state.LockoutAuth.Dispose();
        state.OwnerAuthPolicy.Dispose();
        state.EndorsementAuthPolicy.Dispose();
        state.PlatformAuthPolicy.Dispose();
        state.LockoutAuthPolicy.Dispose();
        state.StorageProofSeed.Dispose();

        Disposed = true;
    }

    /// <summary>
    /// Applies a platform <c>_TPM_Init</c> indication, moving the TPM into
    /// <see cref="TpmLifecyclePhase.Initializing"/> (and out of <see cref="TpmLifecyclePhase.FailureMode"/>
    /// if it was there). This is not a TPM command and produces no response.
    /// </summary>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A task that completes when the indication has been applied.</returns>
    public async ValueTask PowerOnAsync(CancellationToken cancellationToken = default)
    {
        //_TPM_Init is a pure lifecycle transition that declares no effect, so it is stepped directly
        //through the automaton rather than the effectful runner (which would need a memory pool it
        //has no use for here). The automaton still emits the single trace entry for the step.
        _ = await Automaton.StepAsync(new TpmInitSignal(), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Processes a command and produces its response. Has the <see cref="TpmSubmitHandler"/> shape.
    /// </summary>
    /// <param name="command">The command bytes.</param>
    /// <param name="pool">The memory pool for the response buffer.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The response. The caller owns the returned response and must dispose it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "TpmResponse takes ownership of the rented buffer and is owned by the returned TpmResult, which the caller disposes.")]
    public async ValueTask<TpmResult<TpmResponse>> SubmitAsync(ReadOnlyMemory<byte> command, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        if(!TryParseCommand(command.Span, pool, out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode))
        {
            return SerializeResponse(new TpmHeaderOnlyResponse(malformedResponseCode), pool);
        }

        await RunWithEffectsAsync(input, pool, cancellationToken).ConfigureAwait(false);

        TpmResponseIntent intent = Automaton.CurrentState.ResponseIntent
            ?? new TpmHeaderOnlyResponse(TpmRcConstants.TPM_RC_FAILURE);

        return SerializeResponse(intent, pool);
    }

    private async ValueTask RunWithEffectsAsync(TpmSimulatorInput input, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        _ = await PdaRunner.StepWithEffectsAsync<TpmSimulatorState, TpmSimulatorInput, TpmActionContext>(
            Automaton.CurrentState,
            Automaton.StepCount,
            input,
            step: StepCoreAsync,
            actionExtractor: static state => state.NextAction,
            actionExecutor: static (action, context, token) => ExecuteAction(action, context, token),
            //The storage proof seed is read from the live state, not from a constructor field, because
            //TPM2_Clear() rotates it. It is captured once per submitted command: no command both rotates the
            //seed and declares an effect that derives a proof from it, so an effect always sees the seed the
            //command it belongs to was dispatched under.
            actionContext: new TpmActionContext(Rng, pool, SigningBackend, RsaSigningBackend, ProofSeed, Automaton.CurrentState.StorageProofSeed),
            TimeProvider,
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Executes the effectful work a transition declared and feeds the result back as the next input so the
    /// pure transition can frame the response without touching the RNG, the signing backend, or a buffer itself.
    /// </summary>
    /// <remarks>
    /// <c>TPM2_GetRandom()</c> draws octets, <c>TPM2_CreatePrimary()</c> generates a key or provisions a storage
    /// parent, <c>TPM2_Sign()</c> signs a digest, <c>TPM2_Create()</c> seals data into a KEYEDHASH object,
    /// <c>TPM2_Load()</c> computes the loaded object's Name, <c>TPM2_Certify()</c> marshals and signs an object
    /// attestation, <c>TPM2_Quote()</c> marshals and signs a PCR attestation, <c>TPM2_StartAuthSession()</c>
    /// (HMAC) derives a bound session key, and an encrypt-attributed <c>TPM2_GetRandom()</c> encrypts and
    /// authenticates its response (each step needs the RNG, a backend, or the registered digest/HMAC/KDF seams).
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Every owned carrier an effect creates rides the returned input into the automaton, whose installing transition adopts it into durable state and whose refusing arm disposes it through the input's own Dispose; the analyzer cannot see ownership through the record construction.")]
    private static async ValueTask<TpmSimulatorInput> ExecuteAction(PdaAction action, TpmActionContext context, CancellationToken cancellationToken) =>
        action switch
        {
            TpmRngAction rngAction => GenerateRandom(rngAction, context),
            TpmCreateEccKeyAction createAction => await CreateEccKeyAsync(createAction, context, cancellationToken).ConfigureAwait(false),
            TpmCreateRsaKeyAction createRsaAction => await CreateRsaKeyAsync(createRsaAction, context, cancellationToken).ConfigureAwait(false),
            TpmEccSignAction signAction => await SignEccDigestAsync(signAction, context, cancellationToken).ConfigureAwait(false),
            TpmRsaSignAction rsaSignAction => await SignRsaDigestAsync(rsaSignAction, context, cancellationToken).ConfigureAwait(false),
            TpmCreateStorageParentAction storageParentAction => await CreateStorageParentAsync(storageParentAction, context, cancellationToken).ConfigureAwait(false),
            TpmCreateRsaStorageParentAction rsaStorageParentAction => await CreateRsaStorageParentAsync(rsaStorageParentAction, context, cancellationToken).ConfigureAwait(false),
            TpmSealDataAction sealAction => await SealDataAsync(sealAction, context, cancellationToken).ConfigureAwait(false),
            TpmLoadObjectAction loadAction => await LoadObjectAsync(loadAction, context, cancellationToken).ConfigureAwait(false),
            TpmCertifyAction certifyAction => await CertifyObjectAsync(certifyAction, context, cancellationToken).ConfigureAwait(false),
            TpmRsaCertifyAction rsaCertifyAction => await CertifyObjectRsaAsync(rsaCertifyAction, context, cancellationToken).ConfigureAwait(false),
            TpmCertifyCreationAction certifyCreationAction => await CertifyObjectCreationAsync(certifyCreationAction, context, cancellationToken).ConfigureAwait(false),
            TpmRsaCertifyCreationAction rsaCertifyCreationAction => await CertifyObjectCreationRsaAsync(rsaCertifyCreationAction, context, cancellationToken).ConfigureAwait(false),
            TpmQuoteAction quoteAction => await QuoteObjectAsync(quoteAction, context, cancellationToken).ConfigureAwait(false),
            TpmRsaQuoteAction rsaQuoteAction => await QuoteObjectRsaAsync(rsaQuoteAction, context, cancellationToken).ConfigureAwait(false),
            TpmGetTimeAction getTimeAction => await AttestTimeAsync(getTimeAction, context, cancellationToken).ConfigureAwait(false),
            TpmRsaGetTimeAction rsaGetTimeAction => await AttestTimeRsaAsync(rsaGetTimeAction, context, cancellationToken).ConfigureAwait(false),
            TpmNvCertifyAction nvCertifyAction => await CertifyNvIndexAsync(nvCertifyAction, context, cancellationToken).ConfigureAwait(false),
            TpmRsaNvCertifyAction rsaNvCertifyAction => await CertifyNvIndexRsaAsync(rsaNvCertifyAction, context, cancellationToken).ConfigureAwait(false),
            TpmVerifySignatureAction verifySignatureAction => await VerifySignatureEccAsync(verifySignatureAction, context, cancellationToken).ConfigureAwait(false),
            TpmRsaVerifySignatureAction rsaVerifySignatureAction => await VerifySignatureRsaAsync(rsaVerifySignatureAction, context, cancellationToken).ConfigureAwait(false),
            TpmVerifyPolicySignedAction verifyPolicySignedAction => await VerifyPolicySignedEccAsync(verifyPolicySignedAction, context, cancellationToken).ConfigureAwait(false),
            TpmRsaVerifyPolicySignedAction rsaVerifyPolicySignedAction => await VerifyPolicySignedRsaAsync(rsaVerifyPolicySignedAction, context, cancellationToken).ConfigureAwait(false),
            TpmVerifyPolicyAuthorizeTicketAction verifyPolicyAuthorizeTicketAction => await VerifyPolicyAuthorizeTicketAsync(verifyPolicyAuthorizeTicketAction, context, cancellationToken).ConfigureAwait(false),
            TpmMintPolicySecretTicketAction mintPolicySecretTicketAction => await MintPolicySecretTicketAsync(mintPolicySecretTicketAction, context, cancellationToken).ConfigureAwait(false),
            TpmVerifyPolicyTicketAction verifyPolicyTicketAction => await VerifyPolicyTicketAsync(verifyPolicyTicketAction, context, cancellationToken).ConfigureAwait(false),
            TpmFoldPolicyDigestAction foldPolicyDigestAction => FoldPolicyDigestForAssertion(foldPolicyDigestAction, context),
            TpmVerifyCommandHmacAction verifyCommandHmacAction => await VerifyCommandHmacAsync(verifyCommandHmacAction, context, cancellationToken).ConfigureAwait(false),
            TpmDecryptCreateSensitiveAction decryptCreateSensitiveAction => await DecryptCreateSensitiveAsync(decryptCreateSensitiveAction, context, cancellationToken).ConfigureAwait(false),
            TpmDecryptNvDefineAuthAction decryptNvDefineAuthAction => await DecryptNvDefineAuthAsync(decryptNvDefineAuthAction, context, cancellationToken).ConfigureAwait(false),
            TpmDecryptNvChangeAuthAction decryptNvChangeAuthAction => await DecryptNvChangeAuthAsync(decryptNvChangeAuthAction, context, cancellationToken).ConfigureAwait(false),
            TpmDecryptHierarchyChangeAuthAction decryptHierarchyChangeAuthAction => await DecryptHierarchyChangeAuthAsync(decryptHierarchyChangeAuthAction, context, cancellationToken).ConfigureAwait(false),
            TpmDecryptAttestQualifyingDataAction decryptAttestQualifyingDataAction => await DecryptAttestQualifyingDataAsync(decryptAttestQualifyingDataAction, context, cancellationToken).ConfigureAwait(false),
            TpmGenerateStorageProofSeedAction generateStorageProofSeedAction => GenerateStorageProofSeed(generateStorageProofSeedAction, context),
            TpmPersistObjectAction persistObjectAction => PersistObject(persistObjectAction, context),
            TpmSealDataOverSessionsAction sealDataOverSessionsAction => await SealDataOverSessionsAsync(sealDataOverSessionsAction, context, cancellationToken).ConfigureAwait(false),
            TpmStartHmacSessionAction startHmacAction => await StartHmacSessionAsync(startHmacAction, context, cancellationToken).ConfigureAwait(false),
            TpmRecoverRsaSessionSaltAction recoverRsaSaltAction => await RecoverRsaSessionSaltAsync(recoverRsaSaltAction, context, cancellationToken).ConfigureAwait(false),
            TpmRecoverEccSessionSaltAction recoverEccSaltAction => await RecoverEccSessionSaltAsync(recoverEccSaltAction, context, cancellationToken).ConfigureAwait(false),
            TpmEncryptRandomAction encryptRandomAction => await EncryptRandomOverSessionAsync(encryptRandomAction, context, cancellationToken).ConfigureAwait(false),
            TpmUnsealDataAction unsealAction => await UnsealOverSessionsAsync(unsealAction, context, cancellationToken).ConfigureAwait(false),
            TpmMakeCredentialAction makeCredentialAction => await MakeCredentialAsync(makeCredentialAction, context, cancellationToken).ConfigureAwait(false),
            TpmRsaMakeCredentialAction rsaMakeCredentialAction => await MakeCredentialRsaAsync(rsaMakeCredentialAction, context, cancellationToken).ConfigureAwait(false),
            TpmActivateCredentialAction activateCredentialAction => await ActivateCredentialAsync(activateCredentialAction, context, cancellationToken).ConfigureAwait(false),
            TpmRsaActivateCredentialAction rsaActivateCredentialAction => await ActivateCredentialRsaAsync(rsaActivateCredentialAction, context, cancellationToken).ConfigureAwait(false),
            TpmComputeNvNameAction computeNvNameAction => await ComputeNvNameForPolicyAsync(computeNvNameAction, context, cancellationToken).ConfigureAwait(false),
            TpmFramePolicySecretSessionResponseAction frameSessionResponseAction => await FramePolicySecretSessionResponseAsync(frameSessionResponseAction, context, cancellationToken).ConfigureAwait(false),
            TpmComputeNvPublicNameAction computeNvPublicNameAction => await ComputeNvPublicNameAsync(computeNvPublicNameAction, context, cancellationToken).ConfigureAwait(false),
            TpmComputeNvIndexNameAction computeNvIndexNameAction => await ComputeNvIndexNameAsync(computeNvIndexNameAction, context, cancellationToken).ConfigureAwait(false),
            TpmFrameNvSessionResponseAction frameNvSessionResponseAction => await FrameNvSessionResponseAsync(frameNvSessionResponseAction, context, cancellationToken).ConfigureAwait(false),
            TpmFrameNvChangeAuthResponseAction frameNvChangeAuthResponseAction => await FrameNvChangeAuthResponseAsync(frameNvChangeAuthResponseAction, context, cancellationToken).ConfigureAwait(false),
            _ => throw new NotSupportedException($"No executor is registered for action '{action.GetType().Name}'.")
        };

    /// <summary>
    /// SHA-256 digest size: the width of the creation hash, the ticket digest, and the derived hierarchy proof.
    /// </summary>
    /// <remarks>
    /// The simulator models a TPM whose context integrity algorithm is SHA-256 regardless of nameAlg (the object
    /// Name itself is nameAlg-agile — see <see cref="TpmObjectName"/> — but the creation by-products this
    /// constant sizes are not).
    /// </remarks>
    private const int CreationDigestSize = 32;

    /// <summary>
    /// The MSb of a <c>TPM2B_TIMEOUT</c>'s raw UINT64 value: a flag (never itself part of the equation 12
    /// (TPM 2.0 Library Part 2, Section 10.7.5, Table 111) HMAC input, which hashes the raw timeout with this
    /// bit already cleared) indicating a ticket expires on TPM
    /// Reset or TPM Restart (TPM 2.0 Library Part 2, Section 10.4.10's own note; Part 1, clause 7.4.1's
    /// big-endian rule).
    /// </summary>
    /// <remarks>
    /// Internal rather than private: <c>TpmLifecycleTransitions.OnPolicyTicket</c> extracts the same bit from the
    /// wire timeout it parses, and must use this exact mask rather than a second, drift-prone copy of it.
    /// </remarks>
    internal const ulong TimeoutExpiresOnResetBit = 1UL << 63;

    /// <summary>
    /// The simulator's synthetic firmware version, reported in every attestation's firmwareVersion field (TPM
    /// 2.0 Library Part 2, clause 10.12.12): a UINT32 major half of 1 and a minor half of 184, the same v184
    /// spec-corpus revision <c>TPM2_GetCapability()</c> reports as <c>TPM_PT_REVISION</c>
    /// (<c>TpmLifecycleTransitions.SimSpecRevision</c>), so the two surfaces agree on which spec edition this
    /// TPM models.
    /// </summary>
    private const ulong SimulatedFirmwareVersion = (1UL << 32) | 184UL;

    /// <summary>
    /// The marshaled <c>TPMS_CREATION_DATA</c> for a primary under a permanent hierarchy: empty pcrSelect
    /// (UINT32 count 0), pcrDigest (TPM2B of the SHA-256 digest), locality (BYTE), parentNameAlg (UINT16 =
    /// <c>TPM_ALG_NULL</c>), parentName (TPM2B of the 4-octet parent handle), parentQualifiedName (the same),
    /// and outsideInfo (empty TPM2B).
    /// </summary>
    private const int CreationDataSize =
        sizeof(uint)
        + (sizeof(ushort) + CreationDigestSize)
        + sizeof(byte)
        + sizeof(ushort)
        + (sizeof(ushort) + sizeof(uint))
        + (sizeof(ushort) + sizeof(uint))
        + sizeof(ushort);

    /// <summary>
    /// <c>TPM2_CreatePrimary()</c>: draw a key from the injected backend, build the exported public area and
    /// durable key state from it (<see cref="BuildKeyArtifacts"/>, synchronous so the point spans never cross an
    /// await), then compute the faithful creation by-products — Name, creationData, creationHash, creationTicket
    /// — through the registered digest and HMAC seams.
    /// </summary>
    /// <remarks>
    /// The generated key carrier is disposed once everything is copied out of it. The action's userAuth
    /// carrier is owned by the action until the durable key state's construction adopts it; a throw from the
    /// backend generation step or from the artifact-building rents leaves that rental unreturned until the
    /// pool is collected (the automaton itself recovers — the next command clears the pending action — so a
    /// retrying caller repeats the orphan, and the segment is not zeroed until returned).
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the public area and the by-products buffer transfers to the returned TpmPrimaryKeyCreated, then to the TpmCreatePrimaryResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> CreateEccKeyAsync(TpmCreateEccKeyAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        TpmEccSigningBackend backend = context.SigningBackend
            ?? throw new InvalidOperationException("TPM2_CreatePrimary() requires a signing backend, but none was supplied.");

        Tpm2bPublic outPublic;
        TransientKeyState keyState;
        using(TpmGeneratedEccKey key = await backend.GenerateKey(action.Curve.Value, context.Pool, cancellationToken).ConfigureAwait(false))
        {
            (outPublic, keyState) = BuildKeyArtifacts(action, key, context.Pool);
        }

        try
        {
            //name = nameAlg || H_nameAlg(TPMT_PUBLIC), computed once: retained on the key state (so a later
            //TPM2_Certify() can bind it into the attestation without recomputing) and shared with the creation
            //by-products. The Name width depends on nameAlg (agile per TpmObjectName), so its length travels with it.
            (IMemoryOwner<byte> name, int nameLength) = await ComputeObjectNameAsync(outPublic, action.NameAlg, context.Pool, cancellationToken).ConfigureAwait(false);
            using(name)
            {
                keyState = keyState with { Name = Tpm2bName.Create(name.Memory.Span[..nameLength], context.Pool) };

                (Tpm2bCreationData creationData, Tpm2bDigest creationHash, TpmtTkCreation creationTicket, Tpm2bName framedName) =
                    await BuildCreationByProductsAsync(name.Memory[..nameLength], action.Hierarchy.Value, action.Hierarchy, includeName: true, context, cancellationToken).ConfigureAwait(false);

                return new TpmPrimaryKeyCreated(outPublic, keyState, creationData, creationHash, creationTicket, framedName);
            }
        }
        catch
        {
            //The half-built key state's only owner is this frame until the install transition adopts it, so a
            //failing Name/by-products step must release its private-key carrier or the pinned rental is orphaned.
            keyState.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Splits the generated point into its X and Y coordinates, builds the exported public area, and copies the
    /// scalar into an owned, pinned <see cref="PrivateKeyMemory"/> carrier for the durable key state.
    /// Synchronous so the point spans never cross an await.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the built public area transfers to the caller, which carries it to the response intent disposed by SerializeResponse; ownership of the private-key and authValue carriers transfers to the returned TransientKeyState, which the installing transition stores and eviction disposes.")]
    private static (Tpm2bPublic OutPublic, TransientKeyState KeyState) BuildKeyArtifacts(TpmCreateEccKeyAction action, TpmGeneratedEccKey key, BaseMemoryPool pool)
    {
        //The exported point is SEC1 uncompressed (0x04 || X || Y), so X and Y are each the field-width halves
        //after the leading tag octet.
        ReadOnlySpan<byte> point = key.PublicPoint.AsReadOnlySpan();
        int fieldWidth = (point.Length - 1) / 2;
        ReadOnlySpan<byte> x = point.Slice(1, fieldWidth);
        ReadOnlySpan<byte> y = point.Slice(1 + fieldWidth, fieldWidth);
        ReadOnlySpan<byte> scalar = key.PrivateScalar.AsReadOnlySpan();

        TpmsEccPoint eccPoint = TpmsEccPoint.Create(x, y, pool);
        Tpm2bPublic outPublic = Tpm2bPublic.CreateEccSigningKey(
            action.NameAlg.Value, action.Attributes, action.Curve.Value, TpmtEccScheme.Ecdsa(action.SchemeHashAlg.Value), eccPoint, pool, action.AuthPolicy.AsReadOnlySpan());

        //The Name is filled by the caller once it has been computed from the exported public area (through the
        //asynchronous digest seam, which this synchronous point-splitting step must not cross). The SEC1 point is
        //retained so a later ECDH-based command can use this object's public key (TPM 2.0 Library Part 1, clause 24).
        var keyState = new TransientKeyState(
            action.Handle, action.Hierarchy, TpmiAlgPublic.FromValue(TpmAlgIdConstants.TPM_ALG_ECC), action.Curve, CopyToPrivateKeyCarrier(scalar, EccPrivateKeyTag(action.Curve.Value), pool), Tpm2bName.Empty, action.Attributes, point.ToArray(), Tpm2bPublicKeyRsa.Empty, action.AuthPolicy, action.UserAuth);

        return (outPublic, keyState);
    }

    /// <summary>
    /// Copies backend-generated private material out of its scoped carrier into an owned, pinned
    /// <see cref="PrivateKeyMemory"/> the durable key state adopts — the pool boundary extended past the
    /// generating <c>using</c> block into the state record's own field, so the material never lands on the
    /// bare heap between the two.
    /// </summary>
    /// <param name="material">The private material to copy.</param>
    /// <param name="tag">The algorithm-specific private-key tag.</param>
    /// <param name="pool">The memory pool the pinned storage is rented from.</param>
    /// <returns>The owned carrier; ownership transfers to the caller.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented storage transfers to the returned PrivateKeyMemory, which the caller's TransientKeyState adopts and eviction disposes.")]
    private static PrivateKeyMemory CopyToPrivateKeyCarrier(ReadOnlySpan<byte> material, Tag tag, BaseMemoryPool pool)
    {
        IMemoryOwner<byte> storage = pool.Rent(material.Length, AllocationKind.Pinned);
        material.CopyTo(storage.Memory.Span);

        return new PrivateKeyMemory(storage, tag);
    }

    /// <summary>
    /// Resolves the algorithm-specific private-key tag for an ECC curve this simulator's templates admit,
    /// so the retained scalar carries the most specific existing <see cref="CryptoTags"/> entry.
    /// </summary>
    /// <param name="curve">The curve the key lives on.</param>
    /// <returns>The matching private-key tag.</returns>
    /// <exception cref="InvalidOperationException">Thrown for a curve no template this simulator builds admits.</exception>
    private static Tag EccPrivateKeyTag(TpmEccCurveConstants curve) => curve switch
    {
        TpmEccCurveConstants.TPM_ECC_NIST_P256 => CryptoTags.P256PrivateKey,
        TpmEccCurveConstants.TPM_ECC_NIST_P384 => CryptoTags.P384PrivateKey,
        TpmEccCurveConstants.TPM_ECC_NIST_P521 => CryptoTags.P521PrivateKey,
        _ => throw new InvalidOperationException($"No private-key tag is defined for curve '{curve}'.")
    };

    /// <summary>
    /// Resolves the algorithm-specific private-key tag for an RSA key width this simulator's templates admit,
    /// mirroring <see cref="EccPrivateKeyTag"/>.
    /// </summary>
    /// <param name="keyBits">The RSA modulus width in bits.</param>
    /// <returns>The matching private-key tag.</returns>
    /// <exception cref="InvalidOperationException">Thrown for a width no template this simulator builds admits.</exception>
    private static Tag RsaPrivateKeyTag(ushort keyBits) => keyBits switch
    {
        2048 => CryptoTags.Rsa2048PrivateKey,
        4096 => CryptoTags.Rsa4096PrivateKey,
        _ => throw new InvalidOperationException($"No private-key tag is defined for an RSA-{keyBits} key.")
    };

    /// <summary>
    /// <c>TPM2_CreatePrimary()</c> for an RSA key: draw a key from the injected RSA backend, build the exported
    /// public area carrying the modulus and the durable key state, then compute the same faithful creation
    /// by-products the ECC path does (they are key-type-agnostic — the Name hashes the marshaled
    /// <c>TPMT_PUBLIC</c>, which now carries the modulus).
    /// </summary>
    /// <remarks>
    /// The generated key carrier is disposed once everything is copied out of it. The action's userAuth
    /// carrier is owned by the action until the durable key state's construction adopts it; a throw from the
    /// backend generation step or from the artifact-building rents leaves that rental unreturned until the
    /// pool is collected (the automaton itself recovers — the next command clears the pending action — so a
    /// retrying caller repeats the orphan, and the segment is not zeroed until returned).
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the public area and the by-products buffer transfers to the returned TpmPrimaryKeyCreated, then to the TpmCreatePrimaryResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> CreateRsaKeyAsync(TpmCreateRsaKeyAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        TpmRsaSigningBackend backend = context.RsaSigningBackend
            ?? throw new InvalidOperationException("TPM2_CreatePrimary() for an RSA key requires an RSA signing backend, but none was supplied.");

        Tpm2bPublic outPublic;
        TransientKeyState keyState;
        using(TpmGeneratedRsaKey key = await backend.GenerateKey(action.KeyBits.Value, context.Pool, cancellationToken).ConfigureAwait(false))
        {
            (outPublic, keyState) = BuildRsaKeyArtifacts(action, key, context.Pool);
        }

        try
        {
            //name = nameAlg || H_nameAlg(TPMT_PUBLIC), computed once: retained on the key state and shared with the
            //by-products (the Name hashes the marshaled TPMT_PUBLIC, which for an RSA key carries the modulus). The
            //Name width depends on nameAlg (agile per TpmObjectName), so its length travels with it.
            (IMemoryOwner<byte> name, int nameLength) = await ComputeObjectNameAsync(outPublic, action.NameAlg, context.Pool, cancellationToken).ConfigureAwait(false);
            using(name)
            {
                keyState = keyState with { Name = Tpm2bName.Create(name.Memory.Span[..nameLength], context.Pool) };

                (Tpm2bCreationData creationData, Tpm2bDigest creationHash, TpmtTkCreation creationTicket, Tpm2bName framedName) =
                    await BuildCreationByProductsAsync(name.Memory[..nameLength], action.Hierarchy.Value, action.Hierarchy, includeName: true, context, cancellationToken).ConfigureAwait(false);

                return new TpmPrimaryKeyCreated(outPublic, keyState, creationData, creationHash, creationTicket, framedName);
            }
        }
        catch
        {
            //The half-built key state's only owner is this frame until the install transition adopts it, so a
            //failing Name/by-products step must release its private-key carrier or the pinned rental is orphaned.
            keyState.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Builds the exported public area carrying the generated modulus and copies the private key into an owned,
    /// pinned <see cref="PrivateKeyMemory"/> carrier for the durable key state. Synchronous so the key spans
    /// never cross an await.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the built public area transfers to the caller, which carries it to the response intent disposed by SerializeResponse; ownership of the private-key and authValue carriers transfers to the returned TransientKeyState, which the installing transition stores and eviction disposes.")]
    private static (Tpm2bPublic OutPublic, TransientKeyState KeyState) BuildRsaKeyArtifacts(TpmCreateRsaKeyAction action, TpmGeneratedRsaKey key, BaseMemoryPool pool)
    {
        ReadOnlySpan<byte> modulus = key.Modulus.AsReadOnlySpan();
        ReadOnlySpan<byte> privateKey = key.PrivateKey.AsReadOnlySpan();

        Tpm2bPublic outPublic = Tpm2bPublic.CreateRsaSigningKey(
            action.NameAlg.Value, action.Attributes, action.KeyBits.Value, action.Scheme, modulus, pool, action.AuthPolicy.AsReadOnlySpan());

        //The Name is filled by the caller once computed from the exported public area (through the asynchronous
        //digest seam, which this synchronous key-copying step must not cross). An RSA key carries no SEC1 point, so
        //the retained public point is empty (the ECDH-based credential commands model only ECC credential keys).
        //The public modulus is likewise not retained here — only the RSA storage-parent effect
        //(BuildRsaStorageParentArtifacts) retains it, since a signing key needs no RSA-OAEP secret transport.
        var keyState = new TransientKeyState(
            action.Handle, action.Hierarchy, TpmiAlgPublic.FromValue(TpmAlgIdConstants.TPM_ALG_RSA), default, CopyToPrivateKeyCarrier(privateKey, RsaPrivateKeyTag(action.KeyBits.Value), pool), Tpm2bName.Empty, action.Attributes, ReadOnlyMemory<byte>.Empty, Tpm2bPublicKeyRsa.Empty, action.AuthPolicy, action.UserAuth);

        return (outPublic, keyState);
    }

    /// <summary>
    /// Computes the faithful object-creation by-products (TPM 2.0 Library Part 3, clauses 24.1 and 12.1; Part 2,
    /// clause 15) as the separate structures those response tables name: a <c>TPM2B_CREATION_DATA</c>, a
    /// <c>TPM2B_DIGEST</c> creation hash, a <c>TPMT_TK_CREATION</c>, and — for <c>TPM2_CreatePrimary()</c> alone
    /// — the object <c>TPM2B_NAME</c>.
    /// </summary>
    /// <remarks>
    /// <c>TPM2_CreatePrimary()</c> returns the Name (includeName true); <c>TPM2_Create()</c> does not
    /// (includeName false), and then the returned Name is the dispose-immune empty sentinel. The already-computed
    /// Name is passed in (the caller computes it once and also retains it on the key state) because the creation
    /// ticket HMACs over it; the copy returned here is a rental of its own, so the framed response and the key
    /// state never co-own one buffer. This step is in the effectful layer because the creation hash and the
    /// ticket HMAC need the asynchronous digest/HMAC seams.
    /// </remarks>
    /// <param name="name">The object's already-computed Name, which the ticket HMACs over.</param>
    /// <param name="parentHandle">
    /// The handle the creation DATA names as the parent: a permanent hierarchy for
    /// <c>TPM2_CreatePrimary()</c>, the parent object's transient handle for <c>TPM2_Create()</c>.
    /// </param>
    /// <param name="ticketHierarchy">
    /// The hierarchy the creation TICKET names and whose proof keys its HMAC — the hierarchy containing the
    /// created object's Name (Part 2, clause 10.7.3, Table 109). For <c>TPM2_CreatePrimary()</c> that is the
    /// primary handle itself; for <c>TPM2_Create()</c> it is the hierarchy the parent object belongs to, never
    /// the parent's own handle, which is not a <c>TPMI_RH_HIERARCHY</c> value at all.
    /// </param>
    /// <param name="includeName">Whether the object Name is one of the returned by-products.</param>
    /// <param name="context">The action context carrying the proof seeds and the memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The four by-product carriers. Ownership transfers to the caller.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of all four by-product carriers transfers to the caller; the intermediate buffers are released by their using declarations and a failure part-way through releases every carrier already built.")]
    private static async ValueTask<(Tpm2bCreationData CreationData, Tpm2bDigest CreationHash, TpmtTkCreation CreationTicket, Tpm2bName Name)> BuildCreationByProductsAsync(
        ReadOnlyMemory<byte> name, uint parentHandle, TpmiRhHierarchy ticketHierarchy, bool includeName, TpmActionContext context, CancellationToken cancellationToken)
    {
        //creationData (a TPM2B_CREATION_DATA over the marshaled TPMS_CREATION_DATA); creationHash =
        //H_nameAlg(creationData).
        Tpm2bCreationData creationData = await BuildCreationDataAsync(parentHandle, context.Pool, cancellationToken).ConfigureAwait(false);
        Tpm2bDigest creationHash = Tpm2bDigest.Empty;
        TpmtTkCreation creationTicket = TpmtTkCreation.Null;
        try
        {
            using(DigestValue computedHash = await CryptographicKeyEvents.ComputeDigestAsync(
                creationData.GetRawMemory(), CreationDigestSize, CryptoTags.Sha256Digest, context.Pool, cancellationToken: cancellationToken).ConfigureAwait(false))
            {
                creationHash = Tpm2bDigest.Create(computedHash.AsReadOnlySpan(), context.Pool);
            }

            //creationTicket digest = HMAC(proof, TPM_ST_CREATION || name || creationHash), keyed on the proof of
            //the hierarchy the ticket names. The HMAC step rents the digest octets itself, so the ticket adopts
            //that rental rather than copying it.
            using IMemoryOwner<byte> proof = await DeriveHierarchyProofAsync(context, ticketHierarchy.Value, cancellationToken).ConfigureAwait(false);
            IMemoryOwner<byte> ticketDigest = await ComputeCreationTicketDigestAsync(
                proof.Memory[..CreationDigestSize], name, creationHash.AsReadOnlyMemory(), context.Pool, cancellationToken).ConfigureAwait(false);
            creationTicket = TpmtTkCreation.FromMarshaled(ticketHierarchy, ticketDigest, CreationDigestSize);

            //The response Name is a rental of its own: the caller keeps the computed octets only for this frame,
            //and where a key state also retains the Name it owns a separate carrier on a different lifetime.
            Tpm2bName framedName = includeName
                ? Tpm2bName.Create(name.Span, context.Pool)
                : Tpm2bName.Empty;

            return (creationData, creationHash, creationTicket, framedName);
        }
        catch
        {
            //These carriers' only owner is this frame until the by-products record adopts them, so a failing
            //later step must release every earlier one or the rentals are orphaned.
            creationTicket.Dispose();
            creationHash.Dispose();
            creationData.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Computes <c>name = nameAlg || H_nameAlg(marshaled TPMT_PUBLIC)</c> (TPM 2.0 Library Part 1, clause 14, Table 6).
    /// Marshals the public area and delegates the nameAlg-agile digest+framing to the shared
    /// <see cref="TpmObjectName"/> helper.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the Name buffer transfers to the caller, which releases it via a using declaration.")]
    private static async ValueTask<(IMemoryOwner<byte> Owner, int Length)> ComputeObjectNameAsync(Tpm2bPublic outPublic, TpmiAlgHash nameAlg, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        int publicSize = outPublic.PublicArea.GetSerializedSize();
        using IMemoryOwner<byte> marshaled = pool.Rent(publicSize);
        MarshalPublicArea(outPublic, marshaled.Memory.Span[..publicSize]);

        return await ComputeObjectNameFromBytesAsync(marshaled.Memory[..publicSize], nameAlg, pool, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Computes <c>name = nameAlg || H_nameAlg(TPMT_PUBLIC)</c> over already-marshaled public-area bytes — the
    /// form <c>TPM2_Load()</c> has (it receives the marshaled <c>TPMT_PUBLIC</c> in inPublic) and the digest step
    /// <see cref="ComputeObjectNameAsync"/> shares. Delegates to the shared nameAlg-agile
    /// <see cref="TpmObjectName"/> helper (TPM 2.0 Library Part 1, clause 14, Table 6).
    /// </summary>
    private static ValueTask<(IMemoryOwner<byte> Owner, int Length)> ComputeObjectNameFromBytesAsync(ReadOnlyMemory<byte> publicAreaBytes, TpmiAlgHash nameAlg, BaseMemoryPool pool, CancellationToken cancellationToken) =>
        TpmObjectName.ComputeNameAsync(publicAreaBytes, (ushort)nameAlg.Value, pool, cancellationToken);

    /// <summary>
    /// Marshals the <c>TPMT_PUBLIC</c> into its canonical wire form (no TPM2B size prefix) — the hash input for
    /// the Name.
    /// </summary>
    private static void MarshalPublicArea(Tpm2bPublic outPublic, Span<byte> destination)
    {
        var writer = new TpmWriter(destination);
        outPublic.PublicArea.WriteTo(ref writer);
    }

    /// <summary>
    /// The marshaled <c>TPMS_CREATION_DATA</c> both creation commands report (TPM 2.0 Library Part 2, clause
    /// 15.1, Table 246): a <c>TPM2_CreatePrimary()</c> primary under a permanent hierarchy and a
    /// <c>TPM2_Create()</c> child under a loaded parent object. The parent Name and Qualified Name are the
    /// 4-octet handle form, the pcrDigest is the hash of the empty PCR selection, and the locality is the
    /// command locality (0 for this software model).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Two of the fields this frame writes diverge from Part 2's own normative text for a
    /// <c>TPM2_Create()</c> child, whose parent is a loaded transient object rather than a permanent handle.
    /// </para>
    /// <para>
    /// The parent Name and Qualified Name: clause 15.1, printed page 206, states "If the parent is a permanent
    /// handle (TPM_RH_OWNER, TPM_RH_PLATFORM, TPM_RH_ENDORSEMENT, or TPM_RH_NULL), then parentName and
    /// parentQualifiedName will be set to the parent handle value and parentNameAlg will be TPM_ALG_NULL", and
    /// Table 246's <c>parentName</c> row on the same page states "Name of the parent at time of creation. The
    /// size will match digest size associated with parentNameAlg unless it is TPM_ALG_NULL, in which case the
    /// size will be 4 and parentName will be the hierarchy handle." A loaded parent object is neither a
    /// permanent handle nor a hierarchy handle, so its child's creation data owes the parent's own Name and
    /// Qualified Name under the parent's own <c>nameAlg</c> — which is what Part 4's
    /// <c>FillInCreationData()</c> (printed pages 722-723) writes. This model writes the handle form with
    /// <c>parentNameAlg = TPM_ALG_NULL</c> for both parents.
    /// </para>
    /// <para>
    /// The pcrDigest: Table 246's <c>pcrDigest</c> row, printed page 206, states "digest of the selected PCR
    /// using nameAlg of the object for which this structure is being created. pcrDigest.size shall be zero if
    /// the pcrSelect list is empty." This model frames a <c>TPML_PCR_SELECTION</c> of count 0 and then a
    /// full-width digest of the empty hash input rather than the zero-size buffer that "shall" requires.
    /// </para>
    /// <para>
    /// Both are wire-visible: <c>TPMS_CREATION_DATA</c> is hashed into <c>creationHash</c>, thence into the
    /// creation ticket (clause 10.7.3, equation (4), printed page 140) and into
    /// <c>TPM2_CertifyCreation()</c>'s attestation.
    /// </para>
    /// </remarks>
    /// <param name="parentHandle">
    /// The handle the creation data names as the parent: a permanent hierarchy for <c>TPM2_CreatePrimary()</c>,
    /// the parent object's transient handle for <c>TPM2_Create()</c>.
    /// </param>
    /// <param name="pool">The memory pool the marshaled octets are rented from.</param>
    /// <param name="cancellationToken">A cancellation token observed across the pcrDigest computation.</param>
    /// <returns>The marshaled creation data. Ownership transfers to the caller.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the creation-data carrier transfers to the caller, which releases it or hands it onward; a failure between the rental and the adoption releases the rental.")]
    private static async ValueTask<Tpm2bCreationData> BuildCreationDataAsync(uint parentHandle, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        //pcrDigest of the empty PCR selection is the hash of no PCR data (an empty hash input).
        using DigestValue pcrDigest = await CryptographicKeyEvents.ComputeDigestAsync(
            ReadOnlyMemory<byte>.Empty, CreationDigestSize, CryptoTags.Sha256Digest, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        IMemoryOwner<byte> owner = pool.Rent(CreationDataSize);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span[..CreationDataSize]);
            writer.WriteUInt32(0);                                          //pcrSelect: TPML_PCR_SELECTION count 0.
            writer.WriteUInt16((ushort)CreationDigestSize);                 //pcrDigest: TPM2B_DIGEST size.
            writer.WriteBytes(pcrDigest.AsReadOnlySpan());                  //pcrDigest.
            writer.WriteByte((byte)TpmaLocality.TPM_LOC_ZERO);             //locality (locality 0).
            writer.WriteUInt16((ushort)TpmAlgIdConstants.TPM_ALG_NULL);     //parentNameAlg (the handle form names no algorithm).
            writer.WriteUInt16((ushort)sizeof(uint));                      //parentName: TPM2B_NAME size = handle width.
            writer.WriteUInt32(parentHandle);                               //parentName = the parent handle.
            writer.WriteUInt16((ushort)sizeof(uint));                      //parentQualifiedName: size = handle width.
            writer.WriteUInt32(parentHandle);                               //parentQualifiedName = the parent handle.
            writer.WriteUInt16(0);                                          //outsideInfo: empty TPM2B_DATA.
        }
        catch
        {
            owner.Dispose();
            throw;
        }

        //The marshaling step rents the octets itself, so the TPM2B_CREATION_DATA carrier adopts that rental
        //rather than copying it; a rejected adoption releases the rental before the exception leaves.
        return Tpm2bCreationData.FromMarshaled(owner, CreationDataSize, pool);
    }

    /// <summary>
    /// Chooses which of the two seeds <paramref name="hierarchy"/>'s proof derives from: the storage seed for
    /// the storage and endorsement hierarchies, whose proofs a real TPM recomputes whenever the Storage Primary
    /// Seed changes, and the construction-fixed platform seed for everything else.
    /// </summary>
    /// <remarks>
    /// TPM 2.0 Library Part 1, clause 12.5: "A Platform hierarchy proof (phProof)... changes when the PPS
    /// changes. An shProof, used for the Storage and Endorsement hierarchies, changes when the SPS changes."
    /// Splitting the two here is what lets <c>TPM2_Clear()</c> kill outstanding owner and endorsement tickets by
    /// drawing a new storage seed while every platform-hierarchy ticket keeps verifying. A creation ticket names
    /// the hierarchy containing the created object (Part 2, clause 10.7.3, Table 109), so an ordinary object
    /// created under an owner-hierarchy parent takes the owner proof and rotates with the storage seed exactly
    /// as a primary under that hierarchy does. Handles outside the permanent-hierarchy range still reach this
    /// selector — a caller-supplied ticket hierarchy on <c>TPM2_PolicyTicket()</c>/<c>TPM2_CertifyCreation()</c>
    /// is used as-is — and take the platform seed.
    /// </remarks>
    /// <param name="context">The action context carrying both seeds.</param>
    /// <param name="hierarchy">The handle the proof is being derived for.</param>
    /// <returns>The seed to fold the handle into.</returns>
    private static ReadOnlyMemory<byte> SelectHierarchyProofSeed(TpmActionContext context, uint hierarchy) =>
        hierarchy switch
        {
            //Until TPM2_Clear() draws a distinct storage seed the state carries the not-yet-generated
            //sentinel, and the storage/endorsement proofs derive from the same construction-fixed seed the
            //platform proof does — a freshly manufactured TPM's per-hierarchy proofs are exactly what a
            //single-seed derivation yields (Part 3, clause 24.6.1 is what parts them).
            (uint)TpmRh.TPM_RH_OWNER or (uint)TpmRh.TPM_RH_ENDORSEMENT => context.StorageProofSeed.IsGenerated
                ? context.StorageProofSeed.AsReadOnlyMemory()
                : context.ProofSeed,
            _ => context.ProofSeed
        };

    /// <summary>
    /// Derives <paramref name="hierarchy"/>'s proof from whichever seed <see cref="SelectHierarchyProofSeed"/>
    /// governs it — the single entry point every proof-consuming effect goes through, so no site picks a seed of
    /// its own.
    /// </summary>
    /// <param name="context">The action context carrying both seeds and the memory pool.</param>
    /// <param name="hierarchy">The handle the proof is being derived for.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The derived proof. Ownership transfers to the caller.</returns>
    private static ValueTask<IMemoryOwner<byte>> DeriveHierarchyProofAsync(TpmActionContext context, uint hierarchy, CancellationToken cancellationToken) =>
        DeriveHierarchyProofAsync(SelectHierarchyProofSeed(context, hierarchy), hierarchy, context.Pool, cancellationToken);

    /// <summary>
    /// Derives the per-hierarchy proof used as the creation-ticket HMAC key, from the supplied seed and the
    /// hierarchy handle.
    /// </summary>
    /// <remarks>
    /// A real TPM's proof is a persistent random secret fixed at manufacture and stored in NV (one per
    /// hierarchy); the simulator has no NV, so it derives the proof from the injected seed through the
    /// registered digest — the ticket is a genuine HMAC over the exact formula, and the seed is the caller's to
    /// make random (genuine entropy) or fixed (reproducible). Each hierarchy gets a distinct proof because its
    /// handle is folded into the derivation.
    /// </remarks>
    /// <param name="seed">The seed the proof derives from, chosen by <see cref="SelectHierarchyProofSeed"/>.</param>
    /// <param name="hierarchy">The handle folded into the derivation.</param>
    /// <param name="pool">The pool every buffer is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The derived proof. Ownership transfers to the caller.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the proof buffer transfers to the caller, which releases it via a using declaration.")]
    private static async ValueTask<IMemoryOwner<byte>> DeriveHierarchyProofAsync(ReadOnlyMemory<byte> seed, uint hierarchy, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        int inputSize = seed.Length + sizeof(uint);
        using IMemoryOwner<byte> input = pool.Rent(inputSize, AllocationKind.Pinned);
        WriteProofInput(input.Memory.Span[..inputSize], seed.Span, hierarchy);

        using DigestValue proof = await CryptographicKeyEvents.ComputeDigestAsync(
            input.Memory[..inputSize], CreationDigestSize, CryptoTags.Sha256Digest, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        IMemoryOwner<byte> owner = pool.Rent(CreationDigestSize, AllocationKind.Pinned);
        try
        {
            proof.AsReadOnlySpan().CopyTo(owner.Memory.Span[..CreationDigestSize]);

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>The proof-derivation hash input: the TPM seed followed by the hierarchy handle.</summary>
    private static void WriteProofInput(Span<byte> destination, ReadOnlySpan<byte> seed, uint hierarchy)
    {
        var writer = new TpmWriter(destination);
        writer.WriteBytes(seed);
        writer.WriteUInt32(hierarchy);
    }

    /// <summary>
    /// Folds an arbitrary-length seed into a well-mixed UINT32 via FNV-1a — a simple, well-known,
    /// non-cryptographic hash, sufficient because TimeEpoch carries no secrecy requirement of its own (see its
    /// doc comment on <see cref="TpmSimulatorState"/>): it only needs to change across a Time discontinuity,
    /// never to stay hidden.
    /// </summary>
    /// <remarks>
    /// Used once, at <see cref="TpmSimulator"/> construction, to derive the initial TimeEpoch from
    /// <see cref="ProofSeed"/> without touching the injected <see cref="Rng"/> delegate (which would perturb
    /// <c>TPM2_GetRandom()</c>'s deterministic counter stream).
    /// </remarks>
    private static uint FoldSeedToEpoch(ReadOnlySpan<byte> seed)
    {
        const uint FnvOffsetBasis = 2166136261u;
        const uint FnvPrime = 16777619u;

        uint hash = FnvOffsetBasis;
        foreach(byte value in seed)
        {
            hash ^= value;
            hash *= FnvPrime;
        }

        return hash;
    }

    /// <summary>
    /// Computes <c>creationTicket digest = HMAC_contextAlg(proof, TPM_ST_CREATION || Name || creationHash)</c>
    /// (TPM 2.0 Library Part 2, clause 10.7; the context integrity algorithm is SHA-256 for this model).
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the ticket-digest buffer transfers to the caller, which releases it via a using declaration.")]
    private static async ValueTask<IMemoryOwner<byte>> ComputeCreationTicketDigestAsync(
        ReadOnlyMemory<byte> proof, ReadOnlyMemory<byte> name, ReadOnlyMemory<byte> creationHash, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        int messageSize = sizeof(ushort) + name.Length + creationHash.Length;
        using IMemoryOwner<byte> message = pool.Rent(messageSize);
        WriteTicketMessage(message.Memory.Span[..messageSize], name.Span, creationHash.Span);

        using HmacValue hmac = await CryptographicKeyEvents.ComputeHmacAsync(
            message.Memory[..messageSize], proof, CreationDigestSize, CryptoTags.HmacSha256Value, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        IMemoryOwner<byte> owner = pool.Rent(CreationDigestSize);
        try
        {
            hmac.AsReadOnlySpan().CopyTo(owner.Memory.Span[..CreationDigestSize]);

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>The creation-ticket HMAC message: <c>TPM_ST_CREATION</c> (UINT16) || Name || creation hash.</summary>
    private static void WriteTicketMessage(Span<byte> destination, ReadOnlySpan<byte> name, ReadOnlySpan<byte> creationHash)
    {
        var writer = new TpmWriter(destination);
        writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_CREATION);
        writer.WriteBytes(name);
        writer.WriteBytes(creationHash);
    }

    /// <summary>
    /// <c>TPM2_Sign()</c> over an ECC key: sign the digest directly with the retained scalar through the
    /// injected backend.
    /// </summary>
    /// <remarks>
    /// The signature ownership flows to the <see cref="TpmMessageSigned"/> input, then to the
    /// <c>TpmSignResponse</c> intent, and is released by <see cref="SerializeResponse"/> after the r and s
    /// parameters are framed.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the signature transfers to the returned TpmMessageSigned and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> SignEccDigestAsync(TpmEccSignAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        //The effect is the digest carrier's terminal owner: the signing primitive is its only reader, so the
        //using declaration releases it on the throwing arm as well as the successful one.
        using Tpm2bDigest digest = action.Digest;

        TpmEccSigningBackend backend = context.SigningBackend
            ?? throw new InvalidOperationException("TPM2_Sign() over an ECC key requires an ECC signing backend, but none was supplied.");

        using Signature signature = await backend.SignDigest(
            action.Scalar.AsReadOnlyMemory(), digest.AsReadOnlyMemory(), action.Curve.Value, context.Pool, cancellationToken).ConfigureAwait(false);

        return new TpmMessageSigned(TpmtSignature.Create(TpmAlgIdConstants.TPM_ALG_ECDSA, action.HashAlg.Value, signature.AsReadOnlySpan(), context.Pool));
    }

    /// <summary>
    /// <c>TPM2_Sign()</c> over an RSA key: sign the digest directly under the requested scheme through the
    /// injected RSA backend.
    /// </summary>
    /// <remarks>
    /// The signature ownership flows to the <see cref="TpmMessageSigned"/> input, then to the
    /// <c>TpmSignResponse</c> intent, and is released by <see cref="SerializeResponse"/> after the single RSA
    /// signature buffer is framed.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the signature transfers to the returned TpmMessageSigned and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> SignRsaDigestAsync(TpmRsaSignAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        //The effect is the digest carrier's terminal owner: the signing primitive is its only reader, so the
        //using declaration releases it on the throwing arm as well as the successful one.
        using Tpm2bDigest digest = action.Digest;

        TpmRsaSigningBackend backend = context.RsaSigningBackend
            ?? throw new InvalidOperationException("TPM2_Sign() over an RSA key requires an RSA signing backend, but none was supplied.");

        using Signature signature = await backend.SignDigest(
            action.PrivateKey.AsReadOnlyMemory(), digest.AsReadOnlyMemory(), action.Scheme.Value, action.HashAlg.Value, context.Pool, cancellationToken).ConfigureAwait(false);

        return new TpmMessageSigned(TpmtSignature.Create(action.Scheme.Value, action.HashAlg.Value, signature.AsReadOnlySpan(), context.Pool));
    }

    /// <summary>
    /// <c>TPM2_CreatePrimary()</c> for an ECC storage parent: draw a key from the injected backend, build the
    /// exported storage public area carrying its actual public point and the durable parent state, then compute
    /// the same faithful creation by-products the key-bearing paths do.
    /// </summary>
    /// <remarks>
    /// A real TPM generates a real key for a storage primary (its public point is what an endorsement-key
    /// certificate is issued over); the simulator still models no parent-key wrapping of children, so a storage
    /// parent is only used as a handle for <c>TPM2_Create()</c>, but its exported point is now the genuine
    /// generated point. The result reuses the <see cref="TpmPrimaryKeyCreated"/> input the signing paths feed
    /// back. The action's userAuth carrier is owned by the action until the durable parent state's
    /// construction adopts it; a throw from the backend generation step or from the artifact-building rents
    /// leaves that rental unreturned until the pool is collected (the automaton itself recovers — the next
    /// command clears the pending action — so a retrying caller repeats the orphan, and the segment is not
    /// zeroed until returned).
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the public area and the by-products buffer transfers to the returned TpmPrimaryKeyCreated, then to the TpmCreatePrimaryResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> CreateStorageParentAsync(TpmCreateStorageParentAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        TpmEccSigningBackend backend = context.SigningBackend
            ?? throw new InvalidOperationException("TPM2_CreatePrimary() for an ECC storage parent requires a signing backend, but none was supplied.");

        Tpm2bPublic outPublic;
        TransientKeyState keyState;
        using(TpmGeneratedEccKey key = await backend.GenerateKey(action.Curve.Value, context.Pool, cancellationToken).ConfigureAwait(false))
        {
            (outPublic, keyState) = BuildStorageParentArtifacts(action, key, context.Pool);
        }

        try
        {
            //name = nameAlg || H_nameAlg(TPMT_PUBLIC), computed once from the exported public area (which now carries
            //the generated point): retained on the parent state and shared with the creation by-products. The Name
            //width depends on nameAlg (agile per TpmObjectName), so its length travels with it.
            (IMemoryOwner<byte> name, int nameLength) = await ComputeObjectNameAsync(outPublic, action.NameAlg, context.Pool, cancellationToken).ConfigureAwait(false);
            using(name)
            {
                keyState = keyState with { Name = Tpm2bName.Create(name.Memory.Span[..nameLength], context.Pool) };

                (Tpm2bCreationData creationData, Tpm2bDigest creationHash, TpmtTkCreation creationTicket, Tpm2bName framedName) =
                    await BuildCreationByProductsAsync(name.Memory[..nameLength], action.Hierarchy.Value, action.Hierarchy, includeName: true, context, cancellationToken).ConfigureAwait(false);

                return new TpmPrimaryKeyCreated(outPublic, keyState, creationData, creationHash, creationTicket, framedName);
            }
        }
        catch
        {
            //The half-built parent state's only owner is this frame until the install transition adopts it, so a
            //failing Name/by-products step must release its private-key carrier or the pinned rental is orphaned.
            keyState.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Splits the generated point into its X and Y coordinates, builds the exported storage public area carrying
    /// the point, and copies the scalar into an owned, pinned <see cref="PrivateKeyMemory"/> carrier for the
    /// durable parent state. Mirrors <see cref="BuildKeyArtifacts"/> for the storage template; synchronous so
    /// the point spans never cross an await.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the built public area transfers to the caller, which carries it to the response intent disposed by SerializeResponse; ownership of the private-key and authValue carriers transfers to the returned TransientKeyState, which the installing transition stores and eviction disposes.")]
    private static (Tpm2bPublic OutPublic, TransientKeyState KeyState) BuildStorageParentArtifacts(TpmCreateStorageParentAction action, TpmGeneratedEccKey key, BaseMemoryPool pool)
    {
        //The exported point is SEC1 uncompressed (0x04 || X || Y), so X and Y are each the field-width halves
        //after the leading tag octet.
        ReadOnlySpan<byte> point = key.PublicPoint.AsReadOnlySpan();
        int fieldWidth = (point.Length - 1) / 2;
        ReadOnlySpan<byte> x = point.Slice(1, fieldWidth);
        ReadOnlySpan<byte> y = point.Slice(1 + fieldWidth, fieldWidth);
        ReadOnlySpan<byte> scalar = key.PrivateScalar.AsReadOnlySpan();

        TpmsEccPoint eccPoint = TpmsEccPoint.Create(x, y, pool);
        Tpm2bPublic outPublic = Tpm2bPublic.CreateEccStorageParent(action.NameAlg.Value, action.Attributes, action.Curve.Value, eccPoint, pool, action.AuthPolicy.AsReadOnlySpan());

        //The Name is filled by the caller once it has been computed from the exported public area (through the
        //asynchronous digest seam, which this synchronous point-splitting step must not cross). The SEC1 point is
        //retained so credential protection (the endorsement key is a storage parent) can use this object's public key.
        var keyState = new TransientKeyState(
            action.Handle, action.Hierarchy, TpmiAlgPublic.FromValue(TpmAlgIdConstants.TPM_ALG_ECC), action.Curve, CopyToPrivateKeyCarrier(scalar, EccPrivateKeyTag(action.Curve.Value), pool), Tpm2bName.Empty, action.Attributes, point.ToArray(), Tpm2bPublicKeyRsa.Empty, action.AuthPolicy, action.UserAuth);

        return (outPublic, keyState);
    }

    /// <summary>
    /// <c>TPM2_CreatePrimary()</c> for an RSA storage parent: the RSA counterpart of
    /// <see cref="CreateStorageParentAsync"/>, and the path the standard RSA endorsement key rides.
    /// </summary>
    /// <remarks>
    /// Draws a key from the injected RSA backend, builds the exported storage public area carrying its actual
    /// modulus and the durable parent state (retaining the modulus, unlike <see cref="CreateRsaKeyAsync"/>'s
    /// signing path), then computes the same faithful creation by-products the other CreatePrimary paths do.
    /// The action's userAuth carrier is owned by the action until the durable parent state's construction
    /// adopts it; a throw from the backend generation step or from the artifact-building rents leaves that
    /// rental unreturned until the pool is collected (the automaton itself recovers — the next command clears
    /// the pending action — so a retrying caller repeats the orphan, and the segment is not zeroed until
    /// returned).
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the public area and the by-products buffer transfers to the returned TpmPrimaryKeyCreated, then to the TpmCreatePrimaryResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> CreateRsaStorageParentAsync(TpmCreateRsaStorageParentAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        TpmRsaSigningBackend backend = context.RsaSigningBackend
            ?? throw new InvalidOperationException("TPM2_CreatePrimary() for an RSA storage parent requires an RSA signing backend, but none was supplied.");

        Tpm2bPublic outPublic;
        TransientKeyState keyState;
        using(TpmGeneratedRsaKey key = await backend.GenerateKey(action.KeyBits.Value, context.Pool, cancellationToken).ConfigureAwait(false))
        {
            (outPublic, keyState) = BuildRsaStorageParentArtifacts(action, key, context.Pool);
        }

        try
        {
            //name = nameAlg || H_nameAlg(TPMT_PUBLIC), computed once from the exported public area (which now carries
            //the generated modulus): retained on the parent state and shared with the creation by-products.
            (IMemoryOwner<byte> name, int nameLength) = await ComputeObjectNameAsync(outPublic, action.NameAlg, context.Pool, cancellationToken).ConfigureAwait(false);
            using(name)
            {
                keyState = keyState with { Name = Tpm2bName.Create(name.Memory.Span[..nameLength], context.Pool) };

                (Tpm2bCreationData creationData, Tpm2bDigest creationHash, TpmtTkCreation creationTicket, Tpm2bName framedName) =
                    await BuildCreationByProductsAsync(name.Memory[..nameLength], action.Hierarchy.Value, action.Hierarchy, includeName: true, context, cancellationToken).ConfigureAwait(false);

                return new TpmPrimaryKeyCreated(outPublic, keyState, creationData, creationHash, creationTicket, framedName);
            }
        }
        catch
        {
            //The half-built parent state's only owner is this frame until the install transition adopts it, so a
            //failing Name/by-products step must release its private-key carrier or the pinned rental is orphaned.
            keyState.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Builds the exported storage public area carrying the generated modulus and copies the private key into an
    /// owned, pinned <see cref="PrivateKeyMemory"/> carrier for the durable parent state. Mirrors
    /// <see cref="BuildStorageParentArtifacts"/> for the RSA storage template; synchronous so the key spans
    /// never cross an await.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the built public area transfers to the caller, which carries it to the response intent disposed by SerializeResponse; ownership of the private-key and authValue carriers transfers to the returned TransientKeyState, which the installing transition stores and eviction disposes.")]
    private static (Tpm2bPublic OutPublic, TransientKeyState KeyState) BuildRsaStorageParentArtifacts(TpmCreateRsaStorageParentAction action, TpmGeneratedRsaKey key, BaseMemoryPool pool)
    {
        ReadOnlySpan<byte> modulus = key.Modulus.AsReadOnlySpan();
        ReadOnlySpan<byte> privateKey = key.PrivateKey.AsReadOnlySpan();

        Tpm2bPublic outPublic = Tpm2bPublic.CreateRsaStorageParent(action.NameAlg.Value, action.Attributes, action.KeyBits.Value, modulus, pool, action.AuthPolicy.AsReadOnlySpan());

        //The Name is filled by the caller once it has been computed from the exported public area (through the
        //asynchronous digest seam, which this synchronous copying step must not cross). The modulus is retained
        // so RSA-OAEP secret-transport (the endorsement key is a storage parent) can use this object's public key.
        var keyState = new TransientKeyState(
            action.Handle, action.Hierarchy, TpmiAlgPublic.FromValue(TpmAlgIdConstants.TPM_ALG_RSA), default, CopyToPrivateKeyCarrier(privateKey, RsaPrivateKeyTag(action.KeyBits.Value), pool), Tpm2bName.Empty, action.Attributes, ReadOnlyMemory<byte>.Empty, Tpm2bPublicKeyRsa.Create(modulus, pool), action.AuthPolicy, action.UserAuth);

        return (outPublic, keyState);
    }

    /// <summary>
    /// <c>TPM2_Create()</c> over sessions: decrypts inSensitive's data portion in place when a decrypt session is
    /// present (Part 1, clauses 19 and 21; sessionValue = the decrypt session's sessionKey alone, since the
    /// decrypt session always authorizes no entity of its own — Part 1, clause 21.1's inclusion rule is
    /// independent of the command-HMAC bind-omission rule), THEN decodes inSensitive ‖ inPublic ‖ outsideInfo ‖
    /// creationPCR in full.
    /// </summary>
    /// <remarks>
    /// Every field's interpretation (Part 3, clause 5.8) strictly follows the command HMAC(s) verifying (clause
    /// 5.6) and any decryption (clause 5.7), so none of it can happen at wire-parse time. Bounds-checked reads
    /// throughout (never the throwing <c>Tpm2bSensitiveCreate.Parse</c> for inSensitive) so a wrong decryption
    /// key's garbage bytes report a failure code rather than crash the simulator.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the policy-digest carrier copied out of the scoped public area and of the two sensitive carriers rented as this frame's last act transfers to the returned TpmCreateSensitiveDecrypted, whose completing transition hands all three to the sealing action and whose refusing arms release them through the record's own Dispose; every arm that refuses inside this frame releases the policy digest through the local Fail helper, and a rent that fails after the first sensitive carrier already succeeded releases it in the catch before rethrowing.")]
    private static async ValueTask<TpmSimulatorInput> DecryptCreateSensitiveAsync(TpmDecryptCreateSensitiveAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        //The sealed object's retained policy digest is copied out of the scoped public area further down, where
        //a pool is in scope; it is declared here so every refusing arm below reaches the same terminal release.
        Tpm2bDigest authPolicy = Tpm2bDigest.Empty;

        //The request owns this carrier and cpHash has already covered its octets as ciphertext (Part 3,
        //clause 5.6 precedes clause 5.7), so the transform runs over the very buffer the digest read: the
        //carrier's mutable view is the accessor that expresses that, and no other holder aliases it.
        Memory<byte> parameterArea = action.RawParameterArea.Memory;

        //inSensitive's own outer size field (never itself encrypted, Part 1 clause 21.1) is validated only now,
        //after the command HMAC(s) verified: a declared size exceeding the available bytes is blamed on the
        //decrypt session (session index 1) when one is present — the size problem surfaces only while attempting
        //to decrypt — and reported bare otherwise (mirroring the plain password form's own parser).
        if(parameterArea.Length < sizeof(ushort))
        {
            return Fail(TpmRcConstants.TPM_RC_INSUFFICIENT, sizeBlamesDecryptSession: false);
        }

        ushort innerSize = BinaryPrimitives.ReadUInt16BigEndian(parameterArea.Span[..sizeof(ushort)]);
        if(innerSize > parameterArea.Length - sizeof(ushort))
        {
            return Fail(TpmRcConstants.TPM_RC_SIZE, sizeBlamesDecryptSession: action.HasDecryptSession);
        }

        Memory<byte> dataPortion = parameterArea.Slice(sizeof(ushort), innerSize);

        if(action.HasDecryptSession && !action.Symmetric.IsNull)
        {
            //The keystream's sessionValue is assembled by the shared request-decryption helper, which folds the
            //authorizing slot's live entity authValue and leaves a companion's session key alone (Part 1, clause
            //19.1). A cipher refusal releases the request's parse-rented carriers through the helper.
            await ApplyRequestDecryptionAsync(
                action.Symmetric, action.SessionAlg, action.SessionKey, action.EntityAuthValue,
                action.NonceCaller.AsReadOnlyMemory(), action.NonceTpm.AsReadOnlyMemory(), dataPortion, context.Pool, action.Request as IDisposable, cancellationToken).ConfigureAwait(false);
        }

        //TPMS_SENSITIVE_CREATE: userAuth (TPM2B_AUTH) then data (TPM2B_SENSITIVE_DATA), both bounds-checked reads
        //over inSensitive's OWN data portion only — never the trailing inPublic/outsideInfo/creationPCR bytes.
        //Their extents are recorded rather than copied out: the two carriers are rented from the same octets at
        //the very end of this frame, after every remaining check has passed, so no refused decode ever creates one.
        int userAuthOffset;
        int userAuthLength;
        int secretDataOffset;
        int secretDataLength;
        {
            var sensitiveReader = new TpmReader(dataPortion.Span);
            if(!TryReadTpm2bSpan(ref sensitiveReader, out ReadOnlySpan<byte> userAuthOctets, out TpmRcConstants sensitiveResponseCode))
            {
                return Fail(sensitiveResponseCode, sizeBlamesDecryptSession: false);
            }

            userAuthLength = userAuthOctets.Length;
            userAuthOffset = sensitiveReader.Consumed - userAuthLength;

            //userAuth is a TPM2B_AUTH, which the hash union bounds at sizeof(TPMU_HA) (TPM 2.0 Library Part 2,
            //clause 10.4.5, Table 95 over clause 10.4.2, Table 92), so a recovered value wider than that is not
            //a well-formed structure whatever key produced it — refused here, ahead of the rental whose Create
            //refuses the same bound by throwing.
            if(userAuthLength > Tpm2bAuth.MaxSize)
            {
                return Fail(TpmRcConstants.TPM_RC_SIZE, sizeBlamesDecryptSession: false);
            }

            if(!TryReadTpm2bSpan(ref sensitiveReader, out ReadOnlySpan<byte> secretDataOctets, out sensitiveResponseCode))
            {
                return Fail(sensitiveResponseCode, sizeBlamesDecryptSession: false);
            }

            secretDataLength = secretDataOctets.Length;
            secretDataOffset = sensitiveReader.Consumed - secretDataLength;

            if(sensitiveReader.Remaining != 0)
            {
                return Fail(TpmRcConstants.TPM_RC_SIZE, sizeBlamesDecryptSession: false);
            }
        }

        //Parameter: inPublic (TPM2B_PUBLIC) — never encrypted (only the first parameter, inSensitive, is subject
        //to parameter encryption); decode now that inSensitive's own declared size is known-good.
        Memory<byte> afterSensitive = parameterArea[(sizeof(ushort) + innerSize)..];
        var reader = new TpmReader(afterSensitive.Span);
        if(reader.Remaining < sizeof(ushort))
        {
            return Fail(TpmRcConstants.TPM_RC_INSUFFICIENT, sizeBlamesDecryptSession: false);
        }

        TpmiAlgPublic objectType;
        TpmiAlgHash nameAlg;
        bool noDa;
        bool userWithAuth;
        Tpm2bPublic inPublic;
        try
        {
            inPublic = Tpm2bPublic.Parse(ref reader, context.Pool);
        }
        catch(InvalidOperationException)
        {
            //A TPM2B_DIGEST is bounded by sizeof(TPMU_HA) (TPM 2.0 Library Part 2, clause 10.4.2, Table 92) and
            //inPublic's authPolicy is one, so a wider declared size is TPM_RC_SIZE — the structure parser's only
            //refusal channel is the throw, which this frame answers rather than letting it escape the effect
            //executor. inPublic is never encrypted (only inSensitive, the first parameter, is), so the blame is
            //bare, exactly as every other size failure decoded out of this same unencrypted tail is.
            return Fail(TpmRcConstants.TPM_RC_SIZE, sizeBlamesDecryptSession: false);
        }

        using(inPublic)
        {
            objectType = TpmiAlgPublic.FromValue(inPublic.PublicArea.Type);
            nameAlg = TpmiAlgHash.FromValue(inPublic.PublicArea.NameAlg);

            //The scoped public area owns its own policy carrier and releases it at this using, so the digest the
            //sealed object retains is copied out into a carrier of its own — rented here, where a pool is in
            //scope, and released by Fail on every arm that refuses after this point.
            authPolicy = Tpm2bDigest.Create(inPublic.PublicArea.AuthPolicy.AsReadOnlySpan(), context.Pool);
            noDa = (inPublic.PublicArea.ObjectAttributes & TpmaObject.NO_DA) != 0;
            userWithAuth = (inPublic.PublicArea.ObjectAttributes & TpmaObject.USER_WITH_AUTH) != 0;
        }

        if(objectType.Value != TpmAlgIdConstants.TPM_ALG_KEYEDHASH)
        {
            return Fail(TpmRcConstants.TPM_RC_TYPE, sizeBlamesDecryptSession: false);
        }

        //Parameter: outsideInfo (TPM2B_DATA) — included in creation data; not modelled.
        if(!TrySkipTpm2b(ref reader, out TpmRcConstants outsideInfoRc))
        {
            return Fail(outsideInfoRc, sizeBlamesDecryptSession: false);
        }

        //Parameter: creationPCR (TPML_PCR_SELECTION) — a UINT32 count then that many selections, skipped.
        if(!TrySkipPcrSelection(ref reader, out TpmRcConstants creationPcrRc))
        {
            return Fail(creationPcrRc, sizeBlamesDecryptSession: false);
        }

        if(reader.Remaining != 0)
        {
            return Fail(TpmRcConstants.TPM_RC_SIZE, sizeBlamesDecryptSession: false);
        }

        //The sealed object's two sensitive carriers are rented here, this frame's last act after every shape
        //check has passed; the completing transition transfers them into the sealing action, whose effect is
        //their terminal owner, and every refusing arm releases them through the returned record's own Dispose.
        Tpm2bSensitiveData secretData = Tpm2bSensitiveData.Empty;
        try
        {
            secretData = Tpm2bSensitiveData.Create(dataPortion.Span.Slice(secretDataOffset, secretDataLength), context.Pool);

            return new TpmCreateSensitiveDecrypted(
                TpmRcConstants.TPM_RC_SUCCESS, SizeFailureBlamesDecryptSession: false, action.Request,
                nameAlg, authPolicy, noDa, userWithAuth, secretData,
                Tpm2bAuth.Create(dataPortion.Span.Slice(userAuthOffset, userAuthLength), context.Pool));
        }
        catch
        {
            //These carriers' only owner is this frame until the returned record adopts them, so a failing later
            //rent must release them or the pinned rentals are orphaned.
            secretData.Dispose();
            authPolicy.Dispose();
            throw;
        }

        //Local one-off helper: builds the uniform failure shape every early-return site above needs, releasing
        //the policy-digest carrier first — a refusal hands it to no later owner, so this frame is terminal for
        //it (the dispose-immune empty sentinel on the arms that refuse before the public area is decoded).
        TpmCreateSensitiveDecrypted Fail(TpmRcConstants responseCode, bool sizeBlamesDecryptSession)
        {
            authPolicy.Dispose();

            return new(responseCode, sizeBlamesDecryptSession, action.Request,
                default, Tpm2bDigest.Empty, false, false, Tpm2bSensitiveData.Empty, Tpm2bAuth.Empty);
        }
    }

    /// <summary>
    /// Decrypts <c>TPM2_NV_DefineSpace()</c>'s <c>auth</c> first command parameter and reads back its plaintext
    /// value (TPM 2.0 Library Part 3, Section 31.3; Part 1, Section 21) — the request-decrypt counterpart of
    /// <see cref="DecryptCreateSensitiveAsync"/>, run only when the authorizing session itself carries the
    /// <c>decrypt</c> attribute and strictly after that session's command HMAC verified.
    /// </summary>
    /// <remarks>
    /// The keystream is derived from the SAME sessionValue the session's command HMAC used, with the
    /// command-direction nonce ordering (nonceNewer = nonceCaller, nonceOlder = nonceTPM, Part 1, Section 19.2),
    /// through the production <c>TpmParameterEncryption</c> primitives so it matches the host's own encryption by
    /// construction. Only the data portion after the <c>auth</c> field's 2-octet size prefix is transformed (the
    /// size itself is never encrypted, Part 1, Section 21.1); a size field that overruns the captured parameter
    /// bytes is <c>TPM_RC_SIZE</c>.
    /// </remarks>
    /// <param name="action">The declared action carrying the encrypted parameter area and the session's decrypt keying material.</param>
    /// <param name="context">The effect context supplying the memory pool.</param>
    /// <param name="cancellationToken">A token observed across the keystream derivation.</param>
    /// <returns>The decrypted plaintext <c>auth</c> value paired with the request to resume, fed back to <c>OnNvDefineAuthDecrypted</c>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the recovered-auth carrier transfers to the returned TpmNvDefineAuthDecrypted, whose installing transition adopts it and whose refusing arm disposes it through the input's own Dispose.")]
    private static async ValueTask<TpmSimulatorInput> DecryptNvDefineAuthAsync(TpmDecryptNvDefineAuthAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        //The request owns this carrier and cpHash has already covered its octets as ciphertext (Part 3,
        //clause 5.6 precedes clause 5.7), so the transform runs over the very buffer the digest read: the
        //carrier's mutable view is the accessor that expresses that, and no other holder aliases it.
        Memory<byte> parameterArea = action.RawParameterArea.Memory;

        //auth (TPM2B_AUTH) is the first parameter: a 2-octet size (never itself encrypted) then that many data
        //octets. A size overrunning the captured bytes is malformed.
        if(parameterArea.Length < sizeof(ushort))
        {
            return new TpmNvDefineAuthDecrypted(TpmRcConstants.TPM_RC_INSUFFICIENT, action.Request, Tpm2bAuth.Empty);
        }

        ushort authSize = BinaryPrimitives.ReadUInt16BigEndian(parameterArea.Span[..sizeof(ushort)]);
        //Two size rules, one answer: the declared size must fit the captured parameter area, and it must fit a
        //TPM2B_AUTH at all — the hash union bounds that structure at sizeof(TPMU_HA) (TPM 2.0 Library Part 2,
        //clause 10.4.5, Table 95 over clause 10.4.2, Table 92), so a wider recovered value is malformed
        //whatever key produced it. The command's own narrower per-entity rule stays on the installing tail.
        if(authSize > parameterArea.Length - sizeof(ushort) || authSize > Tpm2bAuth.MaxSize)
        {
            return new TpmNvDefineAuthDecrypted(TpmRcConstants.TPM_RC_SIZE, action.Request, Tpm2bAuth.Empty);
        }

        Memory<byte> authData = parameterArea.Slice(sizeof(ushort), authSize);

        if(!action.Symmetric.IsNull)
        {
            //sessionValue = sessionKey ‖ StripTrailingZeros(authValue) (Part 1, clause 19.1), assembled by the
            //shared request-decryption helper in pinned pooled scratch cleared before release. The entity term
            //here is the owner hierarchy's LIVE authValue, unresolved by the session's bind, because parameter
            //encryption ignores the binding even where the command HMAC key omits the term.
            await ApplyRequestDecryptionAsync(
                action.Symmetric, action.SessionAlg, action.SessionKey, action.EntityAuthValue,
                action.NonceCaller.AsReadOnlyMemory(), action.NonceTpm.AsReadOnlyMemory(), authData, context.Pool, action.Request as IDisposable, cancellationToken).ConfigureAwait(false);
        }

        return new TpmNvDefineAuthDecrypted(TpmRcConstants.TPM_RC_SUCCESS, action.Request, Tpm2bAuth.Create(authData.Span, context.Pool));
    }

    /// <summary>
    /// Decrypts <c>TPM2_NV_ChangeAuth()</c>'s <c>newAuth</c> first command parameter and reads back its plaintext
    /// value (TPM 2.0 Library Part 3, clause 31.15; Part 1, clause 19.1) — run only when a SEPARATE session in
    /// the authorization area carries the <c>decrypt</c> attribute, and strictly after every session in that area
    /// has had its command HMAC verified.
    /// </summary>
    /// <remarks>
    /// The keystream is derived from the decrypt session's own <c>sessionValue</c>, which is its session key
    /// alone because that session authorizes no entity (Part 1, clause 19.1) — the one structural difference from
    /// <see cref="DecryptNvDefineAuthAsync"/>, whose single session does both jobs and so folds the entity's
    /// authValue in. Command-direction nonce ordering applies (nonceNewer = nonceCaller, nonceOlder = nonceTPM,
    /// Part 1, clause 19.2), and only the data portion after the 2-octet size prefix is transformed (the size is
    /// never encrypted, clause 19.1); a size field overrunning the captured parameter bytes is
    /// <c>TPM_RC_SIZE</c>. The production <c>TpmParameterEncryption</c> primitives are used, so the transform
    /// matches the host's own encryption by construction.
    /// </remarks>
    /// <param name="action">The declared action carrying the encrypted parameter area and the decrypt session's keying material.</param>
    /// <param name="context">The effect context supplying the memory pool.</param>
    /// <param name="cancellationToken">A token observed across the keystream derivation.</param>
    /// <returns>The decrypted plaintext <c>newAuth</c> paired with the request to resume, fed back to <c>OnNvChangeAuthDecrypted</c>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the recovered-newAuth carrier transfers to the returned TpmNvChangeAuthDecrypted, whose installing transition adopts it and whose refusing arm disposes it through the input's own Dispose.")]
    private static async ValueTask<TpmSimulatorInput> DecryptNvChangeAuthAsync(TpmDecryptNvChangeAuthAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        //The request owns this carrier and cpHash has already covered its octets as ciphertext (Part 3,
        //clause 5.6 precedes clause 5.7), so the transform runs over the very buffer the digest read: the
        //carrier's mutable view is the accessor that expresses that, and no other holder aliases it.
        Memory<byte> parameterArea = action.RawParameterArea.Memory;

        if(parameterArea.Length < sizeof(ushort))
        {
            return new TpmNvChangeAuthDecrypted(TpmRcConstants.TPM_RC_INSUFFICIENT, action.Request, Tpm2bAuth.Empty);
        }

        ushort newAuthSize = BinaryPrimitives.ReadUInt16BigEndian(parameterArea.Span[..sizeof(ushort)]);
        //Two size rules, one answer: the declared size must fit the captured parameter area, and it must fit a
        //TPM2B_AUTH at all — the hash union bounds that structure at sizeof(TPMU_HA) (TPM 2.0 Library Part 2,
        //clause 10.4.5, Table 95 over clause 10.4.2, Table 92), so a wider recovered value is malformed
        //whatever key produced it. The command's own narrower per-entity rule stays on the installing tail.
        if(newAuthSize > parameterArea.Length - sizeof(ushort) || newAuthSize > Tpm2bAuth.MaxSize)
        {
            return new TpmNvChangeAuthDecrypted(TpmRcConstants.TPM_RC_SIZE, action.Request, Tpm2bAuth.Empty);
        }

        Memory<byte> newAuthData = parameterArea.Slice(sizeof(ushort), newAuthSize);

        if(!action.Symmetric.IsNull)
        {
            //The keystream's sessionValue is assembled by the shared request-decryption helper: this command's
            //decrypt companion authorizes no entity, so its empty entity authValue leaves the session key alone
            //(Part 1, clause 19.1).
            await ApplyRequestDecryptionAsync(
                action.Symmetric, action.SessionAlg, action.SessionKey, action.EntityAuthValue,
                action.NonceCaller.AsReadOnlyMemory(), action.NonceTpm.AsReadOnlyMemory(), newAuthData, context.Pool, action.Request as IDisposable, cancellationToken).ConfigureAwait(false);
        }

        return new TpmNvChangeAuthDecrypted(TpmRcConstants.TPM_RC_SUCCESS, action.Request, Tpm2bAuth.Create(newAuthData.Span, context.Pool));
    }

    /// <summary>
    /// Recovers an attest command's <c>qualifyingData</c> first command parameter in plaintext — decrypting it in
    /// place over the one slot carrying the <c>decrypt</c> attribute, or reading it straight through when no slot
    /// carried it (TPM 2.0 Library Part 3, clause 5.7; Part 1, clause 19.1) — for <c>TPM2_Certify()</c>,
    /// <c>TPM2_CertifyCreation()</c>, <c>TPM2_Quote()</c>, <c>TPM2_GetTime()</c>, and <c>TPM2_NV_Certify()</c>
    /// alike.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The step runs for every session-authorized arrival, not only an encrypted one, so the recovered value has
    /// exactly one origin and the width bound below is enforced in exactly one place. The keystream, where one
    /// applies, is derived through the shared request-decryption helper with the command-direction nonce ordering
    /// (nonceNewer is nonceCaller, nonceOlder is nonceTPM, clause 19.2), and only the data portion after the
    /// 2-octet size prefix is transformed — the size field is never protected (clause 19.1).
    /// </para>
    /// <para>
    /// Both size failures are the ones the reference's own decryption routine names — a parameter area too short
    /// to hold the size field is <c>TPM_RC_INSUFFICIENT</c>, a declared size overrunning that area is
    /// <c>TPM_RC_SIZE</c> — and both are session-index-encoded to the decrypt slot by the resuming transition.
    /// For this family the wire parser must already step over the same framing to reach the parameters behind
    /// <c>qualifyingData</c>, so it answers a malformed frame first and these two arms stand as the fail-closed
    /// backstop; the <c>TPM2B_DATA</c> width bound, by contrast, is FIRST answered here, because the parser
    /// cannot check a bound that belongs to a value it has not yet decrypted.
    /// </para>
    /// </remarks>
    /// <param name="action">The declared action carrying the captured parameter area and, when a slot decrypts, that session's keying material.</param>
    /// <param name="context">The effect context supplying the memory pool.</param>
    /// <param name="cancellationToken">A token observed across the keystream derivation.</param>
    /// <returns>The recovered plaintext <c>qualifyingData</c> paired with the request to resume, fed back to <c>OnAttestQualifyingDataDecrypted</c>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the recovered qualifying-data carrier transfers to the returned TpmAttestQualifyingDataDecrypted, whose resuming transition adopts it into the request it rebuilds and whose refusing arms dispose it through the input's own Dispose.")]
    private static async ValueTask<TpmSimulatorInput> DecryptAttestQualifyingDataAsync(
        TpmDecryptAttestQualifyingDataAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        //The request owns this carrier and cpHash has already covered its octets as ciphertext (Part 3,
        //clause 5.6 precedes clause 5.7), so the transform runs over the very buffer the digest read: the
        //carrier's mutable view is the accessor that expresses that, and no other holder aliases it.
        Memory<byte> parameterArea = action.RawParameterArea.Memory;

        //qualifyingData (TPM2B_DATA) is the first parameter: a 2-octet size (never itself encrypted) then that
        //many data octets.
        if(parameterArea.Length < sizeof(ushort))
        {
            return Fail(TpmRcConstants.TPM_RC_INSUFFICIENT);
        }

        ushort dataSize = BinaryPrimitives.ReadUInt16BigEndian(parameterArea.Span[..sizeof(ushort)]);
        if(dataSize > parameterArea.Length - sizeof(ushort))
        {
            return Fail(TpmRcConstants.TPM_RC_SIZE);
        }

        Memory<byte> qualifyingData = parameterArea.Slice(sizeof(ushort), dataSize);

        if(action.Decrypts && !action.Symmetric.IsNull)
        {
            //sessionValue = sessionKey ‖ StripTrailingZeros(authValue) when the decrypt session also authorizes
            //an entity, sessionKey alone when it is a companion (Part 1, clause 19.1), assembled by the shared
            //request-decryption helper in pinned pooled scratch cleared before release.
            await ApplyRequestDecryptionAsync(
                action.Symmetric, action.SessionAlg, action.SessionKey, action.EntityAuthValue,
                action.NonceCaller.AsReadOnlyMemory(), action.NonceTpm.AsReadOnlyMemory(), qualifyingData, context.Pool, action.Request as IDisposable, cancellationToken).ConfigureAwait(false);
        }

        //TPM2B_DATA is bounded by sizeof(TPMT_HA) (Part 2, clause 10.4.3, Table 93). The bound belongs to the
        //PLAINTEXT value, which is why it is checked here rather than at the wire parse: a decrypt session's
        //ciphertext is the same width as its plaintext, but only the recovered octets are the TPM2B_DATA the
        //bound is about. The resuming transition keeps the same check as its fail-closed backstop.
        if(dataSize > Tpm2bData.MaxSize)
        {
            return Fail(TpmRcConstants.TPM_RC_SIZE);
        }

        return new TpmAttestQualifyingDataDecrypted(
            TpmRcConstants.TPM_RC_SUCCESS, action.CommandCode, action.DecryptSessionIndex, action.Request,
            Tpm2bData.Create(qualifyingData.Span, context.Pool));

        //Local one-off helper: builds the uniform failure shape every early-return site above needs, carrying the
        //slot a failure is blamed on so the resuming transition needs no rule of its own.
        TpmAttestQualifyingDataDecrypted Fail(TpmRcConstants responseCode) =>
            new(responseCode, action.CommandCode, action.DecryptSessionIndex, action.Request, Tpm2bData.Empty);
    }

    /// <summary>
    /// Decrypts <c>TPM2_HierarchyChangeAuth()</c>'s <c>newAuth</c> first command parameter and reads back its
    /// plaintext value (TPM 2.0 Library Part 3, clause 24.8; Part 1, clause 19.1) — the hierarchy-family
    /// counterpart of <see cref="DecryptNvChangeAuthAsync"/>, run only when a SEPARATE session in the
    /// authorization area carries the <c>decrypt</c> attribute and strictly after every session in that area has
    /// had its command HMAC verified.
    /// </summary>
    /// <remarks>
    /// The keystream is derived from the decrypt session's own <c>sessionValue</c>, its session key alone,
    /// because that session authorizes no entity (Part 1, clause 19.1). Command-direction nonce ordering applies
    /// (nonceNewer = nonceCaller, nonceOlder = nonceTPM, clause 19.2), and only the data portion after the
    /// 2-octet size prefix is transformed (the size is never encrypted); a size field overrunning the captured
    /// parameter bytes is <c>TPM_RC_SIZE</c>. The production <c>TpmParameterEncryption</c> primitives are used, so
    /// the transform matches the host's own encryption by construction.
    /// </remarks>
    /// <param name="action">The declared action carrying the encrypted parameter area and the decrypt session's keying material.</param>
    /// <param name="context">The effect context supplying the memory pool.</param>
    /// <param name="cancellationToken">A token observed across the keystream derivation.</param>
    /// <returns>The decrypted plaintext <c>newAuth</c> paired with the request to resume, fed back to <c>OnHierarchyChangeAuthDecrypted</c>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the recovered-newAuth carrier transfers to the returned TpmHierarchyChangeAuthDecrypted, whose installing transition adopts it and whose refusing arm disposes it through the input's own Dispose.")]
    private static async ValueTask<TpmSimulatorInput> DecryptHierarchyChangeAuthAsync(TpmDecryptHierarchyChangeAuthAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        //The request owns this carrier and cpHash has already covered its octets as ciphertext (Part 3,
        //clause 5.6 precedes clause 5.7), so the transform runs over the very buffer the digest read: the
        //carrier's mutable view is the accessor that expresses that, and no other holder aliases it.
        Memory<byte> parameterArea = action.RawParameterArea.Memory;

        if(parameterArea.Length < sizeof(ushort))
        {
            return new TpmHierarchyChangeAuthDecrypted(TpmRcConstants.TPM_RC_INSUFFICIENT, action.Request, Tpm2bAuth.Empty);
        }

        ushort newAuthSize = BinaryPrimitives.ReadUInt16BigEndian(parameterArea.Span[..sizeof(ushort)]);
        //Two size rules, one answer: the declared size must fit the captured parameter area, and it must fit a
        //TPM2B_AUTH at all — the hash union bounds that structure at sizeof(TPMU_HA) (TPM 2.0 Library Part 2,
        //clause 10.4.5, Table 95 over clause 10.4.2, Table 92), so a wider recovered value is malformed
        //whatever key produced it. The command's own narrower per-entity rule stays on the installing tail.
        if(newAuthSize > parameterArea.Length - sizeof(ushort) || newAuthSize > Tpm2bAuth.MaxSize)
        {
            return new TpmHierarchyChangeAuthDecrypted(TpmRcConstants.TPM_RC_SIZE, action.Request, Tpm2bAuth.Empty);
        }

        Memory<byte> newAuthData = parameterArea.Slice(sizeof(ushort), newAuthSize);

        if(!action.Symmetric.IsNull)
        {
            //The keystream's sessionValue is assembled by the shared request-decryption helper: this command's
            //decrypt companion authorizes no entity, so its empty entity authValue leaves the session key alone
            //(Part 1, clause 19.1).
            await ApplyRequestDecryptionAsync(
                action.Symmetric, action.SessionAlg, action.SessionKey, action.EntityAuthValue,
                action.NonceCaller.AsReadOnlyMemory(), action.NonceTpm.AsReadOnlyMemory(), newAuthData, context.Pool, action.Request as IDisposable, cancellationToken).ConfigureAwait(false);
        }

        return new TpmHierarchyChangeAuthDecrypted(TpmRcConstants.TPM_RC_SUCCESS, action.Request, Tpm2bAuth.Create(newAuthData.Span, context.Pool));
    }

    /// <summary>
    /// Draws <c>TPM2_Clear()</c>'s replacement storage primary seed from the injected random-number backend
    /// (TPM 2.0 Library Part 3, clause 24.6.1) — the only effect the clear needs, since the transition that
    /// applies every other listed effect is pure.
    /// </summary>
    /// <remarks>
    /// The draw goes into a pooled scratch buffer, exactly as <see cref="GenerateRandom"/>'s does, and is
    /// copied into an owned, pinned <see cref="StorageProofSeed"/> carrier before the scratch is zeroed and
    /// released: the carrier becomes <see cref="TpmSimulatorState.StorageProofSeed"/> at the installing
    /// transition (which disposes the one it replaces) and so outlives both the command and the scratch
    /// rental. It is the key material every owner- and endorsement-hierarchy proof derives from, which is why
    /// the scratch is cleared rather than merely returned.
    /// </remarks>
    /// <param name="action">The declared action carrying the seed width and the request to resume.</param>
    /// <param name="context">The effect context supplying the random-number backend and the memory pool.</param>
    /// <returns>The freshly drawn seed paired with the request to resume, fed back to <c>OnStorageProofSeedGenerated</c>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the seed carrier transfers to the returned TpmStorageProofSeedGenerated, whose installing transition adopts it into TpmSimulatorState.StorageProofSeed and whose refusing arm disposes it through the input's own Dispose.")]
    private static TpmStorageProofSeedGenerated GenerateStorageProofSeed(TpmGenerateStorageProofSeedAction action, TpmActionContext context)
    {
        using IMemoryOwner<byte> owner = context.Pool.Rent(action.SeedSize);
        Span<byte> seed = owner.Memory.Span[..action.SeedSize];
        try
        {
            context.Rng(seed);

            return new TpmStorageProofSeedGenerated(StorageProofSeed.Create(seed, context.Pool), action.Resume);
        }
        finally
        {
            seed.Clear();
        }
    }

    /// <summary>
    /// <c>TPM2_Create()</c> sealing: build the exported sealed-object public area (the sealed-data template,
    /// reproduced from the template fields), the wrapped private blob (the simulator's own encoding of the
    /// sealed octets — it models no parent-key encryption/integrity, having no parent symmetric-key custody),
    /// and the same faithful creation by-products, minus the Name (<c>TPM2_Create()</c> returns no Name).
    /// </summary>
    /// <remarks>
    /// Ownership of all three flows to <see cref="TpmObjectSealed"/>, then to the <c>TpmCreateResponse</c>
    /// intent, and is released by <see cref="SerializeResponse"/> after framing. This effect is the terminal
    /// owner of the action's secret, userAuth, and authorization-policy-digest carriers —
    /// <c>TPM2_Create()</c> installs no durable state, the created object existing only as the returned blob —
    /// so all three are released here once the artifacts are built.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the public area, the private blob, and the by-products buffer transfers to the returned TpmObjectSealed, then to the TpmCreateResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> SealDataAsync(TpmSealDataAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        Tpm2bPublic outPublic;
        Tpm2bPrivate privateBlob;
        Tpm2bCreationData creationData;
        Tpm2bDigest creationHash;
        TpmtTkCreation creationTicket;
        try
        {
            (outPublic, privateBlob, creationData, creationHash, creationTicket) =
                await BuildSealedObjectArtifactsAsync(
                    action.ParentHandle.Value, action.ParentHierarchy, action.NameAlg, action.AuthPolicy, action.NoDa, action.UserWithAuth,
                    action.SecretData.AsReadOnlyMemory(), action.UserAuth.AsReadOnlyMemory(), context, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            action.SecretData.Dispose();
            action.UserAuth.Dispose();
            action.AuthPolicy.Dispose();
        }

        return new TpmObjectSealed(privateBlob, outPublic, creationData, creationHash, creationTicket);
    }

    /// <summary>
    /// <c>TPM2_Create()</c> over sessions: the request-decrypt counterpart of <see cref="SealDataAsync"/>.
    /// </summary>
    /// <remarks>
    /// Builds the SAME sealed-object artifacts through the shared helper, then — because a real (HMAC-table)
    /// session in this command's authorization area needs a genuine response HMAC, unlike the plain password
    /// form — frames the response parameter area (outPrivate ‖ outPublic ‖ creationByProducts, never encrypted
    /// here), rolls a fresh nonceTPM per real session, computes rpHash over it, and each real session's own
    /// response HMAC keyed on its own sessionKey ‖ authValue (Part 1, clause 17.6.8) — mirroring
    /// <see cref="UnsealOverSessionsAsync"/>'s per-session loop. This effect is the terminal owner of the
    /// action's secret, userAuth, and authorization-policy-digest carriers, exactly as
    /// <see cref="SealDataAsync"/> is: <c>TPM2_Create()</c> installs no durable state, so the wrapped private
    /// blob the artifacts step packs them into is their only use.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parameter-area and each entry's HMAC buffer transfers to the returned TpmObjectSealedOverSessions, then to the TpmCreateOverSessionsResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> SealDataOverSessionsAsync(TpmSealDataOverSessionsAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        //This frame is the terminal owner of the caller-nonce carrier every response-session entry owns — the
        //TPM2B_NONCE its slot's request record transferred into it — discharging the obligation once the
        //response HMACs have read the nonces as their nonceOlder term (Part 1, clause 17.6.5), on the success,
        //sealing-failure, and framing-failure paths alike.
        try
        {
            return await SealDataOverSessionsCoreAsync(action, context, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            foreach(TpmCreateResponseSession responseSession in action.ResponseSessions)
            {
                responseSession.NonceCaller.Dispose();
            }
        }
    }

    /// <summary>
    /// Runs <see cref="SealDataOverSessionsAsync"/>'s object building and response framing, with that frame
    /// owning the release of the response-session entries' transferred caller nonces.
    /// </summary>
    /// <param name="action">The declared seal action; its response-session nonces are read here and released by the caller.</param>
    /// <param name="context">The effect context supplying the RNG, the digest and HMAC seams, and the memory pool.</param>
    /// <param name="cancellationToken">The token to observe.</param>
    /// <returns>The framed response pieces to feed back to the transition.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parameter-area and each entry's HMAC buffer transfers to the returned TpmObjectSealedOverSessions, then to the TpmCreateOverSessionsResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> SealDataOverSessionsCoreAsync(TpmSealDataOverSessionsAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        Tpm2bPublic outPublic;
        Tpm2bPrivate privateBlob;
        Tpm2bCreationData creationData;
        Tpm2bDigest creationHash;
        TpmtTkCreation creationTicket;
        try
        {
            (outPublic, privateBlob, creationData, creationHash, creationTicket) =
                await BuildSealedObjectArtifactsAsync(
                    action.ParentHandle.Value, action.ParentHierarchy, action.NameAlg, action.AuthPolicy, action.NoDa, action.UserWithAuth,
                    action.SecretData.AsReadOnlyMemory(), action.UserAuth.AsReadOnlyMemory(), context, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            action.SecretData.Dispose();
            action.UserAuth.Dispose();
            action.AuthPolicy.Dispose();
        }

        using(privateBlob)
        using(outPublic)
        using(creationData)
        using(creationHash)
        using(creationTicket)
        {
            //Frame outPrivate ‖ outPublic ‖ creationData ‖ creationHash ‖ creationTicket exactly as
            //SerializeCreateOverSessionsResponse will write it, so rpHash covers the SAME bytes (Part 1, clause
            //16.8 equation 16).
            int outPublicSize = outPublic.GetSerializedSize();
            int parameterLength =
                privateBlob.SerializedSize
                + outPublicSize
                + creationData.SerializedSize
                + creationHash.SerializedSize
                + creationTicket.SerializedSize;
            IMemoryOwner<byte> parameterArea = context.Pool.Rent(Math.Max(parameterLength, 1));
            try
            {
                {
                    var parameterWriter = new TpmWriter(parameterArea.Memory.Span[..parameterLength]);
                    privateBlob.WriteTo(ref parameterWriter);
                    outPublic.WriteTo(ref parameterWriter);
                    creationData.WriteTo(ref parameterWriter);
                    creationHash.WriteTo(ref parameterWriter);
                    creationTicket.WriteTo(ref parameterWriter);
                }

                if(action.ResponseSessions.IsEmpty)
                {
                    //Only the password placeholder is needed (a TPM_RS_PW parent-auth session with no decrypt
                    //companion) — no rpHash/HMAC computation, mirroring how a plain policy-gated Unseal with no
                    //encrypt session needs none either.
                    return new TpmObjectSealedOverSessions(
                        TpmParameterArea.Adopt(parameterArea, parameterLength), action.HasPasswordPlaceholder, action.PasswordPlaceholderAttributes,
                        ImmutableArray<TpmCreateFramedSessionEntry>.Empty);
                }

                //rpHash computed once per DISTINCT session hash algorithm (Part 1, clause 16.8, equation 16): each
                //real session verifies its response HMAC against its OWN algorithm's rpHash, never one session's
                //hash shared by every session (the host-side mirror lives in TpmCommandExecutor.ExecuteAsync).
                var sessionAlgs = new TpmiAlgHash[action.ResponseSessions.Length];
                for(int i = 0; i < action.ResponseSessions.Length; i++)
                {
                    sessionAlgs[i] = action.ResponseSessions[i].SessionAlg;
                }

                (Tpm2bNonce[] framedNonces, Tpm2bNonce[] retainedNonces) = RollSessionNonces(sessionAlgs, context);
                try
                {
                    (Memory<byte>[] rpHashPerSession, List<(TpmiAlgHash Alg, IMemoryOwner<byte> Owner)> rpHashOwners) = await ComputeRpHashPerSessionAsync(
                        sessionAlgs, TpmCcConstants.TPM_CC_Create, parameterArea.Memory[..parameterLength], context.Pool, cancellationToken).ConfigureAwait(false);
                    try
                    {
                        var entries = ImmutableArray.CreateBuilder<TpmCreateFramedSessionEntry>(action.ResponseSessions.Length);
                        for(int i = 0; i < action.ResponseSessions.Length; i++)
                        {
                            TpmCreateResponseSession session = action.ResponseSessions[i];

                            ReadOnlyMemory<byte> sessionKeyBytes = session.SessionKey.AsReadOnlyMemory();
                            ReadOnlyMemory<byte> authValueBytes = TpmLifecycleTransitions.StripTrailingZeros(session.AuthValue.AsReadOnlyMemory());
                            int sessionValueLength = sessionKeyBytes.Length + authValueBytes.Length;
                            using IMemoryOwner<byte> sessionValueOwner = context.Pool.Rent(Math.Max(sessionValueLength, 1), AllocationKind.Pinned);
                            Memory<byte> sessionValue = sessionValueOwner.Memory[..sessionValueLength];
                            sessionKeyBytes.CopyTo(sessionValue);
                            authValueBytes.CopyTo(sessionValue[sessionKeyBytes.Length..]);

                            Tpm2bAuth hmac = await ComputeResponseHmacAsync(
                                session.SessionAlg, sessionValue, rpHashPerSession[i], framedNonces[i].AsReadOnlyMemory(), session.NonceCaller.AsReadOnlyMemory(), session.SessionAttributes, context.Pool, cancellationToken).ConfigureAwait(false);

                            sessionValueOwner.Memory.Span[..sessionValueLength].Clear();

                            entries.Add(new TpmCreateFramedSessionEntry(session.SessionHandle, framedNonces[i], retainedNonces[i], session.SessionAttributes, hmac));
                        }

                        return new TpmObjectSealedOverSessions(
                            TpmParameterArea.Adopt(parameterArea, parameterLength), action.HasPasswordPlaceholder, action.PasswordPlaceholderAttributes, entries.MoveToImmutable());
                    }
                    finally
                    {
                        foreach(var cached in rpHashOwners)
                        {
                            cached.Owner.Dispose();
                        }
                    }
                }
                catch
                {
                    //The rolled pairs' only owner is this frame until the framed entries adopt them.
                    ReleaseSessionNonces(framedNonces, retainedNonces);
                    throw;
                }
            }
            catch
            {
                parameterArea.Dispose();
                throw;
            }
        }
    }

    /// <summary>
    /// Shared by <see cref="SealDataAsync"/> and <see cref="SealDataOverSessionsAsync"/>: builds the exported
    /// sealed-object public area, the wrapped private blob, and the faithful creation by-products (minus the
    /// Name, which <c>TPM2_Create()</c> does not return) — the object-building logic common to both the plain
    /// password form and the session-authorized form.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the public area, the private blob, and the by-products buffer transfers to the caller, which carries them to whichever response intent SerializeResponse releases after framing; a failure part-way through releases every carrier already rented in this frame.")]
    private static async ValueTask<(Tpm2bPublic OutPublic, Tpm2bPrivate PrivateBlob, Tpm2bCreationData CreationData, Tpm2bDigest CreationHash, TpmtTkCreation CreationTicket)> BuildSealedObjectArtifactsAsync(
        uint parentHandle, TpmiRhHierarchy parentHierarchy, TpmiAlgHash nameAlg, Tpm2bDigest authPolicy, bool noDa, bool userWithAuth,
        ReadOnlyMemory<byte> secretData, ReadOnlyMemory<byte> userAuth, TpmActionContext context, CancellationToken cancellationToken)
    {
        Tpm2bPublic outPublic = Tpm2bPublic.CreateSealedDataTemplate(nameAlg.Value, context.Pool, authPolicy.AsReadOnlySpan(), noDa, userWithAuth);
        Tpm2bPrivate privateBlob = Tpm2bPrivate.Empty;
        try
        {
            //The packer rents the blob octets itself, so the TPM2B_PRIVATE carrier adopts that rental rather than copying it.
            privateBlob = Tpm2bPrivate.FromMarshaled(PackSealedPrivateBlob(userAuth, secretData, context.Pool, out int privateBlobLength), privateBlobLength);

            //The sealed object is not loaded, so its Name is not retained; it is still computed to key the creation
            //ticket HMAC (TPM 2.0 Library Part 2, clause 10.7). No handle is allocated, so nothing carries the Name past here.
            (IMemoryOwner<byte> name, int nameLength) = await ComputeObjectNameAsync(outPublic, nameAlg, context.Pool, cancellationToken).ConfigureAwait(false);
            using(name)
            {
                (Tpm2bCreationData creationData, Tpm2bDigest creationHash, TpmtTkCreation creationTicket, Tpm2bName framedName) =
                    await BuildCreationByProductsAsync(name.Memory[..nameLength], parentHandle, parentHierarchy, includeName: false, context, cancellationToken).ConfigureAwait(false);

                //TPM2_Create() returns no Name, so the by-products carry the dispose-immune empty sentinel there.
                framedName.Dispose();

                return (outPublic, privateBlob, creationData, creationHash, creationTicket);
            }
        }
        catch
        {
            //These two carriers are rented ahead of the Name digest and the by-product build, and this frame is
            //their only owner until the caller adopts the returned tuple, so a throw in either awaited step
            //must release them or the rentals are orphaned.
            privateBlob.Dispose();
            outPublic.Dispose();
            throw;
        }
    }

    /// <summary>
    /// <c>TPM2_Load()</c>: recover the sealed data from the wrapped blob (it is the simulator's own encoding, so
    /// the blob octets are the sealed data) and compute the object Name over the loaded public area through the
    /// registered digest seam.
    /// </summary>
    /// <remarks>
    /// The Name is computed once and carried in TWO owned carriers, because the framed response and the stored
    /// object are separate owners whose lifetimes do not nest: the first flows to <see cref="TpmObjectLoaded"/>,
    /// then to the <c>TpmLoadResponse</c> intent, and is released by <see cref="SerializeResponse"/> after
    /// framing; the second transfers into the stored <see cref="SealedObjectState"/> and lives until the object
    /// is evicted. Two rentals rather than one shared buffer is the same rule <see cref="PersistObject"/>'s deep
    /// copy applies, so neither owner's disposal can reach the other's octets. This effect is the terminal owner
    /// of the caller-supplied public area: hashing its marshaled <c>TPMT_PUBLIC</c> into the Name is its only
    /// use, and nothing downstream reads it, so it is released here on every path.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of both Name carriers transfers to the returned TpmObjectLoaded — one onward to the TpmLoadResponse intent released by SerializeResponse after framing, one onward to the stored SealedObjectState released at eviction — and the refusing arm disposes both through the input's own Dispose; a rent that fails after the first carrier already succeeded releases it in the catch before rethrowing.")]
    private static async ValueTask<TpmSimulatorInput> LoadObjectAsync(TpmLoadObjectAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        //The action's authorization-policy carrier is owned from the moment the effect is entered, so the Name
        //computation runs INSIDE the guarded frame too: a digest seam that throws must reach the catch that
        //releases it, exactly as a failing rent below does.
        Tpm2bName name = Tpm2bName.Empty;
        Tpm2bName retainedName = Tpm2bName.Empty;
        try
        {
            (IMemoryOwner<byte> nameStorage, int nameLength) = await ComputeObjectNameFromBytesAsync(
                action.InPublic.GetRawMemory(), action.NameAlg, context.Pool, cancellationToken).ConfigureAwait(false);

            //The Name helper rents the framed octets itself, so the carrier adopts that rental rather than copying it.
            name = Tpm2bName.FromMarshaled(nameStorage, nameLength);
            retainedName = Tpm2bName.Create(name.Span, context.Pool);
            UnpackSealedPrivateBlob(action.PrivateBlob, context.Pool, out Tpm2bAuth userAuth, out Tpm2bSensitiveData secretData);

            return new TpmObjectLoaded(action.Handle, name, retainedName, secretData, action.AuthPolicy, action.NoDa, action.UserWithAuth, userAuth);
        }
        catch
        {
            //These carriers' only owner is this frame until the feedback record adopts them, so a failing
            //later rent must release them or the pinned rentals are orphaned.
            retainedName.Dispose();
            name.Dispose();
            action.AuthPolicy.Dispose();
            throw;
        }
        finally
        {
            //The Name hash consumed the public area, so this effect is its terminal owner on every path.
            action.InPublic.Dispose();
        }
    }

    /// <summary>
    /// Packs a sealed object's private blob: <c>TPM2_Create()</c>'s own wrapping, since the simulator models no
    /// true parent-key encryption/integrity (it has no parent symmetric-key custody).
    /// </summary>
    /// <remarks>
    /// Layout: a UINT16 big-endian userAuth length, the userAuth octets, then the secret data octets — the
    /// length prefix lets <c>TPM2_Load()</c> recover both the authorization value and the sealed data from the
    /// one opaque blob the caller persists and reloads (TPM 2.0 Library Part 1, clause 17.6.4; Part 3, clauses
    /// 12.1 and 12.2).
    /// </remarks>
    private static IMemoryOwner<byte> PackSealedPrivateBlob(ReadOnlyMemory<byte> userAuth, ReadOnlyMemory<byte> secretData, BaseMemoryPool pool, out int length)
    {
        length = sizeof(ushort) + userAuth.Length + secretData.Length;
        IMemoryOwner<byte> owner = pool.Rent(Math.Max(length, 1));
        try
        {
            Span<byte> span = owner.Memory.Span[..length];
            BinaryPrimitives.WriteUInt16BigEndian(span, (ushort)userAuth.Length);
            userAuth.Span.CopyTo(span[sizeof(ushort)..]);
            secretData.Span.CopyTo(span[(sizeof(ushort) + userAuth.Length)..]);

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Deep-copies a transient object into its persistent instance for <c>TPM2_EvictControl()</c>'s persist
    /// arm (TPM 2.0 Library Part 3, clause 28.5): the persistent instance rents its own private-key, Name,
    /// policy-digest, authValue, and public-modulus carriers, so no two dictionary entries ever co-own a buffer
    /// and either instance's later eviction is free to dispose its own. The empty-authValue, empty-policy, and
    /// empty-modulus sentinels copy to themselves (dispose-immune).
    /// </summary>
    /// <param name="action">The declared action carrying the borrowed transient record and the persistent handle.</param>
    /// <param name="context">The effect context supplying the memory pool.</param>
    /// <returns>The persistent copy, fed back to <c>OnObjectPersisted</c>; its carriers' ownership transfers to the installing transition.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the deep-copied private-key, Name, policy-digest, authValue, and public-modulus carriers transfers to the returned TpmObjectPersisted, whose installing transition adopts them into PersistentObjects and whose refusing arm disposes them through the input's own Dispose.")]
    private static TpmObjectPersisted PersistObject(TpmPersistObjectAction action, TpmActionContext context) =>
        new(action.Transient with
        {
            Handle = TpmiDhObject.FromValue(action.PersistentHandle.Value),
            PrivateKey = CopyToPrivateKeyCarrier(action.Transient.PrivateKey.AsReadOnlySpan(), action.Transient.PrivateKey.Tag, context.Pool),
            Name = Tpm2bName.Create(action.Transient.Name.Span, context.Pool),
            AuthPolicy = Tpm2bDigest.Create(action.Transient.AuthPolicy.AsReadOnlySpan(), context.Pool),
            AuthValue = Tpm2bAuth.Create(action.Transient.AuthValue.AsReadOnlySpan(), context.Pool),
            PublicModulus = Tpm2bPublicKeyRsa.Create(action.Transient.PublicModulus.Buffer, context.Pool)
        });

    /// <summary>
    /// Unpacks a sealed object's private blob into its authorization value and secret data — the inverse of
    /// <see cref="PackSealedPrivateBlob"/>. Both are copied into owned, pinned carriers
    /// (<see cref="Tpm2bAuth"/>/<see cref="Tpm2bSensitiveData"/>) whose ownership rides
    /// <see cref="TpmObjectLoaded"/> into the stored <see cref="SealedObjectState"/> at install; a refusing
    /// arm releases them through the input's own <see cref="TpmObjectLoaded.Dispose"/>.
    /// </summary>
    /// <param name="privateBlob">The wrapped private blob, its shape already gated by <c>OnLoadObject</c>.</param>
    /// <param name="pool">The memory pool the pinned carriers are rented from.</param>
    /// <param name="userAuth">The recovered authorization value; ownership transfers to the caller.</param>
    /// <param name="secretData">The recovered sealed data; ownership transfers to the caller.</param>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of both carriers transfers to the caller's TpmObjectLoaded, whose installing transition stores them and whose refusing arm disposes them.")]
    private static void UnpackSealedPrivateBlob(ReadOnlyMemory<byte> privateBlob, BaseMemoryPool pool, out Tpm2bAuth userAuth, out Tpm2bSensitiveData secretData)
    {
        ReadOnlySpan<byte> span = privateBlob.Span;
        ushort userAuthLength = BinaryPrimitives.ReadUInt16BigEndian(span);
        userAuth = Tpm2bAuth.Create(span.Slice(sizeof(ushort), userAuthLength), pool);
        try
        {
            secretData = Tpm2bSensitiveData.Create(span[(sizeof(ushort) + userAuthLength)..], pool);
        }
        catch
        {
            userAuth.Dispose();
            throw;
        }
    }

    /// <summary>
    /// <c>TPM2_Certify()</c>: compute the subject's and the signer's Qualified Names, marshal the CERTIFY
    /// attestation binding the certified object's Name and the caller nonce, hash it through the registered
    /// digest seam, and sign the digest with the signing key's retained scalar through the injected ECC backend
    /// (this slice models an ECC attestation key).
    /// </summary>
    /// <remarks>
    /// Ownership of the marshaled attest and the signature flows to <see cref="TpmObjectCertified"/>, then to
    /// the <c>TpmCertifyResponse</c> intent, and is released by <see cref="SerializeResponse"/> after the
    /// TPM2B_ATTEST and TPMT_SIGNATURE are framed. This effect is the terminal owner of the carriers the request
    /// transferred into the action and into its response-session entries — the qualifying data and each slot's
    /// caller nonce — and releases them in its <c>finally</c> on every exit path, the attestation having copied
    /// the qualifying data's octets and the entries having been framed by then.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the marshaled attest and the signature transfers to the returned TpmObjectCertified, then to the TpmCertifyResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> CertifyObjectAsync(TpmCertifyAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        try
        {
            TpmEccSigningBackend backend = context.SigningBackend
                ?? throw new InvalidOperationException("TPM2_Certify() requires a signing backend, but none was supplied.");

            int hashSize = action.HashAlg.Value.GetDigestSize()
                ?? throw new InvalidOperationException($"No digest size is registered for hash algorithm '{action.HashAlg.Value}'.");
            Tag hashTag = action.HashAlg.Value.GetDigestTag()
                ?? throw new InvalidOperationException($"No digest tag is registered for hash algorithm '{action.HashAlg.Value}'.");

            (IMemoryOwner<byte> attest, int attestLength) = await BuildSignedCertifyAttestAsync(
                action.SubjectName.AsReadOnlyMemory(), action.SubjectHierarchy.Value, action.SignerName.AsReadOnlyMemory(), action.SignerHierarchy.Value, action.QualifyingData.AsReadOnlyMemory(), action.ClockSnapshot, context.Pool, cancellationToken).ConfigureAwait(false);
            Signature signature;
            try
            {
                //The signature is over H_hashAlg(marshaled attest) — the exact bytes TPM2B_ATTEST carries and the host
                //re-hashes to verify (TPM 2.0 Library Part 3, clause 18.2). The digest width and tag follow the
                //caller's requested scheme hash (action.HashAlg), not a fixed SHA-256.
                using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
                    attest.Memory[..attestLength], hashSize, hashTag, context.Pool, cancellationToken: cancellationToken).ConfigureAwait(false);

                signature = await backend.SignDigest(
                    action.SignerPrivateKey.AsReadOnlyMemory(), digest.AsReadOnlyMemory(), action.SignerCurve.Value, context.Pool, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                attest.Dispose();
                throw;
            }

            return await CompleteAttestAsync(
                TpmCcConstants.TPM_CC_Certify, attest, attestLength, signature, TpmiAlgSigScheme.FromValue(TpmAlgIdConstants.TPM_ALG_ECDSA), action.HashAlg, action.ResponseSessions,
                static (certifyInfo, tpmtSignature) => new TpmObjectCertified(certifyInfo, tpmtSignature), context, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            ReleaseAttestQualifyingData(action.QualifyingData, action.ResponseSessions);
        }
    }

    /// <summary>
    /// The RSA counterpart of <see cref="CertifyObjectAsync"/>: same Qualified Name computation and attestation
    /// marshaling, signed with the signing key's retained private key through the injected RSA backend under the
    /// requested RSA scheme.
    /// </summary>
    /// <remarks>
    /// This effect is the terminal owner of the carriers the request transferred into the action and into its
    /// response-session entries — the qualifying data and each slot's caller nonce — and releases them in its
    /// <c>finally</c> on every exit path.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the marshaled attest and the signature transfers to the returned TpmObjectCertified, then to the TpmCertifyResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> CertifyObjectRsaAsync(TpmRsaCertifyAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        try
        {
            TpmRsaSigningBackend backend = context.RsaSigningBackend
                ?? throw new InvalidOperationException("TPM2_Certify() over an RSA key requires an RSA signing backend, but none was supplied.");

            int hashSize = action.HashAlg.Value.GetDigestSize()
                ?? throw new InvalidOperationException($"No digest size is registered for hash algorithm '{action.HashAlg.Value}'.");
            Tag hashTag = action.HashAlg.Value.GetDigestTag()
                ?? throw new InvalidOperationException($"No digest tag is registered for hash algorithm '{action.HashAlg.Value}'.");

            (IMemoryOwner<byte> attest, int attestLength) = await BuildSignedCertifyAttestAsync(
                action.SubjectName.AsReadOnlyMemory(), action.SubjectHierarchy.Value, action.SignerName.AsReadOnlyMemory(), action.SignerHierarchy.Value, action.QualifyingData.AsReadOnlyMemory(), action.ClockSnapshot, context.Pool, cancellationToken).ConfigureAwait(false);
            Signature signature;
            try
            {
                //The signature is over H_hashAlg(marshaled attest), exactly as the ECC path (TPM 2.0 Library Part 3,
                //clause 18.2). The digest width and tag follow the caller's requested scheme hash (action.HashAlg),
                //not a fixed SHA-256 — the RSA backend's RSA.SignHash rejects a digest whose length disagrees with
                //the hash algorithm it is told to sign under.
                using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
                    attest.Memory[..attestLength], hashSize, hashTag, context.Pool, cancellationToken: cancellationToken).ConfigureAwait(false);

                signature = await backend.SignDigest(
                    action.SignerPrivateKey.AsReadOnlyMemory(), digest.AsReadOnlyMemory(), action.Scheme.Value, action.HashAlg.Value, context.Pool, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                attest.Dispose();
                throw;
            }

            return await CompleteAttestAsync(
                TpmCcConstants.TPM_CC_Certify, attest, attestLength, signature, action.Scheme, action.HashAlg, action.ResponseSessions,
                static (certifyInfo, tpmtSignature) => new TpmObjectCertified(certifyInfo, tpmtSignature), context, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            ReleaseAttestQualifyingData(action.QualifyingData, action.ResponseSessions);
        }
    }

    /// <summary>
    /// Releases the carriers an attest request transferred into its action and its response-session entries — the
    /// <c>TPM2B_DATA</c> qualifying data and every slot's caller nonce — discharging the terminal-owner obligation
    /// of the <c>TPM2_Certify()</c>, <c>TPM2_GetTime()</c>, and <c>TPM2_NV_Certify()</c> effects once the
    /// attestation has copied the qualifying data's octets into <c>extraData</c> and the response entries have been
    /// framed. Carrier disposal is idempotent and the shared empty sentinels are dispose-immune, so the release is
    /// safe on the success, signing-failure, and framing-failure paths alike.
    /// </summary>
    /// <param name="qualifyingData">The transferred <c>TPM2B_DATA</c> carrier.</param>
    /// <param name="responseSessions">The command's response-session entries, each owning its slot's caller nonce; the default value on the all-password arm.</param>
    private static void ReleaseAttestQualifyingData(Tpm2bData qualifyingData, ImmutableArray<TpmAttestResponseSession> responseSessions)
    {
        qualifyingData.Dispose();
        ReleaseAttestResponseSessionNonces(responseSessions);
    }

    /// <summary>
    /// Releases the caller-nonce carrier every attest response-session entry owns — the <c>TPM2B_NONCE</c> its
    /// slot's request record transferred into it — discharging the attest effects' terminal-owner obligation once
    /// the response HMACs have read the nonces as their nonceOlder term (TPM 2.0 Library Part 1, clause 17.6.5).
    /// A <c>TPM_RS_PW</c> slot's placeholder entry owns its slot's nonce exactly as a real entry does, so one
    /// uniform release covers every slot of a mixed authorization area.
    /// </summary>
    /// <remarks>
    /// Carrier disposal is idempotent and the shared empty sentinel is dispose-immune, so the release is safe on
    /// the success, signing-failure, and framing-failure paths alike. The all-password arm carries the default
    /// (uninitialized) array, whose response has no session area and whose parse rented no nonce.
    /// </remarks>
    /// <param name="responseSessions">The command's response-session entries, or the default value on the all-password arm.</param>
    private static void ReleaseAttestResponseSessionNonces(ImmutableArray<TpmAttestResponseSession> responseSessions)
    {
        if(responseSessions.IsDefaultOrEmpty)
        {
            return;
        }

        foreach(TpmAttestResponseSession session in responseSessions)
        {
            session.NonceCaller.Dispose();
        }
    }

    /// <summary>
    /// Computes the subject's and the signer's Qualified Names (TPM 2.0 Library Part 1, clause 14, Table 6) and marshals
    /// the CERTIFY attestation from them — shared between the ECC and RSA <c>TPM2_Certify()</c> paths, which
    /// differ only in how they sign the resulting digest.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the marshaled-attest buffer transfers to the caller, which carries it to the response intent disposed by SerializeResponse.")]
    private static async ValueTask<(IMemoryOwner<byte> Owner, int Length)> BuildSignedCertifyAttestAsync(
        ReadOnlyMemory<byte> subjectName, uint subjectHierarchy, ReadOnlyMemory<byte> signerName, uint signerHierarchy,
        ReadOnlyMemory<byte> qualifyingData, TpmsClockInfo clockInfo, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        (IMemoryOwner<byte> subjectQualifiedName, int subjectQualifiedNameLength) =
            await ComputeHierarchyQualifiedNameAsync(subjectHierarchy, subjectName, pool, cancellationToken).ConfigureAwait(false);
        using(subjectQualifiedName)
        {
            (IMemoryOwner<byte> signerQualifiedName, int signerQualifiedNameLength) =
                await ComputeHierarchyQualifiedNameAsync(signerHierarchy, signerName, pool, cancellationToken).ConfigureAwait(false);
            using(signerQualifiedName)
            {
                return BuildCertifyAttest(
                    subjectName.Span,
                    subjectQualifiedName.Memory.Span[..subjectQualifiedNameLength],
                    signerQualifiedName.Memory.Span[..signerQualifiedNameLength],
                    qualifyingData.Span,
                    clockInfo,
                    pool);
            }
        }
    }

    /// <summary>
    /// Builds the marshaled <c>TPMS_ATTEST</c> for the CERTIFY case (TPM 2.0 Library Part 2, clause 10.12.12)
    /// into a pooled buffer — the exact bytes the signature is over and the TPM2B_ATTEST wraps. Synchronous, so
    /// the spans never cross the digest/sign awaits.
    /// </summary>
    /// <remarks>
    /// Every field the host verifies is cryptographically real: magic (<c>TPM_GENERATED_VALUE</c>), type
    /// (<c>TPM_ST_ATTEST_CERTIFY</c>), extraData (the caller nonce), the attested
    /// <c>TPMS_CERTIFY_INFO.name</c> (the certified object's Name), qualifiedSigner (the signing key's real
    /// Qualified Name), and the attested qualifiedName (the certified object's real Qualified Name) — both
    /// Qualified Names computed by the caller (TPM 2.0 Library Part 1, clause 26.6). clockInfo is the real
    /// Clock/resetCount/restartCount/Safe snapshot the transition folded from state after the per-command
    /// advance; firmwareVersion is the simulator's fixed synthetic identity.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the marshaled-attest buffer transfers to the caller, which carries it to the response intent disposed by SerializeResponse.")]
    private static (IMemoryOwner<byte> Owner, int Length) BuildCertifyAttest(
        ReadOnlySpan<byte> subjectName, ReadOnlySpan<byte> subjectQualifiedName, ReadOnlySpan<byte> signerQualifiedName, ReadOnlySpan<byte> nonce, TpmsClockInfo clockInfo, BaseMemoryPool pool)
    {
        int total =
            sizeof(uint) + sizeof(ushort)                            //magic (TPM_GENERATED) + type (TPMI_ST_ATTEST).
            + (sizeof(ushort) + signerQualifiedName.Length)          //qualifiedSigner (TPM2B_NAME).
            + (sizeof(ushort) + nonce.Length)                        //extraData (TPM2B_DATA).
            + TpmsClockInfo.SerializedSize                           //clockInfo (TPMS_CLOCK_INFO).
            + sizeof(ulong)                                          //firmwareVersion.
            + (sizeof(ushort) + subjectName.Length)                  //attested.name (TPM2B_NAME).
            + (sizeof(ushort) + subjectQualifiedName.Length);        //attested.qualifiedName (TPM2B_NAME).

        IMemoryOwner<byte> owner = pool.Rent(total);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span[..total]);

            writer.WriteUInt32(TpmConstants32.TPM_GENERATED_VALUE);
            writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_ATTEST_CERTIFY);
            writer.WriteTpm2b(signerQualifiedName);                              //qualifiedSigner: the signer's real Qualified Name.
            writer.WriteTpm2b(nonce);                                            //extraData: the caller's qualifyingData, echoed verbatim.

            clockInfo.WriteTo(ref writer);
            writer.WriteUInt64(SimulatedFirmwareVersion);

            //attested = TPMS_CERTIFY_INFO: the certified object's Name (the attested binding), then its real
            //Qualified Name.
            writer.WriteTpm2b(subjectName);
            writer.WriteTpm2b(subjectQualifiedName);

            return (owner, total);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// <c>QN(hierarchy)</c> for a permanent hierarchy handle is the handle itself (TPM 2.0 Library Part 1,
    /// clause 14, Table 6) — every object this simulator creates is a primary directly under a permanent hierarchy, so no
    /// parent-chain walk is needed; the hierarchy's 4-octet big-endian handle value stands in directly as its
    /// own Qualified Name.
    /// </summary>
    /// <remarks>
    /// The nameAlg is read back out of the object's own Name (its first two octets), the same algorithm the
    /// Qualified Name inherits.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the Qualified Name buffer transfers to the caller, which releases it via a using declaration.")]
    private static async ValueTask<(IMemoryOwner<byte> Owner, int Length)> ComputeHierarchyQualifiedNameAsync(
        uint hierarchy, ReadOnlyMemory<byte> name, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        ushort nameAlg = BinaryPrimitives.ReadUInt16BigEndian(name.Span[..sizeof(ushort)]);

        IMemoryOwner<byte> hierarchyHandle = pool.Rent(sizeof(uint));
        try
        {
            BinaryPrimitives.WriteUInt32BigEndian(hierarchyHandle.Memory.Span[..sizeof(uint)], hierarchy);

            return await TpmObjectName.ComputeQualifiedNameAsync(
                hierarchyHandle.Memory[..sizeof(uint)], name, nameAlg, pool, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            hierarchyHandle.Dispose();
        }
    }

    /// <summary>
    /// <c>TPM2_Quote()</c>: compute the PCR composite digest over the selected register values, marshal the
    /// QUOTE attestation binding that composite (and the caller nonce), hash it through the registered digest
    /// seam under the signing scheme's own hash algorithm (<c>action.HashAlg</c>), and sign the digest with the
    /// signing key's retained scalar through the injected ECC backend (this slice models an ECC signing key;
    /// <see cref="QuoteObjectRsaAsync"/> is the RSA counterpart).
    /// </summary>
    /// <remarks>
    /// Ownership of the marshaled attest and the signature flows to <see cref="TpmObjectQuoted"/>, then to the
    /// <c>TpmQuoteResponse</c> intent, and is released by <see cref="SerializeResponse"/> after the TPM2B_ATTEST
    /// and TPMT_SIGNATURE are framed. This effect is the terminal owner of the carriers the request transferred
    /// into the action and into its response-session entry — the qualifying data, the PCR selection, and the sign
    /// slot's caller nonce — and releases them in its <c>finally</c> on every exit path, the attestation having
    /// copied their octets and the entry having been framed by then.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the marshaled attest and the signature transfers to the returned TpmObjectQuoted, then to the TpmQuoteResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> QuoteObjectAsync(TpmQuoteAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        try
        {
            TpmEccSigningBackend backend = context.SigningBackend
                ?? throw new InvalidOperationException("TPM2_Quote() requires a signing backend, but none was supplied.");

            int hashSize = action.HashAlg.Value.GetDigestSize()
                ?? throw new InvalidOperationException($"No digest size is registered for hash algorithm '{action.HashAlg.Value}'.");
            Tag hashTag = action.HashAlg.Value.GetDigestTag()
                ?? throw new InvalidOperationException($"No digest tag is registered for hash algorithm '{action.HashAlg.Value}'.");

            //pcrDigest = H_hashAlg(concatenation of the selected PCR values in ascending PCR-index order) (TPM 2.0
            //Library Part 4, PCRComputeCurrentDigest). The composite is assembled in a pooled buffer, then hashed
            //through the registered digest seam under the signing scheme's own hash algorithm (Part 3, clause 18.4:
            //the PCR digest uses the hash of the signing scheme), not a fixed SHA-256.
            using IMemoryOwner<byte> composite = ConcatenatePcrValues(action.PcrValues, context.Pool, out int compositeLength);
            using DigestValue pcrDigest = await CryptographicKeyEvents.ComputeDigestAsync(
                composite.Memory[..compositeLength], hashSize, hashTag, context.Pool, cancellationToken: cancellationToken).ConfigureAwait(false);

            IMemoryOwner<byte> attest;
            int attestLength;
            {
                (IMemoryOwner<byte> signerQualifiedName, int signerQualifiedNameLength) =
                    await ComputeHierarchyQualifiedNameAsync(action.SignerHierarchy.Value, action.SignerName.AsReadOnlyMemory(), context.Pool, cancellationToken).ConfigureAwait(false);
                using(signerQualifiedName)
                {
                    (attest, attestLength) = BuildQuoteAttest(
                        signerQualifiedName.Memory.Span[..signerQualifiedNameLength], action.QualifyingData.Span, action.PcrSelection, pcrDigest.AsReadOnlySpan(), action.ClockSnapshot, context.Pool);
                }
            }

            Signature signature;
            try
            {
                //The signature is over H_hashAlg(marshaled attest) — the exact bytes TPM2B_ATTEST carries and the host
                //re-hashes to verify (TPM 2.0 Library Part 3, clause 18.4). The digest width and tag follow the
                //caller's requested scheme hash, not a fixed SHA-256.
                using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
                    attest.Memory[..attestLength], hashSize, hashTag, context.Pool, cancellationToken: cancellationToken).ConfigureAwait(false);

                signature = await backend.SignDigest(
                    action.SignerPrivateKey.AsReadOnlyMemory(), digest.AsReadOnlyMemory(), action.SignerCurve.Value, context.Pool, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                attest.Dispose();
                throw;
            }

            return await CompleteAttestAsync(
                TpmCcConstants.TPM_CC_Quote, attest, attestLength, signature, action.SignatureScheme, action.HashAlg, action.ResponseSessions,
                static (quoted, tpmtSignature) => new TpmObjectQuoted(quoted, tpmtSignature), context, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            ReleaseQuoteCarriers(action.QualifyingData, action.PcrSelection, action.ResponseSessions);
        }
    }

    /// <summary>
    /// The RSA counterpart of <see cref="QuoteObjectAsync"/>: same PCR composite and attestation marshaling,
    /// signed with the signing key's retained private key through the injected RSA backend under the requested
    /// RSA scheme.
    /// </summary>
    /// <remarks>
    /// This effect is the terminal owner of the carriers the request transferred into the action and into its
    /// response-session entry — the qualifying data, the PCR selection, and the sign slot's caller nonce — and
    /// releases them in its <c>finally</c> on every exit path.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the marshaled attest and the signature transfers to the returned TpmObjectQuoted, then to the TpmQuoteResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> QuoteObjectRsaAsync(TpmRsaQuoteAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        try
        {
            TpmRsaSigningBackend backend = context.RsaSigningBackend
                ?? throw new InvalidOperationException("TPM2_Quote() over an RSA key requires an RSA signing backend, but none was supplied.");

            int hashSize = action.HashAlg.Value.GetDigestSize()
                ?? throw new InvalidOperationException($"No digest size is registered for hash algorithm '{action.HashAlg.Value}'.");
            Tag hashTag = action.HashAlg.Value.GetDigestTag()
                ?? throw new InvalidOperationException($"No digest tag is registered for hash algorithm '{action.HashAlg.Value}'.");

            //pcrDigest = H_hashAlg(concatenation of the selected PCR values in ascending PCR-index order), exactly as
            //the ECC path, under the signing scheme's own hash algorithm (Part 3, clause 18.4: the PCR digest uses the
            //hash of the signing scheme).
            using IMemoryOwner<byte> composite = ConcatenatePcrValues(action.PcrValues, context.Pool, out int compositeLength);
            using DigestValue pcrDigest = await CryptographicKeyEvents.ComputeDigestAsync(
                composite.Memory[..compositeLength], hashSize, hashTag, context.Pool, cancellationToken: cancellationToken).ConfigureAwait(false);

            IMemoryOwner<byte> attest;
            int attestLength;
            {
                (IMemoryOwner<byte> signerQualifiedName, int signerQualifiedNameLength) =
                    await ComputeHierarchyQualifiedNameAsync(action.SignerHierarchy.Value, action.SignerName.AsReadOnlyMemory(), context.Pool, cancellationToken).ConfigureAwait(false);
                using(signerQualifiedName)
                {
                    (attest, attestLength) = BuildQuoteAttest(
                        signerQualifiedName.Memory.Span[..signerQualifiedNameLength], action.QualifyingData.Span, action.PcrSelection, pcrDigest.AsReadOnlySpan(), action.ClockSnapshot, context.Pool);
                }
            }

            Signature signature;
            try
            {
                //The signature is over H_hashAlg(marshaled attest), exactly as the ECC path (TPM 2.0 Library Part 3,
                //clause 18.4). The digest width and tag follow the caller's requested scheme hash, not a fixed
                //SHA-256 — the RSA backend's RSA.SignHash rejects a digest whose length disagrees with the hash
                //algorithm it is told to sign under.
                using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
                    attest.Memory[..attestLength], hashSize, hashTag, context.Pool, cancellationToken: cancellationToken).ConfigureAwait(false);

                signature = await backend.SignDigest(
                    action.SignerPrivateKey.AsReadOnlyMemory(), digest.AsReadOnlyMemory(), action.Scheme.Value, action.HashAlg.Value, context.Pool, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                attest.Dispose();
                throw;
            }

            return await CompleteAttestAsync(
                TpmCcConstants.TPM_CC_Quote, attest, attestLength, signature, action.Scheme, action.HashAlg, action.ResponseSessions,
                static (quoted, tpmtSignature) => new TpmObjectQuoted(quoted, tpmtSignature), context, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            ReleaseQuoteCarriers(action.QualifyingData, action.PcrSelection, action.ResponseSessions);
        }
    }

    /// <summary>
    /// Releases the carriers a <c>TPM2_Quote()</c> request transferred into its action and its response-session
    /// entry — the qualifying data, the PCR selection, and the sign slot's caller nonce — discharging the quote
    /// effects' terminal-owner obligation once the attestation has copied their octets and the response entry has
    /// been framed. Carrier disposal is idempotent and the shared empty sentinels are dispose-immune, so the
    /// release is safe on the success, signing-failure, and framing-failure paths alike.
    /// </summary>
    /// <param name="qualifyingData">The transferred <c>TPM2B_DATA</c> carrier.</param>
    /// <param name="pcrSelection">The transferred <c>TPML_PCR_SELECTION</c> carrier.</param>
    /// <param name="responseSessions">The command's response-session entries, each owning its slot's caller nonce; the default value on the all-password arm.</param>
    private static void ReleaseQuoteCarriers(Tpm2bData qualifyingData, TpmlPcrSelection pcrSelection, ImmutableArray<TpmAttestResponseSession> responseSessions)
    {
        qualifyingData.Dispose();
        pcrSelection.Dispose();
        ReleaseAttestResponseSessionNonces(responseSessions);
    }

    /// <summary>
    /// Copies the selected PCR values, in order, into one pooled buffer — the PCR composite the quote digest is
    /// computed over. Rents at least one octet so an empty selection still yields a valid (empty) buffer.
    /// Ownership transfers to the caller, which disposes it after the composite digest is taken.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented buffer transfers to the caller, which releases it via a using declaration after the digest is computed.")]
    private static IMemoryOwner<byte> ConcatenatePcrValues(ImmutableArray<ReadOnlyMemory<byte>> values, BaseMemoryPool pool, out int length)
    {
        int total = 0;
        for(int i = 0; i < values.Length; i++)
        {
            total += values[i].Length;
        }

        length = total;
        IMemoryOwner<byte> owner = pool.Rent(Math.Max(total, 1));
        try
        {
            Span<byte> destination = owner.Memory.Span;
            int offset = 0;
            for(int i = 0; i < values.Length; i++)
            {
                ReadOnlySpan<byte> value = values[i].Span;
                value.CopyTo(destination[offset..]);
                offset += value.Length;
            }

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Builds the marshaled <c>TPMS_ATTEST</c> for the QUOTE case (TPM 2.0 Library Part 2, clause 10.12.12; the
    /// quote body is <c>TPMS_QUOTE_INFO</c>, clause 10.12.1) into a pooled buffer — the exact bytes the signature
    /// is over and the TPM2B_ATTEST wraps. Synchronous, so the spans never cross the digest/sign awaits.
    /// </summary>
    /// <remarks>
    /// The fields the host verifies are cryptographically real: magic (<c>TPM_GENERATED_VALUE</c>), type
    /// (<c>TPM_ST_ATTEST_QUOTE</c>), extraData (the caller nonce), qualifiedSigner (the signing key's real
    /// Qualified Name, TPM 2.0 Library Part 1, clause 26.6), and the attested <c>TPMS_QUOTE_INFO</c> {
    /// pcrSelect echoed verbatim, pcrDigest computed over the real PCR values }. clockInfo is the real
    /// Clock/resetCount/restartCount/Safe snapshot the transition folded from state after the per-command
    /// advance; firmwareVersion is the simulator's fixed synthetic identity. The pcrSelect is the caller's
    /// <c>TPML_PCR_SELECTION</c> written back from the parsed structure, which marshals to the same octets the
    /// host produced, so it round-trips through <c>TpmsQuoteInfo.Parse</c> exactly.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the marshaled-attest buffer transfers to the caller, which carries it to the response intent disposed by SerializeResponse.")]
    private static (IMemoryOwner<byte> Owner, int Length) BuildQuoteAttest(
        ReadOnlySpan<byte> signerQualifiedName, ReadOnlySpan<byte> nonce, TpmlPcrSelection pcrSelection, ReadOnlySpan<byte> pcrDigest, TpmsClockInfo clockInfo, BaseMemoryPool pool)
    {
        int total =
            sizeof(uint) + sizeof(ushort)                            //magic (TPM_GENERATED) + type (TPMI_ST_ATTEST).
            + (sizeof(ushort) + signerQualifiedName.Length)          //qualifiedSigner (TPM2B_NAME).
            + (sizeof(ushort) + nonce.Length)                        //extraData (TPM2B_DATA).
            + TpmsClockInfo.SerializedSize                           //clockInfo (TPMS_CLOCK_INFO).
            + sizeof(ulong)                                          //firmwareVersion.
            + pcrSelection.GetSerializedSize()                       //attested.pcrSelect (TPML_PCR_SELECTION).
            + (sizeof(ushort) + pcrDigest.Length);                   //attested.pcrDigest (TPM2B_DIGEST).

        IMemoryOwner<byte> owner = pool.Rent(total);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span[..total]);

            writer.WriteUInt32(TpmConstants32.TPM_GENERATED_VALUE);
            writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_ATTEST_QUOTE);
            writer.WriteTpm2b(signerQualifiedName);                              //qualifiedSigner: the signer's real Qualified Name.
            writer.WriteTpm2b(nonce);                                            //extraData: the caller's qualifyingData, echoed verbatim.

            clockInfo.WriteTo(ref writer);
            writer.WriteUInt64(SimulatedFirmwareVersion);

            //attested = TPMS_QUOTE_INFO: the caller's PCR selection written back in full (the whole
            //TPML_PCR_SELECTION), then the composite digest the TPM computed over the selected PCR values.
            pcrSelection.WriteTo(ref writer);
            writer.WriteTpm2b(pcrDigest);

            return (owner, total);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// <c>TPM2_CertifyCreation()</c>: re-verify the caller-supplied creation ticket, then (on a match) marshal
    /// the CREATION attestation and sign it with the signing key's retained scalar through the injected ECC
    /// backend.
    /// </summary>
    /// <remarks>
    /// Unlike Certify/Quote, the rejection outcome (a mismatched ticket, <c>TPM_RC_TICKET</c>) is decided here
    /// rather than in the pure transition, because the re-derivation needs the asynchronous digest/HMAC seam
    /// (mirrors how <see cref="ActivateCredentialAsync"/>'s integrity check works). This effect is the terminal
    /// owner of the carriers the request transferred into the action and into its response-session entry — the
    /// qualifying data, the creation hash, the ticket digest, and the sign slot's caller nonce — and releases them
    /// in its <c>finally</c> on every exit path, the ticket-mismatch return included.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the marshaled attest and the signature transfers to the returned TpmObjectCreationCertified, then to the TpmCertifyCreationResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> CertifyObjectCreationAsync(TpmCertifyCreationAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        try
        {
            TpmEccSigningBackend backend = context.SigningBackend
                ?? throw new InvalidOperationException("TPM2_CertifyCreation() requires a signing backend, but none was supplied.");

            if(!await VerifyCreationTicketAsync(action.SubjectHierarchy.Value, action.SubjectName.AsReadOnlyMemory(), action.CreationHash.AsReadOnlyMemory(), action.TicketDigest.AsReadOnlyMemory(), context, cancellationToken).ConfigureAwait(false))
            {
                return new TpmObjectCreationCertified(TpmRcConstants.TPM_RC_TICKET, null, null);
            }

            int hashSize = action.HashAlg.Value.GetDigestSize()
                ?? throw new InvalidOperationException($"No digest size is registered for hash algorithm '{action.HashAlg.Value}'.");
            Tag hashTag = action.HashAlg.Value.GetDigestTag()
                ?? throw new InvalidOperationException($"No digest tag is registered for hash algorithm '{action.HashAlg.Value}'.");

            (IMemoryOwner<byte> attest, int attestLength) = await BuildSignedCreationAttestAsync(
                action.SubjectName.AsReadOnlyMemory(), action.CreationHash.AsReadOnlyMemory(), action.SignerHierarchy.Value, action.SignerName.AsReadOnlyMemory(), action.QualifyingData.AsReadOnlyMemory(), action.ClockSnapshot, context.Pool, cancellationToken).ConfigureAwait(false);
            Signature signature;
            try
            {
                using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
                    attest.Memory[..attestLength], hashSize, hashTag, context.Pool, cancellationToken: cancellationToken).ConfigureAwait(false);

                signature = await backend.SignDigest(
                    action.SignerPrivateKey.AsReadOnlyMemory(), digest.AsReadOnlyMemory(), action.SignerCurve.Value, context.Pool, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                attest.Dispose();
                throw;
            }

            return await CompleteAttestAsync(
                TpmCcConstants.TPM_CC_CertifyCreation, attest, attestLength, signature, TpmiAlgSigScheme.FromValue(TpmAlgIdConstants.TPM_ALG_ECDSA), action.HashAlg, action.ResponseSessions,
                static (certifyInfo, tpmtSignature) => new TpmObjectCreationCertified(TpmRcConstants.TPM_RC_SUCCESS, certifyInfo, tpmtSignature), context, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            ReleaseCertifyCreationCarriers(action.QualifyingData, action.CreationHash, action.TicketDigest, action.ResponseSessions);
        }
    }

    /// <summary>
    /// The RSA counterpart of <see cref="CertifyObjectCreationAsync"/>: same ticket re-verification and
    /// attestation marshaling, signed with the signing key's retained private key through the injected RSA
    /// backend under the requested RSA scheme.
    /// </summary>
    /// <remarks>
    /// This effect is the terminal owner of the carriers the request transferred into the action and into its
    /// response-session entry — the qualifying data, the creation hash, the ticket digest, and the sign slot's
    /// caller nonce — and releases them in its <c>finally</c> on every exit path, the ticket-mismatch return
    /// included.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the marshaled attest and the signature transfers to the returned TpmObjectCreationCertified, then to the TpmCertifyCreationResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> CertifyObjectCreationRsaAsync(TpmRsaCertifyCreationAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        try
        {
            TpmRsaSigningBackend backend = context.RsaSigningBackend
                ?? throw new InvalidOperationException("TPM2_CertifyCreation() over an RSA key requires an RSA signing backend, but none was supplied.");

            if(!await VerifyCreationTicketAsync(action.SubjectHierarchy.Value, action.SubjectName.AsReadOnlyMemory(), action.CreationHash.AsReadOnlyMemory(), action.TicketDigest.AsReadOnlyMemory(), context, cancellationToken).ConfigureAwait(false))
            {
                return new TpmObjectCreationCertified(TpmRcConstants.TPM_RC_TICKET, null, null);
            }

            int hashSize = action.HashAlg.Value.GetDigestSize()
                ?? throw new InvalidOperationException($"No digest size is registered for hash algorithm '{action.HashAlg.Value}'.");
            Tag hashTag = action.HashAlg.Value.GetDigestTag()
                ?? throw new InvalidOperationException($"No digest tag is registered for hash algorithm '{action.HashAlg.Value}'.");

            (IMemoryOwner<byte> attest, int attestLength) = await BuildSignedCreationAttestAsync(
                action.SubjectName.AsReadOnlyMemory(), action.CreationHash.AsReadOnlyMemory(), action.SignerHierarchy.Value, action.SignerName.AsReadOnlyMemory(), action.QualifyingData.AsReadOnlyMemory(), action.ClockSnapshot, context.Pool, cancellationToken).ConfigureAwait(false);
            Signature signature;
            try
            {
                using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
                    attest.Memory[..attestLength], hashSize, hashTag, context.Pool, cancellationToken: cancellationToken).ConfigureAwait(false);

                signature = await backend.SignDigest(
                    action.SignerPrivateKey.AsReadOnlyMemory(), digest.AsReadOnlyMemory(), action.Scheme.Value, action.HashAlg.Value, context.Pool, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                attest.Dispose();
                throw;
            }

            return await CompleteAttestAsync(
                TpmCcConstants.TPM_CC_CertifyCreation, attest, attestLength, signature, action.Scheme, action.HashAlg, action.ResponseSessions,
                static (certifyInfo, tpmtSignature) => new TpmObjectCreationCertified(TpmRcConstants.TPM_RC_SUCCESS, certifyInfo, tpmtSignature), context, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            ReleaseCertifyCreationCarriers(action.QualifyingData, action.CreationHash, action.TicketDigest, action.ResponseSessions);
        }
    }

    /// <summary>
    /// Releases the carriers a <c>TPM2_CertifyCreation()</c> request transferred into its action and its
    /// response-session entry — the qualifying data, the creation hash, the ticket digest, and the sign slot's
    /// caller nonce — discharging the certify-creation effects' terminal-owner obligation once the ticket
    /// comparison and the attestation have read their octets and the response entry has been framed. Carrier
    /// disposal is idempotent and the shared empty sentinels are dispose-immune, so the release is safe on the
    /// success, ticket-mismatch, signing-failure, and framing-failure paths alike.
    /// </summary>
    /// <param name="qualifyingData">The transferred <c>TPM2B_DATA</c> carrier.</param>
    /// <param name="creationHash">The transferred creation-hash <c>TPM2B_DIGEST</c> carrier.</param>
    /// <param name="ticketDigest">The transferred ticket-digest <c>TPM2B_DIGEST</c> carrier.</param>
    /// <param name="responseSessions">The command's response-session entries, each owning its slot's caller nonce; the default value on the all-password arm.</param>
    private static void ReleaseCertifyCreationCarriers(
        Tpm2bData qualifyingData, Tpm2bDigest creationHash, Tpm2bDigest ticketDigest, ImmutableArray<TpmAttestResponseSession> responseSessions)
    {
        qualifyingData.Dispose();
        creationHash.Dispose();
        ticketDigest.Dispose();
        ReleaseAttestResponseSessionNonces(responseSessions);
    }

    /// <summary>
    /// Re-verifies a <c>TPM2_CertifyCreation()</c> creation ticket statelessly (TPM 2.0 Library Part 2, clause
    /// 10.7.3; Part 3, clause 18.3): re-derives the certified object's own hierarchy proof (never a
    /// caller-supplied one, so a tampered ticket cannot be rescued by a matching hierarchy claim), recomputes
    /// <c>HMAC(proof, TPM_ST_CREATION || Name || creationHash)</c> with the exact same derivation
    /// <c>TPM2_CreatePrimary()</c>/<c>TPM2_Create()</c> used to produce the original ticket, and compares the
    /// result constant-time against the caller-supplied ticket digest.
    /// </summary>
    private static async ValueTask<bool> VerifyCreationTicketAsync(
        uint subjectHierarchy, ReadOnlyMemory<byte> subjectName, ReadOnlyMemory<byte> creationHash, ReadOnlyMemory<byte> ticketDigest,
        TpmActionContext context, CancellationToken cancellationToken)
    {
        using IMemoryOwner<byte> proof = await DeriveHierarchyProofAsync(context, subjectHierarchy, cancellationToken).ConfigureAwait(false);
        using IMemoryOwner<byte> expectedDigest = await ComputeCreationTicketDigestAsync(
            proof.Memory[..CreationDigestSize], subjectName, creationHash, context.Pool, cancellationToken).ConfigureAwait(false);

        return CryptographicOperations.FixedTimeEquals(expectedDigest.Memory.Span[..CreationDigestSize], ticketDigest.Span);
    }

    /// <summary>
    /// Computes the signer's Qualified Name and marshals the CREATION attestation from it — shared between the
    /// ECC and RSA <c>TPM2_CertifyCreation()</c> paths, which differ only in how they sign the resulting digest.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the marshaled-attest buffer transfers to the caller, which carries it to the response intent disposed by SerializeResponse.")]
    private static async ValueTask<(IMemoryOwner<byte> Owner, int Length)> BuildSignedCreationAttestAsync(
        ReadOnlyMemory<byte> subjectName, ReadOnlyMemory<byte> creationHash, uint signerHierarchy, ReadOnlyMemory<byte> signerName,
        ReadOnlyMemory<byte> qualifyingData, TpmsClockInfo clockInfo, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        (IMemoryOwner<byte> signerQualifiedName, int signerQualifiedNameLength) =
            await ComputeHierarchyQualifiedNameAsync(signerHierarchy, signerName, pool, cancellationToken).ConfigureAwait(false);
        using(signerQualifiedName)
        {
            return BuildCreationAttest(
                subjectName.Span,
                creationHash.Span,
                signerQualifiedName.Memory.Span[..signerQualifiedNameLength],
                qualifyingData.Span,
                clockInfo,
                pool);
        }
    }

    /// <summary>
    /// Builds the marshaled <c>TPMS_ATTEST</c> for the CREATION case (TPM 2.0 Library Part 2, clause 10.12.7)
    /// into a pooled buffer — the exact bytes the signature is over and the TPM2B_ATTEST wraps.
    /// </summary>
    /// <remarks>
    /// Every field the host verifies is cryptographically real: magic, type (<c>TPM_ST_ATTEST_CREATION</c>),
    /// extraData, qualifiedSigner, the attested <c>TPMS_CREATION_INFO.objectName</c> (the certified object's
    /// real Name), and creationHash (the caller-supplied value the re-verified ticket bound). clockInfo is the
    /// real Clock/resetCount/restartCount/Safe snapshot the transition folded from state after the per-command
    /// advance; firmwareVersion is the simulator's fixed synthetic identity.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the marshaled-attest buffer transfers to the caller, which carries it to the response intent disposed by SerializeResponse.")]
    private static (IMemoryOwner<byte> Owner, int Length) BuildCreationAttest(
        ReadOnlySpan<byte> subjectName, ReadOnlySpan<byte> creationHash, ReadOnlySpan<byte> signerQualifiedName, ReadOnlySpan<byte> nonce, TpmsClockInfo clockInfo, BaseMemoryPool pool)
    {
        int total =
            sizeof(uint) + sizeof(ushort)                            //magic (TPM_GENERATED) + type (TPMI_ST_ATTEST).
            + (sizeof(ushort) + signerQualifiedName.Length)          //qualifiedSigner (TPM2B_NAME).
            + (sizeof(ushort) + nonce.Length)                        //extraData (TPM2B_DATA).
            + TpmsClockInfo.SerializedSize                           //clockInfo (TPMS_CLOCK_INFO).
            + sizeof(ulong)                                          //firmwareVersion.
            + (sizeof(ushort) + subjectName.Length)                  //attested.objectName (TPM2B_NAME).
            + (sizeof(ushort) + creationHash.Length);                //attested.creationHash (TPM2B_DIGEST).

        IMemoryOwner<byte> owner = pool.Rent(total);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span[..total]);

            writer.WriteUInt32(TpmConstants32.TPM_GENERATED_VALUE);
            writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_ATTEST_CREATION);
            writer.WriteTpm2b(signerQualifiedName);                              //qualifiedSigner: the signer's real Qualified Name.
            writer.WriteTpm2b(nonce);                                            //extraData: the caller's qualifyingData, echoed verbatim.

            clockInfo.WriteTo(ref writer);
            writer.WriteUInt64(SimulatedFirmwareVersion);

            //attested = TPMS_CREATION_INFO: the certified object's real Name, then the caller-supplied creation
            //hash the re-verified ticket bound.
            writer.WriteTpm2b(subjectName);
            writer.WriteTpm2b(creationHash);

            return (owner, total);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// <c>TPM2_GetTime()</c>: marshal the TIME attestation over the real Time/clockInfo snapshot and the
    /// signer's real Qualified Name, hash it through the registered digest seam under the signing scheme's own
    /// hash algorithm, and sign the digest with the signing key's retained scalar through the injected ECC
    /// backend.
    /// </summary>
    /// <remarks>
    /// This effect is the terminal owner of the carriers the request transferred into the action and into its
    /// response-session entries — the qualifying data and each slot's caller nonce — and releases them in its
    /// <c>finally</c> on every exit path, the attestation having copied the qualifying data's octets and the
    /// entries having been framed by then.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the marshaled attest and the signature transfers to the returned TpmTimeAttested, then to the TpmGetTimeResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> AttestTimeAsync(TpmGetTimeAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        try
        {
            TpmEccSigningBackend backend = context.SigningBackend
                ?? throw new InvalidOperationException("TPM2_GetTime() requires a signing backend, but none was supplied.");

            int hashSize = action.HashAlg.Value.GetDigestSize()
                ?? throw new InvalidOperationException($"No digest size is registered for hash algorithm '{action.HashAlg.Value}'.");
            Tag hashTag = action.HashAlg.Value.GetDigestTag()
                ?? throw new InvalidOperationException($"No digest tag is registered for hash algorithm '{action.HashAlg.Value}'.");

            (IMemoryOwner<byte> attest, int attestLength) = await BuildSignedTimeAttestAsync(
                action.SignerHierarchy.Value, action.SignerName.AsReadOnlyMemory(), action.QualifyingData.AsReadOnlyMemory(), action.Time, action.ClockSnapshot, context.Pool, cancellationToken).ConfigureAwait(false);
            Signature signature;
            try
            {
                using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
                    attest.Memory[..attestLength], hashSize, hashTag, context.Pool, cancellationToken: cancellationToken).ConfigureAwait(false);

                signature = await backend.SignDigest(
                    action.SignerPrivateKey.AsReadOnlyMemory(), digest.AsReadOnlyMemory(), action.SignerCurve.Value, context.Pool, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                attest.Dispose();
                throw;
            }

            return await CompleteAttestAsync(
                TpmCcConstants.TPM_CC_GetTime, attest, attestLength, signature, TpmiAlgSigScheme.FromValue(TpmAlgIdConstants.TPM_ALG_ECDSA), action.HashAlg, action.ResponseSessions,
                static (timeInfo, tpmtSignature) => new TpmTimeAttested(timeInfo, tpmtSignature), context, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            ReleaseAttestQualifyingData(action.QualifyingData, action.ResponseSessions);
        }
    }

    /// <summary>
    /// The RSA counterpart of <see cref="AttestTimeAsync"/>: same real-clock attestation marshaling, signed with
    /// the signing key's retained private key through the injected RSA backend under the requested RSA scheme.
    /// </summary>
    /// <remarks>
    /// This effect is the terminal owner of the carriers the request transferred into the action and into its
    /// response-session entries — the qualifying data and each slot's caller nonce — and releases them in its
    /// <c>finally</c> on every exit path.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the marshaled attest and the signature transfers to the returned TpmTimeAttested, then to the TpmGetTimeResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> AttestTimeRsaAsync(TpmRsaGetTimeAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        try
        {
            TpmRsaSigningBackend backend = context.RsaSigningBackend
                ?? throw new InvalidOperationException("TPM2_GetTime() over an RSA key requires an RSA signing backend, but none was supplied.");

            int hashSize = action.HashAlg.Value.GetDigestSize()
                ?? throw new InvalidOperationException($"No digest size is registered for hash algorithm '{action.HashAlg.Value}'.");
            Tag hashTag = action.HashAlg.Value.GetDigestTag()
                ?? throw new InvalidOperationException($"No digest tag is registered for hash algorithm '{action.HashAlg.Value}'.");

            (IMemoryOwner<byte> attest, int attestLength) = await BuildSignedTimeAttestAsync(
                action.SignerHierarchy.Value, action.SignerName.AsReadOnlyMemory(), action.QualifyingData.AsReadOnlyMemory(), action.Time, action.ClockSnapshot, context.Pool, cancellationToken).ConfigureAwait(false);
            Signature signature;
            try
            {
                using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
                    attest.Memory[..attestLength], hashSize, hashTag, context.Pool, cancellationToken: cancellationToken).ConfigureAwait(false);

                signature = await backend.SignDigest(
                    action.SignerPrivateKey.AsReadOnlyMemory(), digest.AsReadOnlyMemory(), action.Scheme.Value, action.HashAlg.Value, context.Pool, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                attest.Dispose();
                throw;
            }

            return await CompleteAttestAsync(
                TpmCcConstants.TPM_CC_GetTime, attest, attestLength, signature, action.Scheme, action.HashAlg, action.ResponseSessions,
                static (timeInfo, tpmtSignature) => new TpmTimeAttested(timeInfo, tpmtSignature), context, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            ReleaseAttestQualifyingData(action.QualifyingData, action.ResponseSessions);
        }
    }

    /// <summary>
    /// Computes the signer's Qualified Name and marshals the TIME attestation from it — shared between the ECC
    /// and RSA <c>TPM2_GetTime()</c> paths, which differ only in how they sign the resulting digest.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the marshaled-attest buffer transfers to the caller, which carries it to the response intent disposed by SerializeResponse.")]
    private static async ValueTask<(IMemoryOwner<byte> Owner, int Length)> BuildSignedTimeAttestAsync(
        uint signerHierarchy, ReadOnlyMemory<byte> signerName, ReadOnlyMemory<byte> qualifyingData, ulong time, TpmsClockInfo clockInfo, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        (IMemoryOwner<byte> signerQualifiedName, int signerQualifiedNameLength) =
            await ComputeHierarchyQualifiedNameAsync(signerHierarchy, signerName, pool, cancellationToken).ConfigureAwait(false);
        using(signerQualifiedName)
        {
            return BuildTimeAttest(signerQualifiedName.Memory.Span[..signerQualifiedNameLength], qualifyingData.Span, time, clockInfo, pool);
        }
    }

    /// <summary>
    /// Builds the marshaled <c>TPMS_ATTEST</c> for the TIME case (TPM 2.0 Library Part 2, clause 10.12.2) into a
    /// pooled buffer.
    /// </summary>
    /// <remarks>
    /// The attested <c>TPMS_TIME_ATTEST_INFO</c> reports the real Time and clockInfo the transition folded from
    /// state after the per-command advance; the SAME clockInfo snapshot is written both at the envelope level
    /// and inside the nested <c>TPMS_TIME_ATTEST_INFO</c> (TPM 2.0 Library Part 1, clause 36.7 — the two copies
    /// agree). firmwareVersion is likewise the same simulator-fixed constant in both places.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the marshaled-attest buffer transfers to the caller, which carries it to the response intent disposed by SerializeResponse.")]
    private static (IMemoryOwner<byte> Owner, int Length) BuildTimeAttest(ReadOnlySpan<byte> signerQualifiedName, ReadOnlySpan<byte> nonce, ulong time, TpmsClockInfo clockInfo, BaseMemoryPool pool)
    {
        int total =
            sizeof(uint) + sizeof(ushort)                            //magic (TPM_GENERATED) + type (TPMI_ST_ATTEST).
            + (sizeof(ushort) + signerQualifiedName.Length)          //qualifiedSigner (TPM2B_NAME).
            + (sizeof(ushort) + nonce.Length)                        //extraData (TPM2B_DATA).
            + TpmsClockInfo.SerializedSize                           //clockInfo (TPMS_CLOCK_INFO).
            + sizeof(ulong)                                          //firmwareVersion.
            + TpmsTimeAttestInfo.SerializedSize;                     //attested (TPMS_TIME_ATTEST_INFO, fixed layout).

        IMemoryOwner<byte> owner = pool.Rent(total);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span[..total]);

            writer.WriteUInt32(TpmConstants32.TPM_GENERATED_VALUE);
            writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_ATTEST_TIME);
            writer.WriteTpm2b(signerQualifiedName);                              //qualifiedSigner: the signer's real Qualified Name.
            writer.WriteTpm2b(nonce);                                            //extraData: the caller's qualifyingData, echoed verbatim.

            clockInfo.WriteTo(ref writer);
            writer.WriteUInt64(SimulatedFirmwareVersion);

            //attested = TPMS_TIME_ATTEST_INFO: the real time, the same clockInfo snapshot as the envelope copy,
            //and the same firmware-version constant.
            new TpmsTimeAttestInfo(new TpmsTimeInfo(time, clockInfo), SimulatedFirmwareVersion).WriteTo(ref writer);

            return (owner, total);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// <c>TPM2_NV_Certify()</c>: compute the NV Index's real Name, marshal the NV attestation over it and the
    /// requested window of retained contents, hash it through the registered digest seam under the signing
    /// scheme's own hash algorithm, and sign the digest with the signing key's retained scalar through the
    /// injected ECC backend.
    /// </summary>
    /// <remarks>
    /// The signed pair is fed back plain, or — when <see cref="TpmNvCertifyAction.ResponseSessions"/> is
    /// non-empty — framed through <see cref="FrameAttestOverSessionsAsync"/> with one response entry per command
    /// session; the attestation itself is identical on both arms, since a session authorizes the command without
    /// altering what is attested (TPM 2.0 Library Part 3, clause 31.16.1). This effect is the terminal owner of
    /// the carriers the request transferred into the action and into its response-session entries — the qualifying
    /// data and each slot's caller nonce — and releases them in its <c>finally</c> on every exit path, the
    /// attestation having copied the qualifying data's octets and the entries having been framed by then.
    /// </remarks>
    /// <param name="action">The declared action carrying the signer, the Index's public-area fields, the window to attest, and the response-session list.</param>
    /// <param name="context">The effect context supplying the signing backend, the RNG, and the memory pool.</param>
    /// <param name="cancellationToken">A token observed across the digest and signing operations.</param>
    /// <returns>The attest-and-signature feedback, or its session-framed counterpart.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the marshaled attest and the signature transfers either to the returned TpmNvIndexCertified (then to the TpmNvCertifyResponse intent, released by SerializeResponse after framing) or to FrameAttestOverSessionsAsync, which consumes both while framing the parameter area.")]
    private static async ValueTask<TpmSimulatorInput> CertifyNvIndexAsync(TpmNvCertifyAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        try
        {
            TpmEccSigningBackend backend = context.SigningBackend
                ?? throw new InvalidOperationException("TPM2_NV_Certify() requires a signing backend, but none was supplied.");

            int hashSize = action.HashAlg.Value.GetDigestSize()
                ?? throw new InvalidOperationException($"No digest size is registered for hash algorithm '{action.HashAlg.Value}'.");
            Tag hashTag = action.HashAlg.Value.GetDigestTag()
                ?? throw new InvalidOperationException($"No digest tag is registered for hash algorithm '{action.HashAlg.Value}'.");

            (IMemoryOwner<byte> attest, int attestLength) = await BuildSignedNvCertifyAttestAsync(
                action.NvIndex.Value, action.NvIndexNameAlg, action.NvIndexAttributes, action.NvIndexAuthPolicy, action.NvIndexDataSize,
                action.Offset, action.NvContents,
                action.SignerHierarchy.Value, action.SignerName.AsReadOnlyMemory(), action.QualifyingData.AsReadOnlyMemory(), action.ClockSnapshot, context.Pool, cancellationToken).ConfigureAwait(false);

            Signature signature;
            try
            {
                using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
                    attest.Memory[..attestLength], hashSize, hashTag, context.Pool, cancellationToken: cancellationToken).ConfigureAwait(false);

                signature = await backend.SignDigest(
                    action.SignerPrivateKey.AsReadOnlyMemory(), digest.AsReadOnlyMemory(), action.SignerCurve.Value, context.Pool, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                attest.Dispose();
                throw;
            }

            return await CompleteAttestAsync(
                TpmCcConstants.TPM_CC_NV_Certify, attest, attestLength, signature, TpmiAlgSigScheme.FromValue(TpmAlgIdConstants.TPM_ALG_ECDSA), action.HashAlg, action.ResponseSessions,
                static (certifyInfo, tpmtSignature) => new TpmNvIndexCertified(certifyInfo, tpmtSignature), context, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            ReleaseAttestQualifyingData(action.QualifyingData, action.ResponseSessions);
        }
    }

    /// <summary>
    /// The RSA counterpart of <see cref="CertifyNvIndexAsync"/>: same Index-Name computation and attestation
    /// marshaling, signed with the signing key's retained private key through the injected RSA backend under the
    /// requested RSA scheme.
    /// </summary>
    /// <remarks>
    /// This effect is the terminal owner of the carriers the request transferred into the action and into its
    /// response-session entries — the qualifying data and each slot's caller nonce — and releases them in its
    /// <c>finally</c> on every exit path.
    /// </remarks>
    /// <param name="action">The declared action carrying the signer, the Index's public-area fields, the window to attest, and the response-session list.</param>
    /// <param name="context">The effect context supplying the RSA signing backend, the RNG, and the memory pool.</param>
    /// <param name="cancellationToken">A token observed across the digest and signing operations.</param>
    /// <returns>The attest-and-signature feedback, or its session-framed counterpart.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the marshaled attest and the signature transfers either to the returned TpmNvIndexCertified (then to the TpmNvCertifyResponse intent, released by SerializeResponse after framing) or to FrameAttestOverSessionsAsync, which consumes both while framing the parameter area.")]
    private static async ValueTask<TpmSimulatorInput> CertifyNvIndexRsaAsync(TpmRsaNvCertifyAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        try
        {
            TpmRsaSigningBackend backend = context.RsaSigningBackend
                ?? throw new InvalidOperationException("TPM2_NV_Certify() over an RSA key requires an RSA signing backend, but none was supplied.");

            int hashSize = action.HashAlg.Value.GetDigestSize()
                ?? throw new InvalidOperationException($"No digest size is registered for hash algorithm '{action.HashAlg.Value}'.");
            Tag hashTag = action.HashAlg.Value.GetDigestTag()
                ?? throw new InvalidOperationException($"No digest tag is registered for hash algorithm '{action.HashAlg.Value}'.");

            (IMemoryOwner<byte> attest, int attestLength) = await BuildSignedNvCertifyAttestAsync(
                action.NvIndex.Value, action.NvIndexNameAlg, action.NvIndexAttributes, action.NvIndexAuthPolicy, action.NvIndexDataSize,
                action.Offset, action.NvContents,
                action.SignerHierarchy.Value, action.SignerName.AsReadOnlyMemory(), action.QualifyingData.AsReadOnlyMemory(), action.ClockSnapshot, context.Pool, cancellationToken).ConfigureAwait(false);

            Signature signature;
            try
            {
                using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
                    attest.Memory[..attestLength], hashSize, hashTag, context.Pool, cancellationToken: cancellationToken).ConfigureAwait(false);

                signature = await backend.SignDigest(
                    action.SignerPrivateKey.AsReadOnlyMemory(), digest.AsReadOnlyMemory(), action.Scheme.Value, action.HashAlg.Value, context.Pool, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                attest.Dispose();
                throw;
            }

            return await CompleteAttestAsync(
                TpmCcConstants.TPM_CC_NV_Certify, attest, attestLength, signature, action.Scheme, action.HashAlg, action.ResponseSessions,
                static (certifyInfo, tpmtSignature) => new TpmNvIndexCertified(certifyInfo, tpmtSignature), context, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            ReleaseAttestQualifyingData(action.QualifyingData, action.ResponseSessions);
        }
    }

    /// <summary>
    /// Completes an attest command's effect once its attestation is marshaled and signed: wraps the pair into the
    /// structures the response carries — the attest as a <see cref="Tpm2bAttest"/> over the marshaled octets, the
    /// signature as a <see cref="TpmtSignature"/> — and routes them to the shape the authorization area asks for:
    /// the command's own plain result when every slot was a password, or the session-framed
    /// <see cref="TpmAttestedOverSessions"/> when at least one slot carried a real session (TPM 2.0 Library Part 2,
    /// clauses 10.12.13 and 11.3.4; Part 1, clause 16.6.1).
    /// </summary>
    /// <remarks>
    /// This method is the terminal owner of <paramref name="attest"/> and <paramref name="signature"/> from the
    /// moment it is entered: the attest storage is adopted by the <see cref="Tpm2bAttest"/> (and released by it
    /// if the octets fail to parse), the signature octets are copied into the <see cref="TpmtSignature"/>'s own
    /// buffers and the <see cref="Signature"/> released, and both structures then travel inside the returned
    /// result to the framing step that disposes them.
    /// </remarks>
    /// <param name="commandCode">The attest command — on the session arm the <c>commandCode</c> term of every entry's rpHash, threaded onward so the resuming transition labels itself.</param>
    /// <param name="attest">The pooled buffer holding the marshaled <c>TPMS_ATTEST</c>; adopted here.</param>
    /// <param name="attestLength">The number of valid octets in <paramref name="attest"/>.</param>
    /// <param name="signature">The signature over the attestation digest; consumed here.</param>
    /// <param name="signatureScheme">The signing algorithm, the <c>TPMT_SIGNATURE</c> selector.</param>
    /// <param name="hashAlg">The signing scheme's hash algorithm, carried inside the signature member.</param>
    /// <param name="responseSessions">Every session in the command's authorization area, in command-session order; empty on the all-password arm.</param>
    /// <param name="plainResult">Builds the command's own plain-arm result from the two structures.</param>
    /// <param name="context">The effect context supplying the RNG and the memory pool.</param>
    /// <param name="cancellationToken">A token observed across the rpHash and HMAC computations.</param>
    /// <returns>The feedback input for the resuming transition.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the attest and signature structures transfers either to the plain result (then to the command's response intent, released by SerializeResponse after framing) or to FrameAttestOverSessionsAsync, which consumes both while framing the parameter area.")]
    private static async ValueTask<TpmSimulatorInput> CompleteAttestAsync(
        TpmCcConstants commandCode,
        IMemoryOwner<byte> attest,
        int attestLength,
        Signature signature,
        TpmiAlgSigScheme signatureScheme,
        TpmiAlgHash hashAlg,
        ImmutableArray<TpmAttestResponseSession> responseSessions,
        Func<Tpm2bAttest, TpmtSignature, TpmSimulatorInput> plainResult,
        TpmActionContext context,
        CancellationToken cancellationToken)
    {
        Tpm2bAttest attestStructure;
        TpmtSignature signatureStructure;
        using(signature)
        {
            attestStructure = Tpm2bAttest.FromMarshaled(attest, attestLength, context.Pool);
            try
            {
                signatureStructure = TpmtSignature.Create(signatureScheme.Value, hashAlg.Value, signature.AsReadOnlySpan(), context.Pool);
            }
            catch
            {
                attestStructure.Dispose();
                throw;
            }
        }

        if(responseSessions.IsDefaultOrEmpty)
        {
            return plainResult(attestStructure, signatureStructure);
        }

        return await FrameAttestOverSessionsAsync(commandCode, attestStructure, signatureStructure, responseSessions, context, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Frames a signed attestation for the session-authorized arm of an attest command — <c>TPM2_Certify()</c>,
    /// <c>TPM2_CertifyCreation()</c>, <c>TPM2_Quote()</c>, <c>TPM2_GetTime()</c>, <c>TPM2_NV_Certify()</c>: the
    /// <c>TPM2B_ATTEST ‖ TPMT_SIGNATURE</c> response parameter area, then one response session entry per command
    /// session over that area's rpHash (TPM 2.0 Library Part 1, clause 16.8 equation 16; clause 16.6.1).
    /// </summary>
    /// <remarks>
    /// This method is the terminal owner of <paramref name="attest"/> and <paramref name="signature"/> from the
    /// moment it is entered: both are written into the parameter area and released there — the framed octets are
    /// what the rest of the pipeline needs, since rpHash must cover exactly the bytes the response will carry.
    /// The plain arm of every attest command never enters here; its effect feeds the pair back inside the
    /// command's own plain result (<see cref="TpmObjectCertified"/> and its siblings).
    /// </remarks>
    /// <param name="commandCode">The attest command — the <c>commandCode</c> term of every entry's rpHash, threaded onward so the resuming transition labels itself.</param>
    /// <param name="attest">The <c>TPM2B_ATTEST</c>; disposed here.</param>
    /// <param name="signature">The <c>TPMT_SIGNATURE</c> over the attestation digest; disposed here.</param>
    /// <param name="responseSessions">Every session in the command's authorization area, in command-session order; never empty here.</param>
    /// <param name="context">The effect context supplying the RNG and the memory pool.</param>
    /// <param name="cancellationToken">A token observed across the rpHash and HMAC computations.</param>
    /// <returns>The <see cref="TpmAttestedOverSessions"/> feedback input for <c>OnAttestedOverSessions</c>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parameter-area buffer transfers to the returned TpmAttestedOverSessions, then to the TpmAttestOverSessionsResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> FrameAttestOverSessionsAsync(
        TpmCcConstants commandCode,
        Tpm2bAttest attest,
        TpmtSignature signature,
        ImmutableArray<TpmAttestResponseSession> responseSessions,
        TpmActionContext context,
        CancellationToken cancellationToken)
    {
        (IMemoryOwner<byte> parameterArea, int parameterLength) = FrameAttestParameterArea(attest, signature, context.Pool);
        try
        {
            return await FrameAttestSessionEntriesAsync(commandCode, parameterArea, parameterLength, responseSessions, context, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            //The area can hold ciphertext derived from a session key by the time framing fails, so it is cleared
            //before the buffer goes back to the pool — the discipline the encrypt-attributed TPM2_Unseal() and
            //TPM2_GetRandom() paths already keep over their own framed areas.
            parameterArea.Memory.Span[..parameterLength].Clear();
            parameterArea.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Lays a signed attestation out as the response parameter area rpHash will cover: the attest structure
    /// (<c>TPM2B_ATTEST</c>) followed by <c>signature</c> (<c>TPMT_SIGNATURE</c>) — the response shape every
    /// attest command shares (TPM 2.0 Library Part 3, Tables 90, 92, 94, 100, and 255; Part 1, clause 16.8
    /// equation 16).
    /// </summary>
    /// <remarks>
    /// Consumes <paramref name="attest"/> and <paramref name="signature"/>: once their octets are in the framed
    /// buffer nothing downstream needs the originals, so this is where they are released — including on every
    /// failure path, which is also why the layout is done synchronously, with no await able to interleave while
    /// three pooled owners are in hand at once. Each structure writes itself, so the session arm's rpHash input
    /// and the plain arm's framed response are byte-identical by construction.
    /// </remarks>
    /// <param name="attest">The <c>TPM2B_ATTEST</c>; disposed here.</param>
    /// <param name="signature">The <c>TPMT_SIGNATURE</c> over the attestation digest; disposed here.</param>
    /// <param name="pool">The memory pool backing the framed parameter area.</param>
    /// <returns>The framed parameter area and its valid length.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the framed parameter-area buffer transfers to the caller, which releases it if any later framing step fails and otherwise hands it to the response intent.")]
    private static (IMemoryOwner<byte> Owner, int Length) FrameAttestParameterArea(Tpm2bAttest attest, TpmtSignature signature, BaseMemoryPool pool)
    {
        using(attest)
        using(signature)
        {
            int parameterLength = attest.GetSerializedSize() + signature.GetSerializedSize();

            IMemoryOwner<byte> owner = pool.Rent(Math.Max(parameterLength, 1));
            try
            {
                var writer = new TpmWriter(owner.Memory.Span[..parameterLength]);
                attest.WriteTo(ref writer);
                signature.WriteTo(ref writer);

                return (owner, parameterLength);
            }
            catch
            {
                owner.Dispose();
                throw;
            }
        }
    }

    /// <summary>
    /// Rolls a fresh nonceTPM for every real session in an attest command's authorization area, encrypts the
    /// <c>TPM2B_ATTEST</c> over the session carrying the <c>encrypt</c> attribute where one does, and computes
    /// each session's response HMAC over the framed parameter area's rpHash (TPM 2.0 Library Part 1, clause 16.8
    /// equation 16; clauses 16.6.1 and 19.1), emitting the <c>TPM_RS_PW</c> slots' placeholders in place so the
    /// entries stay in command-session order.
    /// </summary>
    /// <remarks>
    /// The three steps are in the only order that works: the response nonceTPM must exist before it can key the
    /// keystream, and rpHash must cover what the response will actually carry, so it is roll, then encrypt, then
    /// rpHash, then HMAC.
    /// rpHash is computed once per DISTINCT session hash algorithm and only for the real sessions: a password
    /// slot has no session hash algorithm and verifies nothing, so it contributes no digest and receives an empty
    /// nonce and an empty HMAC. A real slot's response HMAC is keyed on its own <c>sessionKey ‖ authValue</c>,
    /// the same key its command HMAC used where one was verified (clause 17.6.5). rpHash's <c>commandCode</c>
    /// term is the attest command's own, so an entry framed for one attest command never verifies as another's.
    /// Each entry's caller nonce is BORROWED here — read at the HMAC primitive as the nonceOlder term and never
    /// released — because the effect that called this is the entry's terminal owner and releases it afterwards.
    /// </remarks>
    /// <param name="commandCode">The attest command — rpHash's <c>commandCode</c> term, carried into the feedback.</param>
    /// <param name="parameterArea">The already-framed <c>TPM2B_ATTEST ‖ TPMT_SIGNATURE</c> response parameter area; ownership passes to the returned feedback.</param>
    /// <param name="parameterLength">The number of valid octets in <paramref name="parameterArea"/>.</param>
    /// <param name="responseSessions">Every session in the command's authorization area, in command-session order.</param>
    /// <param name="context">The effect context supplying the RNG and the memory pool.</param>
    /// <param name="cancellationToken">A token observed across the rpHash and HMAC computations.</param>
    /// <returns>The framed parameter area and every session's response entry, fed back to <c>OnAttestedOverSessions</c>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of each real entry's HMAC buffer transfers to the returned TpmAttestedOverSessions, then to the TpmAttestOverSessionsResponse intent, and is released by SerializeResponse after framing. The nonce pairs this method rolls are owned here until the framing overload returns, transfer into the entries on success, and are released by the catch on any fault.")]
    private static async ValueTask<TpmSimulatorInput> FrameAttestSessionEntriesAsync(
        TpmCcConstants commandCode,
        IMemoryOwner<byte> parameterArea,
        int parameterLength,
        ImmutableArray<TpmAttestResponseSession> responseSessions,
        TpmActionContext context,
        CancellationToken cancellationToken)
    {
        int realCount = 0;
        for(int i = 0; i < responseSessions.Length; i++)
        {
            if(!responseSessions[i].IsPasswordPlaceholder)
            {
                realCount++;
            }
        }

        var realAlgs = new TpmiAlgHash[realCount];
        int nonceIndex = 0;
        for(int i = 0; i < responseSessions.Length; i++)
        {
            TpmAttestResponseSession candidate = responseSessions[i];
            if(candidate.IsPasswordPlaceholder)
            {
                continue;
            }

            realAlgs[nonceIndex] = candidate.SessionAlg;
            nonceIndex++;
        }

        (Tpm2bNonce[] framedNonces, Tpm2bNonce[] retainedNonces) = RollSessionNonces(realAlgs, context);
        try
        {
            return await FrameAttestSessionEntriesAsync(
                commandCode, parameterArea, parameterLength, responseSessions, realAlgs, framedNonces, retainedNonces, context, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            //The rolled pairs' only owner is this frame until the framed entries adopt them.
            ReleaseSessionNonces(framedNonces, retainedNonces);
            throw;
        }
    }

    /// <summary>
    /// Frames each attest-command response session entry over the rolled nonceTPM pairs
    /// <see cref="FrameAttestSessionEntriesAsync(TpmCcConstants, IMemoryOwner{byte}, int, ImmutableArray{TpmAttestResponseSession}, TpmActionContext, CancellationToken)"/>
    /// drew — the response-direction parameter encryption, then rpHash per distinct session hash algorithm, then
    /// each real session's own response HMAC (TPM 2.0 Library Part 1, clauses 16.8 and 19.1).
    /// </summary>
    /// <param name="commandCode">The attest command the response answers, the <c>commandCode</c> term of every entry's rpHash.</param>
    /// <param name="parameterArea">The framed <c>TPM2B_ATTEST ‖ TPMT_SIGNATURE</c> parameter area, transformed in place when a session encrypts.</param>
    /// <param name="parameterLength">The number of valid octets in <paramref name="parameterArea"/>.</param>
    /// <param name="responseSessions">Every session owed an entry, in command-session order.</param>
    /// <param name="realAlgs">The real (non-placeholder) sessions' hash algorithms, in entry order.</param>
    /// <param name="framedNonces">The rolled nonces the entries frame; ownership transfers to the entries this builds.</param>
    /// <param name="retainedNonces">The rolled nonces the rolling transition installs; ownership transfers to the entries this builds.</param>
    /// <param name="context">The effect context supplying the memory pool.</param>
    /// <param name="cancellationToken">A token observed across the encryption, rpHash and HMAC computations.</param>
    /// <returns>The framed parameter area and every session's response entry, fed back to <c>OnAttestedOverSessions</c>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of each real entry's HMAC buffer transfers to the returned TpmAttestedOverSessions, then to the TpmAttestOverSessionsResponse intent, and is released by SerializeResponse after framing; the rolled nonce carriers are released by the caller's catch when this method faults.")]
    private static async ValueTask<TpmSimulatorInput> FrameAttestSessionEntriesAsync(
        TpmCcConstants commandCode,
        IMemoryOwner<byte> parameterArea,
        int parameterLength,
        ImmutableArray<TpmAttestResponseSession> responseSessions,
        TpmiAlgHash[] realAlgs,
        Tpm2bNonce[] framedNonces,
        Tpm2bNonce[] retainedNonces,
        TpmActionContext context,
        CancellationToken cancellationToken)
    {
        //Encrypt the data portion of the FIRST response parameter — the TPM2B_ATTEST, after its 2-octet size,
        //which is never protected (Part 1, clause 19.1) — over whichever session carries the encrypt attribute
        //(at most one per command, clause 19.1), with its freshly rolled nonceTPM as nonceNewer and its command
        //caller nonce as nonceOlder (clause 19.2). This sits between the nonce roll and the rpHash because
        //"Parameters in responses are encrypted before any rpHash is computed" (clause 19.1): every entry's HMAC
        //therefore covers the CIPHERTEXT, which is the only thing that makes the transform detectably intact.
        for(int i = 0, realCandidate = 0; i < responseSessions.Length; i++)
        {
            TpmAttestResponseSession candidate = responseSessions[i];
            if(candidate.IsPasswordPlaceholder)
            {
                continue;
            }

            if(candidate.Encrypts)
            {
                ushort attestSize = BinaryPrimitives.ReadUInt16BigEndian(parameterArea.Memory.Span[..sizeof(ushort)]);
                await ApplyResponseEncryptionAsync(
                    candidate.Symmetric, candidate.SessionAlg, candidate.SessionKey, candidate.EntityAuthValue,
                    framedNonces[realCandidate].AsReadOnlyMemory(), candidate.NonceCaller.AsReadOnlyMemory(),
                    parameterArea.Memory.Slice(sizeof(ushort), attestSize), context.Pool, cancellationToken).ConfigureAwait(false);

                break;
            }

            realCandidate++;
        }

        (Memory<byte>[] rpHashPerSession, List<(TpmiAlgHash Alg, IMemoryOwner<byte> Owner)> rpHashOwners) = await ComputeRpHashPerSessionAsync(
            realAlgs, commandCode, parameterArea.Memory[..parameterLength], context.Pool, cancellationToken).ConfigureAwait(false);

        var entries = ImmutableArray.CreateBuilder<TpmAttestFramedSessionEntry>(responseSessions.Length);
        try
        {
            int realIndex = 0;
            for(int i = 0; i < responseSessions.Length; i++)
            {
                TpmAttestResponseSession session = responseSessions[i];
                if(session.IsPasswordPlaceholder)
                {
                    entries.Add(new TpmAttestFramedSessionEntry(
                        IsPasswordPlaceholder: true, session.SessionHandle, Tpm2bNonce.Empty, Tpm2bNonce.Empty, session.SessionAttributes, Hmac: null));

                    continue;
                }

                ReadOnlyMemory<byte> sessionKeyBytes = session.SessionKey.AsReadOnlyMemory();
                ReadOnlyMemory<byte> authValueBytes = TpmLifecycleTransitions.StripTrailingZeros(session.AuthValue.AsReadOnlyMemory());
                int sessionValueLength = sessionKeyBytes.Length + authValueBytes.Length;
                using IMemoryOwner<byte> sessionValueOwner = context.Pool.Rent(Math.Max(sessionValueLength, 1), AllocationKind.Pinned);
                Memory<byte> sessionValue = sessionValueOwner.Memory[..sessionValueLength];
                sessionKeyBytes.CopyTo(sessionValue);
                authValueBytes.CopyTo(sessionValue[sessionKeyBytes.Length..]);

                Tpm2bAuth hmac = await ComputeResponseHmacAsync(
                    session.SessionAlg, sessionValue, rpHashPerSession[realIndex], framedNonces[realIndex].AsReadOnlyMemory(), session.NonceCaller.AsReadOnlyMemory(), session.SessionAttributes, context.Pool, cancellationToken).ConfigureAwait(false);

                sessionValueOwner.Memory.Span[..sessionValueLength].Clear();

                entries.Add(new TpmAttestFramedSessionEntry(
                    IsPasswordPlaceholder: false, session.SessionHandle, framedNonces[realIndex], retainedNonces[realIndex], session.SessionAttributes, hmac));
                realIndex++;
            }

            return new TpmAttestedOverSessions(commandCode, TpmParameterArea.Adopt(parameterArea, parameterLength), entries.ToImmutable());
        }
        catch
        {
            foreach(TpmAttestFramedSessionEntry framed in entries)
            {
                framed.Hmac?.Dispose();
            }

            throw;
        }
        finally
        {
            foreach(var cached in rpHashOwners)
            {
                cached.Owner.Dispose();
            }
        }
    }

    /// <summary>
    /// Computes an NV Index's Name (<c>nameAlg || H_nameAlg(TPMS_NV_PUBLIC)</c>, TPM 2.0 Library Part 1, clause
    /// 16) — the same marshal-and-hash mechanism <see cref="ComputeNvNameForPolicyAsync"/> uses for
    /// <c>TPM2_PolicyNV()</c> — and marshals the NV attestation from it, the signer's Qualified Name, the
    /// requested offset, and the requested window of retained contents.
    /// </summary>
    /// <remarks>
    /// Shared between the ECC and RSA <c>TPM2_NV_Certify()</c> paths, which differ only in how they sign the
    /// resulting digest.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the marshaled-attest buffer transfers to the caller, which carries it to the response intent disposed by SerializeResponse.")]
    private static async ValueTask<(IMemoryOwner<byte> Owner, int Length)> BuildSignedNvCertifyAttestAsync(
        uint nvIndex, TpmiAlgHash nvIndexNameAlg, TpmaNv nvIndexAttributes, Tpm2bDigest nvIndexAuthPolicy, ushort nvIndexDataSize,
        ushort offset, ReadOnlyMemory<byte> nvContents,
        uint signerHierarchy, ReadOnlyMemory<byte> signerName, ReadOnlyMemory<byte> qualifyingData, TpmsClockInfo clockInfo, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        (IMemoryOwner<byte> indexName, int indexNameLength) =
            await ComputeNvIndexNameAsync(nvIndex, nvIndexNameAlg, nvIndexAttributes, nvIndexAuthPolicy, nvIndexDataSize, pool, cancellationToken).ConfigureAwait(false);
        using(indexName)
        {
            (IMemoryOwner<byte> signerQualifiedName, int signerQualifiedNameLength) =
                await ComputeHierarchyQualifiedNameAsync(signerHierarchy, signerName, pool, cancellationToken).ConfigureAwait(false);
            using(signerQualifiedName)
            {
                return BuildNvCertifyAttest(
                    indexName.Memory.Span[..indexNameLength],
                    offset,
                    nvContents.Span,
                    signerQualifiedName.Memory.Span[..signerQualifiedNameLength],
                    qualifyingData.Span,
                    clockInfo,
                    pool);
            }
        }
    }

    /// <summary>
    /// Marshals an NV Index's <c>TPMS_NV_PUBLIC</c> from the Index's own retained fields and computes
    /// <c>nameAlg ‖ H_nameAlg(TPMS_NV_PUBLIC)</c> through the shared nameAlg-agile
    /// <see cref="TpmObjectName"/> helper (TPM 2.0 Library Part 1, clause 14 and Table 6) — the single NV Name
    /// recipe every caller in this file routes through.
    /// </summary>
    /// <remarks>
    /// Every field the recipe hashes is supplied by the caller from the Index it is naming. <paramref name="nameAlg"/>
    /// and <paramref name="authPolicy"/> in particular are part of the hashed structure, so an Index defined with
    /// a SHA-384 Name algorithm, or with a non-empty access policy, has a Name that differs from an otherwise
    /// identical Index defined without them — a Name computed from assumed values would not resolve against the
    /// Index a caller reads with <c>TPM2_NV_ReadPublic()</c>, and an attestation carrying such a Name would bind
    /// to nothing.
    /// </remarks>
    /// <param name="nvIndex">The NV Index handle, the first field of the marshaled public area.</param>
    /// <param name="nameAlg">The Index's own Name algorithm: both a hashed field and the digest the Name is computed with.</param>
    /// <param name="attributes">The Index's current attributes (<c>TPMA_NV</c>).</param>
    /// <param name="authPolicy">The Index's own access policy digest (<c>TPM2B_DIGEST</c>, TPM 2.0 Library Part 2, clause 10.4.2, Table 92), a borrowed reference to the durable Index state's own carrier — copied into the marshaled public area and never disposed here; the empty sentinel when the Index was defined without a policy.</param>
    /// <param name="dataSize">The Index's declared data size.</param>
    /// <param name="pool">The memory pool backing the marshaling buffer and the returned Name.</param>
    /// <param name="cancellationToken">A token observed across the digest computation.</param>
    /// <returns>The pooled Name buffer and its valid length.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the Name buffer transfers to the caller, which releases it via a using declaration.")]
    private static async ValueTask<(IMemoryOwner<byte> Owner, int Length)> ComputeNvIndexNameAsync(
        uint nvIndex, TpmiAlgHash nameAlg, TpmaNv attributes, Tpm2bDigest authPolicy, ushort dataSize,
        BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        using var nvPublic = new TpmsNvPublic(nvIndex, nameAlg.Value, attributes, Tpm2bDigest.Create(authPolicy.AsReadOnlySpan(), pool), dataSize);
        int publicSize = nvPublic.SerializedSize;
        using IMemoryOwner<byte> marshaled = pool.Rent(publicSize);
        var writer = new TpmWriter(marshaled.Memory.Span[..publicSize]);
        nvPublic.WriteTo(ref writer);

        return await TpmObjectName.ComputeNameAsync(
            marshaled.Memory[..publicSize], (ushort)nameAlg.Value, pool, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Builds the marshaled <c>TPMS_ATTEST</c> for the NV case (TPM 2.0 Library Part 2, clause 10.12.8) into a
    /// pooled buffer.
    /// </summary>
    /// <remarks>
    /// Every field the host verifies is cryptographically real: magic, type (<c>TPM_ST_ATTEST_NV</c>),
    /// extraData, qualifiedSigner, the attested <c>TPMS_NV_CERTIFY_INFO.indexName</c> (the Index's real Name),
    /// offset, and nvContents (the retained octets at that offset). clockInfo is the real
    /// Clock/resetCount/restartCount/Safe snapshot the transition folded from state after the per-command
    /// advance; firmwareVersion is the simulator's fixed synthetic identity.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the marshaled-attest buffer transfers to the caller, which carries it to the response intent disposed by SerializeResponse.")]
    private static (IMemoryOwner<byte> Owner, int Length) BuildNvCertifyAttest(
        ReadOnlySpan<byte> indexName, ushort offset, ReadOnlySpan<byte> nvContents, ReadOnlySpan<byte> signerQualifiedName, ReadOnlySpan<byte> nonce, TpmsClockInfo clockInfo, BaseMemoryPool pool)
    {
        int total =
            sizeof(uint) + sizeof(ushort)                            //magic (TPM_GENERATED) + type (TPMI_ST_ATTEST).
            + (sizeof(ushort) + signerQualifiedName.Length)          //qualifiedSigner (TPM2B_NAME).
            + (sizeof(ushort) + nonce.Length)                        //extraData (TPM2B_DATA).
            + TpmsClockInfo.SerializedSize                           //clockInfo (TPMS_CLOCK_INFO).
            + sizeof(ulong)                                          //firmwareVersion.
            + (sizeof(ushort) + indexName.Length)                    //attested.indexName (TPM2B_NAME).
            + sizeof(ushort)                                         //attested.offset (UINT16).
            + (sizeof(ushort) + nvContents.Length);                  //attested.nvContents (TPM2B_MAX_NV_BUFFER).

        IMemoryOwner<byte> owner = pool.Rent(total);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span[..total]);

            writer.WriteUInt32(TpmConstants32.TPM_GENERATED_VALUE);
            writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_ATTEST_NV);
            writer.WriteTpm2b(signerQualifiedName);                              //qualifiedSigner: the signer's real Qualified Name.
            writer.WriteTpm2b(nonce);                                            //extraData: the caller's qualifyingData, echoed verbatim.

            clockInfo.WriteTo(ref writer);
            writer.WriteUInt64(SimulatedFirmwareVersion);

            //attested = TPMS_NV_CERTIFY_INFO: the Index's real Name, the requested offset, then the requested
            //window of retained NV contents.
            writer.WriteTpm2b(indexName);
            writer.WriteUInt16(offset);
            writer.WriteTpm2b(nvContents);

            return (owner, total);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// <c>TPM2_VerifySignature()</c> over an ECC key (Part 3, clause 20.1): verify the caller-supplied digest and
    /// signature against the key's own retained public point through the injected ECC backend's verify delegate
    /// — a public-key operation that needs no authorization and consults no sign attribute (contrast
    /// <c>TPM2_Sign()</c>, which needs both).
    /// </summary>
    /// <remarks>
    /// On a successful verification, re-derive the verifying key's hierarchy proof and compute the
    /// <c>TPMT_TK_VERIFIED</c> digest <c>HMAC(proof, TPM_ST_VERIFIED || digest || keyName)</c> — the mirror
    /// image of the creation ticket's name || creationHash order (Part 2, clause 10.7.4). A failed verification
    /// needs no ticket at all, so the rejection is decided here rather than the pure transition (mirrors
    /// <see cref="CertifyObjectCreationAsync"/>).
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the ticket-digest buffer transfers to the TPMT_TK_VERIFIED carried by the returned TpmSignatureVerified, then to the TpmVerifySignatureResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> VerifySignatureEccAsync(TpmVerifySignatureAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        //The effect is the digest carrier's terminal owner: the verification primitive and the ticket HMAC are
        //its only readers, so the using declaration releases it on every arm.
        using Tpm2bDigest digest = action.Digest;

        TpmEccSigningBackend backend = context.SigningBackend
            ?? throw new InvalidOperationException("TPM2_VerifySignature() over an ECC key requires a signing backend, but none was supplied.");

        bool verified = await backend.VerifyDigest(
            action.PublicPoint, digest.AsReadOnlyMemory(), action.Signature, action.Curve.Value, cancellationToken).ConfigureAwait(false);

        if(!verified)
        {
            return new TpmSignatureVerified(TpmRcConstants.TPM_RC_SIGNATURE, Validation: null);
        }

        using IMemoryOwner<byte> proof = await DeriveHierarchyProofAsync(context, action.KeyHierarchy.Value, cancellationToken).ConfigureAwait(false);
        IMemoryOwner<byte> ticketDigest = await ComputeVerifiedTicketDigestAsync(
            proof.Memory[..CreationDigestSize], digest.AsReadOnlyMemory(), action.KeyName.AsReadOnlyMemory(), context.Pool, cancellationToken).ConfigureAwait(false);

        //The digest helper rents the ticket octets itself, so the whole-ticket carrier adopts that rental.
        return new TpmSignatureVerified(
            TpmRcConstants.TPM_RC_SUCCESS, TpmtTkVerified.FromMarshaled(action.KeyHierarchy, ticketDigest, CreationDigestSize));
    }

    /// <summary>
    /// The RSA counterpart of <see cref="VerifySignatureEccAsync"/>: same verify-then-ticket flow, verified
    /// through the injected RSA backend's verify delegate under the requested RSA scheme.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the ticket-digest buffer transfers to the TPMT_TK_VERIFIED carried by the returned TpmSignatureVerified, then to the TpmVerifySignatureResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> VerifySignatureRsaAsync(TpmRsaVerifySignatureAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        //The effect is the digest carrier's terminal owner: the verification primitive and the ticket HMAC are
        //its only readers, so the using declaration releases it on every arm.
        using Tpm2bDigest digest = action.Digest;

        TpmRsaSigningBackend backend = context.RsaSigningBackend
            ?? throw new InvalidOperationException("TPM2_VerifySignature() over an RSA key requires an RSA signing backend, but none was supplied.");

        bool verified = await backend.VerifyDigest(
            action.PrivateKey.AsReadOnlyMemory(), digest.AsReadOnlyMemory(), action.Signature, action.Scheme.Value, action.HashAlg.Value, cancellationToken).ConfigureAwait(false);

        if(!verified)
        {
            return new TpmSignatureVerified(TpmRcConstants.TPM_RC_SIGNATURE, Validation: null);
        }

        using IMemoryOwner<byte> proof = await DeriveHierarchyProofAsync(context, action.KeyHierarchy.Value, cancellationToken).ConfigureAwait(false);
        IMemoryOwner<byte> ticketDigest = await ComputeVerifiedTicketDigestAsync(
            proof.Memory[..CreationDigestSize], digest.AsReadOnlyMemory(), action.KeyName.AsReadOnlyMemory(), context.Pool, cancellationToken).ConfigureAwait(false);

        //The digest helper rents the ticket octets itself, so the whole-ticket carrier adopts that rental.
        return new TpmSignatureVerified(
            TpmRcConstants.TPM_RC_SUCCESS, TpmtTkVerified.FromMarshaled(action.KeyHierarchy, ticketDigest, CreationDigestSize));
    }

    /// <summary>
    /// Computes <c>verifiedTicket digest = HMAC_contextAlg(proof, TPM_ST_VERIFIED || digest || keyName)</c>
    /// (TPM 2.0 Library Part 2, clause 10.7.4) — the mirror image of
    /// <see cref="ComputeCreationTicketDigestAsync"/>'s <c>TPM_ST_CREATION || Name || creationHash</c> field
    /// order.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the ticket-digest buffer transfers to the caller, which releases it via a using declaration.")]
    private static async ValueTask<IMemoryOwner<byte>> ComputeVerifiedTicketDigestAsync(
        ReadOnlyMemory<byte> proof, ReadOnlyMemory<byte> digest, ReadOnlyMemory<byte> keyName, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        int messageSize = sizeof(ushort) + digest.Length + keyName.Length;
        using IMemoryOwner<byte> message = pool.Rent(messageSize);
        WriteVerifiedTicketMessage(message.Memory.Span[..messageSize], digest.Span, keyName.Span);

        using HmacValue hmac = await CryptographicKeyEvents.ComputeHmacAsync(
            message.Memory[..messageSize], proof, CreationDigestSize, CryptoTags.HmacSha256Value, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        IMemoryOwner<byte> owner = pool.Rent(CreationDigestSize);
        try
        {
            hmac.AsReadOnlySpan().CopyTo(owner.Memory.Span[..CreationDigestSize]);

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>The verified-ticket HMAC message: <c>TPM_ST_VERIFIED</c> (UINT16) || digest || Name.</summary>
    private static void WriteVerifiedTicketMessage(Span<byte> destination, ReadOnlySpan<byte> digest, ReadOnlySpan<byte> keyName)
    {
        var writer = new TpmWriter(destination);
        writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_VERIFIED);
        writer.WriteBytes(digest);
        writer.WriteBytes(keyName);
    }

    /// <summary>
    /// Computes <c>authTicket digest = HMAC_contextAlg(proof, tag || cpHash || policyRef || authName || timeout
    /// || [timeEpoch] || [resetCount])</c> — equation 12 (TPM 2.0 Library Part 2, Section 10.7.5, Table 111),
    /// the formula shared by <c>TPM2_PolicySigned()</c>'s and <c>TPM2_PolicySecret()</c>'s TPMT_TK_AUTH mint and
    /// by <c>TPM2_PolicyTicket()</c>'s re-verification recompute (Part 3, clause 23.5.1, printed page 201: "the
    /// TPM uses the timeout, cpHashA, policyRef, and authName to construct a ticket to compare with the value in
    /// ticket").
    /// </summary>
    /// <remarks>
    /// timeEpoch is folded in only when timeout is non-zero; resetCount only when timeout is non-zero AND
    /// expiresOnReset is set — never unconditionally.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the ticket-digest buffer transfers to the caller, which releases it via a using declaration.")]
    private static async ValueTask<IMemoryOwner<byte>> ComputeAuthTicketDigestAsync(
        ReadOnlyMemory<byte> proof, ushort tag, ReadOnlyMemory<byte> cpHash, ReadOnlyMemory<byte> policyRef, ReadOnlyMemory<byte> authName,
        ulong timeout, bool expiresOnReset, uint timeEpoch, uint resetCount, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        bool includeTimeEpoch = timeout != 0;
        bool includeResetCount = timeout != 0 && expiresOnReset;

        int messageSize =
            sizeof(ushort) + cpHash.Length + policyRef.Length + authName.Length + sizeof(ulong)
            + (includeTimeEpoch ? sizeof(uint) : 0)
            + (includeResetCount ? sizeof(uint) : 0);
        using IMemoryOwner<byte> message = pool.Rent(messageSize);
        WriteAuthTicketMessage(
            message.Memory.Span[..messageSize], tag, cpHash.Span, policyRef.Span, authName.Span, timeout,
            includeTimeEpoch, timeEpoch, includeResetCount, resetCount);

        using HmacValue hmac = await CryptographicKeyEvents.ComputeHmacAsync(
            message.Memory[..messageSize], proof, CreationDigestSize, CryptoTags.HmacSha256Value, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        IMemoryOwner<byte> owner = pool.Rent(CreationDigestSize);
        try
        {
            hmac.AsReadOnlySpan().CopyTo(owner.Memory.Span[..CreationDigestSize]);

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Equation 12's own field order, byte-for-byte: tag || cpHash || policyRef || authName || timeout ||
    /// [timeEpoch] || [resetCount]. The three variable-length fields are the raw TPM2B buffer contents with no
    /// size prefix of their own — matching the reference's <c>CryptDigestUpdate2B</c>, which hashes only the
    /// buffer, never the size (Part 2, Table 111).
    /// </summary>
    /// <remarks>
    /// This is spec parity, not a defect: two distinct (cpHash, policyRef, authName) triples whose concatenation
    /// coincides hash identically, and on the REPLAY side <c>TPM2_PolicyTicket</c> accepts any re-split within
    /// the length bounds it enforces (cpHashA empty or digest-width; authName at most
    /// <see cref="Tpm2bName.MaxSize"/>) — so a re-split replay verifies but then folds the shifted
    /// (policyRef, authName) pair into a DIFFERENT policyDigest, authorizing nothing the original could. The
    /// residual constraint is those length bounds, not any fixed-length Name shape on the mint side; real TPMs
    /// share the property.
    /// </remarks>
    private static void WriteAuthTicketMessage(
        Span<byte> destination, ushort tag, ReadOnlySpan<byte> cpHash, ReadOnlySpan<byte> policyRef, ReadOnlySpan<byte> authName,
        ulong timeout, bool includeTimeEpoch, uint timeEpoch, bool includeResetCount, uint resetCount)
    {
        var writer = new TpmWriter(destination);
        writer.WriteUInt16(tag);
        writer.WriteBytes(cpHash);
        writer.WriteBytes(policyRef);
        writer.WriteBytes(authName);
        writer.WriteUInt64(timeout);

        if(includeTimeEpoch)
        {
            writer.WriteUInt32(timeEpoch);
        }

        if(includeResetCount)
        {
            writer.WriteUInt32(resetCount);
        }
    }

    /// <summary>
    /// Frames a <c>TPM2_PolicySecret()</c>/<c>TPM2_PolicySigned()</c> response's timeout + policyTicket (TPM 2.0
    /// Library Part 3, clauses 23.4/23.3): a NULL ticket (empty TPM2B_TIMEOUT, <c>TPM_RH_NULL</c> hierarchy,
    /// empty digest — Part 2, Section 10.7.2's NULL-ticket convention, the tag set even on a NULL ticket) when
    /// <paramref name="ticketDigest"/> is null; otherwise the real 8-byte big-endian TPM2B_TIMEOUT (bit 63 =
    /// expires-on-reset, Section 10.4.10) and the real TPMT_TK_AUTH.
    /// </summary>
    private static void WriteAuthTicketResponse(
        ref TpmWriter writer, ushort tag, Tpm2bTimeout timeout, uint hierarchy, Tpm2bDigest? ticketDigest)
    {
        if(ticketDigest is null)
        {
            writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
            writer.WriteUInt16(tag);
            writer.WriteUInt32((uint)TpmRh.TPM_RH_NULL);
            writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);

            return;
        }

        timeout.WriteTo(ref writer);

        writer.WriteUInt16(tag);
        writer.WriteUInt32(hierarchy);
        ticketDigest.WriteTo(ref writer);
    }

    /// <summary>
    /// Rents a policyDigest destination at the session's own digest width and applies one <c>PolicyUpdate</c>
    /// formula into it (TPM 2.0 Library Part 1, clause 17.7; Part 3, clause 23), adopting the rental as the
    /// returned <c>TPM2B_DIGEST</c>.
    /// </summary>
    /// <remarks>
    /// This is the single seam every policyDigest advance runs through, whether the fold rides the shared fold
    /// action or an assertion's own verification effect: the destination has no length field and no adopter for
    /// an over-sized buffer, so it must be rented at exactly <c>TpmPolicyDigest.Size</c> for the session hash —
    /// which is why the step needs a frame holding a memory pool at all. The formula itself is synchronous, with
    /// no device round-trip in it. Terms the selected formula does not read are ignored, so a caller passes only
    /// what its own assertion carries.
    /// </remarks>
    /// <param name="fold">The formula to apply.</param>
    /// <param name="policyHashAlgorithm">The session's policy hash algorithm, sizing both the rental and the hash.</param>
    /// <param name="current">The session's current accumulated policyDigest; ignored by the two formulas that reset to a Zero Digest instead.</param>
    /// <param name="restrictedCommand">The command code <c>TPM2_PolicyCommandCode()</c> restricts to.</param>
    /// <param name="nameTerm">The Name term the fold hashes (the authorizing entity's, the signing key's, or the approving key's), as a borrowed Name carrier or a permanent entity's handle value.</param>
    /// <param name="policyRef">The policy qualifier the second <c>PolicyUpdate</c> hash always folds.</param>
    /// <param name="branches">The <c>TPM2_PolicyOR()</c> branch list.</param>
    /// <param name="pcrSelection">The marshaled <c>TPML_PCR_SELECTION</c> exactly as sent.</param>
    /// <param name="pcrDigest">The PCR digest the policy binds to — the caller's on a trial session, the live composite on a real one.</param>
    /// <param name="operandB">The comparison operand the argHash covers.</param>
    /// <param name="offset">The octet offset the argHash covers.</param>
    /// <param name="operation">The <c>TPM_EO</c> comparison the argHash covers.</param>
    /// <param name="pool">The memory pool the destination is rented from.</param>
    /// <returns>The advanced policyDigest in an owned carrier; ownership transfers to the caller.</returns>
    /// <exception cref="InvalidOperationException"><paramref name="fold"/> names no formula this seam applies, or <c>TPM2_PolicyOR()</c> was selected with no branch list.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the destination rental transfers to the returned Tpm2bDigest and from there to the caller's feedback record, whose resuming transition installs it on the session; a fold that throws releases the rental in the catch before rethrowing.")]
    private static Tpm2bDigest FoldPolicyDigest(
        TpmPolicyDigestFold fold,
        TpmiAlgHash policyHashAlgorithm,
        ReadOnlySpan<byte> current,
        TpmCcConstants restrictedCommand,
        TpmHandleName nameTerm,
        ReadOnlySpan<byte> policyRef,
        TpmlDigest? branches,
        ReadOnlySpan<byte> pcrSelection,
        ReadOnlySpan<byte> pcrDigest,
        ReadOnlySpan<byte> operandB,
        ushort offset,
        ushort operation,
        BaseMemoryPool pool)
    {
        //A permanent entity's Name IS its 4-octet big-endian handle value (Part 1, clause 14, Table 6), so a handle-form
        //term is materialized here — this is the frame that holds a memory pool, while the pure transition that
        //resolved the entity holds none. A computed Name is read straight out of the carrier that owns it.
        Span<byte> handleFormName = stackalloc byte[sizeof(uint)];
        ReadOnlySpan<byte> nameTermOctets = nameTerm.Read(handleFormName);

        int size = TpmPolicyDigest.Size(policyHashAlgorithm.Value);
        IMemoryOwner<byte> storage = pool.Rent(size);
        try
        {
            Span<byte> destination = storage.Memory.Span[..size];
            _ = fold switch
            {
                TpmPolicyDigestFold.CommandCode => TpmPolicyDigest.ExtendForCommandCode(current, restrictedCommand, policyHashAlgorithm.Value, destination),
                TpmPolicyDigestFold.AuthValue => TpmPolicyDigest.ExtendForAuthValue(current, policyHashAlgorithm.Value, destination),
                TpmPolicyDigestFold.Pcr => TpmPolicyDigest.ExtendForPcr(current, pcrSelection, pcrDigest, policyHashAlgorithm.Value, destination),
                TpmPolicyDigestFold.Or when branches is not null => TpmPolicyDigest.ExtendForOr(branches, policyHashAlgorithm.Value, destination, pool),
                TpmPolicyDigestFold.CounterTimer => TpmPolicyDigest.ExtendForCounterTimer(current, operandB, offset, operation, policyHashAlgorithm.Value, destination),
                TpmPolicyDigestFold.Secret => TpmPolicyDigest.ExtendForSecret(current, nameTermOctets, policyRef, policyHashAlgorithm.Value, destination),
                TpmPolicyDigestFold.Signed => TpmPolicyDigest.ExtendForSigned(current, nameTermOctets, policyRef, policyHashAlgorithm.Value, destination),
                TpmPolicyDigestFold.Authorize => TpmPolicyDigest.ExtendForAuthorize(nameTermOctets, policyRef, policyHashAlgorithm.Value, destination),
                TpmPolicyDigestFold.Nv => TpmPolicyDigest.ExtendForNv(current, operandB, offset, operation, nameTermOctets, policyHashAlgorithm.Value, destination),
                _ => throw new InvalidOperationException($"No policyDigest fold is defined for '{fold}'.")
            };

            return new Tpm2bDigest(storage);
        }
        catch
        {
            //This rental's only owner is this frame until the carrier adopts it, so a failing fold must release
            //it or the pinned rental is orphaned.
            storage.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Computes the live PCR composite digest a real (non-trial) <c>TPM2_PolicyPCR()</c> binds to:
    /// <c>pcrDigest = H(concatenation of the selected PCR values in ascending PCR-index order)</c> (TPM 2.0
    /// Library Part 4, <c>PCRComputeCurrentDigest</c>).
    /// </summary>
    /// <remarks>
    /// The composite is assembled from the values the transition gathered out of the durable SHA-256 bank, in the
    /// same ascending order <c>TPM2_Quote()</c> gathers, then hashed through the registered digest seam. The
    /// simulator models a SHA-256 PCR bank and takes the composite with SHA-256 (the bank's hash, which for the
    /// SHA-256 policy sessions this path serves is also the session hash the policyDigest folds it in with), so
    /// the seal-time and unseal-time digests agree by construction over the reset (all-zero) bank. The
    /// concatenation scratch is pooled and released before returning.
    /// </remarks>
    /// <param name="values">The selected PCR values in ascending index order — borrowed references to the durable bank's own memory.</param>
    /// <param name="pool">The memory pool the concatenation scratch and the digest are rented from.</param>
    /// <returns>The live composite digest; the caller releases it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the digest transfers to the caller, which releases it via a using declaration.")]
    private static DigestValue ComputeLivePcrComposite(ImmutableArray<ReadOnlyMemory<byte>> values, BaseMemoryPool pool)
    {
        const int digestSize = 32;                  //SHA-256 composite width — the bank's (and these sessions') hash.

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

        return CryptographicKeyEvents.ComputeDigest(
            composite.Memory.Span[..total], digestSize, CryptoTags.Sha256Digest, pool);
    }

    /// <summary>
    /// Advances a policy session's policyDigest for every assertion whose fold has no effect of its own on its
    /// path (TPM 2.0 Library Part 3, clause 23), keyed by <see cref="TpmFoldPolicyDigestAction.Fold"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>TPM2_PolicyPCR()</c> on a real session additionally computes the live PCR composite here and binds the
    /// policy to THAT value rather than the caller's (Part 3, clause 23.7; Part 4, <c>PCRComputeCurrentDigest</c>),
    /// answering <c>TPM_RC_VALUE</c> when the caller supplied a non-empty digest that does not match it — the one
    /// failure any assertion in this group has. A trial session folds the caller's digest verbatim.
    /// </para>
    /// <para>
    /// This effect is the terminal owner of every term carrier the action carries, releasing them all on every
    /// path; only the folded digest leaves the frame.
    /// </para>
    /// </remarks>
    /// <param name="action">The declared fold, carrying the formula's terms and the assertion's own response payload.</param>
    /// <param name="context">The effect context supplying the memory pool.</param>
    /// <returns>The advanced policyDigest paired with the payload the resuming transition frames.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the folded policyDigest transfers to the returned TpmPolicyDigestFolded, whose resuming transition installs it on the session record; every term carrier the action carried is released here in the finally.")]
    private static TpmPolicyDigestFolded FoldPolicyDigestForAssertion(TpmFoldPolicyDigestAction action, TpmActionContext context)
    {
        try
        {
            if(action.Fold == TpmPolicyDigestFold.Pcr && !action.IsTrialSession)
            {
                using DigestValue liveDigest = ComputeLivePcrComposite(action.PcrValues, context.Pool);

                //A real session may still state its expectation; when it does, it must match the live composite
                //or the assertion is refused (Part 3, clause 23.7) — the bind is always to the live value.
                ReadOnlySpan<byte> expected = action.PcrDigest.AsReadOnlySpan();
                if(!expected.IsEmpty && !expected.SequenceEqual(liveDigest.AsReadOnlySpan()))
                {
                    return Completed(TpmRcConstants.TPM_RC_VALUE, Tpm2bDigest.Empty);
                }

                return Completed(
                    TpmRcConstants.TPM_RC_SUCCESS,
                    FoldPolicyDigest(
                        action.Fold, action.PolicyHashAlgorithm, action.CurrentPolicyDigest.AsReadOnlySpan(), action.RestrictedCommand,
                        nameTerm: TpmHandleName.None, policyRef: default, branches: null, action.PcrSelectionBytes.Span, liveDigest.AsReadOnlySpan(),
                        operandB: default, action.Offset, action.Operation, context.Pool));
            }

            //TPM2_PolicyAuthorize() hashes the approving key's Name out of the carrier the request transferred
            //here; every other Name-carrying formula reads a borrow of a value another owner holds.
            TpmHandleName foldNameTerm = action.Fold == TpmPolicyDigestFold.Authorize
                ? TpmHandleName.FromName(action.KeySign)
                : action.NameTerm;

            return Completed(
                TpmRcConstants.TPM_RC_SUCCESS,
                FoldPolicyDigest(
                    action.Fold, action.PolicyHashAlgorithm, action.CurrentPolicyDigest.AsReadOnlySpan(), action.RestrictedCommand,
                    foldNameTerm, action.PolicyRef.AsReadOnlySpan(), action.Branches, action.PcrSelectionBytes.Span,
                    action.PcrDigest.AsReadOnlySpan(), action.OperandB.Span, action.Offset, action.Operation, context.Pool));
        }
        finally
        {
            //The fold consumed these terms, so this effect is their terminal owner on every path; the sentinels
            //the formulas that do not read them carry are dispose-immune.
            action.PolicyRef.Dispose();
            action.KeySign.Dispose();
            action.Branches?.Dispose();
            action.PcrDigest.Dispose();
            action.OperandB.Dispose();
        }

        //Local one-off helper: the uniform feedback shape both the folded and the refused arm return, relaying
        //the assertion's own label and response payload unchanged.
        TpmPolicyDigestFolded Completed(TpmRcConstants responseCode, Tpm2bDigest foldedDigest) =>
            new(responseCode, action.Fold, action.PolicySession, foldedDigest, action.Label, action.TimeoutMagnitude, action.AuthorizingSession);
    }

    /// <summary>
    /// <c>TPM2_PolicySigned()</c> over an ECC authObject (TPM 2.0 Library Part 3, Section 23.3): recompute aHash
    /// under the signature's own scheme hash (H_authAlg, independent of the session's own policy hash algorithm)
    /// through the registered async digest seam, then verify it against authObject's retained public point via
    /// the injected ECC backend — a public-key operation that needs no authorization and consults no sign
    /// attribute (mirrors <see cref="VerifySignatureEccAsync"/>).
    /// </summary>
    /// <remarks>
    /// The ticket-vs-NULL split and the policyDigest fold (<see cref="BuildPolicySignedVerifiedAsync"/>) then
    /// decide the response the continuation transition frames. This effect is the policy qualifier's terminal
    /// owner — the aHash, the ticket HMAC, and the fold are its only uses — while the cpHashA carrier travels
    /// onward to the continuation that either latches it onto the session or releases it.
    /// </remarks>
    private static async ValueTask<TpmSimulatorInput> VerifyPolicySignedEccAsync(TpmVerifyPolicySignedAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        try
        {
            TpmEccSigningBackend backend = context.SigningBackend
                ?? throw new InvalidOperationException("TPM2_PolicySigned() over an ECC key requires a signing backend, but none was supplied.");

            int aHashLength = SessionDigestSize(action.SchemeHashAlg);
            using IMemoryOwner<byte> aHash = await ComputePolicySignedAHashAsync(
                action.NonceTpm.AsReadOnlyMemory(), action.Expiration, action.CpHashA.AsReadOnlyMemory(), action.PolicyRef.AsReadOnlyMemory(), action.SchemeHashAlg, context.Pool, cancellationToken).ConfigureAwait(false);

            bool verified = await backend.VerifyDigest(
                action.PublicPoint, aHash.Memory[..aHashLength], action.Signature, action.Curve.Value, cancellationToken).ConfigureAwait(false);

            return await BuildPolicySignedVerifiedAsync(
                verified, action.PolicySession.Value, action.AuthObjectName, action.PolicyRef, action.PolicyHashAlgorithm,
                action.CurrentPolicyDigest, action.NonceTpm.AsReadOnlyMemory(), action.Expiration, action.CpHashA, action.Hierarchy.Value, action.Timeout, action.TimeEpoch, action.ResetCount,
                context, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            //The transfer into the feedback record never happened, so this frame is still the cpHashA carrier's
            //only owner.
            action.CpHashA.Dispose();
            throw;
        }
        finally
        {
            action.PolicyRef.Dispose();
            action.NonceTpm.Dispose();
        }
    }

    /// <summary>
    /// The RSA counterpart of <see cref="VerifyPolicySignedEccAsync"/>: same aHash-recompute-then-verify flow,
    /// verified through the injected RSA backend's verify delegate under the requested RSA scheme, with the same
    /// carrier ownership.
    /// </summary>
    private static async ValueTask<TpmSimulatorInput> VerifyPolicySignedRsaAsync(TpmRsaVerifyPolicySignedAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        try
        {
            TpmRsaSigningBackend backend = context.RsaSigningBackend
                ?? throw new InvalidOperationException("TPM2_PolicySigned() over an RSA key requires an RSA signing backend, but none was supplied.");

            int aHashLength = SessionDigestSize(action.SchemeHashAlg);
            using IMemoryOwner<byte> aHash = await ComputePolicySignedAHashAsync(
                action.NonceTpm.AsReadOnlyMemory(), action.Expiration, action.CpHashA.AsReadOnlyMemory(), action.PolicyRef.AsReadOnlyMemory(), action.SchemeHashAlg, context.Pool, cancellationToken).ConfigureAwait(false);

            bool verified = await backend.VerifyDigest(
                action.PrivateKey.AsReadOnlyMemory(), aHash.Memory[..aHashLength], action.Signature, action.Scheme.Value, action.SchemeHashAlg.Value, cancellationToken).ConfigureAwait(false);

            return await BuildPolicySignedVerifiedAsync(
                verified, action.PolicySession.Value, action.AuthObjectName, action.PolicyRef, action.PolicyHashAlgorithm,
                action.CurrentPolicyDigest, action.NonceTpm.AsReadOnlyMemory(), action.Expiration, action.CpHashA, action.Hierarchy.Value, action.Timeout, action.TimeEpoch, action.ResetCount,
                context, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            //The transfer into the feedback record never happened, so this frame is still the cpHashA carrier's
            //only owner.
            action.CpHashA.Dispose();
            throw;
        }
        finally
        {
            action.PolicyRef.Dispose();
            action.NonceTpm.Dispose();
        }
    }

    /// <summary>
    /// Shared by <see cref="VerifyPolicySignedEccAsync"/>/<see cref="VerifyPolicySignedRsaAsync"/> (the two
    /// key-type dispatches converge here once the signature itself is checked): a failed verification carries
    /// <c>TPM_RC_SIGNATURE</c> and no ticket.
    /// </summary>
    /// <remarks>
    /// On success, a non-negative expiration (no ticket requested, Part 3, Section 23.2.5) frames a NULL ticket
    /// the same way; only a negative expiration mints the real <c>TPM_ST_AUTH_SIGNED</c> ticket per equation 12
    /// (TPM 2.0 Library Part 2, Section 10.7.5, Table 111), keyed on authObject's own Hierarchy proof, with
    /// expiresOnReset selected by whether the caller's nonceTPM
    /// was empty (an absolute, session-unbound deadline).
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the folded policyDigest, the minted ticket-digest buffer, and the rented timeout carrier transfers to the returned TpmPolicySignedVerified; the continuation installs the digest on the session and TpmSimulator releases the rest once framed, and a failure after any of them was rented releases it in the catch.")]
    private static async ValueTask<TpmSimulatorInput> BuildPolicySignedVerifiedAsync(
        bool signatureVerified, uint policySession, Tpm2bName authObjectName, Tpm2bNonce policyRef, TpmiAlgHash policyHashAlgorithm,
        Tpm2bDigest currentPolicyDigest, ReadOnlyMemory<byte> nonceTpm, int expiration, Tpm2bDigest cpHashA, uint hierarchy,
        ulong timeout, uint timeEpoch, uint resetCount, TpmActionContext context, CancellationToken cancellationToken)
    {
        if(!signatureVerified)
        {
            return new TpmPolicySignedVerified(
                TpmRcConstants.TPM_RC_SIGNATURE, TpmiShPolicy.FromValue(policySession), Tpm2bDigest.Empty, cpHashA,
                0ul, Tpm2bTimeout.Empty, TpmiRhHierarchy.Null, TicketDigest: null);
        }

        //The fold is performed here rather than in the resuming transition because the destination must be
        //rented at the session's own digest width, and only a frame holding a memory pool can do that.
        Tpm2bDigest foldedDigest = FoldPolicyDigest(
            TpmPolicyDigestFold.Signed, policyHashAlgorithm, currentPolicyDigest.AsReadOnlySpan(), restrictedCommand: default,
            TpmHandleName.FromName(authObjectName), policyRef.AsReadOnlySpan(), branches: null, pcrSelection: default, pcrDigest: default,
            operandB: default, offset: 0, operation: 0, context.Pool);

        try
        {
            if(expiration >= 0)
            {
                //No ticket requested, but the deadline (when the caller supplied a non-zero expiration) still
                //participates in the session's timeout tracking (Part 3, Section 23.2.4) — only the response's
                //TPM2B_TIMEOUT/TPMT_TK_AUTH fields are NULL, per Section 23.2.5. The magnitude rides its own field so
                //the continuation can rank it while the framed carrier is the shared empty one the wire form needs.
                return new TpmPolicySignedVerified(
                    TpmRcConstants.TPM_RC_SUCCESS, TpmiShPolicy.FromValue(policySession), foldedDigest, cpHashA,
                    timeout, Tpm2bTimeout.Empty, TpmiRhHierarchy.Null, TicketDigest: null);
            }

            bool expiresOnReset = nonceTpm.IsEmpty;
            using IMemoryOwner<byte> proof = await DeriveHierarchyProofAsync(context, hierarchy, cancellationToken).ConfigureAwait(false);
            IMemoryOwner<byte> ticketDigest = await ComputeAuthTicketDigestAsync(
                proof.Memory[..CreationDigestSize], (ushort)TpmStConstants.TPM_ST_AUTH_SIGNED, cpHashA.AsReadOnlyMemory(), policyRef.AsReadOnlyMemory(), authObjectName.AsReadOnlyMemory(),
                timeout, expiresOnReset, timeEpoch, resetCount, context.Pool, cancellationToken).ConfigureAwait(false);

            //The digest helper rents exactly the ticket octets, so the TPM2B_DIGEST carrier adopts that rental,
            //and is released if the deadline's own rent then fails, so no failure orphans the pinned rental.
            var mintedTicket = new Tpm2bDigest(ticketDigest);
            Tpm2bTimeout framedTimeout;
            try
            {
                framedTimeout = Tpm2bTimeout.Create(timeout, expiresOnReset, context.Pool);
            }
            catch
            {
                mintedTicket.Dispose();
                throw;
            }

            return new TpmPolicySignedVerified(
                TpmRcConstants.TPM_RC_SUCCESS, TpmiShPolicy.FromValue(policySession), foldedDigest, cpHashA,
                timeout, framedTimeout, TpmiRhHierarchy.FromValue(hierarchy), mintedTicket);
        }
        catch
        {
            //The folded digest's only owner is this frame until the feedback record adopts it, so a failing mint
            //must release it or the pinned rental is orphaned.
            foldedDigest.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Computes <c>aHash = H_authAlg(nonceTPM || expiration || cpHashA || policyRef)</c> (TPM 2.0 Library Part
    /// 3, Section 23.3, equation 13) — raw TPM2B payload bytes only, no size prefixes; expiration as a 4-octet
    /// big-endian two's complement integer.
    /// </summary>
    /// <remarks>
    /// The flat concatenation is spec-mandated and inherently boundary-malleable across the variable-length
    /// fields (an empty cpHashA next to a long policyRef hashes identically to a digest-width cpHashA next to
    /// the remainder) — an accepted property of the format, not closed here; the fixed-width expiration is the
    /// only separator. H_authAlg is the hash carried inside the TPMT_SIGNATURE auth parameter, independent of
    /// the session's own policy hash algorithm, which is why this digest is computed here in the effect, through
    /// the registered async digest seam, rather than via the sync <c>TpmPolicyDigest</c> predictor (that
    /// predictor folds a completely different hash — the policyDigest — under the session's own policy hash
    /// algorithm).
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the digest buffer transfers to the caller, which releases it via a using declaration.")]
    private static async ValueTask<IMemoryOwner<byte>> ComputePolicySignedAHashAsync(
        ReadOnlyMemory<byte> nonceTpm, int expiration, ReadOnlyMemory<byte> cpHashA, ReadOnlyMemory<byte> policyRef,
        TpmiAlgHash schemeHashAlg, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        int messageSize = nonceTpm.Length + sizeof(int) + cpHashA.Length + policyRef.Length;
        using IMemoryOwner<byte> message = pool.Rent(messageSize);
        var writer = new TpmWriter(message.Memory.Span[..messageSize]);
        writer.WriteBytes(nonceTpm.Span);
        writer.WriteInt32(expiration);
        writer.WriteBytes(cpHashA.Span);
        writer.WriteBytes(policyRef.Span);

        int digestSize = SessionDigestSize(schemeHashAlg);
        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            message.Memory[..messageSize], digestSize, SessionDigestTag(schemeHashAlg), pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        IMemoryOwner<byte> owner = pool.Rent(digestSize);
        try
        {
            digest.AsReadOnlySpan().CopyTo(owner.Memory.Span[..digestSize]);

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// <c>TPM2_PolicyAuthorize()</c>'s checkTicket re-verification (TPM 2.0 Library Part 3, Section 23.16):
    /// recompute <c>aHash = H_hashAlg(approvedPolicy || policyRef)</c> under keySign's own nameAlg through the
    /// registered async digest seam, derive the hierarchy proof for the CALLER-SUPPLIED
    /// checkTicket.hierarchy (never independently re-derived from keySign — the caller's claim is exactly what
    /// is being checked), recompute the expected ticket via the existing
    /// <see cref="ComputeVerifiedTicketDigestAsync"/> formula (<c>HMAC(proof, TPM_ST_VERIFIED || aHash ||
    /// keySign)</c>), and constant-time compare it to the caller-supplied digest — architecturally the same
    /// stateless recompute-then-FixedTimeEquals shape as <see cref="VerifyCreationTicketAsync"/>, just against a
    /// caller-supplied hierarchy rather than the subject's own.
    /// </summary>
    /// <remarks>
    /// The policyDigest fold that a successful re-verification triggers runs HERE rather than in the resuming
    /// transition, because its destination must be rented at the session's own digest width. That makes this
    /// effect the terminal owner of every carrier the action carries — the approved policy, the qualifier, the
    /// approving key's Name, and the caller's ticket digest — on every path.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the folded policyDigest transfers to the returned TpmPolicyAuthorizeVerified, whose continuation installs it on the session record; the action's own carriers are released here in the finally.")]
    private static async ValueTask<TpmSimulatorInput> VerifyPolicyAuthorizeTicketAsync(
        TpmVerifyPolicyAuthorizeTicketAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        try
        {
            int aHashLength = SessionDigestSize(action.HashAlg);
            int messageSize = action.ApprovedPolicy.Size + action.PolicyRef.Size;
            using IMemoryOwner<byte> message = context.Pool.Rent(messageSize);
            var writer = new TpmWriter(message.Memory.Span[..messageSize]);
            writer.WriteBytes(action.ApprovedPolicy.AsReadOnlySpan());
            writer.WriteBytes(action.PolicyRef.AsReadOnlySpan());

            using DigestValue aHash = await CryptographicKeyEvents.ComputeDigestAsync(
                message.Memory[..messageSize], aHashLength, SessionDigestTag(action.HashAlg), context.Pool, cancellationToken: cancellationToken).ConfigureAwait(false);

            using IMemoryOwner<byte> proof = await DeriveHierarchyProofAsync(context, action.CheckTicketHierarchy.Value, cancellationToken).ConfigureAwait(false);

            using IMemoryOwner<byte> expectedTicket = await ComputeVerifiedTicketDigestAsync(
                proof.Memory[..CreationDigestSize], aHash.AsReadOnlyMemory(), action.KeySign.AsReadOnlyMemory(), context.Pool, cancellationToken).ConfigureAwait(false);

            bool matched = CryptographicOperations.FixedTimeEquals(
                expectedTicket.Memory.Span[..CreationDigestSize], action.CheckTicketDigest.AsReadOnlySpan());

            if(!matched)
            {
                return new TpmPolicyAuthorizeVerified(TpmRcConstants.TPM_RC_VALUE, action.PolicySession, Tpm2bDigest.Empty);
            }

            return new TpmPolicyAuthorizeVerified(
                TpmRcConstants.TPM_RC_SUCCESS,
                action.PolicySession,
                FoldPolicyDigest(
                    TpmPolicyDigestFold.Authorize, action.PolicyHashAlgorithm, current: default, restrictedCommand: default,
                    TpmHandleName.FromName(action.KeySign), action.PolicyRef.AsReadOnlySpan(), branches: null, pcrSelection: default,
                    pcrDigest: default, operandB: default, offset: 0, operation: 0, context.Pool));
        }
        finally
        {
            //The re-verification and the fold were these carriers' only uses, so this effect is their terminal
            //owner on the matched and unmatched paths alike.
            action.ApprovedPolicy.Dispose();
            action.PolicyRef.Dispose();
            action.KeySign.Dispose();
            action.CheckTicketDigest.Dispose();
        }
    }

    /// <summary>
    /// <c>TPM2_PolicySecret()</c>'s ticket mint (TPM 2.0 Library Part 3, Section 23.4): derive
    /// <c>action.Hierarchy</c>'s proof and compute the real <c>TPM_ST_AUTH_SECRET</c> ticket per equation 12
    /// (TPM 2.0 Library Part 2, Section 10.7.5, Table 111).
    /// </summary>
    /// <remarks>
    /// Unlike a verify action, this has no failure mode of its own — the transition only ever declares it once
    /// the authValue/nonceTPM/expiration/cpHashA checks have already passed and a ticket was actually requested
    /// — so it always proceeds to fold, and the policyDigest fold itself runs here too, since its destination
    /// must be rented at the session's own digest width. This effect is the policy qualifier's terminal owner;
    /// the cpHashA it reads is a borrow of the carrier the session already latched.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the folded policyDigest, the minted ticket-digest buffer, and the rented timeout carrier transfers to the returned TpmPolicySecretTicketMinted; the continuation installs the digest on the session and TpmSimulator releases the rest once framed, and a failure after any of them was rented releases it in the catch.")]
    private static async ValueTask<TpmSimulatorInput> MintPolicySecretTicketAsync(TpmMintPolicySecretTicketAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        try
        {
            using IMemoryOwner<byte> proof = await DeriveHierarchyProofAsync(context, action.Hierarchy.Value, cancellationToken).ConfigureAwait(false);

            //The authorizing entity's Name is its 4-octet handle value (Part 1, clause 14, Table 6); the octets are
            //materialized here, in the frame that holds a memory pool, and feed both the ticket HMAC and the fold.
            using IMemoryOwner<byte> authNameOctets = context.Pool.Rent(action.AuthName.Length);
            Memory<byte> authName = authNameOctets.Memory[..action.AuthName.Length];
            action.AuthName.CopyTo(authName.Span);

            IMemoryOwner<byte> ticketDigest = await ComputeAuthTicketDigestAsync(
                proof.Memory[..CreationDigestSize], (ushort)TpmStConstants.TPM_ST_AUTH_SECRET, action.CpHashA.AsReadOnlyMemory(), action.PolicyRef.AsReadOnlyMemory(), authName,
                action.Timeout, action.ExpiresOnReset, action.TimeEpoch, action.ResetCount, context.Pool, cancellationToken).ConfigureAwait(false);

            //The digest helper rents exactly the ticket octets, so the TPM2B_DIGEST carrier adopts that rental; the
            //deadline and its expires-on-reset flag become the one TPM2B_TIMEOUT the response frames. The adopted
            //ticket is released if the deadline's own rent then fails, so no failure orphans the pinned rental.
            var mintedTicket = new Tpm2bDigest(ticketDigest);
            Tpm2bTimeout timeout;
            try
            {
                timeout = Tpm2bTimeout.Create(action.Timeout, action.ExpiresOnReset, context.Pool);
            }
            catch
            {
                mintedTicket.Dispose();
                throw;
            }

            Tpm2bDigest foldedDigest;
            try
            {
                foldedDigest = FoldPolicyDigest(
                    TpmPolicyDigestFold.Secret, action.PolicyHashAlgorithm, action.CurrentPolicyDigest.AsReadOnlySpan(), restrictedCommand: default,
                    action.AuthName, action.PolicyRef.AsReadOnlySpan(), branches: null, pcrSelection: default,
                    pcrDigest: default, operandB: default, offset: 0, operation: 0, context.Pool);
            }
            catch
            {
                mintedTicket.Dispose();
                timeout.Dispose();
                throw;
            }

            return new TpmPolicySecretTicketMinted(
                action.PolicySession, foldedDigest, timeout, action.Hierarchy, mintedTicket, action.AuthorizingSession);
        }
        finally
        {
            //The ticket HMAC and the fold were the qualifier's only uses, so this effect is its terminal owner.
            action.PolicyRef.Dispose();
        }
    }

    /// <summary>
    /// Frames TPM2_PolicySecret()'s session-authorized response (TPM 2.0 Library Part 3, Section 23.4; Part 1, clause 16.6.1).
    /// </summary>
    /// <remarks>
    /// Frames TPM2B_TIMEOUT ‖ TPMT_TK_AUTH via the same helper the password arm's response uses, rolls a fresh
    /// nonceTPM for the authorizing session, computes rpHash over the framed parameter bytes, then the response
    /// HMAC keyed on the SAME sessionKey ‖ authValue the command-HMAC verification used (clause 17.6.5).
    /// <paramref name="action"/>'s <c>Timeout</c> and <c>TicketDigest</c> (when present) are consumed and
    /// disposed here, once their bytes are copied into the framed parameter area — their content does not need
    /// to outlive that copy.
    /// </remarks>
    /// <param name="action">The framing action, carrying the ticket digest, timeout, and the authorizing session's key material and nonces.</param>
    /// <param name="context">The action context supplying the memory pool and RNG.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A <see cref="TpmPolicySecretSessionResponseFramed"/> input carrying the framed parameter area and response HMAC.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parameter-area and HMAC buffers transfers to the returned TpmPolicySecretSessionResponseFramed, then to the TpmPolicySecretOverSessionResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> FramePolicySecretSessionResponseAsync(TpmFramePolicySecretSessionResponseAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        //This frame is the terminal owner of the caller nonce the request record transferred into the
        //authorizing-session entry and that entry carried across the fold and ticket-mint hops into this
        //action: the response HMAC reads it as its nonceOlder term here and nothing past this framing reads it
        //again (Part 1, clause 17.6.5).
        try
        {
            return await FramePolicySecretSessionResponseCoreAsync(action, context, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            action.NonceCaller.Dispose();
        }
    }

    /// <summary>
    /// Runs <see cref="FramePolicySecretSessionResponseAsync"/>'s framing, with that frame owning the release of
    /// the action's transferred caller nonce.
    /// </summary>
    /// <param name="action">The framing action; its caller nonce is read here and released by the caller.</param>
    /// <param name="context">The action context supplying the memory pool and RNG.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A <see cref="TpmPolicySecretSessionResponseFramed"/> input carrying the framed parameter area and response HMAC.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parameter-area and HMAC buffers transfers to the returned TpmPolicySecretSessionResponseFramed, then to the TpmPolicySecretOverSessionResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> FramePolicySecretSessionResponseCoreAsync(TpmFramePolicySecretSessionResponseAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        int parameterLength = action.TicketDigest is { } mintedTicket
            ? action.Timeout.SerializedSize + (sizeof(ushort) + sizeof(uint) + mintedTicket.SerializedSize)
            : sizeof(ushort) + (sizeof(ushort) + sizeof(uint) + sizeof(ushort));

        IMemoryOwner<byte> parameterArea = context.Pool.Rent(parameterLength);
        Tpm2bNonce framedNonceTpm = Tpm2bNonce.Empty;
        Tpm2bNonce retainedNonceTpm = Tpm2bNonce.Empty;
        try
        {
            using(action.Timeout)
            using(action.TicketDigest)
            {
                var writer = new TpmWriter(parameterArea.Memory.Span[..parameterLength]);
                WriteAuthTicketResponse(
                    ref writer, (ushort)TpmStConstants.TPM_ST_AUTH_SECRET, action.Timeout, action.Hierarchy.Value, action.TicketDigest);
            }

            int digestSize = SessionDigestSize(action.SessionAlg);
            (framedNonceTpm, retainedNonceTpm) = RollSessionNonce(action.SessionAlg, context);

            using IMemoryOwner<byte> rpHash = await ComputeSessionRpHashAsync(
                action.SessionAlg, TpmCcConstants.TPM_CC_PolicySecret, parameterArea.Memory[..parameterLength], context.Pool, cancellationToken).ConfigureAwait(false);

            ReadOnlyMemory<byte> sessionKeyBytes = action.SessionKey.AsReadOnlyMemory();
            ReadOnlyMemory<byte> authValueBytes = TpmLifecycleTransitions.StripTrailingZeros(action.AuthValue.AsReadOnlyMemory());
            int sessionValueLength = sessionKeyBytes.Length + authValueBytes.Length;
            using IMemoryOwner<byte> sessionValueOwner = context.Pool.Rent(Math.Max(sessionValueLength, 1), AllocationKind.Pinned);
            Memory<byte> sessionValue = sessionValueOwner.Memory[..sessionValueLength];
            sessionKeyBytes.CopyTo(sessionValue);
            authValueBytes.CopyTo(sessionValue[sessionKeyBytes.Length..]);

            Tpm2bAuth hmac = await ComputeResponseHmacAsync(
                action.SessionAlg, sessionValue, rpHash.Memory[..digestSize], framedNonceTpm.AsReadOnlyMemory(), action.NonceCaller.AsReadOnlyMemory(), action.SessionAttributes, context.Pool, cancellationToken).ConfigureAwait(false);

            sessionValueOwner.Memory.Span[..sessionValueLength].Clear();

            return new TpmPolicySecretSessionResponseFramed(
                action.SessionHandle, action.IsPolicySession, framedNonceTpm, retainedNonceTpm, action.SessionAttributes, TpmParameterArea.Adopt(parameterArea, parameterLength), hmac);
        }
        catch
        {
            //These carriers' only owner is this frame until the returned feedback record adopts them, so a
            //failure after any of them was rented must release them or the pinned rentals are orphaned.
            parameterArea.Dispose();
            retainedNonceTpm.Dispose();
            framedNonceTpm.Dispose();
            throw;
        }
    }

    /// <summary>
    /// <c>TPM2_PolicyTicket()</c>'s re-verification recompute (TPM 2.0 Library Part 3, clause 23.5.1, printed
    /// page 201; Part 4's <c>TPM2_PolicyTicket()</c>, printed page 654, calls <c>TicketComputeAuth</c> with the
    /// caller's own <c>ticket.hierarchy</c>): derive
    /// the hierarchy proof for the CALLER-SUPPLIED <c>action.TicketHierarchy</c> (never independently re-derived
    /// — the caller's claim is exactly what is being checked, mirroring
    /// <see cref="VerifyPolicyAuthorizeTicketAsync"/>), recompute the ticket via
    /// <see cref="ComputeAuthTicketDigestAsync"/> using the TPM's CURRENT TimeEpoch/ResetCount (not anything
    /// carried on the wire — a ticket minted under a since-regenerated epoch fails this comparison), and
    /// constant-time compare it to the caller-supplied digest.
    /// </summary>
    /// <remarks>
    /// On a match the policyDigest fold runs HERE, through the ORIGINAL command's own <c>PolicyUpdate</c>
    /// selected by the ticket's structure tag, because the fold's destination must be rented at the session's own
    /// digest width. This effect is therefore the terminal owner of the ticket digest, the qualifier, and the
    /// authorizing Name; the cpHashA carrier instead travels onward to the continuation that latches or releases
    /// it.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the folded policyDigest transfers to the returned TpmPolicyTicketVerified, whose continuation installs it on the session record; the cpHashA carrier transfers with it and is released here only when that transfer does not happen.")]
    private static async ValueTask<TpmSimulatorInput> VerifyPolicyTicketAsync(TpmVerifyPolicyTicketAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        try
        {
            using IMemoryOwner<byte> proof = await DeriveHierarchyProofAsync(context, action.TicketHierarchy.Value, cancellationToken).ConfigureAwait(false);

            using IMemoryOwner<byte> expectedTicket = await ComputeAuthTicketDigestAsync(
                proof.Memory[..CreationDigestSize], action.Tag, action.CpHashA.AsReadOnlyMemory(), action.PolicyRef.AsReadOnlyMemory(), action.AuthName.AsReadOnlyMemory(),
                action.Timeout, action.ExpiresOnReset, action.TimeEpoch, action.ResetCount, context.Pool, cancellationToken).ConfigureAwait(false);

            bool matched = CryptographicOperations.FixedTimeEquals(
                expectedTicket.Memory.Span[..CreationDigestSize], action.TicketDigest.AsReadOnlySpan());

            if(!matched)
            {
                return new TpmPolicyTicketVerified(
                    TpmRcConstants.TPM_RC_TICKET, action.PolicySession, Tpm2bDigest.Empty, action.CpHashA, action.Timeout);
            }

            //Part 3, Section 23.5.1's own PolicyUpdate(commandCode, authName, policyRef) dispatch: the fold is the
            //ORIGINAL command's, so a session that reaches a policyDigest by replaying a ticket ends up identical
            //to one that reached it through the PolicySigned()/PolicySecret() call that minted it.
            TpmPolicyDigestFold fold = action.Tag == (ushort)TpmStConstants.TPM_ST_AUTH_SIGNED
                ? TpmPolicyDigestFold.Signed
                : TpmPolicyDigestFold.Secret;

            return new TpmPolicyTicketVerified(
                TpmRcConstants.TPM_RC_SUCCESS,
                action.PolicySession,
                FoldPolicyDigest(
                    fold, action.PolicyHashAlgorithm, action.CurrentPolicyDigest.AsReadOnlySpan(), restrictedCommand: default,
                    TpmHandleName.FromName(action.AuthName), action.PolicyRef.AsReadOnlySpan(), branches: null, pcrSelection: default,
                    pcrDigest: default, operandB: default, offset: 0, operation: 0, context.Pool),
                action.CpHashA,
                action.Timeout);
        }
        catch
        {
            //The transfer into the feedback record never happened, so this frame is still the cpHashA carrier's
            //only owner.
            action.CpHashA.Dispose();
            throw;
        }
        finally
        {
            //The recompute and the fold were these carriers' only uses, so this effect is their terminal owner on
            //the matched and unmatched paths alike.
            action.TicketDigest.Dispose();
            action.PolicyRef.Dispose();
            action.AuthName.Dispose();
        }
    }

    /// <summary>
    /// Copies octets into a pooled buffer sized to hold them (at least one octet so an empty payload still rents
    /// a valid buffer). Ownership transfers to the caller; the caller disposes it after the octets are framed
    /// out.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented buffer transfers to the caller, which releases it after framing.")]
    private static IMemoryOwner<byte> CopyToPooled(ReadOnlySpan<byte> source, BaseMemoryPool pool, out int length)
    {
        length = source.Length;
        IMemoryOwner<byte> owner = pool.Rent(Math.Max(length, 1));
        try
        {
            source.CopyTo(owner.Memory.Span[..length]);

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Session-salt OAEP label (Part 1, Annex B.10.2): "SECRET" plus the trailing NUL octet the lhash digest
    /// input requires as part of L (OAEP's own convention, distinct from KDFa/KDFe's auto-appended label
    /// terminator) — the session-salt counterpart of <c>CredentialIdentityLabelOctets</c>, whose use-case string
    /// differs.
    /// </summary>
    private static ReadOnlyMemory<byte> SessionSaltOaepLabelOctets { get; } = "SECRET\0"u8.ToArray();

    /// <summary>
    /// <c>TPM2_StartAuthSession()</c> for a bound and/or salted HMAC session: draw a fresh nonceTPM from the
    /// injected RNG, then derive the session key via the shared <see cref="DeriveSessionKeyAsync"/> helper — the
    /// SAME derivation the host <c>TpmSession.CreateBoundAsync</c> performs, so the two keys agree by
    /// construction.
    /// </summary>
    /// <remarks>
    /// This is the unsalted arm (<c>action.Salt</c> is always empty here); the RSA/ECC salted arms recover a
    /// real salt first, then complete via the same <see cref="TpmHmacSessionStarted"/> shape.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the derived session-key carrier and the computed bound-entity value transfers through the returned TpmHmacSessionStarted to the durable session record OnHmacSessionStarted installs, which is their single owner; the analyzer cannot see the transfer through the record's positional construction.")]
    private static async ValueTask<TpmSimulatorInput> StartHmacSessionAsync(TpmStartHmacSessionAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        //This effect is the terminal owner of the caller nonce the request transferred into the action: the
        //session records only its own nonceTPM (HmacSessionState/PolicySessionState carry no nonceCaller) and
        //TPM2_StartAuthSession()'s response is framed with no sessions, so nothing downstream reads it again.
        try
        {
            (Tpm2bNonce framedNonceTpm, Tpm2bNonce retainedNonceTpm) = RollSessionNonce(action.SessionAlg, context);
            SymmetricKeyMemory sessionKey;
            SessionBoundEntity boundEntity;
            try
            {
                //The bind authValue rides the action as a wire-exact borrowed carrier; its trailing-zero-stripped
                //view is taken only here, at the KDFa and bound-entity fold primitives (Part 1, clause 17.6.4.3).
                ReadOnlyMemory<byte> bindAuthValue = TpmLifecycleTransitions.StripTrailingZeros(action.BindAuthValue.AsReadOnlyMemory());
                sessionKey = await DeriveSessionKeyAsync(
                    action.SessionAlg, bindAuthValue, action.BoundEntityName, action.Salt, framedNonceTpm.AsReadOnlyMemory(), action.NonceCaller.AsReadOnlyMemory(), context.Pool, cancellationToken).ConfigureAwait(false);

                //Dispose the half-built resource on the exception path: until the returned record carries every
                //carrier, the derived key's only owner is this local — a bound-entity computation failure (its input
                //guards are unreachable behind the definition-time authValue size gates, but the invariant must hold
                //regardless) must not orphan the pinned rental.
                try
                {
                    boundEntity = ComputeBoundEntity(action.BoundEntityName, bindAuthValue, action.PolicyContext, context.Pool);
                }
                catch
                {
                    sessionKey.Dispose();
                    throw;
                }
            }
            catch
            {
                //The two nonce carriers' only owner is this frame until the returned record adopts them.
                retainedNonceTpm.Dispose();
                framedNonceTpm.Dispose();
                throw;
            }

            return new TpmHmacSessionStarted(
                TpmRcConstants.TPM_RC_SUCCESS, action.SessionHandle, action.SessionAlg, action.Symmetric, framedNonceTpm, retainedNonceTpm, sessionKey,
                boundEntity, action.PolicyContext, action.IsBoundEntityDaProtected, action.IsBoundToLockout);
        }
        finally
        {
            action.NonceCaller.Dispose();
        }
    }

    /// <summary>
    /// <c>TPM2_StartAuthSession()</c> RSA salted arm: OAEP-decrypt encryptedSalt against tpmKey's retained
    /// private key (TPM 2.0 Library Part 1, Annex B.10.1/B.10.2). ANY internal failure — a null decode (bad
    /// padding, ciphertext &gt;= modulus) or a recovered value wider than the Name-algorithm digest-size cap —
    /// is reported immediately as <c>TPM_RC_VALUE</c>, never poisoned-and-deferred (Part 3, clause 11.1 has no
    /// later integrity check to defer to, unlike <c>TPM2_ActivateCredential()</c>'s RSA arm).
    /// </summary>
    /// <remarks>
    /// On success, derives the session key and completes exactly as the unsalted path.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the derived session-key carrier and the computed bound-entity value transfers through the returned TpmHmacSessionStarted to the durable session record OnHmacSessionStarted installs, which is their single owner; the analyzer cannot see the transfer through the record's positional construction.")]
    private static async ValueTask<TpmSimulatorInput> RecoverRsaSessionSaltAsync(TpmRecoverRsaSessionSaltAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        //This frame is the terminal owner of the two carriers the request transferred into the action — the
        //caller nonce and the OAEP ciphertext — on every exit, including the immediate TPM_RC_VALUE arms the
        //recovery answers with and a fault from the backend.
        try
        {
            return await RecoverRsaSessionSaltCoreAsync(action, context, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            action.Ciphertext.Dispose();
            action.NonceCaller.Dispose();
        }
    }

    /// <summary>
    /// Runs <see cref="RecoverRsaSessionSaltAsync"/>'s recovery and derivation, with that frame owning the
    /// release of the action's transferred carriers.
    /// </summary>
    /// <param name="action">The declared salt-recovery action; its carriers are read here and released by the caller.</param>
    /// <param name="context">The effect context supplying the RSA backend, the RNG, and the memory pool.</param>
    /// <param name="cancellationToken">The token to observe.</param>
    /// <returns>The session-start result to feed back to the transition.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the derived session-key carrier and the computed bound-entity value transfers through the returned TpmHmacSessionStarted to the durable session record OnHmacSessionStarted installs, which is their single owner; the analyzer cannot see the transfer through the record's positional construction.")]
    private static async ValueTask<TpmSimulatorInput> RecoverRsaSessionSaltCoreAsync(TpmRecoverRsaSessionSaltAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        TpmRsaSigningBackend backend = context.RsaSigningBackend
            ?? throw new InvalidOperationException("A salted TPM2_StartAuthSession() over an RSA tpmKey requires an RSA signing backend, but none was supplied.");
        BaseMemoryPool pool = context.Pool;

        int saltCap = SessionDigestSize(action.NameAlg);
        IMemoryOwner<byte>? decoded;
        try
        {
            decoded = await backend.DecryptOaep(
                action.PrivateKey.AsReadOnlyMemory(), action.Ciphertext.AsReadOnlyMemory(), SessionSaltOaepLabelOctets, action.NameAlg.Value, action.NameAlg.Value, pool, cancellationToken).ConfigureAwait(false);
        }
        catch(Exception ex) when(ex is not OperationCanceledException)
        {
            //action.Ciphertext is an attacker-influenceable wire buffer (TPM2B_ENCRYPTED_SECRET, no length
            //validation against the RSA modulus width precedes this call). TpmRsaOaepDecryptDelegate's own
            //contract signals a decode failure by returning null, but the call site must not trust an arbitrary
            //backend to honor that never-throws contract: any throw here (a wrong-length ciphertext, a
            //malformed key encoding, or any other internal failure) collapses to the same immediate
            //TPM_RC_VALUE every other internal recovery failure does (Part 3, clause 11.1), never an unhandled
            //exception escaping as a denial of service.
            return FailedSessionStart(
                action.SessionHandle.Value, action.SessionAlg, action.Symmetric, action.PolicyContext,
                action.IsBoundEntityDaProtected, action.IsBoundToLockout);
        }

        if(decoded is null || decoded.Memory.Length > saltCap)
        {
            decoded?.Dispose();

            return FailedSessionStart(
                action.SessionHandle.Value, action.SessionAlg, action.Symmetric, action.PolicyContext,
                action.IsBoundEntityDaProtected, action.IsBoundToLockout);
        }

        using(decoded)
        {
            (Tpm2bNonce framedNonceTpm, Tpm2bNonce retainedNonceTpm) = RollSessionNonce(action.SessionAlg, context);
            SymmetricKeyMemory sessionKey;
            SessionBoundEntity boundEntity;
            try
            {
                //The bind authValue rides the action as a wire-exact borrowed carrier; its trailing-zero-stripped
                //view is taken only here, at the KDFa and bound-entity fold primitives (Part 1, clause 17.6.4.3).
                ReadOnlyMemory<byte> bindAuthValue = TpmLifecycleTransitions.StripTrailingZeros(action.BindAuthValue.AsReadOnlyMemory());
                sessionKey = await DeriveSessionKeyAsync(
                    action.SessionAlg, bindAuthValue, action.BoundEntityName, decoded.Memory, framedNonceTpm.AsReadOnlyMemory(), action.NonceCaller.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);

                //Dispose the half-built resource on the exception path, exactly as the unsalted arm does.
                try
                {
                    boundEntity = ComputeBoundEntity(action.BoundEntityName, bindAuthValue, action.PolicyContext, pool);
                }
                catch
                {
                    sessionKey.Dispose();
                    throw;
                }
            }
            catch
            {
                //The two nonce carriers' only owner is this frame until the returned record adopts them.
                retainedNonceTpm.Dispose();
                framedNonceTpm.Dispose();
                throw;
            }

            return new TpmHmacSessionStarted(
                TpmRcConstants.TPM_RC_SUCCESS, action.SessionHandle, action.SessionAlg, action.Symmetric, framedNonceTpm, retainedNonceTpm, sessionKey,
                boundEntity, action.PolicyContext, action.IsBoundEntityDaProtected, action.IsBoundToLockout);
        }
    }

    /// <summary>
    /// <c>TPM2_StartAuthSession()</c> ECC salted arm: recover the session salt via a one-pass ECDH exchange
    /// against tpmKey's private scalar and the wire ephemeral public point, then KDFe keyed on tpmKey's OWN Name
    /// algorithm (TPM 2.0 Library Part 1, Annex C.6.1/C.6.2) — never the session's authHash, which may differ (a
    /// mixed-hash session would otherwise leak the wrong hash into this derivation).
    /// </summary>
    /// <remarks>
    /// A malformed marshaled <c>TPMS_ECC_POINT</c>, or one that is off-curve or the point at infinity, is
    /// <c>TPM_RC_VALUE</c>, reported immediately.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "ephemeralPoint/ephemeralX/tpmKeyX are plain byte[] copied out of spans that must not cross an await; sharedValue/salt are IMemoryOwner<byte>, both disposed via using; the derived session-key carrier and computed bound-entity value transfer ownership through the returned TpmHmacSessionStarted to the durable session record, their single owner.")]
    private static async ValueTask<TpmSimulatorInput> RecoverEccSessionSaltAsync(TpmRecoverEccSessionSaltAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        //This frame is the terminal owner of the two carriers the request transferred into the action — the
        //caller nonce and the marshaled ephemeral point — on every exit, including the immediate TPM_RC_VALUE
        //arms a malformed or off-curve point answers with and a fault from the backend.
        try
        {
            return await RecoverEccSessionSaltCoreAsync(action, context, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            action.EncryptedSalt.Dispose();
            action.NonceCaller.Dispose();
        }
    }

    /// <summary>
    /// Runs <see cref="RecoverEccSessionSaltAsync"/>'s exchange and derivation, with that frame owning the
    /// release of the action's transferred carriers.
    /// </summary>
    /// <param name="action">The declared salt-recovery action; its carriers are read here and released by the caller.</param>
    /// <param name="context">The effect context supplying the ECC backend, the RNG, and the memory pool.</param>
    /// <param name="cancellationToken">The token to observe.</param>
    /// <returns>The session-start result to feed back to the transition.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "ephemeralPoint/ephemeralX/tpmKeyX are plain byte[] copied out of spans that must not cross an await; sharedValue/salt are IMemoryOwner<byte>, both disposed via using; the derived session-key carrier and computed bound-entity value transfer ownership through the returned TpmHmacSessionStarted to the durable session record, their single owner.")]
    private static async ValueTask<TpmSimulatorInput> RecoverEccSessionSaltCoreAsync(TpmRecoverEccSessionSaltAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        TpmEccSigningBackend backend = context.SigningBackend
            ?? throw new InvalidOperationException("A salted TPM2_StartAuthSession() over an ECC tpmKey requires a signing backend, but none was supplied.");
        BaseMemoryPool pool = context.Pool;

        byte[] ephemeralPoint;
        byte[] ephemeralX;
        try
        {
            var reader = new TpmReader(action.EncryptedSalt.Span);
            ushort xLen = reader.ReadUInt16();
            ReadOnlySpan<byte> x = reader.ReadBytes(xLen);
            ushort yLen = reader.ReadUInt16();
            ReadOnlySpan<byte> y = reader.ReadBytes(yLen);

            //Both coordinates must equal the curve's field width (32 octets for P-256) BEFORE the on-curve check
            //ever runs. CheckPointOnCurve parses each coordinate as an unsigned BigInteger, so a coordinate with a
            //stripped or added leading zero octet (a 31- or 33-byte encoding of the same numeric value) still
            //reads as a genuine on-curve point there, then reaches CombineToUncompressedPoint below with
            //mismatched x/y lengths, which throws the base ArgumentException (EllipticCurveUtilities.cs) — never
            //TPM_RC_VALUE. Gating on the field width here means a length mismatch is rejected on its own terms,
            //rather than relying on catching that throw (Part 3, clause 11.1).
            if(reader.Remaining != 0
                || x.Length != EllipticCurveConstants.P256.PointArrayLength
                || y.Length != EllipticCurveConstants.P256.PointArrayLength
                || !EllipticCurveUtilities.CheckPointOnCurve(x, y, EllipticCurveTypes.P256))
            {
                return FailedSessionStart(
                    action.SessionHandle.Value, action.SessionAlg, action.Symmetric, action.PolicyContext,
                    action.IsBoundEntityDaProtected, action.IsBoundToLockout);
            }

            ephemeralPoint = EllipticCurveUtilities.CombineToUncompressedPoint(x, y);
            ephemeralX = x.ToArray();
        }
        catch(ArgumentException)
        {
            //encryptedSalt is an attacker-influenceable wire buffer; a structurally malformed marshaled
            //TPMS_ECC_POINT (an under-length coordinate from TpmReader, throwing ArgumentOutOfRangeException — a
            //subclass of ArgumentException — or any other internal validation failure) collapses to the same
            //TPM_RC_VALUE every other internal recovery failure does (Part 3, clause 11.1) — StartAuthSession's
            //salt recovery has no later integrity check to defer a distinct code to.
            return FailedSessionStart(
                action.SessionHandle.Value, action.SessionAlg, action.Symmetric, action.PolicyContext,
                action.IsBoundEntityDaProtected, action.IsBoundToLockout);
        }

        byte[] tpmKeyX = EllipticCurveUtilities.SliceXCoordinate(action.PublicPoint.Span).ToArray();
        int fieldWidth = ephemeralX.Length;
        int saltSize = SessionDigestSize(action.NameAlg);

        using IMemoryOwner<byte> sharedValue = await backend.ComputeSharedSecret(
            action.PrivateScalar.AsReadOnlyMemory(), ephemeralPoint, action.Curve.Value, pool, cancellationToken).ConfigureAwait(false);
        using IMemoryOwner<byte> salt = await Kdfe.DeriveAsync(
            SessionHashName(action.NameAlg), sharedValue.Memory[..fieldWidth], "SECRET", ephemeralX, tpmKeyX, saltSize * 8, pool, cancellationToken).ConfigureAwait(false);

        (Tpm2bNonce framedNonceTpm, Tpm2bNonce retainedNonceTpm) = RollSessionNonce(action.SessionAlg, context);
        SymmetricKeyMemory sessionKey;
        SessionBoundEntity boundEntity;
        try
        {
            //The bind authValue rides the action as a wire-exact borrowed carrier; its trailing-zero-stripped
            //view is taken only here, at the KDFa and bound-entity fold primitives (Part 1, clause 17.6.4.3).
            ReadOnlyMemory<byte> bindAuthValue = TpmLifecycleTransitions.StripTrailingZeros(action.BindAuthValue.AsReadOnlyMemory());
            sessionKey = await DeriveSessionKeyAsync(
                action.SessionAlg, bindAuthValue, action.BoundEntityName, salt.Memory[..saltSize], framedNonceTpm.AsReadOnlyMemory(), action.NonceCaller.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);
            salt.Memory.Span[..saltSize].Clear();

            //Dispose the half-built resource on the exception path, exactly as the unsalted arm does.
            try
            {
                boundEntity = ComputeBoundEntity(action.BoundEntityName, bindAuthValue, action.PolicyContext, pool);
            }
            catch
            {
                sessionKey.Dispose();
                throw;
            }
        }
        catch
        {
            //The two nonce carriers' only owner is this frame until the returned record adopts them.
            retainedNonceTpm.Dispose();
            framedNonceTpm.Dispose();
            throw;
        }

        return new TpmHmacSessionStarted(
            TpmRcConstants.TPM_RC_SUCCESS, action.SessionHandle, action.SessionAlg, action.Symmetric, framedNonceTpm, retainedNonceTpm, sessionKey,
            boundEntity, action.PolicyContext, action.IsBoundEntityDaProtected, action.IsBoundToLockout);
    }

    /// <summary>
    /// Builds a salted arm's secret-recovery failure result (Part 3, clause 11.1).
    /// </summary>
    /// <remarks>
    /// Every field but the session handle/algorithm/symmetric/policyContext is a meaningless empty placeholder,
    /// since <c>OnHmacSessionStarted</c> rejects with <c>TPM_RC_VALUE</c> before ever reading them.
    /// </remarks>
    /// <param name="sessionHandle">The session handle that was allocated before recovery failed.</param>
    /// <param name="sessionAlg">The session's negotiated hash algorithm.</param>
    /// <param name="symmetric">The session's negotiated symmetric definition.</param>
    /// <param name="policyContext">The POLICY/TRIAL session context, when this is a policy or trial session start; <see langword="null"/> for an HMAC session.</param>
    /// <param name="isBoundEntityDaProtected">The bind entity's dictionary-attack protection state, carried for shape parity with the success path; no session is recorded on this path, so it never reaches a session context.</param>
    /// <param name="isBoundToLockout">Whether the bind entity was <c>TPM_RH_LOCKOUT</c>, carried for the same shape parity.</param>
    /// <returns>A <see cref="TpmHmacSessionStarted"/> input carrying <c>TPM_RC_VALUE</c> and empty key material.</returns>
    private static TpmHmacSessionStarted FailedSessionStart(
        uint sessionHandle, TpmiAlgHash sessionAlg, TpmtSymDef symmetric, TpmPolicySessionKeyContext? policyContext,
        bool isBoundEntityDaProtected, bool isBoundToLockout) =>
        new(TpmRcConstants.TPM_RC_VALUE, TpmiShAuthSession.FromValue(sessionHandle), sessionAlg, symmetric, Tpm2bNonce.Empty, Tpm2bNonce.Empty, TpmSimulatorState.EmptySessionKey,
            SessionBoundEntity.Unbound, policyContext, isBoundEntityDaProtected, isBoundToLockout);

    /// <summary>
    /// Computes the bound-entity value a started session records (TPM 2.0 Library Part 4,
    /// <c>SessionComputeBoundEntity()</c>; Part 1, clause 17.6.10): the fold of the bind entity's Name
    /// and its stripped bind-time authValue, for an HMAC session with a real bind entity —
    /// <see cref="SessionBoundEntity.Unbound"/> for an unbound start and for every POLICY/TRIAL
    /// session, which never applies the bind-omission optimization (Part 3, clause 11.1.1's own "the
    /// session is not bound", mirrored by the reference's <c>sessionType == TPM_SE_HMAC</c> guard on
    /// <c>isBound</c>).
    /// </summary>
    /// <param name="boundEntityName">The bind entity's Name term in the model's recorded bind form — a borrow of the entity's own Name carrier, or a permanent entity's handle value materialized here — absent for an unbound start.</param>
    /// <param name="bindAuthValue">The bind entity's stripped authValue as resolved at start.</param>
    /// <param name="policyContext">The POLICY/TRIAL context, or <see langword="null"/> for an HMAC session.</param>
    /// <param name="pool">The memory pool the folded value's storage is rented from.</param>
    /// <returns>The bound-entity value the session record takes ownership of.</returns>
    private static SessionBoundEntity ComputeBoundEntity(
        TpmHandleName boundEntityName, ReadOnlyMemory<byte> bindAuthValue, TpmPolicySessionKeyContext? policyContext, BaseMemoryPool pool)
    {
        if(policyContext is not null || !boundEntityName.IsPresent)
        {
            return SessionBoundEntity.Unbound;
        }

        //A permanent entity's (and, in this model, an NV Index's) Name IS its 4-octet big-endian handle value
        //(Part 1, clause 14, Table 6), so the octets are materialized here rather than carried out of the pure transition
        //that resolved the bind.
        Span<byte> handleFormName = stackalloc byte[sizeof(uint)];

        return SessionBoundEntity.Compute(boundEntityName.Read(handleFormName), bindAuthValue.Span, pool);
    }

    /// <summary>
    /// Derives a session key: <c>KDFa(sessionAlg, bindAuthValue || salt, "ATH", nonceTPM, nonceCaller, bits)</c>
    /// (TPM 2.0 Library Part 1, clause 17.6.10 equations 20/23/25).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The general formula every StartAuthSession HMAC arm (unsalted, RSA-salted, ECC-salted) resolves to;
    /// <paramref name="bindAuthValue"/> is first, <paramref name="salt"/> second (never reversed), each Empty when
    /// absent. The two are concatenated into a single pooled buffer only when both are non-empty (avoiding an
    /// allocation for the common bound-unsalted and salted-unbound cases); the pooled carrier is cleared and
    /// disposed immediately after the KDFa call.
    /// </para>
    /// <para>
    /// A session that is neither bound nor salted never runs KDFa at all: Part 1, clause 17.6.9 gives it
    /// sessionKey = an Empty Buffer, not a digest-width value derived from a zero-length key. Whether a bind
    /// entity is present is NOT the same question as whether its resolved authValue happens to be empty — a
    /// session bound to a real entity whose own authValue is empty (or salted with a zero-length recovered
    /// secret) still runs KDFa over that empty key (RFC 2104's well-defined empty-key HMAC), keyed on the bind
    /// HANDLE rather than the size of the resolved authValue. <paramref name="boundEntityName"/> carries that
    /// signal: <c>TryResolveBindEntity</c> leaves it absent in exactly the <c>TPM_RH_NULL</c> (unbound) case and
    /// present for every other bind entity, regardless of that entity's own authValue.
    /// </para>
    /// </remarks>
    /// <param name="sessionAlg">The session's negotiated hash algorithm.</param>
    /// <param name="bindAuthValue">The bind entity's resolved authValue, or Empty when unbound.</param>
    /// <param name="boundEntityName">The bind entity's Name term, absent in exactly the unbound (<c>TPM_RH_NULL</c>) case; read only for that presence signal.</param>
    /// <param name="salt">The recovered or supplied salt, or Empty when unsalted.</param>
    /// <param name="nonceTpm">The session's rolled nonceTPM.</param>
    /// <param name="nonceCaller">The caller-supplied nonceCaller.</param>
    /// <param name="pool">The memory pool for the concatenation buffer and the returned key's pinned storage.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The derived session key in a pooled sensitive carrier the session record takes ownership of, or the shared <see cref="TpmSimulatorState.EmptySessionKey"/> for a session that is neither bound nor salted.</returns>
    private static async ValueTask<SymmetricKeyMemory> DeriveSessionKeyAsync(
        TpmiAlgHash sessionAlg,
        ReadOnlyMemory<byte> bindAuthValue,
        TpmHandleName boundEntityName,
        ReadOnlyMemory<byte> salt,
        ReadOnlyMemory<byte> nonceTpm,
        ReadOnlyMemory<byte> nonceCaller,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        if(!boundEntityName.IsPresent && salt.IsEmpty)
        {
            return TpmSimulatorState.EmptySessionKey;
        }

        int digestSize = SessionDigestSize(sessionAlg);
        int keyLength = bindAuthValue.Length + salt.Length;

        IMemoryOwner<byte>? keyOwner = null;
        ReadOnlyMemory<byte> key;
        if(keyLength == 0)
        {
            key = ReadOnlyMemory<byte>.Empty;
        }
        else if(salt.IsEmpty)
        {
            key = bindAuthValue;
        }
        else if(bindAuthValue.IsEmpty)
        {
            key = salt;
        }
        else
        {
            keyOwner = pool.Rent(keyLength, AllocationKind.Pinned);
            bindAuthValue.CopyTo(keyOwner.Memory);
            salt.CopyTo(keyOwner.Memory[bindAuthValue.Length..]);
            key = keyOwner.Memory[..keyLength];
        }

        try
        {
            using IMemoryOwner<byte> derived = await Kdfa.DeriveAsync(
                SessionHashName(sessionAlg), key, "ATH", nonceTpm, nonceCaller, digestSize * 8, pool, cancellationToken).ConfigureAwait(false);

            IMemoryOwner<byte> keyStorage = pool.Rent(digestSize, AllocationKind.Pinned);
            derived.Memory.Span[..digestSize].CopyTo(keyStorage.Memory.Span);
            derived.Memory.Span[..digestSize].Clear();

            return new SymmetricKeyMemory(keyStorage, TpmTags.SessionKey);
        }
        finally
        {
            if(keyOwner is not null)
            {
                keyOwner.Memory.Span[..keyLength].Clear();
                keyOwner.Dispose();
            }
        }
    }

    /// <summary>
    /// An encrypt-attributed <c>TPM2_GetRandom()</c> response over a bound HMAC session (TPM 2.0 Library Part 3,
    /// clause 16.1; Part 1, clauses 16.7 and 19).
    /// </summary>
    /// <remarks>
    /// The order is the crux and mirrors the host's response-processing contract: draw the random octets and a
    /// fresh nonceTPM, ENCRYPT the first response parameter, compute rpHash over the ENCRYPTED parameter area,
    /// then compute the response HMAC — so the host, which computes rpHash over the response parameters as
    /// received (still encrypted) before decrypting them, verifies and decrypts by construction.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parameter-area and HMAC buffers transfers to the returned TpmEncryptedRandomProduced, then to the TpmEncryptedRandomResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> EncryptRandomOverSessionAsync(TpmEncryptRandomAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        //This frame is the terminal owner of the caller nonce the continuation transferred into the action: it
        //is read here as the keystream's and the response HMAC's nonceOlder, and nothing past this framing
        //reads it again.
        try
        {
            return await EncryptRandomOverSessionCoreAsync(action, context, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            action.NonceCaller.Dispose();
        }
    }

    /// <summary>
    /// Runs <see cref="EncryptRandomOverSessionAsync"/>'s draw, encryption, and response framing, with that
    /// frame owning the release of the action's transferred caller nonce.
    /// </summary>
    /// <param name="action">The declared encryption action; its carriers are read here and released by the caller.</param>
    /// <param name="context">The effect context supplying the RNG, the digest and HMAC seams, and the memory pool.</param>
    /// <param name="cancellationToken">The token to observe.</param>
    /// <returns>The framed response pieces to feed back to the transition.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parameter-area and HMAC buffers transfers to the returned TpmEncryptedRandomProduced, then to the TpmEncryptedRandomResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> EncryptRandomOverSessionCoreAsync(TpmEncryptRandomAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        int digestSize = SessionDigestSize(action.SessionAlg);
        int byteCount = action.ByteCount;

        //nonceTPM rolled to a fresh value for this response (Part 1, clause 17.6.5): the response nonceNewer.
        (Tpm2bNonce framedNonceTpm, Tpm2bNonce retainedNonceTpm) = RollSessionNonce(action.SessionAlg, context);

        //The first (only) response parameter is randomBytes as a TPM2B_DIGEST: a UINT16 size prefix (the count,
        //left unprotected) followed by the octets, whose data portion is encrypted in place (Part 1, clause 19.1).
        int parameterLength = sizeof(ushort) + byteCount;
        IMemoryOwner<byte> parameterArea;
        try
        {
            parameterArea = context.Pool.Rent(Math.Max(parameterLength, 1));
        }
        catch
        {
            retainedNonceTpm.Dispose();
            framedNonceTpm.Dispose();
            throw;
        }

        try
        {
            //Fill the size field and draw the random octets synchronously (the span never crosses an await).
            {
                Span<byte> paramSpan = parameterArea.Memory.Span[..parameterLength];
                BinaryPrimitives.WriteUInt16BigEndian(paramSpan, (ushort)byteCount);
                context.Rng(paramSpan.Slice(sizeof(ushort), byteCount));
            }

            //Encrypt the data portion (after the 2-octet size). Response direction (Part 1, clause 19.2): nonceNewer
            //= newNonceTPM, nonceOlder = nonceCaller; the key is sessionValue = sessionKey, since TPM2_GetRandom()
            //takes no handle and so its session authorizes no entity whose authValue could fold in (clause 19.1).
            await ApplyResponseEncryptionAsync(
                action.Symmetric, action.SessionAlg, action.SessionKey, Tpm2bAuth.Empty, framedNonceTpm.AsReadOnlyMemory(), action.NonceCaller.AsReadOnlyMemory(),
                parameterArea.Memory.Slice(sizeof(ushort), byteCount), context.Pool, cancellationToken).ConfigureAwait(false);

            //rpHash over the ENCRYPTED parameter area, then the response HMAC over rpHash || nonceTPM || nonceCaller
            //|| sessionAttributes. Both key on the same sessionValue and the same seams the host verifies with.
            using IMemoryOwner<byte> rpHash = await ComputeSessionRpHashAsync(
                action.SessionAlg, TpmCcConstants.TPM_CC_GetRandom, parameterArea.Memory[..parameterLength], context.Pool, cancellationToken).ConfigureAwait(false);

            Tpm2bAuth hmac = await ComputeResponseHmacAsync(
                action.SessionAlg, action.SessionKey.AsReadOnlyMemory(), rpHash.Memory[..digestSize], framedNonceTpm.AsReadOnlyMemory(), action.NonceCaller.AsReadOnlyMemory(), action.SessionAttributes, context.Pool, cancellationToken).ConfigureAwait(false);

            return new TpmEncryptedRandomProduced(action.SessionHandle, framedNonceTpm, retainedNonceTpm, action.SessionAttributes, TpmParameterArea.Adopt(parameterArea, parameterLength), hmac);
        }
        catch
        {
            parameterArea.Memory.Span[..parameterLength].Clear();
            parameterArea.Dispose();
            retainedNonceTpm.Dispose();
            framedNonceTpm.Dispose();
            throw;
        }
    }

    /// <summary>
    /// The <c>TPM2_Unseal()</c> response over 0, 1, or 2 real (HMAC-table) sessions, plus an optional leading
    /// policy-session placeholder entry (TPM 2.0 Library Part 3, clause 12.7; Part 1, clauses 16.7 and 19).
    /// </summary>
    /// <remarks>
    /// The recovered secret is framed as a TPM2B_SENSITIVE_DATA (outData); its data portion is encrypted, in the
    /// same order the encrypt-attributed <c>TPM2_GetRandom()</c> path establishes, over whichever real session
    /// (if any) carries the encrypt attribute: roll a fresh nonceTPM per real session, ENCRYPT outData, compute
    /// rpHash over the ENCRYPTED parameter area ONCE PER DISTINCT session hash algorithm (Part 1, clause 16.8,
    /// equation 16; two real sessions may negotiate different algorithms), then each real session's own response HMAC, keyed on its
    /// own sessionKey ‖ authValue — THE SAME key its command-HMAC verification used (Part 1, clause 17.6.8). A
    /// policy-session placeholder entry carries no HMAC (it has no key); only its nonce width and echoed
    /// attributes travel back for framing.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parameter-area and each entry's HMAC buffer transfers to the returned TpmUnsealedOverSessions, then to the TpmUnsealOverSessionsResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> UnsealOverSessionsAsync(TpmUnsealDataAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        //This frame is the terminal owner of the caller-nonce carrier every response-session entry owns — the
        //TPM2B_NONCE its slot's request record transferred into it — discharging the obligation once the
        //keystream and the response HMACs have read the nonces as their nonceOlder term (Part 1, clause 19.2),
        //on the success and framing-failure paths alike.
        try
        {
            return await UnsealOverSessionsCoreAsync(action, context, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            foreach(TpmUnsealResponseSession responseSession in action.HmacResponseSessions)
            {
                responseSession.NonceCaller.Dispose();
            }
        }
    }

    /// <summary>
    /// Runs <see cref="UnsealOverSessionsAsync"/>'s response framing, with that frame owning the release of the
    /// response-session entries' transferred caller nonces.
    /// </summary>
    /// <param name="action">The declared framing action; its response-session nonces are read here and released by the caller.</param>
    /// <param name="context">The effect context supplying the RNG, the digest and HMAC seams, and the memory pool.</param>
    /// <param name="cancellationToken">The token to observe.</param>
    /// <returns>The framed response pieces to feed back to the transition.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parameter-area and each entry's HMAC buffer transfers to the returned TpmUnsealedOverSessions, then to the TpmUnsealOverSessionsResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> UnsealOverSessionsCoreAsync(TpmUnsealDataAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        int secretLength = action.SecretData.Length;
        int parameterLength = sizeof(ushort) + secretLength;
        IMemoryOwner<byte> parameterArea = context.Pool.Rent(Math.Max(parameterLength, 1));
        try
        {
            //Lay out the sized outData synchronously (the span never crosses an await); the view of the
            //borrowed sealed-data carrier is taken only here, at the framing primitive.
            {
                Span<byte> paramSpan = parameterArea.Memory.Span[..parameterLength];
                BinaryPrimitives.WriteUInt16BigEndian(paramSpan, (ushort)secretLength);
                action.SecretData.AsReadOnlySpan().CopyTo(paramSpan[sizeof(ushort)..]);
            }

            //rpHash is computed once per DISTINCT hash algorithm among action.HmacResponseSessions (Part 1,
            //clause 16.8, equation 16): each real session verifies its response HMAC against its OWN algorithm's
            //rpHash, never one session's hash (nor the policy placeholder's, which carries no HMAC of its own)
            //shared by every real session — the host-side mirror lives in TpmCommandExecutor.ExecuteAsync. The
            //policy placeholder's own algorithm is unrelated to rpHash; it is used only to frame its nonce width,
            //below.
            var sessionAlgs = new TpmiAlgHash[action.HmacResponseSessions.Length];
            for(int i = 0; i < action.HmacResponseSessions.Length; i++)
            {
                sessionAlgs[i] = action.HmacResponseSessions[i].SessionAlg;
            }

            //Roll a fresh nonceTPM for every real session up front (each is an independent RNG draw, Part 1,
            //clause 17.6.5).
            (Tpm2bNonce[] framedNonces, Tpm2bNonce[] retainedNonces) = RollSessionNonces(sessionAlgs, context);
            try
            {
                //Encrypt the data portion (after the 2-octet size) over whichever session (if any) carries the
                //encrypt attribute (Part 1 permits at most one), using its freshly rolled nonceTPM as nonceNewer
                //and its command caller nonce as nonceOlder (clause 19.2).
                for(int i = 0; i < action.HmacResponseSessions.Length; i++)
                {
                    TpmUnsealResponseSession encryptCandidate = action.HmacResponseSessions[i];
                    if(encryptCandidate.Encrypts)
                    {
                        //sessionValue = sessionKey ‖ StripTrailingZeros(authValue) when the encrypting session also
                        //authorizes an entity, sessionKey alone when it is a companion (clause 19.1). The entry
                        //carries that entity term already resolved — the item's LIVE userAuth for the authorizing
                        //slot, the empty carrier for a companion — so this call needs no knowledge of which slot it
                        //is transforming for.
                        await ApplyResponseEncryptionAsync(
                            encryptCandidate.Symmetric, encryptCandidate.SessionAlg, encryptCandidate.SessionKey, encryptCandidate.EntityAuthValue, framedNonces[i].AsReadOnlyMemory(), encryptCandidate.NonceCaller.AsReadOnlyMemory(),
                            parameterArea.Memory.Slice(sizeof(ushort), secretLength), context.Pool, cancellationToken).ConfigureAwait(false);

                        break;
                    }
                }

                (Memory<byte>[] rpHashPerSession, List<(TpmiAlgHash Alg, IMemoryOwner<byte> Owner)> rpHashOwners) = await ComputeRpHashPerSessionAsync(
                    sessionAlgs, TpmCcConstants.TPM_CC_Unseal, parameterArea.Memory[..parameterLength], context.Pool, cancellationToken).ConfigureAwait(false);
                try
                {
                    var entries = ImmutableArray.CreateBuilder<TpmUnsealFramedSessionEntry>(action.HmacResponseSessions.Length);
                    for(int i = 0; i < action.HmacResponseSessions.Length; i++)
                    {
                        TpmUnsealResponseSession session = action.HmacResponseSessions[i];

                        ReadOnlyMemory<byte> sessionKeyBytes = session.SessionKey.AsReadOnlyMemory();
                        ReadOnlyMemory<byte> authValueBytes = TpmLifecycleTransitions.StripTrailingZeros(session.AuthValue.AsReadOnlyMemory());
                        int sessionValueLength = sessionKeyBytes.Length + authValueBytes.Length;
                        using IMemoryOwner<byte> sessionValueOwner = context.Pool.Rent(Math.Max(sessionValueLength, 1), AllocationKind.Pinned);
                        Memory<byte> sessionValue = sessionValueOwner.Memory[..sessionValueLength];
                        sessionKeyBytes.CopyTo(sessionValue);
                        authValueBytes.CopyTo(sessionValue[sessionKeyBytes.Length..]);

                        Tpm2bAuth hmac = await ComputeResponseHmacAsync(
                            session.SessionAlg, sessionValue, rpHashPerSession[i], framedNonces[i].AsReadOnlyMemory(), session.NonceCaller.AsReadOnlyMemory(), session.SessionAttributes, context.Pool, cancellationToken).ConfigureAwait(false);

                        sessionValueOwner.Memory.Span[..sessionValueLength].Clear();

                        entries.Add(new TpmUnsealFramedSessionEntry(session.SessionHandle, framedNonces[i], retainedNonces[i], session.SessionAttributes, hmac));
                    }

                    return new TpmUnsealedOverSessions(
                        TpmParameterArea.Adopt(parameterArea, parameterLength), action.HasPolicyPlaceholder,
                        action.HasPolicyPlaceholder ? SessionDigestSize(action.PolicyPlaceholderAlg) : 0,
                        action.PolicyPlaceholderAttributes, entries.MoveToImmutable());
                }
                finally
                {
                    foreach(var cached in rpHashOwners)
                    {
                        cached.Owner.Dispose();
                    }
                }
            }
            catch
            {
                //The rolled pairs' only owner is this frame until the framed entries adopt them.
                ReleaseSessionNonces(framedNonces, retainedNonces);
                throw;
            }
        }
        catch
        {
            parameterArea.Memory.Span[..parameterLength].Clear();
            parameterArea.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Applies the session's parameter-encryption scheme to the COMMAND first-parameter data in place, recovering
    /// its plaintext: XOR obfuscation (mandatory, self-inverse) or AES-CFB (platform specific), keyed by the
    /// session's <c>sessionValue</c> with the command-direction nonce ordering — nonceNewer is nonceCaller and
    /// nonceOlder is nonceTPM (TPM 2.0 Library Part 1, clauses 19.2 and 19.3).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The <c>sessionValue</c> is assembled here, once, for every request-decrypting effect: <c>sessionKey ‖
    /// authValue</c> when the decrypt session also authorizes an entity, <c>sessionKey</c> alone when it
    /// authorizes none — and "the binding of the session is ignored" (Part 1, clause 19.1), so the entity term is
    /// the authorized entity's LIVE authValue, never the bind-omission-resolved term the command HMAC key uses
    /// (clause 17.6.10, equation 22). A caller whose decrypt session authorizes nothing passes the empty carrier
    /// and gets the session key alone.
    /// </para>
    /// <para>
    /// The concatenation lands in pinned pooled scratch cleared before release, and the borrowed carriers are
    /// viewed only here, at the primitive — the authValue term in its trailing-zero-stripped form (Part 1, clause
    /// 17.6.4.3). The production <c>TpmParameterEncryption</c> primitives do the transform, so it matches the
    /// host's own encryption by construction.
    /// </para>
    /// </remarks>
    /// <param name="symmetric">The decrypt session's negotiated symmetric definition, selecting XOR obfuscation or AES-CFB.</param>
    /// <param name="sessionAlg">The decrypt session's hash algorithm, driving its KDFa.</param>
    /// <param name="sessionKey">The decrypt session's session key — a borrowed reference to the carrier the durable session record owns; copied into the scratch and never disposed here.</param>
    /// <param name="entityAuthValue">The authValue of the entity the decrypt session authorizes, unresolved by bind, or the shared empty carrier when it authorizes none — a borrowed reference the durable state owns.</param>
    /// <param name="nonceCaller">The decrypt session's caller nonce for this command (the decryption's nonceNewer).</param>
    /// <param name="nonceTpm">The decrypt session's stored nonceTPM (the decryption's nonceOlder).</param>
    /// <param name="data">The first parameter's data portion, transformed in place; its 2-octet size field is never encrypted and so is not part of this span (Part 1, clause 19.1).</param>
    /// <param name="pool">The memory pool for the sessionValue scratch and the primitive's own buffers.</param>
    /// <param name="ownedInFlight">
    /// The in-flight request whose parse-rented carriers the calling effect still owns, released here when the
    /// cipher refuses the session's symmetric definition outright. The refusal is an exception rather than a
    /// response code (the negotiation that admitted the definition is at <c>TPM2_StartAuthSession()</c>, so
    /// reaching it here is a model contradiction, not a caller error), and an exception leaving an effect
    /// bypasses every response-code path that would otherwise release those carriers —
    /// <see langword="null"/> where the calling effect holds no owned request.
    /// </param>
    /// <param name="cancellationToken">A token observed across the keystream derivation.</param>
    private static async ValueTask ApplyRequestDecryptionAsync(
        TpmtSymDef symmetric, TpmiAlgHash sessionAlg, SymmetricKeyMemory sessionKey, Tpm2bAuth entityAuthValue,
        ReadOnlyMemory<byte> nonceCaller, ReadOnlyMemory<byte> nonceTpm, Memory<byte> data, BaseMemoryPool pool,
        IDisposable? ownedInFlight, CancellationToken cancellationToken)
    {
        ReadOnlyMemory<byte> sessionKeyBytes = sessionKey.AsReadOnlyMemory();
        ReadOnlyMemory<byte> authValueBytes = TpmLifecycleTransitions.StripTrailingZeros(entityAuthValue.AsReadOnlyMemory());
        int sessionValueLength = sessionKeyBytes.Length + authValueBytes.Length;
        using IMemoryOwner<byte> scratch = pool.Rent(Math.Max(sessionValueLength, 1), AllocationKind.Pinned);
        try
        {
            //Lay out sessionKey ‖ StripTrailingZeros(authValue) synchronously (the span never crosses the await).
            {
                sessionKeyBytes.Span.CopyTo(scratch.Memory.Span);
                authValueBytes.Span.CopyTo(scratch.Memory.Span[sessionKeyBytes.Length..]);
            }

            try
            {
                await ApplyParameterCipherAsync(
                    symmetric, sessionAlg, scratch.Memory[..sessionValueLength], nonceCaller, nonceTpm, data,
                    encrypting: false, pool, cancellationToken).ConfigureAwait(false);
            }
            catch(NotSupportedException)
            {
                ownedInFlight?.Dispose();
                throw;
            }
        }
        finally
        {
            scratch.Memory.Span[..sessionValueLength].Clear();
        }
    }

    /// <summary>
    /// Applies the session's parameter-encryption scheme to the response first-parameter data in place: XOR
    /// obfuscation (mandatory, self-inverse) or AES-CFB (platform specific), keyed by the session's
    /// <c>sessionValue</c> with the response-direction nonces the caller supplies (TPM 2.0 Library Part 1,
    /// clauses 19.2 and 19.3).
    /// </summary>
    /// <remarks>
    /// The <c>sessionValue</c> is assembled here by the same rule the request direction uses: <c>sessionKey ‖
    /// authValue</c> when the encrypting session also authorizes an entity, <c>sessionKey</c> alone when it
    /// authorizes none, with the binding of the session ignored (Part 1, clause 19.1). The concatenation lands in
    /// pinned pooled scratch cleared before release. Reuses the production <c>TpmParameterEncryption</c>
    /// primitives, so the mask/keystream matches the host's decryption by construction.
    /// </remarks>
    /// <param name="symmetric">The encrypting session's negotiated symmetric definition.</param>
    /// <param name="sessionAlg">The encrypting session's hash algorithm, driving its KDFa.</param>
    /// <param name="sessionKey">The encrypting session's session key — a borrowed reference to the carrier the durable session record owns.</param>
    /// <param name="entityAuthValue">The authValue of the entity the encrypting session authorizes, unresolved by bind, or the shared empty carrier when it authorizes none.</param>
    /// <param name="nonceNewer">The response direction's nonceNewer — the session's freshly rolled nonceTPM.</param>
    /// <param name="nonceOlder">The response direction's nonceOlder — the session's command caller nonce.</param>
    /// <param name="data">The first response parameter's data portion, transformed in place; its size field is never encrypted.</param>
    /// <param name="pool">The memory pool for the sessionValue scratch and the primitive's own buffers.</param>
    /// <param name="cancellationToken">A token observed across the keystream derivation.</param>
    private static async ValueTask ApplyResponseEncryptionAsync(
        TpmtSymDef symmetric, TpmiAlgHash sessionAlg, SymmetricKeyMemory sessionKey, Tpm2bAuth entityAuthValue,
        ReadOnlyMemory<byte> nonceNewer, ReadOnlyMemory<byte> nonceOlder, Memory<byte> data, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        ReadOnlyMemory<byte> sessionKeyBytes = sessionKey.AsReadOnlyMemory();
        ReadOnlyMemory<byte> authValueBytes = TpmLifecycleTransitions.StripTrailingZeros(entityAuthValue.AsReadOnlyMemory());
        int sessionValueLength = sessionKeyBytes.Length + authValueBytes.Length;
        using IMemoryOwner<byte> scratch = pool.Rent(Math.Max(sessionValueLength, 1), AllocationKind.Pinned);
        try
        {
            //Lay out sessionKey ‖ StripTrailingZeros(authValue) synchronously (the span never crosses the await).
            {
                sessionKeyBytes.Span.CopyTo(scratch.Memory.Span);
                authValueBytes.Span.CopyTo(scratch.Memory.Span[sessionKeyBytes.Length..]);
            }

            await ApplyParameterCipherAsync(
                symmetric, sessionAlg, scratch.Memory[..sessionValueLength], nonceNewer, nonceOlder, data,
                encrypting: true, pool, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            scratch.Memory.Span[..sessionValueLength].Clear();
        }
    }

    /// <summary>
    /// Dispatches an assembled <c>sessionValue</c> and an ordered nonce pair to the parameter-encryption
    /// primitive the session negotiated — XOR obfuscation (TPM 2.0 Library Part 1, clause 19.2) or AES-CFB
    /// (clause 19.3) — transforming the data in place.
    /// </summary>
    /// <remarks>
    /// The single place either direction names a primitive, so the two directions can differ in nothing but the
    /// nonce order they pass and the CFB direction flag (XOR obfuscation is self-inverse and needs neither). A
    /// symmetric definition that is neither is refused loudly rather than silently left untransformed: a session
    /// can only ever hold <c>TPM_ALG_NULL</c>, XOR, or AES-CFB, since <c>TPM2_StartAuthSession()</c> answers
    /// <c>TPM_RC_SYMMETRIC</c>/<c>TPM_RC_MODE</c> for anything else, and a decrypt or encrypt claim over a
    /// <c>TPM_ALG_NULL</c> session is already <c>TPM_RC_SYMMETRIC</c> at the session-area gate (clause 19.1).
    /// </remarks>
    /// <param name="symmetric">The session's negotiated symmetric definition.</param>
    /// <param name="sessionAlg">The session's hash algorithm, driving the KDFa.</param>
    /// <param name="sessionValue">The assembled key material, viewed from pinned scratch its caller clears.</param>
    /// <param name="nonceNewer">The KDFa <c>contextU</c> term for this direction.</param>
    /// <param name="nonceOlder">The KDFa <c>contextV</c> term for this direction.</param>
    /// <param name="data">The parameter data portion, transformed in place.</param>
    /// <param name="encrypting">Whether the CFB transform runs in the encrypting direction; ignored by the self-inverse XOR obfuscation.</param>
    /// <param name="pool">The memory pool for the primitive's own buffers.</param>
    /// <param name="cancellationToken">A token observed across the keystream derivation.</param>
    /// <exception cref="NotSupportedException">The session's symmetric definition is neither XOR obfuscation nor AES-CFB.</exception>
    [SuppressMessage("Interoperability", "CA1416:Validate platform compatibility",
        Justification = "The AES-CFB branch is selected only when the session negotiated an AES TPMT_SYM_DEF, which this simulator agrees only with a caller that requested it; the XOR branch uses no browser-unsupported API. This mirrors the host TpmSession's own suppression for the same primitive.")]
    private static async ValueTask ApplyParameterCipherAsync(
        TpmtSymDef symmetric, TpmiAlgHash sessionAlg, ReadOnlyMemory<byte> sessionValue,
        ReadOnlyMemory<byte> nonceNewer, ReadOnlyMemory<byte> nonceOlder, Memory<byte> data, bool encrypting,
        BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        HashAlgorithmName hashName = SessionHashName(sessionAlg);

        if(symmetric.IsXor)
        {
            await TpmParameterEncryption.XorAsync(hashName, sessionValue, nonceNewer, nonceOlder, data, pool, cancellationToken).ConfigureAwait(false);
        }
        else if(symmetric.Algorithm == TpmAlgIdConstants.TPM_ALG_AES && symmetric.Mode == TpmAlgIdConstants.TPM_ALG_CFB)
        {
            await TpmParameterEncryption.CfbAsync(hashName, symmetric.KeyBits, sessionValue, nonceNewer, nonceOlder, data, encrypting, pool, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            throw new NotSupportedException(
                $"Session parameter encryption with symmetric algorithm '{symmetric.Algorithm}' mode '{symmetric.Mode}' is not supported; only XOR obfuscation and AES-CFB are implemented.");
        }
    }

    /// <summary>
    /// Computes <c>rpHash</c> for a session response = <c>H_sessionAlg(responseCode(TPM_RC_SUCCESS) ||
    /// commandCode || responseParameterArea)</c> — the response parameter bytes as sent, which for an encrypt
    /// session are the ciphertext (TPM 2.0 Library Part 1, clause 16.8, equation 16). Computed through the registered digest
    /// seam over one contiguous buffer.
    /// </summary>
    /// <remarks>
    /// The commandCode is a parameter so the same helper frames the rpHash of every session-response command
    /// (<c>TPM2_GetRandom()</c>, <c>TPM2_Unseal()</c>, <c>TPM2_Create()</c>, ...) under whichever ONE session's
    /// algorithm the caller supplies; a command with several real sessions negotiating different algorithms
    /// calls this once per distinct algorithm (see <see cref="ComputeRpHashPerSessionAsync"/>).
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rpHash buffer transfers to the caller, which releases it via a using declaration.")]
    private static async ValueTask<IMemoryOwner<byte>> ComputeSessionRpHashAsync(TpmiAlgHash sessionAlg, TpmCcConstants commandCode, ReadOnlyMemory<byte> parameterArea, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        int digestSize = SessionDigestSize(sessionAlg);
        int inputLength = sizeof(uint) + sizeof(uint) + parameterArea.Length;
        using IMemoryOwner<byte> inputOwner = pool.Rent(inputLength);

        //Lay out responseCode || commandCode || parameterArea synchronously (the span never crosses the digest await).
        {
            Span<byte> span = inputOwner.Memory.Span[..inputLength];
            BinaryPrimitives.WriteUInt32BigEndian(span, (uint)TpmRcConstants.TPM_RC_SUCCESS);
            BinaryPrimitives.WriteUInt32BigEndian(span[sizeof(uint)..], (uint)commandCode);
            parameterArea.Span.CopyTo(span[(2 * sizeof(uint))..]);
        }

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            inputOwner.Memory[..inputLength], digestSize, SessionDigestTag(sessionAlg), pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        IMemoryOwner<byte> owner = pool.Rent(digestSize);
        try
        {
            digest.AsReadOnlySpan().CopyTo(owner.Memory.Span[..digestSize]);

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Computes rpHash once per DISTINCT hash algorithm present in <paramref name="sessionAlgs"/>, over the SAME
    /// parameter bytes, caching by algorithm (TPM 2.0 Library Part 1, clause 16.8, equation 16): a Create/Unseal
    /// response framed over several real sessions negotiating different hash algorithms (e.g. a SHA-256 auth
    /// session alongside a SHA-384 decrypt/encrypt companion) needs each session's OWN rpHash, never one
    /// session's hash shared by every session — the host-side mirror of this same fix lives in
    /// <c>TpmCommandExecutor.ExecuteAsync</c>.
    /// </summary>
    /// <returns>
    /// One entry per session in <paramref name="sessionAlgs"/> (by index), each pointing into a cached
    /// distinct-algorithm buffer; the caller disposes every entry in the returned owner list exactly once.
    /// </returns>
    private static async ValueTask<(Memory<byte>[] PerSession, List<(TpmiAlgHash Alg, IMemoryOwner<byte> Owner)> DistinctOwners)> ComputeRpHashPerSessionAsync(
        TpmiAlgHash[] sessionAlgs, TpmCcConstants commandCode, ReadOnlyMemory<byte> parameterArea, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        var perSession = new Memory<byte>[sessionAlgs.Length];
        var distinctOwners = new List<(TpmiAlgHash Alg, IMemoryOwner<byte> Owner)>(Math.Min(sessionAlgs.Length, 3));

        for(int i = 0; i < sessionAlgs.Length; i++)
        {
            TpmiAlgHash alg = sessionAlgs[i];

            int cacheIndex = -1;
            for(int c = 0; c < distinctOwners.Count; c++)
            {
                if(distinctOwners[c].Alg == alg)
                {
                    cacheIndex = c;
                    break;
                }
            }

            if(cacheIndex < 0)
            {
                IMemoryOwner<byte> owner = await ComputeSessionRpHashAsync(alg, commandCode, parameterArea, pool, cancellationToken).ConfigureAwait(false);
                distinctOwners.Add((alg, owner));
                cacheIndex = distinctOwners.Count - 1;
            }

            perSession[i] = distinctOwners[cacheIndex].Owner.Memory[..SessionDigestSize(alg)];
        }

        return (perSession, distinctOwners);
    }

    /// <summary>
    /// The response session HMAC = <c>HMAC_sessionAlg(sessionValue, rpHash || nonceTPM(new) || nonceCaller ||
    /// sessionAttributes)</c> (TPM 2.0 Library Part 1, clause 16.7). sessionValue is the session key (the empty
    /// bind authValue adds nothing). Computed through the registered HMAC seam — the SAME the host verifies
    /// with.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the HMAC buffer transfers to the caller, which carries it to the response intent disposed by SerializeResponse.")]
    private static async ValueTask<Tpm2bAuth> ComputeResponseHmacAsync(
        TpmiAlgHash sessionAlg, ReadOnlyMemory<byte> sessionValue, ReadOnlyMemory<byte> rpHash, ReadOnlyMemory<byte> nonceTpm, ReadOnlyMemory<byte> nonceCaller, TpmaSession sessionAttributes, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        int digestSize = SessionDigestSize(sessionAlg);
        int messageLength = rpHash.Length + nonceTpm.Length + nonceCaller.Length + sizeof(byte);
        using IMemoryOwner<byte> messageOwner = pool.Rent(messageLength);

        //Lay out rpHash || nonceTPM || nonceCaller || sessionAttributes synchronously (the span never crosses the await).
        {
            Span<byte> span = messageOwner.Memory.Span[..messageLength];
            int offset = 0;
            rpHash.Span.CopyTo(span);
            offset += rpHash.Length;
            nonceTpm.Span.CopyTo(span[offset..]);
            offset += nonceTpm.Length;
            nonceCaller.Span.CopyTo(span[offset..]);
            offset += nonceCaller.Length;
            span[offset] = (byte)sessionAttributes;
        }

        using HmacValue hmac = await CryptographicKeyEvents.ComputeHmacAsync(
            messageOwner.Memory[..messageLength], sessionValue, digestSize, SessionHmacTag(sessionAlg), pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        IMemoryOwner<byte> storage = pool.Rent(digestSize);
        try
        {
            hmac.AsReadOnlySpan().CopyTo(storage.Memory.Span[..digestSize]);

            return new Tpm2bAuth(storage);
        }
        catch
        {
            storage.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Executes a queued <see cref="TpmVerifyCommandHmacAction"/>: recompute cpHash over the still-encrypted (if
    /// any) parameter bytes exactly as received, then verify the current pending session's command HMAC against
    /// it (TPM 2.0 Library Part 1, clauses 16.7 and 19.6; Part 3, clause 5.6, check 9).
    /// </summary>
    /// <remarks>
    /// The outcome, together with the queue and the original request, is fed back so
    /// <c>OnCommandHmacVerified</c> can either reject (dictionary-attack-aware) or advance to the next queued
    /// session.
    /// </remarks>
    private static async ValueTask<TpmSimulatorInput> VerifyCommandHmacAsync(TpmVerifyCommandHmacAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        TpmPendingSessionVerification current = action.Current;
        int digestSize = SessionDigestSize(current.SessionAlg);

        using IMemoryOwner<byte> cpHash = await ComputeSessionCpHashAsync(
            current.SessionAlg, action.CommandCode, action.HandleNames, action.ParameterArea, context.Pool, cancellationToken).ConfigureAwait(false);

        bool matched = await VerifySessionHmacAsync(
            current.SessionAlg, current.SessionKey, current.AuthValue, cpHash.Memory[..digestSize],
            current.NonceCaller.AsReadOnlyMemory(), current.NonceTpm.AsReadOnlyMemory(), current.FoldedNonceDecrypt.AsReadOnlyMemory(), current.FoldedNonceEncrypt.AsReadOnlyMemory(), current.SessionAttributes,
            current.SuppliedHmac.AsReadOnlyMemory(), context.Pool, cancellationToken).ConfigureAwait(false);

        return new TpmCommandHmacVerified(
            matched, action.CommandCode, current.SessionIndex, current.IsDaProtected,
            action.HandleNames, action.ParameterArea, action.Remaining, action.NextRequest, current.IsLockoutEntity);
    }

    /// <summary>
    /// Computes cpHash for command-side HMAC verification =
    /// <c>H_sessionAlg(commandCode || Name1..N || parameters-as-received)</c> (TPM 2.0 Library Part 1, clause
    /// 16.7 equation 15) — the command-direction mirror of <see cref="ComputeSessionRpHashAsync"/> (which has a
    /// responseCode term in place of the handle-Name area).
    /// </summary>
    /// <remarks>
    /// Computed over the parameter bytes exactly as received — still encrypted, if a decrypt session is present
    /// (Part 1, clause 21.1) — never decrypted first.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the cpHash buffer transfers to the caller, which releases it via a using declaration.")]
    private static async ValueTask<IMemoryOwner<byte>> ComputeSessionCpHashAsync(
        TpmiAlgHash sessionAlg, TpmCcConstants commandCode, TpmCommandHandleNames handleNames, TpmParameterArea parameterArea, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        int digestSize = SessionDigestSize(sessionAlg);
        int handleNamesLength = handleNames.Length;
        int inputLength = sizeof(uint) + handleNamesLength + parameterArea.Length;
        using IMemoryOwner<byte> inputOwner = pool.Rent(inputLength);

        //Lay out commandCode || Name1..N || parameterArea synchronously (the span never crosses the digest
        //await). The Name terms are materialized here rather than carried as octets because the pure transition
        //that decides them holds no memory pool: a computed Name is copied out of the carrier that owns it and a
        //permanent entity's Name is written from its handle value (Part 1, clause 14, Table 6).
        {
            Span<byte> span = inputOwner.Memory.Span[..inputLength];
            BinaryPrimitives.WriteUInt32BigEndian(span, (uint)commandCode);
            handleNames.CopyTo(span[sizeof(uint)..]);
            parameterArea.Span.CopyTo(span[(sizeof(uint) + handleNamesLength)..]);
        }

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            inputOwner.Memory[..inputLength], digestSize, SessionDigestTag(sessionAlg), pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        IMemoryOwner<byte> owner = pool.Rent(digestSize);
        try
        {
            digest.AsReadOnlySpan().CopyTo(owner.Memory.Span[..digestSize]);

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Verifies a session's command HMAC (TPM 2.0 Library Part 1, clause 17.6.5 equation 17; Part 3, clause 5.6, check 9).
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>authHMAC := HMAC_sessionAlg(sessionKey || authValue, cpHash || nonceCaller || nonceTPM ||
    /// nonceTPMdecrypt || nonceTPMencrypt || sessionAttributes)</c>. The two fold terms (Part 1, clause 17.6.3.4)
    /// are supplied separately and concatenated here, in equation 17's own order, because the pure transition
    /// that decides them holds no memory pool while this effect already assembles the message in pooled scratch.
    /// Both are empty for every session except the first session in a command, and only when that first session
    /// itself authorizes an entity.
    /// </para>
    /// <para>
    /// When both <paramref name="sessionKey"/> and <paramref name="authValue"/> are empty, a zero-length hmac is
    /// ALSO accepted (clause 17.6.15's No-HMAC-Authorization: "hmac is allowed to be either a valid authHMAC or an
    /// Empty Buffer" — the clause's own prose is scoped to policy sessions, and this simulator deliberately extends
    /// the allowance to any session type whose key material is entirely empty, a wider-than-reference leniency
    /// since the reference's <c>CheckSessionHMAC</c> has no empty allowance at all) — but a caller that computed
    /// and sent a genuine authHMAC over that empty key (RFC 2104's well-defined empty-key HMAC — the ordinary,
    /// unremarkable choice for a caller with no reason to special-case it) must still verify normally; the
    /// empty-hmac allowance is a permitted shortcut, never a mandate.
    /// </para>
    /// </remarks>
    /// <param name="sessionAlg">The session's negotiated hash algorithm.</param>
    /// <param name="sessionKey">The session's derived key — the borrowed carrier the durable session record owns; its bytes are viewed only here, at the HMAC primitive, and copied into a pinned scratch cleared before release.</param>
    /// <param name="authValue">The authorized entity's authValue — the borrowed carrier the durable state owns, its trailing-zero-stripped view taken only here (Part 1, clause 17.6.4.3), or the shared empty carrier when the HMAC term omits it.</param>
    /// <param name="cpHash">The command parameter hash.</param>
    /// <param name="nonceCaller">The caller-supplied nonceCaller.</param>
    /// <param name="nonceTpm">The session's current nonceTPM.</param>
    /// <param name="foldedNonceDecrypt">Equation 17's <c>nonceTPMdecrypt</c> term — the decrypting session's nonceTPM when that session is not this one, or Empty.</param>
    /// <param name="foldedNonceEncrypt">Equation 17's <c>nonceTPMencrypt</c> term — the encrypting session's nonceTPM when that session is neither this one nor the decrypting one, or Empty.</param>
    /// <param name="sessionAttributes">The session's attribute octet as supplied on the wire.</param>
    /// <param name="suppliedHmac">The caller-supplied hmac to verify against the expected value.</param>
    /// <param name="pool">The memory pool for the key and message buffers.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns><see langword="true"/> when <paramref name="suppliedHmac"/> matches the expected authHMAC (or the No-HMAC-Authorization case applies); otherwise <see langword="false"/>.</returns>
    private static async ValueTask<bool> VerifySessionHmacAsync(
        TpmiAlgHash sessionAlg, SymmetricKeyMemory sessionKey, Tpm2bAuth authValue, ReadOnlyMemory<byte> cpHash,
        ReadOnlyMemory<byte> nonceCaller, ReadOnlyMemory<byte> nonceTpm, ReadOnlyMemory<byte> foldedNonceDecrypt, ReadOnlyMemory<byte> foldedNonceEncrypt, TpmaSession sessionAttributes,
        ReadOnlyMemory<byte> suppliedHmac, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        ReadOnlyMemory<byte> sessionKeyBytes = sessionKey.AsReadOnlyMemory();
        ReadOnlyMemory<byte> authValueBytes = TpmLifecycleTransitions.StripTrailingZeros(authValue.AsReadOnlyMemory());
        if(sessionKeyBytes.IsEmpty && authValueBytes.IsEmpty && suppliedHmac.IsEmpty)
        {
            return true;
        }

        int digestSize = SessionDigestSize(sessionAlg);
        int keyLength = sessionKeyBytes.Length + authValueBytes.Length;
        using IMemoryOwner<byte> keyOwner = pool.Rent(Math.Max(keyLength, 1), AllocationKind.Pinned);
        Memory<byte> key = keyOwner.Memory[..keyLength];

        int messageLength = cpHash.Length + nonceCaller.Length + nonceTpm.Length + foldedNonceDecrypt.Length + foldedNonceEncrypt.Length + sizeof(byte);
        using IMemoryOwner<byte> messageOwner = pool.Rent(messageLength);
        try
        {
            //Lay out the HMAC key and message synchronously (the spans never cross the HMAC await).
            {
                sessionKeyBytes.Span.CopyTo(key.Span);
                authValueBytes.Span.CopyTo(key.Span[sessionKeyBytes.Length..]);

                Span<byte> span = messageOwner.Memory.Span[..messageLength];
                int offset = 0;
                cpHash.Span.CopyTo(span);
                offset += cpHash.Length;
                nonceCaller.Span.CopyTo(span[offset..]);
                offset += nonceCaller.Length;
                nonceTpm.Span.CopyTo(span[offset..]);
                offset += nonceTpm.Length;
                foldedNonceDecrypt.Span.CopyTo(span[offset..]);
                offset += foldedNonceDecrypt.Length;
                foldedNonceEncrypt.Span.CopyTo(span[offset..]);
                offset += foldedNonceEncrypt.Length;
                span[offset] = (byte)sessionAttributes;
            }

            using HmacValue expected = await CryptographicKeyEvents.ComputeHmacAsync(
                messageOwner.Memory[..messageLength], key, digestSize, SessionHmacTag(sessionAlg), pool, cancellationToken: cancellationToken).ConfigureAwait(false);

            return CryptographicOperations.FixedTimeEquals(expected.AsReadOnlySpan(), suppliedHmac.Span);
        }
        finally
        {
            keyOwner.Memory.Span[..keyLength].Clear();
        }
    }

    /// <summary>
    /// Draws a session's freshly rolled nonceTPM (TPM 2.0 Library Part 1, clause 17.6.5) from the injected RNG
    /// into the PAIR of owned <c>TPM2B_NONCE</c> carriers (Part 2, clause 10.4.4, Table 94) a response needs.
    /// </summary>
    /// <remarks>
    /// The two carriers hold the same octets and have deliberately disjoint owners: the framed one travels to
    /// the response intent, whose serialization step is its terminal owner, while the retained one is installed
    /// on the durable session record by the rolling transition and lives until the next roll or the session's
    /// flush. A single carrier cannot serve both — the framing step and the session table release their carriers
    /// at unrelated moments — so each side rents its own, exactly as a loaded object's framed and retained Names
    /// do.
    /// </remarks>
    /// <param name="sessionAlg">The session hash algorithm whose digest width sizes the nonce.</param>
    /// <param name="context">The effect context supplying the RNG seam and the memory pool.</param>
    /// <returns>The framed carrier and the retained carrier, each owned by its caller until it transfers them onward.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of both rolled nonce carriers transfers to the caller, which hands the framed one to the response intent and the retained one to the rolling transition; a failure while the second is being rented releases the first in the catch before rethrowing.")]
    private static (Tpm2bNonce Framed, Tpm2bNonce Retained) RollSessionNonce(TpmiAlgHash sessionAlg, TpmActionContext context)
    {
        int digestSize = SessionDigestSize(sessionAlg);
        IMemoryOwner<byte> storage = context.Pool.Rent(digestSize);
        Tpm2bNonce framed;
        try
        {
            context.Rng(storage.Memory.Span[..digestSize]);
            framed = new Tpm2bNonce(storage);
        }
        catch
        {
            //The rental's only owner is this frame until the carrier adopts it, so a failing draw must
            //release it or the pinned rental is orphaned.
            storage.Dispose();
            throw;
        }

        try
        {
            return (framed, Tpm2bNonce.Create(framed.AsReadOnlySpan(), context.Pool));
        }
        catch
        {
            framed.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Rolls one nonceTPM carrier PAIR per session, each an independent RNG draw (TPM 2.0 Library Part 1, clause
    /// 17.6.5), releasing every pair already rented when a later draw fails.
    /// </summary>
    /// <param name="sessionAlgs">The sessions' hash algorithms, in the order their response entries are framed.</param>
    /// <param name="context">The effect context supplying the RNG seam and the memory pool.</param>
    /// <returns>The framed carriers and the retained carriers, index-aligned with <paramref name="sessionAlgs"/>.</returns>
    private static (Tpm2bNonce[] Framed, Tpm2bNonce[] Retained) RollSessionNonces(TpmiAlgHash[] sessionAlgs, TpmActionContext context)
    {
        var framed = new Tpm2bNonce[sessionAlgs.Length];
        var retained = new Tpm2bNonce[sessionAlgs.Length];
        try
        {
            for(int i = 0; i < sessionAlgs.Length; i++)
            {
                (framed[i], retained[i]) = RollSessionNonce(sessionAlgs[i], context);
            }
        }
        catch
        {
            //Only this frame owns the pairs already rented until the framed entries adopt them, so a failing
            //later draw must release them or the pinned rentals are orphaned.
            ReleaseSessionNonces(framed, retained);
            throw;
        }

        return (framed, retained);
    }

    /// <summary>
    /// Releases every rolled nonce carrier a failing framing step still owns, tolerating the trailing slots a
    /// partial roll never filled.
    /// </summary>
    /// <param name="framed">The framed carriers, some slots possibly unfilled.</param>
    /// <param name="retained">The retained carriers, some slots possibly unfilled.</param>
    private static void ReleaseSessionNonces(Tpm2bNonce[] framed, Tpm2bNonce[] retained)
    {
        for(int i = 0; i < framed.Length; i++)
        {
            retained[i]?.Dispose();
            framed[i]?.Dispose();
        }
    }

    /// <summary>The digest width in octets of a session hash algorithm.</summary>
    private static int SessionDigestSize(TpmiAlgHash hashAlg) => hashAlg.Value switch
    {
        TpmAlgIdConstants.TPM_ALG_SHA1 => 20,
        TpmAlgIdConstants.TPM_ALG_SHA256 => 32,
        TpmAlgIdConstants.TPM_ALG_SHA384 => 48,
        TpmAlgIdConstants.TPM_ALG_SHA512 => 64,
        _ => throw new NotSupportedException($"Session hash algorithm '{hashAlg}' is not supported.")
    };

    /// <summary>Maps a session hash algorithm to its framework name (the KDF, digest, and HMAC dispatch key).</summary>
    private static HashAlgorithmName SessionHashName(TpmiAlgHash hashAlg) => hashAlg.Value switch
    {
        TpmAlgIdConstants.TPM_ALG_SHA1 => HashAlgorithmName.SHA1,
        TpmAlgIdConstants.TPM_ALG_SHA256 => HashAlgorithmName.SHA256,
        TpmAlgIdConstants.TPM_ALG_SHA384 => HashAlgorithmName.SHA384,
        TpmAlgIdConstants.TPM_ALG_SHA512 => HashAlgorithmName.SHA512,
        _ => throw new NotSupportedException($"Session hash algorithm '{hashAlg}' is not supported.")
    };

    /// <summary>
    /// The digest tag for the session's rpHash: the hash family carried inline (TPM sessions may use SHA-1,
    /// which the convenience <c>CryptoTags</c> deliberately omit), mirroring the executor's own tag
    /// construction.
    /// </summary>
    private static Tag SessionDigestTag(TpmiAlgHash hashAlg) =>
        Tag.Create(SessionHashName(hashAlg))
            .With(Purpose.Digest)
            .With(EncodingScheme.Raw)
            .With(MaterialSemantics.Direct);

    /// <summary>The HMAC tag for the session's response HMAC, mirroring the host <c>TpmSession</c>'s own tag construction.</summary>
    private static Tag SessionHmacTag(TpmiAlgHash hashAlg) =>
        Tag.Create(SessionHashName(hashAlg))
            .With(Purpose.Hmac)
            .With(EncodingScheme.Raw)
            .With(MaterialSemantics.Direct);

    /// <summary>
    /// The credential-protection outer wrap's symmetric key width in bits: the credential key's (endorsement
    /// key's) symmetric algorithm, which for the ECC storage/EK template this model creates is AES-128-CFB (TPM
    /// 2.0 Library Part 1, clause 25.2; the storage parent template negotiates AES-128).
    /// </summary>
    private const int CredentialSymmetricKeyBits = 128;

    /// <summary>The credential-protection outer wrap's symmetric key width in bytes; see <see cref="CredentialSymmetricKeyBits"/>.</summary>
    private const int CredentialSymmetricKeyBytes = CredentialSymmetricKeyBits / 8;

    /// <summary>
    /// The credential-protection outer wrap's AES-CFB block size in octets. The IV is a block of zeros (the
    /// seed is single-use, so no per-object IV is needed).
    /// </summary>
    private const int CredentialSymmetricBlockSize = 16;

    /// <summary>The KDFe use label for the credential-protection seed derivation (TPM 2.0 Library Part 1, clause 24).</summary>
    private const string CredentialIdentityLabel = "IDENTITY";

    /// <summary>The KDFa outer-wrap label for the credential-protection symmetric key (TPM 2.0 Library Part 1, clause 24).</summary>
    private const string CredentialStorageLabel = "STORAGE";

    /// <summary>The KDFa outer-wrap label for the credential-protection HMAC key (TPM 2.0 Library Part 1, clause 24).</summary>
    private const string CredentialIntegrityLabel = "INTEGRITY";

    /// <summary>
    /// The RSA arm's OAEP label (L, TPM 2.0 Library Part 1, Annex B.4, B.10.4): the ASCII octets "IDENTITY" plus
    /// a trailing NUL that is part of the lhash digest input, not a KDFa-style separator the digest skips — a
    /// plain 9-octet buffer, unrelated to <see cref="CredentialIdentityLabel"/> above (which feeds the ECC arm's
    /// KDFe use-label, a different mechanism).
    /// </summary>
    /// <remarks>A static getter, not a byte[] field, per this codebase's static-cache convention.</remarks>
    private static ReadOnlyMemory<byte> CredentialIdentityLabelOctets { get; } = "IDENTITY\0"u8.ToArray();

    /// <summary>
    /// <c>TPM2_MakeCredential()</c>: wrap a credential so only a TPM holding the credential key's private scalar
    /// and the object named by objectName can recover it (TPM 2.0 Library Part 1, clause 24; Part 3, clause
    /// 12.6).
    /// </summary>
    /// <remarks>
    /// The seed is transported by an ECDH exchange with the credential key's public point —
    /// <c>Z = ECDH(ephemeralPriv, EK_pub)</c>, then <c>seed = KDFe(nameAlg, Z, "IDENTITY", ephemeral x, EK
    /// x)</c> — and the outer wrap (<see cref="BuildCredentialBlobAsync"/>) binds the credential's integrity to
    /// objectName. The encrypted secret carries the ephemeral public point as a marshaled TPMS_ECC_POINT, the
    /// ECC form of TPM2B_ENCRYPTED_SECRET (Part 2, clause 11.4.33). Ownership of the credential blob and the
    /// secret flows to <see cref="TpmCredentialMade"/>, then to the response intent, and is released by
    /// <see cref="SerializeResponse"/>.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the credential-blob and secret buffers transfers to the returned TpmCredentialMade, then to the TpmMakeCredentialResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> MakeCredentialAsync(TpmMakeCredentialAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        //This effect is the object Name's and the credential secret's terminal owner: the KDFa derivations and
        //the outer HMAC copy their octets into their own message buffers, so nothing downstream ever reads
        //either carrier.
        using Tpm2bName objectName = action.ObjectName;
        using Tpm2bDigest credential = action.Credential;

        TpmEccSigningBackend backend = context.SigningBackend
            ?? throw new InvalidOperationException("TPM2_MakeCredential() requires a signing backend, but none was supplied.");
        BaseMemoryPool pool = context.Pool;

        int fieldWidth = (action.CredentialKeyPublicPoint.Length - 1) / 2;
        int seedSize = SessionDigestSize(action.NameAlg);

        //A fresh ephemeral key pair for the ECDH seed transport (a new pair per credential; Part 1, clause 24).
        using TpmGeneratedEccKey ephemeral = await backend.GenerateKey(action.CredentialKeyCurve.Value, pool, cancellationToken).ConfigureAwait(false);

        //Extract the SEC1 ephemeral point, the ephemeral scalar, and the two KDFe x-coordinates (partyUInfo = the
        //ephemeral point's x, partyVInfo = the credential key's x) into arrays, so the spans never cross the awaits.
        byte[] ephemeralPoint;
        byte[] ephemeralScalar;
        byte[] ephemeralX;
        byte[] credentialKeyX;
        {
            ReadOnlySpan<byte> ephemeralPointSpan = ephemeral.PublicPoint.AsReadOnlySpan();
            ephemeralPoint = ephemeralPointSpan.ToArray();
            ephemeralScalar = ephemeral.PrivateScalar.AsReadOnlySpan().ToArray();
            ephemeralX = EllipticCurveUtilities.SliceXCoordinate(ephemeralPointSpan).ToArray();
            credentialKeyX = EllipticCurveUtilities.SliceXCoordinate(action.CredentialKeyPublicPoint.Span).ToArray();
        }

        try
        {
            using IMemoryOwner<byte> sharedValue = await backend.ComputeSharedSecret(
                ephemeralScalar, action.CredentialKeyPublicPoint, action.CredentialKeyCurve.Value, pool, cancellationToken).ConfigureAwait(false);
            using IMemoryOwner<byte> seed = await Kdfe.DeriveAsync(
                SessionHashName(action.NameAlg), sharedValue.Memory[..fieldWidth], CredentialIdentityLabel, ephemeralX, credentialKeyX, seedSize * 8, pool, cancellationToken).ConfigureAwait(false);

            (IMemoryOwner<byte> credentialBlobStorage, int credentialBlobLength) = await BuildCredentialBlobAsync(
                seed.Memory[..seedSize], credential.AsReadOnlyMemory(), objectName.AsReadOnlyMemory(), action.NameAlg, pool, cancellationToken).ConfigureAwait(false);
            Tpm2bIdObject credentialBlob = Tpm2bIdObject.FromMarshaled(credentialBlobStorage, credentialBlobLength);
            try
            {
                seed.Memory.Span[..seedSize].Clear();
                (IMemoryOwner<byte> secretStorage, int secretLength) = FrameEccPointSecret(ephemeralPoint, fieldWidth, pool);

                return new TpmCredentialMade(credentialBlob, Tpm2bEncryptedSecret.FromMarshaled(secretStorage, secretLength));
            }
            catch
            {
                credentialBlob.Dispose();
                throw;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ephemeralScalar);
        }
    }

    /// <summary>
    /// Builds the credential blob (<c>TPMS_ID_OBJECT</c>) of <c>TPM2_MakeCredential()</c>'s outer wrap (TPM 2.0
    /// Library Part 1, clause 24): <c>symKey = KDFa(nameAlg, seed, "STORAGE", objectName, empty, symBits)</c>
    /// keys the AES-CFB encryption of the marshaled credential (a zero IV), and <c>hmacKey = KDFa(nameAlg, seed,
    /// "INTEGRITY", empty, empty, digestBits)</c> keys <c>outerHMAC = HMAC(hmacKey, encIdentity ||
    /// objectName)</c>.
    /// </summary>
    /// <remarks>
    /// Both derivations fold in the bound object's Name, so the blob can only be recovered by activating against
    /// that same object. The blob is <c>TPM2B(outerHMAC) || encIdentity</c>.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the credential-blob buffer transfers to the caller, which carries it to the response intent disposed by SerializeResponse; the intermediate buffers are released by their using declarations.")]
    [SuppressMessage("Interoperability", "CA1416:Validate platform compatibility",
        Justification = "The credential-protection outer wrap uses AES-CFB, the symmetric algorithm of the credential key's (endorsement key's) storage template (TPM 2.0 Library Part 1, clause 24); this in-process behavioural simulator is a test/server-side model, not a browser target. This mirrors the host's own suppression for the same primitive.")]
    private static async ValueTask<(IMemoryOwner<byte> Owner, int Length)> BuildCredentialBlobAsync(
        ReadOnlyMemory<byte> seed, ReadOnlyMemory<byte> credential, ReadOnlyMemory<byte> objectName, TpmiAlgHash nameAlg, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        int digestSize = SessionDigestSize(nameAlg);
        HashAlgorithmName hashName = SessionHashName(nameAlg);

        //innerData = marshaled TPM2B_DIGEST(credential): a UINT16 size prefix followed by the credential octets.
        int credLen = credential.Length;
        int innerLen = sizeof(ushort) + credLen;

        using IMemoryOwner<byte> symKey = await Kdfa.DeriveAsync(
            hashName, seed, CredentialStorageLabel, objectName, ReadOnlyMemory<byte>.Empty, CredentialSymmetricKeyBits, pool, cancellationToken).ConfigureAwait(false);
        using IMemoryOwner<byte> encIdentity = pool.Rent(innerLen, AllocationKind.Pinned);

        //Lay out the marshaled credential and AES-CFB-encrypt it in place (synchronous; no await inside the block).
        {
            Span<byte> inner = encIdentity.Memory.Span[..innerLen];
            BinaryPrimitives.WriteUInt16BigEndian(inner, (ushort)credLen);
            credential.Span.CopyTo(inner[sizeof(ushort)..]);

            byte[] zeroIv = new byte[CredentialSymmetricBlockSize];
            TpmParameterEncryption.AesCfb(symKey.Memory.Span[..CredentialSymmetricKeyBytes], zeroIv, inner, encrypting: true);
        }

        symKey.Memory.Span[..CredentialSymmetricKeyBytes].Clear();

        using IMemoryOwner<byte> hmacKey = await Kdfa.DeriveAsync(
            hashName, seed, CredentialIntegrityLabel, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, digestSize * 8, pool, cancellationToken).ConfigureAwait(false);
        using IMemoryOwner<byte> outerHmac = await ComputeCredentialHmacAsync(
            hmacKey.Memory[..digestSize], encIdentity.Memory[..innerLen], objectName, nameAlg, pool, cancellationToken).ConfigureAwait(false);
        hmacKey.Memory.Span[..digestSize].Clear();

        int blobLen = sizeof(ushort) + digestSize + innerLen;
        IMemoryOwner<byte> owner = pool.Rent(blobLen);
        try
        {
            Span<byte> blob = owner.Memory.Span[..blobLen];
            BinaryPrimitives.WriteUInt16BigEndian(blob, (ushort)digestSize);
            outerHmac.Memory.Span[..digestSize].CopyTo(blob[sizeof(ushort)..]);
            encIdentity.Memory.Span[..innerLen].CopyTo(blob[(sizeof(ushort) + digestSize)..]);

            return (owner, blobLen);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Frames the ephemeral public point as the encrypted-secret transport: a marshaled <c>TPMS_ECC_POINT</c>
    /// (TPM2B x || TPM2B y) at the curve field width — the ECC form of <c>TPM2B_ENCRYPTED_SECRET</c> (TPM 2.0
    /// Library Part 2, clauses 11.2.5 and 11.4.33). The point is SEC1 uncompressed (0x04 || X || Y), so X and Y
    /// are the field-width halves after the tag.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the secret buffer transfers to the caller, which carries it to the response intent disposed by SerializeResponse.")]
    private static (IMemoryOwner<byte> Owner, int Length) FrameEccPointSecret(byte[] sec1Point, int fieldWidth, BaseMemoryPool pool)
    {
        int secretLen = 2 * (sizeof(ushort) + fieldWidth);
        IMemoryOwner<byte> owner = pool.Rent(secretLen);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span[..secretLen]);
            writer.WriteTpm2b(sec1Point.AsSpan(1, fieldWidth));                //x coordinate.
            writer.WriteTpm2b(sec1Point.AsSpan(1 + fieldWidth, fieldWidth));   //y coordinate.

            return (owner, secretLen);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// <c>TPM2_MakeCredential()</c> RSA arm: wrap a credential so only a TPM holding the credential key's RSA
    /// private key and the object named by objectName can recover it (TPM 2.0 Library Part 1, clause 24; Annex
    /// B.4, B.10.3, B.10.4; Part 3, clause 12.6).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Unlike the ECC arm, the seed is a fresh random value (no ephemeral key pair — RSA has no ECDH-style split
    /// step), transported by OAEP-encrypting it to the credential key's modulus with label "IDENTITY"+NUL (Annex
    /// B.10.4). The lhash algorithm is the credential key's scheme hash, or nameAlg when the scheme is NULL
    /// (Annex B.4) — every storage-parent template this simulator builds uses scheme NULL, so lhash is
    /// <c>action.NameAlg</c>; MGF1 always uses the key's Name algorithm (also <c>action.NameAlg</c> here) — the
    /// two are threaded as separate delegate parameters, kept distinct on principle, even though they coincide
    /// for L-1. The seed width is the lhash digest size (Part 1, Annex B.10.3: "the size of a digest produced by
    /// the OAEP hash algorithm"), reusing <see cref="SessionDigestSize"/> exactly as the ECC arm's KDFe seed
    /// sizing does.
    /// </para>
    /// <para>
    /// The outer wrap (<see cref="BuildCredentialBlobAsync"/>) is unchanged from the ECC arm (clause 24 does not
    /// branch on the credential key's algorithm). <c>TPM2B_ENCRYPTED_SECRET</c>'s content for RSA is the raw
    /// ciphertext directly, no sub-structure (Part 2, Table 209/210) — unlike the ECC arm's marshaled
    /// TPMS_ECC_POINT, the OAEP ciphertext <c>backend.EncryptOaep</c> returns already IS that content, verbatim;
    /// <see cref="SerializeResponse"/> adds the one TPM2B_ENCRYPTED_SECRET wrapper when framing the wire
    /// response, so no extra framing step belongs here.
    /// </para>
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the credential-blob and secret buffers transfers to the returned TpmCredentialMade, then to the TpmMakeCredentialResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> MakeCredentialRsaAsync(TpmRsaMakeCredentialAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        //This effect is the object Name's and the credential secret's terminal owner: the KDFa derivations and
        //the outer HMAC copy their octets into their own message buffers, so nothing downstream ever reads
        //either carrier.
        using Tpm2bName objectName = action.ObjectName;
        using Tpm2bDigest credential = action.Credential;

        TpmRsaSigningBackend backend = context.RsaSigningBackend
            ?? throw new InvalidOperationException("TPM2_MakeCredential() for an RSA credential key requires an RSA signing backend, but none was supplied.");
        BaseMemoryPool pool = context.Pool;

        int seedSize = SessionDigestSize(action.NameAlg);

        //A fresh random seed drawn from the simulator's RNG seam — not derived from an ephemeral key
        //pair, unlike the ECC arm.
        using IMemoryOwner<byte> seed = pool.Rent(seedSize, AllocationKind.Pinned);
        context.Rng(seed.Memory.Span[..seedSize]);

        try
        {
            IMemoryOwner<byte> secretStorage = await backend.EncryptOaep(
                action.CredentialKeyModulus.AsReadOnlyMemory(), TpmsRsaParms.DefaultExponent, seed.Memory[..seedSize], CredentialIdentityLabelOctets,
                action.NameAlg.Value, action.NameAlg.Value, pool, cancellationToken).ConfigureAwait(false);
            Tpm2bEncryptedSecret secret = Tpm2bEncryptedSecret.FromMarshaled(secretStorage, secretStorage.Memory.Length);
            try
            {
                (IMemoryOwner<byte> credentialBlobStorage, int credentialBlobLength) = await BuildCredentialBlobAsync(
                    seed.Memory[..seedSize], credential.AsReadOnlyMemory(), objectName.AsReadOnlyMemory(), action.NameAlg, pool, cancellationToken).ConfigureAwait(false);

                return new TpmCredentialMade(Tpm2bIdObject.FromMarshaled(credentialBlobStorage, credentialBlobLength), secret);
            }
            catch
            {
                secret.Dispose();
                throw;
            }
        }
        finally
        {
            seed.Memory.Span[..seedSize].Clear();
        }
    }

    /// <summary>
    /// Computes <c>outerHMAC = HMAC_nameAlg(hmacKey, encIdentity || objectName)</c> (TPM 2.0 Library Part 1,
    /// clause 24), through the registered HMAC seam over one contiguous buffer — the same seam MakeCredential
    /// and ActivateCredential both drive, so the produced and recomputed HMACs agree by construction.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the HMAC buffer transfers to the caller, which releases it via a using declaration.")]
    private static async ValueTask<IMemoryOwner<byte>> ComputeCredentialHmacAsync(
        ReadOnlyMemory<byte> hmacKey, ReadOnlyMemory<byte> encIdentity, ReadOnlyMemory<byte> objectName, TpmiAlgHash nameAlg, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        int digestSize = SessionDigestSize(nameAlg);
        int messageLen = encIdentity.Length + objectName.Length;
        using IMemoryOwner<byte> message = pool.Rent(messageLen);

        //Lay out encIdentity || objectName synchronously (the span never crosses the HMAC await).
        {
            Span<byte> span = message.Memory.Span[..messageLen];
            encIdentity.Span.CopyTo(span);
            objectName.Span.CopyTo(span[encIdentity.Length..]);
        }

        using HmacValue hmac = await CryptographicKeyEvents.ComputeHmacAsync(
            message.Memory[..messageLen], hmacKey, digestSize, SessionHmacTag(nameAlg), pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        IMemoryOwner<byte> owner = pool.Rent(digestSize);
        try
        {
            hmac.AsReadOnlySpan().CopyTo(owner.Memory.Span[..digestSize]);

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// <c>TPM2_ActivateCredential()</c>: recover the wrapped credential (TPM 2.0 Library Part 1, clause 24; Part
    /// 3, clause 12.5). Recover the seed by <c>Z = ECDH(EK_priv, ephemeralPub)</c> fed to KDFe — the same seed
    /// MakeCredential produced, by ECDH symmetry — then re-derive symKey/hmacKey from the seed AND the ACTIVATE
    /// object's Name, recompute the outer HMAC over the ciphertext and that Name, and compare it (constant time)
    /// to the blob's HMAC.
    /// </summary>
    /// <remarks>
    /// On a match, AES-CFB-decrypt encIdentity and unmarshal the credential; on a mismatch, answer
    /// <c>TPM_RC_INTEGRITY</c> — so a credential bound to one object cannot be recovered against another (the
    /// negative case). <c>TPM_RC_INTEGRITY</c> is that mismatch's code alone: the unmarshal of the recovered
    /// <c>TPM2B_DIGEST</c> answers <c>TPM_RC_INSUFFICIENT</c> where the plaintext cannot supply the size field
    /// or the declared body, and <c>TPM_RC_SIZE</c> where the declared width exceeds <c>sizeof(TPMU_HA)</c> or
    /// octets remain after the digest — the three-code return contract of Part 4, <c>CredentialToSecret()</c>,
    /// page 734. Ownership of the recovered secret flows to <see cref="TpmCredentialActivated"/>, then to
    /// the response intent, and is released (zeroed) by <see cref="SerializeResponse"/> after framing.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the recovered-secret buffer transfers to the returned TpmCredentialActivated, then to the TpmActivateCredentialResponse intent, and is released by SerializeResponse after framing.")]
    [SuppressMessage("Interoperability", "CA1416:Validate platform compatibility",
        Justification = "The credential-protection outer wrap uses AES-CFB, the symmetric algorithm of the credential key's (endorsement key's) storage template (TPM 2.0 Library Part 1, clause 24); this in-process behavioural simulator is a test/server-side model, not a browser target. This mirrors the host's own suppression for the same primitive.")]
    private static async ValueTask<TpmSimulatorInput> ActivateCredentialAsync(TpmActivateCredentialAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        TpmEccSigningBackend backend = context.SigningBackend
            ?? throw new InvalidOperationException("TPM2_ActivateCredential() requires a signing backend, but none was supplied.");
        BaseMemoryPool pool = context.Pool;

        int fieldWidth = (action.CredentialKeyPublicPoint.Length - 1) / 2;
        int seedSize = SessionDigestSize(action.NameAlg);
        HashAlgorithmName hashName = SessionHashName(action.NameAlg);

        //Recover the ephemeral point from the secret (a marshaled TPMS_ECC_POINT) and the outer-HMAC / encIdentity
        //split from the credential blob (TPM2B outer HMAC || encIdentity), into arrays so no span crosses an await.
        byte[] ephemeralPoint;
        byte[] ephemeralX;
        byte[] credentialKeyX;
        byte[] blobHmac;
        byte[] encIdentity;
        try
        {
            var pointReader = new TpmReader(action.Secret.Span);
            ushort xLen = pointReader.ReadUInt16();
            ReadOnlySpan<byte> x = pointReader.ReadBytes(xLen);
            ushort yLen = pointReader.ReadUInt16();
            ReadOnlySpan<byte> y = pointReader.ReadBytes(yLen);
            ephemeralPoint = EllipticCurveUtilities.CombineToUncompressedPoint(x, y);
            ephemeralX = x.ToArray();
            credentialKeyX = EllipticCurveUtilities.SliceXCoordinate(action.CredentialKeyPublicPoint.Span).ToArray();

            var blobReader = new TpmReader(action.CredentialBlob.Span);
            ushort hmacLen = blobReader.ReadUInt16();
            blobHmac = blobReader.ReadBytes(hmacLen).ToArray();
            encIdentity = blobReader.ReadBytes(blobReader.Remaining).ToArray();
        }
        catch(ArgumentOutOfRangeException)
        {
            //credentialBlob and secret are attacker-influenceable wire buffers; a structurally legal but too-small
            //TPM2B (an under-length ECC point or HMAC) must fail closed as TPM_RC_SIZE rather than throw an
            //out-of-range exception out of the effect executor, which the PDA runner does not catch (Part 3,
            //clause 12.5). The reads and the point assembly are the only under-length-sensitive steps here.
            return new TpmCredentialActivated(TpmRcConstants.TPM_RC_SIZE, CertInfo: null);
        }

        using IMemoryOwner<byte> sharedValue = await backend.ComputeSharedSecret(
            action.CredentialKeyPrivateScalar.AsReadOnlyMemory(), ephemeralPoint, action.CredentialKeyCurve.Value, pool, cancellationToken).ConfigureAwait(false);
        using IMemoryOwner<byte> seed = await Kdfe.DeriveAsync(
            hashName, sharedValue.Memory[..fieldWidth], CredentialIdentityLabel, ephemeralX, credentialKeyX, seedSize * 8, pool, cancellationToken).ConfigureAwait(false);

        //Recompute the outer HMAC over the ciphertext and the ACTIVATE object's Name; a mismatch is TPM_RC_INTEGRITY
        //(Part 3, clause 12.5) — the credential was bound to a different object, or is corrupt.
        using IMemoryOwner<byte> hmacKey = await Kdfa.DeriveAsync(
            hashName, seed.Memory[..seedSize], CredentialIntegrityLabel, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, seedSize * 8, pool, cancellationToken).ConfigureAwait(false);
        using(IMemoryOwner<byte> expectedHmac = await ComputeCredentialHmacAsync(
            hmacKey.Memory[..seedSize], encIdentity, action.ActivateObjectName.AsReadOnlyMemory(), action.NameAlg, pool, cancellationToken).ConfigureAwait(false))
        {
            hmacKey.Memory.Span[..seedSize].Clear();

            if(!CryptographicOperations.FixedTimeEquals(expectedHmac.Memory.Span[..seedSize], blobHmac))
            {
                seed.Memory.Span[..seedSize].Clear();

                return new TpmCredentialActivated(TpmRcConstants.TPM_RC_INTEGRITY, CertInfo: null);
            }
        }

        //Integrity verified: derive symKey from the seed and the activate object's Name, AES-CFB-decrypt encIdentity,
        //and unmarshal the recovered TPM2B_DIGEST credential.
        using IMemoryOwner<byte> symKey = await Kdfa.DeriveAsync(
            hashName, seed.Memory[..seedSize], CredentialStorageLabel, action.ActivateObjectName.AsReadOnlyMemory(), ReadOnlyMemory<byte>.Empty, CredentialSymmetricKeyBits, pool, cancellationToken).ConfigureAwait(false);
        seed.Memory.Span[..seedSize].Clear();

        using IMemoryOwner<byte> plaintext = pool.Rent(Math.Max(encIdentity.Length, 1), AllocationKind.Pinned);
        try
        {
            //Decrypt and read the credential synchronously (no await between the decrypt and the copy-out).
            int credLen;
            Tpm2bDigest certInfo;
            {
                byte[] zeroIv = new byte[CredentialSymmetricBlockSize];
                encIdentity.CopyTo(plaintext.Memory.Span);
                TpmParameterEncryption.AesCfb(symKey.Memory.Span[..CredentialSymmetricKeyBytes], zeroIv, plaintext.Memory.Span[..encIdentity.Length], encrypting: false);
                symKey.Memory.Span[..CredentialSymmetricKeyBytes].Clear();

                //The recovered plaintext is unmarshaled as a TPM2B_DIGEST on the reference's return contract
                //(Part 4, CredentialToSecret(), page 734: "TPM_RC_INSUFFICIENT error during credential
                //unmarshaling / TPM_RC_INTEGRITY credential integrity is broken / TPM_RC_SIZE error during
                //credential unmarshaling"). TPM_RC_INTEGRITY belongs to the outer HMAC alone, which the step
                //above already answered; only a blob that passed that HMAC reaches here, so the unmarshal's own
                //two codes separate malformed structures from one another and never report a credential's
                //binding — the integrity-before-use ordering Part 3, clause 13.3.1 states for this same
                //construction: "Checking the integrity before the data is used prevents attacks on the
                //sensitive area by fuzzing the data and looking at the differences in the response codes."
                //
                //A plaintext too narrow to supply the UINT16 size field is UINT16_Unmarshal()'s shortfall,
                //TPM_RC_INSUFFICIENT (Part 4, TPM2B_DIGEST_Unmarshal(), page 1138).
                if(encIdentity.Length < sizeof(ushort))
                {
                    return new TpmCredentialActivated(TpmRcConstants.TPM_RC_INSUFFICIENT, CertInfo: null);
                }

                var reader = new TpmReader(plaintext.Memory.Span[..encIdentity.Length]);
                credLen = reader.ReadUInt16();

                //A declared width past sizeof(TPMU_HA) is TPM2B_DIGEST_Unmarshal()'s own size refusal, taken
                //before the body is read (Part 4, page 1138: "if((result == TPM_RC_SUCCESS) && (target->t.size
                //> sizeof(TPMU_HA))) result = TPM_RC_SIZE"; Part 2, clause 10.4.2, Table 92) and BEFORE any
                //carrier is rented, so no over-bound TPM2B_DIGEST is ever framed for the host parser to refuse.
                if(credLen > Tpm2bDigest.MaxSize)
                {
                    return new TpmCredentialActivated(TpmRcConstants.TPM_RC_SIZE, CertInfo: null);
                }

                //A declared width the plaintext cannot supply is BYTE_Array_Unmarshal()'s shortfall,
                //TPM_RC_INSUFFICIENT (Part 4, page 1212: "if(*size < count) return TPM_RC_INSUFFICIENT"). The
                //recovered length is attacker-influenceable, so this gate is what keeps an out-of-range read
                //from escaping the effect executor as an exception instead of a response code.
                if(credLen > reader.Remaining)
                {
                    return new TpmCredentialActivated(TpmRcConstants.TPM_RC_INSUFFICIENT, CertInfo: null);
                }

                ReadOnlySpan<byte> credential = reader.ReadBytes(credLen);

                //Octets past the credential mean the plaintext carried more than the one TPM2B_DIGEST, which is
                //CredentialToSecret()'s closing check (Part 4, page 734: "if(result == TPM_RC_SUCCESS && size
                //!= 0) return TPM_RC_SIZE").
                if(reader.Remaining != 0)
                {
                    return new TpmCredentialActivated(TpmRcConstants.TPM_RC_SIZE, CertInfo: null);
                }

                //A zero-length credential frames an empty TPM2B_DIGEST, which is the dispose-immune shared
                //sentinel and rents nothing; any other width rents exactly its own octets, pinned, so the
                //recovered secret never moves and the carrier's size IS the wire size.
                if(credLen == 0)
                {
                    certInfo = Tpm2bDigest.Empty;
                }
                else
                {
                    IMemoryOwner<byte> certInfoStorage = pool.Rent(credLen, AllocationKind.Pinned);
                    try
                    {
                        credential.CopyTo(certInfoStorage.Memory.Span);
                        certInfo = new Tpm2bDigest(certInfoStorage);
                    }
                    catch
                    {
                        certInfoStorage.Memory.Span.Clear();
                        certInfoStorage.Dispose();
                        throw;
                    }
                }
            }

            return new TpmCredentialActivated(TpmRcConstants.TPM_RC_SUCCESS, certInfo);
        }
        finally
        {
            //plaintext held the recovered credential; zero it before returning the buffer to the pool.
            plaintext.Memory.Span[..encIdentity.Length].Clear();
        }
    }

    /// <summary>
    /// <c>TPM2_ActivateCredential()</c> RSA arm: recover the wrapped credential (TPM 2.0 Library Part 1, clause
    /// 24; Annex B.3, B.4, B.10.3, B.10.4; Part 3, clause 12.5). RSADP-decrypt and OAEP-decode the transported
    /// secret with the credential key's retained private key.
    /// </summary>
    /// <remarks>
    /// <para>
    /// On any decode failure — the delegate signals this by returning null rather than a distinct error, per
    /// <c>TpmRsaOaepDecryptDelegate</c>'s contract — substitute a fresh UNPREDICTABLE seed of the correct length
    /// and proceed exactly as on success (TPM 2.0 Library Part 1, Annex B.10.3: "the error should cause the seed
    /// value to be set to an invalid value so that the error will not be reported until the integrity HMAC is
    /// validated", imported by B.10.4 for the credential case); a recovered seed of the wrong width is treated
    /// identically, since a correct-width message is itself part of what OAEP decoding must validate.
    /// </para>
    /// <para>
    /// The substitute is drawn from the RNG seam, NOT a fixed constant: "an invalid value" must be one an
    /// attacker cannot use to construct a passing HMAC. A known substitute (e.g. all-zeros) makes the derived
    /// symKey/hmacKey fully attacker-computable — the ACTIVATE object's Name is public — so an adversary could
    /// forge a credential blob whose outer HMAC validates under that known seed and submit it alongside a
    /// deliberately decode-failing secret, making ActivateCredential return <c>TPM_RC_SUCCESS</c> for a
    /// credential that never validly decrypted to the endorsement key: a forgery/distinguishing oracle that
    /// defeats attestation soundness. An unpredictable seed makes the outer HMAC fail with overwhelming
    /// probability, so the failure is reported uniformly as <c>TPM_RC_INTEGRITY</c> (Annex B.10.3's intent)
    /// without exposing that oracle.
    /// </para>
    /// <para>
    /// The outer-wrap recovery that follows (re-derive symKey/hmacKey from the seed AND the ACTIVATE object's
    /// Name, verify the HMAC constant-time, decrypt, unmarshal the recovered <c>TPM2B_DIGEST</c>) is identical
    /// to the ECC arm's — clause 24 does not branch on the credential key's algorithm — and so is its
    /// three-code return contract: <c>TPM_RC_INTEGRITY</c> for the outer HMAC alone, <c>TPM_RC_INSUFFICIENT</c>
    /// where the plaintext cannot supply the size field or the declared body, <c>TPM_RC_SIZE</c> where the
    /// declared width exceeds <c>sizeof(TPMU_HA)</c> or octets remain after the digest (Part 4,
    /// <c>CredentialToSecret()</c>, page 734).
    /// </para>
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the recovered-secret buffer transfers to the returned TpmCredentialActivated, then to the TpmActivateCredentialResponse intent, and is released by SerializeResponse after framing.")]
    [SuppressMessage("Interoperability", "CA1416:Validate platform compatibility",
        Justification = "The credential-protection outer wrap uses AES-CFB, the symmetric algorithm of the credential key's (endorsement key's) storage template (TPM 2.0 Library Part 1, clause 24); this in-process behavioural simulator is a test/server-side model, not a browser target. This mirrors the host's own suppression for the same primitive.")]
    private static async ValueTask<TpmSimulatorInput> ActivateCredentialRsaAsync(TpmRsaActivateCredentialAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        TpmRsaSigningBackend backend = context.RsaSigningBackend
            ?? throw new InvalidOperationException("TPM2_ActivateCredential() for an RSA credential key requires an RSA signing backend, but none was supplied.");
        BaseMemoryPool pool = context.Pool;

        int seedSize = SessionDigestSize(action.NameAlg);
        HashAlgorithmName hashName = SessionHashName(action.NameAlg);

        //action.Secret is already the unwrapped content of the wire TPM2B_ENCRYPTED_SECRET (the command
        //parser stripped that one framing layer) — for RSA that content is the raw OAEP ciphertext directly, no
        //further sub-structure, unlike the ECC arm's marshaled TPMS_ECC_POINT. Copy it and the credential blob's
        //split (TPM2B outer HMAC || encIdentity) into arrays so no span crosses the OAEP-decrypt await.
        byte[] ciphertext = action.Secret.ToArray();
        byte[] blobHmac;
        byte[] encIdentity;
        try
        {
            var blobReader = new TpmReader(action.CredentialBlob.Span);
            ushort hmacLen = blobReader.ReadUInt16();
            blobHmac = blobReader.ReadBytes(hmacLen).ToArray();
            encIdentity = blobReader.ReadBytes(blobReader.Remaining).ToArray();
        }
        catch(ArgumentOutOfRangeException)
        {
            //credentialBlob is an attacker-influenceable wire buffer; a structurally legal but too-small TPM2B
            //(a declared HMAC length exceeding the actual blob) must fail closed as TPM_RC_SIZE rather than throw
            //an out-of-range exception out of the effect executor, which the PDA runner does not catch (Part 3,
            //clause 12.5) — mirrors the ECC arm's identical guard.
            return new TpmCredentialActivated(TpmRcConstants.TPM_RC_SIZE, CertInfo: null);
        }

        using IMemoryOwner<byte> seed = pool.Rent(seedSize, AllocationKind.Pinned);
        IMemoryOwner<byte>? decoded = await backend.DecryptOaep(
            action.CredentialKeyPrivateKey.AsReadOnlyMemory(), ciphertext, CredentialIdentityLabelOctets, action.NameAlg.Value, action.NameAlg.Value, pool, cancellationToken).ConfigureAwait(false);
        if(decoded is not null && decoded.Memory.Length == seedSize)
        {
            using(decoded)
            {
                decoded.Memory.Span.CopyTo(seed.Memory.Span[..seedSize]);
            }
        }
        else
        {
            //Deferred-failure substitution (Part 1, Annex B.10.3, quoted above): a null decode result, or a
            //correctly-decoded-but-wrong-width message, both become a fresh UNPREDICTABLE seed rather than a
            //distinct rejection here — the outer HMAC check below is what reports the failure, uniformly as
            //TPM_RC_INTEGRITY. The substitute is drawn from the RNG seam, never a fixed value, so its derived
            //symKey/hmacKey are not attacker-computable and no forged blob can validate against it (see the
            //method's doc comment for the forgery-oracle this closes).
            decoded?.Dispose();
            context.Rng(seed.Memory.Span[..seedSize]);
        }

        //Recompute the outer HMAC over the ciphertext and the ACTIVATE object's Name; a mismatch is TPM_RC_INTEGRITY
        //(Part 3, clause 12.5) — the credential was bound to a different object, is corrupt, or (the RSA-specific
        //case) the OAEP decode above silently failed and substituted an invalid seed.
        using IMemoryOwner<byte> hmacKey = await Kdfa.DeriveAsync(
            hashName, seed.Memory[..seedSize], CredentialIntegrityLabel, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, seedSize * 8, pool, cancellationToken).ConfigureAwait(false);
        using(IMemoryOwner<byte> expectedHmac = await ComputeCredentialHmacAsync(
            hmacKey.Memory[..seedSize], encIdentity, action.ActivateObjectName.AsReadOnlyMemory(), action.NameAlg, pool, cancellationToken).ConfigureAwait(false))
        {
            hmacKey.Memory.Span[..seedSize].Clear();

            if(!CryptographicOperations.FixedTimeEquals(expectedHmac.Memory.Span[..seedSize], blobHmac))
            {
                seed.Memory.Span[..seedSize].Clear();

                return new TpmCredentialActivated(TpmRcConstants.TPM_RC_INTEGRITY, CertInfo: null);
            }
        }

        //Integrity verified: derive symKey from the seed and the activate object's Name, AES-CFB-decrypt
        //encIdentity, and unmarshal the recovered TPM2B_DIGEST credential — identical to the ECC arm.
        using IMemoryOwner<byte> symKey = await Kdfa.DeriveAsync(
            hashName, seed.Memory[..seedSize], CredentialStorageLabel, action.ActivateObjectName.AsReadOnlyMemory(), ReadOnlyMemory<byte>.Empty, CredentialSymmetricKeyBits, pool, cancellationToken).ConfigureAwait(false);
        seed.Memory.Span[..seedSize].Clear();

        using IMemoryOwner<byte> plaintext = pool.Rent(Math.Max(encIdentity.Length, 1), AllocationKind.Pinned);
        try
        {
            //Decrypt and read the credential synchronously (no await between the decrypt and the copy-out).
            int credLen;
            Tpm2bDigest certInfo;
            {
                byte[] zeroIv = new byte[CredentialSymmetricBlockSize];
                encIdentity.CopyTo(plaintext.Memory.Span);
                TpmParameterEncryption.AesCfb(symKey.Memory.Span[..CredentialSymmetricKeyBytes], zeroIv, plaintext.Memory.Span[..encIdentity.Length], encrypting: false);
                symKey.Memory.Span[..CredentialSymmetricKeyBytes].Clear();

                //The recovered plaintext is unmarshaled as a TPM2B_DIGEST on the reference's return contract
                //(Part 4, CredentialToSecret(), page 734: "TPM_RC_INSUFFICIENT error during credential
                //unmarshaling / TPM_RC_INTEGRITY credential integrity is broken / TPM_RC_SIZE error during
                //credential unmarshaling"). TPM_RC_INTEGRITY belongs to the outer HMAC alone, which the step
                //above already answered; only a blob that passed that HMAC reaches here, so the unmarshal's own
                //two codes separate malformed structures from one another and never report a credential's
                //binding — the integrity-before-use ordering Part 3, clause 13.3.1 states for this same
                //construction: "Checking the integrity before the data is used prevents attacks on the
                //sensitive area by fuzzing the data and looking at the differences in the response codes."
                //
                //A plaintext too narrow to supply the UINT16 size field is UINT16_Unmarshal()'s shortfall,
                //TPM_RC_INSUFFICIENT (Part 4, TPM2B_DIGEST_Unmarshal(), page 1138).
                if(encIdentity.Length < sizeof(ushort))
                {
                    return new TpmCredentialActivated(TpmRcConstants.TPM_RC_INSUFFICIENT, CertInfo: null);
                }

                var reader = new TpmReader(plaintext.Memory.Span[..encIdentity.Length]);
                credLen = reader.ReadUInt16();

                //A declared width past sizeof(TPMU_HA) is TPM2B_DIGEST_Unmarshal()'s own size refusal, taken
                //before the body is read (Part 4, page 1138: "if((result == TPM_RC_SUCCESS) && (target->t.size
                //> sizeof(TPMU_HA))) result = TPM_RC_SIZE"; Part 2, clause 10.4.2, Table 92) and BEFORE any
                //carrier is rented, so no over-bound TPM2B_DIGEST is ever framed for the host parser to refuse.
                if(credLen > Tpm2bDigest.MaxSize)
                {
                    return new TpmCredentialActivated(TpmRcConstants.TPM_RC_SIZE, CertInfo: null);
                }

                //A declared width the plaintext cannot supply is BYTE_Array_Unmarshal()'s shortfall,
                //TPM_RC_INSUFFICIENT (Part 4, page 1212: "if(*size < count) return TPM_RC_INSUFFICIENT"). The
                //recovered length is attacker-influenceable, so this gate is what keeps an out-of-range read
                //from escaping the effect executor as an exception instead of a response code.
                if(credLen > reader.Remaining)
                {
                    return new TpmCredentialActivated(TpmRcConstants.TPM_RC_INSUFFICIENT, CertInfo: null);
                }

                ReadOnlySpan<byte> credential = reader.ReadBytes(credLen);

                //Octets past the credential mean the plaintext carried more than the one TPM2B_DIGEST, which is
                //CredentialToSecret()'s closing check (Part 4, page 734: "if(result == TPM_RC_SUCCESS && size
                //!= 0) return TPM_RC_SIZE").
                if(reader.Remaining != 0)
                {
                    return new TpmCredentialActivated(TpmRcConstants.TPM_RC_SIZE, CertInfo: null);
                }

                //A zero-length credential frames an empty TPM2B_DIGEST, which is the dispose-immune shared
                //sentinel and rents nothing; any other width rents exactly its own octets, pinned, so the
                //recovered secret never moves and the carrier's size IS the wire size.
                if(credLen == 0)
                {
                    certInfo = Tpm2bDigest.Empty;
                }
                else
                {
                    IMemoryOwner<byte> certInfoStorage = pool.Rent(credLen, AllocationKind.Pinned);
                    try
                    {
                        credential.CopyTo(certInfoStorage.Memory.Span);
                        certInfo = new Tpm2bDigest(certInfoStorage);
                    }
                    catch
                    {
                        certInfoStorage.Memory.Span.Clear();
                        certInfoStorage.Dispose();
                        throw;
                    }
                }
            }

            return new TpmCredentialActivated(TpmRcConstants.TPM_RC_SUCCESS, certInfo);
        }
        finally
        {
            //plaintext held the recovered credential; zero it before returning the buffer to the pool.
            plaintext.Memory.Span[..encIdentity.Length].Clear();
        }
    }

    /// <summary>
    /// <c>TPM2_PolicyNV()</c>: marshal the NV Index's <c>TPMS_NV_PUBLIC</c> and compute its Name (nameAlg ||
    /// H_nameAlg(TPMS_NV_PUBLIC), TPM 2.0 Library Part 1, clause 14, Table 6) through the shared nameAlg-agile
    /// <see cref="TpmObjectName"/> helper and the registered asynchronous digest seam — TPM digests belong
    /// there, not the sync <c>HashFunctionDelegate</c> seam a pure transition could reach on its own.
    /// </summary>
    /// <remarks>
    /// The policyDigest fold the Name feeds runs here as well, because its destination must be rented at the
    /// policy session's own digest width; the Name itself never leaves this frame, so the continuation receives
    /// only the advanced digest. This effect is the comparison operand's terminal owner — the argHash the fold
    /// covers is its only use — so it is released on every path.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the folded policyDigest transfers to the returned TpmNvNameComputedForPolicy, whose continuation installs it on the session record; the computed Name is scoped to this frame and released here, as is the transferred comparison operand.")]
    private static async ValueTask<TpmSimulatorInput> ComputeNvNameForPolicyAsync(TpmComputeNvNameAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        try
        {
            using var nvPublic = new TpmsNvPublic(
                action.NvIndex.Value, action.NameAlg.Value, action.Attributes, Tpm2bDigest.Create(action.AuthPolicy.AsReadOnlySpan(), context.Pool), action.DataSize);
            int publicSize = nvPublic.SerializedSize;
            using IMemoryOwner<byte> marshaled = context.Pool.Rent(publicSize);
            var writer = new TpmWriter(marshaled.Memory.Span[..publicSize]);
            nvPublic.WriteTo(ref writer);

            (IMemoryOwner<byte> name, int nameLength) = await TpmObjectName.ComputeNameAsync(
                marshaled.Memory[..publicSize], (ushort)action.NameAlg.Value, context.Pool, cancellationToken).ConfigureAwait(false);

            //The Name helper rents the octets itself, so the TPM2B_NAME carrier adopts that rental rather than
            //copying it; the fold below is the Name's only use, so this frame is its terminal owner.
            using Tpm2bName nvName = Tpm2bName.FromMarshaled(name, nameLength);

            return new TpmNvNameComputedForPolicy(
                action.PolicySession,
                FoldPolicyDigest(
                    TpmPolicyDigestFold.Nv, action.PolicyHashAlgorithm, action.CurrentPolicyDigest.AsReadOnlySpan(), restrictedCommand: default,
                    TpmHandleName.FromName(nvName), policyRef: default, branches: null, pcrSelection: default, pcrDigest: default,
                    action.OperandB.Span, action.Offset, action.Operation, context.Pool));
        }
        finally
        {
            //The fold consumed the operand, so this effect is its terminal owner on every path; the empty
            //sentinel an empty operand carries is dispose-immune.
            action.OperandB.Dispose();
        }
    }

    /// <summary>
    /// <c>TPM2_NV_ReadPublic()</c>: marshal the NV Index's <c>TPMS_NV_PUBLIC</c> from its retained fields and
    /// compute its Name (nameAlg ‖ H_nameAlg(TPMS_NV_PUBLIC), TPM 2.0 Library Part 1, clause 14, Table 6) through the
    /// shared nameAlg-agile <see cref="TpmObjectName"/> helper and the registered asynchronous digest seam —
    /// the same recipe <see cref="ComputeNvNameForPolicyAsync"/> uses, now serving the command that returns the
    /// public area and Name directly rather than folding the Name into a policyDigest.
    /// </summary>
    /// <remarks>
    /// Unlike <see cref="ComputeNvNameForPolicyAsync"/>'s local <c>nvPublic</c> (marshaled and discarded within
    /// this method), the built public area here is the terminal <see cref="TpmNvReadPublicResponse"/>'s own
    /// payload, so it is NOT disposed on the success path — ownership flows onward through
    /// <see cref="TpmNvPublicNameComputed"/> to the response intent, released once framed. A failure between
    /// construction and the return still disposes it, so no failure path leaks the rented policy-digest buffer.
    /// </remarks>
    /// <param name="action">The declared action carrying the Index's retained public-area fields.</param>
    /// <param name="context">The effect context supplying the memory pool.</param>
    /// <param name="cancellationToken">A token observed across the digest computation.</param>
    /// <returns>The computed public area and Name, fed back to the framing transition.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the built public area and the computed Name buffer transfers to the returned TpmNvPublicNameComputed, then to the TpmNvReadPublicResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> ComputeNvPublicNameAsync(TpmComputeNvPublicNameAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        var nvPublic = new TpmsNvPublic(
            action.NvIndex.Value, action.NameAlg.Value, action.Attributes, Tpm2bDigest.Create(action.AuthPolicy.AsReadOnlySpan(), context.Pool), action.DataSize);
        try
        {
            int publicSize = nvPublic.SerializedSize;
            using IMemoryOwner<byte> marshaled = context.Pool.Rent(publicSize);
            var writer = new TpmWriter(marshaled.Memory.Span[..publicSize]);
            nvPublic.WriteTo(ref writer);

            (IMemoryOwner<byte> name, int nameLength) = await TpmObjectName.ComputeNameAsync(
                marshaled.Memory[..publicSize], (ushort)action.NameAlg.Value, context.Pool, cancellationToken).ConfigureAwait(false);

            return new TpmNvPublicNameComputed(nvPublic, Tpm2bName.FromMarshaled(name, nameLength));
        }
        catch
        {
            nvPublic.Dispose();
            throw;
        }
    }

    /// <summary>
    /// A session-authorized NV command's cpHash Name term: delegates to the shared NV Name recipe with the
    /// Index's own retained public-area fields, threading <see cref="TpmComputeNvIndexNameAction.Resume"/>
    /// through unchanged so <c>OnNvIndexNameComputed</c> can recover the pending session-authorized request once
    /// the Name arrives.
    /// </summary>
    /// <param name="action">The declared action carrying the Index's retained public-area fields and the request to resume.</param>
    /// <param name="context">The effect context supplying the memory pool.</param>
    /// <param name="cancellationToken">A token observed across the digest computation.</param>
    /// <returns>The computed Index Name paired with the request to resume, fed back to <c>OnNvIndexNameComputed</c>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the computed Name carrier transfers to the returned TpmNvIndexNameComputed and is released once cpHash's handle-Name area is built from it (OnNvIndexNameComputed).")]
    private static async ValueTask<TpmSimulatorInput> ComputeNvIndexNameAsync(TpmComputeNvIndexNameAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        (IMemoryOwner<byte> name, int nameLength) = await ComputeNvIndexNameAsync(
            action.NvIndex.Value, action.NameAlg, action.Attributes, action.AuthPolicy, action.DataSize, context.Pool, cancellationToken).ConfigureAwait(false);

        //The Name helper rents the octets itself, so the TPM2B_NAME carrier adopts that rental rather than copying it.
        return new TpmNvIndexNameComputed(Tpm2bName.FromMarshaled(name, nameLength), action.Resume);
    }

    /// <summary>
    /// Frames a session-authorized command's response for the NV and hierarchy families (TPM 2.0 Library Part 1,
    /// clause 16.6.1) — the generalization of <see cref="FramePolicySecretSessionResponseAsync"/>: lay out the
    /// response parameter area (empty for Write/DefineSpace/UndefineSpace/Increment and the hierarchy commands,
    /// the <c>TPM2B_MAX_NV_BUFFER</c> framing of <see cref="TpmFrameNvSessionResponseAction.ReadWindow"/> for
    /// Read), roll a fresh nonceTPM, compute rpHash over that area, then the response HMAC keyed on the SAME
    /// <c>sessionKey ‖ authValue</c> the command-HMAC
    /// verification used (clause 17.6.5).
    /// </summary>
    /// <param name="action">The declared action carrying the session's key material, nonces, attributes, and the read window the parameter area is framed from.</param>
    /// <param name="context">The effect context supplying the RNG backend and the memory pool.</param>
    /// <param name="cancellationToken">A token observed across the rpHash and HMAC computations.</param>
    /// <returns>The framed response parameter area, rolled nonceTPM, and response HMAC, fed back to <c>OnNvSessionResponseFramed</c>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parameter-area and HMAC buffers transfers to the returned TpmNvSessionResponseFramed, then to the TpmNvSessionResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> FrameNvSessionResponseAsync(TpmFrameNvSessionResponseAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        try
        {
            return await FrameNvSessionResponseCoreAsync(action, context, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            //This effect is the terminal owner of the caller nonce the accepting continuation transferred onto
            //the action: the response HMAC in the body is its last reader, and nothing downstream of this frame
            //holds it. The release wraps the whole body — the nonce roll and the hash-width lookup included —
            //so a fault anywhere between the declaration and the HMAC leaves no caller nonce outstanding.
            action.NonceCaller.Dispose();
        }
    }

    /// <summary>
    /// Frames the response parameter area, rolls the nonceTPM and computes the response HMAC for the NV and
    /// hierarchy families — the body <see cref="FrameNvSessionResponseAsync"/> wraps in the release of the
    /// caller nonce the request transferred onto the action.
    /// </summary>
    /// <param name="action">The declared action carrying the session's key material, nonces, attributes, and the read window the parameter area is framed from.</param>
    /// <param name="context">The effect context supplying the RNG backend and the memory pool.</param>
    /// <param name="cancellationToken">A token observed across the rpHash and HMAC computations.</param>
    /// <returns>The framed response parameter area, rolled nonceTPM, and response HMAC, fed back to <c>OnNvSessionResponseFramed</c>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parameter-area and HMAC buffers transfers to the returned TpmNvSessionResponseFramed, then to the TpmNvSessionResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> FrameNvSessionResponseCoreAsync(TpmFrameNvSessionResponseAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        int digestSize = SessionDigestSize(action.SessionAlg);
        (Tpm2bNonce framedNonceTpm, Tpm2bNonce retainedNonceTpm) = RollSessionNonce(action.SessionAlg, context);
        IMemoryOwner<byte>? parameterArea = null;
        Tpm2bAuth? hmac = null;
        try
        {
            //The response parameter area is laid out first, into this effect's own rental, because rpHash is
            //computed over the very octets the response frames (Part 1, clause 16.8 equation 16): a read's
            //TPM2B_MAX_NV_BUFFER window is copied out of the Index's borrowed carrier here, where a pool is in
            //scope, and every parameter-free command frames a zero-length area.
            int parameterLength = action.ReadWindow?.SerializedSize ?? 0;
            parameterArea = context.Pool.Rent(Math.Max(parameterLength, 1));
            if(action.ReadWindow is { } readWindow)
            {
                var parameterWriter = new TpmWriter(parameterArea.Memory.Span[..parameterLength]);
                parameterWriter.WriteTpm2b(readWindow.Span);
            }

            using IMemoryOwner<byte> rpHash = await ComputeSessionRpHashAsync(
                action.SessionAlg, action.CommandCode, parameterArea.Memory[..parameterLength], context.Pool, cancellationToken).ConfigureAwait(false);

            ReadOnlyMemory<byte> sessionKeyBytes = action.SessionKey.AsReadOnlyMemory();
            ReadOnlyMemory<byte> authValueBytes = TpmLifecycleTransitions.StripTrailingZeros(action.AuthValue.AsReadOnlyMemory());
            int sessionValueLength = sessionKeyBytes.Length + authValueBytes.Length;
            using IMemoryOwner<byte> sessionValueOwner = context.Pool.Rent(Math.Max(sessionValueLength, 1), AllocationKind.Pinned);
            Memory<byte> sessionValue = sessionValueOwner.Memory[..sessionValueLength];
            sessionKeyBytes.CopyTo(sessionValue);
            authValueBytes.CopyTo(sessionValue[sessionKeyBytes.Length..]);

            hmac = await ComputeResponseHmacAsync(
                action.SessionAlg, sessionValue, rpHash.Memory[..digestSize], framedNonceTpm.AsReadOnlyMemory(), action.NonceCaller.AsReadOnlyMemory(), action.SessionAttributes, context.Pool, cancellationToken).ConfigureAwait(false);

            sessionValueOwner.Memory.Span[..sessionValueLength].Clear();

            return new TpmNvSessionResponseFramed(action.SessionHandle, framedNonceTpm, retainedNonceTpm, action.SessionAttributes, TpmParameterArea.Adopt(parameterArea, parameterLength), hmac);
        }
        catch
        {
            parameterArea?.Dispose();
            hmac?.Dispose();
            retainedNonceTpm.Dispose();
            framedNonceTpm.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Frames an authValue rotation's response — <c>TPM2_NV_ChangeAuth()</c> (TPM 2.0 Library Part 3, clause
    /// 31.15) or <c>TPM2_HierarchyChangeAuth()</c> (clause 24.8), which share this shape (Part 1, clause 16.6.1):
    /// roll a fresh nonceTPM for every session in the command's authorization area and compute each session's own
    /// response HMAC over the empty response parameter area.
    /// </summary>
    /// <remarks>
    /// Neither command returns parameters, so rpHash covers an empty parameter area — but never an assumed
    /// command code: rpHash's own equation folds <c>commandCode</c> (Part 1, clause 16.8, equation 16), so the
    /// code travels on the action and a rotation framed for one command can never key its response on the other's
    /// digest. rpHash is computed once per DISTINCT session hash algorithm (clause 16.8), since the authorizing
    /// session and a decrypt companion may have been started with different <c>authHash</c> values and each
    /// verifies against its own algorithm's rpHash. The authorizing session's <c>AuthValue</c> already carries the
    /// POST-rotation value where one is required (clause 31.15.1 and clause 24.8.1), resolved by the declaring
    /// transition — this step only keys with what it is handed. A <c>TPM_RS_PW</c> slot contributes a placeholder
    /// entry instead: it has no session key to key an HMAC with and no nonceTPM to roll (clause 17.6.4.1), yet it
    /// still occupies its wire position, because a successful response carries one entry per request session in
    /// request order (clause 16.6.1).
    /// </remarks>
    /// <param name="action">The declared action carrying each session's key material, nonces, and attributes.</param>
    /// <param name="context">The effect context supplying the RNG backend and the memory pool.</param>
    /// <param name="cancellationToken">A token observed across the rpHash and HMAC computations.</param>
    /// <returns>Every session's rolled nonceTPM and response HMAC, fed back to <c>OnNvChangeAuthResponseFramed</c>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of each entry's HMAC buffer transfers to the returned TpmNvChangeAuthResponseFramed, then to the TpmNvChangeAuthResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> FrameNvChangeAuthResponseAsync(TpmFrameNvChangeAuthResponseAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        try
        {
            return await FrameNvChangeAuthResponseEntriesAsync(action, context, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            //This effect is the terminal owner of every slot's caller nonce, each transferred out of the request
            //record by the completing tail that built the entries; the response HMACs above are their last
            //readers. A TPM_RS_PW slot's placeholder entry carries the dispose-immune empty sentinel, so one
            //uniform release covers every slot of a mixed authorization area.
            foreach(TpmNvChangeAuthResponseSession session in action.ResponseSessions)
            {
                session.NonceCaller.Dispose();
            }
        }
    }

    /// <summary>
    /// Rolls each real slot's nonceTPM and computes its response HMAC for an authValue rotation — the body
    /// <see cref="FrameNvChangeAuthResponseAsync"/> wraps in the release of the caller nonces the request
    /// transferred into its response-session entries.
    /// </summary>
    /// <param name="action">The declared action carrying each session's key material, nonces, and attributes.</param>
    /// <param name="context">The effect context supplying the RNG backend and the memory pool.</param>
    /// <param name="cancellationToken">A token observed across the rpHash and HMAC computations.</param>
    /// <returns>Every session's rolled nonceTPM and response HMAC, fed back to <c>OnNvChangeAuthResponseFramed</c>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of each entry's HMAC buffer transfers to the returned TpmNvChangeAuthResponseFramed, then to the TpmNvChangeAuthResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> FrameNvChangeAuthResponseEntriesAsync(TpmFrameNvChangeAuthResponseAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        //A password slot has no session key, no hash algorithm, and no nonceTPM to roll, so the nonce roll and
        //the rpHash algorithm set are taken over the REAL slots alone; its entry is emitted straight into the
        //list at its own wire position (Part 1, clause 16.6.1's same-number-same-order rule).
        int realCount = 0;
        for(int i = 0; i < action.ResponseSessions.Length; i++)
        {
            if(!action.ResponseSessions[i].IsPasswordPlaceholder)
            {
                realCount++;
            }
        }

        var sessionAlgs = new TpmiAlgHash[realCount];
        int nonceIndex = 0;
        for(int i = 0; i < action.ResponseSessions.Length; i++)
        {
            TpmNvChangeAuthResponseSession candidate = action.ResponseSessions[i];
            if(candidate.IsPasswordPlaceholder)
            {
                continue;
            }

            sessionAlgs[nonceIndex] = candidate.SessionAlg;
            nonceIndex++;
        }

        (Tpm2bNonce[] framedNonces, Tpm2bNonce[] retainedNonces) = RollSessionNonces(sessionAlgs, context);
        try
        {
            (Memory<byte>[] rpHashPerSession, List<(TpmiAlgHash Alg, IMemoryOwner<byte> Owner)> rpHashOwners) = await ComputeRpHashPerSessionAsync(
                sessionAlgs, action.CommandCode, ReadOnlyMemory<byte>.Empty, context.Pool, cancellationToken).ConfigureAwait(false);
            try
            {
                var entries = ImmutableArray.CreateBuilder<TpmNvChangeAuthFramedSessionEntry>(action.ResponseSessions.Length);
                int realIndex = 0;
                for(int i = 0; i < action.ResponseSessions.Length; i++)
                {
                    TpmNvChangeAuthResponseSession session = action.ResponseSessions[i];
                    if(session.IsPasswordPlaceholder)
                    {
                        entries.Add(new TpmNvChangeAuthFramedSessionEntry(
                            IsPasswordPlaceholder: true, session.SessionHandle, IsPolicySession: false,
                            Tpm2bNonce.Empty, Tpm2bNonce.Empty, session.SessionAttributes, Hmac: null));

                        continue;
                    }

                    ReadOnlyMemory<byte> sessionKeyBytes = session.SessionKey.AsReadOnlyMemory();
                    ReadOnlyMemory<byte> authValueBytes = TpmLifecycleTransitions.StripTrailingZeros(session.AuthValue.AsReadOnlyMemory());
                    int sessionValueLength = sessionKeyBytes.Length + authValueBytes.Length;
                    using IMemoryOwner<byte> sessionValueOwner = context.Pool.Rent(Math.Max(sessionValueLength, 1), AllocationKind.Pinned);
                    Memory<byte> sessionValue = sessionValueOwner.Memory[..sessionValueLength];
                    sessionKeyBytes.CopyTo(sessionValue);
                    authValueBytes.CopyTo(sessionValue[sessionKeyBytes.Length..]);

                    Tpm2bAuth hmac = await ComputeResponseHmacAsync(
                        session.SessionAlg, sessionValue, rpHashPerSession[realIndex], framedNonces[realIndex].AsReadOnlyMemory(), session.NonceCaller.AsReadOnlyMemory(), session.SessionAttributes, context.Pool, cancellationToken).ConfigureAwait(false);

                    sessionValueOwner.Memory.Span[..sessionValueLength].Clear();

                    entries.Add(new TpmNvChangeAuthFramedSessionEntry(
                        IsPasswordPlaceholder: false, session.SessionHandle, session.IsPolicySession, framedNonces[realIndex], retainedNonces[realIndex], session.SessionAttributes, hmac));
                    realIndex++;
                }

                return new TpmNvChangeAuthResponseFramed(entries.MoveToImmutable());
            }
            finally
            {
                foreach(var cached in rpHashOwners)
                {
                    cached.Owner.Dispose();
                }
            }
        }
        catch
        {
            //The rolled pairs' only owner is this frame until the framed entries adopt them.
            ReleaseSessionNonces(framedNonces, retainedNonces);
            throw;
        }
    }

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented buffer transfers to the returned TpmRandomGenerated, then to the TpmRandomResponse intent, and is released by SerializeResponse after framing.")]
    private static TpmRandomGenerated GenerateRandom(TpmRngAction action, TpmActionContext context)
    {
        //A zero-length request frames an empty TPM2B_DIGEST, which is the dispose-immune shared sentinel and
        //rents nothing; any other width rents exactly its own octets so the carrier's size IS the wire size.
        if(action.ByteCount == 0)
        {
            return new TpmRandomGenerated(Tpm2bDigest.Empty);
        }

        IMemoryOwner<byte> storage = context.Pool.Rent(action.ByteCount);
        try
        {
            context.Rng(storage.Memory.Span[..action.ByteCount]);
        }
        catch
        {
            storage.Dispose();
            throw;
        }

        return new TpmRandomGenerated(new Tpm2bDigest(storage));
    }

    /// <summary>
    /// The default deterministic RNG backend: a per-instance counter stream. Reproducible across runs yet
    /// advancing across draws, so successive <c>TPM2_GetRandom()</c> calls return distinct octets. Not a real
    /// entropy source — provenance is the concern of <c>TpmEntropyProvider</c>, not the device model.
    /// </summary>
    private void FillDeterministic(Span<byte> destination)
    {
        Span<byte> block = stackalloc byte[sizeof(ulong)];
        for(int i = 0; i < destination.Length; i += sizeof(ulong))
        {
            BinaryPrimitives.WriteUInt64LittleEndian(block, RngCounter);
            RngCounter++;

            int take = Math.Min(sizeof(ulong), destination.Length - i);
            block[..take].CopyTo(destination[i..(i + take)]);
        }
    }

    /// <summary>
    /// Caller-supplied context threaded to the action executor without closure capture: the injected RNG
    /// backend, the per-call memory pool, the injected ECC and RSA signing backends (null when none was
    /// supplied), and the two hierarchy-proof seeds <see cref="SelectHierarchyProofSeed"/> chooses between.
    /// </summary>
    private readonly struct TpmActionContext(
        FillEntropyDelegate rng, BaseMemoryPool pool, TpmEccSigningBackend? signingBackend, TpmRsaSigningBackend? rsaSigningBackend,
        ReadOnlyMemory<byte> proofSeed, StorageProofSeed storageProofSeed)
    {
        /// <summary>The injected RNG backend, drawn on for <c>TPM2_GetRandom()</c>.</summary>
        public FillEntropyDelegate Rng { get; } = rng;

        /// <summary>The per-call memory pool used to rent every buffer the action executes with.</summary>
        public BaseMemoryPool Pool { get; } = pool;

        /// <summary>The injected ECC signing backend, or <see langword="null"/> when none was supplied.</summary>
        public TpmEccSigningBackend? SigningBackend { get; } = signingBackend;

        /// <summary>The injected RSA signing backend, or <see langword="null"/> when none was supplied.</summary>
        public TpmRsaSigningBackend? RsaSigningBackend { get; } = rsaSigningBackend;

        /// <summary>
        /// The construction-fixed seed the platform hierarchy's proof derives from, and the fallback for every
        /// handle that is not a storage- or endorsement-hierarchy handle.
        /// </summary>
        public ReadOnlyMemory<byte> ProofSeed { get; } = proofSeed;

        /// <summary>
        /// The seed the storage and endorsement hierarchy proofs derive from — a borrowed reference to the
        /// carrier <see cref="TpmSimulatorState.StorageProofSeed"/> owned when the command was dispatched;
        /// effects read views of it at the derivation primitive and never dispose it. The
        /// not-yet-generated sentinel until <c>TPM2_Clear()</c> draws a distinct seed, in which case
        /// <see cref="SelectHierarchyProofSeed"/> falls back to <see cref="ProofSeed"/>.
        /// </summary>
        public StorageProofSeed StorageProofSeed { get; } = storageProofSeed;
    }

    /// <summary>
    /// Bridges the runner's value-threaded step to the live automaton (one live
    /// automaton per simulated TPM holds the state of record). The runner threads back exactly the
    /// (state, step count) the previous call returned, so the live automaton and the threaded values
    /// stay in lockstep; reading the automaton here is therefore equivalent to using the arguments.
    /// </summary>
    /// <remarks>
    /// On a fault or halt, <see cref="PushdownAutomaton{TState, TInput, TStackSymbol}.CurrentState"/> is left
    /// exactly as it was before the call, including whatever <c>NextAction</c> the prior successful
    /// transition set. Returning that unchanged state to <see cref="PdaRunner.StepWithEffectsAsync"/>'s
    /// action loop — whose only exit condition is <c>NextAction</c> clearing — would make it re-dispatch the
    /// already-executed action without bound, or (on the first step of a command) let
    /// <see cref="SubmitAsync"/> re-serialize the previous command's stale response intent. Surfacing both
    /// outcomes as an exception stops the loop immediately instead.
    /// </remarks>
    /// <param name="currentState">The state threaded back from the previous step.</param>
    /// <param name="currentStepCount">The step count threaded back from the previous step.</param>
    /// <param name="input">The input to apply.</param>
    /// <param name="time">The time provider threaded by the runner; the automaton owns its own <see cref="TimeProvider"/> for trace timestamps.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The resulting (state, step count) pair.</returns>
    /// <exception cref="InvalidOperationException">
    /// The automaton's transition faulted (its <see cref="PushdownAutomaton{TState, TInput, TStackSymbol}.FaultException"/>
    /// is carried as <see cref="Exception.InnerException"/>), or halted because no transition is defined for
    /// <paramref name="input"/>.
    /// </exception>
    private async ValueTask<(TpmSimulatorState State, int StepCount)> StepCoreAsync(
        TpmSimulatorState currentState,
        int currentStepCount,
        TpmSimulatorInput input,
        TimeProvider time,
        CancellationToken cancellationToken)
    {
        bool stepped = await Automaton.StepAsync(input, cancellationToken).ConfigureAwait(false);
        if(!stepped)
        {
            throw Automaton.IsFaulted
                ? new InvalidOperationException("The TPM simulator automaton's transition faulted.", Automaton.FaultException)
                : new InvalidOperationException("The TPM simulator automaton halted: no transition is defined for the current input.");
        }

        return (Automaton.CurrentState, Automaton.StepCount);
    }

    private bool TryParseCommand(ReadOnlySpan<byte> command, BaseMemoryPool pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(command.Length < TpmHeader.HeaderSize)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_COMMAND_SIZE;

            return false;
        }

        var reader = new TpmReader(command);
        TpmHeader header = TpmHeader.Parse(ref reader);

        //The declared command size must match the octet count actually received (Part 3, 5.2).
        if(header.Size != (uint)command.Length)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_COMMAND_SIZE;

            return false;
        }

        //Only the two structurally valid command tags are accepted. A sessions-tagged command's
        //authorization area is parsed by the per-command handlers that require it (the NV commands);
        //commands that take no authorization ignore it.
        if(header.Tag != (ushort)TpmStConstants.TPM_ST_NO_SESSIONS && header.Tag != (ushort)TpmStConstants.TPM_ST_SESSIONS)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_BAD_TAG;

            return false;
        }

        var commandCode = (TpmCcConstants)header.Code;

        switch(commandCode)
        {
            case TpmCcConstants.TPM_CC_Startup:
            {
                input = new TpmStartupRequested(ReadStartupType(ref reader));

                break;
            }
            case TpmCcConstants.TPM_CC_Shutdown:
            {
                input = new TpmShutdownRequested(ReadStartupType(ref reader));

                break;
            }
            case TpmCcConstants.TPM_CC_SelfTest:
            {
                bool isFullTest = reader.Remaining >= sizeof(byte) && reader.ReadByte() != 0;
                input = new TpmSelfTestRequested(isFullTest);

                break;
            }
            case TpmCcConstants.TPM_CC_GetTestResult:
            {
                input = new TpmTestResultRequested();

                break;
            }
            case TpmCcConstants.TPM_CC_GetRandom:
            {
                //A sessions-tagged TPM2_GetRandom() carries an authorization area (the HMAC session with the
                //encrypt attribute) before its parameter; the no-sessions form is the bare command.
                if(header.Tag == (ushort)TpmStConstants.TPM_ST_SESSIONS)
                {
                    return TryParseGetRandomOverSession(ref reader, pool, out input, out malformedResponseCode);
                }

                //TPM2_GetRandom() carries a single UINT16 bytesRequested parameter (Part 3, 16.1); a
                //command whose parameter area is too short to unmarshal it is a shortfall, which the
                //TPM reports as TPM_RC_INSUFFICIENT ("not enough octets in the input buffer"), not the
                //size-value-out-of-range TPM_RC_SIZE (Part 2, Table 4).
                if(reader.Remaining < sizeof(ushort))
                {
                    malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

                    return false;
                }

                input = new TpmGetRandomRequested(reader.ReadUInt16());

                break;
            }
            case TpmCcConstants.TPM_CC_GetCapability:
            {
                //capability (UINT32) + property (UINT32) + propertyCount (UINT32) (Part 3, 30.2). A
                //parameter area too short to unmarshal these is a shortfall (TPM_RC_INSUFFICIENT).
                if(reader.Remaining < 3 * sizeof(uint))
                {
                    malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

                    return false;
                }

                var capability = (TpmCapConstants)reader.ReadUInt32();
                uint property = reader.ReadUInt32();
                uint propertyCount = reader.ReadUInt32();
                input = new TpmGetCapabilityRequested(capability, property, propertyCount);

                break;
            }
            case TpmCcConstants.TPM_CC_NV_DefineSpace:
            {
                return TryParseNvDefineSpace(ref reader, header.Tag, pool, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_NV_Read:
            {
                return TryParseNvRead(ref reader, header.Tag, pool, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_NV_Write:
            {
                return TryParseNvWrite(ref reader, header.Tag, pool, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_NV_UndefineSpace:
            {
                return TryParseNvUndefineSpace(ref reader, header.Tag, pool, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_NV_ChangeAuth:
            {
                return TryParseNvChangeAuth(ref reader, header.Tag, pool, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_NV_Increment:
            {
                return TryParseNvIncrement(ref reader, header.Tag, pool, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_NV_ReadPublic:
            {
                return TryParseNvReadPublic(ref reader, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_EvictControl:
            {
                return TryParseEvictControl(ref reader, header.Tag, pool, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_CreatePrimary:
            {
                //Without any asymmetric backend the simulated TPM does not implement key creation; answer the
                //faithful TPM_RC_COMMAND_CODE rather than entering the automaton with an effect it cannot run.
                //The template type then selects which backend is required (an RSA template needs the RSA backend).
                if(SigningBackend is null && RsaSigningBackend is null)
                {
                    malformedResponseCode = TpmRcConstants.TPM_RC_COMMAND_CODE;

                    return false;
                }

                return TryParseCreatePrimary(ref reader, header.Tag, pool, SigningBackend is not null, RsaSigningBackend is not null, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_Sign:
            {
                if(SigningBackend is null && RsaSigningBackend is null)
                {
                    malformedResponseCode = TpmRcConstants.TPM_RC_COMMAND_CODE;

                    return false;
                }

                return TryParseSign(ref reader, header.Tag, pool, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_Create:
            {
                return TryParseCreate(ref reader, header.Tag, pool, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_Load:
            {
                return TryParseLoad(ref reader, header.Tag, pool, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_Unseal:
            {
                return TryParseUnseal(ref reader, header.Tag, pool, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_Certify:
            {
                //The Certify slice signs the attestation with an ECC or RSA signing key (dispatched on the
                //resolved signer's own key type); without any asymmetric backend the simulated TPM cannot
                //honour it, so answer the faithful TPM_RC_COMMAND_CODE rather than entering an effect it
                //cannot run.
                if(SigningBackend is null && RsaSigningBackend is null)
                {
                    malformedResponseCode = TpmRcConstants.TPM_RC_COMMAND_CODE;

                    return false;
                }

                return TryParseCertify(ref reader, header.Tag, pool, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_CertifyCreation:
            {
                //The CertifyCreation slice signs the attestation with an ECC or RSA signing key exactly like
                //Certify; without any asymmetric backend the simulated TPM cannot honour it, so answer the
                //faithful TPM_RC_COMMAND_CODE rather than entering an effect it cannot run.
                if(SigningBackend is null && RsaSigningBackend is null)
                {
                    malformedResponseCode = TpmRcConstants.TPM_RC_COMMAND_CODE;

                    return false;
                }

                return TryParseCertifyCreation(ref reader, header.Tag, pool, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_GetTime:
            {
                //The GetTime slice signs the time attestation with an ECC or RSA signing key, exactly like
                //Certify; without any asymmetric backend the simulated TPM cannot honour it, so answer the
                //faithful TPM_RC_COMMAND_CODE rather than entering an effect it cannot run.
                if(SigningBackend is null && RsaSigningBackend is null)
                {
                    malformedResponseCode = TpmRcConstants.TPM_RC_COMMAND_CODE;

                    return false;
                }

                return TryParseGetTime(ref reader, header.Tag, pool, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_ReadClock:
            {
                //TPM2_ReadClock() reads durable clock state and needs no backend, no handles, and no
                //parameters at all (Part 3, clause 29.1) — mirrors TPM_CC_PCR_Read's unconditional admission.
                input = new TpmReadClockRequested();

                break;
            }
            case TpmCcConstants.TPM_CC_ClockSet:
            {
                return TryParseClockSet(ref reader, header.Tag, pool, out input, out malformedResponseCode);
            }
            case(TpmCcConstants.TPM_CC_DictionaryAttackLockReset):
            {
                return TryParseDictionaryAttackLockReset(ref reader, header.Tag, pool, out input, out malformedResponseCode);
            }
            case(TpmCcConstants.TPM_CC_DictionaryAttackParameters):
            {
                return TryParseDictionaryAttackParameters(ref reader, header.Tag, pool, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_Clear:
            {
                return TryParseClear(ref reader, header.Tag, pool, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_ClearControl:
            {
                return TryParseClearControl(ref reader, header.Tag, pool, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_HierarchyControl:
            {
                return TryParseHierarchyControl(ref reader, header.Tag, pool, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_SetPrimaryPolicy:
            {
                return TryParseSetPrimaryPolicy(ref reader, header.Tag, pool, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_HierarchyChangeAuth:
            {
                return TryParseHierarchyChangeAuth(ref reader, header.Tag, pool, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_NV_Certify:
            {
                //The NV_Certify slice signs the NV attestation with an ECC or RSA signing key, exactly like
                //Certify; without any asymmetric backend the simulated TPM cannot honour it, so answer the
                //faithful TPM_RC_COMMAND_CODE rather than entering an effect it cannot run.
                if(SigningBackend is null && RsaSigningBackend is null)
                {
                    malformedResponseCode = TpmRcConstants.TPM_RC_COMMAND_CODE;

                    return false;
                }

                return TryParseNvCertify(ref reader, header.Tag, pool, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_VerifySignature:
            {
                //TPM2_VerifySignature() signs nothing itself, but this slice's verify capability lives on the same
                //ECC/RSA signing-backend seam-bundles as the attest commands (TpmEccSigningBackend.VerifyDigest /
                //TpmRsaSigningBackend.VerifyDigest), so it is gated the identical way: without any asymmetric
                //backend the simulated TPM cannot honour it, so answer the faithful TPM_RC_COMMAND_CODE rather
                //than entering an effect it cannot run (mirrors Certify/CertifyCreation/GetTime/NV_Certify's
                //admission gate).
                if(SigningBackend is null && RsaSigningBackend is null)
                {
                    malformedResponseCode = TpmRcConstants.TPM_RC_COMMAND_CODE;

                    return false;
                }

                return TryParseVerifySignature(ref reader, header.Tag, pool, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_PCR_Read:
            {
                //TPM2_PCR_Read() reads durable PCR state and needs no backend, so it is admitted without a
                //signing backend (unlike the signing commands above).
                return TryParsePcrRead(ref reader, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_Quote:
            {
                //The Quote slice signs the attestation with an ECC or RSA signing key; without any asymmetric
                //backend the simulated TPM cannot honour it, so answer the faithful TPM_RC_COMMAND_CODE rather
                //than entering an effect it cannot run.
                if(SigningBackend is null && RsaSigningBackend is null)
                {
                    malformedResponseCode = TpmRcConstants.TPM_RC_COMMAND_CODE;

                    return false;
                }

                return TryParseQuote(ref reader, header.Tag, pool, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_StartAuthSession:
            {
                return TryParseStartAuthSession(ref reader, pool, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_PolicyCommandCode:
            {
                return TryParsePolicyCommandCode(ref reader, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_PolicyAuthValue:
            {
                return TryParsePolicyAuthValue(ref reader, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_PolicyGetDigest:
            {
                return TryParsePolicyGetDigest(ref reader, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_PolicyPCR:
            {
                return TryParsePolicyPcr(ref reader, pool, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_PolicyOR:
            {
                return TryParsePolicyOr(ref reader, pool, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_PolicySecret:
            {
                return TryParsePolicySecret(ref reader, header.Tag, pool, out input, out malformedResponseCode);
            }
            case(TpmCcConstants.TPM_CC_PolicySigned):
            {
                //TPM2_PolicySigned() validates a signature over aHash on the same ECC/RSA signing-backend
                //seam-bundles as TPM2_VerifySignature(), so it is gated identically: without any asymmetric
                //backend the simulated TPM cannot honour it.
                if(SigningBackend is null && RsaSigningBackend is null)
                {
                    malformedResponseCode = TpmRcConstants.TPM_RC_COMMAND_CODE;

                    return false;
                }

                return TryParsePolicySigned(ref reader, header.Tag, pool, out input, out malformedResponseCode);
            }
            case(TpmCcConstants.TPM_CC_PolicyAuthorize):
            {
                return TryParsePolicyAuthorize(ref reader, pool, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_PolicyTicket:
            {
                return TryParsePolicyTicket(ref reader, pool, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_PolicyNV:
            {
                return TryParsePolicyNv(ref reader, header.Tag, pool, out input, out malformedResponseCode);
            }
            case(TpmCcConstants.TPM_CC_PolicyCounterTimer):
            {
                return TryParsePolicyCounterTimer(ref reader, pool, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_MakeCredential:
            {
                //Credential protection transports the seed by ECDH (ECC) or RSA-OAEP (RSA) with the credential
                //key's public area (Part 1, clause 24; Annex B.4/B.10.3/B.10.4), so it needs an asymmetric
                //backend of the matching type — the actual RSA-vs-ECC dispatch lives one layer down in
                //OnMakeCredential (mirroring the six attest-command gates, TpmLifecycleTransitions.cs:1007);
                //without either backend the simulated TPM answers the faithful TPM_RC_COMMAND_CODE.
                if(SigningBackend is null && RsaSigningBackend is null)
                {
                    malformedResponseCode = TpmRcConstants.TPM_RC_COMMAND_CODE;

                    return false;
                }

                return TryParseMakeCredential(ref reader, header.Tag, pool, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_ActivateCredential:
            {
                if(SigningBackend is null && RsaSigningBackend is null)
                {
                    malformedResponseCode = TpmRcConstants.TPM_RC_COMMAND_CODE;

                    return false;
                }

                return TryParseActivateCredential(ref reader, header.Tag, pool, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_FlushContext:
            {
                return TryParseFlushContext(ref reader, out input, out malformedResponseCode);
            }
            default:
            {
                input = new TpmUnsupportedCommandReceived(commandCode);

                break;
            }
        }

        return true;
    }

    /// <summary>
    /// <c>TPM2_NV_DefineSpace()</c> is authorized, so its wire layout after the header is: handle area
    /// (@authHandle, 1 handle), authorization area (a single session), then parameters (auth as
    /// TPM2B_AUTH, publicInfo as TPM2B_NV_PUBLIC).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The authorization area's <c>TPMS_AUTH_COMMAND</c> wire shape is identical whether the session is
    /// <c>TPM_RS_PW</c> or an HMAC session (sessionHandle ‖ nonceCaller ‖ sessionAttributes ‖ hmac), so
    /// <c>TryReadCommandSessionSpans</c> reads it generically, mirroring <c>TryParsePolicySecret</c>: the parsed
    /// sessionHandle alone decides which record this becomes.
    /// </para>
    /// <para>
    /// Reading the area generically also means the parser no longer refuses a session handle that is neither
    /// <c>TPM_RS_PW</c> nor a loaded HMAC session. A <c>TPM_RS_PW</c> handle takes the identical
    /// parse-and-compare route it always did, so the password arm's own authorization behaviour is unchanged;
    /// what changes is the response code for a THIRD kind of handle — a loaded policy session now reaches the
    /// transition, which resolves it against the HMAC-session table alone and answers the session-index-encoded
    /// session-not-loaded code where the parser used to answer <c>TPM_RC_AUTH_TYPE</c>. A real TPM answers
    /// neither (its dispatcher resolves any loaded session before either condition could arise), so this is a
    /// recorded response-code divergence on a path no production verb composes, not a behaviour either code was
    /// ever right about.
    /// </para>
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parse-rented authValue, policy-digest, parameter-area, data-area and authorization-slot credential carriers transfers to the constructed request input, whose installing transition adopts the durable ones into state, whose continuation releases the slot credential and transfers its caller nonce into the response framing, and whose refusing arms dispose them all through the input's own Dispose; a rent that fails after an earlier carrier already succeeded releases it in the catch before rethrowing.")]
    private static bool TryParseNvDefineSpace(ref TpmReader reader, ushort tag, BaseMemoryPool pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        //An authorized command must carry an authorization area, signalled by TPM_ST_SESSIONS. A command sent
        //without one is reported here as TPM_RC_AUTH_MISSING. When such a command also has another error (for
        //example arriving before TPM2_Startup()), Part 3 clause 5.1 makes the order of error reporting
        //non-normative, so answering the missing-authorization here rather than the lifecycle error is
        //conformant; the production executor always frames a session area, so this is an off-path guard.
        if(tag != (ushort)TpmStConstants.TPM_ST_SESSIONS)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_AUTH_MISSING;

            return false;
        }

        //Handle area: @authHandle (the provisioning hierarchy).
        if(reader.Remaining < sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint authHandle = reader.ReadUInt32();

        if(!TryBeginAuthArea(ref reader, out int sessionsStart, out uint authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        if(!TryReadCommandSessionSpans(ref reader, sessionIndex: 0, out TpmiShAuthSession sessionHandle, out ReadOnlySpan<byte> nonceCaller, out TpmaSession sessionAttributes, out ReadOnlySpan<byte> hmac, out malformedResponseCode))
        {
            return false;
        }

        if(!TryEndAuthArea(ref reader, sessionsStart, authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        //NV_DefineSpace's entire parameter set (auth ‖ publicInfo) is every octet left after the authorization
        //area — captured verbatim, before any field is decoded, as the HMAC arm's cpHash parameter term (Part 1,
        //clause 16.7 equation 15); unused by the password arm.
        ReadOnlySpan<byte> rawParameterAreaOctets = reader.PeekBytes(reader.Remaining);

        //Parameter: auth (TPM2B_AUTH) — the authorization value assigned to the new Index.
        if(!TryReadTpm2bSpan(ref reader, out ReadOnlySpan<byte> indexAuth, out malformedResponseCode))
        {
            return false;
        }

        //A TPM2B_AUTH buffer can be no wider than sizeof(TPMU_HA) (TPM 2.0 Library Part 2, clause 10.4.5, Table
        //95, which types it as a TPM2B_DIGEST, and clause 10.4.2, Table 92, which bounds that structure's
        //buffer). The wire bound is answered here, ahead of the rental whose Create refuses the same bound by
        //throwing; the command's own narrower per-entity rule — no wider than the digest of the entity's nameAlg
        //(clause 10.4.5's prose) — stays where it is, on the installing transition.
        if(indexAuth.Length > Tpm2bAuth.MaxSize)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //Parameter: publicInfo (TPM2B_NV_PUBLIC) — a UINT16 size prefix wrapping the TPMS_NV_PUBLIC.
        if(reader.Remaining < sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        ushort publicSize = reader.ReadUInt16();
        if(reader.Remaining < publicSize)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        //TPMS_NV_PUBLIC: nvIndex (UINT32) + nameAlg (UINT16) + attributes (TPMA_NV) + authPolicy (TPM2B_DIGEST) + dataSize (UINT16).
        int publicStart = reader.Consumed;
        if(reader.Remaining < sizeof(uint) + sizeof(ushort) + sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint nvIndex = reader.ReadUInt32();
        TpmiAlgHash nameAlg = TpmiAlgHash.FromValue((TpmAlgIdConstants)reader.ReadUInt16());
        var attributes = (TpmaNv)reader.ReadUInt32();
        if(!TryReadTpm2bSpan(ref reader, out ReadOnlySpan<byte> authPolicy, out malformedResponseCode))
        {
            return false;
        }

        //A TPM2B_DIGEST buffer can be no wider than sizeof(TPMU_HA) (TPM 2.0 Library Part 2, clause 10.4.2,
        //Table 92), so the wire bound is answered here — ahead of the rental, whose Create refuses the same
        //bound by throwing. The defining transition's exact nameAlg-width gate stays as the fail-closed
        //backstop, so the size rule is proved at both layers.
        if(authPolicy.Length > Tpm2bDigest.MaxSize)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        if(reader.Remaining < sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        ushort dataSize = reader.ReadUInt16();

        //The declared public-area size must match the octets it actually spans (Part 3, 5.2).
        if(reader.Consumed - publicStart != publicSize)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //publicInfo is the last parameter, so no octets may follow it; a command whose declared size carries
        //surplus is malformed (Part 3, 5.2).
        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //A TPM_RS_PW session's hmac field is the plaintext supplied authValue (TryReadPasswordSessionBody's own
        //convention, mirrored here since the wire read is shared). The Index authValue, its access policy
        //digest, and the Index's data area — reserved at the declared dataSize, the space every later write
        //merges into (Part 3, clause 31.7.1) — are rented into their owned carriers only now, after every shape
        //check has passed, so no refused parse ever creates one. The area is reserved at this declared dataSize
        //here at parse, ahead of the definition transition's own gates (the attribute, type, hierarchy and
        //size-against-nameAlg refusals clause 31.3 states), so an Index the transition goes on to refuse has
        //nonetheless reserved one: every refusing arm releases it through the request's own Dispose.
        Tpm2bAuth suppliedIndexAuth = Tpm2bAuth.Empty;
        TpmParameterArea parameterArea = TpmParameterArea.Empty;
        Tpm2bDigest indexAuthPolicy = Tpm2bDigest.Empty;
        Tpm2bAuth slotCredential = Tpm2bAuth.Empty;
        Tpm2bNonce slotNonce = Tpm2bNonce.Empty;
        try
        {
            suppliedIndexAuth = Tpm2bAuth.Create(indexAuth, pool);
            if(!sessionHandle.IsPasswordSession)
            {
                parameterArea = TpmParameterArea.Create(rawParameterAreaOctets, pool);
            }

            indexAuthPolicy = Tpm2bDigest.Create(authPolicy, pool);
            slotCredential = Tpm2bAuth.Create(hmac, pool);
            slotNonce = sessionHandle.IsPasswordSession ? Tpm2bNonce.Empty : Tpm2bNonce.Create(nonceCaller, pool);

            input = sessionHandle.IsPasswordSession
                ? new TpmNvDefineSpaceRequested(TpmiRhProvision.FromValue(authHandle), slotCredential, TpmiRhNvLegacyIndex.FromValue(nvIndex), attributes, suppliedIndexAuth, dataSize, nameAlg, indexAuthPolicy, TpmNvIndexData.Allocate(dataSize, pool))
                : new TpmNvDefineSpaceOverSessionRequested(
                    TpmiRhProvision.FromValue(authHandle), sessionHandle, slotNonce, sessionAttributes, slotCredential, parameterArea, suppliedIndexAuth, TpmiRhNvLegacyIndex.FromValue(nvIndex), attributes,
                    nameAlg, indexAuthPolicy, dataSize, TpmNvIndexData.Allocate(dataSize, pool));
        }
        catch
        {
            //These carriers' only owner is this frame until the request adopts them, so a failing later rent
            //must release them or the pinned rentals are orphaned.
            slotNonce.Dispose();
            slotCredential.Dispose();
            suppliedIndexAuth.Dispose();
            parameterArea.Dispose();
            indexAuthPolicy.Dispose();
            throw;
        }

        return true;
    }

    /// <summary>
    /// <c>TPM2_NV_Read()</c> is authorized, so its wire layout after the header is: handle area (@authHandle,
    /// nvIndex — 2 handles), authorization area (a single session), then parameters (size, offset).
    /// </summary>
    /// <remarks>
    /// <c>TryReadCommandSessionSpans</c> reads the authorization area generically, exactly as
    /// <c>TryParseNvDefineSpace</c> does: the parsed sessionHandle alone decides whether this becomes
    /// <see cref="TpmNvReadRequested"/> (password) or <see cref="TpmNvReadOverSessionRequested"/> (HMAC).
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parse-rented parameter-area carrier and of the authorization slot's own two credential carriers — its caller nonce and its supplied hmac — transfers to the constructed request input; the consuming continuation releases the credential and the parameter area per carrier and transfers the nonce into the response framing, and every refusing arm releases all three through the input's own Dispose; a rent that fails after an earlier carrier already succeeded releases it in the catch before rethrowing.")]
    private static bool TryParseNvRead(ref TpmReader reader, ushort tag, BaseMemoryPool pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        //As in TryParseNvDefineSpace, an authorized command must carry an authorization area. A missing one
        //is TPM_RC_AUTH_MISSING; when the command has multiple errors the reporting order is non-normative
        //(Part 3, clause 5.1), and the production executor always frames a session area.
        if(tag != (ushort)TpmStConstants.TPM_ST_SESSIONS)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_AUTH_MISSING;

            return false;
        }

        //Handle area: @authHandle then nvIndex.
        if(reader.Remaining < 2 * sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint authHandle = reader.ReadUInt32();
        uint nvIndex = reader.ReadUInt32();

        if(!TryBeginAuthArea(ref reader, out int sessionsStart, out uint authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        if(!TryReadCommandSessionSpans(ref reader, sessionIndex: 0, out TpmiShAuthSession sessionHandle, out ReadOnlySpan<byte> nonceCaller, out TpmaSession sessionAttributes, out ReadOnlySpan<byte> hmac, out malformedResponseCode))
        {
            return false;
        }

        if(!TryEndAuthArea(ref reader, sessionsStart, authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        //NV_Read's entire parameter set (size ‖ offset) is every octet left after the authorization area —
        //captured verbatim, before either field is decoded, as the HMAC arm's cpHash parameter term.
        ReadOnlySpan<byte> rawParameterAreaOctets = reader.PeekBytes(reader.Remaining);

        //Parameters: size (UINT16) + offset (UINT16).
        if(reader.Remaining < 2 * sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        ushort size = reader.ReadUInt16();
        ushort offset = reader.ReadUInt16();

        //size and offset are the final parameters; no octets may follow them (Part 3, 5.2).
        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //The session slot's own two credentials are rented here alongside the rest, the parse's last act after
        //every wire check has passed, so no refused parse ever creates one. A TPM_RS_PW slot carries no caller
        //nonce at all (its width rule already refused a non-empty one), so only its credential is rented.
        Tpm2bAuth slotCredential = Tpm2bAuth.Empty;
        Tpm2bNonce slotNonce = Tpm2bNonce.Empty;
        TpmParameterArea parameterArea = TpmParameterArea.Empty;
        try
        {
            slotCredential = Tpm2bAuth.Create(hmac, pool);
            slotNonce = sessionHandle.IsPasswordSession ? Tpm2bNonce.Empty : Tpm2bNonce.Create(nonceCaller, pool);
            parameterArea = sessionHandle.IsPasswordSession ? TpmParameterArea.Empty : TpmParameterArea.Create(rawParameterAreaOctets, pool);

            input = sessionHandle.IsPasswordSession
                ? new TpmNvReadRequested(TpmiRhNvAuth.FromValue(authHandle), TpmiRhNvIndex.FromValue(nvIndex), slotCredential, size, offset)
                : new TpmNvReadOverSessionRequested(TpmiRhNvAuth.FromValue(authHandle), TpmiRhNvIndex.FromValue(nvIndex), sessionHandle, slotNonce, sessionAttributes, slotCredential, parameterArea, size, offset, Tpm2bName.Empty);
        }
        catch
        {
            //These carriers' only owner is this frame until the request adopts them, so a failing later rent
            //must release them or the pinned rentals are orphaned.
            parameterArea.Dispose();
            slotNonce.Dispose();
            slotCredential.Dispose();
            throw;
        }

        return true;
    }

    /// <summary>
    /// <c>TPM2_NV_Write()</c> is authorized, so its wire layout after the header is: handle area (@authHandle,
    /// nvIndex — 2 handles), authorization area (a single session), then parameters (data as
    /// TPM2B_MAX_NV_BUFFER, offset as UINT16) (Part 3, clause 31.7).
    /// </summary>
    /// <remarks>
    /// <c>TryReadCommandSessionSpans</c> reads the authorization area generically, exactly as
    /// <c>TryParseNvRead</c> does: the parsed sessionHandle alone decides whether this becomes
    /// <see cref="TpmNvWriteRequested"/> (password) or <see cref="TpmNvWriteOverSessionRequested"/> (HMAC —
    /// only the owner arm consumes the latter; the transition rejects a non-owner authHandle over a session).
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parse-rented parameter-area, data and authorization-slot credential carriers transfers to the constructed request input; the consuming transition or continuation releases them per carrier and transfers the slot's caller nonce into the response framing, and every refusing arm releases them through the input's own Dispose; a rent that fails after an earlier carrier already succeeded releases it in the catch before rethrowing.")]
    private static bool TryParseNvWrite(ref TpmReader reader, ushort tag, BaseMemoryPool pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        //As in TryParseNvRead, an authorized command must carry an authorization area. A missing one is
        //TPM_RC_AUTH_MISSING; when the command has multiple errors the reporting order is non-normative
        //(Part 3, clause 5.1), and the production executor always frames a session area.
        if(tag != (ushort)TpmStConstants.TPM_ST_SESSIONS)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_AUTH_MISSING;

            return false;
        }

        //Handle area: @authHandle then nvIndex.
        if(reader.Remaining < 2 * sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint authHandle = reader.ReadUInt32();
        uint nvIndex = reader.ReadUInt32();

        if(!TryBeginAuthArea(ref reader, out int sessionsStart, out uint authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        if(!TryReadCommandSessionSpans(ref reader, sessionIndex: 0, out TpmiShAuthSession sessionHandle, out ReadOnlySpan<byte> nonceCaller, out TpmaSession sessionAttributes, out ReadOnlySpan<byte> hmac, out malformedResponseCode))
        {
            return false;
        }

        if(!TryEndAuthArea(ref reader, sessionsStart, authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        //NV_Write's entire parameter set (data ‖ offset) is every octet left after the authorization area —
        //captured verbatim, before either field is decoded, as the HMAC arm's cpHash parameter term.
        int parameterAreaStart = reader.Consumed;
        ReadOnlySpan<byte> rawParameterAreaOctets = reader.PeekBytes(reader.Remaining);

        //Parameter: data (TPM2B_MAX_NV_BUFFER). Its extent is recorded rather than copied out: the carrier is
        //rented from these octets as the parse's last act, after every remaining shape check has passed.
        int dataOffset;
        int dataLength;
        {
            if(!TryReadTpm2bSpan(ref reader, out ReadOnlySpan<byte> dataOctets, out malformedResponseCode))
            {
                return false;
            }

            dataLength = dataOctets.Length;
            dataOffset = reader.Consumed - dataLength;
        }

        //A TPM2B_MAX_NV_BUFFER buffer can be no wider than MAX_NV_BUFFER_SIZE (TPM 2.0 Library Part 2, clause
        //10.4.9, Table 99: buffer[size]{:MAX_NV_BUFFER_SIZE}), which this library fixes at
        //Tpm2bMaxNvBuffer.MaxSize and reports through TPM_PT_NV_BUFFER_MAX. The wire bound is answered here —
        //ahead of the rental, whose Create refuses the same bound by throwing — with the marshalling refusal the
        //reference's own TPM2B_MAX_NV_BUFFER unmarshal answers, TPM_RC_SIZE, rather than any command-level code:
        //clause 31.7.1 states no size rule of its own, because a declared size past the structure's bound never
        //reaches the command body at all.
        if(dataLength > Tpm2bMaxNvBuffer.MaxSize)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //Parameter: offset (UINT16).
        if(reader.Remaining < sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        ushort offset = reader.ReadUInt16();

        //offset is the final parameter; no octets may follow it (Part 3, 5.2).
        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //The data carrier and, on the session arm, the captured parameter area are rented only now, after every
        //shape check has passed, so no refused parse ever creates one.
        ReadOnlySpan<byte> dataOctetsToStore = rawParameterAreaOctets.Slice(dataOffset - parameterAreaStart, dataLength);
        TpmParameterArea parameterArea = TpmParameterArea.Empty;
        Tpm2bAuth slotCredential = Tpm2bAuth.Empty;
        Tpm2bNonce slotNonce = Tpm2bNonce.Empty;
        try
        {
            if(!sessionHandle.IsPasswordSession)
            {
                parameterArea = TpmParameterArea.Create(rawParameterAreaOctets, pool);
            }

            slotCredential = Tpm2bAuth.Create(hmac, pool);
            slotNonce = sessionHandle.IsPasswordSession ? Tpm2bNonce.Empty : Tpm2bNonce.Create(nonceCaller, pool);

            input = sessionHandle.IsPasswordSession
                ? new TpmNvWriteRequested(TpmiRhNvAuth.FromValue(authHandle), TpmiRhNvIndex.FromValue(nvIndex), slotCredential, Tpm2bMaxNvBuffer.Create(dataOctetsToStore, pool), offset)
                : new TpmNvWriteOverSessionRequested(
                    TpmiRhNvAuth.FromValue(authHandle), TpmiRhNvIndex.FromValue(nvIndex), sessionHandle, slotNonce, sessionAttributes, slotCredential, parameterArea,
                    Tpm2bMaxNvBuffer.Create(dataOctetsToStore, pool), offset, Tpm2bName.Empty);
        }
        catch
        {
            //These carriers' only owner is this frame until the request adopts them, so a failing later rent
            //must release them or the pinned rentals are orphaned.
            slotNonce.Dispose();
            slotCredential.Dispose();
            parameterArea.Dispose();
            throw;
        }

        return true;
    }

    /// <summary>
    /// <c>TPM2_NV_UndefineSpace()</c> is authorized: handle area (@authHandle, nvIndex — 2 handles),
    /// authorization area (a single session), then no parameters (Part 3, clause 31.4).
    /// </summary>
    /// <remarks>
    /// <c>TryReadCommandSessionSpans</c> reads the authorization area generically, exactly as
    /// <c>TryParseNvWrite</c> does: the parsed sessionHandle alone decides whether this becomes
    /// <see cref="TpmNvUndefineSpaceRequested"/> (password) or <see cref="TpmNvUndefineSpaceOverSessionRequested"/> (HMAC).
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parse-rented parameter-area carrier and of the authorization slot's own two credential carriers — its caller nonce and its supplied hmac — transfers to the constructed request input; the consuming continuation releases the credential and the parameter area per carrier and transfers the nonce into the response framing, and every refusing arm releases all three through the input's own Dispose; a rent that fails after an earlier carrier already succeeded releases it in the catch before rethrowing.")]
    private static bool TryParseNvUndefineSpace(ref TpmReader reader, ushort tag, BaseMemoryPool pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(tag != (ushort)TpmStConstants.TPM_ST_SESSIONS)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_AUTH_MISSING;

            return false;
        }

        //Handle area: @authHandle then nvIndex.
        if(reader.Remaining < 2 * sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint authHandle = reader.ReadUInt32();
        uint nvIndex = reader.ReadUInt32();

        if(!TryBeginAuthArea(ref reader, out int sessionsStart, out uint authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        if(!TryReadCommandSessionSpans(ref reader, sessionIndex: 0, out TpmiShAuthSession sessionHandle, out ReadOnlySpan<byte> nonceCaller, out TpmaSession sessionAttributes, out ReadOnlySpan<byte> hmac, out malformedResponseCode))
        {
            return false;
        }

        if(!TryEndAuthArea(ref reader, sessionsStart, authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        //NV_UndefineSpace carries no parameters at all, so the raw parameter area is always empty — still
        //captured for uniformity with the other NV HMAC arms' cpHash construction.
        ReadOnlySpan<byte> rawParameterAreaOctets = reader.PeekBytes(reader.Remaining);

        //No parameters follow the authorization area; any surplus is malformed (Part 3, 5.2).
        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //The session slot's own two credentials are rented here alongside the rest, the parse's last act after
        //every wire check has passed, so no refused parse ever creates one. A TPM_RS_PW slot carries no caller
        //nonce at all (its width rule already refused a non-empty one), so only its credential is rented.
        Tpm2bAuth slotCredential = Tpm2bAuth.Empty;
        Tpm2bNonce slotNonce = Tpm2bNonce.Empty;
        TpmParameterArea parameterArea = TpmParameterArea.Empty;
        try
        {
            slotCredential = Tpm2bAuth.Create(hmac, pool);
            slotNonce = sessionHandle.IsPasswordSession ? Tpm2bNonce.Empty : Tpm2bNonce.Create(nonceCaller, pool);
            parameterArea = sessionHandle.IsPasswordSession ? TpmParameterArea.Empty : TpmParameterArea.Create(rawParameterAreaOctets, pool);

            input = sessionHandle.IsPasswordSession
                ? new TpmNvUndefineSpaceRequested(TpmiRhProvision.FromValue(authHandle), TpmiRhNvDefinedIndex.FromValue(nvIndex), slotCredential)
                : new TpmNvUndefineSpaceOverSessionRequested(TpmiRhProvision.FromValue(authHandle), TpmiRhNvDefinedIndex.FromValue(nvIndex), sessionHandle, slotNonce, sessionAttributes, slotCredential, parameterArea, Tpm2bName.Empty);
        }
        catch
        {
            //These carriers' only owner is this frame until the request adopts them, so a failing later rent
            //must release them or the pinned rentals are orphaned.
            parameterArea.Dispose();
            slotNonce.Dispose();
            slotCredential.Dispose();
            throw;
        }

        return true;
    }

    /// <summary>
    /// <c>TPM2_NV_ChangeAuth()</c> is authorized: handle area (<c>@nvIndex</c> — a SINGLE handle, unlike every
    /// other authorized NV command in this parser), authorization area (one or two sessions), then the sole
    /// parameter <c>newAuth</c> as a <c>TPM2B_AUTH</c> (Part 3, clause 31.15, Table 252).
    /// </summary>
    /// <remarks>
    /// <para>
    /// One handle because the entity being administered is also the entity authorizing: Table 252 lists
    /// <c>@nvIndex</c> alone, with Auth Index 1 and Auth Role ADMIN. There is no <c>authHandle</c> hierarchy
    /// arm — an owner-authorized rotation is not a shape this command has.
    /// </para>
    /// <para>
    /// The authorization area is read generically with <c>TryReadCommandSessionSpans</c>, as every other NV arm
    /// reads it: a <c>TPMS_AUTH_COMMAND</c>'s wire layout does not depend on the session's kind, so the parser
    /// records what arrived and the transition decides whether it can authorize (only a policy session can). A
    /// second session, when the declared authorizationSize accounts for one, is the separate <c>decrypt</c>
    /// companion that protects <c>newAuth</c> in flight — the same two-session shape <c>TryParseCreate</c> reads.
    /// </para>
    /// <para>
    /// The handle's own out-of-range case is <c>TPM_RC_VALUE</c> — the unmarshal-time interface check
    /// <c>TPMI_RH_NV_INDEX</c> carries (Part 2, Table 72) — distinct from the in-range-but-undefined case, which
    /// the transition answers with <c>TPM_RC_HANDLE</c> (Part 3, clause 5.4). <c>newAuth</c> is captured as
    /// received, ciphertext included when a decrypt session is present: its 2-octet size prefix is never itself
    /// encrypted (Part 1, clause 19.1), so the field can be delimited before anything is decrypted.
    /// </para>
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parse-rented authValue, parameter-area and per-slot credential carriers transfers to the constructed request input, whose installing transition adopts the authValue into durable state, whose completing tail releases both slots' credentials and transfers each slot's caller nonce into that slot's response entry, and whose refusing arms dispose them all through the input's own Dispose; a rent that fails after an earlier carrier already succeeded releases it in the catch before rethrowing.")]
    private static bool TryParseNvChangeAuth(ref TpmReader reader, ushort tag, BaseMemoryPool pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(tag != (ushort)TpmStConstants.TPM_ST_SESSIONS)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_AUTH_MISSING;

            return false;
        }

        //Handle area: nvIndex, the command's only handle.
        if(reader.Remaining < sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint nvIndex = reader.ReadUInt32();
        if((byte)(nvIndex >> 24) != (byte)TpmHt.TPM_HT_NV_INDEX)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_VALUE;

            return false;
        }

        if(!TryBeginAuthArea(ref reader, out int sessionsStart, out uint authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        if(!TryReadCommandSessionSpans(ref reader, sessionIndex: 0, out TpmiShAuthSession sessionHandle, out ReadOnlySpan<byte> nonceCaller, out TpmaSession sessionAttributes, out ReadOnlySpan<byte> hmac, out malformedResponseCode))
        {
            return false;
        }

        TpmiShAuthSession decryptHandle = TpmiShAuthSession.FromValue(0);
        TpmaSession decryptAttributes = default;

        //The companion slot's span locals are declared scoped so they can receive slices that alias the command
        //buffer the by-reference reader points into: without it the compiler must assume a span written through
        //an out parameter of a ref-taking method could outlive that buffer.
        scoped ReadOnlySpan<byte> decryptNonceCaller = ReadOnlySpan<byte>.Empty;
        scoped ReadOnlySpan<byte> decryptHmac = ReadOnlySpan<byte>.Empty;

        bool isSingleSession = reader.Consumed - sessionsStart == (int)authorizationSize;
        if(!isSingleSession)
        {
            if(!TryReadCommandSessionSpans(ref reader, sessionIndex: 1, out decryptHandle, out decryptNonceCaller, out decryptAttributes, out decryptHmac, out malformedResponseCode))
            {
                return false;
            }
        }

        if(!TryEndAuthArea(ref reader, sessionsStart, authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        //newAuth is the entire parameter area, captured verbatim before it is decoded as cpHash's parameter term
        //(Part 1, clause 16.7 equation 15). The capture is an exclusive copy, which is what lets the decrypt
        //effect transform it in place.
        ReadOnlySpan<byte> rawParameterAreaOctets = reader.PeekBytes(reader.Remaining);

        if(!TryReadTpm2bSpan(ref reader, out ReadOnlySpan<byte> newAuth, out malformedResponseCode))
        {
            return false;
        }

        //A TPM2B_AUTH buffer can be no wider than sizeof(TPMU_HA) (TPM 2.0 Library Part 2, clause 10.4.5, Table
        //95, which types it as a TPM2B_DIGEST, and clause 10.4.2, Table 92, which bounds that structure's
        //buffer). The wire bound is answered here, ahead of the rental whose Create refuses the same bound by
        //throwing; the command's own narrower per-entity rule — no wider than the digest of the entity's nameAlg
        //(clause 10.4.5's prose) — stays where it is, on the installing transition.
        if(newAuth.Length > Tpm2bAuth.MaxSize)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //newAuth is the last parameter, so no octets may follow it (Part 3, clause 5.2).
        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //The parameter area and the replacement authValue are rented into their owned carriers only now, after
        //every shape check has passed, so no refused parse ever creates one; when a decrypt session accompanied
        //the command both carriers hold ciphertext, the authValue's being superseded by the decrypt effect's own
        //output while the parameter area is transformed in place.
        TpmParameterArea parameterArea = TpmParameterArea.Empty;
        Tpm2bAuth slotCredential = Tpm2bAuth.Empty;
        Tpm2bNonce slotNonce = Tpm2bNonce.Empty;
        Tpm2bAuth decryptCredential = Tpm2bAuth.Empty;
        Tpm2bNonce decryptNonce = Tpm2bNonce.Empty;
        try
        {
            parameterArea = TpmParameterArea.Create(rawParameterAreaOctets, pool);
            slotCredential = Tpm2bAuth.Create(hmac, pool);
            slotNonce = Tpm2bNonce.Create(nonceCaller, pool);
            decryptCredential = isSingleSession ? Tpm2bAuth.Empty : Tpm2bAuth.Create(decryptHmac, pool);
            decryptNonce = isSingleSession ? Tpm2bNonce.Empty : Tpm2bNonce.Create(decryptNonceCaller, pool);

            input = new TpmNvChangeAuthOverSessionRequested(
                TpmiRhNvIndex.FromValue(nvIndex), sessionHandle, slotNonce, sessionAttributes, slotCredential,
                !isSingleSession, decryptHandle, decryptNonce, decryptAttributes, decryptCredential,
                parameterArea, Tpm2bAuth.Create(newAuth, pool), Tpm2bName.Empty);
        }
        catch
        {
            //These carriers' only owner is this frame until the request adopts them, so a failing later rent
            //must release them or the pinned rentals are orphaned.
            decryptNonce.Dispose();
            decryptCredential.Dispose();
            slotNonce.Dispose();
            slotCredential.Dispose();
            parameterArea.Dispose();
            throw;
        }

        return true;
    }

    /// <summary>
    /// <c>TPM2_NV_ReadPublic()</c> requires no authorization (<c>Auth Index: None</c>, Part 3, clause 31.6):
    /// handle area (nvIndex, 1 handle), no authorization area, no parameters.
    /// </summary>
    /// <remarks>
    /// Modelled on <c>TryReadPolicySessionOnly</c>'s shape (a single handle, confirm nothing follows) rather
    /// than any of the password-authorized NV parse arms above, since this command never reads an
    /// authorization area at all. The handle's own out-of-range case is <c>TPM_RC_VALUE</c> — unmarshal-time,
    /// <c>TPMI_RH_NV_INDEX</c>'s own interface-type check (Part 2, Table 72: "TPM_RC_VALUE error returned if
    /// the handle is out of range") — distinct from the in-range-but-undefined case, which is
    /// <c>TPM_RC_HANDLE</c> at the transition (clause 5.4). The wire tag is <c>TPM_ST_SESSIONS</c> only "if an
    /// audit or encrypt session is present" (Table 234) — this simulator does not yet implement an encrypt
    /// session on <c>nvPublic</c> (the reference command-attribute table marks it ENCRYPT_2-eligible, tracked,
    /// not implemented), so any session-tagged request leaves unparsed trailing octets and fails closed with
    /// <c>TPM_RC_SIZE</c> below rather than silently accepting-but-not-encrypting.
    /// </remarks>
    private static bool TryParseNvReadPublic(ref TpmReader reader, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(reader.Remaining < sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint nvIndex = reader.ReadUInt32();
        if((byte)(nvIndex >> 24) != (byte)TpmHt.TPM_HT_NV_INDEX)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_VALUE;

            return false;
        }

        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        input = new TpmNvReadPublicRequested(TpmiRhNvIndex.FromValue(nvIndex));

        return true;
    }

    /// <summary>
    /// <c>TPM2_NV_Increment()</c> is authorized, so its wire layout after the header is: handle area
    /// (@authHandle, nvIndex — 2 handles), authorization area (a single session), then no parameters
    /// (Part 3, clause 31.8).
    /// </summary>
    /// <remarks>
    /// <c>TryReadCommandSessionSpans</c> reads the authorization area generically, exactly as
    /// <c>TryParseNvUndefineSpace</c> does: the parsed sessionHandle alone decides whether this becomes
    /// <see cref="TpmNvIncrementRequested"/> (password) or <see cref="TpmNvIncrementOverSessionRequested"/>
    /// (HMAC). Both forms carry the identical two handles and the identical empty parameter area — a
    /// <c>TPMS_AUTH_COMMAND</c>'s wire layout does not depend on the session's kind, so the parser records what
    /// arrived and the transition decides which entity the session may authorize.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parse-rented parameter-area carrier and of the authorization slot's own two credential carriers — its caller nonce and its supplied hmac — transfers to the constructed request input; the consuming continuation releases the credential and the parameter area per carrier and transfers the nonce into the response framing, and every refusing arm releases all three through the input's own Dispose; a rent that fails after an earlier carrier already succeeded releases it in the catch before rethrowing.")]
    private static bool TryParseNvIncrement(ref TpmReader reader, ushort tag, BaseMemoryPool pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        //As in TryParseNvWrite, an authorized command must carry an authorization area. A missing one is
        //TPM_RC_AUTH_MISSING; when the command has multiple errors the reporting order is non-normative
        //(Part 3, clause 5.1), and the production executor always frames a session area.
        if(tag != (ushort)TpmStConstants.TPM_ST_SESSIONS)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_AUTH_MISSING;

            return false;
        }

        //Handle area: @authHandle then nvIndex.
        if(reader.Remaining < 2 * sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint authHandle = reader.ReadUInt32();
        uint nvIndex = reader.ReadUInt32();

        if(!TryBeginAuthArea(ref reader, out int sessionsStart, out uint authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        if(!TryReadCommandSessionSpans(ref reader, sessionIndex: 0, out TpmiShAuthSession sessionHandle, out ReadOnlySpan<byte> nonceCaller, out TpmaSession sessionAttributes, out ReadOnlySpan<byte> hmac, out malformedResponseCode))
        {
            return false;
        }

        if(!TryEndAuthArea(ref reader, sessionsStart, authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        //NV_Increment carries no parameters at all, so the raw parameter area is always empty — still captured
        //for uniformity with the other NV HMAC arms' cpHash construction (Part 1, clause 16.7 equation 15).
        ReadOnlySpan<byte> rawParameterAreaOctets = reader.PeekBytes(reader.Remaining);

        //No parameters follow the authorization area; any surplus is malformed (Part 3, 5.2).
        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //The session slot's own two credentials are rented here alongside the rest, the parse's last act after
        //every wire check has passed, so no refused parse ever creates one. A TPM_RS_PW slot carries no caller
        //nonce at all (its width rule already refused a non-empty one), so only its credential is rented.
        Tpm2bAuth slotCredential = Tpm2bAuth.Empty;
        Tpm2bNonce slotNonce = Tpm2bNonce.Empty;
        TpmParameterArea parameterArea = TpmParameterArea.Empty;
        try
        {
            slotCredential = Tpm2bAuth.Create(hmac, pool);
            slotNonce = sessionHandle.IsPasswordSession ? Tpm2bNonce.Empty : Tpm2bNonce.Create(nonceCaller, pool);
            parameterArea = sessionHandle.IsPasswordSession ? TpmParameterArea.Empty : TpmParameterArea.Create(rawParameterAreaOctets, pool);

            input = sessionHandle.IsPasswordSession
                ? new TpmNvIncrementRequested(TpmiRhNvAuth.FromValue(authHandle), TpmiRhNvIndex.FromValue(nvIndex), slotCredential)
                : new TpmNvIncrementOverSessionRequested(TpmiRhNvAuth.FromValue(authHandle), TpmiRhNvIndex.FromValue(nvIndex), sessionHandle, slotNonce, sessionAttributes, slotCredential, parameterArea, Tpm2bName.Empty);
        }
        catch
        {
            //These carriers' only owner is this frame until the request adopts them, so a failing later rent
            //must release them or the pinned rentals are orphaned.
            parameterArea.Dispose();
            slotNonce.Dispose();
            slotCredential.Dispose();
            throw;
        }

        return true;
    }

    /// <summary>
    /// <c>TPM2_EvictControl()</c> is authorized: handle area (@auth, objectHandle — 2 handles), authorization
    /// area (a single password session), then the parameter persistentHandle (TPMI_DH_PERSISTENT) (Part 3,
    /// clause 28.5).
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parse-rented hierarchy-password carrier transfers to the constructed request input, whose consuming transition releases it once the hierarchy compare has consumed it, and whose refusing arms dispose it through the input's own Dispose.")]
    private static bool TryParseEvictControl(ref TpmReader reader, ushort tag, BaseMemoryPool pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(tag != (ushort)TpmStConstants.TPM_ST_SESSIONS)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_AUTH_MISSING;

            return false;
        }

        //Handle area: @auth then objectHandle.
        if(reader.Remaining < 2 * sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint authHandle = reader.ReadUInt32();
        uint objectHandle = reader.ReadUInt32();

        if(!TryReadPasswordAuthArea(ref reader, out ReadOnlySpan<byte> suppliedAuth, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: persistentHandle (TPMI_DH_PERSISTENT).
        if(reader.Remaining < sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint persistentHandle = reader.ReadUInt32();

        //persistentHandle is the final parameter; no octets may follow it (Part 3, 5.2).
        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //The request, with its owned password carrier, is constructed as the parse's last act, so no refused
        //parse ever creates one.
        input = new TpmEvictControlRequested(TpmiRhProvision.FromValue(authHandle), Tpm2bAuth.Create(suppliedAuth, pool), TpmiDhObject.FromValue(objectHandle), TpmiDhPersistent.FromValue(persistentHandle));

        return true;
    }

    /// <summary>
    /// <c>TPM2_CreatePrimary()</c> is authorized, so its wire layout after the header is: handle area
    /// (@primaryHandle, 1 handle), authorization area (a single password session), then parameters (inSensitive
    /// as TPM2B_SENSITIVE_CREATE, inPublic as TPM2B_PUBLIC, outsideInfo as TPM2B_DATA, creationPCR as
    /// TPML_PCR_SELECTION).
    /// </summary>
    /// <remarks>
    /// The Name algorithm, object attributes, and per-algorithm key parameters are read from the ECC or RSA
    /// signing template; the sensitive area's userAuth is read into an owned pooled carrier, while its
    /// sealed-data half, outsideInfo, and the PCR selection are consumed for framing but not modelled.
    /// <paramref name="eccSupported"/>/<paramref name="rsaSupported"/> say which backends are wired,
    /// so a template whose algorithm has no backend is answered <c>TPM_RC_COMMAND_CODE</c> rather than entering
    /// an effect the TPM cannot run.
    /// </remarks>
    private static bool TryParseCreatePrimary(ref TpmReader reader, ushort tag, BaseMemoryPool pool, bool eccSupported, bool rsaSupported, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        //An authorized command must carry an authorization area; a missing one is TPM_RC_AUTH_MISSING, as in
        //the NV commands. The production executor always frames a session area, so this is an off-path guard.
        if(tag != (ushort)TpmStConstants.TPM_ST_SESSIONS)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_AUTH_MISSING;

            return false;
        }

        //Handle area: @primaryHandle (the hierarchy).
        if(reader.Remaining < sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint hierarchy = reader.ReadUInt32();

        if(!TryReadPasswordAuthArea(ref reader, out ReadOnlySpan<byte> suppliedAuth, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: inSensitive (TPM2B_SENSITIVE_CREATE) — the new object's userAuth; the sealed data half is
        //not modelled for a created key. The parsed carriers stay alive (and are released by the using) until
        //every remaining shape check has passed, so the request's owned userAuth carrier is rented only for a
        //fully-validated frame — no refused parse ever creates one.
        if(reader.Remaining < sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        Tpm2bSensitiveCreate parsedSensitive;
        try
        {
            parsedSensitive = Tpm2bSensitiveCreate.Parse(ref reader, pool);
        }
        catch(InvalidOperationException)
        {
            //TPMS_SENSITIVE_CREATE.userAuth is a TPM2B_AUTH, bounded by sizeof(TPMU_HA) (TPM 2.0 Library Part 2,
            //clause 10.4.5, Table 95 over clause 10.4.2, Table 92), so a wider declared size is TPM_RC_SIZE. The
            //structure parser's only refusal channel is the throw, and an unmarshaling error means no command
            //processing occurs (Part 3, clause 5.8.2), so nothing may escape this frame.
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        using(Tpm2bSensitiveCreate inSensitive = parsedSensitive)
        {
            //Parameter: inPublic (TPM2B_PUBLIC) — the ECC or RSA signing template.
            if(reader.Remaining < sizeof(ushort))
            {
                malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

                return false;
            }

            Tpm2bPublic inPublic;
            try
            {
                inPublic = Tpm2bPublic.Parse(ref reader, pool);
            }
            catch(InvalidOperationException)
            {
                //A TPM2B_DIGEST is bounded by sizeof(TPMU_HA) (TPM 2.0 Library Part 2, clause 10.4.2, Table 92)
                //and the template's authPolicy is one, so a wider declared size is TPM_RC_SIZE. The parse is what
                //answers it: the structure parser's only refusal channel is the throw, and an unmarshaling error
                //means no command processing occurs (Part 3, clause 5.8.2), so nothing may escape this frame.
                malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

                return false;
            }

            using(inPublic)
            {
                //Parameter: outsideInfo (TPM2B_DATA) — included in creation data; not modelled. The trailing
                //parameters are skipped before the template is judged: the reference emits this command's
                //template refusals (TPM_RC_SCHEME) from the command action, strictly after every parameter has
                //unmarshaled, and an unmarshaling error means no command processing occurs (Part 3, clause
                //5.8.2) — so a truncated tail answers before an unmodelled template does. The order also lets
                //the request, with its owned userAuth carrier, be constructed as the parse's last act.
                if(!TrySkipTpm2b(ref reader, out malformedResponseCode))
                {
                    return false;
                }

                //Parameter: creationPCR (TPML_PCR_SELECTION) — a UINT32 count then that many selections, skipped.
                if(!TrySkipPcrSelection(ref reader, out malformedResponseCode))
                {
                    return false;
                }

                return TryBuildCreatePrimaryRequest(inPublic.PublicArea, hierarchy, suppliedAuth, inSensitive.Sensitive.UserAuth.AsReadOnlySpan(), pool, eccSupported, rsaSupported, out input, out malformedResponseCode);
            }
        }
    }

    /// <summary>
    /// Turns a parsed inPublic template into the matching create-primary request, or a response code when the
    /// template is unmodelled or its algorithm has no wired backend.
    /// </summary>
    /// <remarks>
    /// An ECC signing template (ECDSA over an ECC key) and an RSA signing template are modelled; the RSA scheme
    /// is carried as-is, so an unrestricted (NULL) scheme is preserved and the signing scheme is chosen per
    /// <c>TPM2_Sign()</c>. The supplied hierarchy password, the template's policy digest, and userAuth are
    /// rented into the request's own carriers at each construction, after the branch's own backend gate — a
    /// refusing branch creates no carrier, and a rent that fails after an earlier one already succeeded releases
    /// it before rethrowing so the pinned rentals are never orphaned.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parse-rented hierarchy-password, policy-digest, and userAuth carriers transfers to the constructed request input: the consuming transition releases the hierarchy password itself once the hierarchy compare has consumed it and threads the policy digest and userAuth into the create action for the effect to install on the durable key state, and the refusing arms dispose all three through the input's own Dispose.")]
    private static bool TryBuildCreatePrimaryRequest(TpmtPublic publicArea, uint hierarchy, ReadOnlySpan<byte> hierarchyPassword, ReadOnlySpan<byte> userAuth, BaseMemoryPool pool, bool eccSupported, bool rsaSupported, [NotNullWhen(true)] out TpmSimulatorInput? request, out TpmRcConstants malformedResponseCode)
    {
        request = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        //Retained so the created object's exported public area — and therefore its Name — carries the template's
        //authPolicy (empty for every template except a standard endorsement key's "PolicyA"), mirroring how
        //TryParseCreate retains TpmCreateSealedObjectRequested.AuthPolicy for the sealed-data path. The scoped
        //public area the caller still holds owns these octets, so the branch that builds a request copies them
        //into a carrier of its own and a refusing branch rents nothing.
        ReadOnlySpan<byte> authPolicy = publicArea.AuthPolicy.AsReadOnlySpan();

        if(publicArea.Type == TpmAlgIdConstants.TPM_ALG_ECC
            && publicArea.Parameters.EccDetail is TpmsEccParms eccParms
            && eccParms.Scheme.Scheme == TpmAlgIdConstants.TPM_ALG_ECDSA)
        {
            //The template is well-formed; without an ECC backend the TPM cannot honour it.
            if(!eccSupported)
            {
                malformedResponseCode = TpmRcConstants.TPM_RC_COMMAND_CODE;

                return false;
            }

            Tpm2bAuth suppliedPassword = Tpm2bAuth.Empty;
            Tpm2bDigest templatePolicy = Tpm2bDigest.Empty;
            try
            {
                suppliedPassword = Tpm2bAuth.Create(hierarchyPassword, pool);
                templatePolicy = Tpm2bDigest.Create(authPolicy, pool);
                request = new TpmCreatePrimaryRequested(TpmiRhHierarchy.FromValue(hierarchy), suppliedPassword, TpmiAlgHash.FromValue(publicArea.NameAlg), publicArea.ObjectAttributes, TpmiEccCurve.FromValue(eccParms.CurveId), TpmiAlgHash.FromValue(eccParms.Scheme.HashAlg), templatePolicy, Tpm2bAuth.Create(userAuth, pool));
            }
            catch
            {
                //These carriers' only owner is this frame until the request adopts them, so a failing later
                //rent must release them or the pinned rentals are orphaned.
                templatePolicy.Dispose();
                suppliedPassword.Dispose();
                throw;
            }

            return true;
        }

        //An ECC restricted storage key (RESTRICTED and DECRYPT set, null scheme): the parent of TPM2_Create().
        //The simulator provisions it as a handle-bearing storage object; it uses the same ECC-engine gate as a
        //signing key (a real TPM needs its ECC engine to make any ECC primary).
        if(publicArea.Type == TpmAlgIdConstants.TPM_ALG_ECC
            && publicArea.Parameters.EccDetail is TpmsEccParms storageParms
            && storageParms.Scheme.Scheme == TpmAlgIdConstants.TPM_ALG_NULL
            && (publicArea.ObjectAttributes & (TpmaObject.RESTRICTED | TpmaObject.DECRYPT)) == (TpmaObject.RESTRICTED | TpmaObject.DECRYPT))
        {
            if(!eccSupported)
            {
                malformedResponseCode = TpmRcConstants.TPM_RC_COMMAND_CODE;

                return false;
            }

            bool noDa = (publicArea.ObjectAttributes & TpmaObject.NO_DA) != 0;
            Tpm2bAuth suppliedPassword = Tpm2bAuth.Empty;
            Tpm2bDigest templatePolicy = Tpm2bDigest.Empty;
            try
            {
                suppliedPassword = Tpm2bAuth.Create(hierarchyPassword, pool);
                templatePolicy = Tpm2bDigest.Create(authPolicy, pool);
                request = new TpmCreateStorageParentRequested(TpmiRhHierarchy.FromValue(hierarchy), suppliedPassword, TpmiAlgHash.FromValue(publicArea.NameAlg), publicArea.ObjectAttributes, TpmiEccCurve.FromValue(storageParms.CurveId), noDa, templatePolicy, Tpm2bAuth.Create(userAuth, pool));
            }
            catch
            {
                //These carriers' only owner is this frame until the request adopts them, so a failing later
                //rent must release them or the pinned rentals are orphaned.
                templatePolicy.Dispose();
                suppliedPassword.Dispose();
                throw;
            }

            return true;
        }

        //An RSA restricted storage key (RESTRICTED and DECRYPT set): the RSA counterpart of the ECC storage-parent
        //branch above, including the standard RSA endorsement key (TCG EK Credential Profile, Annex B.3.3,
        //Template L-1). Checked before the general RSA (signing) branch below, mirroring the ECC split's order.
        if(publicArea.Type == TpmAlgIdConstants.TPM_ALG_RSA
            && publicArea.Parameters.RsaDetail is TpmsRsaParms rsaStorageParms
            && (publicArea.ObjectAttributes & (TpmaObject.RESTRICTED | TpmaObject.DECRYPT)) == (TpmaObject.RESTRICTED | TpmaObject.DECRYPT))
        {
            if(!rsaSupported)
            {
                malformedResponseCode = TpmRcConstants.TPM_RC_COMMAND_CODE;

                return false;
            }

            bool noDa = (publicArea.ObjectAttributes & TpmaObject.NO_DA) != 0;
            Tpm2bAuth suppliedPassword = Tpm2bAuth.Empty;
            Tpm2bDigest templatePolicy = Tpm2bDigest.Empty;
            try
            {
                suppliedPassword = Tpm2bAuth.Create(hierarchyPassword, pool);
                templatePolicy = Tpm2bDigest.Create(authPolicy, pool);
                request = new TpmCreateRsaStorageParentRequested(TpmiRhHierarchy.FromValue(hierarchy), suppliedPassword, TpmiAlgHash.FromValue(publicArea.NameAlg), publicArea.ObjectAttributes, TpmiRsaKeyBits.FromValue(rsaStorageParms.KeyBits), noDa, templatePolicy, Tpm2bAuth.Create(userAuth, pool));
            }
            catch
            {
                //These carriers' only owner is this frame until the request adopts them, so a failing later
                //rent must release them or the pinned rentals are orphaned.
                templatePolicy.Dispose();
                suppliedPassword.Dispose();
                throw;
            }

            return true;
        }

        if(publicArea.Type == TpmAlgIdConstants.TPM_ALG_RSA
            && publicArea.Parameters.RsaDetail is TpmsRsaParms rsaParms)
        {
            if(!rsaSupported)
            {
                malformedResponseCode = TpmRcConstants.TPM_RC_COMMAND_CODE;

                return false;
            }

            Tpm2bAuth suppliedPassword = Tpm2bAuth.Empty;
            Tpm2bDigest templatePolicy = Tpm2bDigest.Empty;
            try
            {
                suppliedPassword = Tpm2bAuth.Create(hierarchyPassword, pool);
                templatePolicy = Tpm2bDigest.Create(authPolicy, pool);
                request = new TpmCreateRsaPrimaryRequested(TpmiRhHierarchy.FromValue(hierarchy), suppliedPassword, TpmiAlgHash.FromValue(publicArea.NameAlg), publicArea.ObjectAttributes, TpmiRsaKeyBits.FromValue(rsaParms.KeyBits), rsaParms.Scheme, templatePolicy, Tpm2bAuth.Create(userAuth, pool));
            }
            catch
            {
                //These carriers' only owner is this frame until the request adopts them, so a failing later
                //rent must release them or the pinned rentals are orphaned.
                templatePolicy.Dispose();
                suppliedPassword.Dispose();
                throw;
            }

            return true;
        }

        //A non-signing or otherwise unmodelled template.
        malformedResponseCode = TpmRcConstants.TPM_RC_SCHEME;

        return false;
    }

    /// <summary>
    /// <c>TPM2_Sign()</c> is authorized, so its wire layout after the header is: handle area (@keyHandle, 1
    /// handle), authorization area (a single password session), then parameters (digest as TPM2B_DIGEST,
    /// inScheme as TPMT_SIG_SCHEME, validation as TPMT_TK_HASHCHECK).
    /// </summary>
    /// <remarks>
    /// The validation ticket is consumed but not checked: this slice signs an externally-computed digest, which
    /// a genuine TPM authorizes with a NULL ticket.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parse-rented key-password carrier transfers to the constructed request input, whose consuming transition releases it once the key-slot compare has consumed it, and whose refusing arms dispose it through the input's own Dispose.")]
    private static bool TryParseSign(ref TpmReader reader, ushort tag, BaseMemoryPool pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(tag != (ushort)TpmStConstants.TPM_ST_SESSIONS)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_AUTH_MISSING;

            return false;
        }

        //Handle area: @keyHandle (the signing key).
        if(reader.Remaining < sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint keyHandle = reader.ReadUInt32();

        if(!TryReadPasswordAuthArea(ref reader, out ReadOnlySpan<byte> suppliedAuth, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: digest (TPM2B_DIGEST) — the externally-computed digest, copied into durable model memory.
        if(!TryReadTpm2bSpan(ref reader, out ReadOnlySpan<byte> digest, out malformedResponseCode))
        {
            return false;
        }

        //A TPM2B_DIGEST buffer can be no wider than sizeof(TPMU_HA) (TPM 2.0 Library Part 2, clause 10.4.2,
        //Table 92), so the wire bound is answered here, ahead of the rental whose Create refuses the same bound
        //by throwing.
        if(digest.Length > Tpm2bDigest.MaxSize)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //Parameter: inScheme (TPMT_SIG_SCHEME) — scheme selector (UINT16) + hash algorithm (UINT16).
        if(reader.Remaining < 2 * sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        TpmiAlgSigScheme signatureScheme = TpmiAlgSigScheme.FromValue((TpmAlgIdConstants)reader.ReadUInt16());
        TpmiAlgHash schemeHashAlg = TpmiAlgHash.FromValue((TpmAlgIdConstants)reader.ReadUInt16());

        //Parameter: validation (TPMT_TK_HASHCHECK) — tag (UINT16) + hierarchy (UINT32) + digest (TPM2B).
        if(reader.Remaining < sizeof(ushort) + sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        _ = reader.ReadUInt16();
        _ = reader.ReadUInt32();
        if(!TrySkipTpm2b(ref reader, out malformedResponseCode))
        {
            return false;
        }

        //The request, with its owned password and digest carriers, is constructed as the parse's last act, so no
        //refused parse ever creates one.
        Tpm2bAuth suppliedKeyPassword = Tpm2bAuth.Empty;
        try
        {
            suppliedKeyPassword = Tpm2bAuth.Create(suppliedAuth, pool);
            input = new TpmSignRequested(TpmiDhObject.FromValue(keyHandle), suppliedKeyPassword, Tpm2bDigest.Create(digest, pool), signatureScheme, schemeHashAlg);
        }
        catch
        {
            //This carrier's only owner is this frame until the request adopts it, so a failing later rent
            //must release it or the pinned rental is orphaned.
            suppliedKeyPassword.Dispose();
            throw;
        }

        return true;
    }

    /// <summary>
    /// <c>TPM2_Create()</c> is authorized, so its wire layout after the header is: handle area (@parentHandle, 1
    /// handle), authorization area (one or two sessions), then parameters (inSensitive as
    /// TPM2B_SENSITIVE_CREATE, inPublic as TPM2B_PUBLIC, outsideInfo as TPM2B_DATA, creationPCR as
    /// TPML_PCR_SELECTION). Only a sealed KEYEDHASH template is modelled.
    /// </summary>
    /// <remarks>
    /// inPublic's Name algorithm, authorization policy, and DA attribute are decoded here (never subject to
    /// parameter encryption, Part 1 clause 21.1); inSensitive's nested userAuth/data are NOT — a decrypt session
    /// may still leave them ciphertext at this point — so only the raw parameter-area bytes are captured for the
    /// session-authorized form, decoded later once the command HMAC(s) verify and (if present) the decrypt
    /// session has run (<c>TpmCreateSealedObjectOverSessionsRequested</c>; Part 3, clause 5.6 precedes clause
    /// 5.7). The first session generically parses as either TPM_RS_PW or a real HMAC session; a single
    /// TPM_RS_PW session (no decrypt companion) is the plain form (<c>TpmCreateSealedObjectRequested</c>),
    /// decoded immediately without decryption. The parent's storage attributes are checked in the transition
    /// (which holds the loaded-object state).
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parse-rented secret, userAuth, parent-password, session-slot credential and session-slot caller-nonce carriers transfers to the constructed request input: the consuming transition threads the secret and userAuth into the seal action for the effect to pack into the wrapped private blob and release, itself releases the parent-password and credential carriers once the compares and the verification queue have consumed them, transfers each slot's caller nonce into that slot's response-session entry, and its refusing arms dispose them all through the input's own Dispose; a rent that fails after an earlier carrier already succeeded releases it in the catch before rethrowing.")]
    private static bool TryParseCreate(ref TpmReader reader, ushort tag, BaseMemoryPool pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(tag != (ushort)TpmStConstants.TPM_ST_SESSIONS)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_AUTH_MISSING;

            return false;
        }

        //Handle area: @parentHandle (the loaded storage parent).
        if(reader.Remaining < sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint parentHandle = reader.ReadUInt32();

        if(!TryBeginAuthArea(ref reader, out int sessionsStart, out uint authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        //First session (handle + nonceCaller + sessionAttributes + hmac). TryReadCommandSessionSpans reads the
        //same TPMS_AUTH_COMMAND layout a password session uses, so it parses either kind; the transition (or,
        //for the plain single-password form below, the handle value itself) decides which.
        if(!TryReadCommandSessionSpans(ref reader, sessionIndex: 0, out TpmiShAuthSession firstHandle, out ReadOnlySpan<byte> firstNonceCaller, out TpmaSession firstAttributes, out ReadOnlySpan<byte> firstHmac, out malformedResponseCode))
        {
            return false;
        }

        bool isSingleSession = reader.Consumed - sessionsStart == (int)authorizationSize;

        if(isSingleSession && firstHandle.IsPasswordSession)
        {
            //Plain password form: decode inSensitive/inPublic/outsideInfo/creationPCR
            //immediately, exactly as every existing caller already relies on. The parsed sensitive
            //carriers stay alive (and are released by the using) until every remaining shape check has
            //passed, so the request's owned carriers are rented only for a fully-validated frame — no
            //refused parse ever creates one.
            if(reader.Remaining < sizeof(ushort))
            {
                malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

                return false;
            }

            Tpm2bSensitiveCreate parsedPlainSensitive;
            try
            {
                parsedPlainSensitive = Tpm2bSensitiveCreate.Parse(ref reader, pool);
            }
            catch(InvalidOperationException)
            {
                //TPMS_SENSITIVE_CREATE.userAuth is a TPM2B_AUTH, bounded by sizeof(TPMU_HA) (TPM 2.0 Library
                //Part 2, clause 10.4.5, Table 95 over clause 10.4.2, Table 92), so a wider declared size is
                //TPM_RC_SIZE. The structure parser's only refusal channel is the throw, and an unmarshaling
                //error means no command processing occurs (Part 3, clause 5.8.2).
                malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

                return false;
            }

            using(Tpm2bSensitiveCreate inSensitive = parsedPlainSensitive)
            {
                if(reader.Remaining < sizeof(ushort))
                {
                    malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

                    return false;
                }

                TpmiAlgPublic plainObjectType;
                TpmiAlgHash plainNameAlg;
                bool plainNoDa;
                bool plainUserWithAuth;

                //The scoped public area releases its own policy carrier at the using below, so the digest the
                //request retains is copied into a carrier of its own inside that scope — the only place the
                //octets are still readable. Every arm that refuses between there and the construction releases
                //it explicitly, so no refusal orphans the rental.
                Tpm2bDigest plainAuthPolicy = Tpm2bDigest.Empty;

                Tpm2bPublic inPublic;
                try
                {
                    inPublic = Tpm2bPublic.Parse(ref reader, pool);
                }
                catch(InvalidOperationException)
                {
                    //A TPM2B_DIGEST is bounded by sizeof(TPMU_HA) (TPM 2.0 Library Part 2, clause 10.4.2, Table
                    //92) and the public area's authPolicy is one, so a wider declared size is TPM_RC_SIZE. The
                    //parse is what answers it: the structure parser's only refusal channel is the throw, and an
                    //unmarshaling error means no command processing occurs (Part 3, clause 5.8.2). Nothing has
                    //been rented for the refused frame yet — the policy carrier is still the empty sentinel.
                    malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

                    return false;
                }

                using(inPublic)
                {
                    plainObjectType = TpmiAlgPublic.FromValue(inPublic.PublicArea.Type);
                    plainNameAlg = TpmiAlgHash.FromValue(inPublic.PublicArea.NameAlg);
                    plainAuthPolicy = Tpm2bDigest.Create(inPublic.PublicArea.AuthPolicy.AsReadOnlySpan(), pool);
                    plainNoDa = (inPublic.PublicArea.ObjectAttributes & TpmaObject.NO_DA) != 0;
                    plainUserWithAuth = (inPublic.PublicArea.ObjectAttributes & TpmaObject.USER_WITH_AUTH) != 0;
                }

                if(plainObjectType.Value != TpmAlgIdConstants.TPM_ALG_KEYEDHASH)
                {
                    plainAuthPolicy.Dispose();
                    malformedResponseCode = TpmRcConstants.TPM_RC_TYPE;

                    return false;
                }

                if(!TrySkipTpm2b(ref reader, out malformedResponseCode))
                {
                    plainAuthPolicy.Dispose();

                    return false;
                }

                if(!TrySkipPcrSelection(ref reader, out malformedResponseCode))
                {
                    plainAuthPolicy.Dispose();

                    return false;
                }

                Tpm2bSensitiveData secretData = Tpm2bSensitiveData.Empty;
                Tpm2bAuth suppliedParentPassword = Tpm2bAuth.Empty;
                try
                {
                    //Every rent the request's carriers need happens inside this frame, so a failure at any one of
                    //them reaches the catch that releases the policy digest already rented above it.
                    secretData = Tpm2bSensitiveData.Create(inSensitive.Sensitive.Data.AsReadOnlySpan(), pool);

                    //The parent slot's plaintext password (the password session's hmac field) rides an owned
                    //pooled carrier to the consuming transition's compare against the parent's retained
                    //authValue; an empty password is the dispose-immune sentinel.
                    suppliedParentPassword = Tpm2bAuth.Create(firstHmac, pool);
                    input = new TpmCreateSealedObjectRequested(
                        TpmiDhObject.FromValue(parentHandle), suppliedParentPassword, plainNameAlg, plainAuthPolicy, plainNoDa, plainUserWithAuth,
                        secretData, Tpm2bAuth.Create(inSensitive.Sensitive.UserAuth.AsReadOnlySpan(), pool));
                }
                catch
                {
                    //These carriers' only owner is this frame until the request adopts them, so a failing
                    //later rent must release them or the pinned rentals are orphaned.
                    plainAuthPolicy.Dispose();
                    secretData.Dispose();
                    suppliedParentPassword.Dispose();
                    throw;
                }

                return true;
            }
        }

        //Session-authorized form: session 0 is a real HMAC session or (paired with a decrypt companion) TPM_RS_PW;
        //session 1, when present, is a SEPARATE bound HMAC session carrying the decrypt attribute (Part 1, clauses
        //19 and 21) — the transition resolves both against state.HmacSessions.
        TpmiShAuthSession decryptHandle = TpmiShAuthSession.FromValue(0);
        scoped ReadOnlySpan<byte> decryptNonceCaller = ReadOnlySpan<byte>.Empty;
        TpmaSession decryptAttributes = default;
        scoped ReadOnlySpan<byte> decryptHmac = ReadOnlySpan<byte>.Empty;

        if(!isSingleSession)
        {
            if(!TryReadCommandSessionSpans(ref reader, sessionIndex: 1, out decryptHandle, out decryptNonceCaller, out decryptAttributes, out decryptHmac, out malformedResponseCode))
            {
                return false;
            }

            if(!TryEndAuthArea(ref reader, sessionsStart, authorizationSize, out malformedResponseCode))
            {
                return false;
            }
        }

        //Capture the ENTIRE remaining parameter area (inSensitive ‖ inPublic ‖ outsideInfo ‖ creationPCR) exactly
        //as received — cpHash's parameter term (still encrypted, if a decrypt session is present) — and decode
        //NOTHING else here: inSensitive's declared size gates where inPublic starts, but that size is validated
        //only after decryption (Part 3, clause 5.7), and every field's interpretation (clause 5.8) must in any
        //case follow the command HMAC verification (clause 5.6) — so the parser stops at the raw capture and
        //TpmDecryptCreateSensitiveAction decodes the whole buffer once verification (and decryption) has run.
        if(reader.Remaining < sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        ReadOnlySpan<byte> rawParameterAreaOctets = reader.PeekBytes(reader.Remaining);
        reader.Skip(reader.Remaining);

        //Each slot's own two credentials are rented here alongside the parameter area, the parse's last act
        //after every wire check has passed, so no refused parse ever creates one. A TPM_RS_PW slot 0 carries no
        //caller nonce at all (its width rule already refused a non-empty one), so its rental resolves to the
        //dispose-immune empty sentinel without a special case.
        Tpm2bNonce firstSlotNonce = Tpm2bNonce.Empty;
        Tpm2bAuth firstSlotCredential = Tpm2bAuth.Empty;
        Tpm2bNonce decryptSlotNonce = Tpm2bNonce.Empty;
        Tpm2bAuth decryptSlotCredential = Tpm2bAuth.Empty;
        TpmParameterArea parameterArea = TpmParameterArea.Empty;
        try
        {
            firstSlotNonce = Tpm2bNonce.Create(firstNonceCaller, pool);
            firstSlotCredential = Tpm2bAuth.Create(firstHmac, pool);
            decryptSlotNonce = Tpm2bNonce.Create(decryptNonceCaller, pool);
            decryptSlotCredential = Tpm2bAuth.Create(decryptHmac, pool);
            parameterArea = TpmParameterArea.Create(rawParameterAreaOctets, pool);

            input = new TpmCreateSealedObjectOverSessionsRequested(
                TpmiDhObject.FromValue(parentHandle), firstHandle, firstSlotNonce, firstAttributes, firstSlotCredential,
                !isSingleSession, decryptHandle, decryptSlotNonce, decryptAttributes, decryptSlotCredential,
                parameterArea);
        }
        catch
        {
            //These carriers' only owner is this frame until the request adopts them, so a failing later rent
            //must release them or the pinned rentals are orphaned.
            parameterArea.Dispose();
            decryptSlotCredential.Dispose();
            decryptSlotNonce.Dispose();
            firstSlotCredential.Dispose();
            firstSlotNonce.Dispose();
            throw;
        }

        return true;
    }

    /// <summary>
    /// <c>TPM2_Load()</c> is authorized: handle area (@parentHandle, 1 handle), authorization area (a single
    /// password session), then parameters (inPrivate as TPM2B_PRIVATE, inPublic as TPM2B_PUBLIC).
    /// </summary>
    /// <remarks>
    /// The wrapped blob carries the sealed data (the simulator's own encoding); the marshaled TPMT_PUBLIC is
    /// retained so the effect can compute the object Name (TPM 2.0 Library Part 3, clause 12.2).
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parse-rented parent-password carrier transfers to the constructed request input, whose consuming transition releases it once the parent-slot compare has consumed it, and whose refusing arms dispose it through the input's own Dispose.")]
    private static bool TryParseLoad(ref TpmReader reader, ushort tag, BaseMemoryPool pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(tag != (ushort)TpmStConstants.TPM_ST_SESSIONS)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_AUTH_MISSING;

            return false;
        }

        //Handle area: @parentHandle (the loaded storage parent).
        if(reader.Remaining < sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint parentHandle = reader.ReadUInt32();

        if(!TryReadPasswordAuthArea(ref reader, out ReadOnlySpan<byte> suppliedAuth, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: inPrivate (TPM2B_PRIVATE) — the wrapped blob, copied into durable model memory.
        if(!TryReadTpm2b(ref reader, out ReadOnlyMemory<byte> privateBlob, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: inPublic (TPM2B_PUBLIC) — the object's public area; retain its object type, Name algorithm,
        //and marshaled TPMT_PUBLIC bytes for the Name computation.
        if(reader.Remaining < sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        Tpm2bPublic inPublic;
        try
        {
            inPublic = Tpm2bPublic.Parse(ref reader, pool);
        }
        catch(InvalidOperationException)
        {
            //A TPM2B_DIGEST is bounded by sizeof(TPMU_HA) (TPM 2.0 Library Part 2, clause 10.4.2, Table 92) and
            //the loaded public area's authPolicy is one, so a wider declared size is TPM_RC_SIZE. The parse is
            //what answers it: the structure parser's only refusal channel is the throw, and an unmarshaling
            //error means no command processing occurs (Part 3, clause 5.8.2).
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //The public area is the LAST wire parameter, so its carrier is the parse's last rental and no earlier
        //refusal can have created it. The object type, Name algorithm and the two attribute bits are resolved
        //values read out of it here; the marshaled TPMT_PUBLIC octets the Name is hashed over stay inside the
        //carrier and travel with it, so nothing is flattened onto the heap.
        TpmiAlgPublic objectType = TpmiAlgPublic.FromValue(inPublic.PublicArea.Type);
        TpmiAlgHash nameAlg = TpmiAlgHash.FromValue(inPublic.PublicArea.NameAlg);

        //noDa/userWithAuth are re-derived from the same caller-supplied public area exactly as authPolicy is —
        //public-area attributes, not sensitive-area state (which travels through the private blob instead).
        bool noDa = (inPublic.PublicArea.ObjectAttributes & TpmaObject.NO_DA) != 0;
        bool userWithAuth = (inPublic.PublicArea.ObjectAttributes & TpmaObject.USER_WITH_AUTH) != 0;

        //The remaining carriers are rented as the parse's last act, inside the multi-carrier guard: the
        //authPolicy the loaded public area carries needs a carrier of its own because the load effect transfers
        //it onto the DURABLE sealed-object state (TPM 2.0 Library Part 3, clause 12.7), which outlives the
        //public area the request owns, and the parent password is compared once by the consuming transition.
        Tpm2bDigest authPolicy = Tpm2bDigest.Empty;
        Tpm2bAuth suppliedParentPassword = Tpm2bAuth.Empty;
        try
        {
            authPolicy = Tpm2bDigest.Create(inPublic.PublicArea.AuthPolicy.AsReadOnlySpan(), pool);
            suppliedParentPassword = Tpm2bAuth.Create(suppliedAuth, pool);

            input = new TpmLoadObjectRequested(
                TpmiDhObject.FromValue(parentHandle), suppliedParentPassword, objectType, nameAlg, authPolicy,
                noDa, userWithAuth, inPublic, privateBlob);
        }
        catch
        {
            //These carriers' only owner is this frame until the request adopts them, so a failing later rent
            //must release every earlier one or the rentals are orphaned.
            suppliedParentPassword.Dispose();
            authPolicy.Dispose();
            inPublic.Dispose();
            throw;
        }

        return true;
    }

    /// <summary>
    /// <c>TPM2_Unseal()</c> is authorized: handle area (@itemHandle, 1 handle), authorization area, then no
    /// parameters (TPM 2.0 Library Part 3, clause 12.7).
    /// </summary>
    /// <remarks>
    /// The authorization area carries either a single session (a password session, a satisfied policy session,
    /// or an HMAC session as the primary authorizer) or two sessions in order: the primary authorizer followed
    /// by a bound HMAC session with the encrypt attribute that protects the recovered outData (Part 1, clauses
    /// 16.7 and 19). The first session is read generically; whether a second session follows selects the form.
    /// Every hmac/password field is captured (never consumed-and-discarded) so the transition can route real
    /// command-HMAC/password verification through the shared mechanism; <c>TPM2_Unseal()</c> has no command
    /// parameters, so cpHash's parameter term is always the empty buffer.
    /// </remarks>
    /// <param name="reader">The wire reader positioned after the command header.</param>
    /// <param name="tag">The command's structure tag.</param>
    /// <param name="pool">The memory pool the request's owned credential carriers are rented from.</param>
    /// <param name="input">The parsed <see cref="TpmUnsealRequested"/> or <see cref="TpmUnsealOverSessionsRequested"/> input on success.</param>
    /// <param name="malformedResponseCode">The response code to return when parsing fails.</param>
    /// <returns><see langword="true"/> when the command parses successfully; otherwise <see langword="false"/>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of every parse-rented session-slot carrier — each slot's caller nonce and its supplied hmac, which for a TPM_RS_PW slot is the plaintext password — transfers to the constructed request input; the consuming transition releases the credentials once the compare and the verification queue have consumed them and transfers each slot's caller nonce into that slot's response-session entry, and every refusing arm releases them through the input's own Dispose; a rent that fails after an earlier carrier already succeeded releases it in the catch before rethrowing.")]
    private static bool TryParseUnseal(ref TpmReader reader, ushort tag, BaseMemoryPool pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(tag != (ushort)TpmStConstants.TPM_ST_SESSIONS)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_AUTH_MISSING;

            return false;
        }

        //Handle area: @itemHandle (the loaded sealed object).
        if(reader.Remaining < sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint itemHandle = reader.ReadUInt32();

        if(!TryBeginAuthArea(ref reader, out int sessionsStart, out uint authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        //First session (handle + nonceCaller + sessionAttributes + hmac). TryReadCommandSessionSpans reads the
        //same TPMS_AUTH_COMMAND layout a password session uses, so it parses either kind.
        if(!TryReadCommandSessionSpans(ref reader, sessionIndex: 0, out TpmiShAuthSession firstHandle, out ReadOnlySpan<byte> firstNonceCaller, out TpmaSession firstAttributes, out ReadOnlySpan<byte> firstHmac, out malformedResponseCode))
        {
            return false;
        }

        //A single session that consumes the whole authorization area is either the plain password form (TPM_RS_PW,
        //returning outData in the clear — firstHmac IS the plaintext supplied password) or a lone policy/HMAC
        //session (which still runs its own gate, but with no encrypt session the recovered outData is returned in
        //the clear).
        if(reader.Consumed - sessionsStart == (int)authorizationSize)
        {
            if(reader.Remaining != 0)
            {
                malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

                return false;
            }

            //The slot's own two credentials are rented here, the parse's last act after every wire check has
            //passed, so no refused parse ever creates one. A TPM_RS_PW slot carries no caller nonce at all (its
            //width rule already refused a non-empty one), so its rental resolves to the dispose-immune empty
            //sentinel without a special case.
            Tpm2bNonce loneSlotNonce = Tpm2bNonce.Empty;
            Tpm2bAuth loneSlotCredential = Tpm2bAuth.Empty;
            try
            {
                loneSlotNonce = Tpm2bNonce.Create(firstNonceCaller, pool);
                loneSlotCredential = Tpm2bAuth.Create(firstHmac, pool);

                input = firstHandle.IsPasswordSession
                    ? new TpmUnsealRequested(TpmiDhObject.FromValue(itemHandle), loneSlotCredential)
                    : new TpmUnsealOverSessionsRequested(
                        TpmiDhObject.FromValue(itemHandle), firstHandle, loneSlotNonce, firstAttributes, loneSlotCredential,
                        HasEncryptSlot: false, EncryptSession: TpmiShAuthSession.FromValue(0), Tpm2bNonce.Empty, EncryptAttributes: default, Tpm2bAuth.Empty);
            }
            catch
            {
                //These carriers' only owner is this frame until the request adopts them, so a failing later rent
                //must release them or the pinned rentals are orphaned.
                loneSlotCredential.Dispose();
                loneSlotNonce.Dispose();
                throw;
            }

            //A password slot's own caller nonce is structurally empty and the plain form keeps no nonce slot at
            //all, so the sentinel this frame still holds owns nothing and needs no release.
            return true;
        }

        //Two sessions: session 1 = the primary authorizer, session 2 = the bound HMAC (encrypt) session that
        //protects outData. Capture the encrypt session's caller nonce, attributes, and hmac for the response path
        //and its own command-HMAC verification.
        if(!TryReadCommandSessionSpans(ref reader, sessionIndex: 1, out TpmiShAuthSession encryptHandle, out ReadOnlySpan<byte> encryptNonceCaller, out TpmaSession encryptAttributes, out ReadOnlySpan<byte> encryptHmac, out malformedResponseCode))
        {
            return false;
        }

        if(!TryEndAuthArea(ref reader, sessionsStart, authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        //No parameters follow the authorization area; any surplus is malformed (Part 3, 5.2).
        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //Each slot's own two credentials are rented here, the parse's last act after every wire check has
        //passed, so no refused parse ever creates one.
        Tpm2bNonce firstSlotNonce = Tpm2bNonce.Empty;
        Tpm2bAuth firstSlotCredential = Tpm2bAuth.Empty;
        Tpm2bNonce encryptSlotNonce = Tpm2bNonce.Empty;
        Tpm2bAuth encryptSlotCredential = Tpm2bAuth.Empty;
        try
        {
            firstSlotNonce = Tpm2bNonce.Create(firstNonceCaller, pool);
            firstSlotCredential = Tpm2bAuth.Create(firstHmac, pool);
            encryptSlotNonce = Tpm2bNonce.Create(encryptNonceCaller, pool);
            encryptSlotCredential = Tpm2bAuth.Create(encryptHmac, pool);

            input = new TpmUnsealOverSessionsRequested(
                TpmiDhObject.FromValue(itemHandle), firstHandle, firstSlotNonce, firstAttributes, firstSlotCredential,
                HasEncryptSlot: true, encryptHandle, encryptSlotNonce, encryptAttributes, encryptSlotCredential);
        }
        catch
        {
            //These carriers' only owner is this frame until the request adopts them, so a failing later rent
            //must release them or the pinned rentals are orphaned.
            encryptSlotCredential.Dispose();
            encryptSlotNonce.Dispose();
            firstSlotCredential.Dispose();
            firstSlotNonce.Dispose();
            throw;
        }

        return true;
    }

    /// <summary>
    /// <c>TPM2_Certify()</c> is authorized and takes two handles, so its wire layout after the header is: handle
    /// area (@objectHandle, @signHandle — 2 handles, both requiring authorization), authorization area (two
    /// sessions in handle order, each independently a <c>TPM_RS_PW</c> password or a real HMAC session,
    /// optionally followed by a companion slot authorizing nothing), then parameters (qualifyingData as
    /// TPM2B_DATA, inScheme as TPMT_SIG_SCHEME). An area of two LONE password slots parses to
    /// <see cref="TpmCertifyRequested"/>; any other combination, including two password slots ALONGSIDE a
    /// companion, to <see cref="TpmCertifyOverSessionRequested"/>.
    /// </summary>
    /// <remarks>
    /// The number of slots is read from the declared authorization size rather than assumed, the
    /// <c>TPM2_Create()</c> idiom, and <c>TryEndAuthArea</c> still answers <c>TPM_RC_AUTHSIZE</c> for a fourth
    /// slot or any surplus octet. The scheme's validation is entirely in the signing scheme selector (TPM 2.0
    /// Library Part 3, clause 18.2).
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parse-rented object-slot credential, sign-slot credential, companion-slot credential, all three slots' caller nonces, and qualifying-data carriers transfers to the constructed request input, whose consuming transition (password) or continuation (session) releases them or transfers them into the certify action and its response-session entries, and whose refusing arms dispose them through the input's own Dispose; a rent that fails after an earlier carrier already succeeded releases it in the catch before rethrowing.")]
    private static bool TryParseCertify(ref TpmReader reader, ushort tag, BaseMemoryPool pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(tag != (ushort)TpmStConstants.TPM_ST_SESSIONS)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_AUTH_MISSING;

            return false;
        }

        //Handle area: @objectHandle (the certified object) then @signHandle (the signing key).
        if(reader.Remaining < 2 * sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        TpmiDhObject objectHandle = TpmiDhObject.FromValue(reader.ReadUInt32());
        TpmiDhObject signHandle = TpmiDhObject.FromValue(reader.ReadUInt32());

        //Both authorization slots (@objectHandle then @signHandle, handle order) are read generically: each slot
        //independently is a TPM_RS_PW password or a real HMAC session.
        if(!TryBeginAuthArea(ref reader, out int sessionsStart, out uint authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        if(!TryReadCommandSessionSpans(ref reader, sessionIndex: 0, out TpmiShAuthSession objectSessionHandle, out ReadOnlySpan<byte> objectNonceCaller, out TpmaSession objectSessionAttributes, out ReadOnlySpan<byte> objectHmac, out malformedResponseCode))
        {
            return false;
        }

        if(!TryReadCommandSessionSpans(ref reader, sessionIndex: 1, out TpmiShAuthSession signSessionHandle, out ReadOnlySpan<byte> signNonceCaller, out TpmaSession signSessionAttributes, out ReadOnlySpan<byte> signHmac, out malformedResponseCode))
        {
            return false;
        }

        //Octets left inside the declared authorization size after the last REQUIRED slot are a companion slot
        //(Part 1, clause 16.6.1, Table 9, position after the authorization sessions).
        bool hasCompanion = reader.Consumed - sessionsStart != (int)authorizationSize;
        TpmiShAuthSession companionSessionHandle = TpmiShAuthSession.FromValue(0);
        TpmaSession companionSessionAttributes = default;

        //The two span locals are declared scoped so they can receive slices that alias the command buffer the
        //by-reference reader points into: without it the compiler must assume a span written through an out
        //parameter of a ref-taking method could outlive that buffer.
        scoped ReadOnlySpan<byte> companionNonceCaller = ReadOnlySpan<byte>.Empty;
        scoped ReadOnlySpan<byte> companionHmac = ReadOnlySpan<byte>.Empty;
        if(hasCompanion
            && !TryReadCommandSessionSpans(ref reader, sessionIndex: 2, out companionSessionHandle, out companionNonceCaller, out companionSessionAttributes, out companionHmac, out malformedResponseCode))
        {
            return false;
        }

        if(!TryEndAuthArea(ref reader, sessionsStart, authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        //The parameter set (qualifyingData ‖ inScheme) is every octet left after the authorization area —
        //captured verbatim, before any field is decoded, as the session arm's cpHash parameter term (Part 1,
        //clause 16.7 equation 15).
        ReadOnlySpan<byte> rawParameterAreaOctets = reader.PeekBytes(reader.Remaining);

        //Which arm the area belongs to is settled before the parameters are read, because it decides how
        //qualifyingData may be treated: two LONE TPM_RS_PW slots are the all-password form the password arm
        //serves, while any other combination — a mixed one, or two password slots alongside a companion — is the
        //session arm, whose response owes at least one real entry.
        bool isAllPassword = objectSessionHandle.IsPasswordSession && signSessionHandle.IsPasswordSession && !hasCompanion;

        //Parameter: qualifyingData (TPM2B_DATA) — the caller nonce echoed into the attestation, and the first
        //command parameter, which is the one a decrypt session protects (Part 1, clause 16.4). On the session
        //form these octets may be CIPHERTEXT, so the parse only steps over the field's framing to reach the
        //parameters behind it and the decrypt step supplies the plaintext (Part 3, clause 5.7 precedes clause
        //5.8); decoding here would also be futile, since a separately copied field is not updated by the in-place
        //transform of the captured area. On the password form no session can protect it, so it is read as a span
        //over the command buffer whose owning carrier is rented as this parse's last act.
        scoped ReadOnlySpan<byte> qualifyingData = ReadOnlySpan<byte>.Empty;
        if(isAllPassword)
        {
            if(!TryReadTpm2bSpan(ref reader, out qualifyingData, out malformedResponseCode))
            {
                return false;
            }

            //TPM2B_DATA is bounded by sizeof(TPMT_HA) (Part 2, clause 10.4.3, Table 93), so a wider value is
            //TPM_RC_SIZE here, before any carrier is rented; the consuming transition's own bound check stands as
            //the fail-closed backstop. The session form's bound is applied to the RECOVERED value instead, which
            //is the only form of it TPM2B_DATA is about.
            if(qualifyingData.Length > Tpm2bData.MaxSize)
            {
                malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

                return false;
            }
        }
        else if(!TrySkipTpm2b(ref reader, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: inScheme (TPMT_SIG_SCHEME) — scheme selector (UINT16) + hash algorithm (UINT16). It sits
        //behind the first parameter and so is never encrypted, which is why it is decoded on both arms alike.
        if(reader.Remaining < 2 * sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        TpmiAlgSigScheme signatureScheme = TpmiAlgSigScheme.FromValue((TpmAlgIdConstants)reader.ReadUInt16());
        TpmiAlgHash schemeHashAlg = TpmiAlgHash.FromValue((TpmAlgIdConstants)reader.ReadUInt16());

        //inScheme is the final parameter; no octets may follow it (Part 3, 5.2).
        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //Either form's owned pooled carriers are rented here, the parse's last act after every wire check has
        //passed, so no refused parse ever creates one.
        Tpm2bAuth suppliedObjectHmac = Tpm2bAuth.Empty;
        Tpm2bAuth suppliedSignHmac = Tpm2bAuth.Empty;
        Tpm2bNonce objectNonce = Tpm2bNonce.Empty;
        Tpm2bNonce signNonce = Tpm2bNonce.Empty;
        Tpm2bAuth companionCredential = Tpm2bAuth.Empty;
        Tpm2bNonce companionNonce = Tpm2bNonce.Empty;
        TpmParameterArea parameterArea = TpmParameterArea.Empty;
        try
        {
            suppliedObjectHmac = Tpm2bAuth.Create(objectHmac, pool);
            suppliedSignHmac = Tpm2bAuth.Create(signHmac, pool);

            //Only the session arm retains the slots' caller nonces, so only it rents them — and it rents BOTH,
            //because a mixed area's TPM_RS_PW slot still owes its own response entry (Part 1, clause 16.6.1).
            objectNonce = isAllPassword ? Tpm2bNonce.Empty : Tpm2bNonce.Create(objectNonceCaller, pool);
            signNonce = isAllPassword ? Tpm2bNonce.Empty : Tpm2bNonce.Create(signNonceCaller, pool);
            companionCredential = hasCompanion ? Tpm2bAuth.Create(companionHmac, pool) : Tpm2bAuth.Empty;
            companionNonce = hasCompanion ? Tpm2bNonce.Create(companionNonceCaller, pool) : Tpm2bNonce.Empty;
            parameterArea = isAllPassword ? TpmParameterArea.Empty : TpmParameterArea.Create(rawParameterAreaOctets, pool);
            input = isAllPassword
                ? new TpmCertifyRequested(
                    objectHandle, suppliedObjectHmac, signHandle, suppliedSignHmac, Tpm2bData.Create(qualifyingData, pool), signatureScheme, schemeHashAlg)
                : new TpmCertifyOverSessionRequested(
                    objectHandle, objectSessionHandle, objectNonce, objectSessionAttributes, suppliedObjectHmac,
                    signHandle, signSessionHandle, signNonce, signSessionAttributes, suppliedSignHmac,
                    Tpm2bData.Empty, signatureScheme, schemeHashAlg, parameterArea,
                    hasCompanion, companionSessionHandle, companionNonce, companionSessionAttributes, companionCredential);
        }
        catch
        {
            //These carriers' only owner is this frame until the request adopts them, so a failing later rent
            //must release them or the pinned rentals are orphaned.
            parameterArea.Dispose();
            companionNonce.Dispose();
            companionCredential.Dispose();
            signNonce.Dispose();
            objectNonce.Dispose();
            suppliedSignHmac.Dispose();
            suppliedObjectHmac.Dispose();
            throw;
        }

        return true;
    }

    /// <summary>
    /// <c>TPM2_CertifyCreation()</c> is authorized and takes two handles, but only ONE requires authorization:
    /// the wire layout after the header is handle area (@signHandle first — USER role — then objectHandle,
    /// Table 88, no auth), authorization area (the signHandle slot, either a <c>TPM_RS_PW</c> password or a real
    /// HMAC session, optionally followed by one or two companion slots authorizing nothing), then parameters
    /// (qualifyingData as TPM2B_DATA, creationHash as TPM2B_DIGEST, inScheme as TPMT_SIG_SCHEME, creationTicket
    /// as TPMT_TK_CREATION). A lone password slot parses to <see cref="TpmCertifyCreationRequested"/>; anything
    /// else, including a password slot ALONGSIDE a companion, to
    /// <see cref="TpmCertifyCreationOverSessionRequested"/>.
    /// </summary>
    /// <remarks>
    /// The number of slots is read from the declared authorization size rather than assumed, the
    /// <c>TPM2_Create()</c> idiom. One authorizing slot leaves BOTH of Table 9's later positions open, so the area
    /// may carry two companions; <c>TryEndAuthArea</c> answers <c>TPM_RC_AUTHSIZE</c> for a fourth slot or any
    /// surplus octet, which is the "no more than three" bound of Part 1, clause 16.6.1. The ticket's own
    /// tag/hierarchy fields are consumed for correct framing but not retained: the transition/effect re-derive the
    /// hierarchy from the resolved object's own retained state rather than trust the caller-supplied fields (TPM
    /// 2.0 Library Part 3, clause 18.3).
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parse-rented sign-slot credential, sign-slot caller nonce, both companion slots' credentials and caller nonces, qualifying-data, creation-hash, and ticket-digest carriers transfers to the constructed request input, whose consuming transition (password) or continuation (session) releases them or transfers them into the certify-creation action and its response-session entries, and whose refusing arms dispose them through the input's own Dispose; a rent that fails after an earlier carrier already succeeded releases it in the catch before rethrowing.")]
    private static bool TryParseCertifyCreation(ref TpmReader reader, ushort tag, BaseMemoryPool pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(tag != (ushort)TpmStConstants.TPM_ST_SESSIONS)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_AUTH_MISSING;

            return false;
        }

        //Handle area: @signHandle (the signing key) then objectHandle (the certified object).
        if(reader.Remaining < 2 * sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        TpmiDhObject signHandle = TpmiDhObject.FromValue(reader.ReadUInt32());
        TpmiDhObject objectHandle = TpmiDhObject.FromValue(reader.ReadUInt32());

        //The authorizing slot (@signHandle; objectHandle carries no authorization) is read generically: a
        //TPM_RS_PW handle is the password form, any other handle is a real HMAC session.
        if(!TryBeginAuthArea(ref reader, out int sessionsStart, out uint authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        if(!TryReadCommandSessionSpans(ref reader, sessionIndex: 0, out TpmiShAuthSession signSessionHandle, out ReadOnlySpan<byte> signNonceCaller, out TpmaSession signSessionAttributes, out ReadOnlySpan<byte> signHmac, out malformedResponseCode))
        {
            return false;
        }

        //Octets left inside the declared authorization size after the last REQUIRED slot are a companion slot
        //(Part 1, clause 16.6.1, Table 9, position after the authorization sessions).
        bool hasCompanion = reader.Consumed - sessionsStart != (int)authorizationSize;
        TpmiShAuthSession companionSessionHandle = TpmiShAuthSession.FromValue(0);
        TpmaSession companionSessionAttributes = default;

        //The two span locals are declared scoped so they can receive slices that alias the command buffer the
        //by-reference reader points into: without it the compiler must assume a span written through an out
        //parameter of a ref-taking method could outlive that buffer.
        scoped ReadOnlySpan<byte> companionNonceCaller = ReadOnlySpan<byte>.Empty;
        scoped ReadOnlySpan<byte> companionHmac = ReadOnlySpan<byte>.Empty;
        if(hasCompanion
            && !TryReadCommandSessionSpans(ref reader, sessionIndex: 1, out companionSessionHandle, out companionNonceCaller, out companionSessionAttributes, out companionHmac, out malformedResponseCode))
        {
            return false;
        }

        //Octets STILL left after the first companion are a second one: with a single authorizing slot, Table 9's
        //positions 2 and 3 are both open, and each may be an encryption, decryption, or audit session (Part 1,
        //clause 16.6.1). A fourth block would overrun the declared size, which TryEndAuthArea answers below.
        bool hasSecondCompanion = reader.Consumed - sessionsStart != (int)authorizationSize;
        TpmiShAuthSession secondCompanionSessionHandle = TpmiShAuthSession.FromValue(0);
        TpmaSession secondCompanionSessionAttributes = default;

        scoped ReadOnlySpan<byte> secondCompanionNonceCaller = ReadOnlySpan<byte>.Empty;
        scoped ReadOnlySpan<byte> secondCompanionHmac = ReadOnlySpan<byte>.Empty;
        if(hasSecondCompanion
            && !TryReadCommandSessionSpans(ref reader, sessionIndex: 2, out secondCompanionSessionHandle, out secondCompanionNonceCaller, out secondCompanionSessionAttributes, out secondCompanionHmac, out malformedResponseCode))
        {
            return false;
        }

        if(!TryEndAuthArea(ref reader, sessionsStart, authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        //The parameter set (qualifyingData ‖ creationHash ‖ inScheme ‖ creationTicket) is every octet left after
        //the authorization area — captured verbatim, before any field is decoded, as the session arm's cpHash
        //parameter term (Part 1, clause 16.7 equation 15).
        ReadOnlySpan<byte> rawParameterAreaOctets = reader.PeekBytes(reader.Remaining);

        //Which arm the area belongs to is settled before the parameters are read, because it decides how
        //qualifyingData may be treated: a LONE TPM_RS_PW slot is the all-password form the password arm serves,
        //while a real session handle, or a password slot alongside a companion, is the session arm.
        bool isPasswordSlot = signSessionHandle.IsPasswordSession && !hasCompanion;

        //Parameter: qualifyingData (TPM2B_DATA) — the caller nonce echoed into the attestation, and the first
        //command parameter, which is the one a decrypt session protects (Part 1, clause 16.4). On the session
        //form these octets may be CIPHERTEXT, so the parse only steps over the field's framing to reach the
        //parameters behind it and the decrypt step supplies the plaintext (Part 3, clause 5.7 precedes clause
        //5.8); decoding here would also be futile, since a separately copied field is not updated by the in-place
        //transform of the captured area. On the password form no session can protect it, so it is read as a span
        //over the command buffer whose owning carrier is rented as this parse's last act.
        scoped ReadOnlySpan<byte> qualifyingData = ReadOnlySpan<byte>.Empty;
        if(isPasswordSlot)
        {
            if(!TryReadTpm2bSpan(ref reader, out qualifyingData, out malformedResponseCode))
            {
                return false;
            }

            //TPM2B_DATA is bounded by sizeof(TPMT_HA) (Part 2, clause 10.4.3, Table 93), so a wider value is
            //TPM_RC_SIZE here, before any carrier is rented; the consuming transition's own bound check stands as
            //the fail-closed backstop. The session form's bound is applied to the RECOVERED value instead, which
            //is the only form of it TPM2B_DATA is about.
            if(qualifyingData.Length > Tpm2bData.MaxSize)
            {
                malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

                return false;
            }
        }
        else if(!TrySkipTpm2b(ref reader, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: creationHash (TPM2B_DIGEST) — behind the first parameter, so never encrypted and decoded on
        //both arms alike.
        if(!TryReadTpm2bSpan(ref reader, out ReadOnlySpan<byte> creationHash, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: inScheme (TPMT_SIG_SCHEME) — scheme selector (UINT16) + hash algorithm (UINT16).
        if(reader.Remaining < 2 * sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        TpmiAlgSigScheme signatureScheme = TpmiAlgSigScheme.FromValue((TpmAlgIdConstants)reader.ReadUInt16());
        TpmiAlgHash schemeHashAlg = TpmiAlgHash.FromValue((TpmAlgIdConstants)reader.ReadUInt16());

        //Parameter: creationTicket (TPMT_TK_CREATION) — tag (UINT16) + hierarchy (UINT32) + digest (TPM2B_DIGEST).
        //Only the digest is retained; the tag/hierarchy fields of a caller-supplied ticket are not trusted.
        if(reader.Remaining < sizeof(ushort) + sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        _ = reader.ReadUInt16();
        _ = reader.ReadUInt32();

        if(!TryReadTpm2bSpan(ref reader, out ReadOnlySpan<byte> ticketDigest, out malformedResponseCode))
        {
            return false;
        }

        //creationTicket is the final parameter; no octets may follow it (Part 3, 5.2).
        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //Either form's owned pooled carriers are rented here, the parse's last act after every wire check has
        //passed, so no refused parse ever creates one.
        Tpm2bAuth signCredential = Tpm2bAuth.Empty;
        Tpm2bNonce signNonce = Tpm2bNonce.Empty;
        Tpm2bAuth companionCredential = Tpm2bAuth.Empty;
        Tpm2bNonce companionNonce = Tpm2bNonce.Empty;
        Tpm2bAuth secondCompanionCredential = Tpm2bAuth.Empty;
        Tpm2bNonce secondCompanionNonce = Tpm2bNonce.Empty;
        Tpm2bData qualifying = Tpm2bData.Empty;
        Tpm2bDigest creation = Tpm2bDigest.Empty;
        TpmParameterArea parameterArea = TpmParameterArea.Empty;
        try
        {
            signCredential = Tpm2bAuth.Create(signHmac, pool);

            //Only the session arm retains the slots' caller nonces, so only it rents them — the password record
            //has no slot to adopt one.
            signNonce = isPasswordSlot ? Tpm2bNonce.Empty : Tpm2bNonce.Create(signNonceCaller, pool);
            companionCredential = hasCompanion ? Tpm2bAuth.Create(companionHmac, pool) : Tpm2bAuth.Empty;
            companionNonce = hasCompanion ? Tpm2bNonce.Create(companionNonceCaller, pool) : Tpm2bNonce.Empty;
            secondCompanionCredential = hasSecondCompanion ? Tpm2bAuth.Create(secondCompanionHmac, pool) : Tpm2bAuth.Empty;
            secondCompanionNonce = hasSecondCompanion ? Tpm2bNonce.Create(secondCompanionNonceCaller, pool) : Tpm2bNonce.Empty;
            //Only the password arm carries a qualifying-data carrier out of the parse; the session arm's is
            //supplied by the decrypt step, which is the only place its plaintext exists.
            qualifying = isPasswordSlot ? Tpm2bData.Create(qualifyingData, pool) : Tpm2bData.Empty;
            creation = Tpm2bDigest.Create(creationHash, pool);
            parameterArea = isPasswordSlot ? TpmParameterArea.Empty : TpmParameterArea.Create(rawParameterAreaOctets, pool);
            input = isPasswordSlot
                ? new TpmCertifyCreationRequested(
                    signHandle, signCredential, objectHandle, qualifying, creation, signatureScheme, schemeHashAlg,
                    Tpm2bDigest.Create(ticketDigest, pool))
                : new TpmCertifyCreationOverSessionRequested(
                    signHandle, signSessionHandle, signNonce, signSessionAttributes, signCredential,
                    objectHandle, qualifying, creation, signatureScheme, schemeHashAlg, Tpm2bDigest.Create(ticketDigest, pool), parameterArea,
                    hasCompanion, companionSessionHandle, companionNonce, companionSessionAttributes, companionCredential,
                    hasSecondCompanion, secondCompanionSessionHandle, secondCompanionNonce, secondCompanionSessionAttributes, secondCompanionCredential);
        }
        catch
        {
            //These carriers' only owner is this frame until the request adopts them, so a failing later rent
            //must release them or the pinned rentals are orphaned.
            parameterArea.Dispose();
            creation.Dispose();
            qualifying.Dispose();
            secondCompanionNonce.Dispose();
            secondCompanionCredential.Dispose();
            companionNonce.Dispose();
            companionCredential.Dispose();
            signNonce.Dispose();
            signCredential.Dispose();
            throw;
        }

        return true;
    }

    /// <summary>
    /// <c>TPM2_GetTime()</c> is authorized and takes two handles, both requiring authorization: the wire layout
    /// after the header is handle area (@privacyAdminHandle — fixed to TPM_RH_ENDORSEMENT — then @signHandle,
    /// Table 99), authorization area (two sessions in handle order, each independently a <c>TPM_RS_PW</c> password
    /// or a real HMAC session, optionally followed by a companion slot authorizing nothing), then parameters
    /// (qualifyingData as TPM2B_DATA, inScheme as TPMT_SIG_SCHEME). An area of two LONE password slots parses to
    /// <see cref="TpmGetTimeRequested"/>; any other combination, including two password slots ALONGSIDE a
    /// companion, to <see cref="TpmGetTimeOverSessionRequested"/>.
    /// </summary>
    /// <remarks>
    /// The number of slots is read from the declared authorization size rather than assumed, the
    /// <c>TPM2_Create()</c> idiom, and <c>TryEndAuthArea</c> still answers <c>TPM_RC_AUTHSIZE</c> for a fourth
    /// slot or any surplus octet.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parse-rented privacy-administrator credential, sign-slot credential, companion-slot credential, all three slots' caller nonces, and qualifying-data carriers transfers to the constructed request input, whose consuming transition (password) or continuation (session) releases them or transfers them into the time-attestation action and its response-session entries, and whose refusing arms dispose them through the input's own Dispose; a rent that fails after an earlier carrier already succeeded releases it in the catch before rethrowing.")]
    private static bool TryParseGetTime(ref TpmReader reader, ushort tag, BaseMemoryPool pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(tag != (ushort)TpmStConstants.TPM_ST_SESSIONS)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_AUTH_MISSING;

            return false;
        }

        //Handle area: @privacyAdminHandle then @signHandle.
        if(reader.Remaining < 2 * sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        //The privacy-administrator slot's interface type admits only TPM_RH_ENDORSEMENT (Part 2, clause 9.20,
        //Table 67); the value is carried as read and the transition answers TPM_RC_HANDLE for anything else, so
        //an out-of-set handle stays a response code rather than becoming an exception at the parse.
        TpmiRhEndorsement privacyAdminHandle = TpmiRhEndorsement.FromValue(reader.ReadUInt32());
        TpmiDhObject signHandle = TpmiDhObject.FromValue(reader.ReadUInt32());

        //Both authorization slots (@privacyAdminHandle then @signHandle, handle order) are read generically: each
        //slot independently is a TPM_RS_PW password or a real HMAC session.
        if(!TryBeginAuthArea(ref reader, out int sessionsStart, out uint authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        if(!TryReadCommandSessionSpans(ref reader, sessionIndex: 0, out TpmiShAuthSession privacyAdminSessionHandle, out ReadOnlySpan<byte> privacyAdminNonceCaller, out TpmaSession privacyAdminSessionAttributes, out ReadOnlySpan<byte> privacyAdminHmac, out malformedResponseCode))
        {
            return false;
        }

        if(!TryReadCommandSessionSpans(ref reader, sessionIndex: 1, out TpmiShAuthSession signSessionHandle, out ReadOnlySpan<byte> signNonceCaller, out TpmaSession signSessionAttributes, out ReadOnlySpan<byte> signHmac, out malformedResponseCode))
        {
            return false;
        }

        //Octets left inside the declared authorization size after the last REQUIRED slot are a companion slot
        //(Part 1, clause 16.6.1, Table 9, position after the authorization sessions).
        bool hasCompanion = reader.Consumed - sessionsStart != (int)authorizationSize;
        TpmiShAuthSession companionSessionHandle = TpmiShAuthSession.FromValue(0);
        TpmaSession companionSessionAttributes = default;

        //The two span locals are declared scoped so they can receive slices that alias the command buffer the
        //by-reference reader points into: without it the compiler must assume a span written through an out
        //parameter of a ref-taking method could outlive that buffer.
        scoped ReadOnlySpan<byte> companionNonceCaller = ReadOnlySpan<byte>.Empty;
        scoped ReadOnlySpan<byte> companionHmac = ReadOnlySpan<byte>.Empty;
        if(hasCompanion
            && !TryReadCommandSessionSpans(ref reader, sessionIndex: 2, out companionSessionHandle, out companionNonceCaller, out companionSessionAttributes, out companionHmac, out malformedResponseCode))
        {
            return false;
        }

        if(!TryEndAuthArea(ref reader, sessionsStart, authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        //The parameter set (qualifyingData ‖ inScheme) is every octet left after the authorization area —
        //captured verbatim, before any field is decoded, as the session arm's cpHash parameter term (Part 1,
        //clause 16.7 equation 15).
        ReadOnlySpan<byte> rawParameterAreaOctets = reader.PeekBytes(reader.Remaining);

        //Which arm the area belongs to is settled before the parameters are read, because it decides how
        //qualifyingData may be treated: two LONE TPM_RS_PW slots are the all-password form the password arm
        //serves, while any other combination — a mixed one, or two password slots alongside a companion — is the
        //session arm, whose response owes at least one real entry.
        bool isAllPassword = privacyAdminSessionHandle.IsPasswordSession && signSessionHandle.IsPasswordSession && !hasCompanion;

        //Parameter: qualifyingData (TPM2B_DATA) — the caller nonce echoed into the attestation, and the first
        //command parameter, which is the one a decrypt session protects (Part 1, clause 16.4). On the session
        //form these octets may be CIPHERTEXT, so the parse only steps over the field's framing to reach the
        //parameters behind it and the decrypt step supplies the plaintext (Part 3, clause 5.7 precedes clause
        //5.8); decoding here would also be futile, since a separately copied field is not updated by the in-place
        //transform of the captured area. On the password form no session can protect it, so it is read as a span
        //over the command buffer whose owning carrier is rented as this parse's last act.
        scoped ReadOnlySpan<byte> qualifyingData = ReadOnlySpan<byte>.Empty;
        if(isAllPassword)
        {
            if(!TryReadTpm2bSpan(ref reader, out qualifyingData, out malformedResponseCode))
            {
                return false;
            }

            //TPM2B_DATA is bounded by sizeof(TPMT_HA) (Part 2, clause 10.4.3, Table 93), so a wider value is
            //TPM_RC_SIZE here, before any carrier is rented; the consuming transition's own bound check stands as
            //the fail-closed backstop. The session form's bound is applied to the RECOVERED value instead, which
            //is the only form of it TPM2B_DATA is about.
            if(qualifyingData.Length > Tpm2bData.MaxSize)
            {
                malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

                return false;
            }
        }
        else if(!TrySkipTpm2b(ref reader, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: inScheme (TPMT_SIG_SCHEME) — scheme selector (UINT16) + hash algorithm (UINT16). It sits
        //behind the first parameter and so is never encrypted, which is why it is decoded on both arms alike.
        if(reader.Remaining < 2 * sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        TpmiAlgSigScheme signatureScheme = TpmiAlgSigScheme.FromValue((TpmAlgIdConstants)reader.ReadUInt16());
        TpmiAlgHash schemeHashAlg = TpmiAlgHash.FromValue((TpmAlgIdConstants)reader.ReadUInt16());

        //inScheme is the final parameter; no octets may follow it (Part 3, 5.2).
        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //Either form's owned pooled carriers are rented here, the parse's last act after every wire check has
        //passed, so no refused parse ever creates one.
        Tpm2bAuth suppliedPrivacyAdminHmac = Tpm2bAuth.Empty;
        Tpm2bAuth suppliedSignHmac = Tpm2bAuth.Empty;
        Tpm2bNonce privacyAdminNonce = Tpm2bNonce.Empty;
        Tpm2bNonce signNonce = Tpm2bNonce.Empty;
        Tpm2bAuth companionCredential = Tpm2bAuth.Empty;
        Tpm2bNonce companionNonce = Tpm2bNonce.Empty;
        TpmParameterArea parameterArea = TpmParameterArea.Empty;
        try
        {
            suppliedPrivacyAdminHmac = Tpm2bAuth.Create(privacyAdminHmac, pool);
            suppliedSignHmac = Tpm2bAuth.Create(signHmac, pool);

            //Only the session arm retains the slots' caller nonces, so only it rents them — and it rents BOTH,
            //because a mixed area's TPM_RS_PW slot still owes its own response entry (Part 1, clause 16.6.1).
            privacyAdminNonce = isAllPassword ? Tpm2bNonce.Empty : Tpm2bNonce.Create(privacyAdminNonceCaller, pool);
            signNonce = isAllPassword ? Tpm2bNonce.Empty : Tpm2bNonce.Create(signNonceCaller, pool);
            companionCredential = hasCompanion ? Tpm2bAuth.Create(companionHmac, pool) : Tpm2bAuth.Empty;
            companionNonce = hasCompanion ? Tpm2bNonce.Create(companionNonceCaller, pool) : Tpm2bNonce.Empty;
            parameterArea = isAllPassword ? TpmParameterArea.Empty : TpmParameterArea.Create(rawParameterAreaOctets, pool);
            input = isAllPassword
                ? new TpmGetTimeRequested(
                    privacyAdminHandle, suppliedPrivacyAdminHmac, signHandle, suppliedSignHmac, Tpm2bData.Create(qualifyingData, pool), signatureScheme, schemeHashAlg)
                : new TpmGetTimeOverSessionRequested(
                    privacyAdminHandle, privacyAdminSessionHandle, privacyAdminNonce, privacyAdminSessionAttributes, suppliedPrivacyAdminHmac,
                    signHandle, signSessionHandle, signNonce, signSessionAttributes, suppliedSignHmac,
                    Tpm2bData.Empty, signatureScheme, schemeHashAlg, parameterArea,
                    hasCompanion, companionSessionHandle, companionNonce, companionSessionAttributes, companionCredential);
        }
        catch
        {
            //These carriers' only owner is this frame until the request adopts them, so a failing later rent
            //must release them or the pinned rentals are orphaned.
            parameterArea.Dispose();
            companionNonce.Dispose();
            companionCredential.Dispose();
            signNonce.Dispose();
            privacyAdminNonce.Dispose();
            suppliedSignHmac.Dispose();
            suppliedPrivacyAdminHmac.Dispose();
            throw;
        }

        return true;
    }

    /// <summary>
    /// <c>TPM2_ClockSet()</c> is authorized by the owner hierarchy, so its wire layout after the header is:
    /// handle area (@auth, 1 handle), authorization area (a single password session), then the parameter
    /// newTime (UINT64) (Part 3, clause 29.2).
    /// </summary>
    /// <param name="reader">The wire reader positioned after the command header.</param>
    /// <param name="tag">The command's structure tag.</param>
    /// <param name="pool">The memory pool the request's owned credential carrier is rented from.</param>
    /// <param name="input">The parsed request input on success.</param>
    /// <param name="malformedResponseCode">The response code to return when parsing fails.</param>
    /// <returns><see langword="true"/> when the command parses successfully; otherwise <see langword="false"/>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parse-rented password carrier transfers to the constructed request input, whose authorizing transition releases it once the compare that is its only use has run, and whose refusing arms dispose it through the input's own Dispose.")]
    private static bool TryParseClockSet(ref TpmReader reader, ushort tag, BaseMemoryPool pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(tag != (ushort)TpmStConstants.TPM_ST_SESSIONS)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_AUTH_MISSING;

            return false;
        }

        //Handle area: @auth (the provisioning hierarchy).
        if(reader.Remaining < sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint authHandle = reader.ReadUInt32();

        if(!TryReadPasswordAuthArea(ref reader, out ReadOnlySpan<byte> ownerAuth, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: newTime (UINT64) — the requested new Clock setting.
        if(reader.Remaining < sizeof(ulong))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        ulong newTime = reader.ReadUInt64();

        //newTime is the final parameter; no octets may follow it (Part 3, 5.2).
        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //The password slot's plaintext authValue rides an owned pooled carrier, rented here as the parse's last
        //act after every wire check has passed, so no refused parse ever creates one.
        input = new TpmClockSetRequested(TpmiRhProvision.FromValue(authHandle), Tpm2bAuth.Create(ownerAuth, pool), newTime);

        return true;
    }

    /// <summary>
    /// <c>TPM2_DictionaryAttackLockReset()</c> is authorized by the lockout hierarchy, so its wire layout after
    /// the header is: handle area (lockHandle, 1 handle), authorization area (a single password session), then
    /// no parameters (Part 3, clause 25.2).
    /// </summary>
    /// <param name="reader">The wire reader positioned after the command header.</param>
    /// <param name="tag">The command's structure tag.</param>
    /// <param name="pool">The memory pool the request's owned credential carrier is rented from.</param>
    /// <param name="input">The parsed request input on success.</param>
    /// <param name="malformedResponseCode">The response code to return when parsing fails.</param>
    /// <returns><see langword="true"/> when the command parses successfully; otherwise <see langword="false"/>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parse-rented password carrier transfers to the constructed request input, whose authorizing transition releases it once the compare that is its only use has run, and whose refusing arms dispose it through the input's own Dispose.")]
    private static bool TryParseDictionaryAttackLockReset(ref TpmReader reader, ushort tag, BaseMemoryPool pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(tag != (ushort)TpmStConstants.TPM_ST_SESSIONS)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_AUTH_MISSING;

            return false;
        }

        //Handle area: lockHandle (the lockout hierarchy).
        if(reader.Remaining < sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint lockHandle = reader.ReadUInt32();

        if(!TryReadPasswordAuthArea(ref reader, out ReadOnlySpan<byte> lockoutAuth, out malformedResponseCode))
        {
            return false;
        }

        //TPM2_DictionaryAttackLockReset has no parameters; the parameter area must be empty.
        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //The password slot's plaintext authValue rides an owned pooled carrier, rented here as the parse's last
        //act after every wire check has passed, so no refused parse ever creates one.
        input = new TpmDictionaryAttackLockResetRequested(TpmiRhLockout.FromValue(lockHandle), Tpm2bAuth.Create(lockoutAuth, pool));

        return true;
    }

    /// <summary>
    /// <c>TPM2_DictionaryAttackParameters()</c> is authorized by the lockout hierarchy exactly like
    /// <c>TPM2_DictionaryAttackLockReset()</c>, then carries newMaxTries/newRecoveryTime/newLockoutRecovery
    /// (three UINT32, Part 3, clause 25.3).
    /// </summary>
    /// <param name="reader">The wire reader positioned after the command header.</param>
    /// <param name="tag">The command's structure tag.</param>
    /// <param name="pool">The memory pool the request's owned credential carrier is rented from.</param>
    /// <param name="input">The parsed request input on success.</param>
    /// <param name="malformedResponseCode">The response code to return when parsing fails.</param>
    /// <returns><see langword="true"/> when the command parses successfully; otherwise <see langword="false"/>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parse-rented password carrier transfers to the constructed request input, whose authorizing transition releases it once the compare that is its only use has run, and whose refusing arms dispose it through the input's own Dispose.")]
    private static bool TryParseDictionaryAttackParameters(ref TpmReader reader, ushort tag, BaseMemoryPool pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(tag != (ushort)TpmStConstants.TPM_ST_SESSIONS)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_AUTH_MISSING;

            return false;
        }

        //Handle area: lockHandle (the lockout hierarchy).
        if(reader.Remaining < sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint lockHandle = reader.ReadUInt32();

        if(!TryReadPasswordAuthArea(ref reader, out ReadOnlySpan<byte> lockoutAuth, out malformedResponseCode))
        {
            return false;
        }

        //Parameters: newMaxTries (UINT32) + newRecoveryTime (UINT32) + newLockoutRecovery (UINT32).
        if(reader.Remaining < 3 * sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint newMaxTries = reader.ReadUInt32();
        uint newRecoveryTime = reader.ReadUInt32();
        uint newLockoutRecovery = reader.ReadUInt32();

        //newLockoutRecovery is the final parameter; no octets may follow it (Part 3, 5.2).
        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //The password slot's plaintext authValue rides an owned pooled carrier, rented here as the parse's last
        //act after every wire check has passed, so no refused parse ever creates one.
        input = new TpmDictionaryAttackParametersRequested(TpmiRhLockout.FromValue(lockHandle), Tpm2bAuth.Create(lockoutAuth, pool), newMaxTries, newRecoveryTime, newLockoutRecovery);

        return true;
    }

    /// <summary>
    /// <c>TPM2_Clear()</c> is authorized: handle area (<c>@authHandle</c>, 1 handle), authorization area (a
    /// single session), then no parameters at all (TPM 2.0 Library Part 3, clause 24.6.2, Table 184).
    /// </summary>
    /// <remarks>
    /// The authorization area is read generically with <c>TryReadCommandSessionSpans</c>, exactly as
    /// <see cref="TryParseNvUndefineSpace"/> reads its own: a <c>TPMS_AUTH_COMMAND</c>'s wire layout does not
    /// depend on the session's kind, so the parsed sessionHandle alone decides whether this becomes
    /// <see cref="TpmClearRequested"/> (password) or <see cref="TpmClearOverSessionRequested"/> (HMAC). The
    /// handle's admissible set (<c>TPMI_RH_CLEAR</c>) is checked at the transition, where the rest of the
    /// authorization ladder lives.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parse-rented parameter-area carrier and of the authorization slot's own two credential carriers — its caller nonce and its supplied hmac — transfers to the constructed request input; the consuming continuation releases the credential and the parameter area per carrier and transfers the nonce into the response framing, and every refusing arm releases all three through the input's own Dispose; a rent that fails after an earlier carrier already succeeded releases it in the catch before rethrowing.")]
    private static bool TryParseClear(ref TpmReader reader, ushort tag, BaseMemoryPool pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(tag != (ushort)TpmStConstants.TPM_ST_SESSIONS)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_AUTH_MISSING;

            return false;
        }

        //Handle area: @authHandle (the authorizing hierarchy).
        if(reader.Remaining < sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint authHandle = reader.ReadUInt32();

        if(!TryBeginAuthArea(ref reader, out int sessionsStart, out uint authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        if(!TryReadCommandSessionSpans(ref reader, sessionIndex: 0, out TpmiShAuthSession sessionHandle, out ReadOnlySpan<byte> nonceCaller, out TpmaSession sessionAttributes, out ReadOnlySpan<byte> hmac, out malformedResponseCode))
        {
            return false;
        }

        if(!TryEndAuthArea(ref reader, sessionsStart, authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        //TPM2_Clear() carries no parameters, so the raw parameter area is always empty — still captured so
        //cpHash is built the same way for every session-authorized command.
        ReadOnlySpan<byte> rawParameterAreaOctets = reader.PeekBytes(reader.Remaining);

        //No parameters follow the authorization area; any surplus is malformed (Part 3, clause 5.2).
        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //The session slot's own two credentials are rented here alongside the rest, the parse's last act after
        //every wire check has passed, so no refused parse ever creates one. A TPM_RS_PW slot carries no caller
        //nonce at all (its width rule already refused a non-empty one), so only its credential is rented.
        Tpm2bAuth slotCredential = Tpm2bAuth.Empty;
        Tpm2bNonce slotNonce = Tpm2bNonce.Empty;
        TpmParameterArea parameterArea = TpmParameterArea.Empty;
        try
        {
            slotCredential = Tpm2bAuth.Create(hmac, pool);
            slotNonce = sessionHandle.IsPasswordSession ? Tpm2bNonce.Empty : Tpm2bNonce.Create(nonceCaller, pool);
            parameterArea = sessionHandle.IsPasswordSession ? TpmParameterArea.Empty : TpmParameterArea.Create(rawParameterAreaOctets, pool);

            input = sessionHandle.IsPasswordSession
                ? new TpmClearRequested(TpmiRhClear.FromValue(authHandle), slotCredential)
                : new TpmClearOverSessionRequested(TpmiRhClear.FromValue(authHandle), sessionHandle, slotNonce, sessionAttributes, slotCredential, parameterArea);
        }
        catch
        {
            //These carriers' only owner is this frame until the request adopts them, so a failing later rent
            //must release them or the pinned rentals are orphaned.
            parameterArea.Dispose();
            slotNonce.Dispose();
            slotCredential.Dispose();
            throw;
        }

        return true;
    }

    /// <summary>
    /// <c>TPM2_ClearControl()</c> is authorized: handle area (<c>@auth</c>, 1 handle), authorization area (a
    /// single session), then the sole parameter <c>disable</c> as a <c>TPMI_YES_NO</c> (TPM 2.0 Library Part 3,
    /// clause 24.7.2, Table 186).
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parse-rented parameter-area carrier and of the authorization slot's own two credential carriers — its caller nonce and its supplied hmac — transfers to the constructed request input; the consuming continuation releases the credential and the parameter area per carrier and transfers the nonce into the response framing, and every refusing arm releases all three through the input's own Dispose; a rent that fails after an earlier carrier already succeeded releases it in the catch before rethrowing.")]
    private static bool TryParseClearControl(ref TpmReader reader, ushort tag, BaseMemoryPool pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(tag != (ushort)TpmStConstants.TPM_ST_SESSIONS)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_AUTH_MISSING;

            return false;
        }

        //Handle area: @auth (the authorizing hierarchy).
        if(reader.Remaining < sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint authHandle = reader.ReadUInt32();

        if(!TryBeginAuthArea(ref reader, out int sessionsStart, out uint authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        if(!TryReadCommandSessionSpans(ref reader, sessionIndex: 0, out TpmiShAuthSession sessionHandle, out ReadOnlySpan<byte> nonceCaller, out TpmaSession sessionAttributes, out ReadOnlySpan<byte> hmac, out malformedResponseCode))
        {
            return false;
        }

        if(!TryEndAuthArea(ref reader, sessionsStart, authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        //The parameter area is captured verbatim before it is decoded, since it is cpHash's parameters term
        //(Part 1, clause 16.7 equation 15).
        ReadOnlySpan<byte> rawParameterAreaOctets = reader.PeekBytes(reader.Remaining);

        //Parameter: disable (TPMI_YES_NO, a single octet).
        if(reader.Remaining < sizeof(byte))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        TpmiYesNo disable = TpmiYesNo.Parse(ref reader);

        //disable is the final parameter; no octets may follow it (Part 3, clause 5.2).
        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //The session slot's own two credentials are rented here alongside the rest, the parse's last act after
        //every wire check has passed, so no refused parse ever creates one. A TPM_RS_PW slot carries no caller
        //nonce at all (its width rule already refused a non-empty one), so only its credential is rented.
        Tpm2bAuth slotCredential = Tpm2bAuth.Empty;
        Tpm2bNonce slotNonce = Tpm2bNonce.Empty;
        TpmParameterArea parameterArea = TpmParameterArea.Empty;
        try
        {
            slotCredential = Tpm2bAuth.Create(hmac, pool);
            slotNonce = sessionHandle.IsPasswordSession ? Tpm2bNonce.Empty : Tpm2bNonce.Create(nonceCaller, pool);
            parameterArea = sessionHandle.IsPasswordSession ? TpmParameterArea.Empty : TpmParameterArea.Create(rawParameterAreaOctets, pool);

            input = sessionHandle.IsPasswordSession
                ? new TpmClearControlRequested(TpmiRhClear.FromValue(authHandle), slotCredential, disable)
                : new TpmClearControlOverSessionRequested(TpmiRhClear.FromValue(authHandle), sessionHandle, slotNonce, sessionAttributes, slotCredential, parameterArea, disable);
        }
        catch
        {
            //These carriers' only owner is this frame until the request adopts them, so a failing later rent
            //must release them or the pinned rentals are orphaned.
            parameterArea.Dispose();
            slotNonce.Dispose();
            slotCredential.Dispose();
            throw;
        }

        return true;
    }

    /// <summary>
    /// <c>TPM2_HierarchyControl()</c> is authorized: handle area (<c>@authHandle</c>, 1 handle), authorization
    /// area (a single session), then the parameters <c>enable</c> (<c>TPMI_RH_ENABLES</c>, a handle-valued
    /// UINT32) and <c>state</c> (<c>TPMI_YES_NO</c>) (TPM 2.0 Library Part 3, clause 24.2.2, Table 176).
    /// </summary>
    /// <remarks>
    /// <c>enable</c> is a parameter that happens to carry a handle value, not a handle-area entry: it names the
    /// bit being written rather than an entity being authorized, which is why it is read here after the
    /// authorization area rather than before it.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parse-rented parameter-area carrier and of the authorization slot's own two credential carriers — its caller nonce and its supplied hmac — transfers to the constructed request input; the consuming continuation releases the credential and the parameter area per carrier and transfers the nonce into the response framing, and every refusing arm releases all three through the input's own Dispose; a rent that fails after an earlier carrier already succeeded releases it in the catch before rethrowing.")]
    private static bool TryParseHierarchyControl(ref TpmReader reader, ushort tag, BaseMemoryPool pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(tag != (ushort)TpmStConstants.TPM_ST_SESSIONS)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_AUTH_MISSING;

            return false;
        }

        //Handle area: @authHandle (the authorizing hierarchy).
        if(reader.Remaining < sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint authHandle = reader.ReadUInt32();

        if(!TryBeginAuthArea(ref reader, out int sessionsStart, out uint authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        if(!TryReadCommandSessionSpans(ref reader, sessionIndex: 0, out TpmiShAuthSession sessionHandle, out ReadOnlySpan<byte> nonceCaller, out TpmaSession sessionAttributes, out ReadOnlySpan<byte> hmac, out malformedResponseCode))
        {
            return false;
        }

        if(!TryEndAuthArea(ref reader, sessionsStart, authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        ReadOnlySpan<byte> rawParameterAreaOctets = reader.PeekBytes(reader.Remaining);

        //Parameters: enable (UINT32) then state (a single octet).
        if(reader.Remaining < sizeof(uint) + sizeof(byte))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint enable = reader.ReadUInt32();
        TpmiYesNo state = TpmiYesNo.Parse(ref reader);

        //state is the final parameter; no octets may follow it (Part 3, clause 5.2).
        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //The session slot's own two credentials are rented here alongside the rest, the parse's last act after
        //every wire check has passed, so no refused parse ever creates one. A TPM_RS_PW slot carries no caller
        //nonce at all (its width rule already refused a non-empty one), so only its credential is rented.
        Tpm2bAuth slotCredential = Tpm2bAuth.Empty;
        Tpm2bNonce slotNonce = Tpm2bNonce.Empty;
        TpmParameterArea parameterArea = TpmParameterArea.Empty;
        try
        {
            slotCredential = Tpm2bAuth.Create(hmac, pool);
            slotNonce = sessionHandle.IsPasswordSession ? Tpm2bNonce.Empty : Tpm2bNonce.Create(nonceCaller, pool);
            parameterArea = sessionHandle.IsPasswordSession ? TpmParameterArea.Empty : TpmParameterArea.Create(rawParameterAreaOctets, pool);

            input = sessionHandle.IsPasswordSession
                ? new TpmHierarchyControlRequested(TpmiRhBaseHierarchy.FromValue(authHandle), slotCredential, TpmiRhEnables.FromValue(enable), state)
                : new TpmHierarchyControlOverSessionRequested(TpmiRhBaseHierarchy.FromValue(authHandle), sessionHandle, slotNonce, sessionAttributes, slotCredential, parameterArea, TpmiRhEnables.FromValue(enable), state);
        }
        catch
        {
            //These carriers' only owner is this frame until the request adopts them, so a failing later rent
            //must release them or the pinned rentals are orphaned.
            parameterArea.Dispose();
            slotNonce.Dispose();
            slotCredential.Dispose();
            throw;
        }

        return true;
    }

    /// <summary>
    /// <c>TPM2_SetPrimaryPolicy()</c> is authorized: handle area (<c>@authHandle</c>, 1 handle), authorization
    /// area (a single session), then the parameters <c>authPolicy</c> (<c>TPM2B_DIGEST</c>) and <c>hashAlg</c>
    /// (<c>TPMI_ALG_HASH+</c>, a UINT16) (TPM 2.0 Library Part 3, clause 24.3.2, Table 178).
    /// </summary>
    /// <remarks>
    /// <c>authPolicy</c> is a sized parameter, but it is a public digest rather than a secret, so this command
    /// declares no decrypt-session shape: the value a caller installs is exactly what any later
    /// <c>TPM2_PolicyGetDigest()</c> would reveal anyway.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parse-rented policy-digest, parameter-area and authorization-slot credential carriers transfers to the constructed request input, whose installing transition hands the policy digest to the hierarchy policy slot, whose continuation releases the slot credential and transfers its caller nonce into the response framing, and whose refusing arms dispose them all through the input's own Dispose; a rent that fails after an earlier carrier already succeeded releases it in the catch before rethrowing.")]
    private static bool TryParseSetPrimaryPolicy(ref TpmReader reader, ushort tag, BaseMemoryPool pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(tag != (ushort)TpmStConstants.TPM_ST_SESSIONS)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_AUTH_MISSING;

            return false;
        }

        //Handle area: @authHandle (the entity whose policy is being set).
        if(reader.Remaining < sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint authHandle = reader.ReadUInt32();

        if(!TryBeginAuthArea(ref reader, out int sessionsStart, out uint authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        if(!TryReadCommandSessionSpans(ref reader, sessionIndex: 0, out TpmiShAuthSession sessionHandle, out ReadOnlySpan<byte> nonceCaller, out TpmaSession sessionAttributes, out ReadOnlySpan<byte> hmac, out malformedResponseCode))
        {
            return false;
        }

        if(!TryEndAuthArea(ref reader, sessionsStart, authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        ReadOnlySpan<byte> rawParameterAreaOctets = reader.PeekBytes(reader.Remaining);

        if(!TryReadTpm2bSpan(ref reader, out ReadOnlySpan<byte> authPolicy, out malformedResponseCode))
        {
            return false;
        }

        //A TPM2B_DIGEST buffer can be no wider than sizeof(TPMU_HA) (TPM 2.0 Library Part 2, clause 10.4.2,
        //Table 92), so the wire bound is answered here — ahead of the rental, whose Create refuses the same
        //bound by throwing. The installing transition's exact hashAlg-width gate stays as the fail-closed
        //backstop, so the size rule is proved at both layers.
        if(authPolicy.Length > Tpm2bDigest.MaxSize)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //Parameter: hashAlg (TPM_ALG_ID, a UINT16).
        if(reader.Remaining < sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        TpmiAlgHash hashAlg = TpmiAlgHash.FromValue((TpmAlgIdConstants)reader.ReadUInt16());

        //hashAlg is the final parameter; no octets may follow it (Part 3, clause 5.2).
        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //The policy digest and the session arm's parameter area ride owned pooled carriers rented here, the
        //parse's last act after every wire check has passed, so no refused parse ever creates one.
        TpmParameterArea parameterArea = sessionHandle.IsPasswordSession
            ? TpmParameterArea.Empty
            : TpmParameterArea.Create(rawParameterAreaOctets, pool);
        Tpm2bAuth slotCredential = Tpm2bAuth.Empty;
        Tpm2bNonce slotNonce = Tpm2bNonce.Empty;
        try
        {
            slotCredential = Tpm2bAuth.Create(hmac, pool);
            slotNonce = sessionHandle.IsPasswordSession ? Tpm2bNonce.Empty : Tpm2bNonce.Create(nonceCaller, pool);

            input = sessionHandle.IsPasswordSession
                ? new TpmSetPrimaryPolicyRequested(TpmiRhHierarchyPolicy.FromValue(authHandle), slotCredential, Tpm2bDigest.Create(authPolicy, pool), hashAlg)
                : new TpmSetPrimaryPolicyOverSessionRequested(TpmiRhHierarchyPolicy.FromValue(authHandle), sessionHandle, slotNonce, sessionAttributes, slotCredential, parameterArea, Tpm2bDigest.Create(authPolicy, pool), hashAlg);
        }
        catch
        {
            //These carriers' only owner is this frame until the request adopts them, so a failing later rent
            //must release them or the pinned rentals are orphaned.
            slotNonce.Dispose();
            slotCredential.Dispose();
            parameterArea.Dispose();
            throw;
        }

        return true;
    }

    /// <summary>
    /// <c>TPM2_HierarchyChangeAuth()</c> is authorized: handle area (<c>@authHandle</c>, 1 handle), authorization
    /// area (one or two sessions), then the sole parameter <c>newAuth</c> as a <c>TPM2B_AUTH</c> (TPM 2.0 Library
    /// Part 3, clause 24.8.2, Table 188).
    /// </summary>
    /// <remarks>
    /// <para>
    /// A second session, when the declared authorizationSize accounts for one, is the separate <c>decrypt</c>
    /// companion that protects <c>newAuth</c> in flight — the same two-session shape
    /// <see cref="TryParseNvChangeAuth"/> reads for the NV family's own authValue rotation. <c>newAuth</c> is
    /// captured as received, ciphertext included: its 2-octet size prefix is never itself encrypted (Part 1,
    /// clause 19.1), so the field can be delimited before anything is decrypted.
    /// </para>
    /// <para>
    /// The plain form is the LONE password area, and the fork says so structurally: a <c>TPM_RS_PW</c> slot 0 is
    /// the plain <see cref="TpmHierarchyChangeAuthRequested"/> only when the declared authorizationSize accounted
    /// for that one block and nothing more. An area that carried a second block is always the session-shaped
    /// record, whatever slot 0 named, because that block must be resolved, validated, HMAC-verified, and answered
    /// with a response entry of its own — Part 3, clause 5.5, step 4 walks every unmarshaled session in turn,
    /// clause 5.6 applies to every session in the area, and Part 1, clause 16.6.1's "If the responseCode is
    /// TPM_RC_SUCCESS, the response has the same number of sessions in the same order as the request" owes it an
    /// entry. Forking on the handle alone would take a <c>[password, decrypt]</c> area down the plain path, where
    /// the companion is never seen and the ciphertext it protects is installed verbatim as the hierarchy's
    /// authorization value. <c>TryParseCreate</c> draws the same structural fork for the same reason.
    /// </para>
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parse-rented authValue, parameter-area and per-slot credential carriers transfers to the constructed request input, whose installing transition adopts the authValue into durable state, whose completing tail releases both slots' credentials and transfers each slot's caller nonce into that slot's response entry, and whose refusing arms dispose them all through the input's own Dispose; a rent that fails after an earlier carrier already succeeded releases it in the catch before rethrowing.")]
    private static bool TryParseHierarchyChangeAuth(ref TpmReader reader, ushort tag, BaseMemoryPool pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(tag != (ushort)TpmStConstants.TPM_ST_SESSIONS)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_AUTH_MISSING;

            return false;
        }

        //Handle area: @authHandle (the entity whose authValue is being replaced).
        if(reader.Remaining < sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint authHandle = reader.ReadUInt32();

        if(!TryBeginAuthArea(ref reader, out int sessionsStart, out uint authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        if(!TryReadCommandSessionSpans(ref reader, sessionIndex: 0, out TpmiShAuthSession sessionHandle, out ReadOnlySpan<byte> nonceCaller, out TpmaSession sessionAttributes, out ReadOnlySpan<byte> hmac, out malformedResponseCode))
        {
            return false;
        }

        TpmiShAuthSession decryptHandle = TpmiShAuthSession.FromValue(0);
        TpmaSession decryptAttributes = default;

        //The companion slot's span locals are declared scoped so they can receive slices that alias the command
        //buffer the by-reference reader points into: without it the compiler must assume a span written through
        //an out parameter of a ref-taking method could outlive that buffer.
        scoped ReadOnlySpan<byte> decryptNonceCaller = ReadOnlySpan<byte>.Empty;
        scoped ReadOnlySpan<byte> decryptHmac = ReadOnlySpan<byte>.Empty;

        bool isSingleSession = reader.Consumed - sessionsStart == (int)authorizationSize;
        if(!isSingleSession)
        {
            if(!TryReadCommandSessionSpans(ref reader, sessionIndex: 1, out decryptHandle, out decryptNonceCaller, out decryptAttributes, out decryptHmac, out malformedResponseCode))
            {
                return false;
            }
        }

        if(!TryEndAuthArea(ref reader, sessionsStart, authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        //newAuth is the entire parameter area, captured verbatim before it is decoded as cpHash's parameters
        //term. The capture is an exclusive copy, which is what lets the decrypt effect transform it in place.
        ReadOnlySpan<byte> rawParameterAreaOctets = reader.PeekBytes(reader.Remaining);

        if(!TryReadTpm2bSpan(ref reader, out ReadOnlySpan<byte> newAuth, out malformedResponseCode))
        {
            return false;
        }

        //A TPM2B_AUTH buffer can be no wider than sizeof(TPMU_HA) (TPM 2.0 Library Part 2, clause 10.4.5, Table
        //95, which types it as a TPM2B_DIGEST, and clause 10.4.2, Table 92, which bounds that structure's
        //buffer). The wire bound is answered here, ahead of the rental whose Create refuses the same bound by
        //throwing; the command's own narrower per-entity rule — no wider than the digest of the entity's nameAlg
        //(clause 10.4.5's prose) — stays where it is, on the installing transition.
        if(newAuth.Length > Tpm2bAuth.MaxSize)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //newAuth is the last parameter, so no octets may follow it (Part 3, clause 5.2).
        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //The parameter area and the replacement authValue are rented into their owned carriers only now, after
        //every shape check has passed, so no refused parse ever creates one; when a decrypt session accompanied
        //the command both hold ciphertext, the authValue's being superseded by the decrypt effect's own output
        //while the parameter area is transformed in place.
        bool isPasswordArm = isSingleSession && sessionHandle.IsPasswordSession;
        TpmParameterArea parameterArea = TpmParameterArea.Empty;
        Tpm2bAuth slotCredential = Tpm2bAuth.Empty;
        Tpm2bNonce slotNonce = Tpm2bNonce.Empty;
        Tpm2bAuth decryptCredential = Tpm2bAuth.Empty;
        Tpm2bNonce decryptNonce = Tpm2bNonce.Empty;
        try
        {
            parameterArea = isPasswordArm ? TpmParameterArea.Empty : TpmParameterArea.Create(rawParameterAreaOctets, pool);
            slotCredential = Tpm2bAuth.Create(hmac, pool);
            slotNonce = sessionHandle.IsPasswordSession ? Tpm2bNonce.Empty : Tpm2bNonce.Create(nonceCaller, pool);
            decryptCredential = isSingleSession ? Tpm2bAuth.Empty : Tpm2bAuth.Create(decryptHmac, pool);
            decryptNonce = isSingleSession ? Tpm2bNonce.Empty : Tpm2bNonce.Create(decryptNonceCaller, pool);

            input = isPasswordArm
                ? new TpmHierarchyChangeAuthRequested(TpmiRhHierarchyAuth.FromValue(authHandle), slotCredential, Tpm2bAuth.Create(newAuth, pool))
                : new TpmHierarchyChangeAuthOverSessionRequested(
                    TpmiRhHierarchyAuth.FromValue(authHandle), sessionHandle, slotNonce, sessionAttributes, slotCredential,
                    !isSingleSession, decryptHandle, decryptNonce, decryptAttributes, decryptCredential,
                    parameterArea, Tpm2bAuth.Create(newAuth, pool));
        }
        catch
        {
            //These carriers' only owner is this frame until the request adopts them, so a failing later rent
            //must release them or the pinned rentals are orphaned.
            decryptNonce.Dispose();
            decryptCredential.Dispose();
            slotNonce.Dispose();
            slotCredential.Dispose();
            parameterArea.Dispose();
            throw;
        }

        return true;
    }

    /// <summary>
    /// <c>TPM2_NV_Certify()</c> is authorized and takes three handles, two of which require authorization: the
    /// wire layout after the header is handle area (@signHandle, @authHandle, nvIndex — Part 3, clause 31.16.2,
    /// Table 254), then parameters (qualifyingData as TPM2B_DATA, inScheme as TPMT_SIG_SCHEME, size as UINT16,
    /// offset as UINT16).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The authorization area carries two required sessions in handle order — session 1 authorizes signHandle,
    /// session 2 authorizes authHandle (Table 254 gives both Auth Role USER) — optionally followed by a third,
    /// companion slot that authorizes nothing (Part 1, clause 16.6.1, Table 9). Each is read generically with
    /// <c>TryReadCommandSessionSpans</c>, the span-returning shape a parse that rents its own carriers needs, and
    /// the slot count comes from the declared authorization size rather than being assumed. A
    /// <c>TPMS_AUTH_COMMAND</c>'s wire layout is the same for a password session and a real one, so the parsed
    /// sessionHandles and the presence of a companion decide the form: two LONE <c>TPM_RS_PW</c> handles make
    /// this <see cref="TpmNvCertifyRequested"/>, and any other combination — including two password slots
    /// alongside a companion — makes it <see cref="TpmNvCertifyOverSessionRequested"/>.
    /// </para>
    /// <para>
    /// The slots are decided independently rather than as a pair, because mixed forms are legal wire: nothing in
    /// Table 254 couples one handle's authorization mechanism to the other's. Every field of every session is
    /// captured rather than consumed-and-discarded — the parser records what arrived and the transition decides
    /// what each slot may authorize.
    /// </para>
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parse-rented sign-slot credential, authorizing-slot credential, companion-slot credential, all three slots' caller nonces, and qualifying-data carriers transfers to the constructed request input, whose consuming transition (password) or continuation (session) releases them or transfers them into the NV-certify action and its response-session entries, and whose refusing arms dispose them through the input's own Dispose; a rent that fails after an earlier carrier already succeeded releases it in the catch before rethrowing.")]
    private static bool TryParseNvCertify(ref TpmReader reader, ushort tag, BaseMemoryPool pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(tag != (ushort)TpmStConstants.TPM_ST_SESSIONS)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_AUTH_MISSING;

            return false;
        }

        //Handle area: @signHandle, @authHandle, nvIndex.
        if(reader.Remaining < 3 * sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        TpmiDhObject signHandle = TpmiDhObject.FromValue(reader.ReadUInt32());
        TpmiRhNvAuth authHandle = TpmiRhNvAuth.FromValue(reader.ReadUInt32());
        TpmiRhNvIndex nvIndex = TpmiRhNvIndex.FromValue(reader.ReadUInt32());

        if(!TryBeginAuthArea(ref reader, out int sessionsStart, out uint authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        //Session 1 authorizes signHandle — the signing key's own USER-role authorization, verified by the
        //transitions on both arms (the all-password form compares the captured password against the signing
        //key's retained authValue exactly as TPM2_Certify()/TPM2_Quote()/TPM2_GetTime() do; the session form
        //compares a password slot inline or verifies a real command HMAC after the Name hop). Every field is
        //captured: a real session here owes a genuine response entry.
        if(!TryReadCommandSessionSpans(ref reader, sessionIndex: 0, out TpmiShAuthSession signSessionHandle, out ReadOnlySpan<byte> signNonceCaller, out TpmaSession signSessionAttributes, out ReadOnlySpan<byte> signHmac, out malformedResponseCode))
        {
            return false;
        }

        //Session 2 authorizes authHandle; this is the slot whose authorization is actually evaluated, over a
        //password compare or a command HMAC depending on the handle it names.
        if(!TryReadCommandSessionSpans(ref reader, sessionIndex: 1, out TpmiShAuthSession authSessionHandle, out ReadOnlySpan<byte> authNonceCaller, out TpmaSession authSessionAttributes, out ReadOnlySpan<byte> authHmac, out malformedResponseCode))
        {
            return false;
        }

        //Octets left inside the declared authorization size after the last REQUIRED slot are a companion slot
        //(Part 1, clause 16.6.1, Table 9, position after the authorization sessions).
        bool hasCompanion = reader.Consumed - sessionsStart != (int)authorizationSize;
        TpmiShAuthSession companionSessionHandle = TpmiShAuthSession.FromValue(0);
        TpmaSession companionSessionAttributes = default;

        //The two span locals are declared scoped so they can receive slices that alias the command buffer the
        //by-reference reader points into: without it the compiler must assume a span written through an out
        //parameter of a ref-taking method could outlive that buffer.
        scoped ReadOnlySpan<byte> companionNonceCaller = ReadOnlySpan<byte>.Empty;
        scoped ReadOnlySpan<byte> companionHmac = ReadOnlySpan<byte>.Empty;
        if(hasCompanion
            && !TryReadCommandSessionSpans(ref reader, sessionIndex: 2, out companionSessionHandle, out companionNonceCaller, out companionSessionAttributes, out companionHmac, out malformedResponseCode))
        {
            return false;
        }

        if(!TryEndAuthArea(ref reader, sessionsStart, authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        //NV_Certify's entire parameter set (qualifyingData ‖ inScheme ‖ size ‖ offset) is every octet left after
        //the authorization area — captured verbatim, before any field is decoded, as the session arm's cpHash
        //parameter term (Part 1, clause 16.7 equation 15).
        ReadOnlySpan<byte> rawParameterAreaOctets = reader.PeekBytes(reader.Remaining);

        //Which arm the area belongs to is settled before the parameters are read, because it decides how
        //qualifyingData may be treated: two LONE TPM_RS_PW slots are the all-password form the password arm
        //serves, while any other combination — a mixed one, or two password slots alongside a companion — is the
        //session arm, whose response owes at least one real entry.
        bool isAllPassword = signSessionHandle.IsPasswordSession && authSessionHandle.IsPasswordSession && !hasCompanion;

        //Parameter: qualifyingData (TPM2B_DATA) — the caller nonce echoed into the attestation, and the first
        //command parameter, which is the one a decrypt session protects (Part 1, clause 16.4). On the session
        //form these octets may be CIPHERTEXT, so the parse only steps over the field's framing to reach the
        //parameters behind it and the decrypt step supplies the plaintext (Part 3, clause 5.7 precedes clause
        //5.8); decoding here would also be futile, since a separately copied field is not updated by the in-place
        //transform of the captured area. On the password form no session can protect it, so it is read as a span
        //over the command buffer whose owning carrier is rented as this parse's last act.
        scoped ReadOnlySpan<byte> qualifyingData = ReadOnlySpan<byte>.Empty;
        if(isAllPassword)
        {
            if(!TryReadTpm2bSpan(ref reader, out qualifyingData, out malformedResponseCode))
            {
                return false;
            }

            //TPM2B_DATA is bounded by sizeof(TPMT_HA) (Part 2, clause 10.4.3, Table 93), so a wider value is
            //TPM_RC_SIZE here, before any carrier is rented; the consuming transition's own bound check stands as
            //the fail-closed backstop. The session form's bound is applied to the RECOVERED value instead, which
            //is the only form of it TPM2B_DATA is about.
            if(qualifyingData.Length > Tpm2bData.MaxSize)
            {
                malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

                return false;
            }
        }
        else if(!TrySkipTpm2b(ref reader, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: inScheme (TPMT_SIG_SCHEME) — scheme selector (UINT16) + hash algorithm (UINT16). It sits
        //behind the first parameter and so is never encrypted, which is why it is decoded on both arms alike.
        if(reader.Remaining < 2 * sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        TpmiAlgSigScheme signatureScheme = TpmiAlgSigScheme.FromValue((TpmAlgIdConstants)reader.ReadUInt16());
        TpmiAlgHash schemeHashAlg = TpmiAlgHash.FromValue((TpmAlgIdConstants)reader.ReadUInt16());

        //Parameters: size (UINT16) + offset (UINT16).
        if(reader.Remaining < 2 * sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        ushort size = reader.ReadUInt16();
        ushort offset = reader.ReadUInt16();

        //offset is the final parameter; no octets may follow it (Part 3, 5.2).
        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //Either form's owned pooled carriers are rented here, the parse's last act after every wire check has
        //passed, so no refused parse ever creates one.
        Tpm2bAuth suppliedSignCredential = Tpm2bAuth.Empty;
        Tpm2bAuth suppliedAuthorizingCredential = Tpm2bAuth.Empty;
        Tpm2bNonce signNonce = Tpm2bNonce.Empty;
        Tpm2bNonce authorizingNonce = Tpm2bNonce.Empty;
        Tpm2bAuth companionCredential = Tpm2bAuth.Empty;
        Tpm2bNonce companionNonce = Tpm2bNonce.Empty;
        TpmParameterArea parameterArea = TpmParameterArea.Empty;
        try
        {
            suppliedSignCredential = Tpm2bAuth.Create(signHmac, pool);
            suppliedAuthorizingCredential = Tpm2bAuth.Create(authHmac, pool);

            //Only the session arm retains the slots' caller nonces, so only it rents them — and it rents BOTH,
            //because a mixed area's TPM_RS_PW slot still owes its own response entry (Part 1, clause 16.6.1).
            signNonce = isAllPassword ? Tpm2bNonce.Empty : Tpm2bNonce.Create(signNonceCaller, pool);
            authorizingNonce = isAllPassword ? Tpm2bNonce.Empty : Tpm2bNonce.Create(authNonceCaller, pool);
            companionCredential = hasCompanion ? Tpm2bAuth.Create(companionHmac, pool) : Tpm2bAuth.Empty;
            companionNonce = hasCompanion ? Tpm2bNonce.Create(companionNonceCaller, pool) : Tpm2bNonce.Empty;
            parameterArea = isAllPassword ? TpmParameterArea.Empty : TpmParameterArea.Create(rawParameterAreaOctets, pool);
            input = isAllPassword
                ? new TpmNvCertifyRequested(
                    signHandle, authHandle, nvIndex, suppliedSignCredential, suppliedAuthorizingCredential,
                    Tpm2bData.Create(qualifyingData, pool), signatureScheme, schemeHashAlg, size, offset)
                : new TpmNvCertifyOverSessionRequested(
                    signHandle, authHandle, nvIndex,
                    signSessionHandle, signNonce, signSessionAttributes, suppliedSignCredential,
                    authSessionHandle, authorizingNonce, authSessionAttributes, suppliedAuthorizingCredential,
                    Tpm2bData.Empty, signatureScheme, schemeHashAlg, size, offset, parameterArea,
                    hasCompanion, companionSessionHandle, companionNonce, companionSessionAttributes, companionCredential, Tpm2bName.Empty);
        }
        catch
        {
            //These carriers' only owner is this frame until the request adopts them, so a failing later rent
            //must release them or the pinned rentals are orphaned.
            parameterArea.Dispose();
            companionNonce.Dispose();
            companionCredential.Dispose();
            authorizingNonce.Dispose();
            signNonce.Dispose();
            suppliedAuthorizingCredential.Dispose();
            suppliedSignCredential.Dispose();
            throw;
        }

        return true;
    }

    /// <summary>
    /// <c>TPM2_VerifySignature()</c> authorizes no entity — keyHandle needs no authorization at all (Part 3,
    /// clause 20.1) — so only the no-sessions form is modelled; a sessions tag would carry an authorization area
    /// this command has no handle for. Its wire layout after the header is: handle area (@keyHandle, 1 handle),
    /// then parameters (digest as TPM2B_DIGEST, signature as TPMT_SIGNATURE: sigAlg selecting the ECDSA r/s
    /// TPM2B pair or the single RSA TPM2B signature).
    /// </summary>
    /// <remarks>
    /// Each TPM2B is read through the already bounds-checked <c>TryReadTpm2b</c>, mirroring the command-input
    /// parsing convention used throughout this file, rather than the host-side <c>TpmuSignature.Parse</c> (built
    /// for trusted response parsing, where an out-of-bounds size throws instead of failing closed).
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parse-rented digest carrier transfers to the constructed request input, whose consuming transition hands it to the verification action for the effect to release, and whose refusing arms dispose it through the input's own Dispose.")]
    private static bool TryParseVerifySignature(ref TpmReader reader, ushort tag, BaseMemoryPool pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(tag != (ushort)TpmStConstants.TPM_ST_NO_SESSIONS)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_BAD_TAG;

            return false;
        }

        //Handle area: @keyHandle (the key whose public part verifies the signature).
        if(reader.Remaining < sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint keyHandle = reader.ReadUInt32();

        //Parameter: digest (TPM2B_DIGEST) — the digest the signature is claimed to be over.
        if(!TryReadTpm2bSpan(ref reader, out ReadOnlySpan<byte> digest, out malformedResponseCode))
        {
            return false;
        }

        //A TPM2B_DIGEST buffer can be no wider than sizeof(TPMU_HA) (TPM 2.0 Library Part 2, clause 10.4.2,
        //Table 92), so the wire bound is answered here, ahead of the rental whose Create refuses the same bound
        //by throwing.
        if(digest.Length > Tpm2bDigest.MaxSize)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //Parameter: signature (TPMT_SIGNATURE) — sigAlg (TPMI_ALG_SIG_SCHEME) selects the union member.
        if(reader.Remaining < sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        TpmiAlgSigScheme sigAlg = TpmiAlgSigScheme.FromValue((TpmAlgIdConstants)reader.ReadUInt16());
        if(sigAlg.Value is not (TpmAlgIdConstants.TPM_ALG_ECDSA or TpmAlgIdConstants.TPM_ALG_RSASSA or TpmAlgIdConstants.TPM_ALG_RSAPSS))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SCHEME;

            return false;
        }

        if(reader.Remaining < sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        TpmiAlgHash hashAlg = TpmiAlgHash.FromValue((TpmAlgIdConstants)reader.ReadUInt16());

        ReadOnlyMemory<byte> signature;
        if(sigAlg.Value == TpmAlgIdConstants.TPM_ALG_ECDSA)
        {
            //TPMS_SIGNATURE_ECDSA: signatureR then signatureS, each a TPM2B_ECC_PARAMETER — concatenated into one
            //IEEE P1363 r ‖ s buffer, the shape the verify delegate takes (the mirror of how the response
            //serializer splits a P1363 signature into r and s when framing TPM2_Sign()/TPM2_Certify() and friends).
            if(!TryReadTpm2b(ref reader, out ReadOnlyMemory<byte> signatureR, out malformedResponseCode))
            {
                return false;
            }

            if(!TryReadTpm2b(ref reader, out ReadOnlyMemory<byte> signatureS, out malformedResponseCode))
            {
                return false;
            }

            signature = ConcatenateEcdsaSignature(signatureR, signatureS);
        }
        else
        {
            //TPMS_SIGNATURE_RSA: the whole signature as one TPM2B_PUBLIC_KEY_RSA.
            if(!TryReadTpm2b(ref reader, out ReadOnlyMemory<byte> rsaSignature, out malformedResponseCode))
            {
                return false;
            }

            signature = rsaSignature;
        }

        //signature is the final parameter; no octets may follow it (Part 3, 5.2).
        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //The owned pooled digest carrier is rented here, the parse's last act after every wire check has passed,
        //so no refused parse ever creates one.
        input = new TpmVerifySignatureRequested(TpmiDhObject.FromValue(keyHandle), Tpm2bDigest.Create(digest, pool), sigAlg, hashAlg, signature);

        return true;

        static ReadOnlyMemory<byte> ConcatenateEcdsaSignature(ReadOnlyMemory<byte> r, ReadOnlyMemory<byte> s)
        {
            byte[] concatenated = new byte[r.Length + s.Length];
            r.Span.CopyTo(concatenated);
            s.Span.CopyTo(concatenated.AsSpan(r.Length));

            return concatenated;
        }
    }

    /// <summary>
    /// <c>TPM2_MakeCredential()</c> takes no authorization (it uses only the credential key's public area), so
    /// its wire layout after the header is: handle area (@handle — 1 handle, the credential key, no auth), then
    /// parameters (credential as TPM2B_DIGEST, objectName as TPM2B_NAME). It is framed with
    /// <c>TPM_ST_NO_SESSIONS</c> (TPM 2.0 Library Part 3, clause 12.6).
    /// </summary>
    /// <remarks>
    /// The credential is copied into durable model memory and the bound Name rides an owned pooled
    /// <c>TPM2B_NAME</c> carrier rented as the parse's last act, so no refused parse ever creates one.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parse-rented object-Name carrier transfers to the constructed request input, whose consuming transition transfers it into the wrap action for the effect to release, and whose refusing arms dispose it through the input's own Dispose.")]
    private static bool TryParseMakeCredential(ref TpmReader reader, ushort tag, BaseMemoryPool pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        //MakeCredential authorizes no entity, so only the no-sessions form is modelled; a sessions tag would carry an
        //authorization area this command has no handle for.
        if(tag != (ushort)TpmStConstants.TPM_ST_NO_SESSIONS)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_BAD_TAG;

            return false;
        }

        //Handle area: @handle (the credential key).
        if(reader.Remaining < sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint keyHandle = reader.ReadUInt32();

        //Parameter: credential (TPM2B_DIGEST) — the secret to wrap.
        if(!TryReadTpm2bSpan(ref reader, out ReadOnlySpan<byte> credential, out malformedResponseCode))
        {
            return false;
        }

        //A TPM2B_DIGEST buffer can be no wider than sizeof(TPMU_HA) (TPM 2.0 Library Part 2, clause 10.4.2,
        //Table 92), so the wire bound is answered here, ahead of the rental whose Create refuses the same bound
        //by throwing.
        if(credential.Length > Tpm2bDigest.MaxSize)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //Parameter: objectName (TPM2B_NAME) — the Name the credential is bound to (the attestation key's Name).
        if(!TryReadTpm2bSpan(ref reader, out ReadOnlySpan<byte> objectName, out malformedResponseCode))
        {
            return false;
        }

        //A TPM2B_NAME's content is bounded by sizeof(TPMU_NAME) — a 2-octet nameAlg plus the widest digest
        //(TPM 2.0 Library Part 2, clause 10.5.3, Table 104; the reference enforces it in TPM2B_NAME_Unmarshal),
        //so an oversized Name is refused here rather than reaching the carrier's own throwing bound.
        if(objectName.Length > Tpm2bName.MaxSize)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //objectName is the final parameter; no octets may follow it (Part 3, 5.2).
        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //The owned pooled credential and Name carriers are rented here, the parse's last act after every wire
        //check has passed, so no refused parse ever creates one.
        Tpm2bDigest credentialSecret = Tpm2bDigest.Empty;
        try
        {
            credentialSecret = Tpm2bDigest.Create(credential, pool);
            input = new TpmMakeCredentialRequested(TpmiDhObject.FromValue(keyHandle), credentialSecret, Tpm2bName.Create(objectName, pool));
        }
        catch
        {
            //This carrier's only owner is this frame until the request adopts it, so a failing later rent
            //must release it or the pinned rental is orphaned.
            credentialSecret.Dispose();
            throw;
        }

        return true;
    }

    /// <summary>
    /// <c>TPM2_ActivateCredential()</c> is authorized and takes two handles, so its wire layout after the header
    /// is: handle area (@activateHandle — the attestation key, ADMIN role; @keyHandle — the credential key, USER
    /// role — 2 handles, both require auth), authorization area, then parameters (credentialBlob as
    /// TPM2B_ID_OBJECT, secret as TPM2B_ENCRYPTED_SECRET). It is framed with <c>TPM_ST_SESSIONS</c> (TPM 2.0
    /// Library Part 3, clause 12.5). The blob and secret are copied into durable model memory.
    /// </summary>
    /// <remarks>
    /// The authorization area is read slot by slot: session 1 (@activateHandle, ADMIN role) stays password-only
    /// in this slice via <c>TryReadPasswordSessionBody</c> — no template this simulator builds sets adminWithPolicy, so a
    /// non-password session there keeps failing <c>TPM_RC_AUTH_TYPE</c>, today's behavior. Session 2 (@keyHandle,
    /// USER role) is read generically via <c>TryReadCommandSessionSpans</c>, mirroring
    /// <c>TryParseUnseal</c>'s first session: a standard endorsement key's authPolicy makes TPM_RS_PW
    /// insufficient there, so the wire form (not just the transition) must be able to carry a policy session
    /// handle. The transition, not the parser, resolves whether that handle names a real policy session and
    /// whether it satisfies the key's authPolicy.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parse-rented activate-password (and, for the plain form, key-password) carriers transfers to the constructed request input, whose consuming transition releases them once the per-slot compares have consumed them, and whose refusing arms dispose them through the input's own Dispose; the plain form's rent that fails after the activate carrier already succeeded releases it in the catch before rethrowing.")]
    private static bool TryParseActivateCredential(ref TpmReader reader, ushort tag, BaseMemoryPool pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(tag != (ushort)TpmStConstants.TPM_ST_SESSIONS)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_AUTH_MISSING;

            return false;
        }

        //Handle area: @activateHandle (the object the credential is bound to) then @keyHandle (the credential key).
        if(reader.Remaining < 2 * sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint activateHandle = reader.ReadUInt32();
        uint keyHandle = reader.ReadUInt32();

        if(!TryBeginAuthArea(ref reader, out int sessionsStart, out uint authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        //Session 1 authorizes @activateHandle (ADMIN role); password-only in this slice. The supplied value is
        //retained for the transition's activate-slot compare in both downstream forms.
        if(!TryReadPasswordSessionBody(ref reader, out ReadOnlySpan<byte> activatePassword, out malformedResponseCode))
        {
            return false;
        }

        //Session 2 authorizes @keyHandle (USER role): read generically so a policy session handle parses, then let
        //the transition resolve it (password vs. policy) exactly as Unseal's over-sessions form does. The hmac
        //field is retained for the plain TPM_RS_PW form's key-slot compare; a real policy session's command-side
        //HMAC verification remains out of scope here (only GetRandom-over-session and Unseal are chartered), so
        //the over-session form does not carry it.
        if(!TryReadCommandSessionSpans(ref reader, sessionIndex: 1, out TpmiShAuthSession keyPolicySession, out _, out TpmaSession keyPolicyAttributes, out ReadOnlySpan<byte> keyHmac, out malformedResponseCode))
        {
            return false;
        }

        //A third session in the area (for example an attempted encrypt session) is not modelled for this command;
        //TryEndAuthArea rejects the surplus naturally with TPM_RC_AUTHSIZE.
        if(!TryEndAuthArea(ref reader, sessionsStart, authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: credentialBlob (TPM2B_ID_OBJECT) — the credential from TPM2_MakeCredential().
        if(!TryReadTpm2b(ref reader, out ReadOnlyMemory<byte> credentialBlob, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: secret (TPM2B_ENCRYPTED_SECRET) — the encrypted seed from TPM2_MakeCredential().
        if(!TryReadTpm2b(ref reader, out ReadOnlyMemory<byte> secret, out malformedResponseCode))
        {
            return false;
        }

        //secret is the final parameter; no octets may follow it (Part 3, 5.2).
        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //The request, with its owned password carrier(s), is constructed as the parse's last act, so no refused
        //parse ever creates one.
        if(keyPolicySession.IsPasswordSession)
        {
            Tpm2bAuth suppliedActivatePassword = Tpm2bAuth.Empty;
            try
            {
                suppliedActivatePassword = Tpm2bAuth.Create(activatePassword, pool);
                input = new TpmActivateCredentialRequested(TpmiDhObject.FromValue(activateHandle), suppliedActivatePassword, TpmiDhObject.FromValue(keyHandle), Tpm2bAuth.Create(keyHmac, pool), credentialBlob, secret);
            }
            catch
            {
                //This carrier's only owner is this frame until the request adopts it, so a failing later rent
                //must release it or the pinned rental is orphaned.
                suppliedActivatePassword.Dispose();
                throw;
            }
        }
        else
        {
            input = new TpmActivateCredentialOverSessionRequested(TpmiDhObject.FromValue(activateHandle), Tpm2bAuth.Create(activatePassword, pool), TpmiDhObject.FromValue(keyHandle), credentialBlob, secret, keyPolicySession, keyPolicyAttributes);
        }

        return true;
    }

    /// <summary>
    /// <c>TPM2_PCR_Read()</c> takes no handles and no authorization (Part 3, clause 22.4): its wire body after
    /// the header is a single TPML_PCR_SELECTION parameter, and it is framed with <c>TPM_ST_NO_SESSIONS</c>.
    /// </summary>
    /// <remarks>The selection is captured verbatim (to echo as pcrSelectionOut) and decoded against the PCR bank in the transition.</remarks>
    private static bool TryParsePcrRead(ref TpmReader reader, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;

        if(!TryReadFinalPcrSelection(ref reader, out ReadOnlyMemory<byte> pcrSelection, out malformedResponseCode))
        {
            return false;
        }

        input = new TpmPcrReadRequested(pcrSelection);

        return true;
    }

    /// <summary>
    /// <c>TPM2_Quote()</c> is authorized and takes one handle, so its wire layout after the header is: handle
    /// area (@signHandle — 1 handle requiring authorization), authorization area (the @signHandle slot, either a
    /// <c>TPM_RS_PW</c> password whose hmac field is the plaintext authValue or a real HMAC session whose hmac is
    /// the command HMAC, optionally followed by one or two companion slots authorizing nothing), then parameters
    /// (qualifyingData as TPM2B_DATA, inScheme as TPMT_SIG_SCHEME, PCRselect as TPML_PCR_SELECTION). A lone
    /// password slot parses to <see cref="TpmQuoteRequested"/>; anything else, including a password slot
    /// ALONGSIDE a companion, parses to <see cref="TpmQuoteOverSessionRequested"/>, whose response owes one entry
    /// per slot (TPM 2.0 Library Part 1, clause 16.6.1).
    /// </summary>
    /// <remarks>
    /// The number of slots is read from the declared authorization size rather than assumed, the
    /// <c>TPM2_Create()</c> idiom: a slot that has not consumed the whole area leaves a companion behind it
    /// (Part 1, clause 16.6.1, Table 9 — "authorization sessions come before sessions used only for encryption,
    /// decryption, or audit"). One authorizing slot leaves BOTH of Table 9's later positions open, so the area may
    /// carry two companions; <c>TryEndAuthArea</c> answers <c>TPM_RC_AUTHSIZE</c> for a fourth slot or any surplus
    /// octet, which is the "no more than three" bound of clause 16.6.1. The scheme's validation is entirely in the
    /// signing scheme selector (Part 3, clause 18.4).
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parse-rented PCR selection, sign-slot credential, sign-slot caller nonce, both companion slots' credentials and caller nonces, and qualifying-data carriers transfers to the constructed request input, whose consuming transition (password) or continuation (session) releases them or transfers them into the quote action and its response-session entries, and whose refusing arms dispose them through the input's own Dispose; a rent that fails after an earlier carrier already succeeded releases it in the catch before rethrowing.")]
    private static bool TryParseQuote(ref TpmReader reader, ushort tag, BaseMemoryPool pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(tag != (ushort)TpmStConstants.TPM_ST_SESSIONS)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_AUTH_MISSING;

            return false;
        }

        //Handle area: @signHandle (the signing key).
        if(reader.Remaining < sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        TpmiDhObject signHandle = TpmiDhObject.FromValue(reader.ReadUInt32());

        //The authorizing slot is read generically: a TPM_RS_PW handle is the password form, any other handle is a
        //real HMAC session. The area is bracketed exactly as the password form was.
        if(!TryBeginAuthArea(ref reader, out int sessionsStart, out uint authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        if(!TryReadCommandSessionSpans(ref reader, sessionIndex: 0, out TpmiShAuthSession signSessionHandle, out ReadOnlySpan<byte> signNonceCaller, out TpmaSession signSessionAttributes, out ReadOnlySpan<byte> signHmac, out malformedResponseCode))
        {
            return false;
        }

        //Octets left inside the declared authorization size after the last REQUIRED slot are a companion slot
        //(Part 1, clause 16.6.1, Table 9, position after the authorization sessions).
        bool hasCompanion = reader.Consumed - sessionsStart != (int)authorizationSize;
        TpmiShAuthSession companionSessionHandle = TpmiShAuthSession.FromValue(0);
        TpmaSession companionSessionAttributes = default;

        //The two span locals are declared scoped so they can receive slices that alias the command buffer the
        //by-reference reader points into: without it the compiler must assume a span written through an out
        //parameter of a ref-taking method could outlive that buffer.
        scoped ReadOnlySpan<byte> companionNonceCaller = ReadOnlySpan<byte>.Empty;
        scoped ReadOnlySpan<byte> companionHmac = ReadOnlySpan<byte>.Empty;
        if(hasCompanion
            && !TryReadCommandSessionSpans(ref reader, sessionIndex: 1, out companionSessionHandle, out companionNonceCaller, out companionSessionAttributes, out companionHmac, out malformedResponseCode))
        {
            return false;
        }

        //Octets STILL left after the first companion are a second one: with a single authorizing slot, Table 9's
        //positions 2 and 3 are both open, and each may be an encryption, decryption, or audit session (Part 1,
        //clause 16.6.1). A fourth block would overrun the declared size, which TryEndAuthArea answers below.
        bool hasSecondCompanion = reader.Consumed - sessionsStart != (int)authorizationSize;
        TpmiShAuthSession secondCompanionSessionHandle = TpmiShAuthSession.FromValue(0);
        TpmaSession secondCompanionSessionAttributes = default;

        scoped ReadOnlySpan<byte> secondCompanionNonceCaller = ReadOnlySpan<byte>.Empty;
        scoped ReadOnlySpan<byte> secondCompanionHmac = ReadOnlySpan<byte>.Empty;
        if(hasSecondCompanion
            && !TryReadCommandSessionSpans(ref reader, sessionIndex: 2, out secondCompanionSessionHandle, out secondCompanionNonceCaller, out secondCompanionSessionAttributes, out secondCompanionHmac, out malformedResponseCode))
        {
            return false;
        }

        if(!TryEndAuthArea(ref reader, sessionsStart, authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        //The parameter set (qualifyingData ‖ inScheme ‖ PCRselect) is every octet left after the authorization
        //area — captured verbatim, before any field is decoded, as the session arm's cpHash parameter term
        //(Part 1, clause 16.7 equation 15).
        ReadOnlySpan<byte> rawParameterAreaOctets = reader.PeekBytes(reader.Remaining);

        //Which arm the area belongs to is settled before the parameters are read, because it decides how
        //qualifyingData may be treated: a LONE TPM_RS_PW slot is the all-password form the password arm serves.
        bool isPasswordSlot = signSessionHandle.IsPasswordSession && !hasCompanion;

        //Parameter: qualifyingData (TPM2B_DATA) — the caller nonce echoed into the attestation, and the first
        //command parameter, which is the one a decrypt session protects (Part 1, clause 16.4). On the session
        //form these octets may be CIPHERTEXT, so the parse only steps over the field's framing to reach the
        //parameters behind it and the decrypt step supplies the plaintext (Part 3, clause 5.7 precedes clause
        //5.8); decoding here would also be futile, since a separately copied field is not updated by the in-place
        //transform of the captured area. On the password form no session can protect it, so it is read as a span
        //over the command buffer whose owning carrier is rented as this parse's last act.
        scoped ReadOnlySpan<byte> qualifyingData = ReadOnlySpan<byte>.Empty;
        if(isPasswordSlot)
        {
            if(!TryReadTpm2bSpan(ref reader, out qualifyingData, out malformedResponseCode))
            {
                return false;
            }

            //TPM2B_DATA is bounded by sizeof(TPMT_HA) (Part 2, clause 10.4.3, Table 93), so a wider value is
            //TPM_RC_SIZE here, before any carrier is rented; the consuming transition's own bound check stands as
            //the fail-closed backstop. The session form's bound is applied to the RECOVERED value instead, which
            //is the only form of it TPM2B_DATA is about.
            if(qualifyingData.Length > Tpm2bData.MaxSize)
            {
                malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

                return false;
            }
        }
        else if(!TrySkipTpm2b(ref reader, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: inScheme (TPMT_SIG_SCHEME) — scheme selector (UINT16) + hash algorithm (UINT16). It sits
        //behind the first parameter and so is never encrypted, which is why it is decoded on both arms alike.
        if(reader.Remaining < 2 * sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        TpmiAlgSigScheme signatureScheme = TpmiAlgSigScheme.FromValue((TpmAlgIdConstants)reader.ReadUInt16());
        TpmiAlgHash schemeHashAlg = TpmiAlgHash.FromValue((TpmAlgIdConstants)reader.ReadUInt16());

        //Parameter: PCRselect (TPML_PCR_SELECTION) — the final parameter, decoded into an owned pooled carrier
        //that both drives the PCR gather in the transition and is written back verbatim into the attestation's
        //pcrSelect. The wire shape is probed first on a by-value copy of the reader, which leaves the reader
        //itself untouched, so a truncated list answers TPM_RC_INSUFFICIENT and a trailing octet TPM_RC_SIZE
        //(Part 3, clause 5.2) before any rental happens.
        TpmReader probe = reader;
        if(!TrySkipPcrSelection(ref probe, out malformedResponseCode))
        {
            return false;
        }

        if(probe.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        TpmlPcrSelection pcrSelection;
        try
        {
            pcrSelection = TpmlPcrSelection.Parse(ref reader, pool);
        }
        catch(InvalidOperationException)
        {
            //A list naming more banks than HASH_COUNT selections is out of the structure's declared bound
            //(Part 2, clause 10.9.7, Table 125: #TPM_RC_SIZE).
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }
        catch(ArgumentOutOfRangeException)
        {
            //A selection whose sizeofSelect lies outside PCR_SELECT_MIN..PCR_SELECT_MAX is out of the member's
            //own declared bounds (Part 2, clause 10.6.2, Table 106: #TPM_RC_VALUE). The probe above already
            //refuses that width, so this is the fail-closed backstop rather than the answering layer.
            malformedResponseCode = TpmRcConstants.TPM_RC_VALUE;

            return false;
        }

        //Either form's owned pooled carriers are rented here, the parse's last act after every wire check has
        //passed, so no refused parse ever creates one. Only the session arm retains the slots' caller nonces, so
        //only it rents them — the password record has no slot to adopt one — and only the password arm carries a
        //qualifying-data carrier out of the parse, the session arm's being supplied by the decrypt step.
        Tpm2bAuth signCredential = Tpm2bAuth.Empty;
        Tpm2bNonce signNonce = Tpm2bNonce.Empty;
        Tpm2bAuth companionCredential = Tpm2bAuth.Empty;
        Tpm2bNonce companionNonce = Tpm2bNonce.Empty;
        Tpm2bAuth secondCompanionCredential = Tpm2bAuth.Empty;
        Tpm2bNonce secondCompanionNonce = Tpm2bNonce.Empty;
        TpmParameterArea parameterArea = TpmParameterArea.Empty;
        try
        {
            signCredential = Tpm2bAuth.Create(signHmac, pool);
            signNonce = isPasswordSlot ? Tpm2bNonce.Empty : Tpm2bNonce.Create(signNonceCaller, pool);
            companionCredential = hasCompanion ? Tpm2bAuth.Create(companionHmac, pool) : Tpm2bAuth.Empty;
            companionNonce = hasCompanion ? Tpm2bNonce.Create(companionNonceCaller, pool) : Tpm2bNonce.Empty;
            secondCompanionCredential = hasSecondCompanion ? Tpm2bAuth.Create(secondCompanionHmac, pool) : Tpm2bAuth.Empty;
            secondCompanionNonce = hasSecondCompanion ? Tpm2bNonce.Create(secondCompanionNonceCaller, pool) : Tpm2bNonce.Empty;
            parameterArea = isPasswordSlot ? TpmParameterArea.Empty : TpmParameterArea.Create(rawParameterAreaOctets, pool);
            input = isPasswordSlot
                ? new TpmQuoteRequested(
                    signHandle, signCredential, Tpm2bData.Create(qualifyingData, pool), signatureScheme, schemeHashAlg, pcrSelection)
                : new TpmQuoteOverSessionRequested(
                    signHandle, signSessionHandle, signNonce, signSessionAttributes, signCredential,
                    Tpm2bData.Empty, signatureScheme, schemeHashAlg, pcrSelection, parameterArea,
                    hasCompanion, companionSessionHandle, companionNonce, companionSessionAttributes, companionCredential,
                    hasSecondCompanion, secondCompanionSessionHandle, secondCompanionNonce, secondCompanionSessionAttributes, secondCompanionCredential);
        }
        catch
        {
            //These carriers' only owner is this frame until the request adopts them, so a failing later rent
            //must release them or the pinned rentals are orphaned.
            parameterArea.Dispose();
            secondCompanionNonce.Dispose();
            secondCompanionCredential.Dispose();
            companionNonce.Dispose();
            companionCredential.Dispose();
            signNonce.Dispose();
            signCredential.Dispose();
            pcrSelection.Dispose();
            throw;
        }

        return true;
    }

    /// <summary>
    /// <c>TPM2_StartAuthSession()</c> is framed with no sessions (Part 3, clause 11.1): its wire body after the
    /// header is the handle area (tpmKey, bind) then the parameters (nonceCaller as TPM2B_NONCE, encryptedSalt
    /// as TPM2B_ENCRYPTED_SECRET, sessionType as TPM_SE (BYTE), symmetric as TPMT_SYM_DEF, authHash as
    /// TPMI_ALG_HASH).
    /// </summary>
    /// <remarks>
    /// A policy or trial session (TPM_SE_POLICY / TPM_SE_TRIAL) and a bound and/or salted HMAC session
    /// (TPM_SE_HMAC) dispatch to distinct inputs, but the clause 11.1 precondition ladder and the salt recovery
    /// behind them are session-type-agnostic: tpmKey, bind, nonceCaller (a KDFa context of the session key),
    /// encryptedSalt, and the negotiated symmetric definition parse and thread through BOTH forms, so a salted
    /// policy session derives its session key exactly as a salted HMAC session does.
    /// </remarks>
    /// <param name="reader">The wire reader positioned after the command header.</param>
    /// <param name="pool">The memory pool the request's owned nonce and salt carriers are rented from.</param>
    /// <param name="input">The parsed <see cref="TpmStartAuthSessionRequested"/> or <see cref="TpmStartHmacSessionRequested"/> input on success.</param>
    /// <param name="malformedResponseCode">The response code to return when parsing fails.</param>
    /// <returns><see langword="true"/> when the command parses successfully; otherwise <see langword="false"/>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parse-rented caller-nonce and encrypted-salt carriers transfers to the constructed request input; the accepted transition transfers both into the session-start action whose effect is their terminal owner, and every refusing arm releases them through the input's own Dispose; a rent that fails after the first carrier already succeeded releases it in the catch before rethrowing.")]
    private static bool TryParseStartAuthSession(ref TpmReader reader, BaseMemoryPool pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        //Handle area: tpmKey (the key salt is encrypted to, or TPM_RH_NULL for unsalted) and bind (the entity a
        //bound session binds to, or TPM_RH_NULL).
        if(reader.Remaining < 2 * sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint tpmKey = reader.ReadUInt32();  //tpmKey (TPM_RH_NULL for an unsalted session).
        uint bind = reader.ReadUInt32();    //bind entity (TPM_RH_NULL when unbound).

        //Parameter: nonceCaller (TPM2B_NONCE) — captured because a bound HMAC session folds it into the session key.
        if(!TryReadTpm2bSpan(ref reader, out ReadOnlySpan<byte> nonceCaller, out malformedResponseCode))
        {
            return false;
        }

        //A TPM2B_NONCE buffer can be no wider than sizeof(TPMU_HA) (TPM 2.0 Library Part 2, clause 10.4.4, Table
        //94, page 134, which types it as a TPM2B_DIGEST, over clause 10.4.2, Table 92, page 134, which bounds
        //that structure's buffer and names TPM_RC_SIZE); the carrier's Create refuses the same bound by
        //throwing, so the wire answer is given here, ahead of the rental. Section 11.1.1's own floor and its
        //"no wider than the digest produced by authHash" ceiling are narrower, session-specific rules and stay
        //where the session's hash is known.
        if(nonceCaller.Length > Tpm2bNonce.MaxSize)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //Parameter: encryptedSalt (TPM2B_ENCRYPTED_SECRET) — an RSA OAEP ciphertext or a marshaled
        //TPMS_ECC_POINT depending on tpmKey's algorithm, captured for the HMAC session's salted arm; empty for an
        //unsalted session.
        if(!TryReadTpm2bSpan(ref reader, out ReadOnlySpan<byte> encryptedSalt, out malformedResponseCode))
        {
            return false;
        }

        //A TPM2B_ENCRYPTED_SECRET's secret is bounded by sizeof(TPMU_ENCRYPTED_SECRET) (TPM 2.0 Library Part 2,
        //clause 11.4.3, Table 210, page 180), the widest asymmetrically protected seed the union holds, and a
        //sized buffer past its prescribed range is TPM_RC_SIZE (clause 10.4.2, Table 92, page 134's implied
        //check). The carrier's Create refuses the same bound by throwing, so the wire answer is given here.
        if(encryptedSalt.Length > Tpm2bEncryptedSecret.MaxSize)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //Parameter: sessionType (TPM_SE, BYTE).
        if(reader.Remaining < sizeof(byte))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        var sessionType = (TpmSeConstants)reader.ReadByte();

        //Parameter: symmetric (TPMT_SYM_DEF) — a null definition for a policy session, or XOR/AES for a parameter-
        //encryption HMAC session. Its unions collapse on the wire (Part 2, clause 11.1.6), so the encoded length
        //depends on the algorithm selector; bound-check the full definition before unmarshalling it.
        if(reader.Remaining < sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        var symmetricAlg = (TpmAlgIdConstants)System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(reader.PeekBytes(sizeof(ushort)));
        int symmetricSize = symmetricAlg switch
        {
            TpmAlgIdConstants.TPM_ALG_NULL => sizeof(ushort),               //algorithm only.
            TpmAlgIdConstants.TPM_ALG_XOR => sizeof(ushort) + sizeof(ushort),//algorithm + keyBits (the KDF hash); XOR has no mode.
            _ => sizeof(ushort) + sizeof(ushort) + sizeof(ushort)           //algorithm + keyBits + mode (a block cipher).
        };
        if(reader.Remaining < symmetricSize)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        TpmtSymDef symmetric = TpmtSymDef.Parse(ref reader);

        //Parameter: authHash (TPMI_ALG_HASH, UINT16) — the session's hash algorithm.
        if(reader.Remaining < sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        TpmiAlgHash authHash = TpmiAlgHash.FromValue((TpmAlgIdConstants)reader.ReadUInt16());

        //authHash is the final parameter; no octets may follow it (Part 3, 5.2).
        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //A bound and/or salted HMAC session drives parameter encryption; a policy/trial session drives a
        //policyDigest — the bind/salt fields are still carried for it (the sessionKey derivation ladder is
        //session-type-independent, Part 3, Section 11.1.1), not discarded. Both owned carriers are rented here,
        //the parse's last act after every wire check has passed, so no refused parse ever creates one.
        Tpm2bNonce startNonceCaller = Tpm2bNonce.Empty;
        Tpm2bEncryptedSecret startEncryptedSalt = Tpm2bEncryptedSecret.Empty;
        try
        {
            startNonceCaller = Tpm2bNonce.Create(nonceCaller, pool);
            startEncryptedSalt = Tpm2bEncryptedSecret.Create(encryptedSalt, pool);

            input = sessionType == TpmSeConstants.TPM_SE_HMAC
                ? new TpmStartHmacSessionRequested(TpmiDhEntity.FromValue(bind), startNonceCaller, symmetric, authHash, TpmiDhObject.FromValue(tpmKey), startEncryptedSalt)
                : new TpmStartAuthSessionRequested(sessionType, authHash, TpmiDhEntity.FromValue(bind), startNonceCaller, symmetric, TpmiDhObject.FromValue(tpmKey), startEncryptedSalt);
        }
        catch
        {
            //These carriers' only owner is this frame until the request adopts them, so a failing later rent
            //must release them or the pinned rentals are orphaned.
            startEncryptedSalt.Dispose();
            startNonceCaller.Dispose();
            throw;
        }

        return true;
    }

    /// <summary>
    /// <c>TPM2_GetRandom()</c> over a bound HMAC session (Part 3, clause 16.1) is framed with an authorization
    /// area: after the header (GetRandom has no command handles) come authorizationSize (UINT32), one
    /// TPMS_AUTH_COMMAND, then the bytesRequested (UINT16) parameter.
    /// </summary>
    /// <remarks>
    /// The session's command HMAC is captured (not verified here — this parser is state-free) so the transition
    /// can route it through <see cref="TpmVerifyCommandHmacAction"/>; GetRandom authorizes no entity, so the
    /// verification's HMAC key will be the session key alone and no dictionary-attack gate applies.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parse-rented parameter-area carrier and of the authorization slot's own two credential carriers — its caller nonce and its supplied hmac — transfers to the constructed request input; the consuming continuation releases the credential and the parameter area per carrier and transfers the nonce into the response encryption, and every refusing arm releases all three through the input's own Dispose; a rent that fails after an earlier carrier already succeeded releases it in the catch before rethrowing.")]
    private static bool TryParseGetRandomOverSession(ref TpmReader reader, BaseMemoryPool pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(!TryBeginAuthArea(ref reader, out int sessionsStart, out uint authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        if(!TryReadCommandSessionSpans(ref reader, sessionIndex: 0, out TpmiShAuthSession sessionHandle, out ReadOnlySpan<byte> nonceCaller, out TpmaSession sessionAttributes, out ReadOnlySpan<byte> hmac, out malformedResponseCode))
        {
            return false;
        }

        if(!TryEndAuthArea(ref reader, sessionsStart, authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: bytesRequested (UINT16). Captured raw (before decode) as cpHash's parameter term (Part 1,
        //clause 16.7 equation 15) — for this fixed 2-octet big-endian field the raw bytes and a re-encoded
        //bytesRequested are byte-identical, but capturing the span read keeps the convention uniform with a
        //variable-length first parameter (TpmUnsealOverSessionsRequested has none to capture at all).
        if(reader.Remaining < sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        ReadOnlySpan<byte> rawParameterAreaOctets = reader.PeekBytes(sizeof(ushort));
        ushort bytesRequested = reader.ReadUInt16();

        //bytesRequested is the final parameter; no octets may follow it (Part 3, 5.2).
        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //The session slot's own two credentials are rented here alongside the parameter area, the parse's last
        //act after every wire check has passed, so no refused parse ever creates one.
        Tpm2bNonce slotNonce = Tpm2bNonce.Empty;
        Tpm2bAuth slotCredential = Tpm2bAuth.Empty;
        TpmParameterArea parameterArea = TpmParameterArea.Empty;
        try
        {
            slotNonce = Tpm2bNonce.Create(nonceCaller, pool);
            slotCredential = Tpm2bAuth.Create(hmac, pool);
            parameterArea = TpmParameterArea.Create(rawParameterAreaOctets, pool);

            input = new TpmGetRandomOverSessionRequested(sessionHandle, slotNonce, sessionAttributes, slotCredential, parameterArea, bytesRequested);
        }
        catch
        {
            //These carriers' only owner is this frame until the request adopts them, so a failing later rent
            //must release them or the pinned rentals are orphaned.
            parameterArea.Dispose();
            slotCredential.Dispose();
            slotNonce.Dispose();
            throw;
        }

        return true;
    }

    /// <summary>
    /// Reads one <c>TPMS_AUTH_COMMAND</c> as spans over the command buffer — sessionHandle (UINT32), nonceCaller
    /// (TPM2B), sessionAttributes (BYTE), hmac (TPM2B) — for a parser that rents the slot's owning carriers as its
    /// last act, so the nonce and the credential reach the request through those carriers alone and never through
    /// an intermediate heap copy.
    /// </summary>
    /// <remarks>
    /// Both sized fields go through <see cref="TryReadSessionCredentialSpan"/>, so each carries the structural
    /// width rule of its own type ahead of its body-length check, and the same layout serves a password slot and
    /// a real session (Part 1, clause 17.6.4.1): the handle alone decides which. It is carried as read through
    /// <see cref="TpmiShAuthSession.FromValue"/>, leaving a handle outside the interface type's set (Part 2, clause
    /// 9.8, Table 55) to the consuming transition's response code rather than a parse-time exception. The reader is
    /// taken by reference so the returned spans, which alias the command buffer, are valid for the caller. A
    /// <c>TPM_RS_PW</c> handle carries the structural rules of Part 1, clause 16.6.4, Table 12, applied through the
    /// shared <see cref="TpmLifecycleTransitions.TryValidatePasswordSlot"/> at this slot's own index — the same one
    /// rule, at the same position, the reference's <c>RetrieveSessionData</c> applies to every slot it unmarshals.
    /// </remarks>
    /// <param name="reader">The reader positioned at the slot's sessionHandle.</param>
    /// <param name="sessionIndex">The slot's zero-based index in the authorization area, for the session-index-encoded response codes.</param>
    /// <param name="sessionHandle">The slot's session handle.</param>
    /// <param name="nonceCaller">The slot's caller nonce, aliasing the command buffer.</param>
    /// <param name="sessionAttributes">The slot's command session attributes (<c>TPMA_SESSION</c>, Part 2, clause 8.4, Table 40).</param>
    /// <param name="hmac">The slot's supplied <c>hmac</c> field, aliasing the command buffer.</param>
    /// <param name="malformedResponseCode">The response code a malformed frame answers with.</param>
    /// <returns><see langword="true"/> when the whole slot read cleanly.</returns>
    private static bool TryReadCommandSessionSpans(
        ref TpmReader reader, int sessionIndex, out TpmiShAuthSession sessionHandle, out ReadOnlySpan<byte> nonceCaller,
        out TpmaSession sessionAttributes, out ReadOnlySpan<byte> hmac, out TpmRcConstants malformedResponseCode)
    {
        sessionHandle = TpmiShAuthSession.FromValue(0);
        nonceCaller = ReadOnlySpan<byte>.Empty;
        sessionAttributes = default;
        hmac = ReadOnlySpan<byte>.Empty;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(reader.Remaining < sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        sessionHandle = TpmiShAuthSession.FromValue(reader.ReadUInt32());

        if(!TryReadSessionCredentialSpan(ref reader, sessionIndex, Tpm2bNonce.MaxSize, out nonceCaller, out malformedResponseCode))
        {
            return false;
        }

        if(reader.Remaining < sizeof(byte))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        sessionAttributes = (TpmaSession)reader.ReadByte();

        if(!TryReadSessionCredentialSpan(ref reader, sessionIndex, Tpm2bAuth.MaxSize, out hmac, out malformedResponseCode))
        {
            return false;
        }

        if(sessionHandle.IsPasswordSession
            && !TpmLifecycleTransitions.TryValidatePasswordSlot(sessionAttributes, nonceCaller.Length, sessionIndex, out malformedResponseCode))
        {
            return false;
        }

        return true;
    }

    /// <summary>
    /// <c>TPM2_PolicyCommandCode()</c> carries the policy session as a command handle with no authorization
    /// (Part 3, clause 23.4): handle area (policySession), then the parameter code (TPM_CC). Framed with no
    /// sessions.
    /// </summary>
    private static bool TryParsePolicyCommandCode(ref TpmReader reader, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        //Handle area: policySession, then the parameter code (TPM_CC).
        if(reader.Remaining < 2 * sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint policySession = reader.ReadUInt32();
        var code = (TpmCcConstants)reader.ReadUInt32();

        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        input = new TpmPolicyCommandCodeRequested(TpmiShPolicy.FromValue(policySession), code);

        return true;
    }

    /// <summary>
    /// <c>TPM2_PolicyAuthValue()</c> carries only the policy session command handle with no parameters (Part 3,
    /// clause 23.18). Framed with no sessions.
    /// </summary>
    private static bool TryParsePolicyAuthValue(ref TpmReader reader, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        if(!TryReadPolicySessionOnly(ref reader, out uint policySession, out malformedResponseCode))
        {
            input = null;

            return false;
        }

        input = new TpmPolicyAuthValueRequested(TpmiShPolicy.FromValue(policySession));

        return true;
    }

    /// <summary>
    /// <c>TPM2_PolicyGetDigest()</c> carries only the policy session command handle with no parameters (Part 3,
    /// clause 23.6). Framed with no sessions.
    /// </summary>
    private static bool TryParsePolicyGetDigest(ref TpmReader reader, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        if(!TryReadPolicySessionOnly(ref reader, out uint policySession, out malformedResponseCode))
        {
            input = null;

            return false;
        }

        input = new TpmPolicyGetDigestRequested(TpmiShPolicy.FromValue(policySession));

        return true;
    }

    /// <summary>Reads the single policy-session command handle of a parameterless policy command and confirms nothing follows.</summary>
    private static bool TryReadPolicySessionOnly(ref TpmReader reader, out uint policySession, out TpmRcConstants malformedResponseCode)
    {
        policySession = 0;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(reader.Remaining < sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        policySession = reader.ReadUInt32();

        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        return true;
    }

    /// <summary>
    /// <c>TPM2_PolicyPCR()</c> carries the policy session command handle then the parameters pcrDigest
    /// (TPM2B_DIGEST) and pcrs (TPML_PCR_SELECTION, the final parameter, captured verbatim to fold into the
    /// policyDigest) (Part 3, clause 23.7). Framed with no sessions.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parse-rented digest carrier transfers to the constructed request input, whose asserting transition is its terminal owner on every arm and releases it through the input's own Dispose.")]
    private static bool TryParsePolicyPcr(ref TpmReader reader, BaseMemoryPool pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;

        if(reader.Remaining < sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint policySession = reader.ReadUInt32();

        //Parameter: pcrDigest (TPM2B_DIGEST) — the expected PCR digest.
        if(!TryReadTpm2bSpan(ref reader, out ReadOnlySpan<byte> pcrDigest, out malformedResponseCode))
        {
            return false;
        }

        //A TPM2B_DIGEST buffer can be no wider than sizeof(TPMU_HA) (TPM 2.0 Library Part 2, clause 10.4.2,
        //Table 92), so the wire bound is answered here, ahead of the rental whose Create refuses the same bound
        //by throwing.
        if(pcrDigest.Length > Tpm2bDigest.MaxSize)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //Parameter: pcrs (TPML_PCR_SELECTION) — captured verbatim so it folds into the policyDigest exactly as sent.
        if(!TryReadFinalPcrSelection(ref reader, out ReadOnlyMemory<byte> pcrSelection, out malformedResponseCode))
        {
            return false;
        }

        //The owned pooled digest carrier is rented here, the parse's last act after every wire check has passed,
        //so no refused parse ever creates one.
        input = new TpmPolicyPcrRequested(TpmiShPolicy.FromValue(policySession), Tpm2bDigest.Create(pcrDigest, pool), pcrSelection);

        return true;
    }

    /// <summary>
    /// <c>TPM2_PolicyOR()</c> carries the policy session command handle then the parameter pHashList
    /// (TPML_DIGEST: a UINT32 count followed by that many TPM2B digests, the final parameter) (Part 3, clause
    /// 23.6). Framed with no sessions.
    /// </summary>
    /// <remarks>
    /// The branch count is bounded by the remaining octets — each branch needs at least a 2-byte size prefix —
    /// so a malformed count runs out of input rather than over-allocating.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parse-rented branch list transfers to the constructed request input, whose accepting arm transfers it into the fold action and whose refusing arms dispose it through the input's own Dispose; a branch rent that fails after earlier ones succeeded releases them inside the list factory.")]
    private static bool TryParsePolicyOr(ref TpmReader reader, BaseMemoryPool pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(reader.Remaining < 2 * sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint policySession = reader.ReadUInt32();
        uint count = reader.ReadUInt32();

        //TPM2_PolicyOR's pHashList carries at least two and at most eight digests (Part 3, clause 23.6); a count
        //outside that range is a malformed command, not an assertion the simulator should fold (a trial session
        //would otherwise silently accept an empty or single-branch list and produce a nonstandard digest).
        const uint MinPolicyOrBranches = 2;
        const uint MaxPolicyOrBranches = 8;
        if(count < MinPolicyOrBranches || count > MaxPolicyOrBranches)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        ImmutableArray<ReadOnlyMemory<byte>>.Builder branches = ImmutableArray.CreateBuilder<ReadOnlyMemory<byte>>();
        for(uint i = 0; i < count; i++)
        {
            //The copy this loop makes is TryReadTpm2b's. TpmlDigest.Parse(ref TpmReader, BaseMemoryPool) reads
            //exactly this wire shape — a UINT32 count followed by that many TPM2B_DIGEST fields — straight into
            //pooled carriers with no public-API change, releasing the carriers already rented when a later one
            //fails. What it does not do is answer a response code: it reports a malformed list by THROWING, and
            //it enforces neither Table 123's own {2:} / {:8} count bound nor the per-branch width bound below,
            //so a parse built on it would read the count itself and answer both gates out of a caught throw.
            if(!TryReadTpm2b(ref reader, out ReadOnlyMemory<byte> branch, out malformedResponseCode))
            {
                return false;
            }

            //Each branch is a TPM2B_DIGEST, whose buffer can be no wider than sizeof(TPMU_HA) (TPM 2.0 Library
            //Part 2, clause 10.4.2, Table 92), so the wire bound is answered here, ahead of the rental whose
            //Create refuses the same bound by throwing.
            if(branch.Length > Tpm2bDigest.MaxSize)
            {
                malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

                return false;
            }

            branches.Add(branch);
        }

        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //The owned pooled branch list is rented here, the parse's last act after every wire check has passed, so
        //no refused parse ever creates one.
        input = new TpmPolicyOrRequested(TpmiShPolicy.FromValue(policySession), TpmlDigest.Create(branches.ToImmutable(), pool));

        return true;
    }

    /// <summary>
    /// Parses a TPM2_PolicySecret() command (TPM 2.0 Library Part 3, clause 23.4).
    /// </summary>
    /// <remarks>
    /// TPM2_PolicySecret() is authorized on the entity being consulted, so its wire layout after the header is:
    /// handle area (authHandle, policySession — only authHandle requires authorization), authorization area (a
    /// single session), then parameters (nonceTPM as TPM2B_NONCE, cpHashA as TPM2B_DIGEST, policyRef as
    /// TPM2B_NONCE, expiration as INT32). The authorization area's TPMS_AUTH_COMMAND wire shape is identical
    /// whether the session is <c>TPM_RS_PW</c>, an HMAC session, or a POLICY session (sessionHandle ‖ nonceCaller ‖
    /// sessionAttributes ‖ hmac — <c>TryReadPasswordSessionBody</c>'s <c>TPM_RS_PW</c> gate is the only
    /// difference), so <c>TryReadCommandSessionSpans</c> reads it generically (Part 3, Section 23.4.1: "A password
    /// session, an HMAC session, or a policy session ... will satisfy this requirement") and the parsed
    /// sessionHandle alone decides which record this becomes — the transition, not the parser, resolves whether a
    /// non-password handle names a real HMAC or POLICY session.
    /// </remarks>
    /// <param name="reader">The wire reader positioned after the command header.</param>
    /// <param name="tag">The command's structure tag.</param>
    /// <param name="pool">The memory pool the request's owned carriers are rented from.</param>
    /// <param name="input">The parsed <see cref="TpmPolicySecretRequested"/> or <see cref="TpmPolicySecretOverSessionRequested"/> input on success.</param>
    /// <param name="malformedResponseCode">The response code to return when parsing fails.</param>
    /// <returns><see langword="true"/> when the command parses successfully; otherwise <see langword="false"/>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parse-rented cpHashA, policyRef, caller-supplied nonceTPM and session-slot carriers transfers to the constructed request input, whose post-authorization ladder is their terminal owner — the caller of that ladder compares and releases the nonceTPM, and the slot's caller nonce transfers into the response-framing action — and whose refusing arms dispose them through the input's own Dispose; a rent that fails after an earlier carrier already succeeded releases it in the catch before rethrowing.")]
    private static bool TryParsePolicySecret(ref TpmReader reader, ushort tag, BaseMemoryPool pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(tag != (ushort)TpmStConstants.TPM_ST_SESSIONS)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_AUTH_MISSING;

            return false;
        }

        //Handle area: authHandle (the authorized entity) then policySession (the command handle, no authorization).
        if(reader.Remaining < 2 * sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint authHandle = reader.ReadUInt32();
        uint policySession = reader.ReadUInt32();

        if(!TryBeginAuthArea(ref reader, out int sessionsStart, out uint authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        if(!TryReadCommandSessionSpans(ref reader, sessionIndex: 0, out TpmiShAuthSession sessionHandle, out ReadOnlySpan<byte> nonceCaller, out TpmaSession sessionAttributes, out ReadOnlySpan<byte> hmac, out malformedResponseCode))
        {
            return false;
        }

        if(!TryEndAuthArea(ref reader, sessionsStart, authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        //PolicySecret's entire parameter set (nonceTPM ‖ cpHashA ‖ policyRef ‖ expiration) is every octet left
        //after the authorization area — captured verbatim, before any field is decoded, as the HMAC/POLICY
        //arm's cpHash parameter term (Part 1, clause 16.7 equation 15); unused by the password arm.
        ReadOnlySpan<byte> rawParameterAreaOctets = reader.PeekBytes(reader.Remaining);

        //Parameter: nonceTPM (TPM2B_NONCE).
        if(!TryReadTpm2bSpan(ref reader, out ReadOnlySpan<byte> nonceTpm, out malformedResponseCode))
        {
            return false;
        }

        //A TPM2B_NONCE buffer can be no wider than sizeof(TPMU_HA) (TPM 2.0 Library Part 2, clause 10.4.4, Table
        //94, page 134, which types it as a TPM2B_DIGEST, and clause 10.4.2, Table 92, page 134, which bounds that
        //structure's buffer); the carrier's Create refuses the same bound by throwing, so the wire answer is
        //given here, ahead of the rental and ahead of any session-state comparison.
        if(nonceTpm.Length > Tpm2bNonce.MaxSize)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //Parameter: cpHashA (TPM2B_DIGEST).
        if(!TryReadTpm2bSpan(ref reader, out ReadOnlySpan<byte> cpHashA, out malformedResponseCode))
        {
            return false;
        }

        //A TPM2B_DIGEST buffer can be no wider than sizeof(TPMU_HA) (TPM 2.0 Library Part 2, clause 10.4.2,
        //Table 92), so the wire bound is answered here, ahead of the rental whose Create refuses the same bound
        //by throwing. The transition's own "exactly the session's digest width" check stays as the backstop.
        if(cpHashA.Length > Tpm2bDigest.MaxSize)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //Parameter: policyRef (TPM2B_NONCE).
        if(!TryReadTpm2bSpan(ref reader, out ReadOnlySpan<byte> policyRef, out malformedResponseCode))
        {
            return false;
        }

        //A TPM2B_NONCE buffer can be no wider than sizeof(TPMU_HA) (TPM 2.0 Library Part 2, clause 10.4.4, Table
        //94, which types it as a TPM2B_DIGEST, and clause 10.4.2, Table 92, which bounds that structure's
        //buffer); the carrier's Create refuses the same bound by throwing, so the wire answer is given here.
        if(policyRef.Length > Tpm2bNonce.MaxSize)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //Parameter: expiration (INT32).
        if(reader.Remaining < sizeof(int))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        int expiration = reader.ReadInt32();

        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //A TPM_RS_PW session's hmac field is the plaintext supplied authValue (TryReadPasswordSessionBody's own
        //convention, mirrored here since the wire read is shared). The owned pooled carriers are rented here,
        //the parse's last act after every wire check has passed, so no refused parse ever creates one. A
        //TPM_RS_PW slot carries no caller nonce at all (its width rule already refused a non-empty one), so its
        //rental resolves to the dispose-immune empty sentinel without a special case.
        Tpm2bDigest suppliedCpHash = Tpm2bDigest.Empty;
        Tpm2bNonce suppliedPolicyRef = Tpm2bNonce.Empty;
        Tpm2bNonce suppliedNonceTpm = Tpm2bNonce.Empty;
        Tpm2bNonce slotNonce = Tpm2bNonce.Empty;
        Tpm2bAuth slotCredential = Tpm2bAuth.Empty;
        TpmParameterArea parameterArea = TpmParameterArea.Empty;
        try
        {
            suppliedCpHash = Tpm2bDigest.Create(cpHashA, pool);
            suppliedPolicyRef = Tpm2bNonce.Create(policyRef, pool);
            suppliedNonceTpm = Tpm2bNonce.Create(nonceTpm, pool);
            slotNonce = Tpm2bNonce.Create(nonceCaller, pool);
            slotCredential = Tpm2bAuth.Create(hmac, pool);
            parameterArea = sessionHandle.IsPasswordSession ? TpmParameterArea.Empty : TpmParameterArea.Create(rawParameterAreaOctets, pool);

            input = sessionHandle.IsPasswordSession
                ? new TpmPolicySecretRequested(TpmiDhEntity.FromValue(authHandle), TpmiShPolicy.FromValue(policySession), slotCredential, suppliedNonceTpm, suppliedCpHash, suppliedPolicyRef, expiration)
                : new TpmPolicySecretOverSessionRequested(
                    TpmiDhEntity.FromValue(authHandle), TpmiShPolicy.FromValue(policySession), sessionHandle, slotNonce, sessionAttributes, slotCredential, parameterArea,
                    suppliedNonceTpm, suppliedCpHash, suppliedPolicyRef, expiration);
        }
        catch
        {
            //These carriers' only owner is this frame until the request adopts them, so a failing later rent
            //must release them or the pinned rentals are orphaned.
            parameterArea.Dispose();
            slotCredential.Dispose();
            slotNonce.Dispose();
            suppliedNonceTpm.Dispose();
            suppliedPolicyRef.Dispose();
            suppliedCpHash.Dispose();
            throw;
        }

        return true;
    }

    /// <summary>
    /// <c>TPM2_PolicySigned()</c> authorizes neither handle (Auth Index: None for both authObject and
    /// policySession, TPM 2.0 Library Part 3, Table 124), so its wire layout after the header is: handle area
    /// (authObject, policySession — 2 handles, no authorization area at all, <c>TPM_ST_NO_SESSIONS</c> exactly
    /// like <c>TPM2_VerifySignature()</c>), then parameters (nonceTPM as TPM2B_NONCE, cpHashA as TPM2B_DIGEST,
    /// policyRef as TPM2B_NONCE, expiration as INT32, auth as TPMT_SIGNATURE).
    /// </summary>
    /// <remarks>The TPMT_SIGNATURE parsing is the same inline, fail-closed block <c>TryParseVerifySignature</c> uses (Part 3, clause 23.3).</remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parse-rented cpHashA and policyRef carriers transfers to the constructed request input, whose consuming transition transfers them into the verification action and whose refusing arms dispose them through the input's own Dispose; a rent that fails after the first carrier already succeeded releases it in the catch before rethrowing.")]
    private static bool TryParsePolicySigned(ref TpmReader reader, ushort tag, BaseMemoryPool pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(tag != (ushort)TpmStConstants.TPM_ST_NO_SESSIONS)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_BAD_TAG;

            return false;
        }

        //Handle area: authObject (validates the signature) then policySession (the session being extended).
        if(reader.Remaining < 2 * sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint authObject = reader.ReadUInt32();
        uint policySession = reader.ReadUInt32();

        //Parameter: nonceTPM (TPM2B_NONCE).
        if(!TryReadTpm2bSpan(ref reader, out ReadOnlySpan<byte> nonceTpm, out malformedResponseCode))
        {
            return false;
        }

        //A TPM2B_NONCE buffer can be no wider than sizeof(TPMU_HA) (TPM 2.0 Library Part 2, clause 10.4.4, Table
        //94, page 134, which types it as a TPM2B_DIGEST, and clause 10.4.2, Table 92, page 134, which bounds that
        //structure's buffer); the carrier's Create refuses the same bound by throwing, so the wire answer is
        //given here, ahead of the rental and ahead of any session-state comparison.
        if(nonceTpm.Length > Tpm2bNonce.MaxSize)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //Parameter: cpHashA (TPM2B_DIGEST).
        if(!TryReadTpm2bSpan(ref reader, out ReadOnlySpan<byte> cpHashA, out malformedResponseCode))
        {
            return false;
        }

        //A TPM2B_DIGEST buffer can be no wider than sizeof(TPMU_HA) (TPM 2.0 Library Part 2, clause 10.4.2,
        //Table 92), so the wire bound is answered here, ahead of the rental whose Create refuses the same bound
        //by throwing. The transition's own "exactly the session's digest width" check stays as the backstop.
        if(cpHashA.Length > Tpm2bDigest.MaxSize)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //Parameter: policyRef (TPM2B_NONCE).
        if(!TryReadTpm2bSpan(ref reader, out ReadOnlySpan<byte> policyRef, out malformedResponseCode))
        {
            return false;
        }

        //A TPM2B_NONCE buffer can be no wider than sizeof(TPMU_HA) (TPM 2.0 Library Part 2, clause 10.4.4, Table
        //94, which types it as a TPM2B_DIGEST, and clause 10.4.2, Table 92, which bounds that structure's
        //buffer); the carrier's Create refuses the same bound by throwing, so the wire answer is given here.
        if(policyRef.Length > Tpm2bNonce.MaxSize)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //Parameter: expiration (INT32).
        if(reader.Remaining < sizeof(int))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        int expiration = reader.ReadInt32();

        //Parameter: auth (TPMT_SIGNATURE) — sigAlg (TPMI_ALG_SIG_SCHEME) selects the union member, mirroring
        //TryParseVerifySignature's inline, fail-closed block exactly.
        if(reader.Remaining < sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        TpmiAlgSigScheme sigAlg = TpmiAlgSigScheme.FromValue((TpmAlgIdConstants)reader.ReadUInt16());
        if(sigAlg.Value is not (TpmAlgIdConstants.TPM_ALG_ECDSA or TpmAlgIdConstants.TPM_ALG_RSASSA or TpmAlgIdConstants.TPM_ALG_RSAPSS))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SCHEME;

            return false;
        }

        if(reader.Remaining < sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        TpmiAlgHash schemeHashAlg = TpmiAlgHash.FromValue((TpmAlgIdConstants)reader.ReadUInt16());

        ReadOnlyMemory<byte> signature;
        if(sigAlg.Value == TpmAlgIdConstants.TPM_ALG_ECDSA)
        {
            if(!TryReadTpm2b(ref reader, out ReadOnlyMemory<byte> signatureR, out malformedResponseCode))
            {
                return false;
            }

            if(!TryReadTpm2b(ref reader, out ReadOnlyMemory<byte> signatureS, out malformedResponseCode))
            {
                return false;
            }

            byte[] concatenated = new byte[signatureR.Length + signatureS.Length];
            signatureR.Span.CopyTo(concatenated);
            signatureS.Span.CopyTo(concatenated.AsSpan(signatureR.Length));
            signature = concatenated;
        }
        else
        {
            if(!TryReadTpm2b(ref reader, out ReadOnlyMemory<byte> rsaSignature, out malformedResponseCode))
            {
                return false;
            }

            signature = rsaSignature;
        }

        //auth is the final parameter; no octets may follow it (Part 3, 5.2).
        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //The owned pooled carriers are rented here, the parse's last act after every wire check has passed, so no
        //refused parse ever creates one.
        Tpm2bDigest suppliedCpHash = Tpm2bDigest.Empty;
        Tpm2bNonce suppliedPolicyRef = Tpm2bNonce.Empty;
        Tpm2bNonce suppliedNonceTpm = Tpm2bNonce.Empty;
        try
        {
            suppliedCpHash = Tpm2bDigest.Create(cpHashA, pool);
            suppliedPolicyRef = Tpm2bNonce.Create(policyRef, pool);
            suppliedNonceTpm = Tpm2bNonce.Create(nonceTpm, pool);
            input = new TpmPolicySignedRequested(
                TpmiDhObject.FromValue(authObject), TpmiShPolicy.FromValue(policySession), suppliedNonceTpm, suppliedCpHash,
                suppliedPolicyRef, expiration, sigAlg, schemeHashAlg, signature);
        }
        catch
        {
            //These carriers' only owner is this frame until the request adopts them, so a failing later rent
            //must release them or the pinned rentals are orphaned.
            suppliedNonceTpm.Dispose();
            suppliedPolicyRef.Dispose();
            suppliedCpHash.Dispose();
            throw;
        }

        return true;
    }

    /// <summary>
    /// <c>TPM2_PolicyAuthorize()</c> carries a single command handle (policySession, no authorization — mirrors
    /// <c>TPM2_PolicyCommandCode()</c>/<c>TPM2_PolicyPCR()</c>/<c>TPM2_PolicyOR()</c>, none of which check the
    /// tag either), so its wire layout after the header is: handle area (policySession), then parameters
    /// (approvedPolicy as TPM2B_DIGEST, policyRef as TPM2B_NONCE, keySign as TPM2B_NAME, checkTicket as
    /// TPMT_TK_VERIFIED: tag, hierarchy, digest as TPM2B_DIGEST) (Part 3, Section 23.16).
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parse-rented approvedPolicy, policyRef, keySign, and checkTicket digest carriers transfers to the constructed request input, whose trial arm transfers them into the policyDigest fold and whose non-trial arm transfers them into the re-verification action, and whose refusing arms dispose them through the input's own Dispose; a rent that fails after earlier carriers already succeeded releases those in the catch before rethrowing.")]
    private static bool TryParsePolicyAuthorize(ref TpmReader reader, BaseMemoryPool pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(reader.Remaining < sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint policySession = reader.ReadUInt32();

        if(!TryReadTpm2bSpan(ref reader, out ReadOnlySpan<byte> approvedPolicy, out malformedResponseCode))
        {
            return false;
        }

        //A TPM2B_DIGEST buffer can be no wider than sizeof(TPMU_HA) (TPM 2.0 Library Part 2, clause 10.4.2,
        //Table 92), so the wire bound is answered here, ahead of the rental whose Create refuses the same bound
        //by throwing. The transition's own equality check against the session's digest stays as the backstop.
        if(approvedPolicy.Length > Tpm2bDigest.MaxSize)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        if(!TryReadTpm2bSpan(ref reader, out ReadOnlySpan<byte> policyRef, out malformedResponseCode))
        {
            return false;
        }

        //A TPM2B_NONCE buffer can be no wider than sizeof(TPMU_HA) (TPM 2.0 Library Part 2, clause 10.4.4, Table
        //94, which types it as a TPM2B_DIGEST, and clause 10.4.2, Table 92, which bounds that structure's
        //buffer); the carrier's Create refuses the same bound by throwing, so the wire answer is given here.
        if(policyRef.Length > Tpm2bNonce.MaxSize)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        if(!TryReadTpm2bSpan(ref reader, out ReadOnlySpan<byte> keySign, out malformedResponseCode))
        {
            return false;
        }

        //A TPM2B_NAME's content is bounded by sizeof(TPMU_NAME) — a 2-octet nameAlg plus the widest digest
        //(TPM 2.0 Library Part 2, clause 10.5.3, Table 104; the reference enforces it in TPM2B_NAME_Unmarshal),
        //so an oversized keySign is refused here rather than reaching the carrier's own throwing bound. The
        //transition's own nameAlg/width checks stay as the fail-closed backstop.
        if(keySign.Length > Tpm2bName.MaxSize)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //checkTicket (TPMT_TK_VERIFIED): tag (UINT16) + hierarchy (UINT32) + digest (TPM2B_DIGEST). Both
        //selector fields are constrained at the wire read, because that is what the command asks for: "The
        //unmarshaling process requires that a proper TPMT_TK_VERIFIED be provided for checkTicket but it may be
        //a NULL Ticket" (Part 3, clause 23.16, printed page 227). The NULL form is <TPM_ST_VERIFIED, TPM_RH_NULL,
        //0x0000> (Part 2, clause 10.7.4, Table 110), so both gates admit it.
        if(reader.Remaining < sizeof(ushort) + sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        //TPMT_TK_VERIFIED.tag is fixed to TPM_ST_VERIFIED (Part 2, Table 110: "TPM_RC_TAG error returned when
        //tag is not TPM_ST_VERIFIED"). The re-verification recompute has no tag-legality check of its own — it
        //would hash whatever tag the caller supplied — so this reader is the only place the constraint holds.
        ushort checkTicketTag = reader.ReadUInt16();
        if(checkTicketTag != (ushort)TpmStConstants.TPM_ST_VERIFIED)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_TAG;

            return false;
        }

        //TPMT_TK_VERIFIED.hierarchy is TPMI_RH_HIERARCHY+ (Part 2, Table 110), so the admitted set is the
        //interface type's own (clause 9.13, Table 60) and a value outside it is TPM_RC_VALUE. The predicate is
        //read from the type rather than restated here, so the admitted set is stated in exactly one place.
        uint checkTicketHierarchy = reader.ReadUInt32();
        if(!TpmiRhHierarchy.IsHierarchy(checkTicketHierarchy))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_VALUE;

            return false;
        }

        if(!TryReadTpm2bSpan(ref reader, out ReadOnlySpan<byte> checkTicketDigest, out malformedResponseCode))
        {
            return false;
        }

        //The ticket's own digest is a TPM2B_DIGEST too (Part 2, clause 10.7.4, Table 110), so it takes the same
        //sizeof(TPMU_HA) bound ahead of its rental.
        if(checkTicketDigest.Length > Tpm2bDigest.MaxSize)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //checkTicket is the final parameter; no octets may follow it (Part 3, 5.2).
        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //The owned pooled carriers are rented here, the parse's last act after every wire check has passed, so no
        //refused parse ever creates one.
        Tpm2bDigest suppliedApprovedPolicy = Tpm2bDigest.Empty;
        Tpm2bNonce suppliedPolicyRef = Tpm2bNonce.Empty;
        Tpm2bName suppliedKeySign = Tpm2bName.Empty;
        try
        {
            suppliedApprovedPolicy = Tpm2bDigest.Create(approvedPolicy, pool);
            suppliedPolicyRef = Tpm2bNonce.Create(policyRef, pool);
            suppliedKeySign = Tpm2bName.Create(keySign, pool);
            input = new TpmPolicyAuthorizeRequested(
                TpmiShPolicy.FromValue(policySession), suppliedApprovedPolicy, suppliedPolicyRef, suppliedKeySign,
                TpmiRhHierarchy.FromValue(checkTicketHierarchy), Tpm2bDigest.Create(checkTicketDigest, pool));
        }
        catch
        {
            //These carriers' only owner is this frame until the request adopts them, so a failing later rent
            //must release them or the pinned rentals are orphaned.
            suppliedKeySign.Dispose();
            suppliedPolicyRef.Dispose();
            suppliedApprovedPolicy.Dispose();
            throw;
        }

        return true;
    }

    /// <summary>
    /// <c>TPM2_PolicyTicket()</c> carries the policy session command handle (no authorization — Auth Index:
    /// None, TPM 2.0 Library Part 3, Table 131), so its wire layout after the header is: handle area
    /// (policySession), then parameters (timeout as TPM2B_TIMEOUT, cpHashA as TPM2B_DIGEST, policyRef as
    /// TPM2B_NONCE, authName as TPM2B_NAME, ticket as TPMT_TK_AUTH: tag, hierarchy, digest as TPM2B_DIGEST)
    /// (Part 3, Section 23.5).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The generic TPM2B_TIMEOUT length rule ("8 or less", Part 2, Table 100) is answered HERE, at the wire
    /// read, ahead of the carrier rental whose <c>Create</c> refuses the same bound by throwing — the same
    /// placement the reference's own <c>TPM2B_TIMEOUT_Unmarshal</c> gives it, which is before any command body
    /// runs. The command-specific "exactly 8" rule is a separate, tighter check and stays in the transition,
    /// where it runs after the trial-session rejection: Part 4's <c>TPM2_PolicyTicket()</c>, printed page 654,
    /// puts <c>if(session->attributes.isTrialPolicy) return TPM_RCS_ATTRIBUTES + RC_PolicyTicket_policySession;</c>
    /// ahead of <c>if(in->timeout.t.size != sizeof(UINT64)) return TPM_RCS_SIZE + RC_PolicyTicket_timeout;</c>.
    /// </para>
    /// <para>
    /// TPMT_TK_AUTH.tag legality (<c>TPM_ST_AUTH_SIGNED</c> or <c>TPM_ST_AUTH_SECRET</c> only — Part 2, Table
    /// 111: "TPM_RC_TAG error returned when tag is not TPM_ST_AUTH_*") IS enforced here, at the wire reader: the
    /// re-verification recompute has no independent tag-legality check of its own (an illegal tag would still
    /// recompute a comparable HMAC, since both sides would hash the caller's own bogus tag), so the wire-level
    /// gate is the only place that constraint is actually enforced. TPMT_TK_AUTH.hierarchy is typed
    /// TPMI_RH_HIERARCHY+ (Part 2, Table 111: {TPM_RH_OWNER, TPM_RH_PLATFORM, TPM_RH_ENDORSEMENT, TPM_RH_NULL},
    /// TPM_RC_VALUE otherwise) and is constrained to that legal set here for the identical reason — the
    /// re-verification recompute derives whatever proof the caller's hierarchy names with no legality check of
    /// its own (<c>TicketComputeAuth</c>'s own contract: the caller's claim is exactly what is being checked).
    /// </para>
    /// <para>
    /// authName has no TPM2B_NAME size bound of its own in the reference (<c>TPM2B_NAME_Unmarshal</c> bounds it
    /// to <c>sizeof(TPMU_NAME)</c>); this reader applies the same bound using this simulator's own widest
    /// modelled Name (2-octet nameAlg plus the widest supported digest, SHA-512) so a caller cannot shift the
    /// cpHash/policyRef/authName split across the un-length-prefixed equation-12 concatenation
    /// (<c>WriteAuthTicketMessage</c>) by supplying an oversized authName.
    /// </para>
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parse-rented timeout, cpHashA, policyRef, authName, and ticket-digest carriers transfers to the constructed request input, whose consuming transition transfers them into the re-verification action, and whose refusing arms dispose them through the input's own Dispose; a rent that fails after earlier carriers already succeeded releases those in the catch before rethrowing.")]
    private static bool TryParsePolicyTicket(ref TpmReader reader, BaseMemoryPool pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(reader.Remaining < sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint policySession = reader.ReadUInt32();

        if(!TryReadTpm2bSpan(ref reader, out ReadOnlySpan<byte> timeout, out malformedResponseCode))
        {
            return false;
        }

        //A TPM2B_TIMEOUT buffer is bounded by sizeof(UINT64) (Part 2, clause 10.4.10, Table 100), the bound the
        //reference's own unmarshal applies before any command body runs; the carrier's Create refuses the same
        //bound by throwing, so the wire answer is given here.
        if(timeout.Length > Tpm2bTimeout.MaxSize)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        if(!TryReadTpm2bSpan(ref reader, out ReadOnlySpan<byte> cpHashA, out malformedResponseCode))
        {
            return false;
        }

        //A TPM2B_DIGEST buffer can be no wider than sizeof(TPMU_HA) (Part 2, clause 10.4.2, Table 92); the
        //transition's own "exactly the session's digest width" check stays as the backstop.
        if(cpHashA.Length > Tpm2bDigest.MaxSize)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        if(!TryReadTpm2bSpan(ref reader, out ReadOnlySpan<byte> policyRef, out malformedResponseCode))
        {
            return false;
        }

        //A TPM2B_NONCE buffer can be no wider than sizeof(TPMU_HA) (TPM 2.0 Library Part 2, clause 10.4.4, Table
        //94, which types it as a TPM2B_DIGEST, and clause 10.4.2, Table 92, which bounds that structure's
        //buffer); the carrier's Create refuses the same bound by throwing, so the wire answer is given here.
        if(policyRef.Length > Tpm2bNonce.MaxSize)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        if(!TryReadTpm2bSpan(ref reader, out ReadOnlySpan<byte> authName, out malformedResponseCode))
        {
            return false;
        }

        if(authName.Length > Tpm2bName.MaxSize)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //ticket (TPMT_TK_AUTH): tag (UINT16) + hierarchy (UINT32) + digest (TPM2B_DIGEST).
        if(reader.Remaining < sizeof(ushort) + sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        ushort ticketTag = reader.ReadUInt16();
        if(ticketTag != (ushort)TpmStConstants.TPM_ST_AUTH_SIGNED && ticketTag != (ushort)TpmStConstants.TPM_ST_AUTH_SECRET)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_TAG;

            return false;
        }

        //TPMT_TK_AUTH.hierarchy is TPMI_RH_HIERARCHY+ (Part 2, clause 10.7.5, Table 111), so the admitted set is
        //the interface type's own (clause 9.13, Table 60) and a value outside it is TPM_RC_VALUE. The predicate
        //is read from the type rather than restated here, so the admitted set is stated in exactly one place.
        uint ticketHierarchy = reader.ReadUInt32();
        if(!TpmiRhHierarchy.IsHierarchy(ticketHierarchy))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_VALUE;

            return false;
        }

        if(!TryReadTpm2bSpan(ref reader, out ReadOnlySpan<byte> ticketDigest, out malformedResponseCode))
        {
            return false;
        }

        //The ticket's own digest is a TPM2B_DIGEST (Part 2, clause 10.7.5, Table 111), so it takes the same
        //sizeof(TPMU_HA) bound ahead of its rental.
        if(ticketDigest.Length > Tpm2bDigest.MaxSize)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //ticket is the final parameter; no octets may follow it (Part 3, 5.2).
        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //The owned pooled carriers are rented here, the parse's last act after every wire check has passed, so no
        //refused parse ever creates one.
        Tpm2bTimeout suppliedTimeout = Tpm2bTimeout.Empty;
        Tpm2bDigest suppliedCpHash = Tpm2bDigest.Empty;
        Tpm2bNonce suppliedPolicyRef = Tpm2bNonce.Empty;
        Tpm2bName suppliedAuthName = Tpm2bName.Empty;
        try
        {
            suppliedTimeout = Tpm2bTimeout.Create(timeout, pool);
            suppliedCpHash = Tpm2bDigest.Create(cpHashA, pool);
            suppliedPolicyRef = Tpm2bNonce.Create(policyRef, pool);
            suppliedAuthName = Tpm2bName.Create(authName, pool);
            input = new TpmPolicyTicketRequested(
                TpmiShPolicy.FromValue(policySession), suppliedTimeout, suppliedCpHash, suppliedPolicyRef, suppliedAuthName,
                ticketTag, TpmiRhHierarchy.FromValue(ticketHierarchy), Tpm2bDigest.Create(ticketDigest, pool));
        }
        catch
        {
            //These carriers' only owner is this frame until the request adopts them, so a failing later rent
            //must release them or the pinned rentals are orphaned.
            suppliedAuthName.Dispose();
            suppliedPolicyRef.Dispose();
            suppliedCpHash.Dispose();
            suppliedTimeout.Dispose();
            throw;
        }

        return true;
    }

    /// <summary>
    /// <c>TPM2_PolicyNV()</c> is authorized on the entity used to read the Index, so its wire layout after the
    /// header is: handle area (authHandle, nvIndex, policySession — only authHandle requires authorization),
    /// authorization area (a single password session), then parameters (operandB as TPM2B_OPERAND, offset as
    /// UINT16, operation as TPM_EO) (Part 3, clause 23.9).
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parse-rented authorization-password carrier transfers to the constructed request input, whose consuming transition releases it once the authorization arm has consumed it, and whose refusing arms dispose it through the input's own Dispose.")]
    private static bool TryParsePolicyNv(ref TpmReader reader, ushort tag, BaseMemoryPool pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(tag != (ushort)TpmStConstants.TPM_ST_SESSIONS)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_AUTH_MISSING;

            return false;
        }

        //Handle area: authHandle, nvIndex, then policySession (the command handle, no authorization).
        if(reader.Remaining < 3 * sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint authHandle = reader.ReadUInt32();
        uint nvIndex = reader.ReadUInt32();
        uint policySession = reader.ReadUInt32();

        if(!TryReadPasswordAuthArea(ref reader, out ReadOnlySpan<byte> suppliedAuth, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: operandB (TPM2B_OPERAND).
        if(!TryReadTpm2bSpan(ref reader, out ReadOnlySpan<byte> operandB, out malformedResponseCode))
        {
            return false;
        }

        //TPM2B_OPERAND is "size limited to the same as the digest structure" (Part 2, clause 10.4.6, Table 96),
        //so its buffer is bounded by sizeof(TPMU_HA) exactly as a TPM2B_DIGEST is (Table 92). The bound is
        //answered here, ahead of the rental, because the carrier factory throws above it.
        if(operandB.Length > Tpm2bOperand.MaxSize)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //Parameters: offset (UINT16) + operation (TPM_EO, UINT16).
        if(reader.Remaining < 2 * sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        ushort offset = reader.ReadUInt16();
        ushort operation = reader.ReadUInt16();

        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //TPM_EO carries only 12 defined values (Part 2, Section 6.8, Table 22); an undefined value is rejected here,
        //at unmarshal (Part 3, clause 5.1), so a REAL session's TpmEoComparator.TryEvaluate and a TRIAL session's
        //unconditional fold reject an invalid operation identically, rather than the real session throwing while the
        //trial session silently folds it.
        if(!((TpmEoConstants)operation).IsDefined())
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_VALUE;

            return false;
        }

        //The request, with its owned password and operand carriers, is constructed as the parse's last act, so no
        //refused parse ever creates one; the password is rented first and released if the operand's rental fails.
        Tpm2bAuth suppliedPassword = Tpm2bAuth.Create(suppliedAuth, pool);
        try
        {
            input = new TpmPolicyNvRequested(
                TpmiRhNvAuth.FromValue(authHandle), suppliedPassword, TpmiRhNvIndex.FromValue(nvIndex),
                TpmiShPolicy.FromValue(policySession), Tpm2bOperand.Create(operandB, pool), offset, operation);
        }
        catch
        {
            suppliedPassword.Dispose();
            throw;
        }

        return true;
    }

    /// <summary>
    /// <c>TPM2_PolicyCounterTimer()</c> carries the policy session command handle (no authorization, so
    /// <c>TPM_ST_NO_SESSIONS</c>) followed by operandB (TPM2B_OPERAND), offset (UINT16), and operation (TPM_EO,
    /// UINT16) — Part 3, clause 23.10.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parse-rented comparison operand transfers to the constructed request input, whose consuming transition hands it to the shared policy-digest fold and whose refusing arms dispose it through the input's own Dispose.")]
    private static bool TryParsePolicyCounterTimer(ref TpmReader reader, BaseMemoryPool pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        //Handle area: policySession (the command handle, no authorization).
        if(reader.Remaining < sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint policySession = reader.ReadUInt32();

        //Parameter: operandB (TPM2B_OPERAND).
        if(!TryReadTpm2bSpan(ref reader, out ReadOnlySpan<byte> operandB, out malformedResponseCode))
        {
            return false;
        }

        //TPM2B_OPERAND is "size limited to the same as the digest structure" (Part 2, clause 10.4.6, Table 96),
        //so its buffer is bounded by sizeof(TPMU_HA) exactly as a TPM2B_DIGEST is (Table 92). The bound is
        //answered here, ahead of the rental, because the carrier factory throws above it.
        if(operandB.Length > Tpm2bOperand.MaxSize)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //Parameters: offset (UINT16) + operation (TPM_EO, UINT16).
        if(reader.Remaining < 2 * sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        ushort offset = reader.ReadUInt16();
        ushort operation = reader.ReadUInt16();

        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //TPM_EO carries only 12 defined values (Part 2, Section 6.8, Table 22); an undefined value is rejected here,
        //at unmarshal (Part 3, clause 5.1), so a REAL session's TpmEoComparator.TryEvaluate and a TRIAL session's
        //unconditional fold reject an invalid operation identically, rather than the real session throwing while the
        //trial session silently folds it.
        if(!((TpmEoConstants)operation).IsDefined())
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_VALUE;

            return false;
        }

        //The request, with its owned operand carrier, is constructed as the parse's last act, so no refused parse
        //ever creates one.
        input = new TpmPolicyCounterTimerRequested(TpmiShPolicy.FromValue(policySession), Tpm2bOperand.Create(operandB, pool), offset, operation);

        return true;
    }

    /// <summary>
    /// <c>TPM2_FlushContext()</c> takes no handles and no authorization (Part 3, clause 28.4): its wire body
    /// after the header is a single flushHandle (TPMI_DH_CONTEXT) parameter, framed with no sessions.
    /// </summary>
    private static bool TryParseFlushContext(ref TpmReader reader, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(reader.Remaining < sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint flushHandle = reader.ReadUInt32();

        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        input = new TpmFlushContextRequested(TpmiDhContext.FromValue(flushHandle));

        return true;
    }

    /// <summary>
    /// Reads a <c>TPML_PCR_SELECTION</c> that is the command's final parameter, capturing its exact wire bytes
    /// (so they can be echoed into the attestation / the PCR_Read response and decoded against the bank) and
    /// validating its structure.
    /// </summary>
    /// <remarks>Any octets after the selection are malformed (Part 3, 5.2).</remarks>
    private static bool TryReadFinalPcrSelection(ref TpmReader reader, out ReadOnlyMemory<byte> selectionBytes, out TpmRcConstants malformedResponseCode)
    {
        selectionBytes = ReadOnlyMemory<byte>.Empty;

        //Capture the whole remaining region (which begins at the selection) before the reader advances; the copy
        //is taken only after the structure validates and no trailing octets remain, so it is exactly the selection.
        ReadOnlySpan<byte> region = reader.PeekBytes(reader.Remaining);

        if(!TrySkipPcrSelection(ref reader, out malformedResponseCode))
        {
            return false;
        }

        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        selectionBytes = region.ToArray();

        return true;
    }

    /// <summary>
    /// Skips a <c>TPML_PCR_SELECTION</c> (UINT32 count + count selections of UINT16 hash + BYTE sizeofSelect +
    /// select), answering the structure's own response codes for a malformed one.
    /// </summary>
    /// <remarks>
    /// A selection's <c>sizeofSelect</c> is bounded on both sides —
    /// <c>sizeofSelect {PCR_SELECT_MIN:}</c> and <c>pcrSelect[sizeofSelect] {:PCR_SELECT_MAX}</c> with
    /// <c>#TPM_RC_VALUE</c> (TPM 2.0 Library Part 2, clause 10.6.2, Table 106; the widths themselves are clause
    /// 10.6.1's equations 1 and 2) — and the bound is tested HERE rather than at the decode that follows,
    /// because this probe runs on a by-value reader copy before anything is rented. The reference unmarshaler
    /// makes the same check in the same place (<c>TPMS_PCR_SELECTION_Unmarshal</c> answers <c>TPM_RC_VALUE</c>
    /// between reading <c>sizeofSelect</c> and reading the bitmap). <see cref="TpmlPcrSelection.Parse"/> keeps
    /// its own range guard as the fail-closed backstop, so the response code has exactly one origin while the
    /// structure still refuses to rent for a width it cannot hold.
    /// </remarks>
    /// <param name="reader">The reader positioned at the list's <c>count</c>.</param>
    /// <param name="malformedResponseCode">The response code for a malformed list; meaningless when this returns <see langword="true"/>.</param>
    /// <returns><see langword="true"/> when a well-formed list was skipped.</returns>
    private static bool TrySkipPcrSelection(ref TpmReader reader, out TpmRcConstants malformedResponseCode)
    {
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(reader.Remaining < sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint count = reader.ReadUInt32();
        for(uint i = 0; i < count; i++)
        {
            if(reader.Remaining < sizeof(ushort) + sizeof(byte))
            {
                malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

                return false;
            }

            _ = reader.ReadUInt16();
            byte sizeofSelect = reader.ReadByte();
            if(sizeofSelect < TpmlPcrSelection.PcrSelectMin || sizeofSelect > TpmlPcrSelection.PcrSelectMax)
            {
                malformedResponseCode = TpmRcConstants.TPM_RC_VALUE;

                return false;
            }

            if(reader.Remaining < sizeofSelect)
            {
                malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

                return false;
            }

            reader.Skip(sizeofSelect);
        }

        return true;
    }

    /// <summary>
    /// Reads a command authorization area carrying a single password session and yields the supplied
    /// authorization value (the hmac field, which for a <c>TPM_RS_PW</c> session is the plaintext authValue).
    /// </summary>
    /// <remarks>
    /// Only password sessions are modelled this slice: HMAC and policy sessions arrive later. The reader is
    /// taken by reference so the returned span, which aliases the command buffer, is valid for the caller,
    /// which rents the owning carrier as its own last act.
    /// </remarks>
    /// <param name="reader">The reader positioned at the authorizationSize field.</param>
    /// <param name="suppliedAuth">The supplied authorization value, aliasing the command buffer.</param>
    /// <param name="malformedResponseCode">The response code for a malformed area; meaningless when this returns <see langword="true"/>.</param>
    /// <returns><see langword="true"/> when a well-formed password authorization area was read.</returns>
    private static bool TryReadPasswordAuthArea(ref TpmReader reader, out ReadOnlySpan<byte> suppliedAuth, out TpmRcConstants malformedResponseCode)
    {
        suppliedAuth = ReadOnlySpan<byte>.Empty;

        if(!TryBeginAuthArea(ref reader, out int sessionsStart, out uint authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        if(!TryReadPasswordSessionBody(ref reader, out suppliedAuth, out malformedResponseCode))
        {
            return false;
        }

        return TryEndAuthArea(ref reader, sessionsStart, authorizationSize, out malformedResponseCode);
    }

    /// <summary>
    /// Reads the authorizationSize (UINT32) field that opens an authorization area and marks where the sessions
    /// begin, so the caller can confirm the sessions account for exactly the declared octets.
    /// </summary>
    private static bool TryBeginAuthArea(ref TpmReader reader, out int sessionsStart, out uint authorizationSize, out TpmRcConstants malformedResponseCode)
    {
        sessionsStart = 0;
        authorizationSize = 0;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(reader.Remaining < sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        authorizationSize = reader.ReadUInt32();
        if(authorizationSize > (uint)reader.Remaining)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_AUTHSIZE;

            return false;
        }

        sessionsStart = reader.Consumed;

        return true;
    }

    /// <summary>
    /// Confirms the sessions consumed exactly the declared authorization octets; any surplus means additional
    /// or oversized sessions this slice's fixed session count does not model.
    /// </summary>
    private static bool TryEndAuthArea(ref TpmReader reader, int sessionsStart, uint authorizationSize, out TpmRcConstants malformedResponseCode)
    {
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(reader.Consumed - sessionsStart != (int)authorizationSize)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_AUTHSIZE;

            return false;
        }

        return true;
    }

    /// <summary>
    /// Reads one <c>TPMS_AUTH_COMMAND</c> password session — sessionHandle (UINT32, must be <c>TPM_RS_PW</c>) +
    /// nonceCaller (TPM2B) + sessionAttributes (BYTE) + hmac (TPM2B) — and yields the supplied authorization
    /// value (the hmac field, which for a <c>TPM_RS_PW</c> session is the plaintext authValue).
    /// </summary>
    /// <remarks>
    /// The two rules that hold for a <c>TPM_RS_PW</c> slot on structure alone are answered here, where the slot's
    /// kind is already known and no lookup has happened yet — the position the reference gives them in
    /// <c>RetrieveSessionData</c> — through the shared
    /// <see cref="TpmLifecycleTransitions.TryValidatePasswordSlot"/>, which is the one place they are stated
    /// (TPM 2.0 Library Part 1, clause 16.6.4, Table 12). Both refusals are session-index-encoded to slot 0,
    /// which is the only position this helper ever reads. The two sized fields carry the width rule of their own
    /// types ahead of that, through <see cref="TryReadSessionCredentialSpan"/>: a password slot's <c>hmac</c> is the same <c>TPM2B_AUTH</c> wire
    /// field a real session's credential is (Part 2, clause 10.13.2, Table 153), so it takes the same bound.
    /// </remarks>
    /// <param name="reader">The reader positioned at the session's handle.</param>
    /// <param name="suppliedAuth">The supplied authorization value, aliasing the command buffer; the caller rents the owning carrier as its own last act.</param>
    /// <param name="malformedResponseCode">The response code for a malformed session; meaningless when this returns <see langword="true"/>.</param>
    /// <returns><see langword="true"/> when a well-formed password session was read.</returns>
    private static bool TryReadPasswordSessionBody(ref TpmReader reader, out ReadOnlySpan<byte> suppliedAuth, out TpmRcConstants malformedResponseCode)
    {
        suppliedAuth = ReadOnlySpan<byte>.Empty;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(reader.Remaining < sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        TpmiShAuthSession sessionHandle = TpmiShAuthSession.FromValue(reader.ReadUInt32());
        if(!sessionHandle.IsPasswordSession)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_AUTH_TYPE;

            return false;
        }

        if(!TryReadSessionCredentialSpan(ref reader, sessionIndex: 0, Tpm2bNonce.MaxSize, out ReadOnlySpan<byte> nonceCaller, out malformedResponseCode))
        {
            return false;
        }

        if(reader.Remaining < sizeof(byte))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        var sessionAttributes = (TpmaSession)reader.ReadByte();

        if(!TryReadSessionCredentialSpan(ref reader, sessionIndex: 0, Tpm2bAuth.MaxSize, out suppliedAuth, out malformedResponseCode))
        {
            return false;
        }

        return TpmLifecycleTransitions.TryValidatePasswordSlot(sessionAttributes, nonceCaller.Length, sessionIndex: 0, out malformedResponseCode);
    }

    /// <summary>
    /// Answers the structural width rule of a session slot's <c>nonce</c> or <c>hmac</c> field, ahead of the
    /// field's own read: a declared size wider than the bound the caller names for that field is
    /// session-index-encoded <c>TPM_RC_SIZE</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>TPMS_AUTH_COMMAND</c> types both fields as sized buffers the hash union bounds — <c>nonce</c> is a
    /// <c>TPM2B_NONCE</c> and <c>hmac</c> a <c>TPM2B_AUTH</c> (TPM 2.0 Library Part 2, clause 10.13.2, Table
    /// 153, page 159), and both are <c>TPM2B_DIGEST</c> by definition (clause 10.4.4, Table 94, page 134 and
    /// clause 10.4.5, Table 95, page 135), so both carry clause 10.4.2's implied check: "As with all sized
    /// buffers, the size is checked to see if it is within the prescribed range. If not, the response code is
    /// TPM_RC_SIZE" (Table 92, page 134). Each field names its OWN carrier's bound —
    /// <see cref="Tpm2bNonce.MaxSize"/> for the nonce, <see cref="Tpm2bAuth.MaxSize"/> for the hmac — so the
    /// value this frame compares against is the one whose factory would refuse the same octets downstream, even
    /// though both resolve to <c>sizeof(TPMU_HA)</c>. The bound is the hash union's width and never the width of
    /// the session's own hash algorithm, which is a property of the session rather than of the wire structure.
    /// </para>
    /// <para>
    /// The check runs on a by-value probe of the reader, which leaves the reader itself untouched, so it lands
    /// BEFORE the field's body-length check and a slot declaring a size the command cannot carry is answered as
    /// an out-of-range size rather than as a truncated command. Answering the width first is also what keeps a
    /// malformed frame away from the authorization compare entirely: a credential no <c>TPM2B_AUTH</c> could
    /// hold is a marshalling refusal rather than a failed authorization, so it charges no dictionary-attack
    /// counter and touches no lockout state.
    /// </para>
    /// <para>
    /// The encoding is the session-area one every other per-slot refusal here uses (Part 2, clause 6.6.2),
    /// because the offending octets belong to a numbered session rather than to a command parameter.
    /// </para>
    /// </remarks>
    /// <param name="reader">The reader positioned at the field's size prefix; unchanged by this check.</param>
    /// <param name="sessionIndex">The slot's zero-based index in the authorization area, for the response encoding.</param>
    /// <param name="maxSize">The bound of the field's own carrier type in octets: <see cref="Tpm2bNonce.MaxSize"/> for a <c>nonce</c>, <see cref="Tpm2bAuth.MaxSize"/> for an <c>hmac</c>.</param>
    /// <param name="malformedResponseCode">The session-index-encoded response code when this returns <see langword="false"/>; meaningless otherwise.</param>
    /// <returns><see langword="true"/> when the declared width is admissible, or when the size prefix itself cannot be read, which the field's own read answers.</returns>
    private static bool TryValidateSessionCredentialWidth(ref TpmReader reader, int sessionIndex, int maxSize, out TpmRcConstants malformedResponseCode)
    {
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        TpmReader probe = reader;
        if(probe.Remaining < sizeof(ushort))
        {
            return true;
        }

        if(probe.ReadUInt16() > maxSize)
        {
            malformedResponseCode = TpmLifecycleTransitions.SessionEncodedRc(TpmRcConstants.TPM_RC_SIZE, sessionIndex);

            return false;
        }

        return true;
    }

    /// <summary>
    /// Reads one session slot's <c>nonce</c> or <c>hmac</c> field as a span over the command buffer, with the
    /// width rule of <see cref="TryValidateSessionCredentialWidth"/> applied first.
    /// </summary>
    /// <param name="reader">The reader positioned at the field's size prefix.</param>
    /// <param name="sessionIndex">The slot's zero-based index in the authorization area, for the response encoding.</param>
    /// <param name="maxSize">The bound of the field's own carrier type in octets: <see cref="Tpm2bNonce.MaxSize"/> for a <c>nonce</c>, <see cref="Tpm2bAuth.MaxSize"/> for an <c>hmac</c>.</param>
    /// <param name="bytes">The octets, aliasing the command buffer.</param>
    /// <param name="malformedResponseCode">The response code a malformed field answers with.</param>
    /// <returns><see langword="true"/> when the field read cleanly.</returns>
    private static bool TryReadSessionCredentialSpan(ref TpmReader reader, int sessionIndex, int maxSize, out ReadOnlySpan<byte> bytes, out TpmRcConstants malformedResponseCode)
    {
        bytes = ReadOnlySpan<byte>.Empty;

        if(!TryValidateSessionCredentialWidth(ref reader, sessionIndex, maxSize, out malformedResponseCode))
        {
            return false;
        }

        return TryReadTpm2bSpan(ref reader, out bytes, out malformedResponseCode);
    }

    /// <summary>Reads a TPM2B (UINT16 size prefix + octets) and copies the octets into durable model memory.</summary>
    private static bool TryReadTpm2b(ref TpmReader reader, out ReadOnlyMemory<byte> bytes, out TpmRcConstants malformedResponseCode)
    {
        bytes = ReadOnlyMemory<byte>.Empty;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(reader.Remaining < sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        ushort size = reader.ReadUInt16();
        if(reader.Remaining < size)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        if(size > 0)
        {
            bytes = reader.ReadBytes(size).ToArray();
        }

        return true;
    }

    /// <summary>
    /// Reads a TPM2B (UINT16 size prefix + octets) as a span over the command buffer, for a parse that rents the
    /// owning carrier as its last act — the octets reach the request through that carrier alone, never through an
    /// intermediate heap copy.
    /// </summary>
    /// <remarks>
    /// The wire checks are <c>TryReadTpm2b</c>'s: a size prefix the command cannot carry, or a declared size the
    /// remaining octets cannot cover, is <c>TPM_RC_INSUFFICIENT</c> (Part 3, clause 5.2). The reader is taken by
    /// reference so the returned span, which aliases the command buffer, is valid for the caller.
    /// </remarks>
    /// <param name="reader">The reader positioned at the size prefix.</param>
    /// <param name="bytes">The octets, aliasing the command buffer.</param>
    /// <param name="malformedResponseCode">The response code a malformed frame answers with.</param>
    /// <returns><see langword="true"/> when the field read cleanly.</returns>
    private static bool TryReadTpm2bSpan(ref TpmReader reader, out ReadOnlySpan<byte> bytes, out TpmRcConstants malformedResponseCode)
    {
        bytes = ReadOnlySpan<byte>.Empty;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(reader.Remaining < sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        ushort size = reader.ReadUInt16();
        if(reader.Remaining < size)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        if(size > 0)
        {
            bytes = reader.ReadBytes(size);
        }

        return true;
    }

    /// <summary>Skips a TPM2B (UINT16 size prefix + octets) without copying — used for fields the model does not retain.</summary>
    private static bool TrySkipTpm2b(ref TpmReader reader, out TpmRcConstants malformedResponseCode)
    {
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(reader.Remaining < sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        ushort size = reader.ReadUInt16();
        if(reader.Remaining < size)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        reader.Skip(size);

        return true;
    }

    private static TpmSuConstants ReadStartupType(ref TpmReader reader)
    {
        //An absent or short startup type is surfaced as an out-of-range value, which the transition
        //rejects with TPM_RC_VALUE — the same outcome the TPM gives for an invalid startupType.
        if(reader.Remaining < sizeof(ushort))
        {
            return (TpmSuConstants)0xFFFF;
        }

        return (TpmSuConstants)reader.ReadUInt16();
    }

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "TpmResponse takes ownership of the rented buffer and is owned by the returned TpmResult, which the caller disposes.")]
    private static TpmResult<TpmResponse> SerializeResponse(TpmResponseIntent intent, BaseMemoryPool pool)
    {
        //An encrypt-attributed GetRandom response is framed with the TPM_ST_SESSIONS tag and a trailing response
        //session area, structurally distinct from every no-sessions response below, so it is framed by its own
        //helper (the terminal owner of its pooled parameter-area and HMAC buffers).
        if(intent is TpmEncryptedRandomResponse encryptedRandom)
        {
            return SerializeEncryptedRandomResponse(encryptedRandom, pool);
        }

        //A policy-gated TPM2_Unseal() response is likewise TPM_ST_SESSIONS-tagged and carries a trailing response
        //session area — but with TWO session entries (the policy session then the encrypt session) — so it is framed
        //by its own helper (the terminal owner of its pooled parameter-area and HMAC buffers).
        if(intent is TpmUnsealOverSessionsResponse unsealOverSessions)
        {
            return SerializeUnsealOverSessionsResponse(unsealOverSessions, pool);
        }

        //TPM2_Create() over sessions is likewise TPM_ST_SESSIONS-tagged and carries a trailing response session
        //area (a TPM_RS_PW placeholder, a real per-session entry, or both) — the request-decrypt counterpart of
        //TpmUnsealOverSessionsResponse — so it too is framed by its own helper.
        if(intent is TpmCreateOverSessionsResponse createOverSessions)
        {
            return SerializeCreateOverSessionsResponse(createOverSessions, pool);
        }

        //A session-authorized TPM2_PolicySecret() response is likewise TPM_ST_SESSIONS-tagged with a trailing
        //response session area (a single entry, the authorizing session's rolled nonce and real response HMAC),
        //structurally the same shape SerializeEncryptedRandomResponse frames — so it too gets its own helper.
        if(intent is TpmPolicySecretOverSessionResponse policySecretOverSession)
        {
            return SerializePolicySecretOverSessionResponse(policySecretOverSession, pool);
        }

        //A session-authorized NV command (NV_Read/NV_Write/NV_DefineSpace/NV_UndefineSpace) response is
        //likewise TPM_ST_SESSIONS-tagged with a trailing single-entry response session area — the NV-family
        //counterpart of TpmPolicySecretOverSessionResponse, generalized over an (possibly empty) parameter area.
        if(intent is TpmNvSessionResponse nvSession)
        {
            return SerializeNvSessionResponse(nvSession, pool);
        }

        //TPM2_NV_ChangeAuth() is TPM_ST_SESSIONS-tagged with no response parameters and one entry per command
        //session — the ADMIN policy session, plus a separate decrypt session when the caller protected newAuth
        //in flight — so it is framed by its own helper rather than the single-entry NV shape above.
        if(intent is TpmNvChangeAuthResponse nvChangeAuth)
        {
            return SerializeNvChangeAuthResponse(nvChangeAuth, pool);
        }

        //An attest command over sessions (Certify/CertifyCreation/Quote/GetTime/NV_Certify) is BOTH
        //parameter-bearing and multi-entry (a TPM2B_ATTEST/TPMT_SIGNATURE pair over independently authorized
        //handles — Part 3, Tables 90/92/94/100/255), so neither of the two NV shapes above can frame it and the
        //attest family shares its own helper.
        if(intent is TpmAttestOverSessionsResponse attestOverSessions)
        {
            return SerializeAttestOverSessionsResponse(attestOverSessions, pool);
        }

        //The TpmRandomResponse intent is the terminal owner of the RNG buffer rented by the action
        //executor; release it in the finally regardless of how framing completes (its octets are
        //copied into the framed TPM2B_DIGEST on the success path).
        Tpm2bDigest? randomBuffer = (intent as TpmRandomResponse)?.RandomBytes;
        TpmsCapabilityData? capabilityData = (intent as TpmCapabilityResponse)?.CapabilityData;

        //The CreatePrimary and Sign intents are the terminal owners of the exported public area, each creation
        //by-product structure, and the signature; release them in the finally once their octets are framed.
        Tpm2bPublic? createdPublic = (intent as TpmCreatePrimaryResponse)?.OutPublic;
        Tpm2bCreationData? createdCreationData = (intent as TpmCreatePrimaryResponse)?.CreationData;
        Tpm2bDigest? createdCreationHash = (intent as TpmCreatePrimaryResponse)?.CreationHash;
        TpmtTkCreation? createdCreationTicket = (intent as TpmCreatePrimaryResponse)?.CreationTicket;
        Tpm2bName? createdName = (intent as TpmCreatePrimaryResponse)?.Name;
        TpmtSignature? signatureValue = (intent as TpmSignResponse)?.Signature;

        //The Create (seal) and Load intents own the wrapped blob, the sealed object's public area, its by-products,
        //and the object Name; release them in the finally once framed. The Unseal intent's octets are durable model
        //memory owned by the loaded object, so nothing is disposed for it.
        Tpm2bPrivate? sealedPrivate = (intent as TpmCreateResponse)?.PrivateBlob;
        Tpm2bPublic? sealedPublic = (intent as TpmCreateResponse)?.OutPublic;
        Tpm2bCreationData? sealedCreationData = (intent as TpmCreateResponse)?.CreationData;
        Tpm2bDigest? sealedCreationHash = (intent as TpmCreateResponse)?.CreationHash;
        TpmtTkCreation? sealedCreationTicket = (intent as TpmCreateResponse)?.CreationTicket;
        Tpm2bName? loadedName = (intent as TpmLoadResponse)?.Name;

        //The NV_ReadPublic intent owns the built public area (which itself owns pooled policy-digest memory) and
        //the computed Name buffer; release them in the finally once framed.
        TpmsNvPublic? nvReadPublicArea = (intent as TpmNvReadPublicResponse)?.NvPublic;
        Tpm2bName? nvReadPublicName = (intent as TpmNvReadPublicResponse)?.NvName;

        //The Certify intent owns the attest structure and the signature structure; release them in the finally
        //once the TPM2B_ATTEST and TPMT_SIGNATURE are framed.
        Tpm2bAttest? certifyInfoBuffer = (intent as TpmCertifyResponse)?.CertifyInfo;
        TpmtSignature? certifySignature = (intent as TpmCertifyResponse)?.Signature;

        //The CertifyCreation, GetTime, and NV_Certify intents likewise own their attest and signature structures;
        //release them in the finally once framed.
        Tpm2bAttest? certifyCreationInfoBuffer = (intent as TpmCertifyCreationResponse)?.CertifyInfo;
        TpmtSignature? certifyCreationSignature = (intent as TpmCertifyCreationResponse)?.Signature;
        Tpm2bAttest? timeInfoBuffer = (intent as TpmGetTimeResponse)?.TimeInfo;
        TpmtSignature? timeSignature = (intent as TpmGetTimeResponse)?.Signature;
        Tpm2bAttest? nvCertifyInfoBuffer = (intent as TpmNvCertifyResponse)?.CertifyInfo;
        TpmtSignature? nvCertifySignature = (intent as TpmNvCertifyResponse)?.Signature;

        //The VerifySignature intent owns only its validation ticket — no attest, no signature (unlike every
        //other attest-family intent above).
        TpmtTkVerified? verifySignatureValidation = (intent as TpmVerifySignatureResponse)?.Validation;

        //The PolicySecret/PolicySigned intents own their framed timeout, and their minted ticket-digest carrier
        //only when a real ticket was minted (null for a NULL ticket, so nothing to dispose there).
        Tpm2bTimeout? policySecretTimeout = (intent as TpmPolicySecretResponse)?.Timeout;
        Tpm2bDigest? policySecretTicketDigest = (intent as TpmPolicySecretResponse)?.TicketDigest;
        Tpm2bTimeout? policySignedTimeout = (intent as TpmPolicySignedResponse)?.Timeout;
        Tpm2bDigest? policySignedTicketDigest = (intent as TpmPolicySignedResponse)?.TicketDigest;

        //The Quote intent likewise owns the marshaled attest buffer and the signature; release them in the finally
        //once framed. The PCR_Read intent's octets are the echoed selection and references into durable bank state,
        //so nothing is disposed for it.
        Tpm2bAttest? quotedBuffer = (intent as TpmQuoteResponse)?.Quoted;
        TpmtSignature? quoteSignature = (intent as TpmQuoteResponse)?.Signature;

        //The MakeCredential intent owns the credential-blob and secret buffers (both public); release them in the
        //finally once framed. The ActivateCredential intent owns the recovered credential secret — confidential, so
        //it is zeroed before disposal (the clear-before-dispose discipline used for the decrypted response parameter).
        Tpm2bIdObject? credentialBlobBuffer = (intent as TpmMakeCredentialResponse)?.CredentialBlob;
        Tpm2bEncryptedSecret? credentialSecretBuffer = (intent as TpmMakeCredentialResponse)?.Secret;
        TpmActivateCredentialResponse? activatedCredential = intent as TpmActivateCredentialResponse;

        //The StartAuthSession intent owns the framing step's own copy of the started session's nonceTPM, rented
        //alongside the copy the durable session record keeps; release it in the finally once framed.
        Tpm2bNonce? startedSessionNonce = (intent as TpmStartAuthSessionResponse)?.NonceTpm;
        try
        {
            int parameterSize = intent switch
            {
                TpmTestResultResponse { ResponseCode: TpmRcConstants.TPM_RC_SUCCESS } => sizeof(ushort) + sizeof(uint),
                TpmRandomResponse random => random.RandomBytes.SerializedSize,
                TpmCapabilityResponse capabilityResponse => sizeof(byte) + capabilityResponse.CapabilityData.GetSerializedSize(),

                //objectHandle + outPublic + creationData + creationHash + creationTicket + name, each sized by
                //its own structure so the framing arm below cannot drift from the size computed here.
                TpmCreatePrimaryResponse createPrimary =>
                    sizeof(uint)
                    + createPrimary.OutPublic.GetSerializedSize()
                    + createPrimary.CreationData.SerializedSize
                    + createPrimary.CreationHash.SerializedSize
                    + createPrimary.CreationTicket.SerializedSize
                    + createPrimary.Name.SerializedSize,

                //ECDSA: sigAlg + hash + r (TPM2B) + s (TPM2B), r and s splitting the IEEE P1363 signature at its
                //half. RSA: sigAlg + hash + sig (one TPM2B). The signature octets are the remaining length.
                TpmSignResponse sign => sign.Signature.GetSerializedSize(),

                //outPrivate (TPM2B_PRIVATE) + outPublic + creationData + creationHash + creationTicket, each
                //sized by its own structure. TPM2_Create() returns no Name (Part 3, clause 12.1).
                TpmCreateResponse createObject =>
                    createObject.PrivateBlob.SerializedSize
                    + createObject.OutPublic.GetSerializedSize()
                    + createObject.CreationData.SerializedSize
                    + createObject.CreationHash.SerializedSize
                    + createObject.CreationTicket.SerializedSize,

                //objectHandle + name (TPM2B_NAME).
                TpmLoadResponse load => sizeof(uint) + load.Name.SerializedSize,

                //outData (TPM2B_SENSITIVE_DATA) carrying the recovered sealed octets.
                TpmUnsealResponse unseal => sizeof(ushort) + unseal.OutData.Length,

                //data (TPM2B_MAX_NV_BUFFER) carrying the octets read from the NV Index.
                TpmNvReadDataResponse nvReadData => nvReadData.Data.SerializedSize,

                //nvPublic (TPM2B_NV_PUBLIC, a UINT16 size prefix around the marshaled TPMS_NV_PUBLIC) + nvName (TPM2B_NAME).
                TpmNvReadPublicResponse nvReadPublic => (sizeof(ushort) + nvReadPublic.NvPublic.SerializedSize) + nvReadPublic.NvName.SerializedSize,

                //certifyInfo (TPM2B_ATTEST) + signature (TPMT_SIGNATURE), each sized by its own structure — the
                //same arithmetic the session arm's parameter-area framing uses, so the two arms cannot drift
                //apart in what rpHash would have to cover.
                TpmCertifyResponse certify => certify.CertifyInfo.GetSerializedSize() + certify.Signature.GetSerializedSize(),

                //certifyInfo (TPM2B_ATTEST) + signature (TPMT_SIGNATURE), the same shape as TpmCertifyResponse.
                TpmCertifyCreationResponse certifyCreation => certifyCreation.CertifyInfo.GetSerializedSize() + certifyCreation.Signature.GetSerializedSize(),

                //timeInfo (TPM2B_ATTEST) + signature (TPMT_SIGNATURE), the same shape as TpmCertifyResponse.
                TpmGetTimeResponse getTime => getTime.TimeInfo.GetSerializedSize() + getTime.Signature.GetSerializedSize(),

                //certifyInfo (TPM2B_ATTEST) + signature (TPMT_SIGNATURE), the same shape as TpmCertifyResponse.
                TpmNvCertifyResponse nvCertify => nvCertify.CertifyInfo.GetSerializedSize() + nvCertify.Signature.GetSerializedSize(),

                //validation (TPMT_TK_VERIFIED): tag (UINT16) + hierarchy (UINT32) + digest (TPM2B_DIGEST) — no
                //attest and no signature, unlike every other attest-family response above.
                TpmVerifySignatureResponse verifySignature => verifySignature.Validation.SerializedSize,

                //currentTime (TPMS_TIME_INFO, fixed layout): the uncertified Time/Clock/resetCount/restartCount/Safe snapshot.
                TpmReadClockResponse => TpmsTimeInfo.SerializedSize,

                //pcrUpdateCounter (UINT32) + pcrSelectionOut (TPML_PCR_SELECTION echoed) + pcrValues (TPML_DIGEST).
                TpmPcrReadResponse pcrRead =>
                    sizeof(uint) + pcrRead.SelectionBytes.Length + PcrValuesSerializedSize(pcrRead.PcrValues),

                //quoted (TPM2B_ATTEST) + signature (TPMT_SIGNATURE), the same shape as TpmCertifyResponse.
                TpmQuoteResponse quote => quote.Quoted.GetSerializedSize() + quote.Signature.GetSerializedSize(),

                //sessionHandle (response handle) + nonceTPM (TPM2B_NONCE of the policy-hash width).
                TpmStartAuthSessionResponse startAuthSession =>
                    sizeof(uint) + startAuthSession.NonceTpm.SerializedSize,

                //policyDigest (TPM2B_DIGEST): the session's accumulated digest.
                TpmPolicyGetDigestResponse policyGetDigest => policyGetDigest.PolicyDigest.SerializedSize,

                //A NULL ticket: empty TPM2B_TIMEOUT + policyTicket (TPMT_TK_AUTH: tag + hierarchy + empty
                //digest). A real ticket: the full 8-byte TPM2B_TIMEOUT + policyTicket with its real digest.
                TpmPolicySecretResponse policySecret => policySecret.TicketDigest is { } secretTicket
                    ? policySecret.Timeout.SerializedSize + (sizeof(ushort) + sizeof(uint) + secretTicket.SerializedSize)
                    : sizeof(ushort) + (sizeof(ushort) + sizeof(uint) + sizeof(ushort)),

                //A NULL ticket: empty TPM2B_TIMEOUT + policyTicket (TPMT_TK_AUTH: tag + hierarchy + empty
                //digest). A real ticket: the full 8-byte TPM2B_TIMEOUT + policyTicket with its real digest.
                TpmPolicySignedResponse policySigned => policySigned.TicketDigest is { } signedTicket
                    ? policySigned.Timeout.SerializedSize + (sizeof(ushort) + sizeof(uint) + signedTicket.SerializedSize)
                    : sizeof(ushort) + (sizeof(ushort) + sizeof(uint) + sizeof(ushort)),

                //credentialBlob (TPM2B_ID_OBJECT) + secret (TPM2B_ENCRYPTED_SECRET).
                TpmMakeCredentialResponse makeCredential =>
                    makeCredential.CredentialBlob.SerializedSize + makeCredential.Secret.SerializedSize,

                //certInfo (TPM2B_DIGEST): the recovered credential secret.
                TpmActivateCredentialResponse activateCredential => activateCredential.CertInfo.SerializedSize,

                _ => 0
            };
            int total = TpmHeader.HeaderSize + parameterSize;

            IMemoryOwner<byte> owner = pool.Rent(total);
            try
            {
                var writer = new TpmWriter(owner.Memory.Span);
                var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)total, (uint)intent.ResponseCode);
                header.WriteTo(ref writer);

                switch(intent)
                {
                    case TpmTestResultResponse { ResponseCode: TpmRcConstants.TPM_RC_SUCCESS } testResultResponse:
                    {
                        writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
                        writer.WriteUInt32((uint)testResultResponse.TestResult);

                        break;
                    }
                    case TpmRandomResponse randomResponse:
                    {
                        randomResponse.RandomBytes.WriteTo(ref writer);

                        break;
                    }
                    case TpmCapabilityResponse capabilityResponse:
                    {
                        capabilityResponse.MoreData.WriteTo(ref writer);
                        capabilityResponse.CapabilityData.WriteTo(ref writer);

                        break;
                    }
                    case TpmCreatePrimaryResponse createPrimaryResponse:
                    {
                        //objectHandle (the response handle area).
                        writer.WriteUInt32(createPrimaryResponse.ObjectHandle.Value);

                        //outPublic (TPM2B_PUBLIC) carrying the generated point.
                        createPrimaryResponse.OutPublic.WriteTo(ref writer);

                        //creationData, creationHash, creationTicket and name, in the order Part 3, clause 24.1's
                        //response table fixes; each structure writes its own size prefix and body, and each was
                        //computed faithfully in the effectful loop (the Name, creation hash, and ticket need the
                        //registered digest and HMAC seams, which are asynchronous).
                        createPrimaryResponse.CreationData.WriteTo(ref writer);
                        createPrimaryResponse.CreationHash.WriteTo(ref writer);
                        createPrimaryResponse.CreationTicket.WriteTo(ref writer);
                        createPrimaryResponse.Name.WriteTo(ref writer);

                        break;
                    }
                    case TpmSignResponse signResponse:
                    {
                        //signature (TPMT_SIGNATURE): the structure writes its own selector, hash, and member.
                        signResponse.Signature.WriteTo(ref writer);

                        break;
                    }
                    case TpmCreateResponse createObjectResponse:
                    {
                        //outPrivate (TPM2B_PRIVATE): the wrapped blob carrying the sealed data.
                        createObjectResponse.PrivateBlob.WriteTo(ref writer);

                        //outPublic (TPM2B_PUBLIC): the sealed object's public area.
                        createObjectResponse.OutPublic.WriteTo(ref writer);

                        //creationData, creationHash and creationTicket, in the order Part 3, clause 12.1's
                        //response table fixes; no Name, which TPM2_Create() does not return.
                        createObjectResponse.CreationData.WriteTo(ref writer);
                        createObjectResponse.CreationHash.WriteTo(ref writer);
                        createObjectResponse.CreationTicket.WriteTo(ref writer);

                        break;
                    }
                    case TpmLoadResponse loadResponse:
                    {
                        //objectHandle (the response handle area).
                        writer.WriteUInt32(loadResponse.ObjectHandle.Value);

                        //name (TPM2B_NAME): the loaded object's Name.
                        loadResponse.Name.WriteTo(ref writer);

                        break;
                    }
                    case TpmUnsealResponse unsealResponse:
                    {
                        //outData (TPM2B_SENSITIVE_DATA): the recovered sealed data, viewed at this framing
                        //primitive from the carrier the loaded sealed object owns.
                        writer.WriteTpm2b(unsealResponse.OutData.AsReadOnlySpan());

                        break;
                    }
                    case TpmNvReadDataResponse nvReadDataResponse:
                    {
                        //data (TPM2B_MAX_NV_BUFFER): the requested window of the NV Index's data area, copied out
                        //of the carrier the still-live Index owns — framing borrows it and never releases it.
                        writer.WriteTpm2b(nvReadDataResponse.Data.Span);

                        break;
                    }
                    case TpmNvReadPublicResponse nvReadPublicResponse:
                    {
                        //nvPublic (TPM2B_NV_PUBLIC): a UINT16 size prefix wrapping the marshaled TPMS_NV_PUBLIC.
                        writer.WriteUInt16((ushort)nvReadPublicResponse.NvPublic.SerializedSize);
                        nvReadPublicResponse.NvPublic.WriteTo(ref writer);

                        //nvName (TPM2B_NAME): the Index's computed Name.
                        nvReadPublicResponse.NvName.WriteTo(ref writer);

                        break;
                    }
                    case TpmCertifyResponse certifyResponse:
                    {
                        //certifyInfo (TPM2B_ATTEST) then signature (TPMT_SIGNATURE): each structure writes itself.
                        certifyResponse.CertifyInfo.WriteTo(ref writer);
                        certifyResponse.Signature.WriteTo(ref writer);

                        break;
                    }
                    case TpmCertifyCreationResponse certifyCreationResponse:
                    {
                        //certifyInfo (TPM2B_ATTEST) then signature (TPMT_SIGNATURE): each structure writes itself.
                        certifyCreationResponse.CertifyInfo.WriteTo(ref writer);
                        certifyCreationResponse.Signature.WriteTo(ref writer);

                        break;
                    }
                    case TpmGetTimeResponse getTimeResponse:
                    {
                        //timeInfo (TPM2B_ATTEST) then signature (TPMT_SIGNATURE): each structure writes itself.
                        getTimeResponse.TimeInfo.WriteTo(ref writer);
                        getTimeResponse.Signature.WriteTo(ref writer);

                        break;
                    }
                    case TpmNvCertifyResponse nvCertifyResponse:
                    {
                        //certifyInfo (TPM2B_ATTEST) then signature (TPMT_SIGNATURE): each structure writes itself,
                        //the same layout the session arm frames into its parameter area.
                        nvCertifyResponse.CertifyInfo.WriteTo(ref writer);
                        nvCertifyResponse.Signature.WriteTo(ref writer);

                        break;
                    }
                    case TpmVerifySignatureResponse verifySignatureResponse:
                    {
                        //validation (TPMT_TK_VERIFIED): tag (TPM_ST_VERIFIED) + hierarchy + digest (TPM2B_DIGEST) —
                        //the HMAC over TPM_ST_VERIFIED || digest || keyName under the verifying key's re-derived
                        //hierarchy proof, written by the structure itself. No attest, no TPMT_SIGNATURE — the odd
                        //one out among the attest-family responses above.
                        verifySignatureResponse.Validation.WriteTo(ref writer);

                        break;
                    }
                    case TpmReadClockResponse readClockResponse:
                    {
                        //currentTime (TPMS_TIME_INFO): fixed layout, no TPM2B wrapping.
                        readClockResponse.CurrentTime.WriteTo(ref writer);

                        break;
                    }
                    case TpmPcrReadResponse pcrReadResponse:
                    {
                        //pcrUpdateCounter (UINT32): zero this slice (no register has been extended).
                        writer.WriteUInt32(pcrReadResponse.PcrUpdateCounter);

                        //pcrSelectionOut (TPML_PCR_SELECTION): the caller's selection echoed verbatim — the
                        //simulator returns every selected register in one read.
                        writer.WriteBytes(pcrReadResponse.SelectionBytes.Span);

                        //pcrValues (TPML_DIGEST): count then each register value as a TPM2B_DIGEST, in ascending
                        //PCR-index order.
                        writer.WriteUInt32((uint)pcrReadResponse.PcrValues.Length);
                        for(int i = 0; i < pcrReadResponse.PcrValues.Length; i++)
                        {
                            writer.WriteTpm2b(pcrReadResponse.PcrValues[i].Span);
                        }

                        break;
                    }
                    case TpmQuoteResponse quoteResponse:
                    {
                        //quoted (TPM2B_ATTEST) then signature (TPMT_SIGNATURE): each structure writes itself.
                        quoteResponse.Quoted.WriteTo(ref writer);
                        quoteResponse.Signature.WriteTo(ref writer);

                        break;
                    }
                    case TpmStartAuthSessionResponse startAuthSessionResponse:
                    {
                        //sessionHandle (the response handle area).
                        writer.WriteUInt32(startAuthSessionResponse.SessionHandle.Value);

                        //nonceTPM (TPM2B_NONCE): the session's real, retained nonce (TPM 2.0 Library Part 3, clause
                        //11.1) for every session kind — a bound HMAC session's session-key KDFa consumed it, and a
                        //policy/trial session's TPM2_PolicySigned() aHash later binds to it (Part 3, Section 23.3),
                        //so neither can be a fixed placeholder.
                        startAuthSessionResponse.NonceTpm.WriteTo(ref writer);

                        break;
                    }
                    case TpmPolicyGetDigestResponse policyGetDigestResponse:
                    {
                        //policyDigest (TPM2B_DIGEST): the session's accumulated policyDigest, copied out of the
                        //carrier the still-live session owns — framing borrows it and never releases it.
                        policyGetDigestResponse.PolicyDigest.WriteTo(ref writer);

                        break;
                    }
                    case TpmPolicySecretResponse policySecretResponse:
                    {
                        WriteAuthTicketResponse(
                            ref writer, (ushort)TpmStConstants.TPM_ST_AUTH_SECRET, policySecretResponse.Timeout,
                            policySecretResponse.Hierarchy.Value, policySecretResponse.TicketDigest);

                        break;
                    }
                    case TpmPolicySignedResponse policySignedResponse:
                    {
                        WriteAuthTicketResponse(
                            ref writer, (ushort)TpmStConstants.TPM_ST_AUTH_SIGNED, policySignedResponse.Timeout,
                            policySignedResponse.Hierarchy.Value, policySignedResponse.TicketDigest);

                        break;
                    }
                    case TpmMakeCredentialResponse makeCredentialResponse:
                    {
                        //credentialBlob (TPM2B_ID_OBJECT): the integrity-protected, encrypted credential.
                        makeCredentialResponse.CredentialBlob.WriteTo(ref writer);

                        //secret (TPM2B_ENCRYPTED_SECRET): the seed transport (the marshaled ephemeral public point).
                        makeCredentialResponse.Secret.WriteTo(ref writer);

                        break;
                    }
                    case TpmActivateCredentialResponse activateCredentialResponse:
                    {
                        //certInfo (TPM2B_DIGEST): the recovered credential secret.
                        activateCredentialResponse.CertInfo.WriteTo(ref writer);

                        break;
                    }
                    default:
                    {
                        break;
                    }
                }

                return TpmResult<TpmResponse>.Success(new TpmResponse(owner, total));
            }
            catch
            {
                owner.Dispose();
                throw;
            }
        }
        finally
        {
            randomBuffer?.Dispose();
            capabilityData?.Dispose();
            createdPublic?.Dispose();
            createdCreationData?.Dispose();
            createdCreationHash?.Dispose();
            createdCreationTicket?.Dispose();
            createdName?.Dispose();
            signatureValue?.Dispose();
            sealedPrivate?.Dispose();
            sealedPublic?.Dispose();
            sealedCreationData?.Dispose();
            sealedCreationHash?.Dispose();
            sealedCreationTicket?.Dispose();
            loadedName?.Dispose();
            nvReadPublicArea?.Dispose();
            nvReadPublicName?.Dispose();
            certifyInfoBuffer?.Dispose();
            certifySignature?.Dispose();
            certifyCreationInfoBuffer?.Dispose();
            certifyCreationSignature?.Dispose();
            timeInfoBuffer?.Dispose();
            timeSignature?.Dispose();
            nvCertifyInfoBuffer?.Dispose();
            nvCertifySignature?.Dispose();
            verifySignatureValidation?.Dispose();
            policySecretTimeout?.Dispose();
            policySecretTicketDigest?.Dispose();
            policySignedTimeout?.Dispose();
            policySignedTicketDigest?.Dispose();
            quotedBuffer?.Dispose();
            quoteSignature?.Dispose();
            credentialBlobBuffer?.Dispose();
            credentialSecretBuffer?.Dispose();
            startedSessionNonce?.Dispose();

            //The recovered credential secret is confidential: releasing its carrier returns the pinned segment to
            //the pool, which zeroes every segment it takes back, so the framed octets do not outlive the response.
            activatedCredential?.CertInfo.Dispose();
        }

        //The serialized size of a TPML_DIGEST (UINT32 count + each value as a TPM2B_DIGEST): the pcrValues member
        //of a TPM2_PCR_Read() response.
        static int PcrValuesSerializedSize(ImmutableArray<ReadOnlyMemory<byte>> values)
        {
            int size = sizeof(uint);
            for(int i = 0; i < values.Length; i++)
            {
                size += sizeof(ushort) + values[i].Length;
            }

            return size;
        }
    }

    /// <summary>
    /// Frames an encrypt-attributed <c>TPM2_GetRandom()</c> response (TPM 2.0 Library Part 3, clause 16.1; Part
    /// 1, clause 16.7). Unlike every no-sessions response, this is <c>TPM_ST_SESSIONS</c>-tagged and carries a
    /// trailing response session area: after the header (GetRandom has no response handles) come parameterSize
    /// (UINT32), the encrypted response parameter area, then TPMS_AUTH_RESPONSE (nonceTPM as TPM2B_NONCE +
    /// sessionAttributes (BYTE) + hmac as TPM2B).
    /// </summary>
    /// <remarks>
    /// The parameter-area and HMAC buffers are the terminal owners released here; the parameter area holds the
    /// recovered value the encryption protects, so it is zeroed before disposal.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "TpmResponse takes ownership of the rented buffer and is owned by the returned TpmResult, which the caller disposes.")]
    private static TpmResult<TpmResponse> SerializeEncryptedRandomResponse(TpmEncryptedRandomResponse intent, BaseMemoryPool pool)
    {
        try
        {
            int nonceLength = intent.NonceTpm.Size;
            int authAreaSize =
                (sizeof(ushort) + nonceLength)          //nonceTPM (TPM2B_NONCE).
                + sizeof(byte)                          //sessionAttributes.
                + intent.Hmac.SerializedSize;           //hmac (TPM2B).

            //parameterSize (UINT32) + the encrypted parameter area + the response session area.
            int parameterSize = intent.ParameterArea.Length;
            int total = TpmHeader.HeaderSize + sizeof(uint) + parameterSize + authAreaSize;

            IMemoryOwner<byte> owner = pool.Rent(total);
            try
            {
                var writer = new TpmWriter(owner.Memory.Span[..total]);

                //Header carries the sessions tag so the caller parses the response session area (Part 1, clause 18).
                var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)total, (uint)intent.ResponseCode);
                header.WriteTo(ref writer);

                //parameterSize then the encrypted TPM2B_DIGEST (its size field is the unprotected count).
                writer.WriteUInt32((uint)parameterSize);
                writer.WriteBytes(intent.ParameterArea.Span);

                //Response session area: nonceTPM, sessionAttributes (echoed and HMAC'd identically), hmac.
                intent.NonceTpm.WriteTo(ref writer);
                writer.WriteByte((byte)intent.SessionAttributes);
                intent.Hmac.WriteTo(ref writer);

                return TpmResult<TpmResponse>.Success(new TpmResponse(owner, total));
            }
            catch
            {
                owner.Dispose();
                throw;
            }
        }
        finally
        {
            //Zero the recovered value before returning the parameter-area buffer to the pool, matching the
            //clear-before-dispose discipline the executor uses for the decrypted response parameter.
            intent.ParameterArea.Memory.Span.Clear();
            intent.ParameterArea.Dispose();
            intent.NonceTpm.Dispose();
            intent.Hmac.Dispose();
        }
    }

    /// <summary>
    /// Frames a session-authorized TPM2_PolicySecret() response (TPM 2.0 Library Part 3, Section 23.4).
    /// </summary>
    /// <remarks>
    /// The same TPM_ST_SESSIONS-tagged, one-session-entry shape <c>SerializeEncryptedRandomResponse</c> frames,
    /// with the framed TPM2B_TIMEOUT ‖ TPMT_TK_AUTH bytes standing in for GetRandom's encrypted TPM2B_DIGEST. The
    /// parameter-area and HMAC buffers are the terminal owners released here.
    /// </remarks>
    /// <param name="intent">The framed session response to serialize.</param>
    /// <param name="pool">The memory pool for the response buffer.</param>
    /// <returns>The serialized <see cref="TpmResponse"/> wrapped in a <see cref="TpmResult{T}"/>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "TpmResponse takes ownership of the rented buffer and is owned by the returned TpmResult, which the caller disposes.")]
    private static TpmResult<TpmResponse> SerializePolicySecretOverSessionResponse(TpmPolicySecretOverSessionResponse intent, BaseMemoryPool pool)
    {
        try
        {
            int nonceLength = intent.NonceTpm.Size;
            int authAreaSize =
                (sizeof(ushort) + nonceLength)          //nonceTPM (TPM2B_NONCE).
                + sizeof(byte)                          //sessionAttributes.
                + intent.Hmac.SerializedSize;           //hmac (TPM2B).

            //parameterSize (UINT32) + the framed timeout/ticket parameter area + the response session area.
            int parameterSize = intent.ParameterArea.Length;
            int total = TpmHeader.HeaderSize + sizeof(uint) + parameterSize + authAreaSize;

            IMemoryOwner<byte> owner = pool.Rent(total);
            try
            {
                var writer = new TpmWriter(owner.Memory.Span[..total]);

                //Header carries the sessions tag so the caller parses the trailing response session area.
                var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)total, (uint)intent.ResponseCode);
                header.WriteTo(ref writer);

                //parameterSize then the already-framed TPM2B_TIMEOUT ‖ TPMT_TK_AUTH bytes verbatim.
                writer.WriteUInt32((uint)parameterSize);
                writer.WriteBytes(intent.ParameterArea.Span);

                //Response session area: nonceTPM, sessionAttributes (echoed and HMAC'd identically), hmac.
                intent.NonceTpm.WriteTo(ref writer);
                writer.WriteByte((byte)intent.SessionAttributes);
                intent.Hmac.WriteTo(ref writer);

                return TpmResult<TpmResponse>.Success(new TpmResponse(owner, total));
            }
            catch
            {
                owner.Dispose();
                throw;
            }
        }
        finally
        {
            intent.ParameterArea.Dispose();
            intent.NonceTpm.Dispose();
            intent.Hmac.Dispose();
        }
    }

    /// <summary>
    /// Frames a session-authorized command's response for the commands whose authorization area carries exactly
    /// one session: the NV family (<c>TPM2_NV_Read()</c>, <c>TPM2_NV_Write()</c>, <c>TPM2_NV_DefineSpace()</c>,
    /// <c>TPM2_NV_UndefineSpace()</c>) and the parameter-free hierarchy and provisioning commands
    /// (<c>TPM2_Clear()</c>, <c>TPM2_ClearControl()</c>, <c>TPM2_HierarchyControl()</c>,
    /// <c>TPM2_SetPrimaryPolicy()</c>) (TPM 2.0 Library Part 1, clause 16.6.1).
    /// </summary>
    /// <remarks>
    /// The same TPM_ST_SESSIONS-tagged, one-session-entry shape <c>SerializePolicySecretOverSessionResponse</c>
    /// frames, generalized over an empty-or-populated parameter area (empty for Write/DefineSpace/UndefineSpace,
    /// the framed TPM2B_MAX_NV_BUFFER for Read). The parameter-area and HMAC buffers are the terminal owners
    /// released here.
    /// </remarks>
    /// <param name="intent">The framed session response to serialize.</param>
    /// <param name="pool">The memory pool for the response buffer.</param>
    /// <returns>The serialized <see cref="TpmResponse"/> wrapped in a <see cref="TpmResult{T}"/>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "TpmResponse takes ownership of the rented buffer and is owned by the returned TpmResult, which the caller disposes.")]
    private static TpmResult<TpmResponse> SerializeNvSessionResponse(TpmNvSessionResponse intent, BaseMemoryPool pool)
    {
        try
        {
            int nonceLength = intent.NonceTpm.Size;
            int authAreaSize =
                (sizeof(ushort) + nonceLength)          //nonceTPM (TPM2B_NONCE).
                + sizeof(byte)                          //sessionAttributes.
                + intent.Hmac.SerializedSize;           //hmac (TPM2B).

            //parameterSize (UINT32) + the already-framed response parameter bytes + the response session area.
            int parameterSize = intent.ParameterArea.Length;
            int total = TpmHeader.HeaderSize + sizeof(uint) + parameterSize + authAreaSize;

            IMemoryOwner<byte> owner = pool.Rent(total);
            try
            {
                var writer = new TpmWriter(owner.Memory.Span[..total]);

                //Header carries the sessions tag so the caller parses the trailing response session area.
                var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)total, (uint)intent.ResponseCode);
                header.WriteTo(ref writer);

                //parameterSize then the already-framed response parameter bytes verbatim (zero-length for
                //Write/DefineSpace/UndefineSpace).
                writer.WriteUInt32((uint)parameterSize);
                writer.WriteBytes(intent.ParameterArea.Span);

                //Response session area: nonceTPM, sessionAttributes (echoed and HMAC'd identically), hmac.
                intent.NonceTpm.WriteTo(ref writer);
                writer.WriteByte((byte)intent.SessionAttributes);
                intent.Hmac.WriteTo(ref writer);

                return TpmResult<TpmResponse>.Success(new TpmResponse(owner, total));
            }
            catch
            {
                owner.Dispose();
                throw;
            }
        }
        finally
        {
            intent.ParameterArea.Dispose();
            intent.NonceTpm.Dispose();
            intent.Hmac.Dispose();
        }
    }

    /// <summary>
    /// Frames an authValue rotation's response — <c>TPM2_NV_ChangeAuth()</c> or
    /// <c>TPM2_HierarchyChangeAuth()</c>: a <c>TPM_ST_SESSIONS</c>-tagged envelope with a zero-length parameter
    /// area — neither command returns parameters (TPM 2.0 Library Part 3, clause 31.15, Table 253 and clause
    /// 24.8, Table 189) — followed by one entry per command session, in command-session order (Part 1, clause 17.6).
    /// </summary>
    /// <remarks>
    /// The <c>parameterSize</c> field is still written, and still zero, because the envelope is
    /// session-tagged: a caller parses the response session area only after consuming that length prefix. Entry
    /// order matches the order the executor parsed and verified the command's sessions in, so a byte off in
    /// either entry fails the caller's own verification. A <c>TPM_RS_PW</c> slot's entry is the placeholder shape
    /// <see cref="SerializeCreateOverSessionsResponse"/> also frames — an empty nonceTPM, the echoed attributes,
    /// and an empty hmac — and still occupies its own wire position. Each real entry's HMAC buffer is the
    /// terminal owner released here; a placeholder owns none.
    /// </remarks>
    /// <param name="intent">The framed session entries to serialize.</param>
    /// <param name="pool">The memory pool for the response buffer.</param>
    /// <returns>The serialized <see cref="TpmResponse"/> wrapped in a <see cref="TpmResult{T}"/>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "TpmResponse takes ownership of the rented buffer and is owned by the returned TpmResult, which the caller disposes.")]
    private static TpmResult<TpmResponse> SerializeNvChangeAuthResponse(TpmNvChangeAuthResponse intent, BaseMemoryPool pool)
    {
        try
        {
            int authAreaSize = 0;
            foreach(TpmNvChangeAuthFramedSessionEntry entry in intent.Entries)
            {
                authAreaSize +=
                    entry.NewNonceTpm.SerializedSize  //nonceTPM (TPM2B_NONCE), empty for a password slot.
                    + sizeof(byte)                               //sessionAttributes.
                    + (entry.Hmac?.SerializedSize ?? sizeof(ushort)); //hmac (TPM2B), empty for a password slot.
            }

            int total = TpmHeader.HeaderSize + sizeof(uint) + authAreaSize;

            IMemoryOwner<byte> owner = pool.Rent(total);
            try
            {
                var writer = new TpmWriter(owner.Memory.Span[..total]);

                var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)total, (uint)intent.ResponseCode);
                header.WriteTo(ref writer);

                writer.WriteUInt32(0u);

                foreach(TpmNvChangeAuthFramedSessionEntry entry in intent.Entries)
                {
                    if(entry.Hmac is Tpm2bAuth entryHmac)
                    {
                        entry.NewNonceTpm.WriteTo(ref writer);
                        writer.WriteByte((byte)entry.SessionAttributes);
                        entryHmac.WriteTo(ref writer);

                        continue;
                    }

                    //A password slot's placeholder: an empty nonceTPM and an empty hmac, since a password
                    //authorization carries no session key to compute one with.
                    writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
                    writer.WriteByte((byte)entry.SessionAttributes);
                    writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
                }

                return TpmResult<TpmResponse>.Success(new TpmResponse(owner, total));
            }
            catch
            {
                owner.Dispose();
                throw;
            }
        }
        finally
        {
            foreach(TpmNvChangeAuthFramedSessionEntry entry in intent.Entries)
            {
                entry.NewNonceTpm.Dispose();
                entry.Hmac?.Dispose();
            }
        }
    }

    /// <summary>
    /// Frames a <c>TPM2_Unseal()</c> response over 0, 1, or 2 real sessions plus an optional leading policy
    /// placeholder entry (TPM 2.0 Library Part 3, clause 12.7; Part 1, clause 16.7).
    /// </summary>
    /// <remarks>
    /// Like the encrypt-attributed GetRandom response it is <c>TPM_ST_SESSIONS</c>-tagged, but its response
    /// session area carries one entry per command session, in order: after the header (Unseal has no response
    /// handles) come parameterSize (UINT32), the (possibly encrypted) outData (TPM2B_SENSITIVE_DATA), then the
    /// policy placeholder entry when present (a zero nonceTPM of its hash width + echoed sessionAttributes + an
    /// EMPTY hmac — a satisfied plain policy session carries no key, so the TPM returns a zero-length response
    /// HMAC for it, Part 1, clause 17.6), followed by every real session's entry (its rolled nonceTPM + echoed
    /// sessionAttributes + its own response hmac). The order matches the order the executor parses and verifies
    /// the sessions in, so a byte-off in any entry fails the caller's verification. The parameter-area and each
    /// entry's HMAC buffer are the terminal owners released here; the parameter area holds the recovered secret,
    /// encrypted when a session carries the encrypt attribute, so it is zeroed before disposal regardless.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "TpmResponse takes ownership of the rented buffer and is owned by the returned TpmResult, which the caller disposes.")]
    private static TpmResult<TpmResponse> SerializeUnsealOverSessionsResponse(TpmUnsealOverSessionsResponse intent, BaseMemoryPool pool)
    {
        try
        {
            //Policy placeholder entry (present only when HasPolicyPlaceholder is set): a zero nonceTPM of the
            //policy hash width, the echoed attributes, and an empty hmac.
            int policyAuthSize = intent.HasPolicyPlaceholder
                ? (sizeof(ushort) + intent.PolicyNonceLength) + sizeof(byte) + sizeof(ushort)
                : 0;

            //One entry per real session: its rolled nonceTPM, the echoed attributes, and its own response HMAC.
            int realAuthSize = 0;
            foreach(TpmUnsealFramedSessionEntry entry in intent.Entries)
            {
                realAuthSize +=
                    entry.NewNonceTpm.SerializedSize //nonceTPM (TPM2B_NONCE).
                    + sizeof(byte)                              //sessionAttributes.
                    + entry.Hmac.SerializedSize;                //hmac (TPM2B).
            }

            int authAreaSize = policyAuthSize + realAuthSize;

            //parameterSize (UINT32) + the (possibly encrypted) parameter area + the response session area.
            int parameterSize = intent.ParameterArea.Length;
            int total = TpmHeader.HeaderSize + sizeof(uint) + parameterSize + authAreaSize;

            IMemoryOwner<byte> owner = pool.Rent(total);
            try
            {
                var writer = new TpmWriter(owner.Memory.Span[..total]);

                //Header carries the sessions tag so the caller parses the response session area (Part 1, clause 18).
                var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)total, (uint)intent.ResponseCode);
                header.WriteTo(ref writer);

                //parameterSize then the (possibly encrypted) outData (its TPM2B size field is the unprotected
                //count). Unseal returns no response handle, so the parameter area follows the header directly
                //(Part 3, clause 12.7).
                writer.WriteUInt32((uint)parameterSize);
                writer.WriteBytes(intent.ParameterArea.Span);

                //Response session area, in command-session order. The policy placeholder, when present, is always
                //session index 0 (a policy session can only ever be Unseal's first, primary-authorizing session).
                if(intent.HasPolicyPlaceholder)
                {
                    Span<byte> policyNonce = stackalloc byte[intent.PolicyNonceLength];
                    policyNonce.Clear();
                    writer.WriteTpm2b(policyNonce);
                    writer.WriteByte((byte)intent.PolicyAttributes);
                    writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
                }

                //Every real session's entry, in command-session order: its rolled nonceTPM (nonceNewer), echoed
                //attributes (HMAC'd identically), and its own response HMAC.
                foreach(TpmUnsealFramedSessionEntry entry in intent.Entries)
                {
                    entry.NewNonceTpm.WriteTo(ref writer);
                    writer.WriteByte((byte)entry.SessionAttributes);
                    entry.Hmac.WriteTo(ref writer);
                }

                return TpmResult<TpmResponse>.Success(new TpmResponse(owner, total));
            }
            catch
            {
                owner.Dispose();
                throw;
            }
        }
        finally
        {
            //Zero the recovered secret before returning the parameter-area buffer to the pool, matching the
            //clear-before-dispose discipline the executor uses for the decrypted response parameter.
            intent.ParameterArea.Memory.Span.Clear();
            intent.ParameterArea.Dispose();
            foreach(TpmUnsealFramedSessionEntry entry in intent.Entries)
            {
                entry.NewNonceTpm.Dispose();
                entry.Hmac.Dispose();
            }
        }
    }

    /// <summary>
    /// Frames a <c>TPM2_Create()</c> response over one or two sessions — the request-decrypt counterpart of
    /// <see cref="SerializeUnsealOverSessionsResponse"/>.
    /// </summary>
    /// <remarks>
    /// Like the Unseal response it is <c>TPM_ST_SESSIONS</c>-tagged with a trailing response session area, in
    /// command-session order: a <c>TPM_RS_PW</c> parent-auth session's placeholder entry (an EMPTY nonceTPM —
    /// unlike a policy placeholder's zero-VALUE, hash-width nonce, Part 1, clause 17.6.4 — plus an empty hmac)
    /// when HasPasswordPlaceholder is set, then every real session's entry (its rolled nonceTPM, echoed
    /// attributes, its own response HMAC). <c>TPM2_Create()</c> has no response handle, so parameterSize then
    /// the parameter area (outPrivate ‖ outPublic ‖ creationByProducts, never encrypted here) follow the header
    /// directly (Part 3, clause 12.1). The parameter-area and each entry's HMAC buffer are the terminal owners
    /// released here.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "TpmResponse takes ownership of the rented buffer and is owned by the returned TpmResult, which the caller disposes.")]
    private static TpmResult<TpmResponse> SerializeCreateOverSessionsResponse(TpmCreateOverSessionsResponse intent, BaseMemoryPool pool)
    {
        try
        {
            //Password placeholder entry (present only when HasPasswordPlaceholder is set): an EMPTY nonceTPM
            //(size 0, Part 1, clause 17.6.4 — unlike a policy session's zero-VALUE, hash-width nonce), the echoed
            //(forced continueSession) attributes, and an empty hmac.
            int passwordAuthSize = intent.HasPasswordPlaceholder
                ? sizeof(ushort) + sizeof(byte) + sizeof(ushort)
                : 0;

            int realAuthSize = 0;
            foreach(TpmCreateFramedSessionEntry entry in intent.Entries)
            {
                realAuthSize +=
                    entry.NewNonceTpm.SerializedSize
                    + sizeof(byte)
                    + entry.Hmac.SerializedSize;
            }

            int authAreaSize = passwordAuthSize + realAuthSize;

            int parameterSize = intent.ParameterArea.Length;
            int total = TpmHeader.HeaderSize + sizeof(uint) + parameterSize + authAreaSize;

            IMemoryOwner<byte> owner = pool.Rent(total);
            try
            {
                var writer = new TpmWriter(owner.Memory.Span[..total]);

                var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)total, (uint)intent.ResponseCode);
                header.WriteTo(ref writer);

                writer.WriteUInt32((uint)parameterSize);
                writer.WriteBytes(intent.ParameterArea.Span);

                //The password placeholder, when present, is always session index 0 (TPM_RS_PW can only ever be
                //TPM2_Create()'s first, parent-authorizing session).
                if(intent.HasPasswordPlaceholder)
                {
                    writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
                    writer.WriteByte((byte)intent.PasswordPlaceholderAttributes);
                    writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
                }

                foreach(TpmCreateFramedSessionEntry entry in intent.Entries)
                {
                    entry.NewNonceTpm.WriteTo(ref writer);
                    writer.WriteByte((byte)entry.SessionAttributes);
                    entry.Hmac.WriteTo(ref writer);
                }

                return TpmResult<TpmResponse>.Success(new TpmResponse(owner, total));
            }
            catch
            {
                owner.Dispose();
                throw;
            }
        }
        finally
        {
            intent.ParameterArea.Dispose();
            foreach(TpmCreateFramedSessionEntry entry in intent.Entries)
            {
                entry.NewNonceTpm.Dispose();
                entry.Hmac.Dispose();
            }
        }
    }

    /// <summary>
    /// Frames an attest command's response — <c>TPM2_Certify()</c>, <c>TPM2_CertifyCreation()</c>,
    /// <c>TPM2_Quote()</c>, <c>TPM2_GetTime()</c>, <c>TPM2_NV_Certify()</c> — over an authorization area carrying at
    /// least one real session (TPM 2.0 Library Part 3, Tables 90, 92, 94, 100, and 255; Part 1, clause 16.6.1).
    /// </summary>
    /// <remarks>
    /// The shape <see cref="SerializeCreateOverSessionsResponse"/> frames, with the placeholder decided per entry
    /// instead of by a single leading flag: an attest command authorizes each of its handles independently, so a
    /// <c>TPM_RS_PW</c> slot can sit at any index. After the header (no attest command returns a response handle)
    /// come parameterSize (UINT32), the framed <c>TPM2B_ATTEST ‖ TPMT_SIGNATURE</c>, then one entry per command
    /// session in command-session order — a password slot's empty nonceTPM, echoed attributes, and empty hmac, or
    /// a real session's rolled nonceTPM, echoed attributes, and its own response hmac. The order matches the order
    /// the executor parsed and verified the sessions in, so a byte off in any entry fails the caller's own
    /// verification. The parameter-area and each real entry's HMAC buffer are the terminal owners released here.
    /// </remarks>
    /// <param name="intent">The framed response to serialize.</param>
    /// <param name="pool">The memory pool for the response buffer.</param>
    /// <returns>The serialized <see cref="TpmResponse"/> wrapped in a <see cref="TpmResult{T}"/>.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "TpmResponse takes ownership of the rented buffer and is owned by the returned TpmResult, which the caller disposes.")]
    private static TpmResult<TpmResponse> SerializeAttestOverSessionsResponse(TpmAttestOverSessionsResponse intent, BaseMemoryPool pool)
    {
        try
        {
            int authAreaSize = 0;
            foreach(TpmAttestFramedSessionEntry entry in intent.Entries)
            {
                authAreaSize +=
                    entry.NewNonceTpm.SerializedSize  //nonceTPM (TPM2B_NONCE), empty for a password slot.
                    + sizeof(byte)                               //sessionAttributes.
                    + (entry.Hmac?.SerializedSize ?? sizeof(ushort)); //hmac (TPM2B), empty for a password slot.
            }

            int parameterSize = intent.ParameterArea.Length;
            int total = TpmHeader.HeaderSize + sizeof(uint) + parameterSize + authAreaSize;

            IMemoryOwner<byte> owner = pool.Rent(total);
            try
            {
                var writer = new TpmWriter(owner.Memory.Span[..total]);

                var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)total, (uint)intent.ResponseCode);
                header.WriteTo(ref writer);

                writer.WriteUInt32((uint)parameterSize);
                writer.WriteBytes(intent.ParameterArea.Span);

                foreach(TpmAttestFramedSessionEntry entry in intent.Entries)
                {
                    if(entry.Hmac is Tpm2bAuth entryHmac)
                    {
                        entry.NewNonceTpm.WriteTo(ref writer);
                        writer.WriteByte((byte)entry.SessionAttributes);
                        entryHmac.WriteTo(ref writer);

                        continue;
                    }

                    //A password slot's placeholder: an empty nonceTPM and an empty hmac, since a password
                    //authorization carries no session key to compute one with.
                    writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
                    writer.WriteByte((byte)entry.SessionAttributes);
                    writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
                }

                return TpmResult<TpmResponse>.Success(new TpmResponse(owner, total));
            }
            catch
            {
                owner.Dispose();
                throw;
            }
        }
        finally
        {
            intent.ParameterArea.Dispose();
            foreach(TpmAttestFramedSessionEntry entry in intent.Entries)
            {
                entry.NewNonceTpm.Dispose();
                entry.Hmac?.Dispose();
            }
        }
    }
}
