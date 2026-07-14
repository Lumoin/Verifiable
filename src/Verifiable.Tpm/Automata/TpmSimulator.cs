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
using Verifiable.Tpm.Infrastructure.Spec.Attributes;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

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
/// The device owns a single live automaton with one run identifier and one trace stream
/// (design decision D2), reachable via <see cref="Subscribe"/>. Commands are processed serially, as a
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
public sealed class TpmSimulator: IObservable<TraceEntry<TpmSimulatorState, TpmSimulatorInput>>
{
    /// <summary>The live automaton holding this TPM's state of record.</summary>
    private PushdownAutomaton<TpmSimulatorState, TpmSimulatorInput, TpmSimulatorStackSymbol> Automaton { get; }

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
    /// The per-TPM seed from which the hierarchy creation-ticket proofs derive — the simulator's stand-in for
    /// the persistent random secrets a real TPM fixes at manufacture and keeps in NV.
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
        Automaton = new PushdownAutomaton<TpmSimulatorState, TpmSimulatorInput, TpmSimulatorStackSymbol>(
            runId: tpmId,
            initialState: TpmSimulatorState.PoweredOff(tpmId, selfTest, clockAdvanceQuantumMs),
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
    public IDisposable Subscribe(IObserver<TraceEntry<TpmSimulatorState, TpmSimulatorInput>> observer) =>
        Automaton.Subscribe(observer);

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
    public async ValueTask<TpmResult<TpmResponse>> SubmitAsync(ReadOnlyMemory<byte> command, MemoryPool<byte> pool, CancellationToken cancellationToken)
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

    private async ValueTask RunWithEffectsAsync(TpmSimulatorInput input, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        _ = await PdaRunner.StepWithEffectsAsync<TpmSimulatorState, TpmSimulatorInput, TpmActionContext>(
            Automaton.CurrentState,
            Automaton.StepCount,
            input,
            step: StepCoreAsync,
            actionExtractor: static state => state.NextAction,
            actionExecutor: static (action, context, token) => ExecuteAction(action, context, token),
            actionContext: new TpmActionContext(Rng, pool, SigningBackend, RsaSigningBackend, ProofSeed),
            TimeProvider,
            cancellationToken).ConfigureAwait(false);
    }

    //Executes the effectful work a transition declared and feeds the result back as the next input so the
    //pure transition can frame the response without touching the RNG, the signing backend, or a buffer
    //itself: TPM2_GetRandom() draws octets, TPM2_CreatePrimary() generates a key or provisions a storage parent,
    //TPM2_Sign() signs a digest, TPM2_Create() seals data into a KEYEDHASH object, TPM2_Load() computes the
    //loaded object's Name, TPM2_Certify() marshals and signs an object attestation, TPM2_Quote() marshals
    //and signs a PCR attestation, TPM2_StartAuthSession() (HMAC) derives a bound session key, and an
    //encrypt-attributed TPM2_GetRandom() encrypts and authenticates its response (each step needs the RNG, a
    //backend, or the registered digest/HMAC/KDF seams).
    private static async ValueTask<TpmSimulatorInput> ExecuteAction(PdaAction action, TpmActionContext context, CancellationToken cancellationToken) =>
        action switch
        {
            TpmRngAction rngAction => GenerateRandom(rngAction, context),
            TpmCreateEccKeyAction createAction => await CreateEccKeyAsync(createAction, context, cancellationToken).ConfigureAwait(false),
            TpmCreateRsaKeyAction createRsaAction => await CreateRsaKeyAsync(createRsaAction, context, cancellationToken).ConfigureAwait(false),
            TpmEccSignAction signAction => await SignEccDigestAsync(signAction, context, cancellationToken).ConfigureAwait(false),
            TpmRsaSignAction rsaSignAction => await SignRsaDigestAsync(rsaSignAction, context, cancellationToken).ConfigureAwait(false),
            TpmCreateStorageParentAction storageParentAction => await CreateStorageParentAsync(storageParentAction, context, cancellationToken).ConfigureAwait(false),
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
            TpmStartHmacSessionAction startHmacAction => await StartHmacSessionAsync(startHmacAction, context, cancellationToken).ConfigureAwait(false),
            TpmEncryptRandomAction encryptRandomAction => await EncryptRandomOverSessionAsync(encryptRandomAction, context, cancellationToken).ConfigureAwait(false),
            TpmUnsealDataAction unsealAction => await UnsealOverSessionsAsync(unsealAction, context, cancellationToken).ConfigureAwait(false),
            TpmMakeCredentialAction makeCredentialAction => await MakeCredentialAsync(makeCredentialAction, context, cancellationToken).ConfigureAwait(false),
            TpmActivateCredentialAction activateCredentialAction => await ActivateCredentialAsync(activateCredentialAction, context, cancellationToken).ConfigureAwait(false),
            TpmComputeNvNameAction computeNvNameAction => await ComputeNvNameForPolicyAsync(computeNvNameAction, context, cancellationToken).ConfigureAwait(false),
            _ => throw new NotSupportedException($"No executor is registered for action '{action.GetType().Name}'.")
        };

    //SHA-256 digest size: the width of the creation hash, the ticket digest, and the derived hierarchy proof. The
    //simulator models a TPM whose context integrity algorithm is SHA-256 regardless of nameAlg (the object Name
    //itself is nameAlg-agile — see TpmObjectName — but the creation by-products this constant sizes are not).
    private const int CreationDigestSize = 32;

    //The simulator's synthetic firmware version, reported in every attestation's firmwareVersion field (TPM 2.0
    //Library Part 2, clause 10.12.12): a UINT32 major half of 1 and a minor half of 184, the same v184
    //spec-corpus revision TPM2_GetCapability() reports as TPM_PT_REVISION (TpmLifecycleTransitions.SimSpecRevision),
    //so the two surfaces agree on which spec edition this TPM models.
    private const ulong SimulatedFirmwareVersion = (1UL << 32) | 184UL;

    //The marshaled TPMS_CREATION_DATA for a primary under a permanent hierarchy: empty pcrSelect (UINT32 count 0),
    //pcrDigest (TPM2B of the SHA-256 digest), locality (BYTE), parentNameAlg (UINT16 = TPM_ALG_NULL), parentName
    //(TPM2B of the 4-octet parent handle), parentQualifiedName (the same), and outsideInfo (empty TPM2B).
    private const int CreationDataSize =
        sizeof(uint)
        + (sizeof(ushort) + CreationDigestSize)
        + sizeof(byte)
        + sizeof(ushort)
        + (sizeof(ushort) + sizeof(uint))
        + (sizeof(ushort) + sizeof(uint))
        + sizeof(ushort);

    //TPM2_CreatePrimary(): draw a key from the injected backend, build the exported public area and durable key
    //state from it (BuildKeyArtifacts, synchronous so the point spans never cross an await), then compute the
    //faithful creation by-products — Name, creationData, creationHash, creationTicket — through the registered
    //digest and HMAC seams. The generated key carrier is disposed once everything is copied out of it.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the public area and the by-products buffer transfers to the returned TpmPrimaryKeyCreated, then to the TpmCreatePrimaryResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> CreateEccKeyAsync(TpmCreateEccKeyAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        TpmEccSigningBackend backend = context.SigningBackend
            ?? throw new InvalidOperationException("TPM2_CreatePrimary() requires a signing backend, but none was supplied.");

        Tpm2bPublic outPublic;
        TransientKeyState keyState;
        using(TpmGeneratedEccKey key = await backend.GenerateKey(action.Curve, context.Pool, cancellationToken).ConfigureAwait(false))
        {
            (outPublic, keyState) = BuildKeyArtifacts(action, key, context.Pool);
        }

        //name = nameAlg || H_nameAlg(TPMT_PUBLIC), computed once: retained on the key state (so a later
        //TPM2_Certify() can bind it into the attestation without recomputing) and shared with the creation
        //by-products. The Name width depends on nameAlg (agile per TpmObjectName), so its length travels with it.
        (IMemoryOwner<byte> name, int nameLength) = await ComputeObjectNameAsync(outPublic, action.NameAlg, context.Pool, cancellationToken).ConfigureAwait(false);
        using(name)
        {
            keyState = keyState with { Name = name.Memory.Span[..nameLength].ToArray() };

            (IMemoryOwner<byte> creationByProducts, int creationByProductsLength) =
                await BuildCreationByProductsAsync(name.Memory[..nameLength], action.Hierarchy, context.ProofSeed, includeName: true, context.Pool, cancellationToken).ConfigureAwait(false);

            return new TpmPrimaryKeyCreated(outPublic, keyState, creationByProducts, creationByProductsLength);
        }
    }

    //Splits the generated point into its X and Y coordinates, builds the exported public area, and copies the
    //scalar into durable model memory. Synchronous so the point spans never cross an await.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the built public area transfers to the caller, which carries it to the response intent disposed by SerializeResponse.")]
    private static (Tpm2bPublic OutPublic, TransientKeyState KeyState) BuildKeyArtifacts(TpmCreateEccKeyAction action, TpmGeneratedEccKey key, MemoryPool<byte> pool)
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
            action.NameAlg, action.Attributes, action.Curve, TpmtEccScheme.Ecdsa(action.SchemeHashAlg), eccPoint, pool, action.AuthPolicy.Span);

        //The Name is filled by the caller once it has been computed from the exported public area (through the
        //asynchronous digest seam, which this synchronous point-splitting step must not cross). The SEC1 point is
        //retained so a later ECDH-based command can use this object's public key (TPM 2.0 Library Part 1, clause 24).
        var keyState = new TransientKeyState(
            action.Handle, action.Hierarchy, TpmAlgIdConstants.TPM_ALG_ECC, action.Curve, scalar.ToArray(), ReadOnlyMemory<byte>.Empty, action.Attributes, point.ToArray(), action.AuthPolicy);

        return (outPublic, keyState);
    }

    //TPM2_CreatePrimary() for an RSA key: draw a key from the injected RSA backend, build the exported public
    //area carrying the modulus and the durable key state, then compute the same faithful creation by-products
    //the ECC path does (they are key-type-agnostic — the Name hashes the marshaled TPMT_PUBLIC, which now
    //carries the modulus). The generated key carrier is disposed once everything is copied out of it.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the public area and the by-products buffer transfers to the returned TpmPrimaryKeyCreated, then to the TpmCreatePrimaryResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> CreateRsaKeyAsync(TpmCreateRsaKeyAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        TpmRsaSigningBackend backend = context.RsaSigningBackend
            ?? throw new InvalidOperationException("TPM2_CreatePrimary() for an RSA key requires an RSA signing backend, but none was supplied.");

        Tpm2bPublic outPublic;
        TransientKeyState keyState;
        using(TpmGeneratedRsaKey key = await backend.GenerateKey(action.KeyBits, context.Pool, cancellationToken).ConfigureAwait(false))
        {
            (outPublic, keyState) = BuildRsaKeyArtifacts(action, key, context.Pool);
        }

        //name = nameAlg || H_nameAlg(TPMT_PUBLIC), computed once: retained on the key state and shared with the
        //by-products (the Name hashes the marshaled TPMT_PUBLIC, which for an RSA key carries the modulus). The
        //Name width depends on nameAlg (agile per TpmObjectName), so its length travels with it.
        (IMemoryOwner<byte> name, int nameLength) = await ComputeObjectNameAsync(outPublic, action.NameAlg, context.Pool, cancellationToken).ConfigureAwait(false);
        using(name)
        {
            keyState = keyState with { Name = name.Memory.Span[..nameLength].ToArray() };

            (IMemoryOwner<byte> creationByProducts, int creationByProductsLength) =
                await BuildCreationByProductsAsync(name.Memory[..nameLength], action.Hierarchy, context.ProofSeed, includeName: true, context.Pool, cancellationToken).ConfigureAwait(false);

            return new TpmPrimaryKeyCreated(outPublic, keyState, creationByProducts, creationByProductsLength);
        }
    }

    //Builds the exported public area carrying the generated modulus and copies the private key into durable
    //model memory. Synchronous so the key spans never cross an await.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the built public area transfers to the caller, which carries it to the response intent disposed by SerializeResponse.")]
    private static (Tpm2bPublic OutPublic, TransientKeyState KeyState) BuildRsaKeyArtifacts(TpmCreateRsaKeyAction action, TpmGeneratedRsaKey key, MemoryPool<byte> pool)
    {
        ReadOnlySpan<byte> modulus = key.Modulus.AsReadOnlySpan();
        ReadOnlySpan<byte> privateKey = key.PrivateKey.AsReadOnlySpan();

        Tpm2bPublic outPublic = Tpm2bPublic.CreateRsaSigningKey(
            action.NameAlg, action.Attributes, action.KeyBits, action.Scheme, modulus, pool, action.AuthPolicy.Span);

        //The Name is filled by the caller once computed from the exported public area (through the asynchronous
        //digest seam, which this synchronous key-copying step must not cross). An RSA key carries no SEC1 point, so
        //the retained public point is empty (the ECDH-based credential commands model only ECC credential keys).
        var keyState = new TransientKeyState(
            action.Handle, action.Hierarchy, TpmAlgIdConstants.TPM_ALG_RSA, default, privateKey.ToArray(), ReadOnlyMemory<byte>.Empty, action.Attributes, ReadOnlyMemory<byte>.Empty, action.AuthPolicy);

        return (outPublic, keyState);
    }

    //Computes the faithful object-creation by-products (TPM 2.0 Library Part 3, clauses 24.1 and 12.1; Part 2,
    //clause 15) and frames them into one pooled buffer: creationData ‖ creationHash ‖ creationTicket, followed by
    //the Name only when includeName is set. TPM2_CreatePrimary() returns the Name (includeName true); TPM2_Create()
    //does not (includeName false). The already-computed Name is passed in (the caller computes it once and also
    //retains it on the key state) because the creation ticket HMACs over it. The framing is in the effectful layer
    //because the creation hash and ticket need the asynchronous digest/HMAC seams.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the framed by-products buffer transfers to the caller; the intermediate buffers are released by their using declarations.")]
    private static async ValueTask<(IMemoryOwner<byte> Owner, int Length)> BuildCreationByProductsAsync(
        ReadOnlyMemory<byte> name, uint hierarchy, ReadOnlyMemory<byte> proofSeed, bool includeName, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        //creationData (marshaled TPMS_CREATION_DATA); creationHash = H_nameAlg(creationData).
        using IMemoryOwner<byte> creationData = await BuildCreationDataAsync(hierarchy, pool, cancellationToken).ConfigureAwait(false);
        using DigestValue creationHash = await CryptographicKeyEvents.ComputeDigestAsync(
            creationData.Memory[..CreationDataSize], CreationDigestSize, CryptoTags.Sha256Digest, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        //creationTicket digest = HMAC(proof, TPM_ST_CREATION || name || creationHash).
        using IMemoryOwner<byte> proof = await DeriveHierarchyProofAsync(proofSeed, hierarchy, pool, cancellationToken).ConfigureAwait(false);
        using IMemoryOwner<byte> ticketDigest = await ComputeCreationTicketDigestAsync(
            proof.Memory[..CreationDigestSize], name, creationHash.AsReadOnlyMemory(), pool, cancellationToken).ConfigureAwait(false);

        return FrameCreationByProducts(hierarchy, name, creationData, creationHash, ticketDigest, includeName, pool);
    }

    //Assembles the creation by-products into one pooled buffer in canonical wire form. Synchronous; the digests
    //it copies in were computed by BuildCreationByProductsAsync before any await reached here.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the framed buffer transfers to the caller; the input buffers are released by their callers' using declarations.")]
    private static (IMemoryOwner<byte> Owner, int Length) FrameCreationByProducts(
        uint hierarchy, ReadOnlyMemory<byte> name, IMemoryOwner<byte> creationData, DigestValue creationHash, IMemoryOwner<byte> ticketDigest, bool includeName, MemoryPool<byte> pool)
    {
        int total =
            (sizeof(ushort) + CreationDataSize)                                       //creationData (TPM2B_CREATION_DATA).
            + (sizeof(ushort) + CreationDigestSize)                                   //creationHash (TPM2B_DIGEST).
            + (sizeof(ushort) + sizeof(uint) + sizeof(ushort) + CreationDigestSize);  //creationTicket (TPMT_TK_CREATION).

        if(includeName)
        {
            total += sizeof(ushort) + name.Length;                                    //name (TPM2B_NAME); width is nameAlg-agile.
        }

        IMemoryOwner<byte> owner = pool.Rent(total);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span[..total]);

            writer.WriteUInt16((ushort)CreationDataSize);
            writer.WriteBytes(creationData.Memory.Span[..CreationDataSize]);

            writer.WriteUInt16((ushort)CreationDigestSize);
            writer.WriteBytes(creationHash.AsReadOnlySpan());

            //A real TPMT_TK_CREATION bound to the hierarchy proof (not a NULL ticket).
            writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_CREATION);
            writer.WriteUInt32(hierarchy);
            writer.WriteUInt16((ushort)CreationDigestSize);
            writer.WriteBytes(ticketDigest.Memory.Span[..CreationDigestSize]);

            //The Name follows only for TPM2_CreatePrimary(); TPM2_Create() returns no Name. Its width is
            //nameAlg-agile, so it is framed from the caller-supplied slice's own length, not a fixed constant.
            if(includeName)
            {
                writer.WriteUInt16((ushort)name.Length);
                writer.WriteBytes(name.Span);
            }

            return (owner, total);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    //name = nameAlg || H_nameAlg(marshaled TPMT_PUBLIC) (TPM 2.0 Library Part 1, clause 16). Marshals the public
    //area and delegates the nameAlg-agile digest+framing to the shared TpmObjectName helper.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the Name buffer transfers to the caller, which releases it via a using declaration.")]
    private static async ValueTask<(IMemoryOwner<byte> Owner, int Length)> ComputeObjectNameAsync(Tpm2bPublic outPublic, TpmAlgIdConstants nameAlg, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        int publicSize = outPublic.PublicArea.GetSerializedSize();
        using IMemoryOwner<byte> marshaled = pool.Rent(publicSize);
        MarshalPublicArea(outPublic, marshaled.Memory.Span[..publicSize]);

        return await ComputeObjectNameFromBytesAsync(marshaled.Memory[..publicSize], nameAlg, pool, cancellationToken).ConfigureAwait(false);
    }

    //name = nameAlg || H_nameAlg(TPMT_PUBLIC) computed over already-marshaled public-area bytes — the form
    //TPM2_Load() has (it receives the marshaled TPMT_PUBLIC in inPublic) and the digest step ComputeObjectNameAsync
    //shares. Delegates to the shared nameAlg-agile TpmObjectName helper (TPM 2.0 Library Part 1, clause 16).
    private static ValueTask<(IMemoryOwner<byte> Owner, int Length)> ComputeObjectNameFromBytesAsync(ReadOnlyMemory<byte> publicAreaBytes, TpmAlgIdConstants nameAlg, MemoryPool<byte> pool, CancellationToken cancellationToken) =>
        TpmObjectName.ComputeNameAsync(publicAreaBytes, (ushort)nameAlg, pool, cancellationToken);

    //Marshals the TPMT_PUBLIC into its canonical wire form (no TPM2B size prefix) — the hash input for the Name.
    private static void MarshalPublicArea(Tpm2bPublic outPublic, Span<byte> destination)
    {
        var writer = new TpmWriter(destination);
        outPublic.PublicArea.WriteTo(ref writer);
    }

    //The marshaled TPMS_CREATION_DATA for a primary under a permanent hierarchy (TPM 2.0 Library Part 2, clause
    //15.1): the parent Name and Qualified Name are the parent's handle, the pcrDigest is the hash of the empty
    //PCR selection, and the locality is the command locality (0 for this software model).
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the creation-data buffer transfers to the caller, which releases it via a using declaration.")]
    private static async ValueTask<IMemoryOwner<byte>> BuildCreationDataAsync(uint hierarchy, MemoryPool<byte> pool, CancellationToken cancellationToken)
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
            writer.WriteUInt16((ushort)TpmAlgIdConstants.TPM_ALG_NULL);     //parentNameAlg (the permanent parent has none).
            writer.WriteUInt16((ushort)sizeof(uint));                      //parentName: TPM2B_NAME size = handle width.
            writer.WriteUInt32(hierarchy);                                  //parentName = the parent handle.
            writer.WriteUInt16((ushort)sizeof(uint));                      //parentQualifiedName: size = handle width.
            writer.WriteUInt32(hierarchy);                                  //parentQualifiedName = the parent handle.
            writer.WriteUInt16(0);                                          //outsideInfo: empty TPM2B_DATA.

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    //Derives the per-hierarchy proof used as the creation-ticket HMAC key, from the TPM's seed and the hierarchy
    //handle. A real TPM's proof is a persistent random secret fixed at manufacture and stored in NV (one per
    //hierarchy); the simulator has no NV, so it derives the proof from the injected seed through the registered
    //digest — the ticket is a genuine HMAC over the exact formula, and the seed is the caller's to make random
    //(genuine entropy) or fixed (reproducible). Each hierarchy gets a distinct proof because its handle is folded
    //into the derivation.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the proof buffer transfers to the caller, which releases it via a using declaration.")]
    private static async ValueTask<IMemoryOwner<byte>> DeriveHierarchyProofAsync(ReadOnlyMemory<byte> seed, uint hierarchy, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        int inputSize = seed.Length + sizeof(uint);
        using IMemoryOwner<byte> input = pool.Rent(inputSize);
        WriteProofInput(input.Memory.Span[..inputSize], seed.Span, hierarchy);

        using DigestValue proof = await CryptographicKeyEvents.ComputeDigestAsync(
            input.Memory[..inputSize], CreationDigestSize, CryptoTags.Sha256Digest, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        IMemoryOwner<byte> owner = pool.Rent(CreationDigestSize);
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

    //The proof-derivation hash input: the TPM seed followed by the hierarchy handle.
    private static void WriteProofInput(Span<byte> destination, ReadOnlySpan<byte> seed, uint hierarchy)
    {
        var writer = new TpmWriter(destination);
        writer.WriteBytes(seed);
        writer.WriteUInt32(hierarchy);
    }

    //creationTicket digest = HMAC_contextAlg(proof, TPM_ST_CREATION || Name || creationHash) (TPM 2.0 Library
    //Part 2, clause 10.7; the context integrity algorithm is SHA-256 for this model).
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the ticket-digest buffer transfers to the caller, which releases it via a using declaration.")]
    private static async ValueTask<IMemoryOwner<byte>> ComputeCreationTicketDigestAsync(
        ReadOnlyMemory<byte> proof, ReadOnlyMemory<byte> name, ReadOnlyMemory<byte> creationHash, MemoryPool<byte> pool, CancellationToken cancellationToken)
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

    //The creation-ticket HMAC message: TPM_ST_CREATION (UINT16) || Name || creation hash.
    private static void WriteTicketMessage(Span<byte> destination, ReadOnlySpan<byte> name, ReadOnlySpan<byte> creationHash)
    {
        var writer = new TpmWriter(destination);
        writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_CREATION);
        writer.WriteBytes(name);
        writer.WriteBytes(creationHash);
    }

    //TPM2_Sign() over an ECC key: sign the digest directly with the retained scalar through the injected backend.
    //The signature ownership flows to the TpmMessageSigned input, then to the TpmSignResponse intent, and is
    //released by SerializeResponse after the r and s parameters are framed.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the signature transfers to the returned TpmMessageSigned and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> SignEccDigestAsync(TpmEccSignAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        TpmEccSigningBackend backend = context.SigningBackend
            ?? throw new InvalidOperationException("TPM2_Sign() over an ECC key requires an ECC signing backend, but none was supplied.");

        Signature signature = await backend.SignDigest(
            action.Scalar, action.Digest, action.Curve, context.Pool, cancellationToken).ConfigureAwait(false);

        return new TpmMessageSigned(signature, TpmAlgIdConstants.TPM_ALG_ECDSA, action.HashAlg);
    }

    //TPM2_Sign() over an RSA key: sign the digest directly under the requested scheme through the injected RSA
    //backend. The signature ownership flows to the TpmMessageSigned input, then to the TpmSignResponse intent,
    //and is released by SerializeResponse after the single RSA signature buffer is framed.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the signature transfers to the returned TpmMessageSigned and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> SignRsaDigestAsync(TpmRsaSignAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        TpmRsaSigningBackend backend = context.RsaSigningBackend
            ?? throw new InvalidOperationException("TPM2_Sign() over an RSA key requires an RSA signing backend, but none was supplied.");

        Signature signature = await backend.SignDigest(
            action.PrivateKey, action.Digest, action.Scheme, action.HashAlg, context.Pool, cancellationToken).ConfigureAwait(false);

        return new TpmMessageSigned(signature, action.Scheme, action.HashAlg);
    }

    //TPM2_CreatePrimary() for an ECC storage parent: draw a key from the injected backend, build the exported
    //storage public area carrying its actual public point and the durable parent state, then compute the same
    //faithful creation by-products the key-bearing paths do. A real TPM generates a real key for a storage primary
    //(its public point is what an endorsement-key certificate is issued over); the simulator still models no
    //parent-key wrapping of children, so a storage parent is only used as a handle for TPM2_Create(), but its
    //exported point is now the genuine generated point. The result reuses the TpmPrimaryKeyCreated input the
    //signing paths feed back.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the public area and the by-products buffer transfers to the returned TpmPrimaryKeyCreated, then to the TpmCreatePrimaryResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> CreateStorageParentAsync(TpmCreateStorageParentAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        TpmEccSigningBackend backend = context.SigningBackend
            ?? throw new InvalidOperationException("TPM2_CreatePrimary() for an ECC storage parent requires a signing backend, but none was supplied.");

        Tpm2bPublic outPublic;
        TransientKeyState keyState;
        using(TpmGeneratedEccKey key = await backend.GenerateKey(action.Curve, context.Pool, cancellationToken).ConfigureAwait(false))
        {
            (outPublic, keyState) = BuildStorageParentArtifacts(action, key, context.Pool);
        }

        //name = nameAlg || H_nameAlg(TPMT_PUBLIC), computed once from the exported public area (which now carries
        //the generated point): retained on the parent state and shared with the creation by-products. The Name
        //width depends on nameAlg (agile per TpmObjectName), so its length travels with it.
        (IMemoryOwner<byte> name, int nameLength) = await ComputeObjectNameAsync(outPublic, action.NameAlg, context.Pool, cancellationToken).ConfigureAwait(false);
        using(name)
        {
            keyState = keyState with { Name = name.Memory.Span[..nameLength].ToArray() };

            (IMemoryOwner<byte> creationByProducts, int creationByProductsLength) =
                await BuildCreationByProductsAsync(name.Memory[..nameLength], action.Hierarchy, context.ProofSeed, includeName: true, context.Pool, cancellationToken).ConfigureAwait(false);

            return new TpmPrimaryKeyCreated(outPublic, keyState, creationByProducts, creationByProductsLength);
        }
    }

    //Splits the generated point into its X and Y coordinates, builds the exported storage public area carrying the
    //point, and copies the scalar into durable model memory. Mirrors BuildKeyArtifacts for the storage template;
    //synchronous so the point spans never cross an await.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the built public area transfers to the caller, which carries it to the response intent disposed by SerializeResponse.")]
    private static (Tpm2bPublic OutPublic, TransientKeyState KeyState) BuildStorageParentArtifacts(TpmCreateStorageParentAction action, TpmGeneratedEccKey key, MemoryPool<byte> pool)
    {
        //The exported point is SEC1 uncompressed (0x04 || X || Y), so X and Y are each the field-width halves
        //after the leading tag octet.
        ReadOnlySpan<byte> point = key.PublicPoint.AsReadOnlySpan();
        int fieldWidth = (point.Length - 1) / 2;
        ReadOnlySpan<byte> x = point.Slice(1, fieldWidth);
        ReadOnlySpan<byte> y = point.Slice(1 + fieldWidth, fieldWidth);
        ReadOnlySpan<byte> scalar = key.PrivateScalar.AsReadOnlySpan();

        TpmsEccPoint eccPoint = TpmsEccPoint.Create(x, y, pool);
        Tpm2bPublic outPublic = Tpm2bPublic.CreateEccStorageParent(action.NameAlg, action.Attributes, action.Curve, eccPoint, pool, action.AuthPolicy.Span);

        //The Name is filled by the caller once it has been computed from the exported public area (through the
        //asynchronous digest seam, which this synchronous point-splitting step must not cross). The SEC1 point is
        //retained so credential protection (the endorsement key is a storage parent) can use this object's public key.
        var keyState = new TransientKeyState(
            action.Handle, action.Hierarchy, TpmAlgIdConstants.TPM_ALG_ECC, action.Curve, scalar.ToArray(), ReadOnlyMemory<byte>.Empty, action.Attributes, point.ToArray(), action.AuthPolicy);

        return (outPublic, keyState);
    }

    //TPM2_Create() sealing: build the exported sealed-object public area (the sealed-data template, reproduced from
    //the template fields), the wrapped private blob (the simulator's own encoding of the sealed octets — it models
    //no parent-key encryption/integrity, having no parent symmetric-key custody), and the same faithful creation
    //by-products, minus the Name (TPM2_Create() returns no Name). Ownership of all three flows to TpmObjectSealed,
    //then to the TpmCreateResponse intent, and is released by SerializeResponse after framing.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the public area, the private blob, and the by-products buffer transfers to the returned TpmObjectSealed, then to the TpmCreateResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> SealDataAsync(TpmSealDataAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        Tpm2bPublic outPublic = Tpm2bPublic.CreateSealedDataTemplate(action.NameAlg, context.Pool, action.AuthPolicy.Span, action.NoDa);
        IMemoryOwner<byte> privateBlob = CopyToPooled(action.SecretData.Span, context.Pool, out int privateBlobLength);

        //The sealed object is not loaded, so its Name is not retained; it is still computed to key the creation
        //ticket HMAC (TPM 2.0 Library Part 2, clause 10.7). No handle is allocated, so nothing carries the Name past here.
        (IMemoryOwner<byte> name, int nameLength) = await ComputeObjectNameAsync(outPublic, action.NameAlg, context.Pool, cancellationToken).ConfigureAwait(false);
        using(name)
        {
            (IMemoryOwner<byte> creationByProducts, int creationByProductsLength) =
                await BuildCreationByProductsAsync(name.Memory[..nameLength], action.ParentHandle, context.ProofSeed, includeName: false, context.Pool, cancellationToken).ConfigureAwait(false);

            return new TpmObjectSealed(privateBlob, privateBlobLength, outPublic, creationByProducts, creationByProductsLength);
        }
    }

    //TPM2_Load(): recover the sealed data from the wrapped blob (it is the simulator's own encoding, so the blob
    //octets are the sealed data) and compute the object Name over the loaded public area through the registered
    //digest seam. The Name buffer ownership flows to TpmObjectLoaded, then to the TpmLoadResponse intent, and is
    //released by SerializeResponse after framing.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the Name buffer transfers to the returned TpmObjectLoaded, then to the TpmLoadResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> LoadObjectAsync(TpmLoadObjectAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        (IMemoryOwner<byte> name, int nameLength) = await ComputeObjectNameFromBytesAsync(
            action.PublicAreaBytes, action.NameAlg, context.Pool, cancellationToken).ConfigureAwait(false);

        return new TpmObjectLoaded(action.Handle, name, nameLength, action.Data, action.AuthPolicy);
    }

    //TPM2_Certify(): compute the subject's and the signer's Qualified Names, marshal the CERTIFY attestation
    //binding the certified object's Name and the caller nonce, hash it through the registered digest seam, and
    //sign the digest with the signing key's retained scalar through the injected ECC backend (this slice models
    //an ECC attestation key). Ownership of the marshaled attest and the signature flows to TpmObjectCertified,
    //then to the TpmCertifyResponse intent, and is released by SerializeResponse after the TPM2B_ATTEST and
    //TPMT_SIGNATURE are framed.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the marshaled attest and the signature transfers to the returned TpmObjectCertified, then to the TpmCertifyResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> CertifyObjectAsync(TpmCertifyAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        TpmEccSigningBackend backend = context.SigningBackend
            ?? throw new InvalidOperationException("TPM2_Certify() requires a signing backend, but none was supplied.");

        int hashSize = action.HashAlg.GetDigestSize()
            ?? throw new InvalidOperationException($"No digest size is registered for hash algorithm '{action.HashAlg}'.");
        Tag hashTag = action.HashAlg.GetDigestTag()
            ?? throw new InvalidOperationException($"No digest tag is registered for hash algorithm '{action.HashAlg}'.");

        (IMemoryOwner<byte> attest, int attestLength) = await BuildSignedCertifyAttestAsync(
            action.SubjectName, action.SubjectHierarchy, action.SignerName, action.SignerHierarchy, action.QualifyingData, action.ClockSnapshot, context.Pool, cancellationToken).ConfigureAwait(false);
        try
        {
            //The signature is over H_hashAlg(marshaled attest) — the exact bytes TPM2B_ATTEST carries and the host
            //re-hashes to verify (TPM 2.0 Library Part 3, clause 18.2). The digest width and tag follow the
            //caller's requested scheme hash (action.HashAlg), not a fixed SHA-256.
            using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
                attest.Memory[..attestLength], hashSize, hashTag, context.Pool, cancellationToken: cancellationToken).ConfigureAwait(false);

            Signature signature = await backend.SignDigest(
                action.SignerPrivateKey, digest.AsReadOnlyMemory(), action.SignerCurve, context.Pool, cancellationToken).ConfigureAwait(false);

            return new TpmObjectCertified(attest, attestLength, signature, TpmAlgIdConstants.TPM_ALG_ECDSA, action.HashAlg);
        }
        catch
        {
            attest.Dispose();
            throw;
        }
    }

    //The RSA counterpart of CertifyObjectAsync: same Qualified Name computation and attestation marshaling, signed
    //with the signing key's retained private key through the injected RSA backend under the requested RSA scheme.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the marshaled attest and the signature transfers to the returned TpmObjectCertified, then to the TpmCertifyResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> CertifyObjectRsaAsync(TpmRsaCertifyAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        TpmRsaSigningBackend backend = context.RsaSigningBackend
            ?? throw new InvalidOperationException("TPM2_Certify() over an RSA key requires an RSA signing backend, but none was supplied.");

        int hashSize = action.HashAlg.GetDigestSize()
            ?? throw new InvalidOperationException($"No digest size is registered for hash algorithm '{action.HashAlg}'.");
        Tag hashTag = action.HashAlg.GetDigestTag()
            ?? throw new InvalidOperationException($"No digest tag is registered for hash algorithm '{action.HashAlg}'.");

        (IMemoryOwner<byte> attest, int attestLength) = await BuildSignedCertifyAttestAsync(
            action.SubjectName, action.SubjectHierarchy, action.SignerName, action.SignerHierarchy, action.QualifyingData, action.ClockSnapshot, context.Pool, cancellationToken).ConfigureAwait(false);
        try
        {
            //The signature is over H_hashAlg(marshaled attest), exactly as the ECC path (TPM 2.0 Library Part 3,
            //clause 18.2). The digest width and tag follow the caller's requested scheme hash (action.HashAlg),
            //not a fixed SHA-256 — the RSA backend's RSA.SignHash rejects a digest whose length disagrees with
            //the hash algorithm it is told to sign under.
            using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
                attest.Memory[..attestLength], hashSize, hashTag, context.Pool, cancellationToken: cancellationToken).ConfigureAwait(false);

            Signature signature = await backend.SignDigest(
                action.SignerPrivateKey, digest.AsReadOnlyMemory(), action.Scheme, action.HashAlg, context.Pool, cancellationToken).ConfigureAwait(false);

            return new TpmObjectCertified(attest, attestLength, signature, action.Scheme, action.HashAlg);
        }
        catch
        {
            attest.Dispose();
            throw;
        }
    }

    //Computes the subject's and the signer's Qualified Names (TPM 2.0 Library Part 1, clause 16) and marshals the
    //CERTIFY attestation from them — shared between the ECC and RSA TPM2_Certify() paths, which differ only in
    //how they sign the resulting digest.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the marshaled-attest buffer transfers to the caller, which carries it to the response intent disposed by SerializeResponse.")]
    private static async ValueTask<(IMemoryOwner<byte> Owner, int Length)> BuildSignedCertifyAttestAsync(
        ReadOnlyMemory<byte> subjectName, uint subjectHierarchy, ReadOnlyMemory<byte> signerName, uint signerHierarchy,
        ReadOnlyMemory<byte> qualifyingData, TpmsClockInfo clockInfo, MemoryPool<byte> pool, CancellationToken cancellationToken)
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

    //Builds the marshaled TPMS_ATTEST for the CERTIFY case (TPM 2.0 Library Part 2, clause 10.12.12) into a pooled
    //buffer — the exact bytes the signature is over and the TPM2B_ATTEST wraps. Synchronous, so the spans never
    //cross the digest/sign awaits. Every field the host verifies is cryptographically real: magic
    //(TPM_GENERATED_VALUE), type (TPM_ST_ATTEST_CERTIFY), extraData (the caller nonce), the attested
    //TPMS_CERTIFY_INFO.name (the certified object's Name), qualifiedSigner (the signing key's real Qualified
    //Name), and the attested qualifiedName (the certified object's real Qualified Name) — both Qualified Names
    //computed by the caller (TPM 2.0 Library Part 1, clause 26.6). clockInfo is the real Clock/resetCount/
    //restartCount/Safe snapshot the transition folded from state after the per-command advance; firmwareVersion
    //is the simulator's fixed synthetic identity.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the marshaled-attest buffer transfers to the caller, which carries it to the response intent disposed by SerializeResponse.")]
    private static (IMemoryOwner<byte> Owner, int Length) BuildCertifyAttest(
        ReadOnlySpan<byte> subjectName, ReadOnlySpan<byte> subjectQualifiedName, ReadOnlySpan<byte> signerQualifiedName, ReadOnlySpan<byte> nonce, TpmsClockInfo clockInfo, MemoryPool<byte> pool)
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

    //QN(hierarchy) for a permanent hierarchy handle is the handle itself (TPM 2.0 Library Part 1, clause 16) —
    //every object this simulator creates is a primary directly under a permanent hierarchy, so no parent-chain
    //walk is needed; the hierarchy's 4-octet big-endian handle value stands in directly as its own Qualified
    //Name. The nameAlg is read back out of the object's own Name (its first two octets), the same algorithm the
    //Qualified Name inherits.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the Qualified Name buffer transfers to the caller, which releases it via a using declaration.")]
    private static async ValueTask<(IMemoryOwner<byte> Owner, int Length)> ComputeHierarchyQualifiedNameAsync(
        uint hierarchy, ReadOnlyMemory<byte> name, MemoryPool<byte> pool, CancellationToken cancellationToken)
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

    //TPM2_Quote(): compute the PCR composite digest over the selected register values, marshal the QUOTE
    //attestation binding that composite (and the caller nonce), hash it through the registered digest seam under
    //the signing scheme's own hash algorithm (action.HashAlg), and sign the digest with the signing key's retained
    //scalar through the injected ECC backend (this slice models an ECC signing key; QuoteObjectRsaAsync is the RSA
    //counterpart). Ownership of the marshaled attest and the signature flows to TpmObjectQuoted, then to the
    //TpmQuoteResponse intent, and is released by SerializeResponse after the TPM2B_ATTEST and TPMT_SIGNATURE are
    //framed.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the marshaled attest and the signature transfers to the returned TpmObjectQuoted, then to the TpmQuoteResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> QuoteObjectAsync(TpmQuoteAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        TpmEccSigningBackend backend = context.SigningBackend
            ?? throw new InvalidOperationException("TPM2_Quote() requires a signing backend, but none was supplied.");

        int hashSize = action.HashAlg.GetDigestSize()
            ?? throw new InvalidOperationException($"No digest size is registered for hash algorithm '{action.HashAlg}'.");
        Tag hashTag = action.HashAlg.GetDigestTag()
            ?? throw new InvalidOperationException($"No digest tag is registered for hash algorithm '{action.HashAlg}'.");

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
                await ComputeHierarchyQualifiedNameAsync(action.SignerHierarchy, action.SignerName, context.Pool, cancellationToken).ConfigureAwait(false);
            using(signerQualifiedName)
            {
                (attest, attestLength) = BuildQuoteAttest(
                    signerQualifiedName.Memory.Span[..signerQualifiedNameLength], action.QualifyingData.Span, action.PcrSelection.Span, pcrDigest.AsReadOnlySpan(), action.ClockSnapshot, context.Pool);
            }
        }

        try
        {
            //The signature is over H_hashAlg(marshaled attest) — the exact bytes TPM2B_ATTEST carries and the host
            //re-hashes to verify (TPM 2.0 Library Part 3, clause 18.4). The digest width and tag follow the
            //caller's requested scheme hash, not a fixed SHA-256.
            using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
                attest.Memory[..attestLength], hashSize, hashTag, context.Pool, cancellationToken: cancellationToken).ConfigureAwait(false);

            Signature signature = await backend.SignDigest(
                action.SignerPrivateKey, digest.AsReadOnlyMemory(), action.SignerCurve, context.Pool, cancellationToken).ConfigureAwait(false);

            return new TpmObjectQuoted(attest, attestLength, signature, action.SignatureScheme, action.HashAlg);
        }
        catch
        {
            attest.Dispose();
            throw;
        }
    }

    //The RSA counterpart of QuoteObjectAsync: same PCR composite and attestation marshaling, signed with the
    //signing key's retained private key through the injected RSA backend under the requested RSA scheme.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the marshaled attest and the signature transfers to the returned TpmObjectQuoted, then to the TpmQuoteResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> QuoteObjectRsaAsync(TpmRsaQuoteAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        TpmRsaSigningBackend backend = context.RsaSigningBackend
            ?? throw new InvalidOperationException("TPM2_Quote() over an RSA key requires an RSA signing backend, but none was supplied.");

        int hashSize = action.HashAlg.GetDigestSize()
            ?? throw new InvalidOperationException($"No digest size is registered for hash algorithm '{action.HashAlg}'.");
        Tag hashTag = action.HashAlg.GetDigestTag()
            ?? throw new InvalidOperationException($"No digest tag is registered for hash algorithm '{action.HashAlg}'.");

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
                await ComputeHierarchyQualifiedNameAsync(action.SignerHierarchy, action.SignerName, context.Pool, cancellationToken).ConfigureAwait(false);
            using(signerQualifiedName)
            {
                (attest, attestLength) = BuildQuoteAttest(
                    signerQualifiedName.Memory.Span[..signerQualifiedNameLength], action.QualifyingData.Span, action.PcrSelection.Span, pcrDigest.AsReadOnlySpan(), action.ClockSnapshot, context.Pool);
            }
        }

        try
        {
            //The signature is over H_hashAlg(marshaled attest), exactly as the ECC path (TPM 2.0 Library Part 3,
            //clause 18.4). The digest width and tag follow the caller's requested scheme hash, not a fixed
            //SHA-256 — the RSA backend's RSA.SignHash rejects a digest whose length disagrees with the hash
            //algorithm it is told to sign under.
            using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
                attest.Memory[..attestLength], hashSize, hashTag, context.Pool, cancellationToken: cancellationToken).ConfigureAwait(false);

            Signature signature = await backend.SignDigest(
                action.SignerPrivateKey, digest.AsReadOnlyMemory(), action.Scheme, action.HashAlg, context.Pool, cancellationToken).ConfigureAwait(false);

            return new TpmObjectQuoted(attest, attestLength, signature, action.Scheme, action.HashAlg);
        }
        catch
        {
            attest.Dispose();
            throw;
        }
    }

    //Copies the selected PCR values, in order, into one pooled buffer — the PCR composite the quote digest is
    //computed over. Rents at least one octet so an empty selection still yields a valid (empty) buffer. Ownership
    //transfers to the caller, which disposes it after the composite digest is taken.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented buffer transfers to the caller, which releases it via a using declaration after the digest is computed.")]
    private static IMemoryOwner<byte> ConcatenatePcrValues(ImmutableArray<ReadOnlyMemory<byte>> values, MemoryPool<byte> pool, out int length)
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

    //Builds the marshaled TPMS_ATTEST for the QUOTE case (TPM 2.0 Library Part 2, clause 10.12.12; the quote body
    //is TPMS_QUOTE_INFO, clause 10.12.1) into a pooled buffer — the exact bytes the signature is over and the
    //TPM2B_ATTEST wraps. Synchronous, so the spans never cross the digest/sign awaits. The fields the host verifies
    //are cryptographically real: magic (TPM_GENERATED_VALUE), type (TPM_ST_ATTEST_QUOTE), extraData (the caller
    //nonce), qualifiedSigner (the signing key's real Qualified Name, TPM 2.0 Library Part 1, clause 26.6), and the
    //attested TPMS_QUOTE_INFO { pcrSelect echoed verbatim, pcrDigest computed over the real PCR values }. clockInfo
    //is the real Clock/resetCount/restartCount/Safe snapshot the transition folded from state after the
    //per-command advance; firmwareVersion is the simulator's fixed synthetic identity. The pcrSelect is the
    //caller's TPML_PCR_SELECTION echoed verbatim (the same octets the host produced), so it round-trips through
    //TpmsQuoteInfo.Parse exactly.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the marshaled-attest buffer transfers to the caller, which carries it to the response intent disposed by SerializeResponse.")]
    private static (IMemoryOwner<byte> Owner, int Length) BuildQuoteAttest(
        ReadOnlySpan<byte> signerQualifiedName, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> pcrSelection, ReadOnlySpan<byte> pcrDigest, TpmsClockInfo clockInfo, MemoryPool<byte> pool)
    {
        int total =
            sizeof(uint) + sizeof(ushort)                            //magic (TPM_GENERATED) + type (TPMI_ST_ATTEST).
            + (sizeof(ushort) + signerQualifiedName.Length)          //qualifiedSigner (TPM2B_NAME).
            + (sizeof(ushort) + nonce.Length)                        //extraData (TPM2B_DATA).
            + TpmsClockInfo.SerializedSize                           //clockInfo (TPMS_CLOCK_INFO).
            + sizeof(ulong)                                          //firmwareVersion.
            + pcrSelection.Length                                    //attested.pcrSelect (TPML_PCR_SELECTION, echoed verbatim).
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

            //attested = TPMS_QUOTE_INFO: the caller's PCR selection echoed verbatim (the full TPML_PCR_SELECTION),
            //then the composite digest the TPM computed over the selected PCR values.
            writer.WriteBytes(pcrSelection);
            writer.WriteTpm2b(pcrDigest);

            return (owner, total);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    //TPM2_CertifyCreation(): re-verify the caller-supplied creation ticket, then (on a match) marshal the CREATION
    //attestation and sign it with the signing key's retained scalar through the injected ECC backend. Unlike
    //Certify/Quote, the rejection outcome (a mismatched ticket, TPM_RC_TICKET) is decided here rather than in the
    //pure transition, because the re-derivation needs the asynchronous digest/HMAC seam (mirrors how
    //ActivateCredentialAsync's integrity check works).
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the marshaled attest and the signature transfers to the returned TpmObjectCreationCertified, then to the TpmCertifyCreationResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> CertifyObjectCreationAsync(TpmCertifyCreationAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        TpmEccSigningBackend backend = context.SigningBackend
            ?? throw new InvalidOperationException("TPM2_CertifyCreation() requires a signing backend, but none was supplied.");

        if(!await VerifyCreationTicketAsync(action.SubjectHierarchy, action.SubjectName, action.CreationHash, action.TicketDigest, context, cancellationToken).ConfigureAwait(false))
        {
            return new TpmObjectCreationCertified(TpmRcConstants.TPM_RC_TICKET, null, 0, null, TpmAlgIdConstants.TPM_ALG_ECDSA, action.HashAlg);
        }

        int hashSize = action.HashAlg.GetDigestSize()
            ?? throw new InvalidOperationException($"No digest size is registered for hash algorithm '{action.HashAlg}'.");
        Tag hashTag = action.HashAlg.GetDigestTag()
            ?? throw new InvalidOperationException($"No digest tag is registered for hash algorithm '{action.HashAlg}'.");

        (IMemoryOwner<byte> attest, int attestLength) = await BuildSignedCreationAttestAsync(
            action.SubjectName, action.CreationHash, action.SignerHierarchy, action.SignerName, action.QualifyingData, action.ClockSnapshot, context.Pool, cancellationToken).ConfigureAwait(false);
        try
        {
            using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
                attest.Memory[..attestLength], hashSize, hashTag, context.Pool, cancellationToken: cancellationToken).ConfigureAwait(false);

            Signature signature = await backend.SignDigest(
                action.SignerPrivateKey, digest.AsReadOnlyMemory(), action.SignerCurve, context.Pool, cancellationToken).ConfigureAwait(false);

            return new TpmObjectCreationCertified(TpmRcConstants.TPM_RC_SUCCESS, attest, attestLength, signature, TpmAlgIdConstants.TPM_ALG_ECDSA, action.HashAlg);
        }
        catch
        {
            attest.Dispose();
            throw;
        }
    }

    //The RSA counterpart of CertifyObjectCreationAsync: same ticket re-verification and attestation marshaling,
    //signed with the signing key's retained private key through the injected RSA backend under the requested
    //RSA scheme.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the marshaled attest and the signature transfers to the returned TpmObjectCreationCertified, then to the TpmCertifyCreationResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> CertifyObjectCreationRsaAsync(TpmRsaCertifyCreationAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        TpmRsaSigningBackend backend = context.RsaSigningBackend
            ?? throw new InvalidOperationException("TPM2_CertifyCreation() over an RSA key requires an RSA signing backend, but none was supplied.");

        if(!await VerifyCreationTicketAsync(action.SubjectHierarchy, action.SubjectName, action.CreationHash, action.TicketDigest, context, cancellationToken).ConfigureAwait(false))
        {
            return new TpmObjectCreationCertified(TpmRcConstants.TPM_RC_TICKET, null, 0, null, action.Scheme, action.HashAlg);
        }

        int hashSize = action.HashAlg.GetDigestSize()
            ?? throw new InvalidOperationException($"No digest size is registered for hash algorithm '{action.HashAlg}'.");
        Tag hashTag = action.HashAlg.GetDigestTag()
            ?? throw new InvalidOperationException($"No digest tag is registered for hash algorithm '{action.HashAlg}'.");

        (IMemoryOwner<byte> attest, int attestLength) = await BuildSignedCreationAttestAsync(
            action.SubjectName, action.CreationHash, action.SignerHierarchy, action.SignerName, action.QualifyingData, action.ClockSnapshot, context.Pool, cancellationToken).ConfigureAwait(false);
        try
        {
            using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
                attest.Memory[..attestLength], hashSize, hashTag, context.Pool, cancellationToken: cancellationToken).ConfigureAwait(false);

            Signature signature = await backend.SignDigest(
                action.SignerPrivateKey, digest.AsReadOnlyMemory(), action.Scheme, action.HashAlg, context.Pool, cancellationToken).ConfigureAwait(false);

            return new TpmObjectCreationCertified(TpmRcConstants.TPM_RC_SUCCESS, attest, attestLength, signature, action.Scheme, action.HashAlg);
        }
        catch
        {
            attest.Dispose();
            throw;
        }
    }

    //Re-verifies a TPM2_CertifyCreation() creation ticket statelessly (TPM 2.0 Library Part 2, clause 10.7.3;
    //Part 3, clause 18.3): re-derives the certified object's own hierarchy proof (never a caller-supplied one, so
    //a tampered ticket cannot be rescued by a matching hierarchy claim), recomputes
    //HMAC(proof, TPM_ST_CREATION || Name || creationHash) with the exact same derivation
    //TPM2_CreatePrimary()/TPM2_Create() used to produce the original ticket, and compares the result constant-time
    //against the caller-supplied ticket digest.
    private static async ValueTask<bool> VerifyCreationTicketAsync(
        uint subjectHierarchy, ReadOnlyMemory<byte> subjectName, ReadOnlyMemory<byte> creationHash, ReadOnlyMemory<byte> ticketDigest,
        TpmActionContext context, CancellationToken cancellationToken)
    {
        using IMemoryOwner<byte> proof = await DeriveHierarchyProofAsync(context.ProofSeed, subjectHierarchy, context.Pool, cancellationToken).ConfigureAwait(false);
        using IMemoryOwner<byte> expectedDigest = await ComputeCreationTicketDigestAsync(
            proof.Memory[..CreationDigestSize], subjectName, creationHash, context.Pool, cancellationToken).ConfigureAwait(false);

        return CryptographicOperations.FixedTimeEquals(expectedDigest.Memory.Span[..CreationDigestSize], ticketDigest.Span);
    }

    //Computes the signer's Qualified Name and marshals the CREATION attestation from it — shared between the ECC
    //and RSA TPM2_CertifyCreation() paths, which differ only in how they sign the resulting digest.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the marshaled-attest buffer transfers to the caller, which carries it to the response intent disposed by SerializeResponse.")]
    private static async ValueTask<(IMemoryOwner<byte> Owner, int Length)> BuildSignedCreationAttestAsync(
        ReadOnlyMemory<byte> subjectName, ReadOnlyMemory<byte> creationHash, uint signerHierarchy, ReadOnlyMemory<byte> signerName,
        ReadOnlyMemory<byte> qualifyingData, TpmsClockInfo clockInfo, MemoryPool<byte> pool, CancellationToken cancellationToken)
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

    //Builds the marshaled TPMS_ATTEST for the CREATION case (TPM 2.0 Library Part 2, clause 10.12.7) into a
    //pooled buffer — the exact bytes the signature is over and the TPM2B_ATTEST wraps. Every field the host
    //verifies is cryptographically real: magic, type (TPM_ST_ATTEST_CREATION), extraData, qualifiedSigner, the
    //attested TPMS_CREATION_INFO.objectName (the certified object's real Name), and creationHash (the
    //caller-supplied value the re-verified ticket bound). clockInfo is the real Clock/resetCount/restartCount/
    //Safe snapshot the transition folded from state after the per-command advance; firmwareVersion is the
    //simulator's fixed synthetic identity.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the marshaled-attest buffer transfers to the caller, which carries it to the response intent disposed by SerializeResponse.")]
    private static (IMemoryOwner<byte> Owner, int Length) BuildCreationAttest(
        ReadOnlySpan<byte> subjectName, ReadOnlySpan<byte> creationHash, ReadOnlySpan<byte> signerQualifiedName, ReadOnlySpan<byte> nonce, TpmsClockInfo clockInfo, MemoryPool<byte> pool)
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

    //TPM2_GetTime(): marshal the TIME attestation over the real Time/clockInfo snapshot and the signer's real
    //Qualified Name, hash it through the registered digest seam under the signing scheme's own hash algorithm,
    //and sign the digest with the signing key's retained scalar through the injected ECC backend.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the marshaled attest and the signature transfers to the returned TpmTimeAttested, then to the TpmGetTimeResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> AttestTimeAsync(TpmGetTimeAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        TpmEccSigningBackend backend = context.SigningBackend
            ?? throw new InvalidOperationException("TPM2_GetTime() requires a signing backend, but none was supplied.");

        int hashSize = action.HashAlg.GetDigestSize()
            ?? throw new InvalidOperationException($"No digest size is registered for hash algorithm '{action.HashAlg}'.");
        Tag hashTag = action.HashAlg.GetDigestTag()
            ?? throw new InvalidOperationException($"No digest tag is registered for hash algorithm '{action.HashAlg}'.");

        (IMemoryOwner<byte> attest, int attestLength) = await BuildSignedTimeAttestAsync(
            action.SignerHierarchy, action.SignerName, action.QualifyingData, action.Time, action.ClockSnapshot, context.Pool, cancellationToken).ConfigureAwait(false);
        try
        {
            using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
                attest.Memory[..attestLength], hashSize, hashTag, context.Pool, cancellationToken: cancellationToken).ConfigureAwait(false);

            Signature signature = await backend.SignDigest(
                action.SignerPrivateKey, digest.AsReadOnlyMemory(), action.SignerCurve, context.Pool, cancellationToken).ConfigureAwait(false);

            return new TpmTimeAttested(attest, attestLength, signature, TpmAlgIdConstants.TPM_ALG_ECDSA, action.HashAlg);
        }
        catch
        {
            attest.Dispose();
            throw;
        }
    }

    //The RSA counterpart of AttestTimeAsync: same real-clock attestation marshaling, signed with the signing
    //key's retained private key through the injected RSA backend under the requested RSA scheme.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the marshaled attest and the signature transfers to the returned TpmTimeAttested, then to the TpmGetTimeResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> AttestTimeRsaAsync(TpmRsaGetTimeAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        TpmRsaSigningBackend backend = context.RsaSigningBackend
            ?? throw new InvalidOperationException("TPM2_GetTime() over an RSA key requires an RSA signing backend, but none was supplied.");

        int hashSize = action.HashAlg.GetDigestSize()
            ?? throw new InvalidOperationException($"No digest size is registered for hash algorithm '{action.HashAlg}'.");
        Tag hashTag = action.HashAlg.GetDigestTag()
            ?? throw new InvalidOperationException($"No digest tag is registered for hash algorithm '{action.HashAlg}'.");

        (IMemoryOwner<byte> attest, int attestLength) = await BuildSignedTimeAttestAsync(
            action.SignerHierarchy, action.SignerName, action.QualifyingData, action.Time, action.ClockSnapshot, context.Pool, cancellationToken).ConfigureAwait(false);
        try
        {
            using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
                attest.Memory[..attestLength], hashSize, hashTag, context.Pool, cancellationToken: cancellationToken).ConfigureAwait(false);

            Signature signature = await backend.SignDigest(
                action.SignerPrivateKey, digest.AsReadOnlyMemory(), action.Scheme, action.HashAlg, context.Pool, cancellationToken).ConfigureAwait(false);

            return new TpmTimeAttested(attest, attestLength, signature, action.Scheme, action.HashAlg);
        }
        catch
        {
            attest.Dispose();
            throw;
        }
    }

    //Computes the signer's Qualified Name and marshals the TIME attestation from it — shared between the ECC and
    //RSA TPM2_GetTime() paths, which differ only in how they sign the resulting digest.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the marshaled-attest buffer transfers to the caller, which carries it to the response intent disposed by SerializeResponse.")]
    private static async ValueTask<(IMemoryOwner<byte> Owner, int Length)> BuildSignedTimeAttestAsync(
        uint signerHierarchy, ReadOnlyMemory<byte> signerName, ReadOnlyMemory<byte> qualifyingData, ulong time, TpmsClockInfo clockInfo, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        (IMemoryOwner<byte> signerQualifiedName, int signerQualifiedNameLength) =
            await ComputeHierarchyQualifiedNameAsync(signerHierarchy, signerName, pool, cancellationToken).ConfigureAwait(false);
        using(signerQualifiedName)
        {
            return BuildTimeAttest(signerQualifiedName.Memory.Span[..signerQualifiedNameLength], qualifyingData.Span, time, clockInfo, pool);
        }
    }

    //Builds the marshaled TPMS_ATTEST for the TIME case (TPM 2.0 Library Part 2, clause 10.12.2) into a pooled
    //buffer. The attested TPMS_TIME_ATTEST_INFO reports the real Time and clockInfo the transition folded from
    //state after the per-command advance; the SAME clockInfo snapshot is written both at the envelope level and
    //inside the nested TPMS_TIME_ATTEST_INFO (TPM 2.0 Library Part 1, clause 36.7 — the two copies agree).
    //firmwareVersion is likewise the same simulator-fixed constant in both places.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the marshaled-attest buffer transfers to the caller, which carries it to the response intent disposed by SerializeResponse.")]
    private static (IMemoryOwner<byte> Owner, int Length) BuildTimeAttest(ReadOnlySpan<byte> signerQualifiedName, ReadOnlySpan<byte> nonce, ulong time, TpmsClockInfo clockInfo, MemoryPool<byte> pool)
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

    //TPM2_NV_Certify(): compute the NV Index's real Name, marshal the NV attestation over it and the requested
    //window of retained contents, hash it through the registered digest seam under the signing scheme's own hash
    //algorithm, and sign the digest with the signing key's retained scalar through the injected ECC backend.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the marshaled attest and the signature transfers to the returned TpmNvIndexCertified, then to the TpmNvCertifyResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> CertifyNvIndexAsync(TpmNvCertifyAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        TpmEccSigningBackend backend = context.SigningBackend
            ?? throw new InvalidOperationException("TPM2_NV_Certify() requires a signing backend, but none was supplied.");

        int hashSize = action.HashAlg.GetDigestSize()
            ?? throw new InvalidOperationException($"No digest size is registered for hash algorithm '{action.HashAlg}'.");
        Tag hashTag = action.HashAlg.GetDigestTag()
            ?? throw new InvalidOperationException($"No digest tag is registered for hash algorithm '{action.HashAlg}'.");

        (IMemoryOwner<byte> attest, int attestLength) = await BuildSignedNvCertifyAttestAsync(
            action.NvIndex, action.NvIndexAttributes, action.NvIndexDataSize, action.Offset, action.NvContents,
            action.SignerHierarchy, action.SignerName, action.QualifyingData, action.ClockSnapshot, context.Pool, cancellationToken).ConfigureAwait(false);
        try
        {
            using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
                attest.Memory[..attestLength], hashSize, hashTag, context.Pool, cancellationToken: cancellationToken).ConfigureAwait(false);

            Signature signature = await backend.SignDigest(
                action.SignerPrivateKey, digest.AsReadOnlyMemory(), action.SignerCurve, context.Pool, cancellationToken).ConfigureAwait(false);

            return new TpmNvIndexCertified(attest, attestLength, signature, TpmAlgIdConstants.TPM_ALG_ECDSA, action.HashAlg);
        }
        catch
        {
            attest.Dispose();
            throw;
        }
    }

    //The RSA counterpart of CertifyNvIndexAsync: same Index-Name computation and attestation marshaling, signed
    //with the signing key's retained private key through the injected RSA backend under the requested RSA scheme.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the marshaled attest and the signature transfers to the returned TpmNvIndexCertified, then to the TpmNvCertifyResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> CertifyNvIndexRsaAsync(TpmRsaNvCertifyAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        TpmRsaSigningBackend backend = context.RsaSigningBackend
            ?? throw new InvalidOperationException("TPM2_NV_Certify() over an RSA key requires an RSA signing backend, but none was supplied.");

        int hashSize = action.HashAlg.GetDigestSize()
            ?? throw new InvalidOperationException($"No digest size is registered for hash algorithm '{action.HashAlg}'.");
        Tag hashTag = action.HashAlg.GetDigestTag()
            ?? throw new InvalidOperationException($"No digest tag is registered for hash algorithm '{action.HashAlg}'.");

        (IMemoryOwner<byte> attest, int attestLength) = await BuildSignedNvCertifyAttestAsync(
            action.NvIndex, action.NvIndexAttributes, action.NvIndexDataSize, action.Offset, action.NvContents,
            action.SignerHierarchy, action.SignerName, action.QualifyingData, action.ClockSnapshot, context.Pool, cancellationToken).ConfigureAwait(false);
        try
        {
            using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
                attest.Memory[..attestLength], hashSize, hashTag, context.Pool, cancellationToken: cancellationToken).ConfigureAwait(false);

            Signature signature = await backend.SignDigest(
                action.SignerPrivateKey, digest.AsReadOnlyMemory(), action.Scheme, action.HashAlg, context.Pool, cancellationToken).ConfigureAwait(false);

            return new TpmNvIndexCertified(attest, attestLength, signature, action.Scheme, action.HashAlg);
        }
        catch
        {
            attest.Dispose();
            throw;
        }
    }

    //Computes an NV Index's Name (nameAlg || H_nameAlg(TPMS_NV_PUBLIC), TPM 2.0 Library Part 1, clause 16) — the
    //same marshal-and-hash mechanism ComputeNvNameForPolicyAsync uses for TPM2_PolicyNV() — and marshals the NV
    //attestation from it, the signer's Qualified Name, the requested offset, and the requested window of
    //retained contents. Shared between the ECC and RSA TPM2_NV_Certify() paths, which differ only in how they
    //sign the resulting digest.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the marshaled-attest buffer transfers to the caller, which carries it to the response intent disposed by SerializeResponse.")]
    private static async ValueTask<(IMemoryOwner<byte> Owner, int Length)> BuildSignedNvCertifyAttestAsync(
        uint nvIndex, TpmaNv nvIndexAttributes, ushort nvIndexDataSize, ushort offset, ReadOnlyMemory<byte> nvContents,
        uint signerHierarchy, ReadOnlyMemory<byte> signerName, ReadOnlyMemory<byte> qualifyingData, TpmsClockInfo clockInfo, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        (IMemoryOwner<byte> indexName, int indexNameLength) =
            await ComputeNvIndexNameAsync(nvIndex, nvIndexAttributes, nvIndexDataSize, pool, cancellationToken).ConfigureAwait(false);
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

    //Marshals a TPMS_NV_PUBLIC for the Index (fixed TPM_ALG_SHA256 nameAlg, empty authPolicy, this model's
    //universal NV Name algorithm — the same shape ComputeNvNameForPolicyAsync builds for TPM2_PolicyNV()) and
    //computes its Name through the shared nameAlg-agile TpmObjectName helper.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the Name buffer transfers to the caller, which releases it via a using declaration.")]
    private static async ValueTask<(IMemoryOwner<byte> Owner, int Length)> ComputeNvIndexNameAsync(
        uint nvIndex, TpmaNv attributes, ushort dataSize, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        using var nvPublic = new TpmsNvPublic(nvIndex, TpmAlgIdConstants.TPM_ALG_SHA256, attributes, Tpm2bDigest.Empty, dataSize);
        int publicSize = nvPublic.SerializedSize;
        using IMemoryOwner<byte> marshaled = pool.Rent(publicSize);
        var writer = new TpmWriter(marshaled.Memory.Span[..publicSize]);
        nvPublic.WriteTo(ref writer);

        return await TpmObjectName.ComputeNameAsync(
            marshaled.Memory[..publicSize], (ushort)TpmAlgIdConstants.TPM_ALG_SHA256, pool, cancellationToken).ConfigureAwait(false);
    }

    //Builds the marshaled TPMS_ATTEST for the NV case (TPM 2.0 Library Part 2, clause 10.12.8) into a pooled
    //buffer. Every field the host verifies is cryptographically real: magic, type (TPM_ST_ATTEST_NV), extraData,
    //qualifiedSigner, the attested TPMS_NV_CERTIFY_INFO.indexName (the Index's real Name), offset, and nvContents
    //(the retained octets at that offset). clockInfo is the real Clock/resetCount/restartCount/Safe snapshot the
    //transition folded from state after the per-command advance; firmwareVersion is the simulator's fixed
    //synthetic identity.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the marshaled-attest buffer transfers to the caller, which carries it to the response intent disposed by SerializeResponse.")]
    private static (IMemoryOwner<byte> Owner, int Length) BuildNvCertifyAttest(
        ReadOnlySpan<byte> indexName, ushort offset, ReadOnlySpan<byte> nvContents, ReadOnlySpan<byte> signerQualifiedName, ReadOnlySpan<byte> nonce, TpmsClockInfo clockInfo, MemoryPool<byte> pool)
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

    //TPM2_VerifySignature() over an ECC key (Part 3, clause 20.1): verify the caller-supplied digest and signature
    //against the key's own retained public point through the injected ECC backend's verify delegate — a
    //public-key operation that needs no authorization and consults no sign attribute (contrast TPM2_Sign(), which
    //needs both). On a successful verification, re-derive the verifying key's hierarchy proof and compute the
    //TPMT_TK_VERIFIED digest HMAC(proof, TPM_ST_VERIFIED || digest || keyName) — the mirror image of the creation
    //ticket's name || creationHash order (Part 2, clause 10.7.4). A failed verification needs no ticket at all, so
    //the rejection is decided here rather than the pure transition (mirrors CertifyObjectCreationAsync).
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the ticket-digest buffer transfers to the returned TpmSignatureVerified, then to the TpmVerifySignatureResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> VerifySignatureEccAsync(TpmVerifySignatureAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        TpmEccSigningBackend backend = context.SigningBackend
            ?? throw new InvalidOperationException("TPM2_VerifySignature() over an ECC key requires a signing backend, but none was supplied.");

        bool verified = await backend.VerifyDigest(
            action.PublicPoint, action.Digest, action.Signature, action.Curve, cancellationToken).ConfigureAwait(false);

        if(!verified)
        {
            return new TpmSignatureVerified(TpmRcConstants.TPM_RC_SIGNATURE, 0, null, 0);
        }

        using IMemoryOwner<byte> proof = await DeriveHierarchyProofAsync(context.ProofSeed, action.KeyHierarchy, context.Pool, cancellationToken).ConfigureAwait(false);
        IMemoryOwner<byte> ticketDigest = await ComputeVerifiedTicketDigestAsync(
            proof.Memory[..CreationDigestSize], action.Digest, action.KeyName, context.Pool, cancellationToken).ConfigureAwait(false);

        return new TpmSignatureVerified(TpmRcConstants.TPM_RC_SUCCESS, action.KeyHierarchy, ticketDigest, CreationDigestSize);
    }

    //The RSA counterpart of VerifySignatureEccAsync: same verify-then-ticket flow, verified through the injected
    //RSA backend's verify delegate under the requested RSA scheme.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the ticket-digest buffer transfers to the returned TpmSignatureVerified, then to the TpmVerifySignatureResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> VerifySignatureRsaAsync(TpmRsaVerifySignatureAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        TpmRsaSigningBackend backend = context.RsaSigningBackend
            ?? throw new InvalidOperationException("TPM2_VerifySignature() over an RSA key requires an RSA signing backend, but none was supplied.");

        bool verified = await backend.VerifyDigest(
            action.PrivateKey, action.Digest, action.Signature, action.Scheme, action.HashAlg, cancellationToken).ConfigureAwait(false);

        if(!verified)
        {
            return new TpmSignatureVerified(TpmRcConstants.TPM_RC_SIGNATURE, 0, null, 0);
        }

        using IMemoryOwner<byte> proof = await DeriveHierarchyProofAsync(context.ProofSeed, action.KeyHierarchy, context.Pool, cancellationToken).ConfigureAwait(false);
        IMemoryOwner<byte> ticketDigest = await ComputeVerifiedTicketDigestAsync(
            proof.Memory[..CreationDigestSize], action.Digest, action.KeyName, context.Pool, cancellationToken).ConfigureAwait(false);

        return new TpmSignatureVerified(TpmRcConstants.TPM_RC_SUCCESS, action.KeyHierarchy, ticketDigest, CreationDigestSize);
    }

    //verifiedTicket digest = HMAC_contextAlg(proof, TPM_ST_VERIFIED || digest || keyName) (TPM 2.0 Library Part 2,
    //clause 10.7.4) — the mirror image of ComputeCreationTicketDigestAsync's TPM_ST_CREATION || Name ||
    //creationHash field order.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the ticket-digest buffer transfers to the caller, which releases it via a using declaration.")]
    private static async ValueTask<IMemoryOwner<byte>> ComputeVerifiedTicketDigestAsync(
        ReadOnlyMemory<byte> proof, ReadOnlyMemory<byte> digest, ReadOnlyMemory<byte> keyName, MemoryPool<byte> pool, CancellationToken cancellationToken)
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

    //The verified-ticket HMAC message: TPM_ST_VERIFIED (UINT16) || digest || Name.
    private static void WriteVerifiedTicketMessage(Span<byte> destination, ReadOnlySpan<byte> digest, ReadOnlySpan<byte> keyName)
    {
        var writer = new TpmWriter(destination);
        writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_VERIFIED);
        writer.WriteBytes(digest);
        writer.WriteBytes(keyName);
    }

    //Copies octets into a pooled buffer sized to hold them (at least one octet so an empty payload still rents a
    //valid buffer). Ownership transfers to the caller; the caller disposes it after the octets are framed out.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented buffer transfers to the caller, which releases it after framing.")]
    private static IMemoryOwner<byte> CopyToPooled(ReadOnlySpan<byte> source, MemoryPool<byte> pool, out int length)
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

    //TPM2_StartAuthSession() for a bound HMAC session: draw a fresh nonceTPM from the injected RNG, then derive the
    //session key via KDFa through the registered HMAC seam — the SAME derivation the host TpmSession.CreateBoundAsync
    //performs — so the two keys agree by construction. The nonceTPM and key are copied into durable model memory
    //(plain arrays, like a transient key's private scalar) the transition records; the transient KDFa buffer is
    //zeroed and released here. The session key is a secret the model retains for the session's lifetime.
    private static async ValueTask<TpmSimulatorInput> StartHmacSessionAsync(TpmStartHmacSessionAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        int digestSize = SessionDigestSize(action.SessionAlg);

        //nonceTPM: a fresh RNG draw of the session-hash width (TPM 2.0 Library Part 1, clause 17.6.7).
        byte[] nonceTpm = new byte[digestSize];
        context.Rng(nonceTpm);

        //sessionKey = KDFa(sessionAlg, bindAuthValue, "ATH", nonceTPM, nonceCaller, digestBits) (Part 1, clause
        //17.6.10 equation 20). bindAuthValue is the KDFa key (empty in this slice); this path is unsalted, so no
        //salt follows it. contextU is nonceTPM, contextV is the start nonceCaller — the same inputs the host uses.
        byte[] sessionKey;
        using(IMemoryOwner<byte> derived = await Kdfa.DeriveAsync(
            SessionHashName(action.SessionAlg), action.BindAuthValue, "ATH", nonceTpm, action.NonceCaller, digestSize * 8, context.Pool, cancellationToken).ConfigureAwait(false))
        {
            sessionKey = derived.Memory.Span[..digestSize].ToArray();
            derived.Memory.Span[..digestSize].Clear();
        }

        return new TpmHmacSessionStarted(action.SessionHandle, action.SessionAlg, action.Symmetric, nonceTpm, sessionKey);
    }

    //An encrypt-attributed TPM2_GetRandom() response over a bound HMAC session (TPM 2.0 Library Part 3, clause 16.1;
    //Part 1, clauses 18.7 and 19). The order is the crux and mirrors the host's response-processing contract: draw
    //the random octets and a fresh nonceTPM, ENCRYPT the first response parameter, compute rpHash over the ENCRYPTED
    //parameter area, then compute the response HMAC — so the host, which computes rpHash over the response
    //parameters as received (still encrypted) before decrypting them, verifies and decrypts by construction.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parameter-area and HMAC buffers transfers to the returned TpmEncryptedRandomProduced, then to the TpmEncryptedRandomResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> EncryptRandomOverSessionAsync(TpmEncryptRandomAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        int digestSize = SessionDigestSize(action.SessionAlg);
        int byteCount = action.ByteCount;

        //nonceTPM rolled to a fresh value for this response (Part 1, clause 17.6.7): the response nonceNewer.
        byte[] newNonceTpm = new byte[digestSize];
        context.Rng(newNonceTpm);

        //The first (only) response parameter is randomBytes as a TPM2B_DIGEST: a UINT16 size prefix (the count,
        //left unprotected) followed by the octets, whose data portion is encrypted in place (Part 1, clause 19.1).
        int parameterLength = sizeof(ushort) + byteCount;
        IMemoryOwner<byte> parameterArea = context.Pool.Rent(Math.Max(parameterLength, 1));
        try
        {
            //Fill the size field and draw the random octets synchronously (the span never crosses an await).
            {
                Span<byte> paramSpan = parameterArea.Memory.Span[..parameterLength];
                BinaryPrimitives.WriteUInt16BigEndian(paramSpan, (ushort)byteCount);
                context.Rng(paramSpan.Slice(sizeof(ushort), byteCount));
            }

            //Encrypt the data portion (after the 2-octet size). Response direction (Part 1, clause 19.2): nonceNewer
            //= newNonceTPM, nonceOlder = nonceCaller; the key is sessionValue = sessionKey (the empty bind authValue
            //adds nothing, Part 1, clause 19.1).
            await ApplyResponseEncryptionAsync(
                action.Symmetric, action.SessionAlg, action.SessionKey, newNonceTpm, action.NonceCaller,
                parameterArea.Memory.Slice(sizeof(ushort), byteCount), context.Pool, cancellationToken).ConfigureAwait(false);

            //rpHash over the ENCRYPTED parameter area, then the response HMAC over rpHash || nonceTPM || nonceCaller
            //|| sessionAttributes. Both key on the same sessionValue and the same seams the host verifies with.
            using IMemoryOwner<byte> rpHash = await ComputeSessionRpHashAsync(
                action.SessionAlg, TpmCcConstants.TPM_CC_GetRandom, parameterArea.Memory[..parameterLength], context.Pool, cancellationToken).ConfigureAwait(false);

            IMemoryOwner<byte> hmac = await ComputeResponseHmacAsync(
                action.SessionAlg, action.SessionKey, rpHash.Memory[..digestSize], newNonceTpm, action.NonceCaller, action.SessionAttributes, context.Pool, cancellationToken).ConfigureAwait(false);

            return new TpmEncryptedRandomProduced(action.SessionHandle, newNonceTpm, action.SessionAttributes, parameterArea, parameterLength, hmac, digestSize);
        }
        catch
        {
            parameterArea.Memory.Span[..parameterLength].Clear();
            parameterArea.Dispose();
            throw;
        }
    }

    //A policy-gated TPM2_Unseal() response over two sessions (TPM 2.0 Library Part 3, clause 12.7; Part 1, clauses
    //18.7 and 19). The recovered secret is framed as a TPM2B_SENSITIVE_DATA (outData), its data portion encrypted
    //over the encrypt session in the same order the encrypt-attributed TPM2_GetRandom() path establishes: draw a
    //fresh nonceTPM, ENCRYPT outData, compute rpHash over the ENCRYPTED parameter area, then the encrypt session's
    //response HMAC — so the host, which computes rpHash over the response parameters as received (still encrypted)
    //before decrypting them, verifies and decrypts by construction. The policy session carries no key, so no HMAC is
    //computed for it; only its nonce width and echoed attributes travel back for framing.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the parameter-area and HMAC buffers transfers to the returned TpmUnsealedOverSessions, then to the TpmUnsealOverSessionsResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> UnsealOverSessionsAsync(TpmUnsealDataAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        int digestSize = SessionDigestSize(action.EncryptSessionAlg);
        int secretLength = action.SecretData.Length;

        //nonceTPM rolled to a fresh value for this response (Part 1, clause 17.6.7): the encrypt session's response
        //nonceNewer.
        byte[] newNonceTpm = new byte[digestSize];
        context.Rng(newNonceTpm);

        //The single response parameter is outData as a TPM2B_SENSITIVE_DATA: a UINT16 size prefix (the count, left
        //unprotected) followed by the sealed octets, whose data portion is encrypted in place (Part 1, clause 19.1).
        int parameterLength = sizeof(ushort) + secretLength;
        IMemoryOwner<byte> parameterArea = context.Pool.Rent(Math.Max(parameterLength, 1));
        try
        {
            //Lay out the sized outData synchronously (the span never crosses an await).
            {
                Span<byte> paramSpan = parameterArea.Memory.Span[..parameterLength];
                BinaryPrimitives.WriteUInt16BigEndian(paramSpan, (ushort)secretLength);
                action.SecretData.Span.CopyTo(paramSpan[sizeof(ushort)..]);
            }

            //Encrypt the data portion (after the 2-octet size) over the encrypt session. Response direction (Part 1,
            //clause 19.2): nonceNewer = newNonceTPM, nonceOlder = the encrypt session's command nonceCaller; the key
            //is sessionValue = sessionKey (the encrypt session authorizes no entity, so its authValue adds nothing,
            //Part 1, clause 19.1).
            await ApplyResponseEncryptionAsync(
                action.EncryptSymmetric, action.EncryptSessionAlg, action.EncryptSessionKey, newNonceTpm, action.EncryptNonceCaller,
                parameterArea.Memory.Slice(sizeof(ushort), secretLength), context.Pool, cancellationToken).ConfigureAwait(false);

            //rpHash over the ENCRYPTED parameter area, then the encrypt session's response HMAC over rpHash ||
            //nonceTPM || nonceCaller || sessionAttributes. Both key on the same sessionValue and the same seams the
            //host verifies with. The policy session's response entry needs no HMAC (it carries no key).
            using IMemoryOwner<byte> rpHash = await ComputeSessionRpHashAsync(
                action.EncryptSessionAlg, TpmCcConstants.TPM_CC_Unseal, parameterArea.Memory[..parameterLength], context.Pool, cancellationToken).ConfigureAwait(false);

            IMemoryOwner<byte> hmac = await ComputeResponseHmacAsync(
                action.EncryptSessionAlg, action.EncryptSessionKey, rpHash.Memory[..digestSize], newNonceTpm, action.EncryptNonceCaller, action.EncryptAttributes, context.Pool, cancellationToken).ConfigureAwait(false);

            int policyNonceLength = SessionDigestSize(action.PolicySessionAlg);

            return new TpmUnsealedOverSessions(
                action.EncryptSessionHandle, newNonceTpm, action.EncryptAttributes, parameterArea, parameterLength, hmac, digestSize, policyNonceLength, action.PolicyAttributes);
        }
        catch
        {
            parameterArea.Memory.Span[..parameterLength].Clear();
            parameterArea.Dispose();
            throw;
        }
    }

    //Applies the session's parameter-encryption scheme to the response first-parameter data in place: XOR
    //obfuscation (mandatory, self-inverse) or AES-CFB (platform specific), keyed by sessionValue with the supplied
    //response-direction nonces (TPM 2.0 Library Part 1, clauses 19.2 and 19.3). Reuses the production
    //TpmParameterEncryption primitives, so the mask/keystream matches the host's decryption by construction.
    [SuppressMessage("Interoperability", "CA1416:Validate platform compatibility",
        Justification = "The AES-CFB branch is selected only when the session negotiated an AES TPMT_SYM_DEF, which this simulator agrees only with a caller that requested it; the XOR branch uses no browser-unsupported API. This mirrors the host TpmSession's own suppression for the same primitive.")]
    private static async ValueTask ApplyResponseEncryptionAsync(
        TpmtSymDef symmetric, TpmAlgIdConstants sessionAlg, ReadOnlyMemory<byte> sessionValue, ReadOnlyMemory<byte> nonceNewer, ReadOnlyMemory<byte> nonceOlder, Memory<byte> data, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        HashAlgorithmName hashName = SessionHashName(sessionAlg);

        if(symmetric.IsXor)
        {
            await TpmParameterEncryption.XorAsync(hashName, sessionValue, nonceNewer, nonceOlder, data, pool, cancellationToken).ConfigureAwait(false);
        }
        else if(symmetric.Algorithm == TpmAlgIdConstants.TPM_ALG_AES && symmetric.Mode == TpmAlgIdConstants.TPM_ALG_CFB)
        {
            await TpmParameterEncryption.CfbAsync(hashName, symmetric.KeyBits, sessionValue, nonceNewer, nonceOlder, data, encrypting: true, pool, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            throw new NotSupportedException(
                $"Session parameter encryption with symmetric algorithm '{symmetric.Algorithm}' mode '{symmetric.Mode}' is not supported; only XOR obfuscation and AES-CFB are implemented.");
        }
    }

    //rpHash for a session response = H_sessionAlg(responseCode(TPM_RC_SUCCESS) || commandCode || responseParameter
    //Area) — the response parameter bytes as sent, which for an encrypt session are the ciphertext (TPM 2.0 Library
    //Part 1, clause 18.7). Computed through the registered digest seam over one contiguous buffer. The commandCode
    //is a parameter so the same helper frames the rpHash of every session-response command (TPM2_GetRandom(),
    //TPM2_Unseal(), ...). The executor derives the rpHash hash from the first authorization session; this slice runs
    //the authorizing and encrypt sessions on one hash, so the encrypt session's hash coincides with it.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rpHash buffer transfers to the caller, which releases it via a using declaration.")]
    private static async ValueTask<IMemoryOwner<byte>> ComputeSessionRpHashAsync(TpmAlgIdConstants sessionAlg, TpmCcConstants commandCode, ReadOnlyMemory<byte> parameterArea, MemoryPool<byte> pool, CancellationToken cancellationToken)
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

    //The response session HMAC = HMAC_sessionAlg(sessionValue, rpHash || nonceTPM(new) || nonceCaller ||
    //sessionAttributes) (TPM 2.0 Library Part 1, clause 18.7). sessionValue is the session key (the empty bind
    //authValue adds nothing). Computed through the registered HMAC seam — the SAME the host verifies with.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the HMAC buffer transfers to the caller, which carries it to the response intent disposed by SerializeResponse.")]
    private static async ValueTask<IMemoryOwner<byte>> ComputeResponseHmacAsync(
        TpmAlgIdConstants sessionAlg, ReadOnlyMemory<byte> sessionValue, ReadOnlyMemory<byte> rpHash, ReadOnlyMemory<byte> nonceTpm, ReadOnlyMemory<byte> nonceCaller, byte sessionAttributes, MemoryPool<byte> pool, CancellationToken cancellationToken)
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
            span[offset] = sessionAttributes;
        }

        using HmacValue hmac = await CryptographicKeyEvents.ComputeHmacAsync(
            messageOwner.Memory[..messageLength], sessionValue, digestSize, SessionHmacTag(sessionAlg), pool, cancellationToken: cancellationToken).ConfigureAwait(false);

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

    //The digest width in octets of a session hash algorithm.
    private static int SessionDigestSize(TpmAlgIdConstants hashAlg) => hashAlg switch
    {
        TpmAlgIdConstants.TPM_ALG_SHA1 => 20,
        TpmAlgIdConstants.TPM_ALG_SHA256 => 32,
        TpmAlgIdConstants.TPM_ALG_SHA384 => 48,
        TpmAlgIdConstants.TPM_ALG_SHA512 => 64,
        _ => throw new NotSupportedException($"Session hash algorithm '{hashAlg}' is not supported.")
    };

    //Maps a session hash algorithm to its framework name (the KDF, digest, and HMAC dispatch key).
    private static HashAlgorithmName SessionHashName(TpmAlgIdConstants hashAlg) => hashAlg switch
    {
        TpmAlgIdConstants.TPM_ALG_SHA1 => HashAlgorithmName.SHA1,
        TpmAlgIdConstants.TPM_ALG_SHA256 => HashAlgorithmName.SHA256,
        TpmAlgIdConstants.TPM_ALG_SHA384 => HashAlgorithmName.SHA384,
        TpmAlgIdConstants.TPM_ALG_SHA512 => HashAlgorithmName.SHA512,
        _ => throw new NotSupportedException($"Session hash algorithm '{hashAlg}' is not supported.")
    };

    //The digest tag for the session's rpHash: the hash family carried inline (TPM sessions may use SHA-1, which the
    //convenience CryptoTags deliberately omit), mirroring the executor's own tag construction.
    private static Tag SessionDigestTag(TpmAlgIdConstants hashAlg) =>
        Tag.Create(SessionHashName(hashAlg))
            .With(Purpose.Digest)
            .With(EncodingScheme.Raw)
            .With(MaterialSemantics.Direct);

    //The HMAC tag for the session's response HMAC, mirroring the host TpmSession's own tag construction.
    private static Tag SessionHmacTag(TpmAlgIdConstants hashAlg) =>
        Tag.Create(SessionHashName(hashAlg))
            .With(Purpose.Hmac)
            .With(EncodingScheme.Raw)
            .With(MaterialSemantics.Direct);

    //The credential-protection outer wrap uses the credential key's (endorsement key's) symmetric algorithm, which
    //for the ECC storage/EK template this model creates is AES-128-CFB (TPM 2.0 Library Part 1, clause 25.2; the
    //storage parent template negotiates AES-128). The IV is a block of zeros (the seed is single-use, so no per-object
    //IV is needed). The KDFe use label is "IDENTITY" and the KDFa outer-wrap labels are "STORAGE" (the symmetric key)
    //and "INTEGRITY" (the HMAC key) (Part 1, clause 24).
    private const int CredentialSymmetricKeyBits = 128;
    private const int CredentialSymmetricKeyBytes = CredentialSymmetricKeyBits / 8;
    private const int CredentialSymmetricBlockSize = 16;
    private const string CredentialIdentityLabel = "IDENTITY";
    private const string CredentialStorageLabel = "STORAGE";
    private const string CredentialIntegrityLabel = "INTEGRITY";

    //TPM2_MakeCredential(): wrap a credential so only a TPM holding the credential key's private scalar and the object
    //named by objectName can recover it (TPM 2.0 Library Part 1, clause 24; Part 3, clause 12.6). The seed is
    //transported by an ECDH exchange with the credential key's public point — Z = ECDH(ephemeralPriv, EK_pub), then
    //seed = KDFe(nameAlg, Z, "IDENTITY", ephemeral x, EK x) — and the outer wrap (BuildCredentialBlobAsync) binds the
    //credential's integrity to objectName. The encrypted secret carries the ephemeral public point as a marshaled
    //TPMS_ECC_POINT, the ECC form of TPM2B_ENCRYPTED_SECRET (Part 2, clause 11.4.33). Ownership of the credential blob
    //and the secret flows to TpmCredentialMade, then to the response intent, and is released by SerializeResponse.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the credential-blob and secret buffers transfers to the returned TpmCredentialMade, then to the TpmMakeCredentialResponse intent, and is released by SerializeResponse after framing.")]
    private static async ValueTask<TpmSimulatorInput> MakeCredentialAsync(TpmMakeCredentialAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        TpmEccSigningBackend backend = context.SigningBackend
            ?? throw new InvalidOperationException("TPM2_MakeCredential() requires a signing backend, but none was supplied.");
        MemoryPool<byte> pool = context.Pool;

        int fieldWidth = (action.CredentialKeyPublicPoint.Length - 1) / 2;
        int seedSize = SessionDigestSize(action.NameAlg);

        //A fresh ephemeral key pair for the ECDH seed transport (a new pair per credential; Part 1, clause 24).
        using TpmGeneratedEccKey ephemeral = await backend.GenerateKey(action.CredentialKeyCurve, pool, cancellationToken).ConfigureAwait(false);

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
                ephemeralScalar, action.CredentialKeyPublicPoint, action.CredentialKeyCurve, pool, cancellationToken).ConfigureAwait(false);
            using IMemoryOwner<byte> seed = await Kdfe.DeriveAsync(
                SessionHashName(action.NameAlg), sharedValue.Memory[..fieldWidth], CredentialIdentityLabel, ephemeralX, credentialKeyX, seedSize * 8, pool, cancellationToken).ConfigureAwait(false);

            (IMemoryOwner<byte> credentialBlob, int credentialBlobLength) = await BuildCredentialBlobAsync(
                seed.Memory[..seedSize], action.Credential, action.ObjectName, action.NameAlg, pool, cancellationToken).ConfigureAwait(false);
            try
            {
                seed.Memory.Span[..seedSize].Clear();
                (IMemoryOwner<byte> secret, int secretLength) = FrameEccPointSecret(ephemeralPoint, fieldWidth, pool);

                return new TpmCredentialMade(credentialBlob, credentialBlobLength, secret, secretLength);
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

    //Builds the credential blob (TPMS_ID_OBJECT) of TPM2_MakeCredential()'s outer wrap (TPM 2.0 Library Part 1, clause
    //24): symKey = KDFa(nameAlg, seed, "STORAGE", objectName, empty, symBits) keys the AES-CFB encryption of the
    //marshaled credential (a zero IV), and hmacKey = KDFa(nameAlg, seed, "INTEGRITY", empty, empty, digestBits) keys
    //outerHMAC = HMAC(hmacKey, encIdentity || objectName). Both derivations fold in the bound object's Name, so the
    //blob can only be recovered by activating against that same object. The blob is TPM2B(outerHMAC) || encIdentity.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the credential-blob buffer transfers to the caller, which carries it to the response intent disposed by SerializeResponse; the intermediate buffers are released by their using declarations.")]
    [SuppressMessage("Interoperability", "CA1416:Validate platform compatibility",
        Justification = "The credential-protection outer wrap uses AES-CFB, the symmetric algorithm of the credential key's (endorsement key's) storage template (TPM 2.0 Library Part 1, clause 24); this in-process behavioural simulator is a test/server-side model, not a browser target. This mirrors the host's own suppression for the same primitive.")]
    private static async ValueTask<(IMemoryOwner<byte> Owner, int Length)> BuildCredentialBlobAsync(
        ReadOnlyMemory<byte> seed, ReadOnlyMemory<byte> credential, ReadOnlyMemory<byte> objectName, TpmAlgIdConstants nameAlg, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        int digestSize = SessionDigestSize(nameAlg);
        HashAlgorithmName hashName = SessionHashName(nameAlg);

        //innerData = marshaled TPM2B_DIGEST(credential): a UINT16 size prefix followed by the credential octets.
        int credLen = credential.Length;
        int innerLen = sizeof(ushort) + credLen;

        using IMemoryOwner<byte> symKey = await Kdfa.DeriveAsync(
            hashName, seed, CredentialStorageLabel, objectName, ReadOnlyMemory<byte>.Empty, CredentialSymmetricKeyBits, pool, cancellationToken).ConfigureAwait(false);
        using IMemoryOwner<byte> encIdentity = pool.Rent(innerLen);

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

    //Frames the ephemeral public point as the encrypted-secret transport: a marshaled TPMS_ECC_POINT (TPM2B x || TPM2B
    //y) at the curve field width — the ECC form of TPM2B_ENCRYPTED_SECRET (TPM 2.0 Library Part 2, clauses 11.2.5 and
    //11.4.33). The point is SEC1 uncompressed (0x04 || X || Y), so X and Y are the field-width halves after the tag.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the secret buffer transfers to the caller, which carries it to the response intent disposed by SerializeResponse.")]
    private static (IMemoryOwner<byte> Owner, int Length) FrameEccPointSecret(byte[] sec1Point, int fieldWidth, MemoryPool<byte> pool)
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

    //outerHMAC = HMAC_nameAlg(hmacKey, encIdentity || objectName) (TPM 2.0 Library Part 1, clause 24), computed through
    //the registered HMAC seam over one contiguous buffer — the same seam MakeCredential and ActivateCredential both
    //drive, so the produced and recomputed HMACs agree by construction.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the HMAC buffer transfers to the caller, which releases it via a using declaration.")]
    private static async ValueTask<IMemoryOwner<byte>> ComputeCredentialHmacAsync(
        ReadOnlyMemory<byte> hmacKey, ReadOnlyMemory<byte> encIdentity, ReadOnlyMemory<byte> objectName, TpmAlgIdConstants nameAlg, MemoryPool<byte> pool, CancellationToken cancellationToken)
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

    //TPM2_ActivateCredential(): recover the wrapped credential (TPM 2.0 Library Part 1, clause 24; Part 3, clause
    //12.5). Recover the seed by Z = ECDH(EK_priv, ephemeralPub) fed to KDFe — the same seed MakeCredential produced,
    //by ECDH symmetry — then re-derive symKey/hmacKey from the seed AND the ACTIVATE object's Name, recompute the
    //outer HMAC over the ciphertext and that Name, and compare it (constant time) to the blob's HMAC. On a match,
    //AES-CFB-decrypt encIdentity and unmarshal the credential; on a mismatch, answer TPM_RC_INTEGRITY — so a
    //credential bound to one object cannot be recovered against another (the negative case). Ownership of the
    //recovered secret flows to TpmCredentialActivated, then to the response intent, and is released (zeroed) by
    //SerializeResponse after framing.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the recovered-secret buffer transfers to the returned TpmCredentialActivated, then to the TpmActivateCredentialResponse intent, and is released by SerializeResponse after framing.")]
    [SuppressMessage("Interoperability", "CA1416:Validate platform compatibility",
        Justification = "The credential-protection outer wrap uses AES-CFB, the symmetric algorithm of the credential key's (endorsement key's) storage template (TPM 2.0 Library Part 1, clause 24); this in-process behavioural simulator is a test/server-side model, not a browser target. This mirrors the host's own suppression for the same primitive.")]
    private static async ValueTask<TpmSimulatorInput> ActivateCredentialAsync(TpmActivateCredentialAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        TpmEccSigningBackend backend = context.SigningBackend
            ?? throw new InvalidOperationException("TPM2_ActivateCredential() requires a signing backend, but none was supplied.");
        MemoryPool<byte> pool = context.Pool;

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
            return new TpmCredentialActivated(TpmRcConstants.TPM_RC_SIZE, null, 0);
        }

        using IMemoryOwner<byte> sharedValue = await backend.ComputeSharedSecret(
            action.CredentialKeyPrivateScalar, ephemeralPoint, action.CredentialKeyCurve, pool, cancellationToken).ConfigureAwait(false);
        using IMemoryOwner<byte> seed = await Kdfe.DeriveAsync(
            hashName, sharedValue.Memory[..fieldWidth], CredentialIdentityLabel, ephemeralX, credentialKeyX, seedSize * 8, pool, cancellationToken).ConfigureAwait(false);

        //Recompute the outer HMAC over the ciphertext and the ACTIVATE object's Name; a mismatch is TPM_RC_INTEGRITY
        //(Part 3, clause 12.5) — the credential was bound to a different object, or is corrupt.
        using IMemoryOwner<byte> hmacKey = await Kdfa.DeriveAsync(
            hashName, seed.Memory[..seedSize], CredentialIntegrityLabel, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, seedSize * 8, pool, cancellationToken).ConfigureAwait(false);
        using(IMemoryOwner<byte> expectedHmac = await ComputeCredentialHmacAsync(
            hmacKey.Memory[..seedSize], encIdentity, action.ActivateObjectName, action.NameAlg, pool, cancellationToken).ConfigureAwait(false))
        {
            hmacKey.Memory.Span[..seedSize].Clear();

            if(!CryptographicOperations.FixedTimeEquals(expectedHmac.Memory.Span[..seedSize], blobHmac))
            {
                seed.Memory.Span[..seedSize].Clear();

                return new TpmCredentialActivated(TpmRcConstants.TPM_RC_INTEGRITY, null, 0);
            }
        }

        //Integrity verified: derive symKey from the seed and the activate object's Name, AES-CFB-decrypt encIdentity,
        //and unmarshal the recovered TPM2B_DIGEST credential.
        using IMemoryOwner<byte> symKey = await Kdfa.DeriveAsync(
            hashName, seed.Memory[..seedSize], CredentialStorageLabel, action.ActivateObjectName, ReadOnlyMemory<byte>.Empty, CredentialSymmetricKeyBits, pool, cancellationToken).ConfigureAwait(false);
        seed.Memory.Span[..seedSize].Clear();

        using IMemoryOwner<byte> plaintext = pool.Rent(Math.Max(encIdentity.Length, 1));
        try
        {
            //Decrypt and read the credential synchronously (no await between the decrypt and the copy-out).
            int credLen;
            IMemoryOwner<byte> certInfo;
            {
                byte[] zeroIv = new byte[CredentialSymmetricBlockSize];
                encIdentity.CopyTo(plaintext.Memory.Span);
                TpmParameterEncryption.AesCfb(symKey.Memory.Span[..CredentialSymmetricKeyBytes], zeroIv, plaintext.Memory.Span[..encIdentity.Length], encrypting: false);
                symKey.Memory.Span[..CredentialSymmetricKeyBytes].Clear();

                var reader = new TpmReader(plaintext.Memory.Span[..encIdentity.Length]);
                credLen = reader.ReadUInt16();
                ReadOnlySpan<byte> credential = reader.ReadBytes(credLen);

                certInfo = pool.Rent(Math.Max(credLen, 1));
                try
                {
                    credential.CopyTo(certInfo.Memory.Span);
                }
                catch
                {
                    certInfo.Memory.Span.Clear();
                    certInfo.Dispose();
                    throw;
                }
            }

            return new TpmCredentialActivated(TpmRcConstants.TPM_RC_SUCCESS, certInfo, credLen);
        }
        finally
        {
            //plaintext held the recovered credential; zero it before returning the buffer to the pool.
            plaintext.Memory.Span[..encIdentity.Length].Clear();
        }
    }

    //TPM2_PolicyNV(): marshal the NV Index's TPMS_NV_PUBLIC and compute its Name (nameAlg || H_nameAlg(TPMS_NV_PUBLIC),
    //TPM 2.0 Library Part 1, clause 16) through the shared nameAlg-agile TpmObjectName helper and the registered
    //asynchronous digest seam — TPM digests belong there, not the sync HashFunctionDelegate seam a pure transition
    //could reach on its own. Feeds the computed Name back with the pending assertion's arguments so the PolicyNV
    //continuation transition can extend the session's policyDigest.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the computed Name buffer transfers to the returned TpmNvNameComputedForPolicy and is released by the PolicyNV continuation transition once the digest extension consumes it.")]
    private static async ValueTask<TpmSimulatorInput> ComputeNvNameForPolicyAsync(TpmComputeNvNameAction action, TpmActionContext context, CancellationToken cancellationToken)
    {
        using var nvPublic = new TpmsNvPublic(action.NvIndex, action.NameAlg, action.Attributes, Tpm2bDigest.Empty, action.DataSize);
        int publicSize = nvPublic.SerializedSize;
        using IMemoryOwner<byte> marshaled = context.Pool.Rent(publicSize);
        var writer = new TpmWriter(marshaled.Memory.Span[..publicSize]);
        nvPublic.WriteTo(ref writer);

        (IMemoryOwner<byte> name, int nameLength) = await TpmObjectName.ComputeNameAsync(
            marshaled.Memory[..publicSize], (ushort)action.NameAlg, context.Pool, cancellationToken).ConfigureAwait(false);

        return new TpmNvNameComputedForPolicy(action.PolicySession, name, nameLength, action.OperandB, action.Offset, action.Operation);
    }

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented buffer transfers to the returned TpmRandomGenerated, then to the TpmRandomResponse intent, and is released by SerializeResponse after framing.")]
    private static TpmRandomGenerated GenerateRandom(TpmRngAction action, TpmActionContext context)
    {
        //Rent at least one octet so a zero-length request still yields a valid (empty) buffer.
        IMemoryOwner<byte> owner = context.Pool.Rent(Math.Max(action.ByteCount, 1));
        try
        {
            context.Rng(owner.Memory.Span[..action.ByteCount]);
        }
        catch
        {
            owner.Dispose();
            throw;
        }

        return new TpmRandomGenerated(owner, action.ByteCount);
    }

    //The default deterministic RNG backend: a per-instance counter stream. Reproducible across runs
    //yet advancing across draws, so successive TPM2_GetRandom() calls return distinct octets. Not a
    //real entropy source — provenance is the concern of TpmEntropyProvider, not the device model.
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

    //Caller-supplied context threaded to the action executor without closure capture: the injected RNG
    //backend, the per-call memory pool, the injected ECC and RSA signing backends (null when none was
    //supplied), and the per-TPM creation-ticket proof seed.
    private readonly struct TpmActionContext(FillEntropyDelegate rng, MemoryPool<byte> pool, TpmEccSigningBackend? signingBackend, TpmRsaSigningBackend? rsaSigningBackend, ReadOnlyMemory<byte> proofSeed)
    {
        public FillEntropyDelegate Rng { get; } = rng;

        public MemoryPool<byte> Pool { get; } = pool;

        public TpmEccSigningBackend? SigningBackend { get; } = signingBackend;

        public TpmRsaSigningBackend? RsaSigningBackend { get; } = rsaSigningBackend;

        public ReadOnlyMemory<byte> ProofSeed { get; } = proofSeed;
    }

    /// <summary>
    /// Bridges the runner's value-threaded step to the live automaton (design decision D2: one live
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

    private bool TryParseCommand(ReadOnlySpan<byte> command, MemoryPool<byte> pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
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
                    return TryParseGetRandomOverSession(ref reader, out input, out malformedResponseCode);
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
                return TryParseNvDefineSpace(ref reader, header.Tag, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_NV_Read:
            {
                return TryParseNvRead(ref reader, header.Tag, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_NV_Write:
            {
                return TryParseNvWrite(ref reader, header.Tag, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_NV_UndefineSpace:
            {
                return TryParseNvUndefineSpace(ref reader, header.Tag, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_EvictControl:
            {
                return TryParseEvictControl(ref reader, header.Tag, out input, out malformedResponseCode);
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

                return TryParseSign(ref reader, header.Tag, out input, out malformedResponseCode);
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
                return TryParseUnseal(ref reader, header.Tag, out input, out malformedResponseCode);
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

                return TryParseCertify(ref reader, header.Tag, out input, out malformedResponseCode);
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

                return TryParseCertifyCreation(ref reader, header.Tag, out input, out malformedResponseCode);
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

                return TryParseGetTime(ref reader, header.Tag, out input, out malformedResponseCode);
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
                return TryParseClockSet(ref reader, header.Tag, out input, out malformedResponseCode);
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

                return TryParseNvCertify(ref reader, header.Tag, out input, out malformedResponseCode);
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

                return TryParseVerifySignature(ref reader, header.Tag, out input, out malformedResponseCode);
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

                return TryParseQuote(ref reader, header.Tag, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_StartAuthSession:
            {
                return TryParseStartAuthSession(ref reader, out input, out malformedResponseCode);
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
                return TryParsePolicyPcr(ref reader, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_PolicyOR:
            {
                return TryParsePolicyOr(ref reader, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_PolicySecret:
            {
                return TryParsePolicySecret(ref reader, header.Tag, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_PolicyNV:
            {
                return TryParsePolicyNv(ref reader, header.Tag, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_MakeCredential:
            {
                //Credential protection transports the seed by ECDH with the credential key's public point, so it
                //needs the ECC backend; without it the simulated TPM answers the faithful TPM_RC_COMMAND_CODE.
                if(SigningBackend is null)
                {
                    malformedResponseCode = TpmRcConstants.TPM_RC_COMMAND_CODE;

                    return false;
                }

                return TryParseMakeCredential(ref reader, header.Tag, out input, out malformedResponseCode);
            }
            case TpmCcConstants.TPM_CC_ActivateCredential:
            {
                if(SigningBackend is null)
                {
                    malformedResponseCode = TpmRcConstants.TPM_RC_COMMAND_CODE;

                    return false;
                }

                return TryParseActivateCredential(ref reader, header.Tag, out input, out malformedResponseCode);
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

    //TPM2_NV_DefineSpace() is authorized, so its wire layout after the header is: handle area
    //(@authHandle, 1 handle), authorization area (a single password session), then parameters
    //(auth as TPM2B_AUTH, publicInfo as TPM2B_NV_PUBLIC). The Name algorithm and access policy carried in
    //the public area are consumed for correct framing but not retained by this slice's NV model.
    private static bool TryParseNvDefineSpace(ref TpmReader reader, ushort tag, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
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

        if(!TryReadPasswordAuthArea(ref reader, out ReadOnlyMemory<byte> ownerAuth, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: auth (TPM2B_AUTH) — the authorization value assigned to the new Index.
        if(!TryReadTpm2b(ref reader, out ReadOnlyMemory<byte> indexAuth, out malformedResponseCode))
        {
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
        _ = reader.ReadUInt16();
        var attributes = (TpmaNv)reader.ReadUInt32();
        if(!TrySkipTpm2b(ref reader, out malformedResponseCode))
        {
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

        input = new TpmNvDefineSpaceRequested(authHandle, ownerAuth, nvIndex, attributes, indexAuth, dataSize);

        return true;
    }

    //TPM2_NV_Read() is authorized, so its wire layout after the header is: handle area (@authHandle,
    //nvIndex — 2 handles), authorization area (a single password session), then parameters (size, offset).
    private static bool TryParseNvRead(ref TpmReader reader, ushort tag, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
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

        if(!TryReadPasswordAuthArea(ref reader, out ReadOnlyMemory<byte> suppliedAuth, out malformedResponseCode))
        {
            return false;
        }

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

        input = new TpmNvReadRequested(authHandle, nvIndex, suppliedAuth, size, offset);

        return true;
    }

    //TPM2_NV_Write() is authorized, so its wire layout after the header is: handle area (@authHandle, nvIndex —
    //2 handles), authorization area (a single password session), then parameters (data as TPM2B_MAX_NV_BUFFER,
    //offset as UINT16) (Part 3, clause 31.7).
    private static bool TryParseNvWrite(ref TpmReader reader, ushort tag, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
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

        if(!TryReadPasswordAuthArea(ref reader, out ReadOnlyMemory<byte> suppliedAuth, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: data (TPM2B_MAX_NV_BUFFER) — copied into durable memory so it survives the command buffer.
        if(!TryReadTpm2b(ref reader, out ReadOnlyMemory<byte> data, out malformedResponseCode))
        {
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

        input = new TpmNvWriteRequested(authHandle, nvIndex, suppliedAuth, data, offset);

        return true;
    }

    //TPM2_NV_UndefineSpace() is authorized: handle area (@authHandle, nvIndex — 2 handles), authorization area
    //(a single password session), then no parameters (Part 3, clause 31.4).
    private static bool TryParseNvUndefineSpace(ref TpmReader reader, ushort tag, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
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

        if(!TryReadPasswordAuthArea(ref reader, out _, out malformedResponseCode))
        {
            return false;
        }

        //No parameters follow the authorization area; any surplus is malformed (Part 3, 5.2).
        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        input = new TpmNvUndefineSpaceRequested(authHandle, nvIndex);

        return true;
    }

    //TPM2_EvictControl() is authorized: handle area (@auth, objectHandle — 2 handles), authorization area (a
    //single password session), then the parameter persistentHandle (TPMI_DH_PERSISTENT) (Part 3, clause 28.5).
    private static bool TryParseEvictControl(ref TpmReader reader, ushort tag, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
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

        if(!TryReadPasswordAuthArea(ref reader, out _, out malformedResponseCode))
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

        input = new TpmEvictControlRequested(authHandle, objectHandle, persistentHandle);

        return true;
    }

    //TPM2_CreatePrimary() is authorized, so its wire layout after the header is: handle area (@primaryHandle,
    //1 handle), authorization area (a single password session), then parameters (inSensitive as
    //TPM2B_SENSITIVE_CREATE, inPublic as TPM2B_PUBLIC, outsideInfo as TPM2B_DATA, creationPCR as
    //TPML_PCR_SELECTION). The Name algorithm, object attributes, and per-algorithm key parameters are read from
    //the ECC or RSA signing template; the sensitive area, outsideInfo, and PCR selection are consumed for framing
    //but not modelled. eccSupported/rsaSupported say which backends are wired, so a template whose algorithm has
    //no backend is answered TPM_RC_COMMAND_CODE rather than entering an effect the TPM cannot run.
    private static bool TryParseCreatePrimary(ref TpmReader reader, ushort tag, MemoryPool<byte> pool, bool eccSupported, bool rsaSupported, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
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

        if(!TryReadPasswordAuthArea(ref reader, out _, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: inSensitive (TPM2B_SENSITIVE_CREATE) — the userAuth and data the simulator does not model.
        if(!TrySkipTpm2b(ref reader, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: inPublic (TPM2B_PUBLIC) — the ECC or RSA signing template.
        if(reader.Remaining < sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        TpmSimulatorInput? parsed;
        using(Tpm2bPublic inPublic = Tpm2bPublic.Parse(ref reader, pool))
        {
            if(!TryBuildCreatePrimaryRequest(inPublic.PublicArea, hierarchy, eccSupported, rsaSupported, out parsed, out malformedResponseCode))
            {
                return false;
            }
        }

        //Parameter: outsideInfo (TPM2B_DATA) — included in creation data; not modelled.
        if(!TrySkipTpm2b(ref reader, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: creationPCR (TPML_PCR_SELECTION) — a UINT32 count then that many selections, skipped.
        if(!TrySkipPcrSelection(ref reader, out malformedResponseCode))
        {
            return false;
        }

        input = parsed;

        return true;
    }

    //Turns a parsed inPublic template into the matching create-primary request, or a response code when the
    //template is unmodelled or its algorithm has no wired backend. An ECC signing template (ECDSA over an ECC
    //key) and an RSA signing template are modelled; the RSA scheme is carried as-is, so an unrestricted (NULL)
    //scheme is preserved and the signing scheme is chosen per TPM2_Sign().
    private static bool TryBuildCreatePrimaryRequest(TpmtPublic publicArea, uint hierarchy, bool eccSupported, bool rsaSupported, [NotNullWhen(true)] out TpmSimulatorInput? request, out TpmRcConstants malformedResponseCode)
    {
        request = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        //Retained so the created object's exported public area — and therefore its Name — carries the template's
        //authPolicy (empty for every template except a standard endorsement key's "PolicyA"), mirroring how
        //TryParseCreate retains TpmCreateSealedObjectRequested.AuthPolicy for the sealed-data path.
        ReadOnlyMemory<byte> authPolicy = publicArea.AuthPolicy.AsReadOnlySpan().ToArray();

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

            request = new TpmCreatePrimaryRequested(hierarchy, publicArea.NameAlg, publicArea.ObjectAttributes, eccParms.CurveId, eccParms.Scheme.HashAlg, authPolicy);

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
            request = new TpmCreateStorageParentRequested(hierarchy, publicArea.NameAlg, publicArea.ObjectAttributes, storageParms.CurveId, noDa, authPolicy);

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

            request = new TpmCreateRsaPrimaryRequested(hierarchy, publicArea.NameAlg, publicArea.ObjectAttributes, rsaParms.KeyBits, rsaParms.Scheme, authPolicy);

            return true;
        }

        //A non-signing or otherwise unmodelled template.
        malformedResponseCode = TpmRcConstants.TPM_RC_SCHEME;

        return false;
    }

    //TPM2_Sign() is authorized, so its wire layout after the header is: handle area (@keyHandle, 1 handle),
    //authorization area (a single password session), then parameters (digest as TPM2B_DIGEST, inScheme as
    //TPMT_SIG_SCHEME, validation as TPMT_TK_HASHCHECK). The validation ticket is consumed but not checked:
    //this slice signs an externally-computed digest, which a genuine TPM authorizes with a NULL ticket.
    private static bool TryParseSign(ref TpmReader reader, ushort tag, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
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

        if(!TryReadPasswordAuthArea(ref reader, out _, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: digest (TPM2B_DIGEST) — the externally-computed digest, copied into durable model memory.
        if(!TryReadTpm2b(ref reader, out ReadOnlyMemory<byte> digest, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: inScheme (TPMT_SIG_SCHEME) — scheme selector (UINT16) + hash algorithm (UINT16).
        if(reader.Remaining < 2 * sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        var signatureScheme = (TpmAlgIdConstants)reader.ReadUInt16();
        var schemeHashAlg = (TpmAlgIdConstants)reader.ReadUInt16();

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

        input = new TpmSignRequested(keyHandle, digest, signatureScheme, schemeHashAlg);

        return true;
    }

    //TPM2_Create() is authorized, so its wire layout after the header is: handle area (@parentHandle, 1 handle),
    //authorization area (a single password session), then parameters (inSensitive as TPM2B_SENSITIVE_CREATE,
    //inPublic as TPM2B_PUBLIC, outsideInfo as TPM2B_DATA, creationPCR as TPML_PCR_SELECTION). Only a sealed
    //KEYEDHASH template is modelled: the data to seal is read from inSensitive, and the object's Name algorithm,
    //authorization policy, and DA attribute are read from inPublic to reproduce its exported public area. The
    //parent's storage attributes are checked in the transition (which holds the loaded-object state).
    private static bool TryParseCreate(ref TpmReader reader, ushort tag, MemoryPool<byte> pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
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

        if(!TryReadPasswordAuthArea(ref reader, out _, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: inSensitive (TPM2B_SENSITIVE_CREATE) — the userAuth (not modelled for the empty-auth seals
        //this slice serves) and the data to seal, copied into durable model memory.
        if(reader.Remaining < sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        ReadOnlyMemory<byte> secret;
        using(Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.Parse(ref reader, pool))
        {
            secret = inSensitive.Sensitive.Data.AsReadOnlySpan().ToArray();
        }

        //Parameter: inPublic (TPM2B_PUBLIC) — the sealed-object template. Extract the fields the exported public
        //area is reproduced from; the object type must be a sealed KEYEDHASH object (the only kind modelled).
        if(reader.Remaining < sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        TpmAlgIdConstants objectType;
        TpmAlgIdConstants nameAlg;
        ReadOnlyMemory<byte> authPolicy;
        bool noDa;
        using(Tpm2bPublic inPublic = Tpm2bPublic.Parse(ref reader, pool))
        {
            objectType = inPublic.PublicArea.Type;
            nameAlg = inPublic.PublicArea.NameAlg;
            authPolicy = inPublic.PublicArea.AuthPolicy.AsReadOnlySpan().ToArray();
            noDa = (inPublic.PublicArea.ObjectAttributes & TpmaObject.NO_DA) != 0;
        }

        if(objectType != TpmAlgIdConstants.TPM_ALG_KEYEDHASH)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_TYPE;

            return false;
        }

        //Parameter: outsideInfo (TPM2B_DATA) — included in creation data; not modelled.
        if(!TrySkipTpm2b(ref reader, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: creationPCR (TPML_PCR_SELECTION) — a UINT32 count then that many selections, skipped.
        if(!TrySkipPcrSelection(ref reader, out malformedResponseCode))
        {
            return false;
        }

        input = new TpmCreateSealedObjectRequested(parentHandle, nameAlg, authPolicy, noDa, secret);

        return true;
    }

    //TPM2_Load() is authorized: handle area (@parentHandle, 1 handle), authorization area (a single password
    //session), then parameters (inPrivate as TPM2B_PRIVATE, inPublic as TPM2B_PUBLIC). The wrapped blob carries
    //the sealed data (the simulator's own encoding); the marshaled TPMT_PUBLIC is retained so the effect can
    //compute the object Name (TPM 2.0 Library Part 3, clause 12.2).
    private static bool TryParseLoad(ref TpmReader reader, ushort tag, MemoryPool<byte> pool, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
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

        if(!TryReadPasswordAuthArea(ref reader, out _, out malformedResponseCode))
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

        TpmAlgIdConstants objectType;
        TpmAlgIdConstants nameAlg;
        ReadOnlyMemory<byte> authPolicy;
        ReadOnlyMemory<byte> publicAreaBytes;
        using(Tpm2bPublic inPublic = Tpm2bPublic.Parse(ref reader, pool))
        {
            objectType = inPublic.PublicArea.Type;
            nameAlg = inPublic.PublicArea.NameAlg;

            //Retain the authPolicy carried in the loaded public area so a policy-gated TPM2_Unseal() can check it
            //(TPM 2.0 Library Part 3, clause 12.7). It is empty for the plain (authValue-only) seal port's objects.
            authPolicy = inPublic.PublicArea.AuthPolicy.AsReadOnlySpan().ToArray();
            publicAreaBytes = inPublic.GetRawBytes().ToArray();
        }

        input = new TpmLoadObjectRequested(parentHandle, objectType, nameAlg, authPolicy, publicAreaBytes, privateBlob);

        return true;
    }

    //TPM2_Unseal() is authorized: handle area (@itemHandle, 1 handle), authorization area, then no parameters (TPM
    //2.0 Library Part 3, clause 12.7). The authorization area carries either a single password session (the plain
    //authValue-only form) or two sessions in order — a policy session that authorizes the object followed by a bound
    //HMAC session with the encrypt attribute that protects the recovered outData (Part 1, clauses 18.7 and 19). The
    //first session is read generically; whether a second session follows selects the form. The command HMACs are
    //consumed but not verified (see TryParseGetRandomOverSession): the command-side integrity of TPM2_Unseal() is
    //not the property under test — the policy gate and the response-side HMAC and parameter encryption are.
    private static bool TryParseUnseal(ref TpmReader reader, ushort tag, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
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

        //First session (handle + nonceCaller + sessionAttributes + hmac). TryReadHmacCommandSession reads the same
        //TPMS_AUTH_COMMAND layout a password session uses, so it parses either kind; the hmac field is consumed.
        if(!TryReadHmacCommandSession(ref reader, out uint firstHandle, out _, out byte firstAttributes, out malformedResponseCode))
        {
            return false;
        }

        //A single session that consumes the whole authorization area is either the plain password form (TPM_RS_PW,
        //returning outData in the clear) or a lone policy session (which still runs the policy gate, but with no
        //encrypt session the recovered outData is returned in the clear).
        if(reader.Consumed - sessionsStart == (int)authorizationSize)
        {
            if(reader.Remaining != 0)
            {
                malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

                return false;
            }

            input = firstHandle == (uint)TpmRh.TPM_RH_PW
                ? new TpmUnsealRequested(itemHandle)
                : new TpmUnsealOverSessionsRequested(itemHandle, firstHandle, firstAttributes, EncryptSession: 0, ReadOnlyMemory<byte>.Empty, EncryptAttributes: 0);

            return true;
        }

        //Two sessions: session 1 = the policy session (authorizes the object), session 2 = the bound HMAC (encrypt)
        //session (protects outData). Capture the encrypt session's caller nonce and attributes for the response path.
        if(!TryReadHmacCommandSession(ref reader, out uint encryptHandle, out ReadOnlyMemory<byte> encryptNonceCaller, out byte encryptAttributes, out malformedResponseCode))
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

        input = new TpmUnsealOverSessionsRequested(itemHandle, firstHandle, firstAttributes, encryptHandle, encryptNonceCaller, encryptAttributes);

        return true;
    }

    //TPM2_Certify() is authorized and takes two handles, so its wire layout after the header is: handle area
    //(@objectHandle, @signHandle — 2 handles, both requiring authorization), authorization area (two password
    //sessions in handle order), then parameters (qualifyingData as TPM2B_DATA, inScheme as TPMT_SIG_SCHEME). The
    //scheme's validation is entirely in the signing scheme selector (TPM 2.0 Library Part 3, clause 18.2).
    private static bool TryParseCertify(ref TpmReader reader, ushort tag, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
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

        uint objectHandle = reader.ReadUInt32();
        uint signHandle = reader.ReadUInt32();

        if(!TryReadTwoPasswordSessions(ref reader, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: qualifyingData (TPM2B_DATA) — the caller nonce echoed into the attestation, copied into durable memory.
        if(!TryReadTpm2b(ref reader, out ReadOnlyMemory<byte> qualifyingData, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: inScheme (TPMT_SIG_SCHEME) — scheme selector (UINT16) + hash algorithm (UINT16).
        if(reader.Remaining < 2 * sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        var signatureScheme = (TpmAlgIdConstants)reader.ReadUInt16();
        var schemeHashAlg = (TpmAlgIdConstants)reader.ReadUInt16();

        //inScheme is the final parameter; no octets may follow it (Part 3, 5.2).
        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        input = new TpmCertifyRequested(objectHandle, signHandle, qualifyingData, signatureScheme, schemeHashAlg);

        return true;
    }

    //TPM2_CertifyCreation() is authorized and takes two handles, but only ONE requires authorization: the wire
    //layout after the header is handle area (@signHandle first — USER role — then objectHandle, Table 88, no
    //auth), authorization area (a SINGLE password session, for signHandle only — TryReadPasswordAuthArea is
    //reusable exactly as NV_Read's single-session shape is), then parameters (qualifyingData as TPM2B_DATA,
    //creationHash as TPM2B_DIGEST, inScheme as TPMT_SIG_SCHEME, creationTicket as TPMT_TK_CREATION). The ticket's
    //own tag/hierarchy fields are consumed for correct framing but not retained: the transition/effect re-derive
    //the hierarchy from the resolved object's own retained state rather than trust the caller-supplied fields
    //(TPM 2.0 Library Part 3, clause 18.3).
    private static bool TryParseCertifyCreation(ref TpmReader reader, ushort tag, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
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

        uint signHandle = reader.ReadUInt32();
        uint objectHandle = reader.ReadUInt32();

        if(!TryReadPasswordAuthArea(ref reader, out _, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: qualifyingData (TPM2B_DATA) — the caller nonce echoed into the attestation, copied into durable memory.
        if(!TryReadTpm2b(ref reader, out ReadOnlyMemory<byte> qualifyingData, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: creationHash (TPM2B_DIGEST).
        if(!TryReadTpm2b(ref reader, out ReadOnlyMemory<byte> creationHash, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: inScheme (TPMT_SIG_SCHEME) — scheme selector (UINT16) + hash algorithm (UINT16).
        if(reader.Remaining < 2 * sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        var signatureScheme = (TpmAlgIdConstants)reader.ReadUInt16();
        var schemeHashAlg = (TpmAlgIdConstants)reader.ReadUInt16();

        //Parameter: creationTicket (TPMT_TK_CREATION) — tag (UINT16) + hierarchy (UINT32) + digest (TPM2B_DIGEST).
        //Only the digest is retained; the tag/hierarchy fields of a caller-supplied ticket are not trusted.
        if(reader.Remaining < sizeof(ushort) + sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        _ = reader.ReadUInt16();
        _ = reader.ReadUInt32();

        if(!TryReadTpm2b(ref reader, out ReadOnlyMemory<byte> ticketDigest, out malformedResponseCode))
        {
            return false;
        }

        //creationTicket is the final parameter; no octets may follow it (Part 3, 5.2).
        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        input = new TpmCertifyCreationRequested(signHandle, objectHandle, qualifyingData, creationHash, signatureScheme, schemeHashAlg, ticketDigest);

        return true;
    }

    //TPM2_GetTime() is authorized and takes two handles, both requiring authorization: the wire layout after the
    //header is handle area (@privacyAdminHandle — fixed to TPM_RH_ENDORSEMENT — then @signHandle, Table 96),
    //authorization area (two password sessions — an attestation carries no secret, so empty-auth password
    //sessions suffice for both in this slice, mirroring TPM2_Certify()'s TryReadTwoPasswordSessions), then
    //parameters (qualifyingData as TPM2B_DATA, inScheme as TPMT_SIG_SCHEME).
    private static bool TryParseGetTime(ref TpmReader reader, ushort tag, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
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

        uint privacyAdminHandle = reader.ReadUInt32();
        uint signHandle = reader.ReadUInt32();

        if(!TryReadTwoPasswordSessions(ref reader, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: qualifyingData (TPM2B_DATA) — the caller nonce echoed into the attestation, copied into durable memory.
        if(!TryReadTpm2b(ref reader, out ReadOnlyMemory<byte> qualifyingData, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: inScheme (TPMT_SIG_SCHEME) — scheme selector (UINT16) + hash algorithm (UINT16).
        if(reader.Remaining < 2 * sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        var signatureScheme = (TpmAlgIdConstants)reader.ReadUInt16();
        var schemeHashAlg = (TpmAlgIdConstants)reader.ReadUInt16();

        //inScheme is the final parameter; no octets may follow it (Part 3, 5.2).
        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        input = new TpmGetTimeRequested(privacyAdminHandle, signHandle, qualifyingData, signatureScheme, schemeHashAlg);

        return true;
    }

    //TPM2_ClockSet() is authorized by the owner hierarchy, so its wire layout after the header is: handle area
    //(@auth, 1 handle), authorization area (a single password session), then the parameter newTime (UINT64)
    //(Part 3, clause 29.2).
    private static bool TryParseClockSet(ref TpmReader reader, ushort tag, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
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

        if(!TryReadPasswordAuthArea(ref reader, out ReadOnlyMemory<byte> ownerAuth, out malformedResponseCode))
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

        input = new TpmClockSetRequested(authHandle, ownerAuth, newTime);

        return true;
    }

    //TPM2_NV_Certify() is authorized and takes three handles, two of which require authorization: the wire layout
    //after the header is handle area (@signHandle, @authHandle, nvIndex — Table 238), authorization area (two
    //password sessions in handle order — session 1 authorizes signHandle and is not retained, exactly as
    //TPM2_Certify()'s does; session 2 authorizes authHandle and IS retained, for the Index-authValue compare
    //TPM2_NV_Read() performs — so the sessions are read inline via the same primitives
    //TryReadTwoPasswordSessions composes, rather than through that helper, because retention differs per
    //session), then parameters (qualifyingData as TPM2B_DATA, inScheme as TPMT_SIG_SCHEME, size as UINT16, offset
    //as UINT16).
    private static bool TryParseNvCertify(ref TpmReader reader, ushort tag, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
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

        uint signHandle = reader.ReadUInt32();
        uint authHandle = reader.ReadUInt32();
        uint nvIndex = reader.ReadUInt32();

        if(!TryBeginAuthArea(ref reader, out int sessionsStart, out uint authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        //Session 1 authorizes signHandle; not retained (the signing key's own auth is not checked in this
        //slice, mirroring TPM2_Certify()/TPM2_Quote()/TPM2_GetTime()).
        if(!TryReadPasswordSessionBody(ref reader, out _, out malformedResponseCode))
        {
            return false;
        }

        //Session 2 authorizes authHandle; retained for the Index-authValue compare (mirroring TPM2_NV_Read()).
        if(!TryReadPasswordSessionBody(ref reader, out ReadOnlyMemory<byte> authSupplied, out malformedResponseCode))
        {
            return false;
        }

        if(!TryEndAuthArea(ref reader, sessionsStart, authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: qualifyingData (TPM2B_DATA) — the caller nonce echoed into the attestation, copied into durable memory.
        if(!TryReadTpm2b(ref reader, out ReadOnlyMemory<byte> qualifyingData, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: inScheme (TPMT_SIG_SCHEME) — scheme selector (UINT16) + hash algorithm (UINT16).
        if(reader.Remaining < 2 * sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        var signatureScheme = (TpmAlgIdConstants)reader.ReadUInt16();
        var schemeHashAlg = (TpmAlgIdConstants)reader.ReadUInt16();

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

        input = new TpmNvCertifyRequested(signHandle, authHandle, nvIndex, authSupplied, qualifyingData, signatureScheme, schemeHashAlg, size, offset);

        return true;
    }

    //TPM2_VerifySignature() authorizes no entity — keyHandle needs no authorization at all (Part 3, clause 20.1) —
    //so only the no-sessions form is modelled; a sessions tag would carry an authorization area this command has
    //no handle for. Its wire layout after the header is: handle area (@keyHandle, 1 handle), then parameters
    //(digest as TPM2B_DIGEST, signature as TPMT_SIGNATURE: sigAlg selecting the ECDSA r/s TPM2B pair or the single
    //RSA TPM2B signature). Each TPM2B is read through the already bounds-checked TryReadTpm2b, mirroring the
    //command-input parsing convention used throughout this file, rather than the host-side TpmuSignature.Parse
    //(built for trusted response parsing, where an out-of-bounds size throws instead of failing closed).
    private static bool TryParseVerifySignature(ref TpmReader reader, ushort tag, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
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
        if(!TryReadTpm2b(ref reader, out ReadOnlyMemory<byte> digest, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: signature (TPMT_SIGNATURE) — sigAlg (TPMI_ALG_SIG_SCHEME) selects the union member.
        if(reader.Remaining < sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        var sigAlg = (TpmAlgIdConstants)reader.ReadUInt16();
        if(sigAlg is not (TpmAlgIdConstants.TPM_ALG_ECDSA or TpmAlgIdConstants.TPM_ALG_RSASSA or TpmAlgIdConstants.TPM_ALG_RSAPSS))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SCHEME;

            return false;
        }

        if(reader.Remaining < sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        var hashAlg = (TpmAlgIdConstants)reader.ReadUInt16();

        ReadOnlyMemory<byte> signature;
        if(sigAlg == TpmAlgIdConstants.TPM_ALG_ECDSA)
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

        input = new TpmVerifySignatureRequested(keyHandle, digest, sigAlg, hashAlg, signature);

        return true;

        static ReadOnlyMemory<byte> ConcatenateEcdsaSignature(ReadOnlyMemory<byte> r, ReadOnlyMemory<byte> s)
        {
            byte[] concatenated = new byte[r.Length + s.Length];
            r.Span.CopyTo(concatenated);
            s.Span.CopyTo(concatenated.AsSpan(r.Length));

            return concatenated;
        }
    }

    //TPM2_MakeCredential() takes no authorization (it uses only the credential key's public area), so its wire layout
    //after the header is: handle area (@handle — 1 handle, the credential key, no auth), then parameters (credential
    //as TPM2B_DIGEST, objectName as TPM2B_NAME). It is framed with TPM_ST_NO_SESSIONS (TPM 2.0 Library Part 3, clause
    //12.6). The credential and the bound Name are copied into durable model memory.
    private static bool TryParseMakeCredential(ref TpmReader reader, ushort tag, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
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
        if(!TryReadTpm2b(ref reader, out ReadOnlyMemory<byte> credential, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: objectName (TPM2B_NAME) — the Name the credential is bound to (the attestation key's Name).
        if(!TryReadTpm2b(ref reader, out ReadOnlyMemory<byte> objectName, out malformedResponseCode))
        {
            return false;
        }

        //objectName is the final parameter; no octets may follow it (Part 3, 5.2).
        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        input = new TpmMakeCredentialRequested(keyHandle, credential, objectName);

        return true;
    }

    //TPM2_ActivateCredential() is authorized and takes two handles, so its wire layout after the header is: handle
    //area (@activateHandle — the attestation key, ADMIN role; @keyHandle — the credential key, USER role — 2 handles,
    //both require auth), authorization area, then parameters (credentialBlob as TPM2B_ID_OBJECT, secret as
    //TPM2B_ENCRYPTED_SECRET). It is framed with TPM_ST_SESSIONS (TPM 2.0 Library Part 3, clause 12.5). The blob and
    //secret are copied into durable model memory.
    //
    //The authorization area is read inline rather than via TryReadTwoPasswordSessions (still used by
    //TPM2_Certify()): session 1 (@activateHandle, ADMIN role) stays password-only in this slice via
    //TryReadPasswordSessionBody — no template this simulator builds sets adminWithPolicy, so a non-password session
    //there keeps failing TPM_RC_AUTH_TYPE, today's behavior. Session 2 (@keyHandle, USER role) is read generically
    //via TryReadHmacCommandSession, mirroring TryParseUnseal's first session: a standard endorsement key's
    //authPolicy makes TPM_RS_PW insufficient there, so the wire form (not just the transition) must be able to
    //carry a policy session handle. The transition, not the parser, resolves whether that handle names a real
    //policy session and whether it satisfies the key's authPolicy.
    private static bool TryParseActivateCredential(ref TpmReader reader, ushort tag, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
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

        //Session 1 authorizes @activateHandle (ADMIN role); password-only in this slice.
        if(!TryReadPasswordSessionBody(ref reader, out _, out malformedResponseCode))
        {
            return false;
        }

        //Session 2 authorizes @keyHandle (USER role): read generically so a policy session handle parses, then let
        //the transition resolve it (password vs. policy) exactly as Unseal's over-sessions form does.
        if(!TryReadHmacCommandSession(ref reader, out uint keyPolicySession, out _, out byte keyPolicyAttributes, out malformedResponseCode))
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

        input = keyPolicySession == (uint)TpmRh.TPM_RH_PW
            ? new TpmActivateCredentialRequested(activateHandle, keyHandle, credentialBlob, secret)
            : new TpmActivateCredentialOverSessionRequested(activateHandle, keyHandle, credentialBlob, secret, keyPolicySession, keyPolicyAttributes);

        return true;
    }

    //TPM2_PCR_Read() takes no handles and no authorization (Part 3, clause 22.4): its wire body after the header
    //is a single TPML_PCR_SELECTION parameter, and it is framed with TPM_ST_NO_SESSIONS. The selection is captured
    //verbatim (to echo as pcrSelectionOut) and decoded against the PCR bank in the transition.
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

    //TPM2_Quote() is authorized and takes one handle, so its wire layout after the header is: handle area
    //(@signHandle — 1 handle requiring authorization), authorization area (a single password session — a quote is
    //public, so an empty-auth password session suffices), then parameters (qualifyingData as TPM2B_DATA, inScheme
    //as TPMT_SIG_SCHEME, PCRselect as TPML_PCR_SELECTION). The scheme's validation is entirely in the signing
    //scheme selector (TPM 2.0 Library Part 3, clause 18.4).
    private static bool TryParseQuote(ref TpmReader reader, ushort tag, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
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

        uint signHandle = reader.ReadUInt32();

        if(!TryReadPasswordAuthArea(ref reader, out _, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: qualifyingData (TPM2B_DATA) — the caller nonce echoed into the attestation, copied into durable memory.
        if(!TryReadTpm2b(ref reader, out ReadOnlyMemory<byte> qualifyingData, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: inScheme (TPMT_SIG_SCHEME) — scheme selector (UINT16) + hash algorithm (UINT16).
        if(reader.Remaining < 2 * sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        var signatureScheme = (TpmAlgIdConstants)reader.ReadUInt16();
        var schemeHashAlg = (TpmAlgIdConstants)reader.ReadUInt16();

        //Parameter: PCRselect (TPML_PCR_SELECTION) — the final parameter, captured verbatim to echo into the
        //attestation's pcrSelect and decoded (against the PCR bank) in the transition.
        if(!TryReadFinalPcrSelection(ref reader, out ReadOnlyMemory<byte> pcrSelection, out malformedResponseCode))
        {
            return false;
        }

        input = new TpmQuoteRequested(signHandle, qualifyingData, signatureScheme, schemeHashAlg, pcrSelection);

        return true;
    }

    //TPM2_StartAuthSession() is framed with no sessions (Part 3, clause 11.1): its wire body after the header is
    //the handle area (tpmKey, bind) then the parameters (nonceCaller as TPM2B_NONCE, encryptedSalt as
    //TPM2B_ENCRYPTED_SECRET, sessionType as TPM_SE (BYTE), symmetric as TPMT_SYM_DEF, authHash as TPMI_ALG_HASH).
    //A policy or trial session (TPM_SE_POLICY / TPM_SE_TRIAL) needs only sessionType and authHash; a bound HMAC
    //session (TPM_SE_HMAC) additionally needs the bind handle, the nonceCaller (a KDFa context of the session key),
    //and the negotiated symmetric definition, so the two forms dispatch to distinct inputs. This slice is unsalted,
    //so tpmKey and encryptedSalt are consumed for framing but not modelled.
    private static bool TryParseStartAuthSession(ref TpmReader reader, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        //Handle area: tpmKey (unsalted: TPM_RH_NULL) and bind (the entity a bound session binds to, or TPM_RH_NULL).
        if(reader.Remaining < 2 * sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        _ = reader.ReadUInt32();            //tpmKey (unsalted: TPM_RH_NULL).
        uint bind = reader.ReadUInt32();    //bind entity (TPM_RH_NULL when unbound).

        //Parameter: nonceCaller (TPM2B_NONCE) — captured because a bound HMAC session folds it into the session key.
        if(!TryReadTpm2b(ref reader, out ReadOnlyMemory<byte> nonceCaller, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: encryptedSalt (TPM2B_ENCRYPTED_SECRET) — consumed unmodelled (this slice is unsalted).
        if(!TrySkipTpm2b(ref reader, out malformedResponseCode))
        {
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

        var authHash = (TpmAlgIdConstants)reader.ReadUInt16();

        //authHash is the final parameter; no octets may follow it (Part 3, 5.2).
        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        //A bound HMAC session drives parameter encryption; a policy/trial session drives a policyDigest.
        input = sessionType == TpmSeConstants.TPM_SE_HMAC
            ? new TpmStartHmacSessionRequested(bind, nonceCaller, symmetric, authHash)
            : new TpmStartAuthSessionRequested(sessionType, authHash);

        return true;
    }

    //TPM2_GetRandom() over a bound HMAC session (Part 3, clause 16.1) is framed with an authorization area: after
    //the header (GetRandom has no command handles) come authorizationSize (UINT32), one TPMS_AUTH_COMMAND, then the
    //bytesRequested (UINT16) parameter. The session's command HMAC is consumed but not verified — GetRandom
    //authorizes no entity, so its command-side integrity is not the property under test; the response HMAC and the
    //parameter encryption of the response are (Part 1, clauses 18.7 and 19).
    private static bool TryParseGetRandomOverSession(ref TpmReader reader, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(!TryBeginAuthArea(ref reader, out int sessionsStart, out uint authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        if(!TryReadHmacCommandSession(ref reader, out uint sessionHandle, out ReadOnlyMemory<byte> nonceCaller, out byte sessionAttributes, out malformedResponseCode))
        {
            return false;
        }

        if(!TryEndAuthArea(ref reader, sessionsStart, authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: bytesRequested (UINT16).
        if(reader.Remaining < sizeof(ushort))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        ushort bytesRequested = reader.ReadUInt16();

        //bytesRequested is the final parameter; no octets may follow it (Part 3, 5.2).
        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        input = new TpmGetRandomOverSessionRequested(sessionHandle, nonceCaller, sessionAttributes, bytesRequested);

        return true;
    }

    //Reads one TPMS_AUTH_COMMAND for an HMAC session — sessionHandle (UINT32) + nonceCaller (TPM2B, captured) +
    //sessionAttributes (BYTE, captured) + hmac (TPM2B, consumed). The caller nonce and attributes drive the
    //response path; the command HMAC is not verified here (see TryParseGetRandomOverSession).
    private static bool TryReadHmacCommandSession(
        ref TpmReader reader, out uint sessionHandle, out ReadOnlyMemory<byte> nonceCaller, out byte sessionAttributes, out TpmRcConstants malformedResponseCode)
    {
        sessionHandle = 0;
        nonceCaller = ReadOnlyMemory<byte>.Empty;
        sessionAttributes = 0;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(reader.Remaining < sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        sessionHandle = reader.ReadUInt32();

        if(!TryReadTpm2b(ref reader, out nonceCaller, out malformedResponseCode))
        {
            return false;
        }

        if(reader.Remaining < sizeof(byte))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        sessionAttributes = reader.ReadByte();

        return TrySkipTpm2b(ref reader, out malformedResponseCode);
    }

    //TPM2_PolicyCommandCode() carries the policy session as a command handle with no authorization (Part 3, clause
    //23.4): handle area (policySession), then the parameter code (TPM_CC). Framed with no sessions.
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

        input = new TpmPolicyCommandCodeRequested(policySession, code);

        return true;
    }

    //TPM2_PolicyAuthValue() carries only the policy session command handle with no parameters (Part 3, clause
    //23.18). Framed with no sessions.
    private static bool TryParsePolicyAuthValue(ref TpmReader reader, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        if(!TryReadPolicySessionOnly(ref reader, out uint policySession, out malformedResponseCode))
        {
            input = null;

            return false;
        }

        input = new TpmPolicyAuthValueRequested(policySession);

        return true;
    }

    //TPM2_PolicyGetDigest() carries only the policy session command handle with no parameters (Part 3, clause
    //23.6). Framed with no sessions.
    private static bool TryParsePolicyGetDigest(ref TpmReader reader, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        if(!TryReadPolicySessionOnly(ref reader, out uint policySession, out malformedResponseCode))
        {
            input = null;

            return false;
        }

        input = new TpmPolicyGetDigestRequested(policySession);

        return true;
    }

    //Reads the single policy-session command handle of a parameterless policy command and confirms nothing follows.
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

    //TPM2_PolicyPCR() carries the policy session command handle then the parameters pcrDigest (TPM2B_DIGEST) and
    //pcrs (TPML_PCR_SELECTION, the final parameter, captured verbatim to fold into the policyDigest) (Part 3, clause
    //23.7). Framed with no sessions.
    private static bool TryParsePolicyPcr(ref TpmReader reader, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
    {
        input = null;

        if(reader.Remaining < sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint policySession = reader.ReadUInt32();

        //Parameter: pcrDigest (TPM2B_DIGEST) — the expected PCR digest, copied into durable model memory.
        if(!TryReadTpm2b(ref reader, out ReadOnlyMemory<byte> pcrDigest, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: pcrs (TPML_PCR_SELECTION) — captured verbatim so it folds into the policyDigest exactly as sent.
        if(!TryReadFinalPcrSelection(ref reader, out ReadOnlyMemory<byte> pcrSelection, out malformedResponseCode))
        {
            return false;
        }

        input = new TpmPolicyPcrRequested(policySession, pcrDigest, pcrSelection);

        return true;
    }

    //TPM2_PolicyOR() carries the policy session command handle then the parameter pHashList (TPML_DIGEST: a UINT32
    //count followed by that many TPM2B digests, the final parameter) (Part 3, clause 23.6). Framed with no sessions.
    //The branch count is bounded by the remaining octets — each branch needs at least a 2-byte size prefix — so a
    //malformed count runs out of input rather than over-allocating.
    private static bool TryParsePolicyOr(ref TpmReader reader, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
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
            if(!TryReadTpm2b(ref reader, out ReadOnlyMemory<byte> branch, out malformedResponseCode))
            {
                return false;
            }

            branches.Add(branch);
        }

        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        input = new TpmPolicyOrRequested(policySession, branches.ToImmutable());

        return true;
    }

    //TPM2_PolicySecret() is authorized on the entity being consulted, so its wire layout after the header is: handle
    //area (authHandle, policySession — only authHandle requires authorization), authorization area (a single
    //password session), then parameters (nonceTPM as TPM2B_NONCE, cpHashA as TPM2B_DIGEST, policyRef as TPM2B_NONCE,
    //expiration as INT32). The immediate form sends the three TPM2B values empty and expiration zero; all are
    //consumed for framing (Part 3, clause 23.4).
    private static bool TryParsePolicySecret(ref TpmReader reader, ushort tag, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
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

        if(!TryReadPasswordAuthArea(ref reader, out _, out malformedResponseCode))
        {
            return false;
        }

        //Parameters: nonceTPM (TPM2B_NONCE), cpHashA (TPM2B_DIGEST), policyRef (TPM2B_NONCE) — all empty here.
        if(!TrySkipTpm2b(ref reader, out malformedResponseCode)
            || !TrySkipTpm2b(ref reader, out malformedResponseCode)
            || !TrySkipTpm2b(ref reader, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: expiration (INT32) — zero in this immediate form (no ticket produced).
        if(reader.Remaining < sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        _ = reader.ReadUInt32();

        if(reader.Remaining != 0)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_SIZE;

            return false;
        }

        input = new TpmPolicySecretRequested(authHandle, policySession);

        return true;
    }

    //TPM2_PolicyNV() is authorized on the entity used to read the Index, so its wire layout after the header is:
    //handle area (authHandle, nvIndex, policySession — only authHandle requires authorization), authorization area
    //(a single password session), then parameters (operandB as TPM2B_OPERAND, offset as UINT16, operation as
    //TPM_EO) (Part 3, clause 23.9).
    private static bool TryParsePolicyNv(ref TpmReader reader, ushort tag, [NotNullWhen(true)] out TpmSimulatorInput? input, out TpmRcConstants malformedResponseCode)
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

        if(!TryReadPasswordAuthArea(ref reader, out _, out malformedResponseCode))
        {
            return false;
        }

        //Parameter: operandB (TPM2B_OPERAND) — the comparison operand, copied into durable model memory.
        if(!TryReadTpm2b(ref reader, out ReadOnlyMemory<byte> operandB, out malformedResponseCode))
        {
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

        input = new TpmPolicyNvRequested(authHandle, nvIndex, policySession, operandB, offset, operation);

        return true;
    }

    //TPM2_FlushContext() takes no handles and no authorization (Part 3, clause 28.4): its wire body after the header
    //is a single flushHandle (TPMI_DH_CONTEXT) parameter, framed with no sessions.
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

        input = new TpmFlushContextRequested(flushHandle);

        return true;
    }

    //Reads a TPML_PCR_SELECTION that is the command's final parameter, capturing its exact wire bytes (so they can
    //be echoed into the attestation / the PCR_Read response and decoded against the bank) and validating its
    //structure. Any octets after the selection are malformed (Part 3, 5.2).
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

    //Skips a TPML_PCR_SELECTION (UINT32 count + count selections of UINT16 hash + BYTE sizeofSelect + select).
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
            if(reader.Remaining < sizeofSelect)
            {
                malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

                return false;
            }

            reader.Skip(sizeofSelect);
        }

        return true;
    }

    //Reads a command authorization area carrying a single password session and yields the supplied
    //authorization value (the hmac field, which for a TPM_RS_PW session is the plaintext authValue).
    //Only password sessions are modelled this slice: HMAC and policy sessions arrive later.
    private static bool TryReadPasswordAuthArea(ref TpmReader reader, out ReadOnlyMemory<byte> suppliedAuth, out TpmRcConstants malformedResponseCode)
    {
        suppliedAuth = ReadOnlyMemory<byte>.Empty;

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

    //Reads a command authorization area carrying exactly two password sessions in handle order — the two
    //authorizations TPM2_Certify requires (the certified object, ADMIN role, then the signing key, USER role).
    //The supplied authorization values are not retained: the objects this slice certifies carry empty auth, so
    //the sessions are consumed for correct framing.
    private static bool TryReadTwoPasswordSessions(ref TpmReader reader, out TpmRcConstants malformedResponseCode)
    {
        if(!TryBeginAuthArea(ref reader, out int sessionsStart, out uint authorizationSize, out malformedResponseCode))
        {
            return false;
        }

        if(!TryReadPasswordSessionBody(ref reader, out _, out malformedResponseCode)
            || !TryReadPasswordSessionBody(ref reader, out _, out malformedResponseCode))
        {
            return false;
        }

        return TryEndAuthArea(ref reader, sessionsStart, authorizationSize, out malformedResponseCode);
    }

    //Reads the authorizationSize (UINT32) field that opens an authorization area and marks where the sessions
    //begin, so the caller can confirm the sessions account for exactly the declared octets.
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

    //Confirms the sessions consumed exactly the declared authorization octets; any surplus means additional or
    //oversized sessions this slice's fixed session count does not model.
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

    //Reads one TPMS_AUTH_COMMAND password session — sessionHandle (UINT32, must be TPM_RS_PW) + nonceCaller
    //(TPM2B) + sessionAttributes (BYTE) + hmac (TPM2B) — and yields the supplied authorization value (the hmac
    //field, which for a TPM_RS_PW session is the plaintext authValue).
    private static bool TryReadPasswordSessionBody(ref TpmReader reader, out ReadOnlyMemory<byte> suppliedAuth, out TpmRcConstants malformedResponseCode)
    {
        suppliedAuth = ReadOnlyMemory<byte>.Empty;
        malformedResponseCode = TpmRcConstants.TPM_RC_SUCCESS;

        if(reader.Remaining < sizeof(uint))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        uint sessionHandle = reader.ReadUInt32();
        if(sessionHandle != (uint)TpmRh.TPM_RH_PW)
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_AUTH_TYPE;

            return false;
        }

        if(!TrySkipTpm2b(ref reader, out malformedResponseCode))
        {
            return false;
        }

        if(reader.Remaining < sizeof(byte))
        {
            malformedResponseCode = TpmRcConstants.TPM_RC_INSUFFICIENT;

            return false;
        }

        _ = reader.ReadByte();

        return TryReadTpm2b(ref reader, out suppliedAuth, out malformedResponseCode);
    }

    //Reads a TPM2B (UINT16 size prefix + octets) and copies the octets into durable model memory.
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

    //Skips a TPM2B (UINT16 size prefix + octets) without copying — used for fields the model does not retain.
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
    private static TpmResult<TpmResponse> SerializeResponse(TpmResponseIntent intent, MemoryPool<byte> pool)
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

        //The TpmRandomResponse intent is the terminal owner of the RNG buffer rented by the action
        //executor; release it in the finally regardless of how framing completes (its octets are
        //copied into the framed TPM2B_DIGEST on the success path).
        IMemoryOwner<byte>? randomBuffer = (intent as TpmRandomResponse)?.RandomBytes;
        TpmsCapabilityData? capabilityData = (intent as TpmCapabilityResponse)?.CapabilityData;

        //The CreatePrimary and Sign intents are the terminal owners of the exported public area, the pre-framed
        //creation by-products buffer, and the signature; release them in the finally once their octets are framed.
        Tpm2bPublic? createdPublic = (intent as TpmCreatePrimaryResponse)?.OutPublic;
        IMemoryOwner<byte>? createdByProducts = (intent as TpmCreatePrimaryResponse)?.CreationByProducts;
        Signature? signatureValue = (intent as TpmSignResponse)?.Signature;

        //The Create (seal) and Load intents own the wrapped blob, the sealed object's public area, its by-products,
        //and the object Name; release them in the finally once framed. The Unseal intent's octets are durable model
        //memory owned by the loaded object, so nothing is disposed for it.
        IMemoryOwner<byte>? sealedPrivate = (intent as TpmCreateResponse)?.PrivateBlob;
        Tpm2bPublic? sealedPublic = (intent as TpmCreateResponse)?.OutPublic;
        IMemoryOwner<byte>? sealedByProducts = (intent as TpmCreateResponse)?.CreationByProducts;
        IMemoryOwner<byte>? loadedName = (intent as TpmLoadResponse)?.Name;

        //The Certify intent owns the marshaled attest buffer and the signature; release them in the finally once
        //the TPM2B_ATTEST and TPMT_SIGNATURE are framed.
        IMemoryOwner<byte>? certifyInfoBuffer = (intent as TpmCertifyResponse)?.CertifyInfo;
        Signature? certifySignature = (intent as TpmCertifyResponse)?.Signature;

        //The CertifyCreation, GetTime, and NV_Certify intents likewise own their marshaled attest buffer and
        //signature; release them in the finally once framed.
        IMemoryOwner<byte>? certifyCreationInfoBuffer = (intent as TpmCertifyCreationResponse)?.CertifyInfo;
        Signature? certifyCreationSignature = (intent as TpmCertifyCreationResponse)?.Signature;
        IMemoryOwner<byte>? timeInfoBuffer = (intent as TpmGetTimeResponse)?.TimeInfo;
        Signature? timeSignature = (intent as TpmGetTimeResponse)?.Signature;
        IMemoryOwner<byte>? nvCertifyInfoBuffer = (intent as TpmNvCertifyResponse)?.CertifyInfo;
        Signature? nvCertifySignature = (intent as TpmNvCertifyResponse)?.Signature;

        //The VerifySignature intent owns only the ticket-digest buffer — no attest, no signature (unlike every
        //other attest-family intent above).
        IMemoryOwner<byte>? verifySignatureTicketDigest = (intent as TpmVerifySignatureResponse)?.TicketDigest;

        //The Quote intent likewise owns the marshaled attest buffer and the signature; release them in the finally
        //once framed. The PCR_Read intent's octets are the echoed selection and references into durable bank state,
        //so nothing is disposed for it.
        IMemoryOwner<byte>? quotedBuffer = (intent as TpmQuoteResponse)?.Quoted;
        Signature? quoteSignature = (intent as TpmQuoteResponse)?.Signature;

        //The MakeCredential intent owns the credential-blob and secret buffers (both public); release them in the
        //finally once framed. The ActivateCredential intent owns the recovered credential secret — confidential, so
        //it is zeroed before disposal (the clear-before-dispose discipline used for the decrypted response parameter).
        IMemoryOwner<byte>? credentialBlobBuffer = (intent as TpmMakeCredentialResponse)?.CredentialBlob;
        IMemoryOwner<byte>? credentialSecretBuffer = (intent as TpmMakeCredentialResponse)?.Secret;
        TpmActivateCredentialResponse? activatedCredential = intent as TpmActivateCredentialResponse;
        try
        {
            int parameterSize = intent switch
            {
                TpmTestResultResponse { ResponseCode: TpmRcConstants.TPM_RC_SUCCESS } => sizeof(ushort) + sizeof(uint),
                TpmRandomResponse random => sizeof(ushort) + random.Length,
                TpmCapabilityResponse capabilityResponse => sizeof(byte) + capabilityResponse.CapabilityData.GetSerializedSize(),

                //objectHandle + outPublic + the pre-framed creationData ‖ creationHash ‖ creationTicket ‖ name.
                TpmCreatePrimaryResponse createPrimary =>
                    sizeof(uint) + createPrimary.OutPublic.GetSerializedSize() + createPrimary.CreationByProductsLength,

                //ECDSA: sigAlg + hash + r (TPM2B) + s (TPM2B), r and s splitting the IEEE P1363 signature at its
                //half. RSA: sigAlg + hash + sig (one TPM2B). The signature octets are the remaining length.
                TpmSignResponse sign => sign.SignatureScheme == TpmAlgIdConstants.TPM_ALG_ECDSA
                    ? (4 * sizeof(ushort)) + sign.Signature.Length
                    : (3 * sizeof(ushort)) + sign.Signature.Length,

                //outPrivate (TPM2B_PRIVATE) + outPublic + the pre-framed creationData ‖ creationHash ‖ creationTicket.
                TpmCreateResponse createObject =>
                    (sizeof(ushort) + createObject.PrivateBlobLength) + createObject.OutPublic.GetSerializedSize() + createObject.CreationByProductsLength,

                //objectHandle + name (TPM2B_NAME).
                TpmLoadResponse load => sizeof(uint) + (sizeof(ushort) + load.NameLength),

                //outData (TPM2B_SENSITIVE_DATA) carrying the recovered sealed octets.
                TpmUnsealResponse unseal => sizeof(ushort) + unseal.OutData.Length,

                //data (TPM2B_MAX_NV_BUFFER) carrying the octets read from the NV Index.
                TpmNvReadDataResponse nvReadData => sizeof(ushort) + nvReadData.Data.Length,

                //certifyInfo (TPM2B_ATTEST) + signature (TPMT_SIGNATURE): sigAlg + hash + either the ECDSA r/s
                //TPM2B pair or the single RSA TPM2B signature (the same framing TPM2_Sign() uses).
                TpmCertifyResponse certify =>
                    (sizeof(ushort) + certify.CertifyInfoLength)
                    + (certify.SignatureScheme == TpmAlgIdConstants.TPM_ALG_ECDSA ? (4 * sizeof(ushort)) : (3 * sizeof(ushort)))
                    + certify.Signature.Length,

                //certifyInfo (TPM2B_ATTEST) + signature (TPMT_SIGNATURE), the same shape as TpmCertifyResponse.
                TpmCertifyCreationResponse certifyCreation =>
                    (sizeof(ushort) + certifyCreation.CertifyInfoLength)
                    + (certifyCreation.SignatureScheme == TpmAlgIdConstants.TPM_ALG_ECDSA ? (4 * sizeof(ushort)) : (3 * sizeof(ushort)))
                    + certifyCreation.Signature.Length,

                //timeInfo (TPM2B_ATTEST) + signature (TPMT_SIGNATURE), the same shape as TpmCertifyResponse.
                TpmGetTimeResponse getTime =>
                    (sizeof(ushort) + getTime.TimeInfoLength)
                    + (getTime.SignatureScheme == TpmAlgIdConstants.TPM_ALG_ECDSA ? (4 * sizeof(ushort)) : (3 * sizeof(ushort)))
                    + getTime.Signature.Length,

                //certifyInfo (TPM2B_ATTEST) + signature (TPMT_SIGNATURE), the same shape as TpmCertifyResponse.
                TpmNvCertifyResponse nvCertify =>
                    (sizeof(ushort) + nvCertify.CertifyInfoLength)
                    + (nvCertify.SignatureScheme == TpmAlgIdConstants.TPM_ALG_ECDSA ? (4 * sizeof(ushort)) : (3 * sizeof(ushort)))
                    + nvCertify.Signature.Length,

                //validation (TPMT_TK_VERIFIED): tag (UINT16) + hierarchy (UINT32) + digest (TPM2B_DIGEST) — no
                //attest and no signature, unlike every other attest-family response above.
                TpmVerifySignatureResponse verifySignature =>
                    sizeof(ushort) + sizeof(uint) + (sizeof(ushort) + verifySignature.TicketDigestLength),

                //currentTime (TPMS_TIME_INFO, fixed layout): the uncertified Time/Clock/resetCount/restartCount/Safe snapshot.
                TpmReadClockResponse => TpmsTimeInfo.SerializedSize,

                //pcrUpdateCounter (UINT32) + pcrSelectionOut (TPML_PCR_SELECTION echoed) + pcrValues (TPML_DIGEST).
                TpmPcrReadResponse pcrRead =>
                    sizeof(uint) + pcrRead.SelectionBytes.Length + PcrValuesSerializedSize(pcrRead.PcrValues),

                //quoted (TPM2B_ATTEST) + signature (TPMT_SIGNATURE): sigAlg + hash + either the ECDSA r/s
                //TPM2B pair or the single RSA TPM2B signature (the same framing TPM2_Sign() uses).
                TpmQuoteResponse quote =>
                    (sizeof(ushort) + quote.QuotedLength)
                    + (quote.SignatureScheme == TpmAlgIdConstants.TPM_ALG_ECDSA ? (4 * sizeof(ushort)) : (3 * sizeof(ushort)))
                    + quote.Signature.Length,

                //sessionHandle (response handle) + nonceTPM (TPM2B_NONCE of the policy-hash width).
                TpmStartAuthSessionResponse startAuthSession =>
                    sizeof(uint) + (sizeof(ushort) + startAuthSession.NonceLength),

                //policyDigest (TPM2B_DIGEST): the session's accumulated digest.
                TpmPolicyGetDigestResponse policyGetDigest =>
                    sizeof(ushort) + policyGetDigest.PolicyDigest.Length,

                //timeout (empty TPM2B_TIMEOUT) + policyTicket (TPMT_TK_AUTH: tag + hierarchy + empty digest).
                TpmPolicySecretResponse =>
                    sizeof(ushort) + (sizeof(ushort) + sizeof(uint) + sizeof(ushort)),

                //credentialBlob (TPM2B_ID_OBJECT) + secret (TPM2B_ENCRYPTED_SECRET).
                TpmMakeCredentialResponse makeCredential =>
                    (sizeof(ushort) + makeCredential.CredentialBlobLength) + (sizeof(ushort) + makeCredential.SecretLength),

                //certInfo (TPM2B_DIGEST): the recovered credential secret.
                TpmActivateCredentialResponse activateCredential =>
                    sizeof(ushort) + activateCredential.CertInfoLength,

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
                        writer.WriteTpm2b(randomResponse.RandomBytes.Memory.Span[..randomResponse.Length]);

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
                        writer.WriteUInt32(createPrimaryResponse.ObjectHandle);

                        //outPublic (TPM2B_PUBLIC) carrying the generated point.
                        createPrimaryResponse.OutPublic.WriteTo(ref writer);

                        //creationData ‖ creationHash ‖ creationTicket ‖ name, computed faithfully and pre-framed
                        //by the effectful loop (the Name, creation hash, and ticket need the registered digest
                        //and HMAC seams, which are asynchronous).
                        writer.WriteBytes(createPrimaryResponse.CreationByProducts.Memory.Span[..createPrimaryResponse.CreationByProductsLength]);

                        break;
                    }
                    case TpmSignResponse signResponse:
                    {
                        ReadOnlySpan<byte> signatureBytes = signResponse.Signature.AsReadOnlySpan();

                        writer.WriteUInt16((ushort)signResponse.SignatureScheme);  //sigAlg: the TPMU_SIGNATURE selector.
                        writer.WriteUInt16((ushort)signResponse.HashAlg);          //hash inside the signature member.

                        if(signResponse.SignatureScheme == TpmAlgIdConstants.TPM_ALG_ECDSA)
                        {
                            //TPMS_SIGNATURE_ECDSA: r and s are the equal-width halves of the IEEE P1363 signature
                            //(each the curve field width), so its length is even and the split at the midpoint is
                            //exact. An odd length would mean the backend did not return canonical P1363 r ‖ s.
                            if((signatureBytes.Length & 1) != 0)
                            {
                                throw new InvalidOperationException(
                                    $"An ECDSA signature must be IEEE P1363 r ‖ s of even length so r and s are equal width; got {signatureBytes.Length} octets.");
                            }

                            int fieldWidth = signatureBytes.Length / 2;
                            writer.WriteTpm2b(signatureBytes[..fieldWidth]);       //signatureR (TPM2B_ECC_PARAMETER).
                            writer.WriteTpm2b(signatureBytes[fieldWidth..]);      //signatureS (TPM2B_ECC_PARAMETER).
                        }
                        else
                        {
                            //TPMS_SIGNATURE_RSA: the whole signature as one TPM2B_PUBLIC_KEY_RSA.
                            writer.WriteTpm2b(signatureBytes);
                        }

                        break;
                    }
                    case TpmCreateResponse createObjectResponse:
                    {
                        //outPrivate (TPM2B_PRIVATE): the wrapped blob carrying the sealed data.
                        writer.WriteTpm2b(createObjectResponse.PrivateBlob.Memory.Span[..createObjectResponse.PrivateBlobLength]);

                        //outPublic (TPM2B_PUBLIC): the sealed object's public area.
                        createObjectResponse.OutPublic.WriteTo(ref writer);

                        //creationData ‖ creationHash ‖ creationTicket (no Name — TPM2_Create() returns none), pre-framed by the effect.
                        writer.WriteBytes(createObjectResponse.CreationByProducts.Memory.Span[..createObjectResponse.CreationByProductsLength]);

                        break;
                    }
                    case TpmLoadResponse loadResponse:
                    {
                        //objectHandle (the response handle area).
                        writer.WriteUInt32(loadResponse.ObjectHandle);

                        //name (TPM2B_NAME): the loaded object's Name.
                        writer.WriteTpm2b(loadResponse.Name.Memory.Span[..loadResponse.NameLength]);

                        break;
                    }
                    case TpmUnsealResponse unsealResponse:
                    {
                        //outData (TPM2B_SENSITIVE_DATA): the recovered sealed data.
                        writer.WriteTpm2b(unsealResponse.OutData.Span);

                        break;
                    }
                    case TpmNvReadDataResponse nvReadDataResponse:
                    {
                        //data (TPM2B_MAX_NV_BUFFER): the octets read from the NV Index.
                        writer.WriteTpm2b(nvReadDataResponse.Data.Span);

                        break;
                    }
                    case TpmCertifyResponse certifyResponse:
                    {
                        //certifyInfo (TPM2B_ATTEST): the marshaled TPMS_ATTEST the signature is over.
                        writer.WriteTpm2b(certifyResponse.CertifyInfo.Memory.Span[..certifyResponse.CertifyInfoLength]);

                        //signature (TPMT_SIGNATURE): sigAlg + hash + either the ECDSA r/s pair or the single RSA
                        //signature, the same framing TPM2_Sign() uses.
                        ReadOnlySpan<byte> certifySignatureBytes = certifyResponse.Signature.AsReadOnlySpan();
                        writer.WriteUInt16((ushort)certifyResponse.SignatureScheme);  //sigAlg: the TPMU_SIGNATURE selector.
                        writer.WriteUInt16((ushort)certifyResponse.HashAlg);          //hash inside the signature member.

                        if(certifyResponse.SignatureScheme == TpmAlgIdConstants.TPM_ALG_ECDSA)
                        {
                            //TPMS_SIGNATURE_ECDSA: r and s are the equal-width halves of the IEEE P1363 signature,
                            //so its length is even and the split at the midpoint is exact. An odd length would
                            //mean the backend did not return canonical P1363 r ‖ s.
                            if((certifySignatureBytes.Length & 1) != 0)
                            {
                                throw new InvalidOperationException(
                                    $"An ECDSA signature must be IEEE P1363 r ‖ s of even length so r and s are equal width; got {certifySignatureBytes.Length} octets.");
                            }

                            int certifyFieldWidth = certifySignatureBytes.Length / 2;
                            writer.WriteTpm2b(certifySignatureBytes[..certifyFieldWidth]);   //signatureR (TPM2B_ECC_PARAMETER).
                            writer.WriteTpm2b(certifySignatureBytes[certifyFieldWidth..]);   //signatureS (TPM2B_ECC_PARAMETER).
                        }
                        else
                        {
                            //TPMS_SIGNATURE_RSA: the whole signature as one TPM2B_PUBLIC_KEY_RSA.
                            writer.WriteTpm2b(certifySignatureBytes);
                        }

                        break;
                    }
                    case TpmCertifyCreationResponse certifyCreationResponse:
                    {
                        //certifyInfo (TPM2B_ATTEST): the marshaled TPMS_ATTEST the signature is over.
                        writer.WriteTpm2b(certifyCreationResponse.CertifyInfo.Memory.Span[..certifyCreationResponse.CertifyInfoLength]);

                        //signature (TPMT_SIGNATURE): sigAlg + hash + either the ECDSA r/s pair or the single RSA
                        //signature, the same framing TPM2_Sign() uses.
                        ReadOnlySpan<byte> certifyCreationSignatureBytes = certifyCreationResponse.Signature.AsReadOnlySpan();
                        writer.WriteUInt16((ushort)certifyCreationResponse.SignatureScheme);  //sigAlg: the TPMU_SIGNATURE selector.
                        writer.WriteUInt16((ushort)certifyCreationResponse.HashAlg);          //hash inside the signature member.

                        if(certifyCreationResponse.SignatureScheme == TpmAlgIdConstants.TPM_ALG_ECDSA)
                        {
                            //TPMS_SIGNATURE_ECDSA: r and s are the equal-width halves of the IEEE P1363 signature,
                            //so its length is even and the split at the midpoint is exact. An odd length would
                            //mean the backend did not return canonical P1363 r ‖ s.
                            if((certifyCreationSignatureBytes.Length & 1) != 0)
                            {
                                throw new InvalidOperationException(
                                    $"An ECDSA signature must be IEEE P1363 r ‖ s of even length so r and s are equal width; got {certifyCreationSignatureBytes.Length} octets.");
                            }

                            int certifyCreationFieldWidth = certifyCreationSignatureBytes.Length / 2;
                            writer.WriteTpm2b(certifyCreationSignatureBytes[..certifyCreationFieldWidth]);   //signatureR (TPM2B_ECC_PARAMETER).
                            writer.WriteTpm2b(certifyCreationSignatureBytes[certifyCreationFieldWidth..]);   //signatureS (TPM2B_ECC_PARAMETER).
                        }
                        else
                        {
                            //TPMS_SIGNATURE_RSA: the whole signature as one TPM2B_PUBLIC_KEY_RSA.
                            writer.WriteTpm2b(certifyCreationSignatureBytes);
                        }

                        break;
                    }
                    case TpmGetTimeResponse getTimeResponse:
                    {
                        //timeInfo (TPM2B_ATTEST): the marshaled TPMS_ATTEST the signature is over.
                        writer.WriteTpm2b(getTimeResponse.TimeInfo.Memory.Span[..getTimeResponse.TimeInfoLength]);

                        //signature (TPMT_SIGNATURE): sigAlg + hash + either the ECDSA r/s pair or the single RSA
                        //signature, the same framing TPM2_Sign() uses.
                        ReadOnlySpan<byte> getTimeSignatureBytes = getTimeResponse.Signature.AsReadOnlySpan();
                        writer.WriteUInt16((ushort)getTimeResponse.SignatureScheme);  //sigAlg: the TPMU_SIGNATURE selector.
                        writer.WriteUInt16((ushort)getTimeResponse.HashAlg);          //hash inside the signature member.

                        if(getTimeResponse.SignatureScheme == TpmAlgIdConstants.TPM_ALG_ECDSA)
                        {
                            //TPMS_SIGNATURE_ECDSA: r and s are the equal-width halves of the IEEE P1363 signature,
                            //so its length is even and the split at the midpoint is exact. An odd length would
                            //mean the backend did not return canonical P1363 r ‖ s.
                            if((getTimeSignatureBytes.Length & 1) != 0)
                            {
                                throw new InvalidOperationException(
                                    $"An ECDSA signature must be IEEE P1363 r ‖ s of even length so r and s are equal width; got {getTimeSignatureBytes.Length} octets.");
                            }

                            int getTimeFieldWidth = getTimeSignatureBytes.Length / 2;
                            writer.WriteTpm2b(getTimeSignatureBytes[..getTimeFieldWidth]);   //signatureR (TPM2B_ECC_PARAMETER).
                            writer.WriteTpm2b(getTimeSignatureBytes[getTimeFieldWidth..]);   //signatureS (TPM2B_ECC_PARAMETER).
                        }
                        else
                        {
                            //TPMS_SIGNATURE_RSA: the whole signature as one TPM2B_PUBLIC_KEY_RSA.
                            writer.WriteTpm2b(getTimeSignatureBytes);
                        }

                        break;
                    }
                    case TpmNvCertifyResponse nvCertifyResponse:
                    {
                        //certifyInfo (TPM2B_ATTEST): the marshaled TPMS_ATTEST the signature is over.
                        writer.WriteTpm2b(nvCertifyResponse.CertifyInfo.Memory.Span[..nvCertifyResponse.CertifyInfoLength]);

                        //signature (TPMT_SIGNATURE): sigAlg + hash + either the ECDSA r/s pair or the single RSA
                        //signature, the same framing TPM2_Sign() uses.
                        ReadOnlySpan<byte> nvCertifySignatureBytes = nvCertifyResponse.Signature.AsReadOnlySpan();
                        writer.WriteUInt16((ushort)nvCertifyResponse.SignatureScheme);  //sigAlg: the TPMU_SIGNATURE selector.
                        writer.WriteUInt16((ushort)nvCertifyResponse.HashAlg);          //hash inside the signature member.

                        if(nvCertifyResponse.SignatureScheme == TpmAlgIdConstants.TPM_ALG_ECDSA)
                        {
                            //TPMS_SIGNATURE_ECDSA: r and s are the equal-width halves of the IEEE P1363 signature,
                            //so its length is even and the split at the midpoint is exact. An odd length would
                            //mean the backend did not return canonical P1363 r ‖ s.
                            if((nvCertifySignatureBytes.Length & 1) != 0)
                            {
                                throw new InvalidOperationException(
                                    $"An ECDSA signature must be IEEE P1363 r ‖ s of even length so r and s are equal width; got {nvCertifySignatureBytes.Length} octets.");
                            }

                            int nvCertifyFieldWidth = nvCertifySignatureBytes.Length / 2;
                            writer.WriteTpm2b(nvCertifySignatureBytes[..nvCertifyFieldWidth]);   //signatureR (TPM2B_ECC_PARAMETER).
                            writer.WriteTpm2b(nvCertifySignatureBytes[nvCertifyFieldWidth..]);   //signatureS (TPM2B_ECC_PARAMETER).
                        }
                        else
                        {
                            //TPMS_SIGNATURE_RSA: the whole signature as one TPM2B_PUBLIC_KEY_RSA.
                            writer.WriteTpm2b(nvCertifySignatureBytes);
                        }

                        break;
                    }
                    case TpmVerifySignatureResponse verifySignatureResponse:
                    {
                        //validation (TPMT_TK_VERIFIED): tag (TPM_ST_VERIFIED) + hierarchy + digest (TPM2B_DIGEST) —
                        //the HMAC over TPM_ST_VERIFIED || digest || keyName under the verifying key's re-derived
                        //hierarchy proof. No attest, no TPMT_SIGNATURE — the odd one out among the attest-family
                        //responses above.
                        writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_VERIFIED);
                        writer.WriteUInt32(verifySignatureResponse.Hierarchy);
                        writer.WriteTpm2b(verifySignatureResponse.TicketDigest.Memory.Span[..verifySignatureResponse.TicketDigestLength]);

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
                        //quoted (TPM2B_ATTEST): the marshaled TPMS_ATTEST the signature is over.
                        writer.WriteTpm2b(quoteResponse.Quoted.Memory.Span[..quoteResponse.QuotedLength]);

                        //signature (TPMT_SIGNATURE): sigAlg + hash + either the ECDSA r/s pair or the single RSA
                        //signature, the same framing TPM2_Sign() uses.
                        ReadOnlySpan<byte> quoteSignatureBytes = quoteResponse.Signature.AsReadOnlySpan();
                        writer.WriteUInt16((ushort)quoteResponse.SignatureScheme);  //sigAlg: the TPMU_SIGNATURE selector.
                        writer.WriteUInt16((ushort)quoteResponse.HashAlg);          //hash inside the signature member.

                        if(quoteResponse.SignatureScheme == TpmAlgIdConstants.TPM_ALG_ECDSA)
                        {
                            //TPMS_SIGNATURE_ECDSA: r and s are the equal-width halves of the IEEE P1363 signature,
                            //so its length is even and the split at the midpoint is exact. An odd length would
                            //mean the backend did not return canonical P1363 r ‖ s.
                            if((quoteSignatureBytes.Length & 1) != 0)
                            {
                                throw new InvalidOperationException(
                                    $"An ECDSA signature must be IEEE P1363 r ‖ s of even length so r and s are equal width; got {quoteSignatureBytes.Length} octets.");
                            }

                            int quoteFieldWidth = quoteSignatureBytes.Length / 2;
                            writer.WriteTpm2b(quoteSignatureBytes[..quoteFieldWidth]);   //signatureR (TPM2B_ECC_PARAMETER).
                            writer.WriteTpm2b(quoteSignatureBytes[quoteFieldWidth..]);   //signatureS (TPM2B_ECC_PARAMETER).
                        }
                        else
                        {
                            //TPMS_SIGNATURE_RSA: the whole signature as one TPM2B_PUBLIC_KEY_RSA.
                            writer.WriteTpm2b(quoteSignatureBytes);
                        }

                        break;
                    }
                    case TpmStartAuthSessionResponse startAuthSessionResponse:
                    {
                        //sessionHandle (the response handle area).
                        writer.WriteUInt32(startAuthSessionResponse.SessionHandle);

                        //nonceTPM (TPM2B_NONCE). A bound HMAC session supplies the real nonceTPM (the value the
                        //session-key KDFa consumed, which the host must receive verbatim to derive the same key,
                        //Part 3, clause 11.1). A policy/trial session leaves it empty: its nonceTPM value does not
                        //affect the policyDigest the assertions drive, so a fixed zero placeholder of the hash
                        //width suffices and those tests do not inspect it.
                        if(startAuthSessionResponse.NonceTpm.IsEmpty)
                        {
                            Span<byte> nonce = stackalloc byte[startAuthSessionResponse.NonceLength];
                            nonce.Clear();
                            writer.WriteTpm2b(nonce);
                        }
                        else
                        {
                            writer.WriteTpm2b(startAuthSessionResponse.NonceTpm.Span);
                        }

                        break;
                    }
                    case TpmPolicyGetDigestResponse policyGetDigestResponse:
                    {
                        //policyDigest (TPM2B_DIGEST): the session's accumulated policyDigest.
                        writer.WriteTpm2b(policyGetDigestResponse.PolicyDigest.Span);

                        break;
                    }
                    case TpmPolicySecretResponse:
                    {
                        //timeout (TPM2B_TIMEOUT): empty in the immediate (expiration 0) form.
                        writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);

                        //policyTicket (TPMT_TK_AUTH): a NULL PolicySecret authorization ticket — tag
                        //TPM_ST_AUTH_SECRET, NULL hierarchy, empty digest. The immediate form produces no usable
                        //ticket; this is a well-formed placeholder the test does not inspect (Part 3, clause 23.4).
                        writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_AUTH_SECRET);
                        writer.WriteUInt32((uint)TpmRh.TPM_RH_NULL);
                        writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);

                        break;
                    }
                    case TpmMakeCredentialResponse makeCredentialResponse:
                    {
                        //credentialBlob (TPM2B_ID_OBJECT): the integrity-protected, encrypted credential.
                        writer.WriteTpm2b(makeCredentialResponse.CredentialBlob.Memory.Span[..makeCredentialResponse.CredentialBlobLength]);

                        //secret (TPM2B_ENCRYPTED_SECRET): the seed transport (the marshaled ephemeral public point).
                        writer.WriteTpm2b(makeCredentialResponse.Secret.Memory.Span[..makeCredentialResponse.SecretLength]);

                        break;
                    }
                    case TpmActivateCredentialResponse activateCredentialResponse:
                    {
                        //certInfo (TPM2B_DIGEST): the recovered credential secret.
                        writer.WriteTpm2b(activateCredentialResponse.CertInfo.Memory.Span[..activateCredentialResponse.CertInfoLength]);

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
            createdByProducts?.Dispose();
            signatureValue?.Dispose();
            sealedPrivate?.Dispose();
            sealedPublic?.Dispose();
            sealedByProducts?.Dispose();
            loadedName?.Dispose();
            certifyInfoBuffer?.Dispose();
            certifySignature?.Dispose();
            certifyCreationInfoBuffer?.Dispose();
            certifyCreationSignature?.Dispose();
            timeInfoBuffer?.Dispose();
            timeSignature?.Dispose();
            nvCertifyInfoBuffer?.Dispose();
            nvCertifySignature?.Dispose();
            verifySignatureTicketDigest?.Dispose();
            quotedBuffer?.Dispose();
            quoteSignature?.Dispose();
            credentialBlobBuffer?.Dispose();
            credentialSecretBuffer?.Dispose();

            //The recovered credential secret is confidential: zero the framed octets before returning the buffer to
            //the pool, matching the clear-before-dispose discipline used for every recovered value.
            if(activatedCredential is not null)
            {
                activatedCredential.CertInfo.Memory.Span[..activatedCredential.CertInfoLength].Clear();
                activatedCredential.CertInfo.Dispose();
            }
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

    //Frames an encrypt-attributed TPM2_GetRandom() response (TPM 2.0 Library Part 3, clause 16.1; Part 1, clause
    //18.7). Unlike every no-sessions response, this is TPM_ST_SESSIONS-tagged and carries a trailing response
    //session area: after the header (GetRandom has no response handles) come parameterSize (UINT32), the encrypted
    //response parameter area, then TPMS_AUTH_RESPONSE (nonceTPM as TPM2B_NONCE + sessionAttributes (BYTE) + hmac as
    //TPM2B). The parameter-area and HMAC buffers are the terminal owners released here; the parameter area holds
    //the recovered value the encryption protects, so it is zeroed before disposal.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "TpmResponse takes ownership of the rented buffer and is owned by the returned TpmResult, which the caller disposes.")]
    private static TpmResult<TpmResponse> SerializeEncryptedRandomResponse(TpmEncryptedRandomResponse intent, MemoryPool<byte> pool)
    {
        try
        {
            int nonceLength = intent.NonceTpm.Length;
            int authAreaSize =
                (sizeof(ushort) + nonceLength)          //nonceTPM (TPM2B_NONCE).
                + sizeof(byte)                          //sessionAttributes.
                + (sizeof(ushort) + intent.HmacLength); //hmac (TPM2B).

            //parameterSize (UINT32) + the encrypted parameter area + the response session area.
            int parameterSize = intent.ParameterLength;
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
                writer.WriteBytes(intent.ParameterArea.Memory.Span[..parameterSize]);

                //Response session area: nonceTPM, sessionAttributes (echoed and HMAC'd identically), hmac.
                writer.WriteTpm2b(intent.NonceTpm.Span);
                writer.WriteByte(intent.SessionAttributes);
                writer.WriteTpm2b(intent.Hmac.Memory.Span[..intent.HmacLength]);

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
            intent.ParameterArea.Memory.Span[..intent.ParameterLength].Clear();
            intent.ParameterArea.Dispose();
            intent.Hmac.Dispose();
        }
    }

    //Frames a policy-gated TPM2_Unseal() response over two sessions (TPM 2.0 Library Part 3, clause 12.7; Part 1,
    //clause 18.7). Like the encrypt-attributed GetRandom response it is TPM_ST_SESSIONS-tagged, but its response
    //session area carries TWO TPMS_AUTH_RESPONSE entries in command-session order: after the header (Unseal has no
    //response handles) come parameterSize (UINT32), the encrypted outData (TPM2B_SENSITIVE_DATA), then the policy
    //session's entry (a zero nonceTPM of its hash width + echoed sessionAttributes + an EMPTY hmac — a satisfied
    //plain policy session carries no key, so the TPM returns a zero-length response HMAC for it, Part 1, clause 19.6)
    //followed by the encrypt session's entry (its rolled nonceTPM + echoed sessionAttributes + response hmac). The
    //order matches the order the executor parses and verifies the sessions in, so a byte-off in either entry fails
    //the caller's verification. The parameter-area and HMAC buffers are the terminal owners released here; the
    //parameter area holds the recovered secret the encryption protects, so it is zeroed before disposal.
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "TpmResponse takes ownership of the rented buffer and is owned by the returned TpmResult, which the caller disposes.")]
    private static TpmResult<TpmResponse> SerializeUnsealOverSessionsResponse(TpmUnsealOverSessionsResponse intent, MemoryPool<byte> pool)
    {
        try
        {
            //Policy session entry: a zero nonceTPM of the policy hash width, the echoed attributes, and an empty hmac.
            int policyAuthSize =
                (sizeof(ushort) + intent.PolicyNonceLength)     //nonceTPM (TPM2B_NONCE), a zero placeholder.
                + sizeof(byte)                                  //sessionAttributes.
                + sizeof(ushort);                               //hmac (TPM2B, empty — no key).

            //Encrypt session entry: the rolled nonceTPM, the echoed attributes, and the response HMAC.
            int encryptAuthSize =
                (sizeof(ushort) + intent.EncryptNonceTpm.Length) //nonceTPM (TPM2B_NONCE).
                + sizeof(byte)                                   //sessionAttributes.
                + (sizeof(ushort) + intent.HmacLength);          //hmac (TPM2B).

            int authAreaSize = policyAuthSize + encryptAuthSize;

            //parameterSize (UINT32) + the encrypted parameter area + the two-entry response session area.
            int parameterSize = intent.ParameterLength;
            int total = TpmHeader.HeaderSize + sizeof(uint) + parameterSize + authAreaSize;

            IMemoryOwner<byte> owner = pool.Rent(total);
            try
            {
                var writer = new TpmWriter(owner.Memory.Span[..total]);

                //Header carries the sessions tag so the caller parses the response session area (Part 1, clause 18).
                var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)total, (uint)intent.ResponseCode);
                header.WriteTo(ref writer);

                //parameterSize then the encrypted outData (its TPM2B size field is the unprotected count). Unseal
                //returns no response handle, so the parameter area follows the header directly (Part 3, clause 12.7).
                writer.WriteUInt32((uint)parameterSize);
                writer.WriteBytes(intent.ParameterArea.Memory.Span[..parameterSize]);

                //Response session area, in command-session order. Policy session first (the authorizing session,
                //supplied first): a zero nonce, echoed attributes, an empty HMAC.
                Span<byte> policyNonce = stackalloc byte[intent.PolicyNonceLength];
                policyNonce.Clear();
                writer.WriteTpm2b(policyNonce);
                writer.WriteByte(intent.PolicyAttributes);
                writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);

                //Encrypt session second: the rolled nonceTPM (nonceNewer), echoed attributes (HMAC'd identically),
                //and the response HMAC.
                writer.WriteTpm2b(intent.EncryptNonceTpm.Span);
                writer.WriteByte(intent.EncryptAttributes);
                writer.WriteTpm2b(intent.Hmac.Memory.Span[..intent.HmacLength]);

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
            intent.ParameterArea.Memory.Span[..intent.ParameterLength].Clear();
            intent.ParameterArea.Dispose();
            intent.Hmac.Dispose();
        }
    }
}
