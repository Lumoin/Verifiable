using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Counter;
using Verifiable.Tpm.Extensions.DictionaryAttack;
using Verifiable.Tpm.Extensions.Hierarchy;
using Verifiable.Tpm.Extensions.Info;
using Verifiable.Tpm.Extensions.Nv;
using Verifiable.Tpm.Extensions.Pcr;
using Verifiable.Tpm.Extensions.Pin;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Extensions.Seal;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tests.TestInfrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Proves the pool-custody contract every <c>Extensions</c> business-capability verb shares: a verb's command and
/// response buffers come from the <see cref="TpmDevice"/> it was called on — <see cref="TpmDevice.Pool"/> — never
/// from an untracked default the verb reaches for on its own. One representative verb per Extensions family is run
/// end to end against the in-house behavioural <see cref="TpmSimulator"/>, with the device constructed over a
/// <see cref="MeteredHousePool"/>: the verb's own success proves it ran the real command, the pool's rent counter
/// rising above zero proves the rentals actually reached the pool under observation (a verb pulling from a hidden
/// default would leave that counter at zero), and the pool's outstanding count returning to zero once every
/// returned carrier is disposed proves nothing escaped it.
/// </summary>
/// <remarks>
/// The in-house <see cref="TpmSimulator"/> models <c>TPM2_GetCapability</c> only for
/// <c>TPM_CAP_TPM_PROPERTIES</c> (TPM 2.0 Library Part 2, clause 10.8.7); every other capability category is
/// deliberately answered <c>TPM_RC_VALUE</c>. The Info and Pcr families' verbs each query an unmodelled
/// category (<c>TPM_CAP_ALGS</c>, <c>TPM_CAP_PCRS</c>) as part of their own composition, so
/// <see cref="InterceptUnmodelledCapabilities"/> answers just those two categories with a canned, empty-list
/// success response and forwards every other command to the simulator unchanged — the pool-custody proof
/// still runs the verb's real composition and the real simulator for everything the simulator implements.
/// </remarks>
[TestClass]
internal sealed class TpmDeviceExtensionsPoolCustodyTests
{
    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// The Info family's verb (<see cref="TpmDeviceExtensions.GetInfoAsync"/>, composing
    /// <c>TPM2_GetCapability</c> and the PCR-read verb internally) rents its scratch buffers from the device's
    /// own pool.
    /// </summary>
    [TestMethod]
    public async Task GetInfoAsyncRentsFromTheDevicesOwnPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(
            InterceptUnmodelledCapabilities(simulator.SubmitAsync), trackingPool.Pool, TestEntropy.NewCounterStream());

        TpmResult<TpmInfo> result = await device.GetInfoAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"GetInfoAsync failed: '{result.ResponseCode}'.");
        Assert.IsGreaterThan(0L, trackingPool.RentedCount, "GetInfoAsync must rent its command and response buffers from the device's own pool.");
        Assert.AreEqual(0L, trackingPool.OutstandingCount, "Every carrier GetInfoAsync rents must be returned once the call completes.");
    }

    /// <summary>
    /// The Pcr family's verb (<see cref="TpmDeviceExtensions.ReadAllPcrsAsync"/>, composing
    /// <c>TPM2_PCR_Read</c> across every implemented bank) rents its scratch buffers from the device's own pool.
    /// </summary>
    [TestMethod]
    public async Task ReadAllPcrsAsyncRentsFromTheDevicesOwnPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(
            InterceptUnmodelledCapabilities(simulator.SubmitAsync), trackingPool.Pool, TestEntropy.NewCounterStream());

        TpmResult<PcrSnapshot> result = await device.ReadAllPcrsAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"ReadAllPcrsAsync failed: '{result.ResponseCode}'.");
        Assert.IsGreaterThan(0L, trackingPool.RentedCount, "ReadAllPcrsAsync must rent its command and response buffers from the device's own pool.");
        Assert.AreEqual(0L, trackingPool.OutstandingCount, "Every carrier ReadAllPcrsAsync rents must be returned once the call completes.");
    }

    /// <summary>
    /// The Nv family's verb (<see cref="TpmDeviceExtensions.NvReadPublicAsync"/>, composing
    /// <c>TPM2_NV_ReadPublic</c>) rents its scratch buffers from the device's own pool. The Counter family's own
    /// define and undefine verbs provision and release the Index read back — an Index's stored public area is
    /// live simulator state for as long as it is defined, so the balance is read after the whole
    /// define-read-undefine lifecycle, not around the read call alone.
    /// </summary>
    [TestMethod]
    public async Task NvReadPublicAsyncRentsFromTheDevicesOwnPool()
    {
        const uint NvIndexHandle = 0x0100_0091;
        byte[] indexAuth = [0x11, 0x22, 0x33, 0x44];

        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, trackingPool.Pool, TestEntropy.NewCounterStream());

        TpmResult<NvDefineSpaceResponse> defineResult = await device.DefineCounterAsync(
            ReadOnlyMemory<byte>.Empty, NvIndexHandle, indexAuth, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"DefineCounterAsync (setup) failed: '{defineResult.ResponseCode}'.");

        long rentedBeforeRead = trackingPool.RentedCount;

        TpmResult<NvReadPublicResponse> publicResult = await device.NvReadPublicAsync(NvIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(publicResult.IsSuccess, $"NvReadPublicAsync failed: '{publicResult.ResponseCode}'.");
        Assert.IsGreaterThan(rentedBeforeRead, trackingPool.RentedCount, "NvReadPublicAsync must itself rent from the device's own pool, beyond whatever setup already rented.");

        publicResult.Value.Dispose();

        TpmResult<NvUndefineSpaceResponse> undefineResult = await device.UndefineCounterAsync(
            ReadOnlyMemory<byte>.Empty, NvIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(undefineResult.IsSuccess, $"UndefineCounterAsync (teardown) failed: '{undefineResult.ResponseCode}'.");

        Assert.AreEqual(0L, trackingPool.OutstandingCount, "Every carrier the define-read-undefine lifecycle rents must be returned once the Index is undefined.");
    }

    /// <summary>
    /// The Counter family's verbs (<see cref="TpmDeviceExtensions.DefineCounterAsync"/>,
    /// <see cref="TpmDeviceExtensions.IncrementCounterAsync"/>,
    /// <see cref="TpmDeviceExtensions.UndefineCounterAsync"/>, composing <c>TPM2_NV_DefineSpace</c>,
    /// <c>TPM2_NV_Increment</c> and <c>TPM2_NV_UndefineSpace</c>) rent their scratch buffers from the device's own
    /// pool across a full define-increment-undefine lifecycle.
    /// </summary>
    [TestMethod]
    public async Task DefineIncrementUndefineCounterAsyncRentFromTheDevicesOwnPool()
    {
        const uint CounterIndexHandle = 0x0100_0090;
        byte[] counterAuth = [0x55, 0x66, 0x77, 0x88];

        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, trackingPool.Pool, TestEntropy.NewCounterStream());

        TpmResult<NvDefineSpaceResponse> defineResult = await device.DefineCounterAsync(
            ReadOnlyMemory<byte>.Empty, CounterIndexHandle, counterAuth, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"DefineCounterAsync failed: '{defineResult.ResponseCode}'.");

        TpmResult<ulong> incrementResult = await device.IncrementCounterAsync(
            CounterIndexHandle, counterAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(incrementResult.IsSuccess, $"IncrementCounterAsync failed: '{incrementResult.ResponseCode}'.");
        Assert.AreEqual(1UL, incrementResult.Value, "The first increment of a freshly defined Counter Index must read back exactly one.");

        TpmResult<NvUndefineSpaceResponse> undefineResult = await device.UndefineCounterAsync(
            ReadOnlyMemory<byte>.Empty, CounterIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(undefineResult.IsSuccess, $"UndefineCounterAsync failed: '{undefineResult.ResponseCode}'.");

        Assert.IsGreaterThan(0L, trackingPool.RentedCount, "The define-increment-undefine sequence must rent from the device's own pool.");
        Assert.AreEqual(0L, trackingPool.OutstandingCount, "Every carrier the sequence rents must be returned once every call completes.");
    }

    /// <summary>
    /// The Hierarchy family's verb (<see cref="TpmDeviceExtensions.ChangeHierarchyAuthWithPasswordAsync"/>,
    /// composing <c>TPM2_HierarchyChangeAuth</c> over a plaintext password session) rents its scratch buffers
    /// from the device's own pool. A non-empty hierarchy authValue is retained live simulator state until it is
    /// rotated again, so the balance is read after rotating to a real value and back to empty, not around one
    /// call alone.
    /// </summary>
    [TestMethod]
    public async Task ChangeHierarchyAuthWithPasswordAsyncRentsFromTheDevicesOwnPool()
    {
        byte[] newLockoutAuth = [0x13, 0x57, 0x9B, 0xDF];

        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, trackingPool.Pool, TestEntropy.NewCounterStream());

        long rentedBeforeRotation = trackingPool.RentedCount;

        TpmResult<HierarchyChangeAuthResponse> result = await device.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_LOCKOUT, ReadOnlyMemory<byte>.Empty, newLockoutAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"ChangeHierarchyAuthWithPasswordAsync failed: '{result.ResponseCode}'.");
        Assert.IsGreaterThan(rentedBeforeRotation, trackingPool.RentedCount, "ChangeHierarchyAuthWithPasswordAsync must rent its command and response buffers from the device's own pool.");

        TpmResult<HierarchyChangeAuthResponse> revertResult = await device.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_LOCKOUT, newLockoutAuth, ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(revertResult.IsSuccess, $"ChangeHierarchyAuthWithPasswordAsync (revert) failed: '{revertResult.ResponseCode}'.");

        Assert.AreEqual(0L, trackingPool.OutstandingCount, "Every carrier the rotate-then-revert-to-empty round trip rents must be returned once it completes.");
    }

    /// <summary>
    /// The Seal family's verbs (<see cref="TpmDeviceExtensions.SealAsync"/>, <see cref="TpmDeviceExtensions.UnsealAsync"/>,
    /// composing <c>TPM2_Create</c>/<c>TPM2_Load</c> and <c>TPM2_Unseal</c>) rent their scratch buffers from the
    /// device's own pool. The storage parent is provisioned with a direct <c>TPM2_CreatePrimary</c> call against a
    /// separate, unobserved pool, so only the two verbs under test are measured for the rent-count proof.
    /// </summary>
    [TestMethod]
    public async Task SealThenUnsealAsyncRentFromTheDevicesOwnPool()
    {
        byte[] secret = "pool custody proof secret"u8.ToArray();
        byte[] sealAuth = "pool-custody-seal-auth"u8.ToArray();

        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, trackingPool.Pool, TestEntropy.NewCounterStream());

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(device, BaseMemoryPool.Shared).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;

        try
        {
            long rentedBeforeSeal = trackingPool.RentedCount;

            TpmResult<TpmSealedBlob> sealResult = await device.SealAsync(
                parentHandle, ReadOnlyMemory<byte>.Empty, secret, sealAuth,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(sealResult.IsSuccess, $"SealAsync failed: '{sealResult.ResponseCode}'.");
            Assert.IsGreaterThan(rentedBeforeSeal, trackingPool.RentedCount, "SealAsync must rent from the device's own pool.");

            using(TpmSealedBlob sealedBlob = sealResult.Value)
            {
                TpmResult<UnsealResponse> unsealResult = await device.UnsealAsync(
                    parentHandle, ReadOnlyMemory<byte>.Empty, sealedBlob, sealAuth, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(unsealResult.IsSuccess, $"UnsealAsync failed: '{unsealResult.ResponseCode}'.");

                using UnsealResponse unsealed = unsealResult.Value;
                Assert.IsTrue(unsealed.OutData.AsReadOnlySpan().SequenceEqual(secret), "The unsealed data must equal the sealed secret.");
            }
        }
        finally
        {
            _ = await device.FlushContextAsync(parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }

        Assert.AreEqual(0L, trackingPool.OutstandingCount, "Every carrier the seal-unseal-flush sequence rents must be returned once every call completes.");
    }

    /// <summary>
    /// The Pin family's verbs (<see cref="TpmDeviceExtensions.DefinePinFailIndexAsync"/>,
    /// <see cref="TpmDeviceExtensions.VerifyPinAsync"/>, <see cref="TpmDeviceExtensions.UndefinePinIndexAsync"/>,
    /// composing <c>TPM2_NV_DefineSpace</c>, <c>TPM2_NV_Write</c> and <c>TPM2_NV_UndefineSpace</c> over a bound HMAC
    /// session) rent their scratch buffers from the device's own pool across a full define-verify-undefine
    /// lifecycle.
    /// </summary>
    [TestMethod]
    public async Task DefineVerifyUndefinePinAsyncRentFromTheDevicesOwnPool()
    {
        const uint PinIndexHandle = 0x0100_0092;
        const uint PinLimit = 3;
        byte[] pinHash = [0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xEE, 0xFF];

        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, trackingPool.Pool, TestEntropy.NewCounterStream());

        TpmResult<NvWriteResponse> defineResult = await device.DefinePinFailIndexAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, pinHash, PinLimit, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"DefinePinFailIndexAsync failed: '{defineResult.ResponseCode}'.");

        TpmResult<TpmPinCounterParameters> verifyResult = await device.VerifyPinAsync(
            PinIndexHandle, pinHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(verifyResult.IsSuccess, $"VerifyPinAsync failed: '{verifyResult.ResponseCode}'.");

        TpmResult<NvUndefineSpaceResponse> undefineResult = await device.UndefinePinIndexAsync(
            ReadOnlyMemory<byte>.Empty, PinIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(undefineResult.IsSuccess, $"UndefinePinIndexAsync failed: '{undefineResult.ResponseCode}'.");

        Assert.IsGreaterThan(0L, trackingPool.RentedCount, "The define-verify-undefine sequence must rent from the device's own pool.");
        Assert.AreEqual(0L, trackingPool.OutstandingCount, "Every carrier the sequence rents must be returned once every call completes.");
    }

    /// <summary>
    /// The Policy family's verbs (<see cref="TpmDeviceExtensions.StartTrialPolicySessionAsync"/>,
    /// <see cref="TpmDeviceExtensions.PolicyAuthValueAsync"/>, composing <c>TPM2_StartAuthSession</c> and
    /// <c>TPM2_PolicyAuthValue</c>) rent their scratch buffers from the device's own pool.
    /// </summary>
    [TestMethod]
    public async Task StartTrialPolicySessionThenPolicyAuthValueAsyncRentFromTheDevicesOwnPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, trackingPool.Pool, TestEntropy.NewCounterStream());

        TpmResult<StartAuthSessionResponse> startResult = await device.StartTrialPolicySessionAsync(
            TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartTrialPolicySessionAsync failed: '{startResult.ResponseCode}'.");

        uint sessionHandle = 0;
        try
        {
            using StartAuthSessionResponse started = startResult.Value;
            sessionHandle = started.SessionHandle.Value;

            TpmResult<PolicyAuthValueResponse> assertResult = await device.PolicyAuthValueAsync(
                sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(assertResult.IsSuccess, $"PolicyAuthValueAsync failed: '{assertResult.ResponseCode}'.");
        }
        finally
        {
            _ = await device.FlushContextAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }

        Assert.IsGreaterThan(0L, trackingPool.RentedCount, "The session-start-then-assertion sequence must rent from the device's own pool.");
        Assert.AreEqual(0L, trackingPool.OutstandingCount, "Every carrier the sequence rents must be returned once every call completes.");
    }

    /// <summary>
    /// The DictionaryAttack family's verb (<see cref="TpmDictionaryAttackExtensions.DictionaryAttackParametersAsync"/>,
    /// composing <c>TPM2_DictionaryAttackParameters</c> over a plaintext lockout-hierarchy password session) rents
    /// its scratch buffers from the device's own pool.
    /// </summary>
    [TestMethod]
    public async Task DictionaryAttackParametersAsyncRentsFromTheDevicesOwnPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, trackingPool.Pool, TestEntropy.NewCounterStream());

        TpmResult<DictionaryAttackParametersResponse> result = await device.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, newMaxTries: 5, newRecoveryTime: 60, newLockoutRecovery: 120,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"DictionaryAttackParametersAsync failed: '{result.ResponseCode}'.");
        Assert.IsGreaterThan(0L, trackingPool.RentedCount, "DictionaryAttackParametersAsync must rent its command and response buffers from the device's own pool.");
        Assert.AreEqual(0L, trackingPool.OutstandingCount, "Every carrier the call rents must be returned once it completes.");
    }

    /// <summary>
    /// Creates the deterministic ECC storage parent under the owner hierarchy against an unobserved pool (setup
    /// scaffolding, not the pool-custody proof itself) and returns the response; the caller owns it and flushes
    /// <see cref="CreatePrimaryResponse.ObjectHandle"/>.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool used for this setup exchange alone.</param>
    /// <returns>The CreatePrimary response for the storage parent.</returns>
    private async Task<CreatePrimaryResponse> CreateStorageParentAsync(TpmDevice device, BaseMemoryPool pool)
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);

        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> parentResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, parentInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(parentResult.IsSuccess, $"CreatePrimary storage parent (setup) failed: '{parentResult.ResponseCode}'.");

        return parentResult.Value;
    }

    /// <summary>
    /// Wraps a <see cref="TpmSubmitHandler"/> so a <c>TPM2_GetCapability</c> request for a category the
    /// simulator does not model (<c>TPM_CAP_ALGS</c>, <c>TPM_CAP_PCRS</c>) is answered with a canned, empty-list
    /// success response instead of the simulator's <c>TPM_RC_VALUE</c> "not modelled" signal; every other
    /// command is forwarded to <paramref name="inner"/> unchanged.
    /// </summary>
    /// <param name="inner">The real handler to forward every other command to.</param>
    /// <returns>The wrapping handler.</returns>
    private static TpmSubmitHandler InterceptUnmodelledCapabilities(TpmSubmitHandler inner)
    {
        return (command, pool, cancellationToken) =>
        {
            ReadOnlySpan<byte> span = command.Span;
            uint commandCode = BinaryPrimitives.ReadUInt32BigEndian(span[6..10]);

            if(commandCode == (uint)TpmCcConstants.TPM_CC_GetCapability)
            {
                uint capability = BinaryPrimitives.ReadUInt32BigEndian(span[10..14]);
                if(capability == (uint)TpmCapConstants.TPM_CAP_ALGS || capability == (uint)TpmCapConstants.TPM_CAP_PCRS)
                {
                    return ValueTask.FromResult(EmptyCapabilityListResponse(pool, capability));
                }
            }

            return inner(command, pool, cancellationToken);
        };
    }

    /// <summary>Builds a <c>TPM2_GetCapability</c> success response whose list arm carries zero entries.</summary>
    /// <param name="pool">The pool the response buffer is rented from.</param>
    /// <param name="capability">The <c>TPM_CAP</c> value the response echoes, selecting which list arm is empty.</param>
    /// <returns>The canned, empty-list success response.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The TpmResponse is owned by the returned TpmResult and disposed by the executor under test.")]
    private static TpmResult<TpmResponse> EmptyCapabilityListResponse(BaseMemoryPool pool, uint capability)
    {
        const ushort TpmStNoSessions = 0x8001;
        const int HeaderSize = 10;
        const int ParameterLength = sizeof(byte) + sizeof(uint) + sizeof(uint);
        const int Total = HeaderSize + ParameterLength;

        IMemoryOwner<byte> owner = pool.Rent(Total);
        Span<byte> frame = owner.Memory.Span[..Total];

        BinaryPrimitives.WriteUInt16BigEndian(frame, TpmStNoSessions);
        BinaryPrimitives.WriteUInt32BigEndian(frame[2..], Total);
        BinaryPrimitives.WriteUInt32BigEndian(frame[6..], (uint)TpmRcConstants.TPM_RC_SUCCESS);
        frame[10] = 0;
        BinaryPrimitives.WriteUInt32BigEndian(frame[11..], capability);
        BinaryPrimitives.WriteUInt32BigEndian(frame[15..], 0u);

        return TpmResult<TpmResponse>.Success(new TpmResponse(owner, Total));
    }

    /// <summary>Creates a simulator, powers it on, and brings it through <c>TPM2_Startup(CLEAR)</c> over an unobserved pool.</summary>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync()
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-extensions-pool-custody", signingBackend: BouncyCastleTpmEccSigningBackend.Create(),
            rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, BaseMemoryPool.Shared).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator to move it into the operational phase.</summary>
    /// <param name="simulator">The simulator to bring operational.</param>
    /// <param name="pool">The memory pool used for this one setup exchange.</param>
    private async Task BringOperationalAsync(TpmSimulator simulator, BaseMemoryPool pool)
    {
        var input = new StartupInput(TpmSuConstants.TPM_SU_CLEAR);
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "TPM2_Startup(CLEAR) must succeed.");

        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code);
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase);
    }
}
