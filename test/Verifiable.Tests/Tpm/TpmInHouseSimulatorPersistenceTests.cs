using System;
using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Infrastructure.Spec.Attributes;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives the object/NV provisioning teardown lifecycle against the in-house behavioural
/// <see cref="TpmSimulator"/> — entirely in-process, with no external assets — through the production command
/// path (<see cref="TpmCommandExecutor"/> with the real inputs and response codecs): persisting and evicting a
/// key with <c>TPM2_EvictControl</c>, and defining then removing an NV Index with <c>TPM2_NV_UndefineSpace</c>.
/// These are the persistence and reclamation operations a real EK/AK provisioning flow uses.
/// </summary>
/// <remarks>
/// Because the in-house simulator starts from a clean, deterministic state on every run (no persistent external
/// process), each test additionally asserts the negative outcome — re-evicting or undefining a now-absent handle
/// returns <c>TPM_RC_HANDLE</c> — which a persistent external simulator could only pre-clean and ignore.
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorPersistenceTests
{
    /// <summary>The owner-hierarchy persistent handle (range 0x81000000-0x817FFFFF) used to persist the test key.</summary>
    private const uint PersistentHandle = 0x8100_0010;

    /// <summary>The NV Index handle used by the undefine test (MSO 0x01 = TPM_HT_NV_INDEX).</summary>
    private const uint NvIndexHandle = 0x0100_0011;

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public async Task EvictControlPersistsAndEvictsAKey()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);

        //Persist the transient key to the fixed persistent handle.
        TpmResult<EvictControlResponse> persistResult = await EvictControlAsync(
            tpm, registry, pool, primary.ObjectHandle.Value, PersistentHandle).ConfigureAwait(false);
        Assert.IsTrue(persistResult.IsSuccess, $"EvictControl (persist) failed: '{persistResult.ResponseCode}'.");

        //Evict it. A successful eviction proves a persistent object existed at the handle — i.e. the persist took
        //effect.
        TpmResult<EvictControlResponse> evictResult = await EvictControlAsync(
            tpm, registry, pool, PersistentHandle, PersistentHandle).ConfigureAwait(false);
        Assert.IsTrue(evictResult.IsSuccess, $"EvictControl (evict) failed: '{evictResult.ResponseCode}'.");

        //Evicting the now-absent persistent handle must fail with TPM_RC_HANDLE.
        TpmResult<EvictControlResponse> reEvictResult = await EvictControlAsync(
            tpm, registry, pool, PersistentHandle, PersistentHandle).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, reEvictResult.ResponseCode, "Evicting an already-evicted handle must fail with TPM_RC_HANDLE.");
    }

    [TestMethod]
    public async Task NvUndefineSpaceFreesTheIndex()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<NvDefineSpaceResponse> defineResult = await DefineIndexAsync(tpm, registry, pool, NvIndexHandle).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"NV_DefineSpace failed: '{defineResult.ResponseCode}'.");

        TpmResult<NvUndefineSpaceResponse> undefineResult = await UndefineAsync(tpm, registry, pool, NvIndexHandle).ConfigureAwait(false);
        Assert.IsTrue(undefineResult.IsSuccess, $"NV_UndefineSpace failed: '{undefineResult.ResponseCode}'.");

        //Re-defining the same handle proves the previous definition was removed and the handle freed.
        TpmResult<NvDefineSpaceResponse> redefineResult = await DefineIndexAsync(tpm, registry, pool, NvIndexHandle).ConfigureAwait(false);
        Assert.IsTrue(redefineResult.IsSuccess, $"NV_DefineSpace after undefine failed: '{redefineResult.ResponseCode}'.");

        //Undefining a handle that was never defined must fail with TPM_RC_HANDLE.
        TpmResult<NvUndefineSpaceResponse> undefineUnknown = await UndefineAsync(tpm, registry, pool, NvIndexHandle + 1).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, undefineUnknown.ResponseCode, "Undefining an unknown NV Index must fail with TPM_RC_HANDLE.");
    }

    /// <summary>Issues TPM2_EvictControl for the given object and persistent handles, returning the result.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="objectHandle">The transient object to persist, or the persistent handle to evict.</param>
    /// <param name="persistentHandle">The persistent handle to assign or evict.</param>
    /// <returns>The EvictControl result.</returns>
    private async Task<TpmResult<EvictControlResponse>> EvictControlAsync(
        TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, uint objectHandle, uint persistentHandle)
    {
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        var input = new EvictControlInput(TpmRh.TPM_RH_OWNER, objectHandle, persistentHandle);

        return await TpmCommandExecutor.ExecuteAsync<EvictControlResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Defines a small DA-exempt NV Index authorized by its own auth value.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The NV Index handle to define.</param>
    /// <returns>The NV_DefineSpace result.</returns>
    private async Task<TpmResult<NvDefineSpaceResponse>> DefineIndexAsync(TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, uint nvIndex)
    {
        using Tpm2bAuth indexAuth = Tpm2bAuth.CreateEmpty(pool);
        using var publicInfo = new TpmsNvPublic(
            nvIndex,
            TpmAlgIdConstants.TPM_ALG_SHA256,
            TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_NO_DA,
            Tpm2bDigest.Empty,
            dataSize: 8);
        using var input = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, indexAuth, publicInfo);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        return await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Undefines (removes) the given NV Index, returning the result for the caller to assert.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The NV Index handle to undefine.</param>
    /// <returns>The NV_UndefineSpace result.</returns>
    private async Task<TpmResult<NvUndefineSpaceResponse>> UndefineAsync(TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, uint nvIndex)
    {
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        var input = new NvUndefineSpaceInput(TpmRh.TPM_RH_OWNER, nvIndex);

        return await TpmCommandExecutor.ExecuteAsync<NvUndefineSpaceResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Creates a primary ECC P-256 signing key under the owner hierarchy.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates a simulator with an ECC signing backend, powers it on, and brings it operational.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(MemoryPool<byte> pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-persistence", signingBackend: BouncyCastleTpmEccSigningBackend.Create());
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>
    /// Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator to move it into
    /// <see cref="TpmLifecyclePhase.Operational"/>.
    /// </summary>
    /// <param name="simulator">The simulator to bring operational.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task BringOperationalAsync(TpmSimulator simulator, MemoryPool<byte> pool)
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
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase);
    }

    /// <summary>Creates a response codec registry covering the commands these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_EvictControl, TpmResponseCodec.EvictControl);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace);

        return registry;
    }
}
