using System;
using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.TestInfrastructure.TpmSimulator;
using Verifiable.Tpm;
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
/// Acceptance tests for the object/NV provisioning lifecycle against the TCG ms-tpm-20-ref software TPM
/// simulator: persisting and evicting a key with TPM2_EvictControl, and defining then removing an NV Index with
/// TPM2_NV_UndefineSpace. These are the persistence and teardown operations a real EK/AK provisioning flow uses
/// (persist the keys to fixed handles; reclaim NV when a credential is rotated).
/// </summary>
/// <remarks>
/// The tests are gated on a running simulator (start the container from
/// <c>test/Verifiable.Tests/TestInfrastructure/TpmSimulator/Dockerfile</c>, publishing ports 2321/2322); they
/// report <see cref="Assert.Inconclusive(string)"/> when none is reachable, so they are safe in any run. Each
/// test pre-cleans its fixed handle so a previous interrupted run cannot leave the persistent simulator in a
/// state that fails the next run.
/// </remarks>
[ConditionalTestClass]
[SkipIfNoTpmSimulator]
[DoNotParallelize]
[TestCategory("RequiresTpmSimulator")]
internal sealed class TpmSimulatorPersistenceTests
{
    /// <summary>The owner-hierarchy persistent handle (range 0x81000000-0x817FFFFF) used to persist the test key.</summary>
    private const uint PersistentHandle = 0x8100_0010;

    /// <summary>The NV Index handle used by the undefine test (MSO 0x01 = TPM_HT_NV_INDEX).</summary>
    private const uint NvIndexHandle = 0x0100_0011;

    /// <summary>The connection to the simulator, established once for the class.</summary>
    private static MsTpmSimulatorConnection? Connection { get; set; }

    /// <summary>The TPM device created over the simulator connection.</summary>
    private static TpmDevice? Tpm { get; set; }

    /// <summary>Whether a simulator was reachable at class initialization.</summary>
    private static bool HasSimulator { get; set; }

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>Connects to the simulator (if one is reachable) and brings up a TPM device for the class.</summary>
    /// <param name="context">The class-level test context.</param>
    [ClassInitialize]
    public static async Task ClassInit(TestContext context)
    {
        if(!MsTpmSimulatorConnection.IsAvailable("localhost", MsTpmSimulatorConnection.DefaultCommandPort, TimeSpan.FromSeconds(1)))
        {
            return;
        }

        Connection = await MsTpmSimulatorConnection.ConnectAsync(
            "localhost", MsTpmSimulatorConnection.DefaultCommandPort, context.CancellationToken).ConfigureAwait(false);
        Tpm = TpmDevice.Create(Connection.SubmitAsync);
        HasSimulator = true;
    }

    /// <summary>Releases the TPM device and simulator connection.</summary>
    [ClassCleanup]
    public static void ClassCleanup()
    {
        Tpm?.Dispose();
        Connection?.Dispose();
    }

    /// <summary>Skips the test when no simulator is reachable.</summary>
    [TestInitialize]
    public void TestInit()
    {
        if(!HasSimulator)
        {
            Assert.Inconclusive("No TPM simulator is reachable on localhost:2321/2322. Start the container from TestInfrastructure/TpmSimulator/Dockerfile.");
        }
    }

    [TestMethod]
    public async Task EvictControlPersistsAndEvictsAKey()
    {
        TpmDevice tpm = Tpm!;
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            //Pre-clean any persistent object a prior interrupted run may have left at this handle.
            _ = await EvictAsync(tpm, registry, pool, PersistentHandle).ConfigureAwait(false);

            //Persist the transient key to the fixed persistent handle.
            using TpmPasswordSession persistAuth = TpmPasswordSession.CreateEmpty(pool);
            var persistInput = new EvictControlInput(TpmRh.TPM_RH_OWNER, primary.ObjectHandle.Value, PersistentHandle);
            TpmResult<EvictControlResponse> persistResult = await TpmCommandExecutor.ExecuteAsync<EvictControlResponse>(
                tpm, persistInput, [persistAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(persistResult.IsSuccess, $"EvictControl (persist) failed: '{persistResult.ResponseCode}'.");

            //Evict it again. A successful eviction proves a persistent object existed at the handle — i.e. the
            //persist took effect — and cleans the handle for the next run.
            TpmResult<EvictControlResponse> evictResult = await EvictAsync(tpm, registry, pool, PersistentHandle).ConfigureAwait(false);
            Assert.IsTrue(evictResult.IsSuccess, $"EvictControl (evict) failed: '{evictResult.ResponseCode}'.");
        }
        finally
        {
            await FlushAsync(tpm, registry, primary.ObjectHandle.Value, pool).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task NvUndefineSpaceFreesTheIndex()
    {
        TpmDevice tpm = Tpm!;
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResponseRegistry registry = CreateRegistry();

        //Pre-clean any index a prior interrupted run may have left.
        _ = await UndefineAsync(tpm, registry, pool, NvIndexHandle).ConfigureAwait(false);
        try
        {
            TpmResult<NvDefineSpaceResponse> defineResult = await DefineIndexAsync(tpm, registry, pool, NvIndexHandle).ConfigureAwait(false);
            Assert.IsTrue(defineResult.IsSuccess, $"NV_DefineSpace failed: '{defineResult.ResponseCode}'.");

            TpmResult<NvUndefineSpaceResponse> undefineResult = await UndefineAsync(tpm, registry, pool, NvIndexHandle).ConfigureAwait(false);
            Assert.IsTrue(undefineResult.IsSuccess, $"NV_UndefineSpace failed: '{undefineResult.ResponseCode}'.");

            //Re-defining the same handle proves the previous definition was removed and the handle freed.
            TpmResult<NvDefineSpaceResponse> redefineResult = await DefineIndexAsync(tpm, registry, pool, NvIndexHandle).ConfigureAwait(false);
            Assert.IsTrue(redefineResult.IsSuccess, $"NV_DefineSpace after undefine failed: '{redefineResult.ResponseCode}'.");
        }
        finally
        {
            _ = await UndefineAsync(tpm, registry, pool, NvIndexHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Evicts (removes) the persistent object at the given handle, returning the result for the caller to assert
    /// or ignore.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="persistentHandle">The persistent handle to evict.</param>
    /// <returns>The EvictControl result.</returns>
    private async Task<TpmResult<EvictControlResponse>> EvictAsync(TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, uint persistentHandle)
    {
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        var input = new EvictControlInput(TpmRh.TPM_RH_OWNER, persistentHandle, persistentHandle);

        return await TpmCommandExecutor.ExecuteAsync<EvictControlResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Defines a small DA-exempt NV Index authorized by its own auth value.
    /// </summary>
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

    /// <summary>
    /// Undefines (removes) the given NV Index, returning the result for the caller to assert or ignore.
    /// </summary>
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

    /// <summary>
    /// Creates a primary ECC P-256 signing key under the owner hierarchy.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response (the caller owns it and flushes the handle).</returns>
    private async Task<CreatePrimaryResponse> CreateSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER,
            password: null,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool,
            noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates a response codec registry covering the commands these tests issue.
    /// </summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_EvictControl, TpmResponseCodec.EvictControl);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }

    /// <summary>
    /// Flushes a transient object handle, ignoring the result.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="handle">The handle to flush.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task FlushAsync(TpmDevice tpm, TpmResponseRegistry registry, uint handle, MemoryPool<byte> pool)
    {
        var flush = FlushContextInput.ForHandle(handle);
        _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, flush, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }
}
