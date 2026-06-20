using System;
using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Tests.TestInfrastructure;
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
/// Coverage for the <see cref="TpmSimulator"/> NV-Index authorization surface (V.5b-1): defining a
/// DA-protected NV Index with the owner hierarchy, then authorizing a read against it through a password
/// session. The authorization outcomes modelled here — bad-authorization vs. dictionary-attack-affecting
/// auth-failure (TPM 2.0 Library Part 1, clause 17.8) — are the substrate the PIN/lockout flow is built
/// on. Commands are driven through <see cref="TpmCommandExecutor"/> with a real
/// <see cref="TpmPasswordSession"/>, which frames the TPM_ST_SESSIONS authorization area the simulator
/// parses; no real TPM hardware is touched.
/// </summary>
[TestClass]
internal sealed class TpmSimulatorNvTests
{
    //An ordinary NV Index handle: its most-significant octet is TPM_HT_NV_INDEX (0x01).
    private const uint NvIndexHandle = 0x0100_0001;

    //Index attributes that authorize read/write with the Index authValue. Without TPMA_NV_NO_DA the Index
    //is dictionary-attack protected, so a wrong authValue is an auth-failure (clause 17.8.3).
    private const TpmaNv DaProtectedAttributes = TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE;

    //The same Index, opted out of dictionary-attack protection: a wrong authValue is a plain bad-auth.
    private const TpmaNv NonDaAttributes = DaProtectedAttributes | TpmaNv.TPMA_NV_NO_DA;

    //An Index that permits authValue-based WRITE but not READ (TPMA_NV_AUTHREAD clear): its authValue cannot
    //authorize a read even when it matches.
    private const TpmaNv WriteOnlyAttributes = TpmaNv.TPMA_NV_AUTHWRITE;

    private static byte[] CorrectAuth { get; } = [0x01, 0x02, 0x03, 0x04];

    private static byte[] WrongAuth { get; } = [0x09, 0x09, 0x09, 0x09];

    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public async Task NvDefineSpaceWithEmptyOwnerAuthSucceeds()
    {
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResponseRegistry registry = CreateNvRegistry();

        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<NvDefineSpaceResponse> result = await DefineSpaceAsync(
            device, pool, registry, NvIndexHandle, DaProtectedAttributes, CorrectAuth, ownerSession).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Expected success, got '{result.ResponseCode}'.");
        Assert.AreSame(NvDefineSpaceResponse.Instance, result.Value);
    }

    [TestMethod]
    public async Task NvDefineSpaceWithWrongOwnerAuthReturnsBadAuth()
    {
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResponseRegistry registry = CreateNvRegistry();

        //The simulator's owner authValue is empty by default; supplying a non-empty owner authorization is
        //a wrong owner auth. Owner authorization is not DA-protected, so the failure is a plain bad-auth.
        using TpmPasswordSession ownerSession = TpmPasswordSession.Create(WrongAuth, pool);
        TpmResult<NvDefineSpaceResponse> result = await DefineSpaceAsync(
            device, pool, registry, NvIndexHandle, DaProtectedAttributes, CorrectAuth, ownerSession).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, result.ResponseCode);
    }

    [TestMethod]
    public async Task NvDefineSpaceOnAlreadyDefinedIndexReturnsNvDefined()
    {
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineDaIndexAsync(device, pool, registry).ConfigureAwait(false);

        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<NvDefineSpaceResponse> result = await DefineSpaceAsync(
            device, pool, registry, NvIndexHandle, DaProtectedAttributes, CorrectAuth, ownerSession).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_DEFINED, result.ResponseCode);
    }

    [TestMethod]
    public async Task NvDefineSpaceWithNonNvHandleReturnsHandle()
    {
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResponseRegistry registry = CreateNvRegistry();

        //A persistent-object handle (MSO 0x81) is not in the NV-Index range, so it cannot be defined as one.
        const uint PersistentHandle = 0x8100_0001;
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<NvDefineSpaceResponse> result = await DefineSpaceAsync(
            device, pool, registry, PersistentHandle, DaProtectedAttributes, CorrectAuth, ownerSession).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, result.ResponseCode);
    }

    [TestMethod]
    public async Task NvReadWithCorrectAuthReturnsUninitialized()
    {
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineDaIndexAsync(device, pool, registry).ConfigureAwait(false);

        //Correct Index authorization passes the auth check; the Index has never been written, so the read
        //answers TPM_RC_NV_UNINITIALIZED (no NV_Write in this slice).
        TpmResult<NvReadResponse> result = await ReadIndexAsync(device, pool, registry, CorrectAuth).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_UNINITIALIZED, result.ResponseCode);
    }

    [TestMethod]
    public async Task NvReadWithWrongAuthOnDaProtectedIndexReturnsAuthFail()
    {
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineDaIndexAsync(device, pool, registry).ConfigureAwait(false);

        //A wrong authValue against a DA-protected Index is an auth-failure (clause 17.8.3): in the next
        //slice it increments the lockout counter.
        TpmResult<NvReadResponse> result = await ReadIndexAsync(device, pool, registry, WrongAuth).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_FAIL, result.ResponseCode);
    }

    [TestMethod]
    public async Task NvReadWithWrongAuthOnNonDaIndexReturnsBadAuth()
    {
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResponseRegistry registry = CreateNvRegistry();

        using(TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool))
        {
            TpmResult<NvDefineSpaceResponse> defineResult = await DefineSpaceAsync(
                device, pool, registry, NvIndexHandle, NonDaAttributes, CorrectAuth, ownerSession).ConfigureAwait(false);
            Assert.IsTrue(defineResult.IsSuccess, $"Define must succeed, got '{defineResult.ResponseCode}'.");
        }

        //A wrong authValue against a non-DA Index is a plain bad-authorization (clause 17.8.1): it does not
        //affect the lockout counter.
        TpmResult<NvReadResponse> result = await ReadIndexAsync(device, pool, registry, WrongAuth).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, result.ResponseCode);
    }

    [TestMethod]
    public async Task NvReadOnIndexWithoutAuthReadReturnsNvAuthorization()
    {
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResponseRegistry registry = CreateNvRegistry();

        using(TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool))
        {
            TpmResult<NvDefineSpaceResponse> defineResult = await DefineSpaceAsync(
                device, pool, registry, NvIndexHandle, WriteOnlyAttributes, CorrectAuth, ownerSession).ConfigureAwait(false);
            Assert.IsTrue(defineResult.IsSuccess, $"Define must succeed, got '{defineResult.ResponseCode}'.");
        }

        //The supplied value matches the Index authValue, but TPMA_NV_AUTHREAD is clear, so the authValue may
        //not authorize a read: the access check refuses it (clause 13.4), distinct from a value mismatch.
        TpmResult<NvReadResponse> result = await ReadIndexAsync(device, pool, registry, CorrectAuth).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_AUTHORIZATION, result.ResponseCode);
    }

    [TestMethod]
    public async Task NvReadOfUndefinedIndexReturnsHandle()
    {
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResponseRegistry registry = CreateNvRegistry();

        //No Index was defined, so the handle does not resolve.
        TpmResult<NvReadResponse> result = await ReadIndexAsync(device, pool, registry, CorrectAuth).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, result.ResponseCode);
    }

    [TestMethod]
    public async Task NvReadWithOwnerAuthHandleReturnsAuthType()
    {
        TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineDaIndexAsync(device, pool, registry).ConfigureAwait(false);

        //Only Index authorization (authHandle == nvIndex) is modelled; an owner-authorized read against the
        //Index is rejected as an unmodelled authorization type.
        using TpmPasswordSession session = TpmPasswordSession.Create(CorrectAuth, pool);
        var readInput = new NvReadInput(AuthHandle: (uint)TpmRh.TPM_RH_OWNER, NvIndex: NvIndexHandle, Size: 8, Offset: 0);
        TpmResult<NvReadResponse> result = await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
            device, readInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_TYPE, result.ResponseCode);
    }

    [TestMethod]
    public async Task NvReadBeforeStartupReturnsInitialize()
    {
        var simulator = new TpmSimulator("tpm-nv-init");
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmResponseRegistry registry = CreateNvRegistry();

        //Phase gating precedes the handle/authorization checks: a well-formed NV_Read before TPM2_Startup()
        //is rejected for the lifecycle phase, not for the (absent) Index.
        TpmResult<NvReadResponse> result = await ReadIndexAsync(device, pool, registry, CorrectAuth).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_INITIALIZE, result.ResponseCode);
    }

    private static TpmResponseRegistry CreateNvRegistry() =>
        new TpmResponseRegistry()
            .Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace)
            .Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead);

    private async Task<TpmResult<NvDefineSpaceResponse>> DefineSpaceAsync(
        TpmDevice device,
        MemoryPool<byte> pool,
        TpmResponseRegistry registry,
        uint nvIndex,
        TpmaNv attributes,
        ReadOnlyMemory<byte> indexAuth,
        TpmPasswordSession ownerSession)
    {
        //The input takes ownership of the auth value and public area and disposes them; the redundant using
        //locals satisfy CA2000 and are safe because both types have idempotent disposal.
        using var auth = Tpm2bAuth.Create(indexAuth.Span, pool);
        using var publicInfo = new TpmsNvPublic(nvIndex, TpmAlgIdConstants.TPM_ALG_SHA256, attributes, Tpm2bDigest.Empty, dataSize: 8);
        using var input = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, auth, publicInfo);

        return await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            device, input, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    private async Task DefineDaIndexAsync(TpmDevice device, MemoryPool<byte> pool, TpmResponseRegistry registry)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<NvDefineSpaceResponse> result = await DefineSpaceAsync(
            device, pool, registry, NvIndexHandle, DaProtectedAttributes, CorrectAuth, ownerSession).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Define must succeed, got '{result.ResponseCode}'.");
    }

    private async Task<TpmResult<NvReadResponse>> ReadIndexAsync(
        TpmDevice device,
        MemoryPool<byte> pool,
        TpmResponseRegistry registry,
        ReadOnlyMemory<byte> suppliedAuth)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);

        //Index authorization: the authorization handle is the Index itself.
        var readInput = new NvReadInput(AuthHandle: NvIndexHandle, NvIndex: NvIndexHandle, Size: 8, Offset: 0);

        return await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
            device, readInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    private async Task<TpmSimulator> CreateOperationalAsync(TpmSelfTestBehavior selfTest = TpmSelfTestBehavior.Passes)
    {
        var simulator = new TpmSimulator("tpm-nv", selfTest);
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using IMemoryOwner<byte> owner = RentCommand(new StartupInput(TpmSuConstants.TPM_SU_CLEAR), pool, out int length);
        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess);
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader header = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)header.Code);
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase);

        return simulator;
    }

    //Frames a no-sessions command (header + handles + parameters) into a pool-rented buffer, mirroring how
    //the executor frames an unauthorized command on the wire. Used to bring the simulator operational.
    private static IMemoryOwner<byte> RentCommand(StartupInput input, MemoryPool<byte> pool, out int length)
    {
        length = TpmHeader.HeaderSize + input.GetSerializedSize();
        IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        return owner;
    }
}
