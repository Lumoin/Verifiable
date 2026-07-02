using System;
using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives TPM sealing ("tie a secret to this computer") against the in-house behavioural
/// <see cref="TpmSimulator"/> — entirely in-process, with no external assets — through the same production command
/// path the production code uses (<see cref="TpmCommandExecutor"/> with the real <see cref="CreateInput"/>,
/// <see cref="LoadInput"/>, <see cref="UnsealInput"/>, and response codecs): <c>TPM2_CreatePrimary()</c> mints an
/// ECC storage parent, <c>TPM2_Create()</c> seals a secret into a KEYEDHASH object, <c>TPM2_Load()</c> brings the
/// wrapped object back into a transient slot, and <c>TPM2_Unseal()</c> recovers the data.
/// </summary>
/// <remarks>
/// <para>
/// The wrapped blob is persisted-and-reloaded through wire bytes only (the private blob is copied and the public
/// area reserialized), mirroring the disk round-trip a real deployment performs — the unseal shares no in-memory
/// object with the seal step beyond those bytes, so a divergence between what the simulator framed and what a
/// genuine TPM would return fails the byte-exact equality assertion.
/// </para>
/// <para>
/// The simulator models the sealed-data path under password authorization; it does not model the bound HMAC
/// session with AES-CFB parameter encryption a full unseal runs over, so the recovered secret is returned in the
/// clear on the (in-process) wire rather than over an encrypted channel. The parameter-encryption channel is a
/// separate concern exercised elsewhere.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorSealTests
{
    /// <summary>The session/name hash algorithm used throughout.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The fixed secret sealed and recovered by the test.</summary>
    private static byte[] SecretBytes { get; } = "Tie this secret to the in-house TPM."u8.ToArray();

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public async Task SealedSecretUnsealsAgainstInHouseSimulator()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //1. Create the storage parent under the owner hierarchy.
        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;

        //2. Seal the secret into a KEYEDHASH object under the parent. The parent has empty auth, so the new object
        //is authorized with an empty password session. noDa: the seal carries an empty authValue (nothing to
        //brute-force), so dictionary-attack protection is moot.
        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, pool);
        using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, noDa: true);
        using CreateInput createInput = new(
            parentHandle,
            inSensitive,
            sealTemplate,
            Tpm2bData.Empty,
            TpmlPcrSelection.Empty);
        using TpmPasswordSession createParentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, createInput, [createParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"Create (seal) failed: '{createResult.ResponseCode}'.");

        using CreateResponse sealedObject = createResult.Value;
        Assert.IsFalse(sealedObject.OutPrivate.IsEmpty, "Sealing must return a wrapped private blob.");
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_KEYEDHASH, sealedObject.OutPublic.PublicArea.Type, "The sealed object must be a KEYEDHASH object.");

        //3. Persist-then-reload through wire bytes only: copy the private blob and reserialize the public area, the
        //disk round-trip a real deployment performs, then TPM2_Load the wrapped object.
        using Tpm2bPrivate inPrivate = Tpm2bPrivate.Create(sealedObject.OutPrivate.Span, pool);
        using Tpm2bPublic inPublic = ClonePublic(sealedObject.OutPublic, pool);
        using LoadInput loadInput = new(parentHandle, inPrivate, inPublic);
        using TpmPasswordSession loadParentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<LoadResponse> loadResult = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
            tpm, loadInput, [loadParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"Load (sealed object) failed: '{loadResult.ResponseCode}'.");

        using LoadResponse loaded = loadResult.Value;
        Assert.IsFalse(loaded.Name.Span.IsEmpty, "Load must return the loaded object's Name.");

        //4. Unseal over a password session and confirm the recovered secret matches byte for byte. The sealed
        //object's authValue is empty, so the empty password session authorizes the unseal.
        using TpmPasswordSession itemAuth = TpmPasswordSession.CreateEmpty(pool);
        UnsealInput unsealInput = UnsealInput.ForItem(loaded.ObjectHandle);

        TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
            tpm, unsealInput, [itemAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(unsealResult.IsSuccess, $"Unseal failed: '{unsealResult.ResponseCode}'.");

        using UnsealResponse unsealed = unsealResult.Value;
        Assert.IsTrue(
            unsealed.OutData.AsReadOnlySpan().SequenceEqual(SecretBytes),
            "The unsealed data must equal the sealed secret, byte for byte, recovered from the wire blob alone.");
    }

    [TestMethod]
    public async Task UnsealWithUnknownItemHandleReturnsHandle()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //No object was loaded, so the transient handle does not resolve (TPM 2.0 Part 3, clause 12.7).
        using TpmPasswordSession itemAuth = TpmPasswordSession.CreateEmpty(pool);
        UnsealInput unsealInput = UnsealInput.ForItem(TpmiDhObject.FromValue(TpmSimulatorState.TransientHandleBase));

        TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
            tpm, unsealInput, [itemAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, unsealResult.ResponseCode);
    }

    [TestMethod]
    public async Task SealUnderNonStorageParentReturnsType()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //A signing key is not a restricted storage key, so it cannot parent a TPM2_Create() child: the seal is
        //rejected with TPM_RC_TYPE (TPM 2.0 Part 3, clause 12.1).
        using CreatePrimaryInput signingInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> signingResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, signingInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signingResult.IsSuccess, $"CreatePrimary (ECC signing key) failed: '{signingResult.ResponseCode}'.");

        using CreatePrimaryResponse signingKey = signingResult.Value;

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SecretBytes, pool);
        using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, noDa: true);
        using CreateInput createInput = new(
            signingKey.ObjectHandle.Value,
            inSensitive,
            sealTemplate,
            Tpm2bData.Empty,
            TpmlPcrSelection.Empty);
        using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, createInput, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_TYPE, createResult.ResponseCode);
    }

    /// <summary>
    /// Creates the deterministic ECC storage parent under the owner hierarchy and returns the response (the caller
    /// owns it).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response for the storage parent.</returns>
    private async Task<CreatePrimaryResponse> CreateStorageParentAsync(TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool)
    {
        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> parentResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, parentInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(parentResult.IsSuccess, $"CreatePrimary storage parent failed: '{parentResult.ResponseCode}'.");

        return parentResult.Value;
    }

    /// <summary>
    /// Creates a simulator with the ECC (BouncyCastle) signing backend wired, powers it on, and brings it through
    /// <c>TPM2_Startup(CLEAR)</c> into the operational phase. The ECC backend is required so the simulator services
    /// <c>TPM2_CreatePrimary()</c>; the storage parent is used only as a handle to parent the sealed object here.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(MemoryPool<byte> pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-seal", signingBackend: BouncyCastleTpmEccSigningBackend.Create());
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>
    /// Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator, mirroring how the executor frames an
    /// unauthorized command on the wire, to move it into <see cref="TpmLifecyclePhase.Operational"/>.
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
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code);
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase);
    }

    /// <summary>Creates a response codec registry covering the commands these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);
        _ = registry.Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load);
        _ = registry.Register(TpmCcConstants.TPM_CC_Unseal, TpmResponseCodec.Unseal);

        return registry;
    }

    /// <summary>
    /// Reserializes a public area into a fresh <see cref="Tpm2bPublic"/>, the round-trip a disk-persisted public
    /// blob makes; keeps the seal and unseal steps firewalled to wire bytes.
    /// </summary>
    /// <param name="source">The public area to clone.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>An independent copy of the public area.</returns>
    private static Tpm2bPublic ClonePublic(Tpm2bPublic source, MemoryPool<byte> pool)
    {
        int size = source.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(size);
        var writer = new TpmWriter(owner.Memory.Span);
        source.WriteTo(ref writer);

        var reader = new TpmReader(owner.Memory.Span[..size]);

        return Tpm2bPublic.Parse(ref reader, pool);
    }
}
