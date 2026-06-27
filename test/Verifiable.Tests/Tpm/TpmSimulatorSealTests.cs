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
/// Acceptance test for TPM sealing ("tie a secret to this computer") against the TCG ms-tpm-20-ref software
/// TPM simulator: seal a secret under a deterministic per-TPM storage parent and recover it with
/// <c>TPM2_Unseal()</c> over a maximum-security channel.
/// </summary>
/// <remarks>
/// <para>
/// The flow exercises the production command path end to end: <c>TPM2_CreatePrimary</c> mints the storage
/// parent, <c>TPM2_Create</c> seals the secret into a KEYEDHASH object
/// (<see cref="Tpm2bPublic.CreateSealedDataTemplate"/> + <see cref="Tpm2bSensitiveCreate.ForSealedData"/>),
/// <c>TPM2_Load</c> brings the wrapped object back into a transient slot, and <c>TPM2_Unseal</c> recovers the
/// data. The wrapped blob is persisted-and-reloaded through wire bytes only (the private blob is copied and the
/// public area reserialized), mirroring the disk round-trip a real deployment performs - the unseal shares no
/// in-memory object with the seal step beyond those bytes.
/// </para>
/// <para>
/// The unseal runs under a bound HMAC session that negotiated AES-CFB parameter encryption with the
/// <c>encrypt</c> attribute set, so the recovered secret (<c>outData</c>) is encrypted on the wire and the
/// executor decrypts it only after the response HMAC verifies (TPM 2.0 Library Part 1, Section 19). A broken
/// session key, nonce, or AES-CFB transform would either fail the response-HMAC check or yield a buffer that
/// does not equal the sealed secret, so the byte-exact equality assertion confirms the protected channel
/// end to end against a genuine TPM.
/// </para>
/// <para>
/// The test is gated on a running simulator (start the container from
/// <c>test/Verifiable.Tests/TestInfrastructure/TpmSimulator/Dockerfile</c>, publishing ports 2321/2322); it
/// reports <see cref="Assert.Inconclusive(string)"/> when none is reachable, so it is safe in any run.
/// </para>
/// </remarks>
[ConditionalTestClass]
[SkipIfNoTpmSimulator]
[DoNotParallelize]
[TestCategory("RequiresTpmSimulator")]
internal sealed class TpmSimulatorSealTests
{
    /// <summary>
    /// The connection to the simulator, established once for the class.
    /// </summary>
    private static MsTpmSimulatorConnection? Connection { get; set; }

    /// <summary>
    /// The TPM device created over the simulator connection.
    /// </summary>
    private static TpmDevice? Tpm { get; set; }

    /// <summary>
    /// Whether a simulator was reachable at class initialization.
    /// </summary>
    private static bool HasSimulator { get; set; }

    /// <summary>
    /// The fixed secret sealed and recovered by the test.
    /// </summary>
    private static byte[] SecretBytes { get; } = "Tie this secret to the TPM."u8.ToArray();

    /// <summary>
    /// Gets or sets the per-test context (supplies the cancellation token).
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Connects to the simulator (if one is reachable) and brings up a TPM device for the class.
    /// </summary>
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

    /// <summary>
    /// Releases the TPM device and simulator connection.
    /// </summary>
    [ClassCleanup]
    public static void ClassCleanup()
    {
        Tpm?.Dispose();
        Connection?.Dispose();
    }

    /// <summary>
    /// Skips the test when no simulator is reachable.
    /// </summary>
    [TestInitialize]
    public void TestInit()
    {
        if(!HasSimulator)
        {
            Assert.Inconclusive("No TPM simulator is reachable on localhost:2321/2322. Start the container from TestInfrastructure/TpmSimulator/Dockerfile.");
        }
    }

    [TestMethod]
    public async Task SealedSecretUnsealsOverEncryptedChannelAgainstSimulator()
    {
        TpmDevice tpm = Tpm!;
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);
        _ = registry.Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_Unseal, TpmResponseCodec.Unseal);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;
        TpmtSymDef symmetric = TpmtSymDef.Aes(128, TpmAlgIdConstants.TPM_ALG_CFB);

        //1. Create the deterministic storage parent under the owner hierarchy.
        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> parentResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, parentInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(parentResult.IsSuccess, $"CreatePrimary storage parent failed: '{parentResult.ResponseCode}'.");

        using CreatePrimaryResponse parent = parentResult.Value;
        uint parentHandle = parent.ObjectHandle.Value;

        try
        {
            //2. Seal the secret into a KEYEDHASH object under the parent. The parent has empty auth, so the new
            //object is authorized with an empty password session. The redundant using locals satisfy CA2000 and
            //are safe via idempotent disposal (CreateInput also owns and disposes them).
            //noDa: the seal carries an empty authValue (nothing to brute-force), so dictionary-attack protection
            //is moot; it also avoids the simulator's once-per-reset daUsed write, which returns TPM_RC_RETRY on
            //the first DA-protected authorization. A PIN-protected seal would keep DA protection (the default).
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
            Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_KEYEDHASH, sealedObject.OutPublic.PublicArea.Type);

            //3. Persist-then-reload through wire bytes only: copy the private blob and reserialize the public
            //area, the disk round-trip a real deployment performs, then TPM2_Load the wrapped object.
            using Tpm2bPrivate inPrivate = Tpm2bPrivate.Create(sealedObject.OutPrivate.Span, pool);
            using Tpm2bPublic inPublic = ClonePublic(sealedObject.OutPublic, pool);
            using LoadInput loadInput = new(parentHandle, inPrivate, inPublic);
            using TpmPasswordSession loadParentAuth = TpmPasswordSession.CreateEmpty(pool);

            TpmResult<LoadResponse> loadResult = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
                tpm, loadInput, [loadParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(loadResult.IsSuccess, $"Load (sealed object) failed: '{loadResult.ResponseCode}'.");

            using LoadResponse loaded = loadResult.Value;
            uint itemHandle = loaded.ObjectHandle.Value;

            //The object's Name is needed for cpHash when authorizing it over an HMAC session (Part 1 eq 15);
            //copy it out of the response so it survives the response's disposal.
            ReadOnlyMemory<byte>[] handleNames = [loaded.Name.Span.ToArray()];

            //4. Start a session bound to the loaded sealed object, negotiating AES-CFB. The bind gives the
            //session a real key (enabling parameter encryption); since the object's authValue is empty, the bound
            //session also authorizes the unseal of that same object.
            StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(itemHandle, SessionAlg, symmetric);

            TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (bound) failed: '{startResult.ResponseCode}'.");

            //nonceTPM ownership transfers to the session below.
            StartAuthSessionResponse startResponse = startResult.Value;
            uint sessionHandle = startResponse.SessionHandle.Value;

            try
            {
                using Tpm2bAuth bindAuth = Tpm2bAuth.CreateEmpty(pool);
                using var session = await TpmSession.CreateBoundAsync(
                    new TpmHandle(sessionHandle),
                    bindAuth.AsReadOnlyMemory(),
                    startInput.NonceCaller,
                    startResponse.NonceTPM,
                    SessionAlg,
                    pool,
                    symmetric: symmetric,
                    cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

                //CONTINUE_SESSION keeps the session for the explicit flush below; ENCRYPT protects the recovered
                //secret (outData), the confidential first response parameter, on the wire.
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                //5. Unseal over the encrypted channel and confirm the recovered secret matches byte for byte.
                UnsealInput unsealInput = UnsealInput.ForItem(loaded.ObjectHandle);

                TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                    tpm, unsealInput, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(unsealResult.IsSuccess,
                    $"Unseal over a bound AES-CFB encrypt session failed: '{unsealResult.ResponseCode}'. A failure means the host-derived session key, nonces, or parameter-decryption transform diverged from the simulator's.");

                using UnsealResponse unsealed = unsealResult.Value;
                Assert.IsTrue(unsealed.OutData.AsReadOnlySpan().SequenceEqual(SecretBytes),
                    "The unsealed data, decrypted from the encrypted response parameter, must equal the sealed secret.");
            }
            finally
            {
                await FlushAsync(tpm, registry, sessionHandle, pool).ConfigureAwait(false);
                await FlushAsync(tpm, registry, itemHandle, pool).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, parentHandle, pool).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Flushes a transient object or session handle, ignoring the result.
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
