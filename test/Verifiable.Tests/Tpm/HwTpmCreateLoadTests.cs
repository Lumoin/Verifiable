using System;
using System.Buffers;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Tests for TPM2_Create / TPM2_Load against real hardware: mint a per-key object under a deterministic
/// storage parent, persist it as an opaque wrapped blob (never consuming TPM storage), and reload it on
/// demand into a transient slot. This is the EUDI WSCD model — one wrapped key per user/device, reloaded
/// per request and released with TPM2_FlushContext. The whole cycle is transient and writes nothing
/// durable, so it is safe on hardware.
/// </summary>
[TestClass]
[DoNotParallelize]
[SkipIfNoTpm]
[TestCategory("RequiresHardwareTpm")]
internal class HwTpmCreateLoadTests
{
    private static TpmDevice Tpm { get; set; } = null!;

    private static bool HasTpm { get; set; }

    public TestContext TestContext { get; set; } = null!;

    [ClassInitialize]
    public static void ClassInit(TestContext context)
    {
        if(TpmDevice.IsAvailable)
        {
            HasTpm = true;
            Tpm = TpmDevice.Open();
        }
    }

    [TestInitialize]
    public void TestInit()
    {
        if(!HasTpm)
        {
            Assert.Inconclusive(TestInfrastructureConstants.NoTpmDeviceAvailableMessage);
        }
    }

    [ClassCleanup]
    public static void ClassCleanup()
    {
        if(HasTpm)
        {
            Tpm.Dispose();
        }
    }

    [TestMethod]
    public async Task CreateChildThenLoadRoundTrips()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);
        _ = registry.Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        //1. Create the deterministic storage parent under the owner hierarchy.
        using var parentInput = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool);
        using var ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> parentResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            Tpm, parentInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        AssertUtilities.AssertSuccess(parentResult, "CreatePrimary storage parent");
        using CreatePrimaryResponse parent = parentResult.Value;
        uint parentHandle = parent.ObjectHandle.Value;
        TestContext.WriteLine($"Storage parent handle: 0x{parentHandle:X8}");

        try
        {
            //2. Mint a child signing key under the parent. The parent has empty auth, so a child is
            //authorized with an empty password session.
            using var createInput = CreateInput.ForEccSigningChild(
                parentHandle, null, TpmEccCurveConstants.TPM_ECC_NIST_P256,
                TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool);
            using var parentAuth = TpmPasswordSession.CreateEmpty(pool);

            TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                Tpm, createInput, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            AssertUtilities.AssertSuccess(createResult, "Create child key");

            using CreateResponse created = createResult.Value;
            Assert.IsFalse(created.OutPrivate.IsEmpty, "Create must return a wrapped private blob.");
            Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECC, created.OutPublic.PublicArea.Type);
            TestContext.WriteLine($"Minted child: private blob {created.OutPrivate.Length} bytes.");

            //3. Load the wrapped blob back, then reload it: the SAME blob yields the SAME object Name (a
            //different transient handle), so the per-request reload model is repeatable. Each load persists
            //the blob + public area exactly as a disk store would.
            byte[] firstName = await LoadAndFlushAsync(created, parentHandle, pool, registry).ConfigureAwait(false);
            byte[] secondName = await LoadAndFlushAsync(created, parentHandle, pool, registry).ConfigureAwait(false);

            Assert.IsNotEmpty(firstName, "The loaded object Name must be non-empty.");
            Assert.AreSequenceEqual(firstName, secondName, "Reloading the same blob must produce the same Name.");
        }
        finally
        {
            await FlushAsync(parentHandle, pool, registry).ConfigureAwait(false);
        }
    }

    //Loads a freshly-wrapped child from its CreateResponse and returns the loaded object Name, then flushes
    //the transient handle. The private blob is copied and the public area is reserialized, mirroring the
    //persist-then-reload disk round-trip the deployment model performs.
    private async Task<byte[]> LoadAndFlushAsync(CreateResponse created, uint parentHandle, MemoryPool<byte> pool, TpmResponseRegistry registry)
    {
        using Tpm2bPrivate inPrivate = Tpm2bPrivate.Create(created.OutPrivate.Span, pool);
        using Tpm2bPublic inPublic = ClonePublic(created.OutPublic, pool);
        using var loadInput = new LoadInput(parentHandle, inPrivate, inPublic);
        using var parentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<LoadResponse> loadResult = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
            Tpm, loadInput, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        AssertUtilities.AssertSuccess(loadResult, "Load child key");

        using LoadResponse loaded = loadResult.Value;
        uint handle = loaded.ObjectHandle.Value;
        Assert.AreEqual((byte)TpmHt.TPM_HT_TRANSIENT, (byte)(handle >> 24), "A loaded object handle must be transient.");
        Assert.IsFalse(loaded.Name.IsEmpty, "A loaded object must have a Name.");
        byte[] name = loaded.Name.Span.ToArray();
        TestContext.WriteLine($"Loaded child handle 0x{handle:X8}, Name {name.Length} bytes.");

        await FlushAsync(handle, pool, registry).ConfigureAwait(false);

        return name;
    }

    private async Task FlushAsync(uint handle, MemoryPool<byte> pool, TpmResponseRegistry registry)
    {
        var flushInput = FlushContextInput.ForHandle(handle);
        TpmResult<FlushContextResponse> flushResult = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            Tpm, flushInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(flushResult.IsSuccess, $"FlushContext failed: '{flushResult.ResponseCode}'.");
    }

    //Reserializes a public area into a fresh Tpm2bPublic, the round-trip a disk-persisted public blob makes.
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
