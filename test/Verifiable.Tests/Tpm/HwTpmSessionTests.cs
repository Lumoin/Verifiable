using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
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
/// Tests for TPM session functionality.
/// </summary>
[ConditionalTestClass]
[SkipIfNoTpm]
[DoNotParallelize]
[TestCategory("RequiresHardwareTpm")]
internal class HwTpmSessionTests
{
    // <summary>
    /// The TPM device for the tests.
    /// </summary>
    private static TpmDevice Tpm { get; set; } = null!;

    /// <summary>
    /// Whether a TPM device is available.
    /// </summary>
    private static bool HasTpm { get; set; }


    /// <summary>
    /// The test context.
    /// </summary>
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
    public async Task StartAuthSessionCreatesValidSession()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();

        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        //Create an unbound, unsalted HMAC session.
        var startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(TpmAlgIdConstants.TPM_ALG_SHA256);

        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            Tpm,
            startInput,
            [],
            pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse response = startResult.Value;

        TestContext.WriteLine($"Session handle: 0x{response.SessionHandle.Value:X8}");
        Assert.IsFalse(response.NonceTPM.IsEmpty, "nonceTPM should not be empty.");
        TestContext.WriteLine($"nonceTPM ({response.NonceTPM.Size} bytes): {Convert.ToHexString(response.NonceTPM.AsReadOnlySpan())}");

        //Clean up: flush the session.
        var flushInput = FlushContextInput.ForHandle(response.SessionHandle.Value);
        TpmResult<FlushContextResponse> flushResult = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            Tpm,
            flushInput,
            [],
            pool,
            registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(flushResult.IsSuccess, $"FlushContext failed: '{flushResult.ResponseCode}'.");
    }


    [TestMethod]
    public async Task GetRandomWithAuditSessionVerifiesIntegrity()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();

        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        //Step 1: Create an HMAC session.
        var startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(TpmAlgIdConstants.TPM_ALG_SHA256);

        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            Tpm,
            startInput,
            [],
            pool,
            registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse startResponse = startResult.Value;

        TestContext.WriteLine($"Session created: handle=0x{startResponse.SessionHandle.Value:X8}, nonceTPM={Convert.ToHexString(startResponse.NonceTPM.AsReadOnlySpan())}");

        //Step 2: Create TpmSession from the response.
        using var session = new TpmSession(
            new TpmHandle(startResponse.SessionHandle.Value),
            startResponse.NonceTPM,
            TpmAlgIdConstants.TPM_ALG_SHA256,
            pool);

        //Configure session for audit (integrity verification without authorization).
        session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

        //Step 3: Execute GetRandom with the session.
        const int NumberOfRandomBytes = 32;
        var getRandomInput = new GetRandomInput(NumberOfRandomBytes);

        TpmResult<GetRandomResponse> randomResult = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
            Tpm,
            getRandomInput,
            [session],
            pool,
            registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(randomResult.IsSuccess, $"GetRandom with session failed: '{randomResult.ResponseCode}'.");

        using GetRandomResponse randomResponse = randomResult.Value;
        Assert.AreEqual(NumberOfRandomBytes, randomResponse.RandomBytes.Size);

        TestContext.WriteLine($"Random bytes: {Convert.ToHexString(randomResponse.RandomBytes.AsReadOnlySpan())}");

        //Step 4: Clean up.
        var flushInput = FlushContextInput.ForHandle(startResponse.SessionHandle.Value);
        TpmResult<FlushContextResponse> flushResult = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            Tpm,
            flushInput,
            [],
            pool,
            registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(flushResult.IsSuccess, $"FlushContext failed: '{flushResult.ResponseCode}'.");
    }


    [TestMethod]
    public async Task MultipleCommandsWithSameSessionUpdateNonces()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();

        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        //Create session.
        var startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(TpmAlgIdConstants.TPM_ALG_SHA256);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            Tpm, startInput, [], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse startResponse = startResult.Value;

        using var session = new TpmSession(
            new TpmHandle(startResponse.SessionHandle.Value),
            startResponse.NonceTPM,
            TpmAlgIdConstants.TPM_ALG_SHA256,
            pool);

        session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

        //Execute GetRandom multiple times with the same session.
        const int RandomBytesPerIteration = 16;
        const int NumberOfIterations = 3;

        for(int i = 0; i < NumberOfIterations; i++)
        {
            var getRandomInput = new GetRandomInput(RandomBytesPerIteration);
            TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                Tpm, getRandomInput, [session], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(result.IsSuccess, $"GetRandom iteration {i} failed: '{result.ResponseCode}'.");

            using GetRandomResponse response = result.Value;
            Assert.AreEqual(RandomBytesPerIteration, response.RandomBytes.Size);

            TestContext.WriteLine($"Iteration {i}: {Convert.ToHexString(response.RandomBytes.AsReadOnlySpan())}");
        }

        //Flush session.
        var flushInput = FlushContextInput.ForHandle(startResponse.SessionHandle.Value);
        TpmResult<FlushContextResponse> flushResult = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            Tpm, flushInput, [], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(flushResult.IsSuccess, $"FlushContext failed: '{flushResult.ResponseCode}'.");
    }


    [TestMethod]
    public async Task BoundSessionToEmptyAuthObjectVerifiesResponseHmac()
    {
        //Binding to an empty-auth entity still derives a non-empty session key (KDFa over an empty key), so
        //this exercises the bound key derivation independently of the authValue path.
        await RunBoundSessionGetRandomAsync(bindPassword: null).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task BoundSessionToPasswordObjectVerifiesResponseHmac()
    {
        //Binding to an entity with a known authValue exercises the full
        //sessionKey = KDFa(bindAuthValue, "ATH", nonceTPM, nonceCaller) derivation: the TPM folds the object's
        //userAuth into the key, and only a byte-identical host derivation produces a verifiable HMAC.
        await RunBoundSessionGetRandomAsync(bindPassword: "bind-secret").ConfigureAwait(false);
    }


    /// <summary>
    /// Establishes a bound HMAC session against a freshly created, transient ECC object and runs an audited
    /// GetRandom through it. The command HMAC (which the TPM verifies) and the response HMAC (which
    /// <see cref="TpmSession.VerifyAndUpdateAsync"/> verifies) both key off the derived session key, so a
    /// successful result is end-to-end proof that the host and the TPM derived an identical bound session key.
    /// All commands are read-only/ephemeral (CreatePrimary in the owner hierarchy, StartAuthSession,
    /// GetRandom, FlushContext); the object and session are flushed before return.
    /// </summary>
    /// <param name="bindPassword">The bind object's authValue as a password, or <see langword="null"/> for empty auth.</param>
    private async Task RunBoundSessionGetRandomAsync(string? bindPassword)
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();

        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

        //Step 1: Create a transient bind object whose authValue is known to this test. The object is marked
        //noDA so that even a regression (host-derived session key diverging from the TPM's) yields
        //TPM_RC_BAD_AUTH rather than advancing this hardware TPM's dictionary-attack counter: binding to a
        //DA-protected object would make an auth failure tick the box toward lockout (Part 1 §17.6 / DA rules).
        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER,
            bindPassword,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool,
            noDa: true);

        //Owner hierarchy typically has empty auth on fresh TPMs.
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            Tpm, primaryInput, [ownerAuth], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = primaryResult.Value;
        uint objectHandle = primary.ObjectHandle.Value;
        TestContext.WriteLine($"Bind object handle: 0x{objectHandle:X8}, name {primary.Name.Size} bytes.");

        try
        {
            //Step 2: Start a bound HMAC session against the object. The generated nonceCaller is the one the
            //key derivation consumes, so it is read back from the input below.
            StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(objectHandle, SessionAlg);

            TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                Tpm, startInput, [], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (bound) failed: '{startResult.ResponseCode}'.");

            //nonceTPM ownership transfers to the session below, so this response is deliberately not disposed.
            StartAuthSessionResponse startResponse = startResult.Value;
            TestContext.WriteLine($"Bound session handle: 0x{startResponse.SessionHandle.Value:X8}.");

            //Step 3: Derive the bound session on the host from the object's authValue and the start nonces.
            Tpm2bAuth bindAuth = bindPassword is null
                ? Tpm2bAuth.CreateEmpty(pool)
                : Tpm2bAuth.CreateFromPassword(bindPassword, pool);

            try
            {
                using var session = await TpmSession.CreateBoundAsync(
                    new TpmHandle(startResponse.SessionHandle.Value),
                    bindAuth.AsReadOnlyMemory(),
                    startInput.NonceCaller,
                    startResponse.NonceTPM,
                    SessionAlg,
                    pool,
                    TestContext.CancellationToken).ConfigureAwait(false);

                //Use the bound session to audit GetRandom (no auth handle, so the session keys off sessionKey
                //only). The AUDIT attribute is load-bearing: it is what makes the TPM verify the command HMAC of
                //this handle-less session, so a wrong host-derived session key surfaces as TPM_RC_AUTH_FAIL -
                //that is exactly what turns this into a host-vs-TPM session-key equality oracle.
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                const int NumberOfRandomBytes = 32;
                var getRandomInput = new GetRandomInput(NumberOfRandomBytes);

                TpmResult<GetRandomResponse> randomResult = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                    Tpm, getRandomInput, [session], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(randomResult.IsSuccess,
                    $"Bound-session GetRandom failed: '{randomResult.ResponseCode}'. A failure here means the host-derived bound session key diverged from the TPM's.");

                using GetRandomResponse randomResponse = randomResult.Value;
                Assert.AreEqual(NumberOfRandomBytes, randomResponse.RandomBytes.Size);
                TestContext.WriteLine($"Bound-session random bytes: {Convert.ToHexString(randomResponse.RandomBytes.AsReadOnlySpan())}");

                //Flush the session.
                var flushSession = FlushContextInput.ForHandle(startResponse.SessionHandle.Value);
                TpmResult<FlushContextResponse> flushSessionResult = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                    Tpm, flushSession, [], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(flushSessionResult.IsSuccess, $"FlushContext (session) failed: '{flushSessionResult.ResponseCode}'.");
            }
            finally
            {
                bindAuth.Dispose();
            }
        }
        finally
        {
            //Flush the transient bind object regardless of the outcome above.
            var flushObject = FlushContextInput.ForHandle(objectHandle);
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                Tpm, flushObject, [], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }
}
