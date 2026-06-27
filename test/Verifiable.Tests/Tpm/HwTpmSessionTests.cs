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
            null,
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
            null,
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
            null,
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
            null,
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
            null,
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
            Tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

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
                Tpm, getRandomInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(result.IsSuccess, $"GetRandom iteration {i} failed: '{result.ResponseCode}'.");

            using GetRandomResponse response = result.Value;
            Assert.AreEqual(RandomBytesPerIteration, response.RandomBytes.Size);

            TestContext.WriteLine($"Iteration {i}: {Convert.ToHexString(response.RandomBytes.AsReadOnlySpan())}");
        }

        //Flush session.
        var flushInput = FlushContextInput.ForHandle(startResponse.SessionHandle.Value);
        TpmResult<FlushContextResponse> flushResult = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            Tpm, flushInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

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


    [TestMethod]
    public async Task EncryptedGetRandomOverBoundXorSessionRoundTripsAgainstHardware()
    {
        //End-to-end XOR parameter encryption against the real TPM: a bound HMAC session negotiates XOR at
        //StartAuthSession and sets the encrypt attribute on GetRandom, so the TPM encrypts the randomBytes
        //response parameter. The session key (KDFa over the bind object's empty authValue and the start nonces)
        //keys BOTH the response HMAC the TPM emits and the XOR mask the TPM applies. The response HMAC verifying
        //here proves the host derived the TPM's exact session key and nonces; the XOR mask is the same KDFa over
        //the same key and nonces (label "XOR" rather than the auth HMAC's direct use) and is validated byte-for-
        //byte by the deterministic KAT, so a verified, correctly-sized decrypted response is end-to-end proof
        //the host decrypts what the TPM encrypted. The bind object is noDA, so a regression (diverged key) yields
        //TPM_RC_AUTH_FAIL without advancing this box's dictionary-attack counter.
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();

        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;
        TpmtSymDef xor = TpmtSymDef.Xor(SessionAlg);

        //Bind to a transient, noDA ECC object with empty auth, so sessionValue is unambiguously the session key.
        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER,
            null,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool,
            noDa: true);

        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            Tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = primaryResult.Value;
        uint objectHandle = primary.ObjectHandle.Value;

        try
        {
            //Start a bound session that negotiates XOR parameter encryption.
            StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(objectHandle, SessionAlg, xor);

            TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                Tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (bound, XOR) failed: '{startResult.ResponseCode}'.");

            //nonceTPM ownership transfers to the session below.
            StartAuthSessionResponse startResponse = startResult.Value;

            Tpm2bAuth bindAuth = Tpm2bAuth.CreateEmpty(pool);
            try
            {
                using var session = await TpmSession.CreateBoundAsync(
                    new TpmHandle(startResponse.SessionHandle.Value),
                    bindAuth.AsReadOnlyMemory(),
                    startInput.NonceCaller,
                    startResponse.NonceTPM,
                    SessionAlg,
                    pool,
                    symmetric: xor,
                    cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

                //The encrypt attribute makes the TPM verify this handle-less session's command HMAC and encrypt
                //the response parameter; a wrong host-derived session key surfaces as TPM_RC_AUTH_FAIL.
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT;

                const int NumberOfRandomBytes = 32;
                var getRandomInput = new GetRandomInput(NumberOfRandomBytes);

                try
                {
                    TpmResult<GetRandomResponse> randomResult = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                        Tpm, getRandomInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                    Assert.IsTrue(randomResult.IsSuccess,
                        $"Encrypted GetRandom failed: '{randomResult.ResponseCode}'. A failure means the host-derived session key or XOR mask diverged from the TPM's.");

                    using GetRandomResponse randomResponse = randomResult.Value;
                    Assert.AreEqual(NumberOfRandomBytes, randomResponse.RandomBytes.Size,
                        "Parameter encryption must not change the parameter length.");
                    TestContext.WriteLine($"Decrypted random bytes: {Convert.ToHexString(randomResponse.RandomBytes.AsReadOnlySpan())}");
                }
                finally
                {
                    //Flush the loaded session even if an assertion above fails (the documented AUTH_FAIL
                    //regression path), so a failing run never leaks a TPM session slot on this hardware.
                    var flushSession = FlushContextInput.ForHandle(startResponse.SessionHandle.Value);
                    _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                        Tpm, flushSession, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                }
            }
            finally
            {
                bindAuth.Dispose();
            }
        }
        finally
        {
            var flushObject = FlushContextInput.ForHandle(objectHandle);
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                Tpm, flushObject, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        }
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
            Tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

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
                Tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

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
                    cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

                //Use the bound session to audit GetRandom (no auth handle, so the session keys off sessionKey
                //only). The AUDIT attribute is load-bearing: it is what makes the TPM verify the command HMAC of
                //this handle-less session, so a wrong host-derived session key surfaces as TPM_RC_AUTH_FAIL -
                //that is exactly what turns this into a host-vs-TPM session-key equality oracle.
                session.SessionAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT;

                const int NumberOfRandomBytes = 32;
                var getRandomInput = new GetRandomInput(NumberOfRandomBytes);

                TpmResult<GetRandomResponse> randomResult = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                    Tpm, getRandomInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(randomResult.IsSuccess,
                    $"Bound-session GetRandom failed: '{randomResult.ResponseCode}'. A failure here means the host-derived bound session key diverged from the TPM's.");

                using GetRandomResponse randomResponse = randomResult.Value;
                Assert.AreEqual(NumberOfRandomBytes, randomResponse.RandomBytes.Size);
                TestContext.WriteLine($"Bound-session random bytes: {Convert.ToHexString(randomResponse.RandomBytes.AsReadOnlySpan())}");

                //Flush the session.
                var flushSession = FlushContextInput.ForHandle(startResponse.SessionHandle.Value);
                TpmResult<FlushContextResponse> flushSessionResult = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                    Tpm, flushSession, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

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
                Tpm, flushObject, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }


    [TestMethod]
    public async Task HmacSessionAuthorizingObjectComputesCpHashOverEntityName()
    {
        //cpHash is computed over entity NAMES, not handle values (Part 1 eq 15). This authorizes a storage
        //PARENT OBJECT (whose Name is nameAlg||H(public), not its handle) over an HMAC session via TPM2_Create:
        //the command HMAC only verifies when the executor feeds the parent's Name into cpHash. The fail-fast
        //refusal to authorize an object without its Name is covered deterministically in TpmCommandExecutorTests;
        //here the real TPM confirms the positive direction end-to-end. The parent is noDA, so a regression that
        //produced a wrong cpHash would return BAD_AUTH without advancing this box's dictionary-attack counter.
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        const string ParentSecret = "parent-secret";
        const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, ParentSecret, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> parentResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            Tpm, parentInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(parentResult.IsSuccess, $"CreatePrimary storage parent failed: '{parentResult.ResponseCode}'.");

        using CreatePrimaryResponse parent = parentResult.Value;
        uint parentHandle = parent.ObjectHandle.Value;

        //The Name is a public identifier (a hash of the public area), not key material.
        ReadOnlyMemory<byte> parentName = parent.Name.Span.ToArray();
        byte[] parentAuth = System.Text.Encoding.UTF8.GetBytes(ParentSecret);

        try
        {
            bool withName = await CreateChildUnderParentAsync(parentHandle, parentAuth, [parentName], SessionAlg, pool, registry).ConfigureAwait(false);
            Assert.IsTrue(withName, "Create over an HMAC session must succeed when cpHash is computed over the parent's Name.");
        }
        finally
        {
            var flushParent = FlushContextInput.ForHandle(parentHandle);
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                Tpm, flushParent, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }


    /// <summary>
    /// Starts a fresh unbound HMAC session that authorizes <paramref name="parentHandle"/> with
    /// <paramref name="parentAuth"/>, runs TPM2_Create of a child under it (optionally supplying the parent
    /// Name for cpHash), and returns whether Create succeeded. The session is flushed before return; on
    /// success the wrapped child blob is disposed (TPM2_Create loads nothing).
    /// </summary>
    private async Task<bool> CreateChildUnderParentAsync(
        uint parentHandle,
        byte[] parentAuth,
        IReadOnlyList<ReadOnlyMemory<byte>>? handleNames,
        TpmAlgIdConstants sessionAlg,
        MemoryPool<byte> pool,
        TpmResponseRegistry registry)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(sessionAlg);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            Tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        //nonceTPM ownership transfers to the session, so this response is deliberately not disposed.
        StartAuthSessionResponse startResponse = startResult.Value;
        using var session = new TpmSession(
            new TpmHandle(startResponse.SessionHandle.Value), startResponse.NonceTPM, sessionAlg, pool);
        session.SetAuthValue(parentAuth, pool);

        try
        {
            using var createInput = CreateInput.ForEccSigningChild(
                parentHandle, null, TpmEccCurveConstants.TPM_ECC_NIST_P256,
                TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool);

            TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                Tpm, createInput, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            if(createResult.IsSuccess)
            {
                using CreateResponse created = createResult.Value;
                TestContext.WriteLine($"Create succeeded: wrapped child blob {created.OutPrivate.Length} bytes.");

                return true;
            }

            TestContext.WriteLine($"Create rejected (expected for the control run): '{createResult.ResponseCode}'.");

            return false;
        }
        finally
        {
            var flushSession = FlushContextInput.ForHandle(startResponse.SessionHandle.Value);
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                Tpm, flushSession, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }
}
