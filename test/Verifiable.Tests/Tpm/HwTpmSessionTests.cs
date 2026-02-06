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
    public void StartAuthSessionCreatesValidSession()
    {
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        var registry = new TpmResponseRegistry();

        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        //Create an unbound, unsalted HMAC session.
        var startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(TpmAlgIdConstants.TPM_ALG_SHA256);

        TpmResult<StartAuthSessionResponse> startResult = TpmCommandExecutor.Execute<StartAuthSessionResponse>(
            Tpm,
            startInput,
            [],
            pool,
            registry);

        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse response = startResult.Value;

        TestContext.WriteLine($"Session handle: 0x{response.SessionHandle.Value:X8}");
        Assert.IsFalse(response.NonceTPM.IsEmpty, "nonceTPM should not be empty.");
        TestContext.WriteLine($"nonceTPM ({response.NonceTPM.Size} bytes): {Convert.ToHexString(response.NonceTPM.AsReadOnlySpan())}");

        //Clean up: flush the session.
        var flushInput = FlushContextInput.ForHandle(response.SessionHandle.Value);
        TpmResult<FlushContextResponse> flushResult = TpmCommandExecutor.Execute<FlushContextResponse>(
            Tpm,
            flushInput,
            [],
            pool,
            registry);

        Assert.IsTrue(flushResult.IsSuccess, $"FlushContext failed: '{flushResult.ResponseCode}'.");
    }


    [TestMethod]
    public void GetRandomWithAuditSessionVerifiesIntegrity()
    {
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        var registry = new TpmResponseRegistry();

        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        //Step 1: Create an HMAC session.
        var startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(TpmAlgIdConstants.TPM_ALG_SHA256);

        TpmResult<StartAuthSessionResponse> startResult = TpmCommandExecutor.Execute<StartAuthSessionResponse>(
            Tpm,
            startInput,
            [],
            pool,
            registry);

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

        TpmResult<GetRandomResponse> randomResult = TpmCommandExecutor.Execute<GetRandomResponse>(
            Tpm,
            getRandomInput,
            [session],
            pool,
            registry);

        Assert.IsTrue(randomResult.IsSuccess, $"GetRandom with session failed: '{randomResult.ResponseCode}'.");

        using GetRandomResponse randomResponse = randomResult.Value;
        Assert.AreEqual(NumberOfRandomBytes, randomResponse.RandomBytes.Size);

        TestContext.WriteLine($"Random bytes: {Convert.ToHexString(randomResponse.RandomBytes.AsReadOnlySpan())}");

        //Step 4: Clean up.
        var flushInput = FlushContextInput.ForHandle(startResponse.SessionHandle.Value);
        TpmResult<FlushContextResponse> flushResult = TpmCommandExecutor.Execute<FlushContextResponse>(
            Tpm,
            flushInput,
            [],
            pool,
            registry);

        Assert.IsTrue(flushResult.IsSuccess, $"FlushContext failed: '{flushResult.ResponseCode}'.");
    }


    [TestMethod]
    public void MultipleCommandsWithSameSessionUpdateNonces()
    {
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        var registry = new TpmResponseRegistry();

        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        //Create session.
        var startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(TpmAlgIdConstants.TPM_ALG_SHA256);
        TpmResult<StartAuthSessionResponse> startResult = TpmCommandExecutor.Execute<StartAuthSessionResponse>(
            Tpm, startInput, [], pool, registry);

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
            TpmResult<GetRandomResponse> result = TpmCommandExecutor.Execute<GetRandomResponse>(
                Tpm, getRandomInput, [session], pool, registry);

            Assert.IsTrue(result.IsSuccess, $"GetRandom iteration {i} failed: '{result.ResponseCode}'.");

            using GetRandomResponse response = result.Value;
            Assert.AreEqual(RandomBytesPerIteration, response.RandomBytes.Size);

            TestContext.WriteLine($"Iteration {i}: {Convert.ToHexString(response.RandomBytes.AsReadOnlySpan())}");
        }

        //Flush session.
        var flushInput = FlushContextInput.ForHandle(startResponse.SessionHandle.Value);
        TpmResult<FlushContextResponse> flushResult = TpmCommandExecutor.Execute<FlushContextResponse>(
            Tpm, flushInput, [], pool, registry);

        Assert.IsTrue(flushResult.IsSuccess, $"FlushContext failed: '{flushResult.ResponseCode}'.");
    }
}