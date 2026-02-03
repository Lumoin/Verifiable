using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Tpm;


/// <summary>
/// Tests for TPM2_GetRandom command.
/// </summary>
[TestClass]
[DoNotParallelize]
[TestCategory("RequiresHardwareTpm")]
public class HwTpmRandomTests
{
    /// <summary>
    /// The TPM device for the tests.
    /// </summary>
    private static TpmDevice Tpm { get; set; } = null!;

    /// <summary>
    /// Whether a TPM device is available.
    /// </summary>
    private static bool HasTpm { get; set; } = false;


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
    public void ExecutorReturnsRequestedBytes()
    {        
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        var registry = new TpmResponseRegistry();

        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);

        const int NumberOfRandomBytes = 16;
        var input = new GetRandomInput(NumberOfRandomBytes);

        TpmResult<GetRandomResponse> result = TpmCommandExecutor.Execute<GetRandomResponse>(
            Tpm,
            input,
            [],
            pool,
            registry);

        Assert.IsTrue(result.IsSuccess, $"Expected success, got: '{result.ResponseCode}'.");

        using GetRandomResponse response = result.Value;
        Assert.AreEqual(NumberOfRandomBytes, response.RandomBytes.Size);

        TestContext.WriteLine($"Random bytes: {Convert.ToHexString(response.RandomBytes.AsReadOnlySpan())}");
    }
}