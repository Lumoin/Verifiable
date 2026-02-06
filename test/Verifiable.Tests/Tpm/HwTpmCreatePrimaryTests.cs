using System.Buffers;
using Verifiable.Cryptography;
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
/// Tests for TPM2_CreatePrimary command.
/// </summary>
[TestClass]
[DoNotParallelize]
[SkipIfNoTpm]
[TestCategory("RequiresHardwareTpm")]
internal class HwTpmCreatePrimaryTests
{
    /// <summary>
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
    public void CreatePrimaryEccSigningKeySucceeds()
    {        
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        var registry = new TpmResponseRegistry();

        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        using var input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER,
            null,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool);

        //Owner hierarchy typically has empty auth on fresh TPMs.
        using var ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = TpmCommandExecutor.Execute<CreatePrimaryResponse>(
            Tpm,
            input,
            [ownerAuth],
            pool,
            registry);

        AssertUtilities.AssertSuccess(result, "CreatePrimary");

        using CreatePrimaryResponse response = result.Value;

        TestContext.WriteLine($"Created ECC key handle: 0x{response.ObjectHandle.Value:X8}");
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECC, response.OutPublic.PublicArea.Type);
        TestContext.WriteLine($"Key type: {response.OutPublic.PublicArea.Type}, nameAlg: {response.OutPublic.PublicArea.NameAlg}");

        Assert.IsFalse(response.Name.IsEmpty, "Name should not be empty.");
        TestContext.WriteLine($"Key name ({response.Name.Size} bytes): {Convert.ToHexString(response.Name.Span)}");

        //Clean up: flush the key.
        var flushInput = FlushContextInput.ForHandle(response.ObjectHandle.Value);
        TpmResult<FlushContextResponse> flushResult = TpmCommandExecutor.Execute<FlushContextResponse>(
            Tpm,
            flushInput,
            [],
            pool,
            registry);

        Assert.IsTrue(flushResult.IsSuccess, $"FlushContext failed: '{flushResult.ResponseCode}'.");
    }


    [TestMethod]
    public void CreatePrimaryRsaSigningKeySucceeds()
    {        
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        var registry = new TpmResponseRegistry();

        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        using var input = CreatePrimaryInput.ForRsaSigningKey(
            TpmRh.TPM_RH_OWNER,
            null,
            2048,
            TpmtRsaScheme.Rsassa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool);

        using var ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = TpmCommandExecutor.Execute<CreatePrimaryResponse>(
            Tpm,
            input,
            [ownerAuth],
            pool,
            registry);

        AssertUtilities.AssertSuccess(result, "CreatePrimary");

        using CreatePrimaryResponse response = result.Value;

        TestContext.WriteLine($"Created RSA key handle: 0x{response.ObjectHandle.Value:X8}");
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_RSA, response.OutPublic.PublicArea.Type);
        TestContext.WriteLine($"Key type: {response.OutPublic.PublicArea.Type}, nameAlg: {response.OutPublic.PublicArea.NameAlg}");

        var flushInput = FlushContextInput.ForHandle(response.ObjectHandle.Value);
        TpmResult<FlushContextResponse> flushResult = TpmCommandExecutor.Execute<FlushContextResponse>(
            Tpm,
            flushInput,
            [],
            pool,
            registry);

        Assert.IsTrue(flushResult.IsSuccess, $"FlushContext failed: '{flushResult.ResponseCode}'.");
    }


    [TestMethod]
    public void CreatePrimaryWithPasswordSucceeds()
    {        
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        var registry = new TpmResponseRegistry();

        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        //Create key with password for the key itself.
        using var input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER,
            "test-password",
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool);

        //Still need owner auth for hierarchy access.
        using var ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = TpmCommandExecutor.Execute<CreatePrimaryResponse>(
            Tpm,
            input,
            [ownerAuth],
            pool,
            registry);

        AssertUtilities.AssertSuccess(result, "CreatePrimary with password");

        using CreatePrimaryResponse response = result.Value;
        TestContext.WriteLine($"Created key with password, handle: 0x{response.ObjectHandle.Value:X8}");

        var flushInput = FlushContextInput.ForHandle(response.ObjectHandle.Value);
        TpmResult<FlushContextResponse> flushResult = TpmCommandExecutor.Execute<FlushContextResponse>(
            Tpm,
            flushInput,
            [],
            pool,
            registry);

        Assert.IsTrue(flushResult.IsSuccess, $"FlushContext failed: '{flushResult.ResponseCode}'.");
    }


    [TestMethod]
    public void CreatePrimarySameTemplateProducesSameKey()
    {        
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        var registry = new TpmResponseRegistry();

        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        byte[]? firstKeyName = null;
        byte[]? secondKeyName = null;

        for(int i = 0; i < 2; i++)
        {
            using var input = CreatePrimaryInput.ForEccSigningKey(
                TpmRh.TPM_RH_OWNER,
                null,
                TpmEccCurveConstants.TPM_ECC_NIST_P256,
                TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
                pool);

            using var ownerAuth = TpmPasswordSession.CreateEmpty(pool);

            TpmResult<CreatePrimaryResponse> result = TpmCommandExecutor.Execute<CreatePrimaryResponse>(
                Tpm,
                input,
                [ownerAuth],
                pool,
                registry);

            AssertUtilities.AssertSuccess(result, $"CreatePrimary iteration {i}");

            using CreatePrimaryResponse response = result.Value;

            if(i == 0)
            {
                firstKeyName = response.Name.Span.ToArray();
            }
            else
            {
                secondKeyName = response.Name.Span.ToArray();
            }

            var flushInput = FlushContextInput.ForHandle(response.ObjectHandle.Value);
            _ = TpmCommandExecutor.Execute<FlushContextResponse>(Tpm, flushInput, [], pool, registry);
        }

        Assert.IsNotNull(firstKeyName);
        Assert.IsNotNull(secondKeyName);
        CollectionAssert.AreEqual(firstKeyName, secondKeyName, "Same template should produce same key name.");
        TestContext.WriteLine($"Both keys have same name: {Convert.ToHexString(firstKeyName)}");
    }    
}