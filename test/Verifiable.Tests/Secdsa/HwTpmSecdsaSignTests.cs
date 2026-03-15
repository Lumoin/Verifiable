using System.Buffers;
using System.Numerics;
using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Secdsa;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.Tpm;
using Verifiable.Tpm;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Secdsa;

/// <summary>
/// Hardware TPM tests for the SECDSA signing path: TPM2_Sign followed by
/// verification using pure .NET EC math.
/// </summary>
[TestClass]
[DoNotParallelize]
[SkipIfNoTpm]
[TestCategory("RequiresHardwareTpm")]
internal sealed class HwTpmSecdsaSignTests
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
    public void TpmSignsDigestAndPureNetVerifies()
    {
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        var registry = new TpmResponseRegistry();

        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);
        _ = registry.Register(TpmCcConstants.TPM_CC_Sign, TpmResponseCodec.Sign);

        using CreatePrimaryInput createInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER,
            null,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool);

        using var ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> createResult = TpmCommandExecutor.Execute<CreatePrimaryResponse>(
            Tpm, createInput, [ownerAuth], pool, registry);

        AssertUtilities.AssertSuccess(createResult, "CreatePrimary");

        using CreatePrimaryResponse createResponse = createResult.Value;

        TpmiDhObject keyHandle = createResponse.ObjectHandle;
        byte[] publicPoint = ExtractEccPublicPoint(createResponse.OutPublic);

        byte[] digest = SHA256.HashData("SECDSA TPM sign test."u8);

        using SignInput signInput = SignInput.ForEcdsa(
            keyHandle, digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        using var keyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<SignResponse> signResult = TpmCommandExecutor.Execute<SignResponse>(
            Tpm, signInput, [keyAuth], pool, registry);

        AssertUtilities.AssertSuccess(signResult, "TPM2_Sign");

        using SignResponse signResponse = signResult.Value;

        BigInteger r = new BigInteger(signResponse.SignatureR.AsReadOnlySpan(), isUnsigned: true, isBigEndian: true);
        BigInteger s = new BigInteger(signResponse.SignatureS.AsReadOnlySpan(), isUnsigned: true, isBigEndian: true);

        EcPoint publicKey = EcMath.DecodePointUncompressed(publicPoint);
        bool valid = SecdsaAlgorithms.Verify(digest, new EcdsaSignature(r, s), publicKey);

        TestContext.WriteLine($"R = {Convert.ToHexString(signResponse.SignatureR.AsReadOnlySpan())}");
        TestContext.WriteLine($"S = {Convert.ToHexString(signResponse.SignatureS.AsReadOnlySpan())}");
        Assert.IsTrue(valid, "TPM-produced ECDSA signature must verify with pure .NET EC math.");

        var flushInput = FlushContextInput.ForHandle(keyHandle.Value);
        _ = TpmCommandExecutor.Execute<FlushContextResponse>(Tpm, flushInput, [], pool, registry);
    }

    [TestMethod]
    public void TpmReadPublicNameIsPresent()
    {
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        var registry = new TpmResponseRegistry();

        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);
        _ = registry.Register(TpmCcConstants.TPM_CC_ReadPublic, TpmResponseCodec.ReadPublic);

        using CreatePrimaryInput createInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER,
            null,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool);

        using var ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> createResult = TpmCommandExecutor.Execute<CreatePrimaryResponse>(
            Tpm, createInput, [ownerAuth], pool, registry);

        AssertUtilities.AssertSuccess(createResult, "CreatePrimary");

        using CreatePrimaryResponse createResponse = createResult.Value;

        TpmiDhObject keyHandle = createResponse.ObjectHandle;

        ReadPublicInput readInput = ReadPublicInput.ForHandle(keyHandle);

        TpmResult<ReadPublicResponse> readResult = TpmCommandExecutor.Execute<ReadPublicResponse>(
            Tpm, readInput, [], pool, registry);

        AssertUtilities.AssertSuccess(readResult, "TPM2_ReadPublic");

        using ReadPublicResponse readResponse = readResult.Value;

        Assert.IsFalse(readResponse.Name.IsEmpty, "Name from ReadPublic must not be empty.");
        TestContext.WriteLine($"Name ({readResponse.Name.Size} bytes): {Convert.ToHexString(readResponse.Name.Span)}");

        var flushInput = FlushContextInput.ForHandle(keyHandle.Value);
        _ = TpmCommandExecutor.Execute<FlushContextResponse>(Tpm, flushInput, [], pool, registry);
    }


    private static byte[] ExtractEccPublicPoint(Tpm2bPublic publicArea)
    {
        //Access the ECC unique field via TpmuPublicId.
        //The exact property path depends on the TpmuPublicId implementation.
        //Adjust if TpmuPublicId exposes ECC coordinates differently.
        ReadOnlySpan<byte> x = publicArea.PublicArea.Unique.Ecc!.X.AsReadOnlySpan();
        ReadOnlySpan<byte> y = publicArea.PublicArea.Unique.Ecc!.Y.AsReadOnlySpan();

        byte[] result = new byte[1 + x.Length + y.Length];
        result[0] = EllipticCurveUtilities.UncompressedCoordinateFormat;
        x.CopyTo(result.AsSpan(1));
        y.CopyTo(result.AsSpan(1 + x.Length));

        return result;
    }
}
