using System.Buffers;
using System.Numerics;
using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Secdsa;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Extensions.Secdsa;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Secdsa;

/// <summary>
/// Hardware TPM tests for the SECDSA ECDH path: TPM2_ECDH_ZGen for blinding key
/// operations and the full SECDSA cross-provider path (TPM signs, pure .NET verifies).
/// </summary>
[TestClass]
[DoNotParallelize]
[SkipIfNoTpm]
[TestCategory("RequiresHardwareTpm")]
internal sealed class HwTpmSecdsaEcdhTests
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
    public void TpmEcdhZGenProducesValidOutputPoint()
    {
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        var registry = new TpmResponseRegistry();

        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        using CreatePrimaryInput createInput = CreatePrimaryInput.ForEccKeyAgreementKey(
            TpmRh.TPM_RH_OWNER,
            null,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            pool);

        using var ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> createResult = TpmCommandExecutor.Execute<CreatePrimaryResponse>(
            Tpm, createInput, [ownerAuth], pool, registry);

        AssertUtilities.AssertSuccess(createResult, "CreatePrimary for ECDH key.");

        using CreatePrimaryResponse createResponse = createResult.Value;
        TpmiDhObject keyHandle = createResponse.ObjectHandle;

        byte[] inPoint = new byte[EllipticCurveConstants.P256.UncompressedPointByteCount];
        inPoint[0] = EllipticCurveUtilities.UncompressedCoordinateFormat;
        EllipticCurveConstants.P256.BasePointXBytes.CopyTo(inPoint.AsSpan(1));
        EllipticCurveConstants.P256.BasePointYBytes.CopyTo(inPoint.AsSpan(1 + EllipticCurveConstants.P256.PointArrayLength));

        TpmResult<EcdhZGenResponse> ecdhResult = Tpm.EcdhZGen(keyHandle, inPoint, pool);

        var flushInput = FlushContextInput.ForHandle(keyHandle.Value);
        _ = TpmCommandExecutor.Execute<FlushContextResponse>(Tpm, flushInput, [], pool, registry);

        AssertUtilities.AssertSuccess(ecdhResult, "TPM2_ECDH_ZGen");

        using EcdhZGenResponse ecdhResponse = ecdhResult.Value;
        byte[] outPoint = ecdhResponse.ToUncompressedPoint();

        Assert.HasCount(EllipticCurveConstants.P256.UncompressedPointByteCount, outPoint,
            "ECDH output point must be 65 bytes.");
        Assert.AreEqual(EllipticCurveUtilities.UncompressedCoordinateFormat, outPoint[0],
            "ECDH output point must start with 0x04.");
        Assert.IsTrue(
            EcMath.IsValidPoint(EcMath.DecodePointUncompressed(outPoint)),
            "ECDH output point must be on the P-256 curve.");

        TestContext.WriteLine($"ECDH output X = {Convert.ToHexString(outPoint.AsSpan(1, EllipticCurveConstants.P256.PointArrayLength))}");
        TestContext.WriteLine($"ECDH output Y = {Convert.ToHexString(outPoint.AsSpan(1 + EllipticCurveConstants.P256.PointArrayLength, EllipticCurveConstants.P256.PointArrayLength))}");
    }

    [TestMethod]
    public void TpmSignsAndPureNetVerifiesFullSecdsaPath()
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

        BigInteger pinKey = EcMath.RandomScalar();
        BigInteger pinInverse = EcMath.ModInverse(pinKey);

        byte[] messageHash = SHA256.HashData("SECDSA WSCA instruction verification path."u8);
        BigInteger adjustedE = EcMath.HashToInteger(messageHash) * pinInverse % EcMath.Q;
        byte[] adjustedDigest = EcMath.ScalarToBytes(adjustedE);

        using SignInput signInput = SignInput.ForEcdsa(
            keyHandle, adjustedDigest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        using var keyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<SignResponse> signResult = TpmCommandExecutor.Execute<SignResponse>(
            Tpm, signInput, [keyAuth], pool, registry);

        AssertUtilities.AssertSuccess(signResult, "TPM2_Sign");

        using SignResponse signResponse = signResult.Value;

        BigInteger r = new BigInteger(signResponse.SignatureR.AsReadOnlySpan(), isUnsigned: true, isBigEndian: true);
        BigInteger s0 = new BigInteger(signResponse.SignatureS.AsReadOnlySpan(), isUnsigned: true, isBigEndian: true);
        BigInteger s = pinKey * s0 % EcMath.Q;

        byte[] uPoint = ExtractEccPublicPoint(createResponse.OutPublic);
        EcPoint y = EcMath.Multiply(EcMath.DecodePointUncompressed(uPoint), pinKey);

        bool valid = SecdsaAlgorithms.Verify(messageHash, new EcdsaSignature(r, s), y);

        Assert.IsTrue(valid, "SECDSA signature (TPM signs, pure .NET verifies) must be valid.");

        var flushInput = FlushContextInput.ForHandle(keyHandle.Value);
        _ = TpmCommandExecutor.Execute<FlushContextResponse>(Tpm, flushInput, [], pool, registry);
    }

    private static byte[] ExtractEccPublicPoint(Tpm2bPublic publicArea)
    {
        ReadOnlySpan<byte> x = publicArea.PublicArea.Unique.Ecc!.X.AsReadOnlySpan();
        ReadOnlySpan<byte> y = publicArea.PublicArea.Unique.Ecc!.Y.AsReadOnlySpan();

        byte[] result = new byte[1 + x.Length + y.Length];
        result[0] = EllipticCurveUtilities.UncompressedCoordinateFormat;
        x.CopyTo(result.AsSpan(1));
        y.CopyTo(result.AsSpan(1 + x.Length));
        return result;
    }
}