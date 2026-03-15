using System;
using System.Buffers;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Verifiable.Cryptography;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Extensions.Secdsa;

namespace Verifiable.Tests.Secdsa;

/// <summary>
/// Tests for SECDSA-related TPM command structure types: construction, serialization
/// shape, and round-trip properties. No TPM hardware is required.
/// </summary>
[TestClass]
internal sealed class TpmSecdsaCommandStructureTests
{
    public TestContext TestContext { get; set; } = null!;

    //Synthetic transient object handles for round-trip tests (TPM 2.0 Part 2, Section 7.4).
    //These are valid in-range transient handle values, not real loaded key handles.
    private static TpmiDhObject TestSigningKeyHandle { get; } =
        TpmiDhObject.FromValue(TpmHcConstants.TRANSIENT_FIRST + 1);

    private static TpmiDhObject TestEcdhKeyHandle { get; } =
        TpmiDhObject.FromValue(TpmHcConstants.TRANSIENT_FIRST + 2);

    private static TpmiDhObject TestEcdhKeyHandle2 { get; } =
        TpmiDhObject.FromValue(TpmHcConstants.TRANSIENT_FIRST + 3);

    private static TpmiDhObject TestObjectHandle { get; } =
        TpmiDhObject.FromValue(TpmHcConstants.TRANSIENT_FIRST + 4);

    [TestMethod]
    public void SignInputCreatesWithCorrectProperties()
    {
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        byte[] digest = new byte[EllipticCurveConstants.P256.PointArrayLength];
        RandomNumberGenerator.Fill(digest);

        using SignInput input = SignInput.ForEcdsa(
            keyHandle: TestSigningKeyHandle,
            digest: digest,
            schemeHashAlg: TpmAlgIdConstants.TPM_ALG_SHA256,
            pool: pool);

        Assert.AreEqual(TestSigningKeyHandle, input.KeyHandle, "Key handle must round-trip.");
        Assert.AreEqual(EllipticCurveConstants.P256.PointArrayLength, input.Digest.Length,
            "Digest must be 32 bytes.");
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, input.SchemeHashAlg,
            "Hash algorithm must round-trip.");
        Assert.IsTrue(input.Digest.Span.SequenceEqual(digest), "Digest bytes must round-trip.");
    }

    [TestMethod]
    public void SignInputDisposeIsIdempotent()
    {
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        byte[] digest = new byte[EllipticCurveConstants.P256.PointArrayLength];

        SignInput input = SignInput.ForEcdsa(TestSigningKeyHandle, digest, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        input.Dispose();
        input.Dispose();
    }

    [TestMethod]
    public void EcdhZGenInputCreatesFromCoordinates()
    {
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        byte[] x = new byte[EllipticCurveConstants.P256.PointArrayLength];
        byte[] y = new byte[EllipticCurveConstants.P256.PointArrayLength];
        RandomNumberGenerator.Fill(x);
        RandomNumberGenerator.Fill(y);

        using EcdhZGenInput input = EcdhZGenInput.Create(
            keyHandle: TestEcdhKeyHandle,
            xCoord: x,
            yCoord: y,
            pool: pool);

        Assert.AreEqual(TestEcdhKeyHandle, input.KeyHandle, "Key handle must round-trip.");
    }

    [TestMethod]
    public void EcdhZGenInputCreatesFromUncompressedPoint()
    {
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        byte[] point = new byte[EllipticCurveConstants.P256.UncompressedPointByteCount];
        point[0] = EllipticCurveUtilities.UncompressedCoordinateFormat;
        RandomNumberGenerator.Fill(point.AsSpan(1));

        using EcdhZGenInput input = EcdhZGenInput.FromUncompressedPoint(
            keyHandle: TestEcdhKeyHandle2,
            uncompressedPoint: point,
            pool: pool);

        Assert.AreEqual(TestEcdhKeyHandle2, input.KeyHandle, "Key handle must round-trip.");
    }

    [TestMethod]
    public void EcdhZGenInputDisposeIsIdempotent()
    {
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        byte[] point = new byte[EllipticCurveConstants.P256.UncompressedPointByteCount];
        point[0] = EllipticCurveUtilities.UncompressedCoordinateFormat;

        EcdhZGenInput input = EcdhZGenInput.FromUncompressedPoint(TestEcdhKeyHandle2, point, pool);
        input.Dispose();
        input.Dispose();
    }

    [TestMethod]
    public void ReadPublicInputCreatesForHandle()
    {
        ReadPublicInput input = ReadPublicInput.ForHandle(TestObjectHandle);

        Assert.AreEqual(TestObjectHandle, input.ObjectHandle, "Object handle must round-trip.");
    }

    [TestMethod]
    public void EcdhZGenResponseParsesAndProducesUncompressedPoint()
    {
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        byte[] xCoordinate = new byte[EllipticCurveConstants.P256.PointArrayLength];
        byte[] yCoordinate = new byte[EllipticCurveConstants.P256.PointArrayLength];
        RandomNumberGenerator.Fill(xCoordinate);
        RandomNumberGenerator.Fill(yCoordinate);

        byte[] wireBytes = BuildFakeEcdhZGenResponseBytes(xCoordinate, yCoordinate);
        TpmReader reader = new(wireBytes);
        using EcdhZGenResponse response = EcdhZGenResponse.Parse(ref reader, pool);

        byte[] point = response.ToUncompressedPoint();

        Assert.HasCount(EllipticCurveConstants.P256.UncompressedPointByteCount, point,
            "Uncompressed point must be 65 bytes.");
        Assert.AreEqual(EllipticCurveUtilities.UncompressedCoordinateFormat, point[0],
            "Prefix must be 0x04.");
        Assert.IsTrue(
            point.AsSpan(1, EllipticCurveConstants.P256.PointArrayLength).SequenceEqual(xCoordinate),
            "X coordinate must match.");
        Assert.IsTrue(
            point.AsSpan(1 + EllipticCurveConstants.P256.PointArrayLength, EllipticCurveConstants.P256.PointArrayLength).SequenceEqual(yCoordinate),
            "Y coordinate must match.");
    }

    [TestMethod]
    public void EcdhZGenResponseDisposeIsIdempotent()
    {
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        byte[] wireBytes = BuildFakeEcdhZGenResponseBytes(
            new byte[EllipticCurveConstants.P256.PointArrayLength],
            new byte[EllipticCurveConstants.P256.PointArrayLength]);
        TpmReader reader = new(wireBytes);

        EcdhZGenResponse response = EcdhZGenResponse.Parse(ref reader, pool);
        response.Dispose();
        response.Dispose();
    }

    private static byte[] BuildFakeEcdhZGenResponseBytes(ReadOnlySpan<byte> xCoordinate, ReadOnlySpan<byte> yCoordinate)
    {
        //TPM2B_ECC_POINT: outer size (2) + TPMS_ECC_POINT.
        //TPMS_ECC_POINT: TPM2B_ECC_PARAMETER(x) + TPM2B_ECC_PARAMETER(y).
        //Each TPM2B_ECC_PARAMETER: uint16 size (big-endian) + bytes.
        int innerSize = 2 + xCoordinate.Length + 2 + yCoordinate.Length;
        byte[] result = new byte[2 + innerSize];
        int pos = 0;

        //Outer TPM2B_ECC_POINT size.
        result[pos++] = (byte)(innerSize >> 8);
        result[pos++] = (byte)innerSize;

        result[pos++] = 0;
        result[pos++] = (byte)xCoordinate.Length;
        xCoordinate.CopyTo(result.AsSpan(pos));
        pos += xCoordinate.Length;

        result[pos++] = 0;
        result[pos++] = (byte)yCoordinate.Length;
        yCoordinate.CopyTo(result.AsSpan(pos));

        return result;
    }
}