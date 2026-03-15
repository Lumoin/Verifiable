using System.Buffers;
using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Secdsa;

namespace Verifiable.Tests.Secdsa;

/// <summary>
/// Tests for the SECDSA protocol message types:
/// <see cref="InternalCertificate"/>, <see cref="BlindedSecdsaInstruction"/>,
/// <see cref="InstructionTranscript"/>, and the wire-level byte types.
/// </summary>
[TestClass]
internal sealed class SecdsaProtocolTypesTests
{
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public void EcPointBytesCreatesFromUncompressedPoint()
    {
        byte[] point = CreateFakeUncompressedPoint();
        using EcPointBytes ecPoint = EcPointBytes.Create(point, MemoryPool<byte>.Shared);

        Assert.AreEqual(EllipticCurveConstants.P256.UncompressedPointByteCount, ecPoint.Value.Length,
            "Uncompressed P-256 point must be 65 bytes.");
        Assert.AreEqual(0x04, ecPoint.Value.Span[0], "Uncompressed point must start with 0x04.");
    }

    [TestMethod]
    public void EcPointBytesXAndYSlicesAreCorrect()
    {
        byte[] point = CreateFakeUncompressedPoint();
        using EcPointBytes ecPoint = EcPointBytes.Create(point, MemoryPool<byte>.Shared);

        Assert.AreEqual(EllipticCurveConstants.P256.PointArrayLength, ecPoint.X.Length,
            "X coordinate must be 32 bytes for P-256.");
        Assert.AreEqual(EllipticCurveConstants.P256.PointArrayLength, ecPoint.Y.Length,
            "Y coordinate must be 32 bytes for P-256.");
        Assert.IsTrue(ecPoint.X.Span.SequenceEqual(point.AsSpan(1, EllipticCurveConstants.P256.PointArrayLength)),
            "X must match bytes 1–32 of the uncompressed point.");
        Assert.IsTrue(ecPoint.Y.Span.SequenceEqual(point.AsSpan(1 + EllipticCurveConstants.P256.PointArrayLength, EllipticCurveConstants.P256.PointArrayLength)),
            "Y must match bytes 33–64 of the uncompressed point.");
    }

    [TestMethod]
    public void EcPointBytesRoundTripsData()
    {
        byte[] point = CreateFakeUncompressedPoint();
        using EcPointBytes ecPoint = EcPointBytes.Create(point, MemoryPool<byte>.Shared);

        Assert.IsTrue(ecPoint.Value.Span.SequenceEqual(point), "Round-tripped point must equal the original bytes.");
    }

    [TestMethod]
    public void RawEcdsaSignatureBytesCreatesFromRAndS()
    {
        byte[] r = new byte[EllipticCurveConstants.P256.PointArrayLength];
        byte[] s = new byte[EllipticCurveConstants.P256.PointArrayLength];
        r[0] = 0xAB;
        s[0] = 0xCD;

        using RawEcdsaSignatureBytes sig = RawEcdsaSignatureBytes.Create(r, s, MemoryPool<byte>.Shared);

        Assert.AreEqual(EllipticCurveConstants.P256.PointArrayLength, sig.R.Length, "R must be 32 bytes.");
        Assert.AreEqual(EllipticCurveConstants.P256.PointArrayLength, sig.S.Length, "S must be 32 bytes.");
        Assert.AreEqual(0xAB, sig.R.Span[0], "First byte of R must match.");
        Assert.AreEqual(0xCD, sig.S.Span[0], "First byte of S must match.");
    }

    [TestMethod]
    public void RawEcdsaSignatureBytesRoundTrips()
    {
        byte[] r = new byte[EllipticCurveConstants.P256.PointArrayLength];
        byte[] s = new byte[EllipticCurveConstants.P256.PointArrayLength];
        RandomNumberGenerator.Fill(r);
        RandomNumberGenerator.Fill(s);

        using RawEcdsaSignatureBytes sig = RawEcdsaSignatureBytes.Create(r, s, MemoryPool<byte>.Shared);

        Assert.IsTrue(sig.R.Span.SequenceEqual(r), "R must round-trip correctly.");
        Assert.IsTrue(sig.S.Span.SequenceEqual(s), "S must round-trip correctly.");
    }

    [TestMethod]
    public void PinKeyScalarBytesCreatesFromScalar()
    {
        byte[] scalar = new byte[EllipticCurveConstants.P256.PointArrayLength];
        scalar[0] = 0x01;

        using PinKeyScalarBytes pinKey = PinKeyScalarBytes.Create(scalar, MemoryPool<byte>.Shared);

        Assert.AreEqual(EllipticCurveConstants.P256.PointArrayLength, pinKey.Value.Length,
            "PIN key scalar must be 32 bytes for P-256.");
        Assert.AreEqual(0x01, pinKey.Value.Span[0], "First byte of scalar must match.");
    }

    [TestMethod]
    public void PinKeyScalarBytesZeroesOnDispose()
    {
        byte[] scalar = new byte[EllipticCurveConstants.P256.PointArrayLength];
        RandomNumberGenerator.Fill(scalar);

        using SensitiveMemoryPool<byte> pool = new();
        PinKeyScalarBytes pinKey = PinKeyScalarBytes.Create(scalar, pool);

        byte[] valueBefore = pinKey.Value.ToArray();
        Assert.IsFalse(Array.TrueForAll(valueBefore, b => b == 0), "Scalar must be non-zero before dispose.");

        pinKey.Dispose();

        using IMemoryOwner<byte> next = pool.Rent(EllipticCurveConstants.P256.PointArrayLength);
        Assert.IsTrue(next.Memory.Span.SequenceEqual(new byte[EllipticCurveConstants.P256.PointArrayLength]),
            "Memory returned to SensitiveMemoryPool must be zeroed.");
    }

    [TestMethod]
    public void SchnorrProofBytesRoundTrips()
    {
        byte[] r = new byte[EllipticCurveConstants.P256.PointArrayLength];
        byte[] s = new byte[EllipticCurveConstants.P256.PointArrayLength];
        RandomNumberGenerator.Fill(r);
        RandomNumberGenerator.Fill(s);

        using SchnorrProofBytes proof = SchnorrProofBytes.Create(r, s, MemoryPool<byte>.Shared);

        Assert.AreEqual(EllipticCurveConstants.P256.PointArrayLength, proof.R.Length, "Proof R must be 32 bytes.");
        Assert.AreEqual(EllipticCurveConstants.P256.PointArrayLength, proof.S.Length, "Proof S must be 32 bytes.");
        Assert.IsTrue(proof.R.Span.SequenceEqual(r), "Proof R must round-trip correctly.");
        Assert.IsTrue(proof.S.Span.SequenceEqual(s), "Proof S must round-trip correctly.");
    }

    [TestMethod]
    public void InternalCertificateCreatesWithAllFields()
    {
        using EcPointBytes nchKey = EcPointBytes.Create(CreateFakeUncompressedPoint(), MemoryPool<byte>.Shared);
        using EcPointBytes blindingKey = EcPointBytes.Create(CreateFakeUncompressedPoint(), MemoryPool<byte>.Shared);
        using EcPointBytes blindPublicKey = EcPointBytes.Create(CreateFakeUncompressedPoint(), MemoryPool<byte>.Shared);
        byte[] sig = new byte[64];
        RandomNumberGenerator.Fill(sig);

        using InternalCertificate cert = InternalCertificate.Create(
            "wallet-account-001",
            nchKey,
            blindingKey,
            blindPublicKey,
            sig,
            MemoryPool<byte>.Shared);

        Assert.AreEqual("wallet-account-001", cert.AccountId, "AccountId must round-trip.");
        Assert.AreEqual(EllipticCurveConstants.P256.UncompressedPointByteCount, cert.NchPublicKey.Value.Length,
            "NCH public key must be 65 bytes.");
        Assert.AreEqual(EllipticCurveConstants.P256.UncompressedPointByteCount, cert.BlindingPublicKey.Value.Length,
            "Blinding public key must be 65 bytes.");
        Assert.AreEqual(EllipticCurveConstants.P256.UncompressedPointByteCount, cert.BlindSecdsaPublicKey.Value.Length,
            "Blind SECDSA public key must be 65 bytes.");
        Assert.AreEqual(64, cert.IssuerSignature.Length, "Issuer signature must be 64 bytes.");
    }

    [TestMethod]
    public void InternalCertificateIssuerSignatureRoundTrips()
    {
        using EcPointBytes nchKey = EcPointBytes.Create(CreateFakeUncompressedPoint(), MemoryPool<byte>.Shared);
        using EcPointBytes blindingKey = EcPointBytes.Create(CreateFakeUncompressedPoint(), MemoryPool<byte>.Shared);
        using EcPointBytes blindPublicKey = EcPointBytes.Create(CreateFakeUncompressedPoint(), MemoryPool<byte>.Shared);
        byte[] sig = new byte[64];
        RandomNumberGenerator.Fill(sig);

        using InternalCertificate cert = InternalCertificate.Create(
            "account-x",
            nchKey,
            blindingKey,
            blindPublicKey,
            sig,
            MemoryPool<byte>.Shared);

        Assert.IsTrue(cert.IssuerSignature.Span.SequenceEqual(sig),
            "Issuer signature bytes must round-trip without modification.");
    }

    [TestMethod]
    public void BlindedSecdsaInstructionCreatesWithAllFields()
    {
        using EcPointBytes noncePoint = EcPointBytes.Create(CreateFakeUncompressedPoint(), MemoryPool<byte>.Shared);
        using EcPointBytes verificationPoint = EcPointBytes.Create(CreateFakeUncompressedPoint(), MemoryPool<byte>.Shared);
        byte[] challenge = new byte[128];
        byte[] ciphertext = new byte[256];
        byte[] tag = new byte[16];
        RandomNumberGenerator.Fill(challenge);
        RandomNumberGenerator.Fill(ciphertext);
        RandomNumberGenerator.Fill(tag);

        using BlindedSecdsaInstruction instruction = BlindedSecdsaInstruction.Create(
            sequenceNumber: 42UL,
            challengeBytes: challenge,
            noncePoint: noncePoint,
            verificationPoint: verificationPoint,
            ciphertextBytes: ciphertext,
            authTagBytes: tag,
            MemoryPool<byte>.Shared);

        Assert.AreEqual(42UL, instruction.SequenceNumber, "Sequence number must round-trip.");
        Assert.AreEqual(128, instruction.Challenge.Length, "Challenge must be 128 bytes.");
        Assert.AreEqual(256, instruction.Ciphertext.Length, "Ciphertext must be 256 bytes.");
        Assert.AreEqual(16, instruction.AuthenticationTag.Length, "Authentication tag must be 16 bytes.");
        Assert.AreEqual(EllipticCurveConstants.P256.UncompressedPointByteCount, instruction.NoncePoint.Value.Length,
            "Nonce point must be 65 bytes.");
        Assert.AreEqual(EllipticCurveConstants.P256.UncompressedPointByteCount, instruction.VerificationPoint.Value.Length,
            "Verification point must be 65 bytes.");
    }

    [TestMethod]
    public void BlindedSecdsaInstructionCiphertextRoundTrips()
    {
        using EcPointBytes noncePoint = EcPointBytes.Create(CreateFakeUncompressedPoint(), MemoryPool<byte>.Shared);
        using EcPointBytes verificationPoint = EcPointBytes.Create(CreateFakeUncompressedPoint(), MemoryPool<byte>.Shared);
        byte[] ciphertext = new byte[64];
        RandomNumberGenerator.Fill(ciphertext);

        using BlindedSecdsaInstruction instruction = BlindedSecdsaInstruction.Create(
            sequenceNumber: 1UL,
            challengeBytes: new byte[32],
            noncePoint: noncePoint,
            verificationPoint: verificationPoint,
            ciphertextBytes: ciphertext,
            authTagBytes: new byte[16],
            MemoryPool<byte>.Shared);

        Assert.IsTrue(instruction.Ciphertext.Span.SequenceEqual(ciphertext),
            "Ciphertext bytes must round-trip without modification.");
    }

    [TestMethod]
    public void InstructionTranscriptCreatesWithAllFields()
    {
        byte[] innerTranscript = new byte[512];
        byte[] wscaSig = new byte[64];
        byte[] result = new byte[128];
        RandomNumberGenerator.Fill(innerTranscript);
        RandomNumberGenerator.Fill(wscaSig);
        RandomNumberGenerator.Fill(result);

        using InstructionTranscript transcript = InstructionTranscript.Create(
            sequenceNumber: 7UL,
            innerTranscriptBytes: innerTranscript,
            wscaSignatureBytes: wscaSig,
            executionResultBytes: result,
            MemoryPool<byte>.Shared);

        Assert.AreEqual(7UL, transcript.SequenceNumber, "Sequence number must round-trip.");
        Assert.AreEqual(512, transcript.InnerTranscript.Length, "Inner transcript must be 512 bytes.");
        Assert.AreEqual(64, transcript.WscaSignature.Length, "WSCA signature must be 64 bytes.");
        Assert.AreEqual(128, transcript.ExecutionResult.Length, "Execution result must be 128 bytes.");
    }

    [TestMethod]
    public void InstructionTranscriptInnerTranscriptRoundTrips()
    {
        byte[] innerTranscript = new byte[128];
        RandomNumberGenerator.Fill(innerTranscript);

        using InstructionTranscript transcript = InstructionTranscript.Create(
            sequenceNumber: 1UL,
            innerTranscriptBytes: innerTranscript,
            wscaSignatureBytes: new byte[64],
            executionResultBytes: new byte[32],
            MemoryPool<byte>.Shared);

        Assert.IsTrue(transcript.InnerTranscript.Span.SequenceEqual(innerTranscript),
            "Inner transcript bytes must round-trip without modification.");
    }

    [TestMethod]
    public void EcPointBytesCreateThrowsOnNullPool()
    {
        byte[] point = CreateFakeUncompressedPoint();
        Assert.ThrowsExactly<ArgumentNullException>(() => EcPointBytes.Create(point, null!));
    }

    [TestMethod]
    public void RawEcdsaSignatureBytesCreateThrowsOnNullPool()
    {
        byte[] r = new byte[EllipticCurveConstants.P256.PointArrayLength];
        byte[] s = new byte[EllipticCurveConstants.P256.PointArrayLength];
        Assert.ThrowsExactly<ArgumentNullException>(() => RawEcdsaSignatureBytes.Create(r, s, null!));
    }

    [TestMethod]
    public void PinKeyScalarBytesCreateThrowsOnNullPool()
    {
        byte[] scalar = new byte[EllipticCurveConstants.P256.PointArrayLength];
        Assert.ThrowsExactly<ArgumentNullException>(() => PinKeyScalarBytes.Create(scalar, null!));
    }

    [TestMethod]
    public void SchnorrProofBytesCreateThrowsOnNullPool()
    {
        byte[] r = new byte[EllipticCurveConstants.P256.PointArrayLength];
        byte[] s = new byte[EllipticCurveConstants.P256.PointArrayLength];
        Assert.ThrowsExactly<ArgumentNullException>(() => SchnorrProofBytes.Create(r, s, null!));
    }

    [TestMethod]
    public void InternalCertificateCreateThrowsOnNullPool()
    {
        using EcPointBytes nchKey = EcPointBytes.Create(CreateFakeUncompressedPoint(), MemoryPool<byte>.Shared);
        using EcPointBytes blindingKey = EcPointBytes.Create(CreateFakeUncompressedPoint(), MemoryPool<byte>.Shared);
        using EcPointBytes blindPublicKey = EcPointBytes.Create(CreateFakeUncompressedPoint(), MemoryPool<byte>.Shared);

        Assert.ThrowsExactly<ArgumentNullException>(() =>
            InternalCertificate.Create("account", nchKey, blindingKey, blindPublicKey, new byte[64], null!));
    }

    [TestMethod]
    public void InternalCertificateCreateThrowsOnNullAccountId()
    {
        using EcPointBytes nchKey = EcPointBytes.Create(CreateFakeUncompressedPoint(), MemoryPool<byte>.Shared);
        using EcPointBytes blindingKey = EcPointBytes.Create(CreateFakeUncompressedPoint(), MemoryPool<byte>.Shared);
        using EcPointBytes blindPublicKey = EcPointBytes.Create(CreateFakeUncompressedPoint(), MemoryPool<byte>.Shared);

        Assert.ThrowsExactly<ArgumentNullException>(() =>
            InternalCertificate.Create(null!, nchKey, blindingKey, blindPublicKey, new byte[64], MemoryPool<byte>.Shared));
    }

    [TestMethod]
    public void BlindedSecdsaInstructionCreateThrowsOnNullPool()
    {
        using EcPointBytes noncePoint = EcPointBytes.Create(CreateFakeUncompressedPoint(), MemoryPool<byte>.Shared);
        using EcPointBytes verificationPoint = EcPointBytes.Create(CreateFakeUncompressedPoint(), MemoryPool<byte>.Shared);

        Assert.ThrowsExactly<ArgumentNullException>(() =>
            BlindedSecdsaInstruction.Create(1UL, new byte[32], noncePoint, verificationPoint, new byte[64], new byte[16], null!));
    }

    [TestMethod]
    public void InstructionTranscriptCreateThrowsOnNullPool()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() =>
            InstructionTranscript.Create(1UL, new byte[64], new byte[64], new byte[32], null!));
    }

    private static byte[] CreateFakeUncompressedPoint()
    {
        byte[] point = new byte[EllipticCurveConstants.P256.UncompressedPointByteCount];
        point[0] = 0x04;
        RandomNumberGenerator.Fill(point.AsSpan(1));
        return point;
    }
}