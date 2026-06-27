using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Non-hardware wire-format coverage for the TPMS_ATTEST family (TPMS_CLOCK_INFO, TPMS_QUOTE_INFO, TPMU_ATTEST,
/// TPMS_ATTEST, TPM2B_ATTEST). The behavioral round-trip — a TPM-signed quote whose attestation parses back and
/// verifies — is covered against the simulator in <c>TpmSimulatorQuoteTests</c>; these assertions need no TPM and
/// pin the field order and the raw-byte retention <c>TPM2_Quote</c> verification depends on.
/// </summary>
[TestClass]
internal sealed class TpmAttestStructureTests
{
    /// <summary>The PCR bank the quote selects from.</summary>
    private const TpmAlgIdConstants PcrBank = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The PCRs the quote covers.</summary>
    private static int[] PcrIndices { get; } = [0, 7];

    /// <summary>A stand-in 32-byte composite PCR digest.</summary>
    private static byte[] SamplePcrDigest { get; } =
    [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    ];

    /// <summary>A stand-in TPM2B_NAME (SHA-256 nameAlg prefix + 32-byte digest).</summary>
    private static byte[] SampleQualifiedSigner { get; } =
    [
        0x00, 0x0B,
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF
    ];

    /// <summary>A stand-in caller nonce echoed in extraData.</summary>
    private static byte[] SampleNonce { get; } =
        [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C];

    /// <summary>A stand-in TPM2B_NAME for a certified object (SHA-256 nameAlg prefix + 32-byte digest).</summary>
    private static byte[] SampleCertifiedName { get; } =
    [
        0x00, 0x0B,
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
        0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF
    ];

    /// <summary>A stand-in TPM2B_NAME for a certified object's qualified name.</summary>
    private static byte[] SampleCertifiedQualifiedName { get; } =
    [
        0x00, 0x0B,
        0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF
    ];

    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public void TpmsClockInfoRoundTripsThroughTheWire()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        var original = new TpmsClockInfo(Clock: 0x1122334455667788UL, ResetCount: 5, RestartCount: 3, Safe: TpmiYesNo.Yes);

        using IMemoryOwner<byte> owner = pool.Rent(TpmsClockInfo.SerializedSize);
        var writer = new TpmWriter(owner.Memory.Span);
        original.WriteTo(ref writer);
        Assert.AreEqual(TpmsClockInfo.SerializedSize, writer.Written);

        var reader = new TpmReader(owner.Memory.Span[..writer.Written]);
        TpmsClockInfo parsed = TpmsClockInfo.Parse(ref reader);

        Assert.AreEqual(0, reader.Remaining);
        Assert.AreEqual(0x1122334455667788UL, parsed.Clock);
        Assert.AreEqual(5u, parsed.ResetCount);
        Assert.AreEqual(3u, parsed.RestartCount);
        Assert.IsTrue(parsed.Safe.IsYes);
    }

    [TestMethod]
    public void TpmsQuoteInfoRoundTripsThroughTheWire()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        //Redundant using locals satisfy CA2000; ownership transfers to original and disposal is idempotent.
        using TpmlPcrSelection pcrSelect = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
        using Tpm2bDigest pcrDigest = Tpm2bDigest.Create(SamplePcrDigest, pool);
        using TpmsQuoteInfo original = TpmsQuoteInfo.Create(pcrSelect, pcrDigest);

        using IMemoryOwner<byte> owner = pool.Rent(original.SerializedSize);
        var writer = new TpmWriter(owner.Memory.Span);
        original.WriteTo(ref writer);
        Assert.AreEqual(original.SerializedSize, writer.Written);

        var reader = new TpmReader(owner.Memory.Span[..writer.Written]);
        using TpmsQuoteInfo parsed = TpmsQuoteInfo.Parse(ref reader, pool);

        Assert.AreEqual(0, reader.Remaining);
        Assert.AreEqual(1, parsed.PcrSelect.Count);
        Assert.AreEqual(PcrBank, parsed.PcrSelect[0].HashAlgorithm);
        Assert.IsTrue(parsed.PcrDigest.AsReadOnlySpan().SequenceEqual(SamplePcrDigest));
    }

    [TestMethod]
    public void TpmsAttestRoundTripsThroughTheWire()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using TpmsAttest original = BuildSampleQuoteAttest(pool);
        Assert.IsTrue(original.IsTpmGenerated);

        using IMemoryOwner<byte> owner = pool.Rent(original.GetSerializedSize());
        var writer = new TpmWriter(owner.Memory.Span);
        original.WriteTo(ref writer);
        Assert.AreEqual(original.GetSerializedSize(), writer.Written);

        //Re-parse through an independent decode path so a transposed field or a size miscount inside WriteTo fails
        //here rather than only against hardware (magic, type, qualifiedSigner, extraData, clockInfo,
        //firmwareVersion, attested — Part 2, 10.12.12).
        var reader = new TpmReader(owner.Memory.Span[..writer.Written]);
        using TpmsAttest parsed = TpmsAttest.Parse(ref reader, pool);

        Assert.AreEqual(0, reader.Remaining);
        Assert.AreEqual(TpmConstants32.TPM_GENERATED_VALUE, parsed.Magic);
        Assert.IsTrue(parsed.IsTpmGenerated);
        Assert.AreEqual(TpmStConstants.TPM_ST_ATTEST_QUOTE, parsed.Type);
        Assert.IsTrue(parsed.QualifiedSigner.Span.SequenceEqual(SampleQualifiedSigner));
        Assert.IsTrue(parsed.ExtraData.Span.SequenceEqual(SampleNonce));
        Assert.AreEqual(0x1122334455667788UL, parsed.ClockInfo.Clock);
        Assert.AreEqual(5u, parsed.ClockInfo.ResetCount);
        Assert.AreEqual(3u, parsed.ClockInfo.RestartCount);
        Assert.IsTrue(parsed.ClockInfo.Safe.IsYes);
        Assert.AreEqual(0x0001000200030004UL, parsed.FirmwareVersion);

        Assert.IsNotNull(parsed.Attested.Quote);
        Assert.AreEqual(1, parsed.Attested.Quote!.PcrSelect.Count);
        Assert.AreEqual(PcrBank, parsed.Attested.Quote.PcrSelect[0].HashAlgorithm);
        Assert.IsTrue(parsed.Attested.Quote.PcrDigest.AsReadOnlySpan().SequenceEqual(SamplePcrDigest));
    }

    [TestMethod]
    public void Tpm2bAttestParsesAndRetainsRawBytes()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        //Marshal a TPMS_ATTEST, wrap it in the TPM2B size prefix (as TPM2_Quote returns it), then parse.
        byte[] attestImage;
        using(TpmsAttest attest = BuildSampleQuoteAttest(pool))
        using(IMemoryOwner<byte> innerOwner = pool.Rent(attest.GetSerializedSize()))
        {
            var innerWriter = new TpmWriter(innerOwner.Memory.Span);
            attest.WriteTo(ref innerWriter);
            attestImage = innerOwner.Memory.Span[..innerWriter.Written].ToArray();
        }

        using IMemoryOwner<byte> owner = pool.Rent(sizeof(ushort) + attestImage.Length);
        var writer = new TpmWriter(owner.Memory.Span);
        writer.WriteUInt16((ushort)attestImage.Length);
        writer.WriteBytes(attestImage);

        var reader = new TpmReader(owner.Memory.Span[..writer.Written]);
        using Tpm2bAttest parsed = Tpm2bAttest.Parse(ref reader, pool);

        Assert.AreEqual(0, reader.Remaining);

        //The retained raw bytes are exactly the marshaled attestation — the bytes a verifier hashes for the
        //signature, which re-serializing the parsed structure is not guaranteed to reproduce.
        Assert.IsTrue(parsed.GetRawBytes().SequenceEqual(attestImage));
        Assert.AreEqual(sizeof(ushort) + attestImage.Length, parsed.GetSerializedSize());

        Assert.AreEqual(TpmStConstants.TPM_ST_ATTEST_QUOTE, parsed.AttestationData.Type);
        Assert.IsTrue(parsed.AttestationData.IsTpmGenerated);
        Assert.IsTrue(parsed.AttestationData.ExtraData.Span.SequenceEqual(SampleNonce));
    }

    [TestMethod]
    public void TpmsCertifyInfoRoundTripsThroughTheWire()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        //Redundant using locals satisfy CA2000; ownership transfers to original and disposal is idempotent.
        using Tpm2bName name = Tpm2bName.Create(SampleCertifiedName, pool);
        using Tpm2bName qualifiedName = Tpm2bName.Create(SampleCertifiedQualifiedName, pool);
        using TpmsCertifyInfo original = TpmsCertifyInfo.Create(name, qualifiedName);

        using IMemoryOwner<byte> owner = pool.Rent(original.SerializedSize);
        var writer = new TpmWriter(owner.Memory.Span);
        original.WriteTo(ref writer);
        Assert.AreEqual(original.SerializedSize, writer.Written);

        var reader = new TpmReader(owner.Memory.Span[..writer.Written]);
        using TpmsCertifyInfo parsed = TpmsCertifyInfo.Parse(ref reader, pool);

        Assert.AreEqual(0, reader.Remaining);
        Assert.IsTrue(parsed.Name.Span.SequenceEqual(SampleCertifiedName));
        Assert.IsTrue(parsed.QualifiedName.Span.SequenceEqual(SampleCertifiedQualifiedName));
    }

    [TestMethod]
    public void TpmsAttestCertifyArmRoundTripsThroughTheWire()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using TpmsAttest original = BuildSampleCertifyAttest(pool);

        using IMemoryOwner<byte> owner = pool.Rent(original.GetSerializedSize());
        var writer = new TpmWriter(owner.Memory.Span);
        original.WriteTo(ref writer);
        Assert.AreEqual(original.GetSerializedSize(), writer.Written);

        var reader = new TpmReader(owner.Memory.Span[..writer.Written]);
        using TpmsAttest parsed = TpmsAttest.Parse(ref reader, pool);

        Assert.AreEqual(0, reader.Remaining);
        Assert.IsTrue(parsed.IsTpmGenerated);
        Assert.AreEqual(TpmStConstants.TPM_ST_ATTEST_CERTIFY, parsed.Type);

        //The certify arm parses (and the quote arm is absent for this type).
        Assert.IsNull(parsed.Attested.Quote);
        Assert.IsNotNull(parsed.Attested.Certify);
        Assert.IsTrue(parsed.Attested.Certify!.Name.Span.SequenceEqual(SampleCertifiedName));
        Assert.IsTrue(parsed.Attested.Certify.QualifiedName.Span.SequenceEqual(SampleCertifiedQualifiedName));
    }

    /// <summary>
    /// Builds a representative TPM_ST_ATTEST_QUOTE attestation structure for the wire-format tests.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The attestation structure (the caller owns it).</returns>
    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the created structures transfers to the returned TpmsAttest, which the caller disposes.")]
    private static TpmsAttest BuildSampleQuoteAttest(MemoryPool<byte> pool)
    {
        TpmuAttest attested = TpmuAttest.ForQuote(TpmsQuoteInfo.Create(
            TpmlPcrSelection.Create(PcrBank, PcrIndices, pool),
            Tpm2bDigest.Create(SamplePcrDigest, pool)));

        return TpmsAttest.Create(
            TpmConstants32.TPM_GENERATED_VALUE,
            TpmStConstants.TPM_ST_ATTEST_QUOTE,
            Tpm2bName.Create(SampleQualifiedSigner, pool),
            Tpm2bData.Create(SampleNonce, pool),
            new TpmsClockInfo(Clock: 0x1122334455667788UL, ResetCount: 5, RestartCount: 3, Safe: TpmiYesNo.Yes),
            firmwareVersion: 0x0001000200030004UL,
            attested);
    }

    /// <summary>
    /// Builds a representative TPM_ST_ATTEST_CERTIFY attestation structure for the wire-format tests.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The attestation structure (the caller owns it).</returns>
    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the created structures transfers to the returned TpmsAttest, which the caller disposes.")]
    private static TpmsAttest BuildSampleCertifyAttest(MemoryPool<byte> pool)
    {
        TpmuAttest attested = TpmuAttest.ForCertify(TpmsCertifyInfo.Create(
            Tpm2bName.Create(SampleCertifiedName, pool),
            Tpm2bName.Create(SampleCertifiedQualifiedName, pool)));

        return TpmsAttest.Create(
            TpmConstants32.TPM_GENERATED_VALUE,
            TpmStConstants.TPM_ST_ATTEST_CERTIFY,
            Tpm2bName.Create(SampleQualifiedSigner, pool),
            Tpm2bData.Create(SampleNonce, pool),
            new TpmsClockInfo(Clock: 0x1122334455667788UL, ResetCount: 5, RestartCount: 3, Safe: TpmiYesNo.Yes),
            firmwareVersion: 0x0001000200030004UL,
            attested);
    }
}
