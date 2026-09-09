using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Wire coverage for the TPMU_ATTEST <c>sessionAudit</c> arm (Table 153) inside a TPMS_ATTEST round trip: a
/// hand-built attestation of type TPM_ST_ATTEST_SESSION_AUDIT parses through both
/// <see cref="TpmsAttest.Parse"/> and <see cref="Tpm2bAttest.FromMarshaled"/> into
/// <see cref="TpmuAttest.SessionAudit"/> with its fields intact, and <see cref="TpmuAttest.ForSessionAudit"/>
/// owns the structure it wraps.
/// </summary>
[TestClass]
internal sealed class TpmuAttestSessionAuditTests
{
    /// <summary>A stand-in TPM2B_NAME (SHA-256 nameAlg prefix + 32-byte digest) for the signing key.</summary>
    private static byte[] SampleQualifiedSigner { get; } =
    [
        0x00, 0x0B,
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF
    ];

    /// <summary>A stand-in caller nonce echoed in extraData.</summary>
    private static byte[] SampleNonce { get; } =
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

    /// <summary>A stand-in 32-octet session audit digest.</summary>
    private static byte[] SampleSessionDigest { get; } =
    [
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
        0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF
    ];

    /// <summary>
    /// "sessionAudit TPMS_SESSION_AUDIT_INFO TPM_ST_ATTEST_SESSION_AUDIT" — a TPMS_ATTEST whose <c>type</c> is
    /// TPM_ST_ATTEST_SESSION_AUDIT carries a TPMS_SESSION_AUDIT_INFO body, and <see cref="TpmsAttest.WriteTo"/>
    /// followed by <see cref="TpmsAttest.Parse"/> reproduces every field, with the quote/certify/creation/time/nv
    /// arms left null.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 10.11.11, Table 153; clause 10.11.6, Table 148</see>.
    /// </summary>
    [TestMethod]
    public void TpmsAttestWithSessionAuditArmRoundTripsThroughTheWireByteExactly()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using TpmsAttest original = BuildSampleSessionAuditAttest(TpmiYesNo.Yes, pool);

        byte[] buffer = new byte[original.GetSerializedSize()];
        var writer = new TpmWriter(buffer);
        original.WriteTo(ref writer);
        Assert.AreEqual(buffer.Length, writer.Written, "WriteTo must fill exactly the reported serialized size.");

        var reader = new TpmReader(buffer);
        using TpmsAttest parsed = TpmsAttest.Parse(ref reader, pool);

        Assert.AreEqual(0, reader.Remaining, "Parse must consume exactly the structure's octets.");
        Assert.AreEqual(TpmStConstants.TPM_ST_ATTEST_SESSION_AUDIT, parsed.Type, "The re-parsed type must be TPM_ST_ATTEST_SESSION_AUDIT.");
        Assert.IsTrue(parsed.QualifiedSigner.Span.SequenceEqual(SampleQualifiedSigner), "qualifiedSigner must round-trip.");
        Assert.IsTrue(parsed.ExtraData.Span.SequenceEqual(SampleNonce), "extraData must round-trip.");

        Assert.IsNull(parsed.Attested.Quote, "The quote arm must be absent for a session-audit attestation.");
        Assert.IsNull(parsed.Attested.Certify, "The certify arm must be absent for a session-audit attestation.");
        Assert.IsNotNull(parsed.Attested.SessionAudit, "The sessionAudit arm must be present.");
        Assert.IsTrue(parsed.Attested.SessionAudit!.ExclusiveSession.IsYes, "exclusiveSession must round-trip as YES.");
        Assert.IsTrue(parsed.Attested.SessionAudit.SessionDigest.AsReadOnlySpan().SequenceEqual(SampleSessionDigest), "sessionDigest must round-trip.");
    }

    /// <summary>
    /// A marshaled TPMS_ATTEST wrapped as the exact bytes <c>TPM2_GetSessionAuditDigest()</c>'s <c>auditInfo</c>
    /// field carries parses through <see cref="Tpm2bAttest.FromMarshaled"/> into the same
    /// <see cref="TpmuAttest.SessionAudit"/> view, retaining the raw octets the signature is computed over.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 10.11.13, Table 155; clause 10.11.11, Table 153</see>.
    /// </summary>
    [TestMethod]
    public void Tpm2bAttestFromMarshaledParsesTheSessionAuditArm()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        byte[] attestImage;
        using(TpmsAttest attest = BuildSampleSessionAuditAttest(TpmiYesNo.No, pool))
        using(IMemoryOwner<byte> innerOwner = pool.Rent(attest.GetSerializedSize()))
        {
            var innerWriter = new TpmWriter(innerOwner.Memory.Span);
            attest.WriteTo(ref innerWriter);
            attestImage = innerOwner.Memory.Span[..innerWriter.Written].ToArray();
        }

        IMemoryOwner<byte> storage = pool.Rent(attestImage.Length);
        attestImage.CopyTo(storage.Memory.Span);

        using Tpm2bAttest parsed = Tpm2bAttest.FromMarshaled(storage, attestImage.Length, pool);

        Assert.IsTrue(parsed.GetRawBytes().SequenceEqual(attestImage), "The retained raw bytes must be exactly the marshaled attestation.");
        Assert.AreEqual(TpmStConstants.TPM_ST_ATTEST_SESSION_AUDIT, parsed.AttestationData.Type, "The wrapped attestation's type must be TPM_ST_ATTEST_SESSION_AUDIT.");
        Assert.IsNotNull(parsed.AttestationData.Attested.SessionAudit, "The sessionAudit arm must be reachable through Tpm2bAttest.");
        Assert.IsTrue(parsed.AttestationData.Attested.SessionAudit!.ExclusiveSession.IsNo, "exclusiveSession must round-trip as NO.");
        Assert.IsTrue(parsed.AttestationData.Attested.SessionAudit.SessionDigest.AsReadOnlySpan().SequenceEqual(SampleSessionDigest), "sessionDigest must round-trip.");
    }

    /// <summary>
    /// <see cref="TpmuAttest.ForSessionAudit"/> takes ownership of the <see cref="TpmsSessionAuditInfo"/> it
    /// wraps, so disposing the union releases exactly the one digest rental the wrapped structure holds.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 10.11.11, Table 153; clause 10.11.6, Table 148</see>.
    /// </summary>
    [TestMethod]
    public void TpmuAttestForSessionAuditDisposeReleasesTheOwnedSessionDigest()
    {
        using var housePool = new MeteredHousePool();

        //Redundant using locals satisfy CA2000; ownership transfers to attested and disposal is idempotent.
        using Tpm2bDigest digest = Tpm2bDigest.Create(SampleSessionDigest, housePool.Pool);
        using TpmsSessionAuditInfo info = TpmsSessionAuditInfo.Create(TpmiYesNo.Yes, digest);
        TpmuAttest attested = TpmuAttest.ForSessionAudit(info);

        Assert.AreEqual(1L, housePool.OutstandingCount, "The wrapped session-audit info's digest is rented before disposal.");
        Assert.AreEqual(TpmStConstants.TPM_ST_ATTEST_SESSION_AUDIT, attested.Type, "ForSessionAudit must select the sessionAudit arm.");

        attested.Dispose();
        Assert.AreEqual(0L, housePool.OutstandingCount, "Disposing the union must release the wrapped digest's rental.");
    }

    /// <summary>
    /// Builds a representative TPM_ST_ATTEST_SESSION_AUDIT attestation for the wire-format tests.
    /// </summary>
    /// <param name="exclusiveSession">The exclusive-session flag to attest.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The attestation structure; the caller owns it.</returns>
    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the created structures transfers to the returned TpmsAttest, which the caller disposes.")]
    private static TpmsAttest BuildSampleSessionAuditAttest(TpmiYesNo exclusiveSession, BaseMemoryPool pool)
    {
        TpmuAttest attested = TpmuAttest.ForSessionAudit(TpmsSessionAuditInfo.Create(exclusiveSession, Tpm2bDigest.Create(SampleSessionDigest, pool)));

        return TpmsAttest.Create(
            TpmConstants32.TPM_GENERATED_VALUE,
            TpmStConstants.TPM_ST_ATTEST_SESSION_AUDIT,
            Tpm2bName.Create(SampleQualifiedSigner, pool),
            Tpm2bData.Create(SampleNonce, pool),
            new TpmsClockInfo(Clock: 0x0102030405060708UL, ResetCount: 2, RestartCount: 1, Safe: TpmiYesNo.Yes),
            firmwareVersion: 0x0001000200030004UL,
            attested);
    }
}
