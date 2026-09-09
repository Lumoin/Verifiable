using System;
using System.Buffers;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Byte-exact wire coverage for TPMS_SESSION_AUDIT_INFO (Table 148): the <c>exclusiveSession</c> flag followed by
/// the <c>sessionDigest</c> sized buffer, its round trip through <see cref="TpmsSessionAuditInfo.WriteTo"/> and
/// <see cref="TpmsSessionAuditInfo.Parse"/> under a metered pool, and the exception a digest size declared past
/// the reader must raise before any rental escapes.
/// </summary>
[TestClass]
internal sealed class TpmsSessionAuditInfoTests
{
    /// <summary>A stand-in 32-octet (SHA-256-width) session digest.</summary>
    private static byte[] ThirtyTwoOctetDigest { get; } =
    [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    ];

    /// <summary>A stand-in 20-octet (SHA-1-width) session digest.</summary>
    private static byte[] TwentyOctetDigest { get; } =
    [
        0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0, 0xF1, 0xF2, 0xF3
    ];

    /// <summary>
    /// "This Table 148 structure is the attested data for TPM2_GetSessionAuditDigest()" and carries
    /// <c>exclusiveSession</c> then <c>sessionDigest</c> — a one-octet TPMI_YES_NO followed by a TPM2B_DIGEST —
    /// for a session marked exclusive with a full SHA-256-width digest.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 10.11.6, Table 148</see>.
    /// </summary>
    [TestMethod]
    public void SessionAuditInfoWithExclusiveSessionYesAndAThirtyTwoOctetDigestRoundTripsThroughTheWireByteExactly()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        //Redundant using local satisfies CA2000; ownership transfers to original and disposal is idempotent.
        using Tpm2bDigest digest = Tpm2bDigest.Create(ThirtyTwoOctetDigest, pool);
        using TpmsSessionAuditInfo original = TpmsSessionAuditInfo.Create(TpmiYesNo.Yes, digest);

        Assert.AreEqual(35, original.SerializedSize, "The 1-octet YES flag plus a 2-octet size prefix plus 32 digest octets is 35.");

        byte[] expected = [0x01, 0x00, 0x20, .. ThirtyTwoOctetDigest];
        byte[] buffer = new byte[original.SerializedSize];
        var writer = new TpmWriter(buffer);
        original.WriteTo(ref writer);

        Assert.AreEqual(buffer.Length, writer.Written, "WriteTo must fill exactly the reported serialized size.");
        Assert.IsTrue(buffer.AsSpan().SequenceEqual(expected), "The wire octets must be exclusiveSession=YES(01) then the TPM2B_DIGEST size and bytes.");

        var reader = new TpmReader(buffer);
        using TpmsSessionAuditInfo parsed = TpmsSessionAuditInfo.Parse(ref reader, pool);

        Assert.AreEqual(0, reader.Remaining, "Parse must consume exactly the structure's octets.");
        Assert.IsTrue(parsed.ExclusiveSession.IsYes, "The re-parsed exclusiveSession flag must read back YES.");
        Assert.AreEqual(32, parsed.SessionDigest.Size, "The re-parsed digest must keep the 32-octet width.");
        Assert.IsTrue(parsed.SessionDigest.AsReadOnlySpan().SequenceEqual(ThirtyTwoOctetDigest), "The re-parsed digest octets must match the original.");
    }

    /// <summary>
    /// The same Table 148 layout for a non-exclusive session with a SHA-1-width (20-octet) digest — the
    /// <c>sessionDigest</c> buffer's width follows the session's own hash algorithm, not a fixed size.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 10.11.6, Table 148</see>.
    /// </summary>
    [TestMethod]
    public void SessionAuditInfoWithExclusiveSessionNoAndATwentyOctetDigestRoundTripsThroughTheWireByteExactly()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        //Redundant using local satisfies CA2000; ownership transfers to original and disposal is idempotent.
        using Tpm2bDigest digest = Tpm2bDigest.Create(TwentyOctetDigest, pool);
        using TpmsSessionAuditInfo original = TpmsSessionAuditInfo.Create(TpmiYesNo.No, digest);

        Assert.AreEqual(23, original.SerializedSize, "The 1-octet NO flag plus a 2-octet size prefix plus 20 digest octets is 23.");

        byte[] expected = [0x00, 0x00, 0x14, .. TwentyOctetDigest];
        byte[] buffer = new byte[original.SerializedSize];
        var writer = new TpmWriter(buffer);
        original.WriteTo(ref writer);

        Assert.AreEqual(buffer.Length, writer.Written, "WriteTo must fill exactly the reported serialized size.");
        Assert.IsTrue(buffer.AsSpan().SequenceEqual(expected), "The wire octets must be exclusiveSession=NO(00) then the TPM2B_DIGEST size and bytes.");

        var reader = new TpmReader(buffer);
        using TpmsSessionAuditInfo parsed = TpmsSessionAuditInfo.Parse(ref reader, pool);

        Assert.AreEqual(0, reader.Remaining, "Parse must consume exactly the structure's octets.");
        Assert.IsTrue(parsed.ExclusiveSession.IsNo, "The re-parsed exclusiveSession flag must read back NO.");
        Assert.IsTrue(parsed.SessionDigest.AsReadOnlySpan().SequenceEqual(TwentyOctetDigest), "The re-parsed digest octets must match the original.");
    }

    /// <summary>
    /// A <c>sessionDigest</c> size declared past the octets the reader actually holds must fail before any
    /// pooled buffer is rented — the same truncation discipline every other TPM2B carrier in this tree observes.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 10.11.6, Table 148</see>.
    /// </summary>
    [TestMethod]
    public void SessionAuditInfoParseWithADigestSizeDeclaredPastTheReaderThrowsWithNoRentalOutstanding()
    {
        using var housePool = new MeteredHousePool();

        //exclusiveSession=YES(01), sessionDigest declares size 0x0020 (32) but only two octets follow.
        byte[] truncated = [0x01, 0x00, 0x20, 0xAA, 0xBB];

        _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => ParseSessionAuditInfo(truncated, housePool.Pool),
            "A declared digest size exceeding the remaining reader octets must be refused.");
        Assert.AreEqual(0L, housePool.OutstandingCount, "The size-vs-remaining check runs before Tpm2bDigest.Parse rents any storage, so nothing was rented.");
    }

    /// <summary>
    /// <see cref="TpmsSessionAuditInfo.Dispose"/> releases the owned digest exactly once; a second call must
    /// neither throw nor return a second rental to the pool.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 10.11.6, Table 148</see>.
    /// </summary>
    [TestMethod]
    public void SessionAuditInfoDisposeIsIdempotentAndReturnsExactlyOneRentalToThePool()
    {
        using var housePool = new MeteredHousePool();

        //Redundant using local satisfies CA2000; ownership transfers to info and disposal is idempotent.
        using Tpm2bDigest digest = Tpm2bDigest.Create(TwentyOctetDigest, housePool.Pool);
        TpmsSessionAuditInfo info = TpmsSessionAuditInfo.Create(TpmiYesNo.No, digest);

        Assert.AreEqual(1L, housePool.OutstandingCount, "The digest buffer is rented before disposal.");

        info.Dispose();
        Assert.AreEqual(0L, housePool.OutstandingCount, "The first Dispose must return the digest's rental.");

        info.Dispose();
        Assert.AreEqual(0L, housePool.OutstandingCount, "A second Dispose must not disturb the balance (no double return).");
    }

    /// <summary>Parses a session-audit-info structure from <paramref name="data"/>; isolates the ref-struct reader from the throwing assertion's lambda.</summary>
    /// <param name="data">The wire octets.</param>
    /// <param name="pool">The memory pool.</param>
    private static void ParseSessionAuditInfo(byte[] data, BaseMemoryPool pool)
    {
        var reader = new TpmReader(data);
        using TpmsSessionAuditInfo _ = TpmsSessionAuditInfo.Parse(ref reader, pool);
    }
}
