using System;
using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Tests for TPM2B buffer structures.
/// </summary>
[TestClass]
internal class Tpm2bStructureTests
{
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public void Tpm2bDigestParsesCorrectly()
    {
        //TPM2B_DIGEST: size (2 bytes) + buffer (variable).
        //SHA-256 produces 32-byte digests.
        byte[] data =
        [
            0x00, 0x20, //Size field: 32 bytes (0x0020 big-endian).
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
        ];
        var reader = new TpmReader(data);
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using Tpm2bDigest digest = Tpm2bDigest.Parse(ref reader, pool);

        Assert.AreEqual(34, reader.Consumed);
        Assert.AreEqual(32, digest.Size);

        //Verify first and last bytes.
        ReadOnlySpan<byte> bytes = digest.AsReadOnlySpan();
        Assert.AreEqual(0x01, bytes[0]);
        Assert.AreEqual(0x20, bytes[31]);
    }

    [TestMethod]
    public void Tpm2bDigestCreateEmptyIsEmpty()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using Tpm2bDigest digest = Tpm2bDigest.Empty;

        Assert.IsTrue(digest.IsEmpty);
        Assert.AreEqual(0, digest.Size);
    }

    [TestMethod]
    public void Tpm2bDigestParsesEmptyBuffer()
    {
        byte[] data = [0x00, 0x00]; //Size = 0.
        var reader = new TpmReader(data);
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using Tpm2bDigest digest = Tpm2bDigest.Parse(ref reader, pool);

        Assert.AreEqual(2, reader.Consumed);
        Assert.IsTrue(digest.IsEmpty);
    }

    [TestMethod]
    public void Tpm2bDigestSerializedSizeIsCorrect()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] testData = new byte[64];

        using Tpm2bDigest digest = Tpm2bDigest.Create(testData, pool);

        //Size field (2) + data length.
        Assert.AreEqual(66, digest.SerializedSize);
    }

    [TestMethod]
    public void Tpm2bDigestCreateCopiesData()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] original = [0x01, 0x02, 0x03, 0x04];

        using Tpm2bDigest digest = Tpm2bDigest.Create(original, pool);

        //Modify original - digest should be unaffected.
        original[0] = 0xFF;

        Assert.AreEqual(0x01, digest.AsReadOnlySpan()[0]);
    }

    /// <summary>
    /// A <c>TPM2B_DIGEST</c> buffer is bounded by <c>sizeof(TPMU_HA)</c> — the widest member of the hash union,
    /// 64 octets for SHA-512 (TPM 2.0 Library Part 2, clause 10.4.2, Table 92's
    /// <c>buffer[size]{:sizeof(TPMU_HA)}</c>). The bound itself is admitted; one octet past it is a structure
    /// no hash algorithm can fill, and the factory refuses it rather than renting for it.
    /// </summary>
    [TestMethod]
    public void Tpm2bDigestCreateAdmitsTheUnionBoundAndRefusesPastIt()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using(Tpm2bDigest atBound = Tpm2bDigest.Create(new byte[Tpm2bDigest.MaxSize], pool))
        {
            Assert.AreEqual(64, atBound.Size, "TPM2B_DIGEST's buffer bound is sizeof(TPMU_HA), the SHA-512 digest width.");
        }

        _ = Assert.ThrowsExactly<ArgumentException>(
            () => Tpm2bDigest.Create(new byte[Tpm2bDigest.MaxSize + 1], pool),
            "A digest wider than sizeof(TPMU_HA) is not a TPM2B_DIGEST and must be refused.");
    }

    /// <summary>
    /// The same <c>sizeof(TPMU_HA)</c> bound governs the wire form: a declared size past it is a malformed
    /// <c>TPM2B_DIGEST</c> (TPM 2.0 Library Part 2, clause 10.4.2, Table 92), refused before any storage is
    /// rented for the octets it claims.
    /// </summary>
    [TestMethod]
    public void Tpm2bDigestParseRefusesADeclaredSizePastTheUnionBound()
    {
        byte[] data = new byte[sizeof(ushort) + Tpm2bDigest.MaxSize + 1];
        data[0] = 0x00;
        data[1] = (byte)(Tpm2bDigest.MaxSize + 1);
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        _ = Assert.ThrowsExactly<InvalidOperationException>(
            () => ParseDigest(data, pool),
            "A declared TPM2B_DIGEST size wider than sizeof(TPMU_HA) is malformed.");
    }

    /// <summary>
    /// <c>TPM2B_NONCE</c> is a <c>TPM2B_DIGEST</c> whose "size limited to the same as the digest structure"
    /// (TPM 2.0 Library Part 2, clause 10.4.4, Table 94, page 134), so it carries that structure's own
    /// <c>sizeof(TPMU_HA)</c> buffer bound (clause 10.4.2, Table 92, page 134). The bound itself is admitted;
    /// one octet past it is refused rather than rented for.
    /// </summary>
    [TestMethod]
    public void Tpm2bNonceCreateAdmitsTheUnionBoundAndRefusesPastIt()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using(Tpm2bNonce atBound = Tpm2bNonce.Create(new byte[Tpm2bNonce.MaxSize], pool))
        {
            Assert.AreEqual(64, atBound.Size, "TPM2B_NONCE inherits TPM2B_DIGEST's sizeof(TPMU_HA) buffer bound.");
        }

        _ = Assert.ThrowsExactly<ArgumentException>(
            () => Tpm2bNonce.Create(new byte[Tpm2bNonce.MaxSize + 1], pool),
            "A nonce wider than sizeof(TPMU_HA) is not a TPM2B_NONCE and must be refused.");
    }

    /// <summary>
    /// The same bound governs <c>TPM2B_NONCE</c>'s wire form: a declared size past <c>sizeof(TPMU_HA)</c> is
    /// malformed (TPM 2.0 Library Part 2, clause 10.4.2, Table 92: "As with all sized buffers, the size is
    /// checked to see if it is within the prescribed range. If not, the response code is TPM_RC_SIZE"), refused
    /// before any storage is rented for the octets it claims.
    /// </summary>
    [TestMethod]
    public void Tpm2bNonceParseRefusesADeclaredSizePastTheUnionBound()
    {
        byte[] wire = new byte[sizeof(ushort) + Tpm2bNonce.MaxSize + 1];
        wire[0] = 0x00;
        wire[1] = (byte)(Tpm2bNonce.MaxSize + 1);
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        _ = Assert.ThrowsExactly<InvalidOperationException>(
            () => ParseNonce(wire, pool),
            "A declared TPM2B_NONCE size wider than sizeof(TPMU_HA) is malformed.");
    }

    /// <summary>
    /// The generated form takes the bound too: <see cref="Tpm2bNonce.CreateRandom"/> can only produce a value a
    /// <c>TPM2B_NONCE</c> could carry on the wire (TPM 2.0 Library Part 2, clause 10.4.4, Table 94 over clause
    /// 10.4.2, Table 92).
    /// </summary>
    [TestMethod]
    public void Tpm2bNonceCreateRandomRefusesALengthPastTheUnionBound()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        _ = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => Tpm2bNonce.CreateRandom(Tpm2bNonce.MaxSize + 1, pool),
            "A generated nonce wider than sizeof(TPMU_HA) could never be framed as a TPM2B_NONCE.");
    }

    /// <summary>
    /// <c>TPM2B_AUTH</c> is a <c>TPM2B_DIGEST</c> that "limits an authValue to being no larger than the largest
    /// digest produced by a TPM" (TPM 2.0 Library Part 2, clause 10.4.5, Table 95, page 135), so it carries the
    /// same <c>sizeof(TPMU_HA)</c> buffer bound (clause 10.4.2, Table 92, page 134). The bound itself is
    /// admitted; one octet past it is refused rather than rented for.
    /// </summary>
    [TestMethod]
    public void Tpm2bAuthCreateAdmitsTheUnionBoundAndRefusesPastIt()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using(Tpm2bAuth atBound = Tpm2bAuth.Create(new byte[Tpm2bAuth.MaxSize], pool))
        {
            Assert.AreEqual(64, atBound.Length, "TPM2B_AUTH inherits TPM2B_DIGEST's sizeof(TPMU_HA) buffer bound.");
        }

        _ = Assert.ThrowsExactly<ArgumentException>(
            () => Tpm2bAuth.Create(new byte[Tpm2bAuth.MaxSize + 1], pool),
            "An authorization value wider than sizeof(TPMU_HA) is not a TPM2B_AUTH and must be refused.");
    }

    /// <summary>
    /// The same bound governs <c>TPM2B_AUTH</c>'s wire form: a declared size past <c>sizeof(TPMU_HA)</c> is
    /// malformed (TPM 2.0 Library Part 2, clause 10.4.2, Table 92), refused before any storage is rented for the
    /// octets it claims.
    /// </summary>
    [TestMethod]
    public void Tpm2bAuthParseRefusesADeclaredSizePastTheUnionBound()
    {
        byte[] wire = new byte[sizeof(ushort) + Tpm2bAuth.MaxSize + 1];
        wire[0] = 0x00;
        wire[1] = (byte)(Tpm2bAuth.MaxSize + 1);
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        _ = Assert.ThrowsExactly<InvalidOperationException>(
            () => ParseAuth(wire, pool),
            "A declared TPM2B_AUTH size wider than sizeof(TPMU_HA) is malformed.");
    }

    /// <summary>
    /// The password overload inherits the bound, measured after the trailing-zero trim clause 17.6.4.3 of TPM
    /// 2.0 Library Part 1 requires: a configuration password whose UTF-8 encoding cannot fit a
    /// <c>TPM2B_AUTH</c> is refused rather than silently shortened into a value no TPM would hold.
    /// </summary>
    [TestMethod]
    public void Tpm2bAuthCreateFromPasswordRefusesAnEncodingPastTheUnionBound()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        string tooLong = new('a', Tpm2bAuth.MaxSize + 1);

        _ = Assert.ThrowsExactly<ArgumentException>(
            () => Tpm2bAuth.CreateFromPassword(tooLong, pool),
            "A password encoding wider than sizeof(TPMU_HA) is not a TPM2B_AUTH and must be refused.");

        using Tpm2bAuth atBound = Tpm2bAuth.CreateFromPassword(new string('a', Tpm2bAuth.MaxSize), pool);
        Assert.AreEqual(Tpm2bAuth.MaxSize, atBound.Length, "An encoding exactly at the bound stays admissible.");
    }

    /// <summary>
    /// Parses a <c>TPM2B_NONCE</c> from a complete wire fragment and releases it, so a refusal can be asserted
    /// as a single expression.
    /// </summary>
    /// <param name="wire">The wire fragment beginning at the size field.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    private static void ParseNonce(byte[] wire, BaseMemoryPool pool)
    {
        var reader = new TpmReader(wire);
        using Tpm2bNonce nonce = Tpm2bNonce.Parse(ref reader, pool);
    }

    /// <summary>
    /// Parses a <c>TPM2B_AUTH</c> from a complete wire fragment and releases it, so a refusal can be asserted as
    /// a single expression.
    /// </summary>
    /// <param name="wire">The wire fragment beginning at the size field.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    private static void ParseAuth(byte[] wire, BaseMemoryPool pool)
    {
        var reader = new TpmReader(wire);
        using Tpm2bAuth auth = Tpm2bAuth.Parse(ref reader, pool);
    }

    /// <summary>
    /// Parses a <c>TPM2B_DIGEST</c> from a complete wire fragment and releases it, so a refusal can be asserted
    /// as a single expression (a <see cref="TpmReader"/> is a <see langword="ref"/> struct and cannot be built
    /// inside the asserted lambda).
    /// </summary>
    /// <param name="wire">The wire fragment beginning at the size field.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    private static void ParseDigest(byte[] wire, BaseMemoryPool pool)
    {
        var reader = new TpmReader(wire);
        using Tpm2bDigest digest = Tpm2bDigest.Parse(ref reader, pool);
    }

    [TestMethod]
    public void Tpm2bNonceParsesCorrectly()
    {
        byte[] data =
        [
            0x00, 0x10, //Size field: 16 bytes.
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
        ];
        var reader = new TpmReader(data);
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using Tpm2bNonce nonce = Tpm2bNonce.Parse(ref reader, pool);

        Assert.AreEqual(18, reader.Consumed);
        Assert.AreEqual(16, nonce.Size);
        Assert.AreEqual(0x11, nonce.AsReadOnlySpan()[0]);
        Assert.AreEqual(0x00, nonce.AsReadOnlySpan()[15]);
    }

    [TestMethod]
    public void Tpm2bNonceCreateRandomGeneratesCorrectLength()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        const int NonceLength = 32;

        using Tpm2bNonce nonce = Tpm2bNonce.CreateRandom(NonceLength, pool);

        Assert.AreEqual(NonceLength, nonce.Size);
        Assert.IsFalse(nonce.IsEmpty);
    }

    [TestMethod]
    public void Tpm2bAuthParsesCorrectly()
    {
        byte[] data =
        [
            0x00, 0x08, //Size field: 8 bytes.
            0x70, 0x61, 0x73, 0x73, 0x77, 0x6F, 0x72, 0x64 //"password" in ASCII.
        ];
        var reader = new TpmReader(data);
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using Tpm2bAuth auth = Tpm2bAuth.Parse(ref reader, pool);

        Assert.AreEqual(10, reader.Consumed);
        Assert.AreEqual(8, auth.Length);
    }

    [TestMethod]
    public void Tpm2bAuthCreateFromPasswordTrimsTrailingZeros()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        //Password with trailing null characters would be trimmed.
        using Tpm2bAuth auth = Tpm2bAuth.CreateFromPassword("test", pool);

        Assert.AreEqual(4, auth.Length);
    }

    [TestMethod]
    public void Tpm2bAuthCreateEmptyIsEmpty()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using Tpm2bAuth auth = Tpm2bAuth.CreateEmpty(pool);

        Assert.IsTrue(auth.IsEmpty);
        Assert.AreEqual(0, auth.Length);
    }
}
