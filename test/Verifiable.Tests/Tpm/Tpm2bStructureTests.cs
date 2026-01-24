using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Tests for TPM2B buffer structures.
/// </summary>
[TestClass]
public class Tpm2bStructureTests
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
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;

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
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;

        using Tpm2bDigest digest = Tpm2bDigest.CreateEmpty();

        Assert.IsTrue(digest.IsEmpty);
        Assert.AreEqual(0, digest.Size);
    }

    [TestMethod]
    public void Tpm2bDigestParsesEmptyBuffer()
    {
        byte[] data = [0x00, 0x00]; //Size = 0.
        var reader = new TpmReader(data);
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;

        using Tpm2bDigest digest = Tpm2bDigest.Parse(ref reader, pool);

        Assert.AreEqual(2, reader.Consumed);
        Assert.IsTrue(digest.IsEmpty);
    }

    [TestMethod]
    public void Tpm2bDigestSerializedSizeIsCorrect()
    {
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        byte[] testData = new byte[64];

        using Tpm2bDigest digest = Tpm2bDigest.Create(testData, pool);

        //Size field (2) + data length.
        Assert.AreEqual(66, digest.GetSerializedSize());
    }

    [TestMethod]
    public void Tpm2bDigestCreateCopiesData()
    {
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        byte[] original = [0x01, 0x02, 0x03, 0x04];

        using Tpm2bDigest digest = Tpm2bDigest.Create(original, pool);

        //Modify original - digest should be unaffected.
        original[0] = 0xFF;

        Assert.AreEqual(0x01, digest.AsReadOnlySpan()[0]);
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
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;

        using Tpm2bNonce nonce = Tpm2bNonce.Parse(ref reader, pool);

        Assert.AreEqual(18, reader.Consumed);
        Assert.AreEqual(16, nonce.Size);
        Assert.AreEqual(0x11, nonce.AsReadOnlySpan()[0]);
        Assert.AreEqual(0x00, nonce.AsReadOnlySpan()[15]);
    }

    [TestMethod]
    public void Tpm2bNonceCreateRandomGeneratesCorrectLength()
    {
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
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
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;

        using Tpm2bAuth auth = Tpm2bAuth.Parse(ref reader, pool);

        Assert.AreEqual(10, reader.Consumed);
        Assert.AreEqual(8, auth.Length);
    }

    [TestMethod]
    public void Tpm2bAuthCreateFromPasswordTrimsTrailingZeros()
    {
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;

        //Password with trailing null characters would be trimmed.
        using Tpm2bAuth auth = Tpm2bAuth.CreateFromPassword("test", pool);

        Assert.AreEqual(4, auth.Length);
    }

    [TestMethod]
    public void Tpm2bAuthCreateEmptyIsEmpty()
    {
        MemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;

        using Tpm2bAuth auth = Tpm2bAuth.CreateEmpty(pool);

        Assert.IsTrue(auth.IsEmpty);
        Assert.AreEqual(0, auth.Length);
    }
}