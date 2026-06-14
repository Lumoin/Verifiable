using System.Buffers;
using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.Microsoft;

namespace Verifiable.Tests.Cryptography;

[TestClass]
internal sealed class KeyExtensionsHmacTests
{
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public async Task SymmetricKeyMemoryComputeHmacAsyncProducesExpectedMac()
    {
        byte[] keyBytes = new byte[32];
        RandomNumberGenerator.Fill(keyBytes);
        byte[] message = "extension-test"u8.ToArray();

        IMemoryOwner<byte> keyOwner = BaseMemoryPool.Shared.Rent(keyBytes.Length);
        keyBytes.AsSpan().CopyTo(keyOwner.Memory.Span);
        using SymmetricKeyMemory key = new(keyOwner, CryptoTags.HmacSha256Key);

        using HmacValue viaExtension = await key.ComputeHmacAsync(
            message,
            32,
            MicrosoftHmacFunctions.ComputeHmacAsync,
            BaseMemoryPool.Shared,
            null,
            TestContext.CancellationToken).ConfigureAwait(false);

        byte[] viaBcl = HMACSHA256.HashData(keyBytes, message);
        CollectionAssert.AreEqual(viaBcl, viaExtension.AsReadOnlySpan().ToArray());
    }


    [TestMethod]
    public async Task SymmetricKeyMemoryVerifyHmacAsyncWithHmacValueAcceptsCorrect()
    {
        byte[] keyBytes = new byte[32];
        RandomNumberGenerator.Fill(keyBytes);
        byte[] message = "verify-test"u8.ToArray();

        IMemoryOwner<byte> keyOwner = BaseMemoryPool.Shared.Rent(keyBytes.Length);
        keyBytes.AsSpan().CopyTo(keyOwner.Memory.Span);
        using SymmetricKeyMemory key = new(keyOwner, CryptoTags.HmacSha256Key);

        using HmacValue mac = await key.ComputeHmacAsync(
            message, 32, MicrosoftHmacFunctions.ComputeHmacAsync,
            BaseMemoryPool.Shared, null, TestContext.CancellationToken).ConfigureAwait(false);

        bool isValid = await key.VerifyHmacAsync(
            message, mac, MicrosoftHmacFunctions.VerifyHmacAsync,
            BaseMemoryPool.Shared, null, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isValid);
    }


    [TestMethod]
    public async Task SymmetricKeyMemoryVerifyHmacAsyncWithRawBytesAcceptsCorrect()
    {
        byte[] keyBytes = new byte[32];
        RandomNumberGenerator.Fill(keyBytes);
        byte[] message = "verify-raw-bytes"u8.ToArray();

        byte[] expectedMac = HMACSHA256.HashData(keyBytes, message);

        IMemoryOwner<byte> keyOwner = BaseMemoryPool.Shared.Rent(keyBytes.Length);
        keyBytes.AsSpan().CopyTo(keyOwner.Memory.Span);
        using SymmetricKeyMemory key = new(keyOwner, CryptoTags.HmacSha256Key);

        bool isValid = await key.VerifyHmacAsync(
            message,
            expectedMac.AsMemory(),
            MicrosoftHmacFunctions.VerifyHmacAsync,
            BaseMemoryPool.Shared,
            null,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isValid);
    }


    [TestMethod]
    public async Task SymmetricKeyMemoryVerifyHmacAsyncRejectsTampered()
    {
        byte[] keyBytes = new byte[32];
        RandomNumberGenerator.Fill(keyBytes);
        byte[] message = "tampered"u8.ToArray();

        byte[] tampered = HMACSHA256.HashData(keyBytes, message);
        tampered[5] ^= 0xff;

        IMemoryOwner<byte> keyOwner = BaseMemoryPool.Shared.Rent(keyBytes.Length);
        keyBytes.AsSpan().CopyTo(keyOwner.Memory.Span);
        using SymmetricKeyMemory key = new(keyOwner, CryptoTags.HmacSha256Key);

        bool isValid = await key.VerifyHmacAsync(
            message,
            tampered.AsMemory(),
            MicrosoftHmacFunctions.VerifyHmacAsync,
            BaseMemoryPool.Shared,
            null,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(isValid);
    }
}
