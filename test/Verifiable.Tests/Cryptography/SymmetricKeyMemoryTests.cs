using System.Buffers;
using System.Security.Cryptography;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Cryptography;

[TestClass]
internal sealed class SymmetricKeyMemoryTests
{
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public void ConstructorWithNullMemoryThrows()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() =>
            _ = new SymmetricKeyMemory(null!, CryptoTags.HmacSha256Key));
    }


    [TestMethod]
    public void ConstructorWithNullTagThrows()
    {
        IMemoryOwner<byte> owner = SensitiveMemoryPool<byte>.Shared.Rent(32);
        try
        {
            Assert.ThrowsExactly<ArgumentNullException>(() =>
                _ = new SymmetricKeyMemory(owner, null!));
        }
        finally
        {
            owner.Dispose();
        }
    }


    [TestMethod]
    public void TagExposesSuppliedTag()
    {
        byte[] keyBytes = new byte[32];
        RandomNumberGenerator.Fill(keyBytes);

        IMemoryOwner<byte> owner = SensitiveMemoryPool<byte>.Shared.Rent(32);
        keyBytes.CopyTo(owner.Memory.Span);

        using SymmetricKeyMemory key = new(owner, CryptoTags.HmacSha256Key);

        Assert.AreSame(CryptoTags.HmacSha256Key, key.Tag);
    }


    [TestMethod]
    public async Task WithKeyBytesAsyncExposesBytesForOperationDuration()
    {
        byte[] expected = new byte[32];
        RandomNumberGenerator.Fill(expected);

        IMemoryOwner<byte> owner = SensitiveMemoryPool<byte>.Shared.Rent(32);
        expected.AsSpan().CopyTo(owner.Memory.Span);

        using SymmetricKeyMemory key = new(owner, CryptoTags.HmacSha256Key);

        byte[] observed = await key.WithKeyBytesAsync(
            static (bytes, _) => ValueTask.FromResult(bytes.ToArray()),
            0).ConfigureAwait(false);

        CollectionAssert.AreEqual(expected, observed);
    }
}
