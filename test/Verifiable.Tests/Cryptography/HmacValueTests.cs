using System.Buffers;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Cryptography;

[TestClass]
internal sealed class HmacValueTests
{
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public void LengthMatchesUnderlyingBufferLength()
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(32);
        owner.Memory.Span.Clear();

        using HmacValue value = new(owner, CryptoTags.HmacSha256Value);

        Assert.AreEqual(32, value.Length);
    }


    [TestMethod]
    public void TwoInstancesWithIdenticalBytesAreEqual()
    {
        byte[] sharedBytes = [1, 2, 3, 4, 5, 6, 7, 8];

        IMemoryOwner<byte> owner1 = BaseMemoryPool.Shared.Rent(sharedBytes.Length);
        sharedBytes.CopyTo(owner1.Memory.Span);

        IMemoryOwner<byte> owner2 = BaseMemoryPool.Shared.Rent(sharedBytes.Length);
        sharedBytes.CopyTo(owner2.Memory.Span);

        using HmacValue a = new(owner1, CryptoTags.HmacSha256Value);
        using HmacValue b = new(owner2, CryptoTags.HmacSha256Value);

        Assert.IsTrue(a.Equals(b));
        Assert.IsTrue(a == b);
        Assert.IsFalse(a != b);
        Assert.AreEqual(a.GetHashCode(), b.GetHashCode());
    }


    [TestMethod]
    public void TwoInstancesWithDifferentBytesAreNotEqual()
    {
        IMemoryOwner<byte> owner1 = BaseMemoryPool.Shared.Rent(8);
        new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }.CopyTo(owner1.Memory.Span);

        IMemoryOwner<byte> owner2 = BaseMemoryPool.Shared.Rent(8);
        new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 }.CopyTo(owner2.Memory.Span);

        using HmacValue a = new(owner1, CryptoTags.HmacSha256Value);
        using HmacValue b = new(owner2, CryptoTags.HmacSha256Value);

        Assert.IsFalse(a.Equals(b));
        Assert.IsFalse(a == b);
        Assert.IsTrue(a != b);
    }


    [TestMethod]
    public void NullEqualsNullViaOperator()
    {
        Assert.IsTrue((HmacValue?)null == (HmacValue?)null);
    }


    [TestMethod]
    public void DebuggerDisplayContainsLengthAndHexPreview()
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(32);
        new byte[]
        {
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
            0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
            0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
            0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
        }.CopyTo(owner.Memory.Span);

        using HmacValue value = new(owner, CryptoTags.HmacSha256Value);

        string text = value.ToString();
        Assert.Contains("32 bytes", text, StringComparison.Ordinal);
        Assert.Contains("b0344c61", text, StringComparison.Ordinal);
    }
}
