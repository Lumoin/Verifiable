using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;

namespace Verifiable.Tests.Cryptography.Aead;

[TestClass]
internal sealed class ContentEncryptionKeyTests
{
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public void NewCekHasZeroUseCount()
    {
        using ContentEncryptionKey cek = BuildCek();
        Assert.AreEqual(0, cek.UseCount);
    }


    [TestMethod]
    public void UseKeyTransfersOwnershipAndIncrementsCount()
    {
        using ContentEncryptionKey cek = BuildCek();
        using SymmetricKeyMemory key = cek.UseKey();
        Assert.IsNotNull(key);
        Assert.AreEqual(1, cek.UseCount);
    }


    [TestMethod]
    public void SecondUseKeyThrowsAndIncrementsCount()
    {
        using ContentEncryptionKey cek = BuildCek();
        using SymmetricKeyMemory consumed = cek.UseKey();

        Assert.ThrowsExactly<InvalidOperationException>(() => cek.UseKey());
        Assert.AreEqual(2, cek.UseCount);
        Assert.IsNotNull(consumed);
    }


    [TestMethod]
    public void TagAccessAfterUseKeyThrows()
    {
        using ContentEncryptionKey cek = BuildCek();
        using SymmetricKeyMemory consumed = cek.UseKey();

        Assert.ThrowsExactly<InvalidOperationException>(() => _ = cek.Tag);
        Assert.IsNotNull(consumed);
    }


    [TestMethod]
    public void DisposeOnUnusedCekDoesNotIncrementUseCount()
    {
        ContentEncryptionKey cek = BuildCek();
        cek.Dispose();
        Assert.AreEqual(0, cek.UseCount);
    }


    /// <summary>Disposing the same key twice is safe; the two calls below are explicit (in addition to the
    /// <see langword="using"/> declaration's own release at scope exit) because the repeated call is itself
    /// the behaviour under test.</summary>
    [TestMethod]
    public void DisposeIsIdempotent()
    {
        using ContentEncryptionKey cek = BuildCek();
        cek.Dispose();
        cek.Dispose();
    }


    [TestMethod]
    public void ConstructorRejectsNullInner()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => _ = new ContentEncryptionKey(null!));
    }


    [TestMethod]
    public async Task ConcurrentUseKeyAdmitsExactlyOneCaller()
    {
        using ContentEncryptionKey cek = BuildCek();
        using System.Threading.Barrier barrier = new(2);
        int successes = 0;
        int failures = 0;

        void Body()
        {
            barrier.SignalAndWait(TestContext.CancellationToken);
            try
            {
                using SymmetricKeyMemory consumed = cek.UseKey();
                Assert.IsNotNull(consumed);
                System.Threading.Interlocked.Increment(ref successes);
            }
            catch(InvalidOperationException)
            {
                System.Threading.Interlocked.Increment(ref failures);
            }
        }

        Task t1 = Task.Run(Body, TestContext.CancellationToken);
        Task t2 = Task.Run(Body, TestContext.CancellationToken);

        await Task.WhenAll(t1, t2).WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(1, successes);
        Assert.AreEqual(1, failures);
        Assert.AreEqual(2, cek.UseCount);
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "SymmetricKeyMemory ownership transfers to the returned ContentEncryptionKey, which is disposed by the caller.")]
    private static ContentEncryptionKey BuildCek()
    {
        byte[] bytes = new byte[32];
        RandomNumberGenerator.Fill(bytes);
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(bytes.Length);
        bytes.AsSpan().CopyTo(owner.Memory.Span);
        SymmetricKeyMemory inner = new(owner, CryptoTags.AesGcmCek);
        return new ContentEncryptionKey(inner);
    }
}
