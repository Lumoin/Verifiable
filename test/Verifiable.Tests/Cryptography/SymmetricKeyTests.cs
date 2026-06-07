using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.Microsoft;

namespace Verifiable.Tests.Cryptography;

[TestClass]
internal sealed class SymmetricKeyTests
{
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "SymmetricKeyMemory ownership transfers to the SymmetricKey, which is disposed via 'using'.")]
    public async Task SymmetricKeyComputeAndVerifyRoundTrips()
    {
        byte[] keyBytes = new byte[32];
        RandomNumberGenerator.Fill(keyBytes);
        byte[] message = "bound-key-roundtrip"u8.ToArray();

        IMemoryOwner<byte> keyOwner = SensitiveMemoryPool<byte>.Shared.Rent(keyBytes.Length);
        keyBytes.AsSpan().CopyTo(keyOwner.Memory.Span);
        SymmetricKeyMemory material = new(keyOwner, CryptoTags.HmacSha256Key);

        using SymmetricKey key = new(
            material,
            id: "test-key-id",
            computeHmac: MicrosoftHmacFunctions.ComputeHmacAsync,
            verifyHmac: MicrosoftHmacFunctions.VerifyHmacAsync);

        Assert.AreEqual("test-key-id", key.Id);

        using HmacValue mac = await key.ComputeHmacAsync(
            message, 32, SensitiveMemoryPool<byte>.Shared, null,
            TestContext.CancellationToken).ConfigureAwait(false);

        bool isValid = await key.VerifyHmacAsync(
            message, mac, SensitiveMemoryPool<byte>.Shared, null,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isValid);
    }


    [TestMethod]
    public void ConstructorRejectsNullComputeDelegate()
    {
        IMemoryOwner<byte> keyOwner = SensitiveMemoryPool<byte>.Shared.Rent(32);
        keyOwner.Memory.Span.Clear();
        using SymmetricKeyMemory material = new(keyOwner, CryptoTags.HmacSha256Key);

        Assert.ThrowsExactly<ArgumentNullException>(() =>
            _ = new SymmetricKey(material, "id", null!, MicrosoftHmacFunctions.VerifyHmacAsync));
    }


    [TestMethod]
    public void ConstructorRejectsNullVerifyDelegate()
    {
        IMemoryOwner<byte> keyOwner = SensitiveMemoryPool<byte>.Shared.Rent(32);
        keyOwner.Memory.Span.Clear();
        using SymmetricKeyMemory material = new(keyOwner, CryptoTags.HmacSha256Key);

        Assert.ThrowsExactly<ArgumentNullException>(() =>
            _ = new SymmetricKey(material, "id", MicrosoftHmacFunctions.ComputeHmacAsync, null!));
    }
}
