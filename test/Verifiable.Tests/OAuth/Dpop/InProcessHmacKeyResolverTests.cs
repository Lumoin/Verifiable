using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.Microsoft;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth.Dpop;

[TestClass]
internal sealed class InProcessHmacKeyResolverTests
{
    public TestContext TestContext { get; set; } = null!;

    private static readonly TenantId TestTenant = new("test-tenant");


    [TestMethod]
    public async Task ResolveCurrentReturnsInitialKey()
    {
        using SymmetricKey key = CreateKey();
        InProcessHmacKeyResolver resolver = new(key, "kid-1");

        HmacKeyResolution? result = await resolver.ResolveAsync(
            kid: null, TestTenant, new RequestContext(), TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.IsNotNull(result);
        Assert.AreEqual("kid-1", result.Kid);
        Assert.AreSame(key, result.Key);
    }


    [TestMethod]
    public async Task ResolveByKidReturnsMatch()
    {
        using SymmetricKey key = CreateKey();
        InProcessHmacKeyResolver resolver = new(key, "kid-A");

        HmacKeyResolution? result = await resolver.ResolveAsync(
            "kid-A", TestTenant, new RequestContext(), TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.IsNotNull(result);
        Assert.AreEqual("kid-A", result.Kid);
        Assert.AreSame(key, result.Key);
    }


    [TestMethod]
    public async Task ResolveUnknownKidReturnsNull()
    {
        using SymmetricKey key = CreateKey();
        InProcessHmacKeyResolver resolver = new(key, "kid-A");

        HmacKeyResolution? result = await resolver.ResolveAsync(
            "kid-never-issued", TestTenant, new RequestContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(result);
    }


    [TestMethod]
    public async Task RotateMovesCurrentToRetired()
    {
        using SymmetricKey first = CreateKey();
        using SymmetricKey second = CreateKey();
        InProcessHmacKeyResolver resolver = new(first, "kid-A");

        resolver.Rotate(second, "kid-B");

        HmacKeyResolution? current = await resolver.ResolveAsync(
            kid: null, TestTenant, new RequestContext(), TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.IsNotNull(current);
        Assert.AreEqual("kid-B", current.Kid);
        Assert.AreSame(second, current.Key);
    }


    [TestMethod]
    public async Task ResolveRetiredKidReturnsRetiredKey()
    {
        using SymmetricKey first = CreateKey();
        using SymmetricKey second = CreateKey();
        InProcessHmacKeyResolver resolver = new(first, "kid-A");

        resolver.Rotate(second, "kid-B");

        HmacKeyResolution? retired = await resolver.ResolveAsync(
            "kid-A", TestTenant, new RequestContext(), TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.IsNotNull(retired);
        Assert.AreEqual("kid-A", retired.Kid);
        Assert.AreSame(first, retired.Key);
    }


    [TestMethod]
    public async Task RotateBeyondMaxRetainedDropsOldest()
    {
        //maxRetainedKeys = 2: at most 2 retired entries are remembered. The
        //fourth rotation should evict the oldest retired entry.
        using SymmetricKey k1 = CreateKey();
        using SymmetricKey k2 = CreateKey();
        using SymmetricKey k3 = CreateKey();
        using SymmetricKey k4 = CreateKey();
        InProcessHmacKeyResolver resolver = new(k1, "kid-1", maxRetainedKeys: 2);

        resolver.Rotate(k2, "kid-2");
        resolver.Rotate(k3, "kid-3");
        resolver.Rotate(k4, "kid-4");

        //kid-1 is the oldest retired and must have been evicted; kid-2 and
        //kid-3 must still be reachable. The InProcessHmacKeyResolver orders
        //retired entries by ordinal kid string for eviction, matching the
        //library's documented behaviour.
        HmacKeyResolution? evicted = await resolver.ResolveAsync(
            "kid-1", TestTenant, new RequestContext(), TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.IsNull(evicted, "Oldest retired key must be evicted past maxRetainedKeys.");

        HmacKeyResolution? still2 = await resolver.ResolveAsync(
            "kid-2", TestTenant, new RequestContext(), TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.IsNotNull(still2);
        Assert.AreSame(k2, still2.Key);

        HmacKeyResolution? still3 = await resolver.ResolveAsync(
            "kid-3", TestTenant, new RequestContext(), TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.IsNotNull(still3);
        Assert.AreSame(k3, still3.Key);
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "SymmetricKeyMemory ownership transfers to the returned SymmetricKey, which the caller disposes.")]
    private static SymmetricKey CreateKey()
    {
        IMemoryOwner<byte> owner = SensitiveMemoryPool<byte>.Shared.Rent(32);
        SymmetricKeyMemory material;
        try
        {
            RandomNumberGenerator.Fill(owner.Memory.Span[..32]);
            material = new SymmetricKeyMemory(owner, CryptoTags.HmacSha256Key);
        }
        catch
        {
            owner.Dispose();
            throw;
        }

        return new SymmetricKey(
            material,
            Guid.NewGuid().ToString("N"),
            MicrosoftHmacFunctions.ComputeHmacAsync,
            MicrosoftHmacFunctions.VerifyHmacAsync);
    }
}
