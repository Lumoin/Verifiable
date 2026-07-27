using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.OAuth.Dpop;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Coverage for <see cref="InMemoryDpopReplayCache"/> — the shipped default backing for
/// <see cref="Verifiable.OAuth.IsDpopProofJtiSeenDelegate"/> and
/// <see cref="Verifiable.OAuth.PersistDpopProofJtiDelegate"/>. Exercises the two properties the prior
/// hand-rolled test double lacked: the read path treating an expired entry as NOT seen, and the entry
/// actually being evicted rather than retained for the lifetime of the process.
/// </summary>
[TestClass]
internal sealed class InMemoryDpopReplayCacheTests
{
    public TestContext TestContext { get; set; } = null!;

    private static readonly ExchangeContext Context = new();


    /// <summary>A jti never persisted is not seen.</summary>
    [TestMethod]
    public async Task UnknownJtiIsNotSeen()
    {
        InMemoryDpopReplayCache cache = new(new FakeTimeProvider());

        Assert.IsFalse(await cache.IsSeenAsync("jti-unknown", Context, TestContext.CancellationToken));
    }


    /// <summary>A persisted jti is seen while its freshness window has not elapsed.</summary>
    [TestMethod]
    public async Task PersistedJtiWithinWindowIsSeen()
    {
        FakeTimeProvider time = new(DateTimeOffset.UnixEpoch);
        InMemoryDpopReplayCache cache = new(time);

        await cache.PersistAsync("jti-1", time.GetUtcNow() + TimeSpan.FromMinutes(1), Context, TestContext.CancellationToken);

        Assert.IsTrue(await cache.IsSeenAsync("jti-1", Context, TestContext.CancellationToken));
    }


    /// <summary>
    /// RFC 9449 §11.1: once the freshness window a jti was persisted under has elapsed, it MUST no
    /// longer be reported as seen — the replay window closes rather than tracking the jti forever. The
    /// prior test double's read path (a bare <c>ContainsKey</c>) never checked the stored expiry, so
    /// this assertion fails against that logic; see the wave report for the recorded pre-fix failure.
    /// </summary>
    [TestMethod]
    public async Task ExpiredJtiIsNotSeen()
    {
        FakeTimeProvider time = new(DateTimeOffset.UnixEpoch);
        InMemoryDpopReplayCache cache = new(time);

        await cache.PersistAsync("jti-expired", time.GetUtcNow() + TimeSpan.FromSeconds(30), Context, TestContext.CancellationToken);

        time.Advance(TimeSpan.FromMinutes(1));

        Assert.IsFalse(await cache.IsSeenAsync("jti-expired", Context, TestContext.CancellationToken));
    }


    /// <summary>
    /// An expired entry is evicted, not merely masked, the moment its expiry is observed on the read
    /// path — <see cref="InMemoryDpopReplayCache.Count"/> drops so the tracked set does not retain
    /// stale entries forever.
    /// </summary>
    [TestMethod]
    public async Task ExpiredEntryIsEvictedOnLookup()
    {
        FakeTimeProvider time = new(DateTimeOffset.UnixEpoch);
        InMemoryDpopReplayCache cache = new(time);

        await cache.PersistAsync("jti-evict", time.GetUtcNow() + TimeSpan.FromSeconds(30), Context, TestContext.CancellationToken);
        time.Advance(TimeSpan.FromMinutes(1));

        await cache.IsSeenAsync("jti-evict", Context, TestContext.CancellationToken);

        Assert.AreEqual(0, cache.Count);
    }


    /// <summary>
    /// An expired entry that is never looked up again is still swept: persisting any jti sweeps every
    /// entry whose expiry has passed, so a cache fed one jti per request does not grow without bound
    /// even when replay attempts never occur.
    /// </summary>
    [TestMethod]
    public async Task PersistSweepsUnrelatedExpiredEntries()
    {
        FakeTimeProvider time = new(DateTimeOffset.UnixEpoch);
        InMemoryDpopReplayCache cache = new(time);

        await cache.PersistAsync("jti-old", time.GetUtcNow() + TimeSpan.FromSeconds(30), Context, TestContext.CancellationToken);
        time.Advance(TimeSpan.FromMinutes(1));

        //A fresh, unrelated jti arrives; its own persist call sweeps jti-old, which nothing ever looks
        //up again.
        await cache.PersistAsync("jti-new", time.GetUtcNow() + TimeSpan.FromSeconds(30), Context, TestContext.CancellationToken);

        Assert.AreEqual(1, cache.Count);
        Assert.IsTrue(await cache.IsSeenAsync("jti-new", Context, TestContext.CancellationToken));
    }


    /// <summary>Persisting the same jti twice overwrites its recorded expiry (idempotent re-insertion).</summary>
    [TestMethod]
    public async Task PersistOverwritesExpiryForSameJti()
    {
        FakeTimeProvider time = new(DateTimeOffset.UnixEpoch);
        InMemoryDpopReplayCache cache = new(time);

        await cache.PersistAsync("jti-1", time.GetUtcNow() + TimeSpan.FromSeconds(1), Context, TestContext.CancellationToken);
        await cache.PersistAsync("jti-1", time.GetUtcNow() + TimeSpan.FromMinutes(5), Context, TestContext.CancellationToken);

        time.Advance(TimeSpan.FromSeconds(2));

        Assert.IsTrue(await cache.IsSeenAsync("jti-1", Context, TestContext.CancellationToken));
    }
}
