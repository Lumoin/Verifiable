using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Server;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Coverage for <see cref="InMemoryDpopReplayCache"/>, the shipped default backing for
/// <see cref="Verifiable.OAuth.ConsultDpopProofJtiDelegate"/>: a first use is claimed and recorded until the instant the
/// caller names, a live record answers a replay, a record past its instant counts as none and is replaced or swept rather
/// than retained for the lifetime of the process.
/// </summary>
[TestClass]
internal sealed class InMemoryDpopReplayCacheTests
{
    /// <summary>The MSTest-supplied per-test context.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The request context the claims are made with; unused by the cache.</summary>
    private static ExchangeContext Context { get; } = [];

    /// <summary>The target URI every claim of a row names.</summary>
    private static Uri TargetUri { get; } = new("https://rs.example/protected");


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 Section 11.1</see>: "servers can store
    /// the jti value of each DPoP proof". A <c>jti</c> never claimed at the target URI is claimed as a first use, and the
    /// cache holds its one record.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task UnknownJtiIsClaimedAsAFirstUseAsync()
    {
        FakeTimeProvider time = new(DateTimeOffset.UnixEpoch);
        InMemoryDpopReplayCache cache = new(time);

        JtiReplayOutcome outcome = await cache.ConsultAsync(
            "jti-unknown", TargetUri, time.GetUtcNow() + TimeSpan.FromMinutes(1), Context, TestContext.CancellationToken);

        Assert.AreEqual(JtiReplayOutcome.FirstUse, outcome);
        Assert.AreEqual(1, cache.Count);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 Section 11.1</see>: "HTTP requests to the
    /// same URI for which the jti value has been seen before would be declined." A <c>jti</c> claimed at the target URI is
    /// answered as a replay while its record's instant has not passed.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ClaimedJtiWithinItsWindowIsAReplayAsync()
    {
        FakeTimeProvider time = new(DateTimeOffset.UnixEpoch);
        InMemoryDpopReplayCache cache = new(time);
        _ = await cache.ConsultAsync("jti-1", TargetUri, time.GetUtcNow() + TimeSpan.FromMinutes(1), Context, TestContext.CancellationToken);

        JtiReplayOutcome outcome = await cache.ConsultAsync(
            "jti-1", TargetUri, time.GetUtcNow() + TimeSpan.FromMinutes(1), Context, TestContext.CancellationToken);

        Assert.AreEqual(JtiReplayOutcome.Replayed, outcome);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 Section 11.1</see>: servers store the jti
    /// "for the time window in which the respective DPoP proof JWT would be accepted". Once the instant a <c>jti</c> was
    /// claimed until has passed, its record counts as none: claimed again, it is a first use.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ExpiredJtiIsClaimedAgainAsAFirstUseAsync()
    {
        FakeTimeProvider time = new(DateTimeOffset.UnixEpoch);
        InMemoryDpopReplayCache cache = new(time);
        _ = await cache.ConsultAsync("jti-expired", TargetUri, time.GetUtcNow() + TimeSpan.FromSeconds(30), Context, TestContext.CancellationToken);

        time.Advance(TimeSpan.FromMinutes(1));
        JtiReplayOutcome outcome = await cache.ConsultAsync(
            "jti-expired", TargetUri, time.GetUtcNow() + TimeSpan.FromSeconds(30), Context, TestContext.CancellationToken);

        Assert.AreEqual(JtiReplayOutcome.FirstUse, outcome);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 Section 11.1</see>: servers store the jti
    /// "for the time window in which the respective DPoP proof JWT would be accepted", and "HTTP requests to the same URI
    /// for which the jti value has been seen before would be declined." A record past its instant is replaced by the claim
    /// of its own pair, not kept beside the new one: that claim is a first use, the cache holds one record after it, and a
    /// further claim of the pair within the new instant is a replay, so the replacing record is the one that counts. The
    /// one record, rather than two, is the library's policy on the cache's size, not a rule of the text.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ClaimOfAnExpiredPairReplacesItsRecordAsync()
    {
        FakeTimeProvider time = new(DateTimeOffset.UnixEpoch);
        InMemoryDpopReplayCache cache = new(time);
        _ = await cache.ConsultAsync("jti-evict", TargetUri, time.GetUtcNow() + TimeSpan.FromSeconds(30), Context, TestContext.CancellationToken);
        time.Advance(TimeSpan.FromMinutes(1));

        JtiReplayOutcome replacing = await cache.ConsultAsync(
            "jti-evict", TargetUri, time.GetUtcNow() + TimeSpan.FromSeconds(30), Context, TestContext.CancellationToken);
        int countAfterReplacing = cache.Count;
        JtiReplayOutcome following = await cache.ConsultAsync(
            "jti-evict", TargetUri, time.GetUtcNow() + TimeSpan.FromSeconds(30), Context, TestContext.CancellationToken);

        Assert.AreEqual(JtiReplayOutcome.FirstUse, replacing, "The claim of an expired pair is a first use.");
        Assert.AreEqual(1, countAfterReplacing, "The expired record is replaced, not kept beside the new one.");
        Assert.AreEqual(JtiReplayOutcome.Replayed, following, "The replacing record counts within its instant.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 Section 11.1</see>: "In the context of
    /// the target URI, servers can store the jti value of each DPoP proof", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">Section 4.3</see>: "servers SHOULD employ
    /// syntax-based normalization (Section 6.2.2 of [RFC3986]) and scheme-based normalization (Section 6.2.3 of
    /// [RFC3986]) before comparing the htu claim." <c>https://RS.example:443/items/a%2fb</c> and
    /// <c>https://rs.example/items/a%2Fb</c> name one target URI, differing by the host's case, the explicit default port
    /// and the case of a percent-encoding's hexadecimal digits. A <c>jti</c> claimed at the one spelling is a replay at the
    /// other, and the cache holds one record.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task TwoSpellingsOfOneTargetUriClaimOneRecordAsync()
    {
        FakeTimeProvider time = new(DateTimeOffset.UnixEpoch);
        InMemoryDpopReplayCache cache = new(time);

        JtiReplayOutcome first = await cache.ConsultAsync(
            "jti-spelled", new Uri("https://RS.example:443/items/a%2fb"), time.GetUtcNow() + TimeSpan.FromMinutes(1), Context,
            TestContext.CancellationToken);
        JtiReplayOutcome second = await cache.ConsultAsync(
            "jti-spelled", new Uri("https://rs.example/items/a%2Fb"), time.GetUtcNow() + TimeSpan.FromMinutes(1), Context,
            TestContext.CancellationToken);

        Assert.AreEqual(JtiReplayOutcome.FirstUse, first);
        Assert.AreEqual(JtiReplayOutcome.Replayed, second, "The second spelling names the target the jti was claimed at.");
        Assert.AreEqual(1, cache.Count, "One target URI is one record.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 Section 11.1</see>: "HTTP requests to the
    /// same URI for which the jti value has been seen before would be declined.", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-6.2.2.2">RFC 3986 Section 6.2.2.2</see>: "These URIs
    /// should be normalized by decoding any percent-encoded octet that corresponds to an unreserved character, as
    /// described in Section 2.3.", a space being no unreserved character. <c>https://rs.example/a%20</c> and
    /// <c>https://rs.example/a</c> name two target URIs. One <c>jti</c> claimed at each, each target handed to the cache in
    /// the normalized form a resource hands its store, is a first use at each, and the cache holds two records.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ATargetEndingInAnEncodedSpaceAndOneWithoutClaimTwoRecordsAsync()
    {
        FakeTimeProvider time = new(DateTimeOffset.UnixEpoch);
        InMemoryDpopReplayCache cache = new(time);

        JtiReplayOutcome encodedSpace = await cache.ConsultAsync(
            "jti-space", new Uri(DpopProofValidator.NormalizeTargetUri("https://rs.example/a%20")), time.GetUtcNow() + TimeSpan.FromMinutes(1),
            Context, TestContext.CancellationToken);
        JtiReplayOutcome withoutSpace = await cache.ConsultAsync(
            "jti-space", new Uri(DpopProofValidator.NormalizeTargetUri("https://rs.example/a")), time.GetUtcNow() + TimeSpan.FromMinutes(1),
            Context, TestContext.CancellationToken);

        Assert.AreEqual(JtiReplayOutcome.FirstUse, encodedSpace, "The jti is first used at the target ending in an encoded space.");
        Assert.AreEqual(JtiReplayOutcome.FirstUse, withoutSpace, "The target without the space is another target.");
        Assert.AreEqual(2, cache.Count, "Two target URIs are two records.");
    }


    /// <summary>
    /// A record past its instant that no claim names again is still swept: the first use of any other pair sweeps every
    /// record whose instant has passed, so a cache fed one <c>jti</c> per request does not grow without bound even when no
    /// replay is ever attempted. The bound on the cache's size is the library's policy, not a rule of RFC 9449, whose
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">Section 11.1</see> names only the time window a
    /// record serves: "for the time window in which the respective DPoP proof JWT would be accepted".
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ClaimSweepsUnrelatedExpiredRecordsAsync()
    {
        FakeTimeProvider time = new(DateTimeOffset.UnixEpoch);
        InMemoryDpopReplayCache cache = new(time);
        _ = await cache.ConsultAsync("jti-old", TargetUri, time.GetUtcNow() + TimeSpan.FromSeconds(30), Context, TestContext.CancellationToken);
        time.Advance(TimeSpan.FromMinutes(1));

        //A fresh, unrelated jti arrives; its own claim sweeps jti-old, which nothing presents again.
        _ = await cache.ConsultAsync("jti-new", TargetUri, time.GetUtcNow() + TimeSpan.FromSeconds(30), Context, TestContext.CancellationToken);

        Assert.AreEqual(1, cache.Count);
        Assert.AreEqual(
            JtiReplayOutcome.Replayed,
            await cache.ConsultAsync("jti-new", TargetUri, time.GetUtcNow() + TimeSpan.FromSeconds(30), Context, TestContext.CancellationToken));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 Section 11.1</see>: "In the context of
    /// the target URI, servers can store the jti value of each DPoP proof for the time window in which the respective DPoP
    /// proof JWT would be accepted to prevent multiple uses of the same DPoP proof." The window is the proof's, so a replay
    /// records nothing: the record keeps the instant its first use was claimed until, a replay naming a later instant does
    /// not lengthen the window, and once the first instant has passed the <c>jti</c> is claimed again as a first use.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task AReplayLeavesTheRecordAsItIsAsync()
    {
        FakeTimeProvider time = new(DateTimeOffset.UnixEpoch);
        InMemoryDpopReplayCache cache = new(time);
        _ = await cache.ConsultAsync("jti-1", TargetUri, time.GetUtcNow() + TimeSpan.FromSeconds(1), Context, TestContext.CancellationToken);
        JtiReplayOutcome replay = await cache.ConsultAsync(
            "jti-1", TargetUri, time.GetUtcNow() + TimeSpan.FromMinutes(5), Context, TestContext.CancellationToken);

        time.Advance(TimeSpan.FromSeconds(2));
        JtiReplayOutcome afterWindow = await cache.ConsultAsync(
            "jti-1", TargetUri, time.GetUtcNow() + TimeSpan.FromSeconds(1), Context, TestContext.CancellationToken);

        Assert.AreEqual(JtiReplayOutcome.Replayed, replay);
        Assert.AreEqual(JtiReplayOutcome.FirstUse, afterWindow);
    }
}
