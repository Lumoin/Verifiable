using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Core.StatusList;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;

using StatusListType = Verifiable.Core.StatusList.StatusList;

namespace Verifiable.Tests.StatusList;

/// <summary>
/// Tests for <see cref="CredentialStatusGate"/>, the verifier-agnostic revocation gate. These
/// exercise it as a bare static call — no OID4VP executor, no server pipeline — which is exactly
/// how a peer wallet or an agent acting as the verifier would invoke it. The caller supplies the
/// already-verified Status List Token through the resolver; here it is built directly, standing in
/// for whatever fetched and verified it (an HTTP + JWS-verify, or an Orleans status-list grain).
/// </summary>
[TestClass]
internal sealed class CredentialStatusGateTests
{
    private const string ListUri = "https://issuer.example/statuslists/1";
    private const int CredentialIndex = 42;
    private static readonly DateTimeOffset Now = TestClock.CanonicalEpoch;

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    public TestContext TestContext { get; set; } = null!;

    private static ResolveVerifiedStatusListTokenDelegate ResolverFor(StatusListToken token) =>
        (uri, ct) => ValueTask.FromResult(token);


    [TestMethod]
    public async Task UnsetEntryReadsAsValid()
    {
        using var list = StatusListType.Create(64, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        var token = new StatusListToken(ListUri, Now, list);

        CredentialStatusOutcome outcome = await CredentialStatusGate.CheckAsync(
            new StatusListReference(CredentialIndex, ListUri), ResolverFor(token), Now, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(outcome.IsValid);
        Assert.AreEqual(StatusTypes.Valid, outcome.Status);
    }


    [TestMethod]
    public async Task RevokedEntryReadsAsInvalid()
    {
        using var list = StatusListType.Create(64, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        list[CredentialIndex] = StatusTypes.Invalid;
        var token = new StatusListToken(ListUri, Now, list);

        CredentialStatusOutcome outcome = await CredentialStatusGate.CheckAsync(
            new StatusListReference(CredentialIndex, ListUri), ResolverFor(token), Now, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsValid);
        Assert.AreEqual(StatusTypes.Invalid, outcome.Status);
    }


    [TestMethod]
    public async Task SuspendedEntryReadsAsNotValid()
    {
        using var list = StatusListType.Create(64, StatusListBitSize.TwoBits, Pool, BitOrder.LeastSignificantFirst);
        list[CredentialIndex] = StatusTypes.Suspended;
        var token = new StatusListToken(ListUri, Now, list);

        CredentialStatusOutcome outcome = await CredentialStatusGate.CheckAsync(
            new StatusListReference(CredentialIndex, ListUri), ResolverFor(token), Now, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsValid);
        Assert.AreEqual(StatusTypes.Suspended, outcome.Status);
    }


    [TestMethod]
    public async Task TokenWhoseSubjectDoesNotMatchTheReferenceFailsClosed()
    {
        using var list = StatusListType.Create(64, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        var tokenForAnotherList = new StatusListToken("https://issuer.example/statuslists/OTHER", Now, list);

        StatusListValidationException? caught = null;
        try
        {
            await CredentialStatusGate.CheckAsync(
                new StatusListReference(CredentialIndex, ListUri), ResolverFor(tokenForAnotherList), Now, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        }
        catch(StatusListValidationException exception)
        {
            caught = exception;
        }

        Assert.IsNotNull(caught, "A status list token whose subject does not match the reference URI must not pass.");
    }


    /// <summary>
    /// A stale-but-unexpired Status List Token must still read as valid: <c>ttl</c> (draft-ietf-oauth-status-list
    /// §5.1/§8.3 step 4.2.4) is a caching hint, not a validity requirement, so its breach alone must never
    /// invalidate the credential. The staleness verdict must nonetheless be reachable from the gate's own
    /// result, computed against the caller-supplied <c>resolvedAt</c> cache timestamp — this is the exact
    /// composition a caching resolver (an RP's local cache, an Orleans status-list grain) would use.
    /// </summary>
    [TestMethod]
    public async Task StaleButUnexpiredTokenIsValidAndFlaggedForRefresh()
    {
        using var list = StatusListType.Create(64, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        var token = new StatusListToken(ListUri, Now, list)
        {
            TimeToLive = 60,
            ExpirationTime = Now.AddDays(1)
        };

        DateTimeOffset cachedAt = Now;
        DateTimeOffset checkedAt = Now.AddMinutes(5);

        CredentialStatusOutcome outcome = await CredentialStatusGate.CheckAsync(
            new StatusListReference(CredentialIndex, ListUri), ResolverFor(token), checkedAt, cachedAt, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(outcome.IsValid, "ttl breach alone must not invalidate a still-unexpired credential status.");
        Assert.AreEqual(StatusTypes.Valid, outcome.Status);
        Assert.IsTrue(outcome.ShouldRefresh, "A token resolved well past its ttl must surface a refresh signal.");
    }


    /// <summary>
    /// When the caller performs no caching of its own — the common case, and the default when
    /// <c>resolvedAt</c> is omitted — a token that carries a <c>ttl</c> must not spuriously read as
    /// stale: it was, by construction, just resolved.
    /// </summary>
    [TestMethod]
    public async Task WithoutACallerSuppliedResolvedAtTheOutcomeIsNeverFlaggedForRefresh()
    {
        using var list = StatusListType.Create(64, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        var token = new StatusListToken(ListUri, Now, list)
        {
            TimeToLive = 1
        };

        CredentialStatusOutcome outcome = await CredentialStatusGate.CheckAsync(
            new StatusListReference(CredentialIndex, ListUri), ResolverFor(token), Now, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(outcome.IsValid);
        Assert.IsFalse(outcome.ShouldRefresh, "A token with no caller-tracked resolution time must not be reported stale.");
    }
}
