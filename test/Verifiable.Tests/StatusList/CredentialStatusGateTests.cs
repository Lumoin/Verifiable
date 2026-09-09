using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Core.StatusList;
using Verifiable.Cryptography;
using Verifiable.Tests.TestDataProviders;
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
    private static DateTimeOffset Now { get; } = TestClock.CanonicalEpoch;

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public async Task UnsetEntryReadsAsValid()
    {
        using var list = StatusListType.Create(64, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        var token = new StatusListToken(ListUri, Now, list);

        CredentialStatusOutcome outcome = await CredentialStatusGate.CheckAsync(
            StatusListFixtures.ContextFor(CredentialIndex, ListUri), StatusListFixtures.ResolverFor(token, Now), Now, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

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
            StatusListFixtures.ContextFor(CredentialIndex, ListUri), StatusListFixtures.ResolverFor(token, Now), Now, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

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
            StatusListFixtures.ContextFor(CredentialIndex, ListUri), StatusListFixtures.ResolverFor(token, Now), Now, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

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
                StatusListFixtures.ContextFor(CredentialIndex, ListUri), StatusListFixtures.ResolverFor(tokenForAnotherList, Now), Now, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        }
        catch(StatusListValidationException exception)
        {
            caught = exception;
        }

        Assert.IsNotNull(caught, "A status list token whose subject does not match the reference URI must not pass.");
    }


    /// <summary>
    /// A stale-but-unexpired Status List Token must still read as valid: <c>ttl</c> (draft-ietf-oauth-status-list
    /// §5.1/§8.3 step 4.d) is a caching hint, not a validity requirement, so its breach alone must never
    /// invalidate the credential. The staleness verdict must nonetheless be reachable from the gate's own
    /// result, computed against the resolution's own <c>ResolvedAt</c> — this is the exact composition a
    /// caching resolver (an RP's local cache, an Orleans status-list grain) would use.
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
            StatusListFixtures.ContextFor(CredentialIndex, ListUri), StatusListFixtures.ResolverFor(token, cachedAt), checkedAt, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(outcome.IsValid, "ttl breach alone must not invalidate a still-unexpired credential status.");
        Assert.AreEqual(StatusTypes.Valid, outcome.Status);
        Assert.IsTrue(outcome.ShouldRefresh, "A token resolved well past its ttl must surface a refresh signal.");
    }


    /// <summary>
    /// A resolution reporting the current instant — the common case, a resolver that always fetches
    /// fresh — must never spuriously read a <c>ttl</c>-carrying token as stale: it was, by construction,
    /// just resolved.
    /// </summary>
    [TestMethod]
    public async Task AResolutionReportingTheCurrentInstantIsNeverFlaggedForRefresh()
    {
        using var list = StatusListType.Create(64, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        var token = new StatusListToken(ListUri, Now, list)
        {
            TimeToLive = 1
        };

        CredentialStatusOutcome outcome = await CredentialStatusGate.CheckAsync(
            StatusListFixtures.ContextFor(CredentialIndex, ListUri), StatusListFixtures.ResolverFor(token, Now), Now, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(outcome.IsValid);
        Assert.IsFalse(outcome.ShouldRefresh, "A resolution reporting the current instant must not be reported stale.");
    }


    /// <summary>
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html#section-8.3">Token
    /// Status List §8.3</see> step 2, "Resolve the Status List Token from the provided URI", is one of the
    /// steps whose failure means "no statement about the status … can be made". A resolver that could not
    /// obtain the Status List Token signals it with <see cref="StatusListResolutionException"/>, which
    /// surfaces from the gate as its base <see cref="StatusListValidationException"/> — the same type a
    /// subject mismatch, an expired list, or an out-of-range index surfaces as.
    /// </summary>
    [TestMethod]
    public async Task AResolverSignalingResolutionFailureSurfacesAsStatusListValidationException()
    {
        ResolveVerifiedStatusListTokenDelegate resolver = (context, ct) =>
            throw new StatusListResolutionException(context.Reference.Uri, "The status list host refused the connection.");

        StatusListValidationException caught = await Assert.ThrowsExactlyAsync<StatusListResolutionException>(
            async () => await CredentialStatusGate.CheckAsync(
                StatusListFixtures.ContextFor(CredentialIndex, ListUri), resolver, Now,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false));

        Assert.IsInstanceOfType<StatusListValidationException>(caught,
            "StatusListResolutionException derives from StatusListValidationException so callers already "
            + "catching that type classify a resolution failure the same as any other undeterminable status.");
    }


    /// <summary>
    /// A resolver that returns <see langword="null"/> found nothing to obtain a status from — the same "no
    /// statement about the status … can be made" outcome
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html#section-8.3">Token
    /// Status List §8.3</see> reserves for every other undeterminable case — so the gate raises
    /// <see cref="StatusListResolutionException"/> rather than an unclassified <see cref="ArgumentNullException"/>.
    /// </summary>
    [TestMethod]
    public async Task AResolverReturningNullSurfacesAsStatusListResolutionException()
    {
        ResolveVerifiedStatusListTokenDelegate resolver = (context, ct) => ValueTask.FromResult<ResolvedStatusListToken?>(null);

        StatusListResolutionException caught = await Assert.ThrowsExactlyAsync<StatusListResolutionException>(
            async () => await CredentialStatusGate.CheckAsync(
                StatusListFixtures.ContextFor(CredentialIndex, ListUri), resolver, Now,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false));

        Assert.AreEqual(ListUri, caught.Uri,
            "The resolution exception names the uri the resolver could not obtain a verified token for.");
    }


    /// <summary>
    /// Step 4.b — "If the Relying Party has local policies regarding the freshness of the Status List
    /// Token, it SHOULD check the issued at claim (iat or 6)" — is the Relying Party's policy, so the
    /// gate is where it is supplied. A token older than the policy allows is one of the checks whose
    /// failure means "no statement about the status of the Referenced Token can be made and the
    /// Referenced Token SHOULD be rejected", so it fails closed here exactly as a subject mismatch or
    /// an expiry does, rather than returning a status the Relying Party has said it will not trust.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token Status List, Section 8.3</see>.
    /// </summary>
    [TestMethod]
    public async Task AStaleTokenUnderAFreshnessPolicyFailsClosedAtTheGate()
    {
        using var list = StatusListType.Create(64, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        var token = new StatusListToken(ListUri, Now, list);
        var freshnessPolicy = new StatusListFreshnessPolicy(TimeSpan.FromHours(1));
        DateTimeOffset checkedAt = Now.AddHours(2);

        StatusListValidationException caught = await Assert.ThrowsExactlyAsync<StatusListValidationException>(
            async () => await CredentialStatusGate.CheckAsync(
                StatusListFixtures.ContextFor(CredentialIndex, ListUri),
                StatusListFixtures.ResolverFor(token, checkedAt),
                checkedAt,
                freshnessPolicy,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false));

        Assert.IsTrue(caught.Message.Contains("issued at", StringComparison.Ordinal),
            "The gate threads the caller's freshness policy into step 4.b, so the refusal names the issued at claim.");
    }


    /// <summary>
    /// A Relying Party's Section 11.5 bounds — "clients should be configured with lower/upper bounds
    /// for these values that fit their respective use-cases" — reach step 4.d through the gate, so the
    /// same token resolved at the same instant and checked at the same instant yields a different
    /// refresh verdict with and without them: a ten-second <c>ttl</c> under a sixty-second floor does
    /// not "accidentally creat[e] unreasonable amounts of requests for a specific URL".
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.5">Token Status List, Section 11.5</see>.
    /// </summary>
    [TestMethod]
    public async Task TheCachingBoundsSuppliedToTheGateDecideTheRefreshVerdict()
    {
        using var list = StatusListType.Create(64, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        var token = new StatusListToken(ListUri, Now, list)
        {
            TimeToLive = 10
        };
        var cachingBounds = new StatusListCachingBounds(TimeSpan.FromSeconds(60), TimeSpan.FromHours(1));
        DateTimeOffset checkedAt = Now.AddSeconds(30);
        StatusListResolutionContext resolutionContext = StatusListFixtures.ContextFor(CredentialIndex, ListUri);

        CredentialStatusOutcome unbounded = await CredentialStatusGate.CheckAsync(
            resolutionContext, StatusListFixtures.ResolverFor(token, Now), checkedAt,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        CredentialStatusOutcome bounded = await CredentialStatusGate.CheckAsync(
            resolutionContext, StatusListFixtures.ResolverFor(token, Now), checkedAt, null, cachingBounds,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(unbounded.ShouldRefresh,
            "Without configured bounds the published ten-second ttl is already breached thirty seconds after resolution.");
        Assert.IsFalse(bounded.ShouldRefresh,
            "With a sixty-second floor configured the same cached copy is held rather than re-requested.");
        Assert.IsTrue(bounded.IsValid,
            "The bounds govern only the caching hint; the status itself is read either way.");
    }


    /// <summary>
    /// Step 2 of the evaluation is "Resolve the Status List Token from the provided URI" — the URI
    /// being the one step 1 read out of the credential's own <c>status_list</c> claim, which step 4.a
    /// then requires the token's <c>sub</c> to equal. The gate therefore hands the resolver that exact
    /// URI, and asks for it once: a second resolution per check would double the request load Section
    /// 11.5 is concerned with, and a different URI would resolve a list the credential never referenced.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token Status List, Section 8.3</see>.
    /// </summary>
    [TestMethod]
    public async Task TheResolverIsAskedForTheReferencedUriExactlyOnce()
    {
        using var list = StatusListType.Create(64, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        var token = new StatusListToken(ListUri, Now, list);

        int invocations = 0;
        string? requestedUri = null;

        ResolveVerifiedStatusListTokenDelegate resolver = (context, cancellationToken) =>
        {
            invocations++;
            requestedUri = context.Reference.Uri;

            return ValueTask.FromResult<ResolvedStatusListToken?>(new ResolvedStatusListToken
            {
                Token = token,
                ResolvedAt = Now,
                IsTokenOwned = false
            });
        };

        CredentialStatusOutcome outcome = await CredentialStatusGate.CheckAsync(
            StatusListFixtures.ContextFor(CredentialIndex, ListUri), resolver, Now,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(1, invocations, "One status evaluation resolves the Status List Token once.");
        Assert.AreEqual(ListUri, requestedUri, "The resolver is asked for the uri the credential's status_list claim carries.");
        Assert.IsTrue(outcome.IsValid, "The single resolution is the one the status is read from.");
    }


    /// <summary>
    /// <see cref="ResolvedStatusListToken.IsTokenOwned"/> declares who releases the pooled Status List:
    /// an OWNED resolution (a per-call fetch-and-verify) is disposed by the gate once it has read the
    /// status and freshness verdicts, so nothing above <see cref="CredentialStatusGate.CheckAsync"/>
    /// leaks the pooled buffer — the RED symptom before ownership was declared, where every status
    /// check on the OID4VP/SIOP seats leaked one pooled buffer.
    /// </summary>
    [TestMethod]
    public async Task AnOwnedResolutionsPooledStatusListIsReturnedAfterCheckAsync()
    {
        using var metered = new MeteredHousePool();
        using var list = StatusListType.Create(64, StatusListBitSize.OneBit, metered.Pool, BitOrder.LeastSignificantFirst);
        var token = new StatusListToken(ListUri, Now, list);

        ResolveVerifiedStatusListTokenDelegate resolver = (context, cancellationToken) =>
            ValueTask.FromResult<ResolvedStatusListToken?>(new ResolvedStatusListToken
            {
                Token = token,
                ResolvedAt = Now,
                IsTokenOwned = true
            });

        CredentialStatusOutcome outcome = await CredentialStatusGate.CheckAsync(
            StatusListFixtures.ContextFor(CredentialIndex, ListUri), resolver, Now, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(outcome.IsValid);
        Assert.AreEqual(0L, metered.OutstandingCount, "An owned resolution's pooled Status List must be released once the gate has read it.");
    }


    /// <summary>
    /// The mirror of <see cref="AnOwnedResolutionsPooledStatusListIsReturnedAfterCheckAsync"/>: a
    /// NOT-owned resolution — a caching resolver sharing one Status List across many checks — must
    /// still have a usable, undisposed carrier once <see cref="CredentialStatusGate.CheckAsync"/>
    /// returns, so a second check against the same cache reads the same live bytes.
    /// </summary>
    [TestMethod]
    public async Task ANotOwnedResolutionsStatusListIsStillUsableAfterCheckAsync()
    {
        using var metered = new MeteredHousePool();
        using var list = StatusListType.Create(64, StatusListBitSize.OneBit, metered.Pool, BitOrder.LeastSignificantFirst);
        var token = new StatusListToken(ListUri, Now, list);

        ResolveVerifiedStatusListTokenDelegate resolver = (context, cancellationToken) =>
            ValueTask.FromResult<ResolvedStatusListToken?>(new ResolvedStatusListToken
            {
                Token = token,
                ResolvedAt = Now,
                IsTokenOwned = false
            });

        CredentialStatusOutcome first = await CredentialStatusGate.CheckAsync(
            StatusListFixtures.ContextFor(CredentialIndex, ListUri), resolver, Now, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        CredentialStatusOutcome second = await CredentialStatusGate.CheckAsync(
            StatusListFixtures.ContextFor(CredentialIndex, ListUri), resolver, Now, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(first.IsValid);
        Assert.IsTrue(second.IsValid, "A second check against the same cached, not-owned resolution must still read a live Status List.");
        Assert.IsGreaterThan(0L, metered.OutstandingCount, "A not-owned resolution's pooled Status List must not be released by the gate.");
    }


    /// <summary>
    /// Step 3.a — "Validate the Status List Token by following the rules defined in Section 7.2 of [RFC7519]
    /// for JWTs and Section 7.2 of [RFC8392] for CWTs. This step might require the resolution of a public key
    /// as described in Section 11.3." — makes the key resolution the resolver's own step, and Section 11.3's
    /// first recommendation — "If the Issuer of the Referenced Token is the same entity as the Status Issuer,
    /// then the same key that is embedded into the Referenced Token may be used for the Status List Token." —
    /// can only be evaluated behind that seam if the Referenced Token's own facts reach it. The gate is a
    /// conduit for them: whatever the caller states about the Referenced Token arrives at the resolver as the
    /// same reference, unread and unrewritten, so a resolver never has to infer trust from the list URI's
    /// authority instead.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token Status List, Section 8.3</see>
    /// and <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.3">Section 11.3</see>.
    /// </summary>
    [TestMethod]
    public async Task TheResolverIsHandedTheResolutionContextUnchanged()
    {
        const string referencedTokenIssuer = "https://issuer.example/pid";

        using var list = StatusListType.Create(64, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        var token = new StatusListToken(ListUri, Now, list);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory referencedTokenIssuerKey = issuerKeys.PublicKey;
        using PrivateKeyMemory unusedPrivateKey = issuerKeys.PrivateKey;

        var reference = new StatusListReference(CredentialIndex, ListUri);
        StatusListResolutionContext resolutionContext = StatusListFixtures.ContextFor(
            reference, referencedTokenIssuer, referencedTokenIssuerKey);

        (ResolveVerifiedStatusListTokenDelegate resolver, IReadOnlyList<StatusListResolutionContext> seen) =
            StatusListFixtures.RecordingResolverFor(StatusListFixtures.ResolverFor(token, Now));

        CredentialStatusOutcome outcome = await CredentialStatusGate.CheckAsync(
            resolutionContext, resolver, Now, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(outcome.IsValid, "The resolution answered, so the status is read from it.");
        Assert.HasCount(1, seen, "One status evaluation hands the resolver one context.");
        Assert.AreSame(resolutionContext, seen[0],
            "Section 8.3 step 3.a's key resolution runs behind the resolver, so the gate passes the caller's context through rather than rebuilding one.");
        Assert.AreEqual(reference, seen[0].Reference,
            "The resolver resolves for the very status_list reference step 1 read out of the credential.");
        Assert.AreEqual(referencedTokenIssuer, seen[0].ReferencedTokenIssuer,
            "Section 11.3's second recommendation is keyed on the Referenced Token's issuer, so it reaches the resolver as stated.");
        Assert.AreSame(referencedTokenIssuerKey, seen[0].ReferencedTokenIssuerKey,
            "Section 11.3's first recommendation is the key the Referenced Token verified under, which the resolver borrows as the very same carrier.");
    }
}
