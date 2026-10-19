using Microsoft.Extensions.Time.Testing;
using Verifiable.Core.Assessment;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.Federation;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Federation;

/// <summary>
/// End-to-end tests for <see cref="FederationTrustMarkResolver.ResolveVerifiedAsync"/> — the first tests that
/// run the full OpenID Federation 1.0 §7 trust-mark pipeline (issuer-signature → §7.3 shape → §6.2 issuer
/// authorization → §7.2.2 delegation → combine) and assert the admit/reject verdict, rather than exercising the
/// three primitives in isolation. The issuer's key is resolved across the chain and the compact JWS is verified
/// with the real ES256 signer on the admit paths; the combine rule (a carried delegation valid, or none carried nor required
/// and the issuer authorized directly) is exercised by both authorization paths and their refusals.
/// </summary>
[TestClass]
internal sealed class FederationTrustMarkResolverTests
{
    public TestContext TestContext { get; set; } = null!;

    private const string MarkId = "https://example.test/trust-mark/sirtfi";

    private static TimeSpan ClockSkew { get; } = TimeSpan.FromMinutes(5);


    /// <summary>A validly-signed mark whose issuer the Trust Anchor authorizes directly (§6.2) is admitted.</summary>
    [TestMethod]
    public async Task DirectlyAuthorizedMarkIsAdmitted()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode subject = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/subject"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/anchor"));

        //The Trust Anchor issues the mark and lists itself as an authorized issuer for the mark id.
        Dictionary<string, object> anchorExtra = new(StringComparer.Ordinal)
        {
            [WellKnownFederationClaimNames.TrustMarkIssuers] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [MarkId] = new List<object> { anchor.Identifier.Value },
            },
        };

        TrustChain chain = await BuildChainAsync(subject, anchor, anchorExtra, now, TestContext.CancellationToken).ConfigureAwait(false);

        MintedTrustMark minted = await FederationTestRing.MintTrustMarkAsync(
            anchor, subject, MarkId, now, now.AddHours(1), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TrustMarkCandidate candidate = new() { Mark = minted.Mark, Header = minted.Header, CompactJws = minted.CompactJws };

        IReadOnlyList<TrustMarkVerdict> verdicts = await FederationTrustMarkResolver.ResolveVerifiedAsync(
            chain, [candidate], VerifyAgainst(anchor), TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared,
            timeProvider: new FakeTimeProvider(now), ClockSkew, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, verdicts);
        Assert.IsTrue(verdicts[0].SignatureVerified, "The mark signature should verify against the resolved issuer key.");
        Assert.AreEqual(ClaimOutcome.Success, verdicts[0].IssuerAuthorization.Outcome);
        Assert.IsTrue(verdicts[0].Admitted, "A signed, directly-authorized mark must be admitted.");
    }


    /// <summary>A mark whose signature does not verify is rejected, even when its issuer is authorized.</summary>
    [TestMethod]
    public async Task MarkWithBadSignatureIsRejected()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode subject = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/subject"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/anchor"));

        Dictionary<string, object> anchorExtra = new(StringComparer.Ordinal)
        {
            [WellKnownFederationClaimNames.TrustMarkIssuers] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [MarkId] = new List<object> { anchor.Identifier.Value },
            },
        };

        TrustChain chain = await BuildChainAsync(subject, anchor, anchorExtra, now, TestContext.CancellationToken).ConfigureAwait(false);

        MintedTrustMark minted = await FederationTestRing.MintTrustMarkAsync(
            anchor, subject, MarkId, now, now.AddHours(1), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //Tamper the signature segment so the real ES256 verification against the resolved anchor key fails.
        string tamperedCompactJws = TamperSignature(minted.CompactJws);
        TrustMarkCandidate candidate = new() { Mark = minted.Mark, Header = minted.Header, CompactJws = tamperedCompactJws };

        IReadOnlyList<TrustMarkVerdict> verdicts = await FederationTrustMarkResolver.ResolveVerifiedAsync(
            chain, [candidate], VerifyAgainst(anchor), TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared,
            timeProvider: new FakeTimeProvider(now), ClockSkew, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(verdicts[0].SignatureVerified, "A tampered signature must not verify against the resolved key.");
        Assert.IsFalse(verdicts[0].Admitted, "A mark whose signature does not verify must be rejected.");
    }


    /// <summary>A validly-signed mark whose issuer is not authorized (and carries no delegation) is rejected.</summary>
    [TestMethod]
    public async Task UnauthorizedIssuerMarkIsRejected()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode subject = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/subject"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/anchor"));

        //No trust_mark_issuers on the anchor — the issuer is not authorized for this mark.
        TrustChain chain = await BuildChainAsync(subject, anchor, anchorExtra: null, now, TestContext.CancellationToken).ConfigureAwait(false);

        MintedTrustMark minted = await FederationTestRing.MintTrustMarkAsync(
            anchor, subject, MarkId, now, now.AddHours(1), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TrustMarkCandidate candidate = new() { Mark = minted.Mark, Header = minted.Header, CompactJws = minted.CompactJws };

        IReadOnlyList<TrustMarkVerdict> verdicts = await FederationTrustMarkResolver.ResolveVerifiedAsync(
            chain, [candidate], VerifyAgainst(anchor), TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared,
            timeProvider: new FakeTimeProvider(now), ClockSkew, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(verdicts[0].SignatureVerified, "The signature still verifies; only authorization is missing.");
        Assert.AreEqual(ClaimOutcome.Failure, verdicts[0].IssuerAuthorization.Outcome);
        Assert.IsFalse(verdicts[0].Admitted, "A signed but unauthorized mark with no delegation must be rejected.");
    }


    /// <summary>
    /// Federation §3.1.2 and §7.2.2: the Trust Anchor's <c>trust_mark_owners</c> claim is keyed by the Trust Mark type, its value
    /// the owner's <c>sub</c> and <c>jwks</c>, and a delegation's signature validates by one of those keys. A mark whose issuer is
    /// not directly authorized but carries a delegation the declared owner signed is admitted, the owner's key read from the Trust
    /// Anchor's declaration - the owner is in no statement of the chain - and the signature verified by the key the resolver hands
    /// the primitive.
    /// </summary>
    /// <returns>A task completing once the verdict is reached.</returns>
    [TestMethod]
    public async Task DelegatedMarkIsAdmitted()
    {
        var now = TimeProvider.System.GetUtcNow();
        using var subject = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/subject"));
        using var anchor = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/anchor"));
        using var owner = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/owner"));

        var chain = await BuildChainAsync(subject, anchor, OwnersDeclaring(owner), now, TestContext.CancellationToken).ConfigureAwait(false);
        var candidate = await DelegatedCandidateAsync(subject, owner, now, now.AddHours(1)).ConfigureAwait(false);

        var verdicts = await ResolveAsync(chain, candidate, now).ConfigureAwait(false);

        Assert.AreEqual(ClaimOutcome.Failure, verdicts[0].IssuerAuthorization.Outcome, "No direct authorization is declared.");
        Assert.AreEqual(ClaimOutcome.Success, verdicts[0].Delegation.Outcome, "The delegation must validate by the declared owner's key.");
        Assert.IsTrue(verdicts[0].Admitted, "A validly-delegated mark must be admitted via the delegation pathway.");
    }


    /// <summary>
    /// Federation §7.3: "If there is a delegation Claim in the instance, the value of that Claim MUST be validated according to
    /// Section 7.2.2." A mark whose issuer the Trust Anchor authorizes directly, carrying a delegation signed by a key other than the
    /// declared owner's, is rejected: a direct authorization never stands in for an invalid delegation.
    /// </summary>
    /// <returns>A task completing once the verdict is reached.</returns>
    [TestMethod]
    public async Task AnInvalidDelegationIsRejectedDespiteDirectAuthorization()
    {
        var now = TimeProvider.System.GetUtcNow();
        using var subject = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/subject"));
        using var anchor = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/anchor"));
        using var owner = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/owner"));
        using var impostor = FederationTestRing.CreateNodeFromKey(owner.Identifier, TestKeyMaterialProvider.CreateFreshP256KeyMaterial().PrivateKey);

        var anchorExtra = new Dictionary<string, object>(OwnersDeclaring(owner), StringComparer.Ordinal)
        {
            [WellKnownFederationClaimNames.TrustMarkIssuers] = new Dictionary<string, object>(StringComparer.Ordinal) { [MarkId] = new List<object> { subject.Identifier.Value } }
        };

        var chain = await BuildChainAsync(subject, anchor, anchorExtra, now, TestContext.CancellationToken).ConfigureAwait(false);
        var candidate = await DelegatedCandidateAsync(subject, impostor, now, now.AddHours(1)).ConfigureAwait(false);

        var verdicts = await ResolveAsync(chain, candidate, now).ConfigureAwait(false);

        Assert.AreEqual(ClaimOutcome.Success, verdicts[0].IssuerAuthorization.Outcome, "The issuer is authorized directly.");
        Assert.AreEqual(ClaimOutcome.Failure, verdicts[0].Delegation.Outcome, "The delegation is signed by no key of the declared owner.");
        Assert.IsFalse(verdicts[0].Admitted, "A present invalid delegation rejects the mark.");
    }


    /// <summary>
    /// Federation §7.3: "If the trust_mark_type of the instance appears in the trust_mark_owners Claim in the Trust Anchor's Entity
    /// Configuration, then the instance MUST contain a delegation Claim." A mark of a type the Trust Anchor declares an owner of,
    /// carrying no delegation, is rejected though its issuer is authorized directly.
    /// </summary>
    /// <returns>A task completing once the verdict is reached.</returns>
    [TestMethod]
    public async Task AMarkOfAnOwnedTypeWithoutADelegationIsRejected()
    {
        var now = TimeProvider.System.GetUtcNow();
        using var subject = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/subject"));
        using var anchor = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/anchor"));
        using var owner = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/owner"));

        var anchorExtra = new Dictionary<string, object>(OwnersDeclaring(owner), StringComparer.Ordinal)
        {
            [WellKnownFederationClaimNames.TrustMarkIssuers] = new Dictionary<string, object>(StringComparer.Ordinal) { [MarkId] = new List<object> { subject.Identifier.Value } }
        };

        var chain = await BuildChainAsync(subject, anchor, anchorExtra, now, TestContext.CancellationToken).ConfigureAwait(false);
        var minted = await FederationTestRing.MintTrustMarkAsync(subject, subject, MarkId, now, now.AddHours(1), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var verdicts = await ResolveAsync(chain, new TrustMarkCandidate { Mark = minted.Mark, Header = minted.Header, CompactJws = minted.CompactJws }, now).ConfigureAwait(false);

        Assert.AreEqual(ClaimOutcome.Success, verdicts[0].IssuerAuthorization.Outcome, "The issuer is authorized directly.");
        Assert.AreEqual(ClaimOutcome.Failure, verdicts[0].Delegation.Outcome, "The type's owner requires a delegation the mark does not carry.");
        Assert.IsFalse(verdicts[0].Admitted, "A required delegation that is absent rejects the mark.");
    }


    /// <summary>
    /// Federation §3.1.2: "If the array following a Trust Mark type identifier is empty, anyone MAY issue Trust Marks with that
    /// identifier." A mark of such a type, issued by an entity the array does not name, is authorized directly and admitted.
    /// </summary>
    /// <returns>A task completing once the verdict is reached.</returns>
    [TestMethod]
    public async Task AnEmptyIssuerListAuthorizesAnyIssuer()
    {
        var now = TimeProvider.System.GetUtcNow();
        using var subject = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/subject"));
        using var anchor = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/anchor"));

        var anchorExtra = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [WellKnownFederationClaimNames.TrustMarkIssuers] = new Dictionary<string, object>(StringComparer.Ordinal) { [MarkId] = new List<object>() }
        };

        var chain = await BuildChainAsync(subject, anchor, anchorExtra, now, TestContext.CancellationToken).ConfigureAwait(false);
        var minted = await FederationTestRing.MintTrustMarkAsync(subject, subject, MarkId, now, now.AddHours(1), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var verdicts = await ResolveAsync(chain, new TrustMarkCandidate { Mark = minted.Mark, Header = minted.Header, CompactJws = minted.CompactJws }, now).ConfigureAwait(false);

        Assert.AreEqual(ClaimOutcome.Success, verdicts[0].IssuerAuthorization.Outcome, "An empty issuer list authorizes any issuer.");
        Assert.IsTrue(verdicts[0].Admitted);
    }


    /// <summary>
    /// Federation §7.3: "The current time MUST be after the time represented by the iat (issued at) Claim (possibly allowing for some
    /// small leeway to account for clock skew)" - a bound on the future side alone, with no maximum age. A mark issued thirty days
    /// ago that has not expired, and one issued thirty days ago carrying no <c>exp</c> ("If not present, it means that the Trust Mark
    /// does not expire"), are admitted; one issued ten minutes past the present, beyond the five-minute leeway, is not; and a mark
    /// issued thirty days ago whose <c>exp</c>, after its issuance, has passed is rejected as expired.
    /// </summary>
    /// <param name="markCase">The mark's dates.</param>
    /// <param name="isAdmitted">Whether the mark is admitted.</param>
    /// <returns>A task completing once the verdict is reached.</returns>
    [TestMethod]
    [DataRow("older-live", true, DisplayName = "Issued thirty days ago, expiring in an hour")]
    [DataRow("older-without-exp", true, DisplayName = "Issued thirty days ago, carrying no exp")]
    [DataRow("future-beyond-leeway", false, DisplayName = "Issued ten minutes past the present")]
    [DataRow("older-expired", false, DisplayName = "Issued thirty days ago, expired a day ago")]
    public async Task AMarksIssuanceIsBoundedOnlyFromTheFuture(string markCase, bool isAdmitted)
    {
        var now = TestClock.CanonicalEpoch;
        using var subject = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/subject"));
        using var anchor = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/anchor"));

        var anchorExtra = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [WellKnownFederationClaimNames.TrustMarkIssuers] = new Dictionary<string, object>(StringComparer.Ordinal) { [MarkId] = new List<object> { anchor.Identifier.Value } }
        };

        var chain = await BuildChainAsync(subject, anchor, anchorExtra, now, TestContext.CancellationToken).ConfigureAwait(false);
        var issuedAt = markCase is "future-beyond-leeway" ? now.AddMinutes(10) : now.AddDays(-30);
        var expiresAt = markCase switch
        {
            "older-live" or "future-beyond-leeway" => now.AddHours(1),
            "older-without-exp" => (DateTimeOffset?)null,
            "older-expired" => now.AddDays(-1),
            _ => throw new ArgumentOutOfRangeException(nameof(markCase), markCase, "No mark is named so.")
        };

        var minted = await FederationTestRing.MintTrustMarkAsync(anchor, subject, MarkId, issuedAt, expiresAt, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        var verdicts = await ResolveAsync(chain, new TrustMarkCandidate { Mark = minted.Mark, Header = minted.Header, CompactJws = minted.CompactJws }, now).ConfigureAwait(false);

        Assert.IsTrue(verdicts[0].SignatureVerified, markCase);
        Assert.AreEqual(isAdmitted, verdicts[0].Admitted, markCase);
    }


    /// <summary>The Trust Anchor's <c>trust_mark_owners</c> claim declaring an owner of <see cref="MarkId"/> with its keys.</summary>
    /// <param name="owner">The owner.</param>
    /// <returns>The claim, keyed by its name.</returns>
    private static Dictionary<string, object> OwnersDeclaring(FederationTestRingNode owner) => new(StringComparer.Ordinal)
    {
        [WellKnownFederationClaimNames.TrustMarkOwners] = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [MarkId] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["sub"] = owner.Identifier.Value,
                ["jwks"] = owner.JwksObject
            }
        }
    };


    /// <summary>A mark the subject issues of <see cref="MarkId"/> under a delegation the signer given signs as the owner.</summary>
    /// <param name="subject">The subject, which issues the mark.</param>
    /// <param name="delegationSigner">The node signing the delegation.</param>
    /// <param name="issuedAt">The instant both are issued at.</param>
    /// <param name="expiresAt">The instant both expire at.</param>
    /// <returns>The candidate.</returns>
    private async Task<TrustMarkCandidate> DelegatedCandidateAsync(FederationTestRingNode subject, FederationTestRingNode delegationSigner, DateTimeOffset issuedAt, DateTimeOffset expiresAt)
    {
        var minted = await FederationTestRing.MintTrustMarkAsync(subject, subject, MarkId, issuedAt, expiresAt, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        var delegation = await FederationTestRing.MintTrustMarkDelegationAsync(delegationSigner, subject, MarkId, issuedAt, expiresAt, TestContext.CancellationToken).ConfigureAwait(false);

        return new TrustMarkCandidate
        {
            Mark = minted.Mark,
            Header = minted.Header,
            CompactJws = minted.CompactJws,
            Delegation = new TrustMarkDelegationCandidate
            {
                Delegation = delegation.Delegation,
                Header = delegation.Header,
                CompactJws = delegation.CompactJws,
            },
        };
    }


    /// <summary>
    /// Resolves the verdict of one candidate, each signature verified by the key the resolver hands the primitive, so a key read
    /// from the wrong place fails the verification.
    /// </summary>
    /// <param name="chain">The trust chain.</param>
    /// <param name="candidate">The candidate.</param>
    /// <param name="now">The instant the mark is judged at.</param>
    /// <returns>The verdicts.</returns>
    private async Task<IReadOnlyList<TrustMarkVerdict>> ResolveAsync(TrustChain chain, TrustMarkCandidate candidate, DateTimeOffset now) =>
        await FederationTrustMarkResolver.ResolveVerifiedAsync(
            chain, [candidate], VerifyByTheResolvedKeyAsync, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared,
            timeProvider: new FakeTimeProvider(now), ClockSkew, TestContext.CancellationToken).ConfigureAwait(false);


    /// <summary>Verifies a compact JWS by the key the resolver handed, through the registered verification of its algorithm.</summary>
    /// <param name="compactJws">The compact JWS.</param>
    /// <param name="key">The key the resolver handed.</param>
    /// <param name="cancellationToken">Token to monitor for cancellation requests.</param>
    /// <returns>Whether the signature verifies by the key.</returns>
    private static async ValueTask<bool> VerifyByTheResolvedKeyAsync(string compactJws, PublicKeyMemory key, CancellationToken cancellationToken) =>
        await Jws.VerifyAsync(compactJws, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, key, cancellationToken).ConfigureAwait(false);

    /// <summary>
    /// Federation §7 makes the <c>kid</c> header a MUST on Trust Mark JWTs. A <c>kid</c>-less mark cannot be
    /// key-pinned: the in-chain resolver returns no key for a kid-less mark (no silent first-key fallback), so
    /// its signature does not verify, and <c>CheckTrustMarkKidPresent</c> names the missing <c>kid</c> as a
    /// shape failure — the alternative (selecting the anchor's first published key) would wrongly admit an
    /// unauthorized kid-less mark.
    /// </summary>
    [TestMethod]
    public async Task KidlessMarkIsRejected()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode subject = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/subject"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/anchor"));

        //The Trust Anchor issues the mark and authorizes itself — so only the missing kid stands between the
        //mark and admission, isolating the F2 fix.
        Dictionary<string, object> anchorExtra = new(StringComparer.Ordinal)
        {
            [WellKnownFederationClaimNames.TrustMarkIssuers] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [MarkId] = new List<object> { anchor.Identifier.Value },
            },
        };

        TrustChain chain = await BuildChainAsync(subject, anchor, anchorExtra, now, TestContext.CancellationToken).ConfigureAwait(false);

        //A mark whose header omits the kid entirely.
        MintedTrustMark minted = await FederationTestRing.MintTrustMarkAsync(
            anchor, subject, MarkId, now, now.AddHours(1),
            includeKid: false, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TrustMarkCandidate candidate = new() { Mark = minted.Mark, Header = minted.Header, CompactJws = minted.CompactJws };

        IReadOnlyList<TrustMarkVerdict> verdicts = await FederationTrustMarkResolver.ResolveVerifiedAsync(
            chain, [candidate], VerifyAgainst(anchor), TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared,
            timeProvider: new FakeTimeProvider(now), ClockSkew, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(verdicts[0].SignatureVerified,
            "A kid-less mark must not resolve a key from the chain (no silent first-key fallback) per §7.");

        Claim kidClaim = verdicts[0].Shape.Claims.Single(
            c => c.Id.Code == WellKnownFederationClaimIds.TrustMarkKidPresent.Code);
        Assert.AreEqual(ClaimOutcome.Failure, kidClaim.Outcome,
            "A kid-less mark must fail TrustMarkKidPresent — Trust Mark JWTs MUST carry a kid per §7.");

        Assert.IsFalse(verdicts[0].Admitted, "A kid-less mark must be rejected.");
    }


    /// <summary>
    /// §7.3's exp/iat shape check runs against the <see cref="TimeProvider"/> passed to
    /// <see cref="FederationTrustMarkResolver.ResolveVerifiedAsync"/>, never <see cref="TimeProvider.System"/>.
    /// The chain and mark are minted valid at a FIXED historical instant far from real wall time
    /// (<see cref="TestClock.CanonicalEpoch"/>); the resolver is called with a <see cref="FakeTimeProvider"/>
    /// fixed to that SAME instant. By real wall-clock time the mark is long expired, so admission here can
    /// only follow from the resolver actually consulting the passed clock rather than silently reading
    /// <see cref="TimeProvider.System"/> — an isolating pin the other tests in this class (which seed their
    /// <see cref="FakeTimeProvider"/> from real wall time) cannot provide.
    /// </summary>
    [TestMethod]
    public async Task MarkValidAtThePassedClockIsAdmittedEvenThoughRealWallTimeHasLongPassedItsExpiry()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;
        using FederationTestRingNode subject = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/subject"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/anchor"));

        Dictionary<string, object> anchorExtra = new(StringComparer.Ordinal)
        {
            [WellKnownFederationClaimNames.TrustMarkIssuers] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [MarkId] = new List<object> { anchor.Identifier.Value },
            },
        };

        TrustChain chain = await BuildChainAsync(subject, anchor, anchorExtra, now, TestContext.CancellationToken).ConfigureAwait(false);

        MintedTrustMark minted = await FederationTestRing.MintTrustMarkAsync(
            anchor, subject, MarkId, now, now.AddHours(1), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TrustMarkCandidate candidate = new() { Mark = minted.Mark, Header = minted.Header, CompactJws = minted.CompactJws };

        IReadOnlyList<TrustMarkVerdict> verdicts = await FederationTrustMarkResolver.ResolveVerifiedAsync(
            chain, [candidate], VerifyAgainst(anchor), TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared,
            timeProvider: new FakeTimeProvider(now), ClockSkew, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(verdicts[0].Admitted,
            "A mark valid at the PASSED clock's instant must be admitted, even though that instant is long " +
            "before real wall time — proving §7.3's exp/iat check reads the injected TimeProvider, not " +
            "TimeProvider.System.");
    }


    /// <summary>Builds a subject → anchor chain, optionally adding extra claims to the anchor's Entity Configuration.</summary>
    private static async Task<TrustChain> BuildChainAsync(
        FederationTestRingNode subject,
        FederationTestRingNode anchor,
        Dictionary<string, object>? anchorExtra,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        MintedStatement subjectEc = await FederationTestRing.MintEntityConfigurationAsync(
            subject, now, now.AddHours(1), cancellationToken: cancellationToken).ConfigureAwait(false);
        MintedStatement anchorAboutSubject = await FederationTestRing.MintSubordinateStatementAsync(
            anchor, subject, now, now.AddHours(1), cancellationToken: cancellationToken).ConfigureAwait(false);
        MintedStatement anchorEc = await FederationTestRing.MintEntityConfigurationAsync(
            anchor, now, now.AddHours(1), extraClaims: anchorExtra, cancellationToken: cancellationToken).ConfigureAwait(false);

        return new TrustChain { Statements = [subjectEc.Statement, anchorAboutSubject.Statement, anchorEc.Statement] };
    }


    /// <summary>A verify delegate that checks the compact JWS against a known ring node's real ES256 key.</summary>
    private static VerifyCompactJwsDelegate VerifyAgainst(FederationTestRingNode node) =>
        (compactJws, key, cancellationToken) => FederationTestRing.VerifyAsync(node, compactJws, cancellationToken);


    /// <summary>
    /// Flips one base64url character of a compact JWS's signature segment, yielding a structurally-valid JWS
    /// whose signature no longer verifies — so the real ES256 check rejects it.
    /// </summary>
    /// <param name="compactJws">The compact JWS to tamper.</param>
    /// <returns>The same header and payload with a corrupted signature segment.</returns>
    private static string TamperSignature(string compactJws)
    {
        string[] parts = compactJws.Split('.');
        char[] signature = parts[2].ToCharArray();
        signature[0] = signature[0] == 'A' ? 'B' : 'A';

        return $"{parts[0]}.{parts[1]}.{new string(signature)}";
    }
}
