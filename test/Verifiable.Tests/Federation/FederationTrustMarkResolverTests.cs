using Verifiable.Core.Assessment;
using Verifiable.Cryptography;
using Verifiable.OAuth.Federation;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Federation;

/// <summary>
/// End-to-end tests for <see cref="FederationTrustMarkResolver.ResolveVerifiedAsync"/> — the first tests that
/// run the full OpenID Federation 1.0 §7 trust-mark pipeline (issuer-signature → §7.3 shape → §6.2 issuer
/// authorization → §7.2.2 delegation → combine) and assert the admit/reject verdict, rather than exercising the
/// three primitives in isolation. The issuer's key is resolved across the chain and the compact JWS is verified
/// with the real ES256 signer on the admit paths; the combine rule (direct authorization OR valid delegation)
/// is exercised by both authorization paths.
/// </summary>
[TestClass]
internal sealed class FederationTrustMarkResolverTests
{
    public TestContext TestContext { get; set; } = null!;

    private const string MarkId = "https://example.test/trust-mark/sirtfi";

    private static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(5);


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
            timeProvider: null, ClockSkew, TestContext.CancellationToken).ConfigureAwait(false);

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
            timeProvider: null, ClockSkew, TestContext.CancellationToken).ConfigureAwait(false);

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
            timeProvider: null, ClockSkew, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(verdicts[0].SignatureVerified, "The signature still verifies; only authorization is missing.");
        Assert.AreEqual(ClaimOutcome.Failure, verdicts[0].IssuerAuthorization.Outcome);
        Assert.IsFalse(verdicts[0].Admitted, "A signed but unauthorized mark with no delegation must be rejected.");
    }


    /// <summary>A mark whose issuer is not directly authorized but carries a valid delegation (§7.2.2) is admitted.</summary>
    [TestMethod]
    public async Task DelegatedMarkIsAdmitted()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode subject = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/subject"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/anchor"));

        //The anchor is the registered Trust Mark Owner; the subject issues the mark under its delegation. No
        //direct trust_mark_issuers entry — admission must come from the delegation pathway.
        Dictionary<string, object> anchorExtra = new(StringComparer.Ordinal)
        {
            [WellKnownFederationClaimNames.TrustMarkOwners] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [anchor.Identifier.Value] = new Dictionary<string, object>(StringComparer.Ordinal),
            },
        };

        TrustChain chain = await BuildChainAsync(subject, anchor, anchorExtra, now, TestContext.CancellationToken).ConfigureAwait(false);

        MintedTrustMark minted = await FederationTestRing.MintTrustMarkAsync(
            subject, subject, MarkId, now, now.AddHours(1), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedTrustMarkDelegation delegation = await FederationTestRing.MintTrustMarkDelegationAsync(
            anchor, subject, MarkId, now, now.AddHours(1), TestContext.CancellationToken).ConfigureAwait(false);

        TrustMarkCandidate candidate = new()
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

        //The mark is signed by the subject; the delegation is signed by the anchor (the owner).
        VerifyCompactJwsDelegate verify = (compactJws, key, cancellationToken) =>
            compactJws == minted.CompactJws ? FederationTestRing.VerifyAsync(subject, compactJws, cancellationToken)
            : compactJws == delegation.CompactJws ? FederationTestRing.VerifyAsync(anchor, compactJws, cancellationToken)
            : ValueTask.FromResult(false);

        IReadOnlyList<TrustMarkVerdict> verdicts = await FederationTrustMarkResolver.ResolveVerifiedAsync(
            chain, [candidate], verify, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared,
            timeProvider: null, ClockSkew, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(ClaimOutcome.Failure, verdicts[0].IssuerAuthorization.Outcome, "No direct authorization is declared.");
        Assert.AreEqual(ClaimOutcome.Success, verdicts[0].Delegation.Outcome, "The delegation must validate.");
        Assert.IsTrue(verdicts[0].Admitted, "A validly-delegated mark must be admitted via the delegation pathway.");
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
