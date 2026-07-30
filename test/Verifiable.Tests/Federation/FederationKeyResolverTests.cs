using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.Federation;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Federation;

/// <summary>
/// Smoke tests for the in-chain
/// <see cref="FederationKeyResolver.BuildInChainResolver"/> default.
/// </summary>
[TestClass]
internal sealed class FederationKeyResolverTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public async Task ResolvesSelfSignedEcKeyFromJwks()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;
        using FederationTestRingNode node = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/leaf"));

        MintedStatement minted = await FederationTestRing.MintEntityConfigurationAsync(
            node, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        ResolveEntityKeyDelegate resolver = FederationKeyResolver.BuildInChainResolver(
            TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared);

        //Self-signed EC: issuerStatement == statementToVerify.
        using PublicKeyMemory? resolved = await resolver(
            minted.Statement, minted.Header, minted.Statement,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(resolved, "Resolver should produce a key for a self-signed EC.");
    }


    [TestMethod]
    public async Task ReturnsNullWhenIssuerHasNoJwks()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;
        using FederationTestRingNode subject = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/subject"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/anchor"));

        //Anchor's Subordinate Statement DOES carry jwks (subject's jwks per §3.1)
        //but for this test we want the issuer statement to LACK jwks. Use the
        //subject's EC as the issuer (a malformed scenario) to ensure that path
        //returns null cleanly. Easier: mint a statement with an empty jwks dict.
        MintedStatement subjectEc = await FederationTestRing.MintEntityConfigurationAsync(
            subject, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //Construct a synthetic "issuer" with empty payload (no jwks).
        Dictionary<string, object> emptyPayloadDict = new(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Iss] = anchor.Identifier.Value,
            [WellKnownJwtClaimNames.Sub] = anchor.Identifier.Value,
            [WellKnownJwtClaimNames.Iat] = now.ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Exp] = now.AddHours(1).ToUnixTimeSeconds(),
        };
        UnverifiedJwtPayload emptyPayload = new(emptyPayloadDict);
        EntityConfiguration emptyIssuer = new()
        {
            Issuer = anchor.Identifier,
            Subject = anchor.Identifier,
            IssuedAt = now,
            ExpiresAt = now.AddHours(1),
            Payload = emptyPayload,
        };

        ResolveEntityKeyDelegate resolver = FederationKeyResolver.BuildInChainResolver(
            TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared);

        using PublicKeyMemory? resolved = await resolver(
            subjectEc.Statement, subjectEc.Header, emptyIssuer,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(resolved, "Resolver should return null when issuer has no jwks.");
    }


    /// <summary>The chain-keyed resolver finds the Trust Anchor's key by its Entity Identifier + kid.</summary>
    [TestMethod]
    public async Task InChainResolvesAnchorKeyByIssuerAndKid()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;
        using FederationTestRingNode subject = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/subject"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/anchor"));

        MintedChain minted = await FederationTestRing.BuildDirectChainAsync(
            subject, anchor, now, now.AddHours(1), TestContext.CancellationToken).ConfigureAwait(false);

        using PublicKeyMemory? key = await FederationKeyResolver.ResolveInChainKeyAsync(
            minted.Chain, anchor.Identifier.Value, anchor.Kid,
            TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(key, "The anchor's key should resolve by its Entity Identifier and kid.");
    }


    /// <summary>The chain-keyed resolver finds the subject's key from its own Entity Configuration.</summary>
    [TestMethod]
    public async Task InChainResolvesSubjectKeyByIssuerAndKid()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;
        using FederationTestRingNode subject = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/subject"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/anchor"));

        MintedChain minted = await FederationTestRing.BuildDirectChainAsync(
            subject, anchor, now, now.AddHours(1), TestContext.CancellationToken).ConfigureAwait(false);

        using PublicKeyMemory? key = await FederationKeyResolver.ResolveInChainKeyAsync(
            minted.Chain, subject.Identifier.Value, subject.Kid,
            TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(key, "The subject's key should resolve by its Entity Identifier and kid.");
    }


    /// <summary>An issuer described by no chain statement resolves to null.</summary>
    [TestMethod]
    public async Task InChainUnknownIssuerResolvesToNull()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;
        using FederationTestRingNode subject = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/subject"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/anchor"));

        MintedChain minted = await FederationTestRing.BuildDirectChainAsync(
            subject, anchor, now, now.AddHours(1), TestContext.CancellationToken).ConfigureAwait(false);

        using PublicKeyMemory? key = await FederationKeyResolver.ResolveInChainKeyAsync(
            minted.Chain, "https://example.test/stranger", kid: null,
            TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(key, "An issuer absent from the chain should resolve to null.");
    }


    /// <summary>A kid no key in the issuer's jwks carries resolves to null.</summary>
    [TestMethod]
    public async Task InChainWrongKidResolvesToNull()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;
        using FederationTestRingNode subject = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/subject"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/anchor"));

        MintedChain minted = await FederationTestRing.BuildDirectChainAsync(
            subject, anchor, now, now.AddHours(1), TestContext.CancellationToken).ConfigureAwait(false);

        using PublicKeyMemory? key = await FederationKeyResolver.ResolveInChainKeyAsync(
            minted.Chain, anchor.Identifier.Value, "kid-does-not-exist",
            TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(key, "A kid absent from the issuer's jwks should resolve to null.");
    }
}
