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


    /// <summary>
    /// Exploit regression (F2, Federation §3.1 <c>kid</c> MUST): a statement signed by a key the issuer
    /// publishes but whose <c>kid</c> header has been STRIPPED must resolve to <see langword="null"/>, never
    /// to a silently-chosen key. The pre-fix resolver returned the issuer's first jwks key (accepting any
    /// key, defeating kid-pinning); the secure answer is a resolution miss so the malformed statement is
    /// caught rather than verified under a guessed key.
    /// </summary>
    [TestMethod]
    public async Task StrippedKidResolvesToNullInsteadOfSilentlyPickingAKey()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;
        using FederationTestRingNode node = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/stripped-kid"));

        MintedStatement minted = await FederationTestRing.MintEntityConfigurationAsync(
            node, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        //The to-be-verified statement's header carries alg and typ but NO kid — a stripped/omitted kid.
        UnverifiedJwtHeader strippedHeader = new(new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [WellKnownJwkMemberNames.Alg] = "ES256",
            [WellKnownJoseHeaderNames.Typ] = WellKnownFederationMediaTypes.EntityStatementJwt
        });

        ResolveEntityKeyDelegate resolver = FederationKeyResolver.BuildInChainResolver(
            TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared);

        using PublicKeyMemory? resolved = await resolver(
            minted.Statement, strippedHeader, minted.Statement,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(resolved,
            "A statement whose kid header is absent must resolve to null (no silent first-key fallback) per §3.1.");
    }


    /// <summary>
    /// Exploit regression (F2): an issuer that published <c>[K_old, K_new]</c> and rotated to <c>K_new</c>. A
    /// statement whose <c>kid</c> is absent must NOT resolve to <c>K_old</c> just because it sits first in the
    /// set — that mis-selects a rotated-away key, and with the order reversed would verify a statement under a
    /// key the issuer never nominated. The secure answer is a resolution miss.
    /// </summary>
    [TestMethod]
    public async Task RotatedKeyAbsentKidResolvesToNullNotTheFirstPublishedKey()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;
        using FederationTestRingNode oldKeyNode = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/issuer"));
        using FederationTestRingNode newKeyNode = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/issuer"));

        EntityIdentifier issuer = new("https://example.test/issuer");

        //An issuer JWK Set carrying two keys, the rotated-away K_old first and the current K_new second.
        Dictionary<string, object> twoKeyJwks = new(StringComparer.Ordinal)
        {
            [WellKnownJwkMemberNames.Keys] = new List<object>
            {
                SingleJwk(oldKeyNode),
                SingleJwk(newKeyNode)
            }
        };

        Dictionary<string, object> payloadDict = new(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Iss] = issuer.Value,
            [WellKnownJwtClaimNames.Sub] = issuer.Value,
            [WellKnownJwtClaimNames.Iat] = now.ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Exp] = now.AddHours(1).ToUnixTimeSeconds(),
            [WellKnownFederationClaimNames.Jwks] = twoKeyJwks
        };

        EntityConfiguration issuerEc = new()
        {
            Issuer = issuer,
            Subject = issuer,
            IssuedAt = now,
            ExpiresAt = now.AddHours(1),
            Payload = new UnverifiedJwtPayload(payloadDict)
        };

        TrustChain chain = new() { Statements = [issuerEc] };

        using PublicKeyMemory? key = await FederationKeyResolver.ResolveInChainKeyAsync(
            chain, issuer.Value, kid: null,
            TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(key,
            "An absent kid over a rotated multi-key issuer must resolve to null, not the first (rotated-away) key.");
    }


    /// <summary>Extracts the single JWK a ring node publishes, for assembling a multi-key JWK Set in tests.</summary>
    /// <param name="node">The ring node whose published key is extracted.</param>
    /// <returns>The node's JWK as a mutable dictionary.</returns>
    private static Dictionary<string, object> SingleJwk(FederationTestRingNode node)
    {
        List<object> keys = (List<object>)node.JwksObject[WellKnownJwkMemberNames.Keys];
        return (Dictionary<string, object>)keys[0];
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
