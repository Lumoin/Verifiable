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
        Dictionary<string, object?> emptyPayloadDict = new(StringComparer.Ordinal)
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
            subject, anchor, now, now.AddHours(1), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

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
            subject, anchor, now, now.AddHours(1), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

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
            subject, anchor, now, now.AddHours(1), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using PublicKeyMemory? key = await FederationKeyResolver.ResolveInChainKeyAsync(
            minted.Chain, "https://example.test/stranger", kid: null,
            TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(key, "An issuer absent from the chain should resolve to null.");
    }


    /// <summary>
    /// Federation §3.1 makes <c>kid</c> a MUST: a statement signed by a key the issuer publishes but whose
    /// <c>kid</c> header has been STRIPPED must resolve to <see langword="null"/>, never to a silently-chosen
    /// key — accepting any key from the issuer's jwks defeats kid-pinning, so the secure answer is a
    /// resolution miss, catching the malformed statement rather than verifying it under a guessed key.
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
        UnverifiedJwtHeader strippedHeader = new()
        {
            [WellKnownJwkMemberNames.Alg] = "ES256",
            [WellKnownJoseHeaderNames.Typ] = WellKnownFederationMediaTypes.EntityStatementJwt
        };

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

        Dictionary<string, object?> payloadDict = new(StringComparer.Ordinal)
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
            Payload = new(payloadDict)
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


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">RFC 7517 §4.5</see> makes
    /// distinct <c>kid</c> values within a set a SHOULD. A chain statement whose <c>jwks</c> carries two
    /// keys published under the SAME <c>kid</c> must resolve to a refusal, not silently pick the
    /// first (or either) of the two — the array's order is attacker-controlled input, not a
    /// legitimate tiebreaker.
    /// </summary>
    [TestMethod]
    public async Task DuplicateKeyIdInJwksResolvesToNullNotTheFirstKey()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;
        using FederationTestRingNode firstKeyNode = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/issuer"));
        using FederationTestRingNode secondKeyNode = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/issuer"));

        EntityIdentifier issuer = new("https://example.test/issuer");
        const string DuplicateKeyId = "duplicated-kid";

        Dictionary<string, object> firstJwk = SingleJwk(firstKeyNode);
        firstJwk[WellKnownJwkMemberNames.Kid] = DuplicateKeyId;
        Dictionary<string, object> secondJwk = SingleJwk(secondKeyNode);
        secondJwk[WellKnownJwkMemberNames.Kid] = DuplicateKeyId;

        Dictionary<string, object> twoKeyJwks = new(StringComparer.Ordinal)
        {
            [WellKnownJwkMemberNames.Keys] = new List<object> { firstJwk, secondJwk }
        };

        Dictionary<string, object?> payloadDict = new(StringComparer.Ordinal)
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
            Payload = new(payloadDict)
        };

        TrustChain chain = new() { Statements = [issuerEc] };

        using PublicKeyMemory? key = await FederationKeyResolver.ResolveInChainKeyAsync(
            chain, issuer.Value, DuplicateKeyId,
            TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(key,
            "A kid appearing on more than one key in the issuer's jwks must resolve to null, not the first match.");
    }


    /// <summary>
    /// The walk over a chain tells an ordinary miss from the refusal of a key set: a first statement about the issuer whose key
    /// set carries no key of the kid - an empty <c>keys</c> array among them, a JWK Set holding no key (RFC 7517 section 5) -
    /// passes the walk on, and the second statement's key resolves; a first statement whose <c>jwks</c> is no JSON object, is
    /// one carrying no <c>keys</c> member or a <c>keys</c> that is no array (RFC 7517 section 5: the member is REQUIRED, an array
    /// of JWK values), whose set names the kid on two keys, or whose selected key builds no key ends the walk with no key, the
    /// second statement's valid key never standing in for the key set the chain refused.
    /// </summary>
    /// <param name="firstStatementCase">The name of the first statement's key set.</param>
    /// <param name="resolves">Whether the walk resolves the second statement's key.</param>
    /// <returns>A task completing once the key is resolved.</returns>
    [TestMethod]
    [DataRow("no-key-of-the-kid", true)]
    [DataRow("keys-empty", true)]
    [DataRow("jwks-not-an-object", false)]
    [DataRow("keys-absent", false)]
    [DataRow("keys-not-an-array", false)]
    [DataRow("kid-on-two-keys", false)]
    [DataRow("selected-key-builds-none", false)]
    public async Task AKeySetTheChainRefusesEndsTheWalkAndAMissPassesItOn(string firstStatementCase, bool resolves)
    {
        var now = TestClock.CanonicalEpoch;
        using var current = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/issuer"));
        using var other = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/issuer"));
        var issuer = new EntityIdentifier("https://example.test/issuer");
        const string KeyId = "current-kid";

        var currentJwk = SingleJwk(current);
        currentJwk[WellKnownJwkMemberNames.Kid] = KeyId;
        var otherJwk = SingleJwk(other);
        otherJwk[WellKnownJwkMemberNames.Kid] = firstStatementCase is "kid-on-two-keys" ? KeyId : "another-kid";
        var keyless = new Dictionary<string, object>(StringComparer.Ordinal) { [WellKnownJwkMemberNames.Kid] = KeyId, [WellKnownJwkMemberNames.Use] = "sig" };

        object firstJwks = firstStatementCase switch
        {
            "no-key-of-the-kid" => KeySet(otherJwk),
            "keys-empty" => KeySet(),
            "jwks-not-an-object" => "not-a-key-set",
            "keys-absent" => new Dictionary<string, object>(StringComparer.Ordinal),
            "keys-not-an-array" => new Dictionary<string, object>(StringComparer.Ordinal) { [WellKnownJwkMemberNames.Keys] = "not-an-array" },
            "kid-on-two-keys" => KeySet(otherJwk, currentJwk),
            "selected-key-builds-none" => KeySet(keyless),
            _ => throw new ArgumentOutOfRangeException(nameof(firstStatementCase), firstStatementCase, "No key set is named so.")
        };

        var chain = new TrustChain { Statements = [StatementAbout(issuer, now, firstJwks), StatementAbout(issuer, now, KeySet(currentJwk))] };

        using var key = await FederationKeyResolver.ResolveInChainKeyAsync(
            chain, issuer.Value, KeyId, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(resolves, key is not null, firstStatementCase);
    }


    /// <summary>A JWK Set of the keys given.</summary>
    /// <param name="keys">The keys.</param>
    /// <returns>The set.</returns>
    private static Dictionary<string, object> KeySet(params Dictionary<string, object>[] keys) =>
        new(StringComparer.Ordinal) { [WellKnownJwkMemberNames.Keys] = keys.Cast<object>().ToList() };


    /// <summary>A self-issued statement about an entity, carrying the <c>jwks</c> given.</summary>
    /// <param name="entity">The entity.</param>
    /// <param name="now">The instant it is issued at.</param>
    /// <param name="jwks">The <c>jwks</c> claim's value.</param>
    /// <returns>The statement.</returns>
    private static EntityConfiguration StatementAbout(EntityIdentifier entity, DateTimeOffset now, object jwks) => new()
    {
        Issuer = entity,
        Subject = entity,
        IssuedAt = now,
        ExpiresAt = now.AddHours(1),
        Payload = new(new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Iss] = entity.Value,
            [WellKnownJwtClaimNames.Sub] = entity.Value,
            [WellKnownJwtClaimNames.Iat] = now.ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Exp] = now.AddHours(1).ToUnixTimeSeconds(),
            [WellKnownFederationClaimNames.Jwks] = jwks
        })
    };


    /// <summary>A kid no key in the issuer's jwks carries resolves to null.</summary>
    [TestMethod]
    public async Task InChainWrongKidResolvesToNull()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;
        using FederationTestRingNode subject = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/subject"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(new EntityIdentifier("https://example.test/anchor"));

        MintedChain minted = await FederationTestRing.BuildDirectChainAsync(
            subject, anchor, now, now.AddHours(1), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        using PublicKeyMemory? key = await FederationKeyResolver.ResolveInChainKeyAsync(
            minted.Chain, anchor.Identifier.Value, "kid-does-not-exist",
            TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(key, "A kid absent from the issuer's jwks should resolve to null.");
    }
}
