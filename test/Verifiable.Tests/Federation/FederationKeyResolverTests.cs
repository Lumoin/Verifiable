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
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
        using FederationTestRingNode node = FederationTestRing.CreateNode(
            new EntityIdentifier("https://example.test/leaf"));

        MintedStatement minted = await FederationTestRing.MintEntityConfigurationAsync(
            node, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        ResolveEntityKeyDelegate resolver = FederationKeyResolver.BuildInChainResolver(
            TestSetup.Base64UrlDecoder, SensitiveMemoryPool<byte>.Shared);

        //Self-signed EC: issuerStatement == statementToVerify.
        using PublicKeyMemory? resolved = await resolver(
            minted.Statement, minted.Header, minted.Statement,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(resolved, "Resolver should produce a key for a self-signed EC.");
    }


    [TestMethod]
    public async Task ReturnsNullWhenIssuerHasNoJwks()
    {
        DateTimeOffset now = TimeProvider.System.GetUtcNow();
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
            TestSetup.Base64UrlDecoder, SensitiveMemoryPool<byte>.Shared);

        using PublicKeyMemory? resolved = await resolver(
            subjectEc.Statement, subjectEc.Header, emptyIssuer,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(resolved, "Resolver should return null when issuer has no jwks.");
    }
}
