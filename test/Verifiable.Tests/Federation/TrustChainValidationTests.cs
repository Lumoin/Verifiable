using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Generic;
using Verifiable.Core;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Federation;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Federation;

/// <summary>
/// Exercises the production <see cref="TrustChainValidation.BuildInlineValidator"/>
/// end to end: a real signed chain from <see cref="FederationTestRing"/> is
/// validated through the library's serialization-firewall seams and the
/// in-chain key resolver, with no test-side signature shortcut. Proves the
/// shipped validator both accepts a sound chain and rejects a tampered link,
/// resolving every verification key from the chain itself.
/// </summary>
[TestClass]
internal sealed class TrustChainValidationTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    /// <summary>Header deserializer mirroring the authorization server's wiring.</summary>
    private static readonly JwtHeaderDeserializer HeaderDeserializer = static bytes =>
        JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
            bytes, TestSetup.DefaultSerializationOptions)
        ?? throw new FormatException("Header JSON parsed to null.");

    /// <summary>Payload deserializer mirroring the authorization server's wiring.</summary>
    private static readonly JwtPayloadDeserializer PayloadDeserializer = static bytes =>
        JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
            bytes, TestSetup.DefaultSerializationOptions)
        ?? throw new FormatException("Payload JSON parsed to null.");


    /// <summary>
    /// Builds the production validator with the in-chain key resolver — the
    /// composition a deployment wires.
    /// </summary>
    private static ValidateTrustChainAsyncDelegate BuildValidator() =>
        TrustChainValidation.BuildInlineValidator(
            HeaderDeserializer,
            PayloadDeserializer,
            TestSetup.Base64UrlDecoder,
            FederationKeyResolver.BuildInChainResolver(TestSetup.Base64UrlDecoder, Pool));


    [TestMethod]
    public async Task SoundChainValidatesThroughTheProductionValidator()
    {
        DateTimeOffset now = TimeProvider.GetUtcNow();

        using FederationTestRingNode subject =
            FederationTestRing.CreateNode(new EntityIdentifier("https://leaf.example.com"));
        using FederationTestRingNode anchor =
            FederationTestRing.CreateNode(new EntityIdentifier("https://anchor.example.com"));

        MintedChain chain = await FederationTestRing.BuildDirectChainAsync(
            subject, anchor, now, now.AddHours(1), TestContext.CancellationToken).ConfigureAwait(false);

        ValidateTrustChainAsyncDelegate validate = BuildValidator();

        TrustChainValidationOutcome outcome = await validate(
            chain.CompactJwsByPosition,
            [anchor.Identifier],
            now,
            TimeSpan.FromMinutes(5),
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(outcome.IsValid,
            $"A sound chain must validate through the production validator. Reason: {outcome.FailureReason}");
        Assert.IsNotNull(outcome.Chain, "A validated outcome must carry the parsed chain.");
        Assert.HasCount(3, outcome.Chain!.Statements, "The direct chain has three positions.");
    }


    [TestMethod]
    public async Task ChainWithATamperedLinkSignatureIsRejected()
    {
        DateTimeOffset now = TimeProvider.GetUtcNow();

        using FederationTestRingNode subject =
            FederationTestRing.CreateNode(new EntityIdentifier("https://leaf.example.com"));
        using FederationTestRingNode anchor =
            FederationTestRing.CreateNode(new EntityIdentifier("https://anchor.example.com"));

        MintedChain chain = await FederationTestRing.BuildDirectChainAsync(
            subject, anchor, now, now.AddHours(1), TestContext.CancellationToken).ConfigureAwait(false);

        //Flip a character in the Subordinate Statement's signature segment. The
        //in-chain resolver still finds the anchor's key (in the anchor's Entity
        //Configuration), so the rejection comes from the signature failing to
        //verify under the chain-vouched key — not from a missing key.
        string[] parts = chain.CompactJwsByPosition[1].Split('.');
        char[] signature = parts[2].ToCharArray();
        signature[0] = signature[0] == 'A' ? 'B' : 'A';
        string tamperedLink = $"{parts[0]}.{parts[1]}.{new string(signature)}";

        List<string> tamperedChain =
        [
            chain.CompactJwsByPosition[0],
            tamperedLink,
            chain.CompactJwsByPosition[2]
        ];

        ValidateTrustChainAsyncDelegate validate = BuildValidator();

        TrustChainValidationOutcome outcome = await validate(
            tamperedChain,
            [anchor.Identifier],
            now,
            TimeSpan.FromMinutes(5),
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsValid,
            "A chain whose link signature does not verify under the chain-vouched key must be rejected.");
    }
}
