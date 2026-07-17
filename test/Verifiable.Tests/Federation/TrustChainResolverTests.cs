using System.Collections.Generic;
using Verifiable.Core;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Federation;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Federation;

/// <summary>
/// Exercises <see cref="TrustChainResolver.BuildAsync"/> — the §10.1
/// <c>authority_hints</c> walker — over an in-process federation graph. Proves
/// it assembles the leaf → anchor chain through an intermediate (which then
/// validates through the production <see cref="TrustChainValidation"/>), and
/// that a cyclic authority graph terminates rather than looping.
/// </summary>
[TestClass]
internal sealed class TrustChainResolverTests
{
    public TestContext TestContext { get; set; } = null!;

    private const string LeafId = "https://leaf.example.com";
    private const string IntermediateId = "https://intermediate.example.com";
    private const string AnchorId = "https://anchor.example.com";
    private const string IntermediateFetch = "https://intermediate.example.com/fetch";
    private const string AnchorFetch = "https://anchor.example.com/fetch";

    private static readonly JwtHeaderDeserializer HeaderDeserializer = static bytes =>
        JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
            bytes, TestSetup.DefaultSerializationOptions)
        ?? throw new FormatException("Header JSON parsed to null.");

    private static readonly JwtPayloadDeserializer PayloadDeserializer = static bytes =>
        JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
            bytes, TestSetup.DefaultSerializationOptions)
        ?? throw new FormatException("Payload JSON parsed to null.");


    [TestMethod]
    public async Task BuildsAndValidatesAChainThroughAnIntermediate()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;

        using FederationTestRingNode leaf = FederationTestRing.CreateNode(new EntityIdentifier(LeafId));
        using FederationTestRingNode intermediate = FederationTestRing.CreateNode(new EntityIdentifier(IntermediateId));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(new EntityIdentifier(AnchorId));

        //Leaf points up to the intermediate; the intermediate up to the anchor.
        //The intermediate and anchor publish a federation_fetch_endpoint so the
        //walker can retrieve the Subordinate Statements they issue.
        MintedStatement leafEc = await FederationTestRing.MintEntityConfigurationAsync(
            leaf, now, now.AddHours(1),
            extraClaims: AuthorityHints(IntermediateId),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement intermediateEc = await FederationTestRing.MintEntityConfigurationAsync(
            intermediate, now, now.AddHours(1),
            extraClaims: Merge(AuthorityHints(AnchorId), FetchEndpoint(IntermediateFetch)),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement anchorEc = await FederationTestRing.MintEntityConfigurationAsync(
            anchor, now, now.AddHours(1),
            extraClaims: FetchEndpoint(AnchorFetch),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        MintedStatement intermediateAboutLeaf = await FederationTestRing.MintSubordinateStatementAsync(
            intermediate, leaf, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement anchorAboutIntermediate = await FederationTestRing.MintSubordinateStatementAsync(
            anchor, intermediate, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Dictionary<string, string> configByEntity = new(StringComparer.Ordinal)
        {
            [LeafId] = leafEc.CompactJws,
            [IntermediateId] = intermediateEc.CompactJws,
            [AnchorId] = anchorEc.CompactJws,
        };
        Dictionary<string, string> endpointToIssuer = new(StringComparer.Ordinal)
        {
            [IntermediateFetch] = IntermediateId,
            [AnchorFetch] = AnchorId,
        };
        Dictionary<string, string> subordinateByIssuerSubject = new(StringComparer.Ordinal)
        {
            [Key(IntermediateId, LeafId)] = intermediateAboutLeaf.CompactJws,
            [Key(AnchorId, IntermediateId)] = anchorAboutIntermediate.CompactJws,
        };

        FetchEntityConfigurationDelegate fetchConfiguration = (entity, context, ct) =>
            ValueTask.FromResult(configByEntity.TryGetValue(entity.Value, out string? jws)
                ? FederationHttpClientTransport.TryParseFetchedStatement(jws)
                : null);

        FetchEntityStatementDelegate fetchSubordinate = (subject, fetchEndpoint, context, ct) =>
        {
            if(endpointToIssuer.TryGetValue(fetchEndpoint.ToString(), out string? issuer)
                && subordinateByIssuerSubject.TryGetValue(Key(issuer, subject.Value), out string? jws))
            {
                return ValueTask.FromResult(FederationHttpClientTransport.TryParseFetchedStatement(jws));
            }

            return ValueTask.FromResult<FetchedEntityStatement?>(null);
        };

        IReadOnlyList<string>? chain = await TrustChainResolver.BuildAsync(
            new EntityIdentifier(LeafId),
            [anchor.Identifier],
            fetchConfiguration,
            fetchSubordinate,
            new ExchangeContext(),
            maxChainLength: 5,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(chain, "The walker must assemble a chain to the trust anchor.");
        Assert.HasCount(5, chain!, "leaf EC, SS, intermediate EC, SS, anchor EC.");
        CollectionAssert.AreEqual(
            new[]
            {
                leafEc.CompactJws,
                intermediateAboutLeaf.CompactJws,
                intermediateEc.CompactJws,
                anchorAboutIntermediate.CompactJws,
                anchorEc.CompactJws,
            },
            (System.Collections.ICollection)chain!,
            "The assembled chain must be leaf -> anchor in canonical order.");

        //The assembled chain, fed to the production validator, must validate:
        //build (§10.1) then verify (§10.2).
        ValidateTrustChainAsyncDelegate validate = TrustChainValidation.BuildInlineValidator(
            HeaderDeserializer,
            PayloadDeserializer,
            TestSetup.Base64UrlDecoder,
            FederationKeyResolver.BuildInChainResolver(TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared));

        TrustChainValidationOutcome outcome = await validate(
            chain!,
            [anchor.Identifier],
            now,
            TimeSpan.FromMinutes(5),
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(outcome.IsValid,
            $"The built chain must validate. Reason: {outcome.FailureReason}");
    }


    [TestMethod]
    public async Task CyclicAuthorityGraphTerminatesWithoutAnchor()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;

        using FederationTestRingNode a = FederationTestRing.CreateNode(new EntityIdentifier("https://a.example.com"));
        using FederationTestRingNode b = FederationTestRing.CreateNode(new EntityIdentifier("https://b.example.com"));

        //A and B name each other as superiors — a cycle. No trust anchor is
        //reachable, so the walk must terminate (loop prevention), not hang.
        MintedStatement aEc = await FederationTestRing.MintEntityConfigurationAsync(
            a, now, now.AddHours(1),
            extraClaims: Merge(AuthorityHints("https://b.example.com"), FetchEndpoint("https://a.example.com/fetch")),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement bEc = await FederationTestRing.MintEntityConfigurationAsync(
            b, now, now.AddHours(1),
            extraClaims: Merge(AuthorityHints("https://a.example.com"), FetchEndpoint("https://b.example.com/fetch")),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement bAboutA = await FederationTestRing.MintSubordinateStatementAsync(
            b, a, now, now.AddHours(1), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement aAboutB = await FederationTestRing.MintSubordinateStatementAsync(
            a, b, now, now.AddHours(1), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Dictionary<string, string> configByEntity = new(StringComparer.Ordinal)
        {
            ["https://a.example.com"] = aEc.CompactJws,
            ["https://b.example.com"] = bEc.CompactJws,
        };
        Dictionary<string, string> endpointToIssuer = new(StringComparer.Ordinal)
        {
            ["https://a.example.com/fetch"] = "https://a.example.com",
            ["https://b.example.com/fetch"] = "https://b.example.com",
        };
        Dictionary<string, string> subordinateByIssuerSubject = new(StringComparer.Ordinal)
        {
            [Key("https://b.example.com", "https://a.example.com")] = bAboutA.CompactJws,
            [Key("https://a.example.com", "https://b.example.com")] = aAboutB.CompactJws,
        };

        FetchEntityConfigurationDelegate fetchConfiguration = (entity, context, ct) =>
            ValueTask.FromResult(configByEntity.TryGetValue(entity.Value, out string? jws)
                ? FederationHttpClientTransport.TryParseFetchedStatement(jws)
                : null);

        FetchEntityStatementDelegate fetchSubordinate = (subject, fetchEndpoint, context, ct) =>
            ValueTask.FromResult(
                endpointToIssuer.TryGetValue(fetchEndpoint.ToString(), out string? issuer)
                && subordinateByIssuerSubject.TryGetValue(Key(issuer, subject.Value), out string? jws)
                    ? FederationHttpClientTransport.TryParseFetchedStatement(jws)
                    : null);

        IReadOnlyList<string>? chain = await TrustChainResolver.BuildAsync(
            new EntityIdentifier("https://a.example.com"),
            [new EntityIdentifier("https://unreachable-anchor.example.com")],
            fetchConfiguration,
            fetchSubordinate,
            new ExchangeContext(),
            maxChainLength: 5,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(chain, "A cyclic graph with no reachable anchor must yield null, not loop.");
    }


    /// <summary>Builds an extra-claims bag carrying an <c>authority_hints</c> array.</summary>
    private static Dictionary<string, object> AuthorityHints(params string[] hints) =>
        new(StringComparer.Ordinal)
        {
            [WellKnownFederationClaimNames.AuthorityHints] = new List<object>(hints),
        };


    /// <summary>Builds an extra-claims bag carrying a <c>federation_entity.federation_fetch_endpoint</c>.</summary>
    private static Dictionary<string, object> FetchEndpoint(string endpoint) =>
        new(StringComparer.Ordinal)
        {
            [WellKnownFederationClaimNames.Metadata] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [WellKnownEntityTypeIdentifiers.FederationEntity.Value] = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    [FederationMetadataParameterNames.FetchEndpoint] = endpoint,
                },
            },
        };


    /// <summary>Merges two extra-claims bags (right wins on key collisions).</summary>
    private static Dictionary<string, object> Merge(
        Dictionary<string, object> left, Dictionary<string, object> right)
    {
        Dictionary<string, object> result = new(left, StringComparer.Ordinal);
        foreach(KeyValuePair<string, object> entry in right)
        {
            result[entry.Key] = entry.Value;
        }

        return result;
    }


    /// <summary>A composite key for the (issuer, subject) Subordinate Statement lookup.</summary>
    private static string Key(string issuer, string subject) => $"{issuer}\n{subject}";
}
