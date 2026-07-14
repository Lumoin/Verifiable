using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core.StatusList;
using Verifiable.Cryptography;
using Verifiable.Foundation;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

using StatusListType = Verifiable.Core.StatusList.StatusList;

namespace Verifiable.Tests.StatusList;

/// <summary>
/// Real-wire capstone for Status List Aggregation (draft-ietf-oauth-status-list §11): an Issuer serves an
/// aggregation response listing multiple Status List Token URIs over a genuine loopback socket
/// (<see cref="StaticContentHost"/>); a Relying Party walks the aggregation, fetches each listed Status List
/// Token over its own real HTTP GET, verifies it, and evaluates one Referenced Token's status per list — each
/// hop proven by the host's per-path request counters.
/// </summary>
[TestClass]
internal sealed class StatusListAggregationHttpFlowTests
{
    /// <summary>The test framework's per-test context, including the cooperative cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The wall clock used to timestamp issued Status List Tokens and evaluate their status.</summary>
    private static TimeProvider Clock => new FakeTimeProvider(TestClock.CanonicalEpoch);

    /// <summary>The bit-array capacity shared by both published Status Lists.</summary>
    private const int Capacity = 16;

    /// <summary>The revoked index inside the first published Status List.</summary>
    private const int FirstRevokedIndex = 3;

    /// <summary>The revoked index inside the second published Status List.</summary>
    private const int SecondRevokedIndex = 5;

    /// <summary>The issuer signing key's identifier, carried as the Status List Token's <c>kid</c>.</summary>
    private const string KeyId = "https://issuer.example/statuslist#key-1";


    /// <summary>
    /// Walks aggregation → lists → per-credential status entirely over real sockets: the aggregation response
    /// and each Status List Token are fetched with their own HTTP requests, and the host's per-path counters
    /// prove every hop crossed the wire rather than being served from a locally-held copy.
    /// </summary>
    [TestMethod]
    public async Task WalksAggregationToListsToPerCredentialStatusOverRealSockets()
    {
        await using StaticContentHost host = await StaticContentHost.StartAsync(TestContext.CancellationToken).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        string firstSubject = new Uri(host.BaseAddress, "/statuslist/1").ToString();
        string secondSubject = new Uri(host.BaseAddress, "/statuslist/2").ToString();

        using StatusListType firstList = StatusListType.Create(Capacity, StatusListBitSize.OneBit, BaseMemoryPool.Shared, BitOrder.LeastSignificantFirst);
        firstList[FirstRevokedIndex] = StatusTypes.Invalid;
        var firstToken = new StatusListToken(firstSubject, Clock.GetUtcNow(), firstList);

        using StatusListType secondList = StatusListType.Create(Capacity, StatusListBitSize.OneBit, BaseMemoryPool.Shared, BitOrder.LeastSignificantFirst);
        secondList[SecondRevokedIndex] = StatusTypes.Invalid;
        var secondToken = new StatusListToken(secondSubject, Clock.GetUtcNow(), secondList);

        string firstJwt = await StatusListTokenJwtFixtures.IssueJwtAsync(firstToken, issuerPrivate, KeyId, TestContext.CancellationToken).ConfigureAwait(false);
        host.Publish("/statuslist/1", Encoding.ASCII.GetBytes(firstJwt), StatusListMediaTypes.StatusListJwtContentType);

        string secondJwt = await StatusListTokenJwtFixtures.IssueJwtAsync(secondToken, issuerPrivate, KeyId, TestContext.CancellationToken).ConfigureAwait(false);
        host.Publish("/statuslist/2", Encoding.ASCII.GetBytes(secondJwt), StatusListMediaTypes.StatusListJwtContentType);

        var aggregation = new StatusListAggregation([firstSubject, secondSubject]);
        ReadOnlyMemory<byte> aggregationBytes = JsonSerializerExtensions.SerializeToUtf8Bytes(aggregation, TestSetup.DefaultSerializationOptions);
        host.Publish("/aggregation", aggregationBytes, "application/json");

        using HttpClient httpClient = new();
        Uri aggregationUri = new(host.BaseAddress, "/aggregation");

        using HttpResponseMessage aggregationResponse = await httpClient.GetAsync(aggregationUri, TestContext.CancellationToken).ConfigureAwait(false);
        aggregationResponse.EnsureSuccessStatusCode();
        ReadOnlyMemory<byte> fetchedAggregationBytes = await aggregationResponse.Content.ReadAsByteArrayAsync(TestContext.CancellationToken).ConfigureAwait(false);
        StatusListAggregation parsedAggregation = JsonSerializerExtensions.Deserialize<StatusListAggregation>(fetchedAggregationBytes.Span, TestSetup.DefaultSerializationOptions)!;

        Assert.HasCount(2, parsedAggregation.StatusLists, "The aggregation MUST list both Status List Token URIs.");
        Assert.Contains(firstSubject, parsedAggregation.StatusLists, "The aggregation MUST list the first Status List Token's URI.");
        Assert.Contains(secondSubject, parsedAggregation.StatusLists, "The aggregation MUST list the second Status List Token's URI.");

        var fetchedTokens = new List<StatusListToken>();
        try
        {
            foreach(string listUri in parsedAggregation.StatusLists)
            {
                (string? contentType, StatusListToken fetched) = await StatusListTokenJwtFixtures
                    .FetchAndParseJwtAsync(httpClient, listUri, issuerPublic, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(StatusListMediaTypes.StatusListJwtContentType, contentType, "Each listed Status List Token MUST be served with the exact statuslist+jwt media type.");
                fetchedTokens.Add(fetched);

                int revokedIndex = string.Equals(listUri, firstSubject, StringComparison.Ordinal) ? FirstRevokedIndex : SecondRevokedIndex;
                byte status = StatusListValidation.GetStatus(fetched, new StatusListReference(revokedIndex, listUri), Clock.GetUtcNow());
                Assert.AreEqual(StatusTypes.Invalid, status, $"The revoked index in '{listUri}' MUST evaluate as invalid.");
            }

            Assert.IsTrue(host.WasRequested("/aggregation"), "The aggregation walk MUST have fetched the aggregation document over the wire.");
            Assert.IsTrue(host.WasRequested("/statuslist/1"), "The aggregation walk MUST have fetched the first list over the wire.");
            Assert.IsTrue(host.WasRequested("/statuslist/2"), "The aggregation walk MUST have fetched the second list over the wire.");
            Assert.AreEqual(3, host.TotalRequests, "Exactly one aggregation fetch plus one fetch per listed Status List Token MUST cross the socket.");
        }
        finally
        {
            foreach(StatusListToken fetched in fetchedTokens)
            {
                fetched.StatusList.Dispose();
            }
        }
    }
}
