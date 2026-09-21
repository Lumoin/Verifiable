using System.Text;
using Verifiable.Core.OutboundFetch;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Federation;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Federation;

/// <summary>
/// Exercises the shipped <see cref="FederationHttpTransport"/> — the
/// transport-agnostic fetch primitive. The library carries no
/// <c>System.Net.Http</c>; the test supplies a single-hop
/// <see cref="OutboundTransportDelegate"/> directly (an application wraps its
/// own <c>HttpClient</c> the same way) and the transport encodes the §8.1 GET
/// conventions and parses the response into a typed statement through the
/// firewall seams.
/// </summary>
[TestClass]
internal sealed class FederationHttpTransportTests
{
    public TestContext TestContext { get; set; } = null!;

    /// <summary>Header deserializer mirroring the authorization server's wiring.</summary>
    private static JwtHeaderDeserializer HeaderDeserializer { get; } = static bytes =>
        JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
            bytes, TestSetup.DefaultSerializationOptions)
        ?? throw new FormatException("Header JSON parsed to null.");

    /// <summary>Payload deserializer mirroring the authorization server's wiring.</summary>
    private static JwtPayloadDeserializer PayloadDeserializer { get; } = static bytes =>
        JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
            bytes, TestSetup.DefaultSerializationOptions)
        ?? throw new FormatException("Payload JSON parsed to null.");


    /// <summary>Builds a single-hop transport that answers with a fixed status and body.</summary>
    private static OutboundTransportDelegate CannedTransport(int statusCode, string body) =>
        CannedTransport(statusCode, body, HttpHeaderSet.Empty);


    /// <summary>Builds a single-hop transport that answers with a fixed status, body, and response headers.</summary>
    private static OutboundTransportDelegate CannedTransport(int statusCode, string body, HttpHeaderSet headers) =>
        (request, context, cancellationToken) =>
            ValueTask.FromResult(new OutboundResponse
            {
                StatusCode = statusCode,
                Body = new TaggedMemory<byte>(Encoding.UTF8.GetBytes(body), Tag.Empty),
                Headers = headers
            });


    [TestMethod]
    public async Task FetchParsesAStatementServedOverTheTransport()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;
        using FederationTestRingNode subject =
            FederationTestRing.CreateNode(new EntityIdentifier("https://leaf.example.com"));

        MintedStatement minted = await FederationTestRing.MintEntityConfigurationAsync(
            subject, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        FetchEntityStatementDelegate fetch = FederationHttpTransport.BuildFetchEntityStatement(
            CannedTransport(200, minted.CompactJws),
            HeaderDeserializer,
            PayloadDeserializer,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared);

        FetchedEntityStatement? result = await fetch(
            subject.Identifier,
            new Uri("https://leaf.example.com/federation_fetch"),
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(result, "A 2xx response carrying a signed statement must parse.");
        Assert.AreEqual(subject.Identifier.Value, result.Statement.Issuer.Value);
        Assert.AreEqual(subject.Identifier.Value, result.Statement.Subject.Value,
            "A subject Entity Configuration has iss == sub.");
        Assert.AreEqual(minted.CompactJws, result.CompactJws);
    }


    /// <summary>
    /// A non-2xx response surfaces as a null fetch — no statement, and so no
    /// <see cref="Verifiable.Core.OutboundFetch.HttpCacheFreshness"/> to report either, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9111#section-5.2">RFC 9111 §5.2</see> (there is no
    /// document a cache could keep from a fetch that produced nothing).
    /// </summary>
    [TestMethod]
    public async Task FetchReturnsNullOnNonSuccessStatus()
    {
        using FederationTestRingNode subject =
            FederationTestRing.CreateNode(new EntityIdentifier("https://leaf.example.com"));

        FetchEntityStatementDelegate fetch = FederationHttpTransport.BuildFetchEntityStatement(
            CannedTransport(404, string.Empty),
            HeaderDeserializer,
            PayloadDeserializer,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared);

        FetchedEntityStatement? result = await fetch(
            subject.Identifier,
            new Uri("https://leaf.example.com/federation_fetch"),
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(result, "A non-2xx response must surface as a null fetch.");
    }


    /// <summary>
    /// A fetched statement's response carrying <c>Cache-Control: max-age</c> reports that many seconds of
    /// storable freshness on the result, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9111#section-5.2">RFC 9111 §5.2</see>.
    /// </summary>
    [TestMethod]
    public async Task FetchReportsMaxAgeAsStorableFreshness()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;
        using FederationTestRingNode subject =
            FederationTestRing.CreateNode(new EntityIdentifier("https://leaf.example.com"));

        MintedStatement minted = await FederationTestRing.MintEntityConfigurationAsync(
            subject, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        FetchEntityStatementDelegate fetch = FederationHttpTransport.BuildFetchEntityStatement(
            CannedTransport(200, minted.CompactJws, HttpHeaderSet.FromPairs((WellKnownHttpHeaderNames.CacheControl, "max-age=180"))),
            HeaderDeserializer,
            PayloadDeserializer,
            TestSetup.Base64UrlDecoder,
            BaseMemoryPool.Shared);

        FetchedEntityStatement? result = await fetch(
            subject.Identifier,
            new Uri("https://leaf.example.com/federation_fetch"),
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(result, "A 2xx response carrying a signed statement must parse.");
        Assert.IsTrue(result.Freshness.IsStorable, "A max-age response is storable.");
        Assert.AreEqual(TimeSpan.FromSeconds(180), result.Freshness.FreshnessLifetime,
            "The reported lifetime is exactly the max-age directive's delta-seconds.");
    }
}
