using System.Collections.Generic;
using System.Text;
using Verifiable.Core;
using Verifiable.Core.OutboundFetch;
using Verifiable.Cryptography;
using Verifiable.JCose;
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
    private static readonly JwtHeaderDeserializer HeaderDeserializer = static bytes =>
        JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
            bytes, TestSetup.DefaultSerializationOptions)
        ?? throw new FormatException("Header JSON parsed to null.");

    /// <summary>Payload deserializer mirroring the authorization server's wiring.</summary>
    private static readonly JwtPayloadDeserializer PayloadDeserializer = static bytes =>
        JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
            bytes, TestSetup.DefaultSerializationOptions)
        ?? throw new FormatException("Payload JSON parsed to null.");


    /// <summary>Builds a single-hop transport that answers with a fixed status and body.</summary>
    private static OutboundTransportDelegate CannedTransport(int statusCode, string body) =>
        (request, context, cancellationToken) =>
            ValueTask.FromResult(new OutboundResponse
            {
                StatusCode = statusCode,
                Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
                Body = new TaggedMemory<byte>(Encoding.UTF8.GetBytes(body), Tag.Empty),
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
            TestSetup.Base64UrlDecoder);

        FetchedEntityStatement? result = await fetch(
            subject.Identifier,
            new Uri("https://leaf.example.com/federation_fetch"),
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(result, "A 2xx response carrying a signed statement must parse.");
        Assert.AreEqual(subject.Identifier.Value, result.Statement.Issuer.Value);
        Assert.AreEqual(subject.Identifier.Value, result.Statement.Subject.Value,
            "A subject Entity Configuration has iss == sub.");
        Assert.AreEqual(minted.CompactJws, result.CompactJws);
    }


    [TestMethod]
    public async Task FetchReturnsNullOnNonSuccessStatus()
    {
        using FederationTestRingNode subject =
            FederationTestRing.CreateNode(new EntityIdentifier("https://leaf.example.com"));

        FetchEntityStatementDelegate fetch = FederationHttpTransport.BuildFetchEntityStatement(
            CannedTransport(404, string.Empty),
            HeaderDeserializer,
            PayloadDeserializer,
            TestSetup.Base64UrlDecoder);

        FetchedEntityStatement? result = await fetch(
            subject.Identifier,
            new Uri("https://leaf.example.com/federation_fetch"),
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(result, "A non-2xx response must surface as a null fetch.");
    }
}
