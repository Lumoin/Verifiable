using System;
using System.Buffers;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Core.SecurityEvents;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Ssf;
using Verifiable.Tests.OAuth;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.SecurityEvents;

/// <summary>
/// Firewalled HTTP end-to-end flows for the Shared Signals receiver surface:
/// real bytes traverse Kestrel + HttpClient over a socket, and each party sees
/// only the wire. The transmitter-side AS serves the discovery document; push
/// and poll move actual signed SETs into the receiver's reception pipeline.
/// </summary>
[TestClass]
internal sealed class SsfHttpFlowTests
{
    private const string ClientId = "https://transmitter.example.com";
    private const string TransmitterIssuer = "https://transmitter.example/";
    private const string ReceiverAudience = "https://receiver.example/ssf";

    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;


    [TestMethod]
    public async Task DiscoveryDocumentServedOverHttpStrictParses()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = app.RegisterClient(
            ClientId,
            new Uri(ClientId),
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.SsfTransmitter,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint));

        app.Server.OAuth().ContributeSsfTransmitterMetadataAsync = static (_, _, _) =>
            ValueTask.FromResult(new SsfTransmitterMetadataContribution
            {
                DeliveryMethodsSupported = [SsfDeliveryMethods.PushHttp, SsfDeliveryMethods.PollHttp]
            });

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = material.Registration.TenantId.Value;

        //The receiver fetches the document over the real socket and consumes it
        //with its strict parser — wire bytes only.
        Uri url = new(host.HttpBaseAddress!, $"/connect/{segment}/.well-known/ssf-configuration");
        using HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, $"GET .well-known/ssf-configuration must return 200. Body: {body}");
        Assert.AreEqual(WellKnownMediaTypes.Application.Json, response.Content.Headers.ContentType?.MediaType);

        SsfTransmitterConfiguration? config = SsfDiscoveryJsonParsing.ParseTransmitterConfiguration(body);
        Assert.IsNotNull(config, $"The served document must parse strictly. Body: {body}");
        Assert.IsFalse(string.IsNullOrEmpty(config.Issuer));
        Assert.IsNotNull(config.JwksUri, "jwks_uri must be advertised — the Receiver verifies SETs against it.");
        Assert.HasCount(2, config.DeliveryMethodsSupported!);
    }


    [TestMethod]
    public async Task PushedSetOverHttpIsVerifiedAcknowledgedAndDeduplicated()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory transmitterPublic = keys.PublicKey;
        using PrivateKeyMemory transmitterPrivate = keys.PrivateKey;

        //The receiver's push endpoint: every request is one SET; the reception
        //pipeline decides 202 versus 400 + {err, description} per RFC 8935.
        HashSet<string> seenJtis = new(StringComparer.Ordinal);
        IsSecurityEventTokenJtiSeenDelegate isSeen =
            (jti, _, _) => ValueTask.FromResult(!seenJtis.Add(jti));

        async Task<MinimalHttpResponse> ReceiverPushHandler(MinimalHttpRequest request, CancellationToken ct)
        {
            if(request.ContentType is null
                || !request.ContentType.StartsWith(WellKnownMediaTypes.Application.SecEventJwt, StringComparison.OrdinalIgnoreCase))
            {
                return new MinimalHttpResponse
                {
                    StatusCode = 400,
                    ContentType = WellKnownMediaTypes.Application.Json,
                    Body = $$"""{"err":"{{SsfDeliveryErrorCodes.InvalidRequest}}","description":"Content-Type must be application/secevent+jwt."}"""
                };
            }

            SsfDeliveryDecision decision = await SecurityEventTokenReception.ReceiveAsync(
                request.Body, transmitterPublic, TransmitterIssuer, ReceiverAudience,
                SecurityEventTestJson.DeserializePart, SecurityEventTestJson.DeserializePart,
                TestSetup.Base64UrlDecoder, isSeen, new ExchangeContext(), Pool, cancellationToken: ct).ConfigureAwait(false);

            if(decision.Outcome is SsfDeliveryOutcome.Accepted or SsfDeliveryOutcome.AcceptedDuplicate)
            {
                return new MinimalHttpResponse { StatusCode = 202 };
            }

            return new MinimalHttpResponse
            {
                StatusCode = 400,
                ContentType = WellKnownMediaTypes.Application.Json,
                Body = $$"""{"err":"{{decision.Error!.Err}}"}"""
            };
        }

        await using MinimalHttpHost receiver = await MinimalHttpHost.StartAsync(
            ReceiverPushHandler, TestContext.CancellationToken).ConfigureAwait(false);

        string compact = await IssueAsync(transmitterPrivate, jwtId: Guid.NewGuid().ToString("N")).ConfigureAwait(false);

        using HttpClient transmitterClient = LoopbackTls.CreatePinnedHttpClient(receiver.Certificate);
        Uri pushUrl = new(receiver.BaseAddress, "/ssf/push");

        //First delivery: verified end to end over the socket and acknowledged.
        Assert.AreEqual(202, (int)(await PushAsync(transmitterClient, pushUrl, compact).ConfigureAwait(false)).StatusCode);

        //At-least-once redelivery of the same SET: re-acknowledged, not an error.
        Assert.AreEqual(202, (int)(await PushAsync(transmitterClient, pushUrl, compact).ConfigureAwait(false)).StatusCode);

        //A tampered SET is rejected with the RFC 8935 invalid_key error body.
        string[] parts = compact.Split('.');
        char[] payload = parts[1].ToCharArray();
        payload[3] = payload[3] == 'A' ? 'B' : 'A';
        string tampered = $"{parts[0]}.{new string(payload)}.{parts[2]}";

        using HttpResponseMessage rejected = await PushAsync(transmitterClient, pushUrl, tampered).ConfigureAwait(false);
        string rejectedBody = await rejected.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)rejected.StatusCode);

        using JsonDocument errorDoc = JsonDocument.Parse(rejectedBody);
        Assert.IsTrue(SsfDeliveryErrorCodes.IsInvalidKey(errorDoc.RootElement.GetProperty("err").GetString()!),
            $"A tampered SET must be rejected with invalid_key. Body: {rejectedBody}");
    }


    [TestMethod]
    public async Task PushedSetWithWrongIssuerIsRejectedOverHttpWithInvalidIssuerError()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory transmitterPublic = keys.PublicKey;
        using PrivateKeyMemory transmitterPrivate = keys.PrivateKey;

        HashSet<string> seenJtis = new(StringComparer.Ordinal);
        IsSecurityEventTokenJtiSeenDelegate isSeen =
            (jti, _, _) => ValueTask.FromResult(!seenJtis.Add(jti));

        async Task<MinimalHttpResponse> ReceiverPushHandler(MinimalHttpRequest request, CancellationToken ct)
        {
            SsfDeliveryDecision decision = await SecurityEventTokenReception.ReceiveAsync(
                request.Body, transmitterPublic, TransmitterIssuer, ReceiverAudience,
                SecurityEventTestJson.DeserializePart, SecurityEventTestJson.DeserializePart,
                TestSetup.Base64UrlDecoder, isSeen, new ExchangeContext(), Pool, cancellationToken: ct).ConfigureAwait(false);

            if(decision.Outcome is SsfDeliveryOutcome.Accepted or SsfDeliveryOutcome.AcceptedDuplicate)
            {
                return new MinimalHttpResponse { StatusCode = 202 };
            }

            return new MinimalHttpResponse
            {
                StatusCode = 400,
                ContentType = WellKnownMediaTypes.Application.Json,
                Body = $$"""{"err":"{{decision.Error!.Err}}"}"""
            };
        }

        await using MinimalHttpHost receiver = await MinimalHttpHost.StartAsync(
            ReceiverPushHandler, TestContext.CancellationToken).ConfigureAwait(false);

        //Signed by the real Transmitter key, but the iss claim names a different Transmitter
        //than the one this Receiver expects for this stream.
        string compact = await IssueAsync(
            transmitterPrivate, jwtId: Guid.NewGuid().ToString("N"), issuer: "https://impostor.example/").ConfigureAwait(false);

        using HttpClient transmitterClient = LoopbackTls.CreatePinnedHttpClient(receiver.Certificate);
        Uri pushUrl = new(receiver.BaseAddress, "/ssf/push");

        using HttpResponseMessage rejected = await PushAsync(transmitterClient, pushUrl, compact).ConfigureAwait(false);
        string rejectedBody = await rejected.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)rejected.StatusCode, $"A wrong-issuer SET must not be acknowledged. Body: {rejectedBody}");

        using JsonDocument errorDoc = JsonDocument.Parse(rejectedBody);
        Assert.IsTrue(SsfDeliveryErrorCodes.IsInvalidIssuer(errorDoc.RootElement.GetProperty("err").GetString()!),
            $"A SET whose iss does not match the expected Transmitter must be rejected with invalid_issuer. Body: {rejectedBody}");
    }


    [TestMethod]
    public async Task PushedSetWithWrongAudienceIsRejectedOverHttpWithInvalidAudienceError()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory transmitterPublic = keys.PublicKey;
        using PrivateKeyMemory transmitterPrivate = keys.PrivateKey;

        HashSet<string> seenJtis = new(StringComparer.Ordinal);
        IsSecurityEventTokenJtiSeenDelegate isSeen =
            (jti, _, _) => ValueTask.FromResult(!seenJtis.Add(jti));

        async Task<MinimalHttpResponse> ReceiverPushHandler(MinimalHttpRequest request, CancellationToken ct)
        {
            SsfDeliveryDecision decision = await SecurityEventTokenReception.ReceiveAsync(
                request.Body, transmitterPublic, TransmitterIssuer, ReceiverAudience,
                SecurityEventTestJson.DeserializePart, SecurityEventTestJson.DeserializePart,
                TestSetup.Base64UrlDecoder, isSeen, new ExchangeContext(), Pool, cancellationToken: ct).ConfigureAwait(false);

            if(decision.Outcome is SsfDeliveryOutcome.Accepted or SsfDeliveryOutcome.AcceptedDuplicate)
            {
                return new MinimalHttpResponse { StatusCode = 202 };
            }

            return new MinimalHttpResponse
            {
                StatusCode = 400,
                ContentType = WellKnownMediaTypes.Application.Json,
                Body = $$"""{"err":"{{decision.Error!.Err}}"}"""
            };
        }

        await using MinimalHttpHost receiver = await MinimalHttpHost.StartAsync(
            ReceiverPushHandler, TestContext.CancellationToken).ConfigureAwait(false);

        //Correct issuer, but the aud claim names a Receiver other than this one.
        string compact = await IssueAsync(
            transmitterPrivate, jwtId: Guid.NewGuid().ToString("N"), audience: "https://other-receiver.example/ssf").ConfigureAwait(false);

        using HttpClient transmitterClient = LoopbackTls.CreatePinnedHttpClient(receiver.Certificate);
        Uri pushUrl = new(receiver.BaseAddress, "/ssf/push");

        using HttpResponseMessage rejected = await PushAsync(transmitterClient, pushUrl, compact).ConfigureAwait(false);
        string rejectedBody = await rejected.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)rejected.StatusCode, $"A wrong-audience SET must not be acknowledged. Body: {rejectedBody}");

        using JsonDocument errorDoc = JsonDocument.Parse(rejectedBody);
        Assert.IsTrue(SsfDeliveryErrorCodes.IsInvalidAudience(errorDoc.RootElement.GetProperty("err").GetString()!),
            $"A SET whose aud does not include this Receiver must be rejected with invalid_audience. Body: {rejectedBody}");
    }


    [TestMethod]
    public async Task RejectedSetWithWrongIssuerDoesNotConsumeItsJtiSoAValidRedeliveryWithTheSameJtiIsAccepted()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory transmitterPublic = keys.PublicKey;
        using PrivateKeyMemory transmitterPrivate = keys.PrivateKey;

        HashSet<string> seenJtis = new(StringComparer.Ordinal);
        IsSecurityEventTokenJtiSeenDelegate isSeen =
            (jti, _, _) => ValueTask.FromResult(!seenJtis.Add(jti));

        async Task<MinimalHttpResponse> ReceiverPushHandler(MinimalHttpRequest request, CancellationToken ct)
        {
            SsfDeliveryDecision decision = await SecurityEventTokenReception.ReceiveAsync(
                request.Body, transmitterPublic, TransmitterIssuer, ReceiverAudience,
                SecurityEventTestJson.DeserializePart, SecurityEventTestJson.DeserializePart,
                TestSetup.Base64UrlDecoder, isSeen, new ExchangeContext(), Pool, cancellationToken: ct).ConfigureAwait(false);

            if(decision.Outcome is SsfDeliveryOutcome.Accepted or SsfDeliveryOutcome.AcceptedDuplicate)
            {
                return new MinimalHttpResponse { StatusCode = 202 };
            }

            return new MinimalHttpResponse
            {
                StatusCode = 400,
                ContentType = WellKnownMediaTypes.Application.Json,
                Body = $$"""{"err":"{{decision.Error!.Err}}"}"""
            };
        }

        await using MinimalHttpHost receiver = await MinimalHttpHost.StartAsync(
            ReceiverPushHandler, TestContext.CancellationToken).ConfigureAwait(false);

        using HttpClient transmitterClient = LoopbackTls.CreatePinnedHttpClient(receiver.Certificate);
        Uri pushUrl = new(receiver.BaseAddress, "/ssf/push");

        string jti = Guid.NewGuid().ToString("N");

        //A wrong-issuer SET carrying jti J: rejected before the dedup check ever runs
        //(SecurityEventTokenVerification validates iss/aud claims before consulting
        //isJtiSeen), so J must not be recorded as seen.
        string wrongIssuerSet = await IssueAsync(transmitterPrivate, jti, issuer: "https://impostor.example/").ConfigureAwait(false);

        using HttpResponseMessage rejected = await PushAsync(transmitterClient, pushUrl, wrongIssuerSet).ConfigureAwait(false);
        string rejectedBody = await rejected.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)rejected.StatusCode, $"The wrong-issuer SET must not be acknowledged. Body: {rejectedBody}");

        using(JsonDocument errorDoc = JsonDocument.Parse(rejectedBody))
        {
            Assert.IsTrue(SsfDeliveryErrorCodes.IsInvalidIssuer(errorDoc.RootElement.GetProperty("err").GetString()!),
                $"The rejection must be invalid_issuer. Body: {rejectedBody}");
        }

        Assert.DoesNotContain(jti, seenJtis,
            "A rejected SET's jti must not be recorded — dedup only runs after claim validation succeeds.");

        //A correctly issued SET carrying the SAME jti must now be accepted: the earlier
        //rejection did not burn J.
        string validSet = await IssueAsync(transmitterPrivate, jti).ConfigureAwait(false);

        Assert.AreEqual(202, (int)(await PushAsync(transmitterClient, pushUrl, validSet).ConfigureAwait(false)).StatusCode);
        Assert.Contains(jti, seenJtis, "The valid redelivery must be processed and its jti recorded.");
    }


    [TestMethod]
    public async Task PollRoundTripDeliversVerifiesAndAcknowledgesOverHttp()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory transmitterPublic = keys.PublicKey;
        using PrivateKeyMemory transmitterPrivate = keys.PrivateKey;

        string jti = Guid.NewGuid().ToString("N");
        string compact = await IssueAsync(transmitterPrivate, jti).ConfigureAwait(false);

        //Transmitter-side poll endpoint glue: pending SETs keyed by jti; acks
        //release them. Parses the receiver's poll request with the SAME library
        //wire models the production transmitter will use.
        Dictionary<string, string> pending = new(StringComparer.Ordinal) { [jti] = compact };
        List<string> acknowledged = [];

        Task<MinimalHttpResponse> TransmitterPollHandler(MinimalHttpRequest request, CancellationToken ct)
        {
            SsfPollRequest? pollRequest = SsfPollJsonParsing.ParsePollRequest(request.Body);
            if(pollRequest is null)
            {
                return Task.FromResult(new MinimalHttpResponse { StatusCode = 400 });
            }

            foreach(string ackedJti in pollRequest.Acks)
            {
                if(pending.Remove(ackedJti))
                {
                    acknowledged.Add(ackedJti);
                }
            }

            var sets = new Dictionary<string, object>(StringComparer.Ordinal);
            foreach(KeyValuePair<string, string> entry in pending)
            {
                sets[entry.Key] = entry.Value;
            }

            string responseBody = JsonSerializerExtensions.Serialize(
                new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    [SsfPollParameterNames.Sets] = sets,
                    [SsfPollParameterNames.MoreAvailable] = false
                },
                TestSetup.DefaultSerializationOptions);

            return Task.FromResult(new MinimalHttpResponse
            {
                StatusCode = 200,
                ContentType = WellKnownMediaTypes.Application.Json,
                Body = responseBody
            });
        }

        await using MinimalHttpHost transmitter = await MinimalHttpHost.StartAsync(
            TransmitterPollHandler, TestContext.CancellationToken).ConfigureAwait(false);

        using HttpClient receiverClient = LoopbackTls.CreatePinnedHttpClient(transmitter.Certificate);
        Uri pollUrl = new(transmitter.BaseAddress, "/ssf/poll");

        //Poll 1: fetch pending SETs.
        SsfPollResponse first = await PollAsync(
            receiverClient, pollUrl, """{"maxEvents":5,"returnImmediately":true}""").ConfigureAwait(false);
        Assert.HasCount(1, first.Sets);
        Assert.IsFalse(first.MoreAvailable);

        //Receive each SET through the same pipeline push uses; collect acks.
        HashSet<string> seenJtis = new(StringComparer.Ordinal);
        IsSecurityEventTokenJtiSeenDelegate isSeen =
            (candidate, _, _) => ValueTask.FromResult(!seenJtis.Add(candidate));

        List<string> toAcknowledge = [];
        foreach(KeyValuePair<string, string> delivered in first.Sets)
        {
            SsfDeliveryDecision decision = await SecurityEventTokenReception.ReceiveAsync(
                delivered.Value, transmitterPublic, TransmitterIssuer, ReceiverAudience,
                SecurityEventTestJson.DeserializePart, SecurityEventTestJson.DeserializePart,
                TestSetup.Base64UrlDecoder, isSeen, new ExchangeContext(), Pool,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(SsfDeliveryOutcome.Accepted, decision.Outcome);
            Assert.AreEqual(CaepEventTypes.SessionRevoked, decision.Token!.Events[0].EventType);
            toAcknowledge.Add(delivered.Key);
        }

        //Poll 2: acknowledge-only (maxEvents 0 + ack). The transmitter releases
        //the SET and has nothing further to deliver.
        SsfPollResponse second = await PollAsync(
            receiverClient, pollUrl,
            $$"""{"maxEvents":0,"returnImmediately":true,"ack":["{{toAcknowledge[0]}}"]}""").ConfigureAwait(false);

        Assert.IsEmpty(second.Sets, "After acknowledgement nothing remains to deliver.");
        Assert.IsEmpty(pending, "The transmitter must release acknowledged SETs.");
        Assert.HasCount(1, acknowledged);
        Assert.AreEqual(jti, acknowledged[0]);
    }


    private async Task<string> IssueAsync(
        PrivateKeyMemory signingKey, string jwtId, string? issuer = null, string? audience = null) =>
        await SecurityEventTokenIssuance.IssueAsync(
            issuer ?? TransmitterIssuer,
            [audience ?? ReceiverAudience],
            jwtId,
            issuedAt: DateTimeOffset.UnixEpoch.AddSeconds(1615305159),
            [new SecurityEvent
            {
                EventType = CaepEventTypes.SessionRevoked,
                Payload = new Dictionary<string, object> { ["event_timestamp"] = 1615304991L }
            }],
            signingKey,
            TestSetup.Base64UrlEncoder,
            SecurityEventTestJson.HeaderSerializer,
            SecurityEventTestJson.PayloadSerializer,
            Pool,
            signingKeyId: "key-1",
            subjectId: SubjectIdentifier.Opaque("stream-1"),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);


    private async Task<HttpResponseMessage> PushAsync(HttpClient client, Uri pushUrl, string compactSet)
    {
        using StringContent content = new(compactSet, Encoding.UTF8, WellKnownMediaTypes.Application.SecEventJwt);

        return await client.PostAsync(pushUrl, content, TestContext.CancellationToken).ConfigureAwait(false);
    }


    private async Task<SsfPollResponse> PollAsync(HttpClient client, Uri pollUrl, string requestJson)
    {
        using StringContent content = new(requestJson, Encoding.UTF8, WellKnownMediaTypes.Application.Json);
        using HttpResponseMessage response = await client.PostAsync(pollUrl, content, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        SsfPollResponse? parsed = SsfPollJsonParsing.ParsePollResponse(body);
        Assert.IsNotNull(parsed, $"The poll response must parse strictly. Body: {body}");

        return parsed;
    }
}
