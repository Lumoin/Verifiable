using System.Collections.Immutable;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Core.SecurityEvents;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Ssf;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// HTTP wire tests for the SSF 1.0 §8.1.1 Stream Configuration endpoint family
/// (create/read/update/replace/delete) served by the transmitter-capable
/// authorization server, backed by a test in-memory stream store behind the
/// integration seams. Every emitted configuration is cross-validated with the
/// RECEIVER's strict parser so transmitter emission and receiver consumption
/// agree on the wire shape.
/// </summary>
[TestClass]
internal sealed class SsfStreamManagementEndpointTests
{
    private const string ClientId = "https://transmitter.example.com";
    private const string TransmitterIssuer = "https://transmitter.example/";
    private const string ReceiverAudience = "https://receiver.example/ssf";

    private static readonly string[] SupportedEvents =
    [
        CaepEventTypes.SessionRevoked,
        CaepEventTypes.CredentialChange
    ];

    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();


    [TestMethod]
    public async Task StreamLifecycleOverHttpWire()
    {
        await using TestHostShell app = new(TimeProvider);
        Dictionary<string, SsfStreamConfiguration> store = RegisterTransmitter(app, out VerifierKeyMaterial material);
        using VerifierKeyMaterial _ = material;

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = material.Registration.TenantId.Value;
        Uri streamUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/ssf/stream");
        HttpClient http = host.SharedHttpClient!;

        //The discovery document now advertises the Configuration Endpoint,
        //because the create seam is wired and on the chain.
        Uri wellKnown = new(host.HttpBaseAddress!, $"/connect/{segment}/.well-known/ssf-configuration");
        using HttpResponseMessage discovery = await http.GetAsync(wellKnown, TestContext.CancellationToken).ConfigureAwait(false);
        SsfTransmitterConfiguration? metadata = SsfDiscoveryJsonParsing.ParseTransmitterConfiguration(
            await discovery.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false));
        Assert.IsNotNull(metadata);
        Assert.IsNotNull(metadata.ConfigurationEndpoint, "configuration_endpoint must be advertised when the store is wired.");
        Assert.AreEqual(streamUrl.AbsolutePath, new Uri(metadata.ConfigurationEndpoint!).AbsolutePath);

        //CREATE (§8.1.1.1) with an empty body: every Receiver-supplied member is
        //optional and absent delivery defaults to poll with a Transmitter-supplied
        //endpoint_url.
        using StringContent emptyBody = new(string.Empty, Encoding.UTF8, WellKnownMediaTypes.Application.Json);
        using HttpResponseMessage created = await http.PostAsync(streamUrl, emptyBody, TestContext.CancellationToken).ConfigureAwait(false);
        string createdBody = await created.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, (int)created.StatusCode, createdBody);

        SsfStreamConfiguration? stream = SsfStreamJsonParsing.ParseStreamConfiguration(createdBody);
        Assert.IsNotNull(stream, $"The created stream must strict-parse. Body: {createdBody}");
        Assert.AreEqual(TransmitterIssuer, stream.Issuer);
        Assert.IsTrue(SsfDeliveryMethods.IsPollHttp(stream.Delivery.Method), "Absent delivery defaults to poll (§8.1.1.1).");
        Assert.IsFalse(string.IsNullOrEmpty(stream.Delivery.EndpointUrl), "Poll endpoint_url is Transmitter-supplied.");
        Assert.HasCount(2, stream.EventsDelivered!);

        //READ one (§8.1.1.2).
        using HttpResponseMessage readOne = await http.GetAsync(
            new Uri($"{streamUrl}?stream_id={stream.StreamId}"), TestContext.CancellationToken).ConfigureAwait(false);
        string readBody = await readOne.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)readOne.StatusCode, readBody);
        SsfStreamConfiguration? read = SsfStreamJsonParsing.ParseStreamConfiguration(readBody);
        Assert.IsNotNull(read);
        Assert.AreEqual(stream.StreamId, read.StreamId);

        //UPDATE (PATCH, §8.1.1.3): change only the description.
        using StringContent patchBody = new(
            $$"""{"stream_id":"{{stream.StreamId}}","description":"updated description"}""",
            Encoding.UTF8, WellKnownMediaTypes.Application.Json);
        using HttpRequestMessage patch = new(HttpMethod.Patch, streamUrl) { Content = patchBody };
        using HttpResponseMessage patched = await http.SendAsync(patch, TestContext.CancellationToken).ConfigureAwait(false);
        string patchedBody = await patched.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)patched.StatusCode, patchedBody);
        SsfStreamConfiguration? updated = SsfStreamJsonParsing.ParseStreamConfiguration(patchedBody);
        Assert.IsNotNull(updated);
        Assert.AreEqual("updated description", updated.Description);
        Assert.HasCount(2, updated.EventsDelivered!, "PATCH must leave absent properties unchanged.");

        //REPLACE (PUT, §8.1.1.4): full Receiver-supplied set; the absent
        //description is a requested deletion.
        using StringContent putBody = new(
            $$"""{"stream_id":"{{stream.StreamId}}","delivery":{"method":"{{SsfDeliveryMethods.PushHttp}}","endpoint_url":"https://receiver.example/push"},"events_requested":["{{CaepEventTypes.SessionRevoked}}"]}""",
            Encoding.UTF8, WellKnownMediaTypes.Application.Json);
        using HttpRequestMessage put = new(HttpMethod.Put, streamUrl) { Content = putBody };
        using HttpResponseMessage replaced = await http.SendAsync(put, TestContext.CancellationToken).ConfigureAwait(false);
        string replacedBody = await replaced.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)replaced.StatusCode, replacedBody);
        SsfStreamConfiguration? swapped = SsfStreamJsonParsing.ParseStreamConfiguration(replacedBody);
        Assert.IsNotNull(swapped);
        Assert.IsTrue(SsfDeliveryMethods.IsPushHttp(swapped.Delivery.Method));
        Assert.IsNull(swapped.Description, "PUT deletes absent Receiver-supplied properties.");
        Assert.HasCount(1, swapped.EventsDelivered!);

        //DELETE (§8.1.1.5), then the read is 404 and the list is empty.
        using HttpRequestMessage delete = new(HttpMethod.Delete, new Uri($"{streamUrl}?stream_id={stream.StreamId}"));
        using HttpResponseMessage deleted = await http.SendAsync(delete, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(204, (int)deleted.StatusCode);

        using HttpResponseMessage readGone = await http.GetAsync(
            new Uri($"{streamUrl}?stream_id={stream.StreamId}"), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(404, (int)readGone.StatusCode);

        using HttpResponseMessage list = await http.GetAsync(streamUrl, TestContext.CancellationToken).ConfigureAwait(false);
        string listBody = await list.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)list.StatusCode, listBody);
        using JsonDocument listDoc = JsonDocument.Parse(listBody);
        Assert.AreEqual(JsonValueKind.Array, listDoc.RootElement.ValueKind, "A list read returns a JSON array (§8.1.1.2).");
        Assert.AreEqual(0, listDoc.RootElement.GetArrayLength());

        Assert.IsEmpty(store, "The store must be empty after deletion.");
    }


    [TestMethod]
    public async Task CreateWithPushDeliveryEchoesRequestedConfiguration()
    {
        await using TestHostShell app = new(TimeProvider);
        Dictionary<string, SsfStreamConfiguration> store = RegisterTransmitter(app, out VerifierKeyMaterial material);
        using VerifierKeyMaterial _ = material;

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri streamUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/ssf/stream");

        using StringContent body = new(
            $$"""{"delivery":{"method":"{{SsfDeliveryMethods.PushHttp}}","endpoint_url":"https://receiver.example/push"},"events_requested":["{{CaepEventTypes.SessionRevoked}}","urn:example:unknown"],"description":"push stream"}""",
            Encoding.UTF8, WellKnownMediaTypes.Application.Json);
        using HttpResponseMessage created = await host.SharedHttpClient!
            .PostAsync(streamUrl, body, TestContext.CancellationToken).ConfigureAwait(false);
        string createdBody = await created.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, (int)created.StatusCode, createdBody);

        SsfStreamConfiguration? stream = SsfStreamJsonParsing.ParseStreamConfiguration(createdBody);
        Assert.IsNotNull(stream);
        Assert.IsTrue(SsfDeliveryMethods.IsPushHttp(stream.Delivery.Method));
        Assert.AreEqual("https://receiver.example/push", stream.Delivery.EndpointUrl);
        //events_delivered is the supported ∩ requested intersection — the unknown
        //event type is ignored (§8.1.1).
        Assert.HasCount(1, stream.EventsDelivered!);
        Assert.AreEqual(CaepEventTypes.SessionRevoked, stream.EventsDelivered![0]);
        Assert.HasCount(1, store);
    }


    [TestMethod]
    public async Task SecondCreateConflictsAndMalformedBodiesAreRejected()
    {
        await using TestHostShell app = new(TimeProvider);
        Dictionary<string, SsfStreamConfiguration> store = RegisterTransmitter(app, out VerifierKeyMaterial material);
        using VerifierKeyMaterial _ = material;

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri streamUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/ssf/stream");
        HttpClient http = host.SharedHttpClient!;

        using StringContent empty = new(string.Empty, Encoding.UTF8, WellKnownMediaTypes.Application.Json);
        using HttpResponseMessage first = await http.PostAsync(streamUrl, empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, (int)first.StatusCode);

        //This single-stream transmitter answers a second create with 409 (§8.1.1.1).
        using StringContent emptyAgain = new(string.Empty, Encoding.UTF8, WellKnownMediaTypes.Application.Json);
        using HttpResponseMessage second = await http.PostAsync(streamUrl, emptyAgain, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(409, (int)second.StatusCode);

        //A body that is not a JSON object is a 400.
        using StringContent garbage = new("not json", Encoding.UTF8, WellKnownMediaTypes.Application.Json);
        using HttpResponseMessage malformed = await http.PostAsync(streamUrl, garbage, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)malformed.StatusCode);

        //An update naming an unknown stream is a 404; one without stream_id is a 400.
        using StringContent unknown = new(
            """{"stream_id":"does-not-exist","description":"x"}""", Encoding.UTF8, WellKnownMediaTypes.Application.Json);
        using HttpRequestMessage patchUnknown = new(HttpMethod.Patch, streamUrl) { Content = unknown };
        Assert.AreEqual(404, (int)(await http.SendAsync(patchUnknown, TestContext.CancellationToken).ConfigureAwait(false)).StatusCode);

        using StringContent noId = new("""{"description":"x"}""", Encoding.UTF8, WellKnownMediaTypes.Application.Json);
        using HttpRequestMessage patchNoId = new(HttpMethod.Patch, streamUrl) { Content = noId };
        Assert.AreEqual(400, (int)(await http.SendAsync(patchNoId, TestContext.CancellationToken).ConfigureAwait(false)).StatusCode);

        //DELETE without the REQUIRED stream_id query parameter is a 400 (§8.1.1.5).
        using HttpRequestMessage deleteNoId = new(HttpMethod.Delete, streamUrl);
        Assert.AreEqual(400, (int)(await http.SendAsync(deleteNoId, TestContext.CancellationToken).ConfigureAwait(false)).StatusCode);
    }


    [TestMethod]
    public async Task StreamControlEndpointsOverHttpWire()
    {
        await using TestHostShell app = new(TimeProvider);
        Dictionary<string, SsfStreamConfiguration> store = RegisterTransmitter(app, out VerifierKeyMaterial material);
        using VerifierKeyMaterial _ = material;

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = material.Registration.TenantId.Value;
        HttpClient http = host.SharedHttpClient!;
        Uri streamUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/ssf/stream");
        Uri statusUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/ssf/status");
        Uri addSubjectUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/ssf/subjects/add");
        Uri removeSubjectUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/ssf/subjects/remove");
        Uri verifyUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/ssf/verify");

        //With every control seam wired, the discovery document advertises the
        //full §7.1 endpoint set — strict-parsed by the receiver parser.
        Uri wellKnown = new(host.HttpBaseAddress!, $"/connect/{segment}/.well-known/ssf-configuration");
        using HttpResponseMessage discovery = await http.GetAsync(wellKnown, TestContext.CancellationToken).ConfigureAwait(false);
        SsfTransmitterConfiguration? metadata = SsfDiscoveryJsonParsing.ParseTransmitterConfiguration(
            await discovery.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false));
        Assert.IsNotNull(metadata);
        Assert.IsNotNull(metadata.StatusEndpoint, "status_endpoint must be advertised when the status seams are wired.");
        Assert.IsNotNull(metadata.AddSubjectEndpoint);
        Assert.IsNotNull(metadata.RemoveSubjectEndpoint);
        Assert.IsNotNull(metadata.VerificationEndpoint);

        //Create the stream the control operations target.
        using StringContent createBody = new(string.Empty, Encoding.UTF8, WellKnownMediaTypes.Application.Json);
        using HttpResponseMessage created = await http.PostAsync(streamUrl, createBody, TestContext.CancellationToken).ConfigureAwait(false);
        SsfStreamConfiguration? stream = SsfStreamJsonParsing.ParseStreamConfiguration(
            await created.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false));
        Assert.IsNotNull(stream);

        //Status read (§8.1.2.1): the new stream is enabled; the emitted status
        //strict-parses with the receiver parser.
        using HttpResponseMessage statusRead = await http.GetAsync(
            new Uri($"{statusUrl}?stream_id={stream.StreamId}"), TestContext.CancellationToken).ConfigureAwait(false);
        string statusBody = await statusRead.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)statusRead.StatusCode, statusBody);
        SsfStreamStatus? status = SsfStreamJsonParsing.ParseStreamStatus(statusBody);
        Assert.IsNotNull(status);
        Assert.IsTrue(SsfStreamStatusValues.IsEnabled(status.Status));

        //Status read without the REQUIRED stream_id → 400; unknown stream → 404.
        using HttpResponseMessage statusNoId = await http.GetAsync(statusUrl, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)statusNoId.StatusCode);
        using HttpResponseMessage statusUnknown = await http.GetAsync(
            new Uri($"{statusUrl}?stream_id=missing"), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(404, (int)statusUnknown.StatusCode);

        //Status update (§8.1.2.2): pause with a reason; the response echoes the
        //updated status.
        using StringContent pauseBody = new(
            $$"""{"stream_id":"{{stream.StreamId}}","status":"paused","reason":"maintenance"}""",
            Encoding.UTF8, WellKnownMediaTypes.Application.Json);
        using HttpResponseMessage paused = await http.PostAsync(statusUrl, pauseBody, TestContext.CancellationToken).ConfigureAwait(false);
        string pausedBody = await paused.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)paused.StatusCode, pausedBody);
        SsfStreamStatus? updatedStatus = SsfStreamJsonParsing.ParseStreamStatus(pausedBody);
        Assert.IsNotNull(updatedStatus);
        Assert.IsTrue(SsfStreamStatusValues.IsPaused(updatedStatus.Status));
        Assert.AreEqual("maintenance", updatedStatus.Reason);

        //A non-conformant status value never reaches the store: the strict
        //parser rejects it and the endpoint responds 400.
        using StringContent badStatus = new(
            $$"""{"stream_id":"{{stream.StreamId}}","status":"halted"}""",
            Encoding.UTF8, WellKnownMediaTypes.Application.Json);
        using HttpResponseMessage rejectedStatus = await http.PostAsync(statusUrl, badStatus, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)rejectedStatus.StatusCode);

        //Add Subject (§8.1.3.2) → empty 200; Remove Subject (§8.1.3.3) → 204.
        using StringContent addBody = new(
            $$"""{"stream_id":"{{stream.StreamId}}","subject":{"format":"email","email":"user@example.com"},"verified":true}""",
            Encoding.UTF8, WellKnownMediaTypes.Application.Json);
        using HttpResponseMessage added = await http.PostAsync(addSubjectUrl, addBody, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)added.StatusCode);

        using StringContent removeBody = new(
            $$$"""{"stream_id":"{{{stream.StreamId}}}","subject":{"format":"email","email":"user@example.com"}}""",
            Encoding.UTF8, WellKnownMediaTypes.Application.Json);
        using HttpResponseMessage removed = await http.PostAsync(removeSubjectUrl, removeBody, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(204, (int)removed.StatusCode);

        //A subject body without a well-formed Subject Identifier is a 400.
        using StringContent badSubject = new(
            $$$"""{"stream_id":"{{{stream.StreamId}}}","subject":{"email":"no-format@example.com"}}""",
            Encoding.UTF8, WellKnownMediaTypes.Application.Json);
        using HttpResponseMessage subjectRejected = await http.PostAsync(addSubjectUrl, badSubject, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)subjectRejected.StatusCode);

        //Trigger Verification (§8.1.4.2) → 204 acceptance; the immediate repeat
        //exceeds the interval in this glue → 429.
        using StringContent verifyBody = new(
            $$"""{"stream_id":"{{stream.StreamId}}","state":"check-1"}""",
            Encoding.UTF8, WellKnownMediaTypes.Application.Json);
        using HttpResponseMessage verified = await http.PostAsync(verifyUrl, verifyBody, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(204, (int)verified.StatusCode);

        using StringContent verifyAgain = new(
            $$"""{"stream_id":"{{stream.StreamId}}","state":"check-2"}""",
            Encoding.UTF8, WellKnownMediaTypes.Application.Json);
        using HttpResponseMessage throttled = await http.PostAsync(verifyUrl, verifyAgain, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(429, (int)throttled.StatusCode);

        Assert.HasCount(1, store);
    }


    [TestMethod]
    public async Task ScopeEnforcementOverHttpWire()
    {
        await using TestHostShell app = new(TimeProvider);
        Dictionary<string, SsfStreamConfiguration> store = RegisterTransmitter(app, out VerifierKeyMaterial material);
        using VerifierKeyMaterial _ = material;
        Assert.IsEmpty(store);

        //An interop-profile §2.7.3 authorizer: each bearer token names its granted
        //scope and coverage follows SsfScopeSatisfies (manage includes read).
        app.Server.OAuth().AuthorizeSsfRequestAsync = static (request, requiredScope, registration, context, ct) =>
        {
            if(!request.Headers.TryGetSingle(WellKnownHttpHeaderNames.Authorization, out string? header) || header is null)
            {
                return ValueTask.FromResult(SsfRequestAuthorization.Unauthorized);
            }

            string? granted = header switch
            {
                "Bearer manage-token" => WellKnownScopes.SsfManage,
                "Bearer read-token" => WellKnownScopes.SsfRead,
                _ => null
            };
            if(granted is null)
            {
                return ValueTask.FromResult(SsfRequestAuthorization.Unauthorized);
            }

            return ValueTask.FromResult(WellKnownScopes.SsfScopeSatisfies(granted, requiredScope)
                ? SsfRequestAuthorization.Authorized
                : SsfRequestAuthorization.Forbidden);
        };

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = material.Registration.TenantId.Value;
        HttpClient http = host.SharedHttpClient!;
        Uri streamUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/ssf/stream");
        Uri statusUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/ssf/status");

        //No token → 401 (§8.1.1.1 error table).
        Assert.AreEqual(401, (int)(await SendAsync(http, HttpMethod.Post, streamUrl, body: string.Empty, token: null)
            .ConfigureAwait(false)).StatusCode);

        //A read-scoped token cannot create — management operations accept ssf.manage.
        Assert.AreEqual(403, (int)(await SendAsync(http, HttpMethod.Post, streamUrl, body: string.Empty, token: "read-token")
            .ConfigureAwait(false)).StatusCode);

        //A manage-scoped token creates.
        using HttpResponseMessage created = await SendAsync(http, HttpMethod.Post, streamUrl, body: string.Empty, token: "manage-token")
            .ConfigureAwait(false);
        string createdBody = await created.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, (int)created.StatusCode, createdBody);
        SsfStreamConfiguration? stream = SsfStreamJsonParsing.ParseStreamConfiguration(createdBody);
        Assert.IsNotNull(stream);

        //A read-scoped token reads status; a manage token covers read too.
        Assert.AreEqual(200, (int)(await SendAsync(
            http, HttpMethod.Get, new Uri($"{statusUrl}?stream_id={stream.StreamId}"), body: null, token: "read-token")
            .ConfigureAwait(false)).StatusCode);
        Assert.AreEqual(200, (int)(await SendAsync(
            http, HttpMethod.Get, new Uri($"{streamUrl}?stream_id={stream.StreamId}"), body: null, token: "manage-token")
            .ConfigureAwait(false)).StatusCode);

        //An unknown token → 401.
        Assert.AreEqual(401, (int)(await SendAsync(
            http, HttpMethod.Get, new Uri($"{statusUrl}?stream_id={stream.StreamId}"), body: null, token: "forged-token")
            .ConfigureAwait(false)).StatusCode);
    }


    /// <summary>
    /// Pins the documented default: the SSF stream-management endpoints delegate
    /// authentication to the application's <c>AuthorizeSsfRequestAsync</c> seam, and when that
    /// seam is left UNWIRED the management requests are served without authentication. This is
    /// the same app-owns-authorization model every other endpoint uses (the library never
    /// invents a token validator); SSF §7.1.1 keeps the well-known discovery document public
    /// regardless. A deployment that requires authentication wires the seam (covered by
    /// <see cref="ScopeEnforcementOverHttpWire"/>); this test exists so
    /// the permissive default cannot change silently — it is an asserted contract, not an
    /// accident of wiring.
    /// </summary>
    [TestMethod]
    public async Task UnwiredAuthorizationSeamLeavesSsfManagementOpen()
    {
        await using TestHostShell app = new(TimeProvider);
        Dictionary<string, SsfStreamConfiguration> store = RegisterTransmitter(app, out VerifierKeyMaterial material);
        using VerifierKeyMaterial _ = material;

        //Deliberately NOT wiring app.Server.OAuth().AuthorizeSsfRequestAsync.
        Assert.IsNull(app.Server.OAuth().AuthorizeSsfRequestAsync,
            "This test pins the behaviour when the authorization seam is unwired.");

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = material.Registration.TenantId.Value;
        HttpClient http = host.SharedHttpClient!;
        Uri streamUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/ssf/stream");

        //No token, no authorization seam → the create is served (201), not rejected.
        using HttpResponseMessage created = await SendAsync(
            http, HttpMethod.Post, streamUrl, body: string.Empty, token: null).ConfigureAwait(false);
        string createdBody = await created.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, (int)created.StatusCode, createdBody);
        Assert.HasCount(1, store);
    }


    private async Task<HttpResponseMessage> SendAsync(
        HttpClient http, HttpMethod method, Uri url, string? body, string? token)
    {
        using HttpRequestMessage request = new(method, url);
        if(body is not null)
        {
            request.Content = new StringContent(body, Encoding.UTF8, WellKnownMediaTypes.Application.Json);
        }

        if(token is not null)
        {
            request.Headers.TryAddWithoutValidation(WellKnownHttpHeaderNames.Authorization, $"Bearer {token}");
        }

        return await http.SendAsync(request, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Registers a transmitter-capable client and wires the shipped default
    /// parsers plus a single-stream in-memory store behind the integration seams.
    /// Returns the store so tests can assert on persisted state.
    /// </summary>
    private static Dictionary<string, SsfStreamConfiguration> RegisterTransmitter(
        TestHostShell app, out VerifierKeyMaterial material)
    {
        material = app.RegisterClient(
            ClientId,
            new Uri(ClientId),
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.SsfTransmitter,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint));

        Dictionary<string, SsfStreamConfiguration> store = new(StringComparer.Ordinal);
        Dictionary<string, SsfStreamStatus> statusByStream = new(StringComparer.Ordinal);
        HashSet<string> verificationRequested = new(StringComparer.Ordinal);

        app.Server.OAuth().UseDefaultSsfJsonParsing();

        app.Server.OAuth().CreateSsfStreamAsync = (request, registration, context, ct) =>
        {
            if(store.Count > 0)
            {
                return ValueTask.FromResult(SsfStreamWriteResult.Failed(SsfStreamWriteOutcome.Conflict));
            }

            string streamId = Guid.NewGuid().ToString("N");
            SsfStreamConfiguration stream = new()
            {
                StreamId = streamId,
                Issuer = TransmitterIssuer,
                Audiences = [ReceiverAudience],
                //Absent delivery defaults to poll with a Transmitter-supplied URL (§8.1.1.1).
                Delivery = request.Delivery ?? new SsfDeliveryConfiguration
                {
                    Method = SsfDeliveryMethods.PollHttp,
                    EndpointUrl = $"https://transmitter.example/ssf/poll/{streamId}"
                },
                EventsSupported = SupportedEvents,
                EventsRequested = request.EventsRequested,
                EventsDelivered = Intersect(request.EventsRequested),
                Description = request.Description
            };

            store[streamId] = stream;
            statusByStream[streamId] = new SsfStreamStatus
            {
                StreamId = streamId,
                Status = SsfStreamStatusValues.Enabled
            };

            return ValueTask.FromResult(SsfStreamWriteResult.Success(stream));
        };

        app.Server.OAuth().ReadSsfStreamsAsync = (streamId, registration, context, ct) =>
        {
            if(streamId is null)
            {
                return ValueTask.FromResult<IReadOnlyList<SsfStreamConfiguration>?>([.. store.Values]);
            }

            return ValueTask.FromResult<IReadOnlyList<SsfStreamConfiguration>?>(
                store.TryGetValue(streamId, out SsfStreamConfiguration? stream) ? [stream] : null);
        };

        app.Server.OAuth().UpdateSsfStreamAsync = (request, registration, context, ct) =>
        {
            if(!store.TryGetValue(request.StreamId, out SsfStreamConfiguration? existing))
            {
                return ValueTask.FromResult(SsfStreamWriteResult.Failed(SsfStreamWriteOutcome.NotFound));
            }

            //PATCH semantics: present Receiver-supplied properties change, absent
            //ones stay (§8.1.1.3).
            SsfStreamConfiguration updated = existing with
            {
                Delivery = request.Delivery ?? existing.Delivery,
                EventsRequested = request.EventsRequested ?? existing.EventsRequested,
                EventsDelivered = request.EventsRequested is null
                    ? existing.EventsDelivered
                    : Intersect(request.EventsRequested),
                Description = request.Description ?? existing.Description
            };

            store[request.StreamId] = updated;

            return ValueTask.FromResult(SsfStreamWriteResult.Success(updated));
        };

        app.Server.OAuth().ReplaceSsfStreamAsync = (request, registration, context, ct) =>
        {
            if(!store.TryGetValue(request.StreamId, out SsfStreamConfiguration? existing))
            {
                return ValueTask.FromResult(SsfStreamWriteResult.Failed(SsfStreamWriteOutcome.NotFound));
            }

            //PUT semantics: the full Receiver-supplied set replaces; absent
            //Receiver-supplied properties are deletions (§8.1.1.4).
            SsfStreamConfiguration replaced = existing with
            {
                Delivery = request.Delivery ?? new SsfDeliveryConfiguration
                {
                    Method = SsfDeliveryMethods.PollHttp,
                    EndpointUrl = $"https://transmitter.example/ssf/poll/{request.StreamId}"
                },
                EventsRequested = request.EventsRequested,
                EventsDelivered = Intersect(request.EventsRequested),
                Description = request.Description
            };

            store[request.StreamId] = replaced;

            return ValueTask.FromResult(SsfStreamWriteResult.Success(replaced));
        };

        app.Server.OAuth().DeleteSsfStreamAsync = (streamId, registration, context, ct) =>
        {
            statusByStream.Remove(streamId);

            return ValueTask.FromResult(store.Remove(streamId)
                ? SsfStreamWriteOutcome.Success
                : SsfStreamWriteOutcome.NotFound);
        };

        app.Server.OAuth().ReadSsfStreamStatusAsync = (streamId, registration, context, ct) =>
            ValueTask.FromResult(statusByStream.TryGetValue(streamId, out SsfStreamStatus? status) ? status : null);

        app.Server.OAuth().UpdateSsfStreamStatusAsync = (requested, registration, context, ct) =>
        {
            if(!statusByStream.ContainsKey(requested.StreamId))
            {
                return ValueTask.FromResult(SsfStreamStatusResult.Failed(SsfStreamOperationOutcome.NotFound));
            }

            statusByStream[requested.StreamId] = requested;

            return ValueTask.FromResult(SsfStreamStatusResult.Success(requested));
        };

        app.Server.OAuth().AddSsfSubjectAsync = (request, registration, context, ct) =>
            ValueTask.FromResult(store.ContainsKey(request.StreamId)
                ? SsfStreamOperationOutcome.Success
                : SsfStreamOperationOutcome.NotFound);

        app.Server.OAuth().RemoveSsfSubjectAsync = (request, registration, context, ct) =>
            ValueTask.FromResult(store.ContainsKey(request.StreamId)
                ? SsfStreamOperationOutcome.Success
                : SsfStreamOperationOutcome.NotFound);

        //One verification per stream in this glue: the second request simulates
        //exceeding min_verification_interval (§8.1.4.2 → 429).
        app.Server.OAuth().TriggerSsfVerificationAsync = (request, registration, context, ct) =>
        {
            if(!store.ContainsKey(request.StreamId))
            {
                return ValueTask.FromResult(SsfStreamOperationOutcome.NotFound);
            }

            return ValueTask.FromResult(verificationRequested.Add(request.StreamId)
                ? SsfStreamOperationOutcome.Success
                : SsfStreamOperationOutcome.TooManyRequests);
        };

        return store;
    }


    //events_delivered = events_supported ∩ events_requested; a null request means
    //the transmitter delivers everything it supports.
    private static IReadOnlyList<string> Intersect(IReadOnlyList<string>? requested)
    {
        if(requested is null)
        {
            return SupportedEvents;
        }

        List<string> delivered = [];
        foreach(string candidate in requested)
        {
            foreach(string supported in SupportedEvents)
            {
                if(string.Equals(candidate, supported, StringComparison.Ordinal))
                {
                    delivered.Add(candidate);
                }
            }
        }

        return delivered;
    }
}
