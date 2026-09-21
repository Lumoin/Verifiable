using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
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
    private const string TenantAToken = "tenant-a-token";
    private const string TenantABearerHeader = "Bearer tenant-a-token";
    private const string TenantBBearerHeader = "Bearer tenant-b-token";
    private const string Receiver1Token = "receiver-1-token";
    private const string Receiver2Token = "receiver-2-token";
    private const string Receiver1BearerHeader = "Bearer " + Receiver1Token;
    private const string Receiver2BearerHeader = "Bearer " + Receiver2Token;

    private static string[] SupportedEvents { get; } =
    [
        CaepEventTypes.SessionRevoked,
        CaepEventTypes.CredentialChange
    ];

    /// <summary>
    /// The Receiver <see cref="RegisterTransmitterAsync"/>'s single-Receiver fixture binds every
    /// permitted request to — that fixture exercises store lifecycle, not Receiver-to-stream
    /// binding, so one fixed identity is enough (SSF 1.0 §8-3).
    /// </summary>
    private static SsfReceiver SingleReceiver { get; } = new() { Id = "receiver-under-test" };

    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);


    /// <summary>
    /// Drives Create, Read, Update (PATCH), Replace (PUT) and Delete for one stream over the real
    /// HTTP wire (SSF §8.1.1.1-§8.1.1.5), starting from a CREATE with an empty body so every
    /// Receiver-supplied member is exercised as absent: delivery defaults to poll with a
    /// Transmitter-supplied endpoint_url, and every response strict-parses with the RECEIVER's own
    /// parser. The discovery document is read first and asserted to advertise configuration_endpoint.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://openid.net/specs/openid-caep-interoperability-profile-1_0-01.html">
    /// OpenID CAEP Interoperability Profile 1.0, draft 01</see> 2.3.4-configuration-endpoint,
    /// 2.3.8-stream-management-api, 2.4.5.1-receiver-create-delivery.
    /// </remarks>
    [TestMethod]
    public async Task StreamLifecycleOverHttpWire()
    {
        await using TestHostShell app = new(TimeProvider);
        (Dictionary<string, SsfStreamConfiguration> store, VerifierKeyMaterial material) = await RegisterTransmitterAsync(app).ConfigureAwait(false);
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


    /// <summary>
    /// CREATE (SSF §8.1.1.1) with an explicit push delivery.method and endpoint_url: the response
    /// echoes the requested push configuration verbatim, and events_delivered narrows to the
    /// supported ∩ requested intersection, silently dropping the one unsupported event type
    /// requested alongside it.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://openid.net/specs/openid-caep-interoperability-profile-1_0-01.html">
    /// OpenID CAEP Interoperability Profile 1.0, draft 01</see> 2.3.8.1-create-delivery-method,
    /// 2.4.5.1-receiver-create-delivery.
    /// </remarks>
    [TestMethod]
    public async Task CreateWithPushDeliveryEchoesRequestedConfiguration()
    {
        await using TestHostShell app = new(TimeProvider);
        (Dictionary<string, SsfStreamConfiguration> store, VerifierKeyMaterial material) = await RegisterTransmitterAsync(app).ConfigureAwait(false);
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
        (_, VerifierKeyMaterial material) = await RegisterTransmitterAsync(app).ConfigureAwait(false);
        using VerifierKeyMaterial materialOwner = material;

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


    /// <summary>
    /// Drives Read Status, Update Status, Add Subject, Remove Subject and Trigger Verification
    /// (SSF §8.1.2-§8.1.4) over the real HTTP wire against a created stream, including the error
    /// responses each REQUIRED parameter and each closed-set value produces, and asserts the
    /// discovery document advertises status_endpoint, add/remove-subject and verification_endpoint
    /// once every control seam is wired.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://openid.net/specs/openid-caep-interoperability-profile-1_0-01.html">
    /// OpenID CAEP Interoperability Profile 1.0, draft 01</see> 2.3.5-status-endpoint,
    /// 2.3.6-verification-endpoint, 2.4.5.2-receiver-invocations.
    /// </remarks>
    [TestMethod]
    public async Task StreamControlEndpointsOverHttpWire()
    {
        await using TestHostShell app = new(TimeProvider);
        (Dictionary<string, SsfStreamConfiguration> store, VerifierKeyMaterial material) = await RegisterTransmitterAsync(app).ConfigureAwait(false);
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


    /// <summary>
    /// Gates every Stream Management API request behind a bearer-token OAuth 2.0 authorizer over
    /// the real HTTP wire: an absent or unrecognised token is rejected (401), a token granted only
    /// ssf.read cannot perform a management operation (403) but can read status, and a token
    /// granted ssf.manage can perform both — the §2.7.3 scope lattice enforced end to end rather
    /// than asserted against the pure predicate alone.
    /// </summary>
    /// <remarks>
    /// Proves <see href="https://openid.net/specs/openid-caep-interoperability-profile-1_0-01.html">
    /// OpenID CAEP Interoperability Profile 1.0, draft 01</see> 2.3.8.2-authorized-operations,
    /// 2.4.3-receiver-oauth, 2.7-oauth-roles, 2.7.2-bearer-token, 2.7.3-scope-operation-table.
    /// </remarks>
    [TestMethod]
    public async Task ScopeEnforcementOverHttpWire()
    {
        await using TestHostShell app = new(TimeProvider);
        (Dictionary<string, SsfStreamConfiguration> store, VerifierKeyMaterial material) = await RegisterTransmitterAsync(app).ConfigureAwait(false);
        using VerifierKeyMaterial _ = material;
        Assert.IsEmpty(store);

        //An interop-profile §2.7.3 authorizer: each bearer token names its granted
        //scope and coverage follows SsfScopeSatisfies (manage includes read).
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.AuthorizeSsfRequestAsync = static (evaluation, registration, context, ct) =>
            {
                if(!evaluation.Request.Headers.TryGetSingle(WellKnownHttpHeaderNames.Authorization, out string? header) || header is null)
                {

                    return ValueTask.FromResult(SsfRequestDecision.Deny(SsfRequestDenialReason.AuthenticationRequired));
                }

                string? granted = header switch
                {
                    "Bearer manage-token" => WellKnownScopes.SsfManage,
                    "Bearer read-token" => WellKnownScopes.SsfRead,
                    _ => null
                };
                if(granted is null)
                {

                    return ValueTask.FromResult(SsfRequestDecision.Deny(SsfRequestDenialReason.AuthenticationRequired));
                }

                return ValueTask.FromResult(WellKnownScopes.SsfScopeSatisfies(granted, evaluation.RequiredScope)
                    ? SsfRequestDecision.Permit(SingleReceiver)
                    : SsfRequestDecision.Deny(SsfRequestDenialReason.InsufficientScope));
            };
        }).ConfigureAwait(false);

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
    /// Pins the fail-closed default: when <c>AuthorizeSsfRequestAsync</c> is left UNWIRED, the
    /// Stream Management API candidates are not materialized at all — SSF 1.0 §8-3 requires
    /// every such endpoint to authorize the caller against the Receiver's own streams, so an
    /// unwired seam leaves no question to ask and the routes are unserved rather than open. The
    /// well-known discovery document stays public regardless (§7.1.1). A deployment that wants
    /// the routes served wires the seam (covered by <see cref="ScopeEnforcementOverHttpWire"/>
    /// and the cross-tenant tests below).
    /// </summary>
    [TestMethod]
    public async Task UnwiredAuthorizationSeamFailsStreamManagementClosed()
    {
        await using TestHostShell app = new(TimeProvider);
        (Dictionary<string, SsfStreamConfiguration> store, VerifierKeyMaterial material) = await RegisterTransmitterAsync(
            app, wireAuthorizationSeam: false).ConfigureAwait(false);
        using VerifierKeyMaterial _ = material;

        //Deliberately NOT wiring app.Server.OAuth().AuthorizeSsfRequestAsync.
        Assert.IsNull(app.Server.OAuth().AuthorizeSsfRequestAsync,
            "This test pins the fail-closed behaviour when the authorization seam is unwired.");

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = material.Registration.TenantId.Value;
        HttpClient http = host.SharedHttpClient!;
        Uri streamUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/ssf/stream");

        //No authorization seam → create and read are unserved routes (404), the same
        //response an unmatched path gets, not a rejected-but-served response.
        using HttpResponseMessage created = await SendAsync(
            http, HttpMethod.Post, streamUrl, body: string.Empty, token: null).ConfigureAwait(false);
        Assert.AreEqual(404, (int)created.StatusCode);

        using HttpResponseMessage read = await SendAsync(
            http, HttpMethod.Get, streamUrl, body: null, token: null).ConfigureAwait(false);
        Assert.AreEqual(404, (int)read.StatusCode);

        Assert.IsEmpty(store, "No stream may be written when the authorization seam is unwired.");
    }


    /// <summary>
    /// A caller fully scoped and authenticated for tenant A's own stream reaches for tenant B's
    /// GET route. SSF 1.0 §8-3: authorization must associate a Receiver with its own stream IDs;
    /// the denial is 403 with a fixed description carrying no tenant, client or stream identifier.
    /// </summary>
    [TestMethod]
    public async Task CrossTenantReadIsForbiddenWithNoIdentifierLeaked()
    {
        await using TestHostShell app = new(TimeProvider);
        TwoTenantFixture fixture = await RegisterTwoTenantTransmittersAsync(app).ConfigureAwait(false);
        using VerifierKeyMaterial _a = fixture.TenantA;
        using VerifierKeyMaterial _b = fixture.TenantB;

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        Uri tenantBStreamUrl = new(host.HttpBaseAddress!, $"/connect/{fixture.TenantB.Registration.TenantId.Value}/ssf/stream");

        using HttpResponseMessage response = await SendAsync(
            http, HttpMethod.Get, tenantBStreamUrl, body: null, token: TenantAToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        AssertCrossTenantDenial(response, body, fixture);
    }


    /// <summary>
    /// The same cross-tenant caller sends POST to create on tenant B. The denial is 403 and
    /// tenant B's store gains no stream (SSF 1.0 §8-3).
    /// </summary>
    [TestMethod]
    public async Task CrossTenantCreateIsForbiddenAndTenantBStoreUnchanged()
    {
        await using TestHostShell app = new(TimeProvider);
        TwoTenantFixture fixture = await RegisterTwoTenantTransmittersAsync(app).ConfigureAwait(false);
        using VerifierKeyMaterial _a = fixture.TenantA;
        using VerifierKeyMaterial _b = fixture.TenantB;

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string tenantBSegment = fixture.TenantB.Registration.TenantId.Value;
        Uri tenantBStreamUrl = new(host.HttpBaseAddress!, $"/connect/{tenantBSegment}/ssf/stream");

        using HttpResponseMessage response = await SendAsync(
            http, HttpMethod.Post, tenantBStreamUrl, body: string.Empty, token: TenantAToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        AssertCrossTenantDenial(response, body, fixture);
        Assert.HasCount(1, fixture.StreamsByTenant[tenantBSegment],
            "A cross-tenant create must never reach tenant B's store.");
    }


    /// <summary>
    /// Every other Stream Management operation (update, replace, delete, status read, status
    /// update, subject add, subject remove and verify) sent cross-tenant is 403, and tenant B's
    /// stream is untouched by the write operations among them.
    /// </summary>
    [TestMethod]
    public async Task CrossTenantWriteAndControlOperationsAreForbiddenAndStoreUnchanged()
    {
        await using TestHostShell app = new(TimeProvider);
        TwoTenantFixture fixture = await RegisterTwoTenantTransmittersAsync(app).ConfigureAwait(false);
        using VerifierKeyMaterial _a = fixture.TenantA;
        using VerifierKeyMaterial _b = fixture.TenantB;

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string tenantBSegment = fixture.TenantB.Registration.TenantId.Value;
        Uri streamUrl = new(host.HttpBaseAddress!, $"/connect/{tenantBSegment}/ssf/stream");
        Uri statusUrl = new(host.HttpBaseAddress!, $"/connect/{tenantBSegment}/ssf/status");
        Uri addSubjectUrl = new(host.HttpBaseAddress!, $"/connect/{tenantBSegment}/ssf/subjects/add");
        Uri removeSubjectUrl = new(host.HttpBaseAddress!, $"/connect/{tenantBSegment}/ssf/subjects/remove");
        Uri verifyUrl = new(host.HttpBaseAddress!, $"/connect/{tenantBSegment}/ssf/verify");
        string streamId = fixture.TenantBStreamId;

        await AssertCrossTenantForbiddenAsync(http, HttpMethod.Patch, streamUrl,
            $$"""{"stream_id":"{{streamId}}","description":"attacker"}""", fixture);
        await AssertCrossTenantForbiddenAsync(http, HttpMethod.Put, streamUrl,
            $$"""{"stream_id":"{{streamId}}","description":"attacker"}""", fixture);
        await AssertCrossTenantForbiddenAsync(http, HttpMethod.Delete,
            new Uri($"{streamUrl}?stream_id={streamId}"), body: null, fixture);
        await AssertCrossTenantForbiddenAsync(http, HttpMethod.Get,
            new Uri($"{statusUrl}?stream_id={streamId}"), body: null, fixture);
        await AssertCrossTenantForbiddenAsync(http, HttpMethod.Post, statusUrl,
            $$"""{"stream_id":"{{streamId}}","status":"paused"}""", fixture);
        await AssertCrossTenantForbiddenAsync(http, HttpMethod.Post, addSubjectUrl,
            $$$"""{"stream_id":"{{{streamId}}}","subject":{"format":"email","email":"attacker@example.com"}}""", fixture);
        await AssertCrossTenantForbiddenAsync(http, HttpMethod.Post, removeSubjectUrl,
            $$$"""{"stream_id":"{{{streamId}}}","subject":{"format":"email","email":"attacker@example.com"}}""", fixture);
        await AssertCrossTenantForbiddenAsync(http, HttpMethod.Post, verifyUrl,
            $$"""{"stream_id":"{{streamId}}","state":"attacker-probe"}""", fixture);

        SsfStreamConfiguration afterAllAttempts = fixture.StreamsByTenant[tenantBSegment][streamId];
        Assert.IsNull(afterAllAttempts.Description,
            "A cross-tenant PATCH/PUT must never write the attacker's description into tenant B's stream.");
        Assert.HasCount(1, fixture.StreamsByTenant[tenantBSegment],
            "A cross-tenant delete must not remove tenant B's stream.");

        Assert.IsTrue(SsfStreamStatusValues.IsEnabled(fixture.StatusByTenant[tenantBSegment][streamId].Status),
            "A cross-tenant status update (pause) must never reach tenant B's status store.");
        Assert.AreEqual(0, fixture.Calls.AddSubjectCallCount,
            "A cross-tenant subject add must be refused before the store delegate runs.");
        Assert.AreEqual(0, fixture.Calls.RemoveSubjectCallCount,
            "A cross-tenant subject remove must be refused before the store delegate runs.");
        Assert.AreEqual(0, fixture.Calls.VerifyCallCount,
            "A cross-tenant verification trigger must be refused before the store delegate runs.");
    }


    private async Task AssertCrossTenantForbiddenAsync(HttpClient http, HttpMethod method, Uri url, string? body, TwoTenantFixture fixture)
    {
        using HttpResponseMessage response = await SendAsync(http, method, url, body, token: TenantAToken)
            .ConfigureAwait(false);
        string responseBody = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        AssertCrossTenantDenial(response, responseBody, fixture);
    }


    /// <summary>
    /// The SSF 1.0 §8-3 cross-tenant denial shape every cross-tenant request shares: 403 with
    /// the exact <c>access_denied</c> error member (never <c>invalid_scope</c>), no
    /// <c>WWW-Authenticate</c> challenge, and no JSON string value anywhere in the parsed body
    /// naming tenant B's tenant id, client id or stream id.
    /// </summary>
    private static void AssertCrossTenantDenial(HttpResponseMessage response, string body, TwoTenantFixture fixture)
    {
        Assert.AreEqual(403, (int)response.StatusCode, body);
        Assert.IsFalse(response.Headers.Contains(WellKnownHttpHeaderNames.WwwAuthenticate),
            "SSF 1.0 §8-3: a tenant-authority denial is a plain 403, never a bearer challenge.");

        (string error, string _) = OAuthErrorAssertions.ReadOAuthErrorBody(body);
        Assert.AreEqual(OAuthErrors.AccessDenied, error,
            "SSF 1.0 §8.1.1.1's 403 rows map a tenant-authority denial to access_denied, never invalid_scope.");

        AssertNoIdentifierLeaked(
            body,
            fixture.TenantB.Registration.TenantId.Value,
            fixture.TenantB.Registration.ClientId,
            fixture.TenantBStreamId);
    }


    /// <summary>
    /// Asserts that no JSON string VALUE anywhere in <paramref name="body"/> equals or contains
    /// any of <paramref name="forbiddenIdentifiers"/> — parsed structurally so a JSON-escaped
    /// occurrence (<c>https:\/\/…</c>) is caught the same as a literal one, unlike a raw
    /// substring search over the wire text.
    /// </summary>
    private static void AssertNoIdentifierLeaked(string body, params ReadOnlySpan<string> forbiddenIdentifiers)
    {
        if(string.IsNullOrEmpty(body))
        {
            return;
        }

        using JsonDocument document = JsonDocument.Parse(body);
        foreach(string identifier in forbiddenIdentifiers)
        {
            AssertNoJsonStringContains(document.RootElement, identifier);
        }
    }


    private static void AssertNoJsonStringContains(JsonElement element, string forbiddenIdentifier)
    {
        switch(element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach(JsonProperty property in element.EnumerateObject())
                {
                    AssertNoJsonStringContains(property.Value, forbiddenIdentifier);
                }

                break;

            case JsonValueKind.Array:
                foreach(JsonElement item in element.EnumerateArray())
                {
                    AssertNoJsonStringContains(item, forbiddenIdentifier);
                }

                break;

            case JsonValueKind.String:
                Assert.DoesNotContain(forbiddenIdentifier, element.GetString()!, StringComparison.Ordinal,
                    $"The response body must not name '{forbiddenIdentifier}'.");

                break;
        }
    }


    /// <summary>
    /// A stream that exists on tenant A but that the decision seam reports as not available to
    /// this caller (SSF 1.0 §8.1.3's "no Event Stream ... for this Event Receiver" shape): GET
    /// with that <c>stream_id</c> answers 404, distinct from the tenant-mismatch 403.
    /// </summary>
    [TestMethod]
    public async Task StreamNotAvailableToReceiverAnswers404()
    {
        await using TestHostShell app = new(TimeProvider);
        TwoTenantFixture fixture = await RegisterTwoTenantTransmittersAsync(app).ConfigureAwait(false);
        using VerifierKeyMaterial _a = fixture.TenantA;
        using VerifierKeyMaterial _b = fixture.TenantB;

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string tenantASegment = fixture.TenantA.Registration.TenantId.Value;
        Uri streamUrl = new(host.HttpBaseAddress!, $"/connect/{tenantASegment}/ssf/stream");
        Uri statusUrl = new(host.HttpBaseAddress!, $"/connect/{tenantASegment}/ssf/status");

        //Read (§8.1.1.2), status read (§8.1.2.1) and delete (§8.1.1.5) each name the hidden
        //stream and each answer 404 identically to an unknown stream id.
        using HttpResponseMessage readResponse = await SendAsync(
            http, HttpMethod.Get, new Uri($"{streamUrl}?stream_id={fixture.HiddenStreamId}"), body: null, token: TenantAToken)
            .ConfigureAwait(false);
        Assert.AreEqual(404, (int)readResponse.StatusCode);

        using HttpResponseMessage statusResponse = await SendAsync(
            http, HttpMethod.Get, new Uri($"{statusUrl}?stream_id={fixture.HiddenStreamId}"), body: null, token: TenantAToken)
            .ConfigureAwait(false);
        Assert.AreEqual(404, (int)statusResponse.StatusCode);

        using HttpResponseMessage deleteResponse = await SendAsync(
            http, HttpMethod.Delete, new Uri($"{streamUrl}?stream_id={fixture.HiddenStreamId}"), body: null, token: TenantAToken)
            .ConfigureAwait(false);
        Assert.AreEqual(404, (int)deleteResponse.StatusCode);

        //§8.1.1.3: update names the hidden stream in its BODY. The decision seam can only
        //refuse it because the endpoint extracts stream_id from the body before calling that
        //seam (SsfRequestEvaluation.StreamId) — the fixture denies StreamNotAvailableToReceiver
        //for UpdateStream by that extracted value, not by a query parameter.
        using HttpResponseMessage updateResponse = await SendAsync(
            http, HttpMethod.Patch, streamUrl,
            $$"""{"stream_id":"{{fixture.HiddenStreamId}}","description":"attacker"}""", token: TenantAToken)
            .ConfigureAwait(false);
        Assert.AreEqual(404, (int)updateResponse.StatusCode);

        Assert.IsTrue(fixture.StreamsByTenant[tenantASegment].ContainsKey(fixture.HiddenStreamId),
            "A stream the decision seam reports unavailable to the caller must never be deleted by that caller.");
        Assert.IsNull(fixture.StreamsByTenant[tenantASegment][fixture.HiddenStreamId].Description,
            "A stream the decision seam reports unavailable to the caller must never be updated by that caller.");
    }


    /// <summary>
    /// With the decision seam wired and bound per tenant, the caller's own-tenant create and read
    /// still succeed — the tenant check adds a denial path without disturbing an authorized
    /// caller's own operations.
    /// </summary>
    [TestMethod]
    public async Task OwnTenantOperationsStillSucceedWithTheDecisionSeamWired()
    {
        await using TestHostShell app = new(TimeProvider);
        TwoTenantFixture fixture = await RegisterTwoTenantTransmittersAsync(app).ConfigureAwait(false);
        using VerifierKeyMaterial _a = fixture.TenantA;
        using VerifierKeyMaterial _b = fixture.TenantB;

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string tenantASegment = fixture.TenantA.Registration.TenantId.Value;
        Uri streamUrl = new(host.HttpBaseAddress!, $"/connect/{tenantASegment}/ssf/stream");

        using HttpResponseMessage created = await SendAsync(
            http, HttpMethod.Post, streamUrl, body: string.Empty, token: TenantAToken).ConfigureAwait(false);
        string createdBody = await created.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, (int)created.StatusCode, createdBody);

        using HttpResponseMessage read = await SendAsync(
            http, HttpMethod.Get, new Uri($"{streamUrl}?stream_id={fixture.TenantAStreamId}"), body: null, token: TenantAToken)
            .ConfigureAwait(false);
        string readBody = await read.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)read.StatusCode, readBody);
    }


    /// <summary>
    /// Two Receivers on ONE tenant, each with its own stream: Receiver 1's list read returns
    /// only its own stream, and every operation naming Receiver 2's stream id — update, replace,
    /// status update, subject add, subject remove, verify, delete and status read — answers 404
    /// to Receiver 1, leaving Receiver 2's stream unchanged (SSF 1.0 §8-3).
    /// </summary>
    [TestMethod]
    public async Task SameTenantDifferentReceiverStreamsAreIsolated()
    {
        await using TestHostShell app = new(TimeProvider);
        SameTenantFixture fixture = await RegisterSameTenantTwoReceiversAsync(app).ConfigureAwait(false);
        using VerifierKeyMaterial _ = fixture.Tenant;

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        HttpClient http = host.SharedHttpClient!;
        string segment = fixture.Tenant.Registration.TenantId.Value;
        Uri streamUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/ssf/stream");
        Uri statusUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/ssf/status");
        Uri addSubjectUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/ssf/subjects/add");
        Uri removeSubjectUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/ssf/subjects/remove");
        Uri verifyUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/ssf/verify");

        //§8.1.1.2-2: Receiver 1's list read returns the stream configurations available to
        //Receiver 1 only.
        using HttpResponseMessage list = await SendAsync(http, HttpMethod.Get, streamUrl, body: null, token: Receiver1Token)
            .ConfigureAwait(false);
        string listBody = await list.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)list.StatusCode, listBody);
        using JsonDocument listDocument = JsonDocument.Parse(listBody);
        Assert.AreEqual(1, listDocument.RootElement.GetArrayLength());
        Assert.AreEqual(
            fixture.Receiver1StreamId,
            listDocument.RootElement[0].GetProperty(SsfStreamConfigParameterNames.StreamId).GetString());

        //Every operation naming Receiver 2's stream id answers 404 to Receiver 1.
        string foreignStreamId = fixture.Receiver2StreamId;
        await AssertReceiverScopedNotFoundAsync(http, HttpMethod.Patch, streamUrl,
            $$"""{"stream_id":"{{foreignStreamId}}","description":"attacker"}""");
        await AssertReceiverScopedNotFoundAsync(http, HttpMethod.Put, streamUrl,
            $$"""{"stream_id":"{{foreignStreamId}}","description":"attacker"}""");
        await AssertReceiverScopedNotFoundAsync(http, HttpMethod.Get,
            new Uri($"{statusUrl}?stream_id={foreignStreamId}"), body: null);
        await AssertReceiverScopedNotFoundAsync(http, HttpMethod.Post, statusUrl,
            $$"""{"stream_id":"{{foreignStreamId}}","status":"paused"}""");
        await AssertReceiverScopedNotFoundAsync(http, HttpMethod.Post, addSubjectUrl,
            $$$"""{"stream_id":"{{{foreignStreamId}}}","subject":{"format":"email","email":"attacker@example.com"}}""");
        await AssertReceiverScopedNotFoundAsync(http, HttpMethod.Post, removeSubjectUrl,
            $$$"""{"stream_id":"{{{foreignStreamId}}}","subject":{"format":"email","email":"attacker@example.com"}}""");
        await AssertReceiverScopedNotFoundAsync(http, HttpMethod.Post, verifyUrl,
            $$"""{"stream_id":"{{foreignStreamId}}","state":"attacker-probe"}""");
        await AssertReceiverScopedNotFoundAsync(http, HttpMethod.Delete,
            new Uri($"{streamUrl}?stream_id={foreignStreamId}"), body: null);

        SsfStreamConfiguration receiver2StreamAfter = fixture.StreamsByReceiver[fixture.Receiver2Id][foreignStreamId];
        Assert.IsNull(receiver2StreamAfter.Description,
            "Receiver 1's cross-Receiver attempts must never write into Receiver 2's stream.");
        Assert.HasCount(1, fixture.StreamsByReceiver[fixture.Receiver2Id],
            "Receiver 1's cross-Receiver delete must not remove Receiver 2's stream.");
    }


    /// <summary>
    /// Sends <paramref name="method"/> to <paramref name="url"/> as Receiver 1 and asserts 404 —
    /// the shape every operation naming Receiver 2's stream id takes (SSF 1.0 §8-3).
    /// </summary>
    private async Task AssertReceiverScopedNotFoundAsync(HttpClient http, HttpMethod method, Uri url, string? body)
    {
        using HttpResponseMessage response = await SendAsync(http, method, url, body, token: Receiver1Token)
            .ConfigureAwait(false);
        Assert.AreEqual(404, (int)response.StatusCode);
    }


    /// <summary>
    /// Pins <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8.1.1.1">
    /// SSF 1.0 §8.1.1.1</see>'s error table outside its own vocabulary: a Stream Management API
    /// request whose <c>AuthorizeSsfRequestAsync</c> seam throws answers 500 with the library's
    /// OAuth <c>server_error</c> body and never reaches the store.
    /// </summary>
    [TestMethod]
    public async Task ThrowingAuthorizationSeamAnswersServerErrorWithNoStoreCall()
    {
        await using TestHostShell app = new(TimeProvider);
        (Dictionary<string, SsfStreamConfiguration> store, VerifierKeyMaterial material) = await RegisterTransmitterAsync(app).ConfigureAwait(false);
        using VerifierKeyMaterial _ = material;

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.AuthorizeSsfRequestAsync = static (evaluation, registration, context, ct) =>
                throw new InvalidOperationException("the authorization seam's own fault, unrelated to this request");
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri streamUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/ssf/stream");

        using HttpResponseMessage response = await SendAsync(
            host.SharedHttpClient!, HttpMethod.Post, streamUrl, body: string.Empty, token: null).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(500, (int)response.StatusCode, body);
        (string error, string _) = OAuthErrorAssertions.ReadOAuthErrorBody(body);
        Assert.AreEqual(OAuthErrors.ServerError, error);
        Assert.IsEmpty(store, "A throwing authorization seam must never reach the store.");
    }


    /// <summary>
    /// A seam that returns a <see langword="null"/> <see cref="SsfRequestDecision"/> is treated
    /// as a denial with reason <see cref="SsfRequestDenialReason.NotAuthorizedForTenant"/>,
    /// never a fault reaching the client.
    /// </summary>
    [TestMethod]
    public async Task NullAuthorizationDecisionIsTreatedAsDenied()
    {
        await using TestHostShell app = new(TimeProvider);
        (Dictionary<string, SsfStreamConfiguration> store, VerifierKeyMaterial material) = await RegisterTransmitterAsync(app).ConfigureAwait(false);
        using VerifierKeyMaterial _ = material;

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.AuthorizeSsfRequestAsync = static (evaluation, registration, context, ct) =>
                ValueTask.FromResult<SsfRequestDecision>(null!);
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri streamUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/ssf/stream");

        using HttpResponseMessage response = await SendAsync(
            host.SharedHttpClient!, HttpMethod.Post, streamUrl, body: string.Empty, token: null).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(403, (int)response.StatusCode, body);
        (string error, string _) = OAuthErrorAssertions.ReadOAuthErrorBody(body);
        Assert.AreEqual(OAuthErrors.AccessDenied, error);
        Assert.IsEmpty(store, "A null authorization decision must never reach the store.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-8-3">SSF 1.0 §8</see>
    /// requires this authorization to associate a Receiver with the stream IDs it may access;
    /// a Receiver with no identifier binds nothing. A seam that permits the caller but binds it
    /// to a <see cref="SsfReceiver"/> whose <see cref="SsfReceiver.Id"/> is whitespace is treated
    /// as a denial with reason <see cref="SsfRequestDenialReason.NotAuthorizedForTenant"/>, never
    /// a request that reaches the store.
    /// </summary>
    [TestMethod]
    public async Task PermitWithWhitespaceReceiverIdIsTreatedAsDenied()
    {
        await using TestHostShell app = new(TimeProvider);
        (Dictionary<string, SsfStreamConfiguration> store, VerifierKeyMaterial material) = await RegisterTransmitterAsync(app).ConfigureAwait(false);
        using VerifierKeyMaterial _ = material;

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.AuthorizeSsfRequestAsync = static (evaluation, registration, context, ct) =>
                ValueTask.FromResult(SsfRequestDecision.Permit(new SsfReceiver { Id = " " }));
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri streamUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/ssf/stream");

        using HttpResponseMessage response = await SendAsync(
            host.SharedHttpClient!, HttpMethod.Post, streamUrl, body: string.Empty, token: null).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(403, (int)response.StatusCode, body);
        (string error, string _) = OAuthErrorAssertions.ReadOAuthErrorBody(body);
        Assert.AreEqual(OAuthErrors.AccessDenied, error);
        Assert.IsEmpty(store, "A permit with no Receiver identifier must never reach the store.");
    }


    /// <summary>Carries a same-tenant fixture's two Receivers, their seeded stream ids and per-Receiver store.</summary>
    private sealed record SameTenantFixture
    {
        /// <summary>The shared tenant's registration and key material.</summary>
        public required VerifierKeyMaterial Tenant { get; init; }

        /// <summary>Receiver 1's host-assigned identifier.</summary>
        public required string Receiver1Id { get; init; }

        /// <summary>Receiver 2's host-assigned identifier.</summary>
        public required string Receiver2Id { get; init; }

        /// <summary>The id of the stream seeded for Receiver 1.</summary>
        public required string Receiver1StreamId { get; init; }

        /// <summary>The id of the stream seeded for Receiver 2.</summary>
        public required string Receiver2StreamId { get; init; }

        /// <summary>The stores, keyed by <see cref="SsfReceiver.Id"/>, the wired delegates read and write.</summary>
        public required Dictionary<string, Dictionary<string, SsfStreamConfiguration>> StreamsByReceiver { get; init; }
    }


    /// <summary>
    /// Registers one transmitter-capable tenant with two Receivers, each with its own seeded
    /// stream, and wires store delegates keyed by <c>receiver.Id</c> — the shape SSF 1.0 §8-3
    /// requires so that one Receiver's operations never reach the other's stream data.
    /// </summary>
    private static async Task<SameTenantFixture> RegisterSameTenantTwoReceiversAsync(TestHostShell app)
    {
        VerifierKeyMaterial tenant = await app.RegisterClientAsync(
            "https://transmitter-same-tenant.example.com",
            new Uri("https://transmitter-same-tenant.example.com"),
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.SsfTransmitter,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)).ConfigureAwait(false);

        const string receiver1Id = "receiver-1";
        const string receiver2Id = "receiver-2";
        string receiver1StreamId = Guid.NewGuid().ToString("N");
        string receiver2StreamId = Guid.NewGuid().ToString("N");

        Dictionary<string, Dictionary<string, SsfStreamConfiguration>> streamsByReceiver = new(StringComparer.Ordinal)
        {
            [receiver1Id] = new(StringComparer.Ordinal) { [receiver1StreamId] = SeedStream(receiver1StreamId) },
            [receiver2Id] = new(StringComparer.Ordinal) { [receiver2StreamId] = SeedStream(receiver2StreamId) }
        };

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultSsfJsonParsing();

            candidateIntegration.ContributeSsfTransmitterMetadataAsync = static (_, _, _) =>
                ValueTask.FromResult(new SsfTransmitterMetadataContribution
                {
                    DeliveryMethodsSupported = [SsfDeliveryMethods.PollHttp]
                });

            candidateIntegration.AuthorizeSsfRequestAsync = (evaluation, registration, context, ct) =>
            {
                if(!evaluation.Request.Headers.TryGetSingle(WellKnownHttpHeaderNames.Authorization, out string? header)
                    || header is null)
                {

                    return ValueTask.FromResult(SsfRequestDecision.Deny(SsfRequestDenialReason.AuthenticationRequired));
                }

                string? receiverId = header switch
                {
                    Receiver1BearerHeader => receiver1Id,
                    Receiver2BearerHeader => receiver2Id,
                    _ => null
                };

                return receiverId is null
                    ? ValueTask.FromResult(SsfRequestDecision.Deny(SsfRequestDenialReason.AuthenticationRequired))
                    : ValueTask.FromResult(SsfRequestDecision.Permit(new SsfReceiver { Id = receiverId }));
            };

            candidateIntegration.CreateSsfStreamAsync = (request, registration, receiver, context, ct) =>
            {
                Dictionary<string, SsfStreamConfiguration> streams = StreamsForReceiver(streamsByReceiver, receiver);
                string streamId = Guid.NewGuid().ToString("N");
                SsfStreamConfiguration stream = SeedStream(streamId) with { Description = request.Description };
                streams[streamId] = stream;

                return ValueTask.FromResult(SsfStreamWriteResult.Success(stream));
            };

            candidateIntegration.ReadSsfStreamsAsync = (streamId, registration, receiver, context, ct) =>
            {
                Dictionary<string, SsfStreamConfiguration> streams = StreamsForReceiver(streamsByReceiver, receiver);
                if(streamId is null)
                {

                    return ValueTask.FromResult<IReadOnlyList<SsfStreamConfiguration>?>([.. streams.Values]);
                }

                return ValueTask.FromResult<IReadOnlyList<SsfStreamConfiguration>?>(
                    streams.TryGetValue(streamId, out SsfStreamConfiguration? stream) ? [stream] : null);
            };

            candidateIntegration.UpdateSsfStreamAsync = (request, registration, receiver, context, ct) =>
            {
                Dictionary<string, SsfStreamConfiguration> streams = StreamsForReceiver(streamsByReceiver, receiver);
                if(!streams.TryGetValue(request.StreamId, out SsfStreamConfiguration? existing))
                {

                    return ValueTask.FromResult(SsfStreamWriteResult.Failed(SsfStreamWriteOutcome.NotFound));
                }

                SsfStreamConfiguration updated = existing with { Description = request.Description ?? existing.Description };
                streams[request.StreamId] = updated;

                return ValueTask.FromResult(SsfStreamWriteResult.Success(updated));
            };

            candidateIntegration.ReplaceSsfStreamAsync = (request, registration, receiver, context, ct) =>
            {
                Dictionary<string, SsfStreamConfiguration> streams = StreamsForReceiver(streamsByReceiver, receiver);
                if(!streams.TryGetValue(request.StreamId, out SsfStreamConfiguration? existing))
                {

                    return ValueTask.FromResult(SsfStreamWriteResult.Failed(SsfStreamWriteOutcome.NotFound));
                }

                SsfStreamConfiguration replaced = existing with { Description = request.Description };
                streams[request.StreamId] = replaced;

                return ValueTask.FromResult(SsfStreamWriteResult.Success(replaced));
            };

            candidateIntegration.DeleteSsfStreamAsync = (streamId, registration, receiver, context, ct) =>
            {
                Dictionary<string, SsfStreamConfiguration> streams = StreamsForReceiver(streamsByReceiver, receiver);

                return ValueTask.FromResult(streams.Remove(streamId)
                    ? SsfStreamWriteOutcome.Success
                    : SsfStreamWriteOutcome.NotFound);
            };

            candidateIntegration.ReadSsfStreamStatusAsync = (streamId, registration, receiver, context, ct) =>
            {
                Dictionary<string, SsfStreamConfiguration> streams = StreamsForReceiver(streamsByReceiver, receiver);

                return ValueTask.FromResult(streams.ContainsKey(streamId) ? SeedStatus(streamId) : null);
            };

            candidateIntegration.UpdateSsfStreamStatusAsync = (requested, registration, receiver, context, ct) =>
            {
                Dictionary<string, SsfStreamConfiguration> streams = StreamsForReceiver(streamsByReceiver, receiver);

                return ValueTask.FromResult(streams.ContainsKey(requested.StreamId)
                    ? SsfStreamStatusResult.Success(requested)
                    : SsfStreamStatusResult.Failed(SsfStreamOperationOutcome.NotFound));
            };

            candidateIntegration.AddSsfSubjectAsync = (request, registration, receiver, context, ct) =>
            {
                Dictionary<string, SsfStreamConfiguration> streams = StreamsForReceiver(streamsByReceiver, receiver);

                return ValueTask.FromResult(streams.ContainsKey(request.StreamId)
                    ? SsfStreamOperationOutcome.Success
                    : SsfStreamOperationOutcome.NotFound);
            };

            candidateIntegration.RemoveSsfSubjectAsync = (request, registration, receiver, context, ct) =>
            {
                Dictionary<string, SsfStreamConfiguration> streams = StreamsForReceiver(streamsByReceiver, receiver);

                return ValueTask.FromResult(streams.ContainsKey(request.StreamId)
                    ? SsfStreamOperationOutcome.Success
                    : SsfStreamOperationOutcome.NotFound);
            };

            candidateIntegration.TriggerSsfVerificationAsync = (request, registration, receiver, context, ct) =>
            {
                Dictionary<string, SsfStreamConfiguration> streams = StreamsForReceiver(streamsByReceiver, receiver);

                return ValueTask.FromResult(streams.ContainsKey(request.StreamId)
                    ? SsfStreamOperationOutcome.Success
                    : SsfStreamOperationOutcome.NotFound);
            };
        }).ConfigureAwait(false);

        return new SameTenantFixture
        {
            Tenant = tenant,
            Receiver1Id = receiver1Id,
            Receiver2Id = receiver2Id,
            Receiver1StreamId = receiver1StreamId,
            Receiver2StreamId = receiver2StreamId,
            StreamsByReceiver = streamsByReceiver
        };
    }


    private static Dictionary<string, SsfStreamConfiguration> StreamsForReceiver(
        Dictionary<string, Dictionary<string, SsfStreamConfiguration>> byReceiver, SsfReceiver receiver) =>
        byReceiver.TryGetValue(receiver.Id, out Dictionary<string, SsfStreamConfiguration>? streams)
            ? streams
            : byReceiver[receiver.Id] = new(StringComparer.Ordinal);


    /// <summary>Carries a two-tenant fixture's registrations, seeded stream ids and shared per-tenant store.</summary>
    private sealed record TwoTenantFixture
    {
        /// <summary>Tenant A's registration and key material.</summary>
        public required VerifierKeyMaterial TenantA { get; init; }

        /// <summary>Tenant B's registration and key material.</summary>
        public required VerifierKeyMaterial TenantB { get; init; }

        /// <summary>The id of the stream seeded on tenant A.</summary>
        public required string TenantAStreamId { get; init; }

        /// <summary>The id of the stream seeded on tenant B.</summary>
        public required string TenantBStreamId { get; init; }

        /// <summary>The id of a second tenant-A stream the decision seam reports as unavailable to the caller.</summary>
        public required string HiddenStreamId { get; init; }

        /// <summary>The stores, keyed by <see cref="TenantId.Value"/>, the wired delegates read and write.</summary>
        public required Dictionary<string, Dictionary<string, SsfStreamConfiguration>> StreamsByTenant { get; init; }

        /// <summary>The status stores, keyed by <see cref="TenantId.Value"/>, the wired status delegates read and write.</summary>
        public required Dictionary<string, Dictionary<string, SsfStreamStatus>> StatusByTenant { get; init; }

        /// <summary>How many times a cross-tenant request reached the subject/verification store delegates.</summary>
        public required SsfStoreCallCounts Calls { get; init; }
    }


    /// <summary>
    /// Counts calls into the subject and verification store delegates, so a cross-tenant test
    /// can assert those delegates never ran rather than only asserting the response status.
    /// </summary>
    private sealed class SsfStoreCallCounts
    {
        /// <summary>How many times <c>AddSsfSubjectAsync</c> ran.</summary>
        public int AddSubjectCallCount { get; private set; }

        /// <summary>How many times <c>RemoveSsfSubjectAsync</c> ran.</summary>
        public int RemoveSubjectCallCount { get; private set; }

        /// <summary>How many times <c>TriggerSsfVerificationAsync</c> ran.</summary>
        public int VerifyCallCount { get; private set; }


        /// <summary>Records one call to <c>AddSsfSubjectAsync</c>.</summary>
        public void RecordAddSubjectCall() => AddSubjectCallCount++;

        /// <summary>Records one call to <c>RemoveSsfSubjectAsync</c>.</summary>
        public void RecordRemoveSubjectCall() => RemoveSubjectCallCount++;

        /// <summary>Records one call to <c>TriggerSsfVerificationAsync</c>.</summary>
        public void RecordVerifyCall() => VerifyCallCount++;
    }


    /// <summary>
    /// Registers two transmitter-capable tenants on the same host, each seeded with its own
    /// stream, and wires shared store delegates keyed by <c>registration.TenantId</c> plus a
    /// decision seam that binds one bearer token to tenant A and a distinct one to tenant B —
    /// permitting a caller only on its own tenant, and denying tenant A's own
    /// <see cref="TwoTenantFixture.HiddenStreamId"/> as unavailable to the caller (SSF 1.0 §8-3).
    /// </summary>
    private static async Task<TwoTenantFixture> RegisterTwoTenantTransmittersAsync(TestHostShell app)
    {
        VerifierKeyMaterial tenantA = await app.RegisterClientAsync(
            "https://transmitter-a.example.com",
            new Uri("https://transmitter-a.example.com"),
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.SsfTransmitter,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)).ConfigureAwait(false);

        VerifierKeyMaterial tenantB = await app.RegisterClientAsync(
            "https://transmitter-b.example.com",
            new Uri("https://transmitter-b.example.com"),
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.SsfTransmitter,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)).ConfigureAwait(false);

        string tenantAStreamId = Guid.NewGuid().ToString("N");
        string tenantBStreamId = Guid.NewGuid().ToString("N");
        string hiddenStreamId = Guid.NewGuid().ToString("N");
        string tenantASegment = tenantA.Registration.TenantId.Value;
        string tenantBSegment = tenantB.Registration.TenantId.Value;

        Dictionary<string, Dictionary<string, SsfStreamConfiguration>> streamsByTenant = new(StringComparer.Ordinal)
        {
            [tenantASegment] = new(StringComparer.Ordinal)
            {
                [tenantAStreamId] = SeedStream(tenantAStreamId),
                [hiddenStreamId] = SeedStream(hiddenStreamId)
            },
            [tenantBSegment] = new(StringComparer.Ordinal)
            {
                [tenantBStreamId] = SeedStream(tenantBStreamId)
            }
        };

        Dictionary<string, Dictionary<string, SsfStreamStatus>> statusByTenant = new(StringComparer.Ordinal)
        {
            [tenantASegment] = new(StringComparer.Ordinal)
            {
                [tenantAStreamId] = SeedStatus(tenantAStreamId),
                [hiddenStreamId] = SeedStatus(hiddenStreamId)
            },
            [tenantBSegment] = new(StringComparer.Ordinal)
            {
                [tenantBStreamId] = SeedStatus(tenantBStreamId)
            }
        };

        SsfStoreCallCounts calls = new();

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultSsfJsonParsing();

            candidateIntegration.ContributeSsfTransmitterMetadataAsync = static (_, _, _) =>
                ValueTask.FromResult(new SsfTransmitterMetadataContribution
                {
                    DeliveryMethodsSupported = [SsfDeliveryMethods.PollHttp]
                });

            candidateIntegration.AuthorizeSsfRequestAsync = (evaluation, registration, context, ct) =>
            {
                if(!evaluation.Request.Headers.TryGetSingle(WellKnownHttpHeaderNames.Authorization, out string? header)
                    || header is null)
                {

                    return ValueTask.FromResult(SsfRequestDecision.Deny(SsfRequestDenialReason.AuthenticationRequired));
                }

                string? boundTenant = header switch
                {
                    TenantABearerHeader => tenantASegment,
                    TenantBBearerHeader => tenantBSegment,
                    _ => null
                };
                if(boundTenant is null)
                {

                    return ValueTask.FromResult(SsfRequestDecision.Deny(SsfRequestDenialReason.AuthenticationRequired));
                }

                if(!string.Equals(boundTenant, evaluation.TenantId.Value, StringComparison.Ordinal))
                {
                    //A host description naming both tenants — the cross-tenant tests prove it
                    //never reaches the wire, only the dispatch Activity.
                    return ValueTask.FromResult(SsfRequestDecision.Deny(
                        SsfRequestDenialReason.NotAuthorizedForTenant,
                        $"caller bound to tenant {boundTenant} has no authority on tenant {evaluation.TenantId.Value}"));
                }

                //§8.1.1.2, §8.1.1.3, §8.1.1.5 and §8.1.2.1: the hidden stream exists on tenant A
                //but the decision seam reports it unavailable to this caller for every operation
                //that names a stream ahead of the store, not only a read — UpdateStream's
                //stream_id rides the body, so the seam can only see it because the endpoint
                //extracts it before calling this seam.
                bool namesHiddenStream = string.Equals(evaluation.StreamId, hiddenStreamId, StringComparison.Ordinal)
                    && evaluation.Operation is SsfRequestOperation.ReadStream or SsfRequestOperation.DeleteStream
                        or SsfRequestOperation.ReadStatus or SsfRequestOperation.UpdateStream;
                if(namesHiddenStream)
                {
                    return ValueTask.FromResult(SsfRequestDecision.Deny(
                        SsfRequestDenialReason.StreamNotAvailableToReceiver,
                        $"stream {hiddenStreamId} is not available to this Receiver"));
                }

                return ValueTask.FromResult(SsfRequestDecision.Permit(new SsfReceiver { Id = boundTenant + "-receiver" }));
            };

            candidateIntegration.CreateSsfStreamAsync = (request, registration, receiver, context, ct) =>
            {
                Dictionary<string, SsfStreamConfiguration> streams = StreamsFor(streamsByTenant, registration);
                string streamId = Guid.NewGuid().ToString("N");
                SsfStreamConfiguration stream = SeedStream(streamId) with { Description = request.Description };
                streams[streamId] = stream;

                return ValueTask.FromResult(SsfStreamWriteResult.Success(stream));
            };

            candidateIntegration.ReadSsfStreamsAsync = (streamId, registration, receiver, context, ct) =>
            {
                Dictionary<string, SsfStreamConfiguration> streams = StreamsFor(streamsByTenant, registration);
                if(streamId is null)
                {

                    return ValueTask.FromResult<IReadOnlyList<SsfStreamConfiguration>?>([.. streams.Values]);
                }

                return ValueTask.FromResult<IReadOnlyList<SsfStreamConfiguration>?>(
                    streams.TryGetValue(streamId, out SsfStreamConfiguration? stream) ? [stream] : null);
            };

            candidateIntegration.UpdateSsfStreamAsync = (request, registration, receiver, context, ct) =>
            {
                Dictionary<string, SsfStreamConfiguration> streams = StreamsFor(streamsByTenant, registration);
                if(!streams.TryGetValue(request.StreamId, out SsfStreamConfiguration? existing))
                {

                    return ValueTask.FromResult(SsfStreamWriteResult.Failed(SsfStreamWriteOutcome.NotFound));
                }

                SsfStreamConfiguration updated = existing with { Description = request.Description ?? existing.Description };
                streams[request.StreamId] = updated;

                return ValueTask.FromResult(SsfStreamWriteResult.Success(updated));
            };

            candidateIntegration.ReplaceSsfStreamAsync = (request, registration, receiver, context, ct) =>
            {
                Dictionary<string, SsfStreamConfiguration> streams = StreamsFor(streamsByTenant, registration);
                if(!streams.TryGetValue(request.StreamId, out SsfStreamConfiguration? existing))
                {

                    return ValueTask.FromResult(SsfStreamWriteResult.Failed(SsfStreamWriteOutcome.NotFound));
                }

                SsfStreamConfiguration replaced = existing with { Description = request.Description };
                streams[request.StreamId] = replaced;

                return ValueTask.FromResult(SsfStreamWriteResult.Success(replaced));
            };

            candidateIntegration.DeleteSsfStreamAsync = (streamId, registration, receiver, context, ct) =>
            {
                Dictionary<string, SsfStreamConfiguration> streams = StreamsFor(streamsByTenant, registration);
                Dictionary<string, SsfStreamStatus> statuses = StatusFor(statusByTenant, registration);
                _ = statuses.Remove(streamId);

                return ValueTask.FromResult(streams.Remove(streamId)
                    ? SsfStreamWriteOutcome.Success
                    : SsfStreamWriteOutcome.NotFound);
            };

            candidateIntegration.ReadSsfStreamStatusAsync = (streamId, registration, receiver, context, ct) =>
            {
                Dictionary<string, SsfStreamStatus> statuses = StatusFor(statusByTenant, registration);

                return ValueTask.FromResult(statuses.TryGetValue(streamId, out SsfStreamStatus? status) ? status : null);
            };

            candidateIntegration.UpdateSsfStreamStatusAsync = (requested, registration, receiver, context, ct) =>
            {
                Dictionary<string, SsfStreamStatus> statuses = StatusFor(statusByTenant, registration);
                if(!statuses.ContainsKey(requested.StreamId))
                {

                    return ValueTask.FromResult(SsfStreamStatusResult.Failed(SsfStreamOperationOutcome.NotFound));
                }

                statuses[requested.StreamId] = requested;

                return ValueTask.FromResult(SsfStreamStatusResult.Success(requested));
            };

            candidateIntegration.AddSsfSubjectAsync = (request, registration, receiver, context, ct) =>
            {
                calls.RecordAddSubjectCall();
                Dictionary<string, SsfStreamConfiguration> streams = StreamsFor(streamsByTenant, registration);

                return ValueTask.FromResult(streams.ContainsKey(request.StreamId)
                    ? SsfStreamOperationOutcome.Success
                    : SsfStreamOperationOutcome.NotFound);
            };

            candidateIntegration.RemoveSsfSubjectAsync = (request, registration, receiver, context, ct) =>
            {
                calls.RecordRemoveSubjectCall();
                Dictionary<string, SsfStreamConfiguration> streams = StreamsFor(streamsByTenant, registration);

                return ValueTask.FromResult(streams.ContainsKey(request.StreamId)
                    ? SsfStreamOperationOutcome.Success
                    : SsfStreamOperationOutcome.NotFound);
            };

            candidateIntegration.TriggerSsfVerificationAsync = (request, registration, receiver, context, ct) =>
            {
                calls.RecordVerifyCall();
                Dictionary<string, SsfStreamConfiguration> streams = StreamsFor(streamsByTenant, registration);

                return ValueTask.FromResult(streams.ContainsKey(request.StreamId)
                    ? SsfStreamOperationOutcome.Success
                    : SsfStreamOperationOutcome.NotFound);
            };
        }).ConfigureAwait(false);

        return new TwoTenantFixture
        {
            TenantA = tenantA,
            TenantB = tenantB,
            TenantAStreamId = tenantAStreamId,
            TenantBStreamId = tenantBStreamId,
            HiddenStreamId = hiddenStreamId,
            StreamsByTenant = streamsByTenant,
            StatusByTenant = statusByTenant,
            Calls = calls
        };
    }


    private static Dictionary<string, SsfStreamConfiguration> StreamsFor(
        Dictionary<string, Dictionary<string, SsfStreamConfiguration>> byTenant, ClientRecord registration) =>
        byTenant.TryGetValue(registration.TenantId.Value, out Dictionary<string, SsfStreamConfiguration>? streams)
            ? streams
            : byTenant[registration.TenantId.Value] = new(StringComparer.Ordinal);


    private static Dictionary<string, SsfStreamStatus> StatusFor(
        Dictionary<string, Dictionary<string, SsfStreamStatus>> byTenant, ClientRecord registration) =>
        byTenant.TryGetValue(registration.TenantId.Value, out Dictionary<string, SsfStreamStatus>? statuses)
            ? statuses
            : byTenant[registration.TenantId.Value] = new(StringComparer.Ordinal);


    private static SsfStreamConfiguration SeedStream(string streamId) =>
        new()
        {
            StreamId = streamId,
            Issuer = TransmitterIssuer,
            Audiences = [ReceiverAudience],
            Delivery = new SsfDeliveryConfiguration
            {
                Method = SsfDeliveryMethods.PollHttp,
                EndpointUrl = $"https://transmitter.example/ssf/poll/{streamId}"
            },
            EventsSupported = SupportedEvents,
            EventsDelivered = SupportedEvents
        };


    private static SsfStreamStatus SeedStatus(string streamId) =>
        new()
        {
            StreamId = streamId,
            Status = SsfStreamStatusValues.Enabled
        };


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
            _ = request.Headers.TryAddWithoutValidation(WellKnownHttpHeaderNames.Authorization, $"Bearer {token}");
        }

        return await http.SendAsync(request, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Registers a transmitter-capable client and wires the shipped default
    /// parsers plus a single-stream in-memory store behind the integration seams.
    /// Returns the store so tests can assert on persisted state, together with the
    /// registered client's key material.
    /// </summary>
    /// <param name="app">The test host shell.</param>
    /// <param name="wireAuthorizationSeam">
    /// When <see langword="true"/> (the default), wires a decision seam that permits every
    /// request — the fixture's default posture for tests that exercise store lifecycle rather
    /// than authorization. <see langword="false"/> leaves the seam unwired, so the Stream
    /// Management API candidates fail closed (SSF 1.0 §8-3).
    /// </param>
    private static async Task<(Dictionary<string, SsfStreamConfiguration> Store, VerifierKeyMaterial Material)> RegisterTransmitterAsync(
        TestHostShell app, bool wireAuthorizationSeam = true)
    {
        VerifierKeyMaterial material = await app.RegisterClientAsync(
            ClientId,
            new Uri(ClientId),
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.SsfTransmitter,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)).ConfigureAwait(false);

        Dictionary<string, SsfStreamConfiguration> store = new(StringComparer.Ordinal);
        Dictionary<string, SsfStreamStatus> statusByStream = new(StringComparer.Ordinal);
        HashSet<string> verificationRequested = new(StringComparer.Ordinal);

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultSsfJsonParsing();

            if(wireAuthorizationSeam)
            {
                //The fixture's default posture: every caller is permitted and bound to the
                //one fixed Receiver, so tests built on this helper exercise store lifecycle
                //rather than authorization (ScopeEnforcementOverHttpWire and the cross-tenant
                //tests wire their own seam instead).
                candidateIntegration.AuthorizeSsfRequestAsync = static (evaluation, registration, context, ct) =>
                    ValueTask.FromResult(SsfRequestDecision.Permit(SingleReceiver));
            }


            //A profile-conformant transmitter declares its delivery methods: CAEP
            //Interoperability Profile 1.0 §2.3.2 makes delivery_methods_supported a
            //MUST-include member the library cannot derive, so the discovery document
            //is refused without it. A deployment supplies the methods it operates.

            candidateIntegration.ContributeSsfTransmitterMetadataAsync = static (_, _, _) =>
                ValueTask.FromResult(new SsfTransmitterMetadataContribution
                {
                    DeliveryMethodsSupported = [SsfDeliveryMethods.PushHttp, SsfDeliveryMethods.PollHttp]
                });


            candidateIntegration.CreateSsfStreamAsync = (request, registration, receiver, context, ct) =>
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


            candidateIntegration.ReadSsfStreamsAsync = (streamId, registration, receiver, context, ct) =>
            {
                if(streamId is null)
                {

                    return ValueTask.FromResult<IReadOnlyList<SsfStreamConfiguration>?>([.. store.Values]);
                }

                return ValueTask.FromResult<IReadOnlyList<SsfStreamConfiguration>?>(
                    store.TryGetValue(streamId, out SsfStreamConfiguration? stream) ? [stream] : null);
            };


            candidateIntegration.UpdateSsfStreamAsync = (request, registration, receiver, context, ct) =>
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


            candidateIntegration.ReplaceSsfStreamAsync = (request, registration, receiver, context, ct) =>
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


            candidateIntegration.DeleteSsfStreamAsync = (streamId, registration, receiver, context, ct) =>
            {
                _ = statusByStream.Remove(streamId);

                return ValueTask.FromResult(store.Remove(streamId)
                    ? SsfStreamWriteOutcome.Success
                    : SsfStreamWriteOutcome.NotFound);
            };


            candidateIntegration.ReadSsfStreamStatusAsync = (streamId, registration, receiver, context, ct) =>
                ValueTask.FromResult(statusByStream.TryGetValue(streamId, out SsfStreamStatus? status) ? status : null);


            candidateIntegration.UpdateSsfStreamStatusAsync = (requested, registration, receiver, context, ct) =>
            {
                if(!statusByStream.ContainsKey(requested.StreamId))
                {

                    return ValueTask.FromResult(SsfStreamStatusResult.Failed(SsfStreamOperationOutcome.NotFound));
                }

                statusByStream[requested.StreamId] = requested;

                return ValueTask.FromResult(SsfStreamStatusResult.Success(requested));
            };


            candidateIntegration.AddSsfSubjectAsync = (request, registration, receiver, context, ct) =>
                ValueTask.FromResult(store.ContainsKey(request.StreamId)
                    ? SsfStreamOperationOutcome.Success
                    : SsfStreamOperationOutcome.NotFound);


            candidateIntegration.RemoveSsfSubjectAsync = (request, registration, receiver, context, ct) =>
                ValueTask.FromResult(store.ContainsKey(request.StreamId)
                    ? SsfStreamOperationOutcome.Success
                    : SsfStreamOperationOutcome.NotFound);


            //One verification per stream in this glue: the second request simulates
            //exceeding min_verification_interval (§8.1.4.2 → 429).

            candidateIntegration.TriggerSsfVerificationAsync = (request, registration, receiver, context, ct) =>
            {
                if(!store.ContainsKey(request.StreamId))
                {

                    return ValueTask.FromResult(SsfStreamOperationOutcome.NotFound);
                }

                return ValueTask.FromResult(verificationRequested.Add(request.StreamId)
                    ? SsfStreamOperationOutcome.Success
                    : SsfStreamOperationOutcome.TooManyRequests);
            };
        }).ConfigureAwait(false);

        return (store, material);
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
