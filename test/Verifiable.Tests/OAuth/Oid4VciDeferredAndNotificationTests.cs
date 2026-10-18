using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.ProtectedResource;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Metadata;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.WebFinger;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Server-side OID4VCI 1.0 §9 Deferred Credential Endpoint and §11 Notification Endpoint,
/// driven through the real dispatch pipeline. Both are protected endpoints sharing the
/// Credential Endpoint's bearer boundary; the library owns the wire — the §9.2 200/202 split,
/// the §11.2 204, and the §9.3 / §11.3 error mapping — while the application seams own the
/// deferred-transaction and <c>notification_id</c> stores only they can consult.
/// </summary>
[TestClass]
internal sealed class Oid4VciDeferredAndNotificationTests
{
    /// <summary>The MSTest-supplied per-test context.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>A fixed clock so issued artefacts are reproducible.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    /// <summary>The Wallet client identifier registered for these tests.</summary>
    private const string ClientId = "https://wallet.client.test";

    /// <summary>The base URI the registered client is reachable at.</summary>
    private static Uri ClientBaseUri { get; } = new("https://wallet.client.test");

    /// <summary>The End-User the deferred Credential is about — the grant-bound subject.</summary>
    private const string OfferSubject = "urn:uuid:end-user-42";

    /// <summary>The §9.1 transaction the Wallet polls for.</summary>
    private const string TransactionId = "8xLOxBtZp8";

    /// <summary>The §11.1 notification identifier a Credential Response returned.</summary>
    private const string NotificationId = "3fwe98js";

    /// <summary>The deferred-issued SD-JWT VC the seam returns; the library echoes it verbatim.</summary>
    private const string IssuedCredential =
        "eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJVbml2ZXJzaXR5RGVncmVlIn0.sig~WyJzYWx0IiwiZGVncmVlIiwiQmFjaGVsb3IiXQ~";

    /// <summary>
    /// The deferred/notification capabilities plus the grant + producer capabilities used to
    /// mint the access token the endpoints then validate.
    /// </summary>
    private static ImmutableHashSet<CapabilityIdentifier> EndpointCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant,
            WellKnownCapabilityIdentifiers.Oid4VciDeferredCredentialEndpoint,
            WellKnownCapabilityIdentifiers.Oid4VciNotificationEndpoint);


    /// <summary>
    /// §9.2: when the deferred issuance completed, the response is HTTP 200 with the §8.3
    /// <c>credentials</c> array and the optional <c>notification_id</c>, uncacheable. The seam
    /// receives the presented <c>transaction_id</c> and the validated access-token subject.
    /// </summary>
    [TestMethod]
    public async Task DeferredEndpointDeliversIssuedCredentials()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, EndpointCapabilities).ConfigureAwait(false);

        string? seenTransactionId = null;
        string? seenSubject = null;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveDeferredCredentialAsync =
                (transactionId, accessToken, registration, context, ct) =>
                {
                    seenTransactionId = transactionId;
                    seenSubject = accessToken.TryGetValue("sub", out object? s) ? s as string : null;

                    return ValueTask.FromResult(DeferredCredentialDecision.Issue(
                        [IssuedCredential], NotificationId));
                };
        }).ConfigureAwait(false);

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);
        ServerHttpResponse response = await DispatchDeferredAsync(
            host, material, "Bearer " + accessToken,
            $"{{\"transaction_id\":\"{TransactionId}\"}}").ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.AreEqual("application/json", response.ContentType);
        Assert.IsTrue(response.Headers.TryGetValue(WellKnownHttpHeaderNames.CacheControl, out string? cacheControl));
        Assert.AreEqual(WellKnownCacheControlValues.NoStore, cacheControl);

        using JsonDocument doc = JsonDocument.Parse(response.Body);
        JsonElement credentials = doc.RootElement.GetProperty("credentials");
        Assert.AreEqual(1, credentials.GetArrayLength());
        Assert.AreEqual(IssuedCredential, credentials[0].GetProperty("credential").GetString());
        Assert.AreEqual(NotificationId, doc.RootElement.GetProperty("notification_id").GetString());

        Assert.AreEqual(TransactionId, seenTransactionId);
        Assert.AreEqual(OfferSubject, seenSubject, "The seam must receive the validated access-token subject.");
    }


    /// <summary>
    /// §9.2: when issuance still needs time, the response is HTTP 202 echoing the SAME
    /// <c>transaction_id</c> with the <c>interval</c> the Wallet SHOULD wait.
    /// </summary>
    [TestMethod]
    public async Task DeferredEndpointEchoesPendingTransaction()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, EndpointCapabilities).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveDeferredCredentialAsync =
                static (_, _, _, _, _) => ValueTask.FromResult(DeferredCredentialDecision.Defer(86400));
        }).ConfigureAwait(false);

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);
        ServerHttpResponse response = await DispatchDeferredAsync(
            host, material, "Bearer " + accessToken,
            $"{{\"transaction_id\":\"{TransactionId}\"}}").ConfigureAwait(false);

        Assert.AreEqual(202, response.StatusCode, response.Body);

        using JsonDocument doc = JsonDocument.Parse(response.Body);
        Assert.AreEqual(TransactionId, doc.RootElement.GetProperty("transaction_id").GetString(),
            "§9.2: the 202 must echo the request's transaction_id.");
        Assert.AreEqual(86400, doc.RootElement.GetProperty("interval").GetInt64());
    }


    /// <summary>
    /// §9.3: an unknown or consumed <c>transaction_id</c> maps to
    /// <c>invalid_transaction_id</c>; an abandoned issuance maps to
    /// <c>credential_request_denied</c> so the Wallet stops polling.
    /// </summary>
    [TestMethod]
    public async Task DeferredEndpointMapsRefusalsToTheSpecErrors()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, EndpointCapabilities).ConfigureAwait(false);

        DeferredCredentialDecision decision = DeferredCredentialDecision.Refuse(
            DeferredCredentialError.InvalidTransactionId);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveDeferredCredentialAsync =
                (_, _, _, _, _) => ValueTask.FromResult(decision);
        }).ConfigureAwait(false);

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);
        ServerHttpResponse unknownId = await DispatchDeferredAsync(
            host, material, "Bearer " + accessToken,
            $"{{\"transaction_id\":\"{TransactionId}\"}}").ConfigureAwait(false);

        Assert.AreEqual(400, unknownId.StatusCode, unknownId.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidTransactionId, unknownId.Body);

        decision = DeferredCredentialDecision.Refuse(DeferredCredentialError.CredentialRequestDenied);
        ServerHttpResponse denied = await DispatchDeferredAsync(
            host, material, "Bearer " + accessToken,
            $"{{\"transaction_id\":\"{TransactionId}\"}}").ConfigureAwait(false);

        Assert.AreEqual(400, denied.StatusCode, denied.Body);
        Assert.Contains(Oid4VciCredentialErrors.CredentialRequestDenied, denied.Body);
    }


    /// <summary>
    /// The deferred endpoint is a protected resource: no bearer answers 401, and a body without
    /// the REQUIRED <c>transaction_id</c> answers <c>invalid_credential_request</c> before the
    /// seam is consulted.
    /// </summary>
    [TestMethod]
    public async Task DeferredEndpointRequiresBearerAndTransactionId()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, EndpointCapabilities).ConfigureAwait(false);

        bool seamConsulted = false;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveDeferredCredentialAsync =
                (_, _, _, _, _) =>
                {
                    seamConsulted = true;

                    return ValueTask.FromResult(DeferredCredentialDecision.Defer(60));
                };
        }).ConfigureAwait(false);

        ServerHttpResponse noBearer = await DispatchDeferredAsync(
            host, material, bearer: null,
            $"{{\"transaction_id\":\"{TransactionId}\"}}").ConfigureAwait(false);
        Assert.AreEqual(401, noBearer.StatusCode, noBearer.Body);
        Assert.IsTrue(noBearer.Headers.TryGetValue(WellKnownHttpHeaderNames.WwwAuthenticate, out string? noBearerChallenge));
        Assert.AreEqual(MissingCredentialsChallenge(host, material), noBearerChallenge);

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);
        ServerHttpResponse noTransaction = await DispatchDeferredAsync(
            host, material, "Bearer " + accessToken, "{}").ConfigureAwait(false);

        Assert.AreEqual(400, noTransaction.StatusCode, noTransaction.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidCredentialRequest, noTransaction.Body);
        Assert.IsFalse(seamConsulted, "Shape failures must not reach the seam.");
    }


    /// <summary>
    /// A server whose Credential Issuer metadata seam is not wired does not serve the Deferred
    /// Credential Endpoint, as it does not serve the Credential Endpoint: without the catalogue the
    /// encryption a Deferred Credential Request asks for cannot be judged against what the Credential
    /// Issuer advertises.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-9.1">OID4VCI 1.0 Section 9.1</see>:
    /// "The Credential Issuer indicates support for encrypted responses by including the
    /// credential_response_encryption parameter in the Credential Issuer Metadata."
    /// </summary>
    [TestMethod]
    public async Task ADeferredCredentialEndpointWithoutTheCatalogueIsNotServed()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, EndpointCapabilities).ConfigureAwait(false);
        await WireProtectedEndpointSeamsAsync(host).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ContributeCredentialIssuerMetadataAsync = null;
        }).ConfigureAwait(false);

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);
        using HttpResponseMessage response = await SendProtectedOverWireAsync(
            host, material, DeferredEndpointRow, "Bearer " + accessToken, ProtectedRequestBody(DeferredEndpointRow))
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.NotFound, response.StatusCode, body);
    }


    /// <summary>
    /// §11.2: an accepted notification answers 204 No Content with an empty body, and the seam
    /// receives the parsed notification. §11 idempotency is the seam's contract — a repeated
    /// identical call answers success again.
    /// </summary>
    [TestMethod]
    public async Task NotificationEndpointAcknowledgesAcceptedEvent()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, EndpointCapabilities).ConfigureAwait(false);

        List<CredentialNotification> seen = [];
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ProcessCredentialNotificationAsync =
                (notification, accessToken, registration, context, ct) =>
                {
                    seen.Add(notification);

                    return ValueTask.FromResult(CredentialNotificationDecision.Accept);
                };
        }).ConfigureAwait(false);

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);
        string body = $"{{\"notification_id\":\"{NotificationId}\",\"event\":\"credential_accepted\"}}";

        ServerHttpResponse first = await DispatchNotificationAsync(
            host, material, "Bearer " + accessToken, body).ConfigureAwait(false);
        ServerHttpResponse second = await DispatchNotificationAsync(
            host, material, "Bearer " + accessToken, body).ConfigureAwait(false);

        Assert.AreEqual(204, first.StatusCode, first.Body);
        Assert.AreEqual(string.Empty, first.Body);
        Assert.AreEqual(204, second.StatusCode, "§11: the notification is idempotent.");

        Assert.HasCount(2, seen);
        Assert.AreEqual(NotificationId, seen[0].NotificationId);
        Assert.AreEqual(Oid4VciNotificationEvents.CredentialAccepted, seen[0].Event);
        Assert.IsNull(seen[0].EventDescription);
    }


    /// <summary>
    /// §11.1's <c>event_description</c> rides through to the seam alongside the failure event.
    /// </summary>
    [TestMethod]
    public async Task NotificationEndpointRelaysFailureEventWithDescription()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, EndpointCapabilities).ConfigureAwait(false);

        CredentialNotification? seen = null;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ProcessCredentialNotificationAsync =
                (notification, _, _, _, _) =>
                {
                    seen = notification;

                    return ValueTask.FromResult(CredentialNotificationDecision.Accept);
                };
        }).ConfigureAwait(false);

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);
        ServerHttpResponse response = await DispatchNotificationAsync(
            host, material, "Bearer " + accessToken,
            $"{{\"notification_id\":\"{NotificationId}\",\"event\":\"credential_failure\","
            + "\"event_description\":\"Could not store the Credential. Out of storage.\"}}")
            .ConfigureAwait(false);

        Assert.AreEqual(204, response.StatusCode, response.Body);
        Assert.IsNotNull(seen);
        Assert.AreEqual(Oid4VciNotificationEvents.CredentialFailure, seen.Event);
        Assert.AreEqual("Could not store the Credential. Out of storage.", seen.EventDescription);
    }


    /// <summary>
    /// §11.1: "Values for the event_description parameter MUST NOT include characters outside the
    /// set %x20-21 / %x23-5B / %x5D-7E." An <c>event_description</c> carrying an out-of-charset
    /// character (here a literal <c>"</c>, 0x22) is sanitized to the allowed set before it reaches
    /// the application seam — the library never propagates a non-conformant value.
    /// </summary>
    [TestMethod]
    public async Task NotificationEventDescriptionIsSanitizedToTheAllowedCharset()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, EndpointCapabilities).ConfigureAwait(false);

        CredentialNotification? seen = null;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ProcessCredentialNotificationAsync =
                (notification, _, _, _, _) =>
                {
                    seen = notification;

                    return ValueTask.FromResult(CredentialNotificationDecision.Accept);
                };
        }).ConfigureAwait(false);

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);

        //The JSON-escaped \" decodes to a literal double-quote (0x22), which is outside the
        //allowed %x20-21 / %x23-5B / %x5D-7E set and is stripped.
        ServerHttpResponse response = await DispatchNotificationAsync(
            host, material, "Bearer " + accessToken,
            $"{{\"notification_id\":\"{NotificationId}\",\"event\":\"credential_failure\","
            + "\"event_description\":\"out \\\"of\\\" storage\"}}").ConfigureAwait(false);

        Assert.AreEqual(204, response.StatusCode, response.Body);
        Assert.IsNotNull(seen);
        Assert.AreEqual("out of storage", seen.EventDescription,
            "The out-of-charset double-quote characters are stripped from event_description.");
    }


    /// <summary>
    /// §11.3: an unknown <c>notification_id</c> answers <c>invalid_notification_id</c>; a
    /// missing required parameter or an undefined (or wrong-case — §11.1 is case-sensitive)
    /// <c>event</c> answers <c>invalid_notification_request</c> before the seam is consulted;
    /// and a missing bearer answers an RFC 6750 401.
    /// </summary>
    [TestMethod]
    public async Task NotificationEndpointRejectsInvalidRequests()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, EndpointCapabilities).ConfigureAwait(false);

        bool seamConsulted = false;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ProcessCredentialNotificationAsync =
                (_, _, _, _, _) =>
                {
                    seamConsulted = true;

                    return ValueTask.FromResult(CredentialNotificationDecision.RejectUnknownId());
                };
        }).ConfigureAwait(false);

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);
        string bearer = "Bearer " + accessToken;

        ServerHttpResponse noBearer = await DispatchNotificationAsync(
            host, material, bearer: null,
            $"{{\"notification_id\":\"{NotificationId}\",\"event\":\"credential_accepted\"}}")
            .ConfigureAwait(false);
        Assert.AreEqual(401, noBearer.StatusCode, noBearer.Body);
        Assert.IsTrue(noBearer.Headers.TryGetValue(WellKnownHttpHeaderNames.WwwAuthenticate, out string? noBearerChallenge));
        Assert.AreEqual(MissingCredentialsChallenge(host, material), noBearerChallenge);

        ServerHttpResponse missingEvent = await DispatchNotificationAsync(
            host, material, bearer,
            $"{{\"notification_id\":\"{NotificationId}\"}}").ConfigureAwait(false);
        Assert.AreEqual(400, missingEvent.StatusCode, missingEvent.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidNotificationRequest, missingEvent.Body);

        ServerHttpResponse wrongCaseEvent = await DispatchNotificationAsync(
            host, material, bearer,
            $"{{\"notification_id\":\"{NotificationId}\",\"event\":\"CREDENTIAL_ACCEPTED\"}}")
            .ConfigureAwait(false);
        Assert.AreEqual(400, wrongCaseEvent.StatusCode, wrongCaseEvent.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidNotificationRequest, wrongCaseEvent.Body);
        Assert.IsFalse(seamConsulted, "Shape failures must not reach the seam.");

        ServerHttpResponse unknownId = await DispatchNotificationAsync(
            host, material, bearer,
            "{\"notification_id\":\"never-issued\",\"event\":\"credential_accepted\"}")
            .ConfigureAwait(false);
        Assert.AreEqual(400, unknownId.StatusCode, unknownId.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidNotificationId, unknownId.Body);
        Assert.IsTrue(seamConsulted, "Only the seam can tell an unknown notification_id.");
    }


    /// <summary>
    /// §12.2.4: the Credential Issuer Metadata advertises <c>deferred_credential_endpoint</c>
    /// and <c>notification_endpoint</c> exactly when the endpoints are on the chain — the
    /// advertised URLs are the ones the matchers bind.
    /// </summary>
    [TestMethod]
    public async Task IssuerMetadataAdvertisesDeferredAndNotificationEndpoints()
    {
        ImmutableHashSet<CapabilityIdentifier> capabilities = EndpointCapabilities.Union(
        [
            WellKnownCapabilityIdentifiers.Oid4VciCredentialEndpoint,
            WellKnownCapabilityIdentifiers.Oid4VciCredentialIssuerMetadata
        ]);

        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, capabilities).ConfigureAwait(false);

        //The fail-closed gates keep each endpoint off the chain until its seams are wired;
        //the metadata derives the advertised URLs from the chain.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultCredentialRequestJsonParsing();


            candidateIntegration.IssueCredentialAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));

            candidateIntegration.ResolveDeferredCredentialAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(DeferredCredentialDecision.Defer(60));

            candidateIntegration.ProcessCredentialNotificationAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(CredentialNotificationDecision.Accept);

            candidateIntegration.ContributeCredentialIssuerMetadataAsync = static (_, _, _) =>
                ValueTask.FromResult(CredentialIssuerMetadataContribution.Empty);
        }).ConfigureAwait(false);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciCredentialIssuerMetadata,
            WellKnownHttpMethods.Get,
            new RequestFields(),
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument doc = JsonDocument.Parse(response.Body);
        string? deferredEndpoint = doc.RootElement
            .GetProperty("deferred_credential_endpoint").GetString();
        string? notificationEndpoint = doc.RootElement
            .GetProperty("notification_endpoint").GetString();

        Assert.IsNotNull(deferredEndpoint);
        Assert.EndsWith("deferred_credential", deferredEndpoint);
        Assert.IsNotNull(notificationEndpoint);
        Assert.EndsWith("notification", notificationEndpoint);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 §3</see>: "If the protected
    /// resource request does not include authentication credentials or does not contain an access token
    /// that enables access to the protected resource, the resource server MUST include the HTTP
    /// "WWW-Authenticate" response header field", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">§3.1</see>: "If the request lacks
    /// any authentication information ... the resource server SHOULD NOT include an error code or other
    /// error information." A request to the Deferred Credential or the Notification endpoint sent over the
    /// wire with no <c>Authorization</c> header is refused with 401, an empty body and the one challenge
    /// <c>Bearer realm="&lt;issuer&gt;", DPoP realm="&lt;issuer&gt;", algs="..."</c>, naming both schemes and no error.
    /// </summary>
    /// <param name="endpointName">The protected endpoint addressed.</param>
    [TestMethod]
    [DataRow(DeferredEndpointRow)]
    [DataRow(NotificationEndpointRow)]
    public async Task ProtectedEndpointChallengesARequestWithoutCredentialsForBothSchemesAsync(string endpointName)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, EndpointCapabilities).ConfigureAwait(false);
        await WireProtectedEndpointSeamsAsync(host).ConfigureAwait(false);

        using HttpResponseMessage response = await SendProtectedOverWireAsync(
            host, material, endpointName, authorization: null, ProtectedRequestBody(endpointName)).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        //The header is read as sent: the client's typed view splits one field value into its challenges.
        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode, body);
        Assert.IsTrue(response.Headers.NonValidated.TryGetValues("WWW-Authenticate", out HeaderStringValues challenges),
            "RFC 6750 §3: the refusal carries a WWW-Authenticate challenge.");
        Assert.AreEqual(MissingCredentialsChallenge(host, material), Assert.ContainsSingle(challenges));
        Assert.AreEqual(string.Empty, body, "RFC 6750 §3.1: no error code or other error information.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 §3</see>: "If the protected
    /// resource request does not include authentication credentials or does not contain an access token
    /// that enables access to the protected resource, the resource server MUST include the HTTP
    /// "WWW-Authenticate" response header field". The <c>realm</c> the challenge names is an
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.4">RFC 9110 §5.6.4</see> quoted-string
    /// ("qdtext = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text"). An issuer configured with Unicode
    /// text, in its path (<c>https://issuer.example/</c> followed by U+79DF U+6237) or in its host
    /// (<c>https://b</c> U+00FC <c>cher.example/tenant</c>), is written there in its URI form, as
    /// <see href="https://www.rfc-editor.org/rfc/rfc3987#section-3.1">RFC 3987 §3.1</see> maps an IRI: the
    /// UTF-8 octets of each path character as "%HH" (<c>%E7%A7%9F%E6%88%B7</c>) and the host by the IDNA
    /// ToASCII operation (<c>xn--bcher-kva.example</c>, RFC 3492's encoding of the label). A request to the
    /// Deferred Credential endpoint sent over the wire with no <c>Authorization</c> header is answered 401,
    /// with an empty body and the one challenge <c>Bearer realm="&lt;that URI&gt;", DPoP realm="&lt;that URI&gt;", algs="..."</c>.
    /// </summary>
    /// <param name="issuerRow">Where the configured issuer holds Unicode text.</param>
    [TestMethod]
    [DataRow(UnicodePathIssuerRow)]
    [DataRow(UnicodeHostIssuerRow)]
    public async Task ProtectedEndpointChallengesARequestWithoutCredentialsUnderAUnicodeIssuerAsync(string issuerRow)
    {
        (Uri configuredIssuer, string expectedRealm) = issuerRow switch
        {
            UnicodePathIssuerRow => (
                new Uri("https://issuer.example/" + string.Concat((char)0x79DF, (char)0x6237)),
                "https://issuer.example/%E7%A7%9F%E6%88%B7"),
            UnicodeHostIssuerRow => (
                new Uri("https://b" + (char)0x00FC + "cher.example/tenant"),
                "https://xn--bcher-kva.example/tenant"),
            _ => throw new ArgumentOutOfRangeException(nameof(issuerRow), issuerRow, "Unknown issuer row.")
        };
        Assert.IsTrue(IssuerIdentifier.Parse(configuredIssuer.OriginalString).IsSuccess,
            "The configured issuer is one the server accepts as an issuer identifier.");

        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, EndpointCapabilities).ConfigureAwait(false);
        await WireProtectedEndpointSeamsAsync(host).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        HostedAuthorizationServer served = host.Host("default");
        ClientRecord unicodeIssuerRegistration = served.Registrations[material.Registration.TenantId.Value] with
        {
            IssuerUri = configuredIssuer
        };
        served.Registrations[unicodeIssuerRegistration.TenantId.Value] = unicodeIssuerRegistration;
        served.Registrations[unicodeIssuerRegistration.ClientId] = unicodeIssuerRegistration;

        using HttpResponseMessage response = await SendProtectedOverWireAsync(
            host, material, DeferredEndpointRow, authorization: null, ProtectedRequestBody(DeferredEndpointRow)).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode, body);
        Assert.IsTrue(response.Headers.NonValidated.TryGetValues("WWW-Authenticate", out HeaderStringValues challenges),
            "RFC 6750 §3: the refusal carries a WWW-Authenticate challenge.");
        Assert.AreEqual(
            $"Bearer realm=\"{expectedRealm}\", {ResourceDpopProofs.DpopChallenge(expectedRealm, error: null)}",
            Assert.ContainsSingle(challenges));
        Assert.AreEqual(string.Empty, body, "RFC 6750 §3.1: no error code or other error information.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-5.1">RFC 9728 Section 5.1</see>: "resource_metadata:
    /// The URL of the protected resource metadata.", with <see href="https://www.rfc-editor.org/rfc/rfc9728#section-1.2">Section
    /// 1.2</see>: "Resource Identifier: The protected resource's resource identifier, which is a URL that uses the https
    /// scheme" and <see href="https://www.rfc-editor.org/rfc/rfc3987#section-3.1">RFC 3987 Section 3.1</see>: "Replace the
    /// ireg-name part of the IRI by the part converted using the ToASCII operation specified in section 4.1 of [RFC3490]
    /// on each dot-separated label". Under a registration allowing
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata"/> whose issuer is configured as
    /// <c>https://b</c> U+00FC <c>cher.example/tenant</c>, a request without credentials sent over a raw TLS connection
    /// to the resource a row addresses is answered 401 with an empty body and exactly the one challenge whose
    /// <c>realm</c> is <c>https://xn--bcher-kva.example/tenant</c> and whose <c>resource_metadata</c> is the resource's
    /// document URL under the host <c>xn--bcher-kva.example</c>, in both the <c>Bearer</c> and the <c>DPoP</c> challenge.
    /// The rows: UserInfo, whose challenges carry <c>scope="openid"</c>; the Credential Endpoint; the Deferred Credential
    /// Endpoint; the Notification Endpoint.
    /// </summary>
    /// <param name="row">The resource addressed.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(UserInfoEndpointRow)]
    [DataRow(CredentialEndpointRow)]
    [DataRow(DeferredEndpointRow)]
    [DataRow(NotificationEndpointRow)]
    public async Task LibraryResourceUnderAnInternationalizedIssuerNamesItsDocumentInUriFormAsync(string row)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, LibraryResourceCapabilities).ConfigureAwait(false);
        await WireProtectedEndpointSeamsAsync(host).ConfigureAwait(false);
        await ServeUnderTheInternationalizedIssuerAsync(host, material).ConfigureAwait(false);
        string path = TestHostShell.ComposeEndpointPath(EndpointNameOf(row), material.Registration.TenantId.Value);
        string documentUrl = $"{InternationalizedAuthorityInUriForm}/.well-known/oauth-protected-resource{path}";
        string? scope = string.Equals(row, UserInfoEndpointRow, StringComparison.Ordinal) ? WellKnownScopes.OpenId : null;
        string scopeParameter = scope is null ? string.Empty : $", scope=\"{scope}\"";

        HttpResponseData response = await SendWithoutCredentialsAsync(host, material, row).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The request is answered without a server fault.");
        Assert.AreEqual(401, response.StatusCode, response.Body);
        Assert.AreEqual(
            $"Bearer realm=\"{InternationalizedIssuerInUriForm}\"{scopeParameter}, resource_metadata=\"{documentUrl}\", "
                + ResourceDpopProofs.DpopChallenge(InternationalizedIssuerInUriForm, error: null, scope, new Uri(documentUrl)),
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        Assert.AreEqual(string.Empty, response.Body, "No error code or other error information.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">RFC 9728 Section 2</see>: "resource REQUIRED. The
    /// protected resource's resource identifier, as defined in Section 1.2." and "authorization_servers OPTIONAL. JSON
    /// array containing a list of OAuth authorization server issuer identifiers", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc3987#section-3.1">RFC 3987 Section 3.1</see>: "when an IRI is used for
    /// resource retrieval, the resource that the IRI locates is the same as the one located by the URI obtained after
    /// converting the IRI". Under a registration allowing
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata"/> whose issuer is configured as
    /// <c>https://b</c> U+00FC <c>cher.example/tenant</c>, a GET of the document of the resource a row addresses over a raw
    /// TLS connection is answered 200 with exactly the document whose <c>resource</c> is the resource's URL under the host
    /// <c>xn--bcher-kva.example</c> and whose <c>authorization_servers</c> is
    /// <c>["https://xn--bcher-kva.example/tenant"]</c>. The rows: UserInfo, its <c>scopes_supported</c>
    /// <c>["openid"]</c>; the Deferred Credential Endpoint.
    /// </summary>
    /// <param name="row">The resource whose document is fetched.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(UserInfoEndpointRow)]
    [DataRow(DeferredEndpointRow)]
    public async Task LibraryResourceDocumentUnderAnInternationalizedIssuerNamesItsUrlsInUriFormAsync(string row)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, LibraryResourceCapabilities).ConfigureAwait(false);
        await WireProtectedEndpointSeamsAsync(host).ConfigureAwait(false);
        await ServeUnderTheInternationalizedIssuerAsync(host, material).ConfigureAwait(false);
        string path = TestHostShell.ComposeEndpointPath(EndpointNameOf(row), material.Registration.TenantId.Value);
        string scopesMember = string.Equals(row, UserInfoEndpointRow, StringComparison.Ordinal) ? ",\"scopes_supported\":[\"openid\"]" : string.Empty;
        string algorithms = "[" + string.Join(",", ResourceDpopProofs.AcceptedProofAlgorithms.Split(' ').Select(static name => $"\"{name}\"")) + "]";

        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Get, new Uri(host.Host("default").HttpBaseAddress!, "/.well-known/oauth-protected-resource" + path), [],
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The document is served without a server fault.");
        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.AreEqual(
            $"{{\"resource\":\"{InternationalizedAuthorityInUriForm}{path}\",\"authorization_servers\":[\"{InternationalizedIssuerInUriForm}\"]"
            + $"{scopesMember},\"bearer_methods_supported\":[\"header\"],\"dpop_signing_alg_values_supported\":{algorithms}}}",
            response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">RFC 9728 Section 2</see>: "resource REQUIRED. The
    /// protected resource's resource identifier, as defined in Section 1.2.", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-1.2">Section 1.2</see>: "a URL that uses the https
    /// scheme" and <see href="https://www.rfc-editor.org/rfc/rfc3987#section-3.1">RFC 3987 Section 3.1</see>: "Replace the
    /// ireg-name part of the IRI by the part converted using the ToASCII operation". Under a registration allowing
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata"/> whose issuer is configured as
    /// <c>https://b</c> U+00FC <c>cher.example/tenant</c>, a GET of the issuer's own document over a raw TLS connection is
    /// answered 200 with the document whose <c>resource</c> is <c>https://xn--bcher-kva.example/tenant</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task IssuerDocumentUnderAnInternationalizedIssuerNamesTheIssuerInUriFormAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, LibraryResourceCapabilities).ConfigureAwait(false);
        await WireProtectedEndpointSeamsAsync(host).ConfigureAwait(false);
        await ServeUnderTheInternationalizedIssuerAsync(host, material).ConfigureAwait(false);

        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Get,
            new Uri(host.Host("default").HttpBaseAddress!,
                TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.ProtectedResourceMetadata, material.Registration.TenantId.Value)),
            [], ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        using JsonDocument document = JsonDocument.Parse(response.Body);
        Assert.AreEqual(InternationalizedIssuerInUriForm, document.RootElement.GetProperty("resource").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.3">RFC 9728 Section 3.3</see>: "The resource value
    /// returned MUST be identical to the protected resource's resource identifier value into which the well-known URI
    /// path suffix was inserted to create the URL used to retrieve the metadata.", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.2">Section 3.2</see>: "An error response uses the
    /// applicable HTTP status code value." A document location two resources' documents are both located at, the same
    /// path and the same query, names no one resource the document could state, a fault of the server's own wiring:
    /// under a registration allowing <see cref="WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata"/>, a GET
    /// of that location over a raw TLS connection is answered 500 with exactly the body
    /// <c>{"error":"server_error","error_description":"The server is not ready to serve this request."}</c>, and a
    /// UserInfo GET without credentials is answered 401 with a challenge naming no <c>resource_metadata</c>. The rows:
    /// the endpoint resolver answering UserInfo at <c>/connect/&lt;t&gt;/resource</c> and the Credential Endpoint at
    /// <c>/connect/&lt;t&gt;/resource/</c>, one location under Section 3.1's rule for the path's terminating slash ("any
    /// terminating slash (/) following the host component MUST be removed"); UserInfo at <c>/&lt;t&gt;</c>, whose location
    /// is the issuer's own document's, the UserInfo request not sent.
    /// </summary>
    /// <param name="row">The endpoint resolver's answers.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(TrailingSlashLocationsRow)]
    [DataRow(IssuerDocumentLocationRow)]
    public async Task DocumentLocationServingTwoResourcesIsAServerErrorAsync(string row)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, LibraryResourceCapabilities).ConfigureAwait(false);
        await WireProtectedEndpointSeamsAsync(host).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        (string UserInfoUrlPath, string CredentialUrlPath, IReadOnlyList<string> Locations) wiring = row switch
        {
            TrailingSlashLocationsRow => (
                $"/connect/{segment}/resource",
                $"/connect/{segment}/resource/",
                [$"/.well-known/oauth-protected-resource/connect/{segment}/resource"]),
            IssuerDocumentLocationRow => (
                $"/{segment}",
                TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.Oid4VciCredential, segment),
                [TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.ProtectedResourceMetadata, segment)]),
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown location row.")
        };

        string userInfoUrlPath = wiring.UserInfoUrlPath;
        await AnswerUserInfoAndTheCredentialEndpointAtAsync(host, userInfoUrlPath, wiring.CredentialUrlPath).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Uri baseAddress = host.Host("default").HttpBaseAddress!;

        foreach(string location in wiring.Locations)
        {
            HttpResponseData document = await RawHttpsRequest.SendAsync(
                host, WellKnownHttpMethods.Get, new Uri(baseAddress, location), [], ReadOnlyMemory<byte>.Empty,
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The location is answered without a server fault.");
            Assert.AreEqual(500, document.StatusCode, document.Body);
            Assert.AreEqual(
                /*lang=json,strict*/ "{\"error\":\"server_error\",\"error_description\":\"The server is not ready to serve this request.\"}",
                document.Body);
        }

        if(!string.Equals(row, IssuerDocumentLocationRow, StringComparison.Ordinal))
        {
            HttpResponseData challenged = await RawHttpsRequest.SendAsync(
                host, WellKnownHttpMethods.Get, new Uri(baseAddress, userInfoUrlPath), [], ReadOnlyMemory<byte>.Empty,
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(401, challenged.StatusCode, challenged.Body);
            Assert.IsNull(
                ProtectedResourceChallenge.TryReadResourceMetadata(
                    Assert.ContainsSingle(challenged.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate))),
                "No challenge names a document.");
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3">RFC 9728 Section 3</see>: "available at a URL formed
    /// by inserting a well-known URI string into the protected resource's resource identifier between the host component
    /// and the path and/or query components, if any", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.3">Section 3.3</see>: "The resource value returned
    /// MUST be identical to the protected resource's resource identifier value into which the well-known URI path suffix
    /// was inserted to create the URL used to retrieve the metadata." Two resources whose identifiers differ in their
    /// query alone have two document locations, the query kept after the inserted path: under a registration allowing
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata"/> whose endpoint resolver answers
    /// UserInfo at <c>/connect/&lt;t&gt;/resource?kind=user</c> and the Credential Endpoint at
    /// <c>/connect/&lt;t&gt;/resource?kind=credential</c>, a GET of the location of the resource a row names, over a raw TLS
    /// connection, is answered 200 with the document whose <c>resource</c> is that resource's identifier. The rows:
    /// UserInfo, whose GET without credentials at its identifier is also answered 401 with exactly the challenge naming
    /// UserInfo's own location as <c>resource_metadata</c>; the Credential Endpoint.
    /// </summary>
    /// <param name="row">The resource whose document is fetched: <see cref="UserInfoEndpointRow"/> or <see cref="CredentialEndpointRow"/>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(UserInfoEndpointRow)]
    [DataRow(CredentialEndpointRow)]
    public async Task ResourcesWhoseIdentifiersDifferInTheirQueryAreServedTheirOwnDocumentsAsync(string row)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, LibraryResourceCapabilities).ConfigureAwait(false);
        await WireProtectedEndpointSeamsAsync(host).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        string userInfoUrlPath = $"/connect/{segment}/resource?kind=user";
        await AnswerUserInfoAndTheCredentialEndpointAtAsync(
            host, userInfoUrlPath, $"/connect/{segment}/resource?kind=credential").ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Uri baseAddress = host.Host("default").HttpBaseAddress!;
        string authority = new Uri(IssuerOf(host, material)).GetLeftPart(UriPartial.Authority);
        string kind = string.Equals(row, UserInfoEndpointRow, StringComparison.Ordinal) ? "user" : "credential";
        string identifier = $"{authority}/connect/{segment}/resource?kind={kind}";
        string location = $"/.well-known/oauth-protected-resource/connect/{segment}/resource?kind={kind}";

        HttpResponseData document = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Get, new Uri(baseAddress, location), [], ReadOnlyMemory<byte>.Empty,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The location is answered without a server fault.");
        Assert.AreEqual(200, document.StatusCode, document.Body);
        using JsonDocument parsed = JsonDocument.Parse(document.Body);
        Assert.AreEqual(identifier, parsed.RootElement.GetProperty("resource").GetString());

        if(string.Equals(row, UserInfoEndpointRow, StringComparison.Ordinal))
        {
            string issuer = IssuerOf(host, material);
            string documentUrl = authority + location;
            HttpResponseData challenged = await RawHttpsRequest.SendAsync(
                host, WellKnownHttpMethods.Get, new Uri(baseAddress, userInfoUrlPath), [], ReadOnlyMemory<byte>.Empty,
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(401, challenged.StatusCode, challenged.Body);
            Assert.AreEqual(
                $"Bearer realm=\"{issuer}\", scope=\"openid\", resource_metadata=\"{documentUrl}\", "
                    + ResourceDpopProofs.DpopChallenge(issuer, error: null, WellKnownScopes.OpenId, new Uri(documentUrl)),
                Assert.ContainsSingle(challenged.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        }
    }


    /// <summary>
    /// Wires the host's endpoint resolver to answer UserInfo at <paramref name="userInfoUrlPath"/> and the Credential
    /// Endpoint at <paramref name="credentialUrlPath"/>, each under the authority of the URL it answers today, so the two
    /// resources' identifiers and document locations are the ones a row names.
    /// </summary>
    /// <param name="host">The host whose integration is altered.</param>
    /// <param name="userInfoUrlPath">UserInfo's path, with any query.</param>
    /// <param name="credentialUrlPath">The Credential Endpoint's path, with any query.</param>
    /// <returns>A task that completes when the alteration is published.</returns>
    private static Task AnswerUserInfoAndTheCredentialEndpointAtAsync(TestHostShell host, string userInfoUrlPath, string credentialUrlPath) =>
        TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            ResolveEndpointUriDelegate resolve = candidateIntegration.ResolveEndpointUriAsync!;
            candidateIntegration.ResolveEndpointUriAsync = async (endpointKey, registration, context, cancellationToken) =>
            {
                Uri? resolved = await resolve(endpointKey, registration, context, cancellationToken).ConfigureAwait(false);

                return (endpointKey, resolved) switch
                {
                    (string key, Uri url) when string.Equals(key, WellKnownEndpointNames.UserInfo, StringComparison.Ordinal) =>
                        new Uri(url.GetLeftPart(UriPartial.Authority) + userInfoUrlPath),
                    (string key, Uri url) when string.Equals(key, WellKnownEndpointNames.Oid4VciCredential, StringComparison.Ordinal) =>
                        new Uri(url.GetLeftPart(UriPartial.Authority) + credentialUrlPath),
                    _ => resolved
                };
            };
        });


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 §7.2</see>: "If the
    /// mechanism used to attempt authentication could be established unambiguously, then the
    /// corresponding challenge SHOULD be used to deliver error information". An access token whose
    /// signature does not verify, presented under the <c>DPoP</c> scheme at the Deferred Credential or
    /// the Notification endpoint over the wire, is refused with 401 <c>invalid_token</c> and the one
    /// challenge <c>DPoP realm="&lt;issuer&gt;", error="invalid_token", algs="..."</c>, never a <c>Bearer</c> one.
    /// </summary>
    /// <param name="endpointName">The protected endpoint addressed.</param>
    [TestMethod]
    [DataRow(DeferredEndpointRow)]
    [DataRow(NotificationEndpointRow)]
    public async Task ProtectedEndpointAnswersARefusedDpopPresentationWithADpopChallengeAsync(string endpointName)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, EndpointCapabilities).ConfigureAwait(false);
        await WireProtectedEndpointSeamsAsync(host).ConfigureAwait(false);

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);
        int signatureStart = accessToken.LastIndexOf('.', StringComparison.Ordinal) + 1;
        int tamperIndex = signatureStart + ((accessToken.Length - signatureStart) / 2);
        char flipped = accessToken[tamperIndex] == 'A' ? 'B' : 'A';
        string tampered = string.Concat(accessToken.AsSpan(0, tamperIndex), flipped.ToString(), accessToken.AsSpan(tamperIndex + 1));

        using HttpResponseMessage response = await SendProtectedOverWireAsync(
            host, material, endpointName, "DPoP " + tampered, ProtectedRequestBody(endpointName)).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode, body);
        Assert.IsTrue(response.Headers.TryGetValues("WWW-Authenticate", out IEnumerable<string>? challenges),
            "RFC 6750 §3: the refusal carries a WWW-Authenticate challenge.");
        Assert.AreEqual(ResourceDpopProofs.DpopChallenge(IssuerOf(host, material), "invalid_token"), challenges.Single());
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("invalid_token", document.RootElement.GetProperty("error").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 Section 7.2</see>: "If the mechanism used
    /// to attempt authentication could be established unambiguously, then the corresponding challenge SHOULD be used to
    /// deliver error information (Figure 18).", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>: "invalid_request The
    /// request is missing a required parameter, includes an unsupported parameter or parameter value, repeats the same
    /// parameter, uses more than one method for including an access token, or is otherwise malformed.  The resource
    /// server SHOULD respond with the HTTP 400 (Bad Request) status code." A request to the Deferred Credential or the
    /// Notification endpoint sent over a raw TLS connection with two <c>Authorization: Bearer</c> field lines
    /// (<c>Authorization = credentials</c> is no list,
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.2">RFC 9110 Section 11.6.2</see>) attempts the
    /// <c>Bearer</c> mechanism alone: it is refused with 400 <c>invalid_request</c> and the one challenge
    /// <c>Bearer realm="&lt;issuer&gt;", error="invalid_request"</c>, and no <c>DPoP</c> challenge.
    /// </summary>
    /// <param name="endpointName">The protected endpoint addressed.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(DeferredEndpointRow)]
    [DataRow(NotificationEndpointRow)]
    public async Task ProtectedEndpointRefusesTwoBearerAuthorizationLinesWithTheBearerChallengeAloneAsync(string endpointName)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, EndpointCapabilities).ConfigureAwait(false);
        await WireProtectedEndpointSeamsAsync(host).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        string segment = material.Registration.TenantId.Value;
        Uri url = new(host.Host("default").HttpBaseAddress!, TestHostShell.ComposeEndpointPath(EndpointNameOf(endpointName), segment));
        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, url,
            [
                new(WellKnownHttpHeaderNames.ContentType, WellKnownMediaTypes.Application.Json),
                new(WellKnownHttpHeaderNames.Authorization, "Bearer first-access-token"),
                new(WellKnownHttpHeaderNames.Authorization, "Bearer second-access-token")
            ],
            Encoding.UTF8.GetBytes(ProtectedRequestBody(endpointName)), TestContext.CancellationToken).ConfigureAwait(false);
        string issuer = host.Host("default").Registrations[segment].IssuerUri!.OriginalString;

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.AreEqual(
            $"Bearer realm=\"{issuer}\", error=\"invalid_request\"",
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        using JsonDocument document = JsonDocument.Parse(response.Body);
        Assert.AreEqual("invalid_request", document.RootElement.GetProperty("error").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-2.1">RFC 6750 Section 2.1</see>: "credentials =
    /// "Bearer" 1*SP b64token"; a credential outside that form is malformed,
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>: "invalid_request The
    /// request is missing a required parameter, includes an unsupported parameter or parameter value, repeats the same
    /// parameter, uses more than one method for including an access token, or is otherwise malformed. The resource server
    /// SHOULD respond with the HTTP 400 (Bad Request) status code.", and the mechanism it attempts is named,
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 Section 7.2</see>: "If the mechanism used
    /// to attempt authentication could be established unambiguously, then the corresponding challenge SHOULD be used to
    /// deliver error information (Figure 18)." A request to the Deferred Credential or the Notification endpoint sent
    /// over a raw TLS connection with a well-formed request body and one <c>Authorization</c> field line naming the
    /// <c>Bearer</c> scheme with the credentials <c>abc def</c>, no token68, is answered 400 with the body
    /// <c>{"error":"invalid_request","error_description":"The Authorization header credentials are not a token68."}</c>,
    /// the one challenge <c>Bearer realm="&lt;issuer&gt;", error="invalid_request"</c> and no <c>DPoP</c> challenge.
    /// </summary>
    /// <param name="endpointName">The protected endpoint addressed.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(DeferredEndpointRow)]
    [DataRow(NotificationEndpointRow)]
    public async Task ProtectedEndpointAnswersACredentialOutsideToken68WithInvalidRequestAsync(string endpointName)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, EndpointCapabilities).ConfigureAwait(false);
        await WireProtectedEndpointSeamsAsync(host).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Uri url = new(host.Host("default").HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(EndpointNameOf(endpointName), material.Registration.TenantId.Value));
        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, url,
            [
                new(WellKnownHttpHeaderNames.ContentType, WellKnownMediaTypes.Application.Json),
                new(WellKnownHttpHeaderNames.Authorization, "Bearer abc def")
            ],
            Encoding.UTF8.GetBytes(ProtectedRequestBody(endpointName)), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The request is answered without a server fault.");
        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.AreEqual(
            $"Bearer realm=\"{IssuerOf(host, material)}\", error=\"invalid_request\"",
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        Assert.AreEqual(
            "{\"error\":\"invalid_request\",\"error_description\":\"The Authorization header credentials are not a token68.\"}",
            response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">RFC 9728 Section 2</see>:
    /// "dpop_bound_access_tokens_required OPTIONAL. Boolean value specifying whether the protected resource always
    /// requires the use of DPoP-bound access tokens [RFC9449]."; <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC
    /// 9449 Section 7.1</see>: "Upon receipt of a request to a protected resource within the protection space requiring
    /// DPoP authentication, the server can respond with a challenge to the client to provide DPoP authentication
    /// information"; and <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>: "If
    /// the request lacks any authentication information (e.g., the client was unaware that authentication is necessary
    /// or attempted using an unsupported authentication method), the resource server SHOULD NOT include an error code or
    /// other error information." At a server whose resources require DPoP-bound access tokens, an access token bound to
    /// no key, presented under the <c>Bearer</c> scheme over a raw TLS connection with a well-formed request body at the
    /// Deferred Credential or the Notification endpoint, is refused: 401, an empty body, the one challenge
    /// <c>DPoP realm="&lt;issuer&gt;", algs="..."</c> with no <c>error</c> and no <c>Bearer</c> challenge, and the one
    /// field line <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c>.
    /// </summary>
    /// <param name="endpointName">The protected endpoint addressed.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(DeferredEndpointRow)]
    [DataRow(NotificationEndpointRow)]
    public async Task ProtectedEndpointRequiringDpopBoundAccessTokensRefusesABearerPresentationAsync(string endpointName)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, EndpointCapabilities).ConfigureAwait(false);
        await WireProtectedEndpointSeamsAsync(host).ConfigureAwait(false);
        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, static candidateIntegration =>
            candidateIntegration.IsDpopBoundAccessTokenRequiredAtResources = true).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Uri url = new(host.Host("default").HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(EndpointNameOf(endpointName), material.Registration.TenantId.Value));
        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, url,
            [
                new(WellKnownHttpHeaderNames.ContentType, WellKnownMediaTypes.Application.Json),
                new(WellKnownHttpHeaderNames.Authorization, "Bearer " + accessToken)
            ],
            Encoding.UTF8.GetBytes(ProtectedRequestBody(endpointName)), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The presentation is refused without a server fault.");
        Assert.AreEqual(401, response.StatusCode, response.Body);
        Assert.AreEqual(
            ResourceDpopProofs.DpopChallenge(IssuerOf(host, material), error: null),
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        Assert.AreEqual(
            ResourceDpopProofs.ExposedDpopResponseFields,
            Assert.ContainsSingle(response.Headers.Headers.GetValues("Access-Control-Expose-Headers")));
        Assert.AreEqual(string.Empty, response.Body, "No error code or other error information.");
    }


    /// <summary>
    /// A request to the Credential, the Deferred Credential or the Notification endpoint sent over the wire, whose
    /// registration the application's materialization seam replaces with a record that is not an OAuth client
    /// registration, is answered 500 with the body's error <c>server_error</c> and no challenge, and the endpoint's
    /// own seam is not called: the endpoint cannot serve the request, and the cause is the server's wiring, not the
    /// caller.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.6.1">RFC 9110 Section 15.6.1</see>: "The 500
    /// (Internal Server Error) status code indicates that the server encountered an unexpected condition that
    /// prevented it from fulfilling the request."
    /// </summary>
    /// <param name="endpointName">The protected endpoint addressed.</param>
    [TestMethod]
    [DataRow(CredentialEndpointRow)]
    [DataRow(DeferredEndpointRow)]
    [DataRow(NotificationEndpointRow)]
    public async Task AProtectedRequestServedUnderARegistrationTheEndpointCannotUseIsAServerErrorAsync(string endpointName)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce,
            EndpointCapabilities.Add(WellKnownCapabilityIdentifiers.Oid4VciCredentialEndpoint)).ConfigureAwait(false);
        await WireProtectedEndpointSeamsAsync(host).ConfigureAwait(false);

        int seamCallCount = 0;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultCredentialRequestJsonParsing();
            candidateIntegration.IssueCredentialAsync = (_, _, _, _, _) =>
            {
                _ = Interlocked.Increment(ref seamCallCount);

                return ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
            };
            candidateIntegration.ResolveDeferredCredentialAsync = (_, _, _, _, _) =>
            {
                _ = Interlocked.Increment(ref seamCallCount);

                return ValueTask.FromResult(DeferredCredentialDecision.Defer(60));
            };
            candidateIntegration.ProcessCredentialNotificationAsync = (_, _, _, _, _) =>
            {
                _ = Interlocked.Increment(ref seamCallCount);

                return ValueTask.FromResult(CredentialNotificationDecision.Accept);
            };
            candidateIntegration.MaterializeRegistrationAsync = static (registration, _, _) => ValueTask.FromResult(new RegistrationMaterialization
            {
                Registration = new WebFingerHttpApplication.PlainRegistration
                {
                    ClientId = registration.ClientId,
                    TenantId = registration.TenantId,
                    AllowedCapabilities = registration.AllowedCapabilities
                }
            });
        }).ConfigureAwait(false);

        using HttpResponseMessage response = await SendProtectedOverWireAsync(
            host, material, endpointName, "Bearer any-token", ProtectedRequestBody(endpointName)).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.InternalServerError, response.StatusCode, body);
        Assert.AreEqual(
            /*lang=json,strict*/ "{\"error\":\"server_error\",\"error_description\":\"The server is not ready to serve this request.\"}", body);
        Assert.IsFalse(response.Headers.Contains("WWW-Authenticate"), "A fault of the server carries no challenge.");
        Assert.AreEqual(0, seamCallCount, "A request the endpoint cannot serve must not reach the endpoint's seam.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-4">RFC 9068 Section 4</see>: "The resource server
    /// MUST validate that the "aud" claim contains a resource indicator value corresponding to an identifier the
    /// resource server expects for itself.  The JWT access token MUST be rejected if "aud" does not contain a
    /// resource indicator of the current resource server as a valid audience." The Credential, the Deferred
    /// Credential and the Notification endpoint are resources of this Authorization Server, whose identifier is
    /// the issuer. An access token from the Pre-Authorized Code grant, issued while the application's audience
    /// resolver names another resource, carries that resource alone as its <c>aud</c>; presented over the wire
    /// under the <c>Bearer</c> scheme with a well-formed request body at the endpoint a row addresses, it is
    /// refused with 401, <c>invalid_token</c> and the one challenge <c>Bearer realm="&lt;issuer&gt;", error="invalid_token"</c>.
    /// </summary>
    /// <param name="endpointName">The protected endpoint addressed.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(CredentialEndpointRow)]
    [DataRow(DeferredEndpointRow)]
    [DataRow(NotificationEndpointRow)]
    public async Task AProtectedEndpointRefusesATokenAudiencedAtAnotherResourceAsync(string endpointName)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce,
            EndpointCapabilities.Add(WellKnownCapabilityIdentifiers.Oid4VciCredentialEndpoint)).ConfigureAwait(false);
        await WireProtectedEndpointSeamsAsync(host).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, static candidateIntegration =>
        {
            candidateIntegration.ResolveAccessTokenAudienceAsync = static (_, _, _) =>
                ValueTask.FromResult<IReadOnlyList<string>?>([OtherResourceAudience]);
        }).ConfigureAwait(false);

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);

        using HttpResponseMessage response = await SendProtectedOverWireAsync(
            host, material, endpointName, "Bearer " + accessToken, ProtectedRequestBody(endpointName)).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        AssertInvalidTokenRefusal(response, body, IssuerOf(host, material));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-2.2">RFC 9068 Section 2.2</see>: "aud  REQUIRED -
    /// as defined in Section 4.1.3 of [RFC7519]." and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-4">Section 4</see>: "The JWT access token MUST be
    /// rejected if "aud" does not contain a resource indicator of the current resource server as a valid
    /// audience." An access token from the Pre-Authorized Code grant, signed again under the registration's
    /// access-token key with its <c>aud</c> claim removed, presented over the wire under the <c>Bearer</c> scheme
    /// with a well-formed request body at the Credential, the Deferred Credential or the Notification endpoint, is
    /// refused with 401, <c>invalid_token</c> and the one challenge <c>Bearer realm="&lt;issuer&gt;", error="invalid_token"</c>.
    /// </summary>
    /// <param name="endpointName">The protected endpoint addressed.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(CredentialEndpointRow)]
    [DataRow(DeferredEndpointRow)]
    [DataRow(NotificationEndpointRow)]
    public async Task AProtectedEndpointRefusesATokenWithoutAnAudienceAsync(string endpointName)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce,
            EndpointCapabilities.Add(WellKnownCapabilityIdentifiers.Oid4VciCredentialEndpoint)).ConfigureAwait(false);
        await WireProtectedEndpointSeamsAsync(host).ConfigureAwait(false);

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);
        string withoutAudience = await CompactJwsResigning.ResignWithAlteredPayloadAsync(
            host, accessToken, material.SigningKeyId, static payload => payload.Remove("aud")).ConfigureAwait(false);

        using HttpResponseMessage response = await SendProtectedOverWireAsync(
            host, material, endpointName, "Bearer " + withoutAudience, ProtectedRequestBody(endpointName)).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        AssertInvalidTokenRefusal(response, body, IssuerOf(host, material));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-5.1">RFC 9728 Section 5.1</see>: "This parameter MAY
    /// also be used in WWW-Authenticate responses using authorization schemes other than "Bearer" [RFC6750], such as the
    /// DPoP scheme defined by [RFC9449]." Under a registration allowing
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata"/>, a value that is no access token
    /// presented under the <c>DPoP</c> scheme over the wire at the endpoint a row addresses is refused with 401 and exactly
    /// the one challenge <c>DPoP realm="&lt;issuer&gt;", error="invalid_token", algs="...", resource_metadata="&lt;document&gt;"</c>,
    /// the document's URL formed by inserting <c>/.well-known/oauth-protected-resource</c> between the host and the path
    /// of the endpoint's URL. The rows: the Deferred Credential Endpoint; the Notification Endpoint.
    /// </summary>
    /// <param name="endpointName">The protected endpoint addressed.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(DeferredEndpointRow)]
    [DataRow(NotificationEndpointRow)]
    public async Task ProtectedEndpointDpopChallengeNamesItsResourceMetadataAsync(string endpointName)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, DocumentServingCapabilities).ConfigureAwait(false);
        await WireProtectedEndpointSeamsAsync(host).ConfigureAwait(false);

        using HttpResponseMessage response = await SendProtectedOverWireAsync(
            host, material, endpointName, "DPoP not.an.access-token", ProtectedRequestBody(endpointName)).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode, body);
        Assert.AreEqual(
            ResourceDpopProofs.DpopChallenge(
                IssuerOf(host, material), "invalid_token", resourceMetadata: new Uri(DocumentUrlOf(EndpointUrlOf(host, material, endpointName)))),
            Assert.ContainsSingle(RawAuthCodeWirePushers.ChallengesOf(response)));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3">RFC 9728 Section 3</see>: "Protected resources
    /// supporting metadata MUST make a JSON document containing metadata as specified in Section 2 available at a URL
    /// formed by inserting a well-known URI string into the protected resource's resource identifier between the host
    /// component and the path and/or query components, if any.", with <see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">Section
    /// 2</see>: "resource REQUIRED. The protected resource's resource identifier, as defined in Section 1.2." and
    /// "authorization_servers OPTIONAL. JSON array containing a list of OAuth authorization server issuer identifiers".
    /// Under a registration allowing <see cref="WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata"/>, a GET
    /// of the document of the endpoint a row addresses over a raw TLS connection is answered 200 <c>application/json</c>
    /// with exactly the document
    /// <c>{"resource":"&lt;endpoint&gt;","authorization_servers":["&lt;issuer&gt;"],"bearer_methods_supported":["header"],"dpop_signing_alg_values_supported":[...]}</c>,
    /// no <c>jwks_uri</c> (the registration serves no JWK Set) and no <c>scopes_supported</c>. The rows: the Credential
    /// Endpoint; the Deferred Credential Endpoint; the Notification Endpoint.
    /// </summary>
    /// <param name="endpointName">The protected endpoint addressed.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(CredentialEndpointRow)]
    [DataRow(DeferredEndpointRow)]
    [DataRow(NotificationEndpointRow)]
    public async Task ProtectedEndpointProtectedResourceMetadataDocumentNamesTheEndpointAsync(string endpointName)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, DocumentServingCapabilities).ConfigureAwait(false);
        await WireProtectedEndpointSeamsAsync(host).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Uri endpointUrl = EndpointUrlOf(host, material, endpointName);

        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Get, new Uri(host.Host("default").HttpBaseAddress!, new Uri(DocumentUrlOf(endpointUrl)).AbsolutePath), [],
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The document is served without a server fault.");
        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.AreEqual(
            WellKnownMediaTypes.Application.Json,
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.ContentType)).Split(';')[0].Trim());
        string algorithms = "[" + string.Join(",", ResourceDpopProofs.AcceptedProofAlgorithms.Split(' ').Select(static name => $"\"{name}\"")) + "]";
        Assert.AreEqual(
            $"{{\"resource\":\"{endpointUrl}\",\"authorization_servers\":[\"{IssuerOf(host, material)}\"],"
            + $"\"bearer_methods_supported\":[\"header\"],\"dpop_signing_alg_values_supported\":{algorithms}}}",
            response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-4">RFC 9728 Section 4</see>: "protected_resources
    /// OPTIONAL. JSON array containing a list of resource identifiers for OAuth protected resources that can be used with
    /// this authorization server." Under a registration allowing UserInfo, the Credential, Deferred Credential and
    /// Notification endpoints, the discovery endpoint and
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata"/>, a GET of the discovery document over a
    /// raw TLS connection is answered 200 with <c>protected_resources</c> exactly the four resources' identifiers, the
    /// URLs the host advertises for them, in the order the server's endpoint chain holds them:
    /// <c>["&lt;UserInfo&gt;","&lt;Credential&gt;","&lt;Deferred Credential&gt;","&lt;Notification&gt;"]</c>. The
    /// server's two lists agree: for each listed identifier, a GET over a raw TLS connection of the document at the
    /// location formed from it is answered 200 with <c>resource</c> the listed entry, code point for code point, and
    /// <c>authorization_servers</c> naming the discovery document's <c>issuer</c>, the cross-check Section 4 leaves to
    /// the application profile ("Note that if the set of legitimate authorization servers to use with a protected
    /// resource is also enumerable, lists in the authorization server metadata and protected resource metadata should
    /// be cross-checked against one another for consistency when these lists are used by the application profile.").
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task DiscoveryListsTheResourcesWhoseDocumentsAreServedAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, DiscoveryCapabilities).ConfigureAwait(false);
        await WireProtectedEndpointSeamsAsync(host).ConfigureAwait(false);

        HttpResponseData response = await GetDiscoveryOverWireAsync(host, material).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The discovery document is served without a server fault.");
        Assert.AreEqual(200, response.StatusCode, response.Body);
        using JsonDocument document = JsonDocument.Parse(response.Body);
        Assert.IsTrue(document.RootElement.TryGetProperty(
            AuthorizationServerMetadataParameterNames.ProtectedResources, out JsonElement protectedResources), response.Body);
        Assert.AreEqual(JsonStringArrayOf(LibraryResourceIdentifiersOf(host, material)), protectedResources.GetRawText());
        string discoveryIssuer = document.RootElement.GetProperty(AuthorizationServerMetadataParameterNames.Issuer).GetString()!;
        foreach(JsonElement entry in protectedResources.EnumerateArray())
        {
            //Each listed resource's own document, fetched at the location formed from the listed identifier.
            string listedIdentifier = entry.GetString()!;
            HttpResponseData resourceDocument = await RawHttpsRequest.SendAsync(
                host, WellKnownHttpMethods.Get,
                new Uri(host.Host("default").HttpBaseAddress!, new Uri(DocumentUrlOf(new Uri(listedIdentifier))).AbsolutePath), [],
                ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(200, resourceDocument.StatusCode, resourceDocument.Body);
            using JsonDocument resourceMetadata = JsonDocument.Parse(resourceDocument.Body);
            string servedResource = resourceMetadata.RootElement.GetProperty("resource").GetString()!;
            Assert.IsTrue(string.Equals(listedIdentifier, servedResource, StringComparison.Ordinal),
                $"The listed entry {listedIdentifier} is the resource its document states, {servedResource}.");
            Assert.AreEqual(
                JsonStringArrayOf([discoveryIssuer]),
                resourceMetadata.RootElement.GetProperty("authorization_servers").GetRawText(),
                "The listed resource's document names the authorization server that lists it.");
        }

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "Every listed resource's document is served without a server fault.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8414#section-3.2">RFC 8414 Section 3.2</see>: "Claims that return
    /// multiple values are represented as JSON arrays. Claims with zero elements MUST be omitted from the response." Under
    /// a registration allowing UserInfo, the Credential, Deferred Credential and Notification endpoints and the discovery
    /// endpoint but not <see cref="WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata"/>, none of the four
    /// resources has a document, so a GET of the discovery document over a raw TLS connection is answered 200 without
    /// <c>protected_resources</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task DiscoveryOmitsProtectedResourcesWhenNoDocumentIsServedAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce,
            DiscoveryCapabilities.Remove(WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata)).ConfigureAwait(false);
        await WireProtectedEndpointSeamsAsync(host).ConfigureAwait(false);

        HttpResponseData response = await GetDiscoveryOverWireAsync(host, material).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The discovery document is served without a server fault.");
        Assert.AreEqual(200, response.StatusCode, response.Body);
        using JsonDocument document = JsonDocument.Parse(response.Body);
        Assert.IsTrue(document.RootElement.TryGetProperty(
            OpenIdProviderMetadataParameterNames.UserinfoEndpoint, out _), "UserInfo is on the chain.");
        Assert.IsFalse(document.RootElement.TryGetProperty(
            AuthorizationServerMetadataParameterNames.ProtectedResources, out _), response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-4">RFC 9728 Section 4</see>: "protected_resources
    /// OPTIONAL. JSON array containing a list of resource identifiers for OAuth protected resources that can be used with
    /// this authorization server.", one member (<see href="https://www.rfc-editor.org/rfc/rfc8259#section-4">RFC 8259
    /// Section 4</see>: "The names within an object SHOULD be unique."). Under the registration of
    /// <see cref="DiscoveryListsTheResourcesWhoseDocumentsAreServedAsync"/> with a discovery contribution naming
    /// <c>protected_resources</c> as <c>["&lt;UserInfo&gt;","https://rs.example/own"]</c>, a GET of the discovery document
    /// over a raw TLS connection is answered 200 with one <c>protected_resources</c>, exactly the four resources'
    /// identifiers in the chain's order and then <c>https://rs.example/own</c>, UserInfo's identifier once.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task DiscoveryListsTheContributedResourcesAfterTheServedOnesAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, DiscoveryCapabilities).ConfigureAwait(false);
        await WireProtectedEndpointSeamsAsync(host).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string userInfo = EndpointUrlOf(host, material, UserInfoEndpointRow).ToString();
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ContributeDiscoveryFieldsAsync = (_, _, _) =>
                ValueTask.FromResult(new DiscoveryDocumentContribution(
                    [new DiscoveryStringArrayField(AuthorizationServerMetadataParameterNames.ProtectedResources, [userInfo, OwnResource])]));
        }).ConfigureAwait(false);

        HttpResponseData response = await GetDiscoveryOverWireAsync(host, material).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The discovery document is served without a server fault.");
        Assert.AreEqual(200, response.StatusCode, response.Body);
        string expected = JsonStringArrayOf([.. LibraryResourceIdentifiersOf(host, material), OwnResource]);
        Assert.Contains($"\"{AuthorizationServerMetadataParameterNames.ProtectedResources}\":{expected}", response.Body);
        Assert.AreEqual(
            1,
            response.Body.Split($"\"{AuthorizationServerMetadataParameterNames.ProtectedResources}\":").Length - 1,
            "The member is written once.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8414#section-3.2">RFC 8414 Section 3.2</see>: "Claims that return
    /// multiple values are represented as JSON arrays. Claims with zero elements MUST be omitted from the response." Under
    /// the registration of <see cref="DiscoveryOmitsProtectedResourcesWhenNoDocumentIsServedAsync"/>, where none of the
    /// four resources has a document, with a discovery contribution naming <c>protected_resources</c> as <c>[]</c>, a GET
    /// of the discovery document over a raw TLS connection is answered 200 without <c>protected_resources</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task DiscoveryOmitsAnEmptyContributedResourceListAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce,
            DiscoveryCapabilities.Remove(WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata)).ConfigureAwait(false);
        await WireProtectedEndpointSeamsAsync(host).ConfigureAwait(false);
        await ContributeProtectedResourceListsAsync(host, [[]]).ConfigureAwait(false);

        HttpResponseData response = await GetDiscoveryOverWireAsync(host, material).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The discovery document is served without a server fault.");
        Assert.AreEqual(200, response.StatusCode, response.Body);
        using JsonDocument document = JsonDocument.Parse(response.Body);
        Assert.IsFalse(document.RootElement.TryGetProperty(
            AuthorizationServerMetadataParameterNames.ProtectedResources, out _), response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-4">RFC 9728 Section 4</see>: "protected_resources
    /// OPTIONAL. JSON array containing a list of resource identifiers for OAuth protected resources that can be used with
    /// this authorization server.", one member (<see href="https://www.rfc-editor.org/rfc/rfc8259#section-4">RFC 8259
    /// Section 4</see>: "The names within an object SHOULD be unique."). Under the registration of
    /// <see cref="DiscoveryListsTheResourcesWhoseDocumentsAreServedAsync"/> with a discovery contribution naming
    /// <c>protected_resources</c> twice, as <c>["https://rs.example/a"]</c> and then as
    /// <c>["&lt;UserInfo&gt;","https://rs.example/b"]</c>, a GET of the discovery document over a raw TLS connection is
    /// answered 200 with one <c>protected_resources</c>, exactly the four resources' identifiers in the chain's order,
    /// then <c>https://rs.example/a</c>, then <c>https://rs.example/b</c>, UserInfo's identifier once.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task DiscoveryMergesEveryContributedResourceListInOrderAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, DiscoveryCapabilities).ConfigureAwait(false);
        await WireProtectedEndpointSeamsAsync(host).ConfigureAwait(false);
        string userInfo = EndpointUrlOf(host, material, UserInfoEndpointRow).ToString();
        await ContributeProtectedResourceListsAsync(host, [[FirstOwnResource], [userInfo, SecondOwnResource]]).ConfigureAwait(false);

        HttpResponseData response = await GetDiscoveryOverWireAsync(host, material).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The discovery document is served without a server fault.");
        Assert.AreEqual(200, response.StatusCode, response.Body);
        string expected = JsonStringArrayOf([.. LibraryResourceIdentifiersOf(host, material), FirstOwnResource, SecondOwnResource]);
        Assert.Contains($"\"{AuthorizationServerMetadataParameterNames.ProtectedResources}\":{expected}", response.Body);
        Assert.AreEqual(
            1,
            response.Body.Split($"\"{AuthorizationServerMetadataParameterNames.ProtectedResources}\":").Length - 1,
            "The member is written once.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-4">RFC 9728 Section 4</see>: "protected_resources
    /// OPTIONAL. JSON array containing a list of resource identifiers for OAuth protected resources that can be used with
    /// this authorization server." Under the registration of
    /// <see cref="DiscoveryOmitsProtectedResourcesWhenNoDocumentIsServedAsync"/>, where none of the four resources has a
    /// document, with a discovery contribution naming <c>protected_resources</c> as <c>["https://rs.example/own"]</c>, a
    /// GET of the discovery document over a raw TLS connection is answered 200 with <c>protected_resources</c> exactly
    /// <c>["https://rs.example/own"]</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task DiscoveryListsTheContributedResourcesAloneWhenNoDocumentIsServedAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce,
            DiscoveryCapabilities.Remove(WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata)).ConfigureAwait(false);
        await WireProtectedEndpointSeamsAsync(host).ConfigureAwait(false);
        await ContributeProtectedResourceListsAsync(host, [[OwnResource]]).ConfigureAwait(false);

        HttpResponseData response = await GetDiscoveryOverWireAsync(host, material).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The discovery document is served without a server fault.");
        Assert.AreEqual(200, response.StatusCode, response.Body);
        using JsonDocument document = JsonDocument.Parse(response.Body);
        Assert.IsTrue(document.RootElement.TryGetProperty(
            AuthorizationServerMetadataParameterNames.ProtectedResources, out JsonElement protectedResources), response.Body);
        Assert.AreEqual(JsonStringArrayOf([OwnResource]), protectedResources.GetRawText());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">RFC 9728 Section 2</see>:
    /// "authorization_details_types_supported OPTIONAL. JSON array containing a list of the authorization details type
    /// values supported by the resource server when the authorization_details request parameter [RFC9396] is used."
    /// Under a registration allowing the authorization code and pre-authorized code grants and
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata"/>, with the authorization details
    /// parsing and the credential authorization seam wired, a GET of the document of the endpoint a row addresses over a
    /// raw TLS connection is answered 200 with exactly the document
    /// <c>{"resource":"&lt;endpoint&gt;","authorization_servers":["&lt;issuer&gt;"],"bearer_methods_supported":["header"],"authorization_details_types_supported":["openid_credential"],"dpop_signing_alg_values_supported":[...]}</c>.
    /// The rows: the Credential Endpoint; the Deferred Credential Endpoint; the Notification Endpoint.
    /// </summary>
    /// <param name="endpointName">The protected endpoint addressed.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(CredentialEndpointRow)]
    [DataRow(DeferredEndpointRow)]
    [DataRow(NotificationEndpointRow)]
    public async Task ProtectedEndpointDocumentNamesTheAuthorizationDetailsTypesItsGrantsProcessAsync(string endpointName)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, DocumentServingCapabilities).ConfigureAwait(false);
        await WireProtectedEndpointSeamsAsync(host).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
            candidateIntegration.ResolveCredentialAuthorizationAsync = static (_, _, _, _, _) =>
                throw new NotImplementedException("A document request never asks for a credential authorization decision.");
        }).ConfigureAwait(false);

        HttpResponseData response = await GetDocumentOverWireAsync(host, material, endpointName).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The document is served without a server fault.");
        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.AreEqual(
            DocumentOf(EndpointUrlOf(host, material, endpointName), IssuerOf(host, material), "[\"openid_credential\"]"),
            response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.2">RFC 9728 Section 3.2</see>: "Parameters with
    /// multiple values are represented as JSON arrays. Parameters with zero values MUST be omitted from the response."
    /// Under the registration of <see cref="ProtectedEndpointDocumentNamesTheAuthorizationDetailsTypesItsGrantsProcessAsync"/>
    /// with the authorization details parsing wired and the credential authorization seam not, a token request carrying
    /// <c>authorization_details</c> is refused, so the resource supports no type and a GET of the document of the endpoint
    /// a row addresses over a raw TLS connection is answered 200 with exactly the document
    /// <c>{"resource":"&lt;endpoint&gt;","authorization_servers":["&lt;issuer&gt;"],"bearer_methods_supported":["header"],"dpop_signing_alg_values_supported":[...]}</c>,
    /// without <c>authorization_details_types_supported</c>. The rows: the Credential Endpoint; the Deferred Credential
    /// Endpoint; the Notification Endpoint.
    /// </summary>
    /// <param name="endpointName">The protected endpoint addressed.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(CredentialEndpointRow)]
    [DataRow(DeferredEndpointRow)]
    [DataRow(NotificationEndpointRow)]
    public async Task ProtectedEndpointDocumentOmitsTheAuthorizationDetailsTypesWithoutTheDecisionSeamAsync(string endpointName)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, DocumentServingCapabilities).ConfigureAwait(false);
        await WireProtectedEndpointSeamsAsync(host).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.AuthorizationDetailTypes.Register(new AuthorizationDetailHandler
            {
                Type = SecondAuthorizationDetailsType,
                ValidateShape = static (_, _) => null
            });

            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
        }).ConfigureAwait(false);

        HttpResponseData response = await GetDocumentOverWireAsync(host, material, endpointName).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The document is served without a server fault.");
        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.AreEqual(DocumentOf(EndpointUrlOf(host, material, endpointName), IssuerOf(host, material), null), response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">RFC 9728 Section 2</see>:
    /// "authorization_details_types_supported OPTIONAL. JSON array containing a list of the authorization details type
    /// values supported by the resource server when the authorization_details request parameter [RFC9396] is used." The
    /// credential issuer's resources process the authorization details of type <c>openid_credential</c>, the type whose
    /// details a token grant turns into <c>credential_identifiers</c>
    /// (<see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.2">OpenID for
    /// Verifiable Credential Issuance 1.0 Section 6.2</see>), and no other. Under the registration of
    /// <see cref="ProtectedEndpointDocumentNamesTheAuthorizationDetailsTypesItsGrantsProcessAsync"/>, with a second type,
    /// <c>payment_initiation</c>, registered beside <c>openid_credential</c> and the authorization details parsing and the
    /// credential authorization seam wired, a GET of the document of the endpoint a row addresses over a raw TLS
    /// connection is answered 200 with exactly the document
    /// <c>{"resource":"&lt;endpoint&gt;","authorization_servers":["&lt;issuer&gt;"],"bearer_methods_supported":["header"],"authorization_details_types_supported":["openid_credential"],"dpop_signing_alg_values_supported":[...]}</c>,
    /// the second type not named. The rows: the Credential Endpoint; the Deferred Credential Endpoint; the Notification
    /// Endpoint.
    /// </summary>
    /// <param name="endpointName">The protected endpoint addressed.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(CredentialEndpointRow)]
    [DataRow(DeferredEndpointRow)]
    [DataRow(NotificationEndpointRow)]
    public async Task ProtectedEndpointDocumentNamesOnlyTheAuthorizationDetailsTypeTheResourceProcessesAsync(string endpointName)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, DocumentServingCapabilities).ConfigureAwait(false);
        await WireProtectedEndpointSeamsAsync(host).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.AuthorizationDetailTypes.Register(new AuthorizationDetailHandler
            {
                Type = SecondAuthorizationDetailsType,
                ValidateShape = static (_, _) => null
            });

            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
            candidateIntegration.ResolveCredentialAuthorizationAsync = static (_, _, _, _, _) =>
                throw new NotImplementedException("A document request never asks for a credential authorization decision.");
        }).ConfigureAwait(false);

        HttpResponseData response = await GetDocumentOverWireAsync(host, material, endpointName).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The document is served without a server fault.");
        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.AreEqual(
            DocumentOf(EndpointUrlOf(host, material, endpointName), IssuerOf(host, material), "[\"openid_credential\"]"),
            response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">RFC 9728 Section 2</see>:
    /// "authorization_details_types_supported OPTIONAL. JSON array containing a list of the authorization details type
    /// values supported by the resource server when the authorization_details request parameter [RFC9396] is used." The
    /// parameter is used through either token grant that processes it, the authorization code grant or the OID4VCI
    /// pre-authorized code grant, so under a registration allowing the Credential Endpoint,
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata"/> and one of the two grants alone, with
    /// the pre-authorized code validation, the authorization details parsing and the credential authorization seam
    /// wired, a GET of the Credential Endpoint's document over a raw TLS connection is answered 200 with exactly the
    /// document
    /// <c>{"resource":"&lt;endpoint&gt;","authorization_servers":["&lt;issuer&gt;"],"bearer_methods_supported":["header"],"authorization_details_types_supported":["openid_credential"],"dpop_signing_alg_values_supported":[...]}</c>.
    /// The rows: the authorization code grant without the pre-authorized code grant; the pre-authorized code grant without
    /// the authorization code grant.
    /// </summary>
    /// <param name="grantRow">The grant the registration allows alone.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(AuthorizationCodeGrantAloneRow)]
    [DataRow(PreAuthorizedCodeGrantAloneRow)]
    public async Task CredentialEndpointDocumentNamesTheAuthorizationDetailsTypeUnderEitherGrantAloneAsync(string grantRow)
    {
        ImmutableHashSet<CapabilityIdentifier> capabilities = grantRow switch
        {
            AuthorizationCodeGrantAloneRow => DocumentServingCapabilities.Remove(WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant),
            PreAuthorizedCodeGrantAloneRow => DocumentServingCapabilities.Remove(WellKnownCapabilityIdentifiers.OAuthAuthorizationCode),
            _ => throw new ArgumentOutOfRangeException(nameof(grantRow), grantRow, "Unknown grant row.")
        };

        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, capabilities).ConfigureAwait(false);
        await WireProtectedEndpointSeamsAsync(host).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidatePreAuthorizedCodeAsync = static (_, _, _, _, _, _) =>
                throw new NotImplementedException("A document request never asks for a pre-authorized code decision.");
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
            candidateIntegration.ResolveCredentialAuthorizationAsync = static (_, _, _, _, _) =>
                throw new NotImplementedException("A document request never asks for a credential authorization decision.");
        }).ConfigureAwait(false);

        HttpResponseData response = await GetDocumentOverWireAsync(host, material, CredentialEndpointRow).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The document is served without a server fault.");
        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.AreEqual(
            DocumentOf(EndpointUrlOf(host, material, CredentialEndpointRow), IssuerOf(host, material), "[\"openid_credential\"]"),
            response.Body);
    }


    /// <summary>
    /// Wires a discovery contribution naming <c>protected_resources</c> once for each of <paramref name="lists"/>, each as
    /// a string array of its values, in the order given.
    /// </summary>
    /// <param name="host">The host whose integration is altered.</param>
    /// <param name="lists">The contributed lists.</param>
    /// <returns>A task that completes when the contribution is wired.</returns>
    private static async Task ContributeProtectedResourceListsAsync(TestHostShell host, IReadOnlyList<IReadOnlyList<string>> lists)
    {
        DiscoveryDocumentContribution contribution = new(
            [.. lists.Select(static list => new DiscoveryStringArrayField(AuthorizationServerMetadataParameterNames.ProtectedResources, list))]);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ContributeDiscoveryFieldsAsync = (_, _, _) => ValueTask.FromResult(contribution);
        }).ConfigureAwait(false);
    }


    /// <summary>A first protected resource the application alone knows of.</summary>
    private static string FirstOwnResource { get; } = "https://rs.example/a";


    /// <summary>A second protected resource the application alone knows of.</summary>
    private static string SecondOwnResource { get; } = "https://rs.example/b";


    /// <summary>
    /// The row whose registration allows the authorization code grant and not the pre-authorized code grant. A constant,
    /// not a property, because a DataRow attribute argument must be a compile-time constant.
    /// </summary>
    private const string AuthorizationCodeGrantAloneRow = "authorization-code-grant-alone";


    /// <summary>
    /// The row whose registration allows the pre-authorized code grant and not the authorization code grant. A constant,
    /// not a property, because a DataRow attribute argument must be a compile-time constant.
    /// </summary>
    private const string PreAuthorizedCodeGrantAloneRow = "pre-authorized-code-grant-alone";


    /// <summary>
    /// The capabilities of <see cref="LibraryResourceCapabilities"/> and
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint"/>, under which the discovery document lists the
    /// four resources of the library. Computed on each read, so it never reads <see cref="LibraryResourceCapabilities"/>
    /// before that property is initialized.
    /// </summary>
    private static ImmutableHashSet<CapabilityIdentifier> DiscoveryCapabilities =>
        LibraryResourceCapabilities.Add(WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint);


    /// <summary>A protected resource the application alone knows of, named by its discovery contribution.</summary>
    private static string OwnResource { get; } = "https://rs.example/own";


    /// <summary>An authorization details type registered beside <c>openid_credential</c>.</summary>
    private static string SecondAuthorizationDetailsType { get; } = "payment_initiation";


    /// <summary>
    /// The identifiers of the four resources of the library, the URLs the host advertises for them, in the order the
    /// server's endpoint chain holds them: UserInfo, then the Credential, Deferred Credential and Notification endpoints.
    /// </summary>
    /// <param name="host">The host holding the registration.</param>
    /// <param name="material">The registration.</param>
    /// <returns>The identifiers.</returns>
    private static IReadOnlyList<string> LibraryResourceIdentifiersOf(TestHostShell host, VerifierKeyMaterial material) =>
    [
        EndpointUrlOf(host, material, UserInfoEndpointRow).ToString(),
        EndpointUrlOf(host, material, CredentialEndpointRow).ToString(),
        EndpointUrlOf(host, material, DeferredEndpointRow).ToString(),
        EndpointUrlOf(host, material, NotificationEndpointRow).ToString()
    ];


    /// <summary>The JSON array of <paramref name="values"/>, each a JSON string, written without whitespace.</summary>
    /// <param name="values">The values.</param>
    /// <returns>The array text.</returns>
    private static string JsonStringArrayOf(IReadOnlyList<string> values) =>
        "[" + string.Join(",", values.Select(static value => $"\"{value}\"")) + "]";


    /// <summary>
    /// The protected resource metadata document of the endpoint a row addresses, written out member by member in the
    /// order the document is written: <c>resource</c>, <c>authorization_servers</c>, <c>bearer_methods_supported</c>
    /// <c>["header"]</c>, <c>authorization_details_types_supported</c> when given, then
    /// <c>dpop_signing_alg_values_supported</c>.
    /// </summary>
    /// <param name="endpointUrl">The endpoint's URL, the document's resource.</param>
    /// <param name="issuer">The issuer, the one authorization server named.</param>
    /// <param name="authorizationDetailsTypes">The <c>authorization_details_types_supported</c> JSON array, or <see langword="null"/> for none.</param>
    /// <returns>The document text.</returns>
    private static string DocumentOf(Uri endpointUrl, string issuer, string? authorizationDetailsTypes)
    {
        string algorithms = JsonStringArrayOf(ResourceDpopProofs.AcceptedProofAlgorithms.Split(' '));
        string detailTypesMember = authorizationDetailsTypes is null
            ? string.Empty
            : $",\"authorization_details_types_supported\":{authorizationDetailsTypes}";

        return $"{{\"resource\":\"{endpointUrl}\",\"authorization_servers\":[\"{issuer}\"],\"bearer_methods_supported\":[\"header\"]"
            + $"{detailTypesMember},\"dpop_signing_alg_values_supported\":{algorithms}}}";
    }


    /// <summary>
    /// Starts the host's listener and GETs the discovery document of the registration over a raw TLS connection, at the
    /// URL the host advertises for <see cref="WellKnownEndpointNames.MetadataDiscovery"/>.
    /// </summary>
    /// <param name="host">The host whose listener serves the request.</param>
    /// <param name="material">The registration.</param>
    /// <returns>The wire response.</returns>
    private async Task<HttpResponseData> GetDiscoveryOverWireAsync(TestHostShell host, VerifierKeyMaterial material)
    {
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        return await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Get,
            new Uri(host.Host("default").HttpBaseAddress!,
                TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.MetadataDiscovery, material.Registration.TenantId.Value)),
            [], ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Starts the host's listener and GETs the protected resource metadata document of the endpoint a row addresses over a
    /// raw TLS connection, at the endpoint's path with <c>/.well-known/oauth-protected-resource</c> inserted before it.
    /// </summary>
    /// <param name="host">The host whose listener serves the request.</param>
    /// <param name="material">The registration.</param>
    /// <param name="row">The endpoint row.</param>
    /// <returns>The wire response.</returns>
    private async Task<HttpResponseData> GetDocumentOverWireAsync(TestHostShell host, VerifierKeyMaterial material, string row)
    {
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Uri endpointUrl = EndpointUrlOf(host, material, row);

        return await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Get, new Uri(host.Host("default").HttpBaseAddress!, new Uri(DocumentUrlOf(endpointUrl)).AbsolutePath), [],
            ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// The capabilities of <see cref="EndpointCapabilities"/>, the Credential Endpoint and
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata"/>, under which the protected resource
    /// metadata documents of the three protected endpoints are served.
    /// </summary>
    private static ImmutableHashSet<CapabilityIdentifier> DocumentServingCapabilities { get; } = EndpointCapabilities
        .Add(WellKnownCapabilityIdentifiers.Oid4VciCredentialEndpoint)
        .Add(WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata);


    /// <summary>
    /// The URL the host advertises for the endpoint a wire row addresses, its resource identifier: the endpoint's path
    /// under the authority of the issuer the host holds for the registration, as the host's endpoint resolver composes it.
    /// </summary>
    /// <param name="host">The host holding the registration.</param>
    /// <param name="material">The registration.</param>
    /// <param name="row">The endpoint row.</param>
    /// <returns>The endpoint's URL.</returns>
    private static Uri EndpointUrlOf(TestHostShell host, VerifierKeyMaterial material, string row) =>
        new(new Uri(IssuerOf(host, material)), TestHostShell.ComposeEndpointPath(EndpointNameOf(row), material.Registration.TenantId.Value));


    /// <summary>
    /// The URL a protected resource metadata document is served at for the resource <paramref name="identifier"/>
    /// identifies, written out: <c>/.well-known/oauth-protected-resource</c> inserted between the host and the path
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.1">RFC 9728 Section 3.1</see>: "GET
    /// /.well-known/oauth-protected-resource/resource1 HTTP/1.1").
    /// </summary>
    /// <param name="identifier">The resource identifier, an https URL with a path and no query.</param>
    /// <returns>The document's URL.</returns>
    private static string DocumentUrlOf(Uri identifier) =>
        $"{identifier.GetLeftPart(UriPartial.Authority)}/.well-known/oauth-protected-resource{identifier.AbsolutePath}";


    /// <summary>The identifier of a resource other than this Authorization Server.</summary>
    private static string OtherResourceAudience { get; } = "https://rs.example.com";

    /// <summary>The row addressing the Credential Endpoint.</summary>
    private const string CredentialEndpointRow = "oid4vci-credential";

    /// <summary>The row addressing the Deferred Credential Endpoint.</summary>
    private const string DeferredEndpointRow = "oid4vci-deferred-credential";

    /// <summary>The row addressing the Notification Endpoint.</summary>
    private const string NotificationEndpointRow = "oid4vci-notification";

    /// <summary>The row whose configured issuer holds Unicode text in its path.</summary>
    private const string UnicodePathIssuerRow = "unicode-path-issuer";

    /// <summary>The row whose configured issuer holds Unicode text in its host.</summary>
    private const string UnicodeHostIssuerRow = "unicode-host-issuer";

    /// <summary>
    /// The row addressing UserInfo. A constant, not a property, because a DataRow attribute argument must be a
    /// compile-time constant.
    /// </summary>
    private const string UserInfoEndpointRow = "userinfo";

    /// <summary>
    /// The row whose endpoint resolver answers the Credential Endpoint at UserInfo's path with a terminating slash. A
    /// constant, not a property, because a DataRow attribute argument must be a compile-time constant.
    /// </summary>
    private const string TrailingSlashLocationsRow = "trailing-slash-locations";

    /// <summary>
    /// The row whose endpoint resolver answers UserInfo at the URL the issuer's own document is located from. A
    /// constant, not a property, because a DataRow attribute argument must be a compile-time constant.
    /// </summary>
    private const string IssuerDocumentLocationRow = "issuer-document-location";


    /// <summary>
    /// The capabilities of <see cref="DocumentServingCapabilities"/> and
    /// <see cref="WellKnownCapabilityIdentifiers.OidcUserInfo"/>, under which the four resources of the library each
    /// have a protected resource metadata document.
    /// </summary>
    private static ImmutableHashSet<CapabilityIdentifier> LibraryResourceCapabilities { get; } =
        DocumentServingCapabilities.Add(WellKnownCapabilityIdentifiers.OidcUserInfo);


    /// <summary>
    /// The internationalized issuer the rows configure, <c>https://b</c> U+00FC <c>cher.example/tenant</c>, its host a
    /// label above U+007F.
    /// </summary>
    private static Uri InternationalizedIssuer { get; } = new("https://b" + (char)0x00FC + "cher.example/tenant");

    /// <summary>
    /// <see cref="InternationalizedIssuer"/> in its URI form, the host converted by the IDNA ToASCII operation
    /// (<see href="https://www.rfc-editor.org/rfc/rfc3987#section-3.1">RFC 3987 Section 3.1</see>).
    /// </summary>
    private static string InternationalizedIssuerInUriForm { get; } = "https://xn--bcher-kva.example/tenant";

    /// <summary>The scheme and authority of <see cref="InternationalizedIssuerInUriForm"/>.</summary>
    private static string InternationalizedAuthorityInUriForm { get; } = "https://xn--bcher-kva.example";


    /// <summary>
    /// Starts the host's listener and replaces the registration the host serves with one whose issuer is
    /// <see cref="InternationalizedIssuer"/>, so every URL the host's endpoint resolver answers carries its host.
    /// </summary>
    /// <param name="host">The host holding the registration.</param>
    /// <param name="material">The registration.</param>
    /// <returns>A task that completes when the registration is replaced.</returns>
    private async Task ServeUnderTheInternationalizedIssuerAsync(TestHostShell host, VerifierKeyMaterial material)
    {
        Assert.IsTrue(IssuerIdentifier.Parse(InternationalizedIssuer.OriginalString).IsSuccess,
            "The configured issuer is one the server accepts as an issuer identifier.");
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer served = host.Host("default");
        ClientRecord internationalized = served.Registrations[material.Registration.TenantId.Value] with
        {
            IssuerUri = InternationalizedIssuer
        };
        served.Registrations[internationalized.TenantId.Value] = internationalized;
        served.Registrations[internationalized.ClientId] = internationalized;
    }


    /// <summary>
    /// Sends a request without credentials over a raw TLS connection to the resource a row addresses: a GET to
    /// UserInfo, and a POST of a well-formed JSON body to an OID4VCI endpoint.
    /// </summary>
    /// <param name="host">The host whose listener serves the request.</param>
    /// <param name="material">The registration whose endpoint path is addressed.</param>
    /// <param name="row">The resource row.</param>
    /// <returns>The wire response.</returns>
    private async Task<HttpResponseData> SendWithoutCredentialsAsync(TestHostShell host, VerifierKeyMaterial material, string row)
    {
        Uri url = new(host.Host("default").HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(EndpointNameOf(row), material.Registration.TenantId.Value));
        bool isUserInfo = string.Equals(row, UserInfoEndpointRow, StringComparison.Ordinal);

        return isUserInfo
            ? await RawHttpsRequest.SendAsync(
                host, WellKnownHttpMethods.Get, url, [], ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false)
            : await RawHttpsRequest.SendAsync(
                host, WellKnownHttpMethods.Post, url,
                [new(WellKnownHttpHeaderNames.ContentType, WellKnownMediaTypes.Application.Json)],
                Encoding.UTF8.GetBytes(ProtectedRequestBody(row)), TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// The endpoint name a wire row addresses.
    /// </summary>
    /// <param name="row">The row.</param>
    /// <returns>The endpoint name.</returns>
    private static string EndpointNameOf(string row) => row switch
    {
        CredentialEndpointRow => WellKnownEndpointNames.Oid4VciCredential,
        DeferredEndpointRow => WellKnownEndpointNames.Oid4VciDeferredCredential,
        NotificationEndpointRow => WellKnownEndpointNames.Oid4VciNotification,
        UserInfoEndpointRow => WellKnownEndpointNames.UserInfo,
        _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown endpoint row.")
    };


    /// <summary>A well-formed request body for the endpoint a wire row addresses.</summary>
    /// <param name="row">The row.</param>
    /// <returns>The JSON body.</returns>
    private static string ProtectedRequestBody(string row) => row switch
    {
        CredentialEndpointRow => "{\"credential_configuration_id\":\"UniversityDegree_dc_sd_jwt\",\"proofs\":{\"jwt\":[\"p\"]}}",
        DeferredEndpointRow => $"{{\"transaction_id\":\"{TransactionId}\"}}",
        NotificationEndpointRow => $"{{\"notification_id\":\"{NotificationId}\",\"event\":\"credential_accepted\"}}",
        _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown endpoint row.")
    };


    /// <summary>
    /// The challenge the protected endpoints answer a request without usable credentials with:
    /// <c>Bearer realm="&lt;issuer&gt;", DPoP realm="&lt;issuer&gt;", algs="..."</c>, the realm of both being the issuer
    /// the server holds for the registration.
    /// </summary>
    /// <param name="host">The host holding the registration.</param>
    /// <param name="material">The registration.</param>
    /// <returns>The literal <c>WWW-Authenticate</c> value.</returns>
    private static string MissingCredentialsChallenge(TestHostShell host, VerifierKeyMaterial material) =>
        $"Bearer realm=\"{IssuerOf(host, material)}\", {ResourceDpopProofs.DpopChallenge(IssuerOf(host, material), error: null)}";


    /// <summary>The issuer the host holds for the registration, the realm of the protected endpoints' challenges.</summary>
    /// <param name="host">The host holding the registration.</param>
    /// <param name="material">The registration.</param>
    /// <returns>The issuer, as written.</returns>
    private static string IssuerOf(TestHostShell host, VerifierKeyMaterial material) =>
        host.Host("default").Registrations[material.Registration.TenantId.Value].IssuerUri!.OriginalString;


    /// <summary>
    /// Wires the credential-issuance, deferred-issuance and notification seams, and the default Credential
    /// Request parsing, so each endpoint a registration's capabilities allow is on the chain and serves a
    /// well-formed request.
    /// </summary>
    /// <param name="host">The host whose integration is altered.</param>
    private static async Task WireProtectedEndpointSeamsAsync(TestHostShell host) =>
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultCredentialRequestJsonParsing();
            candidateIntegration.IssueCredentialAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
            candidateIntegration.ResolveDeferredCredentialAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(DeferredCredentialDecision.Defer(60));
            candidateIntegration.ProcessCredentialNotificationAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(CredentialNotificationDecision.Accept);
        }).ConfigureAwait(false);


    /// <summary>
    /// Asserts the refusal of a presented access token over the wire: 401, exactly one
    /// <c>WWW-Authenticate</c> value <c>Bearer realm="&lt;issuer&gt;", error="invalid_token"</c>, and <c>invalid_token</c> as
    /// the body's <c>error</c>.
    /// </summary>
    /// <param name="response">The wire response.</param>
    /// <param name="body">The response body text.</param>
    /// <param name="issuer">The issuer the host holds for the registration, the challenge's realm.</param>
    private static void AssertInvalidTokenRefusal(HttpResponseMessage response, string body, string issuer)
    {
        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode, body);
        Assert.IsTrue(response.Headers.TryGetValues("WWW-Authenticate", out IEnumerable<string>? challenges),
            "RFC 6750 Section 3: the refusal carries a WWW-Authenticate challenge.");
        Assert.AreEqual($"Bearer realm=\"{issuer}\", error=\"invalid_token\"", challenges.Single());
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("invalid_token", document.RootElement.GetProperty("error").GetString());
    }


    /// <summary>
    /// POSTs <paramref name="jsonBody"/> to the endpoint a wire row addresses over the host's loopback
    /// HTTPS listener, with <paramref name="authorization"/> as the <c>Authorization</c> header when given.
    /// </summary>
    /// <param name="host">The host whose listener serves the request.</param>
    /// <param name="material">The registration whose endpoint path is addressed.</param>
    /// <param name="row">The endpoint row.</param>
    /// <param name="authorization">The <c>Authorization</c> header, or <see langword="null"/> for none.</param>
    /// <param name="jsonBody">The JSON request body.</param>
    /// <returns>The wire response; the caller disposes it.</returns>
    private async Task<HttpResponseMessage> SendProtectedOverWireAsync(
        TestHostShell host, VerifierKeyMaterial material, string row, string? authorization, string jsonBody)
    {
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Uri url = new(host.Host("default").HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(EndpointNameOf(row), material.Registration.TenantId.Value));

        using StringContent content = new(jsonBody, Encoding.UTF8, WellKnownMediaTypes.Application.Json);
        using HttpRequestMessage request = new(HttpMethod.Post, url) { Content = content };
        if(authorization is not null)
        {
            _ = request.Headers.TryAddWithoutValidation("Authorization", authorization);
        }

        return await host.Host("default").SharedHttpClient!.SendAsync(request, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Mints a working access token through the §6 Pre-Authorized Code grant — the same token
    /// boundary both endpoints validate.
    /// </summary>
    private async Task<string> MintAccessTokenAsync(TestHostShell host, VerifierKeyMaterial material)
    {
        //OID4VCI 1.0 §13.10: "Long-lived Access Tokens giving access to Credentials MUST not be
        //issued unless sender-constrained." Keep this plain-bearer credential token within the
        //long-lived threshold (lifetimes longer than 5 minutes are considered long lived).
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidatePreAuthorizedCodeAsync =
                (code, txCode, clientId, registration, context, ct) =>
                    ValueTask.FromResult(PreAuthorizedCodeDecision.Grant(OfferSubject, WellKnownScopes.OpenId));
        }).ConfigureAwait(false);

        ServerHttpResponse tokenResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciPreAuthorizedToken,
            "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.PreAuthorizedCode,
                [OAuthRequestParameterNames.PreAuthorizedCode] = "SplxlOBeZQQYbYS6WxSbIA"
            },
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);

        using JsonDocument doc = JsonDocument.Parse(tokenResponse.Body);

        return doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
    }


    private async Task<ServerHttpResponse> DispatchDeferredAsync(
        TestHostShell host, VerifierKeyMaterial material, string? bearer, string jsonBody) =>
        await DispatchProtectedAsync(
            host, material, WellKnownEndpointNames.Oid4VciDeferredCredential, bearer, jsonBody)
            .ConfigureAwait(false);


    private async Task<ServerHttpResponse> DispatchNotificationAsync(
        TestHostShell host, VerifierKeyMaterial material, string? bearer, string jsonBody) =>
        await DispatchProtectedAsync(
            host, material, WellKnownEndpointNames.Oid4VciNotification, bearer, jsonBody)
            .ConfigureAwait(false);


    private async Task<ServerHttpResponse> DispatchProtectedAsync(
        TestHostShell host,
        VerifierKeyMaterial material,
        string endpointName,
        string? bearer,
        string jsonBody)
    {
        RequestHeaders headers = bearer is null
            ? RequestHeaders.Empty
            : new RequestHeaders(new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                [WellKnownHttpHeaderNames.Authorization] = [bearer]
            });

        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            endpointName,
            "POST",
            new RequestFields(),
            headers,
            jsonBody,
            [],
            TestContext.CancellationToken).ConfigureAwait(false);
    }
}
