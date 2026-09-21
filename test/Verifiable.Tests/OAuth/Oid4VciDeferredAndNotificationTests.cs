using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Text.Json;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

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

        string accessToken = await MintAccessTokenAsync(host, material).ConfigureAwait(false);
        ServerHttpResponse noTransaction = await DispatchDeferredAsync(
            host, material, "Bearer " + accessToken, "{}").ConfigureAwait(false);

        Assert.AreEqual(400, noTransaction.StatusCode, noTransaction.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidCredentialRequest, noTransaction.Body);
        Assert.IsFalse(seamConsulted, "Shape failures must not reach the seam.");
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
