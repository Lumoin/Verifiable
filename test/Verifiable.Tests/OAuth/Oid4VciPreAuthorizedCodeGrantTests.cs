using System.Buffers;
using System.Collections.Immutable;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Server;
using Verifiable.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Server-side OID4VCI 1.0 §6 Pre-Authorized Code grant, driven through the real dispatch
/// pipeline. The Wallet presents a <c>pre-authorized_code</c> (and optional <c>tx_code</c>)
/// the Credential Issuer minted in a Credential Offer; the library validates it through the
/// <see cref="ValidatePreAuthorizedCodeDelegate"/> seam, mints a Bearer access token bound to
/// the seam-resolved subject, and returns it without a <c>c_nonce</c> (§6.2 — moved to the
/// Nonce Endpoint). The seam owns the §6.3 error distinctions the library cannot make.
/// </summary>
[TestClass]
internal sealed class Oid4VciPreAuthorizedCodeGrantTests
{
    /// <summary>The MSTest-supplied per-test context.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>A fixed clock so issued artefacts are reproducible.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));

    /// <summary>The Wallet client identifier registered for the grant tests.</summary>
    private const string ClientId = "https://wallet.client.test";

    /// <summary>The base URI the registered client is reachable at.</summary>
    private static readonly Uri ClientBaseUri = new("https://wallet.client.test");

    /// <summary>The End-User the offered Credential is about — the seam-resolved subject.</summary>
    private const string OfferSubject = "urn:uuid:end-user-42";

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    /// <summary>
    /// The capabilities the grant needs: the grant capability itself, plus
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthAuthorizationCode"/> the shipped
    /// RFC 9068 access-token producer is gated on, plus discovery so the
    /// <c>grant_types_supported</c> advertisement can be asserted.
    /// </summary>
    private static readonly ImmutableHashSet<CapabilityIdentifier> GrantCapabilities =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint);


    /// <summary>
    /// A wired grant exchanges a valid <c>pre-authorized_code</c> + <c>tx_code</c> for a Bearer
    /// access token bound to the offer's subject, echoes the granted scope, carries the §6.2
    /// <c>Cache-Control: no-store</c>, and omits the <c>c_nonce</c> the 1.0 token response no
    /// longer carries.
    /// </summary>
    [TestMethod]
    public async Task IssuesBearerAccessTokenBoundToTheOfferSubjectWithoutCNonce()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, GrantCapabilities);

        //OID4VCI 1.0 §13.10: "Long-lived Access Tokens giving access to Credentials MUST not be
        //issued unless sender-constrained." The Pre-Authorized Code grant mints a plain-bearer
        //credential token; keep it within the long-lived threshold (lifetimes longer than 5
        //minutes are considered long lived) so the §13.10 guard permits issuance.
        host.SetAccessTokenLifetime(material, TimeSpan.FromMinutes(5));

        string? seenCode = null;
        string? seenTxCode = null;
        host.Server.OAuth().ValidatePreAuthorizedCodeAsync =
            (code, txCode, clientId, registration, context, ct) =>
            {
                seenCode = code;
                seenTxCode = txCode;

                return ValueTask.FromResult(
                    PreAuthorizedCodeDecision.Grant(OfferSubject, WellKnownScopes.OpenId));
            };

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciPreAuthorizedToken,
            "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.PreAuthorizedCode,
                [OAuthRequestParameterNames.PreAuthorizedCode] = "SplxlOBeZQQYbYS6WxSbIA",
                [OAuthRequestParameterNames.TxCode] = "493536"
            },
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.AreEqual("application/json", response.ContentType);

        //§6.2: the token response MUST be uncacheable.
        Assert.IsTrue(response.Headers.TryGetValue(WellKnownHttpHeaderNames.CacheControl, out string? cacheControl),
            "The token response MUST carry Cache-Control.");
        Assert.AreEqual(WellKnownCacheControlValues.NoStore, cacheControl);

        //The library handed the seam the wire values verbatim.
        Assert.AreEqual("SplxlOBeZQQYbYS6WxSbIA", seenCode);
        Assert.AreEqual("493536", seenTxCode);

        using JsonDocument doc = JsonDocument.Parse(response.Body);
        JsonElement root = doc.RootElement;
        string accessToken = root.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        Assert.AreEqual(WellKnownAuthenticationSchemes.Bearer, root.GetProperty("token_type").GetString());
        Assert.IsGreaterThan(0, root.GetProperty("expires_in").GetInt32(), "expires_in must reflect the token's exp-iat.");
        Assert.AreEqual(WellKnownScopes.OpenId, root.GetProperty(OAuthRequestParameterNames.Scope).GetString());

        //OID4VCI 1.0 §6.2 + §7: the c_nonce moved to the Nonce Endpoint and MUST NOT be in
        //the token response.
        Assert.IsFalse(root.TryGetProperty("c_nonce", out _),
            "c_nonce must not appear in the OID4VCI 1.0 token response.");

        //§6.2: the access token is bound to the End-User the Credential is about, not the Wallet.
        string[] segments = accessToken.Split('.');
        Assert.HasCount(3, segments);
        byte[] payloadBytes = SecurityEventTestJson.DecodeSegment(segments[1], Pool);
        using JsonDocument payload = JsonDocument.Parse(payloadBytes);
        Assert.AreEqual(OfferSubject, payload.RootElement.GetProperty("sub").GetString());
    }


    /// <summary>
    /// Each §6.3 denial the seam returns maps to its OAuth Token Error Response: a wrong or
    /// expired code and a wrong Transaction Code are <c>invalid_grant</c>; a missing or
    /// unexpected Transaction Code is <c>invalid_request</c>; an unsupported anonymous request
    /// is <c>invalid_client</c>.
    /// </summary>
    [TestMethod]
    public async Task DenialsMapToTheSpecTokenErrorResponses()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, GrantCapabilities);

        await AssertDenialAsync(host, material,
            PreAuthorizedCodeDecision.Deny(PreAuthorizedCodeDenialReason.InvalidCode),
            400, OAuthErrors.InvalidGrant).ConfigureAwait(false);

        await AssertDenialAsync(host, material,
            PreAuthorizedCodeDecision.Deny(PreAuthorizedCodeDenialReason.TransactionCodeInvalid),
            400, OAuthErrors.InvalidGrant).ConfigureAwait(false);

        await AssertDenialAsync(host, material,
            PreAuthorizedCodeDecision.Deny(PreAuthorizedCodeDenialReason.TransactionCodeRequired),
            400, OAuthErrors.InvalidRequest).ConfigureAwait(false);

        await AssertDenialAsync(host, material,
            PreAuthorizedCodeDecision.Deny(PreAuthorizedCodeDenialReason.TransactionCodeUnexpected),
            400, OAuthErrors.InvalidRequest).ConfigureAwait(false);

        await AssertDenialAsync(host, material,
            PreAuthorizedCodeDecision.Deny(PreAuthorizedCodeDenialReason.ClientAuthenticationRequired),
            401, OAuthErrors.InvalidClient).ConfigureAwait(false);
    }


    /// <summary>
    /// §6.1: <c>pre-authorized_code</c> MUST be present when the grant type is used. The
    /// library rejects an absent code with <c>invalid_request</c> before the seam is consulted.
    /// </summary>
    [TestMethod]
    public async Task MissingPreAuthorizedCodeIsRejectedBeforeTheSeam()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, GrantCapabilities);

        bool seamCalled = false;
        host.Server.OAuth().ValidatePreAuthorizedCodeAsync =
            (code, txCode, clientId, registration, context, ct) =>
            {
                seamCalled = true;

                return ValueTask.FromResult(PreAuthorizedCodeDecision.Grant(OfferSubject));
            };

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciPreAuthorizedToken,
            "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.PreAuthorizedCode
            },
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.Contains(OAuthErrors.InvalidRequest, response.Body);
        Assert.IsFalse(seamCalled, "The seam must not be consulted when pre-authorized_code is absent.");
    }


    /// <summary>
    /// Fail-closed: declaring the grant capability without wiring the code-validation seam
    /// leaves the candidate absent from the chain, so the token request 404s rather than an
    /// endpoint that would mint a token for any code string.
    /// </summary>
    [TestMethod]
    public async Task GrantAbsentWhenSeamUnwired()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, GrantCapabilities);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciPreAuthorizedToken,
            "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.PreAuthorizedCode,
                [OAuthRequestParameterNames.PreAuthorizedCode] = "SplxlOBeZQQYbYS6WxSbIA"
            },
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(404, response.StatusCode,
            "An unwired validation seam must leave the grant absent (fail-closed).");
    }


    /// <summary>
    /// A wired grant advertises itself in <c>grant_types_supported</c> (RFC 8414 §2 / OID4VCI
    /// 1.0 Appendix G.1.1) so the Wallet can discover that the Pre-Authorized Code Flow is
    /// available at the token endpoint.
    /// </summary>
    [TestMethod]
    public async Task DiscoveryAdvertisesThePreAuthorizedCodeGrant()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, GrantCapabilities);

        host.Server.OAuth().ValidatePreAuthorizedCodeAsync =
            (code, txCode, clientId, registration, context, ct) =>
                ValueTask.FromResult(PreAuthorizedCodeDecision.Grant(OfferSubject));

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.MetadataDiscovery,
            WellKnownHttpMethods.Get,
            new RequestFields(),
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.Contains(WellKnownGrantTypes.PreAuthorizedCode, response.Body,
            "grant_types_supported must advertise the pre-authorized_code grant when it is active.");
    }


    /// <summary>
    /// OID4VCI 1.0 §12.3: "<c>pre-authorized_grant_anonymous_access_supported</c>: OPTIONAL. A
    /// boolean indicating whether the Credential Issuer accepts a Token Request with a
    /// Pre-Authorized Code but without a <c>client_id</c>." When a deployment opts in (the
    /// anonymous-access policy flag is set), the AS Metadata document advertises the parameter as
    /// <see langword="true"/> alongside the pre-authorized_code grant.
    /// </summary>
    [TestMethod]
    public async Task DiscoveryAdvertisesAnonymousPreAuthorizedAccessWhenEnabled()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, GrantCapabilities);

        host.Server.OAuth().ValidatePreAuthorizedCodeAsync =
            (code, txCode, clientId, registration, context, ct) =>
                ValueTask.FromResult(PreAuthorizedCodeDecision.Grant(OfferSubject));

        //The deployment opts in to anonymous access — the §12.3 advertisement matches what the
        //seam will accept. The flag is read off the per-request context the policy stage mutates.
        ExchangeContext context = new();
        context.SetPreAuthorizedGrantAnonymousAccessSupported(true);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.MetadataDiscovery,
            WellKnownHttpMethods.Get,
            new RequestFields(),
            context,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument doc = JsonDocument.Parse(response.Body);
        Assert.IsTrue(
            doc.RootElement.TryGetProperty(
                AuthorizationServerMetadataParameterNames.PreAuthorizedGrantAnonymousAccessSupported,
                out JsonElement advertised),
            $"pre-authorized_grant_anonymous_access_supported must appear when the deployment enables it. Body: {response.Body}");
        Assert.AreEqual(JsonValueKind.True, advertised.ValueKind,
            "§12.3 advertises the boolean as true when anonymous access is supported.");
    }


    /// <summary>
    /// OID4VCI 1.0 §12.3: "The default is false." A deployment that has NOT opted in to anonymous
    /// access omits <c>pre-authorized_grant_anonymous_access_supported</c> — the Wallet assumes
    /// the §12.3 default of <see langword="false"/> for an absent parameter, so emitting it would
    /// be redundant.
    /// </summary>
    [TestMethod]
    public async Task DiscoveryOmitsAnonymousPreAuthorizedAccessWhenNotEnabled()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, GrantCapabilities);

        host.Server.OAuth().ValidatePreAuthorizedCodeAsync =
            (code, txCode, clientId, registration, context, ct) =>
                ValueTask.FromResult(PreAuthorizedCodeDecision.Grant(OfferSubject));

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.MetadataDiscovery,
            WellKnownHttpMethods.Get,
            new RequestFields(),
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        //The pre-authorized_code grant is still advertised (it is active); only the anonymous-access
        //flag is absent because the deployment did not opt in (the §12.3 default is false).
        Assert.Contains(WellKnownGrantTypes.PreAuthorizedCode, response.Body);

        using JsonDocument doc = JsonDocument.Parse(response.Body);
        Assert.IsFalse(
            doc.RootElement.TryGetProperty(
                AuthorizationServerMetadataParameterNames.PreAuthorizedGrantAnonymousAccessSupported, out _),
            "An un-opted-in deployment omits pre-authorized_grant_anonymous_access_supported (§12.3 default false).");
    }


    /// <summary>
    /// Wires the seam to the given <paramref name="decision"/>, dispatches a well-formed token
    /// request, and asserts the response status and error code the library mapped it to.
    /// </summary>
    private async Task AssertDenialAsync(
        TestHostShell host,
        VerifierKeyMaterial material,
        PreAuthorizedCodeDecision decision,
        int expectedStatus,
        string expectedError)
    {
        host.Server.OAuth().ValidatePreAuthorizedCodeAsync =
            (code, txCode, clientId, registration, context, ct) => ValueTask.FromResult(decision);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciPreAuthorizedToken,
            "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.PreAuthorizedCode,
                [OAuthRequestParameterNames.PreAuthorizedCode] = "SplxlOBeZQQYbYS6WxSbIA",
                [OAuthRequestParameterNames.TxCode] = "493536"
            },
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expectedStatus, response.StatusCode, response.Body);
        Assert.Contains(expectedError, response.Body);
    }
}
