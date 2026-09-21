using Microsoft.Extensions.Time.Testing;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Diagnostics;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Server;
using Verifiable.Server.Diagnostics;
using Verifiable.Tests.TestDataProviders;
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
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    /// <summary>The Wallet client identifier registered for the grant tests.</summary>
    private const string ClientId = "https://wallet.client.test";

    /// <summary>The base URI the registered client is reachable at.</summary>
    private static Uri ClientBaseUri { get; } = new("https://wallet.client.test");

    /// <summary>The End-User the offered Credential is about — the seam-resolved subject.</summary>
    private const string OfferSubject = "urn:uuid:end-user-42";

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>
    /// The capabilities a truly grant-only tenant needs: the grant capability itself, plus discovery
    /// so the <c>grant_types_supported</c> advertisement can be asserted. No
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthAuthorizationCode"/> — grant-only issuance works
    /// because <see cref="Rfc9068AccessTokenProducer"/>'s <c>RequiredCapability</c> is
    /// <see langword="null"/>, an optional tenant-feature gate rather than a grant-capability proxy.
    /// </summary>
    private static ImmutableHashSet<CapabilityIdentifier> GrantCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint);


    /// <summary>
    /// A wired grant exchanges a valid <c>pre-authorized_code</c> + <c>tx_code</c> for a Bearer
    /// access token bound to the offer's subject, echoes the granted scope, carries the §6.2
    /// <c>Cache-Control: no-store</c>, and omits the <c>c_nonce</c> the 1.0 token response no
    /// longer carries. The granted scope is a Credential-issuance scope, not <c>openid</c> — the
    /// Pre-Authorized Code grant establishes no authenticated End-User session, so <c>openid</c>
    /// and the OIDC identity scopes are narrowed away (see
    /// <see cref="OpenidAndIdentityScopesAreDroppedFromPreAuthorizedCodeGrantedScopeWithOtelEvent"/>
    /// for that narrowing proven directly).
    /// </summary>
    [TestMethod]
    public async Task IssuesBearerAccessTokenBoundToTheOfferSubjectWithoutCNonce()
    {
        const string CredentialScope = "UniversityDegree_dc_sd_jwt";

        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, GrantCapabilities).ConfigureAwait(false);

        //OID4VCI 1.0 §13.10: "Long-lived Access Tokens giving access to Credentials MUST not be
        //issued unless sender-constrained." The Pre-Authorized Code grant mints a plain-bearer
        //credential token; keep it within the long-lived threshold (lifetimes longer than 5
        //minutes are considered long lived) so the §13.10 guard permits issuance.
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);

        string? seenCode = null;
        string? seenTxCode = null;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidatePreAuthorizedCodeAsync =
                (code, txCode, clientId, registration, context, ct) =>
                {
                    seenCode = code;
                    seenTxCode = txCode;

                    return ValueTask.FromResult(
                        PreAuthorizedCodeDecision.Grant(OfferSubject, CredentialScope));
                };
        }).ConfigureAwait(false);

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
            [],
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
        Assert.AreEqual(CredentialScope, root.GetProperty(OAuthRequestParameterNames.Scope).GetString());

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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, GrantCapabilities).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, GrantCapabilities).ConfigureAwait(false);

        bool seamCalled = false;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidatePreAuthorizedCodeAsync =
                (code, txCode, clientId, registration, context, ct) =>
                {
                    seamCalled = true;

                    return ValueTask.FromResult(PreAuthorizedCodeDecision.Grant(OfferSubject));
                };
        }).ConfigureAwait(false);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciPreAuthorizedToken,
            "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.PreAuthorizedCode
            },
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.Contains(OAuthErrors.InvalidRequest, response.Body);
        Assert.IsFalse(seamCalled, "The seam must not be consulted when pre-authorized_code is absent.");
    }


    /// <summary>
    /// Fail-closed: declaring the grant capability without wiring the code-validation seam
    /// leaves the grant's own candidate absent from the chain, so it never mints a token for
    /// any code string. RFC 6749 §5.2 governs what a request naming the grant's <c>grant_type</c>
    /// gets instead: with the seam unwired THIS server does not serve
    /// <c>pre-authorized_code</c> at all, so the token endpoint's residual refusal answers
    /// <c>unsupported_grant_type</c> — never the host-generic 404 the absent grant candidate
    /// alone would otherwise leave behind.
    /// </summary>
    [TestMethod]
    public async Task SeamUnwiredRejectsUnsupportedGrantTypeInsteadOfAbsentGrant()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, GrantCapabilities).ConfigureAwait(false);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
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

        Assert.AreEqual(400, response.StatusCode,
            "An unwired validation seam must leave the grant's own candidate absent (fail-closed), "
            + "but the token endpoint's residual refusal must still answer, not the host-generic 404.");
        Assert.Contains(OAuthErrors.UnsupportedGrantType, response.Body, StringComparison.Ordinal);
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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, GrantCapabilities).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidatePreAuthorizedCodeAsync =
                (code, txCode, clientId, registration, context, ct) =>
                    ValueTask.FromResult(PreAuthorizedCodeDecision.Grant(OfferSubject));
        }).ConfigureAwait(false);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.MetadataDiscovery,
            WellKnownHttpMethods.Get,
            new RequestFields(),
            [],
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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, GrantCapabilities).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidatePreAuthorizedCodeAsync =
                (code, txCode, clientId, registration, context, ct) =>
                    ValueTask.FromResult(PreAuthorizedCodeDecision.Grant(OfferSubject));
        }).ConfigureAwait(false);

        //The deployment opts in to anonymous access — the §12.3 advertisement matches what the
        //seam will accept. The flag is read off the per-request context the policy stage mutates.
        ExchangeContext context = [];
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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, GrantCapabilities).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidatePreAuthorizedCodeAsync =
                (code, txCode, clientId, registration, context, ct) =>
                    ValueTask.FromResult(PreAuthorizedCodeDecision.Grant(OfferSubject));
        }).ConfigureAwait(false);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.MetadataDiscovery,
            WellKnownHttpMethods.Get,
            new RequestFields(),
            [],
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
    /// The Pre-Authorized Code grant establishes no authenticated
    /// End-User session (there is no prior Authorization Request), so a seam-granted scope carrying
    /// <c>openid</c> and every OIDC Core §5.4 identity scope has them narrowed away (RFC 6749 §3.3)
    /// before the granted scope ever reaches the token — the issued access token's <c>scope</c> claim
    /// carries none of them — and the narrowing emits
    /// <see cref="OAuthEventNames.IdentityScopesDroppedForNonEndUserGrant"/> naming exactly the
    /// dropped values.
    /// </summary>
    [TestMethod]
    public async Task OpenidAndIdentityScopesAreDroppedFromPreAuthorizedCodeGrantedScopeWithOtelEvent()
    {
        ConcurrentBag<Activity> captured = [];
        using ActivityListener listener = new()
        {
            ShouldListenTo = static source =>
                string.Equals(source.Name, ServerActivitySource.SourceName, StringComparison.Ordinal),
            Sample = static (ref _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = activity => captured.Add(activity)
        };
        ActivitySource.AddActivityListener(listener);

        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, GrantCapabilities).ConfigureAwait(false);
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);

        string grantedScope = string.Join(' ',
            WellKnownScopes.OpenId, WellKnownScopes.Profile, WellKnownScopes.Email,
            WellKnownScopes.Address, WellKnownScopes.Phone);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidatePreAuthorizedCodeAsync =
                (code, txCode, clientId, registration, context, ct) =>
                    ValueTask.FromResult(PreAuthorizedCodeDecision.Grant(OfferSubject, grantedScope));
        }).ConfigureAwait(false);

        string segment = material.Registration.TenantId.Value;
        string handle = material.Registration.TenantHandle!.Value.Value;
        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            segment,
            WellKnownEndpointNames.Oid4VciPreAuthorizedToken,
            "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.PreAuthorizedCode,
                [OAuthRequestParameterNames.PreAuthorizedCode] = "SplxlOBeZQQYbYS6WxSbIA",
                [OAuthRequestParameterNames.TxCode] = "493536"
            },
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument doc = JsonDocument.Parse(response.Body);
        //§6.2 omits the scope field entirely once every requested token — all five are identity
        //scopes — is narrowed away to nothing.
        Assert.IsFalse(doc.RootElement.TryGetProperty(OAuthRequestParameterNames.Scope, out _),
            "The response must omit scope once every requested token is narrowed away.");

        string accessToken = doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        byte[] payloadBytes = SecurityEventTestJson.DecodeSegment(accessToken.Split('.')[1], Pool);
        using JsonDocument payload = JsonDocument.Parse(payloadBytes);
        Assert.AreEqual(string.Empty, payload.RootElement.GetProperty(OAuthRequestParameterNames.Scope).GetString(),
            "The issued access token's scope claim must be empty — RFC 6749 §3.3 narrowing removed "
            + "every identity token before IssuanceContext.Scope was set.");

        //ActivityListener is process-wide (see the ActivityListener cross-contamination guidance):
        //filter captured activities to this test's tenant before asserting.
        List<ActivityEvent> dropEvents = captured
            .Where(a => string.Equals(
                a.GetTagItem(ServerTagNames.TenantHandle) as string, handle, StringComparison.Ordinal))
            .SelectMany(a => a.Events)
            .Where(e => string.Equals(e.Name, OAuthEventNames.IdentityScopesDroppedForNonEndUserGrant, StringComparison.Ordinal))
            .ToList();

        Assert.IsGreaterThan(0, dropEvents.Count,
            $"A '{OAuthEventNames.IdentityScopesDroppedForNonEndUserGrant}' event tagged with tenant "
            + $"'{handle}' must be emitted.");

        string droppedScopesTagValue = dropEvents[0].Tags
            .FirstOrDefault(t => string.Equals(t.Key, OAuthEventNames.DroppedScopesTagName, StringComparison.Ordinal))
            .Value as string ?? string.Empty;
        string[] droppedTokens = droppedScopesTagValue.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        Assert.HasCount(5, droppedTokens, $"Dropped scopes tag was '{droppedScopesTagValue}'.");
        Assert.Contains(WellKnownScopes.OpenId, droppedTokens);
        Assert.Contains(WellKnownScopes.Profile, droppedTokens);
        Assert.Contains(WellKnownScopes.Email, droppedTokens);
        Assert.Contains(WellKnownScopes.Address, droppedTokens);
        Assert.Contains(WellKnownScopes.Phone, droppedTokens);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-5">RFC 9449 §5</see>: "This is
    /// applicable for all access token requests regardless of grant type." A Pre-Authorized Code
    /// Token Request carrying a valid DPoP proof is bound the same way every other grant's token
    /// request is — <c>token_type</c> answers <c>DPoP</c> and the issued access token's
    /// <c>cnf.jkt</c> equals the proof key's RFC 7638 thumbprint.
    /// </summary>
    [TestMethod]
    public async Task PresentedProofBindsTheAccessTokenAndAnswersDpopTokenType()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, GrantCapabilities).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidatePreAuthorizedCodeAsync =
                (code, txCode, clientId, registration, context, ct) =>
                    ValueTask.FromResult(PreAuthorizedCodeDecision.Grant(OfferSubject));
        }).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        material.Registration = host.AlignRegistrationToHostHttpBase("default", material.Registration);

        string segment = material.Registration.TenantId.Value;
        Uri tokenEndpoint = RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, segment);
        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(holderKeys, WellKnownJwaValues.Es256);

        //RFC 9449 §8: the server's single nonce policy challenges the first, nonce-less proof; the
        //retry carrying the echoed nonce succeeds.
        string firstProof = await BuildTokenProofAsync(host, segment, dpopKey, nonce: null, TestContext.CancellationToken)
            .ConfigureAwait(false);
        HttpResponseData challenge = await HttpClientTransport.SendFormPostAsync(
            host.Host("default").SharedHttpClient!, tokenEndpoint, BuildPreAuthorizedFields(),
            OutgoingHeaders.Empty.WithDpop(firstProof), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, challenge.StatusCode, challenge.Body);
        Assert.Contains(OAuthErrors.UseDpopNonce, challenge.Body);
        string? freshNonce = challenge.Headers.TryGetSingle(WellKnownHttpHeaderNames.DPoPNonce);
        Assert.IsNotNull(freshNonce, "RFC 9449 §8 requires a DPoP-Nonce header on the use_dpop_nonce challenge.");

        string proof = await BuildTokenProofAsync(host, segment, dpopKey, nonce: freshNonce, TestContext.CancellationToken)
            .ConfigureAwait(false);
        (int statusCode, string body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, BuildPreAuthorizedFields(), OutgoingHeaders.Empty.WithDpop(proof),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, statusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.AreEqual(WellKnownAuthenticationSchemes.DPoP, doc.RootElement.GetProperty("token_type").GetString(),
            "A presented DPoP proof must bind the Pre-Authorized Code grant's access token the same way it binds every other grant's.");

        string accessToken = doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        string expectedThumbprint = dpopKey.GetThumbprint(TestHostShell.Base64UrlEncoder, TestHostShell.MemoryPool);
        string wireJkt = JwtPayloadReader.ReadCnfJkt(accessToken)
            ?? throw new AssertFailedException("Access-token JWT must carry cnf.jkt under DPoP issuance.");
        Assert.AreEqual(expectedThumbprint, wireJkt,
            "JWT cnf.jkt must equal the DPoP key's RFC 7638 thumbprint.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-13.10">OID4VCI 1.0 §13.10</see>:
    /// "Long-lived Access Tokens giving access to Credentials MUST not be issued unless
    /// sender-constrained." A registration whose access-token lifetime exceeds the threshold is
    /// issued a token when the request carries a valid DPoP proof, and is still refused without
    /// one.
    /// </summary>
    [TestMethod]
    public async Task LongLivedAccessTokenIsIssuedWithAProofAndRefusedWithoutOne()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, GrantCapabilities).ConfigureAwait(false);
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(10)).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidatePreAuthorizedCodeAsync =
                (code, txCode, clientId, registration, context, ct) =>
                    ValueTask.FromResult(PreAuthorizedCodeDecision.Grant(OfferSubject));
        }).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        material.Registration = host.AlignRegistrationToHostHttpBase("default", material.Registration);
        string segment = material.Registration.TenantId.Value;

        (int noProofStatus, string noProofBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, BuildPreAuthorizedFields(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, noProofStatus, noProofBody);
        Assert.Contains(OAuthErrors.InvalidRequest, noProofBody);

        Uri tokenEndpoint = RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, segment);
        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(holderKeys, WellKnownJwaValues.Es256);

        //RFC 9449 §8: the server's single nonce policy challenges the first, nonce-less proof; the
        //retry carrying the echoed nonce succeeds.
        string firstProof = await BuildTokenProofAsync(host, segment, dpopKey, nonce: null, TestContext.CancellationToken)
            .ConfigureAwait(false);
        HttpResponseData challenge = await HttpClientTransport.SendFormPostAsync(
            host.Host("default").SharedHttpClient!, tokenEndpoint, BuildPreAuthorizedFields(),
            OutgoingHeaders.Empty.WithDpop(firstProof), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, challenge.StatusCode, challenge.Body);
        Assert.Contains(OAuthErrors.UseDpopNonce, challenge.Body);
        string? freshNonce = challenge.Headers.TryGetSingle(WellKnownHttpHeaderNames.DPoPNonce);
        Assert.IsNotNull(freshNonce, "RFC 9449 §8 requires a DPoP-Nonce header on the use_dpop_nonce challenge.");

        string proof = await BuildTokenProofAsync(host, segment, dpopKey, nonce: freshNonce, TestContext.CancellationToken)
            .ConfigureAwait(false);
        (int provenStatus, string provenBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, BuildPreAuthorizedFields(), OutgoingHeaders.Empty.WithDpop(proof),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, provenStatus, provenBody);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 §8</see>: the
    /// authorization server answers a nonce-less request with <c>use_dpop_nonce</c> and a
    /// <c>DPoP-Nonce</c> header. The Pre-Authorized Code is single-use and the application's
    /// <see cref="AuthorizationServerIntegration.ValidatePreAuthorizedCodeAsync"/> seam may consume
    /// it, so the nonce challenge MUST run before the seam is consulted — otherwise the wallet's
    /// retry with the same code would find it already spent.
    /// </summary>
    [TestMethod]
    public async Task NonceChallengeRunsBeforeTheSeamAndTheRetryWithTheSameCodeSucceeds()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Haip10, GrantCapabilities).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);

        int seamInvocations = 0;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidatePreAuthorizedCodeAsync =
                (code, txCode, clientId, registration, context, ct) =>
                {
                    seamInvocations++;

                    return ValueTask.FromResult(PreAuthorizedCodeDecision.Grant(OfferSubject));
                };

            //HAIP 1.0's AccessTokenAudPolicy.Required needs a resolved audience; the granted
            //scope is empty here (RFC 6749 §3.3 narrowing drops every identity scope from this
            //grant, so ClientRecord.ScopeToAudience's openid mapping never matches). Fixed
            //resource-server audience, matching the one ScopeToAudience already carries.
            candidateIntegration.ResolveAccessTokenAudienceAsync = static (registration, issuance, ct) =>
                ValueTask.FromResult<IReadOnlyList<string>?>(["https://rs.example.com"]);
        }).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        material.Registration = host.AlignRegistrationToHostHttpBase("default", material.Registration);

        string segment = material.Registration.TenantId.Value;
        Uri tokenEndpoint = RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, segment);
        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(holderKeys, WellKnownJwaValues.Es256);

        string firstProof = await BuildTokenProofAsync(host, segment, dpopKey, nonce: null, TestContext.CancellationToken)
            .ConfigureAwait(false);
        HttpResponseData challenge = await HttpClientTransport.SendFormPostAsync(
            host.Host("default").SharedHttpClient!, tokenEndpoint, BuildPreAuthorizedFields(),
            OutgoingHeaders.Empty.WithDpop(firstProof), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, challenge.StatusCode, challenge.Body);
        Assert.Contains(OAuthErrors.UseDpopNonce, challenge.Body);
        string? freshNonce = challenge.Headers.TryGetSingle(WellKnownHttpHeaderNames.DPoPNonce);
        Assert.IsNotNull(freshNonce, "RFC 9449 §8 requires a DPoP-Nonce header on the use_dpop_nonce challenge.");
        Assert.AreEqual(0, seamInvocations,
            "The nonce challenge must never consume the Pre-Authorized Code — the wallet retries the same code.");

        string retryProof = await BuildTokenProofAsync(host, segment, dpopKey, nonce: freshNonce, TestContext.CancellationToken)
            .ConfigureAwait(false);
        HttpResponseData retryResponse = await HttpClientTransport.SendFormPostAsync(
            host.Host("default").SharedHttpClient!, tokenEndpoint, BuildPreAuthorizedFields(),
            OutgoingHeaders.Empty.WithDpop(retryProof), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, retryResponse.StatusCode, retryResponse.Body);
        Assert.AreEqual(1, seamInvocations,
            "The retry with the same code and the nonce must succeed and consult the seam exactly once.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 §4.2</see>: the
    /// proof's <c>htu</c> MUST match the request URL. A proof bound to a different endpoint is
    /// refused before the code-validation seam is consulted.
    /// </summary>
    [TestMethod]
    public async Task ProofWithWrongHtuIsRejectedWithoutConsultingTheSeam()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, GrantCapabilities).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        material.Registration = host.AlignRegistrationToHostHttpBase("default", material.Registration);
        string segment = material.Registration.TenantId.Value;

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(holderKeys, WellKnownJwaValues.Es256);
        DpopProofClaims claims = new()
        {
            Htm = WellKnownHttpMethods.Post,
            Htu = "https://wrong.example.test/not-the-token-endpoint",
            Iat = TimeProvider.GetUtcNow(),
            Jti = Guid.NewGuid().ToString("N")
        };
        string proof = await DpopProofConstruction.BuildAsync(
            claims, dpopKey, TestHostShell.Base64UrlEncoder, DpopTestSupport.Serializer,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async, TestHostShell.MemoryPool,
            TestContext.CancellationToken).ConfigureAwait(false);

        (int statusCode, string body, int seamInvocations) = await PostPreAuthorizedWithSeamSpyAsync(
            host, segment, OutgoingHeaders.Empty.WithDpop(proof), TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, body);
        Assert.Contains(OAuthErrors.InvalidDpopProof, body);
        Assert.AreEqual(0, seamInvocations, "A proof bound to the wrong htu must never reach the code-validation seam.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 §4.2</see>: the
    /// proof's <c>htm</c> MUST match the request method. A proof minted for <c>GET</c> presented on
    /// this <c>POST</c> token request is refused before the code-validation seam is consulted.
    /// </summary>
    [TestMethod]
    public async Task ProofWithWrongHtmIsRejectedWithoutConsultingTheSeam()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, GrantCapabilities).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        material.Registration = host.AlignRegistrationToHostHttpBase("default", material.Registration);
        string segment = material.Registration.TenantId.Value;

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(holderKeys, WellKnownJwaValues.Es256);
        DpopProofClaims claims = new()
        {
            Htm = WellKnownHttpMethods.Get,
            Htu = RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, segment).OriginalString,
            Iat = TimeProvider.GetUtcNow(),
            Jti = Guid.NewGuid().ToString("N")
        };
        string proof = await DpopProofConstruction.BuildAsync(
            claims, dpopKey, TestHostShell.Base64UrlEncoder, DpopTestSupport.Serializer,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async, TestHostShell.MemoryPool,
            TestContext.CancellationToken).ConfigureAwait(false);

        (int statusCode, string body, int seamInvocations) = await PostPreAuthorizedWithSeamSpyAsync(
            host, segment, OutgoingHeaders.Empty.WithDpop(proof), TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, body);
        Assert.Contains(OAuthErrors.InvalidDpopProof, body);
        Assert.AreEqual(0, seamInvocations, "A proof minted for the wrong HTTP method must never reach the code-validation seam.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 §11.1</see>: "the
    /// authorization server SHOULD check the jti value for replay." The code-validation seam is
    /// consulted on the jti's legitimate first use; a second presentation of that SAME jti never
    /// reaches the seam again — the code is not re-consumed by the replay.
    /// </summary>
    [TestMethod]
    public async Task ReplayedJtiIsRejectedWithoutConsultingTheSeamASecondTime()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, GrantCapabilities).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);

        int seamInvocations = 0;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidatePreAuthorizedCodeAsync =
                (code, txCode, clientId, registration, context, ct) =>
                {
                    seamInvocations++;

                    return ValueTask.FromResult(PreAuthorizedCodeDecision.Grant(OfferSubject));
                };
        }).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        material.Registration = host.AlignRegistrationToHostHttpBase("default", material.Registration);
        string segment = material.Registration.TenantId.Value;

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(holderKeys, WellKnownJwaValues.Es256);
        string htu = RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, segment).OriginalString;
        string jti = Guid.NewGuid().ToString("N");

        async Task<string> BuildProofAsync(string? nonce) =>
            await DpopProofConstruction.BuildAsync(
                new DpopProofClaims
                {
                    Htm = WellKnownHttpMethods.Post,
                    Htu = htu,
                    Iat = TimeProvider.GetUtcNow(),
                    Jti = jti,
                    Nonce = nonce
                },
                dpopKey, TestHostShell.Base64UrlEncoder, DpopTestSupport.Serializer,
                MicrosoftCryptographicFunctionsAdapter.SignP256Async, TestHostShell.MemoryPool,
                TestContext.CancellationToken).ConfigureAwait(false);

        //RFC 9449 §8: the server's single nonce policy challenges the first, nonce-less proof — a
        //challenge registers no jti, so the same jti is still available for the legitimate use below.
        string challengeProof = await BuildProofAsync(nonce: null).ConfigureAwait(false);
        HttpResponseData challenge = await HttpClientTransport.SendFormPostAsync(
            host.Host("default").SharedHttpClient!, RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, segment),
            BuildPreAuthorizedFields(), OutgoingHeaders.Empty.WithDpop(challengeProof), TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(400, challenge.StatusCode, challenge.Body);
        Assert.Contains(OAuthErrors.UseDpopNonce, challenge.Body);
        Assert.AreEqual(0, seamInvocations, "The nonce challenge must never consult the code-validation seam.");
        string freshNonce = challenge.Headers.TryGetSingle(WellKnownHttpHeaderNames.DPoPNonce)
            ?? throw new AssertFailedException("RFC 9449 §8 requires a DPoP-Nonce header on the use_dpop_nonce challenge.");

        //The nonce is stateless (HMAC-signed, valid for its whole window — see
        //DefaultDpopNonceValidation), so the SAME server nonce carries both the legitimate first
        //use and the jti-replay presentation below.
        string firstProof = await BuildProofAsync(freshNonce).ConfigureAwait(false);
        (int firstStatus, string firstBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, BuildPreAuthorizedFields(), OutgoingHeaders.Empty.WithDpop(firstProof),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, firstStatus, firstBody);
        Assert.AreEqual(1, seamInvocations, "The jti's legitimate first use must reach the seam.");

        string replayProof = await BuildProofAsync(freshNonce).ConfigureAwait(false);
        (int replayStatus, string replayBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, BuildPreAuthorizedFields(), OutgoingHeaders.Empty.WithDpop(replayProof),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, replayStatus, replayBody);
        Assert.Contains(OAuthErrors.InvalidDpopProof, replayBody);
        Assert.AreEqual(1, seamInvocations,
            "A replayed jti must never reach the code-validation seam a second time — the code is not re-consumed by the replay.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-5">RFC 9449 §5</see>: a client
    /// whose policy profile mandates DPoP-bound access tokens
    /// (<see cref="ClientPolicyProfiles.RequiresDpop"/>) is refused before the code-validation
    /// seam is consulted when the request carries no proof at all.
    /// </summary>
    [TestMethod]
    public async Task RegistrationRequiringDpopWithoutAProofIsRejectedWithoutConsultingTheSeam()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Haip10, GrantCapabilities).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        material.Registration = host.AlignRegistrationToHostHttpBase("default", material.Registration);
        string segment = material.Registration.TenantId.Value;

        (int statusCode, string body, int seamInvocations) = await PostPreAuthorizedWithSeamSpyAsync(
            host, segment, OutgoingHeaders.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, body);
        Assert.Contains(OAuthErrors.UseDpopNonce, body);
        Assert.AreEqual(0, seamInvocations,
            "A registration whose profile requires DPoP must refuse an unproven request before consulting the seam.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7">RFC 9449 §7</see>: a
    /// DPoP-bound access token must be presented with a matching proof at the resource endpoint. A
    /// token this grant bound is refused at the Credential Endpoint without a proof and accepted
    /// with one — mirrors
    /// <see cref="Oid4VciDpopCredentialEndpointTests.DpopBoundTokenWithValidProofIssues"/> for a
    /// token minted by the Pre-Authorized Code grant instead of the authorization-code grant.
    /// </summary>
    [TestMethod]
    public async Task TokenBoundByThisGrantIsRefusedAtTheCredentialEndpointWithoutAProofAndAcceptedWithOne()
    {
        const string ConfigurationId = "UniversityDegree_dc_sd_jwt";
        const string IssuedCredential = "eyJhbGciOiJFUzI1NiJ9.body.sig";

        await using TestHostShell host = new(TimeProvider);
        ImmutableHashSet<CapabilityIdentifier> capabilities =
            GrantCapabilities.Add(WellKnownCapabilityIdentifiers.Oid4VciCredentialEndpoint);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, capabilities).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidatePreAuthorizedCodeAsync =
                (code, txCode, clientId, registration, context, ct) =>
                    ValueTask.FromResult(PreAuthorizedCodeDecision.Grant(OfferSubject));
            _ = candidateIntegration.UseDefaultCredentialRequestJsonParsing();
            candidateIntegration.IssueCredentialAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
        }).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        material.Registration = host.AlignRegistrationToHostHttpBase("default", material.Registration);

        string segment = material.Registration.TenantId.Value;
        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(holderKeys, WellKnownJwaValues.Es256);

        //RFC 9449 §8: the server's single nonce policy challenges the first, nonce-less proof; the
        //retry carrying the echoed nonce succeeds.
        string tokenChallengeProof = await BuildTokenProofAsync(host, segment, dpopKey, nonce: null, TestContext.CancellationToken)
            .ConfigureAwait(false);
        HttpResponseData tokenChallenge = await HttpClientTransport.SendFormPostAsync(
            host.Host("default").SharedHttpClient!, RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, segment),
            BuildPreAuthorizedFields(), OutgoingHeaders.Empty.WithDpop(tokenChallengeProof), TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(400, tokenChallenge.StatusCode, tokenChallenge.Body);
        Assert.Contains(OAuthErrors.UseDpopNonce, tokenChallenge.Body);
        string tokenNonce = tokenChallenge.Headers.TryGetSingle(WellKnownHttpHeaderNames.DPoPNonce)
            ?? throw new AssertFailedException("RFC 9449 §8 requires a DPoP-Nonce header on the use_dpop_nonce challenge.");

        string tokenProof = await BuildTokenProofAsync(host, segment, dpopKey, nonce: tokenNonce, TestContext.CancellationToken)
            .ConfigureAwait(false);

        (int tokenStatus, string tokenBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, BuildPreAuthorizedFields(), OutgoingHeaders.Empty.WithDpop(tokenProof),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, tokenStatus, tokenBody);

        using JsonDocument tokenDoc = JsonDocument.Parse(tokenBody);
        string accessToken = tokenDoc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;

        Uri credentialUrl = new(host.Host("default").HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.Oid4VciCredential, segment));
        HttpClient httpClient = host.Host("default").SharedHttpClient!;

        using HttpResponseMessage noProofResponse = await PostCredentialRequestAsync(
            httpClient, credentialUrl, ConfigurationId, accessToken, dpopProof: null, TestContext.CancellationToken)
            .ConfigureAwait(false);
        string noProofBody = await noProofResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.BadRequest, noProofResponse.StatusCode, noProofBody);
        Assert.Contains(OAuthErrors.UseDpopNonce, noProofBody);

        string ath = await DpopProofValidator.ComputeAthAsync(
            accessToken, TestHostShell.Base64UrlEncoder, TestHostShell.MemoryPool, TestContext.CancellationToken)
            .ConfigureAwait(false);
        DpopProofClaims credentialClaims = new()
        {
            Htm = WellKnownHttpMethods.Post,
            Htu = credentialUrl.ToString(),
            Iat = TimeProvider.GetUtcNow(),
            Jti = Guid.NewGuid().ToString("N"),
            Ath = ath
        };
        string credentialProof = await DpopProofConstruction.BuildAsync(
            credentialClaims, dpopKey, TestHostShell.Base64UrlEncoder, DpopTestSupport.Serializer,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async, TestHostShell.MemoryPool,
            TestContext.CancellationToken).ConfigureAwait(false);

        using HttpResponseMessage provenResponse = await PostCredentialRequestAsync(
            httpClient, credentialUrl, ConfigurationId, accessToken, credentialProof, TestContext.CancellationToken)
            .ConfigureAwait(false);
        string provenBody = await provenResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.OK, provenResponse.StatusCode, provenBody);
    }


    /// <summary>Builds the minimal well-formed §6.1 Token Request form fields this file's DPoP tests share.</summary>
    private static Dictionary<string, string> BuildPreAuthorizedFields() =>
        new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.PreAuthorizedCode,
            [OAuthRequestParameterNames.PreAuthorizedCode] = "SplxlOBeZQQYbYS6WxSbIA"
        };


    /// <summary>
    /// Builds a DPoP proof bound to the Pre-Authorized Code grant's token endpoint — the same URL
    /// the authorization-code grant serves, disambiguated by <c>grant_type</c>.
    /// </summary>
    private async Task<string> BuildTokenProofAsync(
        TestHostShell host, string segment, DpopKey key, string? nonce, CancellationToken cancellationToken)
    {
        DpopProofClaims claims = new()
        {
            Htm = WellKnownHttpMethods.Post,
            Htu = RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, segment).OriginalString,
            Iat = TimeProvider.GetUtcNow(),
            Jti = Guid.NewGuid().ToString("N"),
            Nonce = nonce
        };

        return await DpopProofConstruction.BuildAsync(
            claims, key, TestHostShell.Base64UrlEncoder, DpopTestSupport.Serializer,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async, TestHostShell.MemoryPool,
            cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Wires a counting <see cref="AuthorizationServerIntegration.ValidatePreAuthorizedCodeAsync"/>
    /// spy and posts a well-formed token request carrying <paramref name="headers"/>, returning
    /// the response alongside how many times the seam was consulted.
    /// </summary>
    private static async Task<(int StatusCode, string Body, int SeamInvocations)> PostPreAuthorizedWithSeamSpyAsync(
        TestHostShell host, string segment, OutgoingHeaders headers, CancellationToken cancellationToken)
    {
        int seamInvocations = 0;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidatePreAuthorizedCodeAsync =
                (code, txCode, clientId, registration, context, ct) =>
                {
                    seamInvocations++;

                    return ValueTask.FromResult(PreAuthorizedCodeDecision.Grant(OfferSubject));
                };
        }).ConfigureAwait(false);

        (int statusCode, string body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, BuildPreAuthorizedFields(), headers, cancellationToken).ConfigureAwait(false);

        return (statusCode, body, seamInvocations);
    }


    /// <summary>Posts a §8 Credential Request under the DPoP scheme, with or without a DPoP proof header.</summary>
    private static async Task<HttpResponseMessage> PostCredentialRequestAsync(
        HttpClient httpClient, Uri credentialUrl, string configurationId, string accessToken,
        string? dpopProof, CancellationToken cancellationToken)
    {
        using StringContent content = new(
            "{\"credential_configuration_id\":\"" + configurationId + "\",\"proofs\":{\"jwt\":[\"p\"]}}",
            Encoding.UTF8, WellKnownMediaTypes.Application.Json);
        using HttpRequestMessage request = new(HttpMethod.Post, credentialUrl) { Content = content };
        _ = request.Headers.TryAddWithoutValidation(
            WellKnownHttpHeaderNames.Authorization, $"DPoP {accessToken}");
        if(dpopProof is not null)
        {
            _ = request.Headers.TryAddWithoutValidation(WellKnownHttpHeaderNames.DPoP, dpopProof);
        }

        return await httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
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
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidatePreAuthorizedCodeAsync =
                (code, txCode, clientId, registration, context, ct) => ValueTask.FromResult(decision);
        }).ConfigureAwait(false);

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
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expectedStatus, response.StatusCode, response.Body);
        Assert.Contains(expectedError, response.Body);
    }
}
