using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Text.Json;
using Verifiable.Core.SecurityEvents;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Logout;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.States;
using Verifiable.OAuth.Oid4Vp.Wallet;
using Verifiable.OAuth.Oid4Vp.Wallet.States;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Metadata;
using Verifiable.OAuth.Ssf;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// One <see cref="HostedAuthorizationServer"/> with the full set of
/// end-to-end-wired OAuth/OIDC capabilities enabled, asserting that the
/// discovery document is coherent <em>bidirectionally</em>: every advertised
/// field is justified by an enabled capability, and every enabled capability's
/// field is present — with no fields bleeding in from roles that are separate
/// documents (OID4VP verifier <c>client_metadata</c>, Federation entity
/// configuration).
/// </summary>
/// <remarks>
/// <para>
/// Capabilities declared in <see cref="WellKnownCapabilityIdentifiers"/> but
/// not yet end-to-end flow-complete are intentionally excluded:
/// <c>OAuthTokenExchange</c>, <c>OAuthTokenIntrospection</c>,
/// <c>OAuthDeviceAuthorization</c>, <c>OidcSessionManagement</c>,
/// <c>VcVerifiableCredentialIssuance</c>, and <c>AuthZenAuthorizationApi</c>.
/// Adding a flow for any of them is the trigger to add it here too.
/// </para>
/// <para>
/// <c>VcVerifiablePresentation</c> (OID4VP verifier) and <c>FederationBase</c>
/// are separate roles whose metadata lives in different documents
/// (<c>client_metadata</c> and the Federation entity configuration); they are
/// covered by their own end-to-end suites and are deliberately not part of the
/// token-AS discovery document asserted here. The reverse assertion below
/// guards against their fields leaking into this document.
/// </para>
/// </remarks>
[TestClass]
internal sealed class AllCapabilitiesAuthorizationServerTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    private const string ClientId = "https://all-capabilities.client.test";
    private static Uri ClientBaseUri { get; } = new("https://all-capabilities.client.test");
    private const string SubjectId = "subject-all-caps-1";

    //RegisterDpopClient hard-codes this as the single allowed redirect URI.
    private static Uri RedirectUri { get; } = new("https://client.example.com/callback");

    private const string VerifierClientId = "https://verifier.example.com";
    private static Uri VerifierBaseUri { get; } = new("https://verifier.example.com");
    private static ImmutableHashSet<CapabilityIdentifier> Oid4VpCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.VcVerifiablePresentation,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint);

    /// <summary>Every OAuth/OIDC capability with end-to-end flow and metadata wiring today.</summary>
    private static ImmutableHashSet<CapabilityIdentifier> TokenServerCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthRefreshToken,
            WellKnownCapabilityIdentifiers.OAuthPushedAuthorization,
            WellKnownCapabilityIdentifiers.OAuthJwtSecuredAuthorizationRequest,
            WellKnownCapabilityIdentifiers.OAuthDirectAuthorization,
            WellKnownCapabilityIdentifiers.OAuthDynamicClientRegistration,
            WellKnownCapabilityIdentifiers.OidcOpenIdConnect,
            WellKnownCapabilityIdentifiers.OidcUserInfo,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.SsfTransmitter,
            WellKnownCapabilityIdentifiers.OAuthClientCredentials,
            WellKnownCapabilityIdentifiers.OAuthTokenRevocation,
            WellKnownCapabilityIdentifiers.OAuthGlobalTokenRevocation,
            WellKnownCapabilityIdentifiers.OidcRpInitiatedLogout,
            WellKnownCapabilityIdentifiers.OidcBackChannelLogout,
            WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata,
            WellKnownCapabilityIdentifiers.OAuthClientIdMetadataDocument);

    /// <summary>The token-AS capabilities plus the OID4VP-verifier and Federation roles, all co-registered.</summary>
    private static ImmutableHashSet<CapabilityIdentifier> TokenServerWithPresentationAndFederation { get; } =
        TokenServerCapabilities
            .Add(WellKnownCapabilityIdentifiers.VcVerifiablePresentation)
            .Add(WellKnownCapabilityIdentifiers.FederationBase);


    /// <summary>
    /// Checks that discovery fields correspond to the enabled endpoint capabilities and supplied metadata operations.
    /// <see href="../../../documents/AuthorizationServerDesign.md#22-endpoint-chain-stage">Server design</see>.
    /// </summary>
    [TestMethod]
    public async Task EverythingEnabledDiscoveryDocumentIsCoherent()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Fapi20, capabilities: TokenServerCapabilities).ConfigureAwait(false);

        //ValidateDpopProofAsync is the gate for advertising dpop_signing_alg_values_supported.
        _ = await host.EnableDpopAsync().ConfigureAwait(false);

        //ValidateClientCredentialsAsync is the gate for the client_credentials
        //grant — without it the grant endpoint does not exist (fail-closed).
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(true);


            //RevokeTokenAsync + ValidateClientCredentialsAsync together gate the RFC 7009
            //revocation endpoint — both must be wired for revocation_endpoint to be advertised.

            candidateIntegration.RevokeTokenAsync = static (_, _, _, _, _) =>
                ValueTask.CompletedTask;


            //Global Token Revocation: capability + the default JSON parse seam + the
            //revoke-subject seam + client auth gate the endpoint — wiring them advertises
            //global_token_revocation_endpoint.

            _ = candidateIntegration.UseDefaultGlobalTokenRevocationJsonParsing();


            candidateIntegration.RevokeSubjectTokensAsync = static (_, _, _, _) =>
                ValueTask.FromResult(GlobalTokenRevocationOutcome.Initiated);


            //RP-Initiated Logout: capability + TerminateSessionAsync + the (host-wired)
            //verification-key resolver gate the end_session endpoint — wiring the seam
            //advertises end_session_endpoint.

            candidateIntegration.TerminateSessionAsync = static (_, _, _, _, _) =>
                ValueTask.CompletedTask;


            //Back-Channel Logout: capability + the deliver (fan-out) seam advertise
            //backchannel_logout_supported / backchannel_logout_session_supported.

            candidateIntegration.DeliverBackChannelLogoutAsync = static (_, _, _, _, _) =>
                ValueTask.CompletedTask;


            //CIMD: capability + the resolver seam advertise client_id_metadata_document_supported.
            //Discovery emission only checks the seam for non-null-ness (privacy §9.1 — discovery
            //requests never trigger a client-document fetch), so a throwing lambda proves that.

            candidateIntegration.ResolveClientMetadataAsync = (uri, context, ct) =>
                throw new NotImplementedException(
                    "Discovery emission only checks ResolveClientMetadataAsync for non-null-ness; it must never invoke it.");
        }).ConfigureAwait(false);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.MetadataDiscovery,
            WellKnownHttpMethods.Get,
            new RequestFields(),
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument doc = JsonDocument.Parse(response.Body);
        JsonElement root = doc.RootElement;

        //Forward: every field the enabled capability set must produce is present.
        string[] expectedPresent =
        [
            "issuer",
            "token_endpoint",
            "revocation_endpoint",
            "global_token_revocation_endpoint",
            "end_session_endpoint",
            "backchannel_logout_supported",
            "backchannel_logout_session_supported",
            "authorization_endpoint",
            "pushed_authorization_request_endpoint",
            "jwks_uri",
            "userinfo_endpoint",
            "subject_types_supported",
            "response_types_supported",
            "id_token_signing_alg_values_supported",
            "grant_types_supported",
            "code_challenge_methods_supported",
            "require_pushed_authorization_requests",
            "authorization_response_iss_parameter_supported",
            "dpop_signing_alg_values_supported",
            "token_endpoint_auth_methods_supported",
            "scopes_supported",
            "claims_supported",
            "claim_types_supported",
            "client_id_metadata_document_supported",
        ];
        foreach(string field in expectedPresent)
        {
            Assert.IsTrue(root.TryGetProperty(field, out _),
                $"Discovery document is missing '{field}' expected from the enabled capability set. Body: {response.Body}");
        }

        //OAuthRefreshToken is enabled, so refresh_token must be advertised alongside authorization_code.
        List<string> grantTypes = EnumerateStrings(root.GetProperty("grant_types_supported"));
        Assert.Contains("authorization_code", grantTypes);
        Assert.Contains("refresh_token", grantTypes,
            "OAuthRefreshToken is enabled, so refresh_token must appear in grant_types_supported.");
        Assert.Contains("client_credentials", grantTypes,
            "OAuthClientCredentials is enabled with its seam wired, so client_credentials must appear in grant_types_supported.");

        //Reverse: every advertised field is justified by an enabled capability — nothing
        //unwired, and no role bleed from the OID4VP-verifier or Federation documents.
        var justified = new HashSet<string>(StringComparer.Ordinal)
        {
            "issuer",
            "token_endpoint",
            "revocation_endpoint",
            "global_token_revocation_endpoint",
            "end_session_endpoint",
            "backchannel_logout_supported",
            "backchannel_logout_session_supported",
            "authorization_endpoint",
            "pushed_authorization_request_endpoint",
            "jwks_uri",
            "userinfo_endpoint",
            "registration_endpoint",
            "subject_types_supported",
            "response_types_supported",
            "id_token_signing_alg_values_supported",
            "grant_types_supported",
            "code_challenge_methods_supported",
            "require_pushed_authorization_requests",
            "authorization_response_iss_parameter_supported",
            "dpop_signing_alg_values_supported",
            "token_endpoint_auth_methods_supported",
            "scopes_supported",
            "claims_supported",
            "claim_types_supported",
            "client_id_metadata_document_supported",
        };
        foreach(JsonProperty prop in root.EnumerateObject())
        {
            Assert.Contains(prop.Name, justified,
                $"Discovery document advertises '{prop.Name}', which is not justified by any enabled " +
                $"capability (unwired field or role bleed). Body: {response.Body}");
        }
    }


    /// <summary>
    /// Checks that the transmitter configuration response preserves its supported delivery methods and authorization metadata.
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-7.1">Shared Signals Framework §7.1</see>.
    /// </summary>
    [TestMethod]
    public async Task SsfTransmitterConfigurationIsServedAndConformant()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Fapi20, capabilities: TokenServerCapabilities).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ContributeSsfTransmitterMetadataAsync = static (_, _, _) =>
                ValueTask.FromResult(new SsfTransmitterMetadataContribution
                {
                    DeliveryMethodsSupported = [SsfDeliveryMethods.PushHttp, SsfDeliveryMethods.PollHttp],
                    AuthorizationSchemeSpecUrns = ["urn:ietf:rfc:6749"],
                    DefaultSubjects = SsfMetadataParameterNames.DefaultSubjectsNone
                });
        }).ConfigureAwait(false);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.SsfConfiguration,
            WellKnownHttpMethods.Get,
            new RequestFields(),
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        //Cross-validate the served document with the RECEIVER's strict parser:
        //transmitter-side emission and receiver-side consumption must agree on
        //the SSF §7.1 wire shape — a firewalled round trip over the document.
        SsfTransmitterConfiguration? config = SsfDiscoveryJsonParsing.ParseTransmitterConfiguration(response.Body);
        Assert.IsNotNull(config, $"The served ssf-configuration must parse strictly. Body: {response.Body}");
        Assert.IsFalse(string.IsNullOrEmpty(config.Issuer), "issuer is REQUIRED (SSF §7.1).");
        Assert.AreEqual("1_0", config.SpecVersion, "spec_version must name the implemented final spec.");
        Assert.IsNotNull(config.JwksUri,
            "jwks_uri must be advertised from the chain — SETs are signed JWTs the Receiver verifies.");
        Assert.HasCount(2, config.DeliveryMethodsSupported!);
        Assert.IsTrue(SsfDeliveryMethods.IsPushHttp(config.DeliveryMethodsSupported![0]));
        Assert.IsTrue(SsfDeliveryMethods.IsPollHttp(config.DeliveryMethodsSupported[1]));
        Assert.HasCount(1, config.AuthorizationSchemes!);
        Assert.AreEqual("urn:ietf:rfc:6749", config.AuthorizationSchemes![0].SpecUrn);
        Assert.AreEqual(SsfMetadataParameterNames.DefaultSubjectsNone, config.DefaultSubjects);
    }


    /// <summary>
    /// Checks that the resource metadata matches its resource identifier and the authorization server advertises that resource.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.3">RFC 9728 §3.3</see>.
    /// </summary>
    [TestMethod]
    public async Task ProtectedResourceMetadataIsServedAndConformant()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Fapi20, capabilities: TokenServerCapabilities).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ContributeProtectedResourceMetadataAsync = static (_, _, _) =>
                ValueTask.FromResult(new Verifiable.OAuth.ProtectedResource.ProtectedResourceMetadataContribution
                {
                    ScopesSupported = [WellKnownScopes.SsfRead, WellKnownScopes.SsfManage],
                    BearerMethodsSupported = [Verifiable.OAuth.ProtectedResource.BearerMethodValues.Header]
                });


            //RFC 9728 §4: the co-located AS enumerates its protected resources in
            //its own metadata through the existing discovery-fields seam.

            candidateIntegration.ContributeDiscoveryFieldsAsync = static (registration, _, _) =>
                ValueTask.FromResult(new DiscoveryDocumentContribution(
                    [new DiscoveryStringArrayField(
                        AuthorizationServerMetadataParameterNames.ProtectedResources,
                        [registration.IssuerUri!.OriginalString])]));
        }).ConfigureAwait(false);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.ProtectedResourceMetadata,
            WellKnownHttpMethods.Get,
            new RequestFields(),
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        //Cross-validate the served document with the CONSUMER's strict parser
        //and run the §3.3 resource-match validation against the identity the
        //§3 well-known URL derives from.
        Verifiable.OAuth.ProtectedResource.ProtectedResourceMetadata? metadata =
            ProtectedResourceMetadataJsonParsing.ParseProtectedResourceMetadata(response.Body!);
        Assert.IsNotNull(metadata, $"The served document must parse strictly. Body: {response.Body}");
        Assert.IsTrue(Verifiable.OAuth.ProtectedResource.ProtectedResourceMetadataValidation.IsResourceMatch(
            metadata, material.Registration.IssuerUri!.OriginalString),
            "§3.3: resource must be identical to the identifier the metadata URL derives from.");
        Assert.IsNotNull(metadata.JwksUri, "jwks_uri is derived from the endpoint chain.");
        Assert.Contains(WellKnownScopes.SsfManage, metadata.ScopesSupported!,
            "The CAEP interop scope-discovery link: the RS advertises its SSF scopes here.");

        //The §4 cross-check: the AS's protected_resources lists the resource,
        //and the resource's document points back at this AS-co-located identity.
        ServerHttpResponse discovery = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.MetadataDiscovery,
            WellKnownHttpMethods.Get,
            new RequestFields(),
            [],
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, discovery.StatusCode, discovery.Body);

        using JsonDocument discoveryDoc = JsonDocument.Parse(discovery.Body!);
        JsonElement protectedResources = discoveryDoc.RootElement.GetProperty(
            AuthorizationServerMetadataParameterNames.ProtectedResources);
        Assert.AreEqual(metadata.Resource, protectedResources[0].GetString(),
            "§4: the AS-listed resource identifier and the resource's own document agree.");
    }


    [TestMethod]
    public async Task EverythingEnabledAuthorizationCodeFlowIssuesAndRefreshesTokens()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: TokenServerCapabilities).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);

        //Auth Code + PKCE + PAR -> token. The core OAuth/OIDC flow must still work with the
        //full capability surface registered — proving no inter-capability interference.
        ServerHttpResponse tokenResponse = await DriveCodeExchangeAsync(host, material, WellKnownScopes.OpenId)
            .ConfigureAwait(false);
        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);

        using JsonDocument tokenDoc = JsonDocument.Parse(tokenResponse.Body);
        Assert.IsTrue(tokenDoc.RootElement.TryGetProperty("access_token", out _),
            $"The token endpoint must return an access_token. Body: {tokenResponse.Body}");
        Assert.IsTrue(tokenDoc.RootElement.TryGetProperty("id_token", out _),
            $"OidcOpenIdConnect is enabled and openid was requested, so an id_token must be issued. Body: {tokenResponse.Body}");

        string refreshToken = ExtractFromBody(tokenResponse.Body, "refresh_token");

        //refresh_token grant -> fresh tokens, proving OAuthRefreshToken works on the same host.
        RequestFields refreshFields = new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.RefreshToken,
            [OAuthRequestParameterNames.RefreshToken] = refreshToken,
            [OAuthRequestParameterNames.ClientId] = ClientId
        };
        ServerHttpResponse refreshResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeToken, "POST",
            refreshFields, [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, refreshResponse.StatusCode, refreshResponse.Body);
        using JsonDocument refreshDoc = JsonDocument.Parse(refreshResponse.Body);
        Assert.IsTrue(refreshDoc.RootElement.TryGetProperty("access_token", out _),
            $"The refresh_token grant must return a fresh access_token. Body: {refreshResponse.Body}");

        //Positive control for the grant-identity invariant: this refresh token
        //originates from the authorization_code grant (not token_exchange), so per
        //Oidc10IdTokenProducer.IsApplicableAsync the redemption must still mint an
        //id_token — contrast TokenExchangeGrantTests
        //.RefreshTokenMintedByTokenExchangeNeverYieldsIdTokenOnRedemption, where a
        //token_exchange-originated refresh must NOT. Without this assertion, a
        //regression that drops id_token issuance from the authorization_code-origin
        //refresh walk would go undetected.
        Assert.IsTrue(refreshDoc.RootElement.TryGetProperty("id_token", out _),
            $"The refresh token originates from the authorization_code grant and openid was requested, " +
            $"so the refresh_token grant must still return an id_token. Body: {refreshResponse.Body}");
    }


    [TestMethod]
    public async Task TokenFlowRoutesCorrectlyWithPresentationAndFederationCoRegistered()
    {
        await using TestHostShell host = new(TimeProvider);
        _ = host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: TokenServerWithPresentationAndFederation).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);

        //With the OID4VP-verifier and Federation matchers co-registered alongside the
        //token-flow matchers on one host, an Auth Code + PKCE token request must still be
        //routed to the token endpoint — never greedily claimed by a VP or Federation
        //matcher. A mis-routing collision would surface here as a non-token response.
        ServerHttpResponse tokenResponse = await DriveCodeExchangeAsync(host, material, WellKnownScopes.OpenId)
            .ConfigureAwait(false);
        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);

        using JsonDocument tokenDoc = JsonDocument.Parse(tokenResponse.Body);
        Assert.IsTrue(tokenDoc.RootElement.TryGetProperty("access_token", out _),
            $"The token request must be handled by the token endpoint even with VP + Federation " +
            $"co-registered (no matcher hijack). Body: {tokenResponse.Body}");
        Assert.IsTrue(tokenDoc.RootElement.TryGetProperty("id_token", out _),
            $"An id_token must still be issued. Body: {tokenResponse.Body}");
    }


    [TestMethod]
    public async Task VpPresentationAndTokenFlowBothRouteCorrectlyOnOneHost()
    {
        //The fixture builds a host wired as an SD-JWT VC OID4VP verifier (issuer trust,
        //DCQL query, presentation drop-out). We co-register a token-AS client on the SAME
        //host and drive BOTH a live VP presentation and the auth-code token flow, asserting
        //each request reaches its own handler — the presentation the verifier
        //(PresentationVerifiedState), the token request the token endpoint — with no hijack
        //in either direction.
        await using FormatRun run = await SdJwtVpFixture.Format.StartAsync(
            TimeProvider, TestContext.CancellationToken).ConfigureAwait(false);
        TestHostShell app = run.App;

        _ = app.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial tokenClient = await app.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: TokenServerCapabilities).ConfigureAwait(false);
        _ = await app.EnableDpopAsync().ConfigureAwait(false);

        using VerifierKeyMaterial verifierKeys = await app.RegisterClientAsync(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities).ConfigureAwait(false);

        //--- A live VP presentation must reach the OID4VP verifier ---
        (Uri requestUri, string parHandle) = await app.HandleParAsync(
            verifierKeys, new TransactionNonce($"nonce-{Guid.NewGuid():N}"), run.Query,
            TestContext.CancellationToken).ConfigureAwait(false);
        string compactJar = await app.HandleJarRequestAsync(
            verifierKeys, parHandle, TestContext.CancellationToken).ConfigureAwait(false);

        (OAuthClient oauthClient, _, _) = app.CreateInProcessOAuthClientAndRegistration(
            verifierKeys.Registration, "https://wallet.example.com/cb",
            verifierKeys.Registration.IssuerUri!.ToString());
        Oid4VpWalletClient walletClient = new(
            oauthClient.Infrastructure,
            TestHostShell.BuildSlimOid4VpWalletConfiguration(
                run.Produce, TestHostShell.PinnedVerifierKeyResolver(verifierKeys.SigningPublicKey)));

        PresentationResult presentation = await walletClient.PresentJarAsync(
            new PresentJarOptions
            {
                CompactJar = compactJar,
                RequestUri = requestUri,
                ExpectedVerifierClientId = VerifierClientId,
                FlowId = $"wallet-{Guid.NewGuid():N}"
            },
            TestContext.CancellationToken).ConfigureAwait(false);
        _ = Assert.IsInstanceOfType<ResponseSent>(presentation.TerminalState,
            "The VP presentation must reach the wallet ResponseSent terminal on the co-registered host.");
        run.AssertClaims((PresentationVerifiedState)app.GetFlowState(parHandle).State);

        //--- The auth-code token flow must reach the token endpoint on the SAME host ---
        ServerHttpResponse tokenResponse = await DriveCodeExchangeAsync(app, tokenClient, WellKnownScopes.OpenId)
            .ConfigureAwait(false);
        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);
        using JsonDocument tokenDoc = JsonDocument.Parse(tokenResponse.Body);
        Assert.IsTrue(tokenDoc.RootElement.TryGetProperty("access_token", out _),
            $"The token request must be handled by the token endpoint on the VP-verifier host (no hijack). Body: {tokenResponse.Body}");
    }


    private async Task<ServerHttpResponse> DriveCodeExchangeAsync(
        TestHostShell host, VerifierKeyMaterial material, string scope)
    {
        InProcessAuthCodeDriveResult result = await InProcessAuthCodeDriver.DriveAsync(
            host, material, SubjectId, RedirectUri,
            new InProcessAuthCodeDriveOptions { Scope = scope },
            TestContext.CancellationToken).ConfigureAwait(false);

        return result.TokenResponse;
    }


    private static string ExtractFromBody(string body, string property)
    {
        using JsonDocument doc = JsonDocument.Parse(body);
        return doc.RootElement.GetProperty(property).GetString()
            ?? throw new InvalidOperationException($"Body property '{property}' was null. Body: {body}");
    }


    private static List<string> EnumerateStrings(JsonElement array)
    {
        List<string> values = [];
        foreach(JsonElement entry in array.EnumerateArray())
        {
            values.Add(entry.GetString() ?? string.Empty);
        }

        return values;
    }
}
