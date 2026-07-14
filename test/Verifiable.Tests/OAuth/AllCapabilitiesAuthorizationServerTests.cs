using System.Collections.Immutable;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Core.SecurityEvents;
using Verifiable.Cryptography;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Logout;
using Verifiable.OAuth.Ssf;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.States;
using Verifiable.OAuth.Oid4Vp.Wallet;
using Verifiable.OAuth.Oid4Vp.Wallet.States;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Metadata;
using Verifiable.Server;
using Verifiable.Server.Routing;
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
    private static readonly Uri ClientBaseUri = new("https://all-capabilities.client.test");
    private const string SubjectId = "subject-all-caps-1";

    //RegisterDpopClient hard-codes this as the single allowed redirect URI.
    private static readonly Uri RedirectUri = new("https://client.example.com/callback");

    private const string VerifierClientId = "https://verifier.example.com";
    private static readonly Uri VerifierBaseUri = new("https://verifier.example.com");
    private static readonly ImmutableHashSet<CapabilityIdentifier> Oid4VpCapabilities =
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
            WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata);

    /// <summary>The token-AS capabilities plus the OID4VP-verifier and Federation roles, all co-registered.</summary>
    private static ImmutableHashSet<CapabilityIdentifier> TokenServerWithPresentationAndFederation { get; } =
        TokenServerCapabilities
            .Add(WellKnownCapabilityIdentifiers.VcVerifiablePresentation)
            .Add(WellKnownCapabilityIdentifiers.FederationBase);


    [TestMethod]
    public async Task EverythingEnabledDiscoveryDocumentIsCoherent()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Fapi20, capabilities: TokenServerCapabilities);

        //ValidateDpopProofAsync is the gate for advertising dpop_signing_alg_values_supported.
        host.EnableDpop();

        //ValidateClientCredentialsAsync is the gate for the client_credentials
        //grant — without it the grant endpoint does not exist (fail-closed).
        host.Server.OAuth().ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(true);

        //RevokeTokenAsync + ValidateClientCredentialsAsync together gate the RFC 7009
        //revocation endpoint — both must be wired for revocation_endpoint to be advertised.
        host.Server.OAuth().RevokeTokenAsync = static (_, _, _, _, _) =>
            ValueTask.CompletedTask;

        //Global Token Revocation: capability + the default JSON parse seam + the
        //revoke-subject seam + client auth gate the endpoint — wiring them advertises
        //global_token_revocation_endpoint.
        host.Server.OAuth().UseDefaultGlobalTokenRevocationJsonParsing();
        host.Server.OAuth().RevokeSubjectTokensAsync = static (_, _, _, _) =>
            ValueTask.FromResult(GlobalTokenRevocationOutcome.Initiated);

        //RP-Initiated Logout: capability + TerminateSessionAsync + the (host-wired)
        //verification-key resolver gate the end_session endpoint — wiring the seam
        //advertises end_session_endpoint.
        host.Server.OAuth().TerminateSessionAsync = static (_, _, _, _, _) =>
            ValueTask.CompletedTask;

        //Back-Channel Logout: capability + the deliver (fan-out) seam advertise
        //backchannel_logout_supported / backchannel_logout_session_supported.
        host.Server.OAuth().DeliverBackChannelLogoutAsync = static (_, _, _, _, _) =>
            ValueTask.CompletedTask;

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.MetadataDiscovery,
            WellKnownHttpMethods.Get,
            new RequestFields(),
            new ExchangeContext(),
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
        };
        foreach(JsonProperty prop in root.EnumerateObject())
        {
            Assert.Contains(prop.Name, justified,
                $"Discovery document advertises '{prop.Name}', which is not justified by any enabled " +
                $"capability (unwired field or role bleed). Body: {response.Body}");
        }
    }


    [TestMethod]
    public async Task SsfTransmitterConfigurationIsServedAndConformant()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Fapi20, capabilities: TokenServerCapabilities);

        host.Server.OAuth().ContributeSsfTransmitterMetadataAsync = static (_, _, _) =>
            ValueTask.FromResult(new SsfTransmitterMetadataContribution
            {
                DeliveryMethodsSupported = [SsfDeliveryMethods.PushHttp, SsfDeliveryMethods.PollHttp],
                AuthorizationSchemeSpecUrns = ["urn:ietf:rfc:6749"],
                DefaultSubjects = SsfMetadataParameterNames.DefaultSubjectsNone
            });

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.SsfConfiguration,
            WellKnownHttpMethods.Get,
            new RequestFields(),
            new ExchangeContext(),
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


    [TestMethod]
    public async Task ProtectedResourceMetadataIsServedAndConformant()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Fapi20, capabilities: TokenServerCapabilities);

        host.Server.OAuth().ContributeProtectedResourceMetadataAsync = static (_, _, _) =>
            ValueTask.FromResult(new Verifiable.OAuth.ProtectedResource.ProtectedResourceMetadataContribution
            {
                ScopesSupported = [WellKnownScopes.SsfRead, WellKnownScopes.SsfManage],
                BearerMethodsSupported = [Verifiable.OAuth.ProtectedResource.BearerMethodValues.Header]
            });

        //RFC 9728 §4: the co-located AS enumerates its protected resources in
        //its own metadata through the existing discovery-fields seam.
        host.Server.OAuth().ContributeDiscoveryFieldsAsync = static (registration, _, _) =>
            ValueTask.FromResult(new DiscoveryDocumentContribution(
                [new DiscoveryStringArrayField(
                    AuthorizationServerMetadataParameterNames.ProtectedResources,
                    [registration.IssuerUri!.OriginalString])]));

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.ProtectedResourceMetadata,
            WellKnownHttpMethods.Get,
            new RequestFields(),
            new ExchangeContext(),
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
            new ExchangeContext(),
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
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: TokenServerCapabilities);
        host.EnableDpop();

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
            refreshFields, new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, refreshResponse.StatusCode, refreshResponse.Body);
        using JsonDocument refreshDoc = JsonDocument.Parse(refreshResponse.Body);
        Assert.IsTrue(refreshDoc.RootElement.TryGetProperty("access_token", out _),
            $"The refresh_token grant must return a fresh access_token. Body: {refreshResponse.Body}");
    }


    [TestMethod]
    public async Task TokenFlowRoutesCorrectlyWithPresentationAndFederationCoRegistered()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: TokenServerWithPresentationAndFederation);
        host.EnableDpop();

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

        app.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial tokenClient = app.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: TokenServerCapabilities);
        app.EnableDpop();

        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

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
        Assert.IsInstanceOfType<ResponseSent>(presentation.TerminalState,
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
        PkceParameters pkce = PkceGeneration.Generate(
            TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        RequestFields parFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = scope
        };
        ServerHttpResponse parResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodePar, "POST",
            parFields, new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parResponse.StatusCode, parResponse.Body);
        string requestUri = ExtractFromBody(parResponse.Body, "request_uri");

        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri
        };
        ExchangeContext authorizeContext = new();
        authorizeContext.SetSubjectId(SubjectId);
        ServerHttpResponse authorizeResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize, WellKnownHttpMethods.Get,
            authorizeFields, authorizeContext,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        string code = ExtractCode(authorizeResponse.Location!);

        RequestFields tokenFields = new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.AuthorizationCode,
            [OAuthRequestParameterNames.Code] = code,
            [OAuthRequestParameterNames.CodeVerifier] = pkce.EncodedVerifier,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString
        };

        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeToken, "POST",
            tokenFields, new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    private static string ExtractFromBody(string body, string property)
    {
        using JsonDocument doc = JsonDocument.Parse(body);
        return doc.RootElement.GetProperty(property).GetString()
            ?? throw new InvalidOperationException($"Body property '{property}' was null. Body: {body}");
    }


    private static string ExtractCode(string location)
    {
        int q = location.IndexOf('?', StringComparison.Ordinal);
        foreach(string pair in location[(q + 1)..].Split('&'))
        {
            int eq = pair.IndexOf('=', StringComparison.Ordinal);
            if(eq > 0 && string.Equals(
                pair[..eq], OAuthRequestParameterNames.Code, StringComparison.Ordinal))
            {
                return Uri.UnescapeDataString(pair[(eq + 1)..]);
            }
        }

        throw new InvalidOperationException(
            $"Authorize redirect did not carry a code parameter: {location}");
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
