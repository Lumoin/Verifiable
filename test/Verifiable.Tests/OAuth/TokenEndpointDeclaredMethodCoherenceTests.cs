using System.Buffers;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Net.Http;
using System.Text;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.JwtBearer;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.TokenExchange;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The token endpoint's declared-method coherence rule. A registration's
/// <see cref="ClientRecord.TokenEndpointAuthMethod"/> and the server's
/// <see cref="AuthorizationServerIntegration.ClientAuthenticationMethodsSupported"/> advertisement are
/// one set: <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02">OAuth
/// Client ID Metadata Document, Section 8.2</see> states "This establishes this client as a
/// confidential client, and any communication with the authorization server MUST include client
/// authentication of the registered type." and "When a client declares token_endpoint_auth_method as
/// private_key_jwt, the authorization server MUST require client authentication according to Section
/// 2.2 of [RFC7523] using the corresponding key discovered from the client's metadata document." A
/// registration declaring a confidential method the token endpoint does not advertise is refused with
/// <c>401 invalid_client</c> before any validator runs; a registration declaring an advertised method
/// is handed to <see cref="AuthorizationServerIntegration.ValidateClientCredentialsAsync"/> for
/// judgment; a registration declaring nothing keeps the public-client path. The rule holds on the
/// authorization-code grant, the refresh-token grant, and the RFC 7523 JWT Bearer grant.
/// </summary>
[TestClass]
internal sealed class TokenEndpointDeclaredMethodCoherenceTests
{
    /// <summary>MSTest's per-test context, supplying the cancellation token every wire call runs under.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The clock the host and the client share.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    private const string ClientId = "https://coherence.client.test";

    private const string SubjectId = "subject-declared-method-coherence-01";

    private const string ClientSecret = "s3cret-of-the-coherence-client";

    private static Uri ClientBaseUri { get; } = new(ClientId);

    private static Uri RedirectUri { get; } = new("https://client.example.com/callback");

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>
    /// The signing key identifier the client stamps into the <c>client_assertion</c> header and the
    /// server publishes in its <c>ClientJwks</c>, so the <c>private_key_jwt</c> validator can resolve
    /// the verification key by <c>kid</c> (RFC 7523 Section 2.2).
    /// </summary>
    private const string SigningKeyId = "coherence-client-key-1";

    /// <summary>
    /// The capability set for the JWT Bearer coherence case: the token-endpoint grants plus
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthJwtBearer"/>, which — together with a wired
    /// <see cref="AuthorizationServerIntegration.ValidateJwtBearerAssertionAsync"/> — puts the RFC 7523
    /// jwt-bearer grant on the endpoint chain.
    /// </summary>
    private static ImmutableHashSet<CapabilityIdentifier> JwtBearerCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthPushedAuthorization,
            WellKnownCapabilityIdentifiers.OAuthJwtBearer,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint);


    /// <summary>
    /// The capability set for the stateless-grant coherence cases: the token-endpoint grants plus
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthClientCredentials"/> and
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthTokenExchange"/>, which put the RFC 6749 §4.4
    /// client_credentials grant and the RFC 8693 token-exchange grant on the endpoint chain — the two
    /// grants that authenticate the client by calling
    /// <see cref="AuthorizationServerIntegration.ValidateClientCredentialsAsync"/> directly.
    /// </summary>
    private static ImmutableHashSet<CapabilityIdentifier> StatelessGrantCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthClientCredentials,
            WellKnownCapabilityIdentifiers.OAuthTokenExchange,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint);


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02">OAuth
    /// Client ID Metadata Document, Section 8.2</see>: "This establishes this client as a confidential
    /// client, and any communication with the authorization server MUST include client authentication
    /// of the registered type." A registration declaring <c>private_key_jwt</c> on a token endpoint
    /// that advertises only <see cref="ClientAuthenticationMethod.None"/> is incoherent — the endpoint
    /// cannot honour the method — so the authorization-code grant is refused with
    /// <c>401 invalid_client</c> before <see cref="AuthorizationServerIntegration.ValidateClientCredentialsAsync"/>
    /// is ever consulted. The counting validator would authenticate every request, so a count of zero
    /// proves the refusal is the coherence gate, not the validator's verdict.
    /// </summary>
    [TestMethod]
    public async Task AuthorizationCodeGrantRefusesDeclaredMethodTheEndpointDoesNotAdvertise()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        int validatorInvocations = 0;
        host.Server.OAuth().ValidateClientCredentialsAsync = (request, fields, registration, context, ct) =>
        {
            validatorInvocations++;

            return ValueTask.FromResult(true);
        };

        DeclareServerSideMethodWithoutAdvertising(host, material, ClientAuthenticationMethod.PrivateKeyJwt);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                RedirectUri.OriginalString,
                profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);
        //The client-side registration stays at its None default — the coherence refusal keys off the
        //server-side declaration, not on whether a credential was attached.

        using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;

        (string flowId, _) = await AuthCodeFlowDriver.DriveParAuthorizeAndCallbackAsync(
            hosted, client, registration, clientFlowStore, segment, RedirectUri, SubjectId, browserClient,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        AuthCodeFlowEndpointResult tokenResult = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreNotEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
            "A registration declaring a method the token endpoint does not advertise must not be issued a token.");
        Assert.AreEqual(OAuthErrors.InvalidClient, tokenResult.ErrorCode,
            "Section 8.2's confidential-client coherence rule refuses with invalid_client.");
        Assert.AreEqual(0, validatorInvocations,
            "The coherence refusal must precede any client-authentication validation.");
    }


    /// <summary>
    /// The refresh-token grant enforces the same
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02">OAuth
    /// Client ID Metadata Document, Section 8.2</see> coherence: "any communication with the
    /// authorization server MUST include client authentication of the registered type." Initial
    /// issuance runs as a public client (nothing declared) to obtain a refresh token; the server
    /// registration is then upgraded to declare <c>private_key_jwt</c> without the endpoint advertising
    /// it, and the refresh is refused with <c>401 invalid_client</c> before the counting validator runs.
    /// </summary>
    [TestMethod]
    public async Task RefreshGrantRefusesDeclaredMethodTheEndpointDoesNotAdvertise()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        int validatorInvocations = 0;
        host.Server.OAuth().ValidateClientCredentialsAsync = (request, fields, registration, context, ct) =>
        {
            validatorInvocations++;

            return ValueTask.FromResult(true);
        };

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                RedirectUri.OriginalString,
                profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;

        //Initial issuance as a public client — nothing declared server-side yet — mints the refresh token.
        AuthCodeFlowDriveResult drive = await AuthCodeFlowDriver.DriveParAuthorizeCallbackAndTokenAsync(
            hosted, client, registration, clientFlowStore, segment, RedirectUri, SubjectId, browserClient,
            scope: WellKnownScopes.OpenId, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        string originalRefreshToken = (string)drive.TokenResult.Body![OAuthRequestParameterNames.RefreshToken];

        //Upgrade the server-side record to declare private_key_jwt without advertising it, then refresh.
        DeclareServerSideMethodWithoutAdvertising(host, material, ClientAuthenticationMethod.PrivateKeyJwt);

        RefreshTokenRequest refreshRequest = new()
        {
            ClientId = registration.ClientId.Value,
            RefreshToken = originalRefreshToken
        };
        AuthCodeFlowEndpointResult refreshResult = await client.AuthCode.RefreshAsync(
            registration, refreshRequest, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreNotEqual(AuthCodeFlowEndpointOutcome.Ok, refreshResult.Outcome,
            "A refresh from a registration declaring an unadvertised method must not be issued new tokens.");
        Assert.AreEqual(OAuthErrors.InvalidClient, refreshResult.ErrorCode,
            "Section 8.2's coherence rule refuses the refresh with invalid_client.");
        Assert.AreEqual(0, validatorInvocations,
            "The coherence refusal must precede any client-authentication validation on the refresh leg.");
    }


    /// <summary>
    /// The RFC 7523 JWT Bearer grant enforces the same
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02">OAuth
    /// Client ID Metadata Document, Section 8.2</see> coherence: "any communication with the
    /// authorization server MUST include client authentication of the registered type." A
    /// credential-less redemption (a bare <c>client_id</c> plus an <c>assertion</c>, no
    /// <c>client_secret</c> or <c>client_assertion</c>) from a registration declaring
    /// <c>private_key_jwt</c> on an endpoint that advertises only
    /// <see cref="ClientAuthenticationMethod.None"/> is refused with <c>401 invalid_client</c> before
    /// either the client-authentication validator or the assertion validator runs.
    /// </summary>
    [TestMethod]
    public async Task JwtBearerGrantRefusesDeclaredMethodTheEndpointDoesNotAdvertise()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: JwtBearerCapabilities);

        int clientAuthInvocations = 0;
        host.Server.OAuth().ValidateClientCredentialsAsync = (request, fields, registration, context, ct) =>
        {
            clientAuthInvocations++;

            return ValueTask.FromResult(true);
        };

        int assertionInvocations = 0;
        host.Server.OAuth().ValidateJwtBearerAssertionAsync = (assertion, requestedScope, registration, context, ct) =>
        {
            assertionInvocations++;

            return ValueTask.FromResult<JwtBearerGrant?>(new JwtBearerGrant { Subject = SubjectId, Scope = string.Empty });
        };

        DeclareServerSideMethodWithoutAdvertising(host, material, ClientAuthenticationMethod.PrivateKeyJwt);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        HttpClient http = hosted.SharedHttpClient!;
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(
            hosted.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, segment));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.JwtBearer,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.Assertion] = "unreached.jwt.assertion"
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(401, (int)response.StatusCode, body);
        Assert.Contains(OAuthErrors.InvalidClient, body,
            "Section 8.2's coherence rule refuses the jwt-bearer redemption with invalid_client.");
        Assert.AreEqual(0, clientAuthInvocations,
            "The coherence refusal must precede any client-authentication validation on the jwt-bearer leg.");
        Assert.AreEqual(0, assertionInvocations,
            "The coherence refusal must precede assertion validation on the jwt-bearer leg.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02">OAuth
    /// Client ID Metadata Document, Section 8.2</see>: "When a client declares token_endpoint_auth_method
    /// as private_key_jwt, the authorization server MUST require client authentication according to
    /// Section 2.2 of [RFC7523] using the corresponding key discovered from the client's metadata
    /// document." When the endpoint advertises <c>private_key_jwt</c> the coherence gate passes and a
    /// valid client assertion (<see href="https://www.rfc-editor.org/rfc/rfc7523">RFC 7523, Section
    /// 2.2</see>) is judged by the real validator and accepted — the token is minted and the validator
    /// was reached.
    /// </summary>
    [TestMethod]
    public async Task AdvertisedPrivateKeyJwtWithValidAssertionIsJudgedAndAccepted()
    {
        var clientKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = host.RegisterDpopClient(
                ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

            await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
            HostedAuthorizationServer hosted = host.Host("default");
            string segment = material.Registration.TenantId.Value;
            Uri tokenEndpoint = new(
                hosted.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, segment));

            string alg = CryptoFormatConversions.DefaultTagToJwaConverter(clientKeys.PublicKey.Tag);
            string jwksJson = BuildJwksJson(clientKeys.PublicKey, alg, SigningKeyId);
            DeclareServerSideMethodAdvertised(
                host, material, ClientAuthenticationMethod.PrivateKeyJwt, jwksJson, alg);

            int validatorInvocations = 0;
            var realValidator = PrivateKeyJwtClientAuthentication.BuildValidator(
                additionalAcceptedAudiences: [tokenEndpoint.OriginalString]);
            host.Server.OAuth().ValidateClientCredentialsAsync = async (request, fields, registration, context, ct) =>
            {
                validatorInvocations++;

                return await realValidator(request, fields, registration, context, ct).ConfigureAwait(false);
            };

            (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
                await host.CreateOAuthClientAndRegistrationAsync(
                    material.Registration,
                    RedirectUri.OriginalString,
                    profile: PolicyProfile.Rfc6749WithPkce,
                    TestContext.CancellationToken).ConfigureAwait(false);
            registration = registration with
            {
                AuthenticationMethod = ClientAuthenticationMethod.PrivateKeyJwt,
                AuthenticationKeyMaterial = clientKeys
            };

            using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
            AuthCodeFlowDriveResult drive = await AuthCodeFlowDriver.DriveParAuthorizeCallbackAndTokenAsync(
                hosted, client, registration, clientFlowStore, segment, RedirectUri, SubjectId, browserClient,
                clientAssertionOptions: new ClientAssertionOptions
                {
                    SigningKeyId = SigningKeyId,
                    HeaderSerializer = host.Server.OAuth().Codecs.JwtHeaderSerializer!,
                    PayloadSerializer = host.Server.OAuth().Codecs.JwtPayloadSerializer!
                },
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, drive.TokenResult.Outcome,
                $"A valid client assertion for an advertised method must authenticate. ErrorCode={drive.TokenResult.ErrorCode} ErrorDescription={drive.TokenResult.ErrorDescription}");
            string accessToken = (string)drive.TokenResult.Body![OAuthRequestParameterNames.AccessToken];
            Assert.IsFalse(string.IsNullOrEmpty(accessToken), "The AS must mint an access token for the authenticated client.");
            Assert.IsGreaterThanOrEqualTo(1, validatorInvocations,
                "The advertised-method path must reach the client-authentication validator.");
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02">OAuth
    /// Client ID Metadata Document, Section 8.2</see> requires client authentication "using the
    /// corresponding key discovered from the client's metadata document." When the endpoint advertises
    /// <c>private_key_jwt</c> the coherence gate passes and the assertion is judged by the real
    /// validator (<see href="https://www.rfc-editor.org/rfc/rfc7523">RFC 7523, Section 2.2</see>); a
    /// client that signs with a key absent from the server's published <c>ClientJwks</c> — a foreign
    /// key — fails the signature check and is refused with <c>401 invalid_client</c>. The validator was
    /// reached and rendered the verdict.
    /// </summary>
    [TestMethod]
    public async Task AdvertisedPrivateKeyJwtWithForeignKeyIsJudgedAndRefused()
    {
        var clientKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        var foreignKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = host.RegisterDpopClient(
                ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

            await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
            HostedAuthorizationServer hosted = host.Host("default");
            string segment = material.Registration.TenantId.Value;
            Uri tokenEndpoint = new(
                hosted.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, segment));

            //The server publishes the FOREIGN key under the client's kid; the client signs with its own
            //key, so the resolved verification key never matches the assertion's signature.
            string alg = CryptoFormatConversions.DefaultTagToJwaConverter(clientKeys.PublicKey.Tag);
            string foreignJwksJson = BuildJwksJson(foreignKeys.PublicKey, alg, SigningKeyId);
            DeclareServerSideMethodAdvertised(
                host, material, ClientAuthenticationMethod.PrivateKeyJwt, foreignJwksJson, alg);

            int validatorInvocations = 0;
            var realValidator = PrivateKeyJwtClientAuthentication.BuildValidator(
                additionalAcceptedAudiences: [tokenEndpoint.OriginalString]);
            host.Server.OAuth().ValidateClientCredentialsAsync = async (request, fields, registration, context, ct) =>
            {
                validatorInvocations++;

                return await realValidator(request, fields, registration, context, ct).ConfigureAwait(false);
            };

            (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
                await host.CreateOAuthClientAndRegistrationAsync(
                    material.Registration,
                    RedirectUri.OriginalString,
                    profile: PolicyProfile.Rfc6749WithPkce,
                    TestContext.CancellationToken).ConfigureAwait(false);
            registration = registration with
            {
                AuthenticationMethod = ClientAuthenticationMethod.PrivateKeyJwt,
                AuthenticationKeyMaterial = clientKeys
            };

            using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
            (string flowId, _) = await AuthCodeFlowDriver.DriveParAuthorizeAndCallbackAsync(
                hosted, client, registration, clientFlowStore, segment, RedirectUri, SubjectId, browserClient,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            AuthCodeFlowEndpointResult tokenResult = await client.AuthCode.ExchangeTokenAsync(
                registration, flowId, new ExchangeContext(),
                new ClientAssertionOptions
                {
                    SigningKeyId = SigningKeyId,
                    HeaderSerializer = host.Server.OAuth().Codecs.JwtHeaderSerializer!,
                    PayloadSerializer = host.Server.OAuth().Codecs.JwtPayloadSerializer!
                },
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreNotEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
                "A client assertion signed by a key absent from the published JWKS must not authenticate.");
            Assert.AreEqual(OAuthErrors.InvalidClient, tokenResult.ErrorCode,
                "A foreign-key assertion is refused with invalid_client.");
            Assert.IsGreaterThanOrEqualTo(1, validatorInvocations,
                "The advertised-method path must reach the client-authentication validator to render the verdict.");
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
            foreignKeys.PublicKey.Dispose();
            foreignKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02">OAuth
    /// Client ID Metadata Document, Section 8.2</see>: "any communication with the authorization server
    /// MUST include client authentication of the registered type." A confidential registration declaring
    /// an advertised <c>private_key_jwt</c> that attaches NO client assertion is refused with
    /// <c>401 invalid_client</c> — the coherence gate passes, the validator is reached
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7523">RFC 7523, Section 2.2</see>), and a request
    /// carrying no assertion of the registered type fails closed.
    /// </summary>
    [TestMethod]
    public async Task AdvertisedPrivateKeyJwtWithoutAnyAssertionIsRefused()
    {
        var clientKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = host.RegisterDpopClient(
                ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

            await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
            HostedAuthorizationServer hosted = host.Host("default");
            string segment = material.Registration.TenantId.Value;
            Uri tokenEndpoint = new(
                hosted.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, segment));

            string alg = CryptoFormatConversions.DefaultTagToJwaConverter(clientKeys.PublicKey.Tag);
            string jwksJson = BuildJwksJson(clientKeys.PublicKey, alg, SigningKeyId);
            DeclareServerSideMethodAdvertised(
                host, material, ClientAuthenticationMethod.PrivateKeyJwt, jwksJson, alg);

            int validatorInvocations = 0;
            var realValidator = PrivateKeyJwtClientAuthentication.BuildValidator(
                additionalAcceptedAudiences: [tokenEndpoint.OriginalString]);
            host.Server.OAuth().ValidateClientCredentialsAsync = async (request, fields, registration, context, ct) =>
            {
                validatorInvocations++;

                return await realValidator(request, fields, registration, context, ct).ConfigureAwait(false);
            };

            (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
                await host.CreateOAuthClientAndRegistrationAsync(
                    material.Registration,
                    RedirectUri.OriginalString,
                    profile: PolicyProfile.Rfc6749WithPkce,
                    TestContext.CancellationToken).ConfigureAwait(false);
            //The client-side registration stays at its None default — it attaches no client_assertion at all.

            using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
            (string flowId, _) = await AuthCodeFlowDriver.DriveParAuthorizeAndCallbackAsync(
                hosted, client, registration, clientFlowStore, segment, RedirectUri, SubjectId, browserClient,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            AuthCodeFlowEndpointResult tokenResult = await client.AuthCode.ExchangeTokenAsync(
                registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreNotEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
                "A confidential client attaching no assertion of the registered type must not be issued a token.");
            Assert.AreEqual(OAuthErrors.InvalidClient, tokenResult.ErrorCode,
                "A missing client assertion for an advertised confidential method is refused with invalid_client.");
            Assert.IsGreaterThanOrEqualTo(1, validatorInvocations,
                "The advertised-method path reaches the validator, which fails closed on the absent assertion.");
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// The coherence refusal keys off a DECLARED method only. A registration declaring nothing is the
    /// PKCE-only public-client shape of
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02">OAuth
    /// Client ID Metadata Document, Section 8.2</see> — it is not a confidential client — so a
    /// credential-less authorization-code exchange proceeds and mints a token even when the endpoint
    /// advertises only <c>private_key_jwt</c>. No coherence gate applies to an undeclared registration.
    /// </summary>
    [TestMethod]
    public async Task UndeclaredRegistrationCredentiallessRequestProceedsAsPublicClient()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        //The endpoint advertises only private_key_jwt; the registration declares nothing.
        host.Server.OAuth().ClientAuthenticationMethodsSupported = [ClientAuthenticationMethod.PrivateKeyJwt];

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                RedirectUri.OriginalString,
                profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);
        //AuthenticationMethod stays at its None default — the client attaches nothing.

        using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;

        AuthCodeFlowDriveResult drive = await AuthCodeFlowDriver.DriveParAuthorizeCallbackAndTokenAsync(
            hosted, client, registration, clientFlowStore, segment, RedirectUri, SubjectId, browserClient,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, drive.TokenResult.Outcome,
            $"An undeclared registration is a public client and must not be caught by the coherence rule. ErrorCode={drive.TokenResult.ErrorCode} ErrorDescription={drive.TokenResult.ErrorDescription}");
        string accessToken = (string)drive.TokenResult.Body![OAuthRequestParameterNames.AccessToken];
        Assert.IsFalse(string.IsNullOrEmpty(accessToken), "The AS must mint an access token for the public client.");
    }


    /// <summary>
    /// For an undeclared registration, RFC 7523 Section 3.1's principle still governs — a presented
    /// credential is judged through the seam, unaffected by what the endpoint advertises. A registration
    /// declaring nothing that attaches a correct <c>client_secret_post</c> credential is validated by
    /// the wired seam and authenticated, even on an endpoint advertising only <c>private_key_jwt</c>:
    /// the <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02">OAuth
    /// Client ID Metadata Document, Section 8.2</see> coherence gate applies to declared confidential
    /// methods, not to a public registration's presented credentials.
    /// </summary>
    [TestMethod]
    public async Task UndeclaredRegistrationPresentedCredentialIsJudgedThroughTheSeam()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> secretMaterial = BuildSecretKeyMaterial(ClientSecret);
        try
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = host.RegisterDpopClient(
                ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

            //The endpoint advertises only private_key_jwt; the registration declares nothing.
            host.Server.OAuth().ClientAuthenticationMethodsSupported = [ClientAuthenticationMethod.PrivateKeyJwt];

            int validatorInvocations = 0;
            host.Server.OAuth().ValidateClientCredentialsAsync = (request, fields, registration, context, ct) =>
            {
                validatorInvocations++;

                return ValueTask.FromResult(
                    fields.TryGetValue(OAuthRequestParameterNames.ClientSecret, out string? secret)
                    && string.Equals(secret, ClientSecret, StringComparison.Ordinal));
            };

            (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
                await host.CreateOAuthClientAndRegistrationAsync(
                    material.Registration,
                    RedirectUri.OriginalString,
                    profile: PolicyProfile.Rfc6749WithPkce,
                    TestContext.CancellationToken).ConfigureAwait(false);
            registration = registration with
            {
                AuthenticationMethod = ClientAuthenticationMethod.ClientSecretPost,
                AuthenticationKeyMaterial = secretMaterial
            };

            using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
            HostedAuthorizationServer hosted = host.Host("default");
            string segment = material.Registration.TenantId.Value;

            AuthCodeFlowDriveResult drive = await AuthCodeFlowDriver.DriveParAuthorizeCallbackAndTokenAsync(
                hosted, client, registration, clientFlowStore, segment, RedirectUri, SubjectId, browserClient,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, drive.TokenResult.Outcome,
                $"A correct presented credential on an undeclared registration must be judged and accepted. ErrorCode={drive.TokenResult.ErrorCode} ErrorDescription={drive.TokenResult.ErrorDescription}");
            string accessToken = (string)drive.TokenResult.Body![OAuthRequestParameterNames.AccessToken];
            Assert.IsFalse(string.IsNullOrEmpty(accessToken), "The AS must mint an access token for the validated credential.");
            Assert.IsGreaterThanOrEqualTo(1, validatorInvocations,
                "A presented credential on an undeclared registration is routed through the validation seam.");
        }
        finally
        {
            secretMaterial.PublicKey.Dispose();
            secretMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// A registration declaring <see cref="ClientAuthenticationMethod.None"/> on an endpoint advertising
    /// only <see cref="ClientAuthenticationMethod.None"/> is coherent and unaffected: None is not a
    /// confidential method, so the
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02">OAuth
    /// Client ID Metadata Document, Section 8.2</see> refusal never fires and a credential-less
    /// authorization-code exchange mints a token.
    /// </summary>
    [TestMethod]
    public async Task DeclaredNoneOnNoneAdvertisingEndpointIsUnaffected()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        //Declare None explicitly server-side and advertise only None.
        DeclareServerSideMethodWithoutAdvertising(host, material, ClientAuthenticationMethod.None);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                RedirectUri.OriginalString,
                profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;

        AuthCodeFlowDriveResult drive = await AuthCodeFlowDriver.DriveParAuthorizeCallbackAndTokenAsync(
            hosted, client, registration, clientFlowStore, segment, RedirectUri, SubjectId, browserClient,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, drive.TokenResult.Outcome,
            $"A registration declaring None on a None-advertising endpoint must mint a token unchanged. ErrorCode={drive.TokenResult.ErrorCode} ErrorDescription={drive.TokenResult.ErrorDescription}");
        string accessToken = (string)drive.TokenResult.Body![OAuthRequestParameterNames.AccessToken];
        Assert.IsFalse(string.IsNullOrEmpty(accessToken), "The AS must mint an access token for the public None client.");
    }


    /// <summary>
    /// The RFC 6749 §4.4 client_credentials grant authenticates the client by calling
    /// <see cref="AuthorizationServerIntegration.ValidateClientCredentialsAsync"/> directly, so it
    /// enforces the same
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02">OAuth
    /// Client ID Metadata Document, Section 8.2</see> coherence: a registration declaring
    /// <c>client_secret_post</c> on an endpoint advertising only
    /// <see cref="ClientAuthenticationMethod.None"/> is refused with <c>401 invalid_client</c> before the
    /// counting validator runs, so a count of zero proves the coherence gate precedes authentication.
    /// </summary>
    [TestMethod]
    public async Task ClientCredentialsGrantRefusesDeclaredMethodTheEndpointDoesNotAdvertise()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: StatelessGrantCapabilities);

        int validatorInvocations = 0;
        host.Server.OAuth().ValidateClientCredentialsAsync = (request, fields, registration, context, ct) =>
        {
            validatorInvocations++;

            return ValueTask.FromResult(true);
        };

        DeclareServerSideMethodWithoutAdvertising(host, material, ClientAuthenticationMethod.ClientSecretPost);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(
            hosted.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, segment));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(hosted.SharedHttpClient!, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ClientSecret] = ClientSecret
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(401, (int)response.StatusCode, body);
        Assert.Contains(OAuthErrors.InvalidClient, body,
            "Section 8.2's coherence rule refuses the client_credentials grant with invalid_client.");
        Assert.AreEqual(0, validatorInvocations,
            "The coherence refusal must precede any client-authentication validation on the client_credentials grant.");
    }


    /// <summary>
    /// When the endpoint advertises <c>client_secret_post</c> the client_credentials coherence gate
    /// passes and the request is handed to
    /// <see cref="AuthorizationServerIntegration.ValidateClientCredentialsAsync"/> for judgment
    /// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02">OAuth
    /// Client ID Metadata Document, Section 8.2</see>): the counting validator is reached, authenticates
    /// the presented secret, and the access token is minted.
    /// </summary>
    [TestMethod]
    public async Task ClientCredentialsGrantAdvertisedMethodReachesTheValidator()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: StatelessGrantCapabilities);

        int validatorInvocations = 0;
        host.Server.OAuth().ValidateClientCredentialsAsync = (request, fields, registration, context, ct) =>
        {
            validatorInvocations++;

            return ValueTask.FromResult(
                fields.TryGetValue(OAuthRequestParameterNames.ClientSecret, out string? secret)
                && string.Equals(secret, ClientSecret, StringComparison.Ordinal));
        };

        DeclareServerSideSecretMethodAdvertised(host, material, ClientAuthenticationMethod.ClientSecretPost);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(
            hosted.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, segment));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(hosted.SharedHttpClient!, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ClientSecret] = ClientSecret
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, (int)response.StatusCode, body);
        Assert.IsGreaterThanOrEqualTo(1, validatorInvocations,
            "The advertised-method path must reach the client-authentication validator on the client_credentials grant.");
    }


    /// <summary>
    /// The RFC 8693 token-exchange grant authenticates the client by calling
    /// <see cref="AuthorizationServerIntegration.ValidateClientCredentialsAsync"/> directly, so it
    /// enforces the same
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02">OAuth
    /// Client ID Metadata Document, Section 8.2</see> coherence: a registration declaring
    /// <c>client_secret_post</c> on an endpoint advertising only
    /// <see cref="ClientAuthenticationMethod.None"/> is refused with <c>401 invalid_client</c> before the
    /// counting validator runs, so a count of zero proves the coherence gate precedes authentication.
    /// </summary>
    [TestMethod]
    public async Task TokenExchangeGrantRefusesDeclaredMethodTheEndpointDoesNotAdvertise()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: StatelessGrantCapabilities);

        int validatorInvocations = 0;
        host.Server.OAuth().ValidateClientCredentialsAsync = (request, fields, registration, context, ct) =>
        {
            validatorInvocations++;

            return ValueTask.FromResult(true);
        };

        //The seams are wired only so the RFC 8693 grant is placed on the endpoint chain; the coherence
        //refusal fires before either of them is consulted.
        host.Server.OAuth().ValidateTokenExchangeTokenAsync = static (token, tokenType, registration, context, ct) =>
            ValueTask.FromResult<ValidatedSecurityToken?>(new ValidatedSecurityToken { Subject = SubjectId });
        host.Server.OAuth().AuthorizeTokenExchangeAsync = static (subject, actor, request, registration, context, ct) =>
            ValueTask.FromResult<TokenExchangeAuthorization?>(
                new TokenExchangeAuthorization { Subject = subject.Subject, Scope = WellKnownScopes.OpenId });

        DeclareServerSideMethodWithoutAdvertising(host, material, ClientAuthenticationMethod.ClientSecretPost);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(
            hosted.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, segment));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(hosted.SharedHttpClient!, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ClientSecret] = ClientSecret,
            [OAuthRequestParameterNames.SubjectToken] = "subject-token-opaque-blob",
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.IdToken)
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(401, (int)response.StatusCode, body);
        Assert.Contains(OAuthErrors.InvalidClient, body,
            "Section 8.2's coherence rule refuses the token-exchange grant with invalid_client.");
        Assert.AreEqual(0, validatorInvocations,
            "The coherence refusal must precede any client-authentication validation on the token-exchange grant.");
    }


    /// <summary>
    /// When the endpoint advertises <c>client_secret_post</c> the token-exchange coherence gate passes
    /// and the request is handed to
    /// <see cref="AuthorizationServerIntegration.ValidateClientCredentialsAsync"/> for judgment
    /// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02">OAuth
    /// Client ID Metadata Document, Section 8.2</see>): the counting validator is reached, authenticates
    /// the presented secret, and the exchanged access token is minted.
    /// </summary>
    [TestMethod]
    public async Task TokenExchangeGrantAdvertisedMethodReachesTheValidator()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: StatelessGrantCapabilities);

        int validatorInvocations = 0;
        host.Server.OAuth().ValidateClientCredentialsAsync = (request, fields, registration, context, ct) =>
        {
            validatorInvocations++;

            return ValueTask.FromResult(
                fields.TryGetValue(OAuthRequestParameterNames.ClientSecret, out string? secret)
                && string.Equals(secret, ClientSecret, StringComparison.Ordinal));
        };
        host.Server.OAuth().ValidateTokenExchangeTokenAsync = static (token, tokenType, registration, context, ct) =>
            ValueTask.FromResult<ValidatedSecurityToken?>(new ValidatedSecurityToken { Subject = SubjectId });
        host.Server.OAuth().AuthorizeTokenExchangeAsync = static (subject, actor, request, registration, context, ct) =>
            ValueTask.FromResult<TokenExchangeAuthorization?>(
                new TokenExchangeAuthorization
                {
                    Subject = subject.Subject,
                    Scope = WellKnownScopes.OpenId,
                    IssuedTokenType = TokenType.AccessToken
                });

        DeclareServerSideSecretMethodAdvertised(host, material, ClientAuthenticationMethod.ClientSecretPost);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(
            hosted.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, segment));

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(hosted.SharedHttpClient!, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.TokenExchange,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.ClientSecret] = ClientSecret,
            [OAuthRequestParameterNames.SubjectToken] = "subject-token-opaque-blob",
            [OAuthRequestParameterNames.SubjectTokenType] = TokenTypeNames.GetName(TokenType.IdToken)
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, (int)response.StatusCode, body);
        Assert.IsGreaterThanOrEqualTo(1, validatorInvocations,
            "The advertised-method path must reach the client-authentication validator on the token-exchange grant.");
    }


    /// <summary>
    /// Re-registers the server-side <see cref="ClientRecord"/> with
    /// <see cref="ClientRecord.TokenEndpointAuthMethod"/> set to <paramref name="method"/> — a
    /// secret-based method that needs no signing-algorithm advertisement — and advertises it alongside
    /// <see cref="ClientAuthenticationMethod.None"/> in
    /// <see cref="AuthorizationServerIntegration.ClientAuthenticationMethodsSupported"/> (RFC 8414,
    /// Section 2), the coherent arrangement where the declared method is one the endpoint honours.
    /// </summary>
    /// <param name="host">The test host whose default server-side record is upgraded.</param>
    /// <param name="material">The registration whose method is declared and advertised.</param>
    /// <param name="method">The secret-based confidential method to declare and advertise.</param>
    private static void DeclareServerSideSecretMethodAdvertised(
        TestHostShell host,
        VerifierKeyMaterial material,
        ClientAuthenticationMethod method)
    {
        UpdateServerRecordMethod(host, material, method, clientJwks: null);
        host.Server.OAuth().ClientAuthenticationMethodsSupported = [ClientAuthenticationMethod.None, method];
    }


    /// <summary>
    /// Re-registers the server-side <see cref="ClientRecord"/> with
    /// <see cref="ClientRecord.TokenEndpointAuthMethod"/> set to <paramref name="method"/> while the
    /// endpoint advertises ONLY <see cref="ClientAuthenticationMethod.None"/> — the incoherent
    /// arrangement the token endpoint refuses under
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02">OAuth
    /// Client ID Metadata Document, Section 8.2</see>. Uses the register-then-upgrade pattern the
    /// sibling grant suites use, because the routing dictionaries are host-internal.
    /// </summary>
    private static void DeclareServerSideMethodWithoutAdvertising(
        TestHostShell host,
        VerifierKeyMaterial material,
        ClientAuthenticationMethod method)
    {
        UpdateServerRecordMethod(host, material, method, clientJwks: null);
        host.Server.OAuth().ClientAuthenticationMethodsSupported = [ClientAuthenticationMethod.None];
    }


    /// <summary>
    /// Re-registers the server-side <see cref="ClientRecord"/> with
    /// <see cref="ClientRecord.TokenEndpointAuthMethod"/> set to <paramref name="method"/> and publishes
    /// <paramref name="clientJwks"/>, while the endpoint advertises <paramref name="method"/> alongside
    /// <see cref="ClientAuthenticationMethod.None"/> and names <paramref name="assertionSigningAlgorithm"/>
    /// in <see cref="AuthorizationServerIntegration.ClientAssertionSigningAlgorithmsSupported"/>
    /// (RFC 8414, Section 2) — the coherent arrangement where the declared method is one the endpoint
    /// honours and the assertion is handed to the validator for judgment.
    /// </summary>
    private static void DeclareServerSideMethodAdvertised(
        TestHostShell host,
        VerifierKeyMaterial material,
        ClientAuthenticationMethod method,
        string clientJwks,
        string assertionSigningAlgorithm)
    {
        UpdateServerRecordMethod(host, material, method, clientJwks);
        host.Server.OAuth().ClientAuthenticationMethodsSupported = [ClientAuthenticationMethod.None, method];
        host.Server.OAuth().ClientAssertionSigningAlgorithmsSupported = [assertionSigningAlgorithm];
    }


    /// <summary>
    /// Swaps the default host's server-side <see cref="ClientRecord"/> for one whose
    /// <see cref="ClientRecord.TokenEndpointAuthMethod"/> is <paramref name="method"/> and whose
    /// <see cref="ClientRecord.ClientJwks"/> is <paramref name="clientJwks"/>, updating both routing
    /// keys and <paramref name="material"/>'s registration so subsequent flow steps see the upgraded
    /// record. The routing dictionaries are host-internal, so the record is replaced through
    /// <see cref="EndpointServer.UpdateClient"/> the way the sibling grant suites do.
    /// </summary>
    private static void UpdateServerRecordMethod(
        TestHostShell host,
        VerifierKeyMaterial material,
        ClientAuthenticationMethod method,
        string? clientJwks)
    {
        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;
        ClientRecord previous = hosted.Registrations[segment];
        ClientRecord updated = previous with
        {
            TokenEndpointAuthMethod = method,
            ClientJwks = clientJwks
        };

        hosted.Registrations[segment] = updated;
        hosted.Registrations[updated.ClientId] = updated;
        hosted.Server.UpdateClient(previous, updated, new ExchangeContext());

        material.Registration = updated;
    }


    /// <summary>
    /// Builds a single-key JWKS JSON document from <paramref name="publicKey"/> under
    /// <paramref name="alg"/> and <paramref name="kid"/> — the <c>ClientJwks</c> the server-side
    /// <c>private_key_jwt</c> validator resolves the verification key from (RFC 7523 Section 2.2). The
    /// same shape the sibling confidential-client suites publish.
    /// </summary>
    private static string BuildJwksJson(PublicKeyMemory publicKey, string alg, string kid)
    {
        IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(publicKey, alg, TestSetup.Base64UrlEncoder);
        StringBuilder sb = new();
        sb.Append('{').Append('"').Append(WellKnownJwkMemberNames.Keys).Append("\":[{");
        foreach(KeyValuePair<string, string> member in jwk)
        {
            sb.Append('"').Append(member.Key).Append("\":\"").Append(member.Value).Append("\",");
        }

        sb.Append('"').Append(WellKnownJwkMemberNames.Kid).Append("\":\"").Append(kid).Append("\"}]}");

        return sb.ToString();
    }


    /// <summary>
    /// Wraps <paramref name="secret"/>'s UTF-8 bytes as a <see cref="PrivateKeyMemory"/> carrying no
    /// crypto tag (<see cref="Tag.Empty"/>) — a bare RFC 6749 Section 2.3.1 shared secret is not an
    /// asymmetric key, so none of the algorithm-specific <see cref="CryptoTags"/> entries apply. The
    /// paired <see cref="PublicKeyMemory"/> is never read; only the <c>PrivateKey</c> half is consulted
    /// for <c>client_secret_post</c>.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership transfers to the caller, which disposes both halves via secretMaterial.PublicKey/PrivateKey.")]
    private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> BuildSecretKeyMaterial(string secret)
    {
        byte[] secretBytes = Encoding.UTF8.GetBytes(secret);
        IMemoryOwner<byte> secretOwner = Pool.Rent(secretBytes.Length);
        secretBytes.CopyTo(secretOwner.Memory.Span);
        PrivateKeyMemory privateKey = new(secretOwner, Tag.Empty);

        //Never read — client_secret_post consults only the PrivateKey half — but a
        //PublicPrivateKeyMaterial pair requires one regardless.
        IMemoryOwner<byte> unusedPublicOwner = Pool.Rent(1);
        PublicKeyMemory publicKey = new(unusedPublicOwner, Tag.Empty);

        return new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(publicKey, privateKey);
    }
}
