using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Core.OutboundFetch;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.OAuth.WellKnown;
using Verifiable.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The flagship real-wire CIMD suite (template: <c>WebFingerCrossWireFlowTests</c>): a genuine
/// Client ID Metadata Document host (<see cref="StaticContentHost"/> or <see cref="CimdServiceHost"/>,
/// both TLS) beside the real <see cref="EndpointServer.DispatchAsync"/> authorization-server path
/// (through <see cref="TestHostShell"/>'s Kestrel host, also TLS, both pinned) — every clause this
/// class proves is exercised by bytes that crossed a real loopback socket, per
/// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html">
/// draft-ietf-oauth-client-id-metadata-document-02</see>.
/// </summary>
/// <remarks>
/// Covers CIMD-02-clause-ledger rows 003, 012, 018, 026, 027, 029, 031, 032, 041, 042, 045, 046, 047,
/// 048, 049, 050, 062, 063, 064, 065, 066, 067 (slice E1 — the happy-path half of the D12 flagship
/// suite; SSRF/cache/negative-fetch rows belong to the companion slice). Every host uses
/// <see cref="TestHostShell.StartHttpHostAsync(CancellationToken)"/>'s or
/// <see cref="StaticContentHost.StartAsync"/>'s single explicit HTTPS <c>Listen</c> convention — there
/// is no plaintext listener anywhere in this file — and every test builds its own hosts, so the suite
/// is parallel-safe.
/// </remarks>
[TestClass]
internal sealed class ClientIdMetadataDocumentCrossWireFlowTests
{
    public TestContext TestContext { get; set; } = null!;

    private const string SubjectId = "subject-cimd-cross-wire-01";
    private const string ClientSigningKeyId = "cimd-client-signing-key-1";


    /// <summary>
    /// The public-client happy path (CIMD-003/012/018/029/032): an unregistered
    /// <c>https://…:{port}/…</c> Client Identifier URL (CIMD-003 — the port is not elided) resolves to
    /// a document served by a real TLS host; the AS fetches it (proving the wire was hit) and the
    /// materialized registration's <c>redirect_uri</c> comes ONLY from that document — a redirect_uri
    /// the document never declared is rejected BEFORE the one it did declare is accepted. PAR →
    /// authorize → callback → token completes over the real wire. A second, HAIP 1.0 client on the
    /// same document host proves RFC 9207 <c>iss</c> continuity survives the CIMD materialization
    /// overlay, byte-exact.
    /// </summary>
    [TestMethod]
    public async Task HappyPath_PublicClient_DocumentSuppliesRedirectUriAndDrivesFullFlow()
    {
        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(TestContext.CancellationToken)
            .ConfigureAwait(false);

        Uri redirectUri = new("https://client.example.com/callback");
        const string path = "/app";
        Uri documentUri = new(documentHost.BaseAddress, path);
        PublishCimdDocument(documentHost, path, documentUri, [redirectUri]);

        await using TestHostShell app = new(timeProvider);
        ClientRecord stub = app.RegisterCimdStubClient(
            documentUri,
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthPushedAuthorization),
            profile: PolicyProfile.Rfc6749WithPkce);

        app.WireCimdMaterialization("default", documentHost.Certificate);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> flowStore) =
            await app.CreateOAuthClientAndRegistrationAsync(
                stub, redirectUri.OriginalString, profile: PolicyProfile.Rfc6749WithPkce, TestContext.CancellationToken)
                .ConfigureAwait(false);

        HostedAuthorizationServer hosted = app.Host("default");
        string segment = stub.TenantId.Value;

        //CIMD-012/D6: a redirect_uri the document never declared is rejected — proving the accepted
        //redirect_uri below comes from the fetched document, not a blanket allow.
        AuthCodeFlowEndpointResult wrongRedirect = await client.AuthCode.StartParAsync(
            registration, new Uri("https://not-in-the-document.example/cb"), OAuthFormEncodedFields.Empty,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreNotEqual(AuthCodeFlowEndpointOutcome.Redirect, wrongRedirect.Outcome,
            "A redirect_uri the CIMD document never declared must not be accepted.");

        string flowId = await DriveParAuthorizeAndCallbackAsync(
            hosted, client, registration, flowStore, segment, redirectUri, SubjectId, app.ServerCertificate,
            TestContext.CancellationToken).ConfigureAwait(false);

        AuthCodeFlowEndpointResult tokenResult = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
            $"Token exchange must succeed over the real wire. ErrorCode={tokenResult.ErrorCode} ErrorDescription={tokenResult.ErrorDescription}");
        Assert.IsFalse(string.IsNullOrEmpty((string)tokenResult.Body![OAuthRequestParameterNames.AccessToken]));

        Assert.IsTrue(documentHost.WasRequested(path),
            "CIMD-029: the authorization server must have fetched the Client ID Metadata Document over the real wire.");

        //CIMD-041/CIMD-003 note: documentUri carries a port (StaticContentHost's ephemeral Kestrel
        //port), and the fetch above succeeded — the port is not a defect.

        //RFC 9207 continuity under HAIP 1.0 (FAPI 2.0 baseline): the redirect's iss must be byte-exact
        //even though the client identity AND redirect_uri came from a fetched CIMD document.
        const string haip10Path = "/app-haip10";
        Uri haip10Redirect = new("https://client.example.com/haip10-callback");
        Uri haip10DocumentUri = new(documentHost.BaseAddress, haip10Path);
        PublishCimdDocument(documentHost, haip10Path, haip10DocumentUri, [haip10Redirect]);

        ClientRecord haip10Stub = app.RegisterCimdStubClient(
            haip10DocumentUri,
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthPushedAuthorization),
            profile: PolicyProfile.Haip10);

        (OAuthClient haip10Client, ClientRegistration haip10Registration, Dictionary<string, FlowState> haip10FlowStore) =
            await app.CreateOAuthClientAndRegistrationAsync(
                haip10Stub, haip10Redirect.OriginalString, profile: PolicyProfile.Haip10, TestContext.CancellationToken)
                .ConfigureAwait(false);

        (_, string haip10Location) = await DriveParAndAuthorizeAsync(
            hosted, haip10Client, haip10Registration, haip10FlowStore, haip10Stub.TenantId.Value, haip10Redirect,
            new OAuthFormEncodedFields(new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
            }),
            SubjectId, app.ServerCertificate, TestContext.CancellationToken).ConfigureAwait(false);

        string? iss = TestBrowser.ExtractQueryParam(haip10Location, OAuthRequestParameterNames.Iss);
        Assert.IsNotNull(iss, "HAIP 1.0 (FAPI 2.0 baseline) must emit iss on the authorize redirect (RFC 9207).");
        Assert.AreEqual(haip10Registration.AuthorizationServerIssuer.OriginalString, iss,
            "RFC 9207 §2 continuity: iss must be byte-exact even though the client's identity and redirect_uri came from the fetched CIMD document.");
    }


    /// <summary>
    /// Confidential-client authentication (CIMD-047/048/049/050): the document declares
    /// <c>token_endpoint_auth_method: private_key_jwt</c> plus an inline <c>jwks</c> (CIMD-048). Token
    /// exchange with NO client authentication fails 401 (CIMD-049 "MUST include client authentication
    /// of the registered type"); a TAMPERED assertion signature fails 401 (RFC 7523 §2.2 verification,
    /// CIMD-050); a VALID <c>private_key_jwt</c> assertion authenticates and the exchange completes.
    /// Both failing attempts leave the authorization code unconsumed — client-authentication failure is
    /// checked before the code-redemption PDA transition — so all three attempts share one flow.
    /// </summary>
    [TestMethod]
    public async Task ConfidentialClient_TokenExchangeRequiresAndValidatesPrivateKeyJwtAssertion()
    {
        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(TestContext.CancellationToken)
            .ConfigureAwait(false);

        Uri redirectUri = new("https://client.example.com/callback");
        const string path = "/app-confidential";
        Uri documentUri = new(documentHost.BaseAddress, path);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> clientKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            string alg = CryptoFormatConversions.DefaultTagToJwaConverter(clientKeys.PublicKey.Tag);
            IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
                clientKeys.PublicKey, alg, TestHostShell.Base64UrlEncoder);
            string jwksJson = BuildJwksJson(jwk, ClientSigningKeyId);

            string documentJson = BuildCimdDocumentJson(
                documentUri.OriginalString,
                redirectUris: [redirectUri],
                tokenEndpointAuthMethod: WellKnownClientAuthenticationMethods.PrivateKeyJwt,
                jwksJson: jwksJson);
            documentHost.Publish(path, Encoding.UTF8.GetBytes(documentJson), "application/json");

            await using TestHostShell app = new(timeProvider);
            ClientRecord stub = app.RegisterCimdStubClient(
                documentUri,
                ImmutableHashSet.Create(
                    WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                    WellKnownCapabilityIdentifiers.OAuthPushedAuthorization),
                profile: PolicyProfile.Rfc6749WithPkce);

            app.WireCimdMaterialization("default", documentHost.Certificate);
            app.Server.OAuth().ValidateClientCredentialsAsync = PrivateKeyJwtClientAuthentication.BuildValidator();

            (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> flowStore) =
                await app.CreateOAuthClientAndRegistrationAsync(
                    stub, redirectUri.OriginalString, profile: PolicyProfile.Rfc6749WithPkce, TestContext.CancellationToken)
                    .ConfigureAwait(false);

            HostedAuthorizationServer hosted = app.Host("default");
            string segment = stub.TenantId.Value;

            string flowId = await DriveParAuthorizeAndCallbackAsync(
                hosted, client, registration, flowStore, segment, redirectUri, SubjectId, app.ServerCertificate,
                TestContext.CancellationToken).ConfigureAwait(false);

            AuthorizationCodeReceivedState codeState = (AuthorizationCodeReceivedState)flowStore[flowId];
            Uri tokenEndpoint = new(
                hosted.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, segment));

            Dictionary<string, string> baseFields = new(StringComparer.Ordinal)
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.AuthorizationCode,
                [OAuthRequestParameterNames.ClientId] = registration.ClientId.Value,
                [OAuthRequestParameterNames.Code] = codeState.Code,
                [OAuthRequestParameterNames.RedirectUri] = codeState.RedirectUri.ToString(),
                [OAuthRequestParameterNames.CodeVerifier] = codeState.Pkce.EncodedVerifier
            };

            //CIMD-049: no client authentication at all.
            using HttpResponseMessage noAssertion = await OAuthTestTransport.PostFormAsync(
                hosted.SharedHttpClient!, tokenEndpoint, baseFields, TestContext.CancellationToken).ConfigureAwait(false);
            string noAssertionBody = await noAssertion.Content.ReadAsStringAsync(TestContext.CancellationToken)
                .ConfigureAwait(false);
            Assert.AreEqual(401, (int)noAssertion.StatusCode, noAssertionBody);
            Assert.Contains(OAuthErrors.InvalidClient, noAssertionBody);

            string validAssertion = await ClientAssertionSigning.SignAsync(
                registration.ClientId.Value,
                registration.AuthorizationServerIssuer.OriginalString,
                Guid.NewGuid().ToString("N"),
                timeProvider.GetUtcNow(),
                timeProvider.GetUtcNow().AddMinutes(5),
                clientKeys.PrivateKey,
                ClientSigningKeyId,
                app.Server.OAuth().Codecs.JwtHeaderSerializer!,
                app.Server.OAuth().Codecs.JwtPayloadSerializer!,
                app.Server.OAuth().Codecs.Encoder!,
                TestHostShell.MemoryPool,
                TestContext.CancellationToken).ConfigureAwait(false);

            //CIMD-050: a tampered assertion signature fails RFC 7523 §2.2 verification.
            Dictionary<string, string> tamperedFields = new(baseFields, StringComparer.Ordinal)
            {
                [OAuthRequestParameterNames.ClientAssertionType] = WellKnownClientAssertionTypes.JwtBearer,
                [OAuthRequestParameterNames.ClientAssertion] = TamperSignature(validAssertion)
            };
            using HttpResponseMessage tampered = await OAuthTestTransport.PostFormAsync(
                hosted.SharedHttpClient!, tokenEndpoint, tamperedFields, TestContext.CancellationToken).ConfigureAwait(false);
            string tamperedBody = await tampered.Content.ReadAsStringAsync(TestContext.CancellationToken)
                .ConfigureAwait(false);
            Assert.AreEqual(401, (int)tampered.StatusCode, tamperedBody);

            //CIMD-047/048/050: a valid private_key_jwt assertion authenticates and the exchange completes.
            Dictionary<string, string> validFields = new(baseFields, StringComparer.Ordinal)
            {
                [OAuthRequestParameterNames.ClientAssertionType] = WellKnownClientAssertionTypes.JwtBearer,
                [OAuthRequestParameterNames.ClientAssertion] = validAssertion
            };
            using HttpResponseMessage ok = await OAuthTestTransport.PostFormAsync(
                hosted.SharedHttpClient!, tokenEndpoint, validFields, TestContext.CancellationToken).ConfigureAwait(false);
            string okBody = await ok.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(200, (int)ok.StatusCode, okBody);

            using JsonDocument tokenDoc = JsonDocument.Parse(okBody);
            Assert.IsFalse(string.IsNullOrEmpty(tokenDoc.RootElement.GetProperty(OAuthRequestParameterNames.AccessToken).GetString()));
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// The §8.2 canonical confidential-client shape (CIMD-048/050): the document declares
    /// <c>token_endpoint_auth_method: private_key_jwt</c> plus a <c>jwks_uri</c> — NOT an inline
    /// <c>jwks</c> — pointing at a SECOND loopback host distinct from the one serving the CIMD
    /// document itself, exactly the shape
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html#section-8.2">
    /// §8.2</see>'s own example advertises. The resolver's Step 9a
    /// (<see cref="ClientIdMetadataDocuments.BuildResolving"/>) fetches the key set through that
    /// second host over the real wire and folds it into the resolved document's <c>jwks</c>, so
    /// <see cref="PrivateKeyJwtClientAuthentication"/>'s validator resolves the client's key and a
    /// VALID <c>private_key_jwt</c> assertion completes the exchange.
    /// </summary>
    [TestMethod]
    public async Task ConfidentialClientWithJwksUriAuthenticatesOverTheRealWire()
    {
        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(TestContext.CancellationToken)
            .ConfigureAwait(false);
        await using StaticContentHost jwksHost = await StaticContentHost.StartAsync(TestContext.CancellationToken)
            .ConfigureAwait(false);

        Uri redirectUri = new("https://client.example.com/callback");
        const string documentPath = "/app-jwks-uri";
        const string jwksPath = "/jwks";
        Uri documentUri = new(documentHost.BaseAddress, documentPath);
        Uri jwksUri = new(jwksHost.BaseAddress, jwksPath);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> clientKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            string alg = CryptoFormatConversions.DefaultTagToJwaConverter(clientKeys.PublicKey.Tag);
            IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
                clientKeys.PublicKey, alg, TestHostShell.Base64UrlEncoder);
            string jwksJson = BuildJwksJson(jwk, ClientSigningKeyId);
            jwksHost.Publish(jwksPath, Encoding.UTF8.GetBytes(jwksJson), "application/json");

            string documentJson = BuildCimdDocumentJson(
                documentUri.OriginalString,
                redirectUris: [redirectUri],
                tokenEndpointAuthMethod: WellKnownClientAuthenticationMethods.PrivateKeyJwt,
                jwksJson: null,
                jwksUri: jwksUri.OriginalString);
            documentHost.Publish(documentPath, Encoding.UTF8.GetBytes(documentJson), "application/json");

            await using TestHostShell app = new(timeProvider);
            ClientRecord stub = app.RegisterCimdStubClient(
                documentUri,
                ImmutableHashSet.Create(
                    WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                    WellKnownCapabilityIdentifiers.OAuthPushedAuthorization),
                profile: PolicyProfile.Rfc6749WithPkce);

            //WireCimdMaterialization pins the resolver's transport to a SINGLE document host
            //certificate; here the resolver must reach both the CIMD document host and the separate
            //jwks_uri host, so the integration is wired directly, mirroring WireCimdMaterialization's
            //own body over a two-certificate pinned, single-hop client.
            using HttpClientHandler resolverHandler =
                LoopbackTls.CreatePinnedHandler([documentHost.Certificate, jwksHost.Certificate]);
            resolverHandler.AllowAutoRedirect = false;
            using HttpClient resolverHttpClient = new(resolverHandler);
            OutboundTransportDelegate resolverTransport =
                GuardedHttpClientTransport.BuildSingleHopTransport(resolverHttpClient);
            ResolveClientMetadataDelegate resolve = ClientIdMetadataDocuments.BuildResolving(
                resolverTransport, new ClientIdMetadataDocumentResolverOptions(), timeProvider);

            AuthorizationServerIntegration oauth = app.Server.OAuth();
            oauth.MaterializeRegistrationAsync = ClientIdMetadataMaterialization.Build();
            oauth.ResolveClientMetadataAsync = (clientMetadataUri, context, cancellationToken) =>
            {
                context.SetOutboundFetchPolicy(TestHostShell.LoopbackOutboundFetchPolicy);

                return resolve(clientMetadataUri, context, cancellationToken);
            };
            oauth.ValidateClientCredentialsAsync = PrivateKeyJwtClientAuthentication.BuildValidator();

            (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> flowStore) =
                await app.CreateOAuthClientAndRegistrationAsync(
                    stub, redirectUri.OriginalString, profile: PolicyProfile.Rfc6749WithPkce, TestContext.CancellationToken)
                    .ConfigureAwait(false);

            HostedAuthorizationServer hosted = app.Host("default");
            string segment = stub.TenantId.Value;

            string flowId = await DriveParAuthorizeAndCallbackAsync(
                hosted, client, registration, flowStore, segment, redirectUri, SubjectId, app.ServerCertificate,
                TestContext.CancellationToken).ConfigureAwait(false);

            AuthorizationCodeReceivedState codeState = (AuthorizationCodeReceivedState)flowStore[flowId];
            Uri tokenEndpoint = new(
                hosted.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, segment));

            string validAssertion = await ClientAssertionSigning.SignAsync(
                registration.ClientId.Value,
                registration.AuthorizationServerIssuer.OriginalString,
                Guid.NewGuid().ToString("N"),
                timeProvider.GetUtcNow(),
                timeProvider.GetUtcNow().AddMinutes(5),
                clientKeys.PrivateKey,
                ClientSigningKeyId,
                app.Server.OAuth().Codecs.JwtHeaderSerializer!,
                app.Server.OAuth().Codecs.JwtPayloadSerializer!,
                app.Server.OAuth().Codecs.Encoder!,
                TestHostShell.MemoryPool,
                TestContext.CancellationToken).ConfigureAwait(false);

            //CIMD-047/048/050: a valid private_key_jwt assertion, authenticated against the key set
            //discovered from the SEPARATE jwks_uri host, completes the exchange.
            Dictionary<string, string> tokenFields = new(StringComparer.Ordinal)
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.AuthorizationCode,
                [OAuthRequestParameterNames.ClientId] = registration.ClientId.Value,
                [OAuthRequestParameterNames.Code] = codeState.Code,
                [OAuthRequestParameterNames.RedirectUri] = codeState.RedirectUri.ToString(),
                [OAuthRequestParameterNames.CodeVerifier] = codeState.Pkce.EncodedVerifier,
                [OAuthRequestParameterNames.ClientAssertionType] = WellKnownClientAssertionTypes.JwtBearer,
                [OAuthRequestParameterNames.ClientAssertion] = validAssertion
            };
            using HttpResponseMessage ok = await OAuthTestTransport.PostFormAsync(
                hosted.SharedHttpClient!, tokenEndpoint, tokenFields, TestContext.CancellationToken).ConfigureAwait(false);
            string okBody = await ok.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(200, (int)ok.StatusCode, okBody);

            using JsonDocument tokenDoc = JsonDocument.Parse(okBody);
            Assert.IsFalse(string.IsNullOrEmpty(tokenDoc.RootElement.GetProperty(OAuthRequestParameterNames.AccessToken).GetString()));

            Assert.IsTrue(jwksHost.WasRequested(jwksPath),
                "CIMD-048/050, §8.2: the jwks_uri host must have been fetched over the real wire to discover the client's key set.");
            Assert.IsGreaterThanOrEqualTo(1, jwksHost.TotalRequests,
                "CIMD-048/050: the jwks_uri host must have served at least one request.");
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// The grant-type carve-out (CIMD-026/027): a redirect-less document (no <c>redirect_uris</c> at
    /// all) still identifies its client and still gets its metadata fetched for the
    /// <c>client_credentials</c> grant, which involves no redirect URL at all — the §4.2 redirect
    /// registration requirement simply does not apply to it. The SAME docless client's PAR fails the
    /// redirect check (D6, already shipped) because the fetched document supplied no registered
    /// redirect URIs whatsoever.
    /// </summary>
    [TestMethod]
    public async Task ClientCredentials_RedirectlessDocumentGrantsTokens_AuthorizeFlowFailsRedirectCheck()
    {
        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(TestContext.CancellationToken)
            .ConfigureAwait(false);

        const string path = "/app-machine";
        Uri documentUri = new(documentHost.BaseAddress, path);
        PublishCimdDocument(documentHost, path, documentUri, redirectUris: null);

        await using TestHostShell app = new(timeProvider);
        ClientRecord stub = app.RegisterCimdStubClient(
            documentUri,
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthPushedAuthorization,
                WellKnownCapabilityIdentifiers.OAuthClientCredentials),
            profile: PolicyProfile.Rfc6749WithPkce);

        app.WireCimdMaterialization("default", documentHost.Certificate);
        app.Server.OAuth().ValidateClientCredentialsAsync = static (_, _, _, _, _) => ValueTask.FromResult(true);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = app.Host("default");
        string segment = stub.TenantId.Value;

        Uri tokenEndpoint = new(
            hosted.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, segment));
        using HttpResponseMessage tokenResponse = await OAuthTestTransport.PostFormAsync(
            hosted.SharedHttpClient!, tokenEndpoint, new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
                [OAuthRequestParameterNames.ClientId] = documentUri.OriginalString
            }, TestContext.CancellationToken).ConfigureAwait(false);
        string tokenBody = await tokenResponse.Content.ReadAsStringAsync(TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(200, (int)tokenResponse.StatusCode, tokenBody);
        Assert.IsTrue(documentHost.WasRequested(path),
            "CIMD-027: client identification and metadata discovery apply regardless of grant type.");

        Uri parEndpoint = new(
            hosted.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodePar, segment));
        using HttpResponseMessage parResponse = await OAuthTestTransport.PostFormAsync(
            hosted.SharedHttpClient!, parEndpoint, new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.ResponseType] = "code",
                [OAuthRequestParameterNames.ClientId] = documentUri.OriginalString,
                [OAuthRequestParameterNames.RedirectUri] = "https://developer.example/callback",
                [OAuthRequestParameterNames.CodeChallenge] = "an-arbitrary-pkce-challenge-value-1234567890",
                [OAuthRequestParameterNames.CodeChallengeMethod] = "S256"
            }, TestContext.CancellationToken).ConfigureAwait(false);
        string parBody = await parResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)parResponse.StatusCode, parBody);
        Assert.Contains("redirect_uri", parBody);
    }


    /// <summary>
    /// Pre-registration (CIMD-031/045/046): the resolver runs ONCE, at the time the Client Identifier
    /// URL is pre-registered — not the request-time <see cref="ClientIdMetadataMaterialization"/> hook,
    /// which is never wired on this host at all. The flow still succeeds, and the document host sees
    /// EXACTLY the one pre-registration-time fetch — zero request-time fetches.
    /// </summary>
    [TestMethod]
    public async Task PreRegistration_ResolvedOnceAtRegistrationTime_FlowSucceedsWithZeroRequestTimeFetches()
    {
        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(TestContext.CancellationToken)
            .ConfigureAwait(false);

        Uri redirectUri = new("https://client.example.com/callback");
        const string path = "/app-prereg";
        Uri documentUri = new(documentHost.BaseAddress, path);
        PublishCimdDocument(documentHost, path, documentUri, [redirectUri]);

        using HttpClient pinnedHttpClient = LoopbackTls.CreatePinnedHttpClient(documentHost.Certificate);
        OutboundTransportDelegate transport = GuardedHttpClientTransport.BuildSingleHopTransport(pinnedHttpClient);
        ResolveClientMetadataDelegate resolve = ClientIdMetadataDocuments.BuildResolving(
            transport, new ClientIdMetadataDocumentResolverOptions(), timeProvider);

        ClientIdMetadataResolution resolution = await resolve(
            documentUri, NewLoopbackContext(), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(resolution.IsResolved,
            $"CIMD-046: the document must resolve at pre-registration time. Defect={resolution.Defect}");

        await using TestHostShell app = new(timeProvider);
        ClientRecord stub = app.RegisterCimdStubClient(
            documentUri,
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthPushedAuthorization),
            profile: PolicyProfile.Rfc6749WithPkce);

        //CIMD-031: the AS associates the Client Identifier URL with client metadata "through other
        //means" — the pre-registration overlay below, applied once — rather than automatically
        //fetching at request time. WireCimdMaterialization is deliberately never called on this host.
        ClientRecord preRegistered = stub with
        {
            AllowedRedirectUris = [.. resolution.Document!.RedirectUris]
        };
        HostedAuthorizationServer host = app.Host("default");
        host.Registrations[preRegistered.TenantId.Value] = preRegistered;
        host.Registrations[preRegistered.ClientId] = preRegistered;
        host.Server.UpdateClient(stub, preRegistered, new ExchangeContext());

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> flowStore) =
            await app.CreateOAuthClientAndRegistrationAsync(
                preRegistered, redirectUri.OriginalString, profile: PolicyProfile.Rfc6749WithPkce, TestContext.CancellationToken)
                .ConfigureAwait(false);

        HostedAuthorizationServer hosted = app.Host("default");
        string segment = preRegistered.TenantId.Value;

        string flowId = await DriveParAuthorizeAndCallbackAsync(
            hosted, client, registration, flowStore, segment, redirectUri, SubjectId, app.ServerCertificate,
            TestContext.CancellationToken).ConfigureAwait(false);

        AuthCodeFlowEndpointResult tokenResult = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
            $"The pre-registered flow must succeed without any request-time CIMD fetch. ErrorCode={tokenResult.ErrorCode}");

        Assert.AreEqual(1, documentHost.TotalRequests,
            "Exactly the pre-registration-time fetch must have crossed the wire — zero request-time fetches.");
    }


    /// <summary>
    /// AS metadata advertisement over the real wire (CIMD-041/042): the RFC 8414 default discovery
    /// location carries <c>client_id_metadata_document_supported: true</c> under the dual gate
    /// (capability allowed AND the resolver wired) — and discovery emission never itself triggers a
    /// document fetch (privacy §9.1).
    /// </summary>
    [TestMethod]
    public async Task Discovery_AdvertisesClientIdMetadataDocumentSupportedOverRealWire()
    {
        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        await using StaticContentHost documentHost = await StaticContentHost.StartAsync(TestContext.CancellationToken)
            .ConfigureAwait(false);

        const string path = "/app-discovery";
        Uri documentUri = new(documentHost.BaseAddress, path);
        PublishCimdDocument(documentHost, path, documentUri, redirectUris: null);

        await using TestHostShell app = new(timeProvider);
        ClientRecord stub = app.RegisterCimdStubClient(
            documentUri,
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint),
            profile: PolicyProfile.Rfc6749WithPkce);

        app.WireCimdMaterialization("default", documentHost.Certificate);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = app.Host("default");
        string segment = stub.TenantId.Value;

        Uri discoveryUrl = new(
            hosted.HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.MetadataOAuthAuthorizationServer, segment));
        using HttpResponseMessage discoveryResponse = await hosted.SharedHttpClient!
            .GetAsync(discoveryUrl, TestContext.CancellationToken).ConfigureAwait(false);
        string discoveryBody = await discoveryResponse.Content.ReadAsStringAsync(TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(200, (int)discoveryResponse.StatusCode, discoveryBody);

        using JsonDocument doc = JsonDocument.Parse(discoveryBody);
        Assert.IsTrue(
            doc.RootElement.TryGetProperty(
                AuthorizationServerMetadataParameterNames.ClientIdMetadataDocumentSupported, out JsonElement flag),
            $"client_id_metadata_document_supported must be present over the real wire. Body={discoveryBody}");
        Assert.IsTrue(flag.GetBoolean());

        Assert.AreEqual(0, documentHost.TotalRequests,
            "Discovery emission must never itself trigger a CIMD document fetch (privacy §9.1).");
    }


    /// <summary>
    /// Appendix A CIMD Service, positive half (CIMD-062/064/066/067): a client provisioned through a
    /// <see cref="CimdServiceHost"/> drives a full auth-code flow exactly like a self-hosted document
    /// would, developer-supplied information is recorded, and — negative half (CIMD-065/067/035
    /// interplay) — once the pinned clock advances past the provision's lifetime, the service answers
    /// 404 and a FRESH authorization request aborts rather than proceeding on stale data.
    /// </summary>
    [TestMethod]
    public async Task CimdService_ProvisionedClientDrivesFullFlow_DeveloperInfoRecorded_ExpiryAbortsFreshRequest()
    {
        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        await using CimdServiceHost cimdService = await CimdServiceHost.StartAsync(
            timeProvider, TestContext.CancellationToken).ConfigureAwait(false);

        Uri redirectUri = new("https://developer.example/cb");
        Uri clientIdentifierUrl = cimdService.ProvisionClient(
            redirectUris: [redirectUri],
            lifetime: TimeSpan.FromMinutes(10),
            developerInfo: "team-mobile");

        await using TestHostShell app = new(timeProvider);
        ClientRecord stub = app.RegisterCimdStubClient(
            clientIdentifierUrl,
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthPushedAuthorization),
            profile: PolicyProfile.Rfc6749WithPkce);

        app.WireCimdMaterialization("default", cimdService.Certificate);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> flowStore) =
            await app.CreateOAuthClientAndRegistrationAsync(
                stub, redirectUri.OriginalString, profile: PolicyProfile.Rfc6749WithPkce, TestContext.CancellationToken)
                .ConfigureAwait(false);

        HostedAuthorizationServer hosted = app.Host("default");
        string segment = stub.TenantId.Value;

        string flowId = await DriveParAuthorizeAndCallbackAsync(
            hosted, client, registration, flowStore, segment, redirectUri, SubjectId, app.ServerCertificate,
            TestContext.CancellationToken).ConfigureAwait(false);

        AuthCodeFlowEndpointResult tokenResult = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
            $"A CIMD Service-provisioned client must drive a full auth-code flow. ErrorCode={tokenResult.ErrorCode}");

        Assert.IsTrue(cimdService.WasRequested(clientIdentifierUrl),
            "The CIMD Service document must have been fetched over the real wire.");
        Assert.AreEqual("team-mobile", cimdService.DeveloperInfo(clientIdentifierUrl),
            "CIMD-066: developer-supplied information about the client under development must be recorded.");

        //CIMD-065: the service expires the provision, measured against the injected TimeProvider.
        timeProvider.Advance(TimeSpan.FromMinutes(11));

        //CIMD-035/067 interplay: a fresh authorization request against an expired provision aborts —
        //the document now 404s, so materialization's resolver call fails and the request never redirects.
        AuthCodeFlowEndpointResult secondPar = await client.AuthCode.StartParAsync(
            registration, redirectUri, OAuthFormEncodedFields.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, secondPar.Outcome,
            "A fresh authorization request against an expired CIMD Service provision must abort, not redirect.");
        Assert.AreEqual(OAuthErrors.InvalidRequest, secondPar.ErrorCode);
    }


    /// <summary>
    /// Appendix A CIMD Service, the redirect-restriction exemption (CIMD-063): an AS that layers an
    /// additional same-origin-with-<c>client_id</c> restriction on <c>redirect_uris</c> (via the §4
    /// <see cref="ClientIdMetadataDocumentResolverOptions.AdditionalDocumentValidation"/> extension
    /// point, CIMD-020) exempts documents served from a CIMD Service's own origin — proven by
    /// contrasting the SAME cross-origin redirect_uri accepted from the service origin and rejected
    /// from an ordinary (non-service) document host under the identical policy.
    /// </summary>
    [TestMethod]
    public async Task CimdService_AdditionalDocumentValidationExemptsServiceOriginFromRedirectOriginRestriction()
    {
        FakeTimeProvider timeProvider = new(TestClock.CanonicalEpoch);
        await using CimdServiceHost cimdService = await CimdServiceHost.StartAsync(
            timeProvider, TestContext.CancellationToken).ConfigureAwait(false);
        await using StaticContentHost foreignHost = await StaticContentHost.StartAsync(TestContext.CancellationToken)
            .ConfigureAwait(false);

        //Neither host's own origin — a hypothetical AS policy requiring redirect_uris to share the
        //client_id's origin (§8.1) would reject this for an ordinary document.
        Uri crossOriginRedirect = new("https://developer.example/cb");

        Uri serviceClientIdentifierUrl = cimdService.ProvisionClient(redirectUris: [crossOriginRedirect]);

        const string foreignPath = "/app-foreign";
        Uri foreignClientIdentifierUrl = new(foreignHost.BaseAddress, foreignPath);
        PublishCimdDocument(foreignHost, foreignPath, foreignClientIdentifierUrl, [crossOriginRedirect]);

        Uri serviceOrigin = cimdService.BaseAddress;
        AdditionalClientIdMetadataDocumentValidationDelegate sameOriginUnlessServiceOrigin =
            (document, clientMetadataUri, context, cancellationToken) =>
            {
                bool isServiceOrigin = string.Equals(
                    clientMetadataUri.Authority, serviceOrigin.Authority, StringComparison.OrdinalIgnoreCase);
                if(isServiceOrigin)
                {
                    //CIMD-063: at least one CIMD Service is exempt from the AS's redirect_uri origin
                    //restriction, so developers are not blocked by it.
                    return ValueTask.FromResult(true);
                }

                bool allSameOrigin = document.RedirectUris.All(uri =>
                    string.Equals(uri.Authority, clientMetadataUri.Authority, StringComparison.OrdinalIgnoreCase));

                return ValueTask.FromResult(allSameOrigin);
            };

        using HttpClient pinnedHttpClient =
            LoopbackTls.CreatePinnedHttpClient([cimdService.Certificate, foreignHost.Certificate]);
        OutboundTransportDelegate transport = GuardedHttpClientTransport.BuildSingleHopTransport(pinnedHttpClient);
        ClientIdMetadataDocumentResolverOptions options = new()
        {
            AdditionalDocumentValidation = sameOriginUnlessServiceOrigin
        };
        ResolveClientMetadataDelegate resolve = ClientIdMetadataDocuments.BuildResolving(transport, options, timeProvider);

        ClientIdMetadataResolution serviceResolution = await resolve(
            serviceClientIdentifierUrl, NewLoopbackContext(), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(serviceResolution.IsResolved,
            $"CIMD-063: the CIMD Service origin must be exempt from the redirect_uri origin restriction. Defect={serviceResolution.Defect}");

        ClientIdMetadataResolution foreignResolution = await resolve(
            foreignClientIdentifierUrl, NewLoopbackContext(), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(ClientIdMetadataResolutionOutcome.InvalidDocument, foreignResolution.Outcome,
            "A non-service document with the SAME cross-origin redirect_uri must still be rejected by the " +
            "restriction — proving the CIMD-063 exemption is doing real work, not a no-op policy.");
    }


    /// <summary>
    /// Drives PAR (a real wire POST) and the browser's authorize GET (a real wire GET with
    /// auto-redirect disabled and the test subject header standing in for an authenticated session),
    /// returning the flow identifier and the raw redirect <c>Location</c> for the caller to inspect.
    /// </summary>
    private static async Task<(string FlowId, string Location)> DriveParAndAuthorizeAsync(
        HostedAuthorizationServer hosted,
        OAuthClient client,
        ClientRegistration registration,
        Dictionary<string, FlowState> clientFlowStore,
        string segment,
        Uri redirectUri,
        OAuthFormEncodedFields additionalParFields,
        string subjectId,
        X509Certificate2 pinnedCertificate,
        CancellationToken cancellationToken)
    {
        AuthCodeFlowEndpointResult parResult = await client.AuthCode.StartParAsync(
            registration, redirectUri, additionalParFields, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, parResult.Outcome,
            $"PAR must redirect over the real wire. ErrorCode={parResult.ErrorCode} ErrorDescription={parResult.ErrorDescription}");

        string flowId = clientFlowStore.Keys.Single();
        ParCompletedState parState = (ParCompletedState)clientFlowStore[flowId];

        Uri authorizeUrl = new(
            hosted.HttpBaseAddress!,
            $"{TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, segment)}" +
            $"?{OAuthRequestParameterNames.ClientId}={Uri.EscapeDataString(registration.ClientId.Value)}" +
            $"&{OAuthRequestParameterNames.RequestUri}={Uri.EscapeDataString(parState.Par.RequestUri.ToString())}");

        using HttpClientHandler noRedirectHandler = LoopbackTls.CreatePinnedHandler(pinnedCertificate);
        noRedirectHandler.AllowAutoRedirect = false;
        using HttpClient browserClient = new(noRedirectHandler) { BaseAddress = hosted.HttpBaseAddress };
        using HttpRequestMessage authorizeRequest = new(HttpMethod.Get, authorizeUrl);
        authorizeRequest.Headers.Add(AuthorizationServerHttpApplication.TestSubjectHeaderName, subjectId);

        using HttpResponseMessage authorizeResponse = await browserClient
            .SendAsync(authorizeRequest, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, (int)authorizeResponse.StatusCode,
            "The authorize endpoint must redirect with the authorization code.");

        return (flowId, authorizeResponse.Headers.Location!.ToString());
    }


    /// <summary>
    /// <see cref="DriveParAndAuthorizeAsync"/> plus the client-local callback state transition,
    /// returning the flow identifier ready for token exchange.
    /// </summary>
    private static async Task<string> DriveParAuthorizeAndCallbackAsync(
        HostedAuthorizationServer hosted,
        OAuthClient client,
        ClientRegistration registration,
        Dictionary<string, FlowState> clientFlowStore,
        string segment,
        Uri redirectUri,
        string subjectId,
        X509Certificate2 pinnedCertificate,
        CancellationToken cancellationToken)
    {
        (string flowId, string location) = await DriveParAndAuthorizeAsync(
            hosted, client, registration, clientFlowStore, segment, redirectUri, OAuthFormEncodedFields.Empty,
            subjectId, pinnedCertificate, cancellationToken).ConfigureAwait(false);

        string code = TestBrowser.ExtractQueryParam(location, OAuthRequestParameterNames.Code)
            ?? throw new InvalidOperationException("Authorize redirect Location missing code.");
        string? iss = TestBrowser.ExtractQueryParam(location, OAuthRequestParameterNames.Iss);

        Dictionary<string, string> callbackFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.Code] = code,
            [OAuthRequestParameterNames.State] = flowId
        };
        if(iss is not null)
        {
            callbackFields[OAuthRequestParameterNames.Iss] = iss;
        }

        AuthCodeFlowEndpointResult callbackResult = await client.AuthCode.HandleCallbackAsync(
            registration, new OAuthFormEncodedFields(callbackFields), cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, callbackResult.Outcome,
            $"Callback must succeed. ErrorCode={callbackResult.ErrorCode} ErrorDescription={callbackResult.ErrorDescription}");

        return flowId;
    }


    /// <summary>
    /// Publishes a Client ID Metadata Document at <paramref name="host"/>'s <paramref name="path"/>
    /// whose <c>client_id</c> is <paramref name="documentUri"/>'s own <see cref="Uri.OriginalString"/>.
    /// </summary>
    private static void PublishCimdDocument(
        StaticContentHost host, string path, Uri documentUri, IReadOnlyList<Uri>? redirectUris)
    {
        string json = BuildCimdDocumentJson(
            documentUri.OriginalString, redirectUris, tokenEndpointAuthMethod: null, jwksJson: null);
        host.Publish(path, Encoding.UTF8.GetBytes(json), "application/json");
    }


    //Builds a conformant Client ID Metadata Document (§4): client_id is REQUIRED (CIMD-013) and
    //always present; every other member is included only when supplied, so an omitted property stays
    //genuinely absent from the wire JSON. jwksJson is embedded UNQUOTED — it is already a JSON
    //object's text, mirroring PrivateKeyJwtClientAuthenticationTests' BuildJwksJson convention.
    //jwksUri is the §8.2 alternative to jwksJson — a confidential client publishes ONE of the two,
    //never both, so callers pass at most one non-null.
    private static string BuildCimdDocumentJson(
        string clientId,
        IReadOnlyList<Uri>? redirectUris,
        string? tokenEndpointAuthMethod,
        string? jwksJson,
        string? jwksUri = null)
    {
        List<string> members = [$"\"client_id\":\"{clientId}\""];

        if(redirectUris is { Count: > 0 })
        {
            string uris = string.Join(',', redirectUris.Select(static uri => $"\"{uri.OriginalString}\""));
            members.Add($"\"redirect_uris\":[{uris}]");
        }

        if(tokenEndpointAuthMethod is not null)
        {
            members.Add($"\"token_endpoint_auth_method\":\"{tokenEndpointAuthMethod}\"");
        }

        if(jwksJson is not null)
        {
            members.Add($"\"jwks\":{jwksJson}");
        }

        if(jwksUri is not null)
        {
            members.Add($"\"jwks_uri\":\"{jwksUri}\"");
        }

        return "{" + string.Join(',', members) + "}";
    }


    //Hand-built JWKS document text from a DpopJwkUtilities.ToJwk dictionary, mirroring
    //PrivateKeyJwtClientAuthenticationTests.BuildJwksJson.
    private static string BuildJwksJson(IReadOnlyDictionary<string, string> jwk, string kid)
    {
        StringBuilder sb = new();
        sb.Append('{').Append('"').Append(WellKnownJwkMemberNames.Keys).Append("\":[{");
        foreach(KeyValuePair<string, string> member in jwk)
        {
            sb.Append('"').Append(member.Key).Append("\":\"").Append(member.Value).Append("\",");
        }

        sb.Append('"').Append(WellKnownJwkMemberNames.Kid).Append("\":\"").Append(kid).Append("\"}]}");

        return sb.ToString();
    }


    //Flips the FIRST character of the compact JWS's signature segment (the part after the final '.').
    //The first base64url character of the signature contributes six full bits to the decoded bytes, so
    //the mutated signature always decodes to a different byte array — unlike flipping the final
    //character, whose two significant bits a lenient base64url decoder can discard, yielding a no-op
    //"tamper" that still verifies. The assertion keeps its header.payload.signature shape but no longer
    //verifies against the client's key.
    private static string TamperSignature(string compactJws)
    {
        int signatureStart = compactJws.LastIndexOf('.') + 1;
        char first = compactJws[signatureStart];
        char replacement = first == 'A' ? 'B' : 'A';

        return string.Concat(compactJws.AsSpan(0, signatureStart), replacement.ToString(), compactJws.AsSpan(signatureStart + 1));
    }


    /// <summary>
    /// A fresh <see cref="ExchangeContext"/> under <see cref="TestHostShell.LoopbackOutboundFetchPolicy"/>
    /// — mirrors <c>WebFingerCrossWireFlowTests.NewLoopbackContext</c> — for standalone resolver calls
    /// this suite drives outside a full AS dispatch (pre-registration, the CIMD-063 demonstration).
    /// </summary>
    private static ExchangeContext NewLoopbackContext()
    {
        ExchangeContext context = new();
        context.SetOutboundFetchPolicy(TestHostShell.LoopbackOutboundFetchPolicy);

        return context;
    }
}
