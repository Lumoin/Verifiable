using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Mirrors <see cref="AuthCodeClientAuthenticationTests"/> for the REFRESH leg: the real
/// <see cref="AuthCodeClient.RefreshAsync(ClientRegistration, RefreshTokenRequest, ExchangeContext, ClientAssertionOptions?, System.Threading.CancellationToken)"/>
/// attaches confidential-client authentication automatically per
/// <see cref="ClientRegistration.AuthenticationMethod"/>, over the real wire, for every declared
/// method — <c>client_secret_post</c>, <c>client_secret_basic</c>, and <c>private_key_jwt</c> — as
/// well as leaving a <see cref="ClientAuthenticationMethod.None"/> public client's refresh untouched.
/// Before this fix the refresh leg posted <see cref="Verifiable.OAuth.Client.OutgoingHeaders.Empty"/>
/// regardless of the declared method, so a confidential client's refresh always 401'd
/// <c>invalid_client</c>; <see cref="ClientRecord.TokenEndpointAuthMethod"/> is set server-side so
/// the refresh fails closed (draft-ietf-oauth-client-id-metadata-document-02 §8.2, CIMD-049/050)
/// without the attached credential — a passing refresh therefore proves the client attached it, not
/// that the server never asked.
/// </summary>
[TestClass]
internal sealed class RefreshConfidentialClientAuthenticationTests
{
    /// <summary>MSTest's per-test context, supplying the cancellation token every wire call runs under.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The clock the host and the client share.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    private const string ClientId = "https://confidential-refresh.client.test";

    private const string SubjectId = "subject-confidential-refresh-01";

    private const string ClientSecret = "s3cret-of-the-confidential-refreshing-client";

    private const string WrongClientSecret = "wrong-secret-not-matching-the-refresh-validator";

    private static Uri ClientBaseUri { get; } = new(ClientId);

    private static Uri RedirectUri { get; } = new("https://client.example.com/callback");

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;


    /// <summary>
    /// <c>client_secret_post</c> (RFC 6749 §2.3.1): the real client attaches <c>client_id</c> +
    /// <c>client_secret</c> to the REFRESH request body — no explicit <see cref="ClientAssertionOptions"/>
    /// needed, driven through the plain <see cref="AuthCodeClient.RefreshAsync(ClientRegistration, RefreshTokenRequest, System.Threading.CancellationToken)"/>
    /// path — and the server-side declared-method invariant requires it on the refresh leg too.
    /// </summary>
    [TestMethod]
    public async Task ClientSecretPostRefreshesOverRealWire()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> secretMaterial = BuildSecretKeyMaterial(ClientSecret);
        try
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
                ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);


            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
                    ValueTask.FromResult(
                        fields.TryGetValue(OAuthRequestParameterNames.ClientSecret, out string? secret)
                        && string.Equals(secret, ClientSecret, StringComparison.Ordinal));
            }).ConfigureAwait(false);

            await DeclareServerSideAuthMethodAsync(host, material, ClientAuthenticationMethod.ClientSecretPost).ConfigureAwait(false);

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

            await DriveInitialIssuanceAndAssertRefreshSucceedsAsync(
                host, client, registration, clientFlowStore, material.Registration.TenantId.Value).ConfigureAwait(false);
        }
        finally
        {
            secretMaterial.PublicKey.Dispose();
            secretMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <c>client_secret_basic</c> (RFC 6749 §2.3.1): the real client attaches an HTTP Basic
    /// <c>Authorization</c> header to the refresh POST — again through the plain <c>RefreshAsync</c>
    /// path, since this method needs no per-call <see cref="ClientAssertionOptions"/> either.
    /// </summary>
    [TestMethod]
    public async Task ClientSecretBasicRefreshesOverRealWire()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> secretMaterial = BuildSecretKeyMaterial(ClientSecret);
        try
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
                ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);


            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
                    ValueTask.FromResult(AuthCodeFlowDriver.DecodeAndMatchBasicHeader(request, registration.ClientId, ClientSecret));
            }).ConfigureAwait(false);

            await DeclareServerSideAuthMethodAsync(host, material, ClientAuthenticationMethod.ClientSecretBasic).ConfigureAwait(false);

            (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
                await host.CreateOAuthClientAndRegistrationAsync(
                    material.Registration,
                    RedirectUri.OriginalString,
                    profile: PolicyProfile.Rfc6749WithPkce,
                    TestContext.CancellationToken).ConfigureAwait(false);
            registration = registration with
            {
                AuthenticationMethod = ClientAuthenticationMethod.ClientSecretBasic,
                AuthenticationKeyMaterial = secretMaterial
            };

            await DriveInitialIssuanceAndAssertRefreshSucceedsAsync(
                host, client, registration, clientFlowStore, material.Registration.TenantId.Value).ConfigureAwait(false);
        }
        finally
        {
            secretMaterial.PublicKey.Dispose();
            secretMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <c>private_key_jwt</c> (RFC 7523 §2.2): the real client signs and attaches a fresh
    /// <c>client_assertion</c> to the refresh POST from <see cref="TestKeyMaterialProvider"/>-generated
    /// P-256 key material, driven through <see cref="AuthCodeFlowDriver.DriveRefreshAsync"/>'s
    /// <see cref="ClientAssertionOptions"/> overload, verified server-side by the real
    /// <see cref="PrivateKeyJwtClientAuthentication.BuildValidator(System.Collections.Generic.IReadOnlyCollection{string}?,CheckClientAssertionJtiReplayDelegate?,Verifiable.OAuth.Server.Pipeline.ResolveJwksUriDelegate?)"/>
    /// pipeline over a published <c>ClientJwks</c> — the same production shape
    /// <see cref="PrivateKeyJwtClientAuthenticationTests"/> exercises directly.
    /// </summary>
    [TestMethod]
    public async Task PrivateKeyJwtRefreshesOverRealWire()
    {
        var clientKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
                ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

            //Start the listener before wiring the validator so the resolved token endpoint URL
            //(the client-signed aud, per RFC 7523 §3 item 3) is known.
            await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
            HostedAuthorizationServer hosted = host.Host("default");
            string segment = material.Registration.TenantId.Value;
            Uri tokenEndpoint = new(
                hosted.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, segment));

            string alg = CryptoFormatConversions.DefaultTagToJwaConverter(clientKeys.PublicKey.Tag);
            const string SigningKeyId = "confidential-refresh-client-key-1";
            IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
                clientKeys.PublicKey, alg, TestSetup.Base64UrlEncoder);
            string jwksJson = BuildJwksJson(jwk, SigningKeyId);


            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.ValidateClientCredentialsAsync =
                    PrivateKeyJwtClientAuthentication.BuildValidator(
                        additionalAcceptedAudiences: [tokenEndpoint.OriginalString]);
            }).ConfigureAwait(false);

            await DeclareServerSideAuthMethodAsync(
                host, material, ClientAuthenticationMethod.PrivateKeyJwt,
                clientJwks: jwksJson, assertionSigningAlgorithm: alg).ConfigureAwait(false);

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

            ClientAssertionOptions assertionOptions = new()
            {
                SigningKeyId = SigningKeyId,
                HeaderSerializer = host.Server.OAuth().Codecs.JwtHeaderSerializer!,
                PayloadSerializer = host.Server.OAuth().Codecs.JwtPayloadSerializer!
            };

            await DriveInitialIssuanceAndAssertRefreshSucceedsAsync(
                host, client, registration, clientFlowStore, segment,
                clientAssertionOptions: assertionOptions).ConfigureAwait(false);
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// A public client (<see cref="ClientAuthenticationMethod.None"/>, the default) attaches no
    /// credential at either leg and relies on PKCE alone (RFC 6749 §6, §3.2.1) — the refresh leg's
    /// new authentication attachment must not regress this baseline, unauthenticated case.
    /// </summary>
    [TestMethod]
    public async Task NoneAuthPublicClientStillRefreshesOverRealWire()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        //TokenEndpointAuthMethod deliberately left unset (null) — a public client presents no
        //credential and the server does not require one.

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                RedirectUri.OriginalString,
                profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);
        //AuthenticationMethod deliberately left at its None default.

        await DriveInitialIssuanceAndAssertRefreshSucceedsAsync(
            host, client, registration, clientFlowStore, material.Registration.TenantId.Value).ConfigureAwait(false);
    }


    /// <summary>
    /// Pins that the positive tests above prove genuine authentication rather than a server that
    /// never checks: a declared confidential client whose refresh request carries no credential at
    /// all (the registration's <see cref="ClientRegistration.AuthenticationMethod"/> stays
    /// <see cref="ClientAuthenticationMethod.None"/> even though the server declared
    /// <c>client_secret_post</c>) still gets refused — the exact 401 <c>invalid_client</c> behavior
    /// this fix corrects FOR an attached credential, preserved for a MISSING one.
    /// </summary>
    [TestMethod]
    public async Task DeclaredConfidentialClientRefreshWithoutAttachedCredentialFailsClosed()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> secretMaterial = BuildSecretKeyMaterial(ClientSecret);
        try
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
                ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);


            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
                    ValueTask.FromResult(
                        fields.TryGetValue(OAuthRequestParameterNames.ClientSecret, out string? secret)
                        && string.Equals(secret, ClientSecret, StringComparison.Ordinal));
            }).ConfigureAwait(false);

            await DeclareServerSideAuthMethodAsync(host, material, ClientAuthenticationMethod.ClientSecretPost).ConfigureAwait(false);

            (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
                await host.CreateOAuthClientAndRegistrationAsync(
                    material.Registration,
                    RedirectUri.OriginalString,
                    profile: PolicyProfile.Rfc6749WithPkce,
                    TestContext.CancellationToken).ConfigureAwait(false);

            //The AUTHENTICATED registration mints the initial tokens (the code-exchange leg is not
            //under test here and must succeed to obtain a refresh token to attempt refreshing with).
            ClientRegistration authenticated = registration with
            {
                AuthenticationMethod = ClientAuthenticationMethod.ClientSecretPost,
                AuthenticationKeyMaterial = secretMaterial
            };

            using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
            HostedAuthorizationServer hosted = host.Host("default");
            string segment = material.Registration.TenantId.Value;

            AuthCodeFlowDriveResult drive = await AuthCodeFlowDriver.DriveParAuthorizeCallbackAndTokenAsync(
                hosted, client, authenticated, clientFlowStore, segment, RedirectUri, SubjectId, browserClient,
                scope: WellKnownScopes.OpenId, cancellationToken: TestContext.CancellationToken)
                .ConfigureAwait(false);
            string originalRefreshToken = (string)drive.TokenResult.Body![OAuthRequestParameterNames.RefreshToken];

            //The refresh attempt itself uses the UNAUTHENTICATED registration — None stays the
            //client's declared method even though the server requires client_secret_post.
            RefreshTokenRequest refreshRequest = new()
            {
                ClientId = registration.ClientId.Value,
                RefreshToken = originalRefreshToken
            };
            AuthCodeFlowEndpointResult refreshResult = await client.AuthCode.RefreshAsync(
                registration, refreshRequest, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreNotEqual(AuthCodeFlowEndpointOutcome.Ok, refreshResult.Outcome,
                "A declared confidential client refreshing without an attached credential must not be issued new tokens.");
            Assert.AreEqual(OAuthErrors.InvalidClient, refreshResult.ErrorCode);
        }
        finally
        {
            secretMaterial.PublicKey.Dispose();
            secretMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// RFC 7523 §3.1: "if client credentials are present in the request, the authorization server
    /// MUST validate them." <see cref="ClientRecord.TokenEndpointAuthMethod"/> is deliberately left
    /// UNDECLARED — before this fix, <c>RequireClientAuthenticationIfDeclaredAsync</c>'s null/None
    /// branch returned success immediately without consulting whether a credential was attached, so a
    /// WRONG <c>client_secret</c> on an undeclared-method refresh was silently ignored and new tokens
    /// were minted anyway. The initial issuance leg is not under test — it uses the no-credential
    /// public path (the registration stays at its <see cref="ClientAuthenticationMethod.None"/>
    /// default) and must succeed to obtain a refresh token; only the refresh leg attaches a
    /// <c>client_secret_post</c> credential that does NOT match what the validator seam accepts.
    /// </summary>
    [TestMethod]
    public async Task PresentedWrongSecretOnUndeclaredMethodRefreshFailsClosed()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> wrongSecretMaterial = BuildSecretKeyMaterial(WrongClientSecret);
        try
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
                ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
            //TokenEndpointAuthMethod deliberately left unset (null) — DeclareServerSideAuthMethod is
            //never called, so the registration never declares a confidential method.

            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
                    ValueTask.FromResult(
                        fields.TryGetValue(OAuthRequestParameterNames.ClientSecret, out string? secret)
                        && string.Equals(secret, ClientSecret, StringComparison.Ordinal));
            }).ConfigureAwait(false);

            (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
                await host.CreateOAuthClientAndRegistrationAsync(
                    material.Registration,
                    RedirectUri.OriginalString,
                    profile: PolicyProfile.Rfc6749WithPkce,
                    TestContext.CancellationToken).ConfigureAwait(false);

            //The initial issuance leg uses the UNAUTHENTICATED (None-default) registration and must
            //succeed to obtain a refresh token to attempt refreshing with.
            using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
            HostedAuthorizationServer hosted = host.Host("default");
            string segment = material.Registration.TenantId.Value;

            AuthCodeFlowDriveResult drive = await AuthCodeFlowDriver.DriveParAuthorizeCallbackAndTokenAsync(
                hosted, client, registration, clientFlowStore, segment, RedirectUri, SubjectId, browserClient,
                scope: WellKnownScopes.OpenId, cancellationToken: TestContext.CancellationToken)
                .ConfigureAwait(false);
            string originalRefreshToken = (string)drive.TokenResult.Body![OAuthRequestParameterNames.RefreshToken];

            //The refresh attempt attaches a WRONG client_secret via client_secret_post — the
            //registration still declares no server-side method, so this exercises the closed
            //fail-open on the undeclared-method branch specifically.
            ClientRegistration wrongCredentialRegistration = registration with
            {
                AuthenticationMethod = ClientAuthenticationMethod.ClientSecretPost,
                AuthenticationKeyMaterial = wrongSecretMaterial
            };
            RefreshTokenRequest refreshRequest = new()
            {
                ClientId = registration.ClientId.Value,
                RefreshToken = originalRefreshToken
            };
            AuthCodeFlowEndpointResult refreshResult = await client.AuthCode.RefreshAsync(
                wrongCredentialRegistration, refreshRequest, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreNotEqual(AuthCodeFlowEndpointOutcome.Ok, refreshResult.Outcome,
                "A wrong client_secret presented on an undeclared token_endpoint_auth_method refresh must not be issued new tokens.");
            Assert.AreEqual(OAuthErrors.InvalidClient, refreshResult.ErrorCode);
        }
        finally
        {
            wrongSecretMaterial.PublicKey.Dispose();
            wrongSecretMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §4.3.1</see>'s reuse-detection revocation is gated on the SAME client
    /// authentication bar a live rotation clears
    /// (<see cref="AuthCodeClient.RefreshAsync(ClientRegistration, RefreshTokenRequest, System.Threading.CancellationToken)"/>'s
    /// declared-method requirement): a party holding only a rotated-out refresh token, without the
    /// declared <c>client_secret_post</c> credential, cannot trigger the family revocation this
    /// method's own denial-of-service reasoning exists to prevent. The refresh endpoint's own
    /// pre-correlation step authenticates the declared method BEFORE any presentation is even
    /// known to be live, retired, or unknown, so this reuse presentation — the correct
    /// <c>client_id</c> but NO <c>client_secret</c>, a raw wire push, since the real client would
    /// never omit a credential it has been configured to attach — is refused
    /// <c>401 invalid_client</c> there, before reuse detection ever runs, without revoking the
    /// successor, which a subsequent authenticated refresh proves still usable.
    /// </summary>
    [TestMethod]
    public async Task ReuseOfRotatedOutRefreshTokenWithoutClientCredentialsLeavesSuccessorUsable()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> secretMaterial = BuildSecretKeyMaterial(ClientSecret);
        try
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
                ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);


            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
                    ValueTask.FromResult(
                        fields.TryGetValue(OAuthRequestParameterNames.ClientSecret, out string? secret)
                        && string.Equals(secret, ClientSecret, StringComparison.Ordinal));
            }).ConfigureAwait(false);

            await DeclareServerSideAuthMethodAsync(host, material, ClientAuthenticationMethod.ClientSecretPost).ConfigureAwait(false);

            (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
                await host.CreateOAuthClientAndRegistrationAsync(
                    material.Registration,
                    RedirectUri.OriginalString,
                    profile: PolicyProfile.Rfc6749WithPkce,
                    TestContext.CancellationToken).ConfigureAwait(false);
            ClientRegistration authenticated = registration with
            {
                AuthenticationMethod = ClientAuthenticationMethod.ClientSecretPost,
                AuthenticationKeyMaterial = secretMaterial
            };

            using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
            HostedAuthorizationServer hosted = host.Host("default");
            string segment = material.Registration.TenantId.Value;

            AuthCodeFlowDriveResult drive = await AuthCodeFlowDriver.DriveParAuthorizeCallbackAndTokenAsync(
                hosted, client, authenticated, clientFlowStore, segment, RedirectUri, SubjectId, browserClient,
                scope: WellKnownScopes.OpenId, cancellationToken: TestContext.CancellationToken)
                .ConfigureAwait(false);
            string originalRefreshToken = (string)drive.TokenResult.Body![OAuthRequestParameterNames.RefreshToken];

            //A single legitimate, AUTHENTICATED rotation.
            RefreshTokenRequest rotateRequest = new()
            {
                ClientId = registration.ClientId.Value,
                RefreshToken = originalRefreshToken
            };
            AuthCodeFlowEndpointResult rotation = await client.AuthCode.RefreshAsync(
                authenticated, rotateRequest, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, rotation.Outcome,
                $"The authenticated rotation must succeed. ErrorCode={rotation.ErrorCode}");
            string successorRefreshToken = (string)rotation.Body![OAuthRequestParameterNames.RefreshToken];

            //The reuse presentation: correct client_id, NO client_secret — a raw wire push, since
            //an attacker holding only the stolen refresh token has no reason to also hold the
            //client's secret.
            (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, originalRefreshToken),
                TestContext.CancellationToken).ConfigureAwait(false);

            //The pre-correlation step authenticates the declared method before this presentation
            //is ever known to be retired — so a credential-less presentation of an UNKNOWN handle
            //answers byte-identically to this retired one.
            (int UnknownStatusCode, string UnknownBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, "unknown-refresh-token-value"),
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(401, StatusCode, Body);
            Assert.Contains(OAuthErrors.InvalidClient, Body, StringComparison.Ordinal);
            Assert.AreEqual(UnknownStatusCode, StatusCode,
                "An unknown handle and a retired one must answer byte-identically once client authentication runs first.");
            Assert.AreEqual(UnknownBody, Body,
                "An unknown handle and a retired one must answer byte-identically once client authentication runs first.");

            //The successor must remain usable — an authenticated refresh of it still succeeds.
            RefreshTokenRequest successorRefreshRequest = new()
            {
                ClientId = registration.ClientId.Value,
                RefreshToken = successorRefreshToken
            };
            AuthCodeFlowEndpointResult successorRefresh = await client.AuthCode.RefreshAsync(
                authenticated, successorRefreshRequest, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, successorRefresh.Outcome,
                $"An unauthenticated reuse presentation must not revoke the successor. ErrorCode={successorRefresh.ErrorCode}");
        }
        finally
        {
            secretMaterial.PublicKey.Dispose();
            secretMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §4.3.1</see>: "if client authentication is included in the request, ensure that
    /// the refresh token was issued to the authenticated client". Basic credentials identify the
    /// bound confidential client even when the refresh form omits client_id.
    /// </summary>
    [TestMethod]
    public async Task BasicOnlyRefreshWithoutFormClientIdRotatesNormally()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        string original = await IssueBasicAuthenticatedRefreshTokenAsync(host, material).ConfigureAwait(false);
        OutgoingHeaders headers = OutgoingHeaders.Empty.WithClientSecretBasic(ClientId, Encoding.UTF8.GetBytes(ClientSecret));
        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, material.Registration.TenantId.Value,
            RawAuthCodeWirePushers.BuildRefreshTokenFields(null, original), headers,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, StatusCode, "Authenticated Basic identity must suffice without form client_id.");
        using JsonDocument document = JsonDocument.Parse(Body);
        Assert.AreNotEqual(original,
            document.RootElement.GetProperty(OAuthRequestParameterNames.RefreshToken).GetString());
    }


    /// <summary>
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §4.3.1</see>: "it will revoke the active refresh token as well as the access
    /// authorization grant associated with it." A valid Basic-only reuse identifies its bound
    /// confidential client and revokes the successor without a form client_id.
    /// </summary>
    [TestMethod]
    public async Task BasicOnlyRefreshReuseWithoutFormClientIdRevokesTheSuccessor()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        string original = await IssueBasicAuthenticatedRefreshTokenAsync(host, material).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        OutgoingHeaders headers = OutgoingHeaders.Empty.WithClientSecretBasic(ClientId, Encoding.UTF8.GetBytes(ClientSecret));
        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, original), headers,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, StatusCode, Body);
        using JsonDocument document = JsonDocument.Parse(Body);
        string successor = document.RootElement.GetProperty(OAuthRequestParameterNames.RefreshToken).GetString()!;

        (int StatusCode, string Body) reuse = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(null, original), headers,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, reuse.StatusCode, reuse.Body);
        (int StatusCode, string Body) afterReuse = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, successor), headers,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, afterReuse.StatusCode,
            "Valid Basic-only reuse must revoke the current successor without form client_id.");
        Assert.Contains(OAuthErrors.InvalidGrant, afterReuse.Body, StringComparison.Ordinal);
    }


    /// <summary>
    /// Identification of a presented <c>client_id</c> runs FIRST at the refresh grant, before the
    /// declared method authenticates: a live refresh presenting BOTH a wrong form
    /// <c>client_id</c> and a failing <c>client_secret</c> is refused by identification alone, with
    /// the SAME constant <c>invalid_grant</c> body an unknown, expired, retired, or revoked refresh
    /// token receives (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749
    /// §5.2</see>'s "issued to another client"), never the credential-specific
    /// <c>invalid_client</c> — an unauthenticated observer must not be able to tell a wrong
    /// <c>client_id</c> on a live token apart from one on a token that never existed. Nothing is
    /// consumed: the successor refresh with the correct identity still succeeds.
    /// </summary>
    [TestMethod]
    public async Task LiveRefreshWithWrongFormClientIdAnswersInvalidGrantRegardlessOfCredential()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> secretMaterial = BuildSecretKeyMaterial(ClientSecret);
        try
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
                ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
                    ValueTask.FromResult(
                        fields.TryGetValue(OAuthRequestParameterNames.ClientSecret, out string? secret)
                        && string.Equals(secret, ClientSecret, StringComparison.Ordinal));
            }).ConfigureAwait(false);

            await DeclareServerSideAuthMethodAsync(host, material, ClientAuthenticationMethod.ClientSecretPost).ConfigureAwait(false);

            (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
                await host.CreateOAuthClientAndRegistrationAsync(
                    material.Registration, RedirectUri.OriginalString, profile: PolicyProfile.Rfc6749WithPkce,
                    TestContext.CancellationToken).ConfigureAwait(false);
            ClientRegistration authenticated = registration with
            {
                AuthenticationMethod = ClientAuthenticationMethod.ClientSecretPost,
                AuthenticationKeyMaterial = secretMaterial
            };

            using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
            HostedAuthorizationServer hosted = host.Host("default");
            string segment = material.Registration.TenantId.Value;

            AuthCodeFlowDriveResult drive = await AuthCodeFlowDriver.DriveParAuthorizeCallbackAndTokenAsync(
                hosted, client, authenticated, clientFlowStore, segment, RedirectUri, SubjectId, browserClient,
                scope: WellKnownScopes.OpenId, cancellationToken: TestContext.CancellationToken)
                .ConfigureAwait(false);
            string original = (string)drive.TokenResult.Body![OAuthRequestParameterNames.RefreshToken];

            Dictionary<string, string> fields = RawAuthCodeWirePushers.BuildRefreshTokenFields(
                "https://a-different-client.test", original);
            fields[OAuthRequestParameterNames.ClientSecret] = WrongClientSecret;

            (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, fields, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(400, StatusCode, Body);
            Assert.Contains(OAuthErrors.InvalidGrant, Body, StringComparison.Ordinal);

            RefreshTokenRequest rotateRequest = new()
            {
                ClientId = registration.ClientId.Value,
                RefreshToken = original
            };
            AuthCodeFlowEndpointResult rotation = await client.AuthCode.RefreshAsync(
                authenticated, rotateRequest, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, rotation.Outcome,
                $"The identification refusal must not consume the refresh token. ErrorCode={rotation.ErrorCode}");
        }
        finally
        {
            secretMaterial.PublicKey.Dispose();
            secretMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// Identification of a presented <c>client_id</c> runs FIRST at the refresh grant: a refresh
    /// presented with valid Basic credentials AND a conflicting form <c>client_id</c> is refused by
    /// identification alone, before the credentials are even consulted, with the SAME constant
    /// <c>invalid_grant</c> body an unknown, expired, retired, or revoked refresh token receives —
    /// no <c>WWW-Authenticate</c> challenge, since this is not a declared-authentication refusal
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 §5.2</see>'s
    /// "issued to another client"). The Basic challenge this RFC 6749 §5.2 sentence requires is
    /// asserted at client credentials instead, where a conflicting field keeps the
    /// credential-specific <c>invalid_client</c> answer. Nothing rotates: the token still refreshes
    /// with the registration's own identity afterward.
    /// </summary>
    [TestMethod]
    public async Task BasicAuthenticatedRefreshWithConflictingFormClientIdReturnsInvalidGrant()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        string original = await IssueBasicAuthenticatedRefreshTokenAsync(host, material).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        OutgoingHeaders headers = OutgoingHeaders.Empty.WithClientSecretBasic(ClientId, Encoding.UTF8.GetBytes(ClientSecret));
        HostedAuthorizationServer hosted = host.Host("default");
        Uri tokenUrl = RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, segment);

        HttpResponseData response = await HttpClientTransport.SendFormPostAsync(
            hosted.SharedHttpClient!, tokenUrl,
            RawAuthCodeWirePushers.BuildRefreshTokenFields("https://not-this-registration.example.com", original),
            headers, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.Contains(OAuthErrors.InvalidGrant, response.Body, StringComparison.Ordinal);
        string? challenge = response.Headers.TryGetSingle(WellKnownHttpHeaderNames.WwwAuthenticate);
        Assert.IsNull(challenge, "An identification refusal is not a declared-authentication failure and carries no WWW-Authenticate.");

        HttpResponseData successorResponse = await HttpClientTransport.SendFormPostAsync(
            hosted.SharedHttpClient!, tokenUrl,
            RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, original),
            headers, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, successorResponse.StatusCode, successorResponse.Body);
    }


    /// <summary>
    /// Issues an initial refresh token through a complete real-wire authorization using Basic
    /// credentials. The setup binds the registration and validates the header so raw refresh
    /// tests can vary only the presence of form client_id.
    /// </summary>
    private async Task<string> IssueBasicAuthenticatedRefreshTokenAsync(TestHostShell host, VerifierKeyMaterial material)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> secretMaterial = BuildSecretKeyMaterial(ClientSecret);
        try
        {

            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
                    ValueTask.FromResult(AuthCodeFlowDriver.DecodeAndMatchBasicHeader(request, registration.ClientId, ClientSecret));
            }).ConfigureAwait(false);

            await DeclareServerSideAuthMethodAsync(host, material, ClientAuthenticationMethod.ClientSecretBasic).ConfigureAwait(false);
            (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
                await host.CreateOAuthClientAndRegistrationAsync(
                    material.Registration, RedirectUri.OriginalString, profile: PolicyProfile.Rfc6749WithPkce,
                    TestContext.CancellationToken).ConfigureAwait(false);
            registration = registration with
            {
                AuthenticationMethod = ClientAuthenticationMethod.ClientSecretBasic,
                AuthenticationKeyMaterial = secretMaterial
            };
            using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
            AuthCodeFlowDriveResult drive = await AuthCodeFlowDriver.DriveParAuthorizeCallbackAndTokenAsync(
                host.Host("default"), client, registration, clientFlowStore, material.Registration.TenantId.Value,
                RedirectUri, SubjectId, browserClient, scope: WellKnownScopes.OpenId,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            return (string)drive.TokenResult.Body![OAuthRequestParameterNames.RefreshToken];
        }
        finally
        {
            secretMaterial.PublicKey.Dispose();
            secretMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// Drives PAR → authorize → callback → token over the real wire to obtain an initial refresh
    /// token, then refreshes through <see cref="AuthCodeFlowDriver.DriveRefreshAsync"/> — asserting
    /// both legs, including the refresh the confidential-auth attachment under test gates, succeeded
    /// and rotated in a fresh access token.
    /// </summary>
    private async Task DriveInitialIssuanceAndAssertRefreshSucceedsAsync(
        TestHostShell host,
        OAuthClient client,
        ClientRegistration registration,
        Dictionary<string, FlowState> clientFlowStore,
        string tenantSegment,
        ClientAssertionOptions? clientAssertionOptions = null)
    {
        using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
        HostedAuthorizationServer hosted = host.Host("default");

        AuthCodeFlowDriveResult drive = await AuthCodeFlowDriver.DriveParAuthorizeCallbackAndTokenAsync(
            hosted, client, registration, clientFlowStore, tenantSegment, RedirectUri, SubjectId, browserClient,
            scope: WellKnownScopes.OpenId, clientAssertionOptions: clientAssertionOptions,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        string originalAccessToken = (string)drive.TokenResult.Body![OAuthRequestParameterNames.AccessToken];
        string originalRefreshToken = (string)drive.TokenResult.Body![OAuthRequestParameterNames.RefreshToken];
        Assert.IsFalse(string.IsNullOrEmpty(originalRefreshToken), "The initial issuance must include a refresh_token.");

        RefreshTokenRequest refreshRequest = new()
        {
            ClientId = registration.ClientId.Value,
            RefreshToken = originalRefreshToken
        };
        AuthCodeFlowEndpointResult refreshResult = await AuthCodeFlowDriver.DriveRefreshAsync(
            client, registration, refreshRequest, clientAssertionOptions, TestContext.CancellationToken)
            .ConfigureAwait(false);

        string newAccessToken = (string)refreshResult.Body![OAuthRequestParameterNames.AccessToken];
        Assert.IsFalse(string.IsNullOrEmpty(newAccessToken), "The AS must mint a fresh access token on refresh.");
        Assert.AreNotEqual(originalAccessToken, newAccessToken,
            "Refresh must issue a fresh access token, not return the original.");
    }


    /// <summary>
    /// Re-registers the server-side <see cref="ClientRecord"/> with
    /// <see cref="ClientRecord.TokenEndpointAuthMethod"/> set to <paramref name="method"/> — the
    /// declared-client shape draft-ietf-oauth-client-id-metadata-document-02 §8.2 (CIMD-049/050) gates
    /// on, so a passing refresh proves the client attached the credential the server actually
    /// required. Uses the register-then-upgrade pattern the sibling grant suites use, because the
    /// routing dictionaries are host-internal. Also declares <paramref name="method"/> on
    /// <see cref="AuthorizationServerIntegration.ClientAuthenticationMethodsSupported"/> (RFC 8414,
    /// Section 2) alongside <see cref="ClientAuthenticationMethod.None"/> — the token endpoint now
    /// refuses a registration declaring a method it does not advertise before any validator runs,
    /// so the advertisement must agree with what this test's registration declares. When
    /// <paramref name="assertionSigningAlgorithm"/> is supplied it becomes the sole entry of
    /// <see cref="AuthorizationServerIntegration.ClientAssertionSigningAlgorithmsSupported"/>.
    /// </summary>
    private static async Task DeclareServerSideAuthMethodAsync(
        TestHostShell host,
        VerifierKeyMaterial material,
        ClientAuthenticationMethod method,
        string? clientJwks = null,
        string? assertionSigningAlgorithm = null)
    {
        HostedAuthorizationServer hosted = host.Host("default");
        _ = await host.SetTokenEndpointAuthMethodAsync(material, method, clientJwks).ConfigureAwait(false);

        await TestHostShell.AlterAsync(hosted.Server, candidateIntegration =>
        {
            candidateIntegration.ClientAuthenticationMethodsSupported =
                [ClientAuthenticationMethod.None, method];
            if(assertionSigningAlgorithm is not null)
            {
                candidateIntegration.ClientAssertionSigningAlgorithmsSupported = [assertionSigningAlgorithm];
            }
        }).ConfigureAwait(false);
    }


    /// <summary>
    /// Wraps <paramref name="secret"/>'s UTF-8 bytes as a <see cref="PrivateKeyMemory"/> carrying no
    /// crypto tag (<see cref="Tag.Empty"/>) — a bare RFC 6749 §2.3.1 shared secret is not an
    /// asymmetric key, so none of the existing <see cref="CryptoTags"/> algorithm-specific entries
    /// apply. The paired <see cref="PublicKeyMemory"/> is never read (only
    /// <see cref="ClientRegistration.AuthenticationKeyMaterial"/>'s <c>PrivateKey</c> half is
    /// consulted for <c>client_secret_post</c>/<c>client_secret_basic</c>).
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership transfers to the caller, which disposes both halves via secretMaterial.PublicKey/PrivateKey.")]
    private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> BuildSecretKeyMaterial(string secret)
    {
        byte[] secretBytes = Encoding.UTF8.GetBytes(secret);
        IMemoryOwner<byte> secretOwner = Pool.Rent(secretBytes.Length);
        secretBytes.CopyTo(secretOwner.Memory.Span);
        PrivateKeyMemory privateKey = new(secretOwner, Tag.Empty);

        //Never read — client_secret_post/basic consult only the PrivateKey half — but a
        //PublicPrivateKeyMaterial pair requires one regardless.
        IMemoryOwner<byte> unusedPublicOwner = Pool.Rent(1);
        PublicKeyMemory publicKey = new(unusedPublicOwner, Tag.Empty);

        return new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(publicKey, privateKey);
    }




    private static string BuildJwksJson(IReadOnlyDictionary<string, string> jwk, string kid)
    {
        StringBuilder sb = new();
        _ = sb.Append('{').Append('"').Append(WellKnownJwkMemberNames.Keys).Append("\":[{");
        foreach(KeyValuePair<string, string> member in jwk)
        {
            _ = sb.Append('"').Append(member.Key).Append("\":\"").Append(member.Value).Append("\",");
        }

        _ = sb.Append('"').Append(WellKnownJwkMemberNames.Kid).Append("\":\"").Append(kid).Append("\"}]}");

        return sb.ToString();
    }


    /// <summary>
    /// A confidential registration's wrong <c>client_secret_basic</c> secret at REFRESH: the
    /// endpoint's pre-correlation step authenticates the declared method before the presented
    /// <c>refresh_token</c> is ever looked up, so an unknown token and a live one answer
    /// byte-identically — <c>401 invalid_client</c> with the <c>WWW-Authenticate: Basic</c>
    /// challenge. A <c>client_id</c> naming a registration other than this tenant's own is
    /// identification, not authentication, and never reaches this answer — it is refused with
    /// the not-found constant instead. The live grant is unconsumed: it still refreshes with the
    /// correct secret afterward.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 §5.2</see>.
    /// </summary>
    [TestMethod]
    public async Task WrongBasicSecretAtRefreshAnswersTheSameBodyForAnUnknownAndALiveRefreshTokenAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        string originalRefreshToken = await IssueBasicAuthenticatedRefreshTokenAsync(host, material).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        HostedAuthorizationServer hosted = host.Host("default");
        Uri tokenUri = RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, segment);

        OutgoingHeaders wrongSecretHeaders = OutgoingHeaders.Empty.WithClientSecretBasic(
            ClientId, Encoding.UTF8.GetBytes(WrongClientSecret));

        HttpResponseData liveResponse = await HttpClientTransport.SendFormPostAsync(
            hosted.SharedHttpClient!, tokenUri, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, originalRefreshToken),
            wrongSecretHeaders, TestContext.CancellationToken).ConfigureAwait(false);
        HttpResponseData unknownResponse = await HttpClientTransport.SendFormPostAsync(
            hosted.SharedHttpClient!, tokenUri, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, "unknown-refresh-token-value"),
            wrongSecretHeaders, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(401, liveResponse.StatusCode, liveResponse.Body);
        Assert.Contains(OAuthErrors.InvalidClient, liveResponse.Body, StringComparison.Ordinal);
        string? liveChallenge = liveResponse.Headers.TryGetSingle(WellKnownHttpHeaderNames.WwwAuthenticate);
        Assert.AreEqual(WellKnownAuthenticationSchemes.Basic, liveChallenge);
        Assert.AreEqual(liveResponse.StatusCode, unknownResponse.StatusCode);
        Assert.AreEqual(liveResponse.Body, unknownResponse.Body,
            "An unknown refresh token and a live one must answer byte-identically for a wrong Basic secret.");
        Assert.AreEqual(liveChallenge, unknownResponse.Headers.TryGetSingle(WellKnownHttpHeaderNames.WwwAuthenticate));

        //A client_id naming a registration other than this tenant's own is identification, never
        //authentication — it answers the not-found constant, never invalid_client.
        HttpResponseData foreignResponse = await HttpClientTransport.SendFormPostAsync(
            hosted.SharedHttpClient!, tokenUri,
            RawAuthCodeWirePushers.BuildRefreshTokenFields("https://not-this-registration.example.com", originalRefreshToken),
            wrongSecretHeaders, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, foreignResponse.StatusCode, foreignResponse.Body);
        Assert.Contains(OAuthErrors.InvalidGrant, foreignResponse.Body, StringComparison.Ordinal);
        Assert.IsFalse(foreignResponse.Body.Contains(OAuthErrors.InvalidClient, StringComparison.Ordinal),
            "A client_id naming a foreign registration must never answer invalid_client at refresh.");

        //The live grant is unconsumed: it still refreshes with the correct secret.
        OutgoingHeaders rightSecretHeaders = OutgoingHeaders.Empty.WithClientSecretBasic(ClientId, Encoding.UTF8.GetBytes(ClientSecret));
        HttpResponseData redemption = await HttpClientTransport.SendFormPostAsync(
            hosted.SharedHttpClient!, tokenUri, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, originalRefreshToken),
            rightSecretHeaders, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, redemption.StatusCode, redemption.Body);
    }
}
