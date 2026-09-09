using System.Buffers;
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
using Verifiable.OAuth.Server;
using Verifiable.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The auth-code token leg attaches confidential-client
/// authentication automatically per <see cref="ClientRegistration.AuthenticationMethod"/>, over the
/// real wire, for every declared method — <c>client_secret_post</c>, <c>client_secret_basic</c>, and
/// <c>private_key_jwt</c> — through <see cref="AuthCodeFlowDriver.DriveParAuthorizeCallbackAndTokenAsync"/>,
/// the same shared drive <see cref="AuthCodeParPkceRealWireFlowTests"/> and the agentic-flow capstone
/// use. <see cref="ClientRecord.TokenEndpointAuthMethod"/> is set server-side so the exchange fails
/// closed (draft-ietf-oauth-client-id-metadata-document-02 §8.2, CIMD-049) without the attached
/// credential — a passing exchange therefore proves the client attached it, not that the server never
/// asked.
/// </summary>
[TestClass]
internal sealed class AuthCodeClientAuthenticationTests
{
    /// <summary>MSTest's per-test context, supplying the cancellation token every wire call runs under.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The clock the host and the client share.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    private const string ClientId = "https://confidential.client.test";

    private const string SubjectId = "subject-confidential-auth-code-01";

    private const string ClientSecret = "s3cret-of-the-confidential-client";

    private const string WrongClientSecret = "wrong-secret-not-matching-the-validator";

    private static Uri ClientBaseUri { get; } = new(ClientId);

    private static Uri RedirectUri { get; } = new("https://client.example.com/callback");

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;


    /// <summary>
    /// <c>client_secret_post</c> (RFC 6749 §2.3.1): the real client attaches <c>client_id</c> +
    /// <c>client_secret</c> to the token-request body — no explicit <see cref="ClientAssertionOptions"/>
    /// needed, so the exchange drives through the plain <see cref="AuthCodeClient.ExchangeTokenAsync(ClientRegistration, string, System.Threading.CancellationToken)"/>
    /// path via <see cref="AuthCodeFlowDriver"/> — and the server-side declared-method invariant
    /// requires it.
    /// </summary>
    [TestMethod]
    public async Task ClientSecretPostAuthenticatesOverRealWire()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> secretMaterial = BuildSecretKeyMaterial(ClientSecret);
        try
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = host.RegisterDpopClient(
                ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);
            DeclareServerSideAuthMethod(host, material, ClientAuthenticationMethod.ClientSecretPost);

            host.Server.OAuth().ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
                ValueTask.FromResult(
                    fields.TryGetValue(OAuthRequestParameterNames.ClientSecret, out string? secret)
                    && string.Equals(secret, ClientSecret, StringComparison.Ordinal));

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

            await DriveAndAssertSucceedsAsync(
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
    /// <c>Authorization</c> header — again through the plain <c>ExchangeTokenAsync</c> path, since
    /// this method needs no per-call <see cref="ClientAssertionOptions"/> either.
    /// </summary>
    [TestMethod]
    public async Task ClientSecretBasicAuthenticatesOverRealWire()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> secretMaterial = BuildSecretKeyMaterial(ClientSecret);
        try
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = host.RegisterDpopClient(
                ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);
            DeclareServerSideAuthMethod(host, material, ClientAuthenticationMethod.ClientSecretBasic);

            host.Server.OAuth().ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
                ValueTask.FromResult(DecodeAndMatchBasicHeader(request, registration.ClientId, ClientSecret));

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

            await DriveAndAssertSucceedsAsync(
                host, client, registration, clientFlowStore, material.Registration.TenantId.Value).ConfigureAwait(false);
        }
        finally
        {
            secretMaterial.PublicKey.Dispose();
            secretMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <c>private_key_jwt</c> (RFC 7523 §2.2): the real client signs and attaches a
    /// <c>client_assertion</c> from <see cref="TestKeyMaterialProvider"/>-generated P-256 key material,
    /// driven through <see cref="AuthCodeFlowDriver.DriveParAuthorizeCallbackAndTokenAsync"/>'s
    /// <see cref="ClientAssertionOptions"/> overload, and the server verifies it with the real
    /// <see cref="PrivateKeyJwtClientAuthentication.BuildValidator(System.Collections.Generic.IReadOnlyCollection{string}?,CheckClientAssertionJtiReplayDelegate?)"/>
    /// pipeline over a published <c>ClientJwks</c> — the same production shape
    /// <see cref="PrivateKeyJwtClientAuthenticationTests"/> exercises directly. The validator accepts
    /// the resolved token endpoint URL as <c>aud</c> (RFC 7523 §3 item 3's permitted alternate),
    /// matching what <see cref="ClientTokenEndpointAuthentication.AttachClientAssertionAsync"/> signs.
    /// </summary>
    [TestMethod]
    public async Task PrivateKeyJwtAuthenticatesOverRealWire()
    {
        var clientKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = host.RegisterDpopClient(
                ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

            //Start the listener before wiring the validator so the resolved token endpoint URL
            //(the client-signed aud, per RFC 7523 §3 item 3) is known.
            await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
            HostedAuthorizationServer hosted = host.Host("default");
            string segment = material.Registration.TenantId.Value;
            Uri tokenEndpoint = new(
                hosted.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, segment));

            string alg = CryptoFormatConversions.DefaultTagToJwaConverter(clientKeys.PublicKey.Tag);
            const string SigningKeyId = "confidential-client-key-1";
            IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
                clientKeys.PublicKey, alg, TestSetup.Base64UrlEncoder);
            string jwksJson = BuildJwksJson(jwk, SigningKeyId);
            DeclareServerSideAuthMethod(
                host, material, ClientAuthenticationMethod.PrivateKeyJwt,
                clientJwks: jwksJson, assertionSigningAlgorithm: alg);

            host.Server.OAuth().ValidateClientCredentialsAsync =
                PrivateKeyJwtClientAuthentication.BuildValidator(
                    additionalAcceptedAudiences: [tokenEndpoint.OriginalString]);

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

            await DriveAndAssertSucceedsAsync(
                host, client, registration, clientFlowStore, material.Registration.TenantId.Value,
                clientAssertionOptions: new ClientAssertionOptions
                {
                    SigningKeyId = SigningKeyId,
                    HeaderSerializer = host.Server.OAuth().Codecs.JwtHeaderSerializer!,
                    PayloadSerializer = host.Server.OAuth().Codecs.JwtPayloadSerializer!
                }).ConfigureAwait(false);
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// RFC 7523 §3 over the real wire: a <c>private_key_jwt</c> assertion carries a <c>jti</c>, and a
    /// store that records it but never resolves what it saved under <c>FlowKind.JtiReplay</c> cannot
    /// maintain the used-<c>jti</c> set. <see cref="JtiReplayGuard"/> answers
    /// <see cref="JtiReplayOutcome.StoreUnavailable"/>, the validator rejects the assertion, and the
    /// token endpoint refuses with <c>invalid_client</c> — the silent no-op the half-wiring would
    /// otherwise produce is caught rather than admitted.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523, Section 3</see>.
    /// </summary>
    [TestMethod]
    public async Task PrivateKeyJwtAssertionFailsClosedWhenStoreCannotProveItself()
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
            const string SigningKeyId = "confidential-client-key-1";
            IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
                clientKeys.PublicKey, alg, TestSetup.Base64UrlEncoder);
            string jwksJson = BuildJwksJson(jwk, SigningKeyId);
            DeclareServerSideAuthMethod(
                host, material, ClientAuthenticationMethod.PrivateKeyJwt,
                clientJwks: jwksJson, assertionSigningAlgorithm: alg);

            //The validator consults the shared (issuer, jti) guard on the assertion's jti, so a store
            //that cannot prove it recorded the jti fails the assertion closed.
            host.Server.OAuth().ValidateClientCredentialsAsync =
                PrivateKeyJwtClientAuthentication.BuildValidator(
                    additionalAcceptedAudiences: [tokenEndpoint.OriginalString],
                    checkJtiReplayAsync: JtiReplayGuard.ConsultAsync);

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

            HalfWireJtiReplayStore(host.Server);

            AuthCodeFlowEndpointResult tokenResult = await client.AuthCode.ExchangeTokenAsync(
                registration,
                flowId,
                new ExchangeContext(),
                clientAssertionOptions: new ClientAssertionOptions
                {
                    SigningKeyId = SigningKeyId,
                    HeaderSerializer = host.Server.OAuth().Codecs.JwtHeaderSerializer!,
                    PayloadSerializer = host.Server.OAuth().Codecs.JwtPayloadSerializer!
                },
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreNotEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
                "The half-wired store must refuse the assertion.");
            Assert.AreEqual(OAuthErrors.InvalidClient, tokenResult.ErrorCode,
                $"RFC 7523 §3: a store that cannot prove it recorded the assertion jti fails closed. Description: {tokenResult.ErrorDescription}");
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// Rewires the host's replay store so it saves normally but never resolves anything under
    /// <c>FlowKind.JtiReplay</c>, while every other correlation kind still resolves through the host's
    /// real resolver. This is the half-wired store the guard's post-save self-check must catch.
    /// </summary>
    /// <param name="server">The hosted server whose OAuth integration resolver is wrapped.</param>
    private static void HalfWireJtiReplayStore(EndpointServer server)
    {
        ResolveCorrelationKeyDelegate original = server.OAuth().ResolveCorrelationKeyAsync!;
        server.OAuth().ResolveCorrelationKeyAsync = (tenantId, flowKind, externalHandle, ctx, ct) =>
            flowKind == FlowKind.JtiReplay
                ? ValueTask.FromResult<string?>(null)
                : original(tenantId, flowKind, externalHandle, ctx, ct);
    }


    /// <summary>
    /// Every declared confidential method fails closed without the credential the client would
    /// normally attach automatically — pinning that the positive tests above prove genuine
    /// authentication rather than a server that never checks. Uses <c>client_secret_post</c>: a
    /// declared confidential client whose <see cref="ClientRegistration.AuthenticationMethod"/> stays
    /// <see cref="ClientAuthenticationMethod.None"/> presents no credential at all.
    /// </summary>
    [TestMethod]
    public async Task DeclaredConfidentialClientWithoutAttachedCredentialFailsClosed()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);
        DeclareServerSideAuthMethod(host, material, ClientAuthenticationMethod.ClientSecretPost);

        host.Server.OAuth().ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
            ValueTask.FromResult(
                fields.TryGetValue(OAuthRequestParameterNames.ClientSecret, out string? secret)
                && string.Equals(secret, ClientSecret, StringComparison.Ordinal));

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                RedirectUri.OriginalString,
                profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);
        //AuthenticationMethod deliberately left at its None default — the client attaches nothing.

        using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;

        (string flowId, _) = await AuthCodeFlowDriver.DriveParAuthorizeAndCallbackAsync(
            hosted, client, registration, clientFlowStore, segment, RedirectUri, SubjectId, browserClient,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        AuthCodeFlowEndpointResult tokenResult = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreNotEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
            "A declared confidential client presenting no credential must not be issued a token.");
        Assert.AreEqual(OAuthErrors.InvalidClient, tokenResult.ErrorCode);
    }


    /// <summary>
    /// RFC 7523 §3.1: "if client credentials are present in the request, the authorization server
    /// MUST validate them." <see cref="ClientRecord.TokenEndpointAuthMethod"/> is deliberately left
    /// UNDECLARED (<see cref="DeclareServerSideAuthMethod"/> is never called) — before this fix,
    /// <c>RequireClientAuthenticationIfDeclaredAsync</c>'s null/None branch returned success
    /// immediately without ever consulting whether a credential was attached, so a WRONG
    /// <c>client_secret</c> on an undeclared-method registration was silently ignored and the token
    /// was minted anyway. The client here attaches a <c>client_secret_post</c> credential that does
    /// NOT match what the validator seam accepts, so a token must not be issued.
    /// </summary>
    [TestMethod]
    public async Task PresentedWrongSecretOnUndeclaredMethodFailsClosed()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> wrongSecretMaterial = BuildSecretKeyMaterial(WrongClientSecret);
        try
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = host.RegisterDpopClient(
                ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);
            //TokenEndpointAuthMethod deliberately left unset (null) — DeclareServerSideAuthMethod is
            //never called, so the registration never declares a confidential method.

            host.Server.OAuth().ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
                ValueTask.FromResult(
                    fields.TryGetValue(OAuthRequestParameterNames.ClientSecret, out string? secret)
                    && string.Equals(secret, ClientSecret, StringComparison.Ordinal));

            (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
                await host.CreateOAuthClientAndRegistrationAsync(
                    material.Registration,
                    RedirectUri.OriginalString,
                    profile: PolicyProfile.Rfc6749WithPkce,
                    TestContext.CancellationToken).ConfigureAwait(false);
            registration = registration with
            {
                AuthenticationMethod = ClientAuthenticationMethod.ClientSecretPost,
                AuthenticationKeyMaterial = wrongSecretMaterial
            };

            using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
            HostedAuthorizationServer hosted = host.Host("default");
            string segment = material.Registration.TenantId.Value;

            (string flowId, _) = await AuthCodeFlowDriver.DriveParAuthorizeAndCallbackAsync(
                hosted, client, registration, clientFlowStore, segment, RedirectUri, SubjectId, browserClient,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            AuthCodeFlowEndpointResult tokenResult = await client.AuthCode.ExchangeTokenAsync(
                registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreNotEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
                "A wrong client_secret presented on an undeclared token_endpoint_auth_method must not be issued a token.");
            Assert.AreEqual(OAuthErrors.InvalidClient, tokenResult.ErrorCode);
        }
        finally
        {
            wrongSecretMaterial.PublicKey.Dispose();
            wrongSecretMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// RFC 7523 §3.1's "MUST validate them" cuts both ways: a CORRECT credential presented on an
    /// undeclared <see cref="ClientRecord.TokenEndpointAuthMethod"/> must authenticate the client
    /// rather than being hard-refused — the fix is validate-if-present, not reject-if-undeclared.
    /// Otherwise-identical to <see cref="ClientSecretPostAuthenticatesOverRealWire"/> except
    /// <see cref="DeclareServerSideAuthMethod"/> is never called, proving the token is minted on the
    /// strength of the validated credential alone, with no server-side declaration in play.
    /// </summary>
    [TestMethod]
    public async Task PresentedCorrectSecretOnUndeclaredMethodAuthenticates()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> secretMaterial = BuildSecretKeyMaterial(ClientSecret);
        try
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = host.RegisterDpopClient(
                ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);
            //TokenEndpointAuthMethod deliberately left unset (null) — no DeclareServerSideAuthMethod call.

            host.Server.OAuth().ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
                ValueTask.FromResult(
                    fields.TryGetValue(OAuthRequestParameterNames.ClientSecret, out string? secret)
                    && string.Equals(secret, ClientSecret, StringComparison.Ordinal));

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

            await DriveAndAssertSucceedsAsync(
                host, client, registration, clientFlowStore, material.Registration.TenantId.Value).ConfigureAwait(false);
        }
        finally
        {
            secretMaterial.PublicKey.Dispose();
            secretMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// The hard-fail arm: an undeclared <see cref="ClientRecord.TokenEndpointAuthMethod"/> whose
    /// request attaches a credential, but the authorization server never wired
    /// <see cref="AuthorizationServerIntegration.ValidateClientCredentialsAsync"/> at all. RFC 7523
    /// §3.1's "MUST validate them" cannot be satisfied by an absent validator, so this must fail
    /// closed rather than silently proceed as if the credential were never presented.
    /// </summary>
    [TestMethod]
    public async Task PresentedCredentialWithUnwiredValidatorOnUndeclaredMethodFailsClosed()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> secretMaterial = BuildSecretKeyMaterial(ClientSecret);
        try
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = host.RegisterDpopClient(
                ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);
            //TokenEndpointAuthMethod deliberately left unset (null); ValidateClientCredentialsAsync
            //deliberately left unwired (null) — the seam-unwired hard-fail arm under test.

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

            (string flowId, _) = await AuthCodeFlowDriver.DriveParAuthorizeAndCallbackAsync(
                hosted, client, registration, clientFlowStore, segment, RedirectUri, SubjectId, browserClient,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            AuthCodeFlowEndpointResult tokenResult = await client.AuthCode.ExchangeTokenAsync(
                registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreNotEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
                "A presented credential with no client-authentication seam configured must not be issued a token.");
            Assert.AreEqual(OAuthErrors.InvalidClient, tokenResult.ErrorCode);
        }
        finally
        {
            secretMaterial.PublicKey.Dispose();
            secretMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// Drives PAR → authorize → callback → token over the real wire and asserts every leg — including
    /// the token exchange the confidential-auth attachment under test gates — succeeded.
    /// </summary>
    private async Task DriveAndAssertSucceedsAsync(
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
            clientAssertionOptions: clientAssertionOptions, cancellationToken: TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, drive.TokenResult.Outcome,
            $"Token exchange must succeed over the real wire. ErrorCode={drive.TokenResult.ErrorCode} ErrorDescription={drive.TokenResult.ErrorDescription}");
        string accessToken = (string)drive.TokenResult.Body![OAuthRequestParameterNames.AccessToken];
        Assert.IsFalse(string.IsNullOrEmpty(accessToken), "The AS must mint an access token.");
    }


    /// <summary>
    /// Re-registers the server-side <see cref="ClientRecord"/> with
    /// <see cref="ClientRecord.TokenEndpointAuthMethod"/> set to <paramref name="method"/> — the
    /// declared-client shape draft-ietf-oauth-client-id-metadata-document-02 §8.2 (CIMD-049) gates
    /// on, so a passing exchange proves the client attached the credential the server actually
    /// required. Uses the register-then-upgrade pattern the sibling grant suites use, because the
    /// routing dictionaries are host-internal. Also declares <paramref name="method"/> on
    /// <see cref="AuthorizationServerIntegration.ClientAuthenticationMethodsSupported"/> (RFC 8414,
    /// Section 2) alongside <see cref="ClientAuthenticationMethod.None"/> — the token endpoint now
    /// refuses a registration declaring a method it does not advertise before any validator runs,
    /// so the advertisement must agree with what this test's registration declares. When
    /// <paramref name="assertionSigningAlgorithm"/> is supplied it becomes the sole entry of
    /// <see cref="AuthorizationServerIntegration.ClientAssertionSigningAlgorithmsSupported"/>.
    /// </summary>
    private static void DeclareServerSideAuthMethod(
        TestHostShell host,
        VerifierKeyMaterial material,
        ClientAuthenticationMethod method,
        string? clientJwks = null,
        string? assertionSigningAlgorithm = null)
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

        hosted.Server.OAuth().ClientAuthenticationMethodsSupported =
            [ClientAuthenticationMethod.None, method];
        if(assertionSigningAlgorithm is not null)
        {
            hosted.Server.OAuth().ClientAssertionSigningAlgorithmsSupported = [assertionSigningAlgorithm];
        }
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


    /// <summary>
    /// The test-side reverse of <see cref="OutgoingHeadersClientAuthExtensions.WithClientSecretBasic"/>
    /// (RFC 6749 §2.3.1): base64-decode the <c>Authorization: Basic</c> header, split the pair on the
    /// first <c>:</c> (the join character the encoder never percent-encodes into either half), and
    /// reverse <c>application/x-www-form-urlencoded</c> on each half — <see cref="ClientId"/> contains
    /// <c>:</c> and <c>/</c>, both of which the encoder percent-escapes, so a naive raw comparison
    /// would never match.
    /// </summary>
    private static bool DecodeAndMatchBasicHeader(
        IncomingRequest? request, string expectedClientId, string expectedClientSecret)
    {
        if(request is null
            || !request.Headers.TryGetSingle(WellKnownHttpHeaderNames.Authorization, out string? authorizationHeader)
            || authorizationHeader is null
            || !authorizationHeader.StartsWith("Basic ", StringComparison.Ordinal))
        {
            return false;
        }

        byte[] decoded = Convert.FromBase64String(authorizationHeader["Basic ".Length..]);
        string pair = Encoding.UTF8.GetString(decoded);
        int separatorIndex = pair.IndexOf(':', StringComparison.Ordinal);
        if(separatorIndex < 0)
        {
            return false;
        }

        string decodedClientId = FormUrlDecode(pair[..separatorIndex]);
        string decodedClientSecret = FormUrlDecode(pair[(separatorIndex + 1)..]);

        return string.Equals(decodedClientId, expectedClientId, StringComparison.Ordinal)
            && string.Equals(decodedClientSecret, expectedClientSecret, StringComparison.Ordinal);
    }


    /// <summary>Reverses <c>application/x-www-form-urlencoded</c> (RFC 6749 Appendix B): <c>+</c> becomes space, then <see cref="Uri.UnescapeDataString"/> resolves the remaining <c>%XX</c> triplets.</summary>
    private static string FormUrlDecode(string value) => Uri.UnescapeDataString(value.Replace('+', ' '));


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
}
