using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.OAuth.Server.States;
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
    /// <see cref="AuthCodeFlowDriver"/>'s confidential PAR path resolves its effective fields
    /// through the same field-composition the public path uses: a <c>scope</c> carried in
    /// <c>additionalParFields</c> reaches the pushed request when no explicit <c>scope</c>
    /// argument overrides it, rather than being silently replaced by the driver's own default
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749 §3.3</see>: the
    /// requested scope is the client's own request parameter).
    /// </summary>
    [TestMethod]
    public async Task ConfidentialDriverPushesScopeSuppliedThroughAdditionalParFields()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> secretMaterial = BuildSecretKeyMaterial(ClientSecret);
        try
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
                ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

            const string RequestedScope = "telemetry.read";
            string? observedScope = null;
            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.ValidateClientCredentialsAsync = (request, fields, registration, context, ct) =>
                {
                    _ = fields.TryGetValue(OAuthRequestParameterNames.Scope, out observedScope);

                    return ValueTask.FromResult(
                        fields.TryGetValue(OAuthRequestParameterNames.ClientSecret, out string? secret)
                        && string.Equals(secret, ClientSecret, StringComparison.Ordinal));
                };
            }).ConfigureAwait(false);

            await DeclareServerSideAuthMethodAsync(host, material, ClientAuthenticationMethod.ClientSecretPost).ConfigureAwait(false);

            (OAuthClient client, ClientRegistration registration, _) = await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration, RedirectUri.OriginalString,
                profile: PolicyProfile.Rfc6749WithPkce, TestContext.CancellationToken).ConfigureAwait(false);
            registration = registration with
            {
                AuthenticationMethod = ClientAuthenticationMethod.ClientSecretPost,
                AuthenticationKeyMaterial = secretMaterial
            };

            await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

            _ = await AuthCodeFlowDriver.PushConfidentialParRequestAsync(
                host.Host("default"), client, registration, material.Registration.TenantId.Value, RedirectUri,
                scope: null,
                additionalParFields: new OAuthFormEncodedFields(
                    new Dictionary<string, string> { [OAuthRequestParameterNames.Scope] = RequestedScope }),
                clientAssertionOptions: null, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(RequestedScope, observedScope,
                "A scope supplied through additionalParFields must reach the pushed confidential request.");
        }
        finally
        {
            secretMaterial.PublicKey.Dispose();
            secretMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2">RFC 9126 §2</see>: "the
    /// authorization server MUST accept its issuer identifier, token endpoint URL, or pushed
    /// authorization request endpoint URL as values that identify it as an intended audience" —
    /// three otherwise identical valid <c>private_key_jwt</c> assertions, each naming a different
    /// one of the three as <c>aud</c>, all authenticate the pushed request with no
    /// <c>additionalAcceptedAudiences</c> wired at all.
    /// </summary>
    [TestMethod]
    public async Task PushedRequestAcceptsEachOfTheThreeRfc9126AudiencesWithoutExplicitWiring()
    {
        var signingKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            string alg = CryptoFormatConversions.DefaultTagToJwaConverter(signingKeys.PublicKey.Tag);
            const string SigningKeyId = "rfc9126-audience-key-1";
            IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
                signingKeys.PublicKey, alg, TestSetup.Base64UrlEncoder);
            string jwksJson = BuildJwksJson(jwk, SigningKeyId);

            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
                ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

            await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
            HostedAuthorizationServer hosted = host.Host("default");
            string segment = material.Registration.TenantId.Value;
            Uri tokenEndpoint = new(
                hosted.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, segment));
            Uri parEndpoint = new(
                hosted.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodePar, segment));

            //No additionalAcceptedAudiences: only the resolved issuer is accepted unless the
            //library itself widens the set per RFC 9126 §2.
            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.ValidateClientCredentialsAsync =
                    PrivateKeyJwtClientAuthentication.BuildValidator();
            }).ConfigureAwait(false);

            await DeclareServerSideAuthMethodAsync(
                host, material, ClientAuthenticationMethod.PrivateKeyJwt,
                clientJwks: jwksJson, assertionSigningAlgorithm: alg).ConfigureAwait(false);

            (OAuthClient client, ClientRegistration registration, _) = await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration, RedirectUri.OriginalString,
                profile: PolicyProfile.Rfc6749WithPkce, TestContext.CancellationToken).ConfigureAwait(false);
            string issuer = registration.AuthorizationServerIssuer.OriginalString;

            foreach((string label, string audience) in new (string Label, string Audience)[]
            {
                ("issuer", issuer),
                ("token endpoint", tokenEndpoint.OriginalString),
                ("PAR endpoint", parEndpoint.OriginalString)
            })
            {
                PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, Pool);
                string assertion = await SignClientAssertionWithoutKidAsync(
                    signingKeys.PrivateKey, ClientId, audience, TimeProvider.GetUtcNow(),
                    host.Server.OAuth().Codecs.JwtHeaderSerializer!, host.Server.OAuth().Codecs.JwtPayloadSerializer!,
                    TestContext.CancellationToken).ConfigureAwait(false);

                Dictionary<string, string> parFields = new(StringComparer.Ordinal)
                {
                    [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
                    [OAuthRequestParameterNames.ClientId] = ClientId,
                    [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
                    [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
                    [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
                    [OAuthRequestParameterNames.ClientAssertionType] = WellKnownClientAssertionTypes.JwtBearer,
                    [OAuthRequestParameterNames.ClientAssertion] = assertion
                };

                (int parStatusCode, string parBody) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
                    host, segment, parFields, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(201, parStatusCode, $"aud={label} ({audience}) Body={parBody}");
            }
        }
        finally
        {
            signingKeys.PublicKey.Dispose();
            signingKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3.2">RFC 7523 §3.2</see>: the
    /// token endpoint authenticates a declared <c>private_key_jwt</c> client independently of
    /// PAR's own authentication call. A valid PAR issues a code; a HOSTILE assertion — signed by a
    /// key the registration never published — presented at REDEMPTION is refused there too, in
    /// the code-redemption endpoint's own pre-correlation step, and the code is not consumed: it
    /// still redeems correctly afterward with the registration's own valid assertion. Removing the
    /// step's own authentication call would let the hostile assertion through.
    /// </summary>
    [TestMethod]
    public async Task TokenEndpointIndependentlyRefusesAHostileAssertionAfterAValidPar()
    {
        var signingKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        var hostileKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            string alg = CryptoFormatConversions.DefaultTagToJwaConverter(signingKeys.PublicKey.Tag);
            IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
                signingKeys.PublicKey, alg, TestSetup.Base64UrlEncoder);
            string jwksJson = BuildJwksJson(jwk, "token-endpoint-own-auth-key-1");

            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
                ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

            await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
            HostedAuthorizationServer hosted = host.Host("default");
            string segment = material.Registration.TenantId.Value;
            Uri tokenEndpoint = new(
                hosted.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, segment));

            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.ValidateClientCredentialsAsync =
                    PrivateKeyJwtClientAuthentication.BuildValidator(
                        additionalAcceptedAudiences: [tokenEndpoint.OriginalString]);
            }).ConfigureAwait(false);

            await DeclareServerSideAuthMethodAsync(
                host, material, ClientAuthenticationMethod.PrivateKeyJwt,
                clientJwks: jwksJson, assertionSigningAlgorithm: alg).ConfigureAwait(false);

            PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, Pool);
            string parAssertion = await SignClientAssertionWithoutKidAsync(
                signingKeys.PrivateKey, ClientId, tokenEndpoint.OriginalString, TimeProvider.GetUtcNow(),
                host.Server.OAuth().Codecs.JwtHeaderSerializer!, host.Server.OAuth().Codecs.JwtPayloadSerializer!,
                TestContext.CancellationToken).ConfigureAwait(false);

            Dictionary<string, string> parFields = new(StringComparer.Ordinal)
            {
                [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
                [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
                [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
                [OAuthRequestParameterNames.ClientAssertionType] = WellKnownClientAssertionTypes.JwtBearer,
                [OAuthRequestParameterNames.ClientAssertion] = parAssertion
            };

            (int parStatusCode, string parBody) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
                host, segment, parFields, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(201, parStatusCode, parBody);
            string requestUri = JsonElement.Parse(parBody).GetProperty(OAuthRequestParameterNames.RequestUri).GetString()!;

            Uri authorizeUrl = new(
                hosted.HttpBaseAddress!,
                $"{TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, segment)}" +
                $"?{OAuthRequestParameterNames.ClientId}={Uri.EscapeDataString(ClientId)}" +
                $"&{OAuthRequestParameterNames.RequestUri}={Uri.EscapeDataString(requestUri)}");

            using HttpResponseMessage authorizeResponse = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
                host, authorizeUrl, SubjectId, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(302, (int)authorizeResponse.StatusCode);
            string code = TestBrowser.ExtractQueryParam(authorizeResponse.Headers.Location!.ToString(), OAuthRequestParameterNames.Code)
                ?? throw new InvalidOperationException("Authorize redirect Location missing code.");

            //A hostile assertion at REDEMPTION — signed by a key the registration never published.
            string hostileAssertion = await SignClientAssertionWithoutKidAsync(
                hostileKeys.PrivateKey, ClientId, tokenEndpoint.OriginalString, TimeProvider.GetUtcNow(),
                host.Server.OAuth().Codecs.JwtHeaderSerializer!, host.Server.OAuth().Codecs.JwtPayloadSerializer!,
                TestContext.CancellationToken).ConfigureAwait(false);
            Dictionary<string, string> hostileFields = RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString);
            hostileFields[OAuthRequestParameterNames.ClientAssertionType] = WellKnownClientAssertionTypes.JwtBearer;
            hostileFields[OAuthRequestParameterNames.ClientAssertion] = hostileAssertion;

            (int hostileStatusCode, string hostileBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, hostileFields, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(401, hostileStatusCode, hostileBody);
            Assert.Contains(OAuthErrors.InvalidClient, hostileBody, StringComparison.Ordinal);

            //The code survives: the registration's own valid assertion still redeems it.
            string redemptionAssertion = await SignClientAssertionWithoutKidAsync(
                signingKeys.PrivateKey, ClientId, tokenEndpoint.OriginalString, TimeProvider.GetUtcNow(),
                host.Server.OAuth().Codecs.JwtHeaderSerializer!, host.Server.OAuth().Codecs.JwtPayloadSerializer!,
                TestContext.CancellationToken).ConfigureAwait(false);
            Dictionary<string, string> validFields = RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString);
            validFields[OAuthRequestParameterNames.ClientAssertionType] = WellKnownClientAssertionTypes.JwtBearer;
            validFields[OAuthRequestParameterNames.ClientAssertion] = redemptionAssertion;

            (int validStatusCode, string validBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, validFields, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(200, validStatusCode, validBody);
        }
        finally
        {
            signingKeys.PublicKey.Dispose();
            signingKeys.PrivateKey.Dispose();
            hostileKeys.PublicKey.Dispose();
            hostileKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2">RFC 9126 §2</see> extends the
    /// token endpoint's <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749
    /// §5.2</see> Basic-challenge obligation to the pushed request: a confidential registration's
    /// own <c>client_id</c> with a wrong <c>client_secret_basic</c> secret is refused at PAR with
    /// the same <c>401 invalid_client</c> and <c>WWW-Authenticate</c> challenge the token endpoint
    /// would carry for the identical failure.
    /// </summary>
    [TestMethod]
    public async Task PushedRequestWithWrongBasicSecretReturns401WithWwwAuthenticateChallenge()
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

        (OAuthClient client, ClientRegistration registration, _) = await host.CreateOAuthClientAndRegistrationAsync(
            material.Registration, RedirectUri.OriginalString,
            profile: PolicyProfile.Rfc6749WithPkce, TestContext.CancellationToken).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> wrongSecretMaterial =
            BuildSecretKeyMaterial("wrong-not-the-registered-secret");
        try
        {
            registration = registration with
            {
                AuthenticationMethod = ClientAuthenticationMethod.ClientSecretBasic,
                AuthenticationKeyMaterial = wrongSecretMaterial
            };

            await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

            (HttpResponseData parResponse, _, _, _, _) = await AuthCodeFlowDriver.PushConfidentialParRequestAsync(
                host.Host("default"), client, registration, material.Registration.TenantId.Value, RedirectUri,
                scope: null, additionalParFields: default, clientAssertionOptions: null,
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(401, parResponse.StatusCode, parResponse.Body);
            Assert.Contains(OAuthErrors.InvalidClient, parResponse.Body, StringComparison.Ordinal);
            string? challenge = parResponse.Headers.TryGetSingle(WellKnownHttpHeaderNames.WwwAuthenticate);
            Assert.AreEqual(WellKnownAuthenticationSchemes.Basic, challenge,
                "The pushed request's own authentication failure over Basic must carry the matching challenge.");
        }
        finally
        {
            wrongSecretMaterial.PublicKey.Dispose();
            wrongSecretMaterial.PrivateKey.Dispose();
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
    /// <see cref="PrivateKeyJwtClientAuthentication.BuildValidator(System.Collections.Generic.IReadOnlyCollection{string}?,CheckClientAssertionJtiReplayDelegate?,Verifiable.OAuth.Server.Pipeline.ResolveJwksUriDelegate?)"/>
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
            const string SigningKeyId = "confidential-client-key-1";
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
    /// The paired positive control for
    /// <see cref="PrivateKeyJwtRefusesEncMarkedEd25519SigningKeyWithKid"/>: the same registered
    /// Ed25519 key, published with no <c>use</c> member — RFC 7517 §4.2 makes <c>use</c> OPTIONAL —
    /// authenticates the client over the real token endpoint.
    /// </summary>
    [TestMethod]
    public async Task PrivateKeyJwtAcceptsEd25519SigningKeyWithNoUseMemberWithKid()
    {
        var signingKeys = TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();
        try
        {
            string alg = CryptoFormatConversions.DefaultTagToJwaConverter(signingKeys.PublicKey.Tag);
            const string SigningKeyId = "ed25519-client-key-1";
            IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
                signingKeys.PublicKey, alg, TestSetup.Base64UrlEncoder);
            string jwksJson = BuildRegisteredJwks(BuildRegisteredJwk(jwk, SigningKeyId));

            await RunPrivateKeyJwtWithKidAsync(
                signingKeys, jwksJson, alg, SigningKeyId, expectAccepted: true,
                "An Ed25519 registered key with no use member must authenticate the client.")
                .ConfigureAwait(false);
        }
        finally
        {
            signingKeys.PublicKey.Dispose();
            signingKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// RFC 7517 §4.2: <c>use</c> identifies whether a key verifies signatures (<c>sig</c>) or
    /// encrypts data (<c>enc</c>). The registered signing key is published marked
    /// <c>"use":"enc"</c>: the selector's <c>sig</c>-eligibility filter excludes it, so no
    /// verification key is found and the client assertion is refused. Ed25519's algorithm-to-key
    /// mapping ignores <c>use</c> downstream — it always resolves to signature verification — so this
    /// negative isolates the SELECTION filter itself rather than the downstream purpose mapping a
    /// P-256 key would also exercise. The selection by <c>kid</c> alone accepts this key set.
    /// </summary>
    [TestMethod]
    public async Task PrivateKeyJwtRefusesEncMarkedEd25519SigningKeyWithKid()
    {
        var signingKeys = TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();
        try
        {
            string alg = CryptoFormatConversions.DefaultTagToJwaConverter(signingKeys.PublicKey.Tag);
            const string SigningKeyId = "ed25519-client-key-1";
            IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
                signingKeys.PublicKey, alg, TestSetup.Base64UrlEncoder);
            string jwksJson = BuildRegisteredJwks(
                BuildRegisteredJwk(jwk, SigningKeyId, use: WellKnownJwkValues.UseEnc));

            await RunPrivateKeyJwtWithKidAsync(
                signingKeys, jwksJson, alg, SigningKeyId, expectAccepted: false,
                "An enc-marked registered key must not authenticate the client.")
                .ConfigureAwait(false);
        }
        finally
        {
            signingKeys.PublicKey.Dispose();
            signingKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// The paired positive control for
    /// <see cref="PrivateKeyJwtRefusesCleanKeyBesideUnrelatedPrivateMaterialWithKid"/>: the requested
    /// key beside an unrelated, equally clean second element authenticates the client — two entries in
    /// the registered set are unremarkable on their own.
    /// </summary>
    [TestMethod]
    public async Task PrivateKeyJwtAcceptsCleanKeyBesideAnUnrelatedCleanElementWithKid()
    {
        var signingKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        var unrelatedKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            string alg = CryptoFormatConversions.DefaultTagToJwaConverter(signingKeys.PublicKey.Tag);
            const string SigningKeyId = "clean-client-key-1";
            const string UnrelatedKeyId = "unrelated-client-key-1";
            IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
                signingKeys.PublicKey, alg, TestSetup.Base64UrlEncoder);
            IReadOnlyDictionary<string, string> unrelatedJwk = DpopJwkUtilities.ToJwk(
                unrelatedKeys.PublicKey, alg, TestSetup.Base64UrlEncoder);
            string jwksJson = BuildRegisteredJwks(
                BuildRegisteredJwk(jwk, SigningKeyId),
                BuildRegisteredJwk(unrelatedJwk, UnrelatedKeyId));

            await RunPrivateKeyJwtWithKidAsync(
                signingKeys, jwksJson, alg, SigningKeyId, expectAccepted: true,
                "A clean requested key beside an unrelated clean element must authenticate the client.")
                .ConfigureAwait(false);
        }
        finally
        {
            signingKeys.PublicKey.Dispose();
            signingKeys.PrivateKey.Dispose();
            unrelatedKeys.PublicKey.Dispose();
            unrelatedKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-5.1">RFC 7517 §5.1</see>'s
    /// <c>keys</c> array is the unit this library's set-wide refusal judges: an UNRELATED element (a
    /// different <c>kid</c>, never requested) carrying <c>d</c> refuses selection of the clean,
    /// requested key too — distinct from
    /// <see cref="PrivateKeyJwtClientAuthentication"/>'s own check of the SELECTED key's members
    /// alone. The selection by <c>kid</c> alone accepts this key set: it selects the requested key by
    /// <c>kid</c> and never inspects the other element.
    /// </summary>
    [TestMethod]
    public async Task PrivateKeyJwtRefusesCleanKeyBesideUnrelatedPrivateMaterialWithKid()
    {
        var signingKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        var unrelatedKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            string alg = CryptoFormatConversions.DefaultTagToJwaConverter(signingKeys.PublicKey.Tag);
            const string SigningKeyId = "clean-client-key-1";
            const string UnrelatedKeyId = "unrelated-client-key-1";
            IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
                signingKeys.PublicKey, alg, TestSetup.Base64UrlEncoder);
            IReadOnlyDictionary<string, string> unrelatedJwk = DpopJwkUtilities.ToJwk(
                unrelatedKeys.PublicKey, alg, TestSetup.Base64UrlEncoder);
            string jwksJson = BuildRegisteredJwks(
                BuildRegisteredJwk(jwk, SigningKeyId),
                BuildRegisteredJwk(unrelatedJwk, UnrelatedKeyId, privateMember: "a-private-scalar-on-a-key-nobody-requested"));

            await RunPrivateKeyJwtWithKidAsync(
                signingKeys, jwksJson, alg, SigningKeyId, expectAccepted: false,
                "An unrelated element carrying private material must refuse the whole set.")
                .ConfigureAwait(false);
        }
        finally
        {
            signingKeys.PublicKey.Dispose();
            signingKeys.PrivateKey.Dispose();
            unrelatedKeys.PublicKey.Dispose();
            unrelatedKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// The positive control for the kid-less branch: a sole registered Ed25519 key with no <c>use</c>
    /// member authenticates a <c>private_key_jwt</c> assertion whose header carries no <c>kid</c> at
    /// all — <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">RFC 7517 §4.5</see> makes
    /// <c>kid</c> optional for a legitimate single-key set.
    /// </summary>
    [TestMethod]
    public async Task PrivateKeyJwtAcceptsSoleEd25519SigningKeyWithNoUseMemberWithoutKid()
    {
        var signingKeys = TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();
        try
        {
            string alg = CryptoFormatConversions.DefaultTagToJwaConverter(signingKeys.PublicKey.Tag);
            IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
                signingKeys.PublicKey, alg, TestSetup.Base64UrlEncoder);
            string jwksJson = BuildRegisteredJwks(BuildRegisteredJwk(jwk, "ed25519-sole-key-1"));

            await RunPrivateKeyJwtWithoutKidAsync(
                signingKeys, jwksJson, alg, expectAccepted: true,
                "A sole registered Ed25519 key with no use member must authenticate a kid-less assertion.")
                .ConfigureAwait(false);
        }
        finally
        {
            signingKeys.PublicKey.Dispose();
            signingKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">RFC 7517 §4.5</see> makes
    /// <c>kid</c> OPTIONAL: a kid-less assertion resolves through
    /// <see cref="JwkJsonReader.SelectSoleKey(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/> against the
    /// registered set's single <c>sig</c>-eligible entry. Marked <c>"use":"enc"</c>, that entry is no
    /// longer eligible and the assertion is refused. The selection by <c>kid</c> alone accepts this
    /// key set: it requires only that the set holds exactly one element, whatever its <c>use</c>.
    /// </summary>
    [TestMethod]
    public async Task PrivateKeyJwtRefusesEncMarkedEd25519SigningKeyWithoutKid()
    {
        var signingKeys = TestKeyMaterialProvider.CreateFreshEd25519KeyMaterial();
        try
        {
            string alg = CryptoFormatConversions.DefaultTagToJwaConverter(signingKeys.PublicKey.Tag);
            IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
                signingKeys.PublicKey, alg, TestSetup.Base64UrlEncoder);
            string jwksJson = BuildRegisteredJwks(
                BuildRegisteredJwk(jwk, "ed25519-sole-key-1", use: WellKnownJwkValues.UseEnc));

            await RunPrivateKeyJwtWithoutKidAsync(
                signingKeys, jwksJson, alg, expectAccepted: false,
                "An enc-marked sole registered key must not authenticate a kid-less assertion.")
                .ConfigureAwait(false);
        }
        finally
        {
            signingKeys.PublicKey.Dispose();
            signingKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// The set-wide refusal reaches the kid-less branch too: an UNRELATED second element carrying
    /// <c>d</c> refuses the set even though the requesting assertion carries no <c>kid</c> to narrow
    /// selection at all. The selection by <c>kid</c> alone refuses this key set too: with no
    /// <c>kid</c> to select by, it requires the set to hold exactly one element, and this one holds
    /// two.
    /// </summary>
    [TestMethod]
    public async Task PrivateKeyJwtRefusesCleanKeyBesideUnrelatedPrivateMaterialWithoutKid()
    {
        var signingKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        var unrelatedKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            string alg = CryptoFormatConversions.DefaultTagToJwaConverter(signingKeys.PublicKey.Tag);
            IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
                signingKeys.PublicKey, alg, TestSetup.Base64UrlEncoder);
            IReadOnlyDictionary<string, string> unrelatedJwk = DpopJwkUtilities.ToJwk(
                unrelatedKeys.PublicKey, alg, TestSetup.Base64UrlEncoder);
            string jwksJson = BuildRegisteredJwks(
                BuildRegisteredJwk(jwk, "clean-sole-key-1"),
                BuildRegisteredJwk(unrelatedJwk, "unrelated-key-1",
                    privateMember: "a-private-scalar-on-a-key-nobody-requested"));

            await RunPrivateKeyJwtWithoutKidAsync(
                signingKeys, jwksJson, alg, expectAccepted: false,
                "An unrelated element carrying private material must refuse a kid-less assertion too.")
                .ConfigureAwait(false);
        }
        finally
        {
            signingKeys.PublicKey.Dispose();
            signingKeys.PrivateKey.Dispose();
            unrelatedKeys.PublicKey.Dispose();
            unrelatedKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// Drives <c>private_key_jwt</c> over the real token endpoint with a <c>kid</c> header identifying
    /// <paramref name="signingKeyId"/> in <paramref name="jwksJson"/>, asserting the exchange's
    /// outcome against <paramref name="expectAccepted"/>.
    /// </summary>
    private async Task RunPrivateKeyJwtWithKidAsync(
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> signingKeys,
        string jwksJson, string alg, string signingKeyId, bool expectAccepted, string context)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;
        Uri tokenEndpoint = new(
            hosted.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, segment));

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
            AuthenticationKeyMaterial = signingKeys
        };

        //RFC 9126 §2: the pushed request now authenticates the client exactly as the token endpoint
        //does, so a key the token endpoint would refuse is refused here, before any code is issued.
        ClientAssertionOptions clientAssertionOptions = new()
        {
            SigningKeyId = signingKeyId,
            HeaderSerializer = host.Server.OAuth().Codecs.JwtHeaderSerializer!,
            PayloadSerializer = host.Server.OAuth().Codecs.JwtPayloadSerializer!
        };

        using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);

        if(!expectAccepted)
        {
            (HttpResponseData parResponse, _, _, _, _) = await AuthCodeFlowDriver.PushConfidentialParRequestAsync(
                hosted, client, registration, segment, RedirectUri, scope: null, additionalParFields: default,
                clientAssertionOptions, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(401, parResponse.StatusCode, $"{context} Body={parResponse.Body}");
            Assert.Contains(OAuthErrors.InvalidClient, parResponse.Body, StringComparison.Ordinal);

            return;
        }

        (string flowId, _) = await AuthCodeFlowDriver.DriveParAuthorizeAndCallbackAsync(
            hosted, client, registration, clientFlowStore, segment, RedirectUri, SubjectId, browserClient,
            clientAssertionOptions: clientAssertionOptions, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        AuthCodeFlowEndpointResult tokenResult = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, [], clientAssertionOptions, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
            $"{context} ErrorCode={tokenResult.ErrorCode} ErrorDescription={tokenResult.ErrorDescription}");
    }


    /// <summary>
    /// Drives <c>private_key_jwt</c> over the real token endpoint with a client assertion carrying no
    /// <c>kid</c> header, asserting the exchange's outcome against <paramref name="expectAccepted"/>.
    /// <see cref="ClientAssertionOptions.SigningKeyId"/> is required and
    /// <see cref="ClientAssertionSigning.SignAsync"/> always attaches it as <c>kid</c>, so this
    /// branch signs its own assertion directly and pushes the token-endpoint form fields rather than
    /// through <see cref="OAuthClient"/>.
    /// </summary>
    private async Task RunPrivateKeyJwtWithoutKidAsync(
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> signingKeys,
        string jwksJson, string alg, bool expectAccepted, string context)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;
        Uri tokenEndpoint = new(
            hosted.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, segment));

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync =
                PrivateKeyJwtClientAuthentication.BuildValidator(
                    additionalAcceptedAudiences: [tokenEndpoint.OriginalString]);
        }).ConfigureAwait(false);

        await DeclareServerSideAuthMethodAsync(
            host, material, ClientAuthenticationMethod.PrivateKeyJwt,
            clientJwks: jwksJson, assertionSigningAlgorithm: alg).ConfigureAwait(false);

        //RFC 9126 §2: the pushed request now authenticates the client exactly as the token
        //endpoint does. ClientAssertionOptions always attaches a kid, so a kid-less assertion is
        //signed directly (as the token-endpoint leg below already does) and pushed over the raw
        //wire rather than through OAuthClient.StartParAsync.
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, Pool);
        string parAssertion = await SignClientAssertionWithoutKidAsync(
            signingKeys.PrivateKey, ClientId, tokenEndpoint.OriginalString, TimeProvider.GetUtcNow(),
            host.Server.OAuth().Codecs.JwtHeaderSerializer!, host.Server.OAuth().Codecs.JwtPayloadSerializer!,
            TestContext.CancellationToken).ConfigureAwait(false);

        Dictionary<string, string> parFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.ClientAssertionType] = WellKnownClientAssertionTypes.JwtBearer,
            [OAuthRequestParameterNames.ClientAssertion] = parAssertion
        };

        (int parStatusCode, string parBody) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, segment, parFields, TestContext.CancellationToken).ConfigureAwait(false);

        if(!expectAccepted)
        {
            Assert.AreEqual(401, parStatusCode, $"{context} Body={parBody}");
            Assert.Contains(OAuthErrors.InvalidClient, parBody, StringComparison.Ordinal);

            return;
        }

        Assert.AreEqual(201, parStatusCode, $"{context} Body={parBody}");
        string requestUri = JsonElement.Parse(parBody).GetProperty(OAuthRequestParameterNames.RequestUri).GetString()
            ?? throw new InvalidOperationException("PAR response missing request_uri.");

        Uri authorizeUrl = new(
            hosted.HttpBaseAddress!,
            $"{TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, segment)}" +
            $"?{OAuthRequestParameterNames.ClientId}={Uri.EscapeDataString(ClientId)}" +
            $"&{OAuthRequestParameterNames.RequestUri}={Uri.EscapeDataString(requestUri)}");

        using HttpResponseMessage authorizeResponse = await RawAuthCodeWirePushers.SendPinnedNoRedirectGetAsync(
            host, authorizeUrl, SubjectId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, (int)authorizeResponse.StatusCode,
            "The authorize endpoint must redirect with the authorization code.");
        string code = TestBrowser.ExtractQueryParam(authorizeResponse.Headers.Location!.ToString(), OAuthRequestParameterNames.Code)
            ?? throw new InvalidOperationException("Authorize redirect Location missing code.");

        string tokenAssertion = await SignClientAssertionWithoutKidAsync(
            signingKeys.PrivateKey, ClientId, tokenEndpoint.OriginalString, TimeProvider.GetUtcNow(),
            host.Server.OAuth().Codecs.JwtHeaderSerializer!, host.Server.OAuth().Codecs.JwtPayloadSerializer!,
            TestContext.CancellationToken).ConfigureAwait(false);

        Dictionary<string, string> fields = RawAuthCodeWirePushers.BuildTokenFields(
            ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString);
        fields[OAuthRequestParameterNames.ClientAssertionType] = WellKnownClientAssertionTypes.JwtBearer;
        fields[OAuthRequestParameterNames.ClientAssertion] = tokenAssertion;

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, fields, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, StatusCode, $"{context} Body={Body}");
    }


    /// <summary>
    /// Signs a <c>private_key_jwt</c> client assertion (RFC 7523 §2.2/§3) whose protected header
    /// carries no <c>kid</c> — the shape the server resolves through
    /// <see cref="JwkJsonReader.SelectSoleKey(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/> rather than by
    /// key identifier.
    /// </summary>
    private static async Task<string> SignClientAssertionWithoutKidAsync(
        PrivateKeyMemory signingKey, string clientId, string audience, DateTimeOffset now,
        JwtHeaderSerializer headerSerializer, JwtPayloadSerializer payloadSerializer,
        CancellationToken cancellationToken)
    {
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);
        JwtHeader header = new(capacity: 2)
        {
            [WellKnownJwkMemberNames.Alg] = algorithm,
            [WellKnownJoseHeaderNames.Typ] = WellKnownJwkValues.TypeJwt
        };
        JwtPayload payload = new(capacity: 6)
        {
            [WellKnownJwtClaimNames.Iss] = clientId,
            [WellKnownJwtClaimNames.Sub] = clientId,
            [WellKnownJwtClaimNames.Aud] = audience,
            [WellKnownJwtClaimNames.Jti] = $"assertion-{Guid.NewGuid():N}",
            [WellKnownJwtClaimNames.Iat] = now.ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Exp] = now.AddMinutes(1).ToUnixTimeSeconds()
        };

        UnsignedJwt unsigned = new(header, payload);
        using JwsMessage jws = await unsigned.SignAsync(
            signingKey, headerSerializer, payloadSerializer, TestSetup.Base64UrlEncoder, Pool, cancellationToken)
            .ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(jws, TestSetup.Base64UrlEncoder);
    }


    /// <summary>
    /// Builds one registered JWK's members from <paramref name="jwk"/>, adding <paramref name="kid"/>
    /// and, when supplied, a <c>use</c> member and a fabricated private-scalar member — the shape the
    /// <c>use</c>-eligibility and set-wide private-material real-wire tests publish as
    /// <see cref="ClientRecord.ClientJwks"/>.
    /// </summary>
    private static Dictionary<string, object> BuildRegisteredJwk(
        IReadOnlyDictionary<string, string> jwk, string kid, string? use = null, string? privateMember = null)
    {
        Dictionary<string, object> jwkObject = new(StringComparer.Ordinal);
        foreach(KeyValuePair<string, string> member in jwk)
        {
            jwkObject[member.Key] = member.Value;
        }

        jwkObject[WellKnownJwkMemberNames.Kid] = kid;
        if(use is not null)
        {
            jwkObject[WellKnownJwkMemberNames.Use] = use;
        }

        if(privateMember is not null)
        {
            jwkObject[WellKnownJwkMemberNames.D] = privateMember;
        }

        return jwkObject;
    }


    /// <summary>Serialises <paramref name="keys"/> as a JWK Set document — <see cref="ClientRecord.ClientJwks"/>'s wire shape.</summary>
    private static string BuildRegisteredJwks(params Dictionary<string, object>[] keys)
    {
        Dictionary<string, object> jwksObject = new(StringComparer.Ordinal)
        {
            [WellKnownJwkMemberNames.Keys] = keys.Cast<object>().ToArray()
        };

        return JsonSerializer.Serialize(jwksObject, TestSetup.DefaultSerializationOptions);
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
            using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
                ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

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


            //The validator consults the shared (issuer, jti) guard on the assertion's jti, so a store
            //that cannot prove it recorded the jti fails the assertion closed.
            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.ValidateClientCredentialsAsync =
                    PrivateKeyJwtClientAuthentication.BuildValidator(
                        additionalAcceptedAudiences: [tokenEndpoint.OriginalString],
                        checkJtiReplayAsync: JtiReplayGuard.ConsultAsync);
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

            ClientAssertionOptions clientAssertionOptions = new()
            {
                SigningKeyId = SigningKeyId,
                HeaderSerializer = host.Server.OAuth().Codecs.JwtHeaderSerializer!,
                PayloadSerializer = host.Server.OAuth().Codecs.JwtPayloadSerializer!
            };

            using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
            (string flowId, _) = await AuthCodeFlowDriver.DriveParAuthorizeAndCallbackAsync(
                hosted, client, registration, clientFlowStore, segment, RedirectUri, SubjectId, browserClient,
                clientAssertionOptions: clientAssertionOptions, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            await HalfWireJtiReplayStoreAsync(host.Server).ConfigureAwait(false);

            AuthCodeFlowEndpointResult tokenResult = await client.AuthCode.ExchangeTokenAsync(
                registration, flowId, [], clientAssertionOptions, TestContext.CancellationToken).ConfigureAwait(false);

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
    private static async Task HalfWireJtiReplayStoreAsync(EndpointServer server)
    {
        ResolveCorrelationKeyDelegate original = server.OAuth().ResolveCorrelationKeyAsync!;
        await TestHostShell.AlterAsync(server, candidateIntegration =>
        {
            candidateIntegration.ResolveCorrelationKeyAsync = (tenantId, flowKind, externalHandle, ctx, ct) =>
                flowKind == FlowKind.JtiReplay
                    ? ValueTask.FromResult<string?>(null)
                    : original(tenantId, flowKind, externalHandle, ctx, ct);
        }).ConfigureAwait(false);
    }


    /// <summary>
    /// Every declared confidential method fails closed without the credential the client would
    /// normally attach automatically — pinning that the positive tests above prove genuine
    /// authentication rather than a server that never checks. Uses <c>client_secret_post</c>: a
    /// declared confidential client whose <see cref="ClientRegistration.AuthenticationMethod"/> stays
    /// <see cref="ClientAuthenticationMethod.None"/> presents no credential at all, so the pushed
    /// request itself is refused per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2">RFC 9126 §2</see>, before any
    /// code can ever be issued.
    /// </summary>
    [TestMethod]
    public async Task DeclaredConfidentialClientWithoutAttachedCredentialFailsClosedAtThePushedRequest()
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
        //AuthenticationMethod deliberately left at its None default — the client attaches nothing.
        _ = clientFlowStore;

        AuthCodeFlowEndpointResult parResult = await client.AuthCode.StartParAsync(
            registration, RedirectUri, OAuthFormEncodedFields.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreNotEqual(AuthCodeFlowEndpointOutcome.Redirect, parResult.Outcome,
            "A declared confidential client presenting no credential must not be pushed.");
        Assert.AreEqual(OAuthErrors.InvalidClient, parResult.ErrorCode);
    }


    /// <summary>
    /// RFC 7523 §3.1: "if client credentials are present in the request, the authorization server
    /// MUST validate them." <see cref="ClientRecord.TokenEndpointAuthMethod"/> is deliberately left
    /// UNDECLARED (<see cref="DeclareServerSideAuthMethodAsync"/> is never called) — before this fix,
    /// <c>RequireClientAuthenticationIfDeclaredAsync</c>'s null/None branch returned success
    /// immediately without ever consulting whether a credential was attached, so a WRONG
    /// <c>client_secret</c> on an undeclared-method registration was silently ignored and the token
    /// was minted anyway. The client here attaches a <c>client_secret_post</c> credential that does
    /// NOT match what the validator seam accepts, so the pushed request itself must be refused
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9126#section-2">RFC 9126 §2</see>) and no code
    /// ever issued.
    /// </summary>
    [TestMethod]
    public async Task PresentedWrongSecretOnUndeclaredMethodFailsClosedAtThePushedRequest()
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
            registration = registration with
            {
                AuthenticationMethod = ClientAuthenticationMethod.ClientSecretPost,
                AuthenticationKeyMaterial = wrongSecretMaterial
            };
            _ = clientFlowStore;

            await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
            HostedAuthorizationServer hosted = host.Host("default");
            string segment = material.Registration.TenantId.Value;

            (HttpResponseData parResponse, _, _, _, _) = await AuthCodeFlowDriver.PushConfidentialParRequestAsync(
                hosted, client, registration, segment, RedirectUri, scope: null, additionalParFields: default,
                clientAssertionOptions: null, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(401, parResponse.StatusCode, parResponse.Body);
            Assert.Contains(OAuthErrors.InvalidClient, parResponse.Body, StringComparison.Ordinal);
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
    /// <see cref="DeclareServerSideAuthMethodAsync"/> is never called, proving the token is minted on the
    /// strength of the validated credential alone, with no server-side declaration in play.
    /// </summary>
    [TestMethod]
    public async Task PresentedCorrectSecretOnUndeclaredMethodAuthenticates()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> secretMaterial = BuildSecretKeyMaterial(ClientSecret);
        try
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
                ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
            //TokenEndpointAuthMethod deliberately left unset (null) — no DeclareServerSideAuthMethod call.

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
    /// §3.1's "MUST validate them" cannot be satisfied by an absent validator, so the pushed request
    /// itself fails closed (<see href="https://www.rfc-editor.org/rfc/rfc9126#section-2">RFC 9126
    /// §2</see>) rather than silently proceeding as if the credential were never presented.
    /// </summary>
    [TestMethod]
    public async Task PresentedCredentialWithUnwiredValidatorOnUndeclaredMethodFailsClosedAtThePushedRequest()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> secretMaterial = BuildSecretKeyMaterial(ClientSecret);
        try
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
                ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
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
            _ = clientFlowStore;

            await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
            HostedAuthorizationServer hosted = host.Host("default");
            string segment = material.Registration.TenantId.Value;

            (HttpResponseData parResponse, _, _, _, _) = await AuthCodeFlowDriver.PushConfidentialParRequestAsync(
                hosted, client, registration, segment, RedirectUri, scope: null, additionalParFields: default,
                clientAssertionOptions: null, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(401, parResponse.StatusCode, parResponse.Body);
            Assert.Contains(OAuthErrors.InvalidClient, parResponse.Body, StringComparison.Ordinal);
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
    /// Drives a real <c>client_assertion</c>, signed by a fresh key, against a registered
    /// <c>ClientJwks</c> that <paramref name="malformKeySet"/> corrupts from an otherwise
    /// well-formed set, and asserts the token endpoint refuses with RFC 6749 §5.2
    /// <c>invalid_client</c> — the same "no usable key" outcome the path already gives for a null
    /// <see cref="ClientRecord.ClientJwks"/>. RFC 8259 §2, §4 (consumer feedback 38, 39): a set that
    /// is not one well-formed JSON document with unique member names must not authenticate a client
    /// under a key its own validation never judged, or that could not even be read.
    /// </summary>
    private async Task RunMalformedRegisteredKeySetFailsClosedAsync(Func<string, string> malformKeySet)
    {
        var clientKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
                ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

            await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
            HostedAuthorizationServer hosted = host.Host("default");
            string segment = material.Registration.TenantId.Value;
            Uri tokenEndpoint = new(
                hosted.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, segment));

            string alg = CryptoFormatConversions.DefaultTagToJwaConverter(clientKeys.PublicKey.Tag);
            const string SigningKeyId = "confidential-client-key-1";
            IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
                clientKeys.PublicKey, alg, TestSetup.Base64UrlEncoder);
            string wellFormedJwksJson = BuildJwksJson(jwk, SigningKeyId);
            string malformedJwksJson = malformKeySet(wellFormedJwksJson);

            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.ValidateClientCredentialsAsync =
                    PrivateKeyJwtClientAuthentication.BuildValidator(
                        additionalAcceptedAudiences: [tokenEndpoint.OriginalString]);
            }).ConfigureAwait(false);

            await DeclareServerSideAuthMethodAsync(
                host, material, ClientAuthenticationMethod.PrivateKeyJwt,
                clientJwks: malformedJwksJson, assertionSigningAlgorithm: alg).ConfigureAwait(false);

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
            _ = clientFlowStore;

            //RFC 9126 §2: the pushed request now runs the SAME assertion validator, so a malformed
            //registered key set fails closed here too, before any code can ever be issued.
            (HttpResponseData parResponse, _, _, _, _) = await AuthCodeFlowDriver.PushConfidentialParRequestAsync(
                hosted, client, registration, segment, RedirectUri, scope: null, additionalParFields: default,
                new ClientAssertionOptions
                {
                    SigningKeyId = SigningKeyId,
                    HeaderSerializer = host.Server.OAuth().Codecs.JwtHeaderSerializer!,
                    PayloadSerializer = host.Server.OAuth().Codecs.JwtPayloadSerializer!
                },
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(401, parResponse.StatusCode,
                $"A malformed registered key set must not authenticate the client. Key set: {malformedJwksJson}");
            Assert.Contains(OAuthErrors.InvalidClient, parResponse.Body, StringComparison.Ordinal,
                "RFC 8259 §2/§4: a registered key set that is not one well-formed JSON document with " +
                $"unique member names must fail closed as invalid_client. Key set: {malformedJwksJson}, " +
                $"Body: {parResponse.Body}");
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// Two <c>keys</c> members at the top level (RFC 8259 §4), the real key FIRST and an empty array
    /// second — the shape a first-match scan (without the gate) actually authenticates under, since it
    /// finds the real key before ever seeing the second, empty array.
    /// </summary>
    [TestMethod]
    public async Task PrivateKeyJwtFailsClosedWhenRegisteredKeySetHasTwoKeysMembers() =>
        await RunMalformedRegisteredKeySetFailsClosedAsync(
            jwksJson => jwksJson[..^1] + ",\"keys\":[]}").ConfigureAwait(false);


    /// <summary>A key object carrying two <c>kid</c> members (RFC 8259 §4) — kid selection must not resolve by position.</summary>
    [TestMethod]
    public async Task PrivateKeyJwtFailsClosedWhenRegisteredKeyObjectHasTwoKidMembers() =>
        await RunMalformedRegisteredKeySetFailsClosedAsync(
            jwksJson => jwksJson[..^3] + ",\"kid\":\"wrong-key-id\"" + jwksJson[^3..]).ConfigureAwait(false);


    /// <summary>A name repeated through a <c>\u</c> escape (RFC 8259 §4/§7) — names compare by decoded value.</summary>
    [TestMethod]
    public async Task PrivateKeyJwtFailsClosedWhenRegisteredKeySetHasANameDuplicatedThroughAnEscape() =>
        await RunMalformedRegisteredKeySetFailsClosedAsync(
            jwksJson => jwksJson[..^3] + ",\"\\u006bid\":\"wrong-key-id\"" + jwksJson[^3..]).ConfigureAwait(false);


    /// <summary>A set truncated before its final brace (RFC 8259 §2) is not one well-formed JSON value.</summary>
    [TestMethod]
    public async Task PrivateKeyJwtFailsClosedWhenRegisteredKeySetIsTruncatedBeforeItsFinalBrace() =>
        await RunMalformedRegisteredKeySetFailsClosedAsync(
            jwksJson => jwksJson[..^1]).ConfigureAwait(false);


    /// <summary>Trailing bytes after the value (RFC 8259 §2) — only insignificant whitespace may follow it.</summary>
    [TestMethod]
    public async Task PrivateKeyJwtFailsClosedWhenRegisteredKeySetHasTrailingBytesAfterTheValue() =>
        await RunMalformedRegisteredKeySetFailsClosedAsync(
            jwksJson => jwksJson + "x").ConfigureAwait(false);


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
    /// A mutable call counter a test closure increments — used to prove whether the shared
    /// <c>(issuer, jti)</c> correlation store was consulted for a given presentation.
    /// </summary>
    private sealed class CallCounter
    {
        /// <summary>The number of times the wrapped delegate ran.</summary>
        public int Count { get; set; }
    }


    /// <summary>
    /// Wraps the host's <c>jti</c> correlation resolver so a recorded entry whose
    /// <see cref="Verifiable.Server.FlowState.ExpiresAt"/> lies at or before
    /// <paramref name="timeProvider"/>'s current instant is reported ABSENT — the shape of an
    /// application store that expires entries on read, unlike
    /// <see cref="HostedAuthorizationServer.JtiIndex"/>, which never forgets. Every other
    /// correlation kind resolves through the host's real delegate unchanged.
    /// <paramref name="jtiReplayResolveCount"/> counts every <see cref="JtiReplayFlowKind"/>
    /// consultation, resolved or not, so a test can prove a presentation never reached the guard.
    /// </summary>
    private static async Task ExpireJtiEntriesPastTheirRecordedWindowAsync(
        EndpointServer server, HostedAuthorizationServer hosted, TimeProvider timeProvider, CallCounter jtiReplayResolveCount)
    {
        ResolveCorrelationKeyDelegate original = server.OAuth().ResolveCorrelationKeyAsync!;
        await TestHostShell.AlterAsync(server, candidateIntegration =>
        {
            candidateIntegration.ResolveCorrelationKeyAsync = async (tenantId, flowKind, externalHandle, ctx, ct) =>
            {
                if(flowKind != FlowKind.JtiReplay)
                {
                    return await original(tenantId, flowKind, externalHandle, ctx, ct).ConfigureAwait(false);
                }

                jtiReplayResolveCount.Count++;
                string? flowId = await original(tenantId, flowKind, externalHandle, ctx, ct).ConfigureAwait(false);

                return flowId is not null
                    && hosted.FlowStates.TryGetValue(flowId, out var entry)
                    && entry.State is JtiSeenState seen
                    && seen.ExpiresAt <= timeProvider.GetUtcNow()
                        ? null
                        : flowId;
            };
        }).ConfigureAwait(false);
    }


    /// <summary>
    /// The HTTP-backed counterpart to <see cref="TestHostShell.CreateOAuthClientAndRegistrationAsync"/>
    /// with one addition: <paramref name="decorateSendFormPostAsync"/> lets a test capture or rewrite
    /// the form fields of one outgoing POST — here, to re-present a <c>private_key_jwt</c> client
    /// assertion verbatim on a later call — while every other request still reaches
    /// <see cref="HttpClientTransport"/> unchanged. Built locally, mirroring
    /// <see cref="TestHostShell.CreateInProcessOAuthClientAndRegistration"/>'s own
    /// <c>decorateSendFormPostAsync</c> seam for the in-process transport, so no existing caller of
    /// the HTTP-backed factory changes shape.
    /// </summary>
    private static (OAuthClient Client, ClientRegistration Registration, Dictionary<string, FlowState> ClientFlowStore)
        CreateInterceptingOAuthClientAndRegistration(
            TestHostShell host,
            HostedAuthorizationServer hosted,
            ClientRecord record,
            string redirectUri,
            PolicyProfile profile,
            TimeProvider timeProvider,
            Func<SendFormPostDelegate, SendFormPostDelegate> decorateSendFormPostAsync)
    {
        ClientRecord alignedRecord = host.AlignRegistrationToHostHttpBase("default", record);
        Dictionary<string, FlowState> clientFlowStore = [];
        string segment = alignedRecord.TenantId.Value;
        Uri baseUri = hosted.HttpBaseAddress!;
        Uri parEndpoint = new(baseUri, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodePar, segment));
        Uri authEndpoint = new(baseUri, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, segment));
        Uri tokenEndpoint = new(baseUri, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, segment));
        Uri revocationEndpoint = new(baseUri, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeRevoke, segment));
        Uri issuerUriValue = alignedRecord.IssuerUri!;

        AuthorizationServerMetadata metadata = new()
        {
            Issuer = issuerUriValue,
            PushedAuthorizationRequestEndpoint = parEndpoint,
            AuthorizationEndpoint = authEndpoint,
            TokenEndpoint = tokenEndpoint,
            RevocationEndpoint = revocationEndpoint
        };

        HttpClient httpClient = hosted.SharedHttpClient!;

        ValueTask<HttpResponseData> BaseSendFormPostAsync(
            Uri endpoint, IReadOnlyCollection<KeyValuePair<string, string>> fields, OutgoingHeaders headers, ExchangeContext context, CancellationToken ct) =>
            HttpClientTransport.SendFormPostAsync(httpClient, endpoint, fields, headers, ct);

        FillEntropyDelegate entropy = TestEntropy.NewCounterStream();

        OAuthClientInfrastructure infrastructure = OAuthClientInfrastructure.Create(
            sendFormPostAsync: decorateSendFormPostAsync(BaseSendFormPostAsync),
            saveStateAsync: (state, _, ct) =>
            {
                clientFlowStore[state.FlowId] = state;

                return ValueTask.CompletedTask;
            },
            loadStateAsync: (flowId, _, ct) =>
                ValueTask.FromResult(clientFlowStore.GetValueOrDefault(flowId)),
            loadStateByRequestUriAsync: (requestUri, _, ct) =>
            {
                foreach(FlowState state in clientFlowStore.Values)
                {
                    if(state is ParCompletedState pc
                        && string.Equals(pc.Par.RequestUri.ToString(), requestUri, StringComparison.Ordinal))
                    {
                        return ValueTask.FromResult<FlowState?>(state);
                    }
                }

                return ValueTask.FromResult<FlowState?>(null);
            },
            parseParResponseAsync: OAuthResponseParsers.ParseParResponse,
            parseTokenResponseAsync: OAuthResponseParsers.ParseTokenResponse,
            parseRegistrationResponseAsync: (body, ct) =>
                throw new NotImplementedException("Test does not exercise dynamic registration."),
            resolveAuthorizationServerMetadataAsync: (issuer, context, ct) =>
                ValueTask.FromResult(new AuthorizationServerMetadataResolution
                {
                    Outcome = AuthorizationServerMetadataResolutionOutcome.Resolved,
                    Metadata = metadata
                }),
            resolveCallbackValidator: ClientPolicyProfiles.DefaultResolveCallbackValidator,
            base64UrlEncoder: TestSetup.Base64UrlEncoder,
            memoryPool: BaseMemoryPool.Shared,
            timeProvider: timeProvider,
            fillEntropy: entropy,
            generateIdentifierAsync: DefaultIdentifierGenerator.For(timeProvider, entropy, BaseMemoryPool.Shared),
            outboundFetchPolicy: TestHostShell.LoopbackOutboundFetchPolicy);

        ClientRegistration registration = new()
        {
            ClientId = new ClientId(alignedRecord.ClientId),
            AuthorizationServerIssuer = issuerUriValue,
            RedirectUris = [new Uri(redirectUri)],
            AuthenticationMethod = ClientAuthenticationMethod.None,
            Profile = profile
        };

        return (new OAuthClient(infrastructure), registration, clientFlowStore);
    }


    /// <summary>
    /// RFC 7523 §3 rule 7: "the authorization server MAY ensure that JWTs are not replayed by
    /// maintaining the set of used jti values for the length of time for which the JWT would be
    /// considered valid based on the applicable exp instant"
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523, Section 3</see>) — the
    /// instant a <c>private_key_jwt</c> client assertion is considered valid until is its <c>exp</c>
    /// PLUS the exchange's clock-skew tolerance (<see cref="PrivateKeyJwtClientAuthentication"/>'s
    /// timing check keeps accepting the assertion until then), not the bare <c>exp</c>. A store that
    /// expires a recorded entry on read (an application store with expiry) must therefore see the
    /// entry held open until <c>exp</c> plus the tolerance, or the SAME assertion authenticates a
    /// second time inside the very grace period the timing check still honours it under. Past
    /// <c>exp</c> plus the tolerance the assertion is refused by the timing check itself — proved
    /// here by the replay guard never being consulted a second time.
    /// </summary>
    [TestMethod]
    public async Task ReplayedPrivateKeyJwtAssertionWithinClockSkewToleranceIsRefusedAsInvalidClient()
    {
        var clientKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
                ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

            await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
            HostedAuthorizationServer hosted = host.Host("default");
            string segment = material.Registration.TenantId.Value;
            Uri tokenEndpoint = new(
                hosted.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, segment));

            string alg = CryptoFormatConversions.DefaultTagToJwaConverter(clientKeys.PublicKey.Tag);
            const string SigningKeyId = "replay-window-key-1";
            IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
                clientKeys.PublicKey, alg, TestSetup.Base64UrlEncoder);
            string jwksJson = BuildJwksJson(jwk, SigningKeyId);

            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.ValidateClientCredentialsAsync =
                    PrivateKeyJwtClientAuthentication.BuildValidator(
                        additionalAcceptedAudiences: [tokenEndpoint.OriginalString],
                        checkJtiReplayAsync: JtiReplayGuard.ConsultAsync);
            }).ConfigureAwait(false);

            await DeclareServerSideAuthMethodAsync(
                host, material, ClientAuthenticationMethod.PrivateKeyJwt,
                clientJwks: jwksJson, assertionSigningAlgorithm: alg).ConfigureAwait(false);

            CallCounter jtiReplayResolveCount = new();
            await ExpireJtiEntriesPastTheirRecordedWindowAsync(
                host.Server, hosted, TimeProvider, jtiReplayResolveCount).ConfigureAwait(false);

            string? capturedAssertion = null;
            string? injectedAssertion = null;
            (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
                CreateInterceptingOAuthClientAndRegistration(
                    host, hosted, material.Registration, RedirectUri.OriginalString,
                    PolicyProfile.Rfc6749WithPkce, TimeProvider,
                    baseSendFormPostAsync => (endpoint, fields, headers, contentType, ct) =>
                    {
                        if(injectedAssertion is not null
                            && fields is OutgoingFormFields mutableFields
                            && fields.Any(field => string.Equals(field.Key, OAuthRequestParameterNames.ClientAssertion, StringComparison.Ordinal)))
                        {
                            mutableFields[OAuthRequestParameterNames.ClientAssertion] = injectedAssertion;
                        }
                        else if(fields.FirstOrDefault(field =>
                                string.Equals(field.Key, OAuthRequestParameterNames.ClientAssertion, StringComparison.Ordinal))
                            .Value is { } assertion)
                        {
                            capturedAssertion = assertion;
                        }

                        return baseSendFormPostAsync(endpoint, fields, headers, contentType, ct);
                    });
            registration = registration with
            {
                AuthenticationMethod = ClientAuthenticationMethod.PrivateKeyJwt,
                AuthenticationKeyMaterial = clientKeys
            };

            using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
            ClientAssertionOptions assertionOptions = new()
            {
                SigningKeyId = SigningKeyId,
                HeaderSerializer = host.Server.OAuth().Codecs.JwtHeaderSerializer!,
                PayloadSerializer = host.Server.OAuth().Codecs.JwtPayloadSerializer!,
                ClientAssertionLifetime = TimeSpan.FromSeconds(10)
            };

            //First presentation: a fresh assertion, exp = now + 10s. Recorded and accepted. The
            //pushed request signs its OWN fresh assertion too (RFC 9126 §2), a first use of a jti
            //distinct from the token leg's.
            (string flowId1, _) = await AuthCodeFlowDriver.DriveParAuthorizeAndCallbackAsync(
                hosted, client, registration, clientFlowStore, segment, RedirectUri, SubjectId, browserClient,
                clientAssertionOptions: assertionOptions, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            AuthCodeFlowEndpointResult firstResult = await client.AuthCode.ExchangeTokenAsync(
                registration, flowId1, [], clientAssertionOptions: assertionOptions, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, firstResult.Outcome,
                $"The first, fresh presentation must authenticate. ErrorCode={firstResult.ErrorCode} ErrorDescription={firstResult.ErrorDescription}");
            Assert.IsNotNull(capturedAssertion, "The client must have attached a client_assertion on the first exchange.");

            //ValidateClientCredentialsDelegate returns a bare bool, so the wire's invalid_client
            //never distinguishes WHY authentication failed. The number of store consultations is the
            //oracle instead: a presentation the guard recognises as a replay on the record it already
            //holds needs exactly ONE resolve (the read that finds it still open, returned as
            //Replayed). A presentation the guard wrongly treats as a first use needs TWO (the
            //miss-triggering read, then the post-save self-check read that discovers the record it
            //just re-wrote under the SAME key already expired) — the guard's own defence against a
            //defective store trips on its own re-save, surfacing as invalid_client either way, but
            //the consultation count tells the two apart.
            int resolveCountAfterFirst = jtiReplayResolveCount.Count;

            //40s later: past exp (10s) but well inside the default 60s clock-skew tolerance — the
            //timing check still accepts the assertion. Re-present the SAME assertion for a SECOND,
            //distinct authorization code.
            TimeProvider.Advance(TimeSpan.FromSeconds(40));
            (string flowId2, _) = await AuthCodeFlowDriver.DriveParAuthorizeAndCallbackAsync(
                hosted, client, registration, clientFlowStore, segment, RedirectUri, SubjectId, browserClient,
                clientAssertionOptions: assertionOptions, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            injectedAssertion = capturedAssertion;
            AuthCodeFlowEndpointResult replayResult = await client.AuthCode.ExchangeTokenAsync(
                registration, flowId2, [], clientAssertionOptions: assertionOptions, TestContext.CancellationToken).ConfigureAwait(false);

            //The pushed request's OWN fresh assertion (RFC 9126 §2) is a first use of a jti distinct
            //from the token leg's, adding its own two consultations (the miss-triggering read and the
            //post-save self-check) ahead of the token leg's single replay-detecting resolve.
            Assert.AreEqual(resolveCountAfterFirst + 3, jtiReplayResolveCount.Count,
                "RFC 7523 §3 rule 7: a presentation still inside the recorded window must be recognised as a " +
                "replay by the FIRST resolve alone (exactly one more consultation) beyond the pushed request's " +
                "own first-use pair — a different count means the guard wrongly treated the token leg's " +
                "presentation as a first use too.");
            Assert.AreNotEqual(AuthCodeFlowEndpointOutcome.Ok, replayResult.Outcome,
                "RFC 7523 §3 rule 7: the SAME assertion presented again inside the exp+skew window it is still valid under must be refused.");
            Assert.AreEqual(OAuthErrors.InvalidClient, replayResult.ErrorCode);

            int resolveCountAfterReplay = jtiReplayResolveCount.Count;

            //A further 40s later (80s total): past exp (10s) PLUS the 60s tolerance (70s) — the
            //timing check itself now refuses the assertion, before the jti guard is ever consulted.
            TimeProvider.Advance(TimeSpan.FromSeconds(40));
            (string flowId3, _) = await AuthCodeFlowDriver.DriveParAuthorizeAndCallbackAsync(
                hosted, client, registration, clientFlowStore, segment, RedirectUri, SubjectId, browserClient,
                clientAssertionOptions: assertionOptions, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            AuthCodeFlowEndpointResult expiredResult = await client.AuthCode.ExchangeTokenAsync(
                registration, flowId3, [], clientAssertionOptions: assertionOptions, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreNotEqual(AuthCodeFlowEndpointOutcome.Ok, expiredResult.Outcome,
                "Past exp plus the clock-skew tolerance the assertion must be refused.");
            Assert.AreEqual(OAuthErrors.InvalidClient, expiredResult.ErrorCode);
            //The pushed request's own fresh assertion is again a first use (its own two
            //consultations); the EXPIRED token-leg assertion itself adds none, refused by the
            //timing check before the jti guard is ever consulted.
            Assert.AreEqual(resolveCountAfterReplay + 2, jtiReplayResolveCount.Count,
                "Past exp plus the tolerance the token-leg assertion must be refused as EXPIRED by the timing check before the jti guard is ever consulted — not as a replay.");
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// A confidential registration's wrong <c>client_secret_basic</c> secret at CODE REDEMPTION:
    /// the endpoint's pre-correlation step authenticates the declared method before the presented
    /// <c>code</c> is ever looked up, so an unknown code and a live one answer byte-identically —
    /// <c>401 invalid_client</c> with the <c>WWW-Authenticate: Basic</c> challenge. A presented
    /// <c>client_id</c> naming a registration other than this tenant's own is identification, not
    /// authentication, and never reaches this answer at all — it is refused with the code
    /// endpoint's own not-found constant instead. The live code is unconsumed: it still
    /// redeems with the correct secret afterward.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 §5.2</see>.
    /// </summary>
    [TestMethod]
    public async Task WrongBasicSecretAtCodeRedemptionAnswersTheSameBodyForAnUnknownAndALiveCodeAsync()
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
                    material.Registration, RedirectUri.OriginalString, profile: PolicyProfile.Rfc6749WithPkce,
                    TestContext.CancellationToken).ConfigureAwait(false);
            registration = registration with
            {
                AuthenticationMethod = ClientAuthenticationMethod.ClientSecretBasic,
                AuthenticationKeyMaterial = secretMaterial
            };

            using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
            HostedAuthorizationServer hosted = host.Host("default");
            string segment = material.Registration.TenantId.Value;

            (string flowId, _) = await AuthCodeFlowDriver.DriveParAuthorizeAndCallbackAsync(
                hosted, client, registration, clientFlowStore, segment, RedirectUri, SubjectId,
                browserClient, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            AuthorizationCodeReceivedState callbackState = (AuthorizationCodeReceivedState)clientFlowStore[flowId];

            Uri tokenUri = RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, segment);
            OutgoingHeaders wrongSecretHeaders = OutgoingHeaders.Empty.WithClientSecretBasic(
                ClientId, Encoding.UTF8.GetBytes(WrongClientSecret));

            Dictionary<string, string> liveFields = RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, callbackState.Code, callbackState.Pkce.EncodedVerifier, callbackState.RedirectUri.OriginalString);
            HttpResponseData liveResponse = await HttpClientTransport.SendFormPostAsync(
                hosted.SharedHttpClient!, tokenUri, liveFields, wrongSecretHeaders, TestContext.CancellationToken).ConfigureAwait(false);

            Dictionary<string, string> unknownFields = RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, "unknown-authorization-code-value", callbackState.Pkce.EncodedVerifier, callbackState.RedirectUri.OriginalString);
            HttpResponseData unknownResponse = await HttpClientTransport.SendFormPostAsync(
                hosted.SharedHttpClient!, tokenUri, unknownFields, wrongSecretHeaders, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(401, liveResponse.StatusCode, liveResponse.Body);
            Assert.Contains(OAuthErrors.InvalidClient, liveResponse.Body, StringComparison.Ordinal);
            string? liveChallenge = liveResponse.Headers.TryGetSingle(WellKnownHttpHeaderNames.WwwAuthenticate);
            Assert.AreEqual(WellKnownAuthenticationSchemes.Basic, liveChallenge);
            Assert.AreEqual(liveResponse.StatusCode, unknownResponse.StatusCode);
            Assert.AreEqual(liveResponse.Body, unknownResponse.Body,
                "An unknown code and a live one must answer byte-identically for a wrong Basic secret.");
            Assert.AreEqual(liveChallenge, unknownResponse.Headers.TryGetSingle(WellKnownHttpHeaderNames.WwwAuthenticate));

            //A client_id naming a registration other than this tenant's own is identification, never
            //authentication — it answers the not-found constant, never invalid_client, at either
            //continuing grant.
            Dictionary<string, string> foreignClientIdFields = RawAuthCodeWirePushers.BuildTokenFields(
                "https://not-this-registration.example.com", callbackState.Code, callbackState.Pkce.EncodedVerifier,
                callbackState.RedirectUri.OriginalString);
            HttpResponseData foreignResponse = await HttpClientTransport.SendFormPostAsync(
                hosted.SharedHttpClient!, tokenUri, foreignClientIdFields, wrongSecretHeaders, TestContext.CancellationToken)
                .ConfigureAwait(false);
            Assert.AreEqual(400, foreignResponse.StatusCode, foreignResponse.Body);
            Assert.Contains(OAuthErrors.InvalidGrant, foreignResponse.Body, StringComparison.Ordinal);
            Assert.IsFalse(foreignResponse.Body.Contains(OAuthErrors.InvalidClient, StringComparison.Ordinal),
                "A client_id naming a foreign registration must never answer invalid_client at code redemption.");

            //The live code is unconsumed: it still redeems with the correct secret.
            OutgoingHeaders rightSecretHeaders = OutgoingHeaders.Empty.WithClientSecretBasic(
                ClientId, Encoding.UTF8.GetBytes(ClientSecret));
            HttpResponseData redemption = await HttpClientTransport.SendFormPostAsync(
                hosted.SharedHttpClient!, tokenUri, liveFields, rightSecretHeaders, TestContext.CancellationToken)
                .ConfigureAwait(false);
            Assert.AreEqual(200, redemption.StatusCode, redemption.Body);
        }
        finally
        {
            secretMaterial.PublicKey.Dispose();
            secretMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// A confidential registration presenting NO credentials at all at CODE REDEMPTION — with and
    /// without the <c>client_id</c> field — is refused <c>401 invalid_client</c> with NO
    /// <c>WWW-Authenticate</c> challenge (no <c>Authorization: Basic</c> header was ever attempted),
    /// identically for an unknown code and a live one, because the declared-method authentication
    /// call in the endpoint's pre-correlation step runs regardless of whether any credential or
    /// <c>client_id</c> is present. The live code is unconsumed: it still redeems once its
    /// declared credential is attached.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.2.1">RFC 6749 §3.2.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NoCredentialsAtCodeRedemptionAnswersTheSameBodyForAnUnknownAndALiveCodeAsync()
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

            (string flowId, _) = await AuthCodeFlowDriver.DriveParAuthorizeAndCallbackAsync(
                hosted, client, authenticated, clientFlowStore, segment, RedirectUri, SubjectId,
                browserClient, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            AuthorizationCodeReceivedState callbackState = (AuthorizationCodeReceivedState)clientFlowStore[flowId];

            Uri tokenUri = RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, segment);

            Dictionary<string, string> liveWithClientId = RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, callbackState.Code, callbackState.Pkce.EncodedVerifier, callbackState.RedirectUri.OriginalString);
            Dictionary<string, string> unknownWithClientId = RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, "unknown-authorization-code-value", callbackState.Pkce.EncodedVerifier, callbackState.RedirectUri.OriginalString);

            await AssertNoCredentialRefusalAsync(hosted, tokenUri, liveWithClientId, unknownWithClientId, TestContext.CancellationToken)
                .ConfigureAwait(false);

            Dictionary<string, string> liveWithoutClientId = new(liveWithClientId, StringComparer.Ordinal);
            _ = liveWithoutClientId.Remove(OAuthRequestParameterNames.ClientId);
            Dictionary<string, string> unknownWithoutClientId = new(unknownWithClientId, StringComparer.Ordinal);
            _ = unknownWithoutClientId.Remove(OAuthRequestParameterNames.ClientId);

            await AssertNoCredentialRefusalAsync(hosted, tokenUri, liveWithoutClientId, unknownWithoutClientId, TestContext.CancellationToken)
                .ConfigureAwait(false);

            //The live code is unconsumed: it still redeems once its declared credential is attached.
            AuthCodeFlowEndpointResult tokenResult = await client.AuthCode.ExchangeTokenAsync(
                authenticated, flowId, [], null, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
                $"The live code must still redeem with its declared credential attached. ErrorCode={tokenResult.ErrorCode}");
        }
        finally
        {
            secretMaterial.PublicKey.Dispose();
            secretMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// Pushes <paramref name="liveFields"/> and <paramref name="unknownFields"/> over the real
    /// wire with no <c>Authorization</c> header and no credential form fields, and asserts both
    /// answer <c>401 invalid_client</c> with no <c>WWW-Authenticate</c> challenge, byte-identically.
    /// </summary>
    private static async Task AssertNoCredentialRefusalAsync(
        HostedAuthorizationServer hosted, Uri tokenUri,
        Dictionary<string, string> liveFields, Dictionary<string, string> unknownFields,
        CancellationToken cancellationToken)
    {
        HttpResponseData liveResponse = await HttpClientTransport.SendFormPostAsync(
            hosted.SharedHttpClient!, tokenUri, liveFields, OutgoingHeaders.Empty, cancellationToken).ConfigureAwait(false);
        HttpResponseData unknownResponse = await HttpClientTransport.SendFormPostAsync(
            hosted.SharedHttpClient!, tokenUri, unknownFields, OutgoingHeaders.Empty, cancellationToken).ConfigureAwait(false);

        Assert.AreEqual(401, liveResponse.StatusCode, liveResponse.Body);
        Assert.Contains(OAuthErrors.InvalidClient, liveResponse.Body, StringComparison.Ordinal);
        Assert.IsNull(liveResponse.Headers.TryGetSingle(WellKnownHttpHeaderNames.WwwAuthenticate),
            "No Authorization header was attempted, so no Basic challenge is added.");
        Assert.AreEqual(liveResponse.StatusCode, unknownResponse.StatusCode);
        Assert.AreEqual(liveResponse.Body, unknownResponse.Body,
            "An unknown code and a live one must answer byte-identically when no credentials are presented.");
    }


    /// <summary>
    /// Once per request, over the real wire, for a LIVE code redeemed with <c>private_key_jwt</c>,
    /// a proof carrying the server's supplied nonce, AND a token-request <c>authorization_details</c>
    /// whose credential metadata declares a NON-EMPTY <c>authorization_servers</c> (so the location
    /// requirement actually resolves to a value, and the request's detail names the CARRIED issuer
    /// in its own <c>locations</c> element — the location decision runs against that carried value,
    /// not merely against a shape that never exercises it): the nonce validator runs exactly once,
    /// the DPoP <c>jti</c> guard registers exactly one first use, the client-assertion validator
    /// runs exactly once, the assertion's own <c>jti</c> is recorded exactly once, the issuer is
    /// resolved exactly TWICE for the whole request — once by the dispatcher's own RFC 9207
    /// <c>iss</c> discovery (<c>EndpointServer.HandleCoreAsync</c>'s §2.6, a separate, unfolded
    /// seam that runs for every request before the step ever does) and once by the step's own
    /// fold-safe resolution, carried so declared authentication and the authorization_details
    /// decision both read that SAME carried value rather than resolving a THIRD time —
    /// <c>ParseAuthorizationDetailsAsync</c> runs exactly once (the step's carry lets the handler
    /// skip its own re-parse), and <c>ContributeCredentialIssuerMetadataAsync</c> runs exactly
    /// once. A separate, preliminary
    /// nonce CHALLENGE (a nonce-less proof against an unknown code) registers no DPoP <c>jti</c> at
    /// all — the guard runs only after the nonce decision has already succeeded. A WRONG-location
    /// detail is refused <c>invalid_authorization_details</c> byte-identically for an unknown code
    /// and the (still unconsumed) live one; the correct-location detail then redeems the live code.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 §11.1</see>,
    /// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523 §3</see>,
    /// <see href="https://www.rfc-editor.org/rfc/rfc9396#section-5">RFC 9396 §5</see>.
    /// </summary>
    [TestMethod]
    public async Task OnceOnlyDelegateCountsAtCodeRedemptionWithPrivateKeyJwtAndNonceBearingProofAsync()
    {
        var signingKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        var probeProofKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
                ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
            _ = await host.EnableDpopAsync().ConfigureAwait(false);

            string alg = CryptoFormatConversions.DefaultTagToJwaConverter(signingKeys.PublicKey.Tag);
            const string SigningKeyId = "once-only-counts-key-1";
            IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(signingKeys.PublicKey, alg, TestSetup.Base64UrlEncoder);
            string jwksJson = BuildJwksJson(jwk, SigningKeyId);

            await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
            HostedAuthorizationServer hosted = host.Host("default");
            string segment = material.Registration.TenantId.Value;
            Uri tokenEndpoint = RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, segment);

            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.ValidateClientCredentialsAsync =
                    PrivateKeyJwtClientAuthentication.BuildValidator(
                        additionalAcceptedAudiences: [tokenEndpoint.OriginalString],
                        checkJtiReplayAsync: JtiReplayGuard.ConsultAsync);
            }).ConfigureAwait(false);

            await DeclareServerSideAuthMethodAsync(
                host, material, ClientAuthenticationMethod.PrivateKeyJwt,
                clientJwks: jwksJson, assertionSigningAlgorithm: alg).ConfigureAwait(false);

            (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
                await host.CreateOAuthClientAndRegistrationAsync(
                    material.Registration, RedirectUri.OriginalString, profile: PolicyProfile.Rfc6749WithPkce,
                    TestContext.CancellationToken).ConfigureAwait(false);
            registration = registration with
            {
                AuthenticationMethod = ClientAuthenticationMethod.PrivateKeyJwt,
                AuthenticationKeyMaterial = signingKeys
            };

            ClientAssertionOptions assertionOptions = new()
            {
                SigningKeyId = SigningKeyId,
                HeaderSerializer = host.Server.OAuth().Codecs.JwtHeaderSerializer!,
                PayloadSerializer = host.Server.OAuth().Codecs.JwtPayloadSerializer!
            };

            using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
            (string flowId, _) = await AuthCodeFlowDriver.DriveParAuthorizeAndCallbackAsync(
                hosted, client, registration, clientFlowStore, segment, RedirectUri, SubjectId, browserClient,
                clientAssertionOptions: assertionOptions, cancellationToken: TestContext.CancellationToken)
                .ConfigureAwait(false);
            AuthorizationCodeReceivedState callbackState = (AuthorizationCodeReceivedState)clientFlowStore[flowId];

            //A preliminary, uncounted probe against an UNKNOWN code obtains a fresh nonce: the
            //jti guard runs only after the nonce decision succeeds, so this challenge must record
            //no DPoP jti at all.
            DpopKey probeProofKey = new(probeProofKeys, WellKnownJwaValues.Es256);
            string probeAssertion = await SignClientAssertionWithoutKidAsync(
                signingKeys.PrivateKey, ClientId, tokenEndpoint.OriginalString, TimeProvider.GetUtcNow(),
                host.Server.OAuth().Codecs.JwtHeaderSerializer!, host.Server.OAuth().Codecs.JwtPayloadSerializer!,
                TestContext.CancellationToken).ConfigureAwait(false);
            string probeProofJti = Guid.NewGuid().ToString("N");
            string probeProof = await DpopProofConstruction.BuildAsync(
                new DpopProofClaims
                {
                    Htm = WellKnownHttpMethods.Post,
                    Htu = tokenEndpoint.OriginalString,
                    Iat = TimeProvider.GetUtcNow(),
                    Jti = probeProofJti,
                    Nonce = null
                },
                probeProofKey, TestHostShell.Base64UrlEncoder, DpopTestSupport.Serializer,
                MicrosoftCryptographicFunctionsAdapter.SignP256Async, TestHostShell.MemoryPool,
                TestContext.CancellationToken).ConfigureAwait(false);

            //The probe's own client assertion is authenticated (and its jti recorded) BEFORE DPoP
            //ever runs, so only the DPoP proof's OWN jti — never the assertion's — is the oracle for
            //"a nonce challenge registers no DPoP jti".
            int dpopJtiFirstUseCountDuringChallenge = 0;
            var saveDuringChallenge = host.Server.OAuth().SaveFlowStateAsync!;
            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.SaveFlowStateAsync = (tenant, key, state, step, ctx, ct) =>
                {
                    if(state is JtiSeenState seen && string.Equals(seen.Jti, probeProofJti, StringComparison.Ordinal))
                    {
                        dpopJtiFirstUseCountDuringChallenge++;
                    }

                    return saveDuringChallenge(tenant, key, state, step, ctx, ct);
                };
            }).ConfigureAwait(false);

            Dictionary<string, string> probeFields = RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, "unknown-authorization-code-value", callbackState.Pkce.EncodedVerifier,
                callbackState.RedirectUri.OriginalString);
            probeFields[OAuthRequestParameterNames.ClientAssertionType] = WellKnownClientAssertionTypes.JwtBearer;
            probeFields[OAuthRequestParameterNames.ClientAssertion] = probeAssertion;

            HttpResponseData challenge = await HttpClientTransport.SendFormPostAsync(
                hosted.SharedHttpClient!, tokenEndpoint, probeFields,
                OutgoingHeaders.Empty.WithDpop(probeProof), TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(400, challenge.StatusCode, challenge.Body);
            Assert.Contains(OAuthErrors.UseDpopNonce, challenge.Body, StringComparison.Ordinal);
            Assert.AreEqual(0, dpopJtiFirstUseCountDuringChallenge, "A nonce challenge must register no DPoP jti.");
            string serverNonce = challenge.Headers.TryGetSingle(WellKnownHttpHeaderNames.DPoPNonce)
                ?? throw new AssertFailedException("The use_dpop_nonce challenge must carry a DPoP-Nonce header.");

            //The counted live redemption: a fresh proof carrying the supplied nonce, a fresh
            //assertion (the probe's own jti must not be re-presented).
            string liveProofJti = Guid.NewGuid().ToString("N");
            string liveProof = await DpopProofConstruction.BuildAsync(
                new DpopProofClaims
                {
                    Htm = WellKnownHttpMethods.Post,
                    Htu = tokenEndpoint.OriginalString,
                    Iat = TimeProvider.GetUtcNow(),
                    Jti = liveProofJti,
                    Nonce = serverNonce
                },
                probeProofKey, TestHostShell.Base64UrlEncoder, DpopTestSupport.Serializer,
                MicrosoftCryptographicFunctionsAdapter.SignP256Async, TestHostShell.MemoryPool,
                TestContext.CancellationToken).ConfigureAwait(false);
            string liveAssertion = await SignClientAssertionWithoutKidAsync(
                signingKeys.PrivateKey, ClientId, tokenEndpoint.OriginalString, TimeProvider.GetUtcNow(),
                host.Server.OAuth().Codecs.JwtHeaderSerializer!, host.Server.OAuth().Codecs.JwtPayloadSerializer!,
                TestContext.CancellationToken).ConfigureAwait(false);

            string issuerLocation = hosted.Registrations[segment].IssuerUri!.OriginalString;
            const string WrongLocation = "https://wrong-location.example.test/";
            const string OnceOnlyDetailsConfigurationId = "once-only-counts-configuration";

            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
                candidateIntegration.ResolveCredentialAuthorizationAsync = (details, subject, reg, ctx, ct) =>
                    ValueTask.FromResult(CredentialAuthorizationDecision.Grant(
                    [
                        new GrantedCredentialAuthorization
                        {
                            CredentialConfigurationId = details[0].CredentialConfigurationId!,
                            CredentialIdentifiers = ["once-only-counts-credential-1"]
                        }
                    ]));
                //A NON-EMPTY contribution activates the OID4VCI 1.0 §5.1.1/§6.1.1 locations
                //requirement against the CARRIED issuer (S2/CONF-4): a request whose detail never
                //names a location cannot prove the decision runs against that carried value rather
                //than a freshly re-resolved one, or that it runs at all.
                candidateIntegration.ContributeCredentialIssuerMetadataAsync = (reg, ctx, ct) =>
                    ValueTask.FromResult(new CredentialIssuerMetadataContribution
                    {
                        AuthorizationServers = [issuerLocation]
                    });
                candidateIntegration.ResolveIssuerAsync = (reg, ctx, ct) =>
                    //Mirrors DefaultIssuerResolver's own read (ClientRecord.IssuerUri) — the
                    //per-request registration the dispatcher hands in, never the captured
                    //client-side `material.Registration`, which the server-side alignment this
                    //test does not otherwise perform may leave stale.
                    ValueTask.FromResult<Uri?>(((ClientRecord)reg).IssuerUri);
            }).ConfigureAwait(false);

            //A WRONG-location detail is refused in the step, before DPoP or code claiming ever
            //run, byte-identically for an unknown code and the still-unconsumed live one. Each
            //leg signs its OWN fresh client assertion (a replay-guarded jti cannot be reused).
            async Task<HttpResponseData> PostWrongLocationAsync(string code)
            {
                string assertion = await SignClientAssertionWithoutKidAsync(
                    signingKeys.PrivateKey, ClientId, tokenEndpoint.OriginalString, TimeProvider.GetUtcNow(),
                    host.Server.OAuth().Codecs.JwtHeaderSerializer!, host.Server.OAuth().Codecs.JwtPayloadSerializer!,
                    TestContext.CancellationToken).ConfigureAwait(false);
                Dictionary<string, string> fields = RawAuthCodeWirePushers.BuildTokenFields(
                    ClientId, code, callbackState.Pkce.EncodedVerifier, callbackState.RedirectUri.OriginalString);
                fields[OAuthRequestParameterNames.ClientAssertionType] = WellKnownClientAssertionTypes.JwtBearer;
                fields[OAuthRequestParameterNames.ClientAssertion] = assertion;
                fields[OAuthRequestParameterNames.AuthorizationDetails] =
                    "[{\"type\":\"openid_credential\",\"credential_configuration_id\":\"" + OnceOnlyDetailsConfigurationId
                    + "\",\"locations\":[\"" + WrongLocation + "\"]}]";

                return await HttpClientTransport.SendFormPostAsync(
                    hosted.SharedHttpClient!, tokenEndpoint, fields, OutgoingHeaders.Empty,
                    TestContext.CancellationToken).ConfigureAwait(false);
            }

            HttpResponseData wrongLocationLiveResponse = await PostWrongLocationAsync(callbackState.Code).ConfigureAwait(false);
            HttpResponseData wrongLocationUnknownResponse = await PostWrongLocationAsync("unknown-authorization-code-value").ConfigureAwait(false);

            Assert.AreEqual(400, wrongLocationLiveResponse.StatusCode, wrongLocationLiveResponse.Body);
            Assert.Contains(OAuthErrors.InvalidAuthorizationDetails, wrongLocationLiveResponse.Body, StringComparison.Ordinal);
            Assert.AreEqual(wrongLocationLiveResponse.StatusCode, wrongLocationUnknownResponse.StatusCode);
            Assert.AreEqual(wrongLocationLiveResponse.Body, wrongLocationUnknownResponse.Body,
                "A wrong-location detail must answer byte-identically for an unknown code and a live, still-unconsumed one.");

            int nonceValidateCount = 0;
            int dpopJtiFirstUseCount = 0;
            int assertionJtiFirstUseCount = 0;
            int assertionValidatorCallCount = 0;
            int resolveIssuerCount = 0;
            int parseAuthorizationDetailsCount = 0;
            int contributeCredentialIssuerMetadataCount = 0;
            var originalNonceValidator = host.Server.OAuth().ValidateDpopNonceAsync!;
            var originalAssertionValidator = host.Server.OAuth().ValidateClientCredentialsAsync!;
            var originalSave = host.Server.OAuth().SaveFlowStateAsync!;
            var originalResolveIssuer = host.Server.OAuth().ResolveIssuerAsync!;
            var originalParse = host.Server.OAuth().ParseAuthorizationDetailsAsync!;
            var originalContribute = host.Server.OAuth().ContributeCredentialIssuerMetadataAsync!;
            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.ValidateDpopNonceAsync = (presented, audience, tenantId, ctx, ct) =>
                {
                    nonceValidateCount++;

                    return originalNonceValidator(presented, audience, tenantId, ctx, ct);
                };
                candidateIntegration.ValidateClientCredentialsAsync = async (request, fields, reg, ctx, ct) =>
                {
                    assertionValidatorCallCount++;

                    return await originalAssertionValidator(request, fields, reg, ctx, ct).ConfigureAwait(false);
                };
                candidateIntegration.SaveFlowStateAsync = (tenant, key, state, step, ctx, ct) =>
                {
                    if(state is JtiSeenState seen)
                    {
                        if(string.Equals(seen.Jti, liveProofJti, StringComparison.Ordinal))
                        {
                            dpopJtiFirstUseCount++;
                        }
                        else
                        {
                            assertionJtiFirstUseCount++;
                        }
                    }

                    return originalSave(tenant, key, state, step, ctx, ct);
                };

                //Item 2 (S2/F2/S7): one resolved issuer, one parse, one metadata contribution for
                //the whole request — the step resolves and carries the issuer, and carries the
                //parsed authorization_details for the handler to read instead of re-running any
                //of the three. Wrapped from the wiring the first alteration above installed, so
                //the counted request below actually exercises the non-empty-AuthorizationServers,
                //carried-issuer location decision (S2/CONF-4), not merely the empty-metadata
                //short-circuit.
                candidateIntegration.ResolveIssuerAsync = (reg, ctx, ct) =>
                {
                    resolveIssuerCount++;

                    return originalResolveIssuer(reg, ctx, ct);
                };
                candidateIntegration.ParseAuthorizationDetailsAsync = async (json, ctx, ct) =>
                {
                    parseAuthorizationDetailsCount++;

                    return await originalParse(json, ctx, ct).ConfigureAwait(false);
                };
                candidateIntegration.ContributeCredentialIssuerMetadataAsync = async (reg, ctx, ct) =>
                {
                    contributeCredentialIssuerMetadataCount++;

                    return await originalContribute(reg, ctx, ct).ConfigureAwait(false);
                };
            }).ConfigureAwait(false);

            Dictionary<string, string> liveFields = RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, callbackState.Code, callbackState.Pkce.EncodedVerifier, callbackState.RedirectUri.OriginalString);
            liveFields[OAuthRequestParameterNames.ClientAssertionType] = WellKnownClientAssertionTypes.JwtBearer;
            liveFields[OAuthRequestParameterNames.ClientAssertion] = liveAssertion;
            liveFields[OAuthRequestParameterNames.AuthorizationDetails] =
                "[{\"type\":\"openid_credential\",\"credential_configuration_id\":\"" + OnceOnlyDetailsConfigurationId
                + "\",\"locations\":[\"" + issuerLocation + "\"]}]";

            HttpResponseData redemption = await HttpClientTransport.SendFormPostAsync(
                hosted.SharedHttpClient!, tokenEndpoint, liveFields,
                OutgoingHeaders.Empty.WithDpop(liveProof), TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(200, redemption.StatusCode, redemption.Body);
            Assert.AreEqual(1, nonceValidateCount, "The nonce validator must run exactly once for this request.");
            Assert.AreEqual(1, dpopJtiFirstUseCount, "The DPoP jti guard must register exactly one first use for this request.");
            Assert.AreEqual(1, assertionValidatorCallCount, "The client-assertion validator must run exactly once for this request.");
            Assert.AreEqual(1, assertionJtiFirstUseCount, "The assertion's own jti must be recorded exactly once for this request.");
            Assert.AreEqual(2, resolveIssuerCount,
                "The issuer must be resolved exactly twice for this request: the dispatcher's own RFC 9207 iss discovery, plus the step's single fold-safe resolution the step, declared authentication and the authorization_details decision all share.");
            Assert.AreEqual(1, parseAuthorizationDetailsCount, "authorization_details must be parsed exactly once for this request.");
            Assert.AreEqual(1, contributeCredentialIssuerMetadataCount, "Credential Issuer metadata must be contributed exactly once for this request.");
        }
        finally
        {
            signingKeys.PublicKey.Dispose();
            signingKeys.PrivateKey.Dispose();
            probeProofKeys.PublicKey.Dispose();
            probeProofKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// After a live alteration of an unrelated integration member
    /// (<see cref="AuthorizationServerIntegration.ClientAssertionSigningAlgorithmsSupported"/>,
    /// mid-lifetime, exactly as the design's live-configuration section permits — the server is
    /// altered UNDER TRAFFIC by an atomic swap), a wrong <c>client_secret_basic</c> secret at CODE
    /// REDEMPTION still answers byte-identically for an unknown code and a live one: the
    /// pre-correlation step is rebuilt from the endpoint chain on every request, so a live
    /// alteration cannot lose it. <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC
    /// 6749 §5.2</see>.
    /// </summary>
    [TestMethod]
    public async Task WrongBasicSecretAtCodeRedemptionStillHoldsAfterLiveAlterationAsync()
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
                    material.Registration, RedirectUri.OriginalString, profile: PolicyProfile.Rfc6749WithPkce,
                    TestContext.CancellationToken).ConfigureAwait(false);
            registration = registration with
            {
                AuthenticationMethod = ClientAuthenticationMethod.ClientSecretBasic,
                AuthenticationKeyMaterial = secretMaterial
            };

            using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
            HostedAuthorizationServer hosted = host.Host("default");
            string segment = material.Registration.TenantId.Value;

            (string flowId, _) = await AuthCodeFlowDriver.DriveParAuthorizeAndCallbackAsync(
                hosted, client, registration, clientFlowStore, segment, RedirectUri, SubjectId,
                browserClient, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            AuthorizationCodeReceivedState callbackState = (AuthorizationCodeReceivedState)clientFlowStore[flowId];

            //The live alteration: an unrelated integration member, swapped mid-lifetime.
            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.ClientAssertionSigningAlgorithmsSupported = [WellKnownJwaValues.Es256];
            }).ConfigureAwait(false);

            Uri tokenUri = RawAuthCodeWirePushers.ResolveTokenEndpointUri(host, segment);
            OutgoingHeaders wrongSecretHeaders = OutgoingHeaders.Empty.WithClientSecretBasic(
                ClientId, Encoding.UTF8.GetBytes(WrongClientSecret));

            Dictionary<string, string> liveFields = RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, callbackState.Code, callbackState.Pkce.EncodedVerifier, callbackState.RedirectUri.OriginalString);
            HttpResponseData liveResponse = await HttpClientTransport.SendFormPostAsync(
                hosted.SharedHttpClient!, tokenUri, liveFields, wrongSecretHeaders, TestContext.CancellationToken).ConfigureAwait(false);

            Dictionary<string, string> unknownFields = RawAuthCodeWirePushers.BuildTokenFields(
                ClientId, "unknown-authorization-code-value", callbackState.Pkce.EncodedVerifier, callbackState.RedirectUri.OriginalString);
            HttpResponseData unknownResponse = await HttpClientTransport.SendFormPostAsync(
                hosted.SharedHttpClient!, tokenUri, unknownFields, wrongSecretHeaders, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(401, liveResponse.StatusCode, liveResponse.Body);
            Assert.Contains(OAuthErrors.InvalidClient, liveResponse.Body, StringComparison.Ordinal);
            Assert.AreEqual(WellKnownAuthenticationSchemes.Basic,
                liveResponse.Headers.TryGetSingle(WellKnownHttpHeaderNames.WwwAuthenticate));
            Assert.AreEqual(liveResponse.StatusCode, unknownResponse.StatusCode);
            Assert.AreEqual(liveResponse.Body, unknownResponse.Body,
                "A live alteration of an unrelated integration member must not disturb the pre-correlation step's byte-identity guarantee.");

            //The live code is unconsumed: it still redeems with the correct secret.
            OutgoingHeaders rightSecretHeaders = OutgoingHeaders.Empty.WithClientSecretBasic(
                ClientId, Encoding.UTF8.GetBytes(ClientSecret));
            HttpResponseData redemption = await HttpClientTransport.SendFormPostAsync(
                hosted.SharedHttpClient!, tokenUri, liveFields, rightSecretHeaders, TestContext.CancellationToken)
                .ConfigureAwait(false);
            Assert.AreEqual(200, redemption.StatusCode, redemption.Body);
        }
        finally
        {
            secretMaterial.PublicKey.Dispose();
            secretMaterial.PrivateKey.Dispose();
        }
    }
}
