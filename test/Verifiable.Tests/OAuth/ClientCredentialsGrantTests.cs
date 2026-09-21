using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Json;
using Verifiable.Core.OutboundFetch;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.ClientCredentials;
using Verifiable.OAuth.Diagnostics;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.Server.Diagnostics;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// HTTP wire tests for the <c>client_credentials</c> grant (RFC 6749 §4.4):
/// a machine client authenticates through the application's
/// <see cref="AuthorizationServerIntegration.ValidateClientCredentialsAsync"/>
/// seam and receives a Bearer access token scoped to its allowed scopes — the
/// flow a Shared Signals Receiver uses to obtain <c>ssf.manage</c> from a
/// Transmitter's authorization server.
/// </summary>
[TestClass]
internal sealed class ClientCredentialsGrantTests
{
    private const string ClientId = "https://machine.example.com";
    private const string ClientSecret = "s3cret-of-the-machine";

    //A non-identity scope, granted alongside RegisterDpopClient's fixed OIDC identity scope set
    //(RegisterMachineClient patches it in) so a happy-path request has SOMETHING left to retain
    //once RFC 6749 §3.3 narrowing removes openid/profile/email/address/phone
    //from every client_credentials grant.
    private const string MachineScope = "telemetry.read";

    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;


    [TestMethod]
    public async Task IssuesBearerAccessTokenOverHttpWire()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterMachineClientAsync(app).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(host.SharedHttpClient!, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.Scope] = MachineScope
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        JsonElement root = doc.RootElement;
        string accessToken = root.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        Assert.AreEqual(WellKnownAuthenticationSchemes.Bearer, root.GetProperty("token_type").GetString());
        Assert.IsGreaterThan(0, root.GetProperty("expires_in").GetInt32(), "expires_in must reflect the token's exp-iat.");
        Assert.AreEqual(MachineScope, root.GetProperty(OAuthRequestParameterNames.Scope).GetString(),
            "A non-identity scope survives RFC 6749 §3.3 narrowing unchanged (only openid and the "
            + "OIDC identity scopes are narrowed).");

        //RFC 9068 §3: with no end-user involved, the subject is the client itself.
        string[] segments = accessToken.Split('.');
        Assert.HasCount(3, segments);
        byte[] payloadBytes = SecurityEventTestJson.DecodeSegment(segments[1], Pool);
        using JsonDocument payload = JsonDocument.Parse(payloadBytes);
        Assert.AreEqual(ClientId, payload.RootElement.GetProperty("sub").GetString());
        Assert.AreEqual(ClientId, payload.RootElement.GetProperty("client_id").GetString());
    }


    [TestMethod]
    public async Task WrongSecretAndDisallowedScopeAreRejected()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterMachineClientAsync(app).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");
        HttpClient http = host.SharedHttpClient!;

        //A wrong secret fails client authentication — 401 invalid_client.
        using HttpResponseMessage badSecret = await OAuthTestTransport.PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = "guessed-wrong"
        }, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(401, (int)badSecret.StatusCode);

        //A scope outside the registration's allowed set — 400 invalid_scope.
        using HttpResponseMessage badScope = await OAuthTestTransport.PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.SsfManage
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string badScopeBody = await badScope.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)badScope.StatusCode, badScopeBody);
        Assert.Contains(OAuthErrors.InvalidScope, badScopeBody);
    }


    [TestMethod]
    public async Task GrantAdvertisesAndFailsClosedWithoutTheSeam()
    {
        //With the seam wired, the discovery document advertises client_credentials.
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterMachineClientAsync(app).ConfigureAwait(false);
        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = material.Registration.TenantId.Value;

        Uri discoveryUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/.well-known/openid-configuration");
        using HttpResponseMessage discovery = await host.SharedHttpClient!
            .GetAsync(discoveryUrl, TestContext.CancellationToken).ConfigureAwait(false);
        string discoveryBody = await discovery.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)discovery.StatusCode, discoveryBody);
        Assert.Contains(WellKnownGrantTypes.ClientCredentials, discoveryBody,
            "grant_types_supported must advertise client_credentials when the grant is active.");

        //Without the seam, the grant endpoint does not exist — fail-closed: an
        //unauthenticated client-credentials grant would mint tokens for anyone.
        await using TestHostShell bare = new(TimeProvider);
        using VerifierKeyMaterial bareMaterial = await bare.RegisterClientAsync(
            ClientId,
            new Uri(ClientId),
            ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthClientCredentials)).ConfigureAwait(false);
        await bare.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer bareHost = bare.Host("default");
        Uri bareTokenUrl = new(bareHost.HttpBaseAddress!, $"/connect/{bareMaterial.Registration.TenantId.Value}/token");

        using HttpResponseMessage unmatched = await OAuthTestTransport.PostFormAsync(bareHost.SharedHttpClient!, bareTokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret
        }, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreNotEqual(200, (int)unmatched.StatusCode,
            "The client_credentials grant must not be reachable without the client-authentication seam.");
    }


    /// <summary>
    /// RFC 9396 §6: a <c>client_credentials</c> token request carrying
    /// <c>authorization_details</c> MUST NOT have the parameter silently dropped. Malformed JSON
    /// and an unknown type each surface the §5 <c>invalid_authorization_details</c> error from the
    /// same shape-validation path the other grants use; a shape-valid <c>openid_credential</c>
    /// object is refused with <c>invalid_authorization_details</c> because this grant has no policy
    /// through which an authorization-details-bound token can be allowed; and a request with no
    /// <c>authorization_details</c> is issued exactly as before.
    /// </summary>
    [TestMethod]
    public async Task AuthorizationDetailsAreValidatedAndRefusedNotSilentlyDropped()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterMachineClientAsync(app).ConfigureAwait(false);
        //The composition-time pairing check requires ResolveCredentialAuthorizationAsync alongside
        //the parser (no further authorization details type is registered here). The
        //client_credentials grant handler never calls it — a shape-valid openid_credential request
        //is refused by this grant's own dedicated policy message, independent of resolver wiring
        //(case (c) below) — so invoking this delegate fails the test rather than merely going
        //unobserved.
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
            candidateIntegration.ResolveCredentialAuthorizationAsync =
                static (details, subject, registration, context, ct) =>
                {
                    Assert.Fail("The client_credentials grant must never consult the credential decision seam.");

                    return ValueTask.FromResult(
                        CredentialAuthorizationDecision.Deny(CredentialAuthorizationDenialReason.AuthorizationDenied));
                };
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");
        HttpClient http = host.SharedHttpClient!;

        //(a) Malformed JSON — §5 "not conforming to the respective type definition".
        using HttpResponseMessage malformed = await OAuthTestTransport.PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.AuthorizationDetails] = "{ not json"
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string malformedBody = await malformed.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)malformed.StatusCode, malformedBody);
        Assert.Contains(OAuthErrors.InvalidAuthorizationDetails, malformedBody);

        //(b) Unknown type — §5 "contains an unknown authorization details type value".
        using HttpResponseMessage unknownType = await OAuthTestTransport.PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.AuthorizationDetails] =
                """[{"type":"no_such_type_for_this_server"}]"""
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string unknownTypeBody = await unknownType.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)unknownType.StatusCode, unknownTypeBody);
        Assert.Contains(OAuthErrors.InvalidAuthorizationDetails, unknownTypeBody);

        //(c) Shape-valid openid_credential — §6: the grant's policy cannot allow the issuance, so
        //the request is refused, not silently dropped.
        using HttpResponseMessage shapeValid = await OAuthTestTransport.PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.AuthorizationDetails] =
                """[{"type":"openid_credential","credential_configuration_id":"UniversityDegree_dc_sd_jwt"}]"""
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string shapeValidBody = await shapeValid.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)shapeValid.StatusCode, shapeValidBody);
        Assert.Contains(OAuthErrors.InvalidAuthorizationDetails, shapeValidBody);
        Assert.DoesNotContain(WellKnownTokenTypes.AccessToken, shapeValidBody,
            "A shape-valid authorization_details request must be refused, never minted into a token.");

        //(d) No authorization_details — the grant is issued exactly as before.
        using HttpResponseMessage plain = await OAuthTestTransport.PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string plainBody = await plain.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)plain.StatusCode, plainBody);
        using JsonDocument plainDoc = JsonDocument.Parse(plainBody);
        Assert.IsTrue(plainDoc.RootElement.TryGetProperty(WellKnownTokenTypes.AccessToken, out _));
        Assert.IsFalse(plainDoc.RootElement.TryGetProperty(OAuthRequestParameterNames.AuthorizationDetails, out _),
            "A client_credentials response carries no authorization_details.");
    }


    /// <summary>
    /// The client-composed <c>client_credentials</c> request over the real wire under
    /// <c>client_secret_basic</c> (RFC 6749 §2.3.1): <see cref="ClientCredentialsClient.RequestTokenAsync"/>
    /// attaches the <c>Authorization: Basic</c> header itself and the server's
    /// <see cref="AuthorizationServerIntegration.ValidateClientCredentialsAsync"/> seam, reading only
    /// that header, authenticates it and issues a token.
    /// </summary>
    [TestMethod]
    public async Task ClientComposedRequestIssuesTokenUnderClientSecretBasicOverRealWire()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> secretMaterial = BuildSecretKeyMaterial(ClientSecret);
        try
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
                ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce,
                capabilities: ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthClientCredentials)).ConfigureAwait(false);
            await AddMachineScopeAsync(host, material).ConfigureAwait(false);

            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
                    ValueTask.FromResult(AuthCodeFlowDriver.DecodeAndMatchBasicHeader(request, registration.ClientId, ClientSecret));
            }).ConfigureAwait(false);

            await DeclareServerSideAuthMethodAsync(host, material, ClientAuthenticationMethod.ClientSecretBasic)
                .ConfigureAwait(false);

            (OAuthClient client, ClientRegistration registration, _) = await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration, ClientId, profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);
            registration = registration with
            {
                AuthenticationMethod = ClientAuthenticationMethod.ClientSecretBasic,
                AuthenticationKeyMaterial = secretMaterial
            };

            AuthCodeFlowEndpointResult result = await client.ClientCredentials.RequestTokenAsync(
                registration, scope: MachineScope, resource: null, [], clientAssertionOptions: null,
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, result.Outcome,
                $"ErrorCode={result.ErrorCode} ErrorDescription={result.ErrorDescription}");
            string accessToken = (string)result.Body![OAuthRequestParameterNames.AccessToken];
            Assert.IsFalse(string.IsNullOrEmpty(accessToken));
            Assert.AreEqual(MachineScope, result.Body[OAuthRequestParameterNames.Scope]);
        }
        finally
        {
            secretMaterial.PublicKey.Dispose();
            secretMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// The client-composed <c>client_credentials</c> request over the real wire under
    /// <c>private_key_jwt</c> (RFC 7523 §2.2): <see cref="ClientCredentialsClient.RequestTokenAsync"/>
    /// signs and attaches the <c>client_assertion</c> itself and the server verifies it with the real
    /// <see cref="PrivateKeyJwtClientAuthentication.BuildValidator(System.Collections.Generic.IReadOnlyCollection{string}?,CheckClientAssertionJtiReplayDelegate?,Verifiable.OAuth.Server.Pipeline.ResolveJwksUriDelegate?)"/>
    /// pipeline over a published <c>ClientJwks</c> — the same production shape
    /// <see cref="AuthCodeClientAuthenticationTests"/> exercises for the authorization-code leg,
    /// proving the shared helper this leg now calls behaves identically.
    /// </summary>
    [TestMethod]
    public async Task ClientComposedRequestIssuesTokenUnderPrivateKeyJwtOverRealWire()
    {
        var clientKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
                ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce,
                capabilities: ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthClientCredentials)).ConfigureAwait(false);
            await AddMachineScopeAsync(host, material).ConfigureAwait(false);

            //Start the listener before wiring the validator so the resolved token endpoint URL
            //(the client-signed aud, per RFC 7523 §3 item 3) is known.
            await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
            HostedAuthorizationServer hosted = host.Host("default");
            string segment = material.Registration.TenantId.Value;
            Uri tokenEndpoint = new(
                hosted.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, segment));

            string alg = CryptoFormatConversions.DefaultTagToJwaConverter(clientKeys.PublicKey.Tag);
            const string SigningKeyId = "client-credentials-key-1";
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

            (OAuthClient client, ClientRegistration registration, _) = await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration, ClientId, profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);
            registration = registration with
            {
                AuthenticationMethod = ClientAuthenticationMethod.PrivateKeyJwt,
                AuthenticationKeyMaterial = clientKeys
            };

            AuthCodeFlowEndpointResult result = await client.ClientCredentials.RequestTokenAsync(
                registration, scope: MachineScope, resource: null, [],
                clientAssertionOptions: new ClientAssertionOptions
                {
                    SigningKeyId = SigningKeyId,
                    HeaderSerializer = host.Server.OAuth().Codecs.JwtHeaderSerializer!,
                    PayloadSerializer = host.Server.OAuth().Codecs.JwtPayloadSerializer!
                },
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, result.Outcome,
                $"ErrorCode={result.ErrorCode} ErrorDescription={result.ErrorDescription}");
            string accessToken = (string)result.Body![OAuthRequestParameterNames.AccessToken];
            Assert.IsFalse(string.IsNullOrEmpty(accessToken));
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 §5.2</see>:
    /// <c>invalid_client</c> covers "Client authentication failed." A wrong <c>client_secret_basic</c>
    /// secret answers <see cref="ClientCredentialsClient.RequestTokenAsync"/>'s typed
    /// <see cref="AuthCodeFlowEndpointOutcome.BadRequest"/> result carrying that exact error code —
    /// never an exception thrown out of the call.
    /// </summary>
    [TestMethod]
    public async Task WrongSecretAnswersTypedInvalidClientFailureNeverAnException()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> wrongSecretMaterial =
            BuildSecretKeyMaterial("guessed-wrong-secret");
        try
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
                ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce,
                capabilities: ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthClientCredentials)).ConfigureAwait(false);

            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
                    ValueTask.FromResult(AuthCodeFlowDriver.DecodeAndMatchBasicHeader(request, registration.ClientId, ClientSecret));
            }).ConfigureAwait(false);

            await DeclareServerSideAuthMethodAsync(host, material, ClientAuthenticationMethod.ClientSecretBasic)
                .ConfigureAwait(false);

            (OAuthClient client, ClientRegistration registration, _) = await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration, ClientId, profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);
            registration = registration with
            {
                AuthenticationMethod = ClientAuthenticationMethod.ClientSecretBasic,
                AuthenticationKeyMaterial = wrongSecretMaterial
            };

            AuthCodeFlowEndpointResult result = await client.ClientCredentials.RequestTokenAsync(
                registration, scope: null, resource: null, [], clientAssertionOptions: null,
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, result.Outcome);
            Assert.AreEqual(OAuthErrors.InvalidClient, result.ErrorCode);
        }
        finally
        {
            wrongSecretMaterial.PublicKey.Dispose();
            wrongSecretMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 §5.2</see>: "If the
    /// client attempted to authenticate via the Authorization request header field, the
    /// authorization server MUST respond with an HTTP 401 (Unauthorized) status code and include
    /// the WWW-Authenticate response header field matching the authentication scheme used by the
    /// client." A registration's own <c>client_id</c> with a wrong <c>client_secret_basic</c>
    /// secret is a declared-method authentication failure (never an identification mismatch), and
    /// still carries the challenge — the sibling
    /// <see cref="RefreshConfidentialClientAuthenticationTests.BasicAuthenticatedRefreshWithConflictingFormClientIdReturnsInvalidGrant"/>
    /// documents asserting here, at the endpoint whose refusal stays <c>invalid_client</c>.
    /// </summary>
    [TestMethod]
    public async Task WrongBasicSecretReturns401WithWwwAuthenticateChallengeOverRealWire()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthClientCredentials)).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
                ValueTask.FromResult(AuthCodeFlowDriver.DecodeAndMatchBasicHeader(request, registration.ClientId, ClientSecret));
        }).ConfigureAwait(false);

        await DeclareServerSideAuthMethodAsync(host, material, ClientAuthenticationMethod.ClientSecretBasic)
            .ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(hosted.HttpBaseAddress!, $"/connect/{segment}/token");

        OutgoingHeaders headers = OutgoingHeaders.Empty.WithClientSecretBasic(
            ClientId, Encoding.UTF8.GetBytes("wrong-secret"));
        HttpResponseData response = await HttpClientTransport.SendFormPostAsync(
            hosted.SharedHttpClient!, tokenUrl,
            new Dictionary<string, string> { [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials },
            headers, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(401, response.StatusCode, response.Body);
        Assert.Contains(OAuthErrors.InvalidClient, response.Body, StringComparison.Ordinal);
        string? challenge = response.Headers.TryGetSingle(WellKnownHttpHeaderNames.WwwAuthenticate);
        Assert.AreEqual(WellKnownAuthenticationSchemes.Basic, challenge,
            "A declared-method authentication failure over Basic must carry the matching WWW-Authenticate challenge.");
    }


    /// <summary>
    /// <see cref="Verifiable.Core.OutboundFetch.OutboundFetchPolicy.SecureDefault"/> refuses a
    /// loopback token endpoint. <see cref="ClientCredentialsClient.RequestTokenAsync"/> evaluates the
    /// policy (<see cref="TokenEndpointClientOperations.EvaluateOutboundPolicy"/>, reached through
    /// <see cref="TokenEndpointClientOperations.SendTokenRequestWithDpopRetryAsync"/>) before dialing
    /// — a transport delegate that throws if ever invoked proves zero dial reached it.
    /// </summary>
    [TestMethod]
    public async Task TokenEndpointDeniedByOutboundPolicyIsNeverDialed()
    {
        Uri issuer = new("https://as.example.com");
        Uri deniedTokenEndpoint = new("https://127.0.0.1:1/token");
        AuthorizationServerMetadata metadata = new()
        {
            Issuer = issuer,
            TokenEndpoint = deniedTokenEndpoint
        };

        OAuthClientInfrastructure infrastructure = OAuthClientInfrastructure.Create(
            sendFormPostAsync: (_, _, _, _, _) =>
                throw new InvalidOperationException("Must not dial a token endpoint the outbound policy denies."),
            saveStateAsync: (_, _, _) => ValueTask.CompletedTask,
            loadStateAsync: (_, _, _) => ValueTask.FromResult<FlowState?>(null),
            loadStateByRequestUriAsync: (_, _, _) => ValueTask.FromResult<FlowState?>(null),
            parseParResponseAsync: OAuthResponseParsers.ParseParResponse,
            parseTokenResponseAsync: OAuthResponseParsers.ParseTokenResponse,
            parseRegistrationResponseAsync: (body, ct) =>
                throw new NotImplementedException("Test does not exercise dynamic registration."),
            resolveAuthorizationServerMetadataAsync: (_, _, _) =>
                ValueTask.FromResult(new AuthorizationServerMetadataResolution
                {
                    Outcome = AuthorizationServerMetadataResolutionOutcome.Resolved,
                    Metadata = metadata
                }),
            resolveCallbackValidator: ClientPolicyProfiles.DefaultResolveCallbackValidator,
            base64UrlEncoder: TestSetup.Base64UrlEncoder,
            memoryPool: BaseMemoryPool.Shared,
            timeProvider: TimeProvider,
            fillEntropy: TestEntropy.NewCounterStream(),
            generateIdentifierAsync: DefaultIdentifierGenerator.For(TimeProvider, TestEntropy.NewCounterStream(), BaseMemoryPool.Shared),
            outboundFetchPolicy: OutboundFetchPolicy.SecureDefault);

        ClientRegistration registration = new()
        {
            ClientId = new ClientId(ClientId),
            AuthorizationServerIssuer = issuer,
            RedirectUris = [new Uri(ClientId)],
            AuthenticationMethod = ClientAuthenticationMethod.None,
            Profile = PolicyProfile.Rfc6749WithPkce
        };

        OAuthClient client = new(infrastructure);

        AuthCodeFlowEndpointResult result = await client.ClientCredentials.RequestTokenAsync(
            registration, scope: null, resource: null, [], clientAssertionOptions: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.InternalError, result.Outcome,
            $"ErrorCode={result.ErrorCode} ErrorDescription={result.ErrorDescription}");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-5">RFC 9449 §5</see>: "This is
    /// applicable for all access token requests regardless of grant type." A <c>client_credentials</c>
    /// request carrying a valid DPoP proof binds the issued access token the same way every other
    /// grant's token request does — <c>token_type</c> answers <c>DPoP</c> and the token's <c>cnf.jkt</c>
    /// equals the proof key's RFC 7638 thumbprint, computed here from the key itself.
    /// </summary>
    [TestMethod]
    public async Task ValidProofBindsTheAccessTokenAndAnswersDpopTokenType()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterMachineClientAsync(app).ConfigureAwait(false);
        _ = await app.EnableDpopAsync().ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        material.Registration = app.AlignRegistrationToHostHttpBase("default", material.Registration);
        HostedAuthorizationServer host = app.Host("default");
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            DpopKey dpopKey = new(holderKeys, WellKnownJwaValues.Es256);
            string expectedThumbprint = dpopKey.GetThumbprint(TestHostShell.Base64UrlEncoder, TestHostShell.MemoryPool);

            async Task<string> BuildProofAsync(string? nonce) =>
                await DpopProofConstruction.BuildAsync(
                    new DpopProofClaims
                    {
                        Htm = WellKnownHttpMethods.Post,
                        Htu = tokenUrl.OriginalString,
                        Iat = TimeProvider.GetUtcNow(),
                        Jti = Guid.NewGuid().ToString("N"),
                        Nonce = nonce
                    },
                    dpopKey, TestHostShell.Base64UrlEncoder, DpopTestSupport.Serializer,
                    MicrosoftCryptographicFunctionsAdapter.SignP256Async, TestHostShell.MemoryPool,
                    TestContext.CancellationToken).ConfigureAwait(false);

            //RFC 9449 §8: the server's single nonce policy challenges the first, nonce-less proof
            //regardless of grant; the retry carrying the echoed nonce then succeeds.
            (HttpResponseMessage response, string body) = await OAuthTestTransport.PostFormWithDpopNonceRetryAsync(
                host.SharedHttpClient!, tokenUrl, new Dictionary<string, string>
                {
                    [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
                    [OAuthRequestParameterNames.ClientId] = ClientId,
                    ["client_secret"] = ClientSecret,
                    [OAuthRequestParameterNames.Scope] = MachineScope
                },
                BuildProofAsync,
                TestContext.CancellationToken).ConfigureAwait(false);
            using(response)
            {
                Assert.AreEqual(200, (int)response.StatusCode, body);

                using JsonDocument doc = JsonDocument.Parse(body);
                Assert.AreEqual(WellKnownAuthenticationSchemes.DPoP, doc.RootElement.GetProperty("token_type").GetString(),
                    "A presented DPoP proof must bind the client_credentials grant's access token the same way it binds every other grant's.");

                string accessToken = doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
                string wireJkt = JwtPayloadReader.ReadCnfJkt(accessToken)
                    ?? throw new AssertFailedException("Access-token JWT must carry cnf.jkt under DPoP issuance.");
                Assert.AreEqual(expectedThumbprint, wireJkt,
                    "JWT cnf.jkt must equal the DPoP key's RFC 7638 thumbprint computed here from the key itself.");
            }
        }
        finally
        {
            holderKeys.PublicKey.Dispose();
            holderKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 §8</see>: the nonce
    /// requirement is the SERVER's, never the grant's — proven here by ASSERTING the challenge
    /// itself, rather than tolerating either outcome the way
    /// <see cref="ValidProofBindsTheAccessTokenAndAnswersDpopTokenType"/>'s permissive retry
    /// helper does. Under <see cref="PolicyProfile.Rfc6749WithPkce"/> — a profile
    /// <see cref="ClientPolicyProfiles.RequiresDpop"/> does NOT mandate — a nonce-less proof still
    /// answers 400 <c>use_dpop_nonce</c> with a non-empty <c>DPoP-Nonce</c> header, and the retry
    /// carrying that exact nonce succeeds.
    /// </summary>
    [TestMethod]
    public async Task NonceLessProofUnderOptionalDpopProfileIsChallengedThenSucceedsAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterMachineClientAsync(app).ConfigureAwait(false);
        _ = await app.EnableDpopAsync().ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        material.Registration = app.AlignRegistrationToHostHttpBase("default", material.Registration);
        HostedAuthorizationServer host = app.Host("default");
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            DpopKey dpopKey = new(holderKeys, WellKnownJwaValues.Es256);

            async Task<string> BuildProofAsync(string? nonce) =>
                await DpopProofConstruction.BuildAsync(
                    new DpopProofClaims
                    {
                        Htm = WellKnownHttpMethods.Post,
                        Htu = tokenUrl.OriginalString,
                        Iat = TimeProvider.GetUtcNow(),
                        Jti = Guid.NewGuid().ToString("N"),
                        Nonce = nonce
                    },
                    dpopKey, TestHostShell.Base64UrlEncoder, DpopTestSupport.Serializer,
                    MicrosoftCryptographicFunctionsAdapter.SignP256Async, TestHostShell.MemoryPool,
                    TestContext.CancellationToken).ConfigureAwait(false);

            (HttpResponseMessage response, string body) = await OAuthTestTransport.PostFormWithMandatoryDpopNonceChallengeAsync(
                host.SharedHttpClient!, tokenUrl, new Dictionary<string, string>
                {
                    [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
                    [OAuthRequestParameterNames.ClientId] = ClientId,
                    ["client_secret"] = ClientSecret,
                    [OAuthRequestParameterNames.Scope] = MachineScope
                },
                BuildProofAsync,
                TestContext.CancellationToken).ConfigureAwait(false);
            using(response)
            {
                Assert.AreEqual(200, (int)response.StatusCode, body);
            }
        }
        finally
        {
            holderKeys.PublicKey.Dispose();
            holderKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-5">RFC 9449 §5</see>: "This is
    /// applicable for all access token requests regardless of grant type." A registration whose
    /// profile mandates DPoP-bound access tokens (<see cref="ClientPolicyProfiles.RequiresDpop"/>) is
    /// refused when the <c>client_credentials</c> request carries no proof at all. The specification
    /// text leaves the exact status open; the concrete refusal the shared validator issues for a
    /// missing-but-mandated proof is the §8 <c>use_dpop_nonce</c> challenge, asserted here by error
    /// code.
    /// </summary>
    [TestMethod]
    public async Task RegistrationRequiringDpopWithoutAProofIsRefused()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterMachineClientAsync(app, PolicyProfile.Haip10).ConfigureAwait(false);
        _ = await app.EnableDpopAsync().ConfigureAwait(false);

        //HAIP 1.0's AccessTokenAudPolicy.Required needs a resolved audience; MachineScope carries no
        //ScopeToAudience mapping, so a fixed resource-server audience stands in, matching the pattern
        //Oid4VciPreAuthorizedCodeGrantTests uses under the same profile.
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveAccessTokenAudienceAsync = static (registration, issuance, ct) =>
                ValueTask.FromResult<IReadOnlyList<string>?>(["https://rs.example.com"]);
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(host.SharedHttpClient!, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.Scope] = MachineScope
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)response.StatusCode, body);
        Assert.Contains(OAuthErrors.UseDpopNonce, body,
            "A registration whose profile mandates DPoP must refuse a proof-less client_credentials request.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 §4.2</see>: the proof's
    /// <c>htu</c> MUST match the request URL. A <c>client_credentials</c> request carrying a proof
    /// bound to a different endpoint is refused and no access token is issued.
    /// </summary>
    [TestMethod]
    public async Task ProofWithWrongHtuIsRejectedWithNoAccessToken()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterMachineClientAsync(app).ConfigureAwait(false);
        _ = await app.EnableDpopAsync().ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = material.Registration.TenantId.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
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

            using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
                host.SharedHttpClient!, tokenUrl, new Dictionary<string, string>
                {
                    [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
                    [OAuthRequestParameterNames.ClientId] = ClientId,
                    ["client_secret"] = ClientSecret,
                    [OAuthRequestParameterNames.Scope] = MachineScope
                },
                OutgoingHeaders.Empty.WithDpop(proof),
                TestContext.CancellationToken).ConfigureAwait(false);
            string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(400, (int)response.StatusCode, body);
            Assert.Contains(OAuthErrors.InvalidDpopProof, body);
            Assert.DoesNotContain(WellKnownTokenTypes.AccessToken, body,
                "A proof bound to the wrong htu must never mint an access token.");
        }
        finally
        {
            holderKeys.PublicKey.Dispose();
            holderKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 §8</see> /
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">§9</see>: <see
    /// cref="ClientCredentialsClient.RequestTokenAsync"/>, with DPoP wired on the client
    /// infrastructure, against a registration whose profile mandates DPoP — the server answers the
    /// first dial with a <c>use_dpop_nonce</c> challenge and the client completes on the second dial,
    /// carrying the fresh nonce.
    /// </summary>
    [TestMethod]
    public async Task ClientRequestCompletesAfterOneNonceRetryOverRealWire()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterMachineClientAsync(app, PolicyProfile.Haip10).ConfigureAwait(false);
        _ = await app.EnableDpopAsync().ConfigureAwait(false);

        int dialCount = 0;
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = (request, fields, registration, context, ct) =>
            {
                dialCount++;

                return ValueTask.FromResult(true);
            };

            //HAIP 1.0's AccessTokenAudPolicy.Required needs a resolved audience; MachineScope carries
            //no ScopeToAudience mapping, so a fixed resource-server audience stands in, matching the
            //pattern Oid4VciPreAuthorizedCodeGrantTests uses under the same profile.
            candidateIntegration.ResolveAccessTokenAudienceAsync = static (registration, issuance, ct) =>
                ValueTask.FromResult<IReadOnlyList<string>?>(["https://rs.example.com"]);
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        material.Registration = app.AlignRegistrationToHostHttpBase("default", material.Registration);
        HostedAuthorizationServer host = app.Host("default");
        string segment = material.Registration.TenantId.Value;
        Uri tokenEndpoint = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        var dpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            DpopKey dpopKey = new(dpopKeys, WellKnownJwaValues.Es256);
            InMemoryDpopNonceCache nonceCache = new();
            AuthorizationServerMetadata metadata = new()
            {
                Issuer = material.Registration.IssuerUri!,
                TokenEndpoint = tokenEndpoint
            };

            OAuthClientInfrastructure infrastructure = OAuthClientInfrastructure.Create(
                sendFormPostAsync: (endpoint, fields, headers, _, ct) =>
                    HttpClientTransport.SendFormPostAsync(host.SharedHttpClient!, endpoint, fields, headers, ct),
                saveStateAsync: (_, _, _) => ValueTask.CompletedTask,
                loadStateAsync: (_, _, _) => ValueTask.FromResult<FlowState?>(null),
                loadStateByRequestUriAsync: (_, _, _) => ValueTask.FromResult<FlowState?>(null),
                parseParResponseAsync: OAuthResponseParsers.ParseParResponse,
                parseTokenResponseAsync: OAuthResponseParsers.ParseTokenResponse,
                parseRegistrationResponseAsync: (body, ct) =>
                    throw new NotImplementedException("Test does not exercise dynamic registration."),
                resolveAuthorizationServerMetadataAsync: (_, _, _) =>
                    ValueTask.FromResult(new AuthorizationServerMetadataResolution
                    {
                        Outcome = AuthorizationServerMetadataResolutionOutcome.Resolved,
                        Metadata = metadata
                    }),
                resolveCallbackValidator: ClientPolicyProfiles.DefaultResolveCallbackValidator,
                base64UrlEncoder: TestSetup.Base64UrlEncoder,
                memoryPool: BaseMemoryPool.Shared,
                timeProvider: TimeProvider,
                fillEntropy: TestEntropy.NewCounterStream(),
                generateIdentifierAsync: DefaultIdentifierGenerator.For(TimeProvider, TestEntropy.NewCounterStream(), BaseMemoryPool.Shared),
                outboundFetchPolicy: TestHostShell.LoopbackOutboundFetchPolicy,
                constructDpopProofAsync: (claims, key, ct) => DpopProofConstruction.BuildAsync(
                    claims, key, TestSetup.Base64UrlEncoder, DpopTestSupport.Serializer,
                    MicrosoftCryptographicFunctionsAdapter.SignP256Async, BaseMemoryPool.Shared, ct),
                dpopKey: dpopKey,
                lookupDpopNonce: nonceCache.Lookup,
                storeDpopNonce: nonceCache.Store);

            ClientRegistration registration = new()
            {
                ClientId = new ClientId(ClientId),
                AuthorizationServerIssuer = material.Registration.IssuerUri!,
                RedirectUris = [new Uri(ClientId)],
                AuthenticationMethod = ClientAuthenticationMethod.None,
                Profile = PolicyProfile.Haip10
            };

            OAuthClient client = new(infrastructure);

            AuthCodeFlowEndpointResult result = await client.ClientCredentials.RequestTokenAsync(
                registration, scope: MachineScope, resource: null, [], clientAssertionOptions: null,
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, result.Outcome,
                $"ErrorCode={result.ErrorCode} ErrorDescription={result.ErrorDescription}");
            Assert.AreEqual(WellKnownAuthenticationSchemes.DPoP, (string)result.Body![OAuthRequestParameterNames.TokenType],
                "The mandating profile's nonce-challenged request must complete DPoP-bound.");
            Assert.AreEqual(2, dialCount,
                "The client must dial the token endpoint twice: once to receive the use_dpop_nonce challenge, once more with the nonce to complete.");
        }
        finally
        {
            dpopKeys.PublicKey.Dispose();
            dpopKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 §8</see>: the DPoP-
    /// retrying send must present a FRESHLY-SIGNED <c>private_key_jwt</c> client assertion (a new
    /// <c>jti</c>) on the retry, not the same one — proved here by wiring the authorization server's
    /// <see cref="PrivateKeyJwtClientAuthentication.BuildValidator(System.Collections.Generic.IReadOnlyCollection{string}?,CheckClientAssertionJtiReplayDelegate?,Verifiable.OAuth.Server.Pipeline.ResolveJwksUriDelegate?)"/>
    /// WITH the client-assertion replay delegate: a second presentation of the SAME assertion is
    /// refused, so the retry can only complete by presenting a different one.
    /// </summary>
    [TestMethod]
    public async Task RequestCompletesAfterOneNonceRetryWithFreshClientAssertionUnderReplayCheckedRegistration()
    {
        var clientKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            await using TestHostShell app = new(TimeProvider);
            using VerifierKeyMaterial material = await RegisterMachineClientAsync(app, PolicyProfile.Haip10).ConfigureAwait(false);
            _ = await app.EnableDpopAsync().ConfigureAwait(false);

            await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
            material.Registration = app.AlignRegistrationToHostHttpBase("default", material.Registration);
            HostedAuthorizationServer host = app.Host("default");
            string segment = material.Registration.TenantId.Value;
            Uri tokenEndpoint = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

            string alg = CryptoFormatConversions.DefaultTagToJwaConverter(clientKeys.PublicKey.Tag);
            const string SigningKeyId = "client-credentials-replay-key-1";
            IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(clientKeys.PublicKey, alg, TestSetup.Base64UrlEncoder);
            string jwksJson = BuildJwksJson(jwk, SigningKeyId);

            //RFC 7523 §3 rule 7: the client-assertion replay delegate is the same JtiReplayGuard
            //store the ID-JAG/JWT-bearer assertion's own jti replay defense uses, so a SECOND
            //presentation of the SAME client_assertion is refused.
            await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
            {
                candidateIntegration.ValidateClientCredentialsAsync =
                    PrivateKeyJwtClientAuthentication.BuildValidator(
                        additionalAcceptedAudiences: [tokenEndpoint.OriginalString],
                        checkJtiReplayAsync: JtiReplayGuard.ConsultAsync);

                //HAIP 1.0's AccessTokenAudPolicy.Required needs a resolved audience; MachineScope
                //carries no ScopeToAudience mapping, so a fixed resource-server audience stands in.
                candidateIntegration.ResolveAccessTokenAudienceAsync = static (registration, issuance, ct) =>
                    ValueTask.FromResult<IReadOnlyList<string>?>(["https://rs.example.com"]);
            }).ConfigureAwait(false);

            await DeclareServerSideAuthMethodAsync(
                app, material, ClientAuthenticationMethod.PrivateKeyJwt,
                clientJwks: jwksJson, assertionSigningAlgorithm: alg).ConfigureAwait(false);

            var dpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
            try
            {
                DpopKey dpopKey = new(dpopKeys, WellKnownJwaValues.Es256);
                InMemoryDpopNonceCache nonceCache = new();
                AuthorizationServerMetadata metadata = new()
                {
                    Issuer = material.Registration.IssuerUri!,
                    TokenEndpoint = tokenEndpoint
                };

                List<string> dialedAssertions = [];
                OAuthClientInfrastructure infrastructure = OAuthClientInfrastructure.Create(
                    sendFormPostAsync: (endpoint, fields, headers, _, ct) =>
                    {
                        dialedAssertions.Add(fields.First(
                            field => string.Equals(field.Key, OAuthRequestParameterNames.ClientAssertion, StringComparison.Ordinal)).Value);

                        return HttpClientTransport.SendFormPostAsync(host.SharedHttpClient!, endpoint, fields, headers, ct);
                    },
                    saveStateAsync: (_, _, _) => ValueTask.CompletedTask,
                    loadStateAsync: (_, _, _) => ValueTask.FromResult<FlowState?>(null),
                    loadStateByRequestUriAsync: (_, _, _) => ValueTask.FromResult<FlowState?>(null),
                    parseParResponseAsync: OAuthResponseParsers.ParseParResponse,
                    parseTokenResponseAsync: OAuthResponseParsers.ParseTokenResponse,
                    parseRegistrationResponseAsync: (body, ct) =>
                        throw new NotImplementedException("Test does not exercise dynamic registration."),
                    resolveAuthorizationServerMetadataAsync: (_, _, _) =>
                        ValueTask.FromResult(new AuthorizationServerMetadataResolution
                        {
                            Outcome = AuthorizationServerMetadataResolutionOutcome.Resolved,
                            Metadata = metadata
                        }),
                    resolveCallbackValidator: ClientPolicyProfiles.DefaultResolveCallbackValidator,
                    base64UrlEncoder: TestSetup.Base64UrlEncoder,
                    memoryPool: BaseMemoryPool.Shared,
                    timeProvider: TimeProvider,
                    fillEntropy: TestEntropy.NewCounterStream(),
                    generateIdentifierAsync: DefaultIdentifierGenerator.For(TimeProvider, TestEntropy.NewCounterStream(), BaseMemoryPool.Shared),
                    outboundFetchPolicy: TestHostShell.LoopbackOutboundFetchPolicy,
                    constructDpopProofAsync: (claims, key, ct) => DpopProofConstruction.BuildAsync(
                        claims, key, TestSetup.Base64UrlEncoder, DpopTestSupport.Serializer,
                        MicrosoftCryptographicFunctionsAdapter.SignP256Async, BaseMemoryPool.Shared, ct),
                    dpopKey: dpopKey,
                    lookupDpopNonce: nonceCache.Lookup,
                    storeDpopNonce: nonceCache.Store);

                ClientRegistration registration = new()
                {
                    ClientId = new ClientId(ClientId),
                    AuthorizationServerIssuer = material.Registration.IssuerUri!,
                    RedirectUris = [new Uri(ClientId)],
                    AuthenticationMethod = ClientAuthenticationMethod.PrivateKeyJwt,
                    AuthenticationKeyMaterial = clientKeys,
                    Profile = PolicyProfile.Haip10
                };

                OAuthClient client = new(infrastructure);

                AuthCodeFlowEndpointResult result = await client.ClientCredentials.RequestTokenAsync(
                    registration, scope: MachineScope, resource: null, [],
                    clientAssertionOptions: new ClientAssertionOptions
                    {
                        SigningKeyId = SigningKeyId,
                        HeaderSerializer = app.Server.OAuth().Codecs.JwtHeaderSerializer!,
                        PayloadSerializer = app.Server.OAuth().Codecs.JwtPayloadSerializer!
                    },
                    TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, result.Outcome,
                    $"ErrorCode={result.ErrorCode} ErrorDescription={result.ErrorDescription}");
                Assert.HasCount(2, dialedAssertions,
                    "The client must dial the token endpoint twice: once to receive the use_dpop_nonce challenge, once more with the nonce to complete.");
                Assert.AreNotEqual(dialedAssertions[0], dialedAssertions[1],
                    "RFC 9449 §8's retry must present a freshly-signed client_assertion (a new jti), not the same one a client-assertion replay defense would refuse.");
            }
            finally
            {
                dpopKeys.PublicKey.Dispose();
                dpopKeys.PrivateKey.Dispose();
            }
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// Registers a truly client-credentials-only confidential machine client (no
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthAuthorizationCode"/>) and wires a
    /// client_secret_post validator. Grant-only issuance works because
    /// <see cref="Rfc9068AccessTokenProducer"/>'s <c>RequiredCapability</c> is
    /// <see langword="null"/> — an optional tenant-feature gate, not a grant-capability proxy —
    /// so every token-issuing grant's own endpoint-match capability
    /// (here <see cref="WellKnownCapabilityIdentifiers.OAuthClientCredentials"/>) is sufficient
    /// on its own.
    /// </summary>
    /// <param name="app">The host to register the machine client on.</param>
    /// <param name="profile">
    /// The client's policy profile — <see cref="PolicyProfile.Rfc6749WithPkce"/> unless a DPoP test
    /// selects a profile <see cref="ClientPolicyProfiles.RequiresDpop"/> mandates against.
    /// </param>
    private static async Task<VerifierKeyMaterial> RegisterMachineClientAsync(TestHostShell app, PolicyProfile? profile = null)
    {
        //RegisterDpopClient supplies the AccessTokenIssuance signing keys the
        //token producers resolve; the plain RegisterClient helper does not.
        VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId,
            new Uri(ClientId),
            profile: profile ?? PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthClientCredentials,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)).ConfigureAwait(false);

        //RegisterDpopClient fixes AllowedScopes to the OIDC identity scope set; add MachineScope
        //(the register-then-upgrade pattern — the routing dictionaries are host-internal) so a
        //happy-path request retains something once the identity scopes are narrowed away.
        HostedAuthorizationServer host = app.Host("default");
        string segment = material.Registration.TenantId.Value;
        ClientRecord previous = host.Registrations[segment];
        ClientRecord updated = previous with
        {
            AllowedScopes = previous.AllowedScopes.Add(MachineScope)
        };


        updated = await host.UpdateClientAsync(previous, updated, []).ConfigureAwait(false);
        material.Registration = updated;

        //client_secret_post (RFC 6749 §2.3.1): the application owns the secret
        //store and the comparison; this test glue checks the form field.
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
                ValueTask.FromResult(
                    fields.TryGetValue("client_secret", out string? secret)
                    && string.Equals(secret, ClientSecret, StringComparison.Ordinal));
        }).ConfigureAwait(false);

        return material;
    }


    /// <summary>
    /// Even though this tenant is granted the
    /// <see cref="WellKnownCapabilityIdentifiers.OidcOpenIdConnect"/> feature — ruling out the
    /// optional capability gate as the explanation — a <c>client_credentials</c> token request carrying
    /// <c>openid</c> never yields an id_token. <see cref="Oidc10IdTokenProducer"/>'s
    /// <c>IsApplicable</c> independently requires <c>GrantType ∈ {authorization_code,
    /// refresh_token}</c>, and the source-side <c>DropIdentityScopesForNonEndUserGrant</c> already
    /// strips <c>openid</c> before the producer walk even runs — this test pins BOTH layers hold.
    /// </summary>
    [TestMethod]
    public async Task NoIdTokenIsMintedForClientCredentialsEvenWithOpenidRequestedAndOidcFeatureGranted()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId,
            new Uri(ClientId),
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthClientCredentials,
                WellKnownCapabilityIdentifiers.OidcOpenIdConnect,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
                ValueTask.FromResult(
                    fields.TryGetValue("client_secret", out string? secret)
                    && string.Equals(secret, ClientSecret, StringComparison.Ordinal));
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(host.SharedHttpClient!, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        Assert.IsTrue(doc.RootElement.TryGetProperty(WellKnownTokenTypes.AccessToken, out _),
            "An access token must still be minted (the id-token narrowing leaves the access-token producer unaffected).");
        Assert.IsFalse(doc.RootElement.TryGetProperty(WellKnownTokenTypes.IdToken, out _),
            "client_credentials must never carry an id_token even when openid was requested on a "
            + "tenant with the OidcOpenIdConnect feature granted.");
    }


    /// <summary>
    /// <c>client_credentials</c> has no authenticated End-User (the
    /// token's <c>sub</c> is the client itself), so a request carrying <c>openid</c> and every OIDC
    /// Core §5.4 identity scope has them narrowed away (RFC 6749 §3.3) before the granted scope ever
    /// reaches the token — the issued access token's <c>scope</c> claim carries none of them — and
    /// the narrowing emits <see cref="OAuthEventNames.IdentityScopesDroppedForNonEndUserGrant"/>
    /// naming exactly the dropped values.
    /// </summary>
    [TestMethod]
    public async Task OpenidAndIdentityScopesAreDroppedFromClientCredentialsGrantedScopeWithOtelEvent()
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

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterMachineClientAsync(app).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = material.Registration.TenantId.Value;
        string handle = material.Registration.TenantHandle!.Value.Value;
        Uri tokenUrl = new(host.HttpBaseAddress!, $"/connect/{segment}/token");

        //RegisterMachineClient's AllowedScopes (via RegisterDpopClient) is exactly the OIDC identity
        //scope set — every token requested here is an identity scope, so the narrowed grant is empty.
        string requestedScope = string.Join(' ',
            WellKnownScopes.OpenId, WellKnownScopes.Profile, WellKnownScopes.Email,
            WellKnownScopes.Address, WellKnownScopes.Phone);

        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(host.SharedHttpClient!, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.Scope] = requestedScope
        }, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);
        //client_credentials always writes the scope field (unlike pre_authorized_code, which omits
        //it when empty) — every identity token was narrowed away, so it comes back empty.
        Assert.AreEqual(string.Empty, doc.RootElement.GetProperty(OAuthRequestParameterNames.Scope).GetString(),
            "The response scope must be empty once every requested token — all five are identity scopes — is narrowed away.");

        string accessToken = doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
        string[] segments = accessToken.Split('.');
        Assert.HasCount(3, segments);
        byte[] payloadBytes = SecurityEventTestJson.DecodeSegment(segments[1], Pool);
        using JsonDocument payload = JsonDocument.Parse(payloadBytes);
        string issuedScope = payload.RootElement.GetProperty(OAuthRequestParameterNames.Scope).GetString()!;
        Assert.AreEqual(string.Empty, issuedScope,
            "The issued access token's scope claim must be empty — RFC 6749 §3.3 narrowing removed "
            + "every identity token before IssuanceContext.Scope was set.");

        //ActivityListener is process-wide (see the ActivityListener cross-contamination
        //guidance): filter captured activities to this test's tenant before asserting.
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
    /// Adds <see cref="MachineScope"/> to <paramref name="material"/>'s registered
    /// <c>AllowedScopes</c> (the register-then-upgrade pattern — the routing dictionaries are
    /// host-internal), so a request for it is not refused as an unregistered scope. Mirrors
    /// <see cref="RegisterMachineClientAsync"/>'s own upgrade step for the tests that build the
    /// registration by hand rather than through that helper.
    /// </summary>
    private static async Task AddMachineScopeAsync(TestHostShell host, VerifierKeyMaterial material)
    {
        HostedAuthorizationServer host0 = host.Host("default");
        string segment = material.Registration.TenantId.Value;
        ClientRecord previous = host0.Registrations[segment];
        ClientRecord updated = previous with
        {
            AllowedScopes = previous.AllowedScopes.Add(MachineScope)
        };

        material.Registration = await host0.UpdateClientAsync(previous, updated, []).ConfigureAwait(false);
    }


    /// <summary>
    /// Builds a <see cref="PublicPrivateKeyMaterial{TPublicKeyMemory, TPrivateKeyMemory}"/> carrying
    /// <paramref name="secret"/> as the private-key bytes <c>client_secret_post</c>/
    /// <c>client_secret_basic</c> attach as the shared secret. The public half is never read by
    /// either method but the pair type requires one regardless.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership transfers to the caller, which disposes both halves via the returned pair's PublicKey/PrivateKey.")]
    private static PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> BuildSecretKeyMaterial(string secret)
    {
        byte[] secretBytes = Encoding.UTF8.GetBytes(secret);
        IMemoryOwner<byte> secretOwner = Pool.Rent(secretBytes.Length);
        secretBytes.CopyTo(secretOwner.Memory.Span);
        PrivateKeyMemory privateKey = new(secretOwner, Tag.Empty);

        IMemoryOwner<byte> unusedPublicOwner = Pool.Rent(1);
        PublicKeyMemory publicKey = new(unusedPublicOwner, Tag.Empty);

        return new PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>(publicKey, privateKey);
    }




    /// <summary>
    /// Declares <paramref name="method"/> as the client's registered token-endpoint authentication
    /// method (and, for <c>private_key_jwt</c>, publishes <paramref name="clientJwks"/>) and adds it
    /// to the server's advertised <c>ClientAuthenticationMethodsSupported</c> set so the declared-
    /// method-coherence gate admits the exchange.
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
    /// Builds a JWKS JSON document publishing one key under <paramref name="kid"/>, the shape
    /// <see cref="PrivateKeyJwtClientAuthentication.BuildValidator(System.Collections.Generic.IReadOnlyCollection{string}?,CheckClientAssertionJtiReplayDelegate?,Verifiable.OAuth.Server.Pipeline.ResolveJwksUriDelegate?)"/>
    /// resolves the client's signing key from.
    /// </summary>
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
}
