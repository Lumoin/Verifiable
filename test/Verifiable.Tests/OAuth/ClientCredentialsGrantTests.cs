using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Text.Json;
using Verifiable.Core.Outbound;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
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
using Verifiable.Tests.WebFinger;

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

        //A wrong form secret fails client authentication: 400 invalid_client, the default status of
        //RFC 6749 Section 5.2 at a server that advertises no client_secret_basic.
        using HttpResponseMessage badSecret = await OAuthTestTransport.PostFormAsync(http, tokenUrl, new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = "guessed-wrong"
        }, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(400, (int)badSecret.StatusCode);

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
                candidateIntegration.ValidateClientCredentialsAsync = static (reading, registration, context, ct) =>
                    ValueTask.FromResult(AuthCodeFlowDriver.DecodeAndMatchBasicHeader(reading, registration.ClientId, ClientSecret));
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
    /// <see cref="PrivateKeyJwtClientAuthentication.BuildValidator(System.Collections.Generic.IReadOnlyCollection{string}?,CheckClientAssertionJtiReplayDelegate?,Verifiable.OAuth.Server.Pipeline.ResolveJwksUriDelegate?,ClientAssertionAudiencePolicy?)"/>
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
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11#section-4">rfc7523bis-11
    /// Section 4</see>: the <c>aud</c> claim value "MUST indicate only the issuer identifier of the
    /// intended authorization server as the audience of the JWT", and a registration that names neither
    /// <see cref="ClientRegistration.ClientAssertionAudience"/> nor
    /// <see cref="ClientRegistration.IsClientAssertionExplicitlyTyped"/> signs the default
    /// <see cref="ClientAssertionAudience.IssuerIdentifier"/> with the default <c>typ</c>, which is
    /// <c>client-authentication+jwt</c> because "Client authentication JWTs SHOULD be explicitly typed
    /// by using the typ header parameter value client-authentication+jwt or another more specific
    /// explicit type value defined by a specification profiling this specification." Drives the
    /// same fixture as <see cref="ClientComposedRequestIssuesTokenUnderPrivateKeyJwtOverRealWire"/>
    /// with the default server validator
    /// (<see cref="PrivateKeyJwtClientAuthentication.BuildValidator(System.Collections.Generic.IReadOnlyCollection{string}?,CheckClientAssertionJtiReplayDelegate?,Verifiable.OAuth.Server.Pipeline.ResolveJwksUriDelegate?,ClientAssertionAudiencePolicy?)"/>,
    /// no additional accepted audiences) wrapped by <see cref="ClientAssertionRecorder.Wrap"/>, proving
    /// what <see cref="ClientCredentialsClient.RequestTokenAsync"/> actually signed
    /// (the issuer-identifier default of
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11#section-4">rfc7523bis-11
    /// Section 4</see> item b) rather than what the token endpoint merely tolerates.
    /// </summary>
    [TestMethod]
    public async Task ClientCredentialsAssertionNamesTheIssuerByDefaultAsync()
    {
        var clientKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
                ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce,
                capabilities: ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthClientCredentials)).ConfigureAwait(false);
            await AddMachineScopeAsync(host, material).ConfigureAwait(false);

            await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

            string alg = CryptoFormatConversions.DefaultTagToJwaConverter(clientKeys.PublicKey.Tag);
            const string SigningKeyId = "issuer-by-default-key-1";
            IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
                clientKeys.PublicKey, alg, TestSetup.Base64UrlEncoder);
            string jwksJson = BuildJwksJson(jwk, SigningKeyId);

            List<string> recordedAssertions = [];
            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.ValidateClientCredentialsAsync = ClientAssertionRecorder.Wrap(recordedAssertions);
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

            Assert.HasCount(1, recordedAssertions,
                "The client_credentials token request must present exactly one client_assertion.");
            (string typ, JsonElement audience) =
                ClientAssertionRecorder.DecodeTypAndAudience(recordedAssertions[0], Pool);
            Assert.AreEqual("client-authentication+jwt", typ);
            Assert.AreEqual(JsonValueKind.String, audience.ValueKind);
            Assert.AreEqual(registration.AuthorizationServerIssuer.OriginalString, audience.GetString());
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11#section-4">rfc7523bis-11
    /// Section 4</see> item b: the <c>aud</c> claim value "MUST indicate only the issuer identifier of
    /// the intended authorization server as the audience of the JWT; this includes that the token
    /// endpoint URL of the authorization server MUST NOT be used as an audience value." A token endpoint
    /// wired with <see cref="ClientAssertionAudiencePolicy.IssuerIdentifierOnly"/> refuses, over the
    /// real wire, the <c>client_credentials</c> request whose registration names
    /// <see cref="ClientAssertionAudience.TokenEndpoint"/> (the client signs the token endpoint URL as
    /// <c>aud</c>) with the error <c>invalid_client</c>, and authenticates the one whose registration
    /// names <see cref="ClientAssertionAudience.IssuerIdentifier"/>. Drives the same fixture as
    /// <see cref="ClientCredentialsAssertionNamesTheIssuerByDefaultAsync"/>.
    /// </summary>
    /// <param name="isTokenEndpointAudience">
    /// <see langword="true"/> when the registration names <see cref="ClientAssertionAudience.TokenEndpoint"/>,
    /// <see langword="false"/> for <see cref="ClientAssertionAudience.IssuerIdentifier"/>.
    /// </param>
    /// <param name="expectedOutcome">The outcome the client's typed result carries for that audience.</param>
    /// <param name="expectedErrorCode">
    /// The <c>error</c> member of the refusal's JSON body, or <see langword="null"/> when the request
    /// is authenticated.
    /// </param>
    [TestMethod]
    [DataRow(true, AuthCodeFlowEndpointOutcome.BadRequest, "invalid_client", DisplayName = "the registration names the token endpoint URL")]
    [DataRow(false, AuthCodeFlowEndpointOutcome.Ok, null, DisplayName = "the registration names the issuer identifier")]
    public async Task IssuerOnlyPolicyHoldsAtTheTokenEndpointAsync(
        bool isTokenEndpointAudience, AuthCodeFlowEndpointOutcome expectedOutcome, string? expectedErrorCode)
    {
        var clientKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
                ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce,
                capabilities: ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthClientCredentials)).ConfigureAwait(false);
            await AddMachineScopeAsync(host, material).ConfigureAwait(false);

            await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

            string alg = CryptoFormatConversions.DefaultTagToJwaConverter(clientKeys.PublicKey.Tag);
            const string SigningKeyId = "issuer-only-token-endpoint-key-1";
            IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
                clientKeys.PublicKey, alg, TestSetup.Base64UrlEncoder);
            string jwksJson = BuildJwksJson(jwk, SigningKeyId);

            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.ValidateClientCredentialsAsync =
                    PrivateKeyJwtClientAuthentication.BuildValidator(
                        audiencePolicy: ClientAssertionAudiencePolicy.IssuerIdentifierOnly);
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
                AuthenticationKeyMaterial = clientKeys,
                ClientAssertionAudience = isTokenEndpointAudience
                    ? ClientAssertionAudience.TokenEndpoint
                    : ClientAssertionAudience.IssuerIdentifier
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

            Assert.AreEqual(expectedOutcome, result.Outcome,
                $"ErrorCode={result.ErrorCode} ErrorDescription={result.ErrorDescription}");
            Assert.AreEqual(expectedErrorCode, result.ErrorCode,
                $"ErrorDescription={result.ErrorDescription}");
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
                candidateIntegration.ValidateClientCredentialsAsync = static (reading, registration, context, ct) =>
                    ValueTask.FromResult(AuthCodeFlowDriver.DecodeAndMatchBasicHeader(reading, registration.ClientId, ClientSecret));
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
            candidateIntegration.ValidateClientCredentialsAsync = static (reading, registration, context, ct) =>
                ValueTask.FromResult(AuthCodeFlowDriver.DecodeAndMatchBasicHeader(reading, registration.ClientId, ClientSecret));
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
        Assert.AreEqual($"Basic realm=\"{material.Registration.IssuerUri!.OriginalString}\"", challenge,
            "A declared-method authentication failure over Basic must carry the matching WWW-Authenticate challenge.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.4">RFC 9110 Section 11.4</see>:
    /// "credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]", with "auth-scheme    = token" of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.1">RFC 9110 Section 11.1</see>, a token of one
    /// or more characters, so an <c>Authorization</c> field line with an empty value is outside the grammar. A
    /// token request sent over a raw TLS connection with that line beside the client's valid
    /// <c>client_secret</c> is refused 400 <c>invalid_request</c>, the code
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see> names for a
    /// request that is otherwise malformed, and no token is issued.
    /// </summary>
    [TestMethod]
    public async Task AnEmptyAuthorizationLineBesideAValidSecretIsAnInvalidRequest()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterMachineClientAsync(app).ConfigureAwait(false);

        HttpResponseData response = await PostTokenRequestOverARawConnectionAsync(
            app, material, string.Empty,
            [
                new(OAuthRequestParameterNames.GrantType, WellKnownGrantTypes.ClientCredentials),
                new(OAuthRequestParameterNames.ClientId, ClientId),
                new(OAuthRequestParameterNames.ClientSecret, ClientSecret),
                new(OAuthRequestParameterNames.Scope, MachineScope)
            ]).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.AreEqual(
            "{\"error\":\"invalid_request\",\"error_description\":\"The Authorization header is not a single well-formed credential.\"}",
            response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>: "If the client
    /// attempted to authenticate via the "Authorization" request header field, the authorization server MUST respond
    /// with an HTTP 401 (Unauthorized) status code and include the "WWW-Authenticate" response header field matching
    /// the authentication scheme used by the client." and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.5.2">RFC 9110 Section 15.5.2</see>: "The server
    /// generating a 401 response MUST send a WWW-Authenticate header field (Section 11.6.1) containing at least one
    /// challenge applicable to the target resource." A token request of a <c>client_secret_basic</c> client sent
    /// over the wire with <c>Authorization: Bearer x</c>, at a server that advertises <c>client_secret_basic</c>, is
    /// refused 401 <c>invalid_client</c> with one <c>WWW-Authenticate</c> field holding the challenge of the scheme
    /// attempted and the <c>Basic</c> challenge the server applies,
    /// <c>Bearer realm="&lt;issuer&gt;", Basic realm="&lt;issuer&gt;"</c>, the list
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.1">RFC 9110 Section 11.6.1</see> defines,
    /// "WWW-Authenticate = #challenge".
    /// </summary>
    [TestMethod]
    public async Task AFailedAttemptOfAnotherSchemeCarriesItsChallengeAndTheBasicChallenge()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthClientCredentials)).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (reading, registration, context, ct) =>
                ValueTask.FromResult(AuthCodeFlowDriver.DecodeAndMatchBasicHeader(reading, registration.ClientId, ClientSecret));
        }).ConfigureAwait(false);

        await DeclareServerSideAuthMethodAsync(host, material, ClientAuthenticationMethod.ClientSecretBasic)
            .ConfigureAwait(false);

        HttpResponseData response = await PostTokenRequestOverARawConnectionAsync(
            host, material, "Bearer x",
            [new(OAuthRequestParameterNames.GrantType, WellKnownGrantTypes.ClientCredentials)]).ConfigureAwait(false);
        string issuer = host.Host("default").Registrations[material.Registration.TenantId.Value].IssuerUri!.OriginalString;

        Assert.AreEqual(401, response.StatusCode, response.Body);
        Assert.AreEqual(
            "{\"error\":\"invalid_client\",\"error_description\":\"Client authentication failed.\"}", response.Body);
        Assert.AreEqual($"Bearer realm=\"{issuer}\", Basic realm=\"{issuer}\"",
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>: "If the client
    /// attempted to authenticate via the "Authorization" request header field, the authorization server MUST respond
    /// with an HTTP 401 (Unauthorized) status code and include the "WWW-Authenticate" response header field matching
    /// the authentication scheme used by the client." A token request sent over the wire with
    /// <c>Authorization: Bearer x</c>, at a server that does not advertise <c>client_secret_basic</c>, is refused 401
    /// <c>invalid_client</c> with the one challenge of the scheme attempted, <c>Bearer realm="&lt;issuer&gt;"</c>.
    /// </summary>
    [TestMethod]
    public async Task AFailedAttemptOfAnotherSchemeWithoutBasicAdvertisedCarriesItsChallengeAlone()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterMachineClientAsync(app).ConfigureAwait(false);

        HttpResponseData response = await PostTokenRequestOverARawConnectionAsync(
            app, material, "Bearer x",
            [new(OAuthRequestParameterNames.GrantType, WellKnownGrantTypes.ClientCredentials)]).ConfigureAwait(false);
        string issuer = app.Host("default").Registrations[material.Registration.TenantId.Value].IssuerUri!.OriginalString;

        Assert.AreEqual(401, response.StatusCode, response.Body);
        Assert.AreEqual($"Bearer realm=\"{issuer}\"",
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.1">RFC 9110 Section 11.1</see>:
    /// "auth-scheme    = token". The library reads a scheme longer than 20 characters as outside the grammar it
    /// accepts, a policy of this library that bounds a scheme a challenge writes back: the longest name in the
    /// <see href="https://www.iana.org/assignments/http-authschemes/http-authschemes.xhtml">IANA HTTP Authentication
    /// Scheme Registry</see> is <c>SCRAM-SHA-256</c>, 13 characters. A token request sent over the wire with
    /// <c>Authorization: abcdefghijklmnopqrstu x</c>, a 21-character scheme, is refused 400 <c>invalid_request</c>,
    /// the <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see> code for a
    /// request that is otherwise malformed, with no challenge.
    /// </summary>
    [TestMethod]
    public async Task ASchemeLongerThanTwentyCharactersIsAnInvalidRequest()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterMachineClientAsync(app).ConfigureAwait(false);

        HttpResponseData response = await PostTokenRequestOverARawConnectionAsync(
            app, material, "abcdefghijklmnopqrstu x",
            [new(OAuthRequestParameterNames.GrantType, WellKnownGrantTypes.ClientCredentials)]).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.AreEqual(
            "{\"error\":\"invalid_request\",\"error_description\":\"The Authorization header is not a single well-formed credential.\"}",
            response.Body);
        Assert.IsEmpty(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate));
    }


    /// <summary>
    /// A token request sent over the wire with <c>Authorization: Basic</c>, whose registration the application's
    /// materialization seam replaces with a record that is not an OAuth client registration, is answered 500 with
    /// the body <c>{"error":"server_error","error_description":"The server is not ready to serve this request."}</c>
    /// and no challenge: the dispatcher places a client registration on the request before any endpoint runs, so
    /// only a materializer of another family leaves the endpoint without one, and the fault is the server's wiring,
    /// not the caller's credential.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.6.1">RFC 9110 Section 15.6.1</see>: "The 500
    /// (Internal Server Error) status code indicates that the server encountered an unexpected condition that
    /// prevented it from fulfilling the request."
    /// </summary>
    [TestMethod]
    public async Task ATokenRequestServedUnderARegistrationTheEndpointCannotUseIsAServerError()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthClientCredentials)).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (reading, registration, context, ct) =>
                ValueTask.FromResult(AuthCodeFlowDriver.DecodeAndMatchBasicHeader(reading, registration.ClientId, ClientSecret));
            candidateIntegration.MaterializeRegistrationAsync = static (registration, _, _) => ValueTask.FromResult(new RegistrationMaterialization
            {
                Registration = new WebFingerHttpApplication.PlainRegistration
                {
                    ClientId = registration.ClientId,
                    TenantId = registration.TenantId,
                    AllowedCapabilities = registration.AllowedCapabilities
                }
            });
        }).ConfigureAwait(false);

        HttpResponseData response = await PostTokenRequestOverARawConnectionAsync(
            host, material,
            WellKnownAuthenticationSchemes.Basic + " " + Convert.ToBase64String(
                Encoding.UTF8.GetBytes(Uri.EscapeDataString(ClientId) + ":" + Uri.EscapeDataString(ClientSecret))),
            [new(OAuthRequestParameterNames.GrantType, WellKnownGrantTypes.ClientCredentials)]).ConfigureAwait(false);

        Assert.AreEqual(500, response.StatusCode, response.Body);
        Assert.AreEqual(
            /*lang=json,strict*/ "{\"error\":\"server_error\",\"error_description\":\"The server is not ready to serve this request.\"}",
            response.Body);
        Assert.IsEmpty(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7617#section-2">RFC 7617 Section 2</see>: "The authentication
    /// parameter 'realm' is REQUIRED ([RFC7235], Section 2.2)." The challenge of a failed <c>Basic</c> attempt names
    /// the issuer the request is served under as its realm, so where no issuer resolves (no application issuer
    /// resolver, a registration without an issuer and no issuer on the request's context) there is no challenge to
    /// send: a token request of a <c>client_secret_basic</c> client sent over the wire with a wrong secret in
    /// <c>Authorization: Basic</c> is refused 400 <c>invalid_client</c> with no challenge, the default status of
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>. The section's
    /// 401 for an attempt in the <c>Authorization</c> field is not sent here, a named deviation of the library.
    /// </summary>
    [TestMethod]
    public async Task AFailedBasicAttemptWhereNoIssuerResolvesIsABadRequestWithoutAChallenge()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthClientCredentials)).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (reading, registration, context, ct) =>
                ValueTask.FromResult(AuthCodeFlowDriver.DecodeAndMatchBasicHeader(reading, registration.ClientId, ClientSecret));
        }).ConfigureAwait(false);

        await DeclareServerSideAuthMethodAsync(host, material, ClientAuthenticationMethod.ClientSecretBasic)
            .ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        ClientRecord withoutIssuer = hosted.Registrations[material.Registration.TenantId.Value] with { IssuerUri = null };
        hosted.Registrations[withoutIssuer.TenantId.Value] = withoutIssuer;
        hosted.Registrations[withoutIssuer.ClientId] = withoutIssuer;

        HttpResponseData response = await PostTokenRequestOverARawConnectionAsync(
            host, material,
            WellKnownAuthenticationSchemes.Basic + " " + Convert.ToBase64String(
                Encoding.UTF8.GetBytes(Uri.EscapeDataString(ClientId) + ":" + Uri.EscapeDataString("wrong-secret"))),
            [new(OAuthRequestParameterNames.GrantType, WellKnownGrantTypes.ClientCredentials)]).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.AreEqual(
            "{\"error\":\"invalid_client\",\"error_description\":\"Client authentication failed.\"}", response.Body);
        Assert.IsEmpty(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate));
    }


    /// <summary>
    /// Posts a token request over a raw TLS connection to <paramref name="material"/>'s token endpoint, starting the
    /// listener first: the form <paramref name="formFields"/> in the order given and one <c>Authorization</c> field
    /// line holding <paramref name="authorization"/> as written, an empty value included, through
    /// <see cref="RawHttpsRequest.SendAsync"/>.
    /// </summary>
    /// <param name="host">The fixture serving the registration.</param>
    /// <param name="material">The registration whose token endpoint is addressed.</param>
    /// <param name="authorization">The value of the one <c>Authorization</c> field line.</param>
    /// <param name="formFields">The form fields, sent as given.</param>
    /// <returns>The wire response.</returns>
    private async Task<HttpResponseData> PostTokenRequestOverARawConnectionAsync(
        TestHostShell host,
        VerifierKeyMaterial material,
        string authorization,
        IReadOnlyList<KeyValuePair<string, string>> formFields)
    {
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Uri tokenUrl = new(host.Host("default").HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");
        string form = string.Join('&', formFields.Select(static pair => Uri.EscapeDataString(pair.Key) + "=" + Uri.EscapeDataString(pair.Value)));

        return await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, tokenUrl,
            [
                new(WellKnownHttpHeaderNames.ContentType, WellKnownMediaTypes.Application.FormUrlEncoded),
                new(WellKnownHttpHeaderNames.Authorization, authorization)
            ],
            Encoding.ASCII.GetBytes(form), TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// <see cref="Verifiable.Core.Outbound.OutboundFetchPolicy.SecureDefault"/> refuses a
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
                ValueTask.FromResult<AuthorizationServerMetadataResolution>(new AuthorizationServerMetadataResolved
                {
                    MetadataLocation = WellKnownPaths.OAuthAuthorizationServer.ComputeUri(metadata.Issuer.OriginalString),
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
            candidateIntegration.ValidateClientCredentialsAsync = (reading, registration, context, ct) =>
            {
                dialCount++;

                return ValueTask.FromResult(true);
            };
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
                    ValueTask.FromResult<AuthorizationServerMetadataResolution>(new AuthorizationServerMetadataResolved
                    {
                        MetadataLocation = WellKnownPaths.OAuthAuthorizationServer.ComputeUri(metadata.Issuer.OriginalString),
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
    /// <see cref="PrivateKeyJwtClientAuthentication.BuildValidator(System.Collections.Generic.IReadOnlyCollection{string}?,CheckClientAssertionJtiReplayDelegate?,Verifiable.OAuth.Server.Pipeline.ResolveJwksUriDelegate?,ClientAssertionAudiencePolicy?)"/>
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
                        checkJtiReplayAsync: JtiReplayGuard.ConsultClientAssertionAsync);
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
                        ValueTask.FromResult<AuthorizationServerMetadataResolution>(new AuthorizationServerMetadataResolved
                        {
                            MetadataLocation = WellKnownPaths.OAuthAuthorizationServer.ComputeUri(metadata.Issuer.OriginalString),
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
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.1">RFC 9449 Section 4.1</see>: "Note that per
    /// [RFC9110], header field names are case insensitive; thus, DPoP, DPOP, dpop, etc., are all valid and
    /// equivalent header field names." A <c>client_credentials</c> request sent to the token endpoint over a raw
    /// TLS connection with a valid proof, carrying the nonce the endpoint supplied, in a field whose name is
    /// spelled <c>dpop</c> or <c>DPOP</c>, is answered 200 with <c>token_type</c> <c>DPoP</c>: the proof was read
    /// and bound the access token.
    /// </summary>
    /// <param name="fieldName">The spelling of the field name the proof is sent under.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("dpop")]
    [DataRow("DPOP")]
    public async Task TokenEndpointReadsTheProofUnderAnySpellingOfTheDpopFieldNameAsync(string fieldName)
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterMachineClientAsync(app).ConfigureAwait(false);
        Uri tokenUrl = await StartDpopTokenEndpointAsync(app, material).ConfigureAwait(false);
        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;
        DpopKey dpopKey = new(holderKeys, WellKnownJwaValues.Es256);

        string nonce = await ObtainTokenEndpointNonceAsync(app, tokenUrl, dpopKey).ConfigureAwait(false);
        string proof = await BuildTokenProofAsync(dpopKey, tokenUrl, nonce).ConfigureAwait(false);
        HttpResponseData response = await RawHttpsRequest.SendAsync(
            app, WellKnownHttpMethods.Post, tokenUrl,
            [
                new(WellKnownHttpHeaderNames.ContentType, WellKnownMediaTypes.Application.FormUrlEncoded),
                new(fieldName, proof)
            ],
            Encoding.ASCII.GetBytes(MachineTokenRequestForm()), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        using JsonDocument document = JsonDocument.Parse(response.Body);
        Assert.AreEqual(WellKnownAuthenticationSchemes.DPoP, document.RootElement.GetProperty("token_type").GetString(),
            "The proof sent under this spelling of the field name binds the access token.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 Section 8</see>: "Nonce values MUST be
    /// unpredictable." Four <c>client_credentials</c> requests sent to the token endpoint over the wire at one
    /// instant, each with a proof carrying no nonce, are each answered 400 <c>use_dpop_nonce</c> with a
    /// <c>DPoP-Nonce</c>, and the four nonces differ from one another. The row shows distinctness at one instant, a
    /// condition of unpredictability and not the whole of it; that each nonce carries the random bytes its issuer drew
    /// is the row <see cref="TokenEndpointNonceCarriesTheRandomBytesItsIssuerDrewAsync"/>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task TokenEndpointSuppliesADistinctNonceInEveryChallengeAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterMachineClientAsync(app).ConfigureAwait(false);
        Uri tokenUrl = await StartDpopTokenEndpointAsync(app, material).ConfigureAwait(false);
        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;
        DpopKey dpopKey = new(holderKeys, WellKnownJwaValues.Es256);

        List<string> nonces = [];
        for(int challenge = 0; challenge < 4; challenge++)
        {
            nonces.Add(await ObtainTokenEndpointNonceAsync(app, tokenUrl, dpopKey).ConfigureAwait(false));
        }

        Assert.HasCount(4, nonces.Distinct(StringComparer.Ordinal), $"Every challenge supplies another nonce: {string.Join(" ", nonces)}");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 Section 8</see>: "This same error
    /// code is used when supplying a new nonce value when there was a nonce mismatch." A <c>client_credentials</c>
    /// request sent to the token endpoint over the wire with a proof whose <c>nonce</c> does not match what the
    /// server supplied is answered 400 with <c>error</c> <c>use_dpop_nonce</c> and one <c>DPoP-Nonce</c> carrying a
    /// new nonce, not the one presented. The rows: the supplied nonce with one character changed; and the supplied
    /// nonce presented after the server's window for it has passed.
    /// </summary>
    /// <param name="row">How the presented nonce fails to match.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(NonceCharacterChangedRow)]
    [DataRow(NonceWindowPassedRow)]
    public async Task TokenEndpointAnswersANonceMismatchWithUseDpopNonceAndANewNonceAsync(string row)
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterMachineClientAsync(app).ConfigureAwait(false);
        Uri tokenUrl = await StartDpopTokenEndpointAsync(app, material).ConfigureAwait(false);
        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;
        DpopKey dpopKey = new(holderKeys, WellKnownJwaValues.Es256);

        string supplied = await ObtainTokenEndpointNonceAsync(app, tokenUrl, dpopKey).ConfigureAwait(false);
        string presented = row switch
        {
            NonceCharacterChangedRow => ChangeMiddleCharacter(supplied),
            NonceWindowPassedRow => supplied,
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown nonce row.")
        };
        if(row == NonceWindowPassedRow)
        {
            TimeProvider.Advance(WellKnownDpopValues.DefaultNonceValidityWindow + TimeSpan.FromMinutes(1));
        }

        string proof = await BuildTokenProofAsync(dpopKey, tokenUrl, presented).ConfigureAwait(false);
        (int statusCode, string body, IReadOnlyList<string> nonces) = await PostMachineTokenRequestAsync(app, tokenUrl, proof).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, body);
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual(OAuthErrors.UseDpopNonce, document.RootElement.GetProperty("error").GetString());
        string newNonce = Assert.ContainsSingle(nonces);
        Assert.AreNotEqual(presented, newNonce, "The rejection supplies a new nonce.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 Section 8</see>: "If the nonce claim
    /// in the DPoP proof does not exactly match a nonce recently supplied by the authorization server to the
    /// client, the authorization server MUST reject the request." A <c>client_credentials</c> request sent to the
    /// token endpoint over the wire with a valid proof whose <c>nonce</c> is the supplied nonce with one character
    /// added, or with the case of its first letter changed, is rejected: 400 and no access token in the body. The
    /// check is item 10 of <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">Section 4.3</see> at the
    /// token endpoint as well: "If the server provided a nonce value to the client, the nonce claim matches the
    /// server-provided nonce value."
    /// </summary>
    /// <param name="row">How the presented nonce differs from the supplied one.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(NonceCharacterAddedRow)]
    [DataRow(NonceCaseChangedRow)]
    public async Task TokenEndpointRejectsAProofWhoseNonceIsNotExactlyOneItSuppliedAsync(string row)
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterMachineClientAsync(app).ConfigureAwait(false);
        Uri tokenUrl = await StartDpopTokenEndpointAsync(app, material).ConfigureAwait(false);
        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;
        DpopKey dpopKey = new(holderKeys, WellKnownJwaValues.Es256);

        string supplied = await ObtainTokenEndpointNonceAsync(app, tokenUrl, dpopKey).ConfigureAwait(false);
        string presented = row switch
        {
            NonceCharacterAddedRow => supplied + "A",
            NonceCaseChangedRow => ChangeCaseOfFirstLetter(supplied),
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown nonce row.")
        };
        Assert.AreNotEqual(supplied, presented);

        string proof = await BuildTokenProofAsync(dpopKey, tokenUrl, presented).ConfigureAwait(false);
        (int statusCode, string body, _) = await PostMachineTokenRequestAsync(app, tokenUrl, proof).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, body);
        Assert.DoesNotContain(WellKnownTokenTypes.AccessToken, body, "A proof whose nonce the server did not supply never mints an access token.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 Section 8</see>: "If the nonce claim in the
    /// DPoP proof does not exactly match a nonce recently supplied by the authorization server to the client, the
    /// authorization server MUST reject the request." A <c>client_credentials</c> request sent to the token endpoint over
    /// the wire with a valid proof whose <c>nonce</c> decodes to the octets the endpoint supplied, or begins with them,
    /// but is not the text it supplied, is rejected: 400 with <c>error</c> <c>use_dpop_nonce</c> and no access token in
    /// the body. The endpoint's nonce key is <see cref="ResourceDpopProofs.PartialGroupNonceKeyId"/>, so its nonces end
    /// in a partial base64url group. The rows: the supplied octets and one more octet, written canonically; the supplied
    /// nonce with a space inside it; the supplied nonce with its <c>=</c> padding; and the supplied nonce with a pad bit
    /// of its last character set. The space and the <c>=</c> are characters outside the base64url alphabet
    /// (<see href="https://www.rfc-editor.org/rfc/rfc4648#section-5">RFC 4648 Section 5</see>, Table 2, written without
    /// padding by <see href="https://www.rfc-editor.org/rfc/rfc7515#section-2">RFC 7515 Section 2</see>), and
    /// <see href="https://www.rfc-editor.org/rfc/rfc4648#section-3.3">RFC 4648 Section 3.3</see> reads: "Implementations
    /// MUST reject the encoded data if it contains characters outside the base alphabet when interpreting base-encoded
    /// data, unless the specification referring to this document explicitly states otherwise".
    /// </summary>
    /// <param name="row">How the presented nonce spells or extends the supplied one.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(NonceExtendedByAnOctetRow)]
    [DataRow(NonceWithASpaceInsideRow)]
    [DataRow(NoncePaddedRow)]
    [DataRow(NonceWithAPadBitSetRow)]
    public async Task TokenEndpointRejectsANonceThatIsNotTheTextItSuppliedAsync(string row)
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterMachineClientAsync(app).ConfigureAwait(false);
        _ = await app.EnableDpopAsync(ResourceDpopProofs.PartialGroupNonceKeyId).ConfigureAwait(false);
        Uri tokenUrl = await StartDpopTokenEndpointAsync(app, material).ConfigureAwait(false);
        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;
        DpopKey dpopKey = new(holderKeys, WellKnownJwaValues.Es256);

        string supplied = await ObtainTokenEndpointNonceAsync(app, tokenUrl, dpopKey).ConfigureAwait(false);
        string presented = row switch
        {
            NonceExtendedByAnOctetRow => ResourceDpopProofs.ExtendNonceByAnOctet(supplied),
            NonceWithASpaceInsideRow => supplied.Insert(supplied.Length / 2, " "),
            NoncePaddedRow => ResourceDpopProofs.PadNonce(supplied),
            NonceWithAPadBitSetRow => ResourceDpopProofs.SetUnusedBitsOfNonce(supplied),
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown nonce row.")
        };
        Assert.AreNotEqual(supplied, presented);

        string proof = await BuildTokenProofAsync(dpopKey, tokenUrl, presented).ConfigureAwait(false);
        (int statusCode, string body, _) = await PostMachineTokenRequestAsync(app, tokenUrl, proof).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, $"A nonce that is not the text the endpoint supplied is rejected: {body}");
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual(OAuthErrors.UseDpopNonce, document.RootElement.GetProperty("error").GetString());
        Assert.DoesNotContain(WellKnownTokenTypes.AccessToken, body, "A proof whose nonce the server did not supply never mints an access token.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 Section 8</see>: "Upon receiving the nonce,
    /// the client is expected to retry its token request using a DPoP proof including the supplied nonce value in the
    /// nonce claim of the DPoP proof." The token endpoint's nonce key is
    /// <see cref="ResourceDpopProofs.PartialGroupNonceKeyId"/>, so the nonce it supplies ends in a partial base64url
    /// group; a <c>client_credentials</c> request sent over the wire with a proof carrying that nonce exactly as supplied
    /// is answered 200 with <c>token_type</c> <c>DPoP</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task TokenEndpointAcceptsTheNonceItSuppliedEndingInAPartialGroupAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterMachineClientAsync(app).ConfigureAwait(false);
        _ = await app.EnableDpopAsync(ResourceDpopProofs.PartialGroupNonceKeyId).ConfigureAwait(false);
        Uri tokenUrl = await StartDpopTokenEndpointAsync(app, material).ConfigureAwait(false);
        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;
        DpopKey dpopKey = new(holderKeys, WellKnownJwaValues.Es256);

        string supplied = await ObtainTokenEndpointNonceAsync(app, tokenUrl, dpopKey).ConfigureAwait(false);
        Assert.AreNotEqual(0, supplied.Length % 4, $"The supplied nonce ends in a partial group: '{supplied}'.");
        string proof = await BuildTokenProofAsync(dpopKey, tokenUrl, supplied).ConfigureAwait(false);
        (int statusCode, string body, _) = await PostMachineTokenRequestAsync(app, tokenUrl, proof).ConfigureAwait(false);

        Assert.AreEqual(200, statusCode, $"The nonce as supplied is accepted: {body}");
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual(WellKnownAuthenticationSchemes.DPoP, document.RootElement.GetProperty("token_type").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 Section 8</see>: "If the nonce claim in the
    /// DPoP proof does not exactly match a nonce recently supplied by the authorization server to the client, the
    /// authorization server MUST reject the request." A decoder may read another spelling as the supplied octets.
    /// <see href="https://www.rfc-editor.org/rfc/rfc4648#section-3.5">RFC 4648 Section 3.5</see>: "decoders MAY chose to
    /// reject an encoding if the pad bits have not been set to zero", so a conforming decoder may read a set pad bit.
    /// <see href="https://www.rfc-editor.org/rfc/rfc4648#section-3.3">RFC 4648 Section 3.3</see>: "Implementations MUST
    /// reject the encoded data if it contains characters outside the base alphabet when interpreting base-encoded data,
    /// unless the specification referring to this document explicitly states otherwise", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-2">RFC 7515 Section 2</see> states no such exception
    /// for base64url, whose alphabet is <see href="https://www.rfc-editor.org/rfc/rfc4648#section-5">Section 5</see>'s
    /// Table 2: a decoder that reads the base64 characters <c>+</c> and <c>/</c> as the base64url <c>-</c> and <c>_</c>
    /// is outside Section 3.3, and for such a decoder the validator's own check of the base64url alphabet is what holds
    /// the exact match. The token endpoint's nonce validation is wired with
    /// <see cref="ResourceDpopProofs.PermissiveBase64UrlDecoder"/>, which reads both, and its issuance with
    /// <see cref="ResourceDpopProofs.RandomFieldOfOnes"/>, so the supplied text holds a <c>_</c>. A
    /// <c>client_credentials</c> request sent over the wire with a proof whose <c>nonce</c> that decoder reads as the
    /// supplied octets, but which is not the supplied text, is rejected: 400 with <c>error</c> <c>use_dpop_nonce</c>,
    /// the refusal answered with a <c>DPoP-Nonce</c> field, and no access token. The rows: the supplied text with the
    /// lowest pad bit of its last character set, with the highest pad bit of its last character set, and with its first
    /// <c>-</c> or <c>_</c> written <c>+</c> or <c>/</c>; each under a nonce HMAC key whose identifier is 12 octets (an
    /// 85-octet nonce, four pad bits) and 13 octets (86 octets, two pad bits).
    /// </summary>
    /// <param name="keyIdRow">The nonce HMAC key, by the length of its identifier.</param>
    /// <param name="spellingRow">How the presented nonce spells the supplied octets.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(TwelveOctetKeyIdRow, PadBitSetSpellingRow)]
    [DataRow(TwelveOctetKeyIdRow, HighestPadBitSetSpellingRow)]
    [DataRow(TwelveOctetKeyIdRow, Base64CharacterSpellingRow)]
    [DataRow(ThirteenOctetKeyIdRow, PadBitSetSpellingRow)]
    [DataRow(ThirteenOctetKeyIdRow, HighestPadBitSetSpellingRow)]
    [DataRow(ThirteenOctetKeyIdRow, Base64CharacterSpellingRow)]
    public async Task TokenEndpointRejectsAnotherSpellingOfTheSuppliedNonceItsDecoderReadsAsync(string keyIdRow, string spellingRow)
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterMachineClientAsync(app).ConfigureAwait(false);
        Uri tokenUrl = await StartDpopTokenEndpointUnderThePermissiveDecoderAsync(app, material, keyIdRow).ConfigureAwait(false);
        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;
        DpopKey dpopKey = new(holderKeys, WellKnownJwaValues.Es256);

        string supplied = await ObtainTokenEndpointNonceAsync(app, tokenUrl, dpopKey).ConfigureAwait(false);
        string presented = spellingRow switch
        {
            PadBitSetSpellingRow => ResourceDpopProofs.SetUnusedBitsOfNonce(supplied),
            HighestPadBitSetSpellingRow => ResourceDpopProofs.SetHighestUnusedBitOfNonce(supplied),
            Base64CharacterSpellingRow => ResourceDpopProofs.SpellNonceInTheBase64Alphabet(supplied),
            _ => throw new ArgumentOutOfRangeException(nameof(spellingRow), spellingRow, "Unknown spelling row.")
        };
        Assert.AreNotEqual(supplied, presented);
        Assert.IsTrue(ResourceDpopProofs.IsReadAsTheSuppliedOctetsByThePermissiveDecoder(presented, supplied),
            "The wired decoder reads the presented spelling as the supplied octets.");

        string proof = await BuildTokenProofAsync(dpopKey, tokenUrl, presented).ConfigureAwait(false);
        (int statusCode, string body, IReadOnlyList<string> nonces) = await PostMachineTokenRequestAsync(app, tokenUrl, proof).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, $"A spelling of the supplied octets that is not the supplied text is rejected: {body}");
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual(OAuthErrors.UseDpopNonce, document.RootElement.GetProperty("error").GetString());
        string answeredNonce = Assert.ContainsSingle(nonces, "The refusal is answered with one DPoP-Nonce field.");
        Assert.AreNotEqual(presented, answeredNonce, "The DPoP-Nonce the refusal is answered with is not the refused spelling.");
        Assert.DoesNotContain(WellKnownTokenTypes.AccessToken, body, "A proof whose nonce the server did not supply never mints an access token.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 Section 8</see>: "Upon receiving the nonce,
    /// the client is expected to retry its token request using a DPoP proof including the supplied nonce value in the
    /// nonce claim of the DPoP proof." Under the wiring of
    /// <see cref="TokenEndpointRejectsAnotherSpellingOfTheSuppliedNonceItsDecoderReadsAsync"/> (the nonce validation reading
    /// through <see cref="ResourceDpopProofs.PermissiveBase64UrlDecoder"/>), a <c>client_credentials</c> request sent over
    /// the wire with a proof carrying the nonce exactly as supplied is answered 200 with <c>token_type</c> <c>DPoP</c>,
    /// under a nonce key of 12 octets and of 13 octets: the decoder reads the supplied text, so the refusals of the other
    /// spellings are the validator's.
    /// </summary>
    /// <param name="keyIdRow">The nonce key, by the length of its identifier.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(TwelveOctetKeyIdRow)]
    [DataRow(ThirteenOctetKeyIdRow)]
    public async Task TokenEndpointAcceptsTheSuppliedNonceUnderAPermissiveDecoderAsync(string keyIdRow)
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterMachineClientAsync(app).ConfigureAwait(false);
        Uri tokenUrl = await StartDpopTokenEndpointUnderThePermissiveDecoderAsync(app, material, keyIdRow).ConfigureAwait(false);
        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;
        DpopKey dpopKey = new(holderKeys, WellKnownJwaValues.Es256);

        string supplied = await ObtainTokenEndpointNonceAsync(app, tokenUrl, dpopKey).ConfigureAwait(false);
        string proof = await BuildTokenProofAsync(dpopKey, tokenUrl, supplied).ConfigureAwait(false);
        (int statusCode, string body, _) = await PostMachineTokenRequestAsync(app, tokenUrl, proof).ConfigureAwait(false);

        Assert.AreEqual(200, statusCode, $"The nonce as supplied is accepted: {body}");
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual(WellKnownAuthenticationSchemes.DPoP, document.RootElement.GetProperty("token_type").GetString());
    }


    /// <summary>
    /// Wires DPoP on the host under the nonce key <paramref name="keyIdRow"/> names, its nonce validation reading through
    /// <see cref="ResourceDpopProofs.PermissiveBase64UrlDecoder"/> and its issuance filling the random field from
    /// <see cref="ResourceDpopProofs.RandomFieldOfOnes"/>, then starts the token endpoint
    /// (<see cref="StartDpopTokenEndpointAsync"/>).
    /// </summary>
    /// <param name="app">The host.</param>
    /// <param name="material">The machine registration.</param>
    /// <param name="keyIdRow">The nonce key, by the length of its identifier.</param>
    /// <returns>The absolute token endpoint URL on the listener.</returns>
    private async Task<Uri> StartDpopTokenEndpointUnderThePermissiveDecoderAsync(TestHostShell app, VerifierKeyMaterial material, string keyIdRow)
    {
        string keyId = keyIdRow switch
        {
            TwelveOctetKeyIdRow => ResourceDpopProofs.PartialGroupNonceKeyId,
            ThirteenOctetKeyIdRow => ResourceDpopProofs.TwoOctetFinalQuantumNonceKeyId,
            _ => throw new ArgumentOutOfRangeException(nameof(keyIdRow), keyIdRow, "Unknown key identifier row.")
        };
        _ = await app.EnableDpopAsync(keyId).ConfigureAwait(false);
        await app.ValidateDpopNoncesWithDecoderAsync(ResourceDpopProofs.PermissiveBase64UrlDecoder).ConfigureAwait(false);
        await app.IssueDpopNoncesFromEntropyAsync(ResourceDpopProofs.RandomFieldOfOnes).ConfigureAwait(false);

        return await StartDpopTokenEndpointAsync(app, material).ConfigureAwait(false);
    }


    /// <summary>The row of a permissive-decoder test whose nonce key identifier is 12 octets, its nonces 85 octets.</summary>
    private const string TwelveOctetKeyIdRow = "twelve-octet-key-identifier";

    /// <summary>The row of a permissive-decoder test whose nonce key identifier is 13 octets, its nonces 86 octets.</summary>
    private const string ThirteenOctetKeyIdRow = "thirteen-octet-key-identifier";

    /// <summary>The row of a permissive-decoder test whose presented nonce is the supplied one with the lowest pad bit of its last character set.</summary>
    private const string PadBitSetSpellingRow = "pad-bit-set";

    /// <summary>The row of a permissive-decoder test whose presented nonce is the supplied one with the highest pad bit of its last character set.</summary>
    private const string HighestPadBitSetSpellingRow = "highest-pad-bit-set";

    /// <summary>The row of a permissive-decoder test whose presented nonce writes the supplied one's first <c>-</c> or <c>_</c> as <c>+</c> or <c>/</c>.</summary>
    private const string Base64CharacterSpellingRow = "base64-character";


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 Section 8</see>: "The rejection
    /// response MAY include a DPoP-Nonce HTTP header providing a new nonce value to use for subsequent requests."
    /// The server takes the option: a <c>client_credentials</c> request sent to the token endpoint over the wire
    /// with a proof whose <c>nonce</c> is the supplied nonce with one character changed is rejected with 400 and one
    /// <c>DPoP-Nonce</c>, and the next request, whose proof carries that nonce, is answered 200 with
    /// <c>token_type</c> <c>DPoP</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task TokenEndpointRejectionOfAMismatchedNonceSuppliesTheNonceOfTheNextRequestAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterMachineClientAsync(app).ConfigureAwait(false);
        Uri tokenUrl = await StartDpopTokenEndpointAsync(app, material).ConfigureAwait(false);
        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;
        DpopKey dpopKey = new(holderKeys, WellKnownJwaValues.Es256);

        string supplied = await ObtainTokenEndpointNonceAsync(app, tokenUrl, dpopKey).ConfigureAwait(false);
        string mismatched = await BuildTokenProofAsync(dpopKey, tokenUrl, ChangeMiddleCharacter(supplied)).ConfigureAwait(false);
        (int rejectedStatus, string rejectedBody, IReadOnlyList<string> rejectionNonces) =
            await PostMachineTokenRequestAsync(app, tokenUrl, mismatched).ConfigureAwait(false);
        Assert.AreEqual(400, rejectedStatus, rejectedBody);
        string newNonce = Assert.ContainsSingle(rejectionNonces, "The rejection provides a new nonce.");

        string proof = await BuildTokenProofAsync(dpopKey, tokenUrl, newNonce).ConfigureAwait(false);
        (int statusCode, string body, _) = await PostMachineTokenRequestAsync(app, tokenUrl, proof).ConfigureAwait(false);

        Assert.AreEqual(200, statusCode, body);
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual(WellKnownAuthenticationSchemes.DPoP, document.RootElement.GetProperty("token_type").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 Section 8</see>: "Other HTTP headers
    /// and JSON fields MAY also be included in the error response, but there MUST NOT be more than one DPoP-Nonce
    /// header." A <c>client_credentials</c> request sent to the token endpoint over a raw TLS connection with a proof
    /// carrying no nonce is answered 400 <c>use_dpop_nonce</c>, and the response head carries exactly one
    /// <c>DPoP-Nonce</c> field line.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task TokenEndpointNonceChallengeCarriesOneDpopNonceFieldAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterMachineClientAsync(app).ConfigureAwait(false);
        Uri tokenUrl = await StartDpopTokenEndpointAsync(app, material).ConfigureAwait(false);
        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;
        DpopKey dpopKey = new(holderKeys, WellKnownJwaValues.Es256);

        HttpResponseData response = await PostNonceLessProofOverARawConnectionAsync(app, tokenUrl, dpopKey).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.Contains(OAuthErrors.UseDpopNonce, response.Body);
        string nonce = Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.DPoPNonce),
            "The challenge carries exactly one DPoP-Nonce field line.");
        Assert.IsFalse(string.IsNullOrEmpty(nonce), "The one DPoP-Nonce field carries a nonce.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8.2">RFC 9449 Section 8.2</see>: "The DPoP-Nonce
    /// HTTP header field uses the nonce syntax defined in Section 8.1.", Figure 22: <c>nonce = 1*NQCHAR</c>. A
    /// <c>client_credentials</c> request sent to the token endpoint over a raw TLS connection with a proof carrying
    /// no nonce is answered 400 <c>use_dpop_nonce</c>, and the <c>DPoP-Nonce</c> field value, read as received, is
    /// one or more NQCHAR.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task TokenEndpointWritesTheNonceInTheNonceSyntaxAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterMachineClientAsync(app).ConfigureAwait(false);
        Uri tokenUrl = await StartDpopTokenEndpointAsync(app, material).ConfigureAwait(false);
        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;
        DpopKey dpopKey = new(holderKeys, WellKnownJwaValues.Es256);

        HttpResponseData response = await PostNonceLessProofOverARawConnectionAsync(app, tokenUrl, dpopKey).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        string nonce = Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.DPoPNonce));
        Assert.IsTrue(DpopWireReading.IsNonceSyntax(nonce), $"The DPoP-Nonce value is 1*NQCHAR: '{nonce}'.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8.2">RFC 9449 Section 8.2</see>: "Responses that
    /// include the DPoP-Nonce HTTP header should be uncacheable (e.g., using Cache-Control: no-store in response to
    /// a GET request) to prevent the response from being used to serve a subsequent request and a stale nonce
    /// value from being used as a result." A <c>client_credentials</c> request sent to the token endpoint over a raw
    /// TLS connection with a proof carrying no nonce is answered 400 with a <c>DPoP-Nonce</c>, and no cache may
    /// store the response (<see href="https://www.rfc-editor.org/rfc/rfc9111#section-3">RFC 9111 Section 3</see>): the
    /// response to a POST is cacheable only with explicit freshness and a <c>Content-Location</c> naming the POST's
    /// target URI (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-9.3.3">RFC 9110 Section 9.3.3</see>), and
    /// the response carries neither.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task TokenEndpointNonceChallengeIsNotStorableByACacheAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterMachineClientAsync(app).ConfigureAwait(false);
        Uri tokenUrl = await StartDpopTokenEndpointAsync(app, material).ConfigureAwait(false);
        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;
        DpopKey dpopKey = new(holderKeys, WellKnownJwaValues.Es256);

        HttpResponseData response = await PostNonceLessProofOverARawConnectionAsync(app, tokenUrl, dpopKey).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.IsNotEmpty(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.DPoPNonce), "The challenge carries a DPoP-Nonce.");
        Assert.IsFalse(DpopWireReading.IsStorableByACache(WellKnownHttpMethods.Post, tokenUrl, response.StatusCode, response.Headers.Headers),
            "A response carrying a DPoP-Nonce is not storable by a cache.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 Section 11.1</see>: "Unlike
    /// cryptographic nonces, it is acceptable for clients to use the same nonce multiple times and for the server
    /// to accept the same nonce multiple times." Two <c>client_credentials</c> requests sent to the token endpoint
    /// over the wire one after the other, their proofs distinct in <c>jti</c> and both carrying the one nonce the
    /// endpoint supplied, are both answered 200 with <c>token_type</c> <c>DPoP</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task TokenEndpointAcceptsTheNonceItSuppliedInSeveralProofsAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterMachineClientAsync(app).ConfigureAwait(false);
        Uri tokenUrl = await StartDpopTokenEndpointAsync(app, material).ConfigureAwait(false);
        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;
        DpopKey dpopKey = new(holderKeys, WellKnownJwaValues.Es256);

        string nonce = await ObtainTokenEndpointNonceAsync(app, tokenUrl, dpopKey).ConfigureAwait(false);
        foreach(string jti in (string[])["first-proof-of-the-nonce", "second-proof-of-the-nonce"])
        {
            string proof = await BuildTokenProofAsync(dpopKey, tokenUrl, nonce, jti).ConfigureAwait(false);
            (int statusCode, string body, _) = await PostMachineTokenRequestAsync(app, tokenUrl, proof).ConfigureAwait(false);

            Assert.AreEqual(200, statusCode, $"The proof '{jti}' carrying the supplied nonce is accepted: {body}");
            using JsonDocument document = JsonDocument.Parse(body);
            Assert.AreEqual(WellKnownAuthenticationSchemes.DPoP, document.RootElement.GetProperty("token_type").GetString());
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.6">RFC 9449 Section 11.6</see>: "In particular,
    /// the algorithm none MUST NOT be allowed." A <c>client_credentials</c> request sent to the token endpoint over
    /// the wire with a proof carrying the supplied nonce whose protected header declares <c>alg</c> <c>none</c>, its
    /// signature made by the P-256 private key whose public half the <c>jwk</c> carries, is refused: 400
    /// <c>invalid_dpop_proof</c> and no access token in the body.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task TokenEndpointRefusesAProofWhoseAlgIsNoneAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterMachineClientAsync(app).ConfigureAwait(false);
        Uri tokenUrl = await StartDpopTokenEndpointAsync(app, material).ConfigureAwait(false);
        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;
        DpopKey dpopKey = new(holderKeys, WellKnownJwaValues.Es256);

        string nonce = await ObtainTokenEndpointNonceAsync(app, tokenUrl, dpopKey).ConfigureAwait(false);
        string proof = await BuildTokenProofAsync(dpopKey, tokenUrl, nonce, alterHeader: header => header["alg"] = "none").ConfigureAwait(false);
        (int statusCode, string body, _) = await PostMachineTokenRequestAsync(app, tokenUrl, proof).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, body);
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual(OAuthErrors.InvalidDpopProof, document.RootElement.GetProperty("error").GetString());
        Assert.DoesNotContain(WellKnownTokenTypes.AccessToken, body, "A proof declaring alg none never mints an access token.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-2">RFC 9449 Section 2</see>: "DPoP is not, however, a
    /// substitute for a secure transport and MUST always be used in conjunction with HTTPS." A client wired with a
    /// DPoP key and the secure default outbound policy, asked for a <c>client_credentials</c> token at an endpoint
    /// whose URL is <c>http</c>, never dials it: the transport sees no request, so no proof leaves the client
    /// outside HTTPS, and the request answers the client's internal error.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ClientNeverSendsAProofToATokenEndpointOutsideHttpsAsync()
    {
        Uri issuer = new("https://as.example.com");
        Uri plainHttpTokenEndpoint = new("http://as.example.com/token");
        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;
        DpopKey dpopKey = new(holderKeys, WellKnownJwaValues.Es256);

        List<OutgoingHeaders> dialed = [];
        OAuthClient client = BuildDpopMachineClient(
            issuer, plainHttpTokenEndpoint, dpopKey, new InMemoryDpopNonceCache(), OutboundFetchPolicy.SecureDefault,
            (endpoint, fields, headers, ct) =>
            {
                dialed.Add(headers);

                return ValueTask.FromResult(new HttpResponseData
                {
                    StatusCode = 400,
                    Body = "{\"error\":\"invalid_request\"}",
                    Headers = ResponseHeaders.Empty
                });
            });

        AuthCodeFlowEndpointResult result = await client.ClientCredentials.RequestTokenAsync(
            MachineClientRegistration(issuer), scope: MachineScope, resource: null, [], clientAssertionOptions: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(dialed, "No request, and so no DPoP proof, is sent to an http endpoint.");
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.InternalError, result.Outcome,
            $"ErrorCode={result.ErrorCode} ErrorDescription={result.ErrorDescription}");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4">RFC 9449 Section 4</see>: "Each HTTP request
    /// requires a unique DPoP proof." A DPoP-wired client asks the token endpoint for a <c>client_credentials</c>
    /// token twice over the wire: the first request is challenged for a nonce and retried, the second carries the
    /// supplied nonce. Every proof the endpoint receives, read from the <c>DPoP</c> field as it arrived, differs
    /// from every other in its <c>jti</c>, and both requests are answered with a DPoP-bound access token under the
    /// endpoint's replay check of the <c>jti</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ClientSendsADistinctProofInEveryTokenRequestAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterMachineClientAsync(app).ConfigureAwait(false);
        Uri tokenUrl = await StartDpopTokenEndpointAsync(app, material).ConfigureAwait(false);
        List<(string HttpUrl, string Proof)> receivedProofs = await app.RecordReceivedDpopProofsAsync().ConfigureAwait(false);
        await AdmitTheMachineClientByItsIdentifierAsync(app).ConfigureAwait(false);
        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;
        DpopKey dpopKey = new(holderKeys, WellKnownJwaValues.Es256);

        OAuthClient client = BuildDpopMachineClientOverWire(app, material, tokenUrl, dpopKey, new InMemoryDpopNonceCache());
        for(int request = 0; request < 2; request++)
        {
            AuthCodeFlowEndpointResult result = await client.ClientCredentials.RequestTokenAsync(
                MachineClientRegistration(material.Registration.IssuerUri!), scope: MachineScope, resource: null, [],
                clientAssertionOptions: null, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, result.Outcome,
                $"Request {request}: ErrorCode={result.ErrorCode} ErrorDescription={result.ErrorDescription}");
            Assert.AreEqual(WellKnownAuthenticationSchemes.DPoP, (string)result.Body![OAuthRequestParameterNames.TokenType]);
        }

        Assert.IsGreaterThanOrEqualTo(3, receivedProofs.Count, "The endpoint received the challenged proof, its retry and the second request's proof.");
        List<string?> jtis = [.. receivedProofs.Select(received => DpopWireReading.ReadPayloadClaim(received.Proof, "jti", Pool))];
        Assert.HasCount(receivedProofs.Count, jtis.Distinct(StringComparer.Ordinal), $"Every proof carries its own jti: {string.Join(" ", jtis)}");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.1">RFC 9449 Section 4.1</see>: "The DPoP HTTP
    /// header field value uses the token68 syntax defined in Section 11.2 of [RFC9110]", Figure 3:
    /// <c>token68 = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="</c>. A DPoP-wired client asks the
    /// token endpoint for a <c>client_credentials</c> token over the wire and is answered with a DPoP-bound access
    /// token, and every <c>DPoP</c> field value the endpoint received, read as it arrived, is one token68.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ClientSendsItsProofInTheToken68SyntaxAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterMachineClientAsync(app).ConfigureAwait(false);
        Uri tokenUrl = await StartDpopTokenEndpointAsync(app, material).ConfigureAwait(false);
        List<(string HttpUrl, string Proof)> receivedProofs = await app.RecordReceivedDpopProofsAsync().ConfigureAwait(false);
        await AdmitTheMachineClientByItsIdentifierAsync(app).ConfigureAwait(false);
        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;
        DpopKey dpopKey = new(holderKeys, WellKnownJwaValues.Es256);

        OAuthClient client = BuildDpopMachineClientOverWire(app, material, tokenUrl, dpopKey, new InMemoryDpopNonceCache());
        AuthCodeFlowEndpointResult result = await client.ClientCredentials.RequestTokenAsync(
            MachineClientRegistration(material.Registration.IssuerUri!), scope: MachineScope, resource: null, [],
            clientAssertionOptions: null, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, result.Outcome, $"ErrorCode={result.ErrorCode} ErrorDescription={result.ErrorDescription}");
        Assert.IsNotEmpty(receivedProofs, "The endpoint received the client's proofs.");
        foreach((_, string proof) in receivedProofs)
        {
            Assert.IsTrue(DpopWireReading.IsToken68(proof), $"The DPoP field value is one token68: '{proof}'.");
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 Section 8</see>: "The nonce is opaque
    /// to the client." The token endpoint here supplies nonces that carry NQCHAR outside the base64url alphabet
    /// (<c>~</c>, <c>.</c>, <c>!</c>, <c>*</c>, <c>(</c>) before the server's own nonce, and reads them back the
    /// same way. A DPoP-wired client asks for a <c>client_credentials</c> token over the wire, is challenged once and
    /// retries: the nonce its retry's proof carries is the supplied nonce exactly, character for character, and the
    /// request is answered with a DPoP-bound access token.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ClientEchoesTheSuppliedNonceExactlyAsItArrivedAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterMachineClientAsync(app).ConfigureAwait(false);
        Uri tokenUrl = await StartDpopTokenEndpointAsync(app, material).ConfigureAwait(false);

        await AdmitTheMachineClientByItsIdentifierAsync(app).ConfigureAwait(false);

        const string OpaquePrefix = "~opaque.nonce!*(";
        List<string> supplied = [];
        List<string> presented = [];
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            IssueDpopNonceDelegate issue = candidateIntegration.IssueDpopNonceAsync!;
            ValidateDpopNonceDelegate validate = candidateIntegration.ValidateDpopNonceAsync!;
            candidateIntegration.IssueDpopNonceAsync = async (audience, tenantId, context, ct) =>
            {
                string nonce = OpaquePrefix + await issue(audience, tenantId, context, ct).ConfigureAwait(false);
                supplied.Add(nonce);

                return nonce;
            };
            candidateIntegration.ValidateDpopNonceAsync = (nonce, audience, tenantId, context, ct) =>
            {
                presented.Add(nonce);

                return nonce.StartsWith(OpaquePrefix, StringComparison.Ordinal)
                    ? validate(nonce[OpaquePrefix.Length..], audience, tenantId, context, ct)
                    : ValueTask.FromResult(DpopNonceValidationResult.Failure(DpopNonceValidationFailureReason.Malformed));
            };
        }).ConfigureAwait(false);
        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;
        DpopKey dpopKey = new(holderKeys, WellKnownJwaValues.Es256);

        OAuthClient client = BuildDpopMachineClientOverWire(app, material, tokenUrl, dpopKey, new InMemoryDpopNonceCache());
        AuthCodeFlowEndpointResult result = await client.ClientCredentials.RequestTokenAsync(
            MachineClientRegistration(material.Registration.IssuerUri!), scope: MachineScope, resource: null, [],
            clientAssertionOptions: null, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, result.Outcome, $"ErrorCode={result.ErrorCode} ErrorDescription={result.ErrorDescription}");
        string suppliedNonce = Assert.ContainsSingle(supplied);
        Assert.AreEqual(suppliedNonce, Assert.ContainsSingle(presented), "The client echoes the nonce exactly as it was supplied.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8.2">RFC 9449 Section 8.2</see>: "The client is
    /// expected to use the existing supplied nonce in DPoP proofs until the server supplies a new nonce value." A
    /// DPoP-wired client asks the token endpoint for a <c>client_credentials</c> token twice over the wire: the
    /// first request is challenged once and retried with the supplied nonce, and the second request's one proof
    /// carries that same nonce, so the endpoint supplies no other nonce and both requests are answered with a
    /// DPoP-bound access token.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ClientUsesTheSuppliedNonceInItsNextTokenRequestAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterMachineClientAsync(app).ConfigureAwait(false);
        Uri tokenUrl = await StartDpopTokenEndpointAsync(app, material).ConfigureAwait(false);
        List<(string HttpUrl, string Proof)> receivedProofs = await app.RecordReceivedDpopProofsAsync().ConfigureAwait(false);
        await AdmitTheMachineClientByItsIdentifierAsync(app).ConfigureAwait(false);
        List<string> supplied = [];
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            IssueDpopNonceDelegate issue = candidateIntegration.IssueDpopNonceAsync!;
            candidateIntegration.IssueDpopNonceAsync = async (audience, tenantId, context, ct) =>
            {
                string nonce = await issue(audience, tenantId, context, ct).ConfigureAwait(false);
                supplied.Add(nonce);

                return nonce;
            };
        }).ConfigureAwait(false);
        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;
        DpopKey dpopKey = new(holderKeys, WellKnownJwaValues.Es256);

        OAuthClient client = BuildDpopMachineClientOverWire(app, material, tokenUrl, dpopKey, new InMemoryDpopNonceCache());
        for(int request = 0; request < 2; request++)
        {
            AuthCodeFlowEndpointResult result = await client.ClientCredentials.RequestTokenAsync(
                MachineClientRegistration(material.Registration.IssuerUri!), scope: MachineScope, resource: null, [],
                clientAssertionOptions: null, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, result.Outcome,
                $"Request {request}: ErrorCode={result.ErrorCode} ErrorDescription={result.ErrorDescription}");
        }

        string suppliedNonce = Assert.ContainsSingle(supplied, "The endpoint supplied one nonce for both requests.");
        Assert.HasCount(3, receivedProofs, "The challenged proof, its retry, and the second request's one proof.");
        Assert.AreEqual(suppliedNonce, DpopWireReading.ReadPayloadClaim(receivedProofs[2].Proof, "nonce", Pool),
            "The second request's proof carries the nonce supplied to the first.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 Section 8</see>: the nonce challenge is
    /// "an HTTP 400 (Bad Request) error response per Section 5.2 of [RFC6749] using use_dpop_nonce as the error code
    /// value." A DPoP-wired client asks for a <c>client_credentials</c> token over the wire; the token endpoint's 400
    /// nonce challenge is rewritten after it crossed the wire into an error response whose <c>error</c> is
    /// <c>invalid_grant</c> and whose <c>error_description</c> is the text <c>use_dpop_nonce</c>, the
    /// <c>DPoP-Nonce</c> field kept. The error code is <c>invalid_grant</c>: the client sends no second request and
    /// answers the refusal with that code.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ClientDoesNotReadAnErrorDescriptionAsANonceChallengeAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterMachineClientAsync(app).ConfigureAwait(false);
        Uri tokenUrl = await StartDpopTokenEndpointAsync(app, material).ConfigureAwait(false);
        List<(string HttpUrl, string Proof)> receivedProofs = await app.RecordReceivedDpopProofsAsync().ConfigureAwait(false);
        await AdmitTheMachineClientByItsIdentifierAsync(app).ConfigureAwait(false);
        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;
        DpopKey dpopKey = new(holderKeys, WellKnownJwaValues.Es256);

        HttpClient httpClient = app.Host("default").SharedHttpClient!;
        int tokenRequests = 0;
        OAuthClient client = BuildDpopMachineClient(
            material.Registration.IssuerUri!, tokenUrl, dpopKey, new InMemoryDpopNonceCache(), TestHostShell.LoopbackOutboundFetchPolicy,
            async (endpoint, fields, headers, ct) =>
            {
                tokenRequests++;
                HttpResponseData answer = await HttpClientTransport.SendFormPostAsync(httpClient, endpoint, fields, headers, ct).ConfigureAwait(false);

                return answer.StatusCode == 400
                    ? answer with { Body = "{\"error\":\"invalid_grant\",\"error_description\":\"use_dpop_nonce\"}" }
                    : answer;
            });
        AuthCodeFlowEndpointResult result = await client.ClientCredentials.RequestTokenAsync(
            MachineClientRegistration(material.Registration.IssuerUri!), scope: MachineScope, resource: null, [],
            clientAssertionOptions: null, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, result.Outcome, $"ErrorCode={result.ErrorCode} ErrorDescription={result.ErrorDescription}");
        Assert.AreEqual(OAuthErrors.InvalidGrant, result.ErrorCode);
        Assert.AreEqual(1, tokenRequests, "The client sends no second request for an invalid_grant refusal.");
        Assert.HasCount(1, receivedProofs, "The endpoint received the one proof of the one request.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-4">RFC 8259 Section 4</see>: "The names within an
    /// object SHOULD be unique." and "When the names within an object are not unique, the behavior of software that
    /// receives such an object is unpredictable." The library's own rule reads an error object naming <c>error</c>
    /// twice as no error object, so no two readers of one body can read two codes from it. A DPoP-wired client asks
    /// for a <c>client_credentials</c> token over the wire; the token endpoint's 400 nonce challenge is rewritten after
    /// it crossed the wire into <c>{"error":"use_dpop_nonce","error":"invalid_grant"}</c>, the <c>DPoP-Nonce</c> field
    /// kept: the client reads no nonce challenge and sends no second request.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ClientDoesNotReadAnErrorBodyNamingItsErrorMemberTwiceAsANonceChallengeAsync()
    {
        (AuthCodeFlowEndpointResult result, int tokenRequests, int receivedProofs) =
            await RequestTokenUnderARewrittenChallengeBodyAsync("{\"error\":\"use_dpop_nonce\",\"error\":\"invalid_grant\"}").ConfigureAwait(false);

        Assert.AreEqual(1, tokenRequests, $"The client sends no second request; it answered {result.Outcome} {result.ErrorCode}.");
        Assert.AreEqual(1, receivedProofs, "The endpoint received the one proof of the one request.");
        Assert.AreNotEqual(AuthCodeFlowEndpointOutcome.Ok, result.Outcome);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>: "The parameters are
    /// serialized into a JSON structure by adding each parameter at the highest structure level." An <c>error</c>
    /// member inside a nested object is no parameter of the error response. A DPoP-wired client asks for a
    /// <c>client_credentials</c> token over the wire; the token endpoint's 400 nonce challenge is rewritten after it
    /// crossed the wire into <c>{"x":{"error":"use_dpop_nonce"},"error":"invalid_grant"}</c>, the <c>DPoP-Nonce</c>
    /// field kept: the error code is <c>invalid_grant</c>, the client sends no second request and answers the refusal
    /// with that code.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ClientDoesNotReadANestedErrorMemberAsANonceChallengeAsync()
    {
        (AuthCodeFlowEndpointResult result, int tokenRequests, int receivedProofs) =
            await RequestTokenUnderARewrittenChallengeBodyAsync("{\"x\":{\"error\":\"use_dpop_nonce\"},\"error\":\"invalid_grant\"}").ConfigureAwait(false);

        Assert.AreEqual(1, tokenRequests, $"The client sends no second request; it answered {result.Outcome} {result.ErrorCode}.");
        Assert.AreEqual(1, receivedProofs, "The endpoint received the one proof of the one request.");
        Assert.AreEqual(OAuthErrors.InvalidGrant, result.ErrorCode);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-7">RFC 8259 Section 7</see>: "Any character may be
    /// escaped." and <see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.3">Section 8.3</see>: "implementations
    /// that compare strings with escaped characters unconverted may incorrectly find that "a\\b" and "a\u005Cb" are not
    /// equal." A DPoP-wired client asks for a <c>client_credentials</c> token over the wire; the token endpoint's 400
    /// nonce challenge is rewritten after it crossed the wire into an error object whose <c>error</c> string writes the
    /// underscore of <c>use_dpop_nonce</c> as the escape <c>\u005f</c>, the <c>DPoP-Nonce</c> field kept. The string is
    /// <c>use_dpop_nonce</c>: the client retries exactly once with the supplied nonce and is answered with a DPoP-bound
    /// access token.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ClientReadsAnErrorCodeWrittenWithAJsonEscapeAsTheCodeItSpellsAsync()
    {
        string escapedBody = "{\"error\":\"use" + '\\' + "u005fdpop_nonce\"}";

        (AuthCodeFlowEndpointResult result, int tokenRequests, int receivedProofs) =
            await RequestTokenUnderARewrittenChallengeBodyAsync(escapedBody).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, result.Outcome, $"ErrorCode={result.ErrorCode} ErrorDescription={result.ErrorDescription}");
        Assert.AreEqual(2, tokenRequests, "The challenged request and its one retry.");
        Assert.AreEqual(2, receivedProofs, "The endpoint received the challenged proof and the retry's.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>: "error REQUIRED. A
    /// single ASCII [USASCII] error code". A JSON array is no error code. A DPoP-wired client asks for a
    /// <c>client_credentials</c> token over the wire; the token endpoint's 400 nonce challenge is rewritten after it
    /// crossed the wire into <c>{"error":["use_dpop_nonce"]}</c>, the <c>DPoP-Nonce</c> field kept: the client reads
    /// no nonce challenge and sends no second request.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ClientDoesNotReadANonStringErrorMemberAsANonceChallengeAsync()
    {
        (AuthCodeFlowEndpointResult result, int tokenRequests, int receivedProofs) =
            await RequestTokenUnderARewrittenChallengeBodyAsync("{\"error\":[\"use_dpop_nonce\"]}").ConfigureAwait(false);

        Assert.AreEqual(1, tokenRequests, $"The client sends no second request; it answered {result.Outcome} {result.ErrorCode}.");
        Assert.AreEqual(1, receivedProofs, "The endpoint received the one proof of the one request.");
        Assert.AreNotEqual(AuthCodeFlowEndpointOutcome.Ok, result.Outcome);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 Section 8</see>: "Nonce values MUST be
    /// unpredictable." The library's nonce issuance writes into each nonce a random field filled from the entropy
    /// source the application wires, so a nonce is as unpredictable as that source. The host's issuance is wired here
    /// to the project's CSPRNG through a source that records every draw. Four <c>client_credentials</c> requests sent
    /// to the token endpoint over the wire at one instant, each with a proof carrying no nonce, are each answered 400
    /// <c>use_dpop_nonce</c> with a <c>DPoP-Nonce</c>; the issuer drew 16 bytes (128 bits) for each nonce, and each
    /// nonce, decoded from base64url, carries at its random field exactly the bytes drawn for it.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task TokenEndpointNonceCarriesTheRandomBytesItsIssuerDrewAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterMachineClientAsync(app).ConfigureAwait(false);
        Uri tokenUrl = await StartDpopTokenEndpointAsync(app, material).ConfigureAwait(false);
        List<string> draws = [];
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.IssueDpopNonceAsync = (audience, tenantId, context, ct) =>
                DefaultDpopNonceIssuance.IssueAsync(
                    audience,
                    tenantId,
                    context,
                    context.RequestServer!.OAuth().GetHmacKeySetAsync!,
                    context.RequestServer!.OAuth().SelectHmacKeyAsync,
                    context.RequestServer!.OAuth().ResolveServerHmacKeyAsync!,
                    TimeProvider,
                    TestHostShell.Base64UrlEncoder,
                    destination =>
                    {
                        (Nonce drawn, _) = MicrosoftEntropyFunctionsAdapter.GenerateNonce(
                            destination.Length, Tag.Create(Purpose.Nonce).With(EntropySource.Csprng), Pool);
                        using(drawn)
                        {
                            drawn.UseNonce().CopyTo(destination);
                        }

                        draws.Add(TestHostShell.Base64UrlEncoder(destination));
                    },
                    Pool,
                    ct);
        }).ConfigureAwait(false);
        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;
        DpopKey dpopKey = new(holderKeys, WellKnownJwaValues.Es256);

        List<string> nonces = [];
        for(int challenge = 0; challenge < 4; challenge++)
        {
            nonces.Add(await ObtainTokenEndpointNonceAsync(app, tokenUrl, dpopKey).ConfigureAwait(false));
        }

        Assert.HasCount(nonces.Count, draws, "The issuer drew from its entropy source once for every nonce it issued.");
        for(int index = 0; index < nonces.Count; index++)
        {
            Assert.AreEqual(draws[index], ReadNonceRandomField(nonces[index]), $"Nonce {index} carries the bytes its issuer drew.");
        }
    }


    /// <summary>
    /// RFC 9449 Section 4.2, of the proof's <c>alg</c>: "It MUST NOT be none" and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.6">Section 11.6</see>: "In particular, the algorithm
    /// none MUST NOT be allowed." A client is wired for a <c>client_credentials</c> request over the wire with a DPoP
    /// key declaring <c>none</c>: the wiring is refused with an <see cref="ArgumentException"/> naming <c>alg</c>, and
    /// the token endpoint receives no proof.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ClientDeclaringTheAlgorithmNoneNeverSendsAProofAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterMachineClientAsync(app).ConfigureAwait(false);
        Uri tokenUrl = await StartDpopTokenEndpointAsync(app, material).ConfigureAwait(false);
        List<(string HttpUrl, string Proof)> receivedProofs = await app.RecordReceivedDpopProofsAsync().ConfigureAwait(false);
        await AdmitTheMachineClientByItsIdentifierAsync(app).ConfigureAwait(false);
        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        ArgumentException? refusal = null;
        AuthCodeFlowEndpointResult? result = null;
        try
        {
            DpopKey dpopKey = new(holderKeys, WellKnownJwaValues.None);
            OAuthClient client = BuildDpopMachineClientOverWire(app, material, tokenUrl, dpopKey, new InMemoryDpopNonceCache());
            result = await client.ClientCredentials.RequestTokenAsync(
                MachineClientRegistration(material.Registration.IssuerUri!), scope: MachineScope, resource: null, [],
                clientAssertionOptions: null, TestContext.CancellationToken).ConfigureAwait(false);
        }
        catch(ArgumentException exception)
        {
            refusal = exception;
        }

        Assert.IsEmpty(receivedProofs, $"No proof reaches the token endpoint; the request was answered {result?.Outcome} {result?.ErrorCode}.");
        Assert.IsNotNull(refusal, "The DPoP key declaring none is refused when the client is wired.");
        Assert.AreEqual("alg", refusal.ParamName);
    }


    /// <summary>
    /// Asks the token endpoint over the wire for a <c>client_credentials</c> token with a DPoP-wired client whose
    /// transport rewrites the body of every 400 answer into <paramref name="challengeBody"/> after it crossed the wire,
    /// the answer's <c>DPoP-Nonce</c> field kept.
    /// </summary>
    /// <param name="challengeBody">The JSON body the client reads in place of each 400 answer's.</param>
    /// <returns>The client's answer, the number of token requests it sent and the number of proofs the endpoint received.</returns>
    private async Task<(AuthCodeFlowEndpointResult Result, int TokenRequests, int ReceivedProofs)> RequestTokenUnderARewrittenChallengeBodyAsync(string challengeBody)
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterMachineClientAsync(app).ConfigureAwait(false);
        Uri tokenUrl = await StartDpopTokenEndpointAsync(app, material).ConfigureAwait(false);
        List<(string HttpUrl, string Proof)> receivedProofs = await app.RecordReceivedDpopProofsAsync().ConfigureAwait(false);
        await AdmitTheMachineClientByItsIdentifierAsync(app).ConfigureAwait(false);
        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;
        DpopKey dpopKey = new(holderKeys, WellKnownJwaValues.Es256);

        HttpClient httpClient = app.Host("default").SharedHttpClient!;
        int tokenRequests = 0;
        OAuthClient client = BuildDpopMachineClient(
            material.Registration.IssuerUri!, tokenUrl, dpopKey, new InMemoryDpopNonceCache(), TestHostShell.LoopbackOutboundFetchPolicy,
            async (endpoint, fields, headers, ct) =>
            {
                tokenRequests++;
                HttpResponseData answer = await HttpClientTransport.SendFormPostAsync(httpClient, endpoint, fields, headers, ct).ConfigureAwait(false);

                return answer.StatusCode == 400 ? answer with { Body = challengeBody } : answer;
            });
        AuthCodeFlowEndpointResult result = await client.ClientCredentials.RequestTokenAsync(
            MachineClientRegistration(material.Registration.IssuerUri!), scope: MachineScope, resource: null, [],
            clientAssertionOptions: null, TestContext.CancellationToken).ConfigureAwait(false);

        return (result, tokenRequests, receivedProofs.Count);
    }


    /// <summary>
    /// Reads the random field of a nonce the library's issuance wrote: the nonce decoded from base64url is a one-octet
    /// length of the key identifier, the identifier, the issue time, the audience hash, then the random field, whose
    /// lengths <see cref="WellKnownDpopValues"/> names.
    /// </summary>
    /// <param name="nonce">The nonce as the <c>DPoP-Nonce</c> field carried it.</param>
    /// <returns>The random field written in base64url.</returns>
    private static string ReadNonceRandomField(string nonce)
    {
        using IMemoryOwner<byte> packed = TestSetup.Base64UrlDecoder(nonce, Pool);
        ReadOnlySpan<byte> bytes = packed.Memory.Span;
        int randomStart = 1 + bytes[0] + WellKnownDpopValues.NonceIssuedAtByteLength + WellKnownDpopValues.NonceAudienceHashByteLength;

        return TestHostShell.Base64UrlEncoder(bytes.Slice(randomStart, WellKnownDpopValues.NonceRandomByteLength));
    }


    /// <summary>The row of the nonce-mismatch test whose presented nonce is the supplied one with one character changed.</summary>
    private const string NonceCharacterChangedRow = "nonce-character-changed";

    /// <summary>The row of the nonce-mismatch test whose presented nonce is the supplied one after its window has passed.</summary>
    private const string NonceWindowPassedRow = "nonce-window-passed";

    /// <summary>The row of the exact-match test whose presented nonce is the supplied one with a character added.</summary>
    private const string NonceCharacterAddedRow = "nonce-character-added";

    /// <summary>The row of the exact-match test whose presented nonce is the supplied one with its first letter in the other case.</summary>
    private const string NonceCaseChangedRow = "nonce-case-changed";

    /// <summary>The row of the exact-text test whose presented nonce is the supplied octets and one more, written canonically.</summary>
    private const string NonceExtendedByAnOctetRow = "nonce-extended-by-an-octet";

    /// <summary>The row of the exact-text test whose presented nonce is the supplied one with a space inside it.</summary>
    private const string NonceWithASpaceInsideRow = "nonce-with-a-space-inside";

    /// <summary>The row of the exact-text test whose presented nonce is the supplied one with its padding.</summary>
    private const string NoncePaddedRow = "nonce-padded";

    /// <summary>The row of the exact-text test whose presented nonce is the supplied one with a pad bit of its last character set.</summary>
    private const string NonceWithAPadBitSetRow = "nonce-with-a-pad-bit-set";


    /// <summary>
    /// Wires DPoP on the host, starts its listener, aligns the registration's issuer to the listener's address so a
    /// proof's <c>htu</c> names the token endpoint URL the listener serves, and returns that URL.
    /// </summary>
    /// <param name="app">The host.</param>
    /// <param name="material">The machine registration.</param>
    /// <returns>The absolute token endpoint URL on the listener.</returns>
    private async Task<Uri> StartDpopTokenEndpointAsync(TestHostShell app, VerifierKeyMaterial material)
    {
        _ = await app.EnableDpopAsync().ConfigureAwait(false);
        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        material.Registration = app.AlignRegistrationToHostHttpBase("default", material.Registration);

        return new Uri(app.Host("default").HttpBaseAddress!, $"/connect/{material.Registration.TenantId.Value}/token");
    }


    /// <summary>The form fields of the machine client's <c>client_credentials</c> request under <c>client_secret_post</c>.</summary>
    /// <returns>The fields.</returns>
    private static Dictionary<string, string> MachineTokenRequestFields() => new(StringComparer.Ordinal)
    {
        [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
        [OAuthRequestParameterNames.ClientId] = ClientId,
        ["client_secret"] = ClientSecret,
        [OAuthRequestParameterNames.Scope] = MachineScope
    };


    /// <summary>The fields of <see cref="MachineTokenRequestFields"/> written as an <c>application/x-www-form-urlencoded</c> body.</summary>
    /// <returns>The body text.</returns>
    private static string MachineTokenRequestForm() =>
        string.Join('&', MachineTokenRequestFields().Select(static pair => Uri.EscapeDataString(pair.Key) + "=" + Uri.EscapeDataString(pair.Value)));


    /// <summary>Builds a token request proof naming POST and <paramref name="tokenUrl"/>, signed by <paramref name="dpopKey"/> at the current instant.</summary>
    /// <param name="dpopKey">The DPoP key that signs the proof.</param>
    /// <param name="tokenUrl">The <c>htu</c>.</param>
    /// <param name="nonce">The <c>nonce</c>, or <see langword="null"/> to carry none.</param>
    /// <param name="jti">The <c>jti</c>, or <see langword="null"/> for a fresh one.</param>
    /// <param name="alterHeader">Rewrites the serialized protected header before signing, or <see langword="null"/> to keep it.</param>
    /// <returns>The compact proof.</returns>
    private Task<string> BuildTokenProofAsync(
        DpopKey dpopKey, Uri tokenUrl, string? nonce, string? jti = null, Action<Dictionary<string, object>>? alterHeader = null) =>
        ResourceDpopProofs.BuildAsync(
            dpopKey, WellKnownHttpMethods.Post, tokenUrl.OriginalString, accessToken: null, nonce, TimeProvider.GetUtcNow(),
            TestContext.CancellationToken, jti, alterHeader);


    /// <summary>
    /// Sends the machine client's <c>client_credentials</c> request with <paramref name="proof"/> in the <c>DPoP</c>
    /// field over the host's client and returns the answer.
    /// </summary>
    /// <param name="app">The host.</param>
    /// <param name="tokenUrl">The token endpoint URL.</param>
    /// <param name="proof">The proof sent.</param>
    /// <returns>The status, the body and every <c>DPoP-Nonce</c> value the answer carries.</returns>
    private async Task<(int StatusCode, string Body, IReadOnlyList<string> Nonces)> PostMachineTokenRequestAsync(
        TestHostShell app, Uri tokenUrl, string proof)
    {
        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            app.Host("default").SharedHttpClient!, tokenUrl, MachineTokenRequestFields(),
            OutgoingHeaders.Empty.WithDpop(proof), TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        IReadOnlyList<string> nonces = response.Headers.TryGetValues(WellKnownHttpHeaderNames.DPoPNonce, out IEnumerable<string>? values)
            ? [.. values]
            : [];

        return ((int)response.StatusCode, body, nonces);
    }


    /// <summary>
    /// Sends the machine client's request with a proof carrying no nonce, asserts the 400 <c>use_dpop_nonce</c>
    /// challenge, and returns the one nonce its <c>DPoP-Nonce</c> supplies.
    /// </summary>
    /// <param name="app">The host.</param>
    /// <param name="tokenUrl">The token endpoint URL.</param>
    /// <param name="dpopKey">The DPoP key that signs the proof.</param>
    /// <returns>The supplied nonce.</returns>
    private async Task<string> ObtainTokenEndpointNonceAsync(TestHostShell app, Uri tokenUrl, DpopKey dpopKey)
    {
        string proof = await BuildTokenProofAsync(dpopKey, tokenUrl, nonce: null).ConfigureAwait(false);
        (int statusCode, string body, IReadOnlyList<string> nonces) = await PostMachineTokenRequestAsync(app, tokenUrl, proof).ConfigureAwait(false);
        Assert.AreEqual(400, statusCode, body);
        Assert.Contains(OAuthErrors.UseDpopNonce, body);

        return Assert.ContainsSingle(nonces, "The nonce challenge supplies a nonce.");
    }


    /// <summary>
    /// Sends the machine client's request over a raw TLS connection with a proof carrying no nonce, so every field
    /// line of the answer is read as received.
    /// </summary>
    /// <param name="app">The host.</param>
    /// <param name="tokenUrl">The token endpoint URL.</param>
    /// <param name="dpopKey">The DPoP key that signs the proof.</param>
    /// <returns>The wire response.</returns>
    private async Task<HttpResponseData> PostNonceLessProofOverARawConnectionAsync(TestHostShell app, Uri tokenUrl, DpopKey dpopKey)
    {
        string proof = await BuildTokenProofAsync(dpopKey, tokenUrl, nonce: null).ConfigureAwait(false);

        return await RawHttpsRequest.SendAsync(
            app, WellKnownHttpMethods.Post, tokenUrl,
            [
                new(WellKnownHttpHeaderNames.ContentType, WellKnownMediaTypes.Application.FormUrlEncoded),
                new(WellKnownHttpHeaderNames.DPoP, proof)
            ],
            Encoding.ASCII.GetBytes(MachineTokenRequestForm()), TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Admits the machine client at the token endpoint by its identifier alone, the client side
    /// <see cref="MachineClientRegistration"/> carrying <see cref="ClientAuthenticationMethod.None"/>.
    /// </summary>
    /// <param name="app">The host.</param>
    /// <returns>A task that completes when the host is altered.</returns>
    private static Task AdmitTheMachineClientByItsIdentifierAsync(TestHostShell app) =>
        TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (reading, registration, context, ct) => ValueTask.FromResult(true);
        });


    /// <summary>The client side of the machine registration: no client authentication, the HAIP 1.0 profile.</summary>
    /// <param name="issuer">The authorization server's issuer.</param>
    /// <returns>The client registration.</returns>
    private static ClientRegistration MachineClientRegistration(Uri issuer) => new()
    {
        ClientId = new ClientId(ClientId),
        AuthorizationServerIssuer = issuer,
        RedirectUris = [new Uri(ClientId)],
        AuthenticationMethod = ClientAuthenticationMethod.None,
        Profile = PolicyProfile.Haip10
    };


    /// <summary>Builds the DPoP-wired client of <see cref="BuildDpopMachineClient"/> over the host's client and loopback policy.</summary>
    /// <param name="app">The host whose listener serves the token endpoint.</param>
    /// <param name="material">The machine registration.</param>
    /// <param name="tokenUrl">The token endpoint URL.</param>
    /// <param name="dpopKey">The client's DPoP key.</param>
    /// <param name="nonceCache">The client's nonce cache.</param>
    /// <returns>The client.</returns>
    private OAuthClient BuildDpopMachineClientOverWire(
        TestHostShell app, VerifierKeyMaterial material, Uri tokenUrl, DpopKey dpopKey, InMemoryDpopNonceCache nonceCache)
    {
        HttpClient httpClient = app.Host("default").SharedHttpClient!;

        return BuildDpopMachineClient(
            material.Registration.IssuerUri!, tokenUrl, dpopKey, nonceCache, TestHostShell.LoopbackOutboundFetchPolicy,
            (endpoint, fields, headers, ct) => HttpClientTransport.SendFormPostAsync(httpClient, endpoint, fields, headers, ct));
    }


    /// <summary>
    /// Builds an <see cref="OAuthClient"/> whose infrastructure carries a DPoP key, the library's proof construction,
    /// the identifier generator, a nonce cache and the given outbound policy and transport, resolving metadata that
    /// names <paramref name="tokenEndpoint"/>.
    /// </summary>
    /// <param name="issuer">The authorization server's issuer.</param>
    /// <param name="tokenEndpoint">The token endpoint the metadata names.</param>
    /// <param name="dpopKey">The client's DPoP key.</param>
    /// <param name="nonceCache">The client's nonce cache.</param>
    /// <param name="outboundFetchPolicy">The outbound policy every dial is evaluated against.</param>
    /// <param name="sendFormPostAsync">The transport of each form post: the endpoint, fields and headers.</param>
    /// <returns>The client.</returns>
    private OAuthClient BuildDpopMachineClient(
        Uri issuer,
        Uri tokenEndpoint,
        DpopKey dpopKey,
        InMemoryDpopNonceCache nonceCache,
        OutboundFetchPolicy outboundFetchPolicy,
        Func<Uri, IReadOnlyCollection<KeyValuePair<string, string>>, OutgoingHeaders, CancellationToken, ValueTask<HttpResponseData>> sendFormPostAsync)
    {
        AuthorizationServerMetadata metadata = new()
        {
            Issuer = issuer,
            TokenEndpoint = tokenEndpoint
        };

        OAuthClientInfrastructure infrastructure = OAuthClientInfrastructure.Create(
            sendFormPostAsync: (endpoint, fields, headers, _, ct) => sendFormPostAsync(endpoint, fields, headers, ct),
            saveStateAsync: (_, _, _) => ValueTask.CompletedTask,
            loadStateAsync: (_, _, _) => ValueTask.FromResult<FlowState?>(null),
            loadStateByRequestUriAsync: (_, _, _) => ValueTask.FromResult<FlowState?>(null),
            parseParResponseAsync: OAuthResponseParsers.ParseParResponse,
            parseTokenResponseAsync: OAuthResponseParsers.ParseTokenResponse,
            parseRegistrationResponseAsync: (body, ct) =>
                throw new NotImplementedException("Test does not exercise dynamic registration."),
            resolveAuthorizationServerMetadataAsync: (_, _, _) =>
                ValueTask.FromResult<AuthorizationServerMetadataResolution>(new AuthorizationServerMetadataResolved
                {
                    MetadataLocation = WellKnownPaths.OAuthAuthorizationServer.ComputeUri(metadata.Issuer.OriginalString),
                    Metadata = metadata
                }),
            resolveCallbackValidator: ClientPolicyProfiles.DefaultResolveCallbackValidator,
            base64UrlEncoder: TestSetup.Base64UrlEncoder,
            memoryPool: Pool,
            timeProvider: TimeProvider,
            fillEntropy: TestEntropy.NewCounterStream(),
            generateIdentifierAsync: DefaultIdentifierGenerator.For(TimeProvider, TestEntropy.NewCounterStream(), Pool),
            outboundFetchPolicy: outboundFetchPolicy,
            constructDpopProofAsync: (claims, key, ct) => DpopProofConstruction.BuildAsync(
                claims, key, TestSetup.Base64UrlEncoder, DpopTestSupport.Serializer,
                MicrosoftCryptographicFunctionsAdapter.SignP256Async, Pool, ct),
            dpopKey: dpopKey,
            lookupDpopNonce: nonceCache.Lookup,
            storeDpopNonce: nonceCache.Store);

        return new OAuthClient(infrastructure);
    }


    /// <summary>Changes the middle character of a base64url value to another base64url character.</summary>
    /// <param name="value">The value.</param>
    /// <returns>The value with one character changed.</returns>
    private static string ChangeMiddleCharacter(string value)
    {
        int middle = value.Length / 2;
        char changed = value[middle] == 'A' ? 'B' : 'A';

        return string.Concat(value.AsSpan(0, middle), changed.ToString(), value.AsSpan(middle + 1));
    }


    /// <summary>Changes the case of the first ASCII letter of a value.</summary>
    /// <param name="value">The value, carrying at least one ASCII letter.</param>
    /// <returns>The value with its first letter in the other case.</returns>
    private static string ChangeCaseOfFirstLetter(string value)
    {
        int index = 0;
        while(!char.IsAsciiLetter(value[index]))
        {
            index++;
        }

        char c = value[index];
        char changed = char.IsUpper(c) ? char.ToLowerInvariant(c) : char.ToUpperInvariant(c);

        return string.Concat(value.AsSpan(0, index), changed.ToString(), value.AsSpan(index + 1));
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
            candidateIntegration.ValidateClientCredentialsAsync = static (reading, registration, context, ct) =>
                ValueTask.FromResult(
                    reading.ClientSecret is string secret
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
            candidateIntegration.ValidateClientCredentialsAsync = static (reading, registration, context, ct) =>
                ValueTask.FromResult(
                    reading.ClientSecret is string secret
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
    /// <see cref="PrivateKeyJwtClientAuthentication.BuildValidator(System.Collections.Generic.IReadOnlyCollection{string}?,CheckClientAssertionJtiReplayDelegate?,Verifiable.OAuth.Server.Pipeline.ResolveJwksUriDelegate?,ClientAssertionAudiencePolicy?)"/>
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
