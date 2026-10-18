using Microsoft.Extensions.Time.Testing;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Introspection;
using Verifiable.OAuth.Server;
using Verifiable.Server.Routing;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The protected resource's half of RFC 7662 token introspection over the real wire: the resource's OAuth client
/// (<see cref="TokenIntrospectionClient.IntrospectAsync"/>) posts to the authorization server's introspection endpoint
/// on the loopback listener of <see cref="TestHostShell"/>, or of a <see cref="MinimalHttpHost"/> standing in for an
/// authorization server whose answers the library's server does not emit, and reads the answer through
/// <see cref="OAuthResponseParsers.ParseTokenIntrospectionResponse"/>. Every exchange passes through the resource's
/// <see cref="IntrospectionExchangeRecorder"/>, so each row reads what was sent and received.
/// </summary>
[TestClass]
internal sealed class TokenIntrospectionClientTests
{
    /// <summary>The MSTest-supplied per-test context.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>A fixed clock so issued artefacts are reproducible.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    /// <summary>The protected resource's client identifier at the authorization server.</summary>
    private const string ClientId = "https://introspection.client.test";

    /// <summary>The base URI the registered resource is reachable at.</summary>
    private static Uri ClientBaseUri { get; } = new("https://introspection.client.test");

    /// <summary>The protected resource's shared secret.</summary>
    private const string ClientSecret = "introspection-secret-of-the-resource";

    /// <summary>The token the resource asks about.</summary>
    private const string PresentedToken = "access-token-to-inspect";

    /// <summary>The capability the introspection endpoint requires.</summary>
    private static ImmutableHashSet<CapabilityIdentifier> IntrospectionCapabilities { get; } =
        ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthTokenIntrospection);

    /// <summary>The JWK SHA-256 Thumbprint the introspected tokens are bound to, the value of RFC 9449 Figure 11.</summary>
    private const string BoundThumbprint = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";

    /// <summary>The request every row sends: the presented token and the hint <c>access_token</c>.</summary>
    private static TokenIntrospectionRequest PresentedRequest { get; } = new() { Token = PresentedToken, TokenTypeHint = "access_token" };


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7662#section-2.1">RFC 7662 Section 2.1</see>: "The protected resource
    /// calls the introspection endpoint using an HTTP POST [RFC7231] request with parameters sent as
    /// "application/x-www-form-urlencoded" data", "token REQUIRED. The string value of the token." and "token_type_hint
    /// OPTIONAL. A hint about the type of the token submitted for introspection.";
    /// <see href="https://www.rfc-editor.org/rfc/rfc7662#section-2.2">Section 2.2</see>: "The server responds with a JSON
    /// object [RFC7159] in "application/json" format with the following top-level members." A resource authenticating
    /// by <c>client_secret_basic</c> introspects an active token over the wire: the request is one POST with
    /// <c>Content-Type: application/x-www-form-urlencoded</c>, the body
    /// <c>token=access-token-to-inspect&amp;token_type_hint=access_token</c> and one <c>Authorization: Basic</c> line;
    /// the answer is received 200 with <c>Content-Type: application/json</c> and read member by member: <c>scope</c> <c>read write</c>, <c>client_id</c>
    /// <c>https://some.other.client</c>, <c>username</c> <c>jdoe</c>, <c>token_type</c> <c>Bearer</c>, <c>sub</c>
    /// <c>Z5O3upPC88QrAjx00dis</c>, <c>aud</c> <c>["https://protected.example.net/resource"]</c>, <c>iss</c>
    /// <c>https://introspection.client.test</c>, <c>jti</c> <c>token-jti-1</c>, <c>iat</c> 2026-06-01T11:00Z and
    /// <c>exp</c> 2026-06-01T13:00Z.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ResourceServerIntrospectsAnActiveTokenOverTheWireAsync()
    {
        DateTimeOffset issuedAt = new(2026, 6, 1, 11, 0, 0, TimeSpan.Zero);
        DateTimeOffset expiresAt = new(2026, 6, 1, 13, 0, 0, TimeSpan.Zero);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> secret = ClientAuthenticationFixtures.BuildSecretKeyMaterial(ClientSecret, BaseMemoryPool.Shared);
        try
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = await host.RegisterClientAsync(ClientId, ClientBaseUri, IntrospectionCapabilities).ConfigureAwait(false);
            ConcurrentQueue<(string Token, string? Hint)> introspected = new();
            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.ValidateClientCredentialsAsync = static (reading, registration, _, _) =>
                    ValueTask.FromResult(AuthCodeFlowDriver.DecodeAndMatchBasicHeader(reading, registration.ClientId, ClientSecret));
                candidateIntegration.IntrospectTokenAsync = (token, hint, _, _, _) =>
                {
                    introspected.Enqueue((token, hint));

                    return ValueTask.FromResult(new TokenIntrospectionResult
                    {
                        IsActive = true,
                        Scope = "read write",
                        ClientId = "https://some.other.client",
                        Username = "jdoe",
                        TokenType = "Bearer",
                        Subject = "Z5O3upPC88QrAjx00dis",
                        Audience = ["https://protected.example.net/resource"],
                        Issuer = "https://introspection.client.test",
                        JwtId = "token-jti-1",
                        IssuedAt = issuedAt,
                        ExpiresAt = expiresAt
                    });
                };
            }).ConfigureAwait(false);
            await ClientAuthenticationFixtures.DeclareServerSideAuthMethodAsync(host, material, ClientAuthenticationMethod.ClientSecretBasic).ConfigureAwait(false);
            using IntrospectingResourceClient resource = await IntrospectingResourceClient.CreateAsync(
                host, material, ClientAuthenticationMethod.ClientSecretBasic, secret, [host.ServerCertificate], alterMetadata: null,
                TestContext.CancellationToken).ConfigureAwait(false);

            Result<TokenIntrospectionResult, OAuthParseError> result = await IntrospectAsync(resource).ConfigureAwait(false);

            Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The introspection request is answered without a server fault.");
            Assert.IsTrue(result.IsSuccess, Describe(result));
            TokenIntrospectionResult answer = result.Value;
            Assert.IsTrue(answer.IsActive);
            Assert.AreEqual("read write", answer.Scope);
            Assert.AreEqual("https://some.other.client", answer.ClientId);
            Assert.AreEqual("jdoe", answer.Username);
            Assert.AreEqual("Bearer", answer.TokenType);
            Assert.AreEqual("Z5O3upPC88QrAjx00dis", answer.Subject);
            Assert.AreEqual("https://protected.example.net/resource", Assert.ContainsSingle(answer.Audience!));
            Assert.AreEqual("https://introspection.client.test", answer.Issuer);
            Assert.AreEqual("token-jti-1", answer.JwtId);
            Assert.AreEqual(new DateTimeOffset(2026, 6, 1, 11, 0, 0, TimeSpan.Zero), answer.IssuedAt);
            Assert.AreEqual(new DateTimeOffset(2026, 6, 1, 13, 0, 0, TimeSpan.Zero), answer.ExpiresAt);
            Assert.IsNull(answer.Confirmation, "A token bound to no key carries no confirmation.");
            (string token, string? hint) = Assert.ContainsSingle(introspected);
            Assert.AreEqual(PresentedToken, token);
            Assert.AreEqual("access_token", hint);
            IntrospectionExchange exchange = Assert.ContainsSingle(resource.Recorder.Exchanges);
            Assert.AreEqual("POST", exchange.Method);
            Assert.AreEqual("application/x-www-form-urlencoded", Assert.ContainsSingle(exchange.RequestHeaderValues("Content-Type")));
            Assert.AreEqual("token=access-token-to-inspect&token_type_hint=access_token", exchange.RequestBody);
            Assert.AreEqual(
                "Basic aHR0cHMlM0ElMkYlMkZpbnRyb3NwZWN0aW9uLmNsaWVudC50ZXN0OmludHJvc3BlY3Rpb24tc2VjcmV0LW9mLXRoZS1yZXNvdXJjZQ==",
                Assert.ContainsSingle(exchange.RequestHeaderValues("Authorization")));
            Assert.AreEqual(200, exchange.StatusCode);
            Assert.AreEqual("application/json", exchange.ResponseContentType, "The answer is a JSON object in application/json format.");
        }
        finally
        {
            secret.PublicKey.Dispose();
            secret.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7662#section-2.1">RFC 7662 Section 2.1</see>: "To prevent token
    /// scanning attacks, the endpoint MUST also require some form of authorization to access this endpoint, such as
    /// client authentication as described in OAuth 2.0 [RFC6749]";
    /// <see href="https://www.rfc-editor.org/rfc/rfc9701#section-4">RFC 9701 Section 4</see>: "The AS MUST authenticate
    /// the caller at the token introspection endpoint. Authentication can utilize client authentication methods". A
    /// resource introspects over the wire authenticated by the method its registration names, and the authorization
    /// server's client authentication reads that method's credential: under <c>client_secret_basic</c> an
    /// <c>Authorization: Basic</c> attempt, under <c>client_secret_post</c> a <c>client_secret</c> form parameter, under
    /// <c>private_key_jwt</c> a <c>client_assertion</c> of the type
    /// <c>urn:ietf:params:oauth:client-assertion-type:jwt-bearer</c>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523 Section 3</see>, item 3: "The JWT MUST
    /// contain an "aud" (audience) claim containing a value that identifies the authorization server as an intended
    /// audience. The token endpoint URL of the authorization server MAY be used as a value for an "aud" element to
    /// identify the authorization server as an intended audience of the JWT." and "the precise strings to be used as the
    /// audience for a given authorization server must be configured out of band by the authorization server and the
    /// issuer of the JWT." The assertion names the audience the registration selects: under the default
    /// <see cref="ClientAssertionAudience.IssuerIdentifier"/> the authorization server's issuer identifier, and under
    /// <see cref="ClientAssertionAudience.TokenEndpoint"/> the URL of the endpoint the operation posts to, the
    /// introspection endpoint. The authorization server is configured to admit that one string beside the identities its
    /// validator admits of its own, and the row reads the assertion's <c>aud</c> as the authorization server received it.
    /// </summary>
    /// <param name="row">
    /// The method: <see cref="BasicRow"/>, <see cref="PostRow"/>, <see cref="PrivateKeyJwtRow"/> or
    /// <see cref="PrivateKeyJwtTokenEndpointAudienceRow"/>.
    /// </param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(BasicRow)]
    [DataRow(PostRow)]
    [DataRow(PrivateKeyJwtRow)]
    [DataRow(PrivateKeyJwtTokenEndpointAudienceRow)]
    public async Task ResourceServerAuthenticatesTheIntrospectionRequestByItsRegisteredMethodAsync(string row)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyMaterial = row switch
        {
            PrivateKeyJwtRow or PrivateKeyJwtTokenEndpointAudienceRow => TestKeyMaterialProvider.CreateFreshP256KeyMaterial(),
            _ => ClientAuthenticationFixtures.BuildSecretKeyMaterial(ClientSecret, BaseMemoryPool.Shared)
        };

        try
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = await host.RegisterClientAsync(ClientId, ClientBaseUri, IntrospectionCapabilities).ConfigureAwait(false);
            await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
            const string SigningKeyId = "introspecting-resource-key-1";
            ClientAuthenticationMethod method = row switch
            {
                BasicRow => ClientAuthenticationMethod.ClientSecretBasic,
                PostRow => ClientAuthenticationMethod.ClientSecretPost,
                _ => ClientAuthenticationMethod.PrivateKeyJwt
            };

            Uri listenerBase = host.Host("default").HttpBaseAddress!;
            Uri introspectionEndpoint = new(listenerBase,
                TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeIntrospect, material.Registration.TenantId.Value));
            Uri alignedIssuer = new(listenerBase, material.Registration.IssuerUri!.AbsolutePath);
            string? expectedAudience = row switch
            {
                PrivateKeyJwtRow => alignedIssuer.OriginalString,
                PrivateKeyJwtTokenEndpointAudienceRow => introspectionEndpoint.OriginalString,
                _ => null
            };

            ValidateClientCredentialsDelegate assertionValidator = PrivateKeyJwtClientAuthentication.BuildValidator(
                additionalAcceptedAudiences: [expectedAudience ?? alignedIssuer.OriginalString]);
            ConcurrentQueue<ClientCredentialReading> readings = new();
            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.ValidateClientCredentialsAsync = (reading, registration, context, ct) =>
                {
                    readings.Enqueue(reading);

                    return row switch
                    {
                        BasicRow => ValueTask.FromResult(AuthCodeFlowDriver.DecodeAndMatchBasicHeader(reading, registration.ClientId, ClientSecret)),
                        PostRow => ValueTask.FromResult(string.Equals(reading.ClientSecret, ClientSecret, StringComparison.Ordinal)),
                        _ => assertionValidator(reading, registration, context, ct)
                    };
                };

                candidateIntegration.IntrospectTokenAsync = static (_, _, _, _, _) =>
                    ValueTask.FromResult(new TokenIntrospectionResult { IsActive = true, Subject = "Z5O3upPC88QrAjx00dis" });
            }).ConfigureAwait(false);
            await (row switch
            {
                PrivateKeyJwtRow or PrivateKeyJwtTokenEndpointAudienceRow => DeclarePrivateKeyJwtAsync(host, material, keyMaterial.PublicKey, SigningKeyId),
                _ => ClientAuthenticationFixtures.DeclareServerSideAuthMethodAsync(host, material, method)
            }).ConfigureAwait(false);
            using IntrospectingResourceClient resource = await IntrospectingResourceClient.CreateAsync(
                host, material, method, keyMaterial, [host.ServerCertificate], alterMetadata: null, TestContext.CancellationToken).ConfigureAwait(false);
            ClientAssertionOptions? assertionOptions = row switch
            {
                PrivateKeyJwtRow or PrivateKeyJwtTokenEndpointAudienceRow => new ClientAssertionOptions
                {
                    SigningKeyId = SigningKeyId,
                    HeaderSerializer = host.Server.OAuth().Codecs.JwtHeaderSerializer!,
                    PayloadSerializer = host.Server.OAuth().Codecs.JwtPayloadSerializer!
                },
                _ => null
            };

            ClientRegistration registration = row switch
            {
                PrivateKeyJwtTokenEndpointAudienceRow => resource.Registration with { ClientAssertionAudience = ClientAssertionAudience.TokenEndpoint },
                _ => resource.Registration
            };

            Result<TokenIntrospectionResult, OAuthParseError> result = await resource.Client.Introspection.IntrospectAsync(
                registration, PresentedRequest, [], assertionOptions, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The introspection request is answered without a server fault.");
            Assert.IsTrue(result.IsSuccess, Describe(result));
            ClientCredentialReading credential = Assert.ContainsSingle(readings);
            (bool isBasicAttempt, bool isFormSecret, string? assertionType) = row switch
            {
                BasicRow => (true, false, null),
                PostRow => (false, true, null),
                _ => (false, false, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
            };

            Assert.AreEqual(isBasicAttempt, credential.HasBasicAuthorization, "An Authorization: Basic attempt is carried under client_secret_basic alone.");
            Assert.AreEqual(isFormSecret, credential.HasClientSecret, "A client_secret form parameter is carried under client_secret_post alone.");
            Assert.AreEqual(assertionType is not null, credential.HasClientAssertion, "A client_assertion is carried under private_key_jwt alone.");
            Assert.AreEqual(assertionType, credential.ClientAssertionType);
            Assert.AreEqual(
                expectedAudience,
                credential.ClientAssertion is string assertion ? ReadAssertionAudience(assertion) : null,
                "The assertion's aud is the audience the registration selects.");
        }
        finally
        {
            keyMaterial.PublicKey.Dispose();
            keyMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// Declares <c>private_key_jwt</c> as the resource's method at the authorization server, publishing
    /// <paramref name="publicKey"/> under <paramref name="signingKeyId"/> as the registration's JWK set and admitting the
    /// key's algorithm for client assertions.
    /// </summary>
    /// <param name="host">The authorization server's fixture.</param>
    /// <param name="material">The resource's registration.</param>
    /// <param name="publicKey">The resource's assertion verification key.</param>
    /// <param name="signingKeyId">The key identifier the key is published under.</param>
    /// <returns>A task that completes when the declaration is published.</returns>
    private static Task DeclarePrivateKeyJwtAsync(TestHostShell host, VerifierKeyMaterial material, PublicKeyMemory publicKey, string signingKeyId)
    {
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(publicKey.Tag);

        return ClientAuthenticationFixtures.DeclareServerSideAuthMethodAsync(
            host, material, ClientAuthenticationMethod.PrivateKeyJwt,
            clientJwks: ClientAuthenticationFixtures.BuildJwksJson(DpopJwkUtilities.ToJwk(publicKey, algorithm, TestSetup.Base64UrlEncoder), signingKeyId),
            assertionSigningAlgorithm: algorithm);
    }


    /// <summary>The row whose resource authenticates by <c>client_secret_basic</c>.</summary>
    private const string BasicRow = "client_secret_basic";

    /// <summary>The row whose resource authenticates by <c>client_secret_post</c>.</summary>
    private const string PostRow = "client_secret_post";

    /// <summary>The row whose resource authenticates by <c>private_key_jwt</c>.</summary>
    private const string PrivateKeyJwtRow = "private_key_jwt";

    /// <summary>
    /// The row whose resource authenticates by <c>private_key_jwt</c> under the
    /// <see cref="ClientAssertionAudience.TokenEndpoint"/> audience.
    /// </summary>
    private const string PrivateKeyJwtTokenEndpointAudienceRow = "private_key_jwt-token-endpoint-audience";


    /// <summary>
    /// The <c>aud</c> claim of <paramref name="clientAssertion"/>'s payload as the authorization server received it: the
    /// string, or the one string of a single-element array.
    /// </summary>
    /// <param name="clientAssertion">The compact client assertion.</param>
    /// <returns>The audience the assertion names.</returns>
    private static string? ReadAssertionAudience(string clientAssertion)
    {
        using JsonDocument payload = JwtPayloadReader.ParsePayloadJson(clientAssertion);
        JsonElement audience = payload.RootElement.GetProperty(WellKnownJwtClaimNames.Aud);

        return audience.ValueKind switch
        {
            JsonValueKind.String => audience.GetString(),
            JsonValueKind.Array => Assert.ContainsSingle(audience.EnumerateArray()).GetString(),
            _ => null
        };
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.2">RFC 9449 Section 6.2</see>: "Note that the resource
    /// server does not send a DPoP proof with the introspection request". A resource whose infrastructure wires DPoP, a
    /// proof construction, a DPoP key and a nonce cache, for its own token requests introspects a token over the wire:
    /// the authorization server receives the request with no <c>DPoP</c> field line, and the resource's recorder saw
    /// none sent.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task IntrospectionRequestCarriesNoDpopProofAsync()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> secret = ClientAuthenticationFixtures.BuildSecretKeyMaterial(ClientSecret, BaseMemoryPool.Shared);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> dpopKeyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = await host.RegisterClientAsync(ClientId, ClientBaseUri, IntrospectionCapabilities).ConfigureAwait(false);
            ConcurrentQueue<int> dpopFieldLineCounts = new();
            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.ValidateClientCredentialsAsync = static (reading, registration, _, _) =>
                    ValueTask.FromResult(AuthCodeFlowDriver.DecodeAndMatchBasicHeader(reading, registration.ClientId, ClientSecret));
                candidateIntegration.IntrospectTokenAsync = (_, _, _, context, _) =>
                {
                    dpopFieldLineCounts.Enqueue(
                        context.IncomingRequest!.Headers.TryGetAll(WellKnownHttpHeaderNames.DPoP, out IReadOnlyList<string>? lines) ? lines!.Count : 0);

                    return ValueTask.FromResult(new TokenIntrospectionResult { IsActive = true, Subject = "Z5O3upPC88QrAjx00dis" });
                };
            }).ConfigureAwait(false);
            await ClientAuthenticationFixtures.DeclareServerSideAuthMethodAsync(host, material, ClientAuthenticationMethod.ClientSecretBasic).ConfigureAwait(false);
            using IntrospectingResourceClient resource = await IntrospectingResourceClient.CreateAsync(
                host, material, ClientAuthenticationMethod.ClientSecretBasic, secret, [host.ServerCertificate], alterMetadata: null,
                TestContext.CancellationToken, new DpopKey(dpopKeyMaterial, WellKnownJwaValues.Es256)).ConfigureAwait(false);

            Result<TokenIntrospectionResult, OAuthParseError> result = await IntrospectAsync(resource).ConfigureAwait(false);

            Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The introspection request is answered without a server fault.");
            Assert.IsTrue(result.IsSuccess, Describe(result));
            Assert.AreEqual(0, Assert.ContainsSingle(dpopFieldLineCounts), "The authorization server receives no DPoP field line.");
            Assert.IsEmpty(Assert.ContainsSingle(resource.Recorder.Exchanges).RequestHeaderValues("DPoP"), "The resource sends no DPoP field line.");
        }
        finally
        {
            secret.PublicKey.Dispose();
            secret.PrivateKey.Dispose();
            dpopKeyMaterial.PublicKey.Dispose();
            dpopKeyMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7662#section-2.2">RFC 7662 Section 2.2</see>: "If the introspection
    /// call is properly authorized but the token is not active, does not exist on this server, or the protected resource
    /// is not allowed to introspect this particular token, then the authorization server MUST return an introspection
    /// response with the "active" field set to "false"." and "the authorization server SHOULD NOT include any additional
    /// information about an inactive token". An authorization server answering 200 <c>application/json</c> over the wire
    /// with <c>active</c> <c>false</c> is read as inactive and nothing else of the body is read: the rows
    /// <c>{"active":false}</c> and <c>{"active":false,"sub":"Z5O3upPC88QrAjx00dis","scope":"read","cnf":{"jkt":"0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"}}</c>
    /// both answer an inactive result with no subject, no scope and no confirmation.
    /// </summary>
    /// <param name="body">The answer's body.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("{\"active\":false}", DisplayName = "active false alone")]
    [DataRow("{\"active\":false,\"sub\":\"Z5O3upPC88QrAjx00dis\",\"scope\":\"read\",\"cnf\":{\"jkt\":\"0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I\"}}", DisplayName = "active false beside further members")]
    public async Task AnInactiveResponseIsReadAsInactiveAndNothingElseAsync(string body)
    {
        HostileIntrospection introspection = await IntrospectAtAHostileServerAsync(JsonAnswer(body)).ConfigureAwait(false);

        Assert.IsTrue(introspection.Result.IsSuccess, Describe(introspection.Result));
        Assert.IsFalse(introspection.Result.Value.IsActive);
        Assert.IsNull(introspection.Result.Value.Subject, "Nothing of an inactive answer beyond active is read.");
        Assert.IsNull(introspection.Result.Value.Scope, "Nothing of an inactive answer beyond active is read.");
        Assert.IsNull(introspection.Result.Value.Confirmation, "Nothing of an inactive answer beyond active is read.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7662#section-2.2">RFC 7662 Section 2.2</see>: "active REQUIRED.
    /// Boolean indicator of whether or not the presented token is currently active." An authorization server answering
    /// 200 over the wire with no boolean <c>active</c> member is refused as a malformed answer with the summary "The
    /// introspection response carries no boolean active member.": the rows <c>{}</c>, <c>{"active":"true"}</c>,
    /// <c>{"active":1}</c> and <c>{"ext":{"active":true}}</c>, whose one <c>active</c> is a member of a nested object and
    /// not a top-level member of the response
    /// (<see href="https://www.rfc-editor.org/rfc/rfc7662#section-2.2">Section 2.2</see>: "The server responds with a JSON
    /// object [RFC7159] in "application/json" format with the following top-level members.").
    /// </summary>
    /// <param name="body">The answer's body.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("{}", DisplayName = "no active member")]
    [DataRow("{\"active\":\"true\"}", DisplayName = "active a string")]
    [DataRow("{\"active\":1}", DisplayName = "active a number")]
    [DataRow("{\"ext\":{\"active\":true}}", DisplayName = "a nested active alone")]
    public async Task AResponseWithoutABooleanActiveIsRefusedAsync(string body)
    {
        HostileIntrospection introspection = await IntrospectAtAHostileServerAsync(JsonAnswer(body)).ConfigureAwait(false);

        OAuthMalformedResponse refusal = AssertFailure<OAuthMalformedResponse>(introspection.Result);
        Assert.AreEqual("The introspection response carries no boolean active member.", refusal.Support.Summary);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7662#section-2.2">RFC 7662 Section 2.2</see>: "scope OPTIONAL. A
    /// JSON string containing a space-separated list of scopes associated with this token, in the format described in
    /// Section 3.3 of OAuth 2.0 [RFC6749].", "exp OPTIONAL. Integer timestamp", "aud OPTIONAL. Service-specific string
    /// identifier or list of string identifiers", "token_type OPTIONAL. Type of the token as defined in Section 5.1 of
    /// OAuth 2.0 [RFC6749]." and "sub OPTIONAL. Subject of the token, as defined in JWT [RFC7519]."; RFC 6749 Appendix
    /// A.4: "scope       = scope-token *( SP scope-token )" and Appendix A.13: "token-type = type-name / URI-reference".
    /// The "Integer timestamp" of <c>exp</c>, <c>iat</c> and <c>nbf</c> names the NumericDate of
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-2">RFC 7519 Section 2</see> ("A JSON numeric value
    /// representing the number of seconds from 1970-01-01T00:00:00Z UTC until the specified UTC date/time, ignoring leap
    /// seconds.") held to an integer, and the reader holds it
    /// lexically: an integer NumericDate is a JSON number whose text is an optional minus sign and digits alone, so a
    /// fraction or an exponent is refused naming the member, whatever value the text denotes.
    /// An authorization server answering 200 over the wire with <c>active</c> <c>true</c> beside a member outside its
    /// definition is refused naming that member with an empty received value: <c>"scope":"read  write"</c> names
    /// <c>scope</c>; <c>"exp":"1419356238"</c>, <c>"exp":1.5e9</c> and <c>"exp":1500000000.5</c> name <c>exp</c>;
    /// <c>"aud":[1]</c> names <c>aud</c>; <c>"token_type":"Bearer token"</c> names <c>token_type</c>; <c>"sub":5</c> names
    /// <c>sub</c>.
    /// </summary>
    /// <param name="member">The member beside <c>active</c>.</param>
    /// <param name="fieldName">The member the refusal names.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("\"scope\":\"read  write\"", "scope", DisplayName = "scope with two spaces")]
    [DataRow("\"exp\":\"1419356238\"", "exp", DisplayName = "exp a string")]
    [DataRow("\"exp\":1.5e9", "exp", DisplayName = "exp in exponent notation")]
    [DataRow("\"exp\":1500000000.5", "exp", DisplayName = "exp a fraction")]
    [DataRow("\"aud\":[1]", "aud", DisplayName = "aud a list of a number")]
    [DataRow("\"token_type\":\"Bearer token\"", "token_type", DisplayName = "token_type outside the grammar")]
    [DataRow("\"sub\":5", "sub", DisplayName = "sub a number")]
    public async Task AMemberOutsideItsDefinitionIsRefusedAsync(string member, string fieldName)
    {
        HostileIntrospection introspection = await IntrospectAtAHostileServerAsync(JsonAnswer($"{{\"active\":true,{member}}}")).ConfigureAwait(false);

        OAuthInvalidFieldValue refusal = AssertFailure<OAuthInvalidFieldValue>(introspection.Result);
        Assert.AreEqual(fieldName, refusal.FieldName);
        Assert.AreEqual(string.Empty, refusal.ReceivedValue, "The refused value is never echoed.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7662#section-2.2">RFC 7662 Section 2.2</see>: "aud OPTIONAL.
    /// Service-specific string identifier or list of string identifiers representing the intended audience for this
    /// token, as defined in JWT [RFC7519]." An authorization server answering 200 over the wire with <c>active</c>
    /// <c>true</c> and <c>"aud":"https://rs.example/"</c> is read as the audience <c>["https://rs.example/"]</c>; with
    /// <c>"aud":["https://a.example/","https://b.example/"]</c> as <c>["https://a.example/","https://b.example/"]</c>.
    /// </summary>
    /// <param name="audience">The <c>aud</c> member's JSON value.</param>
    /// <param name="expected">The audience read, its entries joined by a space.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("\"https://rs.example/\"", "https://rs.example/", DisplayName = "aud a string")]
    [DataRow("[\"https://a.example/\",\"https://b.example/\"]", "https://a.example/ https://b.example/", DisplayName = "aud a list")]
    public async Task TheAudienceIsReadAsAStringOrAListAsync(string audience, string expected)
    {
        HostileIntrospection introspection = await IntrospectAtAHostileServerAsync(JsonAnswer($"{{\"active\":true,\"aud\":{audience}}}")).ConfigureAwait(false);

        Assert.IsTrue(introspection.Result.IsSuccess, Describe(introspection.Result));
        Assert.AreSequenceEqual(expected.Split(' '), introspection.Result.Value.Audience!.ToList());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7662#section-2.2">RFC 7662 Section 2.2</see>: "Specific
    /// implementations MAY extend this structure with their own service-specific response names as top-level members of
    /// this JSON object." An authorization server answering 200 over the wire with <c>active</c> <c>true</c>,
    /// <c>"acr":"urn:mace:incommon:iap:silver"</c>, <c>"auth_time":1419350238</c> and
    /// <c>"extension_field":"twenty-seven"</c> is read with the three extension members carried by name: the string
    /// <c>urn:mace:incommon:iap:silver</c>, the integer 1419350238 and the string <c>twenty-seven</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ExtensionMembersAreCarriedAsAdditionalClaimsAsync()
    {
        HostileIntrospection introspection = await IntrospectAtAHostileServerAsync(JsonAnswer(
            "{\"active\":true,\"acr\":\"urn:mace:incommon:iap:silver\",\"auth_time\":1419350238,\"extension_field\":\"twenty-seven\"}")).ConfigureAwait(false);

        Assert.IsTrue(introspection.Result.IsSuccess, Describe(introspection.Result));
        IReadOnlyDictionary<string, object> claims = introspection.Result.Value.AdditionalClaims!;
        Assert.HasCount(3, claims);
        Assert.AreEqual("urn:mace:incommon:iap:silver", claims["acr"]);
        Assert.AreEqual(1419350238L, claims["auth_time"]);
        Assert.AreEqual("twenty-seven", claims["extension_field"]);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7662#section-2.3">RFC 7662 Section 2.3</see>: "If the protected
    /// resource uses OAuth 2.0 client credentials to authenticate to the introspection endpoint and its credentials are
    /// invalid, the authorization server responds with an HTTP 401 (Unauthorized) as described in Section 5.2 of OAuth
    /// 2.0 [RFC6749]."; RFC 6749 Section 5.2: the error response's <c>error</c> and <c>error_description</c>. The
    /// authorization server's refusal is read as its error: a resource presenting a wrong <c>client_secret</c> form
    /// credential is answered 400 and read as <c>invalid_client</c> with the description "Client authentication
    /// failed."; a resource presenting a wrong secret in an <c>Authorization: Basic</c> attempt is answered 401 with the
    /// <c>Basic</c> challenge and read alike; an authorization server answering 401 with an empty body is read as a
    /// malformed answer with the summary "The introspection endpoint returned an empty response body.". The 400 for a
    /// wrong form credential is the library's authorization server departing from Section 2.3's 401: it answers the
    /// introspection endpoint's client authentication failure as its token endpoint answers one. The row asserts each
    /// answer as the authorization server serves it, and the resource reads both forms as the error.
    /// </summary>
    /// <param name="row">The refusal: <see cref="WrongFormSecretRow"/>, <see cref="WrongBasicSecretRow"/> or <see cref="EmptyUnauthorizedRow"/>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(WrongFormSecretRow)]
    [DataRow(WrongBasicSecretRow)]
    [DataRow(EmptyUnauthorizedRow)]
    public async Task TheAuthorizationServersRefusalIsReadAsItsErrorAsync(string row)
    {
        if(row == EmptyUnauthorizedRow)
        {
            HostileIntrospection hostile = await IntrospectAtAHostileServerAsync(new MinimalHttpResponse { StatusCode = 401 }).ConfigureAwait(false);

            OAuthMalformedResponse malformed = AssertFailure<OAuthMalformedResponse>(hostile.Result);
            Assert.AreEqual("The introspection endpoint returned an empty response body.", malformed.Support.Summary);

            return;
        }

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> wrongSecret = ClientAuthenticationFixtures.BuildSecretKeyMaterial("a-wrong-secret", BaseMemoryPool.Shared);
        try
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = await host.RegisterClientAsync(ClientId, ClientBaseUri, IntrospectionCapabilities).ConfigureAwait(false);
            ClientAuthenticationMethod method = row == WrongBasicSecretRow ? ClientAuthenticationMethod.ClientSecretBasic : ClientAuthenticationMethod.ClientSecretPost;
            await TestHostShell.AlterAsync(host.Server, static candidateIntegration =>
            {
                candidateIntegration.ValidateClientCredentialsAsync = static (reading, registration, _, _) =>
                    ValueTask.FromResult(
                        AuthCodeFlowDriver.DecodeAndMatchBasicHeader(reading, registration.ClientId, ClientSecret)
                        || string.Equals(reading.ClientSecret, ClientSecret, StringComparison.Ordinal));
                candidateIntegration.IntrospectTokenAsync = static (_, _, _, _, _) => ValueTask.FromResult(TokenIntrospectionResult.Inactive);
            }).ConfigureAwait(false);

            //The declaration advertises the one method beside none: under client_secret_post the server advertises no
            //client_secret_basic, so no challenge applies to a form credential.
            await ClientAuthenticationFixtures.DeclareServerSideAuthMethodAsync(host, material, method).ConfigureAwait(false);
            using IntrospectingResourceClient resource = await IntrospectingResourceClient.CreateAsync(
                host, material, method, wrongSecret, [host.ServerCertificate], alterMetadata: null, TestContext.CancellationToken).ConfigureAwait(false);

            Result<TokenIntrospectionResult, OAuthParseError> result = await IntrospectAsync(resource).ConfigureAwait(false);

            Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The introspection request is answered without a server fault.");
            OAuthProtocolError refusal = AssertFailure<OAuthProtocolError>(result);
            Assert.AreEqual("invalid_client", refusal.ErrorCode);
            Assert.AreEqual("Client authentication failed.", refusal.ErrorDescription);
            IntrospectionExchange exchange = Assert.ContainsSingle(resource.Recorder.Exchanges);
            if(row == WrongBasicSecretRow)
            {
                Assert.AreEqual(401, exchange.StatusCode);
                Assert.AreEqual(
                    $"Basic realm=\"{resource.Registration.AuthorizationServerIssuer.OriginalString}\"",
                    Assert.ContainsSingle(exchange.ResponseHeaderValues("WWW-Authenticate")));
            }
            else
            {
                Assert.AreEqual(400, exchange.StatusCode);
                Assert.IsEmpty(exchange.ResponseHeaderValues("WWW-Authenticate"), "No challenge applies to a form credential at a server advertising no client_secret_basic.");
            }
        }
        finally
        {
            wrongSecret.PublicKey.Dispose();
            wrongSecret.PrivateKey.Dispose();
        }
    }


    /// <summary>The row whose resource presents a wrong <c>client_secret</c> form credential.</summary>
    private const string WrongFormSecretRow = "wrong-form-secret";

    /// <summary>The row whose resource presents a wrong secret in an <c>Authorization: Basic</c> attempt.</summary>
    private const string WrongBasicSecretRow = "wrong-basic-secret";

    /// <summary>The row whose authorization server answers 401 with an empty body.</summary>
    private const string EmptyUnauthorizedRow = "empty-401";


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.2">RFC 9449 Section 6.2</see>: "For a DPoP-bound
    /// access token, the hash of the public key to which the token is bound is conveyed to the protected resource as
    /// metainformation in a token introspection response. The hash is conveyed using the same cnf content with jkt member
    /// structure as the JWK Thumbprint confirmation method, described in Section 6.1, as a top-level member of the
    /// introspection response JSON." and "If the token_type member is included in the introspection response, it MUST
    /// contain the value DPoP." A resource introspecting over the wire a token the application answers as bound to the
    /// thumbprint <c>0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I</c> reads that thumbprint as the confirmation and the
    /// token type <c>DPoP</c>: the rows, the application stating the type <c>DPoP</c>, and the application stating none,
    /// the server deriving it.
    /// </summary>
    /// <param name="tokenType">The token type the application states, or <see langword="null"/> for none.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("DPoP", DisplayName = "the token type DPoP stated")]
    [DataRow(null, DisplayName = "the token type derived")]
    public async Task TheBoundTokensConfirmationIsReadFromTheResponseAsync(string? tokenType)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(ClientId, ClientBaseUri, IntrospectionCapabilities).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _) => ValueTask.FromResult(true);
            candidateIntegration.IntrospectTokenAsync = (_, _, _, _, _) => ValueTask.FromResult(new TokenIntrospectionResult
            {
                IsActive = true,
                Subject = "Z5O3upPC88QrAjx00dis",
                TokenType = tokenType,
                Confirmation = new ConfirmationMethod { JwkThumbprint = BoundThumbprint }
            });
        }).ConfigureAwait(false);
        using IntrospectingResourceClient resource = await IntrospectingResourceClient.CreateAsync(
            host, material, ClientAuthenticationMethod.None, null, [host.ServerCertificate], alterMetadata: null, TestContext.CancellationToken).ConfigureAwait(false);

        Result<TokenIntrospectionResult, OAuthParseError> result = await IntrospectAsync(resource).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The introspection request is answered without a server fault.");
        Assert.IsTrue(result.IsSuccess, Describe(result));
        Assert.AreEqual(BoundThumbprint, result.Value.Confirmation?.JwkThumbprint);
        Assert.AreEqual("DPoP", result.Value.TokenType);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-6">RFC 9449 Section 6</see>: "Resource servers MUST be
    /// able to reliably identify whether an access token is DPoP-bound and ascertain sufficient information to verify the
    /// binding to the public key of the DPoP proof (see Section 7.1)." A <c>cnf</c> the resource cannot enforce is
    /// refused, never read as a token bound to no key, the library's fail-closed reading against
    /// <see href="https://www.rfc-editor.org/rfc/rfc7800#section-3.1">RFC 7800 Section 3.1</see>'s "all confirmation
    /// members that are not understood by implementations MUST be ignored". An authorization server answering 200 over
    /// the wire with <c>active</c> <c>true</c> and the <c>cnf</c> of each row is refused naming <c>cnf</c> with the
    /// reason "cnf must be an object carrying a non-empty string jkt, the confirmation this resource enforces.": the
    /// rows <c>{"x5t#S256":"bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2"}</c>, <c>{"jkt":""}</c>, <c>{"jkt":5}</c>,
    /// <c>"x"</c>, <c>null</c>, <c>{}</c> and <c>{"x":{"jkt":"NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"}}</c>, whose
    /// <c>jkt</c> is a member of a nested object and not of the <c>cnf</c> content
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.2">RFC 9449 Section 6.2</see>: "The hash is conveyed
    /// using the same cnf content with jkt member structure as the JWK Thumbprint confirmation method").
    /// </summary>
    /// <param name="confirmation">The <c>cnf</c> member's JSON value.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("{\"x5t#S256\":\"bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2\"}", DisplayName = "a certificate thumbprint alone")]
    [DataRow("{\"jkt\":\"\"}", DisplayName = "an empty jkt")]
    [DataRow("{\"jkt\":5}", DisplayName = "a jkt that is a number")]
    [DataRow("\"x\"", DisplayName = "a cnf that is a string")]
    [DataRow("null", DisplayName = "a cnf that is null")]
    [DataRow("{}", DisplayName = "an empty cnf object")]
    [DataRow("{\"x\":{\"jkt\":\"NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs\"}}", DisplayName = "a jkt in a nested object")]
    public async Task AConfirmationTheResourceCannotEnforceIsRefusedAsync(string confirmation)
    {
        HostileIntrospection introspection = await IntrospectAtAHostileServerAsync(JsonAnswer($"{{\"active\":true,\"cnf\":{confirmation}}}")).ConfigureAwait(false);

        OAuthInvalidFieldValue refusal = AssertFailure<OAuthInvalidFieldValue>(introspection.Result);
        Assert.AreEqual("cnf", refusal.FieldName);
        Assert.AreEqual("cnf must be an object carrying a non-empty string jkt, the confirmation this resource enforces.", refusal.Reason);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.2">RFC 9449 Section 6.2</see>: "If the token_type
    /// member is included in the introspection response, it MUST contain the value DPoP.";
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">Section 7.2</see>: "such a protected resource MUST
    /// reject a DPoP-bound access token received as a bearer token per [RFC6750]." An answer whose <c>token_type</c> and
    /// <c>cnf</c> disagree does not reliably identify whether the token is DPoP-bound and is refused: over the wire,
    /// <c>"token_type":"Bearer"</c> beside <c>"cnf":{"jkt":"0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"}</c> is refused
    /// naming <c>token_type</c> with the reason "token_type must be DPoP for a token whose cnf carries a jkt.", and
    /// <c>"token_type":"DPoP"</c> with no <c>cnf</c> is refused naming <c>cnf</c> with the reason "A token_type of DPoP
    /// names a DPoP-bound token, and the response conveys no cnf jkt to check it against.", as is
    /// <c>"token_type":"DPoP"</c> beside <c>"ext":{"cnf":{"jkt":"NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"}}</c>, whose
    /// one <c>cnf</c> is a member of a nested object and not the top-level member Section 6.2 names ("as a top-level
    /// member of the introspection response JSON").
    /// </summary>
    /// <param name="members">The members beside <c>active</c>.</param>
    /// <param name="fieldName">The member the refusal names.</param>
    /// <param name="reason">The refusal's reason.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("\"token_type\":\"Bearer\",\"cnf\":{\"jkt\":\"0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I\"}", "token_type",
        "token_type must be DPoP for a token whose cnf carries a jkt.", DisplayName = "Bearer beside a jkt")]
    [DataRow("\"token_type\":\"DPoP\"", "cnf",
        "A token_type of DPoP names a DPoP-bound token, and the response conveys no cnf jkt to check it against.", DisplayName = "DPoP without a cnf")]
    [DataRow("\"token_type\":\"DPoP\",\"ext\":{\"cnf\":{\"jkt\":\"NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs\"}}", "cnf",
        "A token_type of DPoP names a DPoP-bound token, and the response conveys no cnf jkt to check it against.", DisplayName = "DPoP with a nested cnf alone")]
    public async Task ATokenTypeContradictingTheConfirmationIsRefusedAsync(string members, string fieldName, string reason)
    {
        HostileIntrospection introspection = await IntrospectAtAHostileServerAsync(JsonAnswer($"{{\"active\":true,{members}}}")).ConfigureAwait(false);

        OAuthInvalidFieldValue refusal = AssertFailure<OAuthInvalidFieldValue>(introspection.Result);
        Assert.AreEqual(fieldName, refusal.FieldName);
        Assert.AreEqual(reason, refusal.Reason);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7662#section-2.2">RFC 7662 Section 2.2</see>: "The server responds
    /// with a JSON object [RFC7159] in "application/json" format with the following top-level members." and "Specific
    /// implementations MAY extend this structure with their own service-specific response names as top-level members of
    /// this JSON object." The members Section 2.2 defines are the response object's own; a member of the same name inside
    /// an extension member's value is that value's. An authorization server answering 200 over the wire with
    /// <c>{"active":true,"ext":{"active":false,"sub":"nested","cnf":{"jkt":"NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"}},"sub":"real"}</c>
    /// is read as active with the subject <c>real</c> and no confirmation, the nested <c>active</c>, <c>sub</c> and
    /// <c>cnf</c> read as none of the response's members, and <c>ext</c> carried as an extension member whose decoded
    /// value holds <c>active</c> <see langword="false"/>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ANestedNamesakeNeverShadowsATopLevelMemberAsync()
    {
        HostileIntrospection introspection = await IntrospectAtAHostileServerAsync(JsonAnswer(
            "{\"active\":true,\"ext\":{\"active\":false,\"sub\":\"nested\",\"cnf\":{\"jkt\":\"NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs\"}},\"sub\":\"real\"}"))
            .ConfigureAwait(false);

        Assert.IsTrue(introspection.Result.IsSuccess, Describe(introspection.Result));
        TokenIntrospectionResult answer = introspection.Result.Value;
        Assert.IsTrue(answer.IsActive, "The top-level active is read.");
        Assert.AreEqual("real", answer.Subject, "The top-level sub is read.");
        Assert.IsNull(answer.Confirmation, "A cnf nested in an extension member is no confirmation of the token.");
        IReadOnlyDictionary<string, object> claims = answer.AdditionalClaims!;
        IReadOnlyDictionary<string, object?> extension = Assert.IsInstanceOfType<IReadOnlyDictionary<string, object?>>(Assert.ContainsSingle(claims).Value);
        Assert.AreEqual("ext", Assert.ContainsSingle(claims).Key);
        Assert.IsFalse((bool)extension["active"]!, "The nested active belongs to the extension member's value.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7493#section-2.3">RFC 7493 Section 2.3</see>: "Objects in I-JSON
    /// messages MUST NOT have members with duplicate names."; <see href="https://www.rfc-editor.org/rfc/rfc8259#section-4">RFC
    /// 8259 Section 4</see>: "The names within an object SHOULD be unique." An object repeating a name is one two readers
    /// can read differently. An authorization server answering 200 over the wire with <c>{"active":true,"active":false}</c>
    /// is refused as a malformed answer with the summary "The introspection response is not a well-formed JSON object,
    /// repeats a member name, or holds a string the reader refuses.", neither of its <c>active</c> members read.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ARepeatedTopLevelNameIsRefusedAsync()
    {
        HostileIntrospection introspection = await IntrospectAtAHostileServerAsync(JsonAnswer("{\"active\":true,\"active\":false}")).ConfigureAwait(false);

        OAuthMalformedResponse refusal = AssertFailure<OAuthMalformedResponse>(introspection.Result);
        Assert.AreEqual(
            "The introspection response is not a well-formed JSON object, repeats a member name, or holds a string the reader refuses.",
            refusal.Support.Summary);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7662#section-4">RFC 7662 Section 4</see>: "If the response contains
    /// the "exp" parameter (expiration), the response MUST NOT be cached beyond the time indicated therein."; the library
    /// caches nothing, a cache being the application's. A resource introspecting one token twice over the wire reaches
    /// the authorization server twice: its introspection seam is invoked twice and both answers are read.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task EachIntrospectionReachesTheAuthorizationServerAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(ClientId, ClientBaseUri, IntrospectionCapabilities).ConfigureAwait(false);
        ConcurrentQueue<string> introspected = new();
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _) => ValueTask.FromResult(true);
            candidateIntegration.IntrospectTokenAsync = (token, _, _, _, _) =>
            {
                introspected.Enqueue(token);

                return ValueTask.FromResult(new TokenIntrospectionResult
                {
                    IsActive = true,
                    Subject = "Z5O3upPC88QrAjx00dis",
                    ExpiresAt = new DateTimeOffset(2026, 6, 1, 13, 0, 0, TimeSpan.Zero)
                });
            };
        }).ConfigureAwait(false);
        using IntrospectingResourceClient resource = await IntrospectingResourceClient.CreateAsync(
            host, material, ClientAuthenticationMethod.None, null, [host.ServerCertificate], alterMetadata: null, TestContext.CancellationToken).ConfigureAwait(false);

        Result<TokenIntrospectionResult, OAuthParseError> first = await IntrospectAsync(resource).ConfigureAwait(false);
        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The first introspection request is answered without a server fault.");
        Result<TokenIntrospectionResult, OAuthParseError> second = await IntrospectAsync(resource).ConfigureAwait(false);
        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The second introspection request is answered without a server fault.");

        Assert.IsTrue(first.IsSuccess, Describe(first));
        Assert.IsTrue(second.IsSuccess, Describe(second));
        Assert.HasCount(2, introspected, "Every introspection reaches the authorization server.");
        Assert.HasCount(2, resource.Recorder.Exchanges, "Every introspection is one exchange.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7662#section-2">RFC 7662 Section 2</see>: "The introspection endpoint
    /// MUST be protected by a transport-layer security mechanism as described in Section 4.";
    /// <see href="https://www.rfc-editor.org/rfc/rfc9701#section-8.2">RFC 9701 Section 8.2</see>: "The authorization
    /// server MUST use Transport Layer Security (TLS) 1.2 (or higher), per BCP 195 [RFC9325], in order to prevent token
    /// data leakage." A resource whose metadata names an introspection endpoint
    /// <c>http://127.0.0.1:&lt;port&gt;/introspect</c>, served by a plain TCP listener on the loopback, under an outbound
    /// policy admitting loopback addresses, refuses before it dials: the operation answers the policy's denial with the
    /// reason "Scheme 'http' is not permitted." and the specification reference <c>RFC 7662 Section 2</c> before the
    /// listener receives a connection, and the resource's transport was handed no request.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task AnIntrospectionEndpointOutsideHttpsIsNeverDialedAsync()
    {
        using TcpListener listener = new(IPAddress.Loopback, 0);
        listener.Start();
        using CancellationTokenSource acceptCancellation = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        Task<TcpClient> connection = listener.AcceptTcpClientAsync(acceptCancellation.Token).AsTask();
        try
        {
            Uri plainHttpEndpoint = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/introspect");
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = await host.RegisterClientAsync(ClientId, ClientBaseUri, IntrospectionCapabilities).ConfigureAwait(false);
            using IntrospectingResourceClient resource = await IntrospectingResourceClient.CreateAsync(
                host, material, ClientAuthenticationMethod.None, null, [host.ServerCertificate],
                metadata => metadata with { IntrospectionEndpoint = plainHttpEndpoint }, TestContext.CancellationToken).ConfigureAwait(false);

            Task<Result<TokenIntrospectionResult, OAuthParseError>> introspection = resource.Client.Introspection.IntrospectAsync(
                resource.Registration, PresentedRequest, [], clientAssertionOptions: null, TestContext.CancellationToken).AsTask();
            Task answered = await Task.WhenAny(introspection, connection).ConfigureAwait(false);
            bool isDialed = !ReferenceEquals(answered, introspection);
            if(isDialed)
            {
                //The dial reached the listener; closing the accepted connection ends the resource's request.
                (await connection.ConfigureAwait(false)).Dispose();
            }

            Result<TokenIntrospectionResult, OAuthParseError>? completed = await CompleteUnlessTheTransportFailedAsync(introspection).ConfigureAwait(false);

            Assert.IsFalse(isDialed, "The resource refuses before it dials: the listener receives no connection.");
            Assert.IsNotNull(completed, "The operation answers without a transport failure.");
            Result<TokenIntrospectionResult, OAuthParseError> result = completed.Value;
            Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "No request reached the authorization server.");
            OAuthOutboundFetchPolicyDenied denial = AssertFailure<OAuthOutboundFetchPolicyDenied>(result);
            Assert.AreEqual("Scheme 'http' is not permitted.", denial.DenyReason);
            Assert.AreEqual(plainHttpEndpoint, denial.Endpoint);
            Assert.AreEqual("RFC 7662 Section 2", denial.Support.SpecificationReference, "The denial cites the clause the policy serves at this endpoint.");
            Assert.IsEmpty(resource.Recorder.Exchanges, "The transport is handed no request.");
            Assert.IsFalse(listener.Pending(), "No connection is pending at the listener.");
        }
        finally
        {
            //A connection the listener did receive is closed so the resource's dial ends; an accept still pending is
            //cancelled with the listener.
            await acceptCancellation.CancelAsync().ConfigureAwait(false);
            if(connection.IsCompletedSuccessfully)
            {
                (await connection.ConfigureAwait(false)).Dispose();
            }
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8414#section-2">RFC 8414 Section 2</see>: "introspection_endpoint
    /// OPTIONAL. URL of the authorization server's OAuth 2.0 introspection endpoint [RFC7662]." A resource whose
    /// authorization server's metadata names no introspection endpoint sends no request: the operation refuses naming
    /// <c>introspection_endpoint</c>, and the resource's transport was handed no request.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task AnAuthorizationServerNamingNoIntrospectionEndpointIsNotDialedAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(ClientId, ClientBaseUri, IntrospectionCapabilities).ConfigureAwait(false);
        using IntrospectingResourceClient resource = await IntrospectingResourceClient.CreateAsync(
            host, material, ClientAuthenticationMethod.None, null, [host.ServerCertificate],
            static metadata => metadata with { IntrospectionEndpoint = null }, TestContext.CancellationToken).ConfigureAwait(false);

        Result<TokenIntrospectionResult, OAuthParseError> result = await IntrospectAsync(resource).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "No request reached the authorization server.");
        OAuthInvalidFieldValue refusal = AssertFailure<OAuthInvalidFieldValue>(result);
        Assert.AreEqual("introspection_endpoint", refusal.FieldName);
        Assert.AreEqual("The authorization server metadata names no introspection_endpoint.", refusal.Reason);
        Assert.IsEmpty(resource.Recorder.Exchanges, "The transport is handed no request.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8414#section-3.3">RFC 8414 Section 3.3</see>: "The "issuer" value
    /// returned MUST be identical to the authorization server's issuer identifier value into which the well-known URI
    /// string was inserted to create the URL used to retrieve the metadata. If these values are not identical, the data
    /// contained in the response MUST NOT be used." A resource whose resolved metadata names an issuer other than the one
    /// its registration pins uses none of it: the operation refuses naming <c>issuer</c>, the authorization server saw no
    /// request and its introspection seam was never invoked.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task MetadataOfAnotherIssuerIsNotUsedAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(ClientId, ClientBaseUri, IntrospectionCapabilities).ConfigureAwait(false);
        bool isIntrospected = false;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _) => ValueTask.FromResult(true);
            candidateIntegration.IntrospectTokenAsync = (_, _, _, _, _) =>
            {
                isIntrospected = true;

                return ValueTask.FromResult(new TokenIntrospectionResult { IsActive = true });
            };
        }).ConfigureAwait(false);
        using IntrospectingResourceClient resource = await IntrospectingResourceClient.CreateAsync(
            host, material, ClientAuthenticationMethod.None, null, [host.ServerCertificate],
            static metadata => metadata with { Issuer = new Uri("https://another-issuer.example/") }, TestContext.CancellationToken).ConfigureAwait(false);

        Result<TokenIntrospectionResult, OAuthParseError> result = await IntrospectAsync(resource).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "No request reached the authorization server.");
        OAuthInvalidFieldValue refusal = AssertFailure<OAuthInvalidFieldValue>(result);
        Assert.AreEqual("issuer", refusal.FieldName);
        Assert.IsEmpty(resource.Recorder.Exchanges, "The transport is handed no request.");
        Assert.IsFalse(isIntrospected, "The authorization server's introspection seam is never invoked.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.4.8">RFC 9110 Section 15.4.8</see>: "The 307
    /// (Temporary Redirect) status code indicates that the target resource resides temporarily under a different URI and
    /// the user agent MUST NOT change the request method if it performs an automatic redirection to that URI." The
    /// introspection request carries the token and the resource's credential, so a redirect followed would send both to
    /// the origin its <c>Location</c> names. An authorization server answering 307 with
    /// <c>Location: https://elsewhere.example/introspect</c> over the wire is refused, the redirect never followed: the
    /// operation answers the refusal with the status 307 and the <c>Location</c> as sent, and the listener received the
    /// one request.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ARedirectingIntrospectionEndpointIsRefusedAsync()
    {
        HostileIntrospection introspection = await IntrospectAtAHostileServerAsync(new MinimalHttpResponse
        {
            StatusCode = 307,
            Headers = new Dictionary<string, string>(StringComparer.Ordinal) { ["Location"] = "https://elsewhere.example/introspect" }
        }).ConfigureAwait(false);

        OAuthRedirectRefused refusal = AssertFailure<OAuthRedirectRefused>(introspection.Result);
        Assert.AreEqual(307, refusal.StatusCode);
        Assert.AreEqual("https://elsewhere.example/introspect", refusal.Location);
        Assert.AreEqual("POST", Assert.ContainsSingle(introspection.Received).Method);
        Assert.HasCount(1, introspection.Exchanges, "The redirect is never followed.");
    }


    /// <summary>
    /// The result of one introspection at a hostile authorization server: the operation's answer, the requests the
    /// hostile listener received and the exchanges the resource's recorder saw.
    /// </summary>
    /// <param name="Result">The operation's answer.</param>
    /// <param name="Received">The requests the hostile listener received, in order.</param>
    /// <param name="Exchanges">The exchanges the resource's recorder saw, in order.</param>
    private sealed record HostileIntrospection(
        Result<TokenIntrospectionResult, OAuthParseError> Result,
        IReadOnlyList<MinimalHttpRequest> Received,
        IReadOnlyList<IntrospectionExchange> Exchanges);


    /// <summary>
    /// Introspects <see cref="PresentedRequest"/> at a <see cref="MinimalHttpHost"/> answering every request with
    /// <paramref name="answer"/>: the resource is registered at a <see cref="TestHostShell"/> whose metadata the resource
    /// resolves with its <c>introspection_endpoint</c> pointed at the hostile listener's <c>/introspect</c>, the resource
    /// authenticating by <c>none</c>. Asserts what the hostile listener received, the one request with the body
    /// <c>token=access-token-to-inspect&amp;token_type_hint=access_token</c> and no <c>DPoP</c> or <c>Authorization</c>
    /// field line, and that the authorization server's listener, which served the resource's metadata, captured no fault.
    /// The hostile listener's handler is this helper's own lambda, whose only acts are an enqueue and the fixed answer,
    /// so a fault there would surface as the answer itself.
    /// </summary>
    /// <param name="answer">The hostile listener's answer.</param>
    /// <returns>The operation's answer, the requests received and the exchanges recorded.</returns>
    private async Task<HostileIntrospection> IntrospectAtAHostileServerAsync(MinimalHttpResponse answer)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(ClientId, ClientBaseUri, IntrospectionCapabilities).ConfigureAwait(false);
        ConcurrentQueue<MinimalHttpRequest> received = new();
        await using MinimalHttpHost hostile = await MinimalHttpHost.StartAsync(
            (request, _) =>
            {
                received.Enqueue(request);

                return Task.FromResult(answer);
            },
            TestContext.CancellationToken).ConfigureAwait(false);
        using IntrospectingResourceClient resource = await IntrospectingResourceClient.CreateAsync(
            host, material, ClientAuthenticationMethod.None, null, [host.ServerCertificate, hostile.Certificate],
            metadata => metadata with { IntrospectionEndpoint = new Uri(hostile.BaseAddress, "/introspect") },
            TestContext.CancellationToken).ConfigureAwait(false);

        Result<TokenIntrospectionResult, OAuthParseError> result = await IntrospectAsync(resource).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The authorization server's listener captured no fault.");
        MinimalHttpRequest sent = Assert.ContainsSingle(received, "The hostile listener receives the one request.");
        Assert.AreEqual("token=access-token-to-inspect&token_type_hint=access_token", sent.Body);
        Assert.IsEmpty(sent.HeaderValues("DPoP"), "The request carries no DPoP field line.");
        Assert.IsEmpty(sent.HeaderValues("Authorization"), "A registration authenticating by none sends no Authorization field line.");

        return new HostileIntrospection(result, [.. received], [.. resource.Recorder.Exchanges]);
    }


    /// <summary>A 200 <c>application/json</c> answer carrying <paramref name="body"/>.</summary>
    /// <param name="body">The JSON body.</param>
    /// <returns>The hostile listener's answer.</returns>
    private static MinimalHttpResponse JsonAnswer(string body) => new()
    {
        StatusCode = 200,
        ContentType = "application/json",
        Body = body
    };


    /// <summary>Introspects <see cref="PresentedRequest"/> through <paramref name="resource"/> with a fresh exchange context and no assertion options.</summary>
    /// <param name="resource">The resource's client.</param>
    /// <returns>The operation's answer.</returns>
    private Task<Result<TokenIntrospectionResult, OAuthParseError>> IntrospectAsync(IntrospectingResourceClient resource) =>
        resource.Client.Introspection.IntrospectAsync(
            resource.Registration, PresentedRequest, [], clientAssertionOptions: null, TestContext.CancellationToken).AsTask();


    /// <summary>
    /// Awaits <paramref name="introspection"/> and answers its result, or <see langword="null"/> when the transport
    /// failed, a dial whose connection the listener closed.
    /// </summary>
    /// <param name="introspection">The operation's pending answer.</param>
    /// <returns>The operation's answer, or <see langword="null"/> when the transport failed.</returns>
    private static async Task<Result<TokenIntrospectionResult, OAuthParseError>?> CompleteUnlessTheTransportFailedAsync(
        Task<Result<TokenIntrospectionResult, OAuthParseError>> introspection)
    {
        try
        {
            return await introspection.ConfigureAwait(false);
        }
        catch(HttpRequestException)
        {
            return null;
        }
    }


    /// <summary>Asserts <paramref name="result"/> failed with a <typeparamref name="TError"/> and answers it.</summary>
    /// <typeparam name="TError">The failure type expected.</typeparam>
    /// <param name="result">The operation's answer.</param>
    /// <returns>The failure.</returns>
    private static TError AssertFailure<TError>(Result<TokenIntrospectionResult, OAuthParseError> result) where TError : OAuthParseError
    {
        Assert.IsFalse(result.IsSuccess, "The operation answers a failure.");

        return Assert.IsInstanceOfType<TError>(result.Error, Describe(result));
    }


    /// <summary>The text an assertion message carries for <paramref name="result"/>: success, or the failure's type, field and summary.</summary>
    /// <param name="result">The operation's answer.</param>
    /// <returns>The description.</returns>
    private static string Describe(Result<TokenIntrospectionResult, OAuthParseError> result) => result.IsSuccess
        ? "Success"
        : result.Error switch
        {
            OAuthInvalidFieldValue invalid => $"{nameof(OAuthInvalidFieldValue)} {invalid.FieldName}: {invalid.Reason}",
            OAuthProtocolError protocol => $"{nameof(OAuthProtocolError)} {protocol.ErrorCode}: {protocol.ErrorDescription}",
            OAuthParseError other => $"{other.GetType().Name}: {other.Support.Summary}"
        };
}
