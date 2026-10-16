using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Introspection;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// RFC 9701 JWT introspection responses (FAPI 2.0 Message Signing §5.5), driven
/// through the real dispatch pipeline: a resource server that sends
/// <c>Accept: application/token-introspection+jwt</c> receives a signed JWT whose
/// <c>token_introspection</c> claim carries the RFC 7662 members, typed
/// <c>token-introspection+jwt</c> so it cannot be confused with an access token.
/// </summary>
[TestClass]
internal sealed class TokenIntrospectionJwtResponseTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    private const string ClientId = "https://rs.introspection.client.test";

    private static Uri ClientBaseUri { get; } = new("https://rs.introspection.client.test");

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    private static ImmutableHashSet<CapabilityIdentifier> IntrospectionCapabilities { get; } =
        ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthTokenIntrospection);


    [TestMethod]
    public async Task SignedResponseCarriesRfc7662MembersInsideTokenIntrospectionClaim()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterSigningCapableResourceServerAsync(host).ConfigureAwait(false);
        await WireActiveTokenAsync(host).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchIntrospectionAsync(
            host, material, acceptJwt: true).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.AreEqual(WellKnownMediaTypes.Application.TokenIntrospectionJwt, response.ContentType);

        //RFC 9701 §8.1: the typ header distinguishes the response from an access token.
        using JsonDocument header = ParseSegment(response.Body, segmentIndex: 0);
        Assert.AreEqual(WellKnownMediaTypes.Jwt.TokenIntrospectionJwt,
            header.RootElement.GetProperty(WellKnownJoseHeaderNames.Typ).GetString());
        Assert.AreEqual(WellKnownJwaValues.Es256,
            header.RootElement.GetProperty(WellKnownJwkMemberNames.Alg).GetString());

        //The signature verifies against the AS's published key.
        bool isSignatureValid = await Jws.VerifyAsync(
            response.Body, TestSetup.Base64UrlDecoder,
            Pool,
            material.SigningPublicKey,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(isSignatureValid);

        //RFC 9701 §5: iss/aud/iat at the top level; sub and exp deliberately absent;
        //the RFC 7662 members ride inside token_introspection.
        using JsonDocument payload = ParseSegment(response.Body, segmentIndex: 1);
        JsonElement root = payload.RootElement;
        Assert.AreEqual(material.Registration.IssuerUri!.OriginalString,
            root.GetProperty(WellKnownJwtClaimNames.Iss).GetString());
        Assert.AreEqual(ClientId, root.GetProperty(WellKnownJwtClaimNames.Aud).GetString());
        Assert.AreEqual(TimeProvider.GetUtcNow().ToUnixTimeSeconds(),
            root.GetProperty(WellKnownJwtClaimNames.Iat).GetInt64());
        Assert.IsFalse(root.TryGetProperty(WellKnownJwtClaimNames.Sub, out _),
            "RFC 9701 §5: the top level SHOULD NOT carry sub.");
        Assert.IsFalse(root.TryGetProperty(WellKnownJwtClaimNames.Exp, out _),
            "RFC 9701 §5: the top level SHOULD NOT carry exp.");

        JsonElement introspection = root.GetProperty("token_introspection");
        Assert.IsTrue(introspection.GetProperty("active").GetBoolean());
        Assert.AreEqual("read write", introspection.GetProperty("scope").GetString());
        Assert.AreEqual("Z5O3upPC88QrAjx00dis", introspection.GetProperty("sub").GetString());
        Assert.AreEqual("token-jti-1", introspection.GetProperty("jti").GetString());
    }


    /// <summary>
    /// RFC 9396 §9.2 holds for the RFC 9701 signed JWT response too: the granted
    /// <c>authorization_details</c> ride inside the <c>token_introspection</c> claim, rendered as
    /// the §2 array structure — the same projection the plain JSON body emits, here through the
    /// wired JWT payload serializer.
    /// </summary>
    [TestMethod]
    public async Task SignedResponseCarriesAuthorizationDetailsInsideTheClaim()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterSigningCapableResourceServerAsync(host).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _) =>
                ValueTask.FromResult(true);

            candidateIntegration.IntrospectTokenAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(new TokenIntrospectionResult
                {
                    IsActive = true,
                    Scope = "credential",
                    AuthorizationDetails =
                    [
                        new AuthorizationDetail
                        {
                            Type = "openid_credential",
                            ExtensionData = new Dictionary<string, string>(StringComparer.Ordinal)
                            {
                                ["credential_configuration_id"] = "\"UniversityDegree_dc_sd_jwt\"",
                                ["credential_identifiers"] = "[\"CivilEngineeringDegree-2026\"]"
                            }
                        }
                    ]
                });
        }).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchIntrospectionAsync(
            host, material, acceptJwt: true).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument payload = ParseSegment(response.Body, segmentIndex: 1);
        JsonElement introspection = payload.RootElement.GetProperty("token_introspection");
        JsonElement details = introspection.GetProperty("authorization_details");

        Assert.AreEqual(JsonValueKind.Array, details.ValueKind);
        Assert.AreEqual(1, details.GetArrayLength());
        Assert.AreEqual("openid_credential", details[0].GetProperty("type").GetString());
        Assert.AreEqual("UniversityDegree_dc_sd_jwt",
            details[0].GetProperty("credential_configuration_id").GetString());
        Assert.AreEqual("CivilEngineeringDegree-2026",
            details[0].GetProperty("credential_identifiers")[0].GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9701#section-5">RFC 9701 Section 5</see>: "token_introspection A JSON
    /// object containing the members of the token introspection response, as specified in [RFC7662], Section 2.2.", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.2">RFC 9449 Section 6.2</see>: the hash of the bound
    /// public key "is conveyed using the same cnf content with jkt member structure as the JWK Thumbprint confirmation
    /// method, described in Section 6.1, as a top-level member of the introspection response JSON." and "If the
    /// token_type member is included in the introspection response, it MUST contain the value DPoP." An introspection
    /// request posted over the wire with <c>Accept: application/token-introspection+jwt</c> for a token the application
    /// answers as active and bound to the thumbprint <c>0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I</c>, stating no token
    /// type, is answered 200 with a JWT signed by the server's introspection key whose <c>token_introspection</c> claim
    /// carries <c>"cnf":{"jkt":"0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"}</c> and <c>"token_type":"DPoP"</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task SignedResponseConveysTheJwkThumbprintBindingInsideTheClaimAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterSigningCapableResourceServerAsync(host).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, static candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _) =>
                ValueTask.FromResult(true);

            candidateIntegration.IntrospectTokenAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(new TokenIntrospectionResult
                {
                    IsActive = true,
                    Scope = "read write",
                    Confirmation = new ConfirmationMethod { JwkThumbprint = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" }
                });
        }).ConfigureAwait(false);

        HttpResponseData response = await IntrospectSignedOverTheWireAsync(host, material).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        bool isSignatureValid = await Jws.VerifyAsync(
            response.Body, TestSetup.Base64UrlDecoder, Pool, material.SigningPublicKey, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(isSignatureValid, "The response is signed by the server's introspection key.");
        using JsonDocument payload = ParseSegment(response.Body, segmentIndex: 1);
        JsonElement introspection = payload.RootElement.GetProperty("token_introspection");
        Assert.IsTrue(introspection.TryGetProperty("cnf", out JsonElement confirmation), $"The claim carries the cnf member: {response.Body}");
        Assert.IsTrue(confirmation.TryGetProperty("jkt", out JsonElement thumbprint), $"The cnf member carries jkt: {response.Body}");
        Assert.AreEqual("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I", thumbprint.GetString(), response.Body);
        Assert.IsTrue(introspection.TryGetProperty("token_type", out JsonElement tokenType), $"The claim carries the token_type member: {response.Body}");
        Assert.AreEqual("DPoP", tokenType.GetString(), response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.1">RFC 9449 Section 6.1</see>: "The value of the jkt
    /// member MUST be the base64url encoding (as defined in [RFC7515]) of the JWK SHA-256 Thumbprint (according to
    /// [RFC7638]) of the DPoP public key (in JWK format) to which the access token is bound.", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9701#section-5">RFC 9701 Section 5</see>: "token_introspection A
    /// JSON object containing the members of the token introspection response, as specified in [RFC7662], Section 2.2."
    /// An application answer confirming the token by an empty thumbprint binds it to no key, a fault of the application's
    /// wiring: an introspection request posted over the wire with <c>Accept: application/token-introspection+jwt</c> is
    /// answered 500 with exactly the body
    /// <c>{"error":"server_error","error_description":"The server is not ready to serve this request."}</c> and no signed
    /// response.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task SignedResponseAnswersAConfirmationWithoutAThumbprintSpellingAsAServerErrorAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterSigningCapableResourceServerAsync(host).ConfigureAwait(false);
        await WireIntrospectionAnswerAsync(host, new TokenIntrospectionResult
        {
            IsActive = true,
            Scope = "read write",
            Confirmation = new ConfirmationMethod { JwkThumbprint = string.Empty }
        }).ConfigureAwait(false);

        HttpResponseData response = await IntrospectSignedOverTheWireAsync(host, material).ConfigureAwait(false);

        Assert.AreEqual(500, response.StatusCode, response.Body);
        Assert.AreEqual(
            "{\"error\":\"server_error\",\"error_description\":\"The server is not ready to serve this request.\"}", response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.2">RFC 9449 Section 6.2</see>: "If the token_type
    /// member is included in the introspection response, it MUST contain the value DPoP.", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9701#section-5">RFC 9701 Section 5</see>: "token_introspection A
    /// JSON object containing the members of the token introspection response, as specified in [RFC7662], Section 2.2."
    /// An application answer confirming the token by the thumbprint <c>0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I</c>
    /// whose extension members name a member the server writes from the confirmation would state the binding twice, a
    /// fault of the application's wiring: an introspection request posted over the wire with
    /// <c>Accept: application/token-introspection+jwt</c> is answered 500 with exactly the body
    /// <c>{"error":"server_error","error_description":"The server is not ready to serve this request."}</c> and no signed
    /// response. The rows: the extension member <c>"token_type":"Bearer"</c>; the extension member
    /// <c>"cnf":{"jkt":"NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"}</c>.
    /// </summary>
    /// <param name="row">
    /// The extension member: <see cref="TokenIntrospectionServerTests.TokenTypeExtensionRow"/> or
    /// <see cref="TokenIntrospectionServerTests.ConfirmationExtensionRow"/>.
    /// </param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(TokenIntrospectionServerTests.TokenTypeExtensionRow)]
    [DataRow(TokenIntrospectionServerTests.ConfirmationExtensionRow)]
    public async Task SignedResponseAnswersAnExtensionMemberNamingAWrittenMemberAsAServerErrorAsync(string row)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterSigningCapableResourceServerAsync(host).ConfigureAwait(false);
        await WireIntrospectionAnswerAsync(host, TokenIntrospectionServerTests.ConfirmedAnswerWithExtensionMember(row)).ConfigureAwait(false);

        HttpResponseData response = await IntrospectSignedOverTheWireAsync(host, material).ConfigureAwait(false);

        Assert.AreEqual(500, response.StatusCode, response.Body);
        Assert.AreEqual(
            "{\"error\":\"server_error\",\"error_description\":\"The server is not ready to serve this request.\"}", response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9701#section-5">RFC 9701 Section 5</see>: "If the access token is
    /// invalid, expired, revoked, or not intended for the calling resource server (audience), the authorization server
    /// MUST set the value of the active member in the token_introspection claim to false and MUST NOT include other
    /// members." An application answer for an inactive token that carries a confirmation by an empty thumbprint and
    /// extension members naming <c>active</c> (<see langword="true"/>), <c>cnf</c> and <c>token_type</c> (<c>Bearer</c>)
    /// is answered as an inactive token: an introspection request posted over the wire with
    /// <c>Accept: application/token-introspection+jwt</c> is answered 200 with a JWT signed by the server's introspection
    /// key whose <c>token_introspection</c> claim is exactly <c>{"active":false}</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task SignedResponseOfAnInactiveTokenCarriesNothingTheAnswerAddsAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterSigningCapableResourceServerAsync(host).ConfigureAwait(false);
        await WireIntrospectionAnswerAsync(host, TokenIntrospectionServerTests.InactiveAnswerCarryingFurtherMembers()).ConfigureAwait(false);

        HttpResponseData response = await IntrospectSignedOverTheWireAsync(host, material).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        bool isSignatureValid = await Jws.VerifyAsync(
            response.Body, TestSetup.Base64UrlDecoder, Pool, material.SigningPublicKey, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(isSignatureValid, "The response is signed by the server's introspection key.");
        using JsonDocument payload = ParseSegment(response.Body, segmentIndex: 1);
        Assert.IsTrue(
            payload.RootElement.TryGetProperty("token_introspection", out JsonElement introspection), $"The response carries the claim: {response.Body}");
        Assert.AreEqual("{\"active\":false}", introspection.GetRawText());
    }


    /// <summary>
    /// Wires client authentication to admit every caller and the introspection seam to answer <paramref name="result"/>
    /// for every token.
    /// </summary>
    /// <param name="host">The host whose integration is altered.</param>
    /// <param name="result">The application's answer.</param>
    /// <returns>A task that completes when the alteration is published.</returns>
    private static Task WireIntrospectionAnswerAsync(TestHostShell host, TokenIntrospectionResult result) =>
        TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _) => ValueTask.FromResult(true);
            candidateIntegration.IntrospectTokenAsync = (_, _, _, _, _) => ValueTask.FromResult(result);
        });


    /// <summary>
    /// Starts the host's listener and posts an introspection request for the token <c>introspected-access-token</c> over
    /// the wire with <c>Accept: application/token-introspection+jwt</c>, the caller naming itself by
    /// <see cref="ClientId"/>, and asserts the host captured no fault in the exchange.
    /// </summary>
    /// <param name="host">The host serving the endpoint.</param>
    /// <param name="material">The calling resource's registration.</param>
    /// <returns>The answer as received.</returns>
    private async Task<HttpResponseData> IntrospectSignedOverTheWireAsync(TestHostShell host, VerifierKeyMaterial material)
    {
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        Uri endpoint = new(hosted.HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeIntrospect, material.Registration.TenantId.Value));
        HttpResponseData response = await HttpClientTransport.SendFormPostAsync(
            hosted.SharedHttpClient!, endpoint,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.Token] = "introspected-access-token",
                [OAuthRequestParameterNames.ClientId] = ClientId
            },
            OutgoingHeaders.Empty.With(WellKnownHttpHeaderNames.Accept, WellKnownMediaTypes.Application.TokenIntrospectionJwt),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsEmpty(hosted.ConsumeHttpFaults(), "The introspection request is answered without a server fault.");

        return response;
    }


    /// <summary>
    /// An inactive-token introspection claim contains only active set to false.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9701#section-4">RFC 9701 §4</see>.
    /// </summary>
    [TestMethod]
    public async Task InactiveTokenDisclosesOnlyActiveFalseInsideTheClaim()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterSigningCapableResourceServerAsync(host).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _) =>
                ValueTask.FromResult(true);

            candidateIntegration.IntrospectTokenAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(new TokenIntrospectionResult { IsActive = false });
        }).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchIntrospectionAsync(
            host, material, acceptJwt: true).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument payload = ParseSegment(response.Body, segmentIndex: 1);
        JsonElement introspection = payload.RootElement.GetProperty("token_introspection");

        Assert.IsFalse(introspection.GetProperty("active").GetBoolean());
        int memberCount = 0;
        foreach(JsonProperty _ in introspection.EnumerateObject())
        {
            memberCount++;
        }

        Assert.AreEqual(1, memberCount,
            "RFC 9701 §5: an inactive token must carry active=false and no other member.");
    }


    [TestMethod]
    public async Task JwtRequestWithoutSigningKeyIsRejected()
    {
        await using TestHostShell host = new(TimeProvider);
        //A baseline registration WITHOUT an IntrospectionResponseSigning key.
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, IntrospectionCapabilities).ConfigureAwait(false);
        await WireActiveTokenAsync(host).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchIntrospectionAsync(
            host, material, acceptJwt: true).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.Contains(OAuthErrors.InvalidRequest, response.Body);
    }


    [TestMethod]
    public async Task PlainJsonRemainsTheDefaultWithoutTheAcceptHeader()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterSigningCapableResourceServerAsync(host).ConfigureAwait(false);
        await WireActiveTokenAsync(host).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchIntrospectionAsync(
            host, material, acceptJwt: false).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.AreEqual(WellKnownMediaTypes.Application.Json, response.ContentType);

        using JsonDocument document = JsonDocument.Parse(response.Body);
        Assert.IsTrue(document.RootElement.GetProperty("active").GetBoolean());
    }


    [TestMethod]
    public async Task DiscoveryAdvertisesIntrospectionSigningAlgsOnlyWithKey()
    {
        ImmutableHashSet<CapabilityIdentifier> capabilities = ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthTokenIntrospection,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint);

        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(ClientId, ClientBaseUri, capabilities).ConfigureAwait(false);
        //The fail-closed candidate gate keeps the introspection endpoint off the chain
        //until its seams are wired; the chain presence is what the advertisement keys on.
        await WireActiveTokenAsync(host).ConfigureAwait(false);

        ServerHttpResponse unkeyed = await DispatchDiscoveryAsync(host, material).ConfigureAwait(false);
        Assert.AreEqual(200, unkeyed.StatusCode, unkeyed.Body);
        Assert.DoesNotContain(
            IntrospectionServerMetadataParameterNames.IntrospectionSigningAlgValuesSupported,
            unkeyed.Body,
            "Without a response-signing key the algorithms must not be advertised.");

        await EnableIntrospectionSigningAsync(host, material).ConfigureAwait(false);

        ServerHttpResponse keyed = await DispatchDiscoveryAsync(host, material).ConfigureAwait(false);
        Assert.AreEqual(200, keyed.StatusCode, keyed.Body);
        Assert.Contains(
            IntrospectionServerMetadataParameterNames.IntrospectionSigningAlgValuesSupported,
            keyed.Body);
        Assert.Contains(WellKnownJwaValues.Es256, keyed.Body);
    }


    private static async Task<VerifierKeyMaterial> RegisterSigningCapableResourceServerAsync(TestHostShell host)
    {
        VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, IntrospectionCapabilities).ConfigureAwait(false);
        await EnableIntrospectionSigningAsync(host, material).ConfigureAwait(false);

        return material;
    }


    private static async Task EnableIntrospectionSigningAsync(TestHostShell host, VerifierKeyMaterial material)
    {
        await host.UpdateSigningKeysAsync(
            material.Registration.TenantId.Value,
            material.Registration.SigningKeys.ToImmutableDictionary().Add(
                KeyUsageContext.IntrospectionResponseSigning,
                new SigningKeySet { Current = [material.SigningKeyId] })).ConfigureAwait(false);
    }


    /// <summary>
    /// Installs an active-token introspection result through a requested alteration.
    /// </summary>
    private static async Task WireActiveTokenAsync(TestHostShell host)
    {
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _) =>
                ValueTask.FromResult(true);

            candidateIntegration.IntrospectTokenAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(new TokenIntrospectionResult
                {
                    IsActive = true,
                    Scope = "read write",
                    TokenType = "Bearer",
                    Subject = "Z5O3upPC88QrAjx00dis",
                    JwtId = "token-jti-1"
                });
        }).ConfigureAwait(false);
    }


    private async ValueTask<ServerHttpResponse> DispatchIntrospectionAsync(
        TestHostShell host, VerifierKeyMaterial material, bool acceptJwt)
    {
        RequestHeaders headers = acceptJwt
            ? new RequestHeaders(new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
            {
                [WellKnownHttpHeaderNames.Accept] = [WellKnownMediaTypes.Application.TokenIntrospectionJwt]
            })
            : RequestHeaders.Empty;

        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeIntrospect,
            "POST",
            new RequestFields { [OAuthRequestParameterNames.Token] = "access-token-to-inspect" },
            headers,
            [],
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    private async ValueTask<ServerHttpResponse> DispatchDiscoveryAsync(
        TestHostShell host, VerifierKeyMaterial material)
    {
        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.MetadataDiscovery,
            WellKnownHttpMethods.Get,
            new RequestFields(),
            [],
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    private static JsonDocument ParseSegment(string compactJwt, int segmentIndex)
    {
        string[] parts = compactJwt.Split('.');
        Assert.HasCount(3, parts);
        using IMemoryOwner<byte> bytes = TestSetup.Base64UrlDecoder(parts[segmentIndex], Pool);
        string json = Encoding.UTF8.GetString(bytes.Memory.Span).TrimEnd('\0');

        return JsonDocument.Parse(json);
    }
}
