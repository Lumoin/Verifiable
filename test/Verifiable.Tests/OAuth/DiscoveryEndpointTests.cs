using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Net;
using System.Text.Json;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Introspection;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Metadata;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// OpenID Connect Discovery 1.0 §3 document shape per
/// <see href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig">OIDC Discovery §3</see>
/// and the RFC 8414 §3 OAuth 2.0 metadata document.
/// </summary>
/// <remarks>
/// Endpoint-URL emission (issuer + per-request EndpointChain walk)
/// pairs with the spec-mandated supporting fields: REQUIRED fields
/// (subject_types_supported, response_types_supported,
/// id_token_signing_alg_values_supported), then the capability-derived,
/// scope, claims, and DPoP fields.
/// </remarks>
[TestClass]
internal sealed class DiscoveryEndpointTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch.AddDays(-15));

    private const string ClientId = "https://discovery.client.test";
    private static Uri ClientBaseUri { get; } = new("https://discovery.client.test");


    [TestMethod]
    public async Task DiscoveryEmitsIssuerVerbatimIncludingPathSegment()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchDiscoveryAsync(host, material)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument body = JsonDocument.Parse(response.Body);
        string? issuer = body.RootElement.GetProperty("issuer").GetString();

        //RFC 8414 §3.3: the issuer in the metadata MUST be identical to the issuer
        //identifier used to build the metadata URL — including the tenant path
        //segment. Collapsing to the authority (the prior bug) breaks the exact-match
        //a conformant client performs.
        string expected = material.Registration.IssuerUri!.OriginalString;
        Assert.AreEqual(expected, issuer,
            "Issuer must be emitted verbatim (with its path/tenant segment), not collapsed to the authority.");
        Assert.AreNotEqual(
            material.Registration.IssuerUri!.GetLeftPart(UriPartial.Authority), issuer,
            "The path-bearing issuer must NOT be reduced to its authority component.");
    }


    /// <summary>
    /// RFC 8414 §3.3 / OIDC Discovery §4.3 issuer-match, consumer side. The reference AS
    /// emits a compliant segment-bearing issuer; a conformant client MUST verify it equals the
    /// per-tenant base the well-known URL was derived from, code point by code point. This is
    /// the strict oracle that reproduces the onboarding-inspector class of rejection in-house:
    /// an issuer whose tenant segment was placed in the endpoint paths but omitted from the
    /// <c>issuer</c> — or a portless placeholder — is rejected, so the metadata MUST NOT be used.
    /// </summary>
    [TestMethod]
    public async Task DiscoveryIssuerMatchEnforcesSection33ConsumerSide()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchDiscoveryAsync(host, material).ConfigureAwait(false);
        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument body = JsonDocument.Parse(response.Body);
        Uri servedIssuer = new(body.RootElement.GetProperty("issuer").GetString()!);

        //The per-tenant base the client derived the well-known URL from (segment-bearing).
        Uri expectedIssuer = material.Registration.IssuerUri!;

        //Compliant: the served issuer carries the tenant segment and equals the base.
        AuthorizationServerMetadata compliant = new() { Issuer = servedIssuer };
        Assert.IsTrue(
            AuthorizationServerMetadataValidation.IsIssuerMatch(compliant, expectedIssuer),
            "A segment-bearing issuer equal to the discovery base satisfies §3.3.");

        //Reproduces the onboarding-inspector rejection: tenant segment present in the endpoint
        //paths but dropped from the issuer (here the authority-only form), checked against the
        //segmented base — MUST be rejected.
        AuthorizationServerMetadata segmentDropped = new()
        {
            Issuer = new Uri(expectedIssuer.GetLeftPart(UriPartial.Authority))
        };
        Assert.IsFalse(
            AuthorizationServerMetadataValidation.IsIssuerMatch(segmentDropped, expectedIssuer),
            "An issuer that drops the tenant segment present in the discovery base violates §3.3.");

        //Reproduces the portless/segmentless placeholder seed (a hardcoded https://localhost):
        //a different authority never equals the per-tenant base.
        AuthorizationServerMetadata placeholder = new() { Issuer = new Uri("https://localhost") };
        Assert.IsFalse(
            AuthorizationServerMetadataValidation.IsIssuerMatch(placeholder, expectedIssuer),
            "A portless/segmentless placeholder issuer does not equal the per-tenant base.");
    }


    /// <summary>
    /// RFC 9207 §3: "<c>authorization_response_iss_parameter_supported</c> ... If omitted,
    /// the default value is <c>false</c>." A parsed metadata document that carries no
    /// <c>authorization_response_iss_parameter_supported</c> member leaves
    /// <see cref="AuthorizationServerMetadata.AuthorizationResponseIssParameterSupported"/>
    /// unset, and the type's own default — <c>bool</c>'s C# default — is <see langword="false"/>,
    /// matching the wire default without any parser-side special-casing.
    /// </summary>
    [TestMethod]
    public void AuthorizationResponseIssParameterSupportedDefaultsToFalseWhenOmitted()
    {
        AuthorizationServerMetadata metadataWithoutTheField = new()
        {
            Issuer = new Uri("https://as.example.com")
        };

        Assert.IsFalse(metadataWithoutTheField.AuthorizationResponseIssParameterSupported,
            "RFC 9207 §3: an omitted authorization_response_iss_parameter_supported must default to false.");
    }


    /// <summary>
    /// draft-ietf-oauth-client-id-metadata-document-02 §6: <c>client_id_metadata_document_supported</c>
    /// is "OPTIONAL. Boolean value ...". A parsed metadata document that carries no
    /// <c>client_id_metadata_document_supported</c> member leaves
    /// <see cref="AuthorizationServerMetadata.ClientIdMetadataDocumentSupported"/> unset, and the
    /// type's own default — <c>bool</c>'s C# default — is <see langword="false"/>, matching the
    /// wire default without any parser-side special-casing.
    /// </summary>
    [TestMethod]
    public void ClientIdMetadataDocumentSupportedDefaultsToFalseWhenOmitted()
    {
        AuthorizationServerMetadata metadataWithoutTheField = new()
        {
            Issuer = new Uri("https://as.example.com")
        };

        Assert.IsFalse(metadataWithoutTheField.ClientIdMetadataDocumentSupported,
            "draft-ietf-oauth-client-id-metadata-document-02 §6: an omitted client_id_metadata_document_supported must default to false.");
    }


    [TestMethod]
    public async Task DiscoveryEmitsSubjectTypesSupportedAsPublic()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchDiscoveryAsync(host, material)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument body = JsonDocument.Parse(response.Body);
        JsonElement subjectTypes = body.RootElement.GetProperty(
            OpenIdProviderMetadataParameterNames.SubjectTypesSupported);

        Assert.AreEqual(JsonValueKind.Array, subjectTypes.ValueKind);
        Assert.HasCount(1, EnumerateStrings(subjectTypes));
        Assert.AreEqual("public", subjectTypes[0].GetString(),
            "OIDC Discovery §3 requires subject_types_supported; the library's default subject identifier strategy is public.");
    }


    [TestMethod]
    public async Task DiscoveryEmitsResponseTypesSupportedAsCodeWhenAuthCodeOnChain()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchDiscoveryAsync(host, material)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument body = JsonDocument.Parse(response.Body);
        JsonElement responseTypes = body.RootElement.GetProperty(
            AuthorizationServerMetadataParameterNames.ResponseTypesSupported);

        Assert.AreEqual(JsonValueKind.Array, responseTypes.ValueKind);
        List<string> values = EnumerateStrings(responseTypes);
        Assert.Contains("code", values,
            "OAuth 2.1 / OIDC Discovery §3 require response_types_supported; AuthorizationCode capability advertises 'code'.");
    }


    [TestMethod]
    public async Task DiscoveryEmitsIdTokenSigningAlgValuesFromIdTokenIssuanceKeys()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchDiscoveryAsync(host, material)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument body = JsonDocument.Parse(response.Body);
        JsonElement algs = body.RootElement.GetProperty(
            OpenIdProviderMetadataParameterNames.IdTokenSigningAlgValuesSupported);

        Assert.AreEqual(JsonValueKind.Array, algs.ValueKind);
        List<string> values = EnumerateStrings(algs);
        Assert.Contains(WellKnownJwaValues.Es256, values,
            "P-256 IdTokenIssuance signing key must surface as ES256 in id_token_signing_alg_values_supported.");
    }


    /// <summary>
    /// The verification-key resolver's documented contract, a contract of this library: every
    /// resolution states the <see cref="KeyUsageContext"/> the key is expected under, and a publishing
    /// site names the set it publishes. The design follows
    /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.12">RFC 8725 §3.12</see>: "Use
    /// different keys for different kinds of JWTs. Then the keys used to validate one kind of JWT will
    /// fail to validate other kinds of JWTs." and
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.2">RFC 7517 §4.2</see>: "The "use"
    /// (public key use) parameter identifies the intended use of the public key." A registration that
    /// lists one P-256 key for each of its ID Token, authorization-response and introspection-response
    /// sets, with the capabilities that put the authorize and introspection endpoints on its chain,
    /// serves its OpenID Provider metadata over the wire with 200, the row's algorithm field
    /// <c>["ES256"]</c>, and the resolver asked for the row's key exactly once, under the row's usage.
    /// The rows: <c>id_token_signing_alg_values_supported</c> under
    /// <see cref="KeyUsageContext.IdTokenIssuance"/>; <c>authorization_signing_alg_values_supported</c>
    /// under <see cref="KeyUsageContext.AuthorizationResponseSigning"/>;
    /// <c>introspection_signing_alg_values_supported</c> under
    /// <see cref="KeyUsageContext.IntrospectionResponseSigning"/>.
    /// </summary>
    /// <param name="algorithmField">The metadata member the row's key set derives its algorithms into.</param>
    [TestMethod]
    [DataRow("id_token_signing_alg_values_supported")]
    [DataRow("authorization_signing_alg_values_supported")]
    [DataRow("introspection_signing_alg_values_supported")]
    public async Task DiscoveryResolvesSigningKeysUnderTheirAdvertisedUsageAsync(string algorithmField)
    {
        await using TestHostShell host = new(TimeProvider);
        ImmutableHashSet<CapabilityIdentifier> capabilities = ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthPushedAuthorization,
            WellKnownCapabilityIdentifiers.OidcOpenIdConnect,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthTokenIntrospection);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: capabilities).ConfigureAwait(false);

        //The introspection endpoint joins the chain only once its seams are wired, and the
        //discovery document advertises introspection-response algorithms only for an endpoint on it.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _) => ValueTask.FromResult(true);
            candidateIntegration.IntrospectTokenAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(new TokenIntrospectionResult { IsActive = false });
        }).ConfigureAwait(false);

        KeyId idTokenKeyId = host.AllocateSigningKey();
        KeyId authorizationResponseKeyId = host.AllocateSigningKey();
        KeyId introspectionResponseKeyId = host.AllocateSigningKey();
        await host.UpdateSigningKeysAsync(material.Registration.TenantId.Value, new Dictionary<KeyUsageContext, SigningKeySet>
        {
            [KeyUsageContext.AccessTokenIssuance] = material.Registration.SigningKeys[KeyUsageContext.AccessTokenIssuance],
            [KeyUsageContext.IdTokenIssuance] = new SigningKeySet { Current = [idTokenKeyId] },
            [KeyUsageContext.AuthorizationResponseSigning] = new SigningKeySet { Current = [authorizationResponseKeyId] },
            [KeyUsageContext.IntrospectionResponseSigning] = new SigningKeySet { Current = [introspectionResponseKeyId] }
        }).ConfigureAwait(false);

        (KeyId rowKeyId, KeyUsageContext rowUsage) = algorithmField switch
        {
            "id_token_signing_alg_values_supported" => (idTokenKeyId, KeyUsageContext.IdTokenIssuance),
            "authorization_signing_alg_values_supported" => (authorizationResponseKeyId, KeyUsageContext.AuthorizationResponseSigning),
            "introspection_signing_alg_values_supported" => (introspectionResponseKeyId, KeyUsageContext.IntrospectionResponseSigning),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithmField), algorithmField, "Unknown algorithm field row.")
        };

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        Uri discoveryUrl = new(hosted.HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.MetadataDiscovery, material.Registration.TenantId.Value));

        hosted.VerificationKeyResolutions.Clear();
        using HttpResponseMessage response = await hosted.SharedHttpClient!.GetAsync(discoveryUrl, TestContext.CancellationToken)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, body);
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.IsTrue(document.RootElement.TryGetProperty(algorithmField, out JsonElement algorithms),
            $"The document advertises {algorithmField}. Body: {body}");
        Assert.AreEqual("ES256", Assert.ContainsSingle(EnumerateStrings(algorithms)));

        VerificationKeyResolution resolution = Assert.ContainsSingle(hosted.ResolutionsOf(rowKeyId));
        Assert.AreEqual(rowUsage, resolution.Usage);
    }


    [TestMethod]
    public async Task DiscoveryEmitsGrantTypesSupportedIncludingAuthorizationCodeAndRefreshToken()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchDiscoveryAsync(host, material)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument body = JsonDocument.Parse(response.Body);
        JsonElement grantTypes = body.RootElement.GetProperty(
            AuthorizationServerMetadataParameterNames.GrantTypesSupported);

        Assert.AreEqual(JsonValueKind.Array, grantTypes.ValueKind);
        List<string> values = EnumerateStrings(grantTypes);
        Assert.Contains("authorization_code", values,
            "AuthorizationCode capability advertises the authorization_code grant per RFC 8414 §2.");
        Assert.Contains("refresh_token", values,
            "AuthCodeRefreshToken endpoint on chain advertises refresh_token per RFC 6749 §6.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-7.5.2">OAuth 2.1
    /// draft-16 §7.5.2</see>: "The plain code challenge method, defined in [RFC7636], is
    /// explicitly forbidden in OAuth 2.1." The advertisement under <see cref="PolicyProfile.Fapi20"/>
    /// names S256 only.
    /// </summary>
    [TestMethod]
    public async Task DiscoveryEmitsCodeChallengeMethodsAsS256OnlyUnderFapi20()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Fapi20).ConfigureAwait(false);

        ServerHttpResponse response = await RawAuthCodeWirePushers.PushNamedEndpointAsync(
            host, material.Registration.TenantId.Value, WellKnownEndpointNames.MetadataDiscovery,
            WellKnownHttpMethods.Get, new RequestFields(), [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument body = JsonDocument.Parse(response.Body);
        JsonElement methods = body.RootElement.GetProperty(
            AuthorizationServerMetadataParameterNames.CodeChallengeMethodsSupported);

        Assert.AreEqual(JsonValueKind.Array, methods.ValueKind);
        List<string> values = EnumerateStrings(methods);
        Assert.HasCount(1, values,
            "OAuth 2.1 §7.5.2 forbids the plain PKCE method under the FAPI 2.0 policy.");
        Assert.AreEqual("S256", values[0]);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8414#section-2">RFC 8414 §2</see> advertises
    /// supported methods. Under <see cref="PolicyProfile.Rfc6749WithPkce"/> this is S256 only,
    /// applying the library's S256-only policy consistently with
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-16#section-7.5.2">OAuth 2.1 §7.5.2</see>:
    /// "The plain code challenge method, defined in [RFC7636], is explicitly forbidden in OAuth 2.1."
    /// </summary>
    [TestMethod]
    public async Task DiscoveryEmitsCodeChallengeMethodsAsS256OnlyUnderRfc6749WithPkce()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        ServerHttpResponse response = await RawAuthCodeWirePushers.PushNamedEndpointAsync(
            host, material.Registration.TenantId.Value, WellKnownEndpointNames.MetadataDiscovery,
            WellKnownHttpMethods.Get, new RequestFields(), [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument body = JsonDocument.Parse(response.Body);
        JsonElement methods = body.RootElement.GetProperty(
            AuthorizationServerMetadataParameterNames.CodeChallengeMethodsSupported);

        Assert.AreEqual(JsonValueKind.Array, methods.ValueKind);
        List<string> values = EnumerateStrings(methods);
        Assert.HasCount(1, values, "Every profile advertises S256 only.");
        Assert.AreEqual("S256", values[0]);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8414#section-2">RFC 8414, Section 2</see>:
    /// "token_endpoint_auth_methods_supported: OPTIONAL. JSON array containing a list of client
    /// authentication methods supported by this token endpoint." The emitted array is the
    /// integration's <see cref="AuthorizationServerIntegration.ClientAuthenticationMethodsSupported"/>
    /// declaration rendered through <see cref="ClientAuthenticationMethodNames"/>; its default value is
    /// <c>[<see cref="ClientAuthenticationMethod.None"/>]</c>, so a host that declares nothing publishes
    /// exactly <c>["none"]</c> — the PKCE-only public-client shape. A deployment adding
    /// <c>client_secret_basic</c> / <c>private_key_jwt</c> / mTLS declares those methods and they appear
    /// in the array; the advertisement and the token endpoint's judgment are one set.
    /// </summary>
    [TestMethod]
    public async Task DiscoveryEmitsTokenEndpointAuthMethodsFromDefaultNoneDeclaration()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchDiscoveryAsync(host, material)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument body = JsonDocument.Parse(response.Body);
        JsonElement methods = body.RootElement.GetProperty(
            AuthorizationServerMetadataParameterNames.TokenEndpointAuthMethodsSupported);

        Assert.AreEqual(JsonValueKind.Array, methods.ValueKind);
        List<string> values = EnumerateStrings(methods);
        Assert.Contains("none", values,
            "The default ClientAuthenticationMethodsSupported = [None] declaration renders token_endpoint_auth_methods_supported as ['none']; deployments declaring client_secret_basic / private_key_jwt / mTLS advertise those methods.");
    }


    [TestMethod]
    public async Task DiscoveryEmitsScopesSupportedFromRegistrationAllowedScopes()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchDiscoveryAsync(host, material)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument body = JsonDocument.Parse(response.Body);
        JsonElement scopes = body.RootElement.GetProperty(
            AuthorizationServerMetadataParameterNames.ScopesSupported);

        Assert.AreEqual(JsonValueKind.Array, scopes.ValueKind);
        List<string> values = EnumerateStrings(scopes);

        //RegisterDpopClient seeds the OIDC Core §5.4 standard scope set on
        //AllowedScopes; discovery must surface each.
        Assert.Contains(WellKnownScopes.OpenId, values);
        Assert.Contains(WellKnownScopes.Profile, values);
        Assert.Contains(WellKnownScopes.Email, values);
        Assert.Contains(WellKnownScopes.Address, values);
        Assert.Contains(WellKnownScopes.Phone, values);

        //Sorted lexicographically for deterministic wire output across
        //ImmutableHashSet iteration order.
        for(int i = 1; i < values.Count; i++)
        {
            Assert.IsLessThan(
                0,
                StringComparer.Ordinal.Compare(values[i - 1], values[i]),
                $"scopes_supported must be sorted ordinally; '{values[i - 1]}' came before '{values[i]}'.");
        }
    }


    [TestMethod]
    public async Task DiscoveryEmitsClaimsSupportedMatchingStandardContributors()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchDiscoveryAsync(host, material)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument body = JsonDocument.Parse(response.Body);
        JsonElement claims = body.RootElement.GetProperty(
            OpenIdProviderMetadataParameterNames.ClaimsSupported);

        Assert.AreEqual(JsonValueKind.Array, claims.ValueKind);
        List<string> values = EnumerateStrings(claims);

        //sub is spec-required; the rest reflect the standard contributors'
        //wire output. Any change to ContributionProfiles.StandardRules must
        //also update the StandardClaimsSupported list in MetadataEndpoints
        //so discovery advertises exactly the claims the contributors emit.
        Assert.Contains(WellKnownJwtClaimNames.Sub, values);

        //Profile family.
        Assert.Contains(WellKnownJwtClaimNames.Name, values);
        Assert.Contains(WellKnownJwtClaimNames.FamilyName, values);
        Assert.Contains(WellKnownJwtClaimNames.UpdatedAt, values);

        //Email family.
        Assert.Contains(WellKnownJwtClaimNames.Email, values);
        Assert.Contains(WellKnownJwtClaimNames.EmailVerified, values);

        //Address (structured).
        Assert.Contains(WellKnownJwtClaimNames.Address, values);

        //Phone family.
        Assert.Contains(WellKnownJwtClaimNames.PhoneNumber, values);
        Assert.Contains(WellKnownJwtClaimNames.PhoneNumberVerified, values);

        //Authentication-context.
        Assert.Contains(WellKnownJwtClaimNames.Acr, values);
        Assert.Contains(WellKnownJwtClaimNames.Amr, values);
        Assert.Contains(WellKnownJwtClaimNames.AuthTime, values);

        //Confirmation (RFC 7800 / RFC 9449 §6.1).
        Assert.Contains(WellKnownJwtClaimNames.Cnf, values);
    }


    [TestMethod]
    public async Task DiscoveryEmitsClaimTypesSupportedAsNormalOnly()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchDiscoveryAsync(host, material)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument body = JsonDocument.Parse(response.Body);
        JsonElement types = body.RootElement.GetProperty(
            OpenIdProviderMetadataParameterNames.ClaimTypesSupported);

        Assert.AreEqual(JsonValueKind.Array, types.ValueKind);
        List<string> values = EnumerateStrings(types);
        Assert.HasCount(1, values,
            "Aggregated and distributed claim types are not implemented.");
        Assert.AreEqual("normal", values[0]);
    }


    [TestMethod]
    public async Task DiscoveryAdvertisesRequireParAndIssParameterUnderFapi20()
    {
        //FAPI 2.0 §5.2.2 mandates PAR and RFC 9207 iss; the advertisement is driven by
        //the resolved policy so it matches enforcement.
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Fapi20).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchDiscoveryAsync(host, material)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument body = JsonDocument.Parse(response.Body);
        Assert.IsTrue(
            body.RootElement.GetProperty(
                AuthorizationServerMetadataParameterNames.RequirePushedAuthorizationRequests).GetBoolean(),
            "FAPI 2.0 §5.2.2 advertises require_pushed_authorization_requests=true.");
        Assert.IsTrue(
            body.RootElement.GetProperty(
                AuthorizationServerMetadataParameterNames.AuthorizationResponseIssParameterSupported).GetBoolean(),
            "FAPI 2.0 advertises authorization_response_iss_parameter_supported=true (RFC 9207).");
    }


    [TestMethod]
    public async Task DiscoveryAdvertisesRequireParFalseUnderRfc6749WithPkce()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchDiscoveryAsync(host, material)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument body = JsonDocument.Parse(response.Body);
        Assert.IsFalse(
            body.RootElement.GetProperty(
                AuthorizationServerMetadataParameterNames.RequirePushedAuthorizationRequests).GetBoolean(),
            "RFC 6749 + PKCE does not mandate PAR; advertise require_pushed_authorization_requests=false.");
    }


    /// <summary>
    /// draft-ietf-oauth-client-id-metadata-document-02 §6 dual gate: the flag is emitted
    /// <see langword="true"/> only when the <see cref="WellKnownCapabilityIdentifiers.OAuthClientIdMetadataDocument"/>
    /// capability is allowed AND <see cref="AuthorizationServerIntegration.ResolveClientMetadataAsync"/>
    /// is wired. The resolver is never invoked by discovery emission (privacy §9.1: discovery/JWKS
    /// requests must not trigger client-document fetches), so a throwing lambda proves the seam is
    /// consulted only for its non-null-ness.
    /// </summary>
    [TestMethod]
    public async Task DiscoveryEmitsClientIdMetadataDocumentSupportedWhenCapabilityAllowedAndResolverWired()
    {
        await using TestHostShell host = new(TimeProvider);
        ImmutableHashSet<CapabilityIdentifier> capabilities = ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthPushedAuthorization,
            WellKnownCapabilityIdentifiers.OidcOpenIdConnect,
            WellKnownCapabilityIdentifiers.OidcUserInfo,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthClientIdMetadataDocument);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: capabilities).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveClientMetadataAsync = (uri, context, ct) =>
                throw new NotImplementedException(
                    "Discovery emission only checks ResolveClientMetadataAsync for non-null-ness; it must never invoke it.");
        }).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchDiscoveryAsync(host, material)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument body = JsonDocument.Parse(response.Body);
        Assert.IsTrue(
            body.RootElement.TryGetProperty(
                AuthorizationServerMetadataParameterNames.ClientIdMetadataDocumentSupported,
                out JsonElement flag),
            $"client_id_metadata_document_supported must be present when the capability is allowed " +
            $"and the resolver is wired. Body: {response.Body}");
        Assert.IsTrue(flag.GetBoolean(),
            "draft-ietf-oauth-client-id-metadata-document-02 §6 advertises true under the dual gate.");
    }


    /// <summary>
    /// Fail-closed half of the §6 dual gate: the capability is allowed but
    /// <see cref="AuthorizationServerIntegration.ResolveClientMetadataAsync"/> is left unwired, so
    /// the flag must be omitted rather than advertised as <see langword="false"/> — an AS that
    /// cannot resolve CIMD documents at all does not claim the capability on the wire.
    /// </summary>
    [TestMethod]
    public async Task DiscoveryOmitsClientIdMetadataDocumentSupportedWhenResolverUnwired()
    {
        await using TestHostShell host = new(TimeProvider);
        ImmutableHashSet<CapabilityIdentifier> capabilities = ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthPushedAuthorization,
            WellKnownCapabilityIdentifiers.OidcOpenIdConnect,
            WellKnownCapabilityIdentifiers.OidcUserInfo,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthClientIdMetadataDocument);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: capabilities).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchDiscoveryAsync(host, material)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument body = JsonDocument.Parse(response.Body);
        Assert.IsFalse(
            body.RootElement.TryGetProperty(
                AuthorizationServerMetadataParameterNames.ClientIdMetadataDocumentSupported, out _),
            $"client_id_metadata_document_supported must be omitted when the resolver seam is unwired. Body: {response.Body}");
    }


    /// <summary>
    /// Fail-closed half of the §6 dual gate: the resolver is wired but the registration does not
    /// carry <see cref="WellKnownCapabilityIdentifiers.OAuthClientIdMetadataDocument"/> (the default
    /// <see cref="TestHostShell.RegisterDpopClientAsync"/> capability set), so the flag must be omitted.
    /// </summary>
    [TestMethod]
    public async Task DiscoveryOmitsClientIdMetadataDocumentSupportedWhenCapabilityMissing()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveClientMetadataAsync = (uri, context, ct) =>
                throw new NotImplementedException(
                    "Discovery emission only checks ResolveClientMetadataAsync for non-null-ness; it must never invoke it.");
        }).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchDiscoveryAsync(host, material)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument body = JsonDocument.Parse(response.Body);
        Assert.IsFalse(
            body.RootElement.TryGetProperty(
                AuthorizationServerMetadataParameterNames.ClientIdMetadataDocumentSupported, out _),
            $"client_id_metadata_document_supported must be omitted when the capability is not allowed. Body: {response.Body}");
    }


    /// <summary>
    /// A discovery member the library writes from a capability is left out when the capability is outside the
    /// capabilities the discovery request is served under, in two forms: the application's materialization answers a
    /// registration without it with the capability added, which the dispatcher's bound withholds, or the
    /// application's capability resolution withholds it from a registration that allows it. The members are
    /// <c>backchannel_logout_supported</c> and <c>backchannel_logout_session_supported</c> of
    /// <see href="https://openid.net/specs/openid-connect-backchannel-1_0.html#BCSupport">OpenID Connect Back-Channel
    /// Logout 1.0 section 2.1</see>, with the delivery seam wired, and <c>client_id_metadata_document_supported</c> of
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02#section-6">draft-ietf-oauth-client-id-metadata-document-02
    /// section 6</see>, with the client metadata resolution wired. The document fetched over the wire is the same
    /// bytes as the
    /// document of a registration that never held the capability, the tenant segment of each registration's
    /// addresses read as one placeholder. A materialization narrows what the server serves and never widens it, and a
    /// capability the resolution withholds is not served, which is this library's rule:
    /// <see href="../../../documents/AuthorizationServerDesign.md#23-per-endpoint-loop-stage">Server design</see>.
    /// </summary>
    /// <param name="member"><c>backChannelLogout</c> or <c>clientIdMetadataDocument</c>.</param>
    /// <param name="form">
    /// <c>materializationAdds</c> or <c>resolutionWithholds</c>, as <see cref="CapabilityBounds"/> names them.
    /// </param>
    [TestMethod]
    [DataRow("backChannelLogout", "materializationAdds", DisplayName = "back-channel logout, the materialization adds the capability")]
    [DataRow("backChannelLogout", "resolutionWithholds", DisplayName = "back-channel logout, the capability resolution withholds the capability")]
    [DataRow("clientIdMetadataDocument", "materializationAdds", DisplayName = "client ID metadata document, the materialization adds the capability")]
    [DataRow("clientIdMetadataDocument", "resolutionWithholds", DisplayName = "client ID metadata document, the capability resolution withholds the capability")]
    public async Task ADiscoveryMemberOutsideTheServedCapabilitiesIsNotAdvertisedAsync(string member, string form)
    {
        CapabilityIdentifier capability = member switch
        {
            "backChannelLogout" => WellKnownCapabilityIdentifiers.OidcBackChannelLogout,
            "clientIdMetadataDocument" => WellKnownCapabilityIdentifiers.OAuthClientIdMetadataDocument,
            _ => throw new ArgumentOutOfRangeException(nameof(member), member, "Unknown member.")
        };
        ImmutableHashSet<CapabilityIdentifier> neverHeld = ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthPushedAuthorization,
            WellKnownCapabilityIdentifiers.OidcOpenIdConnect,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint);

        (string underTheBound, string body) = await GetDiscoveryUnderTheBoundAsync(
            CapabilityBounds.Registered(form, neverHeld, capability),
            CapabilityBounds.Wire(form, capability)).ConfigureAwait(false);
        (string neverHeldAnswer, _) = await GetDiscoveryUnderTheBoundAsync(neverHeld, bound: null).ConfigureAwait(false);

        Assert.AreEqual(neverHeldAnswer, underTheBound);
        Assert.StartsWith("200\nContent-Type: application/json\n", underTheBound);
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.IsFalse(document.RootElement.TryGetProperty(
            AuthorizationServerMetadataParameterNames.BackchannelLogoutSupported, out _), body);
        Assert.IsFalse(document.RootElement.TryGetProperty(
            AuthorizationServerMetadataParameterNames.BackchannelLogoutSessionSupported, out _), body);
        Assert.IsFalse(document.RootElement.TryGetProperty(
            AuthorizationServerMetadataParameterNames.ClientIdMetadataDocumentSupported, out _), body);
    }


    [TestMethod]
    public async Task DiscoveryAdvertisesDpopSigningAlgValuesWhenDpopIsWired()
    {
        //RFC 9449 §5.1 — when the AS wires DPoP proof validation it advertises the
        //accepted proof signature algorithms. RegisterDpopClient wires it.
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        //Wire the server's DPoP proof validation — the gate for advertising the algs.
        _ = await host.EnableDpopAsync().ConfigureAwait(false);

        ServerHttpResponse response = await DispatchDiscoveryAsync(host, material)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument body = JsonDocument.Parse(response.Body);
        JsonElement algs = body.RootElement.GetProperty(
            AuthorizationServerMetadataParameterNames.DpopSigningAlgValuesSupported);

        Assert.AreEqual(JsonValueKind.Array, algs.ValueKind);
        List<string> values = EnumerateStrings(algs);
        Assert.Contains(WellKnownJwaValues.Es256, values,
            "RFC 9449 §5.1 — the accepted DPoP proof algorithms include ES256.");
        Assert.Contains(WellKnownJwaValues.EdDsa, values,
            "RFC 9449 §4.2 accepts EdDSA; the advertisement must include it.");
    }


    [TestMethod]
    public async Task DiscoveryEmitsCompleteOidcMetadataSet()
    {
        //Phase A discovery-completion smoke test: every Phase A discovery
        //chunk's field must appear in the document for an OIDC-capable
        //registration. Chunks 12-16 each pinned individual fields; this
        //assertion ensures the additions compose end-to-end.
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchDiscoveryAsync(host, material)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument body = JsonDocument.Parse(response.Body);

        //Endpoint URLs.
        AssertFieldPresent(body, AuthorizationServerMetadataParameterNames.Issuer);
        AssertFieldPresent(body, AuthorizationServerMetadataParameterNames.AuthorizationEndpoint);
        AssertFieldPresent(body, AuthorizationServerMetadataParameterNames.TokenEndpoint);
        AssertFieldPresent(body, AuthorizationServerMetadataParameterNames.JwksUri);
        AssertFieldPresent(body, OpenIdProviderMetadataParameterNames.UserinfoEndpoint);

        //REQUIRED OIDC fields.
        AssertFieldPresent(body, OpenIdProviderMetadataParameterNames.SubjectTypesSupported);
        AssertFieldPresent(body, AuthorizationServerMetadataParameterNames.ResponseTypesSupported);
        AssertFieldPresent(body, OpenIdProviderMetadataParameterNames.IdTokenSigningAlgValuesSupported);

        //Capability-derived OPTIONAL fields.
        AssertFieldPresent(body, AuthorizationServerMetadataParameterNames.GrantTypesSupported);
        AssertFieldPresent(body, AuthorizationServerMetadataParameterNames.CodeChallengeMethodsSupported);
        AssertFieldPresent(body, AuthorizationServerMetadataParameterNames.TokenEndpointAuthMethodsSupported);

        //Scopes.
        AssertFieldPresent(body, AuthorizationServerMetadataParameterNames.ScopesSupported);

        //Claims advertisement.
        AssertFieldPresent(body, OpenIdProviderMetadataParameterNames.ClaimsSupported);

        //claim_types.
        AssertFieldPresent(body, OpenIdProviderMetadataParameterNames.ClaimTypesSupported);

        //FAPI 2.0 §5.2.2 / RFC 9207 — PAR-required and iss-parameter-supported flags.
        AssertFieldPresent(body, AuthorizationServerMetadataParameterNames.RequirePushedAuthorizationRequests);
        AssertFieldPresent(body, AuthorizationServerMetadataParameterNames.AuthorizationResponseIssParameterSupported);
        //dpop_signing_alg_values_supported is advertised only when DPoP validation is
        //wired (server.Integration.ValidateDpopProofAsync); this registration does not
        //enable it, so it is intentionally absent here — covered by the dedicated test.
    }


    private static void AssertFieldPresent(JsonDocument body, string fieldName)
    {
        Assert.IsTrue(
            body.RootElement.TryGetProperty(fieldName, out _),
            $"Discovery document is missing required field '{fieldName}'.");
    }


    [TestMethod]
    public async Task DiscoveryStillCarriesIssuerAndEndpointUrls()
    {
        //Regression guard — the REQUIRED-field additions must not displace the
        //pre-existing endpoint-URL emission.
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchDiscoveryAsync(host, material)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument body = JsonDocument.Parse(response.Body);
        Assert.IsTrue(body.RootElement.TryGetProperty(
            AuthorizationServerMetadataParameterNames.Issuer, out _),
            "issuer must be present.");
        Assert.IsTrue(body.RootElement.TryGetProperty(
            AuthorizationServerMetadataParameterNames.TokenEndpoint, out _),
            "token_endpoint must be present.");
        Assert.IsTrue(body.RootElement.TryGetProperty(
            OpenIdProviderMetadataParameterNames.UserinfoEndpoint, out _),
            "userinfo_endpoint must be present once UserInfo capability is allowed.");
    }


    /// <summary>
    /// RFC 9470 §7 / RFC 8414 §2 — the AS advertises <c>acr_values_supported</c> so clients
    /// and resource servers know which <c>acr</c> values they may demand at step-up. The
    /// supported assurance levels are deployment authentication knowledge the transport-agnostic
    /// library does not hold, so a deployment surfaces them through the existing
    /// <see cref="AuthorizationServerIntegration.ContributeDiscoveryFieldsAsync"/> seam under the
    /// library-named key; the document round-trips the contributed array verbatim.
    /// </summary>
    [TestMethod]
    public async Task DiscoveryEmitsAppContributedAcrValuesSupported()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ContributeDiscoveryFieldsAsync = static (_, _, _) =>
                ValueTask.FromResult(new DiscoveryDocumentContribution(
                    [new DiscoveryStringArrayField(
                        AuthorizationServerMetadataParameterNames.AcrValuesSupported,
                        ["urn:mace:incommon:iap:silver", "loa-substantial"])]));
        }).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchDiscoveryAsync(host, material)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument body = JsonDocument.Parse(response.Body);
        Assert.IsTrue(body.RootElement.TryGetProperty(
            AuthorizationServerMetadataParameterNames.AcrValuesSupported, out JsonElement acrValues),
            $"acr_values_supported must appear when the deployment contributes it. Body: {response.Body}");
        Assert.AreEqual(JsonValueKind.Array, acrValues.ValueKind);

        List<string> values = EnumerateStrings(acrValues);
        Assert.Contains("urn:mace:incommon:iap:silver", values);
        Assert.Contains("loa-substantial", values);
    }


    /// <summary>
    /// RFC 8414 §3 / §3.1: the authorization server metadata is served at the §3
    /// default well-known location <c>/.well-known/oauth-authorization-server</c>,
    /// path-inserted before the path-bearing tenant issuer's path segment. The
    /// response is <c>200 OK</c> and the <c>issuer</c> member equals the tenant
    /// issuer identifier verbatim (§3.3 issuer-match by code-point equality).
    /// </summary>
    [TestMethod]
    public async Task OAuthAuthorizationServerMetadataServesAtInsertedLocationWithExactIssuer()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchOAuthAuthorizationServerMetadataAsync(host, material)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument body = JsonDocument.Parse(response.Body);
        string? issuer = body.RootElement.GetProperty("issuer").GetString();

        //§3.3: the issuer returned MUST be identical to the issuer identifier the
        //well-known URL was derived from — including the tenant path segment that
        //RFC 8414 §3 inserted the suffix in front of.
        string expected = material.Registration.IssuerUri!.OriginalString;
        Assert.AreEqual(expected, issuer,
            "RFC 8414 §3.3: the issuer at the oauth-authorization-server mount must equal the tenant issuer identifier verbatim.");
    }


    /// <summary>
    /// RFC 8414 §3.1: an authorization server MAY publish the same metadata at
    /// multiple well-known locations derived from its issuer identifier. The
    /// document served at the §3 default <c>oauth-authorization-server</c> mount
    /// is byte-identical to the one served at the appended OIDC
    /// <c>openid-configuration</c> mount for the same tenant.
    /// </summary>
    [TestMethod]
    public async Task OAuthAuthorizationServerMetadataIsByteIdenticalToOpenIdConfiguration()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        ServerHttpResponse oauthMetadata = await DispatchOAuthAuthorizationServerMetadataAsync(host, material)
            .ConfigureAwait(false);
        ServerHttpResponse openIdConfiguration = await DispatchDiscoveryAsync(host, material)
            .ConfigureAwait(false);

        Assert.AreEqual(200, oauthMetadata.StatusCode, oauthMetadata.Body);
        Assert.AreEqual(200, openIdConfiguration.StatusCode, openIdConfiguration.Body);

        //§3.1: both well-known locations are mounts of the same metadata. The
        //library backs both with one body builder, so the wire bytes are equal
        //ordinally — there is no per-location field divergence.
        Assert.AreEqual(openIdConfiguration.Body, oauthMetadata.Body,
            "RFC 8414 §3.1: the document at the oauth-authorization-server location must be byte-identical to the openid-configuration location.");
    }


    /// <summary>
    /// RFC 8414 §3.1 / §5: adding the §3 default <c>oauth-authorization-server</c>
    /// mount leaves the appended OIDC <c>openid-configuration</c> location working
    /// unchanged — <c>200 OK</c> with the exact tenant issuer (§3.3).
    /// </summary>
    [TestMethod]
    public async Task OpenIdConfigurationLocationContinuesToServeAlongsideOAuthAuthorizationServer()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchDiscoveryAsync(host, material)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument body = JsonDocument.Parse(response.Body);
        string? issuer = body.RootElement.GetProperty("issuer").GetString();

        string expected = material.Registration.IssuerUri!.OriginalString;
        Assert.AreEqual(expected, issuer,
            "The appended openid-configuration mount must keep emitting the exact tenant issuer after the oauth-authorization-server mount is added.");
    }


    /// <summary>
    /// Registers the client with <paramref name="capabilities"/> under <see cref="PolicyProfile.Rfc6749WithPkce"/>,
    /// wires the back-channel delivery seam and a client metadata resolution that discovery never calls, applies
    /// <paramref name="bound"/> to the server's integration when given, then fetches the discovery document over the
    /// listener.
    /// </summary>
    /// <param name="capabilities">The capabilities the loaded registration allows.</param>
    /// <param name="bound">
    /// The wiring that sets the capabilities the discovery request is served under, from
    /// <see cref="CapabilityBounds.Wire"/>, or <see langword="null"/> for none.
    /// </param>
    /// <returns>
    /// The answer as <see cref="OAuthTestTransport.ProjectWireAnswer"/> projects it, with the registration's tenant
    /// segment replaced by <c>{segment}</c> so two registrations' answers compare, and the body as received.
    /// </returns>
    private async Task<(string WireAnswer, string Body)> GetDiscoveryUnderTheBoundAsync(
        ImmutableHashSet<CapabilityIdentifier> capabilities, Action<AuthorizationServerIntegration>? bound)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: capabilities).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.DeliverBackChannelLogoutAsync = static (_, _, _, _, _) => ValueTask.CompletedTask;
            candidateIntegration.ResolveClientMetadataAsync = static (_, _, _) =>
                throw new NotImplementedException("Discovery emission never invokes the client metadata resolution.");
            bound?.Invoke(candidateIntegration);
        }).ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;
        Uri discoveryUrl = new(hosted.HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.MetadataDiscovery, segment));

        using HttpResponseMessage response = await hosted.SharedHttpClient!.GetAsync(discoveryUrl, TestContext.CancellationToken)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        return (OAuthTestTransport.ProjectWireAnswer(response, body).Replace(segment, "{segment}", StringComparison.Ordinal), body);
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


    private async ValueTask<ServerHttpResponse> DispatchOAuthAuthorizationServerMetadataAsync(
        TestHostShell host, VerifierKeyMaterial material)
    {
        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.MetadataOAuthAuthorizationServer,
            WellKnownHttpMethods.Get,
            new RequestFields(),
            [],
            TestContext.CancellationToken).ConfigureAwait(false);
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
