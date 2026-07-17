using System.Collections.Immutable;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Metadata;
using Verifiable.Server;
using Verifiable.Server.Routing;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// OAuth Phase A — OpenID Connect Discovery 1.0 §3 document shape per
/// <see href="https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig">OIDC Discovery §3</see>
/// and the RFC 8414 §3 OAuth 2.0 metadata document.
/// </summary>
/// <remarks>
/// Phase 9h shipped the endpoint-URL emission (issuer +
/// per-request EndpointChain walk). Phase A chunks 12-16 complete the
/// metadata document with the spec-mandated supporting fields:
/// chunk 12 — REQUIRED fields (subject_types_supported,
/// response_types_supported, id_token_signing_alg_values_supported);
/// chunks 13-16 — capability-derived, scope, claims, and DPoP fields.
/// </remarks>
[TestClass]
internal sealed class DiscoveryEndpointTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch.AddDays(-15));

    private const string ClientId = "https://discovery.client.test";
    private static readonly Uri ClientBaseUri = new("https://discovery.client.test");


    [TestMethod]
    public async Task DiscoveryEmitsIssuerVerbatimIncludingPathSegment()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

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
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

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


    [TestMethod]
    public async Task DiscoveryEmitsSubjectTypesSupportedAsPublic()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

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
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

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
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

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


    [TestMethod]
    public async Task DiscoveryEmitsGrantTypesSupportedIncludingAuthorizationCodeAndRefreshToken()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

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


    [TestMethod]
    public async Task DiscoveryEmitsCodeChallengeMethodsAsS256Only()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        ServerHttpResponse response = await DispatchDiscoveryAsync(host, material)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument body = JsonDocument.Parse(response.Body);
        JsonElement methods = body.RootElement.GetProperty(
            AuthorizationServerMetadataParameterNames.CodeChallengeMethodsSupported);

        Assert.AreEqual(JsonValueKind.Array, methods.ValueKind);
        List<string> values = EnumerateStrings(methods);
        Assert.HasCount(1, values,
            "OAuth 2.1 §7.5.1 forbids the plain PKCE method; the library advertises S256 only.");
        Assert.AreEqual("S256", values[0]);
    }


    [TestMethod]
    public async Task DiscoveryEmitsTokenEndpointAuthMethodsAsNone()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        ServerHttpResponse response = await DispatchDiscoveryAsync(host, material)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument body = JsonDocument.Parse(response.Body);
        JsonElement methods = body.RootElement.GetProperty(
            AuthorizationServerMetadataParameterNames.TokenEndpointAuthMethodsSupported);

        Assert.AreEqual(JsonValueKind.Array, methods.ValueKind);
        List<string> values = EnumerateStrings(methods);
        Assert.Contains("none", values,
            "The library's token endpoint accepts PKCE-only public clients (auth method 'none'); deployments adding client_secret_basic / private_key_jwt / mTLS advertise those via ContributeDiscoveryFieldsAsync.");
    }


    [TestMethod]
    public async Task DiscoveryEmitsScopesSupportedFromRegistrationAllowedScopes()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

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
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

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
        //so discovery's advertisement stays honest.
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
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

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
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Fapi20);

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
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        ServerHttpResponse response = await DispatchDiscoveryAsync(host, material)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument body = JsonDocument.Parse(response.Body);
        Assert.IsFalse(
            body.RootElement.GetProperty(
                AuthorizationServerMetadataParameterNames.RequirePushedAuthorizationRequests).GetBoolean(),
            "RFC 6749 + PKCE does not mandate PAR; advertise require_pushed_authorization_requests=false.");
    }


    [TestMethod]
    public async Task DiscoveryAdvertisesDpopSigningAlgValuesWhenDpopIsWired()
    {
        //RFC 9449 §5.1 — when the AS wires DPoP proof validation it advertises the
        //accepted proof signature algorithms. RegisterDpopClient wires it.
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        //Wire the server's DPoP proof validation — the gate for advertising the algs.
        host.EnableDpop();

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
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        ServerHttpResponse response = await DispatchDiscoveryAsync(host, material)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument body = JsonDocument.Parse(response.Body);

        //Phase 9h endpoint URLs.
        AssertFieldPresent(body, AuthorizationServerMetadataParameterNames.Issuer);
        AssertFieldPresent(body, AuthorizationServerMetadataParameterNames.AuthorizationEndpoint);
        AssertFieldPresent(body, AuthorizationServerMetadataParameterNames.TokenEndpoint);
        AssertFieldPresent(body, AuthorizationServerMetadataParameterNames.JwksUri);
        AssertFieldPresent(body, OpenIdProviderMetadataParameterNames.UserinfoEndpoint);

        //Chunk 12 — REQUIRED OIDC fields.
        AssertFieldPresent(body, OpenIdProviderMetadataParameterNames.SubjectTypesSupported);
        AssertFieldPresent(body, AuthorizationServerMetadataParameterNames.ResponseTypesSupported);
        AssertFieldPresent(body, OpenIdProviderMetadataParameterNames.IdTokenSigningAlgValuesSupported);

        //Chunk 13 — capability-derived OPTIONAL fields.
        AssertFieldPresent(body, AuthorizationServerMetadataParameterNames.GrantTypesSupported);
        AssertFieldPresent(body, AuthorizationServerMetadataParameterNames.CodeChallengeMethodsSupported);
        AssertFieldPresent(body, AuthorizationServerMetadataParameterNames.TokenEndpointAuthMethodsSupported);

        //Chunk 14 — scopes.
        AssertFieldPresent(body, AuthorizationServerMetadataParameterNames.ScopesSupported);

        //Chunk 15 — claims advertisement.
        AssertFieldPresent(body, OpenIdProviderMetadataParameterNames.ClaimsSupported);

        //Chunk 16 — claim_types.
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
        //Regression guard — the chunk-12 additions must not displace the
        //pre-existing endpoint-URL emission.
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

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
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        host.Server.OAuth().ContributeDiscoveryFieldsAsync = static (_, _, _) =>
            ValueTask.FromResult(new DiscoveryDocumentContribution(
                [new DiscoveryStringArrayField(
                    AuthorizationServerMetadataParameterNames.AcrValuesSupported,
                    ["urn:mace:incommon:iap:silver", "loa-substantial"])]));

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
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

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
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

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
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        ServerHttpResponse response = await DispatchDiscoveryAsync(host, material)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument body = JsonDocument.Parse(response.Body);
        string? issuer = body.RootElement.GetProperty("issuer").GetString();

        string expected = material.Registration.IssuerUri!.OriginalString;
        Assert.AreEqual(expected, issuer,
            "The appended openid-configuration mount must keep emitting the exact tenant issuer after the oauth-authorization-server mount is added.");
    }


    private async ValueTask<ServerHttpResponse> DispatchDiscoveryAsync(
        TestHostShell host, VerifierKeyMaterial material)
    {
        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.MetadataDiscovery,
            WellKnownHttpMethods.Get,
            new RequestFields(),
            new ExchangeContext(),
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
            new ExchangeContext(),
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
