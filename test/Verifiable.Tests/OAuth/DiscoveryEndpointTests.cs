using System.Collections.Immutable;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Routing;

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

    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 5, 17, 12, 0, 0, TimeSpan.Zero));

    private const string ClientId = "https://discovery.client.test";
    private static readonly Uri ClientBaseUri = new("https://discovery.client.test");


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


    private async ValueTask<ServerHttpResponse> DispatchDiscoveryAsync(
        TestHostShell host, VerifierKeyMaterial material)
    {
        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.MetadataDiscovery,
            WellKnownHttpMethods.Get,
            new RequestFields(),
            new RequestContext(),
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
