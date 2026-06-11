using System.Collections.Generic;
using System.Collections.Immutable;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.OAuth;
using Verifiable.OAuth.Introspection;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Routing;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Server-side RFC 7662 token introspection, driven through the real dispatch pipeline.
/// The library owns the wire (client authentication, the §2.2 JSON shape, the rule that an
/// inactive token discloses nothing further, the fail-closed candidate gate); the
/// application owns the token store behind <see cref="IntrospectTokenDelegate"/>.
/// </summary>
[TestClass]
internal sealed class TokenIntrospectionServerTests
{
    /// <summary>The MSTest-supplied per-test context.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>A fixed clock so issued artefacts are reproducible.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));

    /// <summary>The protected-resource client identifier registered for the introspection tests.</summary>
    private const string ClientId = "https://introspection.client.test";

    /// <summary>The base URI the registered client is reachable at.</summary>
    private static readonly Uri ClientBaseUri = new("https://introspection.client.test");

    /// <summary>The single capability the introspection endpoint requires.</summary>
    private static readonly ImmutableHashSet<CapabilityIdentifier> IntrospectionCapabilities =
        ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthTokenIntrospection);


    /// <summary>
    /// A wired introspection endpoint authenticates the caller, relays the token and hint to
    /// the application seam, and answers RFC 7662 §2.2 with the token's metadata as
    /// <c>application/json</c> — including service-specific extension members (here the
    /// RFC 9470 <c>acr</c>/<c>auth_time</c> a step-up deployment records).
    /// </summary>
    [TestMethod]
    public async Task IntrospectionEndpointAuthenticatesCallerAndReturnsActiveTokenMetadata()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, IntrospectionCapabilities);

        DateTimeOffset issuedAt = new(2026, 6, 1, 11, 0, 0, TimeSpan.Zero);
        DateTimeOffset expiresAt = new(2026, 6, 1, 13, 0, 0, TimeSpan.Zero);

        List<(string Token, string? Hint, ClientRecord Client)> introspected = [];
        host.Server.Integration.ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(true);
        host.Server.Integration.IntrospectTokenAsync = (token, hint, registration, _, _) =>
        {
            introspected.Add((token, hint, registration));

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
                ExpiresAt = expiresAt,
                AdditionalClaims = new Dictionary<string, object>
                {
                    ["acr"] = "urn:mace:incommon:iap:silver",
                    ["auth_time"] = issuedAt.ToUnixTimeSeconds()
                }
            });
        };

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeIntrospect,
            "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.Token] = "access-token-to-inspect",
                [OAuthRequestParameterNames.TokenTypeHint] = "access_token"
            },
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.AreEqual("application/json", response.ContentType);

        Assert.HasCount(1, introspected, "The seam must be invoked exactly once.");
        Assert.AreEqual("access-token-to-inspect", introspected[0].Token);
        Assert.AreEqual("access_token", introspected[0].Hint);
        Assert.AreEqual(material.Registration.ClientId, introspected[0].Client.ClientId);

        using JsonDocument document = JsonDocument.Parse(response.Body);
        JsonElement root = document.RootElement;

        Assert.IsTrue(root.GetProperty("active").GetBoolean(), "RFC 7662 §2.2 active must be true.");
        Assert.AreEqual("read write", root.GetProperty("scope").GetString());
        Assert.AreEqual("https://some.other.client", root.GetProperty("client_id").GetString());
        Assert.AreEqual("jdoe", root.GetProperty("username").GetString());
        Assert.AreEqual("Bearer", root.GetProperty("token_type").GetString());
        Assert.AreEqual("Z5O3upPC88QrAjx00dis", root.GetProperty("sub").GetString());
        Assert.AreEqual("https://introspection.client.test", root.GetProperty("iss").GetString());
        Assert.AreEqual("token-jti-1", root.GetProperty("jti").GetString());
        Assert.AreEqual(issuedAt.ToUnixTimeSeconds(), root.GetProperty("iat").GetInt64());
        Assert.AreEqual(expiresAt.ToUnixTimeSeconds(), root.GetProperty("exp").GetInt64());

        //A single audience is written as a JSON string (RFC 7662 §2.2 / RFC 7519 aud).
        Assert.AreEqual(JsonValueKind.String, root.GetProperty("aud").ValueKind);
        Assert.AreEqual("https://protected.example.net/resource", root.GetProperty("aud").GetString());

        //RFC 7662 §2.2 extension members appear as top-level members.
        Assert.AreEqual("urn:mace:incommon:iap:silver", root.GetProperty("acr").GetString());
        Assert.AreEqual(issuedAt.ToUnixTimeSeconds(), root.GetProperty("auth_time").GetInt64());
    }


    /// <summary>
    /// RFC 9396 §9.2: when the application surfaces the granted authorization details for the
    /// token, the library conveys them as the top-level <c>authorization_details</c> member of the
    /// introspection response, carrying the §2 structure (the REQUIRED <c>type</c>, the §2.2 common
    /// fields, and the type-specific members). The application owns the §9.2 per-RS filtering, the
    /// same way it narrows the disclosed scope.
    /// </summary>
    [TestMethod]
    public async Task IntrospectionEmbedsGrantedAuthorizationDetails()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, IntrospectionCapabilities);

        host.Server.Integration.ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(true);
        host.Server.Integration.IntrospectTokenAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(new TokenIntrospectionResult
            {
                IsActive = true,
                Scope = "credential",
                AuthorizationDetails =
                [
                    new AuthorizationDetail
                    {
                        Type = "openid_credential",
                        Locations = ["https://credential-issuer.example"],
                        Actions = ["issue"],
                        ExtensionData = new Dictionary<string, string>(StringComparer.Ordinal)
                        {
                            ["credential_configuration_id"] = "\"UniversityDegree_dc_sd_jwt\"",
                            ["credential_identifiers"] = "[\"CivilEngineeringDegree-2026\",\"ElectricalEngineeringDegree-2026\"]"
                        }
                    }
                ]
            });

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeIntrospect,
            "POST",
            new RequestFields { [OAuthRequestParameterNames.Token] = "credential-access-token" },
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument document = JsonDocument.Parse(response.Body);
        JsonElement details = document.RootElement.GetProperty("authorization_details");

        Assert.AreEqual(JsonValueKind.Array, details.ValueKind,
            "RFC 9396 §9.2: authorization_details is a top-level member carrying the §2 array structure.");
        Assert.AreEqual(1, details.GetArrayLength());

        JsonElement first = details[0];
        Assert.AreEqual("openid_credential", first.GetProperty("type").GetString());

        JsonElement locations = first.GetProperty("locations");
        Assert.AreEqual(JsonValueKind.Array, locations.ValueKind);
        Assert.AreEqual("https://credential-issuer.example", locations[0].GetString());

        JsonElement actions = first.GetProperty("actions");
        Assert.AreEqual("issue", actions[0].GetString());

        //The type-specific members are carried verbatim from the §2 structure.
        Assert.AreEqual("UniversityDegree_dc_sd_jwt",
            first.GetProperty("credential_configuration_id").GetString());
        JsonElement identifiers = first.GetProperty("credential_identifiers");
        Assert.AreEqual(JsonValueKind.Array, identifiers.ValueKind);
        Assert.AreEqual(2, identifiers.GetArrayLength());
        Assert.AreEqual("CivilEngineeringDegree-2026", identifiers[0].GetString());
        Assert.AreEqual("ElectricalEngineeringDegree-2026", identifiers[1].GetString());
    }


    /// <summary>
    /// RFC 9396 §9.2 is conditional ("If the AS includes authorization detail information ..."): an
    /// active token whose result surfaces no authorization details carries no
    /// <c>authorization_details</c> member in the introspection response.
    /// </summary>
    [TestMethod]
    public async Task IntrospectionOmitsAuthorizationDetailsWhenTheTokenCarriesNone()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, IntrospectionCapabilities);

        host.Server.Integration.ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(true);
        host.Server.Integration.IntrospectTokenAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(new TokenIntrospectionResult
            {
                IsActive = true,
                Scope = "read",
                Subject = "Z5O3upPC88QrAjx00dis"
            });

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeIntrospect,
            "POST",
            new RequestFields { [OAuthRequestParameterNames.Token] = "plain-access-token" },
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument document = JsonDocument.Parse(response.Body);
        Assert.IsFalse(document.RootElement.TryGetProperty("authorization_details", out _),
            "RFC 9396 §9.2 is conditional: no authorization details on the token, no member.");
    }


    /// <summary>
    /// Multiple audiences are written as a JSON array, a single audience as a string — both
    /// valid <c>aud</c> shapes per RFC 7519, which RFC 7662 §2.2 inherits.
    /// </summary>
    [TestMethod]
    public async Task IntrospectionEndpointWritesMultipleAudiencesAsArray()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, IntrospectionCapabilities);

        host.Server.Integration.ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(true);
        host.Server.Integration.IntrospectTokenAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(new TokenIntrospectionResult
            {
                IsActive = true,
                Audience = ["https://resource.one/api", "https://resource.two/api"]
            });

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeIntrospect,
            "POST",
            new RequestFields { [OAuthRequestParameterNames.Token] = "multi-aud-token" },
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument document = JsonDocument.Parse(response.Body);
        JsonElement aud = document.RootElement.GetProperty("aud");

        Assert.AreEqual(JsonValueKind.Array, aud.ValueKind);
        Assert.AreEqual(2, aud.GetArrayLength());
        Assert.AreEqual("https://resource.one/api", aud[0].GetString());
        Assert.AreEqual("https://resource.two/api", aud[1].GetString());
    }


    /// <summary>
    /// RFC 7662 §2.2/§2.3: a well-formed, authorized query for an inactive token is not an
    /// error — it answers 200 with <c>{"active":false}</c>. The library enforces the
    /// non-disclosure rule itself: even when the application's result carries metadata, an
    /// inactive result emits the <c>active</c> member and nothing else, so a probing resource
    /// learns nothing about why the token is inactive.
    /// </summary>
    [TestMethod]
    public async Task IntrospectionEndpointInactiveTokenDisclosesNothingFurther()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, IntrospectionCapabilities);

        host.Server.Integration.ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(true);

        //An application that (incorrectly) attaches metadata to an inactive result must not
        //be able to leak it: the library writes only active when IsActive is false.
        host.Server.Integration.IntrospectTokenAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(new TokenIntrospectionResult
            {
                IsActive = false,
                Subject = "should-not-appear",
                Scope = "should-not-appear"
            });

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeIntrospect,
            "POST",
            new RequestFields { [OAuthRequestParameterNames.Token] = "revoked-or-unknown" },
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.AreEqual("application/json", response.ContentType);

        using JsonDocument document = JsonDocument.Parse(response.Body);
        JsonElement root = document.RootElement;

        Assert.IsFalse(root.GetProperty("active").GetBoolean());

        int memberCount = 0;
        foreach(JsonProperty _ in root.EnumerateObject())
        {
            memberCount++;
        }

        Assert.AreEqual(1, memberCount, "An inactive response must carry only the active member (RFC 7662 §2.2).");
    }


    /// <summary>
    /// When client authentication fails the endpoint returns 401 <c>invalid_client</c> and
    /// never reaches the introspection seam — token state is not leaked to an unauthenticated
    /// caller (RFC 7662 §2.3).
    /// </summary>
    [TestMethod]
    public async Task IntrospectionEndpointRejectsUnauthenticatedCallerWithoutTouchingTheStore()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, IntrospectionCapabilities);

        bool seamInvoked = false;
        host.Server.Integration.ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(false);
        host.Server.Integration.IntrospectTokenAsync = (_, _, _, _, _) =>
        {
            seamInvoked = true;

            return ValueTask.FromResult(TokenIntrospectionResult.Inactive);
        };

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeIntrospect,
            "POST",
            new RequestFields { [OAuthRequestParameterNames.Token] = "some-token" },
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(401, response.StatusCode, response.Body);
        Assert.Contains(OAuthErrors.InvalidClient, response.Body, StringComparison.Ordinal);
        Assert.IsFalse(seamInvoked, "A failed authentication must not introspect anything.");
    }


    /// <summary>
    /// Fail-closed: declaring the introspection capability without wiring the introspection
    /// seam leaves the endpoint absent from the chain, so a request to it returns 404 rather
    /// than silently answering for a store it cannot read.
    /// </summary>
    [TestMethod]
    public async Task IntrospectionEndpointAbsentWhenSeamUnwired()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, IntrospectionCapabilities);

        //Client authentication is wired but the introspection seam is not — the candidate
        //gate requires both, so the endpoint must not materialize.
        host.Server.Integration.ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(true);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeIntrospect,
            "POST",
            new RequestFields { [OAuthRequestParameterNames.Token] = "some-token" },
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(404, response.StatusCode,
            "An unwired introspection seam must leave the endpoint absent (fail-closed).");
    }


    /// <summary>
    /// Per-query policy via capability attenuation: a deployment's
    /// <see cref="ResolveCapabilitiesDelegate"/> runs at chain-build time with the request in
    /// scope, so it can drop <c>OAuthTokenIntrospection</c> for a denylisted caller IP (read from
    /// <c>X-Forwarded-For</c>). The endpoint then vanishes (404) for that agent while remaining
    /// available to others — the same per-request attenuation that gates every endpoint, with no
    /// introspection-specific machinery.
    /// </summary>
    [TestMethod]
    public async Task IntrospectionEndpointVanishesForADenylistedCallerIp()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, IntrospectionCapabilities);

        const string blockedIp = "203.0.113.7";
        host.Server.Integration.ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(true);
        host.Server.Integration.IntrospectTokenAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(new TokenIntrospectionResult { IsActive = true, Subject = "Z5O3upPC88QrAjx00dis" });

        //Attenuate per request: when the caller's forwarded IP is denylisted, the active
        //capability set excludes introspection, so the candidate is dropped from the chain.
        host.Server.Integration.ResolveCapabilitiesAsync = (registration, context, _) =>
        {
            bool isBlocked = context.IncomingRequest is { } request
                && request.Headers.TryGetSingle("X-Forwarded-For", out string? ip)
                && ip == blockedIp;

            IReadOnlySet<CapabilityIdentifier> active = isBlocked
                ? registration.AllowedCapabilities.Remove(WellKnownCapabilityIdentifiers.OAuthTokenIntrospection)
                : registration.AllowedCapabilities;

            return ValueTask.FromResult(active);
        };

        RequestFields fields = new() { [OAuthRequestParameterNames.Token] = "some-token" };

        ServerHttpResponse blocked = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value, WellKnownEndpointNames.AuthCodeIntrospect, "POST",
            fields, ForwardedFor(blockedIp), new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse allowed = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value, WellKnownEndpointNames.AuthCodeIntrospect, "POST",
            fields, ForwardedFor("198.51.100.4"), new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(404, blocked.StatusCode,
            "A denylisted caller IP must see no introspection endpoint (attenuated out of the chain).");
        Assert.AreEqual(200, allowed.StatusCode, allowed.Body);
    }


    /// <summary>
    /// Per-caller content policy: RFC 7662 §2.2 lets the AS show the same token differently to
    /// different protected resources. The <see cref="IntrospectTokenDelegate"/> receives the
    /// authenticated caller, so a deployment can narrow the disclosed scope per resource — here a
    /// limited resource sees only <c>read</c> where a full resource sees <c>read write admin</c>.
    /// </summary>
    [TestMethod]
    public async Task IntrospectionNarrowsDisclosedScopePerCallingResource()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial fullResource = host.RegisterClient(
            "https://full.resource.test", new Uri("https://full.resource.test"), IntrospectionCapabilities);
        using VerifierKeyMaterial limitedResource = host.RegisterClient(
            "https://limited.resource.test", new Uri("https://limited.resource.test"), IntrospectionCapabilities);

        host.Server.Integration.ValidateClientCredentialsAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(true);

        string limitedTenant = limitedResource.Registration.TenantId.Value;
        host.Server.Integration.IntrospectTokenAsync = (token, hint, registration, context, ct) =>
        {
            string scope = registration.TenantId.Value == limitedTenant ? "read" : "read write admin";

            return ValueTask.FromResult(new TokenIntrospectionResult
            {
                IsActive = true,
                Subject = "Z5O3upPC88QrAjx00dis",
                Scope = scope
            });
        };

        RequestFields fields = new() { [OAuthRequestParameterNames.Token] = "shared-token" };

        ServerHttpResponse full = await host.DispatchAtEndpointAsync(
            fullResource.Registration.TenantId.Value, WellKnownEndpointNames.AuthCodeIntrospect, "POST",
            fields, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);
        ServerHttpResponse limited = await host.DispatchAtEndpointAsync(
            limitedTenant, WellKnownEndpointNames.AuthCodeIntrospect, "POST",
            fields, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, full.StatusCode, full.Body);
        Assert.AreEqual(200, limited.StatusCode, limited.Body);

        using JsonDocument fullDoc = JsonDocument.Parse(full.Body);
        using JsonDocument limitedDoc = JsonDocument.Parse(limited.Body);

        Assert.AreEqual("read write admin", fullDoc.RootElement.GetProperty("scope").GetString());
        Assert.AreEqual("read", limitedDoc.RootElement.GetProperty("scope").GetString(),
            "RFC 7662 §2.2: the same token introspected by a different resource may be shown a narrower scope.");
    }


    private static RequestHeaders ForwardedFor(string ip) =>
        new(new Dictionary<string, string[]> { ["X-Forwarded-For"] = [ip] });
}
