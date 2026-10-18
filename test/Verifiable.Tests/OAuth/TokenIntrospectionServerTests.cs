using Microsoft.Extensions.Time.Testing;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
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
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    /// <summary>The protected-resource client identifier registered for the introspection tests.</summary>
    private const string ClientId = "https://introspection.client.test";

    /// <summary>The base URI the registered client is reachable at.</summary>
    private static Uri ClientBaseUri { get; } = new("https://introspection.client.test");

    /// <summary>The single capability the introspection endpoint requires.</summary>
    private static ImmutableHashSet<CapabilityIdentifier> IntrospectionCapabilities { get; } =
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
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, IntrospectionCapabilities).ConfigureAwait(false);

        DateTimeOffset issuedAt = new(2026, 6, 1, 11, 0, 0, TimeSpan.Zero);
        DateTimeOffset expiresAt = new(2026, 6, 1, 13, 0, 0, TimeSpan.Zero);

        List<(string Token, string? Hint, ClientRecord Client)> introspected = [];
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _) =>
                ValueTask.FromResult(true);

            candidateIntegration.IntrospectTokenAsync = (token, hint, registration, _, _) =>
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
        }).ConfigureAwait(false);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeIntrospect,
            "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.Token] = "access-token-to-inspect",
                [OAuthRequestParameterNames.TokenTypeHint] = "access_token"
            },
            [],
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

        //RFC 7662 §2.2 permits aud as a string OR a list; this projection always emits the array
        //form, including a single audience — the SAME shape the RFC 9068 JWT access-token producer
        //uses, so one server emits one aud wire shape regardless of endpoint.
        JsonElement aud = root.GetProperty("aud");
        Assert.AreEqual(JsonValueKind.Array, aud.ValueKind);
        Assert.HasCount(1, aud.EnumerateArray().ToList());
        Assert.AreEqual("https://protected.example.net/resource", aud[0].GetString());

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
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, IntrospectionCapabilities).ConfigureAwait(false);

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
        }).ConfigureAwait(false);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeIntrospect,
            "POST",
            new RequestFields { [OAuthRequestParameterNames.Token] = "credential-access-token" },
            [],
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
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, IntrospectionCapabilities).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _) =>
                ValueTask.FromResult(true);

            candidateIntegration.IntrospectTokenAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(new TokenIntrospectionResult
                {
                    IsActive = true,
                    Scope = "read",
                    Subject = "Z5O3upPC88QrAjx00dis"
                });
        }).ConfigureAwait(false);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeIntrospect,
            "POST",
            new RequestFields { [OAuthRequestParameterNames.Token] = "plain-access-token" },
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument document = JsonDocument.Parse(response.Body);
        Assert.IsFalse(document.RootElement.TryGetProperty("authorization_details", out _),
            "RFC 9396 §9.2 is conditional: no authorization details on the token, no member.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.2">RFC 9449 Section 6.2</see>: "For a DPoP-bound
    /// access token, the hash of the public key to which the token is bound is conveyed to the protected resource as
    /// metainformation in a token introspection response. The hash is conveyed using the same cnf content with jkt member
    /// structure as the JWK Thumbprint confirmation method, described in Section 6.1, as a top-level member of the
    /// introspection response JSON." and "If the token_type member is included in the introspection response, it MUST
    /// contain the value DPoP." An introspection request posted over the wire for a token the application answers as
    /// active and bound to the thumbprint <c>0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I</c> is answered 200 with the
    /// top-level member <c>"cnf":{"jkt":"0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"}</c>, the object carrying that one
    /// member, and <c>"token_type":"DPoP"</c>, the text's literal. The rows: the application states no token type, so the
    /// library writes <c>DPoP</c>; the application states <c>DPoP</c>; the application states <c>dpop</c>, the same type
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 Section 5.1</see>: "Value is case
    /// insensitive."), written as <c>DPoP</c>.
    /// </summary>
    /// <param name="tokenType">The token type the application states, or <see langword="null"/> for none.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(null, DisplayName = "no token type stated")]
    [DataRow("DPoP", DisplayName = "the token type DPoP stated")]
    [DataRow("dpop", DisplayName = "the token type dpop stated")]
    public async Task IntrospectionConveysTheJwkThumbprintBindingOfADpopBoundTokenAsync(string? tokenType)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, IntrospectionCapabilities).ConfigureAwait(false);
        await WireIntrospectionAsync(host, new TokenIntrospectionResult
        {
            IsActive = true,
            Subject = "Z5O3upPC88QrAjx00dis",
            TokenType = tokenType,
            Confirmation = new ConfirmationMethod { JwkThumbprint = BoundThumbprint }
        }).ConfigureAwait(false);

        HttpResponseData response = await IntrospectOverTheWireAsync(host, material, OutgoingHeaders.Empty).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        using JsonDocument document = JsonDocument.Parse(response.Body);
        Assert.IsTrue(document.RootElement.TryGetProperty("cnf", out JsonElement confirmation), $"The response carries the cnf member: {response.Body}");
        Assert.AreEqual(JsonValueKind.Object, confirmation.ValueKind, response.Body);
        Assert.IsTrue(confirmation.TryGetProperty("jkt", out JsonElement thumbprint), $"The cnf member carries jkt: {response.Body}");
        Assert.AreEqual("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I", thumbprint.GetString(), response.Body);
        Assert.HasCount(1, confirmation.EnumerateObject().ToList(), "The cnf object carries the jkt member alone.");
        Assert.IsTrue(document.RootElement.TryGetProperty("token_type", out JsonElement writtenTokenType), $"The response carries the token_type member: {response.Body}");
        Assert.AreEqual("DPoP", writtenTokenType.GetString(), response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7662#section-2.2">RFC 7662 Section 2.2</see>: "token_type OPTIONAL.
    /// Type of the token as defined in Section 5.1 of OAuth 2.0 [RFC6749].", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.2">RFC 9449 Section 6.2</see>, whose <c>cnf</c> is
    /// conveyed "For a DPoP-bound access token" only. An introspection request posted over the wire for a token the
    /// application answers as active, bound to no key and of the type <c>Bearer</c>, is answered 200 with
    /// <c>"token_type":"Bearer"</c> and no <c>cnf</c> member.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task IntrospectionOfATokenBoundToNoKeyCarriesNoConfirmationAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, IntrospectionCapabilities).ConfigureAwait(false);
        await WireIntrospectionAsync(host, new TokenIntrospectionResult
        {
            IsActive = true,
            Subject = "Z5O3upPC88QrAjx00dis",
            TokenType = "Bearer"
        }).ConfigureAwait(false);

        HttpResponseData response = await IntrospectOverTheWireAsync(host, material, OutgoingHeaders.Empty).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        using JsonDocument document = JsonDocument.Parse(response.Body);
        Assert.IsFalse(document.RootElement.TryGetProperty("cnf", out _), "A token bound to no key carries no cnf.");
        Assert.IsTrue(document.RootElement.TryGetProperty("token_type", out JsonElement writtenTokenType), $"The response carries the token_type member: {response.Body}");
        Assert.AreEqual("Bearer", writtenTokenType.GetString(), response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.2">RFC 9449 Section 6.2</see>: "If the token_type
    /// member is included in the introspection response, it MUST contain the value DPoP.", for a token whose binding is
    /// conveyed as the <c>cnf</c> member, and <see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.6.1">RFC 9110
    /// Section 15.6.1</see>: "The 500 (Internal Server Error) status code indicates that the server encountered an
    /// unexpected condition that prevented it from fulfilling the request." An application answer whose token type
    /// contradicts its confirmation is a fault of the application's wiring, and the server conveys no binding it cannot
    /// state consistently: an introspection request posted over the wire is answered 500 with exactly the body
    /// <c>{"error":"server_error","error_description":"The server is not ready to serve this request."}</c> and no
    /// introspection member. The rows: the token type <c>Bearer</c> beside a <c>jkt</c> confirmation; the token type
    /// <c>DPoP</c> with no confirmation.
    /// </summary>
    /// <param name="row">The contradiction: <see cref="BearerBesideAConfirmationRow"/> or <see cref="DpopWithoutAConfirmationRow"/>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(BearerBesideAConfirmationRow)]
    [DataRow(DpopWithoutAConfirmationRow)]
    public async Task IntrospectionAnswersATokenTypeContradictingTheConfirmationAsAServerErrorAsync(string row)
    {
        (string tokenType, ConfirmationMethod? confirmation) = row switch
        {
            BearerBesideAConfirmationRow => ("Bearer", new ConfirmationMethod { JwkThumbprint = BoundThumbprint }),
            DpopWithoutAConfirmationRow => ("DPoP", null),
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown contradiction row.")
        };
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, IntrospectionCapabilities).ConfigureAwait(false);
        await WireIntrospectionAsync(host, new TokenIntrospectionResult
        {
            IsActive = true,
            Subject = "Z5O3upPC88QrAjx00dis",
            TokenType = tokenType,
            Confirmation = confirmation
        }).ConfigureAwait(false);

        HttpResponseData response = await IntrospectOverTheWireAsync(host, material, OutgoingHeaders.Empty).ConfigureAwait(false);

        Assert.AreEqual(500, response.StatusCode, response.Body);
        Assert.AreEqual(
            "{\"error\":\"server_error\",\"error_description\":\"The server is not ready to serve this request.\"}", response.Body);
    }


    /// <summary>
    /// The row whose application states the token type <c>Bearer</c> beside a <c>jkt</c> confirmation. A constant, not a
    /// property, because a DataRow attribute argument must be a compile-time constant.
    /// </summary>
    private const string BearerBesideAConfirmationRow = "bearer-beside-a-confirmation";

    /// <summary>
    /// The row whose application states the token type <c>DPoP</c> with no confirmation. A constant, not a property,
    /// because a DataRow attribute argument must be a compile-time constant.
    /// </summary>
    private const string DpopWithoutAConfirmationRow = "dpop-without-a-confirmation";

    /// <summary>The JWK SHA-256 Thumbprint the introspected tokens are bound to, the value of RFC 9449 Figure 11.</summary>
    private static string BoundThumbprint { get; } = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.1">RFC 9449 Section 6.1</see>: "The value of the jkt
    /// member MUST be the base64url encoding (as defined in [RFC7515]) of the JWK SHA-256 Thumbprint (according to
    /// [RFC7638]) of the DPoP public key (in JWK format) to which the access token is bound.", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.2">Section 6.2</see>: the hash "is conveyed using the
    /// same cnf content with jkt member structure as the JWK Thumbprint confirmation method, described in Section 6.1".
    /// A SHA-256 hash is 32 octets, whose base64url encoding is 43 characters. An application answer confirming the token
    /// by a value that is no such encoding binds it to no key, a fault of the application's wiring: an introspection
    /// request posted over the wire is answered 500 with exactly the body
    /// <c>{"error":"server_error","error_description":"The server is not ready to serve this request."}</c> and no
    /// <c>cnf</c> member. The rows: the empty value; three spaces; <c>not-a-thumbprint</c>; the 42 characters of the RFC
    /// 9449 Figure 11 thumbprint without its last.
    /// </summary>
    /// <param name="jwkThumbprint">The confirmation's thumbprint as the application answers it.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("", DisplayName = "an empty thumbprint")]
    [DataRow("   ", DisplayName = "three spaces")]
    [DataRow("not-a-thumbprint", DisplayName = "not-a-thumbprint")]
    [DataRow("0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4", DisplayName = "42 characters")]
    public async Task IntrospectionAnswersAConfirmationWithoutAThumbprintSpellingAsAServerErrorAsync(string jwkThumbprint)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, IntrospectionCapabilities).ConfigureAwait(false);
        await WireIntrospectionAsync(host, new TokenIntrospectionResult
        {
            IsActive = true,
            Subject = "Z5O3upPC88QrAjx00dis",
            Confirmation = new ConfirmationMethod { JwkThumbprint = jwkThumbprint }
        }).ConfigureAwait(false);

        HttpResponseData response = await IntrospectOverTheWireAsync(host, material, OutgoingHeaders.Empty).ConfigureAwait(false);

        Assert.AreEqual(500, response.StatusCode, response.Body);
        Assert.AreEqual(
            "{\"error\":\"server_error\",\"error_description\":\"The server is not ready to serve this request.\"}", response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.2">RFC 9449 Section 6.2</see>: "If the token_type
    /// member is included in the introspection response, it MUST contain the value DPoP.", and the bound key's hash "is
    /// conveyed using the same cnf content with jkt member structure as the JWK Thumbprint confirmation method, described
    /// in Section 6.1, as a top-level member of the introspection response JSON." An application answer confirming the
    /// token by the thumbprint <c>0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I</c> whose extension members name a member
    /// the server writes from the confirmation would state the binding twice, a fault of the application's wiring: an
    /// introspection request posted over the wire is answered 500 with exactly the body
    /// <c>{"error":"server_error","error_description":"The server is not ready to serve this request."}</c> and no
    /// introspection member. The rows: the extension member <c>"token_type":"Bearer"</c>; the extension member
    /// <c>"cnf":{"jkt":"NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"}</c>, the RFC 7638 example thumbprint.
    /// </summary>
    /// <param name="row">The extension member: <see cref="TokenTypeExtensionRow"/> or <see cref="ConfirmationExtensionRow"/>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(TokenTypeExtensionRow)]
    [DataRow(ConfirmationExtensionRow)]
    public async Task IntrospectionAnswersAnExtensionMemberNamingAWrittenMemberAsAServerErrorAsync(string row)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, IntrospectionCapabilities).ConfigureAwait(false);
        await WireIntrospectionAsync(host, ConfirmedAnswerWithExtensionMember(row)).ConfigureAwait(false);

        HttpResponseData response = await IntrospectOverTheWireAsync(host, material, OutgoingHeaders.Empty).ConfigureAwait(false);

        Assert.AreEqual(500, response.StatusCode, response.Body);
        Assert.AreEqual(
            "{\"error\":\"server_error\",\"error_description\":\"The server is not ready to serve this request.\"}", response.Body);
    }


    /// <summary>
    /// The row whose extension members carry <c>"token_type":"Bearer"</c>. A constant, not a property, because a DataRow
    /// attribute argument must be a compile-time constant.
    /// </summary>
    internal const string TokenTypeExtensionRow = "token-type-extension";

    /// <summary>
    /// The row whose extension members carry a <c>cnf</c> object. A constant, not a property, because a DataRow attribute
    /// argument must be a compile-time constant.
    /// </summary>
    internal const string ConfirmationExtensionRow = "cnf-extension";


    /// <summary>
    /// An active application answer confirming the token by the RFC 9449 Figure 11 thumbprint, whose extension members
    /// carry the member <paramref name="row"/> names: <c>"token_type":"Bearer"</c> for <see cref="TokenTypeExtensionRow"/>,
    /// <c>"cnf":{"jkt":"NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"}</c> for <see cref="ConfirmationExtensionRow"/>.
    /// </summary>
    /// <param name="row">The extension member's row.</param>
    /// <returns>The application's answer.</returns>
    internal static TokenIntrospectionResult ConfirmedAnswerWithExtensionMember(string row) => new()
    {
        IsActive = true,
        Subject = "Z5O3upPC88QrAjx00dis",
        Confirmation = new ConfirmationMethod { JwkThumbprint = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" },
        AdditionalClaims = row switch
        {
            TokenTypeExtensionRow => new Dictionary<string, object>(StringComparer.Ordinal) { ["token_type"] = "Bearer" },
            ConfirmationExtensionRow => new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["cnf"] = new Dictionary<string, object>(StringComparer.Ordinal) { ["jkt"] = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" }
            },
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown extension member row.")
        }
    };


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7662#section-2.2">RFC 7662 Section 2.2</see>: "Note that to avoid
    /// disclosing too much of the authorization server's state to a third party, the authorization server SHOULD NOT
    /// include any additional information about an inactive token, including why the token is inactive." An application
    /// answer for an inactive token that carries a confirmation by an empty thumbprint and extension members naming
    /// <c>active</c> (<see langword="true"/>), <c>cnf</c> and <c>token_type</c> (<c>Bearer</c>) is answered as an inactive
    /// token: an introspection request posted over the wire is answered 200 with exactly the body
    /// <c>{"active":false}</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task IntrospectionOfAnInactiveTokenCarriesNothingTheAnswerAddsAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, IntrospectionCapabilities).ConfigureAwait(false);
        await WireIntrospectionAsync(host, InactiveAnswerCarryingFurtherMembers()).ConfigureAwait(false);

        HttpResponseData response = await IntrospectOverTheWireAsync(host, material, OutgoingHeaders.Empty).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.AreEqual("{\"active\":false}", response.Body);
    }


    /// <summary>
    /// An application answer for an inactive token that carries further members: a confirmation by an empty thumbprint,
    /// and extension members naming <c>active</c> (<see langword="true"/>), <c>cnf</c> (the RFC 7638 example thumbprint
    /// as <c>jkt</c>) and <c>token_type</c> (<c>Bearer</c>).
    /// </summary>
    /// <returns>The application's answer.</returns>
    internal static TokenIntrospectionResult InactiveAnswerCarryingFurtherMembers() => new()
    {
        IsActive = false,
        Confirmation = new ConfirmationMethod { JwkThumbprint = string.Empty },
        AdditionalClaims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["active"] = true,
            ["cnf"] = new Dictionary<string, object>(StringComparer.Ordinal) { ["jkt"] = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" },
            ["token_type"] = "Bearer"
        }
    };


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.2">RFC 9449 Section 6.2</see>: "Note that the resource
    /// server does not send a DPoP proof with the introspection request, and the authorization server does not validate
    /// an access token's DPoP binding at the introspection endpoint." The sentence holds for a bound token too: at an
    /// authorization server wiring DPoP, an introspection request posted over the wire for a token the application
    /// answers as active, of the type <c>DPoP</c> and bound to one key, with a valid DPoP proof by another, unrelated key
    /// in its <c>DPoP</c> field, is served as the same request without the field is: 200, the body byte for byte the body
    /// answered without it, both bodies carrying <c>cnf.jkt</c> equal to the bound key's JWK SHA-256 Thumbprint, and no
    /// <c>DPoP-Nonce</c> field line. The authorization server does not hold the token's binding against the proof at the
    /// introspection endpoint.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task IntrospectionEndpointServesARequestCarryingADpopProofAsItServesOneWithoutAsync()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> boundKey = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> unrelatedKey = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            string boundThumbprint = new DpopKey(boundKey, WellKnownJwaValues.Es256).GetThumbprint(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = await host.RegisterClientAsync(
                ClientId, ClientBaseUri, IntrospectionCapabilities).ConfigureAwait(false);
            _ = await host.EnableDpopAsync().ConfigureAwait(false);
            await WireIntrospectionAsync(host, new TokenIntrospectionResult
            {
                IsActive = true,
                Subject = "Z5O3upPC88QrAjx00dis",
                Scope = "read",
                TokenType = "DPoP",
                Confirmation = new ConfirmationMethod { JwkThumbprint = boundThumbprint }
            }).ConfigureAwait(false);
            await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
            string segment = material.Registration.TenantId.Value;
            Uri endpoint = new(host.Host("default").HttpBaseAddress!,
                TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeIntrospect, segment));
            Dictionary<string, string> fields = new(StringComparer.Ordinal)
            {
                [OAuthRequestParameterNames.Token] = "introspected-access-token",
                [OAuthRequestParameterNames.ClientId] = ClientId
            };

            string proof = await ResourceDpopProofs.BuildAsync(
                new DpopKey(unrelatedKey, WellKnownJwaValues.Es256), WellKnownHttpMethods.Post, endpoint.OriginalString,
                accessToken: null, nonce: null, TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);

            HttpResponseData withoutProof = await RawAuthCodeWirePushers.PushRawIntrospectionFieldsAsync(
                host, segment, fields, OutgoingHeaders.Empty, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The request without a proof is answered without a server fault.");
            HttpResponseData withProof = await RawAuthCodeWirePushers.PushRawIntrospectionFieldsAsync(
                host, segment, fields, OutgoingHeaders.Empty.WithDpop(proof), TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The request with a proof is answered without a server fault.");

            Assert.AreEqual(200, withoutProof.StatusCode, withoutProof.Body);
            Assert.AreEqual(200, withProof.StatusCode, withProof.Body);
            Assert.AreSequenceEqual(Encoding.UTF8.GetBytes(withoutProof.Body), Encoding.UTF8.GetBytes(withProof.Body));
            Assert.IsEmpty(withProof.Headers.Headers.GetValues(WellKnownHttpHeaderNames.DPoPNonce), "The endpoint provides no DPoP nonce.");
            foreach(HttpResponseData answered in new[] { withoutProof, withProof })
            {
                using JsonDocument document = JsonDocument.Parse(answered.Body);
                Assert.AreEqual(boundThumbprint, document.RootElement.GetProperty("cnf").GetProperty("jkt").GetString(), answered.Body);
            }
        }
        finally
        {
            boundKey.PublicKey.Dispose();
            boundKey.PrivateKey.Dispose();
            unrelatedKey.PublicKey.Dispose();
            unrelatedKey.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7662#section-2.1">RFC 7662 Section 2.1</see>: "If the server is
    /// unable to locate the token using the given hint, it MUST extend its search across all of its supported token
    /// types. An authorization server MAY ignore this parameter, particularly if it is able to detect the token type
    /// automatically. Values for this field are defined in the "OAuth Token Type Hints" registry defined in OAuth Token
    /// Revocation [RFC7009]." The hint is the application's to read: an introspection request posted over the wire with
    /// <c>token_type_hint=DPoP</c>, a value outside that registry, is answered 200 and the application's introspection
    /// seam receives the hint <c>DPoP</c> as sent.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task IntrospectionEndpointHandsATokenTypeHintToTheApplicationAsSentAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, IntrospectionCapabilities).ConfigureAwait(false);
        ConcurrentQueue<string?> hints = new();
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _) => ValueTask.FromResult(true);
            candidateIntegration.IntrospectTokenAsync = (_, hint, _, _, _) =>
            {
                hints.Enqueue(hint);

                return ValueTask.FromResult(new TokenIntrospectionResult { IsActive = true, Subject = "Z5O3upPC88QrAjx00dis" });
            };
        }).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        HttpResponseData response = await RawAuthCodeWirePushers.PushRawIntrospectionFieldsAsync(
            host, material.Registration.TenantId.Value,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [OAuthRequestParameterNames.Token] = "introspected-access-token",
                [OAuthRequestParameterNames.TokenTypeHint] = "DPoP",
                [OAuthRequestParameterNames.ClientId] = ClientId
            },
            OutgoingHeaders.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The introspection request is answered without a server fault.");
        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.AreEqual("DPoP", Assert.ContainsSingle(hints));
    }


    /// <summary>
    /// Wires client authentication to admit every caller and the introspection seam to answer <paramref name="result"/>
    /// for every token.
    /// </summary>
    /// <param name="host">The host whose integration is altered.</param>
    /// <param name="result">The application's answer.</param>
    /// <returns>A task that completes when the alteration is published.</returns>
    private static Task WireIntrospectionAsync(TestHostShell host, TokenIntrospectionResult result) =>
        TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _) => ValueTask.FromResult(true);
            candidateIntegration.IntrospectTokenAsync = (_, _, _, _, _) => ValueTask.FromResult(result);
        });


    /// <summary>
    /// Starts the host's listener and posts an introspection request for the token <c>introspected-access-token</c> over
    /// the wire with <paramref name="headers"/>, the caller naming itself by <see cref="ClientId"/>, and asserts the host
    /// captured no fault in the exchange.
    /// </summary>
    /// <param name="host">The host serving the endpoint.</param>
    /// <param name="material">The calling resource's registration.</param>
    /// <param name="headers">The request's further header fields.</param>
    /// <returns>The answer as received.</returns>
    private async Task<HttpResponseData> IntrospectOverTheWireAsync(TestHostShell host, VerifierKeyMaterial material, OutgoingHeaders headers)
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
            headers, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsEmpty(hosted.ConsumeHttpFaults(), "The introspection request is answered without a server fault.");

        return response;
    }


    /// <summary>
    /// Multiple audiences are written as a JSON array, a single audience as a string — both
    /// valid <c>aud</c> shapes per RFC 7519, which RFC 7662 §2.2 inherits.
    /// </summary>
    [TestMethod]
    public async Task IntrospectionEndpointWritesMultipleAudiencesAsArray()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, IntrospectionCapabilities).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _) =>
                ValueTask.FromResult(true);

            candidateIntegration.IntrospectTokenAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(new TokenIntrospectionResult
                {
                    IsActive = true,
                    Audience = ["https://resource.one/api", "https://resource.two/api"]
                });
        }).ConfigureAwait(false);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeIntrospect,
            "POST",
            new RequestFields { [OAuthRequestParameterNames.Token] = "multi-aud-token" },
            [],
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
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, IntrospectionCapabilities).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _) =>
                ValueTask.FromResult(true);


            //An application that (incorrectly) attaches metadata to an inactive result must not
            //be able to leak it: the library writes only active when IsActive is false.

            candidateIntegration.IntrospectTokenAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(new TokenIntrospectionResult
                {
                    IsActive = false,
                    Subject = "should-not-appear",
                    Scope = "should-not-appear"
                });
        }).ConfigureAwait(false);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeIntrospect,
            "POST",
            new RequestFields { [OAuthRequestParameterNames.Token] = "revoked-or-unknown" },
            [],
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
    /// <see href="https://www.rfc-editor.org/rfc/rfc7662#section-2.3">RFC 7662 Section 2.3</see>: "If the
    /// protected resource uses OAuth 2.0 client credentials to authenticate to the introspection endpoint and its
    /// credentials are invalid, the authorization server responds with an HTTP 401 (Unauthorized) as described in
    /// Section 5.2 of OAuth 2.0 [RFC6749]." A caller whose client authentication fails, at a server that advertises
    /// no <c>client_secret_basic</c> and for a request that used no <c>Authorization</c> field, is answered 400
    /// <c>invalid_client</c> with no <c>WWW-Authenticate</c> field, and the introspection seam is never reached, so
    /// token state is not leaked to an unauthenticated caller. The 400 is a named deviation of the library from the
    /// section's 401: such a server has no challenge applicable to the endpoint, and a 401 is sent only with one.
    /// </summary>
    [TestMethod]
    public async Task IntrospectionEndpointRejectsUnauthenticatedCallerWithoutTouchingTheStore()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, IntrospectionCapabilities).ConfigureAwait(false);

        bool seamInvoked = false;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _) =>
                ValueTask.FromResult(false);

            candidateIntegration.IntrospectTokenAsync = (_, _, _, _, _) =>
            {
                seamInvoked = true;

                return ValueTask.FromResult(TokenIntrospectionResult.Inactive);
            };
        }).ConfigureAwait(false);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeIntrospect,
            "POST",
            new RequestFields { [OAuthRequestParameterNames.Token] = "some-token" },
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.Contains(OAuthErrors.InvalidClient, response.Body, StringComparison.Ordinal);
        Assert.IsFalse(response.Headers.ContainsKey(WellKnownHttpHeaderNames.WwwAuthenticate), "No challenge applies, so none is sent.");
        Assert.IsFalse(seamInvoked, "A failed authentication must not introspect anything.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7662#section-2.3">RFC 7662 Section 2.3</see>: "If the
    /// protected resource uses OAuth 2.0 client credentials to authenticate to the introspection endpoint and its
    /// credentials are invalid, the authorization server responds with an HTTP 401 (Unauthorized) as described in
    /// Section 5.2 of OAuth 2.0 [RFC6749]." An introspection request posted over the wire with a wrong
    /// <c>client_secret</c> form credential, at a server that advertises no <c>client_secret_basic</c>, is answered
    /// 400 <c>invalid_client</c> with no <c>WWW-Authenticate</c> field, and the introspection seam is never
    /// reached. The 400 is a named deviation of the library from the section's 401: a form credential at such a
    /// server has no challenge applicable to the endpoint, and a 401 is sent only with one
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.5.2">RFC 9110 Section 15.5.2</see>).
    /// </summary>
    [TestMethod]
    public async Task AWrongFormSecretAtAServerWithoutBasicIsABadRequestWithoutAChallenge()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, IntrospectionCapabilities).ConfigureAwait(false);

        bool seamInvoked = false;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (reading, _, _, _) =>
                ValueTask.FromResult(string.Equals(reading.ClientSecret, "the-right-secret", StringComparison.Ordinal));

            candidateIntegration.IntrospectTokenAsync = (_, _, _, _, _) =>
            {
                seamInvoked = true;

                return ValueTask.FromResult(TokenIntrospectionResult.Inactive);
            };
        }).ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        Uri endpoint = new(hosted.HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeIntrospect, material.Registration.TenantId.Value));
        HttpResponseData response = await HttpClientTransport.SendFormPostAsync(
            hosted.SharedHttpClient!, endpoint,
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.Token] = "some-token",
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.ClientSecret] = "a-wrong-secret"
            },
            OutgoingHeaders.Empty, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.AreEqual(
            "{\"error\":\"invalid_client\",\"error_description\":\"Client authentication failed.\"}", response.Body);
        Assert.IsEmpty(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate));
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
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, IntrospectionCapabilities).ConfigureAwait(false);

        //Client authentication is wired but the introspection seam is not — the candidate
        //gate requires both, so the endpoint must not materialize.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _) =>
                ValueTask.FromResult(true);
        }).ConfigureAwait(false);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeIntrospect,
            "POST",
            new RequestFields { [OAuthRequestParameterNames.Token] = "some-token" },
            [],
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
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri, IntrospectionCapabilities).ConfigureAwait(false);

        const string blockedIp = "203.0.113.7";
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _) =>
                ValueTask.FromResult(true);

            candidateIntegration.IntrospectTokenAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(new TokenIntrospectionResult { IsActive = true, Subject = "Z5O3upPC88QrAjx00dis" });


            //Attenuate per request: when the caller's forwarded IP is denylisted, the active
            //capability set excludes introspection, so the candidate is dropped from the chain.

            candidateIntegration.ResolveCapabilitiesAsync = (registration, context, _) =>
            {
                bool isBlocked = context.IncomingRequest is { } request
                    && request.Headers.TryGetSingle("X-Forwarded-For", out string? ip)
                    && ip == blockedIp;

                IReadOnlySet<CapabilityIdentifier> active = isBlocked
                    ? ((ClientRecord)registration).AllowedCapabilities.Remove(WellKnownCapabilityIdentifiers.OAuthTokenIntrospection)
                    : registration.AllowedCapabilities;

                return ValueTask.FromResult(active);
            };
        }).ConfigureAwait(false);

        RequestFields fields = new() { [OAuthRequestParameterNames.Token] = "some-token" };

        ServerHttpResponse blocked = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value, WellKnownEndpointNames.AuthCodeIntrospect, "POST",
            fields, ForwardedFor(blockedIp), [], TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse allowed = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value, WellKnownEndpointNames.AuthCodeIntrospect, "POST",
            fields, ForwardedFor("198.51.100.4"), [], TestContext.CancellationToken).ConfigureAwait(false);

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
        using VerifierKeyMaterial fullResource = await host.RegisterClientAsync(
            "https://full.resource.test", new Uri("https://full.resource.test"), IntrospectionCapabilities).ConfigureAwait(false);
        using VerifierKeyMaterial limitedResource = await host.RegisterClientAsync(
            "https://limited.resource.test", new Uri("https://limited.resource.test"), IntrospectionCapabilities).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (_, _, _, _) =>
                ValueTask.FromResult(true);
        }).ConfigureAwait(false);

        string limitedTenant = limitedResource.Registration.TenantId.Value;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.IntrospectTokenAsync = (token, hint, registration, context, ct) =>
            {
                string scope = registration.TenantId.Value == limitedTenant ? "read" : "read write admin";

                return ValueTask.FromResult(new TokenIntrospectionResult
                {
                    IsActive = true,
                    Subject = "Z5O3upPC88QrAjx00dis",
                    Scope = scope
                });
            };
        }).ConfigureAwait(false);

        RequestFields fields = new() { [OAuthRequestParameterNames.Token] = "shared-token" };

        ServerHttpResponse full = await host.DispatchAtEndpointAsync(
            fullResource.Registration.TenantId.Value, WellKnownEndpointNames.AuthCodeIntrospect, "POST",
            fields, [], TestContext.CancellationToken).ConfigureAwait(false);
        ServerHttpResponse limited = await host.DispatchAtEndpointAsync(
            limitedTenant, WellKnownEndpointNames.AuthCodeIntrospect, "POST",
            fields, [], TestContext.CancellationToken).ConfigureAwait(false);

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
